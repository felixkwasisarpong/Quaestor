//! What the gateway does, with no sockets involved.
//!
//! Each test is one claim about a decision. The transport is tested
//! separately, in `end_to_end.rs`, and it is deliberately thin so that
//! almost nothing worth asserting lives there.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::*;
use quaestor_core::Timestamp;
use quaestor_ledger::HoldState;
use quaestor_proxy::gateway::Incoming;
use quaestor_proxy::{Gateway, InMemoryHolds, Outcome, Reach, RefusalKind};
use quaestor_receipt::{verify_chain, Receipt, ReceiptVerdict};

fn req<'a>(payment: Option<&'a str>, token: &'a str) -> Incoming<'a> {
    Incoming {
        method: "GET",
        target: TARGET,
        authorization: Some(token),
        payment,
        mandate: None,
    }
}

/// A gateway that has already seen the origin's `402`.
fn challenged(atomic: u128) -> Gateway {
    let mut g = gateway();
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, atomic),
        NOW,
    );
    g
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn refusal(outcome: &Outcome) -> (RefusalKind, String, Option<Receipt>) {
    match outcome {
        Outcome::Refuse(r) => (r.kind, r.detail.clone(), r.receipt.clone()),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The door
// ---------------------------------------------------------------------------

#[test]
fn without_a_credential_there_is_no_principal_and_so_no_verdict() {
    let mut g = gateway();
    for auth in [None, Some("Bearer nonsense"), Some("sk_felix_test")] {
        let out = g.on_request(
            &Incoming {
                method: "GET",
                target: TARGET,
                authorization: auth,
                payment: Some(&honest_payment(1_000_000, 1)),
                mandate: None,
            },
            NOW,
        );
        let (kind, _, receipt) = refusal(&out);
        assert_eq!(kind, RefusalKind::Unauthenticated);
        assert!(
            receipt.is_none(),
            "there is no principal to write a receipt against"
        );
    }
}

#[test]
fn a_request_with_no_payment_is_relayed_under_the_callers_name() {
    let mut g = gateway();
    let out = g.on_request(&req(None, &bearer(TOKEN)), NOW);
    match out {
        Outcome::Passthrough { principal } => assert_eq!(principal, "felix"),
        other => panic!("expected passthrough, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The challenge. This is the part a proxy gets wrong.
// ---------------------------------------------------------------------------

#[test]
fn a_payment_for_a_challenge_we_never_saw_is_refused() {
    // The tempting alternative is to fall back to the requirements inside
    // the payload. That is the agent's own claim, and falling back to it is
    // how a correct verifier is made to certify nothing at all.
    let mut g = gateway();
    let out = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    );

    let (kind, detail, _) = refusal(&out);
    assert_eq!(kind, RefusalKind::NoChallenge);
    assert_eq!(kind.status(), 402, "the agent should go and get one");
    assert!(
        detail.contains("no outstanding payment challenge"),
        "{detail}"
    );
}

#[test]
fn a_self_consistent_payment_to_the_wrong_recipient_is_refused() {
    // The headline case. Everything about this payload agrees with itself:
    // the signature is genuine, the authorization pays the attacker, and the
    // `accepted` field says the attacker is who was demanded. Checked
    // against itself it passes every binding test there is.
    //
    // Checked against what the origin actually said, it does not.
    let mut g = challenged(1_000_000);
    let forged = payment(ATTACKER, 1_000_000, 1, requirements(ATTACKER, 1_000_000));

    let out = g.on_request(&req(Some(&forged), &bearer(TOKEN)), NOW);
    let (kind, detail, receipt) = refusal(&out);

    assert_eq!(kind, RefusalKind::Unverifiable);
    assert!(
        detail.contains("authorization pays") && detail.contains("the request demanded"),
        "the refusal should name the binding failure: {detail}"
    );
    assert!(
        receipt.is_none(),
        "nothing verified, so there is nothing to assert in a signed record"
    );
}

#[test]
fn a_payment_for_less_than_was_demanded_is_refused() {
    let mut g = challenged(1_000_000);
    let short = payment(MERCHANT, 1, 1, requirements(MERCHANT, 1));

    let (kind, detail, _) = refusal(&g.on_request(&req(Some(&short), &bearer(TOKEN)), NOW));
    assert_eq!(kind, RefusalKind::Unverifiable);
    assert!(
        detail.contains("atomic units") && detail.contains("was demanded"),
        "{detail}"
    );
}

#[test]
fn one_callers_challenge_is_not_another_callers_licence_to_pay() {
    let mut g = gateway();
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let out = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(OTHER_TOKEN)),
        NOW,
    );
    assert_eq!(refusal(&out).0, RefusalKind::NoChallenge);
}

#[test]
fn a_challenge_does_not_outlive_its_window() {
    let mut g = challenged(1_000_000);
    let out = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        Timestamp(NOW.0 + 120_001),
    );
    assert_eq!(refusal(&out).0, RefusalKind::NoChallenge);
}

#[test]
fn the_same_authorization_cannot_be_presented_twice() {
    let mut g = challenged(1_000_000);
    let once = honest_payment(1_000_000, 1);

    assert!(matches!(
        g.on_request(&req(Some(&once), &bearer(TOKEN)), NOW),
        Outcome::Forward { .. }
    ));
    let (kind, detail, _) = refusal(&g.on_request(&req(Some(&once), &bearer(TOKEN)), NOW));
    assert_eq!(kind, RefusalKind::Unverifiable);
    assert!(
        detail.contains("nonce") || detail.contains("replay"),
        "{detail}"
    );
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

#[test]
fn an_authorized_payment_is_forwarded_with_the_budget_held_not_yet_spent() {
    let (g, holds, intent_id, receipt) = forwarded();

    assert_eq!(intent_id, intent_id_for(1));
    assert!(matches!(receipt.verdict, ReceiptVerdict::Allow));
    assert_eq!(receipt.amount, usdc(1_000_000));
    assert_eq!(receipt.payee, payee_id(MERCHANT));

    assert_eq!(holds.row_count(), 1);
    assert_eq!(
        holds.state_of(&intent_id),
        Some(HoldState::Held),
        "nothing has been written upstream yet, so nothing is spent yet"
    );
    drop(g);
}

#[test]
fn a_blocked_payee_is_denied_and_the_denial_is_signed() {
    let mut g = gateway();
    // The origin itself demands payment to a blocked address.
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(ATTACKER, 1_000_000),
        NOW,
    );
    let honest_but_blocked = payment(ATTACKER, 1_000_000, 1, requirements(ATTACKER, 1_000_000));

    let (kind, detail, receipt) =
        refusal(&g.on_request(&req(Some(&honest_but_blocked), &bearer(TOKEN)), NOW));

    assert_eq!(kind, RefusalKind::Denied);
    assert_eq!(kind.status(), 403);
    assert!(detail.contains("blocked"), "{detail}");

    let receipt = receipt.expect("a refusal about a real payment is receipted");
    assert!(matches!(receipt.verdict, ReceiptVerdict::Deny { .. }));
    receipt
        .verify_signature()
        .expect("and the record is signed");
}

#[test]
fn a_payment_over_the_budget_is_denied() {
    // The 24h budget is 5 USDC. Ask for six.
    let mut g = challenged(6_000_000);
    let (kind, detail, receipt) = refusal(&g.on_request(
        &req(Some(&honest_payment(6_000_000, 1)), &bearer(TOKEN)),
        NOW,
    ));

    assert_eq!(kind, RefusalKind::Denied);
    assert!(detail.contains("budget"), "{detail}");
    assert!(receipt.is_some());
}

#[test]
fn a_payment_above_the_unattended_limit_asks_for_a_human_and_gets_a_refusal() {
    // 3 USDC is inside every budget and above the 2 USDC unattended limit.
    // There is nobody standing at the proxy to approve it, and an
    // escalation nobody answers resolves to a denial. Never to an allow.
    let mut g = challenged(3_000_000);
    let (kind, _, receipt) = refusal(&g.on_request(
        &req(Some(&honest_payment(3_000_000, 1)), &bearer(TOKEN)),
        NOW,
    ));

    assert_eq!(kind, RefusalKind::Escalated);
    assert_eq!(kind.status(), 403, "an unanswered escalation is a no");

    let receipt = receipt.expect("receipted");
    assert!(
        matches!(receipt.verdict, ReceiptVerdict::Escalate { .. }),
        "the record says it was escalated, not that it was denied outright"
    );
}

#[test]
fn a_ledger_that_cannot_be_read_denies_rather_than_assuming_an_empty_budget() {
    let mut g = gateway_with(Box::new(UnreadableHolds), identities());
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let (kind, detail, receipt) = refusal(&g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    ));

    assert_eq!(kind, RefusalKind::Denied);
    assert!(
        detail.contains("could not be run"),
        "a database outage must not read as a fresh budget: {detail}"
    );
    assert!(receipt.is_some());
}

#[test]
fn when_the_snapshot_and_the_ledger_disagree_the_ledger_has_the_last_word() {
    // The policy engine reads a photograph. The ledger reads the truth,
    // under a lock, with every concurrent reservation already visible. This
    // double makes the photograph permanently wrong so the consequence can
    // be asserted: policy allows, the reservation refuses, and the receipt
    // records the refusal.
    let mut g = gateway_with(Box::new(StaleSnapshotHolds::new()), identities());

    // Spend the 5 USDC daily budget in two allowed payments.
    for (i, atomic) in [(1_u8, 2_000_000_u128), (2, 2_000_000)] {
        g.record_challenge(
            "felix",
            "GET",
            TARGET,
            &challenge_body(MERCHANT, atomic),
            NOW,
        );
        assert!(
            matches!(
                g.on_request(&req(Some(&honest_payment(atomic, i)), &bearer(TOKEN)), NOW),
                Outcome::Forward { .. }
            ),
            "payment {i} should be allowed"
        );
    }

    // A third would breach it. Policy cannot see that; the ledger can.
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 2_000_000),
        NOW,
    );
    let (kind, detail, receipt) = refusal(&g.on_request(
        &req(Some(&honest_payment(2_000_000, 3)), &bearer(TOKEN)),
        NOW,
    ));

    assert_eq!(kind, RefusalKind::Denied);
    assert!(
        detail.contains("exhausted between the policy check and the reservation"),
        "the receipt should say which check actually refused: {detail}"
    );
    let receipt = receipt.expect("receipted");
    assert!(matches!(receipt.verdict, ReceiptVerdict::Deny { .. }));
}

// ---------------------------------------------------------------------------
// The point of no return
// ---------------------------------------------------------------------------

/// One authorized payment, with the ledger still visible to the test.
fn forwarded() -> (Gateway, SharedHolds, String, Receipt) {
    let holds = SharedHolds::new();
    let mut g = gateway_with(Box::new(holds.clone()), identities());
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let Outcome::Forward { intent_id, receipt } = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    ) else {
        panic!("expected a forward");
    };
    (g, holds, intent_id, *receipt)
}

#[test]
fn the_spend_is_committed_before_the_payment_is_written() {
    let (mut g, holds, intent_id, _) = forwarded();

    assert_eq!(
        holds.state_of(&intent_id),
        Some(HoldState::Held),
        "before the connection, only held"
    );

    g.commit_spend(&intent_id, NOW).expect("committed");

    assert_eq!(
        holds.state_of(&intent_id),
        Some(HoldState::Captured),
        "committed before a byte goes out, because the write is the point \
         of no return"
    );
}

#[test]
fn a_payment_that_never_left_the_process_gives_the_budget_back() {
    let (mut g, holds, intent_id, _) = forwarded();

    let released = g.on_forward_failed(&intent_id, Reach::NeverConnected, NOW);

    assert!(released, "nothing was written, so nothing was spent");
    assert_eq!(holds.state_of(&intent_id), Some(HoldState::Released));
}

#[test]
fn a_payment_that_may_have_arrived_keeps_the_budget_committed() {
    // The asymmetry that matters. "We do not know whether that money moved"
    // has exactly one safe reading, and it is not the cheap one.
    let (mut g, holds, intent_id, _) = forwarded();

    g.commit_spend(&intent_id, NOW).expect("committed");
    let released = g.on_forward_failed(&intent_id, Reach::MaybeDelivered, NOW);

    assert!(!released, "an unknown outcome does not refund");
    assert_eq!(holds.state_of(&intent_id), Some(HoldState::Captured));
}

#[test]
fn a_released_payment_frees_the_budget_for_the_next_one() {
    // Not bookkeeping for its own sake: this is what makes an unreachable
    // origin cost an agent a retry rather than a day's allowance.
    let (mut g, holds, intent_id, _) = forwarded(); // 1 USDC, held
    g.on_forward_failed(&intent_id, Reach::NeverConnected, NOW);
    assert_eq!(holds.state_of(&intent_id), Some(HoldState::Released));

    // The daily budget is 5 USDC. These come to exactly 5, which only fits
    // if the released 1 USDC really did go back.
    for (nonce, atomic) in [(2_u8, 2_000_000_u128), (3, 2_000_000), (4, 1_000_000)] {
        g.record_challenge(
            "felix",
            "GET",
            TARGET,
            &challenge_body(MERCHANT, atomic),
            NOW,
        );
        let out = g.on_request(
            &req(Some(&honest_payment(atomic, nonce)), &bearer(TOKEN)),
            NOW,
        );
        assert!(
            matches!(out, Outcome::Forward { .. }),
            "payment {nonce} should fit in the freed budget, got {out:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

#[test]
fn every_decision_about_a_real_payment_lands_in_one_unbroken_chain() {
    let mut g = challenged(1_000_000);
    let key = g.public_key();
    let mut receipts = Vec::new();

    // allowed
    let Outcome::Forward { receipt, .. } = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    ) else {
        panic!("expected a forward");
    };
    receipts.push(*receipt);

    // escalated
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 3_000_000),
        NOW,
    );
    let (_, _, r) = refusal(&g.on_request(
        &req(Some(&honest_payment(3_000_000, 2)), &bearer(TOKEN)),
        NOW,
    ));
    receipts.push(r.expect("receipted"));

    // denied
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(ATTACKER, 1_000_000),
        NOW,
    );
    let blocked = payment(ATTACKER, 1_000_000, 3, requirements(ATTACKER, 1_000_000));
    let (_, _, r) = refusal(&g.on_request(&req(Some(&blocked), &bearer(TOKEN)), NOW));
    receipts.push(r.expect("receipted"));

    let report = verify_chain(&receipts, &key, true).expect("the chain must verify");
    assert_eq!(report.count, 3);
    assert_eq!(report.allowed, 1);
    assert_eq!(report.escalated, 1);
    assert_eq!(report.denied, 1);
}

#[test]
fn refusals_at_the_door_do_not_punch_holes_in_the_chain() {
    // Receipts start when a payment verifies, not when a request arrives.
    // The risk in that rule is a gap: if a sequence number were consumed by
    // something that produced no receipt, the log would fail to verify
    // through no fault of anyone's.
    let mut g = challenged(1_000_000);
    let key = g.public_key();

    let mut receipts = Vec::new();
    let Outcome::Forward { receipt, .. } = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    ) else {
        panic!("expected a forward");
    };
    receipts.push(*receipt);

    // Four things that never become a decision about money.
    let noise = [
        Incoming {
            method: "GET",
            target: TARGET,
            authorization: None,
            payment: Some("x"),
            mandate: None,
        },
        Incoming {
            method: "GET",
            target: TARGET,
            authorization: Some(&bearer("wrong")),
            payment: Some("x"),
            mandate: None,
        },
        Incoming {
            method: "GET",
            target: "http://other.example/",
            authorization: Some(&bearer(TOKEN)),
            payment: Some("x"),
            mandate: None,
        },
        Incoming {
            method: "GET",
            target: TARGET,
            authorization: Some(&bearer(TOKEN)),
            payment: Some("!!not base64!!"),
            mandate: None,
        },
    ];
    for n in &noise {
        let (_, _, receipt) = refusal(&g.on_request(n, NOW));
        assert!(receipt.is_none());
    }

    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(ATTACKER, 1_000_000),
        NOW,
    );
    let blocked = payment(ATTACKER, 1_000_000, 2, requirements(ATTACKER, 1_000_000));
    let (_, _, r) = refusal(&g.on_request(&req(Some(&blocked), &bearer(TOKEN)), NOW));
    receipts.push(r.expect("receipted"));

    assert_eq!(receipts[1].seq, 1, "no sequence number was burned");
    verify_chain(&receipts, &key, true).expect("still one unbroken chain");
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

#[test]
fn a_caller_with_no_trusted_roots_cannot_introduce_one_by_presenting_a_chain() {
    let root = ed_key(1);
    let agent = ed_key(2);
    let chain = mandate_chain(&[(root, agent, scope(50_000_000, only(&[])))]);

    let mut g = challenged(1_000_000);
    let out = g.on_request(
        &Incoming {
            method: "GET",
            target: TARGET,
            authorization: Some(&bearer(TOKEN)),
            payment: Some(&honest_payment(1_000_000, 1)),
            mandate: Some(&chain),
        },
        NOW,
    );

    let (kind, detail, _) = refusal(&out);
    assert_eq!(kind, RefusalKind::Denied);
    assert!(detail.contains("no trusted roots"), "{detail}");
}

#[test]
fn a_chain_may_narrow_the_credential() {
    let root = ed_key(1);
    let agent = ed_key(2);
    let narrow = scope(2_000_000, only(&[&MERCHANT.to_ascii_lowercase()]));
    let chain = mandate_chain(&[(root.clone(), agent, narrow)]);

    let ids = quaestor_proxy::Identities::new().insert(
        TOKEN,
        caller(
            "felix",
            "shopper",
            scope(50_000_000, quaestor_verify::mandate::Constraint::Any),
            vec![ed_pk(&root)],
        ),
    );
    let mut g = gateway_with(Box::new(InMemoryHolds::new()), ids);
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let out = g.on_request(
        &Incoming {
            method: "GET",
            target: TARGET,
            authorization: Some(&bearer(TOKEN)),
            payment: Some(&honest_payment(1_000_000, 1)),
            mandate: Some(&chain),
        },
        NOW,
    );
    assert!(matches!(out, Outcome::Forward { .. }), "got {out:?}");
}

#[test]
fn a_chain_may_not_widen_the_credential() {
    // The credential is capped at 2 USDC. The chain, honestly signed by a
    // root this deployment trusts, grants 50. Trusting the root is not the
    // same as agreeing that this credential may use everything the root
    // ever granted anybody.
    let root = ed_key(1);
    let agent = ed_key(2);
    let generous = scope(50_000_000, quaestor_verify::mandate::Constraint::Any);
    let chain = mandate_chain(&[(root.clone(), agent, generous)]);

    let ids = quaestor_proxy::Identities::new().insert(
        TOKEN,
        caller(
            "felix",
            "shopper",
            scope(2_000_000, quaestor_verify::mandate::Constraint::Any),
            vec![ed_pk(&root)],
        ),
    );
    let mut g = gateway_with(Box::new(InMemoryHolds::new()), ids);
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let out = g.on_request(
        &Incoming {
            method: "GET",
            target: TARGET,
            authorization: Some(&bearer(TOKEN)),
            payment: Some(&honest_payment(1_000_000, 1)),
            mandate: Some(&chain),
        },
        NOW,
    );
    let (kind, detail, _) = refusal(&out);
    assert_eq!(kind, RefusalKind::Denied);
    assert!(
        detail.contains("claims more than this credential"),
        "{detail}"
    );
}

#[test]
fn a_chain_for_a_different_principal_is_not_this_callers_authority() {
    let root = ed_key(1);
    let agent = ed_key(2);
    let chain = mandate_chain(&[(
        root.clone(),
        agent,
        scope(2_000_000, quaestor_verify::mandate::Constraint::Any),
    )]);

    // The chain names `felix`; this credential is `ama`.
    let ids = quaestor_proxy::Identities::new().insert(
        OTHER_TOKEN,
        caller(
            "ama",
            "shopper",
            scope(50_000_000, quaestor_verify::mandate::Constraint::Any),
            vec![ed_pk(&root)],
        ),
    );
    let mut g = gateway_with(Box::new(InMemoryHolds::new()), ids);
    g.record_challenge(
        "ama",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let out = g.on_request(
        &Incoming {
            method: "GET",
            target: TARGET,
            authorization: Some(&bearer(OTHER_TOKEN)),
            payment: Some(&honest_payment(1_000_000, 1)),
            mandate: Some(&chain),
        },
        NOW,
    );
    let (kind, detail, _) = refusal(&out);
    assert_eq!(kind, RefusalKind::Denied);
    assert!(detail.contains("the chain is for principal"), "{detail}");
}

// ---------------------------------------------------------------------------
// The record is written before the verdict escapes
// ---------------------------------------------------------------------------

#[test]
fn a_decision_is_on_disk_before_the_agent_learns_it() {
    // The ordering the crash-safety argument rests on. If the receipt were
    // written after the verdict went out, a crash in between would leave a
    // payment in the world with nothing accounting for it.
    let sink = SharedSink::new();
    let mut g = gateway_logging_to(
        Box::new(InMemoryHolds::new()),
        identities(),
        Box::new(sink.clone()),
    );
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let out = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    );

    let Outcome::Forward { receipt, .. } = out else {
        panic!("expected a forward");
    };
    let written = sink.receipts();
    assert_eq!(written.len(), 1, "the log has it already");
    assert_eq!(written[0], *receipt, "and it is the same one");
}

#[test]
fn refusals_are_written_down_too() {
    let sink = SharedSink::new();
    let mut g = gateway_logging_to(
        Box::new(InMemoryHolds::new()),
        identities(),
        Box::new(sink.clone()),
    );
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(ATTACKER, 1_000_000),
        NOW,
    );
    let blocked = payment(ATTACKER, 1_000_000, 1, requirements(ATTACKER, 1_000_000));

    let (kind, _, _) = refusal(&g.on_request(&req(Some(&blocked), &bearer(TOKEN)), NOW));
    assert_eq!(kind, RefusalKind::Denied);
    assert_eq!(sink.receipts().len(), 1, "a denial is evidence");
}

#[test]
fn a_payment_that_cannot_be_recorded_does_not_go_out() {
    // A decision nobody can account for must not become a payment. The hold
    // goes back, because the alternative is a budget consumed for something
    // that never happened and was never written down.
    let holds = SharedHolds::new();
    let mut g = gateway_logging_to(
        Box::new(holds.clone()),
        identities(),
        Box::new(quaestor_proxy::FailingSink),
    );
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(MERCHANT, 1_000_000),
        NOW,
    );

    let out = g.on_request(
        &req(Some(&honest_payment(1_000_000, 1)), &bearer(TOKEN)),
        NOW,
    );

    let (kind, detail, receipt) = refusal(&out);
    assert_eq!(kind, RefusalKind::Unavailable);
    assert_eq!(kind.status(), 503);
    assert!(detail.contains("could not be recorded"), "{detail}");
    assert!(receipt.is_none(), "there is nowhere to have put one");
    assert_eq!(
        holds.state_of(&intent_id_for(1)),
        Some(HoldState::Released),
        "the budget goes back rather than being spent on a secret"
    );
}

#[test]
fn a_refusal_stands_even_when_the_log_is_unwritable() {
    // The asymmetry. Refusing is safe whatever else is broken, and
    // downgrading a denial to an approval because the audit log was full
    // would be an absurd way to lose money.
    let mut g = gateway_logging_to(
        Box::new(InMemoryHolds::new()),
        identities(),
        Box::new(quaestor_proxy::FailingSink),
    );
    g.record_challenge(
        "felix",
        "GET",
        TARGET,
        &challenge_body(ATTACKER, 1_000_000),
        NOW,
    );
    let blocked = payment(ATTACKER, 1_000_000, 1, requirements(ATTACKER, 1_000_000));

    let (kind, detail, receipt) = refusal(&g.on_request(&req(Some(&blocked), &bearer(TOKEN)), NOW));

    assert_eq!(kind, RefusalKind::Denied, "still refused");
    assert!(receipt.is_none());
    assert!(
        detail.contains("could not be written to the receipt log"),
        "the agent is told the record is missing: {detail}"
    );
}
