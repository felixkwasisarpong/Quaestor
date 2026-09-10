//! What the evaluator decides, and why.
//!
//! Every test states one belief about the decision. The interesting ones are
//! not the happy path: they are the cases where an answer that looks safe is
//! wrong in the expensive direction.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;

use quaestor_core::{
    AgentId, Currency, DenyReason, EscalationReason, IdempotencyKey, IntentId, Money, Payee,
    PayeeId, PaymentIntent, PrincipalId, Rail, Timestamp, Verdict,
};
use quaestor_policy::{evaluate, Policy, Request, SpendSnapshot};
use quaestor_verify::mandate::{Constraint, Scope};

const NOW: Timestamp = Timestamp(1_772_000_000_000);
const HORIZON: Timestamp = Timestamp(1_772_100_000_000);
const DAY_MS: i64 = 86_400_000;
const MONTH_MS: i64 = 2_592_000_000;
const HOUR_MS: i64 = 3_600_000;

const POLICY: &str = r#"
version = 1
currency = "USD"

[defaults]
unattended_limit = "50.00 USD"
escalate_first_seen_payee = true
escalate_above_remaining_percent = 50

[[budgets]]
window = "24h"
limit = "500.00 USD"

[[budgets]]
window = "30d"
limit = "2000.00 USD"

[velocity]
max_payments = 20
window = "1h"

[payees]
deny = ["known-bad.example"]
always_escalate = ["new-vendor.example"]

[categories]
deny = ["gambling"]
"#;

fn policy() -> Policy {
    Policy::parse(POLICY).expect("valid policy")
}

fn usd(minor: i128) -> Money {
    Money::new(minor, Currency::USD)
}

fn authority() -> Scope {
    Scope {
        max_amount: usd(100_000),
        payees: Constraint::Only(
            [
                "shop.example",
                "api.example",
                "new-vendor.example",
                "known-bad.example",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>(),
        ),
        categories: Constraint::Any,
        rails: Constraint::Only([Rail::X402].into_iter().collect()),
        not_after: HORIZON,
    }
}

fn intent(minor: i128, domain: &str) -> PaymentIntent {
    PaymentIntent {
        id: IntentId::new("int-1").expect("valid"),
        idempotency_key: IdempotencyKey::new("key-1").expect("valid"),
        agent: AgentId::new("shopper").expect("valid"),
        principal: PrincipalId::new("felix").expect("valid"),
        amount: usd(minor),
        payee: Payee {
            id: PayeeId::new(domain).expect("valid"),
            rail: Rail::X402,
            category: Some("saas".into()),
            domain: Some(domain.to_owned()),
        },
        context: Default::default(),
        requested_at: NOW,
    }
}

/// A snapshot where everything is comfortable: nothing spent, payee known.
fn quiet() -> SpendSnapshot {
    SpendSnapshot::new()
        .with_spend(DAY_MS, usd(0))
        .with_spend(MONTH_MS, usd(0))
        .with_velocity(0)
        .with_payee_seen_before(true)
}

fn decide(intent: &PaymentIntent, state: &SpendSnapshot) -> Verdict {
    let policy = policy();
    let authority = authority();
    evaluate(&Request {
        intent,
        authority: &authority,
        policy: &policy,
        state,
        now: NOW,
    })
}

fn denials(v: &Verdict) -> Vec<DenyReason> {
    match v {
        Verdict::Deny { reasons } => reasons.clone(),
        other => panic!("expected a denial, got {other:?}"),
    }
}

fn escalations(v: &Verdict) -> Vec<EscalationReason> {
    match v {
        Verdict::Escalate { reasons, .. } => reasons.clone(),
        other => panic!("expected an escalation, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------

#[test]
fn a_small_familiar_payment_is_allowed() {
    let v = decide(&intent(1_999, "shop.example"), &quiet());
    match v {
        Verdict::Allow { hold } => {
            assert_eq!(hold.amount, usd(1_999));
            assert_eq!(hold.expires_at.0, NOW.0 + 300_000, "5m default hold");
        }
        other => panic!("expected an allow, got {other:?}"),
    }
}

#[test]
fn every_reason_is_reported_not_just_the_first() {
    // A receipt saying "budget exhausted" when the payee was also blocked
    // and the mandate had expired sends someone to fix the wrong thing.
    let state = SpendSnapshot::new()
        .with_spend(DAY_MS, usd(49_900))
        .with_spend(MONTH_MS, usd(0))
        .with_velocity(99)
        .with_payee_seen_before(true);

    let mut bad = intent(20_000, "known-bad.example");
    bad.payee.category = Some("gambling".into());

    let reasons = denials(&decide(&bad, &state));
    assert!(reasons
        .iter()
        .any(|r| matches!(r, DenyReason::PayeeBlocked)));
    assert!(reasons
        .iter()
        .any(|r| matches!(r, DenyReason::CategoryBlocked { .. })));
    assert!(reasons
        .iter()
        .any(|r| matches!(r, DenyReason::BudgetExceeded { .. })));
    assert!(reasons
        .iter()
        .any(|r| matches!(r, DenyReason::VelocityExceeded { .. })));
    assert!(reasons.len() >= 4, "expected all four, got {reasons:?}");
}

#[test]
fn a_missing_spend_figure_denies_rather_than_assuming_zero() {
    // The failure that matters. A budget we cannot read is a budget we
    // cannot honour, and treating an absent figure as zero would hand an
    // agent a full budget every time the database hiccuped.
    let blind = SpendSnapshot::new()
        .with_spend(MONTH_MS, usd(0))
        .with_velocity(0)
        .with_payee_seen_before(true);

    let reasons = denials(&decide(&intent(100, "shop.example"), &blind));
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, DenyReason::StateUnavailable { .. })),
        "got {reasons:?}"
    );
}

#[test]
fn a_missing_velocity_count_also_denies() {
    let blind = SpendSnapshot::new()
        .with_spend(DAY_MS, usd(0))
        .with_spend(MONTH_MS, usd(0))
        .with_payee_seen_before(true);
    let reasons = denials(&decide(&intent(100, "shop.example"), &blind));
    assert!(reasons
        .iter()
        .any(|r| matches!(r, DenyReason::StateUnavailable { .. })));
}

#[test]
fn a_payment_that_exactly_reaches_the_cap_is_allowed() {
    // Off by one in the expensive direction either way: refusing the last
    // dollar of a budget is a support ticket, allowing one past it is a
    // breach of the limit someone set.
    let at_limit = SpendSnapshot::new()
        .with_spend(DAY_MS, usd(49_000))
        .with_spend(MONTH_MS, usd(0))
        .with_velocity(0)
        .with_payee_seen_before(true);

    assert!(matches!(
        decide(&intent(1_000, "shop.example"), &at_limit),
        Verdict::Escalate { .. } | Verdict::Allow { .. }
    ));

    let over = decide(&intent(1_001, "shop.example"), &at_limit);
    assert!(denials(&over)
        .iter()
        .any(|r| matches!(r, DenyReason::BudgetExceeded { .. })));
}

#[test]
fn the_velocity_limit_is_a_ceiling_not_a_target() {
    // At exactly the limit the next payment is the one too many.
    let at = quiet().with_velocity(20);
    assert!(denials(&decide(&intent(100, "shop.example"), &at))
        .iter()
        .any(|r| matches!(r, DenyReason::VelocityExceeded { .. })));

    let under = quiet().with_velocity(19);
    assert!(!matches!(
        decide(&intent(100, "shop.example"), &under),
        Verdict::Deny { .. }
    ));
}

#[test]
fn an_unfamiliar_payee_asks_a_human_rather_than_refusing() {
    let fresh = quiet().with_payee_seen_before(false);
    let v = decide(&intent(100, "shop.example"), &fresh);
    assert!(escalations(&v).contains(&EscalationReason::FirstSeenPayee));
    assert!(!v.permits_payment(), "an escalation is never an allow");
}

#[test]
fn an_escalation_carries_a_deadline_and_expires_to_nothing() {
    let v = decide(
        &intent(100, "shop.example"),
        &quiet().with_payee_seen_before(false),
    );
    match v {
        Verdict::Escalate { expires_at, .. } => {
            assert_eq!(expires_at.0, NOW.0 + 900_000, "15m default");
        }
        other => panic!("expected escalation, got {other:?}"),
    }
}

#[test]
fn a_payment_above_the_unattended_limit_asks_a_human() {
    let v = decide(&intent(5_001, "shop.example"), &quiet());
    assert!(escalations(&v)
        .iter()
        .any(|r| matches!(r, EscalationReason::AboveUnattendedLimit { .. })));

    // And exactly at the limit does not.
    assert!(matches!(
        decide(&intent(5_000, "shop.example"), &quiet()),
        Verdict::Allow { .. }
    ));
}

#[test]
fn consuming_most_of_what_is_left_asks_a_human() {
    // $10 left in the day, spending $6 of it. Inside every cap, but not the
    // kind of thing to do while its owner is asleep.
    let nearly_spent = SpendSnapshot::new()
        .with_spend(DAY_MS, usd(49_000))
        .with_spend(MONTH_MS, usd(0))
        .with_velocity(0)
        .with_payee_seen_before(true);

    let v = decide(&intent(600, "shop.example"), &nearly_spent);
    assert!(escalations(&v)
        .iter()
        .any(|r| matches!(r, EscalationReason::LargeShareOfBudget { .. })));
}

#[test]
fn a_denial_beats_an_escalation() {
    // Both fire. The answer must be no, not "ask someone".
    let fresh_and_broke = SpendSnapshot::new()
        .with_spend(DAY_MS, usd(50_000))
        .with_spend(MONTH_MS, usd(0))
        .with_velocity(0)
        .with_payee_seen_before(false);

    assert!(matches!(
        decide(&intent(10_000, "shop.example"), &fresh_and_broke),
        Verdict::Deny { .. }
    ));
}

#[test]
fn policy_cannot_permit_what_the_mandate_did_not() {
    // The payee is absent from the delegated authority. No policy setting
    // can rescue it, because the person liable never authorized it.
    let v = decide(&intent(100, "never-delegated.example"), &quiet());
    assert!(denials(&v)
        .iter()
        .any(|r| matches!(r, DenyReason::ScopeWidened { .. })));
}

#[test]
fn a_payment_above_the_delegated_ceiling_is_refused() {
    let v = decide(&intent(100_001, "shop.example"), &quiet());
    assert!(denials(&v)
        .iter()
        .any(|r| matches!(r, DenyReason::ScopeWidened { .. })));
}

#[test]
fn an_expired_mandate_refuses_even_a_trivial_payment() {
    let policy = policy();
    let authority = authority();
    let i = intent(1, "shop.example");
    let after = Timestamp(HORIZON.0 + 1);
    let v = evaluate(&Request {
        intent: &i,
        authority: &authority,
        policy: &policy,
        state: &quiet(),
        now: after,
    });
    assert!(denials(&v)
        .iter()
        .any(|r| matches!(r, DenyReason::MandateExpired { .. })));
}

#[test]
fn a_rail_the_mandate_did_not_cover_is_refused() {
    let mut i = intent(100, "shop.example");
    i.payee.rail = Rail::Card;
    assert!(denials(&decide(&i, &quiet())).contains(&DenyReason::RailNotPermitted));
}

#[test]
fn a_negative_amount_is_an_attack_not_a_refund() {
    let v = decide(&intent(-1_000, "shop.example"), &quiet());
    assert!(denials(&v)
        .iter()
        .any(|r| matches!(r, DenyReason::MalformedIntent { .. })));
}

#[test]
fn a_payment_in_another_currency_is_refused_not_converted() {
    let mut i = intent(100, "shop.example");
    i.amount = Money::new(100, Currency::EUR);
    let v = decide(&i, &quiet());
    assert!(denials(&v)
        .iter()
        .any(|r| matches!(r, DenyReason::MalformedIntent { .. })));
}

#[test]
fn the_verdict_does_not_depend_on_the_order_of_the_rules() {
    // Same inputs, same answer, every time. The property the audit story
    // rests on, and the reason no check short-circuits.
    let i = intent(600, "new-vendor.example");
    let s = quiet().with_payee_seen_before(false);
    let first = decide(&i, &s);
    for _ in 0..50 {
        assert_eq!(decide(&i, &s), first);
    }
}

#[test]
fn a_denial_names_the_tightest_window_that_was_breached() {
    // 24h is exhausted, 30d is not. The reason should be about the day.
    let state = SpendSnapshot::new()
        .with_spend(DAY_MS, usd(50_000))
        .with_spend(MONTH_MS, usd(60_000))
        .with_velocity(0)
        .with_payee_seen_before(true);

    let reasons = denials(&decide(&intent(1_000, "shop.example"), &state));
    let breached: Vec<_> = reasons
        .iter()
        .filter_map(|r| match r {
            DenyReason::BudgetExceeded { limit, .. } => Some(*limit),
            _ => None,
        })
        .collect();
    assert_eq!(breached.first(), Some(&usd(50_000)), "24h cap listed first");
}

#[test]
fn velocity_window_length_is_reported_so_a_human_can_read_it() {
    let v = decide(&intent(100, "shop.example"), &quiet().with_velocity(50));
    let found = denials(&v).into_iter().find_map(|r| match r {
        DenyReason::VelocityExceeded { window_ms, .. } => Some(window_ms),
        _ => None,
    });
    assert_eq!(found, Some(HOUR_MS));
}

#[test]
fn an_always_escalate_payee_asks_a_human_even_when_familiar() {
    let v = decide(&intent(100, "new-vendor.example"), &quiet());
    assert!(escalations(&v)
        .iter()
        .any(|r| matches!(r, EscalationReason::PolicyRequiresApproval { .. })));
}

#[test]
fn evaluation_never_panics_on_extreme_amounts() {
    // A payment authorizer that crashes is a denial of service on somebody's
    // money. There is no input that should take this function down.
    for minor in [i128::MAX, i128::MIN, 0, -1, 1] {
        let mut i = intent(0, "shop.example");
        i.amount = usd(minor);
        let _ = decide(&i, &quiet());

        let extreme = SpendSnapshot::new()
            .with_spend(DAY_MS, usd(i128::MAX))
            .with_spend(MONTH_MS, usd(i128::MIN))
            .with_velocity(u32::MAX)
            .with_payee_seen_before(false);
        let _ = decide(&i, &extreme);
    }
}

// ---------------------------------------------------------------------------
// The recipient and the host are two different parties
// ---------------------------------------------------------------------------
//
// Every fixture above uses the same string for the payee id and the payee
// domain, which is what let `payee_key` prefer the wrong one for eight days
// without a single test noticing. These four separate them. See BUGS.md #015.

/// Paid to `recipient`, served by `host`. On x402 those are an address and a
/// website, and they are routinely not the same party.
fn split_payee(recipient: &str, host: &str) -> PaymentIntent {
    let mut i = intent(1_000, recipient);
    i.payee.id = PayeeId::new(recipient).expect("valid");
    i.payee.domain = Some(host.to_owned());
    i
}

#[test]
fn a_blocked_recipient_is_blocked_however_the_resource_was_served() {
    let mut p = policy();
    p.deny_payees = vec!["0xbad".into()];

    let v = evaluate(&Request {
        intent: &split_payee("0xbad", "perfectly-ordinary.example"),
        authority: &authority(),
        policy: &p,
        state: &quiet(),
        now: NOW,
    });
    assert!(
        matches!(&v, Verdict::Deny { reasons } if reasons.contains(&DenyReason::PayeeBlocked)),
        "the block list names who gets the money: {v:?}"
    );
}

#[test]
fn a_blocked_host_is_blocked_whoever_it_says_to_pay() {
    let mut p = policy();
    p.deny_payees = vec!["known-bad.example".into()];

    let v = evaluate(&Request {
        intent: &split_payee("0xsomeoneelse", "known-bad.example"),
        authority: &authority(),
        policy: &p,
        state: &quiet(),
        now: NOW,
    });
    assert!(
        matches!(&v, Verdict::Deny { reasons } if reasons.contains(&DenyReason::PayeeBlocked)),
        "a block list matches any name the payee answers to: {v:?}"
    );
}

#[test]
fn delegated_authority_names_the_recipient_not_the_host() {
    // The asymmetry. A block list matching more names is safer; an allow
    // list matching more names hands out authority nobody granted. A mandate
    // that permits paying `0xmerchant` must not be satisfiable by paying
    // somebody else through a host that happens to be named `0xmerchant`.
    let mut a = authority();
    a.payees = Constraint::Only(["0xmerchant".to_owned()].into_iter().collect());

    let v = evaluate(&Request {
        intent: &split_payee("0xattacker", "0xmerchant"),
        authority: &a,
        policy: &policy(),
        state: &quiet(),
        now: NOW,
    });
    assert!(
        matches!(&v, Verdict::Deny { reasons }
            if reasons.iter().any(|r| matches!(r, DenyReason::ScopeWidened { .. }))),
        "the host must not stand in for the recipient: {v:?}"
    );
}

#[test]
fn a_permitted_recipient_is_permitted_from_any_host() {
    let mut a = authority();
    a.payees = Constraint::Only(["0xmerchant".to_owned()].into_iter().collect());

    let v = evaluate(&Request {
        intent: &split_payee("0xmerchant", "some-cdn.example"),
        authority: &a,
        policy: &policy(),
        state: &quiet(),
        now: NOW,
    });
    assert!(
        !matches!(&v, Verdict::Deny { reasons }
            if reasons.iter().any(|r| matches!(r, DenyReason::ScopeWidened { .. }))),
        "the grant is about the recipient, so the host is irrelevant: {v:?}"
    );
}
