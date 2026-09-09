//! What a forger would try, and whether it works.
//!
//! A receipt log is only evidence if altering it is detectable. Each test
//! here is one way of altering it.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use ed25519_dalek::SigningKey;
use quaestor_core::{
    Approver, Currency, DenyReason, Hold, IntentId, Money, PrincipalId, Timestamp, Verdict,
};
use quaestor_receipt::{verify_chain, Receipt, ReceiptVerdict, Signer, VerifyFailure};

const NOW: Timestamp = Timestamp(1_772_000_000_000);
const POLICY: [u8; 32] = [0xAB; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn usd(minor: i128) -> Money {
    Money::new(minor, Currency::USD)
}

fn allow() -> Verdict {
    Verdict::Allow {
        hold: Hold {
            intent: IntentId::new("i").expect("valid"),
            amount: usd(100),
            expires_at: Timestamp(NOW.0 + 300_000),
        },
    }
}

fn deny() -> Verdict {
    Verdict::Deny {
        reasons: vec![DenyReason::PayeeBlocked],
    }
}

fn escalate() -> Verdict {
    Verdict::Escalate {
        to: Approver {
            principal: PrincipalId::new("felix").expect("valid"),
            channel: None,
        },
        reasons: vec![quaestor_core::EscalationReason::FirstSeenPayee],
        expires_at: Timestamp(NOW.0 + 900_000),
    }
}

/// Three decisions: one allowed, one denied, one escalated.
fn log() -> (Vec<Receipt>, [u8; 32]) {
    let mut s = Signer::new(key(1));
    let pk = s.public_key();
    let rs = vec![
        s.issue(
            "i1",
            "felix",
            "shopper",
            "shop.example",
            usd(1_999),
            &allow(),
            POLICY,
            NOW,
        ),
        s.issue(
            "i2",
            "felix",
            "shopper",
            "bad.example",
            usd(5_000),
            &deny(),
            POLICY,
            NOW,
        ),
        s.issue(
            "i3",
            "felix",
            "shopper",
            "new.example",
            usd(9_900),
            &escalate(),
            POLICY,
            NOW,
        ),
    ];
    (rs, pk)
}

// ---------------------------------------------------------------------------

#[test]
fn an_untouched_log_verifies() {
    let (rs, pk) = log();
    let report = verify_chain(&rs, &pk, true).expect("should verify");
    assert_eq!(report.count, 3);
    assert_eq!(report.allowed, 1);
    assert_eq!(report.denied, 1);
    assert_eq!(report.escalated, 1);
}

#[test]
fn a_refusal_is_recorded_as_fully_as_an_approval() {
    // The whole argument for this crate. A denial nobody can account for is
    // an argument, and arguments about money are settled with evidence.
    let (rs, pk) = log();
    let denial = &rs[1];
    assert!(matches!(denial.verdict, ReceiptVerdict::Deny { .. }));
    denial.verify_signature().expect("a denial is signed too");
    assert!(verify_chain(&rs[1..2], &pk, false).is_ok());
}

#[test]
fn changing_the_amount_breaks_the_signature() {
    let (mut rs, pk) = log();
    rs[0].amount = usd(1);
    assert!(matches!(
        verify_chain(&rs, &pk, true),
        Err(VerifyFailure::BadSignature { seq: 0 })
    ));
}

#[test]
fn changing_the_reason_for_a_denial_breaks_the_signature() {
    // The reasons are inside the signed bytes on purpose. If only "denied"
    // were covered, anyone could rewrite *why* without breaking anything,
    // and the why is what a dispute is actually about.
    let (mut rs, pk) = log();
    rs[1].verdict = ReceiptVerdict::Deny {
        reasons: vec![DenyReason::MandateMissing],
    };
    assert!(matches!(
        verify_chain(&rs, &pk, true),
        Err(VerifyFailure::BadSignature { seq: 1 })
    ));
}

#[test]
fn turning_a_denial_into_an_approval_breaks_the_signature() {
    let (mut rs, pk) = log();
    rs[1].verdict = ReceiptVerdict::Allow;
    assert!(verify_chain(&rs, &pk, true).is_err());
}

#[test]
fn changing_which_policy_produced_the_decision_breaks_the_signature() {
    let (mut rs, pk) = log();
    rs[2].policy_version = [0xCD; 32];
    assert!(matches!(
        verify_chain(&rs, &pk, true),
        Err(VerifyFailure::BadSignature { seq: 2 })
    ));
}

#[test]
fn deleting_the_awkward_receipt_breaks_the_chain() {
    // The attack a signature alone does not stop. Every remaining receipt
    // is still perfectly signed; what gives it away is the link.
    let (rs, pk) = log();
    let without_the_denial = vec![rs[0].clone(), rs[2].clone()];

    for r in &without_the_denial {
        r.verify_signature()
            .expect("each is still individually valid");
    }
    assert!(
        verify_chain(&without_the_denial, &pk, true).is_err(),
        "a deletion must be detectable"
    );
}

#[test]
fn reordering_receipts_breaks_the_chain() {
    let (rs, pk) = log();
    let shuffled = vec![rs[0].clone(), rs[2].clone(), rs[1].clone()];
    assert!(verify_chain(&shuffled, &pk, true).is_err());
}

#[test]
fn a_forger_with_their_own_key_cannot_pass_as_the_issuer() {
    // A self-consistent chain proves nothing on its own. You have to know
    // whose signature you are expecting.
    let mut forged = Signer::new(key(9));
    let rs = vec![forged.issue("i1", "felix", "a", "p", usd(1), &allow(), POLICY, NOW)];

    assert!(
        verify_chain(&rs, &forged.public_key(), true).is_ok(),
        "internally consistent"
    );
    assert!(
        matches!(
            verify_chain(&rs, &key(1).verifying_key().to_bytes(), true),
            Err(VerifyFailure::WrongSigner { .. })
        ),
        "but not signed by who we expected"
    );
}

#[test]
fn splicing_in_a_receipt_signed_by_the_same_key_is_still_caught() {
    // Harder case: the attacker holds the signing key and inserts a real,
    // correctly signed receipt into the middle. The chain still catches it,
    // because prev_hash of everything after it no longer matches.
    let (rs, pk) = log();
    let mut side = Signer::new(key(1));
    let extra = side.issue("i-extra", "felix", "a", "p", usd(1), &allow(), POLICY, NOW);

    let spliced = vec![rs[0].clone(), extra, rs[1].clone(), rs[2].clone()];
    assert!(verify_chain(&spliced, &pk, true).is_err());
}

#[test]
fn the_head_changes_whenever_anything_does() {
    // Publish the head and anyone holding an earlier copy can tell whether
    // history was rewritten behind them.
    let (rs, pk) = log();
    let a = verify_chain(&rs, &pk, true).expect("verifies").head;

    let mut other = Signer::new(key(1));
    let rs2 = vec![
        other.issue(
            "i1",
            "felix",
            "shopper",
            "shop.example",
            usd(2_000),
            &allow(),
            POLICY,
            NOW,
        ),
        other.issue(
            "i2",
            "felix",
            "shopper",
            "bad.example",
            usd(5_000),
            &deny(),
            POLICY,
            NOW,
        ),
        other.issue(
            "i3",
            "felix",
            "shopper",
            "new.example",
            usd(9_900),
            &escalate(),
            POLICY,
            NOW,
        ),
    ];
    let b = verify_chain(&rs2, &pk, true).expect("verifies").head;
    assert_ne!(a, b, "one changed amount must move the head");
}

#[test]
fn a_slice_from_the_middle_verifies_without_claiming_to_be_the_start() {
    let (rs, pk) = log();
    assert!(
        verify_chain(&rs[1..], &pk, true).is_err(),
        "it is not the genesis"
    );
    assert!(
        verify_chain(&rs[1..], &pk, false).is_ok(),
        "but it is a valid run"
    );
}

#[test]
fn receipts_survive_a_json_round_trip_exactly() {
    // The CLI reads JSON Lines. If serialization lost a byte, every
    // signature would fail for the wrong reason and nobody would trust the
    // tool that reported it.
    let (rs, pk) = log();
    let lines: Vec<String> = rs
        .iter()
        .map(|r| serde_json::to_string(r).expect("serialize"))
        .collect();
    let back: Vec<Receipt> = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("deserialize"))
        .collect();

    assert_eq!(back, rs);
    assert!(verify_chain(&back, &pk, true).is_ok());
}

#[test]
fn a_resumed_chain_links_to_what_came_before() {
    let (rs, pk) = log();
    let last = rs.last().expect("non-empty");
    let mut resumed = Signer::resume(key(1), last);
    let next = resumed.issue("i4", "felix", "a", "p", usd(1), &allow(), POLICY, NOW);

    let mut all = rs.clone();
    all.push(next);
    assert!(
        verify_chain(&all, &pk, true).is_ok(),
        "a restart must not break the chain"
    );
}
