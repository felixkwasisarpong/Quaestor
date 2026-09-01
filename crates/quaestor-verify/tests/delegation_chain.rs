//! Delegation chain attacks, and whether they work.
//!
//! Each test is one thing an attacker would try. Chains are built and signed
//! with real Ed25519 keys, so a passing test means the check actually holds
//! rather than that a fixture happened to be shaped right.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use quaestor_core::{Currency, Money, PrincipalId, Rail, Timestamp};
use quaestor_verify::mandate::{
    verify_chain, ChainError, Constraint, Mandate, PublicKey, Scope, Widening, MAX_CHAIN_DEPTH,
};

const NOW: Timestamp = Timestamp(1_772_000_000_000);
const HORIZON: Timestamp = Timestamp(1_772_100_000_000);

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> PublicKey {
    k.verifying_key().to_bytes()
}

fn only(items: &[&str]) -> Constraint<String> {
    Constraint::Only(items.iter().map(|s| (*s).to_owned()).collect())
}

fn scope(max_minor: i128, payees: &[&str]) -> Scope {
    Scope {
        max_amount: Money::new(max_minor, Currency::USD),
        payees: only(payees),
        categories: Constraint::Any,
        rails: Constraint::Only([Rail::X402].into_iter().collect()),
        not_after: HORIZON,
    }
}

fn principal() -> PrincipalId {
    PrincipalId::new("felix").expect("valid")
}

/// Build and sign one link.
fn link(issuer: &SigningKey, subject: &SigningKey, scope: Scope, nonce: u8) -> Mandate {
    let mut m = Mandate {
        issuer: pk(issuer),
        subject: pk(subject),
        principal: principal(),
        scope,
        nonce: [nonce; 16],
        signature: [0u8; 64],
    };
    m.signature = issuer.sign(&m.signing_bytes()).to_bytes();
    m
}

/// felix → agent → sub-agent, narrowing at each step.
fn honest_chain() -> (Vec<Mandate>, Vec<PublicKey>) {
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let chain = vec![
        link(
            &root,
            &agent,
            scope(50_000, &["shop.example", "api.example"]),
            1,
        ),
        link(&agent, &sub, scope(10_000, &["shop.example"]), 2),
    ];
    (chain, vec![pk(&root)])
}

// ---------------------------------------------------------------------------

#[test]
fn an_honest_chain_confers_the_narrowest_authority_in_it() {
    let (chain, roots) = honest_chain();
    let auth = verify_chain(&chain, &roots, NOW).expect("should verify");

    assert_eq!(auth.holder, pk(&key(3)), "the leaf holds the authority");
    assert_eq!(auth.principal, principal());
    assert_eq!(
        auth.scope.max_amount.minor(),
        10_000,
        "the tighter ceiling wins"
    );
    assert_eq!(auth.scope.payees, only(&["shop.example"]));
}

#[test]
fn a_sub_agent_cannot_grant_itself_more_than_it_was_given() {
    // The attack the whole module exists for. The sub-agent holds a genuine
    // delegation for $100 and issues itself one for $500 — correctly signed
    // with its own key, structurally perfect.
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let chain = vec![
        link(&root, &agent, scope(10_000, &["shop.example"]), 1),
        link(&agent, &sub, scope(50_000, &["shop.example"]), 2),
    ];
    match verify_chain(&chain, &[pk(&root)], NOW) {
        Err(ChainError::ScopeWidened {
            index: 1,
            widening: Widening::AmountRaised { .. },
        }) => {}
        other => panic!("expected a widened ceiling to be caught, got {other:?}"),
    }
}

#[test]
fn a_sub_agent_cannot_add_a_payee_it_was_never_granted() {
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let chain = vec![
        link(&root, &agent, scope(50_000, &["shop.example"]), 1),
        link(
            &agent,
            &sub,
            scope(10_000, &["shop.example", "attacker.example"]),
            2,
        ),
    ];
    assert!(matches!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::ScopeWidened {
            widening: Widening::PayeesWidened,
            ..
        })
    ));
}

#[test]
fn dropping_the_payee_restriction_entirely_is_caught() {
    // The subtle one: not adding a payee, but removing the constraint. A
    // naive subset check on the *listed* payees sees an empty diff and lets
    // this through with unlimited reach.
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let mut wide = scope(10_000, &[]);
    wide.payees = Constraint::Any;
    let chain = vec![
        link(&root, &agent, scope(50_000, &["shop.example"]), 1),
        link(&agent, &sub, wide, 2),
    ];
    assert!(matches!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::ScopeWidened {
            widening: Widening::PayeesWidened,
            ..
        })
    ));
}

#[test]
fn a_chain_that_vouches_for_its_own_root_proves_nothing() {
    let stranger = key(9);
    let agent = key(2);
    let chain = vec![link(&stranger, &agent, scope(50_000, &["shop.example"]), 1)];
    assert_eq!(
        verify_chain(&chain, &[pk(&key(1))], NOW),
        Err(ChainError::UntrustedRoot)
    );
}

#[test]
fn a_link_issued_by_a_key_that_never_received_authority_is_rejected() {
    // Chain is root → agent, then a *different* key issues to the sub-agent
    // with a perfectly valid signature of its own.
    let root = key(1);
    let agent = key(2);
    let outsider = key(7);
    let sub = key(3);
    let chain = vec![
        link(&root, &agent, scope(50_000, &["shop.example"]), 1),
        link(&outsider, &sub, scope(10_000, &["shop.example"]), 2),
    ];
    assert_eq!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::Disconnected { index: 1 })
    );
}

#[test]
fn tampering_with_a_scope_after_signing_breaks_the_signature() {
    let (mut chain, roots) = honest_chain();
    chain[1].scope.max_amount = Money::new(999_999, Currency::USD);
    assert_eq!(
        verify_chain(&chain, &roots, NOW),
        Err(ChainError::BadSignature)
    );
}

#[test]
fn tampering_with_the_principal_breaks_the_signature() {
    let (mut chain, roots) = honest_chain();
    chain[0].principal = PrincipalId::new("someone-else").expect("valid");
    assert_eq!(
        verify_chain(&chain, &roots, NOW),
        Err(ChainError::BadSignature)
    );
}

#[test]
fn a_link_cannot_switch_the_liable_principal() {
    // Signed correctly, but claiming a different person is on the hook.
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let mut second = Mandate {
        issuer: pk(&agent),
        subject: pk(&sub),
        principal: PrincipalId::new("someone-else").expect("valid"),
        scope: scope(10_000, &["shop.example"]),
        nonce: [2u8; 16],
        signature: [0u8; 64],
    };
    second.signature = agent.sign(&second.signing_bytes()).to_bytes();

    let chain = vec![
        link(&root, &agent, scope(50_000, &["shop.example"]), 1),
        second,
    ];
    assert_eq!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::PrincipalChanged { index: 1 })
    );
}

#[test]
fn an_expired_link_invalidates_the_chain() {
    let (chain, roots) = honest_chain();
    let after = Timestamp(HORIZON.0 + 1);
    assert!(matches!(
        verify_chain(&chain, &roots, after),
        Err(ChainError::Expired { .. })
    ));
}

#[test]
fn a_child_cannot_outlive_its_parent() {
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let mut longer = scope(10_000, &["shop.example"]);
    longer.not_after = Timestamp(HORIZON.0 + 1_000_000);
    let chain = vec![
        link(&root, &agent, scope(50_000, &["shop.example"]), 1),
        link(&agent, &sub, longer, 2),
    ];
    assert!(matches!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::ScopeWidened {
            widening: Widening::ExpiryExtended { .. },
            ..
        })
    ));
}

#[test]
fn a_key_may_not_appear_twice_in_a_chain() {
    // Laundering authority back to an earlier holder, or a plain loop.
    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let chain = vec![
        link(&root, &agent, scope(50_000, &["shop.example"]), 1),
        link(&agent, &sub, scope(20_000, &["shop.example"]), 2),
        link(&sub, &agent, scope(10_000, &["shop.example"]), 3),
    ];
    assert!(matches!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::Cycle { .. })
    ));
}

#[test]
fn an_unbounded_chain_is_refused_before_it_is_verified() {
    // Each link is a signature check. Without a depth cap this is a cheap
    // way to burn CPU in the component that must stay responsive.
    let root = key(1);
    let mut chain = Vec::new();
    let mut issuer = root.clone();
    for i in 0..(MAX_CHAIN_DEPTH + 1) {
        let subject = key(u8::try_from(i).unwrap() + 20);
        chain.push(link(
            &issuer,
            &subject,
            scope(10_000, &["shop.example"]),
            i as u8,
        ));
        issuer = subject;
    }
    assert!(matches!(
        verify_chain(&chain, &[pk(&root)], NOW),
        Err(ChainError::TooDeep { .. })
    ));
}

#[test]
fn an_empty_chain_authorizes_nothing() {
    assert_eq!(
        verify_chain(&[], &[pk(&key(1))], NOW),
        Err(ChainError::Empty)
    );
}

#[test]
fn a_single_link_chain_is_valid() {
    let root = key(1);
    let agent = key(2);
    let chain = vec![link(&root, &agent, scope(50_000, &["shop.example"]), 1)];
    let auth = verify_chain(&chain, &[pk(&root)], NOW).expect("verifies");
    assert_eq!(auth.holder, pk(&agent));
    assert_eq!(auth.scope.max_amount.minor(), 50_000);
}

#[test]
fn the_chain_id_changes_when_any_part_of_the_chain_does() {
    let (chain, roots) = honest_chain();
    let a = verify_chain(&chain, &roots, NOW)
        .expect("verifies")
        .chain_id;

    let root = key(1);
    let agent = key(2);
    let sub = key(3);
    let other = vec![
        link(
            &root,
            &agent,
            scope(50_000, &["shop.example", "api.example"]),
            1,
        ),
        link(&agent, &sub, scope(9_999, &["shop.example"]), 2),
    ];
    let b = verify_chain(&other, &roots, NOW)
        .expect("verifies")
        .chain_id;
    assert_ne!(a, b, "a different chain must not share an identifier");
}

#[test]
fn verification_is_a_pure_function_of_its_inputs() {
    let (chain, roots) = honest_chain();
    assert_eq!(
        verify_chain(&chain, &roots, NOW).expect("verifies"),
        verify_chain(&chain, &roots, NOW).expect("verifies")
    );
}

#[test]
fn signing_bytes_cannot_be_confused_by_shifting_a_field_boundary() {
    // Without length prefixes, ("ab","c") and ("a","bc") concatenate the
    // same, and an attacker can move characters between adjacent fields
    // while keeping the signature valid.
    let root = key(1);
    let a = link(&root, &key(2), scope(10_000, &["ab", "c"]), 1);
    let b = link(&root, &key(2), scope(10_000, &["a", "bc"]), 1);
    assert_ne!(a.signing_bytes(), b.signing_bytes());
}

#[test]
fn a_mandate_signature_cannot_be_replayed_as_another_structure() {
    // The domain tag. Signing bytes must start with something only mandates use,
    // so a signature harvested here cannot be presented elsewhere.
    let m = link(&key(1), &key(2), scope(10_000, &["shop.example"]), 1);
    let bytes = m.signing_bytes();
    let tag = b"quaestor.mandate.v1";
    assert!(
        bytes.windows(tag.len()).any(|w| w == tag),
        "signing bytes must carry a domain tag"
    );
}

#[test]
fn constraint_sets_serialize_in_a_stable_order() {
    // If iteration order varied, the same grant would sign differently on
    // each run and nothing would verify twice.
    let root = key(1);
    let mut forward = BTreeSet::new();
    forward.insert("a.example".to_owned());
    forward.insert("z.example".to_owned());
    let mut backward = BTreeSet::new();
    backward.insert("z.example".to_owned());
    backward.insert("a.example".to_owned());

    let mut s1 = scope(10_000, &[]);
    s1.payees = Constraint::Only(forward);
    let mut s2 = scope(10_000, &[]);
    s2.payees = Constraint::Only(backward);

    assert_eq!(
        link(&root, &key(2), s1, 1).signing_bytes(),
        link(&root, &key(2), s2, 1).signing_bytes()
    );
}
