//! Conformance vectors for the x402 `exact` scheme.
//!
//! Every case here is built from a fixed private key and signed for real, so
//! the happy path is a genuinely valid signature rather than a fixture that
//! merely looks like one. The adversarial cases are then derived from it by
//! changing exactly one thing.
//!
//! The generated vectors are written to `vectors/x402/vectors.json` when run
//! with `QUAESTOR_BLESS=1`. That file is the contract the TypeScript and
//! Python verifiers will be held to — if all three don't agree byte for
//! byte, the multi-language claim is decoration.

// Integration tests are their own crate, so the workspace's strict lints
// apply here too. Test code is allowed to panic loudly on a broken fixture —
// that is the failure signal. Library code is not.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use k256::ecdsa::SigningKey;
use quaestor_verify::eip712::{signing_digest, Address, Domain, TransferWithAuthorization};
use quaestor_verify::x402::types::{
    ExactEvmAuthorization, ExactEvmPayload, PaymentPayload, PaymentRequirements,
};
use quaestor_verify::x402::{
    verify_exact_evm, AssetRegistry, AssetSpec, InMemoryNonceStore, VerifiedPayment,
};
use quaestor_verify::VerifyError;

use quaestor_core::Currency;

// A fixed key, so vectors are reproducible. Obviously not a secret.
const PAYER_SK: [u8; 32] = [0x4c; 32];

const NETWORK: &str = "eip155:8453";
const USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MERCHANT: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const CHAIN_ID: u64 = 8453;

const VALID_AFTER: u64 = 1_772_000_000;
const VALID_BEFORE: u64 = 1_772_000_600;
const NOW: u64 = 1_772_000_300;
const AMOUNT: &str = "10000"; // 0.01 USDC at 6 decimals

fn registry() -> AssetRegistry {
    AssetRegistry::new().insert(
        NETWORK,
        USDC,
        AssetSpec {
            currency: Currency::USDC,
            eip712_name: "USD Coin".into(),
            eip712_version: "2".into(),
            chain_id: CHAIN_ID,
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn parse_addr(s: &str) -> Address {
    let body = s.trim_start_matches("0x");
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&PAYER_SK.into()).expect("valid key")
}

fn payer_address() -> Address {
    // Derive it the same way the verifier does, so the fixture cannot drift
    // from the implementation.
    let sk = signing_key();
    let point = sk.verifying_key().to_encoded_point(false);
    let hash = quaestor_verify::eip712::keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    out
}

fn requirements() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".into(),
        network: NETWORK.into(),
        amount: AMOUNT.into(),
        asset: USDC.into(),
        pay_to: MERCHANT.into(),
        max_timeout_seconds: Some(60),
        extra: Some(serde_json::json!({ "name": "USD Coin", "version": "2" })),
    }
}

/// Build a signed payload. `mutate` runs on the authorization *after*
/// signing, so a mutation produces a valid signature over different data —
/// which is exactly the attack we care about.
fn signed_payload(mutate: impl FnOnce(&mut ExactEvmAuthorization)) -> PaymentPayload {
    let payer = payer_address();
    let auth = TransferWithAuthorization {
        from: payer,
        to: parse_addr(MERCHANT),
        value: 10_000,
        valid_after: VALID_AFTER,
        valid_before: VALID_BEFORE,
        nonce: [0x7f; 32],
    };
    let domain = Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: CHAIN_ID,
        verifying_contract: parse_addr(USDC),
    };
    let digest = signing_digest(&domain, &auth);
    let (sig, recid) = signing_key()
        .sign_prehash_recoverable(&digest)
        .expect("sign");
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recid.to_byte() + 27);

    let mut wire = ExactEvmAuthorization {
        from: hex(&payer),
        to: MERCHANT.to_string(),
        value: "10000".into(),
        valid_after: VALID_AFTER.to_string(),
        valid_before: VALID_BEFORE.to_string(),
        nonce: hex(&[0x7f; 32]),
    };
    mutate(&mut wire);

    PaymentPayload {
        x402_version: 2,
        accepted: requirements(),
        payload: ExactEvmPayload {
            signature: hex(&sig_bytes),
            authorization: wire,
        },
    }
}

fn run(payload: &PaymentPayload, now: u64) -> Result<VerifiedPayment, VerifyError> {
    let mut nonces = InMemoryNonceStore::default();
    verify_exact_evm(payload, &requirements(), &registry(), &mut nonces, now)
}

// ---------------------------------------------------------------------------

#[test]
fn a_correctly_signed_payment_verifies() {
    let ok = run(&signed_payload(|_| {}), NOW).expect("should verify");
    assert_eq!(ok.payer, payer_address());
    assert_eq!(ok.payee, parse_addr(MERCHANT));
    assert_eq!(ok.amount.minor(), 10_000);
    assert_eq!(ok.amount.currency(), Currency::USDC);
}

#[test]
fn redirecting_the_payment_is_refused_even_though_the_signature_is_valid() {
    // The whole point. This payload carries a real signature made by the
    // real payer — over an authorization paying somebody else. A verifier
    // that only checks "is the signature valid" accepts this.
    let attacker = "0xdeadBEEFdeadbeefDEADbeefdeadBEEFdeadBEEF";
    let p = signed_payload(|a| a.to = attacker.into());
    assert!(matches!(
        run(&p, NOW),
        Err(VerifyError::RecipientMismatch { .. })
    ));
}

#[test]
fn changing_the_amount_is_refused() {
    let p = signed_payload(|a| a.value = "99999999".into());
    assert!(matches!(
        run(&p, NOW),
        Err(VerifyError::AmountMismatch { .. })
    ));
}

#[test]
fn tampering_with_a_signed_field_breaks_recovery() {
    // Same payee and amount as demanded, so the binding checks pass — but
    // the nonce differs from what was signed, so the digest differs, so the
    // signature recovers to a stranger.
    let p = signed_payload(|a| a.nonce = hex(&[0x01; 32]));
    assert!(matches!(
        run(&p, NOW),
        Err(VerifyError::SignerMismatch { .. })
    ));
}

#[test]
fn claiming_to_be_someone_else_is_refused() {
    let p = signed_payload(|a| a.from = "0x1111111111111111111111111111111111111111".into());
    assert!(matches!(
        run(&p, NOW),
        Err(VerifyError::SignerMismatch { .. })
    ));
}

#[test]
fn an_expired_authorization_is_refused() {
    assert!(matches!(
        run(&signed_payload(|_| {}), VALID_BEFORE + 1),
        Err(VerifyError::Expired { .. })
    ));
}

#[test]
fn an_authorization_from_the_future_is_refused() {
    assert!(matches!(
        run(&signed_payload(|_| {}), VALID_AFTER - 1),
        Err(VerifyError::NotYetValid { .. })
    ));
}

#[test]
fn the_boundaries_of_the_validity_window_are_inclusive() {
    assert!(
        run(&signed_payload(|_| {}), VALID_AFTER).is_ok(),
        "validAfter should be inclusive"
    );
    assert!(
        run(&signed_payload(|_| {}), VALID_BEFORE).is_ok(),
        "validBefore should be inclusive"
    );
}

#[test]
fn an_inverted_window_is_refused_rather_than_silently_never_valid() {
    let p = signed_payload(|a| {
        a.valid_after = "2000".into();
        a.valid_before = "1000".into();
    });
    assert!(matches!(
        run(&p, 1500),
        Err(VerifyError::InvertedWindow { .. })
    ));
}

#[test]
fn the_same_authorization_cannot_be_used_twice() {
    let p = signed_payload(|_| {});
    let mut nonces = InMemoryNonceStore::default();
    assert!(verify_exact_evm(&p, &requirements(), &registry(), &mut nonces, NOW).is_ok());
    assert!(matches!(
        verify_exact_evm(&p, &requirements(), &registry(), &mut nonces, NOW),
        Err(VerifyError::NonceReplayed)
    ));
}

#[test]
fn a_rejected_payload_does_not_burn_the_nonce() {
    // Otherwise an attacker who can see a payer's nonce can grief them by
    // replaying a broken variant until the real payment is refused.
    let mut nonces = InMemoryNonceStore::default();
    let bad = signed_payload(|a| a.value = "1".into());
    assert!(verify_exact_evm(&bad, &requirements(), &registry(), &mut nonces, NOW).is_err());

    let good = signed_payload(|_| {});
    assert!(
        verify_exact_evm(&good, &requirements(), &registry(), &mut nonces, NOW).is_ok(),
        "a failed attempt must not consume the nonce"
    );
}

#[test]
fn an_unknown_token_fails_closed() {
    let mut nonces = InMemoryNonceStore::default();
    let mut req = requirements();
    req.asset = "0x0000000000000000000000000000000000000bad".into();
    assert!(matches!(
        verify_exact_evm(
            &signed_payload(|_| {}),
            &req,
            &AssetRegistry::new(),
            &mut nonces,
            NOW
        ),
        Err(VerifyError::UnknownAsset { .. })
    ));
}

#[test]
fn a_signature_for_a_different_chain_does_not_verify_here() {
    // Cross-chain replay. Same payer, same amount, same merchant, signed
    // against a testnet domain; our registry says mainnet.
    let payer = payer_address();
    let auth = TransferWithAuthorization {
        from: payer,
        to: parse_addr(MERCHANT),
        value: 10_000,
        valid_after: VALID_AFTER,
        valid_before: VALID_BEFORE,
        nonce: [0x7f; 32],
    };
    let testnet = Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: 84532,
        verifying_contract: parse_addr(USDC),
    };
    let (sig, recid) = signing_key()
        .sign_prehash_recoverable(&signing_digest(&testnet, &auth))
        .expect("sign");
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recid.to_byte() + 27);

    let mut p = signed_payload(|_| {});
    p.payload.signature = hex(&sig_bytes);

    assert!(matches!(
        run(&p, NOW),
        Err(VerifyError::SignerMismatch { .. })
    ));
}

#[test]
fn malformed_signatures_are_refused_without_panicking() {
    for (label, sig) in [
        ("empty", ""),
        ("too short", "0xdead"),
        (
            "64 bytes, no recovery id",
            &format!("0x{}", "11".repeat(64)),
        ),
        ("bad recovery id", &format!("0x{}ff", "11".repeat(64))),
        ("not hex", &format!("0x{}zz", "11".repeat(64))),
        ("all zeroes", &format!("0x{}1b", "00".repeat(64))),
    ] {
        let mut p = signed_payload(|_| {});
        p.payload.signature = sig.to_string();
        assert!(run(&p, NOW).is_err(), "should refuse {label}");
    }
}

#[test]
fn a_wrong_protocol_version_is_refused() {
    let mut p = signed_payload(|_| {});
    p.x402_version = 1;
    assert!(matches!(
        run(&p, NOW),
        Err(VerifyError::UnsupportedVersion(1))
    ));
}

#[test]
fn verification_is_a_pure_function_of_its_inputs() {
    // Same inputs, same answer — the property the whole audit story rests on.
    let p = signed_payload(|_| {});
    let a = run(&p, NOW).expect("verifies");
    let b = run(&p, NOW).expect("verifies");
    assert_eq!(a, b);
}

/// Writes the vector file used to hold other language implementations to the
/// same behaviour. Run with `QUAESTOR_BLESS=1 cargo test -p quaestor-verify`.
#[test]
fn emit_conformance_vectors() {
    let cases = vec![
        ("valid", signed_payload(|_| {}), NOW, "accept"),
        (
            "recipient_redirected",
            signed_payload(|a| a.to = "0xdeadBEEFdeadbeefDEADbeefdeadBEEFdeadBEEF".into()),
            NOW,
            "reject:recipient_mismatch",
        ),
        (
            "amount_inflated",
            signed_payload(|a| a.value = "99999999".into()),
            NOW,
            "reject:amount_mismatch",
        ),
        (
            "nonce_tampered",
            signed_payload(|a| a.nonce = hex(&[0x01; 32])),
            NOW,
            "reject:signer_mismatch",
        ),
        (
            "payer_spoofed",
            signed_payload(|a| a.from = "0x1111111111111111111111111111111111111111".into()),
            NOW,
            "reject:signer_mismatch",
        ),
        (
            "expired",
            signed_payload(|_| {}),
            VALID_BEFORE + 1,
            "reject:expired",
        ),
        (
            "not_yet_valid",
            signed_payload(|_| {}),
            VALID_AFTER - 1,
            "reject:not_yet_valid",
        ),
        (
            "window_boundary_start",
            signed_payload(|_| {}),
            VALID_AFTER,
            "accept",
        ),
        (
            "window_boundary_end",
            signed_payload(|_| {}),
            VALID_BEFORE,
            "accept",
        ),
    ];

    let json = serde_json::json!({
        "description": "x402 v2 exact-scheme conformance vectors. Every implementation must agree.",
        "requirements": requirements(),
        "asset": { "network": NETWORK, "address": USDC, "decimals": 6,
                   "eip712": { "name": "USD Coin", "version": "2", "chainId": CHAIN_ID } },
        "cases": cases.iter().map(|(name, payload, now, expect)| serde_json::json!({
            "name": name, "nowSeconds": now, "expect": expect, "payload": payload,
        })).collect::<Vec<_>>(),
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/x402/vectors.json"
    );
    let rendered = format!("{}\n", serde_json::to_string_pretty(&json).expect("render"));

    if std::env::var("QUAESTOR_BLESS").is_ok() {
        std::fs::write(path, &rendered).expect("write vectors");
        return;
    }
    let committed =
        std::fs::read_to_string(path).expect("vectors.json missing; run with QUAESTOR_BLESS=1");
    assert_eq!(
        committed, rendered,
        "vectors have drifted; re-bless if intended"
    );
}
