//! Fixtures for the gateway tests.
//!
//! Payments are signed for real with a fixed secp256k1 key, and mandates
//! with a fixed Ed25519 one. A fixture that merely *looks* like a valid
//! payment would make every one of these tests pass for the wrong reason.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey as EdKey};
use k256::ecdsa::SigningKey;
use quaestor_core::{AgentId, Currency, Money, PrincipalId, Rail, Timestamp};
use quaestor_policy::Policy;
use quaestor_proxy::{Caller, Config, Gateway, Holds, Identities, InMemoryHolds, ReserveRequest};
use quaestor_receipt::Signer;
use quaestor_verify::eip712::{
    keccak256, signing_digest, Address, Domain, TransferWithAuthorization,
};
use quaestor_verify::mandate::{Constraint, Mandate, PublicKey, Scope};
use quaestor_verify::x402::types::{ExactEvmAuthorization, ExactEvmPayload};
use quaestor_verify::x402::{
    AssetRegistry, AssetSpec, InMemoryNonceStore, PaymentPayload, PaymentRequirements,
};

pub const PAYER_SK: [u8; 32] = [0x4c; 32];
pub const NETWORK: &str = "eip155:8453";
pub const USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
pub const MERCHANT: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
pub const ATTACKER: &str = "0xBADbadBADbadBADbadBADbadBADbadBADbadBAD0";
pub const CHAIN_ID: u64 = 8453;

/// Milliseconds. The seconds form is what x402 signs against.
pub const NOW: Timestamp = Timestamp(1_772_000_300_000);
pub const VALID_AFTER: u64 = 1_772_000_000;
pub const VALID_BEFORE: u64 = 1_772_000_600;

pub const TOKEN: &str = "sk_felix_test";
pub const OTHER_TOKEN: &str = "sk_ama_test";
pub const TARGET: &str = "http://origin.example/report";

/// 5 USDC daily, 20 USDC monthly. Escalates above 2 USDC unattended, and
/// blocks the attacker's address outright.
///
/// The blocked address is interpolated from [`ATTACKER`] rather than typed
/// out, so the test cannot quietly stop testing anything because two long
/// hex strings drifted apart by one character.
pub fn policy_toml() -> String {
    format!(
        r#"
version = 1
currency = "USDC"

[defaults]
unattended_limit = "2.000000 USDC"
escalate_first_seen_payee = false
hold_ttl = "5m"

[[budgets]]
window = "24h"
limit = "5.000000 USDC"

[[budgets]]
window = "30d"
limit = "20.000000 USDC"

[payees]
deny = ["{}"]
"#,
        ATTACKER.to_ascii_lowercase()
    )
}

pub fn policy() -> Policy {
    Policy::parse(&policy_toml()).expect("the fixture policy must parse")
}

/// The payee id the gateway derives from an address: lowercase, `0x`-first.
pub fn payee_id(address: &str) -> String {
    address.to_ascii_lowercase()
}

pub fn registry() -> AssetRegistry {
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

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn addr(s: &str) -> Address {
    let body = s.trim_start_matches("0x");
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn payer_key() -> SigningKey {
    SigningKey::from_bytes(&PAYER_SK.into()).expect("valid key")
}

pub fn payer_address() -> Address {
    let point = payer_key().verifying_key().to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    out
}

// -- x402 -------------------------------------------------------------------

pub fn requirements(pay_to: &str, atomic: u128) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".into(),
        network: NETWORK.into(),
        amount: atomic.to_string(),
        asset: USDC.into(),
        pay_to: pay_to.to_owned(),
        max_timeout_seconds: Some(60),
        extra: Some(serde_json::json!({ "name": "USD Coin", "version": "2" })),
    }
}

/// The body an origin returns with its `402`.
pub fn challenge_body(pay_to: &str, atomic: u128) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "x402Version": 2,
        "accepts": [requirements(pay_to, atomic)],
    }))
    .expect("serialize")
}

/// A genuinely signed payment.
///
/// `accepted` is what the payload *claims* it is satisfying. It is separate
/// from `pay_to` on purpose: the interesting attack is a payload that is
/// entirely self-consistent and pays the wrong person.
pub fn payment(pay_to: &str, atomic: u128, nonce: u8, accepted: PaymentRequirements) -> String {
    let payer = payer_address();
    let auth = TransferWithAuthorization {
        from: payer,
        to: addr(pay_to),
        value: atomic,
        valid_after: VALID_AFTER,
        valid_before: VALID_BEFORE,
        nonce: [nonce; 32],
    };
    let domain = Domain {
        name: "USD Coin".into(),
        version: "2".into(),
        chain_id: CHAIN_ID,
        verifying_contract: addr(USDC),
    };
    let digest = signing_digest(&domain, &auth);
    let (sig, recid) = payer_key().sign_prehash_recoverable(&digest).expect("sign");
    let mut sig_bytes = sig.to_bytes().to_vec();
    sig_bytes.push(recid.to_byte() + 27);

    let payload = PaymentPayload {
        x402_version: 2,
        accepted,
        payload: ExactEvmPayload {
            signature: hex(&sig_bytes),
            authorization: ExactEvmAuthorization {
                from: hex(&payer),
                to: pay_to.to_owned(),
                value: atomic.to_string(),
                valid_after: VALID_AFTER.to_string(),
                valid_before: VALID_BEFORE.to_string(),
                nonce: hex(&[nonce; 32]),
            },
        },
    };
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&payload).expect("serialize"))
}

/// The ordinary case: pays the merchant the demanded amount, and says so.
pub fn honest_payment(atomic: u128, nonce: u8) -> String {
    payment(MERCHANT, atomic, nonce, requirements(MERCHANT, atomic))
}

pub fn intent_id_for(nonce: u8) -> String {
    let mut s = String::from("x402:");
    for _ in 0..32 {
        s.push_str(&format!("{nonce:02x}"));
    }
    s
}

// -- mandates ---------------------------------------------------------------

pub fn ed_key(seed: u8) -> EdKey {
    EdKey::from_bytes(&[seed; 32])
}

pub fn ed_pk(k: &EdKey) -> PublicKey {
    k.verifying_key().to_bytes()
}

pub fn scope(max_atomic: i128, payees: Constraint<String>) -> Scope {
    Scope {
        max_amount: Money::new(max_atomic, Currency::USDC),
        payees,
        categories: Constraint::Any,
        rails: Constraint::Only([Rail::X402].into_iter().collect()),
        not_after: Timestamp(NOW.0 + 86_400_000),
    }
}

pub fn only(items: &[&str]) -> Constraint<String> {
    Constraint::Only(items.iter().map(|s| (*s).to_owned()).collect())
}

pub fn mandate_chain(links: &[(EdKey, EdKey, Scope)]) -> String {
    let chain: Vec<Mandate> = links
        .iter()
        .enumerate()
        .map(|(i, (issuer, subject, sc))| {
            let mut m = Mandate {
                issuer: ed_pk(issuer),
                subject: ed_pk(subject),
                principal: PrincipalId::new("felix").expect("valid"),
                scope: sc.clone(),
                nonce: [u8::try_from(i).unwrap_or(0); 16],
                signature: [0u8; 64],
            };
            m.signature = issuer.sign(&m.signing_bytes()).to_bytes();
            m
        })
        .collect();
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&chain).expect("serialize"))
}

// -- the gateway under test -------------------------------------------------

pub fn caller(principal: &str, agent: &str, sc: Scope, roots: Vec<PublicKey>) -> Caller {
    Caller {
        principal: PrincipalId::new(principal).expect("valid"),
        agent: AgentId::new(agent).expect("valid"),
        scope: sc,
        root_keys: roots,
    }
}

/// A gateway with a generous default authority, so that a test which is
/// about budgets is not accidentally about scope.
pub fn identities() -> Identities {
    Identities::new()
        .insert(
            TOKEN,
            caller(
                "felix",
                "shopper",
                scope(50_000_000, Constraint::Any),
                Vec::new(),
            ),
        )
        .insert(
            OTHER_TOKEN,
            caller(
                "ama",
                "shopper",
                scope(50_000_000, Constraint::Any),
                Vec::new(),
            ),
        )
}

pub fn gateway_with(holds: Box<dyn Holds>, identities: Identities) -> Gateway {
    Gateway::new(
        Config::new(policy(), registry()),
        identities,
        holds,
        Box::new(InMemoryNonceStore::default()),
        Signer::new(ed_key(0xAA)),
    )
}

pub fn gateway() -> Gateway {
    gateway_with(Box::new(InMemoryHolds::new()), identities())
}

/// An [`InMemoryHolds`] the test keeps a handle on.
///
/// The workspace forbids `unsafe`, so a test that wants to look at the
/// ledger after a decision shares it properly rather than smuggling a
/// pointer past the borrow checker. The lock is uncontended: these tests are
/// single-threaded and the sharing exists only to let the assertion see what
/// the gateway did.
#[derive(Debug, Clone, Default)]
pub struct SharedHolds(std::sync::Arc<std::sync::Mutex<InMemoryHolds>>);

impl SharedHolds {
    pub fn new() -> SharedHolds {
        SharedHolds::default()
    }

    pub fn state_of(&self, intent_id: &str) -> Option<quaestor_ledger::HoldState> {
        let guard = self.0.lock().expect("not poisoned");
        guard
            .rows()
            .iter()
            .find(|r| r.intent_id == intent_id)
            .map(|r| r.state)
    }

    pub fn row_count(&self) -> usize {
        self.0.lock().expect("not poisoned").rows().len()
    }
}

impl Holds for SharedHolds {
    fn reserve(
        &mut self,
        req: &ReserveRequest<'_>,
    ) -> Result<quaestor_ledger::Reservation, quaestor_proxy::HoldsError> {
        self.0.lock().expect("not poisoned").reserve(req)
    }
    fn capture(
        &mut self,
        intent_id: &str,
        now: Timestamp,
    ) -> Result<quaestor_ledger::HoldRecord, quaestor_proxy::HoldsError> {
        self.0.lock().expect("not poisoned").capture(intent_id, now)
    }
    fn release(
        &mut self,
        intent_id: &str,
        now: Timestamp,
    ) -> Result<quaestor_ledger::HoldRecord, quaestor_proxy::HoldsError> {
        self.0.lock().expect("not poisoned").release(intent_id, now)
    }
    fn spent_in_window(
        &mut self,
        principal: &str,
        currency: &str,
        window_ms: i64,
        now: Timestamp,
    ) -> Result<i128, quaestor_proxy::HoldsError> {
        self.0
            .lock()
            .expect("not poisoned")
            .spent_in_window(principal, currency, window_ms, now)
    }
}

/// A ledger that under-reports committed spend.
///
/// Not a hypothetical. Every snapshot the policy engine reads is a
/// photograph taken before the lock was taken, and a payment that commits in
/// between makes it wrong in exactly this direction. This double makes that
/// window infinitely wide so the consequence can be asserted.
#[derive(Debug)]
pub struct StaleSnapshotHolds {
    inner: InMemoryHolds,
}

impl StaleSnapshotHolds {
    pub fn new() -> StaleSnapshotHolds {
        StaleSnapshotHolds {
            inner: InMemoryHolds::new(),
        }
    }

    pub fn inner_mut(&mut self) -> &mut InMemoryHolds {
        &mut self.inner
    }
}

impl Holds for StaleSnapshotHolds {
    fn reserve(
        &mut self,
        req: &ReserveRequest<'_>,
    ) -> Result<quaestor_ledger::Reservation, quaestor_proxy::HoldsError> {
        self.inner.reserve(req)
    }
    fn capture(
        &mut self,
        intent_id: &str,
        now: Timestamp,
    ) -> Result<quaestor_ledger::HoldRecord, quaestor_proxy::HoldsError> {
        self.inner.capture(intent_id, now)
    }
    fn release(
        &mut self,
        intent_id: &str,
        now: Timestamp,
    ) -> Result<quaestor_ledger::HoldRecord, quaestor_proxy::HoldsError> {
        self.inner.release(intent_id, now)
    }
    /// The lie. Always reports an empty budget.
    fn spent_in_window(
        &mut self,
        _principal: &str,
        _currency: &str,
        _window_ms: i64,
        _now: Timestamp,
    ) -> Result<i128, quaestor_proxy::HoldsError> {
        Ok(0)
    }
}

/// A ledger that cannot be read at all.
#[derive(Debug, Default)]
pub struct UnreadableHolds;

impl Holds for UnreadableHolds {
    fn reserve(
        &mut self,
        _req: &ReserveRequest<'_>,
    ) -> Result<quaestor_ledger::Reservation, quaestor_proxy::HoldsError> {
        Err(quaestor_proxy::HoldsError::NoSuchHold(
            "database is down".into(),
        ))
    }
    fn capture(
        &mut self,
        _intent_id: &str,
        _now: Timestamp,
    ) -> Result<quaestor_ledger::HoldRecord, quaestor_proxy::HoldsError> {
        Err(quaestor_proxy::HoldsError::NoSuchHold(
            "database is down".into(),
        ))
    }
    fn release(
        &mut self,
        _intent_id: &str,
        _now: Timestamp,
    ) -> Result<quaestor_ledger::HoldRecord, quaestor_proxy::HoldsError> {
        Err(quaestor_proxy::HoldsError::NoSuchHold(
            "database is down".into(),
        ))
    }
    fn spent_in_window(
        &mut self,
        _principal: &str,
        _currency: &str,
        _window_ms: i64,
        _now: Timestamp,
    ) -> Result<i128, quaestor_proxy::HoldsError> {
        Err(quaestor_proxy::HoldsError::NoSuchHold(
            "database is down".into(),
        ))
    }
}

pub fn usdc(atomic: i128) -> Money {
    Money::new(atomic, Currency::USDC)
}
