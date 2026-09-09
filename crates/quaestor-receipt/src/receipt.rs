//! The receipt itself, and how it is signed.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use quaestor_core::{DenyReason, EscalationReason, Money, Timestamp, Verdict};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// What a chain's first receipt points back at. All zeroes: there is nothing
/// before it, and saying so explicitly is better than an `Option` that some
/// caller eventually unwraps into a silent gap.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

pub type PublicKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    #[error("signing key is not a valid Ed25519 key")]
    BadKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("receipt is signed by {actual}, not the expected {expected}")]
    WrongSigner { actual: String, expected: String },
}

/// The verdict, flattened for the record.
///
/// Deliberately not a re-export of [`Verdict`]. That type carries a live
/// `Hold` whose state changes after the decision; a receipt has to say what
/// was true at the moment of deciding and never move again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ReceiptVerdict {
    Allow,
    Deny { reasons: Vec<DenyReason> },
    Escalate { reasons: Vec<EscalationReason> },
}

impl ReceiptVerdict {
    pub fn from_verdict(v: &Verdict) -> ReceiptVerdict {
        match v {
            Verdict::Allow { .. } => ReceiptVerdict::Allow,
            Verdict::Deny { reasons } => ReceiptVerdict::Deny {
                reasons: reasons.clone(),
            },
            Verdict::Escalate { reasons, .. } => ReceiptVerdict::Escalate {
                reasons: reasons.clone(),
            },
        }
    }

    fn tag(&self) -> &'static str {
        match self {
            ReceiptVerdict::Allow => "allow",
            ReceiptVerdict::Deny { .. } => "deny",
            ReceiptVerdict::Escalate { .. } => "escalate",
        }
    }
}

/// One decision, recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Position in the chain. Starts at zero.
    pub seq: u64,
    /// Hash of the previous receipt's signing bytes, or [`GENESIS_HASH`].
    #[serde(with = "hex32")]
    pub prev_hash: [u8; 32],

    pub intent_id: String,
    pub principal: String,
    pub agent: String,
    pub payee: String,
    pub amount: Money,

    pub verdict: ReceiptVerdict,

    /// Which rules produced this. Without it a receipt says what was decided
    /// but not what it was decided against, and "the policy at the time" is
    /// exactly what a dispute turns on.
    #[serde(with = "hex32")]
    pub policy_version: [u8; 32],

    /// The clock reading the decision was made against, not when this row
    /// was written. Replaying the decision needs the former.
    pub decided_at: Timestamp,

    #[serde(with = "hex32")]
    pub signer: PublicKey,
    #[serde(with = "hex64")]
    pub signature: [u8; 64],
}

impl Receipt {
    /// The exact bytes the signature covers.
    ///
    /// Length-prefixed and domain-tagged, same discipline as mandates: a
    /// signature over a receipt must never be presentable as a signature
    /// over anything else, and no attacker may shift a field boundary to
    /// move meaning between two adjacent values.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(320);
        push(&mut b, b"quaestor.receipt.v1");
        push(&mut b, &self.seq.to_be_bytes());
        push(&mut b, &self.prev_hash);
        push(&mut b, self.intent_id.as_bytes());
        push(&mut b, self.principal.as_bytes());
        push(&mut b, self.agent.as_bytes());
        push(&mut b, self.payee.as_bytes());
        push(&mut b, &self.amount.minor().to_be_bytes());
        push(&mut b, self.amount.currency().code().as_bytes());
        b.push(self.amount.currency().exponent());
        push(&mut b, &verdict_bytes(&self.verdict));
        push(&mut b, &self.policy_version);
        push(&mut b, &self.decided_at.as_millis().to_be_bytes());
        push(&mut b, &self.signer);
        b
    }

    /// This receipt's own hash, which the next one records as `prev_hash`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"quaestor.receipt.hash.v1");
        h.update(self.signing_bytes());
        h.finalize().into()
    }

    /// Check the signature. Does not check chain position; see
    /// [`crate::verify_chain`].
    pub fn verify_signature(&self) -> Result<(), ReceiptError> {
        let key = VerifyingKey::from_bytes(&self.signer).map_err(|_| ReceiptError::BadKey)?;
        key.verify(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ReceiptError::BadSignature)
    }
}

/// Issues receipts, keeping the chain linked.
#[derive(Debug)]
pub struct Signer {
    key: SigningKey,
    seq: u64,
    prev_hash: [u8; 32],
}

impl Signer {
    /// Begin a fresh chain.
    pub fn new(key: SigningKey) -> Signer {
        Signer {
            key,
            seq: 0,
            prev_hash: GENESIS_HASH,
        }
    }

    /// Continue an existing chain from its last receipt.
    pub fn resume(key: SigningKey, last: &Receipt) -> Signer {
        Signer {
            key,
            seq: last.seq.saturating_add(1),
            prev_hash: last.hash(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.verifying_key().to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        intent_id: &str,
        principal: &str,
        agent: &str,
        payee: &str,
        amount: Money,
        verdict: &Verdict,
        policy_version: [u8; 32],
        decided_at: Timestamp,
    ) -> Receipt {
        use ed25519_dalek::Signer as _;

        let mut r = Receipt {
            seq: self.seq,
            prev_hash: self.prev_hash,
            intent_id: intent_id.to_owned(),
            principal: principal.to_owned(),
            agent: agent.to_owned(),
            payee: payee.to_owned(),
            amount,
            verdict: ReceiptVerdict::from_verdict(verdict),
            policy_version,
            decided_at,
            signer: self.public_key(),
            signature: [0u8; 64],
        };
        r.signature = self.key.sign(&r.signing_bytes()).to_bytes();

        self.prev_hash = r.hash();
        self.seq = self.seq.saturating_add(1);
        r
    }
}

/// Deterministic bytes for a verdict, reasons included.
///
/// The reasons are part of what is signed. A receipt whose signature covered
/// only "denied" would let anyone rewrite *why* without breaking it, and the
/// why is the part a dispute is actually about.
fn verdict_bytes(v: &ReceiptVerdict) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    push(&mut b, v.tag().as_bytes());
    match v {
        ReceiptVerdict::Allow => {}
        ReceiptVerdict::Deny { reasons } => {
            push(&mut b, &u32_be(reasons.len()));
            for r in reasons {
                push(&mut b, json_of(r).as_bytes());
            }
        }
        ReceiptVerdict::Escalate { reasons } => {
            push(&mut b, &u32_be(reasons.len()));
            for r in reasons {
                push(&mut b, json_of(r).as_bytes());
            }
        }
    }
    b
}

/// Reasons are serialized through serde for the signing bytes. Their JSON is
/// produced from a tagged enum with a fixed field order, so it is stable for
/// a given value.
fn json_of<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "<unserializable>".to_owned())
}

fn u32_be(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap_or(u32::MAX).to_be_bytes()
}

fn push(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&u32_be(bytes.len()));
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::to_hex(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        super::from_hex::<32>(&s).map_err(serde::de::Error::custom)
    }
}

mod hex64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::to_hex(v))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        super::from_hex::<64>(&s).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn from_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = s.as_bytes();
    if bytes.len() != N.saturating_mul(2) {
        return Err(format!(
            "expected {N} bytes of hex, got {} chars",
            bytes.len()
        ));
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let text = core::str::from_utf8(pair).map_err(|e| e.to_string())?;
        *slot = u8::from_str_radix(text, 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
