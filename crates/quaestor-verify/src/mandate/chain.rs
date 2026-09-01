//! Delegation chains: who authorized whom, to do how much.
//!
//! A chain starts at a principal — a person or an organization holding a key
//! you already trust — and runs through one or more delegations to the agent
//! actually attempting to spend. Each link is signed by the party doing the
//! delegating, and each link narrows the authority.
//!
//! # What is signed
//!
//! Bytes, not objects. Signing a struct means agreeing on a serialization,
//! and two serializations that a human would call identical produce
//! different signatures. So [`Mandate::signing_bytes`] defines one explicit,
//! length-prefixed, deterministic encoding, and that is what gets signed and
//! checked. Nothing here re-serializes JSON and hopes the field order
//! matches.
//!
//! Every field is length-prefixed rather than concatenated, so that
//! `("ab", "c")` and `("a", "bc")` cannot hash the same. Without prefixes an
//! attacker can shift a boundary and move authority between fields.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use quaestor_core::{PrincipalId, Timestamp};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::mandate::scope::{Scope, Widening};

/// How deep a delegation chain may be.
///
/// Verification cost is linear in depth and every link is a signature check,
/// so an unbounded chain is a denial-of-service vector aimed at the one
/// component that must stay responsive.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// An Ed25519 public key, as it travels.
pub type PublicKey = [u8; 32];

/// One delegation: `issuer` grants `subject` the authority in `scope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mandate {
    /// Who is granting. Must equal the previous link's `subject`, or — for
    /// the first link — the trusted root key.
    pub issuer: PublicKey,
    /// Who receives the authority.
    pub subject: PublicKey,
    /// Human-facing identity of the party ultimately liable. Carried down
    /// the chain unchanged; a link that alters it is rejected.
    pub principal: PrincipalId,
    pub scope: Scope,
    /// Unique per mandate. Two mandates with identical contents are still
    /// distinct grants, and a receipt has to be able to say which one.
    pub nonce: [u8; 16],
    /// Signature by `issuer` over [`Mandate::signing_bytes`].
    #[serde(with = "sig_bytes")]
    pub signature: [u8; 64],
}

impl Mandate {
    /// The exact bytes covered by the signature.
    ///
    /// Deliberately not JSON. See the module docs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // A domain tag, so a signature over a mandate can never be replayed
        // as a signature over some other Quaestor structure.
        push_field(&mut buf, b"quaestor.mandate.v1");
        push_field(&mut buf, &self.issuer);
        push_field(&mut buf, &self.subject);
        push_field(&mut buf, self.principal.as_str().as_bytes());
        push_field(&mut buf, &self.nonce);
        push_field(&mut buf, &scope_bytes(&self.scope));
        buf
    }

    fn verify_signature(&self) -> Result<(), ChainError> {
        let key = VerifyingKey::from_bytes(&self.issuer).map_err(|_| ChainError::BadIssuerKey)?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(&self.signing_bytes(), &sig)
            .map_err(|_| ChainError::BadSignature)
    }
}

/// Deterministic encoding of a scope. Sorted sets, explicit tags, no maps.
fn scope_bytes(scope: &Scope) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    push_field(&mut buf, &scope.max_amount.minor().to_be_bytes());
    push_field(&mut buf, scope.max_amount.currency().code().as_bytes());
    buf.push(scope.max_amount.currency().exponent());
    push_constraint_str(&mut buf, &scope.payees);
    push_constraint_str(&mut buf, &scope.categories);
    push_field(&mut buf, &rails_bytes(&scope.rails));
    push_field(&mut buf, &scope.not_after.as_millis().to_be_bytes());
    buf
}

fn push_constraint_str(buf: &mut Vec<u8>, c: &crate::mandate::scope::Constraint<String>) {
    match c {
        crate::mandate::scope::Constraint::Any => buf.push(0),
        crate::mandate::scope::Constraint::Only(set) => {
            buf.push(1);
            // BTreeSet iterates in sorted order, so this is stable.
            push_field(
                buf,
                &u32::try_from(set.len()).unwrap_or(u32::MAX).to_be_bytes(),
            );
            for item in set {
                push_field(buf, item.as_bytes());
            }
        }
    }
}

fn rails_bytes(c: &crate::mandate::scope::Constraint<quaestor_core::Rail>) -> Vec<u8> {
    let mut buf = Vec::new();
    match c {
        crate::mandate::scope::Constraint::Any => buf.push(0),
        crate::mandate::scope::Constraint::Only(set) => {
            buf.push(1);
            for rail in set {
                buf.push(match rail {
                    quaestor_core::Rail::X402 => 1,
                    quaestor_core::Rail::Ap2 => 2,
                    quaestor_core::Rail::Acp => 3,
                    quaestor_core::Rail::Mpp => 4,
                    quaestor_core::Rail::Ucp => 5,
                    quaestor_core::Rail::Card => 6,
                    quaestor_core::Rail::Other => 7,
                });
            }
        }
    }
    buf
}

/// Length-prefixed append. The prefix is what stops field boundaries moving.
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("chain is empty")]
    Empty,
    #[error("chain is {depth} links deep; the limit is {MAX_CHAIN_DEPTH}")]
    TooDeep { depth: usize },
    #[error("the first link is issued by an untrusted key")]
    UntrustedRoot,
    #[error("issuer key is not a valid Ed25519 point")]
    BadIssuerKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("link {index} is issued by a key that is not the previous subject")]
    Disconnected { index: usize },
    #[error("link {index} widens authority: {widening}")]
    ScopeWidened { index: usize, widening: Widening },
    #[error("link {index} changes the liable principal")]
    PrincipalChanged { index: usize },
    #[error("link {index} expired at {expired_at:?}")]
    Expired { index: usize, expired_at: Timestamp },
    #[error("key {key} appears twice in the chain")]
    Cycle { key: String },
    #[error("scopes could not be intersected: {0}")]
    Unintersectable(quaestor_core::MoneyError),
}

/// A verified chain: who may spend, on whose behalf, up to what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// The agent at the end of the chain — the only key that may now act.
    pub holder: PublicKey,
    pub principal: PrincipalId,
    /// The intersection of every scope in the chain.
    pub scope: Scope,
    /// A stable identifier for this exact chain, for receipts.
    pub chain_id: [u8; 32],
}

/// Walk a delegation chain and return the authority it actually confers.
///
/// `root_keys` are the keys this deployment trusts to originate authority —
/// registered principals, not anything the chain itself asserts. A chain
/// that vouches for its own root is not evidence of anything.
///
/// Ordering note: signatures are checked link by link as we walk, before
/// that link's scope is trusted. Verifying scopes first and signatures after
/// would mean reasoning about numbers nobody has yet proved were authorized.
pub fn verify_chain(
    chain: &[Mandate],
    root_keys: &[PublicKey],
    now: Timestamp,
) -> Result<Authority, ChainError> {
    let Some(first) = chain.first() else {
        return Err(ChainError::Empty);
    };
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(ChainError::TooDeep { depth: chain.len() });
    }
    if !root_keys.contains(&first.issuer) {
        return Err(ChainError::UntrustedRoot);
    }

    let mut seen: Vec<PublicKey> = vec![first.issuer];
    let mut effective: Option<Scope> = None;
    let mut expected_issuer = first.issuer;

    for (index, link) in chain.iter().enumerate() {
        if link.issuer != expected_issuer {
            return Err(ChainError::Disconnected { index });
        }
        link.verify_signature()?;

        if link.scope.not_after < now {
            return Err(ChainError::Expired {
                index,
                expired_at: link.scope.not_after,
            });
        }
        if link.principal != first.principal {
            return Err(ChainError::PrincipalChanged { index });
        }

        // Attenuation, against the running intersection rather than only the
        // immediate parent. Same result when every link is honest; strictly
        // safer when one is not.
        if let Some(parent) = &effective {
            link.scope
                .is_within(parent)
                .map_err(|widening| ChainError::ScopeWidened { index, widening })?;
        }
        effective = Some(match effective {
            None => link.scope.clone(),
            Some(prev) => prev
                .intersect(&link.scope)
                .map_err(ChainError::Unintersectable)?,
        });

        // A key appearing twice means a loop, or an attempt to launder
        // authority back to an earlier holder. Neither is legitimate.
        if seen.contains(&link.subject) {
            return Err(ChainError::Cycle {
                key: hex32(&link.subject),
            });
        }
        seen.push(link.subject);
        expected_issuer = link.subject;
    }

    let scope = effective.ok_or(ChainError::Empty)?;
    let last = chain.last().ok_or(ChainError::Empty)?;

    Ok(Authority {
        holder: last.subject,
        principal: first.principal.clone(),
        scope,
        chain_id: chain_id(chain),
    })
}

/// Hash over every link's signing bytes and signature, so the identifier
/// changes if any part of the chain does.
fn chain_id(chain: &[Mandate]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"quaestor.chain.v1");
    for link in chain {
        let bytes = link.signing_bytes();
        h.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        h.update(&bytes);
        h.update(link.signature);
    }
    h.finalize().into()
}

fn hex32(k: &PublicKey) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

mod sig_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 128 {
            return Err(serde::de::Error::custom("signature must be 64 hex bytes"));
        }
        let mut out = [0u8; 64];
        let bytes = s.as_bytes();
        for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            let text = core::str::from_utf8(pair).map_err(serde::de::Error::custom)?;
            *slot = u8::from_str_radix(text, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}
