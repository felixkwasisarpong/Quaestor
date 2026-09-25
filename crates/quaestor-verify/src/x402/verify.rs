//! Verifying an x402 `exact` payment authorization.
//!
//! # What this proves, and what it does not
//!
//! A valid signature proves that the holder of one private key signed one
//! specific 32-byte digest. That is all it proves. It does not prove the
//! payment is going where the merchant asked, that it has not been sent
//! before, or that the signer was allowed to spend that much.
//!
//! Those are separate checks, and they are the ones that matter. A verifier
//! that stops at `signature_is_valid` will happily accept an authorization
//! that pays an attacker instead of the merchant — the signature over *that*
//! is perfectly good.
//!
//! So the pipeline is deliberately ordered, cheapest and most structural
//! first, and every stage can only reject:
//!
//! 1. version and scheme are ones we implement
//! 2. the asset is one we know the decimals for  (else we fail closed)
//! 3. fields parse into the types they claim to be
//! 4. the validity window is coherent and currently open
//! 5. the authorization matches what the server actually demanded
//! 6. the signature recovers to the address claiming to have signed it
//! 7. the nonce has not been seen
//!
//! Step 5 before step 6 is intentional. Signature recovery is by far the
//! most expensive operation here, and there is no reason to spend it on a
//! payload we have already established is paying the wrong person.

use std::collections::HashMap;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use quaestor_core::{Currency, Money};

use crate::eip712::{keccak256, signing_digest, Address, Domain, TransferWithAuthorization};
use crate::error::VerifyError;
use crate::x402::types::{
    parse_address, parse_hex, parse_u128, parse_u64, parse_word, render_address, PaymentPayload,
    PaymentRequirements, SUPPORTED_VERSION,
};

/// Everything we know about one token, from our own configuration.
///
/// The EIP-712 domain lives here rather than being read out of the
/// counterparty's `extra` field. A verifier that takes the domain from the
/// message it is checking is not verifying anything — the sender chooses
/// what the signature has to match. Ours comes from local config or the
/// request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetSpec {
    pub currency: Currency,
    pub eip712_name: String,
    pub eip712_version: String,
    pub chain_id: u64,
}

/// Tokens this deployment is willing to see payments in.
///
/// Deliberately not auto-populated from chain data: decimals decide whether
/// a number means one dollar or one millionth of one, and guessing wrong is
/// a factor-of-a-million error in an authorization decision. Unknown asset,
/// no verdict.
#[derive(Debug, Clone, Default)]
pub struct AssetRegistry {
    by_key: HashMap<(String, String), AssetSpec>,
}

impl AssetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// `network` is CAIP-2; `asset` is the contract address. Both are
    /// lower-cased on insert and lookup, because hex addresses arrive in
    /// mixed case (EIP-55 checksums) and a case-sensitive miss here would
    /// look like an unknown token.
    pub fn insert(mut self, network: &str, asset: &str, spec: AssetSpec) -> Self {
        self.by_key.insert(
            (network.to_ascii_lowercase(), asset.to_ascii_lowercase()),
            spec,
        );
        self
    }

    pub fn get(&self, network: &str, asset: &str) -> Option<&AssetSpec> {
        self.by_key
            .get(&(network.to_ascii_lowercase(), asset.to_ascii_lowercase()))
    }
}

/// What the store knew about a nonce.
///
/// An enum and not a `bool` because the two readings of `false` — "I have
/// seen this" and "I could not tell" — are the whole point, and a boolean
/// has nowhere to put the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Never seen. The payment may proceed, and the nonce is now recorded.
    Fresh,
    /// Seen before. Refuse.
    Replayed,
}

/// The store could not answer.
///
/// Deliberately not folded into [`Freshness::Replayed`]. A database that is
/// unreachable has not told us this payment is a replay; it has told us
/// nothing. Both outcomes refuse the payment, so the payer sees the same
/// result either way, but the operator does not: one is an attack and the
/// other is an outage, and a system that reports the outage as an attack
/// sends somebody hunting for an attacker who does not exist.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the nonce store could not answer: {0}")]
pub struct NonceStoreUnavailable(pub String);

/// Somewhere to remember which nonces have been used.
///
/// A trait rather than a concrete store because the durable implementation
/// is Postgres and the test implementation is a set, and the verifier should
/// not care. Implementations must be atomic: `check_and_record` has to be a
/// single test-and-set, or two concurrent replays of the same authorization
/// can both be told they are the first.
pub trait NonceStore {
    /// Record the nonce and report whether it was previously unseen.
    ///
    /// `valid_before_secs` is the instant after which this authorization can
    /// never be accepted again, and it is passed in so a durable store can
    /// eventually forget the nonce without reopening the replay window: once
    /// the temporal check refuses the authorization on its own, remembering
    /// its nonce proves nothing. A store that ignores the argument is still
    /// correct, only larger.
    fn check_and_record(
        &mut self,
        payer: &Address,
        nonce: &[u8; 32],
        valid_before_secs: u64,
    ) -> Result<Freshness, NonceStoreUnavailable>;
}

/// In-memory store. Fine for tests and a single process; not durable, so not
/// fine for anything that restarts.
///
/// The name is the warning. This was the proxy's default for twenty-two
/// days, which meant a restart forgot every nonce it had ever seen — see
/// `BUGS.md` #022.
#[derive(Debug, Default)]
pub struct InMemoryNonceStore {
    seen: std::collections::HashSet<([u8; 20], [u8; 32])>,
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_record(
        &mut self,
        payer: &Address,
        nonce: &[u8; 32],
        _valid_before_secs: u64,
    ) -> Result<Freshness, NonceStoreUnavailable> {
        Ok(if self.seen.insert((*payer, *nonce)) {
            Freshness::Fresh
        } else {
            Freshness::Replayed
        })
    }
}

/// What a successful verification establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    /// The address that actually signed — recovered from the signature, not
    /// copied from the payload.
    pub payer: Address,
    pub payee: Address,
    pub amount: Money,
    pub valid_before: u64,
    pub nonce: [u8; 32],
    pub network: String,
    pub asset: String,
}

/// Verify a payment payload against the requirements the server issued.
///
/// `now_secs` is passed in, never read from the clock, so that a decision
/// made today can be replayed and audited a year from now and reach the same
/// answer.
pub fn verify_exact_evm(
    payload: &PaymentPayload,
    required: &PaymentRequirements,
    registry: &AssetRegistry,
    nonces: &mut dyn NonceStore,
    now_secs: u64,
) -> Result<VerifiedPayment, VerifyError> {
    // 1. Is this a shape we implement at all?
    if payload.x402_version != SUPPORTED_VERSION {
        return Err(VerifyError::UnsupportedVersion(payload.x402_version));
    }
    if required.scheme != "exact" {
        return Err(VerifyError::UnsupportedScheme(required.scheme.clone()));
    }

    // 2. Do we know what this token is? Unknown decimals, no verdict.
    let spec = registry
        .get(&required.network, &required.asset)
        .ok_or_else(|| VerifyError::UnknownAsset {
            network: required.network.clone(),
            asset: required.asset.clone(),
        })?;

    // 3. Parse. Nothing below this line handles a string that might be junk.
    let auth = &payload.payload.authorization;
    let from = parse_address("authorization.from", &auth.from)?;
    let to = parse_address("authorization.to", &auth.to)?;
    let value = parse_u128("authorization.value", &auth.value)?;
    let valid_after = parse_u64("authorization.validAfter", &auth.valid_after)?;
    let valid_before = parse_u64("authorization.validBefore", &auth.valid_before)?;
    let nonce = parse_word("authorization.nonce", &auth.nonce)?;

    let required_pay_to = parse_address("payTo", &required.pay_to)?;
    let required_amount = parse_u128("amount", &required.amount)?;
    let token = parse_address("asset", &required.asset)?;

    // 4. Is the window coherent, and open right now?
    if valid_after >= valid_before {
        return Err(VerifyError::InvertedWindow {
            valid_after,
            valid_before,
        });
    }
    if now_secs < valid_after {
        return Err(VerifyError::NotYetValid {
            valid_after,
            now: now_secs,
        });
    }
    if now_secs > valid_before {
        return Err(VerifyError::Expired {
            valid_before,
            now: now_secs,
        });
    }

    // 5. Binding. The signature is about to prove somebody authorized *this*
    //    transfer; here we establish that *this* transfer is the one the
    //    merchant asked for. Skipping this is the mistake that makes a
    //    verifier decorative.
    if to != required_pay_to {
        return Err(VerifyError::RecipientMismatch {
            authorized: render_address(&to),
            required: render_address(&required_pay_to),
        });
    }
    if value != required_amount {
        return Err(VerifyError::AmountMismatch {
            authorized: value,
            required: required_amount,
        });
    }

    // 6. Recovery. The domain comes from our registry, so a signature made
    //    for another chain or another token cannot satisfy this digest.
    let domain = Domain {
        name: spec.eip712_name.clone(),
        version: spec.eip712_version.clone(),
        chain_id: spec.chain_id,
        verifying_contract: token,
    };
    let signed = TransferWithAuthorization {
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
    };
    let digest = signing_digest(&domain, &signed);
    let recovered = recover_signer(&payload.payload.signature, &digest)?;
    if recovered != from {
        return Err(VerifyError::SignerMismatch {
            recovered: render_address(&recovered),
            claimed: render_address(&from),
        });
    }

    // 7. Replay. Last, because it mutates: a payload that fails any earlier
    //    check must not burn a nonce, or an attacker can grief a payer by
    //    replaying garbage.
    //
    //    The nonce is burned here, before the hold is reserved and before
    //    anything is captured. That is the safe direction: a crash between
    //    this line and the capture leaves an authorization that can never be
    //    used again, which costs the payer one re-signature, whereas the
    //    other ordering costs them the payment twice.
    match nonces.check_and_record(&from, &nonce, valid_before) {
        Ok(Freshness::Fresh) => {}
        Ok(Freshness::Replayed) => return Err(VerifyError::NonceReplayed),
        Err(NonceStoreUnavailable(detail)) => {
            return Err(VerifyError::NonceStoreUnavailable { detail })
        }
    }

    // x402 amounts are unsigned; `Money` is signed, because refunds exist.
    // The ranges very nearly coincide but not exactly, and "very nearly" is
    // not a thing this crate is allowed to say about an amount.
    let minor = i128::try_from(value).map_err(|_| VerifyError::Malformed {
        field: "authorization.value",
        detail: "amount exceeds the representable range".into(),
    })?;

    Ok(VerifiedPayment {
        payer: recovered,
        payee: to,
        amount: Money::new(minor, spec.currency),
        valid_before,
        nonce,
        network: required.network.clone(),
        asset: required.asset.clone(),
    })
}

/// Recover the signing address from a 65-byte `r ‖ s ‖ v` signature.
fn recover_signer(sig_hex: &str, digest: &[u8; 32]) -> Result<Address, VerifyError> {
    let bytes = parse_hex("signature", sig_hex)?;
    if bytes.len() != 65 {
        return Err(VerifyError::SignatureLength);
    }
    let (rs, v) = bytes.split_at(64);
    let v = *v.first().ok_or(VerifyError::SignatureLength)?;

    // Ethereum writes v as 27/28; some libraries emit 0/1. Accept both and
    // nothing else — a v of 35+ is EIP-155 chain-encoded and belongs to
    // transaction signing, not typed data.
    let rec = match v {
        0 | 27 => 0u8,
        1 | 28 => 1u8,
        _ => return Err(VerifyError::BadRecoveryId),
    };
    let recid = RecoveryId::from_byte(rec).ok_or(VerifyError::BadRecoveryId)?;

    // `from_slice` rejects a high-S signature, which is what makes a
    // signature non-malleable: without that check the same authorization has
    // two valid encodings and a naive replay guard keyed on the signature
    // bytes can be walked straight past.
    let sig = Signature::from_slice(rs).map_err(|_| VerifyError::Unrecoverable)?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| VerifyError::Unrecoverable)?;

    Ok(address_from_key(&key))
}

/// An EVM address is the last 20 bytes of the keccak hash of the
/// uncompressed public key, minus its leading `0x04` tag.
fn address_from_key(key: &VerifyingKey) -> Address {
    let point = key.to_encoded_point(false);
    let bytes = point.as_bytes();
    let body = bytes.get(1..).unwrap_or_default();
    let hash = keccak256(body);
    let mut out = [0u8; 20];
    if let Some(tail) = hash.get(12..32) {
        out.copy_from_slice(tail);
    }
    out
}
