//! What can go wrong, stated precisely.
//!
//! Every variant here is a refusal. There is no `Warning`, no `Suspicious`,
//! no partial success — a payment authorization either verifies or it does
//! not, and anything the caller has to interpret is a place where someone
//! eventually interprets it as "probably fine".

use quaestor_core::DenyReason;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    // ---- structural ----
    #[error("unsupported x402 version: {0}")]
    UnsupportedVersion(u32),
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("unsupported network: {0}")]
    UnsupportedNetwork(String),
    #[error("malformed field {field}: {detail}")]
    Malformed { field: &'static str, detail: String },

    // ---- cryptographic ----
    #[error("signature is not 65 bytes")]
    SignatureLength,
    #[error("signature recovery id is invalid")]
    BadRecoveryId,
    #[error("signature did not recover to a usable public key")]
    Unrecoverable,
    /// The signature is well-formed and recovers — to the wrong person.
    #[error("signature recovered to {recovered}, but the authorization claims {claimed}")]
    SignerMismatch { recovered: String, claimed: String },

    // ---- binding: the authorization must match what was demanded ----
    //
    // These are the interesting failures. A signature can be perfectly valid
    // over an authorization that pays somebody else.
    #[error("authorization pays {authorized}, but the request demanded {required}")]
    RecipientMismatch {
        authorized: String,
        required: String,
    },
    #[error("authorization is for {authorized} atomic units, but {required} was demanded")]
    AmountMismatch { authorized: u128, required: u128 },

    // ---- temporal ----
    #[error("authorization is not valid until {valid_after} (now {now})")]
    NotYetValid { valid_after: u64, now: u64 },
    #[error("authorization expired at {valid_before} (now {now})")]
    Expired { valid_before: u64, now: u64 },
    #[error("validity window is inverted: validAfter {valid_after} >= validBefore {valid_before}")]
    InvertedWindow { valid_after: u64, valid_before: u64 },

    // ---- replay ----
    #[error("nonce has been seen before")]
    NonceReplayed,

    // ---- configuration ----
    /// We were handed an asset we have no decimals for. Failing closed here
    /// is the only safe option: guessing the exponent means guessing the
    /// amount by a factor of a thousand.
    #[error("asset {asset} on network {network} is not in the asset registry")]
    UnknownAsset { network: String, asset: String },
}

impl VerifyError {
    /// Collapse to the canonical deny reason the rest of the system speaks.
    ///
    /// Detail is deliberately preserved in the `detail` strings rather than
    /// thrown away: a denial nobody can debug gets switched off in
    /// production, which is worse than no denial at all.
    pub fn to_deny_reason(&self) -> DenyReason {
        match self {
            VerifyError::SignatureLength
            | VerifyError::BadRecoveryId
            | VerifyError::Unrecoverable
            | VerifyError::SignerMismatch { .. } => DenyReason::BadSignature,

            VerifyError::Expired { valid_before, .. } => DenyReason::MandateExpired {
                expired_at: quaestor_core::Timestamp(seconds_to_millis(*valid_before)),
            },

            VerifyError::RecipientMismatch { .. }
            | VerifyError::AmountMismatch { .. }
            | VerifyError::NonceReplayed => DenyReason::ScopeWidened {
                detail: self.to_string(),
            },

            other => DenyReason::MalformedIntent {
                detail: other.to_string(),
            },
        }
    }
}

/// Seconds to milliseconds, saturating rather than wrapping. A timestamp so
/// large it overflows is not a real payment, and a panic in a denial path
/// would turn a refusal into an outage.
fn seconds_to_millis(secs: u64) -> i64 {
    i64::try_from(secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signature_failure_collapses_to_bad_signature() {
        for e in [
            VerifyError::SignatureLength,
            VerifyError::BadRecoveryId,
            VerifyError::Unrecoverable,
            VerifyError::SignerMismatch {
                recovered: "0xaa".into(),
                claimed: "0xbb".into(),
            },
        ] {
            assert_eq!(e.to_deny_reason(), DenyReason::BadSignature, "{e}");
        }
    }

    #[test]
    fn a_mismatched_recipient_is_reported_as_widened_scope() {
        let e = VerifyError::RecipientMismatch {
            authorized: "0xattacker".into(),
            required: "0xmerchant".into(),
        };
        match e.to_deny_reason() {
            DenyReason::ScopeWidened { detail } => {
                assert!(
                    detail.contains("0xattacker"),
                    "detail must name the actual payee"
                );
            }
            other => panic!("expected ScopeWidened, got {other:?}"),
        }
    }

    #[test]
    fn an_absurd_expiry_saturates_instead_of_panicking() {
        let e = VerifyError::Expired {
            valid_before: u64::MAX,
            now: 0,
        };
        assert!(matches!(
            e.to_deny_reason(),
            DenyReason::MandateExpired { .. }
        ));
    }
}
