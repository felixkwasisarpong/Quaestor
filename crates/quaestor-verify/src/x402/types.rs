//! x402 v2 wire types.
//!
//! These mirror the protocol exactly and do no interpretation. Parsing and
//! validation are separate steps on purpose: this module's only job is to
//! turn bytes into a shape, and [`super::verify`]'s job is to decide whether
//! that shape means anything.
//!
//! Note `deny_unknown_fields` on [`ExactEvmAuthorization`]. The EIP-712
//! signature covers exactly six named fields, so any additional key in that
//! object is, by definition, unsigned data riding along inside a structure
//! the caller believes is authenticated. We refuse it rather than ignore it.
//! The outer envelope stays permissive so the protocol can add fields
//! without breaking us.

use serde::{Deserialize, Serialize};

use crate::eip712::{Address, Word};
use crate::error::VerifyError;

/// The only version this verifier accepts.
pub const SUPPORTED_VERSION: u32 = 2;

/// What the resource server demanded, from the `402` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    /// CAIP-2, e.g. `eip155:8453`.
    pub network: String,
    /// Atomic units, as a decimal string.
    pub amount: String,
    /// Token contract address, `0x`-prefixed.
    pub asset: String,
    /// Recipient address, `0x`-prefixed.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    #[serde(rename = "maxTimeoutSeconds", default)]
    pub max_timeout_seconds: Option<u64>,
    /// Scheme-specific metadata. Carries the token's EIP-712 `name` and
    /// `version` — which we read for diagnostics and deliberately do not
    /// trust. See [`super::verify`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// What the client sent back, from the `X-PAYMENT` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    /// The requirements the client claims to be satisfying. Untrusted — the
    /// real requirements come from the server, and these two must agree.
    pub accepted: PaymentRequirements,
    pub payload: ExactEvmPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactEvmPayload {
    /// 65-byte secp256k1 signature, `0x`-prefixed: r ‖ s ‖ v.
    pub signature: String,
    pub authorization: ExactEvmAuthorization,
}

/// EIP-3009 `TransferWithAuthorization`, as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactEvmAuthorization {
    pub from: String,
    pub to: String,
    /// Atomic units, decimal string.
    pub value: String,
    #[serde(rename = "validAfter")]
    pub valid_after: String,
    #[serde(rename = "validBefore")]
    pub valid_before: String,
    /// 32 bytes, `0x`-prefixed.
    pub nonce: String,
}

// ---------------------------------------------------------------------------
// Parsing helpers.
//
// Every one of these returns a typed error naming the field. A verifier that
// says "malformed input" and nothing else is a verifier nobody can operate.
// ---------------------------------------------------------------------------

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        b'A'..=b'F' => c.checked_sub(b'A').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    hex_digit(hi)?.checked_mul(16)?.checked_add(hex_digit(lo)?)
}

pub fn parse_hex(field: &'static str, s: &str) -> Result<Vec<u8>, VerifyError> {
    let body = strip_0x(s).as_bytes();
    if body.len() % 2 != 0 {
        return Err(VerifyError::Malformed {
            field,
            detail: "odd number of hex digits".into(),
        });
    }
    let mut out = Vec::with_capacity(body.len() / 2);
    for pair in body.chunks_exact(2) {
        let (Some(&hi), Some(&lo)) = (pair.first(), pair.get(1)) else {
            return Err(VerifyError::Malformed {
                field,
                detail: "short chunk".into(),
            });
        };
        let byte = hex_byte(hi, lo).ok_or_else(|| VerifyError::Malformed {
            field,
            detail: "non-hex digit".into(),
        })?;
        out.push(byte);
    }
    Ok(out)
}

pub fn parse_address(field: &'static str, s: &str) -> Result<Address, VerifyError> {
    let bytes = parse_hex(field, s)?;
    <[u8; 20]>::try_from(bytes.as_slice()).map_err(|_| VerifyError::Malformed {
        field,
        detail: format!("expected 20 bytes, got {}", bytes.len()),
    })
}

pub fn parse_word(field: &'static str, s: &str) -> Result<Word, VerifyError> {
    let bytes = parse_hex(field, s)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| VerifyError::Malformed {
        field,
        detail: format!("expected 32 bytes, got {}", bytes.len()),
    })
}

/// Decimal string to `u128`. Rejects leading `+`, whitespace, and anything
/// with a decimal point — atomic units are integers, and a value that looks
/// fractional means the sender has a different idea of the amount than we do.
pub fn parse_u128(field: &'static str, s: &str) -> Result<u128, VerifyError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VerifyError::Malformed {
            field,
            detail: format!("expected decimal digits, got {s:?}"),
        });
    }
    s.parse::<u128>().map_err(|e| VerifyError::Malformed {
        field,
        detail: e.to_string(),
    })
}

pub fn parse_u64(field: &'static str, s: &str) -> Result<u64, VerifyError> {
    let v = parse_u128(field, s)?;
    u64::try_from(v).map_err(|_| VerifyError::Malformed {
        field,
        detail: "value exceeds u64".into(),
    })
}

/// Lowercase `0x`-prefixed rendering, for error messages and comparisons.
pub fn render_address(a: &Address) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in a {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsing_accepts_both_prefixes_and_rejects_junk() {
        assert_eq!(parse_hex("f", "0xff00").expect("valid"), vec![0xff, 0x00]);
        assert_eq!(parse_hex("f", "ff00").expect("valid"), vec![0xff, 0x00]);
        assert!(parse_hex("f", "0xfff").is_err(), "odd length");
        assert!(parse_hex("f", "0xzz").is_err(), "non-hex");
    }

    #[test]
    fn addresses_must_be_exactly_twenty_bytes() {
        assert!(parse_address("from", &format!("0x{}", "11".repeat(20))).is_ok());
        assert!(parse_address("from", &format!("0x{}", "11".repeat(19))).is_err());
        assert!(parse_address("from", &format!("0x{}", "11".repeat(21))).is_err());
    }

    #[test]
    fn amounts_reject_anything_that_is_not_plain_digits() {
        assert_eq!(parse_u128("value", "10000").expect("valid"), 10_000);
        for bad in ["", " 1", "1 ", "+1", "-1", "1.0", "0x10", "1e3", "１"] {
            assert!(parse_u128("value", bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn an_unknown_field_in_the_authorization_is_refused() {
        // The EIP-712 signature covers six fields. Anything else in this
        // object is unsigned data smuggled inside an authenticated shape.
        let json = r#"{
            "from":"0x11","to":"0x22","value":"1",
            "validAfter":"0","validBefore":"9","nonce":"0x00",
            "refundTo":"0xattacker"
        }"#;
        assert!(serde_json::from_str::<ExactEvmAuthorization>(json).is_err());
    }

    #[test]
    fn an_unknown_field_in_the_envelope_is_tolerated() {
        // Forward compatibility, where it costs nothing: these fields are
        // not inside the signed structure.
        let json = r#"{
            "scheme":"exact","network":"eip155:8453","amount":"1",
            "asset":"0xaa","payTo":"0xbb","maxTimeoutSeconds":60,
            "somethingNew": true
        }"#;
        assert!(serde_json::from_str::<PaymentRequirements>(json).is_ok());
    }
}
