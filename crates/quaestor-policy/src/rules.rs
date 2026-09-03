//! The policy file.
//!
//! Typed TOML rather than a language. A policy language would need a parser,
//! a type checker and a termination proof, and none of those are what makes
//! this component valuable. Deserializing into structs gets the same
//! expressiveness for v1 with the compiler doing the checking, and the
//! evaluator is total by construction because there is nothing to loop over
//! that the schema does not bound.
//!
//! ```toml
//! version = 1
//! currency = "USD"
//!
//! [defaults]
//! unattended_limit  = "50.00 USD"
//! escalate_first_seen_payee = true
//! escalate_above_remaining_percent = 50
//!
//! [[budgets]]
//! window = "24h"
//! limit  = "500.00 USD"
//!
//! [[budgets]]
//! window = "30d"
//! limit  = "2000.00 USD"
//!
//! [velocity]
//! max_payments = 20
//! window = "1h"
//!
//! [payees]
//! deny = ["known-bad.example"]
//! always_escalate = ["new-vendor.example"]
//!
//! [categories]
//! deny = ["gambling"]
//! ```

use quaestor_core::{Currency, Money};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is version {found}; this build understands {expected}")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("unknown currency {0:?}")]
    UnknownCurrency(String),
    #[error("could not parse {field}: {detail}")]
    BadValue { field: &'static str, detail: String },
    #[error("duration {0:?} is not of the form 30s, 15m, 24h or 30d")]
    BadDuration(String),
    #[error("a limit is negative: {0}")]
    NegativeLimit(String),
    #[error("two budgets share the {0} window; one would silently shadow the other")]
    DuplicateWindow(String),
    #[error("escalate_above_remaining_percent must be 0..=100, got {0}")]
    BadPercent(u32),
    #[error("malformed TOML: {0}")]
    Toml(String),
}

pub const POLICY_VERSION: u32 = 1;

/// A rolling spend window. Rolling, not calendar: "500 in any 24 hours",
/// not "500 since midnight". Calendar buckets hand an agent a fresh budget
/// at a predictable instant, which is exactly when a runaway loop gets its
/// second wind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub window_ms: i64,
    pub window_label: String,
    pub limit: Money,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Velocity {
    pub max_payments: u32,
    pub window_ms: i64,
    pub window_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub currency: Currency,
    /// Above this, a payment needs a human even if every cap allows it.
    pub unattended_limit: Money,
    pub escalate_first_seen_payee: bool,
    /// Escalate when a payment would consume more than this share of what
    /// remains in any budget.
    ///
    /// A whole percent, not a fraction. The workspace forbids floating point
    /// arithmetic and that ban is worth keeping intact here rather than
    /// carving out an exception at the edge: a policy file about money should
    /// not contain a float at all, and `50` reads better than `0.5` anyway.
    pub escalate_above_remaining_percent: Option<u32>,
    pub budgets: Vec<Budget>,
    pub velocity: Option<Velocity>,
    pub deny_payees: Vec<String>,
    pub escalate_payees: Vec<String>,
    pub deny_categories: Vec<String>,
    /// A hash of the file this policy came from. Pinned into every receipt,
    /// so a decision can be tied to the exact rules that produced it.
    pub version_hash: [u8; 32],
}

impl Policy {
    pub fn parse(toml_text: &str) -> Result<Policy, PolicyError> {
        let raw: RawPolicy =
            toml::from_str(toml_text).map_err(|e| PolicyError::Toml(e.to_string()))?;

        if raw.version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion {
                found: raw.version,
                expected: POLICY_VERSION,
            });
        }

        let currency = match raw.currency.as_str() {
            "USD" => Currency::USD,
            "EUR" => Currency::EUR,
            "GBP" => Currency::GBP,
            "JPY" => Currency::JPY,
            "USDC" => Currency::USDC,
            other => return Err(PolicyError::UnknownCurrency(other.to_owned())),
        };

        let money = |field: &'static str, s: &str| -> Result<Money, PolicyError> {
            let m = Money::parse(s, currency).map_err(|e| PolicyError::BadValue {
                field,
                detail: e.to_string(),
            })?;
            if m.is_negative() {
                return Err(PolicyError::NegativeLimit(s.to_owned()));
            }
            Ok(m)
        };

        let unattended_limit = money("defaults.unattended_limit", &raw.defaults.unattended_limit)?;

        let escalate_above_remaining_percent = match raw.defaults.escalate_above_remaining_percent {
            None => None,
            Some(p) if p <= 100 => Some(p),
            Some(p) => return Err(PolicyError::BadPercent(p)),
        };

        let mut budgets = Vec::with_capacity(raw.budgets.len());
        for b in &raw.budgets {
            let window_ms = parse_duration_ms(&b.window)?;
            if budgets.iter().any(|e: &Budget| e.window_ms == window_ms) {
                return Err(PolicyError::DuplicateWindow(b.window.clone()));
            }
            budgets.push(Budget {
                window_ms,
                window_label: b.window.clone(),
                limit: money("budgets.limit", &b.limit)?,
            });
        }
        // Sorted shortest first, so a denial names the tightest window that
        // was breached rather than whichever happened to be listed first.
        budgets.sort_by_key(|b| b.window_ms);

        let velocity = match &raw.velocity {
            None => None,
            Some(v) => Some(Velocity {
                max_payments: v.max_payments,
                window_ms: parse_duration_ms(&v.window)?,
                window_label: v.window.clone(),
            }),
        };

        Ok(Policy {
            currency,
            unattended_limit,
            escalate_first_seen_payee: raw.defaults.escalate_first_seen_payee,
            escalate_above_remaining_percent,
            budgets,
            velocity,
            deny_payees: raw.payees.deny,
            escalate_payees: raw.payees.always_escalate,
            deny_categories: raw.categories.deny,
            version_hash: hash(toml_text.as_bytes()),
        })
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"quaestor.policy.v1");
    h.update(bytes);
    h.finalize().into()
}

/// `30s`, `15m`, `24h`, `30d`. No months or years: their length depends on
/// where you are in the calendar, and a spend window whose size depends on
/// the date is not a window.
pub fn parse_duration_ms(s: &str) -> Result<i64, PolicyError> {
    let bad = || PolicyError::BadDuration(s.to_owned());
    let (digits, unit) = s.split_at(s.len().checked_sub(1).ok_or_else(bad)?);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: i64 = digits.parse().map_err(|_| bad())?;
    if n == 0 {
        return Err(bad());
    }
    let unit_ms: i64 = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(bad()),
    };
    n.checked_mul(unit_ms).ok_or_else(bad)
}

// ---------------------------------------------------------------------------
// Raw deserialization shapes. `deny_unknown_fields` throughout: a typo in a
// policy file must be a loud error, never a silently ignored rule. Someone
// writes `always_escalte` and believes they have a control they do not have.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: u32,
    currency: String,
    defaults: RawDefaults,
    #[serde(default)]
    budgets: Vec<RawBudget>,
    #[serde(default)]
    velocity: Option<RawVelocity>,
    #[serde(default)]
    payees: RawPayees,
    #[serde(default)]
    categories: RawCategories,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
    unattended_limit: String,
    #[serde(default)]
    escalate_first_seen_payee: bool,
    #[serde(default)]
    escalate_above_remaining_percent: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    window: String,
    limit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVelocity {
    max_payments: u32,
    window: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPayees {
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    always_escalate: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawCategories {
    #[serde(default)]
    deny: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 1
currency = "USD"

[defaults]
unattended_limit = "50.00 USD"
escalate_first_seen_payee = true
escalate_above_remaining_percent = 50

[[budgets]]
window = "30d"
limit = "2000.00 USD"

[[budgets]]
window = "24h"
limit = "500.00 USD"

[velocity]
max_payments = 20
window = "1h"

[payees]
deny = ["known-bad.example"]
always_escalate = ["new-vendor.example"]

[categories]
deny = ["gambling"]
"#;

    #[test]
    fn a_complete_policy_parses() {
        let p = Policy::parse(SAMPLE).expect("valid");
        assert_eq!(p.currency, Currency::USD);
        assert_eq!(p.unattended_limit.minor(), 5_000);
        assert!(p.escalate_first_seen_payee);
        assert_eq!(p.escalate_above_remaining_percent, Some(50));
        assert_eq!(p.velocity.expect("set").max_payments, 20);
        assert_eq!(p.deny_categories, vec!["gambling".to_owned()]);
    }

    #[test]
    fn budgets_are_sorted_tightest_window_first() {
        // So a denial names the 24h cap rather than the 30d one that happens
        // to be listed above it.
        let p = Policy::parse(SAMPLE).expect("valid");
        assert_eq!(p.budgets.first().expect("one").window_label, "24h");
        assert_eq!(p.budgets.get(1).expect("two").window_label, "30d");
    }

    #[test]
    fn a_typo_in_a_field_name_is_a_loud_error() {
        // The failure that matters most in a policy file: someone writes a
        // rule, the parser ignores it, and they believe they have a control
        // they do not have.
        let typo = SAMPLE.replace("always_escalate", "always_escalte");
        assert!(matches!(Policy::parse(&typo), Err(PolicyError::Toml(_))));
    }

    #[test]
    fn two_budgets_on_the_same_window_are_refused() {
        let dup = SAMPLE.replace(r#"window = "30d""#, r#"window = "24h""#);
        assert!(matches!(
            Policy::parse(&dup),
            Err(PolicyError::DuplicateWindow(_))
        ));
    }

    #[test]
    fn a_negative_limit_is_refused() {
        let neg = SAMPLE.replace(r#"limit = "500.00 USD""#, r#"limit = "-500.00 USD""#);
        assert!(matches!(
            Policy::parse(&neg),
            Err(PolicyError::NegativeLimit(_))
        ));
    }

    #[test]
    fn a_limit_in_the_wrong_currency_is_refused() {
        let mixed = SAMPLE.replace(r#"limit = "500.00 USD""#, r#"limit = "500.00 EUR""#);
        assert!(matches!(
            Policy::parse(&mixed),
            Err(PolicyError::BadValue { .. })
        ));
    }

    #[test]
    fn durations_parse_and_reject_calendar_units() {
        assert_eq!(parse_duration_ms("30s").expect("ok"), 30_000);
        assert_eq!(parse_duration_ms("15m").expect("ok"), 900_000);
        assert_eq!(parse_duration_ms("24h").expect("ok"), 86_400_000);
        assert_eq!(parse_duration_ms("30d").expect("ok"), 2_592_000_000);
        // Months and years have no fixed length, so a window measured in
        // them changes size depending on the date.
        for bad in [
            "1M", "1y", "", "h", "0h", "-1h", "1.5h", "24", "24hh", "  24h",
        ] {
            assert!(parse_duration_ms(bad).is_err(), "should refuse {bad:?}");
        }
    }

    #[test]
    fn a_percent_above_one_hundred_is_refused() {
        let p = SAMPLE.replace(
            "escalate_above_remaining_percent = 50",
            "escalate_above_remaining_percent = 150",
        );
        assert!(matches!(
            Policy::parse(&p),
            Err(PolicyError::BadPercent(150))
        ));
    }

    #[test]
    fn a_policy_file_may_not_contain_a_float() {
        // Not a style rule. Every other number in this file is money or a
        // count, and a float in either is a bug waiting for a rounding mode.
        let f = SAMPLE.replace(
            "escalate_above_remaining_percent = 50",
            "escalate_above_remaining_percent = 0.5",
        );
        assert!(matches!(Policy::parse(&f), Err(PolicyError::Toml(_))));
    }

    #[test]
    fn an_unsupported_version_is_refused_rather_than_guessed_at() {
        let v2 = SAMPLE.replace("version = 1", "version = 2");
        assert!(matches!(
            Policy::parse(&v2),
            Err(PolicyError::UnsupportedVersion { found: 2, .. })
        ));
    }

    #[test]
    fn the_version_hash_changes_with_any_edit() {
        let a = Policy::parse(SAMPLE).expect("valid").version_hash;
        let b = Policy::parse(&SAMPLE.replace("500.00", "500.01"))
            .expect("valid")
            .version_hash;
        assert_ne!(a, b, "a receipt must be able to identify the exact rules");
    }
}
