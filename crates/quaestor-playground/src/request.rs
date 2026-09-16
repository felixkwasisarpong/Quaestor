//! What the page sends, and how it becomes the real types.
//!
//! The wire shape here is deliberately *not* `serde` on the internal types.
//! `Constraint` serializes as `{"kind":"only","values":[…]}`, which is right
//! for a mandate that has to be signed and wrong for something a person
//! types into a textarea. So the page writes `null` for "no restriction" and
//! a list for "exactly these", and this module does the translation.
//!
//! That translation is the one place the distinction between the two can be
//! lost, and losing it is bug #006. It is therefore written once, here, with
//! a test either side of it.

use std::collections::BTreeSet;

use quaestor_core::{Currency, Money, Rail, Timestamp};
use quaestor_verify::mandate::{Constraint, Scope};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Run the policy evaluator over one payment.
    Evaluate(Box<Evaluate>),
    /// Ask whether one scope is contained by another.
    Attenuate(Box<Attenuate>),
}

#[derive(Debug, Deserialize)]
pub struct Evaluate {
    /// The policy file, as typed.
    pub policy: String,
    pub authority: ScopeInput,
    pub payment: PaymentInput,
    #[serde(default)]
    pub state: StateInput,
    pub now_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct Attenuate {
    #[serde(default = "default_currency")]
    pub currency: String,
    pub parent: ScopeInput,
    pub child: ScopeInput,
}

fn default_currency() -> String {
    "USDC".to_owned()
}

/// A scope, in the shape a person would write it.
///
/// `null` and an empty list are **different**, and the difference is the
/// whole point of the attenuation rules: `null` is "no restriction", an
/// empty list is "nothing is permitted". Reading one as the other is how a
/// delegated mandate gains the world; see `BUGS.md` #006.
#[derive(Debug, Deserialize)]
pub struct ScopeInput {
    /// Decimal string, e.g. `"50.000000"`.
    pub max_amount: String,
    #[serde(default)]
    pub payees: Option<Vec<String>>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default)]
    pub rails: Option<Vec<String>>,
    pub not_after_ms: i64,
}

impl ScopeInput {
    pub fn build(&self, currency: Currency) -> Result<Scope, String> {
        let amount = parse_amount(&self.max_amount, currency, "max_amount")?;
        Ok(Scope {
            max_amount: amount,
            payees: constraint(self.payees.as_deref()),
            categories: constraint(self.categories.as_deref()),
            rails: rails(self.rails.as_deref())?,
            not_after: Timestamp(self.not_after_ms),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct PaymentInput {
    pub amount: String,
    pub payee: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_rail")]
    pub rail: String,
}

fn default_rail() -> String {
    "x402".to_owned()
}

/// What the ledger would have said, had there been one.
///
/// A window the policy configures and this map omits is **absent**, not
/// zero, and the evaluator denies on it. That is not a quirk to work around
/// in the page: deleting a line here and watching the verdict turn into a
/// refusal is one of the more useful things the playground can show. See
/// `BUGS.md` #011.
#[derive(Debug, Default, Deserialize)]
pub struct StateInput {
    /// Keyed by the window label used in the policy, e.g. `"24h"`.
    #[serde(default)]
    pub spent: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub velocity: Option<u32>,
    #[serde(default)]
    pub payee_seen: bool,
}

// ---------------------------------------------------------------------------

/// `None` is no restriction; `Some(list)` is exactly that list, empty
/// included.
pub fn constraint(values: Option<&[String]>) -> Constraint<String> {
    match values {
        None => Constraint::Any,
        Some(list) => Constraint::Only(list.iter().cloned().collect()),
    }
}

pub fn rails(values: Option<&[String]>) -> Result<Constraint<Rail>, String> {
    let Some(list) = values else {
        return Ok(Constraint::Any);
    };
    let mut set = BTreeSet::new();
    for r in list {
        set.insert(rail(r)?);
    }
    Ok(Constraint::Only(set))
}

pub fn rail(name: &str) -> Result<Rail, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "x402" => Ok(Rail::X402),
        "ap2" => Ok(Rail::Ap2),
        "acp" => Ok(Rail::Acp),
        "mpp" => Ok(Rail::Mpp),
        "ucp" => Ok(Rail::Ucp),
        "card" => Ok(Rail::Card),
        "other" => Ok(Rail::Other),
        other => Err(format!("unknown rail {other:?}")),
    }
}

pub fn currency(code: &str) -> Result<Currency, String> {
    match code.trim() {
        "USD" => Ok(Currency::USD),
        "EUR" => Ok(Currency::EUR),
        "GBP" => Ok(Currency::GBP),
        "JPY" => Ok(Currency::JPY),
        "USDC" => Ok(Currency::USDC),
        other => Err(format!(
            "unknown currency {other:?}: decimals decide whether a number means \
             one dollar or one millionth of one, so this is not guessed"
        )),
    }
}

/// Parse an amount written without its currency code, e.g. `"1.50"`.
pub fn parse_amount(text: &str, currency: Currency, field: &str) -> Result<Money, String> {
    let text = text.trim();
    let with_code = if text.ends_with(currency.code()) {
        text.to_owned()
    } else {
        format!("{text} {}", currency.code())
    };
    Money::parse(&with_code, currency).map_err(|e| format!("{field}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_and_empty_are_different_grants() {
        // The distinction bug #006 is about, stated where the translation
        // happens. If these ever become the same value, a delegated mandate
        // that drops a restriction reads as narrower.
        assert_eq!(constraint(None), Constraint::Any);
        assert_eq!(constraint(Some(&[])), Constraint::Only(BTreeSet::new()));
        assert_ne!(constraint(None), constraint(Some(&[])));
    }

    #[test]
    fn an_amount_may_omit_its_currency_code() {
        let m = parse_amount("1.50", Currency::USD, "x").expect("valid");
        assert_eq!(m.minor(), 150);
        let m = parse_amount("1.50 USD", Currency::USD, "x").expect("valid");
        assert_eq!(m.minor(), 150);
    }

    #[test]
    fn an_amount_with_too_many_decimals_is_refused_not_rounded() {
        assert!(parse_amount("1.005", Currency::USD, "x").is_err());
    }

    #[test]
    fn an_unknown_currency_is_refused_rather_than_guessed() {
        assert!(currency("XYZ").is_err());
        assert!(currency("USDC").is_ok());
    }
}
