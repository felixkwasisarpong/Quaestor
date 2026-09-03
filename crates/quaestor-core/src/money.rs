//! Money. Integer minor units and a currency, never a float.
//!
//! Two rules this module exists to enforce:
//!
//! 1. There is no way to construct a `Money` from a floating point number.
//!    Not a hard one, not a discouraged one. There is no constructor.
//! 2. Arithmetic across different currencies does not compile into a wrong
//!    answer — it returns an error. Overflow does the same. Every operation
//!    that can fail says so in its type.

use core::fmt;

use serde::{Deserialize, Serialize};

/// The largest exponent [`Currency::new`] accepts. Covers ISO-4217 (max 4)
/// and the 18-decimal precision common to stablecoins.
///
/// Public because a caller validating its own input needs the same bound we
/// enforce, and having to discover it by trial is a bad API.
pub const MAX_EXPONENT: u8 = 18;

/// Maximum length of a currency code, in bytes. ISO codes are 3; token
/// symbols like `USDC` are 4; we allow a little headroom.
pub const CODE_CAP: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MoneyError {
    #[error("currency mismatch: {lhs} vs {rhs}")]
    CurrencyMismatch { lhs: Currency, rhs: Currency },
    #[error("arithmetic overflow")]
    Overflow,
    #[error("negative amount where a non-negative one is required")]
    Negative,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseMoneyError {
    #[error("no currency code: expected something like \"500.00 USD\"")]
    NoCurrency,
    #[error("currency is {found}, but {expected} was expected")]
    CurrencyMismatch { found: String, expected: String },
    #[error("{0:?} is not a decimal amount")]
    NotANumber(String),
    #[error("{found} decimal places given, but this currency allows {allowed}")]
    TooManyDecimals { found: usize, allowed: usize },
    #[error("amount is out of range")]
    OutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CurrencyError {
    #[error("currency code must be 1..={CODE_CAP} ASCII alphanumeric bytes")]
    BadCode,
    #[error("exponent must be 0..={MAX_EXPONENT}")]
    BadExponent,
}

/// A currency: an uppercase code plus the number of decimal places in its
/// minor unit.
///
/// The exponent is part of the currency's identity on purpose. `USD` with
/// exponent 2 and `USD` with exponent 6 are different currencies as far as
/// this type is concerned, and mixing them is an error rather than a silent
/// factor-of-10,000 bug.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Currency {
    code: [u8; CODE_CAP],
    len: u8,
    exponent: u8,
}

impl Currency {
    pub const USD: Currency = Currency::lit(b"USD", 2);
    pub const EUR: Currency = Currency::lit(b"EUR", 2);
    pub const GBP: Currency = Currency::lit(b"GBP", 2);
    pub const JPY: Currency = Currency::lit(b"JPY", 0);
    /// USDC as it appears on-chain: 6 decimals.
    pub const USDC: Currency = Currency::lit(b"USDC", 6);

    /// Compile-time constructor for the constants above.
    ///
    /// The strict arithmetic and indexing lints are switched off for this
    /// function alone. It is `const`, so its only possible arguments are the
    /// byte literals a few lines up, and every one of them is checked at
    /// compile time by [`tests::the_built_in_currencies_are_well_formed`].
    /// A panic here could not reach a running binary — it would be a build
    /// failure. Nowhere else in this crate gets that exemption.
    #[allow(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation
    )]
    const fn lit(code: &[u8], exponent: u8) -> Currency {
        assert!(
            !code.is_empty() && code.len() <= CODE_CAP,
            "currency literal must be 1..=CODE_CAP bytes"
        );
        let mut buf = [0u8; CODE_CAP];
        let mut i = 0;
        while i < code.len() {
            buf[i] = code[i];
            i += 1;
        }
        Currency {
            code: buf,
            len: code.len() as u8,
            exponent,
        }
    }

    /// Build a currency from a code and an exponent.
    ///
    /// The code is upper-cased. Anything that is not ASCII alphanumeric, or
    /// an exponent above [`MAX_EXPONENT`], is rejected.
    pub fn new(code: &str, exponent: u8) -> Result<Currency, CurrencyError> {
        if exponent > MAX_EXPONENT {
            return Err(CurrencyError::BadExponent);
        }
        let n = code.len();
        if n == 0 || n > CODE_CAP || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(CurrencyError::BadCode);
        }
        let mut buf = [0u8; CODE_CAP];
        for (dst, src) in buf.iter_mut().zip(code.bytes()) {
            *dst = src.to_ascii_uppercase();
        }
        // `n <= CODE_CAP` was checked above, so this cannot fail — but the
        // check and the cast are far enough apart that we let the compiler
        // carry the proof instead of a comment.
        let len = u8::try_from(n).map_err(|_| CurrencyError::BadCode)?;
        Ok(Currency {
            code: buf,
            len,
            exponent,
        })
    }

    pub fn code(&self) -> &str {
        self.code
            .get(..usize::from(self.len))
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("???")
    }

    pub const fn exponent(&self) -> u8 {
        self.exponent
    }

    /// 10^exponent — the number of minor units in one major unit.
    fn scale(&self) -> Result<i128, MoneyError> {
        10i128
            .checked_pow(u32::from(self.exponent))
            .ok_or(MoneyError::Overflow)
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Debug for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}e{}", self.code(), self.exponent)
    }
}

/// Wire form: `{"code":"USD","exponent":2}`.
#[derive(Serialize, Deserialize)]
#[serde(rename = "Currency")]
struct CurrencyWire {
    code: String,
    exponent: u8,
}

impl Serialize for Currency {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        CurrencyWire {
            code: self.code().to_owned(),
            exponent: self.exponent,
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Currency, D::Error> {
        let w = CurrencyWire::deserialize(d)?;
        Currency::new(&w.code, w.exponent).map_err(serde::de::Error::custom)
    }
}

/// An amount of money.
///
/// `minor` is the count of minor units — cents for USD, whole yen for JPY,
/// 10^-6 units for USDC. It is signed because refunds and reversals are
/// real, and `i128` because six decimal places of a large stablecoin balance
/// overflows `i64` sooner than people expect.
///
/// # Why `minor` is a string on the wire
///
/// A JSON number is an IEEE-754 double in most parsers, JavaScript's
/// included. Any amount above 2^53 minor units silently loses precision on
/// the way through — and at USDC's six decimals that ceiling is about nine
/// billion dollars, which is not a comfortable margin for a system whose
/// entire job is being right about money. Encoding the integer as a decimal
/// string costs nothing and removes the failure mode.
///
/// It also sidesteps the fact that `serde_json` cannot round-trip a raw
/// `i128` inside an internally-tagged enum — which is where every
/// [`crate::verdict::DenyReason`] carrying a `Money` would have landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Money {
    #[serde(with = "minor_as_string")]
    minor: i128,
    currency: Currency,
}

mod minor_as_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &i128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(itoa(*v).as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<i128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<i128>().map_err(serde::de::Error::custom)
    }

    fn itoa(v: i128) -> String {
        v.to_string()
    }
}

impl Money {
    pub const fn new(minor: i128, currency: Currency) -> Money {
        Money { minor, currency }
    }

    pub const fn zero(currency: Currency) -> Money {
        Money { minor: 0, currency }
    }

    pub const fn minor(&self) -> i128 {
        self.minor
    }

    pub const fn currency(&self) -> Currency {
        self.currency
    }

    pub const fn is_zero(&self) -> bool {
        self.minor == 0
    }

    pub const fn is_negative(&self) -> bool {
        self.minor < 0
    }

    fn same_currency(&self, other: &Money) -> Result<(), MoneyError> {
        if self.currency == other.currency {
            Ok(())
        } else {
            Err(MoneyError::CurrencyMismatch {
                lhs: self.currency,
                rhs: other.currency,
            })
        }
    }

    pub fn checked_add(&self, other: &Money) -> Result<Money, MoneyError> {
        self.same_currency(other)?;
        let minor = self
            .minor
            .checked_add(other.minor)
            .ok_or(MoneyError::Overflow)?;
        Ok(Money {
            minor,
            currency: self.currency,
        })
    }

    pub fn checked_sub(&self, other: &Money) -> Result<Money, MoneyError> {
        self.same_currency(other)?;
        let minor = self
            .minor
            .checked_sub(other.minor)
            .ok_or(MoneyError::Overflow)?;
        Ok(Money {
            minor,
            currency: self.currency,
        })
    }

    /// Multiply by a whole number. Deliberately not a rate or a percentage —
    /// anything that needs rounding needs to say how it rounds, and that is
    /// a separate, explicit operation.
    pub fn checked_mul_int(&self, n: i64) -> Result<Money, MoneyError> {
        let minor = self
            .minor
            .checked_mul(i128::from(n))
            .ok_or(MoneyError::Overflow)?;
        Ok(Money {
            minor,
            currency: self.currency,
        })
    }

    /// Compare, refusing to answer across currencies.
    pub fn try_cmp(&self, other: &Money) -> Result<core::cmp::Ordering, MoneyError> {
        self.same_currency(other)?;
        Ok(self.minor.cmp(&other.minor))
    }

    pub fn try_gt(&self, other: &Money) -> Result<bool, MoneyError> {
        Ok(self.try_cmp(other)? == core::cmp::Ordering::Greater)
    }

    /// Parse `"500.00 USD"` into minor units.
    ///
    /// Written for policy files, which people edit by hand. Three rules make
    /// it safe to put on that boundary:
    ///
    /// - the currency decides how many decimals are legal, so `"1.005 USD"`
    ///   is refused rather than rounded. Silent rounding in a spend limit is
    ///   how a cap ends up being a cent different from what someone wrote.
    /// - there is no float anywhere in the conversion. The fractional part is
    ///   parsed as its own integer and scaled.
    /// - a missing fractional part is padded, so `"5 USD"` is 500 cents, not 5.
    pub fn parse(s: &str, currency: Currency) -> Result<Money, ParseMoneyError> {
        let text = s.trim();
        let (amount, code) = text
            .rsplit_once(char::is_whitespace)
            .ok_or(ParseMoneyError::NoCurrency)?;
        let code = code.trim();
        if !code.eq_ignore_ascii_case(currency.code()) {
            return Err(ParseMoneyError::CurrencyMismatch {
                found: code.to_owned(),
                expected: currency.code().to_owned(),
            });
        }

        let amount = amount.trim();
        let (negative, digits) = match amount.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, amount),
        };

        // A present-but-empty fractional part is malformed, not zero.
        // `"".bytes().all(is_digit)` is vacuously true, so the digit check
        // below would wave `"5."` through as five whole units.
        let (whole, frac) = match digits.split_once('.') {
            Some((_, "")) => return Err(ParseMoneyError::NotANumber(amount.to_owned())),
            Some((w, f)) => (w, f),
            None => (digits, ""),
        };
        if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseMoneyError::NotANumber(amount.to_owned()));
        }
        if !frac.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseMoneyError::NotANumber(amount.to_owned()));
        }

        let exponent = usize::from(currency.exponent());
        if frac.len() > exponent {
            return Err(ParseMoneyError::TooManyDecimals {
                found: frac.len(),
                allowed: exponent,
            });
        }

        let whole: i128 = whole.parse().map_err(|_| ParseMoneyError::OutOfRange)?;
        let scale = currency.scale().map_err(|_| ParseMoneyError::OutOfRange)?;
        let mut minor = whole
            .checked_mul(scale)
            .ok_or(ParseMoneyError::OutOfRange)?;

        if !frac.is_empty() {
            let mut f: i128 = frac.parse().map_err(|_| ParseMoneyError::OutOfRange)?;
            for _ in frac.len()..exponent {
                f = f.checked_mul(10).ok_or(ParseMoneyError::OutOfRange)?;
            }
            minor = minor.checked_add(f).ok_or(ParseMoneyError::OutOfRange)?;
        }
        if negative {
            minor = minor.checked_neg().ok_or(ParseMoneyError::OutOfRange)?;
        }
        Ok(Money { minor, currency })
    }

    /// Reject a negative amount. Use at trust boundaries — a payment intent
    /// for minus twenty dollars is an attack, not a refund.
    pub fn require_non_negative(&self) -> Result<Money, MoneyError> {
        if self.is_negative() {
            Err(MoneyError::Negative)
        } else {
            Ok(*self)
        }
    }
}

impl fmt::Display for Money {
    /// `1234` USD renders as `12.34 USD`; JPY has no fractional part.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Ok(scale) = self.currency.scale() else {
            return write!(f, "{}<bad-exponent> {}", self.minor, self.currency);
        };
        let sign = if self.minor < 0 { "-" } else { "" };
        let abs = self.minor.unsigned_abs();
        let scale_u = scale.unsigned_abs();
        // `scale` is 10^exponent, so it is never zero — but the lint is right
        // that a bare `/` here would be a panic waiting on a future edit.
        let (Some(major), Some(rem)) = (abs.checked_div(scale_u), abs.checked_rem(scale_u)) else {
            return write!(f, "{}<bad-scale> {}", self.minor, self.currency);
        };
        if self.currency.exponent == 0 {
            write!(f, "{sign}{major} {}", self.currency)
        } else {
            let width = usize::from(self.currency.exponent);
            write!(f, "{sign}{major}.{rem:0width$} {}", self.currency)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_with_the_right_number_of_decimals() {
        assert_eq!(Money::new(1234, Currency::USD).to_string(), "12.34 USD");
        assert_eq!(Money::new(5, Currency::USD).to_string(), "0.05 USD");
        assert_eq!(Money::new(-1234, Currency::USD).to_string(), "-12.34 USD");
        assert_eq!(Money::new(1234, Currency::JPY).to_string(), "1234 JPY");
        assert_eq!(
            Money::new(1_500_000, Currency::USDC).to_string(),
            "1.500000 USDC"
        );
    }

    #[test]
    fn adding_different_currencies_is_an_error_not_a_number() {
        let usd = Money::new(100, Currency::USD);
        let eur = Money::new(100, Currency::EUR);
        assert!(matches!(
            usd.checked_add(&eur),
            Err(MoneyError::CurrencyMismatch { .. })
        ));
        assert!(usd.try_cmp(&eur).is_err());
    }

    #[test]
    fn same_code_different_exponent_is_a_different_currency() {
        // The bug this prevents: treating 1_000_000 six-decimal units as
        // 1_000_000 cents, and authorizing ten thousand dollars.
        let cents = Currency::new("USD", 2).expect("valid");
        let micros = Currency::new("USD", 6).expect("valid");
        assert_ne!(cents, micros);
        let a = Money::new(1_000_000, cents);
        let b = Money::new(1_000_000, micros);
        assert!(a.checked_add(&b).is_err());
    }

    #[test]
    fn overflow_returns_an_error_rather_than_wrapping() {
        let big = Money::new(i128::MAX, Currency::USD);
        let one = Money::new(1, Currency::USD);
        assert_eq!(big.checked_add(&one), Err(MoneyError::Overflow));
    }

    #[test]
    fn negative_amounts_can_be_refused_at_a_boundary() {
        assert!(Money::new(-1, Currency::USD)
            .require_non_negative()
            .is_err());
        assert!(Money::new(0, Currency::USD).require_non_negative().is_ok());
    }

    #[test]
    fn parsing_a_written_amount_gives_exact_minor_units() {
        let p = |s| Money::parse(s, Currency::USD).expect("valid");
        assert_eq!(p("500.00 USD").minor(), 50_000);
        assert_eq!(
            p("5 USD").minor(),
            500,
            "a bare whole number is major units"
        );
        assert_eq!(p("0.05 USD").minor(), 5);
        assert_eq!(
            p("0.5 USD").minor(),
            50,
            "one decimal place is tenths, not hundredths"
        );
        assert_eq!(p("-12.34 USD").minor(), -1_234);
        assert_eq!(p("  500.00   usd  ").minor(), 50_000, "whitespace and case");
    }

    #[test]
    fn too_many_decimals_is_refused_rather_than_rounded() {
        // Silent rounding in a spend limit means the cap is a cent away from
        // what someone wrote in a file, and nobody ever finds out.
        assert!(matches!(
            Money::parse("1.005 USD", Currency::USD),
            Err(ParseMoneyError::TooManyDecimals {
                found: 3,
                allowed: 2
            })
        ));
        assert!(Money::parse("1.000000 USDC", Currency::USDC).is_ok());
        assert!(
            Money::parse("1.5 JPY", Currency::JPY).is_err(),
            "JPY has no minor unit"
        );
    }

    #[test]
    fn a_mismatched_currency_is_refused_not_reinterpreted() {
        assert!(matches!(
            Money::parse("500.00 EUR", Currency::USD),
            Err(ParseMoneyError::CurrencyMismatch { .. })
        ));
    }

    #[test]
    fn malformed_amounts_are_refused() {
        for bad in [
            "500.00", "USD", "", "abc USD", "1e3 USD", "0x10 USD", "1..2 USD", "+5 USD", ". USD",
            "5. USD",
        ] {
            assert!(
                Money::parse(bad, Currency::USD).is_err(),
                "should refuse {bad:?}"
            );
        }
    }

    #[test]
    fn parsing_round_trips_through_display() {
        for s in ["500.00 USD", "0.05 USD", "-12.34 USD"] {
            let m = Money::parse(s, Currency::USD).expect("valid");
            assert_eq!(m.to_string(), s, "display must be re-parseable");
            assert_eq!(
                Money::parse(&m.to_string(), Currency::USD).expect("valid"),
                m
            );
        }
    }

    #[test]
    fn the_built_in_currencies_are_well_formed() {
        // Guards the one function in this crate allowed to index and add
        // without checking. If a constant is ever added with a bad literal,
        // this fails rather than shipping a wrong currency code.
        for c in [
            Currency::USD,
            Currency::EUR,
            Currency::GBP,
            Currency::JPY,
            Currency::USDC,
        ] {
            assert!(!c.code().is_empty() && c.code().len() <= CODE_CAP, "{c:?}");
            assert!(c.code().bytes().all(|b| b.is_ascii_alphanumeric()), "{c:?}");
            assert!(c.exponent() <= MAX_EXPONENT, "{c:?}");
            assert_eq!(Currency::new(c.code(), c.exponent()).expect("valid"), c);
        }
    }

    #[test]
    fn currency_codes_are_validated_and_upcased() {
        assert_eq!(Currency::new("usd", 2).expect("valid").code(), "USD");
        assert!(Currency::new("", 2).is_err());
        assert!(Currency::new("TOOLONGCODE", 2).is_err());
        assert!(Currency::new("US$", 2).is_err());
        assert!(Currency::new("USD", 19).is_err());
    }

    #[test]
    fn money_round_trips_through_json() {
        let m = Money::new(1234, Currency::USDC);
        let json = serde_json::to_string(&m).expect("serialize");
        assert_eq!(
            json,
            r#"{"minor":"1234","currency":{"code":"USDC","exponent":6}}"#
        );
        let back: Money = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, m);
    }

    #[test]
    fn large_amounts_survive_a_json_round_trip_intact() {
        // Above 2^53. As a JSON number this would come back wrong in any
        // JavaScript client — including our own playground.
        let huge = Money::new(9_007_199_254_740_993, Currency::USDC);
        let json = serde_json::to_string(&huge).expect("serialize");
        assert!(json.contains(r#""9007199254740993""#), "{json}");
        let back: Money = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, huge);

        let extreme = Money::new(i128::MAX, Currency::USDC);
        let json = serde_json::to_string(&extreme).expect("serialize");
        let back: Money = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, extreme);
    }

    #[test]
    fn a_bad_currency_is_rejected_on_the_way_in() {
        let bad = r#"{"minor":"1","currency":{"code":"US$","exponent":2}}"#;
        assert!(serde_json::from_str::<Money>(bad).is_err());
    }

    #[test]
    fn a_non_numeric_amount_is_rejected_rather_than_defaulted() {
        assert!(serde_json::from_str::<Money>(
            r#"{"minor":"","currency":{"code":"USD","exponent":2}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Money>(
            r#"{"minor":"1.5","currency":{"code":"USD","exponent":2}}"#
        )
        .is_err());
    }
}
