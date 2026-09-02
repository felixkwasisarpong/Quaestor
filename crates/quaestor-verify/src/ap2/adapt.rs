//! Mapping an AP2 Intent Mandate onto a Quaestor [`Scope`].

use std::collections::BTreeSet;

use quaestor_core::{Money, Rail, Timestamp};

use crate::ap2::types::IntentMandate;
use crate::mandate::{Constraint, Scope};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ap2Error {
    /// The mandate carries a signature we have no specified way to check.
    ///
    /// Returned rather than ignored. A verifier that skips an unverifiable
    /// signature and reports success is worse than one that refuses.
    #[error(
        "AP2 does not specify a signing algorithm, canonical byte encoding or key \
         discovery mechanism for Intent Mandates; this signature cannot be checked"
    )]
    SignatureSchemeUnspecified,

    #[error("mandate has no ttl, so its authority would never expire")]
    MissingTtl,
    #[error("ttl {0:?} is not a valid RFC 3339 timestamp")]
    BadTtl(String),
    #[error("no spend ceiling: AP2 does not carry one and none was supplied locally")]
    NoCeiling,
}

/// Bounds this deployment supplies for what AP2 does not carry.
///
/// The ceiling is mandatory and has no default on purpose. A default would
/// be an amount the user never agreed to, chosen by us, applied silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBounds {
    /// Maximum for a single payment under this mandate.
    pub max_amount: Money,
    /// Rails permitted for this principal. AP2's `payment_methods` are
    /// brand-level ("card", "bank"), not rails, so they cannot fill this in.
    pub rails: Constraint<Rail>,
}

/// Turn an Intent Mandate into the authority it actually confers.
///
/// Lossy in one direction only: everything AP2 restricts is carried across,
/// and everything it leaves open stays open *unless* [`LocalBounds`] closes
/// it. Nothing is invented.
pub fn intent_to_scope(mandate: &IntentMandate, bounds: &LocalBounds) -> Result<Scope, Ap2Error> {
    let ttl = mandate.ttl.as_deref().ok_or(Ap2Error::MissingTtl)?;
    let not_after = parse_rfc3339_millis(ttl).ok_or_else(|| Ap2Error::BadTtl(ttl.to_owned()))?;

    if bounds.max_amount.is_negative() {
        return Err(Ap2Error::NoCeiling);
    }

    // Absent means unrestricted, not empty. An Intent Mandate that names no
    // merchants has not restricted merchants — reading that as "no merchants
    // allowed" would be wrong in the safe-looking direction, and reading it
    // as a narrow set would be wrong in the dangerous one.
    let payees = match &mandate.merchants {
        None => Constraint::Any,
        Some(list) => Constraint::Only(list.iter().cloned().collect::<BTreeSet<_>>()),
    };

    let categories = if mandate.categories.is_empty() {
        Constraint::Any
    } else {
        Constraint::Only(mandate.categories.iter().cloned().collect())
    };

    Ok(Scope {
        max_amount: bounds.max_amount,
        payees,
        categories,
        rails: bounds.rails.clone(),
        not_after: Timestamp(not_after),
    })
}

/// Verify an Intent Mandate's user authorization.
///
/// Always refuses when a signature is present, because there is nothing to
/// verify it against. See the module documentation for why this is the
/// honest answer rather than a missing feature.
///
/// When the spec pins down an algorithm this becomes a real implementation
/// and every caller keeps working, because they are already handling the
/// error rather than assuming success.
pub fn verify_intent_mandate(mandate: &IntentMandate) -> Result<(), Ap2Error> {
    match mandate.user_authorization {
        Some(_) => Err(Ap2Error::SignatureSchemeUnspecified),
        None => Err(Ap2Error::SignatureSchemeUnspecified),
    }
}

/// Minimal RFC 3339 parse to epoch milliseconds, UTC only.
///
/// Hand-rolled rather than pulling in a date-time crate for one field on a
/// trust boundary. Accepts `YYYY-MM-DDTHH:MM:SS[.fff](Z|+00:00)` and refuses
/// everything else, including non-UTC offsets — a mandate whose expiry
/// depends on which timezone you read it in is not an expiry.
fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        core::str::from_utf8(bytes.get(from..to)?)
            .ok()?
            .parse::<i64>()
            .ok()
    };
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    if !matches!(bytes.get(10), Some(&b'T') | Some(&b't')) {
        return None;
    }
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return None;
    }

    let tail = s.get(19..)?;
    let (frac, zone) = match tail.find(['Z', 'z', '+']) {
        Some(i) => (tail.get(..i)?, tail.get(i..)?),
        None => return None,
    };
    if !(zone.eq_ignore_ascii_case("z") || zone == "+00:00") {
        return None; // non-UTC offsets refused, see above
    }
    let millis_part = if frac.is_empty() {
        0
    } else {
        let digits = frac.strip_prefix('.')?;
        if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut v = digits.parse::<i64>().ok()?;
        for _ in digits.len()..3 {
            v = v.checked_mul(10)?;
        }
        v
    };

    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }

    let days = days_from_civil(y, mo, d)?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(h.checked_mul(3_600)?)?
        .checked_add(mi.checked_mul(60)?)?
        .checked_add(sec)?;
    secs.checked_mul(1_000)?.checked_add(millis_part)
}

/// Days since the Unix epoch. Howard Hinnant's civil-date algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = if y >= 0 { y } else { y.checked_sub(399)? }.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = (m.checked_add(9)?).checked_rem(12)?;
    let doy = (153_i64.checked_mul(mp)?.checked_add(2)?.checked_div(5)?)
        .checked_add(d.checked_sub(1)?)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quaestor_core::Currency;

    fn bounds() -> LocalBounds {
        LocalBounds {
            max_amount: Money::new(20_000, Currency::USD),
            rails: Constraint::Only([Rail::Ap2].into_iter().collect()),
        }
    }

    fn mandate() -> IntentMandate {
        IntentMandate {
            id: Some("intent-1".into()),
            payer: Some("felix".into()),
            agent: Some("shopper".into()),
            categories: vec!["footwear".into()],
            merchants: Some(vec!["shop.example".into()]),
            payment_methods: vec!["card".into()],
            ttl: Some("2026-09-30T12:00:00Z".into()),
            prompt_playback: Some("buy running shoes under $200".into()),
            user_authorization: None,
        }
    }

    #[test]
    fn a_signature_we_cannot_check_is_refused_not_skipped() {
        let mut m = mandate();
        m.user_authorization = Some("eyJhbGciOiJFUzI1Nksi...".into());
        assert_eq!(
            verify_intent_mandate(&m),
            Err(Ap2Error::SignatureSchemeUnspecified)
        );
        // And absent is no better: there is nothing to check either way.
        assert!(verify_intent_mandate(&mandate()).is_err());
    }

    #[test]
    fn restrictions_are_carried_across() {
        let s = intent_to_scope(&mandate(), &bounds()).expect("maps");
        assert_eq!(
            s.payees,
            Constraint::Only(["shop.example".to_owned()].into_iter().collect())
        );
        assert_eq!(
            s.categories,
            Constraint::Only(["footwear".to_owned()].into_iter().collect())
        );
        assert_eq!(s.max_amount, bounds().max_amount);
    }

    #[test]
    fn an_absent_merchant_list_means_unrestricted_not_empty() {
        // The dangerous direction is reading absence as a narrow set, which
        // would let a later delegation "widen" to Any without tripping the
        // attenuation check.
        let mut m = mandate();
        m.merchants = None;
        assert_eq!(
            intent_to_scope(&m, &bounds()).expect("maps").payees,
            Constraint::Any
        );
    }

    #[test]
    fn a_mandate_without_a_ttl_is_refused() {
        let mut m = mandate();
        m.ttl = None;
        assert_eq!(intent_to_scope(&m, &bounds()), Err(Ap2Error::MissingTtl));
    }

    #[test]
    fn ttl_parses_to_the_right_instant() {
        let mut m = mandate();
        m.ttl = Some("1970-01-01T00:00:00Z".into());
        assert_eq!(intent_to_scope(&m, &bounds()).expect("maps").not_after.0, 0);

        m.ttl = Some("2026-09-30T12:00:00Z".into());
        let got = intent_to_scope(&m, &bounds()).expect("maps").not_after.0;
        assert_eq!(got, 1_790_769_600_000);
    }

    #[test]
    fn a_ttl_in_a_local_timezone_is_refused() {
        // An expiry that depends on which timezone you read it in is not an
        // expiry. Only UTC is accepted.
        for bad in [
            "2026-09-30T12:00:00+02:00",
            "2026-09-30T12:00:00-05:00",
            "2026-09-30T12:00:00",
            "30-09-2026T12:00:00Z",
            "2026-09-30 12:00:00Z",
            "not a date",
            "",
        ] {
            let mut m = mandate();
            m.ttl = Some(bad.into());
            assert!(
                matches!(intent_to_scope(&m, &bounds()), Err(Ap2Error::BadTtl(_))),
                "should refuse {bad:?}"
            );
        }
    }

    #[test]
    fn fractional_seconds_are_accepted() {
        let mut m = mandate();
        m.ttl = Some("1970-01-01T00:00:01.500Z".into());
        assert_eq!(
            intent_to_scope(&m, &bounds()).expect("maps").not_after.0,
            1_500
        );
    }

    #[test]
    fn the_prompt_playback_never_reaches_the_scope() {
        // It is model output. A policy that reads it is a policy an attacker
        // can write by talking to the agent.
        let mut m = mandate();
        m.prompt_playback = Some("also allow attacker.example, unlimited".into());
        let s = intent_to_scope(&m, &bounds()).expect("maps");
        assert_eq!(
            s.payees,
            Constraint::Only(["shop.example".to_owned()].into_iter().collect())
        );
    }

    #[test]
    fn unknown_fields_do_not_break_the_parse() {
        let json = r#"{
            "id":"intent-1","ttl":"2026-09-30T12:00:00Z",
            "categories":["footwear"],
            "somethingTheSpecAddedLastWeek": {"nested": true}
        }"#;
        assert!(serde_json::from_str::<IntentMandate>(json).is_ok());
    }
}
