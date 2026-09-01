//! Scope: the authority a mandate grants, and the rule that it can only
//! ever shrink.
//!
//! # Monotonic attenuation
//!
//! This module exists for one property. When authority is delegated —
//! a person to their agent, that agent to a sub-agent — the child can be
//! given *less* than the parent held, never more. Formally, for every link
//! in a chain, `child ⊆ parent`.
//!
//! It sounds obvious. It is the thing implementations get wrong, and the
//! way they get it wrong is almost always the same: an unconstrained field.
//! If "no payee restriction" and "these three payees" are both representable
//! and you compare them naively, a child that drops the restriction reads as
//! equal-or-narrower and quietly gains the whole world. So the subset rules
//! below are asymmetric on purpose, and `Any ⊆ Only(_)` is false.
//!
//! The idea is not ours; it is the attenuation property from Macaroons, in
//! the shape money needs.

use std::collections::BTreeSet;

use quaestor_core::{Money, MoneyError, Rail, Timestamp};
use serde::{Deserialize, Serialize};

/// A restriction over a set of values.
///
/// `Any` is strictly wider than any `Only`, including an `Only` listing
/// everything currently known — because "everything currently known" and
/// "whatever exists tomorrow" are different grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Constraint<T: Ord> {
    /// No restriction. Only meaningful at the root of a chain.
    Any,
    /// Restricted to exactly this set. An empty set grants nothing, which is
    /// legal — it is the narrowest possible authority, not an error.
    Only(BTreeSet<T>),
}

impl<T: Ord + Clone> Constraint<T> {
    /// Is `self` no wider than `other`?
    pub fn is_within(&self, other: &Constraint<T>) -> bool {
        match (self, other) {
            // Widening. The case everything hinges on.
            (Constraint::Any, Constraint::Only(_)) => false,
            (Constraint::Any, Constraint::Any) => true,
            (Constraint::Only(_), Constraint::Any) => true,
            (Constraint::Only(mine), Constraint::Only(theirs)) => mine.is_subset(theirs),
        }
    }

    /// The largest constraint no wider than either input.
    pub fn intersect(&self, other: &Constraint<T>) -> Constraint<T> {
        match (self, other) {
            (Constraint::Any, c) | (c, Constraint::Any) => c.clone(),
            (Constraint::Only(a), Constraint::Only(b)) => {
                Constraint::Only(a.intersection(b).cloned().collect())
            }
        }
    }

    pub fn permits(&self, value: &T) -> bool {
        match self {
            Constraint::Any => true,
            Constraint::Only(set) => set.contains(value),
        }
    }
}

/// The authority a mandate confers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Ceiling on a single payment under this mandate.
    ///
    /// Cumulative spend is a budget, and budgets are the policy engine's
    /// job — they need durable state, and this type is pure. Here we bound
    /// what one authorization may be worth.
    pub max_amount: Money,
    pub payees: Constraint<String>,
    pub categories: Constraint<String>,
    pub rails: Constraint<Rail>,
    /// Authority ends here, regardless of anything downstream.
    pub not_after: Timestamp,
}

/// Why one scope is not contained by another.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Widening {
    #[error("amount ceiling raised from {parent} to {child}")]
    AmountRaised { parent: Money, child: Money },
    #[error("amount ceilings are in different currencies: {0}")]
    CurrencyChanged(MoneyError),
    #[error("payee restriction widened")]
    PayeesWidened,
    #[error("category restriction widened")]
    CategoriesWidened,
    #[error("rail restriction widened")]
    RailsWidened,
    #[error("expiry extended from {parent:?} to {child:?}")]
    ExpiryExtended { parent: Timestamp, child: Timestamp },
}

impl Scope {
    /// Is this scope contained by `parent`? `Ok(())` means yes.
    ///
    /// Every dimension is checked and the *first* widening is reported. A
    /// caller only needs to know the delegation was invalid; the detail is
    /// for the human reading the receipt afterwards.
    pub fn is_within(&self, parent: &Scope) -> Result<(), Widening> {
        // Currency is part of the comparison, not an afterthought: a child
        // claiming 100 of a different unit is not obviously smaller, and
        // "obviously" is not a standard this code works to.
        match self.max_amount.try_cmp(&parent.max_amount) {
            Err(e) => return Err(Widening::CurrencyChanged(e)),
            Ok(std::cmp::Ordering::Greater) => {
                return Err(Widening::AmountRaised {
                    parent: parent.max_amount,
                    child: self.max_amount,
                })
            }
            Ok(_) => {}
        }

        if !self.payees.is_within(&parent.payees) {
            return Err(Widening::PayeesWidened);
        }
        if !self.categories.is_within(&parent.categories) {
            return Err(Widening::CategoriesWidened);
        }
        if !self.rails.is_within(&parent.rails) {
            return Err(Widening::RailsWidened);
        }
        if self.not_after > parent.not_after {
            return Err(Widening::ExpiryExtended {
                parent: parent.not_after,
                child: self.not_after,
            });
        }
        Ok(())
    }

    /// The authority both scopes agree on.
    ///
    /// Chain verification returns the running intersection rather than the
    /// leaf's own scope. If attenuation is enforced correctly the two are
    /// identical — so this is belt and braces, and it means a bug in the
    /// attenuation check cannot on its own widen an agent's authority.
    pub fn intersect(&self, other: &Scope) -> Result<Scope, MoneyError> {
        let max_amount = match self.max_amount.try_cmp(&other.max_amount)? {
            std::cmp::Ordering::Greater => other.max_amount,
            _ => self.max_amount,
        };
        Ok(Scope {
            max_amount,
            payees: self.payees.intersect(&other.payees),
            categories: self.categories.intersect(&other.categories),
            rails: self.rails.intersect(&other.rails),
            not_after: self.not_after.min(other.not_after),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quaestor_core::Currency;

    fn only(items: &[&str]) -> Constraint<String> {
        Constraint::Only(items.iter().map(|s| (*s).to_owned()).collect())
    }

    fn scope(max_minor: i128) -> Scope {
        Scope {
            max_amount: Money::new(max_minor, Currency::USD),
            payees: only(&["shop.example", "api.example"]),
            categories: only(&["saas"]),
            rails: Constraint::Only([Rail::X402].into_iter().collect()),
            not_after: Timestamp(1_772_000_000_000),
        }
    }

    #[test]
    fn dropping_a_restriction_is_widening_not_narrowing() {
        // The bug this whole module exists to prevent. A child that says
        // "any payee" must not read as within a parent that named three.
        let parent = scope(10_000);
        let mut child = scope(10_000);
        child.payees = Constraint::Any;
        assert_eq!(child.is_within(&parent), Err(Widening::PayeesWidened));
    }

    #[test]
    fn a_root_with_no_restriction_can_delegate_a_restricted_child() {
        let mut root = scope(10_000);
        root.payees = Constraint::Any;
        root.categories = Constraint::Any;
        root.rails = Constraint::Any;
        assert_eq!(scope(10_000).is_within(&root), Ok(()));
    }

    #[test]
    fn a_child_may_narrow_but_never_raise_the_ceiling() {
        let parent = scope(10_000);
        assert_eq!(scope(5_000).is_within(&parent), Ok(()));
        assert_eq!(scope(10_000).is_within(&parent), Ok(()));
        assert!(matches!(
            scope(10_001).is_within(&parent),
            Err(Widening::AmountRaised { .. })
        ));
    }

    #[test]
    fn a_child_cannot_change_currency_to_dodge_the_ceiling() {
        // 100 EUR is not "less than" 10000 US cents. Refuse rather than
        // guess at a rate — this crate does not know what money is worth.
        let parent = scope(10_000);
        let mut child = scope(100);
        child.max_amount = Money::new(100, Currency::EUR);
        assert!(matches!(
            child.is_within(&parent),
            Err(Widening::CurrencyChanged(_))
        ));
    }

    #[test]
    fn a_child_cannot_outlive_its_parent() {
        let parent = scope(10_000);
        let mut child = scope(10_000);
        child.not_after = Timestamp(parent.not_after.0 + 1);
        assert!(matches!(
            child.is_within(&parent),
            Err(Widening::ExpiryExtended { .. })
        ));

        child.not_after = Timestamp(parent.not_after.0 - 1);
        assert_eq!(child.is_within(&parent), Ok(()));
    }

    #[test]
    fn adding_a_payee_the_parent_never_had_is_widening() {
        let parent = scope(10_000);
        let mut child = scope(10_000);
        child.payees = only(&["shop.example", "attacker.example"]);
        assert_eq!(child.is_within(&parent), Err(Widening::PayeesWidened));
    }

    #[test]
    fn granting_nothing_is_legal_and_is_the_narrowest_authority() {
        let parent = scope(10_000);
        let mut child = scope(0);
        child.payees = Constraint::Only(BTreeSet::new());
        assert_eq!(child.is_within(&parent), Ok(()));
        assert!(!child.payees.permits(&"shop.example".to_owned()));
    }

    #[test]
    fn containment_is_reflexive_and_transitive() {
        let a = scope(10_000);
        let b = scope(5_000);
        let c = scope(1_000);
        assert_eq!(a.is_within(&a), Ok(()));
        assert_eq!(b.is_within(&a), Ok(()));
        assert_eq!(c.is_within(&b), Ok(()));
        assert_eq!(c.is_within(&a), Ok(()), "transitivity must hold");
    }

    #[test]
    fn intersection_never_exceeds_either_input() {
        let a = scope(10_000);
        let mut b = scope(5_000);
        b.payees = only(&["shop.example"]);

        let i = a.intersect(&b).expect("same currency");
        assert_eq!(i.is_within(&a), Ok(()));
        assert_eq!(i.is_within(&b), Ok(()));
        assert_eq!(i.max_amount.minor(), 5_000);
        assert_eq!(i.payees, only(&["shop.example"]));
    }

    #[test]
    fn intersecting_any_with_a_restriction_keeps_the_restriction() {
        assert_eq!(
            Constraint::Any.intersect(&only(&["a"])),
            only(&["a"]),
            "Any must not swallow a restriction"
        );
    }
}
