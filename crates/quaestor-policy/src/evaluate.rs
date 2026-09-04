//! The evaluator.
//!
//! # Shape of the decision
//!
//! Every check is run. None of them short-circuits. Denials and escalations
//! are collected, and only then combined:
//!
//! > any denial wins, else any escalation wins, else allow.
//!
//! Short-circuiting on the first denial would be faster and would produce a
//! result that depends on the order the checks happen to be written in. It
//! also gives whoever reads the receipt one reason when there were four,
//! which is the difference between "your budget is exhausted" and "your
//! budget is exhausted, this payee is blocked, and the mandate expired an
//! hour ago". Running everything makes the verdict a function of the inputs
//! alone, which is the property this whole crate exists to have.
//!
//! # Two layers of "no"
//!
//! Authority and policy are separate questions and both are checked.
//!
//! *Authority* is what the delegation chain actually granted. A payment
//! outside it is not merely against the rules, it was never authorized by
//! the person on the hook for it.
//!
//! *Policy* is what this deployment additionally chooses to allow. It can
//! only narrow. There is deliberately no way for a policy file to permit
//! something the mandate did not.

use quaestor_core::{
    Approver, DenyReason, EscalationReason, Hold, Money, PaymentIntent, Timestamp, Verdict,
};
use quaestor_verify::mandate::Scope;

use crate::rules::Policy;
use crate::state::SpendSnapshot;

/// Everything a decision depends on, in one place.
///
/// Bundled into a struct rather than passed as six arguments so that adding
/// an input is a visible change at every call site rather than a silent
/// default. In an authorization function, an argument you forgot to pass is
/// a check you forgot to run.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub intent: &'a PaymentIntent,
    /// The authority the verified delegation chain conferred.
    pub authority: &'a Scope,
    pub policy: &'a Policy,
    pub state: &'a SpendSnapshot,
    /// Passed in, never read from a clock. See the crate docs.
    pub now: Timestamp,
}

pub fn evaluate(req: &Request<'_>) -> Verdict {
    let mut denials: Vec<DenyReason> = Vec::new();
    let mut escalations: Vec<EscalationReason> = Vec::new();

    let amount = req.intent.amount;
    let payee_key = payee_key(req.intent);

    // ---- structural ----------------------------------------------------
    if amount.is_negative() {
        denials.push(DenyReason::MalformedIntent {
            detail: format!("amount is negative: {amount}"),
        });
    }
    if amount.currency() != req.policy.currency {
        denials.push(DenyReason::MalformedIntent {
            detail: format!(
                "payment is in {}, policy is written in {}",
                amount.currency(),
                req.policy.currency
            ),
        });
    }

    // ---- authority: what the chain actually granted ---------------------
    if req.authority.not_after < req.now {
        denials.push(DenyReason::MandateExpired {
            expired_at: req.authority.not_after,
        });
    }
    match amount.try_cmp(&req.authority.max_amount) {
        Ok(std::cmp::Ordering::Greater) => denials.push(DenyReason::ScopeWidened {
            detail: format!(
                "payment of {amount} exceeds the delegated ceiling of {}",
                req.authority.max_amount
            ),
        }),
        Ok(_) => {}
        Err(e) => denials.push(DenyReason::MalformedIntent {
            detail: format!("cannot compare payment to the delegated ceiling: {e}"),
        }),
    }
    if !req.authority.payees.permits(&payee_key) {
        denials.push(DenyReason::ScopeWidened {
            detail: format!("payee {payee_key} is outside the delegated authority"),
        });
    }
    if let Some(category) = &req.intent.payee.category {
        if !req.authority.categories.permits(category) {
            denials.push(DenyReason::ScopeWidened {
                detail: format!("category {category} is outside the delegated authority"),
            });
        }
    }
    if !req.authority.rails.permits(&req.intent.payee.rail) {
        denials.push(DenyReason::RailNotPermitted);
    }

    // ---- policy denials -------------------------------------------------
    if req.policy.deny_payees.iter().any(|p| p == &payee_key) {
        denials.push(DenyReason::PayeeBlocked);
    }
    if let Some(category) = &req.intent.payee.category {
        if req.policy.deny_categories.iter().any(|c| c == category) {
            denials.push(DenyReason::CategoryBlocked {
                category: category.clone(),
            });
        }
    }

    // ---- budgets --------------------------------------------------------
    //
    // Each configured window is checked against the snapshot. A window with
    // no figure is a denial: a budget we cannot read is a budget we cannot
    // honour, and the safe answer to "I don't know" is no.
    for budget in &req.policy.budgets {
        let Some(spent) = req.state.spent_in(budget.window_ms) else {
            denials.push(DenyReason::StateUnavailable {
                detail: format!("no spend figure for the {} window", budget.window_label),
            });
            continue;
        };

        let (Ok(after), Ok(remaining)) =
            (spent.checked_add(&amount), budget.limit.checked_sub(&spent))
        else {
            denials.push(DenyReason::StateUnavailable {
                detail: format!("could not total the {} window", budget.window_label),
            });
            continue;
        };

        match after.try_cmp(&budget.limit) {
            Ok(std::cmp::Ordering::Greater) => denials.push(DenyReason::BudgetExceeded {
                limit: budget.limit,
                attempted: amount,
                remaining: if remaining.is_negative() {
                    Money::zero(budget.limit.currency())
                } else {
                    remaining
                },
            }),
            Ok(_) => {
                // Inside the cap, but is it most of what is left?
                if let Some(percent) = req.policy.escalate_above_remaining_percent {
                    if consumes_more_than(&amount, &remaining, percent) {
                        escalations.push(EscalationReason::LargeShareOfBudget {
                            remaining,
                            attempted: amount,
                        });
                    }
                }
            }
            Err(_) => denials.push(DenyReason::StateUnavailable {
                detail: format!(
                    "currency mismatch against the {} budget",
                    budget.window_label
                ),
            }),
        }
    }

    // ---- velocity -------------------------------------------------------
    if let Some(v) = &req.policy.velocity {
        match req.state.velocity() {
            None => denials.push(DenyReason::StateUnavailable {
                detail: format!(
                    "no payment count for the {} velocity window",
                    v.window_label
                ),
            }),
            Some(count) if count >= v.max_payments => {
                denials.push(DenyReason::VelocityExceeded {
                    limit_per_window: v.max_payments,
                    window_ms: v.window_ms,
                });
            }
            Some(_) => {}
        }
    }

    // ---- escalations ----------------------------------------------------
    if matches!(
        amount.try_cmp(&req.policy.unattended_limit),
        Ok(std::cmp::Ordering::Greater)
    ) {
        escalations.push(EscalationReason::AboveUnattendedLimit {
            limit: req.policy.unattended_limit,
        });
    }
    if req.policy.escalate_first_seen_payee && !req.state.payee_seen_before() {
        escalations.push(EscalationReason::FirstSeenPayee);
    }
    if req.policy.escalate_payees.iter().any(|p| p == &payee_key) {
        escalations.push(EscalationReason::PolicyRequiresApproval {
            rule: format!("payees.always_escalate contains {payee_key}"),
        });
    }

    // ---- combine --------------------------------------------------------
    if !denials.is_empty() {
        return Verdict::Deny { reasons: denials };
    }
    if !escalations.is_empty() {
        return Verdict::Escalate {
            to: Approver {
                principal: req.intent.principal.clone(),
                channel: None,
            },
            reasons: escalations,
            expires_at: Timestamp(
                req.now
                    .as_millis()
                    .saturating_add(req.policy.approval_ttl_ms),
            ),
        };
    }
    Verdict::Allow {
        hold: Hold {
            intent: req.intent.id.clone(),
            amount,
            expires_at: Timestamp(req.now.as_millis().saturating_add(req.policy.hold_ttl_ms)),
        },
    }
}

/// Would `amount` consume more than `percent` of `remaining`?
///
/// Integer throughout: `amount * 100 > remaining * percent`, which is the
/// same comparison as `amount / remaining > percent / 100` without ever
/// dividing. Overflow answers "yes", because a number large enough to
/// overflow this is certainly a large share of any budget, and the
/// consequence of a wrong "yes" is a human being asked.
fn consumes_more_than(amount: &Money, remaining: &Money, percent: u32) -> bool {
    if remaining.is_negative() || remaining.is_zero() {
        return true;
    }
    let (Some(lhs), Some(rhs)) = (
        amount.minor().checked_mul(100),
        remaining.minor().checked_mul(i128::from(percent)),
    ) else {
        return true;
    };
    lhs > rhs
}

/// How a payee is named for policy purposes.
///
/// The hostname where the rail supplies one, since that is what a person
/// writes in a policy file; the rail's own identifier otherwise.
fn payee_key(intent: &PaymentIntent) -> String {
    intent
        .payee
        .domain
        .clone()
        .unwrap_or_else(|| intent.payee.id.as_str().to_owned())
}
