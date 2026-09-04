//! The answer.
//!
//! Three arms, not two. Binary allow/deny is what every general-purpose
//! policy engine offers and it is exactly why none of them works for money:
//! the interesting case is "this is within your authority but outside your
//! habits", and the only correct response to that is to ask someone.
//!
//! Note that every arm carries a receipt, including `Deny`. Refusals are as
//! auditable as approvals — for a regulated user that is the whole product.

use serde::{Deserialize, Serialize};

use crate::ids::{IntentId, PrincipalId};
use crate::intent::Timestamp;
use crate::money::Money;

/// Why a payment was refused. Machine-readable, because the agent has to be
/// able to react to it without parsing English.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DenyReason {
    /// The mandate's signature did not verify.
    BadSignature,
    /// The mandate is structurally valid but no longer live.
    MandateExpired { expired_at: Timestamp },
    /// A delegated mandate claimed authority its parent did not have. The
    /// most important check in the system.
    ScopeWidened { detail: String },
    /// No mandate at all, where policy required one.
    MandateMissing,
    /// A cap would be breached.
    BudgetExceeded {
        limit: Money,
        attempted: Money,
        remaining: Money,
    },
    /// Too many payments too quickly.
    VelocityExceeded {
        limit_per_window: u32,
        window_ms: i64,
    },
    /// The payee is explicitly forbidden.
    PayeeBlocked,
    /// The merchant category is explicitly forbidden.
    CategoryBlocked { category: String },
    /// A rule could not be evaluated because the state it needs was not
    /// available.
    ///
    /// This is a denial, not a pass. A budget we cannot read is a budget we
    /// cannot honour, and the safe answer to "I don't know" is no.
    StateUnavailable { detail: String },
    /// The rail is not permitted for this principal.
    RailNotPermitted,
    /// A human was asked and said no.
    ApprovalDenied,
    /// A human was asked and never answered.
    ApprovalExpired,
    /// The amount was negative or otherwise nonsensical.
    MalformedIntent { detail: String },
}

/// Why a payment needs a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum EscalationReason {
    /// Never paid this payee before.
    FirstSeenPayee,
    /// Would consume more than the configured fraction of a remaining budget.
    LargeShareOfBudget { remaining: Money, attempted: Money },
    /// Above the amount this principal lets the agent spend unattended.
    AboveUnattendedLimit { limit: Money },
    /// Policy named this payee or category as always requiring approval.
    PolicyRequiresApproval { rule: String },
}

/// A reserved amount against a budget. Held, not spent — released if the
/// capture never happens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub intent: IntentId,
    pub amount: Money,
    /// A hold that is never captured must expire, or a crashed agent
    /// silently freezes a budget forever.
    pub expires_at: Timestamp,
}

/// Who was asked to approve, and by what channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    pub principal: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

/// The outcome of evaluating one [`crate::intent::PaymentIntent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Allow {
        hold: Hold,
    },
    Deny {
        /// Non-empty. A denial without a stated reason is a bug.
        reasons: Vec<DenyReason>,
    },
    Escalate {
        to: Approver,
        reasons: Vec<EscalationReason>,
        /// An unanswered escalation resolves to `Deny`, never to `Allow`.
        expires_at: Timestamp,
    },
}

impl Verdict {
    pub const fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }

    /// True when money is permitted to move right now. An escalation is not
    /// an allow, and this method exists so no call site can forget that.
    pub const fn permits_payment(&self) -> bool {
        self.is_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::IntentId;
    use crate::money::{Currency, Money};

    fn hold() -> Hold {
        Hold {
            intent: IntentId::new("int-1").expect("valid"),
            amount: Money::new(1999, Currency::USD),
            expires_at: Timestamp(1_772_000_060_000),
        }
    }

    #[test]
    fn escalation_does_not_permit_payment() {
        let v = Verdict::Escalate {
            to: Approver {
                principal: PrincipalId::new("felix").expect("valid"),
                channel: None,
            },
            reasons: vec![EscalationReason::FirstSeenPayee],
            expires_at: Timestamp(1_772_000_300_000),
        };
        assert!(
            !v.permits_payment(),
            "an escalation must never read as an allow"
        );
    }

    #[test]
    fn only_allow_permits_payment() {
        assert!(Verdict::Allow { hold: hold() }.permits_payment());
        assert!(!Verdict::Deny {
            reasons: vec![DenyReason::PayeeBlocked]
        }
        .permits_payment());
    }

    #[test]
    fn verdicts_are_tagged_on_the_wire_so_they_cannot_be_confused() {
        let json = serde_json::to_string(&Verdict::Allow { hold: hold() }).expect("serialize");
        assert!(json.starts_with(r#"{"verdict":"allow""#), "{json}");

        let denied = Verdict::Deny {
            reasons: vec![DenyReason::BadSignature],
        };
        let json = serde_json::to_string(&denied).expect("serialize");
        assert!(json.contains(r#""verdict":"deny""#), "{json}");
        assert!(json.contains(r#""code":"bad_signature""#), "{json}");
    }

    #[test]
    fn budget_denials_carry_the_numbers_a_human_will_ask_for() {
        let reason = DenyReason::BudgetExceeded {
            limit: Money::new(5000, Currency::USD),
            attempted: Money::new(19999, Currency::USD),
            remaining: Money::new(1200, Currency::USD),
        };
        let json = serde_json::to_string(&reason).expect("serialize");
        let back: DenyReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reason, back);
    }
}
