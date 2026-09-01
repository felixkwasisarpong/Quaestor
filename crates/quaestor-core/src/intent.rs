//! The canonical payment intent.
//!
//! This is the keystone type. Layer 0 — the wire adapters — turn an x402
//! challenge, an AP2 cart mandate or a Stripe checkout into one of these.
//! Every layer above it operates on this and only this, and has never heard
//! of a blockchain.
//!
//! If you find yourself wanting to add a protocol-specific field here, that
//! is the design failing. Put it in the adapter, or generalise it.

use serde::{Deserialize, Serialize};

use crate::ids::{AgentId, IdempotencyKey, IntentId, PayeeId, PrincipalId};
use crate::money::Money;

/// Which rail the money would actually move over. Layers above L0 use this
/// for policy ("never pay over an on-chain rail") and for nothing else.
/// `Ord` is derived so a set of rails has a stable iteration order. That
/// matters more than it looks: constraint sets are serialized into the bytes
/// a mandate signature covers, and an unstable order would make an identical
/// grant produce a different signature on every run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rail {
    X402,
    Ap2,
    Acp,
    Mpp,
    Ucp,
    Card,
    Other,
}

/// Who is being paid, as much as the rail will tell us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payee {
    pub id: PayeeId,
    pub rail: Rail,
    /// Merchant category, where the rail supplies one. Policy can cap by
    /// category, so this is load-bearing when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Hostname, for HTTP-native rails. The basis of first-seen-payee rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Where in the agent's execution this payment came from. Carried so a spend
/// can be traced back to the tool call that caused it — the question every
/// incident review asks first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Set when this payment was triggered by another. Lets policy reason
    /// about a runaway loop rather than seeing 400 unrelated small charges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_intent: Option<IntentId>,
}

/// Milliseconds since the Unix epoch.
///
/// Deliberately not a `SystemTime`: policy evaluation must be a pure
/// function of its inputs, so the current time is passed in, never read.
/// That is what makes a decision replayable a year later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub const fn as_millis(&self) -> i64 {
        self.0
    }

    /// Milliseconds elapsed from `earlier` to `self`. `None` on overflow.
    pub fn since(&self, earlier: Timestamp) -> Option<i64> {
        self.0.checked_sub(earlier.0)
    }
}

/// A payment an agent wants to make, normalised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub id: IntentId,
    pub idempotency_key: IdempotencyKey,

    /// The software actor making the attempt.
    pub agent: AgentId,
    /// The party whose authority is being spent, and who is liable. An agent
    /// is never the economic actor; keeping these separate is what makes the
    /// delegation chain answerable.
    pub principal: PrincipalId,

    pub amount: Money,
    pub payee: Payee,

    #[serde(default)]
    pub context: CallContext,
    pub requested_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::*;
    use crate::money::Currency;

    fn intent() -> PaymentIntent {
        PaymentIntent {
            id: IntentId::new("int-1").expect("valid"),
            idempotency_key: IdempotencyKey::new("key-1").expect("valid"),
            agent: AgentId::new("shopper").expect("valid"),
            principal: PrincipalId::new("felix").expect("valid"),
            amount: Money::new(1999, Currency::USD),
            payee: Payee {
                id: PayeeId::new("api.example.com").expect("valid"),
                rail: Rail::X402,
                category: Some("saas".into()),
                domain: Some("api.example.com".into()),
            },
            context: CallContext::default(),
            requested_at: Timestamp(1_772_000_000_000),
        }
    }

    #[test]
    fn an_intent_round_trips_through_json_unchanged() {
        let a = intent();
        let json = serde_json::to_string(&a).expect("serialize");
        let b: PaymentIntent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(a, b);
    }

    #[test]
    fn absent_optional_context_does_not_appear_on_the_wire() {
        let json = serde_json::to_string(&intent()).expect("serialize");
        assert!(
            !json.contains("session_id"),
            "empty context should be omitted: {json}"
        );
    }

    #[test]
    fn timestamps_subtract_without_panicking_at_the_extremes() {
        assert_eq!(Timestamp(500).since(Timestamp(200)), Some(300));
        assert_eq!(Timestamp(i64::MIN).since(Timestamp(1)), None);
    }
}
