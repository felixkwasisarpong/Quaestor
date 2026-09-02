//! AP2 wire types, as far as the specification pins them down.
//!
//! Fields here follow the published prose field list. Where the spec gives a
//! name but no type, the field is `Option` and typed loosely — being wrong
//! about a shape we were never told is worse than admitting we do not know.
//!
//! Unknown fields are tolerated at this level, because the spec is young and
//! moving. That is the opposite of the choice made for
//! [`crate::x402::types::ExactEvmAuthorization`], and the reason is the
//! signature: there, unknown keys were unsigned data smuggled into an
//! authenticated structure, so refusing them was the safe default. Here
//! nothing is authenticated yet, so strictness would buy nothing and break
//! on every spec revision.

use serde::{Deserialize, Serialize};

/// Prospective authority: what the user will let an agent buy later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentMandate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Who is delegating. The party ultimately liable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,

    /// The agent receiving authority, where the mandate names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,

    /// Product categories the agent may buy within.
    #[serde(default)]
    pub categories: Vec<String>,

    /// Merchants the agent may pay, when the mandate restricts them.
    ///
    /// The spec describes merchant scoping in prose without naming a field;
    /// this is our reading, and it is why the mapping is `Any` when absent
    /// rather than empty. An absent restriction is not a restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchants: Option<Vec<String>>,

    /// Authorized payment methods, as a list or a category.
    #[serde(default)]
    pub payment_methods: Vec<String>,

    /// Expiry. RFC 3339, per the spec's ISO-8601 timestamps elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,

    /// The agent's natural-language restatement of what the user asked for.
    ///
    /// Carried for the audit trail and never used in a decision: it is model
    /// output, and a policy that reads it is a policy an attacker can write
    /// by talking to the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_playback: Option<String>,

    /// Present in real payloads; format unspecified. See the module docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authorization: Option<String>,
}

/// A finalized purchase, authorized with the user present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CartMandate {
    pub id: String,
    #[serde(default)]
    pub user_signature_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_request: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Which Intent Mandate authorized this cart.
    ///
    /// The spec describes the relationship but does not name the field, so
    /// a cart cannot currently be tied back to its authorizing intent in any
    /// way an implementation could agree on. That is a real gap, not an
    /// omission here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_mandate_id: Option<String>,
}
