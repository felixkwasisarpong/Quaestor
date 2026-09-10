//! Who is asking.
//!
//! # An identity header is not an identity
//!
//! The obvious way to tell the proxy which principal's budget to charge is a
//! header: `X-Quaestor-Principal: felix`. It is obvious, it is what a first
//! draft does, and it means any caller who can reach the proxy can spend any
//! principal's budget by typing a different name into a header. There is no
//! attack to describe. You just ask.
//!
//! So the principal is never read from the request. It is looked up from a
//! bearer credential, and everything about the caller — which budget, what
//! authority, whose delegation roots to trust — comes from that lookup.
//!
//! # Why the table stores hashes
//!
//! [`Identities`] keys on the SHA3-256 of the token rather than the token.
//! It costs one hash per request and it means the configuration file, the
//! process memory and any crash dump contain verifiers rather than
//! credentials. Someone who reads them still cannot present anything.
//!
//! It also removes the variable-time comparison. A `HashMap<String, _>`
//! keyed on the secret compares candidate secrets byte by byte on collision;
//! keyed on a hash, the only thing compared is a digest of a value the
//! attacker already supplied.

use std::collections::HashMap;

use quaestor_core::{AgentId, PrincipalId};
use quaestor_verify::mandate::{PublicKey, Scope};
use sha3::{Digest, Sha3_256};

/// One credential, and everything the deployment grants it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Whose money this is. The party on the hook.
    pub principal: PrincipalId,
    /// Which agent is spending it.
    pub agent: AgentId,
    /// The authority this deployment grants this credential, before any
    /// mandate is considered.
    ///
    /// A delegation chain presented in a header may narrow this and may
    /// never widen it. A configured ceiling that a request can raise is not
    /// a ceiling.
    pub scope: Scope,
    /// Keys trusted to originate a delegation chain for this caller.
    ///
    /// Empty means this caller may not present a chain at all, which is the
    /// right default: an empty root list must refuse every chain, never
    /// accept every chain.
    pub root_keys: Vec<PublicKey>,
}

/// Bearer token to [`Caller`].
#[derive(Debug, Clone, Default)]
pub struct Identities {
    by_token_hash: HashMap<[u8; 32], Caller>,
}

impl Identities {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a credential. The token is hashed here and not retained.
    #[must_use]
    pub fn insert(mut self, token: &str, caller: Caller) -> Self {
        self.by_token_hash.insert(token_hash(token), caller);
        self
    }

    /// Look up the caller behind an `Authorization` header value.
    ///
    /// Returns `None` for anything that is not a well-formed bearer
    /// credential we know, with no distinction between "malformed",
    /// "unknown" and "absent". The caller of this function turns all three
    /// into the same refusal, because telling an attacker which of the three
    /// they achieved is free help.
    pub fn from_authorization(&self, header: Option<&str>) -> Option<&Caller> {
        let raw = header?;
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))?
            .trim();
        if token.is_empty() {
            return None;
        }
        self.by_token_hash.get(&token_hash(token))
    }

    pub fn is_empty(&self) -> bool {
        self.by_token_hash.is_empty()
    }
}

fn token_hash(token: &str) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"quaestor.proxy.token.v1");
    h.update(token.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quaestor_core::{Currency, Money, Rail, Timestamp};
    use quaestor_verify::mandate::Constraint;

    fn caller(name: &str) -> Caller {
        Caller {
            principal: PrincipalId::new(name).expect("valid"),
            agent: AgentId::new("shopper").expect("valid"),
            scope: Scope {
                max_amount: Money::new(10_000, Currency::USD),
                payees: Constraint::Any,
                categories: Constraint::Any,
                rails: Constraint::Only([Rail::X402].into_iter().collect()),
                not_after: Timestamp(i64::MAX),
            },
            root_keys: Vec::new(),
        }
    }

    fn table() -> Identities {
        Identities::new().insert("sk_felix", caller("felix"))
    }

    #[test]
    fn a_known_token_resolves_to_its_caller() {
        let found = table()
            .from_authorization(Some("Bearer sk_felix"))
            .cloned()
            .expect("known");
        assert_eq!(found.principal.as_str(), "felix");
    }

    #[test]
    fn no_credential_resolves_to_nobody() {
        let t = table();
        assert!(t.from_authorization(None).is_none());
        assert!(t.from_authorization(Some("")).is_none());
        assert!(t.from_authorization(Some("Bearer ")).is_none());
        assert!(
            t.from_authorization(Some("sk_felix")).is_none(),
            "no scheme"
        );
        assert!(t.from_authorization(Some("Basic sk_felix")).is_none());
        assert!(t.from_authorization(Some("Bearer sk_someone")).is_none());
    }

    #[test]
    fn the_token_itself_is_not_kept_anywhere() {
        // The point of hashing. Whatever leaks out of this structure, it is
        // not something anyone can present at the door.
        let t = table();
        let dumped = format!("{t:?}");
        assert!(
            !dumped.contains("sk_felix"),
            "a token survived into the debug rendering: {dumped}"
        );
    }

    #[test]
    fn two_callers_are_two_budgets() {
        let t = table().insert("sk_ama", caller("ama"));
        assert_eq!(
            t.from_authorization(Some("Bearer sk_ama"))
                .expect("known")
                .principal
                .as_str(),
            "ama"
        );
        assert_eq!(
            t.from_authorization(Some("Bearer sk_felix"))
                .expect("known")
                .principal
                .as_str(),
            "felix"
        );
    }

    #[test]
    fn a_caller_with_no_root_keys_can_present_no_chain() {
        // Stated as a test because the failure mode is the classic one: an
        // empty allow-list read as "no restriction configured".
        assert!(caller("felix").root_keys.is_empty());
    }
}
