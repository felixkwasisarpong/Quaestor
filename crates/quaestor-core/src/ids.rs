//! Identifiers.
//!
//! Every id is its own type. An `AgentId` cannot be passed where a
//! `PrincipalId` is expected, which is the entire point — the distinction
//! between "who acted" and "on whose authority" is the one this system is
//! built to keep straight, and the compiler should be enforcing it rather
//! than a code review.

use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("identifier is empty")]
    Empty,
    #[error("identifier exceeds {0} bytes")]
    TooLong(usize),
    #[error("identifier contains a character outside [A-Za-z0-9._:-]")]
    BadCharacter,
}

const ID_MAX: usize = 128;

fn validate(s: &str) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > ID_MAX {
        return Err(IdError::TooLong(ID_MAX));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(IdError::BadCharacter);
    }
    Ok(())
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
                let s = s.into();
                validate(&s)?;
                Ok($name(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                $name::new(s)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    };
}

id_type! {
    /// A single authorization decision.
    IntentId
}

id_type! {
    /// The software actor attempting to spend. Never the economic actor.
    AgentId
}

id_type! {
    /// The human or organization on whose authority the agent is acting,
    /// and who is economically liable for the result.
    PrincipalId
}

id_type! {
    /// Who a payment is going to, as the rail identifies them.
    PayeeId
}

id_type! {
    /// Caller-supplied key making a request safe to retry. Same key, same
    /// verdict, replayed — never re-executed.
    IdempotencyKey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_reject_empty_overlong_and_exotic_input() {
        assert!(AgentId::new("").is_err());
        assert!(AgentId::new("a".repeat(ID_MAX + 1)).is_err());
        assert!(AgentId::new("agent 1").is_err());
        assert!(AgentId::new("agent/../etc").is_err());
        assert!(AgentId::new("agent:shopper-01").is_ok());
    }

    #[test]
    fn ids_validate_when_deserialized_not_just_when_constructed() {
        assert!(serde_json::from_str::<AgentId>(r#""ok-1""#).is_ok());
        assert!(serde_json::from_str::<AgentId>(r#""not ok""#).is_err());
        assert!(serde_json::from_str::<AgentId>(r#""""#).is_err());
    }

    #[test]
    fn an_agent_id_is_not_a_principal_id() {
        // This test documents a compile-time property. The line below must
        // not compile, and that is the whole reason these are newtypes:
        //
        //     let _: PrincipalId = AgentId::new("a").unwrap();
        //
        let agent = AgentId::new("shopper").expect("valid");
        let principal = PrincipalId::new("shopper").expect("valid");
        assert_eq!(agent.as_str(), principal.as_str());
    }
}
