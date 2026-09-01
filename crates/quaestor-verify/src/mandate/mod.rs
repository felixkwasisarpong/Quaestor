//! Mandates and delegation chains.
//!
//! Protocol-independent on purpose. AP2 Intent and Cart Mandates, ACP
//! delegated tokens and MPP session grants all express the same idea — a
//! narrowing grant of spending authority — in different envelopes. The
//! attenuation rules belong here once; the envelopes belong in adapters.

pub mod chain;
pub mod scope;

pub use chain::{verify_chain, Authority, ChainError, Mandate, PublicKey, MAX_CHAIN_DEPTH};
pub use scope::{Constraint, Scope, Widening};
