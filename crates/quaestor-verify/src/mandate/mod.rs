//! Mandates and delegation chains.
//!
//! Protocol-independent on purpose. AP2 Intent and Cart Mandates, ACP
//! delegated tokens and MPP session grants all express the same idea — a
//! narrowing grant of spending authority — in different envelopes. The
//! attenuation rules belong here once; the envelopes belong in adapters.

/// Signed delegation chains. Behind the `crypto` feature.
///
/// [`scope`] is not: whether one grant is contained by another is a question
/// about sets and integers, and answering it needs no signature. Keeping the
/// two separable is what lets the attenuation rules be checked in a browser.
#[cfg(feature = "crypto")]
pub mod chain;
pub mod scope;

#[cfg(feature = "crypto")]
pub use chain::{verify_chain, Authority, ChainError, Mandate, PublicKey, MAX_CHAIN_DEPTH};
pub use scope::{Constraint, Scope, Widening};
