//! AP2 — Agent Payments Protocol.
//!
//! # What this module does and deliberately does not do
//!
//! AP2's *concepts* map cleanly onto [`crate::mandate`]: an Intent Mandate is
//! a narrowing grant of prospective spending authority, which is exactly what
//! a [`crate::mandate::Scope`] describes. That mapping is implemented here and tested.
//!
//! Its *cryptography* cannot be implemented today, and this module says so
//! rather than pretending otherwise. As of the published specification:
//!
//! - there is no JSON schema for `IntentMandate`, only a prose field list;
//! - no signing algorithm is specified for either core mandate — the sole
//!   concrete hint anywhere is an `ES256K` JWS header on a *PaymentMandate*,
//!   which is a different object;
//! - the linkage from a Cart Mandate back to the Intent Mandate that
//!   authorized it is described in prose and not pinned to any field.
//!
//! You cannot write a conformance-tested verifier for a signature whose
//! algorithm, canonical bytes and key discovery are all unspecified. So
//! [`verify_intent_mandate`] returns [`Ap2Error::SignatureSchemeUnspecified`]
//! for anything carrying a signature, and the scope mapping is exposed
//! separately so it is usable the moment the spec settles.
//!
//! Shipping a function called `verify` that returns `Ok` without checking a
//! signature would be worse than shipping nothing. Someone would rely on it.
//!
//! # The unbounded-amount problem
//!
//! AP2 lists an Intent Mandate's constraints as product categories, payment
//! methods and a time-to-live. **There is no specified ceiling on amount.**
//!
//! An authority with categories and an expiry but no cap is not a bounded
//! delegation — it is "spend whatever you like on shoes until Friday". So
//! [`intent_to_scope`] requires the ceiling to be supplied locally and
//! refuses to build a scope without one. Quaestor will not manufacture an
//! upper bound the user never agreed to, and it will not treat the absence
//! of one as permission.

pub mod adapt;
pub mod types;

pub use adapt::{intent_to_scope, verify_intent_mandate, Ap2Error, LocalBounds};
pub use types::{CartMandate, IntentMandate};
