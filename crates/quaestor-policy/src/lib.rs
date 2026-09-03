//! Deterministic spend policy.
//!
//! Given the same intent, the same rules, the same state snapshot and the
//! same clock reading, this crate returns the same verdict. Today, and when
//! someone replays it in an audit two years from now.
//!
//! That is not a nice property, it is the product. It is why there is no
//! network call in here, no clock read, no randomness, no global state and
//! no model. The current time arrives as an argument. Spend history arrives
//! as a snapshot the caller gathered. Everything this code needs to decide
//! is in front of it.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

pub mod rules;

pub use rules::{parse_duration_ms, Budget, Policy, PolicyError, Velocity, POLICY_VERSION};
