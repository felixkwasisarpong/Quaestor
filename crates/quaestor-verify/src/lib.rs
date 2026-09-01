//! Payment-authorization verification.
//!
//! Establishes that a payment attempt is cryptographically authorized, and
//! authorized for *this* payment — the right payee, the right amount, inside
//! its validity window, not seen before.
//!
//! It does not decide whether the payment is a good idea. That is policy,
//! and it lives one layer up.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

pub mod eip712;
pub mod error;
pub mod mandate;
pub mod x402;

pub use error::VerifyError;
