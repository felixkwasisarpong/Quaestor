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

pub mod ap2;
pub mod mandate;

/// EIP-712 digests, x402 verification and the errors they raise.
///
/// Behind the `crypto` feature, which is on by default. Without it this
/// crate is the attenuation algebra and the AP2 scope mapping, and it
/// compiles anywhere — including `wasm32-unknown-unknown`, where the
/// elliptic-curve crates do not.
#[cfg(feature = "crypto")]
pub mod eip712;
#[cfg(feature = "crypto")]
pub mod error;
#[cfg(feature = "crypto")]
pub mod x402;

#[cfg(feature = "crypto")]
pub use error::VerifyError;
