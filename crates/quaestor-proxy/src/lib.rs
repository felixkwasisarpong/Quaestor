//! The inline gateway.
//!
//! Everything below this crate is a library: types, a verifier, an
//! evaluator, a ledger, a receipt log. Correct, tested, and entirely
//! optional — a library only runs if somebody calls it, and the agent whose
//! spending you are worried about is not going to call it.
//!
//! This crate is the part that is not optional. The agent's HTTP client
//! points at Quaestor instead of at the internet. A payment that Quaestor
//! refuses is not logged and forwarded; it is not forwarded. That is the
//! whole difference.
//!
//! ```text
//!   agent ──▶ quaestor-proxy ──▶ resource server
//!                   │
//!                   ├─ 402 seen        remember what the origin demanded
//!                   ├─ X-PAYMENT seen  verify · evaluate · reserve · sign
//!                   └─ verdict         forward, or answer the agent itself
//! ```
//!
//! # Three ways a proxy throws away a correct verifier
//!
//! Every one of these compiles, passes a happy-path test, and is worthless.
//!
//! **Checking the payment against the requirements inside the payment.**
//! [`quaestor_verify::x402::verify_exact_evm`] takes the payload and the
//! requirements as two arguments precisely so they can come from two
//! sources. An x402 payload carries an `accepted` field describing what the
//! sender *says* it is paying for. Pass that in as the requirements and
//! every binding check compares a value with itself. The verifier still
//! reports success; it has verified that the agent agrees with the agent.
//! The requirements have to come from the `402` the origin actually issued,
//! which means the proxy has to remember it. See [`challenge`].
//!
//! **Believing a header about who is asking.** The budget being spent
//! belongs to a principal. If the principal's name arrives in a header, any
//! caller can spend any principal's budget by typing a different name. See
//! [`identity`].
//!
//! **Capturing the hold when the response comes back.** The card model is
//! reserve, ship, capture on success. It does not transfer, because an
//! `X-PAYMENT` header is a bearer authorization: once it leaves this
//! process the resource server can settle it whenever it likes, including
//! after returning a `500`. Waiting for a `200` to capture means a server
//! that pockets the authorization and errors gets the goods *and* hands the
//! budget back. The point of no return is the write. See [`gateway`].
//!
//! # What the gateway is, structurally
//!
//! [`gateway::Gateway`] has no sockets in it. It takes the parts of a
//! request that matter and returns a decision. The HTTP layer in [`http`]
//! moves bytes and is not allowed to make judgements; every test of the
//! decision logic runs without a listener, and the end-to-end tests exist
//! to check the wiring, not the rules.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

pub mod challenge;
pub mod gateway;
pub mod holds;
pub mod http;
pub mod identity;

pub use challenge::{Challenge, ChallengeKey, ChallengeStore, MAX_ALTERNATIVES};
pub use gateway::{Config, Gateway, Outcome, Reach, Refusal, RefusalKind};
pub use holds::{Holds, HoldsError, InMemoryHolds, PostgresHolds, ReserveRequest};
pub use identity::{Caller, Identities};

/// The header an agent presents its payment in. x402, verbatim.
pub const PAYMENT_HEADER: &str = "x-payment";

/// The header the proxy answers with, carrying the receipt for the decision
/// it just made — including, and especially, a refusal.
pub const RECEIPT_HEADER: &str = "x-quaestor-receipt";

/// An optional delegation chain, base64 JSON. See [`identity`].
pub const MANDATE_HEADER: &str = "x-quaestor-mandate";
