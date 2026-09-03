//! Canonical types for agent payment authorization.
//!
//! Everything in Quaestor above the wire adapters operates on the types in
//! this crate and nothing else. `quaestor-core` has no idea what a
//! blockchain is, cannot open a socket, and does not know what time it is.
//! That is not minimalism for its own sake — it is what makes a decision
//! reproducible, and a reproducible decision is the product.
//!
//! ```
//! use quaestor_core::{Currency, Money};
//!
//! let budget = Money::new(5_000, Currency::USD);   // $50.00
//! let attempt = Money::new(19_999, Currency::USD); // $199.99
//! assert!(attempt.try_gt(&budget).expect("same currency"));
//!
//! // Crossing currencies is an error, not a wrong number.
//! let euros = Money::new(1, Currency::EUR);
//! assert!(budget.checked_add(&euros).is_err());
//! ```

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

pub mod ids;
pub mod intent;
pub mod money;
pub mod verdict;

pub use ids::{AgentId, IdError, IdempotencyKey, IntentId, PayeeId, PrincipalId};
pub use intent::{CallContext, Payee, PaymentIntent, Rail, Timestamp};
pub use money::{Currency, CurrencyError, Money, MoneyError, ParseMoneyError};
pub use verdict::{Approver, DenyReason, EscalationReason, Hold, Verdict};
