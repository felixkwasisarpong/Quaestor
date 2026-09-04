//! What the evaluator needs to know about the past.
//!
//! A snapshot, gathered by the caller, passed in by value. Not a handle to a
//! database, not a trait the evaluator can call.
//!
//! That is the whole trick behind determinism. If the evaluator could query
//! spend history itself, its answer would depend on when it asked, what the
//! connection pool did, and whether a replica was behind. Given a snapshot,
//! the same inputs always produce the same verdict, and a decision made
//! today can be replayed in an audit two years from now against the state it
//! actually saw.
//!
//! It also puts the concurrency problem where it belongs. Reading a snapshot
//! and acting on it is a race unless something else serializes it, and that
//! something is the hold, one layer down. This type is honest about being a
//! photograph rather than a live view.

use std::collections::BTreeMap;

use quaestor_core::Money;

/// Spend and activity as of one instant.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpendSnapshot {
    /// Committed spend per rolling window, keyed by the window's length in
    /// milliseconds. A window the policy configures but this map omits is a
    /// denial, never an assumed zero.
    spent_by_window_ms: BTreeMap<i64, Money>,
    /// Payments already made inside the velocity window.
    payments_in_velocity_window: Option<u32>,
    /// Has this principal paid this payee before?
    payee_seen_before: bool,
}

impl SpendSnapshot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record committed spend for one window.
    pub fn with_spend(mut self, window_ms: i64, spent: Money) -> Self {
        self.spent_by_window_ms.insert(window_ms, spent);
        self
    }

    pub fn with_velocity(mut self, payments: u32) -> Self {
        self.payments_in_velocity_window = Some(payments);
        self
    }

    pub fn with_payee_seen_before(mut self, seen: bool) -> Self {
        self.payee_seen_before = seen;
        self
    }

    /// `None` means we have no figure for this window, which the evaluator
    /// treats as a refusal rather than as zero.
    pub fn spent_in(&self, window_ms: i64) -> Option<Money> {
        self.spent_by_window_ms.get(&window_ms).copied()
    }

    pub fn velocity(&self) -> Option<u32> {
        self.payments_in_velocity_window
    }

    pub fn payee_seen_before(&self) -> bool {
        self.payee_seen_before
    }
}
