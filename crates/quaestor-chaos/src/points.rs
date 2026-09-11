//! Where the process can be made to die, and what should survive each one.
//!
//! Each entry is a claim. The harness arms the point, drives one payment
//! into the window, kills the process there, restarts it, and checks the
//! invariants in [`crate::invariants`]. The `expected` field is written
//! before the run, so a surprise is visible as a surprise rather than
//! rationalised afterwards.
//!
//! The points are listed in the order the code reaches them, which is also
//! the order the danger increases: everything above `capture.after` is a
//! window in which no money can have moved.

/// One place the process can be killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    /// The string passed in [`crate::ARM_VAR`].
    pub name: &'static str,
    /// What the code has just finished doing.
    pub after: &'static str,
    /// What must be true once the process comes back. Written first.
    pub expected: &'static str,
    /// Could the origin have received the payment authorization?
    pub money_may_have_moved: bool,
}

pub const POINTS: &[Point] = &[
    Point {
        name: "reserve.before",
        after: "the payment verified and policy allowed it",
        expected: "Nothing at all. No hold, no receipt, no request upstream. \
                   A decision that was never written down did not happen.",
        money_may_have_moved: false,
    },
    Point {
        name: "ledger.mid_transaction",
        after: "the account row is locked and the windows check out, \
                before the hold row is inserted",
        expected: "No hold. The transaction was open and uncommitted, so \
                   Postgres rolls it back when the connection dies, and the \
                   lock is released with it. If a partial hold survives this, \
                   the reservation is not one transaction and the ledger's \
                   whole correctness argument is wrong.",
        money_may_have_moved: false,
    },
    Point {
        name: "reserve.after",
        after: "the hold is committed, before any receipt exists",
        expected: "A hold in state `held` and no receipt for it. That is \
                   survivable in one direction only: `held` is not spent, it \
                   expires, and the budget comes back. A hold in this state \
                   must never be `captured`.",
        money_may_have_moved: false,
    },
    Point {
        name: "receipt.after_sign",
        after: "the receipt is signed in memory, before it is written down",
        expected: "The hold, and no receipt. The signed receipt is lost, \
                   which is correct: nobody received it and nothing was \
                   decided on the strength of it. The restarted signer \
                   resumes from the last *persisted* receipt, so the lost \
                   sequence number is reused. That is only safe because the \
                   lost one never escaped, and this point exists to check \
                   that it did not.",
        money_may_have_moved: false,
    },
    Point {
        name: "receipt.after_persist",
        after: "the receipt is on disk and fsynced, before the agent sees it",
        expected: "A verifying chain ending in a receipt for a hold that is \
                   still `held`. The agent never learned the verdict, so it \
                   will retry; the retry must not produce a second hold or a \
                   second receipt for the same authorization.",
        money_may_have_moved: false,
    },
    Point {
        name: "connect.after",
        after: "the upstream connection is open, before the spend is captured",
        expected: "Hold still `held`, nothing written to the socket. The \
                   connection dies with the process and the origin sees an \
                   aborted request with no payment in it.",
        money_may_have_moved: false,
    },
    Point {
        name: "capture.after",
        after: "the spend is committed, before a byte of the payment is written",
        expected: "A `captured` hold for a payment the origin never received. \
                   Budget consumed for nothing. This is the deliberate cost \
                   of capturing before the write, and the point of writing \
                   it down is that it is the *recoverable* error: visible in \
                   the ledger, arguable with a receipt, and no money moved. \
                   The opposite ordering loses money silently.",
        money_may_have_moved: false,
    },
    Point {
        name: "write.after",
        after: "the payment is on the wire, before the response comes back",
        expected: "A `captured` hold, and an origin that has the \
                   authorization and may settle it whenever it likes. This \
                   is the one window where the ledger and reality can \
                   genuinely disagree, and the ledger is deliberately wrong \
                   in the direction of having spent the money.",
        money_may_have_moved: true,
    },
];

/// Look a point up by the name used to arm it.
pub fn find(name: &str) -> Option<&'static Point> {
    POINTS.iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_last_window_can_have_moved_money() {
        // Everything before the write is recoverable. If that stops being
        // true, the ordering in `quaestor-proxy` has changed and this file
        // is now lying about it.
        let risky: Vec<&str> = POINTS
            .iter()
            .filter(|p| p.money_may_have_moved)
            .map(|p| p.name)
            .collect();
        assert_eq!(risky, vec!["write.after"]);
    }

    #[test]
    fn points_are_findable_by_name() {
        assert!(find("capture.after").is_some());
        assert!(find("nonsense").is_none());
    }
}
