//! Killing the process on purpose, and checking what survived.
//!
//! Every crash-safety claim in this workspace so far is an argument. The
//! proxy captures a hold before it writes the payment because of a written
//! argument about which direction it is safe to be wrong in. The ledger
//! rolls a refusal back because of a written argument about what a refused
//! attempt must leave behind. Arguments are how you get the design right and
//! they are not evidence that the code does what the argument says.
//!
//! So this crate kills the real process, at a named point, in the middle of
//! the real path, against a real database, and then asks what is left.
//!
//! # Why `abort` and not a returned error
//!
//! A returned error unwinds. Destructors run, buffers flush, a transaction
//! gets a chance to roll back cleanly, and `Drop` impls tidy up. None of
//! that happens when a machine loses power or a container is evicted, and a
//! harness that simulates a crash by being *polite* about it tests a failure
//! mode that does not exist.
//!
//! [`at`] calls [`std::process::abort`]. No unwinding, no destructors, no
//! flush. The only thing it does first is write a marker file, for the
//! reason in [`at`]'s documentation.
//!
//! # Why a production build cannot be crashed
//!
//! The crash points live behind a Cargo feature that nothing in the default
//! build enables. `quaestor-proxy` compiles them to nothing, so the shipped
//! binary has no code path that reads `QUAESTOR_CRASH_AT` and no way to be
//! talked into aborting by an environment variable. A fault injector that
//! ships is a denial of service waiting for someone to find the variable
//! name.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

use std::sync::OnceLock;

pub mod invariants;
pub mod points;

pub use invariants::{check, Finding, Invariant, Observed, Violation};
pub use points::POINTS;

/// Environment variable naming the point to die at.
pub const ARM_VAR: &str = "QUAESTOR_CRASH_AT";

/// Environment variable naming where to record that we died there.
pub const MARKER_VAR: &str = "QUAESTOR_CRASH_MARKER";

static ARMED: OnceLock<Option<String>> = OnceLock::new();

/// Die here, if this is the point we were told to die at.
///
/// # The marker file
///
/// Before aborting, this writes the point's name to the path in
/// [`MARKER_VAR`] and fsyncs it.
///
/// That is not decoration. Without it the harness cannot tell "the process
/// died at the point I armed" from "the process died on the way there, for
/// some unrelated reason" — and the second case looks exactly like the first
/// from outside: a dead process and a database to inspect. A harness that
/// confuses them reports a pass for an invariant it never exercised, which
/// is the worst thing a test can do.
///
/// The write happens outside the system under test, so it cannot repair
/// anything the crash was supposed to break.
pub fn at(name: &str) {
    let armed = ARMED.get_or_init(|| std::env::var(ARM_VAR).ok());
    if armed.as_deref() != Some(name) {
        return;
    }
    record(name);
    std::process::abort();
}

fn record(name: &str) {
    use std::io::Write as _;
    let Ok(path) = std::env::var(MARKER_VAR) else {
        return;
    };
    // Best effort, and deliberately not a panic: failing to write the marker
    // must not change *where* the process dies.
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = f.write_all(name.as_bytes());
        let _ = f.sync_all();
    }
}

/// Is any crash point armed in this process?
pub fn is_armed() -> bool {
    ARMED.get_or_init(|| std::env::var(ARM_VAR).ok()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unarmed_point_is_a_no_op() {
        // The important property, stated where someone will read it: with
        // nothing armed, `at` returns, every time, for every name.
        for p in POINTS {
            at(p.name);
        }
    }

    #[test]
    fn every_point_has_a_unique_name_and_an_explanation() {
        // A crash point whose name collides with another silently arms the
        // wrong one, and the harness reports on a window it never entered.
        let mut names: Vec<&str> = POINTS.iter().map(|p| p.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate crash point name");

        for p in POINTS {
            assert!(!p.name.is_empty());
            assert!(
                p.expected.len() > 20,
                "{}: say what should survive, or the harness is asserting nothing",
                p.name
            );
        }
    }
}
