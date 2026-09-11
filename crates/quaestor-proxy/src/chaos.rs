//! Crash points, or nothing at all.
//!
//! With the `chaos` feature off — which is every build that is not the crash
//! harness — [`at`] is an empty inline function taking a `&'static str`.
//! There is no environment variable read, no comparison, and after inlining
//! no instruction. The shipped binary has no code path that can be talked
//! into aborting.
//!
//! That matters more than it sounds. A fault injector compiled into a
//! release build is a denial of service that ships with the product and
//! waits for somebody to guess the variable name. The feature flag is the
//! difference between a testing tool and a remotely triggerable crash.
//!
//! See `quaestor-chaos` for the mechanism and for what each point claims.

#[cfg(feature = "chaos")]
#[inline]
pub(crate) fn at(name: &'static str) {
    quaestor_chaos::at(name);
}

#[cfg(not(feature = "chaos"))]
#[inline(always)]
pub(crate) fn at(_name: &'static str) {}
