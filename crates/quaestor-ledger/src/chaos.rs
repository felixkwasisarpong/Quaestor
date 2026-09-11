//! Crash points, or nothing at all. See `quaestor-proxy`'s module of the
//! same name for why this is behind a feature rather than a runtime check.

#[cfg(feature = "chaos")]
#[inline]
pub(crate) fn at(name: &'static str) {
    quaestor_chaos::at(name);
}

#[cfg(not(feature = "chaos"))]
#[inline(always)]
pub(crate) fn at(_name: &'static str) {}
