#!/usr/bin/env bash
# Exactly what CI runs, in the same order, with the same flags.
#
# The point is that there is no gap between "it passes locally" and "it
# passes on the runner". Every time those diverge, someone pushes a red
# build and finds out ten minutes later.
set -euo pipefail

export RUSTFLAGS="-D warnings"

# Printed, not assumed. The flags below matched CI for three weeks while the
# *toolchain* did not, and a new clippy lint in a newer stable turned CI red
# while this script stayed green. The version is now pinned in
# rust-toolchain.toml; this line is so a mismatch is visible rather than
# inferred from a failure ten minutes later.
echo "==> toolchain"
cargo --version
cargo clippy --version
export RUSTDOCFLAGS="-D warnings"

echo "==> fmt"
cargo fmt --all --check

echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> test"
cargo test --workspace

echo "==> doc"
cargo doc --workspace --no-deps

echo
echo "all green"
