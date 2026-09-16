#!/usr/bin/env bash
# Build the playground into one self-contained HTML file.
#
# No wasm-pack, no wasm-bindgen, no npm. The module exports four integer
# functions and the page marshals bytes through them, so the whole toolchain
# is cargo plus base64.
#
# The .wasm is inlined rather than fetched, so the result has no origin: it
# works from file://, from a static host, and from a USB stick. It also makes
# "nothing you type leaves your machine" a fact about the file rather than a
# promise printed on it.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=wasm32-unknown-unknown
PROFILE=wasm-release
OUT="target/$TARGET/$PROFILE/quaestor_playground.wasm"

echo "==> target"
rustup target add "$TARGET" >/dev/null 2>&1 || true

echo "==> build"
cargo build -p quaestor-playground --target "$TARGET" --profile "$PROFILE"

echo "==> inline"
# The payload goes through the environment and the filesystem, never through
# an argument list: half a megabyte of base64 is well past what argv carries.
WASM_PATH="$OUT" python3 scripts/inline_wasm.py

printf "==> playground/index.html  %s KB (wasm %s KB)\n" \
  "$(( $(wc -c < playground/index.html) / 1024 ))" \
  "$(( $(wc -c < "$OUT") / 1024 ))"
