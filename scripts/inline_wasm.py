"""Inline the compiled module into the playground page.

Kept as a file rather than a heredoc inside `build-playground.sh` so that the
base64 never has to survive a shell quoting round trip. Half a megabyte of it
does not fit in an argument list, and a version that appeared to work would
fail on somebody else's machine at a size nobody would think to test.
"""

import base64
import os
import pathlib
import sys

PLACEHOLDER = "__WASM_BASE64__"
TEMPLATE = pathlib.Path("playground/index.template.html")
OUTPUT = pathlib.Path("playground/index.html")


def main() -> int:
    wasm_path = os.environ.get("WASM_PATH")
    if not wasm_path:
        print("WASM_PATH is not set", file=sys.stderr)
        return 2

    wasm = pathlib.Path(wasm_path)
    if not wasm.is_file():
        print(f"{wasm} is not a file; build it first", file=sys.stderr)
        return 2

    template = TEMPLATE.read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        print(f"{TEMPLATE} has no {PLACEHOLDER} placeholder", file=sys.stderr)
        return 2

    encoded = base64.b64encode(wasm.read_bytes()).decode("ascii")
    OUTPUT.write_text(template.replace(PLACEHOLDER, encoded), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
