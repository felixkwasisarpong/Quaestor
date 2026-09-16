"""Check the committed playground page matches the committed template.

`playground/index.html` is generated, and it is also committed, because it is
the artifact people open and the file a static host serves. That combination
has exactly one failure mode: somebody edits the template, forgets to run
`scripts/build-playground.sh`, and the page everyone sees is the old one. It
is the same staleness that let `Cargo.lock` sit three crates behind the
manifests for two days without anything going red.

This compares the page with the base64 payload stripped back out against the
template with its placeholder. It deliberately does *not* rebuild the module
and diff the bytes: WebAssembly output is not identical across rustc
versions, so that check would fail for reasons nobody could act on.
"""

import pathlib
import re
import sys

TEMPLATE = pathlib.Path("playground/index.template.html")
PAGE = pathlib.Path("playground/index.html")
PLACEHOLDER = "__WASM_BASE64__"
PAYLOAD = re.compile(r'const WASM_B64 = "[A-Za-z0-9+/=]*";')


def main() -> int:
    if not PAGE.is_file():
        print(f"{PAGE} is missing; run scripts/build-playground.sh", file=sys.stderr)
        return 1

    template = TEMPLATE.read_text(encoding="utf-8")
    page = PAGE.read_text(encoding="utf-8")

    if PLACEHOLDER not in template:
        print(f"{TEMPLATE} has no {PLACEHOLDER} placeholder", file=sys.stderr)
        return 1

    if PLACEHOLDER in page:
        print(f"{PAGE} still holds the placeholder; it was never built", file=sys.stderr)
        return 1

    stripped = PAYLOAD.sub(f'const WASM_B64 = "{PLACEHOLDER}";', page, count=1)
    if stripped == page:
        print(f"{PAGE} has no inlined module in it", file=sys.stderr)
        return 1

    if stripped != template:
        print(
            f"{PAGE} does not match {TEMPLATE}.\n"
            "The template changed and the page was not rebuilt. Run:\n"
            "    ./scripts/build-playground.sh",
            file=sys.stderr,
        )
        return 1

    kb = len(page.encode("utf-8")) // 1024
    print(f"playground is current ({kb} KB, module inlined)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
