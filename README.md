# Quaestor

**The spend firewall for AI agents.** Every payment an agent attempts passes
through Quaestor, which verifies the authorization behind it, enforces the
budget, and signs a receipt for the decision — before a cent moves.

[![ci](https://github.com/felixkwasisarpong/Quaestor/actions/workflows/ci.yml/badge.svg)](https://github.com/felixkwasisarpong/Quaestor/actions/workflows/ci.yml)

**[Try it in your browser](https://felixkwasisarpong.github.io/Quaestor)** ·
[Sixty seconds from a clone](#sixty-seconds) ·
[Everything that has broken so far](BUGS.md)

> Status: **pre-alpha.** Everything marked built below is built and tested,
> and the proxy runs. Nobody has put it in front of real money yet, including
> me. [`BUGS.md`](BUGS.md) is the honest record of what has gone wrong.

---

## The problem

Five protocols now define how an autonomous agent sends money — [x402],
[UCP], [AP2], [ACP] and [MPP]. Every one of them answers *how an agent
pays*. None answers *how you stop it paying the wrong thing*.

(Quaestor verifies x402 today and maps AP2 Intent Mandates onto its own
scopes. The other three are next, and each is an adapter at L0 rather than a
change to anything above it.)

Generic policy engines don't fill the gap: they have no money type, no
rolling spend window, no hold-and-capture lifecycle, and nothing that stops
two concurrent requests from both reading the same remaining budget. See
[why not OPA or Cedar](#why-not-opa-or-cedar).
Every working implementation of this layer today is closed and sold as
managed cloud.

Quaestor is the open one, and it runs on your own infrastructure.

## How it works

```
agent ──▶ L0 wire adapters      x402 today; AP2 scopes ──▶ canonical PaymentIntent
          L1 mandate verify     signature, delegation chain, scope attenuation
          L2 policy             deterministic. budgets, caps, velocity
          L3 receipt            signed, hash-chained, verifiable offline
          L4 ledger             holds, capture, release
          L5 reconcile          not built. authorization vs. what settled
                    │
                    ▼
              allow · deny · escalate
```

L5 is on the diagram because it belongs there, and marked because it does
not exist yet. There is no refund path either: a captured spend is final,
and correcting one is a double-entry problem this ledger does not solve.
See the open questions at the bottom of [`BUGS.md`](BUGS.md).

Only L0 knows what a blockchain is. Everything above it is rail-agnostic, so
a sixth protocol costs an adapter rather than a rewrite.

Three verdicts, not two. `Escalate` is the one that matters: within your
authority, outside your habits, ask a human. An unanswered escalation
resolves to `Deny` — never to `Allow`.

## What's here today

| Crate | Status |
|---|---|
| `quaestor-core` | ✅ `Money`, `PaymentIntent`, `Verdict`, typed ids |
| `quaestor-verify` | ✅ x402 v2 `exact` on EVM; delegation chains with monotonic attenuation; AP2 scope mapping |
| `quaestor-policy` | ✅ rule schema and deterministic evaluator; three verdicts |
| `quaestor-ledger` | ✅ budget holds, concurrency-safe under real contention |
| `quaestor-receipt` | ✅ signed, hash-chained receipts + offline verifier CLI |
| `quaestor-proxy` | ✅ inline HTTP gateway; refused payments are not forwarded |
| `quaestor-chaos` | ✅ crash injection at 8 points, with invariants checked after restart |
| `quaestor-playground` | ✅ the evaluator in a browser, one HTML file, no server |

## Sixty seconds

Nothing to install but a Rust toolchain, and no database needed for this.

```bash
git clone https://github.com/felixkwasisarpong/Quaestor && cd Quaestor

# 1. Watch a decision get signed, then watch a tampered log get caught.
cargo run -p quaestor-receipt --example emit > receipts.jsonl
#    ^ prints the public key on stderr. Copy it.

cargo run -p quaestor-receipt --bin quaestor-verify-receipts -- \
  --key <that key> receipts.jsonl

sed '2d' receipts.jsonl > doctored.jsonl     # delete the denial
cargo run -p quaestor-receipt --bin quaestor-verify-receipts -- \
  --key <that key> doctored.jsonl            # and watch it refuse
```

```
OK  3 receipts verified
    1 allowed, 1 denied, 1 escalated
    head 84756437fd995a3530ac8d2bede64f119f146ddca14a94ce0f8c87b34e69db52

FAILED  receipt 2: prev_hash does not match the receipt before it
This log is not trustworthy. Do not rely on it.
```

Every receipt in the doctored file still passes its own signature check. The
signatures were never the thing that caught it.

## Running the tests

```bash
./scripts/check.sh   # exactly what CI runs: fmt, clippy, test, doc

# The ledger's concurrency tests need a real Postgres. Without this they
# skip rather than fail, because a green suite that proved nothing is worse
# than a red one.
QUAESTOR_TEST_PG="host=/tmp/pgsock port=5433 user=quaestor dbname=quaestor_test" \
  cargo test -p quaestor-ledger

# Crash injection: kills the real process at 8 points inside the payment
# path, restarts it, and checks what survived.
QUAESTOR_TEST_PG="..." cargo test -p quaestor-proxy --features chaos \
  --test crash -- --test-threads=1 --nocapture
```

## Putting it in front of an agent

Everything above is a library, and a library only runs if something calls it.
`quaestor-proxy` is the part that is not optional: point the agent's HTTP
client at it and a refused payment is not forwarded.

```bash
cargo install --path crates/quaestor-proxy    # or use `cargo run -p` below

export QUAESTOR_RECEIPT_KEY=$(openssl rand -hex 32)
export QUAESTOR_TOKEN_SHOPPER=$(openssl rand -hex 24)
quaestor-proxy --config examples/quaestor.toml

http_proxy=http://127.0.0.1:8402 your-agent
```

The example config sets `allow_volatile_ledger`, which keeps budgets in
memory so you can try it without a database. It says so on startup, loudly,
because a budget that a restart forgets is not a budget.

```
agent ──▶ GET /report ─────────────────────▶ origin
      ◀── 402 + accepts[] ◀───────────────── origin      (remembered)
agent ──▶ GET /report + X-PAYMENT ──▶ quaestor
                                        verify · evaluate · reserve · sign
                                        ├─ allow  ──▶ capture, then forward
                                        └─ refuse ──▶ 403 + signed receipt
                                                      the origin sees nothing
```

The payment is checked against the `402` **the origin issued**, never the
copy of it the agent enclosed. Skipping that is how a correct verifier ends
up certifying that the agent agrees with itself; see [`BUGS.md`](BUGS.md)
#003 for the underlying attack.

## Try it without installing anything

**[felixkwasisarpong.github.io/Quaestor](https://felixkwasisarpong.github.io/Quaestor)**
is one file. Open it and the real policy evaluator runs in your browser:
paste a policy, describe a payment, watch allow, deny or escalate with every
reason it found rather than the first.

(Opening [`playground/index.html`](playground/index.html) on github.com shows
you the source, which is mostly a base64 blob. Use the link above, or
download the file and open it locally. It needs no server either way.)

The second tab is the more interesting one. Give a sub-agent a mandate,
remove the payee restriction from it, and watch the delegation refused as
*widening* — the mistake that lets an agent quietly gain the whole world by
appearing to ask for less.

```bash
./scripts/build-playground.sh   # cargo + base64. no wasm-pack, no npm.
```

Only this layer runs there, and that is not a compromise. The evaluator reads
no clock, opens no socket and draws no randomness, because a decision has to
be replayable a year later; the side effect is that it is the one layer a
browser can run unchanged. Signature checking, budgets that survive a restart
and the receipt log need Postgres, sockets and a filesystem, and were never
going to be in a web page.

The module is inlined as base64, so the page has no origin and makes no
requests. Nothing typed into it leaves the machine, and that is a property of
the file rather than a promise printed on it.

## Design notes

The decisions worth knowing before you read the code.

**Money is an integer and its currency carries an exponent.** `USD` at two
decimals and `USD` at six are *different currencies* here, and adding them
returns an error. That prevents a real bug: treating 1,000,000 six-decimal
USDC units as 1,000,000 cents, and authorizing ten thousand dollars.

**Amounts serialize as strings.** A JSON number is an IEEE-754 double in most
parsers, JavaScript's included, so anything above 2^53 minor units silently
loses precision in transit — about nine billion dollars at USDC's six
decimals. A decimal string costs nothing and removes the failure mode.

**Delegated authority can only ever shrink.** A sub-agent holding a genuine
$100 delegation cannot issue itself one for $500 — and, less obviously,
cannot issue itself one that simply *drops* the payee restriction. A naive
subset check on the listed payees sees an empty diff and lets that through
with unlimited reach. `Constraint::Any` is strictly wider than any
`Constraint::Only`, and the rules are asymmetric on purpose.

**Every decision gets a signed receipt, including the refusals.** A denial
nobody can account for is an argument, and arguments about money are settled
with evidence. Receipts are hash-chained, so deleting the inconvenient one
breaks the link for every receipt after it. `quaestor-verify-receipts` checks
a log with nothing but a public key and no network:

```
$ quaestor-verify-receipts --key <hex> receipts.jsonl
OK  3 receipts verified
    1 allowed, 1 denied, 1 escalated
    head 84756437fd995a3530ac8d2bede64f119f146ddca14a94ce0f8c87b34e69db52

$ sed '2d' receipts.jsonl | quaestor-verify-receipts --key <hex>
FAILED  receipt 2: prev_hash does not match the receipt before it
```

This is the thing a managed provider structurally cannot offer. Their audit
trail is a page in their console, and its correctness rests on them.

**The point of no return is the write, not the response.** A card
authorization is a promise held by the issuer: you ship, then capture, and an
uncaptured hold lapses. An `X-PAYMENT` header is a bearer instrument — the
resource server can settle it whenever it likes, including after returning a
`500`. So capturing on a `200` means a server that pockets the authorization
and errors gets paid *and* hands the budget back. Quaestor connects first,
captures, and only then writes; anything that fails before the write releases
the hold, and anything after it does not.

**Two agents cannot both win the last dollar.** A budget is an aggregate over
a time range, so the rows two racing transactions conflict over are the ones
they are each about to write, which is a phantom `READ COMMITTED` does not
prevent. Reservation takes a per-principal row lock and does the read, the
decision and the write inside it. Verified by deleting the lock and watching
a 30-unit budget overspend by 4 to 8 units per run. See [`BUGS.md`](BUGS.md)
#012.

**A signature is not an authorization.** It proves a key holder signed one
digest — not that the payment goes where the merchant asked. Change the `to`
address on a genuine x402 authorization and the signature over *that* is
still valid. The binding checks are what make it mean something, and they run
before signature recovery. See [`BUGS.md`](BUGS.md) #003.

**Crash safety is tested by crashing.** Eight named points inside the real
payment path, each one a written-down claim about what must survive. The
proxy runs as a real process against a real Postgres, is killed with `abort`
at the armed point, restarted, and the surviving state is checked by a
module that reads the holds table with its own SQL rather than the ledger's:

```
=== capture.after ===
  after:   the spend is committed, before a byte of the payment is written
  left:    1 hold(s), 1 receipt(s), origin paid 0 time(s)
           hold x402:0101… is captured

=== write.after ===
  after:   the payment is on the wire, before the response comes back
  left:    1 hold(s), 1 receipt(s), origin paid 1 time(s)
           hold x402:0101… is captured
```

The harness has been watched failing: delete the pre-write capture and
`write.after` reports *the origin was paid, but its hold is `held`*. It found
three bugs before it ran a single crash, including a proxy that could not
talk to Postgres at all and a migration that let the process start exactly
once. See [`BUGS.md`](BUGS.md) #017 to #019.

[`PRINCIPLES.md`](PRINCIPLES.md) covers the rest, including why the policy
evaluator may not read the clock.

## Why not OPA or Cedar?

They are good policy engines, and the reason not to use them here is not a
missing language feature. It is that the hard part of a budget is not the
rule.

Both evaluate a request against data handed to them. Cedar reads only the
request and the entities you pass in; OPA evaluates against the data it has
loaded. That is the right design for authorization, and it is the exact
shape of the bug a budget has to avoid. Two agents read the same snapshot,
both are inside the cap, both are allowed, and together they are over it.
No evaluator that answers from a photograph can fix that. It takes an atomic
reserve against durable state, which is what `quaestor-ledger` is, and why
it is tested by deleting its lock and watching a budget overspend
([`BUGS.md`](BUGS.md) #012).

The rest is real but smaller. Cedar returns exactly `Allow` or `Deny`, and
the case that matters here needs a third answer meaning *ask a human, and
refuse if nobody does*. OPA can return any document, so a third verdict is
expressible there, but money, currency exponents and rolling windows are all
things to build on top rather than types the evaluator understands.

## License

Apache-2.0. No CLA, no contributor licence gymnastics, no relicensing
escape hatch.

[x402]: https://github.com/x402-foundation/x402
[UCP]: https://github.com/Universal-Commerce-Protocol/ucp
[AP2]: https://github.com/google-agentic-commerce/AP2
[ACP]: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol
[MPP]: https://github.com/tempoxyz/mpp-specs
