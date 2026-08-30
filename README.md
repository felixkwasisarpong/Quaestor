# Quaestor

**The spend firewall for AI agents.** Every payment an agent attempts passes
through Quaestor, which verifies the authorization behind it, enforces the
budget, and signs a receipt for the decision — before a cent moves.

> Status: **pre-alpha, day 1.** The core types are here and tested. The
> verifier, policy engine and proxy are not built yet. Watch the repo if you
> want to know when it does something.

---

## The problem

Five protocols now define how an autonomous agent sends money — [x402],
[UCP], [AP2], [ACP] and [MPP]. Every one of them answers *how an agent
pays*. None answers *how you stop it paying the wrong thing*.

Generic policy engines don't fill the gap: they have no money type, no
rolling spend window, no merchant category, no authorization-capture-refund
lifecycle, and only two verdicts when the case that matters needs three.
Every working implementation of this layer today is closed and sold as
managed cloud.

Quaestor is the open one, and it runs on your own infrastructure.

## How it works

```
agent ──▶ L0 wire adapters      x402 · AP2 · … ──▶ canonical PaymentIntent
          L1 mandate verify     signature, delegation chain, scope attenuation
          L2 policy             deterministic. budgets, caps, velocity
          L3 receipt            signed, hash-chained, verifiable offline
          L4 ledger             holds, capture, refund
          L5 reconcile          authorization vs. what actually settled
                    │
                    ▼
              allow · deny · escalate
```

Only L0 knows what a blockchain is. Everything above it is rail-agnostic, so
a sixth protocol costs an adapter rather than a rewrite.

Three verdicts, not two. `Escalate` is the one that matters: within your
authority, outside your habits, ask a human. An unanswered escalation
resolves to `Deny` — never to `Allow`.

## What's here today

| Crate | Status |
|---|---|
| `quaestor-core` | ✅ `Money`, `PaymentIntent`, `Verdict`, typed ids |
| `quaestor-verify` | ✅ x402 v2 `exact` on EVM — EIP-712/EIP-3009, binding checks, replay guard |
| `quaestor-policy` | ⬜ |
| `quaestor-receipt` | ⬜ |
| `quaestor-proxy` | ⬜ |

```bash
./scripts/check.sh   # exactly what CI runs: fmt, clippy, test, doc
```

## Design notes

Two decisions worth knowing before you read the code.

**Money is an integer and its currency carries an exponent.** `USD` at two
decimals and `USD` at six are *different currencies* here, and adding them
returns an error. That prevents a real bug: treating 1,000,000 six-decimal
USDC units as 1,000,000 cents, and authorizing ten thousand dollars.

**Amounts serialize as strings.** A JSON number is an IEEE-754 double in most
parsers, JavaScript's included, so anything above 2^53 minor units silently
loses precision in transit — about nine billion dollars at USDC's six
decimals. A decimal string costs nothing and removes the failure mode.

**A signature is not an authorization.** It proves a key holder signed one
digest — not that the payment goes where the merchant asked. Change the `to`
address on a genuine x402 authorization and the signature over *that* is
still valid. The binding checks are what make it mean something, and they run
before signature recovery. See [`BUGS.md`](BUGS.md) #003.

[`PRINCIPLES.md`](PRINCIPLES.md) covers the rest, including why the policy
evaluator may not read the clock.

## Why not OPA or Cedar?

They are good policy engines for the problem they solve, which is not this
one. They have no money type, no currency-aware comparison, no rolling
window, no merchant category, no notion of a hold, and two verdicts where
this needs three. Encoding payment semantics into Rego means reimplementing
all of that in a language that does not guarantee termination — more work
than writing an evaluator that is correct by construction.

## License

Apache-2.0. No CLA, no contributor licence gymnastics, no relicensing
escape hatch.

[x402]: https://github.com/x402-foundation/x402
[UCP]: https://github.com/Universal-Commerce-Protocol/ucp
[AP2]: https://github.com/google-agentic-commerce/AP2
[ACP]: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol
[MPP]: https://github.com/tempoxyz/mpp-specs
