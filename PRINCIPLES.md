# How Quaestor is built

Quaestor decides whether money moves. That single fact sets every rule below.
These are not style preferences — they are the constraints that make a
decision reproducible, and a reproducible decision is the entire product.

Read this before your first pull request. It is short on purpose.

---

## 1. Money is an integer, or it is a bug

There is no constructor that turns a float into a `Money`. Not a discouraged
one, not one behind a feature flag — there is no such function, and
`clippy::float_arithmetic` is denied across the workspace so one cannot be
added quietly.

A currency's exponent is part of its identity. `USD` at two decimal places
and `USD` at six are different currencies to this codebase, and mixing them
returns an error rather than a number that is wrong by a factor of ten
thousand.

Arithmetic that can overflow returns `Result`. `checked_add`, never `+`.
`arithmetic_side_effects` is denied, so the compiler enforces this rather
than a reviewer noticing.

## 2. Policy evaluation is a pure function

Given the same intent, the same rules and the same clock reading, the
evaluator returns the same verdict — today, and when someone replays it in
an audit two years from now.

That means, inside the evaluator: no network calls. No reading the system
clock — the current time is an argument, always. No file access. No
randomness. No LLM. No global state. It must also **terminate**, which is
the reason we do not embed a general-purpose policy language.

If you need one of those things, you are writing the wrong layer.

## 3. Nothing above L0 knows what a blockchain is

Wire adapters turn x402, AP2, ACP, MPP, UCP and card rails into one
canonical `PaymentIntent`. Everything above operates on that type alone.

When a new protocol appears — and one will — the work is a new adapter, not
a change to the core. If you find yourself adding a protocol-specific field
to `PaymentIntent`, the design is failing. Generalise it, or keep it in the
adapter.

## 4. Refusals are as auditable as approvals

Every verdict carries a signed receipt, including `Deny`. Anyone holding the
public key can verify what was decided and why, offline, without calling our
service.

A managed provider structurally cannot offer this. It is the reason this
project exists, so it is not a feature to be traded away for convenience.

## 5. Three verdicts, never two

`Allow`, `Deny`, `Escalate`. Binary allow/deny is what every general-purpose
policy engine offers and it is exactly why none of them works for money —
the interesting case is "within your authority but outside your habits", and
the only correct answer to that is to ask a person.

An unanswered escalation resolves to `Deny`. Never to `Allow`. Not on
timeout, not on error, not under load.

## 6. Fail closed, always

Every error path denies. A crashed process, an unreachable database, a
malformed mandate, an expired hold, a bug in a rule — the answer is no.

If you write a `match` on an error and any arm lets a payment through, that
is the most serious class of defect in this repository.

## 7. Panics are decisions

`unwrap`, `expect`, `panic!`, and raw indexing are denied in library code.
A crash in a payment authorizer is a denial of service on someone's money.

Where a lint is switched off, it is switched off at the smallest possible
scope, with a comment explaining why it is safe there, and a test proving
it. There is currently exactly one such exemption in the codebase —
`Currency::lit` — and it is `const`, so a violation would be a build failure
rather than a runtime one. Hold new exemptions to that standard.

## 8. Every test states a belief

A test name is a sentence about what must be true:
`escalation_does_not_permit_payment`, not `test_verdict_3`. When it fails,
the name should tell you what broke without opening the file.

Prefer tests that would catch a real, nameable mistake. We are not chasing a
coverage number.

## 9. Write down the bugs

When a test or the crash-injection harness finds something real, record it —
what broke, why it was missed, what now prevents it. That log is not
paperwork; it is the most credible thing this project will publish. A
correctness claim nobody can check is marketing.

Disclose the embarrassing ones. Especially those.

## 10. Boring where it does not matter

The interesting thinking belongs in the money path. Everywhere else: the
obvious approach, the standard library, the fewest dependencies that will do
the job. Every dependency in an authorization boundary is someone else's
supply chain attached to your users' money.

---

## Conventions

- **Format and lint:** `cargo fmt --all` and `cargo clippy --workspace
  --all-targets -- -D warnings` both pass before a commit. CI enforces both.
- **Commits:** imperative subject under 72 characters, explaining *why* where
  the diff already shows *what*.
- **Public items are documented,** and the doc says what the caller needs to
  decide, not what the code plainly does.
- **Errors are typed.** No stringly-typed failures crossing a module
  boundary; a caller must be able to `match` on what went wrong.
