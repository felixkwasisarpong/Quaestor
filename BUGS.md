# Bugs

What broke, why it was missed, and what stops it now.

This file exists because a correctness claim nobody can check is marketing.
The embarrassing entries are the ones worth reading.

---

## 001 — Amounts lost precision on the wire above 2^53

**Day 1. Found by:** a round-trip test that refused to compile.

`serde_json` cannot round-trip a raw `i128` inside an internally-tagged
enum — which is exactly where every `DenyReason` carrying a `Money` lives.
Chasing that surfaced the larger problem underneath it.

A JSON number is an IEEE-754 double in most parsers, JavaScript's included.
Doubles hold integers exactly only up to 2^53. Above that they round, with
no error and no exception. At USDC's six decimals that ceiling arrives at
roughly nine billion dollars — large, but not "never think about it" large
for a system whose whole job is being exactly right about money. The
playground planned for week 4 is itself a JavaScript client, so this would
have shipped straight into the demo.

**Why it was missed:** every test amount was small. The bug is invisible
below the ceiling and silent above it.

**Fix:** `Money.minor` serializes as a decimal string. A test asserts
`i128::MAX` survives a round trip intact.

---

## 002 — `u128` payment amounts do not all fit in `Money`

**Day 2. Found by:** the compiler, refusing `i128::from(u128)`.

x402 amounts are unsigned; `Money` is signed, because refunds exist. The
ranges nearly coincide — but not exactly, and an authorization boundary is
not allowed to say "nearly".

**Why it matters more than it looks:** the tempting fix is a cast. `value as
i128` compiles, and turns an absurd amount into a negative one, which would
then sail past a budget check comparing against a positive limit.

**Fix:** `i128::try_from`, refused as malformed on overflow. The workspace
denies `cast_possible_truncation`, so the tempting version would not have
compiled either.

---

## 003 — A valid signature over the wrong payment

**Day 2. Found by:** writing the adversarial test before the implementation.

Not a bug that shipped — a bug the design would have had if verification had
stopped where it felt finished.

A signature proves that a key holder signed one specific digest. It does not
prove the payment goes where the merchant asked. Take a genuine, correctly
signed x402 authorization, change the `to` address to your own, and the
signature over *that* authorization is still perfectly valid — it is simply
an authorization for a different transfer. A verifier that checks only
`signature_is_valid` accepts it.

The binding checks — authorized recipient equals demanded recipient,
authorized amount equals demanded amount — are what make the signature mean
something. They are also the checks a spec skims over in one line.

**Now covered by:** `redirecting_the_payment_is_refused_even_though_the_signature_is_valid`,
plus the amount, payer-spoofing and field-tampering cases. Binding is
checked *before* signature recovery, because recovery is expensive and there
is no reason to spend it on a payload already known to pay the wrong person.

---

## 004 — Trusting the counterparty's EIP-712 domain

**Day 2. Found by:** reading the x402 spec's `extra` field and asking who
supplies it.

x402 carries the token's EIP-712 `name` and `version` in `extra`, on the
payment requirements — which arrive from the other side. A verifier that
builds its domain separator from those fields lets the sender choose what
the signature has to match, which is not verification.

The `chainId` and `verifyingContract` in that domain are the only things
stopping a signature captured on a testnet from replaying against mainnet,
or a signature for one token from being reused against another.

**Fix:** the domain comes from a local `AssetRegistry`. `extra` is read for
diagnostics and never trusted. An asset missing from the registry is refused
outright rather than guessed at — unknown decimals means a possible
factor-of-a-million error in an authorization decision.

---

## 005 — A failed verification must not burn the nonce

**Day 2. Found by:** thinking about ordering while writing the replay check.

The replay guard is the only stage of verification that mutates state. Put
it early — where it reads naturally, right after parsing — and anyone who
can observe a payer's nonce can grief them: replay a deliberately broken
variant, the nonce is recorded as spent, and the payer's real payment is
then refused as a replay.

**Fix:** the nonce is recorded last, only once every other check has passed.
`a_rejected_payload_does_not_burn_the_nonce` holds the ordering in place.

---

## 006 — Dropping a restriction reads as narrowing

**Day 4. Found by:** writing the attenuation rules down as a table before
implementing them.

Not a bug that shipped. A bug the obvious implementation has.

Delegated authority must only ever shrink. The tempting way to check that is
to compare the listed values — parent allows three payees, child allows two,
two is a subset of three, fine. But "no payee restriction" and "these three
payees" are both representable, and a child that *removes* the restriction
produces an empty diff under that comparison. It reads as narrower and gains
the whole world.

**Fix:** `Constraint::Any` is strictly wider than any `Constraint::Only`,
including one listing everything currently known — "everything known today"
and "whatever exists tomorrow" are different grants. The subset relation is
asymmetric: `Only(_) ⊆ Any` holds, `Any ⊆ Only(_)` does not.

Covered by `dropping_the_payee_restriction_entirely_is_caught`.

---

## 007 — Concatenated fields let an attacker move a boundary

**Day 4. Found by:** deciding what bytes a mandate signature covers.

If signed bytes are field values concatenated, `("ab", "c")` and
`("a", "bc")` produce identical input. An attacker who can influence two
adjacent fields can shift characters between them and keep the signature
valid — moving authority from one field to another without breaking
anything.

**Fix:** every field is length-prefixed, and the encoding opens with a
domain tag (`quaestor.mandate.v1`) so a mandate signature cannot be
presented as a signature over some other structure. Constraint sets use
`BTreeSet`, so iteration order is stable and the same grant signs identically
every time.

Covered by `signing_bytes_cannot_be_confused_by_shifting_a_field_boundary`
and `constraint_sets_serialize_in_a_stable_order`.

---

## 008 — AP2 Intent Mandates have no specified spend ceiling

**Day 6. Found by:** trying to map the spec's constraint list onto a scope
and finding nothing to put in the amount field.

AP2 lists an Intent Mandate's constraints as product categories, authorized
payment methods, and a time-to-live. There is no specified cap on amount.

Categories and an expiry without a ceiling is not a bounded delegation. It
is "spend whatever you like on shoes until Friday".

**Fix:** the mapping requires the ceiling to be supplied locally and refuses
to build a scope without one. Quaestor will not manufacture an upper bound
the user never agreed to, and does not treat the absence of one as
permission.

**Still open upstream.** Worth an issue on the AP2 repository.

---

## 009 — AP2's core mandates cannot currently be verified by anyone

**Day 6. Found by:** trying to implement the verifier the plan called for.

The published specification does not give:

- a JSON schema for `IntentMandate`, only a prose field list;
- a signing algorithm for either core mandate — the only concrete hint
  anywhere is an `ES256K` JWS header on a *PaymentMandate*, a different
  object;
- a canonical byte encoding, so even with an algorithm two implementations
  would disagree on what was signed;
- a named field linking a Cart Mandate back to the Intent Mandate that
  authorized it.

You cannot write a conformance-tested verifier for a signature whose
algorithm, canonical bytes and key discovery are all unspecified.

**Decision:** `verify_intent_mandate` returns
`SignatureSchemeUnspecified` rather than returning `Ok` without checking
anything. The scope mapping ships separately so it is useful now, and every
caller is already handling the error — so when the spec settles, the
implementation lands behind an unchanged signature.

A function named `verify` that returns success without verifying is worse
than no function at all. Someone builds on it.

---

## 010 — `all()` on an empty iterator is true

**Day 7. Found by:** a table of malformed inputs, one of which was `"5. USD"`.

The amount parser split on `.`, then checked that both halves were digits.
For `"5."` the fractional half is the empty string, `"".bytes().all(..)` is
vacuously true, and the amount parsed as five whole units.

Small, and the kind of thing that survives review because the code reads
correctly. It is only visible if you write down the malformed inputs
deliberately rather than testing the shapes you expect.

**Fix:** a present-but-empty fractional part is refused outright.

---

## 011 — An absent spend figure would have read as zero

**Day 8. Found by:** deciding what the evaluator does with a window the
snapshot has no entry for.

The obvious `unwrap_or(zero)` is wrong in the most expensive direction
available. It means every database hiccup hands the agent a completely fresh
budget, and the failure is invisible: the payment is allowed, no error is
raised, and the only trace is a spend figure that never matched reality.

**Fix:** a missing figure is `DenyReason::StateUnavailable`. A budget we
cannot read is a budget we cannot honour, and the safe answer to "I do not
know" is no. Same for a missing velocity count.

The general shape is worth naming, because it recurs: **absent data must
never take the permissive default.** It already bit once as `Constraint::Any`
versus an empty set (006), and it will come up again in the ledger.

---

## 012 — A concurrency test that passed while the bug was present

**Day 12. Found by:** deliberately removing the lock to check the test would
notice.

The gate was a two-agent race: £5.00 left, two agents each asking for £5.00
at the same instant, exactly one may win. With `FOR UPDATE` deleted from the
reservation path, that test **passed three runs out of three.**

A two-way race is simply not reliable evidence. The window between reading
the budget and writing the hold is small, and two threads miss each other far
more often than they collide. The test was not wrong, it was underpowered,
and it would have sat in the suite reading like proof.

The 40-agent version did catch it, every time: 38, 35 and 34 winners against
a budget of 30. Four to eight units of real overspend per run.

**Fix:** the two-agent case now runs 30 rounds against fresh principals. What
matters more is the habit — **a concurrency test is not evidence until you
have watched it fail.** Break the thing it guards, confirm it goes red, put
it back.

---

## 013 — Notes from wiring up Postgres

Three smaller things, kept together because they are the same lesson about
trusting an interface you have not exercised.

`SELECT state` on an enum column deserialized into `String` fails at runtime,
not compile time. `state::text` fixes it.

`$1::hold_state` makes the driver infer the parameter as the enum type and
refuse a `&str`. `$1::text::hold_state` binds a string and lets Postgres do
the conversion.

`Store` needed a hand-written `Debug` rather than a derived one. The
connection can carry credentials, and a struct that prints its own connection
string into a log line is a credential leak with a stack trace attached. The
workspace's `missing_debug_implementations` lint is what raised it.

---

## 014 — A signature does not stop a deletion

**Day 15. Found by:** asking what a signed receipt actually proves.

Signing each receipt stops anyone *altering* one. It does nothing at all
about removing one. An operator who dislikes a particular denial can delete
that line, and every remaining receipt still verifies perfectly, because each
signature only ever covered its own contents.

The gap is easy to miss because the individual check keeps passing. Nothing
looks wrong. The record is simply shorter than it was.

**Fix:** each receipt carries the hash of the one before it, so a removal
breaks the link at that point and at every point after it. A test deletes the
middle receipt, confirms each survivor still passes its own signature check,
and confirms the chain fails anyway.

The related case is worth stating too: a self-consistent chain proves nothing
by itself. An attacker with their own key can produce a perfectly valid one.
Verification takes the expected public key as an argument for that reason.

---

## 015 — The block list matched the website, not the recipient

**Day 17. Found by:** wiring the proxy to the policy engine and watching a
payment to an explicitly blocked address sail through.

`payee_key` read the payee's *domain* and fell back to the id only when the
domain was absent:

```rust
intent.payee.domain.clone()
    .unwrap_or_else(|| intent.payee.id.as_str().to_owned())
```

On x402 those name two different parties. The id is the address the money
goes to; the domain is the host that served the resource. They are related by
nothing at all — an attacker's address can be demanded by a perfectly
ordinary website, which is most of the point of demanding it there.

So `deny_payees = ["0xbad…"]` in a policy file did nothing whenever the
proxy also knew the origin's hostname, which is always. It read correctly,
it parsed correctly, and it blocked nothing.

**Why it was missed for eight days:** the only fixture that exercises
`payee_key` builds its intent with `PayeeId::new(domain)` and
`domain: Some(domain)`. Both identifiers were the same string, so no test
could tell which one the code was reading. The bug was invisible because the
fixture had collapsed the distinction the code was getting wrong.

**Fix, and the asymmetry inside it.** Authority is decided against the id —
whoever receives the money. Block lists (`deny_payees`, `always_escalate`)
match against *every* name the payee answers to.

Those two rules point in opposite directions on purpose:

- A block list matching more names produces more refusals. Being wrong in
  that direction costs a payment.
- An allow list matching more names hands out authority nobody granted. A
  mandate permitting payment to `0xmerchant` must not be satisfiable by
  paying someone else through a host that happens to be called `0xmerchant`.

Four tests now separate the two identifiers, which is the thing the old
fixture never did.

---

## 016 — A mandate could not be written down

**Day 17. Found by:** the proxy putting a delegation chain in a header, which
is the first time anything had.

`Constraint` was `#[serde(tag = "kind")]`. Serde's internally-tagged
representation inserts the tag as a key beside the variant's fields, which is
impossible when the payload is a sequence — so `Constraint::Only` failed at
*runtime* with:

```
cannot serialize tagged newtype variant Constraint::Only containing a sequence
```

Every mandate with any restriction on it — which is every mandate that
restricts anything, which is the entire point of a mandate — could not be
serialized to JSON. `Constraint::Any` serialized fine, which is the wrong half
to have working.

**Why it was missed:** the delegation tests build chains in memory, verify
them in memory, and never write one out. That was reasonable while the only
consumer was a library. A mandate is a thing you *hand to somebody*, and one
that cannot leave the process is not a delegation.

The same family as 001: a type that is correct in Rust and broken on the wire,
failing at runtime on a path nothing exercised.

**Fix:** adjacent tagging, `#[serde(tag = "kind", content = "values")]`. Three
tests now round-trip a full signed chain, both constraint shapes, and confirm
the signing bytes did not move — `signing_bytes` is hand-rolled, so the wire
format and the signature are independent, and that independence is now
asserted rather than assumed.

---

## 017 — The proxy could never talk to a database

**Day 19. Found by:** a crash harness whose first action is to start the
process, kill it, and start it again.

`run()` was annotated `#[tokio::main]`. Inside it, `postgres::Client::connect`
ran. The `postgres` crate is the *blocking* client: it owns a runtime and
drives it with `block_on`, which panics when called from inside another
runtime's worker.

```
thread 'main' panicked at postgres-0.19.14/src/config.rs:465:44:
Cannot start a runtime from within a runtime.
```

So `quaestor-proxy` aborted at startup whenever `QUAESTOR_PG` was set. Not
degraded, not slow: dead, before it ever listened.

It was worse one layer down. `http.rs` opened with a comment saying gateway
work "happens on a blocking thread, because the ledger underneath it is a
synchronous Postgres client" — and then locked the gateway inline in an
`async fn`. The comment described a design nobody had implemented, so every
request touching the ledger would have panicked the same way.

**Why nobody noticed for two days.** Every test set `allow_volatile_ledger`
and ran on `InMemoryHolds`. The in-memory ledger exists for demos; the
Postgres one is the only ledger anyone would deploy. **The single
configuration that matters was the single configuration never exercised**,
and the eleven end-to-end tests all passed while the real thing could not
boot.

The smoke test on day 18 did not catch it either, for the same reason: it
used the example config, which sets `allow_volatile_ledger = true`.

**Fix:** `run()` is a plain function. All setup is synchronous and the
runtime is entered only to serve. Every gateway call now goes through one
`Proxy::with_gateway`, which does the `spawn_blocking` handoff, so a future
call site cannot forget it by writing the obvious thing.

**The lesson is not "test the database path".** It is that a comment
describing a handoff is not a handoff, and that the configuration you skip in
tests is chosen by which one is inconvenient, which is reliably the real one.

---

## 018 — The first crash was permanent

**Day 19. Found by:** the same harness, on its second `start()`.

`quaestor-proxy` applies the schema on startup. Six of the seven statements
in the migration carry `IF NOT EXISTS`. The seventh is:

```sql
CREATE TYPE hold_state AS ENUM ('held', 'captured', 'released', 'expired');
```

Postgres has no `CREATE TYPE IF NOT EXISTS`, so that one statement had no
guard, and the whole migration failed on its second run with
`type "hold_state" already exists`.

The consequence is not "an untidy error on restart". The proxy treats a
failed migration as fatal and exits. **The process could start exactly once
against any given database.** A crash-safe design whose recovery step is
"come back up" had a recovery step that could not run.

**Why it was missed:** the ledger's own tests create the schema once per
database and the concurrency suite reuses it. Nothing had ever asked the same
process to migrate twice, because nothing had ever restarted.

**Fix:** a `DO` block that swallows `duplicate_object`, and a test that
applies the schema three times in a row. The test is the point — the fix is
one SQL idiom, and the reason it was absent is that migrating twice was never
an exercised path.

---

## 019 — The transparency log was never written down

**Day 19. Found by:** writing an invariant checker that wanted to read the
receipt log and discovering there was nothing to read.

`quaestor-receipt` is careful work. Receipts are signed, hash-chained,
verifiable offline with nothing but a public key, and a deletion breaks the
link. `README.md` said all of that. Fourteen tamper tests backed it up.

The proxy signed each receipt, put it in a response header, and dropped it.

So the only copy of any decision was held by the agent whose spending the
decision constrained. "Deleting the awkward receipt breaks the chain" is a
true statement about a log, and there was no log — an operator asked for
their history would have had nothing to hand over, doctored or otherwise.

Every claim was true in the crate and vacuous in the product.

**Fix:** a `ReceiptSink`, and a `JsonLinesSink` that appends and fsyncs
before the verdict reaches anybody. Three consequences fell out of getting
the ordering right, and all three are now tested:

- an allowed payment whose receipt cannot be written is **refused**, and its
  hold released, because a payment nobody can account for is the thing the
  chain exists to prevent;
- a *refusal* that cannot be written still stands, because refusing is safe
  whatever else is broken, and downgrading a denial because the audit log was
  full would be an absurd way to lose money;
- a restart resumes the chain from the persisted tail, which is why a crash
  between signing and persisting is safe: the lost receipt never escaped, so
  reusing its sequence number forks nothing.

That last one is `receipt.after_sign` in the harness.

---

## 020 — The README was wrong about other people's software

**Day 26. Found by:** reading the README cold, the way a hostile commenter
would, and checking every claim it made about somebody else.

Two claims about competitors, both stated with confidence, and one of them
simply false.

The comparison section said Rego is *a language that does not guarantee
termination*. It is the opposite. Rego forbids recursion for exactly that
reason, and OPA's own documentation says policy evaluation "should be known
to *terminate*". Nobody checked, because it sounded like the kind of thing
that is true about a policy language.

It also said OPA and Cedar both have *two verdicts where this needs three*.
Cedar does return exactly `Allow` or `Deny`. OPA returns any document you
like, so a third verdict is expressible there. The claim was true of one
engine and presented as true of both.

And the architecture diagram, one screen further up, listed a *refund* path
and a *reconcile* layer. Neither exists. The ledger has holds, capture and
release; reconciliation was cut on day 3 and has no code at all.

**Why this matters more than a code bug.** Every other entry in this file is
a place the software was wrong. These are places the *documentation* was
wrong, about the one thing a reader cannot check by running a test, on the
page most likely to be read by the people who work on those projects. A
wrong claim about someone else's software is corrected in public, by an
expert, on launch day, and it costs the credibility of every true claim
next to it.

**Fix:** the diagram marks L5 as not built and says there is no refund. The
comparison was rewritten using only what could be verified against each
project's documentation, and it came out stronger: both engines evaluate
against a snapshot of data handed to them, which is precisely the shape of
the budget race the ledger exists to close. The better argument had been
there all along and was hidden behind a worse one that happened to be false.

---

## What the harness found, and what it confirmed

All eight crash points behave as written down beforehand. The three bugs
above were all found *before the first crash ran*, by the setup steps.

The confirmed claims, each now evidence rather than argument:

| killed at | left behind | verdict |
|---|---|---|
| `reserve.before` | nothing | a decision never written down did not happen |
| `ledger.mid_transaction` | nothing | the reservation really is one transaction |
| `reserve.after` | `held`, no receipt | expires, budget returns |
| `receipt.after_sign` | `held`, no receipt | the lost receipt never escaped |
| `receipt.after_persist` | `held`, chain verifies | agent retries, no double hold |
| `connect.after` | `held`, origin saw nothing | |
| `capture.after` | `captured`, origin paid 0 times | the deliberate, visible cost |
| `write.after` | `captured`, origin paid once | ledger and reality agree |

**And the harness was watched failing**, per #012. Deleting the pre-write
capture from `http.rs` turns `write.after` red with exactly the right
sentence:

```
BROKEN: no money without a committed spend: the origin was paid for
        x402:0101…, but its hold is `held`, so the budget will be
        handed back for money that moved
```

Restore the four lines and it goes green. A crash test nobody has watched
fail is decoration.

---

## 021 — CI was red for nineteen days and the local check said green

**Day 27. Found by:** looking at the Actions tab for the first time since
the first week, on the day before launch.

The last green run was 1 September. Every run after it failed, and every one
of them failed on the same step, and nobody noticed because
`scripts/check.sh` printed "all green" every single time it was asked.

The cause is two lines that look like they agree.

`ci.yml` installs the toolchain with `rustup component add`, and
`rust-toolchain.toml` said `channel = "stable"`. So the runner used whatever
stable was current that morning. rustc 1.98 shipped on 1 September carrying
a new `clippy::question_mark` lint. It fires on two `match` expressions in
this repository, one in the RFC 3339 parser and one in the challenge store.
The container the local checks ran in was still on 1.95, from March, where
that lint does not exist.

So both sides ran identical commands with identical flags against different
compilers, and reported opposite results, truthfully.

**Why this is the worst entry in this file.** `scripts/check.sh` exists
*because of* an earlier version of exactly this, on day 1, where CI ran
`cargo doc` and the local check did not. The fix then was to make the script
run the same commands. The script's own comment claims it is "exactly what
CI runs, in the same order, with the same flags" — and that was true, and
was not enough, because the flags were never the variable. The toolchain was.

A parity script that does not pin the compiler is a parity script about
everything except the thing most likely to change underneath it.

**Fix, in three parts:**

- `rust-toolchain.toml` pins `1.98.1`. A compiler upgrade is now a commit
  somebody reviewed rather than something that happens overnight.
- `scripts/check.sh` prints `cargo --version` and `cargo clippy --version`
  before it does anything else, so a mismatch is visible rather than
  deduced from a contradiction later.
- CI gained a non-blocking `latest stable (advisory)` job that deletes the
  pin and runs clippy on whatever stable is newest. New lints now arrive as
  a yellow warning weeks early instead of as a red build nobody can
  reproduce.

**And the honest part:** the fix for the lint took four minutes. The
nineteen days came from trusting a green line in my own terminal over the
one place that was telling me the truth, which I never opened.

---

## 022 — The replay guard was the one part of the system that forgot

**Day 28. Found by:** nobody. It had been sitting in this file, under "Open
questions", for nine days, which is its own kind of finding.

An x402 authorization is a bearer instrument. Anyone holding the signed
payload can present it, and the only thing standing between one signature
and two payments is a record that it has already been spent. The proxy kept
that record in a `HashSet`. A restart emptied it.

So the failure mode was not an attack. It was a deploy.

**What made it survivable, and why that is not a defence.** A replay across
a restart *was* refused, and the harness said so
(`a_restart_must_not_make_a_spent_authorization_spendable_again` has been
green since day 19). But it was refused by the wrong thing. Replacing the
durable store with the old in-memory one and reading the body the proxy
actually returns:

```json
{"error":"denied","detail":"malformed: this intent has already been settled",
 "verdict":{"reasons":[{"code":"malformed_intent", ...}]}}
```

That is the ledger's unique index on `(principal, idempotency_key)`
refusing a second *reservation*, and it only coincides with a replay guard
because the idempotency key is derived from the authorization's nonce. It is
genuine defence in depth and it is worth having. It is not a replay guard,
it reports a replayed bearer instrument as a malformed intent, and it lives
in the layer that reserves budget rather than the layer that verifies
payments. The first person to add retention to the holds table — and
somebody will, because a holds table that grows forever is not a table —
would delete the last thing standing between one signature and two
payments, and no test would have gone red.

**Why the test did not catch it.** It asserted a status code. Any 403
satisfied it, and there were two different guards capable of producing one.
It now asserts on the reason, which is what makes it a test of the replay
guard rather than a test that something, somewhere, said no.

**Fix.** `PgNonceStore` in `quaestor-ledger`, one statement:

```sql
INSERT INTO payment_nonces (payer, nonce, valid_before_secs)
VALUES ($1, $2, $3)
ON CONFLICT (payer, nonce) DO NOTHING
```

The row count is the whole check. No value is read and then acted on, so
there is no window between reading and acting — which is what the trait has
demanded since day 6 and what the entry two bullets above this one in the
open questions warned would be got wrong. Sixteen threads and a barrier
confirm it: exactly one is told it is the first. Rewritten as a `SELECT`
followed by an `INSERT`, nine of the sixteen are.

**Three things fell out of it that were not the bug.**

*The trait could not say "I don't know".* `check_and_record` returned
`bool`, and a database that cannot answer is not the same as a database that
answered no. Collapsing them reports an outage to the operator as a replay
attack and to the agent as a permanent `403` rather than a `503` it should
retry. It now returns `Result<Freshness, NonceStoreUnavailable>`, the
gateway stops trying further payment requirements the moment the failure is
ours rather than the payer's, and `VerifyError::is_infrastructure` keeps the
two apart without anyone parsing a string.

*`postgres::Error` renders as the string "db error".* Everything useful — the
message, the SQLSTATE, the constraint that fired — is one level down in its
source. The first version of the store called `to_string()` on it, so a
missing table would have produced a `503` whose entire explanation was "db
error". True, and worth nothing at three in the morning.

*The crash harness depended on the bug.* `wipe_database` reset `holds` and
`budget_accounts` and nothing else, because until now the nonce store lived
in the proxy's memory and every `kill` wiped it for free. Making it durable
turned the second run of the suite red: a case refused for replaying a nonce
an earlier case had spent. A harness that relies on the system forgetting
stops working the moment the system stops forgetting, and it is better to
learn that from a red test than from a reviewer.

**On the table growing.** A nonce record only has to outlive the
authorization it belongs to. Past `validBefore` the verifier refuses the
payload on the temporal check, which runs *before* the replay check is
reached, so the row has stopped protecting anything. `prune` deletes exactly
those rows. That argument has a premise, and the premise is now a test:
`an_expired_payload_never_reaches_the_nonce_store` hands the verifier a
store that errors if it is consulted at all and asserts an expired payload
is refused without touching it. Move the replay check one step earlier in
the pipeline and that test goes red, which is the point of writing it.

---

## Open questions

- `capture` is terminal and the ledger has no reversing entry. The proxy is
  built around that — it captures only once the upstream connection is up,
  so anything that fails earlier releases a hold that is still `held`. But an
  operator who later establishes that a captured payment genuinely never
  settled has no tool. That is a double-entry problem and it is what the
  ledger's v2 is for.
- Refusals before a payment verifies produce no receipt, deliberately: the
  only amount and payee available are the ones inside the message being
  rejected, and writing those into a signed chain would let anyone publish
  claims into the evidence log. The cost is that a caller flooding the proxy
  with unverifiable payments leaves no signed trace. Metrics, not receipts,
  is probably the answer.
- The gateway is behind one mutex. Reservations for a single principal
  serialize in Postgres anyway, so the lock costs less than it looks like,
  but it also serializes *different* principals, which the database would
  not. First thing to revisit under real load.
- Signature malleability is currently handled by `k256` rejecting high-S
  values. That is a dependency's behaviour, not our test. It deserves an
  explicit case.
- The holds schema records a currency code but not its exponent, and
  `currency_exponent` maps codes to decimals in Rust. The exponent is part of
  a currency's identity everywhere else in this system, so storing only half
  of it is a gap. It should be a column.
- Nothing calls `PgNonceStore::prune`. The method is tested and safe, and
  the table still grows until an operator runs it. A sweep belongs somewhere,
  and putting it on a timer inside the store was rejected on purpose: a
  store that deletes rows on its own schedule is a store whose contents
  depend on when you look, which is the opposite of auditable.
- The proxy opens two Postgres connections, one for holds and one for
  nonces, and neither is pooled. That is deliberate — a rolled-back
  reservation must not roll back the record that an authorization was spent
  — but "two connections, no pool" is a sentence that will need revisiting
  before anyone runs this under load.
