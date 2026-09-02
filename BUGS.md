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

## Open questions

- `NonceStore::check_and_record` is documented as needing to be atomic. The
  in-memory implementation is; the Postgres one is not written yet. If it
  lands as a read followed by a write, two concurrent replays of the same
  authorization can both be told they are the first.
- Signature malleability is currently handled by `k256` rejecting high-S
  values. That is a dependency's behaviour, not our test. It deserves an
  explicit case.
