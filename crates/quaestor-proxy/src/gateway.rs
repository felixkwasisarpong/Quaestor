//! The decision, with no sockets in it.
//!
//! # The order of operations, and why this one
//!
//! ```text
//!   authenticate ─ challenge ─ verify ─ authority ─ evaluate ─ reserve
//!                                                                 │
//!                                 receipt ─ connect ─ capture ─ write bytes
//! ```
//!
//! Everything before `reserve` can only refuse, costs nothing, and touches
//! no durable state. Everything after it is bookkeeping that has to be
//! undone if the next step fails. Putting the cheap total functions first is
//! not an optimisation, it is what makes a refusal free of consequences: a
//! payment rejected at the door leaves the ledger exactly as it was.
//!
//! # The point of no return is the write, not the response
//!
//! This is the one place the gateway departs from the card model, and it is
//! deliberate.
//!
//! A card authorization is a *promise* held by the issuer. You ship, then
//! you capture, and if you never capture the hold lapses and the money was
//! never yours. Reserve, act, capture on success is correct there because
//! the acquirer will not move money without you.
//!
//! An `X-PAYMENT` header is not a promise, it is a bearer instrument. It
//! carries a signature that authorizes a transfer, and anyone holding it can
//! present it for settlement — a resource server can take the header, submit
//! it, and return a `500`. Nobody asks Quaestor for permission, because
//! Quaestor is not in that path. Once those bytes reach the upstream socket,
//! the money is gone as far as this process can know.
//!
//! Capture-on-`200` is therefore wrong in the expensive direction: a server
//! that pockets the authorization and errors gets paid *and* hands the
//! budget back, and the ledger records a spend that never happened.
//!
//! So the capture happens as late as it can while still being before the
//! write. The transport connects first, calls [`Gateway::commit_spend`],
//! and only then writes. That leaves three failure windows and all three
//! fail in the recoverable direction:
//!
//! | fails at | hold is | outcome |
//! |---|---|---|
//! | connect | `held` | released by [`Gateway::on_forward_failed`] |
//! | capture | `held` | the transport must not write; released |
//! | after the write | `captured` | stays captured, see below |
//!
//! A crash between the capture and the write leaves the hold `held`, and it
//! expires. Budget briefly frozen, then returned, and no money moved. The
//! opposite ordering would leave money moved and the budget returned, which
//! nothing later can detect.
//!
//! Once bytes are out, [`Reach::MaybeDelivered`] leaves the spend captured.
//! "We do not know whether that money moved" has exactly one safe reading.
//!
//! # Where receipts start
//!
//! Not at the door. A malformed credential, a missing challenge or an
//! unverifiable signature produce no receipt, because there is nothing yet
//! that a receipt could truthfully assert. The only amount and payee
//! available at that point are the ones inside the message being rejected,
//! and writing attacker-supplied numbers into a signed chain would turn the
//! evidence log into a place anybody can publish claims.
//!
//! From the moment a payment verifies, every outcome is receipted:
//! approvals, denials, escalations, and the case where policy said yes and
//! the ledger said no.

use base64::Engine as _;
use quaestor_core::{
    AgentId, CallContext, Currency, DenyReason, IdempotencyKey, IntentId, Money, Payee, PayeeId,
    PaymentIntent, PrincipalId, Rail, Timestamp, Verdict,
};
use quaestor_policy::{evaluate, Policy, SpendSnapshot};
use quaestor_receipt::{Receipt, Signer};
use quaestor_verify::mandate::{self, Mandate, Scope};
use quaestor_verify::x402::{
    verify_exact_evm, AssetRegistry, NonceStore, PaymentPayload, VerifiedPayment,
};

use crate::challenge::{ChallengeKey, ChallengeStore};
use crate::holds::{Holds, ReserveRequest};
use crate::identity::{Caller, Identities};

/// The parts of an inbound request the gateway is allowed to see.
///
/// Deliberately not a `hyper::Request`. The decision must not be able to
/// depend on a body, a connection, or anything else that would make it
/// untestable without a socket, and the cheapest way to guarantee that is
/// for those things not to be reachable from here.
#[derive(Debug, Clone, Default)]
pub struct Incoming<'a> {
    pub method: &'a str,
    /// The request target as the agent wrote it, absolute form.
    pub target: &'a str,
    pub authorization: Option<&'a str>,
    /// `X-PAYMENT`, base64 as it arrived.
    pub payment: Option<&'a str>,
    /// `X-Quaestor-Mandate`, base64 JSON delegation chain.
    pub mandate: Option<&'a str>,
}

/// Did the request reach the origin?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// The connection was never established, or failed before a byte of the
    /// request was written. The authorization did not leave this process.
    NeverConnected,
    /// Bytes went out and the outcome is unknown: a reset mid-flight, a
    /// timeout, a truncated response. The origin may hold the payment.
    MaybeDelivered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    /// No usable credential. No principal, so no budget and no receipt.
    Unauthenticated,
    /// A payment arrived for a request we never saw a `402` for.
    NoChallenge,
    /// The payment did not satisfy anything the origin demanded.
    Unverifiable,
    /// Policy said no.
    Denied,
    /// Policy wants a human. Nobody is here, so it resolves to no.
    Escalated,
    /// A check could not be run. Fails closed.
    Unavailable,
}

impl RefusalKind {
    /// The status the agent sees.
    ///
    /// `NoChallenge` answers `402` because the agent's correct next move is
    /// to fetch the resource without a payment and read the challenge. Every
    /// other refusal is `403`: this gateway will not authorize the payment,
    /// and retrying the same one is not going to help.
    pub fn status(self) -> u16 {
        match self {
            RefusalKind::Unauthenticated => 401,
            RefusalKind::NoChallenge => 402,
            RefusalKind::Unverifiable | RefusalKind::Denied | RefusalKind::Escalated => 403,
            RefusalKind::Unavailable => 503,
        }
    }
}

/// Why the payment is not being forwarded, and the evidence for it.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub kind: RefusalKind,
    pub detail: String,
    /// Present from the point a payment verified. See the module docs for
    /// why the earlier refusals have none.
    pub receipt: Option<Receipt>,
}

impl Refusal {
    pub fn status(&self) -> u16 {
        self.kind.status()
    }

    /// What goes back to the agent. Reasons included: an agent that is told
    /// only "denied" has to guess, and guessing means retrying.
    pub fn body(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("error".into(), serde_json::json!(kind_code(self.kind)));
        map.insert("detail".into(), serde_json::json!(self.detail));
        if let Some(r) = &self.receipt {
            map.insert("verdict".into(), serde_json::json!(&r.verdict));
            map.insert("receipt_seq".into(), serde_json::json!(r.seq));
        }
        serde_json::Value::Object(map)
    }
}

fn kind_code(k: RefusalKind) -> &'static str {
    match k {
        RefusalKind::Unauthenticated => "unauthenticated",
        RefusalKind::NoChallenge => "no_challenge",
        RefusalKind::Unverifiable => "unverifiable_payment",
        RefusalKind::Denied => "denied",
        RefusalKind::Escalated => "approval_required",
        RefusalKind::Unavailable => "unavailable",
    }
}

/// What the transport should do next.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// No payment on this request. Relay it and, if the answer is a `402`,
    /// hand the body to [`Gateway::record_challenge`] on the way back.
    Passthrough { principal: String },
    /// Authorized, and a hold is now standing against the budget. The
    /// transport is obliged to finish the sequence: connect, then
    /// [`Gateway::commit_spend`], then write — or report what happened
    /// through [`Gateway::on_forward_failed`]. Doing neither freezes the
    /// held amount until it expires.
    Forward {
        intent_id: String,
        receipt: Box<Receipt>,
    },
    /// Answer the agent with this and send nothing upstream.
    Refuse(Box<Refusal>),
}

/// Deployment settings that are not policy.
#[derive(Debug, Clone)]
pub struct Config {
    pub policy: Policy,
    pub registry: AssetRegistry,
    pub challenge_ttl_ms: i64,
    pub challenge_capacity: usize,
}

impl Config {
    pub fn new(policy: Policy, registry: AssetRegistry) -> Config {
        Config {
            policy,
            registry,
            challenge_ttl_ms: 120_000,
            challenge_capacity: 4_096,
        }
    }
}

/// The gateway.
pub struct Gateway {
    config: Config,
    identities: Identities,
    challenges: ChallengeStore,
    nonces: Box<dyn NonceStore + Send>,
    holds: Box<dyn Holds>,
    signer: Signer,
}

impl core::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gateway")
            .field("challenges", &self.challenges.len())
            .field("identities", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Gateway {
    pub fn new(
        config: Config,
        identities: Identities,
        holds: Box<dyn Holds>,
        nonces: Box<dyn NonceStore + Send>,
        signer: Signer,
    ) -> Gateway {
        let challenges = ChallengeStore::new(config.challenge_ttl_ms, config.challenge_capacity);
        Gateway {
            config,
            identities,
            challenges,
            nonces,
            holds,
            signer,
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    pub fn challenges_held(&self) -> usize {
        self.challenges.len()
    }

    /// Remember a `402` on its way back to the agent.
    ///
    /// Returns whether anything was recorded, for logging only. A `402` we
    /// could not read is still relayed unchanged; the consequence surfaces
    /// later, as a refusal, which is the right direction to fail in.
    pub fn record_challenge(
        &mut self,
        principal: &str,
        method: &str,
        target: &str,
        body: &[u8],
        now: Timestamp,
    ) -> bool {
        self.challenges
            .record_402(ChallengeKey::new(principal, method, target), body, now)
    }

    /// Decide what happens to one request.
    pub fn on_request(&mut self, req: &Incoming<'_>, now: Timestamp) -> Outcome {
        let Some(caller) = self
            .identities
            .from_authorization(req.authorization)
            .cloned()
        else {
            return refuse(
                RefusalKind::Unauthenticated,
                "a bearer credential this gateway knows is required",
            );
        };

        let Some(payment_b64) = req.payment else {
            return Outcome::Passthrough {
                principal: caller.principal.as_str().to_owned(),
            };
        };

        self.decide_payment(&caller, req, payment_b64, now)
    }

    fn decide_payment(
        &mut self,
        caller: &Caller,
        req: &Incoming<'_>,
        payment_b64: &str,
        now: Timestamp,
    ) -> Outcome {
        // 1. What did the origin actually demand? If we do not know, we
        //    cannot check anything, and `payload.accepted` is not an answer
        //    to that question — it is the agent's own claim. See `challenge`.
        let key = ChallengeKey::new(caller.principal.as_str(), req.method, req.target);
        let Some(challenge) = self.challenges.get(&key, now) else {
            return refuse(
                RefusalKind::NoChallenge,
                "no outstanding payment challenge for this request; \
                 request the resource without a payment first",
            );
        };
        let alternatives = challenge.alternatives.clone();

        // 2. Decode. Two layers, both attacker-supplied, both refused loudly.
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(payment_b64.trim()) else {
            return refuse(RefusalKind::Unverifiable, "X-PAYMENT is not valid base64");
        };
        let payload: PaymentPayload = match serde_json::from_slice(&raw) {
            Ok(p) => p,
            Err(e) => {
                return refuse(
                    RefusalKind::Unverifiable,
                    &format!("X-PAYMENT is not an x402 payment payload: {e}"),
                )
            }
        };

        // 3. Verify against the origin's demands, one alternative at a time.
        //    A failed alternative costs nothing durable: the nonce is
        //    recorded last, inside the verifier, only on full success.
        let now_secs = now.as_millis().div_euclid(1_000).unsigned_abs();
        let mut last_error = None;
        let mut verified: Option<VerifiedPayment> = None;
        for alt in &alternatives {
            match verify_exact_evm(
                &payload,
                alt,
                &self.config.registry,
                self.nonces.as_mut(),
                now_secs,
            ) {
                Ok(v) => {
                    verified = Some(v);
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        let Some(verified) = verified else {
            let detail = last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "the challenge offered nothing to satisfy".to_owned());
            return refuse(RefusalKind::Unverifiable, &detail);
        };

        // 4. From here there is a payment, so from here everything is
        //    receipted.
        let intent = match self.build_intent(caller, &verified, req, now) {
            Ok(i) => i,
            Err(detail) => return refuse(RefusalKind::Unverifiable, &detail),
        };

        let authority = match self.authority_for(caller, req.mandate, now) {
            Ok(a) => a,
            Err(reason) => {
                let verdict = Verdict::Deny {
                    reasons: vec![reason],
                };
                return self.receipted_refusal(RefusalKind::Denied, &intent, &verdict, now);
            }
        };

        let snapshot = self.snapshot(caller.principal.as_str(), intent.amount.currency(), now);

        let verdict = evaluate(&quaestor_policy::Request {
            intent: &intent,
            authority: &authority,
            policy: &self.config.policy,
            state: &snapshot,
            now,
        });

        match verdict {
            Verdict::Deny { .. } => {
                self.receipted_refusal(RefusalKind::Denied, &intent, &verdict, now)
            }
            Verdict::Escalate { .. } => {
                // Nobody is standing here to approve it. An escalation with
                // no answer is a denial, never an allow, and the receipt
                // records it as the escalation it was.
                self.receipted_refusal(RefusalKind::Escalated, &intent, &verdict, now)
            }
            Verdict::Allow { .. } => self.commit(&intent, now),
        }
    }

    /// Reserve, receipt, capture, and hand the transport a payment it is now
    /// obliged to account for.
    fn commit(&mut self, intent: &PaymentIntent, now: Timestamp) -> Outcome {
        let reservation = self.holds.reserve(&ReserveRequest {
            principal: intent.principal.as_str(),
            agent: intent.agent.as_str(),
            payee: intent.payee.id.as_str(),
            intent_id: intent.id.as_str(),
            idempotency_key: intent.idempotency_key.as_str(),
            amount: intent.amount,
            budgets: &self.config.policy.budgets,
            now,
            hold_ttl_ms: self.config.policy.hold_ttl_ms,
        });

        let reservation = match reservation {
            Ok(r) => r,
            Err(e) => {
                let verdict = Verdict::Deny {
                    reasons: vec![DenyReason::StateUnavailable {
                        detail: format!("the ledger could not be reached: {e}"),
                    }],
                };
                return self.receipted_refusal(RefusalKind::Unavailable, intent, &verdict, now);
            }
        };

        let hold = match reservation {
            quaestor_ledger::Reservation::Reserved(h) => h,

            // Policy read a snapshot; the ledger read the truth, under a
            // lock, with every concurrent reservation already visible. When
            // they disagree the ledger wins, and the receipt says the ledger
            // refused rather than reporting the approval policy gave.
            quaestor_ledger::Reservation::Refused {
                window_label,
                limit,
                already_held,
                attempted,
            } => {
                let remaining = limit
                    .checked_sub(&already_held)
                    .unwrap_or_else(|_| Money::zero(limit.currency()));
                let verdict = Verdict::Deny {
                    reasons: vec![
                        DenyReason::BudgetExceeded {
                            limit,
                            attempted,
                            remaining: if remaining.is_negative() {
                                Money::zero(limit.currency())
                            } else {
                                remaining
                            },
                        },
                        DenyReason::StateUnavailable {
                            detail: format!(
                                "the {window_label} budget was exhausted between the policy \
                                 check and the reservation"
                            ),
                        },
                    ],
                };
                return self.receipted_refusal(RefusalKind::Denied, intent, &verdict, now);
            }

            // The intent id is derived from the authorization's nonce, and a
            // repeated nonce is refused by the verifier long before this
            // point. Arriving here means two different authorizations share
            // an id, which we do not understand well enough to allow.
            quaestor_ledger::Reservation::AlreadySettled(_) => {
                let verdict = Verdict::Deny {
                    reasons: vec![DenyReason::MalformedIntent {
                        detail: "this intent has already been settled".to_owned(),
                    }],
                };
                return self.receipted_refusal(RefusalKind::Denied, intent, &verdict, now);
            }
        };

        let allow = Verdict::Allow {
            hold: quaestor_core::Hold {
                intent: intent.id.clone(),
                amount: hold.amount,
                expires_at: hold.expires_at,
            },
        };
        let receipt = self.issue(intent, &allow, now);

        Outcome::Forward {
            intent_id: intent.id.as_str().to_owned(),
            receipt: Box::new(receipt),
        }
    }

    /// Commit the spend. The transport calls this once the upstream
    /// connection is established and immediately before writing the payment.
    ///
    /// # Contract
    ///
    /// An `Err` means the transport **must not write**, and must then report
    /// [`Reach::NeverConnected`]. Writing a payment whose spend could not be
    /// committed is the one sequence with no safe recovery: the hold expires
    /// on its own and hands back budget for money that may well have moved.
    pub fn commit_spend(
        &mut self,
        intent_id: &str,
        now: Timestamp,
    ) -> Result<(), crate::holds::HoldsError> {
        self.holds.capture(intent_id, now)?;
        Ok(())
    }

    /// A payment this gateway authorized did not go out as intended.
    ///
    /// Returns whether the budget was given back.
    pub fn on_forward_failed(&mut self, intent_id: &str, reach: Reach, now: Timestamp) -> bool {
        match reach {
            // Provably nothing was written, so the hold is still `held` and
            // releasing it is an ordinary, legal transition. This is the
            // entire reason the capture waits for the connection: a spend
            // that has been captured cannot be taken back, because `capture`
            // is terminal and this ledger has no reversing entry.
            Reach::NeverConnected => self.holds.release(intent_id, now).is_ok(),
            // Unknown. The origin may be holding a valid authorization it
            // can settle at leisure.
            Reach::MaybeDelivered => false,
        }
    }

    // -- pieces ----------------------------------------------------------

    fn build_intent(
        &self,
        caller: &Caller,
        verified: &VerifiedPayment,
        req: &Incoming<'_>,
        now: Timestamp,
    ) -> Result<PaymentIntent, String> {
        // Derived from the authorization's own nonce, so the identifier for
        // a payment is a function of the payment. Two receipts for one
        // authorization are then impossible to write by accident, and a
        // replay carries the id of the original.
        let id_text = format!("x402:{}", hex(&verified.nonce));
        let id = IntentId::new(id_text.clone()).map_err(|e| format!("intent id: {e}"))?;
        let idem = IdempotencyKey::new(id_text).map_err(|e| format!("idempotency key: {e}"))?;

        let payee_id =
            PayeeId::new(hex_addr(&verified.payee)).map_err(|e| format!("payee id: {e}"))?;

        Ok(PaymentIntent {
            id,
            idempotency_key: idem,
            agent: AgentId::new(caller.agent.as_str()).map_err(|e| format!("agent id: {e}"))?,
            principal: PrincipalId::new(caller.principal.as_str())
                .map_err(|e| format!("principal id: {e}"))?,
            amount: verified.amount,
            payee: Payee {
                id: payee_id,
                rail: Rail::X402,
                // x402 carries no merchant category. Absent, not empty: a
                // policy that blocks a category must not silently pass every
                // payment that failed to declare one, and `None` is what the
                // evaluator reads as "no category to check".
                category: None,
                domain: domain_of(req.target),
            },
            context: CallContext {
                session_id: None,
                tool_call_id: None,
                parent_intent: None,
            },
            requested_at: now,
        })
    }

    /// What this caller may spend, after any presented delegation chain.
    ///
    /// A chain may narrow the configured scope and may never widen it. That
    /// check is the reason the configured scope exists at all: without it, a
    /// caller who holds any chain rooted in a trusted key could grant
    /// themselves whatever that root once granted anybody.
    fn authority_for(
        &self,
        caller: &Caller,
        mandate_b64: Option<&str>,
        now: Timestamp,
    ) -> Result<Scope, DenyReason> {
        let Some(b64) = mandate_b64 else {
            return Ok(caller.scope.clone());
        };
        if caller.root_keys.is_empty() {
            return Err(DenyReason::ScopeWidened {
                detail: "a delegation chain was presented by a caller with no trusted roots"
                    .to_owned(),
            });
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| DenyReason::MalformedIntent {
                detail: "X-Quaestor-Mandate is not valid base64".to_owned(),
            })?;
        let chain: Vec<Mandate> =
            serde_json::from_slice(&raw).map_err(|e| DenyReason::MalformedIntent {
                detail: format!("X-Quaestor-Mandate is not a delegation chain: {e}"),
            })?;

        let authority = mandate::verify_chain(&chain, &caller.root_keys, now).map_err(|e| {
            DenyReason::ScopeWidened {
                detail: format!("delegation chain rejected: {e}"),
            }
        })?;

        if authority.principal.as_str() != caller.principal.as_str() {
            return Err(DenyReason::ScopeWidened {
                detail: format!(
                    "the chain is for principal {}, the credential is for {}",
                    authority.principal, caller.principal
                ),
            });
        }
        authority
            .scope
            .is_within(&caller.scope)
            .map_err(|w| DenyReason::ScopeWidened {
                detail: format!("the chain claims more than this credential is granted: {w}"),
            })?;

        Ok(authority.scope)
    }

    /// Read committed spend for every configured window.
    ///
    /// A window the ledger cannot answer for is *left out* of the snapshot
    /// rather than filled with a zero. The evaluator turns an absent figure
    /// into `StateUnavailable`, which is a denial. That is the whole
    /// mechanism: this function has no way to express "assume nothing has
    /// been spent", so a database outage cannot become a fresh budget.
    fn snapshot(&mut self, principal: &str, currency: Currency, now: Timestamp) -> SpendSnapshot {
        let mut snap = SpendSnapshot::new();
        let code = currency.code().to_owned();
        let windows: Vec<i64> = self
            .config
            .policy
            .budgets
            .iter()
            .map(|b| b.window_ms)
            .collect();
        for window_ms in windows {
            if let Ok(minor) = self.holds.spent_in_window(principal, &code, window_ms, now) {
                snap = snap.with_spend(window_ms, Money::new(minor, currency));
            }
        }
        snap
    }

    fn issue(&mut self, intent: &PaymentIntent, verdict: &Verdict, now: Timestamp) -> Receipt {
        self.signer.issue(
            intent.id.as_str(),
            intent.principal.as_str(),
            intent.agent.as_str(),
            intent.payee.id.as_str(),
            intent.amount,
            verdict,
            self.config.policy.version_hash,
            now,
        )
    }

    fn receipted_refusal(
        &mut self,
        kind: RefusalKind,
        intent: &PaymentIntent,
        verdict: &Verdict,
        now: Timestamp,
    ) -> Outcome {
        let receipt = self.issue(intent, verdict, now);
        Outcome::Refuse(Box::new(Refusal {
            kind,
            detail: describe(verdict),
            receipt: Some(receipt),
        }))
    }
}

fn refuse(kind: RefusalKind, detail: &str) -> Outcome {
    Outcome::Refuse(Box::new(Refusal {
        kind,
        detail: detail.to_owned(),
        receipt: None,
    }))
}

/// One line an operator can read, from a verdict that may carry four
/// reasons. The receipt keeps all of them; this is the summary.
fn describe(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Allow { .. } => "allowed".to_owned(),
        Verdict::Deny { reasons } => join(reasons.iter().map(render)),
        Verdict::Escalate { reasons, .. } => join(reasons.iter().map(render_escalation)),
    }
}

fn join(parts: impl Iterator<Item = String>) -> String {
    let all: Vec<String> = parts.collect();
    if all.is_empty() {
        "no reason recorded".to_owned()
    } else {
        all.join("; ")
    }
}

fn render(r: &DenyReason) -> String {
    match r {
        DenyReason::BudgetExceeded {
            limit,
            attempted,
            remaining,
        } => format!("{attempted} would breach a {limit} budget with {remaining} left"),
        DenyReason::VelocityExceeded {
            limit_per_window,
            window_ms,
        } => format!("more than {limit_per_window} payments in {window_ms}ms"),
        DenyReason::PayeeBlocked => "this payee is blocked".to_owned(),
        DenyReason::CategoryBlocked { category } => format!("category {category} is blocked"),
        DenyReason::StateUnavailable { detail } => format!("a check could not be run: {detail}"),
        DenyReason::RailNotPermitted => "this rail is not permitted".to_owned(),
        DenyReason::ScopeWidened { detail } => format!("outside the delegated authority: {detail}"),
        DenyReason::MandateExpired { expired_at } => {
            format!("the mandate expired at {}", expired_at.as_millis())
        }
        DenyReason::MandateMissing => "a mandate is required".to_owned(),
        DenyReason::BadSignature => "the mandate signature did not verify".to_owned(),
        DenyReason::ApprovalDenied => "a human declined this".to_owned(),
        DenyReason::ApprovalExpired => "nobody answered the approval request".to_owned(),
        DenyReason::MalformedIntent { detail } => format!("malformed: {detail}"),
    }
}

fn render_escalation(r: &quaestor_core::EscalationReason) -> String {
    match r {
        quaestor_core::EscalationReason::FirstSeenPayee => {
            "this payee has not been paid before".to_owned()
        }
        quaestor_core::EscalationReason::LargeShareOfBudget {
            remaining,
            attempted,
        } => format!("{attempted} is a large share of the {remaining} remaining"),
        quaestor_core::EscalationReason::AboveUnattendedLimit { limit } => {
            format!("above the {limit} unattended limit")
        }
        quaestor_core::EscalationReason::PolicyRequiresApproval { rule } => {
            format!("policy rule {rule} requires approval")
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_addr(a: &[u8; 20]) -> String {
    format!("0x{}", hex(a))
}

/// The origin's host, for the receipt and for policy that cares about it.
/// Best effort: a target we cannot parse produces `None`, and no rule is
/// allowed to treat an absent domain as a match.
fn domain_of(target: &str) -> Option<String> {
    let rest = target.split_once("://").map(|(_, r)| r).unwrap_or(target);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_yields_the_origin_host() {
        assert_eq!(
            domain_of("https://api.example/x"),
            Some("api.example".into())
        );
        assert_eq!(
            domain_of("http://API.Example:8080/x?a=1"),
            Some("api.example:8080".into())
        );
        assert_eq!(domain_of("api.example/x"), Some("api.example".into()));
        assert_eq!(domain_of(""), None);
        assert_eq!(domain_of("https:///x"), None);
    }

    #[test]
    fn a_refusal_carries_its_status_and_a_code_the_agent_can_branch_on() {
        assert_eq!(RefusalKind::Unauthenticated.status(), 401);
        assert_eq!(RefusalKind::NoChallenge.status(), 402);
        assert_eq!(RefusalKind::Denied.status(), 403);
        assert_eq!(RefusalKind::Escalated.status(), 403);
        assert_eq!(RefusalKind::Unavailable.status(), 503);
        assert_eq!(kind_code(RefusalKind::Escalated), "approval_required");
    }
}
