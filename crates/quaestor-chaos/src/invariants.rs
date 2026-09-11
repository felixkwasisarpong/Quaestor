//! What must be true after the process comes back.
//!
//! # An auditor that shares the code under test is not an auditor
//!
//! This module reads the holds table with its own SQL rather than going
//! through `quaestor_ledger::Store` — which it cannot do anyway, because
//! this crate deliberately does not depend on the ledger. If the checker
//! calls the same `sum_window` the reservation path calls, then a wrong
//! window boundary is wrong in both places and the invariant agrees with the
//! bug. Reading the rows independently means the two have to agree about
//! reality rather than about an implementation.
//!
//! The same goes the other way: if this file and the ledger ever disagree,
//! that is a finding, not a flaky test.
//!
//! # The invariants, in order of how much they cost to be wrong about
//!
//! 1. Money without a committed spend. The origin holds an authorization
//!    and the ledger does not know it was spent. Every later budget decision
//!    is made against a figure that is too small, forever.
//! 2. A committed spend with no signed record. The budget is consumed and
//!    nobody can say why. This is the one the receipt chain exists for.
//! 3. An overspent budget. The cap did not hold.
//! 4. A broken or forked receipt chain. The evidence log is not evidence.
//! 5. A hold stuck `held`. Recoverable, but it freezes a budget until
//!    somebody notices, which is usually the following month.

use std::collections::{BTreeMap, BTreeSet};

use quaestor_core::Timestamp;
use quaestor_policy::Budget;
use quaestor_receipt::{verify_chain, Receipt, ReceiptVerdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Invariant {
    NoMoneyWithoutACommittedSpend,
    NoCommittedSpendWithoutARecord,
    BudgetNeverExceeded,
    ReceiptChainIntact,
    NothingStuckHeld,
}

impl Invariant {
    pub fn label(self) -> &'static str {
        match self {
            Invariant::NoMoneyWithoutACommittedSpend => "no money without a committed spend",
            Invariant::NoCommittedSpendWithoutARecord => "no committed spend without a record",
            Invariant::BudgetNeverExceeded => "the budget was never exceeded",
            Invariant::ReceiptChainIntact => "the receipt chain is intact",
            Invariant::NothingStuckHeld => "nothing is stuck held",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub invariant: Invariant,
    pub detail: String,
}

/// Something true but worth saying. Not a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub detail: String,
}

/// One hold, as read from the database and not from the code that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldRow {
    pub intent_id: String,
    pub principal: String,
    pub state: String,
    pub amount_minor: i128,
    pub currency: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl HoldRow {
    /// Live means the money is committed, whether or not it has moved.
    /// `released` and `expired` gave the budget back.
    pub fn is_live(&self) -> bool {
        self.state == "held" || self.state == "captured"
    }
}

/// Everything the harness could see after the restart.
#[derive(Debug, Clone)]
pub struct Observed {
    pub holds: Vec<HoldRow>,
    pub receipts: Vec<Receipt>,
    pub signer_key: [u8; 32],
    /// Intent ids for which the origin actually received a payment header.
    /// Read from the origin's own log, not from anything Quaestor wrote.
    pub origin_was_paid: BTreeSet<String>,
    pub budgets: Vec<Budget>,
    pub now: Timestamp,
}

/// Check everything. Returns what is wrong, and what is merely notable.
pub fn check(o: &Observed) -> (Vec<Violation>, Vec<Finding>) {
    let mut bad = Vec::new();
    let mut notes = Vec::new();

    let by_intent: BTreeMap<&str, &HoldRow> =
        o.holds.iter().map(|h| (h.intent_id.as_str(), h)).collect();

    // ---- 1. money without a committed spend ----------------------------
    //
    // The expensive one. If the origin holds an authorization it can settle
    // and the ledger does not record the spend, the budget is permanently
    // too generous and no later check can notice.
    for intent in &o.origin_was_paid {
        match by_intent.get(intent.as_str()) {
            None => bad.push(Violation {
                invariant: Invariant::NoMoneyWithoutACommittedSpend,
                detail: format!(
                    "the origin was paid for {intent} and the ledger has no hold for it at all"
                ),
            }),
            Some(h) if h.state != "captured" => bad.push(Violation {
                invariant: Invariant::NoMoneyWithoutACommittedSpend,
                detail: format!(
                    "the origin was paid for {intent}, but its hold is `{}`, so the \
                     budget will be handed back for money that moved",
                    h.state
                ),
            }),
            Some(_) => {}
        }
    }

    // ---- 2. a committed spend with no record ---------------------------
    let receipted: BTreeMap<&str, &Receipt> = o
        .receipts
        .iter()
        .map(|r| (r.intent_id.as_str(), r))
        .collect();

    for h in o.holds.iter().filter(|h| h.state == "captured") {
        match receipted.get(h.intent_id.as_str()) {
            None => bad.push(Violation {
                invariant: Invariant::NoCommittedSpendWithoutARecord,
                detail: format!(
                    "hold {} is captured and no receipt accounts for it",
                    h.intent_id
                ),
            }),
            Some(r) if !matches!(r.verdict, ReceiptVerdict::Allow) => bad.push(Violation {
                invariant: Invariant::NoCommittedSpendWithoutARecord,
                detail: format!(
                    "hold {} is captured but its receipt says the payment was refused",
                    h.intent_id
                ),
            }),
            Some(_) => {}
        }
    }

    // A hold with no receipt is fine while it is still `held`: the crash
    // happened between reserving and recording, nothing was spent, and it
    // expires. Worth saying out loud, because it looks alarming in the table.
    for h in o.holds.iter().filter(|h| h.state == "held") {
        if !receipted.contains_key(h.intent_id.as_str()) {
            notes.push(Finding {
                detail: format!(
                    "hold {} is held with no receipt: the crash landed between the \
                     reservation and the record. It expires at {} and the budget returns.",
                    h.intent_id, h.expires_at_ms
                ),
            });
        }
    }

    // ---- 3. the budget ---------------------------------------------------
    //
    // Summed here from the rows, deliberately not by asking the ledger.
    for budget in &o.budgets {
        let Some(since) = o.now.as_millis().checked_sub(budget.window_ms) else {
            continue;
        };
        let mut per_principal: BTreeMap<(&str, &str), i128> = BTreeMap::new();
        for h in o.holds.iter().filter(|h| h.is_live()) {
            if h.created_at_ms <= since {
                continue;
            }
            let slot = per_principal
                .entry((h.principal.as_str(), h.currency.as_str()))
                .or_insert(0);
            *slot = slot.saturating_add(h.amount_minor);
        }
        for ((principal, currency), total) in per_principal {
            if currency != budget.limit.currency().code() {
                continue;
            }
            if total > budget.limit.minor() {
                bad.push(Violation {
                    invariant: Invariant::BudgetNeverExceeded,
                    detail: format!(
                        "{principal} holds {total} {currency} live in the {} window, \
                         against a limit of {}",
                        budget.window_label,
                        budget.limit.minor()
                    ),
                });
            }
        }
    }

    // ---- 4. the chain ----------------------------------------------------
    if o.receipts.is_empty() {
        notes.push(Finding {
            detail: "no receipts were written at all".to_owned(),
        });
    } else {
        if let Err(e) = verify_chain(&o.receipts, &o.signer_key, true) {
            bad.push(Violation {
                invariant: Invariant::ReceiptChainIntact,
                detail: format!("the log does not verify: {e}"),
            });
        }
        // A fork is two receipts claiming the same position. `verify_chain`
        // would notice one of them, but naming it separately is worth doing:
        // this is the specific thing a restart could cause, by resuming from
        // a sequence number that a lost receipt had already used.
        let mut seqs: Vec<u64> = o.receipts.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        let unique = {
            let mut s = seqs.clone();
            s.dedup();
            s.len()
        };
        if unique != seqs.len() {
            bad.push(Violation {
                invariant: Invariant::ReceiptChainIntact,
                detail: "two receipts share a sequence number: the chain forked \
                         across a restart"
                    .to_owned(),
            });
        }
        for (expected, actual) in seqs.iter().enumerate() {
            if u64::try_from(expected).ok() != Some(*actual) {
                bad.push(Violation {
                    invariant: Invariant::ReceiptChainIntact,
                    detail: format!(
                        "sequence numbers are not contiguous: saw {actual} at {expected}"
                    ),
                });
                break;
            }
        }
    }

    // ---- 5. stuck holds --------------------------------------------------
    //
    // Checked after the harness has run a sweep, so this asks whether the
    // sweep works, not whether time has passed.
    for h in o.holds.iter().filter(|h| h.state == "held") {
        if h.expires_at_ms <= o.now.as_millis() {
            bad.push(Violation {
                invariant: Invariant::NothingStuckHeld,
                detail: format!(
                    "hold {} is still `held` with an expiry {}ms in the past; a sweep \
                     has run and did not release it",
                    h.intent_id,
                    o.now.as_millis().saturating_sub(h.expires_at_ms)
                ),
            });
        }
    }

    (bad, notes)
}

/// Read every hold, with this module's own SQL. See the module docs.
#[cfg(feature = "postgres")]
pub fn read_holds(client: &mut postgres::Client) -> Result<Vec<HoldRow>, postgres::Error> {
    let rows = client.query(
        "SELECT intent_id, principal, state::text, amount_minor::text, currency,
                created_at_ms, expires_at_ms
         FROM holds ORDER BY created_at_ms, intent_id",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let minor: String = r.get(3);
            HoldRow {
                intent_id: r.get(0),
                principal: r.get(1),
                state: r.get(2),
                amount_minor: minor.parse().unwrap_or(0),
                currency: r.get(4),
                created_at_ms: r.get(5),
                expires_at_ms: r.get(6),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use quaestor_core::{Currency, DenyReason, Hold, IntentId, Money, Timestamp, Verdict};
    use quaestor_receipt::Signer;

    const NOW: Timestamp = Timestamp(1_772_000_000_000);

    fn usdc(m: i128) -> Money {
        Money::new(m, Currency::USDC)
    }

    fn budgets() -> Vec<Budget> {
        vec![Budget {
            window_ms: 86_400_000,
            window_label: "24h".into(),
            limit: usdc(5_000_000),
        }]
    }

    fn hold(intent: &str, state: &str, minor: i128) -> HoldRow {
        HoldRow {
            intent_id: intent.to_owned(),
            principal: "felix".into(),
            state: state.to_owned(),
            amount_minor: minor,
            currency: "USDC".into(),
            created_at_ms: NOW.0 - 1_000,
            expires_at_ms: NOW.0 + 300_000,
        }
    }

    fn allow() -> Verdict {
        Verdict::Allow {
            hold: Hold {
                intent: IntentId::new("i").expect("valid"),
                amount: usdc(1),
                expires_at: NOW,
            },
        }
    }

    fn deny() -> Verdict {
        Verdict::Deny {
            reasons: vec![DenyReason::PayeeBlocked],
        }
    }

    /// A log of receipts for the given intents, signed for real.
    fn log(entries: &[(&str, Verdict)]) -> (Vec<Receipt>, [u8; 32]) {
        let mut s = Signer::new(SigningKey::from_bytes(&[7u8; 32]));
        let key = s.public_key();
        let rs = entries
            .iter()
            .map(|(id, v)| {
                s.issue(
                    id,
                    "felix",
                    "shopper",
                    "p",
                    usdc(1_000_000),
                    v,
                    [0u8; 32],
                    NOW,
                )
            })
            .collect();
        (rs, key)
    }

    fn observed(holds: Vec<HoldRow>, entries: &[(&str, Verdict)], paid: &[&str]) -> Observed {
        let (receipts, signer_key) = log(entries);
        Observed {
            holds,
            receipts,
            signer_key,
            origin_was_paid: paid.iter().map(|s| (*s).to_owned()).collect(),
            budgets: budgets(),
            now: NOW,
        }
    }

    #[test]
    fn a_clean_run_violates_nothing() {
        let o = observed(
            vec![hold("i1", "captured", 1_000_000)],
            &[("i1", allow())],
            &["i1"],
        );
        let (bad, _) = check(&o);
        assert!(bad.is_empty(), "{bad:?}");
    }

    #[test]
    fn money_the_ledger_does_not_know_about_is_caught() {
        // The origin was paid and the hold never got past `held`. This is
        // the failure the whole capture-before-write ordering exists to
        // prevent, so the checker had better see it.
        let o = observed(
            vec![hold("i1", "held", 1_000_000)],
            &[("i1", allow())],
            &["i1"],
        );
        let (bad, _) = check(&o);
        assert!(bad
            .iter()
            .any(|v| v.invariant == Invariant::NoMoneyWithoutACommittedSpend));
    }

    #[test]
    fn money_with_no_hold_at_all_is_caught() {
        let o = observed(Vec::new(), &[], &["i1"]);
        let (bad, _) = check(&o);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].invariant, Invariant::NoMoneyWithoutACommittedSpend);
    }

    #[test]
    fn a_captured_hold_with_no_receipt_is_caught() {
        let o = observed(vec![hold("i1", "captured", 1_000_000)], &[], &[]);
        let (bad, _) = check(&o);
        assert!(bad
            .iter()
            .any(|v| v.invariant == Invariant::NoCommittedSpendWithoutARecord));
    }

    #[test]
    fn a_captured_hold_whose_receipt_says_denied_is_caught() {
        let o = observed(
            vec![hold("i1", "captured", 1_000_000)],
            &[("i1", deny())],
            &[],
        );
        let (bad, _) = check(&o);
        assert!(bad
            .iter()
            .any(|v| v.invariant == Invariant::NoCommittedSpendWithoutARecord));
    }

    #[test]
    fn a_held_hold_with_no_receipt_is_a_note_not_a_violation() {
        // The reserve.after window. Nothing was spent, so nothing is wrong.
        let o = observed(vec![hold("i1", "held", 1_000_000)], &[], &[]);
        let (bad, notes) = check(&o);
        assert!(bad.is_empty(), "{bad:?}");
        assert!(notes
            .iter()
            .any(|n| n.detail.contains("held with no receipt")));
    }

    #[test]
    fn an_overspent_budget_is_caught() {
        let o = observed(
            vec![
                hold("i1", "captured", 3_000_000),
                hold("i2", "held", 3_000_000),
            ],
            &[("i1", allow()), ("i2", allow())],
            &[],
        );
        let (bad, _) = check(&o);
        assert!(bad
            .iter()
            .any(|v| v.invariant == Invariant::BudgetNeverExceeded));
    }

    #[test]
    fn released_and_expired_holds_do_not_count_against_the_budget() {
        let o = observed(
            vec![
                hold("i1", "released", 5_000_000),
                hold("i2", "expired", 5_000_000),
                hold("i3", "captured", 5_000_000),
            ],
            &[("i3", allow())],
            &[],
        );
        let (bad, _) = check(&o);
        assert!(
            !bad.iter()
                .any(|v| v.invariant == Invariant::BudgetNeverExceeded),
            "{bad:?}"
        );
    }

    #[test]
    fn a_forked_chain_is_caught() {
        // Two receipts at the same position: what a restart would produce if
        // it resumed from a sequence number a lost receipt had used.
        let (mut receipts, key) = log(&[("i1", allow()), ("i2", allow())]);
        let (other, _) = log(&[("i3", allow())]);
        receipts.extend(other); // seq 0 again
        let o = Observed {
            holds: Vec::new(),
            receipts,
            signer_key: key,
            origin_was_paid: BTreeSet::new(),
            budgets: budgets(),
            now: NOW,
        };
        let (bad, _) = check(&o);
        assert!(bad
            .iter()
            .any(|v| v.detail.contains("forked across a restart")));
    }

    #[test]
    fn a_hold_stuck_past_its_expiry_is_caught() {
        let mut h = hold("i1", "held", 1_000_000);
        h.expires_at_ms = NOW.0 - 1;
        let o = observed(vec![h], &[("i1", allow())], &[]);
        let (bad, _) = check(&o);
        assert!(bad
            .iter()
            .any(|v| v.invariant == Invariant::NothingStuckHeld));
    }
}
