//! The ledger, behind a trait.
//!
//! [`quaestor_ledger::Store`] is the real implementation and the only one
//! that should ever be in front of money: its correctness argument is a row
//! lock in Postgres and it is verified under forty-way contention.
//!
//! The trait exists so the gateway's own tests can run without a database.
//! That is a real risk and worth naming: a test double is a place to
//! accidentally test a fiction. [`InMemoryHolds`] therefore implements the
//! same *rules* — the same window arithmetic, the same expiry sweep, the
//! same idempotency check, the same refusal shape — and differs only in
//! having no concurrency to be safe under. Gateway tests use it to ask
//! whether the gateway does the right thing with a refusal. Whether the
//! refusal is correct under contention is asked of Postgres, in
//! `quaestor-ledger`, where it belongs.

use quaestor_core::{Money, Timestamp};
use quaestor_ledger::{HoldRecord, HoldState, LedgerError, Reservation};
use quaestor_policy::Budget;

#[derive(Debug, thiserror::Error)]
pub enum HoldsError {
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("no hold with intent id {0}")]
    NoSuchHold(String),
    #[error("hold {intent} is {state:?} and cannot be {action}")]
    WrongState {
        intent: String,
        state: HoldState,
        action: &'static str,
    },
    #[error("amount is out of range")]
    OutOfRange,
    #[error("currency mismatch: {0}")]
    Currency(quaestor_core::MoneyError),
}

/// Everything a reservation needs.
///
/// A struct rather than nine positional arguments, for the same reason
/// [`quaestor_policy::Request`] is one: at a money boundary, an argument
/// somebody passes in the wrong order is a payment charged to the wrong
/// person, and the compiler cannot tell two `&str`s apart.
#[derive(Debug, Clone)]
pub struct ReserveRequest<'a> {
    pub principal: &'a str,
    pub agent: &'a str,
    pub payee: &'a str,
    pub intent_id: &'a str,
    pub idempotency_key: &'a str,
    pub amount: Money,
    pub budgets: &'a [Budget],
    pub now: Timestamp,
    pub hold_ttl_ms: i64,
}

pub trait Holds: core::fmt::Debug + Send {
    fn reserve(&mut self, req: &ReserveRequest<'_>) -> Result<Reservation, HoldsError>;
    fn capture(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, HoldsError>;
    fn release(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, HoldsError>;
    fn spent_in_window(
        &mut self,
        principal: &str,
        currency: &str,
        window_ms: i64,
        now: Timestamp,
    ) -> Result<i128, HoldsError>;
}

// ---------------------------------------------------------------------------

/// The real one.
#[derive(Debug)]
pub struct PostgresHolds {
    store: quaestor_ledger::Store,
}

impl PostgresHolds {
    pub fn new(store: quaestor_ledger::Store) -> PostgresHolds {
        PostgresHolds { store }
    }

    pub fn store_mut(&mut self) -> &mut quaestor_ledger::Store {
        &mut self.store
    }
}

impl Holds for PostgresHolds {
    fn reserve(&mut self, req: &ReserveRequest<'_>) -> Result<Reservation, HoldsError> {
        Ok(self.store.reserve(
            req.principal,
            req.agent,
            req.payee,
            req.intent_id,
            req.idempotency_key,
            req.amount,
            req.budgets,
            req.now,
            req.hold_ttl_ms,
        )?)
    }

    fn capture(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, HoldsError> {
        Ok(self.store.capture(intent_id, now)?)
    }

    fn release(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, HoldsError> {
        Ok(self.store.release(intent_id, now)?)
    }

    fn spent_in_window(
        &mut self,
        principal: &str,
        currency: &str,
        window_ms: i64,
        now: Timestamp,
    ) -> Result<i128, HoldsError> {
        Ok(self
            .store
            .spent_in_window(principal, currency, window_ms, now)?)
    }
}

// ---------------------------------------------------------------------------

/// Same rules, no database, no concurrency.
///
/// For gateway tests only. Constructing one where money moves would be a
/// budget that forgets everything on restart.
#[derive(Debug, Default)]
pub struct InMemoryHolds {
    rows: Vec<HoldRecord>,
}

impl InMemoryHolds {
    pub fn new() -> InMemoryHolds {
        InMemoryHolds::default()
    }

    pub fn rows(&self) -> &[HoldRecord] {
        &self.rows
    }

    /// Live spend in a window: `held` because the money is committed even
    /// though it has not moved, `captured` because it has. Mirrors the SQL
    /// in `quaestor-ledger`; if the two ever disagree, that one is right.
    fn sum_window(&self, principal: &str, currency: &str, since: i64) -> i128 {
        self.rows
            .iter()
            .filter(|r| r.principal == principal)
            .filter(|r| r.amount.currency().code() == currency)
            .filter(|r| matches!(r.state, HoldState::Held | HoldState::Captured))
            .filter(|r| r.created_at.as_millis() > since)
            .fold(0_i128, |acc, r| acc.saturating_add(r.amount.minor()))
    }

    fn expire_stale(&mut self, principal: &str, now: Timestamp) {
        for r in self.rows.iter_mut() {
            if r.principal == principal
                && r.state == HoldState::Held
                && r.expires_at.as_millis() <= now.as_millis()
            {
                r.state = HoldState::Expired;
            }
        }
    }

    fn transition(
        &mut self,
        intent_id: &str,
        to: HoldState,
        action: &'static str,
        _now: Timestamp,
    ) -> Result<HoldRecord, HoldsError> {
        let Some(row) = self.rows.iter_mut().find(|r| r.intent_id == intent_id) else {
            return Err(HoldsError::NoSuchHold(intent_id.to_owned()));
        };
        if row.state != HoldState::Held {
            return Err(HoldsError::WrongState {
                intent: intent_id.to_owned(),
                state: row.state,
                action,
            });
        }
        row.state = to;
        Ok(row.clone())
    }
}

impl Holds for InMemoryHolds {
    fn reserve(&mut self, req: &ReserveRequest<'_>) -> Result<Reservation, HoldsError> {
        let currency = req.amount.currency().code().to_owned();

        if let Some(existing) = self
            .rows
            .iter()
            .find(|r| r.principal == req.principal && r.intent_id == req.intent_id)
        {
            return Ok(Reservation::AlreadySettled(existing.clone()));
        }

        self.expire_stale(req.principal, req.now);

        for budget in req.budgets {
            let since = req
                .now
                .as_millis()
                .checked_sub(budget.window_ms)
                .ok_or(HoldsError::OutOfRange)?;
            let held = Money::new(
                self.sum_window(req.principal, &currency, since),
                req.amount.currency(),
            );
            let after = held
                .checked_add(&req.amount)
                .map_err(HoldsError::Currency)?;
            if after.try_cmp(&budget.limit).map_err(HoldsError::Currency)?
                == core::cmp::Ordering::Greater
            {
                return Ok(Reservation::Refused {
                    window_label: budget.window_label.clone(),
                    limit: budget.limit,
                    already_held: held,
                    attempted: req.amount,
                });
            }
        }

        let record = HoldRecord {
            intent_id: req.intent_id.to_owned(),
            principal: req.principal.to_owned(),
            agent: req.agent.to_owned(),
            payee: req.payee.to_owned(),
            amount: req.amount,
            state: HoldState::Held,
            created_at: req.now,
            expires_at: Timestamp(
                req.now
                    .as_millis()
                    .checked_add(req.hold_ttl_ms)
                    .ok_or(HoldsError::OutOfRange)?,
            ),
        };
        self.rows.push(record.clone());
        Ok(Reservation::Reserved(record))
    }

    fn capture(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, HoldsError> {
        self.transition(intent_id, HoldState::Captured, "captured", now)
    }

    fn release(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, HoldsError> {
        self.transition(intent_id, HoldState::Released, "released", now)
    }

    fn spent_in_window(
        &mut self,
        principal: &str,
        currency: &str,
        window_ms: i64,
        now: Timestamp,
    ) -> Result<i128, HoldsError> {
        let since = now
            .as_millis()
            .checked_sub(window_ms)
            .ok_or(HoldsError::OutOfRange)?;
        Ok(self.sum_window(principal, currency, since))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quaestor_core::Currency;

    const NOW: Timestamp = Timestamp(1_772_000_000_000);

    fn budgets() -> Vec<Budget> {
        vec![Budget {
            window_ms: 86_400_000,
            window_label: "24h".into(),
            limit: Money::new(10_000, Currency::USD),
        }]
    }

    fn req<'a>(id: &'a str, minor: i128, budgets: &'a [Budget]) -> ReserveRequest<'a> {
        ReserveRequest {
            principal: "felix",
            agent: "shopper",
            payee: "shop.example",
            intent_id: id,
            idempotency_key: id,
            amount: Money::new(minor, Currency::USD),
            budgets,
            now: NOW,
            hold_ttl_ms: 300_000,
        }
    }

    #[test]
    fn the_double_refuses_at_the_same_point_the_real_one_does() {
        let b = budgets();
        let mut h = InMemoryHolds::new();
        assert!(matches!(
            h.reserve(&req("i1", 6_000, &b)),
            Ok(Reservation::Reserved(_))
        ));
        assert!(matches!(
            h.reserve(&req("i2", 4_000, &b)),
            Ok(Reservation::Reserved(_))
        ));
        assert!(
            matches!(
                h.reserve(&req("i3", 1, &b)),
                Ok(Reservation::Refused { .. })
            ),
            "one minor unit over the cap is over the cap"
        );
    }

    #[test]
    fn a_released_hold_gives_the_budget_back() {
        let b = budgets();
        let mut h = InMemoryHolds::new();
        h.reserve(&req("i1", 10_000, &b)).expect("reserved");
        assert!(matches!(
            h.reserve(&req("i2", 1, &b)),
            Ok(Reservation::Refused { .. })
        ));
        h.release("i1", NOW).expect("released");
        assert!(matches!(
            h.reserve(&req("i2", 1, &b)),
            Ok(Reservation::Reserved(_))
        ));
    }

    #[test]
    fn a_captured_hold_does_not() {
        let b = budgets();
        let mut h = InMemoryHolds::new();
        h.reserve(&req("i1", 10_000, &b)).expect("reserved");
        h.capture("i1", NOW).expect("captured");
        assert!(matches!(
            h.reserve(&req("i2", 1, &b)),
            Ok(Reservation::Refused { .. })
        ));
    }

    #[test]
    fn a_hold_can_only_be_settled_once() {
        let b = budgets();
        let mut h = InMemoryHolds::new();
        h.reserve(&req("i1", 100, &b)).expect("reserved");
        h.capture("i1", NOW).expect("first capture");
        assert!(matches!(
            h.capture("i1", NOW),
            Err(HoldsError::WrongState { .. })
        ));
        assert!(matches!(
            h.release("i1", NOW),
            Err(HoldsError::WrongState { .. })
        ));
    }

    #[test]
    fn an_abandoned_hold_stops_occupying_the_budget_once_it_expires() {
        let b = budgets();
        let mut h = InMemoryHolds::new();
        h.reserve(&req("i1", 10_000, &b)).expect("reserved");

        let later = Timestamp(NOW.0 + 300_001);
        let mut r = req("i2", 10_000, &b);
        r.now = later;
        assert!(matches!(h.reserve(&r), Ok(Reservation::Reserved(_))));
    }

    #[test]
    fn replaying_an_intent_returns_the_original_decision() {
        let b = budgets();
        let mut h = InMemoryHolds::new();
        h.reserve(&req("i1", 100, &b)).expect("reserved");
        assert!(matches!(
            h.reserve(&req("i1", 100, &b)),
            Ok(Reservation::AlreadySettled(_))
        ));
        assert_eq!(h.rows().len(), 1, "no second row");
    }
}
