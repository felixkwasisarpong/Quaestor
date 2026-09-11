//! Reserving, capturing and releasing budget holds.

use postgres::{Client, Transaction};
use quaestor_core::{Money, Timestamp};
use quaestor_policy::rules::Budget;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("database error: {0}")]
    Db(#[from] postgres::Error),
    #[error("amount must be positive, got {0}")]
    NonPositiveAmount(Money),
    #[error("currency mismatch: {0}")]
    Currency(quaestor_core::MoneyError),
    #[error("amount is out of range for storage")]
    OutOfRange,
    #[error("no hold with intent id {0}")]
    NoSuchHold(String),
    #[error("hold {intent} is {state:?} and cannot be {action}")]
    WrongState {
        intent: String,
        state: HoldState,
        action: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    Held,
    Captured,
    Released,
    Expired,
}

impl HoldState {
    fn as_str(self) -> &'static str {
        match self {
            HoldState::Held => "held",
            HoldState::Captured => "captured",
            HoldState::Released => "released",
            HoldState::Expired => "expired",
        }
    }

    fn parse(s: &str) -> Option<HoldState> {
        match s {
            "held" => Some(HoldState::Held),
            "captured" => Some(HoldState::Captured),
            "released" => Some(HoldState::Released),
            "expired" => Some(HoldState::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldRecord {
    pub intent_id: String,
    pub principal: String,
    pub agent: String,
    pub payee: String,
    pub amount: Money,
    pub state: HoldState,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
}

/// What a reservation attempt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reservation {
    /// The amount is reserved. Nothing else can spend it until this hold is
    /// captured, released or expires.
    Reserved(HoldRecord),
    /// A budget would have been breached. Carries the window that bit and
    /// what was actually left, so the caller can say something useful.
    Refused {
        window_label: String,
        limit: Money,
        already_held: Money,
        attempted: Money,
    },
    /// This idempotency key has been seen. The original decision is returned
    /// unchanged, and nothing new was reserved.
    AlreadySettled(HoldRecord),
}

/// A handle on the holds tables.
///
/// `Debug` is written by hand rather than derived: the connection can carry
/// credentials, and a store that prints its own connection string into a log
/// line is a credential leak with a stack trace attached.
pub struct Store {
    client: Client,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store { client: <postgres connection> }")
    }
}

impl Store {
    pub fn new(client: Client) -> Self {
        Store { client }
    }

    pub fn migrate(&mut self) -> Result<(), LedgerError> {
        self.client.batch_execute(crate::MIGRATION)?;
        Ok(())
    }

    pub fn client(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Reserve `amount` against every budget, or refuse.
    ///
    /// The whole operation runs inside one transaction that begins by taking
    /// the principal's account row. Reading the windows, deciding, and
    /// writing the hold are one indivisible step; a concurrent caller waits
    /// at the lock and then reads a world that already includes this hold.
    ///
    /// # Arguments
    ///
    /// `now` is passed in rather than read, for the same reason it is passed
    /// to the policy evaluator: a decision has to be replayable.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        principal: &str,
        agent: &str,
        payee: &str,
        intent_id: &str,
        idempotency_key: &str,
        amount: Money,
        budgets: &[Budget],
        now: Timestamp,
        hold_ttl_ms: i64,
    ) -> Result<Reservation, LedgerError> {
        if amount.minor() <= 0 {
            return Err(LedgerError::NonPositiveAmount(amount));
        }
        let currency = amount.currency().code().to_owned();

        let mut tx = self.client.transaction()?;

        // 1. Make sure the account row exists, then take it. `ON CONFLICT DO
        //    NOTHING` followed by a locking select rather than a single
        //    upsert, because an upsert that does nothing does not return a
        //    row to lock.
        tx.execute(
            "INSERT INTO budget_accounts (principal, currency) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            &[&principal, &currency],
        )?;
        tx.execute(
            // FOR UPDATE is the entire correctness argument of this crate.
            // Remove it and the concurrency tests overspend a 30-unit budget
            // by 4 to 8 units per run. Verified, not assumed.
            "SELECT 1 FROM budget_accounts
             WHERE principal = $1 AND currency = $2 FOR UPDATE",
            &[&principal, &currency],
        )?;

        // From here to COMMIT, this principal's budgets belong to us.

        // 2. Idempotency. Checked inside the lock so two concurrent replays
        //    of the same key cannot both find nothing and both insert.
        if let Some(existing) = fetch_by_key(&mut tx, principal, idempotency_key)? {
            tx.commit()?;
            return Ok(Reservation::AlreadySettled(existing));
        }

        // 3. Expire anything stale before summing, so a crashed agent's
        //    abandoned hold does not keep occupying a budget it will never
        //    use.
        tx.execute(
            "UPDATE holds SET state = 'expired', settled_at_ms = $1
             WHERE state = 'held' AND expires_at_ms <= $1 AND principal = $2",
            &[&now.as_millis(), &principal],
        )?;

        // 4. Check every window against what is live right now.
        for budget in budgets {
            let since = now
                .as_millis()
                .checked_sub(budget.window_ms)
                .ok_or(LedgerError::OutOfRange)?;

            let held = sum_window(&mut tx, principal, &currency, since)?;
            let held = Money::new(held, amount.currency());

            let after = held.checked_add(&amount).map_err(LedgerError::Currency)?;
            if after
                .try_cmp(&budget.limit)
                .map_err(LedgerError::Currency)?
                == std::cmp::Ordering::Greater
            {
                // Refusals roll back. A refused attempt must leave no trace
                // that could affect the next one: no hold, and no expiry
                // sweep that a later caller would have to reproduce.
                tx.rollback()?;
                return Ok(Reservation::Refused {
                    window_label: budget.window_label.clone(),
                    limit: budget.limit,
                    already_held: held,
                    attempted: amount,
                });
            }
        }

        // The account row is locked, every window has been checked, and
        // nothing has been written. A crash here must leave no trace: the
        // transaction is open and uncommitted, so Postgres rolls it back
        // when the connection dies. If a partial hold ever survives this,
        // the reservation is not one transaction and this crate's whole
        // correctness argument is wrong.
        crate::chaos::at("ledger.mid_transaction");

        // 5. Every window is satisfied. Write the hold.
        let expires_at = now
            .as_millis()
            .checked_add(hold_ttl_ms)
            .ok_or(LedgerError::OutOfRange)?;

        tx.execute(
            "INSERT INTO holds
               (intent_id, principal, agent, payee, amount_minor, currency,
                state, created_at_ms, expires_at_ms, idempotency_key)
             VALUES ($1,$2,$3,$4,$5::text::numeric,$6,'held',$7,$8,$9)",
            &[
                &intent_id,
                &principal,
                &agent,
                &payee,
                &amount.minor().to_string(),
                &currency,
                &now.as_millis(),
                &expires_at,
                &idempotency_key,
            ],
        )?;

        tx.commit()?;

        Ok(Reservation::Reserved(HoldRecord {
            intent_id: intent_id.to_owned(),
            principal: principal.to_owned(),
            agent: agent.to_owned(),
            payee: payee.to_owned(),
            amount,
            state: HoldState::Held,
            created_at: now,
            expires_at: Timestamp(expires_at),
        }))
    }

    /// The payment settled. The held amount becomes spent.
    pub fn capture(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, LedgerError> {
        self.transition(intent_id, HoldState::Captured, "captured", now)
    }

    /// The payment did not happen. Give the budget back.
    pub fn release(&mut self, intent_id: &str, now: Timestamp) -> Result<HoldRecord, LedgerError> {
        self.transition(intent_id, HoldState::Released, "released", now)
    }

    fn transition(
        &mut self,
        intent_id: &str,
        to: HoldState,
        action: &'static str,
        now: Timestamp,
    ) -> Result<HoldRecord, LedgerError> {
        let mut tx = self.client.transaction()?;

        // Lock the hold itself. Two concurrent captures of the same intent
        // must not both succeed, or the same money is counted twice.
        let row = tx.query_opt(
            // `state::text`: the column is a Postgres enum, which has no
            // direct mapping to String. Casting at the query is clearer than
            // teaching the client library about the type.
            "SELECT state::text FROM holds WHERE intent_id = $1 FOR UPDATE",
            &[&intent_id],
        )?;
        let Some(row) = row else {
            tx.rollback()?;
            return Err(LedgerError::NoSuchHold(intent_id.to_owned()));
        };
        let state: String = row.get(0);
        let state = HoldState::parse(&state).unwrap_or(HoldState::Expired);
        if state != HoldState::Held {
            tx.rollback()?;
            return Err(LedgerError::WrongState {
                intent: intent_id.to_owned(),
                state,
                action,
            });
        }

        tx.execute(
            // `$1::text::hold_state`, not `$1::hold_state`: the latter makes
            // the driver infer the parameter as the enum type and refuse a
            // &str. Going via text binds a string and lets Postgres convert.
            "UPDATE holds SET state = $1::text::hold_state, settled_at_ms = $2
             WHERE intent_id = $3",
            &[&to.as_str(), &now.as_millis(), &intent_id],
        )?;
        let record = fetch_by_intent(&mut tx, intent_id)?
            .ok_or_else(|| LedgerError::NoSuchHold(intent_id.to_owned()))?;
        tx.commit()?;
        Ok(record)
    }

    /// Sweep expired holds. Safe to run from anywhere, any number of times.
    pub fn expire_stale(&mut self, now: Timestamp) -> Result<u64, LedgerError> {
        Ok(self.client.execute(
            "UPDATE holds SET state = 'expired', settled_at_ms = $1
             WHERE state = 'held' AND expires_at_ms <= $1",
            &[&now.as_millis()],
        )?)
    }

    pub fn get(&mut self, intent_id: &str) -> Result<Option<HoldRecord>, LedgerError> {
        let mut tx = self.client.transaction()?;
        let r = fetch_by_intent(&mut tx, intent_id)?;
        tx.commit()?;
        Ok(r)
    }

    /// Total live spend in a window. For building a
    /// [`quaestor_policy::SpendSnapshot`].
    pub fn spent_in_window(
        &mut self,
        principal: &str,
        currency: &str,
        window_ms: i64,
        now: Timestamp,
    ) -> Result<i128, LedgerError> {
        let since = now
            .as_millis()
            .checked_sub(window_ms)
            .ok_or(LedgerError::OutOfRange)?;
        let mut tx = self.client.transaction()?;
        let total = sum_window(&mut tx, principal, currency, since)?;
        tx.commit()?;
        Ok(total)
    }
}

/// Live holds only: `held` because the money is committed even though it has
/// not moved, `captured` because it has. `released` and `expired` gave the
/// budget back and must not count.
fn sum_window(
    tx: &mut Transaction<'_>,
    principal: &str,
    currency: &str,
    since_ms: i64,
) -> Result<i128, LedgerError> {
    let row = tx.query_one(
        "SELECT COALESCE(SUM(amount_minor), 0)::text
         FROM holds
         WHERE principal = $1 AND currency = $2
           AND created_at_ms > $3
           AND state IN ('held', 'captured')",
        &[&principal, &currency, &since_ms],
    )?;
    let total: String = row.get(0);
    total.parse::<i128>().map_err(|_| LedgerError::OutOfRange)
}

fn fetch_by_key(
    tx: &mut Transaction<'_>,
    principal: &str,
    key: &str,
) -> Result<Option<HoldRecord>, LedgerError> {
    let row = tx.query_opt(
        "SELECT intent_id, principal, agent, payee, amount_minor::text, currency,
                state::text, created_at_ms, expires_at_ms
         FROM holds WHERE principal = $1 AND idempotency_key = $2",
        &[&principal, &key],
    )?;
    row.map(row_to_record).transpose()
}

fn fetch_by_intent(
    tx: &mut Transaction<'_>,
    intent_id: &str,
) -> Result<Option<HoldRecord>, LedgerError> {
    let row = tx.query_opt(
        "SELECT intent_id, principal, agent, payee, amount_minor::text, currency,
                state::text, created_at_ms, expires_at_ms
         FROM holds WHERE intent_id = $1",
        &[&intent_id],
    )?;
    row.map(row_to_record).transpose()
}

fn row_to_record(row: postgres::Row) -> Result<HoldRecord, LedgerError> {
    let minor: String = row.get(4);
    let minor: i128 = minor.parse().map_err(|_| LedgerError::OutOfRange)?;
    let code: String = row.get(5);
    let currency = quaestor_core::Currency::new(&code, currency_exponent(&code))
        .map_err(|_| LedgerError::OutOfRange)?;
    let state: String = row.get(6);

    Ok(HoldRecord {
        intent_id: row.get(0),
        principal: row.get(1),
        agent: row.get(2),
        payee: row.get(3),
        amount: Money::new(minor, currency),
        state: HoldState::parse(&state).unwrap_or(HoldState::Expired),
        created_at: Timestamp(row.get(7)),
        expires_at: Timestamp(row.get(8)),
    })
}

/// Decimals for a stored currency code.
///
/// A stopgap: the schema records the code but not the exponent, which is a
/// gap, because the exponent is part of a currency's identity everywhere
/// else in this system. Recorded in BUGS.md rather than papered over.
fn currency_exponent(code: &str) -> u8 {
    match code {
        "JPY" => 0,
        "USDC" | "USDT" => 6,
        _ => 2,
    }
}
