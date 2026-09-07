-- Budget holds.
--
-- Two tables and one rule: a hold is only ever created while its principal's
-- account row is locked, and every reservation decision is made inside that
-- lock. Everything below follows from that.

-- One row per principal and currency. It holds no balance and is never read
-- for its contents. It exists to be locked.
--
-- Why a row whose only purpose is to be locked: rolling budgets are an
-- aggregate over a time range, and Postgres cannot lock rows that do not
-- exist yet. Under READ COMMITTED, two transactions can both compute "480
-- spent, 500 limit, 20 is fine" and both insert, and the sum is 520. The
-- rows they conflict over are the ones they are each about to write, which
-- is exactly the phantom the isolation level does not protect against.
--
-- SERIALIZABLE would catch it, at the cost of making every caller handle
-- serialization failures and retry. A single row to lock is cheaper to
-- reason about and impossible to get subtly wrong at a call site.
CREATE TABLE IF NOT EXISTS budget_accounts (
    principal    TEXT NOT NULL,
    currency     TEXT NOT NULL,
    PRIMARY KEY (principal, currency)
);

CREATE TYPE hold_state AS ENUM ('held', 'captured', 'released', 'expired');

CREATE TABLE IF NOT EXISTS holds (
    intent_id     TEXT PRIMARY KEY,
    principal     TEXT NOT NULL,
    agent         TEXT NOT NULL,
    payee         TEXT NOT NULL,

    -- Minor units. NUMERIC(39,0) because i128 does not fit in BIGINT and an
    -- amount that silently truncates on the way into the database is the
    -- same class of bug as one that truncates on the wire.
    amount_minor  NUMERIC(39,0) NOT NULL,
    currency      TEXT NOT NULL,

    state         hold_state NOT NULL DEFAULT 'held',

    -- Milliseconds since the Unix epoch, matching quaestor_core::Timestamp.
    -- Not TIMESTAMPTZ: the evaluator is given time as an argument and never
    -- reads a clock, and storing an instant in a type the database can
    -- reinterpret by session timezone would undo that.
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    settled_at_ms BIGINT,

    -- Same key, same decision, replayed. Never re-executed.
    idempotency_key TEXT NOT NULL,

    CONSTRAINT amount_is_positive CHECK (amount_minor > 0),
    CONSTRAINT expiry_after_creation CHECK (expires_at_ms > created_at_ms),
    CONSTRAINT settled_only_when_finished CHECK (
        (state = 'held' AND settled_at_ms IS NULL) OR
        (state <> 'held' AND settled_at_ms IS NOT NULL)
    )
);

-- One hold per idempotency key per principal. The database enforces this
-- rather than the application, because the application is the thing that
-- might be running twice.
CREATE UNIQUE INDEX IF NOT EXISTS holds_idempotency
    ON holds (principal, idempotency_key);

-- The window sum reads live holds for a principal in a time range.
CREATE INDEX IF NOT EXISTS holds_window
    ON holds (principal, currency, created_at_ms)
    WHERE state IN ('held', 'captured');

-- Expiry sweeps look for stale holds.
CREATE INDEX IF NOT EXISTS holds_expiry
    ON holds (expires_at_ms)
    WHERE state = 'held';
