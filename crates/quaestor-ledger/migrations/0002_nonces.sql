-- Spent payment authorizations.
--
-- An x402 authorization is a bearer instrument: anyone holding the signed
-- payload can present it. The only thing standing between one authorization
-- and two payments is a record that it has already been used, and a record
-- kept in a process is a record that a restart deletes.
--
-- The primary key is the whole mechanism. `INSERT ... ON CONFLICT DO
-- NOTHING` against it is a single atomic test-and-set, which is what the
-- `NonceStore` contract requires: two concurrent presentations of the same
-- authorization contend on the index, one inserts, the other reports zero
-- rows, and nobody reads a value they then act on.
CREATE TABLE IF NOT EXISTS payment_nonces (
    -- Raw 20-byte EVM address, not its hex rendering. Two spellings of one
    -- address that compare unequal would be two nonce namespaces, and the
    -- second one is free to replay everything spent in the first.
    payer      BYTEA NOT NULL,
    nonce      BYTEA NOT NULL,

    -- Milliseconds since the Unix epoch, as everywhere else in this schema.
    --
    -- Defaulted by the database rather than supplied by the application, so
    -- that inserting a nonce needs no clock on the Rust side. Nothing reads
    -- this column to make a decision; it exists so an operator staring at a
    -- replay can say when the original went through.
    seen_at_ms BIGINT NOT NULL
        DEFAULT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT,

    -- Seconds, because that is the unit x402 puts `validBefore` in, and
    -- converting it here would mean converting it back to compare.
    --
    -- This column is what makes the table finite. See `prune` in
    -- `nonces.rs`: after this instant the authorization is refused by the
    -- expiry check before the replay check is ever reached, so the row has
    -- stopped carrying information and can be deleted.
    valid_before_secs BIGINT NOT NULL,

    PRIMARY KEY (payer, nonce),

    -- Length is not decoration. A 19-byte payer is a different key from the
    -- 20-byte one it was truncated from, and the database is the last place
    -- that can still notice.
    CONSTRAINT payer_is_an_address CHECK (octet_length(payer) = 20),
    CONSTRAINT nonce_is_32_bytes   CHECK (octet_length(nonce) = 32)
);

-- Pruning scans by expiry.
CREATE INDEX IF NOT EXISTS payment_nonces_expiry
    ON payment_nonces (valid_before_secs);
