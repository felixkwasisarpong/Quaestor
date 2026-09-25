//! Remembering spent payment authorizations, durably.
//!
//! # Why this crate and not the verifier
//!
//! `quaestor-verify` defines the [`NonceStore`] contract and ships an
//! in-memory implementation for its own tests. It cannot ship this one: the
//! verifier compiles to `wasm32-unknown-unknown` for the browser playground,
//! and a Postgres client does not. So the trait lives with the code that
//! calls it and the durable implementation lives with the other durable
//! state, which is here.
//!
//! # Why one statement
//!
//! The contract says `check_and_record` must be a single test-and-set. The
//! obvious implementation is a `SELECT` followed by an `INSERT`, and it is
//! wrong in the way this whole crate exists to prevent: two presentations of
//! the same authorization both `SELECT` nothing, both `INSERT`, and one of
//! them gets a unique-violation *after* the other has already been told it
//! may proceed. At best that is an error in the wrong place; at worst the
//! violation is swallowed and both are told yes.
//!
//! `INSERT ... ON CONFLICT DO NOTHING` is the whole check. The contending
//! transaction blocks on the index entry, and the answer is the row count:
//! one means this caller created the record, zero means somebody else
//! already had. No value is read and then acted upon, so there is no window
//! between reading and acting.
//!
//! # Why the table can be emptied
//!
//! A nonce record only has to outlive the authorization it belongs to. Past
//! `validBefore` the verifier refuses the payload on the temporal check,
//! which runs before the replay check is ever reached, so the row has
//! stopped protecting anything. [`PgNonceStore::prune`] deletes exactly
//! those rows and nothing else, and `pruning_cannot_reopen_a_replay` in the
//! integration tests is the proof that the payload it forgets is still
//! refused.

use postgres::Client;
use quaestor_verify::eip712::Address;
use quaestor_verify::x402::{Freshness, NonceStore, NonceStoreUnavailable};

/// A durable nonce store.
///
/// Holds its own connection rather than borrowing the ledger's. The replay
/// check runs during verification, before any hold exists and possibly
/// against a payment that is about to be refused for an unrelated reason;
/// entangling it with the transaction that reserves budget would mean a
/// refused payment could roll back the record that its authorization was
/// spent, which is precisely the record that must survive.
pub struct PgNonceStore {
    client: Client,
}

/// Written by hand for the same reason as [`crate::Store`]: a connection can
/// carry credentials, and a type that prints its own connection string into
/// a log line is a credential leak with a stack trace attached.
impl core::fmt::Debug for PgNonceStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PgNonceStore { client: <postgres connection> }")
    }
}

impl PgNonceStore {
    pub fn new(client: Client) -> Self {
        PgNonceStore { client }
    }

    /// Apply the schema. Idempotent, and the same schema the ledger applies,
    /// so it does not matter which of them runs first or whether both do.
    pub fn migrate(&mut self) -> Result<(), postgres::Error> {
        self.client.batch_execute(crate::MIGRATION)
    }

    /// Delete nonces whose authorizations can no longer be accepted.
    ///
    /// Returns how many rows went. Safe because the condition is the same
    /// one the verifier applies earlier and independently: a payload whose
    /// `validBefore` has passed is refused as expired before its nonce is
    /// ever looked up. Forgetting it cannot let it through.
    ///
    /// Strictly `<`, not `<=`. `validBefore` is the last instant the
    /// authorization is live, and an off-by-one here would delete a record
    /// that is still doing its job.
    ///
    /// Not called on a timer by anything in this crate. A store that quietly
    /// deletes rows on its own schedule is a store whose contents depend on
    /// when you look, and this one is meant to be auditable.
    pub fn prune(&mut self, now_secs: u64) -> Result<u64, postgres::Error> {
        let cutoff = clamp_secs(now_secs);
        self.client.execute(
            "DELETE FROM payment_nonces WHERE valid_before_secs < $1",
            &[&cutoff],
        )
    }

    /// How many nonces are on record. For tests and for operators.
    pub fn len(&mut self) -> Result<i64, postgres::Error> {
        let row = self
            .client
            .query_one("SELECT count(*) FROM payment_nonces", &[])?;
        Ok(row.get(0))
    }

    pub fn is_empty(&mut self) -> Result<bool, postgres::Error> {
        Ok(self.len()? == 0)
    }
}

impl NonceStore for PgNonceStore {
    fn check_and_record(
        &mut self,
        payer: &Address,
        nonce: &[u8; 32],
        valid_before_secs: u64,
    ) -> Result<Freshness, NonceStoreUnavailable> {
        let valid_before = clamp_secs(valid_before_secs);
        let inserted = self
            .client
            .execute(
                "INSERT INTO payment_nonces (payer, nonce, valid_before_secs)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (payer, nonce) DO NOTHING",
                &[&payer.as_slice(), &nonce.as_slice(), &valid_before],
            )
            // The error text and not the error, because the trait's error
            // type is deliberately a string: `quaestor-verify` compiles to
            // WebAssembly and must not learn that Postgres exists.
            .map_err(|e| NonceStoreUnavailable(describe(&e)))?;

        Ok(if inserted == 1 {
            Freshness::Fresh
        } else {
            Freshness::Replayed
        })
    }
}

/// Say what actually went wrong.
///
/// `postgres::Error` renders as the string "db error" and keeps everything
/// useful — the message, the SQLSTATE, the constraint that fired — one level
/// down. A refusal whose only explanation is "db error" is a refusal nobody
/// can act on, and the operator reading it at three in the morning is being
/// asked to guess between a missing table and a dead server.
fn describe(e: &postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        return format!("{} [{}]", db.message(), db.code().code());
    }
    match std::error::Error::source(e) {
        Some(source) => format!("{e}: {source}"),
        None => e.to_string(),
    }
}

/// x402 writes `validBefore` as an unsigned 64-bit count of seconds;
/// Postgres `BIGINT` is signed. The overlap covers every instant anyone will
/// ever sign for, and the remainder is saturated rather than rejected.
///
/// Saturating upward is the safe direction on both uses. As a stored expiry
/// it means "never prunable", so an absurd authorization's nonce is kept
/// forever rather than forgotten early. As a prune cutoff it would mean
/// deleting everything, but that value is the current time, and a clock
/// reading past the year 292 277 026 596 is not a case worth a branch.
fn clamp_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_beyond_i64_saturate_rather_than_wrap() {
        assert_eq!(clamp_secs(0), 0);
        assert_eq!(clamp_secs(1_772_000_000), 1_772_000_000);
        // Wrapping here would turn the furthest-future expiry into the
        // most-prunable row in the table.
        assert_eq!(clamp_secs(u64::MAX), i64::MAX);
    }
}
