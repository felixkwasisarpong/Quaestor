//! The replay guard, against a real database.
//!
//! The claim being tested is one sentence: an x402 authorization can be
//! spent once, and stays spent across a restart. Everything here is an
//! attempt to break that sentence.
//!
//! Set `QUAESTOR_TEST_PG` to a connection string to run them. Without it
//! they skip rather than fail, because a green suite that quietly proved
//! nothing is worse than a red one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use postgres::{Client, NoTls};
use quaestor_ledger::PgNonceStore;
use quaestor_verify::x402::{Freshness, NonceStore};

/// Comfortably in the future, in seconds, so nothing here is prunable by
/// accident.
const LIVE: u64 = 4_000_000_000;

fn conn_string() -> Option<String> {
    std::env::var("QUAESTOR_TEST_PG").ok()
}

/// A fresh schema per test, in its own namespace, so tests can run in
/// parallel against one database without seeing each other.
fn connect(schema: &str, first: bool) -> PgNonceStore {
    let cs = conn_string().expect("checked by caller");
    let mut client = Client::connect(&cs, NoTls).expect("connect");
    if first {
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .expect("schema");
    }
    client
        .batch_execute(&format!("SET search_path TO {schema};"))
        .expect("search_path");
    let mut store = PgNonceStore::new(client);
    if first {
        store.migrate().expect("migrate");
    }
    store
}

fn payer(tag: u8) -> [u8; 20] {
    [tag; 20]
}

fn nonce(tag: u8) -> [u8; 32] {
    [tag; 32]
}

macro_rules! needs_pg {
    ($name:expr) => {
        if conn_string().is_none() {
            println!("skipping {}: QUAESTOR_TEST_PG is not set", $name);
            return;
        }
    };
}

#[test]
fn a_nonce_is_fresh_once_and_never_again() {
    needs_pg!("a_nonce_is_fresh_once_and_never_again");
    let mut s = connect("nonce_once", true);

    assert_eq!(
        s.check_and_record(&payer(1), &nonce(1), LIVE).unwrap(),
        Freshness::Fresh
    );
    for _ in 0..5 {
        assert_eq!(
            s.check_and_record(&payer(1), &nonce(1), LIVE).unwrap(),
            Freshness::Replayed,
            "an authorization is spent once, however many times it is presented"
        );
    }
    assert_eq!(s.len().unwrap(), 1, "a replay must not add a row");
}

#[test]
fn the_key_is_the_pair_not_either_half() {
    needs_pg!("the_key_is_the_pair_not_either_half");
    let mut s = connect("nonce_pair", true);

    assert_eq!(
        s.check_and_record(&payer(1), &nonce(1), LIVE).unwrap(),
        Freshness::Fresh
    );
    // A nonce is only unique per signer. Two payers picking the same 32
    // bytes is not a collision, and treating it as one would let anybody
    // lock a stranger out of their own nonce space by spending it first.
    assert_eq!(
        s.check_and_record(&payer(2), &nonce(1), LIVE).unwrap(),
        Freshness::Fresh
    );
    assert_eq!(
        s.check_and_record(&payer(1), &nonce(2), LIVE).unwrap(),
        Freshness::Fresh
    );
    assert_eq!(s.len().unwrap(), 3);
}

/// The reason this file exists.
#[test]
fn a_restart_does_not_forget() {
    needs_pg!("a_restart_does_not_forget");
    let mut s = connect("nonce_restart", true);
    assert_eq!(
        s.check_and_record(&payer(7), &nonce(7), LIVE).unwrap(),
        Freshness::Fresh
    );

    // Everything the process was holding goes away: the store, its
    // connection, its memory. This is what a crash looks like from the
    // database's side.
    drop(s);

    let mut after = connect("nonce_restart", false);
    assert_eq!(
        after.check_and_record(&payer(7), &nonce(7), LIVE).unwrap(),
        Freshness::Replayed,
        "the authorization was spent before the restart and is still spent after it"
    );
}

/// Two presentations of one authorization, arriving together.
///
/// Sixteen threads and a barrier, because the failure this guards against is
/// invisible at low contention: a read-then-write implementation passes this
/// test perfectly well when the two halves never interleave.
#[test]
fn concurrent_presentations_of_one_authorization_yield_exactly_one_fresh() {
    needs_pg!("concurrent_presentations_of_one_authorization_yield_exactly_one_fresh");
    let _setup = connect("nonce_race", true);

    const THREADS: usize = 16;
    let barrier = Arc::new(Barrier::new(THREADS));
    let fresh = Arc::new(AtomicUsize::new(0));
    let replayed = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let barrier = Arc::clone(&barrier);
        let fresh = Arc::clone(&fresh);
        let replayed = Arc::clone(&replayed);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            let mut s = connect("nonce_race", false);
            barrier.wait();
            match s.check_and_record(&payer(9), &nonce(9), LIVE) {
                Ok(Freshness::Fresh) => fresh.fetch_add(1, Ordering::SeqCst),
                Ok(Freshness::Replayed) => replayed.fetch_add(1, Ordering::SeqCst),
                Err(_) => errors.fetch_add(1, Ordering::SeqCst),
            };
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }

    assert_eq!(
        errors.load(Ordering::SeqCst),
        0,
        "losing the race is a normal outcome, not an error"
    );
    assert_eq!(
        fresh.load(Ordering::SeqCst),
        1,
        "exactly one presentation may be told it is the first"
    );
    assert_eq!(replayed.load(Ordering::SeqCst), THREADS - 1);
}

/// Pruning is the only thing in this crate that deletes a replay record, so
/// its boundary is the boundary of the guarantee.
///
/// The safety argument has two halves and this is the second one. The first
/// half lives in `quaestor-verify`
/// (`an_expired_payload_never_reaches_the_nonce_store`): the temporal check
/// refuses an authorization past `validBefore` before the replay check is
/// reached. Given that, forgetting a nonce at exactly that instant cannot
/// let anything through — and this test pins "exactly that instant".
#[test]
fn pruning_forgets_the_unusable_and_nothing_else() {
    needs_pg!("pruning_forgets_the_unusable_and_nothing_else");
    let mut s = connect("nonce_prune", true);
    let now = 1_772_000_000_u64;

    // One second dead, alive to the last second, and alive by a second.
    s.check_and_record(&payer(1), &nonce(1), now - 1).unwrap();
    s.check_and_record(&payer(2), &nonce(2), now).unwrap();
    s.check_and_record(&payer(3), &nonce(3), now + 1).unwrap();
    assert_eq!(s.len().unwrap(), 3);

    assert_eq!(s.prune(now).unwrap(), 1, "only the dead one goes");
    assert_eq!(s.len().unwrap(), 2);

    // `validBefore` is the last instant the authorization is live, so the
    // row at exactly `now` is still doing its job. An off-by-one here is a
    // one-second replay window, which is several orders of magnitude longer
    // than it takes to send an HTTP request twice.
    assert_eq!(
        s.check_and_record(&payer(2), &nonce(2), now).unwrap(),
        Freshness::Replayed
    );
    assert_eq!(
        s.check_and_record(&payer(3), &nonce(3), now + 1).unwrap(),
        Freshness::Replayed
    );

    // And the pruned one is genuinely gone rather than merely hidden: the
    // store reports it fresh again, which is exactly why the verifier must
    // never reach this call for an expired payload.
    assert_eq!(
        s.check_and_record(&payer(1), &nonce(1), now - 1).unwrap(),
        Freshness::Fresh
    );
}

#[test]
fn a_store_that_cannot_answer_says_so_rather_than_crying_replay() {
    needs_pg!("a_store_that_cannot_answer_says_so_rather_than_crying_replay");
    let mut s = connect("nonce_broken", true);

    // Take the table away underneath it. Any infrastructure failure would
    // do; this one is reproducible and does not need a second process.
    {
        let cs = conn_string().unwrap();
        let mut c = Client::connect(&cs, NoTls).expect("connect");
        c.batch_execute("DROP TABLE nonce_broken.payment_nonces;")
            .expect("drop");
    }

    let err = s
        .check_and_record(&payer(1), &nonce(1), LIVE)
        .expect_err("a missing table is not an answer");

    // The distinction the whole error type exists for: this must not be
    // reported as, or collapsed into, a replay. One of those wakes somebody
    // up to hunt an attacker; the other wakes somebody up to restart a
    // database.
    let text = err.to_string();
    assert!(
        text.contains("could not answer"),
        "unhelpful message: {text}"
    );
    assert!(
        !text.contains("seen before"),
        "an outage must never be described as a replay: {text}"
    );

    // And it has to say what went wrong. `postgres::Error` renders as the
    // bare string "db error" and hides the useful part one level down, so a
    // naive `to_string()` in the store would produce a 503 whose entire
    // explanation is "db error" — true, and worth nothing at three in the
    // morning.
    assert!(
        text.contains("payment_nonces") && text.contains("42P01"),
        "the refusal must name the relation and the SQLSTATE: {text}"
    );
}

/// The schema's length checks are not decoration.
///
/// Rust's type system makes a short payer unrepresentable here, which is
/// precisely why the database check is worth having: the next writer of this
/// table may not be this crate.
#[test]
fn the_database_refuses_a_truncated_address() {
    needs_pg!("the_database_refuses_a_truncated_address");
    let _setup = connect("nonce_lengths", true);
    let cs = conn_string().unwrap();
    let mut c = Client::connect(&cs, NoTls).expect("connect");
    c.batch_execute("SET search_path TO nonce_lengths;")
        .expect("search_path");

    let live = i64::try_from(LIVE).unwrap();
    let short: &[u8] = &[1u8; 19];
    let long_nonce: &[u8] = &[1u8; 33];
    let ok_payer: &[u8] = &[1u8; 20];
    let ok_nonce: &[u8] = &[1u8; 32];

    for (payer, nonce, constraint) in [
        (short, ok_nonce, "payer_is_an_address"),
        (ok_payer, long_nonce, "nonce_is_32_bytes"),
    ] {
        let err = c
            .execute(
                "INSERT INTO payment_nonces (payer, nonce, valid_before_secs) VALUES ($1,$2,$3)",
                &[&payer, &nonce, &live],
            )
            .expect_err("the wrong number of bytes is not a key");
        assert_eq!(
            err.as_db_error().and_then(|e| e.constraint()),
            Some(constraint),
            "{err}"
        );
    }
}

#[test]
fn the_schema_can_be_applied_more_than_once() {
    needs_pg!("the_schema_can_be_applied_more_than_once");
    // BUGS.md #018: the proxy migrates on startup, so a migration that only
    // succeeds once is a process that only starts once, and the first crash
    // is permanent. The nonce table is new, and the rule applies to it too.
    let mut s = connect("nonce_idempotent", true);
    s.migrate().expect("second");
    s.migrate().expect("third");
    s.check_and_record(&payer(1), &nonce(1), LIVE).unwrap();
    s.migrate().expect("fourth, with data present");
    assert_eq!(
        s.check_and_record(&payer(1), &nonce(1), LIVE).unwrap(),
        Freshness::Replayed,
        "re-running the migration must not truncate the table"
    );
}
