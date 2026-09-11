//! The gate.
//!
//! Real Postgres, real threads, real contention. Not a mock, not a
//! simulation of a lock: if these pass, the invariant holds against an
//! actual database under actual concurrency, and if the locking is wrong
//! they fail.
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
use quaestor_core::{Currency, Money, Timestamp};
use quaestor_ledger::{HoldState, LedgerError, Reservation, Store};
use quaestor_policy::rules::Budget;

const NOW: Timestamp = Timestamp(1_772_000_000_000);
const DAY_MS: i64 = 86_400_000;
const HOLD_TTL: i64 = 300_000;

fn conn_string() -> Option<String> {
    std::env::var("QUAESTOR_TEST_PG").ok()
}

fn usd(minor: i128) -> Money {
    Money::new(minor, Currency::USD)
}

fn daily(limit_minor: i128) -> Vec<Budget> {
    vec![Budget {
        window_ms: DAY_MS,
        window_label: "24h".into(),
        limit: usd(limit_minor),
    }]
}

/// A fresh schema per test, in its own namespace, so tests can run in
/// parallel against one database without seeing each other.
fn fresh_store(schema: &str) -> Store {
    let cs = conn_string().expect("checked by caller");
    let mut client = Client::connect(&cs, NoTls).expect("connect");
    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE;
             CREATE SCHEMA {schema};
             SET search_path TO {schema};"
        ))
        .expect("schema");
    let mut store = Store::new(client);
    store.migrate().expect("migrate");
    store
}

fn store_on(schema: &str) -> Store {
    let cs = conn_string().expect("checked by caller");
    let mut client = Client::connect(&cs, NoTls).expect("connect");
    client
        .batch_execute(&format!("SET search_path TO {schema};"))
        .expect("search_path");
    Store::new(client)
}

macro_rules! requires_pg {
    () => {
        if conn_string().is_none() {
            println!("skipping: QUAESTOR_TEST_PG not set");
            return;
        }
    };
}

// ---------------------------------------------------------------------------

#[test]
fn two_agents_cannot_both_win_the_same_last_dollar() {
    requires_pg!();
    // The gate, stated in its smallest form. £5.00 left, two agents, each
    // asking for £5.00, at the same instant. Exactly one may win.
    //
    // Under a naive read-then-write both read "nothing spent", both compute
    // "500 is within 500", and both are allowed. £10.00 leaves the account
    // and neither check was individually wrong.
    //
    // Run many rounds, because a single two-way race is not reliable
    // evidence: with the lock deliberately removed, one round passes far
    // more often than it fails. A property that only sometimes reproduces
    // is not a property, it is a coin toss. Thirty rounds turns it into a
    // test that actually bites.
    let _ = fresh_store("gate_last_dollar");

    for round in 0..30 {
        let winners = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(2));

        let handles: Vec<_> = (0..2)
            .map(|i| {
                let winners = Arc::clone(&winners);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = store_on("gate_last_dollar");
                    barrier.wait(); // start together
                    let r = store
                        .reserve(
                            &format!("felix-{round}"),
                            &format!("agent-{i}"),
                            "shop.example",
                            &format!("intent-{round}-{i}"),
                            &format!("key-{round}-{i}"),
                            usd(500),
                            &daily(500),
                            NOW,
                            HOLD_TTL,
                        )
                        .expect("reserve");
                    if matches!(r, Reservation::Reserved(_)) {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread");
        }

        assert_eq!(
            winners.load(Ordering::SeqCst),
            1,
            "round {round}: exactly one agent may win the last dollar"
        );
    }
}

#[test]
fn forty_agents_never_exceed_the_budget_between_them() {
    requires_pg!();
    // The same property under real load. 40 threads, £1.00 each, £30.00
    // cap. Whatever the interleaving, exactly 30 may win and the total held
    // must never exceed the cap.
    let _ = fresh_store("gate_hundred");

    let winners = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(40));

    let handles: Vec<_> = (0..40)
        .map(|i| {
            let winners = Arc::clone(&winners);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = store_on("gate_hundred");
                barrier.wait();
                let r = store
                    .reserve(
                        "felix",
                        "swarm",
                        "shop.example",
                        &format!("intent-{i}"),
                        &format!("key-{i}"),
                        usd(100),
                        &daily(3_000),
                        NOW,
                        HOLD_TTL,
                    )
                    .expect("reserve");
                if matches!(r, Reservation::Reserved(_)) {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread");
    }

    let won = winners.load(Ordering::SeqCst);
    assert_eq!(won, 30, "exactly the budget's worth should win, got {won}");

    let mut store = store_on("gate_hundred");
    let total = store
        .spent_in_window("felix", "USD", DAY_MS, NOW)
        .expect("sum");
    assert_eq!(total, 3_000, "held total must equal the cap exactly");
    assert!(total <= 3_000, "the invariant: never above the cap");
}

#[test]
fn the_same_idempotency_key_reserves_once_however_many_times_it_arrives() {
    requires_pg!();
    // A retry storm: 20 threads replaying one key. One hold, one reservation,
    // and every caller gets the same answer back.
    let _ = fresh_store("gate_idem");
    let barrier = Arc::new(Barrier::new(20));
    let reserved = Arc::new(AtomicUsize::new(0));
    let replayed = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..20)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let reserved = Arc::clone(&reserved);
            let replayed = Arc::clone(&replayed);
            thread::spawn(move || {
                let mut store = store_on("gate_idem");
                barrier.wait();
                match store
                    .reserve(
                        "felix",
                        "shopper",
                        "shop.example",
                        "intent-same",
                        "key-same",
                        usd(100),
                        &daily(10_000),
                        NOW,
                        HOLD_TTL,
                    )
                    .expect("reserve")
                {
                    Reservation::Reserved(_) => reserved.fetch_add(1, Ordering::SeqCst),
                    Reservation::AlreadySettled(_) => replayed.fetch_add(1, Ordering::SeqCst),
                    Reservation::Refused { .. } => panic!("budget was ample"),
                };
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread");
    }

    assert_eq!(
        reserved.load(Ordering::SeqCst),
        1,
        "exactly one real reservation"
    );
    assert_eq!(replayed.load(Ordering::SeqCst), 19, "the rest replay");

    let mut store = store_on("gate_idem");
    assert_eq!(
        store
            .spent_in_window("felix", "USD", DAY_MS, NOW)
            .expect("sum"),
        100,
        "one key must consume budget once"
    );
}

#[test]
fn different_principals_do_not_block_each_other() {
    requires_pg!();
    // The lock is per principal. One person's agents must never be able to
    // exhaust or delay another's.
    let _ = fresh_store("gate_isolation");
    let barrier = Arc::new(Barrier::new(2));

    let handles: Vec<_> = ["felix", "someone-else"]
        .into_iter()
        .map(|who| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = store_on("gate_isolation");
                barrier.wait();
                store
                    .reserve(
                        who,
                        "agent",
                        "shop.example",
                        &format!("intent-{who}"),
                        &format!("key-{who}"),
                        usd(500),
                        &daily(500),
                        NOW,
                        HOLD_TTL,
                    )
                    .expect("reserve")
            })
        })
        .collect();

    for h in handles {
        assert!(
            matches!(h.join().expect("thread"), Reservation::Reserved(_)),
            "each principal has their own budget"
        );
    }
}

#[test]
fn a_released_hold_gives_the_budget_back() {
    requires_pg!();
    let mut store = fresh_store("gate_release");

    let first = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    assert!(matches!(first, Reservation::Reserved(_)));

    // Budget is now full.
    let blocked = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i2",
            "k2",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    assert!(matches!(blocked, Reservation::Refused { .. }));

    store.release("i1", NOW).expect("release");

    let after = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i3",
            "k3",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    assert!(
        matches!(after, Reservation::Reserved(_)),
        "released budget returns"
    );
}

#[test]
fn a_captured_hold_keeps_consuming_the_budget() {
    requires_pg!();
    // Capture means the money moved. It must go on counting, or a settled
    // payment stops being visible to the next budget check.
    let mut store = fresh_store("gate_capture");
    store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    store.capture("i1", NOW).expect("capture");

    let blocked = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i2",
            "k2",
            usd(100),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    assert!(matches!(blocked, Reservation::Refused { .. }));
}

#[test]
fn a_hold_cannot_be_captured_twice() {
    requires_pg!();
    let mut store = fresh_store("gate_double_capture");
    store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            usd(100),
            &daily(10_000),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    store.capture("i1", NOW).expect("first capture");
    assert!(matches!(
        store.capture("i1", NOW),
        Err(LedgerError::WrongState { .. })
    ));
    assert!(matches!(
        store.release("i1", NOW),
        Err(LedgerError::WrongState { .. })
    ));
}

#[test]
fn an_abandoned_hold_stops_occupying_the_budget_once_it_expires() {
    requires_pg!();
    // A crashed agent must not freeze a budget until somebody notices.
    let mut store = fresh_store("gate_expiry");
    store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");

    let later = Timestamp(NOW.0 + HOLD_TTL + 1);
    let after = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i2",
            "k2",
            usd(500),
            &daily(500),
            later,
            HOLD_TTL,
        )
        .expect("reserve");
    assert!(
        matches!(after, Reservation::Reserved(_)),
        "an expired hold must release its claim"
    );

    assert_eq!(
        store.get("i1").expect("get").expect("exists").state,
        HoldState::Expired
    );
}

#[test]
fn a_refused_reservation_leaves_nothing_behind() {
    requires_pg!();
    // A refusal rolls back. Otherwise a failed attempt could consume an
    // intent id, or leave a partial write the next caller trips over.
    let mut store = fresh_store("gate_refusal_clean");
    store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");

    let refused = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i2",
            "k2",
            usd(500),
            &daily(500),
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    assert!(matches!(refused, Reservation::Refused { .. }));
    assert!(
        store.get("i2").expect("get").is_none(),
        "no row for a refusal"
    );

    // And the same key may be retried later once budget frees up.
    store.release("i1", NOW).expect("release");
    assert!(matches!(
        store
            .reserve(
                "felix",
                "a",
                "shop.example",
                "i2",
                "k2",
                usd(500),
                &daily(500),
                NOW,
                HOLD_TTL
            )
            .expect("reserve"),
        Reservation::Reserved(_)
    ));
}

#[test]
fn every_configured_window_must_be_satisfied_not_just_one() {
    requires_pg!();
    let mut store = fresh_store("gate_windows");
    let budgets = vec![
        Budget {
            window_ms: DAY_MS,
            window_label: "24h".into(),
            limit: usd(50_000),
        },
        Budget {
            window_ms: DAY_MS * 30,
            window_label: "30d".into(),
            limit: usd(1_000),
        },
    ];

    let r = store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            usd(2_000),
            &budgets,
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");
    match r {
        Reservation::Refused { window_label, .. } => assert_eq!(window_label, "30d"),
        other => panic!("the monthly cap should bite, got {other:?}"),
    }
}

#[test]
fn a_non_positive_amount_is_refused_before_it_reaches_the_database() {
    requires_pg!();
    let mut store = fresh_store("gate_amounts");
    for bad in [0, -1, -500] {
        assert!(matches!(
            store.reserve(
                "felix",
                "a",
                "p",
                "i",
                "k",
                usd(bad),
                &daily(500),
                NOW,
                HOLD_TTL
            ),
            Err(LedgerError::NonPositiveAmount(_))
        ));
    }
}

#[test]
fn amounts_survive_the_database_round_trip_at_full_range() {
    requires_pg!();
    // i128 does not fit in BIGINT. If the column were wrong this truncates
    // silently, which is bug 001 all over again in a different medium.
    let mut store = fresh_store("gate_range");
    let huge = i128::MAX / 2;
    store
        .reserve(
            "felix",
            "a",
            "shop.example",
            "i1",
            "k1",
            Money::new(huge, Currency::USD),
            &[Budget {
                window_ms: DAY_MS,
                window_label: "24h".into(),
                limit: Money::new(i128::MAX, Currency::USD),
            }],
            NOW,
            HOLD_TTL,
        )
        .expect("reserve");

    let back = store.get("i1").expect("get").expect("exists");
    assert_eq!(
        back.amount.minor(),
        huge,
        "no truncation on the way through"
    );
}

#[test]
fn the_schema_can_be_applied_twice() {
    // `quaestor-proxy` migrates on startup, so a migration that succeeds
    // only once is a process that starts only once, and the first crash is
    // permanent. Every statement here carried IF NOT EXISTS except
    // CREATE TYPE, which has no such syntax. See BUGS.md #018.
    let Some(conn) = conn_string() else {
        return;
    };
    let client = Client::connect(&conn, NoTls).expect("connect");
    let mut store = Store::new(client);
    store.migrate().expect("first");
    store
        .migrate()
        .expect("a restart applies the same schema again");
    store.migrate().expect("and again");
}
