//! Budget holds.
//!
//! The policy engine decides whether a payment *should* happen. This crate
//! makes sure that decision survives contact with a second agent asking the
//! same question at the same instant.
//!
//! # The race
//!
//! A budget is an aggregate over a time range. The policy engine reads a
//! snapshot of it and answers from that photograph. Between the read and the
//! payment, anything can happen.
//!
//! Two agents, one principal, £500 daily cap, £480 already spent. Both ask
//! to spend £20. Both read £480. Both compute £500, which is within the cap.
//! Both are allowed. £520 leaves the account and no single check was wrong.
//!
//! This is not fixed by being careful in the application. It is fixed by
//! making the read and the write one indivisible step, and that is what this
//! crate is for.
//!
//! # Why a row that exists only to be locked
//!
//! The obvious fix is `SELECT ... FOR UPDATE` over the holds in the window.
//! It does not work: the rows the two transactions conflict over are the
//! ones they are each *about to insert*, and you cannot lock a row that does
//! not exist. This is the phantom read, and `READ COMMITTED` does not stop
//! it.
//!
//! `SERIALIZABLE` does stop it, by aborting one transaction with a
//! serialization failure. That is correct, and it makes retry handling every
//! caller's problem forever. Get it wrong at one call site and the failure
//! mode is a payment that silently did not happen.
//!
//! So: one row per principal and currency, holding nothing, existing to be
//! locked. Every reservation takes it, does its arithmetic, writes, and
//! releases. Reservations for one principal serialize; different principals
//! never touch. A person's agents are not a high-throughput workload, and
//! predictable beats clever at the boundary where money moves.
//!
//! # States
//!
//! `held` → `captured` when the payment settles, `released` when it does
//! not, `expired` when nobody ever said. A hold that could stay `held`
//! forever is a budget one crashed agent freezes until somebody notices,
//! which is usually the following month.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

pub(crate) mod chaos;
pub mod holds;

pub use holds::{HoldRecord, HoldState, LedgerError, Reservation, Store};

/// The schema this crate expects.
pub const MIGRATION: &str = include_str!("../migrations/0001_holds.sql");
