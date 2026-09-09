//! Decision receipts.
//!
//! Every verdict produces one, including the refusals. Especially the
//! refusals: an approval that turns out to be wrong is a bad payment, but a
//! *denial* nobody can account for is an argument, and arguments about money
//! are settled by evidence.
//!
//! # What a receipt is for
//!
//! Six months after a payment, someone asks why it was allowed. Or why it
//! was not. A log line answers that question only if you trust whoever runs
//! the log, and if the answer matters enough to ask, it matters enough that
//! trust is the wrong basis.
//!
//! So a receipt is signed, and it verifies with nothing but a public key.
//! Not an API call, not a support ticket, not access to the system that
//! issued it. [`verify_chain`] and the `quaestor-verify-receipts` binary
//! will check a file of them on a laptop with the network off.
//!
//! That is the specific thing a managed service structurally cannot offer.
//! Their audit trail is a page in their console, and its correctness rests
//! on them.
//!
//! # Why they are chained
//!
//! A signature stops a receipt being *altered*. It does nothing about a
//! receipt being *removed*: delete the awkward one and the remainder still
//! verifies perfectly.
//!
//! Each receipt therefore carries the hash of the one before it. Removing,
//! reordering or inserting anything breaks the chain at that point and every
//! point after it. The operator can still refuse to hand over the log, but
//! they can no longer hand over a doctored one that passes.

#![cfg_attr(
    test,
    allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects,
    )
)]

pub mod chain;
pub mod receipt;

pub use chain::{verify_chain, ChainReport, VerifyFailure};
pub use receipt::{Receipt, ReceiptError, ReceiptVerdict, Signer, GENESIS_HASH};
