//! Verifying a run of receipts.
//!
//! Offline, by construction. This module opens no sockets and reads no
//! clock. Given a slice of receipts and the public key you expect them to
//! be signed by, it tells you whether the record is intact.

use crate::receipt::{to_hex, PublicKey, Receipt, GENESIS_HASH};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyFailure {
    #[error("receipt {seq}: signature does not verify")]
    BadSignature { seq: u64 },
    #[error("receipt {seq}: signed by {actual}, expected {expected}")]
    WrongSigner {
        seq: u64,
        actual: String,
        expected: String,
    },
    /// The chain has been cut. Something was removed, reordered or inserted.
    #[error("receipt {seq}: prev_hash does not match the receipt before it")]
    BrokenLink { seq: u64 },
    #[error("receipt {seq}: expected sequence number {expected}")]
    OutOfOrder { seq: u64, expected: u64 },
    #[error("the first receipt does not begin a chain: prev_hash is not the genesis value")]
    BadGenesis,
}

/// What a run of receipts turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub count: usize,
    pub allowed: usize,
    pub denied: usize,
    pub escalated: usize,
    /// Hash of the last receipt. Publish it, and anyone holding an earlier
    /// copy can tell whether history was rewritten behind them.
    pub head: [u8; 32],
}

/// Check signatures and linkage across a run of receipts.
///
/// `expected_signer` is what makes this meaningful. Without it a chain is
/// merely internally consistent, and an attacker who replaces the whole run
/// with their own correctly-signed one passes. You have to know whose
/// signature you are expecting.
///
/// `from_genesis` should be false when checking a slice from the middle of a
/// longer chain: linkage within the slice is still verified, but the first
/// receipt is not required to be the beginning of history.
pub fn verify_chain(
    receipts: &[Receipt],
    expected_signer: &PublicKey,
    from_genesis: bool,
) -> Result<ChainReport, VerifyFailure> {
    let mut report = ChainReport {
        count: receipts.len(),
        allowed: 0,
        denied: 0,
        escalated: 0,
        head: GENESIS_HASH,
    };

    let mut expected_prev: Option<[u8; 32]> = if from_genesis {
        Some(GENESIS_HASH)
    } else {
        None
    };
    let mut expected_seq: Option<u64> = None;

    for r in receipts {
        if &r.signer != expected_signer {
            return Err(VerifyFailure::WrongSigner {
                seq: r.seq,
                actual: to_hex(&r.signer),
                expected: to_hex(expected_signer),
            });
        }
        r.verify_signature()
            .map_err(|_| VerifyFailure::BadSignature { seq: r.seq })?;

        if let Some(prev) = expected_prev {
            if r.prev_hash != prev {
                return Err(if r.seq == 0 {
                    VerifyFailure::BadGenesis
                } else {
                    VerifyFailure::BrokenLink { seq: r.seq }
                });
            }
        }
        if let Some(seq) = expected_seq {
            if r.seq != seq {
                return Err(VerifyFailure::OutOfOrder {
                    seq: r.seq,
                    expected: seq,
                });
            }
        }

        match &r.verdict {
            crate::ReceiptVerdict::Allow => report.allowed = report.allowed.saturating_add(1),
            crate::ReceiptVerdict::Deny { .. } => report.denied = report.denied.saturating_add(1),
            crate::ReceiptVerdict::Escalate { .. } => {
                report.escalated = report.escalated.saturating_add(1);
            }
        }

        report.head = r.hash();
        expected_prev = Some(report.head);
        expected_seq = Some(r.seq.saturating_add(1));
    }

    Ok(report)
}
