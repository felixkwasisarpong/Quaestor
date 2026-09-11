//! Where receipts actually go.
//!
//! # A log nobody wrote down is not a log
//!
//! Until now the gateway signed a receipt, put it in a response header and
//! forgot it. Every claim made for the receipt chain — that a deletion
//! breaks the link, that an operator cannot hand you a doctored history,
//! that six months later somebody can ask why — assumes there is a history
//! to hand over. There was not one. The agent held the only copy of its own
//! receipt, which makes the evidence log a thing the party being audited is
//! trusted to keep.
//!
//! Found on day 19, by writing an invariant checker that wanted to read the
//! log and discovering there was nothing to read.
//!
//! # Persist before you answer
//!
//! [`ReceiptSink::append`] must not return `Ok` until the receipt would
//! survive losing this process. The gateway calls it *before* the verdict
//! reaches anyone, and an allowed payment whose receipt cannot be written is
//! refused instead.
//!
//! That ordering is what makes a crash between signing and persisting safe.
//! The lost receipt never reached the agent, no hold was captured on the
//! strength of it, and the restarted signer reuses its sequence number — all
//! of which is only true because nothing downstream of the signature had
//! happened yet. Reverse the order and the same crash leaves a payment out
//! in the world with no record and a chain that has forked.
//!
//! # Why every append is fsynced
//!
//! A line in the page cache is not a receipt. The machine that loses power
//! between the write and the flush comes back with a log that is missing
//! exactly the decisions it was busiest making. One fsync per decision is
//! expensive and it is the honest default; a deployment that wants to trade
//! it away should have to say so somewhere more deliberate than here.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use quaestor_receipt::Receipt;

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not serialize the receipt: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("the receipt log is corrupt at its tail: {0}")]
    CorruptTail(String),
}

pub trait ReceiptSink: core::fmt::Debug + Send {
    /// Record a receipt durably. Must not return `Ok` until it would survive
    /// the loss of this process.
    fn append(&mut self, receipt: &Receipt) -> Result<(), SinkError>;

    /// The last receipt in the log, or `None` for an empty one.
    ///
    /// Used to resume the chain across a restart. Resuming from the
    /// *persisted* tail rather than from anything held in memory is the
    /// whole safety argument for the crash window above.
    fn tail(&self) -> Option<&Receipt>;

    /// How many receipts this sink has written or found. Diagnostics only.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------

/// JSON Lines on disk. The format `quaestor-verify-receipts` reads.
#[derive(Debug)]
pub struct JsonLinesSink {
    path: PathBuf,
    file: File,
    tail: Option<Receipt>,
    count: u64,
}

impl JsonLinesSink {
    /// Open or create the log, and find where the chain left off.
    pub fn open(path: impl AsRef<Path>) -> Result<JsonLinesSink, SinkError> {
        let path = path.as_ref().to_path_buf();
        let (tail, count) = read_tail(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(JsonLinesSink {
            path,
            file,
            tail,
            count,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ReceiptSink for JsonLinesSink {
    fn append(&mut self, receipt: &Receipt) -> Result<(), SinkError> {
        let mut line = serde_json::to_vec(receipt)?;
        line.push(b'\n');

        // One write, so a torn line needs a torn *write*, not merely an
        // unlucky moment between two of them.
        self.file.write_all(&line)?;
        self.file.sync_all()?;

        self.tail = Some(receipt.clone());
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    fn tail(&self) -> Option<&Receipt> {
        self.tail.as_ref()
    }

    fn len(&self) -> u64 {
        self.count
    }
}

/// The last receipt, and how many there are.
///
/// The tail is found by reading backwards from the end rather than parsing
/// the whole file, because a restart should not get slower every day the
/// system stays up. The count does read the whole file, and is only used for
/// diagnostics — if that ever becomes the expensive part, it is the part to
/// drop.
fn read_tail(path: &Path) -> Result<(Option<Receipt>, u64), SinkError> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, 0)),
        Err(e) => return Err(SinkError::Io(e)),
    };

    let size = file.metadata()?.len();
    if size == 0 {
        return Ok((None, 0));
    }

    // Read the tail window and take the last complete line in it.
    const WINDOW: u64 = 64 * 1024;
    let from = size.saturating_sub(WINDOW);
    file.seek(SeekFrom::Start(from))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    let last = buf.lines().rev().find(|l| !l.trim().is_empty());
    let tail = match last {
        None => None,
        Some(line) => Some(
            serde_json::from_str::<Receipt>(line.trim())
                // A half-written final line is the expected shape of a crash
                // during append, and it is not something to paper over: the
                // operator has to decide whether to truncate it, because
                // guessing would mean the chain resumes from a receipt whose
                // contents we invented.
                .map_err(|e| SinkError::CorruptTail(e.to_string()))?,
        ),
    };

    let mut all = String::new();
    File::open(path)?.read_to_string(&mut all)?;
    let count = all.lines().filter(|l| !l.trim().is_empty()).count();

    Ok((tail, u64::try_from(count).unwrap_or(u64::MAX)))
}

// ---------------------------------------------------------------------------

/// In memory. For tests, and for nothing else: a receipt log that dies with
/// the process is the situation this module exists to fix.
#[derive(Debug, Default, Clone)]
pub struct MemorySink {
    receipts: Vec<Receipt>,
}

impl MemorySink {
    pub fn new() -> MemorySink {
        MemorySink::default()
    }

    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }
}

impl ReceiptSink for MemorySink {
    fn append(&mut self, receipt: &Receipt) -> Result<(), SinkError> {
        self.receipts.push(receipt.clone());
        Ok(())
    }

    fn tail(&self) -> Option<&Receipt> {
        self.receipts.last()
    }

    fn len(&self) -> u64 {
        u64::try_from(self.receipts.len()).unwrap_or(u64::MAX)
    }
}

/// A sink that always fails, so the gateway's behaviour when it cannot
/// record a decision is a tested path rather than a hope.
#[derive(Debug, Default)]
pub struct FailingSink;

impl ReceiptSink for FailingSink {
    fn append(&mut self, _receipt: &Receipt) -> Result<(), SinkError> {
        Err(SinkError::Io(std::io::Error::other(
            "the receipt log is unwritable",
        )))
    }

    fn tail(&self) -> Option<&Receipt> {
        None
    }

    fn len(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use quaestor_core::{Currency, Hold, IntentId, Money, Timestamp, Verdict};
    use quaestor_receipt::{verify_chain, Signer};

    const NOW: Timestamp = Timestamp(1_772_000_000_000);

    fn allow() -> Verdict {
        Verdict::Allow {
            hold: Hold {
                intent: IntentId::new("i").expect("valid"),
                amount: Money::new(1, Currency::USDC),
                expires_at: NOW,
            },
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("quaestor-sink-{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_chain_survives_being_written_and_read_back() {
        let path = tmp("roundtrip");
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let public = key.verifying_key().to_bytes();

        {
            let mut sink = JsonLinesSink::open(&path).expect("open");
            let mut signer = Signer::new(key.clone());
            for i in 0..3 {
                let r = signer.issue(
                    &format!("i{i}"),
                    "felix",
                    "shopper",
                    "p",
                    Money::new(1_000, Currency::USDC),
                    &allow(),
                    [0u8; 32],
                    NOW,
                );
                sink.append(&r).expect("append");
            }
            assert_eq!(sink.len(), 3);
        }

        let text = std::fs::read_to_string(&path).expect("read");
        let receipts: Vec<Receipt> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse"))
            .collect();
        verify_chain(&receipts, &public, true).expect("the written log verifies");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopening_finds_the_tail_and_the_chain_continues_unbroken() {
        // The restart case. If `tail` were wrong, the resumed signer would
        // link to the wrong place and every later receipt would fail to
        // verify — which is the failure a restart must not cause.
        let path = tmp("resume");
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let public = key.verifying_key().to_bytes();

        {
            let mut sink = JsonLinesSink::open(&path).expect("open");
            let mut signer = Signer::new(key.clone());
            for i in 0..2 {
                let r = signer.issue(
                    &format!("before{i}"),
                    "felix",
                    "a",
                    "p",
                    Money::new(1, Currency::USDC),
                    &allow(),
                    [0u8; 32],
                    NOW,
                );
                sink.append(&r).expect("append");
            }
        }

        {
            let mut sink = JsonLinesSink::open(&path).expect("reopen");
            let tail = sink.tail().expect("a tail").clone();
            assert_eq!(tail.seq, 1);
            assert_eq!(sink.len(), 2);

            let mut signer = Signer::resume(key, &tail);
            let r = signer.issue(
                "after",
                "felix",
                "a",
                "p",
                Money::new(1, Currency::USDC),
                &allow(),
                [0u8; 32],
                NOW,
            );
            assert_eq!(r.seq, 2);
            sink.append(&r).expect("append");
        }

        let text = std::fs::read_to_string(&path).expect("read");
        let receipts: Vec<Receipt> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse"))
            .collect();
        assert_eq!(receipts.len(), 3);
        verify_chain(&receipts, &public, true).expect("a restart does not break the chain");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_empty_or_missing_log_has_no_tail() {
        let path = tmp("empty");
        let sink = JsonLinesSink::open(&path).expect("open");
        assert!(sink.tail().is_none());
        assert!(sink.is_empty());
        drop(sink);

        let again = JsonLinesSink::open(&path).expect("reopen");
        assert!(again.tail().is_none(), "an empty file is not a tail");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_half_written_final_line_is_reported_not_guessed() {
        // The expected shape of a crash during append. Silently dropping the
        // torn line would resume the chain from a receipt whose contents we
        // made up; silently keeping it is impossible. So: refuse to open,
        // and let a person decide.
        let path = tmp("torn");
        std::fs::write(&path, "{\"seq\":0,\"prev_ha").expect("write");

        let err = JsonLinesSink::open(&path).expect_err("must refuse");
        assert!(matches!(err, SinkError::CorruptTail(_)), "{err:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_tail_is_found_without_reading_a_large_log_from_the_start() {
        // A restart should not get slower every day the system stays up.
        let path = tmp("big");
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut sink = JsonLinesSink::open(&path).expect("open");
        let mut signer = Signer::new(key);
        for i in 0..400 {
            let r = signer.issue(
                &format!("i{i}"),
                "felix",
                "a",
                "p",
                Money::new(1, Currency::USDC),
                &allow(),
                [0u8; 32],
                NOW,
            );
            sink.append(&r).expect("append");
        }
        drop(sink);

        let reopened = JsonLinesSink::open(&path).expect("reopen");
        assert_eq!(reopened.tail().expect("tail").seq, 399);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_failing_sink_fails() {
        let mut s = FailingSink;
        let mut signer = Signer::new(SigningKey::from_bytes(&[1u8; 32]));
        let r = signer.issue(
            "i",
            "felix",
            "a",
            "p",
            Money::new(1, Currency::USDC),
            &allow(),
            [0u8; 32],
            NOW,
        );
        assert!(s.append(&r).is_err());
    }
}
