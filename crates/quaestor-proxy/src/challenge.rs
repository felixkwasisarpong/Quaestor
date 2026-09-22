//! What the origin actually demanded.
//!
//! # Why this exists at all
//!
//! An x402 payment payload carries an `accepted` field: the requirements the
//! sender claims to be satisfying. It arrives from the agent, inside the
//! agent's own message, and it is the most tempting thing in the request to
//! verify against, because it is *right there* and it has exactly the right
//! shape.
//!
//! [`quaestor_verify::x402::verify_exact_evm`] checks that the authorized
//! recipient equals the demanded recipient and the authorized amount equals
//! the demanded amount. Hand it `payload.accepted` as the demand and both
//! checks compare a field with itself. It returns `Ok`. Nothing has been
//! established.
//!
//! The demand has to come from the `402` the resource server issued, which
//! is a message the proxy saw and the agent cannot forge. Holding on to it
//! between the challenge and the payment is this module's entire job, and
//! the reason the proxy is stateful when nothing beneath it is.
//!
//! # Every failure here is a refusal
//!
//! The store is bounded and entries expire, so a caller that provokes
//! thousands of `402`s cannot grow it without limit. Both mechanisms can
//! discard an entry that a legitimate payment was about to need.
//!
//! That is survivable in exactly one direction: a missing challenge means
//! the proxy has nothing to check the payment against, and a payment that
//! cannot be checked is refused. Eviction and expiry can cost an agent a
//! round trip. Neither can let a payment through.
//!
//! # Why an entry is not consumed on use
//!
//! A challenge is not a one-shot ticket. A payment can be refused by policy,
//! escalated to a human and re-presented, or simply retried after a network
//! failure, and every one of those needs the same demand to check against.
//! Replay of a *particular* authorization is stopped where it belongs, by
//! the nonce store inside the verifier. Making the challenge disappear on
//! first use would add nothing to that and would break the retry.

use std::collections::{HashMap, VecDeque};

use quaestor_core::Timestamp;
use quaestor_verify::x402::PaymentRequirements;
use serde::Deserialize;

/// The most alternatives one `402` may offer.
///
/// A payment is checked against each until one accepts it, so this bounds
/// the work a hostile origin can ask of the proxy per payment. Eight is more
/// than any real deployment lists and small enough not to matter.
pub const MAX_ALTERNATIVES: usize = 8;

/// Which request this challenge belongs to.
///
/// The principal is part of the key. Without it, one caller's `402` is a
/// demand any other caller can pay against, which is a strange kind of
/// cross-tenant leak: the amounts and the recipient come from somebody
/// else's conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChallengeKey {
    pub principal: String,
    pub method: String,
    pub target: String,
}

impl ChallengeKey {
    pub fn new(principal: &str, method: &str, target: &str) -> ChallengeKey {
        ChallengeKey {
            principal: principal.to_owned(),
            // Methods are case-sensitive in HTTP and we do not normalise
            // them: `get` and `GET` are different requests to an origin, so
            // treating them as one here would be us inventing an equivalence
            // the origin never agreed to.
            method: method.to_owned(),
            target: target.to_owned(),
        }
    }
}

/// One `402`, remembered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Everything the origin said it would accept, in the order it said it.
    pub alternatives: Vec<PaymentRequirements>,
    pub seen_at: Timestamp,
}

/// The body of an x402 `402` response.
#[derive(Debug, Clone, Deserialize)]
struct Challenge402 {
    #[serde(rename = "x402Version")]
    x402_version: Option<u32>,
    accepts: Vec<PaymentRequirements>,
}

/// Bounded, expiring store of outstanding challenges.
#[derive(Debug)]
pub struct ChallengeStore {
    ttl_ms: i64,
    capacity: usize,
    by_key: HashMap<ChallengeKey, Challenge>,
    /// Insertion order, for eviction. Keys can appear more than once if a
    /// challenge was re-recorded; stale entries are skipped when draining.
    order: VecDeque<ChallengeKey>,
}

impl ChallengeStore {
    /// `ttl_ms` should comfortably exceed the time an agent takes to sign a
    /// payment and come back, and should not exceed the origin's own
    /// `maxTimeoutSeconds` by much: a challenge we still honour after the
    /// origin has forgotten it produces a payment the origin will reject.
    pub fn new(ttl_ms: i64, capacity: usize) -> ChallengeStore {
        ChallengeStore {
            ttl_ms,
            capacity: capacity.max(1),
            by_key: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Read a `402` body and remember what it demanded.
    ///
    /// Returns whether anything was recorded. A body that does not parse, or
    /// offers nothing, is not an error the proxy reports: the `402` is
    /// passed back to the agent either way and the agent will find out. What
    /// matters is that nothing was recorded, so a payment arriving later has
    /// no demand to satisfy and is refused.
    pub fn record_402(&mut self, key: ChallengeKey, body: &[u8], now: Timestamp) -> bool {
        let Ok(parsed) = serde_json::from_slice::<Challenge402>(body) else {
            return false;
        };
        if let Some(v) = parsed.x402_version {
            if v != quaestor_verify::x402::SUPPORTED_VERSION {
                return false;
            }
        }
        let alternatives: Vec<PaymentRequirements> = parsed
            .accepts
            .into_iter()
            .take(MAX_ALTERNATIVES)
            .collect::<Vec<_>>();
        if alternatives.is_empty() {
            return false;
        }
        self.insert(
            key,
            Challenge {
                alternatives,
                seen_at: now,
            },
        );
        true
    }

    fn insert(&mut self, key: ChallengeKey, challenge: Challenge) {
        while self.by_key.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if oldest == key {
                continue;
            }
            self.by_key.remove(&oldest);
        }
        self.order.push_back(key.clone());
        self.by_key.insert(key, challenge);
    }

    /// What the origin demanded for this request, if we still hold it.
    ///
    /// Expired entries are dropped rather than returned. There is no variant
    /// meaning "I had one but it is old": the caller's next move is the same
    /// in both cases and a distinction that changes nothing is a distinction
    /// somebody eventually handles wrongly.
    pub fn get(&mut self, key: &ChallengeKey, now: Timestamp) -> Option<&Challenge> {
        let held = self.by_key.get(key)?;
        // A clock that has gone backwards produces no age at all, and that
        // counts as stale: the safe reading of "I cannot tell how old this
        // is" is to refuse the payment that needs it.
        let stale = now
            .as_millis()
            .checked_sub(held.seen_at.as_millis())
            .is_none_or(|age| age > self.ttl_ms);
        if stale {
            self.by_key.remove(key);
            return None;
        }
        self.by_key.get(key)
    }

    /// Drop everything past its time to live. Cheap to call periodically;
    /// correctness does not depend on it, because [`ChallengeStore::get`]
    /// checks anyway.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        let before = self.by_key.len();
        let ttl = self.ttl_ms;
        self.by_key.retain(|_, c| {
            now.as_millis()
                .checked_sub(c.seen_at.as_millis())
                .is_some_and(|age| age <= ttl)
        });
        before.saturating_sub(self.by_key.len())
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp(1_772_000_000_000);

    fn body(pay_to: &str, amount: &str) -> Vec<u8> {
        format!(
            r#"{{"x402Version":2,"accepts":[{{
                "scheme":"exact","network":"eip155:8453","amount":"{amount}",
                "asset":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                "payTo":"{pay_to}","maxTimeoutSeconds":60
            }}]}}"#
        )
        .into_bytes()
    }

    fn key(principal: &str) -> ChallengeKey {
        ChallengeKey::new(principal, "GET", "http://origin.example/report")
    }

    #[test]
    fn a_challenge_survives_until_its_ttl_and_not_past_it() {
        let mut s = ChallengeStore::new(60_000, 16);
        assert!(s.record_402(key("felix"), &body("0xaa", "1000"), NOW));

        assert!(s.get(&key("felix"), Timestamp(NOW.0 + 59_999)).is_some());
        assert!(s.get(&key("felix"), Timestamp(NOW.0 + 60_001)).is_none());
        assert!(s.is_empty(), "an expired entry is dropped, not kept");
    }

    #[test]
    fn one_callers_challenge_is_not_another_callers_demand() {
        let mut s = ChallengeStore::new(60_000, 16);
        s.record_402(key("felix"), &body("0xaa", "1000"), NOW);
        assert!(s.get(&key("ama"), NOW).is_none());
    }

    #[test]
    fn a_challenge_is_not_consumed_by_reading_it() {
        // A refused payment can be re-presented after approval. Replay of a
        // particular authorization is the nonce store's job, not this one's.
        let mut s = ChallengeStore::new(60_000, 16);
        s.record_402(key("felix"), &body("0xaa", "1000"), NOW);
        assert!(s.get(&key("felix"), NOW).is_some());
        assert!(s.get(&key("felix"), NOW).is_some());
    }

    #[test]
    fn a_body_that_is_not_a_challenge_records_nothing() {
        let mut s = ChallengeStore::new(60_000, 16);
        for junk in [
            &b"not json"[..],
            b"{}",
            br#"{"x402Version":2,"accepts":[]}"#,
            br#"{"x402Version":1,"accepts":[{"scheme":"exact","network":"n","amount":"1","asset":"0x1","payTo":"0x2"}]}"#,
        ] {
            assert!(!s.record_402(key("felix"), junk, NOW), "{junk:?}");
        }
        assert!(s.is_empty());
    }

    #[test]
    fn the_store_is_bounded_and_evicts_the_oldest() {
        let mut s = ChallengeStore::new(60_000, 3);
        for i in 0..5 {
            let k = ChallengeKey::new("felix", "GET", &format!("http://o.example/{i}"));
            s.record_402(k, &body("0xaa", "1000"), NOW);
        }
        assert_eq!(s.len(), 3);
        let gone = ChallengeKey::new("felix", "GET", "http://o.example/0");
        let kept = ChallengeKey::new("felix", "GET", "http://o.example/4");
        assert!(s.get(&gone, NOW).is_none(), "oldest evicted");
        assert!(s.get(&kept, NOW).is_some(), "newest kept");
    }

    #[test]
    fn re_recording_the_same_request_does_not_evict_itself() {
        // The eviction loop walks insertion order, which can contain a key
        // twice. Popping the key being written would delete the write.
        let mut s = ChallengeStore::new(60_000, 1);
        s.record_402(key("felix"), &body("0xaa", "1000"), NOW);
        s.record_402(key("felix"), &body("0xbb", "2000"), NOW);

        let c = s.get(&key("felix"), NOW).expect("still there");
        assert_eq!(c.alternatives[0].pay_to, "0xbb", "the newer demand wins");
    }

    #[test]
    fn alternatives_are_capped() {
        let one = r#"{"scheme":"exact","network":"eip155:8453","amount":"1",
            "asset":"0x83","payTo":"0xaa"}"#;
        let many = format!(
            r#"{{"x402Version":2,"accepts":[{}]}}"#,
            std::iter::repeat_n(one, MAX_ALTERNATIVES + 5)
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut s = ChallengeStore::new(60_000, 4);
        assert!(s.record_402(key("felix"), many.as_bytes(), NOW));
        assert_eq!(
            s.get(&key("felix"), NOW)
                .expect("recorded")
                .alternatives
                .len(),
            MAX_ALTERNATIVES
        );
    }

    #[test]
    fn sweeping_removes_exactly_what_has_expired() {
        let mut s = ChallengeStore::new(1_000, 16);
        s.record_402(key("felix"), &body("0xaa", "1"), NOW);
        s.record_402(key("ama"), &body("0xbb", "1"), Timestamp(NOW.0 + 900));

        assert_eq!(s.sweep(Timestamp(NOW.0 + 1_500)), 1);
        assert!(s.get(&key("ama"), Timestamp(NOW.0 + 1_500)).is_some());
    }
}
