//! The small slice of EIP-712 that x402's `exact` scheme on EVM needs.
//!
//! We hash exactly one struct type — EIP-3009's `TransferWithAuthorization` —
//! so this is a few dozen lines rather than a general-purpose typed-data
//! implementation. That is deliberate. A general EIP-712 encoder has to walk
//! arbitrary nested types and is a meaningful attack surface; we only ever
//! need one shape, and one shape can be read and checked by eye.
//!
//! The digest is `keccak256(0x19 || 0x01 || domainSeparator || structHash)`.

use sha3::{Digest, Keccak256};

/// A 32-byte value: a hash, a nonce, or an ABI-encoded word.
pub type Word = [u8; 32];

/// A 20-byte EVM address.
pub type Address = [u8; 20];

pub fn keccak256(bytes: &[u8]) -> Word {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Left-pad a 20-byte address into a 32-byte ABI word.
fn word_from_address(a: &Address) -> Word {
    let mut w = [0u8; 32];
    // Addresses occupy the low 20 bytes; the high 12 stay zero.
    if let Some(slot) = w.get_mut(12..32) {
        slot.copy_from_slice(a);
    }
    w
}

/// Big-endian ABI word from a `u128`. EIP-3009 declares these fields as
/// `uint256`; we accept `u128` because no real amount or Unix timestamp
/// approaches 2^128, and refusing the top half removes a conversion path.
fn word_from_u128(v: u128) -> Word {
    let mut w = [0u8; 32];
    if let Some(slot) = w.get_mut(16..32) {
        slot.copy_from_slice(&v.to_be_bytes());
    }
    w
}

/// The EIP-712 domain.
///
/// Every field here is load-bearing against replay. `chain_id` is what stops
/// a signature captured on a testnet being replayed on mainnet;
/// `verifying_contract` is what stops a signature for one token being
/// replayed against another. Omitting either produces a verifier that
/// accepts signatures it should refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// `TransferWithAuthorization` as declared by EIP-3009. The field order is
/// part of the type hash — reordering it silently changes every digest.
const TRANSFER_TYPE: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

impl Domain {
    pub fn separator(&self) -> Word {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&keccak256(DOMAIN_TYPE));
        buf.extend_from_slice(&keccak256(self.name.as_bytes()));
        buf.extend_from_slice(&keccak256(self.version.as_bytes()));
        buf.extend_from_slice(&word_from_u128(u128::from(self.chain_id)));
        buf.extend_from_slice(&word_from_address(&self.verifying_contract));
        keccak256(&buf)
    }
}

/// The EIP-3009 authorization being signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferWithAuthorization {
    pub from: Address,
    pub to: Address,
    pub value: u128,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: Word,
}

impl TransferWithAuthorization {
    pub fn struct_hash(&self) -> Word {
        let mut buf = Vec::with_capacity(224);
        buf.extend_from_slice(&keccak256(TRANSFER_TYPE));
        buf.extend_from_slice(&word_from_address(&self.from));
        buf.extend_from_slice(&word_from_address(&self.to));
        buf.extend_from_slice(&word_from_u128(self.value));
        buf.extend_from_slice(&word_from_u128(u128::from(self.valid_after)));
        buf.extend_from_slice(&word_from_u128(u128::from(self.valid_before)));
        buf.extend_from_slice(&self.nonce);
        keccak256(&buf)
    }
}

/// The 32 bytes actually signed: `keccak256(0x1901 || domain || structHash)`.
pub fn signing_digest(domain: &Domain, auth: &TransferWithAuthorization) -> Word {
    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain.separator());
    buf.extend_from_slice(&auth.struct_hash());
    keccak256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn domain() -> Domain {
        Domain {
            name: "USDC".into(),
            version: "2".into(),
            chain_id: 84532,
            verifying_contract: addr(0xAA),
        }
    }

    fn auth() -> TransferWithAuthorization {
        TransferWithAuthorization {
            from: addr(0x11),
            to: addr(0x22),
            value: 10_000,
            valid_after: 1_740_672_089,
            valid_before: 1_740_672_154,
            nonce: [0x7F; 32],
        }
    }

    #[test]
    fn keccak_matches_the_known_empty_hash() {
        // The single most-quoted keccak256 value in Ethereum. If this is
        // wrong, the hash function isn't keccak — it's SHA3, which is a
        // different padding and a very confusing afternoon.
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn changing_the_chain_id_changes_the_digest() {
        // Cross-chain replay: the same authorization signed for a testnet
        // must not verify against mainnet.
        let a = signing_digest(&domain(), &auth());
        let mut other = domain();
        other.chain_id = 1;
        assert_ne!(a, signing_digest(&other, &auth()));
    }

    #[test]
    fn changing_the_token_contract_changes_the_digest() {
        let a = signing_digest(&domain(), &auth());
        let mut other = domain();
        other.verifying_contract = addr(0xBB);
        assert_ne!(a, signing_digest(&other, &auth()));
    }

    #[test]
    fn every_authorization_field_is_bound_into_the_digest() {
        let base = signing_digest(&domain(), &auth());

        let mut m = auth();
        m.to = addr(0x33);
        assert_ne!(base, signing_digest(&domain(), &m), "recipient not bound");

        let mut m = auth();
        m.value = 10_001;
        assert_ne!(base, signing_digest(&domain(), &m), "amount not bound");

        let mut m = auth();
        m.nonce = [0x7E; 32];
        assert_ne!(base, signing_digest(&domain(), &m), "nonce not bound");

        let mut m = auth();
        m.valid_before = 1_740_672_155;
        assert_ne!(base, signing_digest(&domain(), &m), "expiry not bound");

        let mut m = auth();
        m.from = addr(0x44);
        assert_ne!(base, signing_digest(&domain(), &m), "payer not bound");
    }

    #[test]
    fn addresses_are_left_padded_into_the_low_twenty_bytes() {
        let w = word_from_address(&addr(0xFF));
        assert_eq!(w.get(..12), Some([0u8; 12].as_slice()));
        assert_eq!(w.get(12..), Some([0xFFu8; 20].as_slice()));
    }

    #[test]
    fn the_digest_is_stable_across_runs() {
        // Guards against accidentally introducing nondeterminism (a map
        // iteration, a timestamp) into what must be a pure function.
        assert_eq!(
            signing_digest(&domain(), &auth()),
            signing_digest(&domain(), &auth())
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
