//! Stateless signature checks, done once per transaction and in parallel.
//!
//! Protocol 4 verified every signature again each time a block was executed
//! (proposal, validation, finalization) and inside every mempool check. The
//! check itself depends only on the transaction bytes, so its result can be
//! remembered. This module keeps the hashes of transactions whose signature
//! has verified, keyed by the SHA-256 of the complete signed bytes. A hit
//! means these exact bytes passed exactly this check before; nothing weaker
//! is ever recorded, and a miss only costs a verification.
//!
//! Account authority (is this key a device of the account, may it spend, is
//! the nonce right) depends on state and is always checked during execution.
use crate::wire;
use ed25519_dalek::{Signature, VerifyingKey};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::Mutex};

const SHARDS: usize = 16;
/// Entries per shard and generation. Two generations are kept, so at most
/// `2 * SHARDS * GENERATION` hashes (about one million) are held.
const GENERATION: usize = 32 * 1024;
const KEY_OFFSET: usize = wire::DOMAIN.len() + 32 + 1 + 24;

pub fn tx_hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}

/// The signature rule of protocol 4, shared by every signed action kind: the
/// 32-byte key in the header must be a canonical, non-weak Ed25519 key, and
/// the final 64 bytes must be its strict signature over everything before
/// them. Envelope bounds and payload rules are checked during execution.
/// No action is longer than this: header, the largest payload, signature.
pub const MAX_TX_BYTES: usize = wire::HEADER + wire::MAX_PAYLOAD + 64;

pub fn signature_valid(raw: &[u8]) -> bool {
    if raw.len() > MAX_TX_BYTES || raw.len() < wire::HEADER + 64 || !raw.starts_with(wire::DOMAIN) {
        return false;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw[KEY_OFFSET..KEY_OFFSET + 32]);
    // RFC 8032: the encoded y-coordinate must be below 2^255 - 19, so that one
    // authority has exactly one encoding.
    let mut coordinate = key;
    coordinate[31] &= 0x7f;
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if coordinate.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    if key.is_weak() {
        return false;
    }
    let split = raw.len() - 64;
    let Ok(signature) = Signature::from_slice(&raw[split..]) else {
        return false;
    };
    key.verify_strict(&raw[..split], &signature).is_ok()
}

/// What is known about a transaction's signature when it is executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigStatus {
    /// These exact bytes passed `signature_valid`.
    Valid,
    /// These exact bytes failed `signature_valid`.
    Invalid,
    /// Not checked yet; execution verifies inline.
    Unknown,
}

#[derive(Default)]
struct Shard {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

pub struct SigCache {
    shards: Vec<Mutex<Shard>>,
}

impl Default for SigCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SigCache {
    pub fn new() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
        }
    }

    fn shard(&self, hash: &[u8; 32]) -> &Mutex<Shard> {
        &self.shards[hash[0] as usize % SHARDS]
    }

    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        // A poisoned shard only means a verification is repeated.
        self.shard(hash)
            .lock()
            .is_ok_and(|shard| shard.current.contains(hash) || shard.previous.contains(hash))
    }

    /// Records that the transaction with this hash passed `signature_valid`.
    fn insert_verified(&self, hash: [u8; 32]) {
        if let Ok(mut shard) = self.shard(&hash).lock() {
            if shard.current.len() >= GENERATION {
                shard.previous = std::mem::take(&mut shard.current);
            }
            shard.current.insert(hash);
        }
    }

    /// Checks one transaction, verifying only if it has not verified before.
    pub fn check(&self, raw: &[u8]) -> SigStatus {
        // Bytes that cannot be an action are refused before anything is hashed.
        if raw.len() > MAX_TX_BYTES {
            return SigStatus::Invalid;
        }
        let hash = tx_hash(raw);
        if self.contains(&hash) {
            SigStatus::Valid
        } else if signature_valid(raw) {
            self.insert_verified(hash);
            SigStatus::Valid
        } else {
            SigStatus::Invalid
        }
    }

    /// Checks a whole block on all cores. Returns each transaction's status,
    /// in block order.
    pub fn check_all<T: AsRef<[u8]> + Sync>(&self, txs: &[T]) -> Vec<SigStatus> {
        txs.par_iter().map(|tx| self.check(tx.as_ref())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(seed: u8, payload: &[u8]) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut raw = wire::DOMAIN.to_vec();
        raw.extend_from_slice(&[7; 32]);
        raw.push(3);
        raw.extend_from_slice(&[0; 24]);
        raw.extend_from_slice(key.verifying_key().as_bytes());
        raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        raw.extend_from_slice(payload);
        let signature = key.sign(&raw).to_bytes();
        raw.extend_from_slice(&signature);
        raw
    }

    #[test]
    fn only_exact_verified_bytes_are_remembered() {
        let cache = SigCache::new();
        let good = signed(1, b"{}");
        assert!(signature_valid(&good));
        assert_eq!(cache.check(&good), SigStatus::Valid);
        assert!(cache.contains(&tx_hash(&good)));
        // Any change to the bytes is a different transaction and fails.
        for index in [0, 20, KEY_OFFSET, wire::HEADER, good.len() - 1] {
            let mut bad = good.clone();
            bad[index] ^= 1;
            assert!(!cache.contains(&tx_hash(&bad)));
            assert_eq!(cache.check(&bad), SigStatus::Invalid);
            assert!(!cache.contains(&tx_hash(&bad)), "a failure must never be cached");
        }
        // Too short, wrong domain, zero key, zero signature.
        assert!(!signature_valid(&good[..wire::HEADER + 63]));
        let mut zero_key = good.clone();
        zero_key[KEY_OFFSET..KEY_OFFSET + 32].fill(0);
        assert!(!signature_valid(&zero_key));
        let mut zero_signature = good.clone();
        let split = zero_signature.len() - 64;
        zero_signature[split..].fill(0);
        assert!(!signature_valid(&zero_signature));
    }

    #[test]
    fn block_check_matches_single_checks_and_keeps_order() {
        let cache = SigCache::new();
        let mut txs: Vec<Vec<u8>> = (1..=40).map(|seed| signed(seed, b"{\"a\":\"1\"}")).collect();
        txs[7][wire::HEADER] ^= 1;
        let last = txs[19].len() - 1;
        txs[19][last] ^= 0x80;
        // Longer than any action: refused without being hashed or verified.
        txs.push(vec![0x54; MAX_TX_BYTES + 1]);
        let result = cache.check_all(&txs);
        for (index, status) in result.iter().enumerate() {
            let expected = if index == 7 || index == 19 || index == 40 {
                SigStatus::Invalid
            } else {
                SigStatus::Valid
            };
            assert_eq!(*status, expected, "transaction {index}");
        }
        // A second pass is served from the cache with the same answers.
        assert_eq!(cache.check_all(&txs), result);
    }

    #[test]
    fn old_generations_are_dropped_not_grown() {
        let cache = SigCache::new();
        for index in 0u32..(SHARDS * GENERATION * 3) as u32 {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&index.to_le_bytes());
            cache.insert_verified(hash);
        }
        let held: usize = cache
            .shards
            .iter()
            .map(|shard| {
                let shard = shard.lock().unwrap();
                shard.current.len() + shard.previous.len()
            })
            .sum();
        assert!(held <= 2 * SHARDS * GENERATION);
    }
}
