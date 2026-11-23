//! Second-round review test (not part of the branch): the streaming root
//! against the tree on key sets built to be awkward.
use sha2::{Digest, Sha256};
use std::sync::Arc;
use timecurrency_v5::merkle::{self, Hash, Op, StreamingRoot};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn hash(&mut self) -> Hash {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_be_bytes());
        }
        out
    }
}
fn set_bit(key: &mut Hash, depth: usize, value: bool) {
    let mask = 0x80u8 >> (depth % 8);
    if value {
        key[depth / 8] |= mask;
    } else {
        key[depth / 8] &= !mask;
    }
}
/// Both roots for these key hashes; values of several lengths, some empty.
fn both(mut keys: Vec<Hash>) -> (Hash, Hash, usize) {
    keys.sort_unstable();
    keys.dedup();
    let value = |hash: &Hash| vec![hash[31]; (hash[30] as usize) % 5];
    let ops: Vec<Op> = keys
        .iter()
        .enumerate()
        .map(|(index, hash)| Op {
            key_hash: *hash,
            leaf: Some(merkle::new_leaf(&(index as u64).to_be_bytes(), *hash, Arc::from(value(hash)))),
        })
        .collect();
    let tree = merkle::update(&None, &ops).unwrap();
    merkle::verify_structure(&tree).unwrap();
    let mut stream = StreamingRoot::new();
    for hash in &keys {
        stream
            .push(hash, merkle::leaf_hash(hash, &merkle::value_hash(&value(hash))))
            .unwrap();
    }
    (merkle::root_hash(&tree), stream.finish(), keys.len())
}

#[test]
fn review2_the_streaming_root_agrees_with_the_tree_on_awkward_key_sets() {
    let mut rng = Rng(7);
    let mut sets = 0u64;
    let mut leaves = 0u64;
    let mut check = |keys: Vec<Hash>, what: &str| {
        let (tree, stream, count) = both(keys);
        assert_eq!(tree, stream, "{what}, {count} leaves");
        sets += 1;
        leaves += count as u64;
    };
    // Complete trees: every n-bit prefix once, with tails of zeros, of ones
    // and random: exactly 2^n leaves, n from 0 to 9.
    for n in 0..=9usize {
        for tail in 0..3 {
            let mut keys = Vec::new();
            for prefix in 0..1u64 << n {
                let mut key = match tail {
                    0 => [0u8; 32],
                    1 => [0xff; 32],
                    _ => rng.hash(),
                };
                for depth in 0..n {
                    set_bit(&mut key, depth, (prefix >> (n - 1 - depth)) & 1 == 1);
                }
                keys.push(key);
            }
            check(keys, "complete tree");
        }
    }
    // The same complete trees hanging below a shared prefix of p bits.
    for p in [1usize, 7, 8, 100, 246] {
        for n in [1usize, 2, 3, 8] {
            let base = rng.hash();
            let mut keys = Vec::new();
            for prefix in 0..1u64 << n {
                let mut key = base;
                for depth in 0..n {
                    set_bit(&mut key, p + depth, (prefix >> (n - 1 - depth)) & 1 == 1);
                }
                keys.push(key);
            }
            check(keys, "complete tree under a prefix");
        }
    }
    // Combs: a base key and, for every bit, the key that differs from it
    // first at that bit (rest equal, rest zero, rest one, rest random).
    for round in 0..8 {
        let base = match round {
            0 => [0u8; 32],
            1 => [0xff; 32],
            _ => rng.hash(),
        };
        for rest in 0..4 {
            let mut keys = vec![base];
            for depth in 0..256usize {
                let mut key = base;
                set_bit(&mut key, depth, !merkle::bit(&base, depth));
                for later in depth + 1..256 {
                    match rest {
                        0 => {}
                        1 => set_bit(&mut key, later, false),
                        2 => set_bit(&mut key, later, true),
                        _ => set_bit(&mut key, later, rng.next() & 1 == 1),
                    }
                }
                keys.push(key);
            }
            check(keys.clone(), "comb");
            // Every prefix of the sorted comb, and every suffix.
            keys.sort_unstable();
            keys.dedup();
            for cut in [1usize, 2, 3, 100, 255, 256] {
                if cut < keys.len() {
                    check(keys[..cut].to_vec(), "comb prefix");
                    check(keys[keys.len() - cut..].to_vec(), "comb suffix");
                }
            }
        }
    }
    // Random tries: each new key copies an earlier one up to a random bit
    // (often a deep one), parts there, and is random, equal, zero or one after.
    for round in 0..4000u64 {
        let count = 1 + (rng.next() % 60) as usize;
        let mut keys = vec![rng.hash()];
        while keys.len() < count {
            let parent = keys[(rng.next() % keys.len() as u64) as usize];
            let depth = match rng.next() % 4 {
                0 => (rng.next() % 8) as usize,
                1 => 248 + (rng.next() % 8) as usize,
                _ => (rng.next() % 256) as usize,
            };
            let mut key = parent;
            set_bit(&mut key, depth, !merkle::bit(&parent, depth));
            let mode = rng.next() % 4;
            for later in depth + 1..256 {
                match mode {
                    0 => {}
                    1 => set_bit(&mut key, later, false),
                    2 => set_bit(&mut key, later, true),
                    _ => set_bit(&mut key, later, rng.next() & 1 == 1),
                }
            }
            keys.push(key);
        }
        check(keys, &format!("random trie {round}"));
    }
    // Larger sets with real key hashes, as a state has them.
    for count in [1000usize, 5000, 20000] {
        let keys: Vec<Hash> = (0..count as u64)
            .map(|index| Sha256::digest(index.to_be_bytes()).into())
            .collect();
        check(keys, "hashed keys");
    }
    eprintln!("{sets} key sets, {leaves} leaves: the streaming root equals the root of the tree on all of them");
}

#[test]
fn review2_what_the_tree_refuses_the_stream_refuses() {
    let mut rng = Rng(11);
    let mut refused = 0;
    for _ in 0..2000 {
        let count = 2 + (rng.next() % 6) as usize;
        let mut keys: Vec<Hash> = (0..count).map(|_| rng.hash()).collect();
        keys.sort_unstable();
        // Out of order, or one key twice (sometimes neither: a == b).
        let a = (rng.next() % count as u64) as usize;
        let b = (rng.next() % count as u64) as usize;
        if rng.next() & 1 == 0 {
            keys.swap(a, b);
        } else {
            keys[a] = keys[b];
        }
        let ops: Vec<Op> = keys
            .iter()
            .map(|hash| Op {
                key_hash: *hash,
                leaf: Some(merkle::new_leaf(b"k", *hash, Arc::from(vec![1u8]))),
            })
            .collect();
        let tree = merkle::update(&None, &ops).is_ok();
        let mut stream = StreamingRoot::new();
        let streamed = keys.iter().all(|hash| stream.push(hash, [3; 32]).is_ok());
        assert_eq!(tree, streamed, "{keys:?}");
        refused += usize::from(!tree);
    }
    eprintln!("{refused} of 2000 sequences refused by both, the rest accepted by both");
}
