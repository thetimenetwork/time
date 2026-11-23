//! The in-memory tree must be indistinguishable from JMT 0.12 with SHA-256:
//! same root after every batch, and the same proof bytes for every key.
use jmt::{JellyfishMerkleTree, KeyHash, RootHash, mock::MockTreeStore, proof::SparseMerkleProof};
use sha2_10::Sha256;
use std::{collections::BTreeMap, sync::Arc};
use timecurrency_v5::{merkle, proof};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64: deterministic and good enough to shape test data.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Applies the same batches to JMT and to our tree and compares everything
/// a light client could observe.
fn compare(mut batch_for: impl FnMut(u64, &BTreeMap<[u8; 32], Vec<u8>>) -> Vec<([u8; 32], Option<Vec<u8>>)>, versions: u64, extra_probes: &[[u8; 32]]) {
    let store = MockTreeStore::default();
    let jmt = JellyfishMerkleTree::<_, Sha256>::new(&store);
    let mut ours: merkle::Link = None;
    let mut live: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    let mut ever: Vec<[u8; 32]> = Vec::new();
    for version in 0..versions {
        let batch = batch_for(version, &live);
        let (root, update) = jmt
            .put_value_set(
                batch.iter().map(|(hash, value)| (KeyHash(*hash), value.clone())),
                version,
            )
            .unwrap();
        store.write_tree_update_batch(update).unwrap();
        let mut ops: Vec<merkle::Op> = batch
            .iter()
            .map(|(hash, value)| merkle::Op {
                key_hash: *hash,
                leaf: value
                    .as_ref()
                    .map(|bytes| merkle::new_leaf(hash, *hash, Arc::from(bytes.as_slice()))),
            })
            .collect();
        ops.sort_by(|a, b| a.key_hash.cmp(&b.key_hash));
        let previous = ours.clone();
        ours = merkle::update(&ours, &ops).unwrap();
        for (hash, value) in &batch {
            match value {
                Some(bytes) => {
                    live.insert(*hash, bytes.clone());
                    ever.push(*hash);
                }
                None => {
                    live.remove(hash);
                }
            }
        }
        assert_eq!(merkle::root_hash(&ours), root.0, "root at version {version}");
        assert_eq!(merkle::leaf_count(&ours), live.len() as u64);
        merkle::verify_structure(&ours).unwrap();
        // The previous version is untouched by the update (copy-on-write).
        if version > 0 {
            let old_root = jmt.get_root_hash(version - 1).unwrap();
            assert_eq!(merkle::root_hash(&previous), old_root.0);
        }
        // Probe present keys, deleted keys and keys that never existed.
        let mut probes: Vec<[u8; 32]> = batch.iter().map(|(hash, _)| *hash).collect();
        probes.extend(live.keys().take(40).copied());
        probes.extend(ever.iter().rev().take(40).copied());
        probes.extend_from_slice(extra_probes);
        for hash in probes {
            let (jmt_value, jmt_proof) = jmt.get_with_proof(KeyHash(hash), version).unwrap();
            let (our_value, our_proof) = merkle::prove(&ours, &hash);
            assert_eq!(jmt_value.as_deref(), our_value.as_deref());
            assert_eq!(our_value.as_deref().map(<[u8]>::to_vec), live.get(&hash).cloned());
            merkle::verify(&our_proof, &root.0, &hash, our_value.as_deref()).unwrap();
            let ours_json =
                serde_json::to_string(&proof::SparseMerkleProof::from(our_proof)).unwrap();
            assert_eq!(serde_json::to_string(&jmt_proof).unwrap(), ours_json);
            // Our bytes are accepted by JMT's own verifier.
            let parsed: SparseMerkleProof<Sha256> = serde_json::from_str(&ours_json).unwrap();
            parsed
                .verify(RootHash(root.0), KeyHash(hash), jmt_value.as_deref())
                .unwrap();
        }
    }
}

#[test]
fn random_keys_match_jmt_across_versions() {
    let mut rng = Rng(7);
    let pool: Vec<[u8; 32]> = (0..3000u32)
        .map(|index| proof::key_hash(&index.to_be_bytes()))
        .collect();
    let anchor = proof::key_hash(b"meta");
    let absent: Vec<[u8; 32]> = (0..25u32)
        .map(|index| proof::key_hash(format!("never-{index}").as_bytes()))
        .collect();
    compare(
        |version, live| {
            let mut batch: BTreeMap<[u8; 32], Option<Vec<u8>>> = BTreeMap::new();
            // Like the real store, one row is rewritten in every version.
            batch.insert(anchor, Some(version.to_be_bytes().to_vec()));
            let size = 1 + rng.below(if version % 9 == 0 { 600 } else { 60 });
            for _ in 0..size {
                let key = pool[rng.below(pool.len() as u64) as usize];
                let delete = live.contains_key(&key) && rng.below(3) == 0;
                let value = (!delete).then(|| {
                    let length = 1 + rng.below(300) as usize;
                    (0..length).map(|_| rng.next() as u8).collect()
                });
                batch.insert(key, value);
            }
            batch.into_iter().collect()
        },
        70,
        &absent,
    );
}

#[test]
fn keys_with_long_shared_prefixes_match_jmt() {
    // Key hashes that agree on many leading bits exercise chains of
    // single-child internal nodes, leaves moving up after deletions, and
    // every nibble boundary of the 16-ary layout JMT uses.
    let mut rng = Rng(99);
    let mut pool: Vec<[u8; 32]> = Vec::new();
    for family in 0u8..6 {
        let mut base = [0u8; 32];
        base[0] = family.wrapping_mul(41);
        for _ in 0..60 {
            let mut hash = base;
            // Flip one bit at a random depth and randomize everything after it.
            let depth = rng.below(250) as usize;
            hash[depth / 8] ^= 0x80 >> (depth % 8);
            for index in (depth / 8 + 1)..32 {
                hash[index] = rng.next() as u8;
            }
            pool.push(hash);
        }
        pool.push(base);
    }
    pool.sort();
    pool.dedup();
    let anchor = [0xffu8; 32];
    let probes: Vec<[u8; 32]> = (0..40)
        .map(|_| {
            let mut hash = pool[rng.below(pool.len() as u64) as usize];
            hash[31] ^= 1;
            hash[20] ^= rng.next() as u8;
            hash
        })
        .filter(|hash| !pool.contains(hash))
        .collect();
    compare(
        |version, live| {
            let mut batch: BTreeMap<[u8; 32], Option<Vec<u8>>> = BTreeMap::new();
            batch.insert(anchor, Some(vec![version as u8]));
            let size = 1 + rng.below(40);
            for _ in 0..size {
                let key = pool[rng.below(pool.len() as u64) as usize];
                let delete = live.contains_key(&key) && rng.below(2) == 0;
                batch.insert(key, (!delete).then(|| vec![rng.next() as u8; 3]));
            }
            // Now and then remove almost everything, so leaves collapse upward.
            if version % 13 == 12 {
                for key in live.keys().filter(|key| **key != anchor).take(live.len() - 2) {
                    batch.insert(*key, None);
                }
            }
            batch.into_iter().collect()
        },
        80,
        &probes,
    );
}

#[test]
fn store_proof_entries_verify_with_the_jmt_verifier() {
    // End to end through the store API the node serves queries from.
    let directory = tempfile::tempdir().unwrap();
    let store = timecurrency_v5::store::Store::open(directory.path()).unwrap();
    let mut updates: Vec<(Vec<u8>, Option<Vec<u8>>)> = (0u32..500)
        .map(|index| {
            (
                format!("account/{index}").into_bytes(),
                Some(format!("{{\"id\":\"{index}\"}}").into_bytes()),
            )
        })
        .collect();
    updates.push((b"meta".to_vec(), Some(b"{}".to_vec())));
    let mut prepared = store.prepare(None, 0, updates).unwrap();
    prepared.set_head_metadata(b"{}".to_vec(), [0; 32]).unwrap();
    let head = store.commit(prepared).unwrap();
    let version = store.current().unwrap().unwrap();
    for key in [&b"account/7"[..], b"account/499", b"meta", b"account/500", b"name/x"] {
        let entry = version.proof(key).unwrap();
        let json = serde_json::to_value(&entry).unwrap();
        let jmt_proof: SparseMerkleProof<Sha256> =
            serde_json::from_value(json["proof"].clone()).unwrap();
        let value = version.get(key);
        jmt_proof
            .verify(
                RootHash(head.root),
                KeyHash(proof::key_hash(key)),
                value.as_deref(),
            )
            .unwrap();
    }
}

#[test]
fn edge_cases_and_old_versions_match_jmt() {
    // Deleting keys that are absent, a tree that empties and refills, a single
    // leaf, empty values, and key hashes that share up to 255 leading bits.
    // Afterwards every version is proven again: old versions stay intact.
    let a = [0x11u8; 32];
    let mut b = a;
    b[31] ^= 1;
    let mut c = a;
    c[30] ^= 0x80;
    let mut d = a;
    d[10] ^= 0x01;
    let never = [0x77u8; 32];
    let script: Vec<Vec<([u8; 32], Option<Vec<u8>>)>> = vec![
        vec![(a, Some(vec![]))],
        vec![(never, None)],
        vec![(b, Some(vec![1])), (c, Some(vec![2])), (d, Some(vec![3]))],
        vec![(never, None), (b, None)],
        vec![(c, None), (d, None)],
        vec![(a, None)],
        vec![(never, None)],
        vec![(a, Some(vec![9])), (b, Some(vec![]))],
        vec![(a, Some(vec![9])), (b, None), (c, Some(vec![7; 300]))],
    ];
    let probes = [never, a, b, c, d];
    let store = MockTreeStore::default();
    let jmt = JellyfishMerkleTree::<_, Sha256>::new(&store);
    let mut versions: Vec<(merkle::Link, [u8; 32])> = Vec::new();
    let mut ours: merkle::Link = None;
    for (version, batch) in script.iter().enumerate() {
        let (root, update) = jmt
            .put_value_set(
                batch.iter().map(|(hash, value)| (KeyHash(*hash), value.clone())),
                version as u64,
            )
            .unwrap();
        store.write_tree_update_batch(update).unwrap();
        let mut ops: Vec<merkle::Op> = batch
            .iter()
            .map(|(hash, value)| merkle::Op {
                key_hash: *hash,
                leaf: value
                    .as_ref()
                    .map(|bytes| merkle::new_leaf(hash, *hash, Arc::from(bytes.as_slice()))),
            })
            .collect();
        ops.sort_by(|x, y| x.key_hash.cmp(&y.key_hash));
        ours = merkle::update(&ours, &ops).unwrap();
        assert_eq!(merkle::root_hash(&ours), root.0, "root at version {version}");
        merkle::verify_structure(&ours).unwrap();
        versions.push((ours.clone(), root.0));
    }
    // The tree was empty after version 5 and 6.
    assert_eq!(versions[5].1, merkle::PLACEHOLDER);
    assert_eq!(versions[6].1, merkle::PLACEHOLDER);
    assert_eq!(merkle::leaf_count(&versions[0].0), 1);
    for (version, (tree, root)) in versions.iter().enumerate() {
        for hash in probes {
            let (jmt_value, jmt_proof) = jmt.get_with_proof(KeyHash(hash), version as u64).unwrap();
            let (our_value, our_proof) = merkle::prove(tree, &hash);
            assert_eq!(jmt_value.as_deref(), our_value.as_deref(), "value at version {version}");
            merkle::verify(&our_proof, root, &hash, our_value.as_deref()).unwrap();
            let ours_json = serde_json::to_string(&proof::SparseMerkleProof::from(our_proof)).unwrap();
            assert_eq!(serde_json::to_string(&jmt_proof).unwrap(), ours_json, "proof at version {version}");
            let parsed: SparseMerkleProof<Sha256> = serde_json::from_str(&ours_json).unwrap();
            parsed
                .verify(RootHash(*root), KeyHash(hash), jmt_value.as_deref())
                .unwrap();
        }
    }
}
