//! Whole-tree authentication followed by fast semantic scans of one immutable
//! snapshot. Uses upstream JMT hashes, never a new commitment construction.
use super::*;
use std::collections::VecDeque;

// Fixed entry count, independent of registry size. JMT nodes have at most 16
// children and key paths at most 64 nibbles. Cache only immutable decoded nodes.
const AUDIT_NODE_CACHE: usize = 4096;
struct AuditNodeCache<'a> {
    snapshot: &'a Snapshot,
    nodes: BTreeMap<NodeKey, Node>,
    fifo: VecDeque<NodeKey>,
}
impl<'a> AuditNodeCache<'a> {
    fn new(snapshot: &'a Snapshot) -> Self {
        Self {
            snapshot,
            nodes: BTreeMap::new(),
            fifo: VecDeque::new(),
        }
    }
    fn get(&mut self, key: &NodeKey) -> Result<&Node> {
        if !self.nodes.contains_key(key) {
            let node = self
                .snapshot
                .get_node_option(key)?
                .context("missing authenticated audit path")?;
            if self.nodes.len() == AUDIT_NODE_CACHE {
                let oldest = self
                    .fifo
                    .pop_front()
                    .context("audit cache queue mismatch")?;
                self.nodes.remove(&oldest);
            }
            self.nodes.insert(key.clone(), node);
            self.fifo.push_back(key.clone());
        }
        self.nodes.get(key).context("audit cache insert missing")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuditStorageProgress {
    pub phase: &'static str,
    pub processed: u64,
    pub total: Option<u64>,
}

/// Constructible only after every tree node/value and the complete raw-key
/// directory have been authenticated. No writer can alter the pinned snapshot.
pub struct VerifiedAudit<'a> {
    snapshot: &'a Snapshot,
    leaf_count: u64,
    tree_nodes: u64,
}

impl Snapshot {
    pub fn audit_verified(
        &self,
        mut progress: impl FnMut(AuditStorageProgress),
    ) -> Result<VerifiedAudit<'_>> {
        let head = self
            .head
            .as_ref()
            .context("audit requires an initialized store")?;
        let root_key = NodeKey::new(head.version, std::iter::empty().collect());
        let mut stack = vec![(root_key, head.root, None)];
        let mut leaf_count = 0u64;
        let mut nodes = 0u64;
        progress(AuditStorageProgress {
            phase: "tree",
            processed: 0,
            total: None,
        });
        while let Some((key, expected_hash, expected_shape)) = stack.pop() {
            ensure!(
                key.nibble_path().num_nibbles() <= 64,
                "JMT path exceeds key length"
            );
            let node = self
                .get_node_option(&key)?
                .context("missing reachable JMT audit node")?;
            if let Some(expected) = expected_shape {
                let actual = match &node {
                    Node::Internal(internal) => Some((false, internal.leaf_count())),
                    Node::Leaf(_) => Some((true, 1)),
                    Node::Null => None,
                };
                ensure!(
                    actual == Some(expected),
                    "JMT child type or subtree leaf count mismatch"
                );
            }
            let actual = match &node {
                Node::Internal(internal) => internal.hash::<Sha256>(),
                Node::Leaf(leaf) => leaf.hash::<Sha256>(),
                Node::Null => JellyfishMerkleTree::<Snapshot, Sha256>::EMPTY_ROOT.0,
            };
            ensure!(
                actual == expected_hash,
                "reachable JMT audit node hash mismatch"
            );
            nodes = nodes.checked_add(1).context("audit node count overflow")?;
            match node {
                Node::Internal(internal) => {
                    ensure!(
                        key.nibble_path().num_nibbles() < 64,
                        "internal node below key length"
                    );
                    let mut children = 0;
                    let mut child_leaves = 0usize;
                    for (nibble, child) in internal.children_sorted() {
                        ensure!(child.version <= head.version, "future JMT child version");
                        let path = key
                            .nibble_path()
                            .nibbles()
                            .chain(std::iter::once(nibble))
                            .collect();
                        stack.push((
                            NodeKey::new(child.version, path),
                            child.hash,
                            Some((child.is_leaf(), child.leaf_count())),
                        ));
                        children += 1;
                        child_leaves = child_leaves
                            .checked_add(child.leaf_count())
                            .context("JMT child leaf count overflow")?;
                    }
                    ensure!(children > 0, "empty internal JMT node");
                    // JMT 0.12 does not expose this cached auxiliary count.
                    // Its serde representation is pinned by Cargo.lock; this
                    // storage-shape check adds no commitment/hash construction.
                    let shape = serde_json::to_value(&internal)?;
                    ensure!(
                        shape["children"]["num_children"].as_u64() == Some(children),
                        "JMT cached child count mismatch"
                    );
                    ensure!(
                        child_leaves == internal.leaf_count(),
                        "JMT internal cached leaf count mismatch"
                    );
                    ensure!(
                        children != 1
                            || internal
                                .children_sorted()
                                .all(|(_, child)| !child.is_leaf()),
                        "noncanonical single-leaf internal node"
                    );
                }
                Node::Leaf(leaf) => {
                    let hash = leaf.key_hash();
                    for (position, nibble) in key.nibble_path().nibbles().enumerate() {
                        let byte = hash.0[position / 2];
                        let expected = if position.is_multiple_of(2) {
                            byte >> 4
                        } else {
                            byte & 15
                        };
                        ensure!(
                            u8::from(nibble) == expected,
                            "JMT leaf lies outside its key path"
                        );
                    }
                    let value = self
                        .get_value_option(head.version, hash)?
                        .context("reachable JMT leaf has no value")?;
                    ensure!(value.len() <= MAX_VALUE_BYTES, "audit value too large");
                    let reconstructed = LeafNode::new(hash, jmt::ValueHash::with::<Sha256>(&value));
                    ensure!(
                        reconstructed.hash::<Sha256>() == leaf.hash::<Sha256>(),
                        "JMT leaf/value audit mismatch"
                    );
                    leaf_count = leaf_count
                        .checked_add(1)
                        .context("audit leaf count overflow")?;
                }
                Node::Null => ensure!(key.nibble_path().num_nibbles() == 0, "null JMT child"),
            }
            if nodes.is_multiple_of(10_000) {
                progress(AuditStorageProgress {
                    phase: "tree",
                    processed: nodes,
                    total: None,
                });
            }
        }
        progress(AuditStorageProgress {
            phase: "tree",
            processed: nodes,
            total: Some(nodes),
        });
        let table = self.read.open_table(ROWS)?;
        ensure!(
            table.len()? == leaf_count,
            "raw directory/JMT leaf count mismatch"
        );
        progress(AuditStorageProgress {
            phase: "directory",
            processed: 0,
            total: Some(leaf_count),
        });
        let mut rows = 0u64;
        let mut cache = AuditNodeCache::new(self);
        for entry in table.iter()? {
            let (key, value) = entry?;
            ensure!(
                !key.value().is_empty() && key.value().len() <= MAX_KEY_BYTES,
                "audit raw key limit"
            );
            let hash = key_hash(key.value());
            ensure!(
                self.audit_contains(hash, &mut cache)?,
                "raw directory has no reachable JMT leaf"
            );
            let authenticated = self
                .get_value_option(head.version, hash)?
                .context("raw row missing authenticated value")?;
            ensure!(
                authenticated == value.value(),
                "raw directory/value audit mismatch"
            );
            rows += 1;
            if rows.is_multiple_of(10_000) {
                progress(AuditStorageProgress {
                    phase: "directory",
                    processed: rows,
                    total: Some(leaf_count),
                });
            }
        }
        ensure!(
            rows == leaf_count,
            "audit directory changed within snapshot"
        );
        progress(AuditStorageProgress {
            phase: "directory",
            processed: rows,
            total: Some(rows),
        });
        Ok(VerifiedAudit {
            snapshot: self,
            leaf_count,
            tree_nodes: nodes,
        })
    }

    // JMT::get() reads only the MVCC value table: it does not test active tree
    // membership. Walk the already fully authenticated tree here instead.
    fn audit_contains(&self, hash: KeyHash, cache: &mut AuditNodeCache<'_>) -> Result<bool> {
        let head = self.head.as_ref().context("audit requires head")?;
        let mut key = NodeKey::new(head.version, std::iter::empty().collect());
        for _ in 0..=64 {
            match cache.get(&key)? {
                Node::Leaf(leaf) => return Ok(leaf.key_hash() == hash),
                Node::Null => return Ok(false),
                Node::Internal(internal) => {
                    let depth = key.nibble_path().num_nibbles();
                    ensure!(depth < 64, "audit path exhausted");
                    let byte = hash.0[depth / 2];
                    let nibble = if depth.is_multiple_of(2) {
                        byte >> 4
                    } else {
                        byte & 15
                    };
                    let Some(child) = internal.child(nibble.into()) else {
                        return Ok(false);
                    };
                    let path = key
                        .nibble_path()
                        .nibbles()
                        .chain(std::iter::once(nibble.into()))
                        .collect();
                    key = NodeKey::new(child.version, path);
                }
            }
        }
        bail!("audit tree depth exceeded")
    }
}

impl VerifiedAudit<'_> {
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
    pub fn tree_nodes(&self) -> u64 {
        self.tree_nodes
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .snapshot
            .read
            .open_table(ROWS)?
            .get(key)?
            .map(|v| v.value().to_vec()))
    }
    pub fn for_each_prefix(
        &self,
        prefix: &[u8],
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        let table = self.snapshot.read.open_table(ROWS)?;
        for item in table.range(prefix..)? {
            let (key, value) = item?;
            if !key.value().starts_with(prefix) {
                break;
            }
            visitor(key.value(), value.value())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initialized() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("audit.redb")).unwrap();
        let meta = b"{}".to_vec();
        let mut prepared = store
            .prepare_updates(
                0,
                vec![
                    (META_KEY.to_vec(), Some(meta.clone())),
                    (b"name/alice".to_vec(), Some(b"1".to_vec())),
                ],
            )
            .unwrap();
        prepared.set_head_metadata(meta, [0; 32]).unwrap();
        store.commit(prepared).unwrap();
        (dir, store)
    }
    #[test]
    fn complete_tree_and_directory_are_authenticated_before_fast_reads() {
        let (_dir, store) = initialized();
        let snapshot = store.snapshot().unwrap();
        let verified = snapshot.audit_verified(|_| {}).unwrap();
        assert_eq!(verified.leaf_count(), 2);
        assert_eq!(verified.get(b"name/alice").unwrap(), Some(b"1".to_vec()));
        assert!(verified.get(b"name/missing").unwrap().is_none());
    }
    #[test]
    fn missing_raw_alias_cannot_hide_a_reachable_tree_leaf() {
        let (_dir, store) = initialized();
        let write = store.db.begin_write().unwrap();
        write
            .open_table(ROWS)
            .unwrap()
            .remove(b"name/alice".as_slice())
            .unwrap();
        write.commit().unwrap();
        assert!(store.snapshot().unwrap().audit_verified(|_| {}).is_err());
    }
    #[test]
    fn orphan_raw_alias_cannot_replace_a_live_alias_at_equal_cardinality() {
        let (_dir, store) = initialized();
        let write = store.db.begin_write().unwrap();
        {
            let mut rows = write.open_table(ROWS).unwrap();
            rows.remove(b"name/alice".as_slice()).unwrap();
            rows.insert(b"name/orphan".as_slice(), b"1".as_slice())
                .unwrap();
            // A stale or fabricated MVCC value is not active tree membership.
            // This prevents accidentally replacing audit_contains with the
            // upstream get() convenience function, which reads MVCC only.
            let key = value_key(key_hash(b"name/orphan"), 0);
            write
                .open_table(VALUES)
                .unwrap()
                .insert(key.as_slice(), encode_value(Some(b"1")).as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert!(store.snapshot().unwrap().audit_verified(|_| {}).is_err());
    }
    #[test]
    fn reachable_node_corruption_is_detected_even_outside_metadata_path() {
        let (_dir, store) = initialized();
        let write = store.db.begin_write().unwrap();
        {
            let mut nodes = write.open_table(NODES).unwrap();
            let changed = nodes
                .iter()
                .unwrap()
                .find_map(|entry| {
                    let (key, value) = entry.unwrap();
                    let node: Node = borsh::from_slice(value.value()).unwrap();
                    match node {
                        Node::Leaf(leaf) if leaf.key_hash() == key_hash(b"name/alice") => Some((
                            key.value().to_vec(),
                            Node::Leaf(LeafNode::new(
                                leaf.key_hash(),
                                jmt::ValueHash::with::<Sha256>(b"tampered"),
                            )),
                        )),
                        _ => None,
                    }
                })
                .unwrap();
            nodes
                .insert(
                    changed.0.as_slice(),
                    borsh::to_vec(&changed.1).unwrap().as_slice(),
                )
                .unwrap();
        }
        write.commit().unwrap();
        assert!(store.snapshot().unwrap().audit_verified(|_| {}).is_err());
    }
    #[test]
    fn auxiliary_internal_leaf_count_is_checked_even_when_root_hash_is_unchanged() {
        let (_dir, store) = initialized();
        let write = store.db.begin_write().unwrap();
        {
            let mut nodes = write.open_table(NODES).unwrap();
            let changed = nodes
                .iter()
                .unwrap()
                .find_map(|entry| {
                    let (key, value) = entry.unwrap();
                    let node: Node = borsh::from_slice(value.value()).unwrap();
                    if let Node::Internal(internal) = &node {
                        let before = internal.hash::<Sha256>();
                        let mut encoded = serde_json::to_value(&node).unwrap();
                        encoded["Internal"]["leaf_count"] = serde_json::json!(999);
                        let corrupted: Node = serde_json::from_value(encoded).unwrap();
                        let Node::Internal(after) = &corrupted else {
                            unreachable!()
                        };
                        assert_eq!(before, after.hash::<Sha256>());
                        Some((key.value().to_vec(), borsh::to_vec(&corrupted).unwrap()))
                    } else {
                        None
                    }
                })
                .unwrap();
            nodes
                .insert(changed.0.as_slice(), changed.1.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert!(store.snapshot().unwrap().audit_verified(|_| {}).is_err());
    }
    #[test]
    fn auxiliary_child_count_is_checked_even_when_root_hash_is_unchanged() {
        let (_dir, store) = initialized();
        let write = store.db.begin_write().unwrap();
        {
            let mut nodes = write.open_table(NODES).unwrap();
            let changed = nodes
                .iter()
                .unwrap()
                .find_map(|entry| {
                    let (key, value) = entry.unwrap();
                    let node: Node = borsh::from_slice(value.value()).unwrap();
                    if let Node::Internal(internal) = &node {
                        let before = internal.hash::<Sha256>();
                        let mut encoded = serde_json::to_value(&node).unwrap();
                        encoded["Internal"]["children"]["num_children"] = serde_json::json!(999);
                        let corrupted: Node = serde_json::from_value(encoded).unwrap();
                        let Node::Internal(after) = &corrupted else {
                            unreachable!()
                        };
                        assert_eq!(before, after.hash::<Sha256>());
                        Some((key.value().to_vec(), borsh::to_vec(&corrupted).unwrap()))
                    } else {
                        None
                    }
                })
                .unwrap();
            nodes
                .insert(changed.0.as_slice(), changed.1.as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert!(store.snapshot().unwrap().audit_verified(|_| {}).is_err());
    }
    #[test]
    fn raw_and_mvcc_tampering_are_detected() {
        for modify_mvcc in [false, true] {
            let (_dir, store) = initialized();
            let write = store.db.begin_write().unwrap();
            if modify_mvcc {
                let key = value_key(key_hash(b"name/alice"), 0);
                write
                    .open_table(VALUES)
                    .unwrap()
                    .insert(key.as_slice(), encode_value(Some(b"999")).as_slice())
                    .unwrap();
            } else {
                write
                    .open_table(ROWS)
                    .unwrap()
                    .insert(b"name/alice".as_slice(), b"999".as_slice())
                    .unwrap();
            }
            write.commit().unwrap();
            assert!(store.snapshot().unwrap().audit_verified(|_| {}).is_err());
        }
    }
}
