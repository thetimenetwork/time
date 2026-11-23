//! In-memory, persistent (copy-on-write) sparse Merkle tree.
//!
//! The root hash and the proofs are bit-for-bit those of the Jellyfish Merkle
//! Tree 0.12 with SHA-256 that protocol 4 uses, so wallets and the WebAssembly
//! verifier need no change. Only the layout differs: JMT stores 16-ary nodes on
//! disk and re-reads them for every update; this tree keeps binary nodes in
//! memory and shares unchanged subtrees between versions through `Arc`.
//!
//! Hashing rules (identical to JMT):
//! - an empty subtree hashes to `PLACEHOLDER`;
//! - a subtree holding exactly one key hashes to that leaf's hash, at any depth;
//! - any other subtree hashes to `H("JMT::IntrnalNode" || left || right)`.
//!
//! Structural invariant: an `Internal` node always has at least two leaves
//! below it. A subtree with one leaf is represented by the leaf itself.
//!
//! Every function here is deterministic. Parallelism only splits work between
//! disjoint subtrees; it never changes the result.

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub type Hash = [u8; 32];

pub const PLACEHOLDER: Hash = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";
const LEAF_DOMAIN: &[u8] = b"JMT::LeafNode";
const INTERNAL_DOMAIN: &[u8] = b"JMT::IntrnalNode";
/// Subtrees with fewer pending operations than this are updated on the
/// calling thread; larger ones are split between worker threads.
const PARALLEL_MIN_OPS: usize = 192;
const PARALLEL_MAX_DEPTH: usize = 12;

pub fn value_hash(value: &[u8]) -> Hash {
    Sha256::digest(value).into()
}

pub fn leaf_hash(key_hash: &Hash, value_hash: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(key_hash);
    hasher.update(value_hash);
    hasher.finalize().into()
}

pub fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(INTERNAL_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Bit `depth` of a key hash, most significant bit first. `false` is the left child.
#[inline]
pub fn bit(key_hash: &Hash, depth: usize) -> bool {
    (key_hash[depth / 8] >> (7 - depth % 8)) & 1 == 1
}

pub type Link = Option<Arc<Node>>;

pub enum Node {
    Internal(Internal),
    Leaf(Leaf),
}

pub struct Internal {
    hash: Hash,
    leaves: u64,
    left: Link,
    right: Link,
}

pub struct Leaf {
    hash: Hash,
    key_hash: Hash,
    value_hash: Hash,
    key: Box<[u8]>,
    value: Arc<[u8]>,
}

impl Leaf {
    pub fn key_hash(&self) -> &Hash {
        &self.key_hash
    }
    pub fn value_hash(&self) -> &Hash {
        &self.value_hash
    }
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub fn value(&self) -> &Arc<[u8]> {
        &self.value
    }
}

impl Node {
    #[inline]
    pub fn hash(&self) -> &Hash {
        match self {
            Node::Internal(node) => &node.hash,
            Node::Leaf(leaf) => &leaf.hash,
        }
    }
    #[inline]
    pub fn leaves(&self) -> u64 {
        match self {
            Node::Internal(node) => node.leaves,
            Node::Leaf(_) => 1,
        }
    }
    #[inline]
    fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }
}

#[inline]
pub fn root_hash(root: &Link) -> Hash {
    root.as_ref().map_or(PLACEHOLDER, |node| *node.hash())
}

#[inline]
pub fn leaf_count(root: &Link) -> u64 {
    root.as_ref().map_or(0, |node| node.leaves())
}

#[inline]
fn link_hash(link: &Link) -> &Hash {
    link.as_ref().map_or(&PLACEHOLDER, |node| node.hash())
}

/// Builds a leaf node. `key_hash` must be the caller's domain-separated hash of `key`.
pub fn new_leaf(key: &[u8], key_hash: Hash, value: Arc<[u8]>) -> Arc<Node> {
    let value_hash = value_hash(&value);
    Arc::new(Node::Leaf(Leaf {
        hash: leaf_hash(&key_hash, &value_hash),
        key_hash,
        value_hash,
        key: key.into(),
        value,
    }))
}

/// One change to the tree: `Some(leaf)` inserts or replaces, `None` deletes.
#[derive(Clone)]
pub struct Op {
    pub key_hash: Hash,
    pub leaf: Option<Arc<Node>>,
}

/// Joins two children into the node for their parent position, keeping the
/// structural invariant: nothing below gives no node, a lone leaf moves up
/// unchanged, anything else becomes an internal node.
fn combine(left: Link, right: Link) -> Link {
    match (&left, &right) {
        (None, None) => None,
        (Some(only), None) if only.is_leaf() => left,
        (None, Some(only)) if only.is_leaf() => right,
        _ => {
            let leaves = leaf_count(&left) + leaf_count(&right);
            Some(Arc::new(Node::Internal(Internal {
                hash: internal_hash(link_hash(&left), link_hash(&right)),
                leaves,
                left,
                right,
            })))
        }
    }
}

fn join<A, B>(depth: usize, ops: usize, left: A, right: B) -> (Link, Link)
where
    A: FnOnce() -> Link + Send,
    B: FnOnce() -> Link + Send,
{
    if ops >= PARALLEL_MIN_OPS && depth < PARALLEL_MAX_DEPTH {
        rayon::join(left, right)
    } else {
        (left(), right())
    }
}

/// Builds the subtree at `depth` that holds exactly the inserted leaves of `ops`.
fn build(depth: usize, ops: &[Op]) -> Link {
    match ops {
        [] => None,
        [only] => only.leaf.clone(),
        _ => {
            // Two distinct 256-bit key hashes differ in some bit; the caller
            // guarantees distinct, sorted key hashes.
            assert!(depth < 256, "duplicate key hash in Merkle update");
            let split = ops.partition_point(|op| !bit(&op.key_hash, depth));
            let (lower, upper) = ops.split_at(split);
            let (left, right) = join(
                depth,
                ops.len(),
                || build(depth + 1, lower),
                || build(depth + 1, upper),
            );
            combine(left, right)
        }
    }
}

fn update_at(node: &Link, depth: usize, ops: &[Op]) -> Link {
    if ops.is_empty() {
        return node.clone();
    }
    match node.as_deref() {
        None => build(depth, ops),
        Some(Node::Leaf(existing)) => {
            match ops.binary_search_by(|op| op.key_hash.cmp(&existing.key_hash)) {
                // The existing leaf is replaced or deleted by one of the operations.
                Ok(_) => build(depth, ops),
                // The existing leaf stays and joins the new leaves below this position.
                Err(position) => {
                    let mut merged = Vec::with_capacity(ops.len() + 1);
                    merged.extend_from_slice(&ops[..position]);
                    merged.push(Op {
                        key_hash: existing.key_hash,
                        leaf: node.clone(),
                    });
                    merged.extend_from_slice(&ops[position..]);
                    build(depth, &merged)
                }
            }
        }
        Some(Node::Internal(internal)) => {
            assert!(depth < 256, "internal node below the last key bit");
            let split = ops.partition_point(|op| !bit(&op.key_hash, depth));
            let (lower, upper) = ops.split_at(split);
            let (left, right) = join(
                depth,
                ops.len(),
                || update_at(&internal.left, depth + 1, lower),
                || update_at(&internal.right, depth + 1, upper),
            );
            combine(left, right)
        }
    }
}

/// Applies `ops` and returns the new root. The old root stays valid and shares
/// every untouched subtree with the new one.
///
/// `ops` must be sorted by `key_hash` with no duplicates; this is checked.
pub fn update(root: &Link, ops: &[Op]) -> Result<Link> {
    ensure!(
        ops.windows(2).all(|pair| pair[0].key_hash < pair[1].key_hash),
        "Merkle operations must be sorted by distinct key hash"
    );
    for op in ops {
        if let Some(leaf) = &op.leaf {
            match leaf.as_ref() {
                Node::Leaf(leaf) => ensure!(
                    leaf.key_hash == op.key_hash,
                    "Merkle operation key does not match its leaf"
                ),
                Node::Internal(_) => bail!("Merkle operation carries an internal node"),
            }
        }
    }
    Ok(update_at(root, 0, ops))
}

/// Looks a key hash up. Returns the leaf only if it holds exactly this key.
pub fn get<'a>(root: &'a Link, key_hash: &Hash) -> Option<&'a Leaf> {
    let mut current = root.as_deref()?;
    let mut depth = 0;
    loop {
        match current {
            Node::Leaf(leaf) => return (leaf.key_hash == *key_hash).then_some(leaf),
            Node::Internal(internal) => {
                let next = if bit(key_hash, depth) {
                    &internal.right
                } else {
                    &internal.left
                };
                current = next.as_deref()?;
                depth += 1;
            }
        }
    }
}

/// A sibling on the path from a leaf position to the root, with enough
/// structure for the verifier to tell a leaf from an internal node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sibling {
    Null,
    Internal { left: Hash, right: Hash },
    Leaf { key_hash: Hash, value_hash: Hash },
}

impl Sibling {
    fn of(link: &Link) -> Self {
        match link.as_deref() {
            None => Sibling::Null,
            Some(Node::Leaf(leaf)) => Sibling::Leaf {
                key_hash: leaf.key_hash,
                value_hash: leaf.value_hash,
            },
            Some(Node::Internal(internal)) => Sibling::Internal {
                left: *link_hash(&internal.left),
                right: *link_hash(&internal.right),
            },
        }
    }
    pub fn hash(&self) -> Hash {
        match self {
            Sibling::Null => PLACEHOLDER,
            Sibling::Internal { left, right } => internal_hash(left, right),
            Sibling::Leaf {
                key_hash,
                value_hash,
            } => leaf_hash(key_hash, value_hash),
        }
    }
}

/// Membership or absence proof. `leaf` is the leaf found at the end of the
/// key's path, if any: the key itself (membership), another key (absence), or
/// nothing (absence at an empty position). `siblings` run from the bottom up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub leaf: Option<(Hash, Hash)>,
    pub siblings: Vec<Sibling>,
}

/// Returns the value stored under `key_hash`, if any, and the proof for it.
pub fn prove(root: &Link, key_hash: &Hash) -> (Option<Arc<[u8]>>, Proof) {
    let mut siblings = Vec::new();
    let mut current = root;
    let mut depth = 0;
    let (value, leaf) = loop {
        match current.as_deref() {
            None => break (None, None),
            Some(Node::Leaf(leaf)) => {
                let value = (leaf.key_hash == *key_hash).then(|| leaf.value.clone());
                break (value, Some((leaf.key_hash, leaf.value_hash)));
            }
            Some(Node::Internal(internal)) => {
                let (next, other) = if bit(key_hash, depth) {
                    (&internal.right, &internal.left)
                } else {
                    (&internal.left, &internal.right)
                };
                siblings.push(Sibling::of(other));
                current = next;
                depth += 1;
            }
        }
    };
    siblings.reverse();
    (value, Proof { leaf, siblings })
}

fn common_prefix_bits(a: &Hash, b: &Hash) -> usize {
    for (index, (x, y)) in a.iter().zip(b).enumerate() {
        let difference = x ^ y;
        if difference != 0 {
            return index * 8 + difference.leading_zeros() as usize;
        }
    }
    256
}

/// Checks a proof against a root: `value` present means membership, absent
/// means absence. Same acceptance rule as JMT's `SparseMerkleProof::verify`.
pub fn verify(proof: &Proof, root: &Hash, key_hash: &Hash, value: Option<&[u8]>) -> Result<()> {
    ensure!(proof.siblings.len() <= 256, "proof has too many siblings");
    match (value, &proof.leaf) {
        (Some(value), Some((leaf_key, leaf_value))) => {
            ensure!(leaf_key == key_hash, "proof is for another key");
            ensure!(
                *leaf_value == value_hash(value),
                "proof is for another value"
            );
        }
        (Some(_), None) => bail!("expected a membership proof"),
        (None, Some((leaf_key, _))) => {
            ensure!(leaf_key != key_hash, "key exists in an absence proof");
            ensure!(
                common_prefix_bits(key_hash, leaf_key) >= proof.siblings.len(),
                "absence proof leaf is not on the key's path"
            );
        }
        (None, None) => {}
    }
    let mut current = proof
        .leaf
        .map_or(PLACEHOLDER, |(key, value)| leaf_hash(&key, &value));
    let depth = proof.siblings.len();
    for (index, sibling) in proof.siblings.iter().enumerate() {
        // siblings[0] is the deepest one, at bit position depth - 1.
        let position = depth - 1 - index;
        current = if bit(key_hash, position) {
            internal_hash(&sibling.hash(), &current)
        } else {
            internal_hash(&current, &sibling.hash())
        };
    }
    ensure!(current == *root, "proof does not match the root");
    Ok(())
}

/// Visits every leaf in key-hash order.
pub fn for_each_leaf<'a, E>(
    root: &'a Link,
    visit: &mut impl FnMut(&'a Leaf) -> Result<(), E>,
) -> Result<(), E> {
    // Explicit stack: recursion depth is bounded by 256, but iteration keeps
    // the visitor's borrow simple.
    let mut stack: Vec<&'a Node> = Vec::new();
    if let Some(node) = root.as_deref() {
        stack.push(node);
    }
    while let Some(node) = stack.pop() {
        match node {
            Node::Leaf(leaf) => visit(leaf)?,
            Node::Internal(internal) => {
                if let Some(right) = internal.right.as_deref() {
                    stack.push(right);
                }
                if let Some(left) = internal.left.as_deref() {
                    stack.push(left);
                }
            }
        }
    }
    Ok(())
}

/// Number of internal nodes, for audit reports.
pub fn internal_count(root: &Link) -> u64 {
    let mut count = 0u64;
    let mut stack: Vec<&Node> = Vec::new();
    if let Some(node) = root.as_deref() {
        stack.push(node);
    }
    while let Some(node) = stack.pop() {
        if let Node::Internal(internal) = node {
            count += 1;
            stack.extend(internal.left.as_deref());
            stack.extend(internal.right.as_deref());
        }
    }
    count
}

/// Recomputes every hash and leaf count from the leaves up and checks the
/// stored ones and the structural invariant. Used by the offline audit.
pub fn verify_structure(root: &Link) -> Result<()> {
    fn check(node: &Node, depth: usize, prefix: &mut Vec<bool>) -> Result<(Hash, u64)> {
        match node {
            Node::Leaf(leaf) => {
                ensure!(
                    leaf.value_hash == value_hash(&leaf.value)
                        && leaf.hash == leaf_hash(&leaf.key_hash, &leaf.value_hash),
                    "leaf hash mismatch"
                );
                ensure!(
                    prefix
                        .iter()
                        .enumerate()
                        .all(|(index, expected)| bit(&leaf.key_hash, index) == *expected),
                    "leaf is stored under the wrong path"
                );
                Ok((leaf.hash, 1))
            }
            Node::Internal(internal) => {
                ensure!(depth < 256, "internal node below the last key bit");
                let mut side = |link: &Link, right: bool| -> Result<(Hash, u64)> {
                    match link.as_deref() {
                        None => Ok((PLACEHOLDER, 0)),
                        Some(child) => {
                            prefix.push(right);
                            let result = check(child, depth + 1, prefix);
                            prefix.pop();
                            result
                        }
                    }
                };
                let (left_hash, left_leaves) = side(&internal.left, false)?;
                let (right_hash, right_leaves) = side(&internal.right, true)?;
                let leaves = left_leaves + right_leaves;
                ensure!(
                    leaves >= 2,
                    "internal node with fewer than two leaves below it"
                );
                ensure!(
                    internal.leaves == leaves
                        && internal.hash == internal_hash(&left_hash, &right_hash),
                    "internal node hash or count mismatch"
                );
                Ok((internal.hash, leaves))
            }
        }
    }
    match root.as_deref() {
        None => Ok(()),
        Some(node) => check(node, 0, &mut Vec::new()).map(|_| ()),
    }
}

/// The root hash of the tree that holds a set of leaves, computed from the
/// leaves in key-hash order without building the tree.
///
/// It applies the three hashing rules at the top of this file and nothing
/// else, so the result is the root `update` gives for the same leaves. What
/// is kept between two leaves is one hash for each internal node on the path
/// to the last leaf whose left side is finished: at most 256 of them,
/// whatever the number of leaves. A snapshot received from peers is checked
/// with it before any of its rows is kept in memory.
pub struct StreamingRoot {
    /// Internal nodes on the path to the last leaf, top down: the bit depth
    /// at which each splits, and the hash of its finished left child.
    pending: Vec<(usize, Hash)>,
    /// The last leaf's key hash, and the finished subtree it is in so far:
    /// its hash, and the depth at which it splits (`None` for a lone leaf,
    /// which hashes the same at every depth).
    last: Option<(Hash, Hash, Option<usize>)>,
    leaves: u64,
}

impl Default for StreamingRoot {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingRoot {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            last: None,
            leaves: 0,
        }
    }
    /// Leaves taken so far.
    pub fn leaves(&self) -> u64 {
        self.leaves
    }
    /// The hash of a subtree as its parent at depth `to - 1` sees it. A lone
    /// leaf is its own hash at any depth. A subtree that splits at depth
    /// `from` is, at each depth above that down to `to`, the only child of
    /// an internal node, on the side the bit of its keys names.
    fn raised(mut hash: Hash, from: Option<usize>, to: usize, key_hash: &Hash) -> Hash {
        let Some(from) = from else {
            return hash;
        };
        for depth in (to..from).rev() {
            hash = if bit(key_hash, depth) {
                internal_hash(&PLACEHOLDER, &hash)
            } else {
                internal_hash(&hash, &PLACEHOLDER)
            };
        }
        hash
    }
    /// Takes the next leaf. Its key hash must be greater than the one before.
    pub fn push(&mut self, key_hash: &Hash, leaf_hash: Hash) -> Result<()> {
        let Some((last_key, mut hash, mut from)) = self.last.take() else {
            self.last = Some((*key_hash, leaf_hash, None));
            self.leaves = 1;
            return Ok(());
        };
        if last_key >= *key_hash {
            self.last = Some((last_key, hash, from));
            bail!("Merkle leaves must come sorted by distinct key hash");
        }
        // The two keys part at this bit: the last one goes left there (its
        // bit is 0, it is the smaller), the new one right. Every node below
        // that depth on the last key's path is finished.
        let split = common_prefix_bits(&last_key, key_hash);
        while let Some(&(depth, left)) = self.pending.last() {
            if depth < split {
                break;
            }
            self.pending.pop();
            hash = internal_hash(&left, &Self::raised(hash, from, depth + 1, &last_key));
            from = Some(depth);
        }
        self.pending
            .push((split, Self::raised(hash, from, split + 1, &last_key)));
        self.last = Some((*key_hash, leaf_hash, None));
        self.leaves += 1;
        Ok(())
    }
    /// The root of the tree that holds exactly the leaves taken.
    pub fn finish(mut self) -> Hash {
        let Some((last_key, mut hash, mut from)) = self.last else {
            return PLACEHOLDER;
        };
        while let Some((depth, left)) = self.pending.pop() {
            hash = internal_hash(&left, &Self::raised(hash, from, depth + 1, &last_key));
            from = Some(depth);
        }
        Self::raised(hash, from, 0, &last_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hash(key: &[u8]) -> Hash {
        Sha256::digest(key).into()
    }
    /// The root the tree itself gives for leaves at these key hashes, and
    /// the root computed from the same leaves as a stream.
    fn both_roots(mut key_hashes: Vec<Hash>) -> (Hash, Hash) {
        key_hashes.sort_unstable();
        key_hashes.dedup();
        let ops: Vec<Op> = key_hashes
            .iter()
            .enumerate()
            .map(|(index, hash)| Op {
                key_hash: *hash,
                leaf: Some(new_leaf(
                    &index.to_be_bytes(),
                    *hash,
                    Arc::from(hash[..(index % 7)].to_vec()),
                )),
            })
            .collect();
        let tree = update(&None, &ops).unwrap();
        verify_structure(&tree).unwrap();
        let mut stream = StreamingRoot::new();
        for op in &ops {
            let leaf = op.leaf.as_ref().unwrap();
            stream.push(&op.key_hash, *leaf.hash()).unwrap();
        }
        assert_eq!(stream.leaves(), ops.len() as u64);
        (root_hash(&tree), stream.finish())
    }
    /// A deterministic stream of 256-bit values.
    fn random(seed: u64, count: usize) -> Vec<Hash> {
        (0..count as u64)
            .map(|index| Sha256::digest([seed.to_be_bytes(), index.to_be_bytes()].concat()).into())
            .collect()
    }

    #[test]
    fn the_streaming_root_is_the_root_of_the_tree() {
        // No leaf, one leaf.
        assert_eq!(StreamingRoot::new().finish(), PLACEHOLDER);
        assert_eq!(both_roots(vec![]), (PLACEHOLDER, PLACEHOLDER));
        for hash in [[0u8; 32], [0xff; 32], key_hash(b"one")] {
            let (tree, stream) = both_roots(vec![hash]);
            assert_eq!(tree, stream);
        }
        // Two leaves whose keys part at every possible bit, with every
        // combination of the bits after it that matters.
        for split in 0..256usize {
            for base in [[0u8; 32], [0xff; 32], key_hash(&split.to_be_bytes())] {
                let (mut low, mut high) = (base, base);
                low[split / 8] &= !(0x80 >> (split % 8));
                high[split / 8] |= 0x80 >> (split % 8);
                let (tree, stream) = both_roots(vec![low, high]);
                assert_eq!(tree, stream, "split at bit {split}");
                // A third leaf elsewhere, before or after the pair.
                let (tree, stream) = both_roots(vec![low, high, key_hash(b"third")]);
                assert_eq!(tree, stream, "split at bit {split} with a third leaf");
            }
        }
        // Random sets of every small size, and larger ones.
        for count in (0..200usize).chain([255, 256, 257, 1000, 4097]) {
            let (tree, stream) = both_roots(random(count as u64, count));
            assert_eq!(tree, stream, "{count} random leaves");
        }
    }

    #[test]
    fn the_streaming_root_follows_deep_shared_prefixes() {
        // Keys that share long prefixes make chains of internal nodes with
        // one child, and leaves that sit deep in the tree.
        let with_prefix = |prefix_bits: usize, tails: &[Hash], base: &Hash| -> Vec<Hash> {
            tails
                .iter()
                .map(|tail| {
                    let mut key = *tail;
                    for depth in 0..prefix_bits {
                        let mask = 0x80u8 >> (depth % 8);
                        key[depth / 8] = (key[depth / 8] & !mask) | (base[depth / 8] & mask);
                    }
                    key
                })
                .collect()
        };
        let base = key_hash(b"base");
        for prefix in [1, 2, 7, 8, 9, 63, 64, 65, 127, 200, 248, 250, 254, 255] {
            for count in [2, 3, 5, 16, 100] {
                // All leaves under one deep prefix.
                let cluster = with_prefix(prefix, &random(prefix as u64, count), &base);
                let (tree, stream) = both_roots(cluster.clone());
                assert_eq!(tree, stream, "{count} leaves under {prefix} bits");
                // The cluster among unrelated leaves, on both sides of it.
                let mut mixed = cluster.clone();
                mixed.extend(random(1000 + prefix as u64, 50));
                mixed.extend([[0u8; 32], [0xff; 32]]);
                let (tree, stream) = both_roots(mixed);
                assert_eq!(tree, stream, "{count} leaves under {prefix} bits, mixed");
                // Clusters inside clusters: a deeper prefix within the first.
                let inner = with_prefix((prefix + 40).min(255), &random(7, count), &cluster[0]);
                let mut nested = cluster;
                nested.extend(inner);
                let (tree, stream) = both_roots(nested);
                assert_eq!(tree, stream, "nested clusters under {prefix} bits");
            }
        }
        // Consecutive integers: the smallest keys, parting only in the last
        // bits, and the largest, and both together.
        let number = |value: u64, fill: u8| -> Hash {
            let mut key = [fill; 32];
            key[24..].copy_from_slice(&value.to_be_bytes());
            key
        };
        for count in [2u64, 3, 4, 5, 8, 9, 255, 256, 1000] {
            let low: Vec<Hash> = (0..count).map(|value| number(value, 0)).collect();
            let high: Vec<Hash> = (0..count).map(|value| number(u64::MAX - value, 0xff)).collect();
            for set in [low.clone(), high.clone(), [low, high].concat()] {
                let (tree, stream) = both_roots(set);
                assert_eq!(tree, stream, "{count} consecutive keys");
            }
        }
    }

    #[test]
    fn the_streaming_root_refuses_leaves_out_of_order() {
        let (low, high) = ([1u8; 32], [2u8; 32]);
        let mut stream = StreamingRoot::new();
        stream.push(&high, [9; 32]).unwrap();
        // Smaller than the last, or the same again.
        assert!(stream.push(&low, [9; 32]).is_err());
        assert!(stream.push(&high, [9; 32]).is_err());
        // A refused leaf changes nothing.
        assert_eq!(stream.leaves(), 1);
        assert_eq!(stream.finish(), [9; 32]);
    }
    fn op(key: &[u8], value: Option<&[u8]>) -> Op {
        let hash = key_hash(key);
        Op {
            key_hash: hash,
            leaf: value.map(|v| new_leaf(key, hash, Arc::from(v))),
        }
    }
    fn sorted(mut ops: Vec<Op>) -> Vec<Op> {
        ops.sort_by(|a, b| a.key_hash.cmp(&b.key_hash));
        ops
    }

    #[test]
    fn empty_single_and_pair_follow_the_hash_rules() {
        let empty: Link = None;
        assert_eq!(root_hash(&empty), PLACEHOLDER);
        let one = update(&empty, &[op(b"a", Some(b"1"))]).unwrap();
        let leaf = leaf_hash(&key_hash(b"a"), &value_hash(b"1"));
        assert_eq!(root_hash(&one), leaf);
        assert_eq!(leaf_count(&one), 1);
        // Deleting the only key returns to the empty tree.
        let none = update(&one, &[op(b"a", None)]).unwrap();
        assert_eq!(root_hash(&none), PLACEHOLDER);
        verify_structure(&one).unwrap();
    }

    #[test]
    fn order_of_insertion_does_not_change_the_root() {
        let keys: Vec<Vec<u8>> = (0u32..500).map(|i| i.to_be_bytes().to_vec()).collect();
        let all = update(
            &None,
            &sorted(keys.iter().map(|k| op(k, Some(k))).collect()),
        )
        .unwrap();
        let mut step: Link = None;
        for chunk in keys.rchunks(7) {
            step = update(&step, &sorted(chunk.iter().map(|k| op(k, Some(k))).collect())).unwrap();
        }
        assert_eq!(root_hash(&all), root_hash(&step));
        assert_eq!(leaf_count(&step), 500);
        verify_structure(&step).unwrap();
        // Delete most keys in batches; the remainder must equal a fresh build.
        let (gone, kept) = keys.split_at(450);
        let mut pruned = step.clone();
        for chunk in gone.chunks(31) {
            pruned = update(&pruned, &sorted(chunk.iter().map(|k| op(k, None)).collect())).unwrap();
        }
        let fresh = update(&None, &sorted(kept.iter().map(|k| op(k, Some(k))).collect())).unwrap();
        assert_eq!(root_hash(&pruned), root_hash(&fresh));
        verify_structure(&pruned).unwrap();
        // The older version is untouched by later updates.
        assert_eq!(leaf_count(&step), 500);
        assert_eq!(get(&step, &key_hash(&keys[0])).unwrap().value().as_ref(), &keys[0][..]);
        assert!(get(&pruned, &key_hash(&keys[0])).is_none());
    }

    #[test]
    fn proofs_verify_and_reject_tampering() {
        let keys: Vec<Vec<u8>> = (0u32..200).map(|i| i.to_be_bytes().to_vec()).collect();
        let tree = update(&None, &sorted(keys.iter().map(|k| op(k, Some(k))).collect())).unwrap();
        let root = root_hash(&tree);
        for key in &keys {
            let hash = key_hash(key);
            let (value, proof) = prove(&tree, &hash);
            assert_eq!(value.as_deref(), Some(&key[..]));
            verify(&proof, &root, &hash, Some(key)).unwrap();
            assert!(verify(&proof, &root, &hash, Some(b"other")).is_err());
            assert!(verify(&proof, &root, &hash, None).is_err());
        }
        for absent in 1000u32..1100 {
            let key = absent.to_be_bytes();
            let hash = key_hash(&key);
            let (value, proof) = prove(&tree, &hash);
            assert!(value.is_none());
            verify(&proof, &root, &hash, None).unwrap();
            assert!(verify(&proof, &root, &hash, Some(&key)).is_err());
            // An absence proof for one key must not serve as absence of a present key.
            let present = key_hash(&keys[0]);
            assert!(verify(&proof, &root, &present, None).is_err());
        }
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        let hash = key_hash(&keys[3]);
        let (_, proof) = prove(&tree, &hash);
        assert!(verify(&proof, &wrong_root, &hash, Some(&keys[3])).is_err());
    }

    #[test]
    fn unsorted_or_duplicate_operations_are_refused() {
        let a = op(b"a", Some(b"1"));
        let b = op(b"b", Some(b"2"));
        let (first, second) = if a.key_hash < b.key_hash { (a, b) } else { (b, a) };
        assert!(update(&None, &[second.clone(), first.clone()]).is_err());
        assert!(update(&None, &[first.clone(), first.clone()]).is_err());
        let mismatched = Op {
            key_hash: first.key_hash,
            leaf: second.leaf.clone(),
        };
        assert!(update(&None, &[mismatched]).is_err());
    }
}
