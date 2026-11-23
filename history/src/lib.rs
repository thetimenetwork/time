//! A compact RFC6962-shaped append-only tree. Network-bound leaf encodings and
//! explicit size prevent leaf/node and ambiguous-tree-shape substitution.
//! A trusted current state root must authenticate Summary before proofs matter.
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "archive")]
pub mod archive;
pub type Hash = [u8; 32];
pub const KEY: &[u8] = b"history/meta";
pub const DOMAIN: &[u8] = b"TIME-HISTORY-V1\0";
pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        let n = s.parse::<u64>().map_err(D::Error::custom)?;
        if n.to_string() != s {
            return Err(D::Error::custom("noncanonical decimal"));
        }
        Ok(n)
    }
}
pub fn hash_bytes(s: &str) -> Result<Hash> {
    let bytes = hex::decode(s)?;
    ensure!(
        s.len() == 64 && hex::encode(&bytes) == s,
        "noncanonical history hash"
    );
    bytes.try_into().map_err(|_| anyhow!("invalid hash length"))
}
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}
pub fn commit_root(network: Hash, size: u64, tree_root: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([2]);
    h.update(DOMAIN);
    h.update(network);
    h.update(size.to_be_bytes());
    h.update(tree_root);
    h.finalize().into()
}
pub fn node_hash(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}
pub fn node_count(size: u64) -> Result<u64> {
    size.checked_mul(2)
        .and_then(|n| n.checked_sub(u64::from(size.count_ones())))
        .ok_or_else(|| anyhow!("history node count overflow"))
}
pub fn split(size: u64) -> Result<u64> {
    ensure!(size > 1, "cannot split a leaf");
    Ok(1u64 << (63 - (size - 1).leading_zeros()))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Leaf {
    #[serde(with = "decimal")]
    pub height: u64,
    pub block_hash: String,
    #[serde(with = "decimal")]
    pub time_micros: u64,
}
impl Leaf {
    pub fn hash(&self, network: Hash) -> Result<Hash> {
        ensure!(
            self.height > 0 && self.height <= i64::MAX as u64,
            "invalid history height"
        );
        let mut h = Sha256::new();
        h.update([0]);
        h.update(DOMAIN);
        h.update(network);
        h.update(self.height.to_be_bytes());
        h.update(hash_bytes(&self.block_hash)?);
        h.update(self.time_micros.to_be_bytes());
        Ok(h.finalize().into())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub version: u8,
    pub network_id: String,
    #[serde(with = "decimal")]
    pub size: u64,
    pub root: String,
    #[serde(with = "decimal")]
    pub last_time_micros: u64,
    /// Left-to-right roots of complete subtrees at decreasing set-bit sizes.
    pub peaks: Vec<String>,
}
pub struct Append {
    pub previous: Summary,
    pub summary: Summary,
    pub leaf: Leaf,
    pub nodes: Vec<Hash>,
}
fn bag(peaks: &[String]) -> Result<Hash> {
    let mut root = None;
    for peak in peaks.iter().rev() {
        let hash = hash_bytes(peak)?;
        root = Some(root.map_or(hash, |right| node_hash(hash, right)));
    }
    Ok(root.unwrap_or_else(empty_root))
}
impl Summary {
    pub fn empty(network: Hash, genesis_time_micros: u64) -> Self {
        Self {
            version: 1,
            network_id: hex::encode(network),
            size: 0,
            root: hex::encode(commit_root(network, 0, empty_root())),
            last_time_micros: genesis_time_micros,
            peaks: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.size <= i64::MAX as u64
                && self.peaks.len() == self.size.count_ones() as usize
                && self.peaks.len() <= 63,
            "history shape/version bound"
        );
        let network = hash_bytes(&self.network_id)?;
        ensure!(
            hash_bytes(&self.root)? == commit_root(network, self.size, bag(&self.peaks)?),
            "history frontier/root mismatch"
        );
        Ok(())
    }
    pub fn append(&self, leaf: Leaf) -> Result<Append> {
        self.validate()?;
        ensure!(
            self.size < i64::MAX as u64 && leaf.height == self.size + 1,
            "nonconsecutive history append"
        );
        ensure!(
            leaf.time_micros > self.last_time_micros
                || (self.size == 0 && leaf.time_micros == self.last_time_micros),
            "history time did not advance"
        );
        let mut next = self.clone();
        let mut carry = leaf.hash(hash_bytes(&self.network_id)?)?;
        let mut nodes = vec![carry];
        let mut n = self.size;
        while n & 1 == 1 {
            let left = hash_bytes(
                &next
                    .peaks
                    .pop()
                    .ok_or_else(|| anyhow!("missing history frontier"))?,
            )?;
            carry = node_hash(left, carry);
            nodes.push(carry);
            n >>= 1;
        }
        next.peaks.push(hex::encode(carry));
        next.size += 1;
        next.last_time_micros = leaf.time_micros;
        next.root = hex::encode(commit_root(
            hash_bytes(&next.network_id)?,
            next.size,
            bag(&next.peaks)?,
        ));
        next.validate()?;
        ensure!(
            node_count(next.size)? - node_count(self.size)? == nodes.len() as u64,
            "history append node count mismatch"
        );
        Ok(Append {
            previous: self.clone(),
            summary: next,
            leaf,
            nodes,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub leaf: Leaf,
    pub siblings: Vec<String>,
}
fn reconstruct(
    index: u64,
    size: u64,
    leaf: Hash,
    path: &[String],
    cursor: &mut usize,
) -> Result<Hash> {
    if size == 1 {
        return Ok(leaf);
    }
    let k = split(size)?;
    let child = if index < k {
        reconstruct(index, k, leaf, path, cursor)?
    } else {
        reconstruct(index - k, size - k, leaf, path, cursor)?
    };
    let sibling = hash_bytes(
        path.get(*cursor)
            .ok_or_else(|| anyhow!("short history proof"))?,
    )?;
    *cursor += 1;
    Ok(if index < k {
        node_hash(child, sibling)
    } else {
        node_hash(sibling, child)
    })
}
impl Proof {
    pub fn verify(&self, summary: &Summary) -> Result<Leaf> {
        summary.validate()?;
        ensure!(
            self.siblings.len() <= 63
                && self.leaf.height > 0
                && self.leaf.height <= summary.size
                && self.leaf.time_micros <= summary.last_time_micros,
            "history proof bounds"
        );
        let mut cursor = 0;
        let network = hash_bytes(&summary.network_id)?;
        let root = reconstruct(
            self.leaf.height - 1,
            summary.size,
            self.leaf.hash(network)?,
            &self.siblings,
            &mut cursor,
        )?;
        ensure!(
            cursor == self.siblings.len()
                && commit_root(network, summary.size, root) == hash_bytes(&summary.root)?,
            "history inclusion proof mismatch"
        );
        Ok(self.leaf.clone())
    }
}
/// Random access to an untrusted archive. Verification is mandatory at output.
pub trait Reader {
    fn leaf(&mut self, height: u64) -> Result<Leaf>;
    fn node(&mut self, position: u64) -> Result<Hash>;
}
fn subtree(reader: &mut impl Reader, start: u64, size: u64) -> Result<Hash> {
    ensure!(size > 0, "empty history subtree");
    if size.is_power_of_two() {
        ensure!(start.is_multiple_of(size), "unaligned complete subtree");
        let position = node_count(start)?
            .checked_add(
                size.checked_mul(2)
                    .ok_or_else(|| anyhow!("subtree overflow"))?
                    - 2,
            )
            .ok_or_else(|| anyhow!("node position overflow"))?;
        return reader.node(position);
    }
    let k = split(size)?;
    Ok(node_hash(
        subtree(reader, start, k)?,
        subtree(reader, start + k, size - k)?,
    ))
}
fn path(
    reader: &mut impl Reader,
    index: u64,
    start: u64,
    size: u64,
    out: &mut Vec<String>,
) -> Result<()> {
    if size == 1 {
        return Ok(());
    }
    let k = split(size)?;
    if index < k {
        path(reader, index, start, k, out)?;
        out.push(hex::encode(subtree(reader, start + k, size - k)?));
    } else {
        path(reader, index - k, start + k, size - k, out)?;
        out.push(hex::encode(subtree(reader, start, k)?));
    }
    Ok(())
}
pub fn prove(reader: &mut impl Reader, summary: &Summary, height: u64) -> Result<Proof> {
    summary.validate()?;
    ensure!(
        height > 0 && height <= summary.size,
        "history height outside committed size"
    );
    let leaf = reader.leaf(height)?;
    ensure!(leaf.height == height, "archive leaf alias");
    let mut siblings = Vec::new();
    path(reader, height - 1, 0, summary.size, &mut siblings)?;
    let proof = Proof { leaf, siblings };
    proof.verify(summary)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Memory {
        leaves: Vec<Leaf>,
        nodes: Vec<Hash>,
    }
    impl Reader for Memory {
        fn leaf(&mut self, h: u64) -> Result<Leaf> {
            self.leaves
                .get(h as usize - 1)
                .cloned()
                .ok_or_else(|| anyhow!("missing leaf"))
        }
        fn node(&mut self, p: u64) -> Result<Hash> {
            self.nodes
                .get(p as usize)
                .copied()
                .ok_or_else(|| anyhow!("missing node"))
        }
    }
    fn leaf(h: u64) -> Leaf {
        Leaf {
            height: h,
            block_hash: hex::encode(Sha256::digest(h.to_be_bytes())),
            time_micros: 1000 + h,
        }
    }
    fn naive(rows: &[Leaf], network: Hash) -> Hash {
        if rows.is_empty() {
            return empty_root();
        }
        if rows.len() == 1 {
            return rows[0].hash(network).unwrap();
        }
        let k = split(rows.len() as u64).unwrap() as usize;
        node_hash(naive(&rows[..k], network), naive(&rows[k..], network))
    }
    #[test]
    fn append_proof_and_independent_recursive_tree_agree() {
        let mut s = Summary::empty([7; 32], 1000);
        let mut m = Memory {
            leaves: Vec::new(),
            nodes: Vec::new(),
        };
        for h in 1..=257 {
            let a = s.append(leaf(h)).unwrap();
            m.leaves.push(a.leaf);
            m.nodes.extend(a.nodes);
            s = a.summary;
            assert_eq!(
                hash_bytes(&s.root).unwrap(),
                commit_root([7; 32], s.size, naive(&m.leaves, [7; 32]))
            );
            for k in [1, h, h / 2 + 1] {
                let proof = prove(&mut m, &s, k).unwrap();
                assert_eq!(proof.verify(&s).unwrap().height, k);
                assert!(proof.siblings.len() <= 9);
            }
        }
    }
    #[test]
    fn mutations_coordinates_and_untrusted_frontiers_reject() {
        let mut s = Summary::empty([7; 32], 1000);
        let mut m = Memory {
            leaves: Vec::new(),
            nodes: Vec::new(),
        };
        for h in 1..=17 {
            let a = s.append(leaf(h)).unwrap();
            m.leaves.push(a.leaf);
            m.nodes.extend(a.nodes);
            s = a.summary;
        }
        let p = prove(&mut m, &s, 4).unwrap();
        let mut bad = p.clone();
        bad.leaf.height = 5;
        assert!(bad.verify(&s).is_err());
        let mut bad = p.clone();
        bad.leaf.time_micros += 1;
        assert!(bad.verify(&s).is_err());
        let mut bad = p.clone();
        bad.siblings.push("00".repeat(32));
        assert!(bad.verify(&s).is_err());
        let mut bad = s.clone();
        bad.network_id = "08".repeat(32);
        assert!(p.verify(&bad).is_err());
        let mut bad = s.clone();
        bad.peaks[0] = "00".repeat(32);
        assert!(bad.validate().is_err());
        let mut bad = s.clone();
        bad.size += 1;
        assert!(p.verify(&bad).is_err());
        assert!(s.append(leaf(19)).is_err());
        let mut earlier = leaf(18);
        earlier.time_micros = 1000;
        assert!(s.append(earlier).is_err());
    }
    #[test]
    fn independent_javascript_vectors_agree() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../vectors.json")).unwrap();
        for vector in file["vectors"].as_array().unwrap() {
            let expected: Summary = serde_json::from_value(vector["summary"].clone()).unwrap();
            let mut s = Summary::empty(hash_bytes(&expected.network_id).unwrap(), 1000);
            let mut m = Memory {
                leaves: Vec::new(),
                nodes: Vec::new(),
            };
            for leaf in vector["leaves"].as_array().unwrap() {
                let leaf: Leaf = serde_json::from_value(leaf.clone()).unwrap();
                let a = s.append(leaf).unwrap();
                m.leaves.push(a.leaf);
                m.nodes.extend(a.nodes);
                s = a.summary;
            }
            assert_eq!(s, expected);
            for proof in vector["proofs"].as_array().unwrap() {
                let proof: Proof = serde_json::from_value(proof.clone()).unwrap();
                proof.verify(&s).unwrap();
                assert_eq!(prove(&mut m, &s, proof.leaf.height).unwrap(), proof);
            }
        }
    }
}
