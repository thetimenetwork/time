//! Compact state-proof wire format, byte-compatible with protocol 4.
//!
//! The JSON produced here is exactly what `jmt::proof::SparseMerkleProof<Sha256>`
//! serializes to, so the WebAssembly verifier and the SDK accept it unchanged.
//! A proof is only authoritative once its root has been authenticated by the
//! consensus light client.
use crate::merkle::{self, Hash, Proof, Sibling};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const KEY_DOMAIN: &[u8] = b"TCDEVNET-KEY-V2\0";
pub const MAX_KEY_BYTES: usize = 256;
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;

/// Domain-separated hash that places a raw state key in the tree.
pub fn key_hash(key: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(KEY_DOMAIN);
    hash.update(key);
    hash.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafNode {
    pub key_hash: Hash,
    pub value_hash: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalNode {
    pub left_child: Hash,
    pub right_child: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SparseMerkleNode {
    Null,
    Internal(InternalNode),
    Leaf(LeafNode),
}

/// Field names, order and enum tags mirror the JMT type. `phantom_hasher`
/// serializes as `null`, as JMT's `PhantomData` marker does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    pub leaf: Option<LeafNode>,
    pub siblings: Vec<SparseMerkleNode>,
    pub phantom_hasher: (),
}

impl From<Proof> for SparseMerkleProof {
    fn from(proof: Proof) -> Self {
        Self {
            leaf: proof.leaf.map(|(key_hash, value_hash)| LeafNode {
                key_hash,
                value_hash,
            }),
            siblings: proof
                .siblings
                .into_iter()
                .map(|sibling| match sibling {
                    Sibling::Null => SparseMerkleNode::Null,
                    Sibling::Internal { left, right } => SparseMerkleNode::Internal(InternalNode {
                        left_child: left,
                        right_child: right,
                    }),
                    Sibling::Leaf {
                        key_hash,
                        value_hash,
                    } => SparseMerkleNode::Leaf(LeafNode {
                        key_hash,
                        value_hash,
                    }),
                })
                .collect(),
            phantom_hasher: (),
        }
    }
}

impl SparseMerkleProof {
    fn to_merkle(&self) -> Proof {
        Proof {
            leaf: self.leaf.map(|leaf| (leaf.key_hash, leaf.value_hash)),
            siblings: self
                .siblings
                .iter()
                .map(|node| match node {
                    SparseMerkleNode::Null => Sibling::Null,
                    SparseMerkleNode::Internal(node) => Sibling::Internal {
                        left: node.left_child,
                        right: node.right_child,
                    },
                    SparseMerkleNode::Leaf(leaf) => Sibling::Leaf {
                        key_hash: leaf.key_hash,
                        value_hash: leaf.value_hash,
                    },
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofEntry {
    pub key_hex: String,
    pub value_b64: Option<String>,
    pub proof: SparseMerkleProof,
}

impl ProofEntry {
    pub fn new(key: &[u8], value: Option<&[u8]>, proof: Proof) -> Self {
        Self {
            key_hex: hex::encode(key),
            value_b64: value.map(|bytes| STANDARD.encode(bytes)),
            proof: proof.into(),
        }
    }

    /// Checks the entry against a root and returns the proven value, or `None`
    /// for a proven absence.
    pub fn verify(&self, expected_root: [u8; 32], expected_key: &[u8]) -> Result<Option<Vec<u8>>> {
        ensure!(
            !expected_key.is_empty() && expected_key.len() <= MAX_KEY_BYTES,
            "invalid proof key length"
        );
        ensure!(
            self.key_hex == hex::encode(expected_key),
            "proof key does not match requested key"
        );
        let value = self
            .value_b64
            .as_ref()
            .map(|text| {
                ensure!(
                    text.len() <= MAX_VALUE_BYTES.div_ceil(3) * 4,
                    "proof value too large"
                );
                let bytes = STANDARD.decode(text)?;
                ensure!(STANDARD.encode(&bytes) == *text, "noncanonical base64 value");
                ensure!(bytes.len() <= MAX_VALUE_BYTES, "proof value too large");
                Ok::<_, anyhow::Error>(bytes)
            })
            .transpose()?;
        merkle::verify(
            &self.proof.to_merkle(),
            &expected_root,
            &key_hash(expected_key),
            value.as_deref(),
        )?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    pub version: u64,
    pub root: [u8; 32],
    pub entries: Vec<ProofEntry>,
}
