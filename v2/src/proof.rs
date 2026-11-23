//! Version 2 compact JMT proof wire format. A proof is only authoritative after
//! the caller authenticates its root with the consensus light client.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use jmt::{KeyHash, RootHash, proof::SparseMerkleProof};
use serde::{Deserialize, Serialize};
use sha2_10::{Digest, Sha256};

pub const KEY_DOMAIN: &[u8] = b"TCDEVNET-KEY-V2\0";
pub const MAX_KEY_BYTES: usize = 256;
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;

pub fn key_hash(key: &[u8]) -> KeyHash {
    let mut hash = Sha256::new();
    hash.update(KEY_DOMAIN);
    hash.update(key);
    KeyHash(hash.finalize().into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofEntry {
    pub key_hex: String,
    pub value_b64: Option<String>,
    pub proof: SparseMerkleProof<Sha256>,
}

impl ProofEntry {
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
            .map(|v| {
                ensure!(
                    v.len() <= MAX_VALUE_BYTES.div_ceil(3) * 4,
                    "proof value too large"
                );
                let bytes = STANDARD.decode(v)?;
                ensure!(STANDARD.encode(&bytes) == *v, "noncanonical base64 value");
                ensure!(bytes.len() <= MAX_VALUE_BYTES, "proof value too large");
                Ok::<_, anyhow::Error>(bytes)
            })
            .transpose()?;
        self.proof.verify(
            RootHash(expected_root),
            key_hash(expected_key),
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
