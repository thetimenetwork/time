//! Historical transaction evidence anchored in fresh canonical JMT block hashes.
use crate::{
    decimal,
    light::{self, Trust},
    parse,
    view::{StateProof, current_rows, history_summary},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tendermint::block::signed_header::SignedHeader;
const MAX_TXS: u64 = 20_000;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptProof {
    tx: Value,
    signed_header: SignedHeader,
    next_signed_header: SignedHeader,
    anchor: StateProof,
}
fn number(v: &Value, name: &str) -> Result<u64, String> {
    if let Some(n) = v.as_u64() {
        Ok(n)
    } else {
        decimal(v, name)
    }
}
fn h(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn leaf(bytes: &[u8]) -> [u8; 32] {
    let mut v = vec![0];
    v.extend_from_slice(bytes);
    h(&v)
}
fn branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut v = vec![1];
    v.extend_from_slice(left);
    v.extend_from_slice(right);
    h(&v)
}

fn proof_root(
    index: u64,
    total: u64,
    item: [u8; 32],
    aunts: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if total == 0 || index >= total || total > MAX_TXS {
        return Err("invalid transaction proof coordinates".into());
    }
    if total == 1 {
        return if aunts.is_empty() {
            Ok(item)
        } else {
            Err("extra proof siblings".into())
        };
    }
    let (last, rest) = aunts.split_last().ok_or("missing proof sibling")?;
    let split = 1u64 << (63 - (total - 1).leading_zeros());
    if index < split {
        Ok(branch(&proof_root(index, split, item, rest)?, last))
    } else {
        Ok(branch(
            last,
            &proof_root(index - split, total - split, item, rest)?,
        ))
    }
}

pub(crate) fn empty_results_root(total: u64) -> [u8; 32] {
    if total == 1 {
        return leaf(&[]);
    }
    let split = 1u64 << (63 - (total - 1).leading_zeros());
    branch(
        &empty_results_root(split),
        &empty_results_root(total - split),
    )
}

pub fn receipt(proof_json: &str, trust_json: &str, now_ms: f64) -> Result<Value, String> {
    let proof: ReceiptProof = parse(proof_json)?;
    let trust: Trust = parse(trust_json)?;
    let history_proofs = proof.anchor.history_proofs.clone();
    let (rows, anchor_meta, _) = current_rows(proof.anchor, &trust, now_ms)?;
    let history = history_summary(&rows, &anchor_meta, &trust)?;
    let now = light::now_micros(now_ms)?;
    for signed in [&proof.signed_header, &proof.next_signed_header] {
        let header = &signed.header;
        let height = header.height.value();
        if header.version.app < light::FIRST_VERSION
            || header.chain_id.as_str() != trust.chain_id
            || header.time.unix_timestamp_nanos() / 1000 > now + light::FUTURE_MICROS
        {
            return Err("historical header chain/version/time mismatch".into());
        }
        let inclusion = history_proofs
            .get(&height.to_string())
            .ok_or("canonical receipt history inclusion missing")?;
        let leaf = inclusion
            .verify(&history)
            .map_err(|e| format!("invalid canonical receipt inclusion: {e}"))?;
        if leaf.height != height
            || leaf.block_hash != header.hash().to_string().to_lowercase()
            || i128::from(leaf.time_micros) != header.time.unix_timestamp_nanos() / 1000
        {
            return Err(
                "historical receipt is not in freshly authenticated canonical history".into(),
            );
        }
        // The header is now known to be part of the chain. A block of a
        // version this build does not implement is not judged: what its
        // transactions and results mean is defined by rules this build lacks.
        // (Asked only here, after the header is authenticated: a header a
        // gateway made up never produces this answer.)
        if header.version.app > light::KNOWN_VERSION {
            return Err(light::upgrade_required(header.version.app));
        }
    }
    let height = number(&proof.tx["height"], "receipt height")?;
    if height != proof.signed_header.header.height.value()
        || height.checked_add(1) != Some(proof.next_signed_header.header.height.value())
        || proof
            .next_signed_header
            .header
            .last_block_id
            .as_ref()
            .is_none_or(|id| id.hash != proof.signed_header.header.hash())
    {
        return Err("receipt headers are not the same finalized chain".into());
    }
    let (raw, tx_hash, total) = included(&proof.tx, &proof.signed_header.header)?;
    // This application admits only fully valid proposals and emits exactly the
    // default successful ExecTxResult for every included transaction. Bind that
    // execution rule to the next certified header, not to an RPC 'code: 0'.
    let results = empty_results_root(total);
    if proof
        .next_signed_header
        .header
        .last_results_hash
        .as_ref()
        .is_none_or(|hash| hash.as_bytes() != results)
    {
        return Err("certified execution results are not all successful defaults".into());
    }
    Ok(
        json!({"verified":true,"txHash":tx_hash,"height":height.to_string(),"rawHex":hex::encode(raw),"executionVerified":true,"blockHash":proof.signed_header.header.hash().to_string().to_lowercase(),"canonicalAnchorHeight":anchor_meta["height"],"verificationMode":"fresh-current-root-canonical-history"}),
    )
}

/// Checks that the transaction in `tx` (the answer of the node's transaction
/// lookup, with its Merkle proof) is part of the block `header` commits to.
/// Returns the transaction bytes, its hash and the block's transaction count.
/// The header itself must already be authenticated by the caller.
fn included(
    tx: &Value,
    header: &tendermint::block::Header,
) -> Result<(Vec<u8>, String, u64), String> {
    let raw = STANDARD
        .decode(tx["tx"].as_str().ok_or("missing transaction bytes")?)
        .map_err(|_| "invalid transaction bytes")?;
    if raw.is_empty() || raw.len() > 512 * 1024 + 512 {
        return Err("invalid transaction size".into());
    }
    let tx_hash = hex::encode(h(&raw));
    if !tx["hash"]
        .as_str()
        .is_some_and(|hash| hash.eq_ignore_ascii_case(&tx_hash))
    {
        return Err("transaction hash mismatch".into());
    }
    let inclusion = &tx["proof"];
    if STANDARD
        .decode(inclusion["data"].as_str().ok_or("missing included data")?)
        .map_err(|_| "invalid included data")?
        != raw
    {
        return Err("proof includes different transaction bytes".into());
    }
    let merkle: tendermint::merkle::proof::Proof =
        serde_json::from_value(inclusion["proof"].clone())
            .map_err(|e| format!("invalid Merkle proof: {e}"))?;
    if merkle.total == 0
        || merkle.total > MAX_TXS
        || merkle.index != number(&tx["index"], "transaction index")?
        || merkle.aunts.len() > 64
    {
        return Err("invalid Merkle proof bounds".into());
    }
    let item = leaf(&h(&raw));
    if merkle.leaf_hash.as_bytes() != item {
        return Err("Merkle leaf does not match transaction".into());
    }
    let aunts = merkle
        .aunts
        .iter()
        .map(|hash| {
            hash.as_bytes()
                .try_into()
                .map_err(|_| "invalid sibling hash".to_string())
        })
        .collect::<Result<Vec<[u8; 32]>, _>>()?;
    let root = proof_root(merkle.index, merkle.total, item, &aunts)?;
    if header
        .data_hash
        .as_ref()
        .is_none_or(|hash| hash.as_bytes() != root)
        || !inclusion["root_hash"]
            .as_str()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(&hex::encode(root)))
    {
        return Err("transaction inclusion is not bound to the signed header".into());
    }
    Ok((raw, tx_hash, merkle.total))
}

/// Headers accepted between the transaction's block and the trusted
/// checkpoint. Older transactions use the canonical-history receipt.
pub const MAX_FAST_HEADERS: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FastReceiptProof {
    tx: Value,
    /// Block headers in ascending height order: the transaction's block
    /// first, the header of the trusted checkpoint last.
    headers: Vec<tendermint::block::Header>,
}

/// A receipt that needs only the transaction's own block to be final.
///
/// The caller's light client must already trust a checkpoint at or after the
/// transaction's block: a header whose commit it verified against a validator
/// set it trusts. `headers` links the transaction's block to that checkpoint
/// by block hashes, so every header in it is part of the same finalized
/// chain. The transaction is then proven to be in its block.
///
/// Why inclusion proves success: validators of this application reject any
/// proposal in which a single transaction fails, so a block that reached
/// finality contains only transactions that executed. That is the assumption
/// the light client already makes about the validators (fewer than one third
/// of the voting power is faulty); the canonical-history receipt, which reads
/// the result hash from the next header, rests on the same assumption. When
/// the next header is part of `headers`, its result hash is checked here too.
///
/// `trust.checkpoint` must be the caller's own verified checkpoint, as stored
/// by its light client. This function checks that checkpoint's signatures
/// against the validator set it carries; it does not re-derive that set from
/// genesis.
pub fn fast_receipt(proof_json: &str, trust_json: &str, now_ms: f64) -> Result<Value, String> {
    let proof: FastReceiptProof = parse(proof_json)?;
    let trust: Trust = parse(trust_json)?;
    let now = light::now_micros(now_ms)?;
    let pinned = trust
        .checkpoint
        .as_ref()
        .ok_or("FAST_RECEIPT_NEEDS_CHECKPOINT: verify the block's light block first")?;
    // Verifies the checkpoint's commit signatures, its validator set hashes
    // and that it is still inside the trusting period.
    let trusted = light::validate_checkpoint(pinned, &trust, now)?;
    let anchor = &trusted.block.signed_header.header;
    if proof.headers.is_empty() || proof.headers.len() > MAX_FAST_HEADERS {
        return Err("fast receipt header count outside supported bounds".into());
    }
    let last = &proof.headers[proof.headers.len() - 1];
    if last.height != anchor.height || last.hash() != anchor.hash() {
        return Err("fast receipt headers do not end at the trusted checkpoint".into());
    }
    for pair in proof.headers.windows(2) {
        let (parent, child) = (&pair[0], &pair[1]);
        if parent.height.value().checked_add(1) != Some(child.height.value())
            || child
                .last_block_id
                .as_ref()
                .is_none_or(|id| id.hash != parent.hash())
        {
            return Err("fast receipt headers are not one finalized chain".into());
        }
    }
    let header = &proof.headers[0];
    if header.version.app < light::FIRST_VERSION || header.chain_id.as_str() != trust.chain_id {
        return Err("fast receipt header chain/version mismatch".into());
    }
    // The header is tied by hashes to the verified checkpoint. "Inclusion
    // proves success" is a statement about the rules of the transaction's own
    // block, so that block must be of a version this build implements. The
    // checkpoint and the headers after the block may be of a later one: they
    // are only hashed here.
    if header.version.app > light::KNOWN_VERSION {
        return Err(light::upgrade_required(header.version.app));
    }
    let height = number(&proof.tx["height"], "receipt height")?;
    if height != header.height.value() {
        return Err("fast receipt transaction is not in the proven block".into());
    }
    let (raw, tx_hash, total) = included(&proof.tx, header)?;
    // The header after the transaction's block commits to that block's
    // execution results. When it is part of the proven chain, require what the
    // canonical receipt requires: every result is the default, successful one.
    let results_checked = match proof.headers.get(1) {
        None => false,
        Some(next) => {
            if next
                .last_results_hash
                .as_ref()
                .is_none_or(|hash| hash.as_bytes() != empty_results_root(total))
            {
                return Err("certified execution results are not all successful defaults".into());
            }
            true
        }
    };
    Ok(
        json!({"verified":true,"txHash":tx_hash,"height":height.to_string(),"rawHex":hex::encode(raw),"executionVerified":true,"resultsChecked":results_checked,"blockHash":header.hash().to_string().to_lowercase(),"trustedHeight":pinned.height,"verificationMode":"finalized-block-inclusion"}),
    )
}
