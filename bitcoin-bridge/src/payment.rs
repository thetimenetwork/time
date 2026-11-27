//! An ordinary Bitcoin payment to a script, proven against the header chain.
//!
//! This is the check of `spec/market.md`, section 5.2. Unlike a bid receipt
//! (`receipt.rs`) the transaction carries no commitment: any wallet can make
//! it. What ties a payment to its purpose is the caller's: the script, which
//! the caller lets serve one purpose and no other, and the block the purpose
//! began at, which the payment must come after. The caller also keeps the
//! set of outputs that have paid.
//!
//! The check has two parts. `claimed_payment` reads the proof alone and
//! costs no state read: the caller uses what it returns (the output and its
//! value) for every refusal it can decide by itself, before `verify_payment`
//! reads headers. Inside `verify_payment` the checks that read one row come
//! before the ones that walk the header chain, and every walk is bounded,
//! because a proof that is refused costs its sender nothing.
use crate::{BitcoinNetwork, HeaderChain, HeaderReader, MAX_BITCOIN_SATS};
use anyhow::{Context, Result, ensure};
use bitcoin::{
    BlockHash, OutPoint, Transaction,
    consensus::{deserialize, serialize},
    merkle_tree::MerkleBlock,
};
use serde::{Deserialize, Serialize};

/// The largest payment a proof may carry: what Bitcoin nodes relay as a
/// standard transaction.
pub const MAX_PAYMENT_TX_BYTES: usize = 100_000;
/// The largest coinbase transaction a proof may carry. With the payment, in
/// hexadecimal, it fits the payload of one action.
pub const MAX_COINBASE_TX_BYTES: usize = 150_000;
/// How far the header chain is walked for one proof. A walk is needed only
/// where the chain holds more than one block at the payment's height, which
/// is near its tip.
pub const MAX_PAYMENT_WALK: u32 = 1_008;
/// How far at or below the starting height a payment's block may lie when
/// the chain of most work has changed since the purpose began. Natural
/// reorganisations are a block or two deep; a wider door would let blocks
/// mined in private, before the purpose began, count as payments after it.
pub const START_SLACK: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentProof {
    pub block_hash: BlockHash,
    /// The payment, serialized without witness data.
    pub transaction: Vec<u8>,
    pub vout: u32,
    /// The coinbase transaction of the same block, serialized without
    /// witness data. It pins the depth of the Merkle tree: without it a
    /// 64-byte transaction could pass for an inner node, and a longer
    /// "transaction" be invented below it.
    pub coinbase: Vec<u8>,
    /// Core gettxoutproof / BIP37 MerkleBlock bytes, matching exactly two
    /// transactions: the coinbase and the payment.
    pub merkle_proof: Vec<u8>,
}

/// What a proof says by itself, before any header is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedPayment {
    pub outpoint: OutPoint,
    pub sats: u64,
    transaction: Transaction,
    coinbase: Transaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPayment {
    pub outpoint: OutPoint,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub confirmations: u32,
    pub sats: u64,
}

/// Whether `script` is one of the five standard receiving forms: pay to
/// public key hash, to script hash, to witness public key hash, to witness
/// script hash, to taproot. Nothing else can be a receiving script.
pub fn standard_script(script: &[u8]) -> bool {
    match script {
        [0x76, 0xa9, 0x14, rest @ ..] => rest.len() == 22 && rest[20..] == [0x88, 0xac],
        [0xa9, 0x14, rest @ ..] => rest.len() == 21 && rest[20] == 0x87,
        [0x00, 0x14, rest @ ..] => rest.len() == 20,
        [0x00, 0x20, rest @ ..] | [0x51, 0x20, rest @ ..] => rest.len() == 32,
        _ => false,
    }
}

/// A transaction as a proof must carry it: within the size bound, in its
/// one canonical serialization, and without witness data (the transaction
/// id does not cover a witness, so witness bytes would be padding nobody
/// paid a Bitcoin fee for).
fn carried(bytes: &[u8], what: &str, most: usize) -> Result<Transaction> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= most,
        "Bitcoin {what} transaction bound"
    );
    let transaction: Transaction = deserialize(bytes).with_context(|| format!("Bitcoin {what} transaction"))?;
    ensure!(
        serialize(&transaction) == bytes,
        "noncanonical Bitcoin {what} transaction serialization"
    );
    ensure!(
        transaction.input.iter().all(|input| input.witness.is_empty()),
        "the Bitcoin {what} transaction is carried without its witness data"
    );
    ensure!(
        !transaction.input.is_empty() && !transaction.output.is_empty(),
        "empty Bitcoin {what} transaction"
    );
    transaction.output.iter().try_fold(0u64, |sum, output| {
        sum.checked_add(output.value.to_sat())
            .filter(|n| *n <= MAX_BITCOIN_SATS)
            .context("Bitcoin transaction output monetary range")
    })?;
    Ok(transaction)
}

/// Reads a proof by itself: the payment pays exactly `script` at the output
/// it names, and the coinbase transaction is one. No header is read and no
/// proof of work is checked: what this returns is a claim.
pub fn claimed_payment(proof: &PaymentProof, script: &[u8]) -> Result<ClaimedPayment> {
    ensure!(standard_script(script), "not a standard receiving script");
    crate::receipt::preflight_merkle_proof(&proof.merkle_proof)?;
    let transaction = carried(&proof.transaction, "payment", MAX_PAYMENT_TX_BYTES)?;
    // The 64-byte transaction / inner Merkle node ambiguity.
    ensure!(transaction.base_size() > 64, "ambiguous short Bitcoin payment transaction");
    ensure!(!transaction.is_coinbase(), "a coinbase output does not pay for a fill");
    let mut inputs = std::collections::BTreeSet::new();
    for input in &transaction.input {
        ensure!(
            !input.previous_output.is_null() && inputs.insert(input.previous_output),
            "null or duplicate Bitcoin payment input"
        );
    }
    // No length is asked of the coinbase: a miner may make it 64 bytes, and
    // an inner node cannot pass for one (it would have to begin with a
    // version, one input and a null previous output: 28 fixed bytes of a
    // hash, and more further on).
    let coinbase = carried(&proof.coinbase, "coinbase", MAX_COINBASE_TX_BYTES)?;
    ensure!(coinbase.is_coinbase(), "the second transaction of a proof is the block's coinbase");
    let output = transaction
        .output
        .get(usize::try_from(proof.vout)?)
        .context("Bitcoin output index out of range")?;
    ensure!(
        output.script_pubkey.as_bytes() == script,
        "Bitcoin receiving script mismatch"
    );
    let sats = output.value.to_sat();
    ensure!(sats >= 1, "Bitcoin payment has no value");
    Ok(ClaimedPayment {
        outpoint: OutPoint { txid: transaction.compute_txid(), vout: proof.vout },
        sats,
        transaction,
        coinbase,
    })
}

impl HeaderChain {
    /// Verifies that `proof` shows an output paying exactly `script`, in a
    /// block of the chain of most work that comes after the starting block
    /// (`start_height`, `start_hash`), with at least `confirmations`.
    /// Returns the output and its value.
    ///
    /// "After the starting block": above its height, or, when the chain of
    /// most work has changed since and is lower there, a block that was not
    /// part of the chain the starting block ended. The block a payment was
    /// in when the purpose began never counts.
    ///
    /// The header chain must not be halted; it need not be fresh. The caller
    /// MUST refuse an output it has accepted before and record this one in
    /// the same authenticated transaction as the effect it has.
    pub fn verify_payment(
        &self,
        reader: &impl HeaderReader,
        proof: &PaymentProof,
        script: &[u8],
        start_height: u32,
        start_hash: &BlockHash,
        confirmations: u32,
    ) -> Result<AcceptedPayment> {
        ensure!(
            self.meta.halted.is_none(),
            "Bitcoin bridge paused after reorganization"
        );
        // Ordinary payments are closed on mainnet in this version, whatever
        // the gate of the auction's receipts says.
        ensure!(
            self.meta.config.network != BitcoinNetwork::Mainnet,
            "ordinary Bitcoin payments are closed on mainnet in this version"
        );
        ensure!(confirmations >= 1, "a payment needs a confirmation");
        let claim = claimed_payment(proof, script)?;
        let merkle: MerkleBlock = deserialize(&proof.merkle_proof)?;
        ensure!(
            serialize(&merkle) == proof.merkle_proof,
            "noncanonical Bitcoin merkle proof"
        );
        ensure!(
            merkle.header.block_hash() == proof.block_hash,
            "Bitcoin merkle proof block mismatch"
        );
        // The proof ties both transactions to the header: the coinbase at
        // the first place, the payment after it. Both are leaves of one
        // tree, so the payment lies at the coinbase's depth.
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        merkle.extract_matches(&mut matches, &mut indexes)?;
        ensure!(
            matches.len() == 2
                && indexes.len() == 2
                && indexes[0] == 0
                && indexes[1] >= 1
                && matches[0] == claim.coinbase.compute_txid()
                && matches[1] == claim.outpoint.txid,
            "Bitcoin merkle proof does not match exactly the coinbase and the payment"
        );
        // One row: the block.
        let block = reader
            .header(&proof.block_hash)?
            .context("payment Bitcoin block unknown or pruned")?;
        ensure!(
            block.header == merkle.header && block.header.block_hash() == proof.block_hash,
            "payment header record mismatch"
        );
        let confirmed = self
            .meta
            .best_height
            .checked_sub(block.height)
            .and_then(|n| n.checked_add(1))
            .context("payment block is above the best height")?;
        ensure!(
            confirmed >= confirmations,
            "Bitcoin payment lacks confirmations"
        );
        // Where the chain holds one block at a height, that block is on
        // the chain of most work, and on every branch that reaches the
        // height: no walk is needed. That is every height but those near
        // the tip where branches compete.
        let at_height = reader.hashes_at_height(block.height)?;
        let alone = at_height.len() == 1 && at_height[0] == proof.block_hash;
        if block.height <= start_height {
            // The chain of most work changed since the start, and the
            // payment's block is at or below the starting height. It counts
            // only if it is close below, and was not part of the chain the
            // purpose started on.
            ensure!(
                !alone && start_height - block.height < START_SLACK,
                "Bitcoin payment is not after the starting block"
            );
            // The new branch must have grown as far past the start as a
            // payment in the block after the start would need for its
            // confirmations. Without this, someone who mined a branch in
            // private would need a lead of one block, not of the
            // confirmations asked, to make a block of it count.
            ensure!(
                self.meta.best_height >= start_height.saturating_add(confirmations),
                "after a reorganisation a payment counts when the chain has its confirmations past the starting height"
            );
            let start = reader
                .header(start_hash)?
                .context("Bitcoin payment is not after the starting block, which is no longer held")?;
            ensure!(
                start.height == start_height && start.header.block_hash() == *start_hash,
                "starting block record mismatch"
            );
            let then = self.ancestor(reader, *start_hash, block.height)?;
            ensure!(
                then.header.block_hash() != proof.block_hash,
                "Bitcoin payment is not after the starting block"
            );
        }
        if !alone {
            ensure!(
                at_height.contains(&proof.block_hash),
                "payment header is not indexed at its height"
            );
            ensure!(
                confirmed <= MAX_PAYMENT_WALK,
                "branches compete at the height of this payment, too far below the tip to be told apart"
            );
            let canonical = self.ancestor(reader, self.meta.best_tip, block.height)?;
            ensure!(
                canonical.header.block_hash() == proof.block_hash,
                "payment is not on greatest-work Bitcoin chain"
            );
        }
        Ok(AcceptedPayment {
            outpoint: claim.outpoint,
            block_hash: proof.block_hash,
            block_height: block.height,
            confirmations: confirmed,
            sats: claim.sats,
        })
    }
}
