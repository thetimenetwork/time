use crate::{BitcoinNetwork, HeaderChain, HeaderReader};
use anyhow::{Context, Result, ensure};
use bitcoin::{
    BlockHash, OutPoint, Transaction,
    consensus::{deserialize, deserialize_partial, encode::VarInt, serialize},
    merkle_tree::MerkleBlock,
};
use serde::{Deserialize, Serialize};

pub const MAX_RECEIPT_TX_BYTES: usize = 1024 * 1024;
pub const MAX_MERKLE_PROOF_BYTES: usize = 4096;
pub const MAX_BITCOIN_SATS: u64 = 21_000_000 * 100_000_000;
pub const BID_DOMAIN: &[u8; 8] = b"TIMEBID1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivingPolicy {
    pub network: BitcoinNetwork,
    pub time_network: [u8; 32],
    pub revision: u64,
    pub script_pubkey: Vec<u8>,
    pub min_sats: u64,
    pub max_sats: u64,
    pub btc_start_height: u32,
    /// Exclusive bounds; absent end means the receiving policy remains active.
    pub btc_end_height: Option<u32>,
    pub time_start_micros: u64,
    pub time_end_micros: Option<u64>,
}
impl ReceivingPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.script_pubkey.is_empty()
                && self.script_pubkey.len() <= 10_000
                && self.script_pubkey[0] != 0x6a,
            "receiving script bound/type"
        );
        ensure!(
            self.min_sats > 0
                && self.min_sats <= self.max_sats
                && self.max_sats <= MAX_BITCOIN_SATS,
            "receiving value bound"
        );
        ensure!(
            self.btc_end_height
                .is_none_or(|h| h > self.btc_start_height)
                && self
                    .time_end_micros
                    .is_none_or(|t| t > self.time_start_micros),
            "receiving policy interval"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BidContext {
    pub time_network: [u8; 32],
    pub account: u64,
    pub auction_epoch: u64,
    pub policy_revision: u64,
    pub time_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptProof {
    pub network: BitcoinNetwork,
    pub block_hash: BlockHash,
    pub transaction: Vec<u8>,
    pub vout: u32,
    pub expected_sats: u64,
    /// Core gettxoutproof / BIP37 MerkleBlock bytes, matching exactly one txid.
    pub merkle_proof: Vec<u8>,
}
pub trait ReceiptIndex {
    fn consumed(&self, outpoint: &OutPoint) -> Result<bool>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedReceipt {
    pub outpoint: OutPoint,
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub confirmations: u32,
    pub account: u64,
    pub auction_epoch: u64,
    pub policy_revision: u64,
    pub sats: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptTransition {
    pub chain: HeaderChain,
    pub receipt: AcceptedReceipt,
}

pub fn bid_commitment(context: &BidContext) -> [u8; 64] {
    let mut payload = [0; 64];
    payload[..8].copy_from_slice(BID_DOMAIN);
    payload[8..40].copy_from_slice(&context.time_network);
    payload[40..48].copy_from_slice(&context.account.to_be_bytes());
    payload[48..56].copy_from_slice(&context.auction_epoch.to_be_bytes());
    payload[56..64].copy_from_slice(&context.policy_revision.to_be_bytes());
    payload
}
pub fn bid_commitment_script(context: &BidContext) -> Vec<u8> {
    let mut script = vec![0x6a, 64];
    script.extend_from_slice(&bid_commitment(context));
    script
}

impl HeaderChain {
    /// The caller MUST atomically persist receipt.outpoint in its consumed
    /// index, this updated chain metadata, and the auction credit. The index
    /// must include earlier receipt transitions staged in the same Time block.
    pub fn prepare_receipt(
        &self,
        reader: &impl HeaderReader,
        index: &impl ReceiptIndex,
        proof: &ReceiptProof,
        policy: &ReceivingPolicy,
        context: &BidContext,
        consensus_now_secs: u64,
    ) -> Result<ReceiptTransition> {
        self.ensure_fresh(reader, consensus_now_secs)?;
        policy.validate()?;
        ensure!(
            proof.network == self.meta.config.network && policy.network == proof.network,
            "Bitcoin receipt network mismatch"
        );
        ensure!(
            proof.network != BitcoinNetwork::Mainnet || self.meta.config.mainnet_receipts_enabled,
            "mainnet Bitcoin receipts are disabled until explicit production gates"
        );
        ensure!(
            policy.time_network == context.time_network
                && policy.revision == context.policy_revision,
            "Time network/policy binding mismatch"
        );
        ensure!(context.account != u64::MAX, "reserved Time account ID");
        ensure!(
            context.time_micros >= policy.time_start_micros
                && policy
                    .time_end_micros
                    .is_none_or(|end| context.time_micros < end),
            "Time receiving policy window closed"
        );
        ensure!(
            !proof.transaction.is_empty() && proof.transaction.len() <= MAX_RECEIPT_TX_BYTES,
            "Bitcoin receipt transaction bound"
        );
        preflight_merkle_proof(&proof.merkle_proof)?;
        let transaction: Transaction = deserialize(&proof.transaction)?;
        ensure!(
            serialize(&transaction) == proof.transaction,
            "noncanonical Bitcoin transaction serialization"
        );
        ensure!(
            !transaction.is_coinbase()
                && !transaction.input.is_empty()
                && !transaction.output.is_empty(),
            "coinbase or empty Bitcoin payment transaction"
        );
        let mut inputs = std::collections::BTreeSet::new();
        for input in &transaction.input {
            ensure!(
                !input.previous_output.is_null() && inputs.insert(input.previous_output),
                "null or duplicate Bitcoin payment input"
            );
        }
        let total = transaction.output.iter().try_fold(0u64, |sum, output| {
            sum.checked_add(output.value.to_sat())
                .filter(|n| *n <= MAX_BITCOIN_SATS)
                .context("Bitcoin transaction output monetary range")
        })?;
        ensure!(total > 0, "Bitcoin payment has no value");
        // Defense in depth against the 64-byte transaction/internal-merkle-node
        // ambiguity. A payment with this exact 64-byte commitment is larger.
        ensure!(
            transaction.base_size() > 64,
            "ambiguous short Bitcoin transaction"
        );
        let outpoint = OutPoint {
            txid: transaction.compute_txid(),
            vout: proof.vout,
        };
        ensure!(
            !index.consumed(&outpoint)?,
            "Bitcoin outpoint already consumed by a Time receipt"
        );
        let output = transaction
            .output
            .get(usize::try_from(proof.vout)?)
            .context("Bitcoin output index out of range")?;
        ensure!(
            output.script_pubkey.as_bytes() == policy.script_pubkey,
            "Bitcoin receiving script mismatch"
        );
        let sats = output.value.to_sat();
        ensure!(
            sats == proof.expected_sats && sats >= policy.min_sats && sats <= policy.max_sats,
            "Bitcoin exact output value/policy mismatch"
        );
        let expected = bid_commitment_script(context);
        let mut commitments = 0;
        for output in &transaction.output {
            let script = output.script_pubkey.as_bytes();
            if script == expected {
                ensure!(
                    output.value.to_sat() == 0,
                    "bid OP_RETURN output value must be zero"
                );
                commitments += 1;
            } else if script.first() == Some(&0x6a)
                && script
                    .windows(BID_DOMAIN.len())
                    .any(|window| window == BID_DOMAIN)
            {
                anyhow::bail!("ambiguous or noncanonical TIMEBID1 commitment");
            }
        }
        ensure!(
            commitments == 1,
            "Bitcoin transaction must contain exactly one bound TIMEBID1 commitment"
        );
        let merkle: MerkleBlock = deserialize(&proof.merkle_proof)?;
        ensure!(
            serialize(&merkle) == proof.merkle_proof,
            "noncanonical Bitcoin merkle proof"
        );
        ensure!(
            merkle.header.block_hash() == proof.block_hash,
            "Bitcoin merkle proof block mismatch"
        );
        let block = reader
            .header(&proof.block_hash)?
            .context("receipt Bitcoin block unknown or pruned")?;
        ensure!(
            block.header == merkle.header && block.header.block_hash() == proof.block_hash,
            "receipt header record mismatch"
        );
        ensure!(
            block.height >= policy.btc_start_height
                && policy.btc_end_height.is_none_or(|end| block.height < end),
            "Bitcoin receiving height window closed"
        );
        let canonical = self.ancestor(reader, self.meta.best_tip, block.height)?;
        ensure!(
            canonical.header.block_hash() == proof.block_hash,
            "receipt is not on greatest-work Bitcoin chain"
        );
        let confirmations = self
            .meta
            .best_height
            .checked_sub(block.height)
            .and_then(|n| n.checked_add(1))
            .context("receipt confirmation coordinate overflow")?;
        ensure!(
            confirmations >= self.meta.config.confirmations,
            "Bitcoin receipt lacks confirmations"
        );
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        merkle.extract_matches(&mut matches, &mut indexes)?;
        ensure!(
            matches.len() == 1 && indexes.len() == 1 && matches[0] == outpoint.txid,
            "Bitcoin merkle proof does not match exactly the payment txid"
        );
        let mut chain = self.clone();
        if block.height > chain.meta.credited_height {
            chain.meta.credited_height = block.height;
            chain.meta.credited_hash = proof.block_hash;
        }
        Ok(ReceiptTransition {
            chain,
            receipt: AcceptedReceipt {
                outpoint,
                block_hash: proof.block_hash,
                block_height: block.height,
                confirmations,
                account: context.account,
                auction_epoch: context.auction_epoch,
                policy_revision: context.policy_revision,
                sats,
            },
        })
    }
}

fn preflight_merkle_proof(bytes: &[u8]) -> Result<()> {
    ensure!(
        (86..=MAX_MERKLE_PROOF_BYTES).contains(&bytes.len()),
        "Bitcoin merkle proof byte bound"
    );
    let (hash_count, used) = deserialize_partial::<VarInt>(&bytes[84..])?;
    ensure!(
        (1..=64).contains(&hash_count.0),
        "Bitcoin single-match proof hash bound"
    );
    let offset = 84usize
        .checked_add(used)
        .and_then(|n| n.checked_add(hash_count.0 as usize * 32))
        .context("Bitcoin proof offset overflow")?;
    ensure!(offset < bytes.len(), "truncated Bitcoin proof hashes");
    let (flag_count, used) = deserialize_partial::<VarInt>(&bytes[offset..])?;
    ensure!(
        (1..=1024).contains(&flag_count.0),
        "Bitcoin proof flag allocation bound"
    );
    ensure!(
        offset
            .checked_add(used)
            .and_then(|n| n.checked_add(flag_count.0 as usize))
            == Some(bytes.len()),
        "Bitcoin merkle proof length mismatch"
    );
    Ok(())
}

#[derive(Default)]
pub struct MemoryReceiptIndex {
    pub consumed: std::collections::BTreeSet<OutPoint>,
}
impl ReceiptIndex for MemoryReceiptIndex {
    fn consumed(&self, outpoint: &OutPoint) -> Result<bool> {
        Ok(self.consumed.contains(outpoint))
    }
}
impl MemoryReceiptIndex {
    pub fn apply(&mut self, receipt: &ReceiptTransition) -> Result<()> {
        ensure!(
            self.consumed.insert(receipt.receipt.outpoint),
            "Bitcoin receipt outpoint was already applied"
        );
        Ok(())
    }
}
