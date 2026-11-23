//! Header validation, durable receipt consumption and auction credit share one
//! staged JMT transaction. An RPC server supplies bytes, never validity.
use crate::{auction, engine::ExtensionHost, treasury_adapter, wire::SignedAction};
use anyhow::{Result, anyhow, ensure};
use bitcoin_bridge::{
    HeaderChain, HeaderReader, HeaderRecord, HeaderTransition, ReceiptIndex,
    bitcoin::{BlockHash, OutPoint, block::Header, consensus::deserialize, hashes::Hash},
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const STATE_KEY: &[u8] = b"bitcoin/meta";
pub const MAX_FUNDING_TX_BYTES: usize = 240 * 1024;
/// Hex replaces JSON byte arrays and has an explicit PREPAYMENT budget. Larger
/// Bitcoin transactions are outside this version's supported funding contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactProof {
    pub network: bitcoin_bridge::BitcoinNetwork,
    pub block_hash: String,
    pub transaction_hex: String,
    pub vout: u32,
    #[serde(with = "pos::decimal::u64")]
    pub expected_sats: u64,
    pub merkle_proof_hex: String,
}
impl CompactProof {
    pub fn decode(self) -> Result<bitcoin_bridge::ReceiptProof> {
        ensure!(
            !self.transaction_hex.is_empty()
                && self.transaction_hex.len() <= MAX_FUNDING_TX_BYTES * 2
                && self.merkle_proof_hex.len() <= bitcoin_bridge::MAX_MERKLE_PROOF_BYTES * 2,
            "funding transaction/proof exceeds supported compact receipt budget"
        );
        let block_hash = BlockHash::from_str(&self.block_hash)?;
        ensure!(
            block_hash.to_string() == self.block_hash,
            "noncanonical Bitcoin block hash"
        );
        let transaction = hex::decode(&self.transaction_hex)?;
        let merkle_proof = hex::decode(&self.merkle_proof_hex)?;
        ensure!(
            hex::encode(&transaction) == self.transaction_hex
                && hex::encode(&merkle_proof) == self.merkle_proof_hex,
            "noncanonical compact receipt hexadecimal"
        );
        Ok(bitcoin_bridge::ReceiptProof {
            network: self.network,
            block_hash,
            transaction,
            vout: self.vout,
            expected_sats: self.expected_sats,
            merkle_proof,
        })
    }
}
pub fn header_key(hash: &BlockHash) -> Vec<u8> {
    [b"bitcoin/header/".as_slice(), hash.as_byte_array()].concat()
}
pub fn height_key(height: u32) -> Vec<u8> {
    [b"bitcoin/height/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn receipt_key(outpoint: &OutPoint) -> Vec<u8> {
    [
        b"bitcoin/receipt/".as_slice(),
        outpoint.txid.as_byte_array(),
        &outpoint.vout.to_be_bytes(),
    ]
    .concat()
}
pub fn credit_prefix(epoch: u64, owner: u64) -> Vec<u8> {
    [
        b"bitcoin/credit/".as_slice(),
        &epoch.to_be_bytes(),
        &owner.to_be_bytes(),
    ]
    .concat()
}
pub fn credit_key(receipt: &bitcoin_bridge::AcceptedReceipt) -> Vec<u8> {
    [
        credit_prefix(receipt.auction_epoch, receipt.account).as_slice(),
        receipt.outpoint.txid.as_byte_array(),
        &receipt.outpoint.vout.to_be_bytes(),
    ]
    .concat()
}
pub fn get(host: &impl ExtensionHost) -> Result<HeaderChain> {
    let row: HeaderChain = serde_json::from_slice(
        &host
            .get(STATE_KEY)?
            .ok_or_else(|| anyhow!("missing Bitcoin bridge state"))?,
    )?;
    ensure!(
        row.meta.config == host.meta().config.bitcoin,
        "Bitcoin configuration mismatch"
    );
    Ok(row)
}
struct Reader<'a, H>(&'a H);
impl<H: ExtensionHost> HeaderReader for Reader<'_, H> {
    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>> {
        let row: Option<HeaderRecord> = self
            .0
            .get(&header_key(hash))?
            .map(|raw| serde_json::from_slice(&raw))
            .transpose()?;
        if let Some(row) = &row {
            ensure!(
                row.header.block_hash() == *hash,
                "Bitcoin header alias mismatch"
            );
        }
        Ok(row)
    }
    fn hashes_at_height(&self, height: u32) -> Result<Vec<BlockHash>> {
        Ok(self
            .0
            .get(&height_key(height))?
            .map(|raw| serde_json::from_slice(&raw))
            .transpose()?
            .unwrap_or_default())
    }
}
impl<H: ExtensionHost> ReceiptIndex for Reader<'_, H> {
    fn consumed(&self, outpoint: &OutPoint) -> Result<bool> {
        Ok(self.0.get(&receipt_key(outpoint))?.is_some())
    }
}
fn persist(host: &mut impl ExtensionHost, transition: HeaderTransition) -> Result<()> {
    for (hash, _) in transition.deletes {
        host.put(header_key(&hash), None)?;
    }
    for row in transition.writes {
        host.put(
            header_key(&row.header.block_hash()),
            Some(serde_json::to_vec(&row)?),
        )?;
    }
    for (height, hashes) in transition.height_updates {
        host.put(
            height_key(height),
            if hashes.is_empty() {
                None
            } else {
                Some(serde_json::to_vec(&hashes)?)
            },
        )?;
    }
    host.put(
        STATE_KEY.to_vec(),
        Some(serde_json::to_vec(&transition.chain)?),
    )
}
pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    persist(
        host,
        HeaderChain::bootstrap_genesis(host.meta().config.bitcoin.clone())?,
    )
}
pub fn begin_block(_host: &mut impl ExtensionHost) -> Result<()> {
    Ok(())
}
pub fn apply(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    let chain = get(host)?;
    let now = u64::try_from(host.meta().time_micros)? / 1_000_000;
    match action.kind {
        40 => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                headers: Vec<String>,
            }
            let input: Input = serde_json::from_value(action.payload.clone())?;
            ensure!(
                !input.headers.is_empty() && input.headers.len() <= chain.meta.config.max_batch,
                "Bitcoin header batch bound"
            );
            let headers = input
                .headers
                .iter()
                .map(|text| {
                    let bytes = hex::decode(text)?;
                    ensure!(
                        bytes.len() == 80 && hex::encode(&bytes) == *text,
                        "noncanonical Bitcoin header"
                    );
                    Ok(deserialize::<Header>(&bytes)?)
                })
                .collect::<Result<Vec<_>>>()?;
            let transition = chain.prepare_headers(&Reader(host), &headers, now)?;
            persist(host, transition)
        }
        41 => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Input {
                #[serde(with = "pos::decimal::u64")]
                epoch: u64,
                #[serde(with = "pos::decimal::u64")]
                policy_revision: u64,
                receipt: CompactProof,
            }
            let p: Input = serde_json::from_value(action.payload.clone())?;
            auction::validate_target(host, p.epoch)?;
            let policy = treasury_adapter::receiving_policy_for_claim(host, p.policy_revision)?;
            let context = bitcoin_bridge::BidContext {
                time_network: treasury_adapter::network(host)?,
                account: action.from,
                auction_epoch: p.epoch,
                policy_revision: p.policy_revision,
                time_micros: host.meta().elapsed_micros()?,
            };
            let receipt = p.receipt.decode()?;
            let transition = chain.prepare_receipt(
                &Reader(host),
                &Reader(host),
                &receipt,
                &policy,
                &context,
                now,
            )?;
            auction::record_bid(host, action.from, p.epoch, transition.receipt.sats)?;
            host.put(
                receipt_key(&transition.receipt.outpoint),
                Some(serde_json::to_vec(&transition.receipt)?),
            )?;
            host.put(
                credit_key(&transition.receipt),
                Some(serde_json::to_vec(&transition.receipt.outpoint)?),
            )?;
            host.put(
                STATE_KEY.to_vec(),
                Some(serde_json::to_vec(&transition.chain)?),
            )
        }
        _ => Err(anyhow!("unsupported Bitcoin bridge action")),
    }
}
pub fn audit(
    snapshot: &crate::store::VerifiedAudit<'_>,
    meta: &crate::engine::Meta,
) -> Result<u64> {
    use crate::engine::canonical_decode;
    let chain: HeaderChain = canonical_decode(
        &snapshot
            .get(STATE_KEY)?
            .ok_or_else(|| anyhow!("missing Bitcoin summary"))?,
    )?;
    chain.meta.config.validate()?;
    ensure!(
        chain.meta.config == meta.config.bitcoin,
        "Bitcoin configuration mismatch"
    );
    let mut headers = 0u64;
    let mut indexes = 0u64;
    let mut receipts = 0u64;
    let mut credits = 0u64;
    snapshot.for_each_prefix(b"bitcoin/header/", |key, value| {
        let row: HeaderRecord = canonical_decode(value)?;
        let hash = row.header.block_hash();
        ensure!(
            key == header_key(&hash) && row.height >= chain.meta.pruned_below,
            "Bitcoin header key/height mismatch"
        );
        row.header.validate_pow(row.header.target())?;
        let index: Vec<BlockHash> = canonical_decode(
            &snapshot
                .get(&height_key(row.height))?
                .ok_or_else(|| anyhow!("missing Bitcoin height index"))?,
        )?;
        ensure!(
            index.iter().filter(|h| **h == hash).count() == 1,
            "Bitcoin height index mismatch"
        );
        if let Some(raw) = snapshot.get(&header_key(&row.header.prev_blockhash))? {
            let parent: HeaderRecord = canonical_decode(&raw)?;
            ensure!(
                parent.height.checked_add(1) == Some(row.height)
                    && parent.chainwork < row.chainwork,
                "Bitcoin parent coordinate/work mismatch"
            );
        }
        headers += 1;
        Ok(())
    })?;
    snapshot.for_each_prefix(b"bitcoin/height/", |key, value| {
        ensure!(
            key.len() == b"bitcoin/height/".len() + 4,
            "invalid Bitcoin height key"
        );
        let height = u32::from_be_bytes(key[key.len() - 4..].try_into()?);
        let hashes: Vec<BlockHash> = canonical_decode(value)?;
        ensure!(
            !hashes.is_empty() && hashes.len() <= chain.meta.config.max_fork_tips + 1,
            "Bitcoin height index bound"
        );
        let mut seen = std::collections::BTreeSet::new();
        for hash in hashes {
            ensure!(seen.insert(hash), "duplicate Bitcoin height entry");
            let row: HeaderRecord = canonical_decode(
                &snapshot
                    .get(&header_key(&hash))?
                    .ok_or_else(|| anyhow!("orphan Bitcoin height entry"))?,
            )?;
            ensure!(row.height == height, "Bitcoin index height mismatch");
        }
        indexes += 1;
        Ok(())
    })?;
    let tip: HeaderRecord = canonical_decode(
        &snapshot
            .get(&header_key(&chain.meta.best_tip))?
            .ok_or_else(|| anyhow!("missing Bitcoin best tip"))?,
    )?;
    ensure!(
        headers == u64::from(chain.meta.record_count)
            && tip.height == chain.meta.best_height
            && tip.chainwork == chain.meta.best_work,
        "Bitcoin tip/count mismatch"
    );
    snapshot.for_each_prefix(b"bitcoin/receipt/", |key, value| {
        let receipt: bitcoin_bridge::AcceptedReceipt = canonical_decode(value)?;
        ensure!(
            key == receipt_key(&receipt.outpoint)
                && receipt.sats >= meta.config.auction.min_sats
                && receipt.sats <= meta.config.auction.max_sats
                && receipt.confirmations >= meta.config.bitcoin.confirmations
                && receipt.block_height <= chain.meta.credited_height
                && snapshot
                    .get(&crate::engine::account_key(receipt.account))?
                    .is_some(),
            "invalid consumed Bitcoin receipt"
        );
        let policy: bitcoin_bridge::ReceivingPolicy = canonical_decode(
            &snapshot
                .get(&treasury_adapter::policy_key(receipt.policy_revision))?
                .ok_or_else(|| anyhow!("receipt receiving policy missing"))?,
        )?;
        ensure!(
            receipt.block_height >= policy.btc_start_height
                && policy
                    .btc_end_height
                    .is_none_or(|end| receipt.block_height < end),
            "receipt outside authenticated receiving height interval"
        );
        let outpoint: OutPoint = canonical_decode(
            &snapshot
                .get(&credit_key(&receipt))?
                .ok_or_else(|| anyhow!("missing receipt credit index"))?,
        )?;
        ensure!(outpoint == receipt.outpoint, "receipt credit alias");
        receipts += 1;
        Ok(())
    })?;
    snapshot.for_each_prefix(b"bitcoin/credit/", |key, value| {
        let outpoint: OutPoint = canonical_decode(value)?;
        let receipt: bitcoin_bridge::AcceptedReceipt = canonical_decode(
            &snapshot
                .get(&receipt_key(&outpoint))?
                .ok_or_else(|| anyhow!("orphan receipt credit"))?,
        )?;
        ensure!(
            key == credit_key(&receipt) && receipt.outpoint == outpoint,
            "credit coordinate mismatch"
        );
        credits += 1;
        Ok(())
    })?;
    ensure!(receipts == credits, "Bitcoin receipt index count mismatch");
    let expected = 1 + headers + indexes + receipts + credits;
    let mut actual = 0;
    snapshot.for_each_prefix(b"bitcoin/", |_, _| {
        actual += 1;
        Ok(())
    })?;
    ensure!(expected == actual, "unexpected Bitcoin namespace leaf");
    Ok(expected)
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    #[test]
    fn supported_transaction_and_worst_proof_fit_before_payment() {
        let receipt = CompactProof {
            network: bitcoin_bridge::BitcoinNetwork::Regtest,
            block_hash: "00".repeat(32),
            transaction_hex: "00".repeat(MAX_FUNDING_TX_BYTES),
            vout: u32::MAX,
            expected_sats: 2_100_000_000_000_000,
            merkle_proof_hex: "00".repeat(bitcoin_bridge::MAX_MERKLE_PROOF_BYTES),
        };
        let value = serde_json::json!({"epoch":u64::MAX.to_string(),"policy_revision":u64::MAX.to_string(),"receipt":receipt});
        assert!(serde_json::to_vec(&value).unwrap().len() < crate::wire::MAX_PAYLOAD);
        let receipt: CompactProof = serde_json::from_value(value["receipt"].clone()).unwrap();
        assert_eq!(
            receipt.clone().decode().unwrap().transaction.len(),
            MAX_FUNDING_TX_BYTES
        );
        let mut bad = receipt;
        bad.transaction_hex.push_str("00");
        assert!(bad.decode().is_err());
    }
    #[test]
    fn old_integer_array_encoding_and_uppercase_hex_are_rejected() {
        let value = serde_json::json!({"network":"regtest","block_hash":"00".repeat(32),"transaction":[0],"vout":0,"expected_sats":1,"merkle_proof":[]});
        assert!(serde_json::from_value::<CompactProof>(value).is_err());
        let proof = CompactProof {
            network: bitcoin_bridge::BitcoinNetwork::Regtest,
            block_hash: "00".repeat(32),
            transaction_hex: "AA".into(),
            vout: 0,
            expected_sats: 1,
            merkle_proof_hex: String::new(),
        };
        assert!(proof.decode().is_err());
    }
}
