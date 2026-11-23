//! Regression adapter for real Bitcoin Core regtest data, never a Bitcoin RPC
//! oracle or a mainnet enabling command.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::PathBuf};
use timecurrency_bitcoin_bridge::{
    bitcoin::{BlockHash, block::Header, consensus::deserialize},
    *,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    network: BitcoinNetwork,
    now_secs: u64,
    headers_hex: Vec<String>,
    expected_best_hash: BlockHash,
    policy: ReceivingPolicy,
    context: BidContext,
    receipt: ReceiptProof,
    #[serde(default)]
    reorg_headers_hex: Vec<String>,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let input = PathBuf::from(args.next().context("scenario JSON path required")?);
    let output = PathBuf::from(args.next().context("NEW output JSON path required")?);
    ensure!(args.next().is_none(), "unexpected argument");
    ensure!(!output.exists(), "existing result is preserved");
    let bytes = fs::read(input)?;
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "regtest scenario byte bound"
    );
    let scenario: Scenario = serde_json::from_slice(&bytes)?;
    ensure!(
        scenario.network == BitcoinNetwork::Regtest,
        "this regression adapter is regtest only"
    );
    ensure!(
        scenario.headers_hex.len() <= 20_000,
        "regtest scenario header count bound"
    );
    let initial = HeaderChain::bootstrap_genesis(BridgeConfig::for_network(scenario.network))?;
    let mut store = MemoryHeaderStore::default();
    store.apply(&initial);
    let mut chain = initial.chain;
    for batch in scenario.headers_hex.chunks(chain.meta.config.max_batch) {
        let headers = batch
            .iter()
            .map(|hex| {
                ensure!(hex.len() == 160, "Bitcoin header hex length");
                Ok(deserialize::<Header>(&hex::decode(hex)?)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let transition = chain.prepare_headers(&store, &headers, scenario.now_secs)?;
        store.apply(&transition);
        chain = transition.chain;
    }
    ensure!(
        chain.meta.best_tip == scenario.expected_best_hash,
        "validated header tip differs from expected Core fixture"
    );
    let mut used = MemoryReceiptIndex::default();
    let accepted = chain.prepare_receipt(
        &store,
        &used,
        &scenario.receipt,
        &scenario.policy,
        &scenario.context,
        scenario.now_secs,
    )?;
    used.apply(&accepted)?;
    let duplicate = accepted
        .chain
        .prepare_receipt(
            &store,
            &used,
            &scenario.receipt,
            &scenario.policy,
            &scenario.context,
            scenario.now_secs,
        )
        .is_err();
    ensure!(duplicate, "duplicate outpoint accepted");
    let mut forged = scenario.receipt.clone();
    forged.expected_sats = forged
        .expected_sats
        .checked_add(1)
        .context("amount overflow")?;
    let forged_rejected = chain
        .prepare_receipt(
            &store,
            &MemoryReceiptIndex::default(),
            &forged,
            &scenario.policy,
            &scenario.context,
            scenario.now_secs,
        )
        .is_err();
    ensure!(forged_rejected, "forged amount accepted");
    let mut reorg_paused = false;
    if !scenario.reorg_headers_hex.is_empty() {
        ensure!(
            scenario.reorg_headers_hex.len() <= accepted.chain.meta.config.max_batch,
            "reorg regression header bound"
        );
        let headers = scenario
            .reorg_headers_hex
            .iter()
            .map(|hex| {
                ensure!(hex.len() == 160, "reorg header length");
                Ok(deserialize::<Header>(&hex::decode(hex)?)?)
            })
            .collect::<Result<Vec<_>>>()?;
        let transition = accepted
            .chain
            .prepare_headers(&store, &headers, scenario.now_secs)?;
        store.apply(&transition);
        ensure!(
            matches!(
                transition.chain.meta.halted,
                Some(HaltReason::CreditedReceiptReorg { .. })
            ),
            "real regtest receipt reorganization failed to pause earnings"
        );
        ensure!(
            transition
                .chain
                .prepare_receipt(
                    &store,
                    &used,
                    &scenario.receipt,
                    &scenario.policy,
                    &scenario.context,
                    scenario.now_secs
                )
                .is_err(),
            "paused bridge accepted a receipt"
        );
        reorg_paused = true;
    }
    let report = json!({"schema_version":1,"source":"Bitcoin Core regtest scenario; headers and proofs independently checked by rust-bitcoin","mainnet_receipts_enabled":false,"network":scenario.network,"validated_headers":store.records.len(),"tip_height":chain.meta.best_height,"tip_hash":chain.meta.best_tip,"tip_chainwork":chain.meta.best_work,"receipt":accepted.receipt,"duplicate_outpoint_rejected":duplicate,"forged_value_rejected":forged_rejected,"real_core_receipt_reorg_paused":reorg_paused,"scope":"PoW/header/Merkle inclusion verification; full Bitcoin transaction/script validity is supplied by Core, not independently implemented here"});
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    println!(
        "Regtest SPV receipt verified at Bitcoin height {}",
        chain.meta.best_height
    );
    Ok(())
}
