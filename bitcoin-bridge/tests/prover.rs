//! Proofs of payment that the market's prover made from a real Bitcoin Core
//! in regtest, held to this crate's verifier (`spec/market.md`, section 5.2).
//!
//! `client-v4/market-services-regtest.test.mjs` writes one run's headers and
//! proofs to the file `TIME_MARKET_REGTEST_EXPORT` names. This test reads the
//! file `TIME_MARKET_REGTEST_SCENARIO` names, builds the header chain from the
//! regtest genesis block with those headers (proof of work, difficulty and
//! links checked as for any kind 40 action), and verifies each proof as the
//! engine does for a kind 54 action. Without the variable it checks nothing
//! and says so: the scenario needs a Bitcoin Core binary to make.
use bitcoin::{BlockHash, block::Header, consensus::deserialize};
use serde::Deserialize;
use std::str::FromStr;
use timecurrency_bitcoin_bridge::*;

#[derive(Deserialize)]
struct Scenario {
    now_secs: u64,
    headers: Vec<String>,
    payments: Vec<Payment>,
}
#[derive(Deserialize)]
struct Payment {
    script: String,
    start_height: u32,
    start_hash: String,
    confirmations: u32,
    sats: String,
    proof: Proof,
}
#[derive(Deserialize)]
struct Proof {
    block_hash: String,
    transaction: String,
    vout: u32,
    coinbase: String,
    merkle_proof: String,
}

#[test]
fn proofs_the_prover_made_from_bitcoin_core_are_accepted() {
    let Ok(path) = std::env::var("TIME_MARKET_REGTEST_SCENARIO") else {
        eprintln!("TIME_MARKET_REGTEST_SCENARIO is not set: no proof of the prover was checked");
        return;
    };
    let scenario: Scenario = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let start = HeaderChain::bootstrap_genesis(BridgeConfig::for_network(BitcoinNetwork::Regtest)).unwrap();
    let mut store = MemoryHeaderStore::default();
    store.apply(&start);
    let mut chain = start.chain;
    let headers: Vec<Header> = scenario
        .headers
        .iter()
        .map(|text| deserialize(&hex::decode(text).unwrap()).unwrap())
        .collect();
    // As a relay hands them in: batches of at most `max_batch`.
    for batch in headers.chunks(chain.meta.config.max_batch) {
        let taken = chain.prepare_headers(&store, batch, scenario.now_secs).unwrap();
        store.apply(&taken);
        chain = taken.chain;
    }
    assert_eq!(chain.meta.best_height as usize, headers.len());
    assert_eq!(chain.meta.best_tip, headers.last().unwrap().block_hash());
    assert!(chain.meta.halted.is_none());
    assert!(!scenario.payments.is_empty(), "the scenario holds no payment");
    for payment in &scenario.payments {
        let proof = PaymentProof {
            block_hash: BlockHash::from_str(&payment.proof.block_hash).unwrap(),
            transaction: hex::decode(&payment.proof.transaction).unwrap(),
            vout: payment.proof.vout,
            coinbase: hex::decode(&payment.proof.coinbase).unwrap(),
            merkle_proof: hex::decode(&payment.proof.merkle_proof).unwrap(),
        };
        let script = hex::decode(&payment.script).unwrap();
        let start_hash = BlockHash::from_str(&payment.start_hash).unwrap();
        let verify = |proof: &PaymentProof, confirmations: u32| {
            chain.verify_payment(&store, proof, &script, payment.start_height, &start_hash, confirmations)
        };
        let accepted = verify(&proof, payment.confirmations).unwrap();
        assert_eq!(accepted.sats.to_string(), payment.sats);
        assert_eq!(accepted.block_hash, proof.block_hash);
        assert_eq!(accepted.outpoint.vout, proof.vout);
        assert!(accepted.block_height > payment.start_height);
        assert_eq!(accepted.confirmations, chain.meta.best_height - accepted.block_height + 1);
        // The same proof with more confirmations asked than the chain has is refused.
        assert!(verify(&proof, accepted.confirmations + 1).is_err());
        // And so is one that names another output of the transaction.
        let mut other = PaymentProof { vout: proof.vout + 1, ..proof.clone() };
        assert!(verify(&other, payment.confirmations).is_err());
        other.vout = proof.vout;
        other.merkle_proof.pop();
        assert!(verify(&other, payment.confirmations).is_err());
    }
}
