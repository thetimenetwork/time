//! Recorded roots: a network without the service records runs staking,
//! punishments, registrations and stops exactly as it did before that
//! setting existed.
//!
//! The run is `stake_script`: 52 blocks on three networks (the protocol-4
//! settings; every optional setting there was before the service records;
//! all new time to validators without the stake hand-over rule), in which
//! validators register, bond, take stake out, retire and register again,
//! delegations come and go, two starting validators are punished, some
//! blocks leave signatures out, accounts are registered and the chain
//! stands still for fifteen days and for three hours. The network id, the
//! state root, the hash of the metadata row and the number of actions a
//! proposer kept were recorded after every block with the engine as it was
//! before the service records were built (on top of the shorter threshold
//! of the clock of the waits), and the same run must give the same values
//! now.
//!
//! Nothing here names the new setting, so that the file compiles and runs
//! unchanged on the engine before it. To record again (only ever on an
//! engine whose rules are known to be the recorded ones):
//! `V5_RECORD_RECORDS_OFF=1 cargo test --test records_unchanged`.
mod common;
mod stake_script;
use common::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stake_script::{BLOCKS, Step, View};
use std::{collections::BTreeMap, path::PathBuf};
use timecurrency_v5::engine::Engine;
use timecurrency_v5::genesis::Genesis;
use timecurrency_v5::store::Store;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Block {
    height: String,
    kept: usize,
    root: String,
    meta_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Run {
    network_id: String,
    blocks: Vec<Block>,
    audited_leaves: String,
    audited_accounts: String,
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("records-off.json")
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history")).unwrap();
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network }
    }
    fn view(&self) -> View<'_> {
        View { engine: &self.engine, network: &self.network }
    }
    /// One block as a proposer builds it, a validator checks it and the
    /// reference path executes it. Returns what is recorded of it.
    fn block(&mut self, step: Step) -> Block {
        let meta = self.engine.meta().unwrap();
        let (height, time) = (meta.height + 1, meta.time_micros + step.delta as i64);
        let absent: Vec<String> = step.absent.iter().map(|owner| pk(*owner as u8 + 101)).collect();
        let signers: Vec<String> = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .filter(|key| !absent.contains(key))
            .collect();
        let hash = sha(height as u64);
        let misbehavior = &step.misbehavior;
        let (proposed, kept) = self
            .engine
            .prepare_filtered_with_misbehavior(height, time, &step.txs, &signers, 1 << 20, hash, misbehavior)
            .unwrap();
        let strict = self.engine.prepare_with_misbehavior(height, time, &kept, &signers, hash, misbehavior).unwrap();
        let reference = self.engine.prepare_reference_with_misbehavior(height, time, &kept, &signers, hash, misbehavior).unwrap();
        assert_eq!(strict.root, proposed.root, "validator and proposer disagree at {height}");
        assert_eq!(reference.root, proposed.root, "fast path and reference disagree at {height}");
        if kept.len() != step.txs.len() - step.refused {
            let reasons: Vec<String> = step
                .txs
                .iter()
                .map(|tx| match self.engine.prepare_with_misbehavior(height, time, &[tx], &signers, hash, misbehavior) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            let summary = String::from_utf8_lossy(&self.engine.version().unwrap().get(b"pos/meta").unwrap()).to_string();
            panic!("network {} height {height}: a scripted action was left out or kept: {reasons:?}\n{summary}", self.network);
        }
        self.engine.commit(proposed, hash).unwrap();
        let meta = self.engine.meta().unwrap();
        assert_eq!(
            meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total,
            meta.elapsed_micros().unwrap(),
            "supply rule at {height}"
        );
        let version = self.engine.version().unwrap();
        Block {
            height: version.height().to_string(),
            kept: kept.len(),
            root: hex::encode(version.root()),
            meta_sha256: hex::encode(Sha256::digest(&version.head().metadata)),
        }
    }
}

fn run(genesis: Genesis) -> Run {
    let mut chain = Chain::new(genesis);
    let mut blocks = Vec::new();
    for height in 1..=BLOCKS {
        let next = stake_script::step(&chain.view(), height);
        blocks.push(chain.block(next));
        if height % 13 == 0 {
            chain.engine.audit().unwrap();
        }
    }
    stake_script::check_the_run(&chain.view());
    let audit = chain.engine.audit().unwrap();
    assert!(audit.history_archive_verified);
    Run {
        network_id: chain.network.clone(),
        blocks,
        audited_leaves: audit.authenticated_leaves.to_string(),
        audited_accounts: audit.account_count.to_string(),
    }
}

#[test]
fn a_network_without_the_service_records_keeps_its_stake_and_its_roots_as_before() {
    let record = std::env::var("V5_RECORD_RECORDS_OFF").is_ok();
    let mut runs = BTreeMap::new();
    for (name, genesis) in stake_script::variants() {
        runs.insert(name.to_string(), run(genesis));
    }
    if record {
        std::fs::write(fixture(), serde_json::to_vec_pretty(&runs).unwrap()).unwrap();
        return;
    }
    let path = fixture();
    let expected: BTreeMap<String, Run> =
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap();
    assert_eq!(expected.keys().collect::<Vec<_>>(), runs.keys().collect::<Vec<_>>());
    for (name, run) in &runs {
        let old = &expected[name];
        assert_eq!(old.network_id, run.network_id, "{name}: network id");
        for (before, now) in old.blocks.iter().zip(&run.blocks) {
            assert_eq!(before, now, "{name}: first difference at height {}", before.height);
        }
        assert_eq!(old.blocks.len(), run.blocks.len(), "{name}: number of blocks");
        assert_eq!(old.audited_leaves, run.audited_leaves, "{name}: leaves the audit counts");
        assert_eq!(old.audited_accounts, run.audited_accounts, "{name}: accounts the audit counts");
    }
    // The three networks differ.
    let last = |name: &str| runs[name].blocks.last().unwrap().root.clone();
    assert_ne!(last("plain"), last("everything"));
    assert_ne!(last("plain"), last("bonding"));
}
