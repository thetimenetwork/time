//! Recorded roots: a network without `distinct_names` registers accounts
//! exactly as it did before the rule for names that look alike existed.
//!
//! `golden.rs` holds roots recorded before the upgrade mechanism, but its
//! runs register no account, and `differential.rs` compares with the
//! protocol-4 engine on random names. This run registers accounts on
//! purpose: sponsored registrations and reveals, among them names that look
//! alike (`alice` and `al_ice`, `paypal` and `paypa1`, `barn` and `bam`,
//! `vvv` and `wv`, `google` and `g00gle`), which a network without the
//! setting accepts as it always did; a name of underscores only, accepted;
//! the same name twice, refused; and a reveal whose paid commitment has
//! expired, refused. The network id, the state root, the hash of the
//! metadata row and the number of actions a proposer kept were recorded
//! after every block with the engine as it was before the rule was built
//! (commit `913fbd1`), and the same run must give the same values now.
//!
//! Nothing here names the new setting, so that the file compiles and runs
//! unchanged on the engine before it. To record again (only ever on an
//! engine whose rules are known to be the recorded ones):
//! `V5_RECORD_NAMES_OFF=1 cargo test --test names_unchanged`.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, account_key, name_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const BLOCKS: i64 = 36;

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
    /// The registered names, by account id.
    names: Vec<String>,
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("names-off.json")
}

/// The networks the runs are made on: the protocol-4 settings, and every
/// optional setting that existed before the rule for names.
fn variants() -> Vec<(&'static str, Genesis)> {
    let plain = genesis_v5();
    let mut everything = genesis_v5();
    everything.validators = (0..7)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    everything.all_new_time_to_validators = true;
    everything.stake_handover = true;
    everything.fees_to_validators_ppm = 250_000;
    everything.fee_micros = 100;
    vec![("plain", plain), ("everything", everything)]
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
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network }
    }
    fn now(&self) -> u64 {
        self.engine.meta().unwrap().elapsed_micros().unwrap()
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    fn signed(&self, from: u64, nonce: u64, auth_epoch: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce,
                auth_epoch,
                public_key: pk(signer),
                payload,
                signature: vec![],
            },
            &key(signer),
        )
        .unwrap()
    }
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        self.signed(from, row.nonce + 1, row.auth_epoch, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    /// Genesis account `sponsor` (key seed `sponsor + 1`) pays for the
    /// registration of the identity `seed` under `name`. The commitment
    /// lasts `lifetime` seconds.
    fn sponsor(&self, sponsor: u64, seed: u8, name: &str, lifetime: u64) -> Vec<u8> {
        let salt = hex::encode([seed; 32]);
        let commitment = ledger::action_commitment(&self.network, &pk(seed), name, &salt).unwrap();
        let expiry = self.now() + lifetime * SECOND;
        let consent = registration::consent_bytes(
            pos::hex32(&self.network).unwrap(),
            sponsor,
            pos::hex32(&pk(seed)).unwrap(),
            pos::hex32(&commitment).unwrap(),
            expiry,
        );
        let payload: Value = json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())});
        let row = self.account(sponsor);
        timecurrency_v5::wire::sign(&self.network, sponsor, row.nonce + 1, row.auth_epoch, 44, &payload, &key(sponsor as u8 + 1)).unwrap()
    }
    /// The new identity takes its name: an action without an account.
    fn reveal(&self, seed: u8, name: &str) -> Vec<u8> {
        self.signed(u64::MAX, 0, 0, seed, ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: hex::encode([seed; 32]) }))
    }
    /// One block as a proposer builds it and a validator checks it. Returns
    /// what is recorded of it.
    fn block(&mut self, step: Step) -> Block {
        let meta = self.engine.meta().unwrap();
        let (height, time) = (meta.height + 1, meta.time_micros + step.delta as i64);
        let signers: Vec<String> = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        let hash = sha(height as u64);
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &step.txs, &signers, 1 << 20, hash).unwrap();
        let strict = self.engine.prepare(height, time, &kept, &signers, hash).unwrap();
        let reference = self.engine.prepare_reference(height, time, &kept, &signers, hash).unwrap();
        assert_eq!(strict.root, proposed.root, "validator and proposer disagree at {height}");
        assert_eq!(reference.root, proposed.root, "fast path and reference disagree at {height}");
        if kept.len() != step.txs.len() - step.refused {
            let reasons: Vec<String> = step
                .txs
                .iter()
                .map(|tx| match self.engine.prepare(height, time, &[tx], &signers, hash) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("network {} height {height}: a scripted action was left out or kept: {reasons:?}", self.network);
        }
        self.engine.commit(proposed, hash).unwrap();
        let version = self.engine.version().unwrap();
        Block {
            height: version.height().to_string(),
            kept: kept.len(),
            root: hex::encode(version.root()),
            meta_sha256: hex::encode(Sha256::digest(&version.head().metadata)),
        }
    }
}

struct Step {
    delta: u64,
    txs: Vec<Vec<u8>>,
    /// How many of `txs` the rules must refuse.
    refused: usize,
}
fn quiet(delta: u64) -> Step {
    Step { delta, txs: vec![], refused: 0 }
}
fn with(delta: u64, txs: Vec<Vec<u8>>) -> Step {
    Step { delta, txs, refused: 0 }
}

/// The names of the run, in the order of their identities' key seeds (201
/// and up). The fifth repeats the first.
const NAMES: [&str; 12] = [
    "alice", "al_ice", "paypal", "paypa1", "alice", "__", "barn", "bam", "vvv", "wv", "g00gle", "google",
];
/// The key seed of the identity that asks for `NAMES[index]`.
fn seed(index: usize) -> u8 {
    201 + index as u8
}

/// The block at `height`, from the state before it.
fn step(chain: &Chain, height: i64) -> Step {
    // Four genesis accounts, each the owner of a starting validator, sponsor
    // one registration each; the reveals follow in the next block.
    let sponsors = |from: usize, lifetimes: [u64; 4]| -> Vec<Vec<u8>> {
        (0..4).map(|i| chain.sponsor(i as u64, seed(from + i), NAMES[from + i], lifetimes[i])).collect()
    };
    let reveals = |from: usize| -> Vec<Vec<u8>> { (0..4).map(|i| chain.reveal(seed(from + i), NAMES[from + i])).collect() };
    match height {
        // The validators' owners earn.
        1..=20 => quiet(60 * SECOND),
        // alice, al_ice, paypal, paypa1: all four are registered.
        21 => with(SECOND, sponsors(0, [3600; 4])),
        22 => with(SECOND, reveals(0)),
        // alice again (its commitment lasts two minutes), then __, barn, bam.
        23 => with(SECOND, sponsors(4, [120, 3600, 3600, 3600])),
        // The second alice is refused: the name is taken.
        24 => Step { delta: SECOND, txs: reveals(4), refused: 1 },
        // vvv, wv, g00gle, google.
        25 => with(SECOND, sponsors(8, [3600; 4])),
        26 => with(SECOND, reveals(8)),
        // Two owners pay new accounts, and a new account pays another.
        27 => with(SECOND, vec![chain.transfer(0, 1, 12, 2 * SECOND), chain.transfer(1, 2, 13, SECOND)]),
        28 => with(SECOND, vec![chain.transfer(12, seed(0), 13, 500_000)]),
        // The commitment of the second alice runs out and is cleaned up.
        29..=31 => quiet(60 * SECOND),
        // Its reveal is refused again: there is no commitment any more.
        32 => Step { delta: SECOND, txs: vec![chain.reveal(seed(4), NAMES[4])], refused: 1 },
        _ => quiet(45 * SECOND),
    }
}

fn run(genesis: Genesis) -> Run {
    let mut chain = Chain::new(genesis);
    let mut blocks = Vec::new();
    for height in 1..=BLOCKS {
        let next = step(&chain, height);
        blocks.push(chain.block(next));
    }
    let audit = chain.engine.audit().unwrap();
    assert!(audit.history_archive_verified);
    // Twelve genesis accounts and eleven registered ones, in the order of
    // their reveals.
    let names: Vec<String> = (GENESIS_ACCOUNTS..audit.account_count).map(|id| chain.account(id).name).collect();
    for (offset, name) in names.iter().enumerate() {
        let id = GENESIS_ACCOUNTS + offset as u64;
        assert_eq!(chain.row(&name_key(name)), Some(serde_json::to_vec(&id.to_string()).unwrap()), "{name}");
    }
    Run {
        network_id: chain.network.clone(),
        blocks,
        audited_leaves: audit.authenticated_leaves.to_string(),
        audited_accounts: audit.account_count.to_string(),
        names,
    }
}

#[test]
fn a_network_without_the_setting_registers_names_as_before() {
    let record = std::env::var("V5_RECORD_NAMES_OFF").is_ok();
    let mut runs = BTreeMap::new();
    for (name, genesis) in variants() {
        let run = run(genesis);
        // Every name but the repeated one is registered, look-alikes included.
        let expected: Vec<&str> = NAMES.iter().enumerate().filter(|(index, _)| *index != 4).map(|(_, name)| *name).collect();
        assert_eq!(run.names, expected, "{name}");
        runs.insert(name.to_string(), run);
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
        assert_eq!(old.names, run.names, "{name}: registered names");
    }
    // The two networks differ: the settings are really in force.
    assert_ne!(runs["plain"].blocks.last().unwrap().root, runs["everything"].blocks.last().unwrap().root);
}
