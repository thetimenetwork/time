//! Recorded roots: byte compatibility of a network on which nobody signals.
//!
//! `differential.rs` compares this engine with the protocol-4 engine. These
//! runs cover what that engine cannot check: account security, both fee
//! settings, all new time to validators, the stake hand-over rule and
//! reported misbehavior. The state root, the hash of the metadata row and the
//! number of transactions a proposer kept were recorded after every block
//! with the engine as it was before the upgrade mechanism was built (crate
//! 0.6.0 with state sync merged, commit `4050976`), and the same runs must
//! give the same values now. The file also holds the leaves the audit
//! counted at the end of each run, and `golden/` holds a restart snapshot
//! that engine wrote in the middle of the first run: it must load and
//! continue to the recorded roots.
//!
//! Nothing here uses anything the upgrade mechanism added, so that the file
//! compiles and runs unchanged on the engine before it. To record again (only
//! ever on an engine whose rules are known to be the recorded ones):
//! `V5_RECORD_GOLDEN=1 cargo test --test golden`.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, Misbehavior, account_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::pos_adapter::DUPLICATE_VOTE;
use timecurrency_v5::security::{self, Role};
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const BLOCKS: i64 = 64;
/// The height at which the first run's restart snapshot was recorded.
const SNAPSHOT_AT: i64 = 30;
const SNAPSHOT_RUN: &str = "plain";

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

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
}

/// The networks the runs are made on.
fn variants() -> Vec<(&'static str, Genesis)> {
    let starting = |count: u64| -> Vec<BootstrapValidator> {
        (0..count)
            .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
            .collect()
    };
    let plain = genesis_v5();
    let mut fee_share = genesis_v5();
    fee_share.fees_to_validators_ppm = 400_000;
    let mut low_fee = genesis_v5();
    low_fee.fee_micros = 10;
    low_fee.fees_to_validators_ppm = 1_000_000;
    let mut all_new_time = genesis_v5();
    all_new_time.validators = starting(5);
    all_new_time.all_new_time_to_validators = true;
    let mut handover = genesis_v5();
    handover.stake_handover = true;
    let mut everything = genesis_v5();
    everything.validators = starting(7);
    everything.all_new_time_to_validators = true;
    everything.stake_handover = true;
    everything.fees_to_validators_ppm = 250_000;
    everything.fee_micros = 100;
    vec![
        ("plain", plain),
        ("fee_share", fee_share),
        ("low_fee", low_fee),
        ("all_new_time", all_new_time),
        ("handover", handover),
        ("everything", everything),
    ]
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    validators: u64,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let validators = genesis.validators.len() as u64;
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network, validators }
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
    fn legacy(&self, from: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + 1,
                auth_epoch: row.auth_epoch,
                public_key: pk(signer),
                payload,
                signature: vec![],
            },
            &key(signer),
        )
        .unwrap()
    }
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn extension(&self, from: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + 1, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
    }
    fn guard(&self, account: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        timecurrency_v5::wire::sign(&self.network, account, 0, 0, kind, &payload, &key(signer)).unwrap()
    }
    fn accepts(&self, seed: u8, account: u64, role: Role) -> Value {
        let name = match role {
            Role::Signin => "signin",
            Role::Spend => "spend",
            Role::Recover => "recover",
        };
        let proof = key(seed).sign(&security::key_message(&self.network, account, role, &pk(seed)).unwrap());
        json!({"public_key": pk(seed), "role": name, "proof": hex::encode(proof.to_bytes())})
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
        let (proposed, kept) = self
            .engine
            .prepare_filtered_with_misbehavior(height, time, &step.txs, &signers, 1 << 20, hash, &step.misbehavior)
            .unwrap();
        let strict = self
            .engine
            .prepare_with_misbehavior(height, time, &kept, &signers, hash, &step.misbehavior)
            .unwrap();
        let reference = self
            .engine
            .prepare_reference_with_misbehavior(height, time, &kept, &signers, hash, &step.misbehavior)
            .unwrap();
        assert_eq!(strict.root, proposed.root, "validator and proposer disagree at {height}");
        assert_eq!(reference.root, proposed.root, "fast path and reference disagree at {height}");
        if !step.either && kept.len() != step.txs.len() - step.refused {
            let reasons: Vec<String> = step
                .txs
                .iter()
                .map(|tx| match self.engine.prepare_with_misbehavior(height, time, &[tx], &signers, hash, &step.misbehavior) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("network {} height {height}: a scripted action was left out or kept: {reasons:?}", self.network);
        }
        self.engine.commit(proposed, hash).unwrap();
        self.recorded(kept.len())
    }
    fn recorded(&self, kept: usize) -> Block {
        let version = self.engine.version().unwrap();
        assert!(version.get(b"upgrade/state").is_none(), "an upgrade row on a network where nobody signals");
        Block {
            height: version.height().to_string(),
            kept,
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
    /// The rules of some of the networks refuse an action of this block and
    /// those of others keep it: whichever it is, the number is recorded.
    either: bool,
    misbehavior: Vec<Misbehavior>,
}
fn quiet(delta: u64) -> Step {
    Step { delta, txs: vec![], refused: 0, either: false, misbehavior: vec![] }
}
fn with(delta: u64, txs: Vec<Vec<u8>>) -> Step {
    Step { delta, txs, refused: 0, either: false, misbehavior: vec![] }
}

// Account 5 secures itself with these keys (its protocol-4 key is seed 6).
const ME: u64 = 5;
const OLD: u8 = 6;
const SIGNIN: u8 = 60;
const SPEND: u8 = 61;
const SHEET: u8 = 62;
const PHRASE: u8 = 63;
const LIMIT: u64 = 500_000;

fn vote(owner: u64, height: u64, block_byte: u8) -> tendermint::Vote {
    use tendermint::{Hash, Signature, Time, Vote, account, block};
    let seed = owner as u8 + 101;
    let public = tendermint::PublicKey::from_raw_ed25519(&hex::decode(pk(seed)).unwrap()).unwrap();
    let mut vote = Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: height.try_into().unwrap(),
        round: 0u32.try_into().unwrap(),
        block_id: Some(block::Id {
            hash: Hash::Sha256([block_byte; 32]),
            part_set_header: block::parts::Header::new(1, Hash::Sha256([block_byte + 1; 32])).unwrap(),
        }),
        timestamp: Some(Time::from_unix_timestamp(1_800_000_000, 0).unwrap()),
        validator_address: account::Id::from(public),
        validator_index: (owner as u32).try_into().unwrap(),
        signature: None,
        extension: vec![],
        extension_signature: None,
    };
    let mut bytes = Vec::new();
    vote.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes).unwrap();
    vote.signature = Some(Signature::try_from(key(seed).sign(&bytes).to_bytes().to_vec()).unwrap());
    vote
}

/// The block at `height`, from the state before it. A function of the height
/// and the state alone, so a run can be continued from a snapshot.
fn step(chain: &Chain, height: i64) -> Step {
    let last = chain.validators - 1;
    match height {
        // The validators' owners earn.
        1..=20 => quiet(60 * SECOND),
        // Four of them pay accounts 5 to 8.
        21 => with(
            SECOND,
            (0..4u64).map(|owner| chain.transfer(owner, owner as u8 + 1, ME + owner, 5 * SECOND)).collect(),
        ),
        // Account 5 adopts the security rules; account 6 pays a merchant.
        22 => {
            let mut keys = vec![
                chain.accepts(SIGNIN, ME, Role::Signin),
                chain.accepts(SPEND, ME, Role::Spend),
                chain.accepts(SHEET, ME, Role::Recover),
                chain.accepts(PHRASE, ME, Role::Recover),
            ];
            keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
            let policy = json!({"threshold": "2", "daily_limit_micros": LIMIT.to_string(), "delay_seconds": "60", "freeze_seconds": "120"});
            let row = chain.account(6);
            let mut reference = Vec::new();
            reference.extend((row.nonce + 1).to_be_bytes());
            reference.extend((chain.now() + 600 * SECOND).to_be_bytes());
            reference.extend([7u8; 16]);
            with(
                SECOND,
                vec![
                    chain.extension(ME, OLD, security::SECURE, json!({"keys": keys, "policy": policy})),
                    chain.legacy(6, 7, ActionPayload::MerchantPayment(ledger::MerchantPayment { to: 7, amount: 250_000, reference: hex::encode(reference) })),
                ],
            )
        }
        // The spend key pays within its limit and asks for a larger payment;
        // a merchant reference that has expired is refused.
        23 => {
            let row = chain.account(6);
            let mut reference = Vec::new();
            reference.extend((row.nonce + 1).to_be_bytes());
            reference.extend(1u64.to_be_bytes());
            reference.extend([8u8; 16]);
            Step {
                delta: SECOND,
                txs: vec![
                    chain.transfer(ME, SPEND, 6, 300_000),
                    chain.legacy(6, 7, ActionPayload::MerchantPayment(ledger::MerchantPayment { to: 7, amount: 1, reference: hex::encode(reference) })),
                ],
                refused: 1,
                either: false,
                misbehavior: vec![],
            }
        }
        24 => with(
            SECOND,
            vec![chain.extension(ME, SPEND, security::PAYMENT, json!({"type": "request", "to": "6", "amount": (2 * SECOND).to_string()}))],
        ),
        // Staking: a starting validator bonds, account 7 registers a validator.
        25 => {
            let proof = key(120).sign(&pos::register_message(pos::hex32(&chain.network).unwrap(), 7, &pk(120), 1000).unwrap());
            with(
                SECOND,
                vec![
                    chain.extension(2, 3, 18, json!({"amount": "30000"})),
                    chain.extension(7, 8, 17, json!({"commission_bps": 1000, "consensus_key": pk(120), "proof": hex::encode(proof.to_bytes())})),
                ],
            )
        }
        // Taking stake out waits for churn capacity on some of the networks.
        26 => Step {
            delta: SECOND,
            txs: vec![chain.extension(2, 3, 19, json!({"amount": "10000", "min_amount": "10000"}))],
            refused: 0,
            either: true,
            misbehavior: vec![],
        },
        27..=31 => quiet(2 * SECOND),
        // CometBFT reports that the last starting validator voted twice.
        32 => Step {
            delta: SECOND,
            txs: vec![],
            refused: 0,
            either: false,
            misbehavior: vec![Misbehavior {
                kind: DUPLICATE_VOTE,
                address: Sha256::digest(hex::decode(pk(last as u8 + 101)).unwrap())[..20].to_vec(),
                height: 29,
            }],
        },
        // During the validator safety hold a payment is refused and a freeze
        // by a recovery key is not.
        33 => {
            let mine: security::Security = serde_json::from_slice(&chain.row(&security::key(ME)).unwrap()).unwrap();
            let freeze = json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": (chain.now() + 600 * SECOND).to_string()});
            Step {
                delta: SECOND,
                txs: vec![chain.transfer(0, 1, 6, 1000), chain.guard(ME, SHEET, security::FREEZE, freeze)],
                refused: 1,
                either: false,
                misbehavior: vec![],
            }
        }
        34..=41 => quiet(2 * SECOND),
        42..=50 => quiet(30 * SECOND),
        // After the freeze has run out the spend key pays again.
        51 => with(240 * SECOND, vec![]),
        52 => with(SECOND, vec![chain.transfer(ME, SPEND, 8, 1000), chain.transfer(8, 9, 9, 2 * SECOND)]),
        // Evidence as an action, against the first starting validator.
        58 => {
            let evidence = pos::DoubleSignEvidence { first: vote(0, 55, 1), second: vote(0, 55, 3) };
            with(SECOND, vec![chain.extension(1, 2, 20, serde_json::to_value(evidence).unwrap())])
        }
        _ => quiet(45 * SECOND),
    }
}

fn run(genesis: Genesis, mut snapshot: impl FnMut(&Chain, i64)) -> Run {
    let mut chain = Chain::new(genesis);
    let mut blocks = Vec::new();
    for height in 1..=BLOCKS {
        let next = step(&chain, height);
        blocks.push(chain.block(next));
        snapshot(&chain, height);
    }
    let audit = chain.engine.audit().unwrap();
    assert!(audit.history_archive_verified);
    Run {
        network_id: chain.network.clone(),
        blocks,
        audited_leaves: audit.authenticated_leaves.to_string(),
        audited_accounts: audit.account_count.to_string(),
    }
}

fn recorded() -> BTreeMap<String, Run> {
    let path = directory().join("roots.json");
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap()
}

fn compare(name: &str, expected: &Run, actual: &Run) {
    assert_eq!(expected.network_id, actual.network_id, "{name}: network id");
    for (old, new) in expected.blocks.iter().zip(&actual.blocks) {
        assert_eq!(old, new, "{name}: first difference at height {}", old.height);
    }
    assert_eq!(expected.blocks.len(), actual.blocks.len(), "{name}: number of blocks");
    assert_eq!(expected.audited_leaves, actual.audited_leaves, "{name}: leaves the audit counts");
    assert_eq!(expected.audited_accounts, actual.audited_accounts, "{name}: accounts the audit counts");
}

#[test]
fn a_network_on_which_nobody_signals_has_the_recorded_roots() {
    let record = std::env::var("V5_RECORD_GOLDEN").is_ok();
    let mut runs = BTreeMap::new();
    for (name, genesis) in variants() {
        let run = run(genesis, |chain, height| {
            if record && name == SNAPSHOT_RUN && height == SNAPSHOT_AT {
                let info = chain.engine.store().write_snapshot(chain.engine.version().unwrap()).unwrap();
                let target = directory().join("snapshot");
                std::fs::create_dir_all(&target).unwrap();
                std::fs::copy(&info.path, target.join(info.path.file_name().unwrap())).unwrap();
            }
        });
        // The scripted actions did what the run is meant to cover.
        assert!(run.blocks.iter().map(|block| block.kept).sum::<usize>() >= 14, "{name}");
        runs.insert(name.to_string(), run);
    }
    if record {
        std::fs::create_dir_all(directory()).unwrap();
        std::fs::write(directory().join("roots.json"), serde_json::to_vec_pretty(&runs).unwrap()).unwrap();
        return;
    }
    let expected = recorded();
    assert_eq!(expected.keys().collect::<Vec<_>>(), runs.keys().collect::<Vec<_>>());
    for (name, run) in &runs {
        compare(name, &expected[name], run);
    }
    // The runs differ from each other: the settings are really in force.
    let finals: std::collections::BTreeSet<&String> = runs.values().map(|run| &run.blocks.last().unwrap().root).collect();
    assert_eq!(finals.len(), runs.len());
}

/// The restart snapshot the earlier engine wrote at `SNAPSHOT_AT` loads and
/// continues to the recorded roots.
#[test]
fn a_snapshot_written_before_the_upgrade_mechanism_continues_to_the_recorded_roots() {
    if std::env::var("V5_RECORD_GOLDEN").is_ok() {
        return;
    }
    let expected = &recorded()[SNAPSHOT_RUN];
    let (_, genesis) = variants().into_iter().find(|(name, _)| *name == SNAPSHOT_RUN).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.v5state");
    std::fs::create_dir_all(&state).unwrap();
    let mut copied = 0;
    for entry in std::fs::read_dir(directory().join("snapshot")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), state.join(entry.file_name())).unwrap();
        copied += 1;
    }
    assert_eq!(copied, 1, "one recorded snapshot");
    let engine = Engine::open(Store::open(&state).unwrap()).unwrap();
    assert_eq!(engine.meta().unwrap().height, SNAPSHOT_AT);
    let mut chain = Chain {
        _dir: dir,
        engine,
        network: genesis.network_id().unwrap(),
        validators: genesis.validators.len() as u64,
    };
    assert_eq!(chain.recorded(expected.blocks[SNAPSHOT_AT as usize - 1].kept), expected.blocks[SNAPSHOT_AT as usize - 1]);
    for height in SNAPSHOT_AT + 1..=BLOCKS {
        let next = step(&chain, height);
        assert_eq!(chain.block(next), expected.blocks[height as usize - 1], "height {height}");
    }
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.authenticated_leaves.to_string(), expected.audited_leaves);
}
