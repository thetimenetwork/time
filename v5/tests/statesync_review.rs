//! Tests written by the independent review of state sync (`fast-join`), kept
//! as regression tests. The fixtures are those of `evidence_auto.rs`.
//!
//! One adaptation to a fix: the report of `--audit` on a restored node now
//! says `history_archive_verified: false` and names the part that was
//! recounted, so the helper `recount` no longer asserts `true` for every
//! node; the one test that calls it asserts the restored node's values.
//!
//! The network has seven starting validators (owners 0 to 6, consensus keys
//! of seeds 101 to 107), so that a jailed validator can leave the roster at
//! H+2 and the network goes on. Where an entry must change nothing, a twin
//! node runs the same blocks without it and the two roots must be equal.
// The fixtures were copied whole; not every one is used here.
#![allow(dead_code, unused_imports, unused_mut)]
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::{
    app::{self, App},
    engine::{self, Meta},
    genesis::{BootstrapValidator, Genesis},
    pos_adapter::{SUMMARY_KEY, candidate_key, misbehavior_key},
    store::Store,
    transport::BatchCheck,
};

const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const REJECT: i32 = response_process_proposal::ProposalStatus::Reject as i32;
const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;
const DUPLICATE_VOTE: i32 = MisbehaviorType::DuplicateVote as i32;
const LIGHT_CLIENT_ATTACK: i32 = MisbehaviorType::LightClientAttack as i32;
const VALIDATORS: u64 = 7;
/// The genesis time of the test fixture (`common::genesis_v5`).
const GENESIS_TIME: i64 = 1_800_000_000_000_000;
/// The starting validator that signs twice in most tests, and the one that
/// reports it with an evidence action.
const OFFENDER: u64 = 3;
const REPORTER: u64 = 1;

fn genesis_at(time_micros: i64) -> Genesis {
    let mut genesis = genesis_v5();
    assert_eq!(genesis.ledger.genesis_time_micros, GENESIS_TIME);
    genesis.ledger.genesis_time_micros = time_micros;
    genesis.validators = (0..VALIDATORS)
        .map(|owner| BootstrapValidator {
            owner,
            consensus_key: pk(owner as u8 + 101),
            commission_bps: 1000,
        })
        .collect();
    genesis
}
fn genesis() -> Genesis {
    genesis_at(GENESIS_TIME)
}
fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: micros / 1_000_000,
        nanos: ((micros % 1_000_000) * 1000) as i32,
    })
}
fn micros(time: &Option<Timestamp>) -> i64 {
    let time = time.as_ref().unwrap();
    time.seconds * 1_000_000 + i64::from(time.nanos / 1000)
}
fn init(genesis: &Genesis) -> RequestInitChain {
    RequestInitChain {
        chain_id: genesis.ledger.chain_id.clone(),
        time: timestamp(genesis.ledger.genesis_time_micros),
        app_state_bytes: serde_json::to_vec(genesis).unwrap().into(),
        validators: genesis
            .validators
            .iter()
            .map(|validator| ValidatorUpdate {
                pub_key: Some(tendermint_proto::crypto::PublicKey {
                    sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                        hex::decode(&validator.consensus_key).unwrap(),
                    )),
                }),
                power: genesis.profile.genesis_power() as i64,
            })
            .collect(),
        ..Default::default()
    }
}
/// The consensus address CometBFT gives a consensus key.
fn address(consensus_key: &str) -> Vec<u8> {
    Sha256::digest(hex::decode(consensus_key).unwrap())[..20].to_vec()
}
/// The consensus address of starting validator `owner`.
fn validator(owner: u64) -> Vec<u8> {
    address(&pk(owner as u8 + 101))
}
/// An entry of the misbehavior list CometBFT sends with a block.
fn entry(kind: i32, address: Vec<u8>, height: i64) -> Misbehavior {
    Misbehavior {
        r#type: kind,
        validator: Some(Validator {
            address: address.into(),
            power: 1,
        }),
        height,
        time: timestamp(GENESIS_TIME.saturating_add(height.saturating_mul(1_000_000)).max(0)),
        total_voting_power: VALIDATORS as i64,
    }
}
/// CometBFT's report that starting validator `owner` voted twice at `height`.
fn double_vote(owner: u64, height: i64) -> Misbehavior {
    entry(DUPLICATE_VOTE, validator(owner), height)
}
fn proposal(request: &RequestFinalizeBlock) -> RequestProcessProposal {
    RequestProcessProposal {
        txs: request.txs.clone(),
        proposed_last_commit: request.decided_last_commit.clone(),
        misbehavior: request.misbehavior.clone(),
        hash: request.hash.clone(),
        height: request.height,
        time: request.time,
        next_validators_hash: request.next_validators_hash.clone(),
        proposer_address: request.proposer_address.clone(),
    }
}
/// A precommit of starting validator `owner` at `height` for the block named
/// by `block_byte`, signed with its consensus key.
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
    vote.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes)
        .unwrap();
    vote.signature = Some(Signature::try_from(key(seed).sign(&bytes).to_bytes().to_vec()).unwrap());
    vote
}
fn offline(path: &Path) -> engine::Engine {
    engine::Engine::open_with_history(
        Store::open(path.with_extension("v5state")).unwrap(),
        path.with_extension("history"),
    )
    .unwrap()
}
/// `time-node-v5 --devnet --db PATH --audit`: the recount an operator runs.
fn recount(path: &Path) -> Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5"))
        .args(["--devnet", "--db"])
        .arg(path)
        .arg("--audit")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "PASS_OFFLINE_AUTHENTICATED_RECOUNT");
    report
}

struct Node {
    app: App,
    network: String,
    genesis_time: i64,
    height: i64,
    elapsed: u64,
    /// The finalize request and its answer for every committed block.
    log: Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>,
}
impl Node {
    /// A new chain of `genesis()`, on a node that judges no proposal by a clock.
    fn start(path: &Path) -> Self {
        Self::on(App::open(path).unwrap(), &genesis())
    }
    /// A new chain of `genesis` on `app`.
    fn on(app: App, genesis: &Genesis) -> Self {
        app.try_init(init(genesis)).unwrap();
        Self::resume(app, genesis, 0, 0)
    }
    /// A node whose chain of `genesis` is at `height`, `elapsed` after genesis.
    fn resume(app: App, genesis: &Genesis, height: i64, elapsed: u64) -> Self {
        Self {
            app,
            network: genesis.network_id().unwrap(),
            genesis_time: genesis.ledger.genesis_time_micros,
            height,
            elapsed,
            log: Vec::new(),
        }
    }
    fn time(&self, delta: u64) -> Option<Timestamp> {
        timestamp(self.genesis_time + (self.elapsed + delta) as i64)
    }
    /// The validators of the committed head, every one of which signed it.
    fn votes(&self) -> Vec<Validator> {
        self.summary()
            .active
            .iter()
            .map(|v| Validator {
                address: address(&v.consensus_key).into(),
                power: v.power as i64,
            })
            .collect()
    }
    /// The next block, `delta` after the last one.
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>, misbehavior: Vec<Misbehavior>) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: self.time(delta),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: (height > 1).then(|| CommitInfo {
                round: 0,
                votes: self
                    .votes()
                    .into_iter()
                    .map(|validator| VoteInfo {
                        validator: Some(validator),
                        block_id_flag: BlockIdFlag::Commit as i32,
                    })
                    .collect(),
            }),
            misbehavior,
            ..Default::default()
        }
    }
    /// What this node proposes for the next block from `txs`.
    fn prepare(&self, delta: u64, txs: &[Vec<u8>], misbehavior: Vec<Misbehavior>) -> Vec<Vec<u8>> {
        self.app
            .prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: 1 << 20,
                txs: txs.iter().cloned().map(Into::into).collect(),
                local_last_commit: Some(ExtendedCommitInfo {
                    round: 0,
                    votes: self
                        .votes()
                        .into_iter()
                        .map(|validator| ExtendedVoteInfo {
                            validator: Some(validator),
                            block_id_flag: BlockIdFlag::Commit as i32,
                            ..Default::default()
                        })
                        .collect(),
                }),
                misbehavior,
                height: self.height + 1,
                time: self.time(delta),
                ..Default::default()
            })
            .txs
            .iter()
            .map(|tx| tx.to_vec())
            .collect()
    }
    /// Commits a finalized block and records it.
    fn committed(&mut self, delta: u64, request: RequestFinalizeBlock, response: ResponseFinalizeBlock) -> ResponseFinalizeBlock {
        self.app.try_commit().unwrap();
        self.height += 1;
        self.elapsed += delta;
        self.log.push((request, response.clone()));
        response
    }
    /// Proposal, finalize and commit of one block, as on a validator.
    #[track_caller]
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>, misbehavior: Vec<Misbehavior>) -> ResponseFinalizeBlock {
        let request = self.request(delta, txs, misbehavior);
        assert_eq!(
            self.app.process_proposal(proposal(&request)).status,
            ACCEPT,
            "proposal rejected at height {}",
            request.height
        );
        let response = self.app.try_finalize(request.clone()).unwrap();
        self.committed(delta, request, response)
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        let response = self.app.query(RequestQuery {
            data: serde_json::to_vec(&vec![hex::encode(key)]).unwrap().into(),
            path: "/compact-proof".into(),
            height: 0,
            prove: false,
        });
        assert_eq!(response.code, 0, "{}", response.log);
        let view: Value = serde_json::from_slice(&response.value).unwrap();
        view["entries"][0]["value_b64"].as_str().map(|text| {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(text).unwrap()
        })
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&engine::account_key(id)).expect("account")).unwrap()
    }
    fn candidate(&self, owner: u64) -> pos::Candidate {
        serde_json::from_slice(&self.row(&candidate_key(owner)).expect("candidate")).unwrap()
    }
    fn summary(&self) -> pos::Summary {
        serde_json::from_slice(&self.row(SUMMARY_KEY).unwrap()).unwrap()
    }
    fn meta(&self) -> Meta {
        serde_json::from_slice(&self.row(b"meta").unwrap()).unwrap()
    }
    fn root(&self) -> [u8; 32] {
        self.app.head().unwrap().unwrap().1
    }
    /// An action of genesis account `from` (key seed `from + 1`), next nonce.
    fn legacy(&self, from: u64, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + 1,
                auth_epoch: row.auth_epoch,
                public_key: pk(from as u8 + 1),
                payload,
                signature: vec![],
            },
            &key(from as u8 + 1),
        )
        .unwrap()
    }
    fn transfer(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn extension(&self, from: u64, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + 1, row.auth_epoch, kind, &payload, &key(from as u8 + 1)).unwrap()
    }
    /// Account `from` registers as a candidate with consensus key seed
    /// `seed` and the minimum self bond.
    fn register(&self, from: u64, seed: u8) -> Vec<u8> {
        let proof = key(seed).sign(&pos::register_message(pos::hex32(&self.network).unwrap(), from, &pk(seed), 1000).unwrap());
        self.extension(from, 17, json!({"commission_bps": 1000, "consensus_key": pk(seed), "proof": hex::encode(proof.to_bytes())}))
    }
    /// Account `from` takes all of its self bond out.
    fn leave(&self, from: u64) -> Vec<u8> {
        let bond = self.candidate(from).self_bond.to_string();
        self.extension(from, 19, json!({"amount": bond, "min_amount": bond}))
    }
    /// Kind 20: `from` reports that starting validator `owner` signed two
    /// blocks at `height`.
    fn report(&self, from: u64, owner: u64, height: u64) -> Vec<u8> {
        let evidence = pos::DoubleSignEvidence { first: vote(owner, height, 1), second: vote(owner, height, 3) };
        self.extension(from, 20, serde_json::to_value(evidence).unwrap())
    }
    fn check(&self, tx: &[u8]) -> ResponseCheckTx {
        self.app.check_batch(vec![RequestCheckTx { tx: tx.to_vec().into(), r#type: 0 }]).pop().unwrap()
    }
    /// Writes a snapshot of the head, stops the node and recounts its state
    /// offline.
    fn stop_and_audit(self, path: &Path) {
        self.app.snapshot().unwrap();
        drop(self);
        let audit = offline(path).audit().unwrap();
        assert!(audit.history_archive_verified);
    }
}

/// The offender stakes in every way a penalty reaches: a self bond (below
/// the minimum, so the roster does not change), a delegation pool, and a
/// self exit and a delegated exit that are still waiting. Account 8 delegates.
fn staked_history(node: &mut Node) {
    for _ in 0..3 {
        node.block(60 * SECOND, vec![], vec![]);
    }
    let txs = vec![node.extension(OFFENDER, 18, json!({"amount": "500000"})), node.transfer(0, 8, 2 * SECOND)];
    node.block(SECOND, txs, vec![]);
    let txs = vec![node.legacy(8, ActionPayload::Delegate(ledger::Delegate { operator: OFFENDER, amount: SECOND, min_shares: 1 }))];
    node.block(SECOND, txs, vec![]);
    let txs = vec![
        node.extension(OFFENDER, 19, json!({"amount": "100000", "min_amount": "100000"})),
        node.legacy(8, ActionPayload::Undelegate(ledger::Undelegate { operator: OFFENDER, shares: 200_000, min_amount: 1 })),
    ];
    node.block(SECOND, txs, vec![]);
    node.block(SECOND, vec![], vec![]);
    node.block(SECOND, vec![], vec![]);
}

// ---------------------------------------------------------------------
// Review test (not part of the branch): a restored node against the node it
// restored from, through the kinds of block the branch's own comparison
// does not run: evidence about heights before the snapshot (reported by
// CometBFT and by an action), jailing and the roster change, exits, a
// delegation, the 14-day cleanup of block rows and the release of exits.
// ---------------------------------------------------------------------
#[test]
fn review_a_restored_node_agrees_through_evidence_exits_and_the_cleanup() {
    use timecurrency_v5::statesync::NodeOptions;
    let dir = tempfile::tempdir().unwrap();
    let options = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let source_path = dir.path().join("source.db");
    let mut source = Node::on(App::open_with_options(&source_path, options).unwrap(), &genesis());
    staked_history(&mut source);
    while source.height < 10 {
        source.block(SECOND, vec![], vec![]);
    }
    source.app.write_sync_snapshot().unwrap().expect("snapshot at height 10");
    let snapshot = source.app.list_snapshots().snapshots.into_iter().find(|s| s.height == 10).unwrap();
    let joined_path = dir.path().join("joined.db");
    let joiner = App::open_with_options(&joined_path, options).unwrap();
    let offer = joiner.offer_snapshot(RequestOfferSnapshot {
        snapshot: Some(snapshot.clone()),
        app_hash: source.log[9].1.app_hash.clone(),
    });
    assert_eq!(offer.result, response_offer_snapshot::Result::Accept as i32);
    for chunk in 0..snapshot.chunks {
        let bytes = source.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 10, format: snapshot.format, chunk }).chunk;
        let answer = joiner.apply_snapshot_chunk(RequestApplySnapshotChunk { index: chunk, chunk: bytes, sender: "peer".into() });
        assert_eq!(answer.result, response_apply_snapshot_chunk::Result::Accept as i32);
    }
    let mut joined = Node::resume(joiner, &genesis(), source.height, source.elapsed);
    assert_eq!(joined.root(), source.root());

    let mut step = |source: &mut Node, joined: &mut Node, delta: u64, txs: Vec<Vec<u8>>, misbehavior: Vec<Misbehavior>, what: &str| {
        let response = source.block(delta, txs.clone(), misbehavior.clone());
        let codes: Vec<u32> = response.tx_results.iter().map(|result| result.code).collect();
        let theirs = joined.block(delta, txs, misbehavior);
        eprintln!(
            "height {} ({what}): tx codes {codes:?}, {} validator update(s), same answer and root: {}",
            source.height,
            response.validator_updates.len(),
            theirs == response && joined.root() == source.root()
        );
        assert_eq!(theirs, response, "{what}");
        assert_eq!(joined.root(), source.root(), "{what}");
        source.app.write_sync_snapshot().unwrap();
        joined.app.write_sync_snapshot().unwrap();
        codes
    };
    // CometBFT reports a double vote at a height before the snapshot.
    step(&mut source, &mut joined, SECOND, vec![], vec![double_vote(OFFENDER, 5)], "misbehavior at height 5");
    for _ in 0..3 {
        step(&mut source, &mut joined, SECOND, vec![], vec![], "roster change");
    }
    // An evidence action about another validator, also before the snapshot.
    let report = source.report(REPORTER, 2, 7);
    assert_eq!(joined.report(REPORTER, 2, 7), report);
    let codes = step(&mut source, &mut joined, SECOND, vec![report], vec![], "evidence action at height 7");
    assert_eq!(codes, [0]);
    for _ in 0..3 {
        step(&mut source, &mut joined, SECOND, vec![], vec![], "roster change");
    }
    // A validator leaves; a delegation to another; a payment. Each is
    // offered to the mempool first; what it admits goes into the block.
    let candidates = vec![
        ("leave", source.leave(4)),
        ("delegate", source.legacy(8, ActionPayload::Delegate(ledger::Delegate { operator: 5, amount: 300_000, min_shares: 1 }))),
        ("pay", source.transfer(0, 9, SECOND)),
    ];
    let mut txs = Vec::new();
    for (name, tx) in candidates {
        let (ours, theirs) = (source.check(&tx), joined.check(&tx));
        eprintln!("mempool: {name}: code {} {:?}; restored node: code {}", ours.code, ours.log, theirs.code);
        assert_eq!(ours.code, theirs.code, "{name}");
        if ours.code == 0 {
            txs.push(tx);
        }
    }
    assert!(txs.len() >= 2, "too few of the actions were admitted");
    let codes = step(&mut source, &mut joined, SECOND, txs, vec![], "leave, delegate, pay");
    assert!(codes.iter().all(|code| *code == 0));
    let undelegate = source.legacy(8, ActionPayload::Undelegate(ledger::Undelegate { operator: OFFENDER, shares: 100_000, min_amount: 1 }));
    let (ours, theirs) = (source.check(&undelegate), joined.check(&undelegate));
    eprintln!("mempool: undelegate: code {} {:?}; restored node: code {}", ours.code, ours.log, theirs.code);
    assert_eq!(ours.code, theirs.code);
    let txs = if ours.code == 0 { vec![undelegate] } else { vec![] };
    step(&mut source, &mut joined, SECOND, txs, vec![], "undelegate");
    // A light client attack reported at a height after the snapshot.
    let attack = entry(LIGHT_CLIENT_ATTACK, validator(6), source.height - 1);
    step(&mut source, &mut joined, SECOND, vec![], vec![attack], "light client attack");
    // Fifteen days pass: the ledger drops the block rows of the heights
    // before and after the snapshot, exits are released.
    step(&mut source, &mut joined, 15 * 86400 * SECOND, vec![], vec![], "15 days later");
    for _ in 0..4 {
        let pay = source.transfer(0, 9, 1000);
        step(&mut source, &mut joined, SECOND, vec![pay], vec![], "after the cleanup");
    }
    let meta = source.meta();
    eprintln!("history_pruned_through {} at height {}", meta.history_pruned_through, meta.height);
    assert!(meta.history_pruned_through > 10, "the cleanup passed the restored height");
    assert_eq!(serde_json::to_string(&joined.meta()).unwrap(), serde_json::to_string(&meta).unwrap());
    // Both offer the same snapshot of height 20.
    let ours = source.app.list_snapshots().snapshots;
    assert_eq!(joined.app.list_snapshots().snapshots.last(), ours.last());
    assert_eq!(ours.last().unwrap().height, 20);
    // The offline recount of both.
    source.app.snapshot().unwrap();
    joined.app.snapshot().unwrap();
    drop(source);
    drop(joined);
    let full = offline(&source_path).audit().unwrap();
    let restored = offline(&joined_path).audit().unwrap();
    eprintln!("recount: full from {}, restored from {}", full.history_archive_from, restored.history_archive_from);
    assert_eq!(engine::Audit { history_archive_from: 1, ..restored }, full);
    let report = recount(&joined_path);
    eprintln!("--audit on the restored node: {}", serde_json::to_string(&report).unwrap());
    // Adapted: the recount passed, but not over the whole history, and the
    // report says so instead of `true`.
    assert_eq!(report["history_archive_verified"], false);
    assert_eq!(report["history_archive_from"], "11");
    assert_eq!(report["state_restored_at"], "10");
    let report = recount(&source_path);
    assert_eq!(report["history_archive_verified"], true);
    assert!(report.get("history_archive_from").is_none() && report.get("state_restored_at").is_none());
}

/// A node that executed every block, with one leaf of its history archive
/// damaged: the recount must fail whatever else lies in the directory.
#[test]
fn review_a_restore_record_must_not_let_a_damaged_archive_pass_the_recount() {
    use std::io::{Seek, SeekFrom, Write};
    use timecurrency_v5::statesync::NodeOptions;
    let dir = tempfile::tempdir().unwrap();
    let options = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let full_path = dir.path().join("full.db");
    let mut full = Node::on(App::open_with_options(&full_path, options).unwrap(), &genesis());
    for _ in 0..12 {
        full.block(SECOND, vec![], vec![]);
        full.app.write_sync_snapshot().unwrap();
    }
    // Another node restores height 10: its history directory holds the record.
    let snapshot = full.app.list_snapshots().snapshots.into_iter().find(|s| s.height == 10).unwrap();
    let restored_path = dir.path().join("restored.db");
    let joiner = App::open_with_options(&restored_path, options).unwrap();
    joiner.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot.clone()), app_hash: full.log[9].1.app_hash.clone() });
    for chunk in 0..snapshot.chunks {
        let bytes = full.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 10, format: 1, chunk }).chunk;
        joiner.apply_snapshot_chunk(RequestApplySnapshotChunk { index: chunk, chunk: bytes, sender: "peer".into() });
    }
    assert_eq!(joiner.head().unwrap().unwrap().0, 10);
    drop(joiner);
    full.app.snapshot().unwrap();
    drop(full);
    // The full node passes; with the leaf of height 3 overwritten it fails.
    assert!(offline(&full_path).audit().unwrap().history_archive_verified);
    let history = full_path.with_extension("history");
    let mut leaves = std::fs::OpenOptions::new().write(true).open(history.join("leaves.bin")).unwrap();
    leaves.seek(SeekFrom::Start(40 + 2 * 40)).unwrap();
    leaves.write_all(&[0u8; 40]).unwrap();
    drop(leaves);
    let damaged = offline(&full_path).audit().unwrap_err();
    eprintln!("damaged archive, no record: {damaged:#}");
    // A record in the directory (copied with a backup of another node's
    // history directory, or left by a restore that stopped before the rename).
    let record = "restored-00000000000000000010.json";
    std::fs::copy(restored_path.with_extension("history").join(record), history.join(record)).unwrap();
    let engine = offline(&full_path);
    let outcome = engine.audit();
    eprintln!(
        "damaged archive, with {record}: {:?}; the node now says it was restored at {:?}",
        outcome.as_ref().map(|audit| (audit.history_archive_verified, audit.history_archive_from)).map_err(|e| format!("{e:#}")),
        engine.history_base()
    );
    assert!(outcome.is_err(), "the recount passed over a damaged leaf");
}

/// Any peer may send chunk requests; CometBFT passes each to the
/// application (`statesync/reactor.go`, no limit).
#[test]
fn review_chunk_requests_of_peers_print_a_line_each() {
    let dir = tempfile::tempdir().unwrap();
    // A node with default settings: it offers nothing.
    let node = Node::start(&dir.path().join("plain.db"));
    for index in 0..1000u32 {
        let answer = node.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 7, format: 1, chunk: index });
        assert!(answer.chunk.is_empty());
    }
}
