//! Two rules of version 5 at the ABCI boundary, driven as CometBFT drives
//! the node:
//!
//! - the misbehavior CometBFT reports with a block (duplicate votes and
//!   light client attacks it verified and committed as evidence) is punished
//!   as an evidence action (kind 20) would punish it, without anyone having
//!   to submit one (`pos_adapter::misbehavior`);
//! - a node rejects in `ProcessProposal` a proposal dated more than a
//!   tolerance ahead of its own clock, and never judges a decided block by it
//!   (`App::open_with_clock`).
//!
//! The network has seven starting validators (owners 0 to 6, consensus keys
//! of seeds 101 to 107), so that a jailed validator can leave the roster at
//! H+2 and the network goes on. Where an entry must change nothing, a twin
//! node runs the same blocks without it and the two roots must be equal.
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
    assert_eq!(report["history_archive_verified"], true);
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

/// Found by fuzzing on 22 November 2026 (`AUDIT-2026-11.md`, "Found by
/// fuzzing"). An evidence action is text from anyone, and the votes in it
/// are read by a library type whose readers panic on two kinds of text: a
/// signature whose `=` signs are not base64 padding, and a date that is in
/// the year 10000 once it is converted to UTC. A node's panic hook ends the
/// process, so one such transaction stopped every node it reached, and it
/// did so before the fee was taken: at the mempool, in a proposal, in a
/// block. The evidence type now refuses those texts (`pos::untrusted`).
///
/// Every door refuses such an action in the same way, and none of them
/// changes anything: not the state, not the sender's nonce or balance.
#[test]
fn evidence_with_a_text_no_reader_can_take_is_refused_at_every_door_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::start(&path);
    staked_history(&mut node);
    let offense = 7;
    let sound = serde_json::to_value(pos::DoubleSignEvidence { first: vote(OFFENDER, offense, 1), second: vote(OFFENDER, offense, 3) }).unwrap();
    let one_more = format!("{}=", sound["first"]["signature"].as_str().unwrap());
    let payment = node.transfer(0, 8, SECOND);
    let held = |node: &Node| (node.account(REPORTER).nonce, node.account(REPORTER).balance);
    let (root, reporter) = (node.root(), held(&node));
    for (field, text) in [("signature", "A========"), ("signature", "="), ("signature", one_more.as_str()), ("timestamp", "9999-12-31T23:59:59-00:01")] {
        for which in ["first", "second"] {
            let mut payload = sound.clone();
            payload[which][field] = json!(text);
            let action = node.extension(REPORTER, 20, payload);
            let told = format!("the {field} {text:?} in the {which} vote");
            // The mempool: refused, and told why.
            let checked = node.check(&action);
            assert_ne!(checked.code, 0, "{told}: the mempool takes it");
            assert!(checked.log.contains(if field == "signature" { pos::untrusted::BASE64 } else { pos::untrusted::DATE }), "{told}: {}", checked.log);
            // A proposer leaves it out and proposes what else it was given.
            assert_eq!(node.prepare(SECOND, &[action.clone(), payment.clone()], vec![]), vec![payment.clone()], "{told}");
            // A proposal that carries it is rejected, alone and beside a sound payment.
            for txs in [vec![action.clone()], vec![payment.clone(), action.clone()]] {
                assert_eq!(node.app.process_proposal(proposal(&node.request(SECOND, txs, vec![]))).status, REJECT, "{told}: a proposal with it is accepted");
            }
            // Nothing was written and nothing was charged.
            assert_eq!(node.root(), root, "{told}");
            assert_eq!(held(&node), reporter, "{told}");
        }
    }
    // The readers took an offset before UTC and base64 without its padding
    // before, and still do: such evidence proves the double signing. (The
    // text of a vote's time is not what was signed; its moment is.)
    let mut written_otherwise = sound.clone();
    for which in ["first", "second"] {
        let signature = written_otherwise[which]["signature"].as_str().unwrap().trim_end_matches('=').to_string();
        assert_eq!(written_otherwise[which]["timestamp"], json!("2027-01-15T08:00:00Z"));
        written_otherwise[which]["signature"] = json!(signature);
        written_otherwise[which]["timestamp"] = json!("2027-01-15T09:00:00+01:00");
    }
    let report = node.extension(REPORTER, 20, written_otherwise);
    assert_eq!(node.check(&report).code, 0);
    assert_eq!(node.prepare(SECOND, std::slice::from_ref(&report), vec![]), vec![report.clone()]);
    node.block(SECOND, vec![report], vec![]);
    assert!(node.candidate(OFFENDER).jailed);
    assert_eq!(node.account(REPORTER).nonce, reporter.0 + 1, "the one report that was taken");
    // The network goes on, and the recount of the state passes.
    node.block(SECOND, vec![], vec![]);
    node.stop_and_audit(&path);
}

#[test]
fn a_reported_double_vote_is_punished_exactly_as_an_evidence_action() {
    let dir = tempfile::tempdir().unwrap();
    // `reported` is told by CometBFT, `submitted` gets an evidence action
    // instead, `control` neither. The same history on all three.
    let reported_path = dir.path().join("reported.db");
    let mut reported = Node::start(&reported_path);
    let mut submitted = Node::start(&dir.path().join("submitted.db"));
    let mut control = Node::start(&dir.path().join("control.db"));
    for node in [&mut reported, &mut submitted, &mut control] {
        staked_history(node);
    }
    assert_eq!(reported.height, 8);
    let offense = 7;
    let report = double_vote(OFFENDER, offense);

    // A proposer applies the list before it selects transactions: the
    // penalty puts the network on hold, so an ordinary payment that fits
    // the block without the list does not fit it with the list.
    let payment = reported.transfer(2, 9, 1000);
    let offered = std::slice::from_ref(&payment);
    assert_eq!(reported.prepare(SECOND, offered, vec![]), vec![payment.clone()]);
    assert!(reported.prepare(SECOND, offered, vec![report.clone()]).is_empty());

    // Block 9: executed once, by ProcessProposal; FinalizeBlock reuses it.
    let before = reported.app.stats();
    let by_report = reported.block(SECOND, vec![], vec![report.clone()]);
    let after = reported.app.stats();
    assert_eq!(after.executed_blocks, before.executed_blocks + 1);
    assert_eq!(after.reused_executions, before.reused_executions + 1);
    let txs = vec![submitted.report(REPORTER, OFFENDER, offense as u64)];
    let by_action = submitted.block(SECOND, txs, vec![]);
    control.block(SECOND, vec![], vec![]);

    // The penalty is what `pos::slash` takes from the offender's row of this
    // block: all self collateral, a twentieth of the pool and of the
    // delegated exits, and the offender is jailed.
    let mut expected = control.candidate(OFFENDER);
    assert!(
        expected.self_bond > 0 && expected.self_exits.assets > 0 && expected.pool_assets >= 20 && expected.delegated_exits.assets >= 20,
        "{expected:?}"
    );
    let penalty = pos::slash(&mut expected).unwrap().bank_credit;
    assert!(expected.jailed && penalty > 0);
    assert_eq!(reported.candidate(OFFENDER), expected);
    assert_eq!(submitted.candidate(OFFENDER), expected);
    let (by_cometbft, by_kind_20, neither) = (reported.meta(), submitted.meta(), control.meta());
    assert_eq!(by_cometbft.bank, neither.bank + penalty, "the penalty goes to the bank");
    assert_eq!(by_cometbft.pos_assets_total, neither.pos_assets_total - penalty);
    assert_eq!(by_cometbft.liquid_total, neither.liquid_total);
    assert_eq!(by_kind_20.pos_assets_total, by_cometbft.pos_assets_total);
    // The evidence action differs only by its fee, paid by the reporter.
    assert_eq!(by_kind_20.bank, by_cometbft.bank + FEE);
    assert_eq!(by_kind_20.liquid_total + FEE, by_cometbft.liquid_total);
    for id in 0..GENESIS_ACCOUNTS {
        let fee = if id == REPORTER { FEE } else { 0 };
        assert_eq!(submitted.account(id).balance + fee, reported.account(id).balance, "account {id}");
    }
    // Escrow, roster schedule and safety hold: the same summary.
    assert_eq!(reported.summary(), submitted.summary());
    let summary = reported.summary();
    assert!(summary.safety_hold);
    assert_eq!(summary.scheduled.last().unwrap().effective_height, 11);
    // CometBFT is told the same: the offender leaves the validator set.
    assert_eq!(by_report.validator_updates, by_action.validator_updates);
    assert_eq!(by_report.validator_updates.len(), 1);
    let removal = &by_report.validator_updates[0];
    assert_eq!(removal.power, 0);
    assert_eq!(
        removal.pub_key,
        Some(tendermint_proto::crypto::PublicKey {
            sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(hex::decode(pk(OFFENDER as u8 + 101)).unwrap())),
        })
    );
    // The replay row of the report, written by the block that punished it.
    let offender: [u8; 20] = validator(OFFENDER).try_into().unwrap();
    assert_eq!(reported.row(&misbehavior_key(1, &offender, offense as u64)), Some(b"\"9\"".to_vec()));
    assert_eq!(submitted.row(&misbehavior_key(1, &offender, offense as u64)), None);

    // Block 10: the hold refuses ordinary payments, on both.
    for node in [&mut reported, &mut submitted, &mut control] {
        node.block(SECOND, vec![], vec![]);
    }
    for node in [&reported, &submitted] {
        let answer = node.check(&node.transfer(2, 9, 1000));
        assert!(answer.code != 0 && answer.log.contains("critical validator hold"), "{}", answer.log);
    }
    // Block 11 (H+2): the offender has left the roster on both, and the hold is over.
    for node in [&mut reported, &mut submitted, &mut control] {
        node.block(SECOND, vec![], vec![]);
    }
    assert_eq!(reported.summary(), submitted.summary());
    let roster = reported.summary().active;
    assert_eq!(roster.len(), 6);
    assert!(!roster.iter().any(|v| v.owner == OFFENDER));
    assert!(!reported.summary().safety_hold);
    assert_eq!(reported.check(&reported.transfer(2, 9, 1000)).code, 0);
    assert_eq!(control.summary().active.len(), 7);

    // A node that never saw a proposal reaches the same state from
    // FinalizeBlock alone, block by block.
    let follower = App::open(dir.path().join("follower.db")).unwrap();
    follower.try_init(init(&genesis())).unwrap();
    for (request, response) in &reported.log {
        assert_eq!(follower.try_finalize(request.clone()).unwrap(), *response, "height {}", request.height);
        follower.try_commit().unwrap();
    }
    assert_eq!(follower.head().unwrap().unwrap(), reported.app.head().unwrap().unwrap());

    reported.app.snapshot().unwrap();
    drop(reported);
    recount(&reported_path);
    submitted.stop_and_audit(&dir.path().join("submitted.db"));
}

#[test]
fn the_same_misbehavior_is_punished_once_and_an_evidence_action_after_it_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // `twice` is told more than `once`; their roots must stay equal.
    let mut twice = Node::start(&dir.path().join("twice.db"));
    let mut once = Node::start(&dir.path().join("once.db"));
    for node in [&mut twice, &mut once] {
        for _ in 0..3 {
            node.block(60 * SECOND, vec![], vec![]);
        }
        let txs = vec![node.extension(OFFENDER, 18, json!({"amount": "500000"}))];
        node.block(SECOND, txs, vec![]);
        node.block(SECOND, vec![], vec![]);
    }
    // Block 6: the same entry twice in one list.
    let offense = double_vote(OFFENDER, 4);
    let bank = once.meta().bank;
    twice.block(SECOND, vec![], vec![offense.clone(), offense.clone()]);
    once.block(SECOND, vec![], vec![offense.clone()]);
    let punished = once.candidate(OFFENDER);
    assert!(punished.jailed && punished.self_bond == 0);
    assert!(once.meta().bank >= bank + 500_000);
    assert_eq!(twice.root(), once.root(), "the second copy changed the state");
    // Block 7: the same entry in a later block.
    twice.block(SECOND, vec![], vec![offense.clone()]);
    once.block(SECOND, vec![], vec![]);
    assert_eq!(twice.root(), once.root());
    // Block 8: the same offender as a light client attack, and at other
    // heights. It is jailed: nothing more.
    twice.block(
        SECOND,
        vec![],
        vec![entry(LIGHT_CLIENT_ATTACK, validator(OFFENDER), 4), double_vote(OFFENDER, 5), double_vote(OFFENDER, 3)],
    );
    once.block(SECOND, vec![], vec![]);
    assert_eq!(twice.root(), once.root());
    // Punished once: the row is the one of block 6, except that it has left
    // the roster at block 8.
    let left = twice.candidate(OFFENDER);
    assert!(left.last_active_end > 0);
    assert_eq!(pos::Candidate { last_active_end: 0, ..left }, punished);
    assert!(!twice.summary().safety_hold, "the offender has left the roster");

    // An evidence action for the offence that was already punished is
    // refused, by the mempool, by validators and by the proposer.
    for node in [&twice, &once] {
        let late = node.report(REPORTER, OFFENDER, 4);
        let answer = node.check(&late);
        assert!(answer.code != 0 && answer.log.contains("already jailed"), "{}", answer.log);
        let request = node.request(SECOND, vec![late.clone()], vec![]);
        assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
        assert!(node.prepare(SECOND, &[late], vec![]).is_empty());
    }

    // The other way round: an evidence action first (block 9), then
    // CometBFT's report of the same offence (block 10): nothing more.
    let second = 5;
    for node in [&mut twice, &mut once] {
        let txs = vec![node.report(REPORTER, second, 7)];
        node.block(SECOND, txs, vec![]);
        assert!(node.candidate(second).jailed);
    }
    twice.block(SECOND, vec![], vec![double_vote(second, 7), entry(LIGHT_CLIENT_ATTACK, validator(second), 6)]);
    once.block(SECOND, vec![], vec![]);
    assert_eq!(twice.root(), once.root());
    twice.stop_and_audit(&dir.path().join("twice.db"));
}

#[test]
fn misbehavior_that_cannot_be_used_changes_nothing_and_a_light_client_attack_is_punished() {
    let dir = tempfile::tempdir().unwrap();
    // `noisy` is told what must be skipped, `plain` is not.
    let mut noisy = Node::start(&dir.path().join("noisy.db"));
    let mut plain = Node::start(&dir.path().join("plain.db"));
    let (newcomer, seed) = (8u64, 120u8);
    for node in [&mut noisy, &mut plain] {
        for _ in 0..3 {
            node.block(60 * SECOND, vec![], vec![]);
        }
        let txs = vec![node.transfer(0, newcomer, 2 * SECOND)];
        node.block(SECOND, txs, vec![]);
        // Block 5: a new candidate; it joins the roster at block 7.
        let txs = vec![node.register(newcomer, seed)];
        node.block(SECOND, txs, vec![]);
    }
    let height = noisy.height + 1;
    let offender = validator(OFFENDER);
    let junk = vec![
        // Nobody's address.
        entry(DUPLICATE_VOTE, vec![9; 20], 4),
        entry(LIGHT_CLIENT_ATTACK, vec![9; 20], 4),
        // A candidate, but not in the roster at that height.
        entry(DUPLICATE_VOTE, address(&pk(seed)), 5),
        entry(LIGHT_CLIENT_ATTACK, address(&pk(seed)), 4),
        // Addresses of the wrong length, or none at all.
        entry(DUPLICATE_VOTE, offender[..19].to_vec(), 4),
        entry(DUPLICATE_VOTE, [offender.clone(), vec![0]].concat(), 4),
        entry(DUPLICATE_VOTE, vec![], 4),
        Misbehavior { validator: None, ..double_vote(OFFENDER, 4) },
        // Types the rule does not act on.
        entry(MisbehaviorType::Unknown as i32, offender.clone(), 4),
        entry(3, offender.clone(), 4),
        entry(-1, offender.clone(), 4),
        entry(i32::MAX, offender.clone(), 4),
        // Heights that are not committed heights before this block.
        double_vote(OFFENDER, 0),
        double_vote(OFFENDER, -1),
        double_vote(OFFENDER, i64::MIN),
        double_vote(OFFENDER, height),
        double_vote(OFFENDER, height + 1),
        double_vote(OFFENDER, i64::MAX),
    ];
    // The proposer is not disturbed either.
    let payment = noisy.transfer(2, 9, 1000);
    assert_eq!(noisy.prepare(SECOND, std::slice::from_ref(&payment), junk.clone()), vec![payment]);
    noisy.block(SECOND, vec![], junk);
    plain.block(SECOND, vec![], vec![]);
    assert_eq!(noisy.root(), plain.root());
    // More entries than CometBFT's evidence limit allows in one block.
    let many: Vec<Misbehavior> = (0..600u64)
        .map(|i| entry(if i % 2 == 0 { DUPLICATE_VOTE } else { LIGHT_CLIENT_ATTACK }, sha(i)[..20].to_vec(), 1 + (i % 6) as i64))
        .collect();
    noisy.block(SECOND, vec![], many);
    plain.block(SECOND, vec![], vec![]);
    assert_eq!(noisy.root(), plain.root());
    assert!(noisy.summary().active.iter().any(|v| v.owner == newcomer));
    assert!(!noisy.candidate(OFFENDER).jailed);

    // Block 8: a light client attack is punished as a duplicate vote is.
    // The newcomer was in the roster at block 7.
    let attacker = address(&pk(seed));
    noisy.block(SECOND, vec![], vec![entry(LIGHT_CLIENT_ATTACK, attacker.clone(), 7)]);
    plain.block(SECOND, vec![], vec![entry(DUPLICATE_VOTE, attacker.clone(), 7)]);
    let punished = noisy.candidate(newcomer);
    assert!(punished.jailed && punished.self_bond == 0, "{punished:?}");
    assert_eq!(punished, plain.candidate(newcomer));
    assert_eq!(noisy.summary(), plain.summary());
    assert!(noisy.summary().safety_hold);
    assert_eq!(serde_json::to_vec(&noisy.meta()).unwrap(), serde_json::to_vec(&plain.meta()).unwrap());
    // Each is recorded under its own type.
    let attacker: [u8; 20] = attacker.try_into().unwrap();
    assert!(noisy.row(&misbehavior_key(2, &attacker, 7)).is_some() && noisy.row(&misbehavior_key(1, &attacker, 7)).is_none());
    assert!(plain.row(&misbehavior_key(1, &attacker, 7)).is_some() && plain.row(&misbehavior_key(2, &attacker, 7)).is_none());
    noisy.stop_and_audit(&dir.path().join("noisy.db"));
    plain.stop_and_audit(&dir.path().join("plain.db"));
}

#[test]
fn a_validator_that_left_is_punished_while_its_stake_is_exposed_and_never_after() {
    let dir = tempfile::tempdir().unwrap();
    let mut noisy = Node::start(&dir.path().join("noisy.db"));
    let mut plain = Node::start(&dir.path().join("plain.db"));
    // Two candidates join and leave again; their stake stays exposed for
    // 14 days after they left.
    let (first, second) = ((8u64, 120u8), (9u64, 121u8));
    for node in [&mut noisy, &mut plain] {
        for _ in 0..3 {
            node.block(60 * SECOND, vec![], vec![]);
        }
        let txs = vec![node.transfer(0, first.0, 2 * SECOND), node.transfer(1, second.0, 2 * SECOND)];
        node.block(SECOND, txs, vec![]);
        // More than one cleanup batch (64 heights) of history first.
        while node.height < 70 {
            node.block(SECOND, vec![], vec![]);
        }
        // Block 71: both register; they are in the roster from block 73.
        let txs = vec![node.register(first.0, first.1), node.register(second.0, second.1)];
        node.block(SECOND, txs, vec![]);
        // After the churn window (20 s on a laboratory network), block 101:
        // both take their bond out, and leave the roster at block 103.
        while node.height < 100 {
            node.block(SECOND, vec![], vec![]);
        }
        let txs = vec![node.leave(first.0), node.leave(second.0)];
        node.block(SECOND, txs, vec![]);
        while node.height < 104 {
            node.block(SECOND, vec![], vec![]);
        }
    }
    let exposed = noisy.candidate(first.0);
    assert!(!exposed.jailed && !exposed.archived && exposed.self_bond == 0 && exposed.self_exits.assets == SECOND, "{exposed:?}");
    assert!(!noisy.summary().active.iter().any(|v| v.owner == first.0 || v.owner == second.0));

    // Block 105: a double vote the first one cast at block 80 is punished:
    // it has left the roster, but it is still a candidate whose stake is
    // exposed. A report naming the second one at block 70, before it
    // joined, is not.
    let punished = entry(DUPLICATE_VOTE, address(&pk(first.1)), 80);
    noisy.block(SECOND, vec![], vec![punished.clone(), entry(DUPLICATE_VOTE, address(&pk(second.1)), 70)]);
    plain.block(SECOND, vec![], vec![punished]);
    assert_eq!(noisy.root(), plain.root());
    let slashed = noisy.candidate(first.0);
    assert!(slashed.jailed && slashed.self_exits.assets == 0, "{slashed:?}");
    assert!(!noisy.candidate(second.0).jailed);

    // Block 106, fifteen days later: both have been archived (their window
    // has closed), and this block cleans up the history up to block 64.
    let jump = 15 * 86_400 * SECOND;
    noisy.block(
        jump,
        vec![],
        vec![
            // Archived: no longer a candidate.
            entry(DUPLICATE_VOTE, address(&pk(second.1)), 80),
            entry(LIGHT_CLIENT_ATTACK, address(&pk(second.1)), 90),
            // Still a validator, but the offence is older than the window.
            double_vote(OFFENDER, 80),
            // History this block removes.
            double_vote(OFFENDER, 10),
            double_vote(OFFENDER, 64),
        ],
    );
    plain.block(jump, vec![], vec![]);
    assert_eq!(noisy.root(), plain.root());
    let archived = noisy.candidate(second.0);
    assert!(archived.archived && !archived.jailed, "{archived:?}");
    assert!(noisy.candidate(first.0).archived);
    assert_eq!(noisy.meta().history_pruned_through, 64);
    assert!(!noisy.candidate(OFFENDER).jailed);
    // Block 107 removes the rest of that history.
    noisy.block(SECOND, vec![], vec![double_vote(OFFENDER, 80)]);
    plain.block(SECOND, vec![], vec![]);
    assert_eq!(noisy.root(), plain.root());
    assert!(noisy.meta().history_pruned_through >= 80);
    let noisy_path = dir.path().join("noisy.db");
    noisy.app.snapshot().unwrap();
    drop(noisy);
    recount(&noisy_path);
    plain.stop_and_audit(&dir.path().join("plain.db"));
}

#[test]
fn a_node_stopped_after_a_block_with_misbehavior_replays_it_to_the_same_state_and_the_recount_passes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::start(&path);
    for _ in 0..3 {
        node.block(60 * SECOND, vec![], vec![]);
    }
    let txs = vec![node.extension(OFFENDER, 18, json!({"amount": "500000"}))];
    node.block(SECOND, txs, vec![]);
    node.block(SECOND, vec![], vec![]);
    let snapshot = node.app.snapshot().unwrap().expect("a snapshot").height;
    assert_eq!(snapshot, 5);
    // Block 6 punishes two validators, block 7 repeats one report, block 8
    // removes both from the roster.
    node.block(SECOND, vec![], vec![double_vote(OFFENDER, 4), double_vote(5, 3)]);
    node.block(SECOND, vec![], vec![double_vote(OFFENDER, 4)]);
    node.block(SECOND, vec![], vec![]);
    assert_eq!(node.summary().active.len(), 5);
    let (height, root) = node.app.head().unwrap().unwrap();
    let (log, elapsed) = (node.log.clone(), node.elapsed);
    // The process dies here: nothing after the snapshot reached the disk.
    drop(node);

    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap().0, snapshot);
    for (request, response) in &log[snapshot as usize..] {
        assert_eq!(app.try_finalize(request.clone()).unwrap(), *response, "height {}", request.height);
        app.try_commit().unwrap();
    }
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    let mut node = Node::resume(app, &genesis(), height as i64, elapsed);
    assert!(node.candidate(OFFENDER).jailed && node.candidate(5).jailed);
    // The chain goes on, with ordinary payments again.
    let txs = vec![node.transfer(2, 9, 1000)];
    node.block(SECOND, txs, vec![]);
    assert_eq!(node.account(9).balance, 1000);
    node.app.snapshot().unwrap();
    drop(node);
    let report = recount(&path);
    assert_eq!(report["height"], "9");
}

#[test]
fn a_block_executed_with_one_misbehavior_list_is_never_reused_for_another() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(&dir.path().join("node.db"));
    for _ in 0..4 {
        node.block(10 * SECOND, vec![], vec![]);
    }
    // Validated with a report; decided without one. CometBFT's block hash
    // covers the evidence, but the key does not rely on it.
    let with = node.request(SECOND, vec![], vec![double_vote(OFFENDER, 3)]);
    let mut without = with.clone();
    without.misbehavior.clear();
    let before = node.app.stats();
    assert_eq!(node.app.process_proposal(proposal(&with)).status, ACCEPT);
    let response = node.app.try_finalize(without.clone()).unwrap();
    let after = node.app.stats();
    assert_eq!(after.executed_blocks, before.executed_blocks + 2);
    assert_eq!(after.reused_executions, before.reused_executions);
    node.committed(SECOND, without, response);
    assert!(!node.candidate(OFFENDER).jailed, "the execution with the report was reused");
    // A list that differs only where the rule does not read is still
    // another list.
    let first = node.request(SECOND, vec![], vec![double_vote(OFFENDER, 3)]);
    let mut other = first.clone();
    other.misbehavior[0].total_voting_power += 1;
    assert_eq!(node.app.process_proposal(proposal(&first)).status, ACCEPT);
    let before = node.app.stats();
    let response = node.app.try_finalize(other.clone()).unwrap();
    assert_eq!(node.app.stats().executed_blocks, before.executed_blocks + 1);
    assert_eq!(node.app.stats().reused_executions, before.reused_executions);
    node.committed(SECOND, other, response);
    assert!(node.candidate(OFFENDER).jailed);
    // The same list: reused.
    let next = node.request(SECOND, vec![], vec![double_vote(OFFENDER, 3)]);
    assert_eq!(node.app.process_proposal(proposal(&next)).status, ACCEPT);
    let before = node.app.stats();
    let response = node.app.try_finalize(next.clone()).unwrap();
    assert_eq!(node.app.stats().reused_executions, before.reused_executions + 1);
    node.committed(SECOND, next, response);
}

#[test]
fn proposer_validator_and_reference_paths_apply_the_same_misbehavior() {
    // On the engine itself, as the differential tests drive it.
    let dir = tempfile::tempdir().unwrap();
    let mut engine = engine::Engine::open_with_history(
        Store::open(dir.path().join("state.v5state")).unwrap(),
        dir.path().join("history"),
    )
    .unwrap();
    let network = genesis().network_id().unwrap();
    engine.initialize(genesis()).unwrap();
    let next = |engine: &engine::Engine, delta: u64| {
        let meta = engine.meta().unwrap();
        let eligible: Vec<String> = engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|v| v.consensus_key)
            .collect();
        (meta.height + 1, meta.time_micros + delta as i64, eligible, sha(meta.height as u64 + 1))
    };
    let row = |engine: &engine::Engine, key: &[u8]| engine.version().unwrap().get(key).map(|row| row.to_vec());
    let payment = |engine: &engine::Engine, from: u64| {
        let account: Account = serde_json::from_slice(&row(engine, &engine::account_key(from)).unwrap()).unwrap();
        ledger::sign_action(
            &Action {
                network_id: network.clone(),
                from,
                nonce: account.nonce + 1,
                auth_epoch: account.auth_epoch,
                public_key: pk(from as u8 + 1),
                payload: ActionPayload::Transfer(ledger::Transfer { to: 9, amount: 1000 }),
                signature: vec![],
            },
            &key(from as u8 + 1),
        )
        .unwrap()
    };
    let reported = |kind: i32, address: Vec<u8>, height: i64| engine::Misbehavior { kind, address, height };
    // Every path, the same root; the proposer keeps what the validator accepts.
    let step = |engine: &mut engine::Engine, txs: Vec<Vec<u8>>, misbehavior: Vec<engine::Misbehavior>| {
        let (height, time, eligible, hash) = next(engine, SECOND);
        let strict = engine.prepare_with_misbehavior(height, time, &txs, &eligible, hash, &misbehavior).unwrap();
        let reference = engine.prepare_reference_with_misbehavior(height, time, &txs, &eligible, hash, &misbehavior).unwrap();
        let (proposed, kept) = engine
            .prepare_filtered_with_misbehavior(height, time, &txs, &eligible, 1 << 20, hash, &misbehavior)
            .unwrap();
        assert_eq!(kept, txs, "the proposer dropped a transaction");
        assert_eq!(strict.root, reference.root, "fast path and reference disagree");
        assert_eq!(strict.root, proposed.root, "proposer and validator disagree");
        engine.commit(strict, hash).unwrap();
    };
    for _ in 0..4 {
        step(&mut engine, vec![], vec![]);
    }
    let (height, time, eligible, hash) = next(&engine, SECOND);
    let without = engine.prepare(height, time, &[payment(&engine, 2)], &eligible, hash).unwrap();
    // Entries that are all skipped: the root of a block without a list.
    let skipped = vec![reported(DUPLICATE_VOTE, vec![9; 20], 3), reported(0, validator(OFFENDER), 3), reported(DUPLICATE_VOTE, validator(OFFENDER), height)];
    let same = engine
        .prepare_with_misbehavior(height, time, &[payment(&engine, 2)], &eligible, hash, &skipped)
        .unwrap();
    assert_eq!(same.root, without.root);
    // A punishable entry: the payment no longer fits the block (the
    // validator safety hold starts with the penalty), on every path.
    let report = vec![reported(LIGHT_CLIENT_ATTACK, validator(OFFENDER), 3)];
    let error = engine
        .prepare_with_misbehavior(height, time, &[payment(&engine, 2)], &eligible, hash, &report)
        .err()
        .expect("accepted");
    assert!(format!("{error:#}").contains("critical validator hold"), "{error:#}");
    assert!(engine
        .prepare_reference_with_misbehavior(height, time, &[payment(&engine, 2)], &eligible, hash, &report)
        .is_err());
    let (_, kept) = engine
        .prepare_filtered_with_misbehavior(height, time, &[payment(&engine, 2)], &eligible, 1 << 20, hash, &report)
        .unwrap();
    assert!(kept.is_empty());
    step(&mut engine, vec![], report);
    let punished: pos::Candidate = serde_json::from_slice(&row(&engine, &candidate_key(OFFENDER)).unwrap()).unwrap();
    assert!(punished.jailed);
    // At H+2 the offender has left the roster and payments fit again.
    step(&mut engine, vec![], vec![]);
    let txs = vec![payment(&engine, 2)];
    step(&mut engine, txs, vec![]);
    engine.audit().unwrap();
}

/// A clock the test sets, in microseconds since the Unix epoch.
struct TestClock(Arc<AtomicI64>);
impl TestClock {
    fn at(micros: i64) -> Self {
        Self(Arc::new(AtomicI64::new(micros)))
    }
    fn set(&self, micros: i64) {
        self.0.store(micros, Ordering::SeqCst);
    }
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    fn clock(&self) -> app::Clock {
        let now = self.0.clone();
        Arc::new(move || UNIX_EPOCH + Duration::from_micros(now.load(Ordering::SeqCst) as u64))
    }
}

#[test]
fn a_proposal_dated_beyond_the_tolerance_is_rejected_and_a_decided_one_is_still_applied() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let tolerance = app::DEFAULT_CLOCK_TOLERANCE.as_micros() as i64;
    assert_eq!(tolerance, 30 * SECOND as i64);
    let clock = TestClock::at(GENESIS_TIME);
    let open = || App::open_with_clock(&path, app::DEFAULT_CLOCK_TOLERANCE, clock.clock()).unwrap();
    let mut node = Node::on(open(), &genesis());
    // Honest blocks are dated in the past of the clocks that judge them.
    clock.set(GENESIS_TIME + 5 * SECOND as i64);
    node.block(SECOND, vec![], vec![]);
    node.block(SECOND, vec![], vec![]);

    // Exactly the tolerance ahead of this node's clock: accepted.
    let request = node.request(SECOND, vec![], vec![]);
    clock.set(micros(&request.time) - tolerance);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, ACCEPT);
    let response = node.app.try_finalize(request.clone()).unwrap();
    node.committed(SECOND, request, response);

    // A microsecond more: rejected before anything of it is executed or
    // remembered. The same proposal is accepted once the clock has caught up.
    let request = node.request(SECOND, vec![node.transfer(0, 9, 1000)], vec![]);
    clock.set(micros(&request.time) - tolerance - 1);
    let before = node.app.stats();
    assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
    assert_eq!(node.app.stats(), before, "a rejected proposal was executed");
    clock.set(micros(&request.time) - tolerance);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, ACCEPT);
    let response = node.app.try_finalize(request.clone()).unwrap();
    let after = node.app.stats();
    assert_eq!(after.executed_blocks, before.executed_blocks + 1);
    assert_eq!(after.reused_executions, before.reused_executions + 1);
    node.committed(SECOND, request, response);

    // A block dated 45 s ahead of this node's clock: beyond this check, but
    // within CometBFT's own `block_time_tolerance` (60 s), so CometBFT on
    // this node prevotes nil after the rejection, yet precommits and commits
    // the block once two thirds of the others prevote it. FinalizeBlock
    // then applies it: the application never refuses a decided block for its
    // date.
    let request = node.request(15 * SECOND, vec![node.transfer(1, 9, 1000)], vec![]);
    assert_eq!(micros(&request.time) - clock.now(), 45 * SECOND as i64);
    let before = node.app.stats();
    assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
    assert_eq!(node.app.stats(), before);
    let response = node.app.try_finalize(request.clone()).unwrap();
    assert_eq!(node.app.stats().executed_blocks, before.executed_blocks + 1);
    node.committed(15 * SECOND, request, response);
    assert_eq!(node.meta().time_micros, GENESIS_TIME + node.elapsed as i64);
    assert_eq!(node.account(9).balance, 2000);
    // The proposer is not judged by the clock: it does not choose the time.
    let payment = node.transfer(2, 9, 1000);
    assert_eq!(node.prepare(SECOND, std::slice::from_ref(&payment), vec![]), vec![payment.clone()]);

    // Restarted with its clock still 45 s behind the chain: the replay of
    // the decided blocks never consults the clock.
    let (height, root) = node.app.head().unwrap().unwrap();
    let (log, elapsed) = (node.log.clone(), node.elapsed);
    drop(node);
    let app = open();
    assert_eq!(app.head().unwrap().unwrap().0, 0, "only the genesis snapshot");
    app.try_init(init(&genesis())).unwrap();
    for (request, response) in &log {
        assert_eq!(app.try_finalize(request.clone()).unwrap(), *response);
        app.try_commit().unwrap();
    }
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    // Its own proposals are judged again once its clock has caught up.
    let mut node = Node::resume(app, &genesis(), height as i64, elapsed);
    let request = node.request(SECOND, vec![payment.clone()], vec![]);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
    clock.set(micros(&request.time));
    node.block(SECOND, vec![payment], vec![]);
    assert_eq!(node.account(9).balance, 3000);
}

#[test]
fn a_node_judges_proposals_by_this_machine_s_clock() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros() as i64;
    // A chain that started an hour ago.
    let genesis = genesis_at(now - 3600 * SECOND as i64);
    let dir = tempfile::tempdir().unwrap();
    let app = App::open_with_clock(dir.path().join("node.db"), app::DEFAULT_CLOCK_TOLERANCE, app::system_clock()).unwrap();
    let mut node = Node::on(app, &genesis);
    // Blocks dated fifty and ten minutes ago: accepted.
    node.block(600 * SECOND, vec![], vec![]);
    node.block(2400 * SECOND, vec![], vec![]);
    // Dated an hour and fifty minutes ahead of this machine's clock: rejected.
    let ahead = node.request(2 * 3600 * SECOND, vec![], vec![]);
    assert_eq!(node.app.process_proposal(proposal(&ahead)).status, REJECT);
    // Ten seconds ahead, within the 30 allowed: accepted.
    let within = node.request(610 * SECOND, vec![], vec![]);
    assert_eq!(node.app.process_proposal(proposal(&within)).status, ACCEPT);
    let response = node.app.try_finalize(within.clone()).unwrap();
    node.committed(610 * SECOND, within, response);
}

// The tests below were written by an independent review, and adapted.

/// Elapsed micros of committed height `height` on `node`.
fn elapsed_of(node: &Node, height: i64) -> u64 {
    (micros(&node.log[(height - 1) as usize].0.time) - node.genesis_time) as u64
}

#[test]
fn the_slash_window_ends_where_kind_20_s_does() {
    for extra in [0u64, 1] {
        let dir = tempfile::tempdir().unwrap();
        let mut auto = Node::start(&dir.path().join("auto.db"));
        let mut manual = Node::start(&dir.path().join("manual.db"));
        let mut control = Node::start(&dir.path().join("control.db"));
        for node in [&mut auto, &mut manual, &mut control] {
            for _ in 0..3 {
                node.block(60 * SECOND, vec![], vec![]);
            }
            let txs = vec![node.extension(OFFENDER, 18, json!({"amount": "500000"}))];
            node.block(SECOND, txs, vec![]);
            node.block(SECOND, vec![], vec![]);
        }
        // The next block is exactly 14 days after the offence, or 1 µs more.
        let offense = 4i64;
        let delta = elapsed_of(&auto, offense) + pos::UNBOND_DELAY + extra - auto.elapsed;
        auto.block(delta, vec![], vec![double_vote(OFFENDER, offense)]);
        control.block(delta, vec![], vec![]);
        let tx = manual.report(REPORTER, OFFENDER, offense as u64);
        let request = manual.request(delta, vec![tx], vec![]);
        let accepted = manual.app.process_proposal(proposal(&request)).status == ACCEPT;
        if extra == 0 {
            assert!(auto.candidate(OFFENDER).jailed, "skipped at exactly 14 days");
            assert!(accepted, "kind 20 refused at exactly 14 days");
        } else {
            assert!(!auto.candidate(OFFENDER).jailed, "punished after 14 days");
            assert_eq!(auto.root(), control.root());
            assert!(!accepted, "kind 20 accepted after 14 days");
        }
    }
}

#[test]
fn on_four_validators_one_report_holds_payments_until_a_funded_candidate_registers() {
    let dir = tempfile::tempdir().unwrap();
    let mut genesis = genesis_at(GENESIS_TIME);
    genesis.validators.truncate(4);
    let path = dir.path().join("node.db");
    let mut node = Node::on(App::open(&path).unwrap(), &genesis);
    for _ in 0..3 {
        node.block(60 * SECOND, vec![], vec![]);
    }
    // Account 8 is given what it takes to register, before the report.
    let txs = vec![node.transfer(0, 8, 2 * SECOND)];
    node.block(SECOND, txs, vec![]);
    node.block(SECOND, vec![], vec![double_vote(OFFENDER, 2)]);
    assert!(node.candidate(OFFENDER).jailed);
    // Three clean validators are too few: the offender stays in the roster
    // and the hold stays on, however long nobody acts.
    for _ in 0..30 {
        node.block(60 * SECOND, vec![], vec![]);
    }
    let summary = node.summary();
    assert!(summary.safety_hold, "hold ended");
    assert!(summary.active.iter().any(|v| v.owner == OFFENDER), "the offender left the roster");
    let answer = node.check(&node.transfer(2, 9, 1000));
    assert!(answer.code != 0 && answer.log.contains("critical validator hold"), "{}", answer.log);
    // A funded candidate registers (allowed during the hold) and takes the
    // offender's place at H+2; then payments pass again.
    let txs = vec![node.register(8, 120)];
    node.block(SECOND, txs, vec![]);
    node.block(SECOND, vec![], vec![]);
    node.block(SECOND, vec![], vec![]);
    let summary = node.summary();
    assert!(!summary.safety_hold);
    assert!(!summary.active.iter().any(|v| v.owner == OFFENDER) && summary.active.iter().any(|v| v.owner == 8));
    let txs = vec![node.transfer(2, 9, 1000)];
    node.block(SECOND, txs, vec![]);
    node.stop_and_audit(&path);
}

#[test]
fn two_offenders_in_either_order_reach_the_same_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut ab = Node::start(&dir.path().join("ab.db"));
    let mut ba = Node::start(&dir.path().join("ba.db"));
    for node in [&mut ab, &mut ba] {
        for _ in 0..4 {
            node.block(60 * SECOND, vec![], vec![]);
        }
    }
    ab.block(SECOND, vec![], vec![entry(LIGHT_CLIENT_ATTACK, validator(2), 3), entry(LIGHT_CLIENT_ATTACK, validator(5), 3)]);
    ba.block(SECOND, vec![], vec![entry(LIGHT_CLIENT_ATTACK, validator(5), 3), entry(LIGHT_CLIENT_ATTACK, validator(2), 3)]);
    assert_eq!(ab.root(), ba.root());
    for node in [&mut ab, &mut ba] {
        node.block(SECOND, vec![], vec![]);
        node.block(SECOND, vec![], vec![]);
    }
    assert_eq!(ab.root(), ba.root());
    assert_eq!(ab.summary().active.len(), 5);
}

#[test]
fn a_waiting_evidence_action_for_the_reported_offender_is_dropped_and_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(&dir.path().join("node.db"));
    for _ in 0..5 {
        node.block(60 * SECOND, vec![], vec![]);
    }
    let tx = node.report(REPORTER, OFFENDER, 4);
    assert_eq!(node.check(&tx).code, 0);
    let report = vec![double_vote(OFFENDER, 4)];
    assert!(node.prepare(SECOND, std::slice::from_ref(&tx), report.clone()).is_empty());
    let request = node.request(SECOND, vec![tx.clone()], report.clone());
    assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
    node.block(SECOND, vec![], report);
    assert!(node.candidate(OFFENDER).jailed);
    assert_ne!(node.check(&tx).code, 0);
}

/// A light client attack whose common height is below the conflicting
/// height names validators of the conflicting height's set (CometBFT
/// `GetByzantineValidators`, equivocation branch). One that joined in
/// between is punished; a duplicate vote at that height is not, nor a light
/// client attack naming a candidate that has never been a validator.
#[test]
fn a_light_client_attack_naming_a_validator_that_joined_after_the_common_height_is_punished() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::start(&path);
    let (newcomer, seed) = (8u64, 120u8);
    let (later, later_seed) = (9u64, 121u8);
    for _ in 0..3 {
        node.block(60 * SECOND, vec![], vec![]);
    }
    let txs = vec![node.transfer(0, newcomer, 2 * SECOND), node.transfer(1, later, 2 * SECOND)];
    node.block(SECOND, txs, vec![]);
    // Block 5: the newcomer registers; it is in the roster from block 7.
    let txs = vec![node.register(newcomer, seed)];
    node.block(SECOND, txs, vec![]);
    for _ in 0..3 {
        node.block(SECOND, vec![], vec![]);
    }
    assert!(node.summary().active.iter().any(|v| v.owner == newcomer));
    // Block 9: another candidate registers; it is not a validator yet. A
    // duplicate vote naming the newcomer at height 4 is skipped: a duplicate
    // vote always names a validator of its own height.
    let txs = vec![node.register(later, later_seed)];
    node.block(SECOND, txs, vec![entry(DUPLICATE_VOTE, address(&pk(seed)), 4)]);
    assert!(!node.candidate(newcomer).jailed);
    // Block 10: light client attacks with common height 4. The newcomer is
    // punished; the candidate that has never been a validator is not.
    assert!(!node.summary().active.iter().any(|v| v.owner == later));
    node.block(
        SECOND,
        vec![],
        vec![entry(LIGHT_CLIENT_ATTACK, address(&pk(later_seed)), 4), entry(LIGHT_CLIENT_ATTACK, address(&pk(seed)), 4)],
    );
    assert!(node.candidate(newcomer).jailed, "not punished");
    assert!(!node.candidate(later).jailed);
    let recorded: [u8; 20] = address(&pk(seed)).try_into().unwrap();
    assert_eq!(node.row(&misbehavior_key(2, &recorded, 4)), Some(b"\"10\"".to_vec()));
    node.stop_and_audit(&path);
}
