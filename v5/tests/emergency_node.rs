//! The emergency path as validators live it, through the ABCI calls CometBFT
//! makes (`docs/design/upgrade-mechanism.md`, section 10;
//! `docs/emergency-fix.md`).
//!
//! Four validators of equal power, each with a program and a state
//! directory of its own, and a stand-in for consensus written for these
//! tests: a proposer builds a block (`PrepareProposal`), every validator
//! that runs judges it (`ProcessProposal`), and the block is decided only
//! if validators with more than two thirds of the power accept it. A
//! decided block is then handed to every validator that runs
//! (`FinalizeBlock`, `Commit`), and later to those that were down. That is
//! what CometBFT does with these answers; nothing here is CometBFT itself.
//!
//! - An emergency at an agreed height, from the coordinated stop to the
//!   switch and the blocks after it: who must cooperate to stop and to
//!   resume, and what a program that was not replaced does.
//! - A fix release built for a height the chain did not stop at.
//! - The root the validators agreed on, checked before a node goes on.
//! - A block that was decided and not executed (a stop in the middle of a
//!   block), and the fix release that repairs it.
//! - The node binary: `--expect-root`, and its unchanged version line.
//! - On a rehearsal build only: the deliberately faulty rule that stops
//!   every node in the middle of a block.
//!
//! `emergency.rs` tests the rules on the engine.
mod common;
use common::*;
use prost::Message;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::Account;
use timecurrency_v5::{
    app::{App, FAILED_BLOCK_LINE, ResumeOptions, StopCause, UpgradeOptions},
    engine,
    rules::{self, Switch, SwitchAt, Versions},
    statesync::NodeOptions,
    transport::BatchCheck,
    upgrade,
};

const SECOND: u64 = pos::SECOND;
const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const VALIDATORS: usize = 4;

fn list(versions: &[(u64, &str)]) -> Versions {
    Versions::new(versions.iter().map(|(version, spec)| (*version, (*spec).to_string()))).unwrap()
}
/// Release 1: version 4 and no switch.
fn old() -> Versions {
    list(&[(4, rules::SPEC_4)])
}
/// A program that implements a version 5 and is not a fix release.
fn plain() -> Versions {
    list(&[(4, rules::SPEC_4), (5, SPEC_5)])
}
/// A fix release for the test network: the switch to version 5 after `height`.
fn fix(height: u64) -> Versions {
    plain()
        .with_switch(Switch { network_id: network_id(), version: 5, at: SwitchAt::After { height } })
        .unwrap()
}
/// A fix release that repairs the decided block `height`.
fn repair(base: Versions, height: u64, block_hash: [u8; 32], parent_root: [u8; 32]) -> Versions {
    base.with_switch(Switch {
        network_id: network_id(),
        version: 5,
        at: SwitchAt::Block { height, block_hash: hex::encode(block_hash), parent_root: hex::encode(parent_root) },
    })
    .unwrap()
}
fn switch() -> Vec<u8> {
    upgrade::switch_action(&network_id(), 5, SPEC_5).unwrap()
}
fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp { seconds: micros / 1_000_000, nanos: ((micros % 1_000_000) * 1000) as i32 })
}
fn init() -> RequestInitChain {
    let genesis = genesis_v5();
    RequestInitChain {
        chain_id: genesis.ledger.chain_id.clone(),
        time: timestamp(genesis.ledger.genesis_time_micros),
        app_state_bytes: serde_json::to_vec(&genesis).unwrap().into(),
        validators: genesis
            .validators
            .iter()
            .map(|validator| ValidatorUpdate {
                pub_key: Some(tendermint_proto::crypto::PublicKey {
                    sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(hex::decode(&validator.consensus_key).unwrap())),
                }),
                power: genesis.profile.genesis_power() as i64,
            })
            .collect(),
        ..Default::default()
    }
}
fn last_commit(height: i64) -> Option<CommitInfo> {
    let genesis = genesis_v5();
    (height > 1).then(|| CommitInfo {
        round: 0,
        votes: genesis
            .validators
            .iter()
            .map(|validator| VoteInfo {
                validator: Some(Validator {
                    address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20].to_vec().into(),
                    power: genesis.profile.genesis_power() as i64,
                }),
                block_id_flag: BlockIdFlag::Commit as i32,
            })
            .collect(),
    })
}
fn proposal(request: &RequestFinalizeBlock) -> RequestProcessProposal {
    RequestProcessProposal {
        txs: request.txs.clone(),
        proposed_last_commit: request.decided_last_commit.clone(),
        misbehavior: request.misbehavior.clone(),
        hash: request.hash.clone(),
        height: request.height,
        time: request.time.clone(),
        next_validators_hash: request.next_validators_hash.clone(),
        proposer_address: request.proposer_address.clone(),
    }
}
/// The hash these tests give a block: of its height and its transactions.
fn block_hash(height: i64, txs: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"block");
    hasher.update(height.to_be_bytes());
    for tx in txs {
        hasher.update((tx.len() as u64).to_be_bytes());
        hasher.update(tx);
    }
    hasher.finalize().into()
}
fn query(app: &App, path: &str, data: &Value) -> Value {
    let response = app.query(RequestQuery { data: serde_json::to_vec(data).unwrap().into(), path: path.into(), height: 0, prove: false });
    assert_eq!(response.code, 0, "{}", response.log);
    serde_json::from_slice(&response.value).unwrap()
}
fn account(app: &App, id: u64) -> Account {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()] }));
    let key = hex::encode(engine::account_key(id));
    let entry = view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == key.as_str()).expect("account entry");
    serde_json::from_slice(&STANDARD.decode(entry["value_b64"].as_str().expect("account exists")).unwrap()).unwrap()
}
fn open(path: &Path, versions: Versions, stop_after_height: Option<u64>, expect_root: Option<(u64, [u8; 32])>) -> anyhow::Result<App> {
    App::open_resuming(path, None, NodeOptions::default(), UpgradeOptions { implemented: versions, stop_after_height }, ResumeOptions { expect_root })
}

/// What a validator did with a decided block.
#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    /// Executed and committed, with this answer.
    Executed(Vec<u8>),
    /// Not executed: the node stopped on purpose (exit code 4).
    Stopped(StopCause),
    /// Not executed: a check failed (the node fails closed, exit code 1).
    Failed(String),
}
struct Round {
    request: RequestFinalizeBlock,
    /// Each validator's vote: `None` from one that does not run.
    votes: Vec<Option<bool>>,
    /// What each validator that runs did with the block, if it was decided.
    decided: Option<Vec<Option<Outcome>>>,
}
struct Net {
    dir: tempfile::TempDir,
    apps: Vec<Option<App>>,
    programs: Vec<Versions>,
    /// The decided blocks, in order: block N is `log[N - 1]`.
    log: Vec<RequestFinalizeBlock>,
    /// The time of the newest decided block, in microseconds since genesis.
    elapsed: u64,
}
impl Net {
    /// Four validators on release 1, with owners able to pay fees.
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let apps = (0..VALIDATORS)
            .map(|index| {
                let app = open(&dir.path().join(format!("validator-{index}")), old(), None, None).unwrap();
                app.try_init(init()).unwrap();
                Some(app)
            })
            .collect();
        let mut net = Self { dir, apps, programs: vec![old(); VALIDATORS], log: Vec::new(), elapsed: 0 };
        net.must_decide(0, SECOND, vec![]);
        while !(0..4).all(|id| net.account(id).balance >= 5 * SECOND) {
            assert!(net.height() < 40, "validator owners were not funded");
            let proposer = net.height() as usize % VALIDATORS;
            net.must_decide(proposer, 60 * SECOND, vec![]);
        }
        net
    }
    fn path(&self, index: usize) -> PathBuf {
        self.dir.path().join(format!("validator-{index}"))
    }
    /// The height of the newest decided block.
    fn height(&self) -> i64 {
        self.log.len() as i64
    }
    fn app(&self, index: usize) -> &App {
        self.apps[index].as_ref().expect("the validator's program is up")
    }
    /// Whether the validator's program runs and has not stopped.
    fn runs(&self, index: usize) -> bool {
        self.apps[index].as_ref().is_some_and(|app| !app.stopped())
    }
    fn head(&self, index: usize) -> (u64, [u8; 32]) {
        self.app(index).head().unwrap().expect("initialized")
    }
    fn stop(&self, index: usize) -> Option<StopCause> {
        self.app(index).stop()
    }
    /// An account, as the first validator that runs holds it.
    fn account(&self, id: u64) -> Account {
        let index = (0..VALIDATORS).find(|index| self.runs(*index)).expect("a validator runs");
        account(self.app(index), id)
    }
    fn pay(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        transfer(&self.account(from), from as u8 + 1, to, amount)
    }
    /// The block dated `delta` after the newest decided one, with `txs`.
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>) -> RequestFinalizeBlock {
        let height = self.height() + 1;
        RequestFinalizeBlock {
            height,
            time: timestamp(genesis_v5().ledger.genesis_time_micros + (self.elapsed + delta) as i64),
            hash: block_hash(height, &txs).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: last_commit(height),
            ..Default::default()
        }
    }
    /// What validator `proposer` proposes of `mempool` for the next block.
    fn proposes(&self, proposer: usize, delta: u64, mempool: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        assert!(self.runs(proposer), "validator {proposer} does not run and proposes nothing");
        let request = self.request(delta, vec![]);
        self.app(proposer)
            .prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: 1 << 20,
                txs: mempool.into_iter().map(Into::into).collect(),
                height: request.height,
                time: request.time,
                local_last_commit: None,
                ..Default::default()
            })
            .txs
            .into_iter()
            .map(|tx| tx.to_vec())
            .collect()
    }
    /// Every running validator's vote on a proposed block. A validator that
    /// does not run, or has stopped, casts none.
    fn votes(&self, request: &RequestFinalizeBlock) -> Vec<Option<bool>> {
        (0..VALIDATORS)
            .map(|index| self.runs(index).then(|| self.app(index).process_proposal(proposal(request)).status == ACCEPT))
            .collect()
    }
    /// Hands one decided block to one validator, as CometBFT does.
    fn execute(&self, index: usize, request: &RequestFinalizeBlock) -> Outcome {
        let app = self.app(index);
        match app.try_finalize(request.clone()) {
            Ok(response) => match app.try_commit() {
                Ok(_) => Outcome::Executed(response.encode_to_vec()),
                Err(error) => Outcome::Failed(format!("{error:#}")),
            },
            Err(error) => match app.stop() {
                Some(cause) => Outcome::Stopped(cause),
                None => Outcome::Failed(format!("{error:#}")),
            },
        }
    }
    /// A block the network decided: recorded, and handed to every validator
    /// that runs and is at the block before.
    fn decide(&mut self, request: RequestFinalizeBlock) -> Vec<Option<Outcome>> {
        let outcomes: Vec<Option<Outcome>> = (0..VALIDATORS)
            .map(|index| (self.runs(index) && self.head(index).0 + 1 == request.height as u64).then(|| self.execute(index, &request)))
            .collect();
        let micros = request.time.as_ref().unwrap();
        self.elapsed = (micros.seconds * 1_000_000 + i64::from(micros.nanos / 1000) - genesis_v5().ledger.genesis_time_micros) as u64;
        self.log.push(request);
        // Every validator that executed the block gave the same answer.
        let answers: Vec<&Vec<u8>> = outcomes.iter().flatten().filter_map(|outcome| match outcome { Outcome::Executed(answer) => Some(answer), _ => None }).collect();
        assert!(answers.windows(2).all(|pair| pair[0] == pair[1]), "validators answered a decided block differently");
        outcomes
    }
    /// One round: validator `proposer` proposes from `mempool`, everybody
    /// votes, and the block is decided with more than two thirds of the power.
    fn round(&mut self, proposer: usize, delta: u64, mempool: Vec<Vec<u8>>) -> Round {
        let txs = self.proposes(proposer, delta, mempool);
        self.round_on(self.request(delta, txs))
    }
    /// As `round`, for a block somebody built by hand.
    fn round_on(&mut self, request: RequestFinalizeBlock) -> Round {
        let votes = self.votes(&request);
        let accepted = votes.iter().filter(|vote| **vote == Some(true)).count();
        let decided = (accepted * 3 > VALIDATORS * 2).then(|| self.decide(request.clone()));
        Round { request, votes, decided }
    }
    /// A round that must decide its block, executed by every validator that runs.
    fn must_decide(&mut self, proposer: usize, delta: u64, mempool: Vec<Vec<u8>>) -> Vec<u8> {
        let expected = mempool.clone();
        let round = self.round(proposer, delta, mempool);
        let outcomes = round.decided.unwrap_or_else(|| panic!("block {} was not decided: votes {:?}", round.request.height, round.votes));
        assert_eq!(round.request.txs.iter().map(|tx| tx.to_vec()).collect::<Vec<_>>(), expected, "the proposer changed the block");
        let mut answer = None;
        for outcome in outcomes.into_iter().flatten() {
            match outcome {
                Outcome::Executed(bytes) => answer = Some(bytes),
                other => panic!("block {}: {other:?}", round.request.height),
            }
        }
        answer.expect("somebody executed the block")
    }
    /// Stops validator `index` cleanly (it saves its state) and starts it on
    /// the same data with another program or other flags.
    fn restart(&mut self, index: usize, versions: Versions, stop_after_height: Option<u64>, expect_root: Option<(u64, [u8; 32])>) {
        if let Some(app) = self.apps[index].take() {
            app.snapshot().unwrap();
            drop(app);
        }
        self.apps[index] = Some(open(&self.path(index), versions.clone(), stop_after_height, expect_root).unwrap_or_else(|error| panic!("validator {index} did not start: {error:#}")));
        self.programs[index] = versions;
    }
    /// Ends validator `index` without saving: its next start is from its
    /// last snapshot.
    fn crash(&mut self, index: usize) {
        self.apps[index] = None;
    }
    /// Hands validator `index` the decided blocks above its head, one by
    /// one, until it has them all or does not execute one.
    fn catch_up(&mut self, index: usize) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        while self.runs(index) && (self.head(index).0 as i64) < self.height() {
            let request = self.log[self.head(index).0 as usize].clone();
            let outcome = self.execute(index, &request);
            let executed = matches!(outcome, Outcome::Executed(_));
            outcomes.push(outcome);
            if !executed {
                break;
            }
        }
        outcomes
    }
    fn status(&self, index: usize) -> Value {
        query(self.app(index), "/status", &json!(null))
    }
    fn version(&self, index: usize) -> u64 {
        self.app(index).info(RequestInfo::default()).app_version
    }
}
fn version_of(answer: &[u8]) -> u64 {
    ResponseFinalizeBlock::decode(answer).unwrap().consensus_param_updates.unwrap().version.unwrap().app
}

/// Design, section 10, end to end on four validators.
///
/// 1. The validators agree on a height `H`. More than a third of the power
///    is restarted with `--stop-after-height H`: the chain stands at `H`.
/// 2. Everybody compares the root at `H`.
/// 3. The fix release is started on that state. With half of the power on
///    it nothing is decided, whoever proposes: the old program rejects the
///    switch block and the fix release rejects every other block. Nobody
///    stops, and no block is made by both together.
/// 4. With more than two thirds on it, its proposer's block is decided: one
///    transaction, the switch. It ends under version 5.
/// 5. The validator that was not replaced does not execute that block and
///    stops (`STOPPED AT A SWITCH`). Started on the fix release, it is
///    handed the block again and holds the others' state.
/// 6. The chain goes on under version 5, and the switch is accepted by
///    nobody a second time.
#[test]
fn an_emergency_at_an_agreed_height_from_the_stop_to_the_switch_and_after() {
    let mut net = Net::start();
    for proposer in 0..VALIDATORS {
        let paid = net.pay(0, 5, 1000);
        net.must_decide(proposer, SECOND, vec![paid]);
    }
    // 1. The agreed height, three blocks ahead. Validators 2 and 3, half of
    // the power, are restarted with the flag.
    let h = net.height() as u64 + 3;
    net.restart(2, old(), Some(h), None);
    net.restart(3, old(), Some(h), None);
    while (net.height() as u64) < h {
        let proposer = net.height() as usize % VALIDATORS;
        let paid = net.pay(1, 5, 500);
        net.must_decide(proposer, SECOND, vec![paid]);
    }
    for index in [2, 3] {
        assert_eq!(net.stop(index), Some(StopCause::Asked { height: h }));
    }
    assert!(net.runs(0) && net.runs(1));
    // The chain stands at H: the two that run are half of the power.
    for proposer in [0, 1] {
        let round = net.round(proposer, SECOND, vec![]);
        assert_eq!(round.votes, vec![Some(true), Some(true), None, None]);
        assert!(round.decided.is_none(), "a block after the agreed height was decided");
    }
    // 2. One height, one root, on all four.
    let agreed = net.head(0);
    assert_eq!(agreed.0, h);
    for index in 0..VALIDATORS {
        assert_eq!(net.head(index), agreed, "validator {index}");
        assert_eq!(net.version(index), 4);
    }
    // 3. The fix release on the two that stopped, each told the agreed root.
    net.restart(2, fix(h), None, Some(agreed));
    net.restart(3, fix(h), None, Some(agreed));
    assert_eq!(
        net.status(2)["upgrade"]["switches"],
        json!([{"version": "5", "spec": SPEC_5, "after_height": h.to_string(), "block_height": (h + 1).to_string()}])
    );
    assert_eq!(net.status(2)["upgrade"]["expect_root"], format!("{h}:{}", hex::encode(agreed.1)));
    assert!(net.status(0)["upgrade"].get("switches").is_none() && net.status(0)["upgrade"].get("expect_root").is_none());
    // Its proposer proposes the switch, alone, whatever its mempool holds.
    let waiting = vec![net.pay(0, 5, 77), net.pay(1, 5, 78)];
    assert_eq!(net.proposes(2, SECOND, waiting.clone()), vec![switch()]);
    // Half of the power on each program: no block is decided, whoever
    // proposes it, and nobody stops.
    for _ in 0..2 {
        for proposer in 0..VALIDATORS {
            let round = net.round(proposer, SECOND, waiting.clone());
            let own = round.request.txs.len() == 1 && round.request.txs[0].as_ref() == switch().as_slice();
            assert_eq!(own, proposer >= 2, "validator {proposer} proposed {} transaction(s)", round.request.txs.len());
            // The old program accepts its own kind of block and the fix
            // release only the switch block.
            assert_eq!(round.votes, vec![Some(!own), Some(!own), Some(own), Some(own)], "proposer {proposer}");
            assert!(round.decided.is_none(), "old and new validators decided a block together");
        }
    }
    for index in 0..VALIDATORS {
        assert!(net.stop(index).is_none(), "a proposal stopped validator {index}");
        assert_eq!(net.head(index), agreed);
    }
    // 4. A third validator on the fix release: more than two thirds.
    net.restart(1, fix(h), None, Some(agreed));
    // A proposal of the old program is still not decided.
    assert!(net.round(0, SECOND, waiting.clone()).decided.is_none());
    let round = net.round(1, 2 * SECOND, waiting.clone());
    assert_eq!(round.votes, vec![Some(false), Some(true), Some(true), Some(true)]);
    let outcomes = round.decided.expect("the switch block was decided");
    assert_eq!(round.request.height as u64, h + 1);
    assert_eq!(round.request.txs.iter().map(|tx| tx.to_vec()).collect::<Vec<_>>(), vec![switch()]);
    let answer = match &outcomes[1] {
        Some(Outcome::Executed(answer)) => answer.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(version_of(&answer), 5, "the switch block ends under version 5");
    assert_eq!(ResponseFinalizeBlock::decode(answer.as_slice()).unwrap().tx_results.len(), 1);
    for index in 1..VALIDATORS {
        assert_eq!(outcomes[index], Some(Outcome::Executed(answer.clone())), "validator {index}");
        assert_eq!((net.head(index).0, net.version(index)), (h + 1, 5));
    }
    // 5. The validator on the old program: nothing of the block executed,
    // stopped on purpose, its state at H.
    assert_eq!(outcomes[0], Some(Outcome::Stopped(StopCause::Switch { height: h + 1 })));
    assert_eq!(net.stop(0).unwrap().first_line(), "STOPPED AT A SWITCH");
    assert_eq!(net.head(0), agreed);
    // Started on the fix release on the same data, it is handed the block
    // again, executes it, and holds what the others hold.
    net.restart(0, fix(h), None, Some(agreed));
    assert!(net.stop(0).is_none());
    assert_eq!(net.catch_up(0), vec![Outcome::Executed(answer)]);
    let after = net.head(1);
    for index in 0..VALIDATORS {
        assert_eq!(net.head(index), after, "validator {index}");
        assert_eq!(net.status(index)["app_version"], "5");
    }
    // 6. The chain goes on under version 5: what waited is now included.
    for proposer in 0..VALIDATORS {
        let paid = net.pay(2, 5, 250);
        let answer = net.must_decide(proposer, SECOND, vec![paid]);
        assert_eq!(version_of(&answer), 5);
    }
    assert_eq!(net.head(0), net.head(3));
    // The switch a second time: never proposed, and a block that carries it
    // is rejected by all four, who run on.
    assert!(net.proposes(0, SECOND, vec![switch()]).is_empty());
    let again = net.round_on(net.request(SECOND, vec![switch()]));
    assert_eq!(again.votes, vec![Some(false); VALIDATORS]);
    assert!(again.decided.is_none() && (0..VALIDATORS).all(|index| net.stop(index).is_none()));
    // The flag for the agreed root is for that one start: a node that has
    // gone on does not start with it again.
    net.apps[3].take().unwrap().snapshot().unwrap();
    let error = format!("{:#}", open(&net.path(3), fix(h), None, Some(agreed)).err().expect("started above the agreed height"));
    assert!(error.contains("already at height") && error.contains("Nothing was changed"), "{error}");
    net.restart(3, fix(h), None, None);
    assert_eq!(net.head(3), net.head(0));
}

/// "More than a third must cooperate to stop": one validator of four is not
/// enough, and the chain goes on without it.
#[test]
fn a_quarter_of_the_power_stopping_at_a_height_does_not_stop_the_chain() {
    let mut net = Net::start();
    let h = net.height() as u64 + 2;
    net.restart(3, old(), Some(h), None);
    while (net.height() as u64) < h + 3 {
        let proposer = net.height() as usize % 3;
        net.must_decide(proposer, SECOND, vec![]);
    }
    assert_eq!(net.stop(3), Some(StopCause::Asked { height: h }));
    assert_eq!((net.head(3).0, net.head(0).0), (h, h + 3));
    // The validator that stopped goes on from its state, without the flag.
    net.restart(3, old(), None, None);
    assert_eq!(net.catch_up(3).len(), 3);
    assert_eq!(net.head(3), net.head(0));
}

/// "What the fix release refuses, so that a wrong `H` cannot be papered
/// over": a decided block `H + 1` that is not the switch block, and a start
/// on a state above `H` that is still under the old version.
#[test]
fn a_fix_release_built_for_a_height_the_chain_did_not_stop_at_does_not_go_on() {
    let mut net = Net::start();
    let h = net.height() as u64 + 2;
    // Nobody stops at H. One validator runs a fix release built for it.
    net.restart(3, fix(h), None, None);
    while (net.height() as u64) < h {
        let proposer = net.height() as usize % VALIDATORS;
        net.must_decide(proposer, SECOND, vec![]);
    }
    let at_h = net.head(3);
    // Its own proposal for H + 1 is the switch, and three quarters reject it.
    let round = net.round(3, SECOND, vec![]);
    assert_eq!(round.votes, vec![Some(false), Some(false), Some(false), Some(true)]);
    assert!(round.decided.is_none() && net.stop(3).is_none());
    // The others' block is decided without it. It does not execute it, and
    // stops on purpose with its state at H.
    let paid = net.pay(0, 5, 1000);
    let round = net.round(0, SECOND, vec![paid]);
    assert_eq!(round.votes, vec![Some(true), Some(true), Some(true), Some(false)]);
    let outcomes = round.decided.expect("three quarters decide");
    let cause = match &outcomes[3] {
        Some(Outcome::Stopped(cause)) => cause.clone(),
        other => panic!("{other:?}"),
    };
    match &cause {
        StopCause::SwitchExpected { height, found } => {
            assert_eq!(*height, h + 1);
            assert!(found.contains("must carry exactly one transaction, the rule switch to protocol version 5") && found.contains("none of which is a rule switch"), "{found}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(cause.first_line(), "STOPPED AT A SWITCH");
    let text = cause.explain(Some(h));
    assert!(text.contains(&format!("The decided block {} is not the switch block this fix release was built for", h + 1)), "{text}");
    assert!(text.contains(&format!("The state at height {h} is saved and valid")) && text.contains("Start the release this state was made by") && text.contains("Delete nothing"), "{text}");
    assert_eq!(net.head(3), at_h, "the head moved");
    assert!(net.app(3).stop_ready(), "no answer is in progress");
    // Started again on the fix release it is handed the block again, and
    // stops again.
    net.restart(3, fix(h), None, None);
    assert!(net.stop(3).is_none());
    assert_eq!(net.catch_up(3), vec![Outcome::Stopped(cause)]);
    assert_eq!(net.head(3), at_h);
    // The release the state was made by executes the block and follows.
    net.restart(3, old(), None, None);
    net.must_decide(1, SECOND, vec![]);
    assert_eq!(net.catch_up(3).len(), 2);
    assert_eq!(net.head(3), net.head(0));
    assert_eq!(net.head(3).0, h + 2);
    // On that state, above H and under version 4, the fix release does not
    // start: it is stopped before it serves.
    net.restart(3, fix(h), None, None);
    let missed = upgrade::MissedSwitch { block_height: h + 1, version: 5, head: h + 2, head_version: 4 };
    assert_eq!(net.stop(3), Some(StopCause::SwitchMissed(missed.clone())));
    assert!(net.app(3).stop_ready());
    assert_eq!(net.stop(3).unwrap().first_line(), "STOPPED AT A SWITCH");
    assert_eq!(net.stop(3).unwrap().explain(Some(h + 2)), missed.explain());
    // It admits nothing, and its state is what it was.
    let refused = net.app(3).check_batch(vec![RequestCheckTx { tx: net.pay(0, 5, 1).into(), r#type: 0 }]).pop().unwrap();
    assert!(refused.code == 1 && refused.log.contains("STOPPED AT A SWITCH"), "{}", refused.log);
    assert_eq!(net.head(3), net.head(0));
    // The agreed root is not asked of a node that is stopped anyway.
    net.apps[3].take().unwrap().snapshot().unwrap();
    let stopped = open(&net.path(3), fix(h), None, Some((h, [9; 32]))).unwrap();
    assert!(matches!(stopped.stop(), Some(StopCause::SwitchMissed(_))));
}

/// `--expect-root H:ROOT`: the state the validators agreed to go on from.
#[test]
fn the_agreed_root_is_checked_before_a_node_goes_on() {
    let mut net = Net::start();
    net.must_decide(0, SECOND, vec![]);
    let (h, root) = net.head(1);
    // Validator 1 saves its state at H and is then taken two blocks further
    // without saving.
    net.app(1).snapshot().unwrap();
    net.must_decide(0, SECOND, vec![]);
    net.must_decide(2, SECOND, vec![]);
    let later = net.head(0);
    assert_eq!(later.0, h + 2);
    // At its head: the right root starts, another one does not.
    net.restart(2, old(), None, Some(later));
    assert_eq!(net.status(2)["upgrade"]["expect_root"], format!("{}:{}", later.0, hex::encode(later.1)));
    net.apps[2] = None;
    let refuse = |net: &Net, index: usize, expect: (u64, [u8; 32])| format!("{:#}", open(&net.path(index), old(), None, Some(expect)).err().expect("the node started"));
    let error = refuse(&net, 2, (later.0, [7; 32]));
    assert!(error.contains(&format!("the state of this node at height {} has the root {}", later.0, hex::encode(later.1))), "{error}");
    assert!(error.contains("Nothing was changed") && error.contains("does not hold the state the validators agreed on"), "{error}");
    // Above the height: not started, whatever the root.
    let error = refuse(&net, 2, (h, root));
    assert!(error.contains(&format!("this node is already at height {}, above it. Nothing was changed.", later.0)), "{error}");
    assert!(refuse(&net, 2, (0, root)).contains("at least 1"));
    net.restart(2, old(), None, None);
    // Below the height: validator 1 starts from its snapshot at H, with
    // the blocks after it still to be replayed. What it had committed counts
    // as reached.
    net.crash(1);
    let error = refuse(&net, 1, (h + 1, [7; 32]));
    assert!(error.contains(&format!("already at height {}", h + 2)), "{error}");
    // The right root at H + 2: it replays to there and goes on.
    net.apps[1] = Some(open(&net.path(1), old(), None, Some(later)).unwrap());
    assert_eq!(net.head(1), (h, root));
    assert_eq!(net.catch_up(1).len(), 2);
    assert_eq!(net.head(1), later);
    net.must_decide(3, SECOND, vec![]);
    assert_eq!(net.head(1), net.head(0));
    // Another root at H + 2: it fails closed at the commit of that block,
    // before it answers, and executes nothing after it.
    let mut net = Net::start();
    net.app(1).snapshot().unwrap();
    let h = net.head(1).0;
    net.must_decide(0, SECOND, vec![]);
    net.must_decide(2, SECOND, vec![]);
    net.crash(1);
    net.apps[1] = Some(open(&net.path(1), old(), None, Some((h + 2, [7; 32]))).unwrap());
    let outcomes = net.catch_up(1);
    assert!(matches!(&outcomes[0], Outcome::Executed(_)), "{outcomes:?}");
    match &outcomes[1] {
        Outcome::Failed(error) => {
            assert!(error.contains(&format!("--expect-root {}:{}", h + 2, hex::encode([7u8; 32]))) && error.contains("It executes nothing after that block"), "{error}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(outcomes.len(), 2);
    // It is faulted: no further request is served.
    assert!(net.app(1).try_finalize(net.request(SECOND, vec![])).is_err());
}

/// A stop in the middle of a block, seen from the nodes. A block was
/// decided and nobody executed it. The fix release that names that block
/// executes it and ends it under version 5; it executes no other block at
/// that height; and a node on the old program that does execute the block
/// ends with another answer, which the next header cannot carry for both.
#[test]
fn a_block_that_was_decided_and_not_executed_is_repaired_by_the_fix_release() {
    let mut net = Net::start();
    net.must_decide(1, SECOND, vec![]);
    let (h, root) = net.head(0);
    // The decided block: a payment. Nobody is handed it yet.
    let stuck = net.request(2 * SECOND, vec![net.pay(0, 5, 4000)]);
    let (s, hash): (u64, [u8; 32]) = (h + 1, stuck.hash.as_ref().try_into().unwrap());
    // What a node says when such a block fails a check of its program.
    let report = net.app(0).failed_block_report(stuck.height, &stuck.hash, &anyhow::anyhow!("a check\nfailed"));
    let lines: Vec<&str> = report.lines().collect();
    assert_eq!(lines.len(), 2, "{report}");
    assert_eq!(lines[0], FAILED_BLOCK_LINE);
    assert!(lines[1].starts_with(&format!("The decided block {s} (hash {}) failed a check of this program and was not executed: a check failed.", hex::encode(hash))), "{report}");
    assert!(lines[1].contains(&format!("The state of this node is at height {h} with the root {}, and nothing of block {s} is in it.", hex::encode(root))), "{report}");
    assert!(lines[1].contains("do not restart it in a loop") && lines[1].contains("Delete nothing, roll nothing back"), "{report}");
    // Three validators are started on the fix release built with those four
    // values. The fourth stays on the old program.
    let fixed = || repair(plain(), s, hash, root);
    for index in 0..3 {
        net.restart(index, fixed(), None, Some((h, root)));
        assert!(net.stop(index).is_none());
    }
    assert_eq!(
        net.status(0)["upgrade"]["switches"],
        json!([{"version": "5", "spec": SPEC_5, "block_height": s.to_string(), "block_hash": hex::encode(hash), "parent_root": hex::encode(root)}])
    );
    // At that height the fix release proposes nothing of its own, and
    // accepts the decided block and no other.
    assert!(net.proposes(0, SECOND, vec![net.pay(1, 5, 1)]).is_empty());
    let other = net.request(2 * SECOND, vec![net.pay(1, 5, 4000)]);
    assert_eq!(net.votes(&other), vec![Some(false), Some(false), Some(false), Some(true)]);
    assert_eq!(net.votes(&stuck), vec![Some(true); VALIDATORS]);
    assert!((0..VALIDATORS).all(|index| net.stop(index).is_none()));
    // Another decided block at that height: not executed, and the node stops.
    match net.execute(2, &other) {
        Outcome::Stopped(StopCause::SwitchExpected { height, found }) => {
            assert_eq!(height, s);
            assert!(found.contains("this fix release repairs the block"), "{found}");
        }
        outcome => panic!("{outcome:?}"),
    }
    assert_eq!(net.head(2), (h, root));
    net.restart(2, fixed(), None, Some((h, root)));
    // The decided block itself: executed by all three, with one answer,
    // under version 5 from the next block on. (The validator on the old
    // program is handed the block afterwards, apart.)
    let apart = net.apps[3].take();
    let outcomes = net.decide(stuck.clone());
    let answer = match &outcomes[0] {
        Some(Outcome::Executed(answer)) => answer.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(version_of(&answer), 5);
    for index in 0..3 {
        assert_eq!(outcomes[index], Some(Outcome::Executed(answer.clone())), "validator {index}");
        assert_eq!((net.head(index).0, net.version(index)), (s, 5));
    }
    // The old program, where it can execute the block at all, ends it with
    // another root and under version 4: the two cannot share the next block,
    // whose header carries one application hash and one version.
    net.apps[3] = apart;
    let old_answer = match net.execute(3, &stuck) {
        Outcome::Executed(answer) => ResponseFinalizeBlock::decode(answer.as_slice()).unwrap(),
        other => panic!("{other:?}"),
    };
    let new_answer = ResponseFinalizeBlock::decode(answer.as_slice()).unwrap();
    assert_ne!(old_answer.app_hash, new_answer.app_hash);
    assert_eq!(old_answer.consensus_param_updates.unwrap().version.unwrap().app, 4);
    assert_ne!(net.head(3).1, net.head(0).1);
    // The payment was executed once, on both.
    assert_eq!(account(net.app(0), 0).nonce, account(net.app(3), 0).nonce);
    // The three go on, and repair nothing a second time.
    net.crash(3);
    let paid = net.pay(1, 5, 10);
    assert_eq!(version_of(&net.must_decide(0, SECOND, vec![paid])), 5);
    assert_eq!(net.head(0), net.head(2));
}

fn node(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5")).args(["--devnet", "--db"]).arg(path).args(extra).output().unwrap();
    (output.status.code(), String::from_utf8_lossy(&output.stdout).to_string(), String::from_utf8_lossy(&output.stderr).to_string())
}

/// The node binary and `--expect-root`: one form of the value, a start that
/// fails with exit code 1 and says why first and last, and a start that
/// runs. Its version line is what it was: this build carries no switch.
#[test]
fn the_node_binary_checks_the_agreed_root_and_carries_no_switch() {
    let version = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5")).arg("--version").output().unwrap();
    let line = String::from_utf8_lossy(&version.stdout).trim().to_string();
    assert_eq!(
        line,
        format!(
            "time-node-v5 {} protocol=4{} devnet-only publicLaunchAllowed=false",
            env!("CARGO_PKG_VERSION"),
            if rules::REHEARSAL { " rehearsal=5" } else { "" }
        )
    );
    assert!(!line.contains("switch"));
    let mut net = Net::start();
    net.must_decide(0, SECOND, vec![]);
    let (h, root) = net.head(0);
    net.apps[0].take().unwrap().snapshot().unwrap();
    let path = net.path(0);
    let (right, wrong) = (format!("{h}:{}", hex::encode(root)), format!("{h}:{}", hex::encode([7u8; 32])));
    // One form: a height, a colon, 64 lowercase hexadecimal characters.
    for bad in [
        "".to_string(),
        h.to_string(),
        hex::encode(root),
        format!("{h}:{}", &hex::encode(root)[2..]),
        format!("{h}:{}", hex::encode(root).to_uppercase()),
        format!("0:{}", hex::encode(root)),
        format!("0{h}:{}", hex::encode(root)),
        format!("{h}:0x{}", &hex::encode(root)[2..]),
        format!("{h} :{}", hex::encode(root)),
        format!("{right}:"),
    ] {
        let (code, _, errors) = node(&path, &["--expect-root", &bad]);
        assert_eq!(code, Some(1), "{bad}: {errors}");
        assert!(errors.contains("--expect-root needs HEIGHT:ROOT"), "{bad}: {errors}");
    }
    assert_eq!(node(&path, &["--expect-root"]).0, Some(1));
    assert_eq!(node(&path, &["--expect-root", &right, "--expect-root", &right]).0, Some(1));
    assert_eq!(node(&path, &["--audit", "--expect-root", &right]).0, Some(1));
    // It cannot stop at or before the height it is to go on from.
    let (code, _, errors) = node(&path, &["--expect-root", &right, "--stop-after-height", &h.to_string()]);
    assert!(code == Some(1) && errors.contains("--stop-after-height must be above the height of --expect-root"), "{errors}");
    // Another root: exit code 1, the reason first and again as the last line.
    let (code, out, errors) = node(&path, &["--expect-root", &wrong]);
    assert_eq!(code, Some(1), "{errors}");
    assert!(out.is_empty() && !errors.contains("ABCI listening"), "{errors}");
    assert!(errors.contains(&format!("the state of this node at height {h} has the root {}", hex::encode(root))), "{errors}");
    let last = errors.lines().rev().find(|line| !line.trim().is_empty()).unwrap();
    assert!(last.starts_with(&format!("The node did not start: --expect-root {wrong}:")) && last.contains("Nothing was changed"), "{last}");
    // Above the height.
    let (code, _, errors) = node(&path, &["--expect-root", &format!("{}:{}", h - 1, hex::encode(root))]);
    assert!(code == Some(1) && errors.contains(&format!("this node is already at height {h}, above it")), "{errors}");
    // Nothing was changed by any of these starts.
    let (code, report, errors) = node(&path, &["--audit"]);
    assert_eq!(code, Some(0), "{errors}");
    let report: Value = serde_json::from_str(&report).unwrap();
    assert_eq!((report["height"].as_str(), report["root"].as_str()), (Some(h.to_string().as_str()), Some(hex::encode(root).as_str())));
    // The right root: the node says what it was told and serves. (With a
    // stop height at its head it would stop at once; one above it lets it
    // serve, and the test ends it.)
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5"))
        .args(["--devnet", "--db"])
        .arg(&path)
        .args(["--listen", &format!("127.0.0.1:{port}"), "--expect-root", &right, "--stop-after-height", &(h + 5).to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(started.elapsed() < std::time::Duration::from_secs(30) && child.try_wait().unwrap().is_none(), "the node did not serve");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    child.kill().unwrap();
    let errors = String::from_utf8_lossy(&child.wait_with_output().unwrap().stderr).to_string();
    assert!(errors.contains(&format!("This node goes on from height {h} only on the state with the root {} (--expect-root).", hex::encode(root))), "{errors}");
    assert!(!errors.contains("FIX RELEASE"), "{errors}");
}

/// REHEARSAL BUILDS ONLY: the deliberately faulty rule, and the stop in the
/// middle of a block that it causes on every node.
#[cfg(feature = "rehearsal-v5")]
mod rehearsal_fault {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// The rehearsal program, as a list: version 5 under the rehearsal hash.
    fn rehearsal() -> Versions {
        list(&[(4, rules::SPEC_4), (rules::REHEARSAL_VERSION, rules::REHEARSAL_SPEC)])
    }
    /// Blocks until account 0 can pay the faulty amount, proposed by the
    /// first three validators in turn.
    fn fund(net: &mut Net) {
        let start = net.height();
        while net.account(0).balance < rules::REHEARSAL_FAULT_MICROS + 5 * SECOND {
            assert!(net.height() < start + 200, "account 0 was not funded");
            let proposer = net.height() as usize % 3;
            net.must_decide(proposer, 60 * SECOND, vec![]);
        }
    }
    /// A network whose account 0 can pay the faulty amount.
    fn funded() -> Net {
        let mut net = Net::start();
        fund(&mut net);
        net
    }

    /// Every validator accepts the block as a proposal, the block is
    /// decided, and no validator can finalize it: each fails closed with its
    /// state at the block before, all at one height with one root. The same
    /// program fails on it again. A fix release that repairs that block
    /// executes it, and from then on the fault is gone.
    #[test]
    fn the_faulty_rule_stops_every_node_in_the_middle_of_a_block_and_a_repair_resumes() {
        let mut net = funded();
        // A microsecond less or more than the amount is a payment like any other.
        for amount in [rules::REHEARSAL_FAULT_MICROS - 1, rules::REHEARSAL_FAULT_MICROS + 1] {
            let paid = net.pay(0, 5, amount);
            net.must_decide(0, SECOND, vec![paid]);
            fund(&mut net);
        }
        let (h, root) = net.head(0);
        let poison = net.pay(0, 5, rules::REHEARSAL_FAULT_MICROS);
        // Admitted, proposed and accepted by all four: nothing tells it apart.
        let admitted = net.app(1).check_batch(vec![RequestCheckTx { tx: poison.clone().into(), r#type: 0 }]).pop().unwrap();
        assert_eq!(admitted.code, 0, "{}", admitted.log);
        let other = net.pay(1, 5, 300);
        let round = net.round(2, SECOND, vec![other.clone(), poison.clone()]);
        assert_eq!(round.request.txs.len(), 2);
        assert_eq!(round.votes, vec![Some(true); VALIDATORS]);
        // Decided, and finalized by nobody.
        let outcomes = round.decided.expect("decided");
        let stuck = round.request.clone();
        let (s, hash): (u64, [u8; 32]) = (h + 1, stuck.hash.as_ref().try_into().unwrap());
        for index in 0..VALIDATORS {
            match &outcomes[index] {
                Some(Outcome::Failed(error)) => assert!(error.contains("REHEARSAL FAULT"), "{error}"),
                other => panic!("validator {index}: {other:?}"),
            }
            // A failure, not a stop on purpose; and nothing of the block is
            // in the state.
            assert!(net.stop(index).is_none());
            assert_eq!(net.head(index), (h, root), "validator {index}");
        }
        // The same program again: the same failure, on the same block.
        for index in 0..VALIDATORS {
            net.restart(index, old(), None, None);
            let again = net.catch_up(index);
            assert!(matches!(&again[..], [Outcome::Failed(error)] if error.contains("REHEARSAL FAULT")), "{again:?}");
            assert_eq!(net.head(index), (h, root));
        }
        // A program that knows the rehearsal version does not have the fix
        // for this block by that: the chain is still under version 4.
        net.restart(3, rehearsal(), None, None);
        assert!(matches!(&net.catch_up(3)[..], [Outcome::Failed(_)]));
        // The fix release, built with the block and the state every node
        // reported, on three validators.
        let fixed = || repair(rehearsal(), s, hash, root);
        let mut answer = None;
        for index in 0..3 {
            net.restart(index, fixed(), None, Some((h, root)));
            match &net.catch_up(index)[..] {
                [Outcome::Executed(bytes)] => {
                    assert!(answer.get_or_insert_with(|| bytes.clone()) == bytes, "validator {index} answered differently");
                }
                other => panic!("validator {index}: {other:?}"),
            }
            assert_eq!((net.head(index).0, net.version(index)), (s, rules::REHEARSAL_VERSION));
        }
        assert_eq!(net.head(0), net.head(2));
        // Both payments of the block were executed, once.
        assert_eq!(account(net.app(0), 0).nonce, account(net.app(3), 0).nonce + 1);
        assert_eq!(account(net.app(0), 1).nonce, account(net.app(3), 1).nonce + 1);
        // The validator that was not replaced is where it was.
        assert_eq!(net.head(3), (h, root));
        // Under the rehearsal version the amount is a payment like any other.
        net.crash(3);
        fund(&mut net);
        let again = net.pay(0, 6, rules::REHEARSAL_FAULT_MICROS);
        assert_eq!(version_of(&net.must_decide(0, SECOND, vec![again])), rules::REHEARSAL_VERSION);
        assert_eq!(net.head(0), net.head(2));
    }

    struct Binary {
        child: Child,
        stream: TcpStream,
        errors: Arc<Mutex<String>>,
    }
    impl Binary {
        fn start(path: &Path) -> Self {
            let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            let mut child = Command::new(env!("CARGO_BIN_EXE_time-node-v5"))
                .args(["--devnet", "--db"])
                .arg(path)
                .args(["--listen", &format!("127.0.0.1:{port}"), "--snapshot-seconds", "3600"])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let errors = Arc::new(Mutex::new(String::new()));
            let (sink, mut pipe) = (errors.clone(), child.stderr.take().unwrap());
            std::thread::spawn(move || {
                let mut buffer = [0u8; 4096];
                while let Ok(count) = pipe.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    sink.lock().unwrap().push_str(&String::from_utf8_lossy(&buffer[..count]));
                }
            });
            let started = Instant::now();
            let stream = loop {
                match TcpStream::connect(("127.0.0.1", port)) {
                    Ok(stream) => break stream,
                    Err(error) => {
                        assert!(started.elapsed() < Duration::from_secs(30), "the node did not listen: {error}; {}", errors.lock().unwrap());
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            };
            stream.set_nodelay(true).unwrap();
            Self { child, stream, errors }
        }
        fn frame(value: request::Value) -> Vec<u8> {
            let request = Request { value: Some(value) };
            let mut frame = Vec::new();
            prost::encoding::encode_varint(request.encoded_len() as u64, &mut frame);
            request.encode(&mut frame).unwrap();
            frame
        }
        fn answer(&mut self, wait: Duration) -> Option<response::Value> {
            self.stream.set_read_timeout(Some(wait)).unwrap();
            let (mut length, mut shift) = (0u64, 0);
            loop {
                let mut byte = [0u8; 1];
                match self.stream.read(&mut byte) {
                    Ok(1) => {}
                    _ => return None,
                }
                length |= u64::from(byte[0] & 0x7f) << shift;
                if byte[0] & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            let mut payload = vec![0u8; length as usize];
            self.stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            self.stream.read_exact(&mut payload).ok()?;
            Response::decode(payload.as_slice()).unwrap().value
        }
        /// A request followed by Flush, as CometBFT's socket client sends it.
        fn call(&mut self, value: request::Value, wait: Duration) -> Option<response::Value> {
            let mut bytes = Self::frame(value);
            bytes.extend(Self::frame(request::Value::Flush(RequestFlush {})));
            self.stream.write_all(&bytes).ok()?;
            let first = self.answer(wait)?;
            self.answer(wait)?;
            Some(first)
        }
        fn exit(&mut self, wait: Duration) -> Option<i32> {
            let started = Instant::now();
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    std::thread::sleep(Duration::from_millis(200));
                    return status.code();
                }
                if started.elapsed() >= wait {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    impl Drop for Binary {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// The rehearsal binary, spoken to over its ABCI socket: the decided
    /// block gets no answer, the node says where it stands, and ends with
    /// exit code 1 (a failure, not the exit code 4 of a stop on purpose).
    /// Started again, it starts: its state is the block before.
    #[test]
    fn the_rehearsal_binary_fails_on_the_decided_block_and_says_where_it_stands() {
        let net = funded();
        let (h, root) = net.head(0);
        let poison = net.pay(0, 5, rules::REHEARSAL_FAULT_MICROS);
        let stuck = net.request(SECOND, vec![poison]);
        let log = net.log.clone();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node");
        let mut binary = Binary::start(&path);
        let wait = Duration::from_secs(30);
        assert!(matches!(binary.call(request::Value::Info(RequestInfo::default()), wait), Some(response::Value::Info(_))));
        assert!(matches!(binary.call(request::Value::InitChain(init()), wait), Some(response::Value::InitChain(_))), "{}", binary.errors.lock().unwrap());
        for request in &log {
            assert!(matches!(binary.call(request::Value::FinalizeBlock(request.clone()), wait), Some(response::Value::FinalizeBlock(_))), "height {}", request.height);
            assert!(matches!(binary.call(request::Value::Commit(RequestCommit {}), wait), Some(response::Value::Commit(_))));
        }
        // (The proposal is not put to the binary: it compares proposals with
        // this machine's clock, and these blocks are dated by the test. The
        // test above shows that a node accepts the block as a proposal.)
        let answer = binary.call(request::Value::FinalizeBlock(stuck.clone()), Duration::from_secs(3));
        assert!(answer.is_none(), "the decided block was answered: {answer:?}");
        let code = binary.exit(Duration::from_secs(15));
        let errors = binary.errors.lock().unwrap().clone();
        assert_eq!(code, Some(1), "{errors}");
        let lines: Vec<&str> = errors.lines().collect();
        let at = lines.iter().position(|line| *line == FAILED_BLOCK_LINE).unwrap_or_else(|| panic!("{errors}"));
        let said = lines[at + 1];
        assert!(said.starts_with(&format!("The decided block {} (hash {}) failed a check of this program and was not executed: REHEARSAL FAULT", h + 1, hex::encode(&stuck.hash))), "{said}");
        assert!(said.contains(&format!("The state of this node is at height {h} with the root {}", hex::encode(root))), "{said}");
        assert!(!errors.lines().any(|line| line.starts_with("STOPPED")), "{errors}");
        drop(binary);
        // Nothing was saved of that block; the recount passes at some height
        // at or below the block before (the node's last snapshot).
        let (code, report, errors) = node(&path, &["--audit"]);
        assert_eq!(code, Some(0), "{errors}");
        let report: Value = serde_json::from_str(&report).unwrap();
        assert!(report["height"].as_str().unwrap().parse::<u64>().unwrap() <= h);
    }
}
