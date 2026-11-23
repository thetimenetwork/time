//! Upgrades as a node lives them, through the ABCI calls CometBFT makes:
//! two programs from one source, one of which implements a version 5; the
//! activating block and the stop after it; restarts at the boundary; the
//! reserved kind 81; `--stop-after-height`; state sync across an activation;
//! what a wallet is served; and the node binary's exit code 4.
//!
//! `upgrade.rs` tests the rules on the engine; `src/upgrade.rs` tests the
//! pure state machine at its exact boundaries.
mod common;
use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    time::Duration,
};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use prost::Message;
use timecurrency_node::ledger::Account;
use timecurrency_v5::{
    app::{App, StopCause, UpgradeOptions, UpgradeWatch},
    engine,
    rules::{self, Versions},
    statesync::NodeOptions,
    transport::BatchCheck,
    upgrade,
};

const SECOND: u64 = pos::SECOND;
const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const REJECT: i32 = response_process_proposal::ProposalStatus::Reject as i32;
/// The specification hash the test version 5 goes by.
const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// A program that implements version 4 only: release 1.
fn old() -> Versions {
    Versions::new([(4, rules::SPEC_4.to_string())]).unwrap()
}
/// A program from the same source that also implements a version 5.
fn new() -> Versions {
    Versions::new([(4, rules::SPEC_4.to_string()), (5, SPEC_5.to_string())]).unwrap()
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
fn query(app: &App, path: &str, data: &Value) -> Value {
    let response = app.query(RequestQuery { data: serde_json::to_vec(data).unwrap().into(), path: path.into(), height: 0, prove: false });
    assert_eq!(response.code, 0, "{}", response.log);
    serde_json::from_slice(&response.value).unwrap()
}
fn entry_value(view: &Value, key: &[u8]) -> Option<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let entry = view["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key_hex"] == hex::encode(key).as_str())
        .unwrap_or_else(|| panic!("no entry for {}", String::from_utf8_lossy(key)));
    entry["value_b64"].as_str().map(|text| STANDARD.decode(text).unwrap())
}
fn account(app: &App, id: u64) -> Account {
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()] }));
    serde_json::from_slice(&entry_value(&view, &engine::account_key(id)).expect("account exists")).unwrap()
}
fn check(app: &App, tx: &[u8]) -> ResponseCheckTx {
    app.check_batch(vec![RequestCheckTx { tx: tx.to_vec().into(), r#type: 0 }]).pop().unwrap()
}
/// The owner of validator `owner` supports version 5 starting at `activate`.
fn support(app: &App, owner: u64, activate: u64, spec: &str) -> Vec<u8> {
    extension(
        &account(app, owner),
        owner as u8 + 1,
        upgrade::SIGNAL,
        json!({"activate_elapsed_micros": activate.to_string(), "spec": spec, "version": "5"}),
    )
}
fn withdraw(app: &App, owner: u64) -> Vec<u8> {
    extension(&account(app, owner), owner as u8 + 1, upgrade::SIGNAL, json!({}))
}
/// An action that carries the reserved kind 81.
fn switch() -> Vec<u8> {
    let payload = format!("{{\"spec\":\"{SPEC_5}\",\"version\":\"5\"}}");
    raw_action(&network_id(), upgrade::SWITCH, u64::MAX, 0, 0, 1, payload.as_bytes())
}

type Log = Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>;

struct Node {
    app: App,
    height: i64,
    elapsed: u64,
    log: Log,
}
fn options(versions: Versions, stop_after_height: Option<u64>) -> UpgradeOptions {
    UpgradeOptions { implemented: versions, stop_after_height }
}
fn open(path: &Path, versions: Versions) -> App {
    App::open_upgradable(path, None, NodeOptions::default(), options(versions, None)).unwrap()
}
impl Node {
    fn start(path: &Path, versions: Versions) -> Self {
        Self::start_with(path, NodeOptions::default(), options(versions, None))
    }
    fn start_with(path: &Path, node: NodeOptions, upgrade: UpgradeOptions) -> Self {
        let app = App::open_upgradable(path, None, node, upgrade).unwrap();
        app.try_init(init()).unwrap();
        Self { app, height: 0, elapsed: 0, log: Vec::new() }
    }
    /// A node opened on existing state, to be fed blocks from `height` on.
    fn resumed(app: App, height: i64, elapsed: u64) -> Self {
        Self { app, height, elapsed, log: Vec::new() }
    }
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: timestamp(genesis_v5().ledger.genesis_time_micros + (self.elapsed + delta) as i64),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: last_commit(height),
            ..Default::default()
        }
    }
    /// What this node proposes of `txs` for the next block.
    fn proposes(&self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let request = self.request(delta, vec![]);
        self.app
            .prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: 1 << 20,
                txs: txs.into_iter().map(Into::into).collect(),
                height: request.height,
                time: request.time,
                ..Default::default()
            })
            .txs
            .into_iter()
            .map(|tx| tx.to_vec())
            .collect()
    }
    /// A block decided by the network: finalize and commit, as on any node.
    fn decided(&mut self, request: &RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let response = self.app.try_finalize(request.clone()).unwrap_or_else(|error| panic!("height {}: {error:#}", request.height));
        self.app.try_commit().unwrap();
        self.height = request.height;
        let micros = request.time.as_ref().unwrap();
        self.elapsed = (micros.seconds * 1_000_000 + i64::from(micros.nanos / 1000) - genesis_v5().ledger.genesis_time_micros) as u64;
        self.log.push((request.clone(), response.clone()));
        response
    }
    /// This node proposes `txs`, validates the proposal and commits it.
    /// Every transaction offered must be kept.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> ResponseFinalizeBlock {
        let kept = self.proposes(delta, txs.clone());
        assert_eq!(kept, txs, "the proposer left a transaction out at height {}", self.height + 1);
        let request = self.request(delta, kept);
        assert_eq!(self.app.process_proposal(proposal(&request)).status, ACCEPT, "height {}", request.height);
        self.decided(&request)
    }
    fn account(&self, id: u64) -> Account {
        account(&self.app, id)
    }
    fn support(&self, owner: u64, activate: u64) -> Vec<u8> {
        support(&self.app, owner, activate, SPEC_5)
    }
    fn state(&self) -> Option<upgrade::State> {
        let view = query(&self.app, "/v4/state", &json!({"include_upgrade": true}));
        entry_value(&view, upgrade::STATE_KEY).map(|row| upgrade::State::decode(&row).unwrap())
    }
    fn version(&self) -> u64 {
        self.app.info(RequestInfo::default()).app_version
    }
    /// Blocks until every validator owner can pay fees.
    fn funded(mut self) -> Self {
        self.block(SECOND, vec![]);
        while !(0..4).all(|id| self.account(id).balance >= 5 * SECOND) {
            assert!(self.height < 40, "validator owners were not funded");
            self.block(60 * SECOND, vec![]);
        }
        self
    }
    /// All four owners signal for a start `ahead` from now; the block
    /// schedules the plan. Returns the start time.
    fn schedule(&mut self, ahead: u64) -> u64 {
        let activate = self.elapsed + ahead;
        let signals = (0..4).map(|owner| self.support(owner, activate)).collect();
        self.block(SECOND, signals);
        let plan = self.state().unwrap().plan.expect("scheduled");
        assert_eq!((plan.version, plan.activate_elapsed_micros, plan.scheduled_elapsed_micros), (5, activate, self.elapsed));
        activate
    }
}

/// Whether a consensus call is still unanswered after a moment. The thread
/// that made it waits until the test process ends, as it does on a node.
fn unanswered<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> bool {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(call());
    });
    matches!(receiver.recv_timeout(Duration::from_millis(400)), Err(mpsc::RecvTimeoutError::Timeout))
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upgrade-state.fixture.json")
}

/// The rows a client proves, as this engine serves them: `upgrade/state`
/// absent, with entries only, with a scheduled plan, and after an
/// activation, each with the answer to `/v4/state` that proves it, the
/// application hash to put in the certifying header, and `/status`.
fn fixture() -> Value {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(&dir.path().join("node"), new()).funded();
    let request = json!({"include_upgrade": true});
    let mut cases = Vec::new();
    let mut capture = |node: &Node, name: &str, what: &str| {
        let view = query(&node.app, "/v4/state", &request);
        let row = entry_value(&view, upgrade::STATE_KEY);
        let meta: Value = serde_json::from_slice(&entry_value(&view, b"meta").unwrap()).unwrap();
        let (_, response) = node.log.last().unwrap();
        assert_eq!(hex::encode(&response.app_hash), view["root"].as_str().unwrap());
        cases.push(json!({
            "name": name,
            "what": what,
            "height": node.height.to_string(),
            "app_hash": view["root"],
            "protocol_version": meta["protocol_version"],
            "next_block_version": response.consensus_param_updates.as_ref().unwrap().version.as_ref().unwrap().app.to_string(),
            "elapsed_micros": node.elapsed.to_string(),
            "request": request,
            "response": view,
            "upgrade_state_utf8": row.as_ref().map(|row| String::from_utf8(row.clone()).unwrap()),
            "upgrade_state": row.as_ref().map(|row| serde_json::from_slice::<Value>(row).unwrap()),
            "status_upgrade": query(&node.app, "/status", &json!(null))["upgrade"],
        }));
    };
    capture(&node, "absent", "Nobody has signalled: the row is proven absent.");
    let activate = node.elapsed + 300 * SECOND;
    let first = node.support(0, activate);
    let withdraws_later = node.support(2, activate);
    node.block(SECOND, vec![first.clone(), node.support(1, activate), withdraws_later]);
    let withdrawal = withdraw(&node.app, 2);
    node.block(SECOND, vec![withdrawal.clone()]);
    capture(&node, "entries_only", "Two validators support a plan and a third has withdrawn: entries of both forms, no plan.");
    node.block(SECOND, vec![node.support(2, activate), node.support(3, activate)]);
    capture(&node, "scheduled", "All four validators support the plan: it is scheduled.");
    node.block(activate - node.elapsed, vec![]);
    let activated_key = upgrade::activated_key(5);
    let proof = query(&node.app, "/compact-proof", &json!([hex::encode(&activated_key)]));
    capture(&node, "activated", "The activating block: the row is gone, the metadata names version 5, and the next header carries it.");
    node.block(SECOND, vec![]);
    capture(&node, "after_activation", "The first block under version 5.");
    json!({
        "description": "Proven upgrade/state rows from the engine (v5/tests/upgrade_node.rs, V5_EXPORT_UPGRADE_FIXTURE=1). Each case holds the answer to /v4/state with include_upgrade, whose root is the application hash of the block at `height` (the header of the next block carries it).",
        "network_id": network_id(),
        "chain_id": genesis_v5().ledger.chain_id,
        "genesis_time_micros": genesis_v5().ledger.genesis_time_micros.to_string(),
        "profile": "laboratory",
        "state_key_utf8": "upgrade/state",
        "state_key_hex": hex::encode(upgrade::STATE_KEY),
        "implemented_by_the_test_program": [{"version": "4", "spec": rules::SPEC_4}, {"version": "5", "spec": SPEC_5}],
        "release_1_implements": [{"version": "4", "spec": rules::SPEC_4}],
        "plan": {"version": "5", "spec": SPEC_5, "activate_elapsed_micros": activate.to_string()},
        "actions": {
            "kind": upgrade::SIGNAL,
            "support": {"from": "0", "signer_seed_hex": hex::encode([1u8; 32]), "payload_utf8": String::from_utf8(upgrade::Proposal { version: 5, activate_elapsed_micros: activate, spec: SPEC_5.into() }.payload()).unwrap(), "action_hex": hex::encode(&first)},
            "withdraw": {"from": "2", "signer_seed_hex": hex::encode([3u8; 32]), "payload_utf8": "{}", "action_hex": hex::encode(&withdrawal)},
        },
        "activated_row": {
            "key_hex": hex::encode(&activated_key),
            "at_height": proof["height"],
            "root": proof["root"],
            "entries": proof["entries"],
        },
        "cases": cases,
    })
}

/// Writes the fixture the verifier and SDK tests read, or checks that the
/// committed one is what this engine produces. Run with
/// `V5_EXPORT_UPGRADE_FIXTURE=1` after any change to the formats (a path as
/// the value writes a second copy there).
#[test]
fn the_fixture_for_clients_is_what_this_engine_produces() {
    let produced = fixture();
    // The four states a client must tell apart are all there.
    let cases = produced["cases"].as_array().unwrap();
    let by_name = |name: &str| cases.iter().find(|case| case["name"] == name).unwrap();
    assert!(by_name("absent")["upgrade_state"].is_null());
    let entries = by_name("entries_only");
    assert!(entries["upgrade_state"]["plan"].is_null());
    assert_eq!(entries["upgrade_state"]["signals"].as_array().unwrap().len(), 3);
    assert!(entries["upgrade_state"]["signals"][2].get("version").is_none(), "a withdrawn entry");
    assert_eq!(entries["status_upgrade"]["scheduled"], Value::Null);
    let scheduled = by_name("scheduled");
    assert_eq!(scheduled["upgrade_state"]["plan"]["version"], "5");
    assert_eq!(scheduled["status_upgrade"]["scheduled"], scheduled["upgrade_state"]["plan"]);
    assert_eq!(scheduled["status_upgrade"]["implements_scheduled"], true);
    assert_eq!((scheduled["protocol_version"].as_str(), scheduled["next_block_version"].as_str()), (Some("4"), Some("4")));
    let activated = by_name("activated");
    assert!(activated["upgrade_state"].is_null());
    assert_eq!((activated["protocol_version"].as_str(), activated["next_block_version"].as_str()), (Some("5"), Some("5")));
    assert_eq!(by_name("after_activation")["protocol_version"], "5");
    let text = serde_json::to_vec_pretty(&produced).unwrap();
    match std::env::var("V5_EXPORT_UPGRADE_FIXTURE") {
        Ok(target) => {
            std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
            std::fs::write(fixture_path(), &text).unwrap();
            if target != "1" {
                let target = PathBuf::from(target);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(target, &text).unwrap();
            }
        }
        Err(_) => {
            let committed: Value = serde_json::from_slice(&std::fs::read(fixture_path()).expect("the committed fixture")).unwrap();
            assert_eq!(committed, produced, "the committed fixture is stale: export it again");
        }
    }
}

/// Two programs from one source, one given version 5 in its list. They
/// compute the same blocks, the activating block included, byte for byte.
/// Then the old one stops: it answers nothing for the next height, admits
/// nothing, and refuses to start again; the new one continues, also from
/// the old one's snapshot.
#[test]
fn the_old_program_computes_the_same_last_block_and_stops_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let (new_path, old_path) = (dir.path().join("new"), dir.path().join("old"));
    let mut newer = Node::start(&new_path, new()).funded();
    let mut older = Node::start(&old_path, old());
    for (request, response) in newer.log.clone() {
        assert_eq!(older.decided(&request), response);
    }
    // The old program admits no support signal: no version 5 is in its list.
    let activate = newer.elapsed + 200 * SECOND;
    let signal = newer.support(0, activate);
    let refused = check(&older.app, &signal);
    assert!(refused.code == 1 && refused.log.contains("does not implement"), "{}", refused.log);
    assert!(older.proposes(SECOND, vec![signal.clone()]).is_empty(), "the old program proposed a signal");
    assert_eq!(check(&newer.app, &signal).code, 0);
    // It executes blocks that carry them all the same: the plan is consensus.
    newer.schedule(200 * SECOND);
    let (request, response) = newer.log.last().unwrap().clone();
    assert_eq!(older.app.process_proposal(proposal(&request)).status, ACCEPT);
    assert_eq!(older.decided(&request), response);
    assert_eq!(older.state(), newer.state());
    // While the plan waits, each says whether it implements it.
    let status = |node: &Node| query(&node.app, "/status", &json!(null))["upgrade"].clone();
    assert_eq!(status(&newer)["implements_scheduled"], true);
    assert_eq!(status(&older)["implements_scheduled"], false);
    assert_eq!(status(&older)["implemented"], json!([{"spec": rules::SPEC_4, "version": "4"}]));
    assert_eq!(status(&older)["scheduled"]["version"], "5");
    let mut watch = UpgradeWatch::default();
    let warned = watch.poll(&older.app.upgrade_status().unwrap().unwrap(), std::time::Instant::now()).unwrap();
    assert!(warned.starts_with("WARNING") && warned.contains("DOES NOT IMPLEMENT"), "{warned}");
    // Blocks before the start time: nothing changes for either.
    for _ in 0..3 {
        newer.block(60 * SECOND, vec![]);
        let (request, response) = newer.log.last().unwrap().clone();
        assert_eq!(older.decided(&request), response);
        assert!(older.app.stop().is_none());
        assert_eq!((older.version(), newer.version()), (4, 4));
    }
    older.app.snapshot().unwrap();
    let before = (older.height, older.elapsed);
    // The activating block: the first dated at or after the start time.
    newer.block(60 * SECOND, vec![]);
    assert!(newer.elapsed >= activate);
    let (activating, response) = newer.log.last().unwrap().clone();
    assert_eq!(response.consensus_param_updates.as_ref().unwrap().version.as_ref().unwrap().app, 5);
    assert_eq!(older.app.process_proposal(proposal(&activating)).status, ACCEPT);
    let same = older.app.try_finalize(activating.clone()).unwrap();
    assert_eq!(same.encode_to_vec(), response.encode_to_vec(), "the old program's answer to the last block differs");
    assert!(older.app.stop().is_none(), "stopped before the commit");
    older.app.try_commit().unwrap();
    assert_eq!(older.app.head().unwrap(), newer.app.head().unwrap(), "the same state, byte for byte");
    // After Commit(h) the old program has stopped.
    let cause = older.app.stop().expect("stopped after the activating block");
    let h = activating.height as u64;
    assert_eq!(
        cause,
        StopCause::Upgrade(upgrade::NotRunnable {
            version: 5,
            spec: Some(SPEC_5.into()),
            from_height: Some(h + 1),
            head: h,
            implemented: "version 4".into(),
            other_rules: false,
        })
    );
    assert_eq!(cause.first_line(), "STOPPED FOR UPGRADE");
    let text = cause.explain(Some(h));
    assert!(text.contains(&format!("protocol version 5 (spec {SPEC_5}) from height {}", h + 1)), "{text}");
    assert!(text.contains(&format!("The state at height {h} is saved and valid")) && text.contains("Delete nothing"), "{text}");
    // It admits nothing and judges nothing for h + 1: neither accept nor reject.
    let refused = check(&older.app, &transfer(&newer.account(0), 1, 5, 1));
    assert!(refused.code == 1 && refused.log.contains("STOPPED FOR UPGRADE"), "{}", refused.log);
    newer.block(SECOND, vec![]);
    let (next, next_response) = newer.log.last().unwrap().clone();
    assert!(older.app.try_finalize(next.clone()).is_err(), "the old program executed a block under version 5");
    assert_eq!(older.app.head().unwrap().unwrap().0, h, "the head moved");
    // Queries still answer, and say what is in force.
    assert_eq!(older.version(), 5);
    // It saves the state at h. Started again, it is stopped before it serves.
    older.app.snapshot().unwrap();
    drop(older);
    let again = open(&old_path, old());
    assert_eq!(again.stop(), Some(cause.clone()));
    assert!(again.stop_ready());
    drop(again);
    // A program with other rules under the same number stops too.
    let other = Versions::new([(4, rules::SPEC_4.to_string()), (5, "66".repeat(32))]).unwrap();
    let wrong = open(&old_path, other);
    match wrong.stop() {
        Some(StopCause::Upgrade(reason)) => {
            assert!(reason.other_rules && reason.spec.as_deref() == Some(SPEC_5));
            assert!(reason.explain().contains("under another specification"));
        }
        other => panic!("{other:?}"),
    }
    drop(wrong);
    // The new program continues from the old program's snapshot.
    let mut upgraded = Node::resumed(open(&old_path, new()), h as i64, 0);
    assert!(upgraded.app.stop().is_none());
    assert_eq!(upgraded.decided(&next), next_response);
    assert_eq!(upgraded.app.head().unwrap(), newer.app.head().unwrap());
    assert_eq!(upgraded.version(), 5);
    upgraded.app.snapshot().unwrap();
    drop(upgraded);
    // The old program restarted from a snapshot before h replays to h and
    // stops there again; one whose snapshot is after h does not start.
    let after = open(&old_path, old());
    assert!(matches!(after.stop(), Some(StopCause::Upgrade(reason)) if reason.head == h + 1));
    drop(after);
    let replay_path = dir.path().join("replay");
    let mut replay = Node::start(&replay_path, old());
    for (request, response) in &newer.log[..before.0 as usize] {
        assert_eq!(&replay.decided(request), response);
    }
    replay.app.snapshot().unwrap();
    drop(replay);
    let mut replay = Node::resumed(open(&replay_path, old()), before.0, before.1);
    assert!(replay.app.stop().is_none());
    assert_eq!(replay.decided(&activating), response);
    assert_eq!(replay.app.stop(), Some(cause));
    // What CometBFT sees of a program that stopped after Commit(h): no
    // answer to anything it asks for h + 1. (These calls never return; they
    // are made last because they keep the node's state directory open.)
    for call in 0..4 {
        let (app, next) = (replay.app.clone(), next.clone());
        assert!(
            unanswered(move || match call {
                0 => app.process_proposal(proposal(&next)).encode_to_vec(),
                1 => app.prepare_proposal(RequestPrepareProposal { height: next.height, time: next.time, max_tx_bytes: 1024, ..Default::default() }).encode_to_vec(),
                2 => app.finalize_block(next).encode_to_vec(),
                _ => app.commit().encode_to_vec(),
            }),
            "the stopped program answered consensus call {call}"
        );
    }
    assert_eq!(replay.app.head().unwrap().unwrap().0, h, "the head moved");
}

/// A proposal that carries the reserved kind 81 is rejected and the node
/// goes on. A decided block that carries it is not executed: the node stops
/// with its head at the block before.
#[test]
fn kind_81_is_refused_rejected_in_a_proposal_and_stops_the_node_in_a_decided_block() {
    let dir = tempfile::tempdir().unwrap();
    for versions in [old(), new()] {
        let path = dir.path().join(format!("node-{}", versions.highest()));
        let mut node = Node::start(&path, versions.clone()).funded();
        // Told by the kind byte alone, whatever else the bytes are.
        let mut garbage = switch();
        garbage.truncate(60);
        for tx in [switch(), garbage.clone()] {
            let refused = check(&node.app, &tx);
            assert!(refused.code == 1, "admitted");
        }
        assert!(check(&node.app, &switch()).log.contains("kind 81 is reserved"));
        // Never proposed.
        let payment = transfer(&node.account(0), 1, 5, 1000);
        assert_eq!(node.proposes(SECOND, vec![switch(), payment.clone()]), vec![payment.clone()]);
        // A proposal with it is rejected, and the node goes on.
        let proposed = node.request(SECOND, vec![payment.clone(), switch()]);
        assert_eq!(node.app.process_proposal(proposal(&proposed)).status, REJECT);
        assert!(node.app.stop().is_none(), "one proposer stopped the node");
        node.block(SECOND, vec![payment]);
        // A decided block with it: nothing is executed, the node stops.
        let head = node.app.head().unwrap();
        let decided = node.request(SECOND, vec![transfer(&node.account(1), 2, 5, 1000), switch()]);
        assert!(node.app.try_finalize(decided.clone()).is_err());
        let height = decided.height as u64;
        assert_eq!(node.app.stop(), Some(StopCause::Switch { height }));
        assert!(node.app.stop_ready(), "no answer is in progress");
        assert_eq!(node.app.head().unwrap(), head, "the head moved");
        assert_eq!(node.app.stop().unwrap().first_line(), "STOPPED AT A SWITCH");
        let text = node.app.stop().unwrap().explain(Some(height - 1));
        assert!(text.contains(&format!("block {height} carries a rule switch")) && text.contains(&format!("The state at height {} is saved", height - 1)), "{text}");
        assert!(check(&node.app, &garbage).log.contains("STOPPED AT A SWITCH"));
        // Its state is the block before; started again it runs, and stops
        // again when the consensus engine hands it the block, which it
        // never answers.
        node.app.snapshot().unwrap();
        let (at, elapsed) = (node.height, node.elapsed);
        drop(node);
        let again = Node::resumed(open(&path, versions), at, elapsed);
        assert!(again.app.stop().is_none());
        assert_eq!(again.app.head().unwrap(), head);
        let app = again.app.clone();
        assert!(unanswered(move || app.finalize_block(decided).encode_to_vec()));
        assert_eq!(again.app.stop(), Some(StopCause::Switch { height }));
        assert_eq!(again.app.head().unwrap(), head);
    }
}

/// `--stop-after-height H`: stop after H, start at H, start above H.
#[test]
fn a_node_told_to_stop_after_a_height_stops_there_and_judges_nothing_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node");
    let asked = |height: u64| options(old(), Some(height));
    let mut node = Node::start_with(&path, NodeOptions::default(), asked(4));
    assert_eq!(query(&node.app, "/status", &json!(null))["upgrade"]["stop_after_height"], "4");
    for _ in 0..3 {
        node.block(SECOND, vec![]);
        assert!(node.app.stop().is_none());
    }
    // Block 4: executed and committed like any other, then the node stops.
    let request = node.request(SECOND, vec![]);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, ACCEPT);
    node.app.try_finalize(request.clone()).unwrap();
    assert!(node.app.stop().is_none());
    node.app.try_commit().unwrap();
    assert_eq!(node.app.stop(), Some(StopCause::Asked { height: 4 }));
    // The answer to that Commit is still to be written when the calls are
    // made directly; the transport reports it (see the binary test).
    assert!(!node.app.stop_ready());
    assert_eq!(node.app.stop().unwrap().first_line(), "STOPPED AS ASKED");
    assert!(node.app.stop().unwrap().explain(Some(4)).contains("--stop-after-height 4"));
    assert_eq!(node.app.head().unwrap().unwrap().0, 4);
    node.height = 4;
    node.elapsed += SECOND;
    assert!(check(&node.app, &transfer(&node.account(0), 1, 5, 1)).log.contains("STOPPED AS ASKED"));
    node.app.snapshot().unwrap();
    let (height, elapsed) = (node.height, node.elapsed);
    drop(node);
    // Started with its head at H, it is stopped at once.
    let at = App::open_upgradable(&path, None, NodeOptions::default(), asked(4)).unwrap();
    assert_eq!(at.stop(), Some(StopCause::Asked { height: 4 }));
    assert!(at.stop_ready());
    drop(at);
    // Started with its head above H, it does not start.
    let error = format!("{:#}", App::open_upgradable(&path, None, NodeOptions::default(), asked(3)).err().expect("opened above H"));
    assert!(error.contains("--stop-after-height 3") && error.contains("already at height 4"), "{error}");
    assert!(App::open_upgradable(&path, None, NodeOptions::default(), asked(0)).is_err());
    // With a later height, or without the flag, it goes on from the same state.
    let mut later = Node::resumed(App::open_upgradable(&path, None, NodeOptions::default(), asked(5)).unwrap(), height, elapsed);
    assert!(later.app.stop().is_none());
    later.block(SECOND, vec![]);
    assert_eq!(later.app.stop(), Some(StopCause::Asked { height: 5 }));
    later.app.snapshot().unwrap();
    drop(later);
    let mut free = Node::resumed(open(&path, old()), height + 1, elapsed + SECOND);
    assert!(free.app.stop().is_none());
    assert_eq!(query(&free.app, "/status", &json!(null))["upgrade"]["stop_after_height"], Value::Null);
    free.block(SECOND, vec![]);
    assert_eq!(free.app.head().unwrap().unwrap().0, 6);
    free.app.snapshot().unwrap();
    let (height, elapsed) = (free.height, free.elapsed);
    drop(free);
    // A node that has the flag does not judge any proposal for H + 1. (The
    // call never returns; it is made last because it keeps the state open.)
    let mut last = Node::resumed(App::open_upgradable(&path, None, NodeOptions::default(), asked(7)).unwrap(), height, elapsed);
    last.block(SECOND, vec![]);
    assert_eq!(last.app.stop(), Some(StopCause::Asked { height: 7 }));
    let judged = proposal(&last.request(SECOND, vec![]));
    let app = last.app.clone();
    assert!(unanswered(move || app.process_proposal(judged).status), "the node judged a proposal for H + 1");
    assert_eq!(last.app.head().unwrap().unwrap().0, 7);
}

/// A wallet reads a coming upgrade from a proven row, asked for like the
/// security row; a view that did not ask has no such entry.
#[test]
fn a_wallet_is_served_the_upgrade_row_or_the_proof_that_it_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(&dir.path().join("node"), new()).funded();
    let key = hex::encode(upgrade::STATE_KEY);
    let entry = |view: &Value| {
        view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == key.as_str()).cloned()
    };
    let asked = query(&node.app, "/v4/state", &json!({"include_upgrade": true}));
    let absent = entry(&asked).expect("an entry that proves absence");
    assert!(absent["value_b64"].is_null() && absent["proof"].is_object());
    assert!(entry(&query(&node.app, "/v4/state", &json!({}))).is_none());
    assert!(entry(&query(&node.app, "/v4/state", &json!({"include_upgrade": false, "ids": ["0"]}))).is_none());
    let status = query(&node.app, "/status", &json!(null));
    assert_eq!(
        status["upgrade"],
        json!({"implemented": [{"spec": rules::SPEC_4, "version": "4"}, {"spec": SPEC_5, "version": "5"}], "scheduled": null, "implements_scheduled": null, "stop_after_height": null})
    );
    assert_eq!(status["app_version"], "4");
    let activate = node.schedule(200 * SECOND);
    let asked = query(&node.app, "/v4/state", &json!({"include_upgrade": true, "ids": ["0"], "include_security": true}));
    let row = entry_value(&asked, upgrade::STATE_KEY).expect("the row");
    let state = upgrade::State::decode(&row).unwrap();
    assert_eq!(state.plan.as_ref().unwrap().activate_elapsed_micros, activate);
    assert_eq!(state.signals.len(), 4);
    let status = query(&node.app, "/status", &json!(null));
    assert_eq!(status["upgrade"]["scheduled"], serde_json::to_value(state.plan.as_ref().unwrap()).unwrap());
    assert_eq!(status["upgrade"]["implements_scheduled"], true);
    // A node that implements the plan logs it once.
    let mut watch = UpgradeWatch::default();
    let now = std::time::Instant::now();
    let status = node.app.upgrade_status().unwrap().unwrap();
    assert!(watch.poll(&status, now).unwrap().starts_with("Upgrade scheduled"));
    assert!(watch.poll(&status, now + Duration::from_secs(3600)).is_none());
    // One that does not warns at once and then every ten minutes.
    let mut blind = status.clone();
    blind.implements_scheduled = Some(false);
    let mut watch = UpgradeWatch::default();
    assert!(watch.poll(&blind, now).unwrap().starts_with("WARNING"));
    assert!(watch.poll(&blind, now + Duration::from_secs(599)).is_none());
    assert!(watch.poll(&blind, now + Duration::from_secs(600)).unwrap().starts_with("WARNING"));
    assert!(watch.poll(&blind, now + Duration::from_secs(601)).is_none());
    // After the activation the status names the version in force.
    node.block(activate - node.elapsed, vec![]);
    assert_eq!(node.version(), 5);
    node.block(SECOND, vec![]);
    let status = query(&node.app, "/status", &json!(null));
    assert_eq!(status["app_version"], "5");
    assert_eq!(status["upgrade"]["scheduled"], Value::Null);
    // Asked for a height: the version in force at that height, with that height's root. The block
    // before the last one is the activating block, whose state already names version 5; the one before
    // that still ran, and names, version 4.
    let at = |height: i64| {
        let response = node.app.query(RequestQuery { data: serde_json::to_vec(&json!(null)).unwrap().into(), path: "/status".into(), height, prove: false });
        assert_eq!(response.code, 0, "{}", response.log);
        serde_json::from_slice::<Value>(&response.value).unwrap()
    };
    let (activated, before) = (at(node.height - 1), at(node.height - 2));
    assert_eq!((activated["height"].as_str(), activated["app_version"].as_str()), (Some((node.height - 1).to_string().as_str()), Some("5")));
    assert_eq!((before["height"].as_str(), before["app_version"].as_str()), (Some((node.height - 2).to_string().as_str()), Some("4")));
    assert_ne!(before["root"], activated["root"]);
    assert!(entry_value(&query(&node.app, "/v4/state", &json!({"include_upgrade": true})), upgrade::STATE_KEY).is_none());
}

/// The node binary: exit code 4 and its first lines, before the ABCI socket
/// opens; `--audit` prints the real version and refuses a head the program
/// does not implement.
#[test]
fn the_node_binary_ends_with_code_4_and_says_why() {
    let run = |path: &Path, extra: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5"))
            .args(["--devnet", "--db"])
            .arg(path)
            .args(extra)
            .output()
            .unwrap();
        (output.status.code(), String::from_utf8_lossy(&output.stdout).to_string(), String::from_utf8_lossy(&output.stderr).to_string())
    };
    let version = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5")).arg("--version").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        format!(
            "time-node-v5 {} protocol=4{} devnet-only publicLaunchAllowed=false",
            env!("CARGO_PKG_VERSION"),
            // A rehearsal build says so in its version line.
            if rules::REHEARSAL { " rehearsal=5" } else { "" }
        )
    );
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.9.0");
    let dir = tempfile::tempdir().unwrap();
    // A chain that has signals and a scheduled plan: the release binary
    // audits it, and reports the plan.
    let path = dir.path().join("node");
    let mut node = Node::start(&path, new()).funded();
    let activate = node.schedule(200 * SECOND);
    node.app.snapshot().unwrap();
    let (height, elapsed, log) = (node.height, node.elapsed, node.log.clone());
    drop(node);
    let (code, report, errors) = run(&path, &["--audit"]);
    assert_eq!(code, Some(0), "{errors}");
    let report: Value = serde_json::from_str(&report).unwrap();
    assert_eq!(report["protocol"], "4");
    assert_eq!(report["upgrade_scheduled"]["activate_elapsed_micros"], activate.to_string());
    assert_eq!(report["upgrade_signals"], "4");
    // --stop-after-height at the head, above it, and malformed.
    let (code, _, errors) = run(&path, &["--stop-after-height", &height.to_string()]);
    assert_eq!(code, Some(4), "{errors}");
    assert!(errors.lines().any(|line| line == "STOPPED AS ASKED"), "{errors}");
    assert!(errors.contains(&format!("The state at height {height} is saved and valid")), "{errors}");
    let (code, _, errors) = run(&path, &["--stop-after-height", &(height - 1).to_string()]);
    assert_eq!(code, Some(1), "{errors}");
    assert!(errors.contains("already at height") && !errors.lines().any(|line| line.starts_with("STOPPED")), "{errors}");
    for bad in ["0", "-1", "x", "1.5", "01"] {
        let (code, _, errors) = run(&path, &["--stop-after-height", bad]);
        assert_eq!(code, Some(1), "{bad}: {errors}");
    }
    assert_eq!(run(&path, &["--audit", "--stop-after-height", "5"]).0, Some(1));
    // The chain activates version 5, which the release binary lacks.
    let mut node = Node::resumed(open(&path, new()), height, elapsed);
    node.log = log;
    node.block(activate - node.elapsed, vec![]);
    assert_eq!(node.version(), 5);
    node.app.snapshot().unwrap();
    let h = node.height;
    drop(node);
    for extra in [&[][..], &["--audit"][..], &["--stop-after-height", "1"][..]] {
        let (code, out, errors) = run(&path, extra);
        assert_eq!(code, Some(4), "{extra:?}: {errors}");
        assert!(errors.lines().any(|line| line == "STOPPED FOR UPGRADE"), "{errors}");
        assert!(errors.contains(&format!("This chain runs protocol version 5 (spec {SPEC_5}) from height {}", h + 1)), "{errors}");
        // A rehearsal build has a version 5 of its own, under another hash
        // than the one this chain activated: it stops all the same.
        let own = if rules::REHEARSAL {
            "This program implements versions 4 to 5, and version 5 under another specification."
        } else {
            "This program implements version 4."
        };
        assert!(errors.contains(own) && errors.contains("Delete nothing."), "{errors}");
        assert!(!errors.contains("ABCI listening") && out.is_empty(), "{errors}");
    }
}

/// State sync and upgrades together. A snapshot taken after an activation
/// restores on a program that implements the version, which then follows
/// the chain. A program that does not implement it, or implements the
/// number under another specification, installs nothing: its state, in
/// memory and on disk, is what it was. A snapshot from before the
/// activation restores on any program, and the old one then executes the
/// activating block and stops like a node that was there all along.
#[test]
fn a_snapshot_under_a_version_the_program_lacks_is_not_installed() {
    const OFFER_ACCEPT: i32 = response_offer_snapshot::Result::Accept as i32;
    const OFFER_REJECT: i32 = response_offer_snapshot::Result::Reject as i32;
    const CHUNK_ACCEPT: i32 = response_apply_snapshot_chunk::Result::Accept as i32;
    const CHUNK_ABORT: i32 = response_apply_snapshot_chunk::Result::Abort as i32;
    const OFFER_ABORT: i32 = response_offer_snapshot::Result::Abort as i32;
    let serving = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let dir = tempfile::tempdir().unwrap();
    let mut source = Node::start_with(&dir.path().join("source"), serving, options(new(), None)).funded();
    let step = |node: &mut Node, delta: u64, txs: Vec<Vec<u8>>| {
        node.block(delta, txs);
        node.app.write_sync_snapshot().unwrap();
    };
    // A plan is scheduled; a snapshot is taken while it waits; it
    // activates; a snapshot is taken after it.
    while source.height % 10 != 8 {
        step(&mut source, SECOND, vec![]);
    }
    let activate = source.elapsed + 400 * SECOND;
    let signals = (0..4).map(|owner| source.support(owner, activate)).collect();
    step(&mut source, SECOND, signals);
    step(&mut source, SECOND, vec![]);
    let before = source.height as u64;
    assert!(before % 10 == 0 && source.state().unwrap().plan.is_some());
    step(&mut source, 200 * SECOND, vec![]);
    step(&mut source, 250 * SECOND, vec![]);
    assert_eq!(source.version(), 5);
    let activating = source.height as u64;
    while source.height % 10 != 0 {
        step(&mut source, SECOND, vec![]);
    }
    let after = source.height as u64;
    for _ in 0..3 {
        step(&mut source, SECOND, vec![]);
    }
    let offered = |height: u64| -> (Snapshot, Vec<Vec<u8>>, Vec<u8>) {
        let snapshot = source.app.list_snapshots().snapshots.into_iter().find(|snapshot| snapshot.height == height).expect("offered");
        let chunks = (0..snapshot.chunks)
            .map(|chunk| source.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height, format: snapshot.format, chunk }).chunk.to_vec())
            .collect();
        (snapshot, chunks, source.log[height as usize - 1].1.app_hash.to_vec())
    };
    let restore = |app: &App, height: u64| -> i32 {
        let (snapshot, chunks, app_hash) = offered(height);
        assert_eq!(app.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot), app_hash: app_hash.into() }).result, OFFER_ACCEPT);
        let mut last = CHUNK_ACCEPT;
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(last, CHUNK_ACCEPT, "chunk {index}");
            let answer = app.apply_snapshot_chunk(RequestApplySnapshotChunk { index: index as u32, chunk: chunk.clone().into(), sender: format!("peer-{index}") });
            // Whatever the outcome, no peer is at fault: the snapshot is authentic.
            assert!(answer.reject_senders.is_empty() && answer.refetch_chunks.is_empty());
            last = answer.result;
        }
        last
    };
    // 1. The program that implements version 5 restores the later snapshot
    // and follows the chain from it.
    let joined = open(&dir.path().join("joined"), new());
    assert_eq!(restore(&joined, after), CHUNK_ACCEPT);
    let mut joined = Node::resumed(joined, after as i64, 0);
    assert!(joined.app.stop().is_none());
    assert_eq!(joined.version(), 5);
    for (request, response) in &source.log[after as usize..] {
        assert_eq!(&joined.decided(request), response);
    }
    assert_eq!(joined.app.head().unwrap(), source.app.head().unwrap());
    // 2. Release 1, with no state: nothing is installed, it is not stopped,
    // and it is still empty after a restart.
    let empty_path = dir.path().join("empty");
    let empty = open(&empty_path, old());
    assert_eq!(restore(&empty, after), CHUNK_ABORT);
    assert!(empty.head().unwrap().is_none() && empty.stop().is_none());
    drop(empty);
    assert!(open(&empty_path, old()).head().unwrap().is_none(), "a state the program cannot run was left on disk");
    // The same for a program with other rules under the number 5.
    let other = open(&dir.path().join("other"), Versions::new([(4, rules::SPEC_4.to_string()), (5, "66".repeat(32))]).unwrap());
    assert_eq!(restore(&other, after), CHUNK_ABORT);
    assert!(other.head().unwrap().is_none());
    // 3. Release 1 holding a state it restored and has not built on: the
    // snapshot from before the activation. Offered the later one, under a
    // version it lacks, it keeps exactly the state it had, in memory and on
    // disk.
    let restored_path = dir.path().join("restored");
    let restored = open(&restored_path, old());
    assert_eq!(restore(&restored, before), CHUNK_ACCEPT);
    let held = restored.head().unwrap();
    assert_eq!(held.map(|(height, _)| height), Some(before));
    assert_eq!(restore(&restored, after), CHUNK_ABORT);
    assert_eq!(restored.head().unwrap(), held);
    assert!(restored.stop().is_none());
    drop(restored);
    let reopened = open(&restored_path, old());
    assert_eq!(reopened.head().unwrap(), held, "the state on disk changed");
    let mut reopened = Node::resumed(reopened, before as i64, 0);
    assert_eq!(&reopened.decided(&source.log[before as usize].0), &source.log[before as usize].1, "the node no longer runs on its own state");
    // A node that built its state by executing blocks takes no snapshot at
    // all, under any version: it is refused when it is offered.
    let mut behind = Node::start(&dir.path().join("behind"), old());
    for (request, response) in &source.log[..5] {
        assert_eq!(&behind.decided(request), response);
    }
    let held = behind.app.head().unwrap();
    let (snapshot, _, app_hash) = offered(after);
    assert_eq!(behind.app.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot), app_hash: app_hash.into() }).result, OFFER_ABORT);
    assert_eq!(behind.app.head().unwrap(), held);
    assert!(behind.app.stop().is_none());
    assert_eq!(&behind.decided(&source.log[5].0), &source.log[5].1, "the node no longer runs on its own state");
    // 4. The snapshot from before the activation restores on release 1,
    // plan and signals included. It executes the blocks up to the
    // activating one and stops after it, as if it had been there all along.
    let late = open(&dir.path().join("late"), old());
    assert_eq!(restore(&late, before), CHUNK_ACCEPT);
    let mut late = Node::resumed(late, before as i64, 0);
    assert_eq!(late.state().unwrap().plan.unwrap().activate_elapsed_micros, activate);
    assert_eq!(query(&late.app, "/status", &json!(null))["upgrade"]["implements_scheduled"], false);
    for (request, response) in &source.log[before as usize..activating as usize] {
        assert!(late.app.stop().is_none());
        assert_eq!(&late.decided(request), response);
    }
    assert!(matches!(late.app.stop(), Some(StopCause::Upgrade(reason)) if reason.head == activating && reason.version == 5));
    // A stopped node restores nothing either.
    let (snapshot, _, app_hash) = offered(after);
    assert_ne!(late.app.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot), app_hash: app_hash.into() }).result, OFFER_ACCEPT);
    // 5. A node told to stop after a height restores nothing beyond it, and
    // stops when it has restored exactly that height.
    let bound = App::open_upgradable(&dir.path().join("bound"), None, NodeOptions::default(), options(new(), Some(before))).unwrap();
    let (snapshot, _, app_hash) = offered(after);
    assert_eq!(bound.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot), app_hash: app_hash.into() }).result, OFFER_REJECT);
    assert_eq!(restore(&bound, before), CHUNK_ACCEPT);
    assert_eq!(bound.stop(), Some(StopCause::Asked { height: before }));
}

/// A validator safety hold at the start time postpones the switch. Nodes
/// with and without the new version agree on every block of it: the block
/// that jails a validator, the held blocks at and after the start time
/// (still version 4), and the postponed activating block, the first without
/// a hold. The old program stops after that block, not at the start time.
#[test]
fn both_programs_agree_on_an_activating_block_that_a_hold_postponed() {
    use ed25519_dalek::Signer;
    let dir = tempfile::tempdir().unwrap();
    let mut newer = Node::start(&dir.path().join("new"), new()).funded();
    let summary = |node: &Node| -> pos::Summary {
        let view = query(&node.app, "/v4/state", &json!({"include_pos": true}));
        serde_json::from_slice(&entry_value(&view, b"pos/meta").expect("the staking summary")).unwrap()
    };
    // A fifth validator with the minimum bond, owned by account 5, that
    // never signals.
    newer.block(SECOND, vec![transfer(&newer.account(0), 1, 5, 3 * SECOND)]);
    let proof = key(120).sign(&pos::register_message(pos::hex32(&network_id()).unwrap(), 5, &pk(120), 1000).unwrap());
    let register = extension(&newer.account(5), 6, 17, json!({"commission_bps": 1000, "consensus_key": pk(120), "proof": hex::encode(proof.to_bytes())}));
    newer.block(SECOND, vec![register]);
    for _ in 0..10 {
        if summary(&newer).active.len() == 5 {
            break;
        }
        newer.block(SECOND, vec![]);
    }
    assert_eq!(summary(&newer).active.len(), 5);
    // Four of five schedule a plan.
    let activate = newer.schedule(200 * SECOND);
    newer.block(activate - newer.elapsed - 2 * SECOND, vec![]);
    // The fifth signs twice; CometBFT reports it with the block before the
    // start time.
    let mut jailing = newer.request(SECOND, vec![]);
    jailing.misbehavior = vec![Misbehavior {
        r#type: MisbehaviorType::DuplicateVote as i32,
        validator: Some(Validator { address: Sha256::digest(hex::decode(pk(120)).unwrap())[..20].to_vec().into(), power: 1 }),
        height: newer.height,
        time: jailing.time.clone(),
        total_voting_power: 5,
    }];
    assert_eq!(newer.app.process_proposal(proposal(&jailing)).status, ACCEPT);
    newer.decided(&jailing);
    assert!(summary(&newer).safety_hold);
    // The first block dated at or after the start time: the hold is on. The
    // plan waits and the next header still carries version 4.
    let held = newer.block(SECOND, vec![]);
    assert!(newer.elapsed >= activate);
    assert!(summary(&newer).safety_hold, "the hold ended before the start time: this run shows nothing");
    assert_eq!(held.consensus_param_updates.as_ref().unwrap().version.as_ref().unwrap().app, 4);
    assert_eq!(newer.version(), 4);
    assert_eq!(newer.state().unwrap().plan.unwrap().activate_elapsed_micros, activate);
    let status = query(&newer.app, "/status", &json!(null));
    assert_eq!(status["upgrade"]["scheduled"]["activate_elapsed_micros"], activate.to_string());
    let waiting = UpgradeWatch::default().poll(&newer.app.upgrade_status().unwrap().unwrap(), std::time::Instant::now()).unwrap();
    assert!(waiting.contains("its start time has come"), "{waiting}");
    // The first block without a hold activates.
    let mut blocks = 0;
    while newer.version() == 4 {
        assert!(blocks < 20, "the plan never activated");
        let hold_before = summary(&newer).safety_hold;
        let response = newer.block(SECOND, vec![]);
        blocks += 1;
        let version = response.consensus_param_updates.as_ref().unwrap().version.as_ref().unwrap().app;
        assert!(hold_before);
        assert_eq!(version == 5, !summary(&newer).safety_hold, "a block activated during a hold, or did not without one");
    }
    let h = newer.height as usize;
    assert!(newer.elapsed > activate && newer.elapsed - activate <= upgrade::Params::of(pos::Profile::Laboratory).late);
    assert!(newer.state().is_none());
    newer.block(SECOND, vec![]);
    // The old program on the same decided blocks: the same answer to each,
    // byte for byte, and no stop before the postponed activating block.
    let mut older = Node::start(&dir.path().join("old"), old());
    for (request, response) in &newer.log[..h] {
        assert!(older.app.stop().is_none(), "the old program stopped before block {}", request.height);
        let same = older.app.try_finalize(request.clone()).unwrap();
        assert_eq!(same.encode_to_vec(), response.encode_to_vec(), "the two programs differ at height {}", request.height);
        older.app.try_commit().unwrap();
    }
    let (height, root) = older.app.head().unwrap().unwrap();
    assert_eq!((height as usize, root.to_vec()), (h, newer.log[h - 1].1.app_hash.to_vec()));
    match older.app.stop() {
        Some(StopCause::Upgrade(reason)) => {
            assert_eq!((reason.version, reason.head, reason.from_height), (5, h as u64, Some(h as u64 + 1)));
            assert_eq!(reason.spec.as_deref(), Some(SPEC_5));
        }
        other => panic!("{other:?}"),
    }
    assert!(older.app.try_finalize(newer.log[h].0.clone()).is_err(), "the old program executed a block under version 5");
}

/// A decided block that carries kind 81 stops the node on purpose whatever
/// else is wrong with it: more transactions than a block may hold, more
/// bytes, or a request above the application's own limit. Without the
/// switch the same blocks are failures, not stops.
#[test]
fn a_decided_switch_block_over_a_budget_still_stops_the_node_on_purpose() {
    let dir = tempfile::tempdir().unwrap();
    let cases: [(&str, Vec<Vec<u8>>); 3] = [
        ("count", vec![vec![1u8; 4]; engine::MAX_BLOCK_TXS + 1]),
        ("bytes", vec![vec![0u8; engine::MAX_BLOCK_TX_BYTES + 1024]]),
        ("request", vec![vec![0u8; 9 * 1024 * 1024]]),
    ];
    for (name, extra) in cases {
        let mut node = Node::start(&dir.path().join(name), old());
        node.block(SECOND, vec![]);
        let head = node.app.head().unwrap();
        let plain = node.request(SECOND, extra.clone());
        assert!(node.app.try_finalize(plain).is_err(), "{name}");
        assert!(node.app.stop().is_none(), "{name}: a block over its budget stopped the node on purpose");
        let mut txs = extra;
        txs.push(switch());
        let decided = node.request(SECOND, txs);
        assert!(node.app.try_finalize(decided).is_err(), "{name}");
        assert_eq!(node.app.stop(), Some(StopCause::Switch { height: 2 }), "{name}");
        assert!(node.app.stop_ready(), "{name}");
        assert_eq!(node.app.head().unwrap(), head, "{name}");
    }
}

/// `--stop-after-height` is judged against the last block the node
/// committed, by the entries of its history archive. Two things must not
/// mislead it. A replay that was itself cut short does not shorten that
/// record (the reviewer's test in `upgrade_review2_node.rs`). And a restore
/// that stopped after it had prepared the archive and before it installed
/// the state leaves records for heights the node never reached: they are
/// not blocks it committed, and a stop height between its state and that
/// height is accepted.
#[test]
fn records_left_by_a_restore_that_never_happened_are_not_committed_blocks() {
    let dir = tempfile::tempdir().unwrap();
    // A chain to take a later history summary from.
    let mut source = Node::start(&dir.path().join("source"), old());
    for _ in 0..9 {
        source.block(SECOND, vec![]);
    }
    let view = query(&source.app, "/v4/state", &json!({"blocks": ["1"]}));
    let summary: history::Summary = serde_json::from_slice(&entry_value(&view, b"history/meta").expect("the history summary")).unwrap();
    assert_eq!(summary.size, 9);
    // A node at genesis whose restore of height 9 was cut short right there.
    let path = dir.path().join("node");
    drop(Node::start(&path, old()));
    {
        let network: [u8; 32] = hex::decode(network_id()).unwrap().try_into().unwrap();
        let mut archive = history::archive::Archive::open(&path.with_extension("history"), network).unwrap();
        archive.seed(&summary).unwrap();
        assert_eq!((archive.entries().unwrap(), archive.last_entry_above(0).unwrap()), (9, 0));
    }
    // Asked to stop after block 5, it starts: it never committed a block.
    let app = App::open_upgradable(&path, None, NodeOptions::default(), options(old(), Some(5)))
        .unwrap_or_else(|error| panic!("refused although the node is at genesis: {error:#}"));
    assert!(app.stop().is_none());
    assert_eq!(app.head().unwrap().map(|(height, _)| height), Some(0));
    // It goes on from genesis and stops after block 5.
    let mut node = Node::resumed(app, 0, 0);
    for (request, response) in &source.log[..5] {
        assert!(node.app.stop().is_none());
        assert_eq!(&node.decided(request), response);
    }
    assert_eq!(node.app.stop(), Some(StopCause::Asked { height: 5 }));
    drop(node);
    // Now it has committed block 5, and a stop height below that is refused.
    let error = format!("{:#}", App::open_upgradable(&path, None, NodeOptions::default(), options(old(), Some(4))).err().expect("opened below what it committed"));
    assert!(error.contains("already at height 5"), "{error}");
}
