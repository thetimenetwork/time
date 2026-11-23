// From the independent review of the upgrade mechanism (its file
// `v5/tests/review_node.rs`), brought into the branch unchanged: no fix
// changed what these tests assert.
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

// ---------------------------------------------------------------------------
// Reviewer's tests: the real binary, spoken to over its ABCI socket as
// CometBFT speaks to it (a request, then Flush; answers read from the wire).
// ---------------------------------------------------------------------------
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

struct Binary {
    child: Child,
    stream: TcpStream,
    errors: Arc<Mutex<String>>,
}
impl Binary {
    fn start(path: &Path, extra: &[&str]) -> Self {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_time-node-v5"))
            .args(["--devnet", "--db"])
            .arg(path)
            .args(["--listen", &format!("127.0.0.1:{port}"), "--snapshot-seconds", "3600"])
            .args(extra)
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
                    assert!(started.elapsed() < Duration::from_secs(20), "the node did not listen: {error}; {}", errors.lock().unwrap());
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
    /// One answer from the wire, or `None` if none comes in `wait` (or the
    /// node closed the connection).
    fn answer(&mut self, wait: Duration) -> Option<response::Value> {
        self.stream.set_read_timeout(Some(wait)).unwrap();
        let mut length = 0u64;
        let mut shift = 0;
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
    /// A request followed by Flush, as CometBFT's socket client sends every
    /// synchronous call; both answers, if they come.
    fn call(&mut self, value: request::Value, wait: Duration) -> (Option<response::Value>, Option<response::Value>) {
        let mut bytes = Self::frame(value);
        bytes.extend(Self::frame(request::Value::Flush(RequestFlush {})));
        if self.stream.write_all(&bytes).is_err() {
            return (None, None);
        }
        let first = self.answer(wait);
        let second = if first.is_some() { self.answer(wait) } else { None };
        (first, second)
    }
    fn init(&mut self) {
        let wait = Duration::from_secs(20);
        assert!(matches!(self.call(request::Value::Info(RequestInfo::default()), wait).0, Some(response::Value::Info(_))));
        assert!(matches!(self.call(request::Value::InitChain(init()), wait).0, Some(response::Value::InitChain(_))), "{}", self.errors.lock().unwrap());
    }
    /// FinalizeBlock: the answer must be `expected`.
    fn finalize(&mut self, request: &RequestFinalizeBlock, expected: &ResponseFinalizeBlock) {
        match self.call(request::Value::FinalizeBlock(request.clone()), Duration::from_secs(20)) {
            (Some(response::Value::FinalizeBlock(answer)), Some(response::Value::Flush(_))) => {
                assert_eq!(answer.encode_to_vec(), expected.encode_to_vec(), "height {}: the binary's answer differs", request.height)
            }
            other => panic!("height {}: {other:?}; {}", request.height, self.errors.lock().unwrap()),
        }
    }
    /// Commit, as CometBFT sends it: both the Commit answer and the answer
    /// to the Flush behind it must arrive, or its `Commit` call fails.
    fn commit(&mut self) {
        match self.call(request::Value::Commit(RequestCommit {}), Duration::from_secs(20)) {
            (Some(response::Value::Commit(_)), Some(response::Value::Flush(_))) => {}
            other => panic!("Commit was not answered in full: {other:?}; {}", self.errors.lock().unwrap()),
        }
    }
    /// The exit code, if the process ends within `wait`.
    fn exit(&mut self, wait: Duration) -> Option<i32> {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                std::thread::sleep(Duration::from_millis(100));
                return status.code();
            }
            if started.elapsed() >= wait {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn errors(&self) -> String {
        self.errors.lock().unwrap().clone()
    }
}
impl Drop for Binary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn audit(path: &Path) -> (Option<i32>, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_time-node-v5")).args(["--devnet", "--db"]).arg(path).arg("--audit").output().unwrap();
    (output.status.code(), String::from_utf8_lossy(&output.stdout).to_string(), String::from_utf8_lossy(&output.stderr).to_string())
}

/// Design 6.1 and 3.4, end to end: the release binary is fed, over its
/// socket, a chain on which a version 5 it lacks is activated. Every answer
/// is the upgraded program's; Commit(h) is answered in full; nothing is
/// answered for h + 1; it ends with code 4 promptly, state saved at h.
#[test]
fn review_the_binary_stops_after_the_activating_block_over_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut newer = Node::start(&dir.path().join("new"), new()).funded();
    newer.schedule(200 * SECOND);
    while newer.version() == 4 {
        newer.block(60 * SECOND, vec![]);
    }
    let h = newer.height as usize;
    newer.block(SECOND, vec![]);
    let log = newer.log.clone();
    let path = dir.path().join("old");
    let mut binary = Binary::start(&path, &[]);
    binary.init();
    for (request, response) in &log[..h] {
        binary.finalize(request, response);
        binary.commit();
    }
    let committed = Instant::now();
    // Block h + 1, the first under version 5: no answer.
    let (answer, _) = binary.call(request::Value::FinalizeBlock(log[h].0.clone()), Duration::from_millis(1500));
    assert!(answer.is_none(), "the release binary answered for h + 1: {answer:?}");
    let code = binary.exit(Duration::from_secs(15));
    let took = committed.elapsed();
    let errors = binary.errors();
    assert_eq!(code, Some(4), "{errors}");
    assert!(errors.lines().any(|line| line == "STOPPED FOR UPGRADE"), "{errors}");
    assert!(errors.contains(&format!("The state at height {h} is saved and valid")), "{errors}");
    // The stop path acts once the Commit answer has left, not on its
    // five-second fallback.
    assert!(took < Duration::from_secs(4), "the node took {took:?} to end after Commit(h): {errors}");
    drop(binary);
    // Started again on the same data it says the same, with the state at h.
    let (code, _, errors) = audit(&path);
    assert_eq!(code, Some(4), "{errors}");
    assert!(errors.contains(&format!("The state at height {h} is saved and valid")), "{errors}");
}

/// `--stop-after-height H` over the socket, with the next consensus request
/// already behind the Commit in the same write.
#[test]
fn review_the_binary_stops_as_asked_over_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = Node::start(&dir.path().join("source"), old());
    for _ in 0..4 {
        source.block(SECOND, vec![]);
    }
    let log = source.log.clone();
    let path = dir.path().join("node");
    let mut binary = Binary::start(&path, &["--stop-after-height", "3"]);
    binary.init();
    for (request, response) in &log[..2] {
        binary.finalize(request, response);
        binary.commit();
    }
    binary.finalize(&log[2].0, &log[2].1);
    // Commit(3) and, right behind it, the proposal for block 4.
    let mut bytes = Binary::frame(request::Value::Commit(RequestCommit {}));
    bytes.extend(Binary::frame(request::Value::ProcessProposal(proposal(&log[3].0))));
    bytes.extend(Binary::frame(request::Value::Flush(RequestFlush {})));
    binary.stream.write_all(&bytes).unwrap();
    let committed = Instant::now();
    assert!(matches!(binary.answer(Duration::from_secs(20)), Some(response::Value::Commit(_))), "{}", binary.errors());
    let next = binary.answer(Duration::from_millis(1500));
    assert!(next.is_none(), "the node judged a proposal for H + 1: {next:?}");
    let code = binary.exit(Duration::from_secs(15));
    let took = committed.elapsed();
    let errors = binary.errors();
    assert_eq!(code, Some(4), "{errors}");
    assert!(errors.lines().any(|line| line == "STOPPED AS ASKED"), "{errors}");
    assert!(took < Duration::from_secs(4), "the node took {took:?} to end after Commit(H): {errors}");
    drop(binary);
    let (code, report, errors) = audit(&path);
    assert_eq!(code, Some(0), "{errors}");
    assert_eq!(serde_json::from_str::<Value>(&report).unwrap()["height"], "3");
}

/// A decided block that carries kind 81, over the socket.
#[test]
fn review_the_binary_stops_at_a_switch_over_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = Node::start(&dir.path().join("source"), old());
    for _ in 0..2 {
        source.block(SECOND, vec![]);
    }
    let log = source.log.clone();
    let decided = source.request(SECOND, vec![switch()]);
    let path = dir.path().join("node");
    let mut binary = Binary::start(&path, &[]);
    binary.init();
    for (request, response) in &log {
        binary.finalize(request, response);
        binary.commit();
    }
    let asked = Instant::now();
    let (answer, _) = binary.call(request::Value::FinalizeBlock(decided), Duration::from_millis(1500));
    assert!(answer.is_none(), "the block was answered: {answer:?}");
    let code = binary.exit(Duration::from_secs(15));
    let took = asked.elapsed();
    let errors = binary.errors();
    assert_eq!(code, Some(4), "{errors}");
    assert!(errors.lines().any(|line| line == "STOPPED AT A SWITCH"), "{errors}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    drop(binary);
    let (code, report, errors) = audit(&path);
    assert_eq!(code, Some(0), "{errors}");
    assert_eq!(serde_json::from_str::<Value>(&report).unwrap()["height"], "2");
}

/// A rehearsal build and a release build on the same blocks: the same answer
/// to every block up to and including the activating one; then the release
/// build stops and the rehearsal build runs on. Run with and without
/// `--features rehearsal-v5`: the binary under test is the build's own.
#[test]
fn review_a_rehearsal_binary_and_a_release_binary_agree_up_to_the_activation() {
    let rehearsal = Versions::new([
        (4, rules::SPEC_4.to_string()),
        (rules::REHEARSAL_VERSION, rules::REHEARSAL_SPEC.to_string()),
    ])
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut source = Node::start(&dir.path().join("source"), rehearsal).funded();
    let before = source.height as usize;
    let activate = source.elapsed + 200 * SECOND;
    let signals: Vec<Vec<u8>> = (0..4).map(|owner| support(&source.app, owner, activate, rules::REHEARSAL_SPEC)).collect();
    source.block(SECOND, signals.clone());
    assert!(source.state().unwrap().plan.is_some());
    while source.version() == 4 {
        source.block(60 * SECOND, vec![]);
    }
    let h = source.height as usize;
    source.block(SECOND, vec![]);
    source.block(SECOND, vec![]);
    let log = source.log.clone();
    let mut binary = Binary::start(&dir.path().join("binary"), &[]);
    binary.init();
    for (request, response) in &log[..before] {
        binary.finalize(request, response);
        binary.commit();
    }
    // Mempool admission is local policy: only a build that implements the
    // plan admits its signals.
    let admitted = match binary.call(request::Value::CheckTx(RequestCheckTx { tx: signals[0].clone().into(), r#type: 0 }), Duration::from_secs(20)).0 {
        Some(response::Value::CheckTx(answer)) => answer.code == 0,
        other => panic!("{other:?}"),
    };
    assert_eq!(admitted, rules::REHEARSAL, "admission of a rehearsal signal");
    // Every block up to and including the activating one: the same answer.
    for (request, response) in &log[before..h] {
        binary.finalize(request, response);
        binary.commit();
    }
    if rules::REHEARSAL {
        for (request, response) in &log[h..] {
            binary.finalize(request, response);
            binary.commit();
        }
        assert!(binary.exit(Duration::from_millis(1500)).is_none(), "the rehearsal build stopped: {}", binary.errors());
    } else {
        let (answer, _) = binary.call(request::Value::FinalizeBlock(log[h].0.clone()), Duration::from_millis(1500));
        assert!(answer.is_none(), "the release build answered for h + 1");
        assert_eq!(binary.exit(Duration::from_secs(15)), Some(4), "{}", binary.errors());
        let errors = binary.errors();
        assert!(errors.lines().any(|line| line == "STOPPED FOR UPGRADE") && errors.contains(rules::REHEARSAL_SPEC), "{errors}");
    }
}

/// Design 3.4: "Started with its head above H, it exits with code 1." The
/// head a node knows at start is its newest snapshot, not the last block it
/// committed.
#[test]
fn review_stop_after_height_below_the_committed_height_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node");
    let mut node = Node::start(&path, old());
    for _ in 0..2 {
        node.block(SECOND, vec![]);
    }
    node.app.snapshot().unwrap();
    let (at, elapsed) = (node.height, node.elapsed);
    for _ in 0..4 {
        node.block(SECOND, vec![]);
    }
    assert_eq!(node.app.head().unwrap().unwrap().0, 6);
    let log = node.log.clone();
    // The process ends without a final snapshot (killed, or a failure).
    drop(node);
    let opened = match App::open_upgradable(&path, None, NodeOptions::default(), options(old(), Some(4))) {
        Err(error) => {
            assert!(format!("{error:#}").contains("already at height"));
            return;
        }
        Ok(app) => app,
    };
    let head = opened.head().unwrap().unwrap().0;
    // What CometBFT's handshake then does: it replays the blocks after the snapshot.
    let mut replay = Node::resumed(opened, at, elapsed);
    for (request, response) in &log[2..4] {
        assert_eq!(&replay.decided(request), response);
    }
    let cause = replay.app.stop();
    panic!(
        "this node had committed block 6. Started with --stop-after-height 4 it opened at its snapshot (height {head}), replayed to 4 and reports {:?}: {}",
        cause.as_ref().map(|cause| cause.first_line()),
        cause.as_ref().map_or_else(String::new, |cause| cause.explain(Some(4)))
    );
}
