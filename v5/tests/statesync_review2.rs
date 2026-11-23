#![allow(dead_code, unused_imports, unused_mut)]
//! State sync and block pruning, as CometBFT drives them: a node offers
//! snapshots in chunks, another restores one and must then be
//! indistinguishable from a node that executed every block; every hostile
//! snapshot, chunk and offer is refused with the node's state untouched; and
//! `Commit` never lets CometBFT delete a block that is still needed.
mod common;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use ed25519_dalek::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, ActionPayload};
use timecurrency_v5::{
    app::App,
    engine,
    statesync::{
        EVIDENCE_MAX_AGE_BLOCKS, Manifest, NodeOptions, RetainInputs, SYNC_FORMAT, metadata_hash,
        retain_height,
    },
    store::Store,
};

const PROPOSAL_ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const OFFER_ACCEPT: i32 = response_offer_snapshot::Result::Accept as i32;
const OFFER_ABORT: i32 = response_offer_snapshot::Result::Abort as i32;
const OFFER_REJECT: i32 = response_offer_snapshot::Result::Reject as i32;
const OFFER_REJECT_FORMAT: i32 = response_offer_snapshot::Result::RejectFormat as i32;
const OFFER_REJECT_SENDER: i32 = response_offer_snapshot::Result::RejectSender as i32;
const CHUNK_ACCEPT: i32 = response_apply_snapshot_chunk::Result::Accept as i32;
const CHUNK_ABORT: i32 = response_apply_snapshot_chunk::Result::Abort as i32;
const CHUNK_RETRY: i32 = response_apply_snapshot_chunk::Result::Retry as i32;
const CHUNK_REJECT_SNAPSHOT: i32 = response_apply_snapshot_chunk::Result::RejectSnapshot as i32;

/// Snapshots for peers every ten blocks, in chunks of 1 KiB so that the
/// small states of these tests span many chunks.
const EVERY: u64 = 10;
const CHUNK: u32 = 1024;

fn serving() -> NodeOptions {
    NodeOptions {
        sync_snapshot_blocks: EVERY,
        sync_chunk_bytes: CHUNK,
        ..NodeOptions::default()
    }
}
fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: micros / 1_000_000,
        nanos: ((micros % 1_000_000) * 1000) as i32,
    })
}
fn init(genesis: &timecurrency_v5::genesis::Genesis) -> RequestInitChain {
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
/// The same rules under another chain id: another network.
fn other_genesis() -> timecurrency_v5::genesis::Genesis {
    let mut genesis = genesis_v5();
    genesis.ledger.chain_id = "time-devnet-v4-another-chain".into();
    genesis
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
                    address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20]
                        .to_vec()
                        .into(),
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
fn try_query(app: &App, path: &str, data: &serde_json::Value) -> Result<serde_json::Value, String> {
    let response = app.query(RequestQuery {
        data: serde_json::to_vec(data).unwrap().into(),
        path: path.into(),
        height: 0,
        prove: false,
    });
    if response.code == 0 {
        Ok(serde_json::from_slice(&response.value).unwrap())
    } else {
        Err(response.log)
    }
}
fn query(app: &App, path: &str, data: &serde_json::Value) -> serde_json::Value {
    try_query(app, path, data).unwrap_or_else(|log| panic!("query failed: {log}"))
}
fn account(app: &App, id: u64) -> Account {
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()] }));
    let key = hex::encode(engine::account_key(id));
    let entry = view["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key_hex"] == key.as_str())
        .unwrap();
    let bytes = STANDARD
        .decode(entry["value_b64"].as_str().expect("account exists"))
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn info(app: &App) -> (i64, Vec<u8>) {
    let info = app.info(RequestInfo::default());
    (info.last_block_height, info.last_block_app_hash.to_vec())
}

type Log = Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>;

struct Node {
    app: App,
    height: i64,
    elapsed: u64,
    /// The finalize request and its answer for every committed block.
    log: Log,
    /// `retain_height` of every `Commit`.
    retained: Vec<i64>,
}
impl Node {
    fn start(path: &Path, options: NodeOptions) -> Self {
        Self::start_on(path, options, &genesis_v5())
    }
    fn start_on(path: &Path, options: NodeOptions, genesis: &timecurrency_v5::genesis::Genesis) -> Self {
        let app = App::open_with_options(path, options).unwrap();
        app.try_init(init(genesis)).unwrap();
        Self::at(app, 0, 0)
    }
    fn at(app: App, height: i64, elapsed: u64) -> Self {
        Self {
            app,
            height,
            elapsed,
            log: Vec::new(),
            retained: Vec::new(),
        }
    }
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: timestamp(
                genesis_v5().ledger.genesis_time_micros + (self.elapsed + delta) as i64,
            ),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: last_commit(height),
            ..Default::default()
        }
    }
    /// Proposal, finalize and commit of one block, as on a validator. The
    /// snapshot thread then writes the snapshot for peers, if one is due.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> ResponseFinalizeBlock {
        let request = self.request(delta, txs);
        if self.app.process_proposal(proposal(&request)).status != PROPOSAL_ACCEPT {
            let height = request.height;
            let reason = self.app.try_finalize(request).unwrap_err();
            panic!("proposal rejected at height {height}: {reason:#}");
        }
        let response = self.app.try_finalize(request.clone()).unwrap();
        self.retained.push(self.app.try_commit().unwrap().retain_height);
        self.app.write_sync_snapshot().unwrap();
        self.height += 1;
        self.elapsed += delta;
        self.log.push((request, response.clone()));
        response
    }
    fn account(&self, id: u64) -> Account {
        account(&self.app, id)
    }
    /// A block with payments from two accounts.
    fn busy_block(&mut self) -> ResponseFinalizeBlock {
        let row = self.account(2);
        let mut txs: Vec<Vec<u8>> = (0..3)
            .map(|index| {
                let mut next = row.clone();
                next.nonce += index;
                transfer(&next, 3, 12, 1)
            })
            .collect();
        txs.push(transfer(&self.account(3), 4, 12, 5000));
        self.block(pos::SECOND, txs)
    }
}

fn sponsor(row: &Account, signer: u8, seed: u8, name: &str, now: u64) -> Vec<u8> {
    let network = network_id();
    let salt = hex::encode([seed; 32]);
    let commitment = ledger::action_commitment(&network, &pk(seed), name, &salt).unwrap();
    let expiry = now + 3600 * pos::SECOND;
    let consent = registration::consent_bytes(
        pos::hex32(&network).unwrap(),
        row.id,
        pos::hex32(&pk(seed)).unwrap(),
        pos::hex32(&commitment).unwrap(),
        expiry,
    );
    extension(
        row,
        signer,
        44,
        json!({"public_key":pk(seed),"commitment":commitment,"expires_elapsed_micros":expiry.to_string(),"proof":hex::encode(key(seed).sign(&consent).to_bytes())}),
    )
}
fn reveal(seed: u8, name: &str) -> Vec<u8> {
    legacy(
        u64::MAX,
        0,
        0,
        seed,
        ActionPayload::Reveal(ledger::Reveal {
            name: name.into(),
            salt: hex::encode([seed; 32]),
        }),
    )
}
fn register_validator(row: &Account, consensus_seed: u8) -> Vec<u8> {
    let network = network_id();
    let proof = key(consensus_seed).sign(
        &pos::register_message(
            pos::hex32(&network).unwrap(),
            row.id,
            &pk(consensus_seed),
            1000,
        )
        .unwrap(),
    );
    extension(
        row,
        row.id as u8 + 1,
        17,
        json!({"commission_bps":1000,"consensus_key":pk(consensus_seed),"proof":hex::encode(proof.to_bytes())}),
    )
}

/// A chain of `height` blocks with funded validators, payments, a new
/// account and a validator registration, on a node that writes a snapshot
/// for peers every `EVERY` blocks.
fn source(path: &Path, height: i64) -> Node {
    let mut node = Node::start(path, serving());
    node.block(pos::SECOND, vec![]);
    while !(0..4).all(|id| node.account(id).balance >= 5 * pos::SECOND) {
        assert!(node.height < 40, "validator owners were not funded");
        node.block(60 * pos::SECOND, vec![]);
    }
    let row = node.account(0);
    node.block(
        pos::SECOND,
        vec![
            transfer(&row, 1, 4, 2 * pos::SECOND),
            sponsor(&node.account(1), 2, 201, "newcomer", node.elapsed),
        ],
    );
    node.block(2 * pos::SECOND, vec![reveal(201, "newcomer")]);
    node.block(pos::SECOND, vec![register_validator(&node.account(4), 120)]);
    assert!(node.height <= height, "the chain is already longer");
    while node.height < height {
        node.busy_block();
    }
    node
}

/// What `Info` answers on a node at `height` of the chain in `log`.
fn info_at(log: &Log, height: u64) -> (i64, Vec<u8>) {
    (height as i64, trusted(log, height))
}
/// What CometBFT's light client hands over for a snapshot of `height`: the
/// application hash of that block.
fn trusted(log: &Log, height: u64) -> Vec<u8> {
    log[height as usize - 1].1.app_hash.to_vec()
}
fn offered(app: &App) -> Vec<Snapshot> {
    app.list_snapshots().snapshots
}
fn snapshot_at(app: &App, height: u64) -> Snapshot {
    offered(app)
        .into_iter()
        .find(|snapshot| snapshot.height == height)
        .unwrap_or_else(|| panic!("no snapshot offered at height {height}"))
}
fn chunks_of(app: &App, snapshot: &Snapshot) -> Vec<Vec<u8>> {
    (0..snapshot.chunks)
        .map(|chunk| {
            let bytes = app
                .load_snapshot_chunk(RequestLoadSnapshotChunk {
                    height: snapshot.height,
                    format: snapshot.format,
                    chunk,
                })
                .chunk
                .to_vec();
            assert!(!bytes.is_empty(), "chunk {chunk} is missing");
            bytes
        })
        .collect()
}
fn offer(app: &App, snapshot: &Snapshot, app_hash: &[u8]) -> i32 {
    app.offer_snapshot(RequestOfferSnapshot {
        snapshot: Some(snapshot.clone()),
        app_hash: app_hash.to_vec().into(),
    })
    .result
}
fn apply(app: &App, index: u32, chunk: &[u8], sender: &str) -> ResponseApplySnapshotChunk {
    app.apply_snapshot_chunk(RequestApplySnapshotChunk {
        index,
        chunk: chunk.to_vec().into(),
        sender: sender.into(),
    })
}
/// Offers a snapshot and applies its chunks in order, each from its own
/// sender ("peer-0", "peer-1", ...). Returns the answer to the last chunk.
fn restore(app: &App, snapshot: &Snapshot, chunks: &[Vec<u8>], app_hash: &[u8]) -> ResponseApplySnapshotChunk {
    assert_eq!(offer(app, snapshot, app_hash), OFFER_ACCEPT);
    let mut last = ResponseApplySnapshotChunk::default();
    for (index, chunk) in chunks.iter().enumerate() {
        last = apply(app, index as u32, chunk, &format!("peer-{index}"));
        if index + 1 < chunks.len() {
            assert_eq!(last.result, CHUNK_ACCEPT, "chunk {index}");
            assert!(last.refetch_chunks.is_empty() && last.reject_senders.is_empty());
        }
    }
    last
}
fn all_senders(chunks: usize) -> Vec<String> {
    let mut senders: Vec<String> = (0..chunks).map(|index| format!("peer-{index}")).collect();
    senders.sort();
    senders
}

/// A snapshot file with its rows changed and its checksum made right again,
/// as someone who wants it to pass every check but the root would write it.
fn rewrite(file: &[u8], change: impl FnOnce(&mut Vec<(Vec<u8>, Vec<u8>)>, &mut u64)) -> Vec<u8> {
    let mut at = 16 + 8 + 32 + 32;
    let mut leaves = u64::from_be_bytes(file[at..at + 8].try_into().unwrap());
    at += 8;
    let metadata = u32::from_be_bytes(file[at..at + 4].try_into().unwrap()) as usize;
    at += 4 + metadata;
    let mut out = file[..at].to_vec();
    let mut rows = Vec::new();
    while at < file.len() - 32 {
        let key = u16::from_be_bytes(file[at..at + 2].try_into().unwrap()) as usize;
        let key_bytes = file[at + 2..at + 2 + key].to_vec();
        at += 2 + key;
        let value = u32::from_be_bytes(file[at..at + 4].try_into().unwrap()) as usize;
        rows.push((key_bytes, file[at + 4..at + 4 + value].to_vec()));
        at += 4 + value;
    }
    change(&mut rows, &mut leaves);
    out[88..96].copy_from_slice(&leaves.to_be_bytes());
    for (key, value) in rows {
        out.extend((key.len() as u16).to_be_bytes());
        out.extend(key);
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    }
    let digest: [u8; 32] = Sha256::digest(&out).into();
    out.extend(digest);
    out
}
/// The offer an attacker makes for `file`: a manifest that matches it.
fn advertise(height: u64, file: &[u8]) -> (Snapshot, Vec<Vec<u8>>) {
    let chunks: Vec<Vec<u8>> = file.chunks(CHUNK as usize).map(<[u8]>::to_vec).collect();
    let metadata = Manifest {
        total_bytes: file.len() as u64,
        chunk_bytes: CHUNK,
        chunk_hashes: chunks.iter().map(|chunk| Sha256::digest(chunk).into()).collect(),
    }
    .encode();
    (
        Snapshot {
            height,
            format: SYNC_FORMAT,
            chunks: chunks.len() as u32,
            hash: metadata_hash(&metadata).to_vec().into(),
            metadata: metadata.into(),
        },
        chunks,
    )
}
/// Every file under the node's state and history directories, by relative
/// path, except the lock files a running node holds.
fn disk(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let name = entry.file_name();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), out);
            } else if name != "LOCK" && name != "writer.lock" {
                out.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    let root = path.parent().unwrap();
    for extension in ["v5state", "history"] {
        walk(root, &path.with_extension(extension), &mut out);
    }
    out
}
fn restart_snapshots(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(path.with_extension("v5state"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("state-") && name.ends_with(".snap"))
        .collect();
    names.sort();
    names
}
/// Feeds decided blocks to a node as block sync does and checks every
/// answer against the node that produced them.
fn replay(app: &App, log: &[(RequestFinalizeBlock, ResponseFinalizeBlock)]) {
    for (request, response) in log {
        assert_eq!(
            app.try_finalize(request.clone()).unwrap(),
            *response,
            "height {}",
            request.height
        );
        app.try_commit().unwrap();
    }
}

use prost::Message as _;

fn frame(request: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    let mut left = request.encoded_len() as u64;
    while left >= 0x80 {
        out.push((left as u8 & 0x7f) | 0x80);
        left >>= 7;
    }
    out.push(left as u8);
    request.encode(&mut out).unwrap();
    out
}
fn read_response(stream: &mut TcpStream) -> std::io::Result<Response> {
    let mut length = 0u64;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        length |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    Response::decode(payload.as_slice()).map_err(std::io::Error::other)
}
fn connect(addr: std::net::SocketAddr) -> TcpStream {
    let stream = loop {
        match TcpStream::connect(addr) {
            Ok(stream) => break stream,
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    stream
}
fn call(stream: &mut TcpStream, value: request::Value) -> std::io::Result<response::Value> {
    // A write into a connection the server already closed may fail: the
    // answer (or its absence) is what the test looks at.
    let _ = stream.write_all(&frame(&Request { value: Some(value) }));
    let _ = stream.flush();
    Ok(read_response(stream)?.value.expect("an answer"))
}


// ---------------------------------------------------------------------
// Second-round review tests (not part of the branch).
// ---------------------------------------------------------------------

fn offline(path: &Path) -> engine::Engine {
    engine::Engine::open_with_history(
        Store::open(path.with_extension("v5state")).unwrap(),
        path.with_extension("history"),
    )
    .unwrap()
}

/// A node restored at height 10 whose CometBFT did not record it. On the
/// next start a restore of height 20 gets as far as step 3 of
/// `Engine::restore` (archive seeded, record written) and stops before the
/// rename. CometBFT starts over once more, is offered height 10 again (the
/// idempotent accept), and the node goes on from there.
#[test]
fn review2_a_record_of_a_restore_that_stopped_does_not_hide_the_one_that_happened() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 24);
    let ten = snapshot_at(&source.app, 10);
    let twenty = snapshot_at(&source.app, 20);
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    assert_eq!(restore(&app, &ten, &chunks_of(&source.app, &ten), &trusted(&source.log, 10)).result, CHUNK_ACCEPT);
    drop(app);
    // What step 3 of a restore of height 20 leaves, made with the code that
    // does it: another node restores height 20 and its record is the file;
    // the archive is seeded with that summary.
    let other = dir.path().join("other.db");
    let helper = App::open(&other).unwrap();
    assert_eq!(restore(&helper, &twenty, &chunks_of(&source.app, &twenty), &trusted(&source.log, 20)).result, CHUNK_ACCEPT);
    drop(helper);
    let record = "restored-00000000000000000020.json";
    let summary: history::Summary =
        serde_json::from_slice(&fs::read(other.with_extension("history").join(record)).unwrap()).unwrap();
    {
        let network: [u8; 32] = hex::decode(&summary.network_id).unwrap().try_into().unwrap();
        let mut archive = history::archive::Archive::open(&path.with_extension("history"), network).unwrap();
        archive.seed(&summary).unwrap();
    }
    fs::copy(other.with_extension("history").join(record), path.with_extension("history").join(record)).unwrap();

    // The node starts: it holds height 10, restored and not built on.
    let app = App::open(&path).unwrap();
    assert_eq!(info(&app), (10, trusted(&source.log, 10)));
    // CometBFT offers height 10 again; accepted, nothing changes; then blocks.
    assert_eq!(restore(&app, &ten, &chunks_of(&source.app, &ten), &trusted(&source.log, 10)).result, CHUNK_ACCEPT);
    replay(&app, &source.log[10..]);
    assert_eq!(info(&app), info(&source.app));
    let recent = json!({"blocks":["11","24"]});
    assert_eq!(query(&app, "/v4/state", &recent), query(&source.app, "/v4/state", &recent));
    let old = try_query(&app, "/v4/state", &json!({"blocks":["5"]})).unwrap_err();
    eprintln!("running, block 5 asked: {old}");
    app.snapshot().unwrap().unwrap();
    drop(app);

    // It is stopped and started (or recounted).
    let engine = offline(&path);
    let base = engine.history_base();
    let audit = engine.audit();
    eprintln!(
        "after a restart: restored at {base:?}; recount: {:?}",
        audit.as_ref().map(|audit| (audit.history_archive_verified, audit.history_archive_from)).map_err(|e| format!("{e:#}"))
    );
    drop(engine);
    let app = App::open(&path).unwrap();
    let old = try_query(&app, "/v4/state", &json!({"blocks":["5"]})).unwrap_err();
    eprintln!("after a restart, block 5 asked: {old}");
    assert_eq!(base, Some(10), "the node no longer knows it was restored at height 10");
    assert!(audit.is_ok(), "the recount of a healthy restored node fails");
}

/// The node holds height 20 with the trusted hash. It is offered that
/// height and hash again with a manifest of the peer's own: a file whose
/// header names the same height and hash and whose rows are forged.
#[test]
fn review2_the_snapshot_already_held_offered_again_with_forged_rows_installs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 24);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let hash = trusted(&source.log, 20);
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    assert_eq!(restore(&app, &snapshot, &chunks, &hash).result, CHUNK_ACCEPT);
    drop(app);
    let app = App::open(&path).unwrap();
    let wanted = json!({"ids":["0","4","12"],"names":["newcomer"],"include_pos":true});
    let before = (info(&app), query(&app, "/v4/state", &wanted), disk(&path));
    let forged = rewrite(&chunks.concat(), |rows, _| {
        for row in rows.iter_mut().filter(|(key, _)| key.starts_with(b"account/")) {
            row.1 = b"{}".to_vec();
        }
    });
    assert_ne!(forged, chunks.concat());
    let (offered, forged_chunks) = advertise(20, &forged);
    let answer = restore(&app, &offered, &forged_chunks, &hash);
    eprintln!(
        "forged rows for the height and hash already held: last chunk answered {} with {:?} rejected",
        answer.result, answer.reject_senders
    );
    assert_eq!((info(&app), query(&app, "/v4/state", &wanted), disk(&path)), before);
    // And the node goes on with the chain's blocks.
    replay(&app, &source.log[20..]);
    assert_eq!(info(&app), info(&source.app));
}

/// Requests of other kinds as large as the transport now reads, on a node
/// with state, over the real transport.
#[test]
fn review2_large_requests_of_other_kinds_are_answered() {
    let dir = tempfile::tempdir().unwrap();
    let node = source(&dir.path().join("node.db"), 12);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let served = node.app.clone();
    std::thread::spawn(move || timecurrency_v5::transport::serve(addr, served, || {}).unwrap());
    let big = vec![0x61u8; 12_000_000];
    let before = info(&node.app);
    let mut connection = connect(addr);
    let describe = |answer: &std::io::Result<response::Value>| match answer {
        Ok(response::Value::CheckTx(r)) => format!("code {} {:?}", r.code, r.log),
        Ok(response::Value::Query(r)) => format!("code {} {:?}", r.code, r.log),
        Ok(response::Value::ProcessProposal(r)) => format!("status {}", r.status),
        Ok(response::Value::OfferSnapshot(r)) => format!("result {}", r.result),
        Ok(other) => format!("{other:?}"),
        Err(error) => format!("connection ended: {error}"),
    };
    let started = std::time::Instant::now();
    let checked = call(&mut connection, request::Value::CheckTx(RequestCheckTx { tx: big.clone().into(), r#type: 0 }));
    eprintln!("12 MB CheckTx: {} in {:?}", describe(&checked), started.elapsed());
    let started = std::time::Instant::now();
    let queried = call(
        &mut connection,
        request::Value::Query(RequestQuery { data: big.clone().into(), path: "/v4/state".into(), height: 0, prove: false }),
    );
    eprintln!("12 MB Query: {} in {:?}", describe(&queried), started.elapsed());
    let request = node.request(pos::SECOND, vec![big.clone()]);
    let started = std::time::Instant::now();
    let judged = call(&mut connection, request::Value::ProcessProposal(proposal(&request)));
    eprintln!("12 MB ProcessProposal: {} in {:?}", describe(&judged), started.elapsed());
    let offered = call(
        &mut connection,
        request::Value::OfferSnapshot(RequestOfferSnapshot {
            snapshot: Some(Snapshot { height: 50, format: SYNC_FORMAT, chunks: 3, hash: vec![1; 32].into(), metadata: big.clone().into() }),
            app_hash: vec![2; 32].into(),
        }),
    );
    eprintln!("12 MB OfferSnapshot: {}", describe(&offered));
    assert!(checked.is_ok() && queried.is_ok() && judged.is_ok() && offered.is_ok());
    assert_eq!(info(&node.app), before);
}
