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

#[test]
fn a_restored_node_and_a_node_that_replayed_from_genesis_agree_on_every_later_block() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = source(&dir.path().join("source.db"), 23);
    // Snapshots exist for the two newest multiples of ten, nothing else.
    let heights: Vec<u64> = offered(&source.app).iter().map(|snapshot| snapshot.height).collect();
    assert_eq!(heights, [10, 20]);
    let snapshot = snapshot_at(&source.app, 20);
    assert_eq!(snapshot.format, SYNC_FORMAT);
    assert_eq!(snapshot.hash[..], metadata_hash(&snapshot.metadata)[..]);
    let chunks = chunks_of(&source.app, &snapshot);
    assert!(chunks.len() > 5, "the test state should span several chunks");
    assert!(chunks[..chunks.len() - 1].iter().all(|chunk| chunk.len() == CHUNK as usize));

    // A new node: no InitChain, as when CometBFT starts with state sync.
    let joined_path = dir.path().join("joined.db");
    let joined = App::open_with_options(&joined_path, serving()).unwrap();
    assert_eq!(info(&joined), (0, vec![]));
    let answer = restore(&joined, &snapshot, &chunks, &trusted(&source.log, 20));
    assert_eq!(answer.result, CHUNK_ACCEPT);
    assert!(answer.refetch_chunks.is_empty() && answer.reject_senders.is_empty());
    // CometBFT now asks Info: exactly the snapshot's height and trusted hash.
    assert_eq!(info(&joined), (20, trusted(&source.log, 20)));
    assert_eq!(
        joined.info(RequestInfo::default()).app_version,
        source.app.info(RequestInfo::default()).app_version
    );
    // The restored file is the node's restart snapshot; no staging file is left.
    assert_eq!(restart_snapshots(&joined_path), ["state-00000000000000000020.snap"]);
    assert!(!joined_path.with_extension("v5state").join("restore.tmp").exists());

    // A third node executes every block from genesis.
    let replayed_path = dir.path().join("replayed.db");
    let replayed = App::open_with_options(&replayed_path, serving()).unwrap();
    replayed.try_init(init(&genesis_v5())).unwrap();
    replay(&replayed, &source.log[..20]);
    assert_eq!(info(&replayed), info(&joined));

    // Blocks 21 to 23 were decided before the node joined: block sync.
    replay(&joined, &source.log[20..]);
    replay(&replayed, &source.log[20..]);
    assert_eq!(info(&joined), info(&source.app));

    // From here the restored node validates proposals like any validator,
    // through payments, a new account, a validator registration and the
    // blocks in which the roster changes.
    let mut joined = Node::at(joined, source.height, source.elapsed);
    let step = |source: &mut Node, joined: &mut Node, delta: u64, txs: Vec<Vec<u8>>| {
        let response = source.block(delta, txs.clone());
        assert_eq!(joined.block(delta, txs), response, "height {}", source.height);
        let (request, response) = source.log.last().unwrap();
        assert_eq!(replayed.try_finalize(request.clone()).unwrap(), *response);
        replayed.try_commit().unwrap();
        replayed.write_sync_snapshot().unwrap();
        assert_eq!(info(&joined.app), info(&source.app));
        assert_eq!(info(&replayed), info(&source.app));
    };
    let row = source.account(0);
    let fund = transfer(&row, 1, 5, 2 * pos::SECOND);
    step(&mut source, &mut joined, pos::SECOND, vec![fund]);
    let txs = vec![
        sponsor(&source.account(1), 2, 202, "latecomer", source.elapsed),
        transfer(&source.account(12), 201, 0, 1),
    ];
    step(&mut source, &mut joined, pos::SECOND, txs);
    step(&mut source, &mut joined, 2 * pos::SECOND, vec![reveal(202, "latecomer")]);
    let register = register_validator(&source.account(5), 121);
    step(&mut source, &mut joined, pos::SECOND, vec![register]);
    for _ in 0..8 {
        let row = source.account(2);
        let txs = vec![transfer(&row, 3, 13, 7), transfer(&source.account(3), 4, 12, 5000)];
        step(&mut source, &mut joined, 60 * pos::SECOND, txs);
    }
    assert!(source.height > 30);
    // As a validator: the mempool admits the same transactions, and asked to
    // propose, it proposes the same block.
    let pending = vec![
        transfer(&source.account(12), 201, 0, 1),
        transfer(&source.account(2), 3, 13, 9),
        // Not valid: the same nonce again.
        transfer(&source.account(2), 3, 13, 10),
    ];
    let admitted = |app: &App| -> Vec<u32> {
        pending
            .iter()
            .map(|tx| app.check_tx(RequestCheckTx { tx: tx.clone().into(), r#type: 0 }).code)
            .collect()
    };
    assert_eq!(admitted(&source.app), [0, 0, 1]);
    assert_eq!(admitted(&joined.app), [0, 0, 1]);
    let propose = |node: &Node| {
        let request = node.request(pos::SECOND, vec![]);
        node.app
            .prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: 1 << 20,
                txs: pending.iter().cloned().map(Into::into).collect(),
                local_last_commit: last_commit(request.height).map(|commit| ExtendedCommitInfo {
                    round: commit.round,
                    votes: commit
                        .votes
                        .into_iter()
                        .map(|vote| ExtendedVoteInfo {
                            validator: vote.validator,
                            block_id_flag: vote.block_id_flag,
                            ..Default::default()
                        })
                        .collect(),
                }),
                height: request.height,
                time: request.time,
                ..Default::default()
            })
            .txs
    };
    let proposed = propose(&source);
    assert_eq!(proposed.len(), 2);
    assert_eq!(propose(&joined), proposed);
    assert_eq!(joined.account(13), source.account(13));
    assert_eq!(joined.account(13).name, "latecomer");

    // The same answers to wallets, byte for byte: accounts, staking, and the
    // history proofs of blocks after the restored height.
    let wanted = json!({"ids":["0","4","12","13"],"names":["newcomer","latecomer"],"owners":["4","5"],"candidates":["4","5"],"blocks":["21","24",source.height.to_string()],"include_pos":true,"include_security":true});
    let view = query(&source.app, "/v4/state", &wanted);
    assert_eq!(query(&joined.app, "/v4/state", &wanted), view);
    assert_eq!(query(&replayed, "/v4/state", &wanted), view);
    assert_eq!(view["history_proofs"].as_object().unwrap().len(), 3);
    // What the restored node cannot serve: the history of blocks at or
    // below the restored height. It says so; it serves nothing wrong.
    for height in ["1", "19", "20"] {
        let old = json!({"blocks":[height]});
        query(&source.app, "/v4/state", &old);
        let refused = try_query(&joined.app, "/v4/state", &old).unwrap_err();
        assert!(refused.contains("restored from a snapshot"), "{refused}");
    }

    // Having restored, it offers the very snapshot the others offer for the
    // next agreed height: same chunks, hash and metadata, so CometBFT pools
    // the three nodes as one source.
    let theirs = snapshot_at(&source.app, 30);
    assert_eq!(snapshot_at(&joined.app, 30), theirs);
    assert_eq!(snapshot_at(&replayed, 30), theirs);
    assert_eq!(chunks_of(&joined.app, &theirs), chunks_of(&source.app, &theirs));

    // It dies and restarts from the snapshot it restored, replays the later
    // blocks and is where the others are.
    let (height, elapsed) = (joined.height, joined.elapsed);
    drop(joined);
    let reopened = App::open_with_options(&joined_path, serving()).unwrap();
    assert_eq!(info(&reopened), (20, trusted(&source.log, 20)));
    replay(&reopened, &source.log[20..]);
    assert_eq!(info(&reopened), info(&source.app));
    assert_eq!(query(&reopened, "/v4/state", &wanted), view);
    assert!(try_query(&reopened, "/v4/state", &json!({"blocks":["20"]})).is_err());
    let mut joined = Node::at(reopened, height, elapsed);
    let pay = transfer(&source.account(12), 201, 0, 1);
    assert_eq!(joined.block(pos::SECOND, vec![pay.clone()]), source.block(pos::SECOND, vec![pay]));
    replay(&replayed, &source.log[source.log.len() - 1..]);
    joined.app.snapshot().unwrap().expect("a snapshot of the head");
    replayed.snapshot().unwrap().expect("a snapshot of the head");
    drop(joined);

    // The offline recount passes on the restored node. It recounts the block
    // history it holds, which starts after the restored height.
    let recount = |path: &Path| {
        let engine = engine::Engine::open_with_history(
            Store::open(path.with_extension("v5state")).unwrap(),
            path.with_extension("history"),
        )
        .unwrap();
        (engine.audit().unwrap(), engine.history_base(), engine.head().unwrap().unwrap())
    };
    let (audit, restored_at, head) = recount(&joined_path);
    assert!(audit.history_archive_verified);
    assert_eq!((audit.history_archive_from, restored_at), (21, Some(20)));
    drop(replayed);
    let (full, never, full_head) = recount(&replayed_path);
    assert_eq!((full.history_archive_from, never), (1, None));
    // Everything else the recount finds is the same on both.
    assert_eq!(
        engine::Audit { history_archive_from: 1, ..audit },
        full
    );
    assert_eq!(head, full_head);
    assert_eq!(head.root, source.app.head().unwrap().unwrap().1);
    assert_eq!(head.version, source.height as u64);
}

#[test]
fn hostile_snapshots_chunks_and_offers_are_refused_and_change_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 21);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let file: Vec<u8> = chunks.concat();
    let hash = trusted(&source.log, 20);
    let last = chunks.len() as u32 - 1;

    let path = dir.path().join("joining.db");
    let options = NodeOptions {
        restore_max_bytes: file.len() as u64 + 4096,
        ..NodeOptions::default()
    };
    let app = App::open_with_options(&path, options).unwrap();
    let untouched = disk(&path);
    // After each attempt: no state, no file written, and a chunk sent now
    // has no restore to go to.
    let nothing_happened = |app: &App| {
        assert_eq!(info(app), (0, vec![]));
        assert_eq!(disk(&path), untouched);
        assert_eq!(apply(app, 0, &chunks[0], "late").result, CHUNK_ABORT);
    };

    // --- Offers that are refused outright ---
    // Another format.
    let mut other = snapshot.clone();
    other.format = 2;
    assert_eq!(offer(&app, &other, &hash), OFFER_REJECT_FORMAT);
    // No snapshot, height zero, a height no chain reaches, a hash that is not 32 bytes.
    assert_eq!(app.offer_snapshot(RequestOfferSnapshot { snapshot: None, app_hash: hash.clone().into() }).result, OFFER_REJECT);
    for height in [0, u64::MAX] {
        let mut other = snapshot.clone();
        other.height = height;
        assert_eq!(offer(&app, &other, &hash), OFFER_REJECT);
    }
    assert_eq!(offer(&app, &snapshot, &hash[..31]), OFFER_REJECT);
    assert_eq!(offer(&app, &snapshot, &[]), OFFER_REJECT);
    // Metadata that is not a manifest, or that the hash or the chunk count
    // disagree with: only a dishonest peer advertises that.
    let malformed: Vec<Box<dyn Fn(&mut Snapshot)>> = vec![
        Box::new(|s: &mut Snapshot| s.metadata = Vec::new().into()),
        Box::new(|s: &mut Snapshot| s.metadata = vec![0u8; 60].into()),
        Box::new(|s: &mut Snapshot| s.metadata = s.metadata[..s.metadata.len() - 1].to_vec().into()),
        Box::new(|s: &mut Snapshot| s.metadata = [s.metadata.as_ref(), &[0u8; 32][..]].concat().into()),
        Box::new(|s: &mut Snapshot| s.hash = vec![7u8; 32].into()),
        Box::new(|s: &mut Snapshot| s.hash = Vec::new().into()),
        Box::new(|s: &mut Snapshot| s.chunks += 1),
        Box::new(|s: &mut Snapshot| s.chunks -= 1),
        Box::new(|s: &mut Snapshot| s.chunks = 0),
        Box::new(|s: &mut Snapshot| s.chunks = u32::MAX),
        // A changed chunk hash, with the snapshot hash left as it was.
        Box::new(|s: &mut Snapshot| {
            let mut metadata = s.metadata.to_vec();
            *metadata.last_mut().unwrap() ^= 1;
            s.metadata = metadata.into();
        }),
    ];
    for change in &malformed {
        let mut other = snapshot.clone();
        change(&mut other);
        assert_eq!(offer(&app, &other, &hash), OFFER_REJECT_SENDER);
    }
    // A well-formed manifest that declares another chunk size or length than
    // its hash count allows, with a matching snapshot hash.
    for (total, chunk) in [(file.len() as u64, 512u32), (file.len() as u64, 8 * 1024 * 1024), (u64::MAX, CHUNK), (0, CHUNK), (file.len() as u64 + CHUNK as u64, CHUNK)] {
        let metadata = Manifest {
            total_bytes: total,
            chunk_bytes: chunk,
            chunk_hashes: chunks.iter().map(|chunk| Sha256::digest(chunk).into()).collect(),
        }
        .encode();
        let mut other = snapshot.clone();
        other.hash = metadata_hash(&metadata).to_vec().into();
        other.metadata = metadata.into();
        assert_eq!(offer(&app, &other, &hash), OFFER_REJECT_SENDER, "{total} {chunk}");
    }
    // A snapshot larger than this node restores (--state-sync-max-mib):
    // refused before a byte of it is fetched. Nobody is blamed.
    let (large, _) = advertise(20, &[file.as_slice(), &vec![0u8; 8192][..]].concat());
    assert_eq!(offer(&app, &large, &hash), OFFER_REJECT);
    nothing_happened(&app);

    // --- A chunk that is not the one the manifest names ---
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
    assert_eq!(apply(&app, 0, &chunks[0], "good").result, CHUNK_ACCEPT);
    let flipped = {
        let mut chunk = chunks[1].clone();
        chunk[500] ^= 0x01;
        chunk
    };
    let oversized = [chunks[1].as_slice(), &[0u8][..]].concat();
    let huge = vec![0xabu8; 5 * 1024 * 1024];
    let hostile: [(&str, &[u8]); 6] = [
        ("corrupted", &flipped),
        ("oversized", &oversized),
        ("huge", &huge),
        ("truncated", &chunks[1][..CHUNK as usize - 1]),
        ("empty", &[]),
        ("another chunk's bytes", &chunks[2]),
    ];
    for (what, chunk) in hostile {
        let answer = apply(&app, 1, chunk, what);
        assert_eq!(answer.result, CHUNK_RETRY, "{what}");
        assert_eq!(answer.refetch_chunks, [1], "{what}");
        assert_eq!(answer.reject_senders, [what], "{what}");
    }
    // A sender name of a megabyte is not kept; an empty one is not reported.
    let answer = apply(&app, 1, &flipped, "");
    assert_eq!((answer.result, answer.reject_senders.len()), (CHUNK_RETRY, 0));
    assert_eq!(apply(&app, 1, &chunks[1], &"x".repeat(1 << 20)).result, CHUNK_ACCEPT);
    // Nothing of the bad chunks was written: the staging file holds exactly
    // the two good ones.
    let staging = path.with_extension("v5state").join("restore.tmp");
    assert_eq!(fs::read(&staging).unwrap(), file[..2 * CHUNK as usize]);
    // The same snapshot offered again starts over, and completes: the bad
    // chunks cost their senders, not the snapshot.
    let answer = restore(&app, &snapshot, &chunks, &hash);
    assert_eq!(answer.result, CHUNK_ACCEPT);
    assert_eq!(info(&app), (20, hash.clone()));
    drop(app);
    fs::remove_dir_all(path.with_extension("v5state")).unwrap();
    fs::remove_dir_all(path.with_extension("history")).unwrap();
    let app = App::open_with_options(&path, options).unwrap();
    let untouched = disk(&path);
    let nothing_happened = |app: &App| {
        assert_eq!(info(app), (0, vec![]));
        assert_eq!(disk(&path), untouched);
        assert_eq!(apply(app, 0, &chunks[0], "late").result, CHUNK_ABORT);
    };

    // --- A missing chunk, chunks out of order ---
    // Chunk 1 never comes and chunk 2 is applied in its place.
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
    assert_eq!(apply(&app, 0, &chunks[0], "a").result, CHUNK_ACCEPT);
    let answer = apply(&app, 2, &chunks[2], "b");
    assert_eq!(answer.result, CHUNK_REJECT_SNAPSHOT);
    assert!(answer.reject_senders.is_empty() && answer.refetch_chunks.is_empty());
    nothing_happened(&app);
    // The last chunk first; a chunk twice; an index the snapshot does not have.
    for (first, second) in [(None, last), (Some(0), 0), (Some(0), last + 1), (Some(0), u32::MAX)] {
        assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
        if let Some(index) = first {
            assert_eq!(apply(&app, index, &chunks[index as usize], "a").result, CHUNK_ACCEPT);
        }
        let chunk = chunks.get(second as usize).unwrap_or(&chunks[0]);
        assert_eq!(apply(&app, second, chunk, "b").result, CHUNK_REJECT_SNAPSHOT);
        nothing_happened(&app);
    }
    // All chunks but the last: the node has no state, and stays that way
    // however long the last one takes.
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
    for index in 0..last {
        assert_eq!(apply(&app, index, &chunks[index as usize], "a").result, CHUNK_ACCEPT);
    }
    assert_eq!(info(&app), (0, vec![]));
    assert!(restart_snapshots(&path).is_empty());
    // A chunk with no offer before it, on a fresh process.
    drop(app);
    let app = App::open_with_options(&path, options).unwrap();
    nothing_happened(&app);

    // --- A snapshot that does not hash to the trusted hash ---
    // Honest chunks, but CometBFT's light client says the state of height
    // 20 has another hash (here: that of height 19). The first chunk shows it.
    assert_eq!(offer(&app, &snapshot, &trusted(&source.log, 19)), OFFER_ACCEPT);
    let answer = apply(&app, 0, &chunks[0], "liar");
    assert_eq!(answer.result, CHUNK_REJECT_SNAPSHOT);
    assert_eq!(answer.reject_senders, ["liar"]);
    nothing_happened(&app);
    // The snapshot of height 10 offered as that of height 20.
    let ten = snapshot_at(&source.app, 10);
    let ten_chunks = chunks_of(&source.app, &ten);
    let mut relabelled = ten.clone();
    relabelled.height = 20;
    assert_eq!(offer(&app, &relabelled, &hash), OFFER_ACCEPT);
    let answer = apply(&app, 0, &ten_chunks[0], "liar");
    assert_eq!((answer.result, answer.reject_senders), (CHUNK_REJECT_SNAPSHOT, vec!["liar".to_string()]));
    nothing_happened(&app);
    // Forgeries that keep the true height and root in the header, a valid
    // file checksum and a manifest that matches every chunk. Only the
    // rebuilt tree can tell: each is rejected at the last chunk, with every
    // peer that sent a chunk of it.
    let forgeries: Vec<(&str, Vec<u8>)> = vec![
        ("one balance changed", rewrite(&file, |rows, _| {
            let row = rows.iter_mut().find(|(key, _)| key.starts_with(b"account/")).unwrap();
            let text = String::from_utf8(row.1.clone()).unwrap();
            let changed = text.replacen("\"balance\":\"", "\"balance\":\"9", 1);
            assert_ne!(changed, text);
            row.1 = changed.into_bytes();
        })),
        ("one row removed", rewrite(&file, |rows, leaves| {
            rows.pop();
            *leaves -= 1;
        })),
        ("one row added", rewrite(&file, |rows, leaves| {
            rows.push((b"account/forged".to_vec(), b"{}".to_vec()));
            *leaves += 1;
        })),
        ("rows out of order", rewrite(&file, |rows, _| rows.swap(0, 1))),
        ("a row twice", rewrite(&file, |rows, leaves| {
            rows.push(rows[0].clone());
            *leaves += 1;
        })),
        ("a row count that is not the rows", rewrite(&file, |_, leaves| *leaves += 1)),
        ("an absurd row count", rewrite(&file, |_, leaves| *leaves = u64::MAX / 2)),
        ("no rows", rewrite(&file, |rows, leaves| {
            rows.clear();
            *leaves = 0;
        })),
        ("a wrong checksum", {
            let mut bytes = file.clone();
            *bytes.last_mut().unwrap() ^= 1;
            bytes
        }),
        ("bytes after the checksum", [file.as_slice(), &[0u8; 100][..]].concat()),
        ("cut short", file[..file.len() - 700].to_vec()),
        ("garbage after the header", [&file[..200], &vec![0xffu8; 3000][..]].concat()),
    ];
    for (what, forged) in &forgeries {
        let (forgery, forged_chunks) = advertise(20, forged);
        let answer = restore(&app, &forgery, &forged_chunks, &hash);
        assert_eq!(answer.result, CHUNK_REJECT_SNAPSHOT, "{what}");
        assert_eq!(answer.reject_senders, all_senders(forged_chunks.len()), "{what}");
        assert!(answer.refetch_chunks.is_empty());
        nothing_happened(&app);
    }

    // --- A snapshot of another chain ---
    let mut foreign = Node::start_on(&dir.path().join("foreign.db"), serving(), &other_genesis());
    for _ in 0..10 {
        foreign.block(pos::SECOND, vec![]);
    }
    let foreign_snapshot = snapshot_at(&foreign.app, 10);
    let foreign_chunks = chunks_of(&foreign.app, &foreign_snapshot);
    // CometBFT follows this chain: the hash it trusts for height 10 is this
    // chain's. The other chain's state cannot have it.
    assert_ne!(trusted(&foreign.log, 10), trusted(&source.log, 10));
    assert_eq!(offer(&app, &foreign_snapshot, &trusted(&source.log, 10)), OFFER_ACCEPT);
    let answer = apply(&app, 0, &foreign_chunks[0], "foreigner");
    assert_eq!((answer.result, answer.reject_senders), (CHUNK_REJECT_SNAPSHOT, vec!["foreigner".to_string()]));
    nothing_happened(&app);
    // Its rows under this chain's header, with a checksum that fits:
    // rejected by the rebuilt root.
    let mut grafted = foreign_chunks.concat();
    grafted[24..56].copy_from_slice(&trusted(&source.log, 10));
    let grafted = rewrite(&grafted, |_, _| {});
    let (graft, graft_chunks) = advertise(10, &grafted);
    let answer = restore(&app, &graft, &graft_chunks, &trusted(&source.log, 10));
    assert_eq!(answer.result, CHUNK_REJECT_SNAPSHOT);
    assert_eq!(answer.reject_senders, all_senders(graft_chunks.len()));
    nothing_happened(&app);

    // After all of that the node restores the honest snapshot and follows
    // the chain.
    let answer = restore(&app, &snapshot, &chunks, &hash);
    assert_eq!(answer.result, CHUNK_ACCEPT);
    assert_eq!(info(&app), (20, hash));
    replay(&app, &source.log[20..]);
    assert_eq!(info(&app), info(&source.app));
}

#[test]
fn a_failed_restore_leaves_a_node_with_state_exactly_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let mut source = source(&dir.path().join("source.db"), 24);
    let ten = snapshot_at(&source.app, 10);
    let ten_chunks = chunks_of(&source.app, &ten);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let file: Vec<u8> = chunks.concat();
    let hash = trusted(&source.log, 20);

    // A node with state that may still restore: it restored height 10, and
    // its CometBFT died before recording that. Both processes start again.
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    assert_eq!(restore(&app, &ten, &ten_chunks, &trusted(&source.log, 10)).result, CHUNK_ACCEPT);
    drop(app);
    let app = App::open(&path).unwrap();
    let wanted = json!({"ids":["0","4","12"],"names":["newcomer"],"include_pos":true});
    let before = (info(&app), query(&app, "/v4/state", &wanted), disk(&path));
    assert_eq!(before.0, (10, trusted(&source.log, 10)));
    assert_eq!(restart_snapshots(&path), ["state-00000000000000000010.snap"]);
    let unchanged = |app: &App| {
        assert_eq!(info(app), before.0);
        assert_eq!(query(app, "/v4/state", &wanted), before.1);
        assert_eq!(disk(&path), before.2);
    };

    // A forged snapshot of a later height, complete and self-consistent.
    let forged = rewrite(&file, |rows, _| {
        let row = rows.iter_mut().find(|(key, _)| key.starts_with(b"account/")).unwrap();
        row.1 = String::from_utf8(row.1.clone())
            .unwrap()
            .replacen("\"balance\":\"", "\"balance\":\"9", 1)
            .into_bytes();
    });
    let (forgery, forged_chunks) = advertise(20, &forged);
    let answer = restore(&app, &forgery, &forged_chunks, &hash);
    assert_eq!(answer.result, CHUNK_REJECT_SNAPSHOT);
    assert_eq!(answer.reject_senders, all_senders(forged_chunks.len()));
    unchanged(&app);
    // A restore abandoned half way, one dropped for a wrong first chunk, one
    // for a chunk out of order.
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
    for index in 0..chunks.len() / 2 {
        assert_eq!(apply(&app, index as u32, &chunks[index], "a").result, CHUNK_ACCEPT);
    }
    assert_eq!(info(&app), before.0);
    assert_eq!(query(&app, "/v4/state", &wanted), before.1);
    assert_eq!(offer(&app, &snapshot, &trusted(&source.log, 19)), OFFER_ACCEPT);
    assert_eq!(apply(&app, 0, &chunks[0], "a").result, CHUNK_REJECT_SNAPSHOT);
    unchanged(&app);
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
    assert_eq!(apply(&app, 3, &chunks[3], "a").result, CHUNK_REJECT_SNAPSHOT);
    unchanged(&app);
    // A snapshot of an earlier height, or of the node's own height with
    // another hash, is not taken: a node never goes back or sideways.
    let (earlier, _) = advertise(9, &file);
    assert_eq!(offer(&app, &earlier, &trusted(&source.log, 9)), OFFER_REJECT);
    assert_eq!(offer(&app, &ten, &trusted(&source.log, 9)), OFFER_REJECT);
    unchanged(&app);
    // The snapshot it already holds, offered again (what its CometBFT does
    // when it starts over): accepted, every chunk taken, nothing changed.
    let answer = restore(&app, &ten, &ten_chunks, &trusted(&source.log, 10));
    assert_eq!(answer.result, CHUNK_ACCEPT);
    assert!(answer.reject_senders.is_empty() && answer.refetch_chunks.is_empty());
    unchanged(&app);
    // An authentic snapshot of another network, with the hash its own chain
    // has (a CometBFT pointed at the wrong chain): every check on the
    // snapshot passes, and the node still refuses to give up its state.
    let mut foreign = Node::start_on(&dir.path().join("foreign.db"), serving(), &other_genesis());
    for _ in 0..20 {
        foreign.block(pos::SECOND, vec![]);
    }
    let foreign_snapshot = snapshot_at(&foreign.app, 20);
    let answer = restore(&app, &foreign_snapshot, &chunks_of(&foreign.app, &foreign_snapshot), &trusted(&foreign.log, 20));
    assert_eq!(answer.result, CHUNK_ABORT);
    assert!(answer.reject_senders.is_empty());
    unchanged(&app);

    // After all of that it restores the honest snapshot of height 20. The
    // snapshot of height 10 goes: CometBFT could not replay from it.
    assert_eq!(restore(&app, &snapshot, &chunks, &hash).result, CHUNK_ACCEPT);
    assert_eq!(info(&app), (20, hash.clone()));
    assert_eq!(restart_snapshots(&path), ["state-00000000000000000020.snap"]);
    let records = |path: &Path| -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(path.with_extension("history"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("restored-"))
            .collect();
        names.sort();
        names
    };
    assert_eq!(records(&path), ["restored-00000000000000000020.json"]);
    replay(&app, &source.log[20..]);
    assert_eq!(info(&app), info(&source.app));
    assert!(try_query(&app, "/v4/state", &json!({"blocks":["9"]})).is_err());
    assert!(try_query(&app, "/v4/state", &json!({"blocks":["15"]})).is_err());
    let recent = json!({"blocks":["21","24"]});
    assert_eq!(query(&app, "/v4/state", &recent), query(&source.app, "/v4/state", &recent));

    // It executes blocks now. From here on it takes no snapshot, whoever
    // asks and whatever is offered: not in this process ...
    while source.height < 31 {
        source.busy_block();
    }
    let later = snapshot_at(&source.app, 30);
    let later_chunks = chunks_of(&source.app, &later);
    let executing = (info(&app), disk(&path));
    assert_eq!(offer(&app, &later, &trusted(&source.log, 30)), OFFER_ABORT);
    assert_eq!(apply(&app, 0, &later_chunks[0], "a").result, CHUNK_ABORT);
    assert_eq!((info(&app), disk(&path)), executing);
    // ... and not after a restart, because what it holds it built itself.
    app.snapshot().unwrap().unwrap();
    drop(app);
    let app = App::open(&path).unwrap();
    assert_eq!(info(&app), info_at(&source.log, 24));
    let built = disk(&path);
    assert_eq!(offer(&app, &later, &trusted(&source.log, 30)), OFFER_ABORT);
    assert_eq!(apply(&app, 0, &later_chunks[0], "a").result, CHUNK_ABORT);
    assert_eq!((info(&app), disk(&path)), (info_at(&source.log, 24), built));
    // The offline recount of that node passes, from the restored height on.
    drop(app);
    let engine = engine::Engine::open_with_history(
        Store::open(path.with_extension("v5state")).unwrap(),
        path.with_extension("history"),
    )
    .unwrap();
    assert_eq!(engine.head().unwrap().unwrap().version, 24);
    assert_eq!(engine.history_base(), Some(20));
    assert!(engine.restorable().is_err());
    let audit = engine.audit().unwrap();
    assert!(audit.history_archive_verified);
    assert_eq!(audit.history_archive_from, 21);
}

#[test]
fn a_node_that_has_executed_blocks_keeps_its_state_and_its_history() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 24);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let hash = trusted(&source.log, 20);
    // A node that executed the first 14 blocks itself, stopped, and is
    // started again with a CometBFT that state-syncs.
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    app.try_init(init(&genesis_v5())).unwrap();
    replay(&app, &source.log[..14]);
    app.snapshot().unwrap().unwrap();
    drop(app);
    let app = App::open(&path).unwrap();
    let wanted = json!({"ids":["0","4","12"],"names":["newcomer"],"blocks":["1","9","14"],"include_pos":true});
    let before = (info(&app), query(&app, "/v4/state", &wanted), disk(&path));
    assert_eq!(before.0, info_at(&source.log, 14));
    // The honest snapshot of a later height is refused before a byte of it
    // is fetched: the node would lose the block history it recorded.
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ABORT);
    assert_eq!(apply(&app, 0, &chunks[0], "a").result, CHUNK_ABORT);
    assert_eq!((info(&app), query(&app, "/v4/state", &wanted), disk(&path)), before);
    // An earlier height is refused as on any node.
    assert_eq!(offer(&app, &snapshot_at(&source.app, 10), &trusted(&source.log, 10)), OFFER_REJECT);
    // Its own height and hash, though, is what it holds: accepted, every
    // chunk taken, and nothing replaced (its history proofs are still served).
    let options = NodeOptions {
        sync_snapshot_blocks: 14,
        sync_chunk_bytes: CHUNK,
        ..NodeOptions::default()
    };
    let twin = App::open_with_options(dir.path().join("twin.db"), options).unwrap();
    twin.try_init(init(&genesis_v5())).unwrap();
    replay(&twin, &source.log[..14]);
    twin.write_sync_snapshot().unwrap().unwrap();
    let own = snapshot_at(&twin, 14);
    let own_chunks = chunks_of(&twin, &own);
    assert_eq!(restore(&app, &own, &own_chunks, &trusted(&source.log, 14)).result, CHUNK_ACCEPT);
    assert_eq!((info(&app), query(&app, "/v4/state", &wanted), disk(&path)), before);
    // It goes on executing.
    replay(&app, &source.log[14..]);
    assert_eq!(info(&app), info(&source.app));

    // A restore is over the moment the node executes a block: here one
    // arrives while chunks are still coming.
    let joining = App::open(dir.path().join("joining.db")).unwrap();
    joining.try_init(init(&genesis_v5())).unwrap();
    assert_eq!(offer(&joining, &snapshot, &hash), OFFER_ACCEPT);
    assert_eq!(apply(&joining, 0, &chunks[0], "a").result, CHUNK_ACCEPT);
    replay(&joining, &source.log[..2]);
    assert_eq!(apply(&joining, 1, &chunks[1], "a").result, CHUNK_ABORT);
    assert_eq!(apply(&joining, 2, &chunks[2], "a").result, CHUNK_ABORT);
    assert_eq!(info(&joining), info_at(&source.log, 2));
    assert!(!dir.path().join("joining.v5state").join("restore.tmp").exists());
    assert_eq!(offer(&joining, &snapshot, &hash), OFFER_ABORT);
}

#[test]
fn a_node_at_genesis_restores_and_a_stopped_restore_leaves_a_node_that_starts() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 22);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let hash = trusted(&source.log, 20);
    // The node ran InitChain once (started without state sync), then its
    // operator turned state sync on.
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    app.try_init(init(&genesis_v5())).unwrap();
    let genesis_root = info(&app);
    assert_eq!(genesis_root.0, 0);
    // The process dies with half the chunks staged.
    assert_eq!(offer(&app, &snapshot, &hash), OFFER_ACCEPT);
    for index in 0..chunks.len() / 2 {
        assert_eq!(apply(&app, index as u32, &chunks[index], "a").result, CHUNK_ACCEPT);
    }
    assert!(path.with_extension("v5state").join("restore.tmp").exists());
    drop(app);
    let app = App::open(&path).unwrap();
    assert_eq!(info(&app), genesis_root);
    assert!(!path.with_extension("v5state").join("restore.tmp").exists());
    // Nothing of the earlier attempt is resumed: a chunk needs a new offer.
    assert_eq!(apply(&app, 0, &chunks[0], "a").result, CHUNK_ABORT);
    assert_eq!(restore(&app, &snapshot, &chunks, &hash).result, CHUNK_ACCEPT);
    assert_eq!(info(&app), (20, hash));
    assert_eq!(restart_snapshots(&path), ["state-00000000000000000020.snap"]);
    // What the restore wrote for the block history, before any later block.
    let prepared = disk(&path);
    replay(&app, &source.log[20..]);
    assert_eq!(info(&app), info(&source.app));
    // InitChain is not accepted on top of it.
    assert!(app.try_init(init(&genesis_v5())).is_err());

    // A restore that stopped after the history archive was prepared and
    // before the state was installed: the archive directory as the restore
    // left it, and no state. The node then starts from genesis after all and
    // executes every block. Nothing of the unfinished restore describes it,
    // and it serves the whole block history.
    let late = dir.path().join("late.db");
    fs::create_dir_all(late.with_extension("history")).unwrap();
    let mut copied = 0;
    for (name, bytes) in &prepared {
        if name.starts_with("node.history") {
            fs::write(late.with_extension("history").join(name.file_name().unwrap()), bytes).unwrap();
            copied += 1;
        }
    }
    assert_eq!(copied, 3, "leaves, nodes and the restore record");
    assert!(late.with_extension("history").join("restored-00000000000000000020.json").exists());
    let app = App::open(&late).unwrap();
    assert_eq!(info(&app), (0, vec![]));
    app.try_init(init(&genesis_v5())).unwrap();
    replay(&app, &source.log);
    assert_eq!(info(&app), info(&source.app));
    let old = json!({"blocks":["1","19","20","21"]});
    assert_eq!(query(&app, "/v4/state", &old), query(&source.app, "/v4/state", &old));
    app.snapshot().unwrap().unwrap();
    drop(app);
    let engine = engine::Engine::open_with_history(
        Store::open(late.with_extension("v5state")).unwrap(),
        late.with_extension("history"),
    )
    .unwrap();
    assert_eq!(engine.history_base(), None);
    assert_eq!(engine.audit().unwrap().history_archive_from, 1);
}

#[test]
fn snapshots_for_peers_are_separate_from_restart_snapshots_and_rotate() {
    let dir = tempfile::tempdir().unwrap();
    // A node without the setting offers nothing and writes nothing extra.
    let quiet_path = dir.path().join("quiet.db");
    let mut quiet = Node::start(&quiet_path, NodeOptions::default());
    for _ in 0..12 {
        quiet.block(pos::SECOND, vec![]);
    }
    assert!(offered(&quiet.app).is_empty());
    assert!(quiet.app.write_sync_snapshot().unwrap().is_none());
    assert!(!quiet_path.with_extension("v5state").join("statesync").exists());
    assert!(quiet.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 10, format: SYNC_FORMAT, chunk: 0 }).chunk.is_empty());

    let path = dir.path().join("node.db");
    let options = NodeOptions {
        sync_snapshots_kept: 3,
        ..serving()
    };
    let mut node = Node::start(&path, options);
    let sync_files = |path: &Path| -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(path.with_extension("v5state").join("statesync"))
            .map(|entries| entries.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        names.sort();
        names
    };
    for _ in 0..9 {
        node.block(pos::SECOND, vec![]);
    }
    assert!(offered(&node.app).is_empty());
    // The timer's snapshots (--snapshot-seconds) go on as before, at
    // whatever height the timer finds: they are never offered.
    node.app.snapshot().unwrap().unwrap();
    assert!(offered(&node.app).is_empty());
    for _ in 9..45 {
        node.block(pos::SECOND, vec![]);
    }
    node.app.snapshot().unwrap().unwrap();
    // The three newest multiples of ten, each a snapshot and its manifest.
    let heights = |app: &App| offered(app).iter().map(|s| s.height).collect::<Vec<_>>();
    assert_eq!(heights(&node.app), [20, 30, 40]);
    assert_eq!(sync_files(&path), [
        "state-00000000000000000020.manifest", "state-00000000000000000020.snap",
        "state-00000000000000000030.manifest", "state-00000000000000000030.snap",
        "state-00000000000000000040.manifest", "state-00000000000000000040.snap",
    ]);
    // The restart snapshots are the two newest the timer wrote.
    assert_eq!(restart_snapshots(&path), ["state-00000000000000000009.snap", "state-00000000000000000045.snap"]);
    // Every offered snapshot is the state of its height: its chunks,
    // reassembled, load as a snapshot whose root is that block's hash.
    for snapshot in offered(&node.app) {
        let file = chunks_of(&node.app, &snapshot).concat();
        assert_eq!(file.len() as u64, Manifest::decode(&snapshot.metadata).unwrap().total_bytes);
        assert_eq!(file[16..24], snapshot.height.to_be_bytes());
        assert_eq!(file[24..56], trusted(&node.log, snapshot.height)[..]);
    }
    // Chunks that do not exist are "missing", not an error or a panic.
    for (height, format, chunk) in [(40, SYNC_FORMAT, u32::MAX), (40, SYNC_FORMAT, 10_000), (40, 2, 0), (10, SYNC_FORMAT, 0), (41, SYNC_FORMAT, 0), (u64::MAX, SYNC_FORMAT, 0)] {
        assert!(node.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height, format, chunk }).chunk.is_empty());
    }
    // A restart offers the same snapshots again and removes what an
    // interrupted write or a lost manifest left behind.
    let before = offered(&node.app);
    let (height, elapsed) = (node.height, node.elapsed);
    drop(node);
    let sync = path.with_extension("v5state").join("statesync");
    fs::write(sync.join("partial-00000000000000000050-1.tmp"), b"half").unwrap();
    fs::write(sync.join("state-00000000000000000050.snap"), b"no manifest").unwrap();
    fs::write(sync.join("state-00000000000000000060.manifest"), b"no snapshot").unwrap();
    let app = App::open_with_options(&path, options).unwrap();
    assert_eq!(offered(&app), before);
    assert_eq!(sync_files(&path).len(), 6);
    // A snapshot damaged on disk is not served: the chunk is missing, and
    // the snapshot is no longer offered.
    let damaged = sync.join("state-00000000000000000030.snap");
    let mut bytes = fs::read(&damaged).unwrap();
    bytes[1500] ^= 0x10;
    fs::write(&damaged, bytes).unwrap();
    assert!(!app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 30, format: SYNC_FORMAT, chunk: 0 }).chunk.is_empty());
    assert!(app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 30, format: SYNC_FORMAT, chunk: 1 }).chunk.is_empty());
    assert_eq!(heights(&app), [20, 40]);
    // Its files are gone, so a restart does not offer it again; asking for
    // it again, any number of times, is a miss like any other.
    assert!(!damaged.exists() && !damaged.with_extension("manifest").exists());
    for chunk in 0..1000 {
        assert!(app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 30, format: SYNC_FORMAT, chunk }).chunk.is_empty());
    }
    // The chain goes on and the rotation with it.
    let mut node = Node::at(app, height, elapsed);
    for _ in 45..61 {
        node.block(pos::SECOND, vec![]);
    }
    assert_eq!(heights(&node.app), [40, 50, 60]);
    // Turned off again, the node offers nothing; the files stay on disk for
    // the operator to remove.
    drop(node);
    let app = App::open(&path).unwrap();
    assert!(offered(&app).is_empty());
    assert!(sync.join("state-00000000000000000060.snap").exists());
}

#[test]
fn retain_height_stays_zero_by_default_and_follows_what_the_node_still_needs() {
    let dir = tempfile::tempdir().unwrap();
    // The default: every Commit answers 0, CometBFT keeps every block.
    let mut plain = Node::start(&dir.path().join("plain.db"), NodeOptions::default());
    // A node asked to keep the last 2,000,000 blocks and to offer snapshots.
    let options = NodeOptions {
        keep_blocks: EVIDENCE_MAX_AGE_BLOCKS,
        ..serving()
    };
    let path = dir.path().join("pruning.db");
    let mut node = Node::start(&path, options);
    let inputs = node.app.retain_inputs().unwrap();
    assert_eq!(
        inputs,
        RetainInputs {
            keep_blocks: EVIDENCE_MAX_AGE_BLOCKS,
            head: 0,
            // InitChain saved the genesis state.
            oldest_snapshot: Some(0),
            oldest_sync_snapshot: None,
            older_than_evidence_time: 0,
        }
    );
    for _ in 0..5 {
        plain.block(pos::SECOND, vec![]);
        node.block(pos::SECOND, vec![]);
    }
    // Fifteen days pass in one block: the first blocks are now older than
    // the 14 days evidence may reach back, by time.
    plain.block(15 * pos::DAY, vec![]);
    node.block(15 * pos::DAY, vec![]);
    for _ in 6..27 {
        plain.block(pos::SECOND, vec![]);
        node.block(pos::SECOND, vec![]);
    }
    let inputs = node.app.retain_inputs().unwrap();
    assert_eq!(inputs.head, 27);
    // Blocks 1 to 5 are more than 14 days old; block 6 and later are not.
    assert_eq!(inputs.older_than_evidence_time, 5);
    assert_eq!(inputs.oldest_snapshot, Some(0));
    assert_eq!(inputs.oldest_sync_snapshot, Some(10));
    // The restart snapshots move on with the timer; two are kept, and the
    // older of them is what a restart may need.
    node.app.snapshot().unwrap().unwrap();
    assert_eq!(node.app.retain_inputs().unwrap().oldest_snapshot, Some(0));
    node.block(pos::SECOND, vec![]);
    node.app.snapshot().unwrap().unwrap();
    assert_eq!(node.app.retain_inputs().unwrap().oldest_snapshot, Some(27));
    for _ in 28..33 {
        node.block(pos::SECOND, vec![]);
    }
    // Two snapshots for peers are kept: 20 and 30.
    let inputs = node.app.retain_inputs().unwrap();
    assert_eq!((inputs.oldest_snapshot, inputs.oldest_sync_snapshot), (Some(27), Some(20)));
    // On a chain this short everything is inside the evidence window of
    // 2,000,000 blocks: nothing is ever pruned, on either node.
    assert_eq!(retain_height(&inputs), 0);
    assert!(node.retained.iter().all(|retain| *retain == 0), "{:?}", node.retained);
    assert!(plain.retained.iter().all(|retain| *retain == 0));
    assert_eq!(plain.app.retain_inputs().unwrap().keep_blocks, 0);

    // The same node, many blocks later (only the height is imagined; what
    // it holds is real). Each need, in turn, is what decides.
    let later = |inputs: RetainInputs| RetainInputs {
        head: 9_000_000,
        ..inputs
    };
    // Evidence by time: blocks 6 and later are not yet 14 days old.
    assert_eq!(retain_height(&later(inputs)), 6);
    let old = RetainInputs {
        older_than_evidence_time: 8_000_000,
        ..later(inputs)
    };
    // Its oldest snapshot for peers (20), then its oldest restart snapshot
    // (27), then the evidence window by blocks, then the setting itself.
    assert_eq!(retain_height(&old), 20);
    assert_eq!(retain_height(&RetainInputs { oldest_sync_snapshot: None, ..old }), 27);
    let fresh = RetainInputs {
        oldest_sync_snapshot: Some(8_999_000),
        oldest_snapshot: Some(8_999_990),
        ..old
    };
    assert_eq!(retain_height(&fresh), 9_000_000 - EVIDENCE_MAX_AGE_BLOCKS);
    assert_eq!(retain_height(&RetainInputs { keep_blocks: 3_000_000, ..fresh }), 6_000_001);
    // And the default, on that same long chain: still nothing.
    assert_eq!(retain_height(&RetainInputs { keep_blocks: 0, ..fresh }), 0);

    // A node restored from a snapshot needs the blocks after the restored
    // height, and says so.
    let snapshot = snapshot_at(&node.app, 30);
    let chunks = chunks_of(&node.app, &snapshot);
    let joined = App::open_with_options(&dir.path().join("joined.db"), options).unwrap();
    assert!(joined.retain_inputs().is_err());
    assert_eq!(restore(&joined, &snapshot, &chunks, &trusted(&node.log, 30)).result, CHUNK_ACCEPT);
    replay(&joined, &node.log[30..]);
    let inputs = joined.retain_inputs().unwrap();
    assert_eq!(
        (inputs.head, inputs.oldest_snapshot, inputs.oldest_sync_snapshot, inputs.older_than_evidence_time),
        (33, Some(30), None, 5)
    );
    assert_eq!(retain_height(&RetainInputs { older_than_evidence_time: 8_000_000, ..later(inputs) }), 30);
}

#[test]
fn the_chunk_size_of_the_node_binary_restores_too() {
    // The other tests cut snapshots into 1 KiB chunks. With the 4 MiB the
    // node binary uses, the small state of a test is a single chunk.
    let dir = tempfile::tempdir().unwrap();
    let options = NodeOptions {
        sync_snapshot_blocks: EVERY,
        ..NodeOptions::default()
    };
    let mut node = Node::start(&dir.path().join("source.db"), options);
    for _ in 0..12 {
        node.block(pos::SECOND, vec![]);
    }
    let snapshot = snapshot_at(&node.app, 10);
    let manifest = Manifest::decode(&snapshot.metadata).unwrap();
    assert_eq!((snapshot.chunks, manifest.chunk_bytes), (1, 4 * 1024 * 1024));
    let chunks = chunks_of(&node.app, &snapshot);
    assert_eq!(chunks[0].len() as u64, manifest.total_bytes);
    let joined = App::open(dir.path().join("joined.db")).unwrap();
    assert_eq!(restore(&joined, &snapshot, &chunks, &trusted(&node.log, 10)).result, CHUNK_ACCEPT);
    assert_eq!(info(&joined), (10, trusted(&node.log, 10)));
    replay(&joined, &node.log[10..]);
    assert_eq!(info(&joined), info(&node.app));
}

// ---------------------------------------------------------------------
// Tests from the independent review of this branch, as they came.
// ---------------------------------------------------------------------
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

/// CometBFT 0.38.26 hands the application whatever a peer sent as a chunk:
/// `statesync/chunks.go` `chunkQueue.Add` checks height, format and index,
/// not the size and not who was asked, and a chunk message may be 16 MB
/// (`statesync/messages.go` `chunkMsgSize`). The application's transport
/// refuses any frame above 8 MiB by closing the connection, and CometBFT
/// stops itself when an ABCI connection ends (`proxy/multi_app_conn.go`
/// `killTMOnClientError`).
#[test]
fn review_a_chunk_a_peer_may_send_must_be_answered_not_end_the_abci_connection() {
    let dir = tempfile::tempdir().unwrap();
    // A source with the node binary's chunk size, and its snapshot at height 10.
    let options = NodeOptions { sync_snapshot_blocks: EVERY, ..NodeOptions::default() };
    let mut source = Node::start(&dir.path().join("source.db"), options);
    for _ in 0..10 {
        source.block(pos::SECOND, vec![]);
    }
    let snapshot = snapshot_at(&source.app, 10);
    let chunks = chunks_of(&source.app, &snapshot);
    let hash = trusted(&source.log, 10);

    // The joining node, behind the real ABCI transport.
    let joiner = App::open_with_options(dir.path().join("joiner.db"), NodeOptions::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let gone = Arc::new(AtomicBool::new(false));
    let (served, flag) = (joiner.clone(), gone.clone());
    std::thread::spawn(move || {
        timecurrency_v5::transport::serve(addr, served, move || flag.store(true, Ordering::SeqCst)).unwrap()
    });
    let mut snapshot_conn = connect(addr);

    // CometBFT offers the honest snapshot; the node accepts.
    let offered = call(
        &mut snapshot_conn,
        request::Value::OfferSnapshot(RequestOfferSnapshot {
            snapshot: Some(snapshot.clone()),
            app_hash: hash.clone().into(),
        }),
    )
    .unwrap();
    assert!(matches!(offered, response::Value::OfferSnapshot(ref r) if r.result == OFFER_ACCEPT), "{offered:?}");

    // A peer's junk of 5 MiB: answered, refetched, sender rejected. Fine.
    let answered = call(
        &mut snapshot_conn,
        request::Value::ApplySnapshotChunk(RequestApplySnapshotChunk {
            index: 0,
            chunk: vec![0xabu8; 5 * 1024 * 1024].into(),
            sender: "attacker".into(),
        }),
    )
    .unwrap();
    match answered {
        response::Value::ApplySnapshotChunk(r) => {
            assert_eq!(r.result, CHUNK_RETRY);
            assert_eq!(r.reject_senders, ["attacker"]);
        }
        other => panic!("{other:?}"),
    }

    // The same peer's junk of 9 MiB, which CometBFT accepts from any peer
    // and passes on: the node must answer this one too.
    let answered = call(
        &mut snapshot_conn,
        request::Value::ApplySnapshotChunk(RequestApplySnapshotChunk {
            index: 0,
            chunk: vec![0xabu8; 9 * 1024 * 1024].into(),
            sender: "attacker".into(),
        }),
    );
    std::thread::sleep(Duration::from_millis(300));
    eprintln!(
        "answer to a 9 MiB chunk: {:?}; node told that its consensus engine is gone: {}",
        answered.as_ref().map(|_| "an answer").map_err(|error| error.to_string()),
        gone.load(Ordering::SeqCst)
    );
    // The honest chunk would still have restored the node.
    let _ = chunks;
    assert!(
        answered.is_ok(),
        "the ABCI snapshot connection was closed instead of answering: {:?}",
        answered.err()
    );
}

/// The process dies after the application installed the snapshot and before
/// CometBFT recorded its own state (`node/node.go` `startStateSync`:
/// `Sync`, then `stateStore.Bootstrap`). On the next start CometBFT is at
/// height 0 again and state-syncs again.
#[test]
fn review_a_restore_cometbft_did_not_record_can_be_offered_again() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 21);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let hash = trusted(&source.log, 20);
    let path = dir.path().join("joiner.db");
    let joiner = App::open_with_options(&path, NodeOptions::default()).unwrap();
    assert_eq!(restore(&joiner, &snapshot, &chunks, &hash).result, CHUNK_ACCEPT);
    drop(joiner); // both processes die here
    let joiner = App::open_with_options(&path, NodeOptions::default()).unwrap();
    assert_eq!(info(&joiner), (20, hash.clone()));
    // CometBFT, at height 0, offers the best snapshot it finds: the same one.
    let again = offer(&joiner, &snapshot, &hash);
    let older = offer(&joiner, &snapshot_at(&source.app, 10), &trusted(&source.log, 10));
    eprintln!("same snapshot offered again: result {again} (1 = ACCEPT, 3 = REJECT); the older one: {older}");
    assert_eq!(again, OFFER_ACCEPT, "the node holds exactly this height and hash, and refuses it");
}

/// A node in the middle of executing blocks (block 22 finalized, not yet
/// committed) is handed, over ABCI, a snapshot of another history of the
/// same network at a later height, with that history's hash as the
/// "trusted" one. Everything in the request comes from the caller.
#[test]
fn review_a_node_that_is_executing_blocks_refuses_a_restore() {
    let dir = tempfile::tempdir().unwrap();
    let running = source(&dir.path().join("running.db"), 21);
    let mut other = Node::start(&dir.path().join("other.db"), serving());
    for _ in 0..30 {
        other.block(7 * pos::SECOND, vec![]);
    }
    let snapshot = snapshot_at(&other.app, 30);
    let chunks = chunks_of(&other.app, &snapshot);
    let hash = trusted(&other.log, 30);
    let before = info(&running.app);
    let request = running.request(pos::SECOND, vec![]);
    running.app.try_finalize(request).unwrap();
    let offered = offer(&running.app, &snapshot, &hash);
    let mut last = ResponseApplySnapshotChunk::default();
    if offered == OFFER_ACCEPT {
        for (index, chunk) in chunks.iter().enumerate() {
            last = apply(&running.app, index as u32, chunk, "caller");
        }
    }
    let after = info(&running.app);
    eprintln!(
        "before: height {} root {}; offer answered {offered}, last chunk {}; after: height {} root {} (the other history's root at 30: {})",
        before.0,
        hex::encode(&before.1),
        last.result,
        after.0,
        hex::encode(&after.1),
        hex::encode(&hash)
    );
    assert_eq!(after, before, "the state of a running node was replaced");
}

// ---------------------------------------------------------------------
// Added with the fix for the review's first finding.
// ---------------------------------------------------------------------

/// The largest chunk a peer can make CometBFT hand to the application, over
/// the real transport: a chunk message is at most 16,000,000 bytes
/// (`statesync/messages.go`, `chunkMsgSize`), so the chunk in it is a few
/// bytes less. It is answered, its sender is rejected, and the restore goes
/// on with the honest chunk on the same connection. Only a frame no chunk
/// message can produce still ends a connection.
#[test]
fn the_largest_chunk_a_peer_can_send_is_answered_and_the_restore_goes_on() {
    use timecurrency_v5::transport::{MAX_FRAME_BYTES, MAX_REQUEST_FRAME_BYTES};
    const CHUNK_MESSAGE_BYTES: usize = 16_000_000;
    let dir = tempfile::tempdir().unwrap();
    let options = NodeOptions { sync_snapshot_blocks: EVERY, ..NodeOptions::default() };
    let mut source = Node::start(&dir.path().join("source.db"), options);
    for _ in 0..12 {
        source.block(pos::SECOND, vec![]);
    }
    let snapshot = snapshot_at(&source.app, 10);
    let chunks = chunks_of(&source.app, &snapshot);
    assert_eq!(chunks.len(), 1);
    let hash = trusted(&source.log, 10);

    let joiner = App::open_with_options(dir.path().join("joiner.db"), NodeOptions::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let gone = Arc::new(AtomicBool::new(false));
    let (served, flag) = (joiner.clone(), gone.clone());
    std::thread::spawn(move || {
        timecurrency_v5::transport::serve(addr, served, move || flag.store(true, Ordering::SeqCst)).unwrap()
    });
    let mut connection = connect(addr);
    let offered = call(
        &mut connection,
        request::Value::OfferSnapshot(RequestOfferSnapshot {
            snapshot: Some(snapshot.clone()),
            app_hash: hash.clone().into(),
        }),
    )
    .unwrap();
    assert!(matches!(offered, response::Value::OfferSnapshot(ref r) if r.result == OFFER_ACCEPT), "{offered:?}");

    // Junk of every size up to the largest a chunk message can carry, from
    // a peer with a node id of the usual 40 characters.
    let peer = "f".repeat(40);
    for size in [MAX_FRAME_BYTES - 100, MAX_FRAME_BYTES, MAX_FRAME_BYTES + 1, 12_000_000, CHUNK_MESSAGE_BYTES] {
        let request = Request {
            value: Some(request::Value::ApplySnapshotChunk(RequestApplySnapshotChunk {
                index: 0,
                chunk: vec![0x5au8; size].into(),
                sender: peer.clone(),
            })),
        };
        assert!(request.encoded_len() <= MAX_REQUEST_FRAME_BYTES, "{size}");
        let answered = call(&mut connection, request.value.unwrap()).unwrap_or_else(|error| {
            panic!("a chunk of {size} bytes ended the connection: {error}")
        });
        match answered {
            response::Value::ApplySnapshotChunk(r) => {
                assert_eq!(r.result, CHUNK_RETRY, "{size}");
                assert_eq!(r.refetch_chunks, [0], "{size}");
                assert_eq!(r.reject_senders, [peer.clone()], "{size}");
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(!gone.load(Ordering::SeqCst));
    // Nothing of it was kept, and the honest chunk restores the node.
    assert_eq!(fs::metadata(dir.path().join("joiner.v5state").join("restore.tmp")).unwrap().len(), 0);
    let answered = call(
        &mut connection,
        request::Value::ApplySnapshotChunk(RequestApplySnapshotChunk {
            index: 0,
            chunk: chunks[0].clone().into(),
            sender: "honest".into(),
        }),
    )
    .unwrap();
    assert!(matches!(answered, response::Value::ApplySnapshotChunk(ref r) if r.result == CHUNK_ACCEPT), "{answered:?}");
    match call(&mut connection, request::Value::Info(RequestInfo::default())).unwrap() {
        response::Value::Info(r) => assert_eq!((r.last_block_height, r.last_block_app_hash.to_vec()), (10, hash)),
        other => panic!("{other:?}"),
    }
    assert_eq!(info(&joiner).0, 10);

    // A frame longer than any request CometBFT can make is still refused
    // before it is read: the length prefix alone ends that connection.
    let mut other = connect(addr);
    let mut prefix = Vec::new();
    let mut left = MAX_REQUEST_FRAME_BYTES as u64 + 1;
    while left >= 0x80 {
        prefix.push((left as u8 & 0x7f) | 0x80);
        left >>= 7;
    }
    prefix.push(left as u8);
    other.write_all(&prefix).unwrap();
    let _ = other.write_all(&[0u8; 1024]);
    assert!(read_response(&mut other).is_err());
    // The first connection is not affected.
    assert!(matches!(
        call(&mut connection, request::Value::Info(RequestInfo::default())).unwrap(),
        response::Value::Info(_)
    ));
}

/// The recount honours the record of a restore only beside an archive that
/// holds no entry at or below its height. The check made when a node starts
/// looks at the first and the last of those entries only; the recount looks
/// at all of them.
#[test]
fn the_recount_ignores_a_restore_record_beside_an_archive_that_holds_older_entries() {
    use std::io::{Seek, SeekFrom};
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 24);
    let snapshot = snapshot_at(&source.app, 20);
    let chunks = chunks_of(&source.app, &snapshot);
    let offline = |path: &Path| {
        engine::Engine::open_with_history(
            Store::open(path.with_extension("v5state")).unwrap(),
            path.with_extension("history"),
        )
        .unwrap()
    };
    // Writes over the archive's entry of one height (40 bytes, after a
    // header of 40).
    let overwrite = |path: &Path, height: u64, bytes: [u8; 40]| {
        let mut leaves = fs::OpenOptions::new()
            .write(true)
            .open(path.with_extension("history").join("leaves.bin"))
            .unwrap();
        leaves.seek(SeekFrom::Start(40 + (height - 1) * 40)).unwrap();
        leaves.write_all(&bytes).unwrap();
    };
    // A restored node: its recount passes, from the block after the restore.
    let restored = dir.path().join("restored.db");
    let app = App::open(&restored).unwrap();
    assert_eq!(restore(&app, &snapshot, &chunks, &trusted(&source.log, 20)).result, CHUNK_ACCEPT);
    replay(&app, &source.log[20..]);
    app.snapshot().unwrap().unwrap();
    drop(app);
    assert_eq!(offline(&restored).audit().unwrap().history_archive_from, 21);
    // A node that executed every block: its recount passes, from block 1.
    let full = dir.path().join("full.db");
    let app = App::open(&full).unwrap();
    app.try_init(init(&genesis_v5())).unwrap();
    replay(&app, &source.log);
    app.snapshot().unwrap().unwrap();
    drop(app);
    assert_eq!(offline(&full).audit().unwrap().history_archive_from, 1);

    // The full node loses its entries of heights 1 and 20, exactly the two
    // the start-up check reads, and gains the other node's record. On start
    // it takes itself for a node restored at height 20 ...
    let record = "restored-00000000000000000020.json";
    fs::copy(restored.with_extension("history").join(record), full.with_extension("history").join(record)).unwrap();
    overwrite(&full, 1, [0; 40]);
    overwrite(&full, 20, [0; 40]);
    let engine = offline(&full);
    assert_eq!(engine.history_base(), Some(20));
    // ... but the recount finds entries below the record's height, ignores
    // the record, recounts from the first block and fails at the damage.
    assert!(engine.audit().is_err(), "a record let a damaged archive pass");
    drop(engine);

    // The restored node's archive gains an entry it should not have (junk
    // where height 7 would be). Its record is no longer honoured either:
    // the recount does not pass over what it cannot account for.
    overwrite(&restored, 7, [0x11; 40]);
    let engine = offline(&restored);
    assert_eq!(engine.history_base(), Some(20));
    assert!(engine.audit().is_err());
    drop(engine);
    // With that entry gone again, it passes as before.
    overwrite(&restored, 7, [0; 40]);
    assert_eq!(offline(&restored).audit().unwrap().history_archive_from, 21);
}

/// Records of restores that did not happen, beside the record of the one
/// that did: neither kind hides it.
#[test]
fn a_record_that_does_not_apply_never_hides_the_record_of_the_restore_that_happened() {
    let dir = tempfile::tempdir().unwrap();
    let source = source(&dir.path().join("source.db"), 24);
    let ten = snapshot_at(&source.app, 10);
    let twenty = snapshot_at(&source.app, 20);
    let offline = |path: &Path| {
        engine::Engine::open_with_history(
            Store::open(path.with_extension("v5state")).unwrap(),
            path.with_extension("history"),
        )
        .unwrap()
    };
    // Where the record of a restore of height 20 comes from: a node that did it.
    let other = dir.path().join("other.db");
    let app = App::open(&other).unwrap();
    assert_eq!(restore(&app, &twenty, &chunks_of(&source.app, &twenty), &trusted(&source.log, 20)).result, CHUNK_ACCEPT);
    drop(app);
    let record = "restored-00000000000000000020.json";
    let stray = other.with_extension("history").join(record);

    // A node restored at height 10.
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    assert_eq!(restore(&app, &ten, &chunks_of(&source.app, &ten), &trusted(&source.log, 10)).result, CHUNK_ACCEPT);
    drop(app);
    // A record above the height it holds (a restore of 20 that stopped
    // before installing anything) is removed when the node starts.
    let planted = path.with_extension("history").join(record);
    fs::copy(&stray, &planted).unwrap();
    let app = App::open(&path).unwrap();
    assert!(!planted.exists());
    assert!(path.with_extension("history").join("restored-00000000000000000010.json").exists());
    // The node runs past height 20 and stops.
    replay(&app, &source.log[10..]);
    app.snapshot().unwrap().unwrap();
    drop(app);
    assert_eq!(offline(&path).history_base(), Some(10));
    // The same record turns up again, now below the node's height, where
    // starting does not remove it. It does not apply (the node holds the
    // entry of height 20, which it executed), so the record before it is
    // the one that counts, and the recount passes as it did.
    fs::copy(&stray, &planted).unwrap();
    let engine = offline(&path);
    assert_eq!(engine.history_base(), Some(10));
    let audit = engine.audit().unwrap();
    assert_eq!(audit.history_archive_from, 11);
    assert!(planted.exists());
}
