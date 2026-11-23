//! The node as CometBFT drives it: ABCI calls in the order consensus makes
//! them, restarts in the middle of a chain, mempool admission, and the rules
//! that differ from protocol 4 on purpose.
mod common;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use ed25519_dalek::Signer;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, ActionPayload};
use timecurrency_v5::{app::App, engine, proof::ProofEntry, transport::BatchCheck};

const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const REJECT: i32 = response_process_proposal::ProposalStatus::Reject as i32;

fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: micros / 1_000_000,
        nanos: ((micros % 1_000_000) * 1000) as i32,
    })
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
/// The four genesis validators, all having signed the previous block.
fn voters() -> Vec<Validator> {
    let genesis = genesis_v5();
    genesis
        .validators
        .iter()
        .map(|validator| Validator {
            address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20]
                .to_vec()
                .into(),
            power: genesis.profile.genesis_power() as i64,
        })
        .collect()
}
fn last_commit(height: i64) -> Option<CommitInfo> {
    (height > 1).then(|| CommitInfo {
        round: 0,
        votes: voters()
            .into_iter()
            .map(|validator| VoteInfo {
                validator: Some(validator),
                block_id_flag: BlockIdFlag::Commit as i32,
            })
            .collect(),
    })
}
fn local_commit() -> Option<ExtendedCommitInfo> {
    Some(ExtendedCommitInfo {
        round: 0,
        votes: voters()
            .into_iter()
            .map(|validator| ExtendedVoteInfo {
                validator: Some(validator),
                block_id_flag: BlockIdFlag::Commit as i32,
                ..Default::default()
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
fn query(app: &App, path: &str, height: i64, data: &serde_json::Value) -> serde_json::Value {
    let response = app.query(RequestQuery {
        data: serde_json::to_vec(data).unwrap().into(),
        path: path.into(),
        height,
        prove: false,
    });
    assert_eq!(response.code, 0, "query failed: {}", response.log);
    serde_json::from_slice(&response.value).unwrap()
}
fn account(app: &App, id: u64) -> Account {
    let view = query(app, "/v4/state", 0, &json!({ "ids": [id.to_string()] }));
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
fn check(app: &App, txs: &[Vec<u8>]) -> Vec<ResponseCheckTx> {
    app.check_batch(
        txs.iter()
            .map(|tx| RequestCheckTx {
                tx: tx.clone().into(),
                r#type: 0,
            })
            .collect(),
    )
}
fn admitted(app: &App, txs: &[Vec<u8>]) -> Vec<bool> {
    check(app, txs).iter().map(|result| result.code == 0).collect()
}

struct Node {
    app: App,
    height: i64,
    elapsed: u64,
    /// The finalize request and its answer for every committed block.
    log: Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>,
}
impl Node {
    fn start(path: &Path) -> Self {
        let app = App::open(path).unwrap();
        app.try_init(init()).unwrap();
        Self {
            app,
            height: 0,
            elapsed: 0,
            log: Vec::new(),
        }
    }
    /// A started chain on which the validator owners (accounts 0..4) have
    /// earned at least `micros` each.
    fn funded(path: &Path, micros: u64) -> Self {
        let mut node = Self::start(path);
        node.block(pos::SECOND, vec![]);
        for _ in 0..40 {
            if (0..4).all(|id| node.account(id).balance >= micros) {
                return node;
            }
            node.block(60 * pos::SECOND, vec![]);
        }
        panic!("validator owners were not funded");
    }
    /// The time of a block `delta` after the previous one.
    fn time(&self, delta: u64) -> Option<Timestamp> {
        timestamp(genesis_v5().ledger.genesis_time_micros + (self.elapsed + delta) as i64)
    }
    /// The next block's finalize request, `delta` after the previous block.
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: self.time(delta),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: last_commit(height),
            ..Default::default()
        }
    }
    /// Commits a finalized request and records it.
    fn committed(
        &mut self,
        delta: u64,
        request: RequestFinalizeBlock,
        response: ResponseFinalizeBlock,
    ) {
        self.app.try_commit().unwrap();
        self.height += 1;
        self.elapsed += delta;
        self.log.push((request, response));
    }
    /// Proposal, finalize and commit of one block, as on a validator.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> ResponseFinalizeBlock {
        let request = self.request(delta, txs);
        if self.app.process_proposal(proposal(&request)).status != ACCEPT {
            let height = request.height;
            let reason = self.app.try_finalize(request).unwrap_err();
            panic!("proposal rejected at height {height}: {reason:#}");
        }
        let response = self.app.try_finalize(request.clone()).unwrap();
        self.committed(delta, request, response.clone());
        response
    }
    fn prepare(&self, delta: u64, budget: i64, txs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        self.app
            .prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: budget,
                txs: txs.iter().cloned().map(Into::into).collect(),
                local_last_commit: local_commit(),
                height: self.height + 1,
                time: self.time(delta),
                ..Default::default()
            })
            .txs
            .iter()
            .map(|tx| tx.to_vec())
            .collect()
    }
    fn account(&self, id: u64) -> Account {
        account(&self.app, id)
    }
    fn root(&self) -> [u8; 32] {
        self.app.head().unwrap().unwrap().1
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
/// Registers account `row` (key seed `id + 1`) as a validator candidate.
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
/// `count` transfers of one micro-unit from `row`, with consecutive nonces.
fn burst(row: &Account, signer: u8, to: u64, count: u64) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            let mut next = row.clone();
            next.nonce += index;
            transfer(&next, signer, to, 1)
        })
        .collect()
}

#[test]
fn a_block_is_executed_once_and_a_repeated_finalize_must_be_identical() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::funded(&dir.path().join("node.db"), 3 * pos::SECOND);
    // Give account 4 the means to register a validator, so that the block
    // below carries validator updates in its answer.
    let row = node.account(0);
    node.block(pos::SECOND, vec![transfer(&row, 1, 4, 2 * pos::SECOND)]);

    let before = node.app.stats();
    let txs = vec![
        transfer(&node.account(1), 2, 5, 1000),
        register_validator(&node.account(4), 120),
    ];
    let request = node.request(pos::SECOND, txs);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, ACCEPT);
    // The same proposal again (another round re-proposing it) is not re-run.
    assert_eq!(node.app.process_proposal(proposal(&request)).status, ACCEPT);
    // A second, different proposal for the same height is kept beside it.
    let mut other = node.request(2 * pos::SECOND, vec![]);
    other.hash = vec![7; 32].into();
    assert_eq!(node.app.process_proposal(proposal(&other)).status, ACCEPT);
    assert_eq!(node.app.stats().executed_blocks, before.executed_blocks + 2);

    let response = node.app.try_finalize(request.clone()).unwrap();
    assert!(!response.validator_updates.is_empty());
    assert_eq!(response.tx_results.len(), 2);
    let after = node.app.stats();
    assert_eq!(
        after.executed_blocks,
        before.executed_blocks + 2,
        "finalize re-executed the block"
    );
    assert_eq!(after.reused_executions, before.reused_executions + 1);

    // Before Commit, only the identical request may be repeated.
    assert_eq!(node.app.try_finalize(request.clone()).unwrap(), response);
    let mut conflict = request.clone();
    conflict.hash = vec![9; 32].into();
    assert!(node.app.try_finalize(conflict.clone()).is_err());
    assert!(node.app.try_finalize(other.clone()).is_err());
    // A proposal cannot displace a finalized block that awaits its commit;
    // asked about the finalized block itself, the answer is unchanged.
    assert_eq!(node.app.process_proposal(proposal(&other)).status, REJECT);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, ACCEPT);
    assert_eq!(node.app.try_finalize(request.clone()).unwrap(), response);
    assert_eq!(node.app.stats().executed_blocks, after.executed_blocks);

    node.committed(pos::SECOND, request.clone(), response.clone());
    assert_eq!(node.app.head().unwrap().unwrap().0, node.height as u64);
    assert_eq!(response.app_hash.as_ref(), &node.root()[..]);
    // After Commit the same block is answered from the stored result,
    // validator updates included; a different block at that height is refused.
    assert_eq!(node.app.try_finalize(request).unwrap(), response);
    assert!(node.app.try_finalize(conflict).is_err());
    assert_eq!(account(&node.app, 5).balance, 1000);

    // A block this node never saw as a proposal (replay, or a round it
    // missed) is executed by finalize itself.
    let before = node.app.stats();
    let request = node.request(pos::SECOND, vec![transfer(&node.account(1), 2, 5, 1)]);
    let response = node.app.try_finalize(request.clone()).unwrap();
    node.committed(pos::SECOND, request, response);
    let after = node.app.stats();
    assert_eq!(after.executed_blocks, before.executed_blocks + 1);
    assert_eq!(after.reused_executions, before.reused_executions);
    assert_eq!(account(&node.app, 5).balance, 1001);
}

#[test]
fn a_bad_proposal_is_rejected_and_the_node_keeps_working() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::funded(&dir.path().join("node.db"), pos::SECOND);
    let row = node.account(0);
    let good = transfer(&row, 1, 5, 1000);
    let mut forged = good.clone();
    *forged.last_mut().unwrap() ^= 1;
    let mut next = row.clone();
    next.nonce += 1;
    for bad in [
        vec![forged],
        // The same transaction twice: the second copy has a stale nonce.
        vec![good.clone(), good.clone()],
        // More than the account owns, block reward included.
        vec![
            good.clone(),
            transfer(&next, 1, 5, row.balance + 3600 * pos::SECOND),
        ],
        // Signed by a key that is not a device of the account.
        vec![transfer(&row, 9, 5, 1000)],
    ] {
        let request = node.request(pos::SECOND, bad);
        assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
        // Consensus never finalizes such a block, but the application must
        // refuse it there as well.
        assert!(node.app.try_finalize(request).is_err());
    }
    // A wrong vote power in the commit is refused too.
    let mut wrong = node.request(pos::SECOND, vec![]);
    wrong.decided_last_commit.as_mut().unwrap().votes[0]
        .validator
        .as_mut()
        .unwrap()
        .power += 1;
    assert_eq!(node.app.process_proposal(proposal(&wrong)).status, REJECT);
    // Nothing of the rejected blocks was kept.
    assert_eq!(node.account(0), row);
    node.block(pos::SECOND, vec![good]);
    assert_eq!(node.account(5).balance, 1000);
}

#[test]
fn restart_loads_the_snapshot_and_replays_later_blocks_to_the_same_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::funded(&path, 5 * pos::SECOND);
    // Blocks with transfers, a new account and a validator registration.
    let row = node.account(0);
    node.block(
        pos::SECOND,
        vec![
            transfer(&row, 1, 4, 2 * pos::SECOND),
            sponsor(&node.account(1), 2, 201, "newcomer", node.elapsed),
        ],
    );
    node.block(2 * pos::SECOND, vec![reveal(201, "newcomer")]);
    let snapshot_height = node.app.snapshot().unwrap().expect("a new snapshot").height;
    assert_eq!(snapshot_height, node.height as u64);
    // Asking again for the same height writes nothing.
    assert!(node.app.snapshot().unwrap().is_none());
    node.block(pos::SECOND, vec![register_validator(&node.account(4), 120)]);
    for round in 0..6u64 {
        let mut txs = burst(&node.account(2), 3, 12, 3 + round);
        txs.push(transfer(&node.account(3), 4, 12, 5000));
        node.block(pos::SECOND + round, txs);
    }
    let (height, root) = node.app.head().unwrap().unwrap();
    assert_eq!(height, node.height as u64);
    let newcomer = node.account(12);
    assert_eq!(newcomer.name, "newcomer");
    assert!(newcomer.balance > 0);
    let wanted = json!({"ids":["0","4","12"],"names":["newcomer"],"blocks":["1",snapshot_height.to_string(),height.to_string()],"include_pos":true});
    let view = query(&node.app, "/v4/state", 0, &wanted);
    let (log, elapsed) = (node.log.clone(), node.elapsed);
    // The process dies here: nothing after the snapshot reached the disk.
    drop(node);

    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap().0, snapshot_height);
    let info = app.info(RequestInfo::default());
    assert_eq!(info.last_block_height as u64, snapshot_height);
    assert_eq!(
        info.last_block_app_hash,
        log[snapshot_height as usize - 1].1.app_hash
    );
    // The consensus engine replays every block after the snapshot.
    for (request, response) in &log[snapshot_height as usize..] {
        assert_eq!(app.try_finalize(request.clone()).unwrap(), *response);
        app.try_commit().unwrap();
    }
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    assert_eq!(account(&app, 12), newcomer);
    // Proofs, including block history proofs from before and after the
    // snapshot, are byte-for-byte what the node served before it died.
    assert_eq!(query(&app, "/v4/state", 0, &wanted), view);
    // The chain continues.
    let mut node = Node {
        app,
        height: height as i64,
        elapsed,
        log: Vec::new(),
    };
    node.block(pos::SECOND, vec![transfer(&node.account(12), 201, 0, 1)]);
    // A clean stop writes a final snapshot; the next start needs no replay.
    let (height, root) = node.app.head().unwrap().unwrap();
    assert_eq!(node.app.snapshot().unwrap().unwrap().height, height);
    drop(node);
    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    drop(app);
    // Full offline recount of the reloaded state, history archive included.
    let engine = engine::Engine::open_with_history(
        timecurrency_v5::store::Store::open(path.with_extension("v5state")).unwrap(),
        path.with_extension("history"),
    )
    .unwrap();
    let audit = engine.audit().unwrap();
    assert!(audit.history_archive_verified);
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 1);
}

#[test]
fn a_node_stopped_right_after_genesis_replays_the_whole_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::funded(&path, pos::SECOND);
    node.block(pos::SECOND, vec![transfer(&node.account(0), 1, 6, 777)]);
    let (height, root) = node.app.head().unwrap().unwrap();
    let log = node.log.clone();
    let genesis_hash = App::open(dir.path().join("fresh.db"))
        .unwrap()
        .try_init(init())
        .unwrap()
        .app_hash;
    drop(node);
    // Only the genesis snapshot exists.
    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap().0, 0);
    // At height zero the consensus engine sends InitChain again.
    assert_eq!(app.try_init(init()).unwrap().app_hash, genesis_hash);
    for (request, response) in &log {
        assert_eq!(app.try_finalize(request.clone()).unwrap(), *response);
        app.try_commit().unwrap();
    }
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    // InitChain is refused once the chain has blocks, and a different
    // genesis is refused at any time.
    assert!(app.try_init(init()).is_err());
    let mut other = init();
    let mut genesis = genesis_v5();
    genesis.recovery_min_delay_micros += 1;
    other.app_state_bytes = serde_json::to_vec(&genesis).unwrap().into();
    assert!(app.try_init(other).is_err());
}

#[test]
fn mempool_admission_follows_the_transactions_already_admitted() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::funded(&dir.path().join("node.db"), pos::SECOND);
    // Account 5 earns nothing by itself, so its balance is exactly known.
    node.block(
        pos::SECOND,
        vec![transfer(&node.account(0), 1, 5, 500_000)],
    );
    let row = node.account(5);
    assert_eq!(row.balance, 500_000);
    let at = |offset: u64| {
        let mut next = row.clone();
        next.nonce += offset;
        next
    };
    let first = transfer(&row, 6, 7, 1000);
    let rival = transfer(&row, 6, 8, 2000);
    let second = transfer(&at(1), 6, 7, 1000);
    let gap = transfer(&at(4), 6, 7, 1000);
    let mut forged = transfer(&at(2), 6, 7, 1000);
    *forged.last_mut().unwrap() ^= 1;
    // After `first` and `second` the account holds `left`.
    let left = row.balance - 2 * (1000 + ledger::FEE_MICROS);
    let too_much = transfer(&at(2), 6, 7, left - ledger::FEE_MICROS + 1);
    let all = transfer(&at(2), 6, 7, left - ledger::FEE_MICROS);
    let broke = transfer(&at(3), 6, 7, 1);
    let results = check(
        &node.app,
        &[
            first.clone(),
            rival.clone(),
            second.clone(),
            gap.clone(),
            forged.clone(),
            too_much.clone(),
            all.clone(),
            broke.clone(),
        ],
    );
    let codes: Vec<bool> = results.iter().map(|result| result.code == 0).collect();
    assert_eq!(
        codes,
        [true, false, true, false, false, false, true, false],
        "{:?}",
        results
            .iter()
            .map(|result| result.log.clone())
            .collect::<Vec<_>>()
    );
    // One at a time gives the same answers as a batch.
    assert_eq!(admitted(&node.app, &[rival.clone()]), [false]);
    assert_eq!(
        admitted(&node.app, &[first.clone()]),
        [false],
        "already pending"
    );
    // Nothing was written: admission never changes committed state.
    assert_eq!(node.account(5), row);

    // A block takes `first`. The consensus engine then re-checks what is
    // left in its mempool, in order, on the new state.
    node.block(pos::SECOND, vec![first.clone()]);
    assert_eq!(
        admitted(&node.app, &[second.clone(), all.clone()]),
        [true, true]
    );
    assert_eq!(
        admitted(&node.app, &[first, rival, gap]),
        [false, false, false]
    );
    // A proposer offered a mix builds a valid block from it.
    let chosen = node.prepare(
        pos::SECOND,
        1 << 20,
        &[forged, second.clone(), too_much, all.clone(), broke],
    );
    assert_eq!(chosen, [second, all]);
    node.block(pos::SECOND, chosen);
    let after = node.account(5);
    assert_eq!((after.balance, after.nonce), (0, row.nonce + 3));
    assert_eq!(
        node.account(7).balance,
        row.balance - 3 * ledger::FEE_MICROS
    );
}

#[test]
fn proposer_respects_the_byte_budget() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::funded(&dir.path().join("node.db"), pos::SECOND);
    let txs = burst(&node.account(0), 1, 5, 10);
    let size = txs[0].len();
    assert_eq!(node.prepare(pos::SECOND, 1 << 20, &txs).len(), 10);
    let fitted = node.prepare(pos::SECOND, 3 * size as i64 + 5, &txs);
    assert_eq!(fitted.len(), 3);
    assert!(fitted.iter().map(Vec::len).sum::<usize>() <= 3 * size + 5);
    assert!(node.prepare(pos::SECOND, 0, &txs).is_empty());
}

#[test]
fn rules_changed_on_purpose_from_protocol_4() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::funded(&dir.path().join("node.db"), 3 * pos::SECOND);

    // 1. CancelPending pays the standard fee. Protocol 4 let any account
    //    fill blocks with it at no cost.
    let cancel = |row: &Account, signer: u8| {
        legacy(
            row.id,
            row.nonce + 1,
            row.auth_epoch,
            signer,
            ActionPayload::CancelPending(ledger::CancelPending {}),
        )
    };
    // Account 9 owns nothing: it cannot pay, so it cannot send the action.
    let poor = node.account(9);
    assert_eq!(poor.balance, 0);
    let results = check(&node.app, &[cancel(&poor, 10)]);
    assert_eq!(results[0].code, 1);
    assert!(
        results[0].log.contains("insufficient funds"),
        "{}",
        results[0].log
    );
    let request = node.request(pos::SECOND, vec![cancel(&poor, 10)]);
    assert_eq!(node.app.process_proposal(proposal(&request)).status, REJECT);
    // Funded with the fee and a little more, the action is accepted and
    // costs exactly the fee.
    node.block(
        pos::SECOND,
        vec![transfer(&node.account(1), 2, 9, ledger::FEE_MICROS + 7)],
    );
    node.block(pos::SECOND, vec![cancel(&node.account(9), 10)]);
    let poor = node.account(9);
    assert_eq!((poor.balance, poor.auth_epoch, poor.nonce), (7, 1, 1));

    // 2. Recovery can be turned off again. Protocol 4 applied the minimum
    //    delay to the "off" form and so rejected it.
    let set = |row: &Account, guardians: Vec<u64>, threshold: u64, delay_seconds: u64| {
        legacy(
            row.id,
            row.nonce + 1,
            row.auth_epoch,
            row.id as u8 + 1,
            ActionPayload::SetRecovery(ledger::SetRecovery {
                guardians,
                threshold,
                delay_seconds,
            }),
        )
    };
    node.block(pos::SECOND, vec![set(&node.account(2), vec![0, 1, 3], 2, 30)]);
    assert!(node.account(2).recovery_policy.is_some());
    // Still refused: a delay below the minimum, and malformed "off" forms.
    for bad in [
        set(&node.account(2), vec![0, 1, 3], 2, 5),
        set(&node.account(2), vec![], 0, 5),
        set(&node.account(2), vec![], 2, 0),
    ] {
        assert_eq!(admitted(&node.app, &[bad]), [false]);
    }
    node.block(pos::SECOND, vec![set(&node.account(2), vec![], 0, 0)]);
    let row = node.account(2);
    assert!(row.recovery_policy.is_none());
    assert_eq!(row.recovery_version, 2);
    // The account spends normally afterwards.
    node.block(pos::SECOND, vec![transfer(&row, 3, 5, 10)]);

    // 3. The guardian list is bounded before any guardian row is loaded.
    let results = check(
        &node.app,
        // As many guardians as an action can carry at all.
        &[set(&node.account(3), (4..=150).collect(), 100, 30)],
    );
    assert_eq!(results[0].code, 1);
    assert!(results[0].log.contains("2..5"), "{}", results[0].log);

    // 4. A block may carry more than protocol 4's 1 MiB of transactions.
    let txs: Vec<Vec<u8>> = (0..4u64)
        .flat_map(|owner| burst(&node.account(owner), owner as u8 + 1, 5, 1400))
        .collect();
    let bytes: usize = txs.iter().map(Vec::len).sum();
    assert!(
        bytes > 1024 * 1024,
        "{bytes} bytes do not exceed the old limit"
    );
    let before = node.account(5).balance;
    node.block(pos::SECOND, txs);
    assert_eq!(node.account(5).balance, before + 4 * 1400);
    // The new limits hold.
    let big = vec![vec![0u8; 1024 * 1024]; 4];
    engine::validate_block_transactions(&big).unwrap();
    let mut over = big;
    over.push(vec![0]);
    assert!(engine::validate_block_transactions(&over).is_err());
    engine::validate_block_transactions(&vec![vec![0u8; 1]; engine::MAX_BLOCK_TXS]).unwrap();
    assert!(
        engine::validate_block_transactions(&vec![vec![0u8; 1]; engine::MAX_BLOCK_TXS + 1])
            .is_err()
    );
}

#[test]
fn answers_and_proofs_are_the_same_bytes_protocol_4_serves() {
    // Wallets, the gateway and the light-client verifier read these answers.
    // On the same chain, both generations must return the same bytes.
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(&dir.path().join("new.db"));
    let old = timecurrency_v4::app::App::open(dir.path().join("old.redb")).unwrap();
    let mut old_init = init();
    old_init.app_state_bytes = serde_json::to_vec(&genesis_v4()).unwrap().into();
    assert_eq!(
        old.try_init(old_init).unwrap().app_hash,
        node.app.info(RequestInfo::default()).last_block_app_hash
    );
    let both = |node: &mut Node, delta: u64, txs: Vec<Vec<u8>>| {
        let request = node.request(delta, txs.clone());
        let expected = old.try_finalize(request.clone()).unwrap();
        old.try_commit().unwrap();
        let response = node.block(delta, txs);
        assert_eq!(
            response.app_hash, expected.app_hash,
            "height {}",
            request.height
        );
        assert_eq!(response.validator_updates, expected.validator_updates);
        assert_eq!(response.tx_results, expected.tx_results);
    };
    both(&mut node, pos::SECOND, vec![]);
    both(&mut node, 60 * pos::SECOND, vec![]);
    both(&mut node, 60 * pos::SECOND, vec![]);
    let txs = vec![
        transfer(&node.account(0), 1, 4, 2 * pos::SECOND),
        sponsor(&node.account(1), 2, 201, "newcomer", node.elapsed),
    ];
    both(&mut node, pos::SECOND, txs);
    let txs = vec![
        reveal(201, "newcomer"),
        register_validator(&node.account(4), 120),
        legacy(
            2,
            node.account(2).nonce + 1,
            0,
            3,
            ActionPayload::SetRecovery(ledger::SetRecovery {
                guardians: vec![0, 1, 3],
                threshold: 2,
                delay_seconds: 30,
            }),
        ),
    ];
    both(&mut node, 2 * pos::SECOND, txs);
    for round in 0..4u64 {
        let txs = burst(&node.account(3), 4, 12, 5 + round);
        both(&mut node, pos::SECOND + round, txs);
    }
    let height = node.height;
    let selections = [
        json!({"ids":["0","2","4","12","999"],"names":["newcomer","person_3","nobody"],"public_keys":[pk(1),pk(201),pk(77)]}),
        json!({"ids":["2"],"owners":["0","4","9"],"candidates":["0","4","11"],"epochs":["0","1"],"include_pos":true,"include_bitcoin":true,"include_policy":true}),
        json!({"blocks":["1","2",height.to_string(),(height + 5).to_string()]}),
    ];
    for at in [0, height - 1] {
        for selection in &selections {
            let request = RequestQuery {
                data: serde_json::to_vec(selection).unwrap().into(),
                path: "/v4/state".into(),
                height: at,
                prove: false,
            };
            let (a, b) = (old.query(request.clone()), node.app.query(request));
            assert_eq!((a.code, b.code), (0, 0), "{} / {}", a.log, b.log);
            assert_eq!(a.height, b.height);
            assert_eq!(a.value, b.value, "selection {selection} at {at}");
            // Every entry verifies against that block's application hash.
            let view: serde_json::Value = serde_json::from_slice(&b.value).unwrap();
            let root: [u8; 32] = node.log[b.height as usize - 1]
                .1
                .app_hash
                .as_ref()
                .try_into()
                .unwrap();
            assert_eq!(view["root"], hex::encode(root));
            for entry in view["entries"].as_array().unwrap() {
                let entry: ProofEntry = serde_json::from_value(entry.clone()).unwrap();
                let key = hex::decode(&entry.key_hex).unwrap();
                entry.verify(root, &key).unwrap();
                let mut wrong = root;
                wrong[0] ^= 1;
                assert!(entry.verify(wrong, &key).is_err());
            }
        }
    }
    let keys = json!([
        hex::encode(b"meta"),
        hex::encode(engine::account_key(12)),
        hex::encode(b"absent")
    ]);
    let request = RequestQuery {
        data: serde_json::to_vec(&keys).unwrap().into(),
        path: "/compact-proof".into(),
        height: 0,
        prove: false,
    };
    let (a, b) = (old.query(request.clone()), node.app.query(request));
    assert_eq!((a.code, b.code), (0, 0), "{} / {}", a.log, b.log);
    assert_eq!(a.value, b.value);
    // Unbounded or unknown queries are refused by both.
    for (path, data, prove) in [
        (
            "/v4/state",
            json!({"ids":(0..9).map(|id| id.to_string()).collect::<Vec<_>>()}),
            false,
        ),
        ("/v4/state", json!({"ids":["01"]}), false),
        ("/v4/state", json!({"everything":true}), false),
        ("/store", json!({}), false),
        ("/v4/state", json!({"ids":["1"]}), true),
    ] {
        let request = RequestQuery {
            data: serde_json::to_vec(&data).unwrap().into(),
            path: path.into(),
            height: 0,
            prove,
        };
        assert_eq!(old.query(request.clone()).code, 1);
        assert_eq!(node.app.query(request).code, 1);
    }
}

#[test]
fn checks_queries_snapshots_and_blocks_run_together() {
    // The connections of the consensus engine are served by different
    // threads. Whatever they interleave, blocks must produce the same state
    // as on a node that does nothing else.
    let dir = tempfile::tempdir().unwrap();
    let mut busy = Node::funded(&dir.path().join("busy.db"), 3 * pos::SECOND);
    let mut quiet = Node::funded(&dir.path().join("quiet.db"), 3 * pos::SECOND);
    assert_eq!(busy.root(), quiet.root());
    let stop = Arc::new(AtomicBool::new(false));
    let mut workers = Vec::new();
    // Mempool traffic: valid, stale and forged transactions.
    for worker in 0..3u64 {
        let (app, stop) = (busy.app.clone(), stop.clone());
        workers.push(std::thread::spawn(move || {
            let mut rounds = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let row = account(&app, worker);
                let mut txs = burst(&row, worker as u8 + 1, 6 + worker, 5);
                let mut forged = txs[0].clone();
                *forged.last_mut().unwrap() ^= 1;
                txs.push(forged);
                let results = app.check_batch(
                    txs.into_iter()
                        .map(|tx| RequestCheckTx {
                            tx: tx.into(),
                            r#type: 0,
                        })
                        .collect(),
                );
                assert_eq!(results.len(), 6);
                assert_eq!(results[5].code, 1, "a forged transaction was admitted");
                rounds += 1;
            }
            rounds
        }));
    }
    // Wallet queries with proofs, checked against the answer's own root.
    for _ in 0..2 {
        let (app, stop) = (busy.app.clone(), stop.clone());
        workers.push(std::thread::spawn(move || {
            let mut rounds = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let view = query(
                    &app,
                    "/v4/state",
                    0,
                    &json!({"ids":["0","1","5"],"include_pos":true}),
                );
                let root: [u8; 32] = hex::decode(view["root"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                for entry in view["entries"].as_array().unwrap() {
                    let entry: ProofEntry = serde_json::from_value(entry.clone()).unwrap();
                    entry
                        .verify(root, &hex::decode(&entry.key_hex).unwrap())
                        .unwrap();
                }
                query(&app, "/status", 0, &json!(null));
                rounds += 1;
            }
            rounds
        }));
    }
    {
        let (app, stop) = (busy.app.clone(), stop.clone());
        workers.push(std::thread::spawn(move || {
            let mut rounds = 0u64;
            while !stop.load(Ordering::Relaxed) {
                app.snapshot().unwrap();
                rounds += 1;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            rounds
        }));
    }
    for round in 0..40u64 {
        let txs: Vec<Vec<u8>> = (0..4u64)
            .flat_map(|owner| {
                burst(
                    &quiet.account(owner),
                    owner as u8 + 1,
                    5 + owner,
                    6 + round % 5,
                )
            })
            .collect();
        let expected = quiet.block(pos::SECOND, txs.clone());
        let response = busy.block(pos::SECOND, txs);
        assert_eq!(response, expected, "round {round}");
    }
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        assert!(
            worker.join().unwrap() > 0,
            "a worker never completed a round"
        );
    }
    assert_eq!(busy.root(), quiet.root());
    for id in 0..GENESIS_ACCOUNTS {
        assert_eq!(busy.account(id), quiet.account(id));
    }
}

#[test]
fn more_proposals_than_the_node_remembers_are_still_finalized_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::funded(&dir.path().join("node.db"), pos::SECOND);
    let row = node.account(0);
    // Five rounds, five different proposals for the same height.
    let proposals: Vec<RequestFinalizeBlock> = (0..5u64)
        .map(|round| {
            let mut request = node.request(pos::SECOND + round, vec![transfer(&row, 1, 5, 100 + round)]);
            request.hash = vec![50 + round as u8; 32].into();
            request
        })
        .collect();
    let before = node.app.stats();
    for request in &proposals {
        assert_eq!(node.app.process_proposal(proposal(request)).status, ACCEPT);
    }
    assert_eq!(node.app.stats().executed_blocks, before.executed_blocks + 5);
    // Consensus decides the first one, which is no longer remembered: it is
    // executed again and gives the result of that block, not of a later one.
    let response = node.app.try_finalize(proposals[0].clone()).unwrap();
    let after = node.app.stats();
    assert_eq!(after.executed_blocks, before.executed_blocks + 6);
    assert_eq!(after.reused_executions, before.reused_executions);
    node.committed(pos::SECOND, proposals[0].clone(), response);
    assert_eq!(node.account(5).balance, 100);
    // The newest of several remembered proposals is reused.
    let row = node.account(0);
    let proposals: Vec<RequestFinalizeBlock> = (0..3u64)
        .map(|round| {
            let mut request = node.request(pos::SECOND + round, vec![transfer(&row, 1, 5, 7 + round)]);
            request.hash = vec![80 + round as u8; 32].into();
            request
        })
        .collect();
    for request in &proposals {
        assert_eq!(node.app.process_proposal(proposal(request)).status, ACCEPT);
    }
    let before = node.app.stats();
    let response = node.app.try_finalize(proposals[2].clone()).unwrap();
    assert_eq!(node.app.stats().reused_executions, before.reused_executions + 1);
    node.committed(pos::SECOND + 2, proposals[2].clone(), response);
    assert_eq!(node.account(5).balance, 109);
}

#[test]
fn a_reconnecting_consensus_engine_starts_admission_from_the_committed_head() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::funded(&dir.path().join("node.db"), pos::SECOND);
    let first = transfer(&node.account(0), 1, 5, 1000);
    assert_eq!(admitted(&node.app, &[first.clone()]), [true]);
    assert_eq!(admitted(&node.app, &[first.clone()]), [false], "already pending");
    // The consensus engine restarted: its mempool is empty again, and so is
    // what the application remembers as pending.
    node.app.peer_connected();
    assert_eq!(admitted(&node.app, &[first]), [true]);
}

#[test]
fn a_wallet_is_served_the_security_row_of_an_account_or_the_proof_that_it_has_none() {
    use timecurrency_v5::security::{self, Role, Security};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::funded(&path, 3 * pos::SECOND);
    node.block(pos::SECOND, vec![transfer(&node.account(0), 1, 5, pos::SECOND)]);
    // Account 5 (key 6) adopts the security rules: a sign-in key, a spend key
    // and two recovery keys.
    let mut keys: Vec<serde_json::Value> = [(60u8, Role::Signin, "signin"), (61, Role::Spend, "spend"), (62, Role::Recover, "recover"), (63, Role::Recover, "recover")]
        .into_iter()
        .map(|(seed, role, name)| {
            let message = security::key_message(&network_id(), 5, role, &pk(seed)).unwrap();
            json!({"public_key": pk(seed), "role": name, "proof": hex::encode(key(seed).sign(&message).to_bytes())})
        })
        .collect();
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    let rules = json!({"threshold": "2", "daily_limit_micros": "500000", "delay_seconds": "60", "freeze_seconds": "120"});
    let adopt = extension(&node.account(5), 6, security::SECURE, json!({"keys": keys, "policy": rules}));
    assert_eq!(admitted(&node.app, &[adopt.clone()]), [true]);
    node.block(pos::SECOND, vec![adopt]);

    // Asked for, the answer proves the row of the secured account and the
    // absence of one for the other account.
    let wanted = json!({"ids": ["1", "5"], "include_security": true});
    let view = query(&node.app, "/v4/state", 0, &wanted);
    let proven = |view: &serde_json::Value, root: [u8; 32], id: u64| -> Option<Vec<u8>> {
        let key = security::key(id);
        let entry = view["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["key_hex"] == hex::encode(&key).as_str())
            .expect("the security key is part of the answer");
        let entry: ProofEntry = serde_json::from_value(entry.clone()).unwrap();
        entry.verify(root, &key).unwrap()
    };
    let row: Security = serde_json::from_slice(&proven(&view, node.root(), 5).expect("account 5 has a row")).unwrap();
    assert_eq!((row.version, row.policy.threshold, row.policy.daily_limit_micros), (1, 2, 500_000));
    assert_eq!(row.allowance_micros, 500_000);
    assert!(proven(&view, node.root(), 1).is_none(), "account 1 has none, and that is proven");
    let roles: Vec<Option<Role>> = node.account(5).devices.iter().map(Role::of).collect();
    assert_eq!(roles.iter().filter(|role| **role == Some(Role::Recover)).count(), 2);
    assert!(roles.contains(&Some(Role::Signin)) && roles.contains(&Some(Role::Spend)) && !roles.contains(&None));

    // Not asked for, no security key is part of the answer; a selection the
    // node does not know is refused.
    let plain = query(&node.app, "/v4/state", 0, &json!({"ids": ["1", "5"]}));
    let prefix = hex::encode(b"security/");
    assert!(!plain["entries"].as_array().unwrap().iter().any(|entry| entry["key_hex"].as_str().unwrap().starts_with(&prefix)));
    let refused = node.app.query(RequestQuery { data: serde_json::to_vec(&json!({"ids": ["5"], "include_security": "yes"})).unwrap().into(), path: "/v4/state".into(), height: 0, prove: false });
    assert_ne!(refused.code, 0);

    // The spend key pays, the sign-in key does not, and the mempool agrees.
    let owner = node.account(5);
    assert_eq!(admitted(&node.app, &[transfer(&owner, 60, 1, 1000)]), [false]);
    assert_eq!(admitted(&node.app, &[transfer(&owner, 61, 1, 600_000)]), [false], "over the daily limit");
    let payment = transfer(&owner, 61, 1, 1000);
    assert_eq!(admitted(&node.app, &[payment.clone()]), [true]);
    node.block(pos::SECOND, vec![payment]);

    // A node restarted from its snapshot serves the same rows and proofs.
    let view = query(&node.app, "/v4/state", 0, &wanted);
    let spent: Security = serde_json::from_slice(&proven(&view, node.root(), 5).unwrap()).unwrap();
    assert!(spent.allowance_micros < 500_000 - 1000, "the payment and its fee came out of the allowance");
    node.app.snapshot().unwrap().expect("a new snapshot");
    let head = node.app.head().unwrap().unwrap();
    drop(node);
    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), head);
    assert_eq!(query(&app, "/v4/state", 0, &wanted), view);
}
