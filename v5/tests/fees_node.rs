//! The fee rule at the ABCI boundary: a network that pays fees on, driven as
//! CometBFT drives it, stopped with fees still owed and restarted.
mod common;
use common::*;
use sha2::{Digest, Sha256};
use std::path::Path;
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::{app::App, engine, genesis::Genesis, pos_adapter::FEE_POOL_KEY, transport::BatchCheck};

const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;

fn genesis() -> Genesis {
    let mut genesis = genesis_v5();
    genesis.fees_to_validators_ppm = 1_000_000;
    genesis
}
fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp { seconds: micros / 1_000_000, nanos: ((micros % 1_000_000) * 1000) as i32 })
}
fn init() -> RequestInitChain {
    let genesis = genesis();
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
/// The four genesis validators; `absent` did not sign the previous block.
fn votes(absent: &[usize]) -> Vec<(Validator, i32)> {
    let genesis = genesis();
    genesis
        .validators
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            (
                Validator {
                    address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20].to_vec().into(),
                    power: genesis.profile.genesis_power() as i64,
                },
                if absent.contains(&index) { BlockIdFlag::Absent as i32 } else { BlockIdFlag::Commit as i32 },
            )
        })
        .collect()
}
fn last_commit(height: i64, absent: &[usize]) -> Option<CommitInfo> {
    (height > 1).then(|| CommitInfo {
        round: 0,
        votes: votes(absent)
            .into_iter()
            .map(|(validator, flag)| VoteInfo { validator: Some(validator), block_id_flag: flag })
            .collect(),
    })
}
fn local_commit(absent: &[usize]) -> Option<ExtendedCommitInfo> {
    Some(ExtendedCommitInfo {
        round: 0,
        votes: votes(absent)
            .into_iter()
            .map(|(validator, flag)| ExtendedVoteInfo { validator: Some(validator), block_id_flag: flag, ..Default::default() })
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
fn offline(path: &Path) -> engine::Engine {
    engine::Engine::open_with_history(
        timecurrency_v5::store::Store::open(path.with_extension("v5state")).unwrap(),
        path.with_extension("history"),
    )
    .unwrap()
}

struct Node {
    app: App,
    network: String,
    height: i64,
    elapsed: u64,
    log: Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>,
}
impl Node {
    fn start(path: &Path) -> Self {
        let app = App::open(path).unwrap();
        app.try_init(init()).unwrap();
        Self { app, network: genesis().network_id().unwrap(), height: 0, elapsed: 0, log: Vec::new() }
    }
    fn time(&self, delta: u64) -> Option<Timestamp> {
        timestamp(genesis().ledger.genesis_time_micros + (self.elapsed + delta) as i64)
    }
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>, absent: &[usize]) -> ResponseFinalizeBlock {
        let height = self.height + 1;
        let request = RequestFinalizeBlock {
            height,
            time: self.time(delta),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: last_commit(height, absent),
            ..Default::default()
        };
        assert_eq!(self.app.process_proposal(proposal(&request)).status, ACCEPT, "proposal rejected at {height}");
        let response = self.app.try_finalize(request.clone()).unwrap();
        self.app.try_commit().unwrap();
        self.height += 1;
        self.elapsed += delta;
        self.log.push((request, response.clone()));
        response
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        let response = self.app.query(RequestQuery {
            data: serde_json::to_vec(&vec![hex::encode(key)]).unwrap().into(),
            path: "/compact-proof".into(),
            height: 0,
            prove: false,
        });
        assert_eq!(response.code, 0, "{}", response.log);
        let view: serde_json::Value = serde_json::from_slice(&response.value).unwrap();
        let entry = &view["entries"][0];
        entry["value_b64"].as_str().map(|text| {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(text).unwrap()
        })
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&engine::account_key(id)).expect("account")).unwrap()
    }
    fn pool(&self) -> u64 {
        self.row(FEE_POOL_KEY).map_or(0, |raw| serde_json::from_slice::<String>(&raw).unwrap().parse().unwrap())
    }
    fn transfer(&self, from: u64, ahead: u64, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + ahead,
                auth_epoch: row.auth_epoch,
                public_key: pk(from as u8 + 1),
                payload: ActionPayload::Transfer(ledger::Transfer { to, amount }),
                signature: vec![],
            },
            &key(from as u8 + 1),
        )
        .unwrap()
    }
}

#[test]
fn a_node_that_pays_fees_on_restarts_with_fees_still_owed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::start(&path);
    node.block(SECOND, vec![], &[]);
    for _ in 0..3 {
        node.block(60 * SECOND, vec![], &[]);
    }
    assert_eq!(node.pool(), 0);
    // Fees are charged; the mempool and the proposer work as before.
    let txs: Vec<Vec<u8>> = (0..4).map(|from| node.transfer(from, 1, 5, SECOND)).collect();
    let admitted = node.app.check_batch(txs.iter().map(|tx| RequestCheckTx { tx: tx.clone().into(), r#type: 0 }).collect());
    assert!(admitted.iter().all(|result| result.code == 0));
    let proposed = node.app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: 1 << 20,
        txs: txs.iter().cloned().map(Into::into).collect(),
        local_last_commit: local_commit(&[]),
        height: node.height + 1,
        time: node.time(SECOND),
        ..Default::default()
    });
    assert_eq!(proposed.txs.len(), 4);
    node.block(SECOND, txs, &[]);
    assert_eq!(node.pool(), 4 * FEE);
    // The node is stopped here, with four fees owed: the snapshot holds the row.
    let snapshot = node.app.snapshot().unwrap().expect("a snapshot").height;
    assert_eq!(snapshot, node.height as u64);
    // Validator 3's signature is missing from the next block: its share
    // stays in the bank. Then more fees; then everyone signs.
    let before: Vec<u64> = (0..4).map(|id| node.account(id).balance).collect();
    node.block(10 * SECOND, vec![], &[3]);
    assert_eq!(node.pool(), 0);
    for id in 0..3 {
        assert_eq!(node.account(id).balance, before[id as usize] + 500_000 + FEE);
    }
    assert_eq!(node.account(3).balance, before[3]);
    let more: Vec<Vec<u8>> = (0..3).map(|ahead| node.transfer(0, 1 + ahead, 6, 7)).collect();
    node.block(10 * SECOND, more, &[]);
    assert_eq!(node.pool(), 3 * FEE);
    node.block(10 * SECOND, vec![], &[1]);
    node.block(10 * SECOND, vec![], &[]);
    let (height, root) = node.app.head().unwrap().unwrap();
    let (log, pool) = (node.log.clone(), node.pool());
    let balances: Vec<u64> = (0..6).map(|id| node.account(id).balance).collect();
    drop(node);

    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap().0, snapshot);
    for (request, response) in &log[snapshot as usize..] {
        // Replayed as a validator that never saw the proposals.
        assert_eq!(app.try_finalize(request.clone()).unwrap(), *response);
        app.try_commit().unwrap();
    }
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    let node = Node { app, network: genesis().network_id().unwrap(), height: height as i64, elapsed: 0, log: Vec::new() };
    assert_eq!(node.pool(), pool);
    assert_eq!((0..6).map(|id| node.account(id).balance).collect::<Vec<_>>(), balances);
    node.app.snapshot().unwrap();
    drop(node);
    let audit = offline(&path).audit().unwrap();
    assert!(audit.history_archive_verified);
}

#[test]
fn a_genesis_that_writes_the_setting_as_zero_is_refused() {
    // Zero is written by leaving the field out, so that a network without
    // the rule has one genesis and older nodes can read it.
    let mut value = serde_json::to_value(genesis_v5()).unwrap();
    value["fees_to_validators_ppm"] = serde_json::json!("0");
    assert!(serde_json::from_value::<Genesis>(value.clone()).is_err());
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(&dir.path().join("node.db")).unwrap();
    let mut request = init();
    request.app_state_bytes = serde_json::to_vec(&value).unwrap().into();
    assert!(app.try_init(request).is_err());
    // A share below a thousandth of one fee is still a share of the fees of
    // a block: 999 parts per million of 1,000 fees are 999 microseconds.
    let mut tiny = genesis_v5();
    tiny.fees_to_validators_ppm = 999;
    tiny.validate().unwrap();
    assert_ne!(tiny.network_id().unwrap(), network_id());
    assert_eq!(tiny.validators_fee(FEE), 0);
    assert_eq!(tiny.validators_fee(1000 * FEE), 999);
}
