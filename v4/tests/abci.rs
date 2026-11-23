mod common;
use common::{genesis, key, pk};
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Action, ActionPayload, Transfer};
use timecurrency_v4::{app::App, wire};
fn timestamp(value: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: value / 1_000_000,
        nanos: ((value % 1_000_000) * 1000) as i32,
    })
}
fn init() -> RequestInitChain {
    let g = genesis();
    RequestInitChain {
        chain_id: g.ledger.chain_id.clone(),
        time: timestamp(g.ledger.genesis_time_micros),
        app_state_bytes: serde_json::to_vec(&g).unwrap().into(),
        validators: g
            .validators
            .iter()
            .map(|v| ValidatorUpdate {
                pub_key: Some(tendermint_proto::crypto::PublicKey {
                    sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                        hex::decode(&v.consensus_key).unwrap(),
                    )),
                }),
                power: g.profile.genesis_power() as i64,
            })
            .collect(),
        ..Default::default()
    }
}
fn block(height: i64, elapsed: u64, txs: Vec<Vec<u8>>) -> RequestFinalizeBlock {
    let g = genesis();
    RequestFinalizeBlock {
        height,
        time: timestamp(g.ledger.genesis_time_micros + elapsed as i64),
        hash: Sha256::digest(height.to_be_bytes()).to_vec().into(),
        txs: txs.into_iter().map(Into::into).collect(),
        decided_last_commit: if height == 1 {
            None
        } else {
            Some(CommitInfo {
                round: 0,
                votes: g
                    .validators
                    .iter()
                    .map(|v| VoteInfo {
                        validator: Some(Validator {
                            address: Sha256::digest(hex::decode(&v.consensus_key).unwrap())[..20]
                                .to_vec()
                                .into(),
                            power: g.profile.genesis_power() as i64,
                        }),
                        block_id_flag: BlockIdFlag::Commit as i32,
                    })
                    .collect(),
            })
        },
        ..Default::default()
    }
}
#[test]
fn exact_pending_and_durable_finalize_retry_preserves_validator_updates_and_genesis_root() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abci.redb");
    let app = App::open(&path).unwrap();
    let initial = app.try_init(init()).unwrap();
    app.try_finalize(block(1, pos::SECOND, vec![])).unwrap();
    app.try_commit().unwrap();
    app.try_finalize(block(2, 61 * pos::SECOND, vec![]))
        .unwrap();
    app.try_commit().unwrap();
    let network = genesis().network_id().unwrap();
    let transfer = ledger::sign_action(
        &Action {
            network_id: network.clone(),
            from: 0,
            nonce: 1,
            auth_epoch: 0,
            public_key: pk(1),
            payload: ActionPayload::Transfer(Transfer {
                to: 4,
                amount: 2 * pos::SECOND,
            }),
            signature: vec![],
        },
        &key(1),
    )
    .unwrap();
    let proof = key(120)
        .sign(&pos::register_message(pos::hex32(&network).unwrap(), 4, &pk(120), 1000).unwrap());
    let registration=wire::sign(&network,4,1,0,17,&serde_json::json!({"commission_bps":1000,"consensus_key":pk(120),"proof":hex::encode(proof.to_bytes())}),&key(5)).unwrap();
    let request = block(3, 62 * pos::SECOND, vec![transfer, registration]);
    let first = app.try_finalize(request.clone()).unwrap();
    assert!(!first.validator_updates.is_empty());
    assert_eq!(app.try_finalize(request.clone()).unwrap(), first);
    let mut conflict = request.clone();
    conflict.hash = vec![9; 32].into();
    assert!(app.try_finalize(conflict.clone()).is_err());
    app.try_commit().unwrap();
    assert_eq!(app.try_finalize(request.clone()).unwrap(), first);
    assert!(app.try_finalize(conflict.clone()).is_err());
    assert_eq!(app.try_init(init()).unwrap().app_hash, initial.app_hash);
    drop(app);
    let reopened = App::open(&path).unwrap();
    assert_eq!(reopened.try_finalize(request).unwrap(), first);
    assert!(reopened.try_finalize(conflict).is_err());
    assert_eq!(
        reopened.try_init(init()).unwrap().app_hash,
        initial.app_hash
    );
    let mut wrong_votes = block(4, 63 * pos::SECOND, vec![]);
    wrong_votes.decided_last_commit.as_mut().unwrap().votes[0]
        .validator
        .as_mut()
        .unwrap()
        .power += 1;
    assert!(reopened.try_finalize(wrong_votes).is_err());
    let response = reopened
        .try_finalize(block(4, 63 * pos::SECOND, vec![]))
        .unwrap();
    assert!(response.validator_updates.is_empty());
    reopened.try_commit().unwrap();
    assert_eq!(reopened.info(RequestInfo::default()).last_block_height, 4);
}
