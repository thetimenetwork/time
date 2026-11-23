use ed25519_dalek::SigningKey;
use tendermint_abci::Application;
use tendermint_proto::{google::protobuf::Timestamp, v0_38::abci::*};
use timecurrency_node::ledger::{Economics, Genesis, GenesisAccount};
use timecurrency_v2::{app::App, proof::ProofEntry};
fn timestamp(value: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: value / 1_000_000,
        nanos: ((value % 1_000_000) * 1000) as i32,
    })
}
fn genesis() -> Genesis {
    Genesis {
        chain_id: "time-devnet-v2-app-tests".into(),
        genesis_time_micros: 1_000_000,
        economics: Economics::default(),
        accounts: vec![GenesisAccount {
            id: 0,
            name: "alice".into(),
            public_key: hex::encode(SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes()),
        }],
    }
}
fn init() -> RequestInitChain {
    let g = genesis();
    RequestInitChain {
        chain_id: g.chain_id.clone(),
        time: timestamp(g.genesis_time_micros),
        app_state_bytes: serde_json::to_vec(&g).unwrap().into(),
        ..Default::default()
    }
}
fn block(height: i64) -> RequestFinalizeBlock {
    RequestFinalizeBlock {
        height,
        time: timestamp(1_000_000 + height * 1_000_000),
        hash: vec![height as u8; 32].into(),
        ..Default::default()
    }
}
fn health(app: &App) -> serde_json::Value {
    let response = app.query(RequestQuery {
        path: "/status".into(),
        ..Default::default()
    });
    assert_eq!(response.code, 0, "{}", response.log);
    serde_json::from_slice(&response.value).unwrap()
}
#[test]
fn local_gc_pressure_does_not_change_consensus_or_publish_pending_finalize() {
    use timecurrency_node::ledger::{self, Action, ActionPayload, Commit};
    let dir = tempfile::tempdir().unwrap();
    let pressured = App::open(dir.path().join("pressured.redb")).unwrap();
    let drained = App::open(dir.path().join("drained.redb")).unwrap();
    for app in [&pressured, &drained] {
        app.try_init(init()).unwrap();
        for height in 1..=200 {
            app.try_finalize(block(height)).unwrap();
            app.try_commit().unwrap();
        }
    }
    assert_eq!(health(&pressured)["maintenance"]["pressure"], true);
    for _ in 0..2000 {
        if drained.maintain_idle().unwrap().is_none() {
            break;
        }
    }
    assert_eq!(
        health(&drained)["maintenance"]["eligible_work_pending"],
        false
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let raw = ledger::sign_action(
        &Action {
            network_id: timecurrency_v2::engine::network_id(&genesis()).unwrap(),
            from: u64::MAX,
            nonce: 0,
            auth_epoch: 0,
            public_key: hex::encode(key.verifying_key().as_bytes()),
            payload: ActionPayload::Commit(Commit {
                commitment: "05".repeat(32),
                expires_elapsed_micros: 290_000_000,
            }),
            signature: vec![],
        },
        &key,
    )
    .unwrap();
    assert_ne!(
        pressured
            .check_tx(RequestCheckTx {
                tx: raw.clone().into(),
                ..Default::default()
            })
            .code,
        0
    );
    assert_eq!(
        drained
            .check_tx(RequestCheckTx {
                tx: raw.clone().into(),
                ..Default::default()
            })
            .code,
        0
    );
    let proposal = RequestProcessProposal {
        height: 201,
        time: block(201).time,
        hash: vec![201; 32].into(),
        txs: vec![raw.clone().into()],
        ..Default::default()
    };
    assert_eq!(pressured.process_proposal(proposal.clone()).status, 1);
    assert_eq!(drained.process_proposal(proposal).status, 1);
    let mut request = block(201);
    request.txs = vec![raw.into()];
    let a = pressured.try_finalize(request.clone()).unwrap();
    let b = drained.try_finalize(request).unwrap();
    assert_eq!(a, b);
    let before = health(&pressured);
    assert!(pressured.maintain_idle().unwrap().is_none());
    assert_eq!(health(&pressured), before);
    pressured.try_commit().unwrap();
    drained.try_commit().unwrap();
    assert_eq!(
        pressured.info(RequestInfo::default()).last_block_app_hash,
        drained.info(RequestInfo::default()).last_block_app_hash
    );
    assert!(pressured.maintain_idle().unwrap().is_some());
}
#[test]
fn version_three_is_explicit_and_survives_finalize_commit_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.redb");
    let app = App::open(&path).unwrap();
    let mut input = genesis();
    input.chain_id = "time-devnet-v3-app-tests".into();
    let mut request = init();
    request.chain_id = input.chain_id.clone();
    request.app_state_bytes = serde_json::to_vec(&input).unwrap().into();
    assert_eq!(
        app.try_init(request)
            .unwrap()
            .consensus_params
            .unwrap()
            .version
            .unwrap()
            .app,
        3
    );
    assert_eq!(app.info(RequestInfo::default()).app_version, 3);
    let expected = app.try_finalize(block(1)).unwrap();
    assert_eq!(
        expected
            .consensus_param_updates
            .as_ref()
            .unwrap()
            .version
            .as_ref()
            .unwrap()
            .app,
        3
    );
    app.try_commit().unwrap();
    drop(app);
    let resumed = App::open(&path).unwrap();
    assert_eq!(resumed.info(RequestInfo::default()).app_version, 3);
    assert_eq!(resumed.try_finalize(block(1)).unwrap(), expected);
}
#[test]
fn prepare_finalize_commit_and_restart_bind_identical_consensus_response() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let app = App::open(&path).unwrap();
    let first = app.try_init(init()).unwrap();
    assert_eq!(
        first
            .consensus_params
            .as_ref()
            .unwrap()
            .version
            .as_ref()
            .unwrap()
            .app,
        2
    );
    assert_eq!(app.info(RequestInfo::default()).app_version, 2);
    let done = app.try_finalize(block(1)).unwrap();
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
    assert_eq!(app.try_finalize(block(1)).unwrap(), done);
    app.try_commit().unwrap();
    assert_eq!(app.try_init(init()).unwrap().app_hash, first.app_hash);
    drop(app);
    let app = App::open(&path).unwrap();
    assert_eq!(app.try_finalize(block(1)).unwrap(), done);
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
    let mut conflict = block(1);
    conflict.hash = vec![9; 32].into();
    assert!(app.try_finalize(conflict).is_err());
}
#[test]
fn abandoned_finalize_does_not_publish_any_incremental_tree_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let app = App::open(&path).unwrap();
    let initial = app.try_init(init()).unwrap().app_hash;
    app.try_finalize(block(1)).unwrap();
    drop(app);
    let app = App::open(&path).unwrap();
    assert_eq!(
        app.info(RequestInfo::default()).last_block_app_hash,
        initial
    );
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
    app.try_finalize(block(1)).unwrap();
    app.try_commit().unwrap();
}
#[test]
fn real_query_proves_requested_account_and_name_absence_without_full_registry() {
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(dir.path().join("app.db")).unwrap();
    let root: [u8; 32] = app
        .try_init(init())
        .unwrap()
        .app_hash
        .to_vec()
        .try_into()
        .unwrap();
    let response = app.query(RequestQuery {
        path: "/v2/view".into(),
        data: br#"{"names":["alice","missing_user"]}"#.to_vec().into(),
        ..Default::default()
    });
    assert_eq!(response.code, 0, "{}", response.log);
    let value: serde_json::Value = serde_json::from_slice(&response.value).unwrap();
    let entries: Vec<ProofEntry> = serde_json::from_value(value["entries"].clone()).unwrap();
    assert!(entries.len() <= 6);
    let absent = entries
        .iter()
        .find(|e| e.key_hex == hex::encode(b"name/missing_user"))
        .unwrap();
    assert!(absent.verify(root, b"name/missing_user").unwrap().is_none());
    for e in entries {
        e.verify(root, &hex::decode(&e.key_hex).unwrap()).unwrap();
    }
    let full = app.query(RequestQuery {
        path: "/snapshot".into(),
        ..Default::default()
    });
    assert_ne!(full.code, 0);
}
#[test]
fn malformed_and_oversize_proposals_reject_without_fault_or_publishing() {
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(dir.path().join("app.db")).unwrap();
    app.try_init(init()).unwrap();
    for tx in [vec![1, 2, 3], vec![0; 1024 * 1024 + 1]] {
        let rejected = app.process_proposal(RequestProcessProposal {
            height: 1,
            time: timestamp(2_000_000),
            hash: vec![1; 32].into(),
            txs: vec![tx.into()],
            ..Default::default()
        });
        assert_eq!(
            rejected.status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
    }
    app.try_finalize(block(1)).unwrap();
    app.try_commit().unwrap();
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
}
#[test]
fn benchmark_funding_chains_cannot_be_initialized_by_the_network_binary() {
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(dir.path().join("app.db")).unwrap();
    let mut g = genesis();
    g.chain_id = "time-devnet-fixture-app".into();
    let mut r = init();
    r.chain_id = g.chain_id.clone();
    r.app_state_bytes = serde_json::to_vec(&g).unwrap().into();
    assert!(app.try_init(r).is_err());
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
}

#[test]
fn persisted_fixture_cannot_bypass_network_isolation_by_skipping_init_chain() {
    use timecurrency_v2::{engine::Engine, store::Store};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.db");
    let mut engine = Engine::open(Store::open(&path).unwrap()).unwrap();
    let mut g = genesis();
    g.chain_id = "time-devnet-fixture-persisted".into();
    let original = engine.initialize(g).unwrap();
    drop(engine);
    assert!(App::open(&path).is_err());
    assert_eq!(
        Store::open(&path).unwrap().head().unwrap().unwrap().root,
        original.root
    );
}
