mod common;
use common::{genesis, key, pk};
use ed25519_dalek::Signer;
use tempfile::TempDir;
use timecurrency_node::ledger::{
    self, Account, Action, ActionPayload, Delegate, Transfer, Undelegate, Withdraw,
};
use timecurrency_v4::{
    engine::{Engine, account_key, canonical_decode},
    pos_adapter,
    store::Store,
    wire,
};
struct Harness {
    _dir: TempDir,
    engine: Engine,
}
impl Harness {
    fn new() -> Self {
        Self::with_genesis(genesis())
    }
    fn with_genesis(config: timecurrency_v4::genesis::Genesis) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.redb")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(config).unwrap();
        Self { _dir: dir, engine }
    }
    fn account(&self, id: u64) -> Account {
        canonical_decode(
            &self
                .engine
                .store()
                .snapshot()
                .unwrap()
                .get(&account_key(id))
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }
    fn extension(&self, from: u64, kind: u8, payload: serde_json::Value) -> Vec<u8> {
        let row = self.account(from);
        wire::sign(
            &self.engine.meta().unwrap().network_id,
            from,
            row.nonce + 1,
            row.auth_epoch,
            kind,
            &payload,
            &key(from as u8 + 1),
        )
        .unwrap()
    }
    fn legacy(&self, from: u64, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.engine.meta().unwrap().network_id.clone(),
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
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let m = self.engine.meta().unwrap();
        let height = m.height + 1;
        let time = m.time_micros + delta as i64;
        let eligible = self
            .engine
            .active_roster_at(m.height as u64)
            .unwrap()
            .into_iter()
            .map(|v| v.consensus_key)
            .collect::<Vec<_>>();
        let hash = sha(height as u64);
        let prepared = self
            .engine
            .prepare(height, time, &txs, &eligible, hash)
            .unwrap();
        self.engine.commit(prepared, hash).unwrap();
        self.engine.audit().unwrap();
    }
}
fn sha(value: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(value.to_be_bytes()).into()
}
#[test]
fn initialization_accrual_reopen_and_full_namespace_supply_audit() {
    let mut h = Harness::new();
    h.engine.audit().unwrap();
    h.block(60 * pos::SECOND, vec![]);
    assert_eq!(h.engine.meta().unwrap().liquid_total, 12 * pos::SECOND);
    let head = h.engine.head().unwrap().unwrap();
    let path = h._dir.path().join("state.redb");
    drop(h.engine);
    let mut engine =
        Engine::open_with_history(Store::open(path).unwrap(), h._dir.path().join("history"))
            .unwrap();
    assert_eq!(engine.head().unwrap().unwrap(), head);
    assert_eq!(engine.initialize(genesis()).unwrap().version, 0);
    engine.audit().unwrap();
}
#[test]
fn real_stake_pool_movements_and_failed_filtered_actions_are_atomic() {
    let mut h = Harness::new();
    h.block(60 * pos::SECOND, vec![]);
    let funding = h.legacy(
        0,
        ActionPayload::Transfer(Transfer {
            to: 4,
            amount: 2 * pos::SECOND,
        }),
    );
    h.block(pos::SECOND, vec![funding]);
    let proof = key(120).sign(
        &pos::register_message(
            pos::hex32(&h.engine.meta().unwrap().network_id).unwrap(),
            4,
            &pk(120),
            1000,
        )
        .unwrap(),
    );
    let register=h.extension(4,17,serde_json::json!({"commission_bps":1000,"consensus_key":pk(120),"proof":hex::encode(proof.to_bytes()),"self_bond":"1500000"}));
    h.block(pos::SECOND, vec![register]);
    let bonded: pos::Candidate = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&pos_adapter::candidate_key(4))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(bonded.self_bond, 1_500_000);
    assert_eq!(h.account(4).balance, 499_000);
    let before = h.engine.meta().unwrap().pos_assets_total;
    let delegate = h.legacy(
        1,
        ActionPayload::Delegate(Delegate {
            operator: 4,
            amount: pos::SECOND,
            min_shares: 1,
        }),
    );
    h.block(pos::SECOND, vec![delegate]);
    assert!(h.engine.meta().unwrap().pos_assets_total >= before + pos::SECOND);
    let bad = h.extension(4, 18, serde_json::json!({"amount":u64::MAX.to_string()}));
    let good = h.legacy(
        2,
        ActionPayload::Transfer(Transfer {
            to: 5,
            amount: 1234,
        }),
    );
    let m = h.engine.meta().unwrap();
    let eligible = h
        .engine
        .active_roster_at(m.height as u64)
        .unwrap()
        .into_iter()
        .map(|v| v.consensus_key)
        .collect::<Vec<_>>();
    let hash = sha(m.height as u64 + 1);
    let (filtered, kept) = h
        .engine
        .prepare_filtered(
            m.height + 1,
            m.time_micros + pos::SECOND as i64,
            &[bad, good.clone()],
            &eligible,
            1024 * 1024,
            hash,
        )
        .unwrap();
    let strict = h
        .engine
        .prepare(
            m.height + 1,
            m.time_micros + pos::SECOND as i64,
            std::slice::from_ref(&good),
            &eligible,
            hash,
        )
        .unwrap();
    assert_eq!(kept, vec![good]);
    assert_eq!(filtered.root, strict.root);
    h.engine.commit(filtered, hash).unwrap();
    h.engine.audit().unwrap();
}

#[test]
fn delegation_exit_is_exposed_until_actual_release_height_plus_fourteen_days() {
    let mut h = Harness::new();
    h.block(60 * pos::SECOND, vec![]);
    let fund = h.legacy(
        0,
        ActionPayload::Transfer(Transfer {
            to: 4,
            amount: 2 * pos::SECOND,
        }),
    );
    h.block(pos::SECOND, vec![fund]);
    let proof = key(120).sign(
        &pos::register_message(
            pos::hex32(&h.engine.meta().unwrap().network_id).unwrap(),
            4,
            &pk(120),
            1000,
        )
        .unwrap(),
    );
    let reg=h.extension(4,17,serde_json::json!({"commission_bps":1000,"consensus_key":pk(120),"proof":hex::encode(proof.to_bytes())}));
    h.block(pos::SECOND, vec![reg]);
    let delegate = h.legacy(
        1,
        ActionPayload::Delegate(Delegate {
            operator: 4,
            amount: pos::SECOND,
            min_shares: 1,
        }),
    );
    h.block(25 * pos::SECOND, vec![delegate]);
    let unbond = h.legacy(
        1,
        ActionPayload::Undelegate(Undelegate {
            operator: 4,
            shares: pos::SECOND,
            min_amount: 1,
        }),
    );
    h.block(pos::SECOND, vec![unbond]);
    let stake: pos::OwnerStake = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&pos_adapter::owner_key(1))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stake.exits.len(), 1);
    let entry = stake.exits[0].id;
    let early = h.legacy(1, ActionPayload::Withdraw(Withdraw { entry }));
    assert!(h.engine.validate_tx(&early).is_err());
    h.block(pos::SECOND, vec![]);
    h.block(pos::SECOND, vec![]);
    assert!(h.engine.validate_tx(&early).is_err());
    h.block(pos::UNBOND_DELAY, vec![]);
    let withdraw = h.legacy(1, ActionPayload::Withdraw(Withdraw { entry }));
    h.block(pos::SECOND, vec![withdraw]);
    let stake: pos::OwnerStake = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&pos_adapter::owner_key(1))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(stake.exits.is_empty());
}

fn vote(owner: u64, height: u64, block_byte: u8) -> tendermint::Vote {
    use tendermint::{Hash, Signature, Time, Vote, account, block};
    let public =
        tendermint::PublicKey::from_raw_ed25519(&hex::decode(pk(owner as u8 + 101)).unwrap())
            .unwrap();
    let mut v = Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: height.try_into().unwrap(),
        round: 0u32.try_into().unwrap(),
        block_id: Some(block::Id {
            hash: Hash::Sha256([block_byte; 32]),
            part_set_header: block::parts::Header::new(1, Hash::Sha256([block_byte + 1; 32]))
                .unwrap(),
        }),
        timestamp: Some(Time::from_unix_timestamp(1_800_000_000, 0).unwrap()),
        validator_address: account::Id::from(public),
        validator_index: (owner as u32).try_into().unwrap(),
        signature: None,
        extension: vec![],
        extension_signature: None,
    };
    let mut bytes = Vec::new();
    v.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes)
        .unwrap();
    v.signature =
        Some(Signature::try_from(key(owner as u8 + 101).sign(&bytes).to_bytes().to_vec()).unwrap());
    v
}
#[test]
fn actual_equivocation_freezes_unsafe_roster_and_repair_waits_for_effective_h2() {
    let mut h = Harness::new();
    h.block(60 * pos::SECOND, vec![]);
    let funding = h.legacy(
        1,
        ActionPayload::Transfer(Transfer {
            to: 4,
            amount: 2 * pos::SECOND,
        }),
    );
    h.block(pos::SECOND, vec![funding]);
    let evidence = serde_json::to_value(pos::DoubleSignEvidence {
        first: vote(0, 1, 1),
        second: vote(0, 1, 3),
    })
    .unwrap();
    let raw = h.extension(2, 20, evidence.clone());
    h.block(pos::SECOND, vec![raw]);
    let get_summary = |h: &Harness| -> pos::Summary {
        canonical_decode(
            &h.engine
                .store()
                .snapshot()
                .unwrap()
                .get(pos_adapter::SUMMARY_KEY)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    };
    assert!(get_summary(&h).safety_hold);
    let payment = h.legacy(
        1,
        ActionPayload::Transfer(Transfer {
            to: 5,
            amount: 1000,
        }),
    );
    assert!(h.engine.validate_tx(&payment).is_err());
    let replay = h.extension(2, 20, evidence);
    assert!(h.engine.validate_tx(&replay).is_err());
    let proof = key(120).sign(
        &pos::register_message(
            pos::hex32(&h.engine.meta().unwrap().network_id).unwrap(),
            4,
            &pk(120),
            1000,
        )
        .unwrap(),
    );
    let register=h.extension(4,17,serde_json::json!({"commission_bps":1000,"consensus_key":pk(120),"proof":hex::encode(proof.to_bytes())}));
    h.block(pos::SECOND, vec![register]);
    let announced = h.engine.meta().unwrap().height as u64;
    let s = get_summary(&h);
    assert!(s.safety_hold);
    assert!(s.latest().iter().all(|v| v.owner != 0));
    assert!(s.active.iter().any(|v| v.owner == 0));
    h.block(pos::SECOND, vec![]);
    assert!(get_summary(&h).safety_hold);
    assert!(h.engine.validate_tx(&payment).is_err());
    h.block(pos::SECOND, vec![]);
    assert_eq!(h.engine.meta().unwrap().height as u64, announced + 2);
    assert!(!get_summary(&h).safety_hold);
    assert!(get_summary(&h).active.iter().all(|v| v.owner != 0));
    let payment = h.legacy(
        1,
        ActionPayload::Transfer(Transfer {
            to: 5,
            amount: 1000,
        }),
    );
    h.block(pos::SECOND, vec![payment]);
}

#[test]
fn deterministic_mixed_actions_preserve_supply_and_filter_matches_strict_execution() {
    let mut h = Harness::new();
    h.block(60 * pos::SECOND, vec![]);
    let mut random = 0x1234_5678_9abc_def0u64;
    for index in 0..80u64 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let sender = (random >> 32) % 4;
        let target = (sender + 1 + (random % 3)) % 4;
        let raw = match index % 5 {
            0 => h.legacy(
                sender,
                ActionPayload::Transfer(Transfer {
                    to: target,
                    amount: 1000 + random % 10000,
                }),
            ),
            1 => h.extension(sender, 18, serde_json::json!({"amount":"10000"})),
            2 => h.legacy(
                sender,
                ActionPayload::Delegate(Delegate {
                    operator: target,
                    amount: 10_000,
                    min_shares: 1,
                }),
            ),
            3 => h.extension(
                sender,
                19,
                serde_json::json!({"amount":"1000","min_amount":"1000"}),
            ),
            _ => {
                let row = h.account(sender);
                let now = h.engine.meta().unwrap().elapsed_micros().unwrap();
                let mut reference = Vec::new();
                reference.extend((row.nonce + 1).to_be_bytes());
                reference.extend((now + 60 * pos::SECOND).to_be_bytes());
                reference.extend([index as u8; 16]);
                h.legacy(
                    sender,
                    ActionPayload::MerchantPayment(ledger::MerchantPayment {
                        to: target,
                        amount: 1000,
                        reference: hex::encode(reference),
                    }),
                )
            }
        };
        let mut invalid = raw.clone();
        *invalid.last_mut().unwrap() ^= 1;
        let m = h.engine.meta().unwrap();
        let eligible = h
            .engine
            .active_roster_at(m.height as u64)
            .unwrap()
            .into_iter()
            .map(|v| v.consensus_key)
            .collect::<Vec<_>>();
        let hash = sha(m.height as u64 + 1);
        let (prepared, kept) = h
            .engine
            .prepare_filtered(
                m.height + 1,
                m.time_micros + pos::SECOND as i64,
                &[invalid, raw],
                &eligible,
                1024 * 1024,
                hash,
            )
            .unwrap();
        let strict = h
            .engine
            .prepare(
                m.height + 1,
                m.time_micros + pos::SECOND as i64,
                &kept,
                &eligible,
                hash,
            )
            .unwrap();
        assert_eq!(prepared.root, strict.root);
        h.engine.commit(prepared, hash).unwrap();
        h.engine.audit().unwrap();
    }
}

#[test]
fn inactive_candidate_slot_is_reclaimed_without_discarding_or_pinning_delegator_dust() {
    let mut h = Harness::new();
    h.block(60 * pos::SECOND, vec![]);
    let fund = h.legacy(
        0,
        ActionPayload::Transfer(Transfer {
            to: 4,
            amount: 2 * pos::SECOND,
        }),
    );
    h.block(pos::SECOND, vec![fund]);
    let proof = key(120).sign(
        &pos::register_message(
            pos::hex32(&h.engine.meta().unwrap().network_id).unwrap(),
            4,
            &pk(120),
            1000,
        )
        .unwrap(),
    );
    let reg=h.extension(4,17,serde_json::json!({"commission_bps":1000,"consensus_key":pk(120),"proof":hex::encode(proof.to_bytes())}));
    h.block(pos::SECOND, vec![reg]);
    let dust = h.legacy(
        1,
        ActionPayload::Delegate(Delegate {
            operator: 4,
            amount: 1,
            min_shares: 1,
        }),
    );
    h.block(25 * pos::SECOND, vec![dust]);
    let self_exit = h.extension(
        4,
        19,
        serde_json::json!({"amount":pos::SECOND.to_string(),"min_amount":"1"}),
    );
    h.block(pos::SECOND, vec![self_exit]);
    h.block(pos::SECOND, vec![]);
    h.block(pos::SECOND, vec![]);
    h.block(pos::UNBOND_DELAY + pos::SECOND, vec![]);
    let exit: pos::OwnerStake = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&pos_adapter::owner_key(4))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let claim = h.extension(
        4,
        21,
        serde_json::json!({"entry":exit.exits[0].id.to_string()}),
    );
    h.block(pos::SECOND, vec![claim]);
    let snapshot = h.engine.store().snapshot().unwrap();
    let summary: pos::Summary =
        canonical_decode(&snapshot.get(pos_adapter::SUMMARY_KEY).unwrap().unwrap()).unwrap();
    let archived: pos::Candidate = canonical_decode(
        &snapshot
            .get(&pos_adapter::candidate_key(4))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(archived.archived);
    assert!(archived.pool_assets >= 1);
    assert_eq!(archived.pool_shares, 1);
    assert_eq!(summary.archived_escrow, archived.pool_assets);
    assert_eq!(summary.archived_candidates, 1);
    assert!(!summary.candidate_ids.contains(&"4".into()));
    drop(snapshot);
    let grief = h.legacy(
        2,
        ActionPayload::Delegate(Delegate {
            operator: 4,
            amount: 1,
            min_shares: 1,
        }),
    );
    assert!(h.engine.validate_tx(&grief).is_err());
    let proof = key(121).sign(
        &pos::register_message(
            pos::hex32(&h.engine.meta().unwrap().network_id).unwrap(),
            4,
            &pk(121),
            1000,
        )
        .unwrap(),
    );
    let replace=h.extension(4,17,serde_json::json!({"commission_bps":1000,"consensus_key":pk(121),"proof":hex::encode(proof.to_bytes())}));
    assert!(h.engine.validate_tx(&replace).is_err());
    let unbond = h.legacy(
        1,
        ActionPayload::Undelegate(Undelegate {
            operator: 4,
            shares: 1,
            min_amount: 1,
        }),
    );
    h.block(pos::SECOND, vec![unbond]);
    h.block(pos::SECOND, vec![]);
    h.block(pos::SECOND, vec![]);
    h.block(pos::UNBOND_DELAY, vec![]);
    let stake: pos::OwnerStake = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&pos_adapter::owner_key(1))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let claim = h.legacy(
        1,
        ActionPayload::Withdraw(Withdraw {
            entry: stake.exits[0].id,
        }),
    );
    h.block(pos::SECOND, vec![claim]);
    let snapshot = h.engine.store().snapshot().unwrap();
    assert!(
        snapshot
            .get(&pos_adapter::candidate_key(4))
            .unwrap()
            .is_none()
    );
    assert!(
        snapshot
            .get(&pos_adapter::consensus_key(&pk(120)).unwrap())
            .unwrap()
            .is_some()
    );
    let summary: pos::Summary =
        canonical_decode(&snapshot.get(pos_adapter::SUMMARY_KEY).unwrap().unwrap()).unwrap();
    assert_eq!(summary.archived_escrow, 0);
    assert_eq!(summary.archived_candidates, 0);
}

#[test]
fn history_archive_is_durable_before_commit_and_stale_prepared_cannot_truncate_it() {
    let mut h = Harness::new();
    let m = h.engine.meta().unwrap();
    let first = h
        .engine
        .prepare(1, m.time_micros + 1_000_000, &[], &[], sha(1))
        .unwrap();
    let conflicting = h
        .engine
        .prepare(1, m.time_micros + 1_000_000, &[], &[], sha(99))
        .unwrap();
    h.engine.commit(first, sha(1)).unwrap();
    assert!(h.engine.commit(conflicting, sha(99)).is_err());
    let proof = h.engine.history_proof(1, 1).unwrap();
    assert_eq!(proof.leaf.block_hash, hex::encode(sha(1)));
    assert!(h.engine.audit().unwrap().history_archive_verified);
    let path = h._dir.path().join("state.redb");
    let archive = h._dir.path().join("history");
    drop(h.engine);
    let reopened = Engine::open_with_history(Store::open(path).unwrap(), archive).unwrap();
    assert_eq!(reopened.history_proof(1, 1).unwrap(), proof);
    assert!(reopened.audit().unwrap().history_archive_verified);
}
#[test]
fn expired_canonical_rows_prune_in_bounded_batches_but_history_proofs_remain_verifiable() {
    let mut h = Harness::new();
    for _ in 0..130 {
        h.block(pos::SECOND, vec![]);
    }
    let before = h.engine.history_proof(130, 1).unwrap();
    h.block(pos::UNBOND_DELAY + 2 * pos::SECOND, vec![]);
    assert_eq!(h.engine.meta().unwrap().history_pruned_through, 64);
    assert!(
        h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&timecurrency_v4::engine::block_key(1))
            .unwrap()
            .is_none()
    );
    let proof = h.engine.history_proof(131, 1).unwrap();
    assert_eq!(proof.leaf, before.leaf);
    assert!(proof.siblings.len() <= 63);
    h.block(pos::SECOND, vec![]);
    assert_eq!(h.engine.meta().unwrap().history_pruned_through, 128);
    h.block(pos::SECOND, vec![]);
    assert_eq!(h.engine.meta().unwrap().history_pruned_through, 130);
    let raw = h
        .engine
        .store()
        .snapshot()
        .unwrap()
        .get(history::KEY)
        .unwrap()
        .unwrap();
    let summary: history::Summary = canonical_decode(&raw).unwrap();
    assert_eq!(
        h.engine
            .history_proof(133, 1)
            .unwrap()
            .verify(&summary)
            .unwrap()
            .height,
        1
    );
    assert!(h.engine.audit().unwrap().history_archive_verified);
}

#[test]
fn seven_day_guardian_approval_window_preserves_full_two_day_post_quorum_delay() {
    let mut config = genesis();
    config.recovery_min_delay_micros = 2 * pos::DAY;
    let mut h = Harness::with_genesis(config);
    h.block(60 * pos::SECOND, vec![]);
    let policy = h.legacy(
        2,
        ActionPayload::SetRecovery(ledger::SetRecovery {
            guardians: vec![0, 1, 3],
            threshold: 2,
            delay_seconds: 2 * 86400,
        }),
    );
    h.block(pos::SECOND, vec![policy]);
    for id in [0, 1] {
        let consent = h.legacy(
            id,
            ActionPayload::ConsentRecovery(ledger::ConsentRecovery {
                target: 2,
                policy_version: 1,
                accept: true,
            }),
        );
        h.block(pos::SECOND, vec![consent]);
    }
    let owner = h.account(2);
    let meta = h.engine.meta().unwrap();
    let expiry = meta.elapsed_micros().unwrap() + 2 * pos::DAY + 7 * pos::DAY;
    let recovery_id = "ab".repeat(32);
    let mut proof = b"TCDEVNET-RECOVERY-V1\0".to_vec();
    proof.extend(pos::hex32(&meta.network_id).unwrap());
    proof.extend(2u64.to_be_bytes());
    proof.extend(owner.auth_epoch.to_be_bytes());
    proof.extend(owner.recovery_version.to_be_bytes());
    proof.extend(hex::decode(&recovery_id).unwrap());
    proof.extend(key(220).verifying_key().as_bytes());
    proof.extend(expiry.to_be_bytes());
    let claim = ledger::ApproveRecovery {
        target: 2,
        policy_version: owner.recovery_version,
        recovery_id: recovery_id.clone(),
        new_public_key: pk(220),
        expires_elapsed_micros: expiry,
        proof: hex::encode(key(220).sign(&proof).to_bytes()),
    };
    let first = h.legacy(0, ActionPayload::ApproveRecovery(claim.clone()));
    let old_view = ledger::State {
        genesis: meta.genesis.clone(),
        network_id: meta.network_id.clone(),
        height: meta.height,
        time_micros: meta.time_micros,
        bank: meta.bank,
        accounts: (0..12).map(|id| h.account(id)).collect(),
        name_commits: vec![],
        pools: vec![],
        auction_epoch: meta.auction_epoch,
        auction_bids: vec![],
        next_unbond_id: 0,
        recovery_cases: vec![],
        protocol_version: 1,
    };
    assert!(ledger::validate_tx(&old_view, &first).is_err());
    assert!(ledger::validate_tx_with_recovery_window(&old_view, &first, 7 * pos::DAY).is_ok());
    let mut old_unchanged = old_view.clone();
    assert!(ledger::apply_tx(&mut old_unchanged, &first).is_err());
    assert_eq!(old_view, old_unchanged);
    let mut wrong_network = first.clone();
    wrong_network[wire::DOMAIN.len()] ^= 1;
    assert!(
        ledger::validate_tx_with_recovery_window(&old_view, &wrong_network, 7 * pos::DAY).is_err()
    );
    let mut stale = old_view.clone();
    stale.accounts[0].auth_epoch += 1;
    assert!(ledger::validate_tx_with_recovery_window(&stale, &first, 7 * pos::DAY).is_err());
    let mut wrong_claim = claim.clone();
    wrong_claim.proof = "00".repeat(64);
    let wrong = h.legacy(0, ActionPayload::ApproveRecovery(wrong_claim));
    assert!(ledger::validate_tx_with_recovery_window(&old_view, &wrong, 7 * pos::DAY).is_err());
    let late_second = h.legacy(1, ActionPayload::ApproveRecovery(claim.clone()));
    let mut late = old_view.clone();
    ledger::apply_tx_with_recovery_window(&mut late, &first, 7 * pos::DAY).unwrap();
    late.time_micros =
        late.genesis.genesis_time_micros + i64::try_from(expiry - 2 * pos::DAY + 1).unwrap();
    let late_before = late.clone();
    assert!(ledger::apply_tx_with_recovery_window(&mut late, &late_second, 7 * pos::DAY).is_err());
    assert_eq!(late, late_before);
    h.block(pos::SECOND, vec![first]);
    h.block(pos::DAY, vec![]);
    let second = h.legacy(1, ActionPayload::ApproveRecovery(claim));
    h.block(pos::SECOND, vec![second]);
    let cases: Vec<ledger::RecoveryCase> = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&timecurrency_v4::engine::recovery_key(2))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let ready = cases[0].ready_elapsed_micros.unwrap();
    assert_eq!(
        ready,
        h.engine.meta().unwrap().elapsed_micros().unwrap() + 2 * pos::DAY
    );
    let row = h.account(2);
    let finish = ledger::sign_action(
        &Action {
            network_id: h.engine.meta().unwrap().network_id.clone(),
            from: 2,
            nonce: row.nonce + 1,
            auth_epoch: row.auth_epoch,
            public_key: pk(220),
            payload: ActionPayload::FinalizeRecovery(ledger::FinalizeRecovery { recovery_id }),
            signature: vec![],
        },
        &key(220),
    )
    .unwrap();
    assert!(h.engine.validate_tx(&finish).is_err());
    h.block(2 * pos::DAY - pos::SECOND, vec![]);
    assert!(h.engine.validate_tx(&finish).is_err());
    h.block(pos::SECOND, vec![finish]);
    assert_eq!(h.account(2).devices[0].public_key, pk(220));
    assert!(
        h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&timecurrency_v4::engine::recovery_key(2))
            .unwrap()
            .is_none()
    );
}

#[test]
fn sponsored_registration_is_paid_external_atomic_and_reveal_only_identity_authorizes_account() {
    let mut h = Harness::new();
    h.block(60 * pos::SECOND, vec![]);
    let network = h.engine.meta().unwrap().network_id.clone();
    let identity = key(240);
    let public = pk(240);
    let salt = "12".repeat(32);
    let name = "new_person";
    let commitment = ledger::action_commitment(&network, &public, name, &salt).unwrap();
    let expiry = h.engine.meta().unwrap().elapsed_micros().unwrap() + 3600 * pos::SECOND;
    let free = ledger::sign_action(
        &Action {
            network_id: network.clone(),
            from: u64::MAX,
            nonce: 0,
            auth_epoch: 0,
            public_key: public.clone(),
            payload: ActionPayload::Commit(ledger::Commit {
                commitment: commitment.clone(),
                expires_elapsed_micros: expiry,
            }),
            signature: vec![],
        },
        &identity,
    )
    .unwrap();
    assert!(h.engine.validate_tx(&free).is_err());
    let consent = registration::consent_bytes(
        pos::hex32(&network).unwrap(),
        0,
        pos::hex32(&public).unwrap(),
        pos::hex32(&commitment).unwrap(),
        expiry,
    );
    let input = serde_json::json!({"public_key":public,"commitment":commitment,"expires_elapsed_micros":expiry.to_string(),"proof":hex::encode(identity.sign(&consent).to_bytes())});
    let paid = h.extension(0, 44, input.clone());
    let before = h.account(0).balance;
    let reveal = ledger::sign_action(
        &Action {
            network_id: network.clone(),
            from: u64::MAX,
            nonce: 0,
            auth_epoch: 0,
            public_key: public.clone(),
            payload: ActionPayload::Reveal(ledger::Reveal {
                name: name.into(),
                salt: salt.clone(),
            }),
            signature: vec![],
        },
        &identity,
    )
    .unwrap();
    let m = h.engine.meta().unwrap();
    let eligible = h
        .engine
        .active_roster_at(m.height as u64)
        .unwrap()
        .into_iter()
        .map(|v| v.consensus_key)
        .collect::<Vec<_>>();
    assert!(
        h.engine
            .prepare(
                m.height + 1,
                m.time_micros + pos::SECOND as i64,
                &[paid.clone(), reveal.clone()],
                &eligible,
                sha(m.height as u64 + 1)
            )
            .is_err()
    );
    assert!(
        h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&registration::commit_key(&pos::hex32(&public).unwrap()))
            .unwrap()
            .is_none()
    );
    assert_eq!(h.account(0).balance, before);
    h.block(pos::SECOND, vec![paid]);
    assert!(h.engine.meta().unwrap().name_commits.is_empty());
    assert!(
        h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&registration::commit_key(&pos::hex32(&public).unwrap()))
            .unwrap()
            .is_some()
    );
    let duplicate = h.extension(0, 44, input);
    assert!(h.engine.validate_tx(&duplicate).is_err());
    let bad = ledger::sign_action(
        &Action {
            network_id: network,
            from: u64::MAX,
            nonce: 0,
            auth_epoch: 0,
            public_key: public.clone(),
            payload: ActionPayload::Reveal(ledger::Reveal {
                name: name.into(),
                salt: "13".repeat(32),
            }),
            signature: vec![],
        },
        &identity,
    )
    .unwrap();
    let m = h.engine.meta().unwrap();
    let eligible = h
        .engine
        .active_roster_at(m.height as u64)
        .unwrap()
        .into_iter()
        .map(|v| v.consensus_key)
        .collect::<Vec<_>>();
    let hash = sha(m.height as u64 + 1);
    let (filtered, kept) = h
        .engine
        .prepare_filtered(
            m.height + 1,
            m.time_micros + pos::SECOND as i64,
            &[bad, reveal.clone()],
            &eligible,
            1024 * 1024,
            hash,
        )
        .unwrap();
    let strict = h
        .engine
        .prepare(
            m.height + 1,
            m.time_micros + pos::SECOND as i64,
            std::slice::from_ref(&reveal),
            &eligible,
            hash,
        )
        .unwrap();
    assert_eq!(kept, vec![reveal]);
    assert_eq!(filtered.root, strict.root);
    h.engine.commit(filtered, hash).unwrap();
    h.engine.audit().unwrap();
    assert_eq!(h.account(12).name, name);
    assert_eq!(h.account(12).balance, 0);
    assert_eq!(h.account(12).devices[0].public_key, public);
    assert!(
        h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(&registration::commit_key(&pos::hex32(&public).unwrap()))
            .unwrap()
            .is_none()
    );
    assert!(h.engine.meta().unwrap().name_commits.is_empty());
    h.block(2 * pos::DAY, vec![]);
    let state: registration::State = canonical_decode(
        &h.engine
            .store()
            .snapshot()
            .unwrap()
            .get(registration::STATE_KEY)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(state.queue_entries, 0);
    assert_eq!(state.commitments, 0);
}
