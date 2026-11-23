use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;
use timecurrency_node::ledger::{self, *};
use timecurrency_v2::{
    engine::{
        self, Engine, Meta, account_key, canonical_decode, name_key, pubkey_key, recovery_key,
    },
    store::Store,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().as_bytes())
}
fn genesis() -> Genesis {
    Genesis {
        chain_id: "time-devnet-v2-engine-tests".into(),
        genesis_time_micros: 1_000_000,
        accounts: (0..5)
            .map(|id| GenesisAccount {
                id,
                name: format!("person_{id}"),
                public_key: pk(id as u8 + 1),
            })
            .collect(),
        economics: Economics {
            mode: EconomicMode::DevnetAuction,
            auction_epoch_seconds: 10,
            unbond_seconds: 1,
            operators: vec![Operator {
                account_id: 0,
                consensus_key: pk(101),
                power: 1,
                commission_bps: 0,
            }],
        },
    }
}
struct Harness {
    _dir: TempDir,
    engine: Engine,
    oracle: State,
}
impl Harness {
    fn new() -> Self {
        Self::with_genesis(genesis())
    }
    fn with_genesis(input: Genesis) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(Store::open(dir.path().join("state.redb")).unwrap()).unwrap();
        engine.initialize(input.clone()).unwrap();
        Self {
            _dir: dir,
            engine,
            oracle: ledger::new(input).unwrap(),
        }
    }
    fn eligible(&self) -> Vec<String> {
        self.oracle
            .genesis
            .economics
            .operators
            .iter()
            .map(|o| o.consensus_key.clone())
            .collect()
    }
    fn raw(&self, network: &str, from: u64, seed: u8, payload: ActionPayload) -> Vec<u8> {
        let (nonce, auth_epoch) = if from == u64::MAX {
            (0, 0)
        } else {
            let account = self.oracle.account(from).unwrap();
            (account.nonce + 1, account.auth_epoch)
        };
        sign_action(
            &Action {
                network_id: network.into(),
                from,
                nonce,
                auth_epoch,
                public_key: pk(seed),
                payload,
                signature: Vec::new(),
            },
            &key(seed),
        )
        .unwrap()
    }
    fn step(&mut self, delta: i64, from: u64, seed: u8, make: impl Fn(&str) -> ActionPayload) {
        let network = self.engine.meta().unwrap().network_id.clone();
        let v2 = self.raw(&network, from, seed, make(&network));
        let v1 = self.raw(
            &self.oracle.network_id,
            from,
            seed,
            make(&self.oracle.network_id),
        );
        self.block(delta, vec![v2], vec![v1]);
    }
    fn advance(&mut self, delta: i64) {
        self.block(delta, Vec::new(), Vec::new());
    }
    fn block(&mut self, delta: i64, v2: Vec<Vec<u8>>, v1: Vec<Vec<u8>>) {
        let h = self.oracle.height + 1;
        let time = self.oracle.time_micros + delta;
        let prepared = self.engine.prepare(h, time, &v2, &self.eligible()).unwrap();
        self.oracle =
            transition_with_eligible(&self.oracle, h, time, &v1, &self.eligible()).unwrap();
        self.engine.commit(prepared, [h as u8; 32]).unwrap();
        self.compare();
    }
    fn rejects(&self, from: u64, seed: u8, make: impl Fn(&str) -> ActionPayload) {
        let network = &self.engine.meta().unwrap().network_id;
        let raw = self.raw(network, from, seed, make(network));
        let original = self.engine.head().unwrap();
        assert!(
            self.engine
                .prepare(
                    self.oracle.height + 1,
                    self.oracle.time_micros + 1,
                    &[raw],
                    &self.eligible()
                )
                .is_err()
        );
        let raw = self.raw(
            &self.oracle.network_id,
            from,
            seed,
            make(&self.oracle.network_id),
        );
        assert!(
            transition_with_eligible(
                &self.oracle,
                self.oracle.height + 1,
                self.oracle.time_micros + 1,
                &[raw],
                &self.eligible()
            )
            .is_err()
        );
        assert_eq!(self.engine.head().unwrap(), original);
    }
    fn compare(&self) {
        let meta = self.engine.meta().unwrap();
        assert_eq!(
            (
                meta.height,
                meta.time_micros,
                meta.bank,
                meta.auction_epoch,
                meta.next_unbond_id
            ),
            (
                self.oracle.height,
                self.oracle.time_micros,
                self.oracle.bank,
                self.oracle.auction_epoch,
                self.oracle.next_unbond_id
            )
        );
        assert_eq!(meta.pools, self.oracle.pools);
        assert_eq!(meta.auction_bids, self.oracle.auction_bids);
        assert_eq!(meta.account_count, self.oracle.accounts.len() as u64);
        let snap = self.engine.store().snapshot().unwrap();
        for account in &self.oracle.accounts {
            let actual: Account =
                canonical_decode(&snap.get(&account_key(account.id)).unwrap().unwrap()).unwrap();
            assert_eq!(&actual, account);
            let cases: Vec<RecoveryCase> = snap
                .get(&recovery_key(account.id))
                .unwrap()
                .map(|b| canonical_decode(&b).unwrap())
                .unwrap_or_default();
            let live: Vec<_> = cases
                .into_iter()
                .filter(|c| {
                    c.expires_elapsed_micros >= self.oracle.elapsed_micros().unwrap()
                        && c.auth_epoch == account.auth_epoch
                        && c.policy_version == account.recovery_version
                })
                .collect();
            assert_eq!(
                live,
                self.oracle
                    .recovery_cases
                    .iter()
                    .filter(|c| c.target == account.id)
                    .cloned()
                    .collect::<Vec<_>>()
            );
        }
        let audit = self.engine.audit().unwrap();
        assert_eq!(
            audit.liquid,
            self.oracle.accounts.iter().map(|a| a.balance).sum::<u64>()
        );
        assert_eq!(
            audit.unbond,
            self.oracle
                .accounts
                .iter()
                .flat_map(|a| &a.unbonding)
                .map(|u| u.amount)
                .sum::<u64>()
        );
    }
    fn earned(&mut self) {
        let epoch = self.oracle.auction_epoch;
        self.step(1, 2, 3, |_| ActionPayload::Bid(Bid { epoch, weight: 1 }));
        self.advance(10_000_000 - self.oracle.elapsed_micros().unwrap() as i64);
    }
}

#[test]
fn all_sixteen_actions_match_full_v1_rules_and_independent_recounts() {
    let mut h = Harness::new();
    h.earned();
    h.step(1, 2, 3, |_| {
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: 2_000_000,
        })
    });
    h.step(1, 2, 3, |_| {
        ActionPayload::Transfer(Transfer {
            to: 4,
            amount: 500_000,
        })
    });
    h.step(1, 3, 4, |_| {
        ActionPayload::MerchantPayment(MerchantPayment {
            to: 4,
            amount: 10_000,
            reference: "ab".repeat(32),
        })
    });
    h.step(1, 2, 3, |_| {
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: 1_000_000,
            min_shares: 1,
        })
    });
    h.advance(1_000_000);
    h.step(1, 2, 3, |_| {
        ActionPayload::Undelegate(Undelegate {
            operator: 0,
            shares: 500_000,
            min_amount: 1,
        })
    });
    h.rejects(2, 3, |_| ActionPayload::Withdraw(Withdraw { entry: 0 }));
    h.advance(1_000_001);
    h.step(1, 2, 3, |_| ActionPayload::Withdraw(Withdraw { entry: 0 }));
    h.step(1, 2, 3, |_| {
        ActionPayload::SetRecovery(SetRecovery {
            guardians: vec![3, 4],
            threshold: 2,
            delay_seconds: 30,
        })
    });
    h.step(1, 3, 4, |_| {
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: true,
        })
    });
    h.step(1, 4, 5, |_| {
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: true,
        })
    });
    for round in 0..2 {
        let auth = h.oracle.account(2).unwrap().auth_epoch;
        let expiry = h.oracle.elapsed_micros().unwrap() + 100_000_000;
        let recovery_id = format!("{:02x}", round + 20).repeat(32);
        let make = |network: &str| {
            let mut body = b"TCDEVNET-RECOVERY-V1\0".to_vec();
            body.extend(hex::decode(network).unwrap());
            body.extend(2u64.to_be_bytes());
            body.extend(auth.to_be_bytes());
            body.extend(1u64.to_be_bytes());
            body.extend(hex::decode(&recovery_id).unwrap());
            body.extend(key(8).verifying_key().as_bytes());
            body.extend(expiry.to_be_bytes());
            ActionPayload::ApproveRecovery(ApproveRecovery {
                target: 2,
                policy_version: 1,
                recovery_id: recovery_id.clone(),
                new_public_key: pk(8),
                expires_elapsed_micros: expiry,
                proof: hex::encode(key(8).sign(&body).to_bytes()),
            })
        };
        h.step(1, 3, 4, make);
        h.step(1, 4, 5, make);
        h.rejects(2, 3, |_| {
            ActionPayload::Transfer(Transfer { to: 3, amount: 1 })
        });
        if round == 0 {
            h.step(1, 2, 3, |_| {
                ActionPayload::CancelRecovery(CancelRecovery {})
            });
        } else {
            h.advance(30_000_001);
            h.step(1, 2, 8, |_| {
                ActionPayload::FinalizeRecovery(FinalizeRecovery {
                    recovery_id: recovery_id.clone(),
                })
            });
        }
    }
    h.step(1, 2, 8, |_| ActionPayload::CancelPending(CancelPending {}));
    let auth = h.oracle.account(2).unwrap().auth_epoch;
    h.step(1, 2, 8, |network| {
        let mut body = b"TCDEVNET-DEVICE-V1\0".to_vec();
        body.extend(hex::decode(network).unwrap());
        body.extend(2u64.to_be_bytes());
        body.extend(auth.to_be_bytes());
        body.extend(key(9).verifying_key().as_bytes());
        body.extend([1, 1]);
        ActionPayload::AddDevice(AddDevice {
            public_key: pk(9),
            can_manage: true,
            can_spend: true,
            proof: hex::encode(key(9).sign(&body).to_bytes()),
        })
    });
    h.step(1, 2, 9, |_| {
        ActionPayload::RevokeDevice(RevokeDevice { public_key: pk(8) })
    });
    h.step(1, 3, 4, |_| {
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: false,
        })
    });
    let expiry = h.oracle.elapsed_micros().unwrap() + 90_000_000;
    h.step(1, u64::MAX, 10, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(10), "new_person", &"ac".repeat(32))
                .unwrap(),
            expires_elapsed_micros: expiry,
        })
    });
    h.step(1, u64::MAX, 10, |_| {
        ActionPayload::Reveal(Reveal {
            name: "new_person".into(),
            salt: "ac".repeat(32),
        })
    });
    assert_eq!(h.engine.meta().unwrap().account_count, 6);
}

#[test]
fn deterministic_random_mixed_blocks_match_full_registry_oracle() {
    let mut h = Harness::new();
    h.earned();
    for to in [1, 3, 4] {
        h.step(1, 2, 3, |_| {
            ActionPayload::Transfer(Transfer {
                to,
                amount: 500_000,
            })
        });
    }
    let mut random = 0xa54ff53a5f1d36f1u64;
    for _ in 0..90 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let from = random % 5;
        let to = (from + 1 + random % 4) % 5;
        let seed = from as u8 + 1;
        match random % 5 {
            0 => h.advance((random % 1_500_000 + 1) as i64),
            1 => {
                let epoch = h.oracle.auction_epoch;
                if h.oracle.auction_bids.iter().any(|b| b.account_id == from) {
                    h.advance(10_000_001);
                } else {
                    h.step(1, from, seed, |_| {
                        ActionPayload::Bid(Bid {
                            epoch,
                            weight: 1 + random % 100,
                        })
                    });
                }
            }
            2 => h.step(1, from, seed, |_| {
                ActionPayload::CancelPending(CancelPending {})
            }),
            _ => {
                let payload = Transfer {
                    to,
                    amount: 1 + random % 5000,
                };
                if h.oracle.account(from).unwrap().balance > payload.amount + FEE_MICROS {
                    h.step(1, from, seed, |_| ActionPayload::Transfer(payload.clone()));
                } else {
                    h.rejects(from, seed, |_| ActionPayload::Transfer(payload.clone()));
                }
            }
        }
    }
}

#[test]
fn unique_registration_indices_hidden_behind_bounded_view_are_enforced() {
    let mut h = Harness::new();
    h.advance(1);
    let expiry = 90_000_000;
    h.rejects(u64::MAX, 3, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(3), "another", &"01".repeat(32)).unwrap(),
            expires_elapsed_micros: expiry,
        })
    });
    h.step(1, u64::MAX, 10, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(10), "person_4", &"01".repeat(32)).unwrap(),
            expires_elapsed_micros: expiry,
        })
    });
    h.rejects(u64::MAX, 10, |_| {
        ActionPayload::Reveal(Reveal {
            name: "person_4".into(),
            salt: "01".repeat(32),
        })
    });
    // Existing colliding name belongs to account 4, which is not the sender or
    // highest sentinel in a subsequent six-account registry.
    h.step(1, u64::MAX, 11, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(11), "other_name", &"01".repeat(32))
                .unwrap(),
            expires_elapsed_micros: expiry,
        })
    });
    h.step(1, u64::MAX, 11, |_| {
        ActionPayload::Reveal(Reveal {
            name: "other_name".into(),
            salt: "01".repeat(32),
        })
    });
    h.rejects(u64::MAX, 10, |_| {
        ActionPayload::Reveal(Reveal {
            name: "person_4".into(),
            salt: "01".repeat(32),
        })
    });
}

#[test]
fn filtered_overlay_replay_rollback_restart_and_genesis_replay_are_consistent() {
    let mut h = Harness::new();
    h.earned();
    let meta = h.engine.meta().unwrap();
    let network = meta.network_id.clone();
    let tx = h.raw(
        &network,
        2,
        3,
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: 1000,
        }),
    );
    let before = h.engine.head().unwrap().unwrap();
    let height = before.version as i64 + 1;
    let time = meta.time_micros + 1;
    assert!(
        h.engine
            .prepare(height, time, &[tx.clone(), tx.clone()], &h.eligible())
            .is_err()
    );
    assert_eq!(h.engine.head().unwrap().unwrap(), before);
    let (one, selected) = h
        .engine
        .prepare_filtered(
            height,
            time,
            &[vec![1], tx.clone(), tx],
            &h.eligible(),
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert!(one.touched_accounts <= 3);
    assert!(one.updated_rows <= 4);
    let duplicate = h
        .engine
        .prepare(height, time, &selected, &h.eligible())
        .unwrap();
    assert_eq!(one.root, duplicate.root);
    let genesis_root = h.engine.store().genesis_head().unwrap().unwrap().root;
    h.engine.commit(one, [7; 32]).unwrap();
    assert!(h.engine.commit(duplicate, [7; 32]).is_err());
    assert_eq!(h.engine.initialize(genesis()).unwrap().root, genesis_root);
    h.engine.audit().unwrap();
}

#[test]
fn durable_restart_and_semantic_metadata_corruption_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    let mut engine = Engine::open(Store::open(&path).unwrap()).unwrap();
    engine.initialize(genesis()).unwrap();
    let prepared = engine.prepare(1, 2_000_000, &[], &[pk(101)]).unwrap();
    engine.commit(prepared, [5; 32]).unwrap();
    let expected = engine.head().unwrap();
    drop(engine);
    let engine = Engine::open(Store::open(&path).unwrap()).unwrap();
    assert_eq!(engine.head().unwrap(), expected);
    engine.audit().unwrap();
    // Even a correctly authenticated but semantically impossible new metadata
    // row is refused when reopening. Direct store writes are test-only here.
    let mut corrupt = engine.meta().unwrap().clone();
    corrupt.height += 1;
    corrupt.time_micros += 1;
    corrupt.bank += 2;
    let bytes = serde_json::to_vec(&corrupt).unwrap();
    let mut tree = engine
        .store()
        .prepare_updates(
            corrupt.height as u64,
            vec![(b"meta".to_vec(), Some(bytes.clone()))],
        )
        .unwrap();
    tree.set_head_metadata(bytes, [0; 32]).unwrap();
    engine.store().commit(tree).unwrap();
    drop(engine);
    assert!(Engine::open(Store::open(&path).unwrap()).is_err());
}

#[test]
fn streamed_audit_detects_index_corruption_not_hidden_by_counter_sum() {
    let h = Harness::new();
    let meta = h.engine.meta().unwrap();
    let mut changed = meta.clone();
    changed.height = 1;
    changed.time_micros += 1;
    changed.bank = 1;
    let bytes = serde_json::to_vec(&changed).unwrap();
    let mut prepared = h
        .engine
        .store()
        .prepare_updates(
            1,
            vec![
                (b"meta".to_vec(), Some(bytes.clone())),
                (name_key("person_4"), Some(serde_json::to_vec("3").unwrap())),
            ],
        )
        .unwrap();
    prepared.set_head_metadata(bytes, [0; 32]).unwrap();
    h.engine.store().commit(prepared).unwrap();
    let dir = h._dir.path().to_path_buf();
    drop(h.engine);
    let engine = Engine::open(Store::open(dir.join("state.redb")).unwrap()).unwrap();
    assert!(engine.audit().is_err());
    let wrong_pub = pubkey_key(&pk(3)).unwrap();
    assert!(engine.store().get(&wrong_pub).unwrap().is_some());
}

#[test]
fn network_is_domain_separated_and_old_v1_transaction_cannot_replay() {
    let mut h = Harness::new();
    assert_ne!(h.oracle.network_id, h.engine.meta().unwrap().network_id);
    let epoch = 0;
    let old = h.raw(
        &h.oracle.network_id,
        2,
        3,
        ActionPayload::Bid(Bid { epoch, weight: 1 }),
    );
    assert!(
        h.engine
            .prepare(1, 1_000_001, &[old], &h.eligible())
            .is_err()
    );
    h.advance(1);
    let mut meta: Meta = h.engine.meta().unwrap().clone();
    meta.protocol_version = 1;
    assert!(meta.validate().is_err());
    assert_eq!(
        engine::network_id(&meta.genesis).unwrap(),
        h.engine.meta().unwrap().network_id
    );
}

#[test]
fn filtered_invalid_transaction_cannot_publish_expired_recovery_cleanup() {
    let mut h = Harness::new();
    h.earned();
    for to in [3, 4] {
        h.step(1, 2, 3, |_| {
            ActionPayload::Transfer(Transfer {
                to,
                amount: 100_000,
            })
        });
    }
    h.step(1, 2, 3, |_| {
        ActionPayload::SetRecovery(SetRecovery {
            guardians: vec![3, 4],
            threshold: 2,
            delay_seconds: 30,
        })
    });
    h.step(1, 3, 4, |_| {
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: true,
        })
    });
    let expiry = h.oracle.elapsed_micros().unwrap() + 40_000_000;
    let auth = h.oracle.account(2).unwrap().auth_epoch;
    h.step(1, 3, 4, |network| {
        let mut body = b"TCDEVNET-RECOVERY-V1\0".to_vec();
        body.extend(hex::decode(network).unwrap());
        body.extend(2u64.to_be_bytes());
        body.extend(auth.to_be_bytes());
        body.extend(1u64.to_be_bytes());
        body.extend([19; 32]);
        body.extend(key(8).verifying_key().as_bytes());
        body.extend(expiry.to_be_bytes());
        ActionPayload::ApproveRecovery(ApproveRecovery {
            target: 2,
            policy_version: 1,
            recovery_id: "13".repeat(32),
            new_public_key: pk(8),
            expires_elapsed_micros: expiry,
            proof: hex::encode(key(8).sign(&body).to_bytes()),
        })
    });
    h.advance(40_000_001);
    assert!(h.engine.store().get(&recovery_key(2)).unwrap().is_some());
    let network = h.engine.meta().unwrap().network_id.clone();
    // Permission is checked after loading the source's cases. A failed action
    // must not leak that read's lazy expiry cleanup into the resulting root.
    let invalid = h.raw(
        &network,
        2,
        8,
        ActionPayload::CancelPending(CancelPending {}),
    );
    let valid = h.raw(
        &network,
        3,
        4,
        ActionPayload::Transfer(Transfer { to: 4, amount: 1 }),
    );
    let height = h.oracle.height + 1;
    let time = h.oracle.time_micros + 1;
    let (filtered, kept) = h
        .engine
        .prepare_filtered(
            height,
            time,
            &[invalid, valid.clone()],
            &h.eligible(),
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(kept, vec![valid]);
    let strict = h
        .engine
        .prepare(height, time, &kept, &h.eligible())
        .unwrap();
    assert_eq!(filtered.root, strict.root);
}

#[test]
fn simultaneous_name_claims_and_mempool_checks_use_committed_coordinates() {
    let mut h = Harness::new();
    let before = h.engine.head().unwrap();
    let network = h.engine.meta().unwrap().network_id.clone();
    let commit = h.raw(
        &network,
        u64::MAX,
        10,
        ActionPayload::Commit(Commit {
            commitment: action_commitment(&network, &pk(10), "same_name", &"ba".repeat(32))
                .unwrap(),
            expires_elapsed_micros: 90_000_000,
        }),
    );
    h.engine.validate_tx(&commit).unwrap();
    assert_eq!(h.engine.head().unwrap(), before);
    h.step(1, u64::MAX, 10, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(10), "same_name", &"ba".repeat(32)).unwrap(),
            expires_elapsed_micros: 90_000_000,
        })
    });
    let reveal = h.raw(
        &network,
        u64::MAX,
        10,
        ActionPayload::Reveal(Reveal {
            name: "same_name".into(),
            salt: "ba".repeat(32),
        }),
    );
    assert!(h.engine.validate_tx(&reveal).is_err());
    h.step(1, u64::MAX, 11, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(11), "same_name", &"ba".repeat(32)).unwrap(),
            expires_elapsed_micros: 90_000_000,
        })
    });
    h.engine.validate_tx(&reveal).unwrap();
    h.advance(1);
    let competitor = h.raw(
        &network,
        u64::MAX,
        11,
        ActionPayload::Reveal(Reveal {
            name: "same_name".into(),
            salt: "ba".repeat(32),
        }),
    );
    let before = h.engine.head().unwrap();
    let time = h.oracle.time_micros + 1;
    let height = h.oracle.height + 1;
    assert!(
        h.engine
            .prepare(
                height,
                time,
                &[reveal.clone(), competitor.clone()],
                &h.eligible()
            )
            .is_err()
    );
    assert_eq!(h.engine.head().unwrap(), before);
    let (filtered, kept) = h
        .engine
        .prepare_filtered(
            height,
            time,
            &[reveal.clone(), competitor],
            &h.eligible(),
            1024 * 1024,
        )
        .unwrap();
    assert_eq!(kept, vec![reveal]);
    let strict = h
        .engine
        .prepare(height, time, &kept, &h.eligible())
        .unwrap();
    assert_eq!(strict.root, filtered.root);
    assert_eq!(strict.meta.account_count, 6);
}

#[test]
fn duplicate_genesis_identity_keys_and_noncanonical_metadata_are_rejected() {
    let mut input = genesis();
    input.accounts[4].public_key = input.accounts[3].public_key.clone();
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(Store::open(dir.path().join("state.redb")).unwrap()).unwrap();
    assert!(engine.initialize(input).is_err());
    assert!(engine.head().unwrap().is_none());
    engine.initialize(genesis()).unwrap();
    let mut value = serde_json::to_value(engine.meta().unwrap()).unwrap();
    value["account_count"] = serde_json::json!("05");
    assert!(serde_json::from_value::<Meta>(value).is_err());
    let mut bytes = serde_json::to_vec(engine.meta().unwrap()).unwrap();
    bytes.push(b' ');
    assert!(canonical_decode::<Meta>(&bytes).is_err());
}

#[test]
fn dense_read_only_guardians_do_not_recount_or_recheck_their_escrow_indices() {
    let mut h = Harness::new();
    h.earned();
    let expiry = h.oracle.elapsed_micros().unwrap() + 90_000_000;
    h.step(1, u64::MAX, 6, |network| {
        ActionPayload::Commit(Commit {
            commitment: action_commitment(network, &pk(6), "guardian_five", &"ba".repeat(32))
                .unwrap(),
            expires_elapsed_micros: expiry,
        })
    });
    h.step(1, u64::MAX, 6, |_| {
        ActionPayload::Reveal(Reveal {
            name: "guardian_five".into(),
            salt: "ba".repeat(32),
        })
    });
    let guardians = [0u64, 1, 3, 4, 5];
    for id in guardians {
        h.step(1, 2, 3, |_| {
            ActionPayload::Transfer(Transfer {
                to: id,
                amount: 200_000,
            })
        });
    }
    for id in guardians {
        h.step(1, id, id as u8 + 1, |_| {
            ActionPayload::Delegate(Delegate {
                operator: 0,
                amount: 64_000,
                min_shares: 1,
            })
        });
    }
    // Every escrow is created by signed protocol transitions, not by injecting
    // fabricated account rows. Five distinct accounts each reach the real cap.
    for _ in 0..64 {
        let network = h.engine.meta().unwrap().network_id.clone();
        let mut v2 = Vec::new();
        let mut v1 = Vec::new();
        for id in guardians {
            let payload = ActionPayload::Undelegate(Undelegate {
                operator: 0,
                shares: 1,
                min_amount: 1,
            });
            v2.push(h.raw(&network, id, id as u8 + 1, payload.clone()));
            v1.push(h.raw(&h.oracle.network_id, id, id as u8 + 1, payload));
        }
        h.block(1, v2, v1);
    }
    assert!(
        guardians
            .iter()
            .all(|id| h.oracle.account(*id).unwrap().unbonding.len() == 64)
    );
    let network = h.engine.meta().unwrap().network_id.clone();
    let payload = ActionPayload::SetRecovery(SetRecovery {
        guardians: guardians.to_vec(),
        threshold: 3,
        delay_seconds: 30,
    });
    let raw = h.raw(&network, 2, 3, payload.clone());
    let oracle_raw = h.raw(&h.oracle.network_id, 2, 3, payload);
    let prepared = h
        .engine
        .prepare(h.oracle.height + 1, h.oracle.time_micros + 1, &[raw], &[])
        .unwrap();
    assert_eq!(prepared.touched_accounts, 6);
    assert_eq!(prepared.changed_accounts, 1);
    assert_eq!(prepared.unbond_index_checks, 0);
    assert_eq!(prepared.updated_rows, 2);
    h.oracle = transition_with_eligible(
        &h.oracle,
        h.oracle.height + 1,
        h.oracle.time_micros + 1,
        &[oracle_raw],
        &[],
    )
    .unwrap();
    h.engine.commit(prepared, [7; 32]).unwrap();
    h.compare();
    // A directly changed dense account still verifies every old escrow owner.
    let payment = h.raw(
        &network,
        3,
        4,
        ActionPayload::Transfer(Transfer { to: 4, amount: 1 }),
    );
    let entry = h.oracle.account(3).unwrap().unbonding[0].id;
    let mut meta = h.engine.meta().unwrap().clone();
    meta.height += 1;
    meta.time_micros += 1;
    meta.bank += 1;
    let bytes = serde_json::to_vec(&meta).unwrap();
    let mut tree = h
        .engine
        .store()
        .prepare_updates(
            meta.height as u64,
            vec![
                (b"meta".to_vec(), Some(bytes.clone())),
                (
                    engine::unbond_key(entry),
                    Some(serde_json::to_vec("4").unwrap()),
                ),
            ],
        )
        .unwrap();
    tree.set_head_metadata(bytes, [0; 32]).unwrap();
    h.engine.store().commit(tree).unwrap();
    let path = h._dir.path().join("state.redb");
    drop(h.engine);
    let reopened = Engine::open(Store::open(path).unwrap()).unwrap();
    assert!(
        reopened
            .prepare(meta.height + 1, meta.time_micros + 1, &[payment], &[])
            .is_err()
    );
}

#[test]
fn audit_progress_covers_complete_tree_directory_and_semantic_phases() {
    let h = Harness::new();
    let mut events = Vec::new();
    let audit = h
        .engine
        .audit_with_progress(|event| events.push((event.phase, event.processed, event.total)))
        .unwrap();
    assert_eq!(audit.authenticated_leaves, 16);
    for phase in [
        "tree",
        "directory",
        "accounts",
        "names",
        "public_keys",
        "recovery",
        "unbond",
    ] {
        assert!(events.iter().any(|e| e.0 == phase));
    }
    assert!(
        events
            .iter()
            .any(|e| e.0 == "accounts" && e.1 == 5 && e.2 == Some(5))
    );
    assert!(events.len() < 30);
}

#[test]
fn v3_merchant_reference_reserves_nonce_and_expiry_without_a_global_spent_index() {
    let mut input = genesis();
    input.chain_id = "time-devnet-v3-engine-tests".into();
    let mut h = Harness::with_genesis(input);
    h.earned();
    assert_eq!(h.engine.meta().unwrap().protocol_version, 3);
    let network = h.engine.meta().unwrap().network_id.clone();
    let nonce = h.oracle.account(2).unwrap().nonce + 1;
    let expiry = h.oracle.elapsed_micros().unwrap() + 60_000_000;
    let reference = |nonce: u64, expiry: u64| {
        hex::encode(
            [
                nonce.to_be_bytes().as_slice(),
                expiry.to_be_bytes().as_slice(),
                &[17; 16],
            ]
            .concat(),
        )
    };
    let order = reference(nonce, expiry);
    let payload = ActionPayload::MerchantPayment(MerchantPayment {
        to: 3,
        amount: 1,
        reference: order.clone(),
    });
    let original = h.raw(&network, 2, 3, payload.clone());
    h.step(1, 2, 3, |_| payload.clone());
    assert!(h.engine.validate_tx(&original).is_err());
    // Another wallet cannot re-sign the same order using the new next nonce.
    let replay = h.raw(&network, 2, 3, payload);
    assert!(h.engine.validate_tx(&replay).is_err());
    let next = h.oracle.account(2).unwrap().nonce + 1;
    let now = h.oracle.elapsed_micros().unwrap();
    for deadline in [now - 1, now + 86_400_000_001] {
        let bad = h.raw(
            &network,
            2,
            3,
            ActionPayload::MerchantPayment(MerchantPayment {
                to: 3,
                amount: 1,
                reference: reference(next, deadline),
            }),
        );
        assert!(h.engine.validate_tx(&bad).is_err());
    }
    // A competing ordinary action consumes the reserved slot. The old order
    // cannot be revived; the merchant must issue a fresh order for approval.
    let abandoned = reference(next, expiry);
    h.step(1, 2, 3, |_| ActionPayload::CancelPending(CancelPending {}));
    let bad = h.raw(
        &network,
        2,
        3,
        ActionPayload::MerchantPayment(MerchantPayment {
            to: 3,
            amount: 1,
            reference: abandoned,
        }),
    );
    assert!(h.engine.validate_tx(&bad).is_err());
    h.engine.audit().unwrap();
}

#[test]
fn v2_random_reference_rules_remain_unchanged_and_v3_network_is_isolated() {
    let mut h = Harness::new();
    h.earned();
    h.step(1, 2, 3, |_| {
        ActionPayload::MerchantPayment(MerchantPayment {
            to: 3,
            amount: 1,
            reference: "ab".repeat(32),
        })
    });
    assert_eq!(h.engine.meta().unwrap().protocol_version, 2);
    let mut third = genesis();
    third.chain_id = "time-devnet-v3-isolated".into();
    let v3 = Harness::with_genesis(third.clone());
    let mut hash = sha2::Sha256::new();
    use sha2::Digest;
    hash.update(b"TCDEVNET-NETWORK-V3\0");
    hash.update(serde_json::to_vec(&third).unwrap());
    assert_eq!(
        v3.engine.meta().unwrap().network_id,
        hex::encode(hash.finalize())
    );
    let mut bad = v3.engine.meta().unwrap().clone();
    bad.protocol_version = 2;
    assert!(bad.validate().is_err());
}

#[cfg(feature = "fixtures")]
#[test]
fn synthetic_fixture_path_is_explicit_bounded_and_conserves_every_microsecond() {
    let mut input = genesis();
    input.chain_id = "time-devnet-fixture-engine".into();
    input.economics = Economics::default();
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open(Store::open(dir.path().join("fixture.redb")).unwrap()).unwrap();
    engine.initialize(input).unwrap();
    let account = Account {
        id: 5,
        name: "fixture_one".into(),
        public_key: pk(20),
        balance: 0,
        nonce: 0,
        auth_epoch: 0,
        devices: vec![Device {
            public_key: pk(20),
            can_manage: true,
            can_spend: true,
        }],
        delegations: vec![],
        unbonding: vec![],
        recovery_version: 0,
        recovery_policy: None,
    };
    engine
        .insert_zero_balance_fixture(vec![account.clone()])
        .unwrap();
    assert_eq!(engine.meta().unwrap().bank, 1);
    assert!(engine.insert_zero_balance_fixture(vec![account]).is_err());
    let prepared = engine.prepare(2, 2_000_000, &[], &[]).unwrap();
    engine.commit(prepared, [0; 32]).unwrap();
    engine.fixture_fund_from_bank(5, 100_000).unwrap();
    let audit = engine.audit().unwrap();
    assert_eq!(audit.liquid, 100_000);
    assert_eq!(engine.meta().unwrap().bank, 900_001);
    assert_eq!(engine.meta().unwrap().elapsed_micros().unwrap(), 1_000_001);
    let mut h = Harness::new();
    assert!(h.engine.fixture_fund_from_bank(2, 0).is_err());
}
