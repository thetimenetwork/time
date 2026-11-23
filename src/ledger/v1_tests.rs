use super::*;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().as_bytes())
}
fn genesis() -> Genesis {
    Genesis {
        chain_id: "time-devnet-v1-adversarial".into(),
        genesis_time_micros: 1_000_000,
        accounts: vec![
            GenesisAccount {
                id: 0,
                name: "operator_a".into(),
                public_key: pk(1),
            },
            GenesisAccount {
                id: 1,
                name: "operator_b".into(),
                public_key: pk(2),
            },
        ],
        economics: Economics {
            mode: EconomicMode::DevnetAuction,
            auction_epoch_seconds: 10,
            unbond_seconds: 60,
            operators: vec![
                Operator {
                    account_id: 0,
                    consensus_key: pk(101),
                    power: 3,
                    commission_bps: 0,
                },
                Operator {
                    account_id: 1,
                    consensus_key: pk(102),
                    power: 1,
                    commission_bps: 1_000,
                },
            ],
        },
    }
}
fn anon(state: &State, seed: u8, payload: ActionPayload) -> Vec<u8> {
    sign_action(
        &Action {
            network_id: state.network_id.clone(),
            from: u64::MAX,
            nonce: 0,
            auth_epoch: 0,
            public_key: pk(seed),
            payload,
            signature: Vec::new(),
        },
        &key(seed),
    )
    .unwrap()
}
fn action(state: &State, account: u64, seed: u8, payload: ActionPayload) -> Vec<u8> {
    let source = state.account(account).unwrap();
    sign_action(
        &Action {
            network_id: state.network_id.clone(),
            from: account,
            nonce: source.nonce + 1,
            auth_epoch: source.auth_epoch,
            public_key: pk(seed),
            payload,
            signature: Vec::new(),
        },
        &key(seed),
    )
    .unwrap()
}
fn commit(state: &State, seed: u8, name: &str) -> Vec<u8> {
    anon(
        state,
        seed,
        ActionPayload::Commit(Commit {
            commitment: action_commitment(&state.network_id, &pk(seed), name, &"ab".repeat(32))
                .unwrap(),
            expires_elapsed_micros: state.elapsed_micros().unwrap() + 90_000_000,
        }),
    )
}
fn reveal(state: &State, seed: u8, name: &str) -> Vec<u8> {
    anon(
        state,
        seed,
        ActionPayload::Reveal(Reveal {
            name: name.into(),
            salt: "ab".repeat(32),
        }),
    )
}
fn register(state: &State, seed: u8, name: &str) -> State {
    let committed = transition(
        state,
        state.height + 1,
        state.time_micros + 1,
        &[commit(state, seed, name)],
    )
    .unwrap();
    let revealed = transition(
        &committed,
        committed.height + 1,
        committed.time_micros + 1,
        &[reveal(&committed, seed, name)],
    )
    .unwrap();
    revealed.validate().unwrap();
    revealed
}
fn laboratory() -> State {
    let state = register(&new(genesis()).unwrap(), 3, "alice");
    register(&state, 4, "bob")
}
fn earned() -> State {
    let state = laboratory();
    let bid = action(
        &state,
        2,
        3,
        ActionPayload::Bid(Bid {
            epoch: state.auction_epoch,
            weight: 10,
        }),
    );
    let bidding = transition(&state, state.height + 1, state.time_micros + 1, &[bid]).unwrap();
    transition(
        &bidding,
        bidding.height + 1,
        bidding.genesis.genesis_time_micros + 10_000_000,
        &[],
    )
    .unwrap()
}
fn assert_rejects_unchanged(state: &State, raw: &[u8]) {
    let mut copy = state.clone();
    let hash = copy.hash().unwrap();
    assert!(validate_tx(state, raw).is_err());
    assert!(apply_tx(&mut copy, raw).is_err());
    assert_eq!(hash, copy.hash().unwrap());
}

#[test]
fn v1_registration_requires_proof_commit_delay_and_unique_permanent_name() {
    let base = new(genesis()).unwrap();
    assert_rejects_unchanged(&base, &reveal(&base, 3, "alice"));
    let pending = transition(&base, 1, base.time_micros + 1, &[commit(&base, 3, "alice")]).unwrap();
    assert_rejects_unchanged(&pending, &commit(&pending, 3, "alice"));
    assert_rejects_unchanged(&pending, &reveal(&pending, 3, "alice"));
    assert!(
        transition(
            &base,
            1,
            base.time_micros + 1,
            &[commit(&base, 3, "alice"), reveal(&base, 3, "alice")]
        )
        .is_err()
    );
    let registered = transition(
        &pending,
        2,
        pending.time_micros + 1,
        &[reveal(&pending, 3, "alice")],
    )
    .unwrap();
    assert_eq!(registered.account(2).unwrap().name, "alice");
    assert_eq!(registered.account(2).unwrap().balance, 0);
    assert_rejects_unchanged(&registered, &commit(&registered, 3, "another_name"));
    let stolen = transition(
        &registered,
        3,
        registered.time_micros + 1,
        &[commit(&registered, 4, "alice")],
    )
    .unwrap();
    assert!(
        transition(
            &stolen,
            4,
            stolen.time_micros + 1,
            &[reveal(&stolen, 4, "alice")]
        )
        .is_err()
    );
    let wrong = anon(
        &pending,
        3,
        ActionPayload::Reveal(Reveal {
            name: "alice".into(),
            salt: "cd".repeat(32),
        }),
    );
    assert!(transition(&pending, 2, pending.time_micros + 1, &[wrong]).is_err());
}

#[test]
fn v1_expired_commit_signature_cannot_reopen_registration_slot() {
    let base = new(genesis()).unwrap();
    let raw = commit(&base, 3, "alice");
    let pending = transition(&base, 1, base.time_micros + 1, std::slice::from_ref(&raw)).unwrap();
    let expired = transition(&pending, 2, base.time_micros + 90_000_001, &[]).unwrap();
    assert!(expired.name_commits.is_empty());
    assert_rejects_unchanged(&expired, &raw);
    let invalid_deadline = anon(
        &base,
        3,
        ActionPayload::Commit(Commit {
            commitment: "aa".repeat(32),
            expires_elapsed_micros: 120_000_001,
        }),
    );
    assert_rejects_unchanged(&base, &invalid_deadline);
}

#[test]
fn v1_wire_rejects_unknown_duplicate_noncanonical_and_trailing_payload() {
    let state = earned();
    let raw = action(
        &state,
        2,
        3,
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
    );
    assert_eq!(
        decode_action(&raw).unwrap().payload,
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 })
    );
    let header = v1::ACTION_DOMAIN.len() + 32 + 1 + 24 + 32;
    for text in [
        r#"{"to":"3","amount":"1","amount":"2"}"#,
        r#"{"to":"3","amount":"1","admin":true}"#,
        r#"{"amount":"1","to":"3"}"#,
        r#"{"to":3,"amount":"1"}"#,
        r#"{"to":"03","amount":"1"}"#,
        r#"{ "to":"3","amount":"1"}"#,
        r#"{"to":"3","amount":"1"} "#,
    ] {
        let mut bad = raw[..header].to_vec();
        bad.extend_from_slice(&(text.len() as u32).to_be_bytes());
        bad.extend_from_slice(text.as_bytes());
        let signature = key(3).sign(&bad).to_bytes();
        bad.extend_from_slice(&signature);
        assert_rejects_unchanged(&state, &bad);
    }
    for offset in [0, v1::ACTION_DOMAIN.len(), raw.len() - 65, raw.len() - 1] {
        let mut bad = raw.clone();
        bad[offset] ^= 1;
        assert_rejects_unchanged(&state, &bad);
    }
    for len in [0, 1, 100, raw.len() - 1] {
        assert_rejects_unchanged(&state, &raw[..len]);
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_rejects_unchanged(&state, &trailing);
}

#[test]
fn v1_auction_moves_existing_bank_without_faucet_and_bid_has_no_cash_requirement() {
    let state = earned();
    state.validate().unwrap();
    assert_eq!(state.elapsed_micros().unwrap(), 10_000_000);
    assert!(state.account(2).unwrap().balance >= 8_000_000);
    assert_eq!(state.account(3).unwrap().balance, 0);
    assert!(state.auction_bids.is_empty());
    assert_eq!(state.auction_epoch, 1);
    let transfer = action(
        &state,
        2,
        3,
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: 2_000_000,
        }),
    );
    let sent = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        std::slice::from_ref(&transfer),
    )
    .unwrap();
    assert_eq!(sent.account(3).unwrap().balance, 2_000_000);
    assert_rejects_unchanged(&sent, &transfer);
    sent.validate().unwrap();
}

#[test]
fn v1_auction_bids_unique_weight_bounded_and_old_bid_cannot_claim_future_epochs() {
    let state = laboratory();
    let raw = action(
        &state,
        2,
        3,
        ActionPayload::Bid(Bid {
            epoch: 0,
            weight: 1,
        }),
    );
    let bidding = transition(&state, state.height + 1, state.time_micros + 1, &[raw]).unwrap();
    assert_rejects_unchanged(
        &bidding,
        &action(
            &bidding,
            2,
            3,
            ActionPayload::Bid(Bid {
                epoch: 0,
                weight: 999,
            }),
        ),
    );
    for (epoch, weight) in [(1, 1), (0, 0), (0, 1_000_001)] {
        assert_rejects_unchanged(
            &state,
            &action(&state, 2, 3, ActionPayload::Bid(Bid { epoch, weight })),
        );
    }
    let jumped = transition(
        &bidding,
        bidding.height + 1,
        bidding.genesis.genesis_time_micros + 100_000_000,
        &[],
    )
    .unwrap();
    assert!(jumped.account(2).unwrap().balance <= 8_000_010);
    assert!(jumped.bank >= 71_999_990);
    jumped.validate().unwrap();
}

#[test]
fn v1_auction_multi_bid_integer_dust_stays_in_bank() {
    let state = laboratory();
    let one = action(
        &state,
        2,
        3,
        ActionPayload::Bid(Bid {
            epoch: 0,
            weight: 1,
        }),
    );
    let two = action(
        &state,
        3,
        4,
        ActionPayload::Bid(Bid {
            epoch: 0,
            weight: 2,
        }),
    );
    let bidding = transition(&state, state.height + 1, state.time_micros + 1, &[one, two]).unwrap();
    let settled = transition(
        &bidding,
        bidding.height + 1,
        bidding.genesis.genesis_time_micros + 10_000_000,
        &[],
    )
    .unwrap();
    let a = settled.account(2).unwrap().balance;
    let b = settled.account(3).unwrap().balance;
    assert!(b == a * 2 || b == a * 2 + 1);
    assert!(settled.bank <= 2);
    settled.validate().unwrap();
}

#[test]
fn v1_delegation_compounds_unbonds_after_real_elapsed_delay_and_conserves() {
    let state = earned();
    let deposit = action(
        &state,
        2,
        3,
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: 2_000_000,
            min_shares: 2_000_000,
        }),
    );
    let delegated =
        transition(&state, state.height + 1, state.time_micros + 1, &[deposit]).unwrap();
    assert_eq!(delegated.pools[0].assets, 2_000_000);
    assert_eq!(delegated.pools[0].total_shares, 2_000_000);
    let rewarded = transition(
        &delegated,
        delegated.height + 1,
        delegated.time_micros + 10_000_000,
        &[],
    )
    .unwrap();
    assert!(rewarded.pools[0].assets >= 3_499_999);
    rewarded.validate().unwrap();
    let unbond = action(
        &rewarded,
        2,
        3,
        ActionPayload::Undelegate(Undelegate {
            operator: 0,
            shares: 2_000_000,
            min_amount: 3_499_999,
        }),
    );
    let unbonded = transition(
        &rewarded,
        rewarded.height + 1,
        rewarded.time_micros + 1,
        &[unbond],
    )
    .unwrap();
    assert_eq!(unbonded.pools[0].assets, 0);
    assert_eq!(unbonded.pools[0].total_shares, 0);
    let pending = &unbonded.account(2).unwrap().unbonding[0];
    let escrow = pending.amount;
    let id = pending.id;
    let withdraw = action(
        &unbonded,
        2,
        3,
        ActionPayload::Withdraw(Withdraw { entry: id }),
    );
    assert_rejects_unchanged(&unbonded, &withdraw);
    let ready = transition(
        &unbonded,
        unbonded.height + 1,
        unbonded.time_micros + 60_000_000,
        &[],
    )
    .unwrap();
    let before = ready.account(2).unwrap().balance;
    let paid = transition(
        &ready,
        ready.height + 1,
        ready.time_micros + 1,
        &[action(
            &ready,
            2,
            3,
            ActionPayload::Withdraw(Withdraw { entry: id }),
        )],
    )
    .unwrap();
    assert_eq!(
        paid.account(2).unwrap().balance,
        before + escrow - FEE_MICROS
    );
    assert!(paid.account(2).unwrap().unbonding.is_empty());
    paid.validate().unwrap();
    assert_rejects_unchanged(
        &paid,
        &action(&paid, 2, 3, ActionPayload::Withdraw(Withdraw { entry: id })),
    );
}

#[test]
fn v1_missing_commit_power_stays_bank_and_commission_does_not_mint() {
    let base = new(genesis()).unwrap();
    let only_b =
        transition_with_eligible(&base, 1, base.time_micros + 10_000_000, &[], &[pk(102)]).unwrap();
    assert_eq!(only_b.account(0).unwrap().balance, 0);
    assert_eq!(only_b.account(1).unwrap().balance, 500_000);
    assert_eq!(only_b.bank, 9_500_000);
    let all = transition(&base, 1, base.time_micros + 10_000_000, &[]).unwrap();
    assert_eq!(all.account(0).unwrap().balance, 1_500_000);
    assert_eq!(all.account(1).unwrap().balance, 500_000);
    assert!(
        transition_with_eligible(&base, 1, base.time_micros + 1, &[], &[pk(102), pk(102)]).is_err()
    );
    assert!(transition_with_eligible(&base, 1, base.time_micros + 1, &[], &[pk(103)]).is_err());
    all.validate().unwrap();
}

fn device_payload(
    state: &State,
    account_id: u64,
    seed: u8,
    manage: bool,
    spend: bool,
) -> AddDevice {
    let account = state.account(account_id).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(v1::DEVICE_DOMAIN);
    bytes.extend_from_slice(&hex::decode(&state.network_id).unwrap());
    bytes.extend_from_slice(&account_id.to_be_bytes());
    bytes.extend_from_slice(&account.auth_epoch.to_be_bytes());
    bytes.extend_from_slice(key(seed).verifying_key().as_bytes());
    bytes.extend_from_slice(&[u8::from(manage), u8::from(spend)]);
    AddDevice {
        public_key: pk(seed),
        can_manage: manage,
        can_spend: spend,
        proof: hex::encode(key(seed).sign(&bytes).to_bytes()),
    }
}

#[test]
fn v1_new_device_proves_possession_and_revocation_kills_old_and_legacy_authority() {
    let state = earned();
    let payload = device_payload(&state, 2, 5, true, true);
    let added = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        &[action(
            &state,
            2,
            3,
            ActionPayload::AddDevice(payload.clone()),
        )],
    )
    .unwrap();
    assert_eq!(added.account(2).unwrap().auth_epoch, 1);
    assert_eq!(added.account(2).unwrap().devices.len(), 2);
    assert_rejects_unchanged(
        &added,
        &action(&added, 2, 3, ActionPayload::AddDevice(payload)),
    );
    let old = action(
        &added,
        2,
        3,
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
    );
    let revoked = transition(
        &added,
        added.height + 1,
        added.time_micros + 1,
        &[action(
            &added,
            2,
            5,
            ActionPayload::RevokeDevice(RevokeDevice { public_key: pk(3) }),
        )],
    )
    .unwrap();
    assert_rejects_unchanged(&revoked, &old);
    assert_rejects_unchanged(
        &revoked,
        &action(
            &revoked,
            2,
            3,
            ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
        ),
    );
    assert_rejects_unchanged(
        &revoked,
        &action(
            &revoked,
            2,
            5,
            ActionPayload::RevokeDevice(RevokeDevice { public_key: pk(5) }),
        ),
    );
    let sent = transition(
        &revoked,
        revoked.height + 1,
        revoked.time_micros + 1,
        &[action(
            &revoked,
            2,
            5,
            ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
        )],
    )
    .unwrap();
    sent.validate().unwrap();
    let legacy = sign_tx(
        &Tx {
            network_id: sent.network_id.clone(),
            from: 2,
            to: 3,
            nonce: sent.account(2).unwrap().nonce + 1,
            amount: 1,
            fee: FEE_MICROS,
            signature: Vec::new(),
        },
        &key(3),
    )
    .unwrap();
    assert_rejects_unchanged(&sent, &legacy);
}

#[test]
fn v1_device_proof_binds_network_account_epoch_permissions_and_device_limit() {
    let state = earned();
    let valid = device_payload(&state, 2, 5, false, true);
    for case in 0..4 {
        let mut payload = valid.clone();
        match case {
            0 => payload.can_manage = true,
            1 => payload.public_key = pk(6),
            2 => payload.proof = "00".repeat(64),
            _ => payload.proof = payload.proof.to_uppercase(),
        }
        assert_rejects_unchanged(
            &state,
            &action(&state, 2, 3, ActionPayload::AddDevice(payload)),
        );
    }
    let added = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        &[action(&state, 2, 3, ActionPayload::AddDevice(valid))],
    )
    .unwrap();
    assert_rejects_unchanged(
        &added,
        &action(
            &added,
            2,
            5,
            ActionPayload::RevokeDevice(RevokeDevice { public_key: pk(3) }),
        ),
    );
    let login = device_payload(&added, 2, 6, false, false);
    let login_only = transition(
        &added,
        added.height + 1,
        added.time_micros + 1,
        &[action(&added, 2, 3, ActionPayload::AddDevice(login))],
    )
    .unwrap();
    assert_rejects_unchanged(
        &login_only,
        &action(
            &login_only,
            2,
            6,
            ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
        ),
    );
    let mut full = login_only;
    for seed in 7..12 {
        let payload = device_payload(&full, 2, seed, false, true);
        full = transition(
            &full,
            full.height + 1,
            full.time_micros + 1,
            &[action(&full, 2, 3, ActionPayload::AddDevice(payload))],
        )
        .unwrap();
    }
    assert_eq!(full.account(2).unwrap().devices.len(), MAX_DEVICES);
    assert_rejects_unchanged(
        &full,
        &action(
            &full,
            2,
            3,
            ActionPayload::AddDevice(device_payload(&full, 2, 12, false, true)),
        ),
    );
}

#[test]
fn v1_invalid_mixed_block_and_failed_stake_are_atomic() {
    let state = earned();
    let before = state.hash().unwrap();
    let one = action(
        &state,
        2,
        3,
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
    );
    assert!(
        transition(
            &state,
            state.height + 1,
            state.time_micros + 1,
            &[one.clone(), one]
        )
        .is_err()
    );
    assert_eq!(before, state.hash().unwrap());
    for payload in [
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: u64::MAX,
        }),
        ActionPayload::Delegate(Delegate {
            operator: 999,
            amount: 1,
            min_shares: 1,
        }),
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: 1,
            min_shares: 2,
        }),
        ActionPayload::Undelegate(Undelegate {
            operator: 0,
            shares: 1,
            min_amount: 1,
        }),
    ] {
        assert_rejects_unchanged(&state, &action(&state, 2, 3, payload));
    }
}

#[test]
fn v1_state_detects_forged_devices_pool_shares_escrow_and_names() {
    let state = earned();
    for case in 0..7 {
        let mut corrupt = state.clone();
        match case {
            0 => corrupt.accounts[2].devices[0].public_key = "00".repeat(32),
            1 => corrupt.accounts[2].auth_epoch = corrupt.accounts[2].nonce + 1,
            2 => corrupt.pools[0].assets = 1,
            3 => corrupt.accounts[2].unbonding.push(Unbonding {
                id: 0,
                amount: 1,
                unlock_elapsed_micros: 0,
            }),
            4 => corrupt.accounts[3].name = "alice".into(),
            5 => corrupt.auction_epoch += 1,
            _ => corrupt.accounts[2].devices.clear(),
        }
        assert!(corrupt.validate().is_err(), "case {case}");
    }
}

#[test]
fn v1_bank_only_mode_rejects_synthetic_economics() {
    let mut configuration = genesis();
    configuration.economics = Economics::default();
    let state = register(&new(configuration).unwrap(), 3, "alice");
    assert_rejects_unchanged(
        &state,
        &action(
            &state,
            2,
            3,
            ActionPayload::Bid(Bid {
                epoch: state.auction_epoch,
                weight: 1,
            }),
        ),
    );
}

#[test]
fn v1_wide_integer_json_is_exact_and_rejects_ambiguous_strings() {
    let mut state = earned();
    state.accounts[2].nonce = u64::MAX - 1;
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["accounts"][2]["nonce"], "18446744073709551614");
    let round: State = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(round, state);
    round.validate().unwrap();
    for text in ["01", "+1", "-0", "1.0", "18446744073709551616"] {
        let mut bad = json.clone();
        bad["bank"] = serde_json::json!(text);
        assert!(serde_json::from_value::<State>(bad).is_err());
    }
}

#[test]
fn v1_randomized_valid_and_invalid_sequences_conserve_every_micro() {
    let mut state = earned();
    let mut rng = 0x123456789abcdefu64;
    for step in 0..250 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let balance = state.account(2).unwrap().balance;
        let payload = match rng % 5 {
            0 => ActionPayload::Bid(Bid {
                epoch: state.auction_epoch,
                weight: rng % 1000 + 1,
            }),
            1 => ActionPayload::Transfer(Transfer {
                to: 3,
                amount: rng % balance.max(1) + 1,
            }),
            2 => ActionPayload::Delegate(Delegate {
                operator: 0,
                amount: rng % balance.max(1) + 1,
                min_shares: 1,
            }),
            3 => ActionPayload::Undelegate(Undelegate {
                operator: 0,
                shares: rng % 100_000 + 1,
                min_amount: 1,
            }),
            _ => ActionPayload::Withdraw(Withdraw { entry: rng % 64 }),
        };
        let raw = action(&state, 2, 3, payload);
        let prior = state.hash().unwrap();
        match transition(
            &state,
            state.height + 1,
            state.time_micros + 1_000_000,
            &[raw],
        ) {
            Ok(next) => {
                next.validate().unwrap();
                state = next;
            }
            Err(_) => {
                assert_eq!(prior, state.hash().unwrap());
                state = transition(&state, state.height + 1, state.time_micros + 1_000_000, &[])
                    .unwrap();
            }
        }
        assert_eq!(
            state.elapsed_micros().unwrap(),
            10_000_000 + (step + 1) * 1_000_000
        );
    }
}

#[test]
fn v1_thin_pool_rounding_donation_is_rejected() {
    let state = earned();
    let first = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        &[action(
            &state,
            2,
            3,
            ActionPayload::Delegate(Delegate {
                operator: 0,
                amount: 1,
                min_shares: 1,
            }),
        )],
    )
    .unwrap();
    let grown = transition(
        &first,
        first.height + 1,
        first.time_micros + 10_000_000,
        &[],
    )
    .unwrap();
    let price = grown.pools[0].assets;
    assert_rejects_unchanged(
        &grown,
        &action(
            &grown,
            2,
            3,
            ActionPayload::Delegate(Delegate {
                operator: 0,
                amount: price + price / 2,
                min_shares: 1,
            }),
        ),
    );
}

#[test]
fn v1_rust_matches_independent_node_crypto_golden_vectors() {
    let spec: serde_json::Value =
        serde_json::from_str(include_str!("../../spec/action-v1.json")).unwrap();
    for vector in spec["vectors"].as_array().unwrap() {
        let raw = hex::decode(vector["raw_hex"].as_str().unwrap()).unwrap();
        let decoded = decode_action(&raw).unwrap();
        assert_eq!(
            decoded.payload.kind() as u64,
            vector["kind"].as_u64().unwrap()
        );
        assert_eq!(sign_action(&decoded, &key(3)).unwrap(), raw);
        public_key(&decoded.public_key)
            .unwrap()
            .verify_strict(
                &raw[..raw.len() - 64],
                &Signature::from_slice(&decoded.signature).unwrap(),
            )
            .unwrap();
    }
    let expected = &spec["commitment_vector"];
    assert_eq!(
        action_commitment(
            expected["network_id"].as_str().unwrap(),
            expected["public_key"].as_str().unwrap(),
            expected["name"].as_str().unwrap(),
            expected["salt"].as_str().unwrap()
        )
        .unwrap(),
        expected["commitment"]
    );
}

#[test]
fn v1_free_bid_is_valid_in_zero_issuance_first_comet_block() {
    let base = new(genesis()).unwrap();
    let bid = action(
        &base,
        0,
        1,
        ActionPayload::Bid(Bid {
            epoch: 0,
            weight: 1,
        }),
    );
    let first = transition(&base, 1, base.time_micros, &[bid]).unwrap();
    assert_eq!(first.bank, 0);
    assert_eq!(first.account(0).unwrap().balance, 0);
    assert_eq!(first.account(0).unwrap().nonce, 1);
    first.validate().unwrap();
}

#[test]
fn v1_original_genesis_key_cannot_bypass_device_rotation_using_legacy_transfer() {
    let base = new(genesis()).unwrap();
    let funded = transition(&base, 1, base.time_micros + 10_000_000, &[]).unwrap();
    let legacy = |state: &State| {
        sign_tx(
            &Tx {
                network_id: state.network_id.clone(),
                from: 0,
                to: 1,
                nonce: state.account(0).unwrap().nonce + 1,
                amount: 1,
                fee: FEE_MICROS,
                signature: Vec::new(),
            },
            &key(1),
        )
        .unwrap()
    };
    validate_tx(&funded, &legacy(&funded)).unwrap();
    let added = transition(
        &funded,
        2,
        funded.time_micros + 1,
        &[action(
            &funded,
            0,
            1,
            ActionPayload::AddDevice(device_payload(&funded, 0, 5, true, true)),
        )],
    )
    .unwrap();
    assert_rejects_unchanged(&added, &legacy(&added));
    let revoked = transition(
        &added,
        3,
        added.time_micros + 1,
        &[action(
            &added,
            0,
            5,
            ActionPayload::RevokeDevice(RevokeDevice { public_key: pk(1) }),
        )],
    )
    .unwrap();
    assert_rejects_unchanged(&revoked, &legacy(&revoked));
    assert_rejects_unchanged(
        &revoked,
        &action(
            &revoked,
            0,
            1,
            ActionPayload::Transfer(Transfer { to: 1, amount: 1 }),
        ),
    );
}

#[test]
fn v1_stale_authority_cross_network_wrong_key_and_nonce_exhaustion_reject() {
    let state = earned();
    let raw = action(
        &state,
        2,
        3,
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
    );
    let correct = decode_action(&raw).unwrap();
    for case in 0..6 {
        let mut changed = correct.clone();
        match case {
            0 => changed.network_id = "22".repeat(32),
            1 => changed.auth_epoch = 1,
            2 => changed.nonce = 0,
            3 => changed.nonce += 1,
            4 => changed.public_key = pk(4),
            _ => changed.from = 3,
        }
        assert_rejects_unchanged(&state, &sign_action(&changed, &key(3)).unwrap());
    }
    let mut exhausted = state.clone();
    exhausted.accounts[2].nonce = u64::MAX;
    let mut impossible = correct;
    impossible.nonce = 0;
    assert_rejects_unchanged(&exhausted, &sign_action(&impossible, &key(3)).unwrap());
}

#[test]
fn v1_bonded_pool_commission_is_a_split_of_existing_issuance() {
    let state = earned();
    let delegated = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        &[action(
            &state,
            2,
            3,
            ActionPayload::Delegate(Delegate {
                operator: 1,
                amount: 1_000_000,
                min_shares: 1_000_000,
            }),
        )],
    )
    .unwrap();
    let operator_before = delegated.account(1).unwrap().balance;
    let rewarded = transition(
        &delegated,
        delegated.height + 1,
        delegated.time_micros + 10_000_000,
        &[],
    )
    .unwrap();
    assert_eq!(
        rewarded.account(1).unwrap().balance - operator_before,
        50_000
    );
    assert_eq!(rewarded.pools[1].assets, 1_450_000);
    rewarded.validate().unwrap();
}

#[test]
fn v1_merchant_reference_is_signed_exactly_and_cannot_be_substituted() {
    let state = earned();
    let one = action(
        &state,
        2,
        3,
        ActionPayload::MerchantPayment(MerchantPayment {
            to: 3,
            amount: 1_000_000,
            reference: "aa".repeat(32),
        }),
    );
    let two = action(
        &state,
        2,
        3,
        ActionPayload::MerchantPayment(MerchantPayment {
            to: 3,
            amount: 1_000_000,
            reference: "bb".repeat(32),
        }),
    );
    assert_ne!(Sha256::digest(&one), Sha256::digest(&two));
    let mut substituted = two.clone();
    let signature = one[one.len() - 64..].to_vec();
    let signature_start = substituted.len() - 64;
    substituted[signature_start..].copy_from_slice(&signature);
    assert_rejects_unchanged(&state, &substituted);
    let paid = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        std::slice::from_ref(&one),
    )
    .unwrap();
    assert_eq!(paid.account(3).unwrap().balance, 1_000_000);
    paid.validate().unwrap();
    assert_rejects_unchanged(&paid, &one);
    assert_rejects_unchanged(&paid, &two);
    for reference in ["ab".repeat(31), "AB".repeat(32), "zz".repeat(32)] {
        assert_rejects_unchanged(
            &state,
            &action(
                &state,
                2,
                3,
                ActionPayload::MerchantPayment(MerchantPayment {
                    to: 3,
                    amount: 1,
                    reference,
                }),
            ),
        );
    }
}

fn execute(state: &State, account: u64, seed: u8, payload: ActionPayload) -> State {
    transition(
        state,
        state.height + 1,
        state.time_micros + 1,
        &[action(state, account, seed, payload)],
    )
    .unwrap()
}
fn recoverable() -> State {
    let base = earned();
    let paid = execute(
        &base,
        2,
        3,
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: 1_000_000,
        }),
    );
    let mut state = execute(
        &paid,
        2,
        3,
        ActionPayload::SetRecovery(SetRecovery {
            guardians: vec![0, 1, 3],
            threshold: 2,
            delay_seconds: 30,
        }),
    );
    for (id, seed) in [(0, 1), (1, 2), (3, 4)] {
        state = execute(
            &state,
            id,
            seed,
            ActionPayload::ConsentRecovery(ConsentRecovery {
                target: 2,
                policy_version: 1,
                accept: true,
            }),
        );
    }
    state
}
fn recovery_claim(state: &State, seed: u8, id: &str) -> ApproveRecovery {
    let owner = state.account(2).unwrap();
    let expiry = state.elapsed_micros().unwrap()
        + owner.recovery_policy.as_ref().unwrap().delay_seconds * MICROS_PER_SECOND
        + 600_000_000;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(recovery::RECOVERY_DOMAIN);
    bytes.extend_from_slice(&hex::decode(&state.network_id).unwrap());
    bytes.extend_from_slice(&2u64.to_be_bytes());
    bytes.extend_from_slice(&owner.auth_epoch.to_be_bytes());
    bytes.extend_from_slice(&owner.recovery_version.to_be_bytes());
    bytes.extend_from_slice(&hex::decode(id).unwrap());
    bytes.extend_from_slice(key(seed).verifying_key().as_bytes());
    bytes.extend_from_slice(&expiry.to_be_bytes());
    ApproveRecovery {
        target: 2,
        policy_version: owner.recovery_version,
        recovery_id: id.into(),
        new_public_key: pk(seed),
        expires_elapsed_micros: expiry,
        proof: hex::encode(key(seed).sign(&bytes).to_bytes()),
    }
}
fn finalize(state: &State, seed: u8, id: &str) -> Vec<u8> {
    action(
        state,
        2,
        seed,
        ActionPayload::FinalizeRecovery(FinalizeRecovery {
            recovery_id: id.into(),
        }),
    )
}

#[test]
fn recovery_empty_fields_preserve_existing_canonical_snapshots() {
    let state = earned();
    let bytes = serde_json::to_vec(&state).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json.get("recovery_cases").is_none());
    for account in json["accounts"].as_array().unwrap() {
        assert!(account.get("recovery_version").is_none());
        assert!(account.get("recovery_policy").is_none());
    }
    let restored: State = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
    assert_eq!(restored.hash().unwrap(), state.hash().unwrap());
}

#[test]
fn recovery_guardians_explicitly_consent_and_single_guardian_cannot_freeze() {
    let state = earned();
    let policy = execute(
        &state,
        2,
        3,
        ActionPayload::SetRecovery(SetRecovery {
            guardians: vec![0, 1, 3],
            threshold: 2,
            delay_seconds: 30,
        }),
    );
    let claim = recovery_claim(&policy, 9, &"aa".repeat(32));
    assert_rejects_unchanged(
        &policy,
        &action(&policy, 0, 1, ActionPayload::ApproveRecovery(claim.clone())),
    );
    let consented = execute(
        &policy,
        0,
        1,
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: true,
        }),
    );
    let voted = execute(&consented, 0, 1, ActionPayload::ApproveRecovery(claim));
    assert!(!recovery_frozen(&voted, 2).unwrap());
    assert_eq!(voted.recovery_cases[0].ready_elapsed_micros, None);
    execute(
        &voted,
        2,
        3,
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
    )
    .validate()
    .unwrap();
}

#[test]
fn recovery_threshold_delay_starts_at_final_required_vote_and_rotates_all_keys() {
    let state = recoverable();
    let id = "aa".repeat(32);
    let claim = recovery_claim(&state, 9, &id);
    let one = execute(&state, 0, 1, ActionPayload::ApproveRecovery(claim.clone()));
    let later = transition(&one, one.height + 1, one.time_micros + 5_000_000, &[]).unwrap();
    let two = execute(&later, 1, 2, ActionPayload::ApproveRecovery(claim.clone()));
    assert!(recovery_frozen(&two, 2).unwrap());
    assert_eq!(
        two.recovery_cases[0].ready_elapsed_micros,
        Some(two.elapsed_micros().unwrap() + 30_000_000)
    );
    assert_rejects_unchanged(&two, &finalize(&two, 9, &id));
    for payload in [
        ActionPayload::Transfer(Transfer { to: 3, amount: 1 }),
        ActionPayload::Bid(Bid {
            epoch: two.auction_epoch,
            weight: 1,
        }),
        ActionPayload::SetRecovery(SetRecovery {
            guardians: vec![],
            threshold: 0,
            delay_seconds: 0,
        }),
    ] {
        assert_rejects_unchanged(&two, &action(&two, 2, 3, payload));
    }
    let ready = transition(&two, two.height + 1, two.time_micros + 30_000_000, &[]).unwrap();
    assert_rejects_unchanged(&ready, &finalize(&ready, 8, &id));
    let recovered = transition(
        &ready,
        ready.height + 1,
        ready.time_micros + 1,
        &[finalize(&ready, 9, &id)],
    )
    .unwrap();
    let owner = recovered.account(2).unwrap();
    assert_eq!(owner.devices.len(), 1);
    assert_eq!(owner.devices[0].public_key, pk(9));
    assert_eq!(owner.auth_epoch, two.account(2).unwrap().auth_epoch + 1);
    assert!(recovered.recovery_cases.is_empty());
    assert_rejects_unchanged(
        &recovered,
        &action(
            &recovered,
            2,
            3,
            ActionPayload::Bid(Bid {
                epoch: recovered.auction_epoch,
                weight: 1,
            }),
        ),
    );
    execute(
        &recovered,
        2,
        9,
        ActionPayload::Bid(Bid {
            epoch: recovered.auction_epoch,
            weight: 1,
        }),
    )
    .validate()
    .unwrap();
    assert_rejects_unchanged(
        &recovered,
        &action(&recovered, 3, 4, ActionPayload::ApproveRecovery(claim)),
    );
}

#[test]
fn recovery_minority_case_cannot_preempt_legitimate_majority_case() {
    let state = recoverable();
    let bad = recovery_claim(&state, 9, &"aa".repeat(32));
    let good = recovery_claim(&state, 10, &"bb".repeat(32));
    let minority = execute(&state, 0, 1, ActionPayload::ApproveRecovery(bad));
    let first = execute(
        &minority,
        1,
        2,
        ActionPayload::ApproveRecovery(good.clone()),
    );
    assert_eq!(first.recovery_cases.len(), 2);
    assert!(!recovery_frozen(&first, 2).unwrap());
    let majority = execute(&first, 3, 4, ActionPayload::ApproveRecovery(good.clone()));
    assert!(recovery_frozen(&majority, 2).unwrap());
    let ready = majority
        .recovery_cases
        .iter()
        .find(|case| case.recovery_id == good.recovery_id)
        .unwrap()
        .ready_elapsed_micros;
    let corrected = execute(&majority, 0, 1, ActionPayload::ApproveRecovery(good));
    assert_eq!(corrected.recovery_cases.len(), 1);
    assert_eq!(corrected.recovery_cases[0].approvals, vec![0, 1, 3]);
    assert_eq!(corrected.recovery_cases[0].ready_elapsed_micros, ready);
    corrected.validate().unwrap();
}

#[test]
fn recovery_optout_removes_vote_unfreezes_and_new_threshold_restarts_full_delay() {
    let state = recoverable();
    let claim = recovery_claim(&state, 9, &"aa".repeat(32));
    let first = execute(&state, 0, 1, ActionPayload::ApproveRecovery(claim.clone()));
    let frozen = execute(&first, 1, 2, ActionPayload::ApproveRecovery(claim.clone()));
    let old_ready = frozen.recovery_cases[0].ready_elapsed_micros.unwrap();
    let waited = transition(
        &frozen,
        frozen.height + 1,
        frozen.time_micros + 5_000_000,
        &[],
    )
    .unwrap();
    let withdrawn = execute(
        &waited,
        0,
        1,
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: false,
        }),
    );
    assert!(!recovery_frozen(&withdrawn, 2).unwrap());
    assert_eq!(withdrawn.recovery_cases[0].ready_elapsed_micros, None);
    let consented = execute(
        &withdrawn,
        0,
        1,
        ActionPayload::ConsentRecovery(ConsentRecovery {
            target: 2,
            policy_version: 1,
            accept: true,
        }),
    );
    let refrozen = execute(&consented, 0, 1, ActionPayload::ApproveRecovery(claim));
    assert!(refrozen.recovery_cases[0].ready_elapsed_micros.unwrap() > old_ready);
    refrozen.validate().unwrap();
}

#[test]
fn recovery_owner_can_cancel_with_zero_liquid_and_old_case_proof_cannot_reopen() {
    let state = recoverable();
    let balance = state.account(2).unwrap().balance;
    let empty = execute(
        &state,
        2,
        3,
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: balance - FEE_MICROS,
        }),
    );
    assert_eq!(empty.account(2).unwrap().balance, 0);
    let claim = recovery_claim(&empty, 9, &"aa".repeat(32));
    let one = execute(&empty, 0, 1, ActionPayload::ApproveRecovery(claim.clone()));
    let frozen = execute(&one, 1, 2, ActionPayload::ApproveRecovery(claim.clone()));
    let canceled = execute(
        &frozen,
        2,
        3,
        ActionPayload::CancelRecovery(CancelRecovery {}),
    );
    assert!(canceled.recovery_cases.is_empty());
    assert_eq!(canceled.account(2).unwrap().balance, 0);
    assert_eq!(
        canceled.account(2).unwrap().auth_epoch,
        frozen.account(2).unwrap().auth_epoch + 1
    );
    assert_rejects_unchanged(
        &canceled,
        &action(&canceled, 3, 4, ActionPayload::ApproveRecovery(claim)),
    );
    assert_rejects_unchanged(
        &canceled,
        &action(
            &canceled,
            2,
            3,
            ActionPayload::CancelRecovery(CancelRecovery {}),
        ),
    );
}

#[test]
fn recovery_expiry_unfreezes_and_expired_proof_cannot_be_replayed() {
    let state = recoverable();
    let claim = recovery_claim(&state, 9, &"aa".repeat(32));
    let one = execute(&state, 0, 1, ActionPayload::ApproveRecovery(claim.clone()));
    let two = execute(&one, 1, 2, ActionPayload::ApproveRecovery(claim.clone()));
    let expired = transition(
        &two,
        two.height + 1,
        two.genesis.genesis_time_micros + claim.expires_elapsed_micros as i64 + 1,
        &[],
    )
    .unwrap();
    assert!(expired.recovery_cases.is_empty());
    assert!(!recovery_frozen(&expired, 2).unwrap());
    assert_rejects_unchanged(
        &expired,
        &action(&expired, 3, 4, ActionPayload::ApproveRecovery(claim)),
    );
}

#[test]
fn recovery_proof_binds_all_authority_claim_and_deadline_fields() {
    let state = recoverable();
    let valid = recovery_claim(&state, 9, &"aa".repeat(32));
    for case in 0..7 {
        let mut wrong = valid.clone();
        match case {
            0 => wrong.target = 3,
            1 => wrong.policy_version += 1,
            2 => wrong.recovery_id = "bb".repeat(32),
            3 => wrong.new_public_key = pk(10),
            4 => wrong.expires_elapsed_micros -= 1,
            5 => wrong.proof = "00".repeat(64),
            _ => wrong.proof = wrong.proof.to_uppercase(),
        }
        assert_rejects_unchanged(
            &state,
            &action(&state, 0, 1, ActionPayload::ApproveRecovery(wrong)),
        );
    }
    assert_rejects_unchanged(
        &state,
        &action(&state, 2, 3, ActionPayload::ApproveRecovery(valid)),
    );
}

#[test]
fn recovery_policy_requires_majority_other_accounts_and_bounded_lab_delay() {
    let state = earned();
    for request in [
        SetRecovery {
            guardians: vec![0],
            threshold: 1,
            delay_seconds: 30,
        },
        SetRecovery {
            guardians: vec![0, 1, 3],
            threshold: 1,
            delay_seconds: 30,
        },
        SetRecovery {
            guardians: vec![0, 1, 2],
            threshold: 2,
            delay_seconds: 30,
        },
        SetRecovery {
            guardians: vec![0, 0, 1],
            threshold: 2,
            delay_seconds: 30,
        },
        SetRecovery {
            guardians: vec![1, 0, 3],
            threshold: 2,
            delay_seconds: 30,
        },
        SetRecovery {
            guardians: vec![0, 1, 99],
            threshold: 2,
            delay_seconds: 30,
        },
        SetRecovery {
            guardians: vec![0, 1, 3],
            threshold: 2,
            delay_seconds: 29,
        },
        SetRecovery {
            guardians: vec![0, 1, 3],
            threshold: 2,
            delay_seconds: 2_592_001,
        },
        SetRecovery {
            guardians: vec![],
            threshold: 0,
            delay_seconds: 30,
        },
    ] {
        assert_rejects_unchanged(
            &state,
            &action(&state, 2, 3, ActionPayload::SetRecovery(request)),
        );
    }
    let configured = recoverable();
    assert_rejects_unchanged(
        &configured,
        &action(
            &configured,
            0,
            1,
            ActionPayload::ConsentRecovery(ConsentRecovery {
                target: 2,
                policy_version: 0,
                accept: false,
            }),
        ),
    );
    let disabled = execute(
        &configured,
        2,
        3,
        ActionPayload::SetRecovery(SetRecovery {
            guardians: vec![],
            threshold: 0,
            delay_seconds: 0,
        }),
    );
    assert!(disabled.account(2).unwrap().recovery_policy.is_none());
    assert_eq!(disabled.account(2).unwrap().recovery_version, 2);
}

#[test]
fn recovery_device_management_change_invalidates_all_prior_claims() {
    let state = recoverable();
    let claim = recovery_claim(&state, 9, &"aa".repeat(32));
    let voted = execute(&state, 0, 1, ActionPayload::ApproveRecovery(claim.clone()));
    let rotated = execute(
        &voted,
        2,
        3,
        ActionPayload::AddDevice(device_payload(&voted, 2, 10, true, true)),
    );
    assert!(rotated.recovery_cases.is_empty());
    assert_rejects_unchanged(
        &rotated,
        &action(&rotated, 1, 2, ActionPayload::ApproveRecovery(claim)),
    );
    assert_eq!(
        rotated
            .account(2)
            .unwrap()
            .recovery_policy
            .as_ref()
            .unwrap()
            .accepted,
        vec![0, 1, 3]
    );
}

#[test]
fn recovery_corrupt_threshold_votes_policy_epoch_and_keys_fail_validation() {
    let state = recoverable();
    let claim = recovery_claim(&state, 9, &"aa".repeat(32));
    let one = execute(&state, 0, 1, ActionPayload::ApproveRecovery(claim.clone()));
    let frozen = execute(&one, 1, 2, ActionPayload::ApproveRecovery(claim));
    for case in 0..8 {
        let mut bad = frozen.clone();
        match case {
            0 => bad.recovery_cases[0].approvals.push(1),
            1 => bad.recovery_cases[0].ready_elapsed_micros = None,
            2 => bad.recovery_cases[0].auth_epoch += 1,
            3 => bad.recovery_cases[0].new_public_key = "00".repeat(32),
            4 => bad.accounts[2]
                .recovery_policy
                .as_mut()
                .unwrap()
                .accepted
                .clear(),
            5 => bad.recovery_cases[0].policy_version += 1,
            6 => {
                let mut duplicate = bad.recovery_cases[0].clone();
                duplicate.recovery_id = "bb".repeat(32);
                bad.recovery_cases.push(duplicate);
            }
            _ => bad.accounts[2].recovery_policy.as_mut().unwrap().threshold = 1,
        }
        assert!(bad.validate().is_err(), "case {case}");
    }
}

#[test]
fn protocol1_block_aggregate_byte_limit_and_legacy_execution_are_explicit() {
    let state = earned();
    let before = state.hash().unwrap();
    let exact = vec![
        vec![0; MAX_BLOCK_TX_BYTES / 2],
        vec![0; MAX_BLOCK_TX_BYTES / 2],
    ];
    validate_block_transactions(&exact).unwrap();
    let mut over = exact;
    over[1].push(0);
    assert!(validate_block_transactions(&over).is_err());
    assert!(
        transition(&state, state.height + 1, state.time_micros + 1, &over)
            .unwrap_err()
            .0
            .contains("byte budget")
    );
    assert_eq!(before, state.hash().unwrap());
    let mut legacy = state.clone();
    legacy.protocol_version = 0;
    legacy.validate().unwrap();
    assert!(
        transition(&legacy, legacy.height + 1, legacy.time_micros + 1, &[])
            .unwrap_err()
            .0
            .contains("legacy protocol")
    );
}

#[test]
fn cancel_pending_nonce_race_cannot_claim_to_undo_an_already_executed_payment() {
    let state = earned();
    let pending = action(
        &state,
        2,
        3,
        ActionPayload::Transfer(Transfer {
            to: 3,
            amount: 1_000_000,
        }),
    );
    let cancellation = action(&state, 2, 3, ActionPayload::CancelPending(CancelPending {}));
    let canceled = transition(
        &state,
        state.height + 1,
        state.time_micros + 1,
        std::slice::from_ref(&cancellation),
    )
    .unwrap();
    assert_eq!(
        canceled.account(2).unwrap().balance,
        state.account(2).unwrap().balance
    );
    assert_eq!(
        canceled.account(2).unwrap().devices,
        state.account(2).unwrap().devices
    );
    assert_eq!(
        canceled.account(2).unwrap().auth_epoch,
        state.account(2).unwrap().auth_epoch + 1
    );
    assert_rejects_unchanged(&canceled, &pending);
    assert_rejects_unchanged(&canceled, &cancellation);
    let paid = transition(&state, state.height + 1, state.time_micros + 1, &[pending]).unwrap();
    assert_eq!(paid.account(3).unwrap().balance, 1_000_000);
    assert_rejects_unchanged(&paid, &cancellation);
    paid.validate().unwrap();
    canceled.validate().unwrap();
}

#[test]
fn cancel_pending_requires_manager_and_cannot_bypass_threshold_freeze() {
    let state = recoverable();
    let restricted = execute(
        &state,
        2,
        3,
        ActionPayload::AddDevice(device_payload(&state, 2, 10, false, true)),
    );
    assert_rejects_unchanged(
        &restricted,
        &action(
            &restricted,
            2,
            10,
            ActionPayload::CancelPending(CancelPending {}),
        ),
    );
    let claim = recovery_claim(&restricted, 9, &"aa".repeat(32));
    let one = execute(
        &restricted,
        0,
        1,
        ActionPayload::ApproveRecovery(claim.clone()),
    );
    let canceled = execute(&one, 2, 3, ActionPayload::CancelPending(CancelPending {}));
    assert!(canceled.recovery_cases.is_empty());
    let fresh = recovery_claim(&canceled, 9, &"bb".repeat(32));
    let one = execute(
        &canceled,
        0,
        1,
        ActionPayload::ApproveRecovery(fresh.clone()),
    );
    let frozen = execute(&one, 1, 2, ActionPayload::ApproveRecovery(fresh));
    assert_rejects_unchanged(
        &frozen,
        &action(
            &frozen,
            2,
            3,
            ActionPayload::CancelPending(CancelPending {}),
        ),
    );
    execute(
        &frozen,
        2,
        3,
        ActionPayload::CancelRecovery(CancelRecovery {}),
    )
    .validate()
    .unwrap();
}

#[test]
fn nav_deposit_accepts_reward_growth_but_enforces_exact_point_one_percent_rounding_loss() {
    let state = earned();
    let first = execute(
        &state,
        2,
        3,
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: 1,
            min_shares: 1,
        }),
    );
    let grown = transition(
        &first,
        first.height + 1,
        first.time_micros + 10_000_000,
        &[],
    )
    .unwrap();
    let assets = grown.pools[0].assets;
    assert_eq!(grown.pools[0].total_shares, 1);
    let accepted = execute(
        &grown,
        2,
        3,
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: assets + assets / 1000,
            min_shares: 1,
        }),
    );
    accepted.validate().unwrap();
    assert_rejects_unchanged(
        &grown,
        &action(
            &grown,
            2,
            3,
            ActionPayload::Delegate(Delegate {
                operator: 0,
                amount: assets + assets / 400,
                min_shares: 1,
            }),
        ),
    );
    let exact = execute(
        &grown,
        2,
        3,
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: assets * 2,
            min_shares: 1,
        }),
    );
    assert_eq!(exact.pools[0].total_shares, 3);
    exact.validate().unwrap();
}
