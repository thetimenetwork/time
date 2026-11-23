//! Deterministic mutation campaign against real parsers and state application.
//! This is a bounded fuzz smoke test, not exhaustive input-space verification.
use ed25519_dalek::SigningKey;
use timecurrency_node::ledger::{
    self, Action, ActionPayload, Economics, Genesis, GenesisAccount, Transfer,
};

#[test]
fn arbitrary_and_mutated_wire_inputs_never_panic_or_partially_spend() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let other = SigningKey::from_bytes(&[2; 32]);
    let mut state = ledger::new(Genesis {
        chain_id: "time-devnet-mutation".into(),
        genesis_time_micros: 1_000_000,
        economics: Economics::default(),
        accounts: vec![
            GenesisAccount {
                id: 0,
                name: "alice".into(),
                public_key: hex::encode(key.verifying_key().as_bytes()),
            },
            GenesisAccount {
                id: 1,
                name: "bob".into(),
                public_key: hex::encode(other.verifying_key().as_bytes()),
            },
        ],
    })
    .unwrap();
    state.height = 1;
    state.time_micros += 1_000_000;
    state.accounts[0].balance = 1_000_000;
    state.validate().unwrap();
    let raw = ledger::sign_action(
        &Action {
            network_id: state.network_id.clone(),
            from: 0,
            nonce: 1,
            auth_epoch: 0,
            public_key: state.accounts[0].public_key.clone(),
            payload: ActionPayload::Transfer(Transfer { to: 1, amount: 1 }),
            signature: vec![],
        },
        &key,
    )
    .unwrap();
    let before = state.hash().unwrap();
    for at in 0..raw.len() {
        let mut changed = raw.clone();
        changed[at] ^= 1;
        assert!(
            ledger::validate_tx(&state, &changed).is_err(),
            "mutation byte {at}"
        );
        assert!(ledger::apply_tx(&mut state, &changed).is_err());
        assert_eq!(state.hash().unwrap(), before, "partial mutation byte {at}");
    }
    let mut seed = 0x6e624eb7a503d9c1u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for case in 0..4096 {
        let length = (next() % 1024) as usize;
        let changed: Vec<u8> = (0..length).map(|_| next() as u8).collect();
        assert!(
            ledger::validate_tx(&state, &changed).is_err(),
            "random input {case}"
        );
        assert!(ledger::apply_tx(&mut state, &changed).is_err());
        assert_eq!(
            state.hash().unwrap(),
            before,
            "random partial mutation {case}"
        );
    }
    ledger::apply_tx(&mut state, &raw).unwrap();
    assert_eq!(state.accounts[1].balance, 1);
    state.validate().unwrap();
}
