//! Component benchmark only. This constructs funded fixtures; it does not mint
//! funds on a live network and does not measure consensus or wallet throughput.
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};
use timecurrency_node::{
    app::state_capacity_charge,
    ledger::{self, Action, ActionPayload, Device, Economics, Genesis, GenesisAccount, Transfer},
};

fn main() {
    let mut results = Vec::new();
    let source = SigningKey::from_bytes(&[1; 32]);
    let receiver = SigningKey::from_bytes(&[2; 32]);
    let genesis = Genesis {
        chain_id: "time-devnet-component-profile".into(),
        genesis_time_micros: 1_000_000,
        economics: Economics::default(),
        accounts: vec![
            GenesisAccount {
                id: 0,
                name: "sender".into(),
                public_key: hex::encode(source.verifying_key().as_bytes()),
            },
            GenesisAccount {
                id: 1,
                name: "receiver".into(),
                public_key: hex::encode(receiver.verifying_key().as_bytes()),
            },
        ],
    };
    let initial = ledger::new(genesis).unwrap();
    for count in [2usize, 100, 1_000, 5_000, 10_000] {
        let mut state = initial.clone();
        state.height = 1;
        state.time_micros += 1_000_000_000_000;
        state.auction_epoch = 100_000;
        state.bank = 999_000_000_000;
        state.accounts[0].balance = 1_000_000_000;
        for id in 2..count {
            let seed: [u8; 32] = Sha256::digest((id as u64).to_be_bytes()).into();
            let key = SigningKey::from_bytes(&seed);
            let mut account = state.accounts[1].clone();
            account.id = id as u64;
            account.name = format!("user_{id}");
            account.public_key = hex::encode(key.verifying_key().as_bytes());
            account.devices = vec![Device {
                public_key: account.public_key.clone(),
                can_manage: true,
                can_spend: true,
            }];
            state.accounts.push(account);
        }
        let started = Instant::now();
        state.validate().unwrap();
        let validation_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let started = Instant::now();
        let raw = serde_json::to_vec(&state).unwrap();
        let serialization_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let started = Instant::now();
        black_box(state.hash().unwrap());
        let hash_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let started = Instant::now();
        let charged = state_capacity_charge(&state).unwrap();
        let capacity_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let mut batches = Vec::new();
        for batch in [100usize, 1_000] {
            let txs: Vec<_> = (1..=batch)
                .map(|nonce| {
                    ledger::sign_action(
                        &Action {
                            network_id: state.network_id.clone(),
                            from: 0,
                            nonce: nonce as u64,
                            auth_epoch: 0,
                            public_key: state.accounts[0].public_key.clone(),
                            payload: ActionPayload::Transfer(Transfer { to: 1, amount: 1 }),
                            signature: vec![],
                        },
                        &source,
                    )
                    .unwrap()
                })
                .collect();
            let mut timings = Vec::new();
            for _ in 0..3 {
                let started = Instant::now();
                let next =
                    ledger::transition(&state, 2, state.time_micros + 1_000_000, &txs).unwrap();
                black_box(next);
                timings.push(started.elapsed().as_secs_f64() * 1_000.0);
            }
            timings.sort_by(f64::total_cmp);
            batches.push(json!({"transactions":batch,"raw_tx_bytes":txs[0].len(),"samples_ms":timings,"median_ms":timings[1],"component_tps":batch as f64*1000.0/timings[1]}));
        }
        results.push(json!({"accounts":count,"snapshot_bytes":raw.len(),"capacity_charged_bytes":charged,"within_lab_capacity":charged<=4*1024*1024,"validate_ms":validation_ms,"serialize_ms":serialization_ms,"state_hash_ms":hash_ms,"capacity_measure_ms":capacity_ms,"full_snapshot_GB_per_day_at_one_block_per_second":raw.len() as f64*86400.0/1e9,"batches":batches}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"schema_version":1,"scope":"RELEASE component fixture benchmark; excludes ABCI checks/proposals, disk durability, RPC, mempool, signing, consensus, WAN and client verification","public_launch_allowed":false,"single_account_nonces_preconstructed_in_one_block":true,"same_account_mempool_pipelining_supported":false,"rows":results})).unwrap());
}
