//! Explicit synthetic fixture workload, never an ABCI or public funding path.
use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::Instant};
use timecurrency_node::ledger::{
    self, Account, Action, ActionPayload, Device, Economics, Genesis, GenesisAccount, Transfer,
};
use timecurrency_v2::{
    engine::{Engine, account_key, name_key, recovery_key},
    store::{Store, StoreOptions},
};

fn key(id: u64) -> SigningKey {
    let mut h = Sha256::new();
    h.update(b"TCDEVNET-SYNTHETIC-IDENTITY-V2\0");
    h.update(id.to_be_bytes());
    SigningKey::from_bytes(&h.finalize().into())
}
fn row(id: u64) -> Account {
    let public_key = hex::encode(key(id).verifying_key().as_bytes());
    Account {
        id,
        name: format!("fx_{id}"),
        public_key: public_key.clone(),
        balance: 0,
        nonce: 0,
        auth_epoch: 0,
        devices: vec![Device {
            public_key,
            can_manage: true,
            can_spend: true,
        }],
        delegations: vec![],
        unbonding: vec![],
        recovery_version: 0,
        recovery_policy: None,
    }
}
fn fingerprint(height: u64) -> [u8; 32] {
    Sha256::digest(height.to_be_bytes()).into()
}
fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut count = 1_000_000u64;
    let mut batch = 5_000u64;
    let mut db = None;
    let mut output = None;
    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| anyhow!("missing option value"))?;
        match arg.as_str() {
            "--accounts" => count = value.parse()?,
            "--batch" => batch = value.parse()?,
            "--db" => db = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(anyhow!("unknown option")),
        }
    }
    ensure!(
        (2..=1_000_000).contains(&count) && (1..=10_000).contains(&batch),
        "fixture workload bounds"
    );
    let path = db.ok_or_else(|| anyhow!("--db NEW_PATH required"))?;
    ensure!(
        !path.exists(),
        "fixture database must be a NEW path; existing data is preserved"
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let started = Instant::now();
    let mut engine = Engine::open(Store::open_with_options(
        &path,
        StoreOptions {
            retained_versions: 32,
            prune_batch: 50_000,
            max_updates: 100_000,
        },
    )?)?;
    let genesis = Genesis {
        chain_id: "time-devnet-fixture-v2-scale".into(),
        genesis_time_micros: 1_000_000,
        economics: Economics::default(),
        accounts: (0..2)
            .map(|id| {
                let a = row(id);
                GenesisAccount {
                    id,
                    name: a.name,
                    public_key: a.public_key,
                }
            })
            .collect(),
    };
    engine.initialize(genesis)?;
    let prepared = engine.prepare(1, 2_001_000_000, &[], &[])?;
    engine.commit(prepared, fingerprint(1))?;
    engine.fixture_fund_from_bank(0, 1_000_000_000)?;
    let mut checkpoints = vec![1_000u64, 10_000, 100_000, count];
    checkpoints.retain(|n| *n <= count);
    checkpoints.sort();
    checkpoints.dedup();
    let mut result = Vec::new();
    let mut current = 2u64;
    for target in checkpoints {
        let phase = Instant::now();
        while current < target {
            let end = (current + batch).min(target);
            let rows = (current..end).map(row).collect();
            engine.insert_zero_balance_fixture(rows)?;
            current = end;
            if current.is_multiple_of(100_000) || current == target {
                eprintln!(
                    "Synthetic accounts committed: {current}; elapsed {:.1}s",
                    started.elapsed().as_secs_f64()
                );
            }
        }
        let creation_ms = phase.elapsed().as_millis();
        let snapshot = engine.store().snapshot()?;
        let head = snapshot
            .head()?
            .ok_or_else(|| anyhow!("missing fixture head"))?;
        let proof_start = Instant::now();
        let bundle = snapshot.proof_bundle(
            &[
                b"meta".to_vec(),
                account_key(0),
                name_key("fx_0"),
                recovery_key(0),
            ],
            head.version,
        )?;
        let proof_bytes = serde_json::to_vec(&bundle)?.len();
        for entry in &bundle.entries {
            entry.verify(head.root, &hex::decode(&entry.key_hex)?)?;
        }
        let missing = snapshot.proof(b"name/absent_user", head.version)?;
        ensure!(
            missing.verify(head.root, b"name/absent_user")?.is_none(),
            "absence verification failed"
        );
        let proof_ms = proof_start.elapsed().as_secs_f64() * 1000.0;
        drop(snapshot);
        let mut samples = Vec::new();
        for _ in 0..3 {
            let meta = engine.meta().unwrap().clone();
            let source: Account =
                serde_json::from_slice(&engine.store().get(&account_key(0))?.unwrap())?;
            let raw: Vec<_> = (1..=100)
                .map(|offset| {
                    ledger::sign_action(
                        &Action {
                            network_id: meta.network_id.clone(),
                            from: 0,
                            nonce: source.nonce + offset,
                            auth_epoch: source.auth_epoch,
                            public_key: source.public_key.clone(),
                            payload: ActionPayload::Transfer(Transfer { to: 1, amount: 1 }),
                            signature: vec![],
                        },
                        &key(0),
                    )
                    .unwrap()
                })
                .collect();
            let run = Instant::now();
            let prepared =
                engine.prepare(meta.height + 1, meta.time_micros + 1_000_000, &raw, &[])?;
            let prepare_ms = run.elapsed().as_secs_f64() * 1000.0;
            let diagnostics = json!({"touched_accounts":prepared.touched_accounts,"updated_rows":prepared.updated_rows,"new_tree_nodes":prepared.new_nodes});
            let commit = Instant::now();
            engine.commit(prepared, fingerprint(meta.height as u64 + 1))?;
            let commit_ms = commit.elapsed().as_secs_f64() * 1000.0;
            samples.push(json!({"transactions":100,"prepare_ms":prepare_ms,"durable_commit_ms":commit_ms,"component_fixture_tps":100_000.0/(prepare_ms+commit_ms),"incremental_work":diagnostics}));
        }
        result.push(json!({"accounts":target,"fixture_creation_ms":creation_ms,"db_bytes":fs::metadata(&path)?.len(),"compact_metadata_account_absence_bundle_bytes":proof_bytes,"proof_generation_and_verification_ms":proof_ms,"samples":samples,"store":engine.store().stats()?}));
    }
    for _ in 0..40 {
        let meta = engine.meta().unwrap();
        let p = engine.prepare(meta.height + 1, meta.time_micros + 1, &[], &[])?;
        engine.commit(p, fingerprint(engine.meta().unwrap().height as u64 + 1))?;
    }
    for _ in 0..1000 {
        let s = engine.store().prune()?;
        if s.nodes + s.values + s.roots == 0 {
            break;
        }
    }
    let final_meta = engine.meta().unwrap().clone();
    let root = engine.head()?.unwrap().root;
    let stats = engine.store().stats()?;
    drop(engine);
    let reopen = Instant::now();
    let engine = Engine::open(Store::open_with_options(
        &path,
        StoreOptions {
            retained_versions: 32,
            prune_batch: 50_000,
            max_updates: 100_000,
        },
    )?)?;
    ensure!(engine.head()?.unwrap().root == root, "reopen changed root");
    let reopen_ms = reopen.elapsed().as_secs_f64() * 1000.0;
    let audit_start = Instant::now();
    let audit = engine.audit()?;
    let audit_ms = audit_start.elapsed().as_millis();
    ensure!(
        audit.account_count == count,
        "post-pruning/reopen stream audit account count mismatch"
    );
    let report = json!({"schema_version":1,"public_launch_allowed":false,"scope":"OFFLINE SYNTHETIC COMPONENT FIXTURE, not a million-user network or WAN test","accounts":count,"fixture_generation":"deterministic test identities, zero balances; existing bank issuance moved to one fixture sender by feature-gated offline tool","network_quorum_measured":false,"proof_root_authentication":"local committed fixture head; network-quorum proof verification tested separately","one_sender_sequential_nonces_preconstructed_per_batch":true,"v1_mempool_pipeline_claim":false,"checkpoints":result,"independent_streaming_recount":{"accounts":audit.account_count,"liquid_micros":audit.liquid.to_string(),"unbond_micros":audit.unbond.to_string(),"duration_ms":audit_ms,"bank_micros":final_meta.bank.to_string(),"exact_elapsed_supply_micros":final_meta.elapsed_micros()?.to_string()},"clean_reopen_ms":reopen_ms,"audit_phase":"full streamed recount AFTER pruning and clean reopen","audit_height":final_meta.height.to_string(),"final_root":hex::encode(root),"final_store":stats,"total_elapsed_ms":started.elapsed().as_millis(),"db_bytes":fs::metadata(&path)?.len()});
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, &encoded)?;
    }
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}
