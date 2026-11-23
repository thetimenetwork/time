//! Explicit offline regression workload over a COPY of the million-account fixture.
#[cfg(not(feature = "fixtures"))]
fn main() {
    eprintln!("This isolated regression example requires --features fixtures");
    std::process::exit(1);
}

#[cfg(feature = "fixtures")]
mod fixture {
    use anyhow::{Result, anyhow, ensure};
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, fs, path::PathBuf, time::Instant};
    use timecurrency_node::ledger::{self, Account, Action, ActionPayload, Transfer};
    use timecurrency_v2::{
        engine::{Engine, account_key},
        store::{GcBudget, GcPolicy, Store, StoreOptions},
    };

    fn key(id: u64) -> SigningKey {
        let mut h = Sha256::new();
        h.update(b"TCDEVNET-SYNTHETIC-IDENTITY-V2\0");
        h.update(id.to_be_bytes());
        SigningKey::from_bytes(&h.finalize().into())
    }
    fn row(engine: &Engine, id: u64) -> Result<Account> {
        Ok(serde_json::from_slice(
            &engine
                .store()
                .get(&account_key(id))?
                .ok_or_else(|| anyhow!("missing fixture account"))?,
        )?)
    }
    fn apply(
        engine: &mut Engine,
        nonces: &mut BTreeMap<u64, u64>,
        transfers: &[(u64, u64, u64)],
    ) -> Result<Value> {
        let phase = Instant::now();
        let meta = engine
            .meta()
            .ok_or_else(|| anyhow!("missing fixture metadata"))?
            .clone();
        let sign = Instant::now();
        let mut raw = Vec::with_capacity(transfers.len());
        for &(from, to, amount) in transfers {
            let nonce = nonces
                .get_mut(&from)
                .ok_or_else(|| anyhow!("nonce not loaded"))?;
            *nonce = nonce
                .checked_add(1)
                .ok_or_else(|| anyhow!("nonce overflow"))?;
            let signing = key(from);
            let public_key = hex::encode(signing.verifying_key().as_bytes());
            raw.push(ledger::sign_action(
                &Action {
                    network_id: meta.network_id.clone(),
                    from,
                    nonce: *nonce,
                    auth_epoch: 0,
                    public_key,
                    payload: ActionPayload::Transfer(Transfer { to, amount }),
                    signature: vec![],
                },
                &signing,
            )?);
        }
        let signing_ms = sign.elapsed().as_secs_f64() * 1000.0;
        let prepare = Instant::now();
        let prepared = engine.prepare(meta.height + 1, meta.time_micros + 1, &raw, &[])?;
        let prepare_ms = prepare.elapsed().as_secs_f64() * 1000.0;
        let work = json!({"touched_accounts":prepared.touched_accounts,"updated_rows":prepared.updated_rows,"new_tree_nodes":prepared.new_nodes,"verified_read_cache":prepared.verified_read_cache_stats()});
        let fingerprint = Sha256::digest((meta.height + 1).to_be_bytes()).into();
        let commit = Instant::now();
        engine.commit(prepared, fingerprint)?;
        let commit_ms = commit.elapsed().as_secs_f64() * 1000.0;
        Ok(
            json!({"transactions":transfers.len(),"signing_and_encoding_ms":signing_ms,"prepare_ms":prepare_ms,"durable_commit_ms":commit_ms,"wall_ms":phase.elapsed().as_secs_f64()*1000.0,"component_tps":if transfers.is_empty(){None}else{Some(transfers.len() as f64*1000.0/(prepare_ms+commit_ms))},"incremental_work":work}),
        )
    }
    fn hot(engine: &mut Engine, nonces: &mut BTreeMap<u64, u64>, phase: &str) -> Result<Value> {
        eprintln!("RETEST phase {phase}");
        let started = Instant::now();
        let mut samples = Vec::new();
        for _ in 0..20 {
            samples.push(apply(engine, nonces, &vec![(0, 1, 1); 100])?);
        }
        Ok(
            json!({"phase":phase,"transactions":2000,"wall_ms":started.elapsed().as_secs_f64()*1000.0,"samples":samples,"gc":engine.store().gc_status(GcPolicy::default())?}),
        )
    }
    fn drain(engine: &Engine, phase: &str) -> Result<Value> {
        eprintln!("RETEST phase {phase}");
        let started = Instant::now();
        let before = engine.store().gc_status(GcPolicy::default())?;
        let mut slices = Vec::new();
        let mut removed = [0u64; 3];
        let mut progress_at = Instant::now();
        while engine
            .store()
            .gc_status(GcPolicy::default())?
            .eligible_work_pending
        {
            ensure!(
                started.elapsed().as_secs() < 7200,
                "GC made insufficient progress in two hours"
            );
            let s = engine.store().maintain_gc(GcBudget::default())?;
            ensure!(
                s.nodes + s.values + s.roots > 0,
                "GC eligible backlog made no progress"
            );
            ensure!(
                s.nodes <= 128 && s.values <= 128 && s.roots <= 16,
                "GC exceeded default row bounds"
            );
            removed[0] += s.nodes as u64;
            removed[1] += s.values as u64;
            removed[2] += s.roots as u64;
            slices.push(s.elapsed_ms);
            if progress_at.elapsed().as_secs() >= 10 {
                eprintln!(
                    "RETEST GC {phase} slices={} removed_nodes={} removed_values={} elapsed_s={:.1}",
                    slices.len(),
                    removed[0],
                    removed[1],
                    started.elapsed().as_secs_f64()
                );
                progress_at = Instant::now();
            }
        }
        Ok(
            json!({"phase":phase,"wall_ms":started.elapsed().as_secs_f64()*1000.0,"budget":{"max_nodes":128,"max_values":128,"max_roots":16,"cooperative_max_ms":10},"slices":slices.len(),"slice_elapsed_ms":slices,"removed_nodes":removed[0],"removed_values":removed[1],"removed_root_records":removed[2],"before":before,"after":engine.store().gc_status(GcPolicy::default())?}),
        )
    }
    pub fn run() -> Result<()> {
        let mut args = std::env::args().skip(1);
        let mut db = None;
        let mut output = None;
        let mut expected = None;
        let mut blocks = 64usize;
        let mut per_block = 512usize;
        let mut peers = 1024usize;
        while let Some(arg) = args.next() {
            let value = args.next().ok_or_else(|| anyhow!("missing option value"))?;
            match arg.as_str() {
                "--db" => db = Some(PathBuf::from(value)),
                "--output" => output = Some(PathBuf::from(value)),
                "--expected-root" => expected = Some(value),
                "--blocks" => blocks = value.parse()?,
                "--per-block" => per_block = value.parse()?,
                "--peers" => peers = value.parse()?,
                _ => return Err(anyhow!("unknown option")),
            }
        }
        ensure!(
            (64..=128).contains(&blocks) && (256..=512).contains(&per_block) && peers == 1024,
            "regression workload requires 1024 peers,64..128blocks,256..512tx/block"
        );
        let db = db.ok_or_else(|| anyhow!("--db COPY required"))?;
        let output = output.ok_or_else(|| anyhow!("--output required"))?;
        let expected = expected.ok_or_else(|| anyhow!("--expected-root required"))?;
        ensure!(!output.exists(), "existing report must be preserved");
        let started = Instant::now();
        let options = StoreOptions {
            retained_versions: 32,
            prune_batch: 128,
            max_updates: 100_000,
        };
        let mut engine = Engine::open(Store::open_with_options(&db, options)?)?;
        let initial = engine
            .head()?
            .ok_or_else(|| anyhow!("missing initial head"))?;
        ensure!(
            hex::encode(initial.root) == expected,
            "copied fixture root differs from pinned baseline"
        );
        let meta = engine
            .meta()
            .ok_or_else(|| anyhow!("uninitialized fixture"))?
            .clone();
        ensure!(
            meta.account_count == 1_000_000
                && meta.genesis.chain_id == "time-devnet-fixture-v2-scale",
            "requires exact isolated million-account fixture"
        );
        ensure!(
            meta.genesis.economics.operators.is_empty(),
            "fixture must remain bank-only"
        );
        let mut nonces = BTreeMap::new();
        for id in [0, 1] {
            let account = row(&engine, id)?;
            ensure!(
                account.auth_epoch == 0
                    && account.public_key == hex::encode(key(id).verifying_key().as_bytes()),
                "deterministic fixture authority mismatch"
            );
            nonces.insert(id, account.nonce);
        }
        let peer_ids: Vec<u64> = (0..peers)
            .map(|i| 2 + (i as u64 * (meta.account_count - 2) / peers as u64))
            .collect();
        let clean = hot(&mut engine, &mut nonces, "clean-hotpair")?;
        let clean_gc = drain(&engine, "clean-maintenance")?;
        eprintln!("RETEST phase peer-prefunding");
        let fund_start = Instant::now();
        for &id in &peer_ids {
            let account = row(&engine, id)?;
            ensure!(
                account.auth_epoch == 0
                    && account.nonce == 0
                    && account.balance == 0
                    && account.public_key == hex::encode(key(id).verifying_key().as_bytes()),
                "peer is not pristine fixture identity"
            );
            nonces.insert(id, account.nonce);
        }
        let funding: Vec<_> = peer_ids.iter().map(|id| (0, *id, 200_000)).collect();
        let funding_sample = apply(&mut engine, &mut nonces, &funding)?;
        let funding_wall = fund_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("RETEST phase distributed-peer-churn");
        let churn_start = Instant::now();
        let mut churn = Vec::new();
        for block in 0..blocks {
            let transfers: Vec<_> = (0..per_block)
                .map(|i| {
                    let index = ((block * per_block + i) * 405 + 13) % peers;
                    (peer_ids[index], peer_ids[(index + 509) % peers], 1)
                })
                .collect();
            churn.push(apply(&mut engine, &mut nonces, &transfers)?);
            if (block + 1).is_multiple_of(8) {
                eprintln!(
                    "RETEST churn blocks={} transactions={} elapsed_s={:.1}",
                    block + 1,
                    (block + 1) * per_block,
                    churn_start.elapsed().as_secs_f64()
                );
            }
        }
        let churn_wall = churn_start.elapsed().as_secs_f64() * 1000.0;
        let backlog = engine.store().gc_status(GcPolicy::default())?;
        let before_gc = hot(
            &mut engine,
            &mut nonces,
            "hotpair-with-retired-bulk-backlog",
        )?;
        eprintln!("RETEST phase retire-all-churn-versions");
        let retire_start = Instant::now();
        for _ in 0..40 {
            apply(&mut engine, &mut nonces, &[])?;
        }
        let retire_ms = retire_start.elapsed().as_secs_f64() * 1000.0;
        let catchup = drain(&engine, "bounded-bulk-catchup")?;
        let after_gc = hot(&mut engine, &mut nonces, "hotpair-after-bulk-catchup")?;
        let final_gc = drain(&engine, "final-maintenance")?;
        let final_meta = engine.meta().unwrap().clone();
        let head = engine.head()?.unwrap();
        let stats = engine.store().stats()?;
        drop(engine);
        let reopen_start = Instant::now();
        let engine = Engine::open(Store::open_with_options(&db, options)?)?;
        ensure!(
            engine.head()?.unwrap() == head,
            "clean reopen changed committed head"
        );
        let reopen_ms = reopen_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("RETEST phase authenticated-full-audit-after-reopen");
        let audit_start = Instant::now();
        let audit = engine.audit_with_progress(|p| {
            eprintln!(
                "AUDIT {} {} {}",
                p.phase,
                p.processed,
                p.total.map_or_else(|| "?".into(), |n| n.to_string())
            )
        })?;
        let audit_ms = audit_start.elapsed().as_secs_f64() * 1000.0;
        ensure!(
            audit.account_count == 1_000_000
                && audit.liquid == final_meta.liquid_total
                && audit.unbond == final_meta.unbond_total,
            "full recount differs from aggregate"
        );
        let supply = final_meta
            .bank
            .checked_add(audit.liquid)
            .and_then(|n| n.checked_add(audit.unbond))
            .ok_or_else(|| anyhow!("supply overflow"))?;
        ensure!(
            supply == final_meta.elapsed_micros()?,
            "supply conservation failed"
        );
        let report = json!({"schema_version":1,"public_launch_allowed":false,"scope":"OFFLINE COPIED MILLION-ACCOUNT REGRESSION; no WAN/quorum/saturation or million-concurrent-user capacity claim","accounts":audit.account_count,"dataset_protocol_version":final_meta.protocol_version,"baseline_root":expected,"initial_height":initial.version,"final_height":head.version,"final_root":hex::encode(head.root),"original_dataset_modified":false,"gc_during_consensus_commit":false,"maintenance_explicit_between_phases":true,"one_second_chain_time_not_measured":true,"clean_hotpair":clean,"clean_maintenance":clean_gc,"peer_prefunding":{"peers":peers,"amount_micros_per_peer":"200000","wall_ms":funding_wall,"sample":funding_sample},"distributed_churn":{"blocks":blocks,"per_block":per_block,"transactions":blocks*per_block,"peer_id_selection":"1024 evenly spaced IDs across 1m registry; permutation multiplier405; recipientoffset509","wall_ms":churn_wall,"samples":churn,"gc_after_churn":backlog},"hotpair_before_gc":before_gc,"empty_blocks_retiring_all_bulk_versions":{"blocks":40,"wall_ms":retire_ms},"bounded_bulk_catchup":catchup,"hotpair_after_gc":after_gc,"final_maintenance":final_gc,"clean_reopen_ms":reopen_ms,"authenticated_full_audit":{"phase":"AFTER bounded maintenance, clean reopen, and authentication of entire JMT and complete raw-row directory","duration_ms":audit_ms,"accounts":audit.account_count,"authenticated_leaves":audit.authenticated_leaves,"authenticated_tree_nodes":audit.authenticated_tree_nodes,"bank_micros":final_meta.bank.to_string(),"liquid_micros":audit.liquid.to_string(),"unbond_micros":audit.unbond.to_string(),"sum_micros":supply.to_string(),"elapsed_micros":final_meta.elapsed_micros()?.to_string()},"final_store":stats,"final_gc":engine.store().gc_status(GcPolicy::default())?,"db_bytes":fs::metadata(&db)?.len(),"total_wall_ms":started.elapsed().as_secs_f64()*1000.0,"limitations":["Pre-signed transactions use deterministic fixture authorities; signing cost is also recorded separately.","Hotpair samples intentionally use two accounts; distributed churn separately exercises1024 sender/recipient identities.","Local commit timings exclude network agreement and separately scheduled maintenance; phase wall times include workload construction.","Copied fixture may benefit from warm OS caches on a shared workstation."]});
        fs::write(output, serde_json::to_vec_pretty(&report)?)?;
        println!(
            "RETEST complete accounts={} root={}",
            audit.account_count,
            hex::encode(head.root)
        );
        Ok(())
    }
}

#[cfg(feature = "fixtures")]
fn main() -> anyhow::Result<()> {
    fixture::run()
}
