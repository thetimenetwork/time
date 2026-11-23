//! Offline diagnostic; it never listens, signs, imports accounts or issues value.
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;
use std::{env, fs, io::Write, path::PathBuf, time::Instant};
use timecurrency_v2::{engine::Engine, store::Store};

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let mut db = None;
    let mut output = None;
    let mut devnet = false;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--devnet" if !devnet => devnet = true,
            "--db" if db.is_none() => {
                db = Some(PathBuf::from(
                    arguments.next().context("--db needs a path")?,
                ));
            }
            "--output" if output.is_none() => {
                output = Some(PathBuf::from(
                    arguments.next().context("--output needs a path")?,
                ));
            }
            "--help" => {
                println!(
                    "audit --devnet --db EXISTING_V2_DATABASE [--output NEW_REPORT_PATH]\nStop the database writer first. Performs a root-bound full streamed supply/index audit; never signs or mints."
                );
                return Ok(());
            }
            _ => bail!("unsupported or duplicate argument: {argument}"),
        }
    }
    ensure!(devnet, "--devnet is required; public launch is disabled");
    let db = db.context("--db is required")?;
    ensure!(
        fs::metadata(&db)?.is_file(),
        "existing database file required"
    );
    if let Some(output) = &output {
        ensure!(!output.try_exists()?, "existing output is preserved");
    }
    let started = Instant::now();
    let engine = Engine::open(Store::open(db)?)?;
    let meta = engine
        .meta()
        .context("database has no initialized ledger")?;
    ensure!(
        meta.genesis.chain_id.starts_with("time-devnet-"),
        "development database required"
    );
    let head = engine.head()?.context("database has no head")?;
    eprintln!(
        "Auditing pinned height {} with {} accounts.",
        meta.height, meta.account_count
    );
    let mut last_phase = "";
    let mut last_message = Instant::now();
    let audit = engine.audit_with_progress(|event| {
        let finished = event.total == Some(event.processed);
        if event.phase != last_phase || finished || last_message.elapsed().as_secs() >= 5 {
            eprintln!(
                "Audit {}: {}{}; elapsed {:.1}s",
                event.phase,
                event.processed,
                event.total.map_or(String::new(), |n| format!("/{n}")),
                started.elapsed().as_secs_f64()
            );
            last_phase = event.phase;
            last_message = Instant::now();
        }
    })?;
    let pool_assets: u64 = meta
        .pools
        .iter()
        .try_fold(0u64, |total, pool| total.checked_add(pool.assets))
        .context("pool total overflow")?;
    let total = meta
        .bank
        .checked_add(audit.liquid)
        .and_then(|v| v.checked_add(audit.unbond))
        .and_then(|v| v.checked_add(pool_assets))
        .context("recount overflow")?;
    ensure!(total == meta.elapsed_micros()?, "elapsed supply mismatch");
    let report = json!({
        "status": "PASS_OFFLINE_STREAMED_AUDIT", "publicLaunchAllowed": false,
        "networkId": meta.network_id, "height": meta.height.to_string(),
        "root": hex::encode(head.root), "accounts": audit.account_count.to_string(),
        "bankMicros": meta.bank.to_string(), "liquidMicros": audit.liquid.to_string(),
        "escrowMicros": audit.unbond.to_string(), "poolAssetsMicros": pool_assets.to_string(),
        "totalMicros": total.to_string(), "elapsedMicros": meta.elapsed_micros()?.to_string(),
        "durationMs": started.elapsed().as_millis(),
        "authenticatedLeaves":audit.authenticated_leaves.to_string(),"authenticatedTreeNodes":audit.authenticated_tree_nodes.to_string(),
        "scope": "Full JMT node/leaf-value authentication; active-leaf/raw-directory bijection; root-bound streamed monetary and bidirectional index recount. One immutable MVCC snapshot; bounded traversal memory."
    });
    let encoded = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = output {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}
