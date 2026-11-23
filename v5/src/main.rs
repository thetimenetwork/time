use std::{
    env,
    error::Error,
    path::PathBuf,
    process,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use timecurrency_v5::{
    app::{self, App, StopCause, UpgradeOptions, UpgradeWatch},
    rules::{self, Versions},
    statesync::{self, NodeOptions},
    transport::Endpoint,
    upgrade,
};

const USAGE: &str = "time-node-v5 --devnet --db PATH [--listen 127.0.0.1:26658 | unix:/absolute/path] [--snapshot-seconds 120] [--clock-tolerance-seconds 30] [--stay-after-disconnect] [--state-sync-snapshot-blocks 0] [--state-sync-snapshots-kept 2] [--state-sync-max-mib 16384] [--keep-blocks 0] [--stop-after-height H] [--expect-root H:ROOT]\n       time-node-v5 --devnet --db PATH --audit\n\nVersion-5 execution engine for the protocol-4 ledger. Public monetary launch is disabled.\nCometBFT v0.38.26 runs separately and connects to this local ABCI endpoint. A Unix socket is created for the node's own user only; a loopback port can be reached by every local program.\nState is kept in memory and saved as snapshots in PATH.v5state; after a restart CometBFT replays the blocks after the newest snapshot.\nProcessProposal rejects a proposed block dated more than --clock-tolerance-seconds (1 to 60, default 30) ahead of this machine's clock; the application never refuses a decided block for its date. CometBFT itself refuses blocks dated consensus.block_time_tolerance (default 60 s) or more ahead of its clock, so a value above that has no effect unless it is raised as well. Keep the clock synchronized.\nState sync: with --state-sync-snapshot-blocks N (0 = off, the default; otherwise 10 to 1000000) the node writes a snapshot for peers at every height that is a multiple of N, keeps the newest --state-sync-snapshots-kept (1 to 10, default 2) in PATH.v5state/statesync and offers them through CometBFT's state sync. Every node of a network that offers snapshots should use the same N. A node restores a snapshot whenever its CometBFT state-syncs, whatever these settings, but none larger than --state-sync-max-mib (4 to 400000, default 16384); what it restores must hash to the application hash CometBFT's light client verified. A restored node holds no block history at or below the restored height.\nPruning: --keep-blocks N (0 = keep every block, the default; otherwise at least 2000000) lets CometBFT delete blocks older than the last N, but never a block after this node's oldest snapshot, the block of a snapshot it still offers, or a block evidence can still name (the last 2000000 blocks and 14 days).
Upgrades: the chain's protocol version changes only by a plan its validators scheduled on the chain, with notice. A program executes nothing under a version it does not implement: after the block that activates one it saves its state, prints STOPPED FOR UPGRADE and ends with exit code 4, and it does the same when started on such a state. Install the release that implements the version and start it on the same data; delete nothing. --stop-after-height H (at least 1) stops the node the same way after it has committed block H (STOPPED AS ASKED, exit code 4): it answers nothing for block H+1. Started with its state at H it stops at once; started above H it changes nothing and fails with exit code 1. A decided block that carries a rule switch (action kind 81) is not executed and stops the node as well (STOPPED AT A SWITCH, exit code 4).
Emergencies (docs/emergency-fix.md): nothing shortens the notice of a plan. A fix release carries a rule switch for one network, compiled in: after the height the validators agreed on it proposes, and accepts, exactly one block, which holds the switch and nothing else and ends by writing the new version. A decided block at that height that is anything else is not executed, and a state that is past that height and still under the old version is not started on (STOPPED AT A SWITCH, exit code 4). This program says at its start whether it carries a switch. --expect-root H:ROOT (ROOT is 64 lowercase hexadecimal characters) is for the start on a state the validators agreed on: the node goes on from height H only if its state there has that root. Started at H with another root, or above H, it changes nothing and fails with exit code 1; started below H it fails at the commit of H if the root is another one. A decided block that fails a check of this program stops the node in the middle of that block: it prints FAILED ON A DECIDED BLOCK with the block and the state it is left at, and ends with exit code 1.
Exit codes: 0 stopped on request, 1 failure, 3 the consensus engine disconnected, 4 stopped at a height on purpose.";
/// Bounds of `--state-sync-snapshot-blocks` when it is not 0. Below ten
/// blocks a snapshot could not be written before the next is due; a million
/// blocks is more than eleven days at one block a second.
const SYNC_SNAPSHOT_BLOCKS: std::ops::RangeInclusive<u64> = 10..=1_000_000;
/// Bounds of `--state-sync-snapshots-kept`: CometBFT advertises at most the
/// ten most recent snapshots of a node.
const SYNC_SNAPSHOTS_KEPT: std::ops::RangeInclusive<u64> = 1..=10;
/// Bounds of `--state-sync-max-mib`: one chunk, and the largest snapshot the
/// format can describe (100,000 chunks of 4 MiB).
const SYNC_MAX_MIB: std::ops::RangeInclusive<u64> = 4..=400_000;
/// Upper bound of `--keep-blocks`; its lower bound, when it is not 0, is the
/// evidence window (`statesync::EVIDENCE_MAX_AGE_BLOCKS`).
const KEEP_BLOCKS_MAX: u64 = 1_000_000_000_000;

/// A whole number without sign, spaces or leading zeros (other than "0").
fn whole_number(text: Option<String>, flag: &str) -> Result<u64, String> {
    let text = text.ok_or(format!("{flag} needs a number"))?;
    if text.is_empty()
        || !text.bytes().all(|c| c.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(format!("{flag} must be a whole number"));
    }
    text.parse().map_err(|_| format!("{flag} must be a whole number"))
}
/// Bounds of `--clock-tolerance-seconds`. Below a second the check would
/// judge clock noise. Above 60 seconds it would allow nothing more: CometBFT
/// 0.38 itself refuses a block dated `consensus.block_time_tolerance`
/// (default 60 s) or more ahead of its clock, at prevote, precommit, commit
/// and in block sync.
const CLOCK_TOLERANCE_SECONDS: std::ops::RangeInclusive<u64> = 1..=60;

/// Set by a termination signal or when the consensus engine disconnects.
static STOP: AtomicBool = AtomicBool::new(false);
/// The stop was caused by the consensus engine going away, not by a request
/// to stop: the process then ends with a failure code so that a supervisor
/// restarts it.
static PEER_GONE: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn install_signal_handlers() {
    extern "C" fn on_signal(_: libc::c_int) {
        // Only an atomic store: async-signal-safe.
        STOP.store(true, Ordering::SeqCst);
    }
    // SAFETY: `on_signal` has the signature `signal` expects and does nothing
    // but an atomic store, which is permitted inside a signal handler.
    unsafe {
        let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

#[derive(Debug, PartialEq)]
struct Options {
    db: PathBuf,
    listen: Endpoint,
    audit: bool,
    snapshot_seconds: u64,
    /// How far ahead of this machine's clock a proposed block may be dated
    /// (`app::DEFAULT_CLOCK_TOLERANCE` unless set).
    clock_tolerance_seconds: u64,
    stay_after_disconnect: bool,
    /// Snapshots for peers, restores and block pruning.
    node: NodeOptions,
    /// `--stop-after-height`: stop after the commit of this block.
    stop_after_height: Option<u64>,
    /// `--expect-root H:ROOT`: go on from height `H` only on the state with
    /// this root (`app::ResumeOptions`).
    expect_root: Option<(u64, [u8; 32])>,
}

/// The value of `--expect-root`: a block height, at least 1, without sign,
/// spaces or leading zeros, a colon, and a root as 64 lowercase hexadecimal
/// characters. One form only: operators compare the text they agreed on.
fn height_and_root(text: Option<String>) -> Result<(u64, [u8; 32]), String> {
    let form = "--expect-root needs HEIGHT:ROOT, a block height (at least 1) and the 64 lowercase hexadecimal characters of a state root";
    let text = text.ok_or(form)?;
    let (height, root) = text.split_once(':').ok_or(form)?;
    let height = whole_number(Some(height.to_string()), "--expect-root").map_err(|_| form)?;
    if height == 0
        || height > i64::MAX as u64
        || root.len() != 64
        || !root.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(form.into());
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(root, &mut bytes).map_err(|_| form)?;
    Ok((height, bytes))
}

fn options(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut args = args.into_iter();
    let mut devnet = false;
    let mut db = None;
    let mut listen = None;
    let mut audit = false;
    let mut snapshot_seconds = None;
    let mut clock_tolerance_seconds = None;
    let mut stay_after_disconnect = false;
    let mut sync_snapshot_blocks = None;
    let mut sync_snapshots_kept = None;
    let mut sync_max_mib = None;
    let mut keep_blocks = None;
    let mut stop_after_height = None;
    let mut expect_root = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--audit" if !audit => audit = true,
            "--devnet" if !devnet => devnet = true,
            "--stay-after-disconnect" if !stay_after_disconnect => stay_after_disconnect = true,
            "--db" if db.is_none() => {
                db = Some(PathBuf::from(args.next().ok_or("--db needs a path")?))
            }
            "--listen" if listen.is_none() => {
                listen = Some(args.next().ok_or("--listen needs an address")?)
            }
            "--snapshot-seconds" if snapshot_seconds.is_none() => {
                let value: u64 = args
                    .next()
                    .ok_or("--snapshot-seconds needs a number")?
                    .parse()
                    .map_err(|_| "--snapshot-seconds must be a whole number")?;
                if !(5..=86_400).contains(&value) {
                    return Err("--snapshot-seconds must be between 5 and 86400".into());
                }
                snapshot_seconds = Some(value);
            }
            "--clock-tolerance-seconds" if clock_tolerance_seconds.is_none() => {
                let value: u64 = args
                    .next()
                    .ok_or("--clock-tolerance-seconds needs a number")?
                    .parse()
                    .map_err(|_| "--clock-tolerance-seconds must be a whole number")?;
                if !CLOCK_TOLERANCE_SECONDS.contains(&value) {
                    return Err("--clock-tolerance-seconds must be between 1 and 60 (CometBFT's own block_time_tolerance is 60 s by default)".into());
                }
                clock_tolerance_seconds = Some(value);
            }
            "--state-sync-snapshot-blocks" if sync_snapshot_blocks.is_none() => {
                let value = whole_number(args.next(), "--state-sync-snapshot-blocks")?;
                if value != 0 && !SYNC_SNAPSHOT_BLOCKS.contains(&value) {
                    return Err("--state-sync-snapshot-blocks must be 0 (no snapshots for peers) or between 10 and 1000000".into());
                }
                sync_snapshot_blocks = Some(value);
            }
            "--state-sync-snapshots-kept" if sync_snapshots_kept.is_none() => {
                let value = whole_number(args.next(), "--state-sync-snapshots-kept")?;
                if !SYNC_SNAPSHOTS_KEPT.contains(&value) {
                    return Err("--state-sync-snapshots-kept must be between 1 and 10".into());
                }
                sync_snapshots_kept = Some(value);
            }
            "--state-sync-max-mib" if sync_max_mib.is_none() => {
                let value = whole_number(args.next(), "--state-sync-max-mib")?;
                if !SYNC_MAX_MIB.contains(&value) {
                    return Err("--state-sync-max-mib must be between 4 and 400000".into());
                }
                sync_max_mib = Some(value);
            }
            "--keep-blocks" if keep_blocks.is_none() => {
                let value = whole_number(args.next(), "--keep-blocks")?;
                if value != 0
                    && !(statesync::EVIDENCE_MAX_AGE_BLOCKS..=KEEP_BLOCKS_MAX).contains(&value)
                {
                    return Err("--keep-blocks must be 0 (keep every block) or at least 2000000: CometBFT needs the last 2000000 blocks and 14 days to judge evidence, so a lower number would change nothing".into());
                }
                keep_blocks = Some(value);
            }
            "--stop-after-height" if stop_after_height.is_none() => {
                let value = whole_number(args.next(), "--stop-after-height")?;
                if value == 0 || value > i64::MAX as u64 {
                    return Err("--stop-after-height must be a block height, at least 1".into());
                }
                stop_after_height = Some(value);
            }
            "--expect-root" if expect_root.is_none() => {
                expect_root = Some(height_and_root(args.next())?);
            }
            _ => return Err(format!("unsupported or duplicate argument: {arg}")),
        }
    }
    if !devnet {
        return Err("--devnet is required; live monetary operation is disabled".into());
    }
    let db =
        db.ok_or("--db is required; storage is never silently placed in a temporary directory")?;
    if db.as_os_str().is_empty() {
        return Err("empty database path".into());
    }
    let listen: Endpoint = listen
        .unwrap_or_else(|| "127.0.0.1:26658".into())
        .parse()?;
    let defaults = NodeOptions::default();
    if sync_snapshot_blocks.unwrap_or(0) == 0 && sync_snapshots_kept.is_some() {
        return Err("--state-sync-snapshots-kept needs --state-sync-snapshot-blocks".into());
    }
    if audit
        && (sync_snapshot_blocks.is_some()
            || sync_snapshots_kept.is_some()
            || sync_max_mib.is_some()
            || keep_blocks.is_some())
    {
        return Err("--audit takes no state-sync or pruning setting".into());
    }
    if audit && stop_after_height.is_some() {
        return Err("--audit takes no --stop-after-height".into());
    }
    if audit && expect_root.is_some() {
        return Err("--audit takes no --expect-root: compare the root it prints yourself".into());
    }
    // One start either stops at a height or goes on from one, not both: a
    // node that is to stop after H and go on from H would be told two things.
    if let (Some(stop), Some((from, _))) = (stop_after_height, expect_root)
        && stop <= from
    {
        return Err("--stop-after-height must be above the height of --expect-root: a node that goes on from a height does not stop at or before it".into());
    }
    let node = NodeOptions {
        keep_blocks: keep_blocks.unwrap_or(defaults.keep_blocks),
        sync_snapshot_blocks: sync_snapshot_blocks.unwrap_or(defaults.sync_snapshot_blocks),
        sync_snapshots_kept: sync_snapshots_kept
            .map_or(defaults.sync_snapshots_kept, |kept| kept as usize),
        restore_max_bytes: sync_max_mib
            .map_or(defaults.restore_max_bytes, |mib| mib * 1024 * 1024),
        sync_chunk_bytes: defaults.sync_chunk_bytes,
    };
    node.validate().map_err(|error| error.to_string())?;
    Ok(Options {
        db,
        listen,
        audit,
        snapshot_seconds: snapshot_seconds.unwrap_or(120),
        clock_tolerance_seconds: clock_tolerance_seconds
            .unwrap_or(app::DEFAULT_CLOCK_TOLERANCE.as_secs()),
        stay_after_disconnect,
        node,
        stop_after_height,
        expect_root,
    })
}

fn audit(options: &Options) -> Result<(), Box<dyn Error>> {
    let engine = timecurrency_v5::engine::Engine::open_with_history(
        timecurrency_v5::store::Store::open(options.db.with_extension("v5state"))?,
        options.db.with_extension("history"),
    )?;
    let meta = engine.meta().ok_or("state is uninitialized")?;
    // A recount judges rows by this program's rules. On a head under rules
    // it does not implement it refuses, as the node refuses to start.
    if let Err(reason) = engine.runnable() {
        let cause = StopCause::Upgrade(reason.clone());
        eprintln!("{}", cause.first_line());
        eprintln!("{}", cause.explain(Some(reason.head)));
        process::exit(app::EXIT_STOPPED);
    }
    // Nor on a head that is past this fix release's rule switch and still
    // under the version before it: the program holds no rules for it.
    if let Some(missed) = engine.missed_switch() {
        let cause = StopCause::SwitchMissed(missed.clone());
        eprintln!("{}", cause.first_line());
        eprintln!("{}", cause.explain(Some(missed.head)));
        process::exit(app::EXIT_STOPPED);
    }
    let audit = engine
        .audit_with_progress(|p| eprintln!("audit phase={} processed={}", p.phase, p.processed))?;
    // Fees recorded as owed to validators and not yet paid (part of the bank).
    let fees_owed: String = match engine
        .version()
        .and_then(|version| version.get(timecurrency_v5::pos_adapter::FEE_POOL_KEY))
    {
        Some(raw) => serde_json::from_slice(&raw)?,
        None => "0".into(),
    };
    let mut report = serde_json::json!({"status":"PASS_OFFLINE_AUTHENTICATED_RECOUNT","protocol":rules::Rules::of(meta).version().to_string(),"engine":"v5","network_id":meta.network_id,"height":meta.height.to_string(),"root":hex::encode(engine.head()?.ok_or("missing head")?.root),"elapsed_micros":meta.elapsed_micros()?.to_string(),"bank":meta.bank.to_string(),"liquid":audit.liquid.to_string(),"pos_escrow":meta.pos_assets_total.to_string(),"auction_reserve":meta.auction_reserve_total.to_string(),"accounts":audit.account_count.to_string(),"authenticated_leaves":audit.authenticated_leaves.to_string(),"authenticated_nodes":audit.authenticated_tree_nodes.to_string(),"history_archive_verified":audit.history_archive_verified && audit.history_archive_from == 1,"history_pruned_through":meta.history_pruned_through.to_string(),"public_launch_allowed":false});
    // A network that pays fees on also reports its setting and what is owed.
    // The report of any other network is unchanged.
    if meta.config.fees_to_validators_ppm > 0 {
        report["fees_to_validators_ppm"] = meta.config.fees_to_validators_ppm.to_string().into();
        report["fees_owed"] = fees_owed.into();
    }
    // A network that refuses names that look alike says so: the recount has
    // then found one skeleton row for every account. The report of any
    // other network is unchanged.
    if meta.config.distinct_names {
        report["distinct_names"] = true.into();
    }
    // A network whose account waits survive a stop says so, with the total
    // of its stops: the recount has compared that total with the block
    // times the state holds. A network whose registrations can carry a set
    // of keys says so as well. The report of any other network is
    // unchanged.
    if let Some(stopped) = meta.stopped_micros {
        report["waits_survive_stops"] = true.into();
        report["stopped_micros"] = stopped.to_string().into();
    }
    if meta.config.protected_registration {
        report["protected_registration"] = true.into();
    }
    // A network that keeps service records says so: the recount has checked
    // them against each other, and against the rows of the staking rules,
    // the accounts, the block times and the rosters it holds. The report of
    // any other network is unchanged.
    if meta.config.service_records {
        report["service_records"] = true.into();
    }
    // A node whose state was restored from a snapshot holds, and has
    // recounted, the block history after the restored height only. Its
    // report says `history_archive_verified: false`, because the history
    // since genesis was not verified, and names the part that was. The
    // report of any other node is unchanged.
    if audit.history_archive_from != 1 {
        report["history_archive_from"] = audit.history_archive_from.to_string().into();
        if let Some(restored) = engine.history_base() {
            report["state_restored_at"] = restored.to_string().into();
        }
    }
    // A chain on which validators have signalled reports the plan and how
    // many signal entries its state holds; one that activated a version, the
    // versions. The report of any other network is unchanged.
    if let Some(state) = engine.upgrade_state()? {
        report["upgrade_scheduled"] = serde_json::to_value(&state.plan)?;
        report["upgrade_signals"] = state.signals.len().to_string().into();
    }
    let mut activated = Vec::new();
    for version in rules::FIRST_VERSION + 1..=rules::Rules::of(meta).version() {
        let row = engine
            .version()
            .and_then(|head| head.get(&upgrade::activated_key(version)))
            .ok_or("missing activation row")?;
        let mut entry: serde_json::Value = serde_json::from_slice(&row)?;
        entry["version"] = version.to_string().into();
        activated.push(entry);
    }
    if !activated.is_empty() {
        report["upgrade_activated"] = activated.into();
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Writes a final snapshot of the committed head and exits. Blocks committed
/// by CometBFT after that snapshot are replayed on the next start.
fn shutdown(app: &App, reason: &str) -> ! {
    eprintln!("Stopping ({reason}); saving state.");
    match app.snapshot() {
        Ok(Some(info)) => eprintln!(
            "Saved snapshot at height {} ({} bytes).",
            info.height, info.bytes
        ),
        Ok(None) => eprintln!("State was already saved."),
        Err(error) => {
            eprintln!("Final snapshot failed: {error:#}");
            process::exit(1);
        }
    }
    process::exit(if PEER_GONE.load(Ordering::SeqCst) { 3 } else { 0 })
}

/// How long the stop path waits for the answer to the last `Commit` to be
/// written before it saves and ends anyway (the consensus engine may be gone).
const STOP_ANSWER_WAIT: Duration = Duration::from_secs(5);
/// How often the node looks at the plan its state holds.
const UPGRADE_WATCH_INTERVAL: Duration = Duration::from_secs(5);

/// The end of the stop path. The node already answers no consensus request
/// and admits no transaction. Saves the state, prints why on the first line,
/// and ends with exit code 4.
fn stopped(app: &App, cause: &StopCause) -> ! {
    let saved = app.snapshot();
    let head = app.head().ok().flatten().map(|(height, _)| height);
    eprintln!("{}", cause.first_line());
    eprintln!("{}", cause.explain(head));
    if let Err(error) = saved {
        eprintln!(
            "The state could not be saved just now ({error:#}). Nothing is lost: at the next start the consensus engine replays the blocks after the last snapshot."
        );
    }
    process::exit(app::EXIT_STOPPED)
}

/// The version line. The kit and the release tool compare it exactly; a
/// rehearsal build has another one and is refused by both.
fn version_line() -> String {
    let rehearsal = if rules::REHEARSAL {
        format!(" rehearsal={}", rules::REHEARSAL_VERSION)
    } else {
        String::new()
    };
    // A build that carries a rule switch says so, with the version and the
    // height of the switch block: `switch=5@1235`. A release that is not a
    // fix release carries none, and its line is what it was.
    let switches: String = Versions::release()
        .switches()
        .iter()
        .map(|switch| format!(" switch={}@{}", switch.version, switch.block_height()))
        .collect();
    format!(
        "time-node-v5 {} protocol={}{rehearsal}{switches} devnet-only publicLaunchAllowed=false",
        env!("CARGO_PKG_VERSION"),
        rules::FIRST_VERSION
    )
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args == ["--version"] {
        println!("{}", version_line());
        return Ok(());
    }
    let options = options(args).map_err(std::io::Error::other)?;
    if options.audit {
        return audit(&options);
    }
    let started = Instant::now();
    let tolerance = Duration::from_secs(options.clock_tolerance_seconds);
    let implemented = Versions::release();
    let app = App::open_resuming(
        &options.db,
        Some((tolerance, app::system_clock())),
        options.node,
        UpgradeOptions {
            implemented: implemented.clone(),
            stop_after_height: options.stop_after_height,
        },
        app::ResumeOptions {
            expect_root: options.expect_root,
        },
    )?;
    match app.head()? {
        Some((height, root)) => eprintln!(
            "Loaded and authenticated state at height {height}, root {}, in {:.1}s.",
            hex::encode(root),
            started.elapsed().as_secs_f64()
        ),
        None => eprintln!("No saved state: waiting for InitChain."),
    }
    // A head this program does not implement, or the height it was told to
    // stop after: say so and end before the ABCI socket opens.
    if let Some(cause) = app.stop() {
        stopped(&app, &cause);
    }
    for entry in implemented.list() {
        eprintln!(
            "This program implements protocol version {} (spec {}).",
            entry.version, entry.spec
        );
    }
    if rules::REHEARSAL {
        eprintln!(
            "REHEARSAL BUILD: protocol version {} here has the rules of version {} and no specification. Never run it on a network that matters.",
            rules::REHEARSAL_VERSION,
            rules::FIRST_VERSION
        );
    }
    // A fix release says so, loudly, with every switch it carries: operators
    // compare these lines before the agreed height.
    for switch in implemented.switches() {
        eprintln!(
            "FIX RELEASE: this program carries a rule switch, without a plan and without notice: {}. On any other network it changes nothing.",
            switch.describe()
        );
    }
    if let Some(height) = options.stop_after_height {
        eprintln!(
            "This node stops after it has committed block {height} (--stop-after-height): it will answer nothing for block {}.",
            height.saturating_add(1)
        );
    }
    if let Some((height, root)) = options.expect_root {
        eprintln!(
            "This node goes on from height {height} only on the state with the root {} (--expect-root).",
            hex::encode(root)
        );
    }
    let mut watch = UpgradeWatch::default();
    if let Some(line) = app
        .upgrade_status()?
        .and_then(|status| watch.poll(&status, Instant::now()))
    {
        eprintln!("{line}");
    }
    // A failed invariant or persistence operation must not leave other
    // request threads running. Print the cause, then stop the whole process;
    // the next start resumes from the last snapshot.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("Fatal application error; stopping all ABCI connections: {info}");
        process::exit(1);
    }));
    install_signal_handlers();
    let background = app.clone();
    let interval = Duration::from_secs(options.snapshot_seconds);
    std::thread::Builder::new()
        .name("time-snapshots".into())
        .spawn(move || {
            let mut last = Instant::now();
            let mut failures = 0u32;
            let mut stop_seen: Option<Instant> = None;
            let mut watched = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(200));
                // Stopped at a height on purpose (an upgrade this program
                // does not implement, --stop-after-height, a rule switch):
                // the node answers no consensus request any more. Once the
                // answer to the last Commit has left, save and end. This
                // comes before a stop request or a lost connection: the
                // consensus engine ends when it gets no answer, and the
                // operator must still be told why this node stopped.
                if let Some(cause) = background.stop() {
                    let waited = stop_seen.get_or_insert_with(Instant::now).elapsed();
                    if background.stop_ready() || waited >= STOP_ANSWER_WAIT {
                        stopped(&background, &cause);
                    }
                    continue;
                }
                if watched.elapsed() >= UPGRADE_WATCH_INTERVAL {
                    watched = Instant::now();
                    if let Ok(Some(status)) = background.upgrade_status()
                        && let Some(line) = watch.poll(&status, watched)
                    {
                        eprintln!("{line}");
                    }
                }
                if STOP.load(Ordering::SeqCst) {
                    let reason = if PEER_GONE.load(Ordering::SeqCst) {
                        "consensus engine disconnected"
                    } else {
                        "stop requested"
                    };
                    shutdown(&background, reason);
                }
                // A snapshot for peers is written as soon as a block asked
                // for one, not on the timer: every node writes the same
                // heights.
                match background.write_sync_snapshot() {
                    Ok(Some(info)) => eprintln!(
                        "State-sync snapshot at height {} ({} bytes).",
                        info.height, info.bytes
                    ),
                    Ok(None) => {}
                    // Restarts do not depend on these snapshots: report and go on.
                    Err(error) => eprintln!("State-sync snapshot failed: {error:#}"),
                }
                if last.elapsed() < interval {
                    continue;
                }
                last = Instant::now();
                match background.snapshot() {
                    Ok(Some(info)) => {
                        failures = 0;
                        eprintln!(
                            "Snapshot at height {} ({} bytes) in {:.1}s.",
                            info.height,
                            info.bytes,
                            last.elapsed().as_secs_f64()
                        );
                    }
                    Ok(None) => failures = 0,
                    Err(error) => {
                        // Blocks stay safe in CometBFT, but recovery time
                        // grows with every missed snapshot.
                        failures += 1;
                        eprintln!("Snapshot failed ({failures} in a row): {error:#}");
                        if failures >= 5 {
                            eprintln!("Snapshots keep failing; stopping.");
                            process::exit(1);
                        }
                    }
                }
            }
        })?;
    eprintln!(
        "DEVNET ONLY: protocol 4 on the version-5 engine. Public monetary launch disabled."
    );
    eprintln!(
        "Proposals dated more than {} s ahead of this machine's clock are rejected (--clock-tolerance-seconds).",
        options.clock_tolerance_seconds
    );
    if options.node.sync_snapshot_blocks > 0 {
        eprintln!(
            "State sync: a snapshot for peers every {} blocks, the newest {} kept (--state-sync-snapshot-blocks, --state-sync-snapshots-kept).",
            options.node.sync_snapshot_blocks, options.node.sync_snapshots_kept
        );
    } else {
        eprintln!("State sync: this node offers no snapshots to peers (--state-sync-snapshot-blocks 0).");
    }
    if options.node.keep_blocks > 0 {
        eprintln!(
            "Pruning: CometBFT may delete blocks older than the last {} (--keep-blocks), except those this node, evidence or an offered snapshot still need.",
            options.node.keep_blocks
        );
    } else {
        eprintln!("Pruning: off, CometBFT keeps every block (--keep-blocks 0).");
    }
    eprintln!("ABCI listening on {}", options.listen);
    let stay = options.stay_after_disconnect;
    timecurrency_v5::transport::serve_on(options.listen, app, move || {
        if !stay {
            // The snapshot thread saves the state and exits.
            PEER_GONE.store(true, Ordering::SeqCst);
            STOP.store(true, Ordering::SeqCst);
        }
    })?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        // The reason comes first and again last: a supervisor that keeps only the last lines of what a
        // program printed would otherwise keep the usage text and lose the reason.
        eprintln!("{error}\n\n{USAGE}\n\nThe node did not start: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        options(args.iter().map(|s| (*s).into()))
    }

    #[test]
    fn refuses_live_mode_and_public_abci() {
        assert!(parse(&["--db", "state"]).is_err());
        assert!(parse(&["--devnet", "--db", "state", "--listen", "0.0.0.0:26658"]).is_err());
        assert!(parse(&["--devnet", "--db", "state", "--listen", "example.com:26658"]).is_err());
        assert!(parse(&["--devnet", "--db", "state", "--mainnet"]).is_err());
        assert!(
            parse(&[
                "--devnet",
                "--db",
                "state",
                "--listen",
                "127.0.0.1:1",
                "--listen",
                "127.0.0.1:2"
            ])
            .is_err()
        );
    }

    #[test]
    fn requires_explicit_state_and_accepts_loopback() {
        assert!(parse(&["--devnet"]).is_err());
        let parsed = parse(&["--devnet", "--db", "state"]).unwrap();
        assert_eq!(parsed.listen.to_string(), "127.0.0.1:26658");
        assert_eq!(parsed.snapshot_seconds, 120);
        assert!(!parsed.stay_after_disconnect);
        assert!(parse(&["--devnet", "--db", "state", "--snapshot-seconds", "1"]).is_err());
        assert_eq!(
            parse(&["--devnet", "--db", "state", "--snapshot-seconds", "30"])
                .unwrap()
                .snapshot_seconds,
            30
        );
    }

    #[test]
    fn the_clock_tolerance_has_a_default_and_bounds() {
        let parsed = parse(&["--devnet", "--db", "state"]).unwrap();
        assert_eq!(parsed.clock_tolerance_seconds, 30);
        assert_eq!(
            Duration::from_secs(parsed.clock_tolerance_seconds),
            app::DEFAULT_CLOCK_TOLERANCE
        );
        for (value, accepted) in [("1", true), ("60", true), ("5", true), ("0", false), ("61", false), ("600", false), ("-1", false), ("1.5", false), ("", false)] {
            let result = parse(&["--devnet", "--db", "state", "--clock-tolerance-seconds", value]);
            assert_eq!(result.is_ok(), accepted, "{value}");
            if accepted {
                assert_eq!(result.unwrap().clock_tolerance_seconds.to_string(), value);
            }
        }
        // Missing value, given twice.
        assert!(parse(&["--devnet", "--db", "state", "--clock-tolerance-seconds"]).is_err());
        assert!(
            parse(&[
                "--devnet",
                "--db",
                "state",
                "--clock-tolerance-seconds",
                "10",
                "--clock-tolerance-seconds",
                "10"
            ])
            .is_err()
        );
    }

    #[test]
    fn state_sync_and_pruning_are_off_by_default_and_strictly_parsed() {
        let base = ["--devnet", "--db", "state"];
        let with = |extra: &[&str]| parse(&[&base[..], extra].concat());
        // Defaults: no snapshots for peers, every block kept.
        let parsed = with(&[]).unwrap();
        assert_eq!(parsed.node, NodeOptions::default());
        assert_eq!(parsed.node.keep_blocks, 0);
        assert_eq!(parsed.node.sync_snapshot_blocks, 0);
        assert_eq!(parsed.node.sync_snapshots_kept, 2);
        assert_eq!(parsed.node.restore_max_bytes, 16 * 1024 * 1024 * 1024);
        assert_eq!(parsed.node.sync_chunk_bytes, 4 * 1024 * 1024);
        for (flag, value, accepted) in [
            ("--state-sync-snapshot-blocks", "0", true),
            ("--state-sync-snapshot-blocks", "10", true),
            ("--state-sync-snapshot-blocks", "1000", true),
            ("--state-sync-snapshot-blocks", "1000000", true),
            ("--state-sync-snapshot-blocks", "9", false),
            ("--state-sync-snapshot-blocks", "1", false),
            ("--state-sync-snapshot-blocks", "1000001", false),
            ("--state-sync-snapshot-blocks", "-10", false),
            ("--state-sync-snapshot-blocks", "+10", false),
            ("--state-sync-snapshot-blocks", "010", false),
            ("--state-sync-snapshot-blocks", "10.0", false),
            ("--state-sync-snapshot-blocks", "1e3", false),
            ("--state-sync-snapshot-blocks", " 10", false),
            ("--state-sync-snapshot-blocks", "", false),
            ("--state-sync-max-mib", "4", true),
            ("--state-sync-max-mib", "16384", true),
            ("--state-sync-max-mib", "400000", true),
            ("--state-sync-max-mib", "3", false),
            ("--state-sync-max-mib", "0", false),
            ("--state-sync-max-mib", "400001", false),
            ("--state-sync-max-mib", "18446744073709551616", false),
            ("--keep-blocks", "0", true),
            ("--keep-blocks", "2000000", true),
            ("--keep-blocks", "5000000", true),
            ("--keep-blocks", "1000000000000", true),
            ("--keep-blocks", "1999999", false),
            ("--keep-blocks", "1", false),
            ("--keep-blocks", "100", false),
            ("--keep-blocks", "1000000000001", false),
            ("--keep-blocks", "-1", false),
            ("--keep-blocks", "00", false),
            ("--keep-blocks", "all", false),
            ("--keep-blocks", "", false),
        ] {
            let result = with(&[flag, value]);
            assert_eq!(result.is_ok(), accepted, "{flag} {value}");
            // Missing value, given twice.
            assert!(with(&[flag]).is_err(), "{flag}");
            assert!(with(&[flag, value, flag, value]).is_err(), "{flag} {value} twice");
        }
        let parsed = with(&["--state-sync-snapshot-blocks", "1000", "--state-sync-snapshots-kept", "3", "--state-sync-max-mib", "8", "--keep-blocks", "3000000"]).unwrap();
        assert_eq!(
            parsed.node,
            NodeOptions {
                keep_blocks: 3_000_000,
                sync_snapshot_blocks: 1000,
                sync_snapshots_kept: 3,
                restore_max_bytes: 8 * 1024 * 1024,
                sync_chunk_bytes: statesync::SYNC_CHUNK_BYTES,
            }
        );
        // How many are kept means nothing without snapshots, and is bounded.
        for (value, accepted) in [("1", true), ("2", true), ("10", true), ("0", false), ("11", false), ("-1", false), ("2.0", false)] {
            let result = with(&["--state-sync-snapshot-blocks", "100", "--state-sync-snapshots-kept", value]);
            assert_eq!(result.is_ok(), accepted, "{value}");
        }
        assert!(with(&["--state-sync-snapshots-kept", "2"]).is_err());
        assert!(with(&["--state-sync-snapshot-blocks", "0", "--state-sync-snapshots-kept", "2"]).is_err());
        assert!(with(&["--state-sync-snapshot-blocks", "100", "--state-sync-snapshots-kept"]).is_err());
        // The offline recount takes none of them.
        assert!(with(&["--audit"]).is_ok());
        assert!(with(&["--audit", "--keep-blocks", "0"]).is_err());
        assert!(with(&["--audit", "--state-sync-snapshot-blocks", "100"]).is_err());
        // Near misses of the names are refused, not ignored.
        for flag in ["--keep-block", "--retain-blocks", "--state-sync", "--statesync-snapshot-blocks", "--keep-blocks=0"] {
            assert!(with(&[flag, "0"]).is_err(), "{flag}");
        }
    }

    #[test]
    fn the_stop_height_is_a_block_height_and_the_version_line_is_exact() {
        let base = ["--devnet", "--db", "state"];
        let with = |extra: &[&str]| parse(&[&base[..], extra].concat());
        assert_eq!(with(&[]).unwrap().stop_after_height, None);
        for (value, accepted) in [
            ("1", true),
            ("2", true),
            ("1234567", true),
            ("9223372036854775807", true),
            ("0", false),
            ("9223372036854775808", false),
            ("18446744073709551616", false),
            ("-1", false),
            ("+1", false),
            ("01", false),
            ("1.0", false),
            ("1e3", false),
            (" 1", false),
            ("", false),
            ("next", false),
        ] {
            let result = with(&["--stop-after-height", value]);
            assert_eq!(result.is_ok(), accepted, "{value}");
            if accepted {
                let parsed = result.unwrap().stop_after_height.map(|height| height.to_string());
                assert_eq!(parsed.as_deref(), Some(value));
            }
        }
        // Missing value, given twice, near misses, and with the recount.
        assert!(with(&["--stop-after-height"]).is_err());
        assert!(with(&["--stop-after-height", "5", "--stop-after-height", "5"]).is_err());
        for flag in ["--stop-after", "--stop-height", "--stop-after-height=5", "--halt-height"] {
            assert!(with(&[flag, "5"]).is_err(), "{flag}");
        }
        assert!(with(&["--audit", "--stop-after-height", "5"]).is_err());
        // It combines with every other setting.
        let parsed = with(&["--stop-after-height", "77", "--keep-blocks", "3000000", "--snapshot-seconds", "30"]).unwrap();
        assert_eq!(
            (parsed.stop_after_height, parsed.node.keep_blocks, parsed.snapshot_seconds),
            (Some(77), 3_000_000, 30)
        );
        // The version line: what the kit and the release tool compare. A
        // rehearsal build says so, and so matches neither.
        let line = version_line();
        let version = env!("CARGO_PKG_VERSION");
        if rules::REHEARSAL {
            assert_eq!(line, format!("time-node-v5 {version} protocol=4 rehearsal=5 devnet-only publicLaunchAllowed=false"));
        } else {
            assert_eq!(line, format!("time-node-v5 {version} protocol=4 devnet-only publicLaunchAllowed=false"));
        }
        assert!(USAGE.contains("--stop-after-height H") && USAGE.contains("exit code 4"));
    }
}
