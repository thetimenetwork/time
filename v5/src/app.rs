//! ABCI application for the version-5 engine.
//!
//! Protocol-4 rules; what differs from the protocol-4 application is how the
//! work is scheduled:
//!
//! - A block is executed once. Validating a proposal (`ProcessProposal`)
//!   keeps its result; `FinalizeBlock` for the same block reuses it.
//! - Mempool checks, queries and block execution read an immutable committed
//!   version, so they run at the same time. Only `Commit` and `InitChain`
//!   take the engine exclusively, and only for the time it takes to swap the
//!   head.
//! - State is persisted by snapshots, not on every block: CometBFT keeps the
//!   blocks and replays the ones after the newest snapshot (see `store`).
//!
//! Two inputs are version 5's own:
//!
//! - The misbehavior CometBFT reports with a block is executed with it
//!   (`crate::pos_adapter::misbehavior`), by the proposer, by validators and
//!   by `FinalizeBlock` alike, and is part of the key under which an
//!   execution is reused (`ExecKey`).
//! - A node opened with `App::open_with_clock`, as the node binary always
//!   is, rejects in `ProcessProposal` a proposal dated more than a tolerance
//!   ahead of its own clock (`DEFAULT_CLOCK_TOLERANCE`).
//!
//! State sync and block pruning (`crate::statesync`) are settings of one
//! node and change no rule: the four ABCI snapshot calls offer this node's
//! snapshots to peers and restore one received from them, and `Commit`
//! answers with the height below which CometBFT may delete blocks.
use crate::{
    engine::{
        CHECK_STATE_ROW_LIMIT, CheckState, Engine, MAX_BLOCK_TX_BYTES, Meta, Prepared,
        RestoreRefusal, account_key, canonical_decode, name_key, pubkey_key, recovery_key,
        validate_block_transactions,
    },
    genesis::Genesis,
    pos_adapter,
    proof::ProofEntry,
    rules::Versions,
    sigcache::SigStatus,
    statesync::{
        self, Chunk, EVIDENCE_MAX_AGE_BLOCKS, EVIDENCE_MAX_AGE_SECONDS, LogLimiter, Logged,
        Manifest, NodeOptions, Restore, RetainInputs, SYNC_FORMAT,
    },
    store::{SnapshotInfo, Store, StoreOptions, Version},
    transport::BatchCheck,
    upgrade,
};
use anyhow::{Context, Result, anyhow, ensure};
use prost::Message;
use rayon::prelude::*;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tendermint_abci::Application;
use tendermint_proto::v0_38::{
    abci::*,
    types::{BlockParams, ConsensusParams, EvidenceParams, VersionParams},
};
use timecurrency_node::ledger::{self, Account};

const MAX_REQUEST: usize = 8 * 1024 * 1024;
const MAX_QUERY: usize = 16 * 1024;
const MAX_PROOF_RESPONSE: usize = 3 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
/// Executed proposals kept for one height: one per consensus round seen.
const MAX_EXECUTED: usize = 3;
/// Snapshot metadata in one `ListSnapshots` answer, below the ABCI frame
/// limit (`transport::MAX_FRAME_BYTES`).
const MAX_LISTED_METADATA: usize = 6 * 1024 * 1024;

/// How far ahead of this node's own clock a proposed block may be dated
/// before `ProcessProposal` rejects it, unless the node is started with
/// another value (`time-node-v5 --clock-tolerance-seconds`).
///
/// Two checks bound a block's time. Under CometBFT 0.38 a block's time is
/// the median, weighted by voting power, of the times in the precommits its
/// last commit carries. More than half of the signing power sets it; so does
/// just over a third when one of them proposes, because the proposer chooses
/// which precommits (any two thirds) the block carries. The ledger rules
/// only require it to advance. CometBFT itself refuses a block dated
/// `consensus.block_time_tolerance` (60 s by default) or more ahead of the
/// node's clock (`state/validation.go`): its node prevotes nil, and panics
/// if the block is prevoted or committed by two thirds all the same. This
/// check narrows that, in the application, to this tolerance: a node
/// rejects such a proposal in `ProcessProposal`, which only costs its
/// prevote. Without two thirds of the prevotes the block is not decided, so
/// the chain's clock stays within this tolerance of the honest validators'
/// clocks, and cannot gain more over time because every proposal is
/// compared with the clock again. More than two thirds can still decide a
/// block dated up to CometBFT's tolerance ahead without the others'
/// prevotes. Either bound keeps a majority from fast-forwarding what waits
/// for time: the new time issued with each block, the 14-day unbonding
/// hold, the 90-day fade of the starting validators' power.
///
/// Why 30 seconds, half of CometBFT's 60:
/// - An honest block is dated in the past, not in the future: its time is
///   when the validators voted on the block before it, as their own clocks
///   read, and by the time the proposal reaches a validator the commit
///   timeout (1 s by default) and the propagation have passed. A proposal is
///   ahead of this node's clock only if the clocks that set the median run
///   ahead of it.
/// - Clocks kept by NTP agree within tens of milliseconds; leap-second
///   smearing differs from a stepped clock by up to about a second; a
///   machine whose time synchronization has failed drifts by its
///   oscillator's error, typically below 50 parts per million, or about 4 s
///   a day. 30 s covers about a week of that. A node 30 to 60 s behind
///   loses its prevotes; one 60 s or more behind stops in CometBFT when two
///   thirds commit a block it deems from the future.
/// - What it leaves a majority is a one-time advance of the chain's clock by
///   at most 30 s: half of what a single block can issue (60 s), 30 s of the
///   hour over which validator-set changes are limited in production, and
///   nothing measurable against the 14-day hold or the 90-day fade. (On a
///   laboratory network, whose fade lasts 60 s, it is a large part of the
///   fade; laboratory networks are for tests.)
pub const DEFAULT_CLOCK_TOLERANCE: Duration = Duration::from_secs(30);

/// The clock a node compares proposed block times with: `system_clock()` on
/// a node, a controlled one in tests.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// This machine's clock (`SystemTime::now`).
pub fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}

/// The check `ProcessProposal` applies to the block time of a proposal.
struct ClockCheck {
    tolerance_micros: i64,
    now: Clock,
}

#[derive(Clone)]
pub struct App {
    shared: Arc<Shared>,
}
struct Shared {
    engine: RwLock<Engine>,
    store: Arc<Store>,
    /// Blocks executed for the next height. Lock order: `executed`, then `engine`.
    executed: Mutex<Vec<Executed>>,
    /// Mempool admission state. Lock order: `check`, then `engine`. Never
    /// taken together with `executed`.
    check: Mutex<Option<CheckState>>,
    faulted: AtomicBool,
    executed_blocks: AtomicU64,
    reused_executions: AtomicU64,
    /// Set by `open_with_clock`: proposals dated too far ahead of this clock
    /// are rejected.
    clock: Option<ClockCheck>,
    /// This node's settings for snapshots, restores and pruning.
    options: NodeOptions,
    /// The state-sync restore in progress, if any. Lock order: `restore`,
    /// then `executed`, then `engine`.
    restore: Mutex<Option<Restore>>,
    /// The committed version a snapshot for peers is due for. Written by
    /// `Commit`, taken by `write_sync_snapshot`. Never held with another lock.
    sync_due: Mutex<Option<Arc<Version>>>,
    /// `--stop-after-height`: after the commit of this block the node stops.
    stop_after_height: Option<u64>,
    /// `--expect-root`: the height and the root the node goes on from
    /// (`ResumeOptions`).
    expect_root: Option<(u64, [u8; 32])>,
    /// Why the node has stopped on purpose, once it has. Never cleared: a
    /// stopped node answers no consensus request and admits no transaction
    /// until the process ends. Never held with another lock.
    stop: Mutex<Option<StopCause>>,
    /// `stop` is set. Read on every consensus request.
    stopped: AtomicBool,
    /// The thread that is answering the `Commit` the node stopped after, and
    /// whether that answer has left (`BatchCheck::answers_written`).
    stop_answering: Mutex<Option<std::thread::ThreadId>>,
    stop_ready: AtomicBool,
    /// The answering thread has answered a Flush since the node stopped.
    stop_flushed: AtomicBool,
    /// Set once this process has finalized or committed a block. From then
    /// on it is a node that executes its chain, and it takes no state from a
    /// snapshot: CometBFT state-syncs only before its first block, so an
    /// offer after that does not come from a CometBFT that is joining.
    executing: AtomicBool,
    /// Limits the log lines for refused chunks. Taken for a moment while
    /// `restore` is held; nothing is locked while it is held.
    refused_chunks: Mutex<LogLimiter>,
}
/// Why a node stopped at a height on purpose (exit code 4). A stopped node
/// has answered the `Commit` in progress, if any, and answers no consensus
/// request after it: it neither accepts nor rejects a proposal for the next
/// height. Its state is saved; the program that implements what comes next
/// continues from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// The head is not runnable: its version is not one this program
    /// implements. The program executed the activating block under the old
    /// rules, as every program does, and stops after it.
    Upgrade(upgrade::NotRunnable),
    /// `--stop-after-height`: block `height` is committed.
    Asked { height: u64 },
    /// The decided block `height` carries action kind 81, a rule switch this
    /// program does not implement. Nothing of it was executed; the head is
    /// the block before.
    Switch { height: u64 },
    /// A fix release only. The decided block `height` is at the height of
    /// this program's switch block and is not that block, or the chain is
    /// not where the program was built to find it; `found` says which
    /// (`upgrade::Verdict::NotTheSwitch`). Nothing of it was executed; the
    /// head is the block before. This is how a wrong height cannot be
    /// papered over (design, section 10).
    SwitchExpected { height: u64, found: String },
    /// A fix release only. The head is past this program's switch block and
    /// still under the version before it: the chain went on without the
    /// switch. The program executes nothing on it, and is stopped before it
    /// serves.
    SwitchMissed(upgrade::MissedSwitch),
}
impl StopCause {
    /// The first line printed. It says why and nothing else. Every stop
    /// that is about a rule switch has the same first line, whichever side
    /// lacks the switch; the line after it says which release to start.
    pub fn first_line(&self) -> &'static str {
        match self {
            Self::Upgrade(_) => "STOPPED FOR UPGRADE",
            Self::Asked { .. } => "STOPPED AS ASKED",
            Self::Switch { .. } | Self::SwitchExpected { .. } | Self::SwitchMissed(_) => "STOPPED AT A SWITCH",
        }
    }
    /// What follows the first line. `saved` is the height of the saved head.
    pub fn explain(&self, saved: Option<u64>) -> String {
        let state = saved.map_or_else(
            || "The node holds no state yet.".to_string(),
            |height| format!("The state at height {height} is saved and valid."),
        );
        match self {
            Self::Upgrade(reason) => reason.explain(),
            Self::Asked { height } => format!(
                "The node was started with --stop-after-height {height} and block {height} is committed. {state} It answers nothing for the next height. Start it without the flag, or with a later height, to go on. Delete nothing."
            ),
            Self::Switch { height } => format!(
                "The decided block {height} carries a rule switch (action kind 81), which this program does not implement. Nothing of that block was executed. {state} Install the release that implements the switch and start it on the same data: the consensus engine hands it the block again. Delete nothing."
            ),
            Self::SwitchExpected { height, found } => format!(
                "The decided block {height} is not the switch block this fix release was built for: {found}. Nothing of that block was executed. {state} This chain did not stop where the fix was agreed, and this program cannot go on with it. Start the release this state was made by, and wait for a fix release built for the chain as it is. Delete nothing."
            ),
            Self::SwitchMissed(missed) => missed.explain(),
        }
    }
}
/// The process exit code of a node that stopped at a height on purpose.
pub const EXIT_STOPPED: i32 = 4;
/// The first line a node prints when a decided block failed a check of this
/// program (`App::failed_block_report`). The node then ends with exit code
/// 1, a failure: nothing was stopped on purpose. The line after it names the
/// block and the state, for the operators to compare.
pub const FAILED_BLOCK_LINE: &str = "FAILED ON A DECIDED BLOCK";

/// What a node is told about versions and stops, beside `NodeOptions`.
#[derive(Clone, Debug)]
pub struct UpgradeOptions {
    /// The versions of the rules this program implements. The node binary
    /// passes its build's list (`Versions::release`); tests run two programs
    /// from one source.
    pub implemented: Versions,
    /// `--stop-after-height H`: after the commit of block `H` the node takes
    /// the stop path. Opened with its head at `H`, it is stopped at once;
    /// with its head above `H`, opening fails.
    pub stop_after_height: Option<u64>,
}
impl Default for UpgradeOptions {
    fn default() -> Self {
        Self {
            implemented: Versions::release(),
            stop_after_height: None,
        }
    }
}

/// What an operator may state about the state a node is to go on from
/// (`time-node-v5 --expect-root`), for a restart that validators agreed on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResumeOptions {
    /// `--expect-root H:ROOT`: the node executes nothing after block `H`
    /// unless its state at `H` has this root. Opened with its head at `H`
    /// and another root, or with its head above `H`, opening fails and
    /// nothing is changed. Opened below `H` (its newest snapshot is older
    /// and the consensus engine replays the blocks up to `H`), it fails
    /// closed at the commit of `H` if the root is another one, before it
    /// answers. It is a check of this node against what the validators
    /// agreed on out of band; it changes no rule and no byte.
    pub expect_root: Option<(u64, [u8; 32])>,
}

/// What a node knows about a coming upgrade (`/status.upgrade`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeStatus {
    /// The version in force at the head, and its elapsed chain time.
    pub version: u64,
    pub elapsed_micros: u64,
    pub scheduled: Option<upgrade::Plan>,
    /// Whether this program implements the scheduled plan. `None` when
    /// nothing is scheduled.
    pub implements_scheduled: Option<bool>,
}

/// How often a node that does not implement a scheduled plan says so.
pub const UPGRADE_WARNING_INTERVAL: Duration = Duration::from_secs(600);

/// Decides when a node writes about a scheduled plan in its log: once if it
/// implements the plan, at start and then every ten minutes if it does not.
#[derive(Default)]
pub struct UpgradeWatch {
    logged: Option<upgrade::Plan>,
    warned: Option<std::time::Instant>,
}
impl UpgradeWatch {
    /// The line to print now, if any.
    pub fn poll(&mut self, status: &UpgradeStatus, now: std::time::Instant) -> Option<String> {
        let Some(plan) = &status.scheduled else {
            self.logged = None;
            self.warned = None;
            return None;
        };
        // The start time is "not before": a validator safety hold postpones
        // the switch to the first block without one.
        let when = if status.elapsed_micros >= plan.activate_elapsed_micros {
            "its start time has come, and it waits for the first block in which no validator safety hold is on".to_string()
        } else {
            format!(
                "about {} s of chain time from now",
                (plan.activate_elapsed_micros - status.elapsed_micros) / 1_000_000
            )
        };
        if status.implements_scheduled == Some(true) {
            if self.logged.as_ref() == Some(plan) {
                return None;
            }
            self.logged = Some(plan.clone());
            self.warned = None;
            return Some(format!(
                "Upgrade scheduled: protocol version {} (spec {}) starts with the first block dated at or after chain time {} micros in which no validator safety hold is on, {when}. This program implements it.",
                plan.version, plan.spec, plan.activate_elapsed_micros
            ));
        }
        if self.logged.as_ref() == Some(plan)
            && self.warned.is_some_and(|last| now.saturating_duration_since(last) < UPGRADE_WARNING_INTERVAL)
        {
            return None;
        }
        self.logged = Some(plan.clone());
        self.warned = Some(now);
        Some(format!(
            "WARNING: an upgrade to protocol version {} (spec {}) is scheduled for chain time {} micros, {when}. THIS PROGRAM DOES NOT IMPLEMENT IT and will stop after the block that activates it (exit code {EXIT_STOPPED}). Install a release that implements it before then.",
            plan.version, plan.spec, plan.activate_elapsed_micros
        ))
    }
}
/// Work counters since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Blocks executed: proposals validated, or finalized blocks whose
    /// proposal this node had not validated.
    pub executed_blocks: u64,
    /// Finalized blocks answered from the execution done for their proposal.
    pub reused_executions: u64,
}
/// Everything block execution depends on.
#[derive(PartialEq, Eq)]
struct ExecKey {
    height: i64,
    time_micros: i64,
    block_hash: [u8; 32],
    eligible: Vec<String>,
    txs_digest: [u8; 32],
    /// The misbehavior CometBFT reported with the block, as received
    /// (`misbehavior_digest`): a block executed with one list is never
    /// reused for a block with another.
    misbehavior_digest: [u8; 32],
    /// The proposer the block's header names, which the service records
    /// count (`Engine::prepare_proposed`).
    proposer: Vec<u8>,
}
struct Executed {
    key: ExecKey,
    prepared: Prepared,
    response: ResponseFinalizeBlock,
    /// Fingerprint of the `FinalizeBlock` request that selected this block.
    finalized: Option<[u8; 32]>,
}
/// Hash over the hashes of all transactions, in order.
fn txs_digest<T: AsRef<[u8]> + Sync>(txs: &[T]) -> [u8; 32] {
    let hashes: Vec<[u8; 32]> = txs
        .par_iter()
        .map(|tx| Sha256::digest(tx.as_ref()).into())
        .collect();
    let mut hasher = Sha256::new();
    hasher.update((txs.len() as u64).to_be_bytes());
    for hash in &hashes {
        hasher.update(hash);
    }
    hasher.finalize().into()
}
/// Hash over the misbehavior list of a block, entry by entry as encoded,
/// every field included.
fn misbehavior_digest(entries: &[Misbehavior]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        let bytes = entry.encode_to_vec();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    hasher.finalize().into()
}
/// The misbehavior list as the engine reads it. Nothing is refused here: the
/// rule (`pos_adapter::misbehavior`) skips the entries it cannot use.
fn reported(entries: &[Misbehavior]) -> Vec<pos_adapter::Misbehavior> {
    entries
        .iter()
        .map(|entry| pos_adapter::Misbehavior {
            kind: entry.r#type,
            address: entry
                .validator
                .as_ref()
                .map_or_else(Vec::new, |validator| validator.address.to_vec()),
            height: entry.height,
        })
        .collect()
}
/// Microseconds since the Unix epoch; negative before it.
fn micros_since_epoch(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_micros()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_micros()).map_or(i64::MIN, |micros| -micros)
        }
    }
}
fn consensus_params(version: u64) -> ConsensusParams {
    ConsensusParams {
        block: Some(BlockParams {
            // Room for the transaction budget plus the block's own framing.
            max_bytes: (MAX_BLOCK_TX_BYTES + 256 * 1024) as i64,
            max_gas: -1,
        }),
        evidence: Some(EvidenceParams {
            // Block pruning (`statesync::retain_height`) keeps what this
            // window can still name.
            max_age_num_blocks: EVIDENCE_MAX_AGE_BLOCKS as i64,
            max_age_duration: Some(tendermint_proto::google::protobuf::Duration {
                seconds: EVIDENCE_MAX_AGE_SECONDS as i64,
                nanos: 0,
            }),
            max_bytes: 65536,
        }),
        version: Some(VersionParams { app: version }),
        validator: None,
        abci: None,
    }
}
fn time(value: Option<&tendermint_proto::google::protobuf::Timestamp>) -> Result<i64> {
    let v = value.ok_or_else(|| anyhow!("missing consensus timestamp"))?;
    ensure!(
        v.seconds >= 0 && (0..1_000_000_000).contains(&v.nanos),
        "invalid timestamp"
    );
    v.seconds
        .checked_mul(1_000_000)
        .and_then(|s| s.checked_add(i64::from(v.nanos / 1000)))
        .ok_or_else(|| anyhow!("timestamp overflow"))
}
fn response(
    root: [u8; 32],
    count: usize,
    version: u64,
    updates: &[pos::Validator],
) -> Result<ResponseFinalizeBlock> {
    Ok(ResponseFinalizeBlock {
        app_hash: root.to_vec().into(),
        tx_results: (0..count).map(|_| ExecTxResult::default()).collect(),
        consensus_param_updates: Some(consensus_params(version)),
        validator_updates: updates
            .iter()
            .map(|v| {
                Ok(ValidatorUpdate {
                    pub_key: Some(tendermint_proto::crypto::PublicKey {
                        sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                            hex::decode(&v.consensus_key)?,
                        )),
                    }),
                    power: i64::try_from(v.power)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        ..Default::default()
    })
}
/// A line for the node's log about what a block did to a plan. `now` is the
/// block's time and `wait` how long a plan may wait after its start time
/// (`upgrade::Params::late`).
pub fn describe_event(event: &upgrade::Event, now: u64, wait: u64) -> String {
    use upgrade::Event;
    let named = |plan: &upgrade::Plan| {
        format!(
            "protocol version {} (spec {}), start at chain time {} micros",
            plan.version, plan.spec, plan.activate_elapsed_micros
        )
    };
    match event {
        Event::Scheduled(plan) => format!("Upgrade scheduled: {}.", named(plan)),
        Event::CancelledSupport(plan) => format!(
            "Upgrade cancelled: {} lost three quarters of the voting power.",
            named(plan)
        ),
        Event::CancelledGap(plan) => format!(
            "Upgrade cancelled: {}; a block was dated more than an hour after its parent.",
            named(plan)
        ),
        // Said as it happened: the block came too late after the start
        // time. Whether a hold made the plan wait is not this line's to
        // guess: without any hold, a pause in block production across the
        // start time does the same (in the laboratory profile after 60 s).
        Event::CancelledLate(plan) => format!(
            "Upgrade cancelled: {}. This block is dated {:.6} s after that start time, more than the {} s a plan may wait, and the plan had not activated: either a validator safety hold lasted that long, or no block was dated in that time.",
            named(plan),
            now.saturating_sub(plan.activate_elapsed_micros) as f64 / 1e6,
            wait / 1_000_000
        ),
        Event::CancelledStale(plan) => format!(
            "Upgrade cancelled: {}; it names another version than the next.",
            named(plan)
        ),
        Event::Postponed(plan) => format!(
            "Upgrade postponed: {}. Its start time has come during a validator safety hold; it activates in the first block without one, or is cancelled by the first block dated more than {} s after its start time.",
            named(plan),
            wait / 1_000_000
        ),
        Event::Activated(plan) => format!(
            "Upgrade activated: {}. The next block is the first under version {}.",
            named(plan),
            plan.version
        ),
        Event::Switched { version, spec, cancelled } => format!(
            "RULE SWITCH: this block is the switch block of a fix release. It wrote protocol version {version} (spec {spec}) without a plan and without notice. The next block is the first under version {version}.{}",
            cancelled
                .as_ref()
                .map_or_else(String::new, |plan| format!(" The plan that was scheduled is gone with it: {}.", named(plan)))
        ),
    }
}
fn eligible(
    roster: &[pos::Validator],
    votes: impl IntoIterator<Item = (Option<Validator>, i32)>,
) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for (n, (validator, flag)) in votes.into_iter().enumerate() {
        ensure!(n < pos::MAX_VALIDATORS, "too many commit votes");
        if flag != 2 {
            continue;
        }
        let v = validator.ok_or_else(|| anyhow!("missing commit voter"))?;
        let op = roster
            .iter()
            .find(|o| {
                hex::decode(&o.consensus_key)
                    .is_ok_and(|k| Sha256::digest(k)[..20] == v.address[..])
            })
            .ok_or_else(|| anyhow!("unknown commit voter"))?;
        ensure!(
            v.power > 0
                && u64::try_from(v.power)? == op.power
                && seen.insert(op.consensus_key.clone()),
            "duplicate/incorrect voter power"
        );
        result.push(op.consensus_key.clone());
    }
    Ok(result)
}
impl App {
    /// Opens the state under `path`: snapshots in `<path>.v5state/`, the block
    /// history archive in `<path>.history/`, as protocol 4 placed it.
    ///
    /// Proposals are not compared with any clock: this is for tools and tests
    /// that drive chains with historical or synthetic dates. The node binary
    /// opens with `open_with_clock`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_checking(path.as_ref(), None, NodeOptions::default(), UpgradeOptions::default(), ResumeOptions::default())
    }
    /// As `open`, with this node's settings for snapshots offered to peers,
    /// restores and block pruning (`statesync::NodeOptions`).
    pub fn open_with_options(path: impl AsRef<Path>, options: NodeOptions) -> Result<Self> {
        Self::open_checking(path.as_ref(), None, options, UpgradeOptions::default(), ResumeOptions::default())
    }
    /// As `open_with_options`, with the versions this program implements
    /// and the height to stop after (`UpgradeOptions`), and with a clock
    /// check if `clock` is given (`open_with_clock`): everything a node can
    /// be told. The node binary opens with this.
    ///
    /// A state whose head this program does not implement opens, stopped
    /// (`stop`): the node then prints why and ends before it serves ABCI.
    /// So does a state whose head is `stop_after_height`. A state whose head
    /// is above `stop_after_height` does not open.
    pub fn open_upgradable(
        path: impl AsRef<Path>,
        clock: Option<(Duration, Clock)>,
        options: NodeOptions,
        upgrade: UpgradeOptions,
    ) -> Result<Self> {
        let clock = match clock {
            Some((tolerance, now)) => Some(ClockCheck {
                tolerance_micros: i64::try_from(tolerance.as_micros())
                    .context("clock tolerance out of range")?,
                now,
            }),
            None => None,
        };
        Self::open_checking(path.as_ref(), clock, options, upgrade, ResumeOptions::default())
    }
    /// As `open_upgradable`, for a restart on a state the validators agreed
    /// on (`ResumeOptions`). The node binary opens with this.
    ///
    /// A fix release also opens stopped when its head is past its own rule
    /// switch and still under the version before it (`StopCause::SwitchMissed`).
    pub fn open_resuming(
        path: impl AsRef<Path>,
        clock: Option<(Duration, Clock)>,
        options: NodeOptions,
        upgrade: UpgradeOptions,
        resume: ResumeOptions,
    ) -> Result<Self> {
        let clock = match clock {
            Some((tolerance, now)) => Some(ClockCheck {
                tolerance_micros: i64::try_from(tolerance.as_micros())
                    .context("clock tolerance out of range")?,
                now,
            }),
            None => None,
        };
        Self::open_checking(path.as_ref(), clock, options, upgrade, resume)
    }
    /// As `open_with_clock`, with the settings of `open_with_options`: what
    /// the node binary opens.
    pub fn open_node(
        path: impl AsRef<Path>,
        tolerance: Duration,
        clock: Clock,
        options: NodeOptions,
    ) -> Result<Self> {
        let tolerance_micros =
            i64::try_from(tolerance.as_micros()).context("clock tolerance out of range")?;
        Self::open_checking(
            path.as_ref(),
            Some(ClockCheck {
                tolerance_micros,
                now: clock,
            }),
            options,
            UpgradeOptions::default(),
            ResumeOptions::default(),
        )
    }
    /// As `open`, and `ProcessProposal` rejects every proposal dated more
    /// than `tolerance` ahead of `clock`, before anything of it is executed
    /// or remembered. The node passes `system_clock()` and
    /// `--clock-tolerance-seconds` (default `DEFAULT_CLOCK_TOLERANCE`, which
    /// explains the value).
    ///
    /// Only live proposals are judged by this clock. `FinalizeBlock` (a
    /// decided block, a replay after a restart, block sync) and
    /// `PrepareProposal` never are: the application never refuses a decided
    /// block for its date. (CometBFT does, by its own `block_time_tolerance`,
    /// before the block reaches the application; see
    /// `DEFAULT_CLOCK_TOLERANCE`.) A rejection here only costs this node's
    /// prevote: CometBFT still precommits and commits a block that two thirds
    /// prevoted.
    ///
    /// Liveness: the check makes `ProcessProposal` depend on the local clock,
    /// which ABCI asks applications not to do. A validator whose clock lags
    /// the median of the voters' clocks by more than the tolerance prevotes
    /// nil. If more than a third of the voting power does, the round fails;
    /// the next proposals for that height carry about the same time (it comes
    /// from the votes of the height before) while the clocks advance, so the
    /// height is decided late, not never. The same happens when clocks are
    /// correct and a majority dates blocks ahead: the chain slows down to the
    /// honest clocks instead of running ahead of them. (A node 60 s or more
    /// behind is stopped by CometBFT's own check, not by this one.)
    ///
    /// Safety is not affected: CometBFT's agreement does not depend on how a
    /// validator judges a proposal, and the execution of a decided block never
    /// reads the clock, so every node reaches the same state from it.
    pub fn open_with_clock(
        path: impl AsRef<Path>,
        tolerance: Duration,
        clock: Clock,
    ) -> Result<Self> {
        let tolerance_micros =
            i64::try_from(tolerance.as_micros()).context("clock tolerance out of range")?;
        Self::open_checking(
            path.as_ref(),
            Some(ClockCheck {
                tolerance_micros,
                now: clock,
            }),
            NodeOptions::default(),
            UpgradeOptions::default(),
            ResumeOptions::default(),
        )
    }
    fn open_checking(
        database: &Path,
        clock: Option<ClockCheck>,
        options: NodeOptions,
        upgrade: UpgradeOptions,
        resume: ResumeOptions,
    ) -> Result<Self> {
        options.validate()?;
        if let Some(parent) = database.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store_options = StoreOptions {
            sync_snapshots_kept: if options.sync_snapshot_blocks > 0 {
                options.sync_snapshots_kept
            } else {
                0
            },
            sync_chunk_bytes: options.sync_chunk_bytes,
            ..StoreOptions::default()
        };
        let engine = Engine::open_with_history(
            Store::open_with_options(database.with_extension("v5state"), store_options)?,
            database.with_extension("history"),
        )?
        .implementing(upgrade.implemented);
        ensure!(
            engine
                .meta()
                .is_none_or(|meta| !meta.genesis.chain_id.starts_with("time-devnet-fixture-")),
            "benchmark fixture databases cannot be opened by the network binary"
        );
        let store = engine.store().clone();
        // What the head already decides: a head this program does not
        // implement, or the height the operator asked to stop after.
        ensure!(
            upgrade.stop_after_height != Some(0),
            "--stop-after-height is at least 1"
        );
        let head = engine.version().map(|version| version.height());
        // How far this node had come is not its newest snapshot: after a
        // start from an older one its state is behind the blocks it has
        // committed, each of which left an entry in the history archive.
        let reached = head.max(engine.history_reached()?);
        // A fix release whose head is past its own rule switch and still
        // under the version before it: the chain went on without the switch.
        // It opens stopped, like a head it does not implement.
        let missed = engine.missed_switch().cloned();
        let stop = match (engine.runnable(), upgrade.stop_after_height, head) {
            (Err(reason), _, _) => Some(StopCause::Upgrade(reason.clone())),
            (Ok(()), _, _) if missed.is_some() => missed.map(StopCause::SwitchMissed),
            (Ok(()), Some(height), _) if reached.is_some_and(|reached| reached > height) => anyhow::bail!(
                "--stop-after-height {height}: this node is already at height {}, above it. Nothing was changed.",
                reached.unwrap_or_default()
            ),
            (Ok(()), Some(height), Some(head)) if head == height => Some(StopCause::Asked { height }),
            _ => None,
        };
        // `--expect-root H:ROOT`: the state the validators agreed to go on
        // from. A node that is past it, or that holds another state there,
        // does not open. (A node below it is checked when it gets there,
        // `try_commit`.) A node that is stopped anyway is not judged: it
        // executes nothing.
        if let (Some((height, root)), None) = (resume.expect_root, &stop) {
            ensure!(height >= 1, "--expect-root names a block height, at least 1");
            if let Some(reached) = reached.filter(|reached| *reached > height) {
                anyhow::bail!(
                    "--expect-root {height}:{}: this node is already at height {reached}, above it. Nothing was changed. The flag is for the one start on the agreed state: start without it to go on.",
                    hex::encode(root)
                );
            }
            if let Some(version) = engine.version().filter(|version| version.height() == height && version.root() != root) {
                anyhow::bail!(
                    "--expect-root {height}:{}: the state of this node at height {height} has the root {}. Nothing was changed. This node does not hold the state the validators agreed on: do not start it as a validator. Compare the root with the other operators again, and read docs/emergency-fix.md.",
                    hex::encode(root),
                    hex::encode(version.root())
                );
            }
        }
        Ok(Self {
            shared: Arc::new(Shared {
                engine: RwLock::new(engine),
                store,
                executed: Mutex::new(Vec::new()),
                check: Mutex::new(None),
                faulted: AtomicBool::new(false),
                executed_blocks: AtomicU64::new(0),
                reused_executions: AtomicU64::new(0),
                clock,
                options,
                restore: Mutex::new(None),
                sync_due: Mutex::new(None),
                stop_after_height: upgrade.stop_after_height,
                expect_root: resume.expect_root,
                stopped: AtomicBool::new(stop.is_some()),
                // Nothing is being answered: the stop can be acted on at once.
                stop_ready: AtomicBool::new(stop.is_some()),
                stop_flushed: AtomicBool::new(false),
                stop: Mutex::new(stop),
                stop_answering: Mutex::new(None),
                executing: AtomicBool::new(false),
                refused_chunks: Mutex::new(LogLimiter::default()),
            }),
        })
    }
    fn healthy(&self) -> Result<()> {
        ensure!(
            !self.shared.faulted.load(Ordering::Acquire),
            "application faulted; restart and inspect"
        );
        Ok(())
    }
    fn engine(&self) -> Result<RwLockReadGuard<'_, Engine>> {
        self.healthy()?;
        self.shared
            .engine
            .read()
            .map_err(|_| anyhow!("application lock poisoned"))
    }
    fn engine_mut(&self) -> Result<RwLockWriteGuard<'_, Engine>> {
        self.healthy()?;
        self.shared
            .engine
            .write()
            .map_err(|_| anyhow!("application lock poisoned"))
    }
    fn executed(&self) -> Result<MutexGuard<'_, Vec<Executed>>> {
        self.healthy()?;
        self.shared
            .executed
            .lock()
            .map_err(|_| anyhow!("application lock poisoned"))
    }
    fn abort<T>(&self, error: anyhow::Error) -> T {
        self.shared.faulted.store(true, Ordering::Release);
        panic!("ABCI v5 failed closed: {error:#}")
    }
    /// Why the node has stopped at a height on purpose, if it has. The node
    /// binary then saves the state, prints the cause and ends with
    /// `EXIT_STOPPED`.
    pub fn stop(&self) -> Option<StopCause> {
        if !self.stopped() {
            return None;
        }
        self.shared.stop.lock().ok().and_then(|stop| stop.clone())
    }
    /// The node has stopped (`stop`): it answers no consensus request and
    /// admits no transaction.
    pub fn stopped(&self) -> bool {
        self.shared.stopped.load(Ordering::Acquire)
    }
    /// The answer to the `Commit` the node stopped after has been written to
    /// the consensus engine, or the node stopped without one in progress.
    /// The node binary waits for this before it saves and ends, so that the
    /// consensus engine has the answer to the last block.
    pub fn stop_ready(&self) -> bool {
        self.stopped() && self.shared.stop_ready.load(Ordering::Acquire)
    }
    /// The versions of the rules this program implements.
    pub fn implemented(&self) -> Result<Arc<Versions>> {
        Ok(self.engine()?.implemented().clone())
    }
    /// Stops the node. The first cause stays.
    fn set_stop(&self, cause: StopCause, answering: bool) {
        let Ok(mut stop) = self.shared.stop.lock() else {
            return;
        };
        if stop.is_some() {
            return;
        }
        *stop = Some(cause);
        if answering {
            if let Ok(mut thread) = self.shared.stop_answering.lock() {
                *thread = Some(std::thread::current().id());
            }
        } else {
            self.shared.stop_ready.store(true, Ordering::Release);
        }
        self.shared.stopped.store(true, Ordering::Release);
    }
    /// After a block is committed or a state restored: stops the node if its
    /// head is one this program does not implement, or the height the
    /// operator asked to stop after. `answering` says that the caller's
    /// answer (to `Commit`) is still to be written.
    fn stop_if_due(&self, answering: bool) -> Result<()> {
        let cause = {
            let engine = self.engine()?;
            let head = engine.version().map(|version| version.height());
            match (engine.runnable(), self.shared.stop_after_height, head) {
                (Err(reason), _, _) => Some(StopCause::Upgrade(reason.clone())),
                (Ok(()), Some(height), Some(head)) if head >= height => Some(StopCause::Asked { height }),
                _ => None,
            }
        };
        if let Some(cause) = cause {
            self.set_stop(cause, answering);
        }
        Ok(())
    }
    /// A consensus request that is not answered: the thread serving it waits
    /// until the process ends. An application that neither accepts nor
    /// rejects cannot be counted either way, and the consensus engine signs
    /// nothing meanwhile.
    fn withhold<T>(&self) -> T {
        // If this is the thread that answered the `Commit` the node stopped
        // after, it writes nothing more: the node need not wait for it.
        if self.answering() {
            self.shared.stop_ready.store(true, Ordering::Release);
        }
        loop {
            std::thread::park();
        }
    }
    /// Whether this thread is the one answering the request the node
    /// stopped after.
    fn answering(&self) -> bool {
        self.shared
            .stop_answering
            .lock()
            .is_ok_and(|thread| *thread == Some(std::thread::current().id()))
    }
    /// What this node knows about a coming upgrade.
    pub fn upgrade_status(&self) -> Result<Option<UpgradeStatus>> {
        let engine = self.engine()?;
        let Some(meta) = engine.meta() else {
            return Ok(None);
        };
        // On a head this program cannot read, nothing more is known.
        let scheduled = if engine.runnable().is_ok() {
            engine.upgrade_state()?.and_then(|state| state.plan)
        } else {
            None
        };
        Ok(Some(UpgradeStatus {
            version: meta.protocol_version,
            elapsed_micros: meta.elapsed_micros()?,
            implements_scheduled: scheduled
                .as_ref()
                .map(|plan| engine.implemented().implements(plan.version, &plan.spec)),
            scheduled,
        }))
    }
    pub fn stats(&self) -> Stats {
        Stats {
            executed_blocks: self.shared.executed_blocks.load(Ordering::Relaxed),
            reused_executions: self.shared.reused_executions.load(Ordering::Relaxed),
        }
    }
    /// Height and root of the committed head, if initialized.
    pub fn head(&self) -> Result<Option<(u64, [u8; 32])>> {
        Ok(self
            .engine()?
            .version()
            .map(|version| (version.height(), version.root())))
    }
    /// Writes a snapshot of the committed head unless one exists for it.
    /// Block execution is not blocked while the file is written.
    pub fn snapshot(&self) -> Result<Option<SnapshotInfo>> {
        self.healthy()?;
        let Some(version) = self.shared.store.current()? else {
            return Ok(None);
        };
        if self.shared.store.snapshot_height()? == Some(version.height()) {
            return Ok(None);
        }
        Ok(Some(self.shared.store.write_snapshot(&version)?))
    }
    /// Writes the snapshot for peers that the last `Commit` at a multiple of
    /// `sync_snapshot_blocks` asked for, if one is waiting. Block execution
    /// is not blocked while the file is written. When blocks arrive faster
    /// than snapshots can be written (a node catching up), only the newest
    /// height that is due is written.
    pub fn write_sync_snapshot(&self) -> Result<Option<SnapshotInfo>> {
        self.healthy()?;
        let due = self
            .shared
            .sync_due
            .lock()
            .map_err(|_| anyhow!("application lock poisoned"))?
            .take();
        match due {
            Some(version) => self.shared.store.write_sync_snapshot(&version),
            None => Ok(None),
        }
    }
    /// What the `retain_height` of the next `Commit` answer is computed from.
    pub fn retain_inputs(&self) -> Result<RetainInputs> {
        let engine = self.engine()?;
        let meta = engine.meta().context("uninitialized chain")?;
        Ok(RetainInputs {
            keep_blocks: self.shared.options.keep_blocks,
            head: u64::try_from(meta.height)?,
            oldest_snapshot: self.shared.store.oldest_snapshot_height(),
            oldest_sync_snapshot: self.shared.store.oldest_sync_snapshot_height()?,
            older_than_evidence_time: meta.history_pruned_through,
        })
    }
    pub fn try_init(&self, request: RequestInitChain) -> Result<ResponseInitChain> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST
                && request.validators.len() <= ledger::MAX_OPERATORS,
            "genesis request budget"
        );
        ensure!(
            matches!(request.initial_height, 0 | 1),
            "initial height must be one"
        );
        ensure!(
            !request.app_state_bytes.is_empty() && request.app_state_bytes.len() <= 1024 * 1024,
            "genesis byte budget"
        );
        let genesis: Genesis = serde_json::from_slice(&request.app_state_bytes)?;
        ensure!(
            genesis.ledger.chain_id == request.chain_id
                && genesis.ledger.genesis_time_micros == time(request.time.as_ref())?,
            "genesis chain/time mismatch"
        );
        ensure!(
            !genesis.ledger.chain_id.starts_with("time-devnet-fixture-"),
            "benchmark fixture chains cannot run ABCI"
        );
        genesis.validate()?;
        {
            ensure!(
                !request.validators.is_empty()
                    && request.validators.len() == genesis.validators.len(),
                "operator/validator roster mismatch"
            );
            let mut seen = BTreeSet::new();
            for v in &request.validators {
                let key = match v.pub_key.as_ref().and_then(|k| k.sum.as_ref()) {
                    Some(tendermint_proto::crypto::public_key::Sum::Ed25519(k)) => hex::encode(k),
                    _ => return Err(anyhow!("unsupported validator key")),
                };
                let _op = genesis
                    .validators
                    .iter()
                    .find(|o| o.consensus_key == key)
                    .ok_or_else(|| anyhow!("unknown consensus key"))?;
                ensure!(
                    v.power > 0
                        && u64::try_from(v.power)? == genesis.profile.genesis_power()
                        && seen.insert(key),
                    "invalid validator authority/power"
                );
            }
        }
        let (head, version) = {
            let mut engine = self.engine_mut()?;
            let head = engine.initialize(genesis)?;
            let version = engine
                .meta()
                .context("uninitialized chain")?
                .protocol_version;
            (head, version)
        };
        // Persist genesis at once: a restart then never depends on InitChain
        // being replayed.
        self.snapshot()?;
        Ok(ResponseInitChain {
            app_hash: head.root.to_vec().into(),
            consensus_params: Some(consensus_params(version)),
            ..Default::default()
        })
    }
    /// What a node says when a decided block failed a check of this program
    /// and it is about to fail closed, in the middle of that block: two
    /// lines, `FAILED_BLOCK_LINE` and then, on one line, the block (height
    /// and hash), why, and the state the node is left at (height and root).
    ///
    /// Every validator that fails on the same block prints the same four
    /// values. They are what the operators compare before anything else, and
    /// what a fix release that repairs the block is built with
    /// (`rules::SwitchAt::Block`).
    pub fn failed_block_report(&self, height: i64, block_hash: &[u8], error: &anyhow::Error) -> String {
        let head = self
            .shared
            .engine
            .read()
            .ok()
            .and_then(|engine| engine.version().map(|version| (version.height(), version.root())));
        let state = head.map_or_else(
            || "The node holds no state yet.".to_string(),
            |(at, root)| {
                format!(
                    "The state of this node is at height {at} with the root {}, and nothing of block {height} is in it.",
                    hex::encode(root)
                )
            },
        );
        let why = format!("{error:#}").replace(['\r', '\n'], " ");
        format!(
            "{FAILED_BLOCK_LINE}\nThe decided block {height} (hash {}) failed a check of this program and was not executed: {why}. {state} The consensus engine keeps the block and hands it over again at every start, so this program fails on it again: do not restart it in a loop. Compare the height, the block hash and the root with the other validators. Delete nothing, roll nothing back, and leave the signer's record of what it signed as it is (docs/emergency-fix.md).",
            hex::encode(block_hash)
        )
    }
    /// What this program holds a proposed or decided block to be, where
    /// rule switches are concerned, before anything of it is executed
    /// (`upgrade::judge`).
    fn switch_verdict<T: AsRef<[u8]>>(&self, height: i64, hash: &[u8], txs: &[T]) -> Result<upgrade::Verdict> {
        let engine = self.engine()?;
        let head = engine.meta().zip(engine.version().map(|version| version.root()));
        Ok(upgrade::judge(engine.implemented(), head, height, hash, txs))
    }
    /// REHEARSAL BUILDS ONLY: the deliberately faulty rule, for rehearsing a
    /// stop in the middle of a block. A decided block that carries a payment
    /// of exactly `rules::REHEARSAL_FAULT_MICROS` fails its check here, on
    /// every node alike, although every node accepted it as a proposal. The
    /// fault is corrected by the rehearsal version: it is gone once that
    /// version is in force, and in the one block a fix release repairs into
    /// it. No release build contains this function.
    #[cfg(feature = "rehearsal-v5")]
    fn rehearsal_fault(&self, request: &RequestFinalizeBlock) -> Result<()> {
        use timecurrency_node::ledger::ActionPayload;
        let engine = self.engine()?;
        let Some(meta) = engine.meta() else {
            return Ok(());
        };
        // A committed block handed over again is not executed again.
        if request.height <= meta.height {
            return Ok(());
        }
        if crate::rules::Rules::of(meta).since(crate::rules::REHEARSAL_VERSION) {
            return Ok(());
        }
        // The block a fix release repairs (or its switch block): the fix is in force for it.
        let hash: [u8; 32] = request.hash.as_ref().try_into().unwrap_or([0; 32]);
        if matches!(engine.switch_block(u64::try_from(request.height)?, hash), Ok(Some(_))) {
            return Ok(());
        }
        let faulty = request.txs.iter().any(|tx| {
            matches!(
                ledger::decode_action(tx).map(|action| action.payload),
                Ok(ActionPayload::Transfer(transfer)) if transfer.amount == crate::rules::REHEARSAL_FAULT_MICROS
            )
        });
        ensure!(
            !faulty,
            "REHEARSAL FAULT: this rehearsal program cannot finalize a block that carries a payment of exactly {} microseconds. It is a deliberate fault, for rehearsing a stop in the middle of a block",
            crate::rules::REHEARSAL_FAULT_MICROS
        );
        Ok(())
    }
    pub fn try_finalize(&self, request: RequestFinalizeBlock) -> Result<ResponseFinalizeBlock> {
        // A decided block that carries the reserved kind 81 is a rule switch
        // this program does not implement. Nothing of it is executed: the
        // node stops with its head at the block before, and the consensus
        // engine, which keeps the block, hands it to the program that is
        // installed next. This comes before every other judgement of the
        // block, its size and count budgets included: whatever else such a
        // block is, this program stops on purpose and does not fail. (A
        // proposal that carries it is only rejected, `process`: one proposer
        // must not be able to stop every node.)
        //
        // A fix release executes one block that carries kind 81: its own
        // switch block, which is that one transaction and nothing else
        // (`upgrade::judge`). A decided block at that height that is anything
        // else is not executed either, and stops the node the same way: the
        // chain did not stop where the fix was agreed.
        match self.switch_verdict(request.height, &request.hash, &request.txs)? {
            upgrade::Verdict::Ordinary | upgrade::Verdict::Switch => {}
            upgrade::Verdict::Foreign => {
                let height = u64::try_from(request.height.max(0))?;
                self.set_stop(StopCause::Switch { height }, false);
                anyhow::bail!("stopped at a rule switch in block {height}");
            }
            upgrade::Verdict::NotTheSwitch(found) => {
                let height = u64::try_from(request.height.max(0))?;
                self.set_stop(StopCause::SwitchExpected { height, found }, false);
                anyhow::bail!("stopped at block {height}, which is not the switch block of this fix release");
            }
        }
        #[cfg(feature = "rehearsal-v5")]
        self.rehearsal_fault(&request)?;
        ensure!(
            request.encoded_len() <= MAX_REQUEST && request.hash.len() == 32,
            "invalid finalized request"
        );
        validate_block_transactions(&request.txs)?;
        let timestamp = time(request.time.as_ref())?;
        let fingerprint: [u8; 32] = Sha256::digest(request.encode_to_vec()).into();
        let block_hash: [u8; 32] = request.hash.as_ref().try_into()?;
        // From its first decided block on, this process restores no snapshot.
        self.shared.executing.store(true, Ordering::Release);
        let mut executed = self.executed()?;
        // A FinalizeBlock repeated before Commit must be the same request.
        if let Some(done) = executed.iter().find(|entry| entry.finalized.is_some()) {
            ensure!(
                done.finalized == Some(fingerprint),
                "different finalize before commit"
            );
            return Ok(done.response.clone());
        }
        let engine = self.engine()?;
        let version = engine.meta().map_or(4, |meta| meta.protocol_version);
        let head = engine
            .version()
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        if request.height > 0 && u64::try_from(request.height)? == head.height() {
            // The committed block again, after a restart on the consensus side.
            ensure!(
                head.head().request_fingerprint == fingerprint,
                "conflicting finalized replay"
            );
            let key = [b"pos/updates/".as_slice(), &head.height().to_be_bytes()].concat();
            let updates: Vec<pos::Validator> = canonical_decode(
                &head
                    .get(&key)
                    .ok_or_else(|| anyhow!("missing durable validator response"))?,
            )?;
            return response(head.root(), request.txs.len(), version, &updates);
        }
        let roster = engine.active_roster_at(u64::try_from(request.height)?.saturating_sub(1))?;
        let keys = eligible(
            &roster,
            request
                .decided_last_commit
                .iter()
                .flat_map(|c| &c.votes)
                .map(|v| (v.validator.clone(), v.block_id_flag)),
        )?;
        let key = ExecKey {
            height: request.height,
            time_micros: timestamp,
            block_hash,
            eligible: keys,
            txs_digest: txs_digest(&request.txs),
            misbehavior_digest: misbehavior_digest(&request.misbehavior),
            proposer: request.proposer_address.to_vec(),
        };
        // Already executed while validating the proposal: every input matches.
        if let Some(index) = executed.iter().position(|entry| entry.key == key) {
            let mut entry = executed.swap_remove(index);
            entry.finalized = Some(fingerprint);
            let result = entry.response.clone();
            executed.clear();
            executed.push(entry);
            self.shared.reused_executions.fetch_add(1, Ordering::Relaxed);
            return Ok(result);
        }
        // A block this node did not validate (a replay, block sync, a round
        // it missed): executed here with the same inputs, misbehavior
        // included, and never compared with the clock.
        self.shared.executed_blocks.fetch_add(1, Ordering::Relaxed);
        let prepared = engine.prepare_proposed(
            request.height,
            timestamp,
            &request.txs,
            &key.eligible,
            block_hash,
            &reported(&request.misbehavior),
            &key.proposer,
        )?;
        let result = response(
            prepared.root,
            prepared.txcount,
            prepared.meta.protocol_version,
            &prepared.validator_updates,
        )?;
        executed.clear();
        executed.push(Executed {
            key,
            prepared,
            response: result.clone(),
            finalized: Some(fingerprint),
        });
        Ok(result)
    }
    pub fn try_commit(&self) -> Result<ResponseCommit> {
        let mut executed = self.executed()?;
        ensure!(self.engine()?.meta().is_some(), "uninitialized chain");
        let finalized = executed
            .iter()
            .position(|entry| entry.finalized.is_some())
            .map(|index| executed.swap_remove(index));
        executed.clear();
        if let Some(mut entry) = finalized {
            self.shared.executing.store(true, Ordering::Release);
            let fingerprint = entry.finalized.unwrap_or_default();
            let events = std::mem::take(&mut entry.prepared.upgrade_events);
            // For the log: this block's time, and how long a plan may wait
            // after its start time on this network.
            let at = entry.prepared.meta.elapsed_micros().unwrap_or(0);
            let wait = upgrade::Params::of(entry.prepared.meta.config.profile).late;
            // The block's history entry is written and synced to disk under
            // the shared lock, so queries and mempool checks are not held up
            // by the disk. Only the swap of the head is exclusive. `executed`
            // stays locked throughout: no other commit can run in between.
            let persisted = self.engine()?.persist_history(&mut entry.prepared);
            let committed = persisted.and_then(|()| {
                self.engine_mut()?
                    .commit(entry.prepared, fingerprint)
                    .map(|_| ())
            });
            if let Err(error) = committed {
                self.shared.faulted.store(true, Ordering::Release);
                return Err(error);
            }
            // `--expect-root H:ROOT`: a node opened below H has now reached
            // it. With another root there it goes no further and answers
            // nothing more: it fails closed, and the consensus engine ends
            // without the answer to this Commit.
            if let Some((height, root)) = self.shared.expect_root {
                let head = self.engine()?.version().map(|version| (version.height(), version.root()));
                if let Some((_, own)) = head.filter(|(at, own)| *at == height && *own != root) {
                    self.shared.faulted.store(true, Ordering::Release);
                    anyhow::bail!(
                        "--expect-root {height}:{}: the state of this node at height {height} has the root {}. It executes nothing after that block. This node does not hold the state the validators agreed on: do not start it as a validator, compare the root with the other operators again, and read docs/emergency-fix.md",
                        hex::encode(root),
                        hex::encode(own)
                    );
                }
            }
            for event in &events {
                eprintln!("{}", describe_event(event, at, wait));
            }
            // A snapshot for peers is due at heights every node agrees on,
            // so that all of them offer the same one. The version is only
            // remembered here; the snapshot thread writes it.
            let every = self.shared.options.sync_snapshot_blocks;
            if every > 0 {
                let version = self.engine()?.version().cloned();
                if let Some(version) = version.filter(|version| version.height() % every == 0) {
                    *self
                        .shared
                        .sync_due
                        .lock()
                        .map_err(|_| anyhow!("application lock poisoned"))? = Some(version);
                }
            }
        }
        drop(executed);
        // The head may be one this program does not implement, or the height
        // the operator asked to stop after. From here on the node answers no
        // consensus request; this answer, to the Commit in progress, is the
        // last one.
        self.stop_if_due(true)?;
        // 0 unless the operator asked for pruning: CometBFT then keeps every
        // block. Otherwise the highest height that leaves what this node,
        // evidence and the peers it offers snapshots to still need.
        let retain = if self.shared.options.keep_blocks == 0 {
            0
        } else {
            statesync::retain_height(&self.retain_inputs()?)
        };
        Ok(ResponseCommit {
            retain_height: i64::try_from(retain)?,
        })
    }
    fn prepare(&self, request: RequestPrepareProposal) -> Result<ResponsePrepareProposal> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST && request.max_tx_bytes >= 0,
            "proposal budget"
        );
        let timestamp = time(request.time.as_ref())?;
        let engine = self.engine()?;
        // A fix release, at the height of its own switch block. At an agreed
        // height the engine proposes the switch itself, below. Where the
        // program repairs a block that was decided already, or where the
        // chain is not as the program was built to find it, there is nothing
        // this node can propose that it would accept: it proposes an empty
        // block, executes nothing, and will reject that block like every
        // other at this height.
        if engine.meta().is_some()
            && !matches!(
                engine.switch_block(u64::try_from(request.height)?, [0; 32]),
                Ok(None) | Ok(Some(upgrade::SwitchBlock { action: Some(_), .. }))
            )
        {
            eprintln!(
                "Proposing an empty block for height {}: it is the height of this fix release's switch block, and no proposal of this node can be that block.",
                request.height
            );
            return Ok(ResponsePrepareProposal { txs: Vec::new() });
        }
        let roster = engine.active_roster_at(u64::try_from(request.height)?.saturating_sub(1))?;
        let keys = eligible(
            &roster,
            request
                .local_last_commit
                .iter()
                .flat_map(|c| &c.votes)
                .map(|v| (v.validator.clone(), v.block_id_flag)),
        )?;
        let budget = usize::try_from(request.max_tx_bytes)?.min(MAX_BLOCK_TX_BYTES);
        // The block will carry this misbehavior, and validators will apply it
        // before the transactions: they are selected on that state. (No
        // clock check here: the proposer does not choose the block time.)
        let misbehavior = reported(&request.misbehavior);
        let accepted = match engine.prepare_filtered_proposed(
            request.height,
            timestamp,
            &request.txs,
            &keys,
            budget,
            [0; 32],
            &misbehavior,
            &request.proposer_address,
        ) {
            Ok((_, accepted)) => accepted,
            Err(error) => {
                // Transactions that pass one by one but cannot be finished as
                // a block must not stop the proposer. Propose an empty block;
                // if even that cannot be built, the state itself is broken
                // and the error is fatal.
                eprintln!("Proposal with mempool transactions failed, proposing empty: {error:#}");
                let none: [Vec<u8>; 0] = [];
                engine.prepare_filtered_proposed(
                    request.height,
                    timestamp,
                    &none,
                    &keys,
                    budget,
                    [0; 32],
                    &misbehavior,
                    &request.proposer_address,
                )?;
                Vec::new()
            }
        };
        Ok(ResponsePrepareProposal {
            txs: accepted.into_iter().map(Into::into).collect(),
        })
    }
    /// Mempool admission for a run of transactions, in request order.
    fn admit(&self, requests: &[RequestCheckTx]) -> Result<Vec<Result<()>>> {
        // Stateless signature checks first, on all cores, without any lock.
        let signatures = self.engine()?.signatures().clone();
        let statuses: Vec<SigStatus> = requests
            .par_iter()
            .map(|request| signatures.check(&request.tx))
            .collect();
        // Then the accounts that the correctly signed transactions will read,
        // also on all cores. Unsigned input makes the node load nothing.
        {
            let signed: Vec<&[u8]> = requests
                .iter()
                .zip(&statuses)
                .filter(|(_, status)| **status == SigStatus::Valid)
                .map(|(request, _)| request.tx.as_ref())
                .collect();
            self.engine()?.preload(&signed);
        }
        // Then admission on the pending state, one at a time and in order.
        let mut check = self
            .shared
            .check
            .lock()
            .map_err(|_| anyhow!("application lock poisoned"))?;
        let engine = self.engine()?;
        let head = engine
            .version()
            .ok_or_else(|| anyhow!("uninitialized chain"))?
            .height();
        let state = match &mut *check {
            Some(state) if state.base_height() == head && state.rows() <= CHECK_STATE_ROW_LIMIT => {
                state
            }
            // A block was committed since (or the state outgrew its bound):
            // start again from the head.
            stale => stale.insert(engine.check_state()?),
        };
        Ok(requests
            .iter()
            .zip(statuses)
            .map(|(request, status)| {
                ensure!(
                    request.encoded_len() <= MAX_REQUEST,
                    "transaction request budget"
                );
                state.admit(&request.tx, status)
            })
            .collect())
    }
}
/// State sync, the restoring side. See `crate::statesync` for what is
/// trusted and what is bounded.
impl App {
    fn restore_slot(&self) -> Result<MutexGuard<'_, Option<Restore>>> {
        self.shared
            .restore
            .lock()
            .map_err(|_| anyhow!("application lock poisoned"))
    }
    /// Judges a snapshot CometBFT offers, on what the offer itself says.
    /// Accepting only opens the staging file; the node's state changes when
    /// the last chunk has been verified, or never.
    fn offer(&self, request: RequestOfferSnapshot) -> response_offer_snapshot::Result {
        use response_offer_snapshot::Result as Offer;
        // A stopped node keeps the state it stopped on.
        if self.healthy().is_err() || self.stopped() {
            return Offer::Abort;
        }
        // CometBFT restores one snapshot at a time: a new offer, accepted
        // or not, means it has given up the one before.
        let Ok(mut slot) = self.restore_slot() else {
            return Offer::Abort;
        };
        if let Some(previous) = slot.take() {
            previous.discard();
        }
        if self.shared.executing.load(Ordering::Acquire) {
            eprintln!(
                "State sync: a snapshot was offered to a node that is executing blocks; refused. A node restores only before its first block: restart it to state-sync."
            );
            return Offer::Abort;
        }
        let Some(snapshot) = request.snapshot else {
            return Offer::Reject;
        };
        if snapshot.format != SYNC_FORMAT {
            return Offer::RejectFormat;
        }
        // The trusted hash and the height come from this node's own CometBFT.
        let Ok(app_hash) = <[u8; 32]>::try_from(request.app_hash.as_ref()) else {
            eprintln!("State sync: the offered application hash is not 32 bytes.");
            return Offer::Reject;
        };
        if snapshot.height == 0 || snapshot.height > i64::MAX as u64 {
            return Offer::Reject;
        }
        // Everything else in the offer is a peer's claim. A snapshot of this
        // format whose metadata is not exactly what this engine writes, or
        // whose hash or chunk count disagree with it, was not made by an
        // honest node of this engine.
        let manifest = match Manifest::decode(&snapshot.metadata) {
            Ok(manifest)
                if manifest.chunks() == snapshot.chunks
                    && snapshot.hash[..] == statesync::metadata_hash(&snapshot.metadata)[..] =>
            {
                manifest
            }
            Ok(_) => {
                eprintln!(
                    "State sync: snapshot {} rejected with its senders: hash or chunk count disagree with its metadata.",
                    snapshot.height
                );
                return Offer::RejectSender;
            }
            Err(error) => {
                eprintln!(
                    "State sync: snapshot {} rejected with its senders: {error:#}",
                    snapshot.height
                );
                return Offer::RejectSender;
            }
        };
        if manifest.total_bytes > self.shared.options.restore_max_bytes {
            eprintln!(
                "State sync: snapshot {} is {} bytes, more than this node restores ({} bytes, --state-sync-max-mib).",
                snapshot.height, manifest.total_bytes, self.shared.options.restore_max_bytes
            );
            return Offer::Reject;
        }
        let held = match self.head() {
            Ok(head) => head,
            Err(_) => return Offer::Abort,
        };
        // The node holds exactly this state already: a restore that its
        // CometBFT did not live to record. It is accepted again; the chunks
        // are taken and checked as always, and at the end nothing needs to
        // be installed (`finish_restore`).
        let already_held = held == Some((snapshot.height, app_hash));
        if !already_held {
            if let Some((height, _)) = held.filter(|(height, _)| *height >= snapshot.height) {
                eprintln!(
                    "State sync: snapshot {} refused, this node already holds height {height} with another hash or a later height. A node restores only a later state than its own.",
                    snapshot.height
                );
                return Offer::Reject;
            }
            // A node that built its state by executing blocks keeps it.
            let restorable = match self.engine() {
                Ok(engine) => engine.restorable(),
                Err(_) => return Offer::Abort,
            };
            if let Err(error) = restorable {
                eprintln!("State sync: snapshot {} refused: {error:#}", snapshot.height);
                return Offer::Abort;
            }
        }
        // A node told to stop after a height restores nothing beyond it.
        if let Some(height) = self.shared.stop_after_height
            && snapshot.height > height
        {
            eprintln!(
                "State sync: snapshot {} refused, this node was started with --stop-after-height {height}.",
                snapshot.height
            );
            return Offer::Reject;
        }
        match Restore::begin(self.shared.store.restore_path(), snapshot.height, app_hash, manifest) {
            Ok(restore) => {
                eprintln!(
                    "State sync: restoring snapshot {} ({} chunks).",
                    snapshot.height, snapshot.chunks
                );
                *slot = Some(restore);
                Offer::Accept
            }
            Err(error) => {
                eprintln!("State sync: cannot stage a snapshot: {error:#}");
                Offer::Abort
            }
        }
    }
    /// Takes one chunk of the accepted snapshot. The last chunk verifies the
    /// whole snapshot and, only if its rows hash to the trusted application
    /// hash, replaces the node's state.
    fn apply_chunk(&self, request: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        use response_apply_snapshot_chunk::Result as Applied;
        let answer = |result: Applied, refetch: Vec<u32>, reject: Vec<String>| {
            ResponseApplySnapshotChunk {
                result: result as i32,
                refetch_chunks: refetch,
                reject_senders: reject.into_iter().filter(|sender| !sender.is_empty()).collect(),
            }
        };
        if self.healthy().is_err() || self.stopped() {
            return answer(Applied::Abort, vec![], vec![]);
        }
        let Ok(mut slot) = self.restore_slot() else {
            return answer(Applied::Abort, vec![], vec![]);
        };
        if self.shared.executing.load(Ordering::Acquire) {
            // Blocks are being executed: whatever restore was open is over.
            if let Some(restore) = slot.take() {
                restore.discard();
            }
            return answer(Applied::Abort, vec![], vec![]);
        }
        let Some(restore) = slot.as_mut() else {
            // No offer was accepted: there is nothing to apply a chunk to.
            return answer(Applied::Abort, vec![], vec![]);
        };
        let outcome = restore.apply(request.index, &request.chunk, &request.sender);
        // A peer's name in a log line is cut to the length of a node id.
        let named: String = request.sender.chars().take(40).collect();
        match outcome {
            Ok(Chunk::Stored) => answer(Applied::Accept, vec![], vec![]),
            Ok(Chunk::Corrupt) => {
                // One peer can repeat this for as long as the sync lasts:
                // the first few are printed, then one line a minute.
                let logged = self
                    .shared
                    .refused_chunks
                    .lock()
                    .map_or(Logged::Nothing, |mut limiter| limiter.note(std::time::Instant::now()));
                match logged {
                    Logged::Full => eprintln!(
                        "State sync: chunk {} from {named:?} is not the chunk the snapshot names; refetching it and rejecting the sender.",
                        request.index
                    ),
                    Logged::Summary(count) => eprintln!(
                        "State sync: {count} more chunk(s) refused and their senders rejected, the latest chunk {} from {named:?}. Such lines are printed at most once a minute from here on.",
                        request.index
                    ),
                    Logged::Nothing => {}
                }
                answer(Applied::Retry, vec![request.index], vec![request.sender])
            }
            Ok(Chunk::OutOfOrder) => {
                // CometBFT applies chunks in order; this restore cannot go
                // on. Nobody's chunk was wrong, so no sender is rejected.
                eprintln!(
                    "State sync: chunk {} arrived where chunk {} was expected; snapshot {} dropped.",
                    request.index,
                    restore.next(),
                    restore.height()
                );
                if let Some(restore) = slot.take() {
                    restore.discard();
                }
                answer(Applied::RejectSnapshot, vec![], vec![])
            }
            Ok(Chunk::WrongSnapshot) => {
                let senders = restore.senders();
                eprintln!(
                    "State sync: snapshot {} does not start with the offered height and trusted hash; rejected with its senders.",
                    restore.height()
                );
                if let Some(restore) = slot.take() {
                    restore.discard();
                }
                answer(Applied::RejectSnapshot, vec![], senders)
            }
            Ok(Chunk::Complete) => match slot.take() {
                Some(restore) => self.finish_restore(restore),
                None => answer(Applied::Abort, vec![], vec![]),
            },
            Err(error) => {
                eprintln!("State sync: cannot write the staging file: {error:#}");
                if let Some(restore) = slot.take() {
                    restore.discard();
                }
                answer(Applied::Abort, vec![], vec![])
            }
        }
    }
    /// All chunks are staged: verify the file and install it.
    fn finish_restore(&self, restore: Restore) -> ResponseApplySnapshotChunk {
        use response_apply_snapshot_chunk::Result as Applied;
        let (height, app_hash, senders) = (restore.height(), restore.app_hash(), restore.senders());
        let staged = restore.close();
        let started = std::time::Instant::now();
        // The node already holds this height with this hash (the offer was
        // accepted for that reason): there is nothing to install, and
        // CometBFT's next question, `Info`, has the answer it expects.
        if self.head().ok().flatten() == Some((height, app_hash)) {
            let _ = std::fs::remove_file(&staged);
            eprintln!("State sync: height {height} with the trusted hash is already held; nothing to restore.");
            return ResponseApplySnapshotChunk {
                result: Applied::Accept as i32,
                refetch_chunks: vec![],
                reject_senders: vec![],
            };
        }
        // No block may be executed or committed while the state is replaced.
        let installed = (|| -> Result<std::result::Result<crate::store::Head, RestoreRefusal>> {
            let mut executed = self.executed()?;
            let mut engine = self.engine_mut()?;
            // Checked under the locks block execution takes: no block can
            // be finalized between this check and the install.
            ensure!(
                !self.shared.executing.load(Ordering::Acquire) && executed.is_empty(),
                "the node is executing blocks"
            );
            let result = engine.restore(&staged, height, app_hash);
            if result.is_ok() {
                executed.clear();
            }
            Ok(result)
        })();
        let (result, senders) = match installed {
            Ok(Ok(head)) => {
                // Mempool admission starts again from the restored head.
                if let Ok(mut check) = self.shared.check.lock() {
                    *check = None;
                }
                eprintln!(
                    "State sync: restored height {} with root {} in {:.1}s. Block history at or below it is not held by this node.",
                    head.version,
                    hex::encode(head.root),
                    started.elapsed().as_secs_f64()
                );
                // The restored head may be the height the operator asked to
                // stop after.
                let _ = self.stop_if_due(true);
                (Applied::Accept, vec![])
            }
            Ok(Err(RestoreRefusal::Snapshot(error))) => {
                eprintln!(
                    "State sync: snapshot {height} rejected with its {} sender(s): {error:#}",
                    senders.len()
                );
                (Applied::RejectSnapshot, senders)
            }
            Ok(Err(RestoreRefusal::Node(error))) => {
                eprintln!("State sync: snapshot {height} is authentic but was not installed: {error:#}");
                (Applied::Abort, vec![])
            }
            Ok(Err(RestoreRefusal::Version(reason))) => {
                let spec = reason.spec.as_deref().map_or_else(String::new, |spec| format!(" (spec {spec})"));
                eprintln!(
                    "State sync: snapshot {height} is authentic, but its state is under protocol version {}{spec}, which this program does not implement: it implements {}. Nothing was installed and the node's state is unchanged. Install a release that implements version {} and state-sync again.",
                    reason.version, reason.implemented, reason.version
                );
                (Applied::Abort, vec![])
            }
            Err(error) => {
                eprintln!("State sync: {error:#}");
                (Applied::Abort, vec![])
            }
        };
        // Installed, the file was moved into place; otherwise it goes.
        let _ = std::fs::remove_file(&staged);
        ResponseApplySnapshotChunk {
            result: result as i32,
            refetch_chunks: vec![],
            reject_senders: senders.into_iter().filter(|sender| !sender.is_empty()).collect(),
        }
    }
}
impl BatchCheck for App {
    /// A consensus engine that connects anew has an empty mempool: admission
    /// starts again from the committed head.
    fn peer_connected(&self) {
        if let Ok(mut check) = self.shared.check.lock() {
            *check = None;
        }
    }
    /// The answers of a batch have been written. If this thread answered
    /// the `Commit` the node stopped after, and the Flush behind it, the
    /// consensus engine now has both and the node may save and end. (A
    /// `Commit` whose Flush arrives in a later batch is not enough: the
    /// consensus engine would lose the answer to its last block.)
    fn answers_written(&self) {
        if !self.stopped() || self.shared.stop_ready.load(Ordering::Acquire) {
            return;
        }
        if self.answering() && self.shared.stop_flushed.load(Ordering::Acquire) {
            self.shared.stop_ready.store(true, Ordering::Release);
        }
    }
    fn check_batch(&self, requests: Vec<RequestCheckTx>) -> Vec<ResponseCheckTx> {
        let rejected = |error: anyhow::Error| ResponseCheckTx {
            code: 1,
            log: error.to_string(),
            ..Default::default()
        };
        // A stopped node admits nothing: it could not execute what it admits.
        if let Some(cause) = self.stop() {
            return requests
                .iter()
                .map(|_| rejected(anyhow!("this node has stopped ({}) and admits no transaction", cause.first_line())))
                .collect();
        }
        match self.admit(&requests) {
            Ok(results) => results
                .into_iter()
                .map(|result| result.map_or_else(rejected, |()| ResponseCheckTx::default()))
                .collect(),
            Err(error) => {
                let message = error.to_string();
                requests
                    .iter()
                    .map(|_| rejected(anyhow!("{message}")))
                    .collect()
            }
        }
    }
}
impl App {
    fn process(&self, request: RequestProcessProposal) -> Result<()> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST && request.hash.len() == 32,
            "proposal budget/hash"
        );
        let timestamp = time(request.time.as_ref())?;
        // A live proposal dated too far ahead of this node's clock is
        // rejected before anything of it is executed or remembered
        // (`open_with_clock`). Rejecting only makes this node prevote nil.
        if let Some(clock) = &self.shared.clock {
            let ahead = timestamp.saturating_sub(micros_since_epoch((clock.now)()));
            if ahead > clock.tolerance_micros {
                eprintln!(
                    "Rejected the proposal for height {} from proposer {}: its block time is {:.3} s ahead of this machine's clock, more than the {:.3} s allowed (--clock-tolerance-seconds). If this repeats, check this machine's time synchronization.",
                    request.height,
                    hex::encode(&request.proposer_address),
                    ahead as f64 / 1e6,
                    clock.tolerance_micros as f64 / 1e6,
                );
                anyhow::bail!("block time ahead of this node's clock");
            }
        }
        // A proposal that carries the reserved kind 81 is rejected, and the
        // node goes on: only a decided block stops it (`try_finalize`). A
        // fix release accepts one such proposal, its own switch block, and at
        // that height rejects every other proposal: as validator it accepts
        // only that block (design, section 10).
        match self.switch_verdict(request.height, &request.hash, &request.txs)? {
            upgrade::Verdict::Ordinary | upgrade::Verdict::Switch => {}
            upgrade::Verdict::Foreign => {
                eprintln!(
                    "Rejected the proposal for height {} from proposer {}: it carries a rule switch (action kind 81), which this program does not implement.",
                    request.height,
                    hex::encode(&request.proposer_address),
                );
                anyhow::bail!("proposal carries a rule switch");
            }
            upgrade::Verdict::NotTheSwitch(found) => {
                eprintln!(
                    "Rejected the proposal for height {} from proposer {}: {found}.",
                    request.height,
                    hex::encode(&request.proposer_address),
                );
                anyhow::bail!("proposal is not the switch block of this fix release");
            }
        }
        let block_hash: [u8; 32] = request.hash.as_ref().try_into()?;
        // A node that judges proposals is in consensus: no restore from here on.
        self.shared.executing.store(true, Ordering::Release);
        let mut executed = self.executed()?;
        let engine = self.engine()?;
        let roster = engine.active_roster_at(u64::try_from(request.height)?.saturating_sub(1))?;
        let keys = eligible(
            &roster,
            request
                .proposed_last_commit
                .iter()
                .flat_map(|c| &c.votes)
                .map(|v| (v.validator.clone(), v.block_id_flag)),
        )?;
        let key = ExecKey {
            height: request.height,
            time_micros: timestamp,
            block_hash,
            eligible: keys,
            txs_digest: txs_digest(&request.txs),
            misbehavior_digest: misbehavior_digest(&request.misbehavior),
            proposer: request.proposer_address.to_vec(),
        };
        // Already executed, in this round or an earlier one. This includes the
        // finalized block itself, which a restarted consensus engine may ask
        // about again before it sends Commit.
        if executed.iter().any(|entry| entry.key == key) {
            return Ok(());
        }
        // A finalized block waiting for Commit is never displaced.
        ensure!(
            executed.iter().all(|entry| entry.finalized.is_none()),
            "proposal while a finalized block awaits commit"
        );
        self.shared.executed_blocks.fetch_add(1, Ordering::Relaxed);
        let prepared = engine.prepare_proposed(
            request.height,
            timestamp,
            &request.txs,
            &key.eligible,
            block_hash,
            &reported(&request.misbehavior),
            &key.proposer,
        )?;
        let result = response(
            prepared.root,
            prepared.txcount,
            prepared.meta.protocol_version,
            &prepared.validator_updates,
        )?;
        executed.retain(|entry| entry.key.height == request.height);
        if executed.len() >= MAX_EXECUTED {
            executed.remove(0);
        }
        executed.push(Executed {
            key,
            prepared,
            response: result,
            finalized: None,
        });
        Ok(())
    }
    /// The field `upgrade` of `/status`. It is not consensus data: it says
    /// what this program implements and what it was told, beside the plan
    /// the state at the queried height holds.
    fn status_upgrade(&self, engine: &Engine, version: &Version) -> serde_json::Value {
        let implemented: Vec<serde_json::Value> = engine
            .implemented()
            .list()
            .iter()
            .map(|entry| json!({"spec": entry.spec, "version": entry.version.to_string()}))
            .collect();
        let scheduled = version
            .get(upgrade::STATE_KEY)
            .and_then(|row| upgrade::State::decode(&row).ok())
            .and_then(|state| state.plan);
        let implements = scheduled
            .as_ref()
            .map(|plan| engine.implemented().implements(plan.version, &plan.spec));
        let mut upgrade = json!({
            "implemented": implemented,
            "scheduled": scheduled,
            "implements_scheduled": implements,
            "stop_after_height": self.shared.stop_after_height.map(|height| height.to_string()),
        });
        // A fix release says which rule switches it carries for this
        // network, so that operators can compare what they run before the
        // agreed height. The field is absent in every other program.
        let network = engine.meta().map(|meta| meta.network_id.as_str());
        let switches: Vec<serde_json::Value> = engine
            .implemented()
            .switches()
            .iter()
            .filter(|switch| Some(switch.network_id.as_str()) == network)
            .map(|switch| {
                let spec = engine.implemented().spec_of(switch.version);
                match &switch.at {
                    crate::rules::SwitchAt::After { height } => json!({"version": switch.version.to_string(), "spec": spec, "after_height": height.to_string(), "block_height": switch.block_height().to_string()}),
                    crate::rules::SwitchAt::Block { height, block_hash, parent_root } => json!({"version": switch.version.to_string(), "spec": spec, "block_height": height.to_string(), "block_hash": block_hash, "parent_root": parent_root}),
                }
            })
            .collect();
        if !switches.is_empty() {
            upgrade["switches"] = switches.into();
        }
        // The state an operator told this node to go on from, if any.
        if let Some((height, root)) = self.shared.expect_root {
            upgrade["expect_root"] = format!("{height}:{}", hex::encode(root)).into();
        }
        upgrade
    }
    fn query_value(&self, request: RequestQuery) -> Result<(i64, Vec<u8>)> {
        ensure!(
            !request.prove && request.data.len() <= MAX_QUERY && request.height >= 0,
            "use bounded custom proof queries"
        );
        let engine = self.engine()?;
        let current = engine
            .version()
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        let height = if request.height == 0 {
            current.height()
        } else {
            u64::try_from(request.height)?
        };
        let version = engine.store().version(height)?;
        let value = match request.path.as_str() {
            "/status" => {
                // The version of the rules in force at the height asked for. At the head it is the
                // engine's own; at an earlier height the two differ across an activation.
                let app_version = version
                    .get(crate::engine::META_KEY)
                    .and_then(|row| crate::engine::peek_version(&row))
                    .or_else(|| engine.meta().map(|meta| meta.protocol_version))
                    .map(|number| number.to_string());
                let mut status = json!({"mode":"devnet","app_version":app_version,"engine":"v5","public_launch_allowed":false,"authenticated":false,"height":version.height().to_string(),"root":hex::encode(version.root()),"state_storage":"memory-merkle-with-snapshots","proofs":"compact-account-membership-and-absence","global_supply_audit":"separate-full-tree-and-semantic-audit","maintenance":{"pressure":false,"eligible_work_pending":false,"snapshot_height":engine.store().snapshot_height()?.map(|h|h.to_string()),"oldest_queryable_version":engine.store().oldest_retained()?.map(|h|h.to_string())}});
                status["upgrade"] = self.status_upgrade(&engine, &version);
                status
            }
            "/compact-proof" => {
                let raw: Vec<String> = serde_json::from_slice(&request.data)?;
                ensure!(!raw.is_empty() && raw.len() <= 32, "proof key budget");
                let keys = raw
                    .into_iter()
                    .map(|s| hex::decode(s).map_err(Into::into))
                    .collect::<Result<Vec<_>>>()?;
                let bundle = version.proof_bundle(&keys)?;
                json!({"height":height.to_string(),"root":hex::encode(version.root()),"entries":bundle.entries})
            }
            "/v4/state" => {
                let selection: Selection = serde_json::from_slice(&request.data)?;
                view(&version, selection, &engine)?
            }
            _ => {
                return Err(anyhow!(
                    "unsupported v4 query; use bounded authenticated selections"
                ));
            }
        };
        let encoded = serde_json::to_vec(&value)?;
        ensure!(
            encoded.len() <= MAX_PROOF_RESPONSE,
            "proof response byte budget"
        );
        Ok((i64::try_from(height)?, encoded))
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    public_keys: Vec<String>,
    #[serde(default)]
    owners: Vec<String>,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    epochs: Vec<String>,
    #[serde(default)]
    blocks: Vec<String>,
    #[serde(default)]
    include_pos: bool,
    #[serde(default)]
    include_bitcoin: bool,
    #[serde(default)]
    include_policy: bool,
    /// Also prove the security row (`crate::security`) of each account asked
    /// for by name, id or key, or that it has none.
    #[serde(default)]
    include_security: bool,
    /// Also prove the row `upgrade/state` (the scheduled plan and the
    /// signals), or that it is absent. A wallet reads a coming upgrade from
    /// this proof, never from a node's word.
    #[serde(default)]
    include_upgrade: bool,
}
fn canonical_id(s: &str) -> Result<u64> {
    ensure!(
        !s.is_empty() && (s == "0" || !s.starts_with('0')) && s.bytes().all(|c| c.is_ascii_digit()),
        "noncanonical account ID"
    );
    Ok(s.parse()?)
}
fn add(
    version: &Version,
    entries: &mut BTreeMap<Vec<u8>, ProofEntry>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    if let Some(entry) = entries.get(&key) {
        return entry.verify(version.root(), &key);
    }
    ensure!(entries.len() < MAX_ENTRIES, "expanded proof entry budget");
    // The proof is checked against this version's root before it is returned.
    let (entry, value) = version.proof_with_value(&key)?;
    entries.insert(key, entry);
    Ok(value)
}
fn view(
    version: &Version,
    selection: Selection,
    engine: &Engine,
) -> Result<serde_json::Value> {
    ensure!(
        selection.names.len() <= 8
            && selection.ids.len() <= 8
            && selection.public_keys.len() <= 8
            && selection.names.len() + selection.ids.len() + selection.public_keys.len() <= 16
            && selection.owners.len() <= 16
            && selection.candidates.len() <= 16
            && selection.epochs.len() <= 8
            && selection.blocks.len() <= 16,
        "selection budget"
    );
    let mut entries = BTreeMap::new();
    let bytes = add(version, &mut entries, b"meta".to_vec())?
        .ok_or_else(|| anyhow!("metadata missing"))?;
    let meta: Meta = canonical_decode(&bytes)?;
    ensure!(
        u64::try_from(meta.height)? == version.height(),
        "metadata height mismatch"
    );
    let mut ids = BTreeSet::new();
    for name in selection.names {
        ensure!(
            (2..=15).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "invalid name"
        );
        if let Some(value) = add(version, &mut entries, name_key(&name))? {
            ids.insert(canonical_id(&serde_json::from_slice::<String>(&value)?)?);
        }
    }
    for id in selection.ids {
        ids.insert(canonical_id(&id)?);
    }
    for key in selection.public_keys {
        let raw_key = hex::decode(&key)?;
        ensure!(
            raw_key.len() == 32 && hex::encode(&raw_key) == key,
            "invalid selected public key"
        );
        add(version, &mut entries, [b"registration/commit/".as_slice(), raw_key.as_slice()].concat(),
        )?;
        if let Some(value) = add(version, &mut entries, pubkey_key(&key)?)? {
            ids.insert(canonical_id(&serde_json::from_slice::<String>(&value)?)?);
        }
    }
    let explicit = ids.clone();
    let mut guardians = BTreeSet::new();
    for id in &ids {
        if let Some(value) = add(version, &mut entries, account_key(*id))? {
            let account: Account = canonical_decode(&value)?;
            add(version, &mut entries, name_key(&account.name),
            )?;
            if explicit.contains(id)
                && let Some(policy) = account.recovery_policy
            {
                guardians.extend(policy.guardians);
            }
        }
        add(version, &mut entries, recovery_key(*id))?;
        if selection.include_security {
            add(version, &mut entries, crate::security::key(*id))?;
        }
    }
    for id in guardians.difference(&ids) {
        if let Some(value) = add(version, &mut entries, account_key(*id))? {
            let account: Account = canonical_decode(&value)?;
            add(version, &mut entries, name_key(&account.name),
            )?;
        }
        add(version, &mut entries, recovery_key(*id))?;
    }
    if selection.include_upgrade {
        add(version, &mut entries, upgrade::STATE_KEY.to_vec())?;
    }
    if selection.include_pos {
        add(version, &mut entries, b"pos/meta".to_vec())?;
    }
    if selection.include_bitcoin {
        add(version, &mut entries, crate::bitcoin_adapter::STATE_KEY.to_vec(),
        )?;
    }
    if selection.include_policy {
        add(version, &mut entries, crate::treasury_adapter::STATE_KEY.to_vec(),
        )?;
        add(version, &mut entries, crate::treasury_adapter::RECEIVING_KEY.to_vec(),
        )?;
    }
    for owner in selection.owners {
        let id = canonical_id(&owner)?;
        if let Some(raw) = add(version, &mut entries, [b"pos/owner/".as_slice(), &id.to_be_bytes()].concat(),
        )? {
            let row: pos::OwnerStake = canonical_decode(&raw)?;
            for exit in row.exits {
                for prefix in [
                    b"pos/release_refs/".as_slice(),
                    b"pos/release_time/".as_slice(),
                ] {
                    add(version, &mut entries, [prefix, &exit.release_height.to_be_bytes()].concat(),
                    )?;
                }
            }
        }
    }
    for owner in selection.candidates {
        let id = canonical_id(&owner)?;
        add(version, &mut entries, [b"pos/candidate/".as_slice(), &id.to_be_bytes()].concat(),
        )?;
    }
    for epoch in selection.epochs {
        let epoch = canonical_id(&epoch)?;
        add(version, &mut entries, crate::auction::epoch_key(epoch),
        )?;
        for owner in &explicit {
            add(version, &mut entries, crate::auction::bid_key(epoch, *owner),
            )?;
        }
    }
    let mut history_proofs = serde_json::Map::new();
    if !selection.blocks.is_empty() {
        add(version, &mut entries, b"history/meta".to_vec(),
        )?;
    }
    for height in selection.blocks {
        let height = canonical_id(&height)?;
        for prefix in [b"block/".as_slice(), b"block_time/".as_slice()] {
            add(version, &mut entries, [prefix, &height.to_be_bytes()].concat(),
            )?;
        }
        if height > 0 && height <= version.height() {
            history_proofs.insert(
                height.to_string(),
                serde_json::to_value(engine.history_proof(version, height)?)?,
            );
        }
    }
    Ok(
        json!({"height":version.height().to_string(),"root":hex::encode(version.root()),"entries":entries.into_values().collect::<Vec<_>>(),"history_proofs":history_proofs}),
    )
}
impl Application for App {
    fn info(&self, _: RequestInfo) -> ResponseInfo {
        let engine = self.engine().unwrap_or_else(|e| self.abort(e));
        let head = engine.version();
        ResponseInfo {
            data: "timecurrency-v5-engine-protocol-4-devnet; public launch disabled".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            app_version: engine.meta().map_or(4, |meta| meta.protocol_version),
            last_block_height: head.map_or(0, |version| version.height() as i64),
            last_block_app_hash: head
                .map_or_else(Vec::new, |version| version.root().to_vec())
                .into(),
        }
    }
    fn init_chain(&self, r: RequestInitChain) -> ResponseInitChain {
        if self.stopped() {
            return self.withhold();
        }
        self.try_init(r).unwrap_or_else(|e| self.abort(e))
    }
    fn finalize_block(&self, r: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        if self.stopped() {
            return self.withhold();
        }
        let (height, hash) = (r.height, r.hash.clone());
        match self.try_finalize(r) {
            Ok(response) => response,
            // Stopped by this very block (it carries a rule switch): it is
            // not executed and not answered.
            Err(_) if self.stopped() => self.withhold(),
            // A decided block that fails a check: the node fails closed, in
            // the middle of that block. It first says where it stands, in
            // words an operator can compare with the other validators.
            Err(error) => {
                eprintln!("{}", self.failed_block_report(height, &hash, &error));
                self.abort(error)
            }
        }
    }
    fn commit(&self) -> ResponseCommit {
        if self.stopped() {
            return self.withhold();
        }
        self.try_commit().unwrap_or_else(|e| self.abort(e))
    }
    fn prepare_proposal(&self, r: RequestPrepareProposal) -> ResponsePrepareProposal {
        if self.stopped() {
            return self.withhold();
        }
        self.prepare(r).unwrap_or_else(|e| self.abort(e))
    }
    /// A stopped node judges no proposal: it neither accepts nor rejects.
    fn process_proposal(&self, r: RequestProcessProposal) -> ResponseProcessProposal {
        if self.stopped() {
            return self.withhold();
        }
        let accepted = self.process(r).is_ok();
        if self.stopped() {
            return self.withhold();
        }
        ResponseProcessProposal {
            status: if accepted {
                response_process_proposal::ProposalStatus::Accept as i32
            } else {
                response_process_proposal::ProposalStatus::Reject as i32
            },
        }
    }
    /// A Flush is answered like any other request. The node remembers one
    /// answered behind the `Commit` it stopped after: the consensus engine's
    /// `Commit` call returns only when it has that answer too.
    fn flush(&self) -> ResponseFlush {
        if self.stopped() && self.answering() {
            self.shared.stop_flushed.store(true, Ordering::Release);
        }
        ResponseFlush {}
    }
    fn extend_vote(&self, _: RequestExtendVote) -> ResponseExtendVote {
        if self.stopped() {
            return self.withhold();
        }
        ResponseExtendVote::default()
    }
    fn check_tx(&self, r: RequestCheckTx) -> ResponseCheckTx {
        // Never an acceptance by default.
        self.check_batch(vec![r]).pop().unwrap_or_else(|| ResponseCheckTx {
            code: 1,
            log: "no admission result".into(),
            ..Default::default()
        })
    }
    fn query(&self, r: RequestQuery) -> ResponseQuery {
        match self.query_value(r) {
            Ok((height, value)) => ResponseQuery {
                height,
                value: value.into(),
                ..Default::default()
            },
            Err(e) => ResponseQuery {
                code: 1,
                log: e.to_string(),
                ..Default::default()
            },
        }
    }
    /// The snapshots this node offers to peers. None unless it was started
    /// with `--state-sync-snapshot-blocks`.
    fn list_snapshots(&self) -> ResponseListSnapshots {
        let snapshots = self
            .healthy()
            .and_then(|()| self.shared.store.sync_snapshots())
            .unwrap_or_default();
        // The answer must fit one ABCI frame. A manifest is at most 3.2 MB,
        // so the newest snapshot always fits; older ones are left out when
        // the state is so large that their manifests do not.
        let mut budget = MAX_LISTED_METADATA;
        let listed: Vec<_> = snapshots
            .into_iter()
            .rev()
            .take_while(|snapshot| {
                let fits = snapshot.metadata.len() <= budget;
                budget = budget.saturating_sub(snapshot.metadata.len());
                fits
            })
            .collect();
        ResponseListSnapshots {
            snapshots: listed
                .into_iter()
                .rev()
                .map(|snapshot| Snapshot {
                    height: snapshot.height,
                    format: SYNC_FORMAT,
                    chunks: snapshot.chunks,
                    hash: snapshot.hash.to_vec().into(),
                    metadata: snapshot.metadata.into(),
                })
                .collect(),
        }
    }
    /// One chunk of an offered snapshot. An empty answer tells CometBFT the
    /// chunk is missing (the snapshot was rotated out, or its file is
    /// damaged).
    fn load_snapshot_chunk(&self, r: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        // Any peer can ask any node for any chunk, as often as it likes, so
        // a chunk that is not offered is answered and not logged. The one
        // line printed is for a snapshot found damaged, once: it is
        // withdrawn, and asking for it again is a miss like any other.
        let chunk = if r.format == SYNC_FORMAT && self.healthy().is_ok() {
            match self.shared.store.load_sync_chunk(r.height, r.chunk) {
                Ok(chunk) => chunk.unwrap_or_default(),
                Err(error) => {
                    eprintln!("{error:#}");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        ResponseLoadSnapshotChunk {
            chunk: chunk.into(),
        }
    }
    fn offer_snapshot(&self, r: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        ResponseOfferSnapshot {
            result: self.offer(r) as i32,
        }
    }
    fn apply_snapshot_chunk(&self, r: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        self.apply_chunk(r)
    }
    fn verify_vote_extension(&self, r: RequestVerifyVoteExtension) -> ResponseVerifyVoteExtension {
        if self.stopped() {
            return self.withhold();
        }
        ResponseVerifyVoteExtension {
            status: if r.vote_extension.is_empty() {
                response_verify_vote_extension::VerifyStatus::Accept as i32
            } else {
                response_verify_vote_extension::VerifyStatus::Reject as i32
            },
        }
    }
}
