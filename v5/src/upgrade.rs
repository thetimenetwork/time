//! Changing the rules of a running network (`docs/design/upgrade-mechanism.md`).
//!
//! The owner account of a validator candidate sends a **signal** (kind 80)
//! naming a plan: the next version, the hash of its specification and the
//! chain time at which it should start. When the signals for one plan hold
//! four fifths of the voting power in force, with the notice still ahead, the
//! plan is **scheduled**. It must keep three quarters in every block until it
//! starts, or it is cancelled. Its start time is "not before": the first
//! block dated at or after it in which no validator safety hold is on is the
//! last under the old rules, and ends by writing the new version. A hold
//! postpones the switch; a plan that has not activated an hour after its
//! start time is cancelled.
//!
//! Everything here is pure: the engine (`engine::Overlay`) supplies the rows
//! and decides when the functions run. A network on which no signal is ever
//! accepted has no row under `upgrade/` and reaches none of this code beyond
//! one lookup per block.
//!
//! What the rules never do: shorten the notice, schedule or activate during
//! a validator safety hold, or activate after a halt. A signal that does not
//! count (a frozen or recovering owner) can only keep a plan from being
//! scheduled or cancel one, which leaves the rules as they are; it can never
//! bring a change about. A jailed validator, supporter or not, is left out
//! of the count altogether until it has left the roster two blocks later:
//! the plan is judged by the validators that remain. So one validator that
//! misbehaves can delay an activation by the blocks its removal takes; it
//! cannot cancel a plan the others keep, and since nothing is scheduled or
//! activated while a jailed validator is in a roster (a hold is on), leaving
//! it out never lets a change happen that the roster in force does not
//! support.
use crate::{
    engine::{Meta, canonical_decode},
    rules::{self, Versions},
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Kind 80: a validator's owner account supports a plan or withdraws.
pub const SIGNAL: u8 = 80;
/// Kind 81, the rule switch of an emergency release (a fix release). A
/// program accepts it in one place only: as the one transaction of its own
/// switch block (`switch_block`), byte for byte (`switch_action`). A program
/// that is not a fix release has no such block: this release never accepts
/// kind 81 and tells it by the kind byte alone. Everywhere else, in every
/// program, a proposal that carries it is rejected, and a decided block that
/// carries it is not executed and stops the node (`app::StopCause::Switch`).
/// It is never admitted to a mempool: the proposer of a switch block writes
/// it itself.
pub const SWITCH: u8 = 81;
/// Where the kind byte is in an action: after the domain and the network id.
pub const KIND_OFFSET: usize = crate::wire::DOMAIN.len() + 32;

/// The plan and the signals. Absent when there is neither.
pub const STATE_KEY: &[u8] = b"upgrade/state";
/// `upgrade/activated/` and the version, 8 bytes big-endian: one row per
/// version that was activated, kept for ever.
pub const ACTIVATED_PREFIX: &[u8] = b"upgrade/activated/";
/// One entry per candidate.
pub const MAX_ENTRIES: usize = pos::MAX_CANDIDATES;
/// The row stays under this size: 256 entries of at most 236 bytes each.
pub const MAX_STATE_BYTES: usize = 64 * 1024;
/// Support needed to schedule a plan: at least four fifths.
pub const SCHEDULE: (u128, u128) = (4, 5);
/// Support a scheduled plan needs in every block: at least three quarters.
pub const KEEP: (u128, u128) = (3, 4);

pub fn activated_key(version: u64) -> Vec<u8> {
    [ACTIVATED_PREFIX, &version.to_be_bytes()].concat()
}
/// Whether an action's bytes carry the reserved kind 81.
pub fn is_switch(raw: &[u8]) -> bool {
    raw.get(KIND_OFFSET) == Some(&SWITCH)
}

/// The one transaction of the switch block of a fix release (design 3.1):
/// the unsigned envelope of a header relay (from 2^64 − 1, nonce 0,
/// authority epoch 0, key and signature all zero) with kind 81 and the
/// payload `{"spec":"H","version":"D"}`. For one network, version and
/// specification there is exactly one such byte string, and a switch block
/// is that string and nothing else.
pub fn switch_action(network_id: &str, version: u64, spec: &str) -> Result<Vec<u8>> {
    ensure!(
        rules::valid_spec(network_id) && rules::valid_spec(spec),
        "a switch names a network and a specification by 64 lowercase hexadecimal characters"
    );
    let payload = format!("{{\"spec\":\"{spec}\",\"version\":\"{version}\"}}");
    let mut raw = crate::wire::DOMAIN.to_vec();
    raw.extend(hex::decode(network_id)?);
    raw.push(SWITCH);
    raw.extend(u64::MAX.to_be_bytes());
    // Nonce, authority epoch and public key: zero.
    raw.extend([0u8; 16 + 32]);
    raw.extend((payload.len() as u32).to_be_bytes());
    raw.extend(payload.as_bytes());
    raw.extend([0u8; 64]);
    Ok(raw)
}

/// What the engine holds while it executes the switch block of a fix
/// release (`switch_block`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchBlock {
    /// The version the block ends by writing, and its specification hash.
    pub version: u64,
    pub spec: String,
    /// At an agreed height: the bytes the block must carry, alone
    /// (`switch_action`). `None` for a repaired block, which carries the
    /// transactions it was decided with.
    pub action: Option<Vec<u8>>,
    /// The switch transaction has been applied.
    pub applied: bool,
}

/// Whether block `height`, executed on the head `meta` describes, is a
/// switch block of this program, and then what it must be.
///
/// - `Ok(None)`: this program has no switch at that block of that network.
///   Every program that is not a fix release answers so for every block.
/// - `Ok(Some(_))`: it is the switch block, and the conditions the program
///   was built on hold: the version in force is the one before the switch's
///   and, for a repaired block, the block has the hash and the state has the
///   root the program names.
/// - `Err(_)`: it is the height of the program's switch block and a
///   condition does not hold. The program executes no such block: it was
///   built for another history than this chain's.
///
/// `head_root` is the root of the committed head; `block_hash` the hash of
/// the block (all zero where a proposer builds one, which has none yet).
pub fn switch_block(
    versions: &Versions,
    meta: &Meta,
    height: u64,
    block_hash: [u8; 32],
    head_root: [u8; 32],
) -> Result<Option<SwitchBlock>> {
    let Some(switch) = versions.switch_block(&meta.network_id, height) else {
        return Ok(None);
    };
    let spec = versions
        .spec_of(switch.version)
        .ok_or_else(|| anyhow!("a switch to a version this program does not implement"))?;
    let head = rules::Rules::of(meta).version();
    ensure!(
        head.checked_add(1) == Some(switch.version),
        "block {height} is where this fix release switches the rules to protocol version {}, and the chain is under version {head} there, not under the version before it",
        switch.version
    );
    let action = match &switch.at {
        rules::SwitchAt::After { .. } => Some(switch_action(&meta.network_id, switch.version, spec)?),
        rules::SwitchAt::Block { block_hash: named, parent_root, .. } => {
            ensure!(
                hex::encode(block_hash) == *named,
                "block {height} has the hash {}, and this fix release repairs the block {height} with the hash {named}",
                hex::encode(block_hash)
            );
            ensure!(
                hex::encode(head_root) == *parent_root,
                "the state before block {height} has the root {}, and this fix release repairs that block on the state with the root {parent_root}",
                hex::encode(head_root)
            );
            None
        }
    };
    Ok(Some(SwitchBlock {
        version: switch.version,
        spec: spec.to_string(),
        action,
        applied: false,
    }))
}

/// What a program holds a block to be, where rule switches are concerned,
/// before it executes anything of it (`judge`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not a switch block of this program, and it carries no kind 81: a
    /// block like any other.
    Ordinary,
    /// The switch block of this program, exactly as it must be.
    Switch,
    /// It carries kind 81 where this program implements no switch: the
    /// switch of a fix release that is not this program.
    Foreign,
    /// It is at the height of this program's switch block and is not that
    /// block, or the chain is not where the program was built to find it.
    /// The text says which.
    NotTheSwitch(String),
}

/// Judges a proposed or decided block before anything of it is executed.
/// `head` is the committed head's metadata and root, if the node has state.
/// A proposal that is not `Ordinary` or `Switch` is rejected; a decided
/// block that is not is never executed, and the node stops (design 6.3 and
/// 10).
pub fn judge<T: AsRef<[u8]>>(
    versions: &Versions,
    head: Option<(&Meta, [u8; 32])>,
    height: i64,
    block_hash: &[u8],
    txs: &[T],
) -> Verdict {
    let carries = txs.iter().any(|tx| is_switch(tx.as_ref()));
    let plain = if carries { Verdict::Foreign } else { Verdict::Ordinary };
    let (Some((meta, root)), Ok(height)) = (head, u64::try_from(height)) else {
        return plain;
    };
    let Some(switch) = versions.switch_block(&meta.network_id, height) else {
        return plain;
    };
    // This program's own switch block, already executed: the consensus
    // engine may hand the committed block over again, and nothing of it is
    // executed a second time.
    if height <= meta.height.max(0) as u64 {
        return Verdict::Ordinary;
    }
    let hash: [u8; 32] = block_hash.try_into().unwrap_or([0; 32]);
    let block = match switch_block(versions, meta, height, hash, root) {
        Ok(Some(block)) => block,
        Ok(None) => return plain,
        Err(error) => return Verdict::NotTheSwitch(format!("{error:#}")),
    };
    match &block.action {
        Some(action) if txs.len() == 1 && txs[0].as_ref() == action.as_slice() => Verdict::Switch,
        Some(_) => Verdict::NotTheSwitch(format!(
            "block {height} must carry exactly one transaction, the rule switch to protocol version {} (spec {}), and it carries {} transaction(s), {}",
            switch.version,
            block.spec,
            txs.len(),
            if carries { "with another rule switch among them" } else { "none of which is a rule switch" }
        )),
        None if carries => Verdict::NotTheSwitch(format!(
            "block {height}, which this fix release repairs, carries a rule switch (action kind 81)"
        )),
        None => Verdict::Switch,
    }
}

/// Why a fix release executes nothing on a head although it implements the
/// head's version: the head is at or past the program's switch block and
/// still under the version before it. The chain went on without the switch,
/// so the program was built for another height (design, section 10: "to
/// start, when its head is above `H` and still at the old version").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissedSwitch {
    /// The height of the switch block this program was built for, and the
    /// version that block was to end under.
    pub block_height: u64,
    pub version: u64,
    /// The height of the head, and the version it is under.
    pub head: u64,
    pub head_version: u64,
}
impl MissedSwitch {
    /// The text printed under `STOPPED AT A SWITCH`.
    pub fn explain(&self) -> String {
        format!(
            "This program is a fix release: it changes the rules of this network to protocol version {} in block {}, and holds no rules of version {} for a block after that one. The state of this node is at height {}, still under version {}: this chain passed block {} without the switch, so this program was built for another height. Nothing was changed. Start the release this state was made by, and wait for a fix release built for a later height. Delete nothing.",
            self.version, self.block_height, self.head_version, self.head, self.head_version, self.block_height
        )
    }
}

/// The switch of this program that the head `meta` describes has passed
/// without taking, if there is one.
pub fn missed_switch(versions: &Versions, meta: &Meta) -> Option<MissedSwitch> {
    let (head, head_version) = (meta.height.max(0) as u64, rules::Rules::of(meta).version());
    versions
        .switches()
        .iter()
        .filter(|switch| {
            switch.network_id == meta.network_id
                && head_version < switch.version
                && head >= switch.block_height()
        })
        .min_by_key(|switch| switch.version)
        .map(|switch| MissedSwitch {
            block_height: switch.block_height(),
            version: switch.version,
            head,
            head_version,
        })
}

/// The times of a profile, all in microseconds of chain time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Least time from scheduling to start.
    pub notice: u64,
    /// Farthest start a signal may name, ahead of the block that carries it.
    pub farthest: u64,
    /// Least time between two changes of one candidate's signal.
    pub interval: u64,
    /// A scheduled plan is cancelled in a block dated more than this after
    /// its parent: a halt uses up notice nobody could act on.
    pub max_gap: u64,
    /// A scheduled plan that has not activated this long after its start
    /// time is cancelled, by the first block dated later, with or without a
    /// hold. A validator safety hold postpones an activation; this bounds
    /// for how long. (In the laboratory profile it is shorter than the gap
    /// rule's hour: a pause of over a minute across the start time cancels
    /// the plan there without any hold.)
    pub late: u64,
}
impl Params {
    pub fn of(profile: pos::Profile) -> Self {
        match profile {
            pos::Profile::Production => Self {
                notice: 21 * pos::DAY,
                farthest: 120 * pos::DAY,
                interval: 600 * pos::SECOND,
                max_gap: 3600 * pos::SECOND,
                late: 3600 * pos::SECOND,
            },
            pos::Profile::Laboratory => Self {
                notice: 120 * pos::SECOND,
                farthest: 3600 * pos::SECOND,
                interval: pos::SECOND,
                max_gap: 3600 * pos::SECOND,
                late: 60 * pos::SECOND,
            },
        }
    }
}

/// What a signal names: the three fields that make two plans the same plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Proposal {
    pub version: u64,
    pub activate_elapsed_micros: u64,
    pub spec: String,
}
impl Proposal {
    /// The one payload that supports this plan.
    pub fn payload(&self) -> Vec<u8> {
        format!(
            "{{\"activate_elapsed_micros\":\"{}\",\"spec\":\"{}\",\"version\":\"{}\"}}",
            self.activate_elapsed_micros, self.spec, self.version
        )
        .into_bytes()
    }
}

/// A decoded signal payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    Support(Proposal),
    Withdraw,
}
/// The payload that withdraws.
pub const WITHDRAW_PAYLOAD: &[u8] = b"{}";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportPayload {
    #[serde(with = "pos::decimal::u64")]
    activate_elapsed_micros: u64,
    spec: String,
    #[serde(with = "pos::decimal::u64")]
    version: u64,
}

/// A payload is one of exactly two byte strings: `{}`, or the three fields
/// of a plan in this order without spaces, numbers as decimal strings
/// without leading zeros, the hash as 64 lowercase hexadecimal characters.
pub fn decode_signal(payload: &[u8]) -> Result<Signal> {
    if payload == WITHDRAW_PAYLOAD {
        return Ok(Signal::Withdraw);
    }
    let form = || anyhow!("a signal payload is a plan (start time, specification hash, version) or {{}}");
    let fields: SupportPayload = serde_json::from_slice(payload).map_err(|_| form())?;
    ensure!(rules::valid_spec(&fields.spec), form());
    let proposal = Proposal {
        version: fields.version,
        activate_elapsed_micros: fields.activate_elapsed_micros,
        spec: fields.spec,
    };
    ensure!(proposal.payload() == payload, form());
    Ok(Signal::Support(proposal))
}

/// A scheduled plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    #[serde(with = "pos::decimal::u64")]
    pub activate_elapsed_micros: u64,
    /// The time of the block that scheduled it.
    #[serde(with = "pos::decimal::u64")]
    pub scheduled_elapsed_micros: u64,
    pub spec: String,
    #[serde(with = "pos::decimal::u64")]
    pub version: u64,
}
impl Plan {
    pub fn proposal(&self) -> Proposal {
        Proposal {
            version: self.version,
            activate_elapsed_micros: self.activate_elapsed_micros,
            spec: self.spec.clone(),
        }
    }
}

/// One candidate's signal. Either the three plan fields are all present (a
/// support entry) or none is (a withdrawn entry, which exists only to
/// enforce the interval between two changes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "pos::decimal::opt_u64")]
    pub activate_elapsed_micros: Option<u64>,
    #[serde(with = "pos::decimal::u64")]
    pub changed_elapsed_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "pos::decimal::opt_u64")]
    pub version: Option<u64>,
}
impl Entry {
    fn new(owner: u64, changed: u64, signal: &Signal) -> Self {
        match signal {
            Signal::Support(proposal) => Self {
                activate_elapsed_micros: Some(proposal.activate_elapsed_micros),
                changed_elapsed_micros: changed,
                owner,
                spec: Some(proposal.spec.clone()),
                version: Some(proposal.version),
            },
            Signal::Withdraw => Self {
                activate_elapsed_micros: None,
                changed_elapsed_micros: changed,
                owner,
                spec: None,
                version: None,
            },
        }
    }
    /// The plan a support entry names; `None` for a withdrawn entry.
    pub fn proposal(&self) -> Option<Proposal> {
        match (self.activate_elapsed_micros, &self.spec, self.version) {
            (Some(activate_elapsed_micros), Some(spec), Some(version)) => Some(Proposal {
                version,
                activate_elapsed_micros,
                spec: spec.clone(),
            }),
            _ => None,
        }
    }
    fn well_formed(&self) -> bool {
        match (self.activate_elapsed_micros, &self.spec, self.version) {
            (Some(_), Some(spec), Some(_)) => rules::valid_spec(spec),
            (None, None, None) => true,
            _ => false,
        }
    }
}

/// The row `upgrade/state`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Present only while a plan is scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Plan>,
    /// Sorted by owner as a number, one entry per candidate.
    pub signals: Vec<Entry>,
}
impl State {
    pub fn is_empty(&self) -> bool {
        self.plan.is_none() && self.signals.is_empty()
    }
    /// What every stored row satisfies.
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.is_empty(), "an empty upgrade row is never stored");
        ensure!(
            self.signals.len() <= MAX_ENTRIES
                && self.signals.windows(2).all(|pair| pair[0].owner < pair[1].owner)
                && self.signals.iter().all(Entry::well_formed),
            "upgrade signals order/bound/form"
        );
        if let Some(plan) = &self.plan {
            ensure!(
                rules::valid_spec(&plan.spec)
                    && plan.scheduled_elapsed_micros <= plan.activate_elapsed_micros,
                "invalid scheduled plan"
            );
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() < MAX_STATE_BYTES, "upgrade row byte limit");
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() < MAX_STATE_BYTES, "upgrade row byte limit");
        let state: Self = canonical_decode(bytes)?;
        state.validate()?;
        Ok(state)
    }
    pub fn entry(&self, owner: u64) -> Option<&Entry> {
        self.signals
            .binary_search_by_key(&owner, |entry| entry.owner)
            .ok()
            .map(|index| &self.signals[index])
    }
    /// Replaces the owner's entry, or adds it in order.
    pub fn set(&mut self, entry: Entry) {
        match self.signals.binary_search_by_key(&entry.owner, |existing| existing.owner) {
            Ok(index) => self.signals[index] = entry,
            Err(index) => self.signals.insert(index, entry),
        }
    }
}

/// The row `upgrade/activated/<version>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activated {
    /// The time of the activating block.
    #[serde(with = "pos::decimal::u64")]
    pub elapsed_micros: u64,
    /// The first block under the version: the one after the activating block.
    #[serde(with = "pos::decimal::u64")]
    pub height: u64,
    /// `"scheduled"`: by a plan, after its notice. `"none"`: by a switch.
    pub notice: String,
    pub spec: String,
}
pub const NOTICE_SCHEDULED: &str = "scheduled";
pub const NOTICE_NONE: &str = "none";
impl Activated {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let row: Self = canonical_decode(bytes)?;
        ensure!(
            rules::valid_spec(&row.spec)
                && row.height > 0
                && (row.notice == NOTICE_SCHEDULED || row.notice == NOTICE_NONE),
            "invalid activation row"
        );
        Ok(row)
    }
}

/// What a signal is judged against.
pub struct Context<'a> {
    /// This block's time. At mempool admission, the time of the last block.
    pub now: u64,
    /// The version in force.
    pub version: u64,
    pub params: Params,
    /// Set at mempool admission and when a proposer selects transactions,
    /// never when a block is validated or executed: this node's own list. A
    /// support signal for rules it does not implement is then refused, so a
    /// mistyped hash, or a stolen owner key without a modified validator,
    /// never reaches a block made by an honest proposer. Not a consensus
    /// rule.
    pub local: Option<&'a Versions>,
    /// How far past the notice a start time must lie at mempool admission
    /// (`engine::ADMISSION_MARGIN_MICROS`): admission runs on the clock of
    /// the last block and the block that would carry the signal has a later
    /// one. Zero when a block is built or executed.
    pub margin: u64,
}

/// Checks 2 to 7 of the design's section 5.1 (the engine has done the
/// first: nonce, authority epoch, a key that may spend, not frozen). Returns
/// the entry that replaces the sender's.
///
/// `candidate` says whether the sender owns a validator candidate that is
/// not archived. It need not be in the roster.
pub fn signal(
    state: &State,
    context: &Context<'_>,
    from: u64,
    payload: &[u8],
    candidate: bool,
) -> Result<Entry> {
    ensure!(
        candidate,
        "only the owner account of a validator candidate signals"
    );
    let signal = decode_signal(payload)?;
    let scheduled = state.plan.as_ref().map(Plan::proposal);
    if let Signal::Support(proposal) = &signal {
        ensure!(
            context.version.checked_add(1) == Some(proposal.version),
            "a signal names the version after the one in force"
        );
        let joins = scheduled.as_ref() == Some(proposal);
        let ahead = proposal.activate_elapsed_micros.saturating_sub(context.now);
        ensure!(
            joins
                || (proposal.activate_elapsed_micros > context.now
                    && ahead >= context.params.notice
                    && ahead <= context.params.farthest),
            "the start time must lie between the notice and the farthest start ahead of this block, or the signal must name the scheduled plan"
        );
        if let Some(own) = context.local {
            ensure!(
                own.implements(proposal.version, &proposal.spec),
                "this node does not implement that version under that specification hash and neither admits nor proposes signals for it"
            );
        }
        ensure!(
            joins || ahead >= context.params.notice.saturating_add(context.margin),
            "the start time is too close to the notice for the signal to be included"
        );
    }
    let existing = state.entry(from);
    let supported = existing.and_then(Entry::proposal);
    match &signal {
        Signal::Support(proposal) => ensure!(
            supported.as_ref() != Some(proposal),
            "this signal changes nothing: the candidate already supports that plan"
        ),
        Signal::Withdraw => ensure!(
            supported.is_some(),
            "this signal changes nothing: the candidate supports no plan"
        ),
    }
    if let Some(entry) = existing {
        ensure!(
            context.now.saturating_sub(entry.changed_elapsed_micros) >= context.params.interval,
            "a candidate changes its signal at most once per interval"
        );
    } else {
        ensure!(
            state.signals.len() < MAX_ENTRIES,
            "the signal table is full"
        );
    }
    Ok(Entry::new(from, context.now, &signal))
}

/// What the end-of-block step is given, beyond the row.
pub struct Block<'a> {
    /// This block's time.
    pub now: u64,
    /// How long after its parent this block is dated.
    pub gap: u64,
    pub height: u64,
    /// The version in force, which executed this block.
    pub version: u64,
    /// A validator safety hold is on.
    pub hold: bool,
    pub params: Params,
    /// The roster in force for this block and each roster already announced
    /// (at most two), with the powers consensus uses.
    pub rosters: Vec<&'a [pos::Validator]>,
    /// Owners of the candidates that are not archived.
    pub candidates: BTreeSet<u64>,
    /// Owners of the validators in these rosters that are jailed. A jailed
    /// validator is left out of the count altogether, out of the total as
    /// well as out of the support: it leaves the roster two blocks after it
    /// was jailed, and until then the plan is judged by the validators that
    /// remain. Otherwise one supporter that signs twice would cancel a plan
    /// the others keep.
    pub jailed: BTreeSet<u64>,
}

/// What a block did to the plan, for the node's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Scheduled(Plan),
    /// The plan lost three quarters of the votes.
    CancelledSupport(Plan),
    /// The block is dated more than `Params::max_gap` after its parent.
    CancelledGap(Plan),
    /// The block is dated more than `Params::late` after the plan's start
    /// time and the plan had not activated: a validator safety hold lasted
    /// that long, or no block was dated in that time.
    CancelledLate(Plan),
    /// The plan names another version than the next. Cannot happen on a
    /// state this engine wrote.
    CancelledStale(Plan),
    /// The start time has come and a validator safety hold is on: the plan
    /// waits for the first block without one. Reported once, by the first
    /// block dated at or after the start time.
    Postponed(Plan),
    Activated(Plan),
    /// The switch block of a fix release wrote the version, without a plan
    /// and without notice. A plan that was scheduled went with it.
    Switched {
        version: u64,
        spec: String,
        cancelled: Option<Plan>,
    },
}

/// The result of the end-of-block step.
#[derive(Debug)]
pub struct Outcome {
    /// The row to store; `None` when it is empty and must not exist.
    pub state: Option<State>,
    /// Set by the activating block: the new version and its row.
    pub activated: Option<(u64, Activated)>,
    pub events: Vec<Event>,
}

/// Counts support, among the validators that are not jailed. `counts(owner)`
/// says whether a validator's signal counts at this block's time: its
/// candidate is not jailed and its owner account is neither frozen nor in a
/// recovery. It is asked once per owner. A frozen or recovering owner stays
/// in the total; a jailed validator does not.
struct Tally<'a, 'b> {
    rosters: &'a [&'a [pos::Validator]],
    jailed: &'a BTreeSet<u64>,
    counts: &'b mut dyn FnMut(u64) -> Result<bool>,
    asked: BTreeMap<u64, bool>,
}
impl Tally<'_, '_> {
    /// Whether `proposal` holds at least `share` of the voting power of the
    /// validators that are not jailed, in the roster in force and in each
    /// announced roster: the lowest value counts. A roster with nobody left
    /// supports nothing.
    fn holds(&mut self, state: &State, proposal: &Proposal, share: (u128, u128)) -> Result<bool> {
        for roster in self.rosters {
            let mut total = 0u128;
            let mut support = 0u128;
            for validator in *roster {
                if self.jailed.contains(&validator.owner) {
                    continue;
                }
                total += u128::from(validator.power);
                let supports = state
                    .entry(validator.owner)
                    .and_then(Entry::proposal)
                    .is_some_and(|named| named == *proposal);
                if !supports {
                    continue;
                }
                let counted = match self.asked.get(&validator.owner) {
                    Some(counted) => *counted,
                    None => {
                        let counted = (self.counts)(validator.owner)?;
                        self.asked.insert(validator.owner, counted);
                        counted
                    }
                };
                if counted {
                    support += u128::from(validator.power);
                }
            }
            // Powers are bounded (`pos::validate_set`): no overflow in 128 bits.
            if total == 0 || support * share.1 < total * share.0 {
                return Ok(false);
            }
        }
        Ok(!self.rosters.is_empty())
    }
}

/// The end of every block on which the row exists or a signal was accepted
/// (section 5.3), after the block's transactions and the roster changes:
///
/// 1. Clean: drop support entries whose owner is no longer a live candidate,
///    whose version is not the one after the version in force, or whose
///    start is closer than the notice and is not the scheduled plan's; drop
///    withdrawn entries once the interval has passed. A support entry that
///    goes less than the interval after its last change leaves a withdrawn
///    entry with that change time, so that the interval between two changes
///    of one candidate holds whatever the cleaning does.
/// 2. Keep or cancel: a scheduled plan is removed if its support is below
///    three quarters, or if this block is dated more than `max_gap` after
///    its parent.
/// 3. Activate, postpone or cancel: for a plan still scheduled whose start
///    time has come. If more than `late` has passed since its start time, it
///    is removed. Otherwise, if a validator safety hold is on, nothing
///    happens: the plan waits for the first block without a hold. Otherwise
///    the version is written and the plan and all entries go.
/// 4. Schedule: with no plan and no hold, a plan with four fifths and a
///    start at least the notice after this block is recorded.
///
/// The start time of a plan is therefore "not before": a plan activates in
/// the first block dated from its start time to `late` after it in which no
/// hold is on, with three quarters of the votes and no gap above `max_gap`,
/// or not at all.
///
/// No input a transaction can create makes this fail: only `counts` can, on
/// a state that fails its own checks.
pub fn end_block(
    mut state: State,
    block: &Block<'_>,
    counts: &mut dyn FnMut(u64) -> Result<bool>,
) -> Result<Outcome> {
    let mut events = Vec::new();
    let mut tally = Tally {
        rosters: &block.rosters,
        jailed: &block.jailed,
        counts,
        asked: BTreeMap::new(),
    };
    let next = block.version.checked_add(1);
    let far_enough = |proposal: &Proposal| {
        proposal.activate_elapsed_micros > block.now
            && proposal.activate_elapsed_micros - block.now >= block.params.notice
    };
    // 1. Clean.
    let scheduled = state.plan.as_ref().map(Plan::proposal);
    let mut kept = Vec::with_capacity(state.signals.len());
    for entry in std::mem::take(&mut state.signals) {
        let stays = entry.proposal().is_some_and(|proposal| {
            block.candidates.contains(&entry.owner)
                && Some(proposal.version) == next
                && (scheduled.as_ref() == Some(&proposal) || far_enough(&proposal))
        });
        if stays {
            kept.push(entry);
        } else if block.now.saturating_sub(entry.changed_elapsed_micros) < block.params.interval {
            // A withdrawn entry that still restricts, or what is left of a
            // support entry that goes: its owner and the time of its change.
            kept.push(Entry {
                activate_elapsed_micros: None,
                changed_elapsed_micros: entry.changed_elapsed_micros,
                owner: entry.owner,
                spec: None,
                version: None,
            });
        }
    }
    state.signals = kept;
    // 2. Keep or cancel.
    if let Some(plan) = state.plan.clone() {
        if block.gap > block.params.max_gap {
            state.plan = None;
            events.push(Event::CancelledGap(plan));
        } else if !tally.holds(&state, &plan.proposal(), KEEP)? {
            state.plan = None;
            events.push(Event::CancelledSupport(plan));
        }
    }
    // 3. Activate, postpone or cancel.
    let mut activated = None;
    if let Some(plan) = state.plan.clone()
        && block.now >= plan.activate_elapsed_micros
    {
        if Some(plan.version) != next {
            // Cannot happen on a state this engine wrote (`audit`): a plan
            // for another version than the next is never activated.
            state.plan = None;
            events.push(Event::CancelledStale(plan));
        } else if block.now - plan.activate_elapsed_micros > block.params.late {
            state.plan = None;
            events.push(Event::CancelledLate(plan));
        } else if block.hold {
            // Postponed. Said once, by the first block at or after the start.
            if block.now.saturating_sub(block.gap) < plan.activate_elapsed_micros {
                events.push(Event::Postponed(plan));
            }
        } else {
            state.plan = None;
            state.signals.clear();
            activated = Some((
                plan.version,
                Activated {
                    elapsed_micros: block.now,
                    height: block
                        .height
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("height exhausted"))?,
                    notice: NOTICE_SCHEDULED.into(),
                    spec: plan.spec.clone(),
                },
            ));
            events.push(Event::Activated(plan));
        }
    }
    // 4. Schedule. Two plans cannot both hold four fifths; the order only
    // makes the choice a function of the row.
    if state.plan.is_none() && activated.is_none() && !block.hold {
        let named: BTreeSet<Proposal> = state.signals.iter().filter_map(Entry::proposal).collect();
        for proposal in named {
            if Some(proposal.version) == next
                && far_enough(&proposal)
                && tally.holds(&state, &proposal, SCHEDULE)?
            {
                let plan = Plan {
                    activate_elapsed_micros: proposal.activate_elapsed_micros,
                    scheduled_elapsed_micros: block.now,
                    spec: proposal.spec,
                    version: proposal.version,
                };
                events.push(Event::Scheduled(plan.clone()));
                state.plan = Some(plan);
                break;
            }
        }
    }
    Ok(Outcome {
        state: (!state.is_empty()).then_some(state),
        activated,
        events,
    })
}

/// The end of the switch block of a fix release (design, section 10), in
/// place of `end_block`: the block ends with the new version and the row
/// `upgrade/activated/<version>` with `"notice":"none"`, and any plan and
/// all entries go. The switch wins over a scheduled plan, also one whose
/// start time has passed: a plan never activates in a switch block.
///
/// A validator safety hold does not postpone it. A hold postpones a plan
/// because support is counted without the jailed validators; a switch counts
/// nothing, and a hold that does not end must not keep a fix out.
///
/// `state` is the stored row, if there is one; `height` and `now` are the
/// switch block's own.
pub fn switch_outcome(state: Option<State>, switch: &SwitchBlock, height: u64, now: u64) -> Result<Outcome> {
    ensure!(
        switch.action.is_none() || switch.applied,
        "the block after the agreed height carries the rule switch of this fix release, and this block does not"
    );
    Ok(Outcome {
        state: None,
        activated: Some((
            switch.version,
            Activated {
                elapsed_micros: now,
                height: height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("height exhausted"))?,
                notice: NOTICE_NONE.into(),
                spec: switch.spec.clone(),
            },
        )),
        events: vec![Event::Switched {
            version: switch.version,
            spec: switch.spec.clone(),
            cancelled: state.and_then(|state| state.plan),
        }],
    })
}

/// Why a program does not execute on a head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotRunnable {
    /// The version of the head: the rules of the next block.
    pub version: u64,
    /// The specification hash the chain activated that version with, if the
    /// state names one this program can read.
    pub spec: Option<String>,
    /// The first block under that version.
    pub from_height: Option<u64>,
    /// The height of the head.
    pub head: u64,
    /// What the program implements, in words.
    pub implemented: String,
    /// The program implements that number under another specification hash.
    pub other_rules: bool,
}
impl NotRunnable {
    /// The text printed under `STOPPED FOR UPGRADE`.
    pub fn explain(&self) -> String {
        let spec = self.spec.as_deref().map_or_else(String::new, |spec| format!(" (spec {spec})"));
        let from = self.from_height.map_or_else(String::new, |height| format!(" from height {height}"));
        let own = if self.other_rules {
            format!("This program implements {}, and version {} under another specification.", self.implemented, self.version)
        } else {
            format!("This program implements {}.", self.implemented)
        };
        format!(
            "This chain runs protocol version {}{spec}{from}. {own} The state at height {} is saved and valid. Install a release that implements version {} with that specification and start it on the same data. Delete nothing.",
            self.version, self.head, self.version
        )
    }
}

/// Whether a program with `versions` executes on the head `meta` describes:
/// its version is in the list and, above the first version, the row
/// `upgrade/activated/<version>` carries the same specification hash.
pub fn runnable(
    versions: &Versions,
    meta: &Meta,
    get: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> std::result::Result<(), NotRunnable> {
    let version = rules::Rules::of(meta).version();
    if version == rules::FIRST_VERSION && versions.spec_of(version).is_some() {
        return Ok(());
    }
    let activated = get(&activated_key(version)).and_then(|row| Activated::decode(&row).ok());
    if let Some(row) = &activated
        && versions.implements(version, &row.spec)
    {
        return Ok(());
    }
    Err(NotRunnable {
        version,
        spec: activated.as_ref().map(|row| row.spec.clone()),
        from_height: activated.as_ref().map(|row| row.height),
        head: meta.height.max(0) as u64,
        implemented: versions.describe(),
        other_rules: versions.spec_of(version).is_some(),
    })
}

/// Recounts the rows under `upgrade/`; returns how many leaves they occupy.
pub fn audit(snapshot: &crate::store::VerifiedAudit<'_>, meta: &Meta) -> Result<u64> {
    let version = rules::Rules::of(meta).version();
    let mut leaves = 0u64;
    if let Some(bytes) = snapshot.get(STATE_KEY)? {
        let state = State::decode(&bytes)?;
        let next = version.checked_add(1);
        ensure!(
            state.plan.as_ref().is_none_or(|plan| Some(plan.version) == next)
                && state
                    .signals
                    .iter()
                    .filter_map(Entry::proposal)
                    .all(|proposal| Some(proposal.version) == next)
                && state
                    .signals
                    .iter()
                    .all(|entry| entry.changed_elapsed_micros <= meta.elapsed_micros().unwrap_or(0)),
            "upgrade row names another version than the next, or a later time than the head"
        );
        leaves += 1;
    }
    let mut expected = rules::FIRST_VERSION;
    snapshot.for_each_prefix(ACTIVATED_PREFIX, |key, value| {
        ensure!(key.len() == ACTIVATED_PREFIX.len() + 8, "activation row key length");
        let named = u64::from_be_bytes(key[ACTIVATED_PREFIX.len()..].try_into()?);
        expected += 1;
        let row = Activated::decode(value)?;
        ensure!(
            named == expected
                && named <= version
                && row.height <= (meta.height.max(0) as u64).saturating_add(1)
                && row.elapsed_micros <= meta.elapsed_micros()?,
            "activation rows are one per version, in order, up to the version in force"
        );
        leaves += 1;
        Ok(())
    })?;
    ensure!(
        expected == version,
        "a version in force above the first has an activation row"
    );
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    fn lab() -> Params {
        Params::of(pos::Profile::Laboratory)
    }
    fn proposal(activate: u64) -> Proposal {
        Proposal { version: 5, activate_elapsed_micros: activate, spec: SPEC.into() }
    }

    #[test]
    fn the_profiles_have_the_times_of_the_design() {
        let production = Params::of(pos::Profile::Production);
        assert_eq!(production.notice, 21 * 86_400 * 1_000_000);
        assert_eq!(production.farthest, 120 * 86_400 * 1_000_000);
        assert_eq!(production.interval, 600 * 1_000_000);
        assert_eq!(production.max_gap, 3_600 * 1_000_000);
        assert_eq!(lab().notice, 120 * 1_000_000);
        assert_eq!(lab().farthest, 3_600 * 1_000_000);
        assert_eq!(lab().interval, 1_000_000);
        assert_eq!(lab().max_gap, 3_600 * 1_000_000);
        assert_eq!(STATE_KEY.len(), 13);
        assert_eq!(activated_key(5), [b"upgrade/activated/".as_slice(), &[0, 0, 0, 0, 0, 0, 0, 5]].concat());
        assert_eq!(KIND_OFFSET, 51);
    }

    #[test]
    fn a_payload_is_one_of_exactly_two_byte_strings() {
        assert_eq!(decode_signal(b"{}").unwrap(), Signal::Withdraw);
        let good = format!("{{\"activate_elapsed_micros\":\"200000000\",\"spec\":\"{SPEC}\",\"version\":\"5\"}}");
        assert_eq!(decode_signal(good.as_bytes()).unwrap(), Signal::Support(proposal(200_000_000)));
        assert_eq!(proposal(200_000_000).payload(), good.as_bytes());
        let upper = SPEC.replace('5', "A");
        for bad in [
            "".to_string(),
            "{ }".into(),
            "[]".into(),
            "null".into(),
            good.replace("\"5\"", "5"),
            good.replace("\"5\"", "\"05\""),
            good.replace("\"5\"", "\"+5\""),
            good.replace("\"200000000\"", "\"0200000000\""),
            good.replace("\"200000000\"", "200000000"),
            good.replace("\"200000000\"", "\"18446744073709551616\""),
            good.replace("\"200000000\"", "\"-1\""),
            good.replace(SPEC, &upper),
            good.replace(SPEC, &SPEC[1..]),
            good.replace(SPEC, &format!("{SPEC}5")),
            good.replace("\",\"spec", "\", \"spec"),
            good.replace('}', ",\"extra\":\"1\"}"),
            good.replace("}", "} "),
            format!(" {good}"),
            // Fields in another order, a field missing, a field twice.
            format!("{{\"spec\":\"{SPEC}\",\"activate_elapsed_micros\":\"200000000\",\"version\":\"5\"}}"),
            format!("{{\"activate_elapsed_micros\":\"200000000\",\"spec\":\"{SPEC}\"}}"),
            format!("{{\"activate_elapsed_micros\":\"200000000\",\"spec\":\"{SPEC}\",\"version\":\"5\",\"version\":\"5\"}}"),
            good.replace("activate", "\\u0061ctivate"),
            "{\"version\":\"5\"}".into(),
        ] {
            assert!(decode_signal(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_row_has_one_encoding_and_both_entry_forms() {
        let mut state = State::default();
        assert!(state.encode().is_err(), "an empty row is never stored");
        state.set(Entry::new(7, 30, &Signal::Support(proposal(500))));
        state.set(Entry::new(2, 40, &Signal::Withdraw));
        state.set(Entry::new(11, 50, &Signal::Support(proposal(500))));
        let entries = format!(
            "[{{\"changed_elapsed_micros\":\"40\",\"owner\":\"2\"}},{{\"activate_elapsed_micros\":\"500\",\"changed_elapsed_micros\":\"30\",\"owner\":\"7\",\"spec\":\"{SPEC}\",\"version\":\"5\"}},{{\"activate_elapsed_micros\":\"500\",\"changed_elapsed_micros\":\"50\",\"owner\":\"11\",\"spec\":\"{SPEC}\",\"version\":\"5\"}}]"
        );
        assert_eq!(String::from_utf8(state.encode().unwrap()).unwrap(), format!("{{\"signals\":{entries}}}"));
        state.plan = Some(Plan { activate_elapsed_micros: 500, scheduled_elapsed_micros: 60, spec: SPEC.into(), version: 5 });
        let text = format!(
            "{{\"plan\":{{\"activate_elapsed_micros\":\"500\",\"scheduled_elapsed_micros\":\"60\",\"spec\":\"{SPEC}\",\"version\":\"5\"}},\"signals\":{entries}}}"
        );
        assert_eq!(String::from_utf8(state.encode().unwrap()).unwrap(), text);
        assert_eq!(State::decode(text.as_bytes()).unwrap(), state);
        // Anything but that encoding is refused: a null plan, an entry with
        // some of the plan fields, entries out of order or twice, spaces.
        for bad in [
            text.replace("{\"plan\":{", "{\"plan\":null,\"x\":{"),
            format!("{{\"plan\":null,\"signals\":{entries}}}"),
            text.replace(&format!(",\"spec\":\"{SPEC}\",\"version\":\"5\"}},{{\"activate_elapsed_micros\":\"500\",\"changed_elapsed_micros\":\"50\""), ",\"version\":\"5\"},{\"activate_elapsed_micros\":\"500\",\"changed_elapsed_micros\":\"50\""),
            text.replace("\"owner\":\"11\"", "\"owner\":\"7\""),
            text.replace("\"owner\":\"11\"", "\"owner\":\"3\""),
            text.replace("\"owner\":\"2\"", "\"owner\":\"02\""),
            text.replace("\"signals\":", "\"signals\": "),
            "{\"signals\":[]}".to_string(),
            "{}".to_string(),
        ] {
            assert!(State::decode(bad.as_bytes()).is_err(), "{bad}");
        }
        // The largest row the bounds allow stays under the limit.
        let mut full = State::default();
        for owner in 0..MAX_ENTRIES as u64 {
            full.set(Entry::new(u64::MAX - 1 - owner, u64::MAX, &Signal::Support(Proposal { version: u64::MAX, activate_elapsed_micros: u64::MAX, spec: SPEC.into() })));
        }
        full.plan = Some(Plan { activate_elapsed_micros: u64::MAX, scheduled_elapsed_micros: u64::MAX, spec: SPEC.into(), version: u64::MAX });
        assert!(full.encode().unwrap().len() < MAX_STATE_BYTES);
    }

    fn context(now: u64) -> Context<'static> {
        Context { now, version: 4, params: lab(), local: None, margin: 0 }
    }

    #[test]
    fn each_refusal_of_a_signal_has_its_reason() {
        let second = 1_000_000u64;
        let now = 1000 * second;
        let notice = lab().notice;
        let good = proposal(now + notice);
        let refused = |state: &State, context: &Context<'_>, from: u64, payload: &[u8], candidate: bool, why: &str| {
            let error = format!("{:#}", signal(state, context, from, payload, candidate).expect_err(why));
            assert!(error.contains(why), "{error}");
        };
        let empty = State::default();
        // 2. Not a candidate.
        refused(&empty, &context(now), 3, &good.payload(), false, "only the owner account of a validator candidate");
        // 3. The payload.
        refused(&empty, &context(now), 3, b"{\"version\":\"5\"}", true, "a signal payload is");
        // 4. The version.
        for version in [4, 6, 0] {
            let other = Proposal { version, ..good.clone() };
            refused(&empty, &context(now), 3, &other.payload(), true, "the version after the one in force");
        }
        // 5. The start time: from the notice to the farthest start.
        refused(&empty, &context(now), 3, &proposal(now + notice - 1).payload(), true, "between the notice and the farthest start");
        refused(&empty, &context(now), 3, &proposal(now + lab().farthest + 1).payload(), true, "between the notice and the farthest start");
        refused(&empty, &context(now), 3, &proposal(now - 1).payload(), true, "between the notice and the farthest start");
        refused(&empty, &context(now), 3, &proposal(0).payload(), true, "between the notice and the farthest start");
        assert!(signal(&empty, &context(now), 3, &proposal(now + notice).payload(), true).is_ok());
        assert!(signal(&empty, &context(now), 3, &proposal(now + lab().farthest).payload(), true).is_ok());
        // ...or exactly the scheduled plan, however close its start is.
        let mut scheduled = State::default();
        scheduled.plan = Some(Plan { activate_elapsed_micros: now + 5, scheduled_elapsed_micros: now - notice, spec: SPEC.into(), version: 5 });
        assert!(signal(&scheduled, &context(now), 3, &proposal(now + 5).payload(), true).is_ok());
        refused(&scheduled, &context(now), 3, &proposal(now + 6).payload(), true, "between the notice and the farthest start");
        let other_spec = Proposal { spec: "66".repeat(32), ..proposal(now + 5) };
        refused(&scheduled, &context(now), 3, &other_spec.payload(), true, "between the notice and the farthest start");
        // 6. It changes something.
        let entry = signal(&empty, &context(now), 3, &good.payload(), true).unwrap();
        assert_eq!(entry, Entry { activate_elapsed_micros: Some(now + notice), changed_elapsed_micros: now, owner: 3, spec: Some(SPEC.into()), version: Some(5) });
        let mut supporting = State::default();
        supporting.set(entry);
        refused(&supporting, &context(now), 3, &good.payload(), true, "changes nothing");
        refused(&empty, &context(now), 3, b"{}", true, "changes nothing");
        // 7. The interval.
        let later = proposal(now + notice + 50 * second);
        refused(&supporting, &context(now + second - 1), 3, &later.payload(), true, "at most once per interval");
        refused(&supporting, &context(now + second - 1), 3, b"{}", true, "at most once per interval");
        let withdrawn = signal(&supporting, &context(now + second), 3, b"{}", true).unwrap();
        assert_eq!(withdrawn, Entry { activate_elapsed_micros: None, changed_elapsed_micros: now + second, owner: 3, spec: None, version: None });
        assert!(signal(&supporting, &context(now + second), 3, &later.payload(), true).is_ok());
        // A withdrawn entry still enforces the interval, and withdrawing
        // twice changes nothing.
        let mut gone = State::default();
        gone.set(withdrawn);
        refused(&gone, &context(now + second), 3, &later.payload(), true, "at most once per interval");
        refused(&gone, &context(now + 5 * second), 3, b"{}", true, "changes nothing");
        assert!(signal(&gone, &context(now + 2 * second), 3, &later.payload(), true).is_ok());
        // Another candidate is not held back by it.
        assert!(signal(&gone, &context(now + second), 4, &later.payload(), true).is_ok());
        // The table holds one entry per candidate and no more.
        let mut full = State::default();
        for owner in 100..100 + MAX_ENTRIES as u64 {
            full.set(Entry::new(owner, now, &Signal::Support(good.clone())));
        }
        refused(&full, &context(now), 3, &good.payload(), true, "the signal table is full");
        assert!(signal(&full, &context(now + second), 100, b"{}", true).is_ok());
    }

    #[test]
    fn the_local_policy_refuses_unknown_rules_and_starts_too_close() {
        let now = 1_000_000_000u64;
        let notice = lab().notice;
        let own = Versions::new([(4, "44".repeat(32)), (5, SPEC.to_string())]).unwrap();
        let release = Versions::new([(4, "44".repeat(32))]).unwrap();
        let empty = State::default();
        let local = |versions: &'static Versions, margin: u64| Context { now, version: 4, params: lab(), local: Some(versions), margin };
        let own: &'static Versions = Box::leak(Box::new(own));
        let release: &'static Versions = Box::leak(Box::new(release));
        let good = proposal(now + notice + 40_000_000);
        // A node that implements the plan admits it; one that does not, or
        // that implements the number under another hash, refuses.
        assert!(signal(&empty, &local(own, 30_000_000), 3, &good.payload(), true).is_ok());
        let error = format!("{:#}", signal(&empty, &local(release, 30_000_000), 3, &good.payload(), true).unwrap_err());
        assert!(error.contains("does not implement"), "{error}");
        let other = Proposal { spec: "66".repeat(32), ..good.clone() };
        assert!(signal(&empty, &local(own, 0), 3, &other.payload(), true).is_err());
        // The same signals pass where a block is validated or executed.
        assert!(signal(&empty, &context(now), 3, &good.payload(), true).is_ok());
        assert!(signal(&empty, &context(now), 3, &other.payload(), true).is_ok());
        // The margin: a start the next block could no longer accept.
        let close = proposal(now + notice + 29_999_999);
        let error = format!("{:#}", signal(&empty, &local(own, 30_000_000), 3, &close.payload(), true).unwrap_err());
        assert!(error.contains("too close"), "{error}");
        assert!(signal(&empty, &local(own, 0), 3, &close.payload(), true).is_ok());
        assert!(signal(&empty, &local(own, 30_000_000), 3, &proposal(now + notice + 30_000_000).payload(), true).is_ok());
        // Withdrawing is never held back by the local policy.
        let mut supporting = State::default();
        supporting.set(Entry::new(3, 0, &Signal::Support(other)));
        assert!(signal(&supporting, &local(release, 30_000_000), 3, b"{}", true).is_ok());
        // A scheduled plan is joined without the margin, but not by a node
        // that does not implement it.
        let mut scheduled = State::default();
        scheduled.plan = Some(Plan { activate_elapsed_micros: now + 5, scheduled_elapsed_micros: 0, spec: SPEC.into(), version: 5 });
        assert!(signal(&scheduled, &local(own, 30_000_000), 3, &proposal(now + 5).payload(), true).is_ok());
        assert!(signal(&scheduled, &local(release, 30_000_000), 3, &proposal(now + 5).payload(), true).is_err());
    }

    fn roster(powers: &[(u64, u64)]) -> Vec<pos::Validator> {
        powers
            .iter()
            .map(|(owner, power)| pos::Validator { owner: *owner, consensus_key: String::new(), power: *power })
            .collect()
    }
    fn block<'a>(now: u64, rosters: Vec<&'a [pos::Validator]>) -> Block<'a> {
        Block {
            now,
            gap: 1_000_000,
            height: 10,
            version: 4,
            hold: false,
            params: lab(),
            candidates: rosters.iter().flat_map(|roster| roster.iter().map(|validator| validator.owner)).collect(),
            jailed: BTreeSet::new(),
            rosters,
        }
    }
    fn supporting(owners: &[u64], named: &Proposal) -> State {
        let mut state = State::default();
        for owner in owners {
            state.set(Entry::new(*owner, 1, &Signal::Support(named.clone())));
        }
        state
    }
    fn all_count() -> impl FnMut(u64) -> Result<bool> {
        |_| Ok(true)
    }

    #[test]
    fn four_fifths_schedule_and_three_quarters_keep_at_the_exact_boundaries() {
        let now = 1_000_000_000u64;
        let named = proposal(now + lab().notice);
        // Exactly 80 of 100 schedules; 79 does not.
        for (signalling, others, scheduled) in [(80u64, 20u64, true), (79, 21, false), (4, 1, true), (799, 201, false), (800, 200, true)] {
            let set = roster(&[(1, signalling), (2, others)]);
            let outcome = end_block(supporting(&[1], &named), &block(now, vec![&set]), &mut all_count()).unwrap();
            assert_eq!(outcome.state.unwrap().plan.is_some(), scheduled, "{signalling}/{others}");
        }
        // Exactly 75 of 100 keeps; 74 cancels.
        for (signalling, others, kept) in [(75u64, 25u64, true), (74, 26, false), (3, 1, true), (749, 251, false)] {
            let set = roster(&[(1, signalling), (2, others)]);
            let mut state = supporting(&[1], &named);
            state.plan = Some(Plan { activate_elapsed_micros: named.activate_elapsed_micros, scheduled_elapsed_micros: now - 5, spec: SPEC.into(), version: 5 });
            let outcome = end_block(state, &block(now, vec![&set]), &mut all_count()).unwrap();
            assert_eq!(outcome.state.as_ref().unwrap().plan.is_some(), kept, "{signalling}/{others}");
            assert_eq!(outcome.events.iter().any(|event| matches!(event, Event::CancelledSupport(_))), !kept);
            // A cancelled plan is not scheduled again by the same block.
            assert!(outcome.activated.is_none());
        }
    }

    #[test]
    fn the_lowest_of_the_rosters_counts() {
        let now = 1_000_000_000u64;
        let named = proposal(now + lab().notice);
        let strong = roster(&[(1, 90), (2, 10)]);
        let weak = roster(&[(1, 79), (2, 10), (3, 11)]);
        let state = || supporting(&[1], &named);
        let scheduled = |rosters: Vec<&[pos::Validator]>| {
            let mut facts = block(now, rosters);
            facts.candidates = [1, 2, 3].into();
            end_block(state(), &facts, &mut all_count()).unwrap().state.unwrap().plan.is_some()
        };
        assert!(scheduled(vec![&strong]));
        assert!(!scheduled(vec![&weak]));
        assert!(!scheduled(vec![&strong, &weak]));
        assert!(!scheduled(vec![&weak, &strong]));
        assert!(!scheduled(vec![&strong, &strong, &weak]));
        assert!(scheduled(vec![&strong, &strong, &strong]));
        // No roster, no support.
        assert!(!scheduled(vec![]));
    }

    #[test]
    fn a_signal_that_does_not_count_is_not_counted_and_is_asked_once() {
        let now = 1_000_000_000u64;
        let named = proposal(now + lab().notice);
        let set = roster(&[(1, 40), (2, 40), (3, 20)]);
        let mut asked = Vec::new();
        let mut counts = |owner: u64| {
            asked.push(owner);
            Ok(owner != 2)
        };
        let outcome = end_block(supporting(&[1, 2], &named), &block(now, vec![&set, &set, &set]), &mut counts).unwrap();
        // 40 of 100 count: not scheduled. The entries stay.
        let state = outcome.state.unwrap();
        assert!(state.plan.is_none());
        assert_eq!(state.signals.len(), 2);
        asked.sort();
        assert_eq!(asked, vec![1, 2], "each owner is judged once, a validator that does not signal never");
        // A failing lookup fails the step: it is a broken state, not an input.
        let mut broken = |_: u64| -> Result<bool> { Err(anyhow!("broken row")) };
        assert!(end_block(supporting(&[1, 2], &named), &block(now, vec![&set]), &mut broken).is_err());
    }

    #[test]
    fn cleaning_drops_what_can_no_longer_count() {
        let now = 1_000_000_000u64;
        let notice = lab().notice;
        let set = roster(&[(1, 10), (2, 10), (3, 10), (4, 10), (5, 10), (6, 10)]);
        let mut state = State::default();
        // Kept: far enough ahead.
        state.set(Entry::new(1, 1, &Signal::Support(proposal(now + notice))));
        // Dropped: closer than the notice and not the scheduled plan's.
        state.set(Entry::new(2, 1, &Signal::Support(proposal(now + notice - 1))));
        // Dropped: names a version other than the next.
        state.set(Entry::new(3, 1, &Signal::Support(Proposal { version: 6, ..proposal(now + notice) })));
        // Dropped: its owner is no longer a live candidate.
        state.set(Entry::new(9, 1, &Signal::Support(proposal(now + notice))));
        // Withdrawn entries: dropped once the interval has passed.
        state.set(Entry::new(4, now - lab().interval, &Signal::Withdraw));
        state.set(Entry::new(5, now - lab().interval + 1, &Signal::Withdraw));
        let outcome = end_block(state, &block(now, vec![&set]), &mut all_count()).unwrap();
        let owners: Vec<u64> = outcome.state.unwrap().signals.iter().map(|entry| entry.owner).collect();
        assert_eq!(owners, vec![1, 5]);
        // The scheduled plan's entries stay however close its start is.
        let near = proposal(now + 1);
        let mut state = supporting(&[1, 2, 3, 4, 5], &near);
        state.plan = Some(Plan { activate_elapsed_micros: now + 1, scheduled_elapsed_micros: 5, spec: SPEC.into(), version: 5 });
        let outcome = end_block(state, &block(now, vec![&set]), &mut all_count()).unwrap();
        let state = outcome.state.unwrap();
        assert!(state.plan.is_some());
        assert_eq!(state.signals.len(), 5);
        // A row left with nothing is removed.
        let mut state = State::default();
        state.set(Entry::new(4, 0, &Signal::Withdraw));
        let outcome = end_block(state, &block(now, vec![&set]), &mut all_count()).unwrap();
        assert!(outcome.state.is_none() && outcome.activated.is_none() && outcome.events.is_empty());
    }

    #[test]
    fn activation_cancellation_and_the_gap() {
        let now = 1_000_000_000u64;
        let set = roster(&[(1, 80), (2, 20)]);
        let plan = |activate: u64| Plan { activate_elapsed_micros: activate, scheduled_elapsed_micros: 5, spec: SPEC.into(), version: 5 };
        let scheduled = |activate: u64| {
            let mut state = supporting(&[1], &proposal(activate));
            state.plan = Some(plan(activate));
            state
        };
        // Before the start time nothing happens.
        let outcome = end_block(scheduled(now + 1), &block(now, vec![&set]), &mut all_count()).unwrap();
        assert!(outcome.activated.is_none() && outcome.state.unwrap().plan.is_some());
        // At the start time, and after it, the block activates: the plan and
        // every entry go, the row with them.
        for activate in [now, now - 7] {
            let outcome = end_block(scheduled(activate), &block(now, vec![&set]), &mut all_count()).unwrap();
            assert!(outcome.state.is_none());
            assert_eq!(
                outcome.activated,
                Some((5, Activated { elapsed_micros: now, height: 11, notice: "scheduled".into(), spec: SPEC.into() }))
            );
            assert_eq!(outcome.events, vec![Event::Activated(plan(activate))]);
        }
        // During a validator safety hold the plan is neither activated nor
        // cancelled: it waits (`a_hold_postpones_the_switch_and_the_wait_is_bounded`).
        // Nothing is scheduled during a hold.
        let mut held = block(now, vec![&set]);
        held.hold = true;
        let outcome = end_block(scheduled(now), &held, &mut all_count()).unwrap();
        assert!(outcome.activated.is_none());
        assert_eq!(outcome.events, vec![Event::Postponed(plan(now))]);
        assert_eq!(outcome.state, Some(scheduled(now)));
        let fresh = supporting(&[1], &proposal(now + lab().notice));
        assert!(end_block(fresh.clone(), &held, &mut all_count()).unwrap().state.unwrap().plan.is_none());
        assert!(end_block(fresh, &block(now, vec![&set]), &mut all_count()).unwrap().state.unwrap().plan.is_some());
        // A hold does not cancel a plan whose start is still ahead.
        let outcome = end_block(scheduled(now + 1), &held, &mut all_count()).unwrap();
        assert!(outcome.state.unwrap().plan.is_some());
        // A block dated more than an hour after its parent cancels a
        // scheduled plan, at its start time or before it.
        for activate in [now, now + 60_000_000] {
            let mut late = block(now, vec![&set]);
            late.gap = lab().max_gap + 1;
            let outcome = end_block(scheduled(activate), &late, &mut all_count()).unwrap();
            assert!(outcome.activated.is_none(), "{activate}");
            assert_eq!(outcome.events, vec![Event::CancelledGap(plan(activate))]);
            assert!(outcome.state.unwrap().plan.is_none());
            // Exactly an hour is not more than an hour.
            late.gap = lab().max_gap;
            let outcome = end_block(scheduled(activate), &late, &mut all_count()).unwrap();
            assert_eq!(outcome.activated.is_some(), activate == now);
            assert!(outcome.events.iter().all(|event| !matches!(event, Event::CancelledGap(_))));
        }
        // After such a gap a plan whose start is still a full notice ahead is
        // scheduled anew, with this block's time: its notice starts again.
        let far = now + lab().notice;
        let mut late = block(now, vec![&set]);
        late.gap = lab().max_gap + 1;
        let outcome = end_block(scheduled(far), &late, &mut all_count()).unwrap();
        assert_eq!(outcome.events.len(), 2);
        assert_eq!(outcome.state.unwrap().plan, Some(Plan { scheduled_elapsed_micros: now, ..plan(far) }));
    }

    /// A hold postpones the switch; it does not cancel the plan. The plan
    /// activates in the first block without a hold, dated from its start
    /// time to `late` after it, and is cancelled by a block dated later.
    #[test]
    fn a_hold_postpones_the_switch_and_the_wait_is_bounded() {
        let start = 1_000_000_000u64;
        let second = 1_000_000u64;
        let set = roster(&[(1, 80), (2, 20)]);
        let plan = Plan { activate_elapsed_micros: start, scheduled_elapsed_micros: 5, spec: SPEC.into(), version: 5 };
        let scheduled = || {
            let mut state = supporting(&[1], &proposal(start));
            state.plan = Some(plan.clone());
            state
        };
        // A block dated `late` after the start, `gap` after its parent.
        let at = |late: u64, gap: u64, hold: bool| {
            let mut facts = block(start + late, vec![&set]);
            facts.gap = gap;
            facts.hold = hold;
            facts
        };
        let limit = lab().late;
        // With a hold on, inside the limit: nothing changes. The first block
        // dated at or after the start time says that the plan waits.
        for (late, gap, said) in [(0, second, true), (second / 2, second, true), (second, second, false), (limit, second, false), (limit, limit + 1, true)] {
            let outcome = end_block(scheduled(), &at(late, gap, true), &mut all_count()).unwrap();
            assert!(outcome.activated.is_none(), "{late}");
            assert_eq!(outcome.state, Some(scheduled()), "{late}");
            assert_eq!(outcome.events, if said { vec![Event::Postponed(plan.clone())] } else { vec![] }, "{late}");
        }
        // The first block without a hold activates, the limit included.
        for late in [0, second, limit] {
            let outcome = end_block(scheduled(), &at(late, second, false), &mut all_count()).unwrap();
            assert_eq!(outcome.activated.as_ref().map(|(version, row)| (*version, row.elapsed_micros, row.height)), Some((5, start + late, 11)));
            assert!(outcome.state.is_none());
            assert_eq!(outcome.events, vec![Event::Activated(plan.clone())]);
        }
        // A block dated later than the limit cancels the plan, hold or not.
        for hold in [true, false] {
            let outcome = end_block(scheduled(), &at(limit + 1, second, hold), &mut all_count()).unwrap();
            assert!(outcome.activated.is_none());
            assert_eq!(outcome.events, vec![Event::CancelledLate(plan.clone())]);
            let state = outcome.state.unwrap();
            assert!(state.plan.is_none() && state.signals.len() == 1);
        }
        // While it waits the plan still needs three quarters, and a block
        // dated more than an hour after its parent still cancels it.
        let outcome = end_block(scheduled(), &at(second, second, true), &mut |_| Ok(false)).unwrap();
        assert_eq!(outcome.events, vec![Event::CancelledSupport(plan.clone())]);
        let mut withdrawn = scheduled();
        withdrawn.set(Entry::new(1, start, &Signal::Withdraw));
        let outcome = end_block(withdrawn, &at(second, second, true), &mut all_count()).unwrap();
        assert_eq!(outcome.events, vec![Event::CancelledSupport(plan.clone())]);
        assert!(outcome.state.is_none());
        let outcome = end_block(scheduled(), &at(second, lab().max_gap + 1, true), &mut all_count()).unwrap();
        assert_eq!(outcome.events, vec![Event::CancelledGap(plan.clone())]);
        // A validator that joins may still support the waiting plan, and a
        // supporter may still withdraw.
        let context = Context { now: start + second, version: 4, params: lab(), local: None, margin: 0 };
        assert!(signal(&scheduled(), &context, 2, &proposal(start).payload(), true).is_ok());
        assert!(signal(&scheduled(), &context, 1, WITHDRAW_PAYLOAD, true).is_ok());
        // Nothing else is scheduled meanwhile: the plan is still there.
        let mut rival = scheduled();
        rival.set(Entry::new(2, 5, &Signal::Support(proposal(start + lab().notice + 10 * second))));
        let outcome = end_block(rival, &at(second, second, true), &mut all_count()).unwrap();
        assert_eq!(outcome.state.unwrap().plan, Some(plan.clone()));
        // In production the limit is the hour of the gap rule: a first block
        // at or after the start time is never too late without also being a
        // gap, so only a hold makes a plan wait.
        let production = Params::of(pos::Profile::Production);
        assert_eq!(production.late, production.max_gap);
        assert_eq!(production.late, 3_600 * second);
        assert_eq!(lab().late, 60 * second);
    }

    /// A jailed validator is left out of the count, out of the total as well
    /// as out of the support, in every roster and for both thresholds. A
    /// jailed supporter cannot cancel a plan the others keep. A jailed
    /// non-supporter raises the others' share to exactly their share of the
    /// validators that remain, and no further; and nothing is scheduled
    /// while a jailed validator is in a roster.
    #[test]
    fn a_jailed_validator_is_left_out_of_the_total_and_of_the_support() {
        let now = 1_000_000_000u64;
        let named = proposal(now + lab().notice);
        let plan = Plan { activate_elapsed_micros: named.activate_elapsed_micros, scheduled_elapsed_micros: now - 5, spec: SPEC.into(), version: 5 };
        let scheduled = |owners: &[u64]| {
            let mut state = supporting(owners, &named);
            state.plan = Some(plan.clone());
            state
        };
        // Whether a scheduled plan is kept by a block with these rosters,
        // supporters and jailed validators. A jailed validator in a roster
        // means a hold, as on the chain.
        let kept_in = |rosters: &[&[(u64, u64)]], supporters: &[u64], jailed: &[u64]| {
            let sets: Vec<Vec<pos::Validator>> = rosters.iter().map(|powers| roster(powers)).collect();
            let mut facts = block(now, sets.iter().map(Vec::as_slice).collect());
            facts.jailed = jailed.iter().copied().collect();
            facts.hold = !jailed.is_empty();
            let outcome = end_block(scheduled(supporters), &facts, &mut all_count()).unwrap();
            assert!(outcome.activated.is_none());
            outcome.state.is_some_and(|state| state.plan.is_some())
        };
        let kept = |powers: &[(u64, u64)], supporters: &[u64], jailed: &[u64]| kept_in(&[powers], supporters, jailed);
        // Five equal validators, four of them support the plan.
        let five = [(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)];
        assert!(kept(&five, &[1, 2, 3, 4], &[]));
        // One supporter is jailed: three of the four that remain keep the
        // plan. (Counted in the total it was three of five, and cancelled.)
        assert!(kept(&five, &[1, 2, 3, 4], &[4]));
        // Two supporters jailed: two of the three that remain do not.
        assert!(!kept(&five, &[1, 2, 3, 4], &[3, 4]));
        // The one that does not support is jailed: all that remain support.
        assert!(kept(&five, &[1, 2, 3, 4], &[5]));
        // An owner that is frozen or recovering is not jailed: its validator
        // stays in the total, and three of five do not keep a plan.
        let set = roster(&five);
        let outcome = end_block(scheduled(&[1, 2, 3, 4]), &block(now, vec![&set]), &mut |owner| Ok(owner != 4)).unwrap();
        assert_eq!(outcome.events, vec![Event::CancelledSupport(plan.clone())]);
        // The other direction. 70 of 100 support: not three quarters. With a
        // non-supporter of 10 jailed, 70 of the 90 that remain do.
        let powers = [(1, 70), (2, 10), (3, 20)];
        assert!(!kept(&powers, &[1], &[]));
        assert!(kept(&powers, &[1], &[2]));
        // The threshold is exact among the validators that remain: three
        // quarters of them keep, a little less does not, however much power
        // was jailed.
        for jailed_power in [1u64, 50, 1_000_000] {
            assert!(kept(&[(1, 75), (2, 25), (3, jailed_power)], &[1], &[3]), "{jailed_power}");
            assert!(!kept(&[(1, 74), (2, 26), (3, jailed_power)], &[1], &[3]), "{jailed_power}");
            assert!(!kept(&[(1, 7499), (2, 2501), (3, jailed_power)], &[1], &[3]), "{jailed_power}");
        }
        // Every roster is judged that way, and the lowest share counts: the
        // announced roster, in which the jailed validator is gone and a new
        // one has come, decides.
        assert!(kept_in(&[&powers, &[(1, 70), (3, 20)]], &[1], &[2]));
        assert!(!kept_in(&[&powers, &[(1, 70), (3, 20), (4, 10)]], &[1], &[2]));
        assert!(kept_in(&[&powers, &[(1, 70), (3, 20), (4, 3)]], &[1], &[2]));
        // When nobody is left, nothing is supported.
        assert!(!kept(&[(1, 50), (2, 50)], &[1, 2], &[1, 2]));
        // Nothing is scheduled while a jailed validator is in a roster,
        // whatever the share among the rest: four of the four that remain
        // support here, and the block still schedules nothing.
        let mut facts = block(now, vec![&set]);
        facts.jailed = [5].into();
        facts.hold = true;
        let outcome = end_block(supporting(&[1, 2, 3, 4], &named), &facts, &mut all_count()).unwrap();
        assert!(outcome.state.unwrap().plan.is_none() && outcome.events.is_empty());
        // The same four on the roster without it, when the hold has ended:
        // four of four of the validators in force. That is scheduled.
        let four = roster(&[(1, 1), (2, 1), (3, 1), (4, 1)]);
        let outcome = end_block(supporting(&[1, 2, 3, 4], &named), &block(now, vec![&four]), &mut all_count()).unwrap();
        assert!(outcome.state.unwrap().plan.is_some());
        // And three of those four are not four fifths: leaving the jailed
        // validator out never made a plan that the roster in force does not
        // support.
        let outcome = end_block(supporting(&[1, 2, 3], &named), &block(now, vec![&four]), &mut all_count()).unwrap();
        assert!(outcome.state.unwrap().plan.is_none());
        // A plan whose start time has come is not activated while a jailed
        // validator is in a roster, whatever the share among the rest.
        let due = Plan { activate_elapsed_micros: now, ..plan.clone() };
        let mut state = supporting(&[1, 2, 3, 4], &proposal(now));
        state.plan = Some(due.clone());
        let outcome = end_block(state, &facts, &mut all_count()).unwrap();
        assert!(outcome.activated.is_none());
        assert_eq!(outcome.events, vec![Event::Postponed(due)]);
    }

    /// Cleaning does not shorten the interval between two changes of one
    /// candidate's signal: a support entry that goes leaves its change time.
    #[test]
    fn a_support_entry_that_is_cleaned_leaves_its_change_time_behind() {
        let now = 1_000_000_000u64;
        let interval = lab().interval;
        let set = roster(&[(1, 10), (2, 10), (3, 10)]);
        let close = proposal(now + lab().notice - 1);
        let mut state = State::default();
        // Changed a moment ago, and its start is now closer than the notice.
        state.set(Entry::new(1, now - 1, &Signal::Support(close.clone())));
        // The same, changed a whole interval ago.
        state.set(Entry::new(2, now - interval, &Signal::Support(close)));
        // Changed a moment ago by an owner that is no longer a candidate.
        state.set(Entry::new(9, now - 5, &Signal::Support(proposal(now + lab().notice))));
        let outcome = end_block(state, &block(now, vec![&set]), &mut all_count()).unwrap();
        let state = outcome.state.unwrap();
        assert_eq!(state.signals, vec![Entry::new(1, now - 1, &Signal::Withdraw), Entry::new(9, now - 5, &Signal::Withdraw)]);
        // The owner cannot change its signal again inside the interval...
        let context = |at: u64| Context { now: at, version: 4, params: lab(), local: None, margin: 0 };
        let named = proposal(now + 600_000_000);
        let error = format!("{:#}", signal(&state, &context(now + interval - 2), 1, &named.payload(), true).unwrap_err());
        assert!(error.contains("at most once per interval"), "{error}");
        assert!(signal(&state, &context(now - 1 + interval), 1, &named.payload(), true).is_ok());
        // ...and what was left behind goes when it no longer restricts.
        let outcome = end_block(state, &block(now - 1 + interval, vec![&set]), &mut all_count()).unwrap();
        assert!(outcome.state.is_none());
    }

    #[test]
    fn two_plans_never_both_schedule_and_the_choice_is_a_function_of_the_row() {
        let now = 1_000_000_000u64;
        let first = proposal(now + lab().notice);
        let second = proposal(now + lab().notice + 1);
        let set = roster(&[(1, 50), (2, 50)]);
        let mut state = State::default();
        state.set(Entry::new(1, 1, &Signal::Support(first.clone())));
        state.set(Entry::new(2, 1, &Signal::Support(second)));
        let outcome = end_block(state, &block(now, vec![&set]), &mut all_count()).unwrap();
        assert!(outcome.state.unwrap().plan.is_none(), "half each schedules neither");
        let outcome = end_block(supporting(&[1, 2], &first), &block(now, vec![&set]), &mut all_count()).unwrap();
        assert_eq!(outcome.state.unwrap().plan.unwrap().proposal(), first);
    }

    /// The starting validators' power counts as consensus counts it, lent
    /// power included: with 55% of the votes they cannot schedule alone,
    /// with 85% they can.
    #[test]
    fn the_starting_validators_schedule_alone_only_with_four_fifths_of_the_votes() {
        let now = 1_000_000_000u64;
        let named = proposal(now + lab().notice);
        for (starting, others, alone) in [(55u64, 45u64, false), (79, 21, false), (80, 20, true), (85, 15, true)] {
            // Twenty starting validators of equal power, and everyone else.
            let mut powers: Vec<(u64, u64)> = (0..20).map(|owner| (owner, starting)).collect();
            powers.push((100, others * 20));
            let set = roster(&powers);
            let owners: Vec<u64> = (0..20).collect();
            let outcome = end_block(supporting(&owners, &named), &block(now, vec![&set]), &mut all_count()).unwrap();
            assert_eq!(outcome.state.unwrap().plan.is_some(), alone, "{starting}%");
        }
    }

    /// The state machine under random signals, roster changes, holds and
    /// block times, checked after every block against a count made here.
    #[test]
    fn random_signals_rosters_and_times_never_break_the_rules() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let second = 1_000_000u64;
        // The lowest share of `proposal` over the rosters, as (support, total).
        // The share among the validators that are not jailed, by this
        // test's own count: a jailed validator is in neither sum, a silent
        // one (frozen, recovering) only in the total.
        fn holds(state: &State, named: &Proposal, rosters: &[Vec<pos::Validator>], silent: &BTreeSet<u64>, jailed: &BTreeSet<u64>, share: (u128, u128)) -> bool {
            rosters.iter().all(|roster| {
                let remaining = || roster.iter().filter(|validator| !jailed.contains(&validator.owner));
                let total: u128 = remaining().map(|validator| u128::from(validator.power)).sum();
                let support: u128 = remaining()
                    .filter(|validator| !silent.contains(&validator.owner) && state.entry(validator.owner).and_then(Entry::proposal).as_ref() == Some(named))
                    .map(|validator| u128::from(validator.power))
                    .sum();
                total > 0 && support * share.1 >= total * share.0
            })
        }
        let (mut activations, mut cancellations, mut schedulings) = (0, 0, 0);
        let (mut postponed, mut too_late, mut after_a_wait) = (0, 0, 0);
        for _run in 0..30 {
            let mut state = State::default();
            let mut now = 1_000_000_000u64;
            let mut version = 4u64;
            let mut height = 10u64;
            let mut powers: Vec<(u64, u64)> = (1..=6).map(|owner| (owner, 1 + next() % 40)).collect();
            // A validator safety hold lasts a few blocks once it starts.
            let mut held_blocks = 0u64;
            // The validator whose jailing the hold stands for: in a roster
            // while the hold lasts, as on the chain.
            let mut jailed_owner = 0u64;
            // When each owner's signal last changed, by this test's own record.
            let mut changed: BTreeMap<u64, u64> = BTreeMap::new();
            for _block in 0..500 {
                let gap = match next() % 150 {
                    0 => lab().max_gap + 1 + next() % 1000,
                    1 => lab().max_gap,
                    _ => 1 + next() % (20 * second),
                };
                now += gap;
                height += 1;
                // A hold starts now and then, and often just when a plan is
                // due: that is the case the rule is for.
                let due = state.plan.as_ref().is_some_and(|plan| now >= plan.activate_elapsed_micros);
                if held_blocks == 0 && (next() % 25 == 0 || (due && next() % 2 == 0)) {
                    held_blocks = 1 + next() % 8;
                    jailed_owner = 1 + next() % 6;
                }
                let hold = held_blocks > 0;
                let jailed: BTreeSet<u64> = if hold { [jailed_owner].into() } else { BTreeSet::new() };
                held_blocks = held_blocks.saturating_sub(1);
                if next() % 8 == 0 {
                    let index = (next() % powers.len() as u64) as usize;
                    powers[index].1 = 1 + next() % 40;
                }
                let mut rosters = vec![roster(&powers)];
                if next() % 3 == 0 {
                    let mut announced = powers.clone();
                    let index = (next() % announced.len() as u64) as usize;
                    announced[index].1 = 1 + next() % 40;
                    rosters.push(roster(&announced));
                }
                // Signals: most name the scheduled plan, as validators that
                // mean to upgrade do, or else the plan of the current stretch
                // of time.
                let common = (now / (500 * second) + 1) * 500 * second + lab().notice;
                for _ in 0..next() % 5 {
                    let owner = 1 + next() % 7;
                    let payload = match next() % 30 {
                        0 => WITHDRAW_PAYLOAD.to_vec(),
                        1 | 2 => Proposal { version: version + next() % 3, activate_elapsed_micros: now + next() % (4000 * second), spec: SPEC.into() }.payload(),
                        _ => match &state.plan {
                            Some(plan) => plan.proposal().payload(),
                            None => Proposal { version: version + 1, activate_elapsed_micros: common, spec: SPEC.into() }.payload(),
                        },
                    };
                    let context = Context { now, version, params: lab(), local: None, margin: 0 };
                    if let Ok(entry) = signal(&state, &context, owner, &payload, owner <= 6) {
                        assert_eq!(entry.owner, owner);
                        assert!(owner <= 6, "a signal of an account without a candidate was accepted");
                        // One change per candidate per interval, whatever the
                        // cleaning did to its entry in between.
                        if let Some(last) = changed.insert(owner, now) {
                            assert!(now - last >= lab().interval, "owner {owner} changed its signal twice in {} micros", now - last);
                        }
                        state.set(entry);
                    }
                }
                let silent: BTreeSet<u64> = (1..=6).filter(|_| next() % 12 == 0).collect();
                let before = state.clone();
                let facts = Block {
                    now,
                    gap,
                    height,
                    version,
                    hold,
                    params: lab(),
                    rosters: rosters.iter().map(Vec::as_slice).collect(),
                    candidates: (1..=6).collect(),
                    jailed: jailed.clone(),
                };
                let outcome = end_block(state, &facts, &mut |owner| Ok(!silent.contains(&owner))).unwrap();
                let after = outcome.state.clone().unwrap_or_default();
                if let Some(stored) = &outcome.state {
                    // What is stored is a valid row, and never an empty one.
                    assert_eq!(State::decode(&stored.encode().unwrap()).unwrap(), *stored);
                }
                // Nothing that cannot count survives a block.
                for entry in &after.signals {
                    match entry.proposal() {
                        Some(named) => {
                            assert_eq!(named.version, version + 1);
                            let scheduled = |state: &State| state.plan.as_ref().map(Plan::proposal).as_ref() == Some(&named);
                            assert!(scheduled(&before) || scheduled(&after) || named.activate_elapsed_micros.saturating_sub(now) >= lab().notice, "a stale entry survived");
                        }
                        None => assert!(now - entry.changed_elapsed_micros < lab().interval),
                    }
                }
                match (&outcome.activated, &before.plan) {
                    (Some((new_version, row)), Some(plan)) => {
                        activations += 1;
                        assert_eq!((*new_version, plan.version), (version + 1, version + 1));
                        assert!(now >= plan.activate_elapsed_micros, "activated before its start");
                        assert!(plan.activate_elapsed_micros - plan.scheduled_elapsed_micros >= lab().notice, "activated without notice");
                        assert!(!hold, "activated during a hold");
                        assert!(now - plan.activate_elapsed_micros <= lab().late, "activated too long after its start");
                        if now.saturating_sub(gap) >= plan.activate_elapsed_micros {
                            after_a_wait += 1;
                        }
                        // An activation clears every entry, and the record with it.
                        changed.clear();
                        assert!(gap <= lab().max_gap, "activated after a gap");
                        assert!(holds(&before, &plan.proposal(), &rosters, &silent, &jailed, KEEP), "activated without three quarters");
                        assert_eq!((row.height, row.elapsed_micros, row.notice.as_str(), row.spec.as_str()), (height + 1, now, NOTICE_SCHEDULED, plan.spec.as_str()));
                        assert!(outcome.state.is_none(), "an activation leaves the plan or an entry behind");
                        version = *new_version;
                    }
                    (Some(_), None) => panic!("activated without a scheduled plan"),
                    (None, _) => {}
                }
                if let Some(plan) = &after.plan {
                    if now >= plan.activate_elapsed_micros {
                        // Only a hold keeps a plan past its start time, and only so long.
                        postponed += 1;
                        assert!(hold, "a plan is still scheduled at its start time without a hold");
                        assert!(now - plan.activate_elapsed_micros <= lab().late, "a plan waited longer than allowed");
                        assert_eq!(before.plan.as_ref(), Some(plan));
                    }
                    assert_eq!(plan.version, version + 1);
                    if before.plan.as_ref() == Some(plan) {
                        assert!(gap <= lab().max_gap, "a plan survived a gap");
                        assert!(holds(&after, &plan.proposal(), &rosters, &silent, &jailed, KEEP), "a plan was kept below three quarters");
                    } else {
                        schedulings += 1;
                        assert!(!hold, "scheduled during a hold");
                        assert_eq!(plan.scheduled_elapsed_micros, now);
                        assert!(plan.activate_elapsed_micros - now >= lab().notice, "scheduled without the notice ahead");
                        assert!(holds(&after, &plan.proposal(), &rosters, &silent, &jailed, SCHEDULE), "scheduled below four fifths");
                    }
                }
                if before.plan.is_some() && outcome.activated.is_none() && after.plan != before.plan {
                    cancellations += 1;
                    assert!(outcome.events.iter().any(|event| matches!(event, Event::CancelledSupport(_) | Event::CancelledGap(_) | Event::CancelledLate(_))));
                    if outcome.events.iter().any(|event| matches!(event, Event::CancelledLate(_))) {
                        too_late += 1;
                    }
                }
                state = after;
            }
        }
        // The run exercised what it checks.
        assert!(activations >= 5 && cancellations >= 5 && schedulings >= 10, "{activations} activations, {cancellations} cancellations, {schedulings} schedulings");
        assert!(postponed >= 3 && after_a_wait >= 1 && too_late >= 1, "{postponed} blocks waited, {after_a_wait} activations after a wait, {too_late} plans cancelled for waiting too long");
    }
}
