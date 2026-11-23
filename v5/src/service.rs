//! Service records: facts about validators, stake and accounts that a
//! network with `service_records` in its genesis keeps from its first block,
//! for rules that may be decided later. **No rule reads them.** They are
//! rows like any other: under the state root, in snapshots and state sync,
//! proven present or absent like any row, and checked by the recount
//! (`audit`). A network without the setting has none of them, and its bytes,
//! state roots and network id are what they were.
//!
//! What a later rule could ask, and the rows that answer it:
//!
//! - *Since when has this validator been registered?* `service/validator/`
//!   ‖ owner (8 bytes): the first registration of the owner account and the
//!   latest one, each as a height and a chain time, the consensus key of the
//!   latest, and how many registrations and punishments the owner has had.
//!   A validator is its owner account: a new consensus key is a new
//!   registration of the same owner (the staking rules have no change of
//!   key), which keeps `first`; another owner has a record of its own.
//!   `service/key/` ‖ consensus key (32 bytes): which owner registered the
//!   key, when, and when it was punished. Keys are never used twice.
//! - *What share of the blocks did it sign?* Counted per week of chain time
//!   (`week_micros`: seven days, sixty seconds in the laboratory profile).
//!   Block `h` carries the commit of block `h - 1`, which its proposer put
//!   together. For each validator of the set that was to sign block `h - 1`
//!   the week of block `h` counts one block `in_set`, and one `signed` if the
//!   commit holds its signature (as the reward rule reads it). The proposer
//!   of block `h`, if the block names one of the set of height `h`, counts
//!   one block `proposed`, and one `omitted` for every signature of the set
//!   that its commit leaves out. The week in progress is one row for all
//!   validators, `service/tally`, rewritten once per block. When a block
//!   opens a new week, each validator's counts of the week that ended join
//!   its record, which keeps the last `KEPT_WEEKS` weeks one by one, the sum
//!   of all older weeks (`older`) and the sum of all weeks (`total`);
//!   `service/weeks` keeps how many blocks each of those weeks had. Block 1
//!   carries no commit and is not counted.
//! - *Whose blocks left its signature out?* `service/missed/` ‖ owner (8) ‖
//!   week (8): for each week in which the validator's signature was missing
//!   from a commit, the number of such blocks per proposer.
//!   `NO_PROPOSER` stands for blocks that named no proposer of the set.
//!   Removed with the week it belongs to. The proposer is the one the
//!   block's header names, and that is the proposer's own word: CometBFT
//!   0.38 checks only that the header names a validator of the set
//!   (`state/validation.go`: it cannot know in which round the block was
//!   proposed). An honest proposer names itself; a dishonest one can name
//!   any validator of the set, and put its `proposed` count and the
//!   signatures it left out on that validator.
//! - *Was it ever punished?* `service/punishment/` ‖ owner (8) ‖ height (8):
//!   every slash, by an evidence action (kind 20) or by misbehavior CometBFT
//!   reported, with the key, the cause and the height of the offense. Never
//!   removed. The owner's record counts them, and the key's record names the
//!   moment.
//! - *How much of this stake has been in place for at least N weeks?*
//!   `service/bond/` ‖ validator (8) for its own bond, in microseconds, and
//!   `service/delegation/` ‖ validator (8) ‖ owner (8) for a delegation, in
//!   shares of the validator's pool: lots, each the amount that came in
//!   during one week. See `Lots` for what happens to them.
//! - *Since when has this account existed?* `service/account/` ‖ id (8):
//!   the height and chain time of the block that created it (height 0 for
//!   the genesis accounts), whatever action created it.
//!
//! What it costs: one row written per block (the tally), plus one per
//! validator whose signature a commit leaves out; once a week one row per
//! validator that was in the set or proposed, and the list of weeks. A
//! payment writes nothing. A registration of an account writes one row, of
//! a validator three, a change of stake one, a punishment three (four if
//! an own bond goes).
use crate::engine::{ExtensionHost, Meta, account_key, block_time_key, canonical_decode};
use crate::store::VerifiedAudit;
use anyhow::{Result, anyhow, ensure};
use pos::Validator;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The namespace of the records.
pub const PREFIX: &[u8] = b"service/";
pub const TALLY_KEY: &[u8] = b"service/tally";
pub const WEEKS_KEY: &[u8] = b"service/weeks";
const ACCOUNT_PREFIX: &[u8] = b"service/account/";
const VALIDATOR_PREFIX: &[u8] = b"service/validator/";
const KEY_PREFIX: &[u8] = b"service/key/";
const PUNISHMENT_PREFIX: &[u8] = b"service/punishment/";
const MISSED_PREFIX: &[u8] = b"service/missed/";
const BOND_PREFIX: &[u8] = b"service/bond/";
const DELEGATION_PREFIX: &[u8] = b"service/delegation/";
/// Every namespace of the records but the two single rows.
const NAMESPACES: [&[u8]; 7] = [ACCOUNT_PREFIX, VALIDATOR_PREFIX, KEY_PREFIX, PUNISHMENT_PREFIX, MISSED_PREFIX, BOND_PREFIX, DELEGATION_PREFIX];

/// Whole weeks kept one by one before the week in progress: the last 53, so
/// that the last 52 whole weeks, a year, can always be read.
pub const KEPT_WEEKS: u64 = 53;
/// The proposer of a block that named no validator of its set.
pub const NO_PROPOSER: u64 = u64::MAX;

pub fn account_record_key(id: u64) -> Vec<u8> {
    [ACCOUNT_PREFIX, &id.to_be_bytes()].concat()
}
pub fn validator_key(owner: u64) -> Vec<u8> {
    [VALIDATOR_PREFIX, &owner.to_be_bytes()].concat()
}
pub fn key_key(consensus_key: &str) -> Result<Vec<u8>> {
    Ok([KEY_PREFIX, &pos::hex32(consensus_key)?].concat())
}
pub fn punishment_key(owner: u64, height: u64) -> Vec<u8> {
    [PUNISHMENT_PREFIX, &owner.to_be_bytes(), &height.to_be_bytes()].concat()
}
pub fn missed_key(owner: u64, week: u64) -> Vec<u8> {
    [MISSED_PREFIX, &owner.to_be_bytes(), &week.to_be_bytes()].concat()
}
pub fn bond_key(validator: u64) -> Vec<u8> {
    [BOND_PREFIX, &validator.to_be_bytes()].concat()
}
pub fn delegation_key(validator: u64, owner: u64) -> Vec<u8> {
    [DELEGATION_PREFIX, &validator.to_be_bytes(), &owner.to_be_bytes()].concat()
}

/// The length of a week of the records: seven days of chain time, and sixty
/// seconds in the laboratory profile, whose other periods are short as well.
pub fn week_micros(profile: pos::Profile) -> u64 {
    match profile {
        pos::Profile::Production => 7 * pos::DAY,
        pos::Profile::Laboratory => 60 * pos::SECOND,
    }
}
/// The week of the records a chain time since genesis falls in.
pub fn week_at(profile: pos::Profile, elapsed: u64) -> u64 {
    elapsed / week_micros(profile)
}
fn week_of(meta: &Meta) -> Result<u64> {
    Ok(week_at(meta.config.profile, meta.elapsed_micros()?))
}

/// A block: its height and its chain time (microseconds since the Unix
/// epoch, as the block's time row holds it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Moment {
    #[serde(with = "pos::decimal::u64")]
    pub height: u64,
    #[serde(with = "crate::engine::decimal::i64")]
    pub time_micros: i64,
}
impl Moment {
    pub fn of(meta: &Meta) -> Result<Self> {
        Ok(Self { height: u64::try_from(meta.height)?, time_micros: meta.time_micros })
    }
}

/// What a validator did in one week, or in several.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Count {
    /// Blocks whose commit it was in the set to sign.
    #[serde(with = "pos::decimal::u64")]
    pub in_set: u64,
    /// Of those, the blocks whose commit holds its signature.
    #[serde(with = "pos::decimal::u64")]
    pub signed: u64,
    /// Blocks it proposed.
    #[serde(with = "pos::decimal::u64")]
    pub proposed: u64,
    /// Signatures of the set that the commits of the blocks it proposed
    /// leave out.
    #[serde(with = "pos::decimal::u64")]
    pub omitted: u64,
}
impl Count {
    fn add(&mut self, other: &Count) -> Result<()> {
        self.in_set = pos::add(self.in_set, other.in_set)?;
        self.signed = pos::add(self.signed, other.signed)?;
        self.proposed = pos::add(self.proposed, other.proposed)?;
        self.omitted = pos::add(self.omitted, other.omitted)?;
        Ok(())
    }
    fn is_zero(&self) -> bool {
        *self == Count::default()
    }
    fn missed(&self) -> u64 {
        self.in_set - self.signed
    }
}
/// One week of a validator's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeekCount {
    #[serde(with = "pos::decimal::u64")]
    pub week: u64,
    #[serde(with = "pos::decimal::u64")]
    pub in_set: u64,
    #[serde(with = "pos::decimal::u64")]
    pub signed: u64,
    #[serde(with = "pos::decimal::u64")]
    pub proposed: u64,
    #[serde(with = "pos::decimal::u64")]
    pub omitted: u64,
}
impl WeekCount {
    fn count(&self) -> Count {
        Count { in_set: self.in_set, signed: self.signed, proposed: self.proposed, omitted: self.omitted }
    }
}
/// `service/validator/` ‖ owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorRecord {
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    /// The first registration of this owner account (genesis: height 0).
    pub first: Moment,
    /// The latest registration.
    pub since: Moment,
    /// The consensus key of the latest registration.
    pub consensus_key: String,
    #[serde(with = "pos::decimal::u64")]
    pub registrations: u64,
    #[serde(with = "pos::decimal::u64")]
    pub punishments: u64,
    /// Every week that has ended, whatever is kept of it one by one.
    pub total: Count,
    /// The weeks that are no longer kept one by one.
    pub older: Count,
    /// The weeks that ended, the newest `KEPT_WEEKS` at most, oldest first.
    /// A week in which the validator was not in the set and proposed
    /// nothing has no entry.
    pub weeks: Vec<WeekCount>,
}
/// `service/key/` ‖ consensus key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    pub registered: Moment,
    /// The block that punished the validator under this key. A punished
    /// validator is jailed for good: a key is punished once at most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub punished: Option<Moment>,
}
/// Why a validator was punished.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// An evidence action (kind 20) proved two votes at one height.
    Evidence,
    /// CometBFT reported a duplicate vote with the block.
    DuplicateVote,
    /// CometBFT reported a light client attack with the block.
    LightClientAttack,
}
/// `service/punishment/` ‖ owner ‖ height of the block that punished.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Punishment {
    pub consensus_key: String,
    pub cause: Cause,
    /// The height at which the validator signed twice (for a light client
    /// attack, the common height CometBFT reports).
    #[serde(with = "pos::decimal::u64")]
    pub offense_height: u64,
    #[serde(with = "crate::engine::decimal::i64")]
    pub time_micros: i64,
}
/// One validator's counts in the week in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TallyEntry {
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    #[serde(with = "pos::decimal::u64")]
    pub in_set: u64,
    #[serde(with = "pos::decimal::u64")]
    pub signed: u64,
    #[serde(with = "pos::decimal::u64")]
    pub proposed: u64,
    #[serde(with = "pos::decimal::u64")]
    pub omitted: u64,
}
impl TallyEntry {
    fn count(&self) -> Count {
        Count { in_set: self.in_set, signed: self.signed, proposed: self.proposed, omitted: self.omitted }
    }
}
/// `service/tally`: the week in progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tally {
    #[serde(with = "pos::decimal::u64")]
    pub week: u64,
    /// Blocks counted in it.
    #[serde(with = "pos::decimal::u64")]
    pub blocks: u64,
    /// Of those, the blocks that named no proposer of their set.
    #[serde(with = "pos::decimal::u64")]
    pub unattributed: u64,
    /// By owner, each once.
    pub validators: Vec<TallyEntry>,
}
/// How many blocks a week that ended had.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeekBlocks {
    #[serde(with = "pos::decimal::u64")]
    pub week: u64,
    #[serde(with = "pos::decimal::u64")]
    pub blocks: u64,
    #[serde(with = "pos::decimal::u64")]
    pub unattributed: u64,
}
/// `service/weeks`: the weeks that ended and are kept one by one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weeks {
    pub weeks: Vec<WeekBlocks>,
}
/// Blocks of one week whose commit left a validator's signature out, by
/// proposer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposerCount {
    #[serde(with = "pos::decimal::u64")]
    pub proposer: u64,
    #[serde(with = "pos::decimal::u64")]
    pub blocks: u64,
}
/// `service/missed/` ‖ owner ‖ week.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Missed {
    /// By proposer, each once.
    pub proposers: Vec<ProposerCount>,
}
/// Stake that came in during one week.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lot {
    #[serde(with = "pos::decimal::u64")]
    pub week: u64,
    #[serde(with = "pos::decimal::u64")]
    pub amount: u64,
}
/// The age of one stake position: lots, oldest first, whose amounts add up
/// to the position (`service/bond/`: microseconds of the validator's own
/// bond; `service/delegation/`: shares of its pool).
///
/// - *In:* what comes in joins the lot of the current week, a new one if
///   there is none.
/// - *Out:* what goes out (when it is unbonded, not when it is withdrawn)
///   leaves from the newest lot first. What stays is
///   then exactly what has been in place without a break: the lots older
///   than N weeks hold the least the position has held at any moment of
///   those N weeks, never more. Stake added last week and taken out again
///   leaves the old lots as they were; old stake taken out and put back is
///   new.
/// - *Moving to another validator* is taking out and putting in: the
///   staking rules have no other way (undelegate, wait fourteen days,
///   withdraw, delegate). It arrives new.
/// - *Rewards:* a delegation is counted in shares. Rewards raise what every
///   share of the pool is worth, so they carry the age of the shares that
///   earned them, pro rata; nobody can direct them to one lot. Rewards
///   added to a validator's own bond (only for starting validators on a
///   network that pays them all new time without the stake hand-over rule)
///   are new stake, in the lot of their week.
/// - *Slashing:* the own bond goes to zero and its row with it. A slash of
///   the pool lowers what every share is worth and leaves the lots as they
///   are.
/// - *Bounded:* whenever a position changes, the lots older than
///   `KEPT_WEEKS` weeks are merged into one, which keeps the week of the
///   newest of them, so that it is never said to be older than it is. A
///   position holds `KEPT_WEEKS + 2` lots at most.
///
/// A lot of week `w` came in during week `w`: it has been in place for at
/// least `current - w - 1` whole weeks. A later rule that asks for N whole
/// weeks counts the lots with `w + N + 1 <= current`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lots {
    pub lots: Vec<Lot>,
}
impl Lots {
    pub fn total(&self) -> Result<u64> {
        self.lots.iter().try_fold(0u64, |sum, lot| pos::add(sum, lot.amount))
    }
    fn deposit(&mut self, week: u64, amount: u64) -> Result<()> {
        match self.lots.last_mut() {
            Some(last) if last.week == week => last.amount = pos::add(last.amount, amount)?,
            Some(last) => {
                ensure!(last.week < week, "a stake lot from a later week");
                self.lots.push(Lot { week, amount });
            }
            None => self.lots.push(Lot { week, amount }),
        }
        Ok(())
    }
    fn withdraw(&mut self, mut amount: u64) -> Result<()> {
        while amount > 0 {
            let last = self.lots.last_mut().ok_or_else(|| anyhow!("more stake taken out than its lots hold"))?;
            let taken = last.amount.min(amount);
            last.amount -= taken;
            amount -= taken;
            if last.amount == 0 {
                self.lots.pop();
            }
        }
        Ok(())
    }
    /// The lots older than `KEPT_WEEKS` weeks before `week`, as one.
    fn merge(&mut self, week: u64) -> Result<()> {
        let horizon = week.saturating_sub(KEPT_WEEKS);
        let old = self.lots.iter().take_while(|lot| lot.week < horizon).count();
        if old >= 2 {
            let amount = self.lots[..old].iter().try_fold(0u64, |sum, lot| pos::add(sum, lot.amount))?;
            let newest = self.lots[old - 1].week;
            self.lots.splice(..old, [Lot { week: newest, amount }]);
        }
        Ok(())
    }
}

fn enabled(host: &impl ExtensionHost) -> bool {
    host.meta().config.service_records
}
fn read<T: serde::de::DeserializeOwned + Serialize>(host: &impl ExtensionHost, key: &[u8]) -> Result<Option<T>> {
    host.get(key)?.map(|raw| canonical_decode(&raw)).transpose()
}
fn write(host: &mut impl ExtensionHost, key: Vec<u8>, value: &impl Serialize) -> Result<()> {
    host.put(key, Some(serde_json::to_vec(value)?))
}

/// The row that records when account `id` was created, at the block `meta`
/// describes; `None` on a network without the records.
pub fn account_created(meta: &Meta, id: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    if !meta.config.service_records {
        return Ok(None);
    }
    Ok(Some((account_record_key(id), serde_json::to_vec(&Moment::of(meta)?)?)))
}

/// The rows of a new network: the week in progress, the weeks that ended
/// (none), and the registration of each starting validator.
pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    if !enabled(host) {
        return Ok(());
    }
    write(host, TALLY_KEY.to_vec(), &Tally { week: week_of(host.meta())?, blocks: 0, unattributed: 0, validators: Vec::new() })?;
    write(host, WEEKS_KEY.to_vec(), &Weeks::default())?;
    let validators = host.meta().config.validators.clone();
    for validator in &validators {
        registered(host, validator.owner, &validator.consensus_key)?;
    }
    Ok(())
}

/// Owner `owner` registers a validator with `consensus_key` in this block.
pub fn registered(host: &mut impl ExtensionHost, owner: u64, consensus_key: &str) -> Result<()> {
    if !enabled(host) {
        return Ok(());
    }
    let at = Moment::of(host.meta())?;
    let record = match read::<ValidatorRecord>(host, &validator_key(owner))? {
        Some(mut record) => {
            record.since = at;
            record.consensus_key = consensus_key.to_string();
            record.registrations = pos::add(record.registrations, 1)?;
            record
        }
        None => ValidatorRecord {
            owner,
            first: at,
            since: at,
            consensus_key: consensus_key.to_string(),
            registrations: 1,
            punishments: 0,
            total: Count::default(),
            older: Count::default(),
            weeks: Vec::new(),
        },
    };
    write(host, validator_key(owner), &record)?;
    let key = key_key(consensus_key)?;
    ensure!(host.get(&key)?.is_none(), "a consensus key is registered once");
    write(host, key, &KeyRecord { owner, registered: at, punished: None })
}

/// Validator `owner`, under `consensus_key`, is punished in this block for
/// what it signed at `offense_height`.
pub fn punished(host: &mut impl ExtensionHost, owner: u64, consensus_key: &str, cause: Cause, offense_height: u64) -> Result<()> {
    if !enabled(host) {
        return Ok(());
    }
    let at = Moment::of(host.meta())?;
    let mut record: ValidatorRecord =
        read(host, &validator_key(owner))?.ok_or_else(|| anyhow!("a punished validator without its record"))?;
    record.punishments = pos::add(record.punishments, 1)?;
    write(host, validator_key(owner), &record)?;
    let key = key_key(consensus_key)?;
    let mut entry: KeyRecord = read(host, &key)?.ok_or_else(|| anyhow!("a punished key without its record"))?;
    ensure!(entry.owner == owner && entry.punished.is_none(), "a key is punished once, and only its owner's validator");
    entry.punished = Some(at);
    write(host, key, &entry)?;
    let row = punishment_key(owner, at.height);
    ensure!(host.get(&row)?.is_none(), "a validator is punished once in a block");
    write(host, row, &Punishment { consensus_key: consensus_key.to_string(), cause, offense_height, time_micros: at.time_micros })
}

/// The counts of block `height`, which carries the commit of the block
/// before it: `set` is the set that was to sign that block, `signed` the
/// consensus keys whose signatures the commit holds, `proposer` the owner of
/// the validator of this block's set that proposed it, if the block names
/// one. Called once per block, after the block's begin-block steps.
pub fn record_block(host: &mut impl ExtensionHost, height: u64, set: &[Validator], signed: &BTreeSet<&String>, proposer: Option<u64>) -> Result<()> {
    if !enabled(host) {
        return Ok(());
    }
    // The tally is always of the week of the head: block 1, which counts
    // nothing, moves it on as well.
    let week = week_of(host.meta())?;
    let mut tally: Tally = read(host, TALLY_KEY)?.ok_or_else(|| anyhow!("missing service tally"))?;
    let rolled = week > tally.week;
    if rolled {
        roll(host, &mut tally, week)?;
    }
    ensure!(week == tally.week, "the service tally is ahead of the chain");
    if height < 2 {
        return if rolled { write(host, TALLY_KEY.to_vec(), &tally) } else { Ok(()) };
    }
    let mut entries: BTreeMap<u64, TallyEntry> = tally.validators.iter().map(|entry| (entry.owner, *entry)).collect();
    fn entry(entries: &mut BTreeMap<u64, TallyEntry>, owner: u64) -> &mut TallyEntry {
        entries.entry(owner).or_insert(TallyEntry { owner, in_set: 0, signed: 0, proposed: 0, omitted: 0 })
    }
    tally.blocks = pos::add(tally.blocks, 1)?;
    match proposer {
        Some(owner) => {
            let counted = entry(&mut entries, owner);
            counted.proposed = pos::add(counted.proposed, 1)?;
        }
        None => tally.unattributed = pos::add(tally.unattributed, 1)?,
    }
    let mut missing = Vec::new();
    for validator in set {
        let counted = entry(&mut entries, validator.owner);
        counted.in_set = pos::add(counted.in_set, 1)?;
        if signed.contains(&validator.consensus_key) {
            counted.signed = pos::add(counted.signed, 1)?;
        } else {
            missing.push(validator.owner);
        }
    }
    if let Some(owner) = proposer {
        let counted = entry(&mut entries, owner);
        counted.omitted = pos::add(counted.omitted, missing.len() as u64)?;
    }
    tally.validators = entries.into_values().collect();
    write(host, TALLY_KEY.to_vec(), &tally)?;
    let by = proposer.unwrap_or(NO_PROPOSER);
    for owner in missing {
        let key = missed_key(owner, week);
        let mut row: Missed = read(host, &key)?.unwrap_or_default();
        match row.proposers.binary_search_by_key(&by, |count| count.proposer) {
            Ok(index) => row.proposers[index].blocks = pos::add(row.proposers[index].blocks, 1)?,
            Err(index) => row.proposers.insert(index, ProposerCount { proposer: by, blocks: 1 }),
        }
        write(host, key, &row)?;
    }
    Ok(())
}

/// The week of `tally` has ended: each validator's counts join its record,
/// what is older than `KEPT_WEEKS` weeks before `week` joins `older` (and its
/// missed blocks go), and the tally starts `week`.
fn roll(host: &mut impl ExtensionHost, tally: &mut Tally, week: u64) -> Result<()> {
    let horizon = week.saturating_sub(KEPT_WEEKS);
    for entry in &tally.validators {
        let mut record: ValidatorRecord =
            read(host, &validator_key(entry.owner))?.ok_or_else(|| anyhow!("a counted validator without its record"))?;
        let count = entry.count();
        record.total.add(&count)?;
        record.weeks.push(WeekCount { week: tally.week, in_set: count.in_set, signed: count.signed, proposed: count.proposed, omitted: count.omitted });
        let old = record.weeks.iter().take_while(|kept| kept.week < horizon).count();
        for kept in record.weeks.drain(..old) {
            record.older.add(&kept.count())?;
            if kept.in_set > kept.signed {
                host.put(missed_key(entry.owner, kept.week), None)?;
            }
        }
        write(host, validator_key(entry.owner), &record)?;
    }
    let mut weeks: Weeks = read(host, WEEKS_KEY)?.ok_or_else(|| anyhow!("missing service weeks"))?;
    if tally.blocks > 0 {
        weeks.weeks.push(WeekBlocks { week: tally.week, blocks: tally.blocks, unattributed: tally.unattributed });
    }
    weeks.weeks.retain(|kept| kept.week >= horizon);
    write(host, WEEKS_KEY.to_vec(), &weeks)?;
    *tally = Tally { week, blocks: 0, unattributed: 0, validators: Vec::new() };
    Ok(())
}

fn lots_changed(host: &mut impl ExtensionHost, key: Vec<u8>, before: u64, after: u64) -> Result<()> {
    if before == after {
        return Ok(());
    }
    let week = week_of(host.meta())?;
    let mut lots: Lots = read(host, &key)?.unwrap_or_default();
    ensure!(lots.total()? == before, "the lots of a stake position differ from the position");
    if after > before {
        lots.deposit(week, after - before)?;
    } else {
        lots.withdraw(before - after)?;
    }
    lots.merge(week)?;
    ensure!(lots.total()? == after, "the lots of a stake position differ from the position");
    if lots.lots.is_empty() {
        host.put(key, None)
    } else {
        write(host, key, &lots)
    }
}
/// The own bond of validator `validator` went from `before` to `after`
/// microseconds in this block.
pub fn bond_changed(host: &mut impl ExtensionHost, validator: u64, before: u64, after: u64) -> Result<()> {
    if !enabled(host) {
        return Ok(());
    }
    lots_changed(host, bond_key(validator), before, after)
}
/// The positions of a stake owner, before and after an action.
pub fn positions_changed(host: &mut impl ExtensionHost, before: &pos::OwnerStake, after: &pos::OwnerStake) -> Result<()> {
    if !enabled(host) || before.positions == after.positions {
        return Ok(());
    }
    let mut validators: BTreeSet<u64> = before.positions.iter().map(|position| position.candidate).collect();
    validators.extend(after.positions.iter().map(|position| position.candidate));
    let shares = |stake: &pos::OwnerStake, validator: u64| {
        stake.positions.iter().find(|position| position.candidate == validator).map_or(0, |position| position.shares)
    };
    for validator in validators {
        lots_changed(host, delegation_key(validator, after.owner), shares(before, validator), shares(after, validator))?;
    }
    Ok(())
}

// ---- The recount ---------------------------------------------------------

fn moment_holds(snapshot: &VerifiedAudit<'_>, meta: &Meta, at: &Moment) -> Result<()> {
    ensure!(
        at.height <= meta.height as u64 && at.time_micros >= meta.genesis.genesis_time_micros && at.time_micros <= meta.time_micros,
        "a service record dated outside the chain"
    );
    if at.height == 0 {
        ensure!(at.time_micros == meta.genesis.genesis_time_micros, "a service record of genesis with another time");
    }
    if let Some(raw) = snapshot.get(&block_time_key(at.height))? {
        let text: String = canonical_decode(&raw)?;
        ensure!(text == at.time_micros.to_string(), "a service record dated otherwise than its block");
    }
    Ok(())
}
fn owner_of(key: &[u8], prefix: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(key[prefix.len()..prefix.len() + 8].try_into()?))
}
fn second_of(key: &[u8], prefix: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(key[prefix.len() + 8..prefix.len() + 16].try_into()?))
}

/// What the recount (`--audit`) checks of the records, and how many rows
/// they are. On a network without the setting there must be none.
///
/// Rebuilt from other rows: one account record for every account, in the
/// order the accounts were made; one punishment for every row the staking
/// rules leave when they punish (`pos/evidence/`, `pos/misbehavior/`); the
/// lots of every stake position add up to it; and, for every week whose
/// blocks the state still holds (the last fourteen days), the number of
/// blocks and every validator's `in_set`, from the block times and the
/// rosters. Checked for consistency: every validator record against its
/// keys, its punishments, its candidate row and its weeks (which add up to
/// `total`); the tally and the weeks; and the missed blocks against the
/// counts and the proposers' `omitted`. What cannot be rebuilt is which
/// signatures a commit held and who proposed a block: the state keeps
/// neither.
pub fn audit(snapshot: &VerifiedAudit<'_>, meta: &Meta) -> Result<u64> {
    if !meta.config.service_records {
        let mut stray = 0u64;
        snapshot.for_each_prefix(PREFIX, |_, _| {
            stray += 1;
            Ok(())
        })?;
        ensure!(stray == 0, "service record rows on a network without service_records");
        return Ok(0);
    }
    let profile = meta.config.profile;
    let height = meta.height as u64;
    let current = week_of(meta)?;
    let mut rows = 0u64;
    // Nothing under the prefix but the namespaces of the records.
    snapshot.for_each_prefix(PREFIX, |key, _| {
        ensure!(
            key == TALLY_KEY || key == WEEKS_KEY || NAMESPACES.iter().any(|prefix| key.starts_with(prefix)),
            "an unknown service record row"
        );
        rows += 1;
        Ok(())
    })?;

    // Accounts: one record per account, dated in the order of the ids.
    let mut accounts = 0u64;
    let mut previous: Option<Moment> = None;
    snapshot.for_each_prefix(ACCOUNT_PREFIX, |key, raw| {
        ensure!(key.len() == ACCOUNT_PREFIX.len() + 8, "account record key length");
        let id = owner_of(key, ACCOUNT_PREFIX)?;
        let at: Moment = canonical_decode(raw)?;
        ensure!(snapshot.get(&account_key(id))?.is_some(), "an account record of no account");
        let genesis = meta.genesis.accounts.binary_search_by_key(&id, |account| account.id).is_ok();
        ensure!((at.height == 0) == genesis, "an account record of the wrong block");
        moment_holds(snapshot, meta, &at)?;
        ensure!(
            previous.is_none_or(|before| at.height >= before.height && at.time_micros >= before.time_micros),
            "accounts recorded out of the order they were made"
        );
        previous = Some(at);
        accounts += 1;
        Ok(())
    })?;
    ensure!(accounts == meta.account_count, "one account record for every account");

    // The week in progress and the weeks that ended.
    let tally: Tally = canonical_decode(&snapshot.get(TALLY_KEY)?.ok_or_else(|| anyhow!("missing service tally"))?)?;
    let weeks: Weeks = canonical_decode(&snapshot.get(WEEKS_KEY)?.ok_or_else(|| anyhow!("missing service weeks"))?)?;
    ensure!(tally.week == current, "a service tally of another week than the head's");
    ensure!(
        tally.validators.windows(2).all(|pair| pair[0].owner < pair[1].owner)
            && tally.validators.iter().all(|entry| !entry.count().is_zero() && entry.signed <= entry.in_set)
            && tally.unattributed <= tally.blocks
            && (tally.blocks > 0 || tally.validators.is_empty()),
        "service tally entries"
    );
    let horizon = tally.week.saturating_sub(KEPT_WEEKS);
    ensure!(
        weeks.weeks.len() as u64 <= KEPT_WEEKS
            && weeks.weeks.windows(2).all(|pair| pair[0].week < pair[1].week)
            && weeks.weeks.iter().all(|kept| kept.week >= horizon && kept.week < tally.week && kept.blocks > 0 && kept.unattributed <= kept.blocks),
        "service weeks"
    );
    // Per week, per validator: what the records say, to be checked against
    // each other and against the recount.
    let mut counted: BTreeMap<u64, BTreeMap<u64, Count>> = BTreeMap::new();
    counted.insert(tally.week, tally.validators.iter().map(|entry| (entry.owner, entry.count())).collect());
    let listed: BTreeMap<u64, WeekBlocks> = weeks.weeks.iter().map(|kept| (kept.week, *kept)).collect();

    // Validators.
    let mut records: BTreeMap<u64, ValidatorRecord> = BTreeMap::new();
    snapshot.for_each_prefix(VALIDATOR_PREFIX, |key, raw| {
        ensure!(key.len() == VALIDATOR_PREFIX.len() + 8, "validator record key length");
        let record: ValidatorRecord = canonical_decode(raw)?;
        ensure!(key == validator_key(record.owner), "validator record key");
        ensure!(snapshot.get(&account_key(record.owner))?.is_some(), "a validator record of no account");
        moment_holds(snapshot, meta, &record.first)?;
        moment_holds(snapshot, meta, &record.since)?;
        ensure!(
            record.first.height <= record.since.height
                && record.registrations >= 1
                && (record.registrations > 1 || record.first == record.since),
            "validator record registrations"
        );
        ensure!(
            snapshot.get(&crate::pos_adapter::consensus_key(&record.consensus_key)?)? == Some(serde_json::to_vec(&record.owner.to_string())?),
            "a validator record with a key its owner did not reserve"
        );
        ensure!(
            record.weeks.len() as u64 <= KEPT_WEEKS + 1
                && record.weeks.windows(2).all(|pair| pair[0].week < pair[1].week)
                && record.weeks.iter().all(|kept| kept.week < tally.week && kept.signed <= kept.in_set && !kept.count().is_zero()),
            "validator record weeks"
        );
        let mut sum = record.older;
        for kept in &record.weeks {
            sum.add(&kept.count())?;
            if kept.week >= horizon {
                ensure!(listed.contains_key(&kept.week), "a validator's week that the weeks do not list");
                counted.entry(kept.week).or_default().insert(record.owner, kept.count());
            }
        }
        ensure!(sum == record.total, "a validator's weeks do not add up to its total");
        ensure!(record.older.signed <= record.older.in_set && record.total.signed <= record.total.in_set, "validator record totals");
        records.insert(record.owner, record);
        Ok(())
    })?;
    for entry in &tally.validators {
        ensure!(records.contains_key(&entry.owner), "a counted validator without its record");
    }
    // Every candidate has its record, under the key it has now.
    snapshot.for_each_prefix(b"pos/candidate/", |_, raw| {
        let candidate: pos::Candidate = canonical_decode(raw)?;
        let record = records.get(&candidate.owner).ok_or_else(|| anyhow!("a validator without its record"))?;
        ensure!(record.consensus_key == candidate.consensus_key, "a validator record with another key than the validator");
        Ok(())
    })?;

    // Keys.
    let mut keys_of: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    let mut punished_keys: BTreeMap<[u8; 20], (u64, Moment)> = BTreeMap::new();
    snapshot.for_each_prefix(KEY_PREFIX, |key, raw| {
        ensure!(key.len() == KEY_PREFIX.len() + 32, "key record key length");
        let consensus_key = hex::encode(&key[KEY_PREFIX.len()..]);
        let entry: KeyRecord = canonical_decode(raw)?;
        let record = records.get(&entry.owner).ok_or_else(|| anyhow!("a key record of no validator"))?;
        ensure!(
            snapshot.get(&crate::pos_adapter::consensus_key(&consensus_key)?)? == Some(serde_json::to_vec(&entry.owner.to_string())?),
            "a key record of a key its owner did not reserve"
        );
        moment_holds(snapshot, meta, &entry.registered)?;
        ensure!(
            entry.registered.height >= record.first.height
                && entry.registered.height <= record.since.height
                && (consensus_key != record.consensus_key || entry.registered == record.since),
            "a key record outside its owner's registrations"
        );
        let (registrations, punishments) = keys_of.entry(entry.owner).or_default();
        *registrations += 1;
        if let Some(at) = entry.punished {
            moment_holds(snapshot, meta, &at)?;
            ensure!(at.height > entry.registered.height, "a key punished before it was registered");
            *punishments += 1;
            let address = crate::pos_adapter::consensus_address(&consensus_key).ok_or_else(|| anyhow!("key address"))?;
            punished_keys.insert(address, (entry.owner, at));
        }
        Ok(())
    })?;
    for (owner, record) in &records {
        let (registrations, punishments) = keys_of.get(owner).copied().unwrap_or((0, 0));
        ensure!(
            registrations == record.registrations && punishments == record.punishments,
            "a validator record's registrations or punishments differ from its keys"
        );
    }
    // A jailed validator was punished under the key it has.
    snapshot.for_each_prefix(b"pos/candidate/", |_, raw| {
        let candidate: pos::Candidate = canonical_decode(raw)?;
        if candidate.jailed {
            let address = crate::pos_adapter::consensus_address(&candidate.consensus_key).ok_or_else(|| anyhow!("key address"))?;
            ensure!(punished_keys.contains_key(&address), "a jailed validator without its punishment");
        }
        Ok(())
    })?;

    // Punishments: one for every row the staking rules leave when they
    // punish.
    let mut punishments = 0u64;
    let mut by_block: BTreeMap<(u64, [u8; 20]), (Cause, u64)> = BTreeMap::new();
    let mut per_owner: BTreeMap<u64, u64> = BTreeMap::new();
    snapshot.for_each_prefix(PUNISHMENT_PREFIX, |key, raw| {
        ensure!(key.len() == PUNISHMENT_PREFIX.len() + 16, "punishment key length");
        let owner = owner_of(key, PUNISHMENT_PREFIX)?;
        let at_height = second_of(key, PUNISHMENT_PREFIX)?;
        let row: Punishment = canonical_decode(raw)?;
        let address = crate::pos_adapter::consensus_address(&row.consensus_key).ok_or_else(|| anyhow!("key address"))?;
        let at = Moment { height: at_height, time_micros: row.time_micros };
        ensure!(
            punished_keys.get(&address) == Some(&(owner, at)) && row.offense_height > 0 && row.offense_height < at_height,
            "a punishment that its key does not name"
        );
        *per_owner.entry(owner).or_default() += 1;
        by_block.insert((at_height, address), (row.cause, row.offense_height));
        punishments += 1;
        Ok(())
    })?;
    for (owner, record) in &records {
        ensure!(per_owner.get(owner).copied().unwrap_or(0) == record.punishments, "a validator's punishments differ from its record");
    }
    let mut evidence = 0u64;
    snapshot.for_each_prefix(b"pos/evidence/", |_, _| {
        evidence += 1;
        Ok(())
    })?;
    let mut reported = 0u64;
    snapshot.for_each_prefix(crate::pos_adapter::MISBEHAVIOR_PREFIX, |key, raw| {
        let prefix = crate::pos_adapter::MISBEHAVIOR_PREFIX.len();
        let cause = match key[prefix] {
            1 => Cause::DuplicateVote,
            2 => Cause::LightClientAttack,
            _ => anyhow::bail!("misbehavior type"),
        };
        let address: [u8; 20] = key[prefix + 1..prefix + 21].try_into()?;
        let offense = u64::from_be_bytes(key[prefix + 21..].try_into()?);
        let text: String = canonical_decode(raw)?;
        let at: u64 = text.parse()?;
        ensure!(by_block.get(&(at, address)) == Some(&(cause, offense)), "a punishment by reported misbehavior without its record");
        reported += 1;
        Ok(())
    })?;
    let by_evidence = by_block.values().filter(|(cause, _)| *cause == Cause::Evidence).count() as u64;
    ensure!(
        punishments == evidence + reported && by_evidence == evidence,
        "the punishments differ from the rows of the staking rules"
    );

    // Missed blocks, against the counts and the proposers.
    let mut omitted: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();
    let mut missed_rows = 0u64;
    snapshot.for_each_prefix(MISSED_PREFIX, |key, raw| {
        ensure!(key.len() == MISSED_PREFIX.len() + 16, "missed key length");
        let owner = owner_of(key, MISSED_PREFIX)?;
        let week = second_of(key, MISSED_PREFIX)?;
        let row: Missed = canonical_decode(raw)?;
        ensure!(
            !row.proposers.is_empty()
                && row.proposers.windows(2).all(|pair| pair[0].proposer < pair[1].proposer)
                && row.proposers.iter().all(|count| count.blocks > 0 && (count.proposer == NO_PROPOSER || records.contains_key(&count.proposer))),
            "missed blocks entries"
        );
        let sum = row.proposers.iter().try_fold(0u64, |sum, count| pos::add(sum, count.blocks))?;
        let expected = if week == tally.week {
            tally.validators.iter().find(|entry| entry.owner == owner).map(|entry| entry.count())
        } else {
            records.get(&owner).and_then(|record| record.weeks.iter().find(|kept| kept.week == week)).map(|kept| kept.count())
        };
        ensure!(expected.is_some_and(|count| count.missed() == sum), "missed blocks that the counts do not show");
        if week >= horizon {
            for count in &row.proposers {
                let total = omitted.entry(week).or_default().entry(count.proposer).or_default();
                *total = pos::add(*total, count.blocks)?;
            }
        }
        missed_rows += 1;
        Ok(())
    })?;
    let mut with_misses = 0u64;
    for entry in &tally.validators {
        if entry.in_set > entry.signed {
            with_misses += 1;
        }
    }
    for record in records.values() {
        with_misses += record.weeks.iter().filter(|kept| kept.in_set > kept.signed).count() as u64;
    }
    ensure!(missed_rows == with_misses, "missed blocks rows differ from the counts");
    // Each kept week: the blocks its validators proposed are its blocks, and
    // what its proposers left out is what its validators missed.
    for (week, validators) in &counted {
        let (blocks, unattributed) = if *week == tally.week {
            (tally.blocks, tally.unattributed)
        } else {
            let kept = listed.get(week).ok_or_else(|| anyhow!("a counted week that the weeks do not list"))?;
            (kept.blocks, kept.unattributed)
        };
        let proposed = validators.values().try_fold(0u64, |sum, count| pos::add(sum, count.proposed))?;
        ensure!(pos::add(proposed, unattributed)? == blocks, "the blocks of a week differ from what its validators proposed");
        let left_out = omitted.get(week);
        for (owner, count) in validators {
            ensure!(count.in_set <= blocks, "more blocks in the set than the week had");
            let by = left_out.and_then(|proposers| proposers.get(owner)).copied().unwrap_or(0);
            ensure!(count.omitted == by, "what a proposer left out differs from what its validators missed");
        }
        if let Some(proposers) = left_out {
            for proposer in proposers.keys() {
                ensure!(*proposer == NO_PROPOSER || validators.contains_key(proposer), "missed blocks by a proposer the week does not count");
            }
        }
    }
    for week in listed.keys() {
        ensure!(counted.contains_key(week), "a listed week without its validators");
    }

    // Rebuilt from the block times and the rosters: the blocks of every week
    // the state still holds whole, and every validator's `in_set`.
    // Block `h` counts the set of `h - 1`, whose roster row the state keeps
    // while `h - 1` is above the cleanup; block 1 counts nothing.
    let pruned = meta.history_pruned_through;
    let first = (pruned + 2).max(2);
    let partial = if pruned == 0 {
        None
    } else {
        let text: String = canonical_decode(&snapshot.get(&block_time_key(pruned + 1))?.ok_or_else(|| anyhow!("missing block time"))?)?;
        let time: i64 = text.parse()?;
        Some(week_at(profile, u64::try_from(time - meta.genesis.genesis_time_micros)?))
    };
    let mut blocks_of: BTreeMap<u64, u64> = BTreeMap::new();
    let mut sets_of: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    let mut rosters: BTreeMap<u64, Vec<Validator>> = BTreeMap::new();
    for at in first..=height {
        let text: String = canonical_decode(&snapshot.get(&block_time_key(at))?.ok_or_else(|| anyhow!("missing block time"))?)?;
        let time: i64 = text.parse()?;
        let week = week_at(profile, u64::try_from(time - meta.genesis.genesis_time_micros)?);
        let pointer: String = canonical_decode(
            &snapshot.get(&crate::pos_adapter::roster_at_key(at - 1))?.ok_or_else(|| anyhow!("missing roster pointer"))?,
        )?;
        let pointer: u64 = pointer.parse()?;
        if !rosters.contains_key(&pointer) {
            rosters.insert(pointer, crate::pos_adapter::roster_at(|key| snapshot.get(key), at - 1)?);
        }
        *blocks_of.entry(week).or_default() += 1;
        *sets_of.entry((week, pointer)).or_default() += 1;
    }
    let mut in_set: BTreeMap<u64, BTreeMap<u64, u64>> = BTreeMap::new();
    for ((week, pointer), blocks) in &sets_of {
        for validator in &rosters[pointer] {
            *in_set.entry(*week).or_default().entry(validator.owner).or_default() += blocks;
        }
    }
    for (week, validators) in &counted {
        if partial.is_some_and(|partial| *week <= partial) {
            continue;
        }
        let blocks = if *week == tally.week { tally.blocks } else { listed[week].blocks };
        ensure!(blocks_of.get(week).copied().unwrap_or(0) == blocks, "the blocks of a week differ from the block times");
        let rebuilt = in_set.remove(week).unwrap_or_default();
        for (owner, count) in validators {
            ensure!(rebuilt.get(owner).copied().unwrap_or(0) == count.in_set, "a validator's blocks in the set differ from the rosters");
        }
        for (owner, blocks) in &rebuilt {
            ensure!(validators.get(owner).is_some_and(|count| count.in_set == *blocks), "a validator of the rosters without its count");
        }
    }

    // Stake: the lots of every position add up to it.
    let check_lots = |lots: &Lots| -> Result<u64> {
        ensure!(
            !lots.lots.is_empty()
                && lots.lots.len() as u64 <= KEPT_WEEKS + 2
                && lots.lots.windows(2).all(|pair| pair[0].week < pair[1].week)
                && lots.lots.iter().all(|lot| lot.amount > 0 && lot.week <= current),
            "stake lots"
        );
        lots.total()
    };
    let mut bonds = 0u64;
    snapshot.for_each_prefix(BOND_PREFIX, |key, raw| {
        ensure!(key.len() == BOND_PREFIX.len() + 8, "bond lots key length");
        let validator = owner_of(key, BOND_PREFIX)?;
        let candidate: pos::Candidate = canonical_decode(
            &snapshot.get(&crate::pos_adapter::candidate_key(validator))?.ok_or_else(|| anyhow!("bond lots of no validator"))?,
        )?;
        ensure!(check_lots(&canonical_decode(raw)?)? == candidate.self_bond, "bond lots differ from the bond");
        bonds += 1;
        Ok(())
    })?;
    let mut bonded = 0u64;
    snapshot.for_each_prefix(b"pos/candidate/", |_, raw| {
        let candidate: pos::Candidate = canonical_decode(raw)?;
        if candidate.self_bond > 0 {
            bonded += 1;
        }
        Ok(())
    })?;
    ensure!(bonds == bonded, "a bond without its lots");
    let mut delegations = 0u64;
    snapshot.for_each_prefix(DELEGATION_PREFIX, |key, raw| {
        ensure!(key.len() == DELEGATION_PREFIX.len() + 16, "delegation lots key length");
        let validator = owner_of(key, DELEGATION_PREFIX)?;
        let owner = second_of(key, DELEGATION_PREFIX)?;
        let shares: String = canonical_decode(
            &snapshot.get(&crate::pos_adapter::position_key(validator, owner))?.ok_or_else(|| anyhow!("delegation lots of no position"))?,
        )?;
        ensure!(check_lots(&canonical_decode(raw)?)?.to_string() == shares, "delegation lots differ from the position");
        delegations += 1;
        Ok(())
    })?;
    let mut positions = 0u64;
    snapshot.for_each_prefix(b"pos/position/", |_, _| {
        positions += 1;
        Ok(())
    })?;
    ensure!(delegations == positions, "a delegation without its lots");
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lots(pairs: &[(u64, u64)]) -> Lots {
        Lots { lots: pairs.iter().map(|(week, amount)| Lot { week: *week, amount: *amount }).collect() }
    }

    #[test]
    fn what_goes_out_leaves_from_the_newest_lot_first() {
        let mut position = lots(&[(1, 100), (5, 50), (9, 30)]);
        position.withdraw(40).unwrap();
        assert_eq!(position, lots(&[(1, 100), (5, 40)]));
        position.withdraw(40).unwrap();
        assert_eq!(position, lots(&[(1, 100)]));
        position.deposit(12, 7).unwrap();
        position.deposit(12, 3).unwrap();
        assert_eq!(position, lots(&[(1, 100), (12, 10)]));
        assert!(position.clone().withdraw(111).is_err());
        position.withdraw(110).unwrap();
        assert!(position.lots.is_empty());
    }

    /// The lots older than N weeks hold the least the position held during
    /// those N weeks: what was in place without a break.
    #[test]
    fn the_old_lots_are_the_least_the_position_held_since() {
        let mut state = 0x5eedu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let mut position = Lots::default();
            let mut held: Vec<u64> = Vec::new();
            for week in 0..40u64 {
                for _ in 0..next() % 3 {
                    let total = position.total().unwrap();
                    if next() % 2 == 0 || total == 0 {
                        position.deposit(week, 1 + next() % 100).unwrap();
                    } else {
                        position.withdraw(1 + next() % total).unwrap();
                    }
                    position.merge(week).unwrap();
                    // What the position holds after every change, by week.
                    while held.len() <= week as usize {
                        held.push(u64::MAX);
                    }
                    held[week as usize] = held[week as usize].min(position.total().unwrap());
                }
                if held.len() <= week as usize {
                    held.push(position.total().unwrap());
                }
            }
            // For each N: the lots with week < 40 - N against the least
            // held from week 40 - N on (each week's least after a change,
            // and what it held when it began).
            let total = position.total().unwrap();
            for n in 1..40u64 {
                let since = 40 - n;
                let old: u64 = position.lots.iter().filter(|lot| lot.week < since).map(|lot| lot.amount).sum();
                let least = held[since as usize..].iter().copied().min().unwrap_or(total).min(total);
                assert!(old <= least, "{n}: {old} > {least}");
            }
        }
    }

    #[test]
    fn lots_beyond_the_horizon_merge_into_one_that_keeps_the_newest_week() {
        let mut position = lots(&[(0, 5), (1, 6), (2, 7), (60, 8)]);
        position.merge(60).unwrap();
        // 60 - 53 = 7: the three oldest are beyond it.
        assert_eq!(position, lots(&[(2, 18), (60, 8)]));
        position.merge(200).unwrap();
        assert_eq!(position, lots(&[(60, 26)]));
        // Never more than the horizon plus two lots.
        let mut busy = Lots::default();
        for week in 0..500u64 {
            busy.deposit(week, 1).unwrap();
            busy.merge(week).unwrap();
            assert!(busy.lots.len() as u64 <= KEPT_WEEKS + 2, "{}", busy.lots.len());
        }
        assert_eq!(busy.total().unwrap(), 500);
    }

    #[test]
    fn the_keys_of_the_records() {
        assert_eq!(account_record_key(7), [b"service/account/".as_slice(), &7u64.to_be_bytes()].concat());
        assert_eq!(punishment_key(1, 2).len(), PUNISHMENT_PREFIX.len() + 16);
        assert_eq!(missed_key(1, 2).len(), MISSED_PREFIX.len() + 16);
        assert_eq!(delegation_key(1, 2).len(), DELEGATION_PREFIX.len() + 16);
        // No namespace is a prefix of another, nor of the two single rows.
        let all: Vec<&[u8]> = NAMESPACES.iter().copied().chain([TALLY_KEY, WEEKS_KEY]).collect();
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert!(i == j || !b.starts_with(a), "{} {}", String::from_utf8_lossy(a), String::from_utf8_lossy(b));
            }
            assert!(a.starts_with(PREFIX));
        }
        assert_eq!(week_micros(pos::Profile::Production), 7 * 86_400 * 1_000_000);
        assert_eq!(week_micros(pos::Profile::Laboratory), 60 * 1_000_000);
    }
}
