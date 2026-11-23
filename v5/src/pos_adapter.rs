//! Authenticated protocol-4 stake rows and account escrow movements.
use crate::engine::{ExtensionHost, block_time_key, canonical_decode};
use anyhow::{Result, anyhow, ensure};
use pos::{Candidate, ExitKind, Movement, OwnerStake, SetSnapshot, Summary, Validator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SUMMARY_KEY: &[u8] = b"pos/meta";
const BASELINE_KEY: &[u8] = b"pos/baseline"; // staged only, removed before publication
pub fn candidate_key(id: u64) -> Vec<u8> {
    [b"pos/candidate/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn owner_key(id: u64) -> Vec<u8> {
    [b"pos/owner/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn consensus_key(key: &str) -> Result<Vec<u8>> {
    Ok([b"pos/consensus/".as_slice(), &pos::hex32(key)?].concat())
}
pub fn roster_key(height: u64) -> Vec<u8> {
    [b"pos/roster/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn roster_at_key(height: u64) -> Vec<u8> {
    [b"pos/roster_at/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn updates_key(height: u64) -> Vec<u8> {
    [b"pos/updates/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn exit_key(id: u64) -> Vec<u8> {
    [b"pos/exit/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn position_key(candidate: u64, owner: u64) -> Vec<u8> {
    [
        b"pos/position/".as_slice(),
        &candidate.to_be_bytes(),
        &owner.to_be_bytes(),
    ]
    .concat()
}
pub fn claim_key(candidate: u64, id: u64) -> Vec<u8> {
    [
        b"pos/claim/".as_slice(),
        &candidate.to_be_bytes(),
        &id.to_be_bytes(),
    ]
    .concat()
}
pub fn release_refs_key(height: u64) -> Vec<u8> {
    [b"pos/release_refs/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn release_time_key(height: u64) -> Vec<u8> {
    [b"pos/release_time/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn release_claim_key(height: u64, id: u64) -> Vec<u8> {
    [
        b"pos/release_claim/".as_slice(),
        &height.to_be_bytes(),
        &id.to_be_bytes(),
    ]
    .concat()
}
pub fn evidence_key(hash: [u8; 32]) -> Vec<u8> {
    [b"pos/evidence/".as_slice(), &hash].concat()
}
/// ABCI `MisbehaviorType` values the automatic penalty acts on
/// (`misbehavior`). Every other value is skipped.
pub const DUPLICATE_VOTE: i32 = tendermint_proto::v0_38::abci::MisbehaviorType::DuplicateVote as i32;
pub const LIGHT_CLIENT_ATTACK: i32 =
    tendermint_proto::v0_38::abci::MisbehaviorType::LightClientAttack as i32;
/// Rows recording each misbehavior entry that was punished, so that the same
/// entry, reported again in the same block or in a later one, is never
/// punished twice. Key: this prefix ‖ type (1 byte: 1 duplicate vote, 2 light
/// client attack) ‖ consensus address (20 bytes) ‖ height of the offense (8
/// bytes, big-endian). Value: the height of the block that applied the
/// penalty, a decimal string, as for `evidence_key`. Never removed, like the
/// rows of kind 20; there is at most one per jailing.
pub const MISBEHAVIOR_PREFIX: &[u8] = b"pos/misbehavior/";
pub fn misbehavior_key(kind: u8, address: &[u8; 20], height: u64) -> Vec<u8> {
    [
        MISBEHAVIOR_PREFIX,
        &[kind],
        address.as_slice(),
        &height.to_be_bytes(),
    ]
    .concat()
}
/// One entry of the misbehavior list CometBFT delivers with a block (ABCI
/// `Misbehavior`): evidence that consensus verified and committed in that
/// block. The values are kept as they arrived and are judged by
/// `misbehavior`, which skips what it cannot use. The time and the voting
/// power CometBFT sends along are not used: the rule reads the time and the
/// roster of the offense height from this state, as kind 20 does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Misbehavior {
    /// ABCI `MisbehaviorType`: `DUPLICATE_VOTE` or `LIGHT_CLIENT_ATTACK`.
    pub kind: i32,
    /// The offender's consensus address: the first 20 bytes of the SHA-256
    /// of its Ed25519 key. Empty when CometBFT named no validator.
    pub address: Vec<u8>,
    /// The height of the offense. For a light client attack CometBFT reports
    /// the common height, at which the validators it names were in the
    /// validator set.
    pub height: i64,
}
/// The consensus address of a validator key, as CometBFT derives it.
pub(crate) fn consensus_address(key: &str) -> Option<[u8; 20]> {
    let key = pos::hex32(key).ok()?;
    Sha256::digest(key)[..20].try_into().ok()
}
/// Fees owed to the validators who signed the last block, in microseconds,
/// as a decimal string.
///
/// On a network that sets `fees_to_validators_ppm`, the validators' part of
/// the fees charged in a block is recorded here when the block ends. The
/// next block carries the signatures of that block, and its `begin_block`
/// adds the amount to the new time those signers share and pays both by one
/// rule. Fees are thus treated exactly like new time: what a validator that
/// did not sign or is jailed would have received stays in the bank, and so
/// does what the reward rule withholds and what does not divide. Nothing is
/// carried further, so in the block that pays, what a signer receives does
/// not depend on who else signed: leaving a signature out gains the others
/// nothing there. (A validator that is left out block after block earns
/// nothing, so its stake falls behind the others'. That was already so for
/// new time, and fees add to it.)
///
/// The amount is part of the bank until it is paid: the supply rule is
/// unchanged. The row lives from the end of one block to the start of the
/// next, only if the amount is not zero, and never on a network that keeps
/// fees in the bank.
pub const FEE_POOL_KEY: &[u8] = b"pos/fee_pool";
fn decode_fee_pool(raw: &[u8]) -> Result<u64> {
    let text: String = canonical_decode(raw)?;
    let value: u64 = text.parse()?;
    ensure!(value > 0 && value.to_string() == text, "fee pool amount");
    Ok(value)
}
/// The most one block can owe: a full block of transactions that each pay
/// the whole fee of this network. Zero on a network that keeps fees in the
/// bank.
pub fn fee_pool_limit(meta: &crate::engine::Meta) -> u64 {
    meta.config
        .validators_fee(crate::engine::MAX_BLOCK_TXS as u64 * meta.config.fee())
}
fn fee_pool(host: &impl ExtensionHost) -> Result<u64> {
    let fees = host
        .get(FEE_POOL_KEY)?
        .map_or(Ok(0), |raw| decode_fee_pool(&raw))?;
    ensure!(
        fees <= fee_pool_limit(host.meta()),
        "more fees owed than one block can charge"
    );
    Ok(fees)
}
fn set_fee_pool(host: &mut impl ExtensionHost, value: u64) -> Result<()> {
    if value > 0 {
        put(host, FEE_POOL_KEY.to_vec(), &value.to_string())
    } else if host.get(FEE_POOL_KEY)?.is_some() {
        host.put(FEE_POOL_KEY.to_vec(), None)
    } else {
        Ok(())
    }
}
/// Records the validators' part of the fees of the block that is ending.
pub fn collect_fees(host: &mut impl ExtensionHost, fees: u64) -> Result<()> {
    if fees == 0 {
        return Ok(());
    }
    // `begin_block` paid out and removed what the block before left.
    ensure!(fee_pool(host)? == 0, "fees of an earlier block were not paid");
    ensure!(
        fees <= host.meta().bank && fees <= fee_pool_limit(host.meta()),
        "fees owed to validators exceed the bank or what one block can charge"
    );
    set_fee_pool(host, fees)
}
fn put(host: &mut impl ExtensionHost, key: Vec<u8>, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if host.get(&key)?.as_ref() == Some(&bytes) {
        return Ok(());
    }
    host.put(key, Some(bytes))
}
fn required<T: serde::de::DeserializeOwned + Serialize>(
    host: &impl ExtensionHost,
    key: &[u8],
) -> Result<T> {
    canonical_decode(&host.get(key)?.ok_or_else(|| anyhow!("missing PoS row"))?)
}
pub fn summary(host: &impl ExtensionHost) -> Result<Summary> {
    let value: Summary = required(host, SUMMARY_KEY)?;
    value.validate()?;
    let config = &host.meta().config;
    ensure!(
        value.profile == config.profile
            && value.escrow == host.meta().pos_assets_total
            && value.handover_matches(config.stake_handover, config.validators.len())?,
        "PoS meta mirror mismatch"
    );
    Ok(value)
}
fn candidates(host: &impl ExtensionHost, s: &Summary) -> Result<Vec<Candidate>> {
    s.candidate_ids
        .iter()
        .map(|text| {
            let id: u64 = text.parse()?;
            let row: Candidate = required(host, &candidate_key(id))?;
            row.validate_reward_height(s.last_height)?;
            ensure!(
                !row.archived
                    && row.owner == id
                    && host.get(&consensus_key(&row.consensus_key)?)?
                        == Some(serde_json::to_vec(&text)?),
                "candidate index mismatch"
            );
            Ok(row)
        })
        .collect()
}
fn owner(host: &impl ExtensionHost, id: u64) -> Result<OwnerStake> {
    let row = match host.get(&owner_key(id))? {
        Some(raw) => canonical_decode(&raw)?,
        None => OwnerStake::new(id),
    };
    row.validate()?;
    ensure!(row.owner == id, "stake owner key mismatch");
    Ok(row)
}
fn save_summary(host: &mut impl ExtensionHost, s: &Summary) -> Result<()> {
    s.validate()?;
    host.set_pos_assets(s.escrow)?;
    put(host, SUMMARY_KEY.to_vec(), s)
}
fn movement(host: &mut impl ExtensionHost, id: u64, effect: Movement) -> Result<()> {
    host.debit(id, effect.debit)?;
    host.credit(id, effect.credit)?;
    host.bank_credit(effect.bank_credit)?;
    host.bank_debit(effect.bank_debit)
}
fn elapsed_at(host: &impl ExtensionHost, height: u64) -> Result<u64> {
    let text: String = required(host, &block_time_key(height))?;
    let absolute: i64 = text.parse()?;
    ensure!(absolute.to_string() == text, "noncanonical block time");
    Ok(u64::try_from(
        absolute
            .checked_sub(host.meta().genesis.genesis_time_micros)
            .ok_or_else(|| anyhow!("block clock overflow"))?,
    )?)
}
fn release_elapsed_at(host: &impl ExtensionHost, height: u64) -> Result<u64> {
    let text: String = required(host, &release_time_key(height))?;
    let absolute: i64 = text.parse()?;
    ensure!(
        absolute.to_string() == text,
        "noncanonical retained release clock"
    );
    Ok(u64::try_from(
        absolute
            .checked_sub(host.meta().genesis.genesis_time_micros)
            .ok_or_else(|| anyhow!("release clock overflow"))?,
    )?)
}
fn release_count(host: &impl ExtensionHost, height: u64) -> Result<u64> {
    match host.get(&release_refs_key(height))? {
        None => Ok(0),
        Some(raw) => {
            let text: String = canonical_decode(&raw)?;
            let count: u64 = text.parse()?;
            ensure!(
                count > 0 && count.to_string() == text,
                "release reference count"
            );
            Ok(count)
        }
    }
}
pub fn roster_at(
    mut get: impl FnMut(&[u8]) -> Result<Option<Vec<u8>>>,
    height: u64,
) -> Result<Vec<Validator>> {
    let raw = get(&roster_at_key(height))?.ok_or_else(|| anyhow!("missing roster pointer"))?;
    let pointer: String = canonical_decode(&raw)?;
    let effective: u64 = pointer.parse()?;
    ensure!(
        effective.to_string() == pointer && effective <= height,
        "invalid roster pointer"
    );
    let row: SetSnapshot = canonical_decode(
        &get(&roster_key(effective))?.ok_or_else(|| anyhow!("missing historical roster"))?,
    )?;
    ensure!(
        row.effective_height == effective,
        "roster key coordinate mismatch"
    );
    pos::validate_set(&row.validators)?;
    Ok(row.validators)
}
#[derive(Default)]
pub struct BlockChanges {
    pub validators: Vec<Validator>,
    pub updates: Vec<Validator>,
}

pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    ensure!(host.get(SUMMARY_KEY)?.is_none(), "PoS already initialized");
    let config = host.meta().config.clone();
    let validators = config
        .validators
        .iter()
        .map(|v| Validator {
            owner: v.owner,
            consensus_key: v.consensus_key.clone(),
            power: config.profile.genesis_power(),
        })
        .collect::<Vec<_>>();
    let s = Summary::with_rules(validators.clone(), config.profile, config.stake_handover)?;
    for v in &config.validators {
        let candidate = Candidate {
            owner: v.owner,
            consensus_key: v.consensus_key.clone(),
            commission_bps: v.commission_bps,
            self_bond: 0,
            pool_assets: 0,
            pool_shares: 0,
            self_exits: Default::default(),
            delegated_exits: Default::default(),
            pending_reward_exits: Vec::new(),
            jailed: false,
            genesis: true,
            archived: false,
            last_active_end: 0,
        };
        candidate.validate()?;
        host.account(v.owner)?;
        put(host, candidate_key(v.owner), &candidate)?;
        put(host, consensus_key(&v.consensus_key)?, &v.owner.to_string())?;
    }
    put(
        host,
        roster_key(0),
        &SetSnapshot {
            announced_height: 0,
            effective_height: 0,
            validators,
        },
    )?;
    put(host, roster_at_key(0), &"0")?;
    put(host, updates_key(0), &Vec::<Validator>::new())?;
    save_summary(host, &s)
}
/// `proposer` is the consensus address the block's header names; only the
/// service records read it (`crate::service::record_block`).
pub fn begin_block(
    host: &mut impl ExtensionHost,
    eligible: &[String],
    delta: u64,
    proposer: &[u8],
) -> Result<BlockChanges> {
    let mut s = summary(host)?;
    let mut rows = candidates(host, &s)?;
    let old = s.active.clone();
    let old_bootstrap_ended = s.bootstrap_ended;
    put(host, BASELINE_KEY.to_vec(), &s.latest().to_vec())?;
    let height = u64::try_from(host.meta().height)?;
    let now = host.meta().elapsed_micros()?;
    let activation = s.begin_block(height, now, &mut rows)?;
    let pointer = if let Some(set) = activation {
        put(host, roster_key(set.effective_height), &set)?;
        set.effective_height
    } else {
        let previous: String = required(host, &roster_at_key(height - 1))?;
        previous.parse()?
    };
    put(host, roster_at_key(height), &pointer.to_string())?;
    if release_count(host, height)? > 0 {
        put(
            host,
            release_time_key(height),
            &host.meta().time_micros.to_string(),
        )?;
    }
    let allowed: BTreeSet<_> = old.iter().map(|v| v.consensus_key.as_str()).collect();
    let mut seen = BTreeSet::new();
    ensure!(
        eligible
            .iter()
            .all(|key| allowed.contains(key.as_str()) && seen.insert(key)),
        "reward eligibility outside previous actual roster"
    );
    let total = old.iter().try_fold(0, |sum, v| pos::add(sum, v.power))?;
    // A fifth of the new time, and with it the validators' part of the fees
    // of the block these validators signed (see `FEE_POOL_KEY`).
    let fees = fee_pool(host)?;
    let issued = delta.min(60 * pos::SECOND);
    let budget = pos::add(host.meta().config.validators_issuance(issued), fees)?;
    // Not under the stake hand-over rule (see `Genesis::all_new_time_to_validators`).
    let bond_bootstrap =
        host.meta().config.all_new_time_to_validators && !host.meta().config.stake_handover;
    if fees > 0 {
        set_fee_pool(host, 0)?;
    }
    for validator in &old {
        if !seen.contains(&validator.consensus_key) {
            continue;
        }
        let candidate = rows
            .iter_mut()
            .find(|c| c.owner == validator.owner)
            .ok_or_else(|| anyhow!("missing reward candidate"))?;
        if candidate.jailed {
            continue;
        }
        let amount = pos::ratio(budget, validator.power, total)?;
        let before = candidate.escrow()?;
        let bootstrap_power =
            (candidate.genesis && !old_bootstrap_ended).then_some(validator.power);
        // On a network that pays all new time to validators, a starting
        // validator's own reward is bonded while its power is lent to it
        // (see `Genesis::all_new_time_to_validators`).
        let bond_before = candidate.self_bond;
        let effect = if bond_bootstrap {
            pos::reward_bonding_bootstrap(candidate, amount, height, bootstrap_power)?
        } else {
            pos::reward_with_weights(candidate, amount, height, bootstrap_power)?
        };
        s.escrow = s
            .escrow
            .checked_sub(before)
            .and_then(|v| v.checked_add(candidate.escrow().ok()?))
            .ok_or_else(|| anyhow!("reward escrow overflow"))?;
        movement(host, candidate.owner, effect)?;
        // A reward bonded for a starting validator is new stake.
        let (owner, bond_after) = (candidate.owner, candidate.self_bond);
        crate::service::bond_changed(host, owner, bond_before, bond_after)?;
    }
    for candidate in &mut rows {
        candidate.prune_reward_exits(height);
        candidate.validate_reward_height(height)?;
        if !candidate.funded(s.profile.min_self_bond())
            && !s.current_or_scheduled(candidate.owner)
            && s.exposure_expired(candidate)?
        {
            s.retire_candidate(candidate)?;
        }
    }
    let active: Vec<_> = rows.iter().filter(|c| !c.archived).cloned().collect();
    s.reconcile(&active, None)?;
    persist_candidates(host, &mut s, rows)?;
    save_summary(host, &s)?;
    // The service records count the commit this block carries, for the set
    // that was to sign it, and the proposer of this block among this
    // block's set. (Nothing of this runs on a network without them.)
    if host.meta().config.service_records {
        let proposer = s
            .active
            .iter()
            .find(|validator| proposer.len() == 20 && consensus_address(&validator.consensus_key).is_some_and(|address| address[..] == *proposer))
            .map(|validator| validator.owner);
        crate::service::record_block(host, height, &old, &seen, proposer)?;
    }
    Ok(BlockChanges {
        validators: s.active,
        updates: Vec::new(),
    })
}
pub fn finalize(host: &mut impl ExtensionHost) -> Result<BlockChanges> {
    let mut s = summary(host)?;
    let rows = candidates(host, &s)?;
    s.reconcile(&rows, None)?;
    let old: Vec<Validator> = required(host, BASELINE_KEY)?;
    let updates = pos::validator_updates(&old, s.latest())?;
    for set in &s.scheduled {
        put(host, roster_key(set.effective_height), set)?;
    }
    put(host, updates_key(host.meta().height as u64), &updates)?;
    host.put(BASELINE_KEY.to_vec(), None)?;
    save_summary(host, &s)?;
    Ok(BlockChanges {
        validators: s.active,
        updates,
    })
}
/// Punishes the misbehavior CometBFT reports with a block. Rule of version 5
/// only (protocol 4 ignores the list). The engine calls it after the
/// begin-block steps and before the block's transactions, so an entry is
/// punished exactly as an evidence action (kind 20) at the head of the block
/// would be, without anyone having to submit one: `pos::slash` (all self
/// collateral and 5% of the delegated stake go to the bank, the validator is
/// jailed), the escrow total adjusted, the movement applied, the roster
/// reconciled (a jailed validator leaves it at H+2 and the validator safety
/// hold is on while it is still in it) and a replay row written
/// (`misbehavior_key`). Unlike kind 20 there is no submitter: no fee, no
/// nonce, no stake row of a submitter.
///
/// The list is part of the block, and every honest node must reach the same
/// state from it, so no entry can make this fail. An entry is skipped, with
/// no effect at all, when
/// 1. its type is neither `DUPLICATE_VOTE` nor `LIGHT_CLIENT_ATTACK`;
/// 2. it names no validator, or an address that is not 20 bytes long;
/// 3. its height is not a committed height whose history this state still
///    holds: not positive, not below this block's height, or at or below
///    `Meta::history_pruned_through`;
/// 4. the same entry (type, address, height) was punished before, earlier in
///    the list or in an earlier block;
/// 5. the address is not that of a validator of the roster at that height,
///    nor, for a light client attack, of a current candidate that has been a
///    validator after that height (CometBFT reports such an attack at the
///    common height but may name validators of the later, conflicting
///    height; a duplicate vote always names one of its own height);
/// 6. that validator is no longer a candidate: archived, or its row is gone
///    (archiving waits until the slash window of its last active height has
///    passed, so 9 below would skip it as well);
/// 7. its candidate row has another consensus key than the roster had (keys
///    are never reused, so this cannot happen; kind 20 refuses it too);
/// 8. it is already jailed, by kind 20, by an earlier entry or by an earlier
///    block: an offender is punished once, as `pos::slash` requires;
/// 9. the offense is older than the slash window, `pos::UNBOND_DELAY` before
///    this block, which kind 20 refuses as well. (CometBFT may still report
///    such evidence: its own limit is the longer of 14 days and 2,000,000
///    blocks.)
///
/// A block whose entries are all skipped changes nothing here. Only a state
/// that fails its own checks makes this return an error.
pub fn misbehavior(host: &mut impl ExtensionHost, entries: &[Misbehavior]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut s = summary(host)?;
    let mut rows = candidates(host, &s)?;
    // `begin_block` has moved the summary to this block.
    let current = s.last_height;
    let now = s.last_elapsed;
    let pruned = host.meta().history_pruned_through;
    // Each roster is decoded once, however many entries name its heights.
    let mut rosters: BTreeMap<String, Vec<([u8; 20], Validator)>> = BTreeMap::new();
    let mut punished = false;
    for entry in entries {
        // 1.
        let kind: u8 = match entry.kind {
            DUPLICATE_VOTE => 1,
            LIGHT_CLIENT_ATTACK => 2,
            _ => continue,
        };
        // 2.
        let Ok(address) = <[u8; 20]>::try_from(entry.address.as_slice()) else {
            continue;
        };
        // 3.
        let Ok(height) = u64::try_from(entry.height) else {
            continue;
        };
        if height == 0 || height >= current || height <= pruned {
            continue;
        }
        // 4.
        let replay = misbehavior_key(kind, &address, height);
        if host.get(&replay)?.is_some() {
            continue;
        }
        // The rows of a retained height exist; a missing one is a broken
        // state, not a bad entry.
        let elapsed = elapsed_at(host, height)?;
        // 5.
        let pointer: String = required(host, &roster_at_key(height))?;
        if !rosters.contains_key(&pointer) {
            let members = roster_at(|key| host.get(key), height)?
                .into_iter()
                .filter_map(|v| consensus_address(&v.consensus_key).map(|a| (a, v)))
                .collect();
            rosters.insert(pointer.clone(), members);
        }
        let member = rosters[&pointer]
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .map(|(_, v)| (v.owner, v.consensus_key.clone()));
        let (owner, key) = match member {
            Some(member) => member,
            // A light client attack is reported at the common height, but
            // when it is an equivocation CometBFT names validators of the
            // conflicting height's set (`GetByzantineValidators`), which may
            // have joined since. Such an offender is the current candidate
            // with that address, if it has been a validator after that
            // height: in the roster now, or removed from it later.
            None if kind == 2 => {
                let Some(row) = rows.iter().find(|c| {
                    consensus_address(&c.consensus_key) == Some(address)
                        && (c.last_active_end > elapsed
                            || s.active
                                .iter()
                                .any(|v| v.owner == c.owner && v.consensus_key == c.consensus_key))
                }) else {
                    continue;
                };
                (row.owner, row.consensus_key.clone())
            }
            None => continue,
        };
        // 6.
        let Some(index) = rows.iter().position(|c| c.owner == owner) else {
            continue;
        };
        // 7. and 8.
        if rows[index].consensus_key != key || rows[index].jailed {
            continue;
        }
        // 9.
        if now
            .checked_sub(elapsed)
            .is_none_or(|age| age > pos::UNBOND_DELAY)
        {
            continue;
        }
        // The penalty of kind 20.
        let row = &mut rows[index];
        let before = row.escrow()?;
        let bond_before = row.self_bond;
        let effect = pos::slash(row)?;
        s.escrow = adjust(s.escrow, before, row.escrow()?)?;
        let bond_after = row.self_bond;
        movement(host, owner, effect)?;
        crate::service::bond_changed(host, owner, bond_before, bond_after)?;
        let cause = if kind == 1 { crate::service::Cause::DuplicateVote } else { crate::service::Cause::LightClientAttack };
        crate::service::punished(host, owner, &key, cause, height)?;
        let active: Vec<_> = rows.iter().filter(|c| !c.archived).cloned().collect();
        s.reconcile(&active, None)?;
        put(host, replay, &s.last_height.to_string())?;
        punished = true;
    }
    if punished {
        persist_candidates(host, &mut s, rows)?;
        save_summary(host, &s)?;
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    consensus_key: String,
    commission_bps: u16,
    proof: String,
    #[serde(default)]
    self_bond: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Amount {
    #[serde(with = "pos::decimal::u64")]
    amount: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfUnbond {
    #[serde(with = "pos::decimal::u64")]
    amount: u64,
    #[serde(with = "pos::decimal::u64")]
    min_amount: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
pub fn apply(host: &mut impl ExtensionHost, action: &crate::wire::SignedAction) -> Result<()> {
    let mut s = summary(host)?;
    let mut rows = candidates(host, &s)?;
    let mut owner = owner(host, action.from)?;
    let previous_owner = owner.clone();
    let target = match action.kind {
        18 | 19 | 24 => Some(action.from),
        5 | 6 => Some(
            action.payload["operator"]
                .as_str()
                .ok_or_else(|| anyhow!("missing candidate"))?
                .parse::<u64>()?,
        ),
        7 | 21 => {
            let entry = action.payload["entry"]
                .as_str()
                .ok_or_else(|| anyhow!("missing exit"))?
                .parse::<u64>()?;
            Some(
                owner
                    .exits
                    .iter()
                    .find(|e| e.id == entry)
                    .ok_or_else(|| anyhow!("unknown exit"))?
                    .candidate,
            )
        }
        _ => None,
    };
    let mut archive_before = None;
    if let Some(id) = target
        && !rows.iter().any(|c| c.owner == id)
    {
        let row: Candidate = required(host, &candidate_key(id))?;
        row.validate()?;
        ensure!(
            row.owner == id
                && row.archived
                && host.get(&consensus_key(&row.consensus_key)?)?
                    == Some(serde_json::to_vec(&id.to_string())?),
            "inactive candidate mismatch"
        );
        archive_before = Some((id, row.escrow()?));
        rows.push(row);
    }
    // Own bonds before the action, for the age of stake (service records).
    let bonds_before: BTreeMap<u64, u64> = rows.iter().map(|row| (row.owner, row.self_bond)).collect();

    let mut required_owner = None;
    let mut effect = Movement::default();
    let mut recipient = action.from;
    match action.kind {
        17 => {
            let p: Register = serde_json::from_value(action.payload.clone())?;
            ensure!(
                host.get(&candidate_key(action.from))?.is_none(),
                "existing candidate/archive must settle before re-registration"
            );
            ensure!(
                host.get(&consensus_key(&p.consensus_key)?)?.is_none(),
                "consensus key was already reserved"
            );
            let network = pos::hex32(&host.meta().network_id)?;
            let (mut row, mut move_) = pos::register_bonded(
                network,
                action.from,
                p.consensus_key.clone(),
                p.commission_bps,
                &hex::decode(p.proof)?,
                s.profile,
            )?;
            if let Some(text) = p.self_bond {
                let amount: u64 = text.parse()?;
                ensure!(
                    amount.to_string() == text && amount >= s.profile.min_self_bond(),
                    "registration self bond below minimum or noncanonical"
                );
                let extra = amount - s.profile.min_self_bond();
                if extra > 0 {
                    pos::bond_self(&mut row, extra)?;
                }
                move_.debit = amount;
            }
            s.admit_with_priority(&row, &mut rows)?;
            effect = move_;
            put(
                host,
                consensus_key(&p.consensus_key)?,
                &action.from.to_string(),
            )?;
            crate::service::registered(host, action.from, &p.consensus_key)?;
            rows.push(row);
            rows.sort_by_key(|c| c.owner);
        }
        18 => {
            let p: Amount = serde_json::from_value(action.payload.clone())?;
            let row = rows
                .iter_mut()
                .find(|c| c.owner == action.from)
                .ok_or_else(|| anyhow!("not a candidate"))?;
            let before = row.escrow()?;
            effect = pos::bond_self(row, p.amount)?;
            s.escrow = adjust(s.escrow, before, row.escrow()?)?;
        }
        5 => {
            let p: timecurrency_node::ledger::Delegate =
                serde_json::from_value(action.payload.clone())?;
            let row = rows
                .iter_mut()
                .find(|c| c.owner == p.operator)
                .ok_or_else(|| anyhow!("unknown candidate"))?;
            let before = row.escrow()?;
            effect = pos::delegate(row, &mut owner, p.amount, p.min_shares)?;
            s.escrow = adjust(s.escrow, before, row.escrow()?)?;
        }
        6 | 19 => {
            let (candidate, kind, quantity, min) = if action.kind == 6 {
                let p: timecurrency_node::ledger::Undelegate =
                    serde_json::from_value(action.payload.clone())?;
                (p.operator, ExitKind::Delegation, p.shares, p.min_amount)
            } else {
                let p: SelfUnbond = serde_json::from_value(action.payload.clone())?;
                (action.from, ExitKind::SelfBond, p.amount, p.min_amount)
            };
            let row = rows
                .iter_mut()
                .find(|c| c.owner == candidate)
                .ok_or_else(|| anyhow!("unknown candidate"))?;
            let before = row.escrow()?;
            effect = pos::unbond(
                row,
                &mut owner,
                kind,
                quantity,
                min,
                s.last_height,
                s.next_exit_id,
            )?;
            ensure!(
                host.get(&exit_key(s.next_exit_id))?.is_none(),
                "duplicate stake exit ID"
            );
            put(host, exit_key(s.next_exit_id), &action.from.to_string())?;
            s.next_exit_id = pos::add(s.next_exit_id, 1)?;
            s.escrow = adjust(s.escrow, before, row.escrow()?)?;
            required_owner = if row.archived { None } else { Some(candidate) };
        }
        7 | 21 => {
            let p: timecurrency_node::ledger::Withdraw =
                serde_json::from_value(action.payload.clone())?;
            let exit = owner
                .exits
                .iter()
                .find(|e| e.id == p.entry)
                .ok_or_else(|| anyhow!("unknown exit"))?
                .clone();
            let release = release_elapsed_at(host, exit.release_height)?;
            let active = s.current_or_scheduled(exit.candidate);
            let row = rows
                .iter_mut()
                .find(|c| c.owner == exit.candidate)
                .ok_or_else(|| anyhow!("missing exit candidate"))?;
            let before = row.escrow()?;
            effect = pos::withdraw(
                row,
                &mut owner,
                p.entry,
                s.last_height,
                s.last_elapsed,
                release,
                active,
            )?;
            s.escrow = adjust(s.escrow, before, row.escrow()?)?;
            ensure!(
                host.get(&exit_key(p.entry))?
                    == Some(serde_json::to_vec(&action.from.to_string())?),
                "stake exit owner index mismatch"
            );
            host.put(exit_key(p.entry), None)?;
        }
        20 => {
            ensure!(
                serde_json::to_vec(&action.payload)?.len() <= 32 * 1024,
                "evidence size limit"
            );
            let proof: pos::DoubleSignEvidence = serde_json::from_value(action.payload.clone())?;
            let height = proof.first.height.value();
            let history = pos::HistoricalMembership {
                height,
                elapsed_micros: elapsed_at(host, height)?,
                validators: roster_at(|key| host.get(key), height)?,
            };
            // Checked with the signature rule consensus itself applies.
            let (id, replay) = crate::evidence::verify_double_sign(
                &host.meta().genesis.chain_id,
                &proof,
                &history,
                s.last_elapsed,
            )?;
            ensure!(
                host.get(&evidence_key(replay))?.is_none(),
                "evidence replay"
            );
            let row = rows
                .iter_mut()
                .find(|c| c.owner == id)
                .ok_or_else(|| anyhow!("missing offender candidate"))?;
            ensure!(
                history
                    .validators
                    .iter()
                    .any(|v| v.owner == id && v.consensus_key == row.consensus_key),
                "historic consensus key mismatch"
            );
            let before = row.escrow()?;
            effect = pos::slash(row)?;
            s.escrow = adjust(s.escrow, before, row.escrow()?)?;
            recipient = id;
            put(host, evidence_key(replay), &s.last_height.to_string())?;
            let consensus_key = row.consensus_key.clone();
            crate::service::punished(host, id, &consensus_key, crate::service::Cause::Evidence, height)?;
        }
        24 => {
            let _: Empty = serde_json::from_value(action.payload.clone())?;
            let i = rows
                .iter()
                .position(|c| c.owner == action.from)
                .ok_or_else(|| anyhow!("not a candidate"))?;
            s.retire_candidate(&mut rows[i])?;
        }
        23 => anyhow::bail!(
            "consensus key rotation is not enabled; retire and register after exposure"
        ),
        _ => anyhow::bail!("unsupported PoS action"),
    }
    if let Some((id, before)) = archive_before {
        let row = rows
            .iter()
            .find(|c| c.owner == id)
            .ok_or_else(|| anyhow!("archive target missing"))?;
        s.archived_escrow = adjust(s.archived_escrow, before, row.escrow()?)?;
    }
    movement(host, recipient, effect)?;
    let active: Vec<_> = rows.iter().filter(|c| !c.archived).cloned().collect();
    s.reconcile(&active, required_owner)?;
    // The age of stake (service records): every own bond and every position
    // this action changed. A new validator had none before.
    if host.meta().config.service_records {
        for row in &rows {
            let before = bonds_before.get(&row.owner).copied().unwrap_or(0);
            crate::service::bond_changed(host, row.owner, before, row.self_bond)?;
        }
        crate::service::positions_changed(host, &previous_owner, &owner)?;
    }
    persist_candidates(host, &mut s, rows)?;
    owner.validate()?;
    sync_owner(host, &previous_owner, &owner)?;
    put(host, owner_key(owner.owner), &owner)?;
    save_summary(host, &s)
}
fn persist_candidates(
    host: &mut impl ExtensionHost,
    s: &mut Summary,
    rows: Vec<Candidate>,
) -> Result<()> {
    for candidate in rows {
        if candidate.archived
            && candidate.escrow()? == 0
            && candidate.pool_shares == 0
            && candidate.self_exits.units == 0
            && candidate.delegated_exits.units == 0
        {
            s.clear_archive(&candidate)?;
            host.put(candidate_key(candidate.owner), None)?;
        } else {
            put(host, candidate_key(candidate.owner), &candidate)?;
        }
    }
    Ok(())
}
fn sync_owner(host: &mut impl ExtensionHost, old: &OwnerStake, new: &OwnerStake) -> Result<()> {
    if old == new {
        return Ok(());
    }
    for position in &old.positions {
        let key = position_key(position.candidate, old.owner);
        ensure!(
            host.get(&key)? == Some(serde_json::to_vec(&position.shares.to_string())?),
            "position backlink corrupt"
        );
        if !new
            .positions
            .iter()
            .any(|p| p.candidate == position.candidate)
        {
            host.put(key, None)?;
        }
    }
    for position in &new.positions {
        put(
            host,
            position_key(position.candidate, new.owner),
            &position.shares.to_string(),
        )?;
    }
    for exit in &old.exits {
        let key = claim_key(exit.candidate, exit.id);
        ensure!(
            host.get(&key)? == Some(serde_json::to_vec(&old.owner.to_string())?),
            "claim backlink corrupt"
        );
        let refs = release_count(host, exit.release_height)?;
        ensure!(
            refs > 0
                && host.get(&release_claim_key(exit.release_height, exit.id))?
                    == Some(serde_json::to_vec(&old.owner.to_string())?),
            "release claim backlink corrupt"
        );
        if !new.exits.iter().any(|e| e.id == exit.id) {
            host.put(key, None)?;
            host.put(release_claim_key(exit.release_height, exit.id), None)?;
            if refs == 1 {
                host.put(release_refs_key(exit.release_height), None)?;
                host.put(release_time_key(exit.release_height), None)?;
            } else {
                put(
                    host,
                    release_refs_key(exit.release_height),
                    &(refs - 1).to_string(),
                )?;
            }
        }
    }
    for exit in &new.exits {
        put(
            host,
            claim_key(exit.candidate, exit.id),
            &new.owner.to_string(),
        )?;
        if !old.exits.iter().any(|e| e.id == exit.id) {
            ensure!(
                host.get(&release_claim_key(exit.release_height, exit.id))?
                    .is_none(),
                "duplicate release claim"
            );
            let refs = pos::add(release_count(host, exit.release_height)?, 1)?;
            put(
                host,
                release_refs_key(exit.release_height),
                &refs.to_string(),
            )?;
            put(
                host,
                release_claim_key(exit.release_height, exit.id),
                &new.owner.to_string(),
            )?;
        }
    }
    Ok(())
}
fn adjust(total: u64, old: u64, new: u64) -> Result<u64> {
    total
        .checked_sub(old)
        .and_then(|v| v.checked_add(new))
        .ok_or_else(|| anyhow!("PoS escrow delta overflow"))
}

/// Independently stream owner positions/claims and compare with bounded pool
/// totals. All underlying leaves/directories have already been authenticated.
pub fn audit(
    snapshot: &crate::store::VerifiedAudit<'_>,
    meta: &crate::engine::Meta,
) -> Result<u64> {
    let s: Summary = canonical_decode(
        &snapshot
            .get(SUMMARY_KEY)?
            .ok_or_else(|| anyhow!("missing stake summary"))?,
    )?;
    s.validate()?;
    ensure!(
        s.profile == meta.config.profile
            && s.handover_matches(meta.config.stake_handover, meta.config.validators.len())?
            && s.escrow == meta.pos_assets_total
            && s.last_height == meta.height as u64
            && s.last_elapsed == meta.elapsed_micros()?,
        "stake summary mismatch"
    );
    let mut count = 1u64;
    let mut escrow = 0u64;
    let mut archived_escrow = 0u64;
    let mut active_count = 0usize;
    let mut archived_count = 0u64;
    let mut positions = 0u64;
    let mut claims = 0u64;
    // Consensus address of every candidate row: whether it is jailed or
    // archived (for the misbehavior rows below).
    let mut punishable: BTreeMap<[u8; 20], bool> = BTreeMap::new();
    snapshot.for_each_prefix(b"pos/candidate/", |key, raw| {
        let candidate: Candidate = canonical_decode(raw)?;
        candidate.validate_reward_height(s.last_height)?;
        if let Some(address) = consensus_address(&candidate.consensus_key) {
            punishable.insert(address, candidate.jailed || candidate.archived);
        }
        let id = candidate.owner;
        ensure!(key == candidate_key(id), "candidate key identity mismatch");
        if candidate.archived {
            ensure!(
                !s.candidate_ids.contains(&id.to_string()) && !s.current_or_scheduled(id),
                "archived candidate retains eligibility"
            );
            archived_escrow = pos::add(archived_escrow, candidate.escrow()?)?;
            archived_count += 1;
        } else {
            ensure!(
                s.candidate_ids.contains(&id.to_string()),
                "candidate directory orphan"
            );
            active_count += 1;
        }
        ensure!(
            snapshot.get(&consensus_key(&candidate.consensus_key)?)?
                == Some(serde_json::to_vec(&id.to_string())?)
                && snapshot.get(&crate::engine::account_key(id))?.is_some(),
            "candidate key/owner backlink mismatch"
        );
        escrow = pos::add(escrow, candidate.escrow()?)?;
        let mut shares = 0u64;
        let mut self_units = 0u64;
        let mut delegated_units = 0u64;
        let prefix = [b"pos/position/".as_slice(), &id.to_be_bytes()].concat();
        snapshot.for_each_prefix(&prefix, |key, value| {
            ensure!(key.len() == prefix.len() + 8, "position index key length");
            let owner_id = u64::from_be_bytes(key[prefix.len()..].try_into()?);
            let text: String = canonical_decode(value)?;
            let amount: u64 = text.parse()?;
            ensure!(
                amount > 0 && amount.to_string() == text,
                "position index amount"
            );
            let owner: OwnerStake = canonical_decode(
                &snapshot
                    .get(&owner_key(owner_id))?
                    .ok_or_else(|| anyhow!("position owner missing"))?,
            )?;
            ensure!(
                owner.owner == owner_id
                    && owner
                        .positions
                        .iter()
                        .any(|p| p.candidate == id && p.shares == amount),
                "orphan position index"
            );
            shares = pos::add(shares, amount)?;
            positions += 1;
            Ok(())
        })?;
        let prefix = [b"pos/claim/".as_slice(), &id.to_be_bytes()].concat();
        snapshot.for_each_prefix(&prefix, |key, value| {
            ensure!(key.len() == prefix.len() + 8, "claim index key length");
            let exit_id = u64::from_be_bytes(key[prefix.len()..].try_into()?);
            let text: String = canonical_decode(value)?;
            let owner_id: u64 = text.parse()?;
            ensure!(owner_id.to_string() == text, "claim owner index");
            let owner: OwnerStake = canonical_decode(
                &snapshot
                    .get(&owner_key(owner_id))?
                    .ok_or_else(|| anyhow!("claim owner missing"))?,
            )?;
            let exit = owner
                .exits
                .iter()
                .find(|e| e.id == exit_id && e.candidate == id)
                .ok_or_else(|| anyhow!("orphan candidate claim"))?;
            if exit.kind == ExitKind::SelfBond {
                ensure!(owner_id == id, "foreign self collateral claim");
                self_units = pos::add(self_units, exit.units)?;
            } else {
                delegated_units = pos::add(delegated_units, exit.units)?;
            }
            claims += 1;
            Ok(())
        })?;
        ensure!(
            shares == candidate.pool_shares
                && self_units == candidate.self_exits.units
                && delegated_units == candidate.delegated_exits.units,
            "independent candidate claim/share totals differ"
        );
        count += 1;
        Ok(())
    })?;
    ensure!(
        active_count == s.candidate_ids.len()
            && archived_count == s.archived_candidates
            && archived_escrow == s.archived_escrow
            && escrow == s.escrow,
        "candidate count/escrow summary mismatch"
    );
    for v in s
        .active
        .iter()
        .chain(s.scheduled.iter().flat_map(|r| &r.validators))
    {
        let row: Candidate = canonical_decode(
            &snapshot
                .get(&candidate_key(v.owner))?
                .ok_or_else(|| anyhow!("missing roster candidate"))?,
        )?;
        ensure!(
            !row.archived && row.consensus_key == v.consensus_key,
            "roster candidate mismatch"
        );
    }
    let mut owner_positions = 0u64;
    let mut exits = 0u64;
    snapshot.for_each_prefix(b"pos/owner/", |key, raw| {
        let row: OwnerStake = canonical_decode(raw)?;
        row.validate()?;
        ensure!(
            key == owner_key(row.owner)
                && snapshot
                    .get(&crate::engine::account_key(row.owner))?
                    .is_some(),
            "stake owner identity mismatch"
        );
        for p in &row.positions {
            ensure!(
                snapshot.get(&candidate_key(p.candidate))?.is_some()
                    && snapshot.get(&position_key(p.candidate, row.owner))?
                        == Some(serde_json::to_vec(&p.shares.to_string())?),
                "position candidate/index mismatch"
            );
            owner_positions += 1;
        }
        for e in &row.exits {
            ensure!(
                snapshot.get(&release_claim_key(e.release_height, e.id))?
                    == Some(serde_json::to_vec(&row.owner.to_string())?),
                "owner release claim index missing"
            );
            ensure!(
                e.id < s.next_exit_id
                    && snapshot.get(&exit_key(e.id))?
                        == Some(serde_json::to_vec(&row.owner.to_string())?)
                    && snapshot.get(&claim_key(e.candidate, e.id))?
                        == Some(serde_json::to_vec(&row.owner.to_string())?)
                    && snapshot.get(&candidate_key(e.candidate))?.is_some(),
                "exit candidate/index mismatch"
            );
            exits += 1;
        }
        count += 1;
        Ok(())
    })?;
    ensure!(
        positions == owner_positions && claims == exits,
        "candidate/owner index cardinality mismatch"
    );
    count = pos::add(count, pos::add(positions, claims)?)?;
    let mut exit_count = 0;
    snapshot.for_each_prefix(b"pos/exit/", |key, raw| {
        ensure!(key.len() == 17, "exit key length");
        let id = u64::from_be_bytes(key[9..].try_into()?);
        let text: String = canonical_decode(raw)?;
        let owner_id: u64 = text.parse()?;
        ensure!(owner_id.to_string() == text, "noncanonical owner index");
        let owner: OwnerStake = canonical_decode(
            &snapshot
                .get(&owner_key(owner_id))?
                .ok_or_else(|| anyhow!("orphan exit index"))?,
        )?;
        ensure!(owner.exits.iter().any(|e| e.id == id), "orphan exit index");
        exit_count += 1;
        count += 1;
        Ok(())
    })?;
    ensure!(exit_count == exits, "exit index count mismatch");
    let mut release_claims = 0u64;
    let mut release_times = 0u64;
    snapshot.for_each_prefix(b"pos/release_refs/", |key, raw| {
        ensure!(key.len() == 25, "release reference key length");
        let height = u64::from_be_bytes(key[17..].try_into()?);
        ensure!(
            height
                <= s.last_height
                    .checked_add(2)
                    .ok_or_else(|| anyhow!("height exhausted"))?,
            "release reference from future"
        );
        let text: String = canonical_decode(raw)?;
        let references: u64 = text.parse()?;
        ensure!(
            references > 0 && references.to_string() == text,
            "release reference count invalid"
        );
        let mut found = 0u64;
        let prefix = [b"pos/release_claim/".as_slice(), &height.to_be_bytes()].concat();
        snapshot.for_each_prefix(&prefix, |key, raw| {
            ensure!(key.len() == prefix.len() + 8, "release claim key length");
            let id = u64::from_be_bytes(key[prefix.len()..].try_into()?);
            let owner_text: String = canonical_decode(raw)?;
            let owner_id: u64 = owner_text.parse()?;
            ensure!(
                owner_id.to_string() == owner_text,
                "release owner index invalid"
            );
            let owner: OwnerStake = canonical_decode(
                &snapshot
                    .get(&owner_key(owner_id))?
                    .ok_or_else(|| anyhow!("release owner missing"))?,
            )?;
            ensure!(
                owner
                    .exits
                    .iter()
                    .any(|e| e.id == id && e.release_height == height),
                "orphan release claim"
            );
            found += 1;
            Ok(())
        })?;
        ensure!(
            found == references,
            "release reference independent recount mismatch"
        );
        release_claims = pos::add(release_claims, found)?;
        let clock = snapshot.get(&release_time_key(height))?;
        if height <= s.last_height {
            let raw = clock.ok_or_else(|| anyhow!("mature release clock missing"))?;
            let text: String = canonical_decode(&raw)?;
            let absolute: i64 = text.parse()?;
            ensure!(
                absolute.to_string() == text
                    && absolute >= meta.genesis.genesis_time_micros
                    && absolute <= meta.time_micros,
                "retained release clock outside history"
            );
            if let Some(recent) = snapshot.get(&block_time_key(height))? {
                ensure!(recent == raw, "retained/recent release clock mismatch");
            }
            release_times += 1;
        } else {
            ensure!(clock.is_none(), "future release clock already exists");
        }
        count += 1;
        Ok(())
    })?;
    ensure!(release_claims == exits, "release claim count mismatch");
    count = pos::add(count, pos::add(release_claims, release_times)?)?;
    // Addresses of every consensus key ever reserved.
    let mut reserved: BTreeSet<[u8; 20]> = BTreeSet::new();
    snapshot.for_each_prefix(b"pos/consensus/", |key, raw| {
        ensure!(key.len() == 46, "consensus index key length");
        pos::public_key(&hex::encode(&key[14..]))?;
        reserved.insert(Sha256::digest(&key[14..])[..20].try_into()?);
        let text: String = canonical_decode(raw)?;
        let id: u64 = text.parse()?;
        ensure!(
            id.to_string() == text && snapshot.get(&crate::engine::account_key(id))?.is_some(),
            "historic consensus owner missing"
        );
        count += 1;
        Ok(())
    })?;
    let start = meta
        .history_pruned_through
        .checked_add(1)
        .ok_or_else(|| anyhow!("history cursor exhausted"))?;
    let mut first_pointer = 0u64;
    let mut previous: Vec<Validator> = Vec::new();
    snapshot.for_each_prefix(b"pos/roster/", |key, raw| {
        let row: SetSnapshot = canonical_decode(raw)?;
        pos::validate_set(&row.validators)?;
        ensure!(
            key == roster_key(row.effective_height)
                && ((row.effective_height == 0 && row.announced_height == 0)
                    || row.announced_height.checked_add(2) == Some(row.effective_height))
                && row.effective_height
                    <= s.last_height
                        .checked_add(2)
                        .ok_or_else(|| anyhow!("height exhausted"))?,
            "roster archive coordinates"
        );
        for v in &row.validators {
            ensure!(
                snapshot.get(&consensus_key(&v.consensus_key)?)?
                    == Some(serde_json::to_vec(&v.owner.to_string())?),
                "roster historic key mismatch"
            );
        }
        if row.effective_height <= start {
            first_pointer = row.effective_height;
        }
        if row.effective_height <= start + 1 {
            previous = row.validators;
        }
        count += 1;
        Ok(())
    })?;
    ensure!(!previous.is_empty(), "missing initial/recent roster");
    let mut pointer_count = 0u64;
    let mut last_pointer = first_pointer;
    snapshot.for_each_prefix(b"pos/roster_at/", |key, raw| {
        ensure!(key.len() == 22, "roster pointer key length");
        let height = u64::from_be_bytes(key[14..].try_into()?);
        let text: String = canonical_decode(raw)?;
        let pointer: u64 = text.parse()?;
        ensure!(pointer.to_string() == text, "noncanonical roster pointer");
        if height == 0 {
            ensure!(pointer == 0, "initial roster pointer invalid");
            count += 1;
            return Ok(());
        }
        ensure!(
            height == start + pointer_count,
            "recent roster pointer history gap"
        );
        let expected = if snapshot.get(&roster_key(height))?.is_some() {
            height
        } else {
            last_pointer
        };
        ensure!(
            pointer == expected,
            "roster pointer did not activate exactH+2"
        );
        last_pointer = pointer;
        pointer_count += 1;
        count += 1;
        Ok(())
    })?;
    ensure!(
        pointer_count == s.last_height - meta.history_pruned_through,
        "recent roster pointer history incomplete"
    );
    ensure!(
        roster_at(|key| snapshot.get(key), s.last_height)? == s.active,
        "actual roster summary mismatch"
    );
    let mut update_count = 0u64;
    snapshot.for_each_prefix(b"pos/updates/", |key, raw| {
        ensure!(key.len() == 20, "validator update key length");
        let height = u64::from_be_bytes(key[12..].try_into()?);
        let updates: Vec<Validator> = canonical_decode(raw)?;
        if height == 0 {
            ensure!(updates.is_empty(), "initial updates nonempty");
            count += 1;
            return Ok(());
        }
        ensure!(
            height == start + update_count,
            "recent validator update history gap"
        );
        let next = snapshot
            .get(&roster_key(height + 2))?
            .map(|raw| canonical_decode::<SetSnapshot>(&raw).map(|r| r.validators))
            .transpose()?
            .unwrap_or_else(|| previous.clone());
        ensure!(
            updates == pos::validator_updates(&previous, &next)?,
            "durable Comet update mismatch"
        );
        previous = next;
        update_count += 1;
        count += 1;
        Ok(())
    })?;
    ensure!(
        update_count == s.last_height - meta.history_pruned_through && previous == s.latest(),
        "recent validator update history incomplete"
    );
    snapshot.for_each_prefix(b"pos/evidence/", |key, raw| {
        ensure!(key.len() == 45, "evidence index key length");
        let text: String = canonical_decode(raw)?;
        let height: u64 = text.parse()?;
        ensure!(
            height.to_string() == text && height <= s.last_height,
            "evidence index coordinates"
        );
        count += 1;
        Ok(())
    })?;
    // Misbehavior reported by CometBFT and punished (`misbehavior`): a
    // known type, an offense before the block that punished it, and an
    // offender that is jailed or archived, or whose archived row has since
    // been cleared (its consensus key stays reserved).
    snapshot.for_each_prefix(MISBEHAVIOR_PREFIX, |key, raw| {
        ensure!(
            key.len() == MISBEHAVIOR_PREFIX.len() + 29,
            "misbehavior index key length"
        );
        let address: [u8; 20] = key[MISBEHAVIOR_PREFIX.len() + 1..key.len() - 8].try_into()?;
        ensure!(
            punishable
                .get(&address)
                .map_or(reserved.contains(&address), |punished| *punished),
            "misbehavior row names an offender that is neither jailed nor archived"
        );
        let kind = key[MISBEHAVIOR_PREFIX.len()];
        let offense = u64::from_be_bytes(key[key.len() - 8..].try_into()?);
        let text: String = canonical_decode(raw)?;
        let height: u64 = text.parse()?;
        ensure!(
            matches!(kind, 1 | 2)
                && height.to_string() == text
                && offense > 0
                && offense < height
                && height <= s.last_height,
            "misbehavior index coordinates"
        );
        count += 1;
        Ok(())
    })?;
    ensure!(
        snapshot.get(BASELINE_KEY)?.is_none(),
        "uncommitted PoS baseline leaked"
    );
    if let Some(raw) = snapshot.get(FEE_POOL_KEY)? {
        ensure!(
            meta.config.fees_to_validators_ppm > 0
                && decode_fee_pool(&raw)? <= meta.bank.min(fee_pool_limit(meta)),
            "fee pool without the rule, above the bank, or above what one block can charge"
        );
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_misbehavior_row_is_keyed_by_type_address_and_height() {
        // The ABCI values the rule acts on, and the byte each is recorded as.
        assert_eq!((DUPLICATE_VOTE, LIGHT_CLIENT_ATTACK), (1, 2));
        let key = misbehavior_key(2, &[7; 20], 0x0102_0304_0506_0708);
        assert_eq!(key.len(), MISBEHAVIOR_PREFIX.len() + 29);
        assert!(key.starts_with(b"pos/misbehavior/"));
        assert_eq!(key[16], 2);
        assert_eq!(key[17..37], [7; 20]);
        assert_eq!(key[37..], [1, 2, 3, 4, 5, 6, 7, 8]);
        // Different type, address or height: a different row.
        assert_ne!(key, misbehavior_key(1, &[7; 20], 0x0102_0304_0506_0708));
        assert_ne!(key, misbehavior_key(2, &[8; 20], 0x0102_0304_0506_0708));
        assert_ne!(key, misbehavior_key(2, &[7; 20], 0x0102_0304_0506_0709));
        // The address is the one CometBFT derives from a consensus key.
        let public = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[101; 32])
                .verifying_key()
                .as_bytes(),
        );
        let digest = Sha256::digest(hex::decode(&public).unwrap());
        assert_eq!(consensus_address(&public).unwrap()[..], digest[..20]);
        assert_eq!(consensus_address("not a key"), None);
    }
}
