//! Deterministic protocol-4 stake escrow. Account authorization, authenticated
//! row access and durable publication belong to the caller; no private keys,
//! premine, RPC trust, implicit reset or Bitcoin claims occur in this crate.
use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod evidence;
mod selection;
pub mod untrusted;
pub use evidence::*;
pub use selection::*;

pub const SECOND: u64 = 1_000_000;
pub const DAY: u64 = 86_400 * SECOND;
pub const SELF_BOND_MIN: u64 = 86_400 * SECOND;
pub const UNBOND_DELAY: u64 = 14 * DAY;
pub const MAX_CANDIDATES: usize = 256;
pub const MAX_VALIDATORS: usize = 100;
pub const MIN_FUNDED: usize = 7;
pub const MIN_ACTIVE: usize = 4;
pub const MAX_POSITIONS: usize = 64;
pub const MAX_EXITS: usize = 64;
/// The stake hand-over rule's target starts at this many times the starting
/// validators' combined power at genesis...
pub const HANDOVER_STAKE_MULTIPLE: u64 = 2;
/// ...and grows by this share, in parts per million, of all the time issued
/// since genesis: a fifth, as fast as validators are paid under the
/// protocol-4 issuance, so that stake which only bonds its rewards never
/// gains on the target by waiting.
pub const HANDOVER_SUPPLY_SHARE_PPM: u64 = 200_000;

/// The stake hand-over rule.
///
/// Under protocol 4 the virtual voting power of the starting validators
/// fades with the calendar alone once seven funded validators exist. Seven
/// minimum bonds of one owner then hold a third of the voting power after a
/// third of the fade period, two thirds before its end and everything at its
/// end, whatever else is staked.
///
/// With this rule the starting validators keep the network until
/// independent stake has proven itself, and then hand it over:
///
/// - The target is `target_power` plus `supply_share_ppm` of all the time
///   issued since genesis, in voting power (seconds of stake).
/// - Seated stake is independent stake: the voting power that validators
///   other than the starting validators hold in the roster in force, after
///   the concentration cap, the churn limit and the two-block delay. A
///   validator that asks to leave counts until the roster without it is in
///   force. The starting validators' own stake never counts, funded or not,
///   rewards they bonded included, and neither does stake delegated to them:
///   on a network whose starting validators are all run by one operator,
///   that operator's stake can never end its own bootstrap.
/// - Every unjailed starting validator holds the same virtual power, a
///   funded one on top of its own stake and of what is delegated to it, so
///   that together, with their own bonds, they hold the larger of the gap
///   between the target and the seated stake, and what keeps them above
///   everyone else together once everyone else holds the stake it asks for,
///   after the concentration cap. Stake delegated to them comes on top and
///   never lowers their part: its owner can take it out at any moment. None
///   gets less than a hundredth of its genesis power before the end. They
///   move first, as one group; nobody else's raise may take them below half,
///   and a starting validator's own exit moves the whole group with it
///   (`Summary::reconcile`). So until the end the total voting power the
///   rule asks for is at least the target, an outsider's share is at most its
///   seated stake divided by it, and everyone else together holds less than
///   half. Only a starting validator jailed for signing twice can take them
///   below half, until their next move, which the churn limit may spread
///   over an hour or more.
/// - The starting validators' virtual power is gone for good
///   (`bootstrap_ended`) once the calendar has run out, seven funded
///   validators other than theirs are in force, and seated stake has stayed
///   at the target for `Profile::handover_hold_micros` (fourteen days in
///   production) of block time. They then leave the roster as fast as the
///   churn limit allows. What they hold of their own stays theirs: an
///   operator that means to stop its validators takes its own stake out
///   first, at the pace of the churn limit, or the network loses the votes
///   of that stake when they stop.
///
/// What the half buys, and what it does not: with less than half, nobody
/// else can finalize a block without the starting validators (a block needs
/// two thirds). Block time, which the hold is counted in, cannot run ahead of
/// the validators' own clocks by more than CometBFT's `block_time_tolerance`
/// (60 seconds by default), which the node's clock check narrows to 30, so
/// nobody can bring the end forward by dating blocks. Anyone with more than a
/// third can still halt the network by not voting, as on any network of
/// this kind; the target is what a third of the votes costs. Who
/// gets the time to stake is partly the starting validators' choice: an
/// operator that sells everything they are paid to one buyer lets that buyer
/// approach half of the votes before the end, more than the third that halts
/// the network.
///
/// Each starting validator holds at least what the calendar leaves it, and
/// their virtual power lasts at least as long as under the calendar. The
/// rule gives the starting validators more power than they had at genesis,
/// and with it more of the validators' rewards, for as long as independent
/// stake stays below the target: on a network where few others stake, the
/// starting validators keep the network for as long as that lasts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StakeHandover {
    /// The target at genesis, in voting power (whole seconds of stake).
    #[serde(with = "decimal::u64")]
    pub target_power: u64,
    /// The share of all the time issued since genesis that the target grows
    /// by, in parts per million.
    #[serde(with = "decimal::u64")]
    pub supply_share_ppm: u64,
    /// Elapsed time at which the seated stake reached the target, while it
    /// has stayed there since.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "decimal::opt_u64"
    )]
    pub reached_at: Option<u64>,
}

impl StakeHandover {
    /// The rule of a network whose starting validators hold `starting` voting
    /// power between them at genesis.
    pub fn for_starting_power(starting: u64) -> Result<Self> {
        Ok(Self {
            target_power: starting
                .checked_mul(HANDOVER_STAKE_MULTIPLE)
                .ok_or_else(|| anyhow!("hand-over target overflow"))?,
            supply_share_ppm: HANDOVER_SUPPLY_SHARE_PPM,
            reached_at: None,
        })
    }
    /// Same parameters; `reached_at` is state, not a parameter.
    pub fn same_rule(&self, other: &Self) -> bool {
        self.target_power == other.target_power && self.supply_share_ppm == other.supply_share_ppm
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Production,
    Laboratory,
}
impl Profile {
    pub fn min_self_bond(self) -> u64 {
        match self {
            Self::Production => SELF_BOND_MIN,
            Self::Laboratory => SECOND,
        }
    }
    pub fn fade_micros(self) -> u64 {
        match self {
            Self::Production => 90 * DAY,
            Self::Laboratory => 60 * SECOND,
        }
    }
    pub fn churn_window(self) -> u64 {
        match self {
            Self::Production => 3600 * SECOND,
            Self::Laboratory => 20 * SECOND,
        }
    }
    pub fn churn_bucket(self) -> u64 {
        match self {
            Self::Production => 60 * SECOND,
            Self::Laboratory => SECOND,
        }
    }
    pub fn genesis_power(self) -> u64 {
        self.min_self_bond() / SECOND
    }
    /// How long the stake must stay at the target of the stake hand-over
    /// rule before the starting validators are gone for good.
    pub fn handover_hold_micros(self) -> u64 {
        match self {
            Self::Production => UNBOND_DELAY,
            Self::Laboratory => 60 * SECOND,
        }
    }
}

pub mod decimal {
    macro_rules! scalar {
        ($name:ident,$ty:ty) => {
            pub mod $name {
                use serde::{Deserialize, Deserializer, Serializer, de::Error};
                pub fn serialize<S: Serializer>(v: &$ty, s: S) -> Result<S::Ok, S::Error> {
                    s.serialize_str(&v.to_string())
                }
                pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<$ty, D::Error> {
                    let text = String::deserialize(d)?;
                    let value = text.parse::<$ty>().map_err(D::Error::custom)?;
                    if value.to_string() != text {
                        return Err(D::Error::custom("noncanonical decimal"));
                    }
                    Ok(value)
                }
            }
        };
    }
    scalar!(u64, u64);
    /// An optional decimal, written only when present (use with
    /// `default, skip_serializing_if = "Option::is_none"`).
    pub mod opt_u64 {
        use serde::{Deserialize, Deserializer, Serializer, de::Error};
        pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(v) => s.serialize_str(&v.to_string()),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
            let text = String::deserialize(d)?;
            let value = text.parse::<u64>().map_err(D::Error::custom)?;
            if value.to_string() != text {
                return Err(D::Error::custom("noncanonical decimal"));
            }
            Ok(Some(value))
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPool {
    #[serde(with = "decimal::u64")]
    pub assets: u64,
    #[serde(with = "decimal::u64")]
    pub units: u64,
}
impl ExitPool {
    fn deposit(&mut self, amount: u64) -> Result<u64> {
        ensure!(amount > 0, "zero exit amount");
        ensure!(
            self.units == 0 || self.assets > 0,
            "previous exit pool was fully slashed; clear its claims first"
        );
        let units = if self.units == 0 {
            amount
        } else {
            ratio(amount, self.units, self.assets)?
        };
        ensure!(units > 0, "exit amount too small");
        let next_units = add(self.units, units)?;
        if self.units > 0 {
            let remainder =
                amount as u128 * self.units as u128 - self.assets as u128 * units as u128;
            ensure!(
                remainder
                    .checked_mul(1000)
                    .ok_or_else(|| anyhow!("exit rounding overflow"))?
                    <= amount as u128 * next_units as u128,
                "exit loses more than0.1percent to rounding"
            );
        }
        let next_assets = add(self.assets, amount)?;
        self.assets = next_assets;
        self.units = next_units;
        Ok(units)
    }
    fn withdraw(&mut self, units: u64) -> Result<u64> {
        ensure!(units > 0 && units <= self.units, "invalid exit units");
        let amount = if units == self.units {
            self.assets
        } else {
            ratio(units, self.assets, self.units)?
        };
        self.assets -= amount;
        self.units -= units;
        Ok(amount)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRewardExit {
    #[serde(with = "decimal::u64")]
    pub release_height: u64,
    #[serde(with = "decimal::u64")]
    pub self_amount: u64,
    #[serde(with = "decimal::u64")]
    pub pool_amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    #[serde(with = "decimal::u64")]
    pub owner: u64,
    pub consensus_key: String,
    pub commission_bps: u16,
    #[serde(with = "decimal::u64")]
    pub self_bond: u64,
    #[serde(with = "decimal::u64")]
    pub pool_assets: u64,
    #[serde(with = "decimal::u64")]
    pub pool_shares: u64,
    pub self_exits: ExitPool,
    pub delegated_exits: ExitPool,
    /// Cash moved out of live capital whose old voting power still applies to
    /// rewards through the interval immediately before its H+2 release.
    pub pending_reward_exits: Vec<PendingRewardExit>,
    pub jailed: bool,
    pub genesis: bool,
    pub archived: bool,
    #[serde(with = "decimal::u64")]
    pub last_active_end: u64,
}
impl Candidate {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.owner != u64::MAX, "reserved stake owner");
        public_key(&self.consensus_key)?;
        ensure!(self.commission_bps <= 2000, "commission above20percent");
        ensure!(
            (self.pool_shares == 0) == (self.pool_assets == 0),
            "invalid live pool"
        );
        for pool in [&self.self_exits, &self.delegated_exits] {
            ensure!(pool.units > 0 || pool.assets == 0, "unowned exit assets");
        }
        ensure!(
            self.pending_reward_exits.len() <= 2
                && self
                    .pending_reward_exits
                    .windows(2)
                    .all(|pair| pair[0].release_height < pair[1].release_height)
                && self.pending_reward_exits.iter().all(|entry| {
                    entry.release_height >= 2 && (entry.self_amount > 0 || entry.pool_amount > 0)
                })
                && (!(self.jailed || self.archived) || self.pending_reward_exits.is_empty()),
            "pending reward-exit bounds/order"
        );
        let (own, pool) = self.pending_reward_exits.iter().try_fold(
            (0, 0),
            |(own, pool), entry| -> Result<_> {
                Ok((add(own, entry.self_amount)?, add(pool, entry.pool_amount)?))
            },
        )?;
        ensure!(
            own <= self.self_exits.assets && pool <= self.delegated_exits.assets,
            "pending reward weights exceed exit assets"
        );
        self.escrow()?;
        Ok(())
    }
    /// Persisted live rows retain only requests from the last two heights.
    pub fn validate_reward_height(&self, height: u64) -> Result<()> {
        self.validate()?;
        let upper = add(height, 2)?;
        ensure!(
            self.pending_reward_exits
                .iter()
                .all(|entry| entry.release_height > height && entry.release_height <= upper),
            "pending reward-exit height"
        );
        Ok(())
    }
    /// Call after paying rewards for height-1, before accepting height's exits.
    pub fn prune_reward_exits(&mut self, height: u64) {
        self.pending_reward_exits
            .retain(|entry| entry.release_height > height);
    }
    pub fn funded(&self, min_self_bond: u64) -> bool {
        !self.jailed && !self.archived && self.self_bond >= min_self_bond
    }
    pub fn escrow(&self) -> Result<u64> {
        add(
            add(self.self_bond, self.pool_assets)?,
            add(self.self_exits.assets, self.delegated_exits.assets)?,
        )
    }
    pub fn power(&self) -> Result<u64> {
        Ok(add(self.self_bond, self.pool_assets)? / SECOND)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Position {
    #[serde(with = "decimal::u64")]
    pub candidate: u64,
    #[serde(with = "decimal::u64")]
    pub shares: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitKind {
    SelfBond,
    Delegation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exit {
    #[serde(with = "decimal::u64")]
    pub id: u64,
    #[serde(with = "decimal::u64")]
    pub candidate: u64,
    pub kind: ExitKind,
    #[serde(with = "decimal::u64")]
    pub units: u64,
    #[serde(with = "decimal::u64")]
    pub requested_height: u64,
    #[serde(with = "decimal::u64")]
    pub release_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerStake {
    #[serde(with = "decimal::u64")]
    pub owner: u64,
    pub positions: Vec<Position>,
    pub exits: Vec<Exit>,
}
impl OwnerStake {
    pub fn new(owner: u64) -> Self {
        Self {
            owner,
            positions: Vec::new(),
            exits: Vec::new(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.owner != u64::MAX, "reserved stake owner");
        ensure!(
            self.positions.len() <= MAX_POSITIONS
                && self
                    .positions
                    .windows(2)
                    .all(|w| w[0].candidate < w[1].candidate)
                && self.positions.iter().all(|p| p.shares > 0),
            "position bounds/order"
        );
        ensure!(
            self.exits.len() <= MAX_EXITS
                && self.exits.windows(2).all(|w| w[0].id < w[1].id)
                && self
                    .exits
                    .iter()
                    .all(|e| e.units > 0
                        && e.requested_height.checked_add(2) == Some(e.release_height)),
            "exit bounds/order"
        );
        Ok(())
    }
}

/// Account movement is explicit. The caller must atomically debit/credit the
/// authenticated owner account and bank with these stake-row replacements.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Movement {
    pub debit: u64,
    pub credit: u64,
    pub bank_credit: u64,
    pub bank_debit: u64,
}

pub fn register_message(
    network: [u8; 32],
    owner: u64,
    key: &str,
    commission_bps: u16,
) -> Result<Vec<u8>> {
    let mut bytes = b"TIME-POS-REGISTER-V1\0".to_vec();
    bytes.extend(network);
    bytes.extend(owner.to_be_bytes());
    bytes.extend(hex32(key)?);
    bytes.extend(commission_bps.to_be_bytes());
    Ok(bytes)
}
pub fn register(
    network: [u8; 32],
    owner: u64,
    key: String,
    commission_bps: u16,
    proof: &[u8],
) -> Result<Candidate> {
    ensure!(commission_bps <= 2000, "commission cap");
    public_key(&key)?.verify_strict(
        &register_message(network, owner, &key, commission_bps)?,
        &Signature::from_slice(proof)?,
    )?;
    Ok(Candidate {
        owner,
        consensus_key: key,
        commission_bps,
        self_bond: 0,
        pool_assets: 0,
        pool_shares: 0,
        self_exits: ExitPool::default(),
        delegated_exits: ExitPool::default(),
        pending_reward_exits: Vec::new(),
        jailed: false,
        genesis: false,
        archived: false,
        last_active_end: 0,
    })
}
pub fn register_bonded(
    network: [u8; 32],
    owner: u64,
    key: String,
    commission: u16,
    proof: &[u8],
    profile: Profile,
) -> Result<(Candidate, Movement)> {
    let mut candidate = register(network, owner, key, commission, proof)?;
    let movement = bond_self(&mut candidate, profile.min_self_bond())?;
    Ok((candidate, movement))
}

pub fn bond_self(candidate: &mut Candidate, amount: u64) -> Result<Movement> {
    candidate.validate()?;
    ensure!(
        !candidate.jailed && !candidate.archived && amount > 0,
        "jailed or zero self bond"
    );
    let mut next = candidate.clone();
    next.self_bond = add(next.self_bond, amount)?;
    next.validate()?;
    *candidate = next;
    Ok(Movement {
        debit: amount,
        ..Default::default()
    })
}
pub fn delegate(
    candidate: &mut Candidate,
    owner: &mut OwnerStake,
    amount: u64,
    min_shares: u64,
) -> Result<Movement> {
    candidate.validate()?;
    owner.validate()?;
    ensure!(
        !candidate.jailed && !candidate.archived && amount > 0 && min_shares > 0,
        "invalid delegation"
    );
    let shares = if candidate.pool_shares == 0 {
        amount
    } else {
        ratio(amount, candidate.pool_shares, candidate.pool_assets)?
    };
    ensure!(shares >= min_shares && shares > 0, "share slippage");
    let total = add(candidate.pool_shares, shares)?;
    if candidate.pool_shares > 0 {
        let remainder = (amount as u128) * (candidate.pool_shares as u128)
            - (candidate.pool_assets as u128) * (shares as u128);
        ensure!(
            remainder
                .checked_mul(1000)
                .ok_or_else(|| anyhow!("rounding overflow"))?
                <= (amount as u128) * (total as u128),
            "delegation loses more than0.1percent to rounding"
        );
    }
    let mut next = owner.clone();
    match next
        .positions
        .binary_search_by_key(&candidate.owner, |p| p.candidate)
    {
        Ok(i) => next.positions[i].shares = add(next.positions[i].shares, shares)?,
        Err(i) => {
            ensure!(next.positions.len() < MAX_POSITIONS, "position cap");
            next.positions.insert(
                i,
                Position {
                    candidate: candidate.owner,
                    shares,
                },
            );
        }
    }
    let assets = add(candidate.pool_assets, amount)?;
    let mut next_candidate = candidate.clone();
    next_candidate.pool_assets = assets;
    next_candidate.pool_shares = total;
    next_candidate.validate()?;
    *candidate = next_candidate;
    *owner = next;
    Ok(Movement {
        debit: amount,
        ..Default::default()
    })
}

/// Root adapter must reserve the resulting full power reduction for H+2 using
/// reconcile(required_owner), otherwise discard all staged row changes.
pub fn unbond(
    candidate: &mut Candidate,
    owner: &mut OwnerStake,
    kind: ExitKind,
    quantity: u64,
    min_amount: u64,
    height: u64,
    id: u64,
) -> Result<Movement> {
    candidate.validate()?;
    owner.validate()?;
    ensure!(
        owner.exits.len() < MAX_EXITS && quantity > 0,
        "exit cap or zero amount"
    );
    let mut next = candidate.clone();
    next.prune_reward_exits(height);
    let mut next_owner = owner.clone();
    let (pool, amount) = match kind {
        ExitKind::SelfBond => {
            ensure!(
                owner.owner == candidate.owner && quantity <= next.self_bond,
                "self bond authority/amount"
            );
            next.self_bond -= quantity;
            (&mut next.self_exits, quantity)
        }
        ExitKind::Delegation => {
            let i = next_owner
                .positions
                .binary_search_by_key(&candidate.owner, |p| p.candidate)
                .map_err(|_| anyhow!("no delegation"))?;
            ensure!(
                quantity <= next_owner.positions[i].shares,
                "insufficient shares"
            );
            let amount = if quantity == next.pool_shares {
                next.pool_assets
            } else {
                ratio(quantity, next.pool_assets, next.pool_shares)?
            };
            ensure!(amount > 0, "zero unbond value");
            next.pool_assets -= amount;
            next.pool_shares -= quantity;
            next_owner.positions[i].shares -= quantity;
            if next_owner.positions[i].shares == 0 {
                next_owner.positions.remove(i);
            }
            (&mut next.delegated_exits, amount)
        }
    };
    ensure!(amount >= min_amount, "unbond slippage");
    let units = pool.deposit(amount)?;
    let release_height = height
        .checked_add(2)
        .ok_or_else(|| anyhow!("height exhausted"))?;
    if !next.archived && !next.jailed {
        let entry = match next.pending_reward_exits.last_mut() {
            Some(entry) if entry.release_height == release_height => entry,
            _ => {
                ensure!(
                    next.pending_reward_exits.len() < 2,
                    "reward-exit bucket cap"
                );
                next.pending_reward_exits.push(PendingRewardExit {
                    release_height,
                    self_amount: 0,
                    pool_amount: 0,
                });
                next.pending_reward_exits.last_mut().unwrap()
            }
        };
        match kind {
            ExitKind::SelfBond => entry.self_amount = add(entry.self_amount, amount)?,
            ExitKind::Delegation => entry.pool_amount = add(entry.pool_amount, amount)?,
        }
    }
    next_owner.exits.push(Exit {
        id,
        candidate: candidate.owner,
        kind,
        units,
        requested_height: height,
        release_height,
    });
    next_owner.validate()?;
    next.validate()?;
    *candidate = next;
    *owner = next_owner;
    Ok(Movement::default())
}

/// All clock arguments and Candidate.last_active_end are ELAPSED microseconds
/// since the pinned genesis, not absolute UTC time. release_time must come from
/// the authenticated accepted H+2 block timestamp minus genesis_time, never an
/// RPC assertion or the request timestamp.
pub fn withdraw(
    candidate: &mut Candidate,
    owner: &mut OwnerStake,
    id: u64,
    height: u64,
    now: u64,
    release_time: u64,
    self_still_active: bool,
) -> Result<Movement> {
    candidate.validate()?;
    owner.validate()?;
    let index = owner
        .exits
        .binary_search_by_key(&id, |e| e.id)
        .map_err(|_| anyhow!("no exit"))?;
    let exit = &owner.exits[index];
    ensure!(
        exit.candidate == candidate.owner && height >= exit.release_height,
        "wrong candidate or pending release height"
    );
    // A self exit remains collateral while this consensus identity still has
    // actual or scheduled authority. If removal was delayed past the original
    // H+2 reduction, its final active time starts a fresh exposure delay.
    let exposure_end = if exit.kind == ExitKind::SelfBond {
        release_time.max(candidate.last_active_end)
    } else {
        release_time
    };
    ensure!(
        now >= exposure_end
            .checked_add(UNBOND_DELAY)
            .ok_or_else(|| anyhow!("unlock overflow"))?,
        "unbond slash-exposure delay incomplete"
    );
    ensure!(
        exit.kind != ExitKind::SelfBond || !self_still_active,
        "self bond still protects active or scheduled votes"
    );
    let mut next = candidate.clone();
    next.prune_reward_exits(height);
    let pool = if exit.kind == ExitKind::SelfBond {
        &mut next.self_exits
    } else {
        &mut next.delegated_exits
    };
    let amount = pool.withdraw(exit.units)?;
    next.validate()?;
    *candidate = next;
    owner.exits.remove(index);
    Ok(Movement {
        credit: amount,
        ..Default::default()
    })
}
pub fn reward(candidate: &mut Candidate, amount: u64) -> Result<Movement> {
    reward_with_weights(candidate, amount, 0, None)
}

/// Split rewards by live capital, with commission only on delegated gross.
/// `height` is the current begin-block height paying height-1's actual roster.
/// Exits released at this height still withhold their fraction for that interval;
/// the adapter prunes them only after payment. Bootstrap power, when provided,
/// must be the previous actual power of an eligible genesis authority, and is
/// unavailable after the previous state's bootstrap handoff has completed.
/// Exiting capital and integer rounding retain their fraction in the bank.
pub fn reward_with_weights(
    candidate: &mut Candidate,
    amount: u64,
    height: u64,
    bootstrap_power: Option<u64>,
) -> Result<Movement> {
    candidate.validate()?;
    ensure!(
        !candidate.jailed && !candidate.archived,
        "inactive validator reward"
    );
    ensure!(
        bootstrap_power.is_none() || candidate.genesis,
        "virtual owner is not genesis"
    );
    let pending = candidate
        .pending_reward_exits
        .iter()
        .filter(|entry| entry.release_height >= height)
        .try_fold(0, |sum, entry| {
            add(add(sum, entry.self_amount)?, entry.pool_amount)
        })?;
    let live = add(candidate.self_bond, candidate.pool_assets)?;
    let capital = add(live, pending)?;
    let virtual_owner = match bootstrap_power {
        Some(power) => power
            .checked_mul(SECOND)
            .ok_or_else(|| anyhow!("virtual reward power overflow"))?
            .saturating_sub(capital),
        None => 0,
    };
    let owner_weight = add(candidate.self_bond, virtual_owner)?;
    let denominator = add(capital, virtual_owner)?;
    if denominator == 0 {
        return Ok(Movement::default());
    }
    let own_gross = ratio(amount, owner_weight, denominator)?;
    let delegated_gross = ratio(amount, candidate.pool_assets, denominator)?;
    let commission = ratio(delegated_gross, u64::from(candidate.commission_bps), 10_000)?;
    let assets = add(candidate.pool_assets, delegated_gross - commission)?;
    let mut next = candidate.clone();
    next.pool_assets = assets;
    next.validate()?;
    *candidate = next;
    Ok(Movement {
        credit: add(own_gross, commission)?,
        bank_debit: add(own_gross, delegated_gross)?,
        ..Default::default()
    })
}

/// Double signing forfeits all self collateral and 5% of live/departing
/// delegated assets. Exit units remain and redeem at their reduced pool NAV.
pub fn slash(candidate: &mut Candidate) -> Result<Movement> {
    candidate.validate()?;
    ensure!(!candidate.jailed, "validator already jailed/slashed");
    let own = add(candidate.self_bond, candidate.self_exits.assets)?;
    let delegated = candidate.pool_assets / 20;
    let departing = candidate.delegated_exits.assets / 20;
    let penalty = add(own, add(delegated, departing)?)?;
    candidate.self_bond = 0;
    candidate.self_exits.assets = 0;
    candidate.pool_assets -= delegated;
    candidate.delegated_exits.assets -= departing;
    candidate.jailed = true;
    candidate.pending_reward_exits.clear();
    Ok(Movement {
        bank_credit: penalty,
        ..Default::default()
    })
}

pub fn ratio(a: u64, b: u64, denominator: u64) -> Result<u64> {
    ensure!(denominator > 0, "zero denominator");
    Ok(u64::try_from(
        (a as u128) * (b as u128) / (denominator as u128),
    )?)
}
pub fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| anyhow!("stake arithmetic overflow"))
}
pub fn hex32(text: &str) -> Result<[u8; 32]> {
    ensure!(text.len() == 64, "public key length");
    let raw = hex::decode(text)?;
    ensure!(hex::encode(&raw) == text, "noncanonical hex");
    raw.try_into().map_err(|_| anyhow!("key size"))
}
pub fn public_key(text: &str) -> Result<VerifyingKey> {
    let bytes = hex32(text)?;
    let mut y = bytes;
    y[31] &= 127;
    let mut p = [255; 32];
    p[0] = 237;
    p[31] = 127;
    ensure!(
        y.iter().rev().cmp(p.iter().rev()).is_lt(),
        "noncanonical Ed25519 key"
    );
    let key = VerifyingKey::from_bytes(&bytes)?;
    ensure!(!key.is_weak(), "weak consensus key");
    Ok(key)
}

/// While the bootstrap lasts on a network that pays all new time to
/// validators, a starting validator is paid one part in this many of its own
/// reward; the rest is added to its stake (`reward_bonding_bootstrap`).
pub const BOOTSTRAP_PAID_PARTS: u64 = 20;

/// The reward rule of a network that pays all new time to validators
/// (version-5 genesis setting `all_new_time_to_validators`).
///
/// Without `bootstrap_power` it is `reward_with_weights`. With it, the reward
/// is split exactly as `reward_with_weights` splits it, but of the owner's
/// own part only one twentieth (`BOOTSTRAP_PAID_PARTS`) is paid out; the rest
/// is added to its self bond. Commission on the delegated part is still paid
/// out, and the delegated part still goes to the pool.
///
/// Why bond: a starting validator's power is lent to it by the bootstrap rule
/// and does not grow with its rewards. When all new time goes to validators,
/// anyone who keeps staking what it earns, and buys whatever the starting
/// validators sell, grows by up to the whole issuance while the lent power
/// stands still, and could end up outvoting them by waiting. Bonding most of
/// their own rewards makes their stake grow at nearly the rate of the
/// issuance, and keeps what anyone can buy small.
///
/// Why pay a part out: with nothing paid out, nobody would hold any time
/// while the bootstrap lasts (there is none at genesis), so nobody could pay
/// the fee of any action: not report a validator that signed twice, not
/// revoke a stolen key, not give anyone their first seconds. One twentieth
/// is many thousands of fees a day for each starting validator. In the
/// production profile, even if one buyer acquired everything the starting
/// validators are paid during the 90 days and staked it all, it would hold
/// about 12 to 15% of all stake when the bootstrap ends (a fifth paid out
/// would let it reach about 46% of the votes). The bound ends with the
/// bootstrap: from then on everything is paid out, and what the starting
/// validators do with it decides who holds the stake.
pub fn reward_bonding_bootstrap(
    candidate: &mut Candidate,
    amount: u64,
    height: u64,
    bootstrap_power: Option<u64>,
) -> Result<Movement> {
    let Some(power) = bootstrap_power else {
        return reward_with_weights(candidate, amount, height, None);
    };
    // The same checks and the same arithmetic as `reward_with_weights`; only
    // where the owner's part goes differs. Kept as a separate copy so that
    // the protocol-4 rule cannot change through this one.
    candidate.validate()?;
    ensure!(
        !candidate.jailed && !candidate.archived,
        "inactive validator reward"
    );
    ensure!(candidate.genesis, "virtual owner is not genesis");
    let pending = candidate
        .pending_reward_exits
        .iter()
        .filter(|entry| entry.release_height >= height)
        .try_fold(0, |sum, entry| {
            add(add(sum, entry.self_amount)?, entry.pool_amount)
        })?;
    let live = add(candidate.self_bond, candidate.pool_assets)?;
    let capital = add(live, pending)?;
    let virtual_owner = power
        .checked_mul(SECOND)
        .ok_or_else(|| anyhow!("virtual reward power overflow"))?
        .saturating_sub(capital);
    let owner_weight = add(candidate.self_bond, virtual_owner)?;
    let denominator = add(capital, virtual_owner)?;
    if denominator == 0 {
        return Ok(Movement::default());
    }
    let own_gross = ratio(amount, owner_weight, denominator)?;
    let delegated_gross = ratio(amount, candidate.pool_assets, denominator)?;
    let commission = ratio(delegated_gross, u64::from(candidate.commission_bps), 10_000)?;
    let paid = own_gross / BOOTSTRAP_PAID_PARTS;
    let mut next = candidate.clone();
    next.pool_assets = add(candidate.pool_assets, delegated_gross - commission)?;
    next.self_bond = add(candidate.self_bond, own_gross - paid)?;
    next.validate()?;
    let movement = Movement {
        credit: add(paid, commission)?,
        bank_debit: add(own_gross, delegated_gross)?,
        ..Default::default()
    };
    *candidate = next;
    Ok(movement)
}
