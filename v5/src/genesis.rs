use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use timecurrency_node::ledger;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapValidator {
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    pub consensus_key: String,
    pub commission_bps: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuctionConfig {
    #[serde(with = "pos::decimal::u64")]
    pub epoch_seconds: u64,
    #[serde(with = "pos::decimal::u64")]
    pub bid_lead_epochs: u64,
    #[serde(with = "pos::decimal::u64")]
    pub max_future_epochs: u64,
    #[serde(with = "pos::decimal::u64")]
    pub min_sats: u64,
    #[serde(with = "pos::decimal::u64")]
    pub max_sats: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub history_version: u8,
    pub bitcoin_receipt_version: u8,
    pub reward_version: u8,
    pub ledger: ledger::Genesis,
    pub profile: pos::Profile,
    pub validators: Vec<BootstrapValidator>,
    pub bitcoin: bitcoin_bridge::BridgeConfig,
    pub treasury: treasury::Policy,
    pub auction: AuctionConfig,
    pub registration: registration::Config,
    #[serde(with = "pos::decimal::u64")]
    pub recovery_min_delay_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub recovery_approval_window_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub trusting_period_seconds: u64,
    /// Parts per million of the action fees of a block that the network pays
    /// on to the validators who signed it (`pos_adapter::begin_block`). Absent
    /// means zero, the protocol-4 rule: fees stay in the bank. The field is
    /// written only when it is set, and zero cannot be written, so a network
    /// that does not use the rule has one encoding, the protocol-4 one, and
    /// keeps its network id.
    #[serde(
        default,
        skip_serializing_if = "is_zero",
        serialize_with = "pos::decimal::u64::serialize",
        deserialize_with = "set_share"
    )]
    pub fees_to_validators_ppm: u64,
    /// What an account action costs, in microseconds of currency. Absent
    /// means `ledger::FEE_MICROS` (1,000), the protocol-4 fee; a network can
    /// set a lower one, from 1 to 999. Like the share above, the field is
    /// written only when it is set, and the protocol-4 fee cannot be written,
    /// so a network that keeps that fee has one encoding, the protocol-4 one,
    /// and keeps its network id. Read it with `fee()`.
    ///
    /// A fee above the protocol-4 fee is not possible: the protocol-4 rules,
    /// which this engine applies unchanged, charge that fee themselves, and
    /// the engine can only stand in for the part a payer does not owe
    /// (`engine::Overlay::apply_legacy`).
    #[serde(
        default = "protocol_fee",
        skip_serializing_if = "is_protocol_fee",
        serialize_with = "pos::decimal::u64::serialize",
        deserialize_with = "set_fee"
    )]
    pub fee_micros: u64,
    /// All of the new time of each block goes to the validators who signed
    /// it, and through them to the people who stake with them, by the
    /// protocol-4 reward rule (`pos_adapter::begin_block`). Absent means the
    /// protocol-4 rule: a fifth of the new time to those validators, the rest
    /// sold for bitcoin at the auction or left in the bank.
    ///
    /// A network with this setting has no bitcoin auction: the bitcoin relay,
    /// bitcoin receipts, auction claims and treasury governance (kinds 40,
    /// 41, 42 and 60 to 63) are refused (`engine::Overlay::apply`). Its
    /// genesis still carries the bitcoin, treasury and auction sections,
    /// which are checked as on any network and otherwise unused.
    ///
    /// While the starting validators' voting power is still lent to them by
    /// the bootstrap rule, only a twentieth of the part of their reward that
    /// is theirs is paid out; the rest is added to their own stake
    /// (`pos::reward_bonding_bootstrap`, which explains the numbers). Their
    /// lent power does not grow with the rewards; anyone who kept staking
    /// rewards that are all of the new time, and bought what they sell,
    /// would otherwise gain on them until it could outvote them.
    ///
    /// The lent power ends only once at least seven validators are active and
    /// all of them stand on their own stake (`pos::Summary::begin_block`). On
    /// a network with fewer validators it never ends, and its starting
    /// validators go on being paid a twentieth of their own reward.
    ///
    /// On a network that also has `stake_handover`, nothing is bonded for
    /// them: that rule keeps them above half of the voting power by itself
    /// until it ends, and ends only on stake other than theirs, which can
    /// come only from what they are paid.
    ///
    /// The setting needs at least five starting validators. With four, one
    /// slashed validator leaves fewer clean validators than the roster needs;
    /// the validator safety hold then refuses every ordinary action, and only
    /// a newly registered validator could end it. Nobody else would hold any
    /// time with which to register one.
    ///
    /// Written only when it is set, as `true`; `false` cannot be written. A
    /// network without it keeps the protocol-4 encoding and its network id.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "set_true")]
    pub all_new_time_to_validators: bool,
    /// The starting validators keep more than half of the voting power, and
    /// stand in for the independent stake that is missing from a target,
    /// until independent stake has held the target for fourteen days
    /// (`pos::StakeHandover`). Absent means the protocol-4 rule: their power
    /// fades with the calendar alone. Written only when it is set, as `true`,
    /// after `all_new_time_to_validators` (only `distinct_names` and the
    /// settings after it can follow); `false` cannot be written. The
    /// production profile requires it.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "set_handover")]
    pub stake_handover: bool,
    /// The network refuses a new account name that looks like a name that
    /// exists: one whose skeleton (`crate::names::skeleton`) an existing
    /// name has, or whose skeleton is empty. The state keeps one row per
    /// name, `name_skeleton/` followed by the skeleton, from the genesis
    /// accounts on (`crate::names`). Absent means the protocol-4 rule: only
    /// the same name twice is refused, and there are no such rows.
    ///
    /// The rule protects the names of a network that had it from its first
    /// block. It is not a rule that can be switched on later: names
    /// registered without it may look alike already.
    ///
    /// Written only when it is set, as `true`, after `stake_handover` (only
    /// the settings below can follow it); `false` cannot be written. A
    /// network without it keeps the protocol-4 encoding and its network id.
    /// The production profile requires it.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "set_distinct")]
    pub distinct_names: bool,
    /// The waits and freezes of the account security rules do not run while
    /// the chain is stopped. They are counted on the active clock
    /// (`engine::Meta::active_micros`): the chain's time minus the total of
    /// all stops, where a stop is the part of the gap between a block and
    /// its parent beyond five minutes (`security::STOP_THRESHOLD_MICROS`,
    /// the clock's own threshold; the upgrade rule keeps its hour). The
    /// total is the field
    /// `stopped_micros` of the metadata row. `crate::security` says which
    /// comparisons use the clock. Absent means the protocol-4 clock, the
    /// chain's time: a chain that was stopped comes back with every wait
    /// shorter by the length of the stop.
    ///
    /// Written only when it is set, as `true`, after `distinct_names`;
    /// `false` cannot be written. A network without it keeps the protocol-4
    /// encoding, its network id and its metadata row. The production
    /// profile requires it.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "set_waits")]
    pub waits_survive_stops: bool,
    /// An account can exist protected from its first block. The reveal of a
    /// sponsored registration can carry the set of keys and the policy of
    /// the account security rules (kind 45, `security::REGISTER`), and this
    /// genesis can list accounts that start with one (`protected_accounts`).
    /// Absent means the protocol-4 rule: every account starts with one key
    /// that can do everything, and adopts the rules later, for a fee.
    ///
    /// Written only when it is set, as `true`, after `waits_survive_stops`;
    /// `false` cannot be written. A network without it keeps the protocol-4
    /// encoding and its network id, and refuses kind 45. The production
    /// profile requires it.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "set_protected")]
    pub protected_registration: bool,
    /// The genesis accounts that start protected: for each, its keys in
    /// their roles and its policy, as the action `secure` would set them.
    /// Such an account starts with these keys in place of its identity key,
    /// and with its security row. Only on a network with
    /// `protected_registration`. Sorted by account id, each account once.
    ///
    /// Written after `protected_registration`, and only when it names an
    /// account: an empty list cannot be written. (Only `service_records` can
    /// follow it.)
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "set_accounts")]
    pub protected_accounts: Vec<ProtectedAccount>,
    /// The network keeps service records from its first block
    /// (`crate::service`): when each validator was registered, by owner and
    /// by consensus key; how many blocks it was to sign and signed, and who
    /// proposed the blocks without its signature, week by week; every
    /// punishment; how long each stake position has been in place; and
    /// when each account was created. **No rule reads them**: they are
    /// facts recorded for rules that may be decided later, which could not
    /// measure the time before the records began. Absent means the
    /// protocol-4 state: no such rows.
    ///
    /// Written only when it is set, as `true`, last of all; `false` cannot
    /// be written. A network without it keeps its encoding, its network id
    /// and its state roots. The production profile requires it.
    #[serde(default, skip_serializing_if = "is_false", deserialize_with = "set_records")]
    pub service_records: bool,
}
/// A genesis account that starts with a set of keys and a policy
/// (`Genesis::protected_accounts`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedAccount {
    #[serde(with = "pos::decimal::u64")]
    pub id: u64,
    /// Sorted by public key, each key once, each in one role.
    pub keys: Vec<ProtectedKey>,
    pub policy: crate::security::Policy,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedKey {
    pub public_key: String,
    pub role: crate::security::Role,
}
impl ProtectedAccount {
    /// The keys of the account as device rows, and its first security row:
    /// judged by the rules every set of keys satisfies
    /// (`security::genesis_set`). `minimum` is the network's least waiting
    /// period.
    pub fn set(&self, minimum: u64) -> Result<(Vec<ledger::Device>, crate::security::Security)> {
        crate::security::genesis_set(
            minimum,
            self.keys.iter().map(|key| (key.public_key.as_str(), key.role)),
            &self.policy,
        )
    }
}
/// All of the fees, in parts per million.
pub const FEE_PARTS: u64 = 1_000_000;
/// Genesis account ids are below this (2^48): the 16 bits above are a zone
/// number, reserved, and zone 0 is this chain.
pub const MAX_GENESIS_ACCOUNT_ID: u64 = 1 << 48;
fn is_zero(value: &u64) -> bool {
    *value == 0
}
fn protocol_fee() -> u64 {
    ledger::FEE_MICROS
}
fn is_protocol_fee(value: &u64) -> bool {
    *value == ledger::FEE_MICROS
}
fn set_fee<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = pos::decimal::u64::deserialize(deserializer)?;
    if !(1..ledger::FEE_MICROS).contains(&value) {
        return Err(serde::de::Error::custom(
            "a written fee is from 1 to 999; the protocol-4 fee of 1000 is written by leaving the field out",
        ));
    }
    Ok(value)
}
fn is_false(value: &bool) -> bool {
    !*value
}
fn set_true<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if !bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "the protocol-4 issuance is written by leaving the field out, not as false",
        ));
    }
    Ok(true)
}
fn set_handover<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if !bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "the protocol-4 calendar rule is written by leaving the field out, not as false",
        ));
    }
    Ok(true)
}
fn set_distinct<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if !bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "the protocol-4 rule for names is written by leaving the field out, not as false",
        ));
    }
    Ok(true)
}
fn set_waits<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if !bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "the protocol-4 clock of the waits is written by leaving the field out, not as false",
        ));
    }
    Ok(true)
}
fn set_protected<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if !bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "the protocol-4 rule for new accounts is written by leaving the field out, not as false",
        ));
    }
    Ok(true)
}
fn set_records<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if !bool::deserialize(deserializer)? {
        return Err(serde::de::Error::custom(
            "a network without service records is written by leaving the field out, not as false",
        ));
    }
    Ok(true)
}
fn set_accounts<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ProtectedAccount>, D::Error> {
    let accounts = Vec::<ProtectedAccount>::deserialize(deserializer)?;
    if accounts.is_empty() {
        return Err(serde::de::Error::custom(
            "a genesis without protected accounts is written by leaving the field out, not as an empty list",
        ));
    }
    Ok(accounts)
}
fn set_share<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = pos::decimal::u64::deserialize(deserializer)?;
    if value == 0 {
        return Err(serde::de::Error::custom(
            "a fee share of zero is written by leaving the field out",
        ));
    }
    Ok(value)
}
impl Genesis {
    /// What `InitChain` requires of a genesis, on top of `validate`: the
    /// production profile requires the stake hand-over rule, distinct
    /// account names, waits that survive a stop, registrations that can
    /// carry a set of keys and service records; and every account that
    /// starts protected has a
    /// set of keys and a policy the account security rules accept. Checked
    /// when a chain is started (`Engine::initialize`), not when a state is
    /// opened, so that a state created before a rule existed still opens.
    /// (The sets are checked here and not in `validate`, which runs with
    /// every block: checking a set decodes each of its keys as a curve
    /// point. `Engine::initialize` writes the rows from the same call, and
    /// the recount checks every stored row against the same rules.)
    pub fn validate_initial(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.profile != pos::Profile::Production || self.stake_handover,
            "production profile requires the stake hand-over rule"
        );
        ensure!(
            self.profile != pos::Profile::Production || self.distinct_names,
            "production profile requires distinct account names (distinct_names): a network that accepted names that look alike cannot take them back"
        );
        ensure!(
            self.profile != pos::Profile::Production || self.waits_survive_stops,
            "production profile requires waits that survive a stop (waits_survive_stops): without it a chain that was stopped comes back with the waits and freezes of its accounts used up"
        );
        ensure!(
            self.profile != pos::Profile::Production || self.protected_registration,
            "production profile requires registrations that can carry a set of keys (protected_registration): without it every account starts with one key that can do everything"
        );
        ensure!(
            self.profile != pos::Profile::Production || self.service_records,
            "production profile requires service records (service_records): a network that starts without them can never measure a validator's or a stake's history before the day they begin"
        );
        for account in &self.protected_accounts {
            account
                .set(self.recovery_min_delay_micros)
                .map_err(|error| anyhow::anyhow!("protected genesis account {}: {error}", account.id))?;
        }
        Ok(())
    }
    /// The rules a new network must use, on top of `validate_initial`: its
    /// genesis account ids are below 2^48. Checked when the database is
    /// new. A repeated `InitChain` on a database that exists is judged by
    /// `validate_initial` and by being the genesis that database holds, as
    /// it was before the bound existed.
    pub fn validate_new(&self) -> Result<()> {
        self.validate_initial()?;
        // An account id is zone * 2^48 + number, and zone 0 is this chain.
        // Registration counts up from the highest genesis id and cannot
        // reach 2^48, so bounding the genesis keeps every id in zone 0.
        ensure!(
            self.ledger.accounts.iter().all(|account| account.id < MAX_GENESIS_ACCOUNT_ID),
            "genesis account ids are below 2^48: higher ids are reserved for zones"
        );
        Ok(())
    }
    /// What an account action costs on this network, in microseconds:
    /// `ledger::FEE_MICROS` unless the genesis sets a lower fee. Everything
    /// that charges, bounds or reasons about the fee reads it here.
    pub fn fee(&self) -> u64 {
        self.fee_micros
    }
    /// The part of `issued`, the new time of one block, that goes to the
    /// validators who signed it: all of it on a network with
    /// `all_new_time_to_validators`, a fifth otherwise (the protocol-4 rule).
    pub fn validators_issuance(&self, issued: u64) -> u64 {
        if self.all_new_time_to_validators {
            issued
        } else {
            issued / 5
        }
    }
    /// Whether this network has a bitcoin auction, and with it the actions
    /// that serve it: kinds 40 (bitcoin headers), 41 (bitcoin receipts), 42
    /// (auction claims) and 60 to 63 (treasury governance).
    pub fn bitcoin_kind_allowed(&self, kind: u8) -> bool {
        !self.all_new_time_to_validators || !matches!(kind, 40..=42 | 60..=63)
    }
    /// The part of `fees`, the action fees charged in one block, that this
    /// network pays on to validators. The rest stays in the bank.
    pub fn validators_fee(&self, fees: u64) -> u64 {
        // `validate` bounds the share by the whole, so the result fits.
        (u128::from(fees) * u128::from(self.fees_to_validators_ppm) / u128::from(FEE_PARTS)) as u64
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.fees_to_validators_ppm <= FEE_PARTS,
            "validators cannot be paid more than the whole fee"
        );
        ensure!(
            (1..=ledger::FEE_MICROS).contains(&self.fee_micros),
            "the action fee is from 1 to the protocol-4 fee of 1000"
        );
        ensure!(
            !self.all_new_time_to_validators || self.validators.len() >= 5,
            "a network that pays all new time to validators needs at least five starting validators"
        );
        ensure!(self.reward_version==1,"explicit proportional reward version one required");
        ensure!(
            self.history_version == 1,
            "explicit authenticated history version one required"
        );
        ensure!(
            self.bitcoin_receipt_version == 1,
            "explicit compact Bitcoin receipt version one required"
        );
        ensure!(
            self.recovery_approval_window_micros == 7 * pos::DAY,
            "recovery approval window must be seven accepted days"
        );
        self.registration.validate()?;
        ensure!(
            self.ledger.chain_id.starts_with("time-devnet-v4-"),
            "explicit development-v4 chain required"
        );
        let canonical = ledger::new(self.ledger.clone())?;
        ensure!(
            canonical.genesis == self.ledger,
            "noncanonical ledger genesis"
        );
        if self.distinct_names {
            // The names are valid and differ (`ledger::new`, above). On a
            // network with distinct names they must not look alike either,
            // and each needs a skeleton to be told apart by.
            let mut owners = BTreeMap::new();
            for account in &self.ledger.accounts {
                let skeleton = crate::names::skeleton(&account.name);
                ensure!(
                    !skeleton.is_empty(),
                    "genesis account name {}: {}",
                    account.name,
                    crate::names::EMPTY
                );
                if let Some(existing) = owners.insert(skeleton, &account.name) {
                    anyhow::bail!(
                        "genesis account names {existing} and {} look alike: a network with distinct names starts without such a pair",
                        account.name
                    );
                }
            }
        }
        // Accounts that start protected: only on a network whose
        // registrations can carry a set of keys, each of them a genesis
        // account, each once, in the order of their ids. The sets
        // themselves are judged when the chain is started
        // (`validate_initial`).
        ensure!(
            self.protected_accounts.is_empty() || self.protected_registration,
            "genesis accounts that start protected need the setting protected_registration"
        );
        ensure!(
            self.protected_accounts.windows(2).all(|pair| pair[0].id < pair[1].id),
            "genesis accounts that start protected are listed once each, in the order of their ids"
        );
        for account in &self.protected_accounts {
            ensure!(
                self.ledger.accounts.iter().any(|row| row.id == account.id),
                "protected genesis account {} is not an account of this genesis",
                account.id
            );
        }
        ensure!(
            self.ledger.economics.mode == ledger::EconomicMode::BankOnly
                && self.ledger.economics.operators.is_empty(),
            "v4 uses separate actual PoS, not legacy economic operators"
        );
        ensure!(
            (4..=20).contains(&self.validators.len()),
            "bootstrap roster must contain four to twenty validators"
        );
        if self.profile == pos::Profile::Production {
            ensure!(
                self.validators.len() == 20,
                "production profile requires twenty bootstrap organizations"
            );
        }
        let mut owners = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for validator in &self.validators {
            ensure!(
                owners.insert(validator.owner) && keys.insert(&validator.consensus_key),
                "duplicate bootstrap validator"
            );
            ensure!(
                self.ledger.accounts.iter().any(|a| a.id == validator.owner),
                "bootstrap owner missing"
            );
            let raw: [u8; 32] = hex::decode(&validator.consensus_key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid consensus key"))?;
            let public = ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
            ensure!(
                !public.is_weak()
                    && hex::encode(raw) == validator.consensus_key
                    && validator.commission_bps <= 2000,
                "invalid bootstrap authority"
            );
        }
        self.treasury.validate()?;
        ensure!(
            self.treasury.revision == 1,
            "initial treasury revision must be one"
        );
        ensure!(
            !self.bitcoin.mainnet_receipts_enabled,
            "valuable Bitcoin receipt acceptance is disabled in this candidate"
        );
        ensure!(
            (1..=86_400).contains(&self.auction.epoch_seconds)
                && (1..=48).contains(&self.auction.max_future_epochs)
                && self.auction.bid_lead_epochs > 0
                && self.auction.bid_lead_epochs <= self.auction.max_future_epochs,
            "invalid auction window"
        );
        ensure!(
            self.auction.min_sats > 0
                && self.auction.min_sats <= self.auction.max_sats
                && self.auction.max_sats <= 2_100_000_000_000_000,
            "invalid Bitcoin amount bounds"
        );
        ensure!(
            self.trusting_period_seconds == 7 * 86_400
                && self.trusting_period_seconds * 1_000_000 < pos::UNBOND_DELAY,
            "trust must be shorter than slashable withdrawal delay"
        );
        ensure!(
            self.recovery_min_delay_micros >= 30_000_000
                && self.recovery_min_delay_micros <= 30 * pos::DAY,
            "invalid recovery delay"
        );
        if self.profile == pos::Profile::Production {
            ensure!(
                self.auction.epoch_seconds == 3600
                    && self.recovery_min_delay_micros >= 2 * pos::DAY,
                "production timing requires hourly auction and at least two-day recovery"
            );
        }
        Ok(())
    }
    pub fn network_id(&self) -> Result<String> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"TCDEVNET-NETWORK-V4\0");
        hash.update(serde_json::to_vec(self)?);
        Ok(hex::encode(hash.finalize()))
    }
}
