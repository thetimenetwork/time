//! Deterministic, zero-premine devnet ledger. Synthetic auction bids and fixed
//! validator stake pools are laboratory fixtures, not a Bitcoin bridge or a
//! permissionless production validator-selection protocol.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, error::Error, fmt};

mod decimal;
mod recovery;
pub use recovery::recovery_frozen;
mod v1;
#[cfg(test)]
mod v1_tests;
pub use v1::{
    Action, ActionPayload, AddDevice, ApproveRecovery, Bid, CancelPending, CancelRecovery, Commit,
    ConsentRecovery, Delegate, FinalizeRecovery, MerchantPayment, Reveal, RevokeDevice,
    SetRecovery, Transfer, Undelegate, Withdraw, action_commitment, decode_action, sign_action,
};

pub const FEE_MICROS: u64 = 1_000;
pub const MAX_BLOCK_TXS: usize = 20_000;
/// Raw transaction bytes, independent of proposer/mempool policy. Consensus
/// block bytes are capped separately by ABCI so all block metadata fits safely
/// inside the 8MiB transport envelope before ProcessProposal can reject it.
pub const MAX_BLOCK_TX_BYTES: usize = 1024 * 1024;
pub const MAX_GENESIS_ACCOUNTS: usize = 100_000;
pub const TRANSFER_DOMAIN: &[u8] = b"TCDEVNET-TRANSFER-V0\0";
pub const TX_BODY_SIZE: usize = TRANSFER_DOMAIN.len() + 32 + 5 * 8;
pub const TX_SIZE: usize = TX_BODY_SIZE + 64;
pub const MAX_ACCOUNTS: usize = 100_000;
pub const MAX_DEVICES: usize = 8;
pub const MAX_OPERATORS: usize = 100;
pub const MAX_PENDING_COMMITS: usize = 10_000;
pub const MAX_AUCTION_BIDS: usize = 10_000;
pub const MAX_UNBONDING: usize = 64;
pub const MICROS_PER_SECOND: u64 = 1_000_000;
pub const MAX_GUARDIANS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerError(pub String);

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Error for LedgerError {}

type Result<T> = std::result::Result<T, LedgerError>;

fn invalid(message: impl Into<String>) -> LedgerError {
    LedgerError(message.into())
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAccount {
    #[serde(with = "decimal::u64")]
    pub id: u64,
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub chain_id: String,
    #[serde(with = "decimal::i64")]
    pub genesis_time_micros: i64,
    pub accounts: Vec<GenesisAccount>,
    #[serde(default)]
    pub economics: Economics,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicMode {
    #[default]
    BankOnly,
    DevnetAuction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    #[serde(with = "decimal::u64")]
    pub account_id: u64,
    pub consensus_key: String,
    #[serde(with = "decimal::u64")]
    pub power: u64,
    pub commission_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Economics {
    pub mode: EconomicMode,
    #[serde(with = "decimal::u64")]
    pub auction_epoch_seconds: u64,
    #[serde(with = "decimal::u64")]
    pub unbond_seconds: u64,
    pub operators: Vec<Operator>,
}

impl Default for Economics {
    fn default() -> Self {
        Self {
            mode: EconomicMode::BankOnly,
            auction_epoch_seconds: 10,
            unbond_seconds: 14 * 86_400,
            operators: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub public_key: String,
    pub can_manage: bool,
    pub can_spend: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    #[serde(with = "decimal::u64")]
    pub operator: u64,
    #[serde(with = "decimal::u64")]
    pub shares: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unbonding {
    #[serde(with = "decimal::u64")]
    pub id: u64,
    #[serde(with = "decimal::u64")]
    pub amount: u64,
    #[serde(with = "decimal::u64")]
    pub unlock_elapsed_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    #[serde(with = "decimal::u64")]
    pub operator: u64,
    #[serde(with = "decimal::u64")]
    pub assets: u64,
    #[serde(with = "decimal::u64")]
    pub total_shares: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameCommit {
    pub public_key: String,
    pub commitment: String,
    #[serde(with = "decimal::i64")]
    pub height: i64,
    #[serde(with = "decimal::u64")]
    pub expires_elapsed_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuctionBid {
    #[serde(with = "decimal::u64")]
    pub account_id: u64,
    #[serde(with = "decimal::u64")]
    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    #[serde(with = "decimal::u64_vec")]
    pub guardians: Vec<u64>,
    #[serde(with = "decimal::u64_vec")]
    pub accepted: Vec<u64>,
    #[serde(with = "decimal::u64")]
    pub threshold: u64,
    #[serde(with = "decimal::u64")]
    pub delay_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCase {
    #[serde(with = "decimal::u64")]
    pub target: u64,
    #[serde(with = "decimal::u64")]
    pub policy_version: u64,
    #[serde(with = "decimal::u64")]
    pub auth_epoch: u64,
    pub recovery_id: String,
    pub new_public_key: String,
    #[serde(with = "decimal::u64")]
    pub expires_elapsed_micros: u64,
    #[serde(with = "decimal::u64_vec")]
    pub approvals: Vec<u64>,
    #[serde(with = "decimal::option_u64")]
    pub ready_elapsed_micros: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    #[serde(with = "decimal::u64")]
    pub id: u64,
    pub name: String,
    pub public_key: String,
    #[serde(with = "decimal::u64")]
    pub balance: u64,
    #[serde(with = "decimal::u64")]
    pub nonce: u64,
    #[serde(with = "decimal::u64")]
    pub auth_epoch: u64,
    pub devices: Vec<Device>,
    pub delegations: Vec<Delegation>,
    pub unbonding: Vec<Unbonding>,
    #[serde(default, with = "decimal::u64", skip_serializing_if = "is_zero")]
    pub recovery_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<RecoveryPolicy>,
}

/// Fixed-field JSON is the devnet's canonical state encoding. Field order is
/// specified by this struct; accounts and genesis accounts are sorted by ID.
/// No maps, floating-point amounts, platform clock reads or secret keys occur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub genesis: Genesis,
    pub network_id: String,
    #[serde(with = "decimal::i64")]
    pub height: i64,
    #[serde(with = "decimal::i64")]
    pub time_micros: i64,
    #[serde(with = "decimal::u64")]
    pub bank: u64,
    pub accounts: Vec<Account>,
    pub name_commits: Vec<NameCommit>,
    pub pools: Vec<Pool>,
    #[serde(with = "decimal::u64")]
    pub auction_epoch: u64,
    pub auction_bids: Vec<AuctionBid>,
    #[serde(with = "decimal::u64")]
    pub next_unbond_id: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_cases: Vec<RecoveryCase>,
    #[serde(default, with = "decimal::u64", skip_serializing_if = "is_zero")]
    pub protocol_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tx {
    pub network_id: String,
    #[serde(with = "decimal::u64")]
    pub from: u64,
    #[serde(with = "decimal::u64")]
    pub to: u64,
    #[serde(with = "decimal::u64")]
    pub nonce: u64,
    #[serde(with = "decimal::u64")]
    pub amount: u64,
    #[serde(with = "decimal::u64")]
    pub fee: u64,
    pub signature: Vec<u8>,
}

fn hex32(text: &str, label: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid(format!(
            "{label} must be canonical lowercase 32-byte hex"
        )));
    }
    let bytes = hex::decode(text).map_err(|_| invalid(format!("invalid {label}")))?;
    bytes
        .try_into()
        .map_err(|_| invalid(format!("invalid {label} length")))
}

fn public_key(text: &str) -> Result<VerifyingKey> {
    let bytes = hex32(text, "public key")?;
    // RFC8032's compressed y-coordinate must be < 2^255-19. Do not accept
    // alternate field encodings as different account authorities.
    let mut coordinate = bytes;
    coordinate[31] &= 0x7f;
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if coordinate.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
        return Err(invalid("noncanonical Ed25519 public key"));
    }
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| invalid("invalid Ed25519 public key"))?;
    if key.is_weak() {
        return Err(invalid("weak Ed25519 public key"));
    }
    Ok(key)
}

fn valid_name(name: &str) -> bool {
    (2..=15).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn validate_genesis(genesis: &Genesis) -> Result<()> {
    let suffix = genesis
        .chain_id
        .strip_prefix("time-devnet-")
        .ok_or_else(|| invalid("only time-devnet-* chain IDs are enabled"))?;
    if suffix.is_empty()
        || genesis.chain_id.len() > 50
        || !suffix
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
    {
        return Err(invalid("invalid devnet chain ID"));
    }
    if genesis.genesis_time_micros < 0 {
        return Err(invalid("negative genesis time"));
    }
    if genesis.accounts.len() > MAX_GENESIS_ACCOUNTS {
        return Err(invalid("genesis account limit exceeded"));
    }
    let mut previous = None;
    let mut names = HashSet::with_capacity(genesis.accounts.len());
    for account in &genesis.accounts {
        if account.id == u64::MAX {
            return Err(invalid("reserved anonymous account ID"));
        }
        if previous.is_some_and(|id| id >= account.id) {
            return Err(invalid("genesis account IDs must be unique and sorted"));
        }
        previous = Some(account.id);
        if !valid_name(&account.name) || !names.insert(account.name.as_str()) {
            return Err(invalid("invalid or duplicate username"));
        }
        public_key(&account.public_key)?;
    }
    let economics = &genesis.economics;
    if !(1..=86_400).contains(&economics.auction_epoch_seconds)
        || !(1..=14 * 86_400).contains(&economics.unbond_seconds)
        || economics.operators.len() > MAX_OPERATORS
    {
        return Err(invalid("invalid laboratory economic configuration"));
    }
    if economics.mode == EconomicMode::BankOnly && !economics.operators.is_empty() {
        return Err(invalid("bank-only mode cannot have economic operators"));
    }
    if economics.mode == EconomicMode::DevnetAuction && economics.operators.is_empty() {
        return Err(invalid("auction mode requires fixed devnet operators"));
    }
    let mut ids = HashSet::new();
    let mut consensus_keys = HashSet::new();
    let mut power_sum = 0u64;
    for operator in &economics.operators {
        if !ids.insert(operator.account_id)
            || !consensus_keys.insert(&operator.consensus_key)
            || !genesis.accounts.iter().any(|a| a.id == operator.account_id)
            || operator.power == 0
            || operator.commission_bps > 2_000
        {
            return Err(invalid("invalid or duplicate fixed devnet operator"));
        }
        public_key(&operator.consensus_key)?;
        power_sum = power_sum
            .checked_add(operator.power)
            .ok_or_else(|| invalid("operator voting power overflow"))?;
    }
    if !economics
        .operators
        .windows(2)
        .all(|w| w[0].account_id < w[1].account_id)
    {
        return Err(invalid("operators must be sorted by account ID"));
    }
    Ok(())
}

fn network_id(genesis: &Genesis) -> Result<String> {
    let bytes =
        serde_json::to_vec(genesis).map_err(|e| invalid(format!("genesis encoding: {e}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn new(mut genesis: Genesis) -> Result<State> {
    genesis.accounts.sort_by_key(|account| account.id);
    genesis
        .economics
        .operators
        .sort_by_key(|operator| operator.account_id);
    validate_genesis(&genesis)?;
    let state = State {
        network_id: network_id(&genesis)?,
        height: 0,
        time_micros: genesis.genesis_time_micros,
        bank: 0,
        accounts: genesis
            .accounts
            .iter()
            .map(|account| Account {
                id: account.id,
                name: account.name.clone(),
                public_key: account.public_key.clone(),
                balance: 0,
                nonce: 0,
                auth_epoch: 0,
                devices: vec![Device {
                    public_key: account.public_key.clone(),
                    can_manage: true,
                    can_spend: true,
                }],
                delegations: Vec::new(),
                unbonding: Vec::new(),
                recovery_version: 0,
                recovery_policy: None,
            })
            .collect(),
        name_commits: Vec::new(),
        pools: genesis
            .economics
            .operators
            .iter()
            .map(|operator| Pool {
                operator: operator.account_id,
                assets: 0,
                total_shares: 0,
            })
            .collect(),
        auction_epoch: 0,
        auction_bids: Vec::new(),
        next_unbond_id: 0,
        recovery_cases: Vec::new(),
        protocol_version: 1,
        genesis,
    };
    state.validate()?;
    Ok(state)
}

impl State {
    pub fn hash(&self) -> Result<[u8; 32]> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| invalid(format!("state encoding: {e}")))?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version > 1 {
            return Err(invalid("unsupported ledger protocol version"));
        }
        validate_genesis(&self.genesis)?;
        if self.network_id != network_id(&self.genesis)? {
            return Err(invalid("genesis identity mismatch"));
        }
        if self.height < 0 || self.time_micros < self.genesis.genesis_time_micros {
            return Err(invalid("invalid state coordinates"));
        }
        if self.accounts.len() < self.genesis.accounts.len() || self.accounts.len() > MAX_ACCOUNTS {
            return Err(invalid("invalid account set size"));
        }
        let elapsed = self.elapsed_micros()?;
        let mut sum = self.bank;
        let mut names = HashSet::new();
        let mut unbond_ids = HashSet::new();
        let mut share_sums = vec![0u64; self.pools.len()];
        let mut previous_id = None;
        for account in &self.accounts {
            if account.id == u64::MAX
                || previous_id.is_some_and(|id| id >= account.id)
                || !valid_name(&account.name)
                || !names.insert(&account.name)
            {
                return Err(invalid("invalid account identity ordering or username"));
            }
            previous_id = Some(account.id);
            public_key(&account.public_key)?;
            if let Ok(index) = self
                .genesis
                .accounts
                .binary_search_by_key(&account.id, |a| a.id)
            {
                let original = &self.genesis.accounts[index];
                if account.name != original.name || account.public_key != original.public_key {
                    return Err(invalid("account identity differs from genesis"));
                }
            } else if self
                .genesis
                .accounts
                .last()
                .is_some_and(|a| account.id <= a.id)
            {
                return Err(invalid("registered account ID precedes genesis identities"));
            }
            if account.devices.is_empty()
                || account.devices.len() > MAX_DEVICES
                || !account.devices.iter().any(|d| d.can_manage)
                || !account.devices.iter().any(|d| d.can_spend)
                || !account
                    .devices
                    .windows(2)
                    .all(|w| w[0].public_key < w[1].public_key)
                || account.auth_epoch > account.nonce
            {
                return Err(invalid("invalid device authority set"));
            }
            for device in &account.devices {
                public_key(&device.public_key)?;
            }
            sum = sum
                .checked_add(account.balance)
                .ok_or_else(|| invalid("supply sum overflow"))?;
            if account.delegations.len() > MAX_OPERATORS
                || !account
                    .delegations
                    .windows(2)
                    .all(|w| w[0].operator < w[1].operator)
                || account.unbonding.len() > MAX_UNBONDING
                || !account.unbonding.windows(2).all(|w| w[0].id < w[1].id)
            {
                return Err(invalid("invalid staking entry bounds or ordering"));
            }
            for delegation in &account.delegations {
                let pool = self
                    .pools
                    .binary_search_by_key(&delegation.operator, |p| p.operator)
                    .map_err(|_| invalid("delegation references unknown operator"))?;
                if delegation.shares == 0 {
                    return Err(invalid("zero delegation shares"));
                }
                share_sums[pool] = share_sums[pool]
                    .checked_add(delegation.shares)
                    .ok_or_else(|| invalid("delegation share overflow"))?;
            }
            for unbond in &account.unbonding {
                if unbond.amount == 0
                    || unbond.id >= self.next_unbond_id
                    || !unbond_ids.insert(unbond.id)
                {
                    return Err(invalid("invalid unbonding entry"));
                }
                sum = sum
                    .checked_add(unbond.amount)
                    .ok_or_else(|| invalid("escrow supply overflow"))?;
            }
            if self.height == 0
                && (account.balance != 0
                    || account.nonce != 0
                    || account.auth_epoch != 0
                    || !account.delegations.is_empty()
                    || !account.unbonding.is_empty()
                    || account.recovery_version != 0
                    || account.recovery_policy.is_some()
                    || account.devices
                        != vec![Device {
                            public_key: account.public_key.clone(),
                            can_manage: true,
                            can_spend: true,
                        }])
            {
                return Err(invalid("genesis accounts must have zero balance and nonce"));
            }
        }
        for original in &self.genesis.accounts {
            if self.account(original.id).is_none() {
                return Err(invalid("missing genesis identity"));
            }
        }
        recovery::validate_recovery_state(self)?;
        if self.pools.len() != self.genesis.economics.operators.len() {
            return Err(invalid("pool set mismatch"));
        }
        for (index, (pool, operator)) in self
            .pools
            .iter()
            .zip(&self.genesis.economics.operators)
            .enumerate()
        {
            if pool.operator != operator.account_id
                || pool.total_shares != share_sums[index]
                || (pool.total_shares == 0) != (pool.assets == 0)
            {
                return Err(invalid("pool assets or shares inconsistent"));
            }
            sum = sum
                .checked_add(pool.assets)
                .ok_or_else(|| invalid("bonded supply overflow"))?;
        }
        if self.name_commits.len() > MAX_PENDING_COMMITS
            || !self
                .name_commits
                .windows(2)
                .all(|w| w[0].public_key < w[1].public_key)
        {
            return Err(invalid("invalid pending name commitment set"));
        }
        for commit in &self.name_commits {
            public_key(&commit.public_key)?;
            hex32(&commit.commitment, "name commitment")?;
            if commit.height <= 0
                || commit.height > self.height
                || commit.expires_elapsed_micros < elapsed
            {
                return Err(invalid("invalid name commitment coordinates"));
            }
        }
        if self.auction_epoch
            != elapsed / (self.genesis.economics.auction_epoch_seconds * MICROS_PER_SECOND)
            || self.auction_bids.len() > MAX_AUCTION_BIDS
            || !self
                .auction_bids
                .windows(2)
                .all(|w| w[0].account_id < w[1].account_id)
        {
            return Err(invalid("invalid current auction"));
        }
        for bid in &self.auction_bids {
            if self.account(bid.account_id).is_none() || !(1..=1_000_000).contains(&bid.weight) {
                return Err(invalid("invalid synthetic auction bid"));
            }
        }
        if self.genesis.economics.mode == EconomicMode::BankOnly && !self.auction_bids.is_empty() {
            return Err(invalid("auction bids disabled in bank-only mode"));
        }
        if sum != elapsed {
            return Err(invalid("supply differs from accepted elapsed time"));
        }
        if self.height == 0
            && (elapsed != 0
                || self.bank != 0
                || !self.name_commits.is_empty()
                || self.accounts.len() != self.genesis.accounts.len()
                || self.next_unbond_id != 0)
        {
            return Err(invalid("nonzero genesis supply"));
        }
        if self.height > 1 && elapsed == 0 {
            return Err(invalid("block time did not advance"));
        }
        Ok(())
    }

    pub fn elapsed_micros(&self) -> Result<u64> {
        self.time_micros
            .checked_sub(self.genesis.genesis_time_micros)
            .and_then(|v| u64::try_from(v).ok())
            .ok_or_else(|| invalid("elapsed time overflow"))
    }

    pub fn account(&self, id: u64) -> Option<&Account> {
        self.accounts
            .binary_search_by_key(&id, |account| account.id)
            .ok()
            .map(|index| &self.accounts[index])
    }
}

fn signing_bytes(tx: &Tx) -> Result<Vec<u8>> {
    let network = hex32(&tx.network_id, "network ID")?;
    let mut raw = Vec::with_capacity(TX_BODY_SIZE);
    raw.extend_from_slice(TRANSFER_DOMAIN);
    raw.extend_from_slice(&network);
    for value in [tx.from, tx.to, tx.nonce, tx.amount, tx.fee] {
        raw.extend_from_slice(&value.to_be_bytes());
    }
    Ok(raw)
}

pub fn encode_tx(tx: &Tx) -> Result<Vec<u8>> {
    if tx.signature.len() != 64 {
        return Err(invalid("signature must be exactly 64 bytes"));
    }
    let mut raw = signing_bytes(tx)?;
    raw.extend_from_slice(&tx.signature);
    Ok(raw)
}

pub fn sign_tx(tx: &Tx, key: &SigningKey) -> Result<Vec<u8>> {
    let mut raw = signing_bytes(tx)?;
    raw.extend_from_slice(&key.sign(&raw).to_bytes());
    Ok(raw)
}

pub fn decode_tx(raw: &[u8]) -> Result<Tx> {
    if raw.len() != TX_SIZE || !raw.starts_with(TRANSFER_DOMAIN) {
        return Err(invalid("malformed transfer encoding"));
    }
    let mut position = TRANSFER_DOMAIN.len();
    let network_id = hex::encode(&raw[position..position + 32]);
    position += 32;
    let mut next_u64 = || {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&raw[position..position + 8]);
        position += 8;
        u64::from_be_bytes(bytes)
    };
    let (from, to, nonce, amount, fee) =
        (next_u64(), next_u64(), next_u64(), next_u64(), next_u64());
    Ok(Tx {
        network_id,
        from,
        to,
        nonce,
        amount,
        fee,
        signature: raw[TX_BODY_SIZE..].to_vec(),
    })
}

fn checked_tx(state: &State, raw: &[u8]) -> Result<(Tx, usize, usize)> {
    let tx = decode_tx(raw)?;
    if tx.network_id != state.network_id {
        return Err(invalid("wrong network"));
    }
    let from = state
        .accounts
        .binary_search_by_key(&tx.from, |account| account.id)
        .map_err(|_| invalid("sender account does not exist"))?;
    let to = state
        .accounts
        .binary_search_by_key(&tx.to, |account| account.id)
        .map_err(|_| invalid("recipient account does not exist"))?;
    if from == to {
        return Err(invalid("self transfer"));
    }
    if tx.amount == 0 {
        return Err(invalid("zero transfer amount"));
    }
    if tx.fee != FEE_MICROS {
        return Err(invalid("incorrect fee"));
    }
    let sender = &state.accounts[from];
    if sender.auth_epoch != 0
        || !state.genesis.accounts.iter().any(|a| a.id == sender.id)
        || !sender
            .devices
            .iter()
            .any(|d| d.public_key == sender.public_key && d.can_spend)
    {
        return Err(invalid("legacy transfer authority disabled"));
    }
    let next_nonce = sender
        .nonce
        .checked_add(1)
        .ok_or_else(|| invalid("nonce exhausted"))?;
    if tx.nonce != next_nonce {
        return Err(invalid("incorrect nonce"));
    }
    let cost = tx
        .amount
        .checked_add(tx.fee)
        .ok_or_else(|| invalid("transfer cost overflow"))?;
    if sender.balance < cost {
        return Err(invalid("insufficient funds"));
    }
    state.accounts[to]
        .balance
        .checked_add(tx.amount)
        .ok_or_else(|| invalid("recipient balance overflow"))?;
    state
        .bank
        .checked_add(tx.fee)
        .ok_or_else(|| invalid("bank overflow"))?;
    let signature =
        Signature::from_slice(&tx.signature).map_err(|_| invalid("malformed signature"))?;
    public_key(&sender.public_key)?
        .verify_strict(&raw[..TX_BODY_SIZE], &signature)
        .map_err(|_| invalid("invalid signature"))?;
    Ok((tx, from, to))
}

/// Validate against a previously validated state without mutation or minting.
pub fn validate_tx(state: &State, raw: &[u8]) -> Result<()> {
    if raw.starts_with(v1::ACTION_DOMAIN) {
        v1::check_action(state, raw).map(|_| ())
    } else {
        checked_tx(state, raw).map(|_| ())
    }
}

/// Sequential proposal filtering uses this function to avoid replaying an
/// entire queue per transaction. Callers must start with a validated state.
/// Every possible error is checked before mutation.
pub fn apply_tx(state: &mut State, raw: &[u8]) -> Result<()> {
    if raw.starts_with(v1::ACTION_DOMAIN) {
        return v1::apply_action(state, raw);
    }
    let (tx, from, to) = checked_tx(state, raw)?;
    state.accounts[from].balance -= tx.amount + tx.fee;
    state.accounts[from].nonce = tx.nonce;
    state.accounts[to].balance += tx.amount;
    state.bank += tx.fee;
    Ok(())
}

/// Trusted protocol adapter with an explicitly pinned guardian coordination
/// window. Legacy entry points retain their exact 600-second window. The
/// complete policy delay still starts only when the consenting quorum forms.
pub fn apply_tx_with_recovery_window(
    state: &mut State,
    raw: &[u8],
    approval_window_micros: u64,
) -> Result<()> {
    recovery::validate_approval_window(approval_window_micros)?;
    if raw.starts_with(v1::ACTION_DOMAIN) {
        v1::apply_action_with_recovery_window(state, raw, approval_window_micros)
    } else {
        apply_tx(state, raw)
    }
}
pub fn validate_tx_with_recovery_window(
    state: &State,
    raw: &[u8],
    approval_window_micros: u64,
) -> Result<()> {
    recovery::validate_approval_window(approval_window_micros)?;
    if raw.starts_with(v1::ACTION_DOMAIN) {
        v1::check_action_with_recovery_window(state, raw, approval_window_micros)
    } else {
        validate_tx(state, raw)
    }
}

/// Advance only bounded economics and expire commitments/recovery claims.
/// This is a trusted-state adapter for the incremental v2 development ledger:
/// callers must supply every configured operator, closing-auction bidder, and
/// recovery target represented in this view. It deliberately does not validate,
/// clone, hash, or iterate the complete account registry.
pub fn advance_economics_and_expire(
    state: &mut State,
    previous_elapsed: u64,
    delta: u64,
    eligible: &[String],
) -> Result<()> {
    v1::advance_economics(state, previous_elapsed, delta, eligible)?;
    let now = state.elapsed_micros()?;
    state
        .name_commits
        .retain(|commit| commit.expires_elapsed_micros >= now);
    recovery::purge_recovery(state)
}

pub fn validate_block_transactions<T: AsRef<[u8]>>(txs: &[T]) -> Result<()> {
    if txs.len() > MAX_BLOCK_TXS {
        return Err(invalid("too many block transactions"));
    }
    let mut bytes = 0usize;
    for tx in txs {
        bytes = bytes
            .checked_add(tx.as_ref().len())
            .ok_or_else(|| invalid("block transaction bytes overflow"))?;
        if bytes > MAX_BLOCK_TX_BYTES {
            return Err(invalid("block transaction byte budget exceeded"));
        }
    }
    Ok(())
}

/// Pure block execution: rejects an invalid body atomically, preserves the
/// original state, and mints exactly the increase in accepted chain time.
pub fn transition(base: &State, height: i64, time_micros: i64, txs: &[Vec<u8>]) -> Result<State> {
    let eligible: Vec<String> = base
        .genesis
        .economics
        .operators
        .iter()
        .map(|o| o.consensus_key.clone())
        .collect();
    transition_with_eligible(base, height, time_micros, txs, &eligible)
}

/// Runtime callers must supply the same preceding-commit signer set in every
/// ABCI execution path. Missing power is retained in the bank, not redistributed
/// to the remaining signers. First-block eligibility is empty.
pub fn transition_with_eligible(
    base: &State,
    height: i64,
    time_micros: i64,
    txs: &[Vec<u8>],
    eligible: &[String],
) -> Result<State> {
    base.validate()?;
    if base.protocol_version != 1 {
        return Err(invalid(
            "legacy protocol requires its original binary; start a fresh version1 development network",
        ));
    }
    let expected_height = base
        .height
        .checked_add(1)
        .ok_or_else(|| invalid("height exhausted"))?;
    if height != expected_height {
        return Err(invalid("incorrect block height"));
    }
    // CometBFT's first header uses the genesis timestamp. That one transition
    // mints zero; every subsequent block must advance accepted chain time.
    let initial_zero_elapsed = base.height == 0 && height == 1 && time_micros == base.time_micros;
    if time_micros < base.time_micros || (time_micros == base.time_micros && !initial_zero_elapsed)
    {
        return Err(invalid("block timestamp must increase"));
    }
    validate_block_transactions(txs)?;
    let elapsed = time_micros
        .checked_sub(base.time_micros)
        .ok_or_else(|| invalid("block time overflow"))? as u64;
    let mut next = base.clone();
    next.height = height;
    next.time_micros = time_micros;
    v1::advance_economics(&mut next, base.elapsed_micros()?, elapsed, eligible)?;
    let now_elapsed = next.elapsed_micros()?;
    next.name_commits
        .retain(|commit| commit.expires_elapsed_micros >= now_elapsed);
    recovery::purge_recovery(&mut next)?;
    for raw in txs {
        apply_tx(&mut next, raw)?;
    }
    next.validate()?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn genesis() -> Genesis {
        Genesis {
            chain_id: "time-devnet-ledger-tests".into(),
            genesis_time_micros: 1_000_000,
            accounts: vec![
                GenesisAccount {
                    id: 2,
                    name: "bob".into(),
                    public_key: hex::encode(key(2).verifying_key().as_bytes()),
                },
                GenesisAccount {
                    id: 1,
                    name: "alice".into(),
                    public_key: hex::encode(key(1).verifying_key().as_bytes()),
                },
            ],
            economics: Economics::default(),
        }
    }

    // Explicitly pre-aged funded fixture used only by unit tests. No such
    // initialization or balance mutation is exposed by the application.
    fn funded_fixture() -> State {
        let mut state = new(genesis()).unwrap();
        state.height = 1;
        state.time_micros += 1_000_000;
        state.accounts[0].balance = 800_000;
        state.accounts[1].balance = 100_000;
        state.bank = 100_000;
        state.validate().unwrap();
        state
    }

    fn payment(state: &State, nonce: u64, amount: u64) -> Vec<u8> {
        sign_tx(
            &Tx {
                network_id: state.network_id.clone(),
                from: 1,
                to: 2,
                nonce,
                amount,
                fee: FEE_MICROS,
                signature: Vec::new(),
            },
            &key(1),
        )
        .unwrap()
    }

    #[test]
    fn genesis_is_zero_supply_canonical_and_detached() {
        let mut input = genesis();
        let state = new(input.clone()).unwrap();
        assert_eq!(state.height, 0);
        assert_eq!(state.bank, 0);
        assert!(
            state
                .accounts
                .iter()
                .all(|a| a.balance == 0 && a.nonce == 0)
        );
        assert_eq!(state.accounts[0].id, 1);
        input.accounts.reverse();
        assert_eq!(
            state.hash().unwrap(),
            new(input.clone()).unwrap().hash().unwrap()
        );
        input.accounts[0].name = "changed".into();
        assert_eq!(state.accounts[0].name, "alice");
        let encoded = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            state.hash().unwrap().as_slice(),
            Sha256::digest(&encoded).as_slice()
        );
    }

    #[test]
    fn invalid_and_duplicate_genesis_authority_is_rejected() {
        for change in 0..7 {
            let mut input = genesis();
            match change {
                0 => input.chain_id = "time-mainnet".into(),
                1 => input.accounts[1].name = input.accounts[0].name.clone(),
                2 => input.accounts[1].id = input.accounts[0].id,
                3 => input.accounts[1].name = "Alice".into(),
                4 => input.accounts[1].public_key = "00".repeat(32),
                5 => input.genesis_time_micros = -1,
                _ => input.accounts[1].public_key = "ff".repeat(32),
            }
            assert!(new(input).is_err(), "case {change}");
        }
    }

    #[test]
    fn deserialization_rejects_hidden_genesis_balances_and_unknown_state_fields() {
        let mut encoded = serde_json::to_value(genesis()).unwrap();
        encoded["accounts"][0]["balance"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Genesis>(encoded).is_err());
        let state = funded_fixture();
        let mut encoded = serde_json::to_value(&state).unwrap();
        encoded["admin_key"] = serde_json::json!("injected");
        assert!(serde_json::from_value::<State>(encoded).is_err());
        let mut snapshot = serde_json::to_value(&state).unwrap();
        snapshot["accounts"][0]["nonce"] = serde_json::json!(4_294_967_296_u64);
        let restored: State = serde_json::from_value(snapshot).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.accounts[0].nonce, 4_294_967_296);
    }

    #[test]
    fn elapsed_time_mints_into_bank_without_a_premine() {
        let base = new(genesis()).unwrap();
        let next = transition(&base, 1, base.time_micros + 600_000_000, &[]).unwrap();
        assert_eq!(next.bank, 600_000_000);
        assert!(next.accounts.iter().all(|a| a.balance == 0));
        assert_eq!(base.bank, 0);
        assert!(transition(&base, 2, base.time_micros + 1, &[]).is_err());
        assert!(transition(&base, 1, base.time_micros - 1, &[]).is_err());
    }

    #[test]
    fn first_comet_block_can_use_genesis_time_without_minting() {
        let base = new(genesis()).unwrap();
        let first = transition(&base, 1, base.time_micros, &[]).unwrap();
        assert_eq!(first.height, 1);
        assert_eq!(first.bank, 0);
        assert!(first.accounts.iter().all(|account| account.balance == 0));
        first.validate().unwrap();
        assert!(transition(&first, 2, first.time_micros, &[]).is_err());
        let second = transition(&first, 2, first.time_micros + 1_000_000, &[]).unwrap();
        assert_eq!(second.bank, 1_000_000);
        let mut invalid = first.clone();
        invalid.height = 2;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn signed_transfer_conserves_supply_and_does_not_mutate_base() {
        let base = funded_fixture();
        let original_hash = base.hash().unwrap();
        let raw = payment(&base, 1, 200_000);
        let next = transition(&base, 2, base.time_micros + 10, &[raw]).unwrap();
        assert_eq!(next.accounts[0].balance, 599_000);
        assert_eq!(next.accounts[1].balance, 300_000);
        assert_eq!(next.accounts[0].nonce, 1);
        assert_eq!(next.bank, 101_010);
        next.validate().unwrap();
        assert_eq!(base.hash().unwrap(), original_hash);
        assert!(validate_tx(&next, &payment(&base, 1, 200_000)).is_err());
    }

    #[test]
    fn nonce_is_u64_and_exhaustion_is_explicit() {
        let mut state = funded_fixture();
        state.accounts[0].nonce = u32::MAX as u64;
        let raw = payment(&state, u32::MAX as u64 + 1, 1);
        apply_tx(&mut state, &raw).unwrap();
        assert_eq!(state.accounts[0].nonce, 4_294_967_296);
        state.accounts[0].nonce = u64::MAX;
        let original_hash = state.hash().unwrap();
        assert!(apply_tx(&mut state, &payment(&funded_fixture(), 0, 1)).is_err());
        assert_eq!(state.hash().unwrap(), original_hash);
    }

    #[test]
    fn wrong_network_key_fee_and_overspend_are_rejected_atomically() {
        let state = funded_fixture();
        let valid = payment(&state, 1, 1);
        for change in 0..7 {
            let mut tx = decode_tx(&valid).unwrap();
            match change {
                0 => tx.network_id = "01".repeat(32),
                1 => tx.nonce = 2,
                2 => tx.amount = u64::MAX,
                3 => tx.amount = 0,
                4 => tx.fee = 0,
                5 => tx.to = tx.from,
                _ => tx.to = 999,
            }
            let raw = sign_tx(&tx, &key(1)).unwrap();
            let mut copy = state.clone();
            let hash = copy.hash().unwrap();
            assert!(apply_tx(&mut copy, &raw).is_err(), "case {change}");
            assert_eq!(copy.hash().unwrap(), hash);
        }
        let wrong_signature = sign_tx(&decode_tx(&valid).unwrap(), &key(2)).unwrap();
        assert!(validate_tx(&state, &wrong_signature).is_err());
    }

    #[test]
    fn malformed_and_modified_signing_bytes_reject() {
        let state = funded_fixture();
        let valid = payment(&state, 1, 1);
        assert_eq!(valid.len(), TX_SIZE);
        assert_eq!(encode_tx(&decode_tx(&valid).unwrap()).unwrap(), valid);
        for len in [0, 1, TX_SIZE - 1, TX_SIZE + 1] {
            assert!(decode_tx(&vec![0; len]).is_err());
        }
        for offset in [0, TRANSFER_DOMAIN.len(), TX_BODY_SIZE - 1, TX_SIZE - 1] {
            let mut modified = valid.clone();
            modified[offset] ^= 1;
            assert!(validate_tx(&state, &modified).is_err());
        }
    }

    #[test]
    fn sequential_payments_and_invalid_block_are_atomic() {
        let base = funded_fixture();
        let first = payment(&base, 1, 1);
        let second = payment(&base, 2, 1);
        let next = transition(&base, 2, base.time_micros + 1, &[first.clone(), second]).unwrap();
        assert_eq!(next.accounts[0].nonce, 2);
        let original = base.hash().unwrap();
        assert!(transition(&base, 2, base.time_micros + 1, &[first.clone(), first]).is_err());
        assert_eq!(base.hash().unwrap(), original);
        let oversized = vec![Vec::new(); MAX_BLOCK_TXS + 1];
        assert!(transition(&base, 2, base.time_micros + 1, &oversized).is_err());
    }

    #[test]
    fn corrupt_snapshot_and_overflow_cannot_hide_in_supply_sum() {
        let base = funded_fixture();
        for change in 0..5 {
            let mut state = base.clone();
            match change {
                0 => state.accounts[0].balance = u64::MAX,
                1 => state.network_id = "00".repeat(32),
                2 => state.accounts.reverse(),
                3 => state.accounts[0].public_key = state.accounts[1].public_key.clone(),
                _ => state.bank += 1,
            }
            assert!(state.validate().is_err(), "case {change}");
            assert!(transition(&state, 2, base.time_micros + 1, &[]).is_err());
        }
        let mut end = base.clone();
        end.height = i64::MAX;
        assert!(transition(&end, i64::MAX, end.time_micros + 1, &[]).is_err());
    }
}
