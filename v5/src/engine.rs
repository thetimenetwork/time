//! Protocol-4 ledger rules on the version-5 execution engine.
//!
//! The state transition is the one protocol 4 defines: the same rows, the same
//! acceptance rules and the same Merkle root for the same block. What changed
//! is how the work is done:
//!
//! - state is read from memory (`crate::store`), not re-proved from disk;
//! - signatures are verified once, on all cores, and remembered
//!   (`crate::sigcache`);
//! - recently used accounts are kept decoded (`AccountCache`);
//! - a plain transfer, the common case, takes a dedicated path that applies
//!   the same rules without copying the chain metadata.
//!
//! `tests/differential.rs` runs the same blocks through the protocol-4 engine
//! and this one and requires identical roots and identical accept/reject
//! decisions. Five rules differ on purpose, each closing a weakness found in
//! the review of protocol 4 (`tests/node.rs` covers the first four,
//! `tests/evidence_auto.rs` the fifth):
//!
//! - a block may carry 4 MiB of transactions instead of 1 MiB
//!   (`MAX_BLOCK_TX_BYTES`);
//! - `CancelPending` pays the standard fee (it was free and unconditional);
//! - `SetRecovery` with no guardians turns recovery off (it was rejected by
//!   the minimum-delay check, so recovery could never be disabled);
//! - double-signing evidence is verified with the signature rule consensus
//!   uses (`crate::evidence`), so a validator cannot sign votes that
//!   consensus counts and evidence cannot prove;
//! - the misbehavior CometBFT reports with a block is punished before the
//!   block's transactions, as an evidence action would punish it
//!   (`crate::pos_adapter::misbehavior`; the `*_with_misbehavior` variants of
//!   `prepare`). Protocol 4 ignores that list; the differential tests never
//!   send one.
//!
//! All validators of one network must therefore run the same engine
//! generation.
pub use crate::pos_adapter::Misbehavior;
pub use crate::store::AuditStorageProgress as AuditProgress;
use crate::{
    rules::{self, Rules, Versions},
    sigcache::{self, SigCache, SigStatus},
    store::{Head, PreparedTree, Store, Version},
    upgrade,
};
use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::VerifyingKey;
use rayon::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
};
use timecurrency_node::ledger::{
    self, Account, ActionPayload, AuctionBid, Genesis, NameCommit, Pool, RecoveryCase, State,
};

pub(crate) mod decimal;

pub const META_KEY: &[u8] = b"meta";
pub const MAX_META_BYTES: usize = 256 * 1024;
pub const MAX_ACCOUNT_BYTES: usize = 32 * 1024;
pub const MAX_GENESIS_ACCOUNTS: usize = 64;
pub const MAX_ACCOUNTS: u64 = u64::MAX - 1;
pub const MAX_COMMITS: usize = 256;
pub const MAX_BIDS: usize = 1024;
/// Transactions per block. Unchanged from protocol 4.
pub const MAX_BLOCK_TXS: usize = 20_000;
/// Transaction bytes per block. Protocol 4 allowed 1 MiB (about 5,000
/// transfers). A network of version-5 nodes allows 4 MiB, so that a block can
/// hold the full 20,000 transfers. All validators of a network must run the
/// same engine generation.
pub const MAX_BLOCK_TX_BYTES: usize = 4 * 1024 * 1024;
/// Decoded accounts kept between blocks: two generations of this size.
const ACCOUNT_CACHE_GENERATION: usize = 500_000;
/// Fewer transactions or missing accounts than this are not worth a parallel
/// load; they are loaded where they are needed.
const PRELOAD_MINIMUM: usize = 32;
/// Rows a mempool admission state may hold before it is started afresh.
pub const CHECK_STATE_ROW_LIMIT: usize = 1_000_000;
/// How long an action that carries an expiry must still be valid to be
/// admitted to the mempool. Admission runs on the clock of the last block and
/// the block that would include the action has a later one: without a margin
/// an action could be admitted that no block can ever include, at no cost to
/// its sender. Blocks themselves are executed without the margin.
pub const ADMISSION_MARGIN_MICROS: u64 = 30 * ledger::MICROS_PER_SECOND;

/// Block-level transaction limits, checked before anything is executed.
pub fn validate_block_transactions<T: AsRef<[u8]>>(txs: &[T]) -> Result<()> {
    ensure!(txs.len() <= MAX_BLOCK_TXS, "too many block transactions");
    let mut bytes = 0usize;
    for tx in txs {
        bytes = bytes
            .checked_add(tx.as_ref().len())
            .ok_or_else(|| anyhow!("block transaction bytes overflow"))?;
        ensure!(
            bytes <= MAX_BLOCK_TX_BYTES,
            "block transaction byte budget exceeded"
        );
    }
    Ok(())
}

/// A decoded account row and the size of its canonical encoding.
pub struct CachedAccount {
    pub row: Account,
    pub encoded_len: usize,
}

struct CacheState {
    /// The committed height the entries describe. Entries are only read or
    /// added by a caller working on exactly this height.
    height: Option<u64>,
    /// A newer and an older generation. A lookup tries both; when the newer
    /// one is full the older one is dropped. Memory stays bounded and a full
    /// cache never has to be emptied at once.
    current: HashMap<u64, Arc<CachedAccount>>,
    previous: HashMap<u64, Arc<CachedAccount>>,
    generation: usize,
}
impl CacheState {
    fn insert(&mut self, id: u64, entry: Arc<CachedAccount>) {
        if self.current.len() >= self.generation {
            let retired = std::mem::replace(&mut self.previous, std::mem::take(&mut self.current));
            // Freeing a full generation takes a while: not under the lock.
            rayon::spawn(move || drop(retired));
        }
        self.current.insert(id, entry);
    }
}

/// Decoded account rows of the latest committed version.
///
/// Correctness rule: an entry is the account's row at `height`, nothing else.
/// Readers and loaders name the height they work on and are ignored if it is
/// not the cache's height; `advance` moves the height and installs every row
/// that the new block changed, under the same lock. A reader working on an
/// older version therefore can neither see newer rows nor store older ones.
pub struct AccountCache {
    state: RwLock<CacheState>,
}

impl AccountCache {
    fn new(height: Option<u64>) -> Self {
        Self::with_generation(height, ACCOUNT_CACHE_GENERATION)
    }
    fn with_generation(height: Option<u64>, generation: usize) -> Self {
        Self {
            state: RwLock::new(CacheState {
                height,
                current: HashMap::new(),
                previous: HashMap::new(),
                generation: generation.max(1),
            }),
        }
    }
    fn get(&self, height: u64, id: u64) -> Option<Arc<CachedAccount>> {
        let state = self.state.read().ok()?;
        if state.height != Some(height) {
            return None;
        }
        state
            .current
            .get(&id)
            .or_else(|| state.previous.get(&id))
            .cloned()
    }
    /// Those of `ids` that are not cached for `height`. Empty when the cache
    /// describes another height: loading for it would be thrown away.
    fn missing(&self, height: u64, ids: Vec<u64>) -> Vec<u64> {
        match self.state.read() {
            Ok(state) if state.height == Some(height) => ids
                .into_iter()
                .filter(|id| !state.current.contains_key(id) && !state.previous.contains_key(id))
                .collect(),
            _ => Vec::new(),
        }
    }
    fn insert_loaded(&self, height: u64, id: u64, entry: Arc<CachedAccount>) {
        self.insert_many(height, vec![(id, entry)]);
    }
    fn insert_many(&self, height: u64, entries: Vec<(u64, Arc<CachedAccount>)>) {
        if let Ok(mut state) = self.state.write() {
            if state.height == Some(height) {
                for (id, entry) in entries {
                    state.insert(id, entry);
                }
            }
        }
    }
    /// Moves the cache from the parent height to the newly committed one.
    fn advance(&self, parent: Option<u64>, height: u64, changed: Vec<(u64, Arc<CachedAccount>)>) {
        // A poisoned lock means another thread panicked; the process is
        // already stopping (see the panic hook in main.rs).
        if let Ok(mut state) = self.state.write() {
            // Rows left from the parent are still right only if they describe
            // the parent and were not changed by this block.
            if state.height != parent {
                let retired = (
                    std::mem::take(&mut state.current),
                    std::mem::take(&mut state.previous),
                );
                rayon::spawn(move || drop(retired));
            }
            for (id, entry) in changed {
                state.insert(id, entry);
                // No older copy of a changed row may survive in the older
                // generation (removed after the insert, which may rotate).
                state.previous.remove(&id);
            }
            state.height = Some(height);
        }
    }
    fn len(&self) -> usize {
        self.state
            .read()
            .map_or(0, |state| state.current.len() + state.previous.len())
    }
}

/// The transactions whose stateless signature check passed.
fn signed<'a, T: AsRef<[u8]>>(txs: &'a [T], statuses: &[SigStatus]) -> Vec<&'a [u8]> {
    txs.iter()
        .zip(statuses)
        .filter(|(_, status)| **status == SigStatus::Valid)
        .map(|(tx, _)| tx.as_ref())
        .collect()
}

/// The accounts a transaction will read, taken from its bytes alone: the
/// sender and, for payments, the recipient. Only a hint for loading accounts
/// ahead of execution; no rule relies on it.
fn touched_ids(raw: &[u8]) -> [Option<u64>; 2] {
    #[derive(Deserialize)]
    struct Recipient<'a> {
        to: &'a str,
    }
    let start = crate::wire::DOMAIN.len() + 32;
    let Some(header) = raw.get(start..crate::wire::HEADER) else {
        return [None, None];
    };
    let mut from = [0u8; 8];
    from.copy_from_slice(&header[1..9]);
    let from = u64::from_be_bytes(from);
    let to = if matches!(header[0], 3 | 10) {
        raw.len()
            .checked_sub(64)
            .and_then(|end| raw.get(crate::wire::HEADER..end))
            .and_then(|payload| serde_json::from_slice::<Recipient>(payload).ok())
            .and_then(|recipient| recipient.to.parse().ok())
    } else {
        None
    };
    [(from != u64::MAX).then_some(from), to]
}

/// A committed account row, decoded and checked exactly as the first load of
/// that row inside a block checks it.
fn load_committed(version: &Version, meta: &Meta, id: u64) -> Result<CachedAccount> {
    let bytes = version
        .get(&account_key(id))
        .ok_or_else(|| anyhow!("account does not exist"))?;
    ensure!(bytes.len() <= MAX_ACCOUNT_BYTES, "account byte limit");
    let row: Account = canonical_decode(&bytes)?;
    ensure!(row.id == id, "account ID mismatch");
    validate_account(&row, meta)?;
    let index = index_bytes(id)?;
    ensure!(
        version.get(&name_key(&row.name)).as_deref() == Some(index.as_slice())
            && version.get(&pubkey_key(&row.public_key)?).as_deref() == Some(index.as_slice()),
        "account identity index mismatch"
    );
    Ok(CachedAccount {
        row,
        encoded_len: bytes.len(),
    })
}

pub fn account_key(id: u64) -> Vec<u8> {
    [b"account/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn recovery_key(id: u64) -> Vec<u8> {
    [b"recovery/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn unbond_key(id: u64) -> Vec<u8> {
    [b"unbond/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn name_key(name: &str) -> Vec<u8> {
    [b"name/".as_slice(), name.as_bytes()].concat()
}
pub fn pubkey_key(key: &str) -> Result<Vec<u8>> {
    Ok([b"pubkey/".as_slice(), &hex32(key)?].concat())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    #[serde(with = "decimal::u64")]
    pub protocol_version: u64,
    // Genesis and configuration never change after InitChain. Sharing them
    // makes copying the metadata cheap; the encoding is unchanged.
    pub genesis: Arc<Genesis>,
    pub config: Arc<crate::genesis::Genesis>,
    #[serde(with = "decimal::u64")]
    pub pos_assets_total: u64,
    #[serde(with = "decimal::u64")]
    pub auction_reserve_total: u64,
    #[serde(with = "decimal::u64")]
    pub history_pruned_through: u64,
    #[serde(with = "decimal::i64")]
    pub history_pruned_time: i64,
    pub network_id: String,
    #[serde(with = "decimal::i64")]
    pub height: i64,
    #[serde(with = "decimal::i64")]
    pub time_micros: i64,
    #[serde(with = "decimal::u64")]
    pub bank: u64,
    #[serde(with = "decimal::u64")]
    pub account_count: u64,
    #[serde(with = "decimal::u64")]
    pub next_account_id: u64,
    #[serde(with = "decimal::u64")]
    pub liquid_total: u64,
    #[serde(with = "decimal::u64")]
    pub unbond_total: u64,
    pub pools: Vec<Pool>,
    #[serde(with = "decimal::vec_u64")]
    pub pool_share_totals: Vec<u64>,
    #[serde(with = "decimal::u64")]
    pub auction_epoch: u64,
    pub auction_bids: Vec<AuctionBid>,
    pub name_commits: Vec<NameCommit>,
    #[serde(with = "decimal::u64")]
    pub next_unbond_id: u64,
    /// The total of all stops so far, in microseconds, on a network with
    /// `waits_survive_stops`: a stop is the part of the gap between a block
    /// and its parent beyond `security::STOP_THRESHOLD_MICROS` (five
    /// minutes), and the block that follows the gap adds it
    /// (`Engine::overlay`). The account security
    /// rules count their waits on the chain's time minus this total
    /// (`active_micros`). On any other network the field is absent, and the
    /// row has the encoding it always had.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_decimal")]
    pub stopped_micros: Option<u64>,
    /// All the seconds the market holds, in microseconds, on a network with
    /// the market (`spec/market.md`, section 4): what sell orders offer,
    /// the bonds of buy orders, and the seconds and deposits of fills. It is
    /// one more term of the supply rule. On any other network the field is
    /// absent, and the row has the encoding it always had.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "optional_decimal")]
    pub market_micros: Option<u64>,
}
/// `Option<u64>` as a decimal string. `None` is written by leaving the
/// field out, and read from its absence only.
mod optional_decimal {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => super::decimal::u64::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
        super::decimal::u64::deserialize(deserializer).map(Some)
    }
}

impl Meta {
    pub fn elapsed_micros(&self) -> Result<u64> {
        Ok(u64::try_from(
            self.time_micros
                .checked_sub(self.genesis.genesis_time_micros)
                .ok_or_else(|| anyhow!("elapsed overflow"))?,
        )?)
    }
    /// The clock the account security rules count their waits on
    /// (`crate::security`, "The clock of the waits"): on a network with
    /// `waits_survive_stops` the chain's time since genesis minus the total
    /// of all stops, and on any other network the chain's time.
    pub fn active_micros(&self) -> Result<u64> {
        let elapsed = self.elapsed_micros()?;
        match self.stopped_micros {
            Some(stopped) => elapsed
                .checked_sub(stopped)
                .ok_or_else(|| anyhow!("the stops exceed the chain's time")),
            None => Ok(elapsed),
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.protocol_version >= rules::FIRST_VERSION && *self.genesis == self.config.ledger,
            "v4 configuration mismatch"
        );
        ensure!(
            self.genesis.accounts.len() <= MAX_GENESIS_ACCOUNTS,
            "bounded genesis exceeded"
        );
        ensure!(
            self.network_id == self.config.network_id()?,
            "v4 network mismatch"
        );
        ensure!(
            self.height >= 0
                && self.account_count >= self.genesis.accounts.len() as u64
                && self.account_count <= MAX_ACCOUNTS
                && self.next_account_id != u64::MAX
                && self.account_count <= self.next_account_id,
            "metadata coordinates/count"
        );
        if let Some(last) = self.genesis.accounts.last() {
            ensure!(self.next_account_id > last.id, "nextID precedes genesis");
        }
        let elapsed = self.elapsed_micros()?;
        ensure!(
            self.stopped_micros.is_some() == self.config.waits_survive_stops,
            "the total of stops belongs to a network with waits_survive_stops, and to no other"
        );
        ensure!(
            self.stopped_micros.is_none_or(|stopped| stopped <= elapsed),
            "the stops exceed the chain's time"
        );
        ensure!(
            self.market_micros.is_some() == self.config.market,
            "the market's total belongs to a network with the market, and to no other"
        );
        ensure!(
            (self.height == 0 && self.history_pruned_through == 0
                || self.height > 0 && self.history_pruned_through < self.height as u64)
                && self.history_pruned_time >= self.genesis.genesis_time_micros
                && self.history_pruned_time <= self.time_micros,
            "history cleanup coordinates"
        );
        if self.history_pruned_through == 0 {
            ensure!(
                self.history_pruned_time == self.genesis.genesis_time_micros,
                "empty history cleanup clock"
            );
        } else {
            ensure!(
                self.time_micros
                    .checked_sub(self.history_pruned_time)
                    .is_some_and(|age| age > pos::UNBOND_DELAY as i64),
                "history cleanup removed slashable height"
            );
        }

        ensure!(self.height <= 1 || elapsed > 0, "nonadvancing time");
        ensure!(
            self.unbond_total == 0
                && self.pools.is_empty()
                && self.pool_share_totals.is_empty()
                && self.auction_bids.is_empty()
                && self.next_unbond_id == 0,
            "legacy economics forbidden onv4"
        );
        let supply = self
            .bank
            .checked_add(self.liquid_total)
            .and_then(|s| s.checked_add(self.pos_assets_total))
            .and_then(|s| s.checked_add(self.auction_reserve_total))
            .and_then(|s| s.checked_add(self.market_micros.unwrap_or(0)))
            .ok_or_else(|| anyhow!("supply overflow"))?;
        ensure!(supply == elapsed, "supply differs from elapsed chain time");
        ensure!(
            self.auction_epoch
                == elapsed / (self.config.auction.epoch_seconds * ledger::MICROS_PER_SECOND),
            "auction epoch mirror mismatch"
        );
        ensure!(
            self.name_commits.is_empty(),
            "v4 commitments must be external paid registration rows"
        );
        ensure!(
            self.name_commits.len() <= MAX_COMMITS
                && self
                    .name_commits
                    .windows(2)
                    .all(|w| w[0].public_key < w[1].public_key),
            "commit bound/order"
        );
        for commitment in &self.name_commits {
            valid_public_key(&commitment.public_key)?;
            hex32(&commitment.commitment)?;
            ensure!(
                commitment.height > 0
                    && commitment.height <= self.height
                    && commitment.expires_elapsed_micros >= elapsed,
                "invalid pending commitment"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_META_BYTES,
            "metadata byte limit"
        );
        Ok(())
    }
    fn view(&self, accounts: Vec<Account>, recovery_cases: Vec<RecoveryCase>) -> State {
        State {
            genesis: (*self.genesis).clone(),
            network_id: self.network_id.clone(),
            height: self.height,
            time_micros: self.time_micros,
            bank: self.bank,
            accounts,
            name_commits: self.name_commits.clone(),
            pools: self.pools.clone(),
            auction_epoch: self.auction_epoch,
            auction_bids: self.auction_bids.clone(),
            next_unbond_id: self.next_unbond_id,
            recovery_cases,
            protocol_version: 1,
        }
    }
    fn absorb(&mut self, state: &State) {
        self.height = state.height;
        self.time_micros = state.time_micros;
        self.bank = state.bank;
        self.name_commits = state.name_commits.clone();
        self.pools = state.pools.clone();
        self.auction_epoch = state.auction_epoch;
        self.auction_bids = state.auction_bids.clone();
        self.next_unbond_id = state.next_unbond_id;
    }
}

pub fn network_id(genesis: &crate::genesis::Genesis) -> Result<String> {
    genesis.network_id()
}

pub struct Prepared {
    pub root: [u8; 32],
    pub meta: Meta,
    pub txcount: usize,
    pub touched_accounts: usize,
    pub changed_accounts: usize,
    pub unbond_index_checks: usize,
    pub updated_rows: usize,
    pub validators: Vec<pos::Validator>,
    pub validator_updates: Vec<pos::Validator>,
    history_append: Option<history::Append>,
    /// The history entry of this block is already on disk.
    history_durable: bool,
    /// What this block did to a scheduled plan, for the node's log.
    pub upgrade_events: Vec<upgrade::Event>,
    tree: PreparedTree,
    /// Canonical encoding of `meta`, as written to the meta row.
    meta_bytes: Vec<u8>,
    /// Decoded rows of every account this block changed.
    changed_rows: Vec<(u64, Arc<CachedAccount>)>,
}

/// The committed head: decoded metadata and the state version it describes.
/// They are replaced together, so they cannot disagree.
struct Committed {
    meta: Meta,
    version: Arc<Version>,
    /// Why this program executes nothing on this head, if it does not
    /// implement the head's version (`upgrade::runnable`).
    not_runnable: Option<upgrade::NotRunnable>,
    /// Why a fix release executes nothing on this head although it
    /// implements its version: the head is past the program's rule switch
    /// and still under the version before it (`upgrade::missed_switch`).
    missed_switch: Option<upgrade::MissedSwitch>,
}
impl Committed {
    fn new(meta: Meta, version: Arc<Version>, versions: &Versions) -> Self {
        let not_runnable =
            upgrade::runnable(versions, &meta, |key| version.get(key).map(|row| row.to_vec())).err();
        let missed_switch = upgrade::missed_switch(versions, &meta);
        Self {
            meta,
            version,
            not_runnable,
            missed_switch,
        }
    }
}

/// Mempool admission state: the committed head plus the effects of every
/// transaction admitted since the last commit.
///
/// Protocol 4 checked each transaction against the committed head alone, so
/// any number of transactions with the same next nonce were admitted although
/// only one could ever be included. Here an admitted transaction is applied,
/// so a second one with the same nonce is refused, and a sequence of nonces
/// from one account is admitted in order. The state is discarded at every
/// commit; CometBFT then re-checks what is still in its mempool, in order.
///
/// This only decides mempool admission. Blocks are always executed in full on
/// the committed head.
pub struct CheckState {
    base_height: u64,
    overlay: Overlay,
    /// Metadata of the committed head, for what is judged on the head alone.
    head: Meta,
    /// Protective account actions admitted since the last commit: account,
    /// signing key and kind.
    protective: BTreeSet<(u64, String, u8)>,
}

impl CheckState {
    /// Height of the committed head this state was started on.
    pub fn base_height(&self) -> u64 {
        self.base_height
    }
    /// Admits the transaction if it is valid after those admitted before it.
    /// A rejected transaction leaves the state unchanged, including the rows
    /// it made the state read: what is held grows only with admitted
    /// transactions, which the consensus engine's mempool bounds.
    pub fn admit(&mut self, raw: &[u8], signature: SigStatus) -> Result<()> {
        if raw
            .get(crate::wire::DOMAIN.len() + 32)
            .is_some_and(|kind| crate::security::protective(*kind))
        {
            return self.admit_protective(raw, signature);
        }
        self.admit_pending(raw, signature)
    }
    /// An account's protective actions (freeze, cancel, root operation,
    /// finishing a replacement) are judged on the committed head alone, not
    /// on what else is waiting. Judged on the pending state, whoever holds
    /// one key of an account could keep its owner's freeze or cancellation
    /// out of the mempool block after block, with an action of his own that
    /// is admitted first and changes the count the owner's action names.
    ///
    /// Actions that exclude each other may therefore wait together. A block
    /// takes the first that still applies, and the re-check after it removes
    /// the rest. One key has one action of each protective kind waiting at a
    /// time: at most four per key and thirty-two per account, of which a
    /// block may take as few as one. (Whoever must cancel several waiting
    /// items at once freezes instead, which drops them all.)
    fn admit_protective(&mut self, raw: &[u8], signature: SigStatus) -> Result<()> {
        let action = crate::wire::decode(raw)?;
        let slot = (action.from, action.public_key.clone(), action.kind);
        ensure!(
            !self.protective.contains(&slot),
            "an action of this kind by this key is already waiting"
        );
        self.overlay.on_head(self.head.clone()).apply(raw, signature)?;
        self.protective.insert(slot);
        // Applied to the pending state as well if it still fits there, so
        // that what is admitted after it is judged with it in place.
        let _ = self.admit_pending(raw, signature);
        Ok(())
    }
    fn admit_pending(&mut self, raw: &[u8], signature: SigStatus) -> Result<()> {
        self.overlay.loaded.clear();
        let result = self.overlay.apply(raw, signature);
        if result.is_err() {
            // Only rows first read by this transaction are listed, and a
            // refused transaction changes none of them.
            for id in std::mem::take(&mut self.overlay.loaded) {
                self.overlay.accounts.remove(&id);
                self.overlay.original.remove(&id);
                self.overlay.loaded_len.remove(&id);
            }
        }
        result
    }
    /// Account rows currently held.
    pub fn rows(&self) -> usize {
        self.overlay.accounts.len()
    }
}

/// Why a state snapshot received from peers was not installed.
#[derive(Debug)]
pub enum RestoreRefusal {
    /// The staged file is not a snapshot of the offered height whose rows
    /// hash to the trusted application hash: whoever sent it is at fault.
    Snapshot(anyhow::Error),
    /// The snapshot is authentic but this node cannot take it (it already
    /// holds that height or a later one, it is on another network, its disk
    /// failed, or this engine cannot read that state). No peer is at fault.
    Node(anyhow::Error),
    /// The snapshot is authentic, but its state is under a protocol version
    /// this program does not implement, or implements under another
    /// specification hash. Nothing was installed and no peer is at fault:
    /// the operator installs a release that implements that version.
    Version(upgrade::NotRunnable),
}

pub struct Engine {
    store: Arc<Store>,
    committed: Option<Committed>,
    history_path: Option<PathBuf>,
    history_archive: Option<Mutex<history::archive::Archive>>,
    /// Set on a node whose state was restored from a snapshot: the history
    /// summary of the restored height. The archive holds no leaf at or below
    /// its size, only its frontier (`history::archive::Archive::seed`).
    history_base: Option<history::Summary>,
    accounts: Arc<AccountCache>,
    signatures: Arc<SigCache>,
    /// The versions of the rules this program implements (`rules::IMPLEMENTED`
    /// unless `implementing` replaced it).
    versions: Arc<Versions>,
}

impl Engine {
    pub fn open(store: Store) -> Result<Self> {
        let versions = Arc::new(Versions::release());
        let committed = match store.current()? {
            None => None,
            Some(version) => {
                let bytes = version
                    .get(META_KEY)
                    .ok_or_else(|| anyhow!("head without authenticated metadata"))?;
                ensure!(
                    *bytes == *version.head().metadata,
                    "head metadata mismatch"
                );
                let meta: Meta = canonical_decode(&bytes)?;
                meta.validate()?;
                ensure!(
                    meta.height as u64 == version.height(),
                    "head/ledger height mismatch"
                );
                Some(Committed::new(meta, version, &versions))
            }
        };
        let height = committed.as_ref().map(|c| c.version.height());
        Ok(Self {
            store: Arc::new(store),
            committed,
            history_path: None,
            history_archive: None,
            history_base: None,
            accounts: Arc::new(AccountCache::new(height)),
            signatures: Arc::new(SigCache::new()),
            versions,
        })
    }
    pub fn open_with_history(store: Store, directory: impl AsRef<Path>) -> Result<Self> {
        let mut engine = Self::open(store)?;
        engine.history_path = Some(directory.as_ref().to_path_buf());
        if let Some(Committed { meta, version, .. }) = &engine.committed {
            let mut archive =
                history::archive::Archive::open(directory.as_ref(), hex32(&meta.network_id)?)?;
            let summary: history::Summary = canonical_decode(
                &version
                    .get(history::KEY)
                    .ok_or_else(|| anyhow!("missing authenticated history summary"))?,
            )?;
            ensure!(
                summary.size == meta.height as u64
                    && summary.network_id == meta.network_id
                    && summary.last_time_micros == u64::try_from(meta.time_micros)?,
                "history/ledger head mismatch"
            );
            archive.verify_committed_prefix(&summary)?;
            // A record above the state's height is what a restore left that
            // stopped before it installed anything. It describes nothing
            // this node holds, and is removed before the node grows past it.
            for height in history_base_heights(directory.as_ref()) {
                if height > summary.size {
                    let _ = std::fs::remove_file(history_base_path(directory.as_ref(), height));
                }
            }
            engine.history_base = read_history_base(directory.as_ref(), &summary, &mut archive);
            engine.history_archive = Some(Mutex::new(archive));
        }
        Ok(engine)
    }
    /// The same engine as a program that implements `versions` instead of
    /// this build's list. Tests run two programs from one source with it; the
    /// node binary always runs its build's list.
    pub fn implementing(mut self, versions: Versions) -> Self {
        self.versions = Arc::new(versions);
        if let Some(committed) = self.committed.take() {
            self.committed = Some(Committed::new(committed.meta, committed.version, &self.versions));
        }
        self
    }
    /// The versions of the rules this program implements.
    pub fn implemented(&self) -> &Arc<Versions> {
        &self.versions
    }
    /// Whether this program executes on the committed head: `Err` says why
    /// not. A program executes nothing, validates nothing and admits nothing
    /// on a head whose version it does not implement; the node stops there
    /// (`app::StopCause::Upgrade`). An engine without state is runnable.
    pub fn runnable(&self) -> std::result::Result<(), &upgrade::NotRunnable> {
        match self.committed.as_ref().and_then(|committed| committed.not_runnable.as_ref()) {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }
    fn ensure_runnable(&self) -> Result<()> {
        if let Err(reason) = self.runnable() {
            anyhow::bail!(
                "this program does not implement protocol version {} and executes nothing on this head",
                reason.version
            );
        }
        if let Some(missed) = self.missed_switch() {
            anyhow::bail!(
                "this fix release switches the rules in block {} and executes nothing on a head past it that is still under protocol version {}",
                missed.block_height,
                missed.head_version
            );
        }
        Ok(())
    }
    /// Why a fix release executes nothing on the committed head, if that
    /// head is past the program's rule switch and still under the version
    /// before it (`upgrade::missed_switch`). The node stops there
    /// (`app::StopCause::SwitchMissed`). `None` in every program that is not
    /// a fix release.
    pub fn missed_switch(&self) -> Option<&upgrade::MissedSwitch> {
        self.committed.as_ref().and_then(|committed| committed.missed_switch.as_ref())
    }
    /// Whether block `height` with the hash `block_hash`, the next one on
    /// the committed head, is a switch block of this program, and then what
    /// it must be (`upgrade::switch_block`).
    pub fn switch_block(&self, height: u64, block_hash: [u8; 32]) -> Result<Option<upgrade::SwitchBlock>> {
        let committed = self.committed()?;
        upgrade::switch_block(&self.versions, &committed.meta, height, block_hash, committed.version.root())
    }
    /// The plan and the signals at the committed head (`upgrade/state`), if
    /// the row exists.
    pub fn upgrade_state(&self) -> Result<Option<upgrade::State>> {
        match self.version().and_then(|version| version.get(upgrade::STATE_KEY)) {
            Some(row) => Ok(Some(upgrade::State::decode(&row)?)),
            None => Ok(None),
        }
    }
    /// The height of the last block above its state that this node made a
    /// history entry for, if it keeps an archive; its state's height if
    /// there is none above. A block gets its entry when it is committed,
    /// and a replay does not cut the entries after the block it replays, so
    /// after a start from an older snapshot this is how far the node had
    /// come while its state is still at the snapshot. Records that a
    /// restore left in the archive without ever installing its state are
    /// not entries of blocks and do not count.
    pub fn history_reached(&self) -> Result<Option<u64>> {
        let floor = self.version().map_or(0, |version| version.height());
        match &self.history_archive {
            Some(archive) => Ok(Some(
                archive
                    .lock()
                    .map_err(|_| anyhow!("history archive lock poisoned"))?
                    .last_entry_above(floor)?,
            )),
            None => Ok(None),
        }
    }
    /// The height this node's state was restored at from a snapshot, if it
    /// was: the node holds no block history at or below it.
    pub fn history_base(&self) -> Option<u64> {
        self.history_base.as_ref().map(|base| base.size)
    }
    /// Whether this node may take a state from a snapshot: only a node that
    /// has executed no block on the state it holds. That is a node with no
    /// state, one at genesis, or one that holds a state it restored and has
    /// not built on (a restore its CometBFT did not live to record). A node
    /// that has executed blocks keeps what it built; to join by state sync
    /// again its operator removes its state and history directories.
    pub fn restorable(&self) -> Result<()> {
        let Some(current) = &self.committed else {
            return Ok(());
        };
        let height = current.version.height();
        ensure!(
            height == 0 || self.history_base() == Some(height),
            "this node has executed blocks up to height {height}: it does not replace its state with a snapshot. To join by state sync again, stop it and remove its state and history directories"
        );
        Ok(())
    }
    /// Replaces the node's state with the snapshot staged in `staged`, if
    /// that file is a snapshot of `height` whose rows hash to `app_hash`
    /// (the hash CometBFT's light client verified) and the node may restore
    /// (`restorable`): it holds no state, or an older one of the same
    /// network on which it has executed no block. On any refusal the state,
    /// in memory and on disk, is what it was; the caller removes the file.
    ///
    /// Order, so that a crash at any point leaves a node that starts:
    /// 1. check the file in a pass that keeps no row, then read it back and
    ///    rebuild the tree (`Store::verify_staged`; no effect);
    /// 2. read the metadata and history rows as `open` does (no effect);
    /// 3. prepare the history archive: its frontier at this height, no leaf
    ///    at or below it, and a record of the height. This is harmless if
    ///    the restore stops here, because of what `restorable` allows: a
    ///    node without state or at genesis has no history to lose, and one
    ///    that restored an older height keeps that height's frontier, which
    ///    is all it reads, and ignores a record above its own height;
    /// 4. move the file into place as the restart snapshot and swap the
    ///    state in memory (`Store::install_restored`).
    pub fn restore(
        &mut self,
        staged: &Path,
        height: u64,
        app_hash: [u8; 32],
    ) -> std::result::Result<Head, RestoreRefusal> {
        let version = self
            .store
            .verify_staged(staged, height, app_hash)
            .map_err(RestoreRefusal::Snapshot)?;
        // From here on the rows are the chain's own state at that height.
        let node = RestoreRefusal::Node;
        // The version first, read from the metadata row as plain JSON: a
        // later version may have rows this program cannot decode at all, and
        // the operator should be told "install the release", not "damaged".
        if let Some(named) = version.get(META_KEY).and_then(|bytes| peek_version(&bytes))
            && self.versions.spec_of(named).is_none()
        {
            return Err(RestoreRefusal::Version(upgrade::NotRunnable {
                version: named,
                spec: None,
                from_height: None,
                head: height,
                implemented: self.versions.describe(),
                other_rules: false,
            }));
        }
        let (meta, summary) = (|| -> Result<(Meta, history::Summary)> {
            let bytes = version
                .get(META_KEY)
                .ok_or_else(|| anyhow!("head without authenticated metadata"))?;
            let meta: Meta = canonical_decode(&bytes)?;
            meta.validate()?;
            ensure!(
                meta.height as u64 == version.height() && height > 0,
                "head/ledger height mismatch"
            );
            ensure!(
                !meta.genesis.chain_id.starts_with("time-devnet-fixture-"),
                "benchmark fixture states cannot be restored by the network binary"
            );
            let summary: history::Summary = canonical_decode(
                &version
                    .get(history::KEY)
                    .ok_or_else(|| anyhow!("missing authenticated history summary"))?,
            )?;
            summary.validate()?;
            ensure!(
                summary.size == meta.height as u64
                    && summary.network_id == meta.network_id
                    && summary.last_time_micros == u64::try_from(meta.time_micros)?,
                "history/ledger head mismatch"
            );
            Ok((meta, summary))
        })()
        .map_err(|error| node(error.context("the restored state cannot be read by this engine")))?;
        // A state under rules this program does not implement is never
        // installed: the program could execute nothing on it, and replacing
        // a state it can run by one it cannot would leave the operator with
        // less. The node keeps what it has and says what to install.
        if let Err(reason) =
            upgrade::runnable(&self.versions, &meta, |key| version.get(key).map(|row| row.to_vec()))
        {
            return Err(RestoreRefusal::Version(reason));
        }
        // Nor a state that is past this fix release's rule switch and still
        // under the version before it: the chain it comes from went on
        // without the switch.
        if let Some(missed) = upgrade::missed_switch(&self.versions, &meta) {
            return Err(node(anyhow!(missed.explain())));
        }
        if let Some(current) = &self.committed {
            if current.meta.network_id != meta.network_id {
                return Err(node(anyhow!(
                    "the snapshot is of network {}, this node holds network {}",
                    meta.network_id,
                    current.meta.network_id
                )));
            }
            if current.version.height() >= height {
                return Err(node(anyhow!(
                    "the node already holds height {}, the snapshot is of height {height}",
                    current.version.height()
                )));
            }
        }
        self.restorable().map_err(node)?;
        // The archive: opened here if the node had no state yet.
        let mut opened = None;
        if let Some(directory) = &self.history_path {
            (|| -> Result<()> {
                let network = hex32(&meta.network_id)?;
                match &self.history_archive {
                    Some(archive) => archive
                        .lock()
                        .map_err(|_| anyhow!("history archive lock poisoned"))?
                        .seed(&summary)?,
                    None => {
                        let mut archive = history::archive::Archive::open(directory, network)?;
                        archive.seed(&summary)?;
                        opened = Some(archive);
                    }
                }
                write_history_base(directory, &summary)
            })()
            .map_err(|error| node(error.context("prepare the history archive")))?;
        }
        let version = match self.store.install_restored(version, staged) {
            Ok(version) => version,
            Err(error) => {
                // Nothing was installed: the record written for this height
                // describes no state of this node.
                if let Some(directory) = &self.history_path {
                    let _ = std::fs::remove_file(history_base_path(directory, summary.size));
                }
                return Err(node(error));
            }
        };
        // Nothing below can fail.
        if let Some(archive) = opened {
            self.history_archive = Some(Mutex::new(archive));
        }
        if let Some(directory) = &self.history_path {
            remove_other_history_bases(directory, summary.size);
            self.history_base = Some(summary);
        }
        let head = version.head().clone();
        // Decoded rows of the state that was replaced are of no use.
        self.accounts = Arc::new(AccountCache::new(Some(version.height())));
        self.committed = Some(Committed::new(meta, version, &self.versions));
        Ok(head)
    }
    pub fn history_proof(&self, version: &Version, height: u64) -> Result<history::Proof> {
        let raw = version
            .proof(history::KEY)?
            .verify(version.root(), history::KEY)?
            .ok_or_else(|| anyhow!("missing authenticated history summary"))?;
        let summary: history::Summary = canonical_decode(&raw)?;
        if let Some(base) = self.history_base() {
            ensure!(
                height > base,
                "this node holds no block history at or below height {base}: its state was restored from a snapshot of that height"
            );
        }
        self.history_archive
            .as_ref()
            .ok_or_else(|| anyhow!("history proof archive unavailable in pure library mode"))?
            .lock()
            .map_err(|_| anyhow!("history archive lock poisoned"))?
            .prove(&summary, height)
    }
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
    pub fn meta(&self) -> Option<&Meta> {
        self.committed.as_ref().map(|committed| &committed.meta)
    }
    /// The committed state version that `meta` describes.
    pub fn version(&self) -> Option<&Arc<Version>> {
        self.committed.as_ref().map(|committed| &committed.version)
    }
    pub fn head(&self) -> Result<Option<Head>> {
        Ok(self.version().map(|version| version.head().clone()))
    }
    pub fn signatures(&self) -> &Arc<SigCache> {
        &self.signatures
    }
    /// Decoded account rows currently cached for the committed head.
    pub fn cached_accounts(&self) -> usize {
        self.accounts.len()
    }
    pub fn active_roster_at(&self, height: u64) -> Result<Vec<pos::Validator>> {
        let version = self
            .version()
            .ok_or_else(|| anyhow!("uninitialized engine"))?;
        crate::pos_adapter::roster_at(|key| Ok(version.get(key).map(|row| row.to_vec())), height)
    }
    fn committed(&self) -> Result<&Committed> {
        self.committed
            .as_ref()
            .ok_or_else(|| anyhow!("uninitialized engine"))
    }
    fn overlay_on(&self, committed: &Committed) -> Overlay {
        Overlay {
            base: Some(committed.version.clone()),
            cache: Some(self.accounts.clone()),
            meta: committed.meta.clone(),
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            original: BTreeMap::new(),
            recoveries: BTreeMap::new(),
            validators: Vec::new(),
            validator_updates: Vec::new(),
            history_append: None,
            safety_hold: None,
            loaded_len: BTreeMap::new(),
            generic_transfers: false,
            journal: false,
            loaded: Vec::new(),
            admission: false,
            fees: 0,
            rules: Rules::of(&committed.meta),
            parent_time_micros: committed.meta.time_micros,
            upgrade: None,
            local: None,
            switch: None,
        }
    }
    /// Loads the accounts these transactions will read into the account
    /// cache, on all cores. Purely a warm-up for the sequential execution
    /// that follows: a row that fails any check is not cached, and the
    /// sequential path then reports the error itself.
    pub fn preload<T: AsRef<[u8]> + Sync>(&self, txs: &[T]) {
        let Some(committed) = &self.committed else {
            return;
        };
        if txs.len() < PRELOAD_MINIMUM {
            return;
        }
        let height = committed.version.height();
        let mut ids: Vec<u64> = txs
            .par_iter()
            .flat_map_iter(|tx| touched_ids(tx.as_ref()).into_iter().flatten())
            .collect();
        ids.par_sort_unstable();
        ids.dedup();
        let missing = self.accounts.missing(height, ids);
        if missing.len() < PRELOAD_MINIMUM {
            return;
        }
        let loaded: Vec<(u64, Arc<CachedAccount>)> = missing
            .par_iter()
            .filter_map(|id| {
                load_committed(&committed.version, &committed.meta, *id)
                    .ok()
                    .map(|entry| (*id, Arc::new(entry)))
            })
            .collect();
        self.accounts.insert_many(height, loaded);
    }
    /// Mempool validation uses committed coordinates and never advances time,
    /// settles an auction, publishes a row, or permits same-height reveals.
    pub fn validate_tx(&self, raw: &[u8]) -> Result<()> {
        let committed = self.committed()?;
        self.ensure_runnable()?;
        let signature = self.signatures.check(raw);
        let mut overlay = self.overlay_on(committed);
        overlay.admission = true;
        overlay.local = Some(self.versions.clone());
        overlay.apply(raw, signature)
    }
    /// Starts mempool admission on top of the committed head.
    pub fn check_state(&self) -> Result<CheckState> {
        let committed = self.committed()?;
        self.ensure_runnable()?;
        let mut overlay = self.overlay_on(committed);
        overlay.journal = true;
        overlay.admission = true;
        overlay.local = Some(self.versions.clone());
        Ok(CheckState {
            base_height: committed.version.height(),
            head: committed.meta.clone(),
            protective: BTreeSet::new(),
            overlay,
        })
    }
    pub fn initialize(&mut self, config: crate::genesis::Genesis) -> Result<Head> {
        // The rules a new network must use are judged when the database is
        // new; a repeated InitChain on one that exists, as it always was.
        if self.committed.is_some() {
            config.validate_initial()?;
        } else {
            config.validate_new()?;
        }
        ensure!(
            config.ledger.accounts.len() <= MAX_GENESIS_ACCOUNTS,
            "bounded genesis"
        );
        let state = ledger::new(config.ledger.clone())?;
        if let Some(Committed { meta, version, .. }) = &self.committed {
            ensure!(
                serde_json::to_vec(&meta.config)? == serde_json::to_vec(&config)?,
                "genesis differs from existing v4 database"
            );
            // CometBFT sends InitChain again only while the application is
            // still at height zero.
            ensure!(
                version.height() == 0,
                "InitChain on a chain that already has blocks"
            );
            return Ok(version.head().clone());
        }
        let mut seen = BTreeSet::new();
        for row in &state.accounts {
            ensure!(
                seen.insert(&row.public_key),
                "duplicate initial identity key"
            );
        }
        let meta = Meta {
            protocol_version: rules::FIRST_VERSION,
            network_id: config.network_id()?,
            // A network whose waits survive a stop counts its stops from
            // the first block; any other has no such number.
            stopped_micros: config.waits_survive_stops.then_some(0),
            // A network with the market starts with nothing in it.
            market_micros: config.market.then_some(0),
            genesis: Arc::new(state.genesis),
            config: Arc::new(config),
            pos_assets_total: 0,
            auction_reserve_total: 0,
            history_pruned_through: 0,
            history_pruned_time: state.time_micros,
            height: 0,
            time_micros: state.time_micros,
            bank: 0,
            account_count: state.accounts.len() as u64,
            next_account_id: state.accounts.last().map_or(Ok(0), |a| {
                a.id.checked_add(1).ok_or_else(|| anyhow!("ID exhausted"))
            })?,
            liquid_total: 0,
            unbond_total: 0,
            pools: Vec::new(),
            pool_share_totals: Vec::new(),
            auction_epoch: 0,
            auction_bids: Vec::new(),
            name_commits: Vec::new(),
            next_unbond_id: 0,
        };
        meta.validate()?;
        if let Some(directory) = &self.history_path {
            self.history_archive = Some(Mutex::new(history::archive::Archive::open(
                directory,
                hex32(&meta.network_id)?,
            )?));
            // A chain that starts at genesis was not restored from anything:
            // a record left by a restore that never finished must not
            // describe it once it has grown past that height.
            for height in history_base_heights(directory) {
                let _ = std::fs::remove_file(history_base_path(directory, height));
            }
        }
        let initial_history =
            history::Summary::empty(hex32(&meta.network_id)?, u64::try_from(meta.time_micros)?);
        let mut overlay = Overlay {
            base: None,
            cache: None,
            meta,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            original: BTreeMap::new(),
            recoveries: BTreeMap::new(),
            validators: Vec::new(),
            validator_updates: Vec::new(),
            history_append: None,
            safety_hold: None,
            loaded_len: BTreeMap::new(),
            generic_transfers: false,
            journal: false,
            loaded: Vec::new(),
            admission: false,
            fees: 0,
            rules: Rules::first(),
            parent_time_micros: state.time_micros,
            upgrade: None,
            local: None,
            switch: None,
        };
        overlay.updates.insert(
            history::KEY.to_vec(),
            Some(serde_json::to_vec(&initial_history)?),
        );
        let distinct_names = overlay.meta.config.distinct_names;
        let config = overlay.meta.config.clone();
        for mut account in state.accounts {
            // An account that starts protected (`protected_accounts`): its
            // keys in their roles take the place of the one key the
            // protocol-4 rules give it, and it has its security row from
            // the first block, as if it had adopted the rules at genesis.
            // Its identity key stays what the genesis says.
            if let Ok(index) = config
                .protected_accounts
                .binary_search_by_key(&account.id, |protected| protected.id)
            {
                let (devices, security) =
                    config.protected_accounts[index].set(config.recovery_min_delay_micros)?;
                account.devices = devices;
                validate_account(&account, &overlay.meta)?;
                crate::security::validate(&overlay.meta, &account, &security)?;
                overlay.updates.insert(
                    crate::security::key(account.id),
                    Some(crate::security::encode(&security)?),
                );
            }
            if distinct_names {
                // The genesis was checked: no two of its names look alike,
                // and each has a skeleton (`Genesis::validate`).
                let previous = overlay.updates.insert(
                    crate::names::key(&crate::names::skeleton(&account.name)),
                    Some(serde_json::to_vec(&account.name)?),
                );
                ensure!(previous.is_none(), "genesis account names look alike");
            }
            overlay
                .updates
                .insert(name_key(&account.name), Some(index_bytes(account.id)?));
            overlay.updates.insert(
                pubkey_key(&account.public_key)?,
                Some(index_bytes(account.id)?),
            );
            // With the service records: the account exists from genesis.
            if let Some((key, value)) = crate::service::account_created(&overlay.meta, account.id)? {
                overlay.updates.insert(key, Some(value));
            }
            overlay
                .updates
                .insert(account_key(account.id), Some(serde_json::to_vec(&account)?));
        }
        {
            let mut stage = ActionStage::new(&mut overlay);
            crate::pos_adapter::initialize(&mut stage)?;
            crate::bitcoin_adapter::initialize(&mut stage)?;
            crate::treasury_adapter::initialize(&mut stage)?;
            crate::auction::initialize(&mut stage)?;
            crate::registration_adapter::initialize(&mut stage)?;
            crate::service::initialize(&mut stage)?;
            crate::market::initialize(&mut stage)?;
            stage.commit();
        }
        let mut prepared = overlay.finish(&self.store, 0)?;
        prepared
            .tree
            .set_head_metadata(prepared.meta_bytes.clone(), [0; 32])?;
        let head = self.store.commit(prepared.tree)?;
        let version = self
            .store
            .current()?
            .ok_or_else(|| anyhow!("genesis version missing after commit"))?;
        self.accounts.advance(None, head.version, prepared.changed_rows);
        self.committed = Some(Committed::new(prepared.meta, version, &self.versions));
        Ok(head)
    }
    /// Executes a block on top of the committed head without publishing it.
    /// Every transaction must be valid; one failure rejects the whole block.
    /// The block carries no misbehavior (`prepare_with_misbehavior`).
    pub fn prepare<T: AsRef<[u8]> + Sync>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        block_hash: [u8; 32],
    ) -> Result<Prepared> {
        self.prepare_with_misbehavior(height, time_micros, txs, eligible, block_hash, &[])
    }
    /// As `prepare`, for a block with which CometBFT reports `misbehavior`.
    /// The list is applied after the begin-block steps and before the
    /// transactions (`crate::pos_adapter::misbehavior`); no entry can make
    /// the block fail.
    pub fn prepare_with_misbehavior<T: AsRef<[u8]> + Sync>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        block_hash: [u8; 32],
        misbehavior: &[Misbehavior],
    ) -> Result<Prepared> {
        self.prepare_proposed(height, time_micros, txs, eligible, block_hash, misbehavior, &[])
    }
    /// As `prepare_with_misbehavior`, for a block whose header names
    /// `proposer`, the consensus address of the validator that proposed it
    /// (ABCI `proposer_address`). Only the service records read it
    /// (`crate::service::record_block`): on a network without them the
    /// proposer changes nothing, and an empty or unknown address is a block
    /// that names no proposer.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_proposed<T: AsRef<[u8]> + Sync>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        block_hash: [u8; 32],
        misbehavior: &[Misbehavior],
        proposer: &[u8],
    ) -> Result<Prepared> {
        validate_block_transactions(txs)?;
        // Stateless signature checks for the whole block on all cores, then
        // the accounts its correctly signed transactions will read.
        let signatures = self.signatures.check_all(txs);
        self.preload(&signed(txs, &signatures));
        let mut overlay =
            self.overlay(height, time_micros, eligible, block_hash, true, misbehavior, proposer)?;
        for (tx, signature) in txs.iter().zip(&signatures) {
            overlay.apply(tx.as_ref(), *signature)?;
        }
        overlay.finish(&self.store, txs.len())
    }
    /// As `prepare`, with every transfer forced through the unmodified
    /// protocol-4 rule adapter and signatures verified inline. Slower; used to
    /// check that the fast path and the reference path agree.
    pub fn prepare_reference<T: AsRef<[u8]>>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        block_hash: [u8; 32],
    ) -> Result<Prepared> {
        self.prepare_reference_with_misbehavior(height, time_micros, txs, eligible, block_hash, &[])
    }
    /// As `prepare_reference`, for a block with which CometBFT reports
    /// `misbehavior`.
    pub fn prepare_reference_with_misbehavior<T: AsRef<[u8]>>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        block_hash: [u8; 32],
        misbehavior: &[Misbehavior],
    ) -> Result<Prepared> {
        self.prepare_reference_proposed(height, time_micros, txs, eligible, block_hash, misbehavior, &[])
    }
    /// As `prepare_reference_with_misbehavior`, for a block whose header
    /// names `proposer` (`prepare_proposed`).
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_reference_proposed<T: AsRef<[u8]>>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        block_hash: [u8; 32],
        misbehavior: &[Misbehavior],
        proposer: &[u8],
    ) -> Result<Prepared> {
        validate_block_transactions(txs)?;
        let mut overlay =
            self.overlay(height, time_micros, eligible, block_hash, false, misbehavior, proposer)?;
        overlay.generic_transfers = true;
        for tx in txs {
            overlay.apply(tx.as_ref(), SigStatus::Unknown)?;
        }
        overlay.finish(&self.store, txs.len())
    }
    /// Selects the transactions a proposer may include: in order, those that
    /// fit and are valid on top of the ones already selected.
    pub fn prepare_filtered<T: AsRef<[u8]> + Sync>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        maxbytes: usize,
        block_hash: [u8; 32],
    ) -> Result<(Prepared, Vec<Vec<u8>>)> {
        self.prepare_filtered_with_misbehavior(
            height,
            time_micros,
            txs,
            eligible,
            maxbytes,
            block_hash,
            &[],
        )
    }
    /// As `prepare_filtered`, for a block with which CometBFT reports
    /// `misbehavior`. The transactions are selected on the state after the
    /// misbehavior is applied, as validators will execute them.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_filtered_with_misbehavior<T: AsRef<[u8]> + Sync>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        maxbytes: usize,
        block_hash: [u8; 32],
        misbehavior: &[Misbehavior],
    ) -> Result<(Prepared, Vec<Vec<u8>>)> {
        self.prepare_filtered_proposed(height, time_micros, txs, eligible, maxbytes, block_hash, misbehavior, &[])
    }
    /// As `prepare_filtered_with_misbehavior`, for a block that `proposer`
    /// proposes (`prepare_proposed`).
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_filtered_proposed<T: AsRef<[u8]> + Sync>(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[T],
        eligible: &[String],
        maxbytes: usize,
        block_hash: [u8; 32],
        misbehavior: &[Misbehavior],
        proposer: &[u8],
    ) -> Result<(Prepared, Vec<Vec<u8>>)> {
        let candidates = &txs[..txs.len().min(MAX_BLOCK_TXS)];
        let signatures = self.signatures.check_all(candidates);
        self.preload(&signed(candidates, &signatures));
        let mut overlay =
            self.overlay(height, time_micros, eligible, block_hash, true, misbehavior, proposer)?;
        // A proposer applies this node's local policy for signals; validators
        // (`prepare_with_misbehavior`) do not.
        overlay.local = Some(self.versions.clone());
        // The block after the agreed height of a fix release: its proposer
        // proposes exactly one transaction, the switch, whatever its mempool
        // holds. (It is a few hundred bytes: no budget leaves it out.)
        if let Some(action) = overlay.switch.as_ref().and_then(|switch| switch.action.clone()) {
            overlay.apply(&action, SigStatus::Unknown)?;
            return Ok((overlay.finish(&self.store, 1)?, vec![action]));
        }
        let mut accepted = Vec::new();
        let mut used = 0usize;
        for (tx, signature) in candidates.iter().zip(&signatures) {
            let tx = tx.as_ref();
            if tx.len() > maxbytes.min(MAX_BLOCK_TX_BYTES).saturating_sub(used) {
                continue;
            }
            if overlay.apply(tx, *signature).is_ok() {
                used += tx.len();
                accepted.push(tx.to_vec());
            }
        }
        Ok((overlay.finish(&self.store, accepted.len())?, accepted))
    }
    /// Starts a block on the committed head. `cached` says whether decoded
    /// account rows may come from the account cache; the reference execution
    /// reads everything from the state itself. The block's misbehavior is
    /// applied last, after the begin-block steps and the history cleanup, so
    /// that it acts on the state the block's first transaction would see.
    /// `proposer` is the consensus address the block's header names (only
    /// the service records read it).
    #[allow(clippy::too_many_arguments)]
    fn overlay(
        &self,
        height: i64,
        time_micros: i64,
        eligible: &[String],
        block_hash: [u8; 32],
        cached: bool,
        misbehavior: &[Misbehavior],
        proposer: &[u8],
    ) -> Result<Overlay> {
        let committed = self.committed()?;
        self.ensure_runnable()?;
        let meta = &committed.meta;
        let snapshot = &committed.version;
        ensure!(
            height
                == meta
                    .height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("height exhausted"))?,
            "incorrect block height"
        );
        ensure!(
            time_micros > meta.time_micros || (meta.height == 0 && time_micros == meta.time_micros),
            "nonadvancing time"
        );
        let delta = u64::try_from(
            time_micros
                .checked_sub(meta.time_micros)
                .ok_or_else(|| anyhow!("time overflow"))?,
        )?;
        let previous_history: history::Summary = canonical_decode(
            &snapshot
                .get(history::KEY)
                .ok_or_else(|| anyhow!("missing history summary"))?,
        )?;
        previous_history.validate()?;
        ensure!(
            previous_history.size == meta.height as u64
                && previous_history.network_id == meta.network_id
                && previous_history.last_time_micros == u64::try_from(meta.time_micros)?,
            "history/ledger head mismatch"
        );
        let history_append = previous_history.append(history::Leaf {
            height: height as u64,
            block_hash: hex::encode(block_hash),
            time_micros: u64::try_from(time_micros)?,
        })?;
        let mut overlay = self.overlay_on(committed);
        if !cached {
            overlay.cache = None;
        }
        // A fix release: whether this block is where the program changes the
        // rules without a plan, and then what the block must be. A block at
        // that height on a chain that is not as the program was built to
        // find it is not executed at all. Every other program, and every
        // other block, gets `None` here.
        overlay.switch =
            upgrade::switch_block(&self.versions, meta, u64::try_from(height)?, block_hash, snapshot.root())?;
        overlay.updates.insert(
            history::KEY.to_vec(),
            Some(serde_json::to_vec(&history_append.summary)?),
        );
        overlay.history_append = Some(history_append);
        overlay.meta.height = height;
        overlay.meta.time_micros = time_micros;
        overlay.meta.bank = pos::add(overlay.meta.bank, delta)?;
        // On a network whose waits survive a stop: what this block is dated
        // after its parent beyond the five minutes of
        // `security::STOP_THRESHOLD_MICROS` is a stop, and joins the total
        // before anything in the block reads the active clock
        // (`Meta::active_micros`). One addition per block, whatever the
        // number of accounts that wait.
        if let Some(stopped) = overlay.meta.stopped_micros {
            let threshold = crate::security::stop_threshold(overlay.meta.config.profile);
            overlay.meta.stopped_micros = Some(pos::add(stopped, delta.saturating_sub(threshold))?);
        }
        let elapsed = overlay.meta.elapsed_micros()?;
        overlay
            .meta
            .name_commits
            .retain(|c| c.expires_elapsed_micros >= elapsed);
        overlay.meta.auction_epoch =
            elapsed / (overlay.meta.config.auction.epoch_seconds * ledger::MICROS_PER_SECOND);
        overlay.updates.insert(
            block_key(height as u64),
            Some(serde_json::to_vec(&hex::encode(block_hash))?),
        );
        overlay.updates.insert(
            block_time_key(height as u64),
            Some(serde_json::to_vec(&time_micros.to_string())?),
        );
        {
            let mut stage = ActionStage::new(&mut overlay);
            let changes = crate::pos_adapter::begin_block(&mut stage, eligible, delta, proposer)?;
            crate::bitcoin_adapter::begin_block(&mut stage)?;
            crate::treasury_adapter::begin_block(&mut stage)?;
            crate::auction::begin_block(&mut stage)?;
            crate::registration_adapter::begin_block(&mut stage)?;
            stage.commit();
            overlay.validators = changes.validators;
            overlay.validator_updates = changes.updates;
        }
        overlay.prune_history()?;
        if !misbehavior.is_empty() {
            // Rule of version 5: the evidence consensus committed in this
            // block is punished as an evidence action at its head would be.
            // Writing the PoS summary clears the cached safety hold, so the
            // transactions are judged with the hold this may have set.
            let mut stage = ActionStage::new(&mut overlay);
            crate::pos_adapter::misbehavior(&mut stage, misbehavior)?;
            stage.commit();
        }
        Ok(overlay)
    }
    /// Makes the block's history entry durable, checking first that the block
    /// was executed on the committed head. It needs no exclusive access: the
    /// archive has its own lock, and an entry ahead of the committed head is
    /// replaced by the next append if that head is not committed after all.
    /// `commit` calls it when the caller has not.
    pub fn persist_history(&self, prepared: &mut Prepared) -> Result<()> {
        let committed = self
            .committed
            .as_ref()
            .ok_or_else(|| anyhow!("uninitialized commit"))?;
        let snapshot = &committed.version;
        let parent = snapshot.height();
        ensure!(
            parent.checked_add(1) == Some(prepared.meta.height as u64)
                && committed.meta.height as u64 == parent,
            "stale prepared commit"
        );
        let append = prepared
            .history_append
            .as_ref()
            .ok_or_else(|| anyhow!("missing prepared history append"))?;
        let current: history::Summary = canonical_decode(
            &snapshot
                .get(history::KEY)
                .ok_or_else(|| anyhow!("missing committed history summary"))?,
        )?;
        ensure!(
            append.previous == current
                && append.summary.size == prepared.meta.height as u64
                && append.summary.network_id == prepared.meta.network_id,
            "prepared history parent mismatch"
        );
        if let Some(archive) = &self.history_archive {
            archive
                .lock()
                .map_err(|_| anyhow!("history archive lock poisoned"))?
                .append_durable(append)?;
        }
        prepared.history_durable = true;
        Ok(())
    }
    pub fn commit(&mut self, mut prepared: Prepared, fingerprint: [u8; 32]) -> Result<Head> {
        prepared
            .tree
            .set_head_metadata(prepared.meta_bytes.clone(), fingerprint)?;
        if !prepared.history_durable {
            self.persist_history(&mut prepared)?;
        }
        let parent = self
            .committed
            .as_ref()
            .ok_or_else(|| anyhow!("uninitialized commit"))?
            .version
            .height();
        ensure!(
            parent.checked_add(1) == Some(prepared.meta.height as u64),
            "stale prepared commit"
        );
        // The store refuses the commit unless its head is still the version
        // this block was executed on.
        let head = self.store.commit(prepared.tree)?;
        let version = self
            .store
            .current()?
            .filter(|version| version.height() == head.version && version.root() == head.root)
            .ok_or_else(|| anyhow!("committed version missing after commit"))?;
        self.accounts
            .advance(Some(parent), head.version, prepared.changed_rows);
        self.committed = Some(Committed::new(prepared.meta, version, &self.versions));
        Ok(head)
    }
    /// Independent streaming recount. It never trusts aggregate counters and
    /// never constructs the full account registry in memory.
    pub fn audit(&self) -> Result<Audit> {
        self.audit_with_progress(|_| {})
    }
    /// Authenticate the entire tree and its raw-key directory before streamed
    /// semantic recounts. Progress is bounded to phase boundaries/10k rows.
    pub fn audit_with_progress(&self, mut progress: impl FnMut(AuditProgress)) -> Result<Audit> {
        let Committed {
            meta,
            version: pinned,
            ..
        } = self.committed()?;
        // A recount judges rows by this program's rules: it says nothing
        // about a state under rules the program does not implement.
        self.ensure_runnable()?;
        ensure!(
            pinned.height() == meta.height as u64
                && pinned.head().metadata == serde_json::to_vec(meta).unwrap_or_default(),
            "audit requires the engine's current authenticated head"
        );
        let snapshot = pinned.audit_verified(&mut progress)?;
        for identity in &meta.genesis.accounts {
            let row: Account = canonical_decode(
                &snapshot
                    .get(&account_key(identity.id))?
                    .ok_or_else(|| anyhow!("missing genesis identity"))?,
            )?;
            ensure!(row.id == identity.id, "genesis account key/ID mismatch");
            validate_account(&row, meta)?;
        }
        for bid in &meta.auction_bids {
            ensure!(
                snapshot.get(&account_key(bid.account_id))?.is_some(),
                "auction bid account missing"
            );
        }
        for commit in &meta.name_commits {
            ensure!(
                snapshot.get(&pubkey_key(&commit.public_key)?)?.is_none(),
                "registered identity has a pending name commitment"
            );
        }
        let mut audit = Audit {
            account_count: 0,
            liquid: 0,
            unbond: 0,
            unbond_entries: 0,
            pool_shares: vec![0; meta.pools.len()],
            last_id: None,
            authenticated_leaves: snapshot.leaf_count(),
            authenticated_tree_nodes: snapshot.tree_nodes(),
            history_archive_verified: false,
            history_archive_from: 0,
        };
        progress(AuditProgress {
            phase: "accounts",
            processed: 0,
            total: Some(meta.account_count),
        });
        snapshot.for_each_prefix(b"account/", |key, value| {
            let row: Account = canonical_decode(value)?;
            ensure!(key == account_key(row.id), "account key/ID mismatch");
            validate_account(&row, meta)?;
            ensure!(
                snapshot.get(&name_key(&row.name))? == Some(index_bytes(row.id)?),
                "name index mismatch"
            );
            ensure!(
                snapshot.get(&pubkey_key(&row.public_key)?)? == Some(index_bytes(row.id)?),
                "identity-key index mismatch"
            );
            for guardian in row
                .recovery_policy
                .as_ref()
                .into_iter()
                .flat_map(|p| &p.guardians)
            {
                ensure!(
                    snapshot.get(&account_key(*guardian))?.is_some(),
                    "missing recovery guardian"
                );
            }
            let cases = read_cases(&snapshot, row.id)?;
            validate_cases(&cases, &row, meta, false)?;
            audit.account_count = audit
                .account_count
                .checked_add(1)
                .ok_or_else(|| anyhow!("count overflow"))?;
            audit.last_id = Some(row.id);
            audit.liquid = audit
                .liquid
                .checked_add(row.balance)
                .ok_or_else(|| anyhow!("liquid recount overflow"))?;
            for unbond in &row.unbonding {
                audit.unbond = audit
                    .unbond
                    .checked_add(unbond.amount)
                    .ok_or_else(|| anyhow!("unbond recount overflow"))?;
                audit.unbond_entries += 1;
                ensure!(
                    snapshot.get(&unbond_key(unbond.id))? == Some(index_bytes(row.id)?),
                    "unbond owner index mismatch"
                );
            }
            for delegation in &row.delegations {
                let i = meta
                    .pools
                    .binary_search_by_key(&delegation.operator, |p| p.operator)
                    .map_err(|_| anyhow!("unknown delegation pool"))?;
                audit.pool_shares[i] = audit.pool_shares[i]
                    .checked_add(delegation.shares)
                    .ok_or_else(|| anyhow!("shares recount overflow"))?;
            }
            if audit.account_count.is_multiple_of(10_000) {
                progress(AuditProgress {
                    phase: "accounts",
                    processed: audit.account_count,
                    total: Some(meta.account_count),
                });
            }
            Ok(())
        })?;
        progress(AuditProgress {
            phase: "accounts",
            processed: audit.account_count,
            total: Some(meta.account_count),
        });
        ensure!(
            audit.account_count == meta.account_count
                && audit.liquid == meta.liquid_total
                && audit.unbond == meta.unbond_total
                && audit.pool_shares == meta.pool_share_totals,
            "independent streamed totals differ from metadata"
        );
        ensure!(
            audit.last_id.map_or(Some(0), |id| id.checked_add(1)) == Some(meta.next_account_id),
            "highest ID mismatch"
        );
        for prefix in [b"name/".as_slice(), b"pubkey/".as_slice()] {
            let phase = if prefix == b"name/" {
                "names"
            } else {
                "public_keys"
            };
            progress(AuditProgress {
                phase,
                processed: 0,
                total: Some(meta.account_count),
            });
            let mut count = 0u64;
            snapshot.for_each_prefix(prefix, |key, value| {
                let id = decode_index(value)?;
                let row: Account = canonical_decode(
                    &snapshot
                        .get(&account_key(id))?
                        .ok_or_else(|| anyhow!("orphan index"))?,
                )?;
                ensure!(
                    key == if prefix == b"name/" {
                        name_key(&row.name)
                    } else {
                        pubkey_key(&row.public_key)?
                    },
                    "index key mismatch"
                );
                count += 1;
                if count.is_multiple_of(10_000) {
                    progress(AuditProgress {
                        phase,
                        processed: count,
                        total: Some(meta.account_count),
                    });
                }
                Ok(())
            })?;
            ensure!(count == meta.account_count, "index cardinality mismatch");
            progress(AuditProgress {
                phase,
                processed: count,
                total: Some(count),
            });
        }
        // Names that look alike (`crate::names`). On a network with distinct
        // names every row names a registered name whose skeleton is the
        // row's key, and there are as many rows as accounts: with the name
        // index recounted above, that is one row for every account and no
        // two accounts with one skeleton. On any other network there is no
        // such row.
        let mut skeleton_rows = 0u64;
        snapshot.for_each_prefix(crate::names::PREFIX, |key, value| {
            ensure!(
                meta.config.distinct_names,
                "name skeleton row on a network without distinct names"
            );
            let name: String = canonical_decode(value)?;
            let skeleton = crate::names::skeleton(&name);
            ensure!(
                !skeleton.is_empty() && key == crate::names::key(&skeleton),
                "name skeleton key mismatch"
            );
            ensure!(
                snapshot.get(&name_key(&name))?.is_some(),
                "name skeleton row of no account"
            );
            skeleton_rows += 1;
            Ok(())
        })?;
        ensure!(
            skeleton_rows
                == if meta.config.distinct_names {
                    meta.account_count
                } else {
                    0
                },
            "name skeleton cardinality mismatch"
        );
        let mut recovery_rows = 0u64;
        progress(AuditProgress {
            phase: "recovery",
            processed: 0,
            total: None,
        });
        snapshot.for_each_prefix(b"recovery/", |key, value| {
            ensure!(key.len() == 17, "invalid recovery row key");
            let id = u64::from_be_bytes(key[9..].try_into()?);
            let row: Account = canonical_decode(
                &snapshot
                    .get(&account_key(id))?
                    .ok_or_else(|| anyhow!("orphan recovery row"))?,
            )?;
            let cases: Vec<RecoveryCase> = canonical_decode(value)?;
            ensure!(!cases.is_empty(), "empty stored recovery row");
            validate_cases(&cases, &row, meta, false)?;
            recovery_rows += 1;
            if recovery_rows.is_multiple_of(10_000) {
                progress(AuditProgress {
                    phase: "recovery",
                    processed: recovery_rows,
                    total: None,
                });
            }
            Ok(())
        })?;
        progress(AuditProgress {
            phase: "recovery",
            processed: recovery_rows,
            total: Some(recovery_rows),
        });
        let mut unbond_indices = 0u64;
        progress(AuditProgress {
            phase: "unbond",
            processed: 0,
            total: Some(audit.unbond_entries),
        });
        snapshot.for_each_prefix(b"unbond/", |key, value| {
            ensure!(key.len() == 15, "invalid unbond index key");
            let entry = u64::from_be_bytes(key[7..].try_into()?);
            let owner = decode_index(value)?;
            let row: Account = canonical_decode(
                &snapshot
                    .get(&account_key(owner))?
                    .ok_or_else(|| anyhow!("orphan unbond owner"))?,
            )?;
            ensure!(
                row.unbonding.binary_search_by_key(&entry, |u| u.id).is_ok(),
                "orphan unbond index"
            );
            unbond_indices += 1;
            if unbond_indices.is_multiple_of(10_000) {
                progress(AuditProgress {
                    phase: "unbond",
                    processed: unbond_indices,
                    total: Some(audit.unbond_entries),
                });
            }
            Ok(())
        })?;
        ensure!(
            unbond_indices == audit.unbond_entries,
            "unbond index cardinality mismatch"
        );
        progress(AuditProgress {
            phase: "unbond",
            processed: unbond_indices,
            total: Some(audit.unbond_entries),
        });
        let history: history::Summary = canonical_decode(
            &snapshot
                .get(history::KEY)?
                .ok_or_else(|| anyhow!("missing history summary"))?,
        )?;
        history.validate()?;
        ensure!(
            history.size == meta.height as u64
                && history.last_time_micros == u64::try_from(meta.time_micros)?
                && history.network_id == meta.network_id,
            "history summary differs from ledger"
        );
        if let Some(archive) = &self.history_archive {
            let mut archive = archive
                .lock()
                .map_err(|_| anyhow!("history archive lock poisoned"))?;
            // A node restored from a snapshot holds the archive from the
            // block after it: that part is recounted, starting from the
            // recorded summary of the restored height, and must end at the
            // authenticated summary. What refers to earlier heights (the
            // cleanup clock, release clocks) cannot be compared with leaves
            // this node never had.
            //
            // The record of a restore is a file beside the archive and no
            // more trusted than the archive. It is honoured only if the
            // archive holds no entry at all at or below its height, as after
            // a restore. Beside an archive that does hold such entries it
            // is ignored and the whole archive is recounted from the first
            // block: a record cannot make a damaged archive pass.
            let restored = match &self.history_base {
                Some(restored) if holds_no_leaf(&mut *archive, 1..=restored.size)? => Some(restored),
                _ => None,
            };
            let base = restored.map_or(0, |restored| restored.size);
            match restored {
                None => archive
                    .audit(&history, u64::try_from(meta.genesis.genesis_time_micros)?)?,
                Some(restored) => audit_archive_after(&mut *archive, restored, &history)?,
            }
            audit.history_archive_from = base + 1;
            if meta.history_pruned_through > base {
                ensure!(
                    archive
                        .prove(&history, meta.history_pruned_through)?
                        .leaf
                        .time_micros
                        == u64::try_from(meta.history_pruned_time)?,
                    "history cleanup clock differs from archive"
                );
            }
            snapshot.for_each_prefix(b"pos/release_time/", |key, raw| {
                ensure!(key.len() == 25, "retained release clock key length");
                let height = u64::from_be_bytes(key[17..].try_into()?);
                let text: String = canonical_decode(raw)?;
                let absolute: u64 = text.parse()?;
                if height <= base {
                    return Ok(());
                }
                ensure!(
                    archive.prove(&history, height)?.leaf.time_micros == absolute,
                    "retained release clock differs from authenticated archive"
                );
                Ok(())
            })?;
            audit.history_archive_verified = true;
        }
        let pos_leaves = crate::pos_adapter::audit(&snapshot, meta)?;
        let auction_leaves = crate::auction::audit(&snapshot, meta)?;
        let bitcoin_leaves = crate::bitcoin_adapter::audit(&snapshot, meta)?;
        let treasury_leaves = crate::treasury_adapter::audit(&snapshot, meta)?;
        let registration_leaves = crate::registration_adapter::audit(&snapshot, meta)?;
        let security_leaves = crate::security::audit(&snapshot, meta)?;
        let upgrade_leaves = upgrade::audit(&snapshot, meta)?;
        let service_leaves = crate::service::audit(&snapshot, meta)?;
        let market_leaves = crate::market::audit(&snapshot, meta)?;
        let mut blocks = 0u64;
        let mut previous_time = meta.history_pruned_time;
        snapshot.for_each_prefix(b"block/", |key, raw| {
            ensure!(key.len() == 14, "block key length");
            let height = u64::from_be_bytes(key[6..].try_into()?);
            ensure!(
                height == meta.history_pruned_through + blocks + 1,
                "block history gap"
            );
            let hash: String = canonical_decode(raw)?;
            ensure!(hex32(&hash)? != [0; 32], "zero accepted block hash");
            blocks += 1;
            Ok(())
        })?;
        let mut times = 0u64;
        let stop_threshold = crate::security::stop_threshold(meta.config.profile);
        let mut recent_stops = 0u64;
        snapshot.for_each_prefix(b"block_time/", |key, raw| {
            ensure!(key.len() == 19, "block time key length");
            let height = u64::from_be_bytes(key[11..].try_into()?);
            ensure!(
                height == meta.history_pruned_through + times + 1,
                "block clock history gap"
            );
            let text: String = canonical_decode(raw)?;
            let absolute: i64 = text.parse()?;
            ensure!(
                absolute.to_string() == text
                    && (absolute > previous_time || (height == 1 && absolute == previous_time)),
                "noncanonical or nonadvancing accepted clock"
            );
            // What this block was dated after its parent beyond the five
            // minutes of the clock of the waits: a stop, on a network that
            // counts them.
            let gap = absolute
                .checked_sub(previous_time)
                .and_then(|gap| u64::try_from(gap).ok())
                .ok_or_else(|| anyhow!("accepted clock gap"))?;
            recent_stops = recent_stops
                .checked_add(gap.saturating_sub(stop_threshold))
                .ok_or_else(|| anyhow!("stops recount overflow"))?;
            previous_time = absolute;
            times += 1;
            Ok(())
        })?;
        // The total of stops (`Meta::stopped_micros`), counted again from
        // the block times the state holds. While no block time has been
        // cleaned up, that is every block since genesis and the two totals
        // are equal. Afterwards the state holds the times of the last
        // fourteen days only: the stops among them are part of the total.
        if let Some(stopped) = meta.stopped_micros {
            ensure!(
                if meta.history_pruned_through == 0 {
                    stopped == recent_stops
                } else {
                    stopped >= recent_stops
                },
                "the total of stops differs from the block times"
            );
        }
        ensure!(
            blocks == meta.height as u64 - meta.history_pruned_through
                && times == blocks
                && (times == 0 || previous_time == meta.time_micros),
            "incomplete block history"
        );
        let expected_leaves = meta
            .account_count
            .checked_mul(3)
            .and_then(|v| v.checked_add(2))
            .and_then(|v| v.checked_add(skeleton_rows))
            .and_then(|v| v.checked_add(recovery_rows))
            .and_then(|v| v.checked_add(unbond_indices))
            .and_then(|v| v.checked_add(pos_leaves))
            .and_then(|v| v.checked_add(auction_leaves))
            .and_then(|v| v.checked_add(bitcoin_leaves))
            .and_then(|v| v.checked_add(treasury_leaves))
            .and_then(|v| v.checked_add(registration_leaves))
            .and_then(|v| v.checked_add(security_leaves))
            .and_then(|v| v.checked_add(upgrade_leaves))
            .and_then(|v| v.checked_add(service_leaves))
            .and_then(|v| v.checked_add(market_leaves))
            .and_then(|v| v.checked_add(blocks.checked_mul(2)?))
            .ok_or_else(|| anyhow!("audited namespace count overflow"))?;
        ensure!(
            snapshot.leaf_count() == expected_leaves,
            "authenticated tree has unknown namespace rows"
        );
        meta.validate()?;
        Ok(audit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audit {
    pub account_count: u64,
    pub liquid: u64,
    pub unbond: u64,
    pub unbond_entries: u64,
    pub pool_shares: Vec<u64>,
    pub last_id: Option<u64>,
    pub authenticated_leaves: u64,
    pub authenticated_tree_nodes: u64,
    /// The block history archive this node holds passed its recount, from
    /// `history_archive_from` on. Only together with `history_archive_from`
    /// equal to 1 does it mean the whole history since genesis: the report of
    /// `time-node-v5 --audit` says `history_archive_verified: true` in that
    /// case alone.
    pub history_archive_verified: bool,
    /// First height whose history entry was recounted from the archive: 1
    /// on a node that executed every block, the height after the restored
    /// one on a node restored from a snapshot, 0 if no archive was checked.
    pub history_archive_from: u64,
}

/// The protocol version a metadata row names, read without decoding the row.
pub(crate) fn peek_version(meta: &[u8]) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_slice(meta).ok()?;
    let text = value.get("protocol_version")?.as_str()?;
    let version: u64 = text.parse().ok()?;
    (version.to_string() == text).then_some(version)
}

const HISTORY_BASE_PREFIX: &str = "restored-";
const HISTORY_BASE_SUFFIX: &str = ".json";

fn history_base_path(directory: &Path, height: u64) -> PathBuf {
    directory.join(format!("{HISTORY_BASE_PREFIX}{height:020}{HISTORY_BASE_SUFFIX}"))
}

/// Heights recorded by `write_history_base` in `directory`.
fn history_base_heights(directory: &Path) -> Vec<u64> {
    let mut heights: Vec<u64> = std::fs::read_dir(directory)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let digits = name
                .to_str()?
                .strip_prefix(HISTORY_BASE_PREFIX)?
                .strip_suffix(HISTORY_BASE_SUFFIX)?
                .to_owned();
            (digits.len() == 20 && digits.bytes().all(|c| c.is_ascii_digit()))
                .then(|| digits.parse().ok())
                .flatten()
        })
        .collect();
    heights.sort_unstable();
    heights
}

/// Records, beside the archive, the history summary of the height a state
/// was restored at. Written before the restored state is installed.
fn write_history_base(directory: &Path, summary: &history::Summary) -> Result<()> {
    use std::io::Write;
    let path = history_base_path(directory, summary.size);
    let partial = path.with_extension("tmp");
    let mut file = std::fs::File::create(&partial)?;
    file.write_all(&serde_json::to_vec(summary)?)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&partial, &path)?;
    Ok(())
}

fn remove_other_history_bases(directory: &Path, keep: u64) {
    for height in history_base_heights(directory) {
        if height != keep {
            let _ = std::fs::remove_file(history_base_path(directory, height));
        }
    }
}

/// Whether the archive holds no entry for any of `heights`: every leaf
/// record there is zero bytes, as `Archive::seed` leaves them. (An entry of a
/// real block is never zero: its block hash is not.)
fn holds_no_leaf(
    archive: &mut history::archive::Archive,
    heights: impl IntoIterator<Item = u64>,
) -> Result<bool> {
    use history::Reader;
    let absent = "0".repeat(64);
    for height in heights {
        let leaf = archive.leaf(height)?;
        if leaf.block_hash != absent || leaf.time_micros != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The restore record that applies to a state whose authenticated history
/// summary is `current`: the newest one at or below its height, of its
/// network, that validates. A record above the state's height is from a
/// restore that never finished and is ignored.
///
/// Like the archive, the record is not trusted. It is passed over here if
/// the archive holds the first or the last entry it says is absent (a record
/// that strayed beside a full archive, or one a restore left that stopped
/// before the node went on from an older height), and the recount ignores
/// the one chosen unless
/// every entry at or below its height is absent, and then fails if it is
/// not the summary the chain had at that height (`audit_archive_after`).
fn read_history_base(
    directory: &Path,
    current: &history::Summary,
    archive: &mut history::archive::Archive,
) -> Option<history::Summary> {
    history_base_heights(directory)
        .into_iter()
        .rev()
        .filter(|height| *height <= current.size)
        .find_map(|height| {
            let bytes = std::fs::read(history_base_path(directory, height)).ok()?;
            let summary: history::Summary = serde_json::from_slice(&bytes).ok()?;
            // A record that does not apply is passed over, and the one
            // before it is tried: the record of a restore that stopped (or
            // one that strayed here) must not hide the record of the
            // restore that happened.
            (summary.size == height
                && summary.size > 0
                && summary.network_id == current.network_id
                && summary.validate().is_ok()
                && holds_no_leaf(archive, [1, summary.size]).unwrap_or(false))
            .then_some(summary)
        })
}

/// Recounts the archive of a node restored at `base`: every entry after it
/// must extend `base` to exactly the authenticated `summary`, with the
/// nodes the archive stores.
fn audit_archive_after(
    archive: &mut history::archive::Archive,
    base: &history::Summary,
    summary: &history::Summary,
) -> Result<()> {
    use history::Reader;
    archive.verify_committed_prefix(summary)?;
    ensure!(
        base.size <= summary.size && base.network_id == summary.network_id,
        "restore record does not belong to this history"
    );
    let mut current = base.clone();
    for height in base.size + 1..=summary.size {
        let append = current.append(archive.leaf(height)?)?;
        let start = history::node_count(current.size)?;
        for (index, hash) in append.nodes.iter().enumerate() {
            ensure!(
                archive.node(start + index as u64)? == *hash,
                "archive internal node mismatch"
            );
        }
        current = append.summary;
    }
    ensure!(current == *summary, "archive recount mismatch");
    Ok(())
}

pub fn block_key(height: u64) -> Vec<u8> {
    [b"block/".as_slice(), &height.to_be_bytes()].concat()
}
pub fn block_time_key(height: u64) -> Vec<u8> {
    [b"block_time/".as_slice(), &height.to_be_bytes()].concat()
}

/// Only authenticated, staged extension access. Engine owns device authority,
/// nonce and fees; returned movement and rows publish in the same tree batch.
pub trait ExtensionHost {
    fn meta(&self) -> &Meta;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn put(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()>;
    fn account(&mut self, id: u64) -> Result<Account>;
    /// Replaces a row this action has loaded with `account`.
    fn set_account(&mut self, row: Account) -> Result<()>;
    fn credit(&mut self, id: u64, amount: u64) -> Result<()>;
    fn debit(&mut self, id: u64, amount: u64) -> Result<()>;
    fn bank_credit(&mut self, amount: u64) -> Result<()>;
    fn bank_debit(&mut self, amount: u64) -> Result<()>;
    /// Moves an action's fee, already taken from the payer, into the bank.
    /// On a network that pays a part of the fees on to validators the engine
    /// also counts it for that payment. Every fee goes through here;
    /// `bank_credit` is for everything else the bank receives.
    fn fee_credit(&mut self, amount: u64) -> Result<()>;
    fn set_auction_reserve(&mut self, total: u64) -> Result<()>;
    fn set_pos_assets(&mut self, total: u64) -> Result<()>;
    /// Sets `Meta::market_micros`, on a network with the market.
    fn set_market(&mut self, total: u64) -> Result<()>;
    /// How far past the current time an expiry must lie: nothing when a block
    /// is executed, `ADMISSION_MARGIN_MICROS` when the mempool decides
    /// admission.
    fn expiry_margin(&self) -> u64 {
        0
    }
}
struct ActionStage<'a> {
    parent: &'a mut Overlay,
    meta: Meta,
    updates: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    accounts: BTreeMap<u64, Account>,
    /// Set by the engine around the account security rules. No other rule
    /// module may write a security row.
    security_rows: bool,
    /// The fees this action has paid, if the network pays a part of them on.
    fees: u64,
    /// The signal entry a kind-80 action sets, applied to the parent's
    /// upgrade row when the action is committed.
    signal: Option<upgrade::Entry>,
}
impl<'a> ActionStage<'a> {
    fn new(parent: &'a mut Overlay) -> Self {
        Self {
            meta: parent.meta.clone(),
            parent,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            security_rows: false,
            fees: 0,
            signal: None,
        }
    }
    fn commit(self) {
        // `fee_credit` has checked that the sum fits.
        self.parent.fees += self.fees;
        self.parent.meta = self.meta;
        if let Some(entry) = self.signal {
            // `Overlay::apply` loaded the row before it judged the signal.
            self.parent.upgrade.get_or_insert_with(Default::default).set(entry);
        }
        if self.updates.contains_key(crate::pos_adapter::SUMMARY_KEY) {
            self.parent.safety_hold = None;
        }
        self.parent.updates.extend(self.updates);
        for id in self.accounts.keys() {
            // The row may have grown; the transfer path must measure it again.
            self.parent.loaded_len.remove(id);
        }
        self.parent.accounts.extend(self.accounts);
    }
    /// Judges a kind-80 action against the upgrade row as this block has
    /// changed it so far (`upgrade::signal`): the entry that replaces the
    /// sender's. The engine has checked nonce, authority epoch, key and
    /// freeze before, and charges the fee after.
    fn signal_entry(&self, action: &crate::wire::SignedAction) -> Result<upgrade::Entry> {
        // The sender owns a validator candidate that is not archived. It
        // need not be in the roster.
        let candidate = match self.get(&crate::pos_adapter::candidate_key(action.from))? {
            Some(row) => !canonical_decode::<pos::Candidate>(&row)?.archived,
            None => false,
        };
        let state = self
            .parent
            .upgrade
            .as_ref()
            .ok_or_else(|| anyhow!("upgrade row not loaded"))?;
        let context = upgrade::Context {
            now: self.meta.elapsed_micros()?,
            version: self.parent.rules.version(),
            params: upgrade::Params::of(self.meta.config.profile),
            local: self.parent.local.as_deref(),
            margin: self.expiry_margin(),
        };
        let payload = action
            .raw_signing_bytes
            .get(crate::wire::HEADER..)
            .ok_or_else(|| anyhow!("action too short"))?;
        upgrade::signal(state, &context, action.from, payload, candidate)
    }
}
impl ExtensionHost for ActionStage<'_> {
    fn meta(&self) -> &Meta {
        &self.meta
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.updates.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.parent.get(key),
        }
    }
    fn put(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        ensure!(
            [
                b"pos/".as_slice(),
                b"bitcoin/",
                b"auction/",
                b"treasury/",
                b"registration/",
                b"security/",
                crate::service::PREFIX,
                crate::market::PREFIX,
            ]
            .iter()
            .any(|prefix| key.starts_with(prefix)),
            "extension attempted reserved namespace"
        );
        ensure!(
            self.security_rows || !key.starts_with(b"security/"),
            "only the account security rules write security rows"
        );
        // A network without the service records never gets one of their
        // rows, whatever a rule module asks.
        ensure!(
            self.meta.config.service_records || !key.starts_with(crate::service::PREFIX),
            "service records belong to a network with service_records"
        );
        ensure!(
            self.meta.config.market || !key.starts_with(crate::market::PREFIX),
            "market rows belong to a network with the market"
        );
        ensure!(
            value.as_ref().is_none_or(|v| v.len() <= 1024 * 1024),
            "extension row byte limit"
        );
        self.updates.insert(key, value);
        Ok(())
    }
    fn account(&mut self, id: u64) -> Result<Account> {
        if let Some(row) = self.accounts.get(&id) {
            return Ok(row.clone());
        }
        let row = self.parent.required(id)?;
        self.accounts.insert(id, row.clone());
        Ok(row)
    }
    fn set_account(&mut self, row: Account) -> Result<()> {
        let staged = self
            .accounts
            .get(&row.id)
            .ok_or_else(|| anyhow!("account row was not loaded by this action"))?;
        // Balances move through credit and debit. This writes what the
        // security rules manage, and nothing else.
        let mut allowed = staged.clone();
        allowed.devices = row.devices.clone();
        allowed.nonce = row.nonce;
        allowed.auth_epoch = row.auth_epoch;
        ensure!(
            allowed == row,
            "only keys, nonce and authority epoch of an account row may be replaced"
        );
        self.accounts.insert(row.id, row);
        Ok(())
    }
    fn credit(&mut self, id: u64, amount: u64) -> Result<()> {
        let mut row = self.account(id)?;
        row.balance = pos::add(row.balance, amount)?;
        self.accounts.insert(id, row);
        Ok(())
    }
    fn debit(&mut self, id: u64, amount: u64) -> Result<()> {
        let mut row = self.account(id)?;
        row.balance = row
            .balance
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("insufficient liquid funds"))?;
        self.accounts.insert(id, row);
        Ok(())
    }
    fn bank_credit(&mut self, amount: u64) -> Result<()> {
        self.meta.bank = pos::add(self.meta.bank, amount)?;
        Ok(())
    }
    fn bank_debit(&mut self, amount: u64) -> Result<()> {
        self.meta.bank = self
            .meta
            .bank
            .checked_sub(amount)
            .ok_or_else(|| anyhow!("insufficient bank"))?;
        Ok(())
    }
    fn fee_credit(&mut self, amount: u64) -> Result<()> {
        self.bank_credit(amount)?;
        if self.meta.config.fees_to_validators_ppm > 0 {
            self.fees = pos::add(self.fees, amount)?;
            ensure!(
                self.parent.fees.checked_add(self.fees).is_some(),
                "fee total overflow"
            );
        }
        Ok(())
    }
    fn set_auction_reserve(&mut self, total: u64) -> Result<()> {
        self.meta.auction_reserve_total = total;
        Ok(())
    }
    fn set_pos_assets(&mut self, total: u64) -> Result<()> {
        self.meta.pos_assets_total = total;
        Ok(())
    }
    fn set_market(&mut self, total: u64) -> Result<()> {
        ensure!(self.meta.market_micros.is_some(), "this network has no market");
        self.meta.market_micros = Some(total);
        Ok(())
    }
    fn expiry_margin(&self) -> u64 {
        if self.parent.admission {
            ADMISSION_MARGIN_MICROS
        } else {
            0
        }
    }
}

struct Overlay {
    /// Committed version this block builds on. `None` only while genesis is
    /// being written.
    base: Option<Arc<Version>>,
    /// Decoded rows of `base`, if a cache may be used.
    cache: Option<Arc<AccountCache>>,
    meta: Meta,
    updates: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    accounts: BTreeMap<u64, Account>,
    original: BTreeMap<u64, Account>,
    recoveries: BTreeMap<u64, Vec<RecoveryCase>>,
    validators: Vec<pos::Validator>,
    validator_updates: Vec<pos::Validator>,
    history_append: Option<history::Append>,
    /// The validator safety-hold flag of the current PoS summary row. Cleared
    /// whenever that row is rewritten.
    safety_hold: Option<bool>,
    /// Encoded size of each account row when it was loaded, while only the
    /// transfer path has changed it since.
    loaded_len: BTreeMap<u64, usize>,
    /// Route transfers through the unmodified protocol-4 adapter.
    generic_transfers: bool,
    /// Record in `loaded` which account rows the current transaction reads
    /// for the first time. Used by mempool admission, which forgets the rows
    /// a refused transaction made it read.
    journal: bool,
    loaded: Vec<u64>,
    /// This overlay decides mempool admission, not the content of a block:
    /// what carries an expiry must then outlive `ADMISSION_MARGIN_MICROS`.
    admission: bool,
    /// The action fees charged in this block so far. They are in the bank;
    /// `finish` records the validators' part of them as owed to the signers
    /// of this block. Counted only on a network that pays a part of them on.
    fees: u64,
    /// The rules in force for this block: those of the committed head. Set
    /// once; the activating block writes the new version after its last
    /// transaction, so nothing in it sees the new number.
    rules: Rules,
    /// The time of the block this one builds on: a scheduled plan is
    /// cancelled in a block dated more than an hour after its parent.
    parent_time_micros: i64,
    /// The row `upgrade/state` as this block has changed it so far. `None`
    /// until a signal makes the block read it: decoded at most once per
    /// block, written at most once, at its end (`upgrade_step`).
    upgrade: Option<upgrade::State>,
    /// This node's own list of versions, set where its local policy applies:
    /// at mempool admission and when a proposer selects transactions. Never
    /// set when a block is validated or executed (`upgrade::Context::local`).
    local: Option<Arc<Versions>>,
    /// Set while the switch block of a fix release is executed
    /// (`Engine::overlay`, `upgrade::switch_block`), and by nothing else: no
    /// admission overlay has it, and no block of a program that is not a fix
    /// release. At an agreed height the block is one transaction, the switch
    /// (`apply`); a repaired block carries the transactions it was decided
    /// with. Either ends by writing the version (`upgrade_step`). A fix
    /// gates what it corrects with `self.rules.since(N + 1)`, and for a
    /// block it repairs also with `self.switch.is_some()`: the header of
    /// that block still carries the version before.
    switch: Option<upgrade::SwitchBlock>,
}

/// A transfer changes only the decimal digits of one balance and one nonce,
/// each at most 20 digits long.
const TRANSFER_ROW_GROWTH: usize = 40;
impl Overlay {
    /// A fresh admission overlay on the same committed version, with the
    /// metadata of that version.
    fn on_head(&self, meta: Meta) -> Overlay {
        Overlay {
            base: self.base.clone(),
            cache: self.cache.clone(),
            meta,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            original: BTreeMap::new(),
            recoveries: BTreeMap::new(),
            validators: Vec::new(),
            validator_updates: Vec::new(),
            history_append: None,
            safety_hold: None,
            loaded_len: BTreeMap::new(),
            generic_transfers: self.generic_transfers,
            journal: false,
            loaded: Vec::new(),
            admission: true,
            fees: 0,
            rules: self.rules,
            parent_time_micros: self.parent_time_micros,
            upgrade: None,
            local: self.local.clone(),
            // Admission never executes a switch block.
            switch: None,
        }
    }
    fn prune_history(&mut self) -> Result<()> {
        for _ in 0..64 {
            let height = self
                .meta
                .history_pruned_through
                .checked_add(1)
                .ok_or_else(|| anyhow!("cleanup height exhausted"))?;
            if height >= self.meta.height as u64 {
                break;
            }
            let text: String = canonical_decode(
                &self
                    .get(&block_time_key(height))?
                    .ok_or_else(|| anyhow!("history cleanup clock missing"))?,
            )?;
            let time: i64 = text.parse()?;
            ensure!(time.to_string() == text, "noncanonical cleanup clock");
            if !self
                .meta
                .time_micros
                .checked_sub(time)
                .is_some_and(|age| age > pos::UNBOND_DELAY as i64)
            {
                break;
            }
            let pointer: String = canonical_decode(
                &self
                    .get(&crate::pos_adapter::roster_at_key(height))?
                    .ok_or_else(|| anyhow!("cleanup roster pointer missing"))?,
            )?;
            let next: String = canonical_decode(
                &self
                    .get(&crate::pos_adapter::roster_at_key(height + 1))?
                    .ok_or_else(|| anyhow!("cleanup next roster pointer missing"))?,
            )?;
            if pointer != next {
                let set: u64 = pointer.parse()?;
                ensure!(
                    set.to_string() == pointer && set <= height,
                    "cleanup roster pointer invalid"
                );
                if set != 0 {
                    self.updates
                        .insert(crate::pos_adapter::roster_key(set), None);
                }
            }
            for key in [
                block_key(height),
                block_time_key(height),
                crate::pos_adapter::roster_at_key(height),
                crate::pos_adapter::updates_key(height),
            ] {
                self.updates.insert(key, None);
            }
            self.meta.history_pruned_through = height;
            self.meta.history_pruned_time = time;
        }
        Ok(())
    }
    /// The committed row under `key`, ignoring this block's changes.
    fn base_get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.base
            .as_ref()
            .and_then(|base| base.get(key))
            .map(|row| row.to_vec())
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.updates.get(key) {
            Some(value) => Ok(value.clone()),
            None => Ok(self.base_get(key)),
        }
    }
    fn required(&mut self, id: u64) -> Result<Account> {
        if let Some(row) = self.accounts.get(&id) {
            return Ok(row.clone());
        }
        let key = account_key(id);
        // The cache holds committed rows of `base`. It applies when this block
        // has not written the row; an account this block already touched is in
        // `self.accounts` and never reaches this point.
        let cache = match (&self.cache, &self.base) {
            (Some(cache), Some(base)) if !self.updates.contains_key(&key) => {
                Some((cache.clone(), base.height()))
            }
            _ => None,
        };
        if let Some((cache, height)) = &cache
            && let Some(entry) = cache.get(*height, id)
        {
            // Decoded, validated and index-checked when it entered the cache.
            self.loaded_len.insert(id, entry.encoded_len);
            self.original.insert(id, entry.row.clone());
            self.accounts.insert(id, entry.row.clone());
            if self.journal {
                self.loaded.push(id);
            }
            return Ok(entry.row.clone());
        }
        let bytes = self
            .get(&key)?
            .ok_or_else(|| anyhow!("account does not exist"))?;
        ensure!(bytes.len() <= MAX_ACCOUNT_BYTES, "account byte limit");
        let row: Account = canonical_decode(&bytes)?;
        ensure!(row.id == id, "account ID mismatch");
        validate_account(&row, &self.meta)?;
        ensure!(
            self.get(&name_key(&row.name))? == Some(index_bytes(id)?)
                && self.get(&pubkey_key(&row.public_key)?)? == Some(index_bytes(id)?),
            "account identity index mismatch"
        );
        self.loaded_len.insert(id, bytes.len());
        if let Some((cache, height)) = cache {
            cache.insert_loaded(
                height,
                id,
                Arc::new(CachedAccount {
                    row: row.clone(),
                    encoded_len: bytes.len(),
                }),
            );
        }
        self.original.insert(id, row.clone());
        self.accounts.insert(id, row.clone());
        if self.journal {
            self.loaded.push(id);
        }
        Ok(row)
    }
    /// Reads `upgrade/state` for this block, once.
    fn load_upgrade(&mut self) -> Result<()> {
        if self.upgrade.is_none() {
            self.upgrade = Some(match self.get(upgrade::STATE_KEY)? {
                Some(row) => upgrade::State::decode(&row)?,
                None => upgrade::State::default(),
            });
        }
        Ok(())
    }
    /// Whether the signal of validator owner `owner` counts at this block's
    /// time: its candidate is not jailed, and the owner account is neither
    /// frozen nor in a recovery (for a secured account a freeze still running
    /// or a replacement of the keys waiting; for a protocol-4 account a
    /// guardian recovery that is ready). Read on the state after this
    /// block's transactions.
    fn signal_counts(&mut self, owner: u64) -> Result<bool> {
        let Some(row) = self.get(&crate::pos_adapter::candidate_key(owner))? else {
            return Ok(false);
        };
        let candidate: pos::Candidate = canonical_decode(&row)?;
        if candidate.jailed || candidate.archived {
            return Ok(false);
        }
        let account = self.required(owner)?;
        if self
            .cases(owner)?
            .iter()
            .any(|case| case.ready_elapsed_micros.is_some())
        {
            return Ok(false);
        }
        // A freeze is counted on the clock of the waits (`Meta::active_micros`).
        let now = self.meta.active_micros()?;
        Ok(!crate::security::frozen_at(|key| self.get(key), &account, now)?)
    }
    /// The end of the block for the plan (`upgrade::end_block`). Without the
    /// row, and without a signal in this block, it costs one lookup. With
    /// `upgrade_write`, which it ends by, this is the one place that writes
    /// `Meta::protocol_version` after genesis.
    fn upgrade_step(&mut self) -> Result<Vec<upgrade::Event>> {
        let stored = self.get(upgrade::STATE_KEY)?;
        // The switch block of a fix release ends by the switch and by
        // nothing else: the version is written, and any plan and all entries
        // go, also those a signal of this very block set. A plan never
        // activates in a switch block (`upgrade::switch_outcome`).
        if let Some(switch) = self.switch.take() {
            self.upgrade = None;
            let state = match &stored {
                Some(row) => Some(upgrade::State::decode(row)?),
                None => None,
            };
            let outcome = upgrade::switch_outcome(
                state,
                &switch,
                u64::try_from(self.meta.height)?,
                self.meta.elapsed_micros()?,
            )?;
            return self.upgrade_write(outcome, stored);
        }
        let state = match (self.upgrade.take(), &stored) {
            (Some(state), _) => state,
            (None, Some(row)) => upgrade::State::decode(row)?,
            (None, None) => return Ok(Vec::new()),
        };
        if state.is_empty() && stored.is_none() {
            // A block that read the row for a signal it then refused.
            return Ok(Vec::new());
        }
        let summary: pos::Summary = canonical_decode(
            &self
                .get(crate::pos_adapter::SUMMARY_KEY)?
                .ok_or_else(|| anyhow!("missing PoS summary"))?,
        )?;
        let mut candidates = BTreeSet::new();
        for id in &summary.candidate_ids {
            candidates.insert(id.parse::<u64>()?);
        }
        let mut rosters: Vec<&[pos::Validator]> = vec![&summary.active];
        rosters.extend(summary.scheduled.iter().map(|set| set.validators.as_slice()));
        // The validators of these rosters that are jailed: left out of the
        // count, total and support alike (`upgrade::Block::jailed`). Read
        // from the candidate rows after this block's transactions.
        let mut jailed = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for validator in rosters.iter().flat_map(|roster| roster.iter()) {
            if !seen.insert(validator.owner) {
                continue;
            }
            let row = self
                .get(&crate::pos_adapter::candidate_key(validator.owner))?
                .ok_or_else(|| anyhow!("roster references an absent candidate"))?;
            if canonical_decode::<pos::Candidate>(&row)?.jailed {
                jailed.insert(validator.owner);
            }
        }
        let block = upgrade::Block {
            now: self.meta.elapsed_micros()?,
            gap: u64::try_from(
                self.meta
                    .time_micros
                    .checked_sub(self.parent_time_micros)
                    .ok_or_else(|| anyhow!("time overflow"))?,
            )?,
            height: u64::try_from(self.meta.height)?,
            version: self.rules.version(),
            hold: summary.safety_hold,
            params: upgrade::Params::of(summary.profile),
            rosters,
            candidates,
            jailed,
        };
        let outcome = upgrade::end_block(state, &block, &mut |owner| self.signal_counts(owner))?;
        self.upgrade_write(outcome, stored)
    }
    /// Writes what the end of the block decided for the version and the
    /// row: by a plan (`upgrade::end_block`) or by the switch of a fix
    /// release (`upgrade::switch_outcome`). `stored` is the row as the block
    /// found it.
    fn upgrade_write(&mut self, outcome: upgrade::Outcome, stored: Option<Vec<u8>>) -> Result<Vec<upgrade::Event>> {
        if let Some((version, row)) = &outcome.activated {
            self.meta.protocol_version = *version;
            self.updates
                .insert(upgrade::activated_key(*version), Some(serde_json::to_vec(row)?));
        }
        let row = match &outcome.state {
            Some(state) => Some(state.encode()?),
            None => None,
        };
        if row != stored {
            self.updates.insert(upgrade::STATE_KEY.to_vec(), row);
        }
        Ok(outcome.events)
    }
    fn cases(&mut self, id: u64) -> Result<Vec<RecoveryCase>> {
        if let Some(cases) = self.recoveries.get(&id) {
            return Ok(cases.clone());
        }
        let row = self.required(id)?;
        let mut cases = match self.get(&recovery_key(id))? {
            Some(bytes) => canonical_decode::<Vec<RecoveryCase>>(&bytes)?,
            None => Vec::new(),
        };
        validate_cases(&cases, &row, &self.meta, false)?;
        let now = self.meta.elapsed_micros()?;
        cases.retain(|c| {
            c.expires_elapsed_micros >= now
                && c.auth_epoch == row.auth_epoch
                && c.policy_version == row.recovery_version
        });
        Ok(cases)
    }
    /// Applies one transaction. `signature` is what is already known about
    /// the stateless signature check of exactly these bytes; with `Unknown`
    /// the check is done here. Nothing is published unless every rule passes.
    fn apply(&mut self, raw: &[u8], signature: SigStatus) -> Result<()> {
        let kind = *raw
            .get(crate::wire::DOMAIN.len() + 32)
            .ok_or_else(|| anyhow!("action too short"))?;
        if kind == 1 {
            anyhow::bail!(
                "free registration commitments are forbidden onv4; use sponsored action44"
            );
        }
        if matches!(kind, 4) {
            anyhow::bail!("synthetic unpaid auction bids are forbidden onv4");
        }
        // The block after the agreed height of a fix release carries exactly
        // one transaction: the switch of this program, byte for byte. It
        // charges nobody and changes no row; the block ends by writing the
        // version (`upgrade_step`). A second transaction, or any other one,
        // makes the block invalid.
        if let Some(switch) = &mut self.switch
            && let Some(action) = &switch.action
        {
            ensure!(
                !switch.applied && raw == action.as_slice(),
                "the block after the agreed height carries exactly one transaction, the rule switch of this fix release"
            );
            switch.applied = true;
            return Ok(());
        }
        // The rule switch of an emergency release is accepted nowhere else:
        // refused at admission, never taken from a mempool, and a proposal
        // that carries it outside the program's own switch block is rejected.
        // (A decided block that carries it there never reaches this point:
        // the node stops before it executes anything of it.) A program that
        // is not a fix release has no switch block.
        if kind == upgrade::SWITCH {
            anyhow::bail!("action kind 81 is reserved for a rule switch and is not accepted by this release");
        }
        // A network that pays all new time to validators has no bitcoin
        // auction, and nothing that serves one is accepted.
        ensure!(
            self.meta.config.bitcoin_kind_allowed(kind),
            "this network has no bitcoin auction: new time goes to validators and the people who stake with them"
        );
        let safety_hold = match self.safety_hold {
            Some(flag) => flag,
            None => {
                let critical: pos::Summary = canonical_decode(
                    &self
                        .get(crate::pos_adapter::SUMMARY_KEY)?
                        .ok_or_else(|| anyhow!("missing PoS summary"))?,
                )?;
                self.safety_hold = Some(critical.safety_hold);
                critical.safety_hold
            }
        };
        // An account's protective actions pass as well: their waiting periods
        // keep running through a hold, so the owner must be able to act.
        ensure!(
            !safety_hold
                || matches!(kind, 17 | 18 | 20 | 40 | upgrade::SIGNAL)
                || crate::security::protective(kind)
                // A fill ends when its time to prove a payment has passed,
                // and that time runs through a hold (`spec/market.md`, 5.5).
                || (kind == crate::market::PROOF && self.meta.config.market),
            "critical validator hold permits only headers, equivocation evidence, existing-account self collateral repair, upgrade signals, or an account's protective actions"
        );
        // A registration that creates its account with a set of keys: an
        // action without an account, like the reveal it stands for.
        if kind == crate::security::REGISTER {
            return self.apply_protected_registration(raw, signature);
        }
        if crate::security::is_kind(kind) {
            let action = crate::wire::decode(raw)?;
            ensure!(action.network_id == self.meta.network_id, "wrong network");
            match signature {
                SigStatus::Valid => {}
                SigStatus::Invalid => anyhow::bail!("invalid action signature"),
                SigStatus::Unknown => {
                    valid_public_key(&action.public_key)?;
                    action.verify_signer()?;
                }
            }
            ensure!(action.from != u64::MAX, "account does not exist");
            let owner = self.required(action.from)?;
            if crate::security::sequenced(kind) {
                ensure!(
                    owner.auth_epoch == action.auth_epoch
                        && owner.nonce.checked_add(1) == Some(action.nonce),
                    "stale authority or incorrect nonce"
                );
            } else {
                // Protective actions are tied to the state they change, not to
                // the account's nonce (see `crate::security`).
                ensure!(
                    action.nonce == 0 && action.auth_epoch == 0,
                    "this action carries no nonce and no authority epoch"
                );
            }
            let mut stage = ActionStage::new(self);
            stage.security_rows = true;
            crate::security::apply(&mut stage, &action, safety_hold)?;
            for row in stage.accounts.values() {
                validate_account(row, &stage.meta)?;
            }
            stage.commit();
            return Ok(());
        }
        if crate::wire::extension_kind(kind) || matches!(kind, 5..=7) {
            let action = if matches!(kind, 5..=7) {
                let legacy = ledger::decode_action(raw)?;
                crate::wire::SignedAction {
                    network_id: legacy.network_id,
                    from: legacy.from,
                    nonce: legacy.nonce,
                    auth_epoch: legacy.auth_epoch,
                    public_key: legacy.public_key,
                    kind,
                    payload: serde_json::to_value(legacy.payload)?,
                    raw_signing_bytes: raw[..raw.len() - 64].to_vec(),
                    signature: legacy.signature,
                }
            } else {
                crate::wire::decode(raw)?
            };
            ensure!(action.network_id == self.meta.network_id, "wrong network");
            let public = action.is_public_headers();
            // A secured account: not frozen now, and whatever this action
            // takes out of its balance must fit its daily limit.
            let mut secured = None;
            if !public {
                match signature {
                    SigStatus::Valid => {}
                    SigStatus::Invalid => anyhow::bail!("invalid action signature"),
                    SigStatus::Unknown => {
                        valid_public_key(&action.public_key)?;
                        action.verify_signer()?;
                    }
                }
                let owner = self.required(action.from)?;
                ensure!(
                    owner.auth_epoch == action.auth_epoch
                        && owner.nonce.checked_add(1) == Some(action.nonce),
                    "stale authority or incorrect nonce"
                );
                ensure!(
                    owner
                        .devices
                        .iter()
                        .any(|d| d.public_key == action.public_key && d.can_spend),
                    "spending device required"
                );
                ensure!(
                    !self
                        .cases(owner.id)?
                        .iter()
                        .any(|c| c.ready_elapsed_micros.is_some()),
                    "account frozen by guardian recovery"
                );
                if let Some(mut security) = crate::security::load(|key| self.get(key), &owner)? {
                    // The clock of the waits (`Meta::active_micros`).
                    let now = self.meta.active_micros()?;
                    security.spend(0, now)?;
                    secured = Some((security, owner.balance, now));
                }
            }
            if kind == upgrade::SIGNAL {
                self.load_upgrade()?;
            }
            let mut stage = ActionStage::new(self);
            // What the action hands to others without taking it from the
            // sender's balance (a market settle, what a release gives up, what
            // new scripts for an order point elsewhere): counted against a
            // secured sender's daily limit like what leaves the balance.
            let mut handed = 0u64;
            match kind {
                5 | 6 | 7 | 17 | 18 | 19 | 20 | 21 | 23 | 24 => {
                    crate::pos_adapter::apply(&mut stage, &action)?
                }
                40 => {
                    crate::bitcoin_adapter::apply(&mut stage, &action)?;
                    crate::market::headers_applied(&mut stage)?;
                }
                41 => crate::bitcoin_adapter::apply(&mut stage, &action)?,
                crate::market::ORDER..=crate::market::ADDRESSES => {
                    handed = crate::market::apply(&mut stage, &action)?;
                }
                42 => crate::auction::apply(&mut stage, &action)?,
                44 => crate::registration_adapter::apply(&mut stage, &action)?,
                60..=63 => crate::treasury_adapter::apply(&mut stage, &action)?,
                upgrade::SIGNAL => {
                    let entry = stage.signal_entry(&action)?;
                    stage.signal = Some(entry);
                }
                _ => anyhow::bail!("unsupported action"),
            }
            if !public {
                let fee = if matches!(kind, 41 | 42) {
                    0
                } else {
                    stage.meta.config.fee()
                };
                stage.debit(action.from, fee)?;
                stage.fee_credit(fee)?;
                let mut owner = stage.account(action.from)?;
                owner.nonce = action.nonce;
                let balance = owner.balance;
                stage.accounts.insert(owner.id, owner);
                if let Some((mut security, before, now)) = secured {
                    security.spend(pos::add(before.saturating_sub(balance), handed)?, now)?;
                    stage.security_rows = true;
                    stage.put(
                        crate::security::key(action.from),
                        Some(crate::security::encode(&security)?),
                    )?;
                }
            }
            stage.commit();
            Ok(())
        } else if kind == 3 && !self.generic_transfers {
            self.apply_transfer(raw, signature)
        } else {
            // Every remaining kind is authorized by the header key's
            // signature, which the rule adapter verifies itself. A signature
            // already known to be bad is rejected without repeating that work.
            ensure!(signature != SigStatus::Invalid, "invalid action signature");
            self.apply_legacy(raw)
        }
    }
    /// A plain transfer, with the rules of `apply_legacy` for kind 3 applied
    /// directly to the two account rows. It accepts and rejects exactly the
    /// transactions the rule adapter does and publishes the same rows; the
    /// differential tests compare the two paths. What it avoids is building a
    /// ledger view, copying the chain metadata and decoding the action twice.
    fn apply_transfer(&mut self, raw: &[u8], signature: SigStatus) -> Result<()> {
        let action = ledger::decode_action(raw)?;
        ensure!(action.network_id == self.meta.network_id, "wrong network");
        let ActionPayload::Transfer(transfer) = &action.payload else {
            anyhow::bail!("not a transfer action");
        };
        match signature {
            SigStatus::Valid => {}
            SigStatus::Invalid => anyhow::bail!("invalid action signature"),
            SigStatus::Unknown => ensure!(
                sigcache::signature_valid(raw),
                "invalid action signature"
            ),
        }
        // The reserved anonymous sender never owns an account.
        ensure!(action.from != u64::MAX, "account does not exist");
        // Both rows are loaded before any rule is checked, as the adapter does.
        let mut sender = self.required(action.from)?;
        let mut recipient = if transfer.to == action.from {
            None
        } else {
            Some(self.required(transfer.to)?)
        };
        let cases = self.cases(action.from)?;
        let now = self.meta.elapsed_micros()?;
        // What an action costs on this network.
        let fee = self.meta.config.fee();
        ensure!(
            sender.auth_epoch == action.auth_epoch,
            "stale authority epoch"
        );
        ensure!(
            sender.nonce.checked_add(1) == Some(action.nonce),
            "incorrect nonce or nonce exhausted"
        );
        ensure!(
            !cases
                .iter()
                .any(|case| case.ready_elapsed_micros.is_some()
                    && case.expires_elapsed_micros >= now),
            "account is frozen by threshold guardian recovery"
        );
        let device = sender
            .devices
            .iter()
            .find(|device| device.public_key == action.public_key)
            .ok_or_else(|| anyhow!("device is not authorized"))?;
        ensure!(device.can_spend, "device permission denied");
        // A secured account pays within its daily limit, and not while frozen.
        let secured = match crate::security::load(|key| self.get(key), &sender)? {
            Some(mut security) => {
                security.spend(
                    transfer
                        .amount
                        .checked_add(fee)
                        .ok_or_else(|| anyhow!("amount overflow"))?,
                    // The clock of the waits, not `now`, the chain's time.
                    self.meta.active_micros()?,
                )?;
                Some(crate::security::encode(&security)?)
            }
            None => None,
        };
        let bank = self
            .meta
            .bank
            .checked_add(fee)
            .ok_or_else(|| anyhow!("bank fee overflow"))?;
        let fees = if self.meta.config.fees_to_validators_ppm > 0 {
            pos::add(self.fees, fee)?
        } else {
            self.fees
        };
        let Some(recipient) = recipient.as_mut().filter(|_| transfer.amount != 0) else {
            anyhow::bail!("invalid transfer amount or recipient");
        };
        recipient.balance = recipient
            .balance
            .checked_add(transfer.amount)
            .ok_or_else(|| anyhow!("recipient balance overflow"))?;
        sender.nonce = action.nonce;
        sender.balance = sender
            .balance
            .checked_sub(transfer.amount)
            .ok_or_else(|| anyhow!("insufficient funds"))?
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("insufficient funds for fee"))?;
        // Of the account rules, only the encoded-size limit can be affected by
        // new balance and nonce digits. Both rows passed every rule when loaded.
        self.transfer_row_fits(&sender)?;
        self.transfer_row_fits(recipient)?;
        // The adapter also requires that no legacy commitment or bid list is
        // left behind; protocol 4 keeps both empty.
        ensure!(
            self.meta.name_commits.is_empty() && self.meta.auction_bids.len() <= MAX_BIDS,
            "v2 bounded metadata capacity"
        );
        // Publish. Nothing above changed this block's state.
        self.meta.bank = bank;
        self.fees = fees;
        if let Some(row) = secured {
            self.updates
                .insert(crate::security::key(sender.id), Some(row));
        }
        self.accounts.insert(recipient.id, recipient.clone());
        self.accounts.insert(sender.id, sender);
        self.recoveries.insert(action.from, cases);
        Ok(())
    }
    fn transfer_row_fits(&self, row: &Account) -> Result<()> {
        let within_bound = self
            .loaded_len
            .get(&row.id)
            .is_some_and(|length| length + TRANSFER_ROW_GROWTH <= MAX_ACCOUNT_BYTES);
        ensure!(
            within_bound || serde_json::to_vec(row)?.len() <= MAX_ACCOUNT_BYTES,
            "account byte limit"
        );
        Ok(())
    }
    fn apply_legacy(&mut self, raw: &[u8]) -> Result<()> {
        // V0 is intentionally not accepted on the v2 network.
        let action = ledger::decode_action(raw)?;
        ensure!(action.network_id == self.meta.network_id, "wrong network");
        // What an action costs on this network, and how much less that is
        // than what the protocol-4 rules applied below charge by themselves
        // (see where they are called). `Genesis::validate` keeps the fee at or
        // below theirs.
        let fee = self.meta.config.fee();
        let cushion = ledger::FEE_MICROS
            .checked_sub(fee)
            .ok_or_else(|| anyhow!("action fee above the protocol-4 fee"))?;
        if self.rules.since(4)
            && let ActionPayload::MerchantPayment(payment) = &action.payload
        {
            let reference = hex32(&payment.reference)?;
            let reserved_nonce = u64::from_be_bytes(reference[..8].try_into()?);
            let expiry = u64::from_be_bytes(reference[8..16].try_into()?);
            let now = self.meta.elapsed_micros()?;
            ensure!(
                reserved_nonce == action.nonce,
                "merchant reference reserved another sender nonce"
            );
            ensure!(
                expiry >= now
                    && expiry
                        <= now
                            .checked_add(86_400 * ledger::MICROS_PER_SECOND)
                            .ok_or_else(|| anyhow!("merchant expiry overflow"))?,
                "merchant reference expired or exceeds one day"
            );
            // Admission runs on the last block's clock: what is admitted must
            // still be valid in the blocks that follow.
            ensure!(
                !self.admission || expiry >= now.saturating_add(ADMISSION_MARGIN_MICROS),
                "merchant reference expires too soon to be included"
            );
        }
        let mut ids = BTreeSet::new();
        let mut targets = BTreeSet::new();
        if action.from != u64::MAX {
            ids.insert(action.from);
            targets.insert(action.from);
        }
        match &action.payload {
            ActionPayload::Commit(_) => {
                ensure!(
                    self.meta.account_count < MAX_ACCOUNTS
                        && self.meta.name_commits.len() < MAX_COMMITS,
                    "v2 registration capacity"
                );
                ensure!(
                    self.get(&pubkey_key(&action.public_key)?)?.is_none(),
                    "identity key already registered"
                );
            }
            ActionPayload::Reveal(p) => {
                ensure!(
                    self.meta.account_count < MAX_ACCOUNTS,
                    "v2 account capacity"
                );
                ensure!(
                    self.get(&name_key(&p.name))?.is_none(),
                    "username unavailable"
                );
                ensure!(
                    self.get(&pubkey_key(&action.public_key)?)?.is_none(),
                    "identity key already registered"
                );
                if self.meta.account_count > 0 {
                    ids.insert(
                        self.meta
                            .next_account_id
                            .checked_sub(1)
                            .ok_or_else(|| anyhow!("highest ID underflow"))?,
                    );
                }
            }
            ActionPayload::Transfer(p) => {
                ids.insert(p.to);
            }
            ActionPayload::MerchantPayment(p) => {
                ids.insert(p.to);
            }
            ActionPayload::SetRecovery(p) => {
                // Checked before any guardian row is loaded. The ledger rule
                // applied below enforces the same limit, so this rejects
                // nothing it would accept.
                ensure!(
                    p.guardians.len() <= ledger::MAX_GUARDIANS,
                    "recovery requires 2..5 distinct guardians"
                );
                // Rule change from protocol 4: the disable form ([], 0, 0) has
                // no delay, so the minimum delay does not apply to it.
                // Protocol 4 rejected it, which made recovery impossible to
                // turn off.
                ensure!(
                    p.guardians.is_empty()
                        || p.delay_seconds
                            .checked_mul(ledger::MICROS_PER_SECOND)
                            .is_some_and(|delay| delay
                                >= self.meta.config.recovery_min_delay_micros),
                    "recovery delay below configured minimum"
                );
                ids.extend(&p.guardians);
            }
            ActionPayload::ConsentRecovery(p) => {
                ids.insert(p.target);
                targets.insert(p.target);
            }
            ActionPayload::ApproveRecovery(p) => {
                ids.insert(p.target);
                targets.insert(p.target);
            }
            ActionPayload::Bid(_) => ensure!(
                self.meta.auction_bids.len() < MAX_BIDS,
                "v2 auction capacity"
            ),
            _ => {}
        }
        let mut rows = Vec::new();
        for id in ids {
            rows.push(self.required(id)?);
        }
        // A secured account sends only payments through these rules; its keys
        // and its recovery are managed by `crate::security`.
        let mut secured = None;
        if let Some(sender) = rows.iter().find(|row| row.id == action.from)
            && action.from != u64::MAX
            && let Some(mut security) = crate::security::load(|key| self.get(key), sender)?
        {
            let amount = match &action.payload {
                ActionPayload::Transfer(p) => Some(p.amount),
                ActionPayload::MerchantPayment(p) => Some(p.amount),
                // Giving up the role of guardian for another account is free,
                // so that nobody keeps counting on a guardian that can no
                // longer act. One recovery key signs it alone, and one key
                // alone must not decide anything: it is refused while a
                // recovery of that account rests on an approval this account
                // gave before it adopted the rules.
                ActionPayload::ConsentRecovery(p) if !p.accept => {
                    let now = self.meta.elapsed_micros()?;
                    ensure!(
                        !self.cases(p.target)?.iter().any(|case| {
                            case.expires_elapsed_micros >= now
                                && case.approvals.contains(&action.from)
                        }),
                        "a recovery in progress rests on this account's approval: withdraw when it is over"
                    );
                    None
                }
                _ => anyhow::bail!(
                    "a secured account manages its keys and recovery with its security rules"
                ),
            };
            if let Some(amount) = amount {
                security.spend(
                    amount
                        .checked_add(fee)
                        .ok_or_else(|| anyhow!("amount overflow"))?,
                    self.meta.active_micros()?,
                )?;
                secured = Some(crate::security::encode(&security)?);
            }
        }
        let mut cases = Vec::new();
        for id in &targets {
            cases.extend(self.cases(*id)?);
        }
        cases.sort_by(|a, b| (a.target, &a.recovery_id).cmp(&(b.target, &b.recovery_id)));
        let paid_commit = if matches!(action.payload, ActionPayload::Reveal(_)) {
            let stage = ActionStage::new(self);
            Some(crate::registration_adapter::for_reveal(
                &stage,
                &action.public_key,
            )?)
        } else {
            None
        };
        let mut view = self.meta.view(rows, cases);
        if let Some((commit, _)) = &paid_commit {
            view.name_commits = vec![commit.clone()];
        }
        // The protocol-4 rules are applied unchanged, and they charge
        // `ledger::FEE_MICROS` or nothing. On a network with a lower fee the
        // payer is lent the difference, the cushion, for the duration of the
        // call, in this staged view only. The rules' own check, balance >=
        // amount + `FEE_MICROS`, is then exactly balance >= amount + fee, so
        // what an action moves out comes from the payer's own balance and
        // never from the cushion. After the call the cushion is taken out
        // where it has gone: out of the bank if the rules charged (the payer
        // has then paid `fee` and the bank received `fee`), out of the
        // payer's balance if they did not (they move no balance without
        // charging). Whatever the rules did, the view must in the end hold
        // what it held before: nothing of it is published otherwise.
        let lent = if cushion > 0 {
            let payer = view
                .accounts
                .binary_search_by_key(&action.from, |row| row.id)
                .ok();
            let held = view_holdings(&view);
            let bank = view.bank;
            if let Some(index) = payer {
                view.accounts[index].balance = view.accounts[index]
                    .balance
                    .checked_add(cushion)
                    .ok_or_else(|| anyhow!("balance overflow"))?;
            }
            Some((payer, bank, held))
        } else {
            None
        };
        ledger::apply_tx_with_recovery_window(
            &mut view,
            raw,
            self.meta.config.recovery_approval_window_micros,
        )?;
        if let Some((payer, bank, _)) = lent {
            let charged = view.bank.checked_sub(bank);
            match (payer, charged) {
                (Some(_), Some(ledger::FEE_MICROS)) => {
                    view.bank = view
                        .bank
                        .checked_sub(cushion)
                        .ok_or_else(|| anyhow!("fee cushion missing from the bank"))?;
                }
                (Some(index), Some(0)) => {
                    ensure!(
                        view.accounts[index].id == action.from,
                        "the rule adapter moved the payer's row"
                    );
                    view.accounts[index].balance = view.accounts[index]
                        .balance
                        .checked_sub(cushion)
                        .ok_or_else(|| anyhow!("fee cushion missing from the payer"))?;
                }
                // An action without an account pays nothing and was lent
                // nothing.
                (None, Some(0)) => {}
                _ => anyhow::bail!("the rule adapter moved something other than a fee"),
            }
        }
        if matches!(action.payload, ActionPayload::CancelPending(_)) {
            // Rule change from protocol 4, where this action was free and had
            // no precondition: an account could then fill blocks at no cost.
            // It now pays the standard fee like every other account action.
            let index = view
                .accounts
                .binary_search_by_key(&action.from, |row| row.id)
                .map_err(|_| anyhow!("account does not exist"))?;
            view.accounts[index].balance = view.accounts[index]
                .balance
                .checked_sub(fee)
                .ok_or_else(|| anyhow!("insufficient funds for fee"))?;
            view.bank = view
                .bank
                .checked_add(fee)
                .ok_or_else(|| anyhow!("bank fee overflow"))?;
        }
        if let Some((_, _, held)) = lent {
            ensure!(
                view_holdings(&view) == held,
                "the rule adapter created or destroyed currency"
            );
        }
        ensure!(
            view.name_commits.len() <= MAX_COMMITS && view.auction_bids.len() <= MAX_BIDS,
            "v2 bounded metadata capacity"
        );
        // All postchecks occur before publishing staged state to the overlay.
        let mut next_meta = self.meta.clone();
        next_meta.absorb(&view);
        let fees = if self.meta.config.fees_to_validators_ppm > 0 {
            // The rule adapter moves nothing into the bank but the fee.
            let charged = next_meta
                .bank
                .checked_sub(self.meta.bank)
                .filter(|charged| *charged == 0 || *charged == fee)
                .ok_or_else(|| anyhow!("the rule adapter moved something other than a fee"))?;
            pos::add(self.fees, charged)?
        } else {
            self.fees
        };
        let mut new_accounts = Vec::new();
        for row in &view.accounts {
            validate_account(row, &next_meta)?;
            if !self.accounts.contains_key(&row.id) {
                ensure!(
                    matches!(action.payload, ActionPayload::Reveal(_))
                        && row.id == next_meta.next_account_id,
                    "unexpected new account ID"
                );
                new_accounts.push(row.clone());
            }
        }
        // On a network with distinct names a new name must not look like a
        // name that exists (`crate::names`). This is where a name becomes
        // known and binding: the protocol-4 rules have just accepted the
        // reveal, so the name is valid, is the one its paid commitment
        // names, and is not taken. Judged against the state as this block
        // has changed it so far, like the name itself. Nothing has been
        // published yet: a refusal leaves the block's state as it was, the
        // commitment included, as any refused reveal does.
        let mut skeletons = Vec::new();
        for row in &new_accounts {
            skeletons.extend(self.skeleton_row(&row.name)?);
        }
        for row in &new_accounts {
            next_meta.account_count = next_meta
                .account_count
                .checked_add(1)
                .ok_or_else(|| anyhow!("account count overflow"))?;
            next_meta.next_account_id = row
                .id
                .checked_add(1)
                .filter(|id| *id != u64::MAX)
                .ok_or_else(|| anyhow!("account ID exhausted"))?;
        }
        for id in &targets {
            let subset: Vec<_> = view
                .recovery_cases
                .iter()
                .filter(|c| c.target == *id)
                .cloned()
                .collect();
            let row = view
                .account(*id)
                .ok_or_else(|| anyhow!("missing recovery target"))?;
            validate_cases(&subset, row, &next_meta, true)?;
        }
        ensure!(
            view.name_commits.is_empty(),
            "successful identity action retained an external commitment"
        );
        if let Some((_, entry_id)) = &paid_commit {
            let mut stage = ActionStage::new(self);
            crate::registration_adapter::consume_commit(&mut stage, &action.public_key, entry_id)?;
            stage.commit();
        }
        self.meta = next_meta;
        self.fees = fees;
        if let Some(row) = secured {
            self.updates
                .insert(crate::security::key(action.from), Some(row));
        }
        for row in view.accounts {
            // The adapter may have changed more than balance and nonce.
            self.loaded_len.remove(&row.id);
            self.accounts.insert(row.id, row);
        }
        for row in new_accounts {
            self.updates
                .insert(name_key(&row.name), Some(index_bytes(row.id)?));
            self.updates
                .insert(pubkey_key(&row.public_key)?, Some(index_bytes(row.id)?));
            // With the service records: when the account came into being.
            if let Some((key, value)) = crate::service::account_created(&self.meta, row.id)? {
                self.updates.insert(key, Some(value));
            }
        }
        for (key, name) in skeletons {
            self.updates.insert(key, Some(name));
        }
        for id in targets {
            self.recoveries.insert(
                id,
                view.recovery_cases
                    .iter()
                    .filter(|c| c.target == id)
                    .cloned()
                    .collect(),
            );
        }
        Ok(())
    }
    /// On a network with distinct names: the row that records `name` under
    /// its skeleton, or the refusal if the name has no skeleton or looks
    /// like a name that exists (`crate::names`). On any other network,
    /// nothing. Read on the state as this block has changed it so far.
    fn skeleton_row(&self, name: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if !self.meta.config.distinct_names {
            return Ok(None);
        }
        let skeleton = crate::names::skeleton(name);
        ensure!(!skeleton.is_empty(), "{}", crate::names::EMPTY);
        let key = crate::names::key(&skeleton);
        if let Some(owner) = self.get(&key)? {
            let existing: String = canonical_decode(&owner)?;
            anyhow::bail!("{}", crate::names::too_close(name, &existing));
        }
        Ok(Some((key, serde_json::to_vec(name)?)))
    }
    /// A registration that creates its account protected (kind 45,
    /// `crate::security::REGISTER`), on a network with
    /// `protected_registration`: the reveal of a sponsored registration,
    /// carrying the set of keys and the policy the account starts with.
    ///
    /// It is a reveal in everything else, and the rules of the protocol-4
    /// reveal are applied here one by one, because those rules know neither
    /// the payload nor an account that starts without a key holding every
    /// power: the header of an action without an account; a valid name that
    /// is free; a registration key that owns no account; a paid commitment
    /// of that key that has not expired and was made in an earlier block;
    /// the next account id. On a network with distinct names the name must
    /// not look like a name that exists either. Like a reveal it pays
    /// nothing: the sponsor paid when the commitment was made.
    ///
    /// The commitment is the one of `crate::security::registration_commitment`:
    /// it names the set of keys and the policy, so the name is taken with
    /// exactly what was committed to or not at all. The set is judged as the
    /// action `secure` judges the set an account adopts
    /// (`crate::security::first_set`). Nothing is published unless every
    /// rule passes, and a refusal leaves what any refused reveal leaves: the
    /// commitment stays until it expires.
    fn apply_protected_registration(&mut self, raw: &[u8], signature: SigStatus) -> Result<()> {
        ensure!(
            self.meta.config.protected_registration,
            "this network does not register accounts with a set of keys: register the account, then adopt the security rules"
        );
        let action = crate::wire::decode(raw)?;
        ensure!(action.network_id == self.meta.network_id, "wrong network");
        match signature {
            SigStatus::Valid => {}
            SigStatus::Invalid => anyhow::bail!("invalid action signature"),
            SigStatus::Unknown => {
                valid_public_key(&action.public_key)?;
                action.verify_signer()?;
            }
        }
        ensure!(
            action.from == u64::MAX && action.nonce == 0 && action.auth_epoch == 0,
            "registration requires anonymous header"
        );
        let (name, salt, setup) = crate::security::registration_payload(&action.payload)?;
        ensure!(
            self.meta.account_count < MAX_ACCOUNTS,
            "v2 account capacity"
        );
        ensure!(
            (2..=15).contains(&name.len())
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
            "invalid canonical username"
        );
        ensure!(
            self.get(&name_key(&name))?.is_none(),
            "username unavailable"
        );
        ensure!(
            self.get(&pubkey_key(&action.public_key)?)?.is_none(),
            "identity key already registered"
        );
        let (commit, entry_id) = {
            let stage = ActionStage::new(self);
            crate::registration_adapter::for_reveal(&stage, &action.public_key)?
        };
        ensure!(
            self.meta.height > commit.height,
            "name reveal requires a later committed height"
        );
        ensure!(
            commit.commitment
                == crate::security::registration_commitment(
                    &self.meta.network_id,
                    &action.public_key,
                    &name,
                    &salt,
                    &setup,
                )?,
            "the registration does not match its paid commitment: the name, the salt and the set of keys must be the ones committed to"
        );
        // The set of keys, by the rules of `secure`. The account's first
        // security row is dated on the clock of the waits.
        let first = crate::security::first_set(&self.meta, &setup, self.meta.active_micros()?)?;
        let id = self.meta.next_account_id;
        let mut next_meta = self.meta.clone();
        next_meta.account_count = next_meta
            .account_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("account count overflow"))?;
        next_meta.next_account_id = id
            .checked_add(1)
            .filter(|next| *next != u64::MAX)
            .ok_or_else(|| anyhow!("account ID exhausted"))?;
        let row = Account {
            id,
            name,
            public_key: action.public_key.clone(),
            balance: 0,
            nonce: 0,
            auth_epoch: 0,
            devices: first.devices.clone(),
            delegations: Vec::new(),
            unbonding: Vec::new(),
            recovery_version: 0,
            recovery_policy: None,
        };
        ensure!(
            !self.accounts.contains_key(&id) && self.get(&account_key(id))?.is_none(),
            "unexpected new account ID"
        );
        validate_account(&row, &next_meta)?;
        crate::security::validate(&next_meta, &row, &first.security)?;
        let skeleton = self.skeleton_row(&row.name)?;
        let created = crate::service::account_created(&self.meta, id)?;
        let indexes = [
            (name_key(&row.name), index_bytes(id)?),
            (pubkey_key(&row.public_key)?, index_bytes(id)?),
            (crate::security::key(id), crate::security::encode(&first.security)?),
        ];
        // Signatures inside the payload last, after every check that costs
        // little: each key of the set accepted its role for this
        // registration key.
        first.accepted(&self.meta.network_id, &action.public_key)?;
        // Publish. The commitment is used up in the same action.
        {
            let mut stage = ActionStage::new(self);
            crate::registration_adapter::consume_commit(&mut stage, &action.public_key, &entry_id)?;
            stage.commit();
        }
        self.meta.account_count = next_meta.account_count;
        self.meta.next_account_id = next_meta.next_account_id;
        for (key, value) in indexes.into_iter().chain(skeleton).chain(created) {
            self.updates.insert(key, Some(value));
        }
        self.loaded_len.remove(&id);
        self.accounts.insert(id, row);
        Ok(())
    }
    fn finish(mut self, store: &Store, txcount: usize) -> Result<Prepared> {
        // Committed rows, ignoring this block's changes.
        let base = self.base.clone();
        let base_get = |key: &[u8]| -> Option<Vec<u8>> {
            base.as_ref()
                .and_then(|version| version.get(key))
                .map(|row| row.to_vec())
        };
        let mut upgrade_events = Vec::new();
        if self.meta.height > 0 {
            let fees = self
                .meta
                .config
                .validators_fee(std::mem::take(&mut self.fees));
            let mut stage = ActionStage::new(&mut self);
            crate::pos_adapter::collect_fees(&mut stage, fees)?;
            let changes = crate::pos_adapter::finalize(&mut stage)?;
            stage.commit();
            self.validators = changes.validators;
            self.validator_updates = changes.updates;
            // The plan: after the block's transactions and roster changes.
            upgrade_events = self.upgrade_step()?;
        }

        let mut old_liquid = 0u64;
        let mut old_unbond = 0u64;
        let mut old_shares = vec![0u64; self.meta.pools.len()];
        let mut new_liquid = 0u64;
        let mut new_unbond = 0u64;
        let mut new_shares = vec![0u64; self.meta.pools.len()];
        let mut changed_accounts = 0;
        let mut changed_rows = Vec::new();
        let mut unbond_index_checks = 0;
        for row in self.accounts.values() {
            let previous = self.original.get(&row.id);
            // Read-only dependencies were authenticated and structurally
            // checked when loaded. They have no asset delta and cannot alter
            // escrow ownership. Do not recount or walk their escrow indices.
            if previous == Some(row) {
                continue;
            }
            changed_accounts += 1;
            if let Some(previous) = previous {
                totals(
                    previous,
                    &self.meta,
                    &mut old_liquid,
                    &mut old_unbond,
                    &mut old_shares,
                )?;
            }
            totals(
                row,
                &self.meta,
                &mut new_liquid,
                &mut new_unbond,
                &mut new_shares,
            )?;
            let bytes = serde_json::to_vec(row)?;
            changed_rows.push((
                row.id,
                Arc::new(CachedAccount {
                    row: row.clone(),
                    encoded_len: bytes.len(),
                }),
            ));
            self.updates.insert(account_key(row.id), Some(bytes));
            for old in previous.into_iter().flat_map(|r| &r.unbonding) {
                unbond_index_checks += 1;
                ensure!(
                    base_get(&unbond_key(old.id)) == Some(index_bytes(row.id)?),
                    "unbond index corrupt"
                );
                if row
                    .unbonding
                    .binary_search_by_key(&old.id, |u| u.id)
                    .is_err()
                {
                    self.updates.insert(unbond_key(old.id), None);
                }
            }
            for new in &row.unbonding {
                if previous
                    .is_none_or(|r| r.unbonding.binary_search_by_key(&new.id, |u| u.id).is_err())
                {
                    unbond_index_checks += 1;
                    ensure!(
                        base_get(&unbond_key(new.id)).is_none()
                            && !self.updates.contains_key(&unbond_key(new.id)),
                        "duplicate unbond ID"
                    );
                    self.updates
                        .insert(unbond_key(new.id), Some(index_bytes(row.id)?));
                }
            }
        }
        self.meta.liquid_total = delta(self.meta.liquid_total, old_liquid, new_liquid)?;
        self.meta.unbond_total = delta(self.meta.unbond_total, old_unbond, new_unbond)?;
        for ((aggregate, old), new) in self
            .meta
            .pool_share_totals
            .iter_mut()
            .zip(old_shares)
            .zip(new_shares)
        {
            *aggregate = delta(*aggregate, old, new)?;
        }
        for (id, cases) in self.recoveries {
            let key = recovery_key(id);
            let value = if cases.is_empty() {
                None
            } else {
                Some(serde_json::to_vec(&cases)?)
            };
            if base_get(&key) != value {
                self.updates.insert(key, value);
            }
        }
        self.meta.validate()?;
        let metadata = serde_json::to_vec(&self.meta)?;
        self.updates
            .insert(META_KEY.to_vec(), Some(metadata.clone()));
        let touched_accounts = self.accounts.len();
        let mut tree = store.prepare(
            self.base.as_ref(),
            self.meta.height as u64,
            self.updates.into_iter().collect(),
        )?;
        tree.set_head_metadata(metadata.clone(), [0; 32])?;
        Ok(Prepared {
            root: tree.root,
            meta: self.meta,
            txcount,
            touched_accounts,
            changed_accounts,
            unbond_index_checks,
            updated_rows: tree.updated_rows(),
            validators: self.validators,
            validator_updates: self.validator_updates,
            history_append: self.history_append,
            history_durable: false,
            upgrade_events,
            tree,
            meta_bytes: metadata,
            changed_rows,
        })
    }
}

fn totals(
    row: &Account,
    meta: &Meta,
    liquid: &mut u64,
    unbond: &mut u64,
    shares: &mut [u64],
) -> Result<()> {
    *liquid = liquid
        .checked_add(row.balance)
        .ok_or_else(|| anyhow!("touched liquid overflow"))?;
    for entry in &row.unbonding {
        *unbond = unbond
            .checked_add(entry.amount)
            .ok_or_else(|| anyhow!("touched escrow overflow"))?;
    }
    for d in &row.delegations {
        let i = meta
            .pools
            .binary_search_by_key(&d.operator, |p| p.operator)
            .map_err(|_| anyhow!("unknown delegation pool"))?;
        shares[i] = shares[i]
            .checked_add(d.shares)
            .ok_or_else(|| anyhow!("touched shares overflow"))?;
    }
    Ok(())
}
/// Everything a ledger view holds: its bank and the balances of its accounts.
/// (Protocol-4 account rows hold nothing else: `validate_account` refuses
/// stake and escrow entries.)
fn view_holdings(view: &State) -> u128 {
    view.accounts
        .iter()
        .fold(u128::from(view.bank), |sum, row| sum + u128::from(row.balance))
}
fn delta(total: u64, old: u64, new: u64) -> Result<u64> {
    total
        .checked_sub(old)
        .and_then(|v| v.checked_add(new))
        .ok_or_else(|| anyhow!("aggregate delta overflow/underflow"))
}
fn index_bytes(id: u64) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&id.to_string())?)
}
fn decode_index(bytes: &[u8]) -> Result<u64> {
    let text: String = canonical_decode(bytes)?;
    let id: u64 = text.parse()?;
    ensure!(id.to_string() == text, "noncanonical index ID");
    Ok(id)
}
pub fn canonical_decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "noncanonical row encoding"
    );
    Ok(value)
}
fn hex32(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "noncanonical 32-byte key"
    );
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow!("key length"))
}
pub(crate) fn valid_public_key(text: &str) -> Result<()> {
    let bytes = hex32(text)?;
    let mut y = bytes;
    y[31] &= 0x7f;
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    ensure!(
        y.iter().rev().cmp(p.iter().rev()).is_lt(),
        "noncanonical Ed25519 key"
    );
    ensure!(
        !VerifyingKey::from_bytes(&bytes)?.is_weak(),
        "weak Ed25519 key"
    );
    Ok(())
}
fn validate_account(row: &Account, meta: &Meta) -> Result<()> {
    ensure!(
        row.id != u64::MAX
            && (2..=15).contains(&row.name.len())
            && row
                .name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
        "invalid identity"
    );
    ensure!(
        row.delegations.is_empty() && row.unbonding.is_empty(),
        "legacy stake rows forbidden onv4"
    );
    valid_public_key(&row.public_key)?;
    if let Ok(i) = meta
        .genesis
        .accounts
        .binary_search_by_key(&row.id, |a| a.id)
    {
        ensure!(
            meta.genesis.accounts[i].name == row.name
                && meta.genesis.accounts[i].public_key == row.public_key,
            "genesis identity changed"
        );
    }
    ensure!(
        !row.devices.is_empty()
            && row.devices.len() <= ledger::MAX_DEVICES
            && row
                .devices
                .windows(2)
                .all(|w| w[0].public_key < w[1].public_key)
            && row.devices.iter().any(|d| d.can_manage)
            && row.devices.iter().any(|d| d.can_spend)
            && row.auth_epoch <= row.nonce,
        "invalid device authority"
    );
    for device in &row.devices {
        valid_public_key(&device.public_key)?;
    }
    ensure!(
        row.delegations.len() <= ledger::MAX_OPERATORS
            && row
                .delegations
                .windows(2)
                .all(|w| w[0].operator < w[1].operator)
            && row.unbonding.len() <= ledger::MAX_UNBONDING
            && row.unbonding.windows(2).all(|w| w[0].id < w[1].id),
        "staking order/bounds"
    );
    for d in &row.delegations {
        ensure!(
            d.shares > 0
                && meta
                    .pools
                    .binary_search_by_key(&d.operator, |p| p.operator)
                    .is_ok(),
            "invalid delegation"
        );
    }
    for u in &row.unbonding {
        ensure!(
            u.amount > 0 && u.id < meta.next_unbond_id,
            "invalid unbond ID/amount"
        );
    }
    ensure!(
        row.recovery_version <= row.auth_epoch,
        "recovery version/epoch"
    );
    if let Some(p) = &row.recovery_policy {
        ensure!(
            row.recovery_version > 0
                && (2..=ledger::MAX_GUARDIANS).contains(&p.guardians.len())
                && p.threshold >= 2
                && p.threshold > p.guardians.len() as u64 / 2
                && p.threshold <= p.guardians.len() as u64
                && (30..=30 * 86400).contains(&p.delay_seconds)
                && p.guardians.windows(2).all(|w| w[0] < w[1])
                && p.accepted.windows(2).all(|w| w[0] < w[1])
                && p.guardians.iter().all(|id| *id != row.id)
                && p.accepted
                    .iter()
                    .all(|id| p.guardians.binary_search(id).is_ok()),
            "invalid recovery policy"
        );
    }
    ensure!(
        serde_json::to_vec(row)?.len() <= MAX_ACCOUNT_BYTES,
        "account byte limit"
    );
    Ok(())
}
fn read_cases(snapshot: &crate::store::VerifiedAudit<'_>, id: u64) -> Result<Vec<RecoveryCase>> {
    match snapshot.get(&recovery_key(id))? {
        None => Ok(Vec::new()),
        Some(bytes) => canonical_decode(&bytes),
    }
}
fn validate_cases(cases: &[RecoveryCase], row: &Account, meta: &Meta, live: bool) -> Result<()> {
    ensure!(
        cases.len() <= ledger::MAX_GUARDIANS
            && cases
                .windows(2)
                .all(|w| w[0].recovery_id < w[1].recovery_id),
        "recovery case order/bound"
    );
    let mut votes = BTreeSet::new();
    for case in cases {
        ensure!(case.target == row.id, "recovery row target mismatch");
        hex32(&case.recovery_id)?;
        valid_public_key(&case.new_public_key)?;
        // Stale/expired rows are authenticated historical garbage until the
        // target is touched; they never contribute authority or a freeze.
        if !live
            && (case.expires_elapsed_micros < meta.elapsed_micros()?
                || case.auth_epoch != row.auth_epoch
                || case.policy_version != row.recovery_version)
        {
            continue;
        }
        let p = row
            .recovery_policy
            .as_ref()
            .ok_or_else(|| anyhow!("case without policy"))?;
        ensure!(
            case.policy_version == row.recovery_version
                && case.auth_epoch == row.auth_epoch
                && case.expires_elapsed_micros >= meta.elapsed_micros()?
                && !case.approvals.is_empty()
                && case.approvals.len() <= p.guardians.len()
                && case.approvals.windows(2).all(|w| w[0] < w[1]),
            "invalid recovery coordinates"
        );
        for id in &case.approvals {
            ensure!(
                p.accepted.binary_search(id).is_ok() && votes.insert(*id),
                "unconsented or duplicate guardian vote"
            );
        }
        ensure!(
            (case.approvals.len() as u64 >= p.threshold) == case.ready_elapsed_micros.is_some()
                && case
                    .ready_elapsed_micros
                    .is_none_or(|ready| ready >= p.delay_seconds * ledger::MICROS_PER_SECOND
                        && ready <= case.expires_elapsed_micros),
            "recovery threshold/delay mismatch"
        );
    }
    Ok(())
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use timecurrency_node::ledger::{Action, Transfer};

    fn entry(id: u64, balance: u64) -> Arc<CachedAccount> {
        Arc::new(CachedAccount {
            row: Account {
                id,
                name: format!("a{id}"),
                public_key: String::new(),
                balance,
                nonce: 0,
                auth_epoch: 0,
                devices: vec![],
                delegations: vec![],
                unbonding: vec![],
                recovery_version: 0,
                recovery_policy: None,
            },
            encoded_len: 1,
        })
    }
    fn balance(cache: &AccountCache, height: u64, id: u64) -> Option<u64> {
        cache.get(height, id).map(|entry| entry.row.balance)
    }

    #[test]
    fn the_cache_stays_bounded_and_never_serves_an_old_row() {
        let cache = AccountCache::with_generation(Some(5), 4);
        for id in 0..5 {
            cache.insert_loaded(5, id, entry(id, 10));
        }
        // The fifth insert started a new generation; the first four remain readable.
        assert_eq!(cache.len(), 5);
        assert_eq!(balance(&cache, 5, 0), Some(10));
        for id in 5..9 {
            cache.insert_loaded(5, id, entry(id, 10));
        }
        // The oldest generation is gone; the size never exceeds two generations.
        assert_eq!(balance(&cache, 5, 0), None);
        assert_eq!(balance(&cache, 5, 4), Some(10));
        assert!(cache.len() <= 8);
        // Another height sees nothing and cannot add anything.
        assert_eq!(balance(&cache, 6, 8), None);
        cache.insert_loaded(6, 20, entry(20, 1));
        assert_eq!(cache.missing(6, vec![8, 20]), Vec::<u64>::new());
        assert_eq!(cache.missing(5, vec![8, 20]), vec![20]);
        // A commit moves the height: changed rows are replaced in both
        // generations, unchanged rows stay.
        let before = cache.len();
        cache.advance(Some(5), 6, vec![(7, entry(7, 99))]);
        assert_eq!(balance(&cache, 6, 7), Some(99));
        assert_eq!(balance(&cache, 6, 5), Some(10));
        assert_eq!(balance(&cache, 5, 5), None);
        assert_eq!(cache.len(), before, "an old copy of the changed row survived");
        // Rotating once more must not bring an old copy back.
        for id in 30..34 {
            cache.insert_loaded(6, id, entry(id, 1));
        }
        assert_eq!(balance(&cache, 6, 7), Some(99));
        // A commit on another parent invalidates everything.
        cache.advance(Some(99), 100, vec![(1, entry(1, 5))]);
        assert_eq!(cache.len(), 1);
        assert_eq!(balance(&cache, 100, 1), Some(5));
        assert_eq!(balance(&cache, 100, 7), None);
    }

    #[test]
    fn touched_accounts_are_read_from_the_transaction_bytes() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let action = |from: u64, payload: ActionPayload| {
            ledger::sign_action(
                &Action {
                    network_id: "ab".repeat(32),
                    from,
                    nonce: 7,
                    auth_epoch: 0,
                    public_key: hex::encode(key.verifying_key().as_bytes()),
                    payload,
                    signature: vec![],
                },
                &key,
            )
            .unwrap()
        };
        let transfer = action(12, ActionPayload::Transfer(Transfer { to: 345, amount: 1 }));
        assert_eq!(touched_ids(&transfer), [Some(12), Some(345)]);
        let cancel = action(12, ActionPayload::CancelPending(ledger::CancelPending {}));
        assert_eq!(touched_ids(&cancel), [Some(12), None]);
        let anonymous = action(u64::MAX, ActionPayload::Transfer(Transfer { to: 3, amount: 1 }));
        assert_eq!(touched_ids(&anonymous), [None, Some(3)]);
        // Anything unreadable gives no hint and no panic.
        assert_eq!(touched_ids(&transfer[..60]), [None, None]);
        assert_eq!(touched_ids(&[]), [None, None]);
        let mut broken = transfer.clone();
        broken[crate::wire::HEADER] = b'[';
        assert_eq!(touched_ids(&broken), [Some(12), None]);
        assert_eq!(touched_ids(&transfer[..crate::wire::HEADER + 3]), [Some(12), None]);
    }
}
