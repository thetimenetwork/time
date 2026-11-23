//! Incremental protocol-4 ledger. Only touched accounts enter the legacy identity rule
//! adapter; neither block execution nor proof generation loads a full registry.
pub use crate::store::AuditStorageProgress as AuditProgress;
use crate::store::{Head, PreparedTree, Snapshot, Store};
use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Mutex,
};
use timecurrency_node::ledger::{
    self, Account, ActionPayload, AuctionBid, Genesis, NameCommit, Pool, RecoveryCase, State,
};

mod decimal;

pub const META_KEY: &[u8] = b"meta";
pub const MAX_META_BYTES: usize = 256 * 1024;
pub const MAX_ACCOUNT_BYTES: usize = 32 * 1024;
pub const MAX_GENESIS_ACCOUNTS: usize = 64;
pub const MAX_ACCOUNTS: u64 = u64::MAX - 1;
pub const MAX_COMMITS: usize = 256;
pub const MAX_BIDS: usize = 1024;

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
    pub genesis: Genesis,
    pub config: crate::genesis::Genesis,
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
}

impl Meta {
    pub fn elapsed_micros(&self) -> Result<u64> {
        Ok(u64::try_from(
            self.time_micros
                .checked_sub(self.genesis.genesis_time_micros)
                .ok_or_else(|| anyhow!("elapsed overflow"))?,
        )?)
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.protocol_version == 4 && self.genesis == self.config.ledger,
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
            genesis: self.genesis.clone(),
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
    pub new_nodes: usize,
    pub validators: Vec<pos::Validator>,
    pub validator_updates: Vec<pos::Validator>,
    history_append: Option<history::Append>,
    tree: PreparedTree,
}
impl Prepared {
    pub fn verified_read_cache_stats(&self) -> crate::store::VerifiedReadCacheStats {
        self.tree.verified_read_cache_stats()
    }
}
pub struct Engine {
    store: Store,
    meta: Option<Meta>,
    history_path: Option<PathBuf>,
    history_archive: Option<Mutex<history::archive::Archive>>,
}

impl Engine {
    pub fn open(store: Store) -> Result<Self> {
        let snapshot = store.snapshot()?;
        let meta = match snapshot.head()? {
            None => {
                ensure!(snapshot.get(META_KEY)?.is_none(), "metadata without head");
                None
            }
            Some(head) => {
                let bytes = snapshot
                    .get(META_KEY)?
                    .ok_or_else(|| anyhow!("head without authenticated metadata"))?;
                ensure!(bytes == head.metadata, "head metadata mismatch");
                let meta: Meta = canonical_decode(&bytes)?;
                meta.validate()?;
                ensure!(
                    meta.height as u64 == head.version,
                    "head/ledger height mismatch"
                );
                Some(meta)
            }
        };
        Ok(Self {
            store,
            meta,
            history_path: None,
            history_archive: None,
        })
    }
    pub fn open_with_history(store: Store, directory: impl AsRef<Path>) -> Result<Self> {
        let mut engine = Self::open(store)?;
        engine.history_path = Some(directory.as_ref().to_path_buf());
        if let Some(meta) = &engine.meta {
            let mut archive =
                history::archive::Archive::open(directory.as_ref(), hex32(&meta.network_id)?)?;
            let summary: history::Summary = canonical_decode(
                &engine
                    .store
                    .snapshot()?
                    .get(history::KEY)?
                    .ok_or_else(|| anyhow!("missing authenticated history summary"))?,
            )?;
            ensure!(
                summary.size == meta.height as u64
                    && summary.network_id == meta.network_id
                    && summary.last_time_micros == u64::try_from(meta.time_micros)?,
                "history/ledger head mismatch"
            );
            archive.verify_committed_prefix(&summary)?;
            engine.history_archive = Some(Mutex::new(archive));
        }
        Ok(engine)
    }
    pub fn history_proof(&self, version: u64, height: u64) -> Result<history::Proof> {
        let snapshot = self.store.snapshot()?;
        let head = snapshot.version_head(version)?;
        let raw = snapshot
            .proof(history::KEY, version)?
            .verify(head.root, history::KEY)?
            .ok_or_else(|| anyhow!("missing authenticated history summary"))?;
        let summary: history::Summary = canonical_decode(&raw)?;
        self.history_archive
            .as_ref()
            .ok_or_else(|| anyhow!("history proof archive unavailable in pure library mode"))?
            .lock()
            .map_err(|_| anyhow!("history archive lock poisoned"))?
            .prove(&summary, height)
    }
    pub fn store(&self) -> &Store {
        &self.store
    }
    pub fn meta(&self) -> Option<&Meta> {
        self.meta.as_ref()
    }
    pub fn head(&self) -> Result<Option<Head>> {
        self.store.snapshot()?.head()
    }
    pub fn active_roster_at(&self, height: u64) -> Result<Vec<pos::Validator>> {
        let snapshot = self.store.snapshot()?;
        crate::pos_adapter::roster_at(|key| snapshot.get(key), height)
    }
    /// Mempool validation uses committed coordinates and never advances time,
    /// settles an auction, publishes a row, or permits same-height reveals.
    pub fn validate_tx(&self, raw: &[u8]) -> Result<()> {
        let meta = self
            .meta
            .clone()
            .ok_or_else(|| anyhow!("uninitialized engine"))?;
        let snapshot = self.store.snapshot()?;
        ensure!(
            snapshot
                .head()?
                .is_some_and(|h| h.version == meta.height as u64
                    && h.metadata == serde_json::to_vec(&meta).unwrap_or_default()),
            "engine stale head"
        );
        let mut overlay = Overlay {
            snapshot,
            meta,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            original: BTreeMap::new(),
            recoveries: BTreeMap::new(),
            validators: Vec::new(),
            validator_updates: Vec::new(),
            history_append: None,
        };
        overlay.apply(raw)
    }
    pub fn initialize(&mut self, config: crate::genesis::Genesis) -> Result<Head> {
        config.validate()?;
        ensure!(
            config.ledger.accounts.len() <= MAX_GENESIS_ACCOUNTS,
            "bounded genesis"
        );
        let state = ledger::new(config.ledger.clone())?;
        if let Some(meta) = &self.meta {
            ensure!(
                serde_json::to_vec(&meta.config)? == serde_json::to_vec(&config)?,
                "genesis differs from existing v4 database"
            );
            return self
                .store
                .genesis_head()?
                .ok_or_else(|| anyhow!("missing genesis head"));
        }
        let mut seen = BTreeSet::new();
        for row in &state.accounts {
            ensure!(
                seen.insert(&row.public_key),
                "duplicate initial identity key"
            );
        }
        let meta = Meta {
            protocol_version: 4,
            network_id: config.network_id()?,
            genesis: state.genesis,
            config,
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
        }
        let initial_history =
            history::Summary::empty(hex32(&meta.network_id)?, u64::try_from(meta.time_micros)?);
        let mut overlay = Overlay {
            snapshot: self.store.snapshot()?,
            meta,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            original: BTreeMap::new(),
            recoveries: BTreeMap::new(),
            validators: Vec::new(),
            validator_updates: Vec::new(),
            history_append: None,
        };
        overlay.updates.insert(
            history::KEY.to_vec(),
            Some(serde_json::to_vec(&initial_history)?),
        );
        for account in state.accounts {
            overlay
                .updates
                .insert(name_key(&account.name), Some(index_bytes(account.id)?));
            overlay.updates.insert(
                pubkey_key(&account.public_key)?,
                Some(index_bytes(account.id)?),
            );
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
            stage.commit();
        }
        let mut prepared = overlay.finish(0)?;
        prepared
            .tree
            .set_head_metadata(serde_json::to_vec(&prepared.meta)?, [0; 32])?;
        let head = self.store.commit(prepared.tree)?;
        self.meta = Some(prepared.meta);
        Ok(head)
    }
    pub fn prepare(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[Vec<u8>],
        eligible: &[String],
        block_hash: [u8; 32],
    ) -> Result<Prepared> {
        ledger::validate_block_transactions(txs)?;
        let mut overlay = self.overlay(height, time_micros, eligible, block_hash)?;
        for tx in txs {
            overlay.apply(tx)?;
        }
        overlay.finish(txs.len())
    }
    pub fn prepare_filtered(
        &self,
        height: i64,
        time_micros: i64,
        txs: &[Vec<u8>],
        eligible: &[String],
        maxbytes: usize,
        block_hash: [u8; 32],
    ) -> Result<(Prepared, Vec<Vec<u8>>)> {
        let mut overlay = self.overlay(height, time_micros, eligible, block_hash)?;
        let mut accepted = Vec::new();
        let mut used = 0usize;
        for tx in txs.iter().take(ledger::MAX_BLOCK_TXS) {
            if tx.len()
                > maxbytes
                    .min(ledger::MAX_BLOCK_TX_BYTES)
                    .saturating_sub(used)
            {
                continue;
            }
            if overlay.apply(tx).is_ok() {
                used += tx.len();
                accepted.push(tx.clone());
            }
        }
        Ok((overlay.finish(accepted.len())?, accepted))
    }
    fn overlay(
        &self,
        height: i64,
        time_micros: i64,
        eligible: &[String],
        block_hash: [u8; 32],
    ) -> Result<Overlay> {
        let meta = self
            .meta
            .clone()
            .ok_or_else(|| anyhow!("uninitialized engine"))?;
        let snapshot = self.store.snapshot()?;
        ensure!(
            snapshot
                .head()?
                .is_some_and(|h| h.version == meta.height as u64
                    && h.metadata == serde_json::to_vec(&meta).unwrap_or_default()),
            "stale engine head"
        );
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
                .get(history::KEY)?
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
        let mut overlay = Overlay {
            snapshot,
            meta,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
            original: BTreeMap::new(),
            recoveries: BTreeMap::new(),
            validators: Vec::new(),
            validator_updates: Vec::new(),
            history_append: None,
        };
        overlay.updates.insert(
            history::KEY.to_vec(),
            Some(serde_json::to_vec(&history_append.summary)?),
        );
        overlay.history_append = Some(history_append);
        overlay.meta.height = height;
        overlay.meta.time_micros = time_micros;
        overlay.meta.bank = pos::add(overlay.meta.bank, delta)?;
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
            let changes = crate::pos_adapter::begin_block(&mut stage, eligible, delta)?;
            crate::bitcoin_adapter::begin_block(&mut stage)?;
            crate::treasury_adapter::begin_block(&mut stage)?;
            crate::auction::begin_block(&mut stage)?;
            crate::registration_adapter::begin_block(&mut stage)?;
            stage.commit();
            overlay.validators = changes.validators;
            overlay.validator_updates = changes.updates;
        }
        overlay.prune_history()?;
        Ok(overlay)
    }
    pub fn commit(&mut self, mut prepared: Prepared, fingerprint: [u8; 32]) -> Result<Head> {
        prepared
            .tree
            .set_head_metadata(serde_json::to_vec(&prepared.meta)?, fingerprint)?;
        let snapshot = self.store.snapshot()?;
        let head = snapshot
            .head()?
            .ok_or_else(|| anyhow!("uninitialized commit"))?;
        ensure!(
            head.version.checked_add(1) == Some(prepared.meta.height as u64)
                && self
                    .meta
                    .as_ref()
                    .is_some_and(|m| m.height as u64 == head.version
                        && serde_json::to_vec(m).is_ok_and(|bytes| bytes == head.metadata)),
            "stale prepared commit"
        );
        let append = prepared
            .history_append
            .as_ref()
            .ok_or_else(|| anyhow!("missing prepared history append"))?;
        let current: history::Summary = canonical_decode(
            &snapshot
                .get(history::KEY)?
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
        let head = self.store.commit(prepared.tree)?;
        self.meta = Some(prepared.meta);
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
        let meta = self
            .meta
            .as_ref()
            .ok_or_else(|| anyhow!("uninitialized engine"))?;
        let pinned = self.store.snapshot()?;
        ensure!(
            pinned
                .head()?
                .is_some_and(|head| head.version == meta.height as u64
                    && head.metadata == serde_json::to_vec(meta).unwrap_or_default()),
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
            archive.audit(&history, u64::try_from(meta.genesis.genesis_time_micros)?)?;
            if meta.history_pruned_through > 0 {
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
            previous_time = absolute;
            times += 1;
            Ok(())
        })?;
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
            .and_then(|v| v.checked_add(recovery_rows))
            .and_then(|v| v.checked_add(unbond_indices))
            .and_then(|v| v.checked_add(pos_leaves))
            .and_then(|v| v.checked_add(auction_leaves))
            .and_then(|v| v.checked_add(bitcoin_leaves))
            .and_then(|v| v.checked_add(treasury_leaves))
            .and_then(|v| v.checked_add(registration_leaves))
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
    pub history_archive_verified: bool,
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
    fn credit(&mut self, id: u64, amount: u64) -> Result<()>;
    fn debit(&mut self, id: u64, amount: u64) -> Result<()>;
    fn bank_credit(&mut self, amount: u64) -> Result<()>;
    fn bank_debit(&mut self, amount: u64) -> Result<()>;
    fn set_auction_reserve(&mut self, total: u64) -> Result<()>;
    fn set_pos_assets(&mut self, total: u64) -> Result<()>;
}
struct ActionStage<'a> {
    parent: &'a mut Overlay,
    meta: Meta,
    updates: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    accounts: BTreeMap<u64, Account>,
}
impl<'a> ActionStage<'a> {
    fn new(parent: &'a mut Overlay) -> Self {
        Self {
            meta: parent.meta.clone(),
            parent,
            updates: BTreeMap::new(),
            accounts: BTreeMap::new(),
        }
    }
    fn commit(self) {
        self.parent.meta = self.meta;
        self.parent.updates.extend(self.updates);
        self.parent.accounts.extend(self.accounts);
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
                b"registration/"
            ]
            .iter()
            .any(|prefix| key.starts_with(prefix)),
            "extension attempted reserved namespace"
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
    fn set_auction_reserve(&mut self, total: u64) -> Result<()> {
        self.meta.auction_reserve_total = total;
        Ok(())
    }
    fn set_pos_assets(&mut self, total: u64) -> Result<()> {
        self.meta.pos_assets_total = total;
        Ok(())
    }
}

struct Overlay {
    snapshot: Snapshot,
    meta: Meta,
    updates: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    accounts: BTreeMap<u64, Account>,
    original: BTreeMap<u64, Account>,
    recoveries: BTreeMap<u64, Vec<RecoveryCase>>,
    validators: Vec<pos::Validator>,
    validator_updates: Vec<pos::Validator>,
    history_append: Option<history::Append>,
}
impl Overlay {
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
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.updates.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.snapshot.get(key),
        }
    }
    fn required(&mut self, id: u64) -> Result<Account> {
        if let Some(row) = self.accounts.get(&id) {
            return Ok(row.clone());
        }
        let bytes = self
            .get(&account_key(id))?
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
        self.original.insert(id, row.clone());
        self.accounts.insert(id, row.clone());
        Ok(row)
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
    fn apply(&mut self, raw: &[u8]) -> Result<()> {
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
        let critical: pos::Summary = canonical_decode(
            &self
                .get(crate::pos_adapter::SUMMARY_KEY)?
                .ok_or_else(|| anyhow!("missing PoS summary"))?,
        )?;
        ensure!(
            !critical.safety_hold || matches!(kind, 17 | 18 | 20 | 40),
            "critical validator hold permits only headers, equivocation evidence, or existing-account self collateral repair"
        );
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
            if !public {
                valid_public_key(&action.public_key)?;
                action.verify_signer()?;
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
            }
            let mut stage = ActionStage::new(self);
            match kind {
                5 | 6 | 7 | 17 | 18 | 19 | 20 | 21 | 23 | 24 => {
                    crate::pos_adapter::apply(&mut stage, &action)?
                }
                40 | 41 => crate::bitcoin_adapter::apply(&mut stage, &action)?,
                42 => crate::auction::apply(&mut stage, &action)?,
                44 => crate::registration_adapter::apply(&mut stage, &action)?,
                60..=63 => crate::treasury_adapter::apply(&mut stage, &action)?,
                _ => anyhow::bail!("unsupported action"),
            }
            if !public {
                let fee = if matches!(kind, 41 | 42) {
                    0
                } else {
                    ledger::FEE_MICROS
                };
                stage.debit(action.from, fee)?;
                stage.bank_credit(fee)?;
                let mut owner = stage.account(action.from)?;
                owner.nonce = action.nonce;
                stage.accounts.insert(owner.id, owner);
            }
            stage.commit();
            Ok(())
        } else {
            self.apply_legacy(raw)
        }
    }
    fn apply_legacy(&mut self, raw: &[u8]) -> Result<()> {
        // V0 is intentionally not accepted on the v2 network.
        let action = ledger::decode_action(raw)?;
        ensure!(action.network_id == self.meta.network_id, "wrong network");
        if self.meta.protocol_version == 4
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
                ensure!(
                    p.delay_seconds
                        .checked_mul(ledger::MICROS_PER_SECOND)
                        .is_some_and(|delay| delay >= self.meta.config.recovery_min_delay_micros),
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
        ledger::apply_tx_with_recovery_window(
            &mut view,
            raw,
            self.meta.config.recovery_approval_window_micros,
        )?;
        ensure!(
            view.name_commits.len() <= MAX_COMMITS && view.auction_bids.len() <= MAX_BIDS,
            "v2 bounded metadata capacity"
        );
        // All postchecks occur before publishing staged state to the overlay.
        let mut next_meta = self.meta.clone();
        next_meta.absorb(&view);
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
        for row in view.accounts {
            self.accounts.insert(row.id, row);
        }
        for row in new_accounts {
            self.updates
                .insert(name_key(&row.name), Some(index_bytes(row.id)?));
            self.updates
                .insert(pubkey_key(&row.public_key)?, Some(index_bytes(row.id)?));
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
    fn finish(mut self, txcount: usize) -> Result<Prepared> {
        if self.meta.height > 0 {
            let mut stage = ActionStage::new(&mut self);
            let changes = crate::pos_adapter::finalize(&mut stage)?;
            stage.commit();
            self.validators = changes.validators;
            self.validator_updates = changes.updates;
        }

        let mut old_liquid = 0u64;
        let mut old_unbond = 0u64;
        let mut old_shares = vec![0u64; self.meta.pools.len()];
        let mut new_liquid = 0u64;
        let mut new_unbond = 0u64;
        let mut new_shares = vec![0u64; self.meta.pools.len()];
        let mut changed_accounts = 0;
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
            self.updates.insert(account_key(row.id), Some(bytes));
            for old in previous.into_iter().flat_map(|r| &r.unbonding) {
                unbond_index_checks += 1;
                ensure!(
                    self.snapshot.get(&unbond_key(old.id))? == Some(index_bytes(row.id)?),
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
                        self.snapshot.get(&unbond_key(new.id))?.is_none()
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
            if self.snapshot.get(&key)? != value {
                self.updates.insert(key, value);
            }
        }
        self.meta.validate()?;
        let metadata = serde_json::to_vec(&self.meta)?;
        self.updates
            .insert(META_KEY.to_vec(), Some(metadata.clone()));
        let touched_accounts = self.accounts.len();
        let mut tree = self
            .snapshot
            .prepare_updates(self.meta.height as u64, self.updates.into_iter().collect())?;
        tree.set_head_metadata(metadata, [0; 32])?;
        Ok(Prepared {
            root: tree.root,
            meta: self.meta,
            txcount,
            touched_accounts,
            changed_accounts,
            unbond_index_checks,
            updated_rows: tree.updated_rows(),
            new_nodes: tree.new_nodes(),
            validators: self.validators,
            validator_updates: self.validator_updates,
            history_append: self.history_append,
            tree,
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
fn valid_public_key(text: &str) -> Result<()> {
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
