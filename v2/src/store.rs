//! Atomic, incremental authenticated storage. Every reader pins a redb MVCC
//! snapshot. Head, raw rows, versioned values, JMT nodes, and pruning queues
//! publish together in one durable transaction; prepared states remain private.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{self, Read, Write},
    ops::Bound,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

mod audit;
pub use audit::*;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use jmt::{
    JellyfishMerkleTree, KeyHash, OwnedValue, Version,
    storage::{LeafNode, Node, NodeKey, TreeReader, TreeUpdateBatch},
};
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    StorageBackend, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize};
use sha2_10::Sha256;

use crate::proof::{MAX_KEY_BYTES, MAX_VALUE_BYTES, ProofBundle, ProofEntry, key_hash};

const INFO: TableDefinition<&str, &[u8]> = TableDefinition::new("v2_info");
const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("v2_current_rows");
const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("v2_jmt_nodes");
const VALUES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("v2_jmt_values");
const ROOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("v2_roots");
const STALE_NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("v2_stale_nodes");
const STALE_VALUES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("v2_stale_values");
const META_KEY: &[u8] = b"meta";
const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;
const FORMAT_MAGIC: &[u8] = b"TCDEVNET-STORE-V2\0JMT0.12-SHA256-REDB4";
const FILE_PREFIX_BYTES: u64 = 4096;

fn file_prefix() -> [u8; 4096] {
    let mut prefix = [0; 4096];
    prefix[..FORMAT_MAGIC.len()].copy_from_slice(FORMAT_MAGIC);
    prefix[64..72].copy_from_slice(&2u64.to_be_bytes());
    prefix
}

pub type Update = (Vec<u8>, Option<Vec<u8>>);
pub type Row = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub version: u64,
    pub root: [u8; 32],
    pub request_fingerprint: [u8; 32],
    pub metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct StoreOptions {
    /// Queryable proof roots including the current root. Physical reclamation
    /// is performed by bounded background maintenance, never inside commit.
    pub retained_versions: u64,
    pub prune_batch: usize,
    pub max_updates: usize,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            retained_versions: 128,
            prune_batch: 10_000,
            max_updates: 100_000,
        }
    }
}

pub struct Store {
    db: Database,
    options: StoreOptions,
}
pub struct Snapshot {
    read: ReadTransaction,
    options: StoreOptions,
    head: Option<Head>,
    verified_reads: Mutex<VerifiedReadCache>,
}

const VERIFIED_READ_MAX_ENTRIES: usize = 8192;
const VERIFIED_READ_MAX_BYTES: usize = 16 * 1024 * 1024;
struct VerifiedReadCache {
    rows: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    fifo: VecDeque<Vec<u8>>,
    charged_bytes: usize,
    hits: u64,
    misses: u64,
    evictions: u64,
}
impl Default for VerifiedReadCache {
    fn default() -> Self {
        // Reserve a conservative fixed allowance for the FIFO's maximum
        // backing capacity even after it has evicted most entries.
        Self {
            rows: BTreeMap::new(),
            fifo: VecDeque::new(),
            charged_bytes: 256 * 1024,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct VerifiedReadCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub entries: usize,
    pub charged_bytes: usize,
}
impl VerifiedReadCache {
    // Both the directory and FIFO own the key; 256 bytes conservatively cover
    // map/queue entry and Vec/Option allocator overhead beyond payload bytes.
    fn charge(key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        256usize
            .checked_add(key.len().checked_mul(2)?)
            .and_then(|n| n.checked_add(value.map_or(0, <[u8]>::len)))
    }
    fn get(&mut self, key: &[u8]) -> Option<Option<Vec<u8>>> {
        match self.rows.get(key) {
            Some(value) => {
                self.hits = self.hits.saturating_add(1);
                Some(value.clone())
            }
            None => {
                self.misses = self.misses.saturating_add(1);
                None
            }
        }
    }
    fn insert(&mut self, key: &[u8], value: Option<&[u8]>) {
        if self.rows.contains_key(key) {
            return;
        }
        let Some(charge) = Self::charge(key, value) else {
            return;
        };
        if key.len() > MAX_KEY_BYTES || charge > VERIFIED_READ_MAX_BYTES {
            return;
        }
        while self.rows.len() >= VERIFIED_READ_MAX_ENTRIES
            || self.charged_bytes > VERIFIED_READ_MAX_BYTES - charge
        {
            let Some(oldest) = self.fifo.pop_front() else {
                return;
            };
            if let Some(value) = self.rows.remove(&oldest) {
                self.charged_bytes -=
                    Self::charge(&oldest, value.as_deref()).expect("stored cache charge");
                self.evictions = self.evictions.saturating_add(1);
            }
        }
        self.rows.insert(key.to_vec(), value.map(<[u8]>::to_vec));
        self.fifo.push_back(key.to_vec());
        self.charged_bytes += charge;
    }
    fn stats(&self) -> VerifiedReadCacheStats {
        VerifiedReadCacheStats {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
            entries: self.rows.len(),
            charged_bytes: self.charged_bytes,
        }
    }
}

pub struct PreparedTree {
    pub version: u64,
    pub root: [u8; 32],
    pub parent: Option<Head>,
    expected_parent: Option<Head>,
    updates: Vec<Update>,
    batch: TreeUpdateBatch,
    metadata: Option<Vec<u8>>,
    fingerprint: [u8; 32],
    verified_read_cache: VerifiedReadCacheStats,
}

impl PreparedTree {
    pub fn set_head_metadata(&mut self, metadata: Vec<u8>, fingerprint: [u8; 32]) -> Result<()> {
        let authenticated = self
            .updates
            .iter()
            .find(|(k, _)| k.as_slice() == META_KEY)
            .and_then(|(_, v)| v.as_deref());
        ensure!(
            authenticated == Some(metadata.as_slice()),
            "head metadata must equal authenticated meta row"
        );
        self.metadata = Some(metadata);
        self.fingerprint = fingerprint;
        Ok(())
    }

    pub fn new_nodes(&self) -> usize {
        self.batch.node_batch.nodes().len()
    }
    pub fn updated_rows(&self) -> usize {
        self.updates.len()
    }

    pub fn verified_read_cache_stats(&self) -> VerifiedReadCacheStats {
        self.verified_read_cache
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PruneStats {
    pub nodes: usize,
    pub values: usize,
    pub roots: usize,
    pub elapsed_ms: u64,
    pub budget_exhausted: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct GcBudget {
    pub max_nodes: usize,
    pub max_values: usize,
    pub max_roots: usize,
    /// A cooperative work deadline, excluding lock acquisition and final fsync.
    /// Individual storage I/O can exceed it; row limits are the hard bound.
    pub max_millis: u64,
}

impl Default for GcBudget {
    fn default() -> Self {
        Self {
            max_nodes: 128,
            max_values: 128,
            max_roots: 16,
            max_millis: 10,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GcPolicy {
    pub high_water_items: u64,
    pub max_lag_versions: u64,
}
impl Default for GcPolicy {
    fn default() -> Self {
        Self {
            high_water_items: 1_000_000,
            max_lag_versions: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct GcStatus {
    pub queued_items: u64,
    pub physical_root_records: u64,
    pub oldest_queryable_version: u64,
    pub oldest_eligible_version: Option<u64>,
    pub lag_versions: u64,
    pub eligible_work_pending: bool,
    /// Health / local transaction admission signal only. Consensus execution
    /// and acceptance must never depend on this machine-local condition.
    pub pressure: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct StoreStats {
    pub current_rows: u64,
    pub tree_nodes: u64,
    pub versioned_values: u64,
    pub retained_root_records: u64,
    pub queued_stale_nodes: u64,
    pub queued_stale_values: u64,
    pub oldest_queryable_version: u64,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(path, StoreOptions::default())
    }

    pub fn open_with_options(path: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        ensure!(
            options.retained_versions > 0 && options.prune_batch > 0 && options.max_updates > 0,
            "invalid store options"
        );
        let path = path.as_ref();
        let mut builder = Database::builder();
        builder.set_cache_size(64 * 1024 * 1024);
        let db = if path.try_exists()? {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?;
            let mut prefix = [0; 4096];
            file.read_exact(&mut prefix).context(
                "v2 file prefix missing (legacy databases require an explicit migration)",
            )?;
            ensure!(
                prefix == file_prefix(),
                "v2 file prefix mismatch; refusing foreign database without mutation"
            );
            ensure!(
                file.metadata()?.len() > FILE_PREFIX_BYTES,
                "incomplete v2 file initialization"
            );
            let read_backend = OffsetBackend {
                base: redb::backends::FileBackend::new(file.try_clone()?)?,
            };
            match builder.open_read_only_with_backend(read_backend) {
                Ok(preflight) => verify_format(&preflight.begin_read()?)?,
                // The prefix already identifies this as our database. redb may
                // now repair its body; foreign files never reach this branch.
                Err(redb::DatabaseError::RepairAborted) => {}
                Err(error) => return Err(error).context("v2 read-only body preflight"),
            }
            let backend = OffsetBackend {
                base: redb::backends::FileBackend::new(file)?,
            };
            let db = builder
                .create_with_backend(backend)
                .context("open v2 database (one writer process only)")?;
            verify_format(&db.begin_read()?)?;
            db
        } else {
            // Never claim a file raced into existence between exists/create.
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(&file_prefix())?;
            file.sync_all()?;
            let db = builder
                .create_with_backend(OffsetBackend {
                    base: redb::backends::FileBackend::new(file)?,
                })
                .context("create v2 database")?;
            let mut write = db.begin_write()?;
            write.set_durability(redb::Durability::Immediate)?;
            {
                write.open_table(INFO)?.insert("format", FORMAT_MAGIC)?;
                write.open_table(ROWS)?;
                write.open_table(NODES)?;
                write.open_table(VALUES)?;
                write.open_table(ROOTS)?;
                write.open_table(STALE_NODES)?;
                write.open_table(STALE_VALUES)?;
            }
            write.commit()?;
            db
        };
        let store = Self { db, options };
        // Reject a damaged or incompletely initialized database on reopen.
        store.snapshot()?.validate_head()?;
        Ok(store)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let read = self.db.begin_read()?;
        let head = read
            .open_table(INFO)?
            .get("head")?
            .map(|v| serde_json::from_slice::<Head>(v.value()))
            .transpose()?;
        Ok(Snapshot {
            read,
            options: self.options,
            head,
            verified_reads: Mutex::new(VerifiedReadCache::default()),
        })
    }
    pub fn head(&self) -> Result<Option<Head>> {
        self.snapshot()?.head()
    }
    pub fn genesis_head(&self) -> Result<Option<Head>> {
        self.snapshot()?.genesis_head()
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.snapshot()?.get(key)
    }
    pub fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<Row>> {
        self.snapshot()?.scan_prefix(prefix, limit)
    }
    pub fn proof(&self, key: &[u8], version: u64) -> Result<ProofEntry> {
        self.snapshot()?.proof(key, version)
    }
    pub fn prepare_updates(&self, version: u64, updates: Vec<Update>) -> Result<PreparedTree> {
        self.snapshot()?.prepare_updates(version, updates)
    }

    pub fn commit(&self, prepared: PreparedTree) -> Result<Head> {
        self.commit_inner(prepared, || Ok(()))
    }

    fn commit_inner(
        &self,
        prepared: PreparedTree,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<Head> {
        let metadata = prepared
            .metadata
            .context("prepared head metadata was not set")?;
        let root_node = prepared
            .batch
            .node_batch
            .nodes()
            .iter()
            .find(|(key, _)| key.version() == prepared.version && key.nibble_path().is_empty())
            .context("prepared batch has no root")?
            .1;
        let actual_root = match root_node {
            Node::Internal(node) => node.hash::<Sha256>(),
            Node::Leaf(node) => node.hash::<Sha256>(),
            Node::Null => JellyfishMerkleTree::<Snapshot, Sha256>::EMPTY_ROOT.0,
        };
        ensure!(prepared.root == actual_root, "prepared root was modified");
        let mut write = self.db.begin_write()?;
        write.set_durability(redb::Durability::Immediate)?;
        {
            let info = write.open_table(INFO)?;
            let current = info
                .get("head")?
                .map(|v| serde_json::from_slice::<Head>(v.value()))
                .transpose()?;
            ensure!(
                prepared.parent == prepared.expected_parent,
                "prepared parent was modified"
            );
            ensure!(
                current == prepared.expected_parent,
                "stale prepared state: committed parent changed"
            );
        }
        let head = Head {
            version: prepared.version,
            root: prepared.root,
            request_fingerprint: prepared.fingerprint,
            metadata,
        };
        {
            let mut nodes = write.open_table(NODES)?;
            for (key, node) in prepared.batch.node_batch.nodes() {
                let key_bytes = borsh::to_vec(key)?;
                let node_bytes = borsh::to_vec(node)?;
                ensure!(
                    nodes.get(key_bytes.as_slice())?.is_none(),
                    "JMT node version already exists"
                );
                nodes.insert(key_bytes.as_slice(), node_bytes.as_slice())?;
            }
        }
        {
            let mut values = write.open_table(VALUES)?;
            let mut stale = write.open_table(STALE_VALUES)?;
            for ((version, hash), value) in prepared.batch.node_batch.values() {
                let key = value_key(*hash, *version);
                let previous = values
                    .range(hash.0.to_vec().as_slice()..=key.as_slice())?
                    .next_back()
                    .transpose()?
                    .map(|(k, _)| k.value().to_vec());
                if let Some(previous) = previous {
                    ensure!(
                        previous.len() == 40 && previous[..32] == hash.0,
                        "corrupt MVCC value key"
                    );
                    let mut index = version.to_be_bytes().to_vec();
                    index.extend_from_slice(&previous);
                    stale.insert(index.as_slice(), &[][..])?;
                }
                let encoded = encode_value(value.as_deref());
                ensure!(
                    values.get(key.as_slice())?.is_none(),
                    "JMT value version already exists"
                );
                values.insert(key.as_slice(), encoded.as_slice())?;
                // Once no retained root predates this deletion, the key has no
                // leaf and its final tombstone can also be reclaimed. Without
                // this entry, churn across unique keys leaks one row per key.
                if value.is_none() {
                    let mut index = version.to_be_bytes().to_vec();
                    index.extend_from_slice(&key);
                    stale.insert(index.as_slice(), &[][..])?;
                }
            }
        }
        {
            let mut rows = write.open_table(ROWS)?;
            for (key, value) in &prepared.updates {
                match value {
                    Some(value) => {
                        rows.insert(key.as_slice(), value.as_slice())?;
                    }
                    None => {
                        rows.remove(key.as_slice())?;
                    }
                }
            }
            let mut stale = write.open_table(STALE_NODES)?;
            for entry in &prepared.batch.stale_node_index_batch {
                let mut index = entry.stale_since_version.to_be_bytes().to_vec();
                let node_key = borsh::to_vec(&entry.node_key)?;
                index.extend_from_slice(&node_key);
                stale.insert(index.as_slice(), node_key.as_slice())?;
            }
            let bytes = serde_json::to_vec(&head)?;
            write
                .open_table(ROOTS)?
                .insert(head.version, bytes.as_slice())?;
            let mut info = write.open_table(INFO)?;
            info.insert("head", bytes.as_slice())?;
            if head.version == 0 {
                info.insert("genesis_head", bytes.as_slice())?;
            }
            let previous_oldest = info
                .get("oldest")?
                .map(|v| {
                    let bytes: [u8; 8] = v.value().try_into().context("corrupt pruning floor")?;
                    Ok::<_, anyhow::Error>(u64::from_be_bytes(bytes))
                })
                .transpose()?
                .unwrap_or(0);
            let oldest = head
                .version
                .saturating_sub(self.options.retained_versions - 1)
                .max(previous_oldest);
            info.insert("oldest", oldest.to_be_bytes().as_slice())?;
        }
        // Retiring an old bulk fixture version can require tens of thousands
        // of random deletes. Physical GC is deliberately a separate bounded
        // transaction; no old-history work runs on the consensus commit path.
        before_commit()?;
        // redb defaults to immediate durability. Never weaken this to eventual.
        write.commit()?;
        Ok(head)
    }

    pub fn prune(&self) -> Result<PruneStats> {
        self.maintain_gc(GcBudget {
            max_nodes: self.options.prune_batch.min(128),
            max_values: self.options.prune_batch.min(128),
            max_roots: self.options.prune_batch.min(16),
            ..GcBudget::default()
        })
    }

    pub fn maintain_gc(&self, budget: GcBudget) -> Result<PruneStats> {
        self.maintain_gc_inner(budget, || Ok(()))
    }

    fn maintain_gc_inner(
        &self,
        budget: GcBudget,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<PruneStats> {
        ensure!(
            budget.max_nodes <= 4096
                && budget.max_values <= 4096
                && budget.max_roots <= 128
                && (1..=100).contains(&budget.max_millis),
            "maintenance budget exceeds hard bounds"
        );
        ensure!(
            budget.max_nodes + budget.max_values + budget.max_roots > 0,
            "empty maintenance budget"
        );
        let started = Instant::now();
        let mut write = self.db.begin_write()?;
        write.set_durability(redb::Durability::Immediate)?;
        let mut result = prune_transaction(&write, budget)?;
        before_commit()?;
        write.commit()?;
        result.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(result)
    }

    pub fn gc_status(&self, policy: GcPolicy) -> Result<GcStatus> {
        self.snapshot()?.gc_status(policy)
    }

    pub fn stats(&self) -> Result<StoreStats> {
        self.snapshot()?.stats()
    }
}

fn verify_format(read: &ReadTransaction) -> Result<()> {
    ensure!(
        read.list_tables()?.count() == 7 && read.list_multimap_tables()?.count() == 0,
        "not an isolated v2 database"
    );
    let info = read
        .open_table(INFO)
        .context("database is not v2 (legacy databases require an explicit migration)")?;
    ensure!(
        info.get("format")?
            .is_some_and(|v| v.value() == FORMAT_MAGIC),
        "v2 database format magic mismatch"
    );
    read.open_table(ROWS)?;
    read.open_table(NODES)?;
    read.open_table(VALUES)?;
    read.open_table(ROOTS)?;
    read.open_table(STALE_NODES)?;
    read.open_table(STALE_VALUES)?;
    Ok(())
}

/// redb operates on the body after an immutable 4KiB application format prefix.
/// FileBackend keeps its native OS locking and durability; only data offsets and
/// lengths are translated. No redb write, repair, or truncation can touch prefix.
#[derive(Debug)]
struct OffsetBackend {
    base: redb::backends::FileBackend,
}

impl OffsetBackend {
    fn absolute(offset: u64, length: usize) -> io::Result<u64> {
        let start = offset
            .checked_add(FILE_PREFIX_BYTES)
            .ok_or_else(|| io::Error::other("v2 body offset overflow"))?;
        start
            .checked_add(length as u64)
            .ok_or_else(|| io::Error::other("v2 body range overflow"))?;
        Ok(start)
    }
}

impl StorageBackend for OffsetBackend {
    fn len(&self) -> io::Result<u64> {
        self.base
            .len()?
            .checked_sub(FILE_PREFIX_BYTES)
            .ok_or_else(|| io::Error::other("v2 file shorter than format prefix"))
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.base.read(Self::absolute(offset, out.len())?, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.base.set_len(Self::absolute(len, 0)?)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.base.sync_data()
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.base.write(Self::absolute(offset, data.len())?, data)
    }
    fn close(&self) -> io::Result<()> {
        self.base.close()
    }
    fn try_lock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.base.try_lock_range(start, end)
    }
    fn try_lock_shared_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.base.try_lock_shared_range(start, end)
    }
    fn lock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<(), redb::BackendError> {
        self.base.lock_range(start, end)
    }
    fn lock_shared_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<(), redb::BackendError> {
        self.base.lock_shared_range(start, end)
    }
    fn unlock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<(), redb::BackendError> {
        self.base.unlock_range(start, end)
    }
    fn query_lock_range(
        &self,
        start: Bound<u64>,
        end: Bound<u64>,
    ) -> std::result::Result<bool, redb::BackendError> {
        self.base.query_lock_range(start, end)
    }
}
impl Snapshot {
    pub fn gc_status(&self, policy: GcPolicy) -> Result<GcStatus> {
        ensure!(
            policy.high_water_items > 0 && policy.max_lag_versions > 0,
            "invalid GC health policy"
        );
        let oldest = self.oldest()?;
        let roots = self.read.open_table(ROOTS)?;
        let physical_root_records = roots.len()?;
        let logical = self
            .head
            .as_ref()
            .map_or(0, |h| h.version.saturating_sub(oldest).saturating_add(1));
        let mut candidates = Vec::with_capacity(3);
        let mut queued = physical_root_records.saturating_sub(logical);
        for definition in [STALE_NODES, STALE_VALUES] {
            let table = self.read.open_table(definition)?;
            queued = queued
                .checked_add(table.len()?)
                .context("GC queue count overflow")?;
            if let Some(entry) = table.iter()?.next() {
                let (key, _) = entry?;
                ensure!(key.value().len() >= 8, "corrupt retirement index");
                let version = u64::from_be_bytes(key.value()[..8].try_into()?);
                if version <= oldest {
                    candidates.push(version);
                }
            }
        }
        if let Some(entry) = roots.iter()?.next() {
            let (version, _) = entry?;
            if version.value() < oldest {
                candidates.push(version.value());
            }
        }
        let oldest_eligible_version = candidates.into_iter().min();
        let lag_versions = oldest_eligible_version.map_or(0, |v| oldest.saturating_sub(v));
        let eligible_work_pending = oldest_eligible_version.is_some();
        Ok(GcStatus {
            queued_items: queued,
            physical_root_records,
            oldest_queryable_version: oldest,
            oldest_eligible_version,
            lag_versions,
            eligible_work_pending,
            pressure: eligible_work_pending
                && (queued >= policy.high_water_items || lag_versions >= policy.max_lag_versions),
        })
    }

    pub fn stats(&self) -> Result<StoreStats> {
        Ok(StoreStats {
            current_rows: self.read.open_table(ROWS)?.len()?,
            tree_nodes: self.read.open_table(NODES)?.len()?,
            versioned_values: self.read.open_table(VALUES)?.len()?,
            retained_root_records: self.read.open_table(ROOTS)?.len()?,
            queued_stale_nodes: self.read.open_table(STALE_NODES)?.len()?,
            queued_stale_values: self.read.open_table(STALE_VALUES)?.len()?,
            oldest_queryable_version: self.oldest()?,
        })
    }
    pub fn head(&self) -> Result<Option<Head>> {
        Ok(self.head.clone())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(cached) = self
            .verified_reads
            .lock()
            .map_err(|_| anyhow::anyhow!("verified read cache poisoned"))?
            .get(key)
        {
            return Ok(cached);
        }
        let raw = self
            .read
            .open_table(ROWS)?
            .get(key)?
            .map(|v| v.value().to_vec());
        let Some(head) = &self.head else {
            ensure!(raw.is_none(), "orphan row without head");
            return Ok(None);
        };
        let tree = JellyfishMerkleTree::<_, Sha256>::new(self);
        let (authenticated, proof) = tree.get_with_proof(key_hash(key), head.version)?;
        proof.verify(
            jmt::RootHash(head.root),
            key_hash(key),
            authenticated.as_deref(),
        )?;
        ensure!(
            raw == authenticated,
            "raw row is detached from authenticated state"
        );
        self.verified_reads
            .lock()
            .map_err(|_| anyhow::anyhow!("verified read cache poisoned"))?
            .insert(key, authenticated.as_deref());
        Ok(authenticated)
    }

    pub fn verified_read_cache_stats(&self) -> Result<VerifiedReadCacheStats> {
        Ok(self
            .verified_reads
            .lock()
            .map_err(|_| anyhow::anyhow!("verified read cache poisoned"))?
            .stats())
    }

    pub fn genesis_head(&self) -> Result<Option<Head>> {
        let table = self.read.open_table(INFO)?;
        table
            .get("genesis_head")?
            .map(|v| serde_json::from_slice(v.value()).context("decode initial head"))
            .transpose()
    }

    pub fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Result<Vec<Row>> {
        ensure!(
            limit <= self.options.max_updates,
            "prefix read limit exceeds store bound"
        );
        let table = self.read.open_table(ROWS)?;
        let mut rows = Vec::new();
        for entry in table.range(prefix..)? {
            let (key, value) = entry?;
            if !key.value().starts_with(prefix) || rows.len() == limit {
                break;
            }
            let authenticated = self
                .get(key.value())?
                .context("row missing from authenticated state")?;
            ensure!(
                authenticated == value.value(),
                "scan row is detached from authenticated state"
            );
            rows.push((key.value().to_vec(), authenticated));
        }
        Ok(rows)
    }

    pub fn for_each_prefix(
        &self,
        prefix: &[u8],
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        let table = self.read.open_table(ROWS)?;
        for entry in table.range(prefix..)? {
            let (key, value) = entry?;
            if !key.value().starts_with(prefix) {
                break;
            }
            let authenticated = self
                .get(key.value())?
                .context("row missing from authenticated state")?;
            ensure!(
                authenticated == value.value(),
                "scan row is detached from authenticated state"
            );
            visitor(key.value(), &authenticated)?;
        }
        Ok(())
    }

    pub fn prepare_updates(&self, version: u64, updates: Vec<Update>) -> Result<PreparedTree> {
        ensure!(
            !updates.is_empty() && updates.len() <= self.options.max_updates,
            "invalid incremental batch size"
        );
        let parent = self.head()?;
        let next = parent
            .as_ref()
            .map(|h| h.version.checked_add(1).context("version overflow"))
            .transpose()?
            .unwrap_or(0);
        ensure!(version == next, "nonconsecutive storage version");
        let mut keys = BTreeSet::new();
        let mut hashed = BTreeMap::new();
        let mut batch_bytes = 0usize;
        for (key, value) in &updates {
            ensure!(
                !key.is_empty() && key.len() <= MAX_KEY_BYTES,
                "invalid key length"
            );
            ensure!(
                value.as_ref().is_none_or(|v| v.len() <= MAX_VALUE_BYTES),
                "row too large"
            );
            batch_bytes = batch_bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.as_ref().map_or(0, Vec::len)))
                .context("batch size overflow")?;
            ensure!(
                batch_bytes <= MAX_BATCH_BYTES,
                "incremental batch exceeds memory bound"
            );
            ensure!(keys.insert(key), "duplicate update key");
            // JMT's TreeReader is a trusted storage interface. Authenticate
            // every old update path ourselves, including absence for freshly
            // allocated keys, before any trusted-reader tree mutation. This
            // prevents a damaged off-meta subtree from entering a new root.
            self.get(key)?;
            ensure!(
                hashed.insert(key_hash(key), value.clone()).is_none(),
                "hashed key collision"
            );
        }
        ensure!(
            updates
                .iter()
                .any(|(k, v)| k.as_slice() == META_KEY && v.is_some()),
            "each version requires authenticated meta row"
        );
        let tree = JellyfishMerkleTree::<_, Sha256>::new(self);
        let (root, batch) = tree.put_value_set(hashed, version)?;
        Ok(PreparedTree {
            version,
            root: root.0,
            expected_parent: parent.clone(),
            parent,
            updates,
            batch,
            metadata: None,
            fingerprint: [0; 32],
            verified_read_cache: self.verified_read_cache_stats()?,
        })
    }

    pub fn proof(&self, key: &[u8], version: u64) -> Result<ProofEntry> {
        ensure!(
            !key.is_empty() && key.len() <= MAX_KEY_BYTES,
            "invalid proof key length"
        );
        let head = self.version_head(version)?;
        let tree = JellyfishMerkleTree::<_, Sha256>::new(self);
        let (value, proof) = tree.get_with_proof(key_hash(key), version)?;
        proof.verify(jmt::RootHash(head.root), key_hash(key), value.as_deref())?;
        Ok(ProofEntry {
            key_hex: hex::encode(key),
            value_b64: value.map(|v| STANDARD.encode(v)),
            proof,
        })
    }

    pub fn proof_bundle(&self, keys: &[Vec<u8>], version: u64) -> Result<ProofBundle> {
        ensure!(
            !keys.is_empty() && keys.len() <= 32,
            "invalid proof bundle size"
        );
        let head = self.version_head(version)?;
        Ok(ProofBundle {
            version,
            root: head.root,
            entries: keys
                .iter()
                .map(|k| self.proof(k, version))
                .collect::<Result<_>>()?,
        })
    }

    pub fn version_head(&self, version: u64) -> Result<Head> {
        let oldest = self.oldest()?;
        ensure!(version >= oldest, "proof version pruned");
        let roots = self.read.open_table(ROOTS)?;
        let bytes = roots.get(version)?.context("unknown proof version")?;
        let head: Head = serde_json::from_slice(bytes.value())?;
        ensure!(head.version == version, "corrupt root version");
        let actual = JellyfishMerkleTree::<_, Sha256>::new(self).get_root_hash(version)?;
        ensure!(actual.0 == head.root, "stored root does not match JMT root");
        Ok(head)
    }

    fn oldest(&self) -> Result<u64> {
        self.read
            .open_table(INFO)?
            .get("oldest")?
            .map(|v| {
                let bytes: [u8; 8] = v.value().try_into().context("corrupt pruning floor")?;
                Ok(u64::from_be_bytes(bytes))
            })
            .transpose()
            .map(|v| v.unwrap_or(0))
    }

    fn validate_head(&self) -> Result<()> {
        if let Some(head) = self.head()? {
            let genesis = self
                .genesis_head()?
                .context("missing immutable initial head")?;
            ensure!(
                genesis.version == 0 && (head.version != 0 || genesis == head),
                "invalid immutable initial head"
            );
            ensure!(
                self.version_head(head.version)? == head,
                "head does not match root record"
            );
            ensure!(
                self.get(META_KEY)?.as_deref() == Some(head.metadata.as_slice()),
                "head does not match metadata row"
            );
            let (value, proof) = JellyfishMerkleTree::<_, Sha256>::new(self)
                .get_with_proof(key_hash(META_KEY), head.version)?;
            ensure!(
                value.as_deref() == Some(head.metadata.as_slice()),
                "metadata row does not match JMT value"
            );
            proof.verify_existence(jmt::RootHash(head.root), key_hash(META_KEY), &head.metadata)?;
        } else {
            ensure!(
                self.read.open_table(ROWS)?.is_empty()?
                    && self.read.open_table(NODES)?.is_empty()?
                    && self.read.open_table(VALUES)?.is_empty()?
                    && self.read.open_table(ROOTS)?.is_empty()?
                    && self.read.open_table(STALE_NODES)?.is_empty()?
                    && self.read.open_table(STALE_VALUES)?.is_empty()?
                    && self.read.open_table(INFO)?.len()? == 1,
                "orphan state without head"
            );
        }
        Ok(())
    }
}

impl TreeReader for Snapshot {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key = borsh::to_vec(node_key)?;
        self.read
            .open_table(NODES)?
            .get(key.as_slice())?
            .map(|v| borsh::from_slice(v.value()).context("decode JMT node"))
            .transpose()
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let key = value_key(key_hash, max_version);
        let table = self.read.open_table(VALUES)?;
        let lower = key_hash.0.to_vec();
        match table
            .range(lower.as_slice()..=key.as_slice())?
            .next_back()
            .transpose()?
        {
            None => Ok(None),
            Some((stored_key, value)) => {
                ensure!(
                    stored_key.value().len() == 40 && stored_key.value()[..32] == key_hash.0,
                    "corrupt MVCC key"
                );
                decode_value(value.value())
            }
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        bail!("snapshot restoration is not supported by this store")
    }
}

fn value_key(hash: KeyHash, version: u64) -> Vec<u8> {
    let mut key = hash.0.to_vec();
    key.extend_from_slice(&version.to_be_bytes());
    key
}

fn encode_value(value: Option<&[u8]>) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut bytes = Vec::with_capacity(value.len() + 1);
            bytes.push(1);
            bytes.extend_from_slice(value);
            bytes
        }
    }
}

fn decode_value(value: &[u8]) -> Result<Option<Vec<u8>>> {
    match value {
        [0] => Ok(None),
        [1, rest @ ..] => Ok(Some(rest.to_vec())),
        _ => bail!("corrupt MVCC value"),
    }
}

fn prune_transaction(write: &WriteTransaction, budget: GcBudget) -> Result<PruneStats> {
    let (oldest, start_kind) = {
        let info = write.open_table(INFO)?;
        let Some(floor) = info.get("oldest")? else {
            return Ok(PruneStats::default());
        };
        let oldest =
            u64::from_be_bytes(floor.value().try_into().context("invalid oldest version")?);
        let kind = info
            .get("gc_next_kind")?
            .map(|v| {
                ensure!(
                    v.value().len() == 1 && v.value()[0] < 3,
                    "corrupt GC scheduling cursor"
                );
                Ok::<_, anyhow::Error>(v.value()[0] as usize)
            })
            .transpose()?
            .unwrap_or(0);
        (oldest, kind)
    };
    let started = Instant::now();
    let deadline = Duration::from_millis(budget.max_millis);
    let mut stats = PruneStats::default();
    for offset in 0..3 {
        let kind = (start_kind + offset) % 3;
        let quota = [budget.max_nodes, budget.max_values, budget.max_roots][kind];
        if quota == 0 {
            continue;
        }
        let processed = stats.nodes + stats.values + stats.roots;
        if processed > 0 && started.elapsed() >= deadline {
            stats.budget_exhausted = true;
            break;
        }
        match kind {
            0 => {
                let mut stale = write.open_table(STALE_NODES)?;
                let mut nodes = write.open_table(NODES)?;
                let mut pending = Vec::new();
                for item in stale.iter()?.take(quota) {
                    let (key, value) = item?;
                    ensure!(key.value().len() >= 8, "corrupt stale node index");
                    if u64::from_be_bytes(key.value()[..8].try_into()?) > oldest {
                        break;
                    }
                    pending.push((key.value().to_vec(), value.value().to_vec()));
                    if started.elapsed() >= deadline {
                        break;
                    }
                }
                for (index, key) in pending {
                    if stats.nodes + stats.values + stats.roots > 0 && started.elapsed() >= deadline
                    {
                        stats.budget_exhausted = true;
                        break;
                    }
                    nodes.remove(key.as_slice())?;
                    stale.remove(index.as_slice())?;
                    stats.nodes += 1;
                }
                stats.budget_exhausted |= stats.nodes == quota;
            }
            1 => {
                let mut stale = write.open_table(STALE_VALUES)?;
                let mut values = write.open_table(VALUES)?;
                let mut pending = Vec::new();
                for item in stale.iter()?.take(quota) {
                    let (key, _) = item?;
                    ensure!(key.value().len() == 48, "corrupt stale value index");
                    if u64::from_be_bytes(key.value()[..8].try_into()?) > oldest {
                        break;
                    }
                    pending.push(key.value().to_vec());
                    if started.elapsed() >= deadline {
                        break;
                    }
                }
                for index in pending {
                    if stats.nodes + stats.values + stats.roots > 0 && started.elapsed() >= deadline
                    {
                        stats.budget_exhausted = true;
                        break;
                    }
                    values.remove(&index[8..])?;
                    stale.remove(index.as_slice())?;
                    stats.values += 1;
                }
                stats.budget_exhausted |= stats.values == quota;
            }
            2 => {
                let mut roots = write.open_table(ROOTS)?;
                let mut pending = Vec::new();
                for entry in roots.range(..oldest)?.take(quota) {
                    pending.push(entry?.0.value());
                    if started.elapsed() >= deadline {
                        break;
                    }
                }
                for version in pending {
                    if stats.nodes + stats.values + stats.roots > 0 && started.elapsed() >= deadline
                    {
                        stats.budget_exhausted = true;
                        break;
                    }
                    roots.remove(version)?;
                    stats.roots += 1;
                }
                stats.budget_exhausted |= stats.roots == quota;
            }
            _ => unreachable!(),
        }
    }
    if stats.nodes + stats.values + stats.roots > 0 {
        // Queue deletions are durable progress cursors. Rotating the first
        // queue is also durable, preventing starvation across crashes when a
        // slow node-delete consumes the entire cooperative time budget.
        write
            .open_table(INFO)?
            .insert("gc_next_kind", &[((start_kind + 1) % 3) as u8][..])?;
    }
    Ok(stats)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn commit(store: &Store, version: u64, updates: Vec<Update>) -> Head {
        let metadata = format!("{{\"height\":{version}}}").into_bytes();
        let mut updates = updates;
        updates.push((META_KEY.to_vec(), Some(metadata.clone())));
        let mut prepared = store.prepare_updates(version, updates).unwrap();
        prepared
            .set_head_metadata(metadata, [version as u8; 32])
            .unwrap();
        store.commit(prepared).unwrap()
    }

    fn drain_gc(store: &Store) {
        for _ in 0..10_000 {
            if !store
                .gc_status(GcPolicy::default())
                .unwrap()
                .eligible_work_pending
            {
                return;
            }
            store
                .maintain_gc(GcBudget {
                    max_nodes: 128,
                    max_values: 128,
                    max_roots: 16,
                    max_millis: 100,
                })
                .unwrap();
        }
        panic!("bounded maintenance did not converge");
    }

    #[test]
    fn incremental_proofs_reopen_and_stale_compare_swap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.redb");
        let store = Store::open(&path).unwrap();
        let zero = commit(
            &store,
            0,
            vec![(b"account/one".to_vec(), Some(b"10".to_vec()))],
        );
        let snapshot = store.snapshot().unwrap();
        let mut stale = snapshot
            .prepare_updates(1, vec![(META_KEY.to_vec(), Some(b"stale".to_vec()))])
            .unwrap();
        stale.set_head_metadata(b"stale".to_vec(), [3; 32]).unwrap();
        let one = commit(
            &store,
            1,
            vec![(b"account/one".to_vec(), Some(b"20".to_vec()))],
        );
        ensure_test(store.commit(stale).is_err());
        assert_eq!(snapshot.get(b"account/one").unwrap(), Some(b"10".to_vec()));
        assert_eq!(snapshot.head().unwrap(), Some(zero.clone()));
        assert_eq!(
            store
                .proof(b"account/one", 0)
                .unwrap()
                .verify(zero.root, b"account/one")
                .unwrap(),
            Some(b"10".to_vec())
        );
        let entry = store.proof(b"account/one", 1).unwrap();
        assert_eq!(
            entry.verify(one.root, b"account/one").unwrap(),
            Some(b"20".to_vec())
        );
        assert!(entry.verify(zero.root, b"account/one").is_err());
        assert!(entry.verify(one.root, b"account/two").is_err());
        assert_eq!(
            store
                .proof(b"absent", 1)
                .unwrap()
                .verify(one.root, b"absent")
                .unwrap(),
            None
        );
        drop(snapshot);
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.head().unwrap(), Some(one));
    }

    fn ensure_test(ok: bool) {
        assert!(ok);
    }

    #[test]
    fn aborted_atomic_commit_and_delete_history() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.redb");
        let store = Store::open(&path).unwrap();
        let head = commit(&store, 0, vec![(b"a".to_vec(), Some(b"initial".to_vec()))]);
        let mut prepared = store
            .prepare_updates(
                1,
                vec![
                    (META_KEY.to_vec(), Some(b"uncommitted".to_vec())),
                    (b"a".to_vec(), Some(b"changed".to_vec())),
                ],
            )
            .unwrap();
        prepared
            .set_head_metadata(b"uncommitted".to_vec(), [1; 32])
            .unwrap();
        assert!(
            store
                .commit_inner(prepared, || bail!("injected transaction abort"))
                .is_err()
        );
        assert_eq!(store.head().unwrap(), Some(head.clone()));
        assert_eq!(store.get(b"a").unwrap(), Some(b"initial".to_vec()));
        let delete = commit(&store, 1, vec![(b"a".to_vec(), None)]);
        assert_eq!(store.get(b"a").unwrap(), None);
        assert_eq!(
            store
                .proof(b"a", 0)
                .unwrap()
                .verify(head.root, b"a")
                .unwrap(),
            Some(b"initial".to_vec())
        );
        assert_eq!(
            store
                .proof(b"a", 1)
                .unwrap()
                .verify(delete.root, b"a")
                .unwrap(),
            None
        );
        drop(store);
        assert_eq!(Store::open(&path).unwrap().head().unwrap(), Some(delete));
    }

    #[test]
    fn bounded_pruning_preserves_live_shared_nodes_and_mvcc_baselines() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open_with_options(
            temp.path().join("state.redb"),
            StoreOptions {
                retained_versions: 3,
                prune_batch: 2,
                max_updates: 100,
            },
        )
        .unwrap();
        commit(
            &store,
            0,
            vec![(b"untouched".to_vec(), Some(b"baseline".to_vec()))],
        );
        for version in 1..20 {
            commit(
                &store,
                version,
                vec![(b"mutating".to_vec(), Some(version.to_be_bytes().to_vec()))],
            );
        }
        assert!(store.proof(b"untouched", 16).is_err());
        for version in 17..20 {
            let snapshot = store.snapshot().unwrap();
            let root = snapshot.version_head(version).unwrap().root;
            assert_eq!(
                snapshot
                    .proof(b"untouched", version)
                    .unwrap()
                    .verify(root, b"untouched")
                    .unwrap(),
                Some(b"baseline".to_vec())
            );
            assert_eq!(
                snapshot
                    .proof(b"mutating", version)
                    .unwrap()
                    .verify(root, b"mutating")
                    .unwrap(),
                Some(version.to_be_bytes().to_vec())
            );
        }
        assert_eq!(store.genesis_head().unwrap().unwrap().version, 0);
        for _ in 0..100 {
            let stats = store.prune().unwrap();
            assert!(stats.nodes <= 2 && stats.values <= 2 && stats.roots <= 2);
            if stats.nodes + stats.values + stats.roots == 0 {
                break;
            }
        }
        assert_eq!(store.get(b"untouched").unwrap(), Some(b"baseline".to_vec()));
    }

    #[test]
    fn bulk_retirement_never_runs_in_tiny_consensus_commit_and_maintenance_resumes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.redb");
        let options = StoreOptions {
            retained_versions: 2,
            prune_batch: 50_000,
            max_updates: 1000,
        };
        let store = Store::open_with_options(&path, options).unwrap();
        let rows: Vec<_> = (0..256)
            .map(|id| (format!("bulk/{id}").into_bytes(), Some(vec![1; 128])))
            .collect();
        let zero = commit(&store, 0, rows.clone());
        let pinned = store.snapshot().unwrap();
        commit(
            &store,
            1,
            rows.into_iter()
                .map(|(key, _)| (key, Some(vec![2; 128])))
                .collect(),
        );
        commit(&store, 2, vec![]);
        let pressure = GcPolicy {
            high_water_items: 1,
            max_lag_versions: 1,
        };
        assert!(store.gc_status(pressure).unwrap().pressure);
        let before = store.stats().unwrap();
        let mut prepared = store
            .prepare_updates(3, vec![(META_KEY.to_vec(), Some(b"tiny".to_vec()))])
            .unwrap();
        prepared
            .set_head_metadata(b"tiny".to_vec(), [3; 32])
            .unwrap();
        let new_nodes = prepared.new_nodes() as u64;
        let head = store.commit(prepared).unwrap();
        let after = store.stats().unwrap();
        assert_eq!(
            after.tree_nodes,
            before.tree_nodes + new_nodes,
            "commit must not visit or remove old history"
        );
        assert_eq!(after.versioned_values, before.versioned_values + 1);
        assert!(
            store.gc_status(pressure).unwrap().pressure,
            "local pressure never rejects a valid commit"
        );
        let budget = GcBudget {
            max_nodes: 2,
            max_values: 3,
            max_roots: 1,
            max_millis: 100,
        };
        for _ in 0..10 {
            let gc = store.maintain_gc(budget).unwrap();
            assert!(gc.nodes <= 2 && gc.values <= 3 && gc.roots <= 1);
        }
        assert_eq!(
            pinned
                .proof(b"bulk/1", 0)
                .unwrap()
                .verify(zero.root, b"bulk/1")
                .unwrap(),
            Some(vec![1; 128]),
            "old MVCC reader survives physical maintenance"
        );
        drop(pinned);
        drop(store);
        let reopened = Store::open_with_options(&path, options).unwrap();
        assert_eq!(reopened.head().unwrap(), Some(head.clone()));
        for _ in 0..4096 {
            if !reopened.gc_status(pressure).unwrap().eligible_work_pending {
                break;
            }
            let gc = reopened.maintain_gc(budget).unwrap();
            assert!(gc.nodes <= 2 && gc.values <= 3 && gc.roots <= 1);
        }
        assert!(!reopened.gc_status(pressure).unwrap().eligible_work_pending);
        assert_eq!(
            reopened
                .proof(b"bulk/1", head.version)
                .unwrap()
                .verify(head.root, b"bulk/1")
                .unwrap(),
            Some(vec![2; 128])
        );
        assert_eq!(reopened.stats().unwrap().retained_root_records, 2);
    }

    #[test]
    fn maintenance_progress_and_round_robin_cursor_abort_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open_with_options(
            temp.path().join("state.redb"),
            StoreOptions {
                retained_versions: 1,
                prune_batch: 1,
                max_updates: 100,
            },
        )
        .unwrap();
        for version in 0..8 {
            commit(
                &store,
                version,
                vec![(b"key".to_vec(), Some(vec![version as u8]))],
            );
        }
        let before = store.stats().unwrap();
        let head = store.head().unwrap();
        let budget = GcBudget {
            max_nodes: 1,
            max_values: 1,
            max_roots: 1,
            max_millis: 1,
        };
        assert!(
            store
                .maintain_gc_inner(budget, || bail!("injected maintenance transaction abort"))
                .is_err()
        );
        let after = store.stats().unwrap();
        assert_eq!(before.tree_nodes, after.tree_nodes);
        assert_eq!(before.versioned_values, after.versioned_values);
        assert_eq!(before.retained_root_records, after.retained_root_records);
        assert_eq!(store.head().unwrap(), head);
        let mut totals = [0; 3];
        for _ in 0..100 {
            if !store
                .gc_status(GcPolicy::default())
                .unwrap()
                .eligible_work_pending
            {
                break;
            }
            let gc = store.maintain_gc(budget).unwrap();
            totals[0] += gc.nodes;
            totals[1] += gc.values;
            totals[2] += gc.roots;
        }
        assert!(
            totals.iter().all(|count| *count > 0),
            "no queue starves under a one millisecond work budget"
        );
        assert!(
            !store
                .gc_status(GcPolicy::default())
                .unwrap()
                .eligible_work_pending
        );
        assert_eq!(store.head().unwrap(), head);
        assert!(
            store
                .maintain_gc(GcBudget {
                    max_nodes: 4097,
                    ..budget
                })
                .is_err()
        );
    }

    #[test]
    fn deleted_key_churn_reclaims_final_tombstones() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open_with_options(
            temp.path().join("state.redb"),
            StoreOptions {
                retained_versions: 2,
                prune_batch: 100,
                max_updates: 100,
            },
        )
        .unwrap();
        commit(&store, 0, vec![]);
        for id in 0u64..20 {
            let key = format!("ephemeral/{id}").into_bytes();
            commit(&store, id * 2 + 1, vec![(key.clone(), Some(vec![42]))]);
            commit(&store, id * 2 + 2, vec![(key, None)]);
        }
        commit(&store, 41, vec![]);
        commit(&store, 42, vec![]);
        drain_gc(&store);
        let stats = store.stats().unwrap();
        assert_eq!(stats.current_rows, 1);
        assert_eq!(stats.versioned_values, 2);
        assert!(stats.queued_stale_nodes + stats.queued_stale_values <= 2);
        let head = store.head().unwrap().unwrap();
        for id in 0..20 {
            let key = format!("ephemeral/{id}");
            assert_eq!(
                store
                    .proof(key.as_bytes(), head.version)
                    .unwrap()
                    .verify(head.root, key.as_bytes())
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn resurrection_preserves_absence_and_reclaims_obsolete_values() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open_with_options(
            temp.path().join("state.redb"),
            StoreOptions {
                retained_versions: 3,
                prune_batch: 100,
                max_updates: 100,
            },
        )
        .unwrap();
        let initial = commit(&store, 0, vec![(b"key".to_vec(), Some(b"first".to_vec()))]);
        let deletion = commit(&store, 1, vec![(b"key".to_vec(), None)]);
        let resurrection = commit(&store, 2, vec![(b"key".to_vec(), Some(b"second".to_vec()))]);
        assert_eq!(
            store
                .proof(b"key", 0)
                .unwrap()
                .verify(initial.root, b"key")
                .unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            store
                .proof(b"key", 1)
                .unwrap()
                .verify(deletion.root, b"key")
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .proof(b"key", 2)
                .unwrap()
                .verify(resurrection.root, b"key")
                .unwrap(),
            Some(b"second".to_vec())
        );
        for version in 3..8 {
            commit(&store, version, vec![]);
        }
        drain_gc(&store);
        let head = store.head().unwrap().unwrap();
        assert_eq!(
            store
                .proof(b"key", 7)
                .unwrap()
                .verify(head.root, b"key")
                .unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(store.stats().unwrap().versioned_values, 4);
    }

    #[test]
    fn rejects_invalid_batches_and_second_writer() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.redb");
        let store = Store::open(&path).unwrap();
        assert!(Store::open(&path).is_err());
        assert!(
            store
                .prepare_updates(1, vec![(META_KEY.to_vec(), Some(vec![]))])
                .is_err()
        );
        assert!(
            store
                .prepare_updates(0, vec![(b"x".to_vec(), Some(vec![]))])
                .is_err()
        );
        assert!(
            store
                .prepare_updates(
                    0,
                    vec![
                        (META_KEY.to_vec(), Some(vec![])),
                        (META_KEY.to_vec(), Some(vec![]))
                    ]
                )
                .is_err()
        );
        let mut prepared = store
            .prepare_updates(0, vec![(META_KEY.to_vec(), Some(b"valid".to_vec()))])
            .unwrap();
        assert!(
            prepared
                .set_head_metadata(b"different".to_vec(), [0; 32])
                .is_err()
        );
        assert!(store.commit(prepared).is_err());
    }

    #[test]
    fn foreign_or_corrupt_format_is_refused_without_mutation() {
        use sha2_10::Digest;
        let temp = tempfile::tempdir().unwrap();
        let foreign = temp.path().join("legacy.redb");
        let db = Database::create(&foreign).unwrap();
        let write = db.begin_write().unwrap();
        {
            const LEGACY: TableDefinition<u64, &[u8]> = TableDefinition::new("legacy_state");
            write
                .open_table(LEGACY)
                .unwrap()
                .insert(0, &b"legacy protocol state"[..])
                .unwrap();
        }
        write.commit().unwrap();
        drop(db);
        let before = Sha256::digest(std::fs::read(&foreign).unwrap());
        assert!(Store::open(&foreign).is_err());
        assert_eq!(before, Sha256::digest(std::fs::read(&foreign).unwrap()));
        let crashed = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store::tests::crash_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("TC_V2_CRASH_TEST_PATH", &foreign)
            .env("TC_V2_CRASH_TEST_PHASE", "foreign")
            .output()
            .unwrap();
        assert!(!crashed.status.success());
        assert!(String::from_utf8_lossy(&crashed.stdout).contains("TC_V2_REACHED_FOREIGN_CRASH"));
        let before = Sha256::digest(std::fs::read(&foreign).unwrap());
        assert!(Store::open(&foreign).is_err());
        assert_eq!(before, Sha256::digest(std::fs::read(&foreign).unwrap()));
        let corrupt = temp.path().join("corrupt.redb");
        let store = Store::open(&corrupt).unwrap();
        let write = store.db.begin_write().unwrap();
        {
            write
                .open_table(INFO)
                .unwrap()
                .insert("format", &b"unrecognized-format"[..])
                .unwrap();
        }
        write.commit().unwrap();
        drop(store);
        let before = Sha256::digest(std::fs::read(&corrupt).unwrap());
        assert!(Store::open(&corrupt).is_err());
        assert_eq!(before, Sha256::digest(std::fs::read(&corrupt).unwrap()));
        let empty = temp.path().join("empty-v2.redb");
        drop(Store::open(&empty).unwrap());
        assert_eq!(Store::open(&empty).unwrap().head().unwrap(), None);
    }

    #[test]
    fn row_or_jmt_value_corruption_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path().join("state.redb")).unwrap();
        commit(&store, 0, vec![(b"a".to_vec(), Some(b"10".to_vec()))]);
        let write = store.db.begin_write().unwrap();
        {
            write
                .open_table(ROWS)
                .unwrap()
                .insert(&b"a"[..], &b"999"[..])
                .unwrap();
        }
        write.commit().unwrap();
        assert!(store.get(b"a").is_err());
        assert!(store.scan_prefix(b"a", 10).is_err());
        let write = store.db.begin_write().unwrap();
        {
            let key = value_key(key_hash(b"a"), 0);
            write
                .open_table(VALUES)
                .unwrap()
                .insert(key.as_slice(), encode_value(Some(b"999")).as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        assert!(store.get(b"a").is_err());
        assert!(store.proof(b"a", 0).is_err());
    }

    #[test]
    fn verified_read_cache_never_accepts_an_initial_corrupt_row() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path().join("state.redb")).unwrap();
        commit(&store, 0, vec![(b"a".to_vec(), Some(b"10".to_vec()))]);
        let write = store.db.begin_write().unwrap();
        {
            write
                .open_table(ROWS)
                .unwrap()
                .insert(&b"a"[..], &b"forged"[..])
                .unwrap();
        }
        write.commit().unwrap();
        let snapshot = store.snapshot().unwrap();
        assert!(snapshot.get(b"a").is_err());
        assert!(snapshot.get(b"a").is_err());
        let stats = snapshot.verified_read_cache_stats().unwrap();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 2);
    }

    #[test]
    fn cached_pinned_reads_survive_concurrent_commit_but_stale_prepare_is_rejected() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Snapshot>();
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path().join("state.redb")).unwrap();
        let zero = commit(&store, 0, vec![(b"a".to_vec(), Some(b"10".to_vec()))]);
        let snapshot = store.snapshot().unwrap();
        assert_eq!(snapshot.get(b"a").unwrap(), Some(b"10".to_vec()));
        assert_eq!(snapshot.get(b"missing").unwrap(), None);
        commit(&store, 1, vec![(b"a".to_vec(), Some(b"20".to_vec()))]);
        assert_eq!(snapshot.get(b"a").unwrap(), Some(b"10".to_vec()));
        assert_eq!(snapshot.get(b"missing").unwrap(), None);
        let before = snapshot.verified_read_cache_stats().unwrap();
        assert_eq!(before.hits, 2);
        assert_eq!(before.misses, 2);
        assert_eq!(
            snapshot
                .proof(b"a", 0)
                .unwrap()
                .verify(zero.root, b"a")
                .unwrap(),
            Some(b"10".to_vec())
        );
        let after = snapshot.verified_read_cache_stats().unwrap();
        assert_eq!(before.hits, after.hits);
        assert_eq!(
            before.misses, after.misses,
            "proof generation must not rely on the read memo"
        );
        let mut stale = snapshot
            .prepare_updates(
                1,
                vec![
                    (META_KEY.to_vec(), Some(b"stale".to_vec())),
                    (b"a".to_vec(), Some(b"30".to_vec())),
                ],
            )
            .unwrap();
        stale.set_head_metadata(b"stale".to_vec(), [1; 32]).unwrap();
        assert!(
            snapshot.verified_read_cache_stats().unwrap().hits > after.hits,
            "prepare reuses already authenticated old paths"
        );
        assert!(store.commit(stale).is_err());
        assert_eq!(store.get(b"a").unwrap(), Some(b"20".to_vec()));
    }

    #[test]
    fn verified_read_cache_bounds_negative_entries_and_large_values() {
        let mut negative = VerifiedReadCache::default();
        for id in 0..9000 {
            negative.insert(format!("missing/{id}").as_bytes(), None);
        }
        let stats = negative.stats();
        assert_eq!(stats.entries, VERIFIED_READ_MAX_ENTRIES);
        assert!(stats.charged_bytes <= VERIFIED_READ_MAX_BYTES);
        assert!(stats.evictions > 0);
        assert_eq!(negative.get(b"missing/0"), None);
        assert_eq!(negative.get(b"missing/8999"), Some(None));
        let mut positive = VerifiedReadCache::default();
        let value = vec![7; MAX_VALUE_BYTES];
        for id in 0..32 {
            positive.insert(format!("large/{id}").as_bytes(), Some(&value));
        }
        let stats = positive.stats();
        assert!(stats.entries < 32);
        assert!(stats.charged_bytes <= VERIFIED_READ_MAX_BYTES);
        assert!(stats.evictions > 0);
        assert_eq!(positive.get(b"large/0"), None);
        assert_eq!(positive.get(b"large/31"), Some(Some(value)));
        let before = positive.stats();
        positive.insert(&vec![1; MAX_KEY_BYTES + 1], None);
        assert_eq!(before.charged_bytes, positive.stats().charged_bytes);
    }

    #[test]
    fn incremental_prepare_rejects_corrupt_old_update_path() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path().join("state.redb")).unwrap();
        let keys: Vec<_> = (0..128)
            .map(|id| format!("row/{id}").into_bytes())
            .collect();
        commit(
            &store,
            0,
            keys.iter()
                .map(|key| (key.clone(), Some(b"original".to_vec())))
                .collect(),
        );
        let snapshot = store.snapshot().unwrap();
        let table = snapshot.read.open_table(NODES).unwrap();
        let meta_nibble = key_hash(META_KEY).0[0] >> 4;
        let (node_key, mut encoded, key) = table
            .iter()
            .unwrap()
            .filter_map(|entry| {
                let (key_bytes, node_bytes) = entry.ok()?;
                let node_key: NodeKey = borsh::from_slice(key_bytes.value()).ok()?;
                if node_key.nibble_path().num_nibbles() != 1 {
                    return None;
                }
                let nibble = node_key.nibble_path().get_nibble(0).as_usize() as u8;
                if nibble == meta_nibble {
                    return None;
                }
                let node: Node = borsh::from_slice(node_bytes.value()).ok()?;
                if !matches!(node, Node::Internal(_)) {
                    return None;
                }
                let key = keys
                    .iter()
                    .find(|key| key_hash(key).0[0] >> 4 == nibble)?
                    .clone();
                Some((node_key, serde_json::to_value(node).ok()?, key))
            })
            .next()
            .expect("fixture has a non-meta internal subtree");
        let update_nibble = (key_hash(&key).0[0] & 15) as usize;
        let children = encoded["Internal"]["children"]["children"]
            .as_array_mut()
            .unwrap();
        let sibling = children
            .iter_mut()
            .enumerate()
            .find(|(index, child)| *index != update_nibble && !child.is_null())
            .unwrap()
            .1;
        let byte = sibling["hash"][0].as_u64().unwrap();
        sibling["hash"][0] = serde_json::json!(byte ^ 1);
        let damaged: Node = serde_json::from_value(encoded).unwrap();
        drop(table);
        drop(snapshot);
        let write = store.db.begin_write().unwrap();
        {
            write
                .open_table(NODES)
                .unwrap()
                .insert(
                    borsh::to_vec(&node_key).unwrap().as_slice(),
                    borsh::to_vec(&damaged).unwrap().as_slice(),
                )
                .unwrap();
        }
        write.commit().unwrap();
        assert!(
            store.get(META_KEY).is_ok(),
            "unrelated meta path still authenticates"
        );
        assert!(
            store.get(&key).is_err(),
            "damaged update path cannot authenticate"
        );
        assert!(
            store
                .prepare_updates(
                    1,
                    vec![
                        (META_KEY.to_vec(), Some(b"next".to_vec())),
                        (key, Some(b"replacement".to_vec()))
                    ]
                )
                .is_err(),
            "unverified old update paths must not propagate into a new committed root"
        );
    }

    #[test]
    fn fresh_account_update_rejects_unauthenticated_raw_collision() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path().join("state.redb")).unwrap();
        commit(&store, 0, vec![]);
        let new_account = [b"account/".as_slice(), &7u64.to_be_bytes()].concat();
        let write = store.db.begin_write().unwrap();
        {
            write
                .open_table(ROWS)
                .unwrap()
                .insert(new_account.as_slice(), &b"orphan account"[..])
                .unwrap();
        }
        write.commit().unwrap();
        assert!(
            store
                .prepare_updates(
                    1,
                    vec![
                        (META_KEY.to_vec(), Some(b"next".to_vec())),
                        (new_account, Some(b"new account".to_vec()))
                    ]
                )
                .is_err()
        );
        assert_eq!(store.head().unwrap().unwrap().version, 0);
    }

    #[test]
    #[ignore = "subprocess crash injection helper"]
    fn crash_helper() {
        let path = std::env::var_os("TC_V2_CRASH_TEST_PATH")
            .expect("parent supplies isolated test DB path");
        let phase = std::env::var("TC_V2_CRASH_TEST_PHASE").unwrap();
        if phase.starts_with("gc_") {
            let store = Store::open(&path).unwrap();
            let budget = GcBudget {
                max_nodes: 1,
                max_values: 1,
                max_roots: 1,
                max_millis: 100,
            };
            if phase == "gc_before" {
                let _ = store.maintain_gc_inner(budget, || {
                    println!("TC_V2_REACHED_GC_BEFORE");
                    std::io::stdout().flush().unwrap();
                    std::process::abort()
                });
            } else {
                store.maintain_gc(budget).unwrap();
                println!("TC_V2_REACHED_GC_AFTER");
                std::io::stdout().flush().unwrap();
                std::process::abort();
            }
        }
        if phase == "foreign" {
            use std::io::Write;
            let db = Database::open(&path).unwrap();
            let write = db.begin_write().unwrap();
            {
                const LEGACY: TableDefinition<u64, &[u8]> = TableDefinition::new("legacy_state");
                write
                    .open_table(LEGACY)
                    .unwrap()
                    .insert(1, &b"uncommitted"[..])
                    .unwrap();
            }
            println!("TC_V2_REACHED_FOREIGN_CRASH");
            std::io::stdout().flush().unwrap();
            std::process::abort();
        }
        let store = Store::open(path).unwrap();
        let mut prepared = store
            .prepare_updates(
                1,
                vec![
                    (META_KEY.to_vec(), Some(b"committed-one".to_vec())),
                    (b"a".to_vec(), Some(b"after".to_vec())),
                ],
            )
            .unwrap();
        prepared
            .set_head_metadata(b"committed-one".to_vec(), [1; 32])
            .unwrap();
        if phase == "before" {
            let _ = store.commit_inner(prepared, || {
                use std::io::Write;
                println!("TC_V2_REACHED_BEFORE_COMMIT");
                std::io::stdout().flush().unwrap();
                std::process::abort()
            });
        } else {
            store.commit(prepared).unwrap();
            use std::io::Write;
            println!("TC_V2_REACHED_AFTER_COMMIT");
            std::io::stdout().flush().unwrap();
            std::process::abort();
        }
    }

    #[test]
    fn real_process_crash_before_and_after_atomic_publish() {
        for phase in ["before", "after"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("state.redb");
            let store = Store::open(&path).unwrap();
            commit(&store, 0, vec![(b"a".to_vec(), Some(b"before".to_vec()))]);
            drop(store);
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::crash_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TC_V2_CRASH_TEST_PATH", &path)
                .env("TC_V2_CRASH_TEST_PHASE", phase)
                .output()
                .unwrap();
            assert!(!output.status.success());
            let marker = format!("TC_V2_REACHED_{}_COMMIT", phase.to_ascii_uppercase());
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(&marker),
                "crash helper did not reach injection boundary: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let reopened = Store::open(&path).unwrap();
            let head = reopened.head().unwrap().unwrap();
            assert_eq!(head.version, if phase == "before" { 0 } else { 1 });
            let value = if phase == "before" {
                b"before".as_slice()
            } else {
                b"after".as_slice()
            };
            assert_eq!(reopened.get(b"a").unwrap().as_deref(), Some(value));
            assert_eq!(
                reopened
                    .proof(b"a", head.version)
                    .unwrap()
                    .verify(head.root, b"a")
                    .unwrap()
                    .as_deref(),
                Some(value)
            );
            assert_eq!(reopened.genesis_head().unwrap().unwrap().version, 0);
        }
    }

    #[test]
    fn real_process_crash_before_and_after_partial_maintenance_publish() {
        for phase in ["gc_before", "gc_after"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("state.redb");
            let options = StoreOptions {
                retained_versions: 1,
                prune_batch: 1,
                max_updates: 100,
            };
            let store = Store::open_with_options(&path, options).unwrap();
            for version in 0..8 {
                commit(
                    &store,
                    version,
                    vec![(b"key".to_vec(), Some(vec![version as u8]))],
                );
            }
            let before = store.stats().unwrap();
            let head = store.head().unwrap();
            drop(store);
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::crash_helper",
                    "--ignored",
                    "--nocapture",
                ])
                .env("TC_V2_CRASH_TEST_PATH", &path)
                .env("TC_V2_CRASH_TEST_PHASE", phase)
                .output()
                .unwrap();
            assert!(!output.status.success());
            let marker = format!("TC_V2_REACHED_{}", phase.to_ascii_uppercase());
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(&marker),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let store = Store::open_with_options(&path, options).unwrap();
            assert_eq!(store.head().unwrap(), head);
            let after = store.stats().unwrap();
            let removed = (before.tree_nodes - after.tree_nodes)
                + (before.versioned_values - after.versioned_values)
                + (before.retained_root_records - after.retained_root_records);
            if phase == "gc_before" {
                assert_eq!(removed, 0);
            } else {
                assert!((1..=3).contains(&removed));
            }
            for _ in 0..100 {
                if !store
                    .gc_status(GcPolicy::default())
                    .unwrap()
                    .eligible_work_pending
                {
                    break;
                }
                store
                    .maintain_gc(GcBudget {
                        max_nodes: 2,
                        max_values: 2,
                        max_roots: 2,
                        max_millis: 100,
                    })
                    .unwrap();
            }
            assert!(
                !store
                    .gc_status(GcPolicy::default())
                    .unwrap()
                    .eligible_work_pending
            );
            assert_eq!(store.get(b"key").unwrap(), Some(vec![7]));
        }
    }

    #[test]
    fn offset_backend_preserves_prefix_on_resize_and_checked_arithmetic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bytes.bin");
        let original: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
        let mut physical = file_prefix().to_vec();
        physical.extend_from_slice(&original);
        std::fs::write(&path, &physical).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let backend = OffsetBackend {
            base: redb::backends::FileBackend::new(file).unwrap(),
        };
        let mut expected = original.clone();
        assert_eq!(backend.len().unwrap(), 16384);
        let replacement = vec![97; 5000];
        backend.write(3500, &replacement).unwrap();
        expected[3500..8500].copy_from_slice(&replacement);
        let mut read = vec![0; original.len()];
        backend.read(0, &mut read).unwrap();
        assert_eq!(read, expected);
        backend.set_len(4100).unwrap();
        expected.truncate(4100);
        backend.set_len(9000).unwrap();
        expected.resize(9000, 0);
        let mut read = vec![0; 9000];
        backend.read(0, &mut read).unwrap();
        assert_eq!(read, expected);
        assert!(backend.write(u64::MAX, &[1]).is_err());
        assert!(backend.read(u64::MAX, &mut [0]).is_err());
        assert!(backend.set_len(u64::MAX).is_err());
        backend.sync_data().unwrap();
        drop(backend);
        let physical = std::fs::read(path).unwrap();
        assert_eq!(&physical[..4096], file_prefix());
        assert_eq!(&physical[4096..], expected);
    }
}
