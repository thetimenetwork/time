//! Authenticated state held in memory, with crash-safe snapshot files.
//!
//! Protocol 4 kept the Merkle tree in a disk database and re-read and re-proved
//! every row it touched. Here the current state and the last few versions live
//! in memory as persistent trees (`crate::merkle`), so a block is executed and
//! hashed without any disk access.
//!
//! Durability comes from two places. CometBFT stores every block durably
//! before asking the application to execute it and replays the blocks an
//! application has not persisted yet. This store writes a full, checksummed
//! snapshot of one version at a time; after a restart the node loads the newest
//! valid snapshot, recomputes its Merkle root from the rows, and CometBFT
//! replays the blocks after it. A snapshot that fails either check is never
//! used.
//!
//! The same file format serves state sync (`crate::statesync`). A node that
//! offers snapshots to peers writes extra files, at heights every node
//! agrees on, under `statesync/` with a manifest of chunk hashes beside
//! each. They are separate from the restart snapshots: other heights,
//! another retention, and never read at start. A node that joins receives
//! such a file in chunks into `restore.tmp`; once it is verified it becomes
//! the node's restart snapshot by a rename (`install_restored`).
use crate::{
    merkle::{self, Link, Op},
    proof::{MAX_KEY_BYTES, MAX_VALUE_BYTES, ProofBundle, ProofEntry, key_hash},
    statesync::{Manifest, SYNC_CHUNK_BYTES, SYNC_MIN_CHUNK_BYTES, metadata_hash},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

pub const META_KEY: &[u8] = b"meta";
/// How long `Store::open` waits for the lock of the state directory before it gives up.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
const MAX_BATCH_BYTES: usize = 256 * 1024 * 1024;
const SNAPSHOT_MAGIC: &[u8; 16] = b"TIMEV5SNAPSHOT\0\x01";
const SNAPSHOT_PREFIX: &str = "state-";
const NO_SNAPSHOT: u64 = u64::MAX;
/// Versions always kept, whatever they cost: the head and the few before it
/// that wallets ask proofs for.
const MIN_RETAINED_VERSIONS: usize = 4;
const SNAPSHOT_SUFFIX: &str = ".snap";
const MANIFEST_SUFFIX: &str = ".manifest";
/// Subdirectory of the snapshots offered to peers.
const SYNC_DIRECTORY: &str = "statesync";
/// Staging file of a state-sync restore in progress.
const RESTORE_FILE: &str = "restore.tmp";
/// Shortest possible snapshot file: its fixed fields and the checksum.
pub const SNAPSHOT_MIN_BYTES: u64 = 16 + 8 + 32 + 32 + 8 + 4 + 32;

/// The height and root a snapshot file declares in its first bytes, if they
/// are the start of one. Nothing is authenticated by this.
pub fn snapshot_header(bytes: &[u8]) -> Option<(u64, [u8; 32])> {
    if bytes.len() < 56 || &bytes[..16] != SNAPSHOT_MAGIC {
        return None;
    }
    Some((
        u64::from_be_bytes(bytes[16..24].try_into().ok()?),
        bytes[24..56].try_into().ok()?,
    ))
}

pub type Update = (Vec<u8>, Option<Vec<u8>>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub version: u64,
    pub root: [u8; 32],
    pub request_fingerprint: [u8; 32],
    pub metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
pub struct StoreOptions {
    /// Versions kept in memory for proofs, including the current one.
    pub retained_versions: usize,
    /// Changed rows kept across all retained versions. Older versions are
    /// dropped beyond it, down to `MIN_RETAINED_VERSIONS`, so memory stays
    /// bounded when blocks are large.
    pub retained_rows: usize,
    /// Upper bound on rows changed by one version.
    pub max_updates: usize,
    /// Snapshot files kept on disk.
    pub snapshots_kept: usize,
    /// Snapshots for peers kept on disk. 0: the node offers none, and those
    /// found on disk are left alone and not offered.
    pub sync_snapshots_kept: usize,
    /// Chunk size of the snapshots written for peers.
    pub sync_chunk_bytes: u32,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            // Each version keeps the tree paths its block changed: about
            // 30 MB for a block of 10,000 transfers.
            retained_versions: 32,
            retained_rows: 1_000_000,
            max_updates: 200_000,
            snapshots_kept: 2,
            sync_snapshots_kept: 0,
            sync_chunk_bytes: SYNC_CHUNK_BYTES,
        }
    }
}

/// One committed, immutable version of the state.
pub struct Version {
    head: Head,
    tree: Link,
    /// Rows this version changed: what keeping it costs beyond its parent.
    changed_rows: usize,
}

impl Version {
    pub fn head(&self) -> &Head {
        &self.head
    }
    pub fn height(&self) -> u64 {
        self.head.version
    }
    pub fn root(&self) -> [u8; 32] {
        self.head.root
    }
    pub fn leaf_count(&self) -> u64 {
        merkle::leaf_count(&self.tree)
    }
    /// The row stored under `key` in this version.
    pub fn get(&self, key: &[u8]) -> Option<Arc<[u8]>> {
        merkle::get(&self.tree, &key_hash(key)).map(|leaf| leaf.value().clone())
    }
    /// Membership or absence proof for `key`, checked against this version's
    /// root before it is returned.
    pub fn proof(&self, key: &[u8]) -> Result<ProofEntry> {
        Ok(self.proof_with_value(key)?.0)
    }
    /// As `proof`, also returning the proven value (`None` for a proven absence).
    pub fn proof_with_value(&self, key: &[u8]) -> Result<(ProofEntry, Option<Vec<u8>>)> {
        ensure!(
            !key.is_empty() && key.len() <= MAX_KEY_BYTES,
            "invalid proof key length"
        );
        let (value, proof) = merkle::prove(&self.tree, &key_hash(key));
        let entry = ProofEntry::new(key, value.as_deref(), proof);
        let verified = entry.verify(self.head.root, key)?;
        ensure!(
            verified.as_deref() == value.as_deref(),
            "proof value differs from the stored row"
        );
        Ok((entry, verified))
    }
    pub fn proof_bundle(&self, keys: &[Vec<u8>]) -> Result<ProofBundle> {
        ensure!(
            !keys.is_empty() && keys.len() <= 32,
            "invalid proof bundle size"
        );
        Ok(ProofBundle {
            version: self.head.version,
            root: self.head.root,
            entries: keys
                .iter()
                .map(|key| self.proof(key))
                .collect::<Result<_>>()?,
        })
    }
    /// Recomputes every hash in the tree and indexes all rows by raw key.
    pub fn audit_verified(
        &self,
        mut progress: impl FnMut(AuditStorageProgress),
    ) -> Result<VerifiedAudit<'_>> {
        let total = self.leaf_count();
        progress(AuditStorageProgress {
            phase: "tree",
            processed: 0,
            total: Some(total),
        });
        merkle::verify_structure(&self.tree)?;
        ensure!(
            merkle::root_hash(&self.tree) == self.head.root,
            "tree root differs from the committed head"
        );
        let mut rows = BTreeMap::new();
        let mut processed = 0u64;
        merkle::for_each_leaf(&self.tree, &mut |leaf| {
            ensure!(
                key_hash(leaf.key()) == *leaf.key_hash(),
                "row is stored under a hash of another key"
            );
            ensure!(
                rows.insert(leaf.key(), leaf.value().as_ref()).is_none(),
                "duplicate raw key in the tree"
            );
            processed += 1;
            if processed % 100_000 == 0 {
                progress(AuditStorageProgress {
                    phase: "rows",
                    processed,
                    total: Some(total),
                });
            }
            Ok(())
        })?;
        ensure!(processed == total, "leaf count differs from the tree");
        ensure!(
            rows.get(META_KEY).copied() == Some(self.head.metadata.as_slice()),
            "metadata row differs from the committed head"
        );
        progress(AuditStorageProgress {
            phase: "rows",
            processed,
            total: Some(total),
        });
        Ok(VerifiedAudit {
            rows,
            leaf_count: total,
            tree_nodes: total + merkle::internal_count(&self.tree),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuditStorageProgress {
    pub phase: &'static str,
    pub processed: u64,
    pub total: Option<u64>,
}

/// Every row of one version, available only after the whole tree has been
/// re-hashed and matched against the committed root.
pub struct VerifiedAudit<'a> {
    rows: BTreeMap<&'a [u8], &'a [u8]>,
    leaf_count: u64,
    tree_nodes: u64,
}

impl VerifiedAudit<'_> {
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
    pub fn tree_nodes(&self) -> u64 {
        self.tree_nodes
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.rows.get(key).map(|value| value.to_vec()))
    }
    pub fn for_each_prefix(
        &self,
        prefix: &[u8],
        mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        let from_prefix = (
            std::ops::Bound::Included(prefix),
            std::ops::Bound::Unbounded,
        );
        for (key, value) in self.rows.range::<[u8], _>(from_prefix) {
            if !key.starts_with(prefix) {
                break;
            }
            visitor(key, value)?;
        }
        Ok(())
    }
}

/// A computed but not yet committed version.
pub struct PreparedTree {
    pub version: u64,
    pub root: [u8; 32],
    parent: Option<(u64, [u8; 32])>,
    tree: Link,
    meta_row: Vec<u8>,
    metadata: Option<Vec<u8>>,
    fingerprint: [u8; 32],
    updated_rows: usize,
}

impl PreparedTree {
    pub fn set_head_metadata(&mut self, metadata: Vec<u8>, fingerprint: [u8; 32]) -> Result<()> {
        ensure!(
            metadata == self.meta_row,
            "head metadata differs from the authenticated meta row"
        );
        self.metadata = Some(metadata);
        self.fingerprint = fingerprint;
        Ok(())
    }
    pub fn updated_rows(&self) -> usize {
        self.updated_rows
    }
    pub fn leaf_count(&self) -> u64 {
        merkle::leaf_count(&self.tree)
    }
}

pub struct SnapshotInfo {
    pub height: u64,
    pub bytes: u64,
    pub path: PathBuf,
}

/// A snapshot this node offers to peers, as ABCI describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncSnapshot {
    pub height: u64,
    pub chunks: u32,
    /// SHA-256 of `metadata`.
    pub hash: [u8; 32],
    /// The encoded `Manifest`.
    pub metadata: Vec<u8>,
}

/// A snapshot file offered to peers and the manifest written with it.
struct Served {
    path: PathBuf,
    manifest: Manifest,
    metadata: Vec<u8>,
}

pub struct Store {
    directory: PathBuf,
    options: StoreOptions,
    versions: RwLock<VecDeque<Arc<Version>>>,
    /// One snapshot is written at a time.
    snapshot_writer: Mutex<()>,
    /// Height of the newest snapshot known to be good: the one loaded at start
    /// or the last one this process wrote. `NO_SNAPSHOT` when there is none.
    /// Read without any lock, so a query never waits for a snapshot write.
    snapshot_height: AtomicU64,
    /// Lowest height among the restart snapshot files on disk, verified or
    /// not: the furthest back a restart could begin. `NO_SNAPSHOT` when
    /// there is none. Block pruning never passes it.
    oldest_snapshot: AtomicU64,
    /// Snapshots offered to peers, by height.
    serving: Mutex<BTreeMap<u64, Arc<Served>>>,
    // Held for the lifetime of the store: one writer per state directory.
    _lock: File,
}

impl Store {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(directory, StoreOptions::default())
    }

    pub fn open_with_options(directory: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        ensure!(
            options.retained_versions >= 2
                && options.max_updates > 0
                && options.snapshots_kept >= 1
                && options.sync_snapshots_kept <= 10
                && (SYNC_MIN_CHUNK_BYTES..=SYNC_CHUNK_BYTES).contains(&options.sync_chunk_bytes),
            "invalid store options"
        );
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)
            .with_context(|| format!("create state directory {}", directory.display()))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(directory.join("LOCK"))?;
        // The lock can be held for an instant by a process that is not using the directory: one that has
        // just ended, or one that is being started from a program that has the directory open (between
        // fork and exec a child holds a copy of every open file; the engine's own tests do this). So the
        // lock is asked for again for a short time before the directory is said to be in use.
        let asked = std::time::Instant::now();
        while lock.try_lock().is_err() {
            ensure!(asked.elapsed() < LOCK_WAIT, "state directory is in use by another process");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut versions: VecDeque<Arc<Version>> = VecDeque::new();
        let mut found = snapshot_files(&directory)?;
        found.reverse();
        let mut failures = Vec::new();
        let mut damaged = Vec::new();
        for (height, path) in &found {
            match load_snapshot(path, *height) {
                Ok(version) => {
                    versions.push_back(Arc::new(version));
                    break;
                }
                Err(error) => {
                    failures.push(format!("{}: {error:#}", path.display()));
                    damaged.push(path.clone());
                }
            }
        }
        // Never fall back to an empty state when snapshot files exist but none
        // can be authenticated: that would hide disk damage behind a full replay.
        // The files are left untouched in that case.
        ensure!(
            found.is_empty() || !versions.is_empty(),
            "no snapshot could be authenticated: {}",
            failures.join("; ")
        );
        for failure in &failures {
            eprintln!("Ignoring unusable snapshot: {failure}");
        }
        // A damaged file newer than the one in use must not count as a
        // snapshot again: it would be kept in place of good ones. It is set
        // aside under another name for inspection.
        for path in &damaged {
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                let aside = directory.join(format!("damaged-{name}"));
                if let Err(error) = fs::rename(path, &aside) {
                    eprintln!("Could not set aside {}: {error}", path.display());
                }
            }
        }
        let loaded = versions.back().map_or(NO_SNAPSHOT, |version| version.height());
        // A restore that did not finish left nothing but its staging file.
        let _ = fs::remove_file(directory.join(RESTORE_FILE));
        let oldest = snapshot_files(&directory)?
            .first()
            .map_or(NO_SNAPSHOT, |(height, _)| *height);
        let serving = if options.sync_snapshots_kept > 0 {
            load_served(&directory.join(SYNC_DIRECTORY), options.sync_snapshots_kept)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            directory,
            options,
            versions: RwLock::new(versions),
            snapshot_writer: Mutex::new(()),
            snapshot_height: AtomicU64::new(loaded),
            oldest_snapshot: AtomicU64::new(oldest),
            serving: Mutex::new(serving),
            _lock: lock,
        })
    }

    fn read_versions(&self) -> Result<std::sync::RwLockReadGuard<'_, VecDeque<Arc<Version>>>> {
        self.versions
            .read()
            .map_err(|_| anyhow!("state version list poisoned"))
    }

    /// The latest committed version, if the chain is initialized.
    pub fn current(&self) -> Result<Option<Arc<Version>>> {
        Ok(self.read_versions()?.back().cloned())
    }

    pub fn head(&self) -> Result<Option<Head>> {
        Ok(self.current()?.map(|version| version.head.clone()))
    }

    /// A retained version by height.
    pub fn version(&self, height: u64) -> Result<Arc<Version>> {
        let versions = self.read_versions()?;
        let oldest = versions.front().context("uninitialized state")?.height();
        ensure!(height >= oldest, "proof version pruned");
        let index = usize::try_from(height - oldest)?;
        let version = versions.get(index).context("unknown proof version")?;
        ensure!(version.height() == height, "state versions are not contiguous");
        Ok(version.clone())
    }

    pub fn oldest_retained(&self) -> Result<Option<u64>> {
        Ok(self.read_versions()?.front().map(|version| version.height()))
    }

    /// Computes the next version from `base` without publishing it.
    pub fn prepare(
        &self,
        base: Option<&Arc<Version>>,
        version: u64,
        updates: Vec<Update>,
    ) -> Result<PreparedTree> {
        ensure!(
            !updates.is_empty() && updates.len() <= self.options.max_updates,
            "invalid state batch size"
        );
        let next = match base {
            Some(base) => base.height().checked_add(1).context("version overflow")?,
            None => 0,
        };
        ensure!(version == next, "nonconsecutive state version");
        let mut keys = BTreeSet::new();
        let mut batch_bytes = 0usize;
        let mut meta_row = None;
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
            ensure!(batch_bytes <= MAX_BATCH_BYTES, "state batch exceeds memory bound");
            ensure!(keys.insert(key.as_slice()), "duplicate update key");
            if key.as_slice() == META_KEY {
                meta_row = value.clone();
            }
        }
        let meta_row = meta_row.context("each version requires the authenticated meta row")?;
        let updated_rows = updates.len();
        let mut ops: Vec<Op> = updates
            .into_par_iter()
            .map(|(key, value)| {
                let hash = key_hash(&key);
                Op {
                    key_hash: hash,
                    leaf: value.map(|bytes| merkle::new_leaf(&key, hash, Arc::from(bytes))),
                }
            })
            .collect();
        ops.par_sort_unstable_by(|a, b| a.key_hash.cmp(&b.key_hash));
        ensure!(
            ops.windows(2).all(|pair| pair[0].key_hash != pair[1].key_hash),
            "hashed key collision"
        );
        let base_tree = base.map(|version| &version.tree);
        let tree = merkle::update(base_tree.unwrap_or(&None), &ops)?;
        Ok(PreparedTree {
            version,
            root: merkle::root_hash(&tree),
            parent: base.map(|version| (version.height(), version.root())),
            tree,
            meta_row,
            metadata: None,
            fingerprint: [0; 32],
            updated_rows,
        })
    }

    /// Publishes a prepared version as the new head. Fails if the head moved
    /// since the version was prepared.
    pub fn commit(&self, prepared: PreparedTree) -> Result<Head> {
        let metadata = prepared
            .metadata
            .context("prepared head metadata was not set")?;
        ensure!(
            merkle::root_hash(&prepared.tree) == prepared.root,
            "prepared root was modified"
        );
        let head = Head {
            version: prepared.version,
            root: prepared.root,
            request_fingerprint: prepared.fingerprint,
            metadata,
        };
        let mut versions = self
            .versions
            .write()
            .map_err(|_| anyhow!("state version list poisoned"))?;
        let current = versions.back().map(|v| (v.height(), v.root()));
        ensure!(
            current == prepared.parent,
            "stale prepared state: committed parent changed"
        );
        versions.push_back(Arc::new(Version {
            head: head.clone(),
            tree: prepared.tree,
            changed_rows: prepared.updated_rows,
        }));
        let mut rows: usize = versions.iter().map(|version| version.changed_rows).sum();
        let mut retired = Vec::new();
        while versions.len() > self.options.retained_versions
            || (versions.len() > MIN_RETAINED_VERSIONS && rows > self.options.retained_rows)
        {
            if let Some(dropped) = versions.pop_front() {
                rows -= dropped.changed_rows;
                retired.push(dropped);
            }
        }
        drop(versions);
        // Freeing a version releases every tree node only it still held, tens
        // of thousands after a large block. That work does not belong on the
        // commit path.
        if !retired.is_empty() {
            rayon::spawn(move || drop(retired));
        }
        Ok(head)
    }

    /// Height of the newest snapshot written or loaded by this process.
    /// Never waits for a snapshot that is being written.
    pub fn snapshot_height(&self) -> Result<Option<u64>> {
        let height = self.snapshot_height.load(Ordering::Acquire);
        Ok((height != NO_SNAPSHOT).then_some(height))
    }

    /// Writes `version` to disk. The file is complete, synced and renamed into
    /// place before older snapshots are removed, so a crash at any point leaves
    /// at least one usable snapshot.
    pub fn write_snapshot(&self, version: &Version) -> Result<SnapshotInfo> {
        let _writer = self
            .snapshot_writer
            .lock()
            .map_err(|_| anyhow!("snapshot writer poisoned"))?;
        let height = version.height();
        let path = snapshot_path(&self.directory, height);
        // Only a file this process loaded or wrote counts as already saved.
        // Any other file under that name is replaced.
        if self.snapshot_height.load(Ordering::Acquire) == height && path.exists() {
            return Ok(SnapshotInfo {
                height,
                bytes: fs::metadata(&path)?.len(),
                path,
            });
        }
        let temporary = self
            .directory
            .join(format!("partial-{height:020}-{}.tmp", std::process::id()));
        let result = write_snapshot_file(version, &temporary, None).map(|(bytes, _)| bytes);
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error.context("write state snapshot"));
            }
        };
        fs::rename(&temporary, &path)?;
        sync_directory(&self.directory)?;
        self.snapshot_height.store(height, Ordering::Release);
        // Remove older snapshots and leftovers of interrupted writes. The
        // file just written is never removed, whatever else is in the directory.
        let files: Vec<(u64, PathBuf)> = snapshot_files(&self.directory)?
            .into_iter()
            .filter(|(_, file)| *file != path)
            .collect();
        let keep = self.options.snapshots_kept.saturating_sub(1);
        if files.len() > keep {
            for (_, old) in &files[..files.len() - keep] {
                let _ = fs::remove_file(old);
            }
        }
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("partial-") && name.ends_with(".tmp") && entry.path() != temporary {
                let _ = fs::remove_file(entry.path());
            }
        }
        self.refresh_oldest_snapshot();
        Ok(SnapshotInfo {
            height,
            bytes,
            path,
        })
    }

    fn refresh_oldest_snapshot(&self) {
        if let Ok(files) = snapshot_files(&self.directory) {
            let oldest = files.first().map_or(NO_SNAPSHOT, |(height, _)| *height);
            self.oldest_snapshot.store(oldest, Ordering::Release);
        }
    }

    /// Lowest height among the snapshot files a restart could begin from.
    /// CometBFT must keep every block after it.
    pub fn oldest_snapshot_height(&self) -> Option<u64> {
        let height = self.oldest_snapshot.load(Ordering::Acquire);
        (height != NO_SNAPSHOT).then_some(height)
    }

    fn serving(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<u64, Arc<Served>>>> {
        self.serving
            .lock()
            .map_err(|_| anyhow!("state-sync snapshot list poisoned"))
    }

    /// The snapshots offered to peers, oldest first.
    pub fn sync_snapshots(&self) -> Result<Vec<SyncSnapshot>> {
        Ok(self
            .serving()?
            .iter()
            .map(|(height, served)| SyncSnapshot {
                height: *height,
                chunks: served.manifest.chunks(),
                hash: metadata_hash(&served.metadata),
                metadata: served.metadata.clone(),
            })
            .collect())
    }

    /// Lowest height among the snapshots offered to peers.
    pub fn oldest_sync_snapshot_height(&self) -> Result<Option<u64>> {
        Ok(self.serving()?.keys().next().copied())
    }

    /// Writes `version` as a snapshot for peers, with its manifest, and
    /// removes the oldest ones beyond `sync_snapshots_kept`. `None` if this
    /// height is already offered.
    pub fn write_sync_snapshot(&self, version: &Version) -> Result<Option<SnapshotInfo>> {
        let kept = self.options.sync_snapshots_kept;
        ensure!(kept > 0, "this node offers no state-sync snapshots");
        let _writer = self
            .snapshot_writer
            .lock()
            .map_err(|_| anyhow!("snapshot writer poisoned"))?;
        let height = version.height();
        if self.serving()?.contains_key(&height) {
            return Ok(None);
        }
        let directory = self.directory.join(SYNC_DIRECTORY);
        fs::create_dir_all(&directory)?;
        let path = snapshot_path(&directory, height);
        let manifest_file = manifest_path(&directory, height);
        let temporary = directory.join(format!("partial-{height:020}-{}.tmp", std::process::id()));
        let written = write_snapshot_file(version, &temporary, Some(self.options.sync_chunk_bytes))
            .and_then(|(total_bytes, chunk_hashes)| {
                let manifest = Manifest {
                    total_bytes,
                    chunk_bytes: self.options.sync_chunk_bytes,
                    chunk_hashes,
                };
                // What is written must be what a peer will accept.
                let metadata = manifest.encode();
                ensure!(
                    Manifest::decode(&metadata)? == manifest,
                    "snapshot manifest does not read back"
                );
                // The snapshot first, then its manifest: a snapshot without
                // a manifest is never offered.
                fs::rename(&temporary, &path)?;
                let partial = directory.join(format!("partial-{height:020}.manifest.tmp"));
                let mut file = File::create(&partial)?;
                file.write_all(&metadata)?;
                file.sync_all()?;
                drop(file);
                fs::rename(&partial, &manifest_file)?;
                sync_directory(&directory)?;
                Ok((manifest, metadata))
            });
        let (manifest, metadata) = match written {
            Ok(written) => written,
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                let _ = fs::remove_file(&path);
                return Err(error.context("write state-sync snapshot"));
            }
        };
        let bytes = manifest.total_bytes;
        let retired: Vec<Arc<Served>> = {
            let mut serving = self.serving()?;
            serving.insert(
                height,
                Arc::new(Served {
                    path: path.clone(),
                    manifest,
                    metadata,
                }),
            );
            let mut retired = Vec::new();
            while serving.len() > kept {
                if let Some((_, served)) = serving.pop_first() {
                    retired.push(served);
                }
            }
            retired
        };
        // No longer offered: the files can go. A peer that is still fetching
        // one is told the chunk is missing and turns to another snapshot.
        for served in retired {
            let _ = fs::remove_file(served.path.with_extension("manifest"));
            let _ = fs::remove_file(&served.path);
        }
        Ok(Some(SnapshotInfo {
            height,
            bytes,
            path,
        }))
    }

    /// One chunk of a snapshot offered to peers, checked against its
    /// manifest before it leaves. `None` when no such snapshot or chunk is
    /// offered: any peer may ask for any chunk, so that is not an error. An
    /// error means an offered file could not be read or is damaged: it is
    /// withdrawn and its files are removed, so that it is not offered again
    /// after a restart either.
    pub fn load_sync_chunk(&self, height: u64, index: u32) -> Result<Option<Vec<u8>>> {
        let Some(served) = self.serving()?.get(&height).cloned() else {
            return Ok(None);
        };
        let Some(length) = served.manifest.chunk_len(index) else {
            return Ok(None);
        };
        let read = (|| -> Result<Vec<u8>> {
            let mut file = File::open(&served.path)?;
            file.seek(SeekFrom::Start(
                u64::from(index) * u64::from(served.manifest.chunk_bytes),
            ))?;
            let mut chunk = vec![0; length];
            file.read_exact(&mut chunk)?;
            ensure!(
                <[u8; 32]>::from(Sha256::digest(&chunk))
                    == served.manifest.chunk_hashes[index as usize],
                "chunk differs from its manifest"
            );
            Ok(chunk)
        })();
        if read.is_err() {
            // Unreadable or damaged: stop offering it, now and after a restart.
            let mut serving = self.serving()?;
            if serving.get(&height).is_some_and(|current| Arc::ptr_eq(current, &served)) {
                serving.remove(&height);
                let _ = fs::remove_file(served.path.with_extension("manifest"));
                let _ = fs::remove_file(&served.path);
            }
        }
        read.map(Some).with_context(|| {
            format!("state-sync snapshot {height} withdrawn: chunk {index} could not be served")
        })
    }

    /// Where the chunks of a restore are staged. One restore at a time.
    pub fn restore_path(&self) -> PathBuf {
        self.directory.join(RESTORE_FILE)
    }

    /// Checks a staged snapshot file and rebuilds its tree. An error means the
    /// file is not a snapshot of `height` whose rows hash to `root`. The
    /// node's own state is not touched.
    ///
    /// The file is read twice. The first pass (`check_snapshot_root`) keeps
    /// no row: it computes the root from the rows as they pass, in memory
    /// that does not grow with the file. Only a file that has the trusted
    /// root, which nobody can forge, is then loaded and built into a tree.
    /// A forged file of any size and shape is refused in the first pass.
    pub fn verify_staged(&self, staged: &Path, height: u64, root: [u8; 32]) -> Result<Version> {
        check_snapshot_root(staged, height, root)?;
        let version = load_snapshot(staged, height)?;
        ensure!(
            version.root() == root,
            "snapshot rows do not hash to the trusted application hash"
        );
        Ok(version)
    }

    /// Makes a verified, staged snapshot the node's state: the file becomes
    /// the restart snapshot of its height, and the version replaces every
    /// version in memory. Refused, with nothing changed, unless the node
    /// holds no state or an older one.
    ///
    /// Older restart snapshots are removed afterwards: CometBFT holds no
    /// blocks between them and the restored height, so a restart from one of
    /// them could never catch up.
    pub fn install_restored(&self, version: Version, staged: &Path) -> Result<Arc<Version>> {
        let _writer = self
            .snapshot_writer
            .lock()
            .map_err(|_| anyhow!("snapshot writer poisoned"))?;
        let mut versions = self
            .versions
            .write()
            .map_err(|_| anyhow!("state version list poisoned"))?;
        let height = version.height();
        ensure!(
            versions.back().is_none_or(|current| current.height() < height),
            "the node already holds this height or a later one"
        );
        let path = snapshot_path(&self.directory, height);
        // Nothing has changed up to here. After the rename nothing can fail:
        // the file on disk and the state in memory change together.
        fs::rename(staged, &path).context("move the restored snapshot into place")?;
        if let Err(error) = sync_directory(&self.directory) {
            eprintln!("Could not sync the state directory after a restore: {error:#}");
        }
        let version = Arc::new(version);
        let retired: Vec<Arc<Version>> = versions.drain(..).collect();
        versions.push_back(version.clone());
        drop(versions);
        self.snapshot_height.store(height, Ordering::Release);
        if let Ok(files) = snapshot_files(&self.directory) {
            for (other, file) in files {
                if other != height {
                    let _ = fs::remove_file(file);
                }
            }
        }
        self.refresh_oldest_snapshot();
        if !retired.is_empty() {
            rayon::spawn(move || drop(retired));
        }
        Ok(version)
    }
}

/// SHA-256 of every `size` bytes of what is written, the last piece being
/// whatever is left.
struct ChunkHasher {
    size: usize,
    filled: usize,
    hasher: Sha256,
    done: Vec<[u8; 32]>,
}

impl ChunkHasher {
    fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let take = (self.size - self.filled).min(bytes.len());
            self.hasher.update(&bytes[..take]);
            self.filled += take;
            bytes = &bytes[take..];
            if self.filled == self.size {
                self.done.push(self.hasher.finalize_reset().into());
                self.filled = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<[u8; 32]> {
        if self.filled > 0 {
            self.done.push(self.hasher.finalize().into());
        }
        self.done
    }
}

/// Writes `version` to `temporary` and syncs it. Returns the file's length
/// and, when `chunk_bytes` is given, the SHA-256 of each chunk of that size.
fn write_snapshot_file(
    version: &Version,
    temporary: &Path,
    chunk_bytes: Option<u32>,
) -> Result<(u64, Vec<[u8; 32]>)> {
    let file = File::create(temporary)?;
    let mut out = HashingWriter {
        inner: BufWriter::with_capacity(4 * 1024 * 1024, file),
        hasher: Sha256::new(),
        written: 0,
        chunks: chunk_bytes.map(|size| ChunkHasher {
            size: size as usize,
            filled: 0,
            hasher: Sha256::new(),
            done: Vec::new(),
        }),
    };
    let head = &version.head;
    let height = version.height();
    out.write_all(SNAPSHOT_MAGIC)?;
    out.write_all(&height.to_be_bytes())?;
    out.write_all(&head.root)?;
    out.write_all(&head.request_fingerprint)?;
    out.write_all(&version.leaf_count().to_be_bytes())?;
    out.write_all(&u32::try_from(head.metadata.len())?.to_be_bytes())?;
    out.write_all(&head.metadata)?;
    merkle::for_each_leaf(&version.tree, &mut |leaf| -> Result<()> {
        out.write_all(&u16::try_from(leaf.key().len())?.to_be_bytes())?;
        out.write_all(leaf.key())?;
        out.write_all(&u32::try_from(leaf.value().len())?.to_be_bytes())?;
        out.write_all(leaf.value())?;
        Ok(())
    })?;
    let digest: [u8; 32] = out.hasher.clone().finalize().into();
    out.inner.write_all(&digest)?;
    if let Some(chunks) = &mut out.chunks {
        chunks.update(&digest);
    }
    let bytes = out.written + 32;
    let file = out
        .inner
        .into_inner()
        .map_err(|error| anyhow!("flush snapshot: {}", error.error()))?;
    file.sync_all()?;
    Ok((bytes, out.chunks.map_or_else(Vec::new, ChunkHasher::finish)))
}

fn manifest_path(directory: &Path, height: u64) -> PathBuf {
    directory.join(format!("{SNAPSHOT_PREFIX}{height:020}{MANIFEST_SUFFIX}"))
}

/// The snapshots for peers found in `directory`: each a snapshot file with a
/// well-formed manifest of the same length. Everything else there (a
/// snapshot without its manifest, an interrupted write, more than `kept`
/// snapshots) is removed. Chunks are checked against the manifest when they
/// are served, not here.
fn load_served(directory: &Path, kept: usize) -> Result<BTreeMap<u64, Arc<Served>>> {
    let mut serving = BTreeMap::new();
    if !directory.is_dir() {
        return Ok(serving);
    }
    for (height, path) in snapshot_files(directory)? {
        let manifest_file = manifest_path(directory, height);
        let usable = (|| -> Result<Served> {
            let length = fs::metadata(&manifest_file)?.len();
            ensure!(length <= 4 * 1024 * 1024, "manifest too large");
            let metadata = fs::read(&manifest_file)?;
            let manifest = Manifest::decode(&metadata)?;
            ensure!(
                fs::metadata(&path)?.len() == manifest.total_bytes,
                "snapshot length differs from its manifest"
            );
            Ok(Served {
                path: path.clone(),
                manifest,
                metadata,
            })
        })();
        match usable {
            Ok(served) => {
                serving.insert(height, Arc::new(served));
            }
            Err(error) => {
                eprintln!("Removing unusable state-sync snapshot {}: {error:#}", path.display());
                let _ = fs::remove_file(&manifest_file);
                let _ = fs::remove_file(&path);
            }
        }
    }
    while serving.len() > kept {
        if let Some((_, served)) = serving.pop_first() {
            let _ = fs::remove_file(served.path.with_extension("manifest"));
            let _ = fs::remove_file(&served.path);
        }
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let known = name
            .strip_prefix(SNAPSHOT_PREFIX)
            .and_then(|rest| {
                rest.strip_suffix(MANIFEST_SUFFIX)
                    .or_else(|| rest.strip_suffix(SNAPSHOT_SUFFIX))
            })
            .and_then(|digits| digits.parse::<u64>().ok())
            .is_some_and(|height| serving.contains_key(&height));
        if !known && (name.starts_with("partial-") || name.starts_with(SNAPSHOT_PREFIX)) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(serving)
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
    /// Per-chunk hashes, for a snapshot that will be offered to peers.
    chunks: Option<ChunkHasher>,
}

impl<W: Write> HashingWriter<W> {
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.inner.write_all(bytes)?;
        self.hasher.update(bytes);
        if let Some(chunks) = &mut self.chunks {
            chunks.update(bytes);
        }
        self.written += bytes.len() as u64;
        Ok(())
    }
}

fn snapshot_path(directory: &Path, height: u64) -> PathBuf {
    directory.join(format!("{SNAPSHOT_PREFIX}{height:020}{SNAPSHOT_SUFFIX}"))
}

/// Snapshot files in the directory, oldest first.
fn snapshot_files(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(digits) = name
            .strip_prefix(SNAPSHOT_PREFIX)
            .and_then(|rest| rest.strip_suffix(SNAPSHOT_SUFFIX))
        else {
            continue;
        };
        if digits.len() == 20 && digits.bytes().all(|c| c.is_ascii_digit()) {
            if let Ok(height) = digits.parse::<u64>() {
                files.push((height, entry.path()));
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    // Directory handles cannot be synced on this platform; the file itself is.
    Ok(())
}

struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
    remaining: u64,
}

impl<R: Read> HashingReader<R> {
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<()> {
        ensure!(
            buffer.len() as u64 <= self.remaining,
            "snapshot is truncated"
        );
        self.inner.read_exact(buffer)?;
        self.hasher.update(&*buffer);
        self.remaining -= buffer.len() as u64;
        Ok(())
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn vec(&mut self, length: usize) -> Result<Vec<u8>> {
        // The length was read from the file: never allocate more than what the
        // file can still hold.
        ensure!(length as u64 <= self.remaining, "snapshot is truncated");
        let mut bytes = vec![0; length];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

/// Checks that a file is a snapshot of `expected_height` whose rows hash to
/// `expected_root`, without keeping any row: the same checks as
/// `load_snapshot` (format, checksum, rows in key-hash order, row count,
/// metadata row, root), with the root computed by `merkle::StreamingRoot`.
/// Memory: the read buffer, one row at a time, and at most 256 hashes.
fn check_snapshot_root(path: &Path, expected_height: u64, expected_root: [u8; 32]) -> Result<()> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    ensure!(length >= SNAPSHOT_MIN_BYTES, "snapshot is too short");
    let mut reader = HashingReader {
        inner: BufReader::with_capacity(1024 * 1024, file),
        hasher: Sha256::new(),
        remaining: length - 32,
    };
    ensure!(
        &reader.array::<16>()? == SNAPSHOT_MAGIC,
        "not a version-5 state snapshot"
    );
    let height = u64::from_be_bytes(reader.array()?);
    ensure!(height == expected_height, "snapshot is of another height");
    let root: [u8; 32] = reader.array()?;
    ensure!(
        root == expected_root,
        "snapshot does not declare the trusted application hash"
    );
    let _request_fingerprint: [u8; 32] = reader.array()?;
    let leaves = u64::from_be_bytes(reader.array()?);
    let metadata_length = u32::from_be_bytes(reader.array()?) as usize;
    ensure!(metadata_length <= MAX_VALUE_BYTES, "snapshot metadata too large");
    let metadata = reader.vec(metadata_length)?;
    ensure!(
        leaves > 0 && leaves <= reader.remaining / 7,
        "snapshot row count is impossible"
    );
    let mut stream = merkle::StreamingRoot::new();
    let mut meta_row_matches = false;
    for _ in 0..leaves {
        let key_length = u16::from_be_bytes(reader.array()?) as usize;
        ensure!(
            key_length > 0 && key_length <= MAX_KEY_BYTES,
            "snapshot key length out of range"
        );
        let key = reader.vec(key_length)?;
        let value_length = u32::from_be_bytes(reader.array()?) as usize;
        ensure!(value_length <= MAX_VALUE_BYTES, "snapshot value too large");
        let value = reader.vec(value_length)?;
        if key == META_KEY {
            meta_row_matches = value == metadata;
        }
        let hash = key_hash(&key);
        // Refuses rows out of key-hash order and a key twice.
        stream.push(&hash, merkle::leaf_hash(&hash, &merkle::value_hash(&value)))?;
    }
    ensure!(reader.remaining == 0, "snapshot has trailing rows");
    let HashingReader {
        mut inner, hasher, ..
    } = reader;
    let mut stored = [0u8; 32];
    inner.read_exact(&mut stored)?;
    let computed: [u8; 32] = hasher.finalize().into();
    ensure!(stored == computed, "snapshot checksum mismatch");
    ensure!(
        stream.finish() == expected_root,
        "snapshot rows do not hash to the trusted application hash"
    );
    ensure!(
        meta_row_matches,
        "snapshot metadata differs from its meta row"
    );
    Ok(())
}

/// Reads a snapshot and rebuilds its tree. The file's checksum, the Merkle
/// root recomputed from the rows, and the metadata row must all match.
fn load_snapshot(path: &Path, expected_height: u64) -> Result<Version> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    ensure!(length >= 16 + 8 + 32 + 32 + 8 + 4 + 32, "snapshot is too short");
    let mut reader = HashingReader {
        inner: BufReader::with_capacity(4 * 1024 * 1024, file),
        hasher: Sha256::new(),
        remaining: length - 32,
    };
    ensure!(
        &reader.array::<16>()? == SNAPSHOT_MAGIC,
        "not a version-5 state snapshot"
    );
    let height = u64::from_be_bytes(reader.array()?);
    ensure!(height == expected_height, "snapshot height differs from its file name");
    let root: [u8; 32] = reader.array()?;
    let request_fingerprint: [u8; 32] = reader.array()?;
    let leaves = u64::from_be_bytes(reader.array()?);
    let metadata_length = u32::from_be_bytes(reader.array()?) as usize;
    ensure!(metadata_length <= MAX_VALUE_BYTES, "snapshot metadata too large");
    let metadata = reader.vec(metadata_length)?;
    // Each row takes at least 7 bytes on disk.
    ensure!(leaves <= reader.remaining / 7, "snapshot row count is impossible");
    // The count is not authenticated yet: reserve a bounded amount and grow.
    let mut rows: Vec<(Vec<u8>, Arc<[u8]>)> =
        Vec::with_capacity(usize::try_from(leaves)?.min(1 << 20));
    for _ in 0..leaves {
        let key_length = u16::from_be_bytes(reader.array()?) as usize;
        ensure!(
            key_length > 0 && key_length <= MAX_KEY_BYTES,
            "snapshot key length out of range"
        );
        let key = reader.vec(key_length)?;
        let value_length = u32::from_be_bytes(reader.array()?) as usize;
        ensure!(value_length <= MAX_VALUE_BYTES, "snapshot value too large");
        let value = reader.vec(value_length)?;
        rows.push((key, Arc::from(value)));
    }
    ensure!(reader.remaining == 0, "snapshot has trailing rows");
    let HashingReader {
        mut inner, hasher, ..
    } = reader;
    let mut stored = [0u8; 32];
    inner.read_exact(&mut stored)?;
    let computed: [u8; 32] = hasher.finalize().into();
    ensure!(stored == computed, "snapshot checksum mismatch");
    let ops: Vec<Op> = rows
        .par_iter()
        .map(|(key, value)| {
            let hash = key_hash(key);
            Op {
                key_hash: hash,
                leaf: Some(merkle::new_leaf(key, hash, value.clone())),
            }
        })
        .collect();
    // Rows are written in key-hash order; `update` rejects any other order
    // and any duplicate.
    let tree = merkle::update(&None, &ops)?;
    ensure!(
        merkle::root_hash(&tree) == root,
        "snapshot rows do not hash to the recorded root"
    );
    ensure!(
        merkle::get(&tree, &key_hash(META_KEY)).map(|leaf| leaf.value().as_ref())
            == Some(metadata.as_slice()),
        "snapshot metadata differs from its meta row"
    );
    if leaves == 0 {
        bail!("snapshot holds no rows");
    }
    Ok(Version {
        head: Head {
            version: height,
            root,
            request_fingerprint,
            metadata,
        },
        tree,
        // A loaded snapshot is the base everything else shares.
        changed_rows: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(height: u64, extra: &[(&[u8], Option<&[u8]>)]) -> Vec<Update> {
        let mut updates = vec![(
            META_KEY.to_vec(),
            Some(format!("{{\"height\":\"{height}\"}}").into_bytes()),
        )];
        updates.extend(
            extra
                .iter()
                .map(|(key, value)| (key.to_vec(), value.map(<[u8]>::to_vec))),
        );
        updates
    }
    fn commit(store: &Store, height: u64, extra: &[(&[u8], Option<&[u8]>)]) -> Head {
        let base = store.current().unwrap();
        let updates = batch(height, extra);
        let meta = updates[0].1.clone().unwrap();
        let mut prepared = store.prepare(base.as_ref(), height, updates).unwrap();
        prepared.set_head_metadata(meta, [height as u8; 32]).unwrap();
        store.commit(prepared).unwrap()
    }

    #[test]
    fn versions_proofs_and_stale_commits() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.current().unwrap().is_none());
        let genesis = commit(&store, 0, &[(b"name/alice", Some(b"\"1\""))]);
        let one = commit(&store, 1, &[(b"name/bob", Some(b"\"2\""))]);
        assert_ne!(genesis.root, one.root);
        let old = store.version(0).unwrap();
        assert_eq!(old.get(b"name/bob"), None);
        assert_eq!(
            store.version(1).unwrap().get(b"name/bob").as_deref(),
            Some(&b"\"2\""[..])
        );
        // Proofs are bound to their own version's root.
        let entry = old.proof(b"name/bob").unwrap();
        assert_eq!(entry.verify(genesis.root, b"name/bob").unwrap(), None);
        assert!(entry.verify(one.root, b"name/bob").is_err());
        // A second version prepared from the same parent can no longer commit.
        let base = store.version(0).unwrap();
        let updates = batch(1, &[(b"name/carol", Some(b"\"3\""))]);
        let meta = updates[0].1.clone().unwrap();
        let mut stale = store.prepare(Some(&base), 1, updates).unwrap();
        stale.set_head_metadata(meta, [0; 32]).unwrap();
        assert!(store.commit(stale).is_err());
        // Batches without the meta row, with duplicates or wrong heights are refused.
        let current = store.current().unwrap();
        assert!(store
            .prepare(current.as_ref(), 2, vec![(b"x".to_vec(), Some(vec![1]))])
            .is_err());
        assert!(store
            .prepare(current.as_ref(), 2, batch(2, &[(b"x", Some(b"1")), (b"x", Some(b"2"))]))
            .is_err());
        assert!(store.prepare(current.as_ref(), 3, batch(3, &[])).is_err());
    }

    #[test]
    fn snapshot_round_trip_and_corruption_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let (head, path) = {
            let store = Store::open(directory.path()).unwrap();
            commit(&store, 0, &[(b"name/alice", Some(b"\"1\""))]);
            let rows: Vec<(Vec<u8>, Vec<u8>)> = (0u32..2000)
                .map(|i| (format!("account/{i}").into_bytes(), vec![i as u8; 40]))
                .collect();
            let extra: Vec<(&[u8], Option<&[u8]>)> = rows
                .iter()
                .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
                .collect();
            let head = commit(&store, 1, &extra);
            // A second process cannot open the same directory.
            assert!(Store::open(directory.path()).is_err());
            let info = store
                .write_snapshot(&store.current().unwrap().unwrap())
                .unwrap();
            assert_eq!(info.height, 1);
            (head, info.path)
        };
        {
            let reopened = Store::open(directory.path()).unwrap();
            let current = reopened.current().unwrap().unwrap();
            assert_eq!(current.head(), &head);
            assert_eq!(current.leaf_count(), 2002);
            let audit = current.audit_verified(|_| {}).unwrap();
            let mut seen = 0;
            audit
                .for_each_prefix(b"account/", |_, _| {
                    seen += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(seen, 2000);
        }
        // Flip one byte in the middle of the file: the snapshot must be refused,
        // and with no other snapshot the store must not open as empty.
        let mut bytes = fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert!(Store::open(directory.path()).is_err());
        // Truncation is refused as well.
        bytes[middle] ^= 0x01;
        bytes.truncate(bytes.len() - 5);
        fs::write(&path, &bytes).unwrap();
        assert!(Store::open(directory.path()).is_err());
    }

    #[test]
    fn older_snapshot_is_used_when_the_newest_is_damaged() {
        let directory = tempfile::tempdir().unwrap();
        let first = {
            let store = Store::open(directory.path()).unwrap();
            let first = commit(&store, 0, &[(b"a", Some(b"1"))]);
            store
                .write_snapshot(&store.current().unwrap().unwrap())
                .unwrap();
            commit(&store, 1, &[(b"b", Some(b"2"))]);
            let info = store
                .write_snapshot(&store.current().unwrap().unwrap())
                .unwrap();
            let mut bytes = fs::read(&info.path).unwrap();
            let last = bytes.len() - 1;
            bytes[last] ^= 0xff;
            fs::write(&info.path, bytes).unwrap();
            first
        };
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(reopened.head().unwrap().unwrap(), first);
        // The damaged file was set aside: it is no snapshot any more, and the
        // good one is still there.
        let names: Vec<String> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|name| name.starts_with("damaged-state-")), "{names:?}");
        assert_eq!(snapshot_files(directory.path()).unwrap().len(), 1);
        // The chain moves on to the height of the damaged file and saves it
        // again; both snapshots on disk are good ones.
        let second = commit(&reopened, 1, &[(b"b", Some(b"2"))]);
        reopened
            .write_snapshot(&reopened.current().unwrap().unwrap())
            .unwrap();
        // A stray file under the next snapshot's name is replaced, not trusted.
        let third = commit(&reopened, 2, &[(b"c", Some(b"3"))]);
        fs::write(snapshot_path(directory.path(), 2), b"not a snapshot").unwrap();
        reopened
            .write_snapshot(&reopened.current().unwrap().unwrap())
            .unwrap();
        assert_eq!(reopened.snapshot_height().unwrap(), Some(2));
        drop(reopened);
        let again = Store::open(directory.path()).unwrap();
        assert_eq!(again.head().unwrap().unwrap(), third);
        drop(again);
        // With the newest one gone, the one before it still loads.
        fs::remove_file(snapshot_path(directory.path(), 2)).unwrap();
        assert_eq!(Store::open(directory.path()).unwrap().head().unwrap().unwrap(), second);
    }

    #[test]
    fn retained_versions_are_bounded_by_count_and_by_changed_rows() {
        let directory = tempfile::tempdir().unwrap();
        let options = StoreOptions {
            retained_versions: 8,
            retained_rows: 40,
            ..StoreOptions::default()
        };
        let store = Store::open_with_options(directory.path(), options).unwrap();
        // Small versions (one row plus the meta row): the count limit applies.
        for height in 0..12u64 {
            commit(&store, height, &[(b"k", Some(&height.to_be_bytes()))]);
        }
        assert_eq!(store.oldest_retained().unwrap(), Some(4));
        // Large versions (eleven rows each): the row budget applies, but the
        // newest four are always kept.
        for height in 12..20u64 {
            let rows: Vec<(Vec<u8>, Vec<u8>)> = (0..10u8)
                .map(|i| (vec![b'r', i], height.to_be_bytes().to_vec()))
                .collect();
            let extra: Vec<(&[u8], Option<&[u8]>)> = rows
                .iter()
                .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
                .collect();
            commit(&store, height, &extra);
        }
        assert_eq!(store.oldest_retained().unwrap(), Some(16));
        assert!(store.version(15).is_err());
        assert_eq!(
            store.version(16).unwrap().get(b"k").as_deref(),
            Some(&11u64.to_be_bytes()[..])
        );
        assert_eq!(store.current().unwrap().unwrap().height(), 19);
    }

    #[test]
    fn reading_the_snapshot_height_never_waits_for_a_snapshot_write() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path()).unwrap());
        assert_eq!(store.snapshot_height().unwrap(), None);
        commit(&store, 0, &[(b"a", Some(b"1"))]);
        store
            .write_snapshot(&store.current().unwrap().unwrap())
            .unwrap();
        // A snapshot write holds this lock for its whole duration.
        let writing = store.snapshot_writer.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = store.clone();
        std::thread::spawn(move || sender.send(reader.snapshot_height().unwrap()).unwrap());
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            Some(0)
        );
        drop(writing);
    }

    /// Reads a snapshot's rows, lets the caller change them, and writes the
    /// file back with a correct checksum.
    fn rewrite(path: &Path, change: impl FnOnce(&mut Vec<(Vec<u8>, Vec<u8>)>, &mut u64)) {
        let bytes = fs::read(path).unwrap();
        let mut at = 16 + 8 + 32 + 32;
        let mut leaves = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
        at += 8;
        let metadata = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + metadata;
        let header = bytes[..at].to_vec();
        let mut rows = Vec::new();
        while at < bytes.len() - 32 {
            let key = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
            let key_bytes = bytes[at + 2..at + 2 + key].to_vec();
            at += 2 + key;
            let value = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            rows.push((key_bytes, bytes[at + 4..at + 4 + value].to_vec()));
            at += 4 + value;
        }
        change(&mut rows, &mut leaves);
        let mut out = header;
        out[88..96].copy_from_slice(&leaves.to_be_bytes());
        for (key, value) in rows {
            out.extend((key.len() as u16).to_be_bytes());
            out.extend(key);
            out.extend((value.len() as u32).to_be_bytes());
            out.extend(value);
        }
        let digest: [u8; 32] = Sha256::digest(&out).into();
        out.extend(digest);
        fs::write(path, out).unwrap();
    }

    #[test]
    fn the_streaming_check_accepts_what_loads_and_refuses_what_does_not() {
        let directory = tempfile::tempdir().unwrap();
        let (path, height, root) = {
            let store = Store::open(directory.path()).unwrap();
            commit(&store, 0, &[(b"a", Some(b"1"))]);
            let rows: Vec<(Vec<u8>, Vec<u8>)> = (0u32..3000)
                .map(|i| (format!("account/{i}").into_bytes(), vec![i as u8; (i % 90) as usize]))
                .collect();
            let extra: Vec<(&[u8], Option<&[u8]>)> = rows
                .iter()
                .map(|(key, value)| (key.as_slice(), Some(value.as_slice())))
                .collect();
            let head = commit(&store, 1, &extra);
            let info = store
                .write_snapshot(&store.current().unwrap().unwrap())
                .unwrap();
            (info.path, head.version, head.root)
        };
        let original = fs::read(&path).unwrap();
        check_snapshot_root(&path, height, root).unwrap();
        assert_eq!(load_snapshot(&path, height).unwrap().root(), root);
        // Another height or another root than the one asked for.
        assert!(check_snapshot_root(&path, height + 1, root).is_err());
        assert!(check_snapshot_root(&path, height, [7; 32]).is_err());
        // Every change the loader refuses, the streaming check refuses too.
        let changes: Vec<Box<dyn Fn(&mut Vec<(Vec<u8>, Vec<u8>)>, &mut u64)>> = vec![
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, _: &mut u64| rows.swap(10, 11)),
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| {
                rows.push(rows[0].clone());
                *leaves += 1;
            }),
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, _: &mut u64| rows[1].1 = b"9".to_vec()),
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| {
                rows.pop();
                *leaves -= 1;
            }),
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| {
                rows.insert(0, (b"zz".to_vec(), b"1".to_vec()));
                *leaves += 1;
            }),
            Box::new(|_: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| *leaves += 1),
            Box::new(|_: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| *leaves -= 1),
            Box::new(|_: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| *leaves = u64::MAX / 2),
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, leaves: &mut u64| {
                rows.clear();
                *leaves = 0;
            }),
            // The metadata row itself.
            Box::new(|rows: &mut Vec<(Vec<u8>, Vec<u8>)>, _: &mut u64| {
                let meta = rows.iter_mut().find(|(key, _)| key.as_slice() == META_KEY).unwrap();
                meta.1.push(b' ');
            }),
        ];
        for (index, change) in changes.iter().enumerate() {
            fs::write(&path, &original).unwrap();
            rewrite(&path, |rows, leaves| change(rows, leaves));
            assert!(load_snapshot(&path, height).is_err(), "change {index} loads");
            assert!(check_snapshot_root(&path, height, root).is_err(), "change {index} passes");
        }
        // The helper itself changes nothing: an untouched file passes both.
        fs::write(&path, &original).unwrap();
        rewrite(&path, |_, _| {});
        check_snapshot_root(&path, height, root).unwrap();
        // A flipped byte anywhere, a missing tail, bytes after the end.
        for at in [0, 20, 40, 70, 90, 97, 120, original.len() / 2, original.len() - 40, original.len() - 1] {
            let mut bytes = original.clone();
            bytes[at] ^= 0x04;
            fs::write(&path, &bytes).unwrap();
            // (Byte 70 is in the request fingerprint, which no hash but the
            // file's checksum covers: the checksum catches it.)
            assert!(check_snapshot_root(&path, height, root).is_err(), "byte {at}");
        }
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(check_snapshot_root(&path, height, root).is_err());
        fs::write(&path, [original.as_slice(), &[0u8][..]].concat()).unwrap();
        assert!(check_snapshot_root(&path, height, root).is_err());
        fs::write(&path, &original[..100]).unwrap();
        assert!(check_snapshot_root(&path, height, root).is_err());
    }

    #[test]
    fn a_chunk_nobody_offers_is_a_miss_and_a_damaged_snapshot_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let options = StoreOptions {
            sync_snapshots_kept: 2,
            sync_chunk_bytes: 1024,
            ..StoreOptions::default()
        };
        let store = Store::open_with_options(directory.path(), options).unwrap();
        commit(&store, 0, &[(b"a", Some(&[7u8; 5000]))]);
        // Nothing is offered yet: every request is a miss, none an error.
        for index in [0, 1, u32::MAX] {
            assert!(store.load_sync_chunk(0, index).unwrap().is_none());
        }
        let info = store
            .write_sync_snapshot(&store.current().unwrap().unwrap())
            .unwrap()
            .unwrap();
        let chunks = store.sync_snapshots().unwrap()[0].chunks;
        assert!(chunks > 4);
        assert_eq!(store.load_sync_chunk(0, 0).unwrap().unwrap().len(), 1024);
        // Beyond the last chunk, another height: misses.
        assert!(store.load_sync_chunk(0, chunks).unwrap().is_none());
        assert!(store.load_sync_chunk(1, 0).unwrap().is_none());
        // The file is damaged: the chunk is an error once, the snapshot and
        // its manifest are gone, and from then on it is a miss.
        let mut bytes = fs::read(&info.path).unwrap();
        bytes[2500] ^= 1;
        fs::write(&info.path, bytes).unwrap();
        assert!(store.load_sync_chunk(0, 2).is_err());
        assert!(store.load_sync_chunk(0, 2).unwrap().is_none());
        assert!(store.load_sync_chunk(0, 0).unwrap().is_none());
        assert!(store.sync_snapshots().unwrap().is_empty());
        assert!(!info.path.exists());
        assert!(!info.path.with_extension("manifest").exists());
        // A restart does not find it again.
        drop(store);
        let store = Store::open_with_options(directory.path(), options).unwrap();
        assert!(store.sync_snapshots().unwrap().is_empty());
    }

    #[test]
    fn snapshots_with_wrong_rows_or_counts_are_refused_even_with_a_valid_checksum() {
        let directory = tempfile::tempdir().unwrap();
        let path = {
            let store = Store::open(directory.path()).unwrap();
            commit(&store, 0, &[(b"a", Some(b"1")), (b"b", Some(b"2")), (b"c", Some(b"3"))]);
            store
                .write_snapshot(&store.current().unwrap().unwrap())
                .unwrap()
                .path
        };
        let original = fs::read(&path).unwrap();
        let attempt = |change: &dyn Fn(&mut Vec<(Vec<u8>, Vec<u8>)>, &mut u64)| -> String {
            fs::write(&path, &original).unwrap();
            rewrite(&path, |rows, leaves| change(rows, leaves));
            match Store::open(directory.path()) {
                Ok(_) => "accepted".into(),
                Err(error) => format!("{error:#}"),
            }
        };
        // The untouched file, rewritten by the helper, still loads.
        assert_eq!(attempt(&|_, _| {}), "accepted");
        // Rows out of order, a row twice, a changed value, a missing row.
        assert_ne!(attempt(&|rows, _| rows.swap(0, 1)), "accepted");
        assert_ne!(attempt(&|rows, leaves| { rows.push(rows[0].clone()); *leaves += 1; }), "accepted");
        assert_ne!(attempt(&|rows, _| rows[1].1 = b"9".to_vec()), "accepted");
        assert_ne!(attempt(&|rows, leaves| { rows.pop(); *leaves -= 1; }), "accepted");
        // A row count that disagrees with the rows, including an absurd one:
        // an error, not an attempt to reserve memory for it.
        assert_ne!(attempt(&|_, leaves| *leaves += 1), "accepted");
        assert_ne!(attempt(&|_, leaves| *leaves -= 1), "accepted");
        assert_ne!(attempt(&|_, leaves| *leaves = u64::MAX / 2), "accepted");
        assert_ne!(attempt(&|rows, leaves| { rows.clear(); *leaves = 0; }), "accepted");
        // Nothing was set aside or deleted while no snapshot could be loaded.
        assert_eq!(snapshot_files(directory.path()).unwrap().len(), 1);
    }
}
