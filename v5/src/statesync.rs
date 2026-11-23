//! State sync (joining from a snapshot) and block pruning.
//!
//! Nothing here is a consensus rule: no state row and no root depends on it.
//!
//! **What is transferred.** A state snapshot file exactly as `crate::store`
//! writes it for a restart (magic, height, root, rows in key-hash order,
//! checksum), cut into chunks of a fixed size. The ABCI snapshot `metadata`
//! is a `Manifest`: the file length, the chunk size and the SHA-256 of every
//! chunk. The ABCI snapshot `hash` is the SHA-256 of that metadata. Two nodes
//! that snapshot the same height produce the same bytes, so CometBFT pools
//! them as one snapshot and fetches chunks from all of them.
//!
//! **What is trusted.** Only the application hash CometBFT passes with
//! `OfferSnapshot`, which its light client verified. The manifest and the
//! chunks are hostile input:
//!
//! - a chunk is written to the staging file only if its length and SHA-256
//!   match the manifest of the accepted offer; otherwise it is refetched and
//!   its sender rejected;
//! - the first chunk must carry the offered height and the trusted hash;
//! - when the last chunk has arrived the whole file is read back, its rows
//!   are hashed into a tree, and that tree's root must be the trusted hash
//!   (`Store::verify_staged`). Only then does anything replace the node's
//!   state. A snapshot that fails here is rejected with every peer that sent
//!   a chunk of it.
//!
//! **Bounds.** While chunks arrive, memory is one chunk as CometBFT handed
//! it over plus the manifest (32 bytes per chunk, at most
//! `SYNC_MAX_CHUNKS`). A peer can make a chunk 16 MB, whatever the manifest
//! says; the transport holds it twice for a moment (the frame and the
//! decoded request), and a chunk of the wrong length or hash is refused
//! here without being written. Disk is the length the manifest declared,
//! which the offer refuses above the node's limit (`--state-sync-max-mib`).
//!
//! When the last chunk has arrived the file is checked in a first pass that
//! keeps no row (`Store::verify_staged`, `merkle::StreamingRoot`): a read
//! buffer, one row, and at most 256 hashes, whatever the file holds. A
//! forged snapshot, whose rows cannot hash to the trusted application hash,
//! is refused there, at that cost. Only a file that passed, which is the
//! chain's own state at that height, is then read into memory and built
//! into the tree, and that takes what the state takes in a running node.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// The one snapshot format this engine offers and accepts.
pub const SYNC_FORMAT: u32 = 1;
/// Chunk size of the snapshots this node offers. A chunk this node serves
/// must fit one ABCI answer (`transport::MAX_FRAME_BYTES`, 8 MiB) and one
/// CometBFT chunk message (16 MB). What a peer sends as a chunk need not be
/// this size: see `transport::MAX_REQUEST_FRAME_BYTES`.
pub const SYNC_CHUNK_BYTES: u32 = 4 * 1024 * 1024;
/// Smallest chunk size accepted from a peer (the last chunk may be shorter).
pub const SYNC_MIN_CHUNK_BYTES: u32 = 1024;
/// Most chunks of one snapshot: CometBFT's own default limit
/// (`statesync.max_snapshot_chunks`), and 3.2 MB of manifest, below its
/// 4 MB snapshot message.
pub const SYNC_MAX_CHUNKS: u32 = 100_000;
/// Default of `--state-sync-max-mib`: the largest snapshot a node restores.
pub const DEFAULT_RESTORE_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// The evidence window the application sets in the consensus parameters
/// (`app::consensus_params`): CometBFT accepts evidence of a height until it
/// is older than this many blocks *and* older than 14 days.
pub const EVIDENCE_MAX_AGE_BLOCKS: u64 = 2_000_000;
pub const EVIDENCE_MAX_AGE_SECONDS: u64 = 14 * 86400;
const MANIFEST_MAGIC: &[u8; 16] = b"TIMEV5STATESYNC\x01";
const MANIFEST_HEADER: usize = 16 + 8 + 4;
/// Longest sender name remembered (a CometBFT node id is 40 characters).
const MAX_SENDER_BYTES: usize = 128;
/// Most distinct senders remembered for one restore.
const MAX_SENDERS: usize = 1024;

/// What the settings of a node decide about snapshots for peers, restores
/// and pruning. `Default` is a node that offers nothing and keeps every
/// block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeOptions {
    /// Blocks CometBFT is asked to keep (`--keep-blocks`). 0: all of them.
    pub keep_blocks: u64,
    /// A snapshot for peers is written at every height that is a multiple of
    /// this (`--state-sync-snapshot-blocks`). 0: none are written or offered.
    pub sync_snapshot_blocks: u64,
    /// Snapshots for peers kept on disk (`--state-sync-snapshots-kept`).
    pub sync_snapshots_kept: usize,
    /// Largest snapshot this node restores (`--state-sync-max-mib`).
    pub restore_max_bytes: u64,
    /// Chunk size of the snapshots this node writes for peers. Every node
    /// must use the same value for their snapshots to be pooled; the node
    /// binary never changes it. Tests use small chunks.
    pub sync_chunk_bytes: u32,
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            keep_blocks: 0,
            sync_snapshot_blocks: 0,
            sync_snapshots_kept: 2,
            restore_max_bytes: DEFAULT_RESTORE_MAX_BYTES,
            sync_chunk_bytes: SYNC_CHUNK_BYTES,
        }
    }
}

impl NodeOptions {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.keep_blocks == 0 || self.keep_blocks >= EVIDENCE_MAX_AGE_BLOCKS,
            "blocks to keep must be 0 (all) or at least the evidence window"
        );
        ensure!(
            (1..=10).contains(&self.sync_snapshots_kept),
            "between 1 and 10 state-sync snapshots are kept"
        );
        ensure!(
            (SYNC_MIN_CHUNK_BYTES..=SYNC_CHUNK_BYTES).contains(&self.sync_chunk_bytes),
            "state-sync chunk size out of range"
        );
        ensure!(self.restore_max_bytes > 0, "restore limit must be positive");
        Ok(())
    }
}

/// The ABCI `metadata` of a snapshot: how the file is cut and what each
/// chunk hashes to. It has exactly one encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub total_bytes: u64,
    pub chunk_bytes: u32,
    pub chunk_hashes: Vec<[u8; 32]>,
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MANIFEST_HEADER + 32 * self.chunk_hashes.len());
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&self.total_bytes.to_be_bytes());
        out.extend_from_slice(&self.chunk_bytes.to_be_bytes());
        for hash in &self.chunk_hashes {
            out.extend_from_slice(hash);
        }
        out
    }
    /// Reads a manifest, refusing every shape but the one `encode` writes
    /// for a file of `total_bytes`: the chunk count must be the one that
    /// length and chunk size give.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= MANIFEST_HEADER + 32
                && bytes.len() <= MANIFEST_HEADER + 32 * SYNC_MAX_CHUNKS as usize
                && (bytes.len() - MANIFEST_HEADER) % 32 == 0,
            "snapshot metadata length"
        );
        ensure!(&bytes[..16] == MANIFEST_MAGIC, "not version-5 snapshot metadata");
        let total_bytes = u64::from_be_bytes(bytes[16..24].try_into()?);
        let chunk_bytes = u32::from_be_bytes(bytes[24..28].try_into()?);
        ensure!(
            (SYNC_MIN_CHUNK_BYTES..=SYNC_CHUNK_BYTES).contains(&chunk_bytes),
            "snapshot chunk size out of range"
        );
        let chunks = (bytes.len() - MANIFEST_HEADER) / 32;
        ensure!(
            total_bytes >= crate::store::SNAPSHOT_MIN_BYTES
                && total_bytes.div_ceil(u64::from(chunk_bytes)) == chunks as u64,
            "snapshot length disagrees with its chunk count"
        );
        Ok(Self {
            total_bytes,
            chunk_bytes,
            chunk_hashes: bytes[MANIFEST_HEADER..]
                .chunks_exact(32)
                .map(|hash| hash.try_into().expect("32-byte slice"))
                .collect(),
        })
    }
    pub fn chunks(&self) -> u32 {
        self.chunk_hashes.len() as u32
    }
    /// Length of chunk `index`: the chunk size, except for the last.
    pub fn chunk_len(&self, index: u32) -> Option<usize> {
        let start = u64::from(index).checked_mul(u64::from(self.chunk_bytes))?;
        (index < self.chunks())
            .then(|| (self.total_bytes - start).min(u64::from(self.chunk_bytes)) as usize)
    }
}

/// The ABCI `hash` of a snapshot: SHA-256 of its metadata.
pub fn metadata_hash(metadata: &[u8]) -> [u8; 32] {
    Sha256::digest(metadata).into()
}

/// Which of a run of like log lines are printed. A peer can make a syncing
/// node refuse chunks for as long as the sync lasts (CometBFT goes on
/// handing over what a rejected peer sends), so the line for a refused chunk
/// is printed in full for the first few and then at most once per interval,
/// with the number left out.
#[derive(Debug, Default)]
pub struct LogLimiter {
    printed: u32,
    left_out: u64,
    last_summary: Option<Instant>,
}

/// What to print for one event.
#[derive(Debug, PartialEq, Eq)]
pub enum Logged {
    /// The line itself.
    Full,
    /// One line for this many events since the last line, this one included.
    Summary(u64),
    /// Nothing.
    Nothing,
}

impl LogLimiter {
    /// Events printed in full before the limit applies.
    pub const FIRST: u32 = 5;
    /// After that, at most one line per this interval.
    pub const INTERVAL: Duration = Duration::from_secs(60);
    /// Records one event at `now` and says what to print for it.
    pub fn note(&mut self, now: Instant) -> Logged {
        if self.printed < Self::FIRST {
            self.printed += 1;
            return Logged::Full;
        }
        self.left_out += 1;
        match self.last_summary {
            Some(last) if now.saturating_duration_since(last) < Self::INTERVAL => Logged::Nothing,
            _ => {
                self.last_summary = Some(now);
                Logged::Summary(std::mem::take(&mut self.left_out))
            }
        }
    }
}

/// What became of one chunk handed to a restore.
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk {
    /// Written to the staging file; more chunks are expected.
    Stored,
    /// Written, and it was the last one: the file is ready to be verified.
    Complete,
    /// Not the bytes the manifest names for this index (wrong length or
    /// hash). Nothing was written: refetch it and reject its sender.
    Corrupt,
    /// The chunk matches the manifest, but the snapshot is not one of the
    /// offered height and trusted hash: reject the snapshot and its senders.
    WrongSnapshot,
    /// Not the next chunk in order. Nothing was written.
    OutOfOrder,
}

/// One restore in progress: the accepted offer and the staging file.
pub struct Restore {
    height: u64,
    app_hash: [u8; 32],
    manifest: Manifest,
    path: PathBuf,
    file: File,
    next: u32,
    senders: BTreeSet<String>,
}

impl Restore {
    /// Starts a restore of the offered snapshot into the staging file
    /// `path`, which is created empty.
    pub fn begin(path: PathBuf, height: u64, app_hash: [u8; 32], manifest: Manifest) -> Result<Self> {
        let file = File::create(&path)
            .with_context(|| format!("create staging file {}", path.display()))?;
        Ok(Self {
            height,
            app_hash,
            manifest,
            path,
            file,
            next: 0,
            senders: BTreeSet::new(),
        })
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn app_hash(&self) -> [u8; 32] {
        self.app_hash
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Index of the chunk expected next.
    pub fn next(&self) -> u32 {
        self.next
    }
    /// Every peer that sent a chunk this restore stored.
    pub fn senders(&self) -> Vec<String> {
        self.senders.iter().cloned().collect()
    }
    /// Takes one chunk. An error is a failure of this machine (the staging
    /// file could not be written), never of the chunk.
    pub fn apply(&mut self, index: u32, chunk: &[u8], sender: &str) -> Result<Chunk> {
        if index != self.next {
            return Ok(Chunk::OutOfOrder);
        }
        let Some(length) = self.manifest.chunk_len(index) else {
            return Ok(Chunk::OutOfOrder);
        };
        if chunk.len() != length
            || <[u8; 32]>::from(Sha256::digest(chunk)) != self.manifest.chunk_hashes[index as usize]
        {
            return Ok(Chunk::Corrupt);
        }
        if sender.len() <= MAX_SENDER_BYTES && self.senders.len() < MAX_SENDERS {
            self.senders.insert(sender.to_owned());
        }
        if index == 0 && crate::store::snapshot_header(chunk) != Some((self.height, self.app_hash)) {
            return Ok(Chunk::WrongSnapshot);
        }
        self.file.write_all(chunk)?;
        self.next += 1;
        if self.next < self.manifest.chunks() {
            return Ok(Chunk::Stored);
        }
        self.file.sync_all()?;
        ensure!(
            self.file.metadata()?.len() == self.manifest.total_bytes,
            "staging file length differs from the chunks written"
        );
        Ok(Chunk::Complete)
    }
    /// Closes the staging file and returns where it is, for verification.
    pub fn close(self) -> PathBuf {
        let Self { path, file, .. } = self;
        drop(file);
        path
    }
    /// Ends the restore without using it and removes the staging file.
    pub fn discard(self) {
        let Self { path, file, .. } = self;
        drop(file);
        let _ = fs::remove_file(path);
    }
}

/// What `retain_height` is computed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainInputs {
    /// `--keep-blocks`; 0 keeps every block.
    pub keep_blocks: u64,
    /// Height of the block being committed.
    pub head: u64,
    /// Lowest height among the snapshot files this node restarts from.
    /// `None`: no snapshot is known, so nothing may be pruned.
    pub oldest_snapshot: Option<u64>,
    /// Lowest height among the snapshots this node offers to peers.
    pub oldest_sync_snapshot: Option<u64>,
    /// Every height up to this one is more than 14 days older than the head
    /// by block time: `Meta::history_pruned_through`, the heights whose
    /// block rows the ledger itself has already dropped for that reason.
    pub older_than_evidence_time: u64,
}

/// The `retain_height` of `ResponseCommit`: CometBFT may delete every block
/// below it. 0 means "delete nothing".
///
/// It is the highest height that keeps all of:
/// - the last `keep_blocks` blocks;
/// - every block after the oldest snapshot this node could restart from
///   (CometBFT replays them), and that snapshot's own block;
/// - the block of the oldest snapshot offered to peers and all later ones (a
///   peer restoring it fetches the headers of that height and the two after
///   it from this node's RPC, and then every later block);
/// - every block evidence can still name: a height is past evidence only
///   when it is more than `EVIDENCE_MAX_AGE_BLOCKS` below the head *and*
///   more than 14 days older than it.
pub fn retain_height(inputs: &RetainInputs) -> u64 {
    if inputs.keep_blocks == 0 {
        return 0;
    }
    let Some(oldest_snapshot) = inputs.oldest_snapshot else {
        return 0;
    };
    // The lowest height that must stay, under each rule.
    let wanted = (inputs.head + 1).saturating_sub(inputs.keep_blocks);
    let past_evidence = inputs
        .head
        .saturating_sub(EVIDENCE_MAX_AGE_BLOCKS + 1)
        .min(inputs.older_than_evidence_time);
    let mut retain = wanted.min(oldest_snapshot).min(past_evidence + 1);
    if let Some(offered) = inputs.oldest_sync_snapshot {
        retain = retain.min(offered);
    }
    // Heights start at 1: "keep from 1" deletes nothing.
    if retain <= 1 { 0 } else { retain }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(total: u64, chunk: u32) -> Manifest {
        Manifest {
            total_bytes: total,
            chunk_bytes: chunk,
            chunk_hashes: (0..total.div_ceil(u64::from(chunk)))
                .map(|index| [index as u8; 32])
                .collect(),
        }
    }

    #[test]
    fn a_manifest_has_one_encoding_and_every_other_shape_is_refused() {
        for (total, chunk) in [(132, 1024), (1024, 1024), (1025, 1024), (10_000, 4096), (5 << 22, SYNC_CHUNK_BYTES)] {
            let wanted = manifest(total, chunk);
            let bytes = wanted.encode();
            assert_eq!(Manifest::decode(&bytes).unwrap(), wanted);
            assert_eq!(
                (0..wanted.chunks()).map(|i| wanted.chunk_len(i).unwrap() as u64).sum::<u64>(),
                total
            );
            assert_eq!(wanted.chunk_len(wanted.chunks()), None);
            // One hash more or fewer, a byte more or fewer.
            let mut more = bytes.clone();
            more.extend([0; 32]);
            assert!(Manifest::decode(&more).is_err());
            assert!(Manifest::decode(&bytes[..bytes.len() - 32]).is_err());
            assert!(Manifest::decode(&bytes[..bytes.len() - 1]).is_err());
            let mut magic = bytes.clone();
            magic[0] ^= 1;
            assert!(Manifest::decode(&magic).is_err());
        }
        // Chunk sizes outside the accepted range, lengths no file can have.
        assert!(Manifest::decode(&manifest(4096, 512).encode()).is_err());
        let mut large = manifest(1 << 23, SYNC_CHUNK_BYTES).encode();
        large[24..28].copy_from_slice(&(SYNC_CHUNK_BYTES + 1).to_be_bytes());
        assert!(Manifest::decode(&large).is_err());
        assert!(Manifest::decode(&manifest(131, 1024).encode()).is_err());
        let mut zero = manifest(2048, 1024).encode();
        zero[16..24].copy_from_slice(&0u64.to_be_bytes());
        assert!(Manifest::decode(&zero).is_err());
        let mut huge = manifest(2048, 1024).encode();
        huge[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Manifest::decode(&huge).is_err());
        assert!(Manifest::decode(&[]).is_err());
        assert!(Manifest::decode(&[0; MANIFEST_HEADER]).is_err());
        // More chunks than a snapshot may have.
        let too_many = vec![0u8; MANIFEST_HEADER + 32 * (SYNC_MAX_CHUNKS as usize + 1)];
        assert!(Manifest::decode(&too_many).is_err());
    }

    fn inputs() -> RetainInputs {
        RetainInputs {
            keep_blocks: 3_000_000,
            head: 10_000_000,
            oldest_snapshot: Some(9_999_000),
            oldest_sync_snapshot: None,
            older_than_evidence_time: 8_500_000,
        }
    }

    #[test]
    fn retain_height_is_the_lowest_of_every_rule() {
        // The setting decides when nothing else needs more.
        assert_eq!(retain_height(&inputs()), 7_000_001);
        // The default keeps everything, whatever else is known.
        assert_eq!(retain_height(&RetainInputs { keep_blocks: 0, ..inputs() }), 0);
        // The node's own oldest snapshot: its block and all later ones stay.
        assert_eq!(
            retain_height(&RetainInputs { oldest_snapshot: Some(6_000_000), ..inputs() }),
            6_000_000
        );
        // No snapshot known: nothing is pruned. One at genesis: nothing either.
        assert_eq!(retain_height(&RetainInputs { oldest_snapshot: None, ..inputs() }), 0);
        assert_eq!(retain_height(&RetainInputs { oldest_snapshot: Some(0), ..inputs() }), 0);
        // A snapshot still offered to peers.
        assert_eq!(
            retain_height(&RetainInputs { oldest_sync_snapshot: Some(5_000_000), ..inputs() }),
            5_000_000
        );
        assert_eq!(
            retain_height(&RetainInputs { oldest_sync_snapshot: Some(9_000_000), ..inputs() }),
            7_000_001
        );
        // Evidence, by blocks: the last 2,000,000 heights below the head stay
        // even when the operator asks for fewer... which the flag refuses,
        // and which the rule holds on its own.
        assert_eq!(
            retain_height(&RetainInputs { keep_blocks: 2_000_000, ..inputs() }),
            10_000_000 - EVIDENCE_MAX_AGE_BLOCKS
        );
        assert_eq!(
            retain_height(&RetainInputs { keep_blocks: 1, ..inputs() }),
            10_000_000 - EVIDENCE_MAX_AGE_BLOCKS
        );
        // Evidence, by time: a height not yet 14 days old stays although
        // more than 2,000,000 blocks are above it (fast blocks).
        assert_eq!(
            retain_height(&RetainInputs { older_than_evidence_time: 4_000_000, ..inputs() }),
            4_000_001
        );
        assert_eq!(retain_height(&RetainInputs { older_than_evidence_time: 0, ..inputs() }), 0);
        // A chain shorter than the evidence window, or than what is kept.
        assert_eq!(
            retain_height(&RetainInputs {
                head: EVIDENCE_MAX_AGE_BLOCKS + 1,
                keep_blocks: EVIDENCE_MAX_AGE_BLOCKS,
                oldest_snapshot: Some(EVIDENCE_MAX_AGE_BLOCKS),
                older_than_evidence_time: EVIDENCE_MAX_AGE_BLOCKS,
                oldest_sync_snapshot: None,
            }),
            0
        );
        assert_eq!(
            retain_height(&RetainInputs {
                head: EVIDENCE_MAX_AGE_BLOCKS + 2,
                keep_blocks: EVIDENCE_MAX_AGE_BLOCKS,
                oldest_snapshot: Some(EVIDENCE_MAX_AGE_BLOCKS),
                older_than_evidence_time: EVIDENCE_MAX_AGE_BLOCKS,
                oldest_sync_snapshot: None,
            }),
            2
        );
        assert_eq!(retain_height(&RetainInputs { head: 5, ..inputs() }), 0);
        assert_eq!(retain_height(&RetainInputs { head: 0, oldest_snapshot: Some(0), ..inputs() }), 0);
    }

    #[test]
    fn what_retain_height_leaves_is_never_needed() {
        // Every combination of small values: each rule holds for the result.
        // (The evidence window is fixed, so heights are placed around it.)
        let base = 3 * EVIDENCE_MAX_AGE_BLOCKS;
        for keep in [EVIDENCE_MAX_AGE_BLOCKS, EVIDENCE_MAX_AGE_BLOCKS + 7, base] {
            for snapshot in [None, Some(0), Some(5), Some(base - 3), Some(base + 9)] {
                for offered in [None, Some(4), Some(base - 8), Some(base + 2)] {
                    for old in [0, 6, base - EVIDENCE_MAX_AGE_BLOCKS - 5, base - 2] {
                        for head in [base, base + 10, base + EVIDENCE_MAX_AGE_BLOCKS] {
                            let inputs = RetainInputs {
                                keep_blocks: keep,
                                head,
                                oldest_snapshot: snapshot,
                                oldest_sync_snapshot: offered,
                                older_than_evidence_time: old.min(head),
                            };
                            let retain = retain_height(&inputs);
                            assert!(retain <= head, "{inputs:?}");
                            if retain == 0 {
                                continue;
                            }
                            // The lowest block that goes is `retain - 1`.
                            let gone = retain - 1;
                            assert!(head - gone >= keep, "{inputs:?}");
                            assert!(gone < snapshot.unwrap(), "{inputs:?}");
                            assert!(offered.is_none_or(|height| gone < height), "{inputs:?}");
                            assert!(
                                head - gone > EVIDENCE_MAX_AGE_BLOCKS && gone <= inputs.older_than_evidence_time,
                                "{inputs:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_ledger_drops_block_rows_at_the_age_evidence_expires() {
        // `RetainInputs::older_than_evidence_time` is read from the ledger's
        // own cleanup (`Meta::history_pruned_through`), which removes the
        // rows of a block once it is older than `pos::UNBOND_DELAY`. That is
        // only the evidence age if the two durations are the same.
        assert_eq!(pos::UNBOND_DELAY, EVIDENCE_MAX_AGE_SECONDS * pos::SECOND);
        assert_eq!(EVIDENCE_MAX_AGE_BLOCKS, 2_000_000);
        assert_eq!(EVIDENCE_MAX_AGE_SECONDS, 14 * 86400);
    }

    #[test]
    fn like_log_lines_are_printed_a_few_times_and_then_once_per_interval() {
        let start = Instant::now();
        let at = |seconds: u64| start + Duration::from_secs(seconds);
        let mut limiter = LogLimiter::default();
        // The first five in full, however fast they come.
        for _ in 0..LogLimiter::FIRST {
            assert_eq!(limiter.note(at(0)), Logged::Full);
        }
        // The sixth says that lines are counted from here on.
        assert_eq!(limiter.note(at(0)), Logged::Summary(1));
        // Ten thousand more within the interval: not one line.
        for index in 0..10_000 {
            assert_eq!(limiter.note(at(index % 60)), Logged::Nothing);
        }
        // The first one after the interval: one line, with the count.
        assert_eq!(limiter.note(at(60)), Logged::Summary(10_001));
        assert_eq!(limiter.note(at(61)), Logged::Nothing);
        assert_eq!(limiter.note(at(119)), Logged::Nothing);
        assert_eq!(limiter.note(at(120)), Logged::Summary(3));
        // A whole day of one refusal a second: one line a minute, no more.
        let mut lines = 0;
        for second in 121..121 + 86_400 {
            if limiter.note(at(second)) != Logged::Nothing {
                lines += 1;
            }
        }
        assert_eq!(lines, 86_400 / 60);
        // A clock that steps back prints nothing extra.
        assert_eq!(limiter.note(at(0)), Logged::Nothing);
    }

    #[test]
    fn options_are_bounded() {
        NodeOptions::default().validate().unwrap();
        assert!(NodeOptions { keep_blocks: EVIDENCE_MAX_AGE_BLOCKS - 1, ..Default::default() }.validate().is_err());
        NodeOptions { keep_blocks: EVIDENCE_MAX_AGE_BLOCKS, ..Default::default() }.validate().unwrap();
        assert!(NodeOptions { sync_snapshots_kept: 0, ..Default::default() }.validate().is_err());
        assert!(NodeOptions { sync_snapshots_kept: 11, ..Default::default() }.validate().is_err());
        assert!(NodeOptions { sync_chunk_bytes: 512, ..Default::default() }.validate().is_err());
        assert!(NodeOptions { sync_chunk_bytes: SYNC_CHUNK_BYTES + 1, ..Default::default() }.validate().is_err());
        assert!(NodeOptions { restore_max_bytes: 0, ..Default::default() }.validate().is_err());
    }
}
