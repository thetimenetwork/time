//! Rebuildable local proof archive, separate from current authenticated state.
//! Persist an append before acknowledging its ledger Commit. A crash may leave
//! an uncommitted tail; a later append checks the trusted prefix before trimming.
use crate::*;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
const MAGIC: &[u8; 8] = b"TIMEHST1";
const HEADER: u64 = 40;
pub struct Archive {
    _writer_lock: File,
    network: Hash,
    leaves: File,
    nodes: File,
}
fn open_file(path: &Path, network: Hash) -> Result<File> {
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(MAGIC)?;
            file.write_all(&network)?;
            file.sync_all()?;
            file
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            OpenOptions::new().read(true).write(true).open(path)?
        }
        Err(e) => return Err(e.into()),
    };
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0; 40];
    file.read_exact(&mut header)?;
    ensure!(
        &header[..8] == MAGIC && header[8..] == network,
        "history archive network/format mismatch"
    );
    Ok(file)
}
fn offset(record: u64, width: u64) -> Result<u64> {
    record
        .checked_mul(width)
        .and_then(|n| n.checked_add(HEADER))
        .ok_or_else(|| anyhow!("archive offset overflow"))
}
impl Archive {
    pub fn open(directory: &Path, network: Hash) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        let writer_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("writer.lock"))?;
        writer_lock.try_lock().map_err(|_| {
            anyhow!("history archive already has a writer; never share it between live engines")
        })?;
        Ok(Self {
            _writer_lock: writer_lock,
            network,
            leaves: open_file(&directory.join("leaves.bin"), network)?,
            nodes: open_file(&directory.join("nodes.bin"), network)?,
        })
    }
    /// How many leaf records the archive file holds, entries of blocks and
    /// the absent records `seed` leaves alike.
    pub fn entries(&self) -> Result<u64> {
        Ok(self.leaves.metadata()?.len().saturating_sub(HEADER) / 40)
    }
    /// The height of the last block whose entry the archive holds above
    /// `floor`, or `floor` if it holds none there. An entry is made durable
    /// before its ledger Commit is acknowledged, and a replay does not cut
    /// the entries that follow the block it replays (`append_durable`): for
    /// a ledger whose saved state is at `floor`, this is the height of the
    /// last block it committed, or one more.
    ///
    /// A record that is all zero bytes is not an entry. `seed` leaves such
    /// records for the heights at and below a restored state, also when the
    /// restore then never happened; the entry of a block (its hash and its
    /// time) is never all zero.
    pub fn last_entry_above(&mut self, floor: u64) -> Result<u64> {
        const RECORDS: u64 = 4096;
        let mut end = self.entries()?;
        let mut buffer = vec![0u8; (RECORDS * 40) as usize];
        while end > floor {
            let start = end.saturating_sub(RECORDS).max(floor);
            let bytes = &mut buffer[..((end - start) * 40) as usize];
            self.leaves.seek(SeekFrom::Start(offset(start, 40)?))?;
            self.leaves.read_exact(bytes)?;
            for index in (0..end - start).rev() {
                let record = &bytes[(index * 40) as usize..((index + 1) * 40) as usize];
                if record.iter().any(|byte| *byte != 0) {
                    return Ok(start + index + 1);
                }
            }
            end = start;
        }
        Ok(floor)
    }
    /// Whether the files hold exactly `append` at its place: its leaf record
    /// and every node it adds.
    fn holds(&mut self, append: &Append, leaf_end: u64, node_end: u64) -> Result<bool> {
        let nodes = append.nodes.len() as u64 * 32;
        if self.leaves.metadata()?.len() < leaf_end + 40 || self.nodes.metadata()?.len() < node_end + nodes {
            return Ok(false);
        }
        let mut record = [0u8; 40];
        self.leaves.seek(SeekFrom::Start(leaf_end))?;
        self.leaves.read_exact(&mut record)?;
        if record[..32] != hash_bytes(&append.leaf.block_hash)? || record[32..] != append.leaf.time_micros.to_be_bytes() {
            return Ok(false);
        }
        self.nodes.seek(SeekFrom::Start(node_end))?;
        for hash in &append.nodes {
            let mut held = [0u8; 32];
            self.nodes.read_exact(&mut held)?;
            if held != *hash {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn verify_committed_prefix(&mut self, summary: &Summary) -> Result<()> {
        self.prefix(summary)
    }
    fn prefix(&mut self, summary: &Summary) -> Result<()> {
        summary.validate()?;
        ensure!(
            hash_bytes(&summary.network_id)? == self.network,
            "archive/trusted network mismatch"
        );
        ensure!(
            self.leaves.metadata()?.len() >= offset(summary.size, 40)?
                && self.nodes.metadata()?.len() >= offset(node_count(summary.size)?, 32)?,
            "history archive missing committed prefix; replay/recover archive before use"
        );
        if summary.size > 0 {
            let tree_root = subtree(self, 0, summary.size)?;
            ensure!(
                commit_root(self.network, summary.size, tree_root) == hash_bytes(&summary.root)?,
                "archive prefix differs from authenticated history root"
            );
        }
        Ok(())
    }
    /// `previous` MUST be the caller's CURRENT authenticated ledger summary,
    /// checked before this call under its commit lock. A merely old valid root
    /// cannot distinguish an uncommitted archive tail from committed history.
    pub fn append_durable(&mut self, append: &Append) -> Result<()> {
        let expected = append.previous.append(append.leaf.clone())?;
        ensure!(
            expected.summary == append.summary && expected.nodes == append.nodes,
            "invalid prepared history append"
        );
        self.prefix(&append.previous)?;
        let leaf_end = offset(append.previous.size, 40)?;
        let node_end = offset(node_count(append.previous.size)?, 32)?;
        // A replay. The archive already holds exactly this entry in this
        // place: its ledger was stopped after it had committed further than
        // its saved state, and is handed the same blocks again. Nothing is
        // written and nothing is cut. The entries after it are the record of
        // blocks this ledger committed, and a replay that is itself cut
        // short must not erase them (`last_entry_above`).
        if self.holds(append, leaf_end, node_end)? {
            self.leaves.sync_all()?;
            self.nodes.sync_all()?;
            return self.prefix(&append.summary);
        }
        self.leaves.set_len(leaf_end)?;
        self.nodes.set_len(node_end)?;
        self.leaves.seek(SeekFrom::Start(leaf_end))?;
        self.nodes.seek(SeekFrom::Start(node_end))?;
        self.leaves
            .write_all(&hash_bytes(&append.leaf.block_hash)?)?;
        self.leaves
            .write_all(&append.leaf.time_micros.to_be_bytes())?;
        for hash in &append.nodes {
            self.nodes.write_all(hash)?;
        }
        self.leaves.sync_all()?;
        self.nodes.sync_all()?;
        self.prefix(&append.summary)
    }
    /// Prepares the archive of a ledger whose state arrived without its
    /// history (restored from a state snapshot taken at `summary`). The files
    /// are extended to the committed length and only the frontier of
    /// `summary` (its peaks) is written, each at the position an append
    /// would have written it. That is everything `prefix` and every later
    /// append and proof of a later height read. Every leaf record at or
    /// below `summary.size` is absent (zero bytes) afterwards: `prove` fails
    /// its own verification for such a height, it never returns a forged
    /// proof, and a reader can tell a seeded archive from a full one.
    ///
    /// `summary` MUST be the caller's authenticated ledger summary. Leaf
    /// records the archive held are dropped, including entries beyond a
    /// committed prefix. Nodes are kept, and an existing peak is overwritten
    /// with the authenticated value: an archive seeded at a lower height
    /// still verifies as the prefix of that height, so a ledger that stays
    /// there after all can go on.
    pub fn seed(&mut self, summary: &Summary) -> Result<()> {
        summary.validate()?;
        ensure!(
            hash_bytes(&summary.network_id)? == self.network,
            "archive/trusted network mismatch"
        );
        let leaf_end = offset(summary.size, 40)?;
        let node_end = offset(node_count(summary.size)?, 32)?;
        // Truncated first, then extended: the extension is zero bytes.
        self.leaves.set_len(HEADER)?;
        self.leaves.set_len(leaf_end)?;
        if self.nodes.metadata()?.len() < node_end {
            self.nodes.set_len(node_end)?;
        }
        // Peaks are ordered left to right, one per set bit of the size, from
        // the highest bit down. A complete subtree of `size` leaves starting
        // at leaf `start` has its root at the position `subtree` reads.
        let mut start = 0u64;
        let mut peaks = summary.peaks.iter();
        for bit in (0..63).rev() {
            let size = 1u64 << bit;
            if summary.size & size == 0 {
                continue;
            }
            let peak = hash_bytes(peaks.next().ok_or_else(|| anyhow!("missing history frontier"))?)?;
            let position = node_count(start)?
                .checked_add(size * 2 - 2)
                .ok_or_else(|| anyhow!("node position overflow"))?;
            self.nodes.seek(SeekFrom::Start(offset(position, 32)?))?;
            self.nodes.write_all(&peak)?;
            start += size;
        }
        ensure!(peaks.next().is_none(), "history frontier has extra peaks");
        self.leaves.sync_all()?;
        self.nodes.sync_all()?;
        self.prefix(summary)
    }
    pub fn prove(&mut self, summary: &Summary, height: u64) -> Result<Proof> {
        self.prefix(summary)?;
        crate::prove(self, summary, height)
    }
    pub fn audit(&mut self, summary: &Summary, genesis_time_micros: u64) -> Result<()> {
        self.prefix(summary)?;
        let mut current = Summary::empty(self.network, genesis_time_micros);
        for h in 1..=summary.size {
            let a = current.append(self.leaf(h)?)?;
            let start = node_count(current.size)?;
            for (i, hash) in a.nodes.iter().enumerate() {
                ensure!(
                    self.node(start + i as u64)? == *hash,
                    "archive internal node mismatch"
                );
            }
            current = a.summary;
        }
        ensure!(current == *summary, "archive recount mismatch");
        Ok(())
    }
}
impl Reader for Archive {
    fn leaf(&mut self, height: u64) -> Result<Leaf> {
        ensure!(height > 0, "invalid archive leaf");
        self.leaves.seek(SeekFrom::Start(offset(height - 1, 40)?))?;
        let mut record = [0; 40];
        self.leaves.read_exact(&mut record)?;
        Ok(Leaf {
            height,
            block_hash: hex::encode(&record[..32]),
            time_micros: u64::from_be_bytes(record[32..].try_into()?),
        })
    }
    fn node(&mut self, position: u64) -> Result<Hash> {
        self.nodes.seek(SeekFrom::Start(offset(position, 32)?))?;
        let mut hash = [0; 32];
        self.nodes.read_exact(&mut hash)?;
        Ok(hash)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn leaf(h: u64, tag: u8) -> Leaf {
        Leaf {
            height: h,
            block_hash: hex::encode([tag; 32]),
            time_micros: 1000 + h,
        }
    }
    #[test]
    fn crash_ahead_tail_is_not_a_ledger_commit_and_can_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        let s = Summary::empty([9; 32], 1000);
        let a = s.append(leaf(1, 1)).unwrap();
        archive.append_durable(&a).unwrap();
        let committed = a.summary;
        let ahead = committed.append(leaf(2, 2)).unwrap();
        archive.append_durable(&ahead).unwrap();
        drop(archive);
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        let different = committed.append(leaf(2, 3)).unwrap();
        archive.append_durable(&different).unwrap();
        let proof = archive.prove(&different.summary, 2).unwrap();
        assert_eq!(proof.leaf.block_hash, hex::encode([3; 32]));
        assert!(proof.verify(&ahead.summary).is_err());
        archive.audit(&different.summary, 1000).unwrap();
        drop(archive);
        assert!(Archive::open(dir.path(), [8; 32]).is_err());
    }
    #[test]
    fn corrupted_archive_cannot_forge_a_proof_or_append_over_another_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        let mut s = Summary::empty([9; 32], 1000);
        for h in 1..=8 {
            let a = s.append(leaf(h, h as u8)).unwrap();
            archive.append_durable(&a).unwrap();
            s = a.summary;
        }
        archive.leaves.seek(SeekFrom::Start(HEADER)).unwrap();
        archive.leaves.write_all(&[0; 32]).unwrap();
        archive.leaves.sync_all().unwrap();
        assert!(archive.prove(&s, 1).is_err());
        assert!(archive.audit(&s, 1000).is_err());
        let mut bad = s.clone();
        bad.peaks[0] = hex::encode([0; 32]);
        bad.root = hex::encode(commit_root([9; 32], bad.size, [0; 32]));
        assert!(
            archive
                .append_durable(&bad.append(leaf(9, 9)).unwrap())
                .is_err()
        );
    }
    #[test]
    fn a_seeded_archive_appends_and_proves_later_heights_like_a_full_one() {
        // For every restore height: a full archive and one seeded with the
        // summary alone take the same later appends. Proofs of later heights
        // are identical; proofs at or below the restore height fail.
        for restored in 1..=20u64 {
            let full_dir = tempfile::tempdir().unwrap();
            let seeded_dir = tempfile::tempdir().unwrap();
            let mut full = Archive::open(full_dir.path(), [9; 32]).unwrap();
            let mut s = Summary::empty([9; 32], 1000);
            for h in 1..=restored {
                let a = s.append(leaf(h, h as u8)).unwrap();
                full.append_durable(&a).unwrap();
                s = a.summary;
            }
            let mut seeded = Archive::open(seeded_dir.path(), [9; 32]).unwrap();
            // An empty archive does not hold the committed prefix.
            assert!(seeded.verify_committed_prefix(&s).is_err());
            seeded.seed(&s).unwrap();
            seeded.verify_committed_prefix(&s).unwrap();
            // Seeding twice, and after a reopen, changes nothing.
            seeded.seed(&s).unwrap();
            drop(seeded);
            let mut seeded = Archive::open(seeded_dir.path(), [9; 32]).unwrap();
            seeded.verify_committed_prefix(&s).unwrap();
            for h in 1..=restored {
                assert!(seeded.prove(&s, h).is_err(), "restored {restored} height {h}");
            }
            for h in restored + 1..=restored + 37 {
                let a = s.append(leaf(h, h as u8)).unwrap();
                full.append_durable(&a).unwrap();
                seeded.append_durable(&a).unwrap();
                s = a.summary;
                for k in 1..=h {
                    let wanted = full.prove(&s, k).unwrap();
                    if k > restored {
                        assert_eq!(seeded.prove(&s, k).unwrap(), wanted);
                    } else {
                        assert!(seeded.prove(&s, k).is_err(), "restored {restored} size {h} height {k}");
                    }
                }
            }
            // The full recount needs every leaf: it refuses a seeded archive.
            full.audit(&s, 1000).unwrap();
            assert!(seeded.audit(&s, 1000).is_err());
        }
        // A summary of another network, or one that does not validate, is refused.
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        let other = Summary::empty([8; 32], 1000).append(leaf(1, 1)).unwrap().summary;
        assert!(archive.seed(&other).is_err());
        let mut bad = Summary::empty([9; 32], 1000).append(leaf(1, 1)).unwrap().summary;
        bad.peaks[0] = hex::encode([0; 32]);
        assert!(archive.seed(&bad).is_err());
    }
    #[test]
    fn seeding_drops_the_leaves_an_archive_held_and_keeps_its_frontier() {
        // An archive complete to height 5, with an entry for height 6 that
        // its ledger never committed, is seeded at height 13. No leaf at or
        // below 13 is held afterwards, the ledger can go on from 13, and a
        // ledger still at height 5 could go on from there too.
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        let mut s = Summary::empty([9; 32], 1000);
        for h in 1..=5 {
            let a = s.append(leaf(h, h as u8)).unwrap();
            archive.append_durable(&a).unwrap();
            s = a.summary;
        }
        let held = s.clone();
        archive.append_durable(&s.append(leaf(6, 66)).unwrap()).unwrap();
        for h in 6..=13 {
            s = s.append(leaf(h, h as u8)).unwrap().summary;
        }
        archive.seed(&s).unwrap();
        let absent = Leaf {
            height: 0,
            block_hash: hex::encode([0; 32]),
            time_micros: 0,
        };
        for h in 1..=13 {
            assert_eq!(archive.leaf(h).unwrap(), Leaf { height: h, ..absent.clone() });
        }
        assert!(archive.leaf(14).is_err());
        // The older summary still verifies: nothing it reads was changed.
        archive.verify_committed_prefix(&held).unwrap();
        let a = s.append(leaf(14, 14)).unwrap();
        archive.append_durable(&a).unwrap();
        assert_eq!(archive.prove(&a.summary, 14).unwrap().leaf, leaf(14, 14));
        assert!(archive.prove(&a.summary, 9).is_err());
    }
    #[test]
    fn review_seeded_archives_at_larger_sizes_match_a_full_one() {
        // Review test: restore heights around powers of two, each followed
        // by the same appends as a full archive, up to height 1200.
        let restores = [255u64, 256, 257, 511, 513, 1023, 1024, 1025];
        let full_dir = tempfile::tempdir().unwrap();
        let mut full = Archive::open(full_dir.path(), [9; 32]).unwrap();
        let mut seeded: Vec<(u64, tempfile::TempDir, Archive)> = Vec::new();
        let mut s = Summary::empty([9; 32], 1000);
        for h in 1..=1200u64 {
            let a = s.append(leaf(h, (h % 251) as u8)).unwrap();
            full.append_durable(&a).unwrap();
            for (_, _, archive) in seeded.iter_mut() {
                archive.append_durable(&a).unwrap();
            }
            s = a.summary;
            if restores.contains(&h) {
                let dir = tempfile::tempdir().unwrap();
                let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
                archive.seed(&s).unwrap();
                seeded.push((h, dir, archive));
            }
            if h % 97 == 0 || h == 1200 || restores.contains(&(h - 1)) {
                for (restored, _, archive) in seeded.iter_mut() {
                    for k in (1..=h).filter(|k| k % 7 == 0 || *k > h - 40 || k.abs_diff(*restored) < 3) {
                        let wanted = full.prove(&s, k).unwrap();
                        if k > *restored {
                            assert_eq!(archive.prove(&s, k).unwrap(), wanted, "restored {restored} size {h} height {k}");
                        } else {
                            assert!(archive.prove(&s, k).is_err(), "restored {restored} size {h} height {k}");
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn simultaneous_archive_writers_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let archive = Archive::open(dir.path(), [9; 32]).unwrap();
        assert!(Archive::open(dir.path(), [9; 32]).is_err());
        drop(archive);
        Archive::open(dir.path(), [9; 32]).unwrap();
    }
    #[test]
    fn entries_counts_the_blocks_whose_entry_was_made_durable() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        assert_eq!(archive.entries().unwrap(), 0);
        let mut s = Summary::empty([9; 32], 1000);
        for h in 1..=5u64 {
            let a = s.append(leaf(h, h as u8)).unwrap();
            archive.append_durable(&a).unwrap();
            s = a.summary;
            assert_eq!(archive.entries().unwrap(), h);
        }
        // An entry replaced by another for the same height is still one.
        let committed = Summary::empty([9; 32], 1000).append(leaf(1, 1)).unwrap().summary;
        archive.append_durable(&committed.append(leaf(2, 22)).unwrap()).unwrap();
        assert_eq!(archive.entries().unwrap(), 2);
        // It is the same after the archive is opened again, and an archive
        // seeded at a height counts that height.
        drop(archive);
        assert_eq!(Archive::open(dir.path(), [9; 32]).unwrap().entries().unwrap(), 2);
        let other = tempfile::tempdir().unwrap();
        let mut seeded = Archive::open(other.path(), [9; 32]).unwrap();
        seeded.seed(&s).unwrap();
        assert_eq!(seeded.entries().unwrap(), 5);
    }
    #[test]
    fn a_replay_keeps_the_entries_after_the_block_it_replays() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        let mut s = Summary::empty([9; 32], 1000);
        let mut appends = Vec::new();
        for h in 1..=6u64 {
            let a = s.append(leaf(h, h as u8)).unwrap();
            archive.append_durable(&a).unwrap();
            s = a.summary.clone();
            appends.push(a);
        }
        let full = s;
        // The ledger starts again from its state at height 2 and is handed
        // blocks 3 and 4 again, and then stops: the entries of 5 and 6 stay.
        drop(archive);
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        archive.append_durable(&appends[2]).unwrap();
        assert_eq!(archive.entries().unwrap(), 6);
        archive.append_durable(&appends[3]).unwrap();
        assert_eq!((archive.entries().unwrap(), archive.last_entry_above(2).unwrap()), (6, 6));
        // What was kept is the history itself: it recounts and proves.
        archive.audit(&full, 1000).unwrap();
        assert_eq!(archive.prove(&full, 6).unwrap().leaf, leaf(6, 6));
        // The replay goes on through 6, and the ledger then makes block 7.
        archive.append_durable(&appends[4]).unwrap();
        archive.append_durable(&appends[5]).unwrap();
        let seven = full.append(leaf(7, 7)).unwrap();
        archive.append_durable(&seven).unwrap();
        assert_eq!(archive.entries().unwrap(), 7);
        archive.audit(&seven.summary, 1000).unwrap();
        // Another block at a height the archive holds replaces the entry and
        // cuts what followed it: that was not this ledger's history.
        let other = appends[2].summary.append(leaf(4, 44)).unwrap();
        archive.append_durable(&other).unwrap();
        assert_eq!((archive.entries().unwrap(), archive.last_entry_above(0).unwrap()), (4, 4));
        archive.audit(&other.summary, 1000).unwrap();
        assert_eq!(archive.prove(&other.summary, 4).unwrap().leaf, leaf(4, 44));
    }
    #[test]
    fn the_last_entry_is_a_block_s_and_not_a_record_that_seeding_left() {
        let dir = tempfile::tempdir().unwrap();
        let mut archive = Archive::open(dir.path(), [9; 32]).unwrap();
        assert_eq!(archive.last_entry_above(0).unwrap(), 0);
        assert_eq!(archive.last_entry_above(7).unwrap(), 7);
        // Seeded at a height (more records than one read takes): the file
        // has that many records and none is the entry of a block.
        let mut s = Summary::empty([9; 32], 1000);
        for h in 1..=5000u64 {
            s = s.append(leaf(h, (h % 251) as u8)).unwrap().summary;
        }
        archive.seed(&s).unwrap();
        assert_eq!(archive.entries().unwrap(), 5000);
        for floor in [0u64, 1, 903, 4096, 4999, 5000, 6000] {
            assert_eq!(archive.last_entry_above(floor).unwrap(), floor, "{floor}");
        }
        // The first block after it is an entry.
        let next = s.append(leaf(5001, 7)).unwrap();
        archive.append_durable(&next).unwrap();
        for floor in [0u64, 4096, 5000] {
            assert_eq!(archive.last_entry_above(floor).unwrap(), 5001, "{floor}");
        }
        assert_eq!(archive.last_entry_above(5001).unwrap(), 5001);
        assert_eq!(archive.last_entry_above(9000).unwrap(), 9000);
    }
}
