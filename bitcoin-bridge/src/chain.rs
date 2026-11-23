use anyhow::{Context, Result, ensure};
use bitcoin::{
    BlockHash, Network,
    block::Header,
    consensus::Params,
    pow::{CompactTarget, Target, Work},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet3,
    Regtest,
}
impl BitcoinNetwork {
    pub fn bitcoin(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet3 => Network::Testnet,
            Self::Regtest => Network::Regtest,
        }
    }
    pub fn params(self) -> Params {
        Params::new(self.bitcoin())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    pub network: BitcoinNetwork,
    pub confirmations: u32,
    pub max_batch: usize,
    pub max_fork_tips: usize,
    pub retention: u32,
    pub max_reorg: u32,
    pub max_tip_age_secs: u64,
    pub max_future_secs: u64,
    pub mainnet_receipts_enabled: bool,
}
impl BridgeConfig {
    pub fn for_network(network: BitcoinNetwork) -> Self {
        Self {
            network,
            confirmations: 12,
            max_batch: 256,
            max_fork_tips: 32,
            retention: 8192,
            max_reorg: 144,
            max_tip_age_secs: 7200,
            max_future_secs: 7200,
            mainnet_receipts_enabled: false,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=4032).contains(&self.confirmations),
            "Bitcoin confirmation bound"
        );
        ensure!(
            (1..=256).contains(&self.max_batch) && (1..=32).contains(&self.max_fork_tips),
            "Bitcoin relay resource bounds"
        );
        ensure!(
            (1..=2016).contains(&self.max_reorg)
                && self.retention >= 4032 + self.max_reorg + 11
                && self.retention <= 16384,
            "Bitcoin retained validation context bound"
        );
        ensure!(
            self.confirmations <= self.max_reorg
                && self.max_tip_age_secs > 0
                && self.max_tip_age_secs <= 14 * 86400
                && self.max_future_secs <= 7200,
            "Bitcoin bridge timing policy"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRecord {
    pub header: Header,
    pub height: u32,
    pub chainwork: Work,
}

/// The adapter reads previously validated, authenticated application state.
/// Every returned record must match its hash and its height index. V4 applies
/// transition rows and chain metadata in the same authenticated transaction.
pub trait HeaderReader {
    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>>;
    fn hashes_at_height(&self, height: u32) -> Result<Vec<BlockHash>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCheckpoint {
    pub network: BitcoinNetwork,
    pub height: u32,
    pub hash: BlockHash,
    pub chainwork: Work,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum HaltReason {
    DeepReorg {
        old_tip: BlockHash,
        candidate: BlockHash,
        common_height: u32,
    },
    CreditedReceiptReorg {
        old_tip: BlockHash,
        candidate: BlockHash,
        common_height: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainMeta {
    pub config: BridgeConfig,
    pub checkpoint: TrustedCheckpoint,
    pub trusted_checkpoint: bool,
    pub best_tip: BlockHash,
    pub best_height: u32,
    pub best_work: Work,
    pub pruned_below: u32,
    pub record_count: u32,
    pub tips: Vec<BlockHash>,
    pub credited_height: u32,
    pub credited_hash: BlockHash,
    pub halted: Option<HaltReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderChain {
    pub meta: ChainMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderTransition {
    pub chain: HeaderChain,
    pub writes: Vec<HeaderRecord>,
    pub deletes: Vec<(BlockHash, u32)>,
    pub height_updates: BTreeMap<u32, Vec<BlockHash>>,
    pub reorg_depth: u32,
}

fn add_work(left: Work, right: Work) -> Result<Work> {
    let a = left.to_be_bytes();
    let b = right.to_be_bytes();
    let mut out = [0; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    ensure!(carry == 0, "Bitcoin accumulated work overflow");
    Ok(Work::from_be_bytes(out))
}
fn checked_record(reader: &impl HeaderReader, hash: &BlockHash) -> Result<HeaderRecord> {
    let row = reader
        .header(hash)?
        .context("unknown or pruned Bitcoin parent")?;
    ensure!(
        row.header.block_hash() == *hash,
        "Bitcoin header index mismatch"
    );
    Ok(row)
}

impl HeaderChain {
    pub fn bootstrap_genesis(config: BridgeConfig) -> Result<HeaderTransition> {
        config.validate()?;
        let header = bitcoin::blockdata::constants::genesis_block(config.network.bitcoin()).header;
        header.validate_pow(header.target())?;
        let row = HeaderRecord {
            header,
            height: 0,
            chainwork: header.work(),
        };
        let network = config.network;
        Self::bootstrap(
            config,
            TrustedCheckpoint {
                network,
                height: 0,
                hash: header.block_hash(),
                chainwork: header.work(),
            },
            vec![row],
            false,
        )
    }

    /// A checkpoint is an explicit external trust decision, not an SPV proof
    /// of the history before it. Its hash authenticates the supplied reverse-
    /// linked validation context. No RPC response can create a trust pin.
    pub fn bootstrap_trusted_checkpoint(
        config: BridgeConfig,
        pin: TrustedCheckpoint,
        headers: Vec<Header>,
    ) -> Result<HeaderTransition> {
        config.validate()?;
        ensure!(
            pin.network == config.network,
            "checkpoint Bitcoin network mismatch"
        );
        let period = pin.height / 2016 * 2016;
        let needed_start = period.saturating_sub(10);
        ensure!(
            !headers.is_empty()
                && headers.len() <= 2027
                && headers.len() as u32 == pin.height - needed_start + 1,
            "checkpoint requires complete retarget/MTP context"
        );
        ensure!(
            headers.last().unwrap().block_hash() == pin.hash,
            "checkpoint pin mismatch"
        );
        if needed_start == 0 {
            ensure!(
                headers[0].block_hash()
                    == bitcoin::blockdata::constants::genesis_block(config.network.bitcoin())
                        .block_hash(),
                "checkpoint context has the wrong network genesis"
            );
        }
        let params = config.network.params();
        let mut context_work = Work::from_be_bytes([0; 32]);
        for (i, header) in headers.iter().enumerate() {
            validate_target(header, &params)?;
            if i > 0 {
                ensure!(
                    header.prev_blockhash == headers[i - 1].block_hash(),
                    "checkpoint context link mismatch"
                );
            }
            context_work = add_work(context_work, header.work())?;
        }
        ensure!(
            pin.chainwork >= context_work,
            "checkpoint chainwork is below authenticated context work"
        );
        let mut work = pin.chainwork - context_work;
        let mut rows = Vec::new();
        for (i, header) in headers.into_iter().enumerate() {
            work = add_work(work, header.work())?;
            rows.push(HeaderRecord {
                header,
                height: needed_start + i as u32,
                chainwork: work,
            });
        }
        Self::bootstrap(config, pin, rows, true)
    }
    fn bootstrap(
        config: BridgeConfig,
        pin: TrustedCheckpoint,
        rows: Vec<HeaderRecord>,
        trusted: bool,
    ) -> Result<HeaderTransition> {
        let last = rows.last().context("empty anchor context")?;
        let first = rows.first().unwrap();
        let chain = Self {
            meta: ChainMeta {
                config,
                checkpoint: pin.clone(),
                trusted_checkpoint: trusted,
                best_tip: pin.hash,
                best_height: pin.height,
                best_work: pin.chainwork,
                pruned_below: first.height,
                record_count: rows.len() as u32,
                tips: vec![pin.hash],
                credited_height: pin.height,
                credited_hash: pin.hash,
                halted: None,
            },
        };
        ensure!(
            last.header.block_hash() == chain.meta.best_tip,
            "anchor terminal hash"
        );
        let height_updates = rows
            .iter()
            .map(|r| (r.height, vec![r.header.block_hash()]))
            .collect();
        Ok(HeaderTransition {
            chain,
            writes: rows,
            deletes: vec![],
            height_updates,
            reorg_depth: 0,
        })
    }
    pub fn validate(&self, reader: &impl HeaderReader) -> Result<()> {
        self.meta.config.validate()?;
        ensure!(
            self.meta.config.network == self.meta.checkpoint.network
                && self.meta.best_height >= self.meta.checkpoint.height,
            "Bitcoin chain metadata network/height"
        );
        if !self.meta.trusted_checkpoint {
            let genesis =
                bitcoin::blockdata::constants::genesis_block(self.meta.config.network.bitcoin())
                    .header;
            ensure!(
                self.meta.checkpoint.height == 0
                    && self.meta.checkpoint.hash == genesis.block_hash()
                    && self.meta.checkpoint.chainwork == genesis.work(),
                "Bitcoin network genesis pin mismatch"
            );
        }
        ensure!(
            !self.meta.tips.is_empty()
                && self.meta.tips.len() <= self.meta.config.max_fork_tips
                && self.meta.tips.contains(&self.meta.best_tip),
            "Bitcoin fork frontier metadata"
        );
        ensure!(
            self.meta.pruned_below <= self.meta.best_height
                && self.meta.credited_height <= self.meta.best_height,
            "Bitcoin chain coordinate metadata"
        );
        let best = checked_record(reader, &self.meta.best_tip)?;
        ensure!(
            best.height == self.meta.best_height && best.chainwork == self.meta.best_work,
            "Bitcoin best tip mismatch"
        );
        validate_target(&best.header, &self.meta.config.network.params())?;
        Ok(())
    }
    pub fn best_record(&self, reader: &impl HeaderReader) -> Result<HeaderRecord> {
        self.validate(reader)?;
        checked_record(reader, &self.meta.best_tip)
    }
    pub fn ancestor(
        &self,
        reader: &impl HeaderReader,
        mut hash: BlockHash,
        height: u32,
    ) -> Result<HeaderRecord> {
        let mut record = checked_record(reader, &hash)?;
        ensure!(
            height >= self.meta.pruned_below && height <= record.height,
            "Bitcoin ancestor outside retained range"
        );
        for _ in 0..=self.meta.config.retention + self.meta.config.max_batch as u32 + 2027 {
            if record.height == height {
                return Ok(record);
            }
            let expected = record
                .height
                .checked_sub(1)
                .context("Bitcoin ancestor underflow")?;
            hash = record.header.prev_blockhash;
            record = checked_record(reader, &hash)?;
            ensure!(
                record.height == expected,
                "Bitcoin header height link mismatch"
            );
        }
        anyhow::bail!("Bitcoin ancestor traversal bound")
    }
    pub fn median_time_past(
        &self,
        reader: &impl HeaderReader,
        parent: &HeaderRecord,
    ) -> Result<u32> {
        let start = parent.height.saturating_sub(10);
        let mut times = Vec::new();
        let mut record = parent.clone();
        loop {
            times.push(record.header.time);
            if record.height == start {
                break;
            }
            record = checked_record(reader, &record.header.prev_blockhash)?;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }
    pub fn expected_bits(
        &self,
        reader: &impl HeaderReader,
        parent: &HeaderRecord,
        new_time: u32,
    ) -> Result<CompactTarget> {
        let params = self.meta.config.network.params();
        let height = parent
            .height
            .checked_add(1)
            .context("Bitcoin height overflow")?;
        let interval = params.difficulty_adjustment_interval() as u32;
        if !height.is_multiple_of(interval) {
            if params.allow_min_difficulty_blocks {
                if u64::from(new_time)
                    > u64::from(parent.header.time) + params.pow_target_spacing * 2
                {
                    return Ok(params.max_attainable_target.to_compact_lossy());
                }
                let min = params.max_attainable_target.to_compact_lossy();
                let mut previous = parent.clone();
                for _ in 0..interval {
                    if previous.height.is_multiple_of(interval) || previous.header.bits != min {
                        return Ok(previous.header.bits);
                    }
                    previous = checked_record(reader, &previous.header.prev_blockhash)?;
                }
                anyhow::bail!("Bitcoin testnet minimum difficulty search bound");
            }
            return Ok(parent.header.bits);
        }
        if params.no_pow_retargeting {
            return Ok(parent.header.bits);
        }
        let first = self.ancestor(reader, parent.header.block_hash(), height - interval)?;
        let span = (i64::from(parent.header.time) - i64::from(first.header.time)).clamp(
            (params.pow_target_timespan / 4) as i64,
            (params.pow_target_timespan * 4) as i64,
        ) as u64;
        Ok(CompactTarget::from_next_work_required(
            parent.header.bits,
            span,
            &params,
        ))
    }
    pub fn prepare_headers(
        &self,
        reader: &impl HeaderReader,
        headers: &[Header],
        consensus_now_secs: u64,
    ) -> Result<HeaderTransition> {
        self.validate(reader)?;
        ensure!(
            self.meta.halted.is_none(),
            "Bitcoin bridge is paused after a reorganization"
        );
        ensure!(
            !headers.is_empty() && headers.len() <= self.meta.config.max_batch,
            "Bitcoin header batch bound"
        );
        let mut overlay = HeaderOverlay::new(reader);
        let mut chain = self.clone();
        let mut reorg_depth = 0;
        for header in headers {
            let hash = header.block_hash();
            if overlay.header(&hash)?.is_some() {
                continue;
            }
            let parent = checked_record(&overlay, &header.prev_blockhash)?;
            ensure!(
                parent.height >= chain.meta.checkpoint.height,
                "Bitcoin fork predates trusted checkpoint"
            );
            let height = parent
                .height
                .checked_add(1)
                .context("Bitcoin height overflow")?;
            ensure!(
                u64::from(header.time)
                    <= consensus_now_secs.saturating_add(chain.meta.config.max_future_secs),
                "Bitcoin header too far in consensus-time future"
            );
            ensure!(
                header.time > chain.median_time_past(&overlay, &parent)?,
                "Bitcoin header fails median-time-past"
            );
            let params = chain.meta.config.network.params();
            let version = header.version.to_consensus();
            ensure!(
                (height < params.bip34_height || version >= 2)
                    && (height < params.bip66_height || version >= 3)
                    && (height < params.bip65_height || version >= 4),
                "obsolete Bitcoin block version"
            );
            let bits = chain.expected_bits(&overlay, &parent, header.time)?;
            ensure!(header.bits == bits, "Bitcoin exact difficulty mismatch");
            validate_target(header, &chain.meta.config.network.params())?;
            let record = HeaderRecord {
                header: *header,
                height,
                chainwork: add_work(parent.chainwork, header.work())?,
            };
            overlay.insert(record.clone())?;
            chain.meta.record_count = chain
                .meta
                .record_count
                .checked_add(1)
                .context("Bitcoin record count overflow")?;
            chain.meta.tips.retain(|tip| *tip != header.prev_blockhash);
            chain.meta.tips.push(hash);
            chain.meta.tips.sort();
            chain.meta.tips.dedup();
            ensure!(
                chain.meta.tips.len()
                    <= chain.meta.config.max_fork_tips + chain.meta.config.max_batch,
                "Bitcoin staged fork frontier capacity"
            );
            if chain.meta.halted.is_none() && record.chainwork > chain.meta.best_work {
                let old_tip = chain.meta.best_tip;
                let common = chain.common_ancestor(&overlay, old_tip, hash)?;
                let depth = chain.meta.best_height - common.height;
                reorg_depth = reorg_depth.max(depth);
                if common.height < chain.meta.credited_height {
                    chain.meta.halted = Some(HaltReason::CreditedReceiptReorg {
                        old_tip,
                        candidate: hash,
                        common_height: common.height,
                    });
                } else if depth > chain.meta.config.max_reorg {
                    chain.meta.halted = Some(HaltReason::DeepReorg {
                        old_tip,
                        candidate: hash,
                        common_height: common.height,
                    });
                }
                if chain.meta.halted.is_none() {
                    chain.meta.best_tip = hash;
                    chain.meta.best_height = height;
                    chain.meta.best_work = record.chainwork;
                }
            }
        }
        ensure!(
            !overlay.writes.is_empty(),
            "Bitcoin relay contains no new headers"
        );
        chain.prune(&mut overlay)?;
        ensure!(
            chain.meta.record_count
                <= chain.meta.config.retention
                    + 2027
                    + chain.meta.config.max_reorg * chain.meta.config.max_fork_tips as u32
                    + chain.meta.config.max_batch as u32,
            "Bitcoin bounded record capacity"
        );
        let (writes, deletes, height_updates) = overlay.finish()?;
        ensure!(
            chain.meta != self.meta || !writes.is_empty(),
            "Bitcoin relay has no retained state effect"
        );
        ensure!(
            serde_json::to_vec(&chain.meta)?.len() < 64 * 1024,
            "Bitcoin metadata bound"
        );
        Ok(HeaderTransition {
            chain,
            writes,
            deletes,
            height_updates,
            reorg_depth,
        })
    }
    fn common_ancestor(
        &self,
        reader: &impl HeaderReader,
        a: BlockHash,
        b: BlockHash,
    ) -> Result<HeaderRecord> {
        let mut a = checked_record(reader, &a)?;
        let mut b = checked_record(reader, &b)?;
        for _ in 0..=self.meta.config.retention + self.meta.config.max_batch as u32 + 2027 {
            if a.height > b.height {
                a = checked_record(reader, &a.header.prev_blockhash)?;
            } else if b.height > a.height {
                b = checked_record(reader, &b.header.prev_blockhash)?;
            } else if a.header.block_hash() == b.header.block_hash() {
                return Ok(a);
            } else {
                a = checked_record(reader, &a.header.prev_blockhash)?;
                b = checked_record(reader, &b.header.prev_blockhash)?;
            }
        }
        anyhow::bail!("Bitcoin common ancestor traversal bound")
    }
    fn prune(&mut self, overlay: &mut HeaderOverlay<'_, impl HeaderReader>) -> Result<()> {
        if let Some(reason) = &self.meta.halted {
            let candidate = match reason {
                HaltReason::DeepReorg { candidate, .. }
                | HaltReason::CreditedReceiptReorg { candidate, .. } => *candidate,
            };
            let all = self.meta.tips.clone();
            let mut protected = vec![self.meta.best_tip, candidate];
            let mut ranked = Vec::new();
            for tip in &all {
                if !protected.contains(tip) {
                    ranked.push((checked_record(overlay, tip)?.chainwork, *tip));
                }
            }
            ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            protected.extend(
                ranked
                    .into_iter()
                    .take(self.meta.config.max_fork_tips.saturating_sub(2))
                    .map(|(_, hash)| hash),
            );
            self.retire_unkept(overlay, &all, &protected, self.meta.pruned_below)?;
            // A one-tip policy still retains one external candidate branch as
            // halt evidence, so height indices are bounded by max_tips + 1.
            self.meta.tips = protected
                .into_iter()
                .take(self.meta.config.max_fork_tips)
                .collect();
            self.meta.tips.sort();
            return Ok(());
        }
        let keep = self
            .meta
            .best_height
            .saturating_sub(self.meta.config.retention)
            .max(self.meta.pruned_below);
        for height in self.meta.pruned_below..keep {
            for hash in overlay.hashes_at_height(height)? {
                overlay.remove(hash, height)?;
                self.meta.record_count -= 1;
            }
        }
        self.meta.pruned_below = keep;
        let floor = self
            .meta
            .best_height
            .saturating_sub(self.meta.config.max_reorg)
            .max(self.meta.checkpoint.height);
        let canonical = self
            .ancestor(overlay, self.meta.best_tip, floor)?
            .header
            .block_hash();
        let mut ranked = Vec::new();
        for tip in self.meta.tips.clone() {
            let record = checked_record(overlay, &tip)?;
            let retained = if record.height < floor {
                false
            } else {
                self.ancestor(overlay, tip, floor)?.header.block_hash() == canonical
            };
            if retained && tip != self.meta.best_tip {
                ranked.push((record.chainwork, tip));
            }
        }
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut tips = vec![self.meta.best_tip];
        tips.extend(
            ranked
                .into_iter()
                .take(self.meta.config.max_fork_tips - 1)
                .map(|(_, hash)| hash),
        );
        // A full low-work frontier cannot prevent a new higher-work batch
        // from being validated and becoming the canonical chain.
        self.retire_unkept(overlay, &self.meta.tips.clone(), &tips, keep)?;
        tips.sort();
        self.meta.tips = tips;
        Ok(())
    }
    fn retire_unkept(
        &mut self,
        overlay: &mut HeaderOverlay<'_, impl HeaderReader>,
        all: &[BlockHash],
        protected_tips: &[BlockHash],
        keep: u32,
    ) -> Result<()> {
        let bound = self.meta.record_count as usize + 1;
        for tip in all {
            if protected_tips.contains(tip) {
                continue;
            }
            let mut old = checked_record(overlay, tip)?;
            // Retire only the divergent branch. Shared canonical ancestors are
            // never deleted; all branch work is bounded by retained history.
            let mut complete = false;
            for _ in 0..bound {
                if old.height < keep {
                    complete = true;
                    break;
                }
                let mut protected = false;
                for kept in protected_tips {
                    let height = checked_record(overlay, kept)?.height;
                    if height >= old.height
                        && self
                            .ancestor(overlay, *kept, old.height)?
                            .header
                            .block_hash()
                            == old.header.block_hash()
                    {
                        protected = true;
                        break;
                    }
                }
                if protected {
                    complete = true;
                    break;
                }
                let previous = old.header.prev_blockhash;
                overlay.remove(old.header.block_hash(), old.height)?;
                self.meta.record_count -= 1;
                if old.height == 0 || overlay.deletes.contains_key(&previous) {
                    complete = true;
                    break;
                }
                old = checked_record(overlay, &previous)?;
            }
            ensure!(complete, "Bitcoin branch retirement traversal bound");
        }
        Ok(())
    }
    pub fn ensure_fresh(&self, reader: &impl HeaderReader, consensus_now_secs: u64) -> Result<()> {
        ensure!(
            self.meta.halted.is_none(),
            "Bitcoin bridge paused after reorganization"
        );
        let tip = self.best_record(reader)?;
        ensure!(
            consensus_now_secs
                <= u64::from(tip.header.time).saturating_add(self.meta.config.max_tip_age_secs),
            "Bitcoin header tip stale"
        );
        ensure!(
            u64::from(tip.header.time)
                <= consensus_now_secs.saturating_add(self.meta.config.max_future_secs),
            "Bitcoin tip ahead of consensus time"
        );
        Ok(())
    }
}
fn validate_target(header: &Header, params: &Params) -> Result<()> {
    let target = header.target();
    ensure!(
        target > Target::ZERO && target <= params.max_attainable_target,
        "Bitcoin target outside network limit"
    );
    header.validate_pow(target)?;
    Ok(())
}

struct HeaderOverlay<'a, R: HeaderReader> {
    reader: &'a R,
    writes: BTreeMap<BlockHash, HeaderRecord>,
    deletes: BTreeMap<BlockHash, u32>,
    heights: BTreeMap<u32, Vec<BlockHash>>,
}
type HeaderRowChanges = (
    Vec<HeaderRecord>,
    Vec<(BlockHash, u32)>,
    BTreeMap<u32, Vec<BlockHash>>,
);
impl<'a, R: HeaderReader> HeaderOverlay<'a, R> {
    fn new(reader: &'a R) -> Self {
        Self {
            reader,
            writes: BTreeMap::new(),
            deletes: BTreeMap::new(),
            heights: BTreeMap::new(),
        }
    }
    fn insert(&mut self, row: HeaderRecord) -> Result<()> {
        let hash = row.header.block_hash();
        let mut hashes = self.hashes_at_height(row.height)?;
        hashes.push(hash);
        hashes.sort();
        hashes.dedup();
        self.heights.insert(row.height, hashes);
        self.writes.insert(hash, row);
        Ok(())
    }
    fn remove(&mut self, hash: BlockHash, height: u32) -> Result<()> {
        if self.deletes.contains_key(&hash) {
            return Ok(());
        }
        let mut hashes = self.hashes_at_height(height)?;
        hashes.retain(|h| *h != hash);
        self.heights.insert(height, hashes);
        self.writes.remove(&hash);
        self.deletes.insert(hash, height);
        Ok(())
    }
    fn finish(self) -> Result<HeaderRowChanges> {
        Ok((
            self.writes.into_values().collect(),
            self.deletes.into_iter().collect(),
            self.heights,
        ))
    }
}
impl<R: HeaderReader> HeaderReader for HeaderOverlay<'_, R> {
    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>> {
        if self.deletes.contains_key(hash) {
            return Ok(None);
        }
        if let Some(row) = self.writes.get(hash) {
            return Ok(Some(row.clone()));
        }
        self.reader.header(hash)
    }
    fn hashes_at_height(&self, height: u32) -> Result<Vec<BlockHash>> {
        if let Some(hashes) = self.heights.get(&height) {
            return Ok(hashes.clone());
        }
        self.reader.hashes_at_height(height)
    }
}

/// Test/tool adapter. Production stores each header/index row separately; this
/// adapter is deliberately not serialized into consensus metadata.
#[derive(Default, Clone)]
pub struct MemoryHeaderStore {
    pub records: BTreeMap<BlockHash, HeaderRecord>,
    pub heights: BTreeMap<u32, Vec<BlockHash>>,
}
impl MemoryHeaderStore {
    pub fn apply(&mut self, transition: &HeaderTransition) {
        for (hash, _) in &transition.deletes {
            self.records.remove(hash);
        }
        for row in &transition.writes {
            self.records.insert(row.header.block_hash(), row.clone());
        }
        for (height, hashes) in &transition.height_updates {
            if hashes.is_empty() {
                self.heights.remove(height);
            } else {
                self.heights.insert(*height, hashes.clone());
            }
        }
    }
}
impl HeaderReader for MemoryHeaderStore {
    fn header(&self, hash: &BlockHash) -> Result<Option<HeaderRecord>> {
        Ok(self.records.get(hash).cloned())
    }
    fn hashes_at_height(&self, height: u32) -> Result<Vec<BlockHash>> {
        Ok(self.heights.get(&height).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accumulated_work_carries_and_overflow_fail_closed() {
        let mut a = [0; 32];
        a[31] = 255;
        let mut b = [0; 32];
        b[31] = 1;
        let result = add_work(Work::from_be_bytes(a), Work::from_be_bytes(b)).unwrap();
        let mut expected = [0; 32];
        expected[30] = 1;
        assert_eq!(result.to_be_bytes(), expected);
        assert!(add_work(Work::from_be_bytes([255; 32]), Work::from_be_bytes(b)).is_err());
        let easy = Target::MAX_ATTAINABLE_REGTEST.to_work();
        let hard = Target::MAX_ATTAINABLE_MAINNET.to_work();
        assert!(hard > easy);
        assert!(add_work(hard, easy).unwrap() > hard);
    }
}
