//! Fixed-validator development ABCI with incremental authenticated state.
use crate::{
    engine::{
        Engine, Meta, Prepared, account_key, canonical_decode, name_key, pubkey_key, recovery_key,
    },
    proof::ProofEntry,
    store::{GcBudget, GcPolicy, PruneStats, Snapshot, Store},
};
use anyhow::{Context, Result, anyhow, ensure};
use prost::Message;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, MutexGuard, TryLockError},
};
use tendermint_abci::Application;
use tendermint_proto::v0_38::{
    abci::*,
    types::{BlockParams, ConsensusParams, EvidenceParams, VersionParams},
};
use timecurrency_node::ledger::{self, Account, Genesis};

const MAX_REQUEST: usize = 8 * 1024 * 1024;
const MAX_QUERY: usize = 16 * 1024;
const MAX_PROOF_RESPONSE: usize = 3 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
#[derive(Clone)]
pub struct App {
    inner: Arc<Mutex<Inner>>,
}
struct Inner {
    engine: Engine,
    pending: Option<Pending>,
    faulted: bool,
}
struct Pending {
    prepared: Prepared,
    fingerprint: [u8; 32],
}
fn consensus_params(version: u64) -> ConsensusParams {
    ConsensusParams {
        block: Some(BlockParams {
            max_bytes: 1024 * 1024,
            max_gas: -1,
        }),
        evidence: Some(EvidenceParams {
            max_age_num_blocks: 100_000,
            max_age_duration: Some(tendermint_proto::google::protobuf::Duration {
                seconds: 48 * 3600,
                nanos: 0,
            }),
            max_bytes: 65536,
        }),
        version: Some(VersionParams { app: version }),
        validator: None,
        abci: None,
    }
}
fn time(value: Option<&tendermint_proto::google::protobuf::Timestamp>) -> Result<i64> {
    let v = value.ok_or_else(|| anyhow!("missing consensus timestamp"))?;
    ensure!(
        v.seconds >= 0 && (0..1_000_000_000).contains(&v.nanos),
        "invalid timestamp"
    );
    v.seconds
        .checked_mul(1_000_000)
        .and_then(|s| s.checked_add(i64::from(v.nanos / 1000)))
        .ok_or_else(|| anyhow!("timestamp overflow"))
}
fn response(root: [u8; 32], count: usize, version: u64) -> ResponseFinalizeBlock {
    ResponseFinalizeBlock {
        app_hash: root.to_vec().into(),
        tx_results: (0..count).map(|_| ExecTxResult::default()).collect(),
        consensus_param_updates: Some(consensus_params(version)),
        ..Default::default()
    }
}
fn eligible(
    meta: &Meta,
    votes: impl IntoIterator<Item = (Option<Validator>, i32)>,
) -> Result<Vec<String>> {
    if meta.genesis.economics.mode == ledger::EconomicMode::BankOnly {
        return Ok(Vec::new());
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for (n, (validator, flag)) in votes.into_iter().enumerate() {
        ensure!(n < ledger::MAX_OPERATORS, "too many commit votes");
        if flag != 2 {
            continue;
        }
        let v = validator.ok_or_else(|| anyhow!("missing commit voter"))?;
        let op = meta
            .genesis
            .economics
            .operators
            .iter()
            .find(|o| {
                hex::decode(&o.consensus_key)
                    .is_ok_and(|k| Sha256::digest(k)[..20] == v.address[..])
            })
            .ok_or_else(|| anyhow!("unknown commit voter"))?;
        ensure!(
            v.power > 0
                && u64::try_from(v.power)? == op.power
                && seen.insert(op.consensus_key.clone()),
            "duplicate/incorrect voter power"
        );
        result.push(op.consensus_key.clone());
    }
    Ok(result)
}
impl App {
    /// Physical history cleanup is local maintenance, never a consensus rule.
    /// Skip busy or unpublished Finalize state rather than delaying that work.
    pub fn maintain_idle(&self) -> Result<Option<PruneStats>> {
        let inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => return Err(anyhow!("application lock poisoned")),
        };
        ensure!(!inner.faulted, "application faulted");
        if inner.pending.is_some() || inner.engine.meta().is_none() {
            return Ok(None);
        }
        let store = inner.engine.store();
        if !store.gc_status(GcPolicy::default())?.eligible_work_pending {
            return Ok(None);
        }
        Ok(Some(store.maintain_gc(GcBudget::default())?))
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let engine = Engine::open(Store::open(path)?)?;
        ensure!(
            engine
                .meta()
                .is_none_or(|meta| !meta.genesis.chain_id.starts_with("time-devnet-fixture-")),
            "benchmark fixture databases cannot be opened by the network binary"
        );
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                engine,
                pending: None,
                faulted: false,
            })),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| anyhow!("application lock poisoned"))?;
        ensure!(!guard.faulted, "application faulted; restart and inspect");
        Ok(guard)
    }
    fn abort<T>(&self, error: anyhow::Error) -> T {
        if let Ok(mut inner) = self.inner.lock() {
            inner.faulted = true;
        }
        panic!("ABCI v2 failed closed: {error}")
    }
    pub fn try_init(&self, request: RequestInitChain) -> Result<ResponseInitChain> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST
                && request.validators.len() <= ledger::MAX_OPERATORS,
            "genesis request budget"
        );
        ensure!(
            matches!(request.initial_height, 0 | 1),
            "initial height must be one"
        );
        ensure!(
            !request.app_state_bytes.is_empty() && request.app_state_bytes.len() <= 1024 * 1024,
            "genesis byte budget"
        );
        let genesis: Genesis = serde_json::from_slice(&request.app_state_bytes)?;
        ensure!(
            genesis.chain_id == request.chain_id
                && genesis.genesis_time_micros == time(request.time.as_ref())?,
            "genesis chain/time mismatch"
        );
        ensure!(
            !genesis.chain_id.starts_with("time-devnet-fixture-"),
            "benchmark fixture chains cannot run ABCI"
        );
        if genesis.economics.mode == ledger::EconomicMode::DevnetAuction {
            ensure!(
                !request.validators.is_empty()
                    && request.validators.len() == genesis.economics.operators.len(),
                "operator/validator roster mismatch"
            );
            let mut seen = BTreeSet::new();
            for v in &request.validators {
                let key = match v.pub_key.as_ref().and_then(|k| k.sum.as_ref()) {
                    Some(tendermint_proto::crypto::public_key::Sum::Ed25519(k)) => hex::encode(k),
                    _ => return Err(anyhow!("unsupported validator key")),
                };
                let op = genesis
                    .economics
                    .operators
                    .iter()
                    .find(|o| o.consensus_key == key)
                    .ok_or_else(|| anyhow!("unknown consensus key"))?;
                ensure!(
                    v.power > 0 && u64::try_from(v.power)? == op.power && seen.insert(key),
                    "invalid validator authority/power"
                );
            }
        }
        let mut inner = self.lock()?;
        let head = inner.engine.initialize(genesis)?;
        let version = inner
            .engine
            .meta()
            .context("uninitialized chain")?
            .protocol_version;
        Ok(ResponseInitChain {
            app_hash: head.root.to_vec().into(),
            consensus_params: Some(consensus_params(version)),
            ..Default::default()
        })
    }
    pub fn try_finalize(&self, request: RequestFinalizeBlock) -> Result<ResponseFinalizeBlock> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST && request.hash.len() == 32,
            "invalid finalized request"
        );
        ledger::validate_block_transactions(&request.txs)?;
        let timestamp = time(request.time.as_ref())?;
        let fingerprint: [u8; 32] = Sha256::digest(request.encode_to_vec()).into();
        let txs: Vec<_> = request.txs.iter().map(|t| t.to_vec()).collect();
        let mut inner = self.lock()?;
        let version = inner.engine.meta().map_or(2, |meta| meta.protocol_version);
        if let Some(p) = &inner.pending {
            ensure!(
                p.fingerprint == fingerprint,
                "different finalize before commit"
            );
            return Ok(response(p.prepared.root, p.prepared.txcount, version));
        }
        let head = inner
            .engine
            .head()?
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        if request.height > 0 && u64::try_from(request.height)? == head.version {
            ensure!(
                head.request_fingerprint == fingerprint,
                "conflicting finalized replay"
            );
            return Ok(response(head.root, txs.len(), version));
        }
        let meta = inner
            .engine
            .meta()
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        let keys = eligible(
            meta,
            request
                .decided_last_commit
                .iter()
                .flat_map(|c| &c.votes)
                .map(|v| (v.validator.clone(), v.block_id_flag)),
        )?;
        let prepared = inner
            .engine
            .prepare(request.height, timestamp, &txs, &keys)?;
        let result = response(
            prepared.root,
            prepared.txcount,
            prepared.meta.protocol_version,
        );
        inner.pending = Some(Pending {
            prepared,
            fingerprint,
        });
        Ok(result)
    }
    pub fn try_commit(&self) -> Result<ResponseCommit> {
        let mut inner = self.lock()?;
        ensure!(inner.engine.meta().is_some(), "uninitialized chain");
        if let Some(p) = inner.pending.take()
            && let Err(error) = inner.engine.commit(p.prepared, p.fingerprint)
        {
            inner.faulted = true;
            return Err(error);
        }
        Ok(ResponseCommit { retain_height: 0 })
    }
    fn prepare(&self, request: RequestPrepareProposal) -> Result<ResponsePrepareProposal> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST && request.max_tx_bytes >= 0,
            "proposal budget"
        );
        let timestamp = time(request.time.as_ref())?;
        let inner = self.lock()?;
        let meta = inner
            .engine
            .meta()
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        let keys = eligible(
            meta,
            request
                .local_last_commit
                .iter()
                .flat_map(|c| &c.votes)
                .map(|v| (v.validator.clone(), v.block_id_flag)),
        )?;
        let txs: Vec<_> = request.txs.iter().map(|t| t.to_vec()).collect();
        let (_, accepted) = inner.engine.prepare_filtered(
            request.height,
            timestamp,
            &txs,
            &keys,
            usize::try_from(request.max_tx_bytes)?.min(ledger::MAX_BLOCK_TX_BYTES),
        )?;
        Ok(ResponsePrepareProposal {
            txs: accepted.into_iter().map(Into::into).collect(),
        })
    }
    fn process(&self, request: RequestProcessProposal) -> Result<()> {
        ensure!(
            request.encoded_len() <= MAX_REQUEST && request.hash.len() == 32,
            "proposal budget/hash"
        );
        let timestamp = time(request.time.as_ref())?;
        let inner = self.lock()?;
        let meta = inner
            .engine
            .meta()
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        let keys = eligible(
            meta,
            request
                .proposed_last_commit
                .iter()
                .flat_map(|c| &c.votes)
                .map(|v| (v.validator.clone(), v.block_id_flag)),
        )?;
        let txs: Vec<_> = request.txs.iter().map(|t| t.to_vec()).collect();
        inner
            .engine
            .prepare(request.height, timestamp, &txs, &keys)?;
        Ok(())
    }
    fn query_value(&self, request: RequestQuery) -> Result<(i64, Vec<u8>)> {
        ensure!(
            !request.prove && request.data.len() <= MAX_QUERY && request.height >= 0,
            "use bounded custom proof queries"
        );
        let inner = self.lock()?;
        let snapshot = inner.engine.store().snapshot()?;
        let current = snapshot
            .head()?
            .ok_or_else(|| anyhow!("uninitialized chain"))?;
        let version = if request.height == 0 {
            current.version
        } else {
            u64::try_from(request.height)?
        };
        let head = snapshot.version_head(version)?;
        let value = match request.path.as_str() {
            "/status" => {
                json!({"mode":"devnet","app_version":inner.engine.meta().map(|m|m.protocol_version.to_string()),"public_launch_allowed":false,"authenticated":false,"height":head.version.to_string(),"root":hex::encode(head.root),"state_storage":"incremental-jmt","proofs":"compact-account-membership-and-absence","global_supply_audit":"separate-full-tree-and-semantic-audit","maintenance":snapshot.gc_status(GcPolicy::default())?})
            }
            "/compact-proof" => {
                let raw: Vec<String> = serde_json::from_slice(&request.data)?;
                ensure!(!raw.is_empty() && raw.len() <= 32, "proof key budget");
                let keys = raw
                    .into_iter()
                    .map(|s| hex::decode(s).map_err(Into::into))
                    .collect::<Result<Vec<_>>>()?;
                let bundle = snapshot.proof_bundle(&keys, version)?;
                json!({"height":version.to_string(),"root":hex::encode(head.root),"entries":bundle.entries})
            }
            "/v2/view" => {
                let selection: Selection = serde_json::from_slice(&request.data)?;
                view(&snapshot, version, head.root, selection)?
            }
            _ => {
                return Err(anyhow!(
                    "unsupported v2 query; full snapshots are not served"
                ));
            }
        };
        let encoded = serde_json::to_vec(&value)?;
        ensure!(
            encoded.len() <= MAX_PROOF_RESPONSE,
            "proof response byte budget"
        );
        Ok((i64::try_from(version)?, encoded))
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    public_keys: Vec<String>,
}
fn canonical_id(s: &str) -> Result<u64> {
    ensure!(
        !s.is_empty() && (s == "0" || !s.starts_with('0')) && s.bytes().all(|c| c.is_ascii_digit()),
        "noncanonical account ID"
    );
    Ok(s.parse()?)
}
fn add(
    snapshot: &Snapshot,
    version: u64,
    root: [u8; 32],
    entries: &mut BTreeMap<Vec<u8>, ProofEntry>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    if let Some(entry) = entries.get(&key) {
        return entry.verify(root, &key);
    }
    ensure!(entries.len() < MAX_ENTRIES, "expanded proof entry budget");
    let entry = snapshot.proof(&key, version)?;
    let value = entry.verify(root, &key)?;
    entries.insert(key, entry);
    Ok(value)
}
fn view(
    snapshot: &Snapshot,
    version: u64,
    root: [u8; 32],
    selection: Selection,
) -> Result<serde_json::Value> {
    ensure!(
        selection.names.len() <= 8
            && selection.ids.len() <= 8
            && selection.public_keys.len() <= 8
            && selection.names.len() + selection.ids.len() + selection.public_keys.len() <= 16,
        "selection budget"
    );
    let mut entries = BTreeMap::new();
    let bytes = add(snapshot, version, root, &mut entries, b"meta".to_vec())?
        .ok_or_else(|| anyhow!("metadata missing"))?;
    let meta: Meta = canonical_decode(&bytes)?;
    ensure!(
        u64::try_from(meta.height)? == version,
        "metadata height mismatch"
    );
    let mut ids = BTreeSet::new();
    for name in selection.names {
        ensure!(
            (2..=15).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "invalid name"
        );
        if let Some(value) = add(snapshot, version, root, &mut entries, name_key(&name))? {
            ids.insert(canonical_id(&serde_json::from_slice::<String>(&value)?)?);
        }
    }
    for id in selection.ids {
        ids.insert(canonical_id(&id)?);
    }
    for key in selection.public_keys {
        if let Some(value) = add(snapshot, version, root, &mut entries, pubkey_key(&key)?)? {
            ids.insert(canonical_id(&serde_json::from_slice::<String>(&value)?)?);
        }
    }
    let explicit = ids.clone();
    for op in &meta.genesis.economics.operators {
        ids.insert(op.account_id);
    }
    let mut guardians = BTreeSet::new();
    for id in &ids {
        if let Some(value) = add(snapshot, version, root, &mut entries, account_key(*id))? {
            let account: Account = canonical_decode(&value)?;
            add(
                snapshot,
                version,
                root,
                &mut entries,
                name_key(&account.name),
            )?;
            if explicit.contains(id)
                && let Some(policy) = account.recovery_policy
            {
                guardians.extend(policy.guardians);
            }
        }
        add(snapshot, version, root, &mut entries, recovery_key(*id))?;
    }
    for id in guardians.difference(&ids) {
        if let Some(value) = add(snapshot, version, root, &mut entries, account_key(*id))? {
            let account: Account = canonical_decode(&value)?;
            add(
                snapshot,
                version,
                root,
                &mut entries,
                name_key(&account.name),
            )?;
        }
        add(snapshot, version, root, &mut entries, recovery_key(*id))?;
    }
    Ok(
        json!({"height":version.to_string(),"root":hex::encode(root),"entries":entries.into_values().collect::<Vec<_>>()}),
    )
}
impl Application for App {
    fn info(&self, _: RequestInfo) -> ResponseInfo {
        let inner = self.lock().unwrap_or_else(|e| self.abort(e));
        let head = inner.engine.head().unwrap_or_else(|e| self.abort(e));
        ResponseInfo {
            data: "timecurrency-v2-incremental-devnet; public launch disabled".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            app_version: inner.engine.meta().map_or(2, |meta| meta.protocol_version),
            last_block_height: head.as_ref().map_or(0, |h| h.version as i64),
            last_block_app_hash: head.map_or_else(Vec::new, |h| h.root.to_vec()).into(),
        }
    }
    fn init_chain(&self, r: RequestInitChain) -> ResponseInitChain {
        self.try_init(r).unwrap_or_else(|e| self.abort(e))
    }
    fn finalize_block(&self, r: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        self.try_finalize(r).unwrap_or_else(|e| self.abort(e))
    }
    fn commit(&self) -> ResponseCommit {
        self.try_commit().unwrap_or_else(|e| self.abort(e))
    }
    fn prepare_proposal(&self, r: RequestPrepareProposal) -> ResponsePrepareProposal {
        self.prepare(r).unwrap_or_else(|e| self.abort(e))
    }
    fn process_proposal(&self, r: RequestProcessProposal) -> ResponseProcessProposal {
        ResponseProcessProposal {
            status: if self.process(r).is_ok() {
                response_process_proposal::ProposalStatus::Accept as i32
            } else {
                response_process_proposal::ProposalStatus::Reject as i32
            },
        }
    }
    fn check_tx(&self, r: RequestCheckTx) -> ResponseCheckTx {
        let result = (|| {
            ensure!(r.encoded_len() <= MAX_REQUEST, "transaction request budget");
            let inner = self.lock()?;
            ensure!(
                !inner
                    .engine
                    .store()
                    .gc_status(GcPolicy::default())?
                    .pressure,
                "temporary local maintenance pressure; retry the same signed bytes later"
            );
            inner.engine.validate_tx(&r.tx)
        })();
        match result {
            Ok(()) => ResponseCheckTx::default(),
            Err(e) => ResponseCheckTx {
                code: 1,
                log: e.to_string(),
                ..Default::default()
            },
        }
    }
    fn query(&self, r: RequestQuery) -> ResponseQuery {
        match self.query_value(r) {
            Ok((height, value)) => ResponseQuery {
                height,
                value: value.into(),
                ..Default::default()
            },
            Err(e) => ResponseQuery {
                code: 1,
                log: e.to_string(),
                ..Default::default()
            },
        }
    }
    fn offer_snapshot(&self, _: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        ResponseOfferSnapshot {
            result: response_offer_snapshot::Result::Reject as i32,
        }
    }
    fn apply_snapshot_chunk(&self, _: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        ResponseApplySnapshotChunk {
            result: response_apply_snapshot_chunk::Result::Abort as i32,
            refetch_chunks: vec![],
            reject_senders: vec![],
        }
    }
    fn verify_vote_extension(&self, r: RequestVerifyVoteExtension) -> ResponseVerifyVoteExtension {
        ResponseVerifyVoteExtension {
            status: if r.vote_extension.is_empty() {
                response_verify_vote_extension::VerifyStatus::Accept as i32
            } else {
                response_verify_vote_extension::VerifyStatus::Reject as i32
            },
        }
    }
}
