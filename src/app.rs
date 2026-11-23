//! Durable ABCI boundary for the deliberately incomplete, devnet-only foundation.
//!
//! CometBFT drives consensus; this application never acknowledges a successful
//! commit until the state record has been durably committed by the store.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use prost::Message;
use serde_json::json;
use sha2::{Digest, Sha256};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    ExecTxResult, RequestApplySnapshotChunk, RequestCheckTx, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal,
    RequestProcessProposal, RequestQuery, RequestVerifyVoteExtension, ResponseApplySnapshotChunk,
    ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock, ResponseInfo, ResponseInitChain,
    ResponseListSnapshots, ResponseLoadSnapshotChunk, ResponseOfferSnapshot,
    ResponsePrepareProposal, ResponseProcessProposal, ResponseQuery, ResponseVerifyVoteExtension,
    response_apply_snapshot_chunk, response_offer_snapshot, response_process_proposal,
    response_verify_vote_extension,
};
use tendermint_proto::v0_38::types::{BlockParams, ConsensusParams, EvidenceParams, VersionParams};

use crate::{
    ledger::{self, Genesis, State},
    store::{Record, Store},
};

const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_GENESIS_BYTES: usize = 1024 * 1024;
pub const PROTOCOL_VERSION: u64 = 1;
pub const CONSENSUS_BLOCK_BYTES: i64 = 1024 * 1024;
pub const CONSENSUS_EVIDENCE_BYTES: i64 = 64 * 1024;

/// Version1 is a fresh development network. Comet updates non-None categories
/// wholesale, so every field of Block/Evidence is specified; Validator/ABCI
/// categories remain untouched. The default 48h evidence age is a lab policy.
fn protocol_consensus_params() -> ConsensusParams {
    ConsensusParams {
        block: Some(BlockParams {
            max_bytes: CONSENSUS_BLOCK_BYTES,
            max_gas: -1,
        }),
        evidence: Some(EvidenceParams {
            max_age_num_blocks: 100_000,
            max_age_duration: Some(tendermint_proto::google::protobuf::Duration {
                seconds: 48 * 3600,
                nanos: 0,
            }),
            max_bytes: CONSENSUS_EVIDENCE_BYTES,
        }),
        version: Some(VersionParams {
            app: PROTOCOL_VERSION,
        }),
        validator: None,
        abci: None,
    }
}
// Full-state proofs are a laboratory constraint. Charge every integer at its
// largest encoded width so an empty block can never overflow solely as clocks,
// balances or nonces acquire another decimal digit.
const MAX_CAPACITY_BYTES: usize = 4 * 1024 * 1024;

fn capacity_charge(value: &serde_json::Value) -> usize {
    use serde_json::Value;
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(_) => 20,
        Value::String(value) => {
            let actual = serde_json::to_vec(value)
                .expect("JSON string encoding")
                .len();
            let digits = value.strip_prefix('-').unwrap_or(value);
            if !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && value.len() <= 20
            {
                actual + 20 - value.len()
            } else {
                actual
            }
        }
        Value::Array(values) => {
            2 + values.len().saturating_sub(1) + values.iter().map(capacity_charge).sum::<usize>()
        }
        Value::Object(values) => {
            2 + values.len().saturating_sub(1)
                + values
                    .iter()
                    .map(|(key, value)| {
                        serde_json::to_vec(key).expect("JSON key encoding").len()
                            + 1
                            + capacity_charge(value)
                    })
                    .sum::<usize>()
        }
    }
}

pub fn state_capacity_charge(state: &State) -> Result<usize> {
    let value =
        serde_json::to_value(state).map_err(|error| failure("measure state capacity", error))?;
    Ok(capacity_charge(&value))
}

fn validate_capacity(state: &State) -> Result<()> {
    if state_capacity_charge(state)? > MAX_CAPACITY_BYTES {
        return Err(AppError("laboratory state/proof capacity exceeded".into()));
    }
    Ok(())
}

fn configured_genesis_validators(genesis: &Genesis, request: &RequestInitChain) -> Result<()> {
    if genesis.economics.mode == ledger::EconomicMode::BankOnly {
        return Ok(());
    }
    if request.validators.len() != genesis.economics.operators.len()
        || request.validators.is_empty()
    {
        return Err(AppError(
            "economic operators differ from consensus genesis".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for validator in &request.validators {
        let key = match validator.pub_key.as_ref().and_then(|key| key.sum.as_ref()) {
            Some(tendermint_proto::crypto::public_key::Sum::Ed25519(key)) => hex::encode(key),
            _ => return Err(AppError("unsupported genesis consensus key".into())),
        };
        let operator = genesis
            .economics
            .operators
            .iter()
            .find(|operator| operator.consensus_key == key)
            .ok_or_else(|| AppError("unknown genesis consensus key".into()))?;
        if !seen.insert(key)
            || validator.power <= 0
            || u64::try_from(validator.power).ok() != Some(operator.power)
        {
            return Err(AppError("invalid genesis operator power".into()));
        }
    }
    Ok(())
}

fn eligible_keys(
    state: &State,
    votes: impl IntoIterator<Item = (Option<tendermint_proto::v0_38::abci::Validator>, i32)>,
) -> Result<Vec<String>> {
    if state.genesis.economics.mode == ledger::EconomicMode::BankOnly {
        return Ok(Vec::new());
    }
    let mut keys = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut count = 0;
    for (validator, flag) in votes {
        count += 1;
        if count > ledger::MAX_OPERATORS {
            return Err(AppError("commit voter budget exceeded".into()));
        }
        if flag != 2 {
            continue;
        }
        let validator = validator.ok_or_else(|| AppError("commit vote has no validator".into()))?;
        let operator = state
            .genesis
            .economics
            .operators
            .iter()
            .find(|operator| {
                hex::decode(&operator.consensus_key)
                    .is_ok_and(|key| Sha256::digest(key)[..20] == validator.address[..])
            })
            .ok_or_else(|| AppError("unknown commit voter".into()))?;
        if !seen.insert(operator.consensus_key.clone())
            || u64::try_from(validator.power).ok() != Some(operator.power)
        {
            return Err(AppError(
                "duplicate or incorrectly weighted commit voter".into(),
            ));
        }
        keys.push(operator.consensus_key.clone());
    }
    Ok(keys)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError(pub String);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for AppError {}

type Result<T> = std::result::Result<T, AppError>;

fn failure(context: &str, error: impl fmt::Display) -> AppError {
    AppError(format!("{context}: {error}"))
}

fn timestamp_micros(value: Option<&tendermint_proto::google::protobuf::Timestamp>) -> Result<i64> {
    let value = value.ok_or_else(|| AppError("missing consensus timestamp".into()))?;
    if value.seconds < 0 || !(0..1_000_000_000).contains(&value.nanos) {
        return Err(AppError("invalid consensus timestamp".into()));
    }
    value
        .seconds
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(i64::from(value.nanos / 1_000)))
        .ok_or_else(|| AppError("consensus timestamp overflow".into()))
}

#[derive(Clone)]
pub struct App {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    store: Store,
    committed: Option<State>,
    pending: Option<Pending>,
    faulted: bool,
}

struct Pending {
    state: State,
    record: Record,
    transaction_count: usize,
}

impl App {
    pub fn new(store: Store) -> Result<Self> {
        let current = store
            .load()
            .map_err(|error| failure("load committed state", error))?;
        let committed = if let Some(record) = current {
            let state: State = serde_json::from_slice(&record.state)
                .map_err(|error| failure("decode committed state", error))?;
            if state.protocol_version != PROTOCOL_VERSION {
                return Err(AppError("unsupported durable legacy development protocol; preserve this database and use its original binary, or start a fresh version1 network with new genesis and signer directories".into()));
            }
            state
                .validate()
                .map_err(|error| failure("validate committed state", error))?;
            validate_capacity(&state)?;
            let canonical =
                serde_json::to_vec(&state).map_err(|error| failure("encode state", error))?;
            if canonical != record.state
                || state.height != record.height
                || state
                    .hash()
                    .map_err(|error| failure("hash state", error))?
                    .as_slice()
                    != record.app_hash
            {
                return Err(AppError(
                    "committed state does not match its durable record".into(),
                ));
            }
            let genesis_record = store
                .get(0)
                .map_err(|error| failure("load genesis", error))?
                .ok_or_else(|| AppError("committed state has no durable genesis".into()))?;
            let genesis_state: State = serde_json::from_slice(&genesis_record.state)
                .map_err(|error| failure("decode genesis", error))?;
            let expected = ledger::new(state.genesis.clone())
                .map_err(|error| failure("validate genesis", error))?;
            if genesis_state != expected || expected.network_id != state.network_id {
                return Err(AppError(
                    "committed state changed the genesis identity".into(),
                ));
            }
            Some(state)
        } else {
            None
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                store,
                committed,
                pending: None,
                faulted: false,
            })),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| AppError("application lock poisoned; restart and inspect state".into()))?;
        if guard.faulted {
            return Err(AppError(
                "application faulted; refusing further state processing".into(),
            ));
        }
        Ok(guard)
    }

    fn abort_request<T>(&self, operation: &str, error: AppError) -> T {
        if let Ok(mut inner) = self.inner.lock() {
            inner.faulted = true;
        }
        // The selected low-level ABCI trait cannot return a transport error.
        // Panicking terminates this request/connection without a success reply;
        // the shared fault flag prevents other connections processing more state.
        panic!("ABCI {operation} failed closed: {error}")
    }

    pub fn committed_state(&self) -> Result<Option<State>> {
        Ok(self.lock()?.committed.clone())
    }

    pub fn try_init_chain(&self, request: RequestInitChain) -> Result<ResponseInitChain> {
        if request.encoded_len() > MAX_REQUEST_BYTES
            || request.validators.len() > ledger::MAX_OPERATORS
        {
            return Err(AppError(
                "genesis request or validator set exceeds protocol1 budget".into(),
            ));
        }
        if request.initial_height != 0 && request.initial_height != 1 {
            return Err(AppError("only initial height one is supported".into()));
        }
        if request.app_state_bytes.is_empty() || request.app_state_bytes.len() > MAX_GENESIS_BYTES {
            return Err(AppError("invalid genesis app-state size".into()));
        }
        let genesis: Genesis = serde_json::from_slice(&request.app_state_bytes)
            .map_err(|error| failure("decode genesis app state", error))?;
        if genesis.chain_id != request.chain_id
            || genesis.genesis_time_micros != timestamp_micros(request.time.as_ref())?
        {
            return Err(AppError(
                "genesis chain or timestamp differs from CometBFT genesis".into(),
            ));
        }
        configured_genesis_validators(&genesis, &request)?;
        let initial = ledger::new(genesis).map_err(|error| failure("create genesis", error))?;
        validate_capacity(&initial)?;
        let app_hash = initial
            .hash()
            .map_err(|error| failure("hash genesis", error))?
            .to_vec();
        let mut inner = self.lock()?;
        if let Some(existing) = &inner.committed {
            if existing.genesis != initial.genesis || existing.network_id != initial.network_id {
                return Err(AppError("attempt to replace initialized genesis".into()));
            }
        } else {
            let state =
                serde_json::to_vec(&initial).map_err(|error| failure("encode genesis", error))?;
            let record = Record {
                height: 0,
                app_hash: app_hash.clone(),
                state,
                block_hash: Vec::new(),
                parent_app_hash: Vec::new(),
                request_hash: Vec::new(),
            };
            if let Err(error) = inner.store.initialize(&record) {
                inner.faulted = true;
                return Err(failure("persist genesis", error));
            }
            inner.committed = Some(initial);
        }
        Ok(ResponseInitChain {
            app_hash: app_hash.into(),
            consensus_params: Some(protocol_consensus_params()),
            ..Default::default()
        })
    }

    pub fn try_finalize_block(
        &self,
        request: RequestFinalizeBlock,
    ) -> Result<ResponseFinalizeBlock> {
        if request.encoded_len() > MAX_REQUEST_BYTES || request.hash.len() != 32 {
            return Err(AppError("invalid finalized block size or hash".into()));
        }
        ledger::validate_block_transactions(&request.txs)
            .map_err(|error| failure("invalid finalized transaction budget", error))?;
        let time = timestamp_micros(request.time.as_ref())?;
        let request_hash = Sha256::digest(request.encode_to_vec()).to_vec();
        let transactions: Vec<Vec<u8>> = request.txs.iter().map(|tx| tx.to_vec()).collect();
        let mut inner = self.lock()?;
        let committed = inner
            .committed
            .as_ref()
            .ok_or_else(|| AppError("chain not initialized".into()))?;
        if let Some(pending) = &inner.pending {
            if pending.record.request_hash != request_hash {
                return Err(AppError("different finalized request before commit".into()));
            }
            return Ok(finalized_response(
                pending.record.app_hash.clone(),
                pending.transaction_count,
            ));
        }
        if request.height == committed.height && request.height > 0 {
            let record = inner
                .store
                .get(request.height)
                .map_err(|error| failure("read finalized replay", error))?
                .ok_or_else(|| AppError("missing finalized replay record".into()))?;
            if record.request_hash != request_hash || record.block_hash != request.hash.as_ref() {
                return Err(AppError(
                    "different finalized request at committed height".into(),
                ));
            }
            return Ok(finalized_response(record.app_hash, transactions.len()));
        }
        let keys = eligible_keys(
            committed,
            request
                .decided_last_commit
                .iter()
                .flat_map(|commit| commit.votes.iter())
                .map(|vote| (vote.validator.clone(), vote.block_id_flag)),
        )?;
        let state =
            ledger::transition_with_eligible(committed, request.height, time, &transactions, &keys)
                .map_err(|error| failure("execute finalized block", error))?;
        validate_capacity(&state)?;
        let app_hash = state
            .hash()
            .map_err(|error| failure("hash finalized state", error))?
            .to_vec();
        let record = Record {
            height: state.height,
            app_hash: app_hash.clone(),
            state: serde_json::to_vec(&state)
                .map_err(|error| failure("encode finalized state", error))?,
            block_hash: request.hash.to_vec(),
            parent_app_hash: committed
                .hash()
                .map_err(|error| failure("hash parent", error))?
                .to_vec(),
            request_hash,
        };
        inner.pending = Some(Pending {
            state,
            record,
            transaction_count: transactions.len(),
        });
        Ok(finalized_response(app_hash, transactions.len()))
    }

    pub fn try_commit(&self) -> Result<ResponseCommit> {
        let mut inner = self.lock()?;
        if inner.committed.is_none() {
            return Err(AppError("chain not initialized".into()));
        }
        if let Some(pending) = &inner.pending {
            if let Err(error) = inner.store.commit(&pending.record) {
                inner.faulted = true;
                return Err(failure("durable commit", error));
            }
            let pending = inner.pending.take().expect("pending checked above");
            inner.committed = Some(pending.state);
        }
        Ok(ResponseCommit { retain_height: 0 })
    }

    pub fn try_prepare_proposal(
        &self,
        request: RequestPrepareProposal,
    ) -> Result<ResponsePrepareProposal> {
        if request.encoded_len() > MAX_REQUEST_BYTES || request.max_tx_bytes < 0 {
            return Err(AppError("invalid proposal request limits".into()));
        }
        let time = timestamp_micros(request.time.as_ref())?;
        let inner = self.lock()?;
        let committed = inner
            .committed
            .as_ref()
            .ok_or_else(|| AppError("chain not initialized".into()))?;
        let keys = eligible_keys(
            committed,
            request
                .local_last_commit
                .iter()
                .flat_map(|commit| commit.votes.iter())
                .map(|vote| (vote.validator.clone(), vote.block_id_flag)),
        )?;
        let mut candidate =
            ledger::transition_with_eligible(committed, request.height, time, &[], &keys)
                .map_err(|error| failure("prepare proposal time/height", error))?;
        let maximum = usize::try_from(request.max_tx_bytes)
            .unwrap_or(usize::MAX)
            .min(ledger::MAX_BLOCK_TX_BYTES);
        let mut total = 0usize;
        let mut txs = Vec::new();
        for tx in request.txs {
            if txs.len() == ledger::MAX_BLOCK_TXS {
                break;
            }
            if tx.len() > maximum.saturating_sub(total) {
                continue;
            }
            if ledger::apply_tx(&mut candidate, &tx).is_ok() {
                total += tx.len();
                txs.push(tx);
            }
        }
        if validate_capacity(&candidate).is_err() {
            txs.clear();
        }
        Ok(ResponsePrepareProposal { txs })
    }
}

fn finalized_response(app_hash: Vec<u8>, count: usize) -> ResponseFinalizeBlock {
    ResponseFinalizeBlock {
        app_hash: app_hash.into(),
        tx_results: (0..count).map(|_| ExecTxResult::default()).collect(),
        consensus_param_updates: Some(protocol_consensus_params()),
        ..Default::default()
    }
}

impl Application for App {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let inner = self
            .lock()
            .unwrap_or_else(|error| self.abort_request("Info", error));
        ResponseInfo {
            data: "timecurrency-devnet-v1; public launch disabled".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            app_version: PROTOCOL_VERSION,
            last_block_height: inner.committed.as_ref().map_or(0, |state| state.height),
            last_block_app_hash: inner
                .committed
                .as_ref()
                .map_or_else(Vec::new, |state| {
                    state.hash().expect("committed state validated").to_vec()
                })
                .into(),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        self.try_init_chain(request)
            .unwrap_or_else(|error| self.abort_request("InitChain", error))
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        self.try_finalize_block(request)
            .unwrap_or_else(|error| self.abort_request("FinalizeBlock", error))
    }

    fn commit(&self) -> ResponseCommit {
        self.try_commit()
            .unwrap_or_else(|error| self.abort_request("Commit", error))
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        self.try_prepare_proposal(request)
            .unwrap_or_else(|error| self.abort_request("PrepareProposal", error))
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        let accepted = (|| -> Result<()> {
            if request.encoded_len() > MAX_REQUEST_BYTES || request.hash.len() != 32 {
                return Err(AppError("invalid proposal size or hash".into()));
            }
            ledger::validate_block_transactions(&request.txs)
                .map_err(|error| failure("invalid proposal transaction budget", error))?;
            let time = timestamp_micros(request.time.as_ref())?;
            let inner = self.lock()?;
            let committed = inner
                .committed
                .as_ref()
                .ok_or_else(|| AppError("chain not initialized".into()))?;
            let txs = request.txs.iter().map(|tx| tx.to_vec()).collect::<Vec<_>>();
            let keys = eligible_keys(
                committed,
                request
                    .proposed_last_commit
                    .iter()
                    .flat_map(|commit| commit.votes.iter())
                    .map(|vote| (vote.validator.clone(), vote.block_id_flag)),
            )?;
            let candidate =
                ledger::transition_with_eligible(committed, request.height, time, &txs, &keys)
                    .map_err(|error| failure("validate complete proposal", error))?;
            validate_capacity(&candidate)?;
            Ok(())
        })()
        .is_ok();
        ResponseProcessProposal {
            status: if accepted {
                response_process_proposal::ProposalStatus::Accept as i32
            } else {
                response_process_proposal::ProposalStatus::Reject as i32
            },
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        let result = (|| -> Result<()> {
            let inner = self.lock()?;
            let state = inner
                .committed
                .as_ref()
                .ok_or_else(|| AppError("chain not initialized".into()))?;
            ledger::validate_tx(state, &request.tx)
                .map_err(|error| failure("invalid transaction", error))
        })();
        match result {
            Ok(()) => ResponseCheckTx {
                code: 0,
                ..Default::default()
            },
            Err(error) => ResponseCheckTx {
                code: 1,
                log: error.to_string(),
                ..Default::default()
            },
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let result = (|| -> Result<(i64, Vec<u8>)> {
            if request.prove {
                return Err(AppError(
                    "authenticated query proofs are not implemented".into(),
                ));
            }
            let inner = self.lock()?;
            let state = inner.committed.as_ref();
            let height = state.map_or(0, |value| value.height);
            if request.path == "/snapshot" {
                let desired = if request.height == 0 {
                    height
                } else {
                    request.height
                };
                if desired < 0 || desired > height {
                    return Err(AppError("snapshot height out of range".into()));
                }
                let record = inner
                    .store
                    .get(desired)
                    .map_err(|error| failure("load snapshot", error))?
                    .ok_or_else(|| AppError("snapshot unavailable".into()))?;
                if record.state.len() > MAX_CAPACITY_BYTES {
                    return Err(AppError(
                        "full-state proof exceeds laboratory query limit".into(),
                    ));
                }
                return Ok((desired, serde_json::to_vec(&json!({"height":desired.to_string(),"app_hash":hex::encode(record.app_hash),"state_b64":STANDARD.encode(record.state),"authenticated":false})).map_err(|error| failure("encode snapshot", error))?));
            }
            if request.height != 0 && request.height != height {
                return Err(AppError("historical query unsupported".into()));
            }
            let value = match request.path.as_str() {
                "/status" => json!({
                    "mode":"devnet-laboratory", "public_launch_allowed":false, "authenticated":false,
                    "protocol_version":PROTOCOL_VERSION.to_string(),
                    "height":height.to_string(), "chain_id":state.map(|value| &value.genesis.chain_id),
                    "time_micros":state.map(|value| value.time_micros.to_string()), "bank":state.map(|value| value.bank.to_string()),
                    "network_id":state.map(|value| &value.network_id), "account_count":state.map(|value| value.accounts.len()),
                    "limitations":["fixed genesis validators; permissionless selection/slashing not implemented", "synthetic development auction is not Bitcoin verification", "full-state proofs require external signed-header verification; state sync not implemented", "accepted chain time is not independently verified UTC"]
                }),
                "/account" => {
                    if request.data.len() > 64 {
                        return Err(AppError("account query too long".into()));
                    }
                    let name = std::str::from_utf8(&request.data)
                        .map_err(|error| failure("account query UTF-8", error))?;
                    let state = state.ok_or_else(|| AppError("chain not initialized".into()))?;
                    let account = state
                        .accounts
                        .iter()
                        .find(|account| account.name == name)
                        .ok_or_else(|| AppError("account not found".into()))?;
                    json!({"authenticated":false,"account":account})
                }
                _ => return Err(AppError("unsupported query path".into())),
            };
            Ok((
                height,
                serde_json::to_vec(&value).map_err(|error| failure("encode query", error))?,
            ))
        })();
        match result {
            Ok((height, value)) => ResponseQuery {
                height,
                value: value.into(),
                ..Default::default()
            },
            Err(error) => ResponseQuery {
                code: 1,
                log: error.to_string(),
                ..Default::default()
            },
        }
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        ResponseListSnapshots::default()
    }
    fn offer_snapshot(&self, _: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        ResponseOfferSnapshot {
            result: response_offer_snapshot::Result::Reject as i32,
        }
    }
    fn load_snapshot_chunk(&self, _: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        ResponseLoadSnapshotChunk::default()
    }
    fn apply_snapshot_chunk(&self, _: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        ResponseApplySnapshotChunk {
            result: response_apply_snapshot_chunk::Result::Abort as i32,
            ..Default::default()
        }
    }
    fn verify_vote_extension(
        &self,
        request: RequestVerifyVoteExtension,
    ) -> ResponseVerifyVoteExtension {
        ResponseVerifyVoteExtension {
            status: if request.vote_extension.is_empty() {
                response_verify_vote_extension::VerifyStatus::Accept as i32
            } else {
                response_verify_vote_extension::VerifyStatus::Reject as i32
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;
    use tendermint_proto::google::protobuf::Timestamp;

    #[test]
    fn numeric_growth_cannot_consume_capacity_reserve() {
        let small =
            json!({"height":"9","bank":"0","signed":"-1","power":1,"values":["7",true,null]});
        let large = json!({"height":"9223372036854775807","bank":"18446744073709551615","signed":"-9223372036854775808","power":100,"values":["18446744073709551615",true,null]});
        assert_eq!(capacity_charge(&small), capacity_charge(&large));
        assert!(capacity_charge(&large) >= serde_json::to_vec(&large).unwrap().len());
        let new_record = json!([small.clone(), small.clone()]);
        assert!(capacity_charge(&new_record) > capacity_charge(&small));
    }

    #[test]
    fn capacity_charge_covers_json_escaping_and_fixed_strings() {
        for value in [
            json!({"name":"escaped\\\"\n😀","number":"12"}),
            json!([]),
            json!({}),
            json!([false, true, null, -1, "", "abc"]),
        ] {
            assert!(capacity_charge(&value) >= serde_json::to_vec(&value).unwrap().len());
        }
    }

    fn timestamp(micros: i64) -> Option<Timestamp> {
        Some(Timestamp {
            seconds: micros / 1_000_000,
            nanos: ((micros % 1_000_000) * 1_000) as i32,
        })
    }

    fn genesis() -> Genesis {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        Genesis {
            chain_id: "time-devnet-app-tests".into(),
            genesis_time_micros: 1_000_000,
            economics: ledger::Economics::default(),
            accounts: vec![
                ledger::GenesisAccount {
                    id: 0,
                    name: "alice".into(),
                    public_key: hex::encode(key.verifying_key().to_bytes()),
                },
                ledger::GenesisAccount {
                    id: 1,
                    name: "bob".into(),
                    public_key: hex::encode(other.verifying_key().to_bytes()),
                },
            ],
        }
    }

    fn init_request() -> RequestInitChain {
        let g = genesis();
        RequestInitChain {
            chain_id: g.chain_id.clone(),
            time: timestamp(g.genesis_time_micros),
            initial_height: 1,
            app_state_bytes: serde_json::to_vec(&g).unwrap().into(),
            ..Default::default()
        }
    }

    fn block(height: i64) -> RequestFinalizeBlock {
        RequestFinalizeBlock {
            height,
            time: timestamp(1_000_000 + height * 1_000_000),
            hash: vec![height as u8; 32].into(),
            ..Default::default()
        }
    }

    fn fixture() -> (TempDir, App) {
        let directory = tempfile::tempdir().unwrap();
        let app = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        app.try_init_chain(init_request()).unwrap();
        (directory, app)
    }

    #[test]
    fn protocol1_pins_safe_comet_budgets_and_exact_finalize_response_replays() {
        let directory = tempfile::tempdir().unwrap();
        let app = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        let initialized = app.try_init_chain(init_request()).unwrap();
        let parameters = initialized.consensus_params.unwrap();
        assert_eq!(
            parameters.block.unwrap(),
            BlockParams {
                max_bytes: 1_048_576,
                max_gas: -1
            }
        );
        let evidence = parameters.evidence.unwrap();
        assert_eq!(evidence.max_bytes, 65_536);
        assert_eq!(evidence.max_age_num_blocks, 100_000);
        assert_eq!(evidence.max_age_duration.unwrap().seconds, 172_800);
        assert_eq!(parameters.version.unwrap().app, 1);
        assert!(parameters.validator.is_none());
        assert!(parameters.abci.is_none());
        assert!(
            CONSENSUS_BLOCK_BYTES as usize + CONSENSUS_EVIDENCE_BYTES as usize + 100 * 1024
                < MAX_REQUEST_BYTES
        );
        assert_eq!(app.committed_state().unwrap().unwrap().protocol_version, 1);
        assert_eq!(app.info(RequestInfo::default()).app_version, 1);
        let expected = app.try_finalize_block(block(1)).unwrap().encode_to_vec();
        assert_eq!(
            app.try_finalize_block(block(1)).unwrap().encode_to_vec(),
            expected
        );
        app.try_commit().unwrap();
        assert_eq!(
            app.try_finalize_block(block(1)).unwrap().encode_to_vec(),
            expected
        );
        drop(app);
        let reopened = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        assert_eq!(
            reopened
                .try_finalize_block(block(1))
                .unwrap()
                .encode_to_vec(),
            expected
        );
    }

    #[test]
    fn protocol1_refuses_legacy_database_without_modifying_it() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("legacy.redb");
        let mut legacy = ledger::new(genesis()).unwrap();
        legacy.protocol_version = 0;
        legacy.validate().unwrap();
        let bytes = serde_json::to_vec(&legacy).unwrap();
        assert!(
            !String::from_utf8(bytes.clone())
                .unwrap()
                .contains("protocol_version")
        );
        let record = Record {
            height: 0,
            app_hash: legacy.hash().unwrap().to_vec(),
            state: bytes.clone(),
            block_hash: Vec::new(),
            parent_app_hash: Vec::new(),
            request_hash: Vec::new(),
        };
        let store = Store::open(&database).unwrap();
        store.initialize(&record).unwrap();
        drop(store);
        let error = App::new(Store::open(&database).unwrap())
            .err()
            .expect("legacy must not migrate silently");
        assert!(error.0.contains("unsupported durable legacy"));
        let reopened = Store::open(&database).unwrap();
        assert_eq!(reopened.load().unwrap().unwrap().state, bytes);
    }

    #[test]
    fn oversized_aggregate_transactions_reject_without_publication_or_faulting_app() {
        let (_directory, app) = fixture();
        let before = app.committed_state().unwrap().unwrap();
        let parts = vec![
            prost::bytes::Bytes::from(vec![0; ledger::MAX_BLOCK_TX_BYTES / 2 + 1]),
            prost::bytes::Bytes::from(vec![0; ledger::MAX_BLOCK_TX_BYTES / 2]),
        ];
        let proposal = RequestProcessProposal {
            height: 1,
            time: timestamp(2_000_000),
            hash: vec![1; 32].into(),
            txs: parts.clone(),
            ..Default::default()
        };
        assert!(proposal.encoded_len() < MAX_REQUEST_BYTES);
        assert_eq!(
            app.process_proposal(proposal).status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        let mut finalized = block(1);
        finalized.txs = parts;
        assert!(
            app.try_finalize_block(finalized)
                .unwrap_err()
                .0
                .contains("byte budget")
        );
        assert_eq!(app.committed_state().unwrap().unwrap(), before);
        assert!(app.inner.lock().unwrap().pending.is_none());
        app.try_finalize_block(block(1)).unwrap();
        app.try_commit().unwrap();
        assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
    }

    #[test]
    fn finalize_is_not_durable_until_commit_and_restart_recovers_exact_hash() {
        let (directory, app) = fixture();
        let initial = app.info(RequestInfo::default());
        let response = app.try_finalize_block(block(1)).unwrap();
        assert_ne!(response.app_hash, initial.last_block_app_hash);
        assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
        assert_eq!(
            app.inner
                .lock()
                .unwrap()
                .store
                .load()
                .unwrap()
                .unwrap()
                .height,
            0
        );
        app.try_commit().unwrap();
        assert_eq!(
            app.info(RequestInfo::default()).last_block_app_hash,
            response.app_hash
        );
        assert_eq!(app.committed_state().unwrap().unwrap().bank, 1_000_000);
        drop(app);
        let reopened = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        assert_eq!(reopened.info(RequestInfo::default()).last_block_height, 1);
        assert_eq!(
            reopened.info(RequestInfo::default()).last_block_app_hash,
            response.app_hash
        );
        assert_eq!(
            reopened.try_finalize_block(block(1)).unwrap().app_hash,
            response.app_hash
        );
        reopened.try_commit().unwrap();
        assert_eq!(reopened.committed_state().unwrap().unwrap().bank, 1_000_000);
    }

    #[test]
    fn unfinished_finalize_is_discarded_on_restart_and_can_be_replayed() {
        let (directory, app) = fixture();
        let expected = app.try_finalize_block(block(1)).unwrap().app_hash;
        drop(app);
        let reopened = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        assert_eq!(reopened.info(RequestInfo::default()).last_block_height, 0);
        assert_eq!(reopened.committed_state().unwrap().unwrap().bank, 0);
        assert_eq!(
            reopened.try_finalize_block(block(1)).unwrap().app_hash,
            expected
        );
        reopened.try_commit().unwrap();
        assert_eq!(reopened.info(RequestInfo::default()).last_block_height, 1);
    }

    #[test]
    fn cloned_connections_share_committed_state_but_do_not_expose_pending_state() {
        let (_directory, consensus) = fixture();
        let query = consensus.clone();
        consensus.try_finalize_block(block(1)).unwrap();
        assert_eq!(query.info(RequestInfo::default()).last_block_height, 0);
        consensus.try_commit().unwrap();
        assert_eq!(query.info(RequestInfo::default()).last_block_height, 1);
    }

    #[test]
    fn first_comet_block_can_equal_genesis_time_without_minting() {
        let (_directory, app) = fixture();
        let mut first = block(1);
        first.time = timestamp(genesis().genesis_time_micros);
        app.try_finalize_block(first).unwrap();
        app.try_commit().unwrap();
        let state = app.committed_state().unwrap().unwrap();
        assert_eq!(state.height, 1);
        assert_eq!(state.bank, 0);
        assert_eq!(state.time_micros, state.genesis.genesis_time_micros);
        let mut unchanged_time = block(2);
        unchanged_time.time = timestamp(state.time_micros);
        assert!(app.try_finalize_block(unchanged_time).is_err());
        app.try_finalize_block(block(2)).unwrap();
        app.try_commit().unwrap();
        assert_eq!(app.committed_state().unwrap().unwrap().bank, 2_000_000);
    }

    #[test]
    fn retries_bind_complete_body_and_metadata_not_only_the_block_hash() {
        let (_directory, app) = fixture();
        let response = app.try_finalize_block(block(1)).unwrap();
        assert_eq!(
            app.try_finalize_block(block(1)).unwrap().app_hash,
            response.app_hash
        );
        let mut changed = block(1);
        changed.txs.push(vec![0; ledger::TX_SIZE].into());
        assert!(app.try_finalize_block(changed).is_err());
        let mut changed = block(1);
        changed.time = timestamp(2_000_001);
        assert!(app.try_finalize_block(changed).is_err());
        app.try_commit().unwrap();
        let mut changed = block(1);
        changed.proposer_address = vec![1; 20].into();
        assert!(app.try_finalize_block(changed).is_err());
        assert_eq!(app.committed_state().unwrap().unwrap().height, 1);
    }

    #[test]
    fn initialization_is_strict_chain_bound_and_cannot_reset_committed_state() {
        let directory = tempfile::tempdir().unwrap();
        let app = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        let mut bad = init_request();
        bad.chain_id = "time-mainnet".into();
        assert!(app.try_init_chain(bad).is_err());
        let mut bad = init_request();
        bad.time = timestamp(1_000_001);
        assert!(app.try_init_chain(bad).is_err());
        let mut bad = init_request();
        let mut value = serde_json::to_value(genesis()).unwrap();
        value["allow_premine"] = json!(true);
        bad.app_state_bytes = serde_json::to_vec(&value).unwrap().into();
        assert!(app.try_init_chain(bad).is_err());
        assert!(app.inner.lock().unwrap().store.load().unwrap().is_none());
        app.try_init_chain(init_request()).unwrap();
        app.try_finalize_block(block(1)).unwrap();
        app.try_commit().unwrap();
        let original = app.info(RequestInfo::default()).last_block_app_hash;
        app.try_init_chain(init_request()).unwrap();
        assert_eq!(
            app.info(RequestInfo::default()).last_block_app_hash,
            original
        );
        let mut replacement = init_request();
        let mut other = genesis();
        other.accounts[0].name = "mallory".into();
        replacement.app_state_bytes = serde_json::to_vec(&other).unwrap().into();
        assert!(app.try_init_chain(replacement).is_err());
    }

    // This fixture deliberately redistributes pre-aged supply only inside a
    // unit test. There is no corresponding application/API operation or faucet.
    fn funded_fixture() -> (TempDir, App, SigningKey) {
        let (directory, app) = fixture();
        app.try_finalize_block(block(1)).unwrap();
        app.try_commit().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        {
            let mut inner = app.inner.lock().unwrap();
            let state = inner.committed.as_mut().unwrap();
            state.accounts[0].balance = 100_000;
            state.bank -= 100_000;
            state.validate().unwrap();
        }
        (directory, app, key)
    }

    fn transfer(app: &App, key: &SigningKey, nonce: u64) -> Vec<u8> {
        ledger::sign_tx(
            &ledger::Tx {
                network_id: app.committed_state().unwrap().unwrap().network_id,
                from: 0,
                to: 1,
                nonce,
                amount: 1_000,
                fee: ledger::FEE_MICROS,
                signature: vec![],
            },
            key,
        )
        .unwrap()
    }

    #[test]
    fn proposal_filter_executes_sequentially_and_process_checks_full_body() {
        let (_directory, app, key) = funded_fixture();
        let first = transfer(&app, &key, 1);
        let second = transfer(&app, &key, 2);
        let before = app.committed_state().unwrap().unwrap();
        let request = RequestPrepareProposal {
            height: 2,
            time: timestamp(3_000_000),
            max_tx_bytes: (2 * ledger::TX_SIZE) as i64,
            txs: vec![
                vec![0; ledger::TX_SIZE].into(),
                first.clone().into(),
                second.clone().into(),
            ],
            ..Default::default()
        };
        let prepared = app.try_prepare_proposal(request).unwrap();
        assert_eq!(
            prepared.txs,
            vec![
                prost::bytes::Bytes::from(first.clone()),
                prost::bytes::Bytes::from(second.clone())
            ]
        );
        let request = RequestProcessProposal {
            height: 2,
            time: timestamp(3_000_000),
            hash: vec![2; 32].into(),
            txs: prepared.txs.clone(),
            ..Default::default()
        };
        assert_eq!(
            app.process_proposal(request.clone()).status,
            response_process_proposal::ProposalStatus::Accept as i32
        );
        let mut changed = request;
        changed.txs[0] = vec![0; ledger::TX_SIZE].into();
        assert_eq!(
            app.process_proposal(changed).status,
            response_process_proposal::ProposalStatus::Reject as i32
        );
        assert_eq!(app.committed_state().unwrap().unwrap(), before);
        assert_eq!(
            app.check_tx(RequestCheckTx {
                tx: first.into(),
                ..Default::default()
            })
            .code,
            0
        );
        assert_ne!(
            app.check_tx(RequestCheckTx {
                tx: second.into(),
                ..Default::default()
            })
            .code,
            0
        );
    }

    #[test]
    fn proposal_byte_budget_filters_without_mutating_committed_state() {
        let (_directory, app, key) = funded_fixture();
        let first = transfer(&app, &key, 1);
        let second = transfer(&app, &key, 2);
        let response = app
            .try_prepare_proposal(RequestPrepareProposal {
                height: 2,
                time: timestamp(3_000_000),
                max_tx_bytes: ledger::TX_SIZE as i64,
                txs: vec![first.clone().into(), second.into()],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(response.txs, vec![prost::bytes::Bytes::from(first)]);
        assert_eq!(app.committed_state().unwrap().unwrap().accounts[0].nonce, 0);
    }

    #[test]
    fn prepare_clamps_untrusted_requested_transaction_budget_to_protocol_limit() {
        let (_directory, app, key) = funded_fixture();
        {
            let mut inner = app.inner.lock().unwrap();
            let state = inner.committed.as_mut().unwrap();
            state.time_micros += 20_000_000;
            state.accounts[0].balance += 20_000_000;
            state.auction_epoch = state.elapsed_micros().unwrap()
                / (state.genesis.economics.auction_epoch_seconds * ledger::MICROS_PER_SECOND);
            state.validate().unwrap();
        }
        let state = app.committed_state().unwrap().unwrap();
        let count = ledger::MAX_BLOCK_TX_BYTES / ledger::TX_SIZE + 1;
        let txs = (1..=count)
            .map(|nonce| prost::bytes::Bytes::from(transfer(&app, &key, nonce as u64)))
            .collect();
        let response = app
            .try_prepare_proposal(RequestPrepareProposal {
                height: state.height + 1,
                time: timestamp(state.time_micros + 1),
                max_tx_bytes: i64::MAX,
                txs,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(response.txs.len(), count - 1);
        assert!(
            response.txs.iter().map(|tx| tx.len()).sum::<usize>() <= ledger::MAX_BLOCK_TX_BYTES
        );
        assert_eq!(app.committed_state().unwrap().unwrap(), state);
    }

    #[test]
    fn failed_commit_does_not_publish_candidate_and_faults_all_connections() {
        let (directory, app) = fixture();
        app.try_finalize_block(block(1)).unwrap();
        {
            // Abort the real transaction after both record and head writes
            // have been staged, before redb can commit either one.
            app.inner.lock().unwrap().store.fail_next_commit_for_test();
        }
        assert!(app.try_commit().is_err());
        {
            let inner = app.inner.lock().unwrap();
            assert!(inner.faulted);
            assert_eq!(inner.committed.as_ref().unwrap().height, 0);
            assert_eq!(inner.store.load().unwrap().unwrap().height, 0);
            assert!(inner.store.get(1).unwrap().is_none());
        }
        assert!(app.try_finalize_block(block(2)).is_err());
        assert_ne!(
            app.query(RequestQuery {
                path: "/status".into(),
                ..Default::default()
            })
            .code,
            0
        );
        drop(app);
        let reopened = App::new(Store::open(&directory.path().join("app.redb")).unwrap()).unwrap();
        assert_eq!(reopened.info(RequestInfo::default()).last_block_height, 0);
    }

    #[test]
    fn trait_adapter_panics_instead_of_acknowledging_invalid_finality() {
        let (_directory, app) = fixture();
        let mut request = block(1);
        request.height = 2;
        let failed =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| app.finalize_block(request)));
        assert!(failed.is_err());
        assert!(app.try_commit().is_err());
    }

    #[test]
    fn invalid_timestamps_hashes_and_uninitialized_calls_fail_closed() {
        let (_directory, app) = fixture();
        for invalid in [
            None,
            Some(Timestamp {
                seconds: -1,
                nanos: 0,
            }),
            Some(Timestamp {
                seconds: 1,
                nanos: 1_000_000_000,
            }),
            Some(Timestamp {
                seconds: i64::MAX,
                nanos: 0,
            }),
        ] {
            let mut request = block(1);
            request.time = invalid;
            assert!(app.try_finalize_block(request).is_err());
        }
        let mut request = block(1);
        request.hash = vec![1; 31].into();
        assert!(app.try_finalize_block(request).is_err());
        assert_eq!(app.committed_state().unwrap().unwrap().height, 0);
        let directory = tempfile::tempdir().unwrap();
        let fresh = App::new(Store::open(&directory.path().join("fresh.redb")).unwrap()).unwrap();
        assert!(fresh.try_commit().is_err());
        assert!(fresh.try_finalize_block(block(1)).is_err());
        assert_ne!(fresh.check_tx(RequestCheckTx::default()).code, 0);
    }

    #[test]
    fn unsupported_proofs_snapshots_and_extensions_are_not_claimed_supported() {
        let (_directory, app) = fixture();
        let status = app.query(RequestQuery {
            path: "/status".into(),
            ..Default::default()
        });
        let value: serde_json::Value = serde_json::from_slice(&status.value).unwrap();
        assert_eq!(value["public_launch_allowed"], false);
        assert_eq!(value["authenticated"], false);
        assert_ne!(
            app.query(RequestQuery {
                path: "/status".into(),
                prove: true,
                ..Default::default()
            })
            .code,
            0
        );
        assert_ne!(
            app.query(RequestQuery {
                path: "/unknown".into(),
                ..Default::default()
            })
            .code,
            0
        );
        assert_eq!(
            app.offer_snapshot(RequestOfferSnapshot::default()).result,
            response_offer_snapshot::Result::Reject as i32
        );
        assert_eq!(
            app.apply_snapshot_chunk(RequestApplySnapshotChunk::default())
                .result,
            response_apply_snapshot_chunk::Result::Abort as i32
        );
        assert_eq!(
            app.verify_vote_extension(RequestVerifyVoteExtension {
                vote_extension: vec![1].into(),
                ..Default::default()
            })
            .status,
            response_verify_vote_extension::VerifyStatus::Reject as i32
        );
    }
}
