//! `time-bench-v5`: measures the application as the consensus engine drives
//! it, without a network.
//!
//! Every account is created and funded through the protocol's own actions
//! (validator rewards, sponsored registration, transfers); nothing is written
//! into the state directly. Block timestamps are synthetic, so hours of chain
//! time pass in seconds.
//!
//! Each measured block goes through the calls a validator receives:
//! mempool checks (`CheckTx`), the proposer's selection (`PrepareProposal`),
//! validation (`ProcessProposal`), `FinalizeBlock` and `Commit`.
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitcoin_bridge::{
    BitcoinNetwork, BridgeConfig,
    bitcoin::{
        PublicKey,
        secp256k1::{Secp256k1, SecretKey},
    },
};
use ed25519_dalek::{Signer, SigningKey};
use rayon::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Instant};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload, GenesisAccount};
use timecurrency_v5::{
    app::App,
    engine::{self, MAX_BLOCK_TX_BYTES, MAX_BLOCK_TXS},
    genesis::{AuctionConfig, BootstrapValidator, Genesis},
    transport::BatchCheck,
    wire,
};

const USAGE: &str = "time-bench-v5 --dir PATH [--accounts 100000] [--block-txs 10000] [--blocks 20] [--cold-blocks 5] [--threads N] [--service-records] [--out FILE]

Builds a chain with --accounts funded accounts in PATH (which must not exist), then measures blocks of --block-txs transfers.
--service-records starts the chain with the genesis setting service_records.";
const GENESIS_ACCOUNTS: u64 = 64;
const VALIDATORS: u64 = 4;
const GENESIS_TIME: i64 = 1_800_000_000_000_000;
/// Requests handed to the application at once, as the transport does.
const CHECK_BATCH: usize = 2048;
const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;

struct Options {
    dir: PathBuf,
    accounts: u64,
    block_txs: usize,
    blocks: usize,
    cold_blocks: usize,
    threads: Option<usize>,
    out: Option<PathBuf>,
    /// The chain keeps service records (genesis setting `service_records`).
    service_records: bool,
}

fn options() -> Result<Options> {
    let mut args = std::env::args().skip(1);
    let mut options = Options {
        dir: PathBuf::new(),
        accounts: 100_000,
        block_txs: 10_000,
        blocks: 20,
        cold_blocks: 5,
        threads: None,
        out: None,
        service_records: false,
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| anyhow!("{arg} needs a value"));
        match arg.as_str() {
            "--dir" => options.dir = PathBuf::from(value()?),
            "--accounts" => options.accounts = value()?.parse()?,
            "--block-txs" => options.block_txs = value()?.parse()?,
            "--blocks" => options.blocks = value()?.parse()?,
            "--cold-blocks" => options.cold_blocks = value()?.parse()?,
            "--threads" => options.threads = Some(value()?.parse()?),
            "--out" => options.out = Some(PathBuf::from(value()?)),
            "--service-records" => options.service_records = true,
            _ => bail!("unsupported argument {arg}"),
        }
    }
    ensure!(!options.dir.as_os_str().is_empty(), "--dir is required");
    ensure!(
        !options.dir.exists(),
        "--dir must not exist yet: the benchmark never reuses a state"
    );
    ensure!(
        (100..=5_000_000).contains(&options.accounts),
        "--accounts must be between 100 and 5000000"
    );
    ensure!(
        (1..=MAX_BLOCK_TXS).contains(&options.block_txs),
        "--block-txs must be between 1 and {MAX_BLOCK_TXS}"
    );
    ensure!(
        options.blocks >= 1 && options.blocks + options.cold_blocks <= 10_000,
        "invalid block counts"
    );
    Ok(options)
}

/// Deterministic test keys. They protect nothing: the chain exists only for
/// the duration of the benchmark.
fn key(label: &str, index: u64) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"time-bench-v5 key\0");
    hasher.update(label.as_bytes());
    hasher.update(index.to_be_bytes());
    SigningKey::from_bytes(&hasher.finalize().into())
}
fn public(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}
fn genesis(service_records: bool) -> Genesis {
    let secp = Secp256k1::new();
    let mut treasury_keys: Vec<String> = (1..=7u8)
        .map(|seed| {
            PublicKey::new(
                bitcoin_bridge::bitcoin::secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&[seed; 32]).expect("valid test scalar"),
                ),
            )
            .to_string()
        })
        .collect();
    treasury_keys.sort();
    Genesis {
        history_version: 1,
        bitcoin_receipt_version: 1,
        reward_version: 1,
        ledger: ledger::Genesis {
            chain_id: "time-devnet-v4-bench-engine-v5".into(),
            genesis_time_micros: GENESIS_TIME,
            accounts: (0..GENESIS_ACCOUNTS)
                .map(|id| GenesisAccount {
                    id,
                    name: format!("genesis_{id}"),
                    public_key: public(&key("genesis", id)),
                })
                .collect(),
            economics: Default::default(),
        },
        profile: pos::Profile::Laboratory,
        validators: (0..VALIDATORS)
            .map(|owner| BootstrapValidator {
                owner,
                consensus_key: public(&key("consensus", owner)),
                commission_bps: 1000,
            })
            .collect(),
        bitcoin: BridgeConfig::for_network(BitcoinNetwork::Regtest),
        treasury: treasury::Policy {
            revision: 1,
            governance_keys: (0..7).map(|index| public(&key("governance", index))).collect(),
            treasury_keys,
        },
        auction: AuctionConfig {
            epoch_seconds: 10,
            bid_lead_epochs: 1,
            max_future_epochs: 48,
            min_sats: 100,
            max_sats: 1_000_000,
        },
        registration: registration::Config::default(),
        recovery_min_delay_micros: 30 * pos::SECOND,
        recovery_approval_window_micros: 7 * pos::DAY,
        trusting_period_seconds: 7 * 86400,
        fees_to_validators_ppm: 0,
        // The protocol-4 fee: the budgets below are counted in it.
        fee_micros: ledger::FEE_MICROS,
        all_new_time_to_validators: false,
        stake_handover: false,
        distinct_names: false,
        waits_survive_stops: false,
        protected_registration: false,
        protected_accounts: Vec::new(),
        service_records,
        market: false,
    }
}
fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: micros / 1_000_000,
        nanos: ((micros % 1_000_000) * 1000) as i32,
    })
}
fn millis(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

/// A sender known to the benchmark: its account and what it may sign next.
#[derive(Clone)]
struct Sender {
    id: u64,
    key: SigningKey,
    public: String,
    nonce: u64,
}
impl Sender {
    fn new(id: u64, key: SigningKey) -> Self {
        let public = public(&key);
        Self {
            id,
            key,
            public,
            nonce: 0,
        }
    }
    /// Signs the next transfer and advances the local nonce.
    fn transfer(&mut self, network: &str, to: u64, amount: u64) -> Vec<u8> {
        self.nonce += 1;
        ledger::sign_action(
            &Action {
                network_id: network.into(),
                from: self.id,
                nonce: self.nonce,
                auth_epoch: 0,
                public_key: self.public.clone(),
                payload: ActionPayload::Transfer(ledger::Transfer { to, amount }),
                signature: vec![],
            },
            &self.key,
        )
        .expect("transfer encodes")
    }
}

#[derive(Default)]
struct Timing {
    txs: usize,
    bytes: usize,
    check_ms: f64,
    prepare_ms: f64,
    process_ms: f64,
    finalize_ms: f64,
    commit_ms: f64,
}

struct Chain {
    app: App,
    network: String,
    height: i64,
    elapsed: u64,
    voters: Vec<Validator>,
}
impl Chain {
    fn start(path: &std::path::Path, service_records: bool) -> Result<Self> {
        let genesis = genesis(service_records);
        genesis.validate().context("benchmark genesis")?;
        let app = App::open(path)?;
        app.try_init(RequestInitChain {
            chain_id: genesis.ledger.chain_id.clone(),
            time: timestamp(GENESIS_TIME),
            app_state_bytes: serde_json::to_vec(&genesis)?.into(),
            validators: genesis
                .validators
                .iter()
                .map(|validator| {
                    Ok(ValidatorUpdate {
                        pub_key: Some(tendermint_proto::crypto::PublicKey {
                            sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                                hex::decode(&validator.consensus_key)?,
                            )),
                        }),
                        power: genesis.profile.genesis_power() as i64,
                    })
                })
                .collect::<Result<_>>()?,
            ..Default::default()
        })?;
        let voters = genesis
            .validators
            .iter()
            .map(|validator| {
                Ok(Validator {
                    address: Sha256::digest(hex::decode(&validator.consensus_key)?)[..20]
                        .to_vec()
                        .into(),
                    power: genesis.profile.genesis_power() as i64,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            app,
            network: genesis.network_id()?,
            height: 0,
            elapsed: 0,
            voters,
        })
    }
    fn request(&self, delta: u64, txs: &[Vec<u8>]) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: timestamp(GENESIS_TIME + (self.elapsed + delta) as i64),
            hash: Sha256::digest(height.to_be_bytes()).to_vec().into(),
            txs: txs.iter().cloned().map(Into::into).collect(),
            decided_last_commit: (height > 1).then(|| CommitInfo {
                round: 0,
                votes: self
                    .voters
                    .iter()
                    .map(|validator| VoteInfo {
                        validator: Some(validator.clone()),
                        block_id_flag: BlockIdFlag::Commit as i32,
                    })
                    .collect(),
            }),
            // The validators take turns to propose, as CometBFT's equal
            // powers make them do. Only the service records read it.
            proposer_address: self.voters[height as usize % self.voters.len()].address.clone(),
            ..Default::default()
        }
    }
    /// One block through the calls a validator receives. `checked` says the
    /// transactions went through the mempool first; `propose` adds the
    /// proposer's selection step.
    fn block(&mut self, delta: u64, txs: &[Vec<u8>], checked: bool, propose: bool) -> Result<Timing> {
        let mut timing = Timing {
            txs: txs.len(),
            bytes: txs.iter().map(Vec::len).sum(),
            ..Default::default()
        };
        if checked {
            let started = Instant::now();
            for chunk in txs.chunks(CHECK_BATCH) {
                let results = self.app.check_batch(
                    chunk
                        .iter()
                        .map(|tx| RequestCheckTx {
                            tx: tx.clone().into(),
                            r#type: 0,
                        })
                        .collect(),
                );
                if let Some(bad) = results.iter().find(|result| result.code != 0) {
                    bail!("mempool refused a benchmark transaction: {}", bad.log);
                }
            }
            timing.check_ms = millis(started);
        }
        let request = self.request(delta, txs);
        if propose {
            let started = Instant::now();
            let chosen = self.app.prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: MAX_BLOCK_TX_BYTES as i64,
                txs: request.txs.clone(),
                local_last_commit: request.decided_last_commit.as_ref().map(|commit| {
                    ExtendedCommitInfo {
                        round: commit.round,
                        votes: commit
                            .votes
                            .iter()
                            .map(|vote| ExtendedVoteInfo {
                                validator: vote.validator.clone(),
                                block_id_flag: vote.block_id_flag,
                                ..Default::default()
                            })
                            .collect(),
                    }
                }),
                height: request.height,
                time: request.time.clone(),
                proposer_address: request.proposer_address.clone(),
                ..Default::default()
            });
            timing.prepare_ms = millis(started);
            ensure!(
                chosen.txs.len() == txs.len(),
                "the proposer kept {} of {} transactions",
                chosen.txs.len(),
                txs.len()
            );
        }
        let started = Instant::now();
        let status = self
            .app
            .process_proposal(RequestProcessProposal {
                txs: request.txs.clone(),
                proposed_last_commit: request.decided_last_commit.clone(),
                hash: request.hash.clone(),
                height: request.height,
                time: request.time.clone(),
                proposer_address: request.proposer_address.clone(),
                ..Default::default()
            })
            .status;
        timing.process_ms = millis(started);
        if status != ACCEPT {
            let reason = self.app.try_finalize(request).err();
            bail!("block {} was rejected: {reason:?}", self.height + 1);
        }
        let started = Instant::now();
        self.app.try_finalize(request)?;
        timing.finalize_ms = millis(started);
        let started = Instant::now();
        self.app.try_commit()?;
        timing.commit_ms = millis(started);
        self.height += 1;
        self.elapsed += delta;
        Ok(timing)
    }
    fn query(&self, path: &str, data: &Value) -> Result<Value> {
        let response = self.app.query(RequestQuery {
            data: serde_json::to_vec(data)?.into(),
            path: path.into(),
            height: 0,
            prove: false,
        });
        ensure!(response.code == 0, "query failed: {}", response.log);
        Ok(serde_json::from_slice(&response.value)?)
    }
    fn account(&self, id: u64) -> Result<Option<Account>> {
        let view = self.query("/v4/state", &json!({ "ids": [id.to_string()] }))?;
        let wanted = hex::encode(engine::account_key(id));
        let entry = view["entries"]
            .as_array()
            .and_then(|entries| entries.iter().find(|entry| entry["key_hex"] == wanted.as_str()))
            .ok_or_else(|| anyhow!("account entry missing from the answer"))?;
        match entry["value_b64"].as_str() {
            None => Ok(None),
            Some(text) => Ok(Some(serde_json::from_slice(&STANDARD.decode(text)?)?)),
        }
    }
    fn balance(&self, id: u64) -> Result<u64> {
        Ok(self
            .account(id)?
            .ok_or_else(|| anyhow!("account {id} does not exist"))?
            .balance)
    }
}

/// Splits transactions into blocks that respect the protocol's limits.
fn blocks_of(txs: Vec<Vec<u8>>, per_block: usize) -> Vec<Vec<Vec<u8>>> {
    let mut blocks = Vec::new();
    let mut current: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0usize;
    for tx in txs {
        if current.len() >= per_block || bytes + tx.len() > MAX_BLOCK_TX_BYTES {
            blocks.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += tx.len();
        current.push(tx);
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    blocks
}

fn summary(label: &str, timings: &[Timing], proposer: bool) -> Value {
    let stat = |pick: &dyn Fn(&Timing) -> f64| {
        let mut values: Vec<f64> = timings.iter().map(pick).collect();
        values.sort_by(f64::total_cmp);
        let at = |q: f64| values[((values.len() as f64 - 1.0) * q).round() as usize];
        json!({"median": (at(0.5) * 100.0).round() / 100.0, "p90": (at(0.9) * 100.0).round() / 100.0, "max": (at(1.0) * 100.0).round() / 100.0})
    };
    let txs = timings.first().map_or(0, |timing| timing.txs);
    let bytes = timings.first().map_or(0, |timing| timing.bytes);
    let total = |timing: &Timing| {
        timing.check_ms
            + if proposer { timing.prepare_ms } else { 0.0 }
            + timing.process_ms
            + timing.finalize_ms
            + timing.commit_ms
    };
    let mut totals: Vec<f64> = timings.iter().map(total).collect();
    totals.sort_by(f64::total_cmp);
    let median_total = totals[(totals.len() - 1) / 2];
    json!({
        "label": label,
        "blocks": timings.len(),
        "txs_per_block": txs,
        "bytes_per_block": bytes,
        "check_ms": stat(&|timing| timing.check_ms),
        "prepare_ms": stat(&|timing| timing.prepare_ms),
        "process_ms": stat(&|timing| timing.process_ms),
        "finalize_ms": stat(&|timing| timing.finalize_ms),
        "commit_ms": stat(&|timing| timing.commit_ms),
        "all_steps_ms": stat(&total),
        // Transactions one node can take through every step, per second of
        // its own work. The network adds its own time on top of this.
        "application_capacity_tps": (txs as f64 / (median_total / 1000.0)).round(),
    })
}

fn resident_mib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

fn run(options: &Options) -> Result<Value> {
    if let Some(threads) = options.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .context("configure worker threads")?;
    }
    let threads = rayon::current_num_threads();
    std::fs::create_dir_all(&options.dir)?;
    let path = options.dir.join("bench.db");
    let mut chain = Chain::start(&path, options.service_records)?;
    let network = chain.network.clone();
    let accounts = options.accounts;
    let measured_txs = (options.blocks + options.cold_blocks) as u64 * options.block_txs as u64;
    // Each account sends the same number of measured transfers.
    let sends_each = measured_txs.div_ceil(accounts) + 1;
    let fund_each = sends_each * (ledger::FEE_MICROS + 1) + 10;
    let registration_fee = genesis(options.service_records).registration.fee_micros;
    let per_account = registration_fee + 2 * ledger::FEE_MICROS + fund_each;
    // Every genesis account sponsors an equal share of the new accounts.
    let share = accounts.div_ceil(GENESIS_ACCOUNTS) * per_account + 50 * ledger::FEE_MICROS;
    let needed = GENESIS_ACCOUNTS * (share + 4 * ledger::FEE_MICROS) + VALIDATORS * 100 * ledger::FEE_MICROS;
    eprintln!(
        "threads={threads} accounts={accounts} measured_txs={measured_txs} currency_needed={:.0}s",
        needed as f64 / 1e6
    );

    // 1. Validator owners earn the currency the benchmark will spend.
    let setup_started = Instant::now();
    let mut genesis_senders: Vec<Sender> = (0..GENESIS_ACCOUNTS)
        .map(|id| Sender::new(id, key("genesis", id)))
        .collect();
    chain.block(pos::SECOND, &[], false, false)?;
    let mut reward_blocks = 0u64;
    let mut empty_ms = 0.0f64;
    loop {
        let mut earned = 0u64;
        for owner in 0..VALIDATORS {
            earned += chain.balance(owner)?;
        }
        if earned >= needed {
            break;
        }
        // The protocol pays at most one fifth of 60 seconds per block.
        let missing = needed - earned;
        let rounds = missing.div_ceil(12 * pos::SECOND).clamp(1, 500);
        for _ in 0..rounds {
            let timing = chain.block(60 * pos::SECOND, &[], false, false)?;
            empty_ms += timing.process_ms + timing.finalize_ms + timing.commit_ms;
        }
        reward_blocks += rounds;
        ensure!(reward_blocks < 2_000_000, "validator owners are not earning");
    }
    // 2. Owners pass the currency to the other genesis accounts; all of them
    //    then act as registration sponsors. An owner first keeps its own
    //    share; one sponsor may be funded by several owners.
    let mut spendable = Vec::new();
    for owner in 0..VALIDATORS {
        spendable.push(chain.balance(owner)?.saturating_sub(share + 50 * ledger::FEE_MICROS));
    }
    let mut funding: Vec<(u64, u64, u64)> = Vec::new();
    for sponsor in VALIDATORS..GENESIS_ACCOUNTS {
        let mut left = share;
        for owner in 0..VALIDATORS {
            let give = left.min(spendable[owner as usize].saturating_sub(ledger::FEE_MICROS));
            if give == 0 {
                continue;
            }
            funding.push((owner, sponsor, give));
            spendable[owner as usize] -= give + ledger::FEE_MICROS;
            left -= give;
            if left == 0 {
                break;
            }
        }
        ensure!(left == 0, "validator owners hold too little for sponsor {sponsor}");
    }
    let txs: Vec<Vec<u8>> = funding
        .iter()
        .map(|(from, to, amount)| genesis_senders[*from as usize].transfer(&network, *to, *amount))
        .collect();
    chain.block(pos::SECOND, &txs, false, false)?;
    for sponsor in 0..GENESIS_ACCOUNTS {
        ensure!(
            chain.balance(sponsor)? >= share,
            "sponsor {sponsor} holds less than its share after funding"
        );
    }

    // 3. Sponsored registration: the sponsor's action, then the new key's
    //    reveal in a later block. New accounts get consecutive IDs in the
    //    order their reveals are executed.
    let new_keys: Vec<SigningKey> = (0..accounts)
        .into_par_iter()
        .map(|index| key("account", index))
        .collect();
    let per_round = (MAX_BLOCK_TXS / 4).min(4000) as u64;
    let mut pending_reveals: Vec<Vec<u8>> = Vec::new();
    let mut registered = 0u64;
    while registered < accounts || !pending_reveals.is_empty() {
        let batch: Vec<u64> = (registered..accounts.min(registered + per_round)).collect();
        let expiry = chain.elapsed + 3600 * pos::SECOND;
        let network_bytes = pos::hex32(&network)?;
        // Nonces are assigned in order first; signing then runs on all cores.
        let jobs: Vec<(u64, u64, u64)> = batch
            .iter()
            .map(|index| {
                let sponsor = &mut genesis_senders[(index % GENESIS_ACCOUNTS) as usize];
                sponsor.nonce += 1;
                (*index, sponsor.id, sponsor.nonce)
            })
            .collect();
        let signed: Vec<(Vec<u8>, Vec<u8>)> = jobs
            .par_iter()
            .map(|(index, sponsor, nonce)| -> Result<(Vec<u8>, Vec<u8>)> {
                let new_key = &new_keys[*index as usize];
                let new_public = public(new_key);
                let name = format!("b{index:x}");
                let salt = hex::encode(Sha256::digest(index.to_be_bytes()));
                let commitment = ledger::action_commitment(&network, &new_public, &name, &salt)
                    .map_err(|error| anyhow!("{error:?}"))?;
                let consent = registration::consent_bytes(
                    network_bytes,
                    *sponsor,
                    pos::hex32(&new_public)?,
                    pos::hex32(&commitment)?,
                    expiry,
                );
                let sponsor_action = wire::sign(
                    &network,
                    *sponsor,
                    *nonce,
                    0,
                    44,
                    &json!({"public_key":new_public,"commitment":commitment,"expires_elapsed_micros":expiry.to_string(),"proof":hex::encode(new_key.sign(&consent).to_bytes())}),
                    &key("genesis", *sponsor),
                )?;
                let reveal = ledger::sign_action(
                    &Action {
                        network_id: network.clone(),
                        from: u64::MAX,
                        nonce: 0,
                        auth_epoch: 0,
                        public_key: new_public,
                        payload: ActionPayload::Reveal(ledger::Reveal { name, salt }),
                        signature: vec![],
                    },
                    new_key,
                )
                .map_err(|error| anyhow!("{error:?}"))?;
                Ok((sponsor_action, reveal))
            })
            .collect::<Result<_>>()?;
        // This block: reveals of the previous round, then this round's
        // sponsor actions.
        let mut txs = std::mem::take(&mut pending_reveals);
        let mut reveals = Vec::with_capacity(signed.len());
        for (sponsor_action, reveal) in signed {
            txs.push(sponsor_action);
            reveals.push(reveal);
        }
        chain.block(pos::SECOND, &txs, false, false)?;
        pending_reveals = reveals;
        registered += batch.len() as u64;
    }
    let first_id = GENESIS_ACCOUNTS;
    for probe in [0, accounts / 2, accounts - 1] {
        let row = chain
            .account(first_id + probe)?
            .ok_or_else(|| anyhow!("registered account {probe} is missing"))?;
        ensure!(
            row.name == format!("b{probe:x}") && row.public_key == public(&new_keys[probe as usize]),
            "registered account {probe} has an unexpected identity"
        );
    }
    // 4. Sponsors fund the new accounts.
    let jobs: Vec<(u64, u64, u64)> = (0..accounts)
        .map(|index| {
            let sponsor = &mut genesis_senders[(index % GENESIS_ACCOUNTS) as usize];
            sponsor.nonce += 1;
            (index, sponsor.id, sponsor.nonce)
        })
        .collect();
    let txs: Vec<Vec<u8>> = jobs
        .par_iter()
        .map(|(index, sponsor, nonce)| {
            let mut sender = Sender::new(*sponsor, key("genesis", *sponsor));
            sender.nonce = nonce - 1;
            sender.transfer(&network, first_id + index, fund_each)
        })
        .collect();
    for block in blocks_of(txs, MAX_BLOCK_TXS) {
        chain.block(pos::SECOND, &block, false, false)?;
    }
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    eprintln!(
        "setup done in {setup_seconds:.1}s: height {}, {reward_blocks} reward blocks",
        chain.height
    );

    // 5. Measured blocks. Sender i of a block is account (offset + i), so no
    //    account appears twice in a block; recipients are spread by a fixed
    //    stride.
    let mut senders: Vec<Sender> = new_keys
        .into_par_iter()
        .enumerate()
        .map(|(index, key)| Sender::new(first_id + index as u64, key))
        .collect();
    let mut cursor = 0usize;
    let mut sign_block = |senders: &mut Vec<Sender>| -> (Vec<Vec<u8>>, f64) {
        let count = options.block_txs;
        let total = senders.len();
        let started = Instant::now();
        let picks: Vec<usize> = (0..count).map(|index| (cursor + index) % total).collect();
        cursor = (cursor + count) % total;
        // Signing is the wallets' work, not the node's; it is timed apart.
        let signed: Vec<(usize, Vec<u8>)> = picks
            .par_iter()
            .map(|index| {
                let mut sender = senders[*index].clone();
                let to = first_id + ((*index as u64 * 7919 + 13) % total as u64);
                let to = if to == sender.id { first_id + (to + 1 - first_id) % total as u64 } else { to };
                (*index, sender.transfer(&network, to, 1))
            })
            .collect();
        let mut txs = Vec::with_capacity(count);
        for (index, tx) in signed {
            senders[index].nonce += 1;
            txs.push(tx);
        }
        (txs, millis(started))
    };
    ensure!(
        options.block_txs <= senders.len(),
        "--block-txs cannot exceed --accounts: each sender appears once per block"
    );
    // One block to warm caches and allocator, not reported.
    let (txs, _) = sign_block(&mut senders);
    chain.block(pos::SECOND, &txs, true, true)?;
    let mut warm = Vec::new();
    let mut sign_ms = Vec::new();
    for _ in 0..options.blocks {
        let (txs, signing) = sign_block(&mut senders);
        sign_ms.push(signing);
        warm.push(chain.block(pos::SECOND, &txs, true, true)?);
    }
    // Blocks whose transactions this node never saw in its mempool: every
    // signature is verified during validation.
    let mut cold = Vec::new();
    for _ in 0..options.cold_blocks {
        let (txs, _) = sign_block(&mut senders);
        cold.push(chain.block(pos::SECOND, &txs, false, false)?);
    }
    let stats = chain.app.stats();

    // 6. Wallet queries with proofs.
    let ids: Vec<u64> = (0..20_000u64).map(|index| first_id + (index * 104_729) % accounts).collect();
    let started = Instant::now();
    for id in &ids[..2000] {
        chain.query("/v4/state", &json!({ "ids": [id.to_string()] }))?;
    }
    let single = 2000.0 / started.elapsed().as_secs_f64();
    let started = Instant::now();
    ids.par_iter().try_for_each(|id| -> Result<()> {
        chain.query("/v4/state", &json!({ "ids": [id.to_string()] }))?;
        Ok(())
    })?;
    let parallel = ids.len() as f64 / started.elapsed().as_secs_f64();

    // 7. Snapshot, restart, and a full recount of the reloaded state.
    let (height, root) = chain.app.head()?.ok_or_else(|| anyhow!("no committed head"))?;
    let memory_mib = resident_mib();
    let started = Instant::now();
    let snapshot = chain
        .app
        .snapshot()?
        .ok_or_else(|| anyhow!("the head was already saved"))?;
    let snapshot_seconds = started.elapsed().as_secs_f64();
    drop(chain);
    let started = Instant::now();
    let reopened = App::open(&path)?;
    let load_seconds = started.elapsed().as_secs_f64();
    ensure!(
        reopened.head()? == Some((height, root)),
        "the reloaded state differs from the saved one"
    );
    drop(reopened);
    let started = Instant::now();
    let audit = engine::Engine::open_with_history(
        timecurrency_v5::store::Store::open(path.with_extension("v5state"))?,
        path.with_extension("history"),
    )?
    .audit()?;
    let audit_seconds = started.elapsed().as_secs_f64();
    ensure!(
        audit.account_count == GENESIS_ACCOUNTS + accounts && audit.history_archive_verified,
        "the recount found an unexpected state"
    );
    sign_ms.sort_by(f64::total_cmp);
    Ok(json!({
        "tool": concat!("time-bench-v5 ", env!("CARGO_PKG_VERSION")),
        "service_records": options.service_records,
        "threads": threads,
        "logical_cpus": std::thread::available_parallelism().map_or(0, |n| n.get()),
        "accounts": accounts,
        "state_rows": audit.authenticated_leaves,
        "setup_seconds": (setup_seconds * 10.0).round() / 10.0,
        "final_height": height,
        "root": hex::encode(root),
        "wallet_signing_ms_per_block_median": sign_ms[sign_ms.len() / 2].round(),
        "empty_block_ms_mean": if reward_blocks == 0 { 0.0 } else { (empty_ms / reward_blocks as f64 * 1000.0).round() / 1000.0 },
        "blocks_seen_in_mempool_first_proposer": summary("mempool, proposal, validation, finalize, commit", &warm, true),
        "blocks_seen_in_mempool_first_validator": summary("mempool, validation, finalize, commit", &warm, false),
        "blocks_never_seen_before": summary("validation with all signatures, finalize, commit", &cold, false),
        "executions": {"blocks_executed": stats.executed_blocks, "finalize_answered_from_proposal": stats.reused_executions},
        "proof_queries_per_second": {"one_thread": single.round(), "all_threads": parallel.round()},
        "snapshot": {"bytes": snapshot.bytes, "write_seconds": (snapshot_seconds * 100.0).round() / 100.0, "load_and_authenticate_seconds": (load_seconds * 100.0).round() / 100.0},
        "full_recount_seconds": (audit_seconds * 100.0).round() / 100.0,
        "resident_memory_mib": memory_mib,
    }))
}

fn main() {
    let options = match options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    match run(&options) {
        Ok(report) => {
            let text = serde_json::to_string_pretty(&report).expect("report encodes");
            println!("{text}");
            if let Some(out) = &options.out {
                if let Err(error) = std::fs::write(out, text + "\n") {
                    eprintln!("could not write {}: {error}", out.display());
                    std::process::exit(1);
                }
            }
        }
        Err(error) => {
            eprintln!("benchmark failed: {error:#}");
            std::process::exit(1);
        }
    }
}
