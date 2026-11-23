//! Service records (`service_records` in the genesis, `src/service.rs`).
//!
//! - How a network chooses them, and that the production profile requires
//!   them.
//! - That nothing else changes: the scripted run of `stake_script` on three
//!   networks with and without the records leaves every other row the same
//!   after every block, and no rule reads a record.
//! - That they are exact: the same run against an independent model of what
//!   the records must say, block by block (counts per week, missed blocks
//!   by proposer, registrations, keys, punishments, accounts, stake lots).
//! - The age of stake never counts new stake as old.
//! - A punishment cannot be washed by registering again, and stake cannot be
//!   made to look old by moving it in a circle.
//! - What a group of proposers that leave a rival's signature out shows in
//!   the records.
//! - The bounds over more weeks than the records keep; a production week.
//! - The recount, and what it refuses.
//! - A node through its proposals, a restart, state sync, proofs and the
//!   recount report; and a switch block of a fix release.
mod common;
mod stake_script;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stake_script::{BLOCKS, DAY, DELEGATOR, EVIDENCED, FIRST_KEY, MINUTE, NEWCOMER, REPORTED, SECOND, SECOND_KEY, Step, View};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::app::App;
use timecurrency_v5::engine::{Audit, Engine, Prepared, account_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::proof::ProofEntry;
use timecurrency_v5::rules::{self, Switch, SwitchAt, Versions};
use timecurrency_v5::service::{
    self, Cause, Count, KEPT_WEEKS, KeyRecord, Lots, Missed, Moment, NO_PROPOSER, Punishment, Tally, ValidatorRecord, Weeks,
};
use timecurrency_v5::statesync::NodeOptions;
use timecurrency_v5::store::Store;
use timecurrency_v5::upgrade;

const WEEK: u64 = 60 * SECOND;

fn recorded(mut genesis: Genesis) -> Genesis {
    genesis.service_records = true;
    genesis
}
/// The consensus address of starting validator `owner` (key seed
/// `owner + 101`), or of key seed `seed`.
fn address_of_seed(seed: u8) -> Vec<u8> {
    Sha256::digest(hex::decode(pk(seed)).unwrap())[..20].to_vec()
}
fn address_of_key(consensus_key: &str) -> Vec<u8> {
    Sha256::digest(hex::decode(consensus_key).unwrap())[..20].to_vec()
}

/// What the records must say, computed from what the test hands the engine
/// and the rosters it reads back: an independent model.
#[derive(Default)]
struct Model {
    counts: BTreeMap<(u64, u64), Count>,
    missed: BTreeMap<(u64, u64), BTreeMap<u64, u64>>,
    /// Per week: blocks, and those that named no proposer of their set.
    blocks: BTreeMap<u64, (u64, u64)>,
    /// Per stake position (the key of its lots): the lots, and the amount
    /// after every block with that block's week.
    lots: BTreeMap<Vec<u8>, Vec<(u64, u64)>>,
    held: BTreeMap<Vec<u8>, Vec<(u64, u64)>>,
    amounts: BTreeMap<Vec<u8>, u64>,
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    model: Model,
    /// The decided blocks: (time after the parent, transactions, signers,
    /// misbehavior, proposer address).
    log: Vec<(u64, Vec<Vec<u8>>, Vec<String>, Vec<timecurrency_v5::engine::Misbehavior>, Vec<u8>)>,
    /// The time of every block, by height (the state cleans up its own).
    times: Vec<i64>,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        Self::on(genesis, None)
    }
    fn on(genesis: Genesis, versions: Option<Versions>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history")).unwrap();
        if let Some(versions) = versions {
            engine = engine.implementing(versions);
        }
        let start = genesis.ledger.genesis_time_micros;
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network, model: Model::default(), log: Vec::new(), times: vec![start] }
    }
    /// Block `height` as the records name it.
    fn at(&self, height: u64) -> Moment {
        Moment { height, time_micros: self.times[height as usize] }
    }
    fn view(&self) -> View<'_> {
        View { engine: &self.engine, network: &self.network }
    }
    fn records(&self) -> bool {
        self.engine.meta().unwrap().config.service_records
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn get<T: DeserializeOwned>(&self, key: &[u8]) -> Option<T> {
        self.row(key).map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn account(&self, id: u64) -> Account {
        self.get(&account_key(id)).unwrap()
    }
    fn height(&self) -> i64 {
        self.engine.meta().unwrap().height
    }
    fn week(&self) -> u64 {
        let meta = self.engine.meta().unwrap();
        service::week_at(meta.config.profile, meta.elapsed_micros().unwrap())
    }
    fn tally(&self) -> Tally {
        self.get(service::TALLY_KEY).unwrap()
    }
    fn validator(&self, owner: u64) -> ValidatorRecord {
        self.get(&service::validator_key(owner)).unwrap()
    }
    /// Every row of the committed state.
    fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let version = self.engine.version().unwrap().clone();
        let mut rows = BTreeMap::new();
        version
            .audit_verified(|_| {})
            .unwrap()
            .for_each_prefix(b"", |key, value| {
                rows.insert(key.to_vec(), value.to_vec());
                Ok(())
            })
            .unwrap();
        rows
    }
    /// The proposer address block `height` names: a validator of the set
    /// before it, chosen by the height; none in every eleventh block; an
    /// address of no validator in every thirteenth.
    fn proposer_for(&self, height: i64) -> Vec<u8> {
        if height % 11 == 0 {
            return Vec::new();
        }
        if height % 13 == 0 {
            return vec![0xee; 20];
        }
        let roster = self.engine.active_roster_at(height as u64 - 1).unwrap();
        address_of_key(&roster[(height as usize * 5) % roster.len()].consensus_key)
    }
    /// One block as a proposer builds it, a validator checks it and the
    /// reference path executes it, with `proposer` in its header. Returns
    /// how many of its transactions the proposer kept.
    fn block_by(&mut self, step: Step, proposer: Vec<u8>) -> usize {
        let meta = self.engine.meta().unwrap();
        let (height, time) = (meta.height + 1, meta.time_micros + step.delta as i64);
        let absent: Vec<String> = step.absent.iter().map(|owner| pk(*owner as u8 + 101)).collect();
        let signers: Vec<String> = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .filter(|key| !absent.contains(key))
            .collect();
        let hash = sha(height as u64);
        let misbehavior = &step.misbehavior;
        let (proposed, kept) = self
            .engine
            .prepare_filtered_proposed(height, time, &step.txs, &signers, 1 << 20, hash, misbehavior, &proposer)
            .unwrap();
        let strict = self.engine.prepare_proposed(height, time, &kept, &signers, hash, misbehavior, &proposer).unwrap();
        let reference = self.engine.prepare_reference_proposed(height, time, &kept, &signers, hash, misbehavior, &proposer).unwrap();
        assert_eq!(strict.root, proposed.root, "validator and proposer disagree at {height}");
        assert_eq!(reference.root, proposed.root, "fast path and reference disagree at {height}");
        if kept.len() != step.txs.len() - step.refused {
            let reasons: Vec<String> = step
                .txs
                .iter()
                .map(|tx| match self.engine.prepare_proposed(height, time, &[tx], &signers, hash, misbehavior, &proposer) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("height {height}: a scripted action was left out or kept: {reasons:?}");
        }
        self.commit(proposed, hash, &signers, &proposer);
        self.log.push((step.delta, kept.clone(), signers, step.misbehavior, proposer));
        kept.len()
    }
    fn block(&mut self, step: Step) -> usize {
        let proposer = self.proposer_for(self.height() + 1);
        self.block_by(step, proposer)
    }
    fn commit(&mut self, prepared: Prepared, hash: [u8; 32], signers: &[String], proposer: &[u8]) {
        let height = prepared.meta.height as u64;
        // The set that was to sign the block before, read before this block
        // may clean its roster rows up.
        let set = self.engine.active_roster_at(height - 1).unwrap();
        self.engine.commit(prepared, hash).unwrap();
        let meta = self.engine.meta().unwrap();
        assert_eq!(meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total, meta.elapsed_micros().unwrap(), "supply rule at {height}");
        self.times.push(meta.time_micros);
        self.follow(height, &set, signers, proposer);
    }
    /// The model after block `height`, which carried the commit of the set
    /// `set` with `signers`.
    fn follow(&mut self, height: u64, set: &[pos::Validator], signers: &[String], proposer: &[u8]) {
        let week = self.week();
        if height >= 2 {
            let next = self.engine.active_roster_at(height).unwrap();
            let by = next.iter().find(|validator| address_of_key(&validator.consensus_key) == proposer).map(|validator| validator.owner);
            let entry = self.model.blocks.entry(week).or_default();
            entry.0 += 1;
            match by {
                Some(owner) => self.model.counts.entry((owner, week)).or_default().proposed += 1,
                None => entry.1 += 1,
            }
            for validator in set {
                let count = self.model.counts.entry((validator.owner, week)).or_default();
                count.in_set += 1;
                if signers.contains(&validator.consensus_key) {
                    count.signed += 1;
                } else {
                    *self.model.missed.entry((validator.owner, week)).or_default().entry(by.unwrap_or(NO_PROPOSER)).or_default() += 1;
                    if let Some(owner) = by {
                        self.model.counts.entry((owner, week)).or_default().omitted += 1;
                    }
                }
            }
        }
        // The stake positions: own bonds and delegations.
        let rows = self.rows();
        let mut now: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
        for (key, value) in rows.range(b"pos/candidate/".to_vec()..).take_while(|(key, _)| key.starts_with(b"pos/candidate/")) {
            let candidate: pos::Candidate = serde_json::from_slice(value).unwrap();
            if candidate.self_bond > 0 {
                now.insert(service::bond_key(u64::from_be_bytes(key[14..22].try_into().unwrap())), candidate.self_bond);
            }
        }
        for (key, value) in rows.range(b"pos/position/".to_vec()..).take_while(|(key, _)| key.starts_with(b"pos/position/")) {
            let shares: String = serde_json::from_slice(value).unwrap();
            let validator = u64::from_be_bytes(key[13..21].try_into().unwrap());
            let owner = u64::from_be_bytes(key[21..29].try_into().unwrap());
            now.insert(service::delegation_key(validator, owner), shares.parse().unwrap());
        }
        let keys: BTreeSet<Vec<u8>> = now.keys().chain(self.model.amounts.keys()).cloned().collect();
        for key in keys {
            let (before, after) = (self.model.amounts.get(&key).copied().unwrap_or(0), now.get(&key).copied().unwrap_or(0));
            let lots = self.model.lots.entry(key.clone()).or_default();
            // The rule, written again here: in to this week's lot, out from
            // the newest, lots older than the horizon merged into one.
            if after > before {
                match lots.last_mut() {
                    Some((last, amount)) if *last == week => *amount += after - before,
                    _ => lots.push((week, after - before)),
                }
            } else {
                let mut out = before - after;
                while out > 0 {
                    let (_, amount) = lots.last_mut().unwrap();
                    let taken = (*amount).min(out);
                    *amount -= taken;
                    out -= taken;
                    if *amount == 0 {
                        lots.pop();
                    }
                }
            }
            if before != after {
                let old = lots.iter().take_while(|(lot, _)| *lot < week.saturating_sub(KEPT_WEEKS)).count();
                if old >= 2 {
                    let merged: u64 = lots[..old].iter().map(|(_, amount)| amount).sum();
                    let newest = lots[old - 1].0;
                    lots.splice(..old, [(newest, merged)]);
                }
            }
            self.model.held.entry(key.clone()).or_default().push((week, after));
        }
        self.model.amounts = now;
        if self.records() {
            self.check_model();
        }
    }
    /// The records against the model.
    fn check_model(&self) {
        let current = self.week();
        let tally = self.tally();
        assert_eq!(tally.week, current);
        let (blocks, unattributed) = self.model.blocks.get(&current).copied().unwrap_or((0, 0));
        assert_eq!((tally.blocks, tally.unattributed), (blocks, unattributed), "the blocks of week {current}");
        let in_tally: BTreeMap<u64, Count> = tally
            .validators
            .iter()
            .map(|entry| (entry.owner, Count { in_set: entry.in_set, signed: entry.signed, proposed: entry.proposed, omitted: entry.omitted }))
            .collect();
        let expected: BTreeMap<u64, Count> =
            self.model.counts.iter().filter(|((_, week), _)| *week == current).map(|((owner, _), count)| (*owner, *count)).collect();
        assert_eq!(in_tally, expected, "the tally of week {current}");
        let weeks: Weeks = self.get(service::WEEKS_KEY).unwrap();
        let horizon = current.saturating_sub(KEPT_WEEKS);
        let listed: Vec<(u64, u64, u64)> = weeks.weeks.iter().map(|kept| (kept.week, kept.blocks, kept.unattributed)).collect();
        let expected: Vec<(u64, u64, u64)> = self
            .model
            .blocks
            .iter()
            .filter(|(week, _)| **week >= horizon && **week < current)
            .map(|(week, (blocks, unattributed))| (*week, *blocks, *unattributed))
            .collect();
        assert_eq!(listed, expected, "the weeks that ended");
        let owners: BTreeSet<u64> = self.model.counts.keys().map(|(owner, _)| *owner).collect();
        for owner in owners {
            let record = self.validator(owner);
            let mut total = Count::default();
            for ((_, week), count) in self.model.counts.range((owner, 0)..(owner, current)) {
                add(&mut total, count);
                let bucket = record.weeks.iter().find(|kept| kept.week == *week);
                if *week >= horizon {
                    let bucket = bucket.unwrap_or_else(|| panic!("validator {owner}: week {week} is not kept"));
                    assert_eq!((bucket.in_set, bucket.signed, bucket.proposed, bucket.omitted), (count.in_set, count.signed, count.proposed, count.omitted));
                } else if let Some(bucket) = bucket {
                    assert_eq!((bucket.in_set, bucket.signed, bucket.proposed, bucket.omitted), (count.in_set, count.signed, count.proposed, count.omitted));
                }
            }
            assert_eq!(record.total, total, "the total of validator {owner}");
            let mut kept = record.older;
            for bucket in &record.weeks {
                add(&mut kept, &Count { in_set: bucket.in_set, signed: bucket.signed, proposed: bucket.proposed, omitted: bucket.omitted });
            }
            assert_eq!(kept, total, "validator {owner}: older and kept weeks");
            // Missed blocks by proposer, for every week the record keeps
            // and for the week in progress.
            for (week, missed) in self.model.missed.range((owner, 0)..=(owner, current)).map(|((_, week), missed)| (*week, missed)) {
                let row: Option<Missed> = self.get(&service::missed_key(owner, week));
                let kept = week == current || record.weeks.iter().any(|bucket| bucket.week == week);
                assert_eq!(row.is_some(), kept, "validator {owner}: missed blocks of week {week}");
                if let Some(row) = row {
                    let by: BTreeMap<u64, u64> = row.proposers.iter().map(|count| (count.proposer, count.blocks)).collect();
                    assert_eq!(&by, missed, "validator {owner}: missed blocks of week {week}");
                }
            }
        }
        // Stake lots.
        for (key, lots) in &self.model.lots {
            let row: Option<Lots> = self.get(key);
            let expected: Vec<(u64, u64)> = lots.clone();
            let found: Vec<(u64, u64)> = row.map(|row| row.lots.iter().map(|lot| (lot.week, lot.amount)).collect()).unwrap_or_default();
            assert_eq!(found, expected, "the lots of {}", String::from_utf8_lossy(&key[..key.len().min(20)]));
        }
    }
    /// Runs the scripted blocks `from..=to`.
    fn script(&mut self, from: i64, to: i64) {
        for height in from..=to {
            let step = stake_script::step(&self.view(), height);
            self.block(step);
            if height % 9 == 0 {
                self.engine.audit().unwrap();
            }
        }
    }
    fn quiet(&mut self, delta: u64) {
        self.block(Step { delta, txs: vec![], refused: 0, absent: vec![], misbehavior: vec![] });
    }
    fn with(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        self.block(Step { delta, txs, refused: 0, absent: vec![], misbehavior: vec![] });
    }
    fn extension(&self, from: u64, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + 1, row.auth_epoch, kind, &payload, &key(from as u8 + 1)).unwrap()
    }
    fn legacy(&self, from: u64, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action { network_id: self.network.clone(), from, nonce: row.nonce + 1, auth_epoch: row.auth_epoch, public_key: pk(from as u8 + 1), payload, signature: vec![] },
            &key(from as u8 + 1),
        )
        .unwrap()
    }
    fn register(&self, from: u64, seed: u8) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let proof = key(seed).sign(&pos::register_message(pos::hex32(&self.network).unwrap(), from, &pk(seed), 1000).unwrap());
        self.extension(from, 17, json!({"commission_bps": 1000, "consensus_key": pk(seed), "proof": hex::encode(proof.to_bytes())}))
    }
}
fn add(total: &mut Count, count: &Count) {
    total.in_set += count.in_set;
    total.signed += count.signed;
    total.proposed += count.proposed;
    total.omitted += count.omitted;
}

/// Seven starting validators on the laboratory profile, with the records.
fn seven() -> Genesis {
    stake_script::variants().into_iter().find(|(name, _)| *name == "plain").unwrap().1
}

#[test]
fn the_setting_is_written_one_way_last_of_all() {
    let parse = |value: Value| {
        let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
        genesis["service_records"] = value;
        serde_json::from_value::<Genesis>(genesis)
    };
    assert!(parse(json!(true)).unwrap().service_records);
    // Not keeping the records is written by leaving the field out.
    for refused in [json!(false), json!("true"), json!(1), json!(null), json!({})] {
        assert!(parse(refused.clone()).is_err(), "{refused}");
    }
    let plain = genesis_v5();
    assert!(!serde_json::to_string(&plain).unwrap().contains("service_records"));
    assert_eq!(plain.network_id().unwrap(), network_id(), "protocol-4 network id");
    // Alone, it follows the protocol-4 fields directly.
    let text = serde_json::to_string(&plain).unwrap();
    assert_eq!(serde_json::to_string(&recorded(plain.clone())).unwrap(), format!("{},\"service_records\":true}}", text.strip_suffix('}').unwrap()));
    // With every other setting, it is the last field, after the accounts
    // that start protected.
    let (_, mut everything) = stake_script::variants().into_iter().find(|(name, _)| *name == "everything").unwrap();
    everything.protected_accounts = vec![timecurrency_v5::genesis::ProtectedAccount {
        id: 9,
        keys: vec![
            timecurrency_v5::genesis::ProtectedKey { public_key: pk(30), role: timecurrency_v5::security::Role::Spend },
            timecurrency_v5::genesis::ProtectedKey { public_key: pk(31), role: timecurrency_v5::security::Role::Recover },
            timecurrency_v5::genesis::ProtectedKey { public_key: pk(32), role: timecurrency_v5::security::Role::Recover },
        ],
        policy: serde_json::from_value(json!({"threshold": "2", "daily_limit_micros": "1000", "delay_seconds": "60", "freeze_seconds": "60"})).unwrap(),
    }];
    everything.protected_accounts[0].keys.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let without = serde_json::to_string(&everything).unwrap();
    assert!(without.ends_with("}]}"), "{without}");
    let with = serde_json::to_string(&recorded(everything.clone())).unwrap();
    assert_eq!(with, format!("{},\"service_records\":true}}", without.strip_suffix('}').unwrap()));
    let parsed: Genesis = serde_json::from_str(&with).unwrap();
    assert_eq!(parsed.network_id().unwrap(), recorded(everything.clone()).network_id().unwrap());
    // The setting is part of the network id.
    assert_ne!(recorded(everything.clone()).network_id().unwrap(), everything.network_id().unwrap());
    assert_ne!(recorded(genesis_v5()).network_id().unwrap(), network_id());
}

#[test]
fn the_production_profile_requires_it() {
    let mut genesis: Genesis = serde_json::from_slice(&serde_json::to_vec(&genesis_v4_with(24)).unwrap()).unwrap();
    genesis.profile = pos::Profile::Production;
    genesis.validators = (0..20).map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 }).collect();
    genesis.auction.epoch_seconds = 3600;
    genesis.recovery_min_delay_micros = 2 * pos::DAY;
    genesis.stake_handover = true;
    genesis.distinct_names = true;
    genesis.waits_survive_stops = true;
    genesis.protected_registration = true;
    // A state created before the rule still opens.
    genesis.validate().unwrap();
    for refusal in [genesis.validate_initial().unwrap_err(), genesis.validate_new().unwrap_err()] {
        let refusal = format!("{refusal:#}");
        assert!(refusal.contains("production profile requires service records (service_records)"), "{refusal}");
    }
    let dir = tempfile::tempdir().unwrap();
    assert!(App::open(dir.path().join("state.db")).unwrap().try_init(init(&genesis)).is_err());
    genesis.service_records = true;
    genesis.validate_new().unwrap();
    // A production chain: the records count in weeks of seven days.
    let mut chain = Chain::new(genesis);
    assert_eq!(chain.tally(), Tally { week: 0, blocks: 0, unattributed: 0, validators: vec![] });
    for _ in 0..20 {
        chain.quiet(DAY);
    }
    assert_eq!(chain.week(), 2);
    assert_eq!(chain.tally().week, 2);
    let weeks: Weeks = chain.get(service::WEEKS_KEY).unwrap();
    // Week 0: blocks 2 to 6 (block 1 carries no commit); week 1: blocks 7
    // to 13.
    assert_eq!(weeks.weeks.iter().map(|kept| (kept.week, kept.blocks)).collect::<Vec<_>>(), vec![(0, 5), (1, 7)]);
    assert_eq!(chain.validator(3).weeks.iter().map(|kept| (kept.week, kept.in_set)).collect::<Vec<_>>(), vec![(0, 5), (1, 7)]);
    chain.engine.audit().unwrap();
    // The laboratory profile takes it or leaves it.
    genesis_v5().validate_new().unwrap();
    recorded(genesis_v5()).validate_new().unwrap();
    assert_eq!(service::week_micros(pos::Profile::Production), 7 * DAY);
    assert_eq!(service::week_micros(pos::Profile::Laboratory), WEEK);
}

/// The rows of two states that should differ only by the records: every row
/// outside `service/` is the same, but for what names the network (the
/// network id, and hashes taken over it by the registration rules), which
/// is mapped from one network to the other by rows both hold under the same
/// key.
fn same_but_the_records(with: &Chain, without: &Chain, height: i64, renames: &mut Vec<(String, String)>) {
    let (mut a, b) = (with.rows(), without.rows());
    let records: Vec<Vec<u8>> = a.keys().filter(|key| key.starts_with(service::PREFIX)).cloned().collect();
    for key in &records {
        a.remove(key);
    }
    assert!(b.keys().all(|key| !key.starts_with(service::PREFIX)), "a record without the setting");
    // What names the network: its id, and the commitments and registration
    // entries the registration rules hash it into, learned from the rows
    // both hold under one key (a pair stays known after its commitment is
    // used up).
    if renames.is_empty() {
        renames.push((with.network.clone(), without.network.clone()));
    }
    for (key, value) in &a {
        if key.starts_with(b"registration/commit/") {
            let (x, y): (Value, Value) = (serde_json::from_slice(value).unwrap(), serde_json::from_slice(&b[key]).unwrap());
            for field in ["commitment", "entry_id"] {
                let pair = (x[field].as_str().unwrap().to_string(), y[field].as_str().unwrap().to_string());
                if !renames.contains(&pair) {
                    renames.push(pair);
                }
            }
        }
    }
    // Each also as the treasury rules write 32 bytes: a JSON list of numbers.
    let as_list = |text: &str| -> Option<String> {
        hex::decode(text).ok().map(|bytes| format!("[{}]", bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(",")))
    };
    let renames: Vec<(String, String)> = renames
        .iter()
        .cloned()
        .chain(renames.iter().filter_map(|(from, to)| Some((as_list(from)?, as_list(to)?))))
        .collect();
    let rename = |text: &[u8]| -> Vec<u8> {
        let mut text = String::from_utf8_lossy(text).to_string();
        for (from, to) in &renames {
            text = text.replace(from, to);
        }
        text.into_bytes()
    };
    let rename_key = |key: &[u8]| -> Vec<u8> {
        let mut key = key.to_vec();
        for (from, to) in &renames {
            if let (Ok(from), Ok(to)) = (hex::decode(from), hex::decode(to)) {
                if key.ends_with(&from) {
                    let at = key.len() - from.len();
                    key.splice(at.., to);
                }
            }
        }
        key
    };
    // The block history summary hashes the network id into its root and its
    // peaks: what it counts must be the same.
    let history = |value: &[u8]| -> Value {
        let mut summary: Value = serde_json::from_slice(value).unwrap();
        for field in ["network_id", "root", "peaks"] {
            summary.as_object_mut().unwrap().remove(field);
        }
        summary
    };
    let mut mapped: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for (key, value) in &a {
        if key == b"meta" {
            let mut meta: Value = serde_json::from_slice(&rename(value)).unwrap();
            assert_eq!(meta["config"]["service_records"], true);
            meta["config"].as_object_mut().unwrap().remove("service_records");
            mapped.insert(key.clone(), serde_json::to_vec(&meta).unwrap());
        } else if key.as_slice() == history::KEY {
            mapped.insert(key.clone(), serde_json::to_vec(&history(value)).unwrap());
        } else {
            mapped.insert(rename_key(key), rename(value));
        }
    }
    assert_eq!(mapped.len(), b.len(), "height {height}: rows");
    for (key, value) in &b {
        let mine = mapped.get(key).unwrap_or_else(|| panic!("height {height}: no row {}", String::from_utf8_lossy(key)));
        let theirs = if key.as_slice() == history::KEY {
            serde_json::to_vec(&history(value)).unwrap()
        } else if key == b"meta" {
            // Read the same way as the other side's, whose fields the reading
            // put in another order.
            serde_json::to_vec(&serde_json::from_slice::<Value>(value).unwrap()).unwrap()
        } else {
            value.clone()
        };
        assert_eq!(String::from_utf8_lossy(mine), String::from_utf8_lossy(&theirs), "height {height}: row {}", String::from_utf8_lossy(key));
    }
}

/// The same blocks on networks that differ only by the setting: every row
/// that exists without the records is the same with them, after every
/// block. The proposers named differ, and change nothing.
#[test]
fn with_the_records_every_other_row_is_as_without_them() {
    for (name, genesis) in stake_script::variants() {
        let mut with = Chain::new(recorded(genesis.clone()));
        let mut without = Chain::new(genesis);
        let mut renames = Vec::new();
        same_but_the_records(&with, &without, 0, &mut renames);
        for height in 1..=BLOCKS {
            let step = stake_script::step(&with.view(), height);
            let other = stake_script::step(&without.view(), height);
            let proposer = with.proposer_for(height);
            let kept = with.block_by(step, proposer);
            // Without the records, another proposer, or none.
            let kept_without = without.block_by(other, if height % 2 == 0 { Vec::new() } else { vec![1; 20] });
            assert_eq!(kept, kept_without, "{name}: height {height}");
            same_but_the_records(&with, &without, height, &mut renames);
        }
        stake_script::check_the_run(&with.view());
        let (a, b) = (with.engine.audit().unwrap(), without.engine.audit().unwrap());
        assert_eq!((a.account_count, a.liquid, a.unbond, a.pool_shares.clone()), (b.account_count, b.liquid, b.unbond, b.pool_shares.clone()), "{name}");
        assert!(a.authenticated_leaves > b.authenticated_leaves, "{name}");
    }
}

/// The scripted run against the model after every block (`Chain::follow`),
/// and what it must have recorded, said fact by fact.
#[test]
fn the_records_of_the_scripted_run_are_exact() {
    for (name, genesis) in stake_script::variants() {
        let mut chain = Chain::new(recorded(genesis));
        chain.script(1, BLOCKS);
        stake_script::check_the_run(&chain.view());
        chain.engine.audit().unwrap();
        let meta = chain.engine.meta().unwrap();
        let genesis_time = meta.genesis.genesis_time_micros;
        let at = |height: u64| chain.at(height);
        // Accounts: the genesis ones from height 0, the two registered in
        // block 20, whatever action created them.
        for id in 0..GENESIS_ACCOUNTS {
            assert_eq!(chain.get::<Moment>(&service::account_record_key(id)), Some(Moment { height: 0, time_micros: genesis_time }), "{name}");
        }
        for id in [GENESIS_ACCOUNTS, GENESIS_ACCOUNTS + 1] {
            assert_eq!(chain.get::<Moment>(&service::account_record_key(id)), Some(at(20)), "{name}");
        }
        assert!(chain.row(&service::account_record_key(GENESIS_ACCOUNTS + 2)).is_none());
        // Starting validators: registered at genesis.
        let genesis_moment = Moment { height: 0, time_micros: genesis_time };
        for owner in 0..7u64 {
            let record = chain.validator(owner);
            assert_eq!((record.first, record.since, record.registrations), (genesis_moment, genesis_moment, 1), "{name}");
            assert_eq!(record.consensus_key, pk(owner as u8 + 101));
        }
        // The newcomer: first registered in block 17, again in block 38
        // under a new key. Its record and its weeks go on.
        let newcomer = chain.validator(NEWCOMER);
        assert_eq!((newcomer.first, newcomer.since, newcomer.registrations, newcomer.punishments), (at(17), at(38), 2, 0), "{name}");
        assert_eq!(newcomer.consensus_key, pk(SECOND_KEY));
        assert!(newcomer.total.in_set > 0);
        let first: KeyRecord = chain.get(&service::key_key(&pk(FIRST_KEY)).unwrap()).unwrap();
        let second: KeyRecord = chain.get(&service::key_key(&pk(SECOND_KEY)).unwrap()).unwrap();
        assert_eq!((first.owner, first.registered, first.punished), (NEWCOMER, at(17), None));
        assert_eq!((second.owner, second.registered, second.punished), (NEWCOMER, at(38), None));
        // The punishments: by reported misbehavior in block 25 (offense at
        // height 10), by evidence in block 29 (offense at height 3). The
        // validators' rows are gone; the records stay.
        for (owner, height, cause, offense) in [(REPORTED, 25, Cause::DuplicateVote, 10), (EVIDENCED, 29, Cause::Evidence, 3)] {
            assert!(chain.view().candidate(owner).is_none());
            let record = chain.validator(owner);
            assert_eq!(record.punishments, 1, "{name}");
            let row: Punishment = chain.get(&service::punishment_key(owner, height)).unwrap();
            assert_eq!(row, Punishment { consensus_key: pk(owner as u8 + 101), cause, offense_height: offense, time_micros: at(height).time_micros });
            let entry: KeyRecord = chain.get(&service::key_key(&pk(owner as u8 + 101)).unwrap()).unwrap();
            assert_eq!(entry.punished, Some(at(height)));
        }
        for owner in [0, 1, 2, 3, 4, NEWCOMER] {
            assert_eq!(chain.validator(owner).punishments, 0);
        }
        // Signatures left out: validator 3 in blocks 21 to 23 and 47,
        // validator 4 in block 22, validator 2 in 41, validator 0 in 47.
        let missed = |owner: u64| -> u64 { chain.model.counts.iter().filter(|((o, _), _)| *o == owner).map(|(_, count)| count.in_set - count.signed).sum() };
        assert_eq!([missed(0), missed(1), missed(2), missed(3), missed(4)], [1, 0, 1, 4, 1], "{name}");
        let record = chain.validator(3);
        let tally = chain.tally();
        let in_tally = tally.validators.iter().find(|entry| entry.owner == 3).map_or(0, |entry| entry.in_set - entry.signed);
        assert_eq!(record.total.in_set - record.total.signed + in_tally, 4);
        // Stake: the own bonds and positions that remain have their lots.
        let bond: Lots = chain.get(&service::bond_key(NEWCOMER)).unwrap();
        assert_eq!(bond.total().unwrap(), chain.view().candidate(NEWCOMER).unwrap().self_bond);
        let delegation: Lots = chain.get(&service::delegation_key(NEWCOMER, DELEGATOR)).unwrap();
        assert_eq!(delegation.lots.len(), 1, "a delegation made after the stop is new");
        assert!(chain.row(&service::bond_key(REPORTED)).is_none() && chain.row(&service::bond_key(EVIDENCED)).is_none());
        // The proposers: some blocks named none, or no validator.
        let unattributed: u64 = chain.model.blocks.values().map(|(_, none)| none).sum();
        assert!(unattributed >= 8, "{name}: {unattributed}");
        assert_eq!(chain.model.blocks.values().map(|(blocks, _)| blocks).sum::<u64>(), BLOCKS as u64 - 1);
    }
}

/// The lots of a position never count new stake as old: what they say has
/// been in place for N whole weeks is at most the least the position held
/// in those weeks.
#[test]
fn the_age_of_stake_never_counts_new_stake_as_old() {
    for (name, genesis) in stake_script::variants() {
        let mut chain = Chain::new(recorded(genesis));
        chain.script(1, BLOCKS);
        let current = chain.week();
        let mut checked = 0;
        for (key, held) in &chain.model.held {
            let lots: Lots = chain.get(key).unwrap_or_default();
            for n in 0..400u64 {
                let old: u64 = lots.lots.iter().filter(|lot| lot.week + n + 1 <= current).map(|lot| lot.amount).sum();
                let least = held.iter().filter(|(week, _)| *week + n >= current).map(|(_, amount)| *amount).min().unwrap_or(0);
                assert!(old <= least, "{name}: {} weeks: {old} said old, least held {least}", n);
                checked += 1;
            }
        }
        assert!(checked > 1000);
    }
    // Stake added and taken out again leaves the old lot as it was; old
    // stake taken out and put back is new. (Below the minimum bond, so that
    // the roster does not change.)
    let mut chain = Chain::new(recorded(seven()));
    for _ in 0..15 {
        chain.quiet(WEEK);
    }
    chain.with(SECOND, vec![chain.extension(2, 18, json!({"amount": "300000"}))]);
    let start = chain.week();
    chain.quiet(3 * WEEK);
    chain.with(SECOND, vec![chain.extension(2, 18, json!({"amount": "200000"}))]);
    let lots = |chain: &Chain| chain.get::<Lots>(&service::bond_key(2)).unwrap().lots.iter().map(|lot| (lot.week, lot.amount)).collect::<Vec<_>>();
    let added = chain.week();
    assert!(added > start);
    assert_eq!(lots(&chain), vec![(start, 300_000), (added, 200_000)]);
    chain.quiet(WEEK);
    chain.with(SECOND, vec![chain.extension(2, 19, json!({"amount": "250000", "min_amount": "250000"}))]);
    assert_eq!(lots(&chain), vec![(start, 250_000)], "the newest lot leaves first");
    chain.quiet(WEEK);
    chain.with(SECOND, vec![chain.extension(2, 18, json!({"amount": "250000"}))]);
    assert_eq!(lots(&chain), vec![(start, 250_000), (chain.week(), 250_000)], "what is put back is new");
    // Rewards that stay in a pool raise what its shares are worth and leave
    // the lots of the delegations as they are.
    chain.with(SECOND, vec![chain.legacy(1, ActionPayload::Transfer(ledger::Transfer { to: 9, amount: 3 * SECOND }))]);
    chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator: 3, amount: SECOND, min_shares: 1 }))]);
    let before = chain.get::<Lots>(&service::delegation_key(3, 9)).unwrap();
    let assets = chain.view().candidate(3).unwrap().pool_assets;
    for _ in 0..5 {
        chain.quiet(WEEK);
    }
    assert!(chain.view().candidate(3).unwrap().pool_assets > assets, "the pool was paid");
    assert_eq!(chain.get::<Lots>(&service::delegation_key(3, 9)).unwrap(), before);
    chain.engine.audit().unwrap();
}

/// Rewards bonded for a starting validator (all new time to validators
/// without the stake hand-over rule) are new stake, in the lot of their
/// week.
#[test]
fn bonded_rewards_are_new_stake() {
    let (_, bonding) = stake_script::variants().into_iter().find(|(name, _)| *name == "bonding").unwrap();
    let mut chain = Chain::new(recorded(bonding));
    let mut weeks = Vec::new();
    // While the starting validators' power is lent to them, each block bonds
    // most of their reward: one lot for each block, in the week of the block.
    for _ in 0..2 {
        chain.quiet(WEEK + SECOND);
        weeks.push(chain.week());
    }
    let summary: pos::Summary = chain.get(pos_adapter_summary()).unwrap();
    let lots: Lots = chain.get(&service::bond_key(0)).unwrap();
    assert_eq!(lots.lots.iter().map(|lot| lot.week).collect::<Vec<_>>(), weeks, "{lots:?}");
    assert_eq!(lots.total().unwrap(), chain.view().candidate(0).unwrap().self_bond);
    // Funded by what was bonded, the seven end the lent power after the
    // sixty seconds of the laboratory profile: from then on rewards are paid
    // out, and the lots stay as they are.
    assert!(summary.bootstrap_ended);
    for _ in 0..3 {
        chain.quiet(WEEK + SECOND);
    }
    assert_eq!(chain.get::<Lots>(&service::bond_key(0)).unwrap(), lots);
    chain.engine.audit().unwrap();
}
fn pos_adapter_summary() -> &'static [u8] {
    timecurrency_v5::pos_adapter::SUMMARY_KEY
}

/// A punishment stays with the owner account: registering again under a new
/// key keeps it, and a new owner starts with a record of its own.
#[test]
fn a_punishment_cannot_be_washed_by_registering_again() {
    let mut chain = Chain::new(recorded(seven()));
    chain.script(1, 40);
    // Validator 6 was punished in block 25 and retired after its fourteen
    // days. Its owner registers again, with a new key.
    assert!(chain.view().candidate(REPORTED).is_none());
    chain.with(SECOND, vec![chain.register(REPORTED, 130)]);
    let record = chain.validator(REPORTED);
    assert_eq!((record.registrations, record.punishments, record.first.height), (2, 1, 0));
    assert_eq!(record.consensus_key, pk(130));
    let fresh: KeyRecord = chain.get(&service::key_key(&pk(130)).unwrap()).unwrap();
    assert_eq!(fresh.punished, None, "the new key is clean; the owner is not");
    let old: KeyRecord = chain.get(&service::key_key(&pk(REPORTED as u8 + 101)).unwrap()).unwrap();
    assert!(old.punished.is_some());
    // An account that never ran a validator registers one: its record has
    // nothing of anybody else's, and starts now.
    chain.with(SECOND, vec![chain.legacy(1, ActionPayload::Transfer(ledger::Transfer { to: 10, amount: 2 * SECOND }))]);
    chain.with(SECOND, vec![chain.register(10, 131)]);
    let new = chain.validator(10);
    assert_eq!((new.registrations, new.punishments, new.total, new.first.height), (1, 0, Count::default(), chain.height() as u64));
    chain.engine.audit().unwrap();
}

/// Moving stake in a circle makes it new: taking it out, waiting the
/// fourteen days and putting it back with another validator, or with the
/// same one, gives a lot of the week it came back.
#[test]
fn stake_moved_in_a_circle_is_new() {
    let mut chain = Chain::new(recorded(seven()));
    for _ in 0..15 {
        chain.quiet(WEEK);
    }
    chain.with(SECOND, vec![chain.legacy(0, ActionPayload::Transfer(ledger::Transfer { to: 9, amount: 5 * SECOND }))]);
    chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator: 1, amount: 2 * SECOND, min_shares: 1 }))]);
    let first = chain.week();
    for _ in 0..10 {
        chain.quiet(WEEK);
    }
    let shares = chain.view().stake(9).unwrap().positions[0].shares;
    assert_eq!(chain.get::<Lots>(&service::delegation_key(1, 9)).unwrap().lots, vec![service::Lot { week: first, amount: shares }]);
    chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Undelegate(ledger::Undelegate { operator: 1, shares, min_amount: 1 }))]);
    assert!(chain.row(&service::delegation_key(1, 9)).is_none());
    // The exit is released two blocks later, and can be taken out fourteen
    // days after that.
    chain.quiet(SECOND);
    chain.quiet(SECOND);
    chain.quiet(15 * DAY);
    let entry = chain.view().stake(9).unwrap().exits[0].id;
    chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Withdraw(ledger::Withdraw { entry }))]);
    for operator in [2, 1] {
        chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator, amount: SECOND / 2, min_shares: 1 }))]);
        let lots: Lots = chain.get(&service::delegation_key(operator, 9)).unwrap();
        assert_eq!(lots.lots.len(), 1);
        assert_eq!(lots.lots[0].week, chain.week(), "back with validator {operator}: new");
    }
    chain.engine.audit().unwrap();
}

/// Two proposers leave validator 3's signature out of every block they
/// propose. The records show it: 3's missed blocks name only those two, and
/// their `omitted` counts carry it. What a later rule could read from that,
/// it can only read because the records keep the proposer of each missed
/// block: here, that 3 signed every block of every other proposer.
#[test]
fn proposers_that_leave_a_signature_out_are_on_the_record() {
    let mut chain = Chain::new(recorded(seven()));
    chain.quiet(SECOND);
    let censors = [0u64, 1];
    let mut by_censor = 0;
    for height in 2..=60i64 {
        let roster = chain.engine.active_roster_at(height as u64 - 1).unwrap();
        let proposer = roster[height as usize % roster.len()].owner;
        let absent = if censors.contains(&proposer) {
            by_censor += 1;
            vec![3]
        } else {
            vec![]
        };
        chain.block_by(Step { delta: 5 * SECOND, txs: vec![], refused: 0, absent, misbehavior: vec![] }, address_of_seed(proposer as u8 + 101));
    }
    let week = chain.week();
    let mut missed: BTreeMap<u64, u64> = BTreeMap::new();
    let mut omitted: BTreeMap<u64, u64> = BTreeMap::new();
    let mut signed_with_others = (0u64, 0u64);
    for w in 0..=week {
        if let Some(row) = chain.get::<Missed>(&service::missed_key(3, w)) {
            for count in row.proposers {
                *missed.entry(count.proposer).or_default() += count.blocks;
            }
        }
    }
    for ((owner, _), count) in &chain.model.counts {
        if censors.contains(owner) {
            *omitted.entry(*owner).or_default() += count.omitted;
        }
    }
    assert_eq!(missed.keys().copied().collect::<Vec<_>>(), censors.to_vec());
    assert_eq!(missed.values().sum::<u64>(), by_censor);
    assert_eq!(omitted.values().sum::<u64>(), by_censor);
    // A rule that leaves the blocks of those proposers aside finds that 3
    // signed all the others.
    for ((owner, _), count) in &chain.model.counts {
        if *owner == 3 {
            signed_with_others.0 += count.signed;
            signed_with_others.1 += count.in_set;
        }
    }
    assert_eq!(signed_with_others.1 - signed_with_others.0, by_censor);
    assert!(by_censor * 4 > signed_with_others.1, "two of seven proposers leave out more than a quarter: {by_censor}");
    chain.engine.audit().unwrap();
}

/// What the records cannot do, said as a test so that nobody takes them for
/// more: the proposer a block's header names is the proposer's own word
/// (CometBFT checks only that it names a validator of the set), so a
/// proposer that leaves a signature out can put it on another validator.
/// A header that names an address of no validator, or none, is counted as
/// a block without a proposer.
#[test]
fn the_proposer_a_header_names_is_its_proposers_word() {
    let mut chain = Chain::new(recorded(seven()));
    chain.quiet(SECOND);
    // Validator 0 proposes, leaves 3 out, and names validator 5.
    let step = |absent: Vec<u64>| Step { delta: SECOND, txs: vec![], refused: 0, absent, misbehavior: vec![] };
    chain.block_by(step(vec![3]), address_of_seed(5 + 101));
    let week = chain.week();
    let missed: Missed = chain.get(&service::missed_key(3, week)).unwrap();
    assert_eq!(missed.proposers, vec![service::ProposerCount { proposer: 5, blocks: 1 }]);
    let tally = chain.tally();
    let five = tally.validators.iter().find(|entry| entry.owner == 5).unwrap();
    assert_eq!((five.proposed, five.omitted), (1, 1));
    // An address of no validator, and none at all.
    chain.block_by(step(vec![3]), vec![7; 20]);
    chain.block_by(step(vec![3]), vec![]);
    let missed: Missed = chain.get(&service::missed_key(3, week)).unwrap();
    assert_eq!(missed.proposers.iter().map(|count| (count.proposer, count.blocks)).collect::<Vec<_>>(), vec![(5, 1), (NO_PROPOSER, 2)]);
    assert_eq!(chain.tally().unattributed, 2);
    chain.engine.audit().unwrap();
}

/// More weeks than the records keep: each validator keeps `KEPT_WEEKS`
/// weeks one by one and sums the rest; the weeks row as many; a position
/// `KEPT_WEEKS + 2` lots at most; missed blocks go with their week.
#[test]
fn the_records_stay_bounded_over_more_weeks_than_they_keep() {
    let mut chain = Chain::new(recorded(seven()));
    for _ in 0..40 {
        chain.quiet(WEEK);
    }
    chain.with(SECOND, vec![chain.legacy(0, ActionPayload::Transfer(ledger::Transfer { to: 9, amount: 55 * SECOND }))]);
    // A large first delegation, so that the pool's rewards keep the price
    // of a share low enough for the small ones after it.
    chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator: 2, amount: 20 * SECOND, min_shares: 1 }))]);
    for round in 0..130u64 {
        // Every week a little more stake, and validator 4's signature
        // missing from one block.
        let delegate = chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator: 2, amount: 250_000 + round, min_shares: 1 }));
        chain.with(WEEK - SECOND, vec![delegate]);
        chain.block(Step { delta: SECOND, txs: vec![], refused: 0, absent: vec![4], misbehavior: vec![] });
        let lots: Lots = chain.get(&service::delegation_key(2, 9)).unwrap();
        assert!(lots.lots.len() as u64 <= KEPT_WEEKS + 2, "{}", lots.lots.len());
    }
    let record = chain.validator(4);
    assert_eq!(record.weeks.len() as u64, KEPT_WEEKS);
    assert!(record.older.in_set > 0 && record.older.signed < record.older.in_set);
    let weeks: Weeks = chain.get(service::WEEKS_KEY).unwrap();
    assert_eq!(weeks.weeks.len() as u64, KEPT_WEEKS);
    // Missed blocks only for the weeks still kept.
    let mut rows = 0;
    for week in 0..=chain.week() {
        if chain.row(&service::missed_key(4, week)).is_some() {
            assert!(week == chain.week() || record.weeks.iter().any(|kept| kept.week == week));
            rows += 1;
        }
    }
    assert!(rows as u64 <= KEPT_WEEKS + 1 && rows > 50, "{rows}");
    let lots: Lots = chain.get(&service::delegation_key(2, 9)).unwrap();
    assert_eq!(lots.lots.len() as u64, KEPT_WEEKS + 2);
    chain.engine.audit().unwrap();
}

/// What the records cost, in rows a block writes: the same blocks on the
/// same head with and without the setting.
#[test]
fn what_the_records_cost_in_rows_written() {
    let mut costs: Vec<BTreeMap<&str, usize>> = Vec::new();
    for genesis in [seven(), recorded(seven())] {
        let mut chain = Chain::new(genesis);
        for _ in 0..15 {
            chain.quiet(WEEK);
        }
        chain.with(SECOND, vec![chain.legacy(0, ActionPayload::Transfer(ledger::Transfer { to: 9, amount: 5 * SECOND }))]);
        chain.with(SECOND, vec![chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator: 2, amount: SECOND, min_shares: 1 }))]);
        // Rows written by a block on this head, dated a second after it (in
        // the same week), with all signatures or without one.
        let rows = |txs: Vec<Vec<u8>>, absent: &[u64], delta: u64| -> usize {
            let meta = chain.engine.meta().unwrap();
            let (height, time) = (meta.height + 1, meta.time_micros + delta as i64);
            let absent: Vec<String> = absent.iter().map(|owner| pk(*owner as u8 + 101)).collect();
            let signers: Vec<String> =
                chain.engine.active_roster_at(meta.height as u64).unwrap().into_iter().map(|v| v.consensus_key).filter(|key| !absent.contains(key)).collect();
            let prepared = chain.engine.prepare_proposed(height, time, &txs, &signers, sha(height as u64), &[], &address_of_seed(101)).unwrap();
            assert_eq!(prepared.txcount, txs.len());
            prepared.updated_rows
        };
        let transfers: Vec<Vec<u8>> = (0..7u64).map(|owner| chain.legacy(owner, ActionPayload::Transfer(ledger::Transfer { to: 10, amount: 1_000 }))).collect();
        let mut cost = BTreeMap::new();
        cost.insert("empty block", rows(vec![], &[], SECOND));
        cost.insert("seven payments", rows(transfers, &[], SECOND));
        cost.insert("one signature left out", rows(vec![], &[3], SECOND));
        cost.insert("three signatures left out", rows(vec![], &[3, 4, 5], SECOND));
        cost.insert("first block of a week", rows(vec![], &[], WEEK));
        cost.insert("bond", rows(vec![chain.extension(1, 18, json!({"amount": "100000"}))], &[], SECOND));
        cost.insert("delegation", rows(vec![chain.legacy(9, ActionPayload::Delegate(ledger::Delegate { operator: 3, amount: SECOND / 2, min_shares: 1 }))], &[], SECOND));
        cost.insert("validator registration", rows(vec![chain.register(9, 140)], &[], SECOND));
        costs.push(cost);
    }
    let added: BTreeMap<&str, usize> = costs[1].iter().map(|(what, rows)| (*what, rows - costs[0][what])).collect();
    println!("rows written without the records: {:?}", costs[0]);
    println!("rows the records add: {added:?}");
    // One row per block, whatever it holds; none per payment.
    assert_eq!(added["empty block"], 1);
    assert_eq!(added["seven payments"], 1);
    // One more per signature left out.
    assert_eq!(added["one signature left out"], 2);
    assert_eq!(added["three signatures left out"], 4);
    // The first block of a week: the tally, the weeks, and the record of
    // each of the seven validators.
    assert_eq!(added["first block of a week"], 1 + 1 + 7);
    // A change of stake: one row of lots.
    assert_eq!(added["bond"], 2);
    assert_eq!(added["delegation"], 2);
    // A registration: the validator's record, its key, its bond.
    assert_eq!(added["validator registration"], 1 + 3);
}

/// Nothing outside the records reads them: the rule modules only call the
/// functions that write them, which return nothing but an error.
#[test]
fn no_rule_reads_the_records() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let writers = ["account_created", "initialize", "registered", "punished", "record_block", "bond_changed", "positions_changed", "Cause::", "PREFIX", "audit"];
    let mut uses = 0;
    for file in std::fs::read_dir(&source).unwrap() {
        let file = file.unwrap().path();
        if file.extension().is_none_or(|extension| extension != "rs") || file.ends_with("service.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        for (at, _) in text.match_indices("service::") {
            let rest = &text[at + "service::".len()..];
            assert!(writers.iter().any(|name| rest.starts_with(name)), "{}: service::{}", file.display(), &rest[..rest.len().min(40)]);
            uses += 1;
        }
    }
    assert!(uses >= 12, "{uses}");
}

/// The state of `chain` with its rows changed, in a store of its own: what
/// the recount says of it.
fn recount(chain: &Chain, change: impl FnOnce(&mut BTreeMap<Vec<u8>, Vec<u8>>)) -> anyhow::Result<Audit> {
    let mut rows = chain.rows();
    change(&mut rows);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.v5state")).unwrap();
    let meta = rows[b"meta".as_slice()].clone();
    let mut tree = store.prepare(None, 0, rows.into_iter().map(|(key, value)| (key, Some(value))).collect()).unwrap();
    tree.set_head_metadata(meta.clone(), [0; 32]).unwrap();
    store.commit(tree).unwrap();
    for version in 1..=chain.height() as u64 {
        let base = store.current().unwrap().unwrap();
        let mut tree = store.prepare(Some(&base), version, vec![(b"meta".to_vec(), Some(meta.clone()))]).unwrap();
        tree.set_head_metadata(meta.clone(), [0; 32]).unwrap();
        store.commit(tree).unwrap();
    }
    Engine::open(store)?.audit()
}
fn edit<T: DeserializeOwned + serde::Serialize>(rows: &mut BTreeMap<Vec<u8>, Vec<u8>>, key: &[u8], change: impl FnOnce(&mut T)) {
    let mut value: T = serde_json::from_slice(&rows[key]).unwrap();
    change(&mut value);
    rows.insert(key.to_vec(), serde_json::to_vec(&value).unwrap());
}

type Change = Box<dyn Fn(&mut BTreeMap<Vec<u8>, Vec<u8>>)>;
fn refused_all(chain: &Chain, cases: Vec<(&str, Change)>) {
    recount(chain, |_| {}).unwrap();
    for (why, change) in cases {
        let reason = format!("{:#}", recount(chain, |rows| change(rows)).unwrap_err());
        assert!(reason.contains(why), "{why}: {reason}");
    }
}
/// A punishment's rows taken away: the punishment, the count of the
/// owner's record and the mark on the key.
fn unpunish(rows: &mut BTreeMap<Vec<u8>, Vec<u8>>, owner: u64, height: u64) {
    assert!(rows.remove(&service::punishment_key(owner, height)).is_some());
    edit::<ValidatorRecord>(rows, &service::validator_key(owner), |record| record.punishments = 0);
    edit::<KeyRecord>(rows, &service::key_key(&pk(owner as u8 + 101)).unwrap(), |entry| entry.punished = None);
}

#[test]
fn the_recount_checks_the_records_and_refuses_damaged_ones() {
    // Thirty blocks in: two validators punished and still jailed, missed
    // blocks in the weeks kept.
    let mut chain = Chain::new(recorded(seven()));
    chain.script(1, 30);
    let cases: Vec<(&str, Change)> = vec![
        ("a jailed validator without its punishment", Box::new(|rows| unpunish(rows, REPORTED, 25))),
        ("one account record for every account", Box::new(|rows| {
            rows.remove(&service::account_record_key(5));
        })),
        ("an account record of the wrong block", Box::new(|rows| edit::<Moment>(rows, &service::account_record_key(GENESIS_ACCOUNTS), |at| at.height = 0))),
        ("a service record dated otherwise than its block", Box::new(|rows| edit::<Moment>(rows, &service::account_record_key(GENESIS_ACCOUNTS), |at| at.time_micros += 1))),
        ("a validator's weeks do not add up to its total", Box::new(|rows| edit::<ValidatorRecord>(rows, &service::validator_key(3), |record| record.total.signed += 1))),
        ("the blocks of a week differ", Box::new(|rows| edit::<Tally>(rows, service::TALLY_KEY, |tally| {
            tally.blocks += 1;
            tally.unattributed += 1;
        }))),
        ("differ from the rosters", Box::new(|rows| edit::<Tally>(rows, service::TALLY_KEY, |tally| {
            let entry = tally.validators.iter_mut().find(|entry| entry.signed > 0).unwrap();
            entry.in_set -= 1;
            entry.signed -= 1;
        }))),
        ("missed blocks rows differ from the counts", Box::new(|rows| {
            let key = rows.keys().find(|key| key.starts_with(b"service/missed/")).unwrap().clone();
            rows.remove(&key);
        })),
        ("missed blocks that the counts do not show", Box::new(|rows| {
            let key = rows.keys().find(|key| key.starts_with(b"service/missed/")).unwrap().clone();
            edit::<Missed>(rows, &key, |row| row.proposers[0].blocks += 1);
        })),
        ("an unknown service record row", Box::new(|rows| {
            rows.insert(b"service/other".to_vec(), b"1".to_vec());
        })),
        ("a validator record with a key its owner did not reserve", Box::new(|rows| edit::<ValidatorRecord>(rows, &service::validator_key(2), |record| record.consensus_key = pk(104)))),
        ("bond lots differ from the bond", Box::new(|rows| edit::<Lots>(rows, &service::bond_key(NEWCOMER), |lots| lots.lots[0].amount += 1))),
    ];
    refused_all(&chain, cases);
    // Forty blocks in: after the stop of fifteen days the block history
    // before it is cleaned up, the punished validators are gone, the
    // newcomer is registered again.
    chain.script(31, 40);
    assert!(chain.engine.meta().unwrap().history_pruned_through > 0);
    let cases: Vec<(&str, Change)> = vec![
        ("the punishments differ from the rows of the staking rules", Box::new(|rows| unpunish(rows, EVIDENCED, 29))),
        ("a punishment by reported misbehavior without its record", Box::new(|rows| unpunish(rows, REPORTED, 25))),
        ("bond lots differ from the bond", Box::new(|rows| edit::<Lots>(rows, &service::bond_key(NEWCOMER), |lots| lots.lots[0].amount += 1))),
        ("delegation lots differ from the position", Box::new(|rows| edit::<Lots>(rows, &service::delegation_key(0, DELEGATOR), |lots| lots.lots[0].amount -= 1))),
        ("a delegation without its lots", Box::new(|rows| {
            rows.remove(&service::delegation_key(0, DELEGATOR));
        })),
        ("differ from the rosters", Box::new(|rows| edit::<Tally>(rows, service::TALLY_KEY, |tally| {
            let entry = tally.validators.iter_mut().find(|entry| entry.signed > 0).unwrap();
            entry.in_set -= 1;
            entry.signed -= 1;
        }))),
        ("a validator record's registrations or punishments differ from its keys", Box::new(|rows| edit::<ValidatorRecord>(rows, &service::validator_key(NEWCOMER), |record| record.registrations = 3))),
    ];
    refused_all(&chain, cases);
    // A record on a network without the setting, even a true one.
    let mut plain = Chain::new(seven());
    plain.quiet(SECOND);
    recount(&plain, |_| {}).unwrap();
    let foreign = format!("{:#}", recount(&plain, |rows| {
        rows.insert(service::account_record_key(0), serde_json::to_vec(&Moment { height: 0, time_micros: 1_800_000_000_000_000 }).unwrap());
    })
    .unwrap_err());
    assert!(foreign.contains("service record rows on a network without service_records"), "{foreign}");
}

// ---- The switch block of a fix release --------------------------------------

const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// The switch block of a fix release is a block like any other for the
/// records: it is counted, its proposer with it, and the recount passes
/// after it.
#[test]
fn a_switch_block_is_counted_like_any_block() {
    let old = Versions::new([(4, rules::SPEC_4.to_string())]).unwrap();
    let genesis = recorded(seven());
    let network = genesis.network_id().unwrap();
    let mut chain = Chain::on(genesis.clone(), Some(old));
    chain.script(1, 24);
    let h = chain.height() as u64;
    let fix = Versions::new([(4, rules::SPEC_4.to_string()), (5, SPEC_5.to_string())])
        .unwrap()
        .with_switch(Switch { network_id: network.clone(), version: 5, at: SwitchAt::After { height: h } })
        .unwrap();
    // The same chain under the fix release.
    let mut fixed = Chain::on(genesis, Some(fix));
    for (delta, txs, signers, misbehavior, proposer) in chain.log.clone() {
        let meta = fixed.engine.meta().unwrap();
        let (height, time) = (meta.height + 1, meta.time_micros + delta as i64);
        let prepared = fixed.engine.prepare_proposed(height, time, &txs, &signers, sha(height as u64), &misbehavior, &proposer).unwrap();
        fixed.commit(prepared, sha(height as u64), &signers, &proposer);
    }
    assert_eq!(fixed.engine.head().unwrap(), chain.engine.head().unwrap());
    let before = fixed.tally();
    let switch = upgrade::switch_action(&network, 5, SPEC_5).unwrap();
    let proposer = fixed.proposer_for(h as i64 + 1);
    let kept = fixed.block_by(Step { delta: 5 * SECOND, txs: vec![switch], refused: 0, absent: vec![2], misbehavior: vec![] }, proposer);
    assert_eq!(kept, 1);
    assert_eq!(fixed.engine.meta().unwrap().protocol_version, 5);
    let after = fixed.tally();
    assert_eq!(after.blocks, if after.week == before.week { before.blocks + 1 } else { 1 });
    fixed.quiet(SECOND);
    fixed.engine.audit().unwrap();
}

// ---- A node, as CometBFT drives it ------------------------------------------

const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const OFFER_ACCEPT: i32 = response_offer_snapshot::Result::Accept as i32;
const CHUNK_ACCEPT: i32 = response_apply_snapshot_chunk::Result::Accept as i32;

fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp { seconds: micros / 1_000_000, nanos: ((micros % 1_000_000) * 1000) as i32 })
}
fn init(genesis: &Genesis) -> RequestInitChain {
    RequestInitChain {
        chain_id: genesis.ledger.chain_id.clone(),
        time: timestamp(genesis.ledger.genesis_time_micros),
        app_state_bytes: serde_json::to_vec(genesis).unwrap().into(),
        validators: genesis
            .validators
            .iter()
            .map(|validator| ValidatorUpdate {
                pub_key: Some(tendermint_proto::crypto::PublicKey {
                    sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(hex::decode(&validator.consensus_key).unwrap())),
                }),
                power: genesis.profile.genesis_power() as i64,
            })
            .collect(),
        ..Default::default()
    }
}
fn query(app: &App, path: &str, data: &Value) -> Value {
    let response = app.query(RequestQuery { data: serde_json::to_vec(data).unwrap().into(), path: path.into(), height: 0, prove: false });
    assert_eq!(response.code, 0, "query failed: {}", response.log);
    serde_json::from_slice(&response.value).unwrap()
}
/// The rows under `keys` as a node proves them, each proof checked against
/// the application hash the node reports.
fn proven(app: &App, keys: &[Vec<u8>]) -> Vec<Option<Vec<u8>>> {
    let info = app.info(RequestInfo::default());
    let root: [u8; 32] = info.last_block_app_hash.to_vec().try_into().unwrap();
    let answer = query(app, "/compact-proof", &json!(keys.iter().map(hex::encode).collect::<Vec<_>>()));
    assert_eq!(answer["root"], hex::encode(root));
    let entries: Vec<ProofEntry> = serde_json::from_value(answer["entries"].clone()).unwrap();
    entries.iter().zip(keys).map(|(entry, key)| entry.verify(root, key).unwrap()).collect()
}
fn account_of(app: &App, id: u64) -> Account {
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()] }));
    let key = hex::encode(account_key(id));
    let entry = view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == key.as_str()).unwrap();
    serde_json::from_slice(&STANDARD.decode(entry["value_b64"].as_str().unwrap()).unwrap()).unwrap()
}
/// `time-node-v5 --devnet --db PATH --audit`.
fn recount_report(path: &Path) -> Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5")).args(["--devnet", "--db"]).arg(path).arg("--audit").output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "PASS_OFFLINE_AUTHENTICATED_RECOUNT");
    report
}

struct Node {
    app: App,
    genesis: Genesis,
    network: String,
    height: i64,
    elapsed: u64,
    log: Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>,
}
impl Node {
    fn start(path: &Path, options: NodeOptions, genesis: &Genesis) -> Self {
        let app = App::open_with_options(path, options).unwrap();
        app.try_init(init(genesis)).unwrap();
        Self { app, genesis: genesis.clone(), network: genesis.network_id().unwrap(), height: 0, elapsed: 0, log: Vec::new() }
    }
    /// The finalize request of the next block: every starting validator
    /// signs but `absent`, and validator `proposer` proposes.
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>, absent: &[u64], proposer: u64) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: timestamp(self.genesis.ledger.genesis_time_micros + (self.elapsed + delta) as i64),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: (height > 1).then(|| CommitInfo {
                round: 0,
                votes: self
                    .genesis
                    .validators
                    .iter()
                    .map(|validator| VoteInfo {
                        validator: Some(Validator { address: address_of_key(&validator.consensus_key).into(), power: self.genesis.profile.genesis_power() as i64 }),
                        block_id_flag: if absent.contains(&validator.owner) { BlockIdFlag::Absent as i32 } else { BlockIdFlag::Commit as i32 },
                    })
                    .collect(),
            }),
            proposer_address: address_of_seed(proposer as u8 + 101).into(),
            ..Default::default()
        }
    }
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>, absent: &[u64], proposer: u64) {
        let request = self.request(delta, txs, absent, proposer);
        let proposal = RequestProcessProposal {
            txs: request.txs.clone(),
            proposed_last_commit: request.decided_last_commit.clone(),
            misbehavior: request.misbehavior.clone(),
            hash: request.hash.clone(),
            height: request.height,
            time: request.time,
            next_validators_hash: request.next_validators_hash.clone(),
            proposer_address: request.proposer_address.clone(),
        };
        assert_eq!(self.app.process_proposal(proposal).status, ACCEPT, "proposal rejected at height {}", request.height);
        let response = self.app.try_finalize(request.clone()).unwrap();
        self.app.try_commit().unwrap();
        self.app.write_sync_snapshot().unwrap();
        self.height += 1;
        self.elapsed += delta;
        self.log.push((request, response));
    }
    fn tally(&self) -> Tally {
        serde_json::from_slice(&proven(&self.app, &[service::TALLY_KEY.to_vec()])[0].clone().unwrap()).unwrap()
    }
}

#[test]
fn a_node_keeps_the_records_through_its_proposals_a_restart_and_state_sync() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = recorded(genesis_v5());
    let serving = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let path = dir.path().join("source.db");
    let mut source = Node::start(&path, serving, &genesis);
    // The proposer's selection names this node's validator (PrepareProposal
    // carries it as well): it builds a block with what the validators then
    // accept.
    let chosen = source.app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: 1 << 20,
        height: 1,
        time: timestamp(genesis.ledger.genesis_time_micros + SECOND as i64),
        proposer_address: address_of_seed(101).into(),
        ..Default::default()
    });
    assert!(chosen.txs.is_empty());
    for height in 1..=24u64 {
        // Validator 2 is left out of every third block, proposed by 1.
        let (absent, proposer) = if height % 3 == 0 { (vec![2], 1) } else { (vec![], height % 4) };
        source.block(20 * SECOND, vec![], &absent, proposer);
    }
    // A wallet reads a record with a proof, like any row.
    let rows = proven(&source.app, &[service::validator_key(2), service::account_record_key(3), service::bond_key(2)]);
    let record: ValidatorRecord = serde_json::from_slice(rows[0].as_ref().unwrap()).unwrap();
    assert_eq!(record.registrations, 1);
    assert!(record.total.in_set > record.total.signed);
    let created: Moment = serde_json::from_slice(rows[1].as_ref().unwrap()).unwrap();
    assert_eq!(created.height, 0);
    assert_eq!(rows[2], None, "validator 2 holds no bond of its own: proven absent");
    // Its signatures missing in blocks proposed by 1, and only by 1.
    let mut by: BTreeMap<u64, u64> = BTreeMap::new();
    for week in 0..=8 {
        if let Some(row) = proven(&source.app, &[service::missed_key(2, week)])[0].clone() {
            let row: Missed = serde_json::from_slice(&row).unwrap();
            for count in row.proposers {
                *by.entry(count.proposer).or_default() += count.blocks;
            }
        }
    }
    assert_eq!(by.keys().copied().collect::<Vec<_>>(), vec![1]);
    // A node that joins by state sync restores the snapshot of height 20,
    // then executes the blocks after it.
    let snapshot = source.app.list_snapshots().snapshots.into_iter().find(|snapshot| snapshot.height == 20).unwrap();
    let trusted = source.log[19].1.app_hash.clone();
    let joined_path = dir.path().join("joined.db");
    let joiner = App::open(&joined_path).unwrap();
    assert_eq!(joiner.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot.clone()), app_hash: trusted.clone() }).result, OFFER_ACCEPT);
    for chunk in 0..snapshot.chunks {
        let bytes = source.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 20, format: snapshot.format, chunk }).chunk;
        assert_eq!(joiner.apply_snapshot_chunk(RequestApplySnapshotChunk { index: chunk, chunk: bytes, sender: "peer".into() }).result, CHUNK_ACCEPT);
    }
    for (request, response) in &source.log[20..] {
        assert_eq!(joiner.try_finalize(request.clone()).unwrap(), *response);
        joiner.try_commit().unwrap();
    }
    assert_eq!(joiner.head().unwrap(), source.app.head().unwrap());
    let mut joined = Node { app: joiner, genesis: genesis.clone(), network: source.network.clone(), height: source.height, elapsed: source.elapsed, log: Vec::new() };
    assert_eq!(joined.tally(), source.tally());
    // The first node stops and starts again from its restart snapshot.
    let (height, root) = source.app.head().unwrap().unwrap();
    source.app.snapshot().unwrap().expect("a restart snapshot");
    let (network, elapsed) = (source.network.clone(), source.elapsed);
    drop(source);
    let app = App::open_with_options(&path, serving).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    let mut restarted = Node { app, genesis: genesis.clone(), network, height: height as i64, elapsed, log: Vec::new() };
    // Both go on to the same state, through stake, across a week.
    let bond = |node: &Node| {
        let row = account_of(&node.app, 2);
        timecurrency_v5::wire::sign(&node.network, 2, row.nonce + 1, row.auth_epoch, 18, &json!({"amount": "300000"}), &key(3)).unwrap()
    };
    for node in [&mut restarted, &mut joined] {
        let tx = bond(node);
        node.block(SECOND, vec![tx], &[], 3);
        node.block(2 * MINUTE, vec![], &[0], 2);
    }
    assert_eq!(restarted.app.head().unwrap(), joined.app.head().unwrap());
    let lots: Lots = serde_json::from_slice(&proven(&restarted.app, &[service::bond_key(2)])[0].clone().unwrap()).unwrap();
    assert_eq!(lots.total().unwrap(), 300_000);
    // The recount of both, offline: the report names the records.
    for (node, node_path) in [(restarted, path), (joined, joined_path)] {
        node.app.snapshot().unwrap();
        drop(node);
        let report = recount_report(&node_path);
        assert_eq!(report["service_records"], true, "{report}");
        let engine = Engine::open_with_history(Store::open(node_path.with_extension("v5state")).unwrap(), node_path.with_extension("history")).unwrap();
        engine.audit().unwrap();
    }
    // Without the setting the report has no such field.
    let plain_path = dir.path().join("plain.db");
    let mut plain = Node::start(&plain_path, NodeOptions::default(), &genesis_v5());
    plain.block(SECOND, vec![], &[], 0);
    plain.block(SECOND, vec![], &[1], 0);
    plain.app.snapshot().unwrap();
    drop(plain);
    assert!(recount_report(&plain_path).get("service_records").is_none());
}
