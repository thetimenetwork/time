//! The emergency path on a network with the account-safety settings: where
//! the rule switch of a fix release (`emergency.rs`) meets waits that
//! survive a stop (`waits_survive_stops.rs`) and accounts protected from the
//! start (`protected_registration.rs`). Each of those was built and tested
//! alone; these tests run them together.
//!
//! - A stop at an agreed height, then the switch: the stand before the
//!   switch block is counted once, by that block, on the clock of the waits,
//!   and a payment that waits is due exactly when the chain has run for it.
//! - A stop in the middle of a block, then the repair: the gap of the
//!   repaired block and the stand before the block after it are each
//!   counted once, and a freeze ends exactly when the chain has run for it.
//! - A switch block and a repaired block on a network with all three
//!   settings (`distinct_names`, `waits_survive_stops`,
//!   `protected_registration`): row by row what an empty block, or the same
//!   block under the old rules, leaves; the supply rule at every block; the
//!   recount.
//! - A registration of kind 45 in the block before a switch, offered with
//!   the switch block, and in the block after it.
//!
//! Every block is built by a proposer or executed as a decided block,
//! validated strictly and executed with the engine's fast paths off; the
//! three must agree, and the supply rule must hold after it.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, META_KEY, Meta, Prepared, account_key, name_key};
use timecurrency_v5::genesis::Genesis;
use timecurrency_v5::names;
use timecurrency_v5::rules::{self, Switch, SwitchAt, Versions};
use timecurrency_v5::security::{self, Role, Security};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;
use timecurrency_v5::upgrade::{self, Event};

const SECOND: u64 = 1_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 3_600 * SECOND;
const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// The account under test (its protocol-4 key is seed 6) and its keys.
const ME: u64 = 5;
const OLD: u8 = 6;
const SIGNIN: u8 = 60;
const SPEND: u8 = 61;
const SHEET: u8 = 62;
const PHRASE: u8 = 63;
const FRIEND: u8 = 64;
const SHOP: u64 = 7;
/// A genesis account that owns no validator, and pays for registrations
/// (its key is seed 9).
const SPONSOR: u64 = 8;
/// Its settings. The waits are far longer than the five minutes of a gap
/// that count.
const LIMIT: u64 = 480_000;
/// The gap above which the rest of a gap is a stop on the clock of the
/// waits (`security::STOP_THRESHOLD_MICROS`).
const T: u64 = 5 * MINUTE;
const DELAY: u64 = 3 * HOUR;
const FREEZE: u64 = 4 * HOUR;
const NOT_OVER: &str = "the waiting period is not over";
const FROZEN: &str = "account is frozen";
const ALONE: &str = "exactly one transaction, the rule switch of this fix release";

/// The test genesis with the three settings the production profile requires.
fn safe() -> Genesis {
    let mut genesis = genesis_v5();
    genesis.distinct_names = true;
    genesis.waits_survive_stops = true;
    genesis.protected_registration = true;
    genesis
}

fn list(versions: &[(u64, &str)]) -> Versions {
    Versions::new(versions.iter().map(|(version, spec)| (*version, (*spec).to_string()))).unwrap()
}
/// Release 1: version 4 and no switch.
fn old() -> Versions {
    list(&[(4, rules::SPEC_4)])
}
/// A program that implements a version 5 and is not a fix release.
fn plain() -> Versions {
    list(&[(4, rules::SPEC_4), (5, SPEC_5)])
}
/// A fix release for `network`: the switch to version 5 after `height`.
fn fix(network: &str, height: u64) -> Versions {
    plain().with_switch(Switch { network_id: network.into(), version: 5, at: SwitchAt::After { height } }).unwrap()
}
/// A fix release for `network` that repairs the decided block `height` with
/// the hash `block_hash` on the state with the root `parent_root`.
fn repair(network: &str, height: u64, block_hash: [u8; 32], parent_root: [u8; 32]) -> Versions {
    plain()
        .with_switch(Switch {
            network_id: network.into(),
            version: 5,
            at: SwitchAt::Block { height, block_hash: hex::encode(block_hash), parent_root: hex::encode(parent_root) },
        })
        .unwrap()
}
/// The one transaction of the switch block of `fix(network, _)`.
fn switch(network: &str) -> Vec<u8> {
    upgrade::switch_action(network, 5, SPEC_5).unwrap()
}
fn switched() -> Vec<Event> {
    vec![Event::Switched { version: 5, spec: SPEC_5.into(), cancelled: None }]
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Signin => "signin",
        Role::Spend => "spend",
        Role::Recover => "recover",
    }
}
fn sorted(mut keys: Vec<Value>) -> Value {
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    json!(keys)
}
fn policy() -> Value {
    json!({"threshold": "2", "daily_limit_micros": LIMIT.to_string(), "delay_seconds": (DELAY / SECOND).to_string(), "freeze_seconds": (FREEZE / SECOND).to_string()})
}
/// A key that joins the set of account `account`, with its holder's
/// acceptance of the role.
fn joins(network: &str, account: u64, seed: u8, role: Role) -> Value {
    let proof = key(seed).sign(&security::key_message(network, account, role, &pk(seed)).unwrap());
    json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
}
/// A key of the set of the account that the registration key
/// `registration` creates, with its holder's acceptance of the role.
fn registers(network: &str, registration: u8, seed: u8, role: Role) -> Value {
    let proof = key(seed).sign(&security::registration_key_message(network, &pk(registration), role, &pk(seed)).unwrap());
    json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
}
/// The set of keys of a registration by `registration`: four keys of its
/// own (seeds `first` to `first + 3`) and the policy of these tests.
fn setup(network: &str, registration: u8, first: u8) -> Value {
    json!({"keys": sorted(vec![
        registers(network, registration, first, Role::Signin),
        registers(network, registration, first + 1, Role::Spend),
        registers(network, registration, first + 2, Role::Recover),
        registers(network, registration, first + 3, Role::Recover),
    ]), "policy": policy()})
}
fn salt(seed: u8) -> String {
    hex::encode([seed; 32])
}
/// The registration that carries `setup` (kind 45), signed by the
/// registration key.
fn register_tx(network: &str, seed: u8, name: &str, setup: &Value) -> Vec<u8> {
    let payload = json!({"name": name, "salt": salt(seed), "security": setup});
    timecurrency_v5::wire::sign(network, u64::MAX, 0, 0, security::REGISTER, &payload, &key(seed)).unwrap()
}
fn commit_key(seed: u8) -> Vec<u8> {
    registration::commit_key(&pos::hex32(&pk(seed)).unwrap())
}

struct Chain {
    dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    /// Every block committed, as (time after its parent, transactions).
    log: Vec<(u64, Vec<Vec<u8>>)>,
}
impl Chain {
    fn on(genesis: Genesis, versions: Versions) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history"))
            .unwrap()
            .implementing(versions);
        engine.initialize(genesis).unwrap();
        Self { dir, engine, network, log: Vec::new() }
    }
    /// Another node: the same genesis and the same decided blocks, under the
    /// program `versions`.
    fn replay(genesis: Genesis, versions: Versions, log: &[(u64, Vec<Vec<u8>>)]) -> Self {
        let mut chain = Self::on(genesis, versions);
        for (delta, txs) in log {
            chain.decided(*delta, txs.clone());
        }
        chain
    }
    /// The same data under another program: the state is saved, and the
    /// engine is opened on it again as a program that implements `versions`.
    fn reopen(self, versions: Versions) -> Self {
        let Self { dir, engine, network, log } = self;
        let version = engine.version().unwrap().clone();
        if engine.store().snapshot_height().unwrap() != Some(version.height()) {
            engine.store().write_snapshot(&version).unwrap();
        }
        drop(version);
        drop(engine);
        let engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history"))
            .unwrap()
            .implementing(versions);
        Self { dir, engine, network, log }
    }
    /// The account under test holds twenty seconds and has adopted the
    /// rules, and the sponsor holds five seconds.
    fn secured(genesis: Genesis, versions: Versions) -> Self {
        let mut chain = Self::on(genesis, versions);
        for _ in 0..20 {
            chain.block(MINUTE, vec![]);
        }
        chain.block(SECOND, (0..4u64).map(|owner| chain.transfer(owner, owner as u8 + 1, ME, 5 * SECOND)).collect());
        chain.block(SECOND, vec![chain.transfer(0, 1, SPONSOR, 5 * SECOND)]);
        let network = chain.network.clone();
        let keys = sorted(vec![
            joins(&network, ME, SIGNIN, Role::Signin),
            joins(&network, ME, SPEND, Role::Spend),
            joins(&network, ME, SHEET, Role::Recover),
            joins(&network, ME, PHRASE, Role::Recover),
            joins(&network, ME, FRIEND, Role::Recover),
        ]);
        let row = chain.account(ME);
        let secure = timecurrency_v5::wire::sign(&network, ME, row.nonce + 1, row.auth_epoch, security::SECURE, &json!({"keys": keys, "policy": policy()}), &key(OLD)).unwrap();
        chain.block(SECOND, vec![secure]);
        assert_eq!(chain.mine().version, 1);
        chain
    }
    fn meta(&self) -> &Meta {
        self.engine.meta().unwrap()
    }
    /// The chain's time since genesis.
    fn now(&self) -> u64 {
        self.meta().elapsed_micros().unwrap()
    }
    /// The clock the account security rules read.
    fn active(&self) -> u64 {
        self.meta().active_micros().unwrap()
    }
    fn stopped(&self) -> u64 {
        self.meta().stopped_micros.expect("a network whose waits survive a stop")
    }
    fn height(&self) -> u64 {
        self.meta().height as u64
    }
    fn version(&self) -> u64 {
        self.meta().protocol_version
    }
    fn root(&self) -> [u8; 32] {
        self.engine.head().unwrap().unwrap().root
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    fn security(&self, id: u64) -> Option<Security> {
        self.row(&security::key(id)).map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn mine(&self) -> Security {
        self.security(ME).expect("the account has adopted the rules")
    }
    /// Every row of the committed state, after the whole tree was hashed again.
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
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + 1,
                auth_epoch: row.auth_epoch,
                public_key: pk(signer),
                payload: ActionPayload::Transfer(ledger::Transfer { to, amount }),
                signature: vec![],
            },
            &key(signer),
        )
        .unwrap()
    }
    /// A payment of the account under test within its daily limit.
    fn pay(&self, amount: u64) -> Vec<u8> {
        self.transfer(ME, SPEND, SHOP, amount)
    }
    fn act(&self, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(ME);
        timecurrency_v5::wire::sign(&self.network, ME, row.nonce + 1, row.auth_epoch, kind, &payload, &key(SPEND)).unwrap()
    }
    /// A payment above the limit, which waits.
    fn request(&self, amount: u64) -> Vec<u8> {
        self.act(security::PAYMENT, json!({"type": "request", "to": SHOP.to_string(), "amount": amount.to_string()}))
    }
    fn execute(&self, id: u64) -> Vec<u8> {
        self.act(security::PAYMENT, json!({"type": "execute", "id": id.to_string()}))
    }
    /// A freeze placed by a recovery key; its signature is good for ten
    /// minutes of the chain's time.
    fn freeze(&self) -> Vec<u8> {
        let mine = self.mine();
        let payload = json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": (self.now() + 600 * SECOND).to_string()});
        timecurrency_v5::wire::sign(&self.network, ME, 0, 0, security::FREEZE, &payload, &key(SHEET)).unwrap()
    }
    /// The sponsor pays for the registration of `name` by `seed` with
    /// `setup`. The commitment lasts twelve hours of the chain's time.
    fn sponsor(&self, seed: u8, name: &str, setup: &Value) -> Vec<u8> {
        let commitment = security::registration_commitment(&self.network, &pk(seed), name, &salt(seed), setup).unwrap();
        let row = self.account(SPONSOR);
        let expiry = self.now() + 12 * HOUR;
        let consent = registration::consent_bytes(
            pos::hex32(&self.network).unwrap(),
            row.id,
            pos::hex32(&pk(seed)).unwrap(),
            pos::hex32(&commitment).unwrap(),
            expiry,
        );
        let payload = json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())});
        timecurrency_v5::wire::sign(&self.network, row.id, row.nonce + 1, row.auth_epoch, 44, &payload, &key(SPONSOR as u8 + 1)).unwrap()
    }
    /// Height, time, signers and hash of a block `delta` after the head.
    /// Block N has the hash `sha(N)`.
    fn next(&self, delta: u64) -> (i64, i64, Vec<String>, [u8; 32]) {
        let meta = self.meta();
        let signers = self.engine.active_roster_at(meta.height as u64).unwrap().into_iter().map(|validator| validator.consensus_key).collect();
        (meta.height + 1, meta.time_micros + delta as i64, signers, sha(meta.height as u64 + 1))
    }
    /// What a proposer keeps of `mempool` for the next block, without
    /// committing.
    fn proposes(&self, delta: u64, mempool: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let (height, time, signers, hash) = self.next(delta);
        self.engine.prepare_filtered(height, time, mempool, &signers, 1 << 20, hash).unwrap().1
    }
    /// A block a proposer builds from exactly `txs`, keeping every one.
    #[track_caller]
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let (height, time, signers, hash) = self.next(delta);
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &txs, &signers, 1 << 20, hash).unwrap_or_else(|error| panic!("the proposer failed at height {height}: {error:#}"));
        if kept != txs {
            let reasons: Vec<String> = txs
                .iter()
                .map(|tx| match self.engine.prepare(height, time, &[tx], &signers, hash) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("the proposer did not keep block {height} as offered: {reasons:?}");
        }
        self.commit_checked(proposed, &kept, delta);
    }
    /// Blocks a minute apart for `micros`, none of them a stop.
    fn run(&mut self, micros: u64) {
        assert_eq!(micros % MINUTE, 0);
        for _ in 0..micros / MINUTE {
            self.block(MINUTE, vec![]);
        }
    }
    /// Commits exactly `txs`, as a validator executes a decided block.
    #[track_caller]
    fn decided(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Event> {
        let (height, time, signers, hash) = self.next(delta);
        let prepared = self.engine.prepare(height, time, &txs, &signers, hash).unwrap_or_else(|error| panic!("block {height} refused: {error:#}"));
        let events = prepared.upgrade_events.clone();
        self.commit_checked(prepared, &txs, delta);
        events
    }
    fn commit_checked(&mut self, prepared: Prepared, txs: &[Vec<u8>], delta: u64) {
        let (height, time, signers, hash) = self.next(delta);
        let strict = self.engine.prepare(height, time, txs, &signers, hash).unwrap();
        let reference = self.engine.prepare_reference(height, time, txs, &signers, hash).unwrap();
        assert_eq!(strict.root, prepared.root, "validator and proposer disagree at height {height}");
        assert_eq!(reference.root, prepared.root, "fast path and reference disagree at height {height}");
        self.engine.commit(prepared, hash).unwrap();
        self.log.push((delta, txs.to_vec()));
        let meta = self.meta();
        assert_eq!(
            meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total,
            meta.elapsed_micros().unwrap(),
            "supply rule at height {height}"
        );
    }
    /// Why the block dated `delta` after the head with exactly `txs` is not
    /// executed: by a validator and by the reference path alike.
    #[track_caller]
    fn refused(&self, delta: u64, txs: &[Vec<u8>]) -> String {
        let (height, time, signers, hash) = self.next(delta);
        let error = match self.engine.prepare(height, time, txs, &signers, hash) {
            Ok(_) => panic!("block {height} was executed"),
            Err(error) => format!("{error:#}"),
        };
        assert!(self.engine.prepare_reference(height, time, txs, &signers, hash).is_err(), "the reference path executed block {height}");
        error
    }
    /// Whether the mempool, which judges on the head, admits `tx`.
    fn admits(&self, tx: &[u8]) -> bool {
        self.engine.check_state().unwrap().admit(tx, SigStatus::Unknown).is_ok()
    }
}

/// The rows of two states that differ only by the switch: the activation
/// row of version 5 is in the first and not in the second, and the metadata
/// rows are the same but for the version.
#[track_caller]
fn same_but_the_version(fixed: &Chain, control: &Chain) {
    let (mut after, mut other) = (fixed.rows(), control.rows());
    assert!(after.remove(&upgrade::activated_key(5)).is_some(), "no activation row");
    let meta = |rows: &mut BTreeMap<Vec<u8>, Vec<u8>>| -> Value { serde_json::from_slice(&rows.remove(META_KEY).unwrap()).unwrap() };
    let (mut switched, unswitched) = (meta(&mut after), meta(&mut other));
    assert_eq!((switched["protocol_version"].as_str(), unswitched["protocol_version"].as_str()), (Some("5"), Some("4")));
    switched["protocol_version"] = "4".into();
    assert_eq!(switched, unswitched, "the switch changed more of the metadata than the version");
    assert_eq!(after.len(), other.len());
    for (key, value) in &after {
        assert_eq!(Some(value), other.get(key), "the two states differ in the row {}", String::from_utf8_lossy(key));
    }
}

/// An emergency at an agreed height on a network whose waits survive a
/// stop. The validators stop after block `H`, compare the root, install
/// the fix release and start it on the same data; the chain stands for six
/// hours. The switch block is dated six hours after `H`.
///
/// Of those six hours the clock of the waits takes five minutes, as after
/// any gap: the switch block counts the rest as a stop, once, exactly as an
/// empty block of the old program at that height would, and no later block
/// counts it again. A payment asked for before the stop is due when the
/// chain has run for its whole wait, to the microsecond.
#[test]
fn the_stand_before_a_switch_block_is_counted_once_on_the_clock_of_the_waits() {
    assert_eq!(security::STOP_THRESHOLD_MICROS, T);
    let mut chain = Chain::secured(safe(), old());
    chain.block(SECOND, vec![chain.request(3 * SECOND)]);
    let asked = chain.active();
    let ready = chain.mine().pending_payments[0].ready_elapsed_micros;
    assert_eq!(ready, asked + DELAY);
    chain.run(30 * MINUTE);
    // A stop of three hours before the emergency: the chain's time is then
    // two hours and 55 minutes ahead of the clock of the waits.
    chain.block(3 * HOUR, vec![]);
    assert_eq!(chain.stopped(), 3 * HOUR - T);
    // The validators stop after H, the head, and start the fix release on
    // the same data.
    let h = chain.height();
    let (stopped, active, now, root) = (chain.stopped(), chain.active(), chain.now(), chain.root());
    let network = chain.network.clone();
    let mut chain = chain.reopen(fix(&network, h));
    assert_eq!((chain.root(), chain.stopped(), chain.active()), (root, stopped, active), "the restart changed the state");
    assert!(chain.engine.missed_switch().is_none() && chain.engine.runnable().is_ok());
    // An empty block of release 1 at the same height, with the same date:
    // what the chain would have done without the switch.
    let mut control = Chain::replay(safe(), old(), &chain.log);
    assert_eq!(control.root(), root);
    // Six hours later the proposer of H + 1 proposes the switch alone,
    // whatever the owner and the others offer.
    let offered = vec![chain.execute(1), chain.pay(1_000), chain.transfer(0, 1, SHOP, 1_000)];
    assert_eq!(chain.proposes(6 * HOUR, &offered), vec![switch(&network)]);
    assert_eq!(chain.decided(6 * HOUR, vec![switch(&network)]), switched());
    control.decided(6 * HOUR, vec![]);
    assert_eq!((chain.height(), chain.version()), (h + 1, 5));
    // Of the six hours five minutes count; the switch block adds the rest
    // to the total of stops.
    assert_eq!(chain.now(), now + 6 * HOUR);
    assert_eq!(chain.stopped(), stopped + 6 * HOUR - T);
    assert_eq!(chain.active(), active + T);
    assert_eq!(chain.active(), chain.now() - chain.stopped());
    // The same as the empty block: the total, the clock, the owner's row.
    assert_eq!((chain.stopped(), chain.active()), (control.stopped(), control.active()));
    assert_eq!(chain.mine(), control.mine());
    same_but_the_version(&chain, &control);
    // The switch block is dated on the chain's time, like any activation.
    let activated: Value = serde_json::from_slice(&chain.row(&upgrade::activated_key(5)).unwrap()).unwrap();
    assert_eq!(activated["elapsed_micros"], chain.now().to_string());
    // Of the wait, half an hour of blocks and five minutes of each of the
    // two gaps have run: not over.
    assert_eq!(chain.active(), asked + 30 * MINUTE + 2 * T);
    assert!(chain.refused(SECOND, &[chain.execute(1)]).contains(NOT_OVER));
    assert!(!chain.admits(&chain.execute(1)));
    // The block after the switch block counts nothing again.
    chain.block(MINUTE, vec![]);
    assert_eq!(chain.stopped(), stopped + 6 * HOUR - T);
    assert_eq!(chain.active(), active + T + MINUTE);
    // Due exactly when the chain has run for the whole wait.
    chain.run(ready - chain.active() - MINUTE);
    assert!(chain.refused(MINUTE - 1, &[chain.execute(1)]).contains(NOT_OVER));
    let shop = chain.account(SHOP).balance;
    chain.block(MINUTE, vec![chain.execute(1)]);
    assert_eq!(chain.active(), ready);
    assert!(chain.mine().pending_payments.is_empty());
    assert_eq!(chain.account(SHOP).balance, shop + 3 * SECOND);
    assert_eq!((chain.version(), chain.stopped()), (5, stopped + 6 * HOUR - T));
    // The recount counts the stops again from the block times: the stand
    // before the switch block once.
    chain.engine.audit().unwrap();
    // A later start of the fix release on these data goes on.
    let mut chain = chain.reopen(fix(&network, h));
    assert_eq!(chain.stopped(), stopped + 6 * HOUR - T);
    chain.block(MINUTE, vec![]);
    chain.engine.audit().unwrap();
}

/// A stop in the middle of a block on a network whose waits survive a
/// stop. Block `S` is decided two hours after its parent and fails on
/// every node; the chain stands eight hours while a fix release that names
/// `S` is built. The repaired block keeps its own date, so it counts its
/// own gap (an hour and 55 minutes of stop), and the block after it counts
/// the stand (seven hours and 55 minutes): each once. A freeze placed
/// before `S` ends exactly when the chain has run for it.
#[test]
fn a_repaired_block_and_the_stand_after_it_are_each_counted_once() {
    let mut control = Chain::secured(safe(), old());
    control.block(SECOND, vec![control.freeze()]);
    let until = control.mine().frozen_until_elapsed_micros;
    assert_eq!(until, control.active() + FREEZE);
    control.run(30 * MINUTE);
    let (s, parent) = (control.height() + 1, control.root());
    let network = control.network.clone();
    let (stopped, active) = (control.stopped(), control.active());
    // The fix release on another node with the same data.
    let mut fixed = Chain::replay(safe(), repair(&network, s, sha(s), parent), &control.log);
    assert_eq!(fixed.root(), parent);
    // Block S: two payments of validators' owners.
    let txs =vec![fixed.transfer(0, 1, SHOP, 1_000), fixed.transfer(1, 2, SHOP, 2_000)];
    assert_eq!(fixed.decided(2 * HOUR, txs.clone()), switched());
    control.decided(2 * HOUR, txs);
    assert_eq!((fixed.height(), fixed.version()), (s, 5));
    // Its own gap: five minutes count, the rest is a stop.
    assert_eq!(fixed.stopped(), stopped + 2 * HOUR - T);
    assert_eq!(fixed.active(), active + T);
    assert_eq!((fixed.stopped(), fixed.active()), (control.stopped(), control.active()));
    same_but_the_version(&fixed, &control);
    fixed.engine.audit().unwrap();
    // The stand while the fix release was built: the block after S comes
    // eight hours after it, and counts all but five minutes of them as a
    // stop.
    fixed.block(8 * HOUR, vec![]);
    assert_eq!(fixed.stopped(), stopped + 10 * HOUR - 2 * T);
    assert_eq!(fixed.active(), active + 2 * T);
    // Forty minutes of the freeze have run: still frozen.
    assert_eq!(fixed.active(), until - FREEZE + 30 * MINUTE + 2 * T);
    assert!(fixed.refused(SECOND, &[fixed.pay(1_000)]).contains(FROZEN));
    fixed.block(MINUTE, vec![]);
    assert_eq!(fixed.stopped(), stopped + 10 * HOUR - 2 * T);
    // It ends to the microsecond.
    fixed.run(until - fixed.active() - MINUTE);
    assert!(fixed.refused(MINUTE - 1, &[fixed.pay(1_000)]).contains(FROZEN));
    fixed.block(MINUTE, vec![fixed.pay(1_000)]);
    assert_eq!(fixed.active(), until);
    assert_eq!(fixed.version(), 5);
    fixed.engine.audit().unwrap();
}

/// The switch block and a repaired block on a network with the three
/// settings the production profile requires. Before the switch: a stop, an
/// account registered protected (kind 45), with the row of its name's
/// skeleton, and an account that adopted the rules with a payment that
/// waits. The switch block leaves the rows an empty block leaves, with the
/// version; the repaired block, which holds a registration of kind 45, a
/// request of a payment above the limit and a transfer, leaves the rows the
/// same block leaves under the old rules, with the version. The supply rule
/// holds at every block, and the recount passes after each.
#[test]
fn a_switch_block_and_a_repaired_block_keep_the_supply_and_the_recount_with_the_three_settings() {
    let network = safe().network_id().unwrap();
    // The switch at an agreed height.
    let mut chain = Chain::secured(safe(), old());
    let first = setup(&network, 201, 70);
    chain.block(SECOND, vec![chain.sponsor(201, "carol", &first)]);
    chain.block(SECOND, vec![]);
    let id = chain.meta().next_account_id;
    chain.block(2 * HOUR, vec![register_tx(&network, 201, "carol", &first), chain.request(3 * SECOND)]);
    assert_eq!(chain.account(id).name, "carol");
    assert_eq!(chain.row(&names::key(&names::skeleton("carol"))), Some(serde_json::to_vec("carol").unwrap()));
    assert_eq!(chain.security(id).unwrap().allowance_elapsed_micros, chain.active());
    assert_eq!(chain.stopped(), 2 * HOUR - T);
    chain.engine.audit().unwrap();
    let h = chain.height();
    let mut control = Chain::replay(safe(), old(), &chain.log);
    let mut chain = chain.reopen(fix(&network, h));
    assert_eq!(chain.decided(5 * HOUR, vec![switch(&network)]), switched());
    control.decided(5 * HOUR, vec![]);
    assert_eq!(chain.stopped(), 7 * HOUR - 2 * T);
    same_but_the_version(&chain, &control);
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 1);
    assert_eq!(audit.account_count, chain.meta().account_count);
    // Under version 5 the chain goes on, with all three rules.
    chain.block(SECOND, vec![chain.transfer(0, 1, SHOP, 1_000)]);
    chain.engine.audit().unwrap();

    // A repaired block.
    let mut control = Chain::secured(safe(), old());
    let second = setup(&network, 202, 80);
    control.block(SECOND, vec![control.sponsor(202, "dave", &second)]);
    control.block(SECOND, vec![]);
    let (s, parent) = (control.height() + 1, control.root());
    let mut fixed = Chain::replay(safe(), repair(&network, s, sha(s), parent), &control.log);
    let id = fixed.meta().next_account_id;
    let txs = vec![register_tx(&network, 202, "dave", &second), fixed.request(3 * SECOND), fixed.transfer(2, 3, SHOP, 500)];
    assert_eq!(fixed.decided(3 * HOUR, txs.clone()), switched());
    control.decided(3 * HOUR, txs);
    assert_eq!((fixed.height(), fixed.version(), fixed.stopped()), (s, 5, 3 * HOUR - T));
    // The block's transactions were executed: the account, its skeleton,
    // its first security row on the clock of the waits, the payment that
    // waits on that clock.
    assert_eq!(fixed.account(id).name, "dave");
    assert_eq!(fixed.row(&names::key(&names::skeleton("dave"))), Some(serde_json::to_vec("dave").unwrap()));
    assert_eq!(fixed.row(&name_key("dave")), Some(serde_json::to_vec(&id.to_string()).unwrap()));
    assert!(fixed.row(&commit_key(202)).is_none());
    assert_eq!(fixed.security(id).unwrap().allowance_elapsed_micros, fixed.active());
    assert_ne!(fixed.active(), fixed.now());
    assert_eq!(fixed.mine().pending_payments[0].ready_elapsed_micros, fixed.active() + DELAY);
    same_but_the_version(&fixed, &control);
    let audit = fixed.engine.audit().unwrap();
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 1);
    control.engine.audit().unwrap();
    fixed.block(4 * HOUR, vec![fixed.transfer(0, 1, SHOP, 1_000)]);
    assert_eq!(fixed.stopped(), 7 * HOUR - 2 * T);
    fixed.engine.audit().unwrap();
}

/// A registration of kind 45 in the block before a switch, offered with
/// the switch block, and in the block after it.
///
/// - In block `H`, under the old rules, it creates its account protected.
/// - At `H + 1` the proposer proposes the switch alone; a block with the
///   registration beside the switch, before it or instead of it is not
///   executed. The registration is not used up: its commitment stays, and
///   the mempool keeps admitting it, before the switch block and after it.
/// - In block `H + 2`, under version 5, it creates its account protected,
///   with its first security row dated on the clock of the waits, which the
///   stand before the switch block held back.
#[test]
fn a_protected_registration_before_beside_and_after_the_switch() {
    let network = safe().network_id().unwrap();
    let mut chain = Chain::secured(safe(), old());
    let (a, b, c) = (setup(&network, 201, 70), setup(&network, 202, 80), setup(&network, 203, 90));
    chain.block(SECOND, vec![chain.sponsor(201, "anna", &a)]);
    chain.block(SECOND, vec![chain.sponsor(202, "bert", &b)]);
    chain.block(SECOND, vec![chain.sponsor(203, "cleo", &c)]);
    chain.block(SECOND, vec![]);
    let (register_a, register_b, register_c) = (register_tx(&network, 201, "anna", &a), register_tx(&network, 202, "bert", &b), register_tx(&network, 203, "cleo", &c));
    // Block H: the last under the old rules.
    let first = chain.meta().next_account_id;
    chain.block(SECOND, vec![register_a.clone()]);
    let h = chain.height();
    assert_eq!(chain.account(first).name, "anna");
    assert_eq!(chain.security(first).unwrap().allowance_elapsed_micros, chain.active());
    let mut chain = chain.reopen(fix(&network, h));
    // The mempool judges on the head and admits the registrations; the
    // proposer of the switch block takes none of them.
    assert!(chain.admits(&register_b) && chain.admits(&register_c));
    let mempool = vec![register_b.clone(), register_c.clone()];
    assert_eq!(chain.proposes(3 * HOUR, &mempool), vec![switch(&network)]);
    for (name, txs) in [
        ("the switch and a registration", vec![switch(&network), register_b.clone()]),
        ("a registration and the switch", vec![register_b.clone(), switch(&network)]),
        ("a registration alone", vec![register_b.clone()]),
        ("the registration of the block before, again", vec![register_a.clone()]),
    ] {
        let error = chain.refused(3 * HOUR, &txs);
        assert!(error.contains(ALONE), "{name}: {error}");
    }
    assert_eq!(chain.decided(3 * HOUR, vec![switch(&network)]), switched());
    assert_eq!(chain.version(), 5);
    assert_eq!(chain.meta().next_account_id, first + 1);
    assert!(chain.row(&commit_key(202)).is_some() && chain.row(&commit_key(203)).is_some());
    // After the switch: still admitted, and executed in the next block.
    assert!(chain.admits(&register_b) && chain.admits(&register_c));
    assert!(!chain.admits(&register_a));
    chain.block(SECOND, vec![register_b, register_c]);
    for (id, name) in [(first + 1, "bert"), (first + 2, "cleo")] {
        assert_eq!(chain.account(id).name, name);
        assert_eq!(chain.row(&names::key(&names::skeleton(name))), Some(serde_json::to_vec(name).unwrap()));
        let row = chain.security(id).expect("protected from its first block");
        assert_eq!(row.allowance_elapsed_micros, chain.active());
    }
    assert_eq!(chain.stopped(), 3 * HOUR - T);
    assert_eq!(chain.now() - chain.active(), 3 * HOUR - T);
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 3);
}
