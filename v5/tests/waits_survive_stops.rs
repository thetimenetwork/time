//! Waits that survive a stop (`waits_survive_stops` in the genesis).
//!
//! The account security rules compare what waits with a clock. Without the
//! setting that clock is the chain's time, and a chain that stops for a day
//! comes back a day later: every wait has run out while no owner could send
//! a cancellation. With the setting the rules read the active clock: the
//! chain's time minus the total of all stops, where a stop is the part of a
//! gap between a block and its parent beyond five minutes
//! (`security::STOP_THRESHOLD_MICROS`, the clock's own threshold; the
//! upgrade rule keeps its hour, `upgrade::Params::max_gap`). The total is
//! one number in the metadata row, `stopped_micros`.
//!
//! Here: how a network chooses the rule; the number, block by block; a
//! waiting payment, a freeze, a raise of the limit, a replacement of the
//! keys and its claim window, each across a long gap and across a short one;
//! the daily allowance; several stops; a stop in the first blocks; what a
//! key signs (its date stays in the chain's time); what somebody who can
//! stop the chain still gets; the recount; and a node through a restart and
//! state sync. `safety_unchanged.rs` holds the roots of a network without
//! the setting, recorded before the rule was built.
mod common;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::app::App;
use timecurrency_v5::engine::{Audit, Engine, Meta, account_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::rules::{self, Versions};
use timecurrency_v5::security::{self, Role, Security};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::statesync::NodeOptions;
use timecurrency_v5::store::Store;
use timecurrency_v5::transport::BatchCheck;
use timecurrency_v5::upgrade;

const SECOND: u64 = 1_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 3_600 * SECOND;
const DAY: u64 = 24 * HOUR;
/// What an action costs on these networks.
const FEE: u64 = ledger::FEE_MICROS;

/// The account under test (its protocol-4 key is seed 6) and its keys.
const ME: u64 = 5;
const OLD: u8 = 6;
const SIGNIN: u8 = 60;
const SPEND: u8 = 61;
const SHEET: u8 = 62;
const PHRASE: u8 = 63;
const FRIEND: u8 = 64;
const NEW_SPEND: u8 = 65;
const SHOP: u64 = 7;
/// Its settings. The waits are far longer than the five minutes of a gap
/// that count.
const LIMIT: u64 = 480_000;
const DELAY: u64 = 3 * HOUR;
const FREEZE: u64 = 4 * HOUR;
/// The gap above which the rest of a gap is a stop: five minutes.
const T: u64 = 5 * MINUTE;

/// The test genesis with the rule.
fn surviving() -> Genesis {
    let mut genesis = genesis_v5();
    genesis.waits_survive_stops = true;
    genesis
}
/// The gap above which the rest of a gap is a stop: the clock's own
/// threshold, five minutes in both profiles. The upgrade rule keeps its
/// hour: the two thresholds are not one any more.
fn threshold() -> u64 {
    let lab = security::stop_threshold(pos::Profile::Laboratory);
    assert_eq!(lab, security::stop_threshold(pos::Profile::Production));
    assert_eq!(lab, security::STOP_THRESHOLD_MICROS);
    assert_eq!(lab, T);
    for profile in [pos::Profile::Laboratory, pos::Profile::Production] {
        assert_eq!(upgrade::Params::of(profile).max_gap, HOUR);
    }
    lab
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
fn stays(seed: u8, role: Role) -> Value {
    json!({"public_key": pk(seed), "role": role_name(role)})
}
fn policy() -> Value {
    json!({"threshold": "2", "daily_limit_micros": LIMIT.to_string(), "delay_seconds": (DELAY / SECOND).to_string(), "freeze_seconds": (FREEZE / SECOND).to_string()})
}
fn signed(network: &str, from: u64, nonce: u64, auth_epoch: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
    ledger::sign_action(
        &Action {
            network_id: network.into(),
            from,
            nonce,
            auth_epoch,
            public_key: pk(signer),
            payload,
            signature: vec![],
        },
        &key(signer),
    )
    .unwrap()
}
/// A key that joins the set of account `account`: it carries its holder's
/// acceptance of the role.
fn joins(network: &str, account: u64, seed: u8, role: Role) -> Value {
    let proof = key(seed).sign(&security::key_message(network, account, role, &pk(seed)).unwrap());
    json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
}
/// The action with which the account under test adopts the rules: one
/// sign-in key, one spend key, three recovery keys, two proofs.
fn secure_tx(network: &str, row: &Account) -> Vec<u8> {
    let keys = sorted(vec![
        joins(network, ME, SIGNIN, Role::Signin),
        joins(network, ME, SPEND, Role::Spend),
        joins(network, ME, SHEET, Role::Recover),
        joins(network, ME, PHRASE, Role::Recover),
        joins(network, ME, FRIEND, Role::Recover),
    ]);
    timecurrency_v5::wire::sign(network, ME, row.nonce + 1, row.auth_epoch, security::SECURE, &json!({"keys": keys, "policy": policy()}), &key(OLD)).unwrap()
}
/// An action of the account under test that takes its next nonce.
fn act_tx(network: &str, row: &Account, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    timecurrency_v5::wire::sign(network, ME, row.nonce + 1, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
}
/// A protective action of the account under test: no nonce, no authority
/// epoch.
fn guard_tx(network: &str, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    timecurrency_v5::wire::sign(network, ME, 0, 0, kind, &payload, &key(signer)).unwrap()
}
fn freeze_tx(network: &str, mine: &Security, signer: u8, expires: u64) -> Vec<u8> {
    guard_tx(network, signer, security::FREEZE, json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": expires.to_string()}))
}
/// A root operation of the account under test, approved by `approvers` and
/// handed in by `sender`. The approvals are void after `expires`.
fn root_tx(network: &str, mine: &Security, sender: u8, approvers: &[u8], operation: Value, expires: u64) -> Vec<u8> {
    let mut keys: Vec<(String, u8)> = approvers.iter().map(|seed| (pk(*seed), *seed)).collect();
    keys.sort();
    let names: Vec<&str> = keys.iter().map(|(public_key, _)| public_key.as_str()).collect();
    let message = security::root_message(network, ME, mine.version, expires, &operation, &names).unwrap();
    let approvals: Vec<Value> = keys
        .iter()
        .map(|(public_key, seed)| json!({"public_key": public_key, "signature": hex::encode(key(*seed).sign(&message).to_bytes())}))
        .collect();
    guard_tx(network, sender, security::ROOT, json!({"op": operation, "expires_elapsed_micros": expires.to_string(), "approvals": approvals}))
}
/// A new set of keys that differs from the first one in its spend key.
fn new_spend_key(network: &str, seed: u8) -> Value {
    json!({"type": "replace", "policy": policy(), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin),
        joins(network, ME, seed, Role::Spend),
        stays(SHEET, Role::Recover),
        stays(PHRASE, Role::Recover),
        stays(FRIEND, Role::Recover),
    ])})
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        Self::open(genesis, None)
    }
    /// A chain on a program that implements `versions`, or the versions of
    /// this build.
    fn open(genesis: Genesis, versions: Option<Versions>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        if let Some(versions) = versions {
            engine = engine.implementing(versions);
        }
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network }
    }
    /// A chain on which the validators' owners have earned and the account
    /// under test holds twenty seconds and has adopted the rules.
    fn secured(genesis: Genesis) -> Self {
        let mut chain = Self::new(genesis);
        for _ in 0..20 {
            chain.block(MINUTE, vec![]);
        }
        chain.block(SECOND, (0..4u64).map(|owner| chain.transfer(owner, owner as u8 + 1, ME, 5 * SECOND)).collect());
        chain.block(SECOND, vec![secure_tx(&chain.network, &chain.account(ME))]);
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
    fn stopped(&self) -> Option<u64> {
        self.meta().stopped_micros
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    fn mine(&self) -> Security {
        serde_json::from_slice(&self.row(&security::key(ME)).expect("the account has adopted the rules")).unwrap()
    }
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        signed(&self.network, from, row.nonce + 1, row.auth_epoch, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn pay(&self, amount: u64) -> Vec<u8> {
        self.transfer(ME, SPEND, SHOP, amount)
    }
    fn act(&self, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        act_tx(&self.network, &self.account(ME), signer, kind, payload)
    }
    fn request(&self, amount: u64) -> Vec<u8> {
        self.act(SPEND, security::PAYMENT, json!({"type": "request", "to": SHOP.to_string(), "amount": amount.to_string()}))
    }
    fn execute(&self, id: u64) -> Vec<u8> {
        self.act(SPEND, security::PAYMENT, json!({"type": "execute", "id": id.to_string()}))
    }
    fn freeze(&self, signer: u8) -> Vec<u8> {
        freeze_tx(&self.network, &self.mine(), signer, self.now() + 600 * SECOND)
    }
    fn root(&self, sender: u8, approvers: &[u8], operation: Value) -> Vec<u8> {
        root_tx(&self.network, &self.mine(), sender, approvers, operation, self.now() + 3_600 * SECOND)
    }
    /// The two recovery keys on the sheet and in the passphrase ask for a
    /// new spend key.
    fn replace(&self, new_spend: u8) -> Vec<u8> {
        self.root(SHEET, &[SHEET, PHRASE], new_spend_key(&self.network, new_spend))
    }
    fn finalize(&self, signer: u8) -> Vec<u8> {
        guard_tx(&self.network, signer, security::FINALIZE, json!({"version": self.mine().version.to_string()}))
    }
    fn cancel_payment(&self, signer: u8, id: u64) -> Vec<u8> {
        guard_tx(&self.network, signer, security::CANCEL, json!({"type": "payment", "id": id.to_string()}))
    }
    /// Height, time, signers and hash of a block `delta` after the last one.
    fn next(&self, delta: u64) -> (i64, i64, Vec<String>, [u8; 32]) {
        let meta = self.meta();
        let signers = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        (meta.height + 1, meta.time_micros + delta as i64, signers, sha(meta.height as u64 + 1))
    }
    /// A block dated `delta` after the last one in which every action is
    /// accepted: as a proposer builds it, as a validator checks it, and with
    /// the fast paths off.
    #[track_caller]
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let (height, time, signers, hash) = self.next(delta);
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &txs, &signers, 1 << 20, hash).unwrap();
        if kept.len() != txs.len() {
            let reasons: Vec<String> = txs
                .iter()
                .map(|tx| match self.engine.prepare(height, time, &[tx], &signers, hash) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("an action was left out of block {height}: {reasons:?}");
        }
        let strict = self.engine.prepare(height, time, &kept, &signers, hash).unwrap();
        let reference = self.engine.prepare_reference(height, time, &kept, &signers, hash).unwrap();
        assert_eq!(strict.root, proposed.root, "validator and proposer disagree at {height}");
        assert_eq!(reference.root, proposed.root, "fast path and reference disagree at {height}");
        self.engine.commit(proposed, hash).unwrap();
        let meta = self.meta();
        assert_eq!(
            meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total,
            meta.elapsed_micros().unwrap(),
            "supply rule"
        );
    }
    /// The chain runs for `micros`: blocks a minute apart, none of them a
    /// stop.
    fn run(&mut self, micros: u64) {
        assert_eq!(micros % MINUTE, 0);
        for _ in 0..micros / MINUTE {
            self.block(MINUTE, vec![]);
        }
    }
    /// The chain stands still for `micros` and then makes one empty block.
    fn stop(&mut self, micros: u64) {
        self.block(micros, vec![]);
    }
    /// An empty block dated `delta` after the last one, as a validator
    /// executes it, without the proposer's and the reference execution: for
    /// the long runs of blocks a wait of days needs at five minutes a block.
    fn quiet(&mut self, delta: u64) {
        let (height, time, signers, hash) = self.next(delta);
        let none: [Vec<u8>; 0] = [];
        let prepared = self.engine.prepare(height, time, &none, &signers, hash).unwrap();
        self.engine.commit(prepared, hash).unwrap();
    }
    /// Why `tx` is refused in a block dated `delta` after the last one: by a
    /// validator, by the reference path, and by a proposer, whose block is
    /// the block without it. Nothing is committed.
    #[track_caller]
    fn refused_after(&self, delta: u64, tx: &[u8]) -> String {
        let (height, time, signers, hash) = self.next(delta);
        let reason = match self.engine.prepare(height, time, &[tx], &signers, hash) {
            Ok(_) => panic!("the action was accepted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(self.engine.prepare_reference(height, time, &[tx], &signers, hash).is_err(), "the reference path accepted it");
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &[tx], &signers, 1 << 20, hash).unwrap();
        assert!(kept.is_empty(), "a proposer kept it");
        let none: [Vec<u8>; 0] = [];
        assert_eq!(proposed.root, self.engine.prepare(height, time, &none, &signers, hash).unwrap().root);
        reason
    }
    /// Why `tx` is refused in the next block, a second later; the mempool,
    /// which judges on the last block, refuses it for the same reason.
    #[track_caller]
    fn refused(&self, tx: &[u8]) -> String {
        let reason = self.refused_after(SECOND, tx);
        let admission = self.engine.check_state().unwrap().admit(tx, SigStatus::Unknown);
        assert_eq!(format!("{:#}", admission.expect_err("the mempool admitted it")), reason, "the mempool's reason");
        reason
    }
    /// Whether a validator accepts `tx` in a block dated `delta` after the
    /// last one. Nothing is committed.
    fn accepted_after(&self, delta: u64, tx: &[u8]) -> bool {
        let (height, time, signers, hash) = self.next(delta);
        self.engine.prepare(height, time, &[tx], &signers, hash).is_ok()
    }
}

const NOT_OVER: &str = "the waiting period is not over";
const FROZEN: &str = "account is frozen";

#[test]
fn a_network_without_the_setting_has_no_such_number_and_is_unchanged() {
    let genesis = genesis_v5();
    assert!(!genesis.waits_survive_stops);
    let text = serde_json::to_string(&genesis).unwrap();
    assert!(!text.contains("waits_survive_stops"), "{text}");
    // The id the protocol-4 engine computes for the same genesis.
    assert_eq!(genesis.network_id().unwrap(), network_id(), "protocol-4 network id");
    let mut chain = Chain::secured(genesis);
    chain.stop(5 * HOUR);
    assert_eq!(chain.stopped(), None);
    assert!(!String::from_utf8_lossy(&chain.row(b"meta").unwrap()).contains("stopped_micros"));
    // The clock of the account security rules is the chain's time.
    assert_eq!(chain.active(), chain.now());
    // And a stop uses up a wait, as it always did: the payment is asked for,
    // the chain stops for five hours, and the payment goes through.
    chain.block(SECOND, vec![chain.request(3 * SECOND)]);
    assert!(chain.refused(&chain.execute(1)).contains(NOT_OVER));
    chain.stop(5 * HOUR);
    chain.block(SECOND, vec![chain.execute(1)]);
    assert!(chain.mine().pending_payments.is_empty());
    chain.engine.audit().unwrap();
}

#[test]
fn the_setting_is_written_one_way_after_the_rule_for_names() {
    let parse = |value: Value| {
        let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
        genesis["waits_survive_stops"] = value;
        serde_json::from_value::<Genesis>(genesis)
    };
    assert!(parse(json!(true)).unwrap().waits_survive_stops);
    // Not using the rule is written by leaving the field out.
    for refused in [json!(false), json!("true"), json!(1), json!(null), json!({})] {
        assert!(parse(refused.clone()).is_err(), "{refused}");
    }
    // Tools that build a genesis compute the network id from their own
    // encoding, so the position of the field is part of the format: after
    // `distinct_names`.
    let mut genesis = genesis_v5();
    genesis.validators = (0..7)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.fees_to_validators_ppm = 1_000_000;
    genesis.fee_micros = 10;
    genesis.all_new_time_to_validators = true;
    genesis.stake_handover = true;
    genesis.distinct_names = true;
    let without = serde_json::to_string(&genesis).unwrap();
    assert!(without.ends_with(r#""distinct_names":true}"#), "{without}");
    genesis.waits_survive_stops = true;
    let with = serde_json::to_string(&genesis).unwrap();
    assert_eq!(with, format!("{},\"waits_survive_stops\":true}}", without.strip_suffix('}').unwrap()));
    let parsed: Genesis = serde_json::from_str(&with).unwrap();
    assert_eq!(parsed.network_id().unwrap(), genesis.network_id().unwrap());
    // Alone, it follows the protocol-4 fields directly.
    let plain = serde_json::to_string(&genesis_v5()).unwrap();
    assert_eq!(serde_json::to_string(&surviving()).unwrap(), format!("{},\"waits_survive_stops\":true}}", plain.strip_suffix('}').unwrap()));
    // The setting is part of the network id.
    assert_ne!(surviving().network_id().unwrap(), network_id());
}

#[test]
fn the_total_of_stops_is_in_the_metadata_from_the_first_block() {
    let t = threshold();
    let mut chain = Chain::new(surviving());
    assert_eq!(chain.stopped(), Some(0));
    assert!(String::from_utf8_lossy(&chain.row(b"meta").unwrap()).ends_with(r#","stopped_micros":"0"}"#));
    // Gaps up to five minutes count in full: no stop.
    let mut total = 0;
    for (gap, stop) in [
        (0, 0),
        (SECOND, 0),
        (MINUTE, 0),
        (t - 1, 0),
        (t, 0),
        // From there on, what goes beyond the five minutes is a stop.
        (t + 1, 1),
        (SECOND, 0),
        (2 * t, t),
        // An hour, the gap after which the upgrade rule cancels a plan, is
        // a stop of 55 minutes on this clock, and an hour and a microsecond
        // one of 55 minutes and a microsecond.
        (HOUR, HOUR - t),
        (HOUR + 1, HOUR + 1 - t),
        (t, 0),
        (10 * HOUR, 10 * HOUR - t),
        (MINUTE, 0),
        (3 * DAY, 3 * DAY - t),
    ] {
        let (before, active) = (chain.now(), chain.active());
        chain.block(gap, vec![]);
        total += stop;
        assert_eq!(chain.stopped(), Some(total), "after a gap of {gap}");
        assert_eq!(chain.now(), before + gap);
        // The active clock moves by the gap, and by five minutes at most.
        assert_eq!(chain.active(), active + gap.min(t), "after a gap of {gap}");
        assert_eq!(chain.active(), chain.now() - total);
    }
    assert_eq!(total, 1 + t + (HOUR - t) + (HOUR + 1 - t) + (10 * HOUR - t) + (3 * DAY - t));
    assert_eq!(total, 3 * DAY + 12 * HOUR + 2 - 3 * t);
    let meta: Value = serde_json::from_slice(&chain.row(b"meta").unwrap()).unwrap();
    assert_eq!(meta["stopped_micros"], total.to_string());
    chain.engine.audit().unwrap();
}

#[test]
fn a_waiting_payment_does_not_come_due_during_a_stop() {
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.request(3 * SECOND)]);
    let asked = chain.active();
    let ready = chain.mine().pending_payments[0].ready_elapsed_micros;
    assert_eq!(ready, asked + DELAY);
    // Half an hour of blocks, then a gap of five minutes: neither is a
    // stop, and both count.
    chain.run(30 * MINUTE);
    chain.block(T, vec![]);
    assert_eq!((chain.stopped(), chain.active()), (Some(0), asked + 30 * MINUTE + T));
    assert!(chain.refused(&chain.execute(1)).contains(NOT_OVER));
    // The chain stops for ten hours. Of those, five minutes count.
    chain.stop(10 * HOUR);
    assert_eq!((chain.stopped(), chain.active()), (Some(10 * HOUR - T), asked + 30 * MINUTE + 2 * T));
    assert!(chain.now() > ready, "by the chain's time the wait would be over");
    assert!(chain.refused(&chain.execute(1)).contains(NOT_OVER));
    assert_eq!(chain.mine().pending_payments.len(), 1);
    // The owner still has the two hours and twenty minutes that were left,
    // and uses them or not: the payment is due exactly when the chain has
    // run for the whole wait.
    assert_eq!(ready - chain.active(), DELAY - 30 * MINUTE - 2 * T);
    chain.run(ready - chain.active() - MINUTE);
    assert!(chain.refused_after(MINUTE - 1, &chain.execute(1)).contains(NOT_OVER));
    assert!(chain.accepted_after(MINUTE, &chain.execute(1)));
    let (shop, mine) = (chain.account(SHOP).balance, chain.account(ME).balance);
    chain.block(MINUTE, vec![chain.execute(1)]);
    assert_eq!(chain.active(), ready);
    assert_eq!(chain.account(SHOP).balance, shop + 3 * SECOND);
    assert_eq!(chain.account(ME).balance, mine - 3 * SECOND - FEE);
    chain.engine.audit().unwrap();
}

#[test]
fn a_freeze_does_not_run_out_during_a_stop() {
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.freeze(SHEET)]);
    let until = chain.mine().frozen_until_elapsed_micros;
    assert_eq!(until, chain.active() + FREEZE);
    // A short gap, then a stop of twelve hours: three times the freeze.
    chain.block(T, vec![]);
    chain.stop(12 * HOUR);
    assert!(chain.now() > until);
    assert_eq!(chain.active(), until - FREEZE + 2 * T);
    assert!(chain.refused(&chain.pay(1_000)).contains(FROZEN));
    // The freeze is not fresh any more, but more than half of it is left:
    // the key that placed it cannot place another one yet.
    assert!(chain.refused(&chain.freeze(SHEET)).contains("account is already frozen"));
    // Three hours and fifty minutes of chain later it ends, to the
    // microsecond.
    assert_eq!(until - chain.active(), 3 * HOUR + 50 * MINUTE);
    chain.run(until - chain.active() - MINUTE);
    assert!(chain.refused_after(MINUTE - 1, &chain.pay(1_000)).contains(FROZEN));
    chain.block(MINUTE, vec![chain.pay(1_000)]);
    assert_eq!(chain.active(), until);
    chain.engine.audit().unwrap();
}

#[test]
fn a_replacement_of_the_keys_neither_comes_due_nor_lapses_during_a_stop() {
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.replace(NEW_SPEND)]);
    let pending = chain.mine().pending_root.expect("a replacement waits");
    let asked = chain.active();
    assert_eq!(pending.ready_elapsed_micros, asked + DELAY);
    assert_eq!(pending.expires_elapsed_micros, asked + DELAY + 7 * DAY);
    // A stop of a day, straight after: the new keys cannot take over, and
    // the account stays frozen for its spend key.
    chain.stop(DAY);
    assert!(chain.now() > pending.ready_elapsed_micros);
    assert!(chain.refused(&chain.finalize(NEW_SPEND)).contains(NOT_OVER));
    assert!(chain.refused(&chain.pay(1_000)).contains(FROZEN));
    // The owner, who holds the spend key and one recovery key, calls it off
    // after the stop exactly as before it.
    assert!(chain.accepted_after(SECOND, &chain.root(SPEND, &[SPEND, FRIEND], json!({"type": "cancel"}))));
    // Left alone, it is due after the two hours and 55 minutes of chain
    // that were missing.
    assert_eq!(pending.ready_elapsed_micros - chain.active(), DELAY - T);
    chain.run(DELAY - T - MINUTE);
    assert!(chain.refused_after(MINUTE - 1, &chain.finalize(NEW_SPEND)).contains(NOT_OVER));
    assert!(chain.accepted_after(MINUTE, &chain.finalize(NEW_SPEND)));
    chain.block(MINUTE, vec![]);
    // Now the claim window of seven days runs. A stop of ten days does not
    // use it up: the replacement is still there to be finished.
    chain.stop(10 * DAY);
    assert!(chain.now() > pending.expires_elapsed_micros);
    assert!(chain.mine().pending_root.is_some());
    assert!(chain.refused(&chain.pay(1_000)).contains(FROZEN));
    chain.block(SECOND, vec![chain.finalize(NEW_SPEND)]);
    assert!(chain.account(ME).devices.iter().any(|device| device.public_key == pk(NEW_SPEND)));
    assert!(chain.mine().pending_root.is_none());
    chain.engine.audit().unwrap();
}

#[test]
fn a_replacement_lapses_after_seven_days_of_chain_whatever_the_stops() {
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.replace(NEW_SPEND)]);
    let pending = chain.mine().pending_root.unwrap();
    // The wait of three hours and the seven days of the claim window are
    // 171 hours of chain: 2,052 blocks five minutes apart, none of them a
    // stop. They pass with a stop of two days in the middle, of which five
    // minutes count.
    assert_eq!(DELAY + 7 * DAY, 2_052 * T);
    for _ in 0..1_000 {
        chain.quiet(T);
    }
    chain.stop(2 * DAY);
    for _ in 0..1_050 {
        chain.quiet(T);
    }
    assert_eq!(chain.stopped(), Some(2 * DAY - T));
    assert_eq!(chain.active(), pending.expires_elapsed_micros - T);
    // The last moment of the window is still inside it; a second later the
    // replacement is gone.
    assert!(chain.accepted_after(T, &chain.finalize(NEW_SPEND)));
    chain.block(T, vec![]);
    assert_eq!(chain.active(), pending.expires_elapsed_micros);
    assert!(chain.refused_after(SECOND, &chain.finalize(NEW_SPEND)).contains("no replacement is waiting"));
    // The account is as it was, and its spend key pays again.
    chain.block(SECOND, vec![chain.pay(1_000)]);
    assert!(chain.mine().pending_root.is_none());
    assert!(chain.account(ME).devices.iter().all(|device| device.public_key != pk(NEW_SPEND)));
}

#[test]
fn a_raise_of_the_limit_and_the_allowance_wait_for_the_chain_too() {
    let mut chain = Chain::secured(surviving());
    // The spend key uses up the allowance of the day, then asks for a limit
    // ten times higher (item 1), which waits.
    let fee_and_all = LIMIT - 2 * FEE;
    chain.block(SECOND, vec![chain.pay(fee_and_all)]);
    chain.block(SECOND, vec![chain.act(SPEND, security::LIMIT, json!({"daily_limit_micros": (10 * LIMIT).to_string()}))]);
    let asked = chain.active();
    assert_eq!(chain.mine().pending_limit.as_ref().unwrap().ready_elapsed_micros, asked + DELAY);
    // Two days of stop. Without the rule the raise would be in force and
    // the allowance full. With it five minutes have passed: the limit is the
    // old one and a 288th of it has come back.
    chain.stop(2 * DAY);
    let level = |chain: &Chain| {
        let mut row = chain.mine();
        row.settle(chain.active());
        (row.policy.daily_limit_micros, row.level(chain.active()))
    };
    let (limit, left) = level(&chain);
    assert_eq!(limit, LIMIT);
    // (And the few microseconds that were left of the first day.)
    assert_eq!(DAY / T, 288);
    assert!((LIMIT / 288..LIMIT / 288 + 20).contains(&left), "{left}");
    assert!(chain.refused(&chain.pay(LIMIT / 2)).contains("over the daily limit"));
    // Any recovery key still cancels the raise: it was never in force.
    chain.block(SECOND, vec![guard_tx(&chain.network, FRIEND, security::CANCEL, json!({"type": "limit", "id": "1"}))]);
    assert!(chain.mine().pending_limit.is_none());
    assert_eq!(chain.mine().policy.daily_limit_micros, LIMIT);
}

#[test]
fn several_stops_add_up_and_a_wait_is_due_when_the_chain_has_run_for_it() {
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.request(SECOND)]);
    let ready = chain.mine().pending_payments[0].ready_elapsed_micros;
    let started = (chain.now(), chain.stopped().unwrap());
    // Three stops, of which five minutes each count, and what runs between
    // them: 60 + 5 + 55 + 5 + 52 minutes leave three minutes of the wait,
    // and the third stop's five minutes end it. Six days and more pass
    // meanwhile.
    chain.run(60 * MINUTE);
    chain.stop(2 * HOUR);
    chain.run(55 * MINUTE);
    chain.stop(5 * DAY);
    chain.run(52 * MINUTE);
    assert_eq!(ready - chain.active(), 3 * MINUTE);
    assert!(chain.refused(&chain.execute(1)).contains(NOT_OVER));
    chain.stop(DAY + 7 * HOUR);
    assert_eq!(chain.stopped().unwrap() - started.1, (2 * HOUR - T) + (5 * DAY - T) + (DAY + 7 * HOUR - T));
    assert_eq!(chain.active(), ready - 3 * MINUTE + T);
    assert!(chain.now() - started.0 > 6 * DAY);
    chain.block(SECOND, vec![chain.execute(1)]);
}

#[test]
fn a_stop_in_the_first_blocks_is_counted_like_any_other() {
    let mut chain = Chain::new(surviving());
    // The validators start six hours after the genesis time: the first
    // block carries the genesis time, the second their clocks.
    chain.block(0, vec![]);
    assert_eq!((chain.now(), chain.stopped()), (0, Some(0)));
    chain.block(6 * HOUR, vec![]);
    assert_eq!((chain.now(), chain.stopped(), chain.active()), (6 * HOUR, Some(6 * HOUR - T), T));
    // A chain whose very first block is dated late.
    let mut late = Chain::new(surviving());
    late.block(2 * DAY, vec![]);
    assert_eq!((late.now(), late.stopped(), late.active()), (2 * DAY, Some(2 * DAY - T), T));
    for chain in [&mut chain, &mut late] {
        chain.run(20 * MINUTE);
        chain.block(SECOND, (0..4u64).map(|owner| chain.transfer(owner, owner as u8 + 1, ME, 3 * SECOND)).collect());
        chain.block(SECOND, vec![secure_tx(&chain.network, &chain.account(ME))]);
        // The allowance is counted from the active clock.
        assert_eq!(chain.mine().allowance_elapsed_micros, chain.active());
        chain.block(SECOND, vec![chain.request(SECOND)]);
        assert_eq!(chain.mine().pending_payments[0].ready_elapsed_micros, chain.active() + DELAY);
        chain.engine.audit().unwrap();
    }
}

#[test]
fn what_a_key_signs_keeps_the_date_of_the_chains_time() {
    let mut chain = Chain::secured(surviving());
    chain.stop(3 * DAY);
    let (now, active) = (chain.now(), chain.active());
    assert_eq!(now - active, 3 * DAY - T);
    // A freeze dated ten minutes ahead on the active clock is long void by
    // the chain's time, and is refused.
    let stale = freeze_tx(&chain.network, &chain.mine(), SHEET, active + 600 * SECOND);
    assert!(chain.refused(&stale).contains("expired"));
    // Approvals given before the stop for an hour are void after it: a stop
    // never keeps a signature alive.
    let mut before = Chain::secured(surviving());
    let approved = before.root(SPEND, &[SPEND, SHEET], json!({"type": "pay", "to": SHOP.to_string(), "amount": SECOND.to_string()}));
    assert!(before.accepted_after(SECOND, &approved));
    before.stop(2 * HOUR);
    assert!(before.refused(&approved).contains("expired"));
    // Dated in the chain's time, both are accepted, and what they start is
    // counted on the active clock.
    chain.block(SECOND, vec![chain.freeze(SHEET)]);
    assert_eq!(chain.mine().frozen_until_elapsed_micros, chain.active() + FREEZE);
    chain.block(SECOND, vec![chain.root(SPEND, &[SPEND, SHEET], json!({"type": "unfreeze", "freezes": "1"}))]);
    chain.block(SECOND, vec![chain.root(SPEND, &[SPEND, SHEET], json!({"type": "pay", "to": SHOP.to_string(), "amount": SECOND.to_string()}))]);
    // A date too far ahead is judged by the chain's time as well.
    let far = freeze_tx(&chain.network, &chain.mine(), SHEET, chain.now() + 31 * DAY);
    assert!(chain.refused(&far).contains("dated too far ahead"));
}

/// Somebody holds the spend key and can stop the chain.
#[test]
fn a_thief_who_stops_the_chain_does_not_get_the_payment() {
    for (genesis, protected) in [(surviving(), true), (genesis_v5(), false)] {
        let mut chain = Chain::secured(genesis);
        // The thief asks for everything, then the chain stops for three days.
        chain.block(SECOND, vec![chain.request(15 * SECOND)]);
        chain.stop(3 * DAY);
        let theft = chain.execute(1);
        if !protected {
            // Without the rule the wait is over when the chain comes back,
            // and the first block can carry the theft.
            assert!(chain.accepted_after(SECOND, &theft));
            continue;
        }
        // With it the payment still waits, in the first block and for all
        // but five minutes of its three hours of chain: the owner's
        // cancellation, by any spend or recovery key, is in time.
        assert!(chain.refused(&theft).contains(NOT_OVER));
        chain.run(2 * HOUR + 50 * MINUTE);
        assert!(chain.refused(&theft).contains(NOT_OVER));
        chain.block(SECOND, vec![chain.cancel_payment(PHRASE, 1)]);
        assert!(chain.refused(&chain.execute(1)).contains("no such waiting payment"));
        assert_eq!(chain.account(SHOP).balance, 0);
    }
}

/// What the rule leaves, said as tests so that nobody takes it for more.
#[test]
fn what_a_stop_can_still_take_from_a_wait() {
    // 1. The first five minutes of a stop count. A wait with less than five
    //    minutes left is over after a stop of any length.
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.request(SECOND)]);
    chain.run(DELAY - 4 * MINUTE);
    assert!(chain.refused(&chain.execute(1)).contains(NOT_OVER));
    chain.stop(5 * HOUR);
    assert!(chain.accepted_after(SECOND, &chain.execute(1)));
    // 2. Gaps of up to five minutes count in full. A chain that makes one
    //    block every five minutes uses up a wait of three hours with 36
    //    blocks.
    let mut slow = Chain::secured(surviving());
    slow.block(SECOND, vec![slow.request(SECOND)]);
    for _ in 0..35 {
        slow.quiet(T);
    }
    assert!(slow.refused_after(T - 1, &slow.execute(1)).contains(NOT_OVER));
    assert!(slow.accepted_after(T, &slow.execute(1)));
    assert_eq!(slow.stopped(), Some(0));
    // 3. The other way round: blocks dated far apart do not make a wait
    //    last for ever. Each block moves the active clock by five minutes,
    //    so the same wait is over after 36 blocks dated a week apart, and
    //    after 36 blocks dated an hour apart.
    for gap in [7 * DAY, HOUR] {
        let mut apart = Chain::secured(surviving());
        apart.block(SECOND, vec![apart.request(SECOND)]);
        for _ in 0..35 {
            apart.quiet(gap);
        }
        assert!(apart.refused(&apart.execute(1)).contains(NOT_OVER));
        assert!(apart.accepted_after(gap, &apart.execute(1)));
    }
}

/// The threshold is the clock's own, to the microsecond: a gap of exactly
/// five minutes is no stop, and five minutes and a microsecond is a stop of
/// a microsecond that the wait does not count. A gap of an hour, after which
/// the upgrade rule cancels a plan, is a stop of 55 minutes here.
#[test]
fn the_threshold_of_the_clock_is_five_minutes_to_the_microsecond() {
    let t = threshold();
    let mut chain = Chain::secured(surviving());
    chain.block(SECOND, vec![chain.request(SECOND)]);
    let ready = chain.mine().pending_payments[0].ready_elapsed_micros;
    let before = chain.stopped().unwrap();
    chain.block(t, vec![]);
    assert_eq!(chain.stopped(), Some(before));
    chain.block(t + 1, vec![]);
    assert_eq!(chain.stopped(), Some(before + 1));
    // The wait has run ten minutes of its three hours.
    assert_eq!(ready - chain.active(), DELAY - 2 * t);
    chain.run(DELAY - 4 * t);
    chain.block(t - 1, vec![]);
    assert_eq!(chain.stopped(), Some(before + 1));
    assert_eq!(ready - chain.active(), t + 1);
    // A block five minutes later leaves a microsecond of the wait, and so
    // does a block five minutes and a microsecond later, or an hour later:
    // what goes beyond the five minutes does not count.
    for gap in [t, t + 1, t + 2, HOUR] {
        assert!(chain.refused_after(gap, &chain.execute(1)).contains(NOT_OVER), "after a gap of {gap}");
    }
    chain.block(HOUR, vec![]);
    assert_eq!(chain.stopped(), Some(before + 1 + HOUR - t));
    assert_eq!(ready - chain.active(), 1);
    // The microsecond that is left.
    chain.block(1, vec![chain.execute(1)]);
    assert_eq!(chain.active(), ready);
    assert!(chain.mine().pending_payments.is_empty());
    chain.engine.audit().unwrap();
}

/// The count of upgrade signals reads whether an owner account is frozen.
/// It reads it on the clock of the freeze.
#[test]
fn a_frozen_owners_upgrade_signal_is_judged_on_the_clock_of_the_freeze() {
    const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const OWNER: u64 = 0;
    let versions = || Versions::new([(4, rules::SPEC_4.to_string()), (5, SPEC_5.to_string())]).unwrap();
    let mut chain = Chain::open(surviving(), Some(versions()));
    // A stop of three hours before anything else. From here on the chain's
    // time is two hours and 55 minutes ahead of the active clock.
    chain.stop(3 * HOUR);
    chain.run(20 * MINUTE);
    assert_eq!(chain.now() - chain.active(), 3 * HOUR - T);
    // Validator owner 0 adopts the rules, with a freeze of two minutes.
    let network = chain.network.clone();
    let keys = sorted(vec![
        joins(&network, OWNER, SIGNIN, Role::Signin),
        joins(&network, OWNER, SPEND, Role::Spend),
        joins(&network, OWNER, SHEET, Role::Recover),
        joins(&network, OWNER, PHRASE, Role::Recover),
    ]);
    let short = json!({"threshold": "2", "daily_limit_micros": LIMIT.to_string(), "delay_seconds": "60", "freeze_seconds": "120"});
    let act = |chain: &Chain, owner: u64, signer: u8, kind: u8, payload: Value| {
        let row = chain.account(owner);
        timecurrency_v5::wire::sign(&network, owner, row.nonce + 1, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
    };
    chain.block(SECOND, vec![act(&chain, OWNER, 1, security::SECURE, json!({"keys": keys, "policy": short}))]);
    // It supports a plan that starts in half an hour, and is then frozen by
    // one of its recovery keys.
    let activate = chain.now() + 30 * MINUTE;
    let support = |chain: &Chain, owner: u64, signer: u8| {
        act(chain, owner, signer, upgrade::SIGNAL, json!({"activate_elapsed_micros": activate.to_string(), "spec": SPEC_5, "version": "5"}))
    };
    chain.block(SECOND, vec![support(&chain, OWNER, SPEND)]);
    let freeze = json!({"freezes": "0", "version": "1", "expires_elapsed_micros": (chain.now() + 600 * SECOND).to_string()});
    chain.block(SECOND, vec![timecurrency_v5::wire::sign(&network, OWNER, 0, 0, security::FREEZE, &freeze, &key(SHEET)).unwrap()]);
    let row: Security = serde_json::from_slice(&chain.row(&security::key(OWNER)).unwrap()).unwrap();
    // The freeze ends at a moment on the active clock. As a time of the
    // chain that moment is long past: read on the chain's time, the account
    // would not be frozen at all.
    assert_eq!(row.frozen_until_elapsed_micros, chain.active() + 120 * SECOND);
    assert!(row.frozen_until_elapsed_micros < chain.now());
    // The other three owners support the plan. With the frozen owner that
    // is three quarters, not the four fifths a plan needs: nothing is
    // scheduled. The frozen owner cannot signal again either.
    chain.block(SECOND, (1..4u64).map(|owner| support(&chain, owner, owner as u8 + 1)).collect());
    let plan = |chain: &Chain| chain.engine.upgrade_state().unwrap().and_then(|state| state.plan);
    assert!(plan(&chain).is_none(), "the signal of a frozen owner counted");
    assert!(chain.refused_after(SECOND, &act(&chain, OWNER, SPEND, upgrade::SIGNAL, json!({}))).contains(FROZEN));
    chain.block(MINUTE, vec![]);
    assert!(plan(&chain).is_none());
    // Two minutes of chain after the freeze was placed it ends, the signal
    // counts again, and the plan is scheduled by that block.
    chain.block(MINUTE, vec![]);
    assert_eq!(plan(&chain).expect("scheduled when the freeze ended").activate_elapsed_micros, activate);
}

/// The state of `chain` with its rows changed, in a store of its own: what
/// the recount says of it.
fn recount(chain: &Chain, change: impl FnOnce(&mut BTreeMap<Vec<u8>, Vec<u8>>)) -> anyhow::Result<Audit> {
    let mut rows = BTreeMap::new();
    chain
        .engine
        .version()
        .unwrap()
        .audit_verified(|_| {})
        .unwrap()
        .for_each_prefix(b"", |key, value| {
            rows.insert(key.to_vec(), value.to_vec());
            Ok(())
        })
        .unwrap();
    change(&mut rows);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.v5state")).unwrap();
    let meta = rows[b"meta".as_slice()].clone();
    let mut tree = store.prepare(None, 0, rows.into_iter().map(|(key, value)| (key, Some(value))).collect()).unwrap();
    tree.set_head_metadata(meta.clone(), [0; 32]).unwrap();
    store.commit(tree).unwrap();
    // A store counts its versions from zero: the same state is published
    // again until the version is the height its metadata names.
    for version in 1..=chain.meta().height as u64 {
        let base = store.current().unwrap().unwrap();
        let mut tree = store.prepare(Some(&base), version, vec![(b"meta".to_vec(), Some(meta.clone()))]).unwrap();
        tree.set_head_metadata(meta.clone(), [0; 32]).unwrap();
        store.commit(tree).unwrap();
    }
    Engine::open(store)?.audit()
}
/// The metadata row with another total of stops, or with none. The total is
/// the last field of the row, so it is cut off and written again.
fn meta_with(rows: &mut BTreeMap<Vec<u8>, Vec<u8>>, total: Option<u64>) {
    let text = String::from_utf8(rows[b"meta".as_slice()].clone()).unwrap();
    let cut = text.find(",\"stopped_micros\"").unwrap_or(text.len() - 1);
    let row = match total {
        Some(total) => format!("{},\"stopped_micros\":\"{total}\"}}", &text[..cut]),
        None => format!("{}}}", &text[..cut]),
    };
    rows.insert(b"meta".to_vec(), row.into_bytes());
}

#[test]
fn the_recount_counts_the_stops_again() {
    let mut chain = Chain::new(surviving());
    chain.run(5 * MINUTE);
    chain.stop(3 * HOUR);
    chain.run(5 * MINUTE);
    chain.stop(DAY);
    assert_eq!(chain.stopped(), Some(3 * HOUR - T + DAY - T));
    // A copy of the state as it is passes.
    recount(&chain, |_| {}).unwrap();
    let refusal = |chain: &Chain, change: &dyn Fn(&mut BTreeMap<Vec<u8>, Vec<u8>>)| format!("{:#}", recount(chain, |rows| change(rows)).unwrap_err());
    // A total that is not the sum of the stops the block times show: lower,
    // which would bring every wait forward, or higher.
    let total = chain.stopped().unwrap();
    for wrong in [total - 1, total + 1, 0] {
        let reason = refusal(&chain, &|rows| meta_with(rows, Some(wrong)));
        assert!(reason.contains("the total of stops differs from the block times"), "{reason}");
    }
    // The number missing on a network with the rule.
    let missing = refusal(&chain, &|rows| meta_with(rows, None));
    assert!(missing.contains("the total of stops belongs to a network with waits_survive_stops"), "{missing}");
    // The number on a network without the rule, even the true one.
    let mut plain = Chain::new(genesis_v5());
    plain.stop(3 * HOUR);
    recount(&plain, |_| {}).unwrap();
    let foreign = refusal(&plain, &|rows| meta_with(rows, Some(2 * HOUR)));
    assert!(foreign.contains("the total of stops belongs to a network with waits_survive_stops"), "{foreign}");
}

// ---- A node, as CometBFT drives it ----------------------------------------

const ACCEPT: i32 = response_process_proposal::ProposalStatus::Accept as i32;
const OFFER_ACCEPT: i32 = response_offer_snapshot::Result::Accept as i32;
const CHUNK_ACCEPT: i32 = response_apply_snapshot_chunk::Result::Accept as i32;

fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: micros / 1_000_000,
        nanos: ((micros % 1_000_000) * 1000) as i32,
    })
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
fn voters(genesis: &Genesis) -> Vec<Validator> {
    genesis
        .validators
        .iter()
        .map(|validator| Validator {
            address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20].to_vec().into(),
            power: genesis.profile.genesis_power() as i64,
        })
        .collect()
}
fn query(app: &App, path: &str, data: &Value) -> Value {
    let response = app.query(RequestQuery {
        data: serde_json::to_vec(data).unwrap().into(),
        path: path.into(),
        height: 0,
        prove: false,
    });
    assert_eq!(response.code, 0, "query failed: {}", response.log);
    serde_json::from_slice(&response.value).unwrap()
}
/// A row as a wallet is served it with `/v4/state`: the bytes under `key`
/// in the answer for account `id` and its security row.
fn served(app: &App, id: u64, key: &[u8]) -> Option<Vec<u8>> {
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()], "include_security": true }));
    let wanted = hex::encode(key);
    let entry = view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == wanted.as_str())?;
    entry["value_b64"].as_str().map(|value| STANDARD.decode(value).unwrap())
}

struct Node {
    app: App,
    genesis: Genesis,
    network: String,
    height: i64,
    elapsed: u64,
    /// The finalize request and its answer for every committed block.
    log: Vec<(RequestFinalizeBlock, ResponseFinalizeBlock)>,
}
impl Node {
    fn start(path: &Path, options: NodeOptions, genesis: &Genesis) -> Self {
        let app = App::open_with_options(path, options).unwrap();
        app.try_init(init(genesis)).unwrap();
        Self { app, genesis: genesis.clone(), network: genesis.network_id().unwrap(), height: 0, elapsed: 0, log: Vec::new() }
    }
    fn time(&self, delta: u64) -> Option<Timestamp> {
        timestamp(self.genesis.ledger.genesis_time_micros + (self.elapsed + delta) as i64)
    }
    fn request(&self, delta: u64, txs: Vec<Vec<u8>>) -> RequestFinalizeBlock {
        let height = self.height + 1;
        RequestFinalizeBlock {
            height,
            time: self.time(delta),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: (height > 1).then(|| CommitInfo {
                round: 0,
                votes: voters(&self.genesis)
                    .into_iter()
                    .map(|validator| VoteInfo { validator: Some(validator), block_id_flag: BlockIdFlag::Commit as i32 })
                    .collect(),
            }),
            ..Default::default()
        }
    }
    fn proposal(request: &RequestFinalizeBlock) -> RequestProcessProposal {
        RequestProcessProposal {
            txs: request.txs.clone(),
            proposed_last_commit: request.decided_last_commit.clone(),
            misbehavior: request.misbehavior.clone(),
            hash: request.hash.clone(),
            height: request.height,
            time: request.time,
            next_validators_hash: request.next_validators_hash.clone(),
            proposer_address: request.proposer_address.clone(),
        }
    }
    /// Whether a validator accepts a block with `txs` as a proposal.
    fn accepts(&self, delta: u64, txs: Vec<Vec<u8>>) -> bool {
        self.app.process_proposal(Self::proposal(&self.request(delta, txs))).status == ACCEPT
    }
    /// Proposal, finalize and commit of one block, as on a validator; then
    /// the snapshot for peers, if one is due.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let request = self.request(delta, txs);
        assert_eq!(self.app.process_proposal(Self::proposal(&request)).status, ACCEPT, "proposal rejected at height {}", request.height);
        let response = self.app.try_finalize(request.clone()).unwrap();
        self.app.try_commit().unwrap();
        self.app.write_sync_snapshot().unwrap();
        self.height += 1;
        self.elapsed += delta;
        self.log.push((request, response));
    }
    /// The mempool's answer to `tx`.
    fn check(&self, tx: &[u8]) -> ResponseCheckTx {
        self.app.check_batch(vec![RequestCheckTx { tx: tx.to_vec().into(), r#type: 0 }]).pop().unwrap()
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&served(&self.app, id, &account_key(id)).expect("account exists")).unwrap()
    }
    fn mine(&self) -> Security {
        serde_json::from_slice(&served(&self.app, ME, &security::key(ME)).expect("the account has adopted the rules")).unwrap()
    }
    fn meta(&self) -> Value {
        serde_json::from_slice(&served(&self.app, ME, b"meta").expect("the metadata row comes with every answer")).unwrap()
    }
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        signed(&self.network, from, row.nonce + 1, row.auth_epoch, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn execute(&self, id: u64) -> Vec<u8> {
        act_tx(&self.network, &self.account(ME), SPEND, security::PAYMENT, json!({"type": "execute", "id": id.to_string()}))
    }
    /// The payment still waits: the mempool and a validator refuse to
    /// complete it.
    fn still_waits(&self) {
        let execute = self.execute(1);
        let answer = self.check(&execute);
        assert_ne!(answer.code, 0, "the mempool admitted the payment");
        assert!(answer.log.contains(NOT_OVER), "{}", answer.log);
        assert!(!self.accepts(SECOND, vec![execute]), "a validator accepted the payment");
    }
}

/// `time-node-v5 --devnet --db PATH --audit`: the recount an operator runs.
fn recount_report(path: &Path) -> Value {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_time-node-v5"))
        .args(["--devnet", "--db"])
        .arg(path)
        .arg("--audit")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "PASS_OFFLINE_AUTHENTICATED_RECOUNT");
    report
}

#[test]
fn the_total_survives_a_restart_and_reaches_a_node_that_joins_from_a_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = surviving();
    // Snapshots for peers every ten blocks, in chunks of 1 KiB.
    let serving = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let path = dir.path().join("source.db");
    let mut source = Node::start(&path, serving, &genesis);
    source.block(SECOND, vec![]);
    while !(0..4).all(|id| source.account(id).balance >= 5 * SECOND) {
        assert!(source.height < 12, "validator owners were not funded");
        source.block(MINUTE, vec![]);
    }
    let fund: Vec<Vec<u8>> = (0..4u64).map(|owner| source.transfer(owner, owner as u8 + 1, ME, 5 * SECOND)).collect();
    source.block(SECOND, fund);
    let secure = secure_tx(&source.network, &source.account(ME));
    source.block(SECOND, vec![secure]);
    let request = act_tx(&source.network, &source.account(ME), SPEND, security::PAYMENT, json!({"type": "request", "to": SHOP.to_string(), "amount": SECOND.to_string()}));
    source.block(SECOND, vec![request]);
    // A stop of two days before the snapshot of height 20, and one of nine
    // hours after it.
    source.block(2 * DAY, vec![]);
    assert!(source.height < 20, "the stop came after the snapshot");
    while source.height < 21 {
        source.block(SECOND, vec![]);
    }
    source.block(9 * HOUR, vec![]);
    let stops = (2 * DAY - T) + (9 * HOUR - T);
    let total = stops.to_string();
    // A wallet reads the number with the state it verifies: the metadata
    // row comes with every answer.
    assert_eq!(source.meta()["stopped_micros"], total.as_str());
    assert_eq!(source.meta()["config"]["waits_survive_stops"], true);
    source.still_waits();

    // A node that joins by state sync restores the snapshot of height 20,
    // then executes the blocks after it.
    let snapshot = source.app.list_snapshots().snapshots.into_iter().find(|snapshot| snapshot.height == 20).unwrap();
    let trusted = source.log[19].1.app_hash.clone();
    let joined_path = dir.path().join("joined.db");
    let joiner = App::open(&joined_path).unwrap();
    assert_eq!(joiner.offer_snapshot(RequestOfferSnapshot { snapshot: Some(snapshot.clone()), app_hash: trusted.clone() }).result, OFFER_ACCEPT);
    assert!(snapshot.chunks > 1);
    for chunk in 0..snapshot.chunks {
        let bytes = source.app.load_snapshot_chunk(RequestLoadSnapshotChunk { height: 20, format: snapshot.format, chunk }).chunk;
        assert_eq!(joiner.apply_snapshot_chunk(RequestApplySnapshotChunk { index: chunk, chunk: bytes, sender: "peer".into() }).result, CHUNK_ACCEPT);
    }
    assert_eq!(joiner.head().unwrap().unwrap().0, 20);
    assert_eq!(joiner.info(RequestInfo::default()).last_block_app_hash, trusted);
    for (request, response) in &source.log[20..] {
        assert_eq!(joiner.try_finalize(request.clone()).unwrap(), *response);
        joiner.try_commit().unwrap();
    }
    assert_eq!(joiner.head().unwrap(), source.app.head().unwrap());
    let mut joined = Node { app: joiner, genesis: genesis.clone(), network: source.network.clone(), height: source.height, elapsed: source.elapsed, log: Vec::new() };
    assert_eq!(joined.meta()["stopped_micros"], total.as_str());
    joined.still_waits();

    // The first node stops and starts again from its restart snapshot.
    let (height, root) = source.app.head().unwrap().unwrap();
    source.app.snapshot().unwrap().expect("a restart snapshot");
    let (network, elapsed) = (source.network.clone(), source.elapsed);
    drop(source);
    let app = App::open_with_options(&path, serving).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    let mut restarted = Node { app, genesis: genesis.clone(), network, height: height as i64, elapsed, log: Vec::new() };
    assert_eq!(restarted.meta()["stopped_micros"], total.as_str());
    restarted.still_waits();

    // Both go on to the same state: the wait ends on both when the chain
    // has run for it, and not before.
    let ready = restarted.mine().pending_payments[0].ready_elapsed_micros;
    let active = restarted.elapsed - stops;
    assert!(ready > active);
    let left = ready - active;
    for node in [&mut restarted, &mut joined] {
        let mut remaining = left;
        while remaining > T {
            node.block(T, vec![]);
            remaining -= T;
        }
        assert!(!node.accepts(remaining - 1, vec![node.execute(1)]));
        let execute = node.execute(1);
        node.block(remaining, vec![execute]);
        assert!(node.mine().pending_payments.is_empty());
    }
    assert_eq!(restarted.app.head().unwrap(), joined.app.head().unwrap());

    // The recount of both, offline. The report of the command an operator
    // runs names the rule and the total.
    for (node, node_path) in [(restarted, path), (joined, joined_path)] {
        node.app.snapshot().unwrap();
        drop(node);
        let report = recount_report(&node_path);
        assert_eq!(report["waits_survive_stops"], true, "{report}");
        assert_eq!(report["stopped_micros"], total.as_str(), "{report}");
        let engine = Engine::open_with_history(Store::open(node_path.with_extension("v5state")).unwrap(), node_path.with_extension("history")).unwrap();
        engine.audit().unwrap();
        assert_eq!(engine.meta().unwrap().stopped_micros, Some(stops));
    }
}

/// The report of the recount of a network without the rule has the fields it
/// always had.
#[test]
fn the_recount_report_of_a_network_without_the_setting_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::start(&path, NodeOptions::default(), &genesis_v5());
    node.block(SECOND, vec![]);
    node.block(5 * HOUR, vec![]);
    node.app.snapshot().unwrap();
    drop(node);
    let report = recount_report(&path);
    let mut fields: Vec<&str> = report.as_object().unwrap().keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "accounts", "auction_reserve", "authenticated_leaves", "authenticated_nodes", "bank", "elapsed_micros", "engine", "height",
            "history_archive_verified", "history_pruned_through", "liquid", "network_id", "pos_escrow", "protocol", "public_launch_allowed", "root",
            "status",
        ]
    );
}
