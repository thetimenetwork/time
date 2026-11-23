//! The emergency path on the real engine: the rule switch of a fix release
//! (`docs/design/upgrade-mechanism.md`, section 10; `docs/emergency-fix.md`).
//!
//! A fix release carries one switch for one network: after the height the
//! validators agreed on, the next block is exactly one transaction (action
//! kind 81) and ends by writing the new version. These tests run chains on
//! which programs with and without such a switch execute the same blocks,
//! and show that the switch is accepted exactly once and under no other
//! condition: not at another height, for another version, specification or
//! network, a second time, beside another transaction, or by a program that
//! is not that fix release. They compare the state after the switch block,
//! row by row, with the state after an empty block. The last tests cover a
//! block that a fix release repairs (a stop in the middle of a block).
//!
//! Every block is built by a proposer, validated strictly and executed with
//! the engine's fast paths off; the three must agree. `emergency_node.rs`
//! runs the same path through the ABCI calls, with several validators.
mod common;
use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, META_KEY, Misbehavior, Prepared, account_key};
use timecurrency_v5::genesis::Genesis;
use timecurrency_v5::pos_adapter::{DUPLICATE_VOTE, SUMMARY_KEY};
use timecurrency_v5::rules::{self, Switch, SwitchAt, Versions};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;
use timecurrency_v5::upgrade::{self, Event};

const SECOND: u64 = 1_000_000;
const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const SPEC_6: &str = "6666666666666666666666666666666666666666666666666666666666666666";

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
/// A fix release for the test network: the switch to version 5 after `height`.
fn fix(height: u64) -> Versions {
    fix_on(&network_id(), height)
}
fn fix_on(network: &str, height: u64) -> Versions {
    plain()
        .with_switch(Switch { network_id: network.to_string(), version: 5, at: SwitchAt::After { height } })
        .unwrap()
}
/// The one transaction of the switch block of `fix(_)`.
fn switch() -> Vec<u8> {
    upgrade::switch_action(&network_id(), 5, SPEC_5).unwrap()
}

struct Chain {
    dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    /// Reported with the next block.
    misbehavior: Vec<Misbehavior>,
    /// Every block committed, as (time after its parent, transactions).
    log: Vec<(u64, Vec<Vec<u8>>)>,
}
impl Chain {
    /// The test network on a program that implements `versions`, with the
    /// four validator owners able to pay fees. Every chain made this way
    /// executes the same first blocks, whatever its program.
    fn on(versions: Versions) -> Self {
        Self::with(genesis_v5(), versions)
    }
    fn with(genesis: Genesis, versions: Versions) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history"))
            .unwrap()
            .implementing(versions);
        engine.initialize(genesis).unwrap();
        let mut chain = Self { dir, engine, network, misbehavior: Vec::new(), log: Vec::new() };
        while (0..4).any(|owner| chain.account(owner).balance < 20 * SECOND) {
            assert!(chain.height() < 80, "validator owners were not funded");
            chain.block(60 * SECOND, vec![]);
        }
        chain
    }
    /// The same data under another program: the state is saved, and the
    /// engine is opened on it again as a program that implements `versions`.
    fn reopen(self, versions: Versions) -> Self {
        let Self { dir, engine, network, misbehavior, log } = self;
        let version = engine.version().unwrap().clone();
        if engine.store().snapshot_height().unwrap() != Some(version.height()) {
            engine.store().write_snapshot(&version).unwrap();
        }
        drop(version);
        drop(engine);
        let engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history"))
            .unwrap()
            .implementing(versions);
        Self { dir, engine, network, misbehavior, log }
    }
    fn now(&self) -> u64 {
        self.engine.meta().unwrap().elapsed_micros().unwrap()
    }
    fn height(&self) -> u64 {
        self.engine.meta().unwrap().height as u64
    }
    fn version(&self) -> u64 {
        self.engine.meta().unwrap().protocol_version
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
    fn summary(&self) -> pos::Summary {
        serde_json::from_slice(&self.row(SUMMARY_KEY).unwrap()).unwrap()
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
    fn next(&self, delta: u64) -> (i64, i64, Vec<String>, [u8; 32]) {
        let meta = self.engine.meta().unwrap();
        let signers = self.engine.active_roster_at(meta.height as u64).unwrap().into_iter().map(|validator| validator.consensus_key).collect();
        (meta.height + 1, meta.time_micros + delta as i64, signers, sha(meta.height as u64 + 1))
    }
    /// Offers `txs` to a proposer, commits what it keeps and returns that.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let (height, time, signers, hash) = self.next(delta);
        let misbehavior = std::mem::take(&mut self.misbehavior);
        let (proposed, kept) = self
            .engine
            .prepare_filtered_with_misbehavior(height, time, &txs, &signers, 1 << 20, hash, &misbehavior)
            .unwrap_or_else(|error| panic!("the proposer failed at height {height}: {error:#}"));
        self.commit_checked(proposed, &kept, delta, &misbehavior);
        kept
    }
    /// Commits exactly `txs`, as a validator executes a decided block.
    fn decided(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Event> {
        let (height, time, signers, hash) = self.next(delta);
        let misbehavior = std::mem::take(&mut self.misbehavior);
        let prepared = self
            .engine
            .prepare_with_misbehavior(height, time, &txs, &signers, hash, &misbehavior)
            .unwrap_or_else(|error| panic!("block {height} refused: {error:#}"));
        let events = prepared.upgrade_events.clone();
        self.commit_checked(prepared, &txs, delta, &misbehavior);
        events
    }
    fn commit_checked(&mut self, prepared: Prepared, txs: &[Vec<u8>], delta: u64, misbehavior: &[Misbehavior]) {
        let (height, time, signers, hash) = self.next(delta);
        let strict = self.engine.prepare_with_misbehavior(height, time, txs, &signers, hash, misbehavior).unwrap();
        let reference = self.engine.prepare_reference_with_misbehavior(height, time, txs, &signers, hash, misbehavior).unwrap();
        assert_eq!(strict.root, prepared.root, "validator and proposer disagree at height {height}");
        assert_eq!(reference.root, prepared.root, "fast path and reference disagree at height {height}");
        let before = self.version();
        self.engine.commit(prepared, hash).unwrap();
        self.log.push((delta, txs.to_vec()));
        // The version rises by one or not at all, and a version above the
        // first has its activation row.
        assert!(self.version() == before || self.version() == before + 1);
        if self.engine.runnable().is_ok() && self.engine.missed_switch().is_none() {
            self.engine.audit().unwrap();
        }
    }
    /// Why the block dated `delta` after the head with exactly `txs` is not
    /// executed: by a validator and by the reference path alike.
    #[track_caller]
    fn refused(&self, delta: u64, txs: &[Vec<u8>]) -> String {
        let (height, time, signers, hash) = self.next(delta);
        let error = match self.engine.prepare_with_misbehavior(height, time, txs, &signers, hash, &self.misbehavior) {
            Ok(_) => panic!("block {height} was executed"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            self.engine.prepare_reference_with_misbehavior(height, time, txs, &signers, hash, &self.misbehavior).is_err(),
            "the reference path executed block {height}"
        );
        error
    }
    /// What a proposer keeps of `txs` for the next block, without committing.
    fn proposes(&self, delta: u64, txs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let (height, time, signers, hash) = self.next(delta);
        self.engine.prepare_filtered_with_misbehavior(height, time, txs, &signers, 1 << 20, hash, &self.misbehavior).unwrap().1
    }
    fn pay(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + 1,
                auth_epoch: row.auth_epoch,
                public_key: pk(from as u8 + 1),
                payload: ActionPayload::Transfer(ledger::Transfer { to, amount }),
                signature: vec![],
            },
            &key(from as u8 + 1),
        )
        .unwrap()
    }
    /// The owner of a validator supports version 5 from `activate` on.
    fn support(&self, owner: u64, activate: u64) -> Vec<u8> {
        let row = self.account(owner);
        timecurrency_v5::wire::sign(
            &self.network,
            owner,
            row.nonce + 1,
            row.auth_epoch,
            upgrade::SIGNAL,
            &json!({"activate_elapsed_micros": activate.to_string(), "spec": SPEC_5, "version": "5"}),
            &key(owner as u8 + 1),
        )
        .unwrap()
    }
    /// CometBFT reports with the next block that starting validator `owner`
    /// voted twice at the head.
    fn jail(&mut self, owner: u64) {
        self.misbehavior.push(Misbehavior {
            kind: DUPLICATE_VOTE,
            address: Sha256::digest(hex::decode(pk(owner as u8 + 101)).unwrap())[..20].to_vec(),
            height: self.height() as i64,
        });
    }
    fn activated(&self, version: u64) -> Option<String> {
        self.row(&upgrade::activated_key(version)).map(|row| String::from_utf8(row).unwrap())
    }
}

/// The height every chain of these tests is at once its owners are funded.
fn funded_height() -> u64 {
    Chain::on(old()).height()
}

/// What the switch block does to the state, proven against an empty block.
///
/// Two programs execute the same blocks up to the agreed height `H`. Then
/// the fix release executes its switch block and release 1 an empty block,
/// with the same date and the same signers. Row by row the two states are
/// the same, but for the version in the metadata row and the row that
/// records the activation.
#[test]
fn the_switch_block_does_what_an_empty_block_does_and_writes_the_version() {
    let h = funded_height() + 3;
    let mut fixed = Chain::on(fix(h));
    let mut control = Chain::on(old());
    assert_eq!(fixed.root(), control.root());
    // Up to H the fix release runs the old rules: payments, block by block.
    while fixed.height() < h {
        let paid = fixed.pay(0, 5, 1000 + fixed.height());
        assert_eq!(fixed.block(SECOND, vec![paid.clone()]), vec![paid.clone()]);
        control.decided(SECOND, vec![paid]);
        assert_eq!(fixed.root(), control.root(), "the two programs differ before the agreed height");
        assert_eq!(fixed.version(), 4);
    }
    assert!(fixed.engine.missed_switch().is_none() && fixed.engine.runnable().is_ok());
    let before = fixed.rows();
    assert_eq!(before, control.rows());
    // Block H + 1. Whatever the proposer is offered, it proposes exactly one
    // transaction: the switch of this program.
    let offered = vec![fixed.pay(0, 5, 7), fixed.pay(1, 5, 9), fixed.support(2, fixed.now() + 500 * SECOND)];
    assert_eq!(fixed.proposes(3 * SECOND, &offered), vec![switch()]);
    assert_eq!(fixed.proposes(3 * SECOND, &[]), vec![switch()]);
    let (_, time, signers, hash) = fixed.next(3 * SECOND);
    let events = fixed.engine.prepare(h as i64 + 1, time, &[switch()], &signers, hash).unwrap().upgrade_events;
    assert_eq!(events, vec![Event::Switched { version: 5, spec: SPEC_5.into(), cancelled: None }]);
    assert_eq!(fixed.block(3 * SECOND, offered), vec![switch()]);
    control.decided(3 * SECOND, vec![]);
    assert_eq!((fixed.height(), fixed.version(), control.version()), (h + 1, 5, 4));
    // The activation row: the first block under version 5 is H + 2, the
    // time is the switch block's, and there was no notice.
    assert_eq!(
        fixed.activated(5).unwrap(),
        format!("{{\"elapsed_micros\":\"{}\",\"height\":\"{}\",\"notice\":\"none\",\"spec\":\"{SPEC_5}\"}}", fixed.now(), h + 2)
    );
    // Row by row against the empty block.
    let (mut after, mut empty) = (fixed.rows(), control.rows());
    assert_eq!(after.remove(&upgrade::activated_key(5)).map(|row| row.len()), fixed.activated(5).map(|row| row.len()));
    let meta = |rows: &mut BTreeMap<Vec<u8>, Vec<u8>>| -> Value { serde_json::from_slice(&rows.remove(META_KEY).unwrap()).unwrap() };
    let (mut switched, unswitched) = (meta(&mut after), meta(&mut empty));
    assert_eq!((switched["protocol_version"].as_str(), unswitched["protocol_version"].as_str()), (Some("5"), Some("4")));
    switched["protocol_version"] = "4".into();
    assert_eq!(switched, unswitched, "the switch block changed more of the metadata than the version");
    assert_eq!(after.len(), empty.len());
    for (key, value) in &after {
        assert_eq!(Some(value), empty.get(key), "the switch block and an empty block differ in the row {}", String::from_utf8_lossy(key));
    }
    // No row under upgrade/ but the activation; no account changed that an
    // empty block does not change; nobody paid a fee for the switch.
    assert!(fixed.rows().keys().filter(|key| key.starts_with(b"upgrade/")).eq([&upgrade::activated_key(5)]));
    assert!(fixed.row(upgrade::STATE_KEY).is_none());
    for owner in 0..GENESIS_ACCOUNTS {
        assert_eq!(fixed.account(owner), control.account(owner));
    }
    // The supply rule held (the metadata check of every block) and the
    // recount passes, with the activation row counted.
    fixed.engine.audit().unwrap();
    // The chain goes on under version 5, with the rules of 4 unchanged.
    let paid = fixed.pay(0, 5, 1000);
    assert_eq!(fixed.block(SECOND, vec![paid.clone()]), vec![paid]);
    assert_eq!((fixed.version(), fixed.height()), (5, h + 2));
    // Release 1 does not go there: the block it would need next is under a
    // version it lacks, which the header says. It cannot execute the switch
    // block either.
    let stopped = Chain::on(old());
    let mut stopped = stopped;
    for (delta, txs) in &fixed.log[stopped.log.len()..h as usize] {
        stopped.decided(*delta, txs.clone());
    }
    assert_eq!(stopped.height(), h);
    assert!(stopped.refused(3 * SECOND, &[switch()]).contains("kind 81 is reserved"));
}

/// The switch is accepted in one block, as one byte string, by one program.
#[test]
fn the_switch_is_accepted_exactly_once_and_under_no_other_condition() {
    let h = funded_height() + 3;
    let mut chain = Chain::on(fix(h));
    let reserved = "kind 81 is reserved";
    let alone = "exactly one transaction, the rule switch of this fix release";
    // Before the agreed height: refused in a block, never proposed, never
    // admitted.
    while chain.height() < h {
        assert!(chain.refused(SECOND, &[switch()]).contains(reserved), "height {}", chain.height() + 1);
        assert!(chain.proposes(SECOND, &[switch()]).is_empty());
        assert!(format!("{:#}", chain.engine.validate_tx(&switch()).unwrap_err()).contains(reserved));
        chain.block(SECOND, vec![]);
    }
    // At the agreed height the switch is still not admitted to a mempool:
    // the proposer writes it itself.
    assert!(format!("{:#}", chain.engine.validate_tx(&switch()).unwrap_err()).contains(reserved));
    assert!(chain.engine.check_state().unwrap().admit(&switch(), SigStatus::Unknown).is_err());
    // Block H + 1 is the switch and nothing else.
    let payment = chain.pay(0, 5, 1000);
    let other = |version: u64, spec: &str, network: &str| upgrade::switch_action(network, version, spec).unwrap();
    let signed = raw_action(&chain.network, upgrade::SWITCH, 0, chain.account(0).nonce + 1, 0, 1, format!("{{\"spec\":\"{SPEC_5}\",\"version\":\"5\"}}").as_bytes());
    let mut longer = switch();
    longer.push(0);
    let mut shorter = switch();
    shorter.pop();
    for (name, txs, why) in [
        ("no transaction", vec![], "carries the rule switch of this fix release, and this block does not"),
        ("a payment", vec![payment.clone()], alone),
        ("the switch and a payment", vec![switch(), payment.clone()], alone),
        ("a payment and the switch", vec![payment.clone(), switch()], alone),
        ("the switch twice", vec![switch(), switch()], alone),
        ("a switch to version 6", vec![other(6, SPEC_5, &chain.network)], alone),
        ("a switch to version 4", vec![other(4, rules::SPEC_4, &chain.network)], alone),
        ("a switch under another specification", vec![other(5, SPEC_6, &chain.network)], alone),
        ("a switch of another network", vec![other(5, SPEC_5, &"ab".repeat(32))], alone),
        ("a signed action of kind 81", vec![signed], alone),
        ("the switch and one byte", vec![longer], alone),
        ("the switch less one byte", vec![shorter], alone),
    ] {
        let error = chain.refused(SECOND, &txs);
        assert!(error.contains(why), "{name}: {error}");
        assert_eq!((chain.height(), chain.version()), (h, 4), "{name}");
    }
    // Exactly the switch: accepted, once.
    assert_eq!(chain.decided(SECOND, vec![switch()]), vec![Event::Switched { version: 5, spec: SPEC_5.into(), cancelled: None }]);
    assert_eq!((chain.height(), chain.version()), (h + 1, 5));
    // A second time, in any later block: refused like before the height.
    for _ in 0..3 {
        assert!(chain.refused(SECOND, &[switch()]).contains(reserved));
        assert!(chain.proposes(SECOND, &[switch()]).is_empty());
        assert!(format!("{:#}", chain.engine.validate_tx(&switch()).unwrap_err()).contains(reserved));
        chain.block(SECOND, vec![]);
    }
    assert_eq!(chain.version(), 5);
    // The same blocks under other programs, at the agreed height.
    let log = chain.log.clone();
    let at_h = |versions: Versions| {
        let mut other = Chain::on(versions);
        for (delta, txs) in &log[other.log.len()..h as usize] {
            other.decided(*delta, txs.clone());
        }
        assert_eq!(other.height(), h);
        other
    };
    // Release 1, and a program that implements version 5 and is not a fix
    // release: no switch block. The block after H is a block like any other.
    for versions in [old(), plain()] {
        let mut other = at_h(versions);
        assert!(other.refused(SECOND, &[switch()]).contains(reserved));
        assert!(other.proposes(SECOND, &[switch()]).is_empty());
        other.decided(SECOND, vec![]);
        assert_eq!((other.height(), other.version()), (h + 1, 4));
    }
    // A fix release built for a later height: at H + 1 it is not at its
    // switch block either. (One built for an earlier height never gets
    // here: the next test.)
    for wrong in [h + 1, h + 5] {
        let mut other = at_h(fix(wrong));
        assert!(other.refused(SECOND, &[switch()]).contains(reserved), "{wrong}");
        other.decided(SECOND, vec![]);
        assert_eq!((other.height(), other.version()), (h + 1, 4));
    }
    // One built for the height before: the block at H is its switch block,
    // and the chain's block there is another one. It does not execute it.
    let mut earlier = Chain::on(fix(h - 1));
    for (delta, txs) in &log[earlier.log.len()..h as usize - 1] {
        earlier.decided(*delta, txs.clone());
    }
    assert_eq!(earlier.height(), h - 1);
    let (delta, txs) = &log[h as usize - 1];
    assert!(earlier.refused(*delta, txs).contains("and this block does not"));
}

/// A release runs on more than one network, and a height means nothing on
/// another chain: a switch names its network, and changes no other.
#[test]
fn a_switch_is_for_one_network_and_changes_no_other() {
    let h = funded_height() + 2;
    let elsewhere = "cd".repeat(32);
    let mut chain = Chain::on(fix_on(&elsewhere, h));
    let mut control = Chain::on(old());
    while chain.height() < h + 3 {
        // No block is a switch block here, the one after H included.
        assert!(chain.refused(SECOND, &[switch()]).contains("kind 81 is reserved"));
        assert!(chain.refused(SECOND, &[upgrade::switch_action(&elsewhere, 5, SPEC_5).unwrap()]).contains("kind 81 is reserved"));
        let paid = chain.pay(1, 5, 500);
        assert_eq!(chain.block(SECOND, vec![paid.clone()]), vec![paid.clone()]);
        control.decided(SECOND, vec![paid]);
        assert_eq!(chain.root(), control.root());
    }
    assert_eq!(chain.version(), 4);
    assert!(chain.engine.missed_switch().is_none());
    assert!(chain.rows().keys().all(|key| !key.starts_with(b"upgrade/")));
}

/// "The switch wins over a scheduled plan whose start time has passed: a plan
/// never activates in a switch block." And a validator safety hold, which
/// postpones a plan, does not postpone a switch.
#[test]
fn the_switch_wins_over_a_scheduled_plan_and_is_not_postponed_by_a_hold() {
    let f = funded_height();
    // Block F + 1 schedules a plan for version 5 that starts 130 s later;
    // block F + 2 is dated before that start and block F + 3 after it.
    let h = f + 2;
    let mut fixed = Chain::on(fix(h));
    let mut control = Chain::on(plain());
    let activate = fixed.now() + SECOND + 130 * SECOND;
    let signals: Vec<Vec<u8>> = (0..4).map(|owner| fixed.support(owner, activate)).collect();
    assert_eq!(fixed.block(SECOND, signals.clone()), signals);
    control.decided(SECOND, signals);
    let plan = fixed.engine.upgrade_state().unwrap().unwrap().plan.expect("scheduled");
    assert_eq!((plan.version, plan.activate_elapsed_micros), (5, activate));
    fixed.block(100 * SECOND, vec![]);
    control.decided(100 * SECOND, vec![]);
    assert_eq!(fixed.root(), control.root());
    assert!(fixed.now() < activate && fixed.height() == h);
    // The block dated after the start. Without a switch, the plan activates
    // in it, with its notice behind it.
    assert_eq!(control.decided(40 * SECOND, vec![]), vec![Event::Activated(plan.clone())]);
    assert!(control.activated(5).unwrap().contains("\"notice\":\"scheduled\""));
    // In the switch block the switch does it, and says so: no notice.
    assert_eq!(fixed.decided(40 * SECOND, vec![switch()]), vec![Event::Switched { version: 5, spec: SPEC_5.into(), cancelled: Some(plan) }]);
    assert!(fixed.now() >= activate);
    assert!(fixed.activated(5).unwrap().contains("\"notice\":\"none\""));
    assert_eq!((fixed.version(), control.version()), (5, 5));
    // The plan and every entry are gone.
    assert!(fixed.engine.upgrade_state().unwrap().is_none());
    assert!(fixed.rows().keys().filter(|key| key.starts_with(b"upgrade/")).eq([&upgrade::activated_key(5)]));
    fixed.engine.audit().unwrap();

    // A hold: CometBFT reports with the switch block that a validator signed
    // twice. The validator is jailed, the hold is on, and a plan would wait.
    // The switch does not.
    let h = funded_height() + 1;
    let mut held = Chain::on(fix(h));
    held.block(SECOND, vec![]);
    held.jail(3);
    assert_eq!(held.decided(SECOND, vec![switch()]), vec![Event::Switched { version: 5, spec: SPEC_5.into(), cancelled: None }]);
    assert!(held.summary().safety_hold, "the test is about a block in which a hold is on");
    assert_eq!(held.version(), 5);
    held.engine.audit().unwrap();
}

/// "What the fix release refuses: to start, when its head is above `H` and
/// still at the old version." The chain went on without the switch, so the
/// program was built for another height.
#[test]
fn a_fix_release_executes_nothing_past_its_switch_under_the_old_version() {
    let h = funded_height() + 2;
    let mut chain = Chain::on(old());
    while chain.height() < h + 3 {
        chain.block(SECOND, vec![]);
    }
    let head = chain.root();
    // At H itself the fix release is where it was built to be.
    let chain = chain.reopen(fix(h + 3));
    assert!(chain.engine.missed_switch().is_none());
    assert_eq!(chain.proposes(SECOND, &[]), vec![switch()]);
    // One block past its switch block and still under version 4: nothing.
    let chain = chain.reopen(fix(h));
    let missed = chain.engine.missed_switch().expect("past the switch").clone();
    assert_eq!(missed, upgrade::MissedSwitch { block_height: h + 1, version: 5, head: h + 3, head_version: 4 });
    let text = missed.explain();
    assert!(text.contains(&format!("to protocol version 5 in block {}", h + 1)) && text.contains(&format!("at height {}, still under version 4", h + 3)), "{text}");
    assert!(text.contains("Nothing was changed") && text.contains("Delete nothing"), "{text}");
    let (height, time, signers, hash) = chain.next(SECOND);
    let none: [Vec<u8>; 0] = [];
    let refused = |result: anyhow::Result<()>| format!("{:#}", result.expect_err("ran on a head past its switch"));
    for attempt in [
        refused(chain.engine.prepare(height, time, &none, &signers, hash).map(|_| ())),
        refused(chain.engine.prepare(height, time, &[switch()], &signers, hash).map(|_| ())),
        refused(chain.engine.prepare_filtered(height, time, &none, &signers, 1 << 20, hash).map(|_| ())),
        refused(chain.engine.prepare_reference(height, time, &none, &signers, hash).map(|_| ())),
        refused(chain.engine.validate_tx(&chain.pay(0, 5, 1))),
        refused(chain.engine.check_state().map(|_| ())),
        refused(chain.engine.audit().map(|_| ())),
    ] {
        assert!(attempt.contains("executes nothing on a head past it"), "{attempt}");
    }
    assert_eq!(chain.root(), head, "the state changed");
    // The release the state was made by goes on with it.
    let mut chain = chain.reopen(old());
    assert!(chain.engine.missed_switch().is_none());
    chain.block(SECOND, vec![]);
    // A chain that took the switch is not past it: the version says so.
    let mut switched = Chain::on(fix(h));
    while switched.height() < h {
        switched.block(SECOND, vec![]);
    }
    switched.block(SECOND, vec![]);
    switched.block(SECOND, vec![]);
    let switched = switched.reopen(fix(h));
    assert!(switched.version() == 5 && switched.engine.missed_switch().is_none() && switched.engine.runnable().is_ok());
}

/// The switch leads from the version before it and from no other: on a chain
/// that is under another version at that height, the program executes no
/// block there.
#[test]
fn the_chain_must_be_under_the_version_before_at_the_switch_height() {
    let h = funded_height() + 2;
    // A switch to version 6 on a chain that is under version 4 at H.
    let six = list(&[(4, rules::SPEC_4), (5, SPEC_5), (6, SPEC_6)])
        .with_switch(Switch { network_id: network_id(), version: 6, at: SwitchAt::After { height: h } })
        .unwrap();
    let mut chain = Chain::on(six);
    while chain.height() < h {
        chain.block(SECOND, vec![]);
    }
    let own = upgrade::switch_action(&chain.network, 6, SPEC_6).unwrap();
    for txs in [vec![], vec![own], vec![switch()]] {
        let error = chain.refused(SECOND, &txs);
        assert!(error.contains("the chain is under version 4 there, not under the version before it"), "{error}");
    }
    let (height, time, signers, hash) = chain.next(SECOND);
    let none: [Vec<u8>; 0] = [];
    assert!(chain.engine.prepare_filtered(height, time, &none, &signers, 1 << 20, hash).is_err(), "a proposer built a block there");
    assert_eq!((chain.height(), chain.version()), (h, 4));
}

/// "Every later release keeps the switch in its list, so that it replays the
/// chain from genesis."
#[test]
fn a_later_release_replays_the_chain_across_the_switch() {
    let h = funded_height() + 2;
    let mut chain = Chain::on(fix(h));
    let mut roots = vec![chain.root()];
    while chain.height() < h + 4 {
        let paid = chain.pay(2, 5, 300 + chain.height());
        chain.block(SECOND, vec![paid]);
        roots.push(chain.root());
    }
    assert_eq!(chain.version(), 5);
    assert_eq!(chain.log[h as usize], (SECOND, vec![switch()]));
    let first = chain.log.len() - roots.len() + 1;
    // A later release: one more version, and the switch kept.
    let later = list(&[(4, rules::SPEC_4), (5, SPEC_5), (6, SPEC_6)])
        .with_switch(Switch { network_id: network_id(), version: 5, at: SwitchAt::After { height: h } })
        .unwrap();
    let mut replay = Chain::on(later);
    assert_eq!(replay.log.len(), first);
    for (index, (delta, txs)) in chain.log[first..].iter().enumerate() {
        replay.decided(*delta, txs.clone());
        assert_eq!(replay.root(), roots[index + 1], "the replay differs at height {}", replay.height());
    }
    assert_eq!((replay.version(), replay.height()), (5, h + 4));
    // A release that dropped the switch cannot: at that block it finds a
    // transaction it accepts nowhere.
    let mut dropped = Chain::on(plain());
    for (delta, txs) in &chain.log[first..h as usize] {
        dropped.decided(*delta, txs.clone());
    }
    assert!(dropped.refused(SECOND, &[switch()]).contains("kind 81 is reserved"));
}

/// A stop in the middle of a block: a block was decided and no program
/// could execute it. A fix release names that block by its height and hash
/// and the state before it by its root, executes it with the transactions
/// it was decided with, and ends it under the new version.
#[test]
fn a_fix_release_repairs_one_decided_block_and_ends_it_under_the_new_version() {
    let h = funded_height() + 2;
    let mut control = Chain::on(old());
    while control.height() < h {
        control.block(SECOND, vec![]);
    }
    let (s, hash, parent) = (h + 1, sha(h + 1), control.root());
    let repair = |height: u64, hash: [u8; 32], parent: [u8; 32]| {
        plain()
            .with_switch(Switch {
                network_id: network_id(),
                version: 5,
                at: SwitchAt::Block { height, block_hash: hex::encode(hash), parent_root: hex::encode(parent) },
            })
            .unwrap()
    };
    let at_h = |versions: Versions| {
        let mut chain = Chain::on(versions);
        while chain.height() < h {
            chain.block(SECOND, vec![]);
        }
        assert_eq!(chain.root(), parent);
        chain
    };
    // The decided block: two payments. (These tests give block N the hash
    // `sha(N)`.)
    let mut fixed = at_h(repair(s, hash, parent));
    let (first, second) = (fixed.pay(0, 5, 1000), fixed.pay(1, 6, 2000));
    let txs = vec![first.clone(), second.clone()];
    let before = (fixed.account(5).balance, fixed.account(6).balance);
    assert_eq!(fixed.decided(2 * SECOND, txs.clone()), vec![Event::Switched { version: 5, spec: SPEC_5.into(), cancelled: None }]);
    control.decided(2 * SECOND, txs.clone());
    // Its transactions were executed, and it ended under version 5.
    assert_eq!((fixed.account(5).balance, fixed.account(6).balance), (before.0 + 1000, before.1 + 2000));
    assert_eq!((fixed.height(), fixed.version(), control.version()), (s, 5, 4));
    assert_eq!(
        fixed.activated(5).unwrap(),
        format!("{{\"elapsed_micros\":\"{}\",\"height\":\"{}\",\"notice\":\"none\",\"spec\":\"{SPEC_5}\"}}", fixed.now(), s + 1)
    );
    // Against the same block under the old rules (which, in these tests,
    // can execute it): the same rows, but for the version and its row.
    let (mut after, mut plain_rows) = (fixed.rows(), control.rows());
    assert!(after.remove(&upgrade::activated_key(5)).is_some());
    let meta = |rows: &mut BTreeMap<Vec<u8>, Vec<u8>>| -> Value { serde_json::from_slice(&rows.remove(META_KEY).unwrap()).unwrap() };
    let (mut switched, unswitched) = (meta(&mut after), meta(&mut plain_rows));
    switched["protocol_version"] = "4".into();
    assert_eq!(switched, unswitched);
    assert_eq!(after, plain_rows);
    fixed.engine.audit().unwrap();
    // It goes on under version 5, and the block is not repaired twice.
    fixed.block(SECOND, vec![]);
    assert_eq!((fixed.height(), fixed.version()), (s + 1, 5));

    // Another block at that height, or another state before it: not executed.
    let other = at_h(repair(s, sha(999), parent));
    assert!(other.refused(2 * SECOND, &txs).contains("this fix release repairs the block"));
    let other = at_h(repair(s, hash, [7; 32]));
    assert!(other.refused(2 * SECOND, &txs).contains("on the state with the root"));
    // A proposer builds nothing at that height: the block exists already.
    let other = at_h(repair(s, hash, parent));
    let (height, time, signers, _) = other.next(2 * SECOND);
    assert!(other.engine.prepare_filtered(height, time, &txs, &signers, 1 << 20, [0; 32]).is_err());
    // Kind 81 has no place in a repaired block.
    assert!(other.refused(2 * SECOND, &[first.clone(), switch()]).contains("kind 81 is reserved"));
    // A transaction that is still invalid makes the block invalid, as in
    // every block: a repair that cannot execute its block is no repair.
    assert!(other.refused(2 * SECOND, &[first.clone(), first.clone()]).contains("nonce"));
    // The block before and the block after are blocks like any other.
    let mut early = Chain::on(repair(s, hash, parent));
    while early.height() < h {
        assert_eq!(early.version(), 4);
        early.block(SECOND, vec![]);
    }
    // And on a state that passed that height without the repair, nothing.
    let mut passed = at_h(old());
    passed.block(SECOND, vec![]);
    passed.block(SECOND, vec![]);
    let passed = passed.reopen(repair(s, hash, parent));
    assert_eq!(passed.engine.missed_switch().map(|missed| (missed.block_height, missed.head)), Some((s, s + 1)));
}

/// The switch transaction as a file, for whoever builds or checks one
/// outside the engine (the cloud harness compares its own bytes with it:
/// `campaign/lib/emergency-rules.test.mjs`). Write it again with
/// `V5_EXPORT_SWITCH_FIXTURE=1 cargo test --test emergency the_fixture`.
#[test]
fn the_fixture_of_the_switch_action_is_what_this_engine_writes() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/switch-action.fixture.json");
    let expected = json!({
        "note": "The one transaction of a switch block (action kind 81) for this network, version and specification hash, as the engine writes it: v5/src/upgrade.rs, switch_action.",
        "network_id": network_id(),
        "version": "5",
        "spec": SPEC_5,
        "action_hex": hex::encode(switch()),
    });
    if std::env::var_os("V5_EXPORT_SWITCH_FIXTURE").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&expected).unwrap() + "\n").unwrap();
    }
    let stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap();
    assert_eq!(stored, expected, "tests/fixtures/switch-action.fixture.json is not what this engine writes");
}

/// The bytes of the switch: design, section 3.1.
#[test]
fn the_switch_action_is_the_unsigned_envelope_of_the_design() {
    let network = network_id();
    let payload = format!("{{\"spec\":\"{SPEC_5}\",\"version\":\"5\"}}");
    let mut expected = timecurrency_v5::wire::DOMAIN.to_vec();
    expected.extend(hex::decode(&network).unwrap());
    expected.push(81);
    expected.extend(u64::MAX.to_be_bytes());
    expected.extend([0u8; 8]);
    expected.extend([0u8; 8]);
    expected.extend([0u8; 32]);
    expected.extend((payload.len() as u32).to_be_bytes());
    expected.extend(payload.as_bytes());
    expected.extend([0u8; 64]);
    assert_eq!(switch(), expected);
    assert!(upgrade::is_switch(&switch()));
    assert_eq!(switch()[upgrade::KIND_OFFSET], upgrade::SWITCH);
    // One byte string per network, version and specification.
    assert_ne!(upgrade::switch_action(&network, 6, SPEC_5).unwrap(), switch());
    assert_ne!(upgrade::switch_action(&network, 5, SPEC_6).unwrap(), switch());
    assert_ne!(upgrade::switch_action(&"ab".repeat(32), 5, SPEC_5).unwrap(), switch());
    assert!(upgrade::switch_action("xyz", 5, SPEC_5).is_err());
    assert!(upgrade::switch_action(&network, 5, "55").is_err());
    // The envelope decoder of signed actions does not know the kind.
    assert!(timecurrency_v5::wire::decode(&switch()).is_err());
}
