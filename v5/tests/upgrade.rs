//! The upgrade rules on the real engine: signals, the plan and what cancels
//! it, whose signal counts, the local policy, replay and spam, the genesis
//! id bound, and where the version is read and written.
//!
//! Every block here is built by a proposer, validated strictly and executed
//! with the engine's fast paths off; the three must agree. After every block
//! the plan is checked against an independent count of its support.
//! `src/upgrade.rs` tests the state machine at its exact boundaries;
//! `upgrade_node.rs` tests the node around it.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, Misbehavior, account_key};
use timecurrency_v5::genesis::Genesis;
use timecurrency_v5::pos_adapter::{DUPLICATE_VOTE, SUMMARY_KEY, candidate_key};
use timecurrency_v5::rules::{self, Versions};
use timecurrency_v5::security::{self, Role};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;
use timecurrency_v5::upgrade::{self, Event, Params};

const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;
const SPEC_5: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn old() -> Versions {
    Versions::new([(4, rules::SPEC_4.to_string())]).unwrap()
}
fn new() -> Versions {
    Versions::new([(4, rules::SPEC_4.to_string()), (5, SPEC_5.to_string())]).unwrap()
}
fn lab() -> Params {
    Params::of(pos::Profile::Laboratory)
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    /// Reported with the next block.
    misbehavior: Vec<Misbehavior>,
}
impl Chain {
    /// The test network, on a program that implements versions 4 and 5,
    /// with validator owners 0 to 3 able to pay fees.
    fn new() -> Self {
        Self::on(genesis_v5(), new())
    }
    fn on(genesis: Genesis, versions: Versions) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(Store::open(dir.path().join("state.v5state")).unwrap(), dir.path().join("history"))
            .unwrap()
            .implementing(versions);
        engine.initialize(genesis).unwrap();
        let mut chain = Self { _dir: dir, engine, network, misbehavior: Vec::new() };
        // Until every validator owner can pay fees and fund others.
        while (0..4).any(|owner| chain.account(owner).balance < 20 * SECOND) {
            assert!(chain.height() < 80, "validator owners were not funded");
            chain.block(60 * SECOND, vec![]);
        }
        chain
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
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    fn summary(&self) -> pos::Summary {
        serde_json::from_slice(&self.row(SUMMARY_KEY).unwrap()).unwrap()
    }
    fn state(&self) -> Option<upgrade::State> {
        self.engine.upgrade_state().unwrap()
    }
    fn plan(&self) -> Option<upgrade::Plan> {
        self.state().and_then(|state| state.plan)
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
        let (proposed, kept) = self.engine.prepare_filtered_with_misbehavior(height, time, &txs, &signers, 1 << 20, hash, &misbehavior).unwrap();
        self.commit_checked(proposed, &kept, delta, &misbehavior);
        kept
    }
    /// Commits exactly `txs`, as a validator executes a decided block: the
    /// proposer's local policy plays no part.
    fn decided(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let (height, time, signers, hash) = self.next(delta);
        let misbehavior = std::mem::take(&mut self.misbehavior);
        let prepared = self
            .engine
            .prepare_with_misbehavior(height, time, &txs, &signers, hash, &misbehavior)
            .unwrap_or_else(|error| panic!("block refused: {error:#}"));
        self.commit_checked(prepared, &txs, delta, &misbehavior);
    }
    fn commit_checked(&mut self, prepared: timecurrency_v5::engine::Prepared, txs: &[Vec<u8>], delta: u64, misbehavior: &[Misbehavior]) {
        let (height, time, signers, hash) = self.next(delta);
        let strict = self.engine.prepare_with_misbehavior(height, time, txs, &signers, hash, misbehavior).unwrap();
        let reference = self.engine.prepare_reference_with_misbehavior(height, time, txs, &signers, hash, misbehavior).unwrap();
        assert_eq!(strict.root, prepared.root, "validator and proposer disagree");
        assert_eq!(reference.root, prepared.root, "fast path and reference disagree");
        let before = (self.version(), self.plan(), self.now());
        self.engine.commit(prepared, hash).unwrap();
        self.invariants(before, delta);
    }
    /// What must hold after every block, counted independently of the rule.
    fn invariants(&self, before: (u64, Option<upgrade::Plan>, u64), delta: u64) {
        let (version_before, plan_before, _) = before;
        let summary = self.summary();
        let now = self.now();
        let version = self.version();
        // A jailed validator in the roster in force or in an announced one
        // means a hold. The rule that leaves jailed validators out of the
        // count rests on it: nothing is scheduled or activated while one is
        // there, so the count is then only about keeping a scheduled plan.
        let jailed_in_a_roster = std::iter::once(&summary.active)
            .chain(summary.scheduled.iter().map(|set| &set.validators))
            .flatten()
            .any(|validator| self.jailed(validator.owner));
        assert!(!jailed_in_a_roster || summary.safety_hold, "a jailed validator is in a roster and no hold is on");
        if version != version_before {
            assert!(!jailed_in_a_roster, "activated with a jailed validator in a roster");
        }
        // The version rises by one or not at all, and only by a plan that
        // was scheduled, whose start has come, with its notice behind it, no
        // hold on, and no gap above an hour.
        assert!(version == version_before || version == version_before + 1);
        if version != version_before {
            let plan = plan_before.clone().expect("activated without a scheduled plan");
            assert_eq!(plan.version, version);
            assert!(now >= plan.activate_elapsed_micros, "activated before its start time");
            assert!(plan.activate_elapsed_micros - plan.scheduled_elapsed_micros >= lab().notice, "activated without its notice");
            assert!(!summary.safety_hold, "activated during a hold");
            assert!(delta <= lab().max_gap, "activated after a gap");
            assert!(now - plan.activate_elapsed_micros <= lab().late, "activated too long after its start time");
            assert!(self.state().is_none(), "the plan and every entry go with an activation");
            let row: upgrade::Activated = serde_json::from_slice(&self.row(&upgrade::activated_key(version)).unwrap()).unwrap();
            assert_eq!((row.height, row.elapsed_micros, row.notice.as_str(), row.spec.as_str()), (self.height() + 1, now, "scheduled", plan.spec.as_str()));
        }
        match self.state() {
            None => {}
            Some(state) => {
                assert!(!state.is_empty(), "an empty row is stored");
                if let Some(plan) = &state.plan {
                    // After a gap above an hour only a plan scheduled anew by
                    // this very block exists.
                    assert!(delta <= lab().max_gap || plan.scheduled_elapsed_micros == now, "a plan survived a gap above an hour");
                    // Only a validator safety hold keeps a plan past its
                    // start time, and only for the time allowed.
                    assert!(
                        now < plan.activate_elapsed_micros
                            || (summary.safety_hold && now - plan.activate_elapsed_micros <= lab().late && plan_before.as_ref() == Some(plan)),
                        "a plan is still scheduled at or after its start without a hold, or for too long"
                    );
                    assert_eq!(plan.version, version + 1);
                    // Three quarters of the validators that are not jailed,
                    // in the roster in force and in each announced one, by
                    // this test's own count: a jailed validator is in
                    // neither sum.
                    for roster in std::iter::once(&summary.active).chain(summary.scheduled.iter().map(|set| &set.validators)) {
                        let total: u128 = roster.iter().filter(|validator| !self.jailed(validator.owner)).map(|validator| u128::from(validator.power)).sum();
                        let support: u128 = roster
                            .iter()
                            .filter(|validator| {
                                state.entry(validator.owner).and_then(|entry| entry.proposal()) == Some(plan.proposal()) && self.counts(validator.owner)
                            })
                            .map(|validator| u128::from(validator.power))
                            .sum();
                        assert!(support * 4 >= total * 3, "a scheduled plan holds {support} of {total}");
                    }
                    if plan_before.as_ref() != Some(plan) {
                        assert_eq!(plan.scheduled_elapsed_micros, now);
                        assert!(plan.activate_elapsed_micros - now >= lab().notice, "scheduled without the notice ahead");
                        assert!(!summary.safety_hold, "scheduled during a hold");
                    }
                }
            }
        }
        if self.engine.runnable().is_ok() {
            self.engine.audit().unwrap();
        }
    }
    /// Whether the validator of `owner` is jailed, read from its row.
    fn jailed(&self, owner: u64) -> bool {
        serde_json::from_slice::<pos::Candidate>(&self.row(&candidate_key(owner)).unwrap()).unwrap().jailed
    }
    /// Whether the signal of `owner` counts now, read from the rows.
    fn counts(&self, owner: u64) -> bool {
        let candidate: pos::Candidate = serde_json::from_slice(&self.row(&candidate_key(owner)).unwrap()).unwrap();
        let frozen = self.row(&security::key(owner)).is_some_and(|row| {
            let mut security: security::Security = serde_json::from_slice(&row).unwrap();
            security.settle(self.now());
            security.frozen(self.now())
        });
        let recovering = self.row(&timecurrency_v5::engine::recovery_key(owner)).is_some_and(|row| {
            let cases: Vec<ledger::RecoveryCase> = serde_json::from_slice(&row).unwrap();
            cases.iter().any(|case| case.ready_elapsed_micros.is_some() && case.expires_elapsed_micros >= self.now())
        });
        !candidate.jailed && !frozen && !recovering
    }
    #[track_caller]
    fn accept(&mut self, tx: Vec<u8>) {
        let (height, time, signers, hash) = self.next(SECOND);
        if let Err(error) = self.engine.prepare(height, time, &[&tx], &signers, hash) {
            panic!("refused: {error:#}");
        }
        assert_eq!(self.block(SECOND, vec![tx.clone()]), vec![tx]);
    }
    /// Refused by a validator, by a proposer and by the reference path.
    #[track_caller]
    fn refuse(&mut self, tx: Vec<u8>, why: &str) {
        let (height, time, signers, hash) = self.next(SECOND);
        let error = match self.engine.prepare(height, time, &[&tx], &signers, hash) {
            Ok(_) => panic!("accepted, expected a refusal naming: {why}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains(why), "refused for another reason: {error}");
        assert!(self.engine.prepare_reference(height, time, &[&tx], &signers, hash).is_err(), "reference path accepted");
        let (_, kept) = self.engine.prepare_filtered(height, time, &[&tx], &signers, 1 << 20, hash).unwrap();
        assert!(kept.is_empty(), "proposer kept a refused transaction");
    }
    fn legacy(&self, from: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action { network_id: self.network.clone(), from, nonce: row.nonce + 1, auth_epoch: row.auth_epoch, public_key: pk(signer), payload, signature: vec![] },
            &key(signer),
        )
        .unwrap()
    }
    fn pay(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, from as u8 + 1, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn act(&self, from: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + 1, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
    }
    /// The owner of a validator supports version 5 from `activate` on.
    fn support(&self, owner: u64, activate: u64) -> Vec<u8> {
        self.support_with(owner, owner as u8 + 1, 5, activate, SPEC_5)
    }
    fn support_with(&self, owner: u64, signer: u8, version: u64, activate: u64, spec: &str) -> Vec<u8> {
        self.act(owner, signer, upgrade::SIGNAL, json!({"activate_elapsed_micros": activate.to_string(), "spec": spec, "version": version.to_string()}))
    }
    fn withdraw(&self, owner: u64) -> Vec<u8> {
        self.act(owner, owner as u8 + 1, upgrade::SIGNAL, json!({}))
    }
    /// All of `owners` support a start `ahead` from now, in one block.
    fn signal_all(&mut self, owners: &[u64], ahead: u64) -> u64 {
        let activate = self.now() + ahead;
        let txs: Vec<Vec<u8>> = owners.iter().map(|owner| self.support(*owner, activate)).collect();
        assert_eq!(self.block(SECOND, txs.clone()), txs);
        activate
    }
    /// Account `from` registers a validator with the minimum self bond.
    fn register(&self, from: u64, seed: u8) -> Vec<u8> {
        let proof = key(seed).sign(&pos::register_message(pos::hex32(&self.network).unwrap(), from, &pk(seed), 1000).unwrap());
        self.act(from, from as u8 + 1, 17, json!({"commission_bps": 1000, "consensus_key": pk(seed), "proof": hex::encode(proof.to_bytes())}))
    }
    /// What the next block, dated `delta` after the head and carrying `txs`,
    /// does to the plan, without committing it.
    fn events(&self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Event> {
        let (height, time, signers, hash) = self.next(delta);
        self.engine
            .prepare_with_misbehavior(height, time, &txs, &signers, hash, &self.misbehavior)
            .unwrap()
            .upgrade_events
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
}

#[test]
fn a_plan_is_scheduled_at_four_fifths_kept_at_three_quarters_and_activates_at_its_start() {
    let mut chain = Chain::new();
    assert!(chain.state().is_none());
    // Three of four equal validators are three quarters: not enough to schedule.
    let activate = chain.signal_all(&[0, 1, 2], 600 * SECOND);
    let state = chain.state().unwrap();
    assert!(state.plan.is_none() && state.signals.len() == 3);
    // A signal costs the fee, and takes the nonce.
    let (before, bank) = (chain.account(3), chain.engine.meta().unwrap().bank);
    chain.accept(chain.support(3, activate));
    let after = chain.account(3);
    assert_eq!(after.nonce, before.nonce + 1);
    assert!(chain.engine.meta().unwrap().bank >= bank + FEE);
    // All four: scheduled, with the time of this block.
    let plan = chain.plan().expect("scheduled");
    assert_eq!(plan, upgrade::Plan { activate_elapsed_micros: activate, scheduled_elapsed_micros: chain.now(), spec: SPEC_5.into(), version: 5 });
    assert_eq!(chain.version(), 4);
    // One withdraws: exactly three quarters, kept.
    chain.accept(chain.withdraw(0));
    assert_eq!(chain.plan(), Some(plan.clone()));
    // It supports the scheduled plan again, although the entry would be new.
    chain.accept(chain.support(0, activate));
    // Blocks go by; nothing changes before the start time.
    while chain.now() + 60 * SECOND < activate {
        chain.block(60 * SECOND, vec![]);
        assert_eq!((chain.plan(), chain.version()), (Some(plan.clone()), 4));
    }
    // The first block dated at or after the start time is the last under
    // version 4: a payment in it is executed under the old rules, and it
    // ends by writing the new version.
    let paid = chain.pay(0, 5, 1000);
    assert_eq!(chain.block(activate - chain.now() + 3, vec![paid.clone()]), vec![paid]);
    assert_eq!(chain.version(), 5);
    assert!(chain.state().is_none());
    assert_eq!(
        String::from_utf8(chain.row(&upgrade::activated_key(5)).unwrap()).unwrap(),
        format!("{{\"elapsed_micros\":\"{}\",\"height\":\"{}\",\"notice\":\"scheduled\",\"spec\":\"{SPEC_5}\"}}", chain.now(), chain.height() + 1)
    );
    // The chain runs on under version 5 with the rules of 4 unchanged.
    chain.accept(chain.pay(1, 5, 1000));
    // Replay: the old signals are worthless, by nonce and by version.
    chain.refuse(chain.support(2, chain.now() + 600 * SECOND), "the version after the one in force");
    // A signal for version 6 is valid for a validator, and no honest
    // proposer of this program includes it.
    let six = chain.support_with(2, 3, 6, chain.now() + 600 * SECOND, SPEC_5);
    assert!(chain.block(SECOND, vec![six.clone()]).is_empty());
    chain.decided(SECOND, vec![six]);
    assert_eq!(chain.state().unwrap().signals.len(), 1);
    chain.engine.audit().unwrap();
}

#[test]
fn a_plan_is_cancelled_by_lost_support_and_by_a_gap() {
    let mut chain = Chain::new();
    // Lost support: two of four withdraw.
    let activate = chain.signal_all(&[0, 1, 2, 3], 900 * SECOND);
    assert!(chain.plan().is_some());
    chain.accept(chain.withdraw(0));
    assert!(chain.plan().is_some());
    chain.accept(chain.withdraw(1));
    assert!(chain.plan().is_none(), "half of the votes kept a plan");
    assert_eq!(chain.version(), 4);
    // The same plan is scheduled again once four fifths support it again,
    // and its notice starts again.
    chain.block(SECOND, vec![chain.support(0, activate), chain.support(1, activate)]);
    let plan = chain.plan().expect("scheduled again");
    assert_eq!(plan.scheduled_elapsed_micros, chain.now());
    // A block dated more than an hour after its parent cancels a plan,
    // before its start time or at it. Exactly an hour is not such a gap. In
    // the laboratory profile it is still far more than the 60 seconds a
    // plan may be late: this one, 900 seconds ahead, is cancelled for that.
    assert_eq!(chain.events(lab().max_gap, vec![]), vec![Event::CancelledLate(plan.clone())]);
    chain.block(lab().max_gap, vec![]);
    assert!(chain.plan().is_none() && chain.version() == 4);
    // A plan whose start time such a block passes by less than that
    // activates in it: an hour exactly does not cancel.
    let mut chain = Chain::new();
    let activate = chain.signal_all(&[0, 1, 2, 3], 3590 * SECOND);
    let plan = chain.plan().expect("scheduled");
    assert_eq!(chain.events(lab().max_gap, vec![]), vec![Event::Activated(plan)]);
    chain.block(lab().max_gap, vec![]);
    assert!(chain.now() >= activate && chain.now() - activate <= lab().late && chain.version() == 5);
    let mut chain = Chain::new();
    let activate = chain.signal_all(&[0, 1, 2, 3], 3000 * SECOND);
    chain.block(60 * SECOND, vec![]);
    assert!(chain.plan().is_some());
    chain.block(lab().max_gap + 1, vec![]);
    assert!(chain.plan().is_none() && chain.version() == 4, "a halt did not cancel the plan");
    // Its entries are dropped by the next block: their start is past.
    assert!(chain.now() > activate);
    chain.block(SECOND, vec![]);
    assert!(chain.state().is_none());
    // A gap before the start time cancels as well, and the plan may be
    // scheduled anew only with a full notice ahead.
    let activate = chain.signal_all(&[0, 1, 2, 3], 3590 * SECOND);
    assert!(chain.plan().is_some());
    chain.block(lab().max_gap + 1, vec![]);
    assert!(chain.plan().is_none() && chain.now() < activate + lab().max_gap);
    chain.block(SECOND, vec![]);
    assert!(chain.state().is_none(), "less than the notice was left: the entries go");
}

/// A chain whose plan, supported by all four validators, has reached its
/// start time during a validator safety hold that does not end: validator 3
/// is jailed, and a roster of four cannot let it go. The plan waits.
fn waiting_plan() -> (Chain, upgrade::Plan, u64) {
    let mut chain = Chain::new();
    let activate = chain.signal_all(&[0, 1, 2, 3], 300 * SECOND);
    let plan = chain.plan().expect("scheduled");
    chain.block(200 * SECOND, vec![]);
    chain.jail(3);
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold);
    // The jailed validator is left out of the count: the three that remain
    // all support the plan.
    assert!(!chain.counts(3) && chain.plan().is_some());
    chain.refuse(chain.pay(0, 5, 1000), "critical validator hold");
    // The first block dated at or after the start time says that it waits.
    let to_start = activate - chain.now();
    assert_eq!(chain.events(to_start, vec![]), vec![Event::Postponed(plan.clone())]);
    chain.block(to_start, vec![]);
    assert!(chain.summary().safety_hold);
    assert_eq!((chain.plan(), chain.version()), (Some(plan.clone()), 4), "a hold at the start time neither activates nor cancels");
    (chain, plan, activate)
}

/// A hold that outlasts the time allowed after the start (60 seconds in the
/// laboratory profile, an hour in production) cancels the plan.
#[test]
fn a_hold_that_outlasts_the_time_allowed_cancels_the_plan() {
    let (mut chain, plan, activate) = waiting_plan();
    // Block after block the plan waits, and says nothing more.
    for _ in 0..3 {
        assert_eq!(chain.events(10 * SECOND, vec![]), vec![]);
        chain.block(10 * SECOND, vec![]);
        assert_eq!((chain.plan(), chain.version()), (Some(plan.clone()), 4));
    }
    // Exactly the time allowed after its start it still waits...
    chain.block(activate + lab().late - chain.now(), vec![]);
    assert!(chain.summary().safety_hold);
    assert_eq!((chain.plan(), chain.version()), (Some(plan.clone()), 4));
    // ...and the next block, dated later, cancels it.
    assert_eq!(chain.events(1, vec![]), vec![Event::CancelledLate(plan.clone())]);
    chain.block(1, vec![]);
    assert!(chain.plan().is_none() && chain.version() == 4);
    // During the hold a signal is still accepted, so support can be withdrawn.
    chain.accept(chain.withdraw(0));
    // And nothing is scheduled during a hold.
    chain.block(SECOND, vec![]);
    let later = chain.now() + 600 * SECOND;
    chain.block(SECOND, vec![chain.support(0, later), chain.support(1, later), chain.support(2, later)]);
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold && chain.plan().is_none());
    assert_eq!(chain.version(), 4);
}

/// While a plan waits for a hold to end it still needs three quarters of
/// the votes in every block.
#[test]
fn a_waiting_plan_that_loses_three_quarters_is_cancelled() {
    let (mut chain, plan, _) = waiting_plan();
    chain.block(5 * SECOND, vec![]);
    assert_eq!(chain.plan(), Some(plan.clone()));
    // The three that are not jailed all support it. One of them withdraws:
    // two of three are not three quarters.
    let withdrawal = chain.withdraw(0);
    assert_eq!(chain.events(SECOND, vec![withdrawal.clone()]), vec![Event::CancelledSupport(plan)]);
    assert_eq!(chain.block(SECOND, vec![withdrawal.clone()]), vec![withdrawal]);
    assert!(chain.summary().safety_hold);
    assert!(chain.plan().is_none() && chain.version() == 4);
}

/// While a plan waits, a block dated more than an hour after its parent
/// cancels it, as before its start time.
#[test]
fn a_waiting_plan_is_cancelled_by_a_block_gap_above_one_hour() {
    let (mut chain, plan, _) = waiting_plan();
    chain.block(5 * SECOND, vec![]);
    assert_eq!(chain.plan(), Some(plan.clone()));
    assert_eq!(chain.events(lab().max_gap + 1, vec![]), vec![Event::CancelledGap(plan)]);
    chain.block(lab().max_gap + 1, vec![]);
    assert!(chain.plan().is_none() && chain.version() == 4);
    chain.block(SECOND, vec![]);
    assert!(chain.state().is_none());
}

/// A hold that ends inside the time allowed: the plan survives the jailing
/// of a validator just before its start time and activates in the first
/// block without a hold. One validator that misbehaves delays a switch by
/// the blocks its removal takes; it does not cancel a plan the others keep.
#[test]
fn a_hold_at_the_start_time_postpones_the_switch_until_the_hold_ends() {
    let mut chain = Chain::new();
    chain.accept(chain.pay(0, 5, 5 * SECOND));
    let activate = chain.signal_all(&[0, 1, 2, 3], 1500 * SECOND);
    let plan = chain.plan().expect("scheduled");
    // A fifth validator, with the minimum bond, that never signals.
    chain.accept(chain.register(5, 120));
    for _ in 0..10 {
        if chain.summary().active.len() == 5 {
            break;
        }
        chain.block(SECOND, vec![]);
    }
    assert_eq!(chain.summary().active.len(), 5);
    chain.block(activate - chain.now() - 2 * SECOND, vec![]);
    assert_eq!(chain.plan(), Some(plan.clone()));
    // It signs twice; consensus reports it with the block before the start.
    chain.misbehavior.push(Misbehavior {
        kind: DUPLICATE_VOTE,
        address: Sha256::digest(hex::decode(pk(120)).unwrap())[..20].to_vec(),
        height: chain.height() as i64,
    });
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold && chain.plan() == Some(plan.clone()));
    // The first block dated at or after the start time: the hold is on.
    assert_eq!(chain.events(SECOND, vec![]), vec![Event::Postponed(plan.clone())]);
    chain.block(SECOND, vec![]);
    assert!(chain.now() >= activate);
    assert!(chain.summary().safety_hold, "the hold ended before the start time: this run shows nothing");
    assert_eq!((chain.plan(), chain.version()), (Some(plan.clone()), 4));
    // (This hold ends with the next block: the jailed validator leaves the
    // roster two blocks after it was reported.)
    // The hold ends when the jailed validator has left the roster. The
    // first block without it is the last under the old rules.
    let mut waited = 0;
    while chain.version() == 4 {
        assert!(waited < 20, "the plan never activated");
        let events = chain.events(SECOND, vec![]);
        chain.block(SECOND, vec![]);
        waited += 1;
        if chain.summary().safety_hold {
            assert_eq!(events, vec![]);
            assert_eq!((chain.plan(), chain.version()), (Some(plan.clone()), 4));
        } else {
            assert_eq!(events, vec![Event::Activated(plan.clone())]);
        }
    }
    assert_eq!(chain.version(), 5);
    assert!(!chain.summary().safety_hold && chain.state().is_none());
    let row: upgrade::Activated = serde_json::from_slice(&chain.row(&upgrade::activated_key(5)).unwrap()).unwrap();
    assert_eq!((row.elapsed_micros, row.height), (chain.now(), chain.height() + 1));
    assert!(row.elapsed_micros > activate && row.elapsed_micros - activate <= lab().late);
    // The chain runs on under the new version.
    chain.accept(chain.pay(1, 6, 1000));
}

#[test]
fn the_roster_may_change_between_scheduling_and_activation() {
    let mut chain = Chain::new();
    for account in [5u64, 6] {
        chain.accept(chain.pay(account - 5, account, 5 * SECOND));
    }
    let activate = chain.signal_all(&[0, 1, 2, 3], 1500 * SECOND);
    let plan = chain.plan().expect("scheduled");
    // A fifth validator that does not signal: four of five, kept.
    chain.accept(chain.register(5, 120));
    for _ in 0..10 {
        if chain.summary().active.len() == 5 {
            break;
        }
        chain.block(SECOND, vec![]);
    }
    assert_eq!(chain.summary().active.len(), 5);
    assert_eq!(chain.plan(), Some(plan.clone()));
    // Close to the start time, with less than the notice left, the new
    // validator can still support the scheduled plan, and no other.
    chain.block(activate - chain.now() - 100 * SECOND, vec![]);
    assert_eq!(chain.plan(), Some(plan.clone()));
    chain.refuse(chain.support(5, activate + 1), "between the notice and the farthest start");
    chain.accept(chain.support(5, activate));
    assert_eq!(chain.state().unwrap().signals.len(), 5);
    chain.accept(chain.withdraw(5));
    assert_eq!(chain.plan(), Some(plan));
    // A sixth that does not signal leaves four of six: cancelled as soon as
    // that roster is announced, before it is in force.
    chain.accept(chain.register(6, 121));
    let announced = |chain: &Chain| {
        let summary = chain.summary();
        chain.plan().is_none() && summary.active.len() == 5 && summary.scheduled.iter().any(|set| set.validators.len() == 6)
    };
    let mut announced_first = announced(&chain);
    for _ in 0..40 {
        if chain.plan().is_none() {
            break;
        }
        chain.block(SECOND, vec![]);

        if announced(&chain) {
            announced_first = true;
        }
    }
    assert!(chain.plan().is_none(), "four of six kept a plan");
    assert!(announced_first, "the plan was cancelled only once the roster was in force");
    assert!(chain.now() < activate);
    assert_eq!(chain.version(), 4);
}

#[test]
fn a_frozen_or_recovering_owner_does_not_count_and_counts_again_when_the_freeze_ends() {
    let mut chain = Chain::new();
    // Owner 0 secures its account: one sign-in key, one spend key, three
    // recovery keys.
    let accepts = |chain: &Chain, seed: u8, role: Role, name: &str| {
        let proof = key(seed).sign(&security::key_message(&chain.network, 0, role, &pk(seed)).unwrap());
        json!({"public_key": pk(seed), "role": name, "proof": hex::encode(proof.to_bytes())})
    };
    let mut keys = vec![
        accepts(&chain, 60, Role::Signin, "signin"),
        accepts(&chain, 61, Role::Spend, "spend"),
        accepts(&chain, 62, Role::Recover, "recover"),
        accepts(&chain, 63, Role::Recover, "recover"),
    ];
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    let policy = json!({"threshold": "2", "daily_limit_micros": "500000", "delay_seconds": "60", "freeze_seconds": "120"});
    chain.accept(chain.act(0, 1, security::SECURE, json!({"keys": keys, "policy": policy})));
    let activate = chain.now() + 2000 * SECOND;
    // Which key: a spend key signals. A sign-in key and a recovery key do not.
    chain.refuse(chain.support_with(0, 60, 5, activate, SPEC_5), "spending device required");
    chain.refuse(chain.support_with(0, 62, 5, activate, SPEC_5), "spending device required");
    chain.refuse(chain.support_with(0, 1, 5, activate, SPEC_5), "spending device required");
    // One recovery key freezes the account. While it is frozen its spend
    // key cannot signal at all: the fee would lower the balance...
    let mine: security::Security = serde_json::from_slice(&chain.row(&security::key(0)).unwrap()).unwrap();
    let freeze = json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": (chain.now() + 600 * SECOND).to_string()});
    chain.accept(timecurrency_v5::wire::sign(&chain.network, 0, 0, 0, security::FREEZE, &freeze, &key(62)).unwrap());
    assert!(!chain.counts(0));
    chain.refuse(chain.support_with(0, 61, 5, activate, SPEC_5), "account is frozen");
    let frozen: security::Security = serde_json::from_slice(&chain.row(&security::key(0)).unwrap()).unwrap();
    let frozen_until = frozen.frozen_until_elapsed_micros;
    assert!(frozen_until > chain.now());
    // ...so the other three signal: three quarters, nothing is scheduled.
    assert_eq!(chain.signal_all(&[1, 2, 3], activate - chain.now()), activate);
    assert!(chain.plan().is_none());
    // The freeze ends by time alone; the owner signals; all four count.
    chain.block(frozen_until - chain.now() + SECOND, vec![]);
    assert!(chain.counts(0));
    chain.accept(chain.support_with(0, 61, 5, activate, SPEC_5));
    let plan = chain.plan().expect("scheduled once the freeze had ended");
    // Frozen again: its signal stops counting at once, without any action
    // of the spend key. Three of four keep the plan; one more loss ends it.
    let mine: security::Security = serde_json::from_slice(&chain.row(&security::key(0)).unwrap()).unwrap();
    let freeze = json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": (chain.now() + 600 * SECOND).to_string()});
    chain.accept(timecurrency_v5::wire::sign(&chain.network, 0, 0, 0, security::FREEZE, &freeze, &key(63)).unwrap());
    assert!(!chain.counts(0));
    assert_eq!(chain.plan(), Some(plan.clone()), "three quarters keep");
    // A protocol-4 owner whose guardians have a recovery ready does not
    // count either: owner 1, guardians 8, 9 and 10, two of them needed.
    chain.accept(chain.pay(2, 8, 2 * SECOND));
    chain.accept(chain.pay(2, 9, 2 * SECOND));
    chain.accept(chain.legacy(1, 2, ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![8, 9, 10], threshold: 2, delay_seconds: 30 })));
    for guardian in [8u64, 9] {
        let version = chain.account(1).recovery_version;
        chain.accept(chain.legacy(guardian, guardian as u8 + 1, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 1, policy_version: version, accept: true })));
    }
    let row = chain.account(1);
    let recovery_id = hex::encode(sha(77));
    let expiry = chain.now() + 30 * SECOND + 7 * pos::DAY;
    let mut message = b"TCDEVNET-RECOVERY-V1\0".to_vec();
    message.extend(hex::decode(&chain.network).unwrap());
    message.extend(1u64.to_be_bytes());
    message.extend(row.auth_epoch.to_be_bytes());
    message.extend(row.recovery_version.to_be_bytes());
    message.extend(hex::decode(&recovery_id).unwrap());
    message.extend(key(200).verifying_key().as_bytes());
    message.extend(expiry.to_be_bytes());
    let claim = ledger::ApproveRecovery {
        target: 1,
        policy_version: row.recovery_version,
        recovery_id,
        new_public_key: pk(200),
        expires_elapsed_micros: expiry,
        proof: hex::encode(key(200).sign(&message).to_bytes()),
    };
    chain.accept(chain.legacy(8, 9, ActionPayload::ApproveRecovery(claim.clone())));
    assert!(chain.counts(1) && chain.plan().is_some(), "one approval is not a recovery");
    chain.accept(chain.legacy(9, 10, ActionPayload::ApproveRecovery(claim)));
    assert!(!chain.counts(1));
    assert!(chain.plan().is_none(), "a frozen and a recovering owner out of four: half is not three quarters");
    assert_eq!(chain.version(), 4);
}

#[test]
fn each_signal_is_judged_by_its_sender_its_form_its_times_and_the_interval() {
    let mut chain = Chain::new();
    let now = chain.now();
    let good = now + 600 * SECOND;
    // Not the owner of a validator candidate.
    chain.accept(chain.pay(0, 5, 5 * SECOND));
    chain.refuse(chain.support(5, good), "only the owner account of a validator candidate");
    chain.refuse(chain.withdraw(5), "only the owner account of a validator candidate");
    // The payload: one of two byte strings.
    for (payload, why) in [
        (json!({"version": "5"}), "a signal payload is"),
        (json!({"activate_elapsed_micros": good.to_string(), "spec": SPEC_5, "version": "5", "note": "x"}), "a signal payload is"),
        (json!({"activate_elapsed_micros": good.to_string(), "spec": SPEC_5.to_uppercase().replace('5', "A"), "version": "5"}), "a signal payload is"),
        (json!({"activate_elapsed_micros": format!("0{good}"), "spec": SPEC_5, "version": "5"}), "a signal payload is"),
        (json!({"activate_elapsed_micros": good, "spec": SPEC_5, "version": 5}), "a signal payload is"),
        (json!({"withdraw": true}), "a signal payload is"),
    ] {
        chain.refuse(chain.act(0, 1, upgrade::SIGNAL, payload), why);
    }
    // The version: the one in force plus one.
    for version in [4u64, 6, 0] {
        chain.refuse(chain.support_with(0, 1, version, good, SPEC_5), "the version after the one in force");
    }
    // The start time, judged on the time of the block that carries it (one
    // second after the head here): from the notice to the farthest start.
    let block_time = chain.now() + SECOND;
    chain.refuse(chain.support(0, block_time + lab().notice - 1), "between the notice and the farthest start");
    chain.refuse(chain.support(0, block_time + lab().farthest + 1), "between the notice and the farthest start");
    chain.refuse(chain.support(0, 1), "between the notice and the farthest start");
    // The ordinary checks: nonce, authority epoch, network, key, signature.
    let row = chain.account(0);
    let payload = json!({"activate_elapsed_micros": good.to_string(), "spec": SPEC_5, "version": "5"});
    let sign = |network: &str, nonce: u64, epoch: u64, signer: u8| timecurrency_v5::wire::sign(network, 0, nonce, epoch, upgrade::SIGNAL, &payload, &key(signer)).unwrap();
    chain.refuse(sign(&chain.network, row.nonce, row.auth_epoch, 1), "stale authority or incorrect nonce");
    chain.refuse(sign(&chain.network, row.nonce + 2, row.auth_epoch, 1), "stale authority or incorrect nonce");
    chain.refuse(sign(&chain.network, row.nonce + 1, row.auth_epoch + 1, 1), "stale authority or incorrect nonce");
    chain.refuse(sign(&"ab".repeat(32), row.nonce + 1, row.auth_epoch, 1), "wrong network");
    chain.refuse(sign(&chain.network, row.nonce + 1, row.auth_epoch, 2), "spending device required");
    let mut forged = sign(&chain.network, row.nonce + 1, row.auth_epoch, 1);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    chain.refuse(forged, "invalid action signature");
    // At the bounds it is accepted.
    chain.accept(chain.support(0, block_time + lab().notice));
    // It must change something.
    // The same plan a block later is too close, and so is judged before "it changes nothing".
    chain.refuse(chain.support(0, block_time + lab().notice), "between the notice and the farthest start");
    chain.refuse(chain.withdraw(1), "changes nothing");
    // Replay: the same bytes again.
    let again = chain.support(1, good);
    chain.accept(again.clone());
    chain.refuse(again, "stale authority or incorrect nonce");
    // Spam: one change per candidate per interval. Two in one block: the
    // second is left out by the proposer and makes a decided block invalid.
    let first = chain.support(2, good);
    let mut row = chain.account(2);
    row.nonce += 1;
    let second = timecurrency_v5::wire::sign(&chain.network, 2, row.nonce + 1, row.auth_epoch, upgrade::SIGNAL, &json!({}), &key(3)).unwrap();
    let (height, time, signers, hash) = chain.next(SECOND);
    let error = format!("{:#}", chain.engine.prepare(height, time, &[&first, &second], &signers, hash).err().expect("two changes in one block"));
    assert!(error.contains("at most once per interval"), "{error}");
    assert_eq!(chain.block(SECOND, vec![first.clone(), second]), vec![first]);
    // A second later the candidate may change its signal.
    chain.accept(chain.withdraw(2));
    // The row is written once per block whatever the number of signals, and
    // is one row.
    let state = chain.state().unwrap();
    // (Owner 0's entry is gone already: its start came closer than the notice.)
    assert_eq!(state.signals.iter().map(|entry| entry.owner).collect::<Vec<_>>(), vec![1, 2]);
    assert!(state.signals[1].proposal().is_none() && state.plan.is_none());
    // The withdrawn entry goes once the interval has passed; the support
    // entries whose start is now closer than the notice go as well.
    chain.block(SECOND, vec![]);
    assert_eq!(chain.state().unwrap().signals.len(), 1);
    chain.block(600 * SECOND, vec![]);
    assert!(chain.state().is_none(), "stale entries were kept");
    assert!(chain.row(upgrade::STATE_KEY).is_none());
}

#[test]
fn the_local_policy_is_in_admission_and_proposal_only() {
    // A program that implements version 4 only, as release 1 does.
    let mut chain = Chain::on(genesis_v5(), old());
    let good = chain.now() + 600 * SECOND;
    let signal = chain.support(0, good);
    // Mempool admission refuses a support signal for rules it lacks...
    let refusal = |result: anyhow::Result<()>| format!("{:#}", result.expect_err("admitted"));
    assert!(refusal(chain.engine.validate_tx(&signal)).contains("does not implement"));
    let mut pending = chain.engine.check_state().unwrap();
    assert!(refusal(pending.admit(&signal, SigStatus::Unknown)).contains("does not implement"));
    // ...and its proposer leaves it out...
    assert!(chain.block(SECOND, vec![signal.clone()]).is_empty());
    assert!(chain.state().is_none());
    // ...but a decided block that carries it is executed like any other:
    // the plan is consensus, the policy is not.
    let signal = chain.support(0, good);
    chain.decided(SECOND, vec![signal]);
    assert_eq!(chain.state().unwrap().signals.len(), 1);
    // A withdrawal is admitted and proposed by any program.
    // (Not in the same second as the change before it: admission judges
    // the interval on the clock of the last block.)
    assert!(refusal(chain.engine.validate_tx(&chain.withdraw(0))).contains("at most once per interval"));
    chain.block(SECOND, vec![]);
    let withdrawal = chain.withdraw(0);
    chain.engine.validate_tx(&withdrawal).unwrap();
    assert_eq!(chain.block(SECOND, vec![withdrawal.clone()]), vec![withdrawal]);
    // Even a plan every validator signalled for is scheduled on this program.
    let txs: Vec<Vec<u8>> = (0..4).map(|owner| chain.support(owner, good)).collect();
    chain.decided(SECOND, txs);
    assert!(chain.plan().is_some());
    // A program that implements the plan admits it, with the margin: a
    // start the next block could no longer accept is not admitted, though a
    // proposer, who knows the block's time, includes it.
    let mut chain = Chain::new();
    let other_spec = chain.support_with(0, 1, 5, chain.now() + 600 * SECOND, &"66".repeat(32));
    assert!(refusal(chain.engine.validate_tx(&other_spec)).contains("does not implement"));
    let close = chain.support(0, chain.now() + lab().notice + 20 * SECOND);
    assert!(refusal(chain.engine.validate_tx(&close)).contains("too close"));
    let mut pending = chain.engine.check_state().unwrap();
    assert!(refusal(pending.admit(&close, SigStatus::Unknown)).contains("too close"));
    let fine = chain.support(0, chain.now() + lab().notice + 30 * SECOND);
    pending.admit(&fine, SigStatus::Unknown).unwrap();
    // Admitted signals count against what follows them in the mempool: one
    // change per candidate.
    let mut row = chain.account(0);
    row.nonce += 1;
    let second = timecurrency_v5::wire::sign(&chain.network, 0, row.nonce + 1, row.auth_epoch, upgrade::SIGNAL, &json!({}), &key(1)).unwrap();
    assert!(refusal(pending.admit(&second, SigStatus::Unknown)).contains("at most once per interval"));
    assert_eq!(chain.block(SECOND, vec![close.clone()]), vec![close]);
}

#[test]
fn the_reserved_kind_81_is_never_accepted() {
    let mut chain = Chain::new();
    let payload = format!("{{\"spec\":\"{SPEC_5}\",\"version\":\"5\"}}");
    // The form a fix release will use, and anything else under that kind.
    let unsigned = {
        let mut raw = timecurrency_v5::wire::DOMAIN.to_vec();
        raw.extend(hex::decode(&chain.network).unwrap());
        raw.push(upgrade::SWITCH);
        raw.extend(u64::MAX.to_be_bytes());
        raw.extend([0u8; 16]);
        raw.extend([0u8; 32]);
        raw.extend((payload.len() as u32).to_be_bytes());
        raw.extend(payload.as_bytes());
        raw.extend([0u8; 64]);
        raw
    };
    assert!(upgrade::is_switch(&unsigned));
    let signed = raw_action(&chain.network, upgrade::SWITCH, 0, chain.account(0).nonce + 1, 0, 1, payload.as_bytes());
    for tx in [unsigned, signed] {
        assert!(format!("{:#}", chain.engine.validate_tx(&tx).unwrap_err()).contains("kind 81 is reserved"));
        chain.refuse(tx, "kind 81 is reserved");
    }
    assert!(timecurrency_v5::wire::decode(&raw_action(&chain.network, upgrade::SWITCH, 0, 1, 0, 1, b"{}")).is_err());
    assert!(!upgrade::is_switch(&chain.pay(0, 5, 1)));
}

#[test]
fn a_program_executes_nothing_on_a_head_it_does_not_implement() {
    // Two engines from one source on the same blocks.
    let mut newer = Chain::new();
    let mut older = Chain::on(genesis_v5(), old());
    assert_eq!(older.engine.head().unwrap().unwrap().root, newer.engine.head().unwrap().unwrap().root);
    let activate = newer.now() + 300 * SECOND;
    let mut blocks: Vec<(u64, Vec<Vec<u8>>)> = vec![(SECOND, (0..4).map(|owner| newer.support(owner, activate)).collect())];
    blocks.push((100 * SECOND, vec![]));
    blocks.push((250 * SECOND, vec![]));
    for (delta, txs) in blocks {
        assert!(older.engine.runnable().is_ok());
        newer.decided(delta, txs.clone());
        older.decided(delta, txs);
        assert_eq!(older.engine.head().unwrap(), newer.engine.head().unwrap(), "the two programs differ");
    }
    assert_eq!((older.version(), newer.version()), (5, 5));
    // The same state, the activating block included. Then the old one runs
    // nothing more: no block, no admission, no recount.
    let reason = older.engine.runnable().unwrap_err().clone();
    assert_eq!((reason.version, reason.head, reason.from_height, reason.spec.as_deref()), (5, older.height(), Some(older.height() + 1), Some(SPEC_5)));
    assert!(newer.engine.runnable().is_ok());
    let (height, time, signers, hash) = older.next(SECOND);
    let none: [Vec<u8>; 0] = [];
    let refused = |result: anyhow::Result<()>| format!("{:#}", result.expect_err("ran on a head it does not implement"));
    assert!(refused(older.engine.prepare(height, time, &none, &signers, hash).map(|_| ())).contains("does not implement protocol version 5"));
    assert!(refused(older.engine.prepare_filtered(height, time, &none, &signers, 1 << 20, hash).map(|_| ())).contains("does not implement"));
    assert!(refused(older.engine.prepare_reference(height, time, &none, &signers, hash).map(|_| ())).contains("does not implement"));
    assert!(refused(older.engine.validate_tx(&newer.pay(0, 5, 1))).contains("does not implement"));
    assert!(refused(older.engine.check_state().map(|_| ())).contains("does not implement"));
    assert!(refused(older.engine.audit().map(|_| ())).contains("does not implement"));
    // The new one goes on, and its recount covers the activation row.
    newer.accept(newer.pay(0, 5, 1000));
    newer.engine.audit().unwrap();
}

#[test]
fn genesis_account_ids_are_below_two_to_the_forty_eight() {
    let open = || {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(Store::open(dir.path().join("state")).unwrap()).unwrap();
        (dir, engine)
    };
    let with_last = |id: u64| {
        let mut genesis = genesis_v5();
        genesis.ledger.accounts.last_mut().unwrap().id = id;
        genesis
    };
    let limit = 1u64 << 48;
    assert_eq!(timecurrency_v5::genesis::MAX_GENESIS_ACCOUNT_ID, limit);
    for (id, accepted) in [(GENESIS_ACCOUNTS - 1, true), (limit - 1, true), (limit, false), (limit + 1, false), (u64::MAX - 1, false)] {
        let (_dir, mut engine) = open();
        let result = engine.initialize(with_last(id));
        assert_eq!(result.is_ok(), accepted, "{id}");
        if let Err(error) = result {
            assert!(format!("{error:#}").contains("below 2^48"), "{error:#}");
            assert!(engine.head().unwrap().is_none());
        } else {
            // Registration counts up from there.
            assert_eq!(engine.meta().unwrap().next_account_id, id + 1);
        }
    }
    // A state that exists is still opened: the bound is on new networks.
    assert!(with_last(limit).validate().is_ok() && with_last(limit).validate_new().is_err());
    // A repeated InitChain on a database that exists is judged without the
    // bound, as it was before the bound existed, and returns the same head.
    assert!(with_last(limit).validate_initial().is_ok());
    let (_dir, mut engine) = open();
    let head = engine.initialize(genesis_v5()).unwrap();
    assert_eq!(engine.initialize(genesis_v5()).unwrap(), head);
    assert!(engine.initialize(with_last(limit - 1)).is_err(), "another genesis was accepted on an existing database");
}

/// `meta.protocol_version` is written in one place after genesis and read
/// through `Rules`, in `Meta::validate` and where `app.rs` reports it. Any
/// other use fails here, so that whoever adds one looks at this rule.
#[test]
fn the_version_is_written_in_one_place_and_read_through_the_gate() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = std::collections::BTreeMap::new();
    let mut pending = vec![source.clone()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let uses: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with("//") && line.contains("protocol_version"))
                .map(str::to_string)
                .collect();
            if !uses.is_empty() {
                found.insert(path.strip_prefix(&source).unwrap().to_string_lossy().replace('\\', "/"), uses);
            }
        }
    }
    let files: Vec<&str> = found.keys().map(String::as_str).collect();
    assert_eq!(files, vec!["app.rs", "engine.rs", "rules.rs"], "{found:#?}");
    // rules.rs: the gate reads it.
    assert_eq!(found["rules.rs"], vec!["Self(meta.protocol_version)"]);
    // engine.rs: the field, the check "4 or more", the genesis value, the
    // one write at an activation, and the unrelated field of the protocol-4
    // ledger view.
    let engine = &found["engine.rs"];
    assert_eq!(engine.len(), 6, "{engine:#?}");
    assert!(engine.contains(&"let text = value.get(\"protocol_version\")?.as_str()?;".to_string()), "{engine:#?}");
    assert_eq!(engine.iter().filter(|line| line.contains("protocol_version =") && !line.contains("==")).count(), 1, "{engine:#?}");
    assert!(engine.contains(&"self.meta.protocol_version = *version;".to_string()));
    assert!(engine.contains(&"self.protocol_version >= rules::FIRST_VERSION && *self.genesis == self.config.ledger,".to_string()));
    assert!(engine.contains(&"protocol_version: rules::FIRST_VERSION,".to_string()));
    assert!(engine.contains(&"protocol_version: 1,".to_string()));
    // No equality with a version number anywhere.
    for (file, uses) in &found {
        for line in uses {
            assert!(!line.contains("protocol_version ==") && !line.contains("protocol_version !="), "{file}: {line}");
        }
    }
    // app.rs only reports it: none of its uses assigns or compares.
    assert!(found["app.rs"].iter().all(|line| !line.contains("protocol_version =")), "{:#?}", found["app.rs"]);
    // The gate is used, not a comparison, where a rule depends on the version.
    let engine_text = std::fs::read_to_string(source.join("engine.rs")).unwrap();
    assert!(engine_text.contains("if self.rules.since(4)"));
}

/// Five equal validators, four of which support a scheduled plan; the fifth,
/// owned by account 5, has the minimum bond and never signals.
fn four_of_five() -> (Chain, upgrade::Plan, u64) {
    let mut chain = Chain::new();
    chain.accept(chain.pay(0, 5, 5 * SECOND));
    let activate = chain.signal_all(&[0, 1, 2, 3], 1500 * SECOND);
    let plan = chain.plan().expect("scheduled");
    chain.accept(chain.register(5, 120));
    for _ in 0..10 {
        if chain.summary().active.len() == 5 {
            break;
        }
        chain.block(SECOND, vec![]);
    }
    assert_eq!(chain.summary().active.len(), 5);
    assert_eq!(chain.plan(), Some(plan.clone()));
    (chain, plan, activate)
}
fn owners(chain: &Chain) -> Vec<u64> {
    chain.summary().active.iter().map(|validator| validator.owner).collect()
}

/// A supporter that signs twice does not cancel a plan the others keep. It
/// is left out of the count, total and support alike, until it has left the
/// roster; three of the four that remain keep the plan, and it activates at
/// its start time. (Counted in the total, the jailed supporter made it three
/// of five, and the plan was cancelled in the block that reported it.)
#[test]
fn a_jailed_supporter_does_not_cancel_a_plan_the_others_keep() {
    let (mut chain, plan, activate) = four_of_five();
    chain.jail(3);
    assert_eq!(chain.events(SECOND, vec![]), vec![]);
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold && chain.jailed(3) && owners(&chain).contains(&3));
    assert_eq!(chain.plan(), Some(plan.clone()), "one jailed supporter cancelled the plan");
    let mut blocks = 0;
    while chain.summary().safety_hold {
        chain.block(SECOND, vec![]);
        blocks += 1;
        assert!(blocks < 20, "the hold does not end");
        assert_eq!(chain.plan(), Some(plan.clone()));
    }
    // The roster without it: four validators, three of them support.
    assert_eq!(owners(&chain), vec![0, 1, 2, 5]);
    assert_eq!(chain.plan(), Some(plan.clone()));
    // Its entry is still in the row and still does not count.
    assert!(chain.state().unwrap().entry(3).is_some() && !chain.counts(3));
    chain.block(activate - chain.now(), vec![]);
    assert_eq!(chain.version(), 5);
}

/// What the rule does not do: a second supporter jailed leaves two of the
/// three that remain, which is not three quarters. The plan is cancelled.
#[test]
fn two_jailed_supporters_leave_too_few_and_the_plan_is_cancelled() {
    let (mut chain, plan, _) = four_of_five();
    chain.jail(3);
    chain.block(SECOND, vec![]);
    while chain.summary().safety_hold {
        chain.block(SECOND, vec![]);
    }
    assert_eq!((owners(&chain), chain.plan()), (vec![0, 1, 2, 5], Some(plan.clone())));
    chain.jail(2);
    assert_eq!(chain.events(SECOND, vec![]), vec![Event::CancelledSupport(plan)]);
    chain.block(SECOND, vec![]);
    assert!(chain.plan().is_none() && chain.version() == 4);
}

/// The other direction. A jailed validator that does not support the plan
/// is left out of the total too, which raises the share of the others to
/// their share of the validators that remain. That helps no plan to be
/// scheduled: while it is in a roster a hold is on and nothing is scheduled,
/// even with every validator that remains in support; when the hold has
/// ended the plan is judged, and scheduled, by the roster really in force.
#[test]
fn a_jailed_validator_that_does_not_support_helps_no_plan_to_be_scheduled() {
    let mut chain = Chain::new();
    chain.accept(chain.pay(0, 5, 5 * SECOND));
    chain.accept(chain.register(5, 120));
    for _ in 0..10 {
        if chain.summary().active.len() == 5 {
            break;
        }
        chain.block(SECOND, vec![]);
    }
    assert_eq!(owners(&chain), vec![0, 1, 2, 3, 5]);
    let activate = chain.now() + 1500 * SECOND;
    // Three of five support: no plan.
    let three: Vec<Vec<u8>> = (0..3).map(|owner| chain.support(owner, activate)).collect();
    assert_eq!(chain.block(SECOND, three.clone()), three);
    assert!(chain.plan().is_none());
    // Validator 5 signs twice. In the block that reports it owner 3 signals
    // as well: all four validators that remain support the plan.
    chain.misbehavior.push(Misbehavior {
        kind: DUPLICATE_VOTE,
        address: Sha256::digest(hex::decode(pk(120)).unwrap())[..20].to_vec(),
        height: chain.height() as i64,
    });
    let fourth = chain.support(3, activate);
    assert_eq!(chain.events(SECOND, vec![fourth.clone()]), vec![]);
    assert_eq!(chain.block(SECOND, vec![fourth.clone()]), vec![fourth]);
    assert!(chain.summary().safety_hold && chain.jailed(5));
    assert!(chain.plan().is_none(), "a plan was scheduled while a jailed validator was in a roster");
    let mut blocks = 0;
    while chain.summary().safety_hold {
        assert!(chain.plan().is_none(), "a plan was scheduled during the hold");
        chain.block(SECOND, vec![]);
        blocks += 1;
        assert!(blocks < 20, "the hold does not end");
    }
    // The block that ended the hold: the roster is the four, all of them
    // support, and the plan is scheduled by that block, with its time.
    assert_eq!(owners(&chain), vec![0, 1, 2, 3]);
    let plan = chain.plan().expect("scheduled once the hold had ended");
    assert_eq!((plan.activate_elapsed_micros, plan.scheduled_elapsed_micros), (activate, chain.now()));
    // Three of those four keep it; two do not.
    chain.accept(chain.withdraw(0));
    assert_eq!(chain.plan(), Some(plan), "three of four keep");
    chain.accept(chain.withdraw(1));
    assert!(chain.plan().is_none(), "two of four kept a plan");
}

/// The laboratory profile allows a plan to be 60 seconds late, and the gap
/// that cancels is an hour. A pause in block production of more than those
/// 60 seconds across the start time cancels the plan there with no hold at
/// any time, and the log line says that, not that a hold lasted.
#[test]
fn in_the_laboratory_a_pause_of_over_a_minute_across_the_start_time_cancels_the_plan() {
    let mut chain = Chain::new();
    let activate = chain.signal_all(&[0, 1, 2, 3], 300 * SECOND);
    let plan = chain.plan().expect("scheduled");
    chain.block(activate - chain.now() - SECOND, vec![]);
    // A block exactly the wait after the start time would still activate.
    assert_eq!(chain.events(SECOND + lab().late, vec![]), vec![Event::Activated(plan.clone())]);
    // One dated later cancels, although no hold is or was on.
    let events = chain.events(SECOND + lab().late + 1, vec![]);
    assert_eq!(events, vec![Event::CancelledLate(plan.clone())]);
    chain.block(SECOND + lab().late + 1, vec![]);
    assert!(!chain.summary().safety_hold);
    assert_eq!((chain.plan(), chain.version()), (None, 4));
    let line = timecurrency_v5::app::describe_event(&events[0], chain.now(), lab().late);
    assert!(line.starts_with("Upgrade cancelled:"), "{line}");
    assert!(line.contains("is dated 60.000001 s after that start time, more than the 60 s a plan may wait"), "{line}");
    assert!(line.contains("either a validator safety hold lasted that long, or no block was dated in that time"), "{line}");
    // In production the wait is the hour of the gap rule: there the first
    // block at or after the start time is never too late without also being
    // a gap, and the line for a gap names the gap.
    let production = Params::of(pos::Profile::Production);
    assert_eq!(production.late, production.max_gap);
}
