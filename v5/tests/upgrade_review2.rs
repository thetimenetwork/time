// From the second pass of the independent review of the upgrade mechanism
// (its file `v5/tests/review2_adv.rs`), brought into the branch unchanged
// except where a decision taken after that review changed behaviour. Each
// such place is marked ADAPTED and quotes the reviewer's original line.
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
                    // Three quarters in the roster in force and in each
                    // announced one, by this test's own count.
                    for roster in std::iter::once(&summary.active).chain(summary.scheduled.iter().map(|set| &set.validators)) {
                        // ADAPTED: a jailed validator is now left out of the total
                        // as well as out of the support (decision of the project
                        // lead after the second review). Original line:
                        //   let total: u128 = roster.iter().map(|validator| u128::from(validator.power)).sum();
                        let total: u128 = roster
                            .iter()
                            .filter(|validator| !serde_json::from_slice::<pos::Candidate>(&self.row(&candidate_key(validator.owner)).unwrap()).unwrap().jailed)
                            .map(|validator| u128::from(validator.power))
                            .sum();
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

// ---------------------------------------------------------------------------
// Second review pass: the postponement rule and the interval fix.
// ---------------------------------------------------------------------------

fn address(seed: u8) -> Vec<u8> {
    Sha256::digest(hex::decode(pk(seed)).unwrap())[..20].to_vec()
}

/// How long a hold lasts when validators are jailed in consecutive blocks:
/// the price, in jailed validators, of each block of delay.
#[test]
fn review2_blocks_of_hold_per_jailed_validator() {
    let mut chain = Chain::new();
    for account in [5u64, 6] {
        chain.accept(chain.pay(account - 5, account, 5 * SECOND));
    }
    chain.accept(chain.register(5, 120));
    chain.accept(chain.register(6, 121));
    let mut waited = 0;
    while chain.summary().active.len() < 6 {
        chain.block(SECOND, vec![]);
        waited += 1;
        assert!(waited < 400, "the sixth validator never entered the roster");
    }
    eprintln!("six validators in force after {waited} more block(s)");
    assert!(!chain.summary().safety_hold);
    // Validator 5 is reported in one block, validator 6 in the next.
    chain.misbehavior.push(Misbehavior { kind: DUPLICATE_VOTE, address: address(120), height: chain.height() as i64 });
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold);
    chain.misbehavior.push(Misbehavior { kind: DUPLICATE_VOTE, address: address(121), height: chain.height() as i64 - 1 });
    chain.block(SECOND, vec![]);
    let mut held = 2;
    while chain.summary().safety_hold {
        chain.block(SECOND, vec![]);
        held += 1;
        assert!(held < 50, "the hold does not end");
    }
    eprintln!("two validators jailed in consecutive blocks: the hold was on for {held} block(s)");
    assert!(held <= 4, "{held}");
}

// ADAPTED: decided after this review (B): a jailed validator is left out of
// the total as well as out of the support. Original comment:
//   A supporter of the plan that is jailed: its signal stops counting at
//   once, but its voting power stays in the total until the roster without
//   it is in force two blocks later.
/// A supporter of the plan that is jailed: it is left out of the count, out
/// of the total as well as out of the support, until the roster without it
/// is in force two blocks later. The plan is judged by the validators that
/// remain, and they keep it.
#[test]
fn review2_a_jailed_supporter_and_the_plan_the_others_keep() {
    let mut chain = Chain::new();
    chain.accept(chain.pay(0, 5, 5 * SECOND));
    let activate = chain.signal_all(&[0, 1, 2, 3], 1500 * SECOND);
    chain.accept(chain.register(5, 120));
    for _ in 0..10 {
        if chain.summary().active.len() == 5 {
            break;
        }
        chain.block(SECOND, vec![]);
    }
    assert_eq!(chain.summary().active.len(), 5);
    assert!(chain.plan().is_some(), "four of five keep the plan");
    // Long before the start time, supporter 3 signs twice.
    chain.jail(3);
    chain.block(SECOND, vec![]);
    assert!(chain.now() + 1000 * SECOND < activate);
    let cancelled_at = chain.plan().is_none();
    let mut blocks = 0;
    while chain.summary().safety_hold {
        chain.block(SECOND, vec![]);
        blocks += 1;
    }
    let summary = chain.summary();
    let state = chain.state();
    let supporters = summary
        .active
        .iter()
        .filter(|validator| state.as_ref().and_then(|state| state.entry(validator.owner)).and_then(|entry| entry.proposal()).is_some())
        .count();
    eprintln!(
        "after {blocks} more block(s) the roster has {} validators, {supporters} of them with a support entry; plan: {:?}",
        summary.active.len(),
        chain.plan().map(|plan| plan.activate_elapsed_micros)
    );
    // ADAPTED: the plan is now kept, in the block that reports the jailing,
    // while the hold lasts and on the roster without the jailed validator.
    // The original final assertion, which failed before the decision and
    // holds now, is kept as it was:
    //   assert!(
    //       !cancelled_at,
    //       "one jailed supporter cancelled the plan in the block that reported it: 3 of 5 counted, although 3 of the 4 validators left when it is gone support the plan"
    //   );
    assert!(
        !cancelled_at,
        "one jailed supporter cancelled the plan in the block that reported it: 3 of 5 counted, although 3 of the 4 validators left when it is gone support the plan"
    );
    // ADAPTED (added): three of the four that remain keep it after the hold.
    assert!(blocks >= 1, "no hold followed the jailing");
    assert_eq!((summary.active.len(), supporters), (4, 3));
    assert_eq!(chain.plan().map(|plan| plan.activate_elapsed_micros), Some(activate), "the plan did not survive the hold");
    assert_eq!(chain.version(), 4);
}

// ADAPTED: decided after this review (C): the laboratory wait stays at 60
// seconds, so this pause still cancels the plan; what changed is that the
// node's log now says why without blaming a hold. Original comment:
//   Laboratory profile: the time allowed after the start is 60 seconds and
//   the block gap that cancels is an hour. A pause between the two that spans
//   the start time, with no hold at any time.
/// Laboratory profile: the time allowed after the start is 60 seconds and
/// the block gap that cancels is an hour. A pause between the two that spans
/// the start time, with no hold at any time, cancels the plan: the block
/// came more than the wait after the start time.
#[test]
fn review2_a_laboratory_pause_of_a_minute_across_the_start_time() {
    let mut chain = Chain::new();
    let activate = chain.signal_all(&[0, 1, 2, 3], 300 * SECOND);
    chain.block(activate - chain.now() - SECOND, vec![]);
    assert!(chain.plan().is_some() && !chain.summary().safety_hold);
    // The next block is dated 62 seconds after its parent, 61 after the start.
    let events = chain.events(62 * SECOND, vec![]);
    chain.block(62 * SECOND, vec![]);
    assert!(!chain.summary().safety_hold);
    eprintln!("events: {events:?}");
    // ADAPTED: the decision keeps this behaviour. Original line:
    //   assert_eq!(chain.version(), 5, "no hold was ever on, the gap is far below an hour, and the plan was cancelled: {events:?}");
    assert!(
        matches!(events.as_slice(), [Event::CancelledLate(plan)] if plan.activate_elapsed_micros == activate),
        "a pause of 62 seconds across the start time: {events:?}"
    );
    assert_eq!((chain.plan(), chain.version()), (None, 4));
    // The log line for it says what happened and blames no hold.
    let line = timecurrency_v5::app::describe_event(&events[0], chain.now(), lab().late);
    assert!(line.contains("is dated 61.000000 s after that start time, more than the 60 s a plan may wait"), "{line}");
    assert!(line.contains("or no block was dated in that time"), "{line}");
}

/// The exact boundary of "more than the wait", on the engine, with a hold
/// that lasts: the plan is still there in a block dated exactly the wait
/// after the start, and gone in the next.
#[test]
fn review2_the_deadline_is_exact_and_nothing_is_left_after_it() {
    let mut chain = Chain::new();
    let activate = chain.signal_all(&[0, 1, 2, 3], 300 * SECOND);
    let plan = chain.plan().unwrap();
    chain.block(200 * SECOND, vec![]);
    chain.jail(3);
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold);
    chain.block(activate - chain.now(), vec![]);
    assert_eq!(chain.plan(), Some(plan.clone()));
    // Exactly the wait after the start: still waiting (the hold is on).
    chain.block(lab().late, vec![]);
    assert_eq!(chain.now(), activate + lab().late);
    assert_eq!((chain.plan(), chain.version()), (Some(plan), 4));
    // One microsecond later: cancelled, never activated.
    chain.block(1, vec![]);
    assert_eq!((chain.plan(), chain.version()), (None, 4));
    // The entries of the dead plan go with the next block (or leave only
    // what still enforces the interval), and nothing is scheduled.
    chain.block(SECOND, vec![]);
    chain.block(SECOND, vec![]);
    assert!(chain.state().is_none(), "{:?}", chain.state());
    chain.engine.audit().unwrap();
}

/// The interval fix: what cleaning leaves behind restricts its owner for at
/// most one interval after that owner's own last change, and never longer.
#[test]
fn review2_what_cleaning_leaves_restricts_for_one_interval_at_most() {
    let mut chain = Chain::new();
    let ms = 1000u64;
    let t1 = chain.now() + ms;
    let first = chain.support(0, t1 + lab().notice);
    assert_eq!(chain.block(ms, vec![first.clone()]), vec![first]);
    // Cleaned in the next block: a withdrawn entry with the old change time.
    chain.block(ms, vec![]);
    let left = chain.state().unwrap().entry(0).cloned().unwrap();
    assert!(left.proposal().is_none());
    assert_eq!(left.changed_elapsed_micros, t1);
    // Withdrawing "again" changes nothing and is refused: the owner cannot
    // push its own change time forward.
    chain.refuse(chain.withdraw(0), "changes nothing");
    // Exactly one interval after its own change it signals again.
    chain.block(t1 + lab().interval - chain.now() - ms, vec![]);
    let at = chain.now() + ms;
    assert_eq!(at, t1 + lab().interval);
    let again = chain.support(0, at + 600 * SECOND);
    assert_eq!(chain.block(ms, vec![again.clone()]), vec![again]);
}
