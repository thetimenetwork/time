// From the independent review of the upgrade mechanism (its file
// `v5/tests/review_adv.rs`), brought into the branch unchanged except where
// a fix changed behaviour. Each such place is marked ADAPTED and quotes the
// reviewer's original line.
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
use timecurrency_v5::upgrade::{self, Params};

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
                    // ADAPTED: a validator safety hold now postpones the switch, so
                    // a plan may still be scheduled at or after its start time
                    // while a hold is on, for the time allowed. Original line:
                    //   assert!(now < plan.activate_elapsed_micros, "a plan is still scheduled at or after its start");
                    assert!(
                        now < plan.activate_elapsed_micros || (summary.safety_hold && now - plan.activate_elapsed_micros <= lab().late),
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
// Reviewer's tests. Each asserts the property the design states; a failure
// is a finding.
// ---------------------------------------------------------------------------

/// Design 3.3 / 5.1(7): "least time between two changes of one candidate's
/// signal". An entry the cleaning step drops takes its timestamp with it.
#[test]
fn review_one_change_per_interval_holds_across_cleaned_entries() {
    let mut chain = Chain::new();
    let ms = 1000u64;
    // Block 1: owner 0 names a start exactly one notice after that block.
    let t1 = chain.now() + ms;
    let first = chain.support(0, t1 + lab().notice);
    assert_eq!(chain.block(ms, vec![first.clone()]), vec![first]);
    let changed = chain.state().unwrap().entry(0).unwrap().changed_elapsed_micros;
    assert_eq!(changed, t1);
    // Block 2, one millisecond later: the entry is closer than the notice.
    chain.block(ms, vec![]);
    // Block 3, two milliseconds after its last change (interval: 1 s).
    let t3 = chain.now() + ms;
    let again = chain.support(0, t3 + 600 * SECOND);
    let kept = chain.block(ms, vec![again.clone()]);
    let since = chain.now() - changed;
    assert!(
        kept.is_empty(),
        "owner 0 changed its signal again {since} micros after its last change; the interval is {} micros",
        lab().interval
    );
}

/// How often one candidate can have a signal accepted, by naming each time
/// the nearest start the rules allow.
#[test]
fn review_signals_per_candidate_in_one_interval() {
    let mut chain = Chain::new();
    let ms = 1000u64;
    let start = chain.now();
    let mut accepted = 0;
    // 200 blocks of 1 ms: a fifth of one interval.
    for _ in 0..200 {
        let at = chain.now() + ms;
        let tx = chain.support(0, at + lab().notice);
        accepted += chain.block(ms, vec![tx]).len();
    }
    let elapsed = chain.now() - start;
    assert!(elapsed < lab().interval);
    assert!(accepted <= 1, "{accepted} changes of one candidate's signal were accepted in {elapsed} micros (interval {})", lab().interval);
}

// ADAPTED: the rule changed after this review (decision of the project lead):
// a hold at the start time postpones the switch instead of cancelling the
// plan. Original comment:
//   Design 5.3 step 3: a validator safety hold at the start time cancels the
//   plan. A hold is on for the two blocks after any validator is jailed. What
//   that lets one small validator that never signalled do, and what it costs.
/// Design 5.3 step 3: a validator safety hold at the start time postpones
/// the switch. A hold is on for the two blocks after any validator is
/// jailed. One small validator that never signalled and signs twice just
/// before the start time delays the activation by those blocks; the plan
/// survives and activates in the first block without a hold.
#[test]
fn review_what_one_jailed_validator_does_to_a_scheduled_plan() {
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
    // Up to two seconds before the start: the plan holds 4 of 5.
    chain.block(activate - chain.now() - 2 * SECOND, vec![]);
    assert_eq!(chain.plan(), Some(plan));
    let before = String::from_utf8(chain.row(&candidate_key(5)).unwrap()).unwrap();
    let (total, power) = {
        let summary = chain.summary();
        (summary.active.iter().map(|v| v.power).sum::<u64>(), summary.active.iter().find(|v| v.owner == 5).unwrap().power)
    };
    // Validator 5 signs twice; consensus reports it with the next block.
    chain.misbehavior.push(Misbehavior {
        kind: DUPLICATE_VOTE,
        address: Sha256::digest(hex::decode(pk(120)).unwrap())[..20].to_vec(),
        height: chain.height() as i64,
    });
    chain.block(SECOND, vec![]);
    assert!(chain.summary().safety_hold && chain.plan().is_some());
    // The first block dated at or after the start time.
    chain.block(SECOND, vec![]);
    assert!(chain.now() >= activate);
    // ADAPTED (added): the plan survives the jailing. In the first block
    // dated at or after its start time the hold is on: it is neither
    // activated nor cancelled.
    assert!(chain.summary().safety_hold, "the hold ended before the start time");
    let waiting = chain.plan().expect("the plan was cancelled by one jailed validator");
    assert_eq!((waiting.activate_elapsed_micros, chain.version()), (activate, 4));
    let after = String::from_utf8(chain.row(&candidate_key(5)).unwrap()).unwrap();
    eprintln!("validator 5 held {power} of {total} voting power and never signalled");
    eprintln!("candidate row before: {before}");
    eprintln!("candidate row after:  {after}");
    eprintln!("version {} plan {:?} hold {}", chain.version(), chain.plan(), chain.summary().safety_hold);
    let mut blocks = 0;
    while chain.summary().safety_hold {
        // ADAPTED (added): while the hold lasts the plan waits.
        assert_eq!((chain.plan(), chain.version()), (Some(waiting.clone()), 4));
        chain.block(SECOND, vec![]);
        blocks += 1;
    }
    eprintln!("the hold ended {blocks} block(s) later; version {}", chain.version());
    assert_eq!(chain.version(), 5, "a plan with four fifths of the votes and its full notice was cancelled by one jailed validator");
    // ADAPTED (added): it activated in the first block without a hold, after
    // its start time and inside the time allowed.
    assert!(blocks >= 1 && chain.state().is_none());
    let row: upgrade::Activated = serde_json::from_slice(&chain.row(&upgrade::activated_key(5)).unwrap()).unwrap();
    assert_eq!((row.elapsed_micros, row.height), (chain.now(), chain.height() + 1));
    assert!(row.elapsed_micros > activate && row.elapsed_micros - activate <= lab().late);
}
