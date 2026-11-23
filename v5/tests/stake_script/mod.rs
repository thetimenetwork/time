//! One scripted run of 52 blocks on three networks, shared by
//! `records_unchanged.rs`, which recorded its roots before the service
//! records (`service_records`) existed, and `service_records.rs`, which runs
//! it with them.
//!
//! The run touches everything the service records describe, on purpose:
//!
//! - seven starting validators sign, and some blocks leave the signatures of
//!   one or two of them out;
//! - accounts are registered (kind 2, and kind 45 where the network takes
//!   it);
//! - stake goes in and out in every way the staking rules allow: a
//!   registration with more than the minimum self bond (kind 17), self
//!   bonds (18), delegations (5), partial and full undelegations (6),
//!   partial and full self unbonds (19), withdrawals of a delegated and of a
//!   self exit (7, 21), the retirement of a validator without a self bond
//!   once its fourteen days have passed, and a new registration of the same
//!   owner with a new consensus key;
//! - one starting validator is punished through the misbehavior CometBFT
//!   reports and another through an evidence action (kind 20);
//! - the chain stands still for fifteen days and for three hours.
//!
//! Nothing here names the service records, so that the file compiles and
//! runs on the engine from before them. The script reads the chain only
//! through `View` and says what each block holds; the test that runs it
//! builds and executes the blocks.
#![allow(dead_code)]
use crate::common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, Meta, Misbehavior, account_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::pos_adapter::{self, DUPLICATE_VOTE};
use timecurrency_v5::security::{self, Role};

pub const SECOND: u64 = 1_000_000;
pub const MINUTE: u64 = 60 * SECOND;
pub const HOUR: u64 = 3_600 * SECOND;
pub const DAY: u64 = 24 * HOUR;
/// Blocks in the run.
pub const BLOCKS: i64 = 52;
/// The genesis account that registers a validator, retires it and registers
/// again with another consensus key (key seeds `FIRST_KEY`, `SECOND_KEY`).
pub const NEWCOMER: u64 = 8;
pub const FIRST_KEY: u8 = 120;
pub const SECOND_KEY: u8 = 121;
/// The starting validator punished through the misbehavior CometBFT reports
/// (block 25), and the one punished by an evidence action (block 29).
pub const REPORTED: u64 = 6;
pub const EVIDENCED: u64 = 5;
/// The account that delegates to validators 0 and `NEWCOMER`.
pub const DELEGATOR: u64 = 9;

/// The networks of the run: the protocol-4 settings; every optional setting
/// that existed before the service records; and all new time to validators
/// without the stake hand-over rule, whose starting validators stake most of
/// their reward. All have seven starting validators.
pub fn variants() -> Vec<(&'static str, Genesis)> {
    let seven = |mut genesis: Genesis| {
        genesis.validators = (0..7)
            .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
            .collect();
        genesis
    };
    let plain = seven(genesis_v5());
    let mut everything = seven(genesis_v5());
    everything.all_new_time_to_validators = true;
    everything.stake_handover = true;
    everything.fees_to_validators_ppm = 250_000;
    everything.fee_micros = 100;
    everything.distinct_names = true;
    everything.waits_survive_stops = true;
    everything.protected_registration = true;
    let mut bonding = seven(genesis_v5());
    bonding.all_new_time_to_validators = true;
    vec![("plain", plain), ("everything", everything), ("bonding", bonding)]
}

/// One block of the run.
pub struct Step {
    /// How long after its parent it is dated.
    pub delta: u64,
    pub txs: Vec<Vec<u8>>,
    /// How many of `txs` the rules must refuse.
    pub refused: usize,
    /// Starting validators whose signatures the block's commit leaves out
    /// (the commit of the block before, which this block carries).
    pub absent: Vec<u64>,
    /// The misbehavior CometBFT reports with the block.
    pub misbehavior: Vec<Misbehavior>,
}
fn quiet(delta: u64) -> Step {
    Step { delta, txs: vec![], refused: 0, absent: vec![], misbehavior: vec![] }
}
fn with(delta: u64, txs: Vec<Vec<u8>>) -> Step {
    Step { delta, txs, refused: 0, absent: vec![], misbehavior: vec![] }
}
fn without(delta: u64, absent: Vec<u64>) -> Step {
    Step { delta, txs: vec![], refused: 0, absent, misbehavior: vec![] }
}

/// The consensus address of validator `owner`, as CometBFT names it.
pub fn address(owner: u64) -> Vec<u8> {
    Sha256::digest(hex::decode(pk(owner as u8 + 101)).unwrap())[..20].to_vec()
}

/// A precommit of starting validator `owner` at `height`, for a block whose
/// hash is all `block_byte`.
fn vote(owner: u64, height: u64, block_byte: u8) -> tendermint::Vote {
    use tendermint::{Hash, Signature, Time, Vote, account, block};
    let seed = owner as u8 + 101;
    let public = tendermint::PublicKey::from_raw_ed25519(&hex::decode(pk(seed)).unwrap()).unwrap();
    let mut vote = Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: height.try_into().unwrap(),
        round: 0u32.try_into().unwrap(),
        block_id: Some(block::Id {
            hash: Hash::Sha256([block_byte; 32]),
            part_set_header: block::parts::Header::new(1, Hash::Sha256([block_byte + 1; 32])).unwrap(),
        }),
        timestamp: Some(Time::from_unix_timestamp(1_800_000_000, 0).unwrap()),
        validator_address: account::Id::from(public),
        validator_index: (owner as u32).try_into().unwrap(),
        signature: None,
        extension: vec![],
        extension_signature: None,
    };
    let mut bytes = Vec::new();
    vote.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes).unwrap();
    vote.signature = Some(Signature::try_from(key(seed).sign(&bytes).to_bytes().to_vec()).unwrap());
    vote
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Signin => "signin",
        Role::Spend => "spend",
        Role::Recover => "recover",
    }
}

/// What the script reads of a chain.
pub struct View<'a> {
    pub engine: &'a Engine,
    pub network: &'a str,
}
impl View<'_> {
    fn meta(&self) -> &Meta {
        self.engine.meta().unwrap()
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    pub fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    pub fn candidate(&self, id: u64) -> Option<pos::Candidate> {
        self.row(&pos_adapter::candidate_key(id)).map(|row| serde_json::from_slice(&row).unwrap())
    }
    pub fn stake(&self, id: u64) -> Option<pos::OwnerStake> {
        self.row(&pos_adapter::owner_key(id)).map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn now(&self) -> u64 {
        self.meta().elapsed_micros().unwrap()
    }
    /// A protocol-4 action of genesis account `from` (key seed `from + 1`),
    /// `ahead` nonces after its next one.
    fn legacy_ahead(&self, from: u64, ahead: u64, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        ledger::sign_action(
            &Action {
                network_id: self.network.to_string(),
                from,
                nonce: row.nonce + 1 + ahead,
                auth_epoch: row.auth_epoch,
                public_key: pk(from as u8 + 1),
                payload,
                signature: vec![],
            },
            &key(from as u8 + 1),
        )
        .unwrap()
    }
    fn legacy(&self, from: u64, payload: ActionPayload) -> Vec<u8> {
        self.legacy_ahead(from, 0, payload)
    }
    fn transfer(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn extension_ahead(&self, from: u64, ahead: u64, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(self.network, from, row.nonce + 1 + ahead, row.auth_epoch, kind, &payload, &key(from as u8 + 1)).unwrap()
    }
    fn extension(&self, from: u64, kind: u8, payload: Value) -> Vec<u8> {
        self.extension_ahead(from, 0, kind, payload)
    }
    /// Owner `owner` bonds half of what it holds, five seconds at most.
    fn bond(&self, owner: u64) -> Vec<u8> {
        let amount = (self.account(owner).balance / 2).min(5 * SECOND);
        self.extension(owner, 18, json!({"amount": amount.to_string()}))
    }
    fn delegate(&self, from: u64, operator: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ActionPayload::Delegate(ledger::Delegate { operator, amount, min_shares: 1 }))
    }
    fn undelegate(&self, from: u64, ahead: u64, operator: u64, shares: u64) -> Vec<u8> {
        self.legacy_ahead(from, ahead, ActionPayload::Undelegate(ledger::Undelegate { operator, shares, min_amount: 1 }))
    }
    fn shares(&self, from: u64, operator: u64) -> u64 {
        self.stake(from)
            .and_then(|stake| stake.positions.iter().find(|position| position.candidate == operator).map(|position| position.shares))
            .unwrap_or(0)
    }
    /// The exits of `from` from validator `operator`, oldest first.
    fn exits(&self, from: u64, operator: u64) -> Vec<u64> {
        self.stake(from)
            .map(|stake| stake.exits.iter().filter(|exit| exit.candidate == operator).map(|exit| exit.id).collect())
            .unwrap_or_default()
    }
    fn register(&self, from: u64, seed: u8, self_bond: Option<u64>) -> Vec<u8> {
        let proof = key(seed).sign(&pos::register_message(pos::hex32(self.network).unwrap(), from, &pk(seed), 1000).unwrap());
        let mut payload = json!({"commission_bps": 1000, "consensus_key": pk(seed), "proof": hex::encode(proof.to_bytes())});
        if let Some(amount) = self_bond {
            payload["self_bond"] = amount.to_string().into();
        }
        self.extension(from, 17, payload)
    }
    fn report(&self, from: u64, owner: u64, height: u64) -> Vec<u8> {
        let evidence = pos::DoubleSignEvidence { first: vote(owner, height, 1), second: vote(owner, height, 3) };
        self.extension(from, 20, serde_json::to_value(evidence).unwrap())
    }
    /// Genesis account `sponsor` pays for a registration of identity `seed`
    /// with `commitment`.
    fn sponsor_with(&self, sponsor: u64, seed: u8, commitment: String) -> Vec<u8> {
        let expiry = self.now() + 3_600 * SECOND;
        let consent = registration::consent_bytes(
            pos::hex32(self.network).unwrap(),
            sponsor,
            pos::hex32(&pk(seed)).unwrap(),
            pos::hex32(&commitment).unwrap(),
            expiry,
        );
        let payload = json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())});
        self.extension(sponsor, 44, payload)
    }
    fn salt(seed: u8) -> String {
        hex::encode([seed; 32])
    }
    fn sponsor(&self, sponsor: u64, seed: u8, name: &str) -> Vec<u8> {
        self.sponsor_with(sponsor, seed, ledger::action_commitment(self.network, &pk(seed), name, &Self::salt(seed)).unwrap())
    }
    fn reveal(&self, seed: u8, name: &str) -> Vec<u8> {
        ledger::sign_action(
            &Action {
                network_id: self.network.to_string(),
                from: u64::MAX,
                nonce: 0,
                auth_epoch: 0,
                public_key: pk(seed),
                payload: ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: Self::salt(seed) }),
                signature: vec![],
            },
            &key(seed),
        )
        .unwrap()
    }
    /// The set of keys an account registered by `registration` starts with
    /// (seeds `first` to `first + 3`), each key with its acceptance.
    fn setup(&self, registration: u8, first: u8) -> Value {
        let accepts = |seed: u8, role: Role| {
            let proof = key(seed).sign(&security::registration_key_message(self.network, &pk(registration), role, &pk(seed)).unwrap());
            json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
        };
        let mut keys = vec![accepts(first, Role::Signin), accepts(first + 1, Role::Spend), accepts(first + 2, Role::Recover), accepts(first + 3, Role::Recover)];
        keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
        json!({"keys": keys, "policy": {"threshold": "2", "daily_limit_micros": "500000", "delay_seconds": "60", "freeze_seconds": "60"}})
    }
    fn sponsor_protected(&self, sponsor: u64, seed: u8, name: &str) -> Vec<u8> {
        let setup = self.setup(seed, 70);
        let commitment = security::registration_commitment(self.network, &pk(seed), name, &Self::salt(seed), &setup).unwrap();
        self.sponsor_with(sponsor, seed, commitment)
    }
    fn register_protected(&self, seed: u8, name: &str) -> Vec<u8> {
        let payload = json!({"name": name, "salt": Self::salt(seed), "security": self.setup(seed, 70)});
        timecurrency_v5::wire::sign(self.network, u64::MAX, 0, 0, security::REGISTER, &payload, &key(seed)).unwrap()
    }
    fn protected(&self) -> bool {
        self.meta().config.protected_registration
    }
}

/// The block at `height`, from the state before it.
pub fn step(view: &View<'_>, height: i64) -> Step {
    match height {
        // The starting validators' owners earn.
        1..=15 => quiet(60 * SECOND),
        // Five of them pay accounts 7 to 11, which have nothing.
        16 => with(SECOND, (0..5u64).map(|owner| view.transfer(owner, owner + 7, 3 * SECOND)).collect()),
        // Account 8 registers a validator with a self bond above the
        // minimum; account 9 delegates to validator 0; owner 1 bonds.
        17 => with(
            SECOND,
            vec![view.register(NEWCOMER, FIRST_KEY, Some(2 * SECOND)), view.delegate(DELEGATOR, 0, SECOND), view.bond(1)],
        ),
        // Account 9 delegates to the new validator, account 10 to validator
        // 2; owners 0, 2, 3 and 4 bond as well, so that no validator holds a
        // third of the power when the new one leaves.
        18 => with(
            SECOND,
            vec![view.delegate(DELEGATOR, NEWCOMER, SECOND / 2), view.delegate(10, 2, SECOND), view.bond(0), view.bond(2), view.bond(3), view.bond(4)],
        ),
        // Two registrations are paid for: one the protocol-4 way, one with a
        // set of keys where the network takes it.
        19 => with(
            SECOND,
            vec![
                view.sponsor(7, 201, "newton"),
                if view.protected() { view.sponsor_protected(11, 202, "kepler") } else { view.sponsor(11, 202, "kepler") },
            ],
        ),
        20 => with(SECOND, vec![view.reveal(201, "newton"), if view.protected() { view.register_protected(202, "kepler") } else { view.reveal(202, "kepler") }]),
        // Blocks whose commit leaves signatures out.
        21 => without(30 * SECOND, vec![3]),
        22 => without(30 * SECOND, vec![3, 4]),
        23 => without(30 * SECOND, vec![3]),
        24 => quiet(30 * SECOND),
        // CometBFT reports that validator 6 signed twice at height 10. Its
        // stake is slashed and it is jailed; the safety hold lasts until it
        // has left the roster.
        25 => Step { misbehavior: vec![Misbehavior { kind: DUPLICATE_VOTE, address: address(REPORTED), height: 10 }], ..quiet(SECOND) },
        26 | 27 => quiet(30 * SECOND),
        // Half of a delegation and a part of a self bond go out.
        28 => {
            let half = view.shares(DELEGATOR, 0) / 2;
            with(SECOND, vec![view.undelegate(DELEGATOR, 0, 0, half), view.extension(1, 19, json!({"amount": "500000", "min_amount": "500000"}))])
        }
        // Account 7 proves that validator 5 signed twice at height 3.
        29 => with(SECOND, vec![view.report(7, EVIDENCED, 3)]),
        // Long enough for the churn of the punishments to pass.
        30 | 31 => quiet(30 * SECOND),
        // The new validator takes its whole self bond out, and account 9 all
        // that it delegated to it.
        32 => {
            let bond = view.candidate(NEWCOMER).unwrap().self_bond.to_string();
            let shares = view.shares(DELEGATOR, NEWCOMER);
            with(SECOND, vec![view.extension(NEWCOMER, 19, json!({"amount": bond, "min_amount": bond})), view.undelegate(DELEGATOR, 0, NEWCOMER, shares)])
        }
        33..=35 => quiet(60 * SECOND),
        // The chain stands still for fifteen days. The first block after it
        // retires the candidates that hold no self bond and have not voted
        // for fourteen days: the new validator, whose row stays while its
        // exits wait, and the two punished ones, whose rows go.
        36 => quiet(15 * DAY),
        // The retired validator takes its self exit out, which clears its
        // row; account 9 takes out both of its delegated exits.
        37 => {
            let mut txs = Vec::new();
            for (ahead, entry) in view.exits(NEWCOMER, NEWCOMER).into_iter().enumerate() {
                txs.push(view.extension_ahead(NEWCOMER, ahead as u64, 21, json!({"entry": entry.to_string()})));
            }
            let mut ahead = 0;
            for operator in [0, NEWCOMER] {
                for entry in view.exits(DELEGATOR, operator) {
                    txs.push(view.legacy_ahead(DELEGATOR, ahead, ActionPayload::Withdraw(ledger::Withdraw { entry })));
                    ahead += 1;
                }
            }
            with(SECOND, txs)
        }
        // The same owner registers again, with a new consensus key.
        38 => with(SECOND, vec![view.register(NEWCOMER, SECOND_KEY, None)]),
        39 | 40 => quiet(60 * SECOND),
        41 => without(60 * SECOND, vec![2]),
        42..=44 => quiet(60 * SECOND),
        // The chain stands still for three hours.
        45 => quiet(3 * HOUR),
        // Stake moves again after the stop.
        46 => {
            let shares = view.shares(10, 2) / 3;
            with(SECOND, vec![view.extension(2, 18, json!({"amount": "300000"})), view.undelegate(10, 0, 2, shares), view.delegate(DELEGATOR, NEWCOMER, SECOND / 4)])
        }
        47 => without(45 * SECOND, vec![0, 3]),
        _ => quiet(45 * SECOND),
    }
}

/// What the run must have done on every network, said where it ends.
pub fn check_the_run(view: &View<'_>) {
    // Two accounts registered.
    assert_eq!(view.meta().account_count, GENESIS_ACCOUNTS + 2);
    // Both starting validators punished: jailed, and retired once their
    // fourteen days had passed. Nothing was left on their rows, which are
    // gone; their consensus keys stay reserved.
    for owner in [REPORTED, EVIDENCED] {
        assert!(view.candidate(owner).is_none(), "validator {owner}");
        assert!(view.engine.version().unwrap().get(&pos_adapter::consensus_key(&pk(owner as u8 + 101)).unwrap()).is_some());
    }
    // The newcomer is a candidate again, under its second key.
    let newcomer = view.candidate(NEWCOMER).expect("registered again");
    assert_eq!(newcomer.consensus_key, pk(SECOND_KEY));
    assert!(!newcomer.archived && !newcomer.jailed);
    // Account 9 holds a delegation to it, and what is left with validator 0.
    assert!(view.shares(DELEGATOR, NEWCOMER) > 0 && view.shares(DELEGATOR, 0) > 0);
    assert!(view.exits(DELEGATOR, 0).is_empty() && view.exits(DELEGATOR, NEWCOMER).is_empty());
    // Owner 1 holds a self exit it cannot take out while it validates.
    assert_eq!(view.exits(1, 1).len(), 1);
    assert!(view.candidate(1).unwrap().self_bond > 0 && view.candidate(2).unwrap().self_bond > 0);
}
