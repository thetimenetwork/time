//! Recorded roots: a network without the two account-safety settings runs
//! the account security rules and its registrations exactly as it did before
//! those settings existed.
//!
//! `names_unchanged.rs` records registrations and `golden.rs` the upgrade
//! mechanism, but neither run uses the account security rules, and neither
//! has a block dated hours or days after its parent. This run does both on
//! purpose. One account adopts the rules and then, with long gaps between
//! some blocks:
//!
//! - asks for a payment above its limit, which a short gap leaves waiting
//!   and a gap of five hours makes due (the protocol-4 clock: a stop uses up
//!   the wait);
//! - is frozen, and the freeze runs out during a gap of six hours;
//! - asks for a raise of its limit, which is due after a gap of three hours;
//! - has its keys replaced by recovery keys alone: the wait runs out during
//!   a gap of nine hours and a key of the new set finishes it;
//! - has a second such replacement lapse during a gap of eight days.
//!
//! Two accounts are registered the protocol-4 way, a registration lapses,
//! and an action of a kind this engine did not know (45) is refused. The
//! network id, the state root, the hash of the metadata row and the number
//! of actions a proposer kept were recorded after every block with the
//! engine as it was before the settings were built (commit `3d316ac`), and
//! the same run must give the same values now.
//!
//! Nothing here names the new settings, so that the file compiles and runs
//! unchanged on the engine before them. To record again (only ever on an
//! engine whose rules are known to be the recorded ones):
//! `V5_RECORD_SAFETY_OFF=1 cargo test --test safety_unchanged`.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, account_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::security::{self, Role, Security};
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const HOUR: u64 = 3_600 * SECOND;
const DAY: u64 = 24 * HOUR;
const BLOCKS: i64 = 52;

/// The account under test (its protocol-4 key is seed 6) and its keys.
const ME: u64 = 5;
const OLD: u8 = 6;
const SIGNIN: u8 = 60;
const SPEND: u8 = 61;
const SHEET: u8 = 62;
const PHRASE: u8 = 63;
const FRIEND: u8 = 64;
const SECOND_SPEND: u8 = 65;
const THIRD_SPEND: u8 = 66;
/// Who is paid.
const SHOP: u64 = 7;
/// The settings of the account: what its spend key may move in a day, how
/// long what it starts alone waits, and how long a freeze lasts.
const LIMIT: u64 = 500_000;
const DELAY_SECONDS: u64 = 2 * 3_600;
const FREEZE_SECONDS: u64 = 4 * 3_600;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Block {
    height: String,
    kept: usize,
    root: String,
    meta_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Run {
    network_id: String,
    blocks: Vec<Block>,
    audited_leaves: String,
    audited_accounts: String,
    /// The SHA-256 of the security row of the account under test at the end,
    /// as stored.
    security_row_sha256: String,
    /// Its balance and that of the account it paid.
    balances: Vec<String>,
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("safety-off.json")
}

/// The networks the runs are made on: the protocol-4 settings, and every
/// optional setting that existed before the two of this change.
fn variants() -> Vec<(&'static str, Genesis)> {
    let plain = genesis_v5();
    let mut everything = genesis_v5();
    everything.validators = (0..7)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    everything.all_new_time_to_validators = true;
    everything.stake_handover = true;
    everything.fees_to_validators_ppm = 250_000;
    everything.fee_micros = 100;
    everything.distinct_names = true;
    vec![("plain", plain), ("everything", everything)]
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
    json!({"threshold": "2", "daily_limit_micros": LIMIT.to_string(), "delay_seconds": DELAY_SECONDS.to_string(), "freeze_seconds": FREEZE_SECONDS.to_string()})
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network }
    }
    fn now(&self) -> u64 {
        self.engine.meta().unwrap().elapsed_micros().unwrap()
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
    fn signed(&self, from: u64, nonce: u64, auth_epoch: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
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
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        self.signed(from, row.nonce + 1, row.auth_epoch, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    /// An action of the account under test that takes its next nonce.
    fn act(&self, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(ME);
        timecurrency_v5::wire::sign(&self.network, ME, row.nonce + 1, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
    }
    /// A protective action of the account under test: no nonce, no
    /// authority epoch.
    fn guard(&self, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        timecurrency_v5::wire::sign(&self.network, ME, 0, 0, kind, &payload, &key(signer)).unwrap()
    }
    /// A key that joins the set of the account under test: it carries its
    /// holder's acceptance of the role.
    fn joins(&self, seed: u8, role: Role) -> Value {
        let proof = key(seed).sign(&security::key_message(&self.network, ME, role, &pk(seed)).unwrap());
        json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
    }
    fn secure(&self) -> Vec<u8> {
        let keys = sorted(vec![
            self.joins(SIGNIN, Role::Signin),
            self.joins(SPEND, Role::Spend),
            self.joins(SHEET, Role::Recover),
            self.joins(PHRASE, Role::Recover),
            self.joins(FRIEND, Role::Recover),
        ]);
        self.act(OLD, security::SECURE, json!({"keys": keys, "policy": policy()}))
    }
    fn freeze(&self, signer: u8) -> Vec<u8> {
        let mine = self.mine();
        self.guard(
            signer,
            security::FREEZE,
            json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": (self.now() + 600 * SECOND).to_string()}),
        )
    }
    /// The two recovery keys on the sheet and in the passphrase ask for a
    /// new set of keys that differs from the present one in its spend key.
    fn replace_spend_key(&self, new_spend: u8) -> Vec<u8> {
        let operation = json!({"type": "replace", "policy": policy(), "keys": sorted(vec![
            stays(SIGNIN, Role::Signin),
            self.joins(new_spend, Role::Spend),
            stays(SHEET, Role::Recover),
            stays(PHRASE, Role::Recover),
            stays(FRIEND, Role::Recover),
        ])});
        let expires = self.now() + 3_600 * SECOND;
        let mut approvers = [(pk(SHEET), SHEET), (pk(PHRASE), PHRASE)];
        approvers.sort();
        let names: Vec<&str> = approvers.iter().map(|(public_key, _)| public_key.as_str()).collect();
        let message = security::root_message(&self.network, ME, self.mine().version, expires, &operation, &names).unwrap();
        let approvals: Vec<Value> = approvers
            .iter()
            .map(|(public_key, seed)| json!({"public_key": public_key, "signature": hex::encode(key(*seed).sign(&message).to_bytes())}))
            .collect();
        self.guard(SHEET, security::ROOT, json!({"op": operation, "expires_elapsed_micros": expires.to_string(), "approvals": approvals}))
    }
    fn finalize(&self, signer: u8) -> Vec<u8> {
        self.guard(signer, security::FINALIZE, json!({"version": self.mine().version.to_string()}))
    }
    /// Genesis account `sponsor` (key seed `sponsor + 1`) pays for the
    /// registration of the identity `seed` under `name`. The commitment
    /// lasts `lifetime` seconds.
    fn sponsor(&self, sponsor: u64, seed: u8, name: &str, lifetime: u64) -> Vec<u8> {
        let salt = hex::encode([seed; 32]);
        let commitment = ledger::action_commitment(&self.network, &pk(seed), name, &salt).unwrap();
        let expiry = self.now() + lifetime * SECOND;
        let consent = registration::consent_bytes(
            pos::hex32(&self.network).unwrap(),
            sponsor,
            pos::hex32(&pk(seed)).unwrap(),
            pos::hex32(&commitment).unwrap(),
            expiry,
        );
        let payload: Value = json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())});
        let row = self.account(sponsor);
        timecurrency_v5::wire::sign(&self.network, sponsor, row.nonce + 1, row.auth_epoch, 44, &payload, &key(sponsor as u8 + 1)).unwrap()
    }
    /// The new identity takes its name: an action without an account.
    fn reveal(&self, seed: u8, name: &str) -> Vec<u8> {
        self.signed(u64::MAX, 0, 0, seed, ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: hex::encode([seed; 32]) }))
    }
    /// One block as a proposer builds it and a validator checks it. Returns
    /// what is recorded of it.
    fn block(&mut self, step: Step) -> Block {
        let meta = self.engine.meta().unwrap();
        let (height, time) = (meta.height + 1, meta.time_micros + step.delta as i64);
        let signers: Vec<String> = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        let hash = sha(height as u64);
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &step.txs, &signers, 1 << 20, hash).unwrap();
        let strict = self.engine.prepare(height, time, &kept, &signers, hash).unwrap();
        let reference = self.engine.prepare_reference(height, time, &kept, &signers, hash).unwrap();
        assert_eq!(strict.root, proposed.root, "validator and proposer disagree at {height}");
        assert_eq!(reference.root, proposed.root, "fast path and reference disagree at {height}");
        if kept.len() != step.txs.len() - step.refused {
            let reasons: Vec<String> = step
                .txs
                .iter()
                .map(|tx| match self.engine.prepare(height, time, &[tx], &signers, hash) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("network {} height {height}: a scripted action was left out or kept: {reasons:?}", self.network);
        }
        self.engine.commit(proposed, hash).unwrap();
        let version = self.engine.version().unwrap();
        Block {
            height: version.height().to_string(),
            kept: kept.len(),
            root: hex::encode(version.root()),
            meta_sha256: hex::encode(Sha256::digest(&version.head().metadata)),
        }
    }
}

struct Step {
    delta: u64,
    txs: Vec<Vec<u8>>,
    /// How many of `txs` the rules must refuse.
    refused: usize,
}
fn quiet(delta: u64) -> Step {
    Step { delta, txs: vec![], refused: 0 }
}
fn with(delta: u64, txs: Vec<Vec<u8>>) -> Step {
    Step { delta, txs, refused: 0 }
}
fn refused(delta: u64, tx: Vec<u8>) -> Step {
    Step { delta, txs: vec![tx], refused: 1 }
}

/// The block at `height`, from the state before it.
fn step(chain: &Chain, height: i64) -> Step {
    let request = |amount: u64| chain.act(SPEND, security::PAYMENT, json!({"type": "request", "to": SHOP.to_string(), "amount": amount.to_string()}));
    let execute = |id: u64| chain.act(SPEND, security::PAYMENT, json!({"type": "execute", "id": id.to_string()}));
    match height {
        // The validators' owners earn.
        1..=20 => quiet(60 * SECOND),
        // Four of them pay the account under test: it holds twenty seconds.
        21 => with(SECOND, (0..4u64).map(|owner| chain.transfer(owner, owner as u8 + 1, ME, 5 * SECOND)).collect()),
        // It adopts the rules: one sign-in key, one spend key, three
        // recovery keys, two proofs for a root operation.
        22 => with(SECOND, vec![chain.secure()]),
        // It pays within its limit; two owners sponsor a registration each.
        23 => with(SECOND, vec![chain.transfer(ME, SPEND, SHOP, 100_000), chain.sponsor(0, 201, "newton", 3600), chain.sponsor(1, 202, "kepler", 3600)]),
        // The two names are taken. The account asks for a payment above its
        // limit, which waits two hours (item 1).
        24 => with(SECOND, vec![chain.reveal(201, "newton"), chain.reveal(202, "kepler"), request(3 * SECOND)]),
        // A short gap: half an hour. The payment still waits.
        25 => quiet(1_800 * SECOND),
        26 => refused(SECOND, execute(1)),
        // A long gap: five hours. Without the new setting it uses up the
        // wait, and the payment goes through.
        27 => quiet(5 * HOUR),
        28 => with(SECOND, vec![execute(1)]),
        // A recovery key freezes the account for four hours.
        29 => with(SECOND, vec![chain.freeze(SHEET)]),
        30 => refused(SECOND, chain.transfer(ME, SPEND, SHOP, 50_000)),
        // Six hours later the freeze is over.
        31 => quiet(6 * HOUR),
        32 => with(SECOND, vec![chain.transfer(ME, SPEND, SHOP, 50_000)]),
        // A raise of the limit, which waits two hours (item 2), and a gap of
        // three. The next payment is made under the new limit.
        33 => with(SECOND, vec![chain.act(SPEND, security::LIMIT, json!({"daily_limit_micros": "2000000"}))]),
        34 => quiet(3 * HOUR),
        35 => with(SECOND, vec![chain.transfer(ME, SPEND, SHOP, 100_000)]),
        // Two recovery keys ask for a new spend key. The account is frozen
        // while that waits; a key of the new set cannot finish it yet.
        36 => with(SECOND, vec![chain.replace_spend_key(SECOND_SPEND)]),
        37 => refused(SECOND, chain.finalize(SECOND_SPEND)),
        // Nine hours later it can.
        38 => quiet(9 * HOUR),
        39 => with(SECOND, vec![chain.finalize(SECOND_SPEND)]),
        // A second replacement, which nobody finishes: eight days later its
        // seven days of claim window are over and the account is as it was.
        40 => with(SECOND, vec![chain.replace_spend_key(THIRD_SPEND)]),
        41 => quiet(8 * DAY),
        42 => refused(SECOND, chain.finalize(THIRD_SPEND)),
        43 => with(SECOND, vec![chain.transfer(ME, SECOND_SPEND, SHOP, 100_000)]),
        // An action of a kind the engine did not know before this change
        // (45), signed by a key without an account, and a registration that
        // is paid for and lapses.
        44 => Step {
            delta: SECOND,
            txs: vec![
                raw_action(&chain.network, 45, u64::MAX, 0, 0, 203, br#"{"name":"galileo","salt":"00"}"#),
                chain.sponsor(2, 204, "galileo", 120),
            ],
            refused: 1,
        },
        45..=47 => quiet(60 * SECOND),
        48 => refused(SECOND, chain.reveal(204, "galileo")),
        _ => quiet(45 * SECOND),
    }
}

fn run(genesis: Genesis) -> Run {
    let mut chain = Chain::new(genesis);
    let mut blocks = Vec::new();
    for height in 1..=BLOCKS {
        let next = step(&chain, height);
        blocks.push(chain.block(next));
        match height {
            // What the script relies on, said where it happens.
            24 => assert_eq!(chain.mine().pending_payments.len(), 1),
            28 => assert!(chain.mine().pending_payments.is_empty(), "the payment went through"),
            29 => assert_eq!(chain.mine().freezes, 1),
            35 => assert_eq!(chain.mine().policy.daily_limit_micros, 2_000_000),
            36 => assert!(chain.mine().pending_root.is_some()),
            39 => assert!(chain.account(ME).devices.iter().any(|device| device.public_key == pk(SECOND_SPEND))),
            43 => assert!(chain.mine().pending_root.is_none(), "the second replacement lapsed"),
            _ => {}
        }
    }
    let audit = chain.engine.audit().unwrap();
    assert!(audit.history_archive_verified);
    // Twelve genesis accounts and the two registered ones.
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 2);
    assert!(chain.account(ME).devices.iter().all(|device| device.public_key != pk(THIRD_SPEND)));
    Run {
        network_id: chain.network.clone(),
        blocks,
        audited_leaves: audit.authenticated_leaves.to_string(),
        audited_accounts: audit.account_count.to_string(),
        security_row_sha256: hex::encode(Sha256::digest(chain.row(&security::key(ME)).unwrap())),
        balances: vec![chain.account(ME).balance.to_string(), chain.account(SHOP).balance.to_string()],
    }
}

#[test]
fn a_network_without_the_settings_keeps_its_waits_and_registrations_as_before() {
    let record = std::env::var("V5_RECORD_SAFETY_OFF").is_ok();
    let mut runs = BTreeMap::new();
    for (name, genesis) in variants() {
        runs.insert(name.to_string(), run(genesis));
    }
    if record {
        std::fs::write(fixture(), serde_json::to_vec_pretty(&runs).unwrap()).unwrap();
        return;
    }
    let path = fixture();
    let expected: BTreeMap<String, Run> =
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap();
    assert_eq!(expected.keys().collect::<Vec<_>>(), runs.keys().collect::<Vec<_>>());
    for (name, run) in &runs {
        let old = &expected[name];
        assert_eq!(old.network_id, run.network_id, "{name}: network id");
        for (before, now) in old.blocks.iter().zip(&run.blocks) {
            assert_eq!(before, now, "{name}: first difference at height {}", before.height);
        }
        assert_eq!(old.blocks.len(), run.blocks.len(), "{name}: number of blocks");
        assert_eq!(old.audited_leaves, run.audited_leaves, "{name}: leaves the audit counts");
        assert_eq!(old.audited_accounts, run.audited_accounts, "{name}: accounts the audit counts");
        assert_eq!(old.security_row_sha256, run.security_row_sha256, "{name}: the security row");
        assert_eq!(old.balances, run.balances, "{name}: balances");
    }
    // The two networks differ: the settings are really in force.
    assert_ne!(runs["plain"].blocks.last().unwrap().root, runs["everything"].blocks.last().unwrap().root);
}
