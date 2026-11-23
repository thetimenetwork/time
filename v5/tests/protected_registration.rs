//! Accounts that are protected from their first block
//! (`protected_registration` in the genesis; the rule is described in
//! `src/security.rs`).
//!
//! An account adopts the account security rules with an action that costs a
//! fee, and a new account holds nothing. On a network with the setting the
//! reveal of a sponsored registration can carry the set of keys and the
//! policy (kind 45), and a genesis can list accounts that start with one.
//!
//! Here: how a network chooses the rule and that one that does not is
//! unchanged; a registration that creates a protected account and what it
//! costs; what the new account can and cannot do in the block that creates
//! it; that the set of keys is judged exactly as the adopting action judges
//! it, and what a refusal leaves; that the paid commitment binds the set;
//! two registrations of one name; a genesis with protected accounts; what
//! the production profile requires; and a node through its mempool, a
//! restart and state sync. `safety_unchanged.rs` holds the roots of a
//! network without the setting, recorded before the rule was built.
mod common;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::app::App;
use timecurrency_v5::engine::{Engine, Meta, account_key, name_key, pubkey_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis, ProtectedAccount, ProtectedKey};
use timecurrency_v5::names;
use timecurrency_v5::security::{self, Policy, Role, Security};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::statesync::NodeOptions;
use timecurrency_v5::store::Store;
use timecurrency_v5::transport::BatchCheck;

const SECOND: u64 = 1_000_000;
const MINUTE: u64 = 60 * SECOND;
const FEE: u64 = ledger::FEE_MICROS;
/// What a sponsor pays for a registration on these networks: the
/// registration charge and the fee of its action.
const SPONSOR_PAYS: u64 = 10_000 + FEE;

/// The keys of the account that is registered: the key that registers it,
/// and the keys of its set.
const REGISTRATION: u8 = 201;
const SIGNIN: u8 = 60;
const SPEND: u8 = 61;
const SHEET: u8 = 62;
const PHRASE: u8 = 63;
/// A key of somebody else.
const THIEF: u8 = 99;
/// A genesis account that owns no validator, and pays for registrations.
const SPONSOR: u64 = 8;
const SHOP: u64 = 7;
const LIMIT: u64 = 500_000;
const DELAY: u64 = 60;
const FREEZE: u64 = 120;
const REFUSED_COMMITMENT: &str = "does not match its paid commitment";

/// The test genesis with the rule.
fn protected() -> Genesis {
    let mut genesis = genesis_v5();
    genesis.protected_registration = true;
    genesis
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
fn policy(threshold: u64, limit: u64) -> Value {
    json!({"threshold": threshold.to_string(), "daily_limit_micros": limit.to_string(), "delay_seconds": DELAY.to_string(), "freeze_seconds": FREEZE.to_string()})
}
fn salt(seed: u8) -> String {
    hex::encode([seed; 32])
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
/// A key of a set, with its holder's acceptance of the role on the account
/// that the registration key `registration` creates.
fn registers(network: &str, registration: u8, seed: u8, role: Role) -> Value {
    let proof = key(seed).sign(&security::registration_key_message(network, &pk(registration), role, &pk(seed)).unwrap());
    json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
}
/// A key of a set, with its holder's acceptance of the role on the existing
/// account `account`: what the adopting action (kind 70) takes.
fn joins(network: &str, account: u64, seed: u8, role: Role) -> Value {
    let proof = key(seed).sign(&security::key_message(network, account, role, &pk(seed)).unwrap());
    json!({"public_key": pk(seed), "role": role_name(role), "proof": hex::encode(proof.to_bytes())})
}
/// The set of keys of these tests for a registration by `registration`: one
/// sign-in key, one spend key, two recovery keys, two proofs.
fn standard(network: &str, registration: u8) -> Value {
    json!({"keys": sorted(vec![
        registers(network, registration, SIGNIN, Role::Signin),
        registers(network, registration, SPEND, Role::Spend),
        registers(network, registration, SHEET, Role::Recover),
        registers(network, registration, PHRASE, Role::Recover),
    ]), "policy": policy(2, LIMIT)})
}
/// The commitment a sponsor pays for: of a registration that carries
/// `setup`, or of a protocol-4 registration.
fn commitment(network: &str, seed: u8, name: &str, setup: Option<&Value>) -> String {
    match setup {
        Some(setup) => security::registration_commitment(network, &pk(seed), name, &salt(seed), setup).unwrap(),
        None => ledger::action_commitment(network, &pk(seed), name, &salt(seed)).unwrap(),
    }
}
/// Account `row` (key seed `id + 1`) pays for the registration of the
/// identity `seed` under `commitment`, which lasts `lifetime` seconds from
/// `now`.
fn sponsor_tx(network: &str, row: &Account, seed: u8, commitment: &str, now: u64, lifetime: u64) -> Vec<u8> {
    let expiry = now + lifetime * SECOND;
    let consent = registration::consent_bytes(
        pos::hex32(network).unwrap(),
        row.id,
        pos::hex32(&pk(seed)).unwrap(),
        pos::hex32(commitment).unwrap(),
        expiry,
    );
    let payload: Value = json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())});
    timecurrency_v5::wire::sign(network, row.id, row.nonce + 1, row.auth_epoch, 44, &payload, &key(row.id as u8 + 1)).unwrap()
}
/// The registration that carries `setup` (kind 45): an action without an
/// account, signed by the registration key.
fn register_tx(network: &str, seed: u8, name: &str, setup: &Value) -> Vec<u8> {
    let payload = json!({"name": name, "salt": salt(seed), "security": setup});
    timecurrency_v5::wire::sign(network, u64::MAX, 0, 0, security::REGISTER, &payload, &key(seed)).unwrap()
}
/// The protocol-4 reveal.
fn reveal_tx(network: &str, seed: u8, name: &str) -> Vec<u8> {
    signed(network, u64::MAX, 0, 0, seed, ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: salt(seed) }))
}
fn commit_key(seed: u8) -> Vec<u8> {
    registration::commit_key(&pos::hex32(&pk(seed)).unwrap())
}
/// An action of account `id` that takes the nonce after `nonce`.
fn act_tx(network: &str, id: u64, nonce: u64, auth_epoch: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    timecurrency_v5::wire::sign(network, id, nonce + 1, auth_epoch, kind, &payload, &key(signer)).unwrap()
}
/// A protective action of account `id`: no nonce, no authority epoch.
fn guard_tx(network: &str, id: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    timecurrency_v5::wire::sign(network, id, 0, 0, kind, &payload, &key(signer)).unwrap()
}
/// A freeze of account `id` as it is right after it was created.
fn first_freeze(network: &str, id: u64, signer: u8, expires: u64) -> Vec<u8> {
    guard_tx(network, id, signer, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": expires.to_string()}))
}
/// A root operation of account `id` at the first version of its settings.
fn first_root(network: &str, id: u64, sender: u8, approvers: &[u8], operation: Value, expires: u64) -> Vec<u8> {
    let mut keys: Vec<(String, u8)> = approvers.iter().map(|seed| (pk(*seed), *seed)).collect();
    keys.sort();
    let names: Vec<&str> = keys.iter().map(|(public_key, _)| public_key.as_str()).collect();
    let message = security::root_message(network, id, 1, expires, &operation, &names).unwrap();
    let approvals: Vec<Value> = keys
        .iter()
        .map(|(public_key, seed)| json!({"public_key": public_key, "signature": hex::encode(key(*seed).sign(&message).to_bytes())}))
        .collect();
    guard_tx(network, id, sender, security::ROOT, json!({"op": operation, "expires_elapsed_micros": expires.to_string(), "approvals": approvals}))
}
/// The roles of the keys of an account row, by key seed.
fn roles(row: &Account, seeds: &[u8]) -> Vec<Option<Role>> {
    seeds
        .iter()
        .map(|seed| row.devices.iter().find(|device| device.public_key == pk(*seed)).and_then(Role::of))
        .collect()
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    fn try_new(genesis: Genesis) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir().unwrap();
        let network = genesis.network_id()?;
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis)?;
        Ok(Self { _dir: dir, engine, network })
    }
    fn new(genesis: Genesis) -> Self {
        Self::try_new(genesis).unwrap()
    }
    /// A chain on which the validators' owners (accounts 0 to 3) have
    /// earned, and the sponsor of these tests holds five seconds.
    fn funded(genesis: Genesis) -> Self {
        let mut chain = Self::new(genesis);
        for _ in 0..20 {
            chain.block(MINUTE, vec![]);
        }
        chain.block(SECOND, vec![chain.transfer(0, 1, SPONSOR, 5 * SECOND)]);
        chain
    }
    fn meta(&self) -> &Meta {
        self.engine.meta().unwrap()
    }
    fn now(&self) -> u64 {
        self.meta().elapsed_micros().unwrap()
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
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        signed(&self.network, from, row.nonce + 1, row.auth_epoch, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    /// The sponsor of these tests pays for a commitment of the identity
    /// `seed`.
    fn sponsor(&self, seed: u8, commitment: &str) -> Vec<u8> {
        sponsor_tx(&self.network, &self.account(SPONSOR), seed, commitment, self.now(), 3600)
    }
    /// The sponsor pays for a registration of `name` by `seed` that carries
    /// `setup` (or a protocol-4 registration), and one block more passes:
    /// the mempool judges on the last block and takes a reveal one block
    /// after its commitment's.
    fn commit(&mut self, seed: u8, name: &str, setup: Option<&Value>) {
        self.block(SECOND, vec![self.sponsor(seed, &commitment(&self.network, seed, name, setup))]);
        self.block(SECOND, vec![]);
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
    /// A block in which every action is accepted: as a proposer builds it,
    /// as a validator checks it, and with the fast paths off.
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
    /// Why `tx` is refused in the next block, by a validator. The reference
    /// path refuses it too, and a proposer leaves it out: its block is the
    /// block without it. Nothing is committed.
    #[track_caller]
    fn refuses_in_a_block(&self, tx: &[u8]) -> String {
        let (height, time, signers, hash) = self.next(SECOND);
        let reason = match self.engine.prepare(height, time, &[tx], &signers, hash) {
            Ok(_) => panic!("the action was accepted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(self.engine.prepare_reference(height, time, &[tx], &signers, hash).is_err(), "the reference path accepted it");
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &[tx], &signers, 1 << 20, hash).unwrap();
        assert!(kept.is_empty(), "a proposer kept it");
        let none: [Vec<u8>; 0] = [];
        let empty = self.engine.prepare(height, time, &none, &signers, hash).unwrap();
        assert_eq!(proposed.root, empty.root, "a refused action left something in the proposer's block");
        reason
    }
    /// As `refuses_in_a_block`; the mempool refuses it for the same reason.
    #[track_caller]
    fn refuses(&self, tx: &[u8]) -> String {
        let reason = self.refuses_in_a_block(tx);
        let admission = self.engine.check_state().unwrap().admit(tx, SigStatus::Unknown);
        assert_eq!(format!("{:#}", admission.expect_err("the mempool admitted it")), reason, "the mempool's reason");
        reason
    }
    /// Why a validator refuses the block `first` followed by `tx`, although
    /// it accepts `first` alone: `tx` is refused on the state `first` leaves.
    #[track_caller]
    fn refuses_after(&self, first: &[Vec<u8>], tx: &[u8]) -> String {
        let (height, time, signers, hash) = self.next(SECOND);
        self.engine.prepare(height, time, first, &signers, hash).expect("the block without the action");
        let mut all = first.to_vec();
        all.push(tx.to_vec());
        let reason = match self.engine.prepare(height, time, &all, &signers, hash) {
            Ok(_) => panic!("the action was accepted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(self.engine.prepare_reference(height, time, &all, &signers, hash).is_err(), "the reference path accepted it");
        let (_, kept) = self.engine.prepare_filtered(height, time, &all, &signers, 1 << 20, hash).unwrap();
        assert_eq!(kept, first, "a proposer kept it");
        reason
    }
    /// Whether a validator accepts the block `first` followed by `tx`.
    fn accepts_after(&self, first: &[Vec<u8>], tx: &[u8]) -> bool {
        let (height, time, signers, hash) = self.next(SECOND);
        let mut all = first.to_vec();
        all.push(tx.to_vec());
        let strict = self.engine.prepare(height, time, &all, &signers, hash);
        let reference = self.engine.prepare_reference(height, time, &all, &signers, hash);
        match (strict, reference) {
            (Ok(strict), Ok(reference)) => {
                assert_eq!(strict.root, reference.root);
                true
            }
            (Err(_), Err(_)) => false,
            _ => panic!("the fast path and the reference path disagree"),
        }
    }
    /// How many accounts have a security row.
    fn security_rows(&self) -> u64 {
        let mut rows = 0;
        self.engine
            .version()
            .unwrap()
            .audit_verified(|_| {})
            .unwrap()
            .for_each_prefix(b"security/", |_, _| {
                rows += 1;
                Ok(())
            })
            .unwrap();
        rows
    }
}

#[test]
fn a_network_without_the_setting_refuses_the_action_and_is_unchanged() {
    let genesis = genesis_v5();
    assert!(!genesis.protected_registration && genesis.protected_accounts.is_empty());
    let text = serde_json::to_string(&genesis).unwrap();
    assert!(!text.contains("protected_registration") && !text.contains("protected_accounts"), "{text}");
    // The id the protocol-4 engine computes for the same genesis.
    assert_eq!(genesis.network_id().unwrap(), network_id(), "protocol-4 network id");
    let mut chain = Chain::funded(genesis);
    // A commitment is thirty-two bytes to the chain: the sponsor's action is
    // accepted whatever they commit to. The registration itself is not.
    let setup = standard(&chain.network, REGISTRATION);
    chain.commit(REGISTRATION, "alice", Some(&setup));
    let refusal = chain.refuses(&register_tx(&chain.network, REGISTRATION, "alice", &setup));
    assert!(refusal.contains("this network does not register accounts with a set of keys"), "{refusal}");
    assert_eq!(chain.meta().account_count, GENESIS_ACCOUNTS);
    assert_eq!(chain.security_rows(), 0);
    // Registering and then adopting the rules works as it always did.
    chain.commit(202, "bob", None);
    let id = chain.meta().next_account_id;
    chain.block(SECOND, vec![reveal_tx(&chain.network, 202, "bob")]);
    assert_eq!(roles(&chain.account(id), &[202]), [None], "one key with every power");
    chain.engine.audit().unwrap();
}

#[test]
fn the_setting_is_written_one_way_and_the_accounts_after_it() {
    let parse = |field: &str, value: Value| {
        let mut genesis = serde_json::to_value(protected()).unwrap();
        genesis[field] = value;
        serde_json::from_value::<Genesis>(genesis)
    };
    assert!(parse("protected_registration", json!(true)).unwrap().protected_registration);
    // Not using the rule is written by leaving the field out.
    for refused in [json!(false), json!("true"), json!(1), json!(null), json!({})] {
        assert!(parse("protected_registration", refused.clone()).is_err(), "{refused}");
    }
    // A genesis without protected accounts leaves that field out as well,
    // and an entry has its three fields and no other.
    let entry = json!({"id": "5", "keys": [{"public_key": pk(SPEND), "role": "spend"}], "policy": policy(2, LIMIT)});
    assert_eq!(parse("protected_accounts", json!([entry.clone()])).unwrap().protected_accounts.len(), 1);
    let mut extra = entry.clone();
    extra["note"] = json!("x");
    let mut proof = entry.clone();
    proof["keys"][0]["proof"] = json!("00");
    let mut number = entry.clone();
    number["id"] = json!(5);
    for refused in [json!([]), json!(null), json!({}), json!([extra]), json!([proof]), json!([number])] {
        assert!(parse("protected_accounts", refused.clone()).is_err(), "{refused}");
    }
    // The position of the fields is part of the format: after
    // `waits_survive_stops`, the setting first.
    let mut genesis = genesis_v5();
    genesis.validators = (0..7)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.fees_to_validators_ppm = 1_000_000;
    genesis.fee_micros = 10;
    genesis.all_new_time_to_validators = true;
    genesis.stake_handover = true;
    genesis.distinct_names = true;
    genesis.waits_survive_stops = true;
    let without = serde_json::to_string(&genesis).unwrap();
    assert!(without.ends_with(r#""distinct_names":true,"waits_survive_stops":true}"#), "{without}");
    genesis.protected_registration = true;
    let with = serde_json::to_string(&genesis).unwrap();
    assert_eq!(with, format!("{},\"protected_registration\":true}}", without.strip_suffix('}').unwrap()));
    genesis.protected_accounts = vec![owner_set(5, 70)];
    let listed = serde_json::to_string(&genesis).unwrap();
    assert!(listed.starts_with(&format!("{},\"protected_accounts\":[{{\"id\":\"5\",\"keys\":[{{\"public_key\":", with.strip_suffix('}').unwrap())), "{listed}");
    assert!(listed.ends_with(r#""policy":{"threshold":"2","daily_limit_micros":"500000","delay_seconds":"60","freeze_seconds":"120"}}]}"#), "{listed}");
    let parsed: Genesis = serde_json::from_str(&listed).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), listed);
    assert_eq!(parsed.network_id().unwrap(), genesis.network_id().unwrap());
    // Alone, the setting follows the protocol-4 fields directly. It is part
    // of the network id, and so is the list.
    let plain = serde_json::to_string(&genesis_v5()).unwrap();
    assert_eq!(serde_json::to_string(&protected()).unwrap(), format!("{},\"protected_registration\":true}}", plain.strip_suffix('}').unwrap()));
    assert_ne!(protected().network_id().unwrap(), network_id());
    let mut with_accounts = protected();
    with_accounts.protected_accounts = vec![owner_set(5, 70)];
    assert_ne!(with_accounts.network_id().unwrap(), protected().network_id().unwrap());
}

#[test]
fn a_registration_creates_the_account_protected_at_the_cost_of_a_registration() {
    let mut genesis = protected();
    genesis.distinct_names = true;
    let mut chain = Chain::funded(genesis);
    let setup = standard(&chain.network, REGISTRATION);
    let before = chain.account(SPONSOR).balance;
    chain.block(SECOND, vec![chain.sponsor(REGISTRATION, &commitment(&chain.network, REGISTRATION, "alice", Some(&setup)))]);
    // The sponsor pays what any registration costs, when the commitment is
    // made.
    assert_eq!(chain.account(SPONSOR).balance, before - SPONSOR_PAYS);
    assert!(chain.row(&commit_key(REGISTRATION)).is_some());
    // The registration cannot be in the block of its commitment, nor in the
    // mempool before another block: the rule of every reveal.
    let register = register_tx(&chain.network, REGISTRATION, "alice", &setup);
    let admission = chain.engine.check_state().unwrap().admit(&register, SigStatus::Unknown);
    assert!(format!("{:#}", admission.unwrap_err()).contains("requires a later committed height"));
    let id = chain.meta().next_account_id;
    let (bank, supply) = (chain.meta().bank, chain.now());
    chain.block(SECOND, vec![register.clone()]);
    // The account exists with its four keys in their roles. None holds
    // every power, and the registration key is its identity and no key of
    // it.
    let row = chain.account(id);
    assert_eq!((row.id, row.name.as_str(), row.public_key.as_str()), (id, "alice", pk(REGISTRATION).as_str()));
    assert_eq!((row.balance, row.nonce, row.auth_epoch), (0, 0, 0));
    assert_eq!(row.devices.len(), 4);
    assert_eq!(
        roles(&row, &[SIGNIN, SPEND, SHEET, PHRASE, REGISTRATION]),
        [Some(Role::Signin), Some(Role::Spend), Some(Role::Recover), Some(Role::Recover), None]
    );
    assert!(row.devices.iter().all(|device| device.public_key != pk(REGISTRATION)));
    assert!(row.devices.windows(2).all(|pair| pair[0].public_key < pair[1].public_key));
    // Its security row is the one the adopting action would have written,
    // dated at this block.
    let security = chain.security(id).expect("a security row from the first block");
    assert_eq!(
        security,
        Security {
            version: 1,
            policy: Policy { threshold: 2, daily_limit_micros: LIMIT, delay_seconds: DELAY, freeze_seconds: FREEZE },
            allowance_micros: LIMIT,
            allowance_elapsed_micros: chain.now(),
            frozen_until_elapsed_micros: 0,
            freezes: 0,
            pending_limit: None,
            pending_payments: vec![],
            next_id: 1,
            pending_root: None,
        }
    );
    // The indexes of any account, the row of its name on a network with
    // distinct names, and the commitment used up.
    assert_eq!(chain.row(&name_key("alice")), Some(serde_json::to_vec(&id.to_string()).unwrap()));
    assert_eq!(chain.row(&pubkey_key(&pk(REGISTRATION)).unwrap()), Some(serde_json::to_vec(&id.to_string()).unwrap()));
    assert_eq!(chain.row(&names::key("alice")), Some(serde_json::to_vec("alice").unwrap()));
    assert_eq!(chain.row(&commit_key(REGISTRATION)), None);
    assert_eq!((chain.meta().account_count, chain.meta().next_account_id), (GENESIS_ACCOUNTS + 1, id + 1));
    // The registration itself paid nothing to anyone: the sponsor's balance
    // did not move, and the bank received the new time of the block and
    // gave out what it gives the validators, no more.
    assert_eq!(chain.account(SPONSOR).balance, before - SPONSOR_PAYS);
    let without = {
        // The same block without the registration, on the same parent: the
        // bank ends where it ended.
        let mut other = Chain::funded({
            let mut genesis = protected();
            genesis.distinct_names = true;
            genesis
        });
        other.block(SECOND, vec![other.sponsor(REGISTRATION, &commitment(&other.network, REGISTRATION, "alice", Some(&setup)))]);
        assert_eq!((other.meta().bank, other.now()), (bank, supply));
        other.block(SECOND, vec![]);
        other.meta().bank
    };
    assert_eq!(chain.meta().bank, without);
    // The same registration is not taken twice, and the recount passes.
    assert!(chain.refuses(&register).contains("username unavailable"));
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 1);
    assert_eq!(chain.security_rows(), 1);
}

#[test]
fn what_the_new_account_can_and_cannot_do_in_its_first_block() {
    let mut chain = Chain::funded(protected());
    let network = chain.network.clone();
    let setup = standard(&network, REGISTRATION);
    chain.commit(REGISTRATION, "alice", Some(&setup));
    let id = chain.meta().next_account_id;
    let register = register_tx(&network, REGISTRATION, "alice", &setup);
    let expires = chain.now() + 600 * SECOND;
    let pay = |signer: u8, nonce: u64, amount: u64| signed(&network, id, nonce + 1, 0, signer, ActionPayload::Transfer(ledger::Transfer { to: SHOP, amount }));

    // With nothing in it, in the block that creates it: its recovery key
    // freezes it, at no cost, because it has nothing to pay with.
    assert!(chain.accepts_after(std::slice::from_ref(&register), &first_freeze(&network, id, SHEET, expires)));
    // And nothing that costs the full fee goes through.
    let empty = chain.refuses_after(std::slice::from_ref(&register), &pay(SPEND, 0, 1));
    assert!(empty.contains("insufficient funds"), "{empty}");

    // Somebody pays it five seconds in the same block.
    let first = vec![register.clone(), chain.transfer(0, 1, id, 5 * SECOND)];
    // Its spend key pays within the daily limit, asks for a payment above
    // it (which waits), and adds a sign-in key.
    assert!(chain.accepts_after(&first, &pay(SPEND, 0, LIMIT - FEE)));
    assert!(chain.accepts_after(&first, &act_tx(&network, id, 0, 0, SPEND, security::PAYMENT, json!({"type": "request", "to": SHOP.to_string(), "amount": (3 * SECOND).to_string()}))));
    let another = joins(&network, id, 70, Role::Signin);
    assert!(chain.accepts_after(&first, &act_tx(&network, id, 0, 0, SPEND, security::SIGNIN, json!({"add": [{"public_key": another["public_key"], "proof": another["proof"]}], "remove": []}))));
    // The spend key and one recovery key pay above the limit at once.
    let above = json!({"type": "pay", "to": SHOP.to_string(), "amount": (4 * SECOND).to_string()});
    assert!(chain.accepts_after(&first, &first_root(&network, id, SPEND, &[SPEND, SHEET], above.clone(), expires)));

    // What it cannot do, from that same first block on.
    let refused = [
        // More than the limit with the spend key alone.
        (pay(SPEND, 0, LIMIT), "over the daily limit"),
        // Anything with the registration key, which is no key of the account.
        (pay(REGISTRATION, 0, 1_000), "not authorized"),
        (act_tx(&network, id, 0, 0, REGISTRATION, security::SECURE, standard_for_account(&network, id)), "already secured"),
        (first_freeze(&network, id, REGISTRATION, expires), "a spend or recovery key of this account is required"),
        // A payment with the sign-in key or with a recovery key.
        (pay(SIGNIN, 0, 1_000), "permission denied"),
        (pay(SHEET, 0, 1_000), "permission denied"),
        // A root operation with one proof.
        (first_root(&network, id, SHEET, &[SHEET], above.clone(), expires), "not enough proofs"),
        // The protocol-4 way of adding a key, with a recovery key.
        (
            signed(&network, id, 1, 0, SHEET, ActionPayload::AddDevice(ledger::AddDevice { public_key: pk(THIEF), can_manage: true, can_spend: true, proof: "00".repeat(64) })),
            "a secured account manages its keys and recovery with its security rules",
        ),
        // Adopting the rules again, with any key.
        (act_tx(&network, id, 0, 0, SPEND, security::SECURE, standard_for_account(&network, id)), "already secured"),
    ];
    for (tx, why) in &refused {
        let reason = chain.refuses_after(&first, tx);
        assert!(reason.contains(why), "expected {why}, got: {reason}");
    }

    // The block, with a payment in it; then the same refusals on the
    // committed account, from the mempool as well.
    let mut block = first.clone();
    block.push(pay(SPEND, 0, 100_000));
    chain.block(SECOND, block);
    assert_eq!(chain.account(id).balance, 5 * SECOND - 100_000 - FEE);
    assert_eq!(chain.account(SHOP).balance, 100_000);
    assert_eq!(chain.security(id).unwrap().allowance_micros, LIMIT - 100_000 - FEE);
    let reason = chain.refuses(&pay(REGISTRATION, 1, 1_000));
    assert!(reason.contains("not authorized"), "{reason}");
    let reason = chain.refuses(&pay(SPEND, 1, LIMIT));
    assert!(reason.contains("over the daily limit"), "{reason}");
    chain.engine.audit().unwrap();
}
/// The set of these tests as an existing account `id` would adopt it.
fn standard_for_account(network: &str, id: u64) -> Value {
    json!({"keys": sorted(vec![
        joins(network, id, SIGNIN, Role::Signin),
        joins(network, id, SPEND, Role::Spend),
        joins(network, id, SHEET, Role::Recover),
        joins(network, id, PHRASE, Role::Recover),
    ]), "policy": policy(2, LIMIT)})
}

/// What a set under test is made for: an account that adopts the rules, or
/// the account a registration key (by its seed) creates.
#[derive(Clone, Copy)]
enum Subject {
    Account(u64),
    Registration(u8),
}
/// How a key of a set under test proves its acceptance.
#[derive(Clone, Copy, PartialEq)]
enum Proof {
    /// As the rules ask.
    Given,
    /// None.
    Missing,
    /// For another role.
    OtherRole,
    /// Sixty-four bytes that are no signature of anything.
    Garbage,
}

#[test]
fn the_set_of_keys_is_judged_as_the_adopting_action_judges_it() {
    // Account 5 (protocol-4 key seed 6) adopts the rules with kind 70; the
    // identity 201 registers with kind 45. Both carry the same set, which
    // is refused: for the same reason, in the same words.
    const ME: u64 = 5;
    let mut chain = Chain::funded(protected());
    chain.block(SECOND, vec![chain.transfer(0, 1, ME, 5 * SECOND)]);
    let network = chain.network.clone();
    let other = Role::Recover;
    let key_of = |seed: u8, role: Role, proof: Proof, subject: Subject| -> Value {
        let signed_role = if proof == Proof::OtherRole { if role == other { Role::Spend } else { other } } else { role };
        let mut entry = match subject {
            Subject::Account(account) => joins(&network, account, seed, signed_role),
            Subject::Registration(registration) => registers(&network, registration, seed, signed_role),
        };
        entry["role"] = json!(role_name(role));
        match proof {
            Proof::Missing => {
                entry.as_object_mut().unwrap().remove("proof");
            }
            Proof::Garbage => entry["proof"] = json!("ab".repeat(64)),
            _ => {}
        }
        entry
    };
    let good = [(SIGNIN, Role::Signin, Proof::Given), (SPEND, Role::Spend, Proof::Given), (SHEET, Role::Recover, Proof::Given), (PHRASE, Role::Recover, Proof::Given)];
    let with = |index: usize, proof: Proof| {
        let mut keys = good.to_vec();
        keys[index].2 = proof;
        keys
    };
    let nine: Vec<(u8, Role, Proof)> = (0..9).map(|i| (70 + i, if i < 2 { Role::Spend } else { Role::Recover }, Proof::Given)).collect();
    let waits = |delay: u64, freeze: u64| json!({"threshold": "2", "daily_limit_micros": "1", "delay_seconds": delay.to_string(), "freeze_seconds": freeze.to_string()});
    let cases: Vec<(&str, Vec<(u8, Role, Proof)>, Value, bool, &str)> = vec![
        ("a threshold of one", good.to_vec(), policy(1, LIMIT), true, "the threshold is at least two"),
        ("a threshold above the recovery keys", good.to_vec(), policy(3, LIMIT), true, "at most the number of recovery keys"),
        ("one recovery key", good[..3].to_vec(), policy(2, LIMIT), true, "at most the number of recovery keys"),
        ("no spend key", vec![good[0], good[2], good[3]], policy(2, LIMIT), true, "at least one spend key"),
        ("a wait below the network's minimum", good.to_vec(), waits(29, 120), true, "waiting periods"),
        ("a freeze below the network's minimum", good.to_vec(), waits(60, 29), true, "waiting periods"),
        ("a wait above thirty days", good.to_vec(), waits(30 * 86_400 + 1, 120), true, "waiting periods"),
        ("nine keys", nine, policy(2, LIMIT), true, "too many keys"),
        ("a key without its acceptance", with(1, Proof::Missing), policy(2, LIMIT), true, "must carry its holder's acceptance"),
        ("a sign-in key without its acceptance", with(0, Proof::Missing), policy(2, LIMIT), true, "must carry its holder's acceptance"),
        ("an acceptance of another role", with(2, Proof::OtherRole), policy(2, LIMIT), true, "signature does not verify"),
        ("an acceptance that is no signature", with(3, Proof::Garbage), policy(2, LIMIT), true, "signature does not verify"),
        ("keys out of order", good.to_vec(), policy(2, LIMIT), false, "keys must be distinct, sorted"),
    ];
    let mut seed = 210u8;
    for (what, keys, rules, in_order, why) in cases {
        let list = |subject: Subject| -> Value {
            let entries: Vec<Value> = keys.iter().map(|(seed, role, proof)| key_of(*seed, *role, *proof, subject)).collect();
            let mut list = sorted(entries);
            if !in_order {
                list.as_array_mut().unwrap().reverse();
            }
            list
        };
        // The adopting action.
        let adopting = json!({"keys": list(Subject::Account(ME)), "policy": rules});
        let row = chain.account(ME);
        let by_secure = chain.refuses(&act_tx(&network, ME, row.nonce, row.auth_epoch, 6, security::SECURE, adopting));
        assert!(by_secure.contains(why), "{what}, adopting: {by_secure}");
        // The registration, with a commitment to exactly this set. (Each
        // case registers with a key of its own: a key has one paid
        // commitment at a time.)
        seed += 1;
        let setup = json!({"keys": list(Subject::Registration(seed)), "policy": rules});
        chain.commit(seed, "carol", Some(&setup));
        let by_registration = chain.refuses(&register_tx(&network, seed, "carol", &setup));
        assert_eq!(by_registration, by_secure, "{what}: the two actions refuse the set in different words");
    }
    // The payload itself has one accepted form, like every payload of these
    // rules: no other field, no number in place of a string, no key twice.
    let setup = standard(&network, REGISTRATION);
    chain.commit(REGISTRATION, "alice", Some(&setup));
    let sign = |payload: Value| timecurrency_v5::wire::sign(&network, u64::MAX, 0, 0, security::REGISTER, &payload, &key(REGISTRATION)).unwrap();
    for payload in [
        json!({"name": "alice", "salt": salt(REGISTRATION), "security": setup, "memo": "x"}),
        json!({"name": "alice", "salt": salt(REGISTRATION)}),
        json!({"name": "alice", "salt": salt(REGISTRATION), "security": setup["keys"]}),
        json!({"name": "alice", "security": setup}),
    ] {
        chain.refuses(&sign(payload));
    }
    // An acceptance is given for one registration key. Given for another,
    // or for the number the account will have, it is refused.
    let id = chain.meta().next_account_id;
    for stranger in [standard(&network, THIEF), standard_for_account(&network, id)] {
        chain.commit(seed + 1, "dave", Some(&stranger));
        let refusal = chain.refuses(&register_tx(&network, seed + 1, "dave", &stranger));
        assert!(refusal.contains("signature does not verify"), "{refusal}");
        seed += 1;
    }
    // And one given for a registration is no acceptance for an account.
    let row = chain.account(ME);
    let moved = chain.refuses(&act_tx(&network, ME, row.nonce, row.auth_epoch, 6, security::SECURE, standard(&network, REGISTRATION)));
    assert!(moved.contains("signature does not verify"), "{moved}");
    // Nothing was registered by any of it; the set as the rules ask for it
    // is.
    assert_eq!(chain.meta().account_count, GENESIS_ACCOUNTS);
    chain.block(SECOND, vec![register_tx(&network, REGISTRATION, "alice", &setup)]);
    assert_eq!(chain.meta().account_count, GENESIS_ACCOUNTS + 1);
    chain.engine.audit().unwrap();
}

#[test]
fn a_refused_set_leaves_what_any_refused_reveal_leaves() {
    // Two chains with the same history: on one a registration is refused
    // for its set of keys, on the other a protocol-4 reveal is refused
    // because its name is taken.
    let mut bad_set = Chain::funded(protected());
    let mut taken = Chain::funded(protected());
    let network = bad_set.network.clone();
    assert_eq!(network, taken.network);
    let mut setup = standard(&network, REGISTRATION);
    setup["policy"] = policy(1, LIMIT);
    bad_set.commit(REGISTRATION, "alice", Some(&setup));
    taken.commit(REGISTRATION, "person_3", None);
    let rows = |chain: &Chain| (chain.row(&commit_key(REGISTRATION)).is_some(), chain.account(SPONSOR).balance, chain.meta().account_count, chain.meta().next_account_id, chain.security_rows());
    let before = (rows(&bad_set), rows(&taken));
    assert_eq!(before.0, before.1);
    assert_eq!(before.0, (true, 5 * SECOND - SPONSOR_PAYS, GENESIS_ACCOUNTS, GENESIS_ACCOUNTS, 0));
    let bad = register_tx(&network, REGISTRATION, "alice", &setup);
    assert!(bad_set.refuses(&bad).contains("the threshold is at least two"));
    assert!(taken.refuses(&reveal_tx(&network, REGISTRATION, "person_3")).contains("username unavailable"));
    // A block passes on both. The commitment is still there, the sponsor
    // is not paid back, no account and no row was made.
    for chain in [&mut bad_set, &mut taken] {
        chain.block(SECOND, vec![]);
    }
    assert_eq!((rows(&bad_set), rows(&taken)), before);
    assert_eq!(bad_set.row(&name_key("alice")), None);
    assert_eq!(bad_set.row(&pubkey_key(&pk(REGISTRATION)).unwrap()), None);
    // The key cannot be sponsored again while its commitment lasts, on
    // either chain.
    for chain in [&bad_set, &taken] {
        let again = chain.refuses(&chain.sponsor(REGISTRATION, &commitment(&network, REGISTRATION, "alice", None)));
        assert!(again.contains("unexpired registration commitment already exists"), "{again}");
    }
    // After an hour the commitment is cleaned up, and the name is free for
    // anyone, as it always was.
    for _ in 0..62 {
        bad_set.block(MINUTE, vec![]);
    }
    assert!(bad_set.row(&commit_key(REGISTRATION)).is_none());
    assert!(bad_set.refuses(&bad).contains("paid registration commitment missing or consumed"));
    bad_set.commit(202, "alice", None);
    bad_set.block(SECOND, vec![reveal_tx(&network, 202, "alice")]);
    bad_set.engine.audit().unwrap();
}

#[test]
fn the_paid_commitment_binds_the_set_of_keys() {
    let mut chain = Chain::funded(protected());
    let network = chain.network.clone();
    let setup = standard(&network, REGISTRATION);
    chain.commit(REGISTRATION, "alice", Some(&setup));
    // Somebody else's paid commitment, for another name, made as early, and
    // a commitment made the protocol-4 way.
    let theirs = standard(&network, THIEF);
    chain.commit(THIEF, "mallory", Some(&theirs));
    chain.commit(202, "bob", None);
    let honest = register_tx(&network, REGISTRATION, "alice", &setup);
    let mismatch = |tx: Vec<u8>| {
        let reason = chain.refuses(&tx);
        assert!(reason.contains(REFUSED_COMMITMENT), "{reason}");
    };

    // 1. Whoever holds the registration key, and nothing else of the owner,
    //    cannot take the name with keys of their own. Every key of this set
    //    accepted its role for this very registration key; the set is not
    //    the one committed to.
    let mut swapped = setup.clone();
    swapped["keys"] = sorted(vec![
        registers(&network, REGISTRATION, SIGNIN, Role::Signin),
        registers(&network, REGISTRATION, THIEF, Role::Spend),
        registers(&network, REGISTRATION, SHEET, Role::Recover),
        registers(&network, REGISTRATION, PHRASE, Role::Recover),
    ]);
    mismatch(register_tx(&network, REGISTRATION, "alice", &swapped));
    // One more key, or one key fewer.
    let mut more = setup.clone();
    more["keys"] = sorted(setup["keys"].as_array().unwrap().iter().cloned().chain([registers(&network, REGISTRATION, THIEF, Role::Recover)]).collect());
    mismatch(register_tx(&network, REGISTRATION, "alice", &more));
    // The same keys with a limit a thousand times higher, or without the
    // waits.
    let mut generous = setup.clone();
    generous["policy"] = policy(2, 1000 * LIMIT);
    mismatch(register_tx(&network, REGISTRATION, "alice", &generous));
    let mut hasty = setup.clone();
    hasty["policy"]["delay_seconds"] = json!("30");
    mismatch(register_tx(&network, REGISTRATION, "alice", &hasty));
    // The same set, a role exchanged between two keys.
    let mut exchanged = setup.clone();
    exchanged["keys"] = sorted(vec![
        registers(&network, REGISTRATION, SIGNIN, Role::Spend),
        registers(&network, REGISTRATION, SPEND, Role::Signin),
        registers(&network, REGISTRATION, SHEET, Role::Recover),
        registers(&network, REGISTRATION, PHRASE, Role::Recover),
    ]);
    mismatch(register_tx(&network, REGISTRATION, "alice", &exchanged));
    // The committed set under another name or salt.
    mismatch(register_tx(&network, REGISTRATION, "alicia", &setup));
    let other_salt = json!({"name": "alice", "salt": salt(7), "security": setup});
    mismatch(timecurrency_v5::wire::sign(&network, u64::MAX, 0, 0, security::REGISTER, &other_salt, &key(REGISTRATION)).unwrap());

    // 2. Nor can the name be taken with no set at all: the protocol-4
    //    reveal of the same name and salt does not match either.
    let plain = chain.refuses(&reveal_tx(&network, REGISTRATION, "alice"));
    assert!(plain.contains("name reveal does not match commitment"), "{plain}");

    // 3. Somebody who sees the registration on its way and holds no key of
    //    it: a changed copy is not signed by the registration key,
    let mut altered = honest.clone();
    let at = altered.len() - 64 - 40;
    altered[at] = if altered[at] == b'0' { b'1' } else { b'0' };
    assert_ne!(altered, honest);
    let (height, time, signers, hash) = chain.next(SECOND);
    assert!(chain.engine.prepare(height, time, &[&altered], &signers, hash).is_err());
    assert!(chain.engine.prepare_reference(height, time, &[&altered], &signers, hash).is_err());
    assert!(chain.engine.check_state().unwrap().admit(&altered, SigStatus::Unknown).is_err());
    assert!(chain.engine.prepare_filtered(height, time, &[&altered], &signers, 1 << 20, hash).unwrap().1.is_empty());
    //    the same content signed by a key without a paid commitment is no
    //    registration,
    let unpaid = chain.refuses(&register_tx(&network, 98, "alice", &standard(&network, 98)));
    assert!(unpaid.contains("paid registration commitment missing or consumed"), "{unpaid}");
    //    and a paid commitment for another name does not take this one,
    //    with their own keys or with the owner's.
    mismatch(register_tx(&network, THIEF, "alice", &theirs));
    mismatch(register_tx(&network, THIEF, "alice", &setup));

    // 4. A commitment made the protocol-4 way is not good for a
    //    registration with a set.
    mismatch(register_tx(&network, 202, "bob", &standard(&network, 202)));

    // After all of it both commitments are as they were, and each takes its
    // name with what it committed to.
    let id = chain.meta().next_account_id;
    chain.block(SECOND, vec![honest, reveal_tx(&network, 202, "bob"), register_tx(&network, THIEF, "mallory", &theirs)]);
    assert_eq!(chain.account(id).name, "alice");
    assert_eq!(roles(&chain.account(id), &[SPEND, THIEF]), [Some(Role::Spend), None]);
    assert_eq!(roles(&chain.account(id + 1), &[202]), [None]);
    assert_eq!(chain.account(id + 2).name, "mallory");
    chain.engine.audit().unwrap();
}

#[test]
fn the_commitment_names_everything_it_is_made_of() {
    let network = protected().network_id().unwrap();
    let setup = standard(&network, REGISTRATION);
    let of = |network: &str, seed: u8, name: &str, salt: &str, setup: &Value| security::registration_commitment(network, &pk(seed), name, salt, setup).unwrap();
    let base = of(&network, REGISTRATION, "alice", &salt(1), &setup);
    assert_eq!(base.len(), 64);
    let mut other = setup.clone();
    other["policy"]["daily_limit_micros"] = json!("500001");
    for different in [
        of(&network_id(), REGISTRATION, "alice", &salt(1), &setup),
        of(&network, 202, "alice", &salt(1), &setup),
        of(&network, REGISTRATION, "alic", &salt(1), &setup),
        of(&network, REGISTRATION, "alice", &salt(2), &setup),
        of(&network, REGISTRATION, "alice", &salt(1), &other),
        // The protocol-4 commitment of the same name, key and salt.
        ledger::action_commitment(&network, &pk(REGISTRATION), "alice", &salt(1)).unwrap(),
    ] {
        assert_ne!(different, base);
    }
    // The bytes, written out: the domain, the network, the key, the name
    // and a zero byte, the salt, and the hash of the set as JSON with
    // sorted keys and no spaces.
    let mut bytes = b"TCDEVNET-NAME-PROTECTED-V1\0".to_vec();
    bytes.extend(hex::decode(&network).unwrap());
    bytes.extend(hex::decode(pk(REGISTRATION)).unwrap());
    bytes.extend(b"alice\0");
    bytes.extend([1u8; 32]);
    bytes.extend(Sha256::digest(serde_json::to_vec(&setup).unwrap()));
    assert_eq!(base, hex::encode(Sha256::digest(&bytes)));
    assert!(serde_json::to_string(&setup).unwrap().starts_with(r#"{"keys":[{"proof":""#));
    // What a key signs to accept its role: another domain than for an
    // account, and the registration key where the account's number stands.
    let message = security::registration_key_message(&network, &pk(REGISTRATION), Role::Recover, &pk(SHEET)).unwrap();
    let mut expected = b"TCDEVNET-REGISTER-KEY-V1\0".to_vec();
    expected.extend(hex::decode(&network).unwrap());
    expected.extend(hex::decode(pk(REGISTRATION)).unwrap());
    expected.push(2);
    expected.extend(hex::decode(pk(SHEET)).unwrap());
    assert_eq!(message, expected);
    assert_ne!(message.len(), security::key_message(&network, 5, Role::Recover, &pk(SHEET)).unwrap().len());
}

#[test]
fn of_two_registrations_of_one_name_the_first_wins_whatever_their_kind() {
    let mut genesis = protected();
    genesis.distinct_names = true;
    let mut chain = Chain::funded(genesis);
    let network = chain.network.clone();
    let (first, second, third) = (standard(&network, REGISTRATION), standard(&network, 202), standard(&network, 204));
    chain.block(
        SECOND,
        vec![chain.sponsor(REGISTRATION, &commitment(&network, REGISTRATION, "alice", Some(&first)))],
    );
    for (seed, name, setup) in [(202u8, "alice", Some(&second)), (203, "al_ice", None), (204, "a1ice", Some(&third))] {
        chain.block(SECOND, vec![chain.sponsor(seed, &commitment(&network, seed, name, setup))]);
    }
    chain.block(SECOND, vec![]);
    // One block is offered all four. The first is registered; the same name
    // and the two names that look like it are left out, and each is refused
    // for the reason any registration of it would be.
    let offered = vec![
        register_tx(&network, REGISTRATION, "alice", &first),
        register_tx(&network, 202, "alice", &second),
        reveal_tx(&network, 203, "al_ice"),
        register_tx(&network, 204, "a1ice", &third),
    ];
    let (height, time, signers, hash) = chain.next(SECOND);
    let (_, kept) = chain.engine.prepare_filtered(height, time, &offered, &signers, 1 << 20, hash).unwrap();
    assert_eq!(kept, offered[..1]);
    let mut pending = chain.engine.check_state().unwrap();
    pending.admit(&offered[0], SigStatus::Unknown).unwrap();
    assert!(format!("{:#}", pending.admit(&offered[1], SigStatus::Unknown).unwrap_err()).contains("username unavailable"));
    for look_alike in &offered[2..] {
        let reason = format!("{:#}", pending.admit(look_alike, SigStatus::Unknown).unwrap_err());
        assert!(reason.contains("is too close to the existing name alice"), "{reason}");
    }
    chain.block(SECOND, kept);
    assert!(chain.refuses(&offered[1]).contains("username unavailable"));
    assert!(chain.refuses(&offered[3]).contains(&names::too_close("a1ice", "alice")));
    assert_eq!(chain.meta().account_count, GENESIS_ACCOUNTS + 1);
    chain.engine.audit().unwrap();
}

/// The set a genesis gives account `id`: a sign-in key, a spend key and two
/// recovery keys, from the key seeds `seed` to `seed + 3`.
fn owner_set(id: u64, seed: u8) -> ProtectedAccount {
    let mut keys: Vec<ProtectedKey> = [(seed, Role::Signin), (seed + 1, Role::Spend), (seed + 2, Role::Recover), (seed + 3, Role::Recover)]
        .into_iter()
        .map(|(seed, role)| ProtectedKey { public_key: pk(seed), role })
        .collect();
    keys.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    ProtectedAccount { id, keys, policy: Policy { threshold: 2, daily_limit_micros: LIMIT, delay_seconds: DELAY, freeze_seconds: FREEZE } }
}
/// The test genesis in which the four validators' owner accounts start
/// protected: account `i` with the key seeds `70 + 5 i` and up.
fn protected_owners() -> Genesis {
    let mut genesis = protected();
    genesis.protected_accounts = (0..4).map(|id| owner_set(id, 70 + 5 * id as u8)).collect();
    genesis
}

#[test]
fn a_genesis_can_start_accounts_protected() {
    let genesis = protected_owners();
    genesis.validate_new().unwrap();
    let mut chain = Chain::new(genesis.clone());
    let network = chain.network.clone();
    assert_eq!(chain.security_rows(), 4);
    for id in 0..4u64 {
        let seed = 70 + 5 * id as u8;
        let row = chain.account(id);
        // The identity key is what the genesis says, and it is no key of
        // the account any more.
        assert_eq!(row.public_key, pk(id as u8 + 1));
        assert_eq!(
            roles(&row, &[seed, seed + 1, seed + 2, seed + 3, id as u8 + 1]),
            [Some(Role::Signin), Some(Role::Spend), Some(Role::Recover), Some(Role::Recover), None]
        );
        assert_eq!((row.devices.len(), row.nonce, row.auth_epoch), (4, 0, 0));
        let security = chain.security(id).unwrap();
        assert_eq!((security.version, security.allowance_micros, security.allowance_elapsed_micros, security.next_id), (1, LIMIT, 0, 1));
        assert_eq!(security.policy, genesis.protected_accounts[id as usize].policy);
    }
    // The other genesis accounts are as protocol 4 makes them.
    assert_eq!(roles(&chain.account(4), &[5]), [None]);
    assert_eq!(chain.security(4), None);
    chain.engine.audit().unwrap();
    // The owners earn as before, and act with the keys of their roles from
    // the first block that pays them.
    for _ in 0..20 {
        chain.block(MINUTE, vec![]);
    }
    let earned = chain.account(0).balance;
    assert!(earned > 5 * SECOND);
    let pay = |chain: &Chain, signer: u8, amount: u64| chain.transfer(0, signer, SHOP, amount);
    for (tx, why) in [
        (pay(&chain, 1, 1_000), "not authorized"),
        (pay(&chain, 70, 1_000), "permission denied"),
        (pay(&chain, 72, 1_000), "permission denied"),
        (pay(&chain, 71, LIMIT), "over the daily limit"),
        (act_tx(&network, 0, 0, 0, 1, security::SECURE, standard_for_account(&network, 0)), "already secured"),
    ] {
        let reason = chain.refuses(&tx);
        assert!(reason.contains(why), "expected {why}, got: {reason}");
    }
    chain.block(SECOND, vec![pay(&chain, 71, 100_000)]);
    assert_eq!(chain.account(SHOP).balance, 100_000);
    // A recovery key freezes, and the spend key with a recovery key lifts
    // the freeze: the account has all of its rules.
    let expires = chain.now() + 600 * SECOND;
    chain.block(SECOND, vec![first_freeze(&network, 0, 73, expires)]);
    assert!(chain.refuses(&pay(&chain, 71, 1_000)).contains("account is frozen"));
    chain.block(SECOND, vec![first_root(&network, 0, 71, &[71, 72], json!({"type": "unfreeze", "freezes": "1"}), expires)]);
    chain.block(SECOND, vec![pay(&chain, 71, 1_000)]);
    assert!(chain.account(0).balance > earned - 200_000, "the owner still earns");
    chain.engine.audit().unwrap();

    // The list is part of the genesis and of the network id.
    let meta: Value = serde_json::from_slice(&chain.row(b"meta").unwrap()).unwrap();
    assert_eq!(meta["config"]["protected_accounts"].as_array().unwrap().len(), 4);
    assert_eq!(meta["config"]["protected_registration"], true);
    assert_ne!(genesis.network_id().unwrap(), protected().network_id().unwrap());
}

#[test]
fn a_genesis_with_a_wrong_list_of_protected_accounts_is_refused() {
    // The list needs the setting, names genesis accounts, each once, in
    // the order of their ids: judged whenever a genesis is read.
    let structure = |change: fn(&mut Genesis)| {
        let mut genesis = protected_owners();
        change(&mut genesis);
        format!("{:#}", genesis.validate().unwrap_err())
    };
    assert!(structure(|genesis| genesis.protected_registration = false).contains("need the setting protected_registration"));
    assert!(structure(|genesis| genesis.protected_accounts[3].id = 500).contains("is not an account of this genesis"));
    assert!(structure(|genesis| genesis.protected_accounts.swap(0, 1)).contains("listed once each, in the order of their ids"));
    assert!(structure(|genesis| genesis.protected_accounts[1] = genesis.protected_accounts[0].clone()).contains("listed once each"));
    // The set of each account is judged when a chain is started, by the
    // rules of every set of keys. The refusal names the account.
    let set = |change: fn(&mut ProtectedAccount)| {
        let mut genesis = protected_owners();
        change(&mut genesis.protected_accounts[2]);
        genesis.validate().unwrap();
        let refusal = format!("{:#}", genesis.validate_new().unwrap_err());
        assert!(refusal.starts_with("protected genesis account 2: "), "{refusal}");
        assert!(genesis.validate_initial().is_err());
        assert!(Chain::try_new(genesis.clone()).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(App::open(dir.path().join("state.db")).unwrap().try_init(init(&genesis)).is_err());
        refusal
    };
    assert!(set(|account| account.policy.threshold = 1).contains("the threshold is at least two"));
    assert!(set(|account| account.policy.threshold = 3).contains("at most the number of recovery keys"));
    assert!(set(|account| account.policy.delay_seconds = 29).contains("waiting periods"));
    assert!(set(|account| account.policy.freeze_seconds = 31 * 86_400).contains("waiting periods"));
    assert!(set(|account| account.keys.retain(|key| key.role != Role::Spend)).contains("at least one spend key"));
    assert!(set(|account| account.keys.reverse()).contains("keys must be distinct, sorted"));
    assert!(set(|account| account.keys[1] = account.keys[0].clone()).contains("keys must be distinct, sorted"));
    assert!(set(|account| account.keys.clear()).contains("keys must be distinct, sorted"));
    assert!(set(|account| account.keys[0].public_key = "00".repeat(32)).contains("Ed25519 key"));
    assert!(set(|account| account.keys = (0..9).map(|i| ProtectedKey { public_key: pk(150 + i), role: Role::Recover }).collect()).contains("keys must be distinct, sorted and at most eight"));
}

#[test]
fn the_production_profile_requires_both_settings() {
    // A production genesis: twenty starting organizations, hourly auction,
    // two-day recovery delay, the stake hand-over rule, distinct names.
    let mut genesis: Genesis = serde_json::from_slice(&serde_json::to_vec(&genesis_v4_with(24)).unwrap()).unwrap();
    genesis.profile = pos::Profile::Production;
    genesis.validators = (0..20)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.auction.epoch_seconds = 3600;
    genesis.recovery_min_delay_micros = 2 * pos::DAY;
    genesis.stake_handover = true;
    genesis.distinct_names = true;
    // The profile's later requirement, which `tests/service_records.rs`
    // tests.
    genesis.service_records = true;
    let refused = |genesis: &Genesis, why: &str| {
        // A state created before the rules still opens.
        genesis.validate().unwrap();
        for refusal in [genesis.validate_initial().unwrap_err(), genesis.validate_new().unwrap_err()] {
            let refusal = format!("{refusal:#}");
            assert!(refusal.contains(why), "{refusal}");
        }
        assert!(format!("{:#}", Chain::try_new(genesis.clone()).err().unwrap()).contains(why));
        let dir = tempfile::tempdir().unwrap();
        assert!(App::open(dir.path().join("state.db")).unwrap().try_init(init(genesis)).is_err());
    };
    refused(&genesis, "production profile requires waits that survive a stop (waits_survive_stops)");
    // Neither stands in for the other.
    let mut registration_only = genesis.clone();
    registration_only.protected_registration = true;
    refused(&registration_only, "production profile requires waits that survive a stop (waits_survive_stops)");
    genesis.waits_survive_stops = true;
    refused(&genesis, "production profile requires registrations that can carry a set of keys (protected_registration)");
    genesis.protected_registration = true;
    genesis.validate_new().unwrap();
    // With the twenty owner accounts protected, as the ceremony writes it.
    // The waits of a production network are at least two days.
    genesis.protected_accounts = (0..20)
        .map(|id| {
            let mut account = owner_set(id, 121 + 4 * id as u8);
            account.policy.delay_seconds = 2 * 86_400;
            account.policy.freeze_seconds = 2 * 86_400;
            account
        })
        .collect();
    genesis.validate_new().unwrap();
    let chain = Chain::new(genesis.clone());
    assert_eq!(chain.security_rows(), 20);
    assert_eq!(chain.meta().stopped_micros, Some(0));
    chain.engine.audit().unwrap();
    // A lab wait in a production genesis is refused with the account named.
    genesis.protected_accounts[7].policy.delay_seconds = 3600;
    assert!(format!("{:#}", genesis.validate_new().unwrap_err()).starts_with("protected genesis account 7: waiting periods"));
    // The laboratory profile takes every combination.
    for (waits, registration) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut lab = genesis_v5();
        lab.waits_survive_stops = waits;
        lab.protected_registration = registration;
        lab.validate_new().unwrap();
    }
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
/// A row as a wallet is served it with `/v4/state`, asked for account `id`
/// with its security row: the bytes under `key`, or none if the answer
/// proves that there is no such row.
fn served(app: &App, id: u64, key: &[u8]) -> Option<Vec<u8>> {
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()], "include_security": true }));
    let wanted = hex::encode(key);
    let entry = view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == wanted.as_str()).expect("the answer has an entry for the row");
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
    /// What a proposer makes of `txs`.
    fn prepare(&self, delta: u64, txs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        self.app
            .prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: 1 << 20,
                txs: txs.iter().cloned().map(Into::into).collect(),
                local_last_commit: Some(ExtendedCommitInfo {
                    round: 0,
                    votes: voters(&self.genesis)
                        .into_iter()
                        .map(|validator| ExtendedVoteInfo { validator: Some(validator), block_id_flag: BlockIdFlag::Commit as i32, ..Default::default() })
                        .collect(),
                }),
                height: self.height + 1,
                time: self.time(delta),
                ..Default::default()
            })
            .txs
            .iter()
            .map(|tx| tx.to_vec())
            .collect()
    }
    /// The mempool's answer to `tx`.
    fn check(&self, tx: &[u8]) -> ResponseCheckTx {
        self.app.check_batch(vec![RequestCheckTx { tx: tx.to_vec().into(), r#type: 0 }]).pop().unwrap()
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&served(&self.app, id, &account_key(id)).expect("account exists")).unwrap()
    }
    fn security(&self, id: u64) -> Option<Security> {
        served(&self.app, id, &security::key(id)).map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn transfer(&self, from: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        signed(&self.network, from, row.nonce + 1, row.auth_epoch, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    /// The answers of this node to a registration whose set is not the one
    /// committed to.
    fn refuses_the_swapped_set(&self, tx: &[u8]) {
        let answer = self.check(tx);
        assert_ne!(answer.code, 0, "the mempool admitted it");
        assert!(answer.log.contains(REFUSED_COMMITMENT), "{}", answer.log);
        assert!(self.prepare(SECOND, &[tx.to_vec()]).is_empty(), "a proposer kept it");
        assert!(!self.accepts(SECOND, vec![tx.to_vec()]), "a validator accepted it");
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
fn a_node_registers_protected_accounts_and_serves_their_settings_after_a_restart_and_a_state_sync() {
    let dir = tempfile::tempdir().unwrap();
    // Both rules of this change, and protected owners in the genesis.
    let mut genesis = protected_owners();
    genesis.waits_survive_stops = true;
    // Snapshots for peers every ten blocks, in chunks of 1 KiB.
    let serving = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let path = dir.path().join("source.db");
    let mut source = Node::start(&path, serving, &genesis);
    let network = source.network.clone();
    // A wallet is served the settings of a genesis account that starts
    // protected from the state of height zero.
    assert_eq!(source.security(0).unwrap().version, 1);
    assert_eq!(source.security(4), None);
    source.block(SECOND, vec![]);
    while source.account(0).balance < 5 * SECOND {
        assert!(source.height < 12, "validator owners were not funded");
        source.block(MINUTE, vec![]);
    }
    // Owner 0 pays the sponsor with its spend key (seed 71), within its
    // daily limit.
    let fund = source.transfer(0, 71, SPONSOR, 100_000);
    source.block(SECOND, vec![fund]);
    let setup = standard(&network, REGISTRATION);
    let sponsor = sponsor_tx(&network, &source.account(SPONSOR), REGISTRATION, &commitment(&network, REGISTRATION, "alice", Some(&setup)), source.elapsed, 3600);
    source.block(SECOND, vec![sponsor]);
    source.block(SECOND, vec![]);
    // The mempool, a proposer and a validator take the registration, and
    // refuse it with another set.
    let register = register_tx(&network, REGISTRATION, "alice", &setup);
    let mut swapped = setup.clone();
    swapped["policy"] = policy(2, 1000 * LIMIT);
    let swapped = register_tx(&network, REGISTRATION, "alice", &swapped);
    source.refuses_the_swapped_set(&swapped);
    assert_eq!(source.check(&register).code, 0);
    assert_eq!(source.prepare(SECOND, std::slice::from_ref(&register)), std::slice::from_ref(&register));
    let id = GENESIS_ACCOUNTS;
    source.block(SECOND, vec![register]);
    assert!(source.height < 20, "the registration came after the snapshot");
    // A wallet reads the new account with its security row, proven.
    let registered = source.account(id);
    assert_eq!(roles(&registered, &[SPEND, REGISTRATION]), [Some(Role::Spend), None]);
    let row = source.security(id).expect("the security row of the registered account");
    assert_eq!((row.version, row.allowance_micros), (1, LIMIT));
    while source.height < 22 {
        source.block(SECOND, vec![]);
    }

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
    assert_eq!(joiner.info(RequestInfo::default()).last_block_app_hash, trusted);
    for (request, response) in &source.log[20..] {
        assert_eq!(joiner.try_finalize(request.clone()).unwrap(), *response);
        joiner.try_commit().unwrap();
    }
    assert_eq!(joiner.head().unwrap(), source.app.head().unwrap());
    let mut joined = Node { app: joiner, genesis: genesis.clone(), network: network.clone(), height: source.height, elapsed: source.elapsed, log: Vec::new() };

    // The first node stops and starts again from its restart snapshot.
    let (height, root) = source.app.head().unwrap().unwrap();
    source.app.snapshot().unwrap().expect("a restart snapshot");
    let elapsed = source.elapsed;
    drop(source);
    let app = App::open_with_options(&path, serving).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    let mut restarted = Node { app, genesis: genesis.clone(), network: network.clone(), height: height as i64, elapsed, log: Vec::new() };

    // On both, the registered account and the protected owner are what
    // they were, and go on under their rules: the owner pays the new
    // account, whose spend key pays on within its limit and not above it.
    for node in [&mut restarted, &mut joined] {
        assert_eq!(node.account(id), registered);
        assert_eq!(node.security(id), Some(row.clone()));
        assert_eq!(node.security(0).unwrap().version, 1);
        let pay_in = node.transfer(0, 71, id, 300_000);
        node.block(SECOND, vec![pay_in]);
        let by_registration_key = node.transfer(id, REGISTRATION, SHOP, 1_000);
        assert_ne!(node.check(&by_registration_key).code, 0);
        assert!(!node.accepts(SECOND, vec![by_registration_key]));
        let pay_on = node.transfer(id, SPEND, SHOP, 100_000);
        node.block(SECOND, vec![pay_on]);
        assert_eq!(node.account(SHOP).balance, 100_000);
    }
    assert_eq!(restarted.app.head().unwrap(), joined.app.head().unwrap());

    // The recount of both, offline: five security rows, and the report of
    // the command an operator runs names the rules of the network.
    for (node, node_path) in [(restarted, path), (joined, joined_path)] {
        node.app.snapshot().unwrap();
        drop(node);
        let report = recount_report(&node_path);
        assert_eq!(report["protected_registration"], true, "{report}");
        assert_eq!(report["waits_survive_stops"], true, "{report}");
        assert_eq!(report["stopped_micros"], "0", "{report}");
        assert_eq!(report["accounts"], (GENESIS_ACCOUNTS + 1).to_string());
        let engine = Engine::open_with_history(Store::open(node_path.with_extension("v5state")).unwrap(), node_path.with_extension("history")).unwrap();
        engine.audit().unwrap();
    }
}

/// Writes the bytes the SDK (`client-v4/time-sdk.js`,
/// `client-v4/account-security.mjs`) must reproduce for a registration that
/// carries a set of keys. Run with `V5_EXPORT_REGISTRATION_FIXTURE=1` after
/// any change to the formats; `client-v4/protected-registration.test.mjs`
/// then compares against the new file.
#[test]
fn export_the_fixture_for_the_sdk() {
    if std::env::var("V5_EXPORT_REGISTRATION_FIXTURE").is_err() {
        return;
    }
    let mut chain = Chain::funded(protected());
    let network = chain.network.clone();
    let setup = standard(&network, REGISTRATION);
    let committed = commitment(&network, REGISTRATION, "alice", Some(&setup));
    let sponsor_row = chain.account(SPONSOR);
    let sponsor = chain.sponsor(REGISTRATION, &committed);
    let sponsor_expires = chain.now() + 3600 * SECOND;
    chain.block(SECOND, vec![sponsor.clone()]);
    chain.block(SECOND, vec![]);
    let register = register_tx(&network, REGISTRATION, "alice", &setup);
    let id = chain.meta().next_account_id;
    let seeds = [("registration", REGISTRATION), ("signin", SIGNIN), ("spend", SPEND), ("sheet", SHEET), ("phrase", PHRASE), ("sponsor", SPONSOR as u8 + 1)];
    let acceptances: Vec<Value> = [(SIGNIN, Role::Signin), (SPEND, Role::Spend), (SHEET, Role::Recover), (PHRASE, Role::Recover)]
        .into_iter()
        .map(|(seed, role)| {
            let message = security::registration_key_message(&network, &pk(REGISTRATION), role, &pk(seed)).unwrap();
            json!({"public_key": pk(seed), "role": role_name(role), "message": hex::encode(&message), "proof": hex::encode(key(seed).sign(&message).to_bytes())})
        })
        .collect();
    let fixture = json!({
        "network_id": network,
        "seeds": seeds.iter().map(|(name, seed)| json!({"name": name, "seed_hex": hex::encode([*seed; 32]), "public_key": pk(*seed)})).collect::<Vec<_>>(),
        "name": "alice",
        "salt": salt(REGISTRATION),
        "policy": {"threshold": "2", "daily_limit_micros": LIMIT.to_string(), "delay_seconds": DELAY.to_string(), "freeze_seconds": FREEZE.to_string()},
        "acceptances": acceptances,
        "security": setup,
        "commitment": committed,
        "protocol_4_commitment": commitment(&network, REGISTRATION, "alice", None),
        "sponsor": {"account": {"id": SPONSOR.to_string(), "nonce": sponsor_row.nonce.to_string(), "auth_epoch": sponsor_row.auth_epoch.to_string()}, "expires_elapsed_micros": sponsor_expires.to_string(), "action_hex": hex::encode(&sponsor)},
        "registration": {"action_hex": hex::encode(&register), "account_id": id.to_string()},
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client-v4/protected-registration.fixture.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    // The exported actions are the real thing: the chain accepts them.
    chain.block(SECOND, vec![register]);
    assert_eq!(chain.account(id).name, "alice");
}
