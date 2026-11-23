//! Names that look alike (`distinct_names` in the genesis; the rule and its
//! rows are described in `src/names.rs`, the skeleton's test vectors are in
//! `spec/name-skeleton-vectors.json` and read by that module's own tests).
//!
//! Here: how a network chooses the rule and that one that does not is
//! unchanged (its recorded roots are in `names_unchanged.rs`); the genesis;
//! what is refused and what is accepted; that a refusal changes nothing;
//! the recount; and a node, through its mempool, its proofs, a restart and
//! state sync.
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
use timecurrency_v5::engine::{Audit, Engine, Meta, account_key, name_key, pubkey_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::names;
use timecurrency_v5::proof::ProofEntry;
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::statesync::NodeOptions;
use timecurrency_v5::store::Store;
use timecurrency_v5::transport::BatchCheck;

const SECOND: u64 = 1_000_000;
/// What a sponsor pays for a registration on these networks: the
/// registration charge and the fee of the action.
const SPONSOR_PAYS: u64 = 10_000 + 1_000;

/// The test genesis with the rule.
fn distinct() -> Genesis {
    let mut genesis = genesis_v5();
    genesis.distinct_names = true;
    genesis
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
/// Genesis account `row` (key seed `id + 1`) pays for the registration of
/// the identity `seed` under `name`. The commitment lasts `lifetime` seconds
/// from `now`.
fn sponsor_tx(network: &str, row: &Account, seed: u8, name: &str, now: u64, lifetime: u64) -> Vec<u8> {
    let salt = hex::encode([seed; 32]);
    let commitment = ledger::action_commitment(network, &pk(seed), name, &salt).unwrap();
    let expiry = now + lifetime * SECOND;
    let consent = registration::consent_bytes(
        pos::hex32(network).unwrap(),
        row.id,
        pos::hex32(&pk(seed)).unwrap(),
        pos::hex32(&commitment).unwrap(),
        expiry,
    );
    let payload: Value = json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())});
    timecurrency_v5::wire::sign(network, row.id, row.nonce + 1, row.auth_epoch, 44, &payload, &key(row.id as u8 + 1)).unwrap()
}
/// The new identity takes its name: an action without an account.
fn reveal_tx(network: &str, seed: u8, name: &str) -> Vec<u8> {
    signed(network, u64::MAX, 0, 0, seed, ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: hex::encode([seed; 32]) }))
}
/// The row that holds the paid commitment of the identity `seed`.
fn commit_key(seed: u8) -> Vec<u8> {
    registration::commit_key(&pos::hex32(&pk(seed)).unwrap())
}
/// The value of the row of a skeleton: the name that owns it.
fn owner(name: &str) -> Option<Vec<u8>> {
    Some(serde_json::to_vec(name).unwrap())
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
    /// A chain on which the validators' owners (accounts 0 to 3) have earned.
    fn funded(genesis: Genesis) -> Self {
        let mut chain = Self::new(genesis);
        for _ in 0..20 {
            chain.block(60 * SECOND, vec![]);
        }
        chain
    }
    fn meta(&self) -> &Meta {
        self.engine.meta().unwrap()
    }
    fn now(&self) -> u64 {
        self.meta().elapsed_micros().unwrap()
    }
    fn root(&self) -> [u8; 32] {
        self.engine.version().unwrap().root()
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    fn transfer(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        signed(&self.network, from, row.nonce + 1, row.auth_epoch, from as u8 + 1, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn sponsor(&self, sponsor: u64, seed: u8, name: &str, lifetime: u64) -> Vec<u8> {
        sponsor_tx(&self.network, &self.account(sponsor), seed, name, self.now(), lifetime)
    }
    fn reveal(&self, seed: u8, name: &str) -> Vec<u8> {
        reveal_tx(&self.network, seed, name)
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
    /// A block with `offered`, as a proposer builds it and a validator
    /// checks it. Returns how many of the actions it kept.
    fn propose(&mut self, delta: u64, offered: Vec<Vec<u8>>) -> usize {
        let (height, time, signers, hash) = self.next(delta);
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &offered, &signers, 1 << 20, hash).unwrap();
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
        kept.len()
    }
    /// A block in which every action is accepted.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let offered = txs.len();
        if self.propose(delta, txs.clone()) != offered {
            let (height, time, signers, hash) = self.next(delta);
            // (The block is committed; the reasons are those of each action alone on the state after it.)
            let reasons: Vec<String> = txs
                .iter()
                .map(|tx| match self.engine.prepare(height, time, &[tx], &signers, hash) {
                    Ok(_) => "accepted".into(),
                    Err(error) => format!("{error:#}"),
                })
                .collect();
            panic!("an action was left out of the block before height {height}: {reasons:?}");
        }
    }
    /// Why `tx` is refused in the next block, by a validator. The reference
    /// path refuses it too, the mempool refuses it for the same reason, and
    /// a proposer leaves it out: its block is the block without it. Nothing
    /// is committed.
    fn refuses(&self, tx: &[u8]) -> String {
        let (height, time, signers, hash) = self.next(SECOND);
        let reason = match self.engine.prepare(height, time, &[tx], &signers, hash) {
            Ok(_) => panic!("the action was accepted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(self.engine.prepare_reference(height, time, &[tx], &signers, hash).is_err(), "the reference path accepted it");
        let admission = self.engine.check_state().unwrap().admit(tx, SigStatus::Unknown);
        assert_eq!(format!("{:#}", admission.expect_err("the mempool admitted it")), reason, "the mempool's reason");
        let (proposed, kept) = self.engine.prepare_filtered(height, time, &[tx], &signers, 1 << 20, hash).unwrap();
        assert!(kept.is_empty(), "a proposer kept it");
        let none: [Vec<u8>; 0] = [];
        let empty = self.engine.prepare(height, time, &none, &signers, hash).unwrap();
        assert_eq!(proposed.root, empty.root, "a refused action left something in the proposer's block");
        reason
    }
    /// A sponsored registration: the sponsor's action, then the reveal in the
    /// next block. Returns the new account's id.
    fn register(&mut self, sponsor: u64, seed: u8, name: &str) -> u64 {
        self.block(SECOND, vec![self.sponsor(sponsor, seed, name, 3600)]);
        let id = self.meta().next_account_id;
        self.block(SECOND, vec![self.reveal(seed, name)]);
        let row = self.account(id);
        assert_eq!((row.name.as_str(), row.public_key.as_str()), (name, pk(seed).as_str()));
        assert_eq!(self.row(&name_key(name)), Some(serde_json::to_vec(&id.to_string()).unwrap()));
        id
    }
    /// A paid commitment for `name`, then the refusal of its reveal. (The
    /// mempool judges on the last block and takes a reveal one block after
    /// its commitment's: a block passes first.)
    fn refused(&mut self, sponsor: u64, seed: u8, name: &str) -> String {
        self.block(SECOND, vec![self.sponsor(sponsor, seed, name, 3600)]);
        self.block(SECOND, vec![]);
        self.refuses(&self.reveal(seed, name))
    }
    /// How many rows the rule holds.
    fn skeleton_rows(&self) -> u64 {
        let mut rows = 0;
        self.engine
            .version()
            .unwrap()
            .audit_verified(|_| {})
            .unwrap()
            .for_each_prefix(names::PREFIX, |_, _| {
                rows += 1;
                Ok(())
            })
            .unwrap();
        rows
    }
}

#[test]
fn a_network_without_the_setting_is_unchanged() {
    let genesis = genesis_v5();
    assert!(!genesis.distinct_names);
    let text = serde_json::to_string(&genesis).unwrap();
    assert!(!text.contains("distinct_names"), "{text}");
    // The id the protocol-4 engine computes for the same genesis.
    assert_eq!(genesis.network_id().unwrap(), network_id(), "protocol-4 network id");
    let mut chain = Chain::funded(genesis);
    assert!(!String::from_utf8_lossy(&chain.row(b"meta").unwrap()).contains("distinct_names"));
    // Names that look alike, and a name of underscores, are registered as
    // they always were, and there is no row of the rule.
    for (index, name) in ["alice", "al_ice", "paypa1", "paypal", "__", "barn", "bam"].iter().enumerate() {
        chain.register(index as u64 % 4, 201 + index as u8, name);
    }
    assert_eq!(chain.skeleton_rows(), 0);
    assert_eq!(chain.row(&names::key("alice")), None);
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 7);
}

#[test]
fn the_setting_is_written_one_way_and_last() {
    let parse = |value: Value| {
        let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
        genesis["distinct_names"] = value;
        serde_json::from_value::<Genesis>(genesis)
    };
    assert!(parse(json!(true)).unwrap().distinct_names);
    // Not using the rule is written by leaving the field out.
    for refused in [json!(false), json!("true"), json!(1), json!(null), json!({})] {
        assert!(parse(refused.clone()).is_err(), "{refused}");
    }
    // Tools that build a genesis compute the network id from their own
    // encoding, so the position of the field is part of the format: last,
    // after every other optional setting.
    let mut genesis = genesis_v5();
    genesis.validators = (0..7)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.fees_to_validators_ppm = 1_000_000;
    genesis.fee_micros = 10;
    genesis.all_new_time_to_validators = true;
    genesis.stake_handover = true;
    let without = serde_json::to_string(&genesis).unwrap();
    assert!(without.ends_with(r#""stake_handover":true}"#), "{without}");
    genesis.distinct_names = true;
    let with = serde_json::to_string(&genesis).unwrap();
    assert_eq!(with, format!("{},\"distinct_names\":true}}", without.strip_suffix('}').unwrap()));
    let parsed: Genesis = serde_json::from_str(&with).unwrap();
    assert_eq!(parsed.network_id().unwrap(), genesis.network_id().unwrap());
    // Alone, it follows the protocol-4 fields directly.
    let plain = serde_json::to_string(&genesis_v5()).unwrap();
    assert_eq!(serde_json::to_string(&distinct()).unwrap(), format!("{},\"distinct_names\":true}}", plain.strip_suffix('}').unwrap()));
    // The setting is part of the network id.
    assert_ne!(distinct().network_id().unwrap(), network_id());
}

#[test]
fn every_genesis_name_gets_its_row() {
    let plain = Chain::new(genesis_v5());
    let chain = Chain::new(distinct());
    assert!(String::from_utf8_lossy(&chain.row(b"meta").unwrap()).contains(r#""distinct_names":true"#));
    // The twelve genesis accounts are person_0 to person_11.
    let expected = [
        "persono", "personl", "person2", "person3", "person4", "person5", "person6", "person7", "person8", "person9", "personlo", "personll",
    ];
    for (id, skeleton) in expected.iter().enumerate() {
        let name = format!("person_{id}");
        assert_eq!(names::skeleton(&name), *skeleton);
        assert_eq!(chain.row(&names::key(skeleton)), owner(&name), "{name}");
    }
    assert_eq!(chain.skeleton_rows(), GENESIS_ACCOUNTS);
    // Twelve rows more than the same genesis without the rule, and nothing else.
    let (with, without) = (chain.engine.audit().unwrap(), plain.engine.audit().unwrap());
    assert_eq!(with.authenticated_leaves, without.authenticated_leaves + GENESIS_ACCOUNTS);
    assert_eq!(with.account_count, without.account_count);
    assert_ne!(chain.root(), plain.root());
}

#[test]
fn a_genesis_whose_names_look_alike_or_have_no_skeleton_is_refused() {
    // person_0 and person0.
    let mut alike = distinct();
    alike.ledger.accounts[1].name = "person0".into();
    let refusal = format!("{:#}", alike.validate().unwrap_err());
    assert!(refusal.contains("person_0") && refusal.contains("person0") && refusal.contains("look alike"), "{refusal}");
    assert!(alike.validate_new().is_err() && alike.network_id().is_err());
    let refusal = format!("{:#}", Chain::try_new(alike.clone()).err().unwrap());
    assert!(refusal.contains("look alike"), "{refusal}");
    // As a file: the node refuses it at InitChain.
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(dir.path().join("state.db")).unwrap();
    let refusal = format!("{:#}", app.try_init(init(&alike)).unwrap_err());
    assert!(refusal.contains("look alike"), "{refusal}");
    // Further apart in the list, and by the other parts of the rule.
    for (index, name) in [(11, "person_l"), (7, "p_e_r_s_o_n_2"), (2, "_personlo")] {
        let mut alike = distinct();
        alike.ledger.accounts[index].name = name.into();
        let refusal = format!("{:#}", alike.validate().unwrap_err());
        assert!(refusal.contains(name) && refusal.contains("look alike"), "{name}: {refusal}");
    }
    // Underscores alone.
    let mut empty = distinct();
    empty.ledger.accounts[3].name = "___".into();
    let refusal = format!("{:#}", empty.validate().unwrap_err());
    assert!(refusal.contains("___") && refusal.contains("no letter and no digit"), "{refusal}");
    assert!(Chain::try_new(empty.clone()).is_err());
    // Without the setting these are the genesis files they always were.
    for mut genesis in [alike, empty] {
        genesis.distinct_names = false;
        genesis.validate_new().unwrap();
        let chain = Chain::new(genesis);
        assert_eq!(chain.skeleton_rows(), 0);
        chain.engine.audit().unwrap();
    }
}

#[test]
fn the_production_profile_requires_it() {
    // A production genesis: twenty starting organizations, hourly auction,
    // two-day recovery delay, the stake hand-over rule.
    let mut genesis: Genesis = serde_json::from_slice(&serde_json::to_vec(&genesis_v4_with(24)).unwrap()).unwrap();
    genesis.profile = pos::Profile::Production;
    genesis.validators = (0..20)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.auction.epoch_seconds = 3600;
    genesis.recovery_min_delay_micros = 2 * pos::DAY;
    genesis.stake_handover = true;
    // The profile's three later requirements are met here:
    // `tests/waits_survive_stops.rs`, `tests/protected_registration.rs` and
    // `tests/service_records.rs` test them.
    genesis.waits_survive_stops = true;
    genesis.protected_registration = true;
    genesis.service_records = true;
    // A new network is refused; a state created before the rule still opens.
    genesis.validate().unwrap();
    for refusal in [genesis.validate_initial().unwrap_err(), genesis.validate_new().unwrap_err()] {
        let refusal = format!("{refusal:#}");
        assert!(refusal.contains("production profile requires distinct account names"), "{refusal}");
    }
    let refusal = format!("{:#}", Chain::try_new(genesis.clone()).err().unwrap());
    assert!(refusal.contains("distinct account names"), "{refusal}");
    let dir = tempfile::tempdir().unwrap();
    let app = App::open(dir.path().join("state.db")).unwrap();
    assert!(app.try_init(init(&genesis)).is_err());
    // Neither rule stands in for the other.
    let mut names_only = genesis.clone();
    names_only.stake_handover = false;
    names_only.distinct_names = true;
    assert!(format!("{:#}", names_only.validate_new().unwrap_err()).contains("stake hand-over"));
    genesis.distinct_names = true;
    genesis.validate_new().unwrap();
    let chain = Chain::new(genesis);
    assert_eq!(chain.skeleton_rows(), 24);
    chain.engine.audit().unwrap();
    // The laboratory profile takes both.
    genesis_v5().validate_new().unwrap();
    distinct().validate_new().unwrap();
}

#[test]
fn a_look_alike_is_refused_and_a_distinct_name_is_accepted() {
    let mut chain = Chain::funded(distinct());
    let mut seed = 200u8;
    let mut next = || {
        seed += 1;
        seed
    };
    let mut accounts = GENESIS_ACCOUNTS;
    // Each line: a name that is registered, then names that look like it.
    let cases: [(&str, &[&str]); 8] = [
        ("alice", &["al_ice", "_alice_", "a_l_i_c_e", "a1ice", "alice_"]),
        ("paypal", &["paypa1", "pay_pal", "paypa_1"]),
        ("g00gle", &["google", "go0gle", "g_o_o_g_l_e"]),
        ("barn", &["bam", "ba_rn", "b_am"]),
        ("wv", &["vvv", "v_v_v", "w_v", "vw", "v_w"]),
        ("ww", &["vwv", "vvvv", "wvv", "vvw"]),
        ("rn", &["m_", "r_n", "_m"]),
        ("lo", &["10", "1o", "l0", "l_o"]),
    ];
    for (taken, close) in cases {
        let id = chain.register(accounts % 4, next(), taken);
        assert_eq!(id, accounts);
        accounts += 1;
        let skeleton = names::skeleton(taken);
        assert_eq!(chain.row(&names::key(&skeleton)), owner(taken));
        for name in close {
            assert_eq!(names::skeleton(name), skeleton, "{name}");
            let refusal = chain.refused(accounts % 4, next(), name);
            assert_eq!(refusal, names::too_close(name, taken));
            assert!(refusal.contains(&format!("too close to the existing name {taken}")), "{refusal}");
            // Nothing of the refused name is in the state.
            assert_eq!(chain.row(&name_key(name)), None);
            assert_eq!(chain.row(&names::key(&skeleton)), owner(taken));
        }
    }
    // The same name twice is refused as it always was, before the rule is asked.
    let refusal = chain.refused(0, next(), "alice");
    assert!(refusal.contains("username unavailable"), "{refusal}");
    // Names the rule leaves to a wallet's warning, and names that share
    // letters only: all registered.
    for name in ["alicia", "bob", "binance", "b1nance", "mail", "mall", "paypai", "googie", "barm", "vn", "al", "ice", "nr", "o1"] {
        let id = chain.register(accounts % 4, next(), name);
        assert_eq!(id, accounts, "{name}");
        accounts += 1;
        assert_eq!(chain.row(&names::key(&names::skeleton(name))), owner(name));
    }
    assert_eq!(chain.meta().account_count, accounts);
    assert_eq!(chain.skeleton_rows(), accounts);
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.account_count, accounts);
}

#[test]
fn a_name_without_a_skeleton_is_refused() {
    let mut chain = Chain::funded(distinct());
    for (index, name) in ["__", "___", "_______________"].iter().enumerate() {
        assert_eq!(names::skeleton(name), "");
        let refusal = chain.refused(index as u64, 201 + index as u8, name);
        assert_eq!(refusal, names::EMPTY);
        assert_eq!(chain.row(&name_key(name)), None);
    }
    // No row was written under the bare prefix.
    assert_eq!(chain.row(names::PREFIX), None);
    assert_eq!(chain.skeleton_rows(), GENESIS_ACCOUNTS);
    // One letter or digit is enough.
    chain.register(3, 210, "_a_");
    chain.register(3, 211, "__7");
    chain.engine.audit().unwrap();
}

/// A refused look-alike leaves the state as any refused reveal always has:
/// nothing changes, the paid commitment stays until it expires, and the
/// sponsor's charge is not returned. The same steps are made for a reveal
/// that protocol 4 already refused (the same name twice), side by side.
#[test]
fn a_refusal_leaves_the_state_as_any_refused_reveal_does() {
    let mut chain = Chain::funded(distinct());
    let alice = chain.register(0, 201, "alice");
    // Two accounts that own no validator (their balances change with
    // nothing but their own actions) are given a second each.
    chain.block(SECOND, vec![chain.transfer(0, 5, SECOND), chain.transfer(1, 6, SECOND)]);
    // Each pays for one commitment that lasts two minutes: account 5 for a
    // name that looks like alice, account 6 for alice itself.
    chain.block(SECOND, vec![chain.sponsor(5, 202, "al_ice", 120), chain.sponsor(6, 203, "alice", 120)]);
    for sponsor in [5, 6] {
        assert_eq!(chain.account(sponsor).balance, SECOND - SPONSOR_PAYS);
    }
    // (A block passes: the mempool takes a reveal one block after its commitment's.)
    chain.block(SECOND, vec![]);
    let commits = [chain.row(&commit_key(202)).unwrap(), chain.row(&commit_key(203)).unwrap()];
    // What the registration rules count, apart from the clock they keep.
    let counted = |chain: &Chain| -> registration::State {
        let mut state: registration::State = serde_json::from_slice(&chain.row(registration::STATE_KEY).unwrap()).unwrap();
        (state.last_elapsed_micros, state.last_height) = (0, 0);
        state
    };
    let registration_state = counted(&chain);
    assert_eq!((registration_state.commitments, registration_state.queue_entries), (2, 3));
    let (close, same) = (chain.reveal(202, "al_ice"), chain.reveal(203, "alice"));
    // Refused by a validator, by the reference path and by the mempool; a
    // proposer's block with it is the block without it.
    assert_eq!(chain.refuses(&close), names::too_close("al_ice", "alice"));
    assert!(chain.refuses(&same).contains("username unavailable"));
    // The block a proposer makes of both holds neither.
    let (accounts, next_id) = (chain.meta().account_count, chain.meta().next_account_id);
    assert_eq!(chain.propose(SECOND, vec![close.clone(), same.clone()]), 0);
    assert_eq!((chain.meta().account_count, chain.meta().next_account_id), (accounts, next_id));
    for (index, (seed, name)) in [(202u8, "al_ice"), (203u8, "alice")].into_iter().enumerate() {
        // The commitment is as it was, and nothing was returned to its sponsor.
        assert_eq!(chain.row(&commit_key(seed)).as_ref(), Some(&commits[index]), "{name}");
        assert_eq!(chain.account(5 + index as u64).balance, SECOND - SPONSOR_PAYS);
        // The identity has no account.
        assert_eq!(chain.row(&pubkey_key(&pk(seed)).unwrap()), None);
        // While the commitment lasts, the same identity cannot be paid for again.
        let again = chain.sponsor(5 + index as u64, seed, "albert", 120);
        assert!(chain.refuses(&again).contains("unexpired registration commitment already exists"));
    }
    assert_eq!(counted(&chain), registration_state);
    assert_eq!(chain.row(&name_key("al_ice")), None);
    assert_eq!(chain.row(&name_key("alice")), Some(serde_json::to_vec(&alice.to_string()).unwrap()));
    assert_eq!(chain.row(&names::key("alice")), owner("alice"));
    assert_eq!(chain.skeleton_rows(), accounts);
    chain.engine.audit().unwrap();
    // The commitments run out and are cleaned up, both alike. The reveal of
    // the look-alike is then refused for want of a commitment, before the
    // rule for names is asked.
    for _ in 0..3 {
        chain.block(60 * SECOND, vec![]);
    }
    for seed in [202u8, 203u8] {
        assert_eq!(chain.row(&commit_key(seed)), None);
    }
    assert!(chain.refuses(&close).contains("paid registration commitment missing"));
    assert!(chain.refuses(&same).contains("username unavailable"));
    // Each identity is then paid for again, under a name that is free, and
    // gets its account.
    let albert = chain.register(5, 202, "albert");
    let alma = chain.register(6, 203, "alma");
    assert_eq!((albert, alma), (accounts, accounts + 1));
    for sponsor in [5, 6] {
        assert_eq!(chain.account(sponsor).balance, SECOND - 2 * SPONSOR_PAYS);
    }
    chain.engine.audit().unwrap();
}

#[test]
fn of_two_names_that_look_alike_the_first_in_a_block_or_in_the_mempool_wins() {
    let mut chain = Chain::funded(distinct());
    chain.block(SECOND, vec![chain.sponsor(0, 201, "carol", 3600), chain.sponsor(1, 202, "car0l", 3600), chain.sponsor(2, 203, "dave", 3600)]);
    // (A block passes: the mempool takes a reveal one block after its commitment's.)
    chain.block(SECOND, vec![]);
    let (carol, close, dave) = (chain.reveal(201, "carol"), chain.reveal(202, "car0l"), chain.reveal(203, "dave"));
    let (height, time, signers, hash) = chain.next(SECOND);
    // A block with both is not valid, in either order.
    for order in [[&carol, &close], [&close, &carol]] {
        let refusal = format!("{:#}", chain.engine.prepare(height, time, &order, &signers, hash).err().unwrap());
        assert!(refusal.contains("too close to the existing name"), "{refusal}");
        assert!(chain.engine.prepare_reference(height, time, &order, &signers, hash).is_err());
    }
    // Each alone is.
    chain.engine.prepare(height, time, &[&carol], &signers, hash).unwrap();
    chain.engine.prepare(height, time, &[&close], &signers, hash).unwrap();
    // The mempool judges a reveal with what is already waiting.
    let mut waiting = chain.engine.check_state().unwrap();
    waiting.admit(&close, SigStatus::Unknown).unwrap();
    let refusal = format!("{:#}", waiting.admit(&carol, SigStatus::Unknown).unwrap_err());
    assert_eq!(refusal, names::too_close("carol", "car0l"));
    waiting.admit(&dave, SigStatus::Unknown).unwrap();
    // A proposer keeps the first and what does not look like it.
    assert_eq!(chain.propose(SECOND, vec![close, carol.clone(), dave]), 2);
    assert_eq!(chain.account(GENESIS_ACCOUNTS).name, "car0l");
    assert_eq!(chain.account(GENESIS_ACCOUNTS + 1).name, "dave");
    assert_eq!(chain.row(&names::key("carol")), owner("car0l"));
    assert_eq!(chain.refuses(&carol), names::too_close("carol", "car0l"));
    chain.engine.audit().unwrap();
}

#[test]
fn a_row_is_proven_present_or_absent_like_any_row() {
    let mut chain = Chain::funded(distinct());
    chain.register(0, 201, "alice");
    let version = chain.engine.version().unwrap();
    let (present, absent) = (names::key("alice"), names::key("bob"));
    let bundle = version.proof_bundle(&[present.clone(), absent.clone(), name_key("alice")]).unwrap();
    assert_eq!(bundle.root, chain.root());
    assert_eq!(bundle.entries[0].verify(chain.root(), &present).unwrap(), owner("alice"));
    assert_eq!(bundle.entries[1].verify(chain.root(), &absent).unwrap(), None);
    // A proof is for its key and its root.
    assert!(bundle.entries[0].verify(chain.root(), &absent).is_err());
    assert!(bundle.entries[1].verify(chain.root(), &present).is_err());
    assert!(bundle.entries[0].verify([7; 32], &present).is_err());
    // After bob registers, the absence is no longer provable and the row is.
    chain.register(1, 202, "bob");
    assert!(bundle.entries[1].verify(chain.root(), &absent).is_err());
    let (entry, value) = chain.engine.version().unwrap().proof_with_value(&absent).unwrap();
    assert_eq!(value, owner("bob"));
    assert_eq!(entry.verify(chain.root(), &absent).unwrap(), owner("bob"));
}

/// The state of `genesis` at height 0 with its rows changed, in a store of
/// its own: what the recount says of it.
fn recount(genesis: Genesis, change: impl FnOnce(&mut BTreeMap<Vec<u8>, Vec<u8>>)) -> anyhow::Result<Audit> {
    let chain = Chain::new(genesis);
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
    tree.set_head_metadata(meta, [0; 32]).unwrap();
    store.commit(tree).unwrap();
    Engine::open(store)?.audit()
}

#[test]
fn the_recount_checks_the_rows() {
    let refusal = |genesis: Genesis, change: fn(&mut BTreeMap<Vec<u8>, Vec<u8>>)| format!("{:#}", recount(genesis, change).unwrap_err());
    // A copy of the state as it is passes, with and without the rule.
    let with = recount(distinct(), |_| {}).unwrap();
    let without = recount(genesis_v5(), |_| {}).unwrap();
    assert_eq!(with.authenticated_leaves, without.authenticated_leaves + GENESIS_ACCOUNTS);
    // A row is missing.
    let missing = refusal(distinct(), |rows| {
        rows.remove(&names::key("person2")).unwrap();
    });
    assert!(missing.contains("name skeleton cardinality mismatch"), "{missing}");
    // A row names another account's name.
    let wrong = refusal(distinct(), |rows| {
        rows.insert(names::key("person2"), serde_json::to_vec("person_3").unwrap()).unwrap();
    });
    assert!(wrong.contains("name skeleton key mismatch"), "{wrong}");
    // A row for a name nobody has.
    let stray = refusal(distinct(), |rows| {
        rows.insert(names::key("zed"), serde_json::to_vec("zed").unwrap());
    });
    assert!(stray.contains("name skeleton row of no account"), "{stray}");
    // A row under the bare prefix, for a name of underscores.
    let empty = refusal(distinct(), |rows| {
        rows.insert(names::PREFIX.to_vec(), serde_json::to_vec("__").unwrap());
    });
    assert!(empty.contains("name skeleton key mismatch"), "{empty}");
    // A value that is not the one encoding of a name.
    let spaced = refusal(distinct(), |rows| {
        rows.insert(names::key("person2"), b" \"person_2\"".to_vec()).unwrap();
    });
    assert!(spaced.contains("noncanonical row encoding"), "{spaced}");
    // A row of the rule on a network without it, even a true one.
    let foreign = refusal(genesis_v5(), |rows| {
        rows.insert(names::key("person2"), serde_json::to_vec("person_2").unwrap());
    });
    assert!(foreign.contains("name skeleton row on a network without distinct names"), "{foreign}");
}

/// The genesis ceremony (`tools/genesis-v5.mjs`) computes the skeleton
/// itself, and so does the SDK. A ceremony that computed another one would
/// build a genesis no node starts from, and a wallet that did would call a
/// name free that the chain refuses. Beyond the shared vectors: thousands of
/// names, most of them made of the letters the rule touches, through the
/// engine and through the ceremony tool. `client-v4/name-skeleton.test.mjs`
/// compares the tool with the SDK in the same way. Needs `node` on the path;
/// skipped where there is none.
#[test]
fn the_ceremony_tool_computes_the_skeleton_the_engine_computes() {
    let all = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let touched = b"rnvwm_01lo";
    let mut state = [11u8; 32];
    let mut next = |below: usize| -> usize {
        state = Sha256::digest(state).into();
        u32::from_be_bytes(state[..4].try_into().unwrap()) as usize % below
    };
    let mut list: Vec<String> = Vec::new();
    for _ in 0..6000 {
        let length = 2 + next(14);
        let name: String = (0..length)
            .map(|_| if next(4) == 0 { all[next(all.len())] as char } else { touched[next(touched.len())] as char })
            .collect();
        list.push(name);
    }
    let module = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tools").join("genesis-v5.mjs");
    let script = r#"import {pathToFileURL} from 'node:url';
const tool = await import(pathToFileURL(process.env.GENESIS_MODULE).href);
let input = '';
for await (const chunk of process.stdin) input += chunk;
console.log(JSON.stringify(JSON.parse(input).map((name) => tool.nameSkeleton(name))));
"#;
    let Ok(mut child) = std::process::Command::new("node")
        .args(["--input-type=module", "-e", script])
        .env("GENESIS_MODULE", &module)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    else {
        eprintln!("skipped: node is not on the path");
        return;
    };
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&list).unwrap()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let answers: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(answers.len(), list.len());
    let (mut contracted, mut empty) = (0, 0);
    for (name, tool) in list.iter().zip(&answers) {
        let engine = names::skeleton(name);
        assert_eq!(*tool, engine, "the ceremony tool and the engine disagree on {name}");
        contracted += usize::from(engine.contains('m') || engine.contains('w'));
        empty += usize::from(engine.is_empty());
    }
    // The comparison is not vacuous: most names are changed by the last step,
    // and some have no skeleton at all.
    assert!(contracted > 3000 && empty > 0, "{contracted} contracted, {empty} empty");
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
/// The rows under `keys` as a node proves them (`/compact-proof`), each
/// proof checked against the application hash the node reports.
fn proven(app: &App, keys: &[Vec<u8>]) -> Vec<Option<Vec<u8>>> {
    let info = app.info(RequestInfo::default());
    let root: [u8; 32] = info.last_block_app_hash.to_vec().try_into().unwrap();
    let answer = query(app, "/compact-proof", &json!(keys.iter().map(hex::encode).collect::<Vec<_>>()));
    assert_eq!(answer["root"], hex::encode(root));
    let entries: Vec<ProofEntry> = serde_json::from_value(answer["entries"].clone()).unwrap();
    assert_eq!(entries.len(), keys.len());
    entries.iter().zip(keys).map(|(entry, key)| entry.verify(root, key).unwrap()).collect()
}
fn account_of(app: &App, id: u64) -> Account {
    let view = query(app, "/v4/state", &json!({ "ids": [id.to_string()] }));
    let key = hex::encode(account_key(id));
    let entry = view["entries"].as_array().unwrap().iter().find(|entry| entry["key_hex"] == key.as_str()).unwrap();
    serde_json::from_slice(&STANDARD.decode(entry["value_b64"].as_str().expect("account exists")).unwrap()).unwrap()
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
        account_of(&self.app, id)
    }
    fn sponsor(&self, sponsor: u64, seed: u8, name: &str) -> Vec<u8> {
        sponsor_tx(&self.network, &self.account(sponsor), seed, name, self.elapsed, 3600)
    }
    fn reveal(&self, seed: u8, name: &str) -> Vec<u8> {
        reveal_tx(&self.network, seed, name)
    }
    /// Blocks until the validators' owners (accounts 0 to 3) hold five
    /// seconds each.
    fn fund(&mut self) {
        self.block(SECOND, vec![]);
        while !(0..4).all(|id| self.account(id).balance >= 5 * SECOND) {
            assert!(self.height < 40, "validator owners were not funded");
            self.block(60 * SECOND, vec![]);
        }
    }
    fn register(&mut self, sponsor: u64, seed: u8, name: &str) {
        let action = self.sponsor(sponsor, seed, name);
        self.block(SECOND, vec![action]);
        self.block(SECOND, vec![self.reveal(seed, name)]);
    }
    /// A paid commitment of the identity `seed` for `name`, and one block
    /// more: the mempool judges on the last block and takes a reveal one
    /// block after its commitment's.
    fn commit(&mut self, sponsor: u64, seed: u8, name: &str) {
        let action = self.sponsor(sponsor, seed, name);
        self.block(SECOND, vec![action]);
        self.block(SECOND, vec![]);
    }
    /// The answers of this node to everything a look-alike of alice asks of
    /// it: `seed` holds a paid commitment for `name`.
    fn refuses_the_look_alike(&self, seed: u8, name: &str) {
        let reveal = self.reveal(seed, name);
        let answer = self.check(&reveal);
        assert_ne!(answer.code, 0, "the mempool admitted {name}");
        assert!(answer.log.contains(&names::too_close(name, "alice")), "{}", answer.log);
        assert!(self.prepare(SECOND, std::slice::from_ref(&reveal)).is_empty(), "a proposer kept {name}");
        assert!(!self.accepts(SECOND, vec![reveal]), "a validator accepted a block with {name}");
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

/// The report of the recount of a network without the rule has the fields it
/// always had: nothing about names.
#[test]
fn the_recount_report_of_a_network_without_the_setting_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let mut node = Node::start(&path, NodeOptions::default(), &genesis_v5());
    node.fund();
    node.register(0, 201, "alice");
    node.register(1, 202, "al_ice");
    node.app.snapshot().unwrap();
    drop(node);
    let report = recount_report(&path);
    assert_eq!(report["accounts"], (GENESIS_ACCOUNTS + 2).to_string());
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

#[test]
fn a_node_refuses_a_look_alike_in_its_mempool_and_in_a_proposal_and_proves_the_rows() {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::start(&dir.path().join("node.db"), NodeOptions::default(), &distinct());
    node.fund();
    node.register(0, 201, "alice");
    assert_eq!(node.account(GENESIS_ACCOUNTS).name, "alice");
    node.commit(1, 202, "al_ice");
    node.refuses_the_look_alike(202, "al_ice");
    // The row of alice, and that no name with the skeleton of bob exists:
    // proven against the application hash, like any row a client asks for.
    assert_eq!(
        proven(&node.app, &[names::key("alice"), names::key("bob"), names::key(&names::skeleton("person_11"))]),
        [owner("alice"), None, owner("person_11")]
    );
    // What a wallet reads of a name is what it always read.
    let view = query(&node.app, "/v4/state", &json!({ "names": ["alice", "al_ice"] }));
    let keys: Vec<&str> = view["entries"].as_array().unwrap().iter().map(|entry| entry["key_hex"].as_str().unwrap()).collect();
    assert!(keys.contains(&hex::encode(name_key("alice")).as_str()) && keys.contains(&hex::encode(name_key("al_ice")).as_str()));
    assert!(!keys.iter().any(|key| key.starts_with(&hex::encode(names::PREFIX))));
    // A distinct name goes through the same calls.
    node.commit(2, 203, "bob");
    let reveal = node.reveal(203, "bob");
    assert_eq!(node.check(&reveal).code, 0);
    assert_eq!(node.prepare(SECOND, std::slice::from_ref(&reveal)), std::slice::from_ref(&reveal));
    node.block(SECOND, vec![reveal]);
    assert_eq!(proven(&node.app, &[names::key("bob")]), [owner("bob")]);
}

#[test]
fn the_rows_survive_a_restart_and_reach_a_node_that_joins_from_a_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = distinct();
    // Snapshots for peers every ten blocks, in chunks of 1 KiB.
    let serving = NodeOptions { sync_snapshot_blocks: 10, sync_chunk_bytes: 1024, ..NodeOptions::default() };
    let path = dir.path().join("source.db");
    let mut source = Node::start(&path, serving, &genesis);
    source.fund();
    source.register(0, 201, "alice");
    assert!(source.height < 20, "the registration came after the snapshot");
    while source.height < 22 {
        source.block(SECOND, vec![]);
    }
    source.commit(1, 202, "al_ice");
    let keys = [names::key("alice"), names::key("bob"), names::key("persono")];
    let rows = [owner("alice"), None, owner("person_0")];
    assert_eq!(proven(&source.app, &keys), rows);

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
    assert_eq!(proven(&joiner, &keys), rows);
    let joined = Node { app: joiner, genesis: genesis.clone(), network: source.network.clone(), height: source.height, elapsed: source.elapsed, log: Vec::new() };
    joined.refuses_the_look_alike(202, "al_ice");

    // The first node stops and starts again from its restart snapshot.
    let (height, root) = source.app.head().unwrap().unwrap();
    source.app.snapshot().unwrap().expect("a restart snapshot");
    let (network, elapsed) = (source.network.clone(), source.elapsed);
    drop(source);
    let app = App::open_with_options(&path, serving).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), (height, root));
    let mut restarted = Node { app, genesis: genesis.clone(), network, height: height as i64, elapsed, log: Vec::new() };
    assert_eq!(proven(&restarted.app, &keys), rows);
    restarted.refuses_the_look_alike(202, "al_ice");
    // Both go on to the same state, and a distinct name is registered on both.
    let mut joined = joined;
    for node in [&mut restarted, &mut joined] {
        node.register(2, 203, "bob");
        assert_eq!(proven(&node.app, &keys), [owner("alice"), owner("bob"), owner("person_0")]);
    }
    assert_eq!(restarted.app.head().unwrap(), joined.app.head().unwrap());

    // The recount of both, offline: one row of the rule for every account,
    // and the report of the command an operator runs says that the network
    // has the rule.
    for (node, node_path) in [(restarted, path), (joined, joined_path)] {
        node.app.snapshot().unwrap();
        drop(node);
        let report = recount_report(&node_path);
        assert_eq!(report["distinct_names"], true, "{report}");
        assert_eq!(report["accounts"], (GENESIS_ACCOUNTS + 2).to_string());
        let engine = Engine::open_with_history(Store::open(node_path.with_extension("v5state")).unwrap(), node_path.with_extension("history")).unwrap();
        let audit = engine.audit().unwrap();
        assert_eq!(audit.account_count, GENESIS_ACCOUNTS + 2);
        let mut rows = 0;
        engine
            .version()
            .unwrap()
            .audit_verified(|_| {})
            .unwrap()
            .for_each_prefix(names::PREFIX, |_, _| {
                rows += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(rows, GENESIS_ACCOUNTS + 2);
    }
}
