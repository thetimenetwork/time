//! Fees paid on to validators (`fees_to_validators_ppm` in the genesis).
//!
//! Without the setting a network keeps the protocol-4 rule: every fee stays
//! in the bank (the differential tests compare that case with the protocol-4
//! engine block by block). With it, the validators' part of the fees of a
//! block joins the new time shared by the validators who signed that block
//! and is paid by the same rule, at the start of the next block.
//!
//! Every block here is also executed with the engine's fast paths off, and
//! the two results must have the same root. `fees_model.rs` checks the same
//! rule against an independent recomputation on random blocks.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, Meta, account_key};
use timecurrency_v5::pos_adapter::FEE_POOL_KEY;
use timecurrency_v5::security::{self, Role};
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;
const ALL: u64 = 1_000_000;
/// New time each of the four validators earns in a ten-second block: a fifth
/// of the block's time, shared by four equal voting powers.
const TIME_REWARD: u64 = 10 * SECOND / 5 / 4;

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    /// A chain whose four validator owners (accounts 0 to 3) have earned new
    /// time for a while. `ppm` is the validators' part of the fees.
    fn new(ppm: u64) -> Self {
        let mut genesis = genesis_v5();
        genesis.fees_to_validators_ppm = ppm;
        let network = genesis.network_id().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        let mut chain = Self {
            _dir: dir,
            engine,
            network,
        };
        for _ in 0..20 {
            chain.block(60 * SECOND, vec![]);
        }
        chain
    }
    fn meta(&self) -> &Meta {
        self.engine.meta().unwrap()
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.engine.version().unwrap().get(key).map(|row| row.to_vec())
    }
    fn account(&self, id: u64) -> Account {
        serde_json::from_slice(&self.row(&account_key(id)).unwrap()).unwrap()
    }
    fn balances(&self) -> Vec<u64> {
        (0..GENESIS_ACCOUNTS).map(|id| self.account(id).balance).collect()
    }
    /// Fees owed to the validators who signed the last block.
    fn pool(&self) -> u64 {
        self.row(FEE_POOL_KEY).map_or(0, |raw| {
            let text: String = serde_json::from_slice(&raw).unwrap();
            let value: u64 = text.parse().unwrap();
            assert!(value > 0, "an empty pool has no row");
            value
        })
    }
    fn validators(&self) -> Vec<String> {
        self.engine
            .active_roster_at(self.meta().height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect()
    }
    /// Everyone but the validator of account `owner`.
    fn validators_without(&self, owner: u64) -> Vec<String> {
        self.engine
            .active_roster_at(self.meta().height as u64)
            .unwrap()
            .into_iter()
            .filter(|validator| validator.owner != owner)
            .map(|validator| validator.consensus_key)
            .collect()
    }
    /// Commits a block of exactly `txs`. All validators signed the block
    /// before it.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let signers = self.validators();
        self.block_signed_by(delta, txs, &signers);
    }
    /// Commits a block of exactly `txs` that carries the signatures of
    /// `signers` only on the block before it.
    fn block_signed_by(&mut self, delta: u64, txs: Vec<Vec<u8>>, signers: &[String]) {
        let meta = self.meta();
        let (height, time) = (meta.height + 1, meta.time_micros + delta as i64);
        let hash = sha(height as u64);
        let strict = self
            .engine
            .prepare(height, time, &txs, signers, hash)
            .unwrap_or_else(|error| panic!("block refused: {error:#}"));
        let reference = self
            .engine
            .prepare_reference(height, time, &txs, signers, hash)
            .unwrap();
        assert_eq!(strict.root, reference.root, "fast path and reference disagree");
        let (proposed, kept) = self
            .engine
            .prepare_filtered(height, time, &txs, signers, 1 << 20, hash)
            .unwrap();
        assert_eq!(kept, txs, "the proposer dropped a transaction");
        assert_eq!(proposed.root, strict.root, "proposer and validator disagree");
        self.engine.commit(strict, hash).unwrap();
        assert!(self.pool() <= self.meta().bank, "more owed than the bank holds");
        assert_eq!(self.supply(), self.meta().elapsed_micros().unwrap());
    }
    fn legacy(&self, from: u64, payload: ActionPayload) -> Vec<u8> {
        self.legacy_at(from, 1, payload)
    }
    /// An action of `from` signed by its genesis key, `ahead` nonces on.
    fn legacy_at(&self, from: u64, ahead: u64, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        let seed = from as u8 + 1;
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + ahead,
                auth_epoch: row.auth_epoch,
                public_key: pk(seed),
                payload,
                signature: vec![],
            },
            &key(seed),
        )
        .unwrap()
    }
    fn transfer(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn extension(&self, from: u64, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(
            &self.network,
            from,
            row.nonce + 1,
            row.auth_epoch,
            kind,
            &payload,
            &key(from as u8 + 1),
        )
        .unwrap()
    }
    /// One payment of a second from each validator owner to account 5.
    fn four_payments(&self) -> Vec<Vec<u8>> {
        (0..4).map(|from| self.transfer(from, 5, SECOND)).collect()
    }
    /// Bank, balances, stake and auction reserve.
    fn supply(&self) -> u64 {
        let meta = self.meta();
        meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total
    }
}

#[test]
fn a_network_without_the_setting_keeps_every_fee_in_the_bank() {
    let genesis = genesis_v5();
    assert_eq!(genesis.fees_to_validators_ppm, 0);
    let text = serde_json::to_string(&genesis).unwrap();
    assert!(!text.contains("fees_to_validators"), "{text}");
    assert_eq!(genesis.network_id().unwrap(), network_id(), "protocol-4 network id");

    let mut chain = Chain::new(0);
    let bank = chain.meta().bank;
    let before = chain.balances();
    chain.block(10 * SECOND, chain.four_payments());
    assert!(chain.row(FEE_POOL_KEY).is_none());
    chain.block(10 * SECOND, vec![]);
    assert!(chain.row(FEE_POOL_KEY).is_none());
    // Two blocks of new time, less the validators' fifth, plus the four fees.
    assert_eq!(chain.meta().bank, bank + 16 * SECOND + 4 * FEE);
    for id in 0..4usize {
        assert_eq!(
            chain.account(id as u64).balance,
            before[id] + 2 * TIME_REWARD - SECOND - FEE
        );
    }
    chain.engine.audit().unwrap();
}

#[test]
fn fees_are_paid_to_the_validators_who_signed_the_block() {
    let mut chain = Chain::new(ALL);
    assert_ne!(chain.network, network_id(), "the setting is part of the network id");
    let bank = chain.meta().bank;
    let before = chain.balances();

    chain.block(10 * SECOND, chain.four_payments());
    // The fees are in the bank, recorded as owed.
    assert_eq!(chain.pool(), 4 * FEE);
    assert_eq!(chain.meta().bank, bank + 8 * SECOND + 4 * FEE);
    for id in 0..4usize {
        assert_eq!(
            chain.account(id as u64).balance,
            before[id] + TIME_REWARD - SECOND - FEE
        );
    }
    assert_eq!(chain.account(5).balance, before[5] + 4 * SECOND);
    chain.engine.audit().unwrap();

    // The next block carries the four signatures of that block.
    chain.block(10 * SECOND, vec![]);
    assert!(chain.row(FEE_POOL_KEY).is_none());
    assert_eq!(chain.meta().bank, bank + 16 * SECOND);
    for id in 0..4usize {
        assert_eq!(
            chain.account(id as u64).balance,
            before[id] + 2 * TIME_REWARD - SECOND
        );
    }
    chain.engine.audit().unwrap();
}

#[test]
fn the_share_of_a_validator_that_did_not_sign_stays_in_the_bank() {
    let mut chain = Chain::new(ALL);
    chain.block(10 * SECOND, chain.four_payments());
    assert_eq!(chain.pool(), 4 * FEE);
    let before = chain.balances();
    let bank = chain.meta().bank;

    // Validator 3's signature on that block is missing from the next one.
    let present = chain.validators_without(3);
    chain.block_signed_by(10 * SECOND, vec![], &present);
    for id in 0..3usize {
        assert_eq!(chain.account(id as u64).balance, before[id] + TIME_REWARD + FEE);
    }
    assert_eq!(chain.account(3).balance, before[3], "no new time and no fee");
    // Its quarter of both stays in the bank, as its new time always did.
    assert_eq!(chain.pool(), 0);
    assert_eq!(chain.meta().bank, bank + 10 * SECOND - 3 * (TIME_REWARD + FEE));
    chain.engine.audit().unwrap();

    // Nothing of it is paid later, to anyone.
    chain.block(10 * SECOND, vec![]);
    for id in 0..4usize {
        let earlier = if id < 3 { TIME_REWARD + FEE } else { 0 };
        assert_eq!(
            chain.account(id as u64).balance,
            before[id] + earlier + TIME_REWARD
        );
    }
}

#[test]
fn leaving_a_signature_out_gains_the_others_nothing() {
    // The same fees, once with every signature and once with validator 3's
    // left out. Validators 0 to 2 receive the same either way.
    let run = |omit: bool| -> Vec<u64> {
        let mut chain = Chain::new(ALL);
        chain.block(10 * SECOND, chain.four_payments());
        let before = chain.balances();
        for _ in 0..5 {
            let signers = if omit {
                chain.validators_without(3)
            } else {
                chain.validators()
            };
            let txs = chain.four_payments();
            chain.block_signed_by(10 * SECOND, txs, &signers);
        }
        let after = chain.balances();
        (0..4).map(|id| after[id] + 5 * (SECOND + FEE) - before[id]).collect()
    };
    let (honest, omitted) = (run(false), run(true));
    assert_eq!(honest, vec![5 * (TIME_REWARD + FEE); 4]);
    assert_eq!(omitted[..3], honest[..3]);
    assert_eq!(omitted[3], 0);
}

#[test]
fn what_does_not_divide_stays_in_the_bank() {
    // A third of a fee, 333 microseconds, among four validators: the new
    // time and the fees are split as one sum, and one microsecond is left.
    let mut chain = Chain::new(ALL / 3);
    chain.block(10 * SECOND, vec![chain.transfer(0, 5, SECOND)]);
    assert_eq!(chain.pool(), 333);
    let before = chain.balances();
    let bank = chain.meta().bank;
    chain.block(10 * SECOND, vec![]);
    for id in 0..4usize {
        assert_eq!(chain.account(id as u64).balance, before[id] + TIME_REWARD + 83);
    }
    assert_eq!(chain.pool(), 0);
    assert_eq!(chain.meta().bank, bank + 10 * SECOND - 4 * (TIME_REWARD + 83));
    chain.engine.audit().unwrap();
}

#[test]
fn the_share_is_taken_from_the_fees_of_the_whole_block() {
    // A twentieth of a percent of one fee is half a microsecond. One fee
    // alone pays nothing on; two in one block pay one microsecond.
    let mut chain = Chain::new(500);
    chain.block(10 * SECOND, vec![chain.transfer(0, 5, SECOND)]);
    assert_eq!(chain.pool(), 0);
    chain.block(
        10 * SECOND,
        vec![chain.transfer(0, 5, SECOND), chain.transfer(1, 5, SECOND)],
    );
    assert_eq!(chain.pool(), 1);
    chain.engine.audit().unwrap();
}

#[test]
fn a_part_of_the_fees_can_stay_in_the_bank() {
    let mut chain = Chain::new(ALL / 2);
    let bank = chain.meta().bank;
    let before = chain.balances();
    chain.block(10 * SECOND, chain.four_payments());
    assert_eq!(chain.pool(), 2 * FEE);
    chain.block(10 * SECOND, vec![]);
    assert_eq!(chain.pool(), 0);
    // Half of the four fees stayed.
    assert_eq!(chain.meta().bank, bank + 16 * SECOND + 2 * FEE);
    for id in 0..4usize {
        assert_eq!(
            chain.account(id as u64).balance,
            before[id] + 2 * TIME_REWARD - SECOND - FEE + FEE / 2
        );
    }
}

fn accepts(network: &str, seed: u8, account: u64, role: Role) -> Value {
    let name = match role {
        Role::Signin => "signin",
        Role::Spend => "spend",
        Role::Recover => "recover",
    };
    let proof = key(seed)
        .sign(&security::key_message(network, account, role, &pk(seed)).unwrap())
        .to_bytes();
    json!({"public_key": pk(seed), "role": name, "proof": hex::encode(proof)})
}

#[test]
fn every_kind_of_action_pays_its_fee_on() {
    let mut chain = Chain::new(ALL);
    // Account 5 needs a balance for its own action.
    chain.block(10 * SECOND, vec![chain.transfer(0, 5, 5 * SECOND)]);
    chain.block(10 * SECOND, vec![]);
    assert_eq!(chain.pool(), 0);

    let now = chain.meta().elapsed_micros().unwrap();
    let merchant = chain.account(1);
    let mut reference = [7u8; 32];
    reference[..8].copy_from_slice(&(merchant.nonce + 1).to_be_bytes());
    reference[8..16].copy_from_slice(&(now + 3600 * SECOND).to_be_bytes());
    let mut keys = vec![
        accepts(&chain.network, 60, 5, Role::Signin),
        accepts(&chain.network, 61, 5, Role::Spend),
        accepts(&chain.network, 62, 5, Role::Recover),
        accepts(&chain.network, 63, 5, Role::Recover),
    ];
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    let policy = json!({"threshold": "2", "daily_limit_micros": "500000", "delay_seconds": "60", "freeze_seconds": "120"});
    let txs = vec![
        // The transfer fast path.
        chain.transfer(0, 6, SECOND),
        // The protocol-4 rule adapter.
        chain.legacy(
            1,
            ActionPayload::MerchantPayment(ledger::MerchantPayment {
                to: 6,
                amount: SECOND,
                reference: hex::encode(reference),
            }),
        ),
        // A staking action: the validator owner adds to its own stake.
        chain.extension(2, 18, json!({"amount": "10000"})),
        // The account security rules.
        chain.extension(5, security::SECURE, json!({"keys": keys, "policy": policy})),
    ];
    chain.block(10 * SECOND, txs);
    assert_eq!(chain.pool(), 4 * FEE);
    chain.engine.audit().unwrap();
    chain.block(10 * SECOND, vec![]);
    assert_eq!(chain.pool(), 0);
    chain.engine.audit().unwrap();
}

#[test]
fn cancelling_what_is_waiting_pays_its_fee_on_too() {
    // The fee `CancelPending` pays is charged by this engine, not by the
    // protocol-4 rule adapter.
    let mut chain = Chain::new(ALL);
    chain.block(
        10 * SECOND,
        vec![chain.legacy(0, ActionPayload::CancelPending(ledger::CancelPending {}))],
    );
    assert_eq!(chain.pool(), FEE);
}

#[test]
fn the_setting_is_a_share_of_the_fees_written_one_way() {
    let mut genesis = genesis_v5();
    genesis.fees_to_validators_ppm = ALL + 1;
    assert!(genesis.validate().is_err());
    let dir = tempfile::tempdir().unwrap();
    let mut engine = Engine::open_with_history(
        Store::open(dir.path().join("state.v5state")).unwrap(),
        dir.path().join("history"),
    )
    .unwrap();
    assert!(engine.initialize(genesis).is_err());

    let parse = |value: Value| {
        let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
        genesis["fees_to_validators_ppm"] = value;
        serde_json::from_value::<timecurrency_v5::genesis::Genesis>(genesis)
    };
    // A decimal string like every other amount.
    assert!(parse(json!(1_000_000)).is_err());
    assert!(parse(json!("01000")).is_err());
    // Zero is written by leaving the field out: a network that keeps fees in
    // the bank has one genesis, the protocol-4 one.
    assert!(parse(json!("0")).is_err());
    let parsed = parse(json!("1000000")).unwrap();
    assert_eq!(parsed.fees_to_validators_ppm, ALL);
    parsed.validate().unwrap();
}

#[test]
fn the_setting_is_the_last_field_of_the_genesis() {
    // Tools that build a genesis compute the network id from their own
    // encoding (`campaign/lib/genesis.mjs` appends the field last), so the
    // position and form of the field are part of the format.
    let mut genesis = genesis_v5();
    let without = serde_json::to_string(&genesis).unwrap();
    genesis.fees_to_validators_ppm = ALL;
    let with = serde_json::to_string(&genesis).unwrap();
    assert_eq!(
        with,
        format!(
            "{},\"fees_to_validators_ppm\":\"1000000\"}}",
            without.strip_suffix('}').unwrap()
        )
    );
    let parsed: timecurrency_v5::genesis::Genesis = serde_json::from_str(&with).unwrap();
    assert_eq!(parsed.network_id().unwrap(), genesis.network_id().unwrap());
}

#[test]
fn under_load_the_fees_of_every_block_reach_its_signers() {
    // The same payments on a network that keeps fees in the bank and on one
    // that pays them on. Everything but who holds the fees must be equal.
    let mut kept = Chain::new(0);
    let mut paid = Chain::new(ALL);
    assert_eq!(kept.balances(), paid.balances());
    // Fees of the block before, and what the signers of it are due.
    let mut owed = 0u64;
    let mut paid_on = 0u64;
    let mut charged = 0u64;
    for round in 0..40u64 {
        let build = |chain: &Chain| -> Vec<Vec<u8>> {
            let mut txs = Vec::new();
            for from in 0..4u64 {
                // Several payments of one account in one block.
                for ahead in 1..=(1 + (round + from) % 3) {
                    txs.push(chain.legacy_at(
                        from,
                        ahead,
                        ActionPayload::Transfer(ledger::Transfer {
                            to: 4 + (round + from + ahead) % 8,
                            amount: 1000 + round * 7 + ahead,
                        }),
                    ));
                }
            }
            txs
        };
        let a = build(&kept);
        let b = build(&paid);
        assert_eq!(a.len(), b.len());
        // In one round of four, one validator's signature is missing.
        let missing = (round % 4 == 1).then_some(round % 3);
        let signers = |chain: &Chain| match missing {
            Some(owner) => chain.validators_without(owner),
            None => chain.validators(),
        };
        let (sa, sb) = (signers(&kept), signers(&paid));
        // Four equal validators: each signer is due a quarter.
        paid_on += owed / 4 * sb.len() as u64;
        assert_eq!(paid.pool(), owed);
        owed = a.len() as u64 * FEE;
        charged += owed;
        kept.block_signed_by(3 * SECOND, a, &sa);
        paid.block_signed_by(3 * SECOND, b, &sb);
    }
    // A quiet block signed by everyone pays the fees of the last one.
    kept.block(3 * SECOND, vec![]);
    paid.block(3 * SECOND, vec![]);
    paid_on += owed;
    assert_eq!(paid.pool(), 0);
    assert!(paid_on < charged && paid_on > charged * 9 / 10);
    // The bank of the paying network holds only the shares of the missing
    // signers. The validators hold the rest.
    assert_eq!(kept.meta().bank - paid.meta().bank, paid_on);
    let (kept_balances, paid_balances) = (kept.balances(), paid.balances());
    let gained: u64 = (0..4).map(|id| paid_balances[id] - kept_balances[id]).sum();
    assert_eq!(gained, paid_on);
    assert_eq!(kept_balances[4..], paid_balances[4..], "nobody else is affected");
    assert_eq!(kept.supply(), paid.supply());
    kept.engine.audit().unwrap();
    paid.engine.audit().unwrap();
}
