//! All new time to validators (`all_new_time_to_validators` in the genesis).
//!
//! Without the setting a network keeps the protocol-4 rule: a fifth of each
//! block's new time goes to the validators who signed the block before, the
//! rest to the bitcoin auction or the bank (the differential tests compare
//! that case with the protocol-4 engine block by block). With it, all of the
//! new time goes to those validators, the bitcoin actions are refused, and a
//! starting validator's own reward is staked for it while its voting power
//! is lent to it by the bootstrap rule.
//!
//! Every block here is also executed by the reference path and by a
//! proposer, and the three must agree; the supply rule is checked after each.
mod common;
use common::*;
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, Meta, account_key};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::pos_adapter::{SUMMARY_KEY, candidate_key};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;
const STARTING: u64 = 7;

/// The test genesis with seven starting validators (owners 0 to 6), the
/// fewest a network with the setting may have.
fn genesis(all: bool) -> Genesis {
    let mut genesis = genesis_v5();
    genesis.validators = (0..STARTING)
        .map(|owner| BootstrapValidator {
            owner,
            consensus_key: pk(owner as u8 + 101),
            commission_bps: 1000,
        })
        .collect();
    genesis.all_new_time_to_validators = all;
    genesis
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        let network = genesis.network_id().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        Self {
            _dir: dir,
            engine,
            network,
        }
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
    fn candidate(&self, owner: u64) -> pos::Candidate {
        serde_json::from_slice(&self.row(&candidate_key(owner)).unwrap()).unwrap()
    }
    fn summary(&self) -> pos::Summary {
        serde_json::from_slice(&self.row(SUMMARY_KEY).unwrap()).unwrap()
    }
    fn signers(&self) -> Vec<String> {
        self.engine
            .active_roster_at(self.meta().height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect()
    }
    /// Bank, balances, stake and auction reserve.
    fn supply(&self) -> u64 {
        let meta = self.meta();
        meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total
    }
    /// Commits a block of exactly `txs`, `delta` after the last one; every
    /// validator signed the block before it.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let signers = self.signers();
        self.block_signed_by(delta, txs, &signers);
    }
    /// The same, with the signatures of `signers` only on the block before it.
    fn block_signed_by(&mut self, delta: u64, txs: Vec<Vec<u8>>, signers: &[String]) {
        let signers = signers.to_vec();
        let meta = self.meta();
        let (height, time) = (meta.height + 1, meta.time_micros + delta as i64);
        let hash = sha(height as u64);
        let strict = self
            .engine
            .prepare(height, time, &txs, &signers, hash)
            .unwrap_or_else(|error| panic!("block refused: {error:#}"));
        let reference = self
            .engine
            .prepare_reference(height, time, &txs, &signers, hash)
            .unwrap();
        assert_eq!(strict.root, reference.root, "fast path and reference disagree");
        let (proposed, kept) = self
            .engine
            .prepare_filtered(height, time, &txs, &signers, 1 << 20, hash)
            .unwrap();
        assert_eq!(kept, txs, "the proposer dropped a transaction");
        assert_eq!(proposed.root, strict.root, "proposer and validator disagree");
        self.engine.commit(strict, hash).unwrap();
        assert_eq!(self.supply(), self.meta().elapsed_micros().unwrap(), "supply rule");
    }
    /// The block is refused by a validator, by the reference path, by a
    /// proposer (which drops the transaction) and by mempool admission, each
    /// for a reason that names `why`.
    fn refuse(&mut self, tx: Vec<u8>, why: &str) {
        let signers = self.signers();
        let meta = self.meta();
        let (height, time) = (meta.height + 1, meta.time_micros + SECOND as i64);
        let hash = sha(height as u64);
        let txs = vec![tx.clone()];
        let error = format!("{:#}", self.engine.prepare(height, time, &txs, &signers, hash).err().expect("accepted"));
        assert!(error.contains(why), "refused for another reason: {error}");
        assert!(self.engine.prepare_reference(height, time, &txs, &signers, hash).is_err());
        let (_, kept) = self
            .engine
            .prepare_filtered(height, time, &txs, &signers, 1 << 20, hash)
            .unwrap();
        assert!(kept.is_empty(), "a proposer kept it");
        let mut pending = self.engine.check_state().unwrap();
        let admission = format!("{:#}", pending.admit(&tx, SigStatus::Unknown).expect_err("admitted"));
        assert!(admission.contains(why), "admission refused for another reason: {admission}");
    }
    fn transfer(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        let seed = from as u8 + 1;
        ledger::sign_action(
            &Action {
                network_id: self.network.clone(),
                from,
                nonce: row.nonce + 1,
                auth_epoch: row.auth_epoch,
                public_key: pk(seed),
                payload: ActionPayload::Transfer(ledger::Transfer { to, amount }),
                signature: vec![],
            },
            &key(seed),
        )
        .unwrap()
    }
    /// An extension action of `from`, signed by its genesis key.
    fn extension(&self, from: u64, kind: u8, payload: serde_json::Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + 1, row.auth_epoch, kind, &payload, &key(from as u8 + 1)).unwrap()
    }
    fn self_bonds(&self) -> u64 {
        (0..STARTING).map(|owner| self.candidate(owner).self_bond).sum()
    }
}

#[test]
fn the_setting_is_written_only_when_set() {
    // Absent: the protocol-4 encoding and network id.
    let plain = genesis_v5();
    assert!(!plain.all_new_time_to_validators);
    let text = serde_json::to_string(&plain).unwrap();
    assert!(!text.contains("all_new_time"), "{text}");
    assert_eq!(plain.network_id().unwrap(), network_id(), "protocol-4 network id");
    // Set: written as true, last, and part of the network id.
    let set = genesis(true);
    let text = serde_json::to_string(&set).unwrap();
    assert!(text.ends_with(",\"all_new_time_to_validators\":true}"), "{text}");
    assert_ne!(set.network_id().unwrap(), genesis(false).network_id().unwrap());
    let back: Genesis = serde_json::from_str(&text).unwrap();
    assert!(back.all_new_time_to_validators);
    // False is written by leaving the field out; anything else is refused.
    for bad in ["false", "\"true\"", "1", "null"] {
        let other = text.replace(":true}", &format!(":{bad}}}"));
        assert!(serde_json::from_str::<Genesis>(&other).is_err(), "{bad} was accepted");
    }
    // At least five starting validators. With fewer than seven their lent
    // power never ends, and they go on being paid a twentieth.
    let mut four = genesis_v5();
    four.all_new_time_to_validators = true;
    let error = format!("{:#}", four.validate().unwrap_err());
    assert!(error.contains("at least five starting validators"), "{error}");
    let mut five = genesis(true);
    five.validators.truncate(5);
    assert!(five.validate().is_ok());
    assert!(genesis(true).validate().is_ok());
}

#[test]
fn without_the_setting_validators_are_paid_a_fifth_of_the_new_time() {
    let mut chain = Chain::new(genesis(false));
    chain.block(10 * SECOND, vec![]);
    let (bank, liquid) = (chain.meta().bank, chain.meta().liquid_total);
    chain.block(10 * SECOND, vec![]);
    // Seven equal powers share two seconds; the rest of the ten stays in the bank.
    let paid = chain.meta().liquid_total - liquid;
    assert!((2 * SECOND - STARTING..=2 * SECOND).contains(&paid), "paid {paid}");
    assert_eq!(chain.meta().bank, bank + 10 * SECOND - paid);
    assert_eq!(chain.self_bonds(), 0, "nothing is staked for them");
    chain.engine.audit().unwrap();
}

#[test]
fn all_new_time_goes_to_validators_and_most_of_it_is_staked_while_their_power_is_lent() {
    let mut chain = Chain::new(genesis(true));
    assert!(!chain.summary().bootstrap_ended);
    let mut blocks = 0u64;
    // While their power is lent, a twentieth of what the starting validators
    // earn is paid out and the rest is staked for them; the bank keeps only
    // what does not divide evenly.
    while !chain.summary().bootstrap_ended {
        chain.block(10 * SECOND, vec![]);
        blocks += 1;
        assert!(blocks < 60, "the lent power did not end");
        let meta = chain.meta();
        assert!(meta.bank <= blocks * STARTING, "bank {} after {blocks} blocks", meta.bank);
        assert_eq!(chain.self_bonds(), meta.pos_assets_total);
        if !chain.summary().bootstrap_ended {
            let earned = meta.liquid_total + meta.pos_assets_total;
            assert!(meta.liquid_total.abs_diff(earned / 20) <= blocks * STARTING, "paid {} of {earned}", meta.liquid_total);
        }
    }
    // All seven stand on their own stake now. Voting power counts whole
    // seconds of stake, so early on some held a second more power than others
    // for a block or two and earned more: the parts are close, not equal.
    let summary = chain.summary();
    assert_eq!(summary.active.len() as u64, STARTING);
    let bonds: Vec<u64> = (0..STARTING).map(|owner| chain.candidate(owner).self_bond).collect();
    let (low, high) = (*bonds.iter().min().unwrap(), *bonds.iter().max().unwrap());
    assert!(low >= SECOND && high - low <= 3 * SECOND, "{bonds:?} after {blocks} blocks");
    eprintln!("lent power ended after {blocks} blocks of 10 s; stakes {bonds:?}");

    // From now on rewards are paid out in full, and all of the new time is paid.
    let (staked, liquid, bank) = (chain.meta().pos_assets_total, chain.meta().liquid_total, chain.meta().bank);
    chain.block(10 * SECOND, vec![]);
    chain.block(10 * SECOND, vec![]);
    let paid = chain.meta().liquid_total - liquid;
    assert!((20 * SECOND - 2 * STARTING..=20 * SECOND).contains(&paid), "paid {paid}");
    assert_eq!(chain.meta().pos_assets_total, staked, "no longer staked for them");
    assert!(chain.meta().bank - bank <= 2 * STARTING);
    let before = chain.account(9).balance;
    chain.block(SECOND, vec![chain.transfer(0, 9, SECOND)]);
    assert_eq!(chain.account(9).balance, before + SECOND);
    chain.engine.audit().unwrap();
}

#[test]
fn while_the_power_is_lent_a_validator_that_signs_twice_can_be_reported_and_slashed() {
    let mut chain = Chain::new(genesis(true));
    chain.block(10 * SECOND, vec![]);
    chain.block(10 * SECOND, vec![]);
    assert!(!chain.summary().bootstrap_ended);
    // The twentieth paid out is enough for the fee.
    assert!(chain.account(1).balance >= 100 * FEE);
    let bond = chain.candidate(3).self_bond;
    assert!(bond > 0);
    let bank = chain.meta().bank;
    chain.block(10 * SECOND, vec![chain.extension(1, 20, evidence(3, 1))]);
    let slashed = chain.candidate(3);
    assert!(slashed.jailed && slashed.self_bond == 0, "{slashed:?}");
    assert!(chain.meta().bank >= bank + bond, "the staked rewards were forfeited to the bank");
    chain.engine.audit().unwrap();
}

#[test]
fn a_starting_validator_that_never_signs_keeps_the_power_lent_but_time_still_circulates() {
    // Seven starting validators and one of them never signs: only six can
    // stand on their own stake, fewer than the seven the end of the lent
    // power needs, so it does not end. The network still runs (six of seven
    // is over two thirds), and a twentieth of the rewards is still paid out.
    let mut chain = Chain::new(genesis(true));
    let absent = pk(101);
    for _ in 0..300 {
        let signers: Vec<String> = chain.signers().into_iter().filter(|key| *key != absent).collect();
        chain.block_signed_by(10 * SECOND, vec![], &signers);
    }
    assert!(!chain.summary().bootstrap_ended);
    assert_eq!(chain.candidate(0).self_bond, 0, "the absent validator earned nothing");
    let earned = chain.meta().liquid_total + chain.meta().pos_assets_total;
    assert!(chain.meta().liquid_total.abs_diff(earned / 20) <= 300 * STARTING);
    // That is enough to use the network, for example to give someone seconds.
    let before = chain.account(9).balance;
    let signers: Vec<String> = chain.signers().into_iter().filter(|key| *key != absent).collect();
    chain.block_signed_by(SECOND, vec![chain.transfer(2, 9, SECOND)], &signers);
    assert_eq!(chain.account(9).balance, before + SECOND);
    chain.engine.audit().unwrap();
}

#[test]
fn a_starting_validator_that_does_not_sign_earns_nothing_and_its_share_stays_in_the_bank() {
    let mut chain = Chain::new(genesis(true));
    chain.block(10 * SECOND, vec![]);
    let absent = chain.engine.active_roster_at(chain.meta().height as u64).unwrap()[0].clone();
    let signers: Vec<String> = chain
        .signers()
        .into_iter()
        .filter(|key| *key != absent.consensus_key)
        .collect();
    let (bond, bank) = (chain.candidate(absent.owner).self_bond, chain.meta().bank);
    let meta = chain.meta();
    let (height, time) = (meta.height + 1, meta.time_micros + 10 * SECOND as i64);
    let hash = sha(height as u64);
    let prepared = chain.engine.prepare(height, time, &Vec::<Vec<u8>>::new(), &signers, hash).unwrap();
    chain.engine.commit(prepared, hash).unwrap();
    assert_eq!(chain.candidate(absent.owner).self_bond, bond);
    // About a seventh of the ten seconds stays in the bank.
    let kept = chain.meta().bank - bank;
    assert!((10 * SECOND / 7 - 10..=10 * SECOND / 7 + 10).contains(&kept), "kept {kept}");
    assert_eq!(chain.supply(), chain.meta().elapsed_micros().unwrap());
    chain.engine.audit().unwrap();
}

#[test]
fn the_bitcoin_actions_are_refused_on_such_a_network() {
    let mut chain = Chain::new(genesis(true));
    chain.block(10 * SECOND, vec![]);
    let network = chain.network.clone();
    for kind in [40u8, 41, 42, 60, 61, 62, 63] {
        let tx = raw_action(&network, kind, 0, 1, 0, 1, b"{}");
        chain.refuse(tx, "this network has no bitcoin auction");
    }
    // The same bytes on a network without the setting are refused, but for
    // what they are, not for the setting.
    let mut plain = Chain::new(genesis(false));
    plain.block(10 * SECOND, vec![]);
    let network = plain.network.clone();
    for kind in [40u8, 41, 42, 60, 61, 62, 63] {
        let tx = raw_action(&network, kind, 0, 1, 0, 1, b"{}");
        let signers = plain.signers();
        let meta = plain.meta();
        let error = format!(
            "{:#}",
            plain
                .engine
                .prepare(meta.height + 1, meta.time_micros + SECOND as i64, &[tx], &signers, sha(meta.height as u64 + 1))
                .err()
                .expect("accepted")
        );
        assert!(!error.contains("no bitcoin auction"), "{error}");
    }
}

#[test]
fn bonding_splits_a_reward_as_the_protocol_4_rule_does_and_pays_a_twentieth_of_the_own_part() {
    // A starting validator taken from a chain so that it is a real row; once
    // with a delegated pool, once without.
    let mut chain = Chain::new(genesis(true));
    for _ in 0..3 {
        chain.block(10 * SECOND, vec![]);
    }
    let alone = chain.candidate(0);
    let mut pooled = alone.clone();
    pooled.pool_assets = 3 * SECOND;
    pooled.pool_shares = 3 * SECOND;
    pooled.validate().unwrap();
    for candidate in [alone, pooled] {
        for (amount, power) in [(7 * SECOND, None), (7 * SECOND, Some(5u64)), (1, Some(5)), (0, Some(5)), (123_457, Some(1)), (u64::MAX / 4, Some(1))] {
            let (mut paid, mut bonded) = (candidate.clone(), candidate.clone());
            let protocol = pos::reward_with_weights(&mut paid, amount, 1, power).unwrap();
            let bonding = pos::reward_bonding_bootstrap(&mut bonded, amount, 1, power).unwrap();
            // Same pool, same total taken from the bank.
            assert_eq!(bonded.pool_assets, paid.pool_assets);
            assert_eq!(bonding.bank_debit, protocol.bank_debit);
            let delegated = paid.pool_assets - candidate.pool_assets;
            match power {
                None => {
                    assert_eq!(bonding, protocol);
                    assert_eq!(bonded, paid);
                }
                Some(_) => {
                    // What the protocol-4 rule pays out is split: staked, and
                    // a twentieth of the own part paid out with the commission.
                    let staked = bonded.self_bond - candidate.self_bond;
                    assert_eq!(bonding.credit + staked, protocol.credit);
                    assert_eq!(bonding.bank_debit, staked + delegated + bonding.credit);
                    assert_eq!(paid.self_bond, candidate.self_bond);
                    if candidate.pool_assets == 0 {
                        // No commission: the own part is all of it.
                        assert_eq!(bonding.credit, protocol.credit / pos::BOOTSTRAP_PAID_PARTS);
                    }
                }
            }
        }
    }
}

/// A precommit of starting validator `owner` for a block named by `block_byte`.
fn vote(owner: u64, height: u64, block_byte: u8) -> tendermint::Vote {
    use ed25519_dalek::Signer;
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
/// Evidence that `owner` signed two different blocks at `height`.
fn evidence(owner: u64, height: u64) -> serde_json::Value {
    serde_json::to_value(pos::DoubleSignEvidence { first: vote(owner, height, 1), second: vote(owner, height, 3) }).unwrap()
}
