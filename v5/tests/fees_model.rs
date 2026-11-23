//! The fee rule (`fees_to_validators_ppm`) against an independent model.
//!
//! Written for the review of the rule. Every block is executed by the
//! proposer path, the validator path and the reference path, and after every
//! block the fee pool row, the bank and the validators' credits are compared
//! with a recomputation from the committed state: the validators' part of
//! the fees of a block joins the new time of the validators who signed it,
//! one rule pays both, and nothing is carried further. `fees.rs` holds the
//! readable cases.
//!
//! The recomputation calls the same reward function as the engine, so it
//! finds wrong execution, not a wrong rule. One check uses no model at all
//! (from the second review): before every block, the block is executed with
//! no transactions for no signer, for every signer alone, for the signers
//! it really has and for the whole roster. What a set of signers is paid
//! must be the sum of what its members are paid alone, in what leaves the
//! bank, what reaches balances and what reaches stake. So what a signer is
//! paid does not depend on who else signed.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, Meta, account_key};
use timecurrency_v5::pos_adapter::{self, FEE_POOL_KEY};
use timecurrency_v5::security::{self, Role};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;
const ALL: u64 = 1_000_000;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// A candidate transaction and what it moves into the bank if it is included:
/// `fee` is the action's fee (the only part the rule may count), `extra` is
/// anything else (registration charge), `slash` names a validator whose
/// penalty the action moves into the bank.
#[derive(Clone)]
struct Tx {
    raw: Vec<u8>,
    fee: u64,
    extra: u64,
    slash: Option<u64>,
}
fn paid(raw: Vec<u8>) -> Tx {
    Tx { raw, fee: FEE, extra: 0, slash: None }
}
fn free(raw: Vec<u8>) -> Tx {
    Tx { raw, fee: 0, extra: 0, slash: None }
}

#[derive(Default, Debug)]
struct Seen {
    absent_share_kept: u64,
    jailed_share_kept: u64,
    withheld_fee: u64,
    fee_to_delegators: u64,
    fee_on_virtual_power: u64,
    fee_on_real_stake: u64,
    fee_blocks: u64,
    /// Blocks on which the sums were compared while fees were owed, and of
    /// those the ones whose real signers were not the whole roster.
    additive_fee_blocks: u64,
    additive_partial: u64,
    /// Rosters seen that differ from the one before (a set change between
    /// the block that was signed and the block that pays).
    roster_changes: u64,
    last_roster: Vec<String>,
}

struct Expect {
    bank_debit: u64,
    /// Owner, balance before, credit.
    credits: Vec<(u64, u64, u64)>,
    /// Owner, pool assets after the reward.
    pools: Vec<(u64, u64)>,
}

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    ppm: u64,
    seen: Seen,
}
impl Chain {
    fn new(ppm: u64, validators: u64) -> Self {
        let mut genesis = genesis_v5();
        genesis.fees_to_validators_ppm = ppm;
        genesis.validators = (0..validators)
            .map(|owner| timecurrency_v5::genesis::BootstrapValidator {
                owner,
                consensus_key: pk(owner as u8 + 101),
                commission_bps: 1000,
            })
            .collect();
        let network = genesis.network_id().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine, network, ppm, seen: Seen::default() }
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
    fn summary(&self) -> pos::Summary {
        serde_json::from_slice(&self.row(pos_adapter::SUMMARY_KEY).unwrap()).unwrap()
    }
    fn candidate(&self, id: u64) -> pos::Candidate {
        serde_json::from_slice(&self.row(&pos_adapter::candidate_key(id)).unwrap()).unwrap()
    }
    fn stake(&self, id: u64) -> Option<pos::OwnerStake> {
        self.row(&pos_adapter::owner_key(id))
            .map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn pool(&self) -> u64 {
        self.row(FEE_POOL_KEY).map_or(0, |raw| {
            let text: String = serde_json::from_slice(&raw).unwrap();
            let value: u64 = text.parse().unwrap();
            assert!(value > 0, "an empty pool has no row");
            value
        })
    }
    fn signers(&self) -> Vec<String> {
        self.engine
            .active_roster_at(self.meta().height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect()
    }
    /// The validators' part of one fee.
    fn part(&self, fee: u64) -> u64 {
        (u128::from(fee) * u128::from(self.ppm) / 1_000_000) as u64
    }
    fn legacy(&self, from: u64, ahead: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        self.legacy_raw(from, row.nonce + ahead, row.auth_epoch, signer, payload)
    }
    fn legacy_raw(&self, from: u64, nonce: u64, auth_epoch: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
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
    fn transfer(&self, from: u64, ahead: u64, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ahead, from as u8 + 1, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn extension(&self, from: u64, ahead: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + ahead, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
    }
    /// A protective action: no nonce, no authority epoch.
    fn guard(&self, from: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        timecurrency_v5::wire::sign(&self.network, from, 0, 0, kind, &payload, &key(signer)).unwrap()
    }

    /// What `begin_block` of the next block must pay, from the committed
    /// rows alone.
    fn expect(&mut self, signers: &[String], delta: u64) -> Expect {
        let s = self.summary();
        let total: u64 = s.active.iter().map(|v| v.power).sum();
        let fees = self.pool();
        // New time and the fees of the last block are one budget.
        let budget = delta.min(60 * SECOND) / 5 + fees;
        let height = self.meta().height as u64 + 1;
        let mut bank_debit = 0u64;
        let mut credits = Vec::new();
        let mut pools = Vec::new();
        if fees > 0 {
            self.seen.fee_blocks += 1;
        }
        for v in &s.active {
            let amount = (u128::from(budget) * u128::from(v.power) / u128::from(total)) as u64;
            let fee_part = (u128::from(fees) * u128::from(v.power) / u128::from(total)) as u64;
            if !signers.contains(&v.consensus_key) {
                // Stays in the bank, like its share of new time.
                if fee_part > 0 {
                    self.seen.absent_share_kept += 1;
                }
                continue;
            }
            let mut c = self.candidate(v.owner);
            if c.jailed {
                if fee_part > 0 {
                    self.seen.jailed_share_kept += 1;
                }
                continue;
            }
            let bootstrap = (c.genesis && !s.bootstrap_ended).then_some(v.power);
            let pool_before = c.pool_assets;
            let live = c.self_bond + c.pool_assets;
            let effect = pos::reward_with_weights(&mut c, amount, height, bootstrap).unwrap();
            assert!(effect.bank_debit <= amount, "the reward rule paid more than it was given");
            if fee_part > 0 {
                if effect.bank_debit < amount {
                    self.seen.withheld_fee += 1;
                }
                if c.pool_assets > pool_before {
                    self.seen.fee_to_delegators += 1;
                }
                if bootstrap.is_some() && live < v.power * SECOND {
                    self.seen.fee_on_virtual_power += 1;
                }
                if live > 0 {
                    self.seen.fee_on_real_stake += 1;
                }
            }
            bank_debit += effect.bank_debit;
            credits.push((v.owner, self.account(v.owner).balance, effect.credit));
            pools.push((v.owner, c.pool_assets));
        }
        Expect { bank_debit, credits, pools }
    }

    /// Offers `offered` to a proposer, checks the block on every path and
    /// against the recomputation, commits it and returns what was included.
    fn step(&mut self, delta: u64, offered: &[Tx], signers: &[String]) -> Vec<Vec<u8>> {
        let expect = self.expect(signers, delta);
        let before = self.meta().clone();
        let (height, time) = (before.height + 1, before.time_micros + delta as i64);
        let hash = sha(height as u64);
        self.additive(height, time, hash, signers);
        // Penalties of slashing actions, from the rows as the reward of this
        // block leaves them.
        let penalties: Vec<u64> = offered
            .iter()
            .map(|tx| {
                tx.slash.map_or(0, |owner| {
                    let c = self.candidate(owner);
                    let pool = expect
                        .pools
                        .iter()
                        .find(|(id, _)| *id == owner)
                        .map_or(c.pool_assets, |(_, pool)| *pool);
                    c.self_bond + c.self_exits.assets + pool / 20 + c.delegated_exits.assets / 20
                })
            })
            .collect();
        let raws: Vec<Vec<u8>> = offered.iter().map(|tx| tx.raw.clone()).collect();
        let (prepared, kept) = self
            .engine
            .prepare_filtered(height, time, &raws, signers, 1 << 22, hash)
            .unwrap_or_else(|error| panic!("height {height}: the proposer failed: {error:#}"));
        let strict = self
            .engine
            .prepare(height, time, &kept, signers, hash)
            .unwrap_or_else(|error| panic!("height {height}: validators refuse the proposal: {error:#}"));
        let reference = self
            .engine
            .prepare_reference(height, time, &kept, signers, hash)
            .unwrap_or_else(|error| panic!("height {height}: the reference refuses the proposal: {error:#}"));
        assert_eq!(strict.root, prepared.root, "height {height}: validator and proposer disagree");
        assert_eq!(reference.root, prepared.root, "height {height}: fast path and reference disagree");
        let whole = self.engine.prepare(height, time, &raws, signers, hash);
        assert_eq!(
            whole.is_ok(),
            kept.len() == raws.len(),
            "height {height}: strict execution and filtering disagree"
        );
        let whole_reference = self.engine.prepare_reference(height, time, &raws, signers, hash);
        assert_eq!(whole_reference.is_ok(), whole.is_ok(), "height {height}: reference acceptance");
        self.engine.commit(prepared, hash).unwrap();

        let mut fees = 0u64;
        let mut credited = 0u64;
        let mut left: Vec<(usize, &Tx)> = offered.iter().enumerate().collect();
        for raw in &kept {
            let at = left.iter().position(|(_, tx)| &tx.raw == raw).expect("kept an unknown transaction");
            let (index, tx) = left.remove(at);
            fees += tx.fee;
            credited += tx.fee + tx.extra + penalties[index];
        }
        let after = self.meta();
        // The validators' part of the fees of this block, and nothing older.
        assert_eq!(self.pool(), self.part(fees), "height {height}: fee pool of {fees} in fees");
        assert!(self.pool() <= after.bank, "height {height}: pool above the bank");
        assert_eq!(
            after.bank,
            before.bank + delta - expect.bank_debit + credited,
            "height {height}: bank"
        );
        assert_eq!(
            after.bank + after.liquid_total + after.pos_assets_total + after.auction_reserve_total,
            after.elapsed_micros().unwrap(),
            "height {height}: supply"
        );
        if self.ppm == 0 {
            assert!(self.row(FEE_POOL_KEY).is_none(), "a pool row without the rule");
        }
        if kept.is_empty() {
            for (owner, balance, credit) in &expect.credits {
                assert_eq!(self.account(*owner).balance, balance + credit, "height {height}: credit of {owner}");
            }
            for (owner, pool) in &expect.pools {
                assert_eq!(self.candidate(*owner).pool_assets, *pool, "height {height}: pool of {owner}");
            }
        }
        kept
    }
    /// What a set of signers is paid at the start of the next block, as the
    /// sum of what its members are paid alone: bank, balances, stake.
    fn additive(&mut self, height: i64, time: i64, hash: [u8; 32], signers: &[String]) {
        let none: [Vec<u8>; 0] = [];
        let roster = self.signers();
        let totals = |set: &[String]| -> (u64, u64, u64) {
            let prepared = self
                .engine
                .prepare(height, time, &none, set, hash)
                .unwrap_or_else(|error| panic!("height {height}: {error:#}"));
            (prepared.meta.bank, prepared.meta.liquid_total, prepared.meta.pos_assets_total)
        };
        let base = totals(&[]);
        let paid = |set: &[String]| -> (u64, u64, u64) {
            let after = totals(set);
            (base.0 - after.0, after.1 - base.1, after.2 - base.2)
        };
        let mut alone = BTreeMap::new();
        for key in &roster {
            let pay = paid(std::slice::from_ref(key));
            // Everything that leaves the bank reaches a balance or stake.
            assert_eq!(pay.0, pay.1 + pay.2, "height {height}: payment of one signer does not balance");
            alone.insert(key.clone(), pay);
        }
        for set in [signers.to_vec(), roster.clone()] {
            let sum = set.iter().fold((0u64, 0u64, 0u64), |sum, key| {
                let pay = alone[key];
                (sum.0 + pay.0, sum.1 + pay.1, sum.2 + pay.2)
            });
            assert_eq!(
                paid(&set),
                sum,
                "height {height}: what {} signers are paid is not the sum of what each is paid alone",
                set.len()
            );
        }
        if self.pool() > 0 {
            self.seen.additive_fee_blocks += 1;
            if signers.len() != roster.len() {
                self.seen.additive_partial += 1;
            }
        }
        if !self.seen.last_roster.is_empty() && self.seen.last_roster != roster {
            self.seen.roster_changes += 1;
        }
        self.seen.last_roster = roster;
    }
    /// A block of exactly these transactions, signed by everyone.
    fn all(&mut self, delta: u64, txs: Vec<Tx>) {
        let signers = self.signers();
        let kept = self.step(delta, &txs, &signers);
        assert_eq!(kept.len(), txs.len(), "a transaction of a scripted block was refused");
    }
    fn refused(&self, raw: &[u8]) -> String {
        let meta = self.meta();
        let (height, time) = (meta.height + 1, meta.time_micros + SECOND as i64);
        match self.engine.prepare(height, time, &[raw], &self.signers(), sha(height as u64)) {
            Ok(_) => panic!("accepted"),
            Err(error) => format!("{error:#}"),
        }
    }
}

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
    vote.to_signable_bytes("time-devnet-v4-engine-test".parse().unwrap(), &mut bytes)
        .unwrap();
    vote.signature = Some(Signature::try_from(key(seed).sign(&bytes).to_bytes().to_vec()).unwrap());
    vote
}
fn evidence(owner: u64) -> Value {
    serde_json::to_value(pos::DoubleSignEvidence { first: vote(owner, 1, 1), second: vote(owner, 1, 3) }).unwrap()
}
fn sponsor(chain: &Chain, sponsor: u64, ahead: u64, seed: u8, name: &str) -> Tx {
    let salt = hex::encode([seed; 32]);
    let commitment = ledger::action_commitment(&chain.network, &pk(seed), name, &salt).unwrap();
    let expiry = chain.now() + 3600 * SECOND;
    let consent = registration::consent_bytes(
        pos::hex32(&chain.network).unwrap(),
        sponsor,
        pos::hex32(&pk(seed)).unwrap(),
        pos::hex32(&commitment).unwrap(),
        expiry,
    );
    let raw = chain.extension(
        sponsor,
        ahead,
        sponsor as u8 + 1,
        44,
        json!({"public_key":pk(seed),"commitment":commitment,"expires_elapsed_micros":expiry.to_string(),"proof":hex::encode(key(seed).sign(&consent).to_bytes())}),
    );
    Tx { raw, fee: FEE, extra: chain.meta().config.registration.fee_micros, slash: None }
}
fn reveal(chain: &Chain, seed: u8, name: &str) -> Tx {
    free(chain.legacy_raw(
        u64::MAX,
        0,
        0,
        seed,
        ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: hex::encode([seed; 32]) }),
    ))
}
fn register(chain: &Chain, owner: u64, ahead: u64, consensus_seed: u8) -> Tx {
    let proof = key(consensus_seed).sign(
        &pos::register_message(pos::hex32(&chain.network).unwrap(), owner, &pk(consensus_seed), 1000).unwrap(),
    );
    paid(chain.extension(
        owner,
        ahead,
        owner as u8 + 1,
        17,
        json!({"commission_bps":1000,"consensus_key":pk(consensus_seed),"proof":hex::encode(proof.to_bytes())}),
    ))
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
/// Adopting the security rules with keys 60 (sign-in), 61 (spend), 62 and 63
/// (recovery).
fn secure(chain: &Chain, account: u64, limit: u64) -> Tx {
    let mut keys = vec![
        accepts(&chain.network, 60, account, Role::Signin),
        accepts(&chain.network, 61, account, Role::Spend),
        accepts(&chain.network, 62, account, Role::Recover),
        accepts(&chain.network, 63, account, Role::Recover),
    ];
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    let policy = json!({"threshold": "2", "daily_limit_micros": limit.to_string(), "delay_seconds": "60", "freeze_seconds": "120"});
    paid(chain.extension(account, 1, account as u8 + 1, security::SECURE, json!({"keys": keys, "policy": policy})))
}

/// Every class of fee, of bank income that is no fee, and of action that is
/// free, one after the other, with the pool recomputed after every block.
fn every_class(ppm: u64) {
    let mut chain = Chain::new(ppm, 4);
    for _ in 0..20 {
        chain.all(60 * SECOND, vec![]);
    }
    assert_eq!(chain.pool(), 0);
    // Transfers on the fast path, a merchant payment, `CancelPending` (whose
    // fee this engine charges itself), and stake of a validator owner.
    let now = chain.now();
    let mut reference = [7u8; 32];
    reference[..8].copy_from_slice(&(chain.account(1).nonce + 1).to_be_bytes());
    reference[8..16].copy_from_slice(&(now + 3600 * SECOND).to_be_bytes());
    chain.all(
        10 * SECOND,
        vec![
            paid(chain.transfer(0, 1, 5, 5 * SECOND)),
            paid(chain.transfer(0, 2, 6, 5 * SECOND)),
            paid(chain.transfer(0, 3, 7, FEE + 300)),
            paid(chain.transfer(0, 4, 8, 3 * SECOND)),
            paid(chain.transfer(0, 5, 4, 3 * SECOND)),
            paid(chain.legacy(
                1,
                1,
                2,
                ActionPayload::MerchantPayment(ledger::MerchantPayment { to: 6, amount: SECOND, reference: hex::encode(reference) }),
            )),
            paid(chain.legacy(3, 1, 4, ActionPayload::CancelPending(ledger::CancelPending {}))),
            paid(chain.extension(2, 1, 3, 18, json!({"amount": "10000"}))),
            paid(chain.extension(0, 6, 1, 18, json!({"amount": "30000"}))),
        ],
    );
    assert_eq!(chain.pool(), chain.part(9 * FEE));
    chain.engine.audit().unwrap();
    // Delegation to a bootstrap validator, a sponsored registration (its
    // charge is no fee), a guardian policy, a new validator candidate.
    chain.all(
        10 * SECOND,
        vec![
            paid(chain.legacy(5, 1, 6, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 400_000, min_shares: 1 }))),
            sponsor(&chain, 1, 1, 201, "newcomer"),
            paid(chain.legacy(
                6,
                1,
                7,
                ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![0, 1, 2], threshold: 2, delay_seconds: 30 }),
            )),
            register(&chain, 4, 1, 124),
        ],
    );
    chain.engine.audit().unwrap();
    // The reveal is free. Guardians consent (a fee each).
    let version = chain.account(6).recovery_version;
    chain.all(
        10 * SECOND,
        vec![
            reveal(&chain, 201, "newcomer"),
            paid(chain.legacy(0, 1, 1, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: true }))),
            paid(chain.legacy(1, 1, 2, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: true }))),
        ],
    );
    assert_eq!(chain.account(12).name, "newcomer");
    // One guardian approves a recovery (a fee); undelegating and a partial
    // exit of own stake pay a fee as well.
    let target = chain.account(6);
    let recovery_id = hex::encode(sha(900));
    let expiry = chain.now() + 30 * SECOND + 7 * pos::DAY;
    let mut message = b"TCDEVNET-RECOVERY-V1\0".to_vec();
    message.extend(hex::decode(&chain.network).unwrap());
    message.extend(6u64.to_be_bytes());
    message.extend(target.auth_epoch.to_be_bytes());
    message.extend(target.recovery_version.to_be_bytes());
    message.extend(hex::decode(&recovery_id).unwrap());
    message.extend(key(230).verifying_key().as_bytes());
    message.extend(expiry.to_be_bytes());
    let claim = ledger::ApproveRecovery {
        target: 6,
        policy_version: target.recovery_version,
        recovery_id,
        new_public_key: pk(230),
        expires_elapsed_micros: expiry,
        proof: hex::encode(key(230).sign(&message).to_bytes()),
    };
    chain.all(
        10 * SECOND,
        vec![
            paid(chain.legacy(1, 1, 2, ActionPayload::ApproveRecovery(claim))),
            paid(chain.legacy(5, 1, 6, ActionPayload::Undelegate(ledger::Undelegate { operator: 0, shares: 100_000, min_amount: 1 }))),
            paid(chain.extension(0, 1, 1, 19, json!({"amount": "10000", "min_amount": "10000"}))),
        ],
    );
    assert!(!chain.candidate(0).pending_reward_exits.is_empty());
    // Free actions of the protocol-4 rules: a guardian withdraws consent, the
    // owner calls the recovery off.
    chain.all(
        10 * SECOND,
        vec![
            free(chain.legacy(0, 1, 1, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: false }))),
            free(chain.legacy(6, 1, 7, ActionPayload::CancelRecovery(ledger::CancelRecovery {}))),
        ],
    );
    chain.engine.audit().unwrap();
    // Account 7 holds one fee and 300: adopting the security rules takes the
    // fee, a freeze then costs what is left.
    assert_eq!(chain.account(7).balance, FEE + 300);
    chain.all(10 * SECOND, vec![secure(&chain, 7, 500_000)]);
    assert_eq!(chain.account(7).balance, 300);
    let expires = chain.now() + 600 * SECOND;
    let freeze = chain.guard(7, 62, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": expires.to_string()}));
    chain.all(10 * SECOND, vec![Tx { raw: freeze, fee: 300, extra: 0, slash: None }]);
    assert_eq!(chain.account(7).balance, 0);
    // Refused late: a secured account over its daily limit fails after its
    // fee was taken inside the stage; an overspending transfer fails after
    // the fast path has added its fee. Neither may leave a trace.
    chain.all(10 * SECOND, vec![secure(&chain, 8, 1500)]);
    let over = chain.legacy(8, 1, 61, ActionPayload::Delegate(ledger::Delegate { operator: 1, amount: 1000, min_shares: 1 }));
    assert!(chain.refused(&over).contains("daily limit"), "{}", chain.refused(&over));
    let overspend = chain.transfer(4, 1, 5, u64::MAX / 4);
    assert!(chain.refused(&overspend).contains("insufficient funds"));
    let signers = chain.signers();
    let good = [paid(chain.transfer(1, 1, 9, 77)), paid(chain.transfer(2, 1, 9, 78))];
    let kept = chain.step(
        10 * SECOND,
        &[good[0].clone(), paid(over), paid(overspend), good[1].clone()],
        &signers,
    );
    assert_eq!(kept, vec![good[0].raw.clone(), good[1].raw.clone()]);
    chain.engine.audit().unwrap();
    // A validator is caught signing twice: the reporter pays a fee, the
    // penalty goes to the bank and is no fee. The offender stays in the
    // roster for two more blocks; its share of the fees stays in the bank.
    assert!(chain.candidate(0).self_bond > 0);
    let report = chain.extension(2, 1, 3, 20, evidence(0));
    chain.all(10 * SECOND, vec![Tx { raw: report, fee: FEE, extra: 0, slash: Some(0) }]);
    assert!(chain.candidate(0).jailed && chain.summary().safety_hold);
    for _ in 0..6 {
        chain.all(10 * SECOND, vec![]);
    }
    println!("ppm {ppm}: {:?}", chain.seen);
    if ppm > 0 {
        assert!(chain.seen.jailed_share_kept > 0, "{:?}", chain.seen);
        assert!(chain.seen.withheld_fee > 0, "{:?}", chain.seen);
        assert!(chain.seen.fee_to_delegators > 0, "{:?}", chain.seen);
    } else {
        assert_eq!(chain.seen.fee_blocks, 0);
    }
    chain.engine.audit().unwrap();
}

#[test]
fn every_class_of_fee_and_of_other_bank_income_is_counted_right() {
    every_class(ALL);
}
#[test]
fn the_same_with_a_share_that_does_not_divide_a_fee() {
    every_class(333_333);
}
#[test]
fn the_same_without_the_rule() {
    every_class(0);
}

/// One random candidate transaction.
fn candidate(chain: &Chain, rng: &mut Rng, ahead: &mut BTreeMap<u64, u64>, reveals: &mut Vec<(u8, String)>, next_identity: &mut u8, list: &mut Vec<Tx>) {
    let id = rng.below(GENESIS_ACCOUNTS);
    let row = chain.account(id);
    let offset = 1 + ahead.get(&id).copied().unwrap_or(0);
    let other = (id + 1 + rng.below(GENESIS_ACCOUNTS - 1)) % GENESIS_ACCOUNTS;
    let signer = id as u8 + 1;
    let candidates = chain.summary().candidate_ids;
    let mut used = true;
    match rng.below(100) {
        0..=34 => {
            let amount = 1 + rng.below((row.balance / 6).max(2));
            list.push(paid(chain.transfer(id, offset, other, amount)));
        }
        35..=44 => {
            used = false;
            let raw = match rng.below(6) {
                0 => {
                    let mut raw = chain.transfer(id, offset, other, 5);
                    *raw.last_mut().unwrap() ^= 1;
                    raw
                }
                1 => chain.transfer(id, offset + 1, other, 5),
                2 => chain.transfer(id, offset, other, row.balance + 1),
                3 => chain.transfer(id, offset, id, 5),
                4 => chain.transfer(id, offset, other, 0),
                _ => chain.transfer(id, offset, 1_000_000 + other, 5),
            };
            // Should one become valid by its place in the block, it is a
            // transfer and pays one fee.
            list.push(paid(raw));
        }
        45..=49 => {
            let mut reference = Vec::new();
            reference.extend((row.nonce + offset).to_be_bytes());
            let expiry = if rng.chance(85) { chain.now() + 600 * SECOND } else { 1 };
            reference.extend(expiry.to_be_bytes());
            reference.extend([rng.next() as u8; 16]);
            list.push(paid(chain.legacy(
                id,
                offset,
                signer,
                ActionPayload::MerchantPayment(ledger::MerchantPayment { to: other, amount: 1 + rng.below(2000), reference: hex::encode(reference) }),
            )));
        }
        50..=69 => {
            let amounts = [1u64, 1000, 10_000, 400_000, SECOND, 2 * SECOND + 7];
            let amount = amounts[rng.below(amounts.len() as u64) as usize];
            let operator: u64 = candidates[rng.below(candidates.len() as u64) as usize].parse().unwrap();
            let own = candidates.contains(&id.to_string());
            let raw = match rng.below(5) {
                0 if own => chain.extension(id, offset, signer, 18, json!({"amount": amount.to_string()})),
                1 if own => chain.extension(id, offset, signer, 19, json!({"amount": amount.to_string(), "min_amount": "1"})),
                2 | 0 | 1 => chain.legacy(id, offset, signer, ActionPayload::Delegate(ledger::Delegate { operator, amount, min_shares: 1 })),
                _ => {
                    let Some(position) = chain.stake(id).and_then(|stake| stake.positions.first().cloned()) else {
                        return;
                    };
                    let shares = if rng.chance(30) { position.shares } else { 1 + rng.below(position.shares) };
                    chain.legacy(id, offset, signer, ActionPayload::Undelegate(ledger::Undelegate { operator: position.candidate, shares, min_amount: 1 }))
                }
            };
            list.push(paid(raw));
        }
        70..=72 => list.push(paid(chain.legacy(id, offset, signer, ActionPayload::CancelPending(ledger::CancelPending {})))),
        73..=77 => {
            if *next_identity >= 230 {
                return;
            }
            let seed = *next_identity;
            *next_identity += 1;
            let name = format!("new_{seed}");
            list.push(sponsor(chain, id, offset, seed, &name));
            reveals.push((seed, name));
        }
        78..=81 => {
            used = false;
            if reveals.is_empty() {
                return;
            }
            let (seed, name) = reveals[rng.below(reveals.len() as u64) as usize].clone();
            list.push(reveal(chain, seed, &name));
        }
        82..=85 => {
            if candidates.contains(&id.to_string()) {
                return;
            }
            list.push(register(chain, id, offset, 120 + id as u8));
        }
        _ => {
            used = false;
        }
    }
    if used {
        *ahead.entry(id).or_default() += 1;
    }
}

/// Random blocks on a network that pays fees on: `funded` says whether the
/// seven bootstrap validators put up real stake first (the bootstrap then
/// ends) or keep their virtual power.
fn random(seed: u64, ppm: u64, validators: u64, funded: bool, blocks: u64) -> Chain {
    let mut chain = Chain::new(ppm, validators);
    let mut rng = Rng(seed);
    chain.all(60 * SECOND, vec![]);
    chain.all(60 * SECOND, vec![]);
    if funded {
        let bonds = (0..validators)
            .map(|id| paid(chain.extension(id, 1, id as u8 + 1, 18, json!({"amount": (SECOND + id * 250_000).to_string()}))))
            .collect();
        chain.all(SECOND, bonds);
        chain.all(20 * SECOND, vec![]);
        assert!(chain.summary().bootstrap_ended);
    }
    // The other accounts get something to act with.
    let mut funding = Vec::new();
    for owner in 0..validators.min(4) {
        let amount = chain.account(owner).balance / 3;
        for index in 0..2u64 {
            let to = validators + (owner * 2 + index) % (GENESIS_ACCOUNTS - validators);
            funding.push(paid(chain.transfer(owner, 1 + index, to, amount)));
        }
    }
    chain.all(SECOND, funding);
    let mut reveals = Vec::new();
    let mut next_identity = 200u8;
    let mut included = 0usize;
    let mut slashed = false;
    for round in 0..blocks {
        let mut list = Vec::new();
        let mut ahead = BTreeMap::new();
        for _ in 0..rng.below(12) {
            candidate(&chain, &mut rng, &mut ahead, &mut reveals, &mut next_identity, &mut list);
        }
        if list.len() > 1 && rng.chance(15) {
            let copy = list[0].clone();
            list.push(copy);
        }
        // Once, a validator that was in the first roster is reported.
        if round == blocks / 2 && !slashed {
            slashed = true;
            list = vec![Tx { raw: chain.extension(validators - 1, 1, validators as u8, 20, evidence(1)), fee: FEE, extra: 0, slash: Some(1) }];
        }
        let roster = chain.signers();
        // Everyone signs the blocks right after the report, so that the
        // offender's share is seen to wait.
        let after_report = slashed && round <= blocks / 2 + 3;
        let signers: Vec<String> = match rng.below(10) {
            _ if after_report => roster.clone(),
            0 => roster.clone(),
            1 => Vec::new(),
            _ => roster.iter().filter(|_| rng.chance(80)).cloned().collect(),
        };
        let span = if rng.chance(10) { 70 * SECOND } else { 9 * SECOND };
        let delta = 1 + rng.below(span);
        included += chain.step(delta, &list, &signers).len();
        if round % 40 == 39 {
            chain.engine.audit().unwrap();
        }
    }
    chain.engine.audit().unwrap();
    assert!(slashed && chain.candidate(1).jailed);
    assert!(included as u64 > blocks, "only {included} transactions were included");
    println!("seed {seed:#x}: {included} included, {:?}", chain.seen);
    chain
}

#[test]
fn random_blocks_on_bootstrap_validators_keep_the_pool_exact() {
    let chain = random(0x5eed_0101, ALL, 4, false, 220);
    let seen = &chain.seen;
    assert!(seen.absent_share_kept > 0 && seen.fee_on_virtual_power > 0 && seen.fee_blocks > 50, "{seen:?}");
    assert!(seen.additive_fee_blocks > 40 && seen.additive_partial > 20, "{seen:?}");
}
#[test]
fn random_blocks_on_staked_validators_keep_the_pool_exact() {
    let chain = random(0x5eed_0202, ALL, 7, true, 260);
    let seen = &chain.seen;
    assert!(
        seen.absent_share_kept > 0
            && seen.jailed_share_kept > 0
            && seen.withheld_fee > 0
            && seen.fee_to_delegators > 0
            && seen.fee_on_real_stake > 0,
        "{seen:?}"
    );
    assert!(
        seen.additive_fee_blocks > 40 && seen.additive_partial > 20 && seen.roster_changes > 0,
        "{seen:?}"
    );
}
#[test]
fn random_blocks_with_an_odd_share_keep_the_pool_exact() {
    random(0x5eed_0303, 123_457, 7, true, 160);
}
#[test]
fn random_blocks_without_the_rule_never_make_a_pool() {
    let chain = random(0x5eed_0404, 0, 7, true, 120);
    assert_eq!(chain.seen.fee_blocks, 0);
}

#[test]
fn the_mempool_admits_the_same_with_and_without_the_rule() {
    let mut results = Vec::new();
    for ppm in [0, ALL] {
        let mut chain = Chain::new(ppm, 4);
        for _ in 0..5 {
            chain.all(60 * SECOND, vec![]);
        }
        chain.all(SECOND, vec![paid(chain.transfer(0, 1, 5, 3 * SECOND)), secure(&chain, 1, 500_000)]);
        let mut pending = chain.engine.check_state().unwrap();
        let unknown = SigStatus::Unknown;
        let expires = chain.now() + 600 * SECOND;
        let offered = vec![
            chain.transfer(0, 1, 5, 1000),
            chain.transfer(0, 2, 5, u64::MAX / 2),
            chain.transfer(0, 2, 6, 1000),
            chain.transfer(0, 2, 6, 1000),
            chain.extension(2, 1, 3, 18, json!({"amount": "10000"})),
            chain.extension(2, 1, 3, 18, json!({"amount": "10000"})),
            chain.legacy(5, 1, 6, ActionPayload::CancelPending(ledger::CancelPending {})),
            chain.legacy(5, 2, 6, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 1000, min_shares: 1 })),
            chain.legacy(6, 1, 7, ActionPayload::CancelPending(ledger::CancelPending {})),
            // A protective action, judged on the head.
            chain.guard(1, 62, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": expires.to_string()})),
            chain.guard(1, 62, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": expires.to_string()})),
            chain.guard(1, 63, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": expires.to_string()})),
        ];
        let admitted: Vec<bool> = offered.iter().map(|raw| pending.admit(raw, unknown).is_ok()).collect();
        // What the mempool admitted, a proposer includes (but for the second
        // freeze of the same account, which the first one makes stale).
        let wanted: Vec<Tx> = offered
            .iter()
            .zip(&admitted)
            .filter(|(_, admitted)| **admitted)
            .map(|(raw, _)| paid(raw.clone()))
            .collect();
        let signers = chain.signers();
        let kept = chain.step(SECOND, &wanted, &signers);
        assert_eq!(kept.len(), wanted.len() - 1);
        chain.engine.audit().unwrap();
        results.push(admitted);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(
        results[0],
        // The ninth is account 6 paying its fee out of the transfer that
        // was admitted before it.
        vec![true, false, true, false, true, false, true, false, true, true, false, true]
    );
}

/// Blocks one and four microseconds long hand out no new time (a fifth of
/// the block's time rounds to nothing): the whole payment is fees, and what
/// the reward rule withholds for departing stake stays in the bank.
#[test]
fn blocks_too_short_for_new_time_still_pay_fees_exactly() {
    let mut chain = Chain::new(ALL, 7);
    chain.all(60 * SECOND, vec![]);
    chain.all(60 * SECOND, vec![]);
    let bonds = (0..7)
        .map(|id| paid(chain.extension(id, 1, id as u8 + 1, 18, json!({"amount": (2 * SECOND).to_string()}))))
        .collect();
    chain.all(SECOND, bonds);
    chain.all(20 * SECOND, vec![]);
    assert!(chain.summary().bootstrap_ended);
    chain.all(SECOND, vec![paid(chain.transfer(1, 1, 7, SECOND))]);
    chain.all(
        SECOND,
        vec![paid(chain.legacy(7, 1, 8, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 700_000, min_shares: 1 })))],
    );
    let mut txs = vec![paid(chain.legacy(
        7,
        1,
        8,
        ActionPayload::Undelegate(ledger::Undelegate { operator: 0, shares: 300_000, min_amount: 1 }),
    ))];
    for ahead in 1..=30 {
        txs.push(paid(chain.transfer(2, ahead, 8, 3)));
    }
    chain.all(SECOND, txs);
    assert_eq!(chain.candidate(0).pending_reward_exits.len(), 1);
    assert_eq!(chain.pool(), 31 * FEE);
    let (withheld, delegators) = (chain.seen.withheld_fee, chain.seen.fee_to_delegators);
    let bank = chain.meta().bank;
    chain.all(1, vec![]);
    // Nothing but fees left the bank, and no more than was owed.
    assert!(chain.seen.withheld_fee > withheld && chain.seen.fee_to_delegators > delegators, "{:?}", chain.seen);
    let paid_out = bank + 1 - chain.meta().bank;
    assert!(paid_out > 25 * FEE && paid_out <= 31 * FEE, "{paid_out}");
    assert_eq!(chain.pool(), 0);
    chain.all(4, vec![paid(chain.transfer(3, 1, 8, 3))]);
    chain.all(1, vec![]);
    chain.all(SECOND, vec![]);
    chain.engine.audit().unwrap();
}
