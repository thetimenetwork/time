//! The amount of the action fee (`fee_micros` in the genesis).
//!
//! Protocol 4 fixed what an account action costs at 1,000 microseconds
//! (`ledger::FEE_MICROS`). A network can set a lower fee, from 1 to 999.
//!
//! Without the setting nothing changes. The differential tests compare that
//! case with the protocol-4 engine block by block; the first tests here pin
//! the genesis bytes and the network id and, for the rules protocol 4 does
//! not have, the state roots of a scripted pass through every kind of action,
//! taken on the engine as it was before the fee became a setting.
//!
//! With the setting every action costs exactly the fee, or nothing, to the
//! microsecond: on the transfer fast path, in the protocol-4 rule adapter
//! (whose rules charge 1,000 themselves and are lent the difference for the
//! duration of one action), in the staking and registration extensions and in
//! the account security rules. Every block here is executed by a validator,
//! by the reference path and by a proposer, and the three must agree.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{abci::*, types::BlockIdFlag},
};
use timecurrency_node::ledger::{self, Account, Action, ActionPayload};
use timecurrency_v5::app::App;
use timecurrency_v5::engine::{Engine, Meta, account_key};
use timecurrency_v5::genesis::Genesis;
use timecurrency_v5::pos_adapter::{FEE_POOL_KEY, fee_pool_limit};
use timecurrency_v5::security::{self, Role, Security};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;
use timecurrency_v5::transport::BatchCheck;

const SECOND: u64 = 1_000_000;
const ALL: u64 = 1_000_000;
/// The fee of protocol 4, and of a network that sets none.
const PROTOCOL_FEE: u64 = ledger::FEE_MICROS;
/// New time each of the four validators earns in a ten-second block.
const TIME_REWARD: u64 = 10 * SECOND / 5 / 4;

/// The test genesis with a fee and a share of the fees for validators.
fn network(fee: u64, ppm: u64) -> Genesis {
    let mut genesis = genesis_v5();
    genesis.fee_micros = fee;
    genesis.fees_to_validators_ppm = ppm;
    genesis
}
fn open(directory: &Path) -> Engine {
    Engine::open_with_history(Store::open(directory.join("state.v5state")).unwrap(), directory.join("history")).unwrap()
}

struct Chain {
    dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    /// What an action costs on this network.
    fee: u64,
    /// Hash over the root of every block committed so far.
    roots: Sha256,
}
impl Chain {
    /// A chain whose four validator owners (accounts 0 to 3) have earned new
    /// time for a while.
    fn start(genesis: Genesis) -> Self {
        let network = genesis.network_id().unwrap();
        let fee = genesis.fee();
        let dir = tempfile::tempdir().unwrap();
        let mut engine = open(dir.path());
        engine.initialize(genesis).unwrap();
        let mut chain = Self { dir, engine, network, fee, roots: Sha256::new() };
        for _ in 0..20 {
            chain.block(60 * SECOND, vec![]);
        }
        chain
    }
    fn new(fee: u64, ppm: u64) -> Self {
        Self::start(network(fee, ppm))
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
    fn balance(&self, id: u64) -> u64 {
        self.account(id).balance
    }
    fn security(&self, id: u64) -> Security {
        serde_json::from_slice(&self.row(&security::key(id)).expect("a secured account")).unwrap()
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
    /// Bank, balances, stake and auction reserve.
    fn supply(&self) -> u64 {
        let meta = self.meta();
        meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total
    }
    /// The roots of all blocks so far and the metadata row, as one hash.
    fn fingerprint(&self) -> String {
        let mut hash = self.roots.clone();
        hash.update(serde_json::to_vec(self.meta()).unwrap());
        hex::encode(hash.finalize())
    }
    /// Height, time, signers and hash of the next block.
    fn next(&self, delta: u64) -> (i64, i64, Vec<String>, [u8; 32]) {
        let meta = self.meta();
        (meta.height + 1, meta.time_micros + delta as i64, self.validators(), sha(meta.height as u64 + 1))
    }

    /// Commits a block of exactly `txs` and returns what they moved into the
    /// bank: the bank of this block less the bank of the same block without
    /// transactions. The block is executed by a validator, by the reference
    /// path and by a proposer, and the three must agree.
    #[track_caller]
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> u64 {
        let (height, time, signers, hash) = self.next(delta);
        let none: [Vec<u8>; 0] = [];
        let empty = self.engine.prepare(height, time, &none, &signers, hash).unwrap();
        let strict = self
            .engine
            .prepare(height, time, &txs, &signers, hash)
            .unwrap_or_else(|error| panic!("block refused: {error:#}"));
        let reference = self
            .engine
            .prepare_reference(height, time, &txs, &signers, hash)
            .unwrap_or_else(|error| panic!("the reference path refused the block: {error:#}"));
        assert_eq!(strict.root, reference.root, "fast path and reference disagree");
        let (proposed, kept) = self
            .engine
            .prepare_filtered(height, time, &txs, &signers, 1 << 22, hash)
            .unwrap();
        assert_eq!(kept, txs, "the proposer dropped a transaction");
        assert_eq!(proposed.root, strict.root, "proposer and validator disagree");
        let gained = strict.meta.bank - empty.meta.bank;
        self.roots.update(strict.root);
        self.engine.commit(strict, hash).unwrap();
        assert!(self.pool() <= self.meta().bank, "more owed than the bank holds");
        assert_eq!(self.supply(), self.now(), "the supply rule");
        gained
    }
    /// Commits a block of exactly `txs`, which must bring the bank `fees` in
    /// action fees and `other` besides, and of which the validators' part of
    /// the fees, and nothing else, must be owed to them.
    #[track_caller]
    fn charges(&mut self, delta: u64, txs: Vec<Vec<u8>>, fees: u64, other: u64) {
        assert_eq!(self.block(delta, txs), fees + other, "what the block brought the bank");
        let part = u128::from(fees) * u128::from(self.meta().config.fees_to_validators_ppm) / 1_000_000;
        assert_eq!(u128::from(self.pool()), part, "what is owed to validators");
    }
    /// The transaction is refused by a validator (the reason names `why`), by
    /// the reference path and by the mempool, and a proposer that is offered
    /// it builds the block it builds without it: nothing of it is left.
    #[track_caller]
    fn refuse(&self, tx: &[u8], why: &str) {
        let (height, time, signers, hash) = self.next(SECOND);
        let none: [Vec<u8>; 0] = [];
        let error = match self.engine.prepare(height, time, &[tx], &signers, hash) {
            Ok(_) => panic!("accepted, expected a refusal naming: {why}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains(why), "refused for another reason: {error}");
        assert!(
            self.engine.prepare_reference(height, time, &[tx], &signers, hash).is_err(),
            "the reference path accepted"
        );
        assert!(self.engine.validate_tx(tx).is_err(), "the mempool admitted");
        let empty = self.engine.prepare(height, time, &none, &signers, hash).unwrap();
        let (proposed, kept) = self
            .engine
            .prepare_filtered(height, time, &[tx], &signers, 1 << 22, hash)
            .unwrap();
        assert!(kept.is_empty(), "the proposer kept a refused transaction");
        assert_eq!(proposed.root, empty.root, "a refused transaction left a trace");
    }

    fn signed(&self, from: u64, nonce: u64, auth_epoch: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        ledger::sign_action(
            &Action { network_id: self.network.clone(), from, nonce, auth_epoch, public_key: pk(signer), payload, signature: vec![] },
            &key(signer),
        )
        .unwrap()
    }
    /// An action of `from`, `ahead` nonces on, signed by the key of `signer`.
    fn legacy(&self, from: u64, ahead: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        let row = self.account(from);
        self.signed(from, row.nonce + ahead, row.auth_epoch, signer, payload)
    }
    /// A payment of `from`, signed by its genesis key.
    fn transfer(&self, from: u64, ahead: u64, to: u64, amount: u64) -> Vec<u8> {
        self.pay(from, ahead, from as u8 + 1, to, amount)
    }
    fn pay(&self, from: u64, ahead: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ahead, signer, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    /// The reference of a payment to a shop: the nonce it reserves and a date
    /// ten minutes ahead.
    fn order(&self, nonce: u64, to: u64, amount: u64) -> ActionPayload {
        let mut reference = [7u8; 32];
        reference[..8].copy_from_slice(&nonce.to_be_bytes());
        reference[8..16].copy_from_slice(&(self.now() + 600 * SECOND).to_be_bytes());
        ActionPayload::MerchantPayment(ledger::MerchantPayment { to, amount, reference: hex::encode(reference) })
    }
    /// A payment to a shop: the protocol-4 rule adapter executes it on every
    /// path.
    fn merchant(&self, from: u64, ahead: u64, signer: u8, to: u64, amount: u64) -> Vec<u8> {
        self.legacy(from, ahead, signer, self.order(self.account(from).nonce + ahead, to, amount))
    }
    fn extension(&self, from: u64, ahead: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + ahead, row.auth_epoch, kind, &payload, &key(signer)).unwrap()
    }
    /// A protective action of a secured account: no nonce, no authority epoch.
    fn guard(&self, from: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
        timecurrency_v5::wire::sign(&self.network, from, 0, 0, kind, &payload, &key(signer)).unwrap()
    }
    /// The signature by which the holder of a key accepts a role on an account.
    fn acceptance(&self, seed: u8, account: u64, role: Role) -> String {
        hex::encode(key(seed).sign(&security::key_message(&self.network, account, role, &pk(seed)).unwrap()).to_bytes())
    }
    /// `account` adopts the security rules with keys 60 (sign-in), 61 (spend),
    /// 62 and 63 (recovery), two proofs and this daily limit. Signed by its
    /// genesis key.
    fn secure(&self, account: u64, limit: u64) -> Vec<u8> {
        let keys = sorted(vec![
            json!({"public_key": pk(60), "role": "signin", "proof": self.acceptance(60, account, Role::Signin)}),
            json!({"public_key": pk(61), "role": "spend", "proof": self.acceptance(61, account, Role::Spend)}),
            json!({"public_key": pk(62), "role": "recover", "proof": self.acceptance(62, account, Role::Recover)}),
            json!({"public_key": pk(63), "role": "recover", "proof": self.acceptance(63, account, Role::Recover)}),
        ]);
        self.extension(account, 1, account as u8 + 1, security::SECURE, json!({"keys": keys, "policy": policy(limit)}))
    }
    /// A root operation of `account` approved by `approvers` and submitted by
    /// `sender`, valid for ten minutes.
    fn root(&self, account: u64, sender: u8, approvers: &[u8], operation: Value) -> Vec<u8> {
        let version = self.security(account).version;
        let expires = self.now() + 600 * SECOND;
        let mut keys: Vec<(String, u8)> = approvers.iter().map(|seed| (pk(*seed), *seed)).collect();
        keys.sort();
        let names: Vec<&str> = keys.iter().map(|(public_key, _)| public_key.as_str()).collect();
        let message = security::root_message(&self.network, account, version, expires, &operation, &names).unwrap();
        let approvals: Vec<Value> = keys
            .iter()
            .map(|(public_key, seed)| json!({"public_key": public_key, "signature": hex::encode(key(*seed).sign(&message).to_bytes())}))
            .collect();
        self.guard(account, sender, security::ROOT, json!({"op": operation, "expires_elapsed_micros": expires.to_string(), "approvals": approvals}))
    }
    fn freeze(&self, account: u64, signer: u8) -> Vec<u8> {
        let row = self.security(account);
        self.guard(
            account,
            signer,
            security::FREEZE,
            json!({"freezes": row.freezes.to_string(), "version": row.version.to_string(), "expires_elapsed_micros": (self.now() + 600 * SECOND).to_string()}),
        )
    }
    /// A sponsor pays for the registration of the identity `seed`.
    fn sponsor(&self, sponsor: u64, ahead: u64, seed: u8, name: &str) -> Vec<u8> {
        let salt = hex::encode([seed; 32]);
        let commitment = ledger::action_commitment(&self.network, &pk(seed), name, &salt).unwrap();
        let expiry = self.now() + 3600 * SECOND;
        let consent = registration::consent_bytes(
            pos::hex32(&self.network).unwrap(),
            sponsor,
            pos::hex32(&pk(seed)).unwrap(),
            pos::hex32(&commitment).unwrap(),
            expiry,
        );
        self.extension(
            sponsor,
            ahead,
            sponsor as u8 + 1,
            44,
            json!({"public_key": pk(seed), "commitment": commitment, "expires_elapsed_micros": expiry.to_string(), "proof": hex::encode(key(seed).sign(&consent).to_bytes())}),
        )
    }
    /// The new identity takes its name: an action without an account.
    fn reveal(&self, seed: u8, name: &str) -> Vec<u8> {
        self.signed(u64::MAX, 0, 0, seed, ActionPayload::Reveal(ledger::Reveal { name: name.into(), salt: hex::encode([seed; 32]) }))
    }
    /// A new key with both powers for `account`, with its holder's proof.
    fn device(&self, account: u64, seed: u8) -> ActionPayload {
        let mut message = b"TCDEVNET-DEVICE-V1\0".to_vec();
        message.extend(hex::decode(&self.network).unwrap());
        message.extend(account.to_be_bytes());
        message.extend(self.account(account).auth_epoch.to_be_bytes());
        message.extend(key(seed).verifying_key().as_bytes());
        message.extend([1, 1]);
        ActionPayload::AddDevice(ledger::AddDevice { public_key: pk(seed), can_manage: true, can_spend: true, proof: hex::encode(key(seed).sign(&message).to_bytes()) })
    }
    /// What a guardian approves: `target` is to be taken over by the key of
    /// `seed`.
    fn claim(&self, target: u64, seed: u8, number: u64) -> ActionPayload {
        let row = self.account(target);
        let recovery_id = hex::encode(sha(number));
        let expiry = self.now() + 30 * SECOND + 7 * pos::DAY;
        let mut message = b"TCDEVNET-RECOVERY-V1\0".to_vec();
        message.extend(hex::decode(&self.network).unwrap());
        message.extend(target.to_be_bytes());
        message.extend(row.auth_epoch.to_be_bytes());
        message.extend(row.recovery_version.to_be_bytes());
        message.extend(hex::decode(&recovery_id).unwrap());
        message.extend(key(seed).verifying_key().as_bytes());
        message.extend(expiry.to_be_bytes());
        ActionPayload::ApproveRecovery(ledger::ApproveRecovery {
            target,
            policy_version: row.recovery_version,
            recovery_id,
            new_public_key: pk(seed),
            expires_elapsed_micros: expiry,
            proof: hex::encode(key(seed).sign(&message).to_bytes()),
        })
    }
    fn consent(&self, guardian: u64, ahead: u64, target: u64, accept: bool) -> Vec<u8> {
        self.legacy(
            guardian,
            ahead,
            guardian as u8 + 1,
            ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target, policy_version: self.account(target).recovery_version, accept }),
        )
    }
    /// A guardian policy of `account`: these guardians, two of them needed.
    fn guardians(&self, account: u64, guardians: [u64; 3]) -> Vec<u8> {
        self.legacy(
            account,
            1,
            account as u8 + 1,
            ActionPayload::SetRecovery(ledger::SetRecovery { guardians: guardians.to_vec(), threshold: 2, delay_seconds: 30 }),
        )
    }
    fn cancel_pending(&self, account: u64) -> Vec<u8> {
        self.legacy(account, 1, account as u8 + 1, ActionPayload::CancelPending(ledger::CancelPending {}))
    }
    /// Owner 0 pays each of `amounts` (account, microseconds) in one block;
    /// nothing is sent where the amount is zero.
    fn fund(&mut self, amounts: &[(u64, u64)]) {
        let txs: Vec<Vec<u8>> = amounts
            .iter()
            .filter(|(_, amount)| *amount > 0)
            .enumerate()
            .map(|(index, (to, amount))| self.transfer(0, 1 + index as u64, *to, *amount))
            .collect();
        let count = txs.len() as u64;
        self.charges(10 * SECOND, txs, count * self.fee, 0);
    }
    /// The account pays out all it holds but the fee of doing so.
    fn empty(&mut self, account: u64, signer: u8, to: u64) {
        let amount = self.balance(account) - self.fee;
        self.charges(SECOND, vec![self.pay(account, 1, signer, to, amount)], self.fee, 0);
        assert_eq!(self.balance(account), 0);
    }
}

/// The one accepted form of a list of keys: sorted by key.
fn sorted(mut keys: Vec<Value>) -> Value {
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    json!(keys)
}
fn policy(limit: u64) -> Value {
    json!({"threshold": "2", "daily_limit_micros": limit.to_string(), "delay_seconds": "60", "freeze_seconds": "120"})
}

/// The balances of the accounts that earn nothing by themselves (every
/// account but the four validator owners), kept by hand: what the test says
/// an action costs is taken off here, and the chain must agree.
struct Book(BTreeMap<u64, u64>);
impl Book {
    fn open(chain: &Chain) -> Self {
        Self((4..chain.meta().next_account_id).map(|id| (id, chain.balance(id))).collect())
    }
    fn pays(&mut self, id: u64, amount: u64) {
        let balance = self.0.get_mut(&id).expect("an account of the book");
        *balance = balance.checked_sub(amount).expect("the book says the account cannot pay this");
    }
    fn gets(&mut self, id: u64, amount: u64) {
        *self.0.entry(id).or_insert(0) += amount;
    }
    #[track_caller]
    fn agrees(&self, chain: &Chain) {
        for (id, balance) in &self.0 {
            assert_eq!(chain.balance(*id), *balance, "balance of account {id}");
        }
    }
}

/// One action of every kind that pays the fee, and of every kind that is
/// free, each checked for what it costs its payer, what it brings the bank
/// and what of it is owed to validators. Returns the number of whole fees
/// charged.
fn every_kind_of_action(chain: &mut Chain) -> u64 {
    let fee = chain.fee;
    let registration = chain.meta().config.registration.fee_micros;
    let mut fees = 0u64;

    // The owners pass on what they earned: eight payments on the fast path.
    let txs = vec![
        chain.transfer(0, 1, 4, 5 * SECOND),
        chain.transfer(0, 2, 5, 5 * SECOND),
        chain.transfer(1, 1, 6, 5 * SECOND),
        chain.transfer(1, 2, 7, 5 * SECOND),
        chain.transfer(2, 1, 8, 5 * SECOND),
        chain.transfer(2, 2, 9, 5 * SECOND),
        chain.transfer(3, 1, 10, SECOND),
        chain.transfer(3, 2, 11, SECOND),
    ];
    chain.charges(10 * SECOND, txs, 8 * fee, 0);
    fees += 8;
    let mut book = Book::open(chain);
    assert_eq!(book.0[&4], 5 * SECOND);

    // A payment, a payment to a shop, a guardian policy, `CancelPending`
    // (whose fee this engine charges itself), own stake of a validator, the
    // security rules, a delegation, a sponsored registration (its charge is
    // no fee) and a new key.
    let txs = vec![
        chain.transfer(4, 1, 10, 300_000),
        chain.merchant(5, 1, 6, 10, 200_000),
        chain.guardians(6, [4, 5, 7]),
        chain.cancel_pending(7),
        chain.extension(2, 1, 3, 18, json!({"amount": "30000"})),
        chain.secure(8, 500_000),
        chain.legacy(9, 1, 10, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 400_000, min_shares: 1 })),
        chain.sponsor(4, 2, 201, "newcomer"),
        chain.legacy(5, 2, 6, chain.device(5, 70)),
    ];
    chain.charges(10 * SECOND, txs, 9 * fee, registration);
    fees += 9;
    book.pays(4, 300_000 + fee);
    book.gets(10, 300_000);
    book.pays(5, 200_000 + fee);
    book.gets(10, 200_000);
    book.pays(6, fee);
    book.pays(7, fee);
    book.pays(8, fee);
    book.pays(9, 400_000 + fee);
    book.pays(4, fee + registration);
    book.pays(5, fee);
    book.agrees(chain);
    assert_eq!(chain.account(7).auth_epoch, 1);
    chain.engine.audit().unwrap();

    // The new identity takes its name (free: it has no account to pay
    // from), two guardians consent, a key is removed.
    let txs = vec![
        chain.reveal(201, "newcomer"),
        chain.consent(4, 1, 6, true),
        chain.consent(5, 1, 6, true),
        chain.legacy(5, 2, 6, ActionPayload::RevokeDevice(ledger::RevokeDevice { public_key: pk(70) })),
    ];
    chain.charges(10 * SECOND, txs, 3 * fee, 0);
    fees += 3;
    book.gets(12, 0);
    book.pays(4, fee);
    book.pays(5, 2 * fee);
    book.agrees(chain);
    assert_eq!(chain.account(12).name, "newcomer");

    // Both guardians approve a recovery of account 6, which freezes it. A
    // delegator and a validator take stake out.
    let claim = chain.claim(6, 230, 900);
    let txs = vec![
        chain.legacy(4, 1, 5, claim.clone()),
        chain.legacy(5, 1, 6, claim),
        chain.legacy(9, 1, 10, ActionPayload::Undelegate(ledger::Undelegate { operator: 0, shares: 100_000, min_amount: 1 })),
        chain.extension(2, 1, 3, 19, json!({"amount": "10000", "min_amount": "10000"})),
    ];
    chain.charges(10 * SECOND, txs, 4 * fee, 0);
    fees += 4;
    book.pays(4, fee);
    book.pays(5, fee);
    book.pays(9, fee);
    book.agrees(chain);
    chain.refuse(&chain.transfer(6, 1, 10, 5), "frozen");

    // Free under the protocol-4 rules: a guardian withdraws its consent, the
    // owner calls the recovery off. Nobody's balance moves.
    let txs = vec![
        chain.consent(4, 1, 6, false),
        chain.legacy(6, 1, 7, ActionPayload::CancelRecovery(ledger::CancelRecovery {})),
    ];
    chain.charges(10 * SECOND, txs, 0, 0);
    book.agrees(chain);

    // A third guardian consents and a second recovery is approved, waits its
    // delay and is finished by the new key: free as well.
    chain.charges(10 * SECOND, vec![chain.consent(7, 1, 6, true)], fee, 0);
    fees += 1;
    book.pays(7, fee);
    let claim = chain.claim(6, 231, 901);
    let txs = vec![chain.legacy(5, 1, 6, claim.clone()), chain.legacy(7, 1, 8, claim)];
    chain.charges(10 * SECOND, txs, 2 * fee, 0);
    fees += 2;
    book.pays(5, fee);
    book.pays(7, fee);
    book.agrees(chain);
    chain.charges(40 * SECOND, vec![], 0, 0);
    let finish = chain.legacy(6, 1, 231, ActionPayload::FinalizeRecovery(ledger::FinalizeRecovery { recovery_id: hex::encode(sha(901)) }));
    chain.charges(SECOND, vec![finish], 0, 0);
    book.agrees(chain);
    assert_eq!(chain.account(6).devices.len(), 1);
    chain.charges(SECOND, vec![chain.pay(6, 1, 231, 10, 1000)], fee, 0);
    fees += 1;
    book.pays(6, 1000 + fee);
    book.gets(10, 1000);
    book.agrees(chain);
    chain.engine.audit().unwrap();

    // The secured account, with its spend key: a payment, a payment to a
    // shop, a payment that waits, a lower limit and a new sign-in key. All
    // five fees and both amounts come out of the daily limit.
    let txs = vec![
        chain.pay(8, 1, 61, 10, 100_000),
        chain.merchant(8, 2, 61, 10, 50_000),
        chain.extension(8, 3, 61, security::PAYMENT, json!({"type": "request", "to": "10", "amount": "2000000"})),
        chain.extension(8, 4, 61, security::LIMIT, json!({"daily_limit_micros": "400000"})),
        chain.extension(8, 5, 61, security::SIGNIN, json!({"add": [{"public_key": pk(64), "proof": chain.acceptance(64, 8, Role::Signin)}], "remove": []})),
    ];
    chain.charges(10 * SECOND, txs, 5 * fee, 0);
    fees += 5;
    book.pays(8, 150_000 + 5 * fee);
    book.gets(10, 150_000);
    book.agrees(chain);
    let row = chain.security(8);
    assert_eq!(row.allowance_micros, 500_000 - 150_000 - 5 * fee);
    assert_eq!((row.policy.daily_limit_micros, row.pending_payments.len()), (400_000, 1));

    // A recovery key freezes the account; the spend key and a recovery key
    // lift the freeze; a payment waits again and a recovery key cancels it.
    chain.charges(SECOND, vec![chain.freeze(8, 62)], fee, 0);
    assert!(chain.security(8).pending_payments.is_empty());
    let unfreeze = json!({"type": "unfreeze", "freezes": chain.security(8).freezes.to_string()});
    chain.charges(SECOND, vec![chain.root(8, 61, &[61, 62], unfreeze)], fee, 0);
    let request = chain.extension(8, 1, 61, security::PAYMENT, json!({"type": "request", "to": "10", "amount": "1000000"}));
    chain.charges(SECOND, vec![request], fee, 0);
    let waiting = chain.security(8).pending_payments[0].id;
    let cancel = chain.guard(8, 63, security::CANCEL, json!({"type": "payment", "id": waiting.to_string()}));
    chain.charges(SECOND, vec![cancel], fee, 0);
    fees += 4;
    book.pays(8, 4 * fee);
    book.agrees(chain);

    // With two proofs a payment above the limit goes at once.
    let pay = json!({"type": "pay", "to": "10", "amount": "700000"});
    chain.charges(SECOND, vec![chain.root(8, 61, &[61, 62], pay)], fee, 0);
    fees += 1;
    book.pays(8, 700_000 + fee);
    book.gets(10, 700_000);
    book.agrees(chain);

    // The recovery keys alone replace the spend key: the request waits, and
    // the new spend key finishes it.
    let replace = json!({"type": "replace", "policy": policy(400_000), "keys": sorted(vec![
        json!({"public_key": pk(60), "role": "signin"}),
        json!({"public_key": pk(62), "role": "recover"}),
        json!({"public_key": pk(63), "role": "recover"}),
        json!({"public_key": pk(65), "role": "spend", "proof": chain.acceptance(65, 8, Role::Spend)}),
    ])});
    chain.charges(SECOND, vec![chain.root(8, 62, &[62, 63], replace)], fee, 0);
    chain.charges(61 * SECOND, vec![], 0, 0);
    let finish = chain.guard(8, 65, security::FINALIZE, json!({"version": chain.security(8).version.to_string()}));
    chain.charges(SECOND, vec![finish], fee, 0);
    fees += 2;
    book.pays(8, 2 * fee);
    book.agrees(chain);

    // A payment with two proofs must leave the fee in the account. This one
    // leaves one microsecond less than a fee beside it, and the freeze that
    // follows costs what is left.
    let balance = chain.balance(8);
    let all_but = |left: u64| json!({"type": "pay", "to": "10", "amount": (balance - fee - left).to_string()});
    chain.refuse(&chain.root(8, 65, &[62, 65], json!({"type": "pay", "to": "10", "amount": (balance - fee + 1).to_string()})), "insufficient liquid funds");
    chain.charges(SECOND, vec![chain.root(8, 65, &[62, 65], all_but(fee - 1))], fee, 0);
    fees += 1;
    book.pays(8, balance - (fee - 1));
    book.gets(10, balance - fee - (fee - 1));
    book.agrees(chain);
    assert_eq!(chain.balance(8), fee - 1);
    chain.charges(SECOND, vec![chain.freeze(8, 62)], fee - 1, 0);
    book.pays(8, fee - 1);
    book.agrees(chain);
    assert_eq!(chain.balance(8), 0);
    chain.engine.audit().unwrap();
    fees
}

/// Continues `every_kind_of_action`, where account 8 ends emptied and
/// frozen, with spend key 65 and recovery keys 62 and 63. (Kept apart so that
/// the roots of the scripted pass stay those the engine gave before the fee
/// became a setting.)
fn an_emptied_account_is_still_recovered(chain: &mut Chain) {
    assert_eq!(chain.balance(8), 0);
    assert!(chain.security(8).frozen_until_elapsed_micros > 0);
    // The spend key and a recovery key cannot act at once: every root
    // operation but a replacement asked for by the recovery keys alone needs
    // the full fee of the network.
    let unfreeze = json!({"type": "unfreeze", "freezes": chain.security(8).freezes.to_string()});
    chain.refuse(&chain.root(8, 65, &[62, 65], unfreeze), "insufficient funds for fee");
    // The recovery keys alone can still replace the keys. It costs what is
    // left, nothing here, and the new spend key finishes it after the delay,
    // which ends the freeze.
    let replace = json!({"type": "replace", "policy": policy(400_000), "keys": sorted(vec![
        json!({"public_key": pk(60), "role": "signin"}),
        json!({"public_key": pk(62), "role": "recover"}),
        json!({"public_key": pk(63), "role": "recover"}),
        json!({"public_key": pk(66), "role": "spend", "proof": chain.acceptance(66, 8, Role::Spend)}),
    ])});
    chain.charges(SECOND, vec![chain.root(8, 62, &[62, 63], replace)], 0, 0);
    chain.charges(61 * SECOND, vec![], 0, 0);
    let finish = chain.guard(8, 66, security::FINALIZE, json!({"version": chain.security(8).version.to_string()}));
    chain.charges(SECOND, vec![finish], 0, 0);
    assert!(chain.account(8).devices.iter().any(|d| d.public_key == pk(66) && d.can_spend));
    assert_eq!(chain.security(8).frozen_until_elapsed_micros, 0);
    assert_eq!(chain.balance(8), 0);
    chain.engine.audit().unwrap();
}

// ---------------------------------------------------------------- no setting

#[test]
fn a_network_without_the_setting_is_the_protocol_4_network() {
    let genesis = genesis_v5();
    assert_eq!((genesis.fee_micros, genesis.fee()), (PROTOCOL_FEE, PROTOCOL_FEE));
    assert_eq!(PROTOCOL_FEE, 1000);
    // The bytes of the protocol-4 genesis, and so its network id. (The
    // registration charge has a field of the same name inside its own object:
    // the setting would be a field of the genesis itself.)
    let text = serde_json::to_string(&genesis).unwrap();
    assert_eq!(text, serde_json::to_string(&genesis_v4()).unwrap());
    assert!(serde_json::to_value(&genesis).unwrap().get("fee_micros").is_none(), "{text}");
    assert_eq!(genesis.network_id().unwrap(), network_id(), "protocol-4 network id");
    // Set in code to the protocol-4 fee, it is the same network.
    let named = network(PROTOCOL_FEE, 0);
    assert_eq!(serde_json::to_string(&named).unwrap(), text);
    assert_eq!(named.network_id().unwrap(), network_id());

    // The metadata row has no trace of the setting, and every kind of action
    // costs what it did.
    let mut chain = Chain::start(genesis);
    assert_eq!(chain.fee, PROTOCOL_FEE);
    let meta = serde_json::to_value(chain.meta()).unwrap();
    assert!(meta["config"].get("fee_micros").is_none());
    assert_eq!(fee_pool_limit(chain.meta()), 0);
    let before = chain.balance(0);
    chain.charges(10 * SECOND, vec![chain.transfer(0, 1, 5, SECOND)], 1000, 0);
    assert_eq!(chain.balance(0), before + TIME_REWARD - SECOND - 1000);
    chain.engine.audit().unwrap();
}

#[test]
fn without_the_setting_every_root_is_what_it_was_before_the_setting_existed() {
    // The differential tests cannot compare the rules protocol 4 does not
    // have: account security, the fee of `CancelPending`, fees paid on to
    // validators. These two hashes, over the root of every block of the
    // scripted pass and the final metadata row, were taken from the engine as
    // it was before the fee became a setting, once with fees kept in the bank
    // and once with fees paid on.
    for (ppm, before) in [
        (0, "ff64dbd8a83f122df1c17ea94817b2af4844ba0c206a780d9ce2fa78efd1bdea"),
        (ALL, "dbf0fe4f8d24c156a96646291e442c0feab3baf18cceb266be514925fbd91404"),
    ] {
        let mut genesis = genesis_v5();
        genesis.fees_to_validators_ppm = ppm;
        let mut chain = Chain::start(genesis);
        assert_eq!(every_kind_of_action(&mut chain), 41);
        assert_eq!(chain.fingerprint(), before, "with {ppm} parts per million of the fees paid on");
    }
}

// ---------------------------------------------------------------- the setting

fn written(value: Value) -> Result<Genesis, serde_json::Error> {
    let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
    genesis["fee_micros"] = value;
    serde_json::from_value::<Genesis>(genesis)
}

#[test]
fn the_setting_is_a_fee_from_1_to_999_written_one_way() {
    for refused in [
        // The protocol-4 fee is written by leaving the field out.
        json!("1000"),
        // No fee, and more than protocol 4 charges.
        json!("0"),
        json!("1001"),
        json!("2000"),
        json!("1000000"),
        json!("18446744073709551615"),
        json!("18446744073709551616"),
        // Other spellings of numbers that would be allowed.
        json!("00"),
        json!("+0"),
        json!("-0"),
        json!("0.0"),
        json!(""),
        json!(" "),
        json!(" 10"),
        json!("10 "),
        json!("+10"),
        json!("010"),
        json!("0999"),
        json!("10.0"),
        json!("1e2"),
        json!("0x10"),
        json!("-10"),
        json!("１０"),
        json!("ten"),
        json!(0),
        json!(1),
        json!(10),
        json!(999),
        json!(1000),
        json!(10.5),
        json!(true),
        json!(null),
        json!(["10"]),
        json!({"micros": "10"}),
    ] {
        assert!(written(refused.clone()).is_err(), "read {refused}");
    }
    let mut ids = vec![network_id()];
    for (text, fee) in [("1", 1u64), ("2", 2), ("10", 10), ("500", 500), ("999", 999)] {
        let genesis = written(json!(text)).unwrap();
        assert_eq!((genesis.fee_micros, genesis.fee()), (fee, fee));
        genesis.validate().unwrap();
        // One encoding, read back to the same value and the same bytes.
        let bytes = serde_json::to_vec(&genesis).unwrap();
        let again: Genesis = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&again).unwrap(), bytes);
        assert_eq!(serde_json::to_value(&genesis).unwrap()["fee_micros"], json!(text));
        // The fee is part of the network id: every fee is another network.
        let id = genesis.network_id().unwrap();
        assert!(!ids.contains(&id), "fee {fee} shares a network id");
        ids.push(id);
    }
}

#[test]
fn a_fee_set_in_code_is_checked_like_a_written_one() {
    for bad in [0, 1001, 5000, u64::MAX] {
        let genesis = network(bad, 0);
        assert!(genesis.validate().is_err(), "fee {bad} is valid");
        assert!(genesis.network_id().is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(open(dir.path()).initialize(genesis).is_err(), "a chain started with fee {bad}");
    }
    for good in [1, 999, 1000] {
        network(good, 0).validate().unwrap();
    }
}

#[test]
fn the_setting_is_written_directly_after_the_share_of_the_fees() {
    // Tools that build a genesis compute the network id from their own
    // encoding (`campaign/lib/genesis.mjs`), so the position and form of the
    // field are part of the format.
    let without = serde_json::to_string(&genesis_v5()).unwrap();
    let body = without.strip_suffix('}').unwrap();
    let fee_only = network(10, 0);
    assert_eq!(serde_json::to_string(&fee_only).unwrap(), format!("{body},\"fee_micros\":\"10\"}}"));
    let both = network(10, ALL);
    let text = serde_json::to_string(&both).unwrap();
    assert_eq!(text, format!("{body},\"fees_to_validators_ppm\":\"1000000\",\"fee_micros\":\"10\"}}"));
    // The share alone is still the last field, as before.
    assert_eq!(
        serde_json::to_string(&network(PROTOCOL_FEE, ALL)).unwrap(),
        format!("{body},\"fees_to_validators_ppm\":\"1000000\"}}")
    );
    let parsed: Genesis = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed.network_id().unwrap(), both.network_id().unwrap());
    // The three are different networks, and none is the protocol-4 one.
    let ids = [fee_only.network_id().unwrap(), both.network_id().unwrap(), network(PROTOCOL_FEE, ALL).network_id().unwrap(), network_id()];
    for (index, id) in ids.iter().enumerate() {
        assert!(!ids[..index].contains(id));
    }
    // Written first, with white space, or before the share: the same network
    // and, written back, the same bytes.
    let first: Genesis = serde_json::from_str(&format!(r#"{{ "fee_micros" : "10" , "fees_to_validators_ppm":"1000000",{}}}"#, body.strip_prefix('{').unwrap())).unwrap();
    assert_eq!(first.network_id().unwrap(), both.network_id().unwrap());
    assert_eq!(serde_json::to_string(&first).unwrap(), text);
    // Twice, with the same or with different values.
    for tail in [r#","fee_micros":"10","fee_micros":"10"}"#, r#","fee_micros":"10","fee_micros":"11"}"#] {
        assert!(serde_json::from_str::<Genesis>(&format!("{body}{tail}")).is_err());
    }
}

#[test]
fn the_metadata_row_carries_the_setting_and_cannot_claim_another() {
    let lower = Chain::new(10, 0);
    assert_eq!(lower.meta().config.fee(), 10);
    let text = serde_json::to_string(lower.meta()).unwrap();
    assert_eq!(serde_json::to_value(lower.meta()).unwrap()["config"]["fee_micros"], json!("10"));
    serde_json::from_str::<Meta>(&text).unwrap().validate().unwrap();

    let plain = Chain::new(PROTOCOL_FEE, 0);
    let off = serde_json::to_string(plain.meta()).unwrap();
    let mark = r#""trusting_period_seconds":"604800""#;
    // A stored row that writes the protocol-4 fee out is not read back.
    let forged = off.replacen(mark, &format!(r#"{mark},"fee_micros":"1000""#), 1);
    assert_ne!(forged, off);
    assert!(serde_json::from_str::<Meta>(&forged).is_err());
    // One that names another fee is read, and refused: it is not the genesis
    // the network id was made from.
    let forged = off.replacen(mark, &format!(r#"{mark},"fee_micros":"7""#), 1);
    let meta: Meta = serde_json::from_str(&forged).unwrap();
    assert_eq!(meta.config.fee(), 7);
    assert!(meta.validate().is_err());
    assert_ne!(plain.engine.head().unwrap().unwrap().root, lower.engine.head().unwrap().unwrap().root);
}

// ---------------------------------------------------------------- what an action costs

#[test]
fn every_kind_of_action_costs_the_fee_or_nothing() {
    // Fees kept in the bank, and fees paid on to validators.
    for (fee, ppm) in [(10, 0), (10, ALL), (1, 0), (1, ALL), (999, 0), (999, 333_333)] {
        let mut chain = Chain::new(fee, ppm);
        assert_eq!(chain.fee, fee);
        let bank = chain.meta().bank;
        assert_eq!(every_kind_of_action(&mut chain), 41, "fee {fee}");
        // Nothing is left of what the protocol-4 rules were lent: the supply
        // rule held after every block, and the recount agrees.
        chain.engine.audit().unwrap();
        assert!(chain.meta().bank > bank);
        an_emptied_account_is_still_recovered(&mut chain);
    }
}

/// What must be in an account for an action, to the microsecond: one
/// microsecond less is refused on every path and leaves no trace.
fn the_fee_is_due_to_the_microsecond(fee: u64) {
    let mut chain = Chain::new(fee, 0);
    let registration = chain.meta().config.registration.fee_micros;
    let lent = PROTOCOL_FEE - fee;
    // Payments: account 4 on the fast path, account 5 through the protocol-4
    // rule adapter. Each holds 5,000 and one fee.
    chain.fund(&[
        (4, 5000 + fee),
        (5, 5000 + fee),
        // One microsecond short of the fee, or of the amount and the fee.
        (6, fee - 1),
        (7, fee - 1),
        (8, fee - 1),
        (9, 400_000 + fee - 1),
        (10, registration + fee - 1),
        (11, fee - 1),
    ]);
    for over in [1, 2, fee, lent, lent + 1, PROTOCOL_FEE - 1, PROTOCOL_FEE, PROTOCOL_FEE + 1, 5 * SECOND] {
        if over == 0 {
            continue;
        }
        chain.refuse(&chain.transfer(4, 1, 11, 5000 + over), "insufficient funds");
        chain.refuse(&chain.merchant(5, 1, 6, 11, 5000 + over), "insufficient funds");
    }
    chain.charges(SECOND, vec![chain.transfer(4, 1, 11, 5000), chain.merchant(5, 1, 6, 11, 5000)], 2 * fee, 0);
    assert_eq!((chain.balance(4), chain.balance(5)), (0, 0));

    // Actions that move nothing but the fee, and actions of the extensions.
    let delegate = |chain: &Chain| chain.legacy(9, 1, 10, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 400_000, min_shares: 1 }));
    chain.refuse(&chain.guardians(6, [4, 5, 7]), "insufficient funds for fee");
    chain.refuse(&chain.cancel_pending(7), "insufficient funds for fee");
    chain.refuse(&chain.secure(8, 500_000), "insufficient funds for fee");
    chain.refuse(&delegate(&chain), "insufficient liquid funds");
    chain.refuse(&chain.sponsor(10, 1, 202, "second"), "insufficient liquid funds");
    // Account 11 received the two payments above: it gives them back first.
    let received = chain.balance(11) - (fee - 1);
    chain.charges(SECOND, vec![chain.transfer(11, 1, 4, received - fee)], fee, 0);
    assert_eq!(chain.balance(11), fee - 1);
    chain.refuse(&chain.legacy(11, 1, 12, chain.device(11, 71)), "insufficient funds for fee");

    // One microsecond more, and each of them is accepted and leaves nothing.
    let txs: Vec<Vec<u8>> = (6..=11).enumerate().map(|(index, to)| chain.transfer(1, 1 + index as u64, to, 1)).collect();
    chain.charges(SECOND, txs, 6 * fee, 0);
    let txs = vec![
        chain.guardians(6, [4, 5, 7]),
        chain.cancel_pending(7),
        chain.secure(8, 500_000),
        delegate(&chain),
        chain.sponsor(10, 1, 202, "second"),
        chain.legacy(11, 1, 12, chain.device(11, 71)),
    ];
    chain.charges(SECOND, txs, 6 * fee, registration);
    for id in 5..=11 {
        assert_eq!(chain.balance(id), 0, "account {id}");
    }
    chain.engine.audit().unwrap();
}
#[test]
fn a_fee_of_ten_is_due_to_the_microsecond() {
    the_fee_is_due_to_the_microsecond(10);
}
#[test]
fn a_fee_of_one_is_due_to_the_microsecond() {
    the_fee_is_due_to_the_microsecond(1);
}
#[test]
fn a_fee_of_999_and_the_protocol_4_fee_are_due_to_the_microsecond() {
    the_fee_is_due_to_the_microsecond(999);
    the_fee_is_due_to_the_microsecond(PROTOCOL_FEE);
}

/// The protocol-4 rules charge 1,000 and are lent the difference to the fee
/// of the network while they run. Nothing of it can be paid out, kept or
/// used for a fee: an account that holds nothing can do only what is free.
fn what_the_protocol_4_rules_are_lent_cannot_be_spent(fee: u64) {
    let mut chain = Chain::new(fee, 0);
    let lent = PROTOCOL_FEE - fee;
    assert!(lent > 0);
    chain.fund(&[(4, 2000 + 2 * fee), (5, SECOND), (6, 2000 + 2 * fee), (7, SECOND), (9, 2 * (1 + fee)), (10, 2 * (1 + fee))]);
    // Account 6 names guardians, and they consent, while all can pay.
    chain.charges(SECOND, vec![chain.guardians(6, [4, 5, 7])], fee, 0);
    chain.charges(SECOND, vec![chain.consent(4, 1, 6, true), chain.consent(5, 1, 6, true), chain.consent(7, 1, 6, true)], 3 * fee, 0);
    assert_eq!((chain.balance(4), chain.balance(6)), (2000 + fee, 2000 + fee));

    // No amount above what the account holds less the fee can be paid,
    // whatever part of what is lent it would use.
    for amount in [2001, 2000 + fee, 2001 + fee, 2000 + lent, 2000 + fee + lent - 1, 2000 + fee + lent, 2001 + fee + lent, 2000 + PROTOCOL_FEE] {
        chain.refuse(&chain.transfer(4, 1, 11, amount), "insufficient funds");
        chain.refuse(&chain.merchant(4, 1, 5, 11, amount), "insufficient funds");
    }
    // Three payments of one account in one block, which holds what two of
    // them cost: what the first was lent is not there for the second.
    for (account, shop) in [(9, false), (10, true)] {
        let txs: Vec<Vec<u8>> = (1..=3)
            .map(|ahead| if shop { chain.merchant(account, ahead, account as u8 + 1, 11, 1) } else { chain.transfer(account, ahead, 11, 1) })
            .collect();
        let (height, time, signers, hash) = chain.next(SECOND);
        assert!(chain.engine.prepare(height, time, &txs, &signers, hash).is_err());
        assert!(chain.engine.prepare_reference(height, time, &txs, &signers, hash).is_err());
        let (_, kept) = chain.engine.prepare_filtered(height, time, &txs, &signers, 1 << 22, hash).unwrap();
        assert_eq!(kept, txs[..2]);
        chain.charges(SECOND, kept, 2 * fee, 0);
        assert_eq!(chain.balance(account), 0);
    }

    // Accounts 4 and 6 pay out all they hold.
    chain.empty(4, 5, 11);
    chain.empty(6, 7, 11);
    // With nothing, account 4 cannot do what costs the fee: what it is lent
    // is less than the protocol-4 rules charge.
    chain.refuse(&chain.transfer(4, 1, 11, 1), "insufficient funds");
    chain.refuse(&chain.merchant(4, 1, 5, 11, 1), "insufficient funds");
    chain.refuse(&chain.guardians(4, [5, 6, 7]), "insufficient funds for fee");
    chain.refuse(&chain.cancel_pending(4), "insufficient funds for fee");
    chain.refuse(&chain.legacy(4, 1, 5, chain.device(4, 72)), "insufficient funds for fee");
    chain.refuse(&chain.legacy(4, 1, 5, chain.claim(6, 232, 910)), "insufficient funds for fee");
    // What is free it can do, and it still holds nothing afterwards: its
    // guardian consent is withdrawn at no cost.
    chain.charges(SECOND, vec![chain.consent(4, 1, 6, false)], 0, 0);
    assert_eq!(chain.balance(4), 0);

    // A recovery of account 6, which holds nothing, is approved by its two
    // other guardians (they pay). The owner calls it off: free.
    let claim = chain.claim(6, 232, 911);
    chain.charges(SECOND, vec![chain.legacy(5, 1, 6, claim.clone()), chain.legacy(7, 1, 8, claim)], 2 * fee, 0);
    chain.refuse(&chain.transfer(6, 1, 11, 1), "frozen");
    chain.charges(SECOND, vec![chain.legacy(6, 1, 7, ActionPayload::CancelRecovery(ledger::CancelRecovery {}))], 0, 0);
    assert_eq!(chain.balance(6), 0);
    // Approved again, it waits its delay and the new key finishes it: free,
    // so that an account with nothing can be recovered.
    let claim = chain.claim(6, 233, 912);
    chain.charges(SECOND, vec![chain.legacy(5, 1, 6, claim.clone()), chain.legacy(7, 1, 8, claim)], 2 * fee, 0);
    chain.charges(40 * SECOND, vec![], 0, 0);
    let finish = chain.legacy(6, 1, 233, ActionPayload::FinalizeRecovery(ledger::FinalizeRecovery { recovery_id: hex::encode(sha(912)) }));
    chain.charges(SECOND, vec![finish], 0, 0);
    let row = chain.account(6);
    assert_eq!((row.balance, row.devices.len()), (0, 1));
    // The recovered account still cannot pay a fee out of what is lent.
    chain.refuse(&chain.pay(6, 1, 233, 11, 1), "insufficient funds");
    chain.refuse(&chain.legacy(6, 1, 233, ActionPayload::CancelPending(ledger::CancelPending {})), "insufficient funds for fee");
    chain.engine.audit().unwrap();
}
#[test]
fn what_a_fee_of_ten_leaves_to_be_lent_cannot_be_spent() {
    what_the_protocol_4_rules_are_lent_cannot_be_spent(10);
}
#[test]
fn what_a_fee_of_one_leaves_to_be_lent_cannot_be_spent() {
    what_the_protocol_4_rules_are_lent_cannot_be_spent(1);
}
#[test]
fn what_a_fee_of_999_leaves_to_be_lent_cannot_be_spent() {
    what_the_protocol_4_rules_are_lent_cannot_be_spent(999);
}

#[test]
fn the_daily_limit_of_a_secured_account_counts_the_amount_and_the_fee() {
    const LIMIT: u64 = 50_000;
    for fee in [10, 1, 999, PROTOCOL_FEE] {
        let mut chain = Chain::new(fee, 0);
        chain.fund(&[(8, SECOND), (9, SECOND), (10, SECOND)]);
        chain.charges(SECOND, vec![chain.secure(8, LIMIT), chain.secure(9, LIMIT), chain.secure(10, LIMIT)], 3 * fee, 0);
        let delegate = |chain: &Chain, amount: u64| chain.legacy(10, 1, 61, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount, min_shares: 1 }));
        // One microsecond above the limit, fee included: refused on the fast
        // path, in the rule adapter and in the staking extension.
        chain.refuse(&chain.pay(8, 1, 61, 11, LIMIT - fee + 1), "daily limit");
        chain.refuse(&chain.merchant(9, 1, 61, 11, LIMIT - fee + 1), "daily limit");
        chain.refuse(&delegate(&chain, LIMIT - fee + 1), "daily limit");
        // The amount that fits with its fee uses the limit up exactly.
        let txs = vec![chain.pay(8, 1, 61, 11, LIMIT - fee), chain.merchant(9, 1, 61, 11, LIMIT - fee), delegate(&chain, LIMIT - fee)];
        chain.charges(SECOND, txs, 3 * fee, 0);
        let now = chain.now();
        for account in [8, 9, 10] {
            let row = chain.security(account);
            assert_eq!((row.allowance_micros, row.allowance_elapsed_micros), (0, now), "fee {fee}, account {account}");
            assert_eq!(chain.balance(account), SECOND - fee - LIMIT);
        }
        // Nothing is left, not even for the smallest payment or for an
        // action that costs the fee alone.
        chain.refuse(&chain.pay(8, 1, 61, 11, 1), "daily limit");
        chain.refuse(&chain.merchant(9, 1, 61, 11, 1), "daily limit");
        chain.refuse(&chain.extension(8, 1, 61, security::LIMIT, json!({"daily_limit_micros": "40000"})), "daily limit");
        chain.engine.audit().unwrap();
    }
}

#[test]
fn fees_paid_on_to_validators_are_the_fee_times_the_actions() {
    for (fee, ppm) in [(10, ALL), (10, ALL / 2), (1, ALL), (1, ALL / 2), (999, ALL)] {
        let mut chain = Chain::new(fee, ppm);
        let registration = chain.meta().config.registration.fee_micros;
        // The bound of the row: a full block of actions at this fee.
        assert_eq!(fee_pool_limit(chain.meta()), 20_000 * fee * ppm / ALL);
        chain.fund(&[(4, SECOND), (5, SECOND), (6, SECOND), (7, SECOND), (8, SECOND), (9, SECOND)]);
        chain.charges(10 * SECOND, vec![], 0, 0);
        assert_eq!(chain.pool(), 0);
        let before: Vec<u64> = (0..4).map(|id| chain.balance(id)).collect();
        let txs = vec![
            chain.transfer(4, 1, 10, 1000),
            chain.merchant(5, 1, 6, 10, 1000),
            chain.guardians(6, [4, 5, 7]),
            chain.cancel_pending(7),
            chain.secure(8, 500_000),
            chain.sponsor(9, 1, 203, "third"),
        ];
        // `charges` checks the row: the validators' part of six fees. The
        // registration charge is no fee.
        chain.charges(10 * SECOND, txs, 6 * fee, registration);
        assert_eq!(chain.pool(), 6 * fee * ppm / ALL);
        chain.engine.audit().unwrap();
        // The next block carries the four signatures of that one: the fees
        // join the new time and are paid with it. What does not divide by
        // four stays in the bank.
        let bank = chain.meta().bank;
        chain.charges(10 * SECOND, vec![], 0, 0);
        let each = (10 * SECOND / 5 + 6 * fee * ppm / ALL) / 4;
        for id in 0..4usize {
            assert_eq!(chain.balance(id as u64), before[id] + TIME_REWARD + each, "fee {fee}, {ppm} ppm, owner {id}");
        }
        assert_eq!(chain.meta().bank, bank + 10 * SECOND - 4 * each);
        chain.engine.audit().unwrap();
    }
    // The protocol-4 fee keeps its bound.
    assert_eq!(fee_pool_limit(Chain::new(PROTOCOL_FEE, ALL).meta()), 20_000_000);
}

// ---------------------------------------------------------------- against a model

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
}

/// What the model knows of an account: all that decides whether its next
/// action is accepted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Holder {
    balance: u64,
    nonce: u64,
    epoch: u64,
}
#[derive(Clone, Copy, Debug)]
enum Does {
    /// A payment, plain or to a shop.
    Pays { to: u64, amount: u64 },
    /// `CancelPending`, or guardian recovery turned off: both cost the fee
    /// alone and move the authority epoch on.
    ChangesAuthority,
}
#[derive(Clone, Debug)]
struct Offer {
    raw: Vec<u8>,
    from: u64,
    nonce: u64,
    epoch: u64,
    does: Does,
}
/// The rule, written down without the engine: an action names the account's
/// next nonce and its authority epoch, and costs the fee of the network; a
/// payment moves its amount besides, to another account. Applies the offer
/// to the model if it is accepted.
fn accepted(model: &mut BTreeMap<u64, Holder>, offer: &Offer, fee: u64) -> bool {
    let mut payer = model[&offer.from];
    if offer.nonce != payer.nonce + 1 || offer.epoch != payer.epoch {
        return false;
    }
    payer.nonce += 1;
    match offer.does {
        Does::Pays { to, amount } => {
            let Some(cost) = amount.checked_add(fee) else { return false };
            if amount == 0 || to == offer.from || !model.contains_key(&to) || payer.balance < cost {
                return false;
            }
            payer.balance -= cost;
            model.get_mut(&to).unwrap().balance += amount;
        }
        Does::ChangesAuthority => {
            if payer.balance < fee {
                return false;
            }
            payer.balance -= fee;
            payer.epoch += 1;
        }
    }
    model.insert(offer.from, payer);
    true
}
/// One offer of an account, made on what the model says the account will be
/// when the offers before it have been judged: amounts are aimed at the
/// largest that can be paid, one microsecond more, and what the protocol-4
/// rules are lent on top.
fn offer(chain: &Chain, rng: &mut Rng, model: &BTreeMap<u64, Holder>) -> Offer {
    let from = 4 + rng.below(8);
    let to = 4 + (from - 4 + 1 + rng.below(7)) % 8;
    let holder = model[&from];
    let (fee, signer) = (chain.fee, from as u8 + 1);
    let most = holder.balance.saturating_sub(fee);
    let amount = match rng.below(9) {
        0 => most,
        1 => most + 1,
        2 => holder.balance,
        3 => most + (PROTOCOL_FEE - fee),
        4 => holder.balance + PROTOCOL_FEE,
        _ => 1 + rng.below((holder.balance / 3).max(2)),
    };
    let (mut nonce, mut epoch) = (holder.nonce + 1, holder.epoch);
    let pays = Does::Pays { to, amount };
    let (does, shop) = match rng.below(20) {
        0..=8 => (pays, false),
        9..=14 => (pays, true),
        15 | 16 => (Does::ChangesAuthority, false),
        17 => (Does::ChangesAuthority, true),
        18 => {
            // A nonce too far, or an authority epoch not yet reached.
            nonce += 1;
            (pays, rng.below(2) == 0)
        }
        _ => {
            epoch += 1;
            (pays, rng.below(2) == 0)
        }
    };
    let payload = match (does, shop) {
        (Does::Pays { to, amount }, false) => ActionPayload::Transfer(ledger::Transfer { to, amount }),
        (Does::Pays { to, amount }, true) => chain.order(nonce, to, amount),
        (Does::ChangesAuthority, false) => ActionPayload::CancelPending(ledger::CancelPending {}),
        (Does::ChangesAuthority, true) => ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![], threshold: 0, delay_seconds: 0 }),
    };
    Offer { raw: chain.signed(from, nonce, epoch, signer, payload), from, nonce, epoch, does }
}

fn random_blocks_cost_what_the_model_says(fee: u64, seed: u64, rounds: u64) {
    let mut chain = Chain::new(fee, 0);
    let mut rng = Rng(seed);
    let (mut offered, mut included, mut edges, mut refused_edges) = (0u64, 0u64, 0u64, 0u64);
    for round in 0..rounds {
        if round % 16 == 0 {
            // The eight accounts get a little to act with, again and again:
            // some of them just a few fees.
            let amounts: Vec<(u64, u64)> = (4..12).map(|id| (id, 1 + fee * rng.below(12) + rng.below(700))).collect();
            chain.fund(&amounts);
        }
        let read = |chain: &Chain| -> BTreeMap<u64, Holder> {
            (4..12)
                .map(|id| {
                    let row = chain.account(id);
                    (id, Holder { balance: row.balance, nonce: row.nonce, epoch: row.auth_epoch })
                })
                .collect()
        };
        let start = read(&chain);
        let mut model = start.clone();
        let mut offers: Vec<(Offer, bool)> = Vec::new();
        for _ in 0..rng.below(11) {
            let next = if !offers.is_empty() && rng.below(12) == 0 {
                // The same bytes a second time.
                offers[rng.below(offers.len() as u64) as usize].0.clone()
            } else {
                offer(&chain, &mut rng, &model)
            };
            let before = model[&next.from];
            let verdict = accepted(&mut model, &next, fee);
            if let Does::Pays { amount, .. } = next.does {
                let exact = amount.checked_add(fee) == Some(before.balance);
                edges += u64::from(verdict && exact);
                refused_edges += u64::from(!verdict && amount.checked_add(fee) == before.balance.checked_add(1));
            }
            offers.push((next, verdict));
        }
        let raws: Vec<Vec<u8>> = offers.iter().map(|(offer, _)| offer.raw.clone()).collect();
        let expected: Vec<Vec<u8>> = offers.iter().filter(|(_, verdict)| *verdict).map(|(offer, _)| offer.raw.clone()).collect();
        offered += raws.len() as u64;
        included += expected.len() as u64;

        let delta = 1 + rng.below(9 * SECOND);
        let (height, time, signers, hash) = chain.next(delta);
        let none: [Vec<u8>; 0] = [];
        let empty = chain.engine.prepare(height, time, &none, &signers, hash).unwrap();
        let (proposed, kept) = chain.engine.prepare_filtered(height, time, &raws, &signers, 1 << 22, hash).unwrap();
        assert_eq!(kept, expected, "fee {fee}, round {round}: the proposer and the model disagree on {offers:?}");
        let strict = chain.engine.prepare(height, time, &kept, &signers, hash).unwrap();
        let reference = chain.engine.prepare_reference(height, time, &kept, &signers, hash).unwrap();
        assert_eq!(strict.root, proposed.root, "fee {fee}, round {round}: validator and proposer disagree");
        assert_eq!(reference.root, proposed.root, "fee {fee}, round {round}: fast path and reference disagree");
        let whole = kept.len() == raws.len();
        assert_eq!(chain.engine.prepare(height, time, &raws, &signers, hash).is_ok(), whole);
        assert_eq!(chain.engine.prepare_reference(height, time, &raws, &signers, hash).is_ok(), whole);
        // The reference path, which has no way to leave a transaction out,
        // refuses each offer the model refuses where it stands: after the
        // accepted offers before it.
        let mut prefix: Vec<Vec<u8>> = Vec::new();
        let mut checked = 0;
        for (offer, verdict) in &offers {
            if *verdict {
                prefix.push(offer.raw.clone());
            } else if checked < 3 {
                checked += 1;
                let mut with = prefix.clone();
                with.push(offer.raw.clone());
                assert!(
                    chain.engine.prepare_reference(height, time, &with, &signers, hash).is_err(),
                    "fee {fee}, round {round}: the reference path accepted {offer:?}"
                );
            }
        }
        // The fees of the block, and nothing else, reached the bank.
        assert_eq!(proposed.meta.bank - empty.meta.bank, fee * kept.len() as u64, "fee {fee}, round {round}: bank");
        chain.engine.commit(proposed, hash).unwrap();
        assert_eq!(chain.supply(), chain.now(), "fee {fee}, round {round}: supply");
        assert_eq!(read(&chain), model, "fee {fee}, round {round}: accounts after {offers:?}");
        let paid: u64 = (4..12).map(|id| start[&id].balance).sum::<u64>() - (4..12).map(|id| model[&id].balance).sum::<u64>();
        assert_eq!(paid, fee * kept.len() as u64);
    }
    chain.engine.audit().unwrap();
    println!("fee {fee}: {included} of {offered} offers included, {edges} that left nothing, {refused_edges} one microsecond short");
    assert!(included > rounds && included < offered, "{included} of {offered}");
    assert!(edges > 5 && refused_edges > 5, "{edges} exact payments, {refused_edges} refused by one microsecond");
}
#[test]
fn random_blocks_at_a_fee_of_ten_cost_what_the_model_says() {
    random_blocks_cost_what_the_model_says(10, 0x5eed_fee0_0010, 90);
}
#[test]
fn random_blocks_at_a_fee_of_one_cost_what_the_model_says() {
    random_blocks_cost_what_the_model_says(1, 0x5eed_fee0_0001, 90);
}
#[test]
fn random_blocks_at_a_fee_of_999_cost_what_the_model_says() {
    random_blocks_cost_what_the_model_says(999, 0x5eed_fee0_0999, 90);
}
#[test]
fn random_blocks_at_the_protocol_4_fee_cost_what_the_model_says() {
    random_blocks_cost_what_the_model_says(PROTOCOL_FEE, 0x5eed_fee0_1000, 90);
}

// ---------------------------------------------------------------- mempool, storage, node

#[test]
fn the_mempool_admits_what_the_fee_of_the_network_pays_for() {
    let mut chain = Chain::new(10, 0);
    // Account 4 holds what two payments of five cost, account 5 one
    // microsecond less than a payment to a shop costs.
    chain.fund(&[(4, 2 * (5 + 10)), (5, 5 + 10 - 1), (7, 9)]);
    let mut pending = chain.engine.check_state().unwrap();
    let unknown = SigStatus::Unknown;
    assert_eq!(pending.rows(), 0);
    pending.admit(&chain.transfer(4, 1, 6, 5), unknown).unwrap();
    pending.admit(&chain.transfer(4, 2, 6, 5), unknown).unwrap();
    let refusal = format!("{:#}", pending.admit(&chain.transfer(4, 3, 6, 5), unknown).unwrap_err());
    assert!(refusal.contains("insufficient funds"), "{refusal}");
    assert_eq!(pending.rows(), 2);
    // Refused by the rule adapter, one microsecond short: nothing of what
    // it read, and nothing of what it was lent, stays behind.
    assert!(pending.admit(&chain.merchant(5, 1, 6, 8, 5), unknown).is_err());
    assert!(pending.admit(&chain.cancel_pending(7), unknown).is_err());
    assert_eq!(pending.rows(), 2);
    // Account 6 pays the fee of its own action out of the two payments that
    // wait before it.
    assert_eq!(chain.balance(6), 0);
    pending.admit(&chain.cancel_pending(6), unknown).unwrap();
    // Nothing is left of the ten for a payment with its next nonce and its
    // new authority epoch.
    let next = chain.signed(6, 2, 1, 7, ActionPayload::Transfer(ledger::Transfer { to: 8, amount: 1 }));
    let refusal = format!("{:#}", pending.admit(&next, unknown).unwrap_err());
    assert!(refusal.contains("insufficient funds"), "{refusal}");
    // What was admitted is what a block includes.
    let txs = vec![chain.transfer(4, 1, 6, 5), chain.transfer(4, 2, 6, 5), chain.cancel_pending(6)];
    chain.charges(SECOND, txs, 30, 0);
    assert_eq!((chain.balance(4), chain.balance(6)), (0, 0));
}

#[test]
fn a_saved_state_is_read_back_with_its_fee() {
    let mut chain = Chain::new(10, ALL);
    chain.fund(&[(4, SECOND)]);
    let cancel = chain.legacy(4, 2, 5, ActionPayload::CancelPending(ledger::CancelPending {}));
    chain.charges(SECOND, vec![chain.transfer(4, 1, 5, 1000), cancel], 20, 0);
    let (root, network, pool) = (chain.engine.head().unwrap().unwrap().root, chain.network.clone(), chain.pool());
    assert_eq!(pool, 20);
    chain.engine.store().write_snapshot(chain.engine.version().unwrap()).unwrap();
    let Chain { dir, engine, .. } = chain;
    drop(engine);

    let engine = open(dir.path());
    let meta = engine.meta().unwrap();
    assert_eq!((meta.config.fee(), meta.config.fee_micros), (10, 10));
    assert_eq!(meta.network_id, network);
    assert_eq!(engine.head().unwrap().unwrap().root, root);
    engine.audit().unwrap();
    // The chain goes on at the same fee.
    let mut chain = Chain { dir, engine, network, fee: 10, roots: Sha256::new() };
    assert_eq!(chain.pool(), pool);
    let before = chain.balance(4);
    chain.charges(SECOND, vec![chain.transfer(4, 1, 5, 7)], 10, 0);
    assert_eq!(chain.balance(4), before - 17);
    chain.engine.audit().unwrap();
}

fn timestamp(micros: i64) -> Option<Timestamp> {
    Some(Timestamp { seconds: micros / 1_000_000, nanos: ((micros % 1_000_000) * 1000) as i32 })
}
/// The first request a node receives, with this application state.
fn init(genesis: &Genesis, app_state: &Value) -> RequestInitChain {
    RequestInitChain {
        chain_id: genesis.ledger.chain_id.clone(),
        time: timestamp(genesis.ledger.genesis_time_micros),
        app_state_bytes: serde_json::to_vec(app_state).unwrap().into(),
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

/// A node driven as the consensus engine drives it: every block carries the
/// signatures of all four validators on the block before.
struct Node {
    app: App,
    genesis: Genesis,
    height: i64,
    elapsed: u64,
}
impl Node {
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let height = self.height + 1;
        let votes = self
            .genesis
            .validators
            .iter()
            .map(|validator| VoteInfo {
                validator: Some(Validator {
                    address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20].to_vec().into(),
                    power: self.genesis.profile.genesis_power() as i64,
                }),
                block_id_flag: BlockIdFlag::Commit as i32,
            })
            .collect();
        let request = RequestFinalizeBlock {
            height,
            time: timestamp(self.genesis.ledger.genesis_time_micros + (self.elapsed + delta) as i64),
            hash: sha(height as u64).to_vec().into(),
            txs: txs.into_iter().map(Into::into).collect(),
            decided_last_commit: (height > 1).then(|| CommitInfo { round: 0, votes }),
            ..Default::default()
        };
        let proposal = RequestProcessProposal {
            txs: request.txs.clone(),
            proposed_last_commit: request.decided_last_commit.clone(),
            misbehavior: request.misbehavior.clone(),
            hash: request.hash.clone(),
            height: request.height,
            time: request.time.clone(),
            next_validators_hash: request.next_validators_hash.clone(),
            proposer_address: request.proposer_address.clone(),
        };
        let accept = response_process_proposal::ProposalStatus::Accept as i32;
        assert_eq!(self.app.process_proposal(proposal).status, accept, "proposal rejected at {height}");
        self.app.try_finalize(request).unwrap();
        self.app.try_commit().unwrap();
        self.height += 1;
        self.elapsed += delta;
    }
    fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        let response = self.app.query(RequestQuery {
            data: serde_json::to_vec(&vec![hex::encode(key)]).unwrap().into(),
            path: "/compact-proof".into(),
            height: 0,
            prove: false,
        });
        assert_eq!(response.code, 0, "{}", response.log);
        let view: Value = serde_json::from_slice(&response.value).unwrap();
        view["entries"][0]["value_b64"].as_str().map(|text| {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            STANDARD.decode(text).unwrap()
        })
    }
    fn balance(&self, id: u64) -> u64 {
        serde_json::from_slice::<Account>(&self.row(&account_key(id)).expect("account")).unwrap().balance
    }
}

#[test]
fn a_node_starts_a_network_with_a_lower_fee_and_reads_no_other_form() {
    let genesis = network(10, ALL);
    let state = serde_json::to_value(&genesis).unwrap();
    assert_eq!(state["fee_micros"], json!("10"));
    for refused in [json!("1000"), json!("0"), json!("1001"), json!(10), json!("010")] {
        let mut forged = state.clone();
        forged["fee_micros"] = refused.clone();
        let dir = tempfile::tempdir().unwrap();
        let app = App::open(dir.path().join("node.db")).unwrap();
        assert!(app.try_init(init(&genesis, &forged)).is_err(), "a node started with fee {refused}");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let app = App::open(&path).unwrap();
    app.try_init(init(&genesis, &state)).unwrap();
    let mut node = Node { app, genesis: genesis.clone(), height: 0, elapsed: 0 };
    node.block(SECOND, vec![]);
    for _ in 0..3 {
        node.block(60 * SECOND, vec![]);
    }
    // A payment of account 0: admitted by the mempool, included, and it
    // costs its amount and ten.
    let before = (node.balance(0), node.balance(5));
    let payment = |nonce: u64, amount: u64| {
        ledger::sign_action(
            &Action {
                network_id: genesis.network_id().unwrap(),
                from: 0,
                nonce,
                auth_epoch: 0,
                public_key: pk(1),
                payload: ActionPayload::Transfer(ledger::Transfer { to: 5, amount }),
                signature: vec![],
            },
            &key(1),
        )
        .unwrap()
    };
    // The mempool decides on the last block: a payment of all the account
    // holds there less nine, one microsecond more than the fee leaves, is
    // not admitted.
    let admitted = node.app.check_batch(
        [payment(1, before.0 - 10 + 1), payment(1, SECOND)]
            .into_iter()
            .map(|tx| RequestCheckTx { tx: tx.into(), r#type: 0 })
            .collect(),
    );
    assert_eq!((admitted[0].code, admitted[1].code), (1, 0), "{}", admitted[0].log);
    node.block(10 * SECOND, vec![payment(1, SECOND)]);
    assert_eq!(node.balance(0), before.0 + TIME_REWARD - SECOND - 10);
    assert_eq!(node.balance(5), before.1 + SECOND);
    let owed: String = serde_json::from_slice(&node.row(FEE_POOL_KEY).expect("fees owed")).unwrap();
    assert_eq!(owed, "10");
    // Stopped and started again, the node has the same head and the same fee.
    node.app.snapshot().unwrap().expect("a snapshot");
    let head = node.app.head().unwrap().unwrap();
    drop(node);
    let app = App::open(&path).unwrap();
    assert_eq!(app.head().unwrap().unwrap(), head);
    drop(app);
    let engine = Engine::open_with_history(Store::open(path.with_extension("v5state")).unwrap(), path.with_extension("history")).unwrap();
    assert_eq!(engine.meta().unwrap().config.fee(), 10);
    assert_eq!(engine.meta().unwrap().network_id, genesis.network_id().unwrap());
    assert!(engine.audit().unwrap().history_archive_verified);
}
