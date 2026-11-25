//! Account security rules on the real engine: what each kind of key can and
//! cannot do, alone and together, including when it has been stolen.
//!
//! Every accepted block is also executed with the engine's fast paths off, and
//! the two results must have the same root.
mod common;
use common::*;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use timecurrency_node::ledger::{self, Account, ActionPayload};
use timecurrency_v5::engine::{Engine, account_key};
use timecurrency_v5::security::{self, Role, Security};
use timecurrency_v5::sigcache::SigStatus;
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
const FEE: u64 = ledger::FEE_MICROS;
const LIMIT: u64 = 500_000;
const DELAY: u64 = 60;
const FREEZE: u64 = 120;

// Keys of the account under test (account 5, whose protocol-4 key is seed 6).
const ME: u64 = 5;
const OLD: u8 = 6;
const SIGNIN: u8 = 60;
const SPEND: u8 = 61;
const SHEET: u8 = 62;
const PHRASE: u8 = 63;
const FRIEND: u8 = 64;

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Chain {
    /// A chain on which the four validator owners have earned for a while and
    /// account 5 holds 20 seconds.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis_v5()).unwrap();
        let mut chain = Self { _dir: dir, engine };
        for _ in 0..40 {
            chain.block(60 * SECOND, vec![]);
        }
        for owner in 0..4u64 {
            let row = chain.account(owner);
            chain.accept(transfer(&row, owner as u8 + 1, ME, 5 * SECOND));
        }
        assert_eq!(chain.account(ME).balance, 20 * SECOND);
        chain
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
    fn security(&self, id: u64) -> Option<Security> {
        self.row(&security::key(id))
            .map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn next(&self, delta: u64) -> (i64, i64, Vec<String>, [u8; 32]) {
        let meta = self.engine.meta().unwrap();
        let eligible = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        (
            meta.height + 1,
            meta.time_micros + delta as i64,
            eligible,
            sha(meta.height as u64 + 1),
        )
    }
    /// Offers `txs` to a proposer, commits what it keeps and returns that.
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let (height, time, eligible, hash) = self.next(delta);
        let (prepared, kept) = self
            .engine
            .prepare_filtered(height, time, &txs, &eligible, 1 << 20, hash)
            .unwrap();
        let strict = self
            .engine
            .prepare(height, time, &kept, &eligible, hash)
            .unwrap();
        let reference = self
            .engine
            .prepare_reference(height, time, &kept, &eligible, hash)
            .unwrap();
        assert_eq!(strict.root, prepared.root, "validator and proposer disagree");
        assert_eq!(reference.root, prepared.root, "fast path and reference disagree");
        self.engine.commit(prepared, hash).unwrap();
        kept
    }
    fn wait(&mut self, seconds: u64) {
        self.block(seconds * SECOND, vec![]);
    }
    #[track_caller]
    fn accept(&mut self, tx: Vec<u8>) {
        let (height, time, eligible, hash) = self.next(SECOND);
        if let Err(error) = self.engine.prepare(height, time, &[&tx], &eligible, hash) {
            panic!("refused: {error:#}");
        }
        assert_eq!(self.block(SECOND, vec![tx.clone()]), vec![tx]);
    }
    /// The transaction is refused by a validator, by a proposer and by the
    /// reference path, and the reason names `why`.
    #[track_caller]
    fn refuse(&mut self, tx: Vec<u8>, why: &str) {
        let (height, time, eligible, hash) = self.next(SECOND);
        let error = match self.engine.prepare(height, time, &[&tx], &eligible, hash) {
            Ok(_) => panic!("accepted, expected a refusal naming: {why}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains(why), "refused for another reason: {error}");
        assert!(
            self.engine
                .prepare_reference(height, time, &[&tx], &eligible, hash)
                .is_err(),
            "reference path accepted"
        );
        let (_, kept) = self
            .engine
            .prepare_filtered(height, time, &[&tx], &eligible, 1 << 20, hash)
            .unwrap();
        assert!(kept.is_empty(), "proposer kept a refused transaction");
    }
    fn me(&self) -> Account {
        self.account(ME)
    }
    fn mine(&self) -> Security {
        self.security(ME).expect("account 5 is secured")
    }
}

fn accepts(seed: u8, account: u64, role: Role) -> String {
    hex::encode(
        key(seed)
            .sign(&security::key_message(&network_id(), account, role, &pk(seed)).unwrap())
            .to_bytes(),
    )
}
fn role_name(role: Role) -> &'static str {
    match role {
        Role::Signin => "signin",
        Role::Spend => "spend",
        Role::Recover => "recover",
    }
}
/// A key that joins the set: it carries its holder's acceptance.
fn joins(seed: u8, account: u64, role: Role) -> Value {
    json!({"public_key": pk(seed), "role": role_name(role), "proof": accepts(seed, account, role)})
}
/// A key that is already on the account in this role.
fn stays(seed: u8, role: Role) -> Value {
    json!({"public_key": pk(seed), "role": role_name(role)})
}
/// The one accepted form of a list of keys: sorted by key.
fn sorted(mut keys: Vec<Value>) -> Value {
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    json!(keys)
}
fn policy(threshold: u64, limit: u64) -> Value {
    json!({"threshold": threshold.to_string(), "daily_limit_micros": limit.to_string(), "delay_seconds": DELAY.to_string(), "freeze_seconds": FREEZE.to_string()})
}
/// One sign-in key, one spend key, three recovery keys (sheet, passphrase, a
/// friend), two proofs needed.
fn standard_keys() -> Value {
    sorted(vec![
        joins(SIGNIN, ME, Role::Signin),
        joins(SPEND, ME, Role::Spend),
        joins(SHEET, ME, Role::Recover),
        joins(PHRASE, ME, Role::Recover),
        joins(FRIEND, ME, Role::Recover),
    ])
}
fn secured() -> Chain {
    let mut chain = Chain::new();
    let row = chain.me();
    chain.accept(extension(
        &row,
        OLD,
        security::SECURE,
        json!({"keys": standard_keys(), "policy": policy(2, LIMIT)}),
    ));
    chain
}
fn send(chain: &Chain, signer: u8, to: u64, amount: u64) -> Vec<u8> {
    transfer(&chain.me(), signer, to, amount)
}
/// An action of account 5 that takes its next nonce.
fn act(chain: &Chain, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    extension(&chain.me(), signer, kind, payload)
}
fn request(chain: &Chain, signer: u8, to: u64, amount: u64) -> Vec<u8> {
    act(chain, signer, security::PAYMENT, json!({"type": "request", "to": to.to_string(), "amount": amount.to_string()}))
}
fn execute(chain: &Chain, signer: u8, id: u64) -> Vec<u8> {
    act(chain, signer, security::PAYMENT, json!({"type": "execute", "id": id.to_string()}))
}
fn set_limit(chain: &Chain, signer: u8, limit: u64) -> Vec<u8> {
    act(chain, signer, security::LIMIT, json!({"daily_limit_micros": limit.to_string()}))
}
fn signin_keys(chain: &Chain, signer: u8, add: &[u8], remove: &[u8]) -> Vec<u8> {
    let mut add: Vec<Value> = add.iter().map(|seed| json!({"public_key": pk(*seed), "proof": accepts(*seed, ME, Role::Signin)})).collect();
    add.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    let mut remove: Vec<String> = remove.iter().map(|seed| pk(*seed)).collect();
    remove.sort();
    act(chain, signer, security::SIGNIN, json!({"add": add, "remove": remove}))
}
/// A protective action of account 5: no nonce, no authority epoch.
fn guard(signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    guard_of(ME, signer, kind, payload)
}
fn guard_of(account: u64, signer: u8, kind: u8, payload: Value) -> Vec<u8> {
    timecurrency_v5::wire::sign(&network_id(), account, 0, 0, kind, &payload, &key(signer)).unwrap()
}
fn freeze(chain: &Chain, signer: u8) -> Vec<u8> {
    freeze_until(chain, signer, chain.now() + 600 * SECOND)
}
/// A freeze for the account as it is now, valid until `expires`.
fn freeze_until(chain: &Chain, signer: u8, expires: u64) -> Vec<u8> {
    let mine = chain.mine();
    guard(signer, security::FREEZE, json!({"freezes": mine.freezes.to_string(), "version": mine.version.to_string(), "expires_elapsed_micros": expires.to_string()}))
}
fn refusal(result: anyhow::Result<()>) -> String {
    format!("{:#}", result.expect_err("admitted"))
}
fn finalize(chain: &Chain, signer: u8) -> Vec<u8> {
    guard(signer, security::FINALIZE, json!({"version": chain.mine().version.to_string()}))
}
fn cancel(signer: u8, what: &str, id: u64) -> Vec<u8> {
    guard(signer, security::CANCEL, json!({"type": what, "id": id.to_string()}))
}
fn unfreeze(chain: &Chain) -> Value {
    json!({"type": "unfreeze", "freezes": chain.mine().freezes.to_string()})
}
fn pay(to: u64, amount: u64) -> Value {
    json!({"type": "pay", "to": to.to_string(), "amount": amount.to_string()})
}
/// A root action for account 5 submitted by `sender`, approved by `approvers`.
fn root(chain: &Chain, sender: u8, approvers: &[u8], operation: Value) -> Vec<u8> {
    root_for(sender, approvers, operation, chain.mine().version, chain.now() + 3600 * SECOND)
}
fn approvals(account: u64, approvers: &[u8], operation: &Value, version: u64, expires: u64) -> Vec<Value> {
    let mut keys: Vec<(String, u8)> = approvers.iter().map(|seed| (pk(*seed), *seed)).collect();
    keys.sort();
    let names: Vec<&str> = keys.iter().map(|(public_key, _)| public_key.as_str()).collect();
    let message = security::root_message(&network_id(), account, version, expires, operation, &names).unwrap();
    keys.iter()
        .map(|(public_key, seed)| json!({"public_key": public_key, "signature": hex::encode(key(*seed).sign(&message).to_bytes())}))
        .collect()
}
fn root_for(sender: u8, approvers: &[u8], operation: Value, version: u64, expires: u64) -> Vec<u8> {
    let approvals = approvals(ME, approvers, &operation, version, expires);
    guard(sender, security::ROOT, json!({"op": operation, "expires_elapsed_micros": expires.to_string(), "approvals": approvals}))
}
/// A replacement that keeps everything except the spend key.
fn new_spend_key(seed: u8) -> Value {
    json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin),
        joins(seed, ME, Role::Spend),
        stays(SHEET, Role::Recover),
        stays(PHRASE, Role::Recover),
        stays(FRIEND, Role::Recover),
    ])})
}
fn roles(row: &Account) -> Vec<(String, Option<Role>)> {
    row.devices
        .iter()
        .map(|device| (device.public_key.clone(), Role::of(device)))
        .collect()
}
fn has_key(chain: &Chain, seed: u8) -> bool {
    chain.me().devices.iter().any(|device| device.public_key == pk(seed))
}

#[test]
fn adopting_the_rules_gives_every_key_one_role() {
    let mut chain = Chain::new();
    let row = chain.me();
    let two = |a: Value, b: Value, c: Value| sorted(vec![a, b, c]);
    // Refused set-ups, each for its own reason.
    let cases = [
        (json!({"keys": standard_keys(), "policy": policy(1, LIMIT)}), "threshold is at least two"),
        (
            json!({"keys": sorted(vec![joins(SPEND, ME, Role::Spend), joins(SHEET, ME, Role::Recover)]), "policy": policy(2, LIMIT)}),
            "threshold is at least two and at most the number of recovery keys",
        ),
        (
            json!({"keys": sorted(vec![joins(SHEET, ME, Role::Recover), joins(PHRASE, ME, Role::Recover)]), "policy": policy(2, LIMIT)}),
            "at least one spend key",
        ),
        (
            json!({"keys": two(stays(SPEND, Role::Spend), joins(SHEET, ME, Role::Recover), joins(PHRASE, ME, Role::Recover)), "policy": policy(2, LIMIT)}),
            "must carry its holder's acceptance",
        ),
        (
            // An acceptance given for another role, or for another account.
            json!({"keys": two(json!({"public_key": pk(SPEND), "role": "spend", "proof": accepts(SPEND, ME, Role::Recover)}), joins(SHEET, ME, Role::Recover), joins(PHRASE, ME, Role::Recover)), "policy": policy(2, LIMIT)}),
            "signature does not verify",
        ),
        (
            json!({"keys": two(joins(SPEND, 6, Role::Spend), joins(SHEET, ME, Role::Recover), joins(PHRASE, ME, Role::Recover)), "policy": policy(2, LIMIT)}),
            "signature does not verify",
        ),
        (
            // The same key in two roles.
            json!({"keys": two(joins(SPEND, ME, Role::Spend), joins(SPEND, ME, Role::Recover), joins(PHRASE, ME, Role::Recover)), "policy": policy(2, LIMIT)}),
            "keys must be distinct",
        ),
        (
            json!({"keys": standard_keys(), "policy": {"threshold": "2", "daily_limit_micros": "1", "delay_seconds": "29", "freeze_seconds": "120"}}),
            "waiting periods",
        ),
        (
            // Every key of the first set accepts its role, sign-in keys included.
            json!({"keys": sorted(vec![stays(SIGNIN, Role::Signin), joins(SPEND, ME, Role::Spend), joins(SHEET, ME, Role::Recover), joins(PHRASE, ME, Role::Recover)]), "policy": policy(2, LIMIT)}),
            "must carry its holder's acceptance",
        ),
    ];
    for (payload, why) in cases {
        chain.refuse(extension(&row, OLD, security::SECURE, payload), why);
    }
    // One accepted form: keys in order, the policy as an object, no null.
    let mut reversed = standard_keys().as_array().unwrap().clone();
    reversed.reverse();
    chain.refuse(extension(&row, OLD, security::SECURE, json!({"keys": reversed, "policy": policy(2, LIMIT)})), "keys must be distinct, sorted");
    chain.refuse(
        extension(&row, OLD, security::SECURE, json!({"keys": standard_keys(), "policy": ["2", LIMIT.to_string(), "60", "120"]})),
        "one accepted form",
    );
    let mut with_null = standard_keys().as_array().unwrap().clone();
    with_null[0]["proof"] = Value::Null;
    chain.refuse(extension(&row, OLD, security::SECURE, json!({"keys": with_null, "policy": policy(2, LIMIT)})), "one accepted form");
    // Only the account's own full key can adopt the rules.
    chain.refuse(
        extension(&row, SPEND, security::SECURE, json!({"keys": standard_keys(), "policy": policy(2, LIMIT)})),
        "only a key with full authority",
    );
    chain.accept(extension(&row, OLD, security::SECURE, json!({"keys": standard_keys(), "policy": policy(2, LIMIT)})));

    let row = chain.me();
    let mut expected = vec![
        (pk(SIGNIN), Some(Role::Signin)),
        (pk(SPEND), Some(Role::Spend)),
        (pk(SHEET), Some(Role::Recover)),
        (pk(PHRASE), Some(Role::Recover)),
        (pk(FRIEND), Some(Role::Recover)),
    ];
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(roles(&row), expected);
    assert_eq!(row.balance, 20 * SECOND - FEE);
    let mine = chain.mine();
    assert_eq!((mine.version, mine.policy.threshold, mine.allowance_micros), (1, 2, LIMIT));
    // The old all-powerful key is gone; the rules cannot be adopted twice.
    chain.refuse(send(&chain, OLD, 6, 1000), "device is not authorized");
    chain.refuse(
        act(&chain, SPEND, security::SECURE, json!({"keys": standard_keys(), "policy": policy(2, LIMIT)})),
        "already secured",
    );
    chain.accept(send(&chain, SPEND, 6, 1000));
    chain.engine.audit().unwrap();
}

#[test]
fn a_sign_in_key_signs_nothing_the_chain_accepts() {
    let mut chain = secured();
    let no = "a spend or recovery key of this account is required";
    chain.refuse(send(&chain, SIGNIN, 6, 1000), "device permission denied");
    chain.refuse(signin_keys(&chain, SIGNIN, &[], &[SIGNIN]), "a spend key is required");
    chain.refuse(request(&chain, SIGNIN, 6, 5), "a spend key is required");
    chain.refuse(set_limit(&chain, SIGNIN, 1), "a spend key is required");
    let row = chain.me();
    chain.refuse(
        legacy(ME, row.nonce + 1, row.auth_epoch, SIGNIN, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 50_000, min_shares: 1 })),
        "spending device required",
    );
    // Not even what protects. A stolen sign-in key must not be able to stop
    // the account, or to stand in the way of the keys above it.
    chain.refuse(freeze(&chain, SIGNIN), no);
    chain.accept(request(&chain, SPEND, 6, 4 * SECOND));
    chain.refuse(cancel(SIGNIN, "payment", 1), no);
    // It approves no root operation, and cannot hand in one others approved.
    chain.refuse(
        root(&chain, SHEET, &[SIGNIN, SHEET], new_spend_key(70)),
        "only spend and recovery keys approve",
    );
    chain.refuse(root(&chain, SIGNIN, &[SPEND, SHEET], new_spend_key(70)), no);
    // Nor does it finish a replacement, although it is a key of the new set.
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)));
    chain.wait(DELAY);
    chain.refuse(finalize(&chain, SIGNIN), "only a spend or recovery key of the new set");
    chain.accept(finalize(&chain, FRIEND));
    assert!(has_key(&chain, 70) && has_key(&chain, SIGNIN));
    // A key that is not on the account can do none of it either.
    chain.refuse(freeze(&chain, 99), no);
    chain.refuse(cancel(99, "payment", 1), no);
    chain.engine.audit().unwrap();
}

#[test]
fn a_spend_or_recovery_key_freezes_and_two_proofs_lift_it() {
    let mut chain = secured();
    let before = chain.me().balance;
    chain.accept(freeze(&chain, FRIEND));
    assert_eq!(chain.me().balance, before - FEE);
    let mine = chain.mine();
    assert_eq!(mine.frozen_until_elapsed_micros, chain.now() + FREEZE * SECOND);
    assert_eq!(mine.freezes, 1);
    // While frozen a spend key can do nothing that costs the account, and
    // the sign-in keys stay as they are.
    chain.refuse(send(&chain, SPEND, 6, 1000), "account is frozen");
    chain.refuse(request(&chain, SPEND, 6, 5), "account is frozen");
    chain.refuse(signin_keys(&chain, SPEND, &[70], &[]), "account is frozen");
    chain.refuse(signin_keys(&chain, SPEND, &[], &[SIGNIN]), "account is frozen");
    chain.refuse(set_limit(&chain, SPEND, 1), "account is frozen");
    // The freeze cannot be renewed at once, by any key.
    chain.refuse(freeze(&chain, FRIEND), "already frozen");
    chain.refuse(freeze(&chain, SPEND), "already frozen");
    // The owner, with the spend key and one recovery key, replaces the
    // recovery key that froze the account, and that ends the freeze.
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin), stays(SPEND, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), joins(70, ME, Role::Recover),
    ])})));
    chain.refuse(freeze(&chain, FRIEND), "a spend or recovery key of this account is required");
    assert_eq!(chain.mine().frozen_until_elapsed_micros, 0);
    chain.accept(send(&chain, SPEND, 6, 1000));
    // The spend key freezes as well. Left alone, a freeze ends by itself.
    chain.accept(freeze(&chain, SPEND));
    chain.refuse(send(&chain, SPEND, 6, 1000), "account is frozen");
    chain.wait(FREEZE);
    chain.accept(send(&chain, SPEND, 6, 1000));
    chain.engine.audit().unwrap();
}
#[test]
fn a_spend_key_is_held_to_the_daily_limit_fees_included() {
    let mut chain = secured();
    chain.refuse(send(&chain, SPEND, 6, LIMIT), "over the daily limit");
    chain.accept(send(&chain, SPEND, 6, LIMIT - FEE - 10_000));
    let left = chain.mine().level(chain.now());
    assert!((10_000..10_020).contains(&left), "left {left}");
    chain.refuse(send(&chain, SPEND, 6, 10_000), "over the daily limit");
    // Fees count: nine payments of 100 cost 1,100 each, and then not even
    // the fee of a tenth fits.
    for _ in 0..9 {
        chain.accept(send(&chain, SPEND, 6, 100));
    }
    let left = chain.mine().level(chain.now());
    assert!(left < FEE, "left {left}");
    chain.refuse(send(&chain, SPEND, 6, 1), "over the daily limit");
    chain.refuse(signin_keys(&chain, SPEND, &[70], &[]), "over the daily limit");
    chain.refuse(request(&chain, SPEND, 6, 5), "over the daily limit");
    chain.refuse(set_limit(&chain, SPEND, 1), "over the daily limit");
    // Half a day later about half the limit is back, not more.
    chain.wait(43_200);
    let level = chain.mine().level(chain.now());
    assert!((LIMIT / 2..LIMIT / 2 + 2_000).contains(&level), "level {level}");
    chain.refuse(send(&chain, SPEND, 6, level), "over the daily limit");
    chain.accept(send(&chain, SPEND, 6, level - FEE));
    // A merchant payment and staking count the same way.
    let row = chain.me();
    let mut reference = [0u8; 32];
    reference[..8].copy_from_slice(&(row.nonce + 1).to_be_bytes());
    reference[8..16].copy_from_slice(&(chain.now() + 600 * SECOND).to_be_bytes());
    chain.refuse(
        legacy(ME, row.nonce + 1, row.auth_epoch, SPEND, ActionPayload::MerchantPayment(ledger::MerchantPayment { to: 6, amount: 50_000, reference: hex::encode(reference) })),
        "over the daily limit",
    );
    chain.refuse(
        legacy(ME, row.nonce + 1, row.auth_epoch, SPEND, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 50_000, min_shares: 1 })),
        "over the daily limit",
    );
    chain.wait(86_400);
    let row = chain.me();
    chain.accept(legacy(ME, row.nonce + 1, row.auth_epoch, SPEND, ActionPayload::Delegate(ledger::Delegate { operator: 0, amount: 50_000, min_shares: 1 })));
    let level = chain.mine().level(chain.now());
    assert!((LIMIT - 50_000 - FEE..=LIMIT - 50_000 - FEE + 10).contains(&level), "level {level}");
    chain.engine.audit().unwrap();
}

#[test]
fn a_larger_payment_waits_in_the_open_and_can_be_cancelled() {
    let mut chain = secured();
    let amount = 4 * SECOND;
    chain.accept(request(&chain, SPEND, 6, amount));
    let waiting = chain.mine().pending_payments;
    assert_eq!(waiting.len(), 1);
    assert_eq!((waiting[0].id, waiting[0].to, waiting[0].amount), (1, 6, amount));
    assert_eq!(chain.me().balance, 20 * SECOND - 2 * FEE, "nothing has left yet");
    chain.refuse(execute(&chain, SPEND, 1), "waiting period is not over");
    // One recovery key cancels it.
    chain.accept(cancel(FRIEND, "payment", 1));
    chain.refuse(execute(&chain, SPEND, 1), "no such waiting payment");
    chain.refuse(cancel(FRIEND, "payment", 1), "no such waiting payment");
    // Asked again and left alone, it goes through after the wait. The amount
    // is outside the daily limit; the two fees are inside it.
    chain.accept(request(&chain, SPEND, 6, amount));
    chain.wait(DELAY);
    let (mine, theirs) = (chain.me().balance, chain.account(6).balance);
    let level = chain.mine().level(chain.now());
    chain.accept(execute(&chain, SPEND, 2));
    assert_eq!(chain.me().balance, mine - amount - FEE);
    assert_eq!(chain.account(6).balance, theirs + amount);
    assert!(chain.mine().pending_payments.is_empty());
    let after = chain.mine().level(chain.now());
    assert!((level - FEE..=level - FEE + 20).contains(&after), "the fee came out of the limit: {level} to {after}");
    // At most four wait at a time; a spend key can cancel as well.
    for _ in 0..4 {
        chain.accept(request(&chain, SPEND, 6, 7));
    }
    chain.refuse(request(&chain, SPEND, 6, 7), "too many payments");
    chain.accept(cancel(SPEND, "payment", 4));
    // Not to oneself, not for nothing, not to nobody.
    chain.refuse(request(&chain, SPEND, ME, 7), "invalid payment");
    chain.refuse(request(&chain, SPEND, 6, 0), "invalid payment");
    chain.refuse(request(&chain, SPEND, 9999, 7), "");
    chain.engine.audit().unwrap();
}

#[test]
fn raising_the_limit_waits_and_lowering_it_does_not() {
    let mut chain = secured();
    chain.refuse(set_limit(&chain, SPEND, LIMIT), "already has this value");
    chain.accept(set_limit(&chain, SPEND, 4 * LIMIT));
    assert_eq!(chain.mine().policy.daily_limit_micros, LIMIT);
    chain.refuse(send(&chain, SPEND, 6, LIMIT), "over the daily limit");
    // A recovery key cancels a raise the owner did not expect, once.
    let raise = chain.mine().pending_limit.unwrap().id;
    chain.accept(cancel(SHEET, "limit", raise));
    chain.refuse(cancel(SHEET, "limit", raise), "no such raise of the limit is waiting");
    chain.accept(set_limit(&chain, SPEND, 4 * LIMIT));
    chain.refuse(cancel(SHEET, "limit", raise), "no such raise of the limit is waiting");
    chain.wait(DELAY);
    // In force now, but the allowance only grows with time.
    chain.refuse(send(&chain, SPEND, 6, LIMIT), "over the daily limit");
    chain.wait(86_400);
    chain.accept(send(&chain, SPEND, 6, 3 * LIMIT));
    assert_eq!(chain.mine().policy.daily_limit_micros, 4 * LIMIT);
    // Lowering is immediate and cuts what is left.
    chain.accept(set_limit(&chain, SPEND, 5000));
    let mine = chain.mine();
    assert_eq!(mine.policy.daily_limit_micros, 5000);
    assert!(mine.allowance_micros <= 5000);
    chain.refuse(send(&chain, SPEND, 6, 5000), "over the daily limit");
    chain.engine.audit().unwrap();
}

#[test]
fn the_spend_key_replaces_a_stolen_sign_in_key_at_once() {
    let mut chain = secured();
    // The login was stolen. With the spend key alone the owner puts a new
    // sign-in key in its place: one action, no waiting.
    let (epoch, balance) = (chain.me().auth_epoch, chain.me().balance);
    chain.accept(signin_keys(&chain, SPEND, &[70], &[SIGNIN]));
    assert!(has_key(&chain, 70) && !has_key(&chain, SIGNIN));
    assert_eq!(chain.me().auth_epoch, epoch + 1, "sessions of the old keys end");
    assert_eq!(chain.me().balance, balance - FEE);
    // What the thief holds is a key of no account.
    chain.refuse(freeze(&chain, SIGNIN), "a spend or recovery key of this account is required");
    chain.refuse(signin_keys(&chain, SPEND, &[], &[SIGNIN]), "no such sign-in key");
    chain.refuse(signin_keys(&chain, SPEND, &[70], &[]), "already on the account");
    // Only sign-in keys go this way: spend and recovery keys are out of reach.
    chain.refuse(signin_keys(&chain, SPEND, &[], &[SHEET]), "no such sign-in key");
    chain.refuse(signin_keys(&chain, SPEND, &[], &[SPEND]), "no such sign-in key");
    // A new key must accept the role itself, as a sign-in key of this account.
    for proof in [accepts(72, ME, Role::Signin), accepts(71, ME, Role::Spend), accepts(71, 6, Role::Signin)] {
        chain.refuse(
            act(&chain, SPEND, security::SIGNIN, json!({"add": [{"public_key": pk(71), "proof": proof}], "remove": []})),
            "signature does not verify",
        );
    }
    // No other key manages sign-in keys.
    chain.refuse(signin_keys(&chain, SHEET, &[71], &[]), "a spend key is required");
    chain.refuse(signin_keys(&chain, 70, &[71], &[]), "a spend key is required");
    // Several at once; an account may be left without any.
    chain.accept(signin_keys(&chain, SPEND, &[71, 72], &[]));
    chain.accept(signin_keys(&chain, SPEND, &[], &[70, 71, 72]));
    assert_eq!(chain.me().devices.len(), 4, "one spend key and three recovery keys");
    chain.refuse(act(&chain, SPEND, security::SIGNIN, json!({"add": [], "remove": []})), "between one and eight");
    // The account holds eight keys at most.
    chain.accept(signin_keys(&chain, SPEND, &[73, 74, 75, 76], &[]));
    chain.refuse(signin_keys(&chain, SPEND, &[77], &[]), "at most eight");
    chain.accept(signin_keys(&chain, SPEND, &[77], &[73]));
    chain.engine.audit().unwrap();
}
#[test]
fn the_spend_key_with_one_recovery_key_acts_at_once() {
    let mut chain = secured();
    // One proof is not enough, whichever it is.
    chain.refuse(root(&chain, SPEND, &[SPEND], new_spend_key(70)), "not enough proofs");
    chain.refuse(root(&chain, SHEET, &[SHEET], new_spend_key(70)), "not enough proofs");
    // The owner replaces a spend key that may have been copied.
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], new_spend_key(70)));
    assert_eq!(chain.mine().version, 2);
    assert!(chain.mine().pending_root.is_none());
    chain.refuse(send(&chain, SPEND, 6, 1000), "device is not authorized");
    chain.accept(send(&chain, 70, 6, 1000));
    // A payment above the limit, at once, with a second proof.
    let (mine, theirs) = (chain.me().balance, chain.account(6).balance);
    chain.refuse(root(&chain, 70, &[SHEET, PHRASE], pay(6, 3_000_000)), "a spend key must take part");
    chain.accept(root(&chain, 70, &[70, PHRASE], pay(6, 3_000_000)));
    assert_eq!(chain.me().balance, mine - 3_000_000 - FEE);
    assert_eq!(chain.account(6).balance, theirs + 3_000_000);
    chain.refuse(root(&chain, 70, &[70, PHRASE], pay(6, 300 * SECOND)), "insufficient liquid funds");
    // Approvals for a payment are good for an hour at most.
    let (version, late) = (chain.mine().version, chain.now() + 2 * 3600 * SECOND);
    chain.refuse(root_for(70, &[70, PHRASE], pay(6, 5), version, late), "dated too far ahead");
    // A freeze is lifted the same way, not by recovery keys alone; the same
    // proofs can also pay during a freeze.
    chain.accept(freeze(&chain, PHRASE));
    chain.refuse(root(&chain, SHEET, &[SHEET, PHRASE], unfreeze(&chain)), "a spend key must take part");
    chain.accept(root(&chain, 70, &[70, FRIEND], pay(6, 2_000_000)));
    chain.accept(root(&chain, 70, &[70, FRIEND], unfreeze(&chain)));
    chain.accept(send(&chain, 70, 6, 1000));
    chain.refuse(root(&chain, 70, &[70, FRIEND], unfreeze(&chain)), "account is not frozen");
    chain.engine.audit().unwrap();
}

#[test]
fn recovery_keys_replace_a_stolen_spend_key_and_the_thief_cannot_stop_it() {
    let mut chain = secured();
    // The thief holds the spend key and the sign-in key, and has started a
    // large payment and a raise of the limit.
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    chain.accept(set_limit(&chain, SPEND, 40 * LIMIT));
    // The owner has lost the device. Two recovery keys ask for a new spend key.
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)));
    let mine = chain.mine();
    let pending = mine.pending_root.clone().expect("the replacement waits");
    assert_eq!(pending.ready_elapsed_micros, chain.now() + DELAY * SECOND);
    assert_eq!(mine.version, 2);
    assert!(mine.pending_payments.is_empty() && mine.pending_limit.is_none(), "what the thief had started is dropped");
    assert!(has_key(&chain, SPEND), "old keys stay until the wait is over");

    // The thief can no longer do anything that costs the account.
    chain.refuse(send(&chain, SPEND, 6, 1000), "account is frozen");
    chain.refuse(request(&chain, SPEND, 6, 5), "account is frozen");
    chain.refuse(execute(&chain, SPEND, 1), "account is frozen");
    chain.refuse(set_limit(&chain, SPEND, 9 * LIMIT), "account is frozen");
    chain.refuse(signin_keys(&chain, SPEND, &[71], &[]), "account is frozen");
    // Nor cancel the replacement, lift the freeze or push through one of its own.
    chain.refuse(root(&chain, SPEND, &[SPEND], json!({"type": "cancel"})), "not enough proofs");
    chain.refuse(root(&chain, SPEND, &[SPEND], unfreeze(&chain)), "not enough proofs");
    chain.refuse(root(&chain, SPEND, &[SPEND], new_spend_key(71)), "not enough proofs");
    // Protocol 4's single-key management is closed to it as well.
    let row = chain.me();
    for payload in [
        ActionPayload::CancelRecovery(ledger::CancelRecovery {}),
        ActionPayload::CancelPending(ledger::CancelPending {}),
        ActionPayload::RevokeDevice(ledger::RevokeDevice { public_key: pk(SHEET) }),
        ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![1, 2], threshold: 2, delay_seconds: 30 }),
    ] {
        chain.refuse(legacy(ME, row.nonce + 1, row.auth_epoch, SPEND, payload), "manages its keys and recovery with its security rules");
    }
    // Nobody finishes early, and only a key of the new set finishes at all.
    chain.refuse(finalize(&chain, 70), "waiting period is not over");
    chain.wait(DELAY);
    chain.refuse(finalize(&chain, 99), "only a spend or recovery key of the new set");
    chain.refuse(finalize(&chain, SPEND), "only a spend or recovery key of the new set");
    chain.refuse(guard(70, security::FINALIZE, json!({"version": "1"})), "security settings have changed");
    chain.accept(finalize(&chain, 70));

    let mine = chain.mine();
    assert!(mine.pending_root.is_none());
    assert_eq!(mine.version, 3);
    assert_eq!(mine.policy.daily_limit_micros, LIMIT);
    assert!(!has_key(&chain, SPEND));
    chain.refuse(send(&chain, SPEND, 6, 1000), "device is not authorized");
    chain.accept(send(&chain, 70, 6, 1000));
    chain.refuse(finalize(&chain, 70), "no replacement is waiting");
    chain.engine.audit().unwrap();
}

#[test]
fn removing_a_sign_in_key_does_not_void_a_replacement_that_keeps_it() {
    let mut chain = secured();
    // The owner, without the device, has two recovery keys approve a new
    // spend key. The new set keeps the sign-in key as it is.
    let rescue = root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70));
    // The thief holds the spend key, sees it coming and removes that sign-in
    // key first.
    chain.accept(signin_keys(&chain, SPEND, &[], &[SIGNIN]));
    // The replacement goes through all the same, without the key that is gone.
    chain.accept(rescue);
    let pending = chain.mine().pending_root.expect("the replacement waits");
    assert_eq!(pending.devices.len(), 4);
    assert!(!pending.devices.iter().any(|device| device.public_key == pk(SIGNIN)));
    chain.refuse(signin_keys(&chain, SPEND, &[71], &[]), "account is frozen");
    chain.wait(DELAY);
    chain.accept(finalize(&chain, 70));
    assert!(has_key(&chain, 70) && !has_key(&chain, SPEND) && !has_key(&chain, SIGNIN));

    // The same when the owner acts at once with the spend key and a recovery
    // key, and the thief, who holds a copy of the spend key, is faster.
    chain.accept(signin_keys(&chain, 70, &[72], &[]));
    let keep = |spend: u8| json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(72, Role::Signin), joins(spend, ME, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover),
    ])});
    let rescue = root(&chain, 70, &[70, SHEET], keep(73));
    chain.accept(signin_keys(&chain, 70, &[], &[72]));
    chain.accept(rescue);
    assert!(has_key(&chain, 73) && !has_key(&chain, 70) && !has_key(&chain, 72));
    assert_eq!(chain.me().devices.len(), 4);

    // Only a sign-in key that is gone is left out. A spend or recovery key
    // that is not on the account, or a key kept in another role, still needs
    // its holder's acceptance.
    let with = |extra: Value| json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(73, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover), extra,
    ])});
    for extra in [stays(99, Role::Recover), stays(98, Role::Spend)] {
        chain.refuse(root(&chain, 73, &[73, SHEET], with(extra)), "must carry its holder's acceptance");
    }
    // An entry that is left out is checked like any other: a real key, each
    // once, the list in order. It is no way to carry anything else in the
    // action, and the replacement still has one accepted form.
    let kept = || vec![stays(73, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover)];
    let replacing = |keys: Vec<Value>| json!({"type": "replace", "policy": policy(2, LIMIT), "keys": keys});
    let gone = |seed: u8| stays(seed, Role::Signin);
    let mut junk = sorted(kept()).as_array().unwrap().clone();
    junk.push(json!({"public_key": "z".repeat(4000), "role": "signin"}));
    chain.refuse(root(&chain, 73, &[73, SHEET], replacing(junk)), "noncanonical 32-byte key");
    let mut words = sorted(kept()).as_array().unwrap().clone();
    words.push(json!({"public_key": "not a key", "role": "signin"}));
    chain.refuse(root(&chain, 73, &[73, SHEET], replacing(words)), "");
    let mut twice = sorted({ let mut keys = kept(); keys.push(gone(120)); keys }).as_array().unwrap().clone();
    let at = twice.iter().position(|key| key["public_key"] == json!(pk(120))).unwrap();
    twice.insert(at, gone(120));
    chain.refuse(root(&chain, 73, &[73, SHEET], replacing(twice)), "keys must be distinct, sorted");
    let mut unsorted = sorted({ let mut keys = kept(); keys.push(gone(120)); keys }).as_array().unwrap().clone();
    unsorted.reverse();
    chain.refuse(root(&chain, 73, &[73, SHEET], replacing(unsorted)), "keys must be distinct, sorted");
    let mut many = kept();
    many.extend((120..125).map(gone));
    chain.refuse(root(&chain, 73, &[73, SHEET], replacing(sorted(many).as_array().unwrap().clone())), "too many keys");
    // In order and real, absent sign-in keys are left out and the rest is installed.
    let mut fine = kept();
    fine.extend([gone(120), gone(121)]);
    chain.accept(root(&chain, 73, &[73, SHEET], replacing(sorted(fine).as_array().unwrap().clone())));
    assert_eq!(chain.me().devices.len(), 4);
    chain.refuse(
        root(&chain, 73, &[73, SHEET], json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
            stays(73, Role::Spend), stays(SHEET, Role::Signin), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover), joins(74, ME, Role::Recover),
        ])})),
        "must carry its holder's acceptance",
    );
    chain.engine.audit().unwrap();
}

#[test]
fn what_a_spend_key_started_does_not_survive_a_replacement_that_is_called_off() {
    let mut chain = secured();
    // The thief starts a payment and a raise; the owner, without the device,
    // asks for a replacement; then the device turns up and the owner calls
    // the replacement off with two recovery keys.
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    chain.accept(set_limit(&chain, SPEND, 40 * LIMIT));
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)));
    chain.wait(2 * DELAY);
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], json!({"type": "cancel"})));
    // The account works again, and none of it comes back.
    chain.refuse(execute(&chain, SPEND, 1), "no such waiting payment");
    chain.refuse(send(&chain, SPEND, 6, 2 * LIMIT), "over the daily limit");
    assert_eq!(chain.mine().policy.daily_limit_micros, LIMIT);
    chain.accept(send(&chain, SPEND, 6, 1000));
    // The same when a replacement lapses because nobody finished it.
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)));
    chain.wait(DELAY + 7 * 86_400 + 1);
    chain.refuse(finalize(&chain, 70), "no replacement is waiting");
    chain.refuse(execute(&chain, SPEND, 4), "no such waiting payment");
    chain.accept(send(&chain, SPEND, 6, 1000));
    chain.engine.audit().unwrap();
}

#[test]
fn the_owner_stops_a_replacement_asked_for_with_stolen_recovery_keys() {
    let mut chain = secured();
    // Two recovery keys are in the wrong hands and ask for their own spend key.
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(80)));
    // A second one cannot be stacked on top.
    chain.refuse(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(81)), "already waiting");
    // The owner still has the device and the third recovery key: two proofs.
    chain.accept(root(&chain, SPEND, &[SPEND, FRIEND], json!({"type": "cancel"})));
    assert!(chain.mine().pending_root.is_none());
    chain.refuse(finalize(&chain, 80), "no replacement is waiting");
    chain.refuse(root(&chain, SPEND, &[SPEND, FRIEND], json!({"type": "cancel"})), "no replacement is waiting");
    // And replaces the two stolen keys at once.
    chain.accept(root(&chain, SPEND, &[SPEND, FRIEND], json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin), stays(SPEND, Role::Spend), joins(90, ME, Role::Recover), joins(91, ME, Role::Recover), stays(FRIEND, Role::Recover),
    ])})));
    chain.refuse(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(80)), "a spend or recovery key of this account is required");
    chain.refuse(root(&chain, SPEND, &[SHEET, PHRASE], new_spend_key(80)), "approval from a key that is not on the account");
    chain.accept(send(&chain, SPEND, 6, 1000));
    // With the spend key and one recovery key the owner can also simply
    // replace everything while a hostile replacement waits.
    let hostile = json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin), joins(82, ME, Role::Spend), stays(90, Role::Recover), stays(91, Role::Recover), stays(FRIEND, Role::Recover),
    ])});
    chain.accept(root(&chain, FRIEND, &[90, 91], hostile));
    chain.refuse(send(&chain, SPEND, 6, 1000), "account is frozen");
    chain.accept(root(&chain, SPEND, &[SPEND, FRIEND], json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin), stays(SPEND, Role::Spend), joins(92, ME, Role::Recover), joins(93, ME, Role::Recover), stays(FRIEND, Role::Recover),
    ])})));
    assert!(chain.mine().pending_root.is_none());
    chain.refuse(finalize(&chain, 82), "no replacement is waiting");
    chain.accept(send(&chain, SPEND, 6, 1000));
    chain.engine.audit().unwrap();
}

#[test]
fn approvals_cannot_be_reused_moved_or_stretched() {
    let mut chain = secured();
    let small = pay(6, 1000);
    let (version, expires) = (chain.mine().version, chain.now() + 3000 * SECOND);
    chain.accept(root_for(SPEND, &[SPEND, SHEET], small.clone(), version, expires));
    // The same approvals again: the version moved on.
    chain.refuse(root_for(SPEND, &[SPEND, SHEET], small.clone(), version, expires), "signature does not verify");
    let version = chain.mine().version;
    // Given for another operation, another expiry, or already expired.
    let given = approvals(ME, &[SPEND, SHEET], &small, version, expires);
    chain.refuse(guard(SPEND, security::ROOT, json!({"op": pay(6, 9_000_000), "expires_elapsed_micros": expires.to_string(), "approvals": given})), "signature does not verify");
    chain.refuse(guard(SPEND, security::ROOT, json!({"op": small, "expires_elapsed_micros": (expires + 1).to_string(), "approvals": given})), "signature does not verify");
    chain.refuse(root_for(SPEND, &[SPEND, SHEET], small.clone(), version, chain.now()), "expired");
    chain.refuse(root_for(SPEND, &[SPEND, SHEET], json!({"type": "cancel"}), version, chain.now() + 31 * 86_400 * SECOND), "dated too far ahead");
    // The same key twice, keys out of order, a key of no account.
    chain.refuse(guard(SPEND, security::ROOT, json!({"op": small, "expires_elapsed_micros": expires.to_string(), "approvals": [given[0], given[0]]})), "each key once");
    chain.refuse(guard(SPEND, security::ROOT, json!({"op": small, "expires_elapsed_micros": expires.to_string(), "approvals": [given[1], given[0]]})), "each key once");
    chain.refuse(root(&chain, SPEND, &[SPEND, 99], small.clone()), "approval from a key that is not on the account");
    // Approvals for another account do not carry over.
    let foreign = approvals(6, &[SPEND, SHEET], &small, version, expires);
    chain.refuse(guard(SPEND, security::ROOT, json!({"op": small, "expires_elapsed_micros": expires.to_string(), "approvals": foreign})), "signature does not verify");

    // The owner approves a new spend key with three keys. Somebody who holds
    // another recovery key hands it in with the spend key's approval left
    // out, which would turn it into a replacement that waits and freezes.
    let replacement = new_spend_key(70);
    let three = approvals(ME, &[SPEND, SHEET, PHRASE], &replacement, version, expires);
    let without_spend: Vec<Value> = three.iter().filter(|a| a["public_key"] != json!(pk(SPEND))).cloned().collect();
    assert_eq!(without_spend.len(), 2);
    chain.refuse(guard(FRIEND, security::ROOT, json!({"op": replacement, "expires_elapsed_micros": expires.to_string(), "approvals": without_spend})), "signature does not verify");
    chain.accept(guard(FRIEND, security::ROOT, json!({"op": replacement, "expires_elapsed_micros": expires.to_string(), "approvals": three})));
    assert!(chain.mine().pending_root.is_none(), "it happened at once, as approved");
    assert!(has_key(&chain, 70));

    // Approvals to lift one freeze do not lift a later one.
    chain.accept(freeze(&chain, FRIEND));
    let stale = root(&chain, 70, &[70, SHEET], unfreeze(&chain));
    chain.wait(FREEZE);
    chain.refuse(stale.clone(), "account is not frozen");
    chain.accept(freeze(&chain, FRIEND));
    chain.refuse(stale, "frozen again since");
    chain.refuse(send(&chain, 70, 6, 1000), "account is frozen");

    // Two spend keys are still one proof.
    chain.accept(root(&chain, 70, &[70, SHEET], json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(70, Role::Spend), joins(71, ME, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover),
    ])})));
    chain.refuse(root(&chain, 70, &[70, 71], small), "not enough proofs");
    chain.engine.audit().unwrap();
}

#[test]
fn a_replacement_must_be_a_valid_set_of_keys() {
    let mut chain = secured();
    let replace = |keys: Value, threshold: u64| json!({"type": "replace", "policy": policy(threshold, LIMIT), "keys": keys});
    // A key cannot hold two roles.
    chain.refuse(
        root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(vec![stays(SPEND, Role::Spend), joins(SPEND, ME, Role::Recover), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover)]), 2)),
        "keys must be distinct",
    );
    // No set without a spend key, none with fewer recovery keys than proofs needed.
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(vec![stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover)]), 2)), "at least one spend key");
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(vec![stays(SPEND, Role::Spend), stays(SHEET, Role::Recover)]), 2)), "at most the number of recovery keys");
    // A key that changes role, or a new key, must accept it.
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(vec![stays(SPEND, Role::Spend), stays(SIGNIN, Role::Recover), stays(SHEET, Role::Recover)]), 2)), "must carry its holder's acceptance");
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(vec![stays(SPEND, Role::Spend), stays(95, Role::Recover), stays(SHEET, Role::Recover)]), 2)), "must carry its holder's acceptance");
    // More than eight keys; keys out of order.
    let many: Vec<Value> = (0..9).map(|i| joins(100 + i, ME, if i == 0 { Role::Spend } else { Role::Recover })).collect();
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(many), 2)), "too many keys");
    let mut unordered = new_spend_key(70);
    unordered["keys"].as_array_mut().unwrap().reverse();
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], unordered), "keys must be distinct, sorted");
    // Unknown operations and fields are refused.
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], json!({"type": "drain"})), "unknown variant");
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], json!({"type": "cancel", "extra": "1"})), "unknown field");
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], json!({"type": "unfreeze"})), "missing field");
    // A higher threshold with three recovery keys works, and is then needed.
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], replace(sorted(vec![
        stays(SPEND, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover),
    ]), 3)));
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], pay(6, 5)), "not enough proofs");
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET, PHRASE], pay(6, 5)));
    chain.refuse(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)), "not enough proofs");
    chain.engine.audit().unwrap();
}

#[test]
fn protocol_4_accounts_keep_their_rules_and_secured_ones_lose_single_key_management() {
    let mut chain = secured();
    // A recovery key carries protocol 4's "can manage" flag. Alone it must not
    // manage anything.
    let row = chain.me();
    let new_device = ledger::AddDevice { public_key: pk(96), can_manage: true, can_spend: true, proof: "00".repeat(64) };
    for payload in [
        ActionPayload::AddDevice(new_device),
        ActionPayload::RevokeDevice(ledger::RevokeDevice { public_key: pk(SPEND) }),
        ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![1, 2], threshold: 2, delay_seconds: 30 }),
        ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: 1, accept: true }),
        ActionPayload::CancelPending(ledger::CancelPending {}),
        ActionPayload::CancelRecovery(ledger::CancelRecovery {}),
    ] {
        chain.refuse(legacy(ME, row.nonce + 1, row.auth_epoch, SHEET, payload), "manages its keys and recovery with its security rules");
    }
    // The account next door never adopted the rules: its single key still
    // manages it, and the security actions do not apply to it.
    chain.accept(transfer(&chain.account(0), 1, 6, SECOND));
    let other = chain.account(6);
    chain.accept(legacy(6, other.nonce + 1, other.auth_epoch, 7, ActionPayload::CancelPending(ledger::CancelPending {})));
    let other = chain.account(6);
    chain.refuse(guard_of(6, 7, security::FREEZE, json!({"freezes": "0", "expires_elapsed_micros": (chain.now() + 60 * SECOND).to_string()})), "has not adopted the security rules");
    chain.refuse(extension(&other, 7, security::LIMIT, json!({"daily_limit_micros": "1"})), "has not adopted the security rules");
    assert!(chain.security(6).is_none());
    chain.accept(transfer(&other, 7, ME, 1000));
    // An account with a guardian policy turns it off first.
    let other = chain.account(6);
    chain.accept(legacy(6, other.nonce + 1, other.auth_epoch, 7, ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![1, 2], threshold: 2, delay_seconds: 30 })));
    let other = chain.account(6);
    let keys = sorted(vec![joins(110, 6, Role::Spend), joins(111, 6, Role::Recover), joins(112, 6, Role::Recover)]);
    chain.refuse(extension(&other, 7, security::SECURE, json!({"keys": keys, "policy": policy(2, LIMIT)})), "turn guardian recovery off");
    chain.accept(legacy(6, other.nonce + 1, other.auth_epoch, 7, ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![], threshold: 0, delay_seconds: 0 })));
    let other = chain.account(6);
    chain.accept(extension(&other, 7, security::SECURE, json!({"keys": keys, "policy": policy(2, LIMIT)})));
    assert!(chain.security(6).is_some());
    chain.engine.audit().unwrap();
}

#[test]
fn a_secured_account_can_stop_being_someone_elses_guardian() {
    let mut chain = Chain::new();
    // Account 6 names accounts 5 and 7 as its guardians; both agree.
    chain.accept(transfer(&chain.account(0), 1, 6, SECOND));
    chain.accept(transfer(&chain.account(1), 2, 7, SECOND));
    let ward = chain.account(6);
    chain.accept(legacy(6, ward.nonce + 1, ward.auth_epoch, 7, ActionPayload::SetRecovery(ledger::SetRecovery { guardians: vec![5, 7], threshold: 2, delay_seconds: 30 })));
    let version = chain.account(6).recovery_version;
    for (guardian, seed) in [(5u64, OLD), (7, 8)] {
        let row = chain.account(guardian);
        chain.accept(legacy(guardian, row.nonce + 1, row.auth_epoch, seed, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: true })));
    }
    assert_eq!(chain.account(6).recovery_policy.unwrap().accepted, vec![5, 7]);
    // While it is still a protocol-4 account, account 5 approves a recovery
    // of account 6.
    let ward = chain.account(6);
    let (recovery_id, expiry) = (hex::encode(sha(77)), chain.now() + 30 * SECOND + 7 * 86_400 * SECOND);
    let mut message = b"TCDEVNET-RECOVERY-V1\0".to_vec();
    message.extend(hex::decode(network_id()).unwrap());
    message.extend(6u64.to_be_bytes());
    message.extend(ward.auth_epoch.to_be_bytes());
    message.extend(ward.recovery_version.to_be_bytes());
    message.extend(hex::decode(&recovery_id).unwrap());
    message.extend(key(99).verifying_key().as_bytes());
    message.extend(expiry.to_be_bytes());
    let claim = ledger::ApproveRecovery {
        target: 6,
        policy_version: ward.recovery_version,
        recovery_id,
        new_public_key: pk(99),
        expires_elapsed_micros: expiry,
        proof: hex::encode(key(99).sign(&message).to_bytes()),
    };
    let row = chain.me();
    chain.accept(legacy(ME, row.nonce + 1, row.auth_epoch, OLD, ActionPayload::ApproveRecovery(claim)));
    // Account 5 adopts the security rules. It can no longer vote as a
    // guardian, but it can say so on the chain, for free.
    let row = chain.me();
    chain.accept(extension(&row, OLD, security::SECURE, json!({"keys": standard_keys(), "policy": policy(2, LIMIT)})));
    let row = chain.me();
    chain.refuse(
        legacy(ME, row.nonce + 1, row.auth_epoch, SHEET, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: true })),
        "manages its keys and recovery with its security rules",
    );
    // One recovery key signs the withdrawal, and one key alone decides
    // nothing: not while a recovery in progress rests on this account's
    // approval, and never with a sign-in or spend key.
    let leave = |signer: u8| legacy(ME, row.nonce + 1, row.auth_epoch, signer, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: false }));
    chain.refuse(leave(SHEET), "a recovery in progress rests on this account's approval");
    chain.wait(30 + 7 * 86_400 + 1);
    chain.refuse(leave(SIGNIN), "device permission denied");
    chain.refuse(leave(SPEND), "device permission denied");
    chain.accept(freeze(&chain, FRIEND));
    let balance = chain.me().balance;
    chain.accept(legacy(ME, row.nonce + 1, row.auth_epoch, SHEET, ActionPayload::ConsentRecovery(ledger::ConsentRecovery { target: 6, policy_version: version, accept: false })));
    assert_eq!(chain.me().balance, balance, "leaving is free, frozen or not");
    assert_eq!(chain.account(6).recovery_policy.unwrap().accepted, vec![7]);
    chain.engine.audit().unwrap();
}

#[test]
fn stale_envelopes_and_forged_signatures_are_refused() {
    let mut chain = secured();
    let row = chain.me();
    // Wrong nonce, wrong authority epoch.
    let lower = json!({"daily_limit_micros": "1"});
    let mut stale = row.clone();
    stale.nonce += 1;
    chain.refuse(extension(&stale, SPEND, security::LIMIT, lower.clone()), "stale authority or incorrect nonce");
    let mut stale = row.clone();
    stale.auth_epoch += 1;
    chain.refuse(extension(&stale, SPEND, security::LIMIT, lower.clone()), "stale authority or incorrect nonce");
    // A protective action carries neither; one that does is refused, so that
    // the same request cannot be sent in many forms.
    let state = json!({"freezes": "0", "version": "1", "expires_elapsed_micros": (chain.now() + 60 * SECOND).to_string()});
    chain.refuse(extension(&row, SPEND, security::FREEZE, state.clone()), "carries no nonce");
    // A signature that does not belong to the envelope.
    let mut forged = freeze(&chain, SPEND);
    *forged.last_mut().unwrap() ^= 1;
    chain.refuse(forged, "");
    // A payload that is not what the kind expects.
    chain.refuse(guard(SPEND, security::FREEZE, json!({})), "missing field");
    chain.refuse(guard(SPEND, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": state["expires_elapsed_micros"], "extra": "1"})), "unknown field");
    chain.refuse(guard(SPEND, security::FREEZE, json!({"freezes": "0", "version": "1", "expires_elapsed_micros": chain.now().to_string()})), "expired");
    // A freeze names the count and the settings it was signed for.
    chain.refuse(guard(SPEND, security::FREEZE, json!({"freezes": "0", "expires_elapsed_micros": state["expires_elapsed_micros"]})), "missing field");
    chain.refuse(guard(SPEND, security::FREEZE, json!({"freezes": "0", "version": "2", "expires_elapsed_micros": state["expires_elapsed_micros"]})), "the security settings have changed");
    chain.refuse(guard(SPEND, security::FREEZE, json!({"freezes": "1", "version": "1", "expires_elapsed_micros": state["expires_elapsed_micros"]})), "the account has been frozen since");
    chain.refuse(extension(&row, SPEND, security::LIMIT, json!({"daily_limit_micros": 5})), "invalid type");
    chain.refuse(extension(&row, SPEND, security::LIMIT, json!({"daily_limit_micros": "05"})), "noncanonical decimal");
    chain.refuse(extension(&row, SPEND, security::PAYMENT, json!({"type": "steal", "to": "6", "amount": "5"})), "unknown variant");
    // An account that does not exist.
    chain.refuse(guard_of(9_999, SPEND, security::FREEZE, state), "");
}

#[test]
fn pending_transactions_are_admitted_by_the_same_rules() {
    let mut chain = secured();
    let row = chain.me();
    let mut pending = chain.engine.check_state().unwrap();
    // Two payments that fit the limit one by one but not together.
    let first = transfer(&row, SPEND, 6, 300_000);
    let mut after = row.clone();
    after.nonce += 1;
    let second = transfer(&after, SPEND, 6, 300_000);
    pending.admit(&first, SigStatus::Unknown).unwrap();
    assert!(pending.admit(&second, SigStatus::Unknown).is_err(), "over the limit together");
    // A freeze admitted first keeps a later payment out, and is not admitted twice.
    let mut pending = chain.engine.check_state().unwrap();
    let stop = freeze(&chain, FRIEND);
    pending.admit(&stop, SigStatus::Unknown).unwrap();
    assert!(pending.admit(&transfer(&row, SPEND, 6, 1000), SigStatus::Unknown).is_err());
    assert!(pending.admit(&stop, SigStatus::Unknown).is_err());
    // Neither is a root operation or a cancellation.
    let mut pending = chain.engine.check_state().unwrap();
    let rescue = root(&chain, SHEET, &[SPEND, SHEET], new_spend_key(70));
    pending.admit(&rescue, SigStatus::Unknown).unwrap();
    assert!(pending.admit(&rescue, SigStatus::Unknown).is_err());
    // A block that carries a freeze and then a payment is refused as a whole
    // by a validator; a proposer keeps the freeze and drops the payment.
    let (height, time, eligible, hash) = chain.next(SECOND);
    let block = vec![stop.clone(), transfer(&row, SPEND, 6, 1000)];
    assert!(chain.engine.prepare(height, time, &block, &eligible, hash).is_err());
    assert_eq!(chain.block(SECOND, block), vec![stop.clone()]);
    // The same protective action twice in one block: the second copy goes.
    chain.wait(FREEZE);
    let again = freeze(&chain, FRIEND);
    assert_eq!(chain.block(SECOND, vec![again.clone(), again.clone()]), vec![again]);
    // A sign-in key's attempt at a protective action is not admitted at all.
    chain.wait(FREEZE);
    let mut pending = chain.engine.check_state().unwrap();
    assert!(pending.admit(&freeze(&chain, SIGNIN), SigStatus::Unknown).is_err());
}

#[test]
fn a_key_holder_cannot_keep_the_owners_protective_actions_out_of_the_mempool() {
    let mut chain = secured();
    // The thief holds the spend key and has a large payment waiting.
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    // Admission runs on the clock of the last block. A freeze that expires
    // before any block could include it would be admitted, change the count
    // the owner's freeze names and drop what the owner's cancellation names,
    // then never be included, block after block and at no cost. It is not
    // admitted, although a block at this very moment would still take it.
    let mut pending = chain.engine.check_state().unwrap();
    for expires in [chain.now() + 1, chain.now() + 29 * SECOND] {
        let fake = freeze_until(&chain, SPEND, expires);
        assert!(refusal(pending.admit(&fake, SigStatus::Unknown)).contains("too soon to be included"));
    }
    // A freeze of the thief that can be included is admitted. The owner's
    // freeze and cancellation are admitted all the same: protective actions
    // are judged on the last block, not on what else is waiting.
    let thief = freeze(&chain, SPEND);
    let (stop, call_off) = (freeze(&chain, FRIEND), cancel(SHEET, "payment", 1));
    pending.admit(&thief, SigStatus::Unknown).unwrap();
    pending.admit(&stop, SigStatus::Unknown).unwrap();
    pending.admit(&call_off, SigStatus::Unknown).unwrap();
    // A root operation of the owner as well, and it does not shut out a
    // second key's freeze.
    let rescue = root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70));
    pending.admit(&rescue, SigStatus::Unknown).unwrap();
    pending.admit(&freeze(&chain, PHRASE), SigStatus::Unknown).unwrap();
    // One key has one action of a kind waiting for a target: the same freeze
    // signed again with another date is not a second one.
    for again in [freeze_until(&chain, SPEND, chain.now() + 700 * SECOND), freeze_until(&chain, FRIEND, chain.now() + 700 * SECOND)] {
        assert!(refusal(pending.admit(&again, SigStatus::Unknown)).contains("already waiting"));
    }
    assert!(refusal(pending.admit(&cancel(SHEET, "payment", 1), SigStatus::Unknown)).contains("already waiting"));
    assert!(refusal(pending.admit(&cancel(SHEET, "payment", 7), SigStatus::Unknown)).contains("already waiting"));
    // Another key cancelling the same item is fine.
    pending.admit(&cancel(FRIEND, "payment", 1), SigStatus::Unknown).unwrap();
    // What does not hold on the last block is still refused.
    assert!(refusal(pending.admit(&cancel(PHRASE, "payment", 7), SigStatus::Unknown)).contains("no such waiting payment"));
    assert!(pending.admit(&finalize(&chain, 70), SigStatus::Unknown).is_err());
    // The thief's freeze is in place in the pending state: his own payments
    // are no longer admitted behind it.
    assert!(pending.admit(&send(&chain, SPEND, 6, 10), SigStatus::Unknown).is_err());

    // In a block the first that applies wins and the proposer drops the rest.
    // Whichever freeze it is, the waiting payment is gone.
    let kept = chain.block(SECOND, vec![thief.clone(), stop.clone(), call_off.clone()]);
    assert_eq!(kept, vec![thief]);
    assert!(chain.mine().pending_payments.is_empty());
    chain.refuse(execute(&chain, SPEND, 1), "account is frozen");
    // After the block the losers are refused on re-check and leave the mempool.
    let mut pending = chain.engine.check_state().unwrap();
    assert!(pending.admit(&stop, SigStatus::Unknown).is_err());
    assert!(pending.admit(&call_off, SigStatus::Unknown).is_err());
    // The owner's replacement, signed before the freeze, is still good.
    pending.admit(&rescue, SigStatus::Unknown).unwrap();

    // A merchant payment whose reference is about to lapse is not admitted
    // either: with the transactions queued behind it, it would wait for free.
    // A block one second later still accepts it.
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], unfreeze(&chain)));
    let row = chain.me();
    let payment = |expires: u64| {
        let mut reference = [0u8; 32];
        reference[..8].copy_from_slice(&(row.nonce + 1).to_be_bytes());
        reference[8..16].copy_from_slice(&expires.to_be_bytes());
        legacy(ME, row.nonce + 1, row.auth_epoch, SPEND, ActionPayload::MerchantPayment(ledger::MerchantPayment { to: 6, amount: 1000, reference: hex::encode(reference) }))
    };
    let mut pending = chain.engine.check_state().unwrap();
    let soon = payment(chain.now() + 10 * SECOND);
    assert!(refusal(pending.admit(&soon, SigStatus::Unknown)).contains("too soon to be included"));
    pending.admit(&payment(chain.now() + 31 * SECOND), SigStatus::Unknown).unwrap();
    chain.accept(soon);
    chain.engine.audit().unwrap();
}

#[test]
fn many_accounts_and_waiting_states_pass_the_recount() {
    let mut chain = secured();
    // Account 6 secures itself too, with other keys.
    let other = chain.account(6);
    let keys = sorted(vec![joins(110, 6, Role::Spend), joins(111, 6, Role::Recover), joins(112, 6, Role::Recover)]);
    chain.accept(transfer(&chain.account(0), 1, 6, 2 * SECOND));
    chain.accept(extension(&other, 7, security::SECURE, json!({"keys": keys, "policy": policy(2, 0)})));
    // With a limit of zero the spend key moves nothing by itself.
    chain.refuse(transfer(&chain.account(6), 110, ME, 1), "over the daily limit");
    // Leave every kind of waiting state behind on account 5.
    chain.accept(request(&chain, SPEND, 6, 7));
    chain.accept(set_limit(&chain, SPEND, 2 * LIMIT));
    let mine = chain.mine();
    assert!(mine.pending_limit.is_some() && mine.pending_payments.len() == 1);
    let audit = chain.engine.audit().unwrap();
    assert_eq!(audit.account_count, chain.engine.meta().unwrap().account_count);
    // A waiting replacement, then its completion.
    chain.accept(freeze(&chain, FRIEND));
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)));
    assert!(chain.mine().pending_root.is_some());
    chain.engine.audit().unwrap();
    chain.wait(DELAY);
    chain.accept(finalize(&chain, 70));
    let mine = chain.mine();
    assert!(mine.pending_root.is_none() && mine.pending_limit.is_none() && mine.pending_payments.is_empty());
    assert_eq!(mine.frozen_until_elapsed_micros, 0);
    chain.engine.audit().unwrap();
}

#[test]
fn a_thief_who_keeps_the_nonce_busy_cannot_keep_the_owner_out() {
    let mut chain = secured();
    // The thief holds the spend key and has a large payment waiting.
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    // The owner prepares a freeze and, with the spend key and the sheet, a new
    // spend key. Neither names a nonce.
    let stop = freeze(&chain, FRIEND);
    let rescue = root(&chain, SHEET, &[SPEND, SHEET], new_spend_key(70));
    // Meanwhile the thief uses up nonce after nonce.
    for _ in 0..5 {
        chain.accept(send(&chain, SPEND, 6, 10));
    }
    // Both still go through, in one block together with yet another payment
    // of the thief that was sent first.
    let racing = send(&chain, SPEND, 6, 10);
    assert_eq!(chain.block(SECOND, vec![racing.clone(), stop.clone(), rescue.clone()]), vec![racing, stop.clone(), rescue.clone()]);
    let mine = chain.mine();
    assert!(mine.pending_payments.is_empty(), "the waiting payment is gone");
    assert_eq!(mine.frozen_until_elapsed_micros, 0, "new keys end the freeze");
    chain.refuse(send(&chain, SPEND, 6, 10), "device is not authorized");
    chain.refuse(execute(&chain, SPEND, 1), "a spend key is required");
    chain.accept(send(&chain, 70, 6, 10));
    // Neither can be included a second time.
    chain.refuse(stop, "the account has been frozen since");
    chain.refuse(rescue, "approval from a key that is not on the account");
    chain.engine.audit().unwrap();
}

#[test]
fn a_freeze_drops_what_was_waiting_and_cannot_be_replayed() {
    let mut chain = secured();
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    chain.accept(set_limit(&chain, SPEND, 50 * LIMIT));
    let first = freeze(&chain, FRIEND);
    chain.accept(first.clone());
    let mine = chain.mine();
    assert!(mine.pending_payments.is_empty() && mine.pending_limit.is_none());
    // After the freeze has run out the old request is worth nothing: it names
    // a count that has moved on. A new one works.
    chain.wait(FREEZE);
    chain.refuse(first, "the account has been frozen since");
    chain.refuse(execute(&chain, SPEND, 1), "no such waiting payment");
    chain.wait(86_400);
    chain.refuse(send(&chain, SPEND, 6, 2 * LIMIT), "over the daily limit");
    // A freeze that was signed but not sent lapses with its date.
    let unsent = freeze(&chain, SHEET);
    chain.wait(601);
    chain.refuse(unsent, "expired");
    // One signed before the keys were replaced does not land on the new keys.
    let early = freeze(&chain, SHEET);
    chain.accept(root(&chain, SPEND, &[SPEND, PHRASE], new_spend_key(70)));
    chain.refuse(early, "the security settings have changed");
    chain.accept(root(&chain, 70, &[70, PHRASE], json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin), joins(SPEND, ME, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover),
    ])})));
    chain.accept(freeze(&chain, SHEET));
    // A cancellation names what it cancels, so it works once.
    chain.wait(FREEZE);
    chain.accept(set_limit(&chain, SPEND, 50 * LIMIT));
    let raise = chain.mine().pending_limit.unwrap().id;
    chain.accept(cancel(FRIEND, "limit", raise));
    chain.accept(set_limit(&chain, SPEND, 50 * LIMIT));
    chain.refuse(cancel(FRIEND, "limit", raise), "no such raise of the limit is waiting");
    chain.engine.audit().unwrap();
}

#[test]
fn an_emptied_account_can_still_be_frozen_and_recovered() {
    let mut chain = secured();
    // Everything but 400 units leaves; a fee is 1,000.
    let balance = chain.me().balance;
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], pay(6, balance - FEE - 400)));
    assert_eq!(chain.me().balance, 400);
    // Nothing that takes a nonce can be paid for any more.
    chain.refuse(send(&chain, SPEND, 6, 1), "insufficient funds");
    // A freeze takes what is left; what recovers the account then costs
    // nothing: asking for new keys with recovery keys alone, and finishing.
    chain.accept(freeze(&chain, FRIEND));
    assert_eq!(chain.me().balance, 0);
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(70)));
    // Everything else costs the full fee, with or without a balance. Each
    // root operation makes the next one valid at once: were they free for an
    // empty account, one account could fill every block.
    let same_keys = json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        stays(SIGNIN, Role::Signin), stays(SPEND, Role::Spend), stays(SHEET, Role::Recover), stays(PHRASE, Role::Recover), stays(FRIEND, Role::Recover),
    ])});
    for (approvers, operation) in [
        (&[SPEND, SHEET][..], same_keys.clone()),
        (&[SPEND, SHEET][..], unfreeze(&chain)),
        (&[SPEND, SHEET][..], json!({"type": "cancel"})),
        (&[SHEET, PHRASE][..], json!({"type": "cancel"})),
    ] {
        chain.refuse(root(&chain, SHEET, approvers, operation), "insufficient funds for fee");
    }
    chain.wait(DELAY);
    chain.accept(finalize(&chain, 70));
    assert!(has_key(&chain, 70) && !has_key(&chain, SPEND));
    assert_eq!(chain.me().balance, 0);
    // What is free cannot be repeated: a freeze once per half freeze period,
    // a replacement by recovery keys one at a time.
    chain.accept(freeze(&chain, FRIEND));
    chain.refuse(freeze(&chain, FRIEND), "already frozen");
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(71)));
    chain.refuse(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(72)), "already waiting");
    chain.refuse(root(&chain, SHEET, &[SHEET, PHRASE], json!({"type": "cancel"})), "insufficient funds for fee");
    // With exactly one fee the owner calls it off once, and the fee is taken in full.
    chain.accept(transfer(&chain.account(0), 1, ME, FEE));
    chain.accept(root(&chain, 70, &[70, FRIEND], json!({"type": "cancel"})));
    assert_eq!(chain.me().balance, 0);
    // A payment with two proofs must leave the fee as well.
    chain.accept(transfer(&chain.account(0), 1, ME, 5 * FEE));
    chain.accept(root(&chain, 70, &[70, FRIEND], unfreeze(&chain)));
    chain.refuse(root(&chain, 70, &[70, FRIEND], pay(6, 4 * FEE)), "insufficient liquid funds");
    chain.accept(root(&chain, 70, &[70, FRIEND], pay(6, 3 * FEE)));
    assert_eq!(chain.me().balance, 0);
    chain.engine.audit().unwrap();
}

/// A precommit of validator `owner` for a block named by `block_byte`.
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

#[test]
fn a_validator_safety_hold_does_not_stop_protective_actions() {
    let mut chain = secured();
    // The thief has a payment waiting when a validator is caught signing two
    // blocks, which puts the network on hold for ordinary actions.
    chain.accept(request(&chain, SPEND, 6, 9 * SECOND));
    let evidence = serde_json::to_value(pos::DoubleSignEvidence { first: vote(0, 1, 1), second: vote(0, 1, 3) }).unwrap();
    chain.accept(extension(&chain.account(2), 3, 20, evidence));
    let summary: pos::Summary = serde_json::from_slice(&chain.row(timecurrency_v5::pos_adapter::SUMMARY_KEY).unwrap()).unwrap();
    assert!(summary.safety_hold);
    chain.refuse(send(&chain, SPEND, 6, 10), "critical validator hold");
    chain.refuse(execute(&chain, SPEND, 1), "critical validator hold");
    chain.refuse(set_limit(&chain, SPEND, 1), "critical validator hold");
    // The owner is not shut out while the payment's wait runs down.
    chain.wait(DELAY);
    chain.accept(cancel(FRIEND, "payment", 1));
    chain.accept(freeze(&chain, FRIEND));
    chain.refuse(root(&chain, SPEND, &[SPEND, SHEET], pay(6, 5)), "no payments during a validator safety hold");
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], new_spend_key(70)));
    assert!(has_key(&chain, 70));
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(71)));
    chain.wait(DELAY);
    chain.accept(finalize(&chain, 71));
    assert!(has_key(&chain, 71) && !has_key(&chain, 70));
    chain.engine.audit().unwrap();
}

/// Writes the bytes the wallet library (`client-v4/account-security.mjs`) must
/// reproduce. Run with `V5_EXPORT_SECURITY_FIXTURE=1` after any change to the
/// formats; the JavaScript tests then compare against the new file.
#[test]
fn export_the_fixture_for_the_wallet_library() {
    if std::env::var("V5_EXPORT_SECURITY_FIXTURE").is_err() {
        return;
    }
    let mut chain = Chain::new();
    let before = chain.me();
    let secure_payload = json!({"keys": standard_keys(), "policy": policy(2, LIMIT)});
    let secure = extension(&before, OLD, security::SECURE, secure_payload.clone());
    chain.accept(secure.clone());
    let seeds = [("old", OLD), ("signin", SIGNIN), ("spend", SPEND), ("sheet", SHEET), ("phrase", PHRASE), ("friend", FRIEND), ("next", 70)];
    let acceptances: Vec<Value> = [(SIGNIN, Role::Signin), (SPEND, Role::Spend), (SHEET, Role::Recover)]
        .into_iter()
        .map(|(seed, role)| json!({"public_key": pk(seed), "role": role_name(role), "message": hex::encode(security::key_message(&network_id(), ME, role, &pk(seed)).unwrap()), "proof": accepts(seed, ME, role)}))
        .collect();
    let operation = new_spend_key(70);
    let (version, expires) = (chain.mine().version, chain.now() + 3000 * SECOND);
    let approvers = [pk(SPEND), pk(SHEET)];
    let mut names: Vec<&str> = approvers.iter().map(String::as_str).collect();
    names.sort();
    let message = security::root_message(&network_id(), ME, version, expires, &operation, &names).unwrap();
    let root_action = root_for(SHEET, &[SPEND, SHEET], operation.clone(), version, expires);
    let freeze_payload = json!({"freezes": chain.mine().freezes.to_string(), "version": chain.mine().version.to_string(), "expires_elapsed_micros": expires.to_string()});
    let freeze_action = guard(SHEET, security::FREEZE, freeze_payload.clone());
    let row = chain.me();
    let limit_action = set_limit(&chain, SPEND, 2 * LIMIT);
    // Allowance readings for a row with a raise waiting.
    chain.accept(send(&chain, SPEND, 6, 300_000));
    chain.accept(set_limit(&chain, SPEND, 4 * LIMIT));
    let stored = chain.mine();
    let readings: Vec<Value> = [0u64, 30, 59, 60, 61, 3600, 86_400, 200_000]
        .into_iter()
        .map(|seconds| {
            let now = chain.now() + seconds * SECOND;
            let mut copy = stored.clone();
            copy.settle(now);
            json!({"now_elapsed_micros": now.to_string(), "allowance_micros": copy.level(now).to_string()})
        })
        .collect();
    let fixture = json!({
        "network_id": network_id(),
        "account": {"id": ME.to_string(), "before_secure": {"nonce": before.nonce.to_string(), "auth_epoch": before.auth_epoch.to_string()}, "after_secure": {"nonce": row.nonce.to_string(), "auth_epoch": row.auth_epoch.to_string()}},
        "seeds": seeds.iter().map(|(name, seed)| json!({"name": name, "seed_hex": hex::encode([*seed; 32]), "public_key": pk(*seed)})).collect::<Vec<_>>(),
        "acceptances": acceptances,
        "secure": {"payload": secure_payload, "action_hex": hex::encode(&secure)},
        "root": {"operation": operation, "version": version.to_string(), "expires_elapsed_micros": expires.to_string(), "approvers": approvers, "message_hex": hex::encode(&message), "action_hex": hex::encode(&root_action)},
        "freeze": {"payload": freeze_payload, "action_hex": hex::encode(&freeze_action)},
        "limit": {"daily_limit_micros": (2 * LIMIT).to_string(), "action_hex": hex::encode(&limit_action)},
        "allowance": {"security": serde_json::to_value(&stored).unwrap(), "readings": readings},
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client-v4/account-security.fixture.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    // The exported actions are the real thing: the chain accepts them.
    chain.accept(freeze_action);
}

// "Move my account to another device" (web-v4/wallet/device-move.mjs). The
// other device made a payment key and a login key and sent their acceptances;
// this account's payment key and one recovery key put them in at once, and
// every other payment and login key goes. Nothing new in the engine: it is the
// replacement of a stolen payment key, with both new keys made elsewhere.
const MOVED_SPEND: u8 = 70;
const MOVED_SIGNIN: u8 = 71;
fn move_to_another_device() -> Value {
    json!({"type": "replace", "policy": policy(2, LIMIT), "keys": sorted(vec![
        joins(MOVED_SPEND, ME, Role::Spend),
        joins(MOVED_SIGNIN, ME, Role::Signin),
        stays(SHEET, Role::Recover),
        stays(PHRASE, Role::Recover),
        stays(FRIEND, Role::Recover),
    ])})
}

/// The bytes of a move, signed by the payment key and the sheet, dated ten
/// minutes ahead as the wallet dates them, with what the account was before.
fn a_move(chain: &Chain) -> (Account, u64, u64, u64, Vec<u8>) {
    let (before, at, version) = (chain.me(), chain.now(), chain.mine().version);
    let expires = at + 600 * SECOND;
    (before, at, version, expires, root_for(SPEND, &[SPEND, SHEET], move_to_another_device(), version, expires))
}
/// The SHA-256 of those bytes: the action of client-v4/device-move.fixture.json,
/// which web-v4/wallet/device-move.test.mjs builds byte for byte (and holds the
/// same digest). Checked here on every run, without reading that file, which is
/// outside the release.
const MOVE_ACTION_SHA256: &str = "8949e25cebdc960f92ef2f9150229b929580c031e57b40c7d43338827c8df23e";

/// The bytes the wallet builds for a move are accepted here, do what the wallet
/// says, and cannot be used twice.
#[test]
fn a_move_to_another_device_replaces_both_keys_at_once_and_cannot_be_replayed() {
    use sha2::Digest;
    let mut chain = secured();
    let (before, _, version, expires, action) = a_move(&chain);
    assert_eq!(hex::encode(sha2::Sha256::digest(&action)), MOVE_ACTION_SHA256, "the bytes changed: run export_the_move_fixture_for_the_wallet and the wallet's test");
    chain.accept(action.clone());
    let row = chain.me();
    let mut expected = vec![
        (pk(MOVED_SIGNIN), Some(Role::Signin)),
        (pk(MOVED_SPEND), Some(Role::Spend)),
        (pk(SHEET), Some(Role::Recover)),
        (pk(PHRASE), Some(Role::Recover)),
        (pk(FRIEND), Some(Role::Recover)),
    ];
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(roles(&row), expected);
    // The authority epoch and the nonce move on, the version too, and the full fee is paid.
    assert_eq!((row.nonce, row.auth_epoch, row.balance), (before.nonce + 1, before.auth_epoch + 1, before.balance - FEE));
    assert_eq!(chain.mine().version, version + 1);
    // The old payment key pays nothing any more; the new one does.
    chain.refuse(send(&chain, SPEND, 6, 1000), "device is not authorized");
    chain.accept(send(&chain, MOVED_SPEND, 6, 1000));
    // The same bytes again: their submitter left the account.
    chain.refuse(action.clone(), "a spend or recovery key of this account is required");
    // Handed in by a recovery key that stayed: one approver left the account.
    chain.refuse(root_for(SHEET, &[SPEND, SHEET], move_to_another_device(), version, expires), "approval from a key that is not on the account");
    // Two recovery keys that stayed, for the version the move named: that version is gone.
    chain.refuse(root_for(SHEET, &[SHEET, PHRASE], move_to_another_device(), version, expires), "signature does not verify");
    chain.engine.audit().unwrap();
}

/// Writes client-v4/device-move.fixture.json: the keys, the account and the bytes
/// of a move, which the wallet's test reproduces. Run with
/// `V5_EXPORT_MOVE_FIXTURE=1`; the exported action is accepted here.
#[test]
fn export_the_move_fixture_for_the_wallet() {
    if std::env::var("V5_EXPORT_MOVE_FIXTURE").is_err() {
        return;
    }
    let mut chain = secured();
    let (before, at, version, expires, action) = a_move(&chain);
    chain.accept(action.clone());
    let row = chain.me();
    let seeds = [("signin", SIGNIN), ("spend", SPEND), ("sheet", SHEET), ("phrase", PHRASE), ("friend", FRIEND), ("moved_spend", MOVED_SPEND), ("moved_signin", MOVED_SIGNIN)];
    let fixture = json!({
        "network_id": network_id(),
        "account": {"id": ME.to_string(), "nonce": before.nonce.to_string(), "auth_epoch": before.auth_epoch.to_string(), "balance": before.balance.to_string()},
        "policy": policy(2, LIMIT),
        "version": version.to_string(),
        "chain_elapsed_micros": at.to_string(),
        "expires_elapsed_micros": expires.to_string(),
        "seeds": seeds.iter().map(|(name, seed)| json!({"name": name, "seed_hex": hex::encode([*seed; 32]), "public_key": pk(*seed)})).collect::<Vec<_>>(),
        "operation": move_to_another_device(),
        "action_hex": hex::encode(&action),
        "after": {"nonce": row.nonce.to_string(), "auth_epoch": row.auth_epoch.to_string(), "devices": serde_json::to_value(&row.devices).unwrap(), "version": (version + 1).to_string()},
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client-v4/device-move.fixture.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
}

/// The engine takes a move while the account is frozen, and while a
/// replacement asked for by two recovery keys waits: being a replacement with
/// the payment key among its approvers, it ends both. The wallet refuses both
/// itself (device-move.mjs): a freeze or a waiting replacement is something the
/// person must look at first, and a move must not sweep it away unseen.
#[test]
fn the_engine_would_take_a_move_over_a_freeze_or_a_waiting_replacement() {
    let mut chain = secured();
    chain.accept(freeze(&chain, FRIEND));
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], move_to_another_device()));
    assert_eq!(chain.mine().frozen_until_elapsed_micros, 0);
    assert!(has_key(&chain, MOVED_SPEND) && has_key(&chain, MOVED_SIGNIN) && !has_key(&chain, SPEND) && !has_key(&chain, SIGNIN));

    let mut chain = secured();
    chain.accept(root(&chain, SHEET, &[SHEET, PHRASE], new_spend_key(72)));
    assert!(chain.mine().pending_root.is_some());
    chain.accept(root(&chain, SPEND, &[SPEND, SHEET], move_to_another_device()));
    assert!(chain.mine().pending_root.is_none());
    assert!(has_key(&chain, MOVED_SPEND) && !has_key(&chain, 72));
    chain.engine.audit().unwrap();
}

/// How long a signed move can land, which is how long the new device keeps
/// its keys when the person withdraws the request (device-move.mjs,
/// withdrawMove): a change of login keys moves the authority epoch on but not
/// the security version that the approvals name, so a move signed before it
/// still lands; once its approvals have expired, it never does.
#[test]
fn a_signed_move_lands_until_its_approvals_expire_whatever_the_epoch() {
    let mut chain = secured();
    let action = root(&chain, SPEND, &[SPEND, SHEET], move_to_another_device());
    let epoch = chain.me().auth_epoch;
    chain.accept(signin_keys(&chain, SPEND, &[73], &[SIGNIN]));
    assert_eq!((chain.me().auth_epoch, chain.mine().version), (epoch + 1, 1));
    chain.accept(action);
    assert!(has_key(&chain, MOVED_SPEND) && has_key(&chain, MOVED_SIGNIN) && !has_key(&chain, 73) && !has_key(&chain, SPEND));

    let mut chain = secured();
    let expires = chain.now() + 600 * SECOND;
    let action = root_for(SPEND, &[SPEND, SHEET], move_to_another_device(), chain.mine().version, expires);
    chain.wait(600);
    chain.refuse(action, "expired, expiring too soon to be included, or dated too far ahead");
    assert!(has_key(&chain, SPEND) && !has_key(&chain, MOVED_SPEND));
    chain.engine.audit().unwrap();
}
