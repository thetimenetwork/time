//! The fee setting, from its review: the transfer fast path against the
//! reference path at the edges of what the protocol-4 rules are lent, and
//! actions whose recipient or header names the payer.
mod common;
use common::*;
use timecurrency_node::ledger::{self, Action, ActionPayload};
use timecurrency_v5::engine::{Engine, account_key};
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
}
impl Chain {
    fn new(fee: u64) -> Self {
        let mut genesis = genesis_v5();
        genesis.fee_micros = fee;
        let network = genesis.network_id().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        let mut chain = Self { _dir: dir, engine, network };
        for _ in 0..20 {
            chain.block(60 * SECOND, vec![]);
        }
        chain
    }
    fn next(&self, delta: u64) -> (i64, i64, Vec<String>, [u8; 32]) {
        let meta = self.engine.meta().unwrap();
        let signers = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|v| v.consensus_key)
            .collect();
        (meta.height + 1, meta.time_micros + delta as i64, signers, sha(meta.height as u64 + 1))
    }
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        let (h, t, s, hash) = self.next(delta);
        let fast = match self.engine.prepare(h, t, &txs, &s, hash) {
            Ok(p) => p,
            Err(e) => panic!("fast path refused: {e:#}"),
        };
        let reference = match self.engine.prepare_reference(h, t, &txs, &s, hash) {
            Ok(p) => p,
            Err(e) => panic!("reference refused: {e:#}"),
        };
        assert_eq!(fast.root, reference.root, "roots differ");
        self.engine.commit(fast, hash).unwrap();
    }
    fn account(&self, id: u64) -> ledger::Account {
        serde_json::from_slice(&self.engine.version().unwrap().get(&account_key(id)).unwrap()).unwrap()
    }
    fn signed(&self, from: u64, nonce: u64, epoch: u64, signer: u8, payload: ActionPayload) -> Vec<u8> {
        ledger::sign_action(
            &Action { network_id: self.network.clone(), from, nonce, auth_epoch: epoch, public_key: pk(signer), payload, signature: vec![] },
            &key(signer),
        )
        .unwrap()
    }
    fn transfer(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        self.signed(from, row.nonce + 1, row.auth_epoch, from as u8 + 1, ActionPayload::Transfer(ledger::Transfer { to, amount }))
    }
    fn merchant(&self, from: u64, to: u64, amount: u64) -> Vec<u8> {
        let row = self.account(from);
        let now = self.engine.meta().unwrap().elapsed_micros().unwrap();
        let mut reference = [7u8; 32];
        reference[..8].copy_from_slice(&(row.nonce + 1).to_be_bytes());
        reference[8..16].copy_from_slice(&(now + 600 * SECOND).to_be_bytes());
        self.signed(
            from,
            row.nonce + 1,
            row.auth_epoch,
            from as u8 + 1,
            ActionPayload::MerchantPayment(ledger::MerchantPayment { to, amount, reference: hex::encode(reference) }),
        )
    }
    /// The errors of the fast path and of the reference path (both must refuse).
    fn errors(&self, tx: &[u8]) -> (String, String) {
        let (h, t, s, hash) = self.next(SECOND);
        let fast = match self.engine.prepare(h, t, &[tx], &s, hash) {
            Ok(_) => panic!("fast path accepted"),
            Err(e) => format!("{e:#}"),
        };
        let reference = match self.engine.prepare_reference(h, t, &[tx], &s, hash) {
            Ok(_) => panic!("reference path accepted"),
            Err(e) => format!("{e:#}"),
        };
        assert!(self.engine.validate_tx(tx).is_err(), "mempool admitted");
        (fast, reference)
    }
}

#[test]
fn fast_and_reference_paths_differ_only_in_error_text_at_the_lent_edge() {
    for fee in [1u64, 10, 999] {
        let mut chain = Chain::new(fee);
        let lent = ledger::FEE_MICROS - fee;
        // Account 5 earns nothing by itself: it holds exactly what it is sent.
        chain.block(SECOND, vec![chain.transfer(0, 5, 5 * SECOND)]);
        let balance = chain.account(5).balance;
        assert_eq!(balance, 5 * SECOND);
        // Above the balance but within what is lent: refused by both, with
        // different texts.
        for amount in [balance + 1, balance + lent] {
            let (fast, reference) = chain.errors(&chain.transfer(5, 6, amount));
            assert!(fast.ends_with("insufficient funds"), "fee {fee}: {fast}");
            assert!(reference.contains("insufficient funds for fee"), "fee {fee}: {reference}");
        }
        // Past what is lent: same text.
        let (fast, reference) = chain.errors(&chain.transfer(5, 6, balance + lent + 1));
        assert!(fast.ends_with("insufficient funds") && reference.ends_with("insufficient funds"), "{fast} / {reference}");
        // One microsecond more than the balance less the fee.
        let (fast, reference) = chain.errors(&chain.transfer(5, 6, balance - fee + 1));
        assert!(fast.contains("insufficient funds for fee") && reference.contains("insufficient funds for fee"));
        // To oneself, and to a shop that is oneself: refused on both paths.
        let (fast, reference) = chain.errors(&chain.transfer(5, 5, 1));
        assert!(fast.contains("invalid transfer amount or recipient") && reference.contains("invalid transfer amount or recipient"), "{fast} / {reference}");
        let (fast, reference) = chain.errors(&chain.merchant(5, 5, 1));
        assert!(fast.contains("invalid transfer amount or recipient") && reference.contains("invalid transfer amount or recipient"), "{fast} / {reference}");
        // A name reveal signed with an account's header (not anonymous).
        let row = chain.account(5);
        let reveal = chain.signed(5, row.nonce + 1, row.auth_epoch, 6, ActionPayload::Reveal(ledger::Reveal { name: "someone".into(), salt: "11".repeat(32) }));
        let _ = chain.errors(&reveal);
        // Everything but the fee, on both paths: the same root, nothing left.
        chain.block(SECOND, vec![chain.transfer(5, 6, balance - fee)]);
        assert_eq!(chain.account(5).balance, 0);
        assert_eq!(chain.account(6).balance, balance - fee);
        chain.engine.audit().unwrap();
    }
}
