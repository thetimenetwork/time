//! The market of seconds against bitcoin (`spec/market.md`): orders, fills,
//! proofs of payment against regtest proof-of-work headers, payments in
//! parts, expiry, the ways out, the account rules, and the recount after
//! every scenario.
mod common;
use bitcoin_bridge::bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
    absolute::LockTime,
    block::{Header, Version},
    consensus::serialize,
    hashes::Hash,
    merkle_tree::{self, MerkleBlock},
    transaction::Version as TxVersion,
};
use common::*;
use serde_json::{Value, json};
use timecurrency_node::ledger::Account;
use timecurrency_v5::engine::{Engine, account_key};
use timecurrency_v5::market::{self, Candle, Fill, Heights, Index, Order, Summary};
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;
/// 250 satoshis for one second.
const PRICE: u64 = 250_000_000;
const SELLER: u64 = 5;
const BUYER: u64 = 6;
const ANYONE: u64 = 7;
const OTHER: u64 = 8;
const USED: &str = "a receiving script serves one order or fill, once";
const TAKEN: &str = "serves a fill or has served one";

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
    network: String,
    /// The newest Bitcoin header the test has mined, and its height.
    tip: Header,
    height: u32,
    /// Every block so far: the time since the block before it, and the
    /// transactions it kept. A node is handed the same blocks (`Node`).
    log: Vec<(u64, Vec<Vec<u8>>)>,
}
impl Chain {
    fn with(market: bool) -> Self {
        let mut genesis = genesis_v5();
        genesis.market = market;
        // A network with the market counts its waits on a clock that
        // stands while the chain stands.
        genesis.waits_survive_stops = market;
        let network = genesis.network_id().unwrap();
        let regtest = bitcoin_bridge::bitcoin::blockdata::constants::genesis_block(
            bitcoin_bridge::bitcoin::Network::Regtest,
        )
        .header;
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        let mut chain = Self { _dir: dir, engine, network, tip: regtest, height: 0, log: Vec::new() };
        // The four validators' owners earn three seconds a block each;
        // each of them funds one account of the tests.
        for _ in 0..340 {
            chain.block(60 * SECOND, vec![]);
        }
        for (from, to) in [SELLER, BUYER, ANYONE, OTHER].into_iter().enumerate() {
            let from = from as u64;
            let row = chain.account(from);
            let tx = timecurrency_node::ledger::sign_action(
                &timecurrency_node::ledger::Action {
                    network_id: chain.network.clone(),
                    from,
                    nonce: row.nonce + 1,
                    auth_epoch: row.auth_epoch,
                    public_key: pk(from as u8 + 1),
                    payload: timecurrency_node::ledger::ActionPayload::Transfer(
                        timecurrency_node::ledger::Transfer { to, amount: 1_000 * SECOND },
                    ),
                    signature: vec![],
                },
                &key(from as u8 + 1),
            )
            .unwrap();
            chain.accept(tx);
        }
        chain
    }
    fn new() -> Self {
        Self::with(true)
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
    fn held(&self) -> u64 {
        self.engine.meta().unwrap().market_micros.unwrap()
    }
    fn summary(&self) -> Summary {
        serde_json::from_slice(&self.row(market::META_KEY).unwrap()).unwrap()
    }
    fn order(&self, id: u64) -> Option<Order> {
        self.row(&market::order_key(id)).map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn fill(&self, id: u64) -> Option<Fill> {
        self.row(&market::fill_key(id)).map(|row| serde_json::from_slice(&row).unwrap())
    }
    fn index(&self, id: u64) -> Index {
        self.row(&market::index_key(id)).map(|row| serde_json::from_slice(&row).unwrap()).unwrap_or_default()
    }
    fn fee(&self) -> u64 {
        self.engine.meta().unwrap().config.fee()
    }
    fn now_secs(&self) -> u32 {
        (self.engine.meta().unwrap().time_micros / 1_000_000) as u32
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
        (meta.height + 1, meta.time_micros + delta as i64, eligible, sha(meta.height as u64 + 1))
    }
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let (height, time, eligible, hash) = self.next(delta);
        let (prepared, kept) =
            self.engine.prepare_filtered(height, time, &txs, &eligible, 1 << 20, hash).unwrap();
        let strict = self.engine.prepare(height, time, &kept, &eligible, hash).unwrap();
        let reference = self.engine.prepare_reference(height, time, &kept, &eligible, hash).unwrap();
        assert_eq!(strict.root, prepared.root, "validator and proposer disagree");
        assert_eq!(reference.root, prepared.root, "fast path and reference disagree");
        self.engine.commit(prepared, hash).unwrap();
        self.log.push((delta, kept.clone()));
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
    #[track_caller]
    fn refuse(&mut self, tx: Vec<u8>, why: &str) {
        let (height, time, eligible, hash) = self.next(SECOND);
        let error = match self.engine.prepare(height, time, &[&tx], &eligible, hash) {
            Ok(_) => panic!("accepted, expected a refusal naming: {why}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains(why), "refused for another reason: {error}");
        assert!(
            self.engine.prepare_reference(height, time, &[&tx], &eligible, hash).is_err(),
            "reference path accepted"
        );
        let (_, kept) =
            self.engine.prepare_filtered(height, time, &[&tx], &eligible, 1 << 20, hash).unwrap();
        assert!(kept.is_empty(), "proposer kept a refused transaction");
    }
    /// A market action of account `from`, signed with its genesis key.
    fn act(&self, from: u64, kind: u8, payload: Value) -> Vec<u8> {
        self.act_with(from, from as u8 + 1, kind, payload)
    }
    /// The same, signed with another key of the account.
    fn act_with(&self, from: u64, seed: u8, kind: u8, payload: Value) -> Vec<u8> {
        let row = self.account(from);
        timecurrency_v5::wire::sign(&self.network, from, row.nonce + 1, row.auth_epoch, kind, &payload, &key(seed))
            .unwrap()
    }
    fn mine(&mut self, root: TxMerkleNode) -> Header {
        let mut header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: self.tip.block_hash(),
            merkle_root: root,
            // A header of now: the chain is fresh, and above the median
            // of the headers before it.
            time: self.now_secs().max(self.tip.time + 1),
            bits: self.tip.bits,
            nonce: 0,
        };
        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }
        self.tip = header;
        self.height += 1;
        header
    }
    fn relay(&mut self, headers: &[Header]) {
        let payload = json!({"headers": headers.iter().map(|h| hex::encode(serialize(h))).collect::<Vec<_>>()});
        let tx = timecurrency_v5::wire::public_headers(&self.network, &payload).unwrap();
        self.accept(tx);
    }
    /// Mines `count` empty Bitcoin blocks and hands their headers to the chain.
    fn bitcoin_blocks(&mut self, count: u32) {
        let headers: Vec<Header> = (0..count).map(|_| self.mine(TxMerkleNode::all_zeros())).collect();
        self.relay(&headers);
    }
    /// A Bitcoin block that holds its coinbase and `tx`, relayed. Returns
    /// the fields of a proof of `tx`'s first output, without the fill.
    fn confirm(&mut self, tx: &Transaction) -> Value {
        let coinbase = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes([vec![0x04], (self.height + 1).to_le_bytes().to_vec()].concat()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_bytes(hex::decode(script(0xcb)).unwrap()),
            }],
        };
        // The proof carries the transactions without their witness data.
        let mut carried = tx.clone();
        for input in &mut carried.input {
            input.witness = Witness::new();
        }
        let ids = [coinbase.compute_txid(), tx.compute_txid()];
        let root = merkle_tree::calculate_root(ids.iter().copied()).unwrap();
        let header = self.mine(TxMerkleNode::from_byte_array(root.to_byte_array()));
        self.relay(&[header]);
        let merkle = MerkleBlock::from_header_txids_with_predicate(&header, &ids, |_| true);
        json!({
            "block_hash": header.block_hash().to_string(),
            "coinbase": hex::encode(serialize(&coinbase)),
            "merkle_proof": hex::encode(serialize(&merkle)),
            "transaction": hex::encode(serialize(&carried)),
            "vout": "0",
        })
    }
    /// A Bitcoin block that holds one payment of `sats` to `script`.
    fn pay(&mut self, script: &str, sats: u64, seed: u8) -> Value {
        self.confirm(&payment(script, sats, seed))
    }
    /// What a proof costs its sender: the fee, and once more for every 256
    /// bytes of its payload.
    fn proof_cost(&self, fill: u64, payment: &Value) -> u64 {
        let mut payload = payment.clone();
        payload["fill"] = json!(fill.to_string());
        let bytes = serde_json::to_vec(&payload).unwrap().len() as u64;
        self.fee() * (1 + bytes / market::PROOF_BYTES_PER_FEE)
    }
    fn proof(&self, from: u64, fill: u64, payment: &Value) -> Vec<u8> {
        let mut payload = payment.clone();
        payload["fill"] = json!(fill.to_string());
        self.act(from, market::PROOF, payload)
    }
    #[track_caller]
    fn audit(&self) {
        if let Err(error) = self.engine.audit() {
            panic!("recount: {error:#}");
        }
    }
}

fn payment(script: &str, sats: u64, seed: u8) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_bytes(hex::decode(script).unwrap()),
        }],
    }
}
fn script(byte: u8) -> String {
    hex::encode([vec![0x00, 0x14], vec![byte; 20]].concat())
}
fn sell_order(amount: u64, scripts: &[String], confirmations: u32, deposit_ppm: u64) -> Value {
    json!({
        "amount_micros": amount.to_string(),
        "confirmations": confirmations.to_string(),
        "deposit_ppm": deposit_ppm.to_string(),
        "min_deposit_micros": "0",
        "min_sats": "1000",
        "pay_blocks": "6",
        "price": PRICE.to_string(),
        "scripts": scripts,
        "side": "sell",
    })
}
fn buy_order(amount: u64, confirmations: u32, deposit_ppm: u64) -> Value {
    json!({
        "amount_micros": amount.to_string(),
        "confirmations": confirmations.to_string(),
        "deposit_ppm": deposit_ppm.to_string(),
        "forms": ["p2wpkh"],
        "min_sats": "1000",
        "pay_blocks": "6",
        "price": PRICE.to_string(),
        "side": "buy",
    })
}
fn take(order: u64, amount: u64, to: u64) -> Value {
    json!({
        "amount_micros": amount.to_string(),
        "order": order.to_string(),
        "sats": market::sats(amount, PRICE).unwrap().to_string(),
        "to": to.to_string(),
    })
}
fn sale(order: u64, amount: u64, confirmations: u32, receiving: String) -> Value {
    json!({
        "amount_micros": amount.to_string(),
        "confirmations": confirmations.to_string(),
        "order": order.to_string(),
        "sats": market::sats(amount, PRICE).unwrap().to_string(),
        "script": receiving,
    })
}

#[test]
fn a_sell_order_is_taken_paid_in_bitcoin_and_the_proof_moves_the_seconds() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(3);
    let fee = chain.fee();
    let seller = chain.balance(SELLER);
    let buyer = chain.balance(BUYER);
    // 100 seconds on offer, two confirmations asked, a deposit of 5%. An
    // order pays the fee once, and once more for each script it lists.
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(2)], 2, 50_000)));
    assert_eq!(chain.balance(SELLER), seller - 100 * SECOND - 3 * fee);
    assert_eq!(chain.held(), 100 * SECOND);
    assert_eq!(chain.index(SELLER).orders, vec![1]);
    assert_eq!(chain.order(1).unwrap().key, pk(SELLER as u8 + 1));
    // The buyer takes 40 seconds: 10,000 satoshis, and 2 seconds of deposit.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)));
    let fill = chain.fill(1).unwrap();
    assert_eq!(fill.sats, 10_000);
    assert_eq!(fill.deposit_micros, 2 * SECOND);
    assert_eq!(fill.script, script(1));
    assert_eq!(fill.start_height, 3);
    assert_eq!(fill.start_hash, chain.tip.block_hash().to_string());
    assert_eq!((fill.owner, fill.payer, fill.to), (SELLER, BUYER, BUYER));
    assert_eq!(chain.balance(BUYER), buyer - 2 * SECOND - fee);
    assert_eq!(chain.order(1).unwrap().amount_micros, 60 * SECOND);
    assert_eq!(chain.held(), 102 * SECOND);
    assert_eq!(chain.index(BUYER).fills, vec![1]);
    chain.audit();
    // The payment is in Bitcoin block 4. With one confirmation the proof is
    // refused; with two, anyone hands it in.
    let payment = chain.pay(&script(1), 10_000, 9);
    chain.refuse(chain.proof(ANYONE, 1, &payment), "lacks confirmations");
    chain.bitcoin_blocks(1);
    let anyone = chain.balance(ANYONE);
    chain.accept(chain.proof(ANYONE, 1, &payment));
    // A proof pays for its size: a small one, a few fees.
    let cost = chain.proof_cost(1, &payment);
    assert!(cost > fee && cost < 8 * fee, "{cost}");
    assert_eq!(chain.balance(ANYONE), anyone - cost);
    // The seconds and the whole deposit are the buyer's.
    assert_eq!(chain.balance(BUYER), buyer + 40 * SECOND - fee);
    assert_eq!(chain.balance(SELLER), seller - 100 * SECOND - 3 * fee);
    assert!(chain.fill(1).is_none());
    assert!(chain.index(BUYER).fills.is_empty());
    let order = chain.order(1).unwrap();
    assert_eq!(order.amount_micros, 60 * SECOND);
    // The first script has served its fill; the second is free.
    let slots = order.scripts.unwrap();
    assert!(slots[0].used && slots[0].fill.is_none());
    assert!(!slots[1].used && slots[1].fill.is_none());
    assert_eq!(chain.held(), 60 * SECOND);
    // The trade is counted.
    let state = chain.summary();
    assert_eq!((state.trades, state.seconds_micros, state.sats, state.last_price), (1, 40 * SECOND, 10_000, Some(PRICE)));
    assert_eq!((state.orders, state.fills), (1, 0));
    chain.refuse(chain.proof(ANYONE, 1, &payment), "no such fill");
    // A payment that is in a Bitcoin block before a fill is made does not
    // count for it: someone pays the second script, and then takes.
    let early = chain.pay(&script(2), 10_000, 11);
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)));
    assert_eq!(chain.fill(2).unwrap().script, script(2));
    chain.bitcoin_blocks(1);
    chain.refuse(chain.proof(ANYONE, 2, &early), "not after the starting block");
    // The payment of the first fill does not pay the second.
    chain.refuse(chain.proof(ANYONE, 2, &payment), "script mismatch");
    // Both scripts have a fill or have had one: nothing more can be taken.
    chain.refuse(chain.act(ANYONE, market::TAKE, take(1, 20 * SECOND, ANYONE)), TAKEN);
    chain.audit();
}

#[test]
fn a_payment_of_a_part_buys_a_part_and_the_fill_goes_on() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(2)], 1, 100_000)));
    let seller = chain.balance(SELLER);
    let buyer = chain.balance(BUYER);
    let other = chain.balance(OTHER);
    // The buyer takes 80 seconds for another account: 20,000 satoshis, a
    // deposit of 8 seconds.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 80 * SECOND, OTHER)));
    assert_eq!(chain.fill(1).unwrap().deposit_micros, 8 * SECOND);
    // A payment of a part is no smaller than the order's smallest trade
    // (1,000 satoshis here): nobody pays a seller in dust.
    let dust = chain.pay(&script(1), 999, 2);
    chain.refuse(chain.proof(ANYONE, 1, &dust), "at least the order's smallest trade");
    // The seller pays 1,000 satoshis to their own address and proves it.
    // In the first draft a payment of a part ended the fill and gave the
    // seller the deposit. Now it buys its part, and the fill goes on.
    let own = chain.pay(&script(1), 1_000, 3);
    let cost = chain.proof_cost(1, &own);
    chain.accept(chain.proof(SELLER, 1, &own));
    let fill = chain.fill(1).unwrap();
    assert_eq!((fill.amount_micros, fill.sats, fill.deposit_micros), (76 * SECOND, 19_000, 7_600_000));
    assert_eq!(chain.balance(OTHER), other + 4 * SECOND);
    // The buyer has a twentieth of the deposit back; the rest is still locked.
    assert_eq!(chain.balance(BUYER), buyer - fee - 8 * SECOND + 400_000);
    assert_eq!(chain.balance(SELLER), seller - cost);
    // A quarter of the price arrives, and anyone proves it.
    let quarter = chain.pay(&script(1), 5_000, 5);
    chain.accept(chain.proof(ANYONE, 1, &quarter));
    let fill = chain.fill(1).unwrap();
    assert_eq!((fill.amount_micros, fill.sats, fill.deposit_micros), (56 * SECOND, 14_000, 5_600_000));
    assert_eq!(chain.balance(OTHER), other + 24 * SECOND);
    // The same output never pays twice.
    chain.refuse(chain.proof(ANYONE, 1, &quarter), "has paid for a fill already");
    // The script still serves this fill, and the order's rest is as it was.
    assert_eq!(chain.order(1).unwrap().amount_micros, 20 * SECOND);
    assert_eq!(chain.held(), 20 * SECOND + 56 * SECOND + 5_600_000);
    chain.audit();
    // What is still to pay is what was agreed less what was paid, to the
    // satoshi. It arrives, with a little more: the fill ends, the seconds
    // are all delivered and the deposit is all back.
    let rest = chain.pay(&script(1), 14_500, 6);
    chain.accept(chain.proof(ANYONE, 1, &rest));
    assert!(chain.fill(1).is_none());
    assert_eq!(chain.balance(OTHER), other + 80 * SECOND);
    assert_eq!(chain.balance(BUYER), buyer - fee);
    assert_eq!(chain.balance(SELLER), seller - cost);
    // Three payments counted, and satoshis up to the price and no further.
    let state = chain.summary();
    assert_eq!((state.trades, state.seconds_micros, state.sats), (3, 80 * SECOND, 1_000 + 5_000 + 14_000));
    assert_eq!(chain.held(), 20 * SECOND);
    chain.audit();
}

#[test]
fn a_fill_made_for_another_account_is_that_accounts_to_give_up() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(2)], 1, 100_000)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 80 * SECOND, OTHER)));
    let seller = chain.balance(SELLER);
    let buyer = chain.balance(BUYER);
    let other = chain.balance(OTHER);
    // Whoever made the fill cannot end it while the other account's
    // bitcoin is on its way; nor can the seller.
    chain.refuse(chain.act(BUYER, market::RELEASE, json!({"fill": "1"})), "only the account its seconds go to");
    chain.refuse(chain.act(SELLER, market::RELEASE, json!({"fill": "1"})), "only the account its seconds go to");
    // The account the seconds go to gives the fill up: the seconds are on
    // offer again, and the deposit, which the payer locked, is the seller's.
    chain.accept(chain.act(OTHER, market::RELEASE, json!({"fill": "1"})));
    assert_eq!(chain.balance(OTHER), other - fee);
    assert_eq!(chain.balance(BUYER), buyer);
    assert_eq!(chain.balance(SELLER), seller + 8 * SECOND);
    assert_eq!(chain.order(1).unwrap().amount_micros, 100 * SECOND);
    assert_eq!(chain.held(), 100 * SECOND);
    chain.audit();
}

#[test]
fn a_fill_that_is_not_paid_ends_after_the_grace_and_the_deposit_is_the_sellers() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(2);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1)], 2, 50_000)));
    let seller = chain.balance(SELLER);
    let buyer = chain.balance(BUYER);
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 100 * SECOND, BUYER)));
    // Started at height 2, six blocks to pay, two confirmations: the last
    // height is 9.
    let fill = chain.fill(1).unwrap();
    assert_eq!(fill.last_height().unwrap(), 9);
    let expire = |chain: &Chain| chain.act(ANYONE, market::EXPIRE, json!({"fill": "1"}));
    chain.refuse(expire(&chain), "has not learnt the last height");
    chain.bitcoin_blocks(6);
    chain.refuse(expire(&chain), "has not learnt the last height");
    chain.bitcoin_blocks(1);
    // The chain knows height 9 now. For twenty seconds a proof is still
    // accepted, and the fill cannot end.
    chain.refuse(expire(&chain), "a proof of a payment made in time is accepted");
    chain.wait(15);
    chain.refuse(expire(&chain), "a proof of a payment made in time is accepted");
    // The chain learnt of the eight Bitcoin blocks in two seconds. The
    // payer still has the time twenty-six blocks are taken to last (the
    // time to pay, twice the confirmations, and sixteen; a second each in
    // the laboratory) and the grace, counted from the fill.
    assert_eq!(
        fill.earliest_end(&market::Params::of(pos::Profile::Laboratory)).unwrap(),
        fill.opened_micros + 46 * SECOND
    );
    chain.wait(5);
    chain.refuse(expire(&chain), "counted from when it was made");
    chain.wait(22);
    chain.refuse(expire(&chain), "counted from when it was made");
    chain.wait(2);
    chain.accept(expire(&chain));
    assert!(chain.fill(1).is_none());
    assert_eq!(chain.order(1).unwrap().amount_micros, 100 * SECOND);
    assert_eq!(chain.balance(SELLER), seller + 5 * SECOND);
    assert_eq!(chain.balance(BUYER), buyer - fee - 5 * SECOND);
    assert_eq!(chain.summary().trades, 0);
    assert_eq!(chain.held(), 100 * SECOND);
    // The seconds are on offer, and no script is left to sell them to.
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 100 * SECOND, BUYER)), TAKEN);
    chain.accept(chain.act(SELLER, market::CANCEL, json!({"order": "1"})));
    assert_eq!(chain.held(), 0);
    chain.audit();
}

#[test]
fn a_fill_paid_in_part_and_then_left_ends_with_the_rest_of_its_deposit() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1)], 1, 100_000)));
    let seller = chain.balance(SELLER);
    let buyer = chain.balance(BUYER);
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 100 * SECOND, BUYER)));
    // Three quarters are paid; the rest never comes.
    let part = chain.pay(&script(1), 18_750, 4);
    chain.accept(chain.proof(ANYONE, 1, &part));
    assert_eq!(chain.balance(BUYER), buyer - fee - 10 * SECOND + 75 * SECOND + 7_500_000);
    chain.bitcoin_blocks(6);
    chain.wait(46);
    chain.accept(chain.act(ANYONE, market::EXPIRE, json!({"fill": "1"})));
    // The quarter not paid for is on offer again; the quarter of the
    // deposit that stood for it is the seller's.
    assert_eq!(chain.order(1).unwrap().amount_micros, 25 * SECOND);
    assert_eq!(chain.balance(SELLER), seller + 2_500_000);
    assert_eq!(chain.held(), 25 * SECOND);
    assert_eq!(chain.summary().trades, 1);
    chain.audit();
}

#[test]
fn a_late_payment_counts_while_the_fill_exists() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(2);
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1)], 2, 0)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 100 * SECOND, BUYER)));
    // The time to pay ends at height 8. The payment is in block 10.
    chain.bitcoin_blocks(7);
    let payment = chain.pay(&script(1), 25_000, 5);
    chain.bitcoin_blocks(1);
    let buyer = chain.balance(BUYER);
    chain.accept(chain.proof(ANYONE, 1, &payment));
    assert_eq!(chain.balance(BUYER), buyer + 100 * SECOND);
    chain.audit();
}

#[test]
fn a_proof_pays_for_its_size_and_carries_no_witness_data() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(2)], 1, 0)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 60 * SECOND, BUYER)));
    // A payment in a large transaction: a second output of 6,000 bytes.
    let mut large = payment(&script(1), 10_000, 7);
    large.output.push(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes([vec![0x6a], vec![0x51; 6_000]].concat()),
    });
    let evidence = chain.confirm(&large);
    let mut payload = evidence.clone();
    payload["fill"] = json!("1");
    let bytes = serde_json::to_vec(&payload).unwrap().len() as u64;
    assert!(bytes > 12_000, "{bytes}");
    let anyone = chain.balance(ANYONE);
    chain.accept(chain.proof(ANYONE, 1, &evidence));
    // The fee, and once more for every 256 bytes of the payload: about
    // fifty fees for these twelve thousand bytes.
    assert_eq!(chain.balance(ANYONE), anyone - fee - fee * (bytes / market::PROOF_BYTES_PER_FEE));
    assert!(bytes / market::PROOF_BYTES_PER_FEE >= 47);
    // A transaction with its witness data has the same id and more bytes
    // nobody paid a miner for: refused.
    let mut signed = payment(&script(2), 15_000, 8);
    signed.input[0].witness = Witness::from_slice(&[vec![1u8; 72], vec![2u8; 33]]);
    let mut with_witness = chain.confirm(&signed);
    let stripped = with_witness["transaction"].clone();
    with_witness["transaction"] = json!(hex::encode(serialize(&signed)));
    chain.refuse(chain.proof(ANYONE, 2, &with_witness), "without its witness data");
    // A proof without the block's coinbase has not the fields of one.
    let mut bare = with_witness.clone();
    bare.as_object_mut().unwrap().remove("coinbase");
    assert!(chain.engine.validate_tx(&chain.proof(ANYONE, 2, &bare)).is_err());
    with_witness["transaction"] = stripped;
    // An account that holds nothing, and to which this proof brings
    // nothing, cannot pay for it: refused before a header is read.
    assert_eq!(chain.balance(9), 0);
    chain.refuse(chain.proof(9, 2, &with_witness), "cannot pay the fee of this proof");
    // As the proof must carry it, from an account that can pay, it is
    // accepted.
    chain.accept(chain.proof(ANYONE, 2, &with_witness));
    assert!(chain.order(1).is_none());
    chain.audit();
}

#[test]
fn a_sell_order_can_ask_a_least_deposit_of_every_fill() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let mut payload = sell_order(100 * SECOND, &[script(1), script(2)], 1, 10_000);
    payload["min_deposit_micros"] = json!((3 * SECOND).to_string());
    chain.accept(chain.act(SELLER, market::ORDER, payload));
    // One per cent of 10 seconds is a tenth of a second: the least applies.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 10 * SECOND, BUYER)));
    assert_eq!(chain.fill(1).unwrap().deposit_micros, 3 * SECOND);
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 90 * SECOND, BUYER)));
    assert_eq!(chain.fill(2).unwrap().deposit_micros, 3 * SECOND);
    assert_eq!(chain.held(), 106 * SECOND);
    // A least deposit above what is on offer is refused.
    let mut payload = sell_order(10 * SECOND, &[script(3)], 1, 0);
    payload["min_deposit_micros"] = json!((11 * SECOND).to_string());
    chain.refuse(chain.act(SELLER, market::ORDER, payload), "the least deposit is at most what is on offer");
    chain.audit();
}

#[test]
fn the_payer_can_release_and_the_owner_can_settle_without_bitcoin() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(2)], 1, 50_000)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 60 * SECOND, BUYER)));
    assert_eq!(chain.index(BUYER).fills, vec![1, 2]);
    // The seller does not release, the buyer does not settle.
    chain.refuse(chain.act(SELLER, market::RELEASE, json!({"fill": "1"})), "only the account its seconds go to");
    chain.refuse(chain.act(BUYER, market::SETTLE, json!({"fill": "1"})), "only the owner");
    let seller = chain.balance(SELLER);
    let buyer = chain.balance(BUYER);
    // Released: the seconds are on offer again, the deposit is the seller's.
    chain.accept(chain.act(BUYER, market::RELEASE, json!({"fill": "1"})));
    assert_eq!(chain.balance(BUYER), buyer - fee);
    assert_eq!(chain.balance(SELLER), seller + 2 * SECOND);
    assert_eq!(chain.order(1).unwrap().amount_micros, 40 * SECOND);
    // Settled: the buyer has the seconds and the deposit, and no trade is
    // counted, for the chain saw no payment.
    chain.accept(chain.act(SELLER, market::SETTLE, json!({"fill": "2"})));
    assert_eq!(chain.balance(BUYER), buyer - fee + 60 * SECOND + 3 * SECOND);
    assert_eq!(chain.balance(SELLER), seller + 2 * SECOND - fee);
    assert_eq!(chain.summary().trades, 0);
    assert_eq!(chain.held(), 40 * SECOND);
    assert_eq!(chain.index(BUYER).fills, Vec::<u64>::new());
    // A payment that arrives after the settle cannot be turned into
    // seconds a second time: the script has served.
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)), TAKEN);
    chain.audit();
}

#[test]
fn a_cancelled_order_gives_back_what_is_on_offer_and_goes_with_its_last_fill() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    let seller = chain.balance(SELLER);
    // The order: three fees (itself and two scripts). The cancel: one.
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(4)], 1, 0)));
    chain.refuse(chain.act(BUYER, market::CANCEL, json!({"order": "1"})), "only its owner");
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 30 * SECOND, BUYER)));
    chain.accept(chain.act(SELLER, market::CANCEL, json!({"order": "1"})));
    // 70 seconds are back; the order stays, closed, for its fill.
    assert_eq!(chain.balance(SELLER), seller - 30 * SECOND - 4 * fee);
    let order = chain.order(1).unwrap();
    assert!(!order.open && order.amount_micros == 0);
    assert_eq!(chain.held(), 30 * SECOND);
    chain.refuse(chain.act(SELLER, market::CANCEL, json!({"order": "1"})), "only its owner cancels an open order");
    chain.refuse(chain.act(ANYONE, market::TAKE, take(1, 1, ANYONE)), "not an open sell order");
    // Its scripts still serve it.
    chain.refuse(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(4)], 1, 0)), USED);
    chain.audit();
    // The fill is released: its seconds go to the owner, not back on offer,
    // and the order goes.
    chain.accept(chain.act(BUYER, market::RELEASE, json!({"fill": "1"})));
    assert_eq!(chain.balance(SELLER), seller - 4 * fee);
    assert!(chain.order(1).is_none());
    assert_eq!(chain.held(), 0);
    assert_eq!(chain.summary().orders, 0);
    // The script that had a fill has served. The one that had none is free.
    chain.refuse(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(1)], 1, 0)), USED);
    chain.accept(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(4)], 1, 0)));
    // An order without a fill goes at once when it is cancelled, and its
    // script is free again.
    chain.accept(chain.act(OTHER, market::CANCEL, json!({"order": "2"})));
    assert!(chain.order(2).is_none());
    chain.accept(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(4)], 1, 0)));
    chain.audit();
}

#[test]
fn a_buy_order_locks_a_bond_and_a_seller_who_fills_it_is_paid_or_compensated() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    let buyer = chain.balance(BUYER);
    let seller = chain.balance(SELLER);
    // The buyer wants 50 seconds, waits for at most 3 confirmations, locks
    // a bond of 10%, and pays to one form of address.
    chain.accept(chain.act(BUYER, market::ORDER, buy_order(50 * SECOND, 3, 100_000)));
    assert_eq!(chain.balance(BUYER), buyer - 5 * SECOND - fee);
    assert_eq!(chain.held(), 5 * SECOND);
    // More confirmations than the buyer waits for; a form of address the
    // buyer does not pay to.
    chain.refuse(chain.act(SELLER, market::SELL, sale(1, 20 * SECOND, 4, script(7))), "confirmations asked");
    let taproot = hex::encode([vec![0x51, 0x20], vec![7; 32]].concat());
    chain.refuse(chain.act(SELLER, market::SELL, sale(1, 20 * SECOND, 2, taproot)), "does not pay to this form");
    chain.accept(chain.act(SELLER, market::SELL, sale(1, 20 * SECOND, 2, script(7))));
    let fill = chain.fill(1).unwrap();
    assert_eq!((fill.owner, fill.payer, fill.to), (SELLER, BUYER, BUYER));
    assert_eq!(fill.deposit_micros, 2 * SECOND);
    assert_eq!(chain.balance(SELLER), seller - 20 * SECOND - fee);
    let order = chain.order(1).unwrap();
    assert_eq!((order.amount_micros, order.bond_micros, order.fills), (30 * SECOND, 3 * SECOND, Some(1)));
    assert_eq!(chain.held(), 25 * SECOND);
    assert_eq!(chain.index(BUYER).fills, vec![1]);
    // The script serves this fill and nothing else.
    chain.refuse(chain.act(OTHER, market::SELL, sale(1, 10 * SECOND, 2, script(7))), USED);
    chain.audit();
    // The buyer pays the 5,000 satoshis; two confirmations later the proof
    // gives them the seconds and their bond's part.
    let payment = chain.pay(&script(7), 5_000, 2);
    chain.bitcoin_blocks(1);
    chain.accept(chain.proof(ANYONE, 1, &payment));
    assert_eq!(chain.balance(BUYER), buyer - 5 * SECOND - fee + 20 * SECOND + 2 * SECOND);
    assert_eq!(chain.order(1).unwrap().fills, Some(0));
    assert_eq!(chain.held(), 3 * SECOND);
    // A second seller is not paid: after the time to pay and the grace
    // they have their seconds back, and the bond's part with them.
    let other = chain.balance(OTHER);
    chain.accept(chain.act(OTHER, market::SELL, sale(1, 30 * SECOND, 1, script(8))));
    assert_eq!(chain.fill(2).unwrap().deposit_micros, 3 * SECOND);
    // Nothing is on offer any more, and the order stays for its fill.
    let order = chain.order(1).unwrap();
    assert_eq!((order.amount_micros, order.bond_micros, order.open), (0, 0, true));
    chain.bitcoin_blocks(6);
    chain.wait(44);
    chain.accept(chain.act(ANYONE, market::EXPIRE, json!({"fill": "2"})));
    assert_eq!(chain.balance(OTHER), other - fee + 3 * SECOND);
    assert!(chain.order(1).is_none());
    assert_eq!(chain.held(), 0);
    assert_eq!(chain.summary().trades, 1);
    // The scripts of the two fills have served.
    chain.refuse(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(8)], 1, 0)), USED);
    chain.refuse(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(7)], 1, 0)), USED);
    chain.audit();
}

#[test]
fn what_an_order_and_a_fill_must_be() {
    let mut chain = Chain::new();
    // No Bitcoin header yet but the genesis block, which is years old:
    // orders can be made, fills cannot.
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1)], 1, 0)));
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)), "stale");
    chain.bitcoin_blocks(1);
    let order = |change: &dyn Fn(&mut Value)| {
        let mut payload = sell_order(100 * SECOND, &[script(3)], 1, 0);
        change(&mut payload);
        payload
    };
    let seventeen: Vec<String> = (100..117).map(script).collect();
    let cases: [(&dyn Fn(&mut Value), &str); 15] = [
        (&|p| p["price"] = json!("0"), "a price is from 1"),
        (&|p| p["amount_micros"] = json!("0"), "at least a microsecond"),
        (&|p| p["min_sats"] = json!("25001"), "worth at least its smallest trade"),
        (&|p| p["min_sats"] = json!("0"), "worth at least its smallest trade"),
        (&|p| p["confirmations"] = json!("0"), "order bounds"),
        (&|p| p["confirmations"] = json!("101"), "order bounds"),
        (&|p| p["pay_blocks"] = json!("0"), "order bounds"),
        (&|p| p["pay_blocks"] = json!("145"), "order bounds"),
        (&|p| p["deposit_ppm"] = json!("1000001"), "order bounds"),
        (&|p| p["scripts"] = json!([]), "sell order shape"),
        (&|p| p["scripts"] = json!(seventeen), "at most sixteen receiving scripts"),
        (&|p| p["scripts"] = json!(["6a0100"]), "five standard forms"),
        (&|p| p["scripts"] = json!([script(1)]), USED),
        (&|p| p["forms"] = json!(["p2tr"]), "lists scripts, not forms"),
        (&|p| p["forms"] = Value::Null, "null"),
    ];
    for (change, why) in cases {
        chain.refuse(chain.act(OTHER, market::ORDER, order(change)), why);
    }
    // The same script twice in one order, and an uppercase script.
    chain.refuse(chain.act(OTHER, market::ORDER, sell_order(100 * SECOND, &[script(3), script(3)], 1, 0)), USED);
    chain.refuse(
        chain.act(OTHER, market::ORDER, sell_order(100 * SECOND, &[script(0xab).to_uppercase()], 1, 0)),
        "five standard forms",
    );
    // A sell order names its least deposit and lists its scripts; a buy
    // order does neither, and lists forms that exist, in order, each once.
    let mut payload = sell_order(10 * SECOND, &[script(4)], 1, 0);
    payload.as_object_mut().unwrap().remove("scripts");
    chain.refuse(chain.act(OTHER, market::ORDER, payload), "lists its receiving scripts");
    let mut payload = sell_order(10 * SECOND, &[script(4)], 1, 0);
    payload.as_object_mut().unwrap().remove("min_deposit_micros");
    chain.refuse(chain.act(OTHER, market::ORDER, payload), "names the least deposit");
    let mut payload = buy_order(10 * SECOND, 1, 0);
    payload["scripts"] = json!([script(4)]);
    chain.refuse(chain.act(OTHER, market::ORDER, payload), "lists no script");
    let mut payload = buy_order(10 * SECOND, 1, 0);
    payload["scripts"] = Value::Null;
    chain.refuse(chain.act(OTHER, market::ORDER, payload), "null");
    let mut payload = buy_order(10 * SECOND, 1, 0);
    payload["min_deposit_micros"] = json!("0");
    chain.refuse(chain.act(OTHER, market::ORDER, payload), "names no least deposit");
    for forms in [json!([]), json!(["p2wpkh", "p2tr"]), json!(["p2tr", "p2tr"]), json!(["p2pk"])] {
        let mut payload = buy_order(10 * SECOND, 1, 0);
        payload["forms"] = forms;
        chain.refuse(chain.act(OTHER, market::ORDER, payload), "buy order shape");
    }
    let mut payload = buy_order(10 * SECOND, 1, 0);
    payload.as_object_mut().unwrap().remove("forms");
    chain.refuse(chain.act(OTHER, market::ORDER, payload), "lists the forms");
    // More than the account holds.
    chain.refuse(
        chain.act(OTHER, market::ORDER, sell_order(5_000 * SECOND, &[script(4)], 1, 0)),
        "insufficient",
    );
    // Fills: more than is on offer, the wrong price, a smaller trade than
    // the order's smallest, a rest that nobody could take, an account that
    // does not exist.
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 101 * SECOND, BUYER)), "at most what is on offer");
    let mut payload = take(1, 40 * SECOND, BUYER);
    payload["sats"] = json!("9999");
    chain.refuse(chain.act(BUYER, market::TAKE, payload), "the satoshis named are the price");
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 3 * SECOND, BUYER)), "smallest trade");
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 97 * SECOND, BUYER)), "leaves nothing on offer");
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, 4_000)), "account");
    chain.refuse(chain.act(BUYER, market::TAKE, take(9, 40 * SECOND, BUYER)), "no such order");
    // One script, one fill.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)));
    chain.refuse(chain.act(ANYONE, market::TAKE, take(1, 40 * SECOND, ANYONE)), TAKEN);
    // A proof of a payment to another script; a proof that names a block
    // it is not for.
    let elsewhere = chain.pay(&script(2), 10_000, 6);
    chain.refuse(chain.proof(ANYONE, 1, &elsewhere), "script mismatch");
    let mut misplaced = chain.pay(&script(1), 10_000, 7);
    let right = misplaced["block_hash"].clone();
    misplaced["block_hash"] = elsewhere["block_hash"].clone();
    chain.refuse(chain.proof(ANYONE, 1, &misplaced), "block mismatch");
    // A payload with a field too many.
    chain.refuse(chain.act(ANYONE, market::EXPIRE, json!({"fill": "1", "order": "1"})), "names a fill");
    // The proof as it is: accepted.
    misplaced["block_hash"] = right;
    chain.accept(chain.proof(ANYONE, 1, &misplaced));
    chain.audit();
}

#[test]
fn a_rest_smaller_than_the_smallest_trade_can_be_taken_whole() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    // 10 seconds, 2,500 satoshis, and no trade below 1,000.
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(10 * SECOND, &[script(1), script(2), script(3)], 1, 0)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 10 * SECOND, BUYER)));
    // The buyer pays 2,000 of the 2,500 satoshis and gives the rest up: 2
    // seconds go back on offer, worth 500 satoshis, less than the smallest
    // trade.
    let payment = chain.pay(&script(1), 2_000, 1);
    chain.accept(chain.proof(BUYER, 1, &payment));
    assert_eq!(chain.fill(1).unwrap().amount_micros, 2 * SECOND);
    chain.accept(chain.act(BUYER, market::RELEASE, json!({"fill": "1"})));
    assert_eq!(chain.order(1).unwrap().amount_micros, 2 * SECOND);
    // A part of the rest is refused; all of it is taken.
    chain.refuse(chain.act(ANYONE, market::TAKE, take(1, SECOND, ANYONE)), "smallest trade");
    chain.accept(chain.act(ANYONE, market::TAKE, take(1, 2 * SECOND, ANYONE)));
    assert_eq!(chain.fill(2).unwrap().sats, 500);
    chain.audit();
}

#[test]
fn a_network_without_the_market_refuses_its_kinds_and_keeps_no_row() {
    let mut chain = Chain::with(false);
    assert!(chain.engine.meta().unwrap().market_micros.is_none());
    assert!(chain.row(market::META_KEY).is_none());
    chain.refuse(
        chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1)], 1, 0)),
        "this network has no market",
    );
    chain.refuse(chain.act(SELLER, market::CANCEL, json!({"order": "1"})), "this network has no market");
    chain.refuse(
        chain.act(SELLER, market::ADDRESSES, json!({"order": "1", "scripts": [script(1)]})),
        "this network has no market",
    );
    // The header relay of a network with an auction works as before, and
    // writes no clock of heights.
    chain.bitcoin_blocks(2);
    assert!(chain.row(market::HEIGHTS_KEY).is_none());
    chain.audit();
}

#[test]
fn a_network_with_the_market_needs_waits_that_survive_a_stop() {
    let mut genesis = genesis_v5();
    genesis.market = true;
    let error = genesis.validate().unwrap_err().to_string();
    assert!(error.contains("waits that survive a stop"), "{error}");
    genesis.waits_survive_stops = true;
    genesis.validate().unwrap();
}

#[test]
fn the_clock_of_heights_records_each_batch_that_raises_the_best_height() {
    let mut chain = Chain::new();
    let heights = |chain: &Chain| -> Heights {
        serde_json::from_slice(&chain.row(market::HEIGHTS_KEY).unwrap()).unwrap()
    };
    assert_eq!(heights(&chain).entries.len(), 1);
    assert_eq!((heights(&chain).entries[0].height, heights(&chain).entries[0].at), (0, 0));
    chain.bitcoin_blocks(3);
    chain.bitcoin_blocks(1);
    let entries = heights(&chain).entries;
    assert_eq!(entries.iter().map(|e| e.height).collect::<Vec<_>>(), vec![0, 3, 4]);
    assert!(entries[1].at > 0 && entries[2].at > entries[1].at);
    chain.audit();
}

#[test]
fn candles_hold_the_prices_of_an_hour_of_proven_trades() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let priced = |price: u64, receiving: &[String]| {
        let mut payload = sell_order(100 * SECOND, receiving, 1, 0);
        payload["price"] = json!(price.to_string());
        payload
    };
    chain.accept(chain.act(SELLER, market::ORDER, priced(PRICE, &[script(1), script(3)])));
    chain.accept(chain.act(SELLER, market::ORDER, priced(2 * PRICE, &[script(2)])));
    let mut hours = Vec::new();
    for (order, price, seed) in [(1u64, PRICE, 1u8), (2, 2 * PRICE, 2), (1, PRICE, 3)] {
        let mut payload = take(order, 10 * SECOND, BUYER);
        payload["sats"] = json!(market::sats(10 * SECOND, price).unwrap().to_string());
        chain.accept(chain.act(BUYER, market::TAKE, payload));
        let fill = chain.summary().next_fill - 1;
        let payment = chain.pay(&chain.fill(fill).unwrap().script, market::sats(10 * SECOND, price).unwrap(), seed);
        chain.accept(chain.proof(ANYONE, fill, &payment));
        let meta = chain.engine.meta().unwrap();
        hours.push(meta.elapsed_micros().unwrap() / (60 * SECOND));
    }
    // In the laboratory an hour is a minute; the three trades above took a
    // few seconds each, so at most two candles hold them.
    let mut trades = 0;
    let mut seen = std::collections::BTreeSet::new();
    for hour in hours {
        if !seen.insert(hour) {
            continue;
        }
        let candle: Candle = serde_json::from_slice(&chain.row(&market::candle_key(hour)).unwrap()).unwrap();
        assert!(candle.low == PRICE || candle.low == 2 * PRICE);
        assert!(candle.low <= candle.open && candle.low <= candle.close && candle.high >= candle.open);
        trades += candle.trades;
    }
    assert_eq!(trades, 3);
    let state = chain.summary();
    assert_eq!((state.trades, state.seconds_micros, state.sats), (3, 30 * SECOND, 2_500 + 5_000 + 2_500));
    assert_eq!(state.last_price, Some(PRICE));
    chain.audit();
}

/// The seller's account gets the account security rules: a sign-in key, a
/// spend key (seed 61) and three recovery keys, with a daily limit. Its
/// one key that did everything is no key of it any more.
fn secure_seller(chain: &mut Chain, daily_limit: u64) {
    use ed25519_dalek::Signer;
    use timecurrency_v5::security::{self, Role};
    let joins = |seed: u8, role: Role, name: &str| {
        let proof = key(seed).sign(&security::key_message(&chain.network, SELLER, role, &pk(seed)).unwrap());
        json!({"public_key": pk(seed), "role": name, "proof": hex::encode(proof.to_bytes())})
    };
    let mut keys = vec![
        joins(60, Role::Signin, "signin"),
        joins(61, Role::Spend, "spend"),
        joins(62, Role::Recover, "recover"),
        joins(63, Role::Recover, "recover"),
        joins(64, Role::Recover, "recover"),
    ];
    keys.sort_by(|a, b| a["public_key"].as_str().cmp(&b["public_key"].as_str()));
    let payload = json!({
        "keys": keys,
        "policy": {
            "threshold": "2",
            "daily_limit_micros": daily_limit.to_string(),
            "delay_seconds": "60",
            "freeze_seconds": "120",
        },
    });
    let tx = chain.act(SELLER, security::SECURE, payload);
    chain.accept(tx);
}

#[test]
fn a_settle_a_release_and_new_scripts_count_against_the_daily_limit_of_a_secured_account() {
    const LIMIT: &str = "over the daily limit";
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    secure_seller(&mut chain, 50 * SECOND);
    // 31 of the day's 50 seconds go into a sell order.
    chain.accept(chain.act_with(SELLER, 61, market::ORDER, sell_order(31 * SECOND, &[script(1), script(2)], 1, 0)));
    // More than what is left of the day is refused, as for a payment.
    chain.refuse(
        chain.act_with(SELLER, 61, market::ORDER, sell_order(20 * SECOND, &[script(3)], 1, 0)),
        LIMIT,
    );
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 11 * SECOND, BUYER)));
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 20 * SECOND, BUYER)));
    // Whoever holds the spend key and an accomplice's fill cannot hand the
    // 20 seconds over at once: a settle counts like a payment, and the day
    // has less than 19 seconds left.
    let buyer = chain.balance(BUYER);
    chain.refuse(chain.act_with(SELLER, 61, market::SETTLE, json!({"fill": "2"})), LIMIT);
    assert_eq!(chain.balance(BUYER), buyer);
    // Nor can they point the order at an address of their own: new scripts
    // count what the order holds, on offer and in its fills (31 seconds),
    // like a new order.
    chain.refuse(
        chain.act_with(SELLER, 61, market::ADDRESSES, json!({"order": "1", "scripts": [script(9)]})),
        LIMIT,
    );
    // 11 seconds fit.
    chain.accept(chain.act_with(SELLER, 61, market::SETTLE, json!({"fill": "1"})));
    assert_eq!(chain.balance(BUYER), buyer + 11 * SECOND);
    // The secured account as a buyer, from a seller who asks no deposit:
    // taking 9 seconds costs a fee. Giving the purchase up counts the 9
    // seconds it would have brought, more than is left of the day (less
    // than 8): whoever holds the spend key cannot end the owner's purchase
    // while the owner's bitcoin is on its way.
    chain.accept(chain.act(OTHER, market::ORDER, sell_order(9 * SECOND, &[script(5)], 1, 0)));
    chain.accept(chain.act_with(SELLER, 61, market::TAKE, take(2, 9 * SECOND, SELLER)));
    assert_eq!(chain.fill(3).unwrap().deposit_micros, 0);
    chain.refuse(chain.act_with(SELLER, 61, market::RELEASE, json!({"fill": "3"})), LIMIT);
    assert!(chain.fill(3).is_some());
    // The payment is proven by anyone.
    let full = chain.pay(&script(5), 2_250, 10);
    let seller = chain.balance(SELLER);
    chain.accept(chain.proof(ANYONE, 3, &full));
    assert_eq!(chain.balance(SELLER), seller + 9 * SECOND);
    chain.audit();
}

#[test]
fn an_order_stands_while_the_key_that_made_it_is_a_spending_key_of_its_owner() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let fee = chain.fee();
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(20 * SECOND, &[script(1)], 1, 0)));
    assert_eq!(chain.order(1).unwrap().key, pk(SELLER as u8 + 1));
    // The account adopts the security rules: the key that made the order
    // is replaced by a spend key (and others that cannot spend).
    secure_seller(&mut chain, 500 * SECOND);
    // Whoever made the order, the owner or someone who held the old key:
    // it takes nothing more.
    chain.refuse(chain.act(BUYER, market::TAKE, take(1, 20 * SECOND, BUYER)), "no longer a spending key of its owner");
    // The owner gives it a new receiving script with the new key, and the
    // order answers for that key. No seconds move; the fee is paid once
    // more for the script.
    let held = chain.held();
    let seller = chain.balance(SELLER);
    chain.refuse(
        chain.act(BUYER, market::ADDRESSES, json!({"order": "1", "scripts": [script(2)]})),
        "only its owner gives an open sell order new receiving scripts",
    );
    chain.refuse(
        chain.act_with(SELLER, 61, market::ADDRESSES, json!({"order": "1", "scripts": []})),
        "one to sixteen new receiving scripts",
    );
    chain.refuse(chain.act_with(SELLER, 61, market::ADDRESSES, json!({"order": "1", "scripts": [script(1)]})), USED);
    chain.accept(chain.act_with(SELLER, 61, market::ADDRESSES, json!({"order": "1", "scripts": [script(2)]})));
    assert_eq!(chain.held(), held);
    assert_eq!(chain.balance(SELLER), seller - 2 * fee);
    assert_eq!(chain.order(1).unwrap().key, pk(61));
    assert_eq!(chain.order(1).unwrap().scripts.unwrap().len(), 2);
    // A fill is taken and given up: its script has served, and the seconds
    // are on offer with one script left.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 20 * SECOND, BUYER)));
    assert_eq!(chain.fill(1).unwrap().script, script(1));
    chain.accept(chain.act(BUYER, market::RELEASE, json!({"fill": "1"})));
    // New scripts take the place of those that have served.
    let fifteen: Vec<String> = (10..25).map(script).collect();
    chain.accept(chain.act_with(SELLER, 61, market::ADDRESSES, json!({"order": "1", "scripts": fifteen})));
    let slots = chain.order(1).unwrap().scripts.unwrap();
    assert_eq!(slots.len(), 16);
    assert!(slots.iter().all(|slot| !slot.used && slot.fill.is_none()));
    assert_eq!(slots[0].script, script(2));
    // Sixteen is all an order lists at a time.
    chain.refuse(
        chain.act_with(SELLER, 61, market::ADDRESSES, json!({"order": "1", "scripts": [script(30)]})),
        "at most sixteen receiving scripts",
    );
    // The script that served stays used, for this order and every other.
    chain.refuse(chain.act(OTHER, market::ORDER, sell_order(10 * SECOND, &[script(1)], 1, 0)), USED);
    // A buy order has no scripts to renew.
    chain.accept(chain.act(BUYER, market::ORDER, buy_order(10 * SECOND, 1, 0)));
    chain.refuse(
        chain.act(BUYER, market::ADDRESSES, json!({"order": "2", "scripts": [script(31)]})),
        "only its owner gives an open sell order new receiving scripts",
    );
    chain.audit();
}

#[test]
fn many_small_parts_never_give_more_than_was_locked_and_the_recount_holds_after_each() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    // A price that does not divide evenly, an amount that is not round, a
    // deposit of an odd share.
    let price = 333_333_337u64;
    let amount = 97 * SECOND + 123_457;
    let mut order = sell_order(amount, &[script(1)], 1, 77_777);
    order["price"] = json!(price.to_string());
    chain.accept(chain.act(SELLER, market::ORDER, order));
    let agreed = market::sats(amount, price).unwrap();
    let mut taking = take(1, amount, BUYER);
    taking["sats"] = json!(agreed.to_string());
    let buyer = chain.balance(BUYER);
    chain.accept(chain.act(BUYER, market::TAKE, taking));
    let fee = chain.fee();
    let deposit = chain.fill(1).unwrap().deposit_micros;
    assert_eq!(chain.balance(BUYER), buyer - fee - deposit);
    // Parts of 1,000 to 1,998 satoshis, as a fixed sequence that looks
    // random, until less than 2,000 are left.
    let mut paid = 0u64;
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut seed = 20u8;
    while agreed - paid >= 2_000 && seed < 60 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let part = 1_000 + state % 999;
        let before = chain.fill(1).unwrap();
        let evidence = chain.pay(&script(1), part, seed);
        seed += 1;
        chain.accept(chain.proof(ANYONE, 1, &evidence));
        paid += part;
        let after = chain.fill(1).unwrap();
        // What is still to pay falls by exactly what was paid.
        assert_eq!(after.sats, before.sats - part);
        assert_eq!(after.sats, agreed - paid);
        // Seconds and deposit only ever leave the fill, and never more
        // than the part's share.
        let delivered = before.amount_micros - after.amount_micros;
        assert!(u128::from(delivered) * u128::from(before.sats) <= u128::from(before.amount_micros) * u128::from(part));
        assert!(after.deposit_micros <= before.deposit_micros);
        chain.audit();
    }
    assert!(seed > 30, "the walk had steps");
    // The rest, to the satoshi.
    let rest = agreed - paid;
    let evidence = chain.pay(&script(1), rest, seed);
    chain.accept(chain.proof(ANYONE, 1, &evidence));
    assert!(chain.fill(1).is_none() && chain.order(1).is_none());
    // The buyer has all the seconds, all the deposit, and has paid the
    // agreed satoshis and not one more.
    assert_eq!(chain.balance(BUYER), buyer - fee + amount);
    assert_eq!(chain.summary().sats, agreed);
    assert_eq!(chain.summary().seconds_micros, amount);
    assert_eq!(chain.held(), 0);
    chain.audit();
}

#[test]
fn a_payment_that_came_a_little_short_is_not_lost_on_a_fill_of_the_smallest_size() {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    // An order that sells all or nothing: its smallest trade is its value,
    // 25,000 satoshis for 100 seconds.
    let mut order = sell_order(100 * SECOND, &[script(1)], 1, 0);
    order["min_sats"] = json!("25000");
    chain.accept(chain.act(SELLER, market::ORDER, order));
    let buyer = chain.balance(BUYER);
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 100 * SECOND, BUYER)));
    let fee = chain.fee();
    // The exchange keeps 300 satoshis: 24,700 arrive. Less than the
    // smallest trade and less than the fill needs, and more than half of
    // it: it counts.
    let short = chain.pay(&script(1), 24_700, 3);
    chain.accept(chain.proof(ANYONE, 1, &short));
    let fill = chain.fill(1).unwrap();
    assert_eq!(fill.sats, 300);
    assert_eq!(fill.amount_micros, 100 * SECOND - 98_800_000);
    assert_eq!(chain.balance(BUYER), buyer - fee + 98_800_000);
    // The 300 that are missing are all the fill still needs: they count.
    // Less than half of them would not.
    let crumb = chain.pay(&script(1), 149, 4);
    chain.refuse(chain.proof(ANYONE, 1, &crumb), "half of what the fill still needs");
    let rest = chain.pay(&script(1), 300, 5);
    chain.accept(chain.proof(ANYONE, 1, &rest));
    assert!(chain.fill(1).is_none() && chain.order(1).is_none());
    assert_eq!(chain.balance(BUYER), buyer - fee + 100 * SECOND);
    assert_eq!(chain.summary().sats, 25_000);
    chain.audit();
}

#[test]
fn a_network_with_the_market_keeps_the_header_chains_numbers_the_rules_quote() {
    let market = || {
        let mut genesis = genesis_v5();
        genesis.market = true;
        genesis.waits_survive_stops = true;
        genesis
    };
    market().validate().unwrap();
    let mut genesis = market();
    genesis.bitcoin.max_fork_tips = 1;
    assert!(genesis.validate().is_err());
    let mut genesis = market();
    genesis.bitcoin.max_reorg = 288;
    genesis.bitcoin.retention = 8192;
    assert!(genesis.validate().unwrap_err().to_string().contains("reorganisation bound of 144"));
    let mut genesis = market();
    genesis.bitcoin.max_tip_age_secs = 86_400;
    assert!(genesis.validate().is_err());
    // A network without the market may choose them as before.
    let mut genesis = genesis_v5();
    genesis.bitcoin.max_tip_age_secs = 86_400;
    genesis.validate().unwrap();
}

/// Other languages build and sign the market's actions too: the SDK
/// (`client-v4/time-sdk.js`) and the Python client (`clients/python/`).
/// `spec/market-vectors.json` holds them to the engine. This is its text: one
/// scenario in which every kind from 50 to 58 is signed by `wire::sign` and
/// accepted here, with the signer's seed, the exact bytes and the fee the
/// engine took; the price arithmetic at its edges; the form of scripts that
/// are standard and of some that are not, with the address of each standard
/// one; Bitcoin transactions with and without their witness data; and Merkle
/// proofs with what each proves.
fn market_vectors() -> String {
    use bitcoin_bridge::bitcoin::{Address, Network, consensus::deserialize};
    /// Signs, has the engine accept, and records an action. `moved` is
    /// what the action itself adds to the sender's balance (seconds locked
    /// are negative); the rest of what the balance lost is the fee.
    fn send(chain: &mut Chain, actions: &mut Vec<Value>, name: &str, from: u64, kind: u8, payload: Value, moved: i64) {
        let row = chain.account(from);
        let signed = chain.act(from, kind, payload.clone());
        chain.accept(signed.clone());
        let paid = row.balance as i64 + moved - chain.balance(from) as i64;
        let fee = chain.fee() as i64;
        assert!(paid >= fee && paid % fee == 0 && paid / fee < 1_000, "{name}: {paid} is not a number of fees");
        actions.push(json!({
            "name": name,
            "kind": kind,
            "from": from.to_string(),
            "nonce": (row.nonce + 1).to_string(),
            "auth_epoch": row.auth_epoch.to_string(),
            "seed_hex": hex::encode([from as u8 + 1; 32]),
            "public_key": pk(from as u8 + 1),
            "payload": payload,
            "payload_json": serde_json::to_string(&payload).unwrap(),
            "signed_hex": hex::encode(&signed),
            "network_fee_micros": fee.to_string(),
            "fee_micros": paid.to_string(),
        }));
    }
    /// The payload of a proof for `fill`, and what a Bitcoin node gives for
    /// it: the two transactions with their witness data. (A coinbase of a
    /// block with witness data carries one witness item of 32 bytes.)
    fn proven(chain: &mut Chain, fill: u64, tx: &Transaction) -> (Value, Value) {
        let mut payload = chain.confirm(tx);
        payload["fill"] = json!(fill.to_string());
        let mut coinbase: Transaction = deserialize(&hex::decode(payload["coinbase"].as_str().unwrap()).unwrap()).unwrap();
        coinbase.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
        let node = json!({"coinbase": hex::encode(serialize(&coinbase)), "transaction": hex::encode(serialize(tx))});
        assert_ne!(node["coinbase"], payload["coinbase"]);
        assert_ne!(node["transaction"], payload["transaction"]);
        (payload, node)
    }
    let s = SECOND as i64;
    let p2pkh = hex::encode([vec![0x76, 0xa9, 0x14], vec![0x11; 20], vec![0x88, 0xac]].concat());
    let p2sh = hex::encode([vec![0xa9, 0x14], vec![0x22; 20], vec![0x87]].concat());
    let p2wsh = hex::encode([vec![0x00, 0x20], vec![0x33; 32]].concat());
    let p2tr = hex::encode([vec![0x51, 0x20], vec![0x44; 32]].concat());
    let (signature, public, schnorr): (&[u8], &[u8], &[u8]) = (&[0x30; 72], &[0x02; 33], &[0x5c; 64]);
    let mut chain = Chain::new();
    chain.bitcoin_blocks(1);
    let mut actions = Vec::new();
    // Kind 50, a sell order: 100 seconds, three scripts of three forms, a
    // deposit of 5% and of a quarter of a second at least. It pays the fee
    // once, and once more for each script.
    let mut payload = sell_order(100 * SECOND, &[script(1), p2tr.clone(), p2pkh.clone()], 1, 50_000);
    payload["min_deposit_micros"] = json!("250000");
    send(&mut chain, &mut actions, "sell_order", SELLER, market::ORDER, payload, -100 * s);
    // Kind 50, a buy order: 50 seconds, a bond of 10%, four forms.
    let mut payload = buy_order(50 * SECOND, 3, 100_000);
    payload["forms"] = json!(["p2sh", "p2tr", "p2wpkh", "p2wsh"]);
    send(&mut chain, &mut actions, "buy_order", BUYER, market::ORDER, payload, -5 * s);
    // Kind 58: two more scripts for the sell order.
    send(
        &mut chain,
        &mut actions,
        "new_scripts",
        SELLER,
        market::ADDRESSES,
        json!({"order": "1", "scripts": [p2sh.clone(), script(2)]}),
        0,
    );
    // Kind 52: a fill made for another account; the sender locks 2 seconds.
    send(&mut chain, &mut actions, "take_for_another", BUYER, market::TAKE, take(1, 40 * SECOND, OTHER), -2 * s);
    // Kind 53: 20 seconds sold to the buy order, two confirmations asked.
    send(&mut chain, &mut actions, "sell", SELLER, market::SELL, sale(2, 20 * SECOND, 2, p2wsh.clone()), -20 * s);
    // Kind 54: 4,000 of the first fill's 10,000 satoshis arrive, and anyone
    // proves it. The fill goes on.
    let mut part = payment(&script(1), 4_000, 9);
    part.input[0].witness = Witness::from_slice(&[signature, public]);
    let (payload, node) = proven(&mut chain, 1, &part);
    let held = |fill: &Fill| {
        json!({
            "amount_micros": fill.amount_micros.to_string(),
            "deposit_micros": fill.deposit_micros.to_string(),
            "sats": fill.sats.to_string(),
        })
    };
    let before = held(&chain.fill(1).unwrap());
    send(&mut chain, &mut actions, "proof_of_a_part", ANYONE, market::PROOF, payload, 0);
    actions.last_mut().unwrap()["bitcoin_node"] = node;
    // What the fill held before the part and holds after it: the part buys
    // floor(amount × paid / sats), and what is still to pay falls by what
    // was paid.
    actions.last_mut().unwrap()["fill"] = json!({"before": before, "paid_sats": "4000", "after": held(&chain.fill(1).unwrap())});
    assert_eq!(chain.fill(1).unwrap().sats, 6_000);
    // Kind 54 again: the rest, in a transaction with eighty-one other
    // outputs, whose proof is several times as large.
    let mut rest = payment(&script(1), 6_000, 10);
    rest.input[0].witness = Witness::from_slice(&[schnorr]);
    let other = |sats: u64, receiving: &str| TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: ScriptBuf::from_bytes(hex::decode(receiving).unwrap()),
    };
    rest.output.insert(0, other(700, &p2tr));
    rest.output.extend((0..80u8).map(|index| other(1_000 + u64::from(index), &script(100 + index))));
    let (mut payload, node) = proven(&mut chain, 1, &rest);
    payload["vout"] = json!("1");
    assert!(serde_json::to_vec(&payload).unwrap().len() > 4_096);
    send(&mut chain, &mut actions, "proof", ANYONE, market::PROOF, payload, 0);
    actions.last_mut().unwrap()["bitcoin_node"] = node;
    assert!(chain.fill(1).is_none());
    // Kind 52 again, for the sender, and kind 56: the account the seconds
    // would go to gives the fill up.
    send(&mut chain, &mut actions, "take", BUYER, market::TAKE, take(1, 20 * SECOND, BUYER), -s);
    assert_eq!(chain.fill(3).unwrap().script, p2tr);
    send(&mut chain, &mut actions, "release", BUYER, market::RELEASE, json!({"fill": "3"}), 0);
    // Kind 57: the seller hands the seconds of the second fill over.
    send(&mut chain, &mut actions, "settle", SELLER, market::SETTLE, json!({"fill": "2"}), 0);
    // Kind 53 for all that is left of the buy order, which is not paid, and
    // kind 55 when its time has passed.
    send(&mut chain, &mut actions, "sell_the_rest", OTHER, market::SELL, sale(2, 30 * SECOND, 1, script(8)), -30 * s);
    chain.bitcoin_blocks(6);
    chain.wait(50);
    send(&mut chain, &mut actions, "expire", ANYONE, market::EXPIRE, json!({"fill": "4"}), 0);
    // Kind 51: the seller takes back the 60 seconds the sell order still offers.
    send(&mut chain, &mut actions, "cancel", SELLER, market::CANCEL, json!({"order": "1"}), 60 * s);
    assert!(chain.order(1).is_none() && chain.order(2).is_none());
    assert_eq!(chain.held(), 0);
    chain.audit();
    let kinds: std::collections::BTreeSet<u64> = actions.iter().map(|action| action["kind"].as_u64().unwrap()).collect();
    assert_eq!(kinds, (50..=58).collect::<std::collections::BTreeSet<u64>>());
    let times = |name: &str| {
        let action = actions.iter().find(|action| action["name"] == name).unwrap();
        action["fee_micros"].as_str().unwrap().parse::<u64>().unwrap() / chain.fee()
    };
    assert_eq!((times("sell_order"), times("buy_order"), times("new_scripts"), times("cancel")), (4, 1, 3, 1));
    // A proof pays the fee once more for every 256 bytes of its payload: a
    // small one about a dozen fees.
    for name in ["proof_of_a_part", "proof"] {
        let action = actions.iter().find(|action| action["name"] == name).unwrap();
        let bytes = action["payload_json"].as_str().unwrap().len() as u64;
        assert_eq!(times(name), 1 + bytes / market::PROOF_BYTES_PER_FEE, "{name}");
    }
    assert!((4..=16).contains(&times("proof_of_a_part")) && times("proof") > 20);

    // The price arithmetic (`spec/market.md`, section 3). `sats` is null
    // where the engine refuses.
    let most = market::SATS_MAX / 1_000;
    let costs: Vec<Value> = [
        (0, 1),
        (1, 1),
        (1_000_000_000_000, 1),
        (1_000_000_000_001, 1),
        (999_999, PRICE),
        (SECOND, PRICE),
        (40 * SECOND, PRICE),
        (3, 3_333_333_333_333),
        (3, 3_333_333_333_334),
        (1, market::PRICE_MAX),
        (SECOND, market::PRICE_MAX),
        (most, market::PRICE_MAX),
        (most + 1, market::PRICE_MAX),
        (u64::MAX, 1),
        (u64::MAX, 113_841_228),
        (u64::MAX, 113_841_229),
        (u64::MAX, market::PRICE_MAX),
        (SECOND, 0),
        (SECOND, market::PRICE_MAX + 1),
        (0, 0),
    ]
    .into_iter()
    .map(|(amount, price): (u64, u64)| {
        json!({
            "amount_micros": amount.to_string(),
            "price": price.to_string(),
            "sats": market::sats(amount, price).ok().map(|value| value.to_string()),
        })
    })
    .collect();
    // What a payment buys. The engine's result stops at the largest number
    // a row holds.
    let buys: Vec<Value> = [
        (0, 1),
        (1, 1),
        (1, 30),
        (1, 1_000_000_000_000),
        (1, 1_000_000_000_001),
        (1, market::PRICE_MAX),
        (999, market::PRICE_MAX),
        (1_000, market::PRICE_MAX),
        (10_000, PRICE),
        (9_999, PRICE),
        (5_000, PRICE),
        (18_446_744, 1),
        (18_446_745, 1),
        (market::SATS_MAX, 1),
        (market::SATS_MAX, market::PRICE_MAX),
        (u64::MAX, market::PRICE_MAX),
        (u64::MAX, 1),
    ]
    .into_iter()
    .map(|(paid, price): (u64, u64)| {
        json!({
            "sats": paid.to_string(),
            "price": price.to_string(),
            "bought_micros": market::bought(paid, price).to_string(),
        })
    })
    .collect();
    for cost in &costs {
        // Paying the price always buys the amount.
        if let Some(value) = cost["sats"].as_str() {
            let (amount, price): (u64, u64) =
                (cost["amount_micros"].as_str().unwrap().parse().unwrap(), cost["price"].as_str().unwrap().parse().unwrap());
            assert!(market::bought(value.parse().unwrap(), price) >= amount);
        }
    }
    // Scripts, and the form the engine sees in each; null: not a receiving
    // script.
    let with = |head: &[u8], byte: u8, length: usize, tail: &[u8]| hex::encode([head, vec![byte; length].as_slice(), tail].concat());
    let forms: Vec<Value> = [
        p2pkh.clone(),
        p2sh.clone(),
        script(1),
        p2wsh.clone(),
        p2tr.clone(),
        with(&[0x76, 0xa9, 0x14], 0, 20, &[0x88, 0xac]),
        with(&[0xa9, 0x14], 0xff, 20, &[0x87]),
        with(&[0x00, 0x14], 0xff, 20, &[]),
        with(&[0x00, 0x20], 0, 32, &[]),
        with(&[0x51, 0x20], 0xff, 32, &[]),
        String::new(),
        "00".into(),
        "6a0100".into(),
        with(&[0x76, 0xa9, 0x14], 1, 19, &[0x88, 0xac]),
        with(&[0x76, 0xa9, 0x14], 1, 21, &[0x88, 0xac]),
        with(&[0x76, 0xa9, 0x14], 1, 20, &[0x88, 0xad]),
        with(&[0x76, 0xa9, 0x14], 1, 20, &[0x87, 0xac]),
        with(&[0x76, 0xa9, 0x15], 1, 20, &[0x88, 0xac]),
        with(&[0x76, 0xa8, 0x14], 1, 20, &[0x88, 0xac]),
        with(&[0xa9, 0x14], 1, 19, &[0x87]),
        with(&[0xa9, 0x14], 1, 21, &[0x87]),
        with(&[0xa9, 0x14], 1, 20, &[0x88]),
        with(&[0xa9, 0x14], 1, 20, &[]),
        with(&[0xa8, 0x14], 1, 20, &[0x87]),
        with(&[0x00, 0x14], 1, 19, &[]),
        with(&[0x00, 0x14], 1, 21, &[]),
        with(&[0x00, 0x14], 1, 32, &[]),
        with(&[0x00, 0x20], 1, 20, &[]),
        with(&[0x00, 0x20], 1, 31, &[]),
        with(&[0x00, 0x20], 1, 33, &[]),
        with(&[0x00, 0x15], 1, 21, &[]),
        with(&[0x51, 0x14], 1, 20, &[]),
        with(&[0x51, 0x20], 1, 31, &[]),
        with(&[0x51, 0x20], 1, 33, &[]),
        with(&[0x52, 0x20], 1, 32, &[]),
        with(&[0x60, 0x20], 1, 32, &[]),
        with(&[0x51, 0x02], 1, 2, &[]),
        with(&[0x21], 2, 33, &[0xac]),
        with(&[0x6a, 0x20], 1, 32, &[]),
    ]
    .into_iter()
    .map(|text| json!({"form": market::form_of(&hex::decode(&text).unwrap()), "script": text}))
    .collect();
    assert_eq!(forms.iter().filter(|entry| !entry["form"].is_null()).count(), 10);
    // The address of every standard script above on each Bitcoin network,
    // as the engine's Bitcoin library writes it.
    let addresses: Vec<Value> = forms
        .iter()
        .filter(|entry| !entry["form"].is_null())
        .flat_map(|entry| {
            let text = entry["script"].as_str().unwrap().to_string();
            [("mainnet", Network::Bitcoin), ("testnet3", Network::Testnet), ("regtest", Network::Regtest)].map(
                |(name, network)| {
                    let receiving = ScriptBuf::from_bytes(hex::decode(&text).unwrap());
                    json!({
                        "address": Address::from_script(&receiving, network).unwrap().to_string(),
                        "network": name,
                        "script": text,
                    })
                },
            )
        })
        .collect();
    assert_eq!(addresses.len(), 30);
    // Bitcoin transactions as the engine's Bitcoin library serializes them,
    // with their witness data and without, and the id of each. A proof
    // carries a transaction; other languages must find the same bytes.
    let input = |seed: u8, script_sig: &[u8], witness: &[&[u8]]| TxIn {
        previous_output: OutPoint { txid: Txid::from_byte_array([seed; 32]), vout: u32::from(seed) },
        script_sig: ScriptBuf::from_bytes(script_sig.to_vec()),
        sequence: Sequence(0xffff_fffd),
        witness: Witness::from_slice(witness),
    };
    let output = |sats: u64, receiving: &str| TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: ScriptBuf::from_bytes(hex::decode(receiving).unwrap()),
    };
    let build = |version: TxVersion, lock: u32, input: Vec<TxIn>, output: Vec<TxOut>| Transaction {
        version,
        lock_time: LockTime::from_consensus(lock),
        input,
        output,
    };
    let (leaf, control, redeem, empty): (&[u8], &[u8], &[u8], &[u8]) = (&[0xac; 300], &[0xc0; 65], &[0x16; 23], &[]);
    let (one, none): (&[&[u8]], &[&[u8]]) = (&[public], &[]);
    let transactions: Vec<Value> = [
        (
            "p2wpkh_spend",
            build(
                TxVersion::TWO,
                0,
                vec![input(1, &[], &[signature, public])],
                vec![output(10_000, &script(1)), output(89_000, &p2tr)],
            ),
        ),
        ("p2tr_key_spend", build(TxVersion::TWO, 0, vec![input(2, &[], &[schnorr])], vec![output(5_000, &p2tr)])),
        (
            "p2tr_script_spend",
            build(
                TxVersion::TWO,
                840_000,
                vec![input(3, &[], &[schnorr, leaf, control])],
                vec![output(7_500, &p2wsh), output(1, &p2pkh)],
            ),
        ),
        (
            "legacy",
            build(
                TxVersion::ONE,
                0,
                vec![input(4, &[0x47; 107], &[]), input(5, &[0x48; 106], &[])],
                vec![output(2_500, &p2pkh), output(600, &p2sh)],
            ),
        ),
        (
            "some_inputs_without_witness",
            build(
                TxVersion::TWO,
                500_000_000,
                vec![
                    input(6, &[0x47; 107], &[]),
                    input(7, &[], &[signature, public]),
                    input(8, redeem, &[signature, public]),
                    input(9, &[0x47; 107], &[]),
                ],
                vec![output(20_000, &script(2))],
            ),
        ),
        (
            "an_empty_witness_item",
            build(TxVersion::TWO, 0, vec![input(10, &[], &[empty, signature, empty, leaf])], vec![output(1_000, &script(3))]),
        ),
        (
            "253_outputs",
            build(
                TxVersion::TWO,
                0,
                vec![input(11, &[], &[schnorr])],
                (0..253).map(|index| output(1_000 + index, &script(4))).collect(),
            ),
        ),
        (
            "253_inputs_and_a_long_script",
            build(
                TxVersion::ONE,
                1,
                (0..253).map(|index| input(index as u8, &[0x51], if index == 200 { one } else { none })).collect(),
                vec![output(0, &hex::encode([vec![0x6a, 0x4d, 0x00, 0x01], vec![0x77; 256]].concat()))],
            ),
        ),
    ]
    .into_iter()
    .map(|(name, transaction)| {
        let mut bare = transaction.clone();
        for input in &mut bare.input {
            input.witness = Witness::new();
        }
        assert_eq!(bare.compute_txid(), transaction.compute_txid());
        json!({
            "name": name,
            "transaction": hex::encode(serialize(&transaction)),
            "txid": transaction.compute_txid().to_string(),
            "without_witness": hex::encode(serialize(&bare)),
        })
    })
    .collect();

    // Merkle proofs as the engine's Bitcoin library writes and reads them,
    // for blocks of several sizes: which transactions each proves, and at
    // which place of the block. (The headers carry no proof of work: these
    // vectors are about the tree.) A proof of payment is one that proves
    // exactly two, the first of them at place 0.
    let merkle_proofs: Vec<Value> = [
        (1usize, vec![0usize]),
        (2, vec![0, 1]),
        (2, vec![1]),
        (3, vec![0, 2]),
        (3, vec![0, 1]),
        (7, vec![0, 5]),
        (7, vec![0, 6]),
        (12, vec![0, 7]),
        (12, vec![3]),
        (12, vec![0, 4, 11]),
        (33, vec![0, 32]),
        (100, vec![0, 57]),
        (100, vec![]),
    ]
    .into_iter()
    .map(|(count, places)| {
        let ids: Vec<Txid> = (0..count).map(|index| Txid::from_byte_array(sha(1_000 * count as u64 + index as u64))).collect();
        let root = merkle_tree::calculate_root(ids.iter().copied()).unwrap();
        let header = Header {
            version: Version::from_consensus(4),
            prev_blockhash: chain.tip.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array(root.to_byte_array()),
            time: 1_800_000_000,
            bits: chain.tip.bits,
            nonce: count as u32,
        };
        let wanted: Vec<Txid> = places.iter().map(|place| ids[*place]).collect();
        let merkle = MerkleBlock::from_header_txids_with_predicate(&header, &ids, |id| wanted.contains(id));
        let (mut matched, mut indexes) = (vec![], vec![]);
        merkle.extract_matches(&mut matched, &mut indexes).unwrap();
        assert_eq!((matched, indexes), (wanted, places.iter().map(|place| *place as u32).collect::<Vec<u32>>()));
        json!({
            "block_hash": header.block_hash().to_string(),
            "matched": places.iter().map(|place| json!({"hash": hex::encode(ids[*place].to_byte_array()), "place": place})).collect::<Vec<_>>(),
            "merkle_proof": hex::encode(serialize(&merkle)),
            "transactions": count,
        })
    })
    .collect();

    format!(
        "{}\n",
        serde_json::to_string_pretty(&json!({
            "note": "The market's actions as the engine signs and accepts them (spec/market.md, section 6), its price arithmetic (section 3), the forms of receiving script (5.1) with the address of each standard script on each Bitcoin network, and Bitcoin transactions as the engine's Bitcoin library serializes them, with their witness data and without (`without_witness` is what a proof carries; `txid` is the same for both), and Merkle proofs with the transactions each proves to be in its block (`hash` is a transaction id as its bytes stand in the proof, `place` its place in the block). Written by v5/tests/market.rs (V5_EXPORT_MARKET_VECTORS=1), which holds the SHA-256 of this file and checks on every run that the engine still gives this text; client-v4/market.test.mjs, client-v4/bitcoin-address.test.mjs and clients/python/tests hold the SDK and the Python client to this file. The keys are test keys: each seed is one byte repeated, on a laboratory network that exists in the test only. An action is the envelope of spec/protocol-4.md, section 4: `signed_hex` is every byte of it, and `payload_json` the payload as it stands in those bytes. `fee_micros` is what the engine took from the sender for it, beside the seconds the action locks, on a network whose fee is `network_fee_micros`. A proof also has `bitcoin_node`: its two transactions as a Bitcoin node gives them, with their witness data, which a client removes. The proof of a part also has `fill`: what the fill held before it and holds after it. `sats` is null where the engine refuses the amount or the price. `form` is null for a script that is not a receiving script.",
            "network_id": chain.network,
            "bitcoin_network": "regtest",
            "actions": actions,
            "sats": costs,
            "bought": buys,
            "forms": forms,
            "addresses": addresses,
            "transactions": transactions,
            "merkle_proofs": merkle_proofs,
        }))
        .unwrap()
    )
}
/// The SHA-256 of that text, which is the SHA-256 of `spec/market-vectors.json`
/// (the SDK's test holds the file to this line). Checked here on every run
/// without reading the file, which is outside the release.
const MARKET_VECTORS_SHA256: &str = "edbb208fed0e11cd4c1b1c283285157a417d0a02e7fd1da19be268eab250ef89";

/// The engine still signs, accepts and computes what the vectors say.
#[test]
fn the_vectors_for_other_languages_are_actions_the_engine_accepts() {
    use sha2::Digest;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(market_vectors().as_bytes())),
        MARKET_VECTORS_SHA256,
        "the vectors changed: run export_the_market_vectors_for_other_languages with V5_EXPORT_MARKET_VECTORS=1, put the SHA-256 of spec/market-vectors.json here, and run the tests of client-v4/ and clients/python/"
    );
}

/// Writes `spec/market-vectors.json`. Run with `V5_EXPORT_MARKET_VECTORS=1`
/// after any change to the market's payloads, fees or arithmetic.
#[test]
fn export_the_market_vectors_for_other_languages() {
    if std::env::var("V5_EXPORT_MARKET_VECTORS").is_err() {
        return;
    }
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/market-vectors.json");
    std::fs::write(&file, market_vectors()).unwrap();
}

// ---- What a wallet is served (`/v4/state`): the rows of the market with
// their proofs, or the proof that a row is absent. A wallet shows a person
// a fill, its script and its satoshis from these proofs before they pay
// bitcoin, never from a node's word.

/// A node that is handed the blocks of a `Chain` as CometBFT hands them to
/// an application, and answers the queries a wallet's gateway makes.
struct Node {
    _dir: tempfile::TempDir,
    app: timecurrency_v5::app::App,
    /// The blocks of the chain it has executed, and the time of the last.
    done: usize,
    time: i64,
}
impl Node {
    fn of(chain: &Chain, market: bool) -> Self {
        use tendermint_proto::v0_38::abci::{RequestInitChain, ValidatorUpdate};
        // The genesis of `Chain::with`.
        let mut genesis = genesis_v5();
        genesis.market = market;
        genesis.waits_survive_stops = market;
        let dir = tempfile::tempdir().unwrap();
        let app = timecurrency_v5::app::App::open(dir.path().join("node")).unwrap();
        app.try_init(RequestInitChain {
            chain_id: genesis.ledger.chain_id.clone(),
            time: Self::timestamp(genesis.ledger.genesis_time_micros),
            app_state_bytes: serde_json::to_vec(&genesis).unwrap().into(),
            validators: genesis
                .validators
                .iter()
                .map(|validator| ValidatorUpdate {
                    pub_key: Some(tendermint_proto::crypto::PublicKey {
                        sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                            hex::decode(&validator.consensus_key).unwrap(),
                        )),
                    }),
                    power: genesis.profile.genesis_power() as i64,
                })
                .collect(),
            ..Default::default()
        })
        .unwrap();
        let mut node = Self { _dir: dir, app, done: 0, time: genesis.ledger.genesis_time_micros };
        node.follow(chain);
        node
    }
    fn timestamp(micros: i64) -> Option<tendermint_proto::google::protobuf::Timestamp> {
        Some(tendermint_proto::google::protobuf::Timestamp {
            seconds: micros / 1_000_000,
            nanos: ((micros % 1_000_000) * 1000) as i32,
        })
    }
    /// Executes the blocks the chain has made since. The node's state is
    /// then the chain's, root for root.
    fn follow(&mut self, chain: &Chain) {
        use sha2::{Digest, Sha256};
        use tendermint_proto::v0_38::{
            abci::{CommitInfo, RequestFinalizeBlock, Validator, VoteInfo},
            types::BlockIdFlag,
        };
        let genesis = genesis_v5();
        for (delta, txs) in &chain.log[self.done..] {
            let height = self.done as i64 + 1;
            self.time += *delta as i64;
            let votes = genesis
                .validators
                .iter()
                .map(|validator| VoteInfo {
                    validator: Some(Validator {
                        address: Sha256::digest(hex::decode(&validator.consensus_key).unwrap())[..20].to_vec().into(),
                        power: genesis.profile.genesis_power() as i64,
                    }),
                    block_id_flag: BlockIdFlag::Commit as i32,
                })
                .collect();
            let response = self
                .app
                .try_finalize(RequestFinalizeBlock {
                    height,
                    time: Self::timestamp(self.time),
                    hash: sha(height as u64).to_vec().into(),
                    txs: txs.iter().cloned().map(Into::into).collect(),
                    // Every validator signed, from the first block on, as
                    // on the chain (`Chain::next`).
                    decided_last_commit: Some(CommitInfo { round: 0, votes }),
                    ..Default::default()
                })
                .unwrap_or_else(|error| panic!("height {height}: {error:#}"));
            assert!(
                response.tx_results.iter().all(|result| result.code == 0),
                "the node refused a transaction the chain kept, at height {height}"
            );
            self.app.try_commit().unwrap();
            self.done += 1;
        }
        let version = chain.engine.version().unwrap();
        assert_eq!(
            self.app.head().unwrap(),
            Some((version.height(), version.root())),
            "the node and the chain disagree"
        );
    }
    fn query(&self, selection: &Value) -> tendermint_proto::v0_38::abci::ResponseQuery {
        use tendermint_abci::Application;
        self.app.query(tendermint_proto::v0_38::abci::RequestQuery {
            data: serde_json::to_vec(selection).unwrap().into(),
            path: "/v4/state".into(),
            height: 0,
            prove: false,
        })
    }
    /// The answer to `/v4/state` for `selection`.
    #[track_caller]
    fn served(&self, selection: &Value) -> Value {
        let response = self.query(selection);
        assert_eq!(response.code, 0, "{selection}: {}", response.log);
        serde_json::from_slice(&response.value).unwrap()
    }
    /// Why the node refuses `selection`.
    #[track_caller]
    fn refusal(&self, selection: &Value) -> String {
        let response = self.query(selection);
        assert_ne!(response.code, 0, "{selection} was answered");
        response.log
    }
}

/// The row an answer proves under `key`, checked against the answer's own
/// root: its bytes, or none when the answer proves that there is no row.
#[track_caller]
fn proven(view: &Value, key: &[u8]) -> Option<Vec<u8>> {
    let root: [u8; 32] = hex::decode(view["root"].as_str().unwrap()).unwrap().try_into().unwrap();
    let wanted = hex::encode(key);
    let entry = view["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key_hex"] == wanted.as_str())
        .unwrap_or_else(|| panic!("the answer has no entry for {}", String::from_utf8_lossy(key)));
    let entry: timecurrency_v5::proof::ProofEntry = serde_json::from_value(entry.clone()).unwrap();
    entry.verify(root, key).unwrap()
}
/// Whether an answer has any entry under `market/`.
fn names_the_market(view: &Value) -> bool {
    let prefix = hex::encode(market::PREFIX);
    view["entries"].as_array().unwrap().iter().any(|entry| entry["key_hex"].as_str().unwrap().starts_with(&prefix))
}

/// A small market: an open sell order with one address that has served a
/// proven trade, one that serves a fill in progress, paid in part, and one
/// that is free; a buy order with a fill against it; the candles of the two
/// payments. Returns the chain and the hours a wallet asks for: those of the
/// two payments (they may be one hour) and the hour after, which has none.
fn small_market() -> (Chain, Vec<u64>) {
    let mut chain = Chain::new();
    chain.bitcoin_blocks(3);
    // 100 seconds on offer at 250 satoshis a second, two confirmations, a
    // deposit of 5%.
    chain.accept(chain.act(SELLER, market::ORDER, sell_order(100 * SECOND, &[script(1), script(2), script(3)], 2, 50_000)));
    // One trade from the fill to the proof: 40 seconds for 10,000 satoshis.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 40 * SECOND, BUYER)));
    let payment = chain.pay(&script(1), 10_000, 9);
    chain.bitcoin_blocks(1);
    chain.accept(chain.proof(ANYONE, 1, &payment));
    let hour = |chain: &Chain| {
        let meta = chain.engine.meta().unwrap();
        meta.elapsed_micros().unwrap() / market::Params::of(meta.config.profile).hour_micros
    };
    let first = hour(&chain);
    // A fill in progress: 20 seconds for 5,000 satoshis, to be paid to the
    // second address. 2,000 satoshis arrive: 8 seconds are the buyer's, and
    // the fill goes on for the other 12.
    chain.accept(chain.act(BUYER, market::TAKE, take(1, 20 * SECOND, BUYER)));
    let part = chain.pay(&script(2), 2_000, 10);
    chain.bitcoin_blocks(1);
    chain.accept(chain.proof(ANYONE, 2, &part));
    let second = hour(&chain);
    assert_eq!(chain.fill(2).unwrap().amount_micros, 12 * SECOND);
    // A buy order, and a seller who fills a part of it.
    chain.accept(chain.act(OTHER, market::ORDER, buy_order(50 * SECOND, 3, 100_000)));
    chain.accept(chain.act(SELLER, market::SELL, sale(2, 10 * SECOND, 2, script(4))));
    chain.audit();
    let mut hours = vec![first, second, second + 1];
    hours.dedup();
    (chain, hours)
}
/// What a wallet asks of that market: the summary and the clock of heights,
/// every order and fill with one id beyond them, the four accounts, the
/// five addresses, the hours; and the Bitcoin header chain, whose best
/// height says whether a fill can end.
fn small_market_selection(hours: &[u64]) -> Value {
    json!({
        "include_bitcoin": true,
        "include_market": true,
        "market_orders": ["1", "2", "3"],
        "market_fills": ["1", "2", "3", "4"],
        "market_accounts": [SELLER.to_string(), BUYER.to_string(), ANYONE.to_string(), OTHER.to_string()],
        "market_scripts": [script(1), script(2), script(3), script(4), script(5)],
        "market_candles": hours.iter().map(u64::to_string).collect::<Vec<_>>(),
    })
}
/// The rows that selection names, read from the chain's own state, in the
/// shape a verifier gives them to a wallet: a row as it is stored, `null`
/// where there is none.
fn small_market_rows(chain: &Chain, hours: &[u64]) -> Value {
    let row = |key: &[u8]| -> Value {
        chain.row(key).map_or(Value::Null, |bytes| serde_json::from_slice(&bytes).unwrap())
    };
    let by_id = |ids: &[u64], key: fn(u64) -> Vec<u8>| -> Value {
        Value::Object(ids.iter().map(|id| (id.to_string(), row(&key(*id)))).collect())
    };
    let scripts: serde_json::Map<String, Value> = (1..=5)
        .map(|byte| (script(byte), row(&market::script_key(&hex::decode(script(byte)).unwrap()))))
        .collect();
    json!({
        "summary": row(market::META_KEY),
        "heights": row(market::HEIGHTS_KEY),
        "orders": by_id(&[1, 2, 3], market::order_key),
        "fills": by_id(&[1, 2, 3, 4], market::fill_key),
        "accounts": by_id(&[SELLER, BUYER, ANYONE, OTHER], market::index_key),
        "scripts": scripts,
        "candles": by_id(hours, market::candle_key),
    })
}
/// Every key that selection names under `market/`.
fn small_market_keys(hours: &[u64]) -> Vec<Vec<u8>> {
    let mut keys = vec![market::META_KEY.to_vec(), market::HEIGHTS_KEY.to_vec()];
    keys.extend([1, 2, 3].map(market::order_key));
    keys.extend([1, 2, 3, 4].map(market::fill_key));
    keys.extend([SELLER, BUYER, ANYONE, OTHER].map(market::index_key));
    keys.extend((1..=5).map(|byte| market::script_key(&hex::decode(script(byte)).unwrap())));
    keys.extend(hours.iter().copied().map(market::candle_key));
    keys
}

#[test]
fn a_wallet_is_served_the_rows_of_the_market_or_the_proof_that_they_are_absent() {
    let (chain, hours) = small_market();
    let node = Node::of(&chain, true);
    let selection = small_market_selection(&hours);
    let view = node.served(&selection);
    // Every key the selection names has an entry, and it proves what the
    // state holds: the row, or that there is none.
    let keys = small_market_keys(&hours);
    for key in &keys {
        assert_eq!(proven(&view, key), chain.row(key), "{}", String::from_utf8_lossy(key));
    }
    let held = |key: &[u8]| chain.row(key).is_some();
    assert!(held(&market::fill_key(2)) && held(&market::fill_key(3)) && held(&market::order_key(2)));
    assert!(!held(&market::fill_key(1)) && !held(&market::fill_key(4)) && !held(&market::order_key(3)));
    assert!(!held(&market::index_key(ANYONE)) && !held(&market::candle_key(*hours.last().unwrap())));
    assert!(hours[..hours.len() - 1].iter().all(|hour| held(&market::candle_key(*hour))));
    // The four states of an address: served, listed (one with a fill in
    // progress, one free), serving a fill against a buy order, unknown.
    let of_script = |byte: u8| chain.row(&market::script_key(&hex::decode(script(byte)).unwrap())).map(|row| String::from_utf8(row).unwrap());
    assert_eq!(of_script(1).as_deref(), Some("{}"));
    assert_eq!(of_script(2).as_deref(), Some(r#"{"order":"1"}"#));
    assert_eq!(of_script(3).as_deref(), Some(r#"{"order":"1"}"#));
    assert_eq!(of_script(4).as_deref(), Some(r#"{"fill":"3"}"#));
    assert_eq!(of_script(5), None);
    // Not asked for, no key of the market is part of an answer.
    assert!(names_the_market(&view));
    assert!(!names_the_market(&node.served(&json!({"ids": ["5"], "include_bitcoin": true}))));
    assert!(!names_the_market(&node.served(&json!({"include_market": false, "market_orders": []}))));
    // Each part can be asked for by itself, and the same id twice is one entry.
    let one = node.served(&json!({"market_fills": ["2", "2"]}));
    assert_eq!(proven(&one, &market::fill_key(2)), chain.row(&market::fill_key(2)));
    assert_eq!(one["entries"].as_array().unwrap().len(), 2, "the metadata and the fill");
    // The bounds: sixteen orders, fills and addresses, eight accounts,
    // thirty-two candles.
    let ids = |count: u64| (1..=count).map(|id| id.to_string()).collect::<Vec<_>>();
    for (field, most) in [("market_orders", 16), ("market_fills", 16), ("market_accounts", 8), ("market_candles", 32)] {
        assert_eq!(node.served(&json!({field: ids(most)}))["entries"].as_array().unwrap().len() as u64, most + 1, "{field}");
        assert_eq!(node.refusal(&json!({field: ids(most + 1)})), "selection budget", "{field}");
        // An id is a canonical decimal number.
        for id in ["01", "", "-1", "1.0", "0x1", " 1", "18446744073709551616"] {
            node.refusal(&json!({field: [id]}));
        }
        node.refusal(&json!({field: [1]}));
        node.refusal(&json!({field: "1"}));
    }
    let scripts = |count: u8| (0..count).map(script).collect::<Vec<_>>();
    assert_eq!(node.served(&json!({"market_scripts": scripts(16)}))["entries"].as_array().unwrap().len(), 17);
    assert_eq!(node.refusal(&json!({"market_scripts": scripts(17)})), "selection budget");
    // An address is a receiving script of one of the five standard forms,
    // in lowercase hexadecimal.
    let form = |head: &[u8], body: usize, tail: &[u8]| hex::encode([head, &vec![0xabu8; body], tail].concat());
    let standard = [
        form(&[0x76, 0xa9, 0x14], 20, &[0x88, 0xac]),
        form(&[0xa9, 0x14], 20, &[0x87]),
        form(&[0x00, 0x14], 20, &[]),
        form(&[0x00, 0x20], 32, &[]),
        form(&[0x51, 0x20], 32, &[]),
    ];
    let view = node.served(&json!({"market_scripts": standard}));
    for text in &standard {
        assert_eq!(proven(&view, &market::script_key(&hex::decode(text).unwrap())), None);
    }
    for other in [
        standard[2].to_uppercase(),
        standard[2][2..].to_string(),
        standard[2][1..].to_string(),
        format!("{}00", standard[2]),
        form(&[0x52, 0x20], 32, &[]),
        "6a0100".to_string(),
        String::new(),
        "zz".to_string(),
    ] {
        node.refusal(&json!({"market_scripts": [other]}));
    }
    assert_eq!(node.refusal(&json!({"market_scripts": [standard[0].to_uppercase()]})), "invalid selected receiving script");
    // A flag is true or false, and the node knows no other selection.
    node.refusal(&json!({"include_market": "yes"}));
    node.refusal(&json!({"include_market": 1}));
    node.refusal(&json!({"market_paid": ["1"]}));
    node.refusal(&json!({"include_markets": true}));
}

#[test]
fn a_network_without_the_market_answers_that_it_has_none() {
    let chain = Chain::with(false);
    let node = Node::of(&chain, false);
    // The same question as on a network with the market. It is not
    // refused: every key is proven absent.
    let view = node.served(&small_market_selection(&[341, 342]));
    for key in small_market_keys(&[341, 342]) {
        assert_eq!(proven(&view, &key), None, "{}", String::from_utf8_lossy(&key));
    }
    let meta: Value = serde_json::from_slice(&proven(&view, b"meta").unwrap()).unwrap();
    assert!(meta["config"].get("market").is_none() && meta.get("market_micros").is_none());
    // The bounds and the forms are the same on every network.
    assert_eq!(node.refusal(&json!({"market_orders": (1..=17).map(|id| id.to_string()).collect::<Vec<_>>()})), "selection budget");
    assert_eq!(node.refusal(&json!({"market_scripts": ["6a0100"]})), "invalid selected receiving script");
}

fn market_fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/market-state.fixture.json")
}

/// The rows of the market as this engine serves them to a wallet: for four
/// states, the answer to `/v4/state` that proves them, the application hash
/// to put in the certifying header, the rows as the state holds them, and
/// whether the chain lets the fill in progress end without payment.
fn market_fixture() -> Value {
    use tendermint_proto::v0_38::abci::RequestInfo;
    use tendermint_abci::Application;
    let (mut chain, hours) = small_market();
    let mut node = Node::of(&chain, true);
    let request = small_market_selection(&hours);
    let capture = |chain: &Chain, node: &Node, name: &str, what: &str, expiry: Value| -> Value {
        let view = node.served(&request);
        let meta = chain.engine.meta().unwrap();
        let version = chain.engine.version().unwrap();
        assert_eq!(view["root"], hex::encode(version.root()));
        let stored: Value = serde_json::from_slice(&proven(&view, b"meta").unwrap()).unwrap();
        let bitcoin: Value = serde_json::from_slice(&proven(&view, timecurrency_v5::bitcoin_adapter::STATE_KEY).unwrap()).unwrap();
        json!({
            "name": name,
            "what": what,
            "height": version.height().to_string(),
            "app_hash": view["root"],
            "protocol_version": stored["protocol_version"],
            "next_block_version": node.app.info(RequestInfo::default()).app_version.to_string(),
            "elapsed_micros": meta.elapsed_micros().unwrap().to_string(),
            "clock_of_the_waits_micros": meta.active_micros().unwrap().to_string(),
            "market_micros": meta.market_micros.map(|held| held.to_string()),
            "bitcoin_best_height": bitcoin["meta"]["best_height"],
            "request": request,
            "response": view,
            "market": small_market_rows(chain, &hours),
            "expiry": expiry,
        })
    };
    let expire = |chain: &Chain| chain.act(ANYONE, market::EXPIRE, json!({"fill": "2"}));
    let mut cases = Vec::new();
    // 1. The fill in progress has its whole time to pay ahead.
    let not_learnt = "the chain has not learnt the last height of this fill";
    chain.refuse(expire(&chain), not_learnt);
    cases.push(capture(&chain, &node, "trading", "An open sell order with a proven trade, a fill in progress that was paid in part, and a free address; a buy order with a fill against it. The chain has not learnt the last height of fill 2.", json!({"fill": "2", "accepted": false, "refusal": not_learnt})));
    // 2. Bitcoin moves on: the chain knows the last height of the fill, and
    // the time in which a proof is still accepted has begun.
    chain.bitcoin_blocks(8);
    node.follow(&chain);
    let in_grace = "a fill ends after the time in which a proof of a payment made in time is accepted";
    chain.refuse(expire(&chain), in_grace);
    cases.push(capture(&chain, &node, "learnt", "Eight Bitcoin blocks later: the chain has learnt the last height of fill 2, and a proof of a payment made in time is still accepted.", json!({"fill": "2", "accepted": false, "refusal": in_grace})));
    // 3. A minute later the fill can end.
    chain.wait(60);
    node.follow(&chain);
    cases.push(capture(&chain, &node, "due", "A minute later: the rest of fill 2 was not paid and anyone may end it.", json!({"fill": "2", "accepted": true, "refusal": null})));
    chain.accept(expire(&chain));
    assert!(chain.fill(2).is_none());
    chain.audit();
    // 4. A network without the market, asked the same.
    let plain = Chain::with(false);
    let plain_node = Node::of(&plain, false);
    cases.push(capture(&plain, &plain_node, "no_market", "A network without the market: every row is proven absent.", Value::Null));
    let genesis = genesis_v5();
    json!({
        "description": "Proven rows of the market from the engine (v5/tests/market.rs, V5_EXPORT_MARKET_FIXTURE=1). Each case holds the answer to /v4/state for `request`, whose root is the application hash of the block at `height` (the header of the next block carries it), and under `market` the rows the state holds, as a verifier gives them to a wallet.",
        "chain_id": genesis.ledger.chain_id,
        "genesis_time_micros": genesis.ledger.genesis_time_micros.to_string(),
        "profile": "laboratory",
        "network_id": chain.network,
        "network_id_without_the_market": plain.network,
        "accounts": {"seller": SELLER.to_string(), "buyer": BUYER.to_string(), "anyone": ANYONE.to_string(), "other": OTHER.to_string()},
        "scripts": {"served": script(1), "serving": script(2), "listed": script(3), "of_a_fill_against_a_buy_order": script(4), "unknown": script(5)},
        "candle_hours": hours.iter().map(u64::to_string).collect::<Vec<_>>(),
        "price": PRICE.to_string(),
        "cases": cases,
    })
}

/// Writes the fixture the verifier and the SDK tests read, or checks that
/// the committed one is what this engine produces. Run with
/// `V5_EXPORT_MARKET_FIXTURE=../verifier-v4/fixtures/market-state.fixture.json`
/// after any change to the rows of the market or to the answer of
/// `/v4/state` (a path as the value writes a second copy there, which is
/// the one the verifier's tests read; `1` writes this crate's copy alone),
/// then export the verifier's own file from it
/// (`V4_EXPORT_MARKET_FIXTURE=1 cargo test` in `verifier-v4`).
#[test]
fn the_market_fixture_for_clients_is_what_this_engine_produces() {
    let produced = market_fixture();
    let cases = produced["cases"].as_array().unwrap();
    let by_name = |name: &str| cases.iter().find(|case| case["name"] == name).unwrap();
    // The states a wallet must tell apart are all there.
    let trading = &by_name("trading")["market"];
    assert_eq!(trading["summary"]["trades"], "2");
    assert_eq!(trading["orders"]["1"]["side"], "sell");
    assert_eq!(trading["orders"]["2"]["side"], "buy");
    assert_eq!(trading["orders"]["3"], Value::Null);
    assert_eq!(trading["fills"]["1"], Value::Null);
    assert_eq!((&trading["fills"]["2"]["side"], &trading["fills"]["2"]["script"]), (&json!("sell"), &json!(script(2))));
    assert_eq!((&trading["fills"]["3"]["side"], &trading["fills"]["3"]["script"]), (&json!("buy"), &json!(script(4))));
    assert_eq!(trading["accounts"][ANYONE.to_string()], Value::Null);
    assert_eq!(trading["accounts"][BUYER.to_string()], json!({"fills": ["2"], "orders": []}));
    let hours = produced["candle_hours"].as_array().unwrap();
    let traded: u64 = hours.iter().filter_map(|hour| trading["candles"][hour.as_str().unwrap()]["trades"].as_str()).map(|n| n.parse::<u64>().unwrap()).sum();
    assert_eq!(traded, 2);
    assert_eq!(trading["candles"][hours.last().unwrap().as_str().unwrap()], Value::Null);
    // The fill that was paid in part holds what is still to pay.
    assert_eq!((trading["fills"]["2"]["amount_micros"].as_str(), trading["fills"]["2"]["sats"].as_str()), (Some("12000000"), Some("3000")));
    assert_eq!(by_name("due")["expiry"]["accepted"], true);
    assert_eq!(by_name("no_market")["market"]["summary"], Value::Null);
    assert_eq!(by_name("no_market")["market_micros"], Value::Null);
    let text = serde_json::to_vec(&produced).unwrap();
    match std::env::var("V5_EXPORT_MARKET_FIXTURE") {
        Ok(target) => {
            std::fs::write(market_fixture_path(), &text).unwrap();
            if target != "1" {
                std::fs::write(std::path::PathBuf::from(target), &text).unwrap();
            }
        }
        Err(_) => {
            let committed: Value = serde_json::from_slice(&std::fs::read(market_fixture_path()).expect("the committed fixture")).unwrap();
            assert_eq!(committed, produced, "the committed fixture is stale: export it again");
        }
    }
}
