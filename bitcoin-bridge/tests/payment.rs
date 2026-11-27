//! An ordinary payment proven against regtest proof-of-work fixtures
//! (`spec/market.md`, section 5.2). Like `bridge.rs`, these are not a claim of
//! full Bitcoin transaction validity.
use bitcoin::{
    Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
    absolute::LockTime,
    block::{Header, Version},
    consensus::serialize,
    hashes::Hash,
    merkle_tree::{self, MerkleBlock},
    transaction::Version as TxVersion,
};
use timecurrency_bitcoin_bridge::*;

fn genesis() -> (HeaderChain, MemoryHeaderStore) {
    let t =
        HeaderChain::bootstrap_genesis(BridgeConfig::for_network(BitcoinNetwork::Regtest)).unwrap();
    let mut s = MemoryHeaderStore::default();
    s.apply(&t);
    (t.chain, s)
}
fn mine(parent: &HeaderRecord, time: u32, root: TxMerkleNode) -> Header {
    let mut h = Header {
        version: Version::from_consensus(4),
        prev_blockhash: parent.header.block_hash(),
        merkle_root: root,
        time,
        bits: parent.header.bits,
        nonce: 0,
    };
    while h.validate_pow(h.target()).is_err() {
        h.nonce = h.nonce.checked_add(1).unwrap();
    }
    h
}
fn append(chain: &mut HeaderChain, store: &mut MemoryHeaderStore, header: Header) {
    let t = chain
        .prepare_headers(store, &[header], u64::from(header.time))
        .unwrap();
    store.apply(&t);
    *chain = t.chain;
}
fn extend(chain: &mut HeaderChain, store: &mut MemoryHeaderStore, count: u32) {
    for _ in 0..count {
        let p = store.records[&chain.meta.best_tip].clone();
        append(
            chain,
            store,
            mine(&p, p.header.time + 1, TxMerkleNode::all_zeros()),
        );
    }
}
/// The hash of the block at `height` on the chain of most work.
fn at(chain: &HeaderChain, store: &MemoryHeaderStore, height: u32) -> BlockHash {
    chain.ancestor(store, chain.meta.best_tip, height).unwrap().header.block_hash()
}
fn p2wpkh(byte: u8) -> Vec<u8> {
    [vec![0x00, 0x14], vec![byte; 20]].concat()
}
fn pay(outputs: &[(&[u8], u64)], seed: u8) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs
            .iter()
            .map(|(script, sats)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
            })
            .collect(),
    }
}
/// A coinbase transaction; `tag` makes it its block's own.
fn coinbase(tag: u8) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x03, tag, 0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000_000_000),
            script_pubkey: ScriptBuf::from_bytes(p2wpkh(0xcb)),
        }],
    }
}
/// A block on `parent` that holds `transactions` (the first is its
/// coinbase), and a proof of the coinbase and of the transaction at `which`.
fn block(parent: &HeaderRecord, time: u32, transactions: &[Transaction], which: usize) -> (Header, PaymentProof) {
    let ids: Vec<Txid> = transactions.iter().map(Transaction::compute_txid).collect();
    let root = merkle_tree::calculate_root(ids.iter().copied()).unwrap();
    let header = mine(parent, time, TxMerkleNode::from_byte_array(root.to_byte_array()));
    let wanted = [ids[0], ids[which]];
    let merkle = MerkleBlock::from_header_txids_with_predicate(&header, &ids, |id| wanted.contains(id));
    let proof = PaymentProof {
        block_hash: header.block_hash(),
        transaction: serialize(&transactions[which]),
        vout: 0,
        coinbase: serialize(&transactions[0]),
        merkle_proof: serialize(&merkle),
    };
    (header, proof)
}
/// A chain of `before` empty blocks, then one block that holds a coinbase
/// and `tx`, then `after` empty blocks.
fn fixture(tx: &Transaction, before: u32, after: u32) -> (HeaderChain, MemoryHeaderStore, PaymentProof) {
    let (mut c, mut s) = genesis();
    extend(&mut c, &mut s, before);
    let parent = s.records[&c.meta.best_tip].clone();
    let (header, proof) = block(&parent, parent.header.time + 1, &[coinbase(1), tx.clone()], 1);
    append(&mut c, &mut s, header);
    extend(&mut c, &mut s, after);
    (c, s, proof)
}
/// `verify_payment` with the starting block named by its height on the
/// chain of most work.
fn verify(c: &HeaderChain, s: &MemoryHeaderStore, proof: &PaymentProof, script: &[u8], start: u32, k: u32) -> anyhow::Result<AcceptedPayment> {
    c.verify_payment(s, proof, script, start, &at(c, s, start), k)
}
#[track_caller]
fn refused(result: anyhow::Result<AcceptedPayment>, why: &str) {
    let error = result.expect_err("accepted").to_string();
    assert!(error.contains(why), "refused for another reason: {error}");
}

#[test]
fn the_five_standard_forms_and_nothing_else() {
    let p2pkh = [vec![0x76, 0xa9, 0x14], vec![1; 20], vec![0x88, 0xac]].concat();
    let p2sh = [vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat();
    let p2wsh = [vec![0x00, 0x20], vec![1; 32]].concat();
    let p2tr = [vec![0x51, 0x20], vec![1; 32]].concat();
    for good in [&p2pkh, &p2sh, &p2wpkh(1), &p2wsh, &p2tr] {
        assert!(standard_script(good), "{}", hex::encode(good));
        // One byte more, one byte less.
        let mut long = good.to_vec();
        long.push(0);
        assert!(!standard_script(&long));
        assert!(!standard_script(&good[..good.len() - 1]));
    }
    // The last byte changed where the form ends in an opcode.
    let mut bad = p2pkh.clone();
    *bad.last_mut().unwrap() = 0xad;
    assert!(!standard_script(&bad));
    let mut bad = p2sh.clone();
    *bad.last_mut().unwrap() = 0x88;
    assert!(!standard_script(&bad));
    // The 20 bytes of a public key hash alone are no script hash form, and
    // the reverse: each form is matched whole.
    assert!(!standard_script(&p2pkh[3..23]));
    // A data output, an empty script, a future witness version, a bare key.
    assert!(!standard_script(&[0x6a, 0x01, 0x00]));
    assert!(!standard_script(&[]));
    assert!(!standard_script(&[vec![0x52, 0x20], vec![1; 32]].concat()));
    assert!(!standard_script(&[vec![0x21], vec![2; 33], vec![0xac]].concat()));
}

#[test]
fn a_payment_counts_with_its_confirmations_and_above_the_starting_height() {
    let script = p2wpkh(3);
    let tx = pay(&[(&script, 250_000), (&p2wpkh(9), 10)], 7);
    // Blocks 1 and 2 are empty, the payment is in block 3, two more follow.
    let (c, s, proof) = fixture(&tx, 2, 2);
    // What the proof says by itself, before any header is read.
    let claim = claimed_payment(&proof, &script).unwrap();
    assert_eq!((claim.outpoint.txid, claim.outpoint.vout, claim.sats), (tx.compute_txid(), 0, 250_000));
    let paid = verify(&c, &s, &proof, &script, 2, 3).unwrap();
    assert_eq!(paid.sats, 250_000);
    assert_eq!(paid.block_height, 3);
    assert_eq!(paid.confirmations, 3);
    assert_eq!(paid.outpoint, claim.outpoint);
    // One confirmation more than it has.
    refused(verify(&c, &s, &proof, &script, 2, 4), "lacks confirmations");
    // A block at the starting height does not count: it may hold a payment
    // made before the fill.
    refused(verify(&c, &s, &proof, &script, 3, 1), "not after the starting block");
    // No confirmations asked is refused, not read as "any".
    assert!(verify(&c, &s, &proof, &script, 2, 0).is_err());
}

#[test]
fn another_script_another_output_and_a_changed_proof_are_refused() {
    let script = p2wpkh(3);
    let other = p2wpkh(4);
    let tx = pay(&[(&script, 250_000), (&other, 99)], 7);
    let (c, s, proof) = fixture(&tx, 0, 0);
    verify(&c, &s, &proof, &script, 0, 1).unwrap();
    // The fill's script is not the one this output pays.
    refused(verify(&c, &s, &proof, &other, 0, 1), "script mismatch");
    // The second output pays `other`, and is its own payment.
    let mut second = proof.clone();
    second.vout = 1;
    assert_eq!(verify(&c, &s, &second, &other, 0, 1).unwrap().sats, 99);
    assert!(verify(&c, &s, &second, &script, 0, 1).is_err());
    let mut missing = proof.clone();
    missing.vout = 2;
    assert!(verify(&c, &s, &missing, &script, 0, 1).is_err());
    // A script that is not of a standard form is refused even when paid.
    let data = [0x6a, 0x01, 0x00];
    let odd = pay(&[(&data, 5)], 8);
    let (c2, s2, odd_proof) = fixture(&odd, 0, 0);
    refused(verify(&c2, &s2, &odd_proof, &data, 0, 1), "not a standard receiving script");
    // Another transaction under the same Merkle proof.
    let mut swapped = proof.clone();
    swapped.transaction = serialize(&pay(&[(&script, 250_000)], 9));
    refused(verify(&c, &s, &swapped, &script, 0, 1), "does not match exactly the coinbase and the payment");
    // A byte appended to the transaction, to the proof; a proof cut short.
    let mut long = proof.clone();
    long.transaction.push(0);
    assert!(verify(&c, &s, &long, &script, 0, 1).is_err());
    let mut long = proof.clone();
    long.merkle_proof.push(0);
    assert!(verify(&c, &s, &long, &script, 0, 1).is_err());
    let mut short = proof.clone();
    short.merkle_proof.pop();
    assert!(verify(&c, &s, &short, &script, 0, 1).is_err());
    // A block hash the proof is not for.
    let mut elsewhere = proof.clone();
    elsewhere.block_hash = c.meta.checkpoint.hash;
    refused(verify(&c, &s, &elsewhere, &script, 0, 1), "block mismatch");
    // An output without value.
    let nothing = pay(&[(&script, 0), (&other, 5)], 10);
    let (c3, s3, nothing_proof) = fixture(&nothing, 0, 0);
    refused(verify(&c3, &s3, &nothing_proof, &script, 0, 1), "no value");
}

#[test]
fn a_proof_carries_the_blocks_coinbase_and_no_witness_data() {
    let script = p2wpkh(3);
    let tx = pay(&[(&script, 250_000)], 7);
    let (mut c, mut s) = genesis();
    let parent = s.records[&c.meta.best_tip].clone();
    let all = [coinbase(1), pay(&[(&p2wpkh(8), 1)], 5), tx.clone(), pay(&[(&p2wpkh(8), 2)], 6)];
    let (header, proof) = block(&parent, parent.header.time + 1, &all, 2);
    append(&mut c, &mut s, header);
    verify(&c, &s, &proof, &script, 0, 1).unwrap();
    let ids: Vec<Txid> = all.iter().map(Transaction::compute_txid).collect();
    // A Merkle proof of the payment alone, as `gettxoutproof` gives for one
    // transaction: the depth of the tree is not pinned, and it is refused.
    let alone = MerkleBlock::from_header_txids_with_predicate(&header, &ids, |id| *id == ids[2]);
    let mut single = proof.clone();
    single.merkle_proof = serialize(&alone);
    refused(verify(&c, &s, &single, &script, 0, 1), "does not match exactly the coinbase and the payment");
    // A third transaction matched as well.
    let three = MerkleBlock::from_header_txids_with_predicate(&header, &ids, |id| *id != ids[3]);
    let mut wide = proof.clone();
    wide.merkle_proof = serialize(&three);
    refused(verify(&c, &s, &wide, &script, 0, 1), "does not match exactly the coinbase and the payment");
    // Another transaction of the block in the coinbase's place: it is in
    // the tree, and it is not a coinbase.
    let pair = MerkleBlock::from_header_txids_with_predicate(&header, &ids, |id| *id == ids[1] || *id == ids[2]);
    let mut fake = proof.clone();
    fake.coinbase = serialize(&all[1]);
    fake.merkle_proof = serialize(&pair);
    refused(verify(&c, &s, &fake, &script, 0, 1), "is the block's coinbase");
    // The coinbase of another block.
    let mut foreign = proof.clone();
    foreign.coinbase = serialize(&coinbase(2));
    refused(verify(&c, &s, &foreign, &script, 0, 1), "does not match exactly the coinbase and the payment");
    // A coinbase output cannot be the payment.
    let mut own = proof.clone();
    own.transaction = proof.coinbase.clone();
    refused(verify(&c, &s, &own, &p2wpkh(0xcb), 0, 1), "a coinbase output does not pay for a fill");
    // The same payment with witness data: the same transaction id, more
    // bytes that no miner was paid for. Refused, for the payment and for
    // the coinbase.
    let mut signed = tx.clone();
    signed.input[0].witness = Witness::from_slice(&[vec![1u8; 72], vec![2u8; 33]]);
    assert_eq!(signed.compute_txid(), tx.compute_txid());
    let mut padded = proof.clone();
    padded.transaction = serialize(&signed);
    refused(verify(&c, &s, &padded, &script, 0, 1), "without its witness data");
    let mut reserved = coinbase(1);
    reserved.input[0].witness = Witness::from_slice(&[vec![0u8; 32]]);
    let mut padded = proof.clone();
    padded.coinbase = serialize(&reserved);
    refused(verify(&c, &s, &padded, &script, 0, 1), "without its witness data");
}

#[test]
fn a_payment_on_a_branch_that_lost_does_not_count() {
    let script = p2wpkh(3);
    let tx = pay(&[(&script, 250_000)], 7);
    let (mut c, mut s, proof) = fixture(&tx, 1, 0);
    let start = at(&c, &s, 1);
    c.verify_payment(&s, &proof, &script, 1, &start, 1).unwrap();
    // A branch from block 1 with two blocks has more work than the payment's.
    let fork_parent = c.ancestor(&s, c.meta.best_tip, 1).unwrap();
    let a = mine(&fork_parent, fork_parent.header.time + 5, TxMerkleNode::all_zeros());
    append(&mut c, &mut s, a);
    let a_record = s.records[&a.block_hash()].clone();
    let b = mine(&a_record, a.time + 1, TxMerkleNode::all_zeros());
    append(&mut c, &mut s, b);
    assert_eq!(c.meta.best_tip, b.block_hash());
    refused(c.verify_payment(&s, &proof, &script, 1, &start, 1), "greatest-work");
}

#[test]
fn mainnet_stays_closed_and_a_halted_chain_proves_nothing() {
    let script = p2wpkh(3);
    let tx = pay(&[(&script, 250_000)], 7);
    let (c, s, proof) = fixture(&tx, 0, 0);
    let start = at(&c, &s, 0);
    let mut halted = c.clone();
    halted.meta.halted = Some(HaltReason::DeepReorg {
        old_tip: c.meta.best_tip,
        candidate: c.meta.best_tip,
        common_height: 0,
    });
    assert!(halted.verify_payment(&s, &proof, &script, 0, &start, 1).is_err());
    // Mainnet is closed to ordinary payments whatever the gate of the
    // auction's receipts says.
    for gate in [false, true] {
        let mut mainnet = c.clone();
        mainnet.meta.config.network = BitcoinNetwork::Mainnet;
        mainnet.meta.config.mainnet_receipts_enabled = gate;
        refused(mainnet.verify_payment(&s, &proof, &script, 0, &start, 1), "mainnet");
    }
}

#[test]
fn after_a_reorganisation_a_payment_below_the_starting_height_counts_unless_it_was_there_before() {
    let script = p2wpkh(3);
    // Block 1 holds a payment that exists before anything starts.
    let early = pay(&[(&script, 111)], 5);
    let (mut c, mut s, early_proof) = fixture(&early, 0, 0);
    // The purpose starts when the chain of most work ends at block 3a.
    extend(&mut c, &mut s, 2);
    let start = c.meta.best_tip;
    assert_eq!(c.meta.best_height, 3);
    // A branch from block 1: 2b holds the payment, 3b and 4b follow. It
    // has more work, and the starting block is no longer on the chain.
    let one = c.ancestor(&s, c.meta.best_tip, 1).unwrap();
    let late = pay(&[(&script, 222)], 6);
    let (b2, late_proof) = block(&one, one.header.time + 9, &[coinbase(2), late.clone()], 1);
    append(&mut c, &mut s, b2);
    let mut parent = s.records[&b2.block_hash()].clone();
    for _ in 0..2 {
        let next = mine(&parent, parent.header.time + 1, TxMerkleNode::all_zeros());
        append(&mut c, &mut s, next);
        parent = s.records[&next.block_hash()].clone();
    }
    assert_eq!(c.meta.best_height, 4);
    assert_ne!(at(&c, &s, 3), start);
    // Block 2b is below the starting height 3 and was not on the chain the
    // purpose started on: the payment counts.
    assert_eq!(c.verify_payment(&s, &late_proof, &script, 3, &start, 1).unwrap().sats, 222);
    // With two confirmations asked, the block has them (it has three), but
    // the chain has not yet grown two blocks past the starting height: a
    // branch mined in private needs the lead any payment needs, not one
    // block.
    refused(
        c.verify_payment(&s, &late_proof, &script, 3, &start, 2),
        "has its confirmations past the starting height",
    );
    let top = s.records[&c.meta.best_tip].clone();
    append(&mut c, &mut s, mine(&top, top.header.time + 1, TxMerkleNode::all_zeros()));
    assert_eq!(c.verify_payment(&s, &late_proof, &script, 3, &start, 2).unwrap().sats, 222);
    // Block 1 was on that chain: its payment existed before, and does not.
    refused(c.verify_payment(&s, &early_proof, &script, 3, &start, 1), "not after the starting block");
    // A starting block the chain does not hold proves nothing.
    let unknown = BlockHash::from_byte_array([9; 32]);
    assert!(c.verify_payment(&s, &late_proof, &script, 3, &unknown, 1).is_err());
}

#[test]
fn an_old_payment_is_proven_without_a_walk_where_the_chain_holds_one_block_at_its_height() {
    let script = p2wpkh(3);
    let tx = pay(&[(&script, 250_000)], 7);
    // Twelve hundred blocks on top of the payment's: more than any walk
    // goes. The chain holds one block at that height, so none is needed.
    let (c, s, proof) = fixture(&tx, 1, 1_200);
    assert!(1_200 > MAX_PAYMENT_WALK);
    assert_eq!(verify(&c, &s, &proof, &script, 1, 1).unwrap().confirmations, 1_201);
    // And a payment at the starting height is refused without one.
    refused(verify(&c, &s, &proof, &script, 2, 1), "not after the starting block");
}

#[test]
fn a_coinbase_may_be_short_and_a_payment_may_not() {
    let script = p2wpkh(3);
    // A coinbase of 64 bytes: a four-byte script, one output with an empty
    // script. A miner may make one; the payments of its block are proven
    // all the same.
    let small = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x00, 0x00]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(5_000_000_000), script_pubkey: ScriptBuf::new() }],
    };
    assert_eq!(serialize(&small).len(), 64);
    let tx = pay(&[(&script, 250_000)], 7);
    let (mut c, mut s) = genesis();
    let parent = s.records[&c.meta.best_tip].clone();
    let (header, proof) = block(&parent, parent.header.time + 1, &[small, tx], 1);
    append(&mut c, &mut s, header);
    assert_eq!(verify(&c, &s, &proof, &script, 0, 1).unwrap().sats, 250_000);
    // A coinbase larger than a proof may carry.
    let mut large = proof.clone();
    large.coinbase = vec![0u8; MAX_COINBASE_TX_BYTES + 1];
    refused(verify(&c, &s, &large, &script, 0, 1), "coinbase transaction bound");
    let mut large = proof.clone();
    large.transaction = vec![0u8; MAX_PAYMENT_TX_BYTES + 1];
    refused(verify(&c, &s, &large, &script, 0, 1), "payment transaction bound");
}
