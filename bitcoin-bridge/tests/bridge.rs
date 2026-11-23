//! Regtest PoW/Merkle unit fixtures. These are not a claim of full Bitcoin
//! transaction validity; the separate Bitcoin Core regtest runner supplies that.
use bitcoin::{
    Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Txid,
    Witness,
    absolute::LockTime,
    block::{Header, Version},
    consensus::serialize,
    hashes::Hash,
    merkle_tree::MerkleBlock,
    pow::CompactTarget,
    transaction::Version as TxVersion,
};
use std::collections::BTreeSet;
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
fn payment(context: &BidContext, script: &[u8], sats: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(bid_commitment_script(context)),
            },
        ],
    }
}
fn receipt_fixture() -> (
    HeaderChain,
    MemoryHeaderStore,
    ReceivingPolicy,
    BidContext,
    ReceiptProof,
    u64,
) {
    let (mut c, mut s) = genesis();
    let g = s.records[&c.meta.best_tip].clone();
    let context = BidContext {
        time_network: [9; 32],
        account: 42,
        auction_epoch: 7,
        policy_revision: 3,
        time_micros: u64::from(g.header.time + 100) * 1_000_000,
    };
    let script = [vec![0, 32], vec![3; 32]].concat();
    let policy = ReceivingPolicy {
        network: BitcoinNetwork::Regtest,
        time_network: [9; 32],
        revision: 3,
        script_pubkey: script.clone(),
        min_sats: 100,
        max_sats: 1_000_000,
        btc_start_height: 1,
        btc_end_height: None,
        time_start_micros: 0,
        time_end_micros: None,
    };
    let tx = payment(&context, &script, 100_000);
    let id = tx.compute_txid();
    let header = mine(
        &g,
        g.header.time + 1,
        TxMerkleNode::from_byte_array(id.to_byte_array()),
    );
    append(&mut c, &mut s, header);
    let merkle = MerkleBlock::from_header_txids_with_predicate(&header, &[id], |t| *t == id);
    let proof = ReceiptProof {
        network: BitcoinNetwork::Regtest,
        block_hash: header.block_hash(),
        transaction: serialize(&tx),
        vout: 0,
        expected_sats: 100_000,
        merkle_proof: serialize(&merkle),
    };
    extend(&mut c, &mut s, 11);
    let now = u64::from(s.records[&c.meta.best_tip].header.time);
    (c, s, policy, context, proof, now)
}

#[test]
fn real_pow_headers_reject_bad_target_links_mtp_future_and_no_effect_duplicates() {
    let (mut c, mut s) = genesis();
    let p = s.records[&c.meta.best_tip].clone();
    let good = mine(&p, p.header.time + 1, TxMerkleNode::all_zeros());
    let mut bad = good;
    bad.prev_blockhash = BlockHash::all_zeros();
    assert!(c.prepare_headers(&s, &[bad], u64::from(good.time)).is_err());
    let mut bad = good;
    bad.bits = CompactTarget::from_consensus(0x2100ffff);
    assert!(c.prepare_headers(&s, &[bad], u64::from(good.time)).is_err());
    let mut bad = good;
    bad.bits = CompactTarget::from_consensus(0x207ffffe);
    bad.nonce = 0;
    while bad.validate_pow(bad.target()).is_err() {
        bad.nonce += 1;
    }
    assert!(
        c.prepare_headers(&s, &[bad], u64::from(good.time)).is_err(),
        "real proof of work at an incorrect difficulty must still fail"
    );
    let mut bad = mine(&p, p.header.time, TxMerkleNode::all_zeros());
    assert!(c.prepare_headers(&s, &[bad], u64::from(good.time)).is_err());
    bad = mine(&p, p.header.time + 7201, TxMerkleNode::all_zeros());
    assert!(
        c.prepare_headers(&s, &[bad], u64::from(p.header.time))
            .is_err()
    );
    let mut no_pow = good;
    while no_pow.validate_pow(no_pow.target()).is_ok() {
        no_pow.nonce += 1;
    }
    assert!(
        c.prepare_headers(&s, &[no_pow], u64::from(good.time))
            .is_err()
    );
    append(&mut c, &mut s, good);
    assert!(
        c.prepare_headers(&s, &[good], u64::from(good.time))
            .is_err()
    );
    assert_eq!(c.meta.best_height, 1);
}

#[test]
fn failed_header_batch_is_atomic_and_state_is_serializable() {
    let (c, s) = genesis();
    let p = s.records[&c.meta.best_tip].clone();
    let good = mine(&p, p.header.time + 1, TxMerkleNode::all_zeros());
    let mut bad = good;
    bad.prev_blockhash = BlockHash::all_zeros();
    let before = serde_json::to_vec(&c).unwrap();
    assert!(
        c.prepare_headers(&s, &[good, bad], u64::from(good.time))
            .is_err()
    );
    assert_eq!(serde_json::to_vec(&c).unwrap(), before);
    assert_eq!(s.records.len(), 1);
    let restored: HeaderChain = serde_json::from_slice(&before).unwrap();
    restored.validate(&s).unwrap();
    assert!(before.len() < 64 * 1024);
}

#[test]
fn network_genesis_pins_and_default_mainnet_gate_are_explicit() {
    let main =
        HeaderChain::bootstrap_genesis(BridgeConfig::for_network(BitcoinNetwork::Mainnet)).unwrap();
    let test = HeaderChain::bootstrap_genesis(BridgeConfig::for_network(BitcoinNetwork::Testnet3))
        .unwrap();
    let reg =
        HeaderChain::bootstrap_genesis(BridgeConfig::for_network(BitcoinNetwork::Regtest)).unwrap();
    let hashes: BTreeSet<_> = [
        main.chain.meta.best_tip,
        test.chain.meta.best_tip,
        reg.chain.meta.best_tip,
    ]
    .into_iter()
    .collect();
    assert_eq!(hashes.len(), 3);
    assert!(!main.chain.meta.config.mainnet_receipts_enabled);
    let mut wrong = reg.chain.clone();
    wrong.meta.config.network = BitcoinNetwork::Mainnet;
    let mut s = MemoryHeaderStore::default();
    s.apply(&reg);
    assert!(wrong.validate(&s).is_err());
}

#[test]
fn accepted_receipt_exact_binding_confirmations_and_consumption() {
    let (c, s, policy, context, proof, now) = receipt_fixture();
    let mut index = MemoryReceiptIndex::default();
    let accepted = c
        .prepare_receipt(&s, &index, &proof, &policy, &context, now)
        .unwrap();
    assert_eq!(accepted.receipt.sats, 100_000);
    assert_eq!(accepted.receipt.account, 42);
    assert_eq!(accepted.receipt.confirmations, 12);
    assert_eq!(accepted.chain.meta.credited_height, 1);
    index.apply(&accepted).unwrap();
    assert!(
        accepted
            .chain
            .prepare_receipt(&s, &index, &proof, &policy, &context, now)
            .is_err()
    );
    assert!(index.apply(&accepted).is_err());
    let mut not_confirmed = c.clone();
    not_confirmed.meta.best_tip = s.heights[&11][0];
    not_confirmed.meta.best_height = 11;
    not_confirmed.meta.best_work = s.records[&not_confirmed.meta.best_tip].chainwork;
    assert!(
        not_confirmed
            .prepare_receipt(
                &s,
                &MemoryReceiptIndex::default(),
                &proof,
                &policy,
                &context,
                now
            )
            .is_err()
    );
}

#[test]
fn forgery_wrong_network_context_script_value_epoch_revision_and_proof_all_rejected() {
    let (c, s, policy, context, proof, now) = receipt_fixture();
    let index = MemoryReceiptIndex::default();
    for network in [BitcoinNetwork::Mainnet, BitcoinNetwork::Testnet3] {
        let mut p = proof.clone();
        p.network = network;
        assert!(
            c.prepare_receipt(&s, &index, &p, &policy, &context, now)
                .is_err()
        );
    }
    for field in 0..4 {
        let mut ctx = context.clone();
        match field {
            0 => ctx.time_network = [1; 32],
            1 => ctx.account += 1,
            2 => ctx.auction_epoch += 1,
            _ => ctx.policy_revision += 1,
        };
        assert!(
            c.prepare_receipt(&s, &index, &proof, &policy, &ctx, now)
                .is_err()
        );
    }
    let mut p = policy.clone();
    p.script_pubkey[2] ^= 1;
    assert!(
        c.prepare_receipt(&s, &index, &proof, &p, &context, now)
            .is_err()
    );
    let mut p = proof.clone();
    p.expected_sats += 1;
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .is_err()
    );
    let mut p = proof.clone();
    p.merkle_proof[90] ^= 1;
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .is_err()
    );
    let mut p = proof.clone();
    p.transaction[20] ^= 1;
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .is_err()
    );
    let mut p = proof.clone();
    p.merkle_proof.extend_from_slice(&[0]);
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .is_err()
    );
    let mut p = proof.clone();
    p.merkle_proof[84] = 0xfe;
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .is_err()
    );
}

#[test]
fn receiving_policy_height_time_windows_and_stale_header_gate() {
    let (c, s, policy, context, proof, now) = receipt_fixture();
    let index = MemoryReceiptIndex::default();
    let mut p = policy.clone();
    p.btc_start_height = 2;
    assert!(
        c.prepare_receipt(&s, &index, &proof, &p, &context, now)
            .is_err()
    );
    let mut p = policy.clone();
    p.btc_end_height = Some(1);
    assert!(
        c.prepare_receipt(&s, &index, &proof, &p, &context, now)
            .is_err()
    );
    let mut p = policy.clone();
    p.time_end_micros = Some(context.time_micros);
    assert!(
        c.prepare_receipt(&s, &index, &proof, &p, &context, now)
            .is_err()
    );
    assert!(
        c.prepare_receipt(&s, &index, &proof, &policy, &context, now + 7201)
            .is_err()
    );
}

#[test]
fn duplicate_nonminimal_and_nonzero_value_bid_commitments_rejected() {
    let (c, s, policy, context, proof, now) = receipt_fixture();
    let index = MemoryReceiptIndex::default();
    let tx: Transaction = bitcoin::consensus::deserialize(&proof.transaction).unwrap();
    let mut duplicate = tx.clone();
    duplicate.output.push(duplicate.output[1].clone());
    let mut p = proof.clone();
    p.transaction = serialize(&duplicate);
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .unwrap_err()
            .to_string()
            .contains("exactly one")
    );
    let mut nonminimal = tx.clone();
    let mut script = vec![0x6a, 0x4c, 64];
    script.extend_from_slice(&bid_commitment(&context));
    nonminimal.output[1].script_pubkey = ScriptBuf::from_bytes(script);
    let mut p = proof.clone();
    p.transaction = serialize(&nonminimal);
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .unwrap_err()
            .to_string()
            .contains("noncanonical")
    );
    let mut nonzero = tx;
    nonzero.output[1].value = Amount::from_sat(1);
    let mut p = proof;
    p.transaction = serialize(&nonzero);
    assert!(
        c.prepare_receipt(&s, &index, &p, &policy, &context, now)
            .unwrap_err()
            .to_string()
            .contains("must be zero")
    );
}

#[test]
fn heavier_reorg_removing_credited_anchor_pauses_new_earning_without_time_rollback() {
    let (c, mut s, policy, context, proof, now) = receipt_fixture();
    let accepted = c
        .prepare_receipt(
            &s,
            &MemoryReceiptIndex::default(),
            &proof,
            &policy,
            &context,
            now,
        )
        .unwrap();
    let c = accepted.chain;
    let mut parent = s.records[&c.meta.checkpoint.hash].clone();
    let mut fork = Vec::new();
    for n in 1..=13 {
        let header = mine(
            &parent,
            parent.header.time + 2,
            TxMerkleNode::from_byte_array([n; 32]),
        );
        let work = parent.chainwork + header.work();
        parent = HeaderRecord {
            header,
            height: n as u32,
            chainwork: work,
        };
        fork.push(header);
    }
    let transition = c
        .prepare_headers(&s, &fork, u64::from(parent.header.time))
        .unwrap();
    assert!(matches!(
        transition.chain.meta.halted,
        Some(HaltReason::CreditedReceiptReorg { .. })
    ));
    assert_eq!(transition.chain.meta.best_tip, c.meta.best_tip);
    s.apply(&transition);
    assert!(
        transition
            .chain
            .prepare_receipt(
                &s,
                &MemoryReceiptIndex::default(),
                &proof,
                &policy,
                &context,
                u64::from(parent.header.time)
            )
            .is_err()
    );
}

#[test]
fn paused_batch_retires_staged_fork_spam_and_validates_its_entire_suffix() {
    let (c, mut s, policy, context, proof, now) = receipt_fixture();
    let accepted = c
        .prepare_receipt(
            &s,
            &MemoryReceiptIndex::default(),
            &proof,
            &policy,
            &context,
            now,
        )
        .unwrap();
    let mut c = accepted.chain;
    c.meta.config.max_fork_tips = 2;
    let genesis = s.records[&c.meta.checkpoint.hash].clone();
    let mut headers = Vec::new();
    for n in 1..=30 {
        headers.push(mine(
            &genesis,
            genesis.header.time + 2,
            TxMerkleNode::from_byte_array([n; 32]),
        ));
    }
    let mut parent = genesis;
    for n in 1..=13 {
        let h = mine(
            &parent,
            parent.header.time + 3,
            TxMerkleNode::from_byte_array([100 + n; 32]),
        );
        parent = HeaderRecord {
            header: h,
            height: n as u32,
            chainwork: parent.chainwork + h.work(),
        };
        headers.push(h);
    }
    let mut with_invalid_suffix = headers.clone();
    let mut bad = parent.header;
    bad.prev_blockhash = BlockHash::all_zeros();
    with_invalid_suffix.push(bad);
    assert!(
        c.prepare_headers(&s, &with_invalid_suffix, u64::from(parent.header.time))
            .is_err(),
        "a halt must not cause the remaining header batch to bypass validation"
    );
    let transition = c
        .prepare_headers(&s, &headers, u64::from(parent.header.time))
        .unwrap();
    s.apply(&transition);
    let c = transition.chain;
    assert!(c.meta.halted.is_some());
    assert_eq!(c.meta.record_count, 26);
    assert_eq!(s.records.len(), 26);
    assert!(
        s.heights
            .values()
            .all(|hashes| hashes.len() <= c.meta.config.max_fork_tips + 1)
    );
    c.validate(&s).unwrap();
}

#[test]
fn deep_reorg_policy_pauses_a_valid_heavier_fork() {
    let (mut c, mut s) = genesis();
    c.meta.config.max_reorg = 12;
    extend(&mut c, &mut s, 14);
    let old_tip = c.meta.best_tip;
    let mut parent = s.records[&c.meta.checkpoint.hash].clone();
    let mut headers = Vec::new();
    for n in 1..=15 {
        let h = mine(
            &parent,
            parent.header.time + 2,
            TxMerkleNode::from_byte_array([n; 32]),
        );
        parent = HeaderRecord {
            header: h,
            height: n as u32,
            chainwork: parent.chainwork + h.work(),
        };
        headers.push(h);
    }
    let transition = c
        .prepare_headers(&s, &headers, u64::from(parent.header.time))
        .unwrap();
    assert!(matches!(
        transition.chain.meta.halted,
        Some(HaltReason::DeepReorg { .. })
    ));
    assert_eq!(transition.chain.meta.best_tip, old_tip);
    let mut too_many = c.meta.config.clone();
    too_many.max_fork_tips = 0;
    assert!(too_many.validate().is_err());
}

#[test]
fn full_frontier_cannot_block_a_new_higher_work_fork() {
    let (mut c, mut s) = genesis();
    c.meta.config.max_fork_tips = 2;
    extend(&mut c, &mut s, 3);
    let original = c.meta.best_tip;
    let g = s.records[&c.meta.checkpoint.hash].clone();
    let a = mine(
        &g,
        g.header.time + 2,
        TxMerkleNode::from_byte_array([1; 32]),
    );
    let arow = HeaderRecord {
        header: a,
        height: 1,
        chainwork: g.chainwork + a.work(),
    };
    let a2 = mine(&arow, a.time + 1, TxMerkleNode::from_byte_array([2; 32]));
    let t = c.prepare_headers(&s, &[a, a2], u64::from(a2.time)).unwrap();
    s.apply(&t);
    c = t.chain;
    assert_eq!(c.meta.tips.len(), 2);
    let mut parent = g.clone();
    let mut branch = Vec::new();
    for n in 1..=4 {
        let h = mine(
            &parent,
            parent.header.time + 3,
            TxMerkleNode::from_byte_array([10 + n; 32]),
        );
        parent = HeaderRecord {
            header: h,
            height: n as u32,
            chainwork: parent.chainwork + h.work(),
        };
        branch.push(h);
    }
    let t = c
        .prepare_headers(&s, &branch, u64::from(parent.header.time))
        .unwrap();
    s.apply(&t);
    c = t.chain;
    assert_eq!(c.meta.best_tip, parent.header.block_hash());
    assert_eq!(c.meta.tips.len(), 2);
    assert!(c.meta.tips.contains(&original));
    assert!(!s.records.contains_key(&a.block_hash()));
    let unretained = mine(
        &g,
        g.header.time + 4,
        TxMerkleNode::from_byte_array([99; 32]),
    );
    assert!(
        c.prepare_headers(&s, &[unretained], u64::from(parent.header.time))
            .is_err()
    );
}

#[test]
fn expired_sibling_forks_sharing_history_are_pruned_without_dangling_nodes() {
    let (mut c, mut s) = genesis();
    c.meta.config.max_reorg = 12;
    c.meta.config.max_fork_tips = 3;
    extend(&mut c, &mut s, 3);
    let g = s.records[&c.meta.checkpoint.hash].clone();
    let shared = mine(
        &g,
        g.header.time + 2,
        TxMerkleNode::from_byte_array([1; 32]),
    );
    let parent = HeaderRecord {
        header: shared,
        height: 1,
        chainwork: g.chainwork + shared.work(),
    };
    let a = mine(
        &parent,
        shared.time + 1,
        TxMerkleNode::from_byte_array([2; 32]),
    );
    let b = mine(
        &parent,
        shared.time + 1,
        TxMerkleNode::from_byte_array([3; 32]),
    );
    let t = c
        .prepare_headers(&s, &[shared, a, b], u64::from(a.time))
        .unwrap();
    s.apply(&t);
    c = t.chain;
    assert_eq!(c.meta.tips.len(), 3);
    extend(&mut c, &mut s, 17);
    assert_eq!(c.meta.best_height, 20);
    assert_eq!(c.meta.tips.len(), 1);
    assert_eq!(s.records.len(), 21);
    assert_eq!(c.meta.record_count, 21);
    c.validate(&s).unwrap();
}

#[test]
fn retained_header_window_preserves_future_retarget_and_mtp_context() {
    let (mut c, mut s) = genesis();
    c.meta.config.max_reorg = 12;
    c.meta.config.retention = 4055;
    let mut remaining = 4140;
    while remaining > 0 {
        let count = remaining.min(256);
        let mut parent = s.records[&c.meta.best_tip].clone();
        let mut batch = Vec::new();
        for _ in 0..count {
            let header = mine(&parent, parent.header.time + 1, TxMerkleNode::all_zeros());
            parent = HeaderRecord {
                header,
                height: parent.height + 1,
                chainwork: parent.chainwork + header.work(),
            };
            batch.push(header);
        }
        let t = c
            .prepare_headers(&s, &batch, u64::from(parent.header.time))
            .unwrap();
        s.apply(&t);
        c = t.chain;
        remaining -= count;
    }
    assert_eq!(c.meta.best_height, 4140);
    assert_eq!(c.meta.pruned_below, 85);
    assert_eq!(s.records.len(), 4056);
    assert_eq!(c.meta.record_count, 4056);
    assert!(c.ancestor(&s, c.meta.best_tip, 84).is_err());
    extend(&mut c, &mut s, 1);
    c.validate(&s).unwrap();
}

#[test]
fn mainnet_receipt_gate_runs_before_decoding_untrusted_payment_bytes() {
    let transition =
        HeaderChain::bootstrap_genesis(BridgeConfig::for_network(BitcoinNetwork::Mainnet)).unwrap();
    let mut s = MemoryHeaderStore::default();
    s.apply(&transition);
    let c = transition.chain;
    let now = u64::from(s.records[&c.meta.best_tip].header.time);
    let policy = ReceivingPolicy {
        network: BitcoinNetwork::Mainnet,
        time_network: [1; 32],
        revision: 0,
        script_pubkey: vec![0, 20, 1],
        min_sats: 1,
        max_sats: 100,
        btc_start_height: 0,
        btc_end_height: None,
        time_start_micros: 0,
        time_end_micros: None,
    };
    let context = BidContext {
        time_network: [1; 32],
        account: 0,
        auction_epoch: 0,
        policy_revision: 0,
        time_micros: now * 1_000_000,
    };
    let proof = ReceiptProof {
        network: BitcoinNetwork::Mainnet,
        block_hash: c.meta.best_tip,
        transaction: vec![],
        vout: 0,
        expected_sats: 1,
        merkle_proof: vec![],
    };
    assert!(
        c.prepare_receipt(
            &s,
            &MemoryReceiptIndex::default(),
            &proof,
            &policy,
            &context,
            now
        )
        .unwrap_err()
        .to_string()
        .contains("mainnet Bitcoin receipts are disabled")
    );
}

#[test]
fn bitcoin_core_mainnet_retarget_reference_vectors() {
    // Values from Bitcoin Core v30.0 src/test/pow_tests.cpp. This tests target
    // arithmetic only, not a claim that synthetic headers prove mainnet work.
    let params = bitcoin::consensus::Params::MAINNET;
    for (bits, start, end, want) in [
        (0x1d00ffff, 1261130161u64, 1262152739u64, 0x1d00d86a),
        (0x1d00ffff, 1231006505, 1233061996, 0x1d00ffff),
        (0x1c05a3f4, 1279008237, 1279297671, 0x1c0168fd),
        (0x1c387f6f, 1263163443, 1269211443, 0x1d00e1fd),
    ] {
        assert_eq!(
            CompactTarget::from_next_work_required(
                CompactTarget::from_consensus(bits),
                end - start,
                &params
            )
            .to_consensus(),
            want
        );
    }
}

#[test]
fn trusted_checkpoint_requires_pinned_hash_network_and_complete_context() {
    let (mut c, mut s) = genesis();
    extend(&mut c, &mut s, 20);
    let headers: Vec<_> = (0..=20)
        .map(|h| s.records[&s.heights[&h][0]].header)
        .collect();
    let pin = TrustedCheckpoint {
        network: BitcoinNetwork::Regtest,
        height: 20,
        hash: c.meta.best_tip,
        chainwork: c.meta.best_work,
    };
    let restored = HeaderChain::bootstrap_trusted_checkpoint(
        c.meta.config.clone(),
        pin.clone(),
        headers.clone(),
    )
    .unwrap();
    assert!(restored.chain.meta.trusted_checkpoint);
    let mut missing = headers.clone();
    missing.remove(0);
    assert!(
        HeaderChain::bootstrap_trusted_checkpoint(c.meta.config.clone(), pin.clone(), missing)
            .is_err()
    );
    let mut wrong = pin.clone();
    wrong.hash = BlockHash::all_zeros();
    assert!(
        HeaderChain::bootstrap_trusted_checkpoint(c.meta.config.clone(), wrong, headers.clone())
            .is_err()
    );
    let mut wrong = pin;
    wrong.network = BitcoinNetwork::Mainnet;
    assert!(HeaderChain::bootstrap_trusted_checkpoint(c.meta.config, wrong, headers).is_err());
}
