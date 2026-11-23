//! A receipt that needs only the transaction's own block to be final.
use crate::{fixtures::*, light, receipt};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tendermint::{Hash, block};

const ROSTER: [(u8, u64); 4] = [(1, 10), (2, 10), (3, 10), (4, 10)];

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn leaf(raw: &[u8]) -> [u8; 32] {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&sha(raw));
    sha(&bytes)
}
fn branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = vec![1];
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    sha(&bytes)
}
/// A signed transfer of account 7 on the fixture network, as wallets send it.
fn payment(nonce: u64) -> Vec<u8> {
    let signer = key(9);
    let payload = br#"{"to":"1","amount":"5"}"#;
    let mut raw = b"TCDEVNET-ACTION-V1\0".to_vec();
    raw.extend([0xab; 32]);
    raw.push(3);
    for value in [7u64, nonce, 0] {
        raw.extend(value.to_be_bytes());
    }
    raw.extend(signer.verifying_key().as_bytes());
    raw.extend((payload.len() as u32).to_be_bytes());
    raw.extend(payload);
    let signature = signer.sign(&raw).to_bytes();
    raw.extend(signature);
    raw
}
/// A signed block at `height` holding `txs`, extending `previous`, whose
/// header commits to the results of `executed` successful transactions of the
/// block before it.
fn block_with(
    height: u64,
    txs: &[Vec<u8>],
    previous: &light::LightBlock,
    executed: u64,
) -> light::LightBlock {
    block_of_version(4, height, txs, previous, executed)
}
/// The same block with application version `app` in its header.
fn block_of_version(
    app: u64,
    height: u64,
    txs: &[Vec<u8>],
    previous: &light::LightBlock,
    executed: u64,
) -> light::LightBlock {
    let validators = roster(&ROSTER);
    let data_hash = match txs {
        [] => None,
        [one] => Some(leaf(one)),
        [a, b] => Some(branch(&leaf(a), &leaf(b))),
        _ => panic!("fixture supports at most two transactions"),
    };
    let header = block::Header {
        version: block::header::Version { block: 11, app },
        chain_id: "time-devnet-v4-fixture".parse().unwrap(),
        height: height.try_into().unwrap(),
        time: tendermint::Time::from_unix_timestamp(T0 + height as i64, 0).unwrap(),
        last_block_id: Some(previous.signed_header.commit.block_id),
        last_commit_hash: None,
        data_hash: data_hash.map(Hash::Sha256),
        validators_hash: validators.hash(),
        next_validators_hash: validators.hash(),
        consensus_hash: Hash::Sha256([4; 32]),
        app_hash: tendermint::AppHash::try_from(vec![0u8; 32]).unwrap(),
        last_results_hash: (executed > 0).then(|| Hash::Sha256(receipt::empty_results_root(executed))),
        evidence_hash: None,
        proposer_address: validators.validators()[0].address,
    };
    sign_header(header, &ROSTER, &ROSTER)
}
/// The node's transaction lookup answer for transaction `index` of `txs`.
fn lookup(height: u64, txs: &[Vec<u8>], index: usize) -> Value {
    let raw = &txs[index];
    let (root, aunts) = match txs {
        [one] => (leaf(one), vec![]),
        [a, b] => (
            branch(&leaf(a), &leaf(b)),
            vec![STANDARD.encode(leaf(&txs[1 - index]))],
        ),
        _ => panic!("fixture supports one or two transactions"),
    };
    json!({"height":height.to_string(),"hash":hex::encode(sha(raw)),"index":index,"tx":STANDARD.encode(raw),"proof":{"data":STANDARD.encode(raw),"root_hash":hex::encode(root),"proof":{"total":txs.len().to_string(),"index":index.to_string(),"leaf_hash":STANDARD.encode(leaf(raw)),"aunts":aunts}}})
}
struct Fixture {
    trust: light::Trust,
    proof: Value,
    blocks: Vec<light::LightBlock>,
}
/// Blocks 1..=4. Block 2 holds payments 1 and 2, block 4 holds payment 3.
/// The light client trusts block `trusted`; the receipt is for payment 2.
fn fixture(trusted: usize) -> Fixture {
    let (first, pin) = bootstrap(&ROSTER);
    let txs = [payment(1), payment(2)];
    let second = block_with(2, &txs, &first, 0);
    let third = block_with(3, &[], &second, 2);
    let fourth = block_with(4, &[payment(3)], &third, 0);
    let blocks = vec![first, second, third, fourth];
    let mut trust = pin;
    trust.checkpoint = Some(light::checkpoint(blocks[trusted - 1].clone()));
    let headers: Vec<Value> = blocks[1..trusted]
        .iter()
        .map(|block| serde_json::to_value(&block.signed_header.header).unwrap())
        .collect();
    Fixture {
        trust,
        proof: json!({"tx": lookup(2, &txs, 1), "headers": headers}),
        blocks,
    }
}
fn check(fixture: &Fixture) -> Result<Value, String> {
    receipt::fast_receipt(
        &fixture.proof.to_string(),
        &serde_json::to_string(&fixture.trust).unwrap(),
        ((T0 + 100) * 1000) as f64,
    )
}

#[test]
fn a_transaction_in_the_trusted_block_or_one_it_extends_is_proven() {
    for trusted in [2, 3, 4] {
        let checked = check(&fixture(trusted)).unwrap();
        assert_eq!(checked["verified"], true);
        assert_eq!(checked["executionVerified"], true);
        assert_eq!(checked["height"], "2");
        assert_eq!(checked["trustedHeight"], trusted.to_string());
        assert_eq!(checked["txHash"], hex::encode(sha(&payment(2))));
        assert_eq!(checked["rawHex"], hex::encode(payment(2)));
        assert_eq!(checked["verificationMode"], "finalized-block-inclusion");
        // With the next header in the chain, its result hash was checked too.
        assert_eq!(checked["resultsChecked"], trusted > 2);
    }
}

#[test]
fn the_next_header_must_commit_to_successful_results() {
    // A validly signed chain whose third block records results for another
    // number of transactions than the second block holds.
    let (first, pin) = bootstrap(&ROSTER);
    let txs = [payment(1), payment(2)];
    let second = block_with(2, &txs, &first, 0);
    for (executed, accepted) in [(2, true), (3, false), (1, false), (0, false)] {
        let third = block_with(3, &[], &second, executed);
        let mut trust = pin.clone();
        trust.checkpoint = Some(light::checkpoint(third.clone()));
        let headers = json!([second.signed_header.header, third.signed_header.header]);
        let result = receipt::fast_receipt(
            &json!({"tx": lookup(2, &txs, 1), "headers": headers}).to_string(),
            &serde_json::to_string(&trust).unwrap(),
            ((T0 + 100) * 1000) as f64,
        );
        assert_eq!(result.is_ok(), accepted, "results of {executed} transactions");
        if let Err(error) = result {
            assert!(error.contains("execution results"), "{error}");
        }
    }
}

#[test]
fn the_checkpoint_must_be_trusted_and_verified_first() {
    // No checkpoint at all.
    let mut f = fixture(2);
    f.trust.checkpoint = None;
    assert!(check(&f).unwrap_err().contains("FAST_RECEIPT_NEEDS_CHECKPOINT"));
    // A checkpoint whose commit does not verify is refused by the same
    // routine that guards every other proof.
    let mut f = fixture(2);
    let checkpoint = f.trust.checkpoint.as_mut().unwrap();
    let mut forged = serde_json::to_value(&checkpoint.block).unwrap();
    forged["signed_header"]["commit"]["signatures"][0]["signature"] =
        forged["signed_header"]["commit"]["signatures"][1]["signature"].clone();
    checkpoint.block = serde_json::from_value(forged).unwrap();
    assert!(check(&f).is_err());
    // An expired checkpoint is not a trust anchor.
    let f = fixture(2);
    let late = ((T0 + 8 * 86400) * 1000) as f64;
    assert!(
        receipt::fast_receipt(
            &f.proof.to_string(),
            &serde_json::to_string(&f.trust).unwrap(),
            late
        )
        .unwrap_err()
        .contains("CHECKPOINT_REFRESH_REQUIRED")
    );
}

#[test]
fn headers_must_form_the_chain_that_ends_at_the_checkpoint() {
    // The proven block is not the trusted one and no link is given.
    let mut f = fixture(3);
    f.proof["headers"].as_array_mut().unwrap().pop();
    assert!(check(&f).unwrap_err().contains("do not end at the trusted checkpoint"));
    // A header from another chain with the same height.
    let mut f = fixture(3);
    let other = block_with(2, &[payment(50)], &f.blocks[0], 0);
    f.proof["headers"][0] = serde_json::to_value(&other.signed_header.header).unwrap();
    assert!(check(&f).unwrap_err().contains("not one finalized chain"));
    // A gap in the chain.
    let mut f = fixture(4);
    f.proof["headers"].as_array_mut().unwrap().remove(1);
    assert!(check(&f).unwrap_err().contains("not one finalized chain"));
    // Headers in the wrong order.
    let mut f = fixture(3);
    f.proof["headers"].as_array_mut().unwrap().reverse();
    assert!(check(&f).is_err());
    // No headers, and more headers than the format allows.
    let mut f = fixture(2);
    f.proof["headers"] = json!([]);
    assert!(check(&f).unwrap_err().contains("header count"));
    let mut f = fixture(2);
    let one = f.proof["headers"][0].clone();
    f.proof["headers"] = json!(vec![one; receipt::MAX_FAST_HEADERS + 1]);
    assert!(check(&f).unwrap_err().contains("header count"));
    // A modified field changes the header hash and breaks the link.
    let mut f = fixture(3);
    f.proof["headers"][0]["data_hash"] = json!(hex::encode([7u8; 32]).to_uppercase());
    assert!(check(&f).is_err());
}

#[test]
fn the_transaction_must_be_the_one_in_the_proven_block() {
    for mutation in 0..8 {
        let mut f = fixture(3);
        let tx = &mut f.proof["tx"];
        match mutation {
            0 => tx["tx"] = json!(STANDARD.encode(payment(60))),
            1 => tx["hash"] = json!("00".repeat(32)),
            2 => tx["height"] = json!("3"),
            3 => tx["index"] = json!(0),
            4 => tx["proof"]["proof"]["aunts"] = json!([STANDARD.encode([9u8; 32])]),
            5 => tx["proof"]["proof"]["total"] = json!("3"),
            6 => tx["proof"]["data"] = json!(STANDARD.encode(payment(1))),
            _ => tx["proof"]["root_hash"] = json!("11".repeat(32)),
        }
        assert!(check(&f).is_err(), "mutation {mutation} was accepted");
    }
    // A valid proof for the transaction of block 4 does not pass as block 2.
    let mut f = fixture(4);
    f.proof["tx"] = lookup(2, &[payment(3)], 0);
    assert!(check(&f).is_err());
    // Unknown fields are refused rather than ignored.
    let mut f = fixture(2);
    f.proof["next_signed_header"] = json!({});
    assert!(check(&f).is_err());
}

/// A change of the protocol version (docs/design/upgrade-mechanism.md, 8.1,
/// rule 3). The proof is the second payment of block 2 under a checkpoint at
/// block 4; `versions` are the application versions of blocks 2, 3 and 4.
fn across_versions(versions: [u64; 3], forge: impl FnOnce(&mut Value)) -> Result<Value, String> {
    let (first, pin) = bootstrap(&ROSTER);
    let txs = [payment(1), payment(2)];
    let second = block_of_version(versions[0], 2, &txs, &first, 0);
    let third = block_of_version(versions[1], 3, &[], &second, 2);
    let fourth = block_of_version(versions[2], 4, &[payment(3)], &third, 0);
    let mut trust = pin;
    trust.checkpoint = Some(light::checkpoint(fourth.clone()));
    let mut proof = json!({"tx": lookup(2, &txs, 1), "headers": [second.signed_header.header, third.signed_header.header, fourth.signed_header.header]});
    forge(&mut proof);
    receipt::fast_receipt(
        &proof.to_string(),
        &serde_json::to_string(&trust).unwrap(),
        ((T0 + 100) * 1000) as f64,
    )
}

#[test]
fn a_block_of_a_version_this_build_does_not_implement_asks_for_an_upgrade() {
    // Today's chain.
    assert_eq!(across_versions([4, 4, 4], |_| {}).unwrap()["verified"], true);
    // The transaction's own block is of a version this build implements;
    // the blocks after it and the checkpoint are of a later one. They are
    // only hashed, so the payment is proven, its results included.
    let proven = across_versions([4, 5, 5], |_| {}).unwrap();
    assert_eq!(proven["verified"], true);
    assert_eq!(proven["resultsChecked"], true);
    assert_eq!(proven["trustedHeight"], "4");
    // The transaction's own block is of a later version: not judged.
    for versions in [[5, 5, 5], [5, 6, 7], [9, 9, 9]] {
        let error = across_versions(versions, |_| {}).unwrap_err();
        assert!(error.starts_with("UPGRADE_REQUIRED: "), "{error}");
        assert!(error.contains(&format!("protocol version {}", versions[0])), "{error}");
    }
    // Below the network's first version: refused as before.
    let error = across_versions([3, 4, 4], |_| {}).unwrap_err();
    assert!(error.contains("chain/version mismatch"), "{error}");
    // A gateway cannot produce the answer by writing a version into a
    // header: the header then no longer hashes into the verified chain.
    for index in 0..3 {
        let error = across_versions([4, 4, 4], |proof| {
            proof["headers"][index]["version"]["app"] = json!("5");
        })
        .unwrap_err();
        assert!(!error.contains("UPGRADE_REQUIRED"), "header {index}: {error}");
    }
}

/// Writes the blocks of `fixture` for the gateway and SDK tests.
#[test]
fn export_fast_receipt_fixture_when_requested() {
    if std::env::var("V4_EXPORT_FAST_RECEIPT_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    let f = fixture(4);
    let (_, pin) = bootstrap(&ROSTER);
    let encode = |txs: &[Vec<u8>]| -> Vec<String> { txs.iter().map(|tx| STANDARD.encode(tx)).collect() };
    let value = json!({
        "trust": pin,
        "now_ms": (T0 + 100) * 1000,
        "blocks": f.blocks,
        "txs": {"1": encode(&[]), "2": encode(&[payment(1), payment(2)]), "3": encode(&[]), "4": encode(&[payment(3)])},
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("fast-receipt.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
}
