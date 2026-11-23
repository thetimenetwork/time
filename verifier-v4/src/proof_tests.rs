use crate::{fixtures::*, light, receipt, view};
use base64::{Engine, engine::general_purpose::STANDARD};
use jmt::{JellyfishMerkleTree, mock::MockTreeStore};
use serde_json::{Value, json};
use sha2_10::{Digest, Sha256};
fn kh(key: &[u8]) -> jmt::KeyHash {
    jmt::KeyHash(Sha256::digest([b"TCDEVNET-KEY-V2\0".as_slice(), key].concat()).into())
}
fn id(prefix: &[u8], n: u64) -> Vec<u8> {
    [prefix, &n.to_be_bytes()].concat()
}
fn leaf(raw: &[u8]) -> [u8; 32] {
    Sha256::digest([&[0u8][..], raw].concat()).into()
}
struct HistoryMemory {
    leaves: Vec<history::Leaf>,
    nodes: Vec<history::Hash>,
}
impl history::Reader for HistoryMemory {
    fn leaf(&mut self, height: u64) -> Result<history::Leaf, anyhow::Error> {
        self.leaves
            .get(height as usize - 1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing test leaf"))
    }
    fn node(&mut self, index: u64) -> Result<history::Hash, anyhow::Error> {
        self.nodes
            .get(index as usize)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("missing test node"))
    }
}
pub fn fixture() -> Value {
    fixture_with(|_| {})
}
/// The same fixture with the metadata row changed by `edit` before it is
/// committed and signed.
pub fn fixture_with(edit: impl FnOnce(&mut Value)) -> Value {
    fixture_built(edit, Vec::new(), Vec::new(), 4, 4)
}
/// The fixture with the metadata row changed by `edit`, the rows `more`
/// added to the state and the keys `absent` proven absent in it. The header
/// that certifies the state (height 6) carries application version
/// `anchor_version`; the two headers of the receipt (heights 1 and 2) carry
/// `receipt_version`.
pub fn fixture_built(
    edit: impl FnOnce(&mut Value),
    more: Vec<(Vec<u8>, Value)>,
    absent: Vec<Vec<u8>>,
    anchor_version: u64,
    receipt_version: u64,
) -> Value {
    let a = [(1, 10), (2, 10), (3, 10), (4, 10)];
    let b = [(5, 10), (6, 10), (7, 10), (8, 10)];
    let mut h1 = block(1, &a, &a, None, T0 + 1).signed_header.header;
    h1.version.app = receipt_version;
    let raw = b"public fixture transaction";
    let hash: [u8; 32] = Sha256::digest(raw).into();
    let data = leaf(&hash);
    h1.data_hash = Some(tendermint::Hash::Sha256(data));
    let first = sign_header(h1, &a, &a);
    let mut h2 = block(2, &a, &b, Some(&first), T0 + 2).signed_header.header;
    h2.version.app = receipt_version;
    h2.last_results_hash = Some(tendermint::Hash::Sha256(leaf(&[])));
    let second = sign_header(h2, &a, &b);
    let genesis = json!({"chain_id":"time-devnet-v4-fixture","genesis_time_micros":((T0+1)*1_000_000).to_string()});
    let mut meta = json!({"protocol_version":"4","network_id":"ab".repeat(32),"height":"5","time_micros":((T0+1209899)*1_000_000).to_string(),"genesis":genesis,"config":{"ledger":genesis,"reward_version":1,"history_version":1,"bitcoin_receipt_version":1,"recovery_approval_window_micros":"604800000000","registration":{"fee_micros":"10000","max_lifetime_micros":"86400000000","bucket_micros":"3600000000"},"recovery_min_delay_micros":"30000000"},"bank":"1209898000000","liquid_total":"0","pos_assets_total":"0","auction_reserve_total":"0","unbond_total":"0","next_unbond_id":"0","pools":[],"pool_share_totals":[],"auction_bids":[],"name_commits":[],"account_count":"1","next_account_id":"1"});
    let account = json!({"id":"0","name":"alice","public_key":hex::encode(key(42).verifying_key().to_bytes()),"balance":"0","nonce":"0","auth_epoch":"0","devices":[{"public_key":hex::encode(key(42).verifying_key().to_bytes()),"can_manage":true,"can_spend":true}],"delegations":[],"unbonding":[]});
    edit(&mut meta);
    let mut rows = vec![
        (b"meta".to_vec(), meta),
        (b"name/alice".to_vec(), json!("0")),
        (id(b"account/", 0), account),
    ];
    let third = block(3, &b, &b, Some(&second), T0 + 3);
    let fourth = block(4, &b, &b, Some(&third), T0 + 4);
    let fifth = block(5, &b, &b, Some(&fourth), T0 + 1209899);
    let mut summary = history::Summary::empty([0xab; 32], ((T0 + 1) * 1_000_000) as u64);
    let mut memory = HistoryMemory {
        leaves: Vec::new(),
        nodes: Vec::new(),
    };
    for block in [&first, &second, &third, &fourth, &fifth] {
        let header = &block.signed_header.header;
        let append = summary
            .append(history::Leaf {
                height: header.height.value(),
                block_hash: header.hash().to_string().to_lowercase(),
                time_micros: (header.time.unix_timestamp_nanos() / 1000) as u64,
            })
            .unwrap();
        memory.leaves.push(append.leaf);
        memory.nodes.extend(append.nodes);
        summary = append.summary;
    }
    rows.push((
        history::KEY.to_vec(),
        serde_json::to_value(&summary).unwrap(),
    ));
    rows.push((id(b"pos/owner/",0),json!({"owner":"0","positions":[],"exits":[{"id":"1","candidate":"0","kind":"delegation","units":"1","requested_height":"1","release_height":"3"},{"id":"2","candidate":"0","kind":"delegation","units":"1","requested_height":"4","release_height":"6"}]})));
    rows.push((
        id(b"pos/release_time/", 3),
        json!(((T0 + 3) * 1_000_000).to_string()),
    ));
    let mut history_proofs = serde_json::Map::new();
    for height in [1u64, 2] {
        history_proofs.insert(
            height.to_string(),
            serde_json::to_value(history::prove(&mut memory, &summary, height).unwrap()).unwrap(),
        );
    }
    rows.push(([b"registration/commit/".as_slice(),&[0xcc;32]].concat(),json!({"public_key":"cc".repeat(32),"commitment":"dd".repeat(32),"entry_id":"ee".repeat(32),"sponsor":"0","created_elapsed_micros":"1209898000000","expires_elapsed_micros":"1296298000000","height":"5"})));
    rows.extend(more);
    let db = MockTreeStore::default();
    let tree = JellyfishMerkleTree::<_, Sha256>::new(&db);
    let (root, batch) = tree
        .put_value_set(
            rows.iter()
                .map(|(k, v)| (kh(k), Some(serde_json::to_vec(v).unwrap()))),
            0,
        )
        .unwrap();
    db.write_tree_update_batch(batch).unwrap();
    let mut keys = rows.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
    keys.extend([
        b"name/missing".to_vec(),
        id(b"recovery/", 0),
        id(b"account/", 999),
        [b"pubkey/".as_slice(), &[0xcc; 32]].concat(),
        [b"pubkey/".as_slice(), &[0xff; 32]].concat(),
        [b"registration/commit/".as_slice(), &[0xff; 32]].concat(),
        id(b"block/", 1),
        id(b"block_time/", 1),
        id(b"block/", 2),
        id(b"block_time/", 2),
        id(b"pos/release_time/", 6),
    ]);
    keys.extend(absent);
    let entries:Vec<Value>=keys.iter().map(|key|{let(value,proof)=tree.get_with_proof(kh(key),0).unwrap();json!({"key_hex":hex::encode(key),"value_b64":value.map(|v|STANDARD.encode(v)),"proof":proof})}).collect();
    let mut h6 = block(6, &b, &b, Some(&fifth), T0 + 1209900)
        .signed_header
        .header;
    h6.app_hash = tendermint::AppHash::try_from(root.0.to_vec()).unwrap();
    h6.version.app = anchor_version;
    let sixth = sign_header(h6, &b, &b);
    let pin = trust(&a, Some(light::checkpoint(sixth.clone())));
    let proof =
        json!({"height":"5","entries":entries,"history_proofs":history_proofs,"light_block":sixth});
    json!({"trust":pin,"now_ms":(T0+1209901)*1000,"request":{"names":["alice","missing"],"ids":["999"],"owners":["0"],"public_keys":["cc".repeat(32),"ff".repeat(32)],"blocks":["1","2"]},"proof":proof,"receipt":{"tx":{"height":"1","hash":hex::encode(hash),"index":0,"tx":STANDARD.encode(raw),"proof":{"data":STANDARD.encode(raw),"root_hash":hex::encode(data),"proof":{"total":"1","index":"0","leaf_hash":STANDARD.encode(data),"aunts":[]}}},"signed_header":first.signed_header,"next_signed_header":second.signed_header,"anchor":proof}})
}
fn check(f: &Value) -> Result<Value, String> {
    view::view(
        &f["proof"].to_string(),
        &f["trust"].to_string(),
        &f["request"].to_string(),
        f["now_ms"].as_f64().unwrap(),
    )
}
fn receipt_check(f: &Value) -> Result<Value, String> {
    receipt::receipt(
        &f["receipt"].to_string(),
        &f["trust"].to_string(),
        f["now_ms"].as_f64().unwrap(),
    )
}
#[test]
fn real_signed_dynamic_root_authenticates_selected_presence_and_absence() {
    let f = fixture();
    let v = check(&f).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["names"]["missing"], Value::Null);
    assert_eq!(v["absentAccountIds"], json!(["999"]));
}
#[test]
fn canonical_current_root_makes_old_receipts_durable_without_extending_anchor_trust() {
    let f = fixture();
    assert_eq!(receipt_check(&f).unwrap()["executionVerified"], true);
    let mut stale = f.clone();
    stale["now_ms"] = json!(f["now_ms"].as_u64().unwrap() + 604800000);
    assert!(
        receipt_check(&stale)
            .unwrap_err()
            .contains("CHECKPOINT_REFRESH_REQUIRED")
    );
}
#[test]
fn gateway_mutations_missing_rows_state_time_and_forged_roots_fail_closed() {
    let original = fixture();
    for mutation in 0..12 {
        let mut f = original.clone();
        match mutation {
            0 => f["proof"]["entries"][0]["value_b64"] = json!(STANDARD.encode(b"{}")),
            1 => f["proof"]["entries"][0]["key_hex"] = json!(hex::encode(b"wrong")),
            2 => {
                f["proof"]["entries"].as_array_mut().unwrap().remove(0);
            }
            3 => f["request"]["names"] = json!(["unproved"]),
            4 => f["proof"]["height"] = json!("1"),
            5 => f["trust"]["network_id"] = json!("cd".repeat(32)),
            6 => {
                f["proof"]["light_block"]["signed_header"]["header"]["app_hash"] =
                    json!("00".repeat(32))
            }
            7 => f["now_ms"] = json!(original["now_ms"].as_u64().unwrap() + 60000),
            8 => f["now_ms"] = json!(original["now_ms"].as_u64().unwrap() - 30000),
            9 => f["trust"]["app_version"] = json!("3"),
            10 => f["proof"]["entries"]
                .as_array_mut()
                .unwrap()
                .push(original["proof"]["entries"][0].clone()),
            _ => {
                f["proof"]["entries"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|e| e["key_hex"] != hex::encode(b"name/missing"));
            }
        }
        assert!(check(&f).is_err(), "mutation {mutation}");
    }
}
#[test]
fn receipt_requires_fresh_canonical_both_header_hashes_and_execution_root() {
    let original = fixture();
    for mutation in 0..6 {
        let mut f = original.clone();
        match mutation {
            0 => f["receipt"]["tx"]["hash"] = json!("00".repeat(32)),
            1 => f["receipt"]["signed_header"]["header"]["data_hash"] = json!("00".repeat(32)),
            2 => {
                f["receipt"]["next_signed_header"]["header"]["last_results_hash"] =
                    json!("00".repeat(32))
            }
            3 => {
                f["receipt"]["anchor"]["entries"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|e| e["key_hex"] != hex::encode(history::KEY));
            }
            4 => f["receipt"]["tx"]["proof"]["proof"]["total"] = json!("0"),
            _ => {
                f["receipt"]["anchor"]["entries"][0]["value_b64"] = json!(STANDARD.encode(b"{}"));
            }
        }
        assert!(receipt_check(&f).is_err(), "receipt mutation {mutation}");
    }
}
/// The action fee is a setting of the network's genesis (`fee_micros`, left
/// out for the protocol-4 fee of 1000). The verifier assumes no fee: a state
/// that carries the setting verifies like any other, and the setting reaches
/// the wallet unchanged, which reads the fee from it.
#[test]
fn a_network_fee_setting_reaches_the_wallet_unchanged() {
    let plain = check(&fixture()).unwrap();
    assert_eq!(plain["verified"], true);
    assert!(plain["state"]["config"].get("fee_micros").is_none());
    for fee in ["1", "10", "999"] {
        let f = fixture_with(|meta| meta["config"]["fee_micros"] = json!(fee));
        let v = check(&f).unwrap();
        assert_eq!(v["verified"], true);
        assert_eq!(v["state"]["config"]["fee_micros"], json!(fee));
        assert_eq!(receipt_check(&f).unwrap()["executionVerified"], true);
    }
}
#[test]
fn export_fee_proof_fixture_when_requested() {
    if std::env::var("V4_EXPORT_FEE_FIXTURE").as_deref() == Ok("1") {
        let f = fixture_with(|meta| meta["config"]["fee_micros"] = json!("10"));
        std::fs::write("fixtures/proof-fee.json", serde_json::to_vec(&f).unwrap()).unwrap();
    }
}
#[test]
fn export_public_proof_fixture_when_requested() {
    if std::env::var("V4_REBUILD_PUBLIC_FIXTURES").as_deref() == Ok("1") {
        std::fs::create_dir_all("fixtures").unwrap();
        std::fs::write(
            "fixtures/proof.json",
            serde_json::to_vec_pretty(&fixture()).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn history_vectors_from_independent_javascript_verify_in_shared_pure_crate() {
    let vectors: Value = serde_json::from_str(include_str!("../../history/vectors.json")).unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let summary: history::Summary = serde_json::from_value(vector["summary"].clone()).unwrap();
        for proof in vector["proofs"].as_array().unwrap() {
            let proof: history::Proof = serde_json::from_value(proof.clone()).unwrap();
            assert!(proof.verify(&summary).is_ok());
            let mut altered = proof.clone();
            altered.leaf.time_micros += 1;
            assert!(altered.verify(&summary).is_err());
        }
    }
}
#[test]
fn old_raw_history_cannot_substitute_for_accumulator_membership() {
    let original = fixture();
    for kind in 0..5 {
        let mut f = original.clone();
        match kind {
            0 => f["receipt"]["anchor"]["history_proofs"] = json!({}),
            1 => f["receipt"]["anchor"]["history_proofs"]["1"]["leaf"]["height"] = json!("2"),
            2 => f["receipt"]["anchor"]["history_proofs"]["1"]["leaf"]["time_micros"] = json!("1"),
            3 => {
                f["receipt"]["anchor"]["history_proofs"]["1"]["siblings"] = json!(["00".repeat(32)])
            }
            _ => f["receipt"]["anchor"]["history_proofs"]["1"]["siblings"]
                .as_array_mut()
                .unwrap()
                .push(json!("00".repeat(32))),
        }
        assert!(receipt_check(&f).is_err());
    }
}

#[test]
fn retained_exit_clocks_remain_proved_after_recent_history_pruning() {
    let f = fixture();
    let checked = check(&f).unwrap();
    assert_eq!(
        checked["state"]["release_times"]["3"],
        json!(((T0 + 3) * 1_000_000).to_string())
    );
    assert_eq!(checked["state"]["release_times"]["6"], Value::Null);
    for height in [3u64, 6] {
        let mut bad = f.clone();
        bad["proof"]["entries"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["key_hex"] != hex::encode(id(b"pos/release_time/", height)));
        assert!(check(&bad).is_err());
    }
}

#[test]
fn history_empty_extra_path_peak_and_integer_boundaries_fail_closed() {
    let vectors: Value = serde_json::from_str(include_str!("../../history/vectors.json")).unwrap();
    let vector = &vectors["vectors"][0];
    let summary: history::Summary = serde_json::from_value(vector["summary"].clone()).unwrap();
    let proof: history::Proof = serde_json::from_value(vector["proofs"][0].clone()).unwrap();
    assert!(proof.verify(&summary).is_ok());
    for kind in 0..8 {
        let mut s = summary.clone();
        let mut p = proof.clone();
        match kind {
            0 => s.size = 0,
            1 => s.size = i64::MAX as u64 + 1,
            2 => s.peaks.push("00".repeat(32)),
            3 => p.siblings.push("00".repeat(32)),
            4 => p.leaf.height = 0,
            5 => p.leaf.height = 2,
            6 => s.last_time_micros = 0,
            _ => p.siblings = vec!["00".repeat(32); 64],
        }
        assert!(p.verify(&s).is_err(), "history boundary {kind}");
    }
    assert!(history::node_count(i64::MAX as u64).is_ok());
    assert!(history::node_count(u64::MAX).is_err());
    assert!(
        history::Summary::empty([0; 32], 0)
            .append(history::Leaf {
                height: 0,
                block_hash: "00".repeat(32),
                time_micros: 1
            })
            .is_err()
    );
    assert!(
        serde_json::from_str::<history::Leaf>(
            r#"{"height":"1","height":"2","block_hash":"00","time_micros":"1"}"#
        )
        .is_err()
    );
}

#[test]
fn paid_commit_queries_authenticate_device_binding_and_absence() {
    let f = fixture();
    let v = check(&f).unwrap();
    assert_eq!(v["state"]["name_commits"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["state"]["name_commits"][0]["public_key"],
        json!("cc".repeat(32))
    );
    assert_eq!(v["registrationKeys"]["cc".repeat(32)], Value::Null);
    for key in [
        [b"registration/commit/".as_slice(), &[0xcc; 32]].concat(),
        [b"registration/commit/".as_slice(), &[0xff; 32]].concat(),
    ] {
        let mut bad = f.clone();
        bad["proof"]["entries"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["key_hex"] != hex::encode(&key));
        assert!(check(&bad).is_err());
    }
}
