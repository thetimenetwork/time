//! Public fixtures captured from the actual seven-validator native rehearsal.
//! Capture clocks are fixed for deterministic replay; they are not fresh pins
//! for a new live client or independent-operator evidence.
use serde_json::{Value, json};
fn fixture(name: &str) -> Value {
    serde_json::from_str(match name {
        "view" => include_str!("../fixtures/live-view.json"),
        _ => include_str!("../fixtures/live-receipt.json"),
    })
    .unwrap()
}
fn view(f: &Value) -> Result<Value, String> {
    crate::view::view(
        &f["proof"].to_string(),
        &f["trust"].to_string(),
        &f["request"].to_string(),
        f["now_ms"].as_f64().unwrap(),
    )
}
fn receipt(f: &Value) -> Result<Value, String> {
    crate::receipt::receipt(
        &f["proof"].to_string(),
        &f["trust"].to_string(),
        f["now_ms"].as_f64().unwrap(),
    )
}
#[test]
fn captured_native_quorum_state_and_canonical_payment_verify() {
    let v = fixture("view");
    assert_eq!(view(&v).unwrap()["verified"], true);
    assert_eq!(
        v["proof"]["light_block"]["validators"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_eq!(
        receipt(&fixture("receipt")).unwrap()["executionVerified"],
        true
    );
}
#[test]
fn captured_native_quorum_rejects_provider_header_key_clock_and_receipt_mutations() {
    let original = fixture("view");
    for kind in 0..8 {
        let mut f = original.clone();
        match kind {
            0 => f["proof"]["entries"][0]["value_b64"] = json!("e30="),
            1 => f["proof"]["height"] = json!("1"),
            2 => f["proof"]["light_block"]["signed_header"]["commit"]["signatures"] = json!([]),
            3 => f["proof"]["light_block"]["next_validators"] = json!([]),
            4 => f["trust"]["network_id"] = json!("00".repeat(32)),
            5 => f["now_ms"] = json!(f["now_ms"].as_u64().unwrap() + 60_000),
            6 => f["trust"]["app_version"] = json!("3"),
            _ => f["request"]["public_keys"] = json!(["ab".repeat(32)]),
        }
        assert!(view(&f).is_err(), "live mutation {kind}");
    }
    let mut r = fixture("receipt");
    r["proof"]["anchor"]["history_proofs"] = json!({});
    assert!(receipt(&r).is_err());
}

#[test]
fn historical_reward_zero_state_is_not_accepted_as_reward_one_authority() {
    let old: Value =
        serde_json::from_str(include_str!("../fixtures/live-view.reward0.json")).unwrap();
    assert!(view(&old).unwrap_err().contains("reward version"));
    let old: Value =
        serde_json::from_str(include_str!("../fixtures/live-receipt.reward0.json")).unwrap();
    assert!(receipt(&old).unwrap_err().contains("reward version"));
}
