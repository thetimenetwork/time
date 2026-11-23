//! The fee rule: the forms of its genesis setting (from the second review).
mod common;
use common::*;
use serde_json::{Value, json};
use timecurrency_v5::engine::Meta;
use timecurrency_v5::genesis::Genesis;
use timecurrency_v5::store::Store;

fn with(value: Value) -> Result<Genesis, serde_json::Error> {
    let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
    genesis["fees_to_validators_ppm"] = value;
    serde_json::from_value::<Genesis>(genesis)
}

#[test]
fn only_one_form_of_every_share_is_read_and_no_form_of_zero() {
    for refused in [
        json!("0"),
        json!("00"),
        json!("+0"),
        json!("-0"),
        json!("0.0"),
        json!(""),
        json!(" "),
        json!(" 1"),
        json!("1 "),
        json!("+1"),
        json!("01"),
        json!("1.0"),
        json!("1e3"),
        json!("0x10"),
        json!("-1"),
        json!("18446744073709551616"),
        json!(0),
        json!(1),
        json!(1.5),
        json!(true),
        json!(null),
        json!(["1"]),
        json!({"ppm": "1"}),
    ] {
        assert!(with(refused.clone()).is_err(), "read {refused}");
    }
    for (text, share) in [("1", 1u64), ("999", 999), ("500000", 500_000), ("1000000", 1_000_000)] {
        let genesis = with(json!(text)).unwrap();
        assert_eq!(genesis.fees_to_validators_ppm, share);
        genesis.validate().unwrap();
        // One encoding, read back to the same value and the same bytes.
        let bytes = serde_json::to_vec(&genesis).unwrap();
        let again: Genesis = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&again).unwrap(), bytes);
        assert_ne!(genesis.network_id().unwrap(), network_id());
    }
    // Readable but out of range: refused by the rules, not by the reader.
    let above = with(json!("1000001")).unwrap();
    assert!(above.validate().is_err() && above.network_id().is_err());
    let huge = with(json!("18446744073709551615")).unwrap();
    assert!(huge.validate().is_err());
}

#[test]
fn the_field_cannot_be_written_twice_or_with_spaces_that_change_the_network() {
    let base = serde_json::to_string(&genesis_v5()).unwrap();
    let body = base.strip_suffix('}').unwrap();
    // Twice, with the same or with different values.
    for tail in [
        r#","fees_to_validators_ppm":"5","fees_to_validators_ppm":"5"}"#,
        r#","fees_to_validators_ppm":"5","fees_to_validators_ppm":"6"}"#,
    ] {
        assert!(serde_json::from_str::<Genesis>(&format!("{body}{tail}")).is_err());
    }
    // First instead of last, and with white space: the same network.
    let last: Genesis = serde_json::from_str(&format!(r#"{body},"fees_to_validators_ppm":"5"}}"#)).unwrap();
    let first: Genesis =
        serde_json::from_str(&format!(r#"{{ "fees_to_validators_ppm" : "5" ,{}}}"#, body.strip_prefix('{').unwrap())).unwrap();
    assert_eq!(first.network_id().unwrap(), last.network_id().unwrap());
    assert_eq!(serde_json::to_vec(&first).unwrap(), serde_json::to_vec(&last).unwrap());
    // Without the field: the bytes of the protocol-4 genesis, exactly.
    let off: Genesis = serde_json::from_str(&base).unwrap();
    assert_eq!(serde_json::to_string(&off).unwrap(), serde_json::to_string(&genesis_v4()).unwrap());
    assert_eq!(off.network_id().unwrap(), network_id());
}

#[test]
fn the_metadata_row_of_a_network_without_the_setting_has_no_trace_of_it() {
    let open = |ppm: u64| {
        let mut genesis = genesis_v5();
        genesis.fees_to_validators_ppm = ppm;
        let dir = tempfile::tempdir().unwrap();
        let mut engine = timecurrency_v5::engine::Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        let meta: Meta = engine.meta().unwrap().clone();
        (serde_json::to_string(&meta).unwrap(), engine.head().unwrap().unwrap().root, dir)
    };
    let (off, off_root, _a) = open(0);
    let (on, on_root, _b) = open(7);
    assert!(!off.contains("fees_to_validators"), "{off}");
    assert!(on.contains(r#""fees_to_validators_ppm":"7""#));
    assert_ne!(off_root, on_root);
    // A stored metadata row that names zero is not read back.
    let forged = off.replacen(r#""trusting_period_seconds":"604800""#, r#""trusting_period_seconds":"604800","fees_to_validators_ppm":"0""#, 1);
    assert_ne!(forged, off);
    assert!(serde_json::from_str::<Meta>(&forged).is_err());
}
