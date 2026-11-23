//! A change of the protocol version on a running network, as this verifier
//! sees it (docs/design/upgrade-mechanism.md, sections 3.2, 3.5 and 8.1):
//!
//! 1. headers: the version is at least the network's first one and never
//!    goes down; there is no upper bound, so a checkpoint keeps advancing;
//! 2. views: the version of the state is the certifying header's, and one
//!    this build does not implement is refused with `UPGRADE_REQUIRED:`;
//! 3. the `upgrade/state` row is proven present or proven absent, and a proof
//!    without an entry for it is refused;
//! 4. receipts: a block of a version this build does not implement is not
//!    judged.
//!
//! The rows here are written by hand from section 3.2 of the design.
use crate::{
    fixtures::*,
    light::*,
    proof_tests::{fixture, fixture_built, fixture_with},
    receipt, view,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

const A: [(u8, u64); 4] = [(1, 10), (2, 10), (3, 10), (4, 10)];
/// Words that make the SDK ask the gateway again (`getVerifiedState`). A
/// refusal for a version must not be one of them: asking again cannot help.
const RETRIED: [&str; 3] = ["ROLLBACK", "CHECKPOINT_MISMATCH", "LIGHT_UPDATE_BUDGET"];

fn key() -> Vec<u8> {
    b"upgrade/state".to_vec()
}
fn view_check(f: &Value) -> Result<Value, String> {
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
/// The fixture's request, with the upgrade entry asked for.
fn asking(mut f: Value) -> Value {
    f["request"]["include_upgrade"] = json!(true);
    f
}
/// A fixture whose state holds `row` under `upgrade/state`, asked with the entry.
fn with_row(row: Value) -> Value {
    asking(fixture_built(|_| {}, vec![(key(), row)], Vec::new(), 4, 4))
}
/// A fixture whose proof shows that the state holds no `upgrade/state` row.
fn without_row() -> Value {
    asking(fixture_built(|_| {}, Vec::new(), vec![key()], 4, 4))
}
// The fixture's state is 1,209,898 seconds after genesis. The plan below was
// scheduled 298 seconds before that and starts 21 days after its scheduling.
const SPEC: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
fn support(owner: &str) -> Value {
    json!({"activate_elapsed_micros":"3024000000000","changed_elapsed_micros":"1209000000000","owner":owner,"spec":SPEC,"version":"5"})
}
fn withdrawn(owner: &str) -> Value {
    json!({"changed_elapsed_micros":"1209000000000","owner":owner})
}
fn plan() -> Value {
    json!({"activate_elapsed_micros":"3024000000000","scheduled_elapsed_micros":"1209600000000","spec":SPEC,"version":"5"})
}
fn scheduled() -> Value {
    json!({"plan": plan(), "signals": [support("3"), withdrawn("7"), support("12")]})
}
fn entry_of<'a>(f: &'a mut Value, key: &[u8]) -> &'a mut Value {
    let wanted = hex::encode(key);
    f["proof"]["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["key_hex"] == wanted)
        .expect("the fixture proves this key")
}
fn drop_entry(f: &mut Value, key: &[u8]) {
    let wanted = hex::encode(key);
    f["proof"]["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["key_hex"] != wanted);
}

// ---- 1. headers

#[test]
fn a_checkpoint_keeps_advancing_across_versions_this_build_does_not_implement() {
    let (first, mut pin) = bootstrap(&A);
    pin.checkpoint = Some(checkpoint_from(&update(first.clone(), &pin, now()).unwrap()));
    // The block after an activation carries the new version.
    let second = block_at(KNOWN_VERSION + 1, 2, &A, &A, Some(&first), T0 + 2);
    let accepted = update(second.clone(), &pin, now()).unwrap();
    assert_eq!(accepted["verified"], true);
    assert_eq!(accepted["checkpoint"]["height"], "2");
    pin.checkpoint = Some(checkpoint_from(&accepted));
    // A checkpoint of that version is a trust anchor like any other.
    assert_eq!(trust_status(&pin, now()).unwrap()["ready"], true);
    // Later versions too, adjacent or skipped: there is no upper bound.
    let third = block_at(KNOWN_VERSION + 1, 3, &A, &A, Some(&second), T0 + 3);
    let fourth = block_at(KNOWN_VERSION + 3, 4, &A, &A, Some(&third), T0 + 4);
    let fifth = block_at(u64::MAX, 5, &A, &A, Some(&fourth), T0 + 5);
    let skipped = update(fourth.clone(), &pin, now()).unwrap();
    assert_eq!(skipped["verified"], true);
    pin.checkpoint = Some(checkpoint_from(&skipped));
    let last = update(fifth, &pin, now()).unwrap();
    assert_eq!(last["checkpoint"]["height"], "5");
    // From a checkpoint of the first version straight to a later one.
    let mut old = bootstrap(&A).1;
    old.checkpoint = Some(checkpoint(first));
    assert_eq!(update(fourth, &old, now()).unwrap()["verified"], true);
}

#[test]
fn a_header_below_the_version_of_the_trusted_checkpoint_or_of_the_network_is_refused() {
    let (first, mut pin) = bootstrap(&A);
    pin.checkpoint = Some(checkpoint(first.clone()));
    let second = block_at(5, 2, &A, &A, Some(&first), T0 + 2);
    pin.checkpoint = Some(checkpoint_from(&update(second.clone(), &pin, now()).unwrap()));
    // The next block claims the version before the upgrade again.
    let lower = block(3, &A, &A, Some(&second), T0 + 3);
    let error = update(lower, &pin, now()).unwrap_err();
    assert!(error.starts_with("INVALID_LIGHT_BLOCK: "), "{error}");
    assert!(error.contains("lower than the trusted checkpoint"), "{error}");
    assert!(RETRIED.iter().all(|word| !error.contains(word)), "{error}");
    // The same two blocks further on.
    let third = block_at(5, 3, &A, &A, Some(&second), T0 + 3);
    let lower = block(4, &A, &A, Some(&third), T0 + 4);
    assert!(
        update(lower, &pin, now())
            .unwrap_err()
            .contains("lower than the trusted checkpoint")
    );
    let lower = block_at(4, 4, &A, &A, Some(&third), T0 + 4);
    assert!(update(lower, &pin, now()).is_err());
    // The same version and a higher one are accepted.
    assert_eq!(update(third.clone(), &pin, now()).unwrap()["verified"], true);
    let higher = block_at(6, 4, &A, &A, Some(&third), T0 + 4);
    assert_eq!(update(higher, &pin, now()).unwrap()["verified"], true);
    // Below the first version of the network: refused at the bootstrap, as
    // an update and as a stored checkpoint.
    let genesis = bootstrap(&A).1;
    for version in [0, 1, 3] {
        let error = update(block_at(version, 1, &A, &A, None, T0 + 1), &genesis, now()).unwrap_err();
        assert!(error.contains("application version"), "{error}");
        let mut at_first = genesis.clone();
        at_first.checkpoint = Some(checkpoint(first.clone()));
        let candidate = block_at(version, 2, &A, &A, Some(&first), T0 + 2);
        assert!(update(candidate.clone(), &at_first, now()).is_err());
        at_first.checkpoint = Some(checkpoint(candidate));
        assert!(trust_status(&at_first, now()).is_err());
    }
    assert_eq!(FIRST_VERSION, 4);
}

#[test]
fn a_checkpoint_stored_before_an_upgrade_still_loads_and_the_anchor_keeps_the_first_version() {
    let (first, mut pin) = bootstrap(&A);
    pin.checkpoint = Some(checkpoint(first.clone()));
    // What a wallet stored before the activation, read back as it stores it.
    let stored: Trust = serde_json::from_str(&serde_json::to_string(&pin).unwrap()).unwrap();
    assert_eq!(stored.app_version, "4");
    assert_eq!(trust_status(&stored, now()).unwrap()["height"], "1");
    // It advances to a block of the new version, and the result loads again.
    let second = block_at(5, 2, &A, &A, Some(&first), T0 + 2);
    let mut after = stored.clone();
    after.checkpoint = Some(checkpoint_from(&update(second, &stored, now()).unwrap()));
    let reloaded: Trust = serde_json::from_str(&serde_json::to_string(&after).unwrap()).unwrap();
    assert_eq!(trust_status(&reloaded, now()).unwrap()["height"], "2");
    // The anchor still names the first version, and only that one: a trust
    // manifest is never reissued for an upgrade.
    assert_eq!(reloaded.app_version, "4");
    assert!(policy(&reloaded).is_ok());
    let mut reissued = reloaded.clone();
    reissued.app_version = "5".into();
    assert!(policy(&reissued).unwrap_err().starts_with("INVALID_TRUST"));
    assert!(trust_status(&reissued, now()).is_err());
}

// ---- 2. views

#[test]
fn a_view_of_a_version_this_build_does_not_implement_asks_for_an_upgrade() {
    assert_eq!(KNOWN_VERSION, 4, "release 1 implements versions 4 to 4");
    // The state and its certifying header agree on a later version; and a
    // header of a later version over a state that still says 4. Either way
    // the certified header decides, before a row is read.
    for (meta, header) in [("5", 5u64), ("4", 5), ("6", 6), ("5", 9)] {
        let f = fixture_built(
            |m| m["protocol_version"] = json!(meta),
            Vec::new(),
            Vec::new(),
            header,
            4,
        );
        let error = view_check(&f).unwrap_err();
        assert_eq!(
            error,
            format!(
                "UPGRADE_REQUIRED: the network runs protocol version {header}; this software implements versions 4 to 4. Install a release that implements version {header}."
            )
        );
        assert!(RETRIED.iter().all(|word| !error.contains(word)), "{error}");
        // It stays the answer when that state is no longer fresh: the version
        // of a chain does not go down again.
        let mut late = f.clone();
        late["now_ms"] = json!(f["now_ms"].as_u64().unwrap() + 60_000);
        assert!(view_check(&late).unwrap_err().starts_with("UPGRADE_REQUIRED: "));
        // And with the upgrade entry asked for.
        assert!(view_check(&asking(f)).unwrap_err().starts_with("UPGRADE_REQUIRED: "));
    }
    // A gateway cannot produce that answer by its own word. A version
    // written into the header of a version-4 proof gives another header
    // hash than the checkpoint this client verified.
    let mut forged = fixture();
    forged["proof"]["light_block"]["signed_header"]["header"]["version"]["app"] = json!("5");
    let error = view_check(&forged).unwrap_err();
    assert!(error.starts_with("CHECKPOINT_MISMATCH"), "{error}");
    // Changed in the client's own checkpoint as well, the signatures no
    // longer cover the header.
    forged["trust"]["checkpoint"]["block"]["signed_header"]["header"]["version"]["app"] = json!("5");
    let error = view_check(&forged).unwrap_err();
    assert!(!error.contains("UPGRADE_REQUIRED"), "{error}");
    // Nor by the version field of the state alone (see the next test).
}

#[test]
fn the_version_of_a_state_is_the_version_of_its_certifying_header() {
    // Equal: verified, and the wallet reads the proven number.
    assert_eq!(view_check(&fixture()).unwrap()["state"]["protocol_version"], "4");
    // A state that names a later version, an earlier one, or none this
    // network ever had, under a header of version 4.
    for meta in ["5", "3", "0", "40", "18446744073709551615"] {
        let f = fixture_with(|m| m["protocol_version"] = json!(meta));
        assert_eq!(
            view_check(&f).unwrap_err(),
            "state/header version or height mismatch",
            "state version {meta}"
        );
    }
    // Not the one spelling of a number.
    for meta in [json!(4), json!("04"), json!(" 4"), json!("4.0"), Value::Null] {
        let f = fixture_with(|m| m["protocol_version"] = meta.clone());
        let error = view_check(&f).unwrap_err();
        assert!(error.starts_with("INVALID_DECIMAL"), "{meta}: {error}");
    }
    let f = fixture_with(|m| {
        m.as_object_mut().unwrap().remove("protocol_version");
    });
    assert!(view_check(&f).is_err());
}

// ---- 3. the upgrade entry

#[test]
fn the_key_and_the_stored_bytes_are_those_of_the_design() {
    assert_eq!(key().len(), 13);
    assert_eq!(hex::encode(key()), "757067726164652f7374617465");
    // Canonical JSON: keys sorted, no spaces, integers as decimal strings.
    assert_eq!(
        serde_json::to_string(&scheduled()).unwrap(),
        format!(
            "{{\"plan\":{{\"activate_elapsed_micros\":\"3024000000000\",\"scheduled_elapsed_micros\":\"1209600000000\",\"spec\":\"{SPEC}\",\"version\":\"5\"}},\"signals\":[{{\"activate_elapsed_micros\":\"3024000000000\",\"changed_elapsed_micros\":\"1209000000000\",\"owner\":\"3\",\"spec\":\"{SPEC}\",\"version\":\"5\"}},{{\"changed_elapsed_micros\":\"1209000000000\",\"owner\":\"7\"}},{{\"activate_elapsed_micros\":\"3024000000000\",\"changed_elapsed_micros\":\"1209000000000\",\"owner\":\"12\",\"spec\":\"{SPEC}\",\"version\":\"5\"}}]}}"
        )
    );
    // The fixture stores exactly these bytes under the key.
    let mut f = with_row(scheduled());
    let stored = STANDARD
        .decode(entry_of(&mut f, &key())["value_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(stored, serde_json::to_vec(&scheduled()).unwrap());
}

#[test]
fn the_upgrade_entry_is_proven_present_or_proven_absent_and_never_assumed() {
    // Proven absent: no plan and no signal. The answer says so explicitly.
    let absent = without_row();
    let checked = view_check(&absent).unwrap();
    assert!(checked["state"].as_object().unwrap().contains_key("upgrade"));
    assert_eq!(checked["state"]["upgrade"], Value::Null);
    // Proven present: the row as stored.
    let present = with_row(scheduled());
    assert_eq!(view_check(&present).unwrap()["state"]["upgrade"], scheduled());
    // Not asked for: the state says nothing about upgrades, whatever the
    // proof holds. Nobody can take that for "no plan".
    for base in [&absent, &present] {
        for flag in [None, Some(false)] {
            let mut quiet = base.clone();
            match flag {
                None => {
                    quiet["request"].as_object_mut().unwrap().remove("include_upgrade");
                }
                Some(value) => quiet["request"]["include_upgrade"] = json!(value),
            }
            let checked = view_check(&quiet).unwrap();
            assert!(!checked["state"].as_object().unwrap().contains_key("upgrade"));
        }
    }
    // Asked for, and the proof has no entry for the key: refused, whether
    // the row exists or not. A gateway cannot hide a plan by leaving it out.
    for base in [&absent, &present] {
        let mut withheld = base.clone();
        drop_entry(&mut withheld, &key());
        let error = view_check(&withheld).unwrap_err();
        assert_eq!(
            error,
            "missing requested proof for 757067726164652f7374617465"
        );
    }
    assert!(view_check(&asking(fixture())).is_err());
    // Nor by answering "absent" for a row that exists, by serving another
    // value, or by serving the proof of absence of another state.
    let mut lied = present.clone();
    entry_of(&mut lied, &key())["value_b64"] = Value::Null;
    assert!(view_check(&lied).unwrap_err().contains("invalid key/value proof"));
    let mut swapped = present.clone();
    entry_of(&mut swapped, &key())["value_b64"] =
        json!(STANDARD.encode(serde_json::to_vec(&json!({"signals":[withdrawn("7")]})).unwrap()));
    assert!(view_check(&swapped).unwrap_err().contains("invalid key/value proof"));
    let mut transplanted = present.clone();
    let foreign = entry_of(&mut absent.clone(), &key()).clone();
    *entry_of(&mut transplanted, &key()) = foreign;
    assert!(view_check(&transplanted).unwrap_err().contains("invalid key/value proof"));
    // The flag is a boolean and nothing else.
    for flag in [json!("true"), json!(1), Value::Null] {
        let mut odd = present.clone();
        odd["request"]["include_upgrade"] = flag;
        assert!(view_check(&odd).unwrap_err().starts_with("INVALID_JSON"));
    }
}

#[test]
fn every_form_the_row_can_have_reaches_the_wallet_as_stored() {
    let largest = json!({"plan": plan(), "signals": (0..256u64).map(|n| if n % 5 == 0 { withdrawn(&(n * 1000).to_string()) } else { support(&(n * 1000).to_string()) }).collect::<Vec<_>>()});
    for row in [
        // Signals only: nothing is scheduled.
        json!({"signals": [support("3")]}),
        json!({"signals": [withdrawn("0")]}),
        json!({"signals": [support("3"), withdrawn("7"), support("12")]}),
        // A scheduled plan, with and without entries.
        scheduled(),
        json!({"plan": plan(), "signals": []}),
        // Owners are compared as numbers, not as text.
        json!({"signals": [support("9"), support("10"), support("18446744073709551614")]}),
        // One entry per candidate, at most 256.
        largest,
    ] {
        assert!(serde_json::to_vec(&row).unwrap().len() < 64 * 1024);
        assert_eq!(view_check(&with_row(row.clone())).unwrap()["state"]["upgrade"], row);
    }
}

#[test]
fn a_row_in_any_other_form_is_refused() {
    let edit = |change: &dyn Fn(&mut Value)| {
        let mut row = scheduled();
        change(&mut row);
        row
    };
    let too_many = json!({"signals": (0..257u64).map(|n| withdrawn(&n.to_string())).collect::<Vec<_>>()});
    let cases: Vec<(&str, Value)> = vec![
        ("not an object", json!([])),
        ("a string", json!("none")),
        ("no fields", json!({})),
        ("an empty row, which the engine removes", json!({"signals": []})),
        ("signals missing", json!({"plan": plan()})),
        ("signals not a list", json!({"signals": {}})),
        ("an unknown field", edit(&|r| r["height"] = json!("1"))),
        ("plan null", edit(&|r| r["plan"] = Value::Null)),
        ("plan not an object", edit(&|r| r["plan"] = json!("5"))),
        ("plan lacks a field", edit(&|r| { r["plan"].as_object_mut().unwrap().remove("spec"); })),
        ("plan has another field", edit(&|r| r["plan"]["scheduled_height"] = json!("9"))),
        ("plan for the version in force", edit(&|r| r["plan"]["version"] = json!("4"))),
        ("plan two versions ahead", edit(&|r| r["plan"]["version"] = json!("6"))),
        ("plan version as a number", edit(&|r| r["plan"]["version"] = json!(5))),
        ("plan version with a leading zero", edit(&|r| r["plan"]["version"] = json!("05"))),
        ("plan time as a number", edit(&|r| r["plan"]["activate_elapsed_micros"] = json!(3024000000000u64))),
        ("plan time out of range", edit(&|r| r["plan"]["scheduled_elapsed_micros"] = json!("18446744073709551616"))),
        ("spec in upper case", edit(&|r| r["plan"]["spec"] = json!(SPEC.to_uppercase()))),
        ("spec too short", edit(&|r| r["plan"]["spec"] = json!(&SPEC[1..]))),
        ("spec not hexadecimal", edit(&|r| r["plan"]["spec"] = json!("g".repeat(64)))),
        ("an entry that is not an object", edit(&|r| r["signals"][0] = json!("3"))),
        ("an entry without owner", edit(&|r| { r["signals"][1].as_object_mut().unwrap().remove("owner"); })),
        ("an entry with three fields", edit(&|r| r["signals"][1]["version"] = json!("5"))),
        ("a support entry without spec", edit(&|r| { r["signals"][0].as_object_mut().unwrap().remove("spec"); })),
        ("a support entry with another field", edit(&|r| r["signals"][0]["power"] = json!("1"))),
        ("an entry spec in upper case", edit(&|r| r["signals"][0]["spec"] = json!(SPEC.to_uppercase()))),
        ("an entry version as a number", edit(&|r| r["signals"][0]["version"] = json!(5))),
        ("an entry time as a number", edit(&|r| r["signals"][1]["changed_elapsed_micros"] = json!(1))),
        ("owner as a number", edit(&|r| r["signals"][0]["owner"] = json!(3))),
        ("owner with a leading zero", edit(&|r| r["signals"][0]["owner"] = json!("03"))),
        ("the id that is not an account", edit(&|r| r["signals"][2]["owner"] = json!("18446744073709551615"))),
        ("owners not ascending", edit(&|r| r["signals"][1]["owner"] = json!("13"))),
        ("owners sorted as text", json!({"signals": [support("10"), support("9")]})),
        ("an owner twice", edit(&|r| r["signals"][1]["owner"] = json!("3"))),
        ("more entries than candidates", too_many),
    ];
    for (what, row) in cases {
        // The validators of the fixture certified this row: only the check
        // of its form stands between it and the wallet.
        let error = view_check(&with_row(row)).unwrap_err();
        assert!(
            !error.contains("proof") && !error.contains("UPGRADE_REQUIRED"),
            "{what}: {error}"
        );
        assert!(
            error.contains("upgrade") || error.contains("plan") || error.contains("signal") || error.starts_with("INVALID_DECIMAL"),
            "{what}: {error}"
        );
    }
    // Not asked for, such a row is not looked at.
    let mut quiet = with_row(json!({"signals": []}));
    quiet["request"]["include_upgrade"] = json!(false);
    assert_eq!(view_check(&quiet).unwrap()["verified"], true);
}

// ---- 4. receipts

#[test]
fn a_receipt_of_a_version_this_build_does_not_implement_asks_for_an_upgrade() {
    assert_eq!(receipt_check(&fixture()).unwrap()["executionVerified"], true);
    // The fresh state the receipt is anchored in is of a later version.
    let f = fixture_built(|m| m["protocol_version"] = json!("5"), Vec::new(), Vec::new(), 5, 4);
    let error = receipt_check(&f).unwrap_err();
    assert!(error.starts_with("UPGRADE_REQUIRED: the network runs protocol version 5; "), "{error}");
    // The blocks of the receipt themselves are, and they are part of the
    // chain: both headers are in the authenticated history.
    let f = fixture_built(|_| {}, Vec::new(), Vec::new(), 4, 5);
    let error = receipt_check(&f).unwrap_err();
    assert!(error.starts_with("UPGRADE_REQUIRED: the network runs protocol version 5; "), "{error}");
    // Below the network's first version: refused as before.
    let f = fixture_built(|_| {}, Vec::new(), Vec::new(), 4, 3);
    assert_eq!(receipt_check(&f).unwrap_err(), "historical header chain/version/time mismatch");
    // A gateway cannot produce the answer by writing a version into a
    // header: that header is then not the one in the authenticated history.
    for header in ["signed_header", "next_signed_header"] {
        let mut forged = fixture();
        forged["receipt"][header]["header"]["version"]["app"] = json!("5");
        let error = receipt_check(&forged).unwrap_err();
        assert!(error.contains("not in freshly authenticated canonical history"), "{error}");
        forged["receipt"][header]["header"]["version"]["app"] = json!("3");
        assert_eq!(receipt_check(&forged).unwrap_err(), "historical header chain/version/time mismatch");
    }
}

/// Writes what the JavaScript tests of the SDK, the light client and the
/// servers read: `fixtures/upgrade.json`.
#[test]
fn export_upgrade_fixture_when_requested() {
    if std::env::var("V4_EXPORT_UPGRADE_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    let view_of = |f: Value| json!({"trust": f["trust"], "now_ms": f["now_ms"], "request": f["request"], "proof": f["proof"]});
    let later = fixture_built(|m| m["protocol_version"] = json!("5"), Vec::new(), vec![key()], 5, 4);
    let (first, pin) = bootstrap(&A);
    let second = block(2, &A, &A, Some(&first), T0 + 2);
    let third = block_at(5, 3, &A, &A, Some(&second), T0 + 3);
    let fourth = block_at(5, 4, &A, &A, Some(&third), T0 + 4);
    let fifth = block_at(6, 5, &A, &A, Some(&fourth), T0 + 5);
    let lower = block(5, &A, &A, Some(&fourth), T0 + 5);
    let value = json!({
        "note": "Hand-made from docs/design/upgrade-mechanism.md section 3.2 by verifier-v4/src/upgrade_tests.rs (V4_EXPORT_UPGRADE_FIXTURE=1). Test keys only.",
        "key_hex": hex::encode(key()),
        "rows": {"signals": json!({"signals": [support("3"), withdrawn("7")]}), "plan": scheduled()},
        "views": {
            "absent": view_of(without_row()),
            "signals": view_of(with_row(json!({"signals": [support("3"), withdrawn("7")]}))),
            "plan": view_of(with_row(scheduled())),
            "malformed": view_of(with_row(json!({"plan": Value::Null, "signals": [support("3")]}))),
            "version5": view_of(asking(later.clone())),
            "mismatch": view_of(asking(fixture_built(|m| m["protocol_version"] = json!("5"), Vec::new(), vec![key()], 4, 4))),
        },
        "receipt_version5": {"trust": later["trust"], "now_ms": later["now_ms"], "receipt": later["receipt"]},
        "light": {"trust": pin, "now_ms": (T0 + 100) * 1000, "blocks": [first, second, third, fourth, fifth], "lower": lower},
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::write(path.join("upgrade.json"), serde_json::to_vec(&value).unwrap()).unwrap();
}

// ---- 5. the engine's own rows
//
// `fixtures/upgrade-state.fixture.json` is written by the engine
// (v5/tests/upgrade_node.rs): for five heights of a laboratory chain that
// schedules and activates version 5, the answer of `/v4/state` to
// `{"include_upgrade":true}` and its root, which is the application hash of
// that height. The engine tests run without CometBFT, so the file holds no
// signed header. Here each answer is put under a header that carries exactly
// that application hash, the version the engine names for the next block and
// the chain's own times, signed by test validators: everything the verifier
// checks below the signatures is the engine's.
const ENGINE: &str = include_str!("../fixtures/upgrade-state.fixture.json");

fn engine_cases() -> Vec<(String, Value)> {
    use tendermint::{Hash, Time, block};
    let fixture: Value = serde_json::from_str(ENGINE).unwrap();
    assert_eq!(fixture["state_key_hex"], hex::encode(key()));
    let genesis: u64 = fixture["genesis_time_micros"].as_str().unwrap().parse().unwrap();
    let validators = roster(&A);
    let mut cases = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let height: u64 = case["height"].as_str().unwrap().parse().unwrap();
        let elapsed: u64 = case["elapsed_micros"].as_str().unwrap().parse().unwrap();
        let version: u64 = case["next_block_version"].as_str().unwrap().parse().unwrap();
        let root = hex::decode(case["response"]["root"].as_str().unwrap()).unwrap();
        assert_eq!(case["response"]["root"], case["app_hash"]);
        // The header of the next block, one second after the state it certifies.
        let micros = genesis + elapsed + 1_000_000;
        let header = block::Header {
            version: block::header::Version { block: 11, app: version },
            chain_id: fixture["chain_id"].as_str().unwrap().parse().unwrap(),
            height: (height + 1).try_into().unwrap(),
            time: Time::from_unix_timestamp((micros / 1_000_000) as i64, ((micros % 1_000_000) * 1000) as u32).unwrap(),
            last_block_id: Some(block::Id {
                hash: Hash::Sha256([7; 32]),
                part_set_header: block::parts::Header::new(1, Hash::Sha256([9; 32])).unwrap(),
            }),
            last_commit_hash: None,
            data_hash: None,
            validators_hash: validators.hash(),
            next_validators_hash: validators.hash(),
            consensus_hash: Hash::Sha256([4; 32]),
            app_hash: tendermint::AppHash::try_from(root).unwrap(),
            last_results_hash: None,
            evidence_hash: None,
            proposer_address: validators.validators()[0].address,
        };
        let certified = sign_header(header, &A, &A);
        let pin = Trust {
            chain_id: fixture["chain_id"].as_str().unwrap().into(),
            network_id: fixture["network_id"].as_str().unwrap().into(),
            app_version: "4".into(),
            genesis_time_micros: genesis.to_string(),
            trusting_period_seconds: "604800".into(),
            unbonding_period_seconds: "1209600".into(),
            initial_validators: values(&validators),
            checkpoint: Some(checkpoint(certified.clone())),
        };
        let proof = json!({"height": case["response"]["height"], "entries": case["response"]["entries"], "history_proofs": case["response"]["history_proofs"], "light_block": certified});
        cases.push((
            case["name"].as_str().unwrap().to_string(),
            json!({"trust": pin, "now_ms": micros / 1000 + 1000, "request": case["request"], "proof": proof, "upgrade": case["upgrade_state"], "state_version": case["protocol_version"], "what": case["what"]}),
        ));
    }
    cases
}

#[test]
fn the_rows_the_engine_writes_verify_and_read_as_the_engine_stored_them() {
    let cases = engine_cases();
    assert_eq!(
        cases.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(),
        ["absent", "entries_only", "scheduled", "activated", "after_activation"]
    );
    for (name, f) in &cases {
        assert_eq!(f["request"], json!({"include_upgrade": true}), "{name}");
        if f["state_version"] != "4" {
            // The activating block writes version 5 and the next header
            // carries it: from there on this build asks for an upgrade.
            let error = view_check(f).unwrap_err();
            assert!(error.starts_with("UPGRADE_REQUIRED: the network runs protocol version 5; "), "{name}: {error}");
            continue;
        }
        let checked = view_check(f).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(checked["verified"], true, "{name}");
        assert_eq!(checked["state"]["protocol_version"], "4", "{name}");
        assert!(checked["state"].as_object().unwrap().contains_key("upgrade"), "{name}");
        // The row reaches the wallet exactly as the engine stored it.
        assert_eq!(checked["state"]["upgrade"], f["upgrade"], "{name}");
        // And the bytes under the key are the canonical JSON of that row.
        let mut copy = f.clone();
        match entry_of(&mut copy, &key())["value_b64"].as_str() {
            Some(stored) => assert_eq!(STANDARD.decode(stored).unwrap(), serde_json::to_vec(&f["upgrade"]).unwrap(), "{name}"),
            None => assert_eq!(f["upgrade"], Value::Null, "{name}"),
        }
        // Without the entry the engine's own proof is refused.
        drop_entry(&mut copy, &key());
        assert_eq!(view_check(&copy).unwrap_err(), "missing requested proof for 757067726164652f7374617465", "{name}");
        // "Absent" for a row that exists does not verify.
        if !f["upgrade"].is_null() {
            let mut lied = f.clone();
            entry_of(&mut lied, &key())["value_b64"] = Value::Null;
            assert!(view_check(&lied).unwrap_err().contains("invalid key/value proof"), "{name}");
        }
    }
    let row = |name: &str| cases.iter().find(|(n, _)| n == name).unwrap().1["upgrade"].clone();
    assert_eq!(row("absent"), Value::Null);
    assert!(row("entries_only").get("plan").is_none());
    assert_eq!(row("entries_only")["signals"].as_array().unwrap().len(), 3);
    assert_eq!(row("scheduled")["plan"]["version"], "5");
    assert_eq!(row("scheduled")["signals"].as_array().unwrap().len(), 4);
}

/// Writes the engine's cases with their test headers for the JavaScript
/// tests: `fixtures/upgrade-engine.json`.
#[test]
fn export_engine_upgrade_fixture_when_requested() {
    if std::env::var("V4_EXPORT_UPGRADE_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    use sha2::{Digest, Sha256};
    let cases: serde_json::Map<String, Value> = engine_cases().into_iter().collect();
    let value = json!({
        "note": "The engine's proven upgrade/state rows (verifier-v4/fixtures/upgrade-state.fixture.json, written by v5/tests/upgrade_node.rs), each under a header signed by test validators that carries the engine's application hash. Written by verifier-v4/src/upgrade_tests.rs (V4_EXPORT_UPGRADE_FIXTURE=1).",
        "source_sha256": hex::encode(Sha256::digest(ENGINE.as_bytes())),
        "cases": cases,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::write(path.join("upgrade-engine.json"), serde_json::to_vec(&value).unwrap()).unwrap();
}
