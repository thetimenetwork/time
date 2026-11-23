//! No text from a gateway, a node or a stored trust ends the verifier.
//!
//! Found by fuzzing on 22 November 2026: a commit signature that was not
//! base64 made the verifier panic. In WebAssembly a panic is a trap, and an
//! instance that has trapped about a hundred times fails on honest answers.
//! `untrusted.rs` says which texts the libraries cannot take; `parse` in
//! `lib.rs` refuses them before a library reads them. These tests put each
//! such text into every place of real answers.
use crate::{fixtures::*, light, receipt, untrusted, view};
use serde_json::{Value, json};
use std::{cell::Cell, panic, sync::Once};

/// Texts on which a reader of the `tendermint` crates panics.
const STOPPING: [&str; 8] = ["A========", "=", "==", "=A", "AAAA=A", "AAAA====", "9999-12-31T23:59:59-00:01", "9999-12-31 00:01:00.5-23:59"];

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}
/// What the call returns, or `None` if it panics. The panics that are
/// expected here are not printed.
fn outcome<T>(call: impl FnOnce() -> T + panic::UnwindSafe) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let before = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                before(info);
            }
        }));
    });
    QUIET.with(|quiet| quiet.set(true));
    let outcome = panic::catch_unwind(call);
    QUIET.with(|quiet| quiet.set(false));
    outcome.ok()
}
/// Whether the call panics.
fn panics<T>(call: impl FnOnce() -> T + panic::UnwindSafe) -> bool {
    outcome(call).is_none()
}

/// Every place of a JSON value that holds a text.
fn texts(value: &Value, here: Vec<String>, all: &mut Vec<Vec<String>>) {
    match value {
        Value::String(_) => all.push(here),
        Value::Object(fields) => {
            for (name, inner) in fields {
                texts(inner, [here.clone(), vec![name.clone()]].concat(), all);
            }
        }
        Value::Array(items) => {
            for (index, inner) in items.iter().enumerate() {
                texts(inner, [here.clone(), vec![index.to_string()]].concat(), all);
            }
        }
        _ => {}
    }
}
fn put(value: &mut Value, place: &[String], text: &str) {
    match place.split_first() {
        None => *value = json!(text),
        Some((step, rest)) => match value {
            Value::Array(items) => put(&mut items[step.parse::<usize>().unwrap()], rest, text),
            _ => put(&mut value[step.as_str()], rest, text),
        },
    }
}
/// Runs `verify` on the answer with a stopping text in each place that
/// holds a text: one of base64 and one date in every place, and all of them
/// in every twentieth place. No run may panic, and every run must end in a
/// refusal that names the text. Returns how many places there were.
fn every_place(label: &str, answer: &Value, verify: impl Fn(&Value) -> Result<Value, String> + panic::RefUnwindSafe) -> usize {
    assert!(verify(answer).is_ok(), "{label}: the answer as it is does not verify: {:?}", verify(answer).err());
    let mut places = Vec::new();
    texts(answer, Vec::new(), &mut places);
    let mut runs = 0;
    for (index, place) in places.iter().enumerate() {
        let chosen: &[&str] = if index % 20 == 0 { &STOPPING } else { &[STOPPING[index % 6], STOPPING[6 + index % 2]] };
        for text in chosen {
            let mut changed = answer.clone();
            put(&mut changed, place, text);
            let refused = outcome(|| verify(&changed)).unwrap_or_else(|| panic!("{label}: {text:?} at {place:?} ends the verifier")).expect_err("a refusal");
            assert!(refused.contains(untrusted::BASE64) || refused.contains(untrusted::DATE), "{label}: {text:?} at {place:?}: {refused}");
            runs += 1;
        }
    }
    assert!(runs >= 2 * places.len());
    places.len()
}
fn live(name: &str) -> Value {
    serde_json::from_str(match name {
        "view" => include_str!("../fixtures/live-view.json"),
        _ => include_str!("../fixtures/live-receipt.json"),
    })
    .unwrap()
}

#[test]
fn a_state_proof_with_such_a_text_anywhere_is_refused_without_a_panic() {
    let fixture = live("view");
    let now = fixture["now_ms"].as_f64().unwrap();
    let request = fixture["request"].to_string();
    let trust = fixture["trust"].to_string();
    let proof = fixture["proof"].to_string();
    let places = every_place("state proof", &fixture["proof"], |proof| view::view(&proof.to_string(), &trust, &request, now))
        + every_place("trust of a state proof", &fixture["trust"], |trust| view::view(&proof, &trust.to_string(), &request, now));
    assert!(places > 150, "{places} places");
    // The selection is the wallet's own text; it comes the same way.
    let selection = json!({ "names": ["A========"] }).to_string();
    assert!(!panics(|| view::view(&proof, &trust, &selection, now)));
    assert!(view::view(&proof, &trust, &selection, now).unwrap_err().contains(untrusted::BASE64));
}

#[test]
fn a_receipt_with_such_a_text_anywhere_is_refused_without_a_panic() {
    let fixture = live("receipt");
    let now = fixture["now_ms"].as_f64().unwrap();
    let trust = fixture["trust"].to_string();
    let places = every_place("receipt", &fixture["proof"], |proof| receipt::receipt(&proof.to_string(), &trust, now));
    assert!(places > 60, "{places} places");
}

#[test]
fn a_light_block_and_a_trust_with_such_a_text_anywhere_are_refused_without_a_panic() {
    let (block, trust) = bootstrap(&[(1, 10), (2, 10), (3, 10), (4, 10)]);
    let now_ms = (now() / 1000) as f64;
    let (block, trust) = (serde_json::to_value(block).unwrap(), serde_json::to_value(trust).unwrap());
    let trust_text = trust.to_string();
    let block_text = block.to_string();
    let places = every_place("light block", &block, |block| light::update_json(&block.to_string(), &trust_text, now_ms))
        + every_place("trust", &trust, |trust| light::update_json(&block_text, &trust.to_string(), now_ms));
    assert!(places > 60, "{places} places");
    // The trust alone, as the wallet checks it when it opens.
    let status = |trust: &Value| crate::parse::<light::Trust>(&trust.to_string()).and_then(|trust| light::trust_status(&trust, now()));
    assert!(every_place("stored trust", &trust, status) > 20);
}

/// What the check is for: without it, the types of the `tendermint` crates
/// panic on these texts. (If a later version of the libraries refuses them,
/// this test says so, and the check can be looked at again.)
#[test]
fn the_library_types_alone_still_panic_on_these_texts() {
    let (block, _) = bootstrap(&[(1, 10), (2, 10), (3, 10), (4, 10)]);
    let sound = serde_json::to_value(&block).unwrap();
    let read = |value: &Value| serde_json::from_str::<light::LightBlock>(&value.to_string()).is_ok();
    assert!(read(&sound));
    let mut signature = sound.clone();
    signature["signed_header"]["commit"]["signatures"][0]["signature"] = json!("A========");
    assert!(panics(|| read(&signature)), "the library now refuses a signature that is not base64");
    let mut time = sound.clone();
    time["signed_header"]["header"]["time"] = json!("9999-12-31T23:59:59-00:01");
    assert!(panics(|| read(&time)), "the library now refuses a date beyond its years");
    let mut key = sound.clone();
    key["validators"][0]["pub_key"]["value"] = json!("=");
    assert!(panics(|| serde_json::from_value::<tendermint::validator::Info>(key["validators"][0].clone())), "the library now refuses a public key that is not base64");
    // The same three through the verifier's own way in: refused, no panic.
    for changed in [&signature, &time, &key] {
        assert!(!panics(|| crate::parse::<light::LightBlock>(&changed.to_string())));
        assert!(crate::parse::<light::LightBlock>(&changed.to_string()).unwrap_err().starts_with("INVALID_JSON: "));
    }
    // A validator record that did not come through `parse`.
    assert!(!panics(|| light::parse_set(key["validators"].as_array().unwrap())));
    assert!(light::parse_set(key["validators"].as_array().unwrap()).unwrap_err().contains(untrusted::BASE64));
}

#[test]
fn honest_answers_and_plain_mistakes_are_judged_as_before() {
    // What verified before verifies; the fixtures of the other tests say the rest.
    let fixture = live("view");
    let verified = view::view(&fixture["proof"].to_string(), &fixture["trust"].to_string(), &fixture["request"].to_string(), fixture["now_ms"].as_f64().unwrap()).unwrap();
    assert_eq!(verified["verified"], true);
    // A text that is not JSON is told as that, in the reader's own words.
    assert_eq!(crate::parse::<Value>("{\"a\":").unwrap_err(), format!("INVALID_JSON: {}", serde_json::from_str::<Value>("{\"a\":").unwrap_err()));
    // A text the decoder merely cannot read is left to it: an error of the type, as before.
    let (block, _) = bootstrap(&[(1, 10), (2, 10), (3, 10), (4, 10)]);
    let mut odd = serde_json::to_value(&block).unwrap();
    odd["signed_header"]["commit"]["signatures"][0]["signature"] = json!("not base64!");
    assert_eq!(untrusted::refusal("not base64!"), None);
    let refused = crate::parse::<light::LightBlock>(&odd.to_string()).unwrap_err();
    assert!(refused.starts_with("INVALID_JSON: ") && !refused.contains(untrusted::BASE64), "{refused}");
    // A field name is no text a reader decodes.
    assert_eq!(crate::parse::<Value>(r#"{"A========":"x"}"#).unwrap(), json!({ "A========": "x" }));
}
