//! Evidence of double signing is text from anyone. No such text may end the
//! program that reads it: found by fuzzing on 22 November 2026, when a vote
//! whose signature was not base64 stopped the node (`src/untrusted.rs` says
//! what the libraries do; `AUDIT-2026-11.md`, "Found by fuzzing").
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{cell::Cell, panic, sync::Once};
use tendermint::{Hash, Signature, Time, Vote, account, block};
use time_pos::{DoubleSignEvidence, HistoricalMembership, Validator, untrusted, verify_double_sign};

const CHAIN: &str = "time-devnet-v4-test";

fn signing() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn public() -> String {
    hex::encode(signing().verifying_key().as_bytes())
}
fn vote(block_byte: u8) -> Vote {
    let key = tendermint::PublicKey::from_raw_ed25519(signing().verifying_key().as_bytes()).unwrap();
    let mut vote = Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: 10u64.try_into().unwrap(),
        round: 0u32.try_into().unwrap(),
        block_id: Some(block::Id {
            hash: Hash::Sha256([block_byte; 32]),
            part_set_header: block::parts::Header::new(1, Hash::Sha256([block_byte + 1; 32])).unwrap(),
        }),
        timestamp: Some(Time::from_unix_timestamp(100, 0).unwrap()),
        validator_address: account::Id::from(key),
        validator_index: 0u32.try_into().unwrap(),
        signature: None,
        extension: vec![],
        extension_signature: None,
    };
    let mut bytes = Vec::new();
    vote.to_signable_bytes(CHAIN.parse().unwrap(), &mut bytes).unwrap();
    vote.signature = Some(Signature::try_from(signing().sign(&bytes).to_bytes().to_vec()).unwrap());
    vote
}
fn history() -> HistoricalMembership {
    HistoricalMembership { height: 10, elapsed_micros: 100, validators: vec![Validator { owner: 100, consensus_key: public(), power: 100 }] }
}
/// Sound evidence, as the JSON a sender writes.
fn evidence() -> Value {
    serde_json::to_value(DoubleSignEvidence { first: vote(1), second: vote(3) }).unwrap()
}
fn read(value: &Value) -> Result<DoubleSignEvidence, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}
thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}
/// Whether the call panics. (A node does not catch a panic: its panic hook
/// ends the process.) The panics that are expected here are not printed.
fn call_panics<T>(call: impl FnOnce() -> T + panic::UnwindSafe) -> bool {
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
    let outcome = panic::catch_unwind(|| drop(call()));
    QUIET.with(|quiet| quiet.set(false));
    outcome.is_err()
}
/// Whether reading the evidence panics.
fn panics(value: &Value) -> bool {
    call_panics(|| read(value))
}

/// Texts the readers of the libraries cannot take: base64 with `=` signs
/// that are not padding (the first six), and the one kind of date that
/// leaves the years the date library knows.
const STOPPING: [&str; 8] = ["A========", "=", "==", "=A", "AAAA=A", "AAAA====", "9999-12-31T23:59:59-00:01", "9999-12-31 00:01:00.5-23:59"];

/// What the check is for: the vote type of the library, read alone as the
/// evidence type read it before, still panics on these texts. (If a later
/// version of the library refuses them, this test says so.)
#[test]
fn the_vote_type_alone_still_panics_on_these_texts() {
    let sound = evidence()["first"].clone();
    assert!(serde_json::from_value::<Vote>(sound.clone()).is_ok());
    for (field, text) in [("signature", "A========"), ("signature", "="), ("timestamp", "9999-12-31T23:59:59-00:01")] {
        let mut vote = sound.clone();
        vote[field] = json!(text);
        assert!(call_panics(|| serde_json::from_value::<Vote>(vote)), "the library now refuses {text:?} as a {field}");
    }
}

/// The wallet's JavaScript keeps the same two rules (`client-v4/
/// proof-verifier.mjs`), so that it can refuse such a text before the
/// compiled verifier reads it. `spec/untrusted-text-vectors.json` holds texts
/// with what the rules say of each; this test holds the file to the rules
/// here, and a test of the JavaScript holds the JavaScript to the file.
/// `TIME_WRITE_VECTORS=1` writes the file anew.
#[test]
fn the_vectors_for_other_languages_are_what_the_rules_say() {
    /// Every text of the alphabet up to a length.
    fn all(alphabet: &[&str], longest: usize) -> Vec<String> {
        let mut texts = vec![String::new()];
        let mut last = vec![String::new()];
        for _ in 0..longest {
            last = last.iter().flat_map(|text| alphabet.iter().map(move |letter| format!("{text}{letter}"))).collect();
            texts.extend(last.iter().cloned());
        }
        texts
    }
    let mut texts = all(&["A", "="], 6);
    texts.extend(all(&["A", "=", " "], 3).into_iter().filter(|text| text.contains(' ')));
    let signature = format!("{}==", "q".repeat(86));
    for text in ["A========", "AAAA====", "QUJD", "QUJDRA==", "QUJDRA=", "QUJDRA", "QUJD=QUJD===", "\u{e9}=", "=\u{e9}", "A\u{e9}==", "\u{e9}\u{e9}\u{e9}\u{e9}=A", "AAAA\u{a0}", "AAAA=\u{a0}", "AAAA=\u{2026}", "====\n", "=\t", "not base64!", "9999", "-", "{}"] {
        texts.push(text.into());
    }
    for ending in ["", "=", "==", "A", "=A", "A=", "====", "A===", "AA=="] {
        texts.push(format!("{signature}{ending}"));
        texts.push(format!("{}{ending}", &signature[..86]));
    }
    for date in ["9999-12-31", "9999-12-30", "9998-12-31", "2026-11-22", "0000-01-01"] {
        for time in ["00:00:00", "00:00:59", "00:01:00", "12:00:00", "23:59:59", "23:59:60", "24:00:00"] {
            for offset in ["Z", "-00:00", "-00:01", "+00:01", "-12:00", "-23:59", "+23:59", "-24:00", "-0001", "\u{2212}00:01"] {
                texts.push(format!("{date}T{time}{offset}"));
            }
        }
    }
    for text in ["9999-12-31 23:59:59.5-00:01", "9999-12-31t23:59:59.123456789-23:59", "9999-12-31T23:59:59-00:01 ", " 9999-12-31T23:59:59-00:01", "9999-12-31T23:59:59-00:01Z", "9999-12-31T23:59:5\u{e9}-00:01", "9999-12-31T23-59-59-00:01"] {
        texts.push(text.into());
    }
    let vectors: Vec<Value> = texts
        .iter()
        .map(|text| json!({ "text": text, "base64": untrusted::base64_stops_the_decoder(text.as_bytes()), "date": untrusted::date_stops_the_reader(text) }))
        .collect();
    let named = |field: &str| vectors.iter().filter(|vector| vector[field] == true).count();
    assert!(named("base64") > 40 && named("date") > 15 && vectors.len() > 400, "{} of base64, {} of dates, {} in all", named("base64"), named("date"), vectors.len());
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("spec").join("untrusted-text-vectors.json");
    let wanted = format!(
        "{}\n",
        serde_json::to_string_pretty(&json!({
            "note": "Texts from outside, and whether a library under the engine and the verifier panics on them: `base64` for the base64 decoder, `date` for the date reader. The rules are in pos/src/untrusted.rs (the same file as verifier-v4/src/untrusted.rs), which holds them against the libraries; pos/tests/untrusted_text.rs writes this file from them. client-v4/proof-verifier.mjs keeps the same rules in JavaScript and is tested against this file.",
            "vectors": vectors,
        }))
        .unwrap()
    );
    if std::env::var_os("TIME_WRITE_VECTORS").is_some() {
        std::fs::write(&file, &wanted).unwrap();
    }
    let kept = std::fs::read_to_string(&file).unwrap_or_default();
    assert!(kept == wanted, "spec/untrusted-text-vectors.json is not what the rules say: write it anew with TIME_WRITE_VECTORS=1");
}

#[test]
fn the_two_copies_of_the_rules_are_one_text() {
    // The verifier is built from its own folder and keeps its own copy.
    assert!(include_str!("../src/untrusted.rs") == include_str!("../../verifier-v4/src/untrusted.rs"), "pos/src/untrusted.rs and verifier-v4/src/untrusted.rs differ: they must be the same file");
}

#[test]
fn sound_evidence_is_read_as_before_and_proves_the_double_signing() {
    let value = evidence();
    let read_back = read(&value).unwrap();
    let (owner, _) = verify_double_sign(CHAIN, &read_back, &history(), 200, false).unwrap();
    assert_eq!(owner, 100);
    // The fields a vote has in JSON, so that the test below knows it has been to every place.
    let first = value["first"].as_object().unwrap();
    for field in ["type", "height", "round", "block_id", "timestamp", "validator_address", "validator_index", "signature", "extension", "extension_signature"] {
        assert!(first.contains_key(field), "a vote in JSON has no field {field}: {value}");
    }
    assert!(first["signature"].as_str().unwrap().ends_with("=="), "a signature of 64 bytes ends in two padding signs");
}

#[test]
fn a_signature_the_decoder_cannot_take_is_refused_and_does_not_end_the_program() {
    let texts: Vec<_> = STOPPING.iter().filter(|text| untrusted::base64_stops_the_decoder(text.as_bytes())).collect();
    assert_eq!(texts.len(), 6);
    for text in texts {
        for which in ["first", "second"] {
            let mut value = evidence();
            value[which]["signature"] = json!(text);
            assert!(!panics(&value), "evidence with the signature {text:?} in its {which} vote ends the program");
            let error = read(&value).expect_err("such evidence is refused");
            assert!(error.contains(untrusted::BASE64), "{text:?}: {error}");
        }
    }
    // The signature of consensus with one `=` more: the text that was found.
    let mut value = evidence();
    let longer = format!("{}=", value["first"]["signature"].as_str().unwrap());
    value["first"]["signature"] = json!(longer);
    assert!(!panics(&value));
    assert!(read(&value).unwrap_err().contains(untrusted::BASE64));
}

#[test]
fn a_date_the_reader_cannot_take_is_refused_and_does_not_end_the_program() {
    let texts: Vec<_> = STOPPING.iter().filter(|text| untrusted::date_stops_the_reader(text)).collect();
    assert_eq!(texts.len(), 2);
    for text in texts {
        for which in ["first", "second"] {
            let mut value = evidence();
            value[which]["timestamp"] = json!(text);
            assert!(!panics(&value), "evidence with the timestamp {text:?} in its {which} vote ends the program");
            let error = read(&value).expect_err("such evidence is refused");
            assert!(error.contains(untrusted::DATE), "{text:?}: {error}");
        }
    }
}

/// What was read before is read now. The decoder takes base64 without its
/// padding, and the date reader takes an offset: evidence written that way
/// was accepted, and a network may hold a block with it.
#[test]
fn what_the_readers_took_before_is_still_taken() {
    let mut value = evidence();
    for which in ["first", "second"] {
        let signature = value[which]["signature"].as_str().unwrap().to_string();
        value[which]["signature"] = json!(signature.trim_end_matches('='));
        // 100 seconds after 1970, written an hour east of UTC.
        assert_eq!(value[which]["timestamp"], json!("1970-01-01T00:01:40Z"));
        value[which]["timestamp"] = json!("1970-01-01T01:01:40+01:00");
    }
    let read_back = read(&value).unwrap();
    assert_eq!(verify_double_sign(CHAIN, &read_back, &history(), 200, false).unwrap().0, 100);
    // A date in the last year the library knows, in UTC and east of it.
    for date in ["9999-12-31T23:59:59Z", "9999-12-31T23:59:59.999999999+00:01", "9999-12-31T23:59:59-00:00"] {
        let mut value = evidence();
        value["first"]["timestamp"] = json!(date);
        assert!(read(&value).is_ok(), "{date}");
    }
    // The two fields and no other, in a map or as a list of two, as the type was read before.
    let value = evidence();
    assert!(read(&json!([value["first"], value["second"]])).is_ok());
    let mut more = value.clone();
    more["third"] = json!(1);
    assert!(read(&more).unwrap_err().contains("unknown field `third`"));
    let mut less = value.clone();
    less.as_object_mut().unwrap().remove("second");
    assert!(read(&less).unwrap_err().contains("missing field `second`"));
    // A field of a vote that no reader knows is passed over, whatever its text.
    let mut extra = value.clone();
    extra["first"]["note"] = json!("A========");
    assert!(read(&extra).is_ok());
}

/// Every place of a vote, with every such text in it: no place ends the
/// program. This is what shows that the check names every field it must.
#[test]
fn no_text_in_any_place_of_a_vote_ends_the_program() {
    fn places(value: &Value, here: Vec<String>, all: &mut Vec<Vec<String>>) {
        all.push(here.clone());
        match value {
            Value::Object(fields) => {
                for (name, inner) in fields {
                    places(inner, [here.clone(), vec![name.clone()]].concat(), all);
                }
            }
            Value::Array(items) => {
                for (index, inner) in items.iter().enumerate() {
                    places(inner, [here.clone(), vec![index.to_string()]].concat(), all);
                }
            }
            _ => {}
        }
    }
    fn put(value: &mut Value, place: &[String], text: &Value) {
        match place.split_first() {
            None => *value = text.clone(),
            Some((step, rest)) => match value {
                Value::Array(items) => put(&mut items[step.parse::<usize>().unwrap()], rest, text),
                _ => put(&mut value[step.as_str()], rest, text),
            },
        }
    }
    let mut sound = evidence();
    // The fields a sender may add or write otherwise: a vote extension, and the other name of the part header.
    sound["first"]["extension"] = json!([1, 2, 3]);
    sound["first"]["extension_signature"] = json!(vec![9; 64]);
    let parts = sound["second"]["block_id"]["parts"].take();
    assert!(parts.is_object(), "{sound}");
    sound["second"]["block_id"].as_object_mut().unwrap().remove("parts");
    sound["second"]["block_id"]["part_set_header"] = parts;
    assert!(read(&sound).is_ok(), "{:?}", read(&sound).err());
    let mut all = Vec::new();
    places(&sound, Vec::new(), &mut all);
    assert!(all.len() >= 30, "{} places", all.len());
    let others = [json!(""), json!("0"), json!("-1"), json!("18446744073709551616"), json!("zz"), json!("0001-01-01T00:00:00Z"), json!("0000-01-01T00:00:00+23:59"), json!("9999-12-31T23:59:60Z"), json!(null), json!(-1), json!(1e300), json!([]), json!({})];
    let (mut refused, mut read_anyway) = (0, 0);
    for place in &all {
        for text in STOPPING.iter().map(|text| json!(text)).chain(others.iter().cloned()) {
            let mut value = sound.clone();
            put(&mut value, place, &text);
            assert!(!panics(&value), "{text} at {place:?} ends the program");
            match read(&value) {
                Ok(_) => read_anyway += 1,
                Err(_) => refused += 1,
            }
        }
    }
    assert!(refused > 300 && read_anyway > 0, "{refused} refused, {read_anyway} read");
}
