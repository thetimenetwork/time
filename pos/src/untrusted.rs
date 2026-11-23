//! Texts from outside that the libraries beneath this crate cannot take.
//!
//! JSON from people nobody trusts is read here with the types of the
//! `tendermint` crates: votes in evidence of double signing, light blocks,
//! receipts, validator records. Two of the readers under those types do not
//! refuse every text they cannot read. On some they panic, which ends the
//! program: a node stops, a wallet's verifier is lost.
//!
//! 1. **Base64** (`subtle-encoding` 0.5.1, used by `tendermint` and
//!    `tendermint-proto` 0.40.4 for signatures, public keys and other bytes).
//!    The decoder sizes its result from the length of the text without the
//!    `=` signs at its end: three bytes for every four characters. Then it
//!    writes three bytes for every four characters but the last one to four,
//!    whatever they are, and for the last ones one byte fewer than there are
//!    characters before the first `=`. A text with more `=` at its end than
//!    base64 has (`A========`) gets a result too small for what is written;
//!    a text whose last characters begin with `=` (`=`, `AAAA=A`) makes it
//!    write "minus one" bytes. Both are a panic.
//! 2. **Dates** (`tendermint-proto` 0.40.4 with `time` 0.3.55). A date is
//!    read with its offset from UTC and then converted to UTC with a call
//!    that panics when the result leaves the years the library knows. That
//!    is one case: the last day of the year 9999 with an offset that moves
//!    it into the year 10000 (`9999-12-31T23:59:59-00:01`).
//!
//! The two functions below say for a text exactly whether its reader would
//! panic: no more and no less. A text on which a reader only returns an
//! error is left to that reader, so everything that was accepted before is
//! accepted now and nothing else is.
//!
//! This file exists twice, byte for byte the same: `pos/src/untrusted.rs`
//! and `verifier-v4/src/untrusted.rs`. The verifier is built for WebAssembly
//! from its own folder and cannot depend on `pos`. A test of `pos`
//! (`tests/untrusted_text.rs`) compares the two files. The tests at the end
//! of this file hold each rule against the library itself, in both crates.
use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

/// What a refusal says of a text the base64 decoder would panic on.
pub const BASE64: &str = "a text is not base64: its `=` signs are not where base64 has them";
/// What a refusal says of a date the date reader would panic on.
pub const DATE: &str = "a date is beyond the year 9999 when it is converted to UTC";

/// Whether `subtle_encoding::base64::decode` panics on this text.
pub fn base64_stops_the_decoder(text: &[u8]) -> bool {
    let length = text.len();
    // An empty text is an empty result; one that ends in white space is
    // refused before anything is written.
    if length == 0 || char::from(text[length - 1]).is_whitespace() {
        return false;
    }
    // The `=` signs at the end (the first character is never counted as
    // one), and the room they leave.
    let mut padding = 0;
    while padding < length - 1 && text[length - 1 - padding] == b'=' {
        padding += 1;
    }
    let room = (length - padding) * 3 / 4;
    // Every four characters but the last one to four: three bytes each.
    let whole = (length - 1) / 4;
    if 3 * whole > room {
        return true;
    }
    // The last one to four characters, up to the first `=`: one byte fewer
    // than their number, and none of them is "minus one".
    let filled = text[4 * whole..].iter().take_while(|byte| **byte != b'=').count();
    filled == 0 || 3 * whole + filled - 1 > room
}

/// Whether the date reader of `tendermint-proto` panics on this text.
///
/// It reads `YYYY-MM-DD`, any one byte, `hh:mm:ss`, an optional fraction and
/// then `Z` or an offset `+hh:mm` or `-hh:mm` (hours to 23, minutes to 59;
/// a 60th second counts as the 59th). Only the last day of 9999 can leave
/// its years, and only with an offset behind UTC that carries the time past
/// midnight. A text the reader does not take in the first place may be named
/// here too: it is refused either way.
pub fn date_stops_the_reader(text: &str) -> bool {
    let text = text.as_bytes();
    let two = |at: usize| match (text.get(at), text.get(at + 1)) {
        (Some(tens), Some(ones)) if tens.is_ascii_digit() && ones.is_ascii_digit() => {
            Some(u32::from(tens - b'0') * 10 + u32::from(ones - b'0'))
        }
        _ => None,
    };
    if text.len() < 25 || &text[..10] != b"9999-12-31" || text[13] != b':' || text[16] != b':' {
        return false;
    }
    let offset = text.len() - 6;
    if text[offset] != b'-' || text[offset + 3] != b':' {
        return false;
    }
    match (two(11), two(14), two(17), two(offset + 1), two(offset + 4)) {
        (Some(hour), Some(minute), Some(second), Some(hours_behind), Some(minutes_behind)) => {
            hour * 3600 + minute * 60 + second.min(59) + hours_behind * 3600 + minutes_behind * 60 >= 86_400
        }
        _ => false,
    }
}

/// Why this text must not reach a reader of the `tendermint` crates, whichever
/// of the two it would reach; `None` if it may.
pub fn refusal(text: &str) -> Option<&'static str> {
    if base64_stops_the_decoder(text.as_bytes()) {
        Some(BASE64)
    } else if date_stops_the_reader(text) {
        Some(DATE)
    } else {
        None
    }
}

/// The first reason to refuse among all the texts of a JSON value (field
/// names are not read by any reader and are not looked at).
pub fn value(value: &Value) -> Result<(), &'static str> {
    match value {
        Value::String(text) => refusal(text).map_or(Ok(()), Err),
        Value::Array(items) => items.iter().try_for_each(self::value),
        Value::Object(fields) => fields.values().try_for_each(self::value),
        _ => Ok(()),
    }
}

/// Reads any JSON text without keeping it, and fails with a reason at the
/// first text in it (not a field name) that `refusal` names:
/// `serde_json::from_str::<Scan>(text)`. Such a failure is an error "of the
/// data" (`serde_json::Error::is_data`); a text that is not JSON fails as it
/// does for any reader, with an error of its syntax.
pub struct Scan;

impl<'de> Deserialize<'de> for Scan {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Scan)
    }
}

impl<'de> Visitor<'de> for Scan {
    type Value = Scan;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any JSON")
    }
    fn visit_str<E: Error>(self, text: &str) -> Result<Scan, E> {
        refusal(text).map_or(Ok(Scan), |reason| Err(E::custom(reason)))
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<Scan, E> {
        Ok(Scan)
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<Scan, E> {
        Ok(Scan)
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<Scan, E> {
        Ok(Scan)
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<Scan, E> {
        Ok(Scan)
    }
    fn visit_unit<E: Error>(self) -> Result<Scan, E> {
        Ok(Scan)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Scan, A::Error> {
        while items.next_element::<Scan>()?.is_some() {}
        Ok(Scan)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Scan, A::Error> {
        while fields.next_key::<IgnoredAny>()?.is_some() {
            fields.next_value::<Scan>()?;
        }
        Ok(Scan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{cell::Cell, panic, sync::Once};

    thread_local! {
        static QUIET: Cell<bool> = const { Cell::new(false) };
    }

    /// What a panic said, or `None` if the reader returned. The panics that
    /// are expected here are not printed.
    fn panic_of(read: impl FnOnce() + panic::UnwindSafe) -> Option<String> {
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
        let outcome = panic::catch_unwind(read);
        QUIET.with(|quiet| quiet.set(false));
        outcome.err().map(|payload| {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
                .unwrap_or_default()
        })
    }

    /// The library's base64 decoder, reached as an outsider reaches it:
    /// through a public key in JSON. Any text that decodes to something that
    /// is no key is an error; only the decoder can panic.
    fn decoder_panics(text: &str) -> bool {
        let key = json!({ "type": "tendermint/PubKeyEd25519", "value": text });
        match panic_of(move || drop(serde_json::from_value::<tendermint::PublicKey>(key))) {
            None => false,
            // A build with debug assertions (this test's, not a released
            // program's) also stops where the decoder wrote fewer bytes than
            // it made room for. A released program returns those bytes.
            Some(message) => !message.contains("left == right"),
        }
    }

    /// The library's date reader, reached through a time in JSON.
    fn reader_panics(text: &str) -> bool {
        let time = json!(text);
        panic_of(move || drop(serde_json::from_value::<tendermint::Time>(time))).is_some()
    }

    /// Every text of the alphabet up to a length.
    fn texts(alphabet: &[&str], longest: usize) -> Vec<String> {
        let mut all = vec![String::new()];
        let mut last = vec![String::new()];
        for _ in 0..longest {
            last = last.iter().flat_map(|text| alphabet.iter().map(move |letter| format!("{text}{letter}"))).collect();
            all.extend(last.iter().cloned());
        }
        all
    }

    #[test]
    fn the_base64_rule_names_exactly_the_texts_the_decoder_panics_on() {
        let mut corpus = texts(&["A", "=", " "], 9);
        corpus.extend(texts(&["A", "="], 13));
        // Characters of more than one byte, a byte that is white space only
        // as the last byte of a character, and characters that are no base64.
        corpus.extend(texts(&["A", "=", "\u{e9}", "\u{a0}", "-"], 5));
        // A signature as consensus writes it (64 bytes, 88 characters), with
        // every ending of up to six characters in place of its own and after it.
        let signature = format!("{}==", "q".repeat(86));
        for ending in texts(&["A", "="], 6) {
            corpus.push(format!("{}{ending}", &signature[..82]));
            corpus.push(format!("{signature}{ending}"));
        }
        let mut stopped = 0;
        for text in &corpus {
            let expected = decoder_panics(text);
            assert_eq!(base64_stops_the_decoder(text.as_bytes()), expected, "{text:?}");
            assert_eq!(refusal(text) == Some(BASE64), expected, "{text:?}");
            stopped += usize::from(expected);
        }
        // The test would say nothing if the decoder never panicked.
        assert!(stopped > corpus.len() / 4 && stopped < corpus.len(), "{stopped} of {}", corpus.len());
        for text in ["A========", "=", "==", "=A", "AAAA=A", "AAAA====", &format!("{signature}=")] {
            assert!(base64_stops_the_decoder(text.as_bytes()), "{text}");
        }
        // What base64 is, with its padding or without, is never named.
        for bytes in 0..70usize {
            let mut encoded = String::new();
            for chunk in vec![0xa7u8; bytes].chunks(3) {
                let value = chunk.iter().fold(0u32, |all, byte| all << 8 | u32::from(*byte)) << (8 * (3 - chunk.len()));
                for place in 0..=chunk.len() {
                    encoded.push(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(value >> (18 - 6 * place) & 63) as usize] as char);
                }
                encoded.push_str(&"=".repeat(3 - chunk.len()));
            }
            assert!(!base64_stops_the_decoder(encoded.as_bytes()), "{encoded}");
            assert!(!base64_stops_the_decoder(encoded.trim_end_matches('=').as_bytes()), "{encoded} without its padding");
            assert!(!decoder_panics(&encoded), "{encoded}");
        }
    }

    #[test]
    fn the_date_rule_names_the_dates_the_reader_panics_on_and_none_it_reads() {
        let mut corpus = Vec::new();
        for date in ["9999-12-31", "9999-12-30", "9999-11-30", "9998-12-31", "0000-01-01", "0001-01-01", "2026-11-22", "9999-12-32", "99999-12-31"] {
            for separator in ["T", "t", " ", "_"] {
                for time in ["00:00:00", "00:00:01", "12:00:00", "23:59:00", "23:59:58", "23:59:59", "23:59:60", "22:59:60", "24:00:00", "23:60:00", "2:00:00"] {
                    for fraction in ["", ".0", ".5", ".999999999", ".9999999999", "."] {
                        for offset in ["Z", "z", "", "+00:00", "-00:00", "-00:01", "+00:01", "-01:00", "-12:00", "-23:59", "+23:59", "-24:00", "-00:60", "-0001", "- 0:01", "\u{2212}00:01", "-00:01 "] {
                            corpus.push(format!("{date}{separator}{time}{fraction}{offset}"));
                        }
                    }
                }
            }
        }
        let (mut stopped, mut read) = (0, 0);
        for text in &corpus {
            let named = date_stops_the_reader(text);
            if reader_panics(text) {
                assert!(named, "the reader panics on {text:?} and the rule does not name it");
                stopped += 1;
            } else if serde_json::from_value::<tendermint::Time>(json!(text)).is_ok() {
                assert!(!named, "the reader reads {text:?} and the rule names it");
                assert_eq!(refusal(text), None, "{text:?}");
                read += 1;
            }
        }
        assert!(stopped > 50 && read > 500, "{stopped} panics and {read} dates read among {}", corpus.len());
        // The edge, to the second.
        assert!(date_stops_the_reader("9999-12-31T23:59:59-00:01"));
        assert!(date_stops_the_reader("9999-12-31T00:01:00-23:59"));
        assert!(!date_stops_the_reader("9999-12-31T00:01:00-23:59."));
        assert!(!date_stops_the_reader("9999-12-31T00:00:59-23:59"));
        assert!(!date_stops_the_reader("9999-12-31T23:59:59Z"));
        assert!(!date_stops_the_reader("9999-12-31T23:59:59+23:59"));
        assert!(!date_stops_the_reader("9999-12-31T23:59:59-00:00"));
        assert_eq!(refusal("9999-12-31 12:00:00.25-12:00"), Some(DATE));
    }

    #[test]
    fn a_scan_finds_such_a_text_wherever_it_is_and_nothing_else() {
        let scan = |text: &str| serde_json::from_str::<Scan>(text).map(drop);
        for sound in [
            r#"{"a":[1,-2,3.5,true,null,"AAAA","QQ==",{"b":"2026-11-22T10:00:00Z"}],"c":""}"#,
            // A field name is not a text any reader decodes.
            r#"{"A========":1,"9999-12-31T23:59:59-00:01":[]}"#,
            "[]",
            "\"x\"",
            "3",
        ] {
            scan(sound).unwrap_or_else(|error| panic!("{sound}: {error}"));
            value(&serde_json::from_str(sound).unwrap()).unwrap();
        }
        for (unsound, reason) in [
            (r#"{"a":[1,{"b":[[{"signature":"A========"}]]}]}"#, BASE64),
            (r#"["AAAA","AAAA=A"]"#, BASE64),
            // As JSON writes the same text with escapes.
            (r#"{"a":"A\u003d\u003d\u003d\u003d\u003d\u003d\u003d\u003d"}"#, BASE64),
            (r#"{"a":"x","a":"="}"#, BASE64),
            (r#"{"header":{"time":"9999-12-31T23:59:59-00:01"}}"#, DATE),
            ("\"==\"", BASE64),
        ] {
            let error = scan(unsound).expect_err(unsound);
            assert!(error.is_data() && error.to_string().starts_with(reason), "{unsound}: {error}");
        }
        // The one a value keeps of two fields of one name is the last; the scan above saw both.
        assert_eq!(value(&json!({ "a": [{ "b": "A========" }] })), Err(BASE64));
        assert_eq!(value(&json!({ "a": { "time": "9999-12-31T23:59:59-00:01" } })), Err(DATE));
        // Text that is not JSON fails as it does for every reader, not as a refusal.
        for broken in ["{\"a\":", "[1,]", "", "{\"a\":\"\\ud800\"}"] {
            assert!(!scan(broken).expect_err(broken).is_data(), "{broken}");
        }
        // A broken text is still refused for what stands before the break.
        assert!(scan(r#"{"a":"A========","b":"#).expect_err("a refusal").is_data());
    }
}
