//! Version-four dynamic-validator light client and authenticated state verifier.
//! A trusting period protects a locally trusted checkpoint; an RPC response can
//! never refresh an expired trust anchor by itself.
#[cfg(test)]
mod fast_receipt_tests;
#[cfg(test)]
mod fixtures;
pub mod light;
#[cfg(test)]
mod light_tests;
#[cfg(test)]
mod live_tests;
pub mod market;
#[cfg(test)]
mod market_tests;
#[cfg(test)]
mod proof_tests;
#[cfg(test)]
mod untrusted_tests;
#[cfg(test)]
mod upgrade_tests;
pub mod untrusted;

use serde_json::Value;
use wasm_bindgen::prelude::*;
pub const MAX_JSON: usize = 8 * 1024 * 1024;
/// Reads a JSON text from outside into a type. Everything a gateway, a node
/// or a stored trust hands to the verifier comes through here.
///
/// The types of the `tendermint` crates panic on certain texts instead of
/// refusing them (`untrusted`): in WebAssembly that is a trap, and an
/// instance that has trapped often enough fails on honest answers too. So
/// before any type reads the text, every text in it is looked at, and one
/// that would stop a reader is refused here, as invalid JSON is.
pub fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, String> {
    if text.len() > MAX_JSON {
        return Err("JSON_LIMIT: verification input exceeds eight MiB".into());
    }
    // A text that is not JSON fails the scan too, in its syntax: that error
    // is left to the reader below, which says the same of it as before.
    if let Err(error) = serde_json::from_str::<untrusted::Scan>(text)
        && error.is_data()
    {
        return Err(format!("INVALID_JSON: {error}"));
    }
    serde_json::from_str(text).map_err(|e| format!("INVALID_JSON: {e}"))
}
pub fn decimal(value: &Value, label: &str) -> Result<u64, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("INVALID_DECIMAL: {label} must be a decimal string"))?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!("INVALID_DECIMAL: noncanonical {label}"));
    }
    text.parse()
        .map_err(|_| format!("INVALID_DECIMAL: overflow in {label}"))
}
#[wasm_bindgen]
pub fn verify_light_update(
    candidate_json: &str,
    trust_json: &str,
    now_ms: f64,
) -> Result<String, JsValue> {
    light::update_json(candidate_json, trust_json, now_ms)
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn verify_trust(trust_json: &str, now_ms: f64) -> Result<String, JsValue> {
    parse(trust_json)
        .and_then(|trust| light::trust_status(&trust, light::now_micros(now_ms)?))
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}

pub mod receipt;
pub mod view;

#[wasm_bindgen]
pub fn verify_view_proof(
    proof: &str,
    trust: &str,
    selection: &str,
    now: f64,
) -> Result<String, JsValue> {
    view::view(proof, trust, selection, now)
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn verify_receipt(proof: &str, trust: &str, now: f64) -> Result<String, JsValue> {
    receipt::receipt(proof, trust, now)
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn verify_fast_receipt(proof: &str, trust: &str, now: f64) -> Result<String, JsValue> {
    receipt::fast_receipt(proof, trust, now)
        .and_then(|v| serde_json::to_string(&v).map_err(|e| e.to_string()))
        .map_err(|e| JsValue::from_str(&e))
}
