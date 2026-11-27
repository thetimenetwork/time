//! The market of seconds against bitcoin, as this verifier reads it
//! (`spec/market.md`, section 4):
//!
//! 1. the rows a selection names are proven present or proven absent, and
//!    reach the wallet exactly as the state holds them;
//! 2. a row under another key, a row that is not canonical, a row of a form
//!    this build does not know, a proof for another key and absence claimed
//!    for a row that exists are refused;
//! 3. the seconds the market holds are a term of the supply rule, on a
//!    network with the setting and on no other;
//! 4. the engine's own rows (`fixtures/market-state.fixture.json`, written
//!    by `v5/tests/market.rs`) verify and read as the engine stored them.
//!
//! The rows of parts 1 to 3 are written by hand from section 4 of the
//! specification.
use crate::{
    fixtures::T0,
    proof_tests::{fixture_built, fixture_raw},
    view,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2_10::{Digest, Sha256};

/// The fixture's state is 1,209,898 seconds after genesis.
const ELAPSED: u64 = 1_209_898_000_000;
/// What the hand-made market holds: 20 seconds on offer, a bond of 3, and
/// a fill of 40 with a deposit of 2.
const HELD: u64 = 65_000_000;
/// 250 satoshis for one second.
const PRICE: &str = "250000000";

fn id_key(namespace: &[u8], id: u64) -> Vec<u8> {
    [namespace, &id.to_be_bytes()].concat()
}
fn order_key(id: u64) -> Vec<u8> {
    id_key(b"market/order/", id)
}
fn fill_key(id: u64) -> Vec<u8> {
    id_key(b"market/fill/", id)
}
fn account_key(id: u64) -> Vec<u8> {
    id_key(b"market/account/", id)
}
fn candle_key(hour: u64) -> Vec<u8> {
    id_key(b"market/candle/", hour)
}
fn script_key(script: &str) -> Vec<u8> {
    [b"market/script/".as_slice(), Sha256::digest(hex::decode(script).unwrap()).as_slice()].concat()
}
/// A pay-to-witness-public-key-hash script.
fn script(byte: u8) -> String {
    hex::encode([vec![0x00, 0x14], vec![byte; 20]].concat())
}
fn check(f: &Value) -> Result<Value, String> {
    view::view(
        &f["proof"].to_string(),
        &f["trust"].to_string(),
        &f["request"].to_string(),
        f["now_ms"].as_f64().unwrap(),
    )
}
fn refused(f: &Value) -> String {
    match check(f) {
        Ok(_) => panic!("verified"),
        Err(error) => error,
    }
}
fn moment() -> Value {
    json!({"height": "4", "time_micros": ((T0 + 1_209_800) * 1_000_000).to_string()})
}
fn summary() -> Value {
    json!({"fills":"1","last_price":PRICE,"next_fill":"3","next_order":"3","orders":"2","sats":"10000","seconds_micros":"40000000","trades":"1"})
}
fn heights() -> Value {
    json!({"entries":[{"at":"0","height":"0"},{"at":"1209000000000","height":"4"}]})
}
/// An open sell order: its first script has served a fill, its second
/// serves fill 2, its third is free.
fn sell_order() -> Value {
    json!({"amount_micros":"20000000","bond_micros":"0","confirmations":"2","created":moment(),"deposit_ppm":"50000","id":"1","key":"ab".repeat(32),"min_deposit_micros":"0","min_sats":"1000","open":true,"owner":"5","pay_blocks":"6","price":PRICE,
        "scripts":[{"script":script(1),"used":true},{"fill":"2","script":script(2)},{"script":script(3)}],"side":"sell"})
}
fn buy_order() -> Value {
    json!({"amount_micros":"30000000","bond_micros":"3000000","confirmations":"3","created":moment(),"deposit_ppm":"100000","fills":"0","forms":["p2tr","p2wpkh"],"id":"2","key":"cd".repeat(32),"min_deposit_micros":"0","min_sats":"1000","open":true,"owner":"6","pay_blocks":"6","price":"240000000","side":"buy"})
}
fn fill() -> Value {
    json!({"amount_micros":"40000000","confirmations":"2","created":moment(),"deposit_micros":"2000000","id":"2","opened_micros":"1209800000000","order":"1","owner":"5","pay_blocks":"6","payer":"6","price":PRICE,"sats":"10000","script":script(2),"side":"sell","start_hash":"0f".repeat(32),"start_height":"4","to":"6"})
}
fn candle() -> Value {
    json!({"close":PRICE,"high":"260000000","low":"240000000","open":"245000000","sats":"10000","seconds_micros":"40000000","trades":"1"})
}
/// Every row of the hand-made market, under its key.
fn rows() -> Vec<(Vec<u8>, Value)> {
    vec![
        (b"market/meta".to_vec(), summary()),
        (b"market/heights".to_vec(), heights()),
        (order_key(1), sell_order()),
        (order_key(2), buy_order()),
        (fill_key(2), fill()),
        (account_key(5), json!({"fills":[],"orders":["1"]})),
        (account_key(6), json!({"fills":["2"],"orders":["2"]})),
        (script_key(&script(1)), json!({})),
        (script_key(&script(2)), json!({"order":"1"})),
        (script_key(&script(4)), json!({"fill":"9"})),
        (candle_key(336), candle()),
    ]
}
/// The keys the selection names that hold no row.
fn absent() -> Vec<Vec<u8>> {
    vec![order_key(7), fill_key(3), account_key(9), script_key(&script(5)), candle_key(337)]
}
fn request() -> Value {
    json!({
        "include_market": true,
        "market_orders": ["1", "2", "7"],
        "market_fills": ["2", "3"],
        "market_accounts": ["5", "6", "9"],
        "market_scripts": [script(1), script(2), script(4), script(5)],
        "market_candles": ["336", "337"],
    })
}
/// The metadata of a network with the market that holds `HELD`.
fn with_market(meta: &mut Value) {
    meta["config"]["market"] = json!(true);
    meta["market_micros"] = json!(HELD.to_string());
    meta["bank"] = json!((ELAPSED - HELD).to_string());
}
fn asking(mut f: Value) -> Value {
    f["request"] = request();
    f
}
/// A network with the market whose state holds `rows`.
fn market_of(rows: Vec<(Vec<u8>, Value)>, absent: Vec<Vec<u8>>) -> Value {
    asking(fixture_built(with_market, rows, absent, 4, 4))
}
fn market() -> Value {
    market_of(rows(), absent())
}
/// The hand-made market with the row under `key` replaced by `row`.
fn with_row(key: &[u8], row: Value) -> Value {
    let mut all = rows();
    all.iter_mut().find(|(k, _)| k == key).expect("the fixture holds this key").1 = row;
    market_of(all, absent())
}
/// The same, with the bytes stored under `key` given as they are.
fn with_bytes(key: &[u8], bytes: &[u8]) -> Value {
    let all = rows()
        .into_iter()
        .map(|(k, row)| if k == key { (k, bytes.to_vec()) } else { (k, serde_json::to_vec(&row).unwrap()) })
        .collect();
    asking(fixture_raw(with_market, all, absent(), 4, 4))
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
fn edited(row: Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut row = row;
    edit(&mut row);
    row
}
fn without(row: Value, field: &str) -> Value {
    edited(row, |row| {
        row.as_object_mut().unwrap().remove(field);
    })
}

// ---- 1. presence and absence

#[test]
fn the_rows_of_the_market_reach_the_wallet_as_the_state_holds_them() {
    let checked = check(&market()).unwrap();
    assert_eq!(checked["verified"], true);
    let state = &checked["state"];
    assert_eq!(state["config"]["market"], true);
    assert_eq!(state["market_micros"], HELD.to_string());
    assert_eq!(
        state["market"],
        json!({
            "summary": summary(),
            "heights": heights(),
            "orders": {"1": sell_order(), "2": buy_order(), "7": null},
            "fills": {"2": fill(), "3": null},
            "accounts": {"5": {"fills":[],"orders":["1"]}, "6": {"fills":["2"],"orders":["2"]}, "9": null},
            "scripts": {script(1): {}, script(2): {"order":"1"}, script(4): {"fill":"9"}, script(5): null},
            "candles": {"336": candle(), "337": null},
        })
    );
    // A selection that names rows only says nothing of the summary; one
    // that asks nothing of the market has no such object at all.
    let mut one = market();
    one["request"] = json!({"market_fills": ["2"]});
    assert_eq!(
        check(&one).unwrap()["state"]["market"],
        json!({"orders": {}, "fills": {"2": fill()}, "accounts": {}, "scripts": {}, "candles": {}})
    );
    one["request"] = json!({"include_market": false, "ids": ["999"]});
    assert!(check(&one).unwrap()["state"].get("market").is_none());
    // The same script asked twice is one entry.
    one["request"] = json!({"market_scripts": [script(2), script(2)]});
    assert_eq!(check(&one).unwrap()["state"]["market"]["scripts"], json!({script(2): {"order":"1"}}));
}

#[test]
fn every_standard_form_of_receiving_script_can_be_asked_for() {
    let with = |head: &[u8], body: usize, tail: &[u8]| hex::encode([head, &vec![7u8; body], tail].concat());
    let forms = [
        with(&[0x76, 0xa9, 0x14], 20, &[0x88, 0xac]),
        with(&[0xa9, 0x14], 20, &[0x87]),
        with(&[0x00, 0x14], 20, &[]),
        with(&[0x00, 0x20], 32, &[]),
        with(&[0x51, 0x20], 32, &[]),
    ];
    let mut f = fixture_built(with_market, vec![(script_key(&forms[0]), json!({"order":"3"}))], forms[1..].iter().map(|s| script_key(s)).collect(), 4, 4);
    f["request"] = json!({"market_scripts": forms});
    let scripts = check(&f).unwrap()["state"]["market"]["scripts"].clone();
    assert_eq!(scripts[&forms[0]], json!({"order":"3"}));
    for form in &forms[1..] {
        assert_eq!(scripts[form], Value::Null);
    }
    // Anything else is not a receiving script, and no row can exist for it.
    for other in [
        "6a0100".to_string(),
        with(&[0x00, 0x14], 19, &[]),
        with(&[0x00, 0x14], 21, &[]),
        with(&[0x52, 0x20], 32, &[]),
        with(&[0x76, 0xa9, 0x14], 20, &[0x88, 0xad]),
        forms[0].to_uppercase(),
        forms[2][1..].to_string(),
        String::new(),
    ] {
        f["request"] = json!({"market_scripts": [other]});
        assert_eq!(refused(&f), "a receiving script is one of the five standard forms, in lowercase hexadecimal", "{other}");
    }
}

#[test]
fn a_network_without_the_market_proves_that_it_has_none() {
    // The same question, answered "none": the node proves every key absent.
    let none: Vec<Vec<u8>> = rows().into_iter().map(|(key, _)| key).chain(absent()).collect();
    let f = asking(fixture_built(|_| {}, Vec::new(), none.clone(), 4, 4));
    let checked = check(&f).unwrap();
    assert!(checked["state"]["config"].get("market").is_none());
    assert!(checked["state"].get("market_micros").is_none());
    assert_eq!(
        checked["state"]["market"],
        json!({
            "summary": null,
            "heights": null,
            "orders": {"1": null, "2": null, "7": null},
            "fills": {"2": null, "3": null},
            "accounts": {"5": null, "6": null, "9": null},
            "scripts": {script(1): null, script(2): null, script(4): null, script(5): null},
            "candles": {"336": null, "337": null},
        })
    );
    // A row under `market/` on such a network is not a state the engine
    // writes, whichever row it is.
    for (key, row) in rows() {
        let others = none.iter().filter(|k| **k != key).cloned().collect();
        let f = asking(fixture_built(|_| {}, vec![(key.clone(), row)], others, 4, 4));
        assert_eq!(refused(&f), "market rows belong to a network with the market", "{}", String::from_utf8_lossy(&key));
    }
    // And a network with the market has its summary and its clock.
    for key in [b"market/meta".as_slice(), b"market/heights"] {
        let kept = rows().into_iter().filter(|(k, _)| k != key).collect();
        let f = market_of(kept, absent().into_iter().chain([key.to_vec()]).collect());
        assert_eq!(refused(&f), "a network with the market holds its summary and its clock of heights");
    }
}

// ---- 2. refusals

#[test]
fn a_row_under_another_key_is_refused() {
    // Order 2 stored under the key of order 1, and the reverse.
    assert_eq!(refused(&with_row(&order_key(1), buy_order())), "order key mismatch");
    assert_eq!(refused(&with_row(&order_key(2), sell_order())), "order key mismatch");
    assert_eq!(refused(&with_row(&fill_key(2), edited(fill(), |row| row["id"] = json!("3")))), "fill key mismatch");
    // A row of another kind under a key is not that kind of row.
    assert_eq!(refused(&with_row(&fill_key(2), sell_order())), "fill has missing or unknown fields");
    assert_eq!(refused(&with_row(&order_key(1), fill())), "order has missing or unknown fields");
    assert_eq!(refused(&with_row(&candle_key(336), summary())), "candle has missing or unknown fields");
    assert_eq!(refused(&with_row(b"market/meta", heights())), "market summary has missing or unknown fields");
}

#[test]
fn a_row_that_is_not_canonical_is_refused() {
    let canonical = serde_json::to_vec(&fill()).unwrap();
    assert_eq!(check(&with_bytes(&fill_key(2), &canonical)).unwrap()["state"]["market"]["fills"]["2"], fill());
    let text = String::from_utf8(canonical).unwrap();
    for other in [
        // A space, a line end, the fields in another order, a field twice,
        // a character written as an escape.
        text.replacen(':', ": ", 1),
        format!("{text}\n"),
        text.replacen(r#""amount_micros":"40000000","confirmations":"2","#, r#""confirmations":"2","amount_micros":"40000000","#, 1),
        text.replacen(r#""sats":"10000","#, r#""sats":"1","sats":"10000","#, 1),
        text.replacen(r#""side":"sell""#, &format!(r#""side":"s{}u0065ll""#, '\x5c'), 1),
    ] {
        assert_ne!(other, text);
        // The bytes are the state's own: every proof verifies, and the row
        // read loosely is the same fill.
        assert_eq!(serde_json::from_str::<Value>(&other).unwrap(), fill(), "{other}");
        assert_eq!(refused(&with_bytes(&fill_key(2), other.as_bytes())), "noncanonical market row", "{other}");
    }
    // Every kind of row is held to it, the summary too.
    let loose = serde_json::to_string_pretty(&summary()).unwrap();
    assert_eq!(refused(&with_bytes(b"market/meta", loose.as_bytes())), "noncanonical market row");
    let loose = serde_json::to_string(&json!({})).unwrap() + " ";
    assert_eq!(refused(&with_bytes(&script_key(&script(1)), loose.as_bytes())), "noncanonical market row");
}

#[test]
fn a_proof_for_another_key_and_absence_claimed_for_a_row_that_exists_are_refused() {
    let honest = market();
    // Without the entry the proof is refused: an entry left out is never
    // read as "no such row".
    for key in rows().into_iter().map(|(key, _)| key).chain(absent()) {
        let mut f = honest.clone();
        let wanted = hex::encode(&key);
        f["proof"]["entries"].as_array_mut().unwrap().retain(|entry| entry["key_hex"] != wanted);
        assert_eq!(refused(&f), format!("missing requested proof for {wanted}"));
    }
    // "Absent" for a row that exists does not verify.
    for (key, _) in rows() {
        let mut f = honest.clone();
        entry_of(&mut f, &key)["value_b64"] = Value::Null;
        assert!(refused(&f).contains("invalid key/value proof"), "{}", String::from_utf8_lossy(&key));
    }
    // A row claimed for a key that holds none does not verify.
    let mut f = honest.clone();
    entry_of(&mut f, &order_key(7))["value_b64"] = json!(STANDARD.encode(serde_json::to_vec(&sell_order()).unwrap()));
    assert!(refused(&f).contains("invalid key/value proof"));
    // The proof of another key, relabelled: order 2's entry under the key
    // of order 1, a fill's proof of absence under the key of a fill that
    // exists, and the reverse.
    for (from, to) in [(order_key(2), order_key(1)), (fill_key(3), fill_key(2)), (fill_key(2), fill_key(3)), (script_key(&script(5)), script_key(&script(2)))] {
        let mut f = honest.clone();
        let mut moved = entry_of(&mut f, &from).clone();
        moved["key_hex"] = json!(hex::encode(&to));
        *entry_of(&mut f, &to) = moved;
        assert!(refused(&f).contains("invalid key/value proof"));
    }
    // Another value under the right key.
    let mut f = honest.clone();
    let cheaper = edited(fill(), |row| row["sats"] = json!("1"));
    entry_of(&mut f, &fill_key(2))["value_b64"] = json!(STANDARD.encode(serde_json::to_vec(&cheaper).unwrap()));
    assert!(refused(&f).contains("invalid key/value proof"));
}

#[test]
fn a_row_of_a_form_this_build_does_not_know_is_refused() {
    let set = |field: &'static str, value: Value| move |row: &mut Value| row[field] = value;
    let cases: Vec<(Vec<u8>, Value, &str)> = vec![
        // The summary.
        (b"market/meta".to_vec(), edited(summary(), set("more", json!("1"))), "market summary has missing or unknown fields"),
        (b"market/meta".to_vec(), without(summary(), "trades"), "market summary has missing or unknown fields"),
        (b"market/meta".to_vec(), edited(summary(), set("orders", json!(2))), "INVALID_DECIMAL: market summary orders must be a decimal string"),
        (b"market/meta".to_vec(), edited(summary(), set("orders", json!("02"))), "INVALID_DECIMAL: noncanonical market summary orders"),
        (b"market/meta".to_vec(), edited(summary(), set("orders", json!("3"))), "market summary counts more rows than it gave ids"),
        (b"market/meta".to_vec(), edited(summary(), set("fills", json!("3"))), "market summary counts more rows than it gave ids"),
        (b"market/meta".to_vec(), without(summary(), "last_price"), "market summary has a last price exactly when it has a trade"),
        (b"market/meta".to_vec(), edited(summary(), set("trades", json!("0"))), "market summary has a last price exactly when it has a trade"),
        (b"market/meta".to_vec(), edited(summary(), set("last_price", json!("0"))), "market summary last_price is not a price"),
        (b"market/meta".to_vec(), edited(summary(), set("last_price", json!("1000000000000001"))), "market summary last_price is not a price"),
        // The clock of heights.
        (b"market/heights".to_vec(), json!({"entries":[]}), "the clock of heights holds one to 256 entries"),
        (b"market/heights".to_vec(), json!({"entries":(0..257).map(|n| json!({"at":"0","height":n.to_string()})).collect::<Vec<_>>()}), "the clock of heights holds one to 256 entries"),
        (b"market/heights".to_vec(), json!({"entries":[{"at":"5","height":"4"},{"at":"6","height":"4"}]}), "the clock of heights does not rise in height and time"),
        (b"market/heights".to_vec(), json!({"entries":[{"at":"5","height":"4"},{"at":"4","height":"5"}]}), "the clock of heights does not rise in height and time"),
        (b"market/heights".to_vec(), json!({"entries":[{"at":"5","height":"4294967296"}]}), "clock of heights height exceeds 32 bits"),
        (b"market/heights".to_vec(), json!({"entries":[{"at":"5","height":"4","hash":"00"}]}), "entry of the clock of heights has missing or unknown fields"),
        (b"market/heights".to_vec(), json!({"entries":{}}), "invalid clock of heights"),
        // An order.
        (order_key(1), edited(sell_order(), set("note", json!("x"))), "order has missing or unknown fields"),
        (order_key(1), without(sell_order(), "key"), "order has missing or unknown fields"),
        (order_key(1), edited(sell_order(), set("keys", json!("ab".repeat(32)))), "order has missing or unknown fields"),
        (order_key(1), edited(sell_order(), set("fills", json!("0"))), "order has missing or unknown fields"),
        (order_key(1), edited(sell_order(), set("forms", json!(["p2tr"]))), "order has missing or unknown fields"),
        (order_key(2), edited(buy_order(), set("scripts", json!([{"script": script(9)}]))), "order has missing or unknown fields"),
        (order_key(1), edited(sell_order(), set("side", json!("both"))), "the side of the market is sell or buy"),
        (order_key(1), edited(sell_order(), set("key", json!("AB".repeat(32)))), "the key of an order must be 64 lowercase hexadecimal characters"),
        (order_key(1), edited(sell_order(), set("key", json!("ab".repeat(31)))), "the key of an order must be 64 lowercase hexadecimal characters"),
        (order_key(1), edited(sell_order(), set("open", json!("true"))), "an order is open or it is not"),
        (order_key(1), edited(sell_order(), set("price", json!("0"))), "order price is not a price"),
        (order_key(1), edited(sell_order(), set("confirmations", json!("0"))), "order bounds"),
        (order_key(1), edited(sell_order(), set("confirmations", json!("101"))), "order bounds"),
        (order_key(1), edited(sell_order(), set("pay_blocks", json!("145"))), "order bounds"),
        (order_key(1), edited(sell_order(), set("deposit_ppm", json!("1000001"))), "order bounds"),
        (order_key(1), edited(sell_order(), set("min_sats", json!("0"))), "order bounds"),
        (order_key(1), edited(sell_order(), set("bond_micros", json!("1"))), "sell order shape"),
        (order_key(1), edited(sell_order(), set("scripts", json!([]))), "sell order shape"),
        (order_key(1), edited(sell_order(), set("scripts", json!((0..17).map(|n| json!({"script": script(n)})).collect::<Vec<_>>()))), "sell order shape"),
        (order_key(1), edited(sell_order(), set("scripts", json!([{"script": script(1)}, {"script": script(1)}]))), "an order lists a receiving script twice"),
        (order_key(1), edited(sell_order(), set("scripts", json!([{"script": "6a0100"}]))), "a receiving script is one of the five standard forms, in lowercase hexadecimal"),
        (order_key(1), edited(sell_order(), set("scripts", json!([{"script": script(1), "used": false}]))), "order script that has served"),
        (order_key(1), edited(sell_order(), set("scripts", json!([{"fill": "2", "script": script(1), "used": true}]))), "order script that has served"),
        (order_key(1), edited(sell_order(), set("scripts", json!([{"script": script(1), "order": "1"}]))), "order script has missing or unknown fields"),
        (order_key(1), edited(sell_order(), set("created", json!({"height": "4"}))), "order creation has missing or unknown fields"),
        (order_key(1), edited(sell_order(), set("created", json!({"height": "4", "time_micros": "-1"}))), "INVALID_DECIMAL: noncanonical order creation time_micros"),
        (order_key(1), edited(sell_order(), set("open", json!(false))), "a closed order offers nothing and has a fill"),
        (order_key(2), edited(buy_order(), set("min_deposit_micros", json!("1"))), "buy order shape"),
        (order_key(2), edited(buy_order(), set("fills", json!("17"))), "buy order shape"),
        (order_key(2), edited(buy_order(), set("forms", json!([]))), "buy order shape"),
        (order_key(2), edited(buy_order(), set("forms", json!(["p2wpkh", "p2tr"]))), "buy order shape"),
        (order_key(2), edited(buy_order(), set("forms", json!(["p2tr", "p2tr"]))), "buy order shape"),
        (order_key(2), edited(buy_order(), set("forms", json!(["p2pk"]))), "an order names a form of receiving script that does not exist"),
        (order_key(2), edited(buy_order(), |row| { row["open"] = json!(false); row["amount_micros"] = json!("0"); row["bond_micros"] = json!("0"); }), "a closed order offers nothing and has a fill"),
        // A fill.
        (fill_key(2), edited(fill(), set("paid", json!("1"))), "fill has missing or unknown fields"),
        (fill_key(2), without(fill(), "start_hash"), "fill has missing or unknown fields"),
        (fill_key(2), edited(fill(), set("amount_micros", json!("040000000"))), "INVALID_DECIMAL: noncanonical fill amount_micros"),
        (fill_key(2), edited(fill(), set("amount_micros", json!(40000000))), "INVALID_DECIMAL: fill amount_micros must be a decimal string"),
        (fill_key(2), edited(fill(), set("sats", json!("0"))), "the satoshis of a fill are none, or more than the price of its seconds"),
        (fill_key(2), edited(fill(), set("sats", json!("10001"))), "the satoshis of a fill are none, or more than the price of its seconds"),
        (fill_key(2), edited(fill(), set("price", json!("249900000"))), "the satoshis of a fill are none, or more than the price of its seconds"),
        (fill_key(2), edited(fill(), set("amount_micros", json!("39990000"))), "the satoshis of a fill are none, or more than the price of its seconds"),
        (fill_key(2), edited(fill(), |row| { row["amount_micros"] = json!("18446744073709551615"); row["price"] = json!("1000000000000000"); }), "the satoshis of a fill are none, or more than the price of its seconds"),
        (fill_key(2), edited(fill(), |row| { row["amount_micros"] = json!("0"); row["sats"] = json!("0"); }), "fill bounds"),
        (fill_key(2), edited(fill(), set("confirmations", json!("0"))), "fill bounds"),
        (fill_key(2), edited(fill(), set("pay_blocks", json!("0"))), "fill bounds"),
        (fill_key(2), edited(fill(), set("start_height", json!("4294967290"))), "fill bounds"),
        (fill_key(2), edited(fill(), set("start_height", json!("4294967296"))), "fill start_height exceeds 32 bits"),
        (fill_key(2), edited(fill(), set("script", json!(script(0xab).to_uppercase()))), "a receiving script is one of the five standard forms, in lowercase hexadecimal"),
        (fill_key(2), edited(fill(), set("script", json!("0014"))), "a receiving script is one of the five standard forms, in lowercase hexadecimal"),
        (fill_key(2), edited(fill(), set("start_hash", json!("0f".repeat(31)))), "the starting block of a fill must be 64 lowercase hexadecimal characters"),
        (fill_key(2), edited(fill(), |row| { row["side"] = json!("buy"); row["to"] = json!("7"); }), "a fill against a buy order gives its seconds to its payer"),
        // An account's index.
        (account_key(5), json!({"fills":[],"orders":[]}), "empty market index"),
        (account_key(5), json!({"orders":["1"]}), "market index has missing or unknown fields"),
        (account_key(5), json!({"fills":[],"orders":["2","1"]}), "a market index lists at most 64 ids, ascending, each once"),
        (account_key(5), json!({"fills":["1","1"],"orders":[]}), "a market index lists at most 64 ids, ascending, each once"),
        (account_key(5), json!({"fills":[],"orders":(1..=65).map(|n| n.to_string()).collect::<Vec<_>>()}), "a market index lists at most 64 ids, ascending, each once"),
        (account_key(5), json!({"fills":[],"orders":[1]}), "INVALID_DECIMAL: market index id must be a decimal string"),
        // A script.
        (script_key(&script(2)), json!({"fill":"1","order":"1"}), "a script serves an order or a fill, not both"),
        (script_key(&script(2)), json!({"used":true}), "script row has missing or unknown fields"),
        (script_key(&script(2)), json!({"order":"01"}), "INVALID_DECIMAL: noncanonical script row order"),
        (script_key(&script(2)), json!([]), "script row is not an object"),
        // A candle.
        (candle_key(336), edited(candle(), set("volume", json!("1"))), "candle has missing or unknown fields"),
        (candle_key(336), edited(candle(), set("trades", json!("0"))), "candle bounds"),
        (candle_key(336), edited(candle(), set("low", json!("245000001"))), "candle bounds"),
        (candle_key(336), edited(candle(), set("high", json!("249999999"))), "candle bounds"),
        (candle_key(336), edited(candle(), set("open", json!("0"))), "candle open is not a price"),
    ];
    for (key, row, expected) in cases {
        assert_eq!(refused(&with_row(&key, row.clone())), expected, "{} {row}", String::from_utf8_lossy(&key));
    }
    // The forms the engine does write, beside those of the fixture: a closed
    // order whose fill is still open, a fill against a buy order, a summary
    // before the first trade, the largest clock.
    for (key, row) in [
        (order_key(1), edited(sell_order(), |row| { row["open"] = json!(false); row["amount_micros"] = json!("0"); })),
        (order_key(2), edited(buy_order(), |row| { row["open"] = json!(false); row["amount_micros"] = json!("0"); row["bond_micros"] = json!("0"); row["fills"] = json!("16"); })),
        (fill_key(2), edited(fill(), |row| { row["side"] = json!("buy"); row["to"] = json!("6"); })),
        // A fill that was paid in part: what is still to pay is less than
        // the price of what it holds, down to one satoshi.
        (fill_key(2), edited(fill(), set("sats", json!("9999")))),
        (fill_key(2), edited(fill(), set("sats", json!("1")))),
        (b"market/meta".to_vec(), json!({"fills":"0","next_fill":"1","next_order":"1","orders":"0","sats":"0","seconds_micros":"0","trades":"0"})),
        (b"market/heights".to_vec(), json!({"entries":(0..256).map(|n| json!({"at":"7","height":n.to_string()})).collect::<Vec<_>>()})),
        (account_key(5), json!({"fills":(1..=64).map(|n| n.to_string()).collect::<Vec<_>>(),"orders":[]})),
    ] {
        let checked = check(&with_row(&key, row.clone())).unwrap_or_else(|error| panic!("{row}: {error}"));
        assert_eq!(checked["verified"], true);
    }
}

#[test]
fn a_selection_beyond_its_bounds_or_with_another_form_of_id_is_refused() {
    let honest = market();
    let many = |count: u64| (1..=count).map(|n| n.to_string()).collect::<Vec<_>>();
    for (field, most) in [("market_orders", 16), ("market_fills", 16), ("market_accounts", 8), ("market_candles", 32)] {
        let mut f = honest.clone();
        f["request"] = json!({field: many(most + 1)});
        assert_eq!(refused(&f), "selection budget exceeded", "{field}");
        // At the bound the selection is read; the proof has no entry for these ids.
        f["request"] = json!({field: many(most)});
        assert!(refused(&f).starts_with("missing requested proof for "), "{field}");
    }
    let mut f = honest.clone();
    f["request"] = json!({"market_scripts": (0..17).map(script).collect::<Vec<_>>()});
    assert_eq!(refused(&f), "selection budget exceeded");
    for (field, what) in [("market_orders", "order id"), ("market_fills", "fill id"), ("market_accounts", "market account id"), ("market_candles", "candle hour")] {
        for id in ["01", "", "-1", "1.0", "18446744073709551616", " 1"] {
            let mut f = honest.clone();
            f["request"] = json!({field: [id]});
            let error = refused(&f);
            assert!(error.starts_with("INVALID_DECIMAL: ") && error.ends_with(what), "{field} {id}: {error}");
        }
        let mut f = honest.clone();
        f["request"] = json!({field: [1]});
        assert!(refused(&f).starts_with("INVALID_JSON: "), "{field}");
    }
    for odd in [json!({"include_market": "yes"}), json!({"market_orders": "1"}), json!({"market_paid": ["1"]}), json!({"include_markets": true})] {
        let mut f = honest.clone();
        f["request"] = odd;
        assert!(refused(&f).starts_with("INVALID_JSON: "));
    }
}

// ---- 3. the supply rule

#[test]
fn the_seconds_the_market_holds_are_a_term_of_the_supply_rule() {
    assert_eq!(check(&market()).unwrap()["verified"], true);
    let supply = "authenticated aggregate supply differs from elapsed minting";
    let belongs = "the market's total belongs to a network with the market, and to no other";
    let build = |edit: fn(&mut Value)| asking(fixture_built(edit, rows(), absent(), 4, 4));
    // Left out of the sum, or counted twice.
    assert_eq!(refused(&build(|meta| { with_market(meta); meta["bank"] = json!(ELAPSED.to_string()); })), supply);
    assert_eq!(refused(&build(|meta| { with_market(meta); meta["market_micros"] = json!((HELD - 1).to_string()); })), supply);
    // The total without the setting, and the setting without the total.
    assert_eq!(refused(&build(|meta| { with_market(meta); meta["config"].as_object_mut().unwrap().remove("market"); })), belongs);
    assert_eq!(refused(&build(|meta| { with_market(meta); meta.as_object_mut().unwrap().remove("market_micros"); })), belongs);
    assert_eq!(refused(&build(|meta| meta["market_micros"] = json!("0"))), belongs);
    // The setting is written as `true` or left out.
    for written in [json!(false), json!("true"), json!(1), Value::Null] {
        let mut f = market();
        // Changed after signing: the bytes no longer verify, whatever they say.
        let meta = entry_of(&mut f, b"meta");
        let mut row: Value = serde_json::from_slice(&STANDARD.decode(meta["value_b64"].as_str().unwrap()).unwrap()).unwrap();
        row["config"]["market"] = written;
        meta["value_b64"] = json!(STANDARD.encode(serde_json::to_vec(&row).unwrap()));
        assert!(refused(&f).contains("invalid key/value proof"));
    }
    assert_eq!(refused(&build(|meta| { with_market(meta); meta["config"]["market"] = json!(false); })), "unsupported market setting");
    assert_eq!(refused(&build(|meta| { with_market(meta); meta["config"]["market"] = json!("true"); })), "unsupported market setting");
    assert_eq!(refused(&build(|meta| { with_market(meta); meta["market_micros"] = json!(65_000_000); })), "INVALID_DECIMAL: market total must be a decimal string");
    // A market that holds nothing: the field is there, and it is zero.
    let empty = build(|meta| { meta["config"]["market"] = json!(true); meta["market_micros"] = json!("0"); });
    assert_eq!(check(&empty).unwrap()["state"]["market_micros"], "0");
    // A receipt is anchored in the same state, and judged by the same rule.
    let f = fixture_built(with_market, rows(), absent(), 4, 4);
    let receipt = |f: &Value| crate::receipt::receipt(&f["receipt"].to_string(), &f["trust"].to_string(), f["now_ms"].as_f64().unwrap());
    assert_eq!(receipt(&f).unwrap()["executionVerified"], true);
    let f = fixture_built(|meta| { with_market(meta); meta["bank"] = json!(ELAPSED.to_string()); }, rows(), absent(), 4, 4);
    assert_eq!(receipt(&f).unwrap_err(), supply);
}

#[test]
fn the_price_formula_is_the_engines() {
    use crate::market::sats;
    // The vectors of `v5/src/market.rs`.
    assert_eq!(sats(1_000_000, 1), Some(1));
    assert_eq!(sats(1, 1), Some(1));
    assert_eq!(sats(1_000_000_000, 250_000_000), Some(250_000));
    assert_eq!(sats(999_999, 3), Some(1));
    assert_eq!(sats(7, 1_000_000_000_000), Some(7));
    assert_eq!(sats(123_456_789, 987_654_321), Some(121_933));
    assert_eq!(sats(0, 5), Some(0));
    assert_eq!(sats(u64::MAX, 1_000_000_000_000_000), None);
    assert_eq!(sats(1, 0), None);
    assert_eq!(sats(1, 1_000_000_000_000_001), None);
    // The most satoshis there are, and one more.
    assert_eq!(sats(2_100_000_000_000_000, 1_000_000_000_000), Some(2_100_000_000_000_000));
    assert_eq!(sats(2_100_000_000_000_001, 1_000_000_000_000), None);
}

// ---- 4. the engine's own rows
//
// `fixtures/market-state.fixture.json` is written by the engine
// (v5/tests/market.rs, which keeps a copy of its own under
// v5/tests/fixtures and holds it to what the engine produces): for four
// states, the answer of `/v4/state` to a selection that names the
// market's rows, and its root, which is the
// application hash of that height. The engine tests run without CometBFT,
// so the file holds no signed header. Here each answer is put under a
// header that carries exactly that application hash and the chain's own
// times, signed by test validators: everything the verifier checks below
// the signatures is the engine's.
const ENGINE: &str = include_str!("../fixtures/market-state.fixture.json");
const A: [(u8, u64); 4] = [(1, 10), (2, 10), (3, 10), (4, 10)];

fn engine_cases() -> Vec<(String, Value)> {
    use crate::{
        fixtures::{roster, sign_header, values},
        light::{Trust, checkpoint},
    };
    use tendermint::{Hash, Time, block};
    let fixture: Value = serde_json::from_str(ENGINE).unwrap();
    let genesis: u64 = fixture["genesis_time_micros"].as_str().unwrap().parse().unwrap();
    let validators = roster(&A);
    let mut cases = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let height: u64 = case["height"].as_str().unwrap().parse().unwrap();
        let elapsed: u64 = case["elapsed_micros"].as_str().unwrap().parse().unwrap();
        let version: u64 = case["next_block_version"].as_str().unwrap().parse().unwrap();
        let root = hex::decode(case["response"]["root"].as_str().unwrap()).unwrap();
        assert_eq!(case["response"]["root"], case["app_hash"]);
        // A network without the market is another network: the setting is
        // part of the genesis its id is made from.
        let network = if name == "no_market" { &fixture["network_id_without_the_market"] } else { &fixture["network_id"] };
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
            network_id: network.as_str().unwrap().into(),
            app_version: "4".into(),
            genesis_time_micros: genesis.to_string(),
            trusting_period_seconds: "604800".into(),
            unbonding_period_seconds: "1209600".into(),
            initial_validators: values(&validators),
            checkpoint: Some(checkpoint(certified.clone())),
        };
        let proof = json!({"height": case["response"]["height"], "entries": case["response"]["entries"], "history_proofs": case["response"]["history_proofs"], "light_block": certified});
        cases.push((
            name.to_string(),
            json!({
                "trust": pin, "now_ms": micros / 1000 + 1000, "request": case["request"], "proof": proof,
                "what": case["what"], "market": case["market"], "market_micros": case["market_micros"], "expiry": case["expiry"],
                "bitcoin_best_height": case["bitcoin_best_height"], "clock_of_the_waits_micros": case["clock_of_the_waits_micros"],
            }),
        ));
    }
    cases
}

#[test]
fn the_rows_the_engine_writes_verify_and_read_as_the_engine_stored_them() {
    let cases = engine_cases();
    assert_eq!(cases.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), ["trading", "learnt", "due", "no_market"]);
    let prefix = hex::encode(b"market/");
    for (name, f) in &cases {
        let checked = check(f).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(checked["verified"], true, "{name}");
        let state = &checked["state"];
        // The rows reach the wallet exactly as the state of the engine holds them.
        assert_eq!(state["market"], f["market"], "{name}");
        assert_eq!(state["config"].get("market").is_some(), name != "no_market", "{name}");
        assert_eq!(state.get("market_micros").cloned().unwrap_or(Value::Null), f["market_micros"], "{name}");
        assert_eq!(state["bitcoin"]["meta"]["best_height"], f["bitcoin_best_height"], "{name}");
        let keys: Vec<String> = f["proof"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["key_hex"].as_str().unwrap().to_string())
            .filter(|key| key.starts_with(&prefix))
            .collect();
        assert_eq!(keys.len(), 2 + 3 + 4 + 4 + 5 + f["request"]["market_candles"].as_array().unwrap().len(), "{name}");
        for key in &keys {
            let key = hex::decode(key).unwrap();
            // Without the entry the proof is refused, though every other
            // entry is the engine's own.
            let mut copy = f.clone();
            let wanted = hex::encode(&key);
            copy["proof"]["entries"].as_array_mut().unwrap().retain(|entry| entry["key_hex"] != wanted.as_str());
            assert_eq!(refused(&copy), format!("missing requested proof for {wanted}"), "{name}");
            let mut copy = f.clone();
            let stored = entry_of(&mut copy, &key)["value_b64"].clone();
            match stored.as_str() {
                // "Absent" for a row that exists does not verify, and the
                // bytes under the key are the canonical JSON of the row.
                Some(stored) => {
                    let bytes = STANDARD.decode(stored).unwrap();
                    let row: Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(serde_json::to_vec(&row).unwrap(), bytes, "{name}");
                    entry_of(&mut copy, &key)["value_b64"] = Value::Null;
                    assert!(refused(&copy).contains("invalid key/value proof"), "{name}");
                }
                // A row claimed where the state holds none does not verify.
                None => {
                    entry_of(&mut copy, &key)["value_b64"] = json!(STANDARD.encode(b"{}"));
                    assert!(refused(&copy).contains("invalid key/value proof"), "{name}");
                }
            }
        }
        // Not asked for, the state says nothing of the market.
        let mut plain = f.clone();
        plain["request"] = json!({});
        assert!(check(&plain).unwrap()["state"].get("market").is_none(), "{name}");
    }
    let of = |name: &str| cases.iter().find(|(n, _)| n == name).unwrap().1["market"].clone();
    // A fill is not the same row from its making to its end: paid in part,
    // it holds what is still to pay (5,000 satoshis less the 2,000 paid).
    let fill = &of("trading")["fills"]["2"];
    assert_eq!((fill["amount_micros"].as_str(), fill["sats"].as_str(), fill["price"].as_str()), (Some("12000000"), Some("3000"), Some("250000000")));
    assert_eq!(of("trading")["fills"]["1"], Value::Null);
    assert_eq!(of("trading")["orders"]["1"]["key"].as_str().map(str::len), Some(64));
    assert_eq!(of("due")["fills"]["2"], of("trading")["fills"]["2"]);
    assert!(of("learnt")["heights"]["entries"].as_array().unwrap().len() > of("trading")["heights"]["entries"].as_array().unwrap().len());
    assert_eq!(of("no_market")["summary"], Value::Null);
    assert!(of("no_market")["orders"].as_object().unwrap().values().all(Value::is_null));
}

/// Writes the cases of the engine with their test headers for the
/// JavaScript tests: `fixtures/market-engine.json`.
#[test]
fn export_engine_market_fixture_when_requested() {
    if std::env::var("V4_EXPORT_MARKET_FIXTURE").as_deref() != Ok("1") {
        return;
    }
    let engine: Value = serde_json::from_str(ENGINE).unwrap();
    let cases: serde_json::Map<String, Value> = engine_cases().into_iter().collect();
    let value = json!({
        "note": "The proven rows of the market as the engine serves them (verifier-v4/fixtures/market-state.fixture.json, written by v5/tests/market.rs), each under a header signed by test validators that carries the application hash of the engine. Written by verifier-v4/src/market_tests.rs (V4_EXPORT_MARKET_FIXTURE=1).",
        "source_sha256": hex::encode(Sha256::digest(ENGINE.as_bytes())),
        "profile": engine["profile"],
        "accounts": engine["accounts"],
        "scripts": engine["scripts"],
        "candle_hours": engine["candle_hours"],
        "price": engine["price"],
        "cases": cases,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    std::fs::write(path.join("market-engine.json"), serde_json::to_vec(&value).unwrap()).unwrap();
}
