//! The rows of the market of seconds against bitcoin, as the version-5 engine
//! stores them (`spec/market.md`, section 4; `v5/src/market.rs`).
//!
//! A wallet reads these rows before a person pays bitcoin to an address: the
//! fill, the script it names, the satoshis, the confirmations, the starting
//! block. So each row is checked for its exact form here, and anything else
//! is refused: this build could not say what it means.
//!
//! - Every row is canonical JSON: its fields in alphabetical order, no
//!   spaces, every number a decimal string. The bytes are compared when the
//!   entry is authenticated (`view::authenticate_entries`); the fields are
//!   checked below.
//! - A row that carries its own id is refused under another key.
//! - The content is authenticated by the proof, and the engine is what
//!   enforces the rules of the market. The bounds checked here are those
//!   every row the engine writes has, in both profiles.
use crate::{decimal, view};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const PREFIX: &[u8] = b"market/";
pub const META_KEY: &[u8] = b"market/meta";
pub const HEIGHTS_KEY: &[u8] = b"market/heights";
const ORDER: &[u8] = b"market/order/";
const FILL: &[u8] = b"market/fill/";
const ACCOUNT: &[u8] = b"market/account/";
const SCRIPT: &[u8] = b"market/script/";
const CANDLE: &[u8] = b"market/candle/";

/// Most orders, most fills and most receiving scripts one selection names,
/// most accounts, and most candles: the node's bounds (`v5/src/app.rs`).
pub const MAX_ROWS: usize = 16;
pub const MAX_ACCOUNTS: usize = 8;
pub const MAX_CANDLES: usize = 32;

const PRICE_MAX: u64 = 1_000_000_000_000_000;
const SATS_MAX: u64 = 2_100_000_000_000_000;
const PRICE_SCALE: u128 = 1_000_000_000_000;
const PPM: u64 = 1_000_000;
const K_MAX: u64 = 100;
const N_MAX: u64 = 144;
const MAX_ORDERS: usize = 64;
const MAX_PAYER_FILLS: usize = 64;
const MAX_SCRIPTS: usize = 16;
const MAX_BUY_FILLS: u64 = 16;
const MAX_HEIGHT_ENTRIES: usize = 256;
/// The names of the five standard forms, as a buy order lists them.
const FORMS: [&str; 5] = ["p2pkh", "p2sh", "p2tr", "p2wpkh", "p2wsh"];

/// What a selection asks of the market.
pub struct Asked<'a> {
    pub summary: bool,
    pub orders: &'a [String],
    pub fills: &'a [String],
    pub accounts: &'a [String],
    pub scripts: &'a [String],
    pub candles: &'a [String],
}
impl Asked<'_> {
    pub fn within_budget(&self) -> bool {
        self.orders.len() <= MAX_ROWS
            && self.fills.len() <= MAX_ROWS
            && self.accounts.len() <= MAX_ACCOUNTS
            && self.scripts.len() <= MAX_ROWS
            && self.candles.len() <= MAX_CANDLES
    }
    fn anything(&self) -> bool {
        self.summary
            || !(self.orders.is_empty()
                && self.fills.is_empty()
                && self.accounts.is_empty()
                && self.scripts.is_empty()
                && self.candles.is_empty())
    }
}

/// Whether the network has the market: the setting `market` of its genesis,
/// which is part of the metadata row. It is written as `true` or left out.
pub fn setting(meta: &Value) -> Result<bool, String> {
    match meta["config"].get("market") {
        None => Ok(false),
        Some(Value::Bool(true)) => Ok(true),
        Some(_) => Err("unsupported market setting".into()),
    }
}
/// All the seconds the market holds: the field `market_micros` of the
/// metadata row, one more term of the supply rule. The field exists on a
/// network with the market and on no other.
pub fn held(meta: &Value) -> Result<u64, String> {
    match (setting(meta)?, meta.get("market_micros")) {
        (true, Some(total)) => decimal(total, "market total"),
        (false, None) => Ok(0),
        _ => Err("the market's total belongs to a network with the market, and to no other".into()),
    }
}

/// The fields of `row`: every one of `required`, any of `optional`, and no
/// other.
fn fields<'a>(
    row: &'a Value,
    required: &[&str],
    optional: &[&str],
    what: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = row.as_object().ok_or_else(|| format!("{what} is not an object"))?;
    if !required.iter().all(|field| object.contains_key(*field))
        || !object.keys().all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
    {
        return Err(format!("{what} has missing or unknown fields"));
    }
    Ok(object)
}
fn number(object: &Map<String, Value>, field: &str, what: &str) -> Result<u64, String> {
    decimal(&object[field], &format!("{what} {field}"))
}
/// A number the engine holds in 32 bits.
fn number32(object: &Map<String, Value>, field: &str, what: &str) -> Result<u64, String> {
    let value = number(object, field, what)?;
    if value > u64::from(u32::MAX) {
        return Err(format!("{what} {field} exceeds 32 bits"));
    }
    Ok(value)
}
fn hash(value: &Value, what: &str) -> Result<(), String> {
    if !value.as_str().is_some_and(|text| {
        text.len() == 64 && text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    }) {
        return Err(format!("{what} must be 64 lowercase hexadecimal characters"));
    }
    Ok(())
}
/// A receiving script: lowercase hexadecimal, one of the five standard forms
/// (`spec/market.md`, 5.1; `bitcoin_bridge::standard_script`).
pub fn script(text: &str) -> Result<Vec<u8>, String> {
    let refused = || "a receiving script is one of the five standard forms, in lowercase hexadecimal".to_string();
    if text.len() % 2 != 0 || !text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(refused());
    }
    let bytes = hex::decode(text).map_err(|_| refused())?;
    let standard = match bytes.as_slice() {
        [0x76, 0xa9, 0x14, rest @ ..] => rest.len() == 22 && rest[20..] == [0x88, 0xac],
        [0xa9, 0x14, rest @ ..] => rest.len() == 21 && rest[20] == 0x87,
        [0x00, 0x14, rest @ ..] => rest.len() == 20,
        [0x00, 0x20, rest @ ..] | [0x51, 0x20, rest @ ..] => rest.len() == 32,
        _ => false,
    };
    if !standard {
        return Err(refused());
    }
    Ok(bytes)
}
fn script_of(value: &Value) -> Result<&str, String> {
    let text = value.as_str().ok_or("a receiving script must be a string")?;
    script(text)?;
    Ok(text)
}
fn side(value: &Value) -> Result<bool, String> {
    match value.as_str() {
        Some("sell") => Ok(true),
        Some("buy") => Ok(false),
        _ => Err("the side of the market is sell or buy".into()),
    }
}
fn price(object: &Map<String, Value>, field: &str, what: &str) -> Result<u64, String> {
    let value = number(object, field, what)?;
    if !(1..=PRICE_MAX).contains(&value) {
        return Err(format!("{what} {field} is not a price"));
    }
    Ok(value)
}
/// `{"height":H,"time_micros":T}`: a block and its time.
fn moment(value: &Value, what: &str) -> Result<(), String> {
    let object = fields(value, &["height", "time_micros"], &[], what)?;
    number(object, "height", what)?;
    if number(object, "time_micros", what)? > i64::MAX as u64 {
        return Err(format!("{what} time exceeds the time a chain can count"));
    }
    Ok(())
}
/// What `amount` microseconds cost at `price`, in satoshis, rounded up
/// (`spec/market.md`, section 3).
pub fn sats(amount: u64, price: u64) -> Option<u64> {
    if !(1..=PRICE_MAX).contains(&price) {
        return None;
    }
    let value = (u128::from(amount) * u128::from(price)).div_ceil(PRICE_SCALE);
    (value <= u128::from(SATS_MAX)).then_some(value as u64)
}

/// `market/meta`.
pub fn summary(row: &Value) -> Result<(), String> {
    let what = "market summary";
    let object = fields(
        row,
        &["fills", "next_fill", "next_order", "orders", "sats", "seconds_micros", "trades"],
        &["last_price"],
        what,
    )?;
    // Ids start at 1, and the rows that exist were each given one.
    if number(object, "fills", what)? >= number(object, "next_fill", what)?
        || number(object, "orders", what)? >= number(object, "next_order", what)?
    {
        return Err("market summary counts more rows than it gave ids".into());
    }
    number(object, "sats", what)?;
    number(object, "seconds_micros", what)?;
    // The last price is written once a trade exists.
    let traded = number(object, "trades", what)? > 0;
    if object.contains_key("last_price") != traded {
        return Err("market summary has a last price exactly when it has a trade".into());
    }
    if traded {
        price(object, "last_price", what)?;
    }
    Ok(())
}

/// `market/heights`: when the chain learnt of Bitcoin heights.
pub fn heights(row: &Value) -> Result<(), String> {
    let what = "clock of heights";
    let entries = fields(row, &["entries"], &[], what)?["entries"]
        .as_array()
        .ok_or("invalid clock of heights")?;
    if entries.is_empty() || entries.len() > MAX_HEIGHT_ENTRIES {
        return Err("the clock of heights holds one to 256 entries".into());
    }
    let mut previous: Option<(u64, u64)> = None;
    for entry in entries {
        let object = fields(entry, &["at", "height"], &[], "entry of the clock of heights")?;
        let (at, height) = (number(object, "at", what)?, number32(object, "height", what)?);
        if previous.is_some_and(|(before, below)| before > at || below >= height) {
            return Err("the clock of heights does not rise in height and time".into());
        }
        previous = Some((at, height));
    }
    Ok(())
}

/// `market/order/<id>` (`spec/market.md`, 4.1).
pub fn order(row: &Value, id: u64) -> Result<(), String> {
    let what = "order";
    let common = [
        "amount_micros",
        "bond_micros",
        "confirmations",
        "created",
        "deposit_ppm",
        "id",
        "key",
        "min_deposit_micros",
        "min_sats",
        "open",
        "owner",
        "pay_blocks",
        "price",
        "side",
    ];
    let sell = side(row.get("side").ok_or("order has missing or unknown fields")?)?;
    let own: &[&str] = if sell { &["scripts"] } else { &["fills", "forms"] };
    let object = fields(row, &[&common[..], own].concat(), &[], what)?;
    if number(object, "id", what)? != id {
        return Err("order key mismatch".into());
    }
    let amount = number(object, "amount_micros", what)?;
    let bond = number(object, "bond_micros", what)?;
    moment(&object["created"], "order creation")?;
    // The public key that signed the order, or that last gave it scripts.
    hash(&object["key"], "the key of an order")?;
    let least_deposit = number(object, "min_deposit_micros", what)?;
    let open = object["open"].as_bool().ok_or("an order is open or it is not")?;
    number(object, "owner", what)?;
    price(object, "price", what)?;
    if !(1..=K_MAX).contains(&number32(object, "confirmations", what)?)
        || !(1..=N_MAX).contains(&number32(object, "pay_blocks", what)?)
        || number(object, "deposit_ppm", what)? > PPM
        || !(1..=SATS_MAX).contains(&number(object, "min_sats", what)?)
    {
        return Err("order bounds".into());
    }
    let open_fills = if sell {
        let slots = object["scripts"].as_array().ok_or("invalid order scripts")?;
        if bond != 0 || !(1..=MAX_SCRIPTS).contains(&slots.len()) {
            return Err("sell order shape".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut serving = 0u64;
        for slot in slots {
            let entry = fields(slot, &["script"], &["fill", "used"], "order script")?;
            if !seen.insert(script_of(&entry["script"])?) {
                return Err("an order lists a receiving script twice".into());
            }
            if entry.contains_key("fill") {
                number(entry, "fill", "order script")?;
                serving += 1;
            }
            // `used` is written as `true` or left out, and a script that
            // has served has no fill.
            if entry.get("used").is_some_and(|used| *used != json!(true) || entry.contains_key("fill")) {
                return Err("order script that has served".into());
            }
        }
        serving
    } else {
        let forms = object["forms"].as_array().ok_or("invalid order forms")?;
        let names = forms
            .iter()
            .map(|form| form.as_str().filter(|name| FORMS.contains(name)))
            .collect::<Option<Vec<_>>>()
            .ok_or("an order names a form of receiving script that does not exist")?;
        let fills = number(object, "fills", what)?;
        if least_deposit != 0 || fills > MAX_BUY_FILLS || names.is_empty() || names.windows(2).any(|w| w[0] >= w[1]) {
            return Err("buy order shape".into());
        }
        fills
    };
    if !open && (amount != 0 || bond != 0 || open_fills == 0) {
        return Err("a closed order offers nothing and has a fill".into());
    }
    Ok(())
}

/// `market/fill/<id>` (`spec/market.md`, 4.2).
pub fn fill(row: &Value, id: u64) -> Result<(), String> {
    let what = "fill";
    let object = fields(
        row,
        &[
            "amount_micros",
            "confirmations",
            "created",
            "deposit_micros",
            "id",
            "opened_micros",
            "order",
            "owner",
            "pay_blocks",
            "payer",
            "price",
            "sats",
            "script",
            "side",
            "start_hash",
            "start_height",
            "to",
        ],
        &[],
        what,
    )?;
    if number(object, "id", what)? != id {
        return Err("fill key mismatch".into());
    }
    let amount = number(object, "amount_micros", what)?;
    let confirmations = number32(object, "confirmations", what)?;
    let pay_blocks = number32(object, "pay_blocks", what)?;
    let start = number32(object, "start_height", what)?;
    moment(&object["created"], "fill creation")?;
    number(object, "deposit_micros", what)?;
    number(object, "opened_micros", what)?;
    number(object, "order", what)?;
    number(object, "owner", what)?;
    let payer = number(object, "payer", what)?;
    let to = number(object, "to", what)?;
    script_of(&object["script"])?;
    hash(&object["start_hash"], "the starting block of a fill")?;
    // The last height of a fill is a Bitcoin height: it fits 32 bits.
    if amount == 0
        || !(1..=K_MAX).contains(&confirmations)
        || !(1..=N_MAX).contains(&pay_blocks)
        || start + pay_blocks + confirmations - 1 > u64::from(u32::MAX)
    {
        return Err("fill bounds".into());
    }
    // What is still to pay: the price of the seconds when the fill is made,
    // by the one formula, less every payment of a part since. It is never
    // nothing, and never more than the price of what the fill still holds
    // (a part buys its seconds rounded down). A wallet shows a person this
    // number to pay.
    let still = number(object, "sats", what)?;
    if !sats(amount, price(object, "price", what)?).is_some_and(|most| (1..=most).contains(&still)) {
        return Err("the satoshis of a fill are none, or more than the price of its seconds".into());
    }
    // A fill against a buy order is paid by the order's owner, for itself.
    if !side(&object["side"])? && payer != to {
        return Err("a fill against a buy order gives its seconds to its payer".into());
    }
    Ok(())
}

/// `market/account/<id>`: the open orders an account owns and the open fills
/// it pays. No row when both are empty.
pub fn index(row: &Value) -> Result<(), String> {
    let what = "market index";
    let object = fields(row, &["fills", "orders"], &[], what)?;
    let mut total = 0;
    for (field, most) in [("fills", MAX_PAYER_FILLS), ("orders", MAX_ORDERS)] {
        let list = object[field].as_array().ok_or("invalid market index")?;
        let ids = list.iter().map(|id| decimal(id, "market index id")).collect::<Result<Vec<_>, _>>()?;
        if ids.len() > most || ids.windows(2).any(|w| w[0] >= w[1]) {
            return Err("a market index lists at most 64 ids, ascending, each once".into());
        }
        total += ids.len();
    }
    if total == 0 {
        return Err("empty market index".into());
    }
    Ok(())
}

/// `market/script/<SHA-256 of the script>`: `{"order":N}` for a script an
/// order lists, `{"fill":N}` for the script of an open fill against a buy
/// order, `{}` for a script that has served a fill.
pub fn script_use(row: &Value) -> Result<(), String> {
    let what = "script row";
    let object = fields(row, &[], &["fill", "order"], what)?;
    if object.len() > 1 {
        return Err("a script serves an order or a fill, not both".into());
    }
    for field in object.keys() {
        number(object, field, what)?;
    }
    Ok(())
}

/// `market/candle/<hour>`: one hour of proven trades.
pub fn candle(row: &Value) -> Result<(), String> {
    let what = "candle";
    let object = fields(row, &["close", "high", "low", "open", "sats", "seconds_micros", "trades"], &[], what)?;
    let (close, high, low, open) =
        (price(object, "close", what)?, price(object, "high", what)?, price(object, "low", what)?, price(object, "open", what)?);
    number(object, "sats", what)?;
    number(object, "seconds_micros", what)?;
    if number(object, "trades", what)? == 0 || low > open.min(close) || high < open.max(close) {
        return Err("candle bounds".into());
    }
    Ok(())
}

fn key(namespace: &[u8], id: u64) -> Vec<u8> {
    [namespace, &id.to_be_bytes()].concat()
}
pub fn script_key(script: &[u8]) -> Vec<u8> {
    [SCRIPT, Sha256::digest(script).as_slice()].concat()
}

/// What a verified state says of the market, for what was asked:
///
/// `{"summary":ROW|null,"heights":ROW|null,"orders":{ID:ROW|null,…},"fills":{…},"accounts":{…},"scripts":{SCRIPT:ROW|null,…},"candles":{HOUR:ROW|null,…}}`
///
/// - `summary` and `heights` are there only when the selection asked for
///   them (`include_market`); the five maps hold exactly what was named.
/// - `null` is a row proven absent. A proof without an entry for a key that
///   was asked is refused (`view::get`): a gateway that leaves an entry out
///   is never read as the absence of a row.
/// - On a network with the market the summary and the clock of heights
///   exist. On a network without it no row under `market/` does, and one
///   that is proven present is refused.
///
/// `None` when the selection asked nothing of the market.
pub fn rows(rows: &view::AuthenticatedRows, asked: &Asked, enabled: bool) -> Result<Option<Value>, String> {
    if !asked.anything() {
        return Ok(None);
    }
    let read = |key: &[u8]| -> Result<Option<&Value>, String> {
        let row = view::get(rows, key)?;
        if row.is_some() && !enabled {
            return Err("market rows belong to a network with the market".into());
        }
        Ok(row)
    };
    let mut market = Map::new();
    if asked.summary {
        for (field, key, check) in [
            ("summary", META_KEY, summary as fn(&Value) -> Result<(), String>),
            ("heights", HEIGHTS_KEY, heights),
        ] {
            let row = read(key)?;
            if row.is_none() && enabled {
                return Err("a network with the market holds its summary and its clock of heights".into());
            }
            if let Some(row) = row {
                check(row)?;
            }
            market.insert(field.into(), row.cloned().unwrap_or(Value::Null));
        }
    }
    let mut orders = Map::new();
    for id in asked.orders {
        let n = decimal(&json!(id), "order id")?;
        let row = read(&key(ORDER, n))?;
        if let Some(row) = row {
            order(row, n)?;
        }
        orders.insert(id.clone(), row.cloned().unwrap_or(Value::Null));
    }
    let mut fills = Map::new();
    for id in asked.fills {
        let n = decimal(&json!(id), "fill id")?;
        let row = read(&key(FILL, n))?;
        if let Some(row) = row {
            fill(row, n)?;
        }
        fills.insert(id.clone(), row.cloned().unwrap_or(Value::Null));
    }
    let mut accounts = Map::new();
    for id in asked.accounts {
        let n = decimal(&json!(id), "market account id")?;
        let row = read(&key(ACCOUNT, n))?;
        if let Some(row) = row {
            index(row)?;
        }
        accounts.insert(id.clone(), row.cloned().unwrap_or(Value::Null));
    }
    let mut scripts = Map::new();
    for text in asked.scripts {
        let row = read(&script_key(&script(text)?))?;
        if let Some(row) = row {
            script_use(row)?;
        }
        scripts.insert(text.clone(), row.cloned().unwrap_or(Value::Null));
    }
    let mut candles = Map::new();
    for hour in asked.candles {
        let n = decimal(&json!(hour), "candle hour")?;
        let row = read(&key(CANDLE, n))?;
        if let Some(row) = row {
            candle(row)?;
        }
        candles.insert(hour.clone(), row.cloned().unwrap_or(Value::Null));
    }
    for (field, map) in [("orders", orders), ("fills", fills), ("accounts", accounts), ("scripts", scripts), ("candles", candles)] {
        market.insert(field.into(), Value::Object(map));
    }
    Ok(Some(Value::Object(market)))
}
