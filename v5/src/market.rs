//! The market of seconds against bitcoin (`spec/market.md`).
//!
//! Nobody holds the bitcoin: it is paid on the Bitcoin network to an address
//! of the seller, and the chain gives the seconds of a trade to the buyer
//! when it has seen a proof of that payment (`bitcoin_bridge::verify_payment`
//! against the header chain of `crate::bitcoin_adapter`). The market holds
//! seconds only: what sell orders offer, the bonds of buy orders, and the
//! seconds and deposits of fills. Their sum is `Meta::market_micros`, one
//! term of the supply rule.
//!
//! Every row of this module lives under `market/`, on a network whose
//! genesis carries `market` and on no other. The engine checks the sender's
//! signature, nonce and spending key before `apply`; after it, it takes the
//! fee and counts against a secured sender's daily limit what left the
//! balance and what `apply` returns, as for every extension action. A
//! frozen sender is refused there whenever anything is counted.
use crate::engine::{ExtensionHost, Meta, canonical_decode};
use crate::wire::SignedAction;
use anyhow::{Result, anyhow, ensure};
use bitcoin_bridge::bitcoin::{BlockHash, OutPoint, hashes::Hash};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub const PREFIX: &[u8] = b"market/";
pub const META_KEY: &[u8] = b"market/meta";
pub const HEIGHTS_KEY: &[u8] = b"market/heights";

/// An order: seconds offered for bitcoin, or a promise to buy.
pub const ORDER: u8 = 50;
/// The owner takes back what an order still offers.
pub const CANCEL: u8 = 51;
/// A fill against a sell order: the sender promises the bitcoin.
pub const TAKE: u8 = 52;
/// A fill against a buy order: the sender locks the seconds.
pub const SELL: u8 = 53;
/// Proof of a Bitcoin payment to the script of a fill. Anyone may send it,
/// for a payment in full or of a part.
pub const PROOF: u8 = 54;
/// A fill that was not paid in time ends. Anyone may send it.
pub const EXPIRE: u8 = 55;
/// The account a fill's seconds go to gives the fill up.
pub const RELEASE: u8 = 56;
/// The owner of a fill's seconds hands them over without a proof.
pub const SETTLE: u8 = 57;
/// The owner of a sell order gives it new receiving scripts.
pub const ADDRESSES: u8 = 58;

pub fn is_kind(kind: u8) -> bool {
    (ORDER..=ADDRESSES).contains(&kind)
}

pub const PRICE_MAX: u64 = 1_000_000_000_000_000;
pub const SATS_MAX: u64 = 2_100_000_000_000_000;
/// A price is millionths of a satoshi for one second, and a second is a
/// million microseconds.
const PRICE_SCALE: u128 = 1_000_000_000_000;
const PPM: u64 = 1_000_000;
pub const K_MAX: u32 = 100;
pub const N_MAX: u32 = 144;
pub const MAX_ORDERS: usize = 64;
pub const MAX_PAYER_FILLS: usize = 64;
pub const MAX_SCRIPTS: usize = 16;
pub const MAX_BUY_FILLS: u64 = 16;
pub const MAX_HEIGHT_ENTRIES: usize = 256;
/// Blocks added to the time a fill is given before it can end unpaid
/// (`Fill::earliest_end`).
pub const SPARE_BLOCKS: u64 = 16;
/// A proof of payment pays the fee once more for each of these many bytes
/// of its payload.
pub const PROOF_BYTES_PER_FEE: u64 = 256;

/// The numbers that differ between the profiles (`spec/market.md`, 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub k_min: u32,
    /// The shortest time to pay, in Bitcoin blocks.
    pub n_min: u32,
    /// What one Bitcoin block is taken to last when the end of a fill is
    /// bounded in time (`spec/market.md`, 5.5).
    pub block_micros: u64,
    pub grace_micros: u64,
    pub bond_min_ppm: u64,
    pub min_sats: u64,
    pub hour_micros: u64,
}
impl Params {
    pub fn of(profile: pos::Profile) -> Self {
        match profile {
            pos::Profile::Production => Self {
                k_min: 3,
                n_min: 3,
                block_micros: 600 * pos::SECOND,
                grace_micros: 30 * 60 * pos::SECOND,
                bond_min_ppm: 30_000,
                min_sats: 1_000,
                hour_micros: 3_600 * pos::SECOND,
            },
            pos::Profile::Laboratory => Self {
                k_min: 1,
                n_min: 1,
                block_micros: pos::SECOND,
                grace_micros: 20 * pos::SECOND,
                bond_min_ppm: 0,
                min_sats: 1,
                hour_micros: 60 * pos::SECOND,
            },
        }
    }
}

/// What `amount` microseconds cost at `price`, in satoshis, rounded up.
pub fn sats(amount: u64, price: u64) -> Result<u64> {
    ensure!((1..=PRICE_MAX).contains(&price), "a price is from 1 to 10^15");
    let product = u128::from(amount) * u128::from(price);
    let value = product.div_ceil(PRICE_SCALE);
    ensure!(value <= u128::from(SATS_MAX), "more satoshis than exist");
    Ok(value as u64)
}
/// The microseconds `paid` satoshis buy at `price`, rounded down.
pub fn bought(paid: u64, price: u64) -> u64 {
    let value = u128::from(paid) * PRICE_SCALE / u128::from(price.max(1));
    u64::try_from(value).unwrap_or(u64::MAX)
}
/// `total × part / whole`, rounded down; `part` is at most `whole`.
fn share(total: u64, part: u64, whole: u64) -> Result<u64> {
    ensure!(whole > 0 && part <= whole, "share bounds");
    Ok((u128::from(total) * u128::from(part) / u128::from(whole)) as u64)
}
/// `amount × ppm / 10^6`, rounded up.
fn ppm_ceil(amount: u64, ppm: u64) -> Result<u64> {
    ensure!(ppm <= PPM, "a deposit is at most the whole");
    Ok((u128::from(amount) * u128::from(ppm)).div_ceil(u128::from(PPM)) as u64)
}

mod dec32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value: u32 = text.parse().map_err(serde::de::Error::custom)?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical number"));
        }
        Ok(value)
    }
}
mod opt64 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => pos::decimal::u64::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
        pos::decimal::u64::deserialize(deserializer).map(Some)
    }
}

/// A block: its height and its time in microseconds since the Unix epoch,
/// as the block's time row holds it. The market keeps its own type and
/// reads nothing of the service records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Moment {
    #[serde(with = "pos::decimal::u64")]
    pub height: u64,
    #[serde(with = "crate::engine::decimal::i64")]
    pub time_micros: i64,
}
impl Moment {
    pub fn of(meta: &Meta) -> Result<Self> {
        Ok(Self { height: u64::try_from(meta.height)?, time_micros: meta.time_micros })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Sell,
    Buy,
}

/// `market/meta`. The fields are in the order they are written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    #[serde(with = "pos::decimal::u64")]
    pub fills: u64,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt64")]
    pub last_price: Option<u64>,
    #[serde(with = "pos::decimal::u64")]
    pub next_fill: u64,
    #[serde(with = "pos::decimal::u64")]
    pub next_order: u64,
    #[serde(with = "pos::decimal::u64")]
    pub orders: u64,
    #[serde(with = "pos::decimal::u64")]
    pub sats: u64,
    #[serde(with = "pos::decimal::u64")]
    pub seconds_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub trades: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt64")]
    pub fill: Option<u64>,
    pub script: String,
    /// A fill has used the script and ended. A script serves one fill, ever.
    #[serde(default, skip_serializing_if = "is_false")]
    pub used: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
impl Slot {
    fn free(&self) -> bool {
        self.fill.is_none() && !self.used
    }
}

/// The names of the five standard forms, as a buy order lists them.
pub const FORMS: [&str; 5] = ["p2pkh", "p2sh", "p2tr", "p2wpkh", "p2wsh"];
/// The form of a standard receiving script.
pub fn form_of(script: &[u8]) -> Option<&'static str> {
    if !bitcoin_bridge::standard_script(script) {
        return None;
    }
    Some(match (script[0], script.len()) {
        (0x76, _) => "p2pkh",
        (0xa9, _) => "p2sh",
        (0x51, _) => "p2tr",
        (0x00, 22) => "p2wpkh",
        _ => "p2wsh",
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    #[serde(with = "pos::decimal::u64")]
    pub amount_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub bond_micros: u64,
    #[serde(with = "dec32")]
    pub confirmations: u32,
    pub created: Moment,
    #[serde(with = "pos::decimal::u64")]
    pub deposit_ppm: u64,
    /// A buy order: the number of its open fills.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt64")]
    pub fills: Option<u64>,
    /// A buy order: the forms of receiving script its owner can pay to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forms: Option<Vec<String>>,
    #[serde(with = "pos::decimal::u64")]
    pub id: u64,
    /// The public key that signed the order, or that last gave it new
    /// scripts. The order takes fills while that key is a spending key of
    /// its owner.
    pub key: String,
    /// A sell order: the least deposit of a fill, whatever its size.
    #[serde(with = "pos::decimal::u64")]
    pub min_deposit_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub min_sats: u64,
    pub open: bool,
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    #[serde(with = "dec32")]
    pub pay_blocks: u32,
    #[serde(with = "pos::decimal::u64")]
    pub price: u64,
    /// A sell order: its receiving scripts, in the owner's order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripts: Option<Vec<Slot>>,
    pub side: Side,
}
impl Order {
    fn open_fills(&self) -> u64 {
        match &self.scripts {
            Some(slots) => slots.iter().filter(|slot| slot.fill.is_some()).count() as u64,
            None => self.fills.unwrap_or(0),
        }
    }
    /// What the market holds for this order outside its fills.
    fn held(&self) -> u64 {
        match self.side {
            Side::Sell => self.amount_micros,
            Side::Buy => self.bond_micros,
        }
    }
    /// The bounds of an order that do not depend on the moment.
    fn validate(&self, params: &Params) -> Result<()> {
        ensure!((1..=PRICE_MAX).contains(&self.price), "order price");
        ensure!(
            self.key.len() == 64 && self.key.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "order key"
        );
        ensure!(
            (params.k_min..=K_MAX).contains(&self.confirmations)
                && (params.n_min..=N_MAX).contains(&self.pay_blocks)
                && self.deposit_ppm <= PPM
                && self.min_sats >= params.min_sats
                && self.min_sats <= SATS_MAX,
            "order bounds"
        );
        match self.side {
            Side::Sell => {
                let slots = self.scripts.as_ref().ok_or_else(|| anyhow!("a sell order lists its scripts"))?;
                ensure!(
                    self.fills.is_none()
                        && self.forms.is_none()
                        && self.bond_micros == 0
                        && (1..=MAX_SCRIPTS).contains(&slots.len())
                        && slots.iter().all(|slot| !(slot.used && slot.fill.is_some())),
                    "sell order shape"
                );
                let mut seen = std::collections::BTreeSet::new();
                for slot in slots {
                    ensure!(
                        standard(&slot.script).is_ok() && seen.insert(&slot.script),
                        "sell order script"
                    );
                }
            }
            Side::Buy => {
                ensure!(
                    self.scripts.is_none()
                        && self.min_deposit_micros == 0
                        && self.fills.is_some_and(|n| n <= MAX_BUY_FILLS)
                        && self.forms.as_ref().is_some_and(|forms| {
                            !forms.is_empty()
                                && forms.windows(2).all(|w| w[0] < w[1])
                                && forms.iter().all(|form| FORMS.contains(&form.as_str()))
                        })
                        && self.deposit_ppm >= params.bond_min_ppm,
                    "buy order shape"
                );
            }
        }
        ensure!(
            self.open || (self.amount_micros == 0 && self.bond_micros == 0 && self.open_fills() > 0),
            "a closed order offers nothing and has a fill"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fill {
    #[serde(with = "pos::decimal::u64")]
    pub amount_micros: u64,
    #[serde(with = "dec32")]
    pub confirmations: u32,
    pub created: Moment,
    #[serde(with = "pos::decimal::u64")]
    pub deposit_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub id: u64,
    /// The moment the fill was made, on the clock of the waits.
    #[serde(with = "pos::decimal::u64")]
    pub opened_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub order: u64,
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    #[serde(with = "dec32")]
    pub pay_blocks: u32,
    #[serde(with = "pos::decimal::u64")]
    pub payer: u64,
    #[serde(with = "pos::decimal::u64")]
    pub price: u64,
    #[serde(with = "pos::decimal::u64")]
    pub sats: u64,
    pub script: String,
    pub side: Side,
    /// The best Bitcoin block the chain knew when the action that made the
    /// fill was executed.
    pub start_hash: String,
    #[serde(with = "dec32")]
    pub start_height: u32,
    #[serde(with = "pos::decimal::u64")]
    pub to: u64,
}
impl Fill {
    /// The Bitcoin height at which a payment made in the last block of the
    /// time to pay has its confirmations.
    pub fn last_height(&self) -> Result<u32> {
        self.start_height
            .checked_add(self.pay_blocks)
            .and_then(|h| h.checked_add(self.confirmations))
            .and_then(|h| h.checked_sub(1))
            .ok_or_else(|| anyhow!("fill height overflow"))
    }
    /// The earliest moment the fill can end without payment, on the clock
    /// of the waits, whatever the chain has learnt of Bitcoin: the time to
    /// pay and to confirm at the pace Bitcoin is taken to have, and the
    /// grace.
    pub fn earliest_end(&self, params: &Params) -> Result<u64> {
        // The time to pay, twice the confirmations, and sixteen blocks: a new
        // fill may start as far behind Bitcoin as a fresh header chain can
        // be, blocks do not come evenly, and they come slower than one in
        // ten minutes whenever miners have left since the last retarget.
        u64::from(self.pay_blocks)
            .checked_add(u64::from(self.confirmations))
            .and_then(|blocks| blocks.checked_add(u64::from(self.confirmations)))
            .and_then(|blocks| blocks.checked_add(SPARE_BLOCKS))
            .and_then(|blocks| blocks.checked_mul(params.block_micros))
            .and_then(|span| span.checked_add(params.grace_micros))
            .and_then(|span| span.checked_add(self.opened_micros))
            .ok_or_else(|| anyhow!("fill time overflow"))
    }
}

/// `market/script/`: what a script serves: an order that lists it, or a
/// fill against a buy order. With neither field the script has served a
/// fill that ended; the row stays, and the script serves nothing again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptUse {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt64")]
    pub fill: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt64")]
    pub order: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paid {
    #[serde(with = "pos::decimal::u64")]
    pub fill: u64,
    #[serde(with = "dec32")]
    pub height: u32,
    #[serde(with = "pos::decimal::u64")]
    pub sats: u64,
}

/// `market/account/`: the open orders an account owns and the open fills
/// it pays, ascending.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    #[serde(with = "crate::engine::decimal::vec_u64")]
    pub fills: Vec<u64>,
    #[serde(with = "crate::engine::decimal::vec_u64")]
    pub orders: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeightEntry {
    #[serde(with = "pos::decimal::u64")]
    pub at: u64,
    #[serde(with = "dec32")]
    pub height: u32,
}
/// `market/heights`: when the chain learnt of Bitcoin heights, on the clock
/// of the waits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heights {
    pub entries: Vec<HeightEntry>,
}
impl Heights {
    /// The moment of the oldest entry whose height is at least `height`.
    pub fn known(&self, height: u32) -> Option<u64> {
        self.entries.iter().find(|entry| entry.height >= height).map(|entry| entry.at)
    }
    /// The chain's best height is `best` at the moment `now`. An entry is
    /// added when `best` is above every height recorded. When the best
    /// height has fallen (a chain of more work that is lower), the entries
    /// above it go: those heights are not known any more.
    pub fn learn(&mut self, best: u32, now: u64) {
        self.entries.retain(|entry| entry.height <= best);
        if self.entries.last().is_none_or(|newest| newest.height < best) {
            self.entries.push(HeightEntry { at: now, height: best });
        }
        if self.entries.len() > MAX_HEIGHT_ENTRIES {
            let extra = self.entries.len() - MAX_HEIGHT_ENTRIES;
            self.entries.drain(..extra);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candle {
    #[serde(with = "pos::decimal::u64")]
    pub close: u64,
    #[serde(with = "pos::decimal::u64")]
    pub high: u64,
    #[serde(with = "pos::decimal::u64")]
    pub low: u64,
    #[serde(with = "pos::decimal::u64")]
    pub open: u64,
    #[serde(with = "pos::decimal::u64")]
    pub sats: u64,
    #[serde(with = "pos::decimal::u64")]
    pub seconds_micros: u64,
    #[serde(with = "pos::decimal::u64")]
    pub trades: u64,
}

pub fn order_key(id: u64) -> Vec<u8> {
    [b"market/order/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn fill_key(id: u64) -> Vec<u8> {
    [b"market/fill/".as_slice(), &id.to_be_bytes()].concat()
}
pub fn script_key(script: &[u8]) -> Vec<u8> {
    [b"market/script/".as_slice(), Sha256::digest(script).as_slice()].concat()
}
pub fn paid_key(outpoint: &OutPoint) -> Vec<u8> {
    [
        b"market/paid/".as_slice(),
        outpoint.txid.as_byte_array(),
        &outpoint.vout.to_be_bytes(),
    ]
    .concat()
}
pub fn index_key(account: u64) -> Vec<u8> {
    [b"market/account/".as_slice(), &account.to_be_bytes()].concat()
}
pub fn candle_key(hour: u64) -> Vec<u8> {
    [b"market/candle/".as_slice(), &hour.to_be_bytes()].concat()
}

/// A receiving script in lowercase hexadecimal, of a standard form.
fn standard(text: &str) -> Result<Vec<u8>> {
    let script = hex::decode(text)?;
    ensure!(
        hex::encode(&script) == text && bitcoin_bridge::standard_script(&script),
        "a receiving script is one of the five standard forms, in lowercase hexadecimal"
    );
    Ok(script)
}
fn read<T: DeserializeOwned + Serialize>(host: &impl ExtensionHost, key: &[u8]) -> Result<Option<T>> {
    host.get(key)?.map(|raw| canonical_decode(&raw)).transpose()
}
fn write<T: Serialize>(host: &mut impl ExtensionHost, key: Vec<u8>, value: &T) -> Result<()> {
    host.put(key, Some(serde_json::to_vec(value)?))
}
fn summary(host: &impl ExtensionHost) -> Result<Summary> {
    read(host, META_KEY)?.ok_or_else(|| anyhow!("missing market state"))
}
fn total(host: &impl ExtensionHost) -> Result<u64> {
    host.meta().market_micros.ok_or_else(|| anyhow!("this network has no market"))
}
/// Seconds enter the market (they have left a balance in the same action).
fn hold(host: &mut impl ExtensionHost, amount: u64) -> Result<()> {
    let held = pos::add(total(host)?, amount)?;
    host.set_market(held)
}
/// Seconds leave the market to the balance of `account`.
fn pay_out(host: &mut impl ExtensionHost, account: u64, amount: u64) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let held = total(host)?.checked_sub(amount).ok_or_else(|| anyhow!("the market holds less than it pays out"))?;
    host.set_market(held)?;
    host.credit(account, amount)
}
fn index(host: &impl ExtensionHost, account: u64) -> Result<Index> {
    Ok(read(host, &index_key(account))?.unwrap_or_default())
}
fn save_index(host: &mut impl ExtensionHost, account: u64, row: &Index) -> Result<()> {
    if row.fills.is_empty() && row.orders.is_empty() {
        host.put(index_key(account), None)
    } else {
        write(host, index_key(account), row)
    }
}
fn insert_sorted(list: &mut Vec<u64>, id: u64) -> Result<()> {
    match list.binary_search(&id) {
        Ok(_) => anyhow::bail!("market index holds the id already"),
        Err(at) => list.insert(at, id),
    }
    Ok(())
}
fn remove_sorted(list: &mut Vec<u64>, id: u64) -> Result<()> {
    let at = list.binary_search(&id).map_err(|_| anyhow!("market index lacks the id"))?;
    list.remove(at);
    Ok(())
}
/// Whether `account` is frozen under the account security rules now.
fn frozen(host: &mut impl ExtensionHost, account: u64) -> Result<bool> {
    let row = host.account(account)?;
    let now = host.meta().active_micros()?;
    crate::security::frozen_at(|key| host.get(key), &row, now)
}

pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    if !host.meta().config.market {
        return Ok(());
    }
    write(
        host,
        META_KEY.to_vec(),
        &Summary {
            fills: 0,
            last_price: None,
            next_fill: 1,
            next_order: 1,
            orders: 0,
            sats: 0,
            seconds_micros: 0,
            trades: 0,
        },
    )?;
    let height = crate::bitcoin_adapter::get(host)?.meta.best_height;
    write(host, HEIGHTS_KEY.to_vec(), &Heights { entries: vec![HeightEntry { at: 0, height }] })
}

/// After a kind 40 action: the clock of heights learns the best height if
/// it is above every height it has recorded.
pub fn headers_applied(host: &mut impl ExtensionHost) -> Result<()> {
    if !host.meta().config.market {
        return Ok(());
    }
    let best = crate::bitcoin_adapter::get(host)?.meta.best_height;
    let before: Heights = read(host, HEIGHTS_KEY)?.ok_or_else(|| anyhow!("missing clock of heights"))?;
    let mut heights = before.clone();
    heights.learn(best, host.meta().active_micros()?);
    if heights == before {
        return Ok(());
    }
    write(host, HEIGHTS_KEY.to_vec(), &heights)
}

/// Applies one market action. Returns what the action hands to others out
/// of seconds the sender had put on offer before (a settle): the engine
/// counts it against the sender's daily limit beside what left the balance.
pub fn apply(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<u64> {
    ensure!(host.meta().config.market, "this network has no market");
    match action.kind {
        ORDER => order(host, action).map(|_| 0),
        CANCEL => cancel(host, action).map(|_| 0),
        TAKE => take(host, action).map(|_| 0),
        SELL => sell(host, action).map(|_| 0),
        PROOF => proof(host, action).map(|_| 0),
        ADDRESSES => addresses(host, action),
        EXPIRE => expire(host, action).map(|_| 0),
        RELEASE => release(host, action),
        SETTLE => settle(host, action),
        _ => Err(anyhow!("unsupported market action")),
    }
}

/// A list that is written is a list: `null` is not "absent".
fn listed<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(deserializer).map(Some)
}

fn order(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        #[serde(with = "pos::decimal::u64")]
        amount_micros: u64,
        #[serde(with = "dec32")]
        confirmations: u32,
        #[serde(with = "pos::decimal::u64")]
        deposit_ppm: u64,
        #[serde(default, deserialize_with = "listed")]
        forms: Option<Vec<String>>,
        #[serde(default, with = "opt64")]
        min_deposit_micros: Option<u64>,
        #[serde(with = "pos::decimal::u64")]
        min_sats: u64,
        #[serde(with = "dec32")]
        pay_blocks: u32,
        #[serde(with = "pos::decimal::u64")]
        price: u64,
        #[serde(default, deserialize_with = "listed")]
        scripts: Option<Vec<String>>,
        side: Side,
    }
    let p: Input = serde_json::from_value(action.payload.clone())?;
    let params = Params::of(host.meta().config.profile);
    ensure!(p.amount_micros >= 1, "an order offers at least a microsecond");
    let value = sats(p.amount_micros, p.price)?;
    ensure!(
        value >= p.min_sats && p.min_sats >= params.min_sats,
        "an order is worth at least its smallest trade, and that at least the network's"
    );
    let mut state = summary(host)?;
    let id = state.next_order;
    let mut mine = index(host, action.from)?;
    ensure!(mine.orders.len() < MAX_ORDERS, "too many open orders");
    ensure!(
        p.scripts.as_ref().is_none_or(|list| list.len() <= MAX_SCRIPTS),
        "a sell order lists at most sixteen receiving scripts"
    );
    let (held, bond, fills, scripts, forms, min_deposit) = match p.side {
        Side::Sell => {
            ensure!(p.forms.is_none(), "a sell order lists scripts, not forms");
            let min_deposit = p
                .min_deposit_micros
                .ok_or_else(|| anyhow!("a sell order names the least deposit of a fill"))?;
            ensure!(min_deposit <= p.amount_micros, "the least deposit is at most what is on offer");
            let list = p.scripts.ok_or_else(|| anyhow!("a sell order lists its receiving scripts"))?;
            let mut slots = Vec::with_capacity(list.len());
            for text in list {
                let script = standard(&text)?;
                let key = script_key(&script);
                ensure!(host.get(&key)?.is_none(), "a receiving script serves one order or fill, once");
                write(host, key, &ScriptUse { fill: None, order: Some(id) })?;
                slots.push(Slot { fill: None, script: text, used: false });
            }
            (p.amount_micros, 0, None, Some(slots), None, min_deposit)
        }
        Side::Buy => {
            ensure!(
                p.scripts.is_none() && p.min_deposit_micros.is_none(),
                "a buy order lists no script and names no least deposit"
            );
            let forms = p.forms.ok_or_else(|| anyhow!("a buy order lists the forms of script it pays to"))?;
            let bond = ppm_ceil(p.amount_micros, p.deposit_ppm)?;
            (bond, bond, Some(0), None, Some(forms), 0)
        }
    };
    let row = Order {
        amount_micros: p.amount_micros,
        bond_micros: bond,
        confirmations: p.confirmations,
        created: Moment::of(host.meta())?,
        deposit_ppm: p.deposit_ppm,
        fills,
        forms,
        id,
        key: action.public_key.clone(),
        min_deposit_micros: min_deposit,
        min_sats: p.min_sats,
        open: true,
        owner: action.from,
        pay_blocks: p.pay_blocks,
        price: p.price,
        scripts,
        side: p.side,
    };
    // Two scripts of one order with the same bytes: the second found the
    // row the first wrote. `validate` repeats the bound for the recount.
    row.validate(&params)?;
    host.debit(action.from, held)?;
    hold(host, held)?;
    write(host, order_key(id), &row)?;
    insert_sorted(&mut mine.orders, id)?;
    save_index(host, action.from, &mine)?;
    state.next_order = pos::add(id, 1)?;
    state.orders = pos::add(state.orders, 1)?;
    write(host, META_KEY.to_vec(), &state)?;
    // A row is written for every script: the fee once more for each.
    surcharge(host, action.from, row.scripts.as_ref().map_or(0, |slots| slots.len() as u64))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Named {
    #[serde(default, with = "opt64")]
    order: Option<u64>,
    #[serde(default, with = "opt64")]
    fill: Option<u64>,
}
fn named_order(action: &SignedAction) -> Result<u64> {
    let p: Named = serde_json::from_value(action.payload.clone())?;
    ensure!(p.fill.is_none(), "this action names an order");
    p.order.ok_or_else(|| anyhow!("this action names an order"))
}
fn named_fill(action: &SignedAction) -> Result<u64> {
    let p: Named = serde_json::from_value(action.payload.clone())?;
    ensure!(p.order.is_none(), "this action names a fill");
    p.fill.ok_or_else(|| anyhow!("this action names a fill"))
}

/// Removes an order that has ended: its row, its script rows, its place in
/// its owner's index.
fn drop_order(host: &mut impl ExtensionHost, state: &mut Summary, row: &Order) -> Result<()> {
    ensure!(row.held() == 0 && row.open_fills() == 0, "an order that goes holds nothing");
    if let Some(slots) = &row.scripts {
        for slot in slots {
            // A script that served a fill keeps its row, empty, for ever
            // (`end_fill` wrote it).
            if !slot.used {
                host.put(script_key(&hex::decode(&slot.script)?), None)?;
            }
        }
    }
    host.put(order_key(row.id), None)?;
    let mut owner = index(host, row.owner)?;
    remove_sorted(&mut owner.orders, row.id)?;
    save_index(host, row.owner, &owner)?;
    state.orders = state.orders.checked_sub(1).ok_or_else(|| anyhow!("order count underflow"))?;
    Ok(())
}

fn cancel(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    let id = named_order(action)?;
    let mut row: Order = read(host, &order_key(id))?.ok_or_else(|| anyhow!("no such order"))?;
    ensure!(row.owner == action.from && row.open, "only its owner cancels an open order");
    let back = row.held();
    row.amount_micros = 0;
    row.bond_micros = 0;
    pay_out(host, row.owner, back)?;
    let mut state = summary(host)?;
    if row.open_fills() == 0 {
        drop_order(host, &mut state, &row)?;
    } else {
        row.open = false;
        write(host, order_key(id), &row)?;
    }
    write(host, META_KEY.to_vec(), &state)
}

/// What a new fill needs of the Bitcoin side: a network that is open to
/// the market, and a header chain that is fresh. Returns its best block.
fn bitcoin_ready(host: &impl ExtensionHost) -> Result<(u32, String)> {
    let (height, hash) = crate::bitcoin_adapter::fresh(host)?;
    Ok((height, hash.to_string()))
}
/// An order takes a new fill while its owner is not frozen and the key that
/// made the order (or last gave it scripts) is still one of the owner's
/// spending keys. A key that was stolen and then removed takes its orders
/// with it; adding a key, or changing a sign-in or recovery key, stops
/// nothing.
fn owner_stands(host: &mut impl ExtensionHost, row: &Order) -> Result<()> {
    ensure!(!frozen(host, row.owner)?, "the owner of this order is frozen");
    let owner = host.account(row.owner)?;
    ensure!(
        owner.devices.iter().any(|device| device.can_spend && device.public_key == row.key),
        "the key that made this order is no longer a spending key of its owner: it takes no new fill"
    );
    Ok(())
}
/// An action that writes more rows than a payment, or takes more room in a
/// block, pays the fee `times` more.
fn surcharge(host: &mut impl ExtensionHost, account: u64, times: u64) -> Result<()> {
    if times == 0 {
        return Ok(());
    }
    let extra = host.meta().config.fee().checked_mul(times).ok_or_else(|| anyhow!("fee overflow"))?;
    host.debit(account, extra)?;
    host.fee_credit(extra)
}
/// The satoshis of a new fill of `amount` against `row`, and what it leaves
/// on offer.
fn fill_size(row: &Order, amount: u64, named: u64, params: &Params) -> Result<(u64, u64)> {
    ensure!(
        (1..=row.amount_micros).contains(&amount),
        "a fill takes at least a microsecond and at most what is on offer"
    );
    let value = sats(amount, row.price)?;
    ensure!(value == named, "the satoshis named are the price of the amount");
    let left = row.amount_micros - amount;
    // All that is on offer can always be taken, so that a rest smaller
    // than the order's smallest trade is not stuck.
    ensure!(
        value >= row.min_sats || (left == 0 && value >= params.min_sats),
        "a fill is at least the order's smallest trade, or all that is on offer"
    );
    ensure!(
        left == 0 || sats(left, row.price)? >= row.min_sats,
        "a fill leaves nothing on offer, or at least the order's smallest trade"
    );
    Ok((value, left))
}

fn take(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        #[serde(with = "pos::decimal::u64")]
        amount_micros: u64,
        #[serde(with = "pos::decimal::u64")]
        order: u64,
        #[serde(with = "pos::decimal::u64")]
        sats: u64,
        #[serde(with = "pos::decimal::u64")]
        to: u64,
    }
    let p: Input = serde_json::from_value(action.payload.clone())?;
    let params = Params::of(host.meta().config.profile);
    let (start_height, start_hash) = bitcoin_ready(host)?;
    let mut row: Order = read(host, &order_key(p.order))?.ok_or_else(|| anyhow!("no such order"))?;
    ensure!(row.side == Side::Sell && row.open, "not an open sell order");
    owner_stands(host, &row)?;
    let (value, left) = fill_size(&row, p.amount_micros, p.sats, &params)?;
    let _ = host.account(p.to)?;
    let mut state = summary(host)?;
    let id = state.next_fill;
    let slots = row.scripts.as_mut().ok_or_else(|| anyhow!("sell order without scripts"))?;
    let slot = slots
        .iter_mut()
        .find(|slot| slot.free())
        .ok_or_else(|| anyhow!("every receiving script of this order serves a fill or has served one"))?;
    slot.fill = Some(id);
    let script = slot.script.clone();
    let mut payer = index(host, action.from)?;
    ensure!(payer.fills.len() < MAX_PAYER_FILLS, "too many open fills to pay");
    let deposit = ppm_ceil(p.amount_micros, row.deposit_ppm)?.max(row.min_deposit_micros);
    host.debit(action.from, deposit)?;
    hold(host, deposit)?;
    row.amount_micros = left;
    let fill = Fill {
        amount_micros: p.amount_micros,
        confirmations: row.confirmations,
        created: Moment::of(host.meta())?,
        deposit_micros: deposit,
        id,
        opened_micros: host.meta().active_micros()?,
        order: row.id,
        owner: row.owner,
        pay_blocks: row.pay_blocks,
        payer: action.from,
        price: row.price,
        sats: value,
        script,
        side: Side::Sell,
        start_hash,
        start_height,
        to: p.to,
    };
    fill.last_height()?;
    write(host, fill_key(id), &fill)?;
    write(host, order_key(row.id), &row)?;
    insert_sorted(&mut payer.fills, id)?;
    save_index(host, action.from, &payer)?;
    state.next_fill = pos::add(id, 1)?;
    state.fills = pos::add(state.fills, 1)?;
    write(host, META_KEY.to_vec(), &state)
}

fn sell(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        #[serde(with = "pos::decimal::u64")]
        amount_micros: u64,
        #[serde(with = "dec32")]
        confirmations: u32,
        #[serde(with = "pos::decimal::u64")]
        order: u64,
        #[serde(with = "pos::decimal::u64")]
        sats: u64,
        script: String,
    }
    let p: Input = serde_json::from_value(action.payload.clone())?;
    let params = Params::of(host.meta().config.profile);
    let (start_height, start_hash) = bitcoin_ready(host)?;
    let mut row: Order = read(host, &order_key(p.order))?.ok_or_else(|| anyhow!("no such order"))?;
    ensure!(row.side == Side::Buy && row.open, "not an open buy order");
    owner_stands(host, &row)?;
    let (value, left) = fill_size(&row, p.amount_micros, p.sats, &params)?;
    ensure!(
        (params.k_min..=row.confirmations).contains(&p.confirmations),
        "the confirmations asked are at least the network's fewest and at most what the buyer waits for"
    );
    let script = standard(&p.script)?;
    let form = form_of(&script).ok_or_else(|| anyhow!("receiving script form"))?;
    ensure!(
        row.forms.as_ref().is_some_and(|forms| forms.iter().any(|name| name == form)),
        "the buyer does not pay to this form of receiving script"
    );
    let key = script_key(&script);
    ensure!(host.get(&key)?.is_none(), "a receiving script serves one order or fill, once");
    let open = row.fills.ok_or_else(|| anyhow!("buy order without a fill count"))?;
    ensure!(open < MAX_BUY_FILLS, "this buy order has as many open fills as it can have");
    let mut payer = index(host, row.owner)?;
    ensure!(payer.fills.len() < MAX_PAYER_FILLS, "the buyer has too many open fills to pay");
    let mut state = summary(host)?;
    let id = state.next_fill;
    let deposit = if left == 0 {
        row.bond_micros
    } else {
        share(row.bond_micros, p.amount_micros, row.amount_micros)?
    };
    host.debit(action.from, p.amount_micros)?;
    hold(host, p.amount_micros)?;
    row.bond_micros -= deposit;
    row.amount_micros = left;
    row.fills = Some(open + 1);
    let fill = Fill {
        amount_micros: p.amount_micros,
        confirmations: p.confirmations,
        created: Moment::of(host.meta())?,
        deposit_micros: deposit,
        id,
        opened_micros: host.meta().active_micros()?,
        order: row.id,
        owner: action.from,
        pay_blocks: row.pay_blocks,
        payer: row.owner,
        price: row.price,
        sats: value,
        script: p.script,
        side: Side::Buy,
        start_hash,
        start_height,
        to: row.owner,
    };
    fill.last_height()?;
    write(host, key, &ScriptUse { fill: Some(id), order: None })?;
    write(host, fill_key(id), &fill)?;
    write(host, order_key(row.id), &row)?;
    insert_sorted(&mut payer.fills, id)?;
    save_index(host, row.owner, &payer)?;
    state.next_fill = pos::add(id, 1)?;
    state.fills = pos::add(state.fills, 1)?;
    write(host, META_KEY.to_vec(), &state)
}

/// Ends a fill: `bought` of its seconds go to `to`, the rest goes back;
/// `deposit_back` of its deposit goes to the payer, the rest to the owner.
fn end_fill(
    host: &mut impl ExtensionHost,
    state: &mut Summary,
    fill: &Fill,
    bought: u64,
    deposit_back: u64,
) -> Result<()> {
    ensure!(
        bought <= fill.amount_micros && deposit_back <= fill.deposit_micros,
        "a fill gives at most what it holds"
    );
    let rest = fill.amount_micros - bought;
    let mut order: Order =
        read(host, &order_key(fill.order))?.ok_or_else(|| anyhow!("a fill names an order that exists"))?;
    pay_out(host, fill.to, bought)?;
    if fill.side == Side::Sell && order.open {
        // Back on offer: the seconds stay in the market.
        order.amount_micros = pos::add(order.amount_micros, rest)?;
    } else {
        pay_out(host, fill.owner, rest)?;
    }
    pay_out(host, fill.payer, deposit_back)?;
    pay_out(host, fill.owner, fill.deposit_micros - deposit_back)?;
    match fill.side {
        Side::Sell => {
            let slot = order
                .scripts
                .as_mut()
                .and_then(|slots| slots.iter_mut().find(|slot| slot.fill == Some(fill.id)))
                .ok_or_else(|| anyhow!("no script of the order serves this fill"))?;
            ensure!(slot.script == fill.script, "the order's script is the fill's");
            slot.fill = None;
            slot.used = true;
        }
        Side::Buy => {
            order.fills = Some(
                order
                    .fills
                    .and_then(|n| n.checked_sub(1))
                    .ok_or_else(|| anyhow!("buy order fill count underflow"))?,
            );
        }
    }
    // The script has served its fill: its row stays, empty, for ever.
    write(host, script_key(&hex::decode(&fill.script)?), &ScriptUse { fill: None, order: None })?;
    host.put(fill_key(fill.id), None)?;
    let mut payer = index(host, fill.payer)?;
    remove_sorted(&mut payer.fills, fill.id)?;
    save_index(host, fill.payer, &payer)?;
    state.fills = state.fills.checked_sub(1).ok_or_else(|| anyhow!("fill count underflow"))?;
    // A closed order goes with its last fill, and so does an order with
    // nothing left on offer.
    if order.open_fills() == 0 && (!order.open || order.amount_micros == 0) {
        let left = order.held();
        if left > 0 {
            // A buy order whose amount is used up keeps no bond; this is
            // the rounding of nothing, written for the recount's sake.
            order.bond_micros = 0;
            order.amount_micros = 0;
            pay_out(host, order.owner, left)?;
        }
        drop_order(host, state, &order)
    } else {
        write(host, order_key(order.id), &order)
    }
}

fn open_fill(host: &impl ExtensionHost, id: u64) -> Result<Fill> {
    read(host, &fill_key(id))?.ok_or_else(|| anyhow!("no such fill"))
}

fn proof(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        block_hash: String,
        coinbase: String,
        #[serde(with = "pos::decimal::u64")]
        fill: u64,
        merkle_proof: String,
        transaction: String,
        #[serde(with = "dec32")]
        vout: u32,
    }
    let p: Input = serde_json::from_value(action.payload.clone())?;
    let fill = open_fill(host, p.fill)?;
    ensure!(
        !p.transaction.is_empty()
            && p.transaction.len() <= bitcoin_bridge::MAX_PAYMENT_TX_BYTES * 2
            && !p.coinbase.is_empty()
            && p.coinbase.len() <= bitcoin_bridge::MAX_COINBASE_TX_BYTES * 2
            && p.merkle_proof.len() <= bitcoin_bridge::MAX_MERKLE_PROOF_BYTES * 2,
        "payment transaction/proof exceeds the supported budget"
    );
    let block_hash = BlockHash::from_str(&p.block_hash)?;
    ensure!(block_hash.to_string() == p.block_hash, "noncanonical Bitcoin block hash");
    let transaction = hex::decode(&p.transaction)?;
    let coinbase = hex::decode(&p.coinbase)?;
    let merkle_proof = hex::decode(&p.merkle_proof)?;
    ensure!(
        hex::encode(&transaction) == p.transaction
            && hex::encode(&coinbase) == p.coinbase
            && hex::encode(&merkle_proof) == p.merkle_proof,
        "noncanonical payment hexadecimal"
    );
    let evidence = bitcoin_bridge::PaymentProof { block_hash, transaction, vout: p.vout, coinbase, merkle_proof };
    let script = hex::decode(&fill.script)?;
    // What the proof says by itself decides every refusal that needs no
    // header: a refused proof costs its sender nothing, so the checks that
    // read the header chain come last.
    let claim = bitcoin_bridge::claimed_payment(&evidence, &script)?;
    let key = paid_key(&claim.outpoint);
    ensure!(host.get(&key)?.is_none(), "this Bitcoin output has paid for a fill already");
    let params = Params::of(host.meta().config.profile);
    // A payment of a part is no smaller than the order's own smallest
    // trade: a buyer does not pay a seller in dust the seller cannot spend.
    let order: Order =
        read(host, &order_key(fill.order))?.ok_or_else(|| anyhow!("a fill names an order that exists"))?;
    // Half of what is still to pay always counts, so that a payment which
    // came a little short (an exchange kept its fee) is not lost on a fill
    // no larger than the smallest trade; the rest is then at least half of
    // itself, and so on: a fill takes a handful of small outputs at most.
    ensure!(
        claim.sats >= fill.sats || claim.sats >= order.min_sats || u128::from(claim.sats) * 2 >= u128::from(fill.sats),
        "a payment of a part is at least the order's smallest trade, or half of what the fill still needs"
    );
    // The fill says what is still to pay. A payment of all of it buys all
    // the fill holds; a payment of a part buys the same part of it,
    // rounded down, and leaves the rest to pay to the satoshi.
    let full = claim.sats >= fill.sats;
    let seconds = if full { fill.amount_micros } else { share(fill.amount_micros, claim.sats, fill.sats)? };
    ensure!(seconds >= 1, "the payment buys less than a microsecond");
    let deposit_back = if full { fill.deposit_micros } else { share(fill.deposit_micros, seconds, fill.amount_micros)? };
    // A proof pays for the room it takes in a block: the fee once more for
    // every 256 bytes of its payload, the price of that room in ordinary
    // actions. Before any header is read, the sender must be able to pay
    // it, with what this proof brings them: a proof that is refused costs
    // nothing, and must cost validators nothing either.
    let payload = action.raw_signing_bytes.len().saturating_sub(crate::wire::HEADER) as u64;
    let extra = payload / PROOF_BYTES_PER_FEE;
    let cost = host
        .meta()
        .config
        .fee()
        .checked_mul(extra.checked_add(1).ok_or_else(|| anyhow!("fee overflow"))?)
        .ok_or_else(|| anyhow!("fee overflow"))?;
    let mut brings = 0u64;
    if action.from == fill.to {
        brings = pos::add(brings, seconds)?;
    }
    if action.from == fill.payer {
        brings = pos::add(brings, deposit_back)?;
    }
    ensure!(
        pos::add(host.account(action.from)?.balance, brings)? >= cost,
        "the sender cannot pay the fee of this proof"
    );
    // A frozen sender who would pay more than the proof brings is refused
    // by the engine after this function; refuse it here, before any header
    // is read.
    ensure!(
        brings >= cost || !frozen(host, action.from)?,
        "a frozen account sends no proof that costs it more than it brings"
    );
    let payment = crate::bitcoin_adapter::payment(
        host,
        &evidence,
        &script,
        fill.start_height,
        &BlockHash::from_str(&fill.start_hash)?,
        fill.confirmations,
    )?;
    ensure!(
        payment.outpoint == claim.outpoint && payment.sats == claim.sats,
        "the payment verified is the payment claimed"
    );
    let counted = payment.sats.min(fill.sats);
    write(host, key, &Paid { fill: fill.id, height: payment.block_height, sats: payment.sats })?;
    let mut state = summary(host)?;
    if full {
        // Paid in full: the fill ends, and the whole deposit goes back.
        end_fill(host, &mut state, &fill, seconds, deposit_back)?;
    } else {
        // A part: its seconds go to `to`, its share of the deposit goes
        // back to the payer, and the fill goes on, smaller, until the rest
        // is paid or its time has passed. A payment of a part ends
        // nothing, so anyone may prove one.
        pay_out(host, fill.to, seconds)?;
        pay_out(host, fill.payer, deposit_back)?;
        let mut rest = fill.clone();
        rest.amount_micros -= seconds;
        rest.deposit_micros -= deposit_back;
        rest.sats -= claim.sats;
        ensure!(rest.amount_micros >= 1 && rest.sats >= 1, "a fill paid in part still holds seconds to pay for");
        write(host, fill_key(rest.id), &rest)?;
    }
    // The trade is counted (`spec/market.md`, section 9).
    let hour = host.meta().elapsed_micros()? / params.hour_micros;
    let mut candle: Candle = read(host, &candle_key(hour))?.unwrap_or(Candle {
        close: fill.price,
        high: fill.price,
        low: fill.price,
        open: fill.price,
        sats: 0,
        seconds_micros: 0,
        trades: 0,
    });
    candle.close = fill.price;
    candle.high = candle.high.max(fill.price);
    candle.low = candle.low.min(fill.price);
    // No rule reads these numbers: they stop at the largest a row can
    // hold rather than refuse a proof.
    candle.sats = candle.sats.saturating_add(counted);
    candle.seconds_micros = candle.seconds_micros.saturating_add(seconds);
    candle.trades = candle.trades.saturating_add(1);
    write(host, candle_key(hour), &candle)?;
    state.last_price = Some(fill.price);
    state.sats = state.sats.saturating_add(counted);
    state.seconds_micros = state.seconds_micros.saturating_add(seconds);
    state.trades = state.trades.saturating_add(1);
    write(host, META_KEY.to_vec(), &state)?;
    // The fee for the proof's size, taken last, so that an account which
    // held nothing can pay it out of the seconds it has just bought.
    surcharge(host, action.from, extra)
}

fn expire(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    let fill = open_fill(host, named_fill(action)?)?;
    ensure!(
        !crate::bitcoin_adapter::halted(host)?,
        "the Bitcoin header chain is halted: a fill ends by a release or by its owner's settle"
    );
    let heights: Heights = read(host, HEIGHTS_KEY)?.ok_or_else(|| anyhow!("missing clock of heights"))?;
    let last = fill.last_height()?;
    let known = heights
        .known(last)
        .filter(|_| crate::bitcoin_adapter::get(host).is_ok_and(|chain| chain.meta.best_height >= last))
        .ok_or_else(|| anyhow!("the chain has not learnt the last height of this fill"))?;
    let params = Params::of(host.meta().config.profile);
    let now = host.meta().active_micros()?;
    ensure!(
        known.checked_add(params.grace_micros).is_some_and(|end| end <= now),
        "a fill ends after the time in which a proof of a payment made in time is accepted"
    );
    // However fast the chain learnt of Bitcoin (a relay that was behind
    // hands in many headers at once), the payer has had the time to pay.
    ensure!(
        fill.earliest_end(&params)? <= now,
        "a fill ends after its time to pay and to confirm, counted from when it was made"
    );
    let mut state = summary(host)?;
    end_fill(host, &mut state, &fill, 0, 0)?;
    write(host, META_KEY.to_vec(), &state)
}

fn release(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<u64> {
    let fill = open_fill(host, named_fill(action)?)?;
    // The account the seconds go to gives the fill up. For a fill someone
    // made for another account that is the other account, not the payer:
    // whoever made the fill cannot end it while the bitcoin is on its way.
    ensure!(fill.to == action.from, "only the account its seconds go to releases a fill");
    let mut state = summary(host)?;
    end_fill(host, &mut state, &fill, 0, 0)?;
    write(host, META_KEY.to_vec(), &state)?;
    // What the sender gives up counts against the daily limit like a
    // payment: the seconds the fill would have brought, and the deposit if
    // the sender locked it. Someone who holds a stolen spending key could
    // otherwise end the owner's purchase while the owner's bitcoin is on
    // its way to an accomplice who sold with no deposit.
    let deposit = if action.from == fill.payer { fill.deposit_micros } else { 0 };
    // On a halted header chain nothing can be proven and nothing expires:
    // a release is then the only way a buyer can end a fill, and it counts
    // the deposit alone, so that an account with a daily limit is not held
    // in a purchase that cannot complete.
    if crate::bitcoin_adapter::halted(host)? {
        return Ok(deposit);
    }
    pos::add(fill.amount_micros, deposit)
}

fn settle(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<u64> {
    let fill = open_fill(host, named_fill(action)?)?;
    ensure!(fill.owner == action.from, "only the owner of its seconds settles a fill");
    let mut state = summary(host)?;
    end_fill(host, &mut state, &fill, fill.amount_micros, fill.deposit_micros)?;
    write(host, META_KEY.to_vec(), &state)?;
    Ok(fill.amount_micros)
}

/// Kind 58: the owner of an open sell order gives it new receiving
/// scripts. The scripts that have served leave the order's list (their
/// rows stay); the new ones join it. No seconds move, and yet the action
/// counts against the daily limit like a new order: new scripts decide
/// where the bitcoin for the order's seconds is paid, so someone with a
/// stolen spending key could otherwise point an order of any size at an
/// address of their own. Returns what counts: the seconds on offer and
/// those in the order's open fills.
fn addresses(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<u64> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        #[serde(with = "pos::decimal::u64")]
        order: u64,
        scripts: Vec<String>,
    }
    let p: Input = serde_json::from_value(action.payload.clone())?;
    ensure!((1..=MAX_SCRIPTS).contains(&p.scripts.len()), "one to sixteen new receiving scripts");
    let added = p.scripts.len() as u64;
    let mut row: Order = read(host, &order_key(p.order))?.ok_or_else(|| anyhow!("no such order"))?;
    ensure!(
        row.owner == action.from && row.open && row.side == Side::Sell,
        "only its owner gives an open sell order new receiving scripts"
    );
    let mut counted = row.amount_micros;
    let slots = row.scripts.as_mut().ok_or_else(|| anyhow!("sell order without scripts"))?;
    for id in slots.iter().filter_map(|slot| slot.fill) {
        counted = pos::add(counted, open_fill(host, id)?.amount_micros)?;
    }
    slots.retain(|slot| !slot.used);
    for text in p.scripts {
        let script = standard(&text)?;
        let key = script_key(&script);
        ensure!(host.get(&key)?.is_none(), "a receiving script serves one order or fill, once");
        write(host, key, &ScriptUse { fill: None, order: Some(row.id) })?;
        slots.push(Slot { fill: None, script: text, used: false });
    }
    ensure!(slots.len() <= MAX_SCRIPTS, "an order has at most sixteen receiving scripts that have not served");
    // The order now answers for the key that made this change.
    row.key = action.public_key.clone();
    row.validate(&Params::of(host.meta().config.profile))?;
    write(host, order_key(row.id), &row)?;
    surcharge(host, action.from, added)?;
    Ok(counted)
}

/// The recount of `spec/market.md`, section 8, over a fully authenticated
/// tree. Returns the number of leaves under `market/`.
pub fn audit(snapshot: &crate::store::VerifiedAudit<'_>, meta: &Meta) -> Result<u64> {
    let mut actual = 0u64;
    snapshot.for_each_prefix(PREFIX, |_, _| {
        actual += 1;
        Ok(())
    })?;
    if !meta.config.market {
        ensure!(actual == 0 && meta.market_micros.is_none(), "market rows on a network without the market");
        return Ok(0);
    }
    let params = Params::of(meta.config.profile);
    let state: Summary =
        canonical_decode(&snapshot.get(META_KEY)?.ok_or_else(|| anyhow!("missing market state"))?)?;
    let mut leaves = 1u64;
    let mut held = 0u64;
    let mut orders = 0u64;
    let mut scripts = 0u64;
    let mut by_owner = std::collections::BTreeMap::<u64, Vec<u64>>::new();
    snapshot.for_each_prefix(b"market/order/", |key, value| {
        let row: Order = canonical_decode(value)?;
        ensure!(key == order_key(row.id) && row.id < state.next_order, "order key/id");
        row.validate(&params)?;
        ensure!(snapshot.get(&crate::engine::account_key(row.owner))?.is_some(), "order owner");
        held = pos::add(held, row.held())?;
        if let Some(slots) = &row.scripts {
            for slot in slots {
                let used: ScriptUse = canonical_decode(
                    &snapshot
                        .get(&script_key(&hex::decode(&slot.script)?))?
                        .ok_or_else(|| anyhow!("order script without its row"))?,
                )?;
                if slot.used {
                    ensure!(used == ScriptUse { fill: None, order: None }, "used script row");
                } else {
                    ensure!(used == ScriptUse { fill: None, order: Some(row.id) }, "order script row");
                    scripts += 1;
                }
                if let Some(id) = slot.fill {
                    let fill: Fill = canonical_decode(
                        &snapshot.get(&fill_key(id))?.ok_or_else(|| anyhow!("order names a fill that is gone"))?,
                    )?;
                    ensure!(
                        fill.order == row.id && fill.side == Side::Sell && fill.script == slot.script,
                        "order script fill"
                    );
                }
            }
        }
        by_owner.entry(row.owner).or_default().push(row.id);
        orders += 1;
        leaves += 1;
        Ok(())
    })?;
    let mut fills = 0u64;
    let mut by_payer = std::collections::BTreeMap::<u64, Vec<u64>>::new();
    let mut of_order = std::collections::BTreeMap::<u64, u64>::new();
    snapshot.for_each_prefix(b"market/fill/", |key, value| {
        let row: Fill = canonical_decode(value)?;
        ensure!(key == fill_key(row.id) && row.id < state.next_fill, "fill key/id");
        ensure!(
            row.amount_micros >= 1
                && (1..=PRICE_MAX).contains(&row.price)
                && (1..=sats(row.amount_micros, row.price)?).contains(&row.sats)
                && (params.k_min..=K_MAX).contains(&row.confirmations)
                && (params.n_min..=N_MAX).contains(&row.pay_blocks)
                && row.last_height().is_ok()
                && row.earliest_end(&params).is_ok()
                && BlockHash::from_str(&row.start_hash).is_ok_and(|hash| hash.to_string() == row.start_hash),
            "fill bounds"
        );
        for account in [row.owner, row.payer, row.to] {
            ensure!(snapshot.get(&crate::engine::account_key(account))?.is_some(), "fill account");
        }
        let order: Order = canonical_decode(
            &snapshot.get(&order_key(row.order))?.ok_or_else(|| anyhow!("fill names an order that is gone"))?,
        )?;
        ensure!(order.side == row.side && order.price == row.price, "fill order");
        match row.side {
            Side::Sell => {
                ensure!(
                    order.owner == row.owner
                        && order
                            .scripts
                            .as_ref()
                            .is_some_and(|slots| slots.iter().any(|s| s.fill == Some(row.id) && s.script == row.script)),
                    "sell fill is not named by its order"
                );
            }
            Side::Buy => {
                ensure!(order.owner == row.payer && row.to == row.payer, "buy fill payer");
                let used: ScriptUse = canonical_decode(
                    &snapshot
                        .get(&script_key(&standard(&row.script)?))?
                        .ok_or_else(|| anyhow!("fill script without its row"))?,
                )?;
                ensure!(used == ScriptUse { fill: Some(row.id), order: None }, "fill script row");
                scripts += 1;
                *of_order.entry(row.order).or_default() += 1;
            }
        }
        held = pos::add(held, pos::add(row.amount_micros, row.deposit_micros)?)?;
        by_payer.entry(row.payer).or_default().push(row.id);
        fills += 1;
        leaves += 1;
        Ok(())
    })?;
    snapshot.for_each_prefix(b"market/order/", |_, value| {
        let row: Order = canonical_decode(value)?;
        if row.side == Side::Buy {
            ensure!(
                row.fills == Some(of_order.get(&row.id).copied().unwrap_or(0)),
                "buy order fill count"
            );
        }
        Ok(())
    })?;
    ensure!(
        Some(held) == meta.market_micros && orders == state.orders && fills == state.fills,
        "market recount: what the rows hold differs from the totals"
    );
    let mut script_rows = 0u64;
    let mut serving = 0u64;
    snapshot.for_each_prefix(b"market/script/", |key, value| {
        let row: ScriptUse = canonical_decode(value)?;
        ensure!(
            key.len() == b"market/script/".len() + 32 && !(row.fill.is_some() && row.order.is_some()),
            "script row"
        );
        // A row with neither field is a script that has served its fill.
        if row.fill.is_some() || row.order.is_some() {
            serving += 1;
        }
        script_rows += 1;
        Ok(())
    })?;
    ensure!(serving == scripts, "a script row names an order or a fill that does not name it");
    leaves += script_rows;
    let mut indexes = 0u64;
    snapshot.for_each_prefix(b"market/account/", |key, value| {
        let row: Index = canonical_decode(value)?;
        ensure!(key.len() == b"market/account/".len() + 8, "market index key");
        let account = u64::from_be_bytes(key[key.len() - 8..].try_into()?);
        ensure!(
            (!row.orders.is_empty() || !row.fills.is_empty())
                && row.orders.len() <= MAX_ORDERS
                && row.fills.len() <= MAX_PAYER_FILLS
                && Some(&row.orders) == by_owner.get(&account).or(Some(&Vec::new()))
                && Some(&row.fills) == by_payer.get(&account).or(Some(&Vec::new())),
            "market index of an account"
        );
        indexes += 1;
        Ok(())
    })?;
    let expected: std::collections::BTreeSet<u64> = by_owner.keys().chain(by_payer.keys()).copied().collect();
    ensure!(indexes == expected.len() as u64, "an account with orders or fills has no market index");
    leaves += indexes;
    let mut paid = 0u64;
    snapshot.for_each_prefix(b"market/paid/", |key, value| {
        let row: Paid = canonical_decode(value)?;
        ensure!(
            key.len() == b"market/paid/".len() + 36 && row.sats >= 1 && row.fill < state.next_fill,
            "paid output row"
        );
        paid += 1;
        Ok(())
    })?;
    leaves += paid;
    let mut candles = 0u64;
    let (mut trades, mut seconds, mut value_sats) = (0u64, 0u64, 0u64);
    let mut newest = None;
    snapshot.for_each_prefix(b"market/candle/", |key, value| {
        let row: Candle = canonical_decode(value)?;
        ensure!(key.len() == b"market/candle/".len() + 8, "candle key");
        ensure!(
            row.trades >= 1
                && row.low >= 1
                && row.low <= row.open.min(row.close)
                && row.high >= row.open.max(row.close)
                && row.high <= PRICE_MAX,
            "candle bounds"
        );
        trades = trades.saturating_add(row.trades);
        seconds = seconds.saturating_add(row.seconds_micros);
        value_sats = value_sats.saturating_add(row.sats);
        newest = Some(row.close);
        candles += 1;
        Ok(())
    })?;
    ensure!(
        trades == state.trades
            && seconds == state.seconds_micros
            && value_sats == state.sats
            && newest == state.last_price
            && (paid == trades || trades == u64::MAX),
        "the candles add up to the market's totals"
    );
    leaves += candles;
    let heights: Heights =
        canonical_decode(&snapshot.get(HEIGHTS_KEY)?.ok_or_else(|| anyhow!("missing clock of heights"))?)?;
    let bitcoin: bitcoin_bridge::HeaderChain = canonical_decode(
        &snapshot.get(crate::bitcoin_adapter::STATE_KEY)?.ok_or_else(|| anyhow!("missing Bitcoin summary"))?,
    )?;
    ensure!(
        !heights.entries.is_empty()
            && heights.entries.len() <= MAX_HEIGHT_ENTRIES
            && heights.entries.windows(2).all(|w| w[0].height < w[1].height && w[0].at <= w[1].at)
            && heights
                .entries
                .last()
                .is_some_and(|e| e.at <= meta.active_micros().unwrap_or(0) && e.height <= bitcoin.meta.best_height),
        "clock of heights"
    );
    leaves += 1;
    ensure!(leaves == actual, "unexpected leaf under market/");
    Ok(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_price_formula_rounds_up_for_the_cost_and_down_for_what_is_bought() {
        // One second at a price of one millionth of a satoshi costs a satoshi.
        assert_eq!(sats(1_000_000, 1).unwrap(), 1);
        assert_eq!(sats(1, 1).unwrap(), 1);
        // 1,000 seconds at 250 satoshis a second.
        assert_eq!(sats(1_000_000_000, 250_000_000).unwrap(), 250_000);
        assert_eq!(bought(250_000, 250_000_000), 1_000_000_000);
        // What a satoshi less buys costs at most what was paid.
        for (amount, price) in [(999_999u64, 3u64), (7, 1_000_000_000_000), (123_456_789, 987_654_321)] {
            let cost = sats(amount, price).unwrap();
            assert!(bought(cost, price) >= amount, "paying the cost buys the amount");
            if cost > 1 {
                assert!(bought(cost - 1, price) < amount, "a satoshi less does not");
            }
        }
        assert!(sats(u64::MAX, PRICE_MAX).is_err());
        assert!(sats(1, 0).is_err());
        assert!(sats(1, PRICE_MAX + 1).is_err());
        assert_eq!(bought(u64::MAX, 1), u64::MAX);
    }
    #[test]
    fn shares_round_down_and_deposits_round_up() {
        assert_eq!(share(10, 1, 3).unwrap(), 3);
        assert_eq!(share(10, 3, 3).unwrap(), 10);
        assert!(share(10, 4, 3).is_err());
        assert!(share(10, 0, 0).is_err());
        assert_eq!(ppm_ceil(1, 1).unwrap(), 1);
        assert_eq!(ppm_ceil(1_000_000, 10_000).unwrap(), 10_000);
        assert_eq!(ppm_ceil(5, 0).unwrap(), 0);
        assert!(ppm_ceil(5, PPM + 1).is_err());
    }
    #[test]
    fn the_clock_of_heights_answers_with_the_oldest_entry_that_reaches() {
        let heights = Heights {
            entries: vec![
                HeightEntry { at: 0, height: 10 },
                HeightEntry { at: 50, height: 14 },
                HeightEntry { at: 90, height: 15 },
            ],
        };
        assert_eq!(heights.known(3), Some(0));
        assert_eq!(heights.known(10), Some(0));
        assert_eq!(heights.known(11), Some(50));
        assert_eq!(heights.known(14), Some(50));
        assert_eq!(heights.known(15), Some(90));
        assert_eq!(heights.known(16), None);
    }
    #[test]
    fn the_clock_forgets_heights_the_chain_no_longer_has() {
        let mut heights = Heights { entries: vec![HeightEntry { at: 0, height: 10 }] };
        // Six cheap blocks, then a chain of more work that is lower.
        heights.learn(16, 100);
        assert_eq!(heights.known(16), Some(100));
        heights.learn(11, 200);
        assert_eq!(heights.known(16), None, "a height the chain lost is not known");
        assert_eq!(heights.known(11), Some(200));
        assert_eq!(heights.entries.len(), 2);
        // The same height again changes nothing; a higher one is learnt
        // at the moment it comes.
        heights.learn(11, 300);
        assert_eq!(heights.known(11), Some(200));
        heights.learn(16, 400);
        assert_eq!(heights.known(16), Some(400));
        // Below everything recorded: one entry stands for the new best.
        heights.learn(3, 500);
        assert_eq!(heights.entries, vec![HeightEntry { at: 500, height: 3 }]);
        // The clock keeps its newest entries.
        for step in 0..(MAX_HEIGHT_ENTRIES as u32 + 5) {
            heights.learn(4 + step, 600 + u64::from(step));
        }
        assert_eq!(heights.entries.len(), MAX_HEIGHT_ENTRIES);
        assert_eq!(heights.entries.last().unwrap().height, 4 + MAX_HEIGHT_ENTRIES as u32 + 4);
    }
    #[test]
    fn each_standard_form_has_its_name() {
        let with = |head: &[u8], body: usize, tail: &[u8]| [head, &vec![7u8; body], tail].concat();
        assert_eq!(form_of(&with(&[0x76, 0xa9, 0x14], 20, &[0x88, 0xac])), Some("p2pkh"));
        assert_eq!(form_of(&with(&[0xa9, 0x14], 20, &[0x87])), Some("p2sh"));
        assert_eq!(form_of(&with(&[0x00, 0x14], 20, &[])), Some("p2wpkh"));
        assert_eq!(form_of(&with(&[0x00, 0x20], 32, &[])), Some("p2wsh"));
        assert_eq!(form_of(&with(&[0x51, 0x20], 32, &[])), Some("p2tr"));
        assert_eq!(form_of(&[0x6a, 0x01, 0x00]), None);
        let mut sorted = FORMS;
        sorted.sort();
        assert_eq!(sorted, FORMS, "a buy order lists its forms in this order");
    }
}
