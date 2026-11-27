// The traders' side of the wallet's market, without a page (market-trade-ui.mjs draws with it): the depth of the book,
// the geometry of a candle chart, and the stop orders this wallet keeps.
//
// WHAT A "PRICE" IS HERE (spec/market.md, section 9). A candle and a last price say what was RECORDED: the price two
// accounts agreed for one fill. No rule of the chain reads them, two accounts of one person can trade at any price,
// and it need not cost a Bitcoin fee. They are not what a second is worth. The page says "recorded" every time.
//
// STOP ORDERS ARE THIS WALLET'S, NOT THE CHAIN'S (spec/market.md, section 11: never a rule of the chain). A stop order
// is a rule kept in this browser. It is looked at only while the wallet is open and unlocked here. It always has a
// limit price: when it fires, what is prepared is an order at that price, never an order "at any price". Its trigger
// is judged on rows of the book that this wallet has read through its own verifier, with a least size, or on several
// recorded trades together with the chain's own last recorded price: never on one last price alone, which one tiny
// trade can move. And it never signs: the wallet's signing asks the person for every action (a review, and on a
// protected account the payment password), and a stop order does not change that. When it fires it says so and
// prepares the order for the person to review and sign.

const DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
const assert = (value, message) => { if (!value) throw new Error(message); };
const big = value => { assert(typeof value === 'bigint' || (typeof value === 'string' && DECIMAL.test(value)), 'A whole number was expected.'); return BigInt(value); };

export const RECORD_WORDS = Object.freeze({
  chart: 'Recorded prices: what was agreed in fills that were then paid and proven. A record, not a quote and not what a second is worth. Anyone can trade with themselves at any price, so place no order because of these alone.',
  trades: 'Recorded trades, from the market\'s list: each is one proven payment, at the price of its fill.',
  book: 'The book, from the market\'s list. Before you take or sell into an order, this wallet reads that order from the chain and shows you what the chain holds.',
});

// ---------------------------------------------------------------- the depth of the book
/// The orders of one side as price levels with what stands there and what has added up to there, best price first.
/// `orders`: a side of the book from the list (market-api.mjs), already best first. `most`: how many levels.
export function bookLevels(orders, most = 12) {
  const levels = [];
  let total = 0n;
  for (const order of orders) {
    if (order.open !== true || BigInt(order.amount_micros) < 1n) continue;
    let level = levels[levels.length - 1];
    if (!level || level.price !== order.price) { if (levels.length >= most) break; level = { price: order.price, amountMicros: 0n, orders: [], takes: false }; levels.push(level); }
    level.amountMicros += BigInt(order.amount_micros); level.orders.push(order.id); level.takes = level.takes || order.takes_fill === true; total += BigInt(order.amount_micros); level.sumMicros = total;
  }
  return { levels: levels.map(level => ({ price: level.price, amountMicros: level.amountMicros.toString(), sumMicros: level.sumMicros.toString(), orders: level.orders, takes: level.takes })), totalMicros: total.toString() };
}
/// A share of a whole in thousandths, for a bar: 0 to 1000.
export function share(part, whole) { const total = big(String(whole)); return total === 0n ? 0 : Number(big(String(part)) * 1000n / total); }

// ---------------------------------------------------------------- a candle chart
/// Where each candle stands in a drawing `width` by `height` (in the drawing's own units), oldest on the left. `candles`:
/// `[{ open, high, low, close }]` in prices of the chain (whole numbers), oldest first; at most `most` newest are drawn.
/// Gives `{ bars: [{ x, width, wickX, top, bottom, bodyTop, bodyHeight, up }], low, high }`, with `low` and `high` the
/// lowest and highest price drawn (the scale is theirs: truthful, with no smoothing and nothing between two candles).
export function candleGeometry(candles, width, height, { pad = 8, most = 60 } = {}) {
  const shown = candles.slice(-most);
  if (!shown.length) return { bars: [], low: null, high: null };
  let low = big(shown[0].low), high = big(shown[0].high);
  for (const candle of shown) { if (big(candle.low) < low) low = big(candle.low); if (big(candle.high) > high) high = big(candle.high); }
  const span = high - low, inner = height - 2 * pad, slot = (width - 2 * pad) / shown.length, body = Math.max(1, Math.min(18, slot * 0.6));
  // A price as a height: the highest at the top. With one price only, everything stands in the middle.
  const y = price => (span === 0n ? pad + inner / 2 : pad + inner * Number(high - big(price)) / Number(span));
  const round = value => Math.round(value * 100) / 100;
  const bars = shown.map((candle, index) => {
    const centre = pad + slot * (index + 0.5), open = y(candle.open), close = y(candle.close), up = big(candle.close) >= big(candle.open);
    return { x: round(centre - body / 2), width: round(body), wickX: round(centre), top: round(y(candle.high)), bottom: round(y(candle.low)), bodyTop: round(Math.min(open, close)), bodyHeight: round(Math.max(1, Math.abs(open - close))), up };
  });
  return { bars, low: low.toString(), high: high.toString() };
}
/// Where the list's candles of the chain's own hours differ from the rows the chain proves for those hours:
/// the numbers of the hours that differ. `proven(hour)` gives the proven row or null.
export function candlesDiffer(listed, proven) {
  const out = [];
  for (const candle of listed) {
    const row = proven(candle.number);
    if (row === undefined) continue;
    if (row === null || ['open', 'high', 'low', 'close', 'sats', 'seconds_micros', 'trades'].some(field => String(row[field]) !== String(candle[field]))) out.push(candle.number);
  }
  return out;
}

// ---------------------------------------------------------------- stop orders, kept by this wallet
export const STOPS_PREFIX = 'timecurrency.market-stops.v1:';
export const stopsKey = (networkId, name) => `${STOPS_PREFIX}${networkId}:${name}`;
export const STOP_LIMIT = 16, STOP_TRADES_MIN = 3, STOP_TRADES_MAX = 20;
export const STOP_WORDS = Object.freeze({
  what: 'A stop order is a rule this wallet keeps in this browser: the chain has no stop orders and knows nothing of it. It is watched only while this wallet is open and unlocked here.',
  limit: 'A stop order always has a limit price. When it fires, the wallet prepares an order at that price, never an order at any price.',
  asks: 'When it fires, the wallet tells you and prepares the order. You review and sign it, like every action: this wallet signs nothing by itself, and stop orders do not change that.',
  book: 'Judged on the book as this browser reads it from the chain: the best price among orders of at least the size you set. One tiny order cannot move it.',
  trades: 'Judged on several recorded trades in a row, together with the chain\'s own last recorded price. One trade alone cannot fire it.',
  hidden: 'Which orders exist comes from the market\'s list. A service that hides orders can make a stop fire early, or not at all. The limit price is what protects you.',
  noLimit: 'A stop order needs a limit price: this wallet sends no order at any price.',
  noAddress: 'A stop order that sells needs a free address of your own Bitcoin wallet, kept aside for it. Add one under "My Bitcoin addresses".',
});
const SIDES = ['sell', 'buy'], SOURCES = ['book', 'trades'], WHEN = ['at_or_below', 'at_or_above'], STATES = ['armed', 'fired', 'done'];
const price = value => { const number = big(String(value)); assert(number >= 1n && number <= 1000000000000000n, 'A price is from 0.000001 to 1,000,000,000 satoshis for one second.'); return number.toString(); };
/// A stop order as this wallet keeps it, checked; anything in another form is refused. `given`:
/// - `side`: 'sell' (when it fires, a sell order is prepared) or 'buy' (a buy order);
/// - `trigger`: `{ source: 'book', when, price, minMicros }` (the best buy price for a sale, the best sell price for a
///   purchase, among proven orders that offer at least `minMicros`), or `{ source: 'trades', when, price, count }` (the
///   last `count` recorded trades, 3 to 20, and the chain's last recorded price);
/// - `limit`: the price of the order that is prepared. It is required;
/// - `amountMicros`; for a sale `script` and `address`, the receiving address kept aside for it.
export function stopOrder(given) {
  assert(given && typeof given === 'object', 'A stop order was expected.');
  assert(SIDES.includes(given.side), 'A stop order sells or buys.');
  assert(given.limit !== undefined && given.limit !== null && given.limit !== '', STOP_WORDS.noLimit);
  const trigger = given.trigger ?? {};
  assert(SOURCES.includes(trigger.source) && WHEN.includes(trigger.when), 'Choose what the stop order watches, and whether it fires at or below, or at or above, your trigger price.');
  const stop = { id: String(given.id ?? ''), side: given.side, limit: price(given.limit), amountMicros: big(String(given.amountMicros)).toString(), state: STATES.includes(given.state) ? given.state : 'armed',
    trigger: { source: trigger.source, when: trigger.when, price: price(trigger.price) } };
  assert(/^[0-9a-f]{16}$/.test(stop.id), 'A stop order has an id.'); assert(BigInt(stop.amountMicros) >= 1n, 'Enter how many seconds.');
  if (trigger.source === 'book') { stop.trigger.minMicros = big(String(trigger.minMicros)).toString(); assert(BigInt(stop.trigger.minMicros) >= 1n, 'Set the least size of an order that counts for the trigger: one tiny order must not move it.'); }
  else { assert(Number.isInteger(trigger.count) && trigger.count >= STOP_TRADES_MIN && trigger.count <= STOP_TRADES_MAX, `A stop order on recorded trades counts ${STOP_TRADES_MIN} to ${STOP_TRADES_MAX} trades in a row: one trade alone can be made by anyone, at any price.`); stop.trigger.count = trigger.count; }
  if (stop.side === 'sell') {
    assert(typeof given.script === 'string' && /^[0-9a-f]{44,68}$/.test(given.script) && typeof given.address === 'string' && /^[0-9A-Za-z]{14,90}$/.test(given.address), STOP_WORDS.noAddress);
    stop.script = given.script; stop.address = given.address;
  }
  if (given.fired && typeof given.fired === 'object') stop.fired = { height: DECIMAL.test(String(given.fired.height)) ? String(given.fired.height) : '0', seen: DECIMAL.test(String(given.fired.seen)) ? String(given.fired.seen) : stop.trigger.price };
  return stop;
}
/// Why a new stop order is refused beyond its form, in words, or null: a trigger that one small order could move.
/// `leastMicros`: the seconds the network's smallest trade buys at the trigger price (market.mjs, leastAmountFor).
export function stopRefusal(stop, leastMicros) {
  if (stop.trigger.source === 'book' && BigInt(stop.trigger.minMicros) < BigInt(leastMicros)) return `The least size that counts for the trigger is too small: an order of the network's smallest trade (${leastMicros} microseconds at that price) would move it. Set it higher.`;
  return null;
}
/// The stop orders as stored, read strictly: an entry in another form is dropped.
export function readStops(stored) {
  let parsed = null;
  try { parsed = typeof stored === 'string' ? JSON.parse(stored) : null; } catch { parsed = null; }
  if (!parsed || parsed.v !== 1 || !Array.isArray(parsed.stops)) return [];
  const out = [];
  for (const entry of parsed.stops.slice(0, STOP_LIMIT)) { try { out.push(stopOrder(entry)); } catch { /* an entry in another form is not a stop order of this wallet */ } }
  return out;
}
export const writeStops = stops => JSON.stringify({ v: 1, stops: stops.slice(0, STOP_LIMIT) });
/// The price the trigger of a book stop looks at, on PROVEN order rows: for a sale the best (highest) buy price, for a
/// purchase the best (lowest) sell price, among open orders that offer at least `minMicros`, are not the account's
/// own and, for sell orders, have a free address. `rows`: proven order rows. Null when no order counts.
export function bookPrice(stop, rows, ownAccount) {
  const side = stop.side === 'sell' ? 'buy' : 'sell';
  const counted = rows.filter(row => row && row.side === side && row.open === true && row.owner !== String(ownAccount) && BigInt(row.amount_micros) >= BigInt(stop.trigger.minMicros)
    && (side === 'buy' || row.scripts.some(entry => entry.fill === undefined && entry.used !== true))).map(row => BigInt(row.price));
  if (!counted.length) return null;
  return counted.reduce((best, value) => (side === 'buy' ? (value > best ? value : best) : (value < best ? value : best))).toString();
}
const meets = (stop, value) => (stop.trigger.when === 'at_or_below' ? BigInt(value) <= BigInt(stop.trigger.price) : BigInt(value) >= BigInt(stop.trigger.price));
/// Whether a stop order fires, and on what:
/// - a book stop: `seen.book`, the price bookPrice gives on proven rows (null: no order counts, and nothing fires);
/// - a trades stop: `seen.trades`, the prices of the newest recorded trades, newest first (the list's), and
///   `seen.last`, the chain's own last recorded price (proven). It fires when each of the newest `count` trades meets
///   the trigger and the proven last price does too. Fewer trades than `count`: nothing fires.
export function stopFires(stop, seen) {
  if (stop.state !== 'armed') return { fires: false };
  if (stop.trigger.source === 'book') return seen.book === null || seen.book === undefined ? { fires: false } : { fires: meets(stop, seen.book), seen: String(seen.book) };
  const trades = (seen.trades ?? []).slice(0, stop.trigger.count);
  if (trades.length < stop.trigger.count || seen.last === null || seen.last === undefined) return { fires: false };
  return { fires: trades.every(value => meets(stop, value)) && meets(stop, seen.last), seen: String(seen.last) };
}
/// The scripts that armed or fired stop orders keep aside: the sell form does not offer them.
export const reservedScripts = stops => stops.filter(stop => stop.side === 'sell' && stop.state !== 'done').map(stop => stop.script);
