// The lists of the market, read from the trading API under the wallet's own address (deploy/api/README.md, "The
// market"): the book, the depth, the trades, the candles, an account's orders and fills.
//
// A LIST IS A SERVER'S WORD. Every answer here is the index's (`proven: false`). The wallet shows it as a list and
// never pays or signs on it: market-ui.mjs reads each row it acts on through the wallet's own verifier first.
// So this module takes from an answer only what it can hold to a form: decimal strings, a few fixed words, true and
// false. No sentence of a server reaches the page from here, and an answer in another form is refused whole, in the
// wallet's own words.
//
// Requests go to this origin only (the page's Content-Security-Policy allows no other), without cookies, without a
// referrer, never followed to another address, waited for fifteen seconds and read to 512 KiB at most.

const WAIT_MS = 15000, MOST_BYTES = 512 * 1024;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/, HEX64 = /^[0-9a-f]{64}$/;
export const API_WORDS = Object.freeze({
  unreadable: 'The market\'s list could not be read: the service sent an answer this wallet does not understand. Nothing was signed.',
  down: 'The market\'s list could not be reached. Check your connection and try again. Nothing was signed.',
  notReady: 'The market\'s list is still being put together by the service. Try again in a moment.',
  noMarket: 'The service says that this network has no market.',
  busy: 'The market\'s list is busy. Try again in a moment.',
});
// A plain Error, so that the page shows its words as the wallet's own (actions.mjs, failureNotice).
const refuse = (words, code) => { const error = new Error(words); error.marketApi = code; return error; };
const dec = (value) => { if (typeof value !== 'string' || !DECIMAL.test(value)) throw refuse(API_WORDS.unreadable, 'form'); return value; };
const decOrNull = (value) => (value === null || value === undefined ? null : dec(value));
const bool = (value) => { if (typeof value !== 'boolean') throw refuse(API_WORDS.unreadable, 'form'); return value; };
const oneOf = (value, words) => { if (!words.includes(value)) throw refuse(API_WORDS.unreadable, 'form'); return value; };
const list = (value, most) => { if (!Array.isArray(value) || value.length > most) throw refuse(API_WORDS.unreadable, 'form'); return value; };
const whole = (value) => { if (!Number.isSafeInteger(value) || value < 0) throw refuse(API_WORDS.unreadable, 'form'); return value; };
const FORMS = ['p2pkh', 'p2sh', 'p2tr', 'p2wpkh', 'p2wsh'];

/// Where the index stands, from an answer's `market_index` and `index`: only what the page shows when it is not clean.
export function indexNote(body) {
  const note = body?.market_index;
  if (!note || typeof note !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  return { asOf: decOrNull(note.as_of_height), ready: bool(note.ready), consistent: bool(note.consistent), pendingRows: whole(note.pending_rows),
    tapeReconciled: note.tape_reconciled === null || note.tape_reconciled === undefined ? null : bool(note.tape_reconciled),
    tapeComplete: note.tape_complete === null || note.tape_complete === undefined ? null : bool(note.tape_complete),
    indexedHeight: decOrNull(body?.index?.indexed_height) };
}
/// What the page says of an index that is not clean, one sentence each, or nothing. `provenHeight`: the height of the
/// wallet's own latest verified state, to say how far the list lags.
export function indexWarnings(note, provenHeight = null) {
  const out = [];
  if (!note.ready) out.push('The list is still being put together: it may miss orders.');
  if (!note.consistent) out.push('The service says its list does not agree with the chain right now (it is reading every row again). Orders may be missing or out of date.');
  if (note.tapeReconciled === false) out.push('The service says its list of trades does not add up to what the chain counted. The trades and the chart may be wrong.');
  if (note.tapeComplete === false) out.push('The list of trades does not go back to the start of the chain.');
  if (note.asOf !== null && provenHeight !== null && BigInt(provenHeight) > BigInt(note.asOf) + 20n) out.push(`The list is as of block ${note.asOf}; this browser has checked the chain at block ${provenHeight}. The list is behind.`);
  return out;
}
function orderItem(item) {
  if (!item || typeof item !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  const side = oneOf(item.side, ['sell', 'buy']);
  return { id: dec(item.id), side, owner: dec(item.owner), price: dec(item.price), amount_micros: dec(item.amount_micros), sats: dec(item.sats), min_sats: dec(item.min_sats), confirmations: dec(item.confirmations), pay_blocks: dec(item.pay_blocks),
    deposit_ppm: dec(item.deposit_ppm), min_deposit_micros: dec(item.min_deposit_micros), bond_micros: dec(item.bond_micros), open: bool(item.open), takes_fill: bool(item.takes_fill), open_fills: whole(item.open_fills),
    free_scripts: item.free_scripts === null || item.free_scripts === undefined ? null : whole(item.free_scripts), forms: item.forms === null || item.forms === undefined ? null : list(item.forms, 5).map(form => oneOf(form, FORMS)) };
}
function fillItem(item) {
  if (!item || typeof item !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  return { id: dec(item.id), order: dec(item.order), side: oneOf(item.side, ['sell', 'buy']), owner: dec(item.owner), payer: dec(item.payer), to: dec(item.to), price: dec(item.price), amount_micros: dec(item.amount_micros), sats: dec(item.sats), deposit_micros: dec(item.deposit_micros),
    script: typeof item.script === 'string' && /^[0-9a-f]{44,68}$/.test(item.script) ? item.script : (() => { throw refuse(API_WORDS.unreadable, 'form'); })(), roles: list(item.roles ?? [], 3).map(role => oneOf(role, ['payer', 'owner', 'to'])) };
}
function endedItem(item) {
  if (!item || typeof item !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  return { fill: dec(item.fill), order: decOrNull(item.order), how: oneOf(item.how, ['paid', 'expired', 'released', 'settled', 'unknown']), roles: list(item.roles ?? [], 3).map(role => oneOf(role, ['payer', 'owner', 'to'])), height: decOrNull(item.height) };
}
function tradeItem(item) {
  if (!item || typeof item !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  return { fill: dec(item.fill), price: decOrNull(item.price), sats: decOrNull(item.sats), seconds_micros: decOrNull(item.seconds_micros), height: decOrNull(item.height), full: item.full === null || item.full === undefined ? null : bool(item.full),
    txid: typeof item.bitcoin_txid === 'string' && HEX64.test(item.bitcoin_txid) ? item.bitcoin_txid : null, time: typeof item.time === 'string' && /^[0-9TZ:.+-]{10,40}$/.test(item.time) ? item.time : null };
}
function candleItem(item) {
  const prices = item?.recorded_prices;
  if (!item || typeof item !== 'object' || !prices || typeof prices !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  const candle = { number: dec(item.number), start: dec(item.start_time_micros), open: dec(prices.open), high: dec(prices.high), low: dec(prices.low), close: dec(prices.close), sats: dec(item.sats), seconds_micros: dec(item.seconds_micros), trades: dec(item.trades), source: oneOf(item.source, ['state_row', 'computed']) };
  const [open, high, low, close] = [candle.open, candle.high, candle.low, candle.close].map(BigInt);
  if (low > open || low > close || high < open || high < close) throw refuse(API_WORDS.unreadable, 'form');
  return candle;
}
function level(item) {
  if (!item || typeof item !== 'object') throw refuse(API_WORDS.unreadable, 'form');
  return { price: dec(item.price), amount_micros: dec(item.amount_micros), takeable_micros: dec(item.takeable_micros), sats: dec(item.sats), orders: whole(item.orders) };
}

/// `c`: { fetch, wait(ms) -> AbortSignal }. `fetch` is the page's; a test hands in its own.
export function createMarketApi({ fetch, timeout = ms => AbortSignal.timeout(ms) }) {
  async function get(path) {
    let response, text;
    try {
      response = await fetch(path, { method: 'GET', headers: { Accept: 'application/json' }, redirect: 'error', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: timeout(WAIT_MS) });
      text = await response.text();
    } catch { throw refuse(API_WORDS.down, 'down'); }
    if (typeof text !== 'string' || text.length > MOST_BYTES) throw refuse(API_WORDS.unreadable, 'form');
    let body = null;
    try { body = JSON.parse(text); } catch { body = null; }
    if (response.status === 429) throw refuse(API_WORDS.busy, 'busy');
    if (response.status === 503) throw refuse(body?.error?.code === 'market_index_not_ready' ? API_WORDS.notReady : API_WORDS.busy, 'not-ready');
    if (response.status === 404) { const error = refuse(API_WORDS.noMarket, 'not-found'); error.code = typeof body?.error?.code === 'string' ? body.error.code : ''; error.body = body && typeof body === 'object' ? body : null; throw error; }
    if (response.status !== 200 || !body || typeof body !== 'object') throw refuse(response.status >= 500 ? API_WORDS.down : API_WORDS.unreadable, 'status');
    return body;
  }
  const id = value => { if (typeof value !== 'string' || !DECIMAL.test(value)) throw new Error('A number was expected.'); return value; };
  return {
    /// A side of the book: open orders that offer something, best price first (at most 200).
    async orders(side) { const body = await get(`/v1/market/orders?side=${oneOf(side, ['sell', 'buy'])}&limit=200`); return { items: list(body.items, 200).map(orderItem), more: body.has_more === true, index: indexNote(body) }; },
    /// The depth: the first prices of each side with what stands there, and the last recorded price.
    async depth(levels = 12) { const body = await get(`/v1/market/depth?levels=${whole(levels)}`); return { sell: list(body.sell, 100).map(level), buy: list(body.buy, 100).map(level), truncated: body.truncated === true, lastRecorded: decOrNull(body.last_recorded_price), index: indexNote(body) }; },
    /// The newest proven payments, newest first.
    async trades(limit = 30) { const body = await get(`/v1/market/trades?limit=${whole(limit)}`); return { items: list(body.items, 200).map(tradeItem), index: indexNote(body) }; },
    /// Candles, newest first. `interval`: 'hour' (the chain's own), '1m', '5m', '15m' or '1d' (added up by the index).
    async candles(interval, limit = 60) { const body = await get(`/v1/market/candles?interval=${oneOf(interval, ['hour', '1m', '5m', '15m', '1d'])}&limit=${whole(limit)}`); return { interval, intervalMicros: decOrNull(body.interval_micros), items: list(body.items, 500).map(candleItem), index: indexNote(body) }; },
    /// An account's open orders, the open fills it has a part in (with its roles), and the fills that ended.
    async account(account) { const body = await get(`/v1/accounts/${id(account)}/market`); return { orders: list(body.orders, 200).map(orderItem), fills: list(body.fills, 200).map(fillItem), fillsTruncated: body.fills_truncated === true, ended: list(body.ended?.items ?? [], 200).map(endedItem), index: indexNote(body) }; },
    /// What the index says of one fill: how it ended (or null while it is open or unknown) and the satoshis of the
    /// payments it counted. The row itself is NOT taken from here: the wallet reads it through its own verifier.
    async fillNote(fill) {
      let body;
      try { body = await get(`/v1/market/fills/${id(fill)}`); }
      catch (error) { if (error.marketApi !== 'not-found' || error.code !== 'fill_not_found' || !error.body) throw error; body = error.body; }
      const indexed = body.indexed ?? {};
      return { ended: indexed.ended ? endedItem(indexed.ended).how : null, payments: list(indexed.payments ?? [], 200).map(tradeItem), known: true };
    },
    /// Whether the Bitcoin header chain is fresh, as far as the service can tell (true, false or null: it does not
    /// know). A new purchase needs a fresh chain; the chain itself decides, this is only so that the page can say why.
    async bitcoin() { const body = await get('/v1/market'); const chain = body.bitcoin ?? {}; return { fresh: chain.fresh === true ? true : chain.fresh === false ? false : null, halted: chain.halted === true, index: indexNote(body) }; },
  };
}
