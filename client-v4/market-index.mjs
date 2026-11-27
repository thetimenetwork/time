// The market's index: the book of open orders, the open fills, the trades and the candles of a network whose
// genesis has the `market` setting (spec/market.md), kept in the index file beside the blocks (indexer.mjs) and
// served by the HTTP API (api.mjs). Validators keep no list of orders; this file keeps one.
//
// Validators are the only authority. What is here is an index, and it is filled in two ways that are kept apart:
//
// - THE BOOK (orders and fills) is never worked out from the rules. A row is stored only as the node PROVED it:
//   read with a proof against validator signatures, at one height, through a verified state reader. Which rows to
//   read again is taken from the actions of the indexed blocks: an action names what it touches (50 a new order;
//   51 and 58 the order named; 52 and 53 the order named and a new fill; 54 to 57 the fill named and its order),
//   and the summary's counters (`next_order`, `next_fill`; ids are dense from 1) give the ids of new rows. After
//   every pass that leaves nothing to read, the rows held are counted against the summary's `orders` and `fills`
//   of the same height; when they differ every id is read again, and answers say `consistent: false` meanwhile.
// - THE TAPE (one entry for every accepted proof of payment, kind 54) needs the fill's row as it was just before
//   the payment, and a state of the past cannot be asked for: a node keeps the states of its last blocks only. So
//   a working copy of every open fill (the ledger) is kept beside the proven rows: made from the proven row, or
//   from the action that made the fill when no proven row was to be had, and lowered by each payment of a part as
//   the rule says (spec/market.md, 6.5: what `TimeSDK.marketFillBuys` computes). An entry of the tape says which
//   it was (`basis`). The ledger is checked against every proven row that is read, the tape's sums against the
//   summary's `trades`, `sats` and `seconds_micros` at the same height, and the tape of an hour against the
//   candle the chain keeps for it. A difference is logged and said in every answer (`tape_reconciled: false`).
//
// Heights. The node's query takes a height, and this index reads at one exact height: that of the block before
// the newest indexed one, whose state the newest header proves. The blocks up to that height are followed first, so
// that what is read can be compared with what was followed. A read that mixes rows of two heights would count a
// book that never existed. When the indexer is further behind the chain than the node keeps states (a first sync, a restart
// after a stop), nothing can be read at its height: the actions of those blocks are followed for the tape and for
// the list of rows to read, and the rows are read when the indexer has come within the node's reach. The book is
// then the proven book of that height, whatever happened on the way.
import { createHash } from 'node:crypto';
import './time-sdk.js';
import { transactionOutputs } from './bitcoin-address.mjs';

const SDK = globalThis.TimeSDK;
/// The kinds of the market (spec/market.md, section 6).
export const MARKET_FIRST_KIND = 50, MARKET_LAST_KIND = 58;
/// Intervals of candles this index computes from its tape, in seconds. Their buckets begin on whole multiples of the
/// interval since 1970 (UTC), as charts expect; the chain's own candle (`hour`) begins with the chain.
export const COMPUTED_INTERVALS = Object.freeze({ '1m': 60, '5m': 300, '15m': 900, '1d': 86400 });
/// How many rows of one side a depth answer reads at most.
export const DEPTH_SCAN = 5000;
const MAX_ID = Number.MAX_SAFE_INTEGER;
/// An id as a number SQLite and JavaScript both hold exactly, or null. Ids are dense from 1, so a real one is small.
const idOf = (text) => (typeof text === 'string' && /^[1-9][0-9]{0,15}$/.test(text) && Number(text) <= MAX_ID ? Number(text) : null);
const sum = (a, b) => (BigInt(a) + BigInt(b)).toString();
/// The id of a transaction serialized without witness data, as Bitcoin software prints it.
function bitcoinTxid(hex) {
  const once = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return Buffer.from(createHash('sha256').update(once).digest()).reverse().toString('hex');
}
/// What a payment of `paid` satoshis does to a fill that holds `amount` microseconds with `due` satoshis still to
/// pay (spec/market.md, 6.5; the engine's `market::proof`): at least what is due buys all, and counts what was due;
/// less buys the same part, rounded down, and counts what was paid. `TimeSDK.marketFillBuys` gives the same seconds.
export function paymentOf(amount, due, paid) {
  const a = BigInt(amount), d = BigInt(due), s = BigInt(paid), full = s >= d;
  return { full, seconds: (full ? a : a * s / d).toString(), counted: (full ? d : s).toString() };
}

/// The market's tables in the index file `db`, and what reads and writes them. `transaction(work)` is the index's own.
export function createMarketStore(db, transaction, { networkId, startHeight }) {
  db.exec(`
    CREATE INDEX IF NOT EXISTS actions_market ON actions (height, idx) WHERE kind BETWEEN 50 AND 58;
    CREATE INDEX IF NOT EXISTS actions_headers ON actions (height, idx) WHERE kind = 40;
    CREATE TABLE IF NOT EXISTS market_orders (id INTEGER PRIMARY KEY, side TEXT NOT NULL, price INTEGER NOT NULL, owner TEXT NOT NULL, offered INTEGER NOT NULL CHECK(offered IN (0, 1)), proven_at INTEGER NOT NULL, row TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS market_book ON market_orders (side, price, id) WHERE offered = 1;
    CREATE INDEX IF NOT EXISTS market_book_buy ON market_orders (side, price DESC, id ASC) WHERE offered = 1;
    CREATE INDEX IF NOT EXISTS market_orders_owner ON market_orders (owner, id);
    CREATE TABLE IF NOT EXISTS market_fills (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, owner TEXT NOT NULL, payer TEXT NOT NULL, recipient TEXT NOT NULL, proven_at INTEGER NOT NULL, row TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS market_fills_owner ON market_fills (owner, id);
    CREATE INDEX IF NOT EXISTS market_fills_payer ON market_fills (payer, id);
    CREATE INDEX IF NOT EXISTS market_fills_recipient ON market_fills (recipient, id);
    CREATE TABLE IF NOT EXISTS market_ledger (id INTEGER PRIMARY KEY, order_id INTEGER, side TEXT, owner TEXT, payer TEXT, recipient TEXT, price TEXT, amount TEXT NOT NULL, sats TEXT NOT NULL, basis TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS market_made (height INTEGER NOT NULL, idx INTEGER NOT NULL, kind TEXT NOT NULL, id INTEGER NOT NULL, PRIMARY KEY (height, idx)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS market_new_orders (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, side TEXT NOT NULL, price TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS market_dirty (kind TEXT NOT NULL, id INTEGER NOT NULL, PRIMARY KEY (kind, id)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS market_trades (height INTEGER NOT NULL, idx INTEGER NOT NULL, time_micros INTEGER NOT NULL, fill_id INTEGER, price TEXT, sats TEXT, seconds TEXT, body TEXT NOT NULL, PRIMARY KEY (height, idx)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS market_trades_time ON market_trades (time_micros, height, idx);
    CREATE INDEX IF NOT EXISTS market_trades_fill ON market_trades (fill_id, height, idx);
    CREATE TABLE IF NOT EXISTS market_ended (fill_id INTEGER PRIMARY KEY, height INTEGER NOT NULL, idx INTEGER NOT NULL, owner TEXT, payer TEXT, recipient TEXT, body TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS market_ended_owner ON market_ended (owner, height, idx);
    CREATE INDEX IF NOT EXISTS market_ended_payer ON market_ended (payer, height, idx);
    CREATE INDEX IF NOT EXISTS market_ended_recipient ON market_ended (recipient, height, idx);
    CREATE TABLE IF NOT EXISTS market_candles (hour INTEGER PRIMARY KEY, proven_at INTEGER NOT NULL, matches INTEGER, row TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS market_buckets (seconds INTEGER NOT NULL, bucket INTEGER NOT NULL, open TEXT NOT NULL, high TEXT NOT NULL, low TEXT NOT NULL, close TEXT NOT NULL, sats TEXT NOT NULL, micros TEXT NOT NULL, trades INTEGER NOT NULL, PRIMARY KEY (seconds, bucket)) WITHOUT ROWID;
  `);
  const q = {
    get: db.prepare('SELECT value FROM kv WHERE key = ?'),
    put: db.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value'),
    block: db.prepare('SELECT height, time, time_micros FROM blocks WHERE height = ?'),
    nextBlock: db.prepare('SELECT MIN(height) AS height FROM actions INDEXED BY actions_market WHERE height > ? AND height <= ? AND kind BETWEEN 50 AND 58'),
    actions: db.prepare('SELECT idx, hash, raw FROM actions INDEXED BY actions_market WHERE height = ? AND kind BETWEEN 50 AND 58 ORDER BY idx ASC'),
    headers: db.prepare('SELECT raw FROM actions INDEXED BY actions_headers WHERE kind = 40 ORDER BY height DESC, idx DESC LIMIT ?'),
    order: db.prepare('SELECT * FROM market_orders WHERE id = ?'),
    putOrder: db.prepare('INSERT INTO market_orders (id, side, price, owner, offered, proven_at, row) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET side = excluded.side, price = excluded.price, owner = excluded.owner, offered = excluded.offered, proven_at = excluded.proven_at, row = excluded.row'),
    dropOrder: db.prepare('DELETE FROM market_orders WHERE id = ?'),
    orders: db.prepare('SELECT COUNT(*) AS count FROM market_orders'),
    ordersOf: db.prepare('SELECT * FROM market_orders WHERE owner = ? ORDER BY id ASC LIMIT ?'),
    // Each side is read in the order of an index of its own, from the price of the cursor on.
    sells: db.prepare("SELECT * FROM market_orders INDEXED BY market_book WHERE side = 'sell' AND offered = 1 AND price >= ? AND (price > ? OR id > ?) ORDER BY price ASC, id ASC LIMIT ?"),
    buys: db.prepare("SELECT * FROM market_orders INDEXED BY market_book_buy WHERE side = 'buy' AND offered = 1 AND price <= ? AND (price < ? OR id > ?) ORDER BY price DESC, id ASC LIMIT ?"),
    fill: db.prepare('SELECT * FROM market_fills WHERE id = ?'),
    putFill: db.prepare('INSERT INTO market_fills (id, order_id, owner, payer, recipient, proven_at, row) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET order_id = excluded.order_id, owner = excluded.owner, payer = excluded.payer, recipient = excluded.recipient, proven_at = excluded.proven_at, row = excluded.row'),
    dropFill: db.prepare('DELETE FROM market_fills WHERE id = ?'),
    fills: db.prepare('SELECT COUNT(*) AS count FROM market_fills'),
    ledger: db.prepare('SELECT * FROM market_ledger WHERE id = ?'),
    putLedger: db.prepare('INSERT INTO market_ledger (id, order_id, side, owner, payer, recipient, price, amount, sats, basis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET order_id = excluded.order_id, side = excluded.side, owner = excluded.owner, payer = excluded.payer, recipient = excluded.recipient, price = excluded.price, amount = excluded.amount, sats = excluded.sats, basis = excluded.basis'),
    lowerLedger: db.prepare("UPDATE market_ledger SET amount = ?, sats = ?, basis = 'derived_row' WHERE id = ?"),
    dropLedger: db.prepare('DELETE FROM market_ledger WHERE id = ?'),
    newOrder: db.prepare('INSERT OR REPLACE INTO market_new_orders (id, owner, side, price) VALUES (?, ?, ?, ?)'),
    made: db.prepare('INSERT OR REPLACE INTO market_made (height, idx, kind, id) VALUES (?, ?, ?, ?)'),
    madeAt: db.prepare('SELECT kind, id FROM market_made WHERE height = ? AND idx = ?'),
    newOrderOf: db.prepare('SELECT owner, side, price FROM market_new_orders WHERE id = ?'),
    dropNewOrders: db.prepare('DELETE FROM market_new_orders'),
    mark: db.prepare('INSERT OR IGNORE INTO market_dirty (kind, id) VALUES (?, ?)'),
    unmark: db.prepare('DELETE FROM market_dirty WHERE kind = ? AND id = ?'),
    marked: db.prepare('SELECT id FROM market_dirty WHERE kind = ? ORDER BY id ASC LIMIT ?'),
    marks: db.prepare('SELECT COUNT(*) AS count FROM market_dirty'),
    putTrade: db.prepare('INSERT OR REPLACE INTO market_trades (height, idx, time_micros, fill_id, price, sats, seconds, body) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'),
    tradesBetween: db.prepare('SELECT price, sats, seconds FROM market_trades INDEXED BY market_trades_time WHERE time_micros >= ? AND time_micros < ? ORDER BY time_micros ASC, height ASC, idx ASC'),
    tradeHours: db.prepare('SELECT DISTINCT CAST((time_micros - ?) / ? AS INTEGER) AS hour FROM market_trades WHERE height > ?'),
    tradesOfFill: db.prepare('SELECT height, idx, body FROM market_trades INDEXED BY market_trades_fill WHERE fill_id = ? ORDER BY height ASC, idx ASC LIMIT ?'),
    trades_asc: db.prepare('SELECT height, idx, body FROM market_trades WHERE (height, idx) > (?, ?) ORDER BY height ASC, idx ASC LIMIT ?'),
    trades_desc: db.prepare('SELECT height, idx, body FROM market_trades WHERE (height, idx) < (?, ?) ORDER BY height DESC, idx DESC LIMIT ?'),
    putEnded: db.prepare('INSERT OR REPLACE INTO market_ended (fill_id, height, idx, owner, payer, recipient, body) VALUES (?, ?, ?, ?, ?, ?, ?)'),
    ended: db.prepare('SELECT body FROM market_ended WHERE fill_id = ?'),
    dropEnded: db.prepare('DELETE FROM market_ended WHERE fill_id = ?'),
    candle: db.prepare('SELECT * FROM market_candles WHERE hour = ?'),
    putCandle: db.prepare('INSERT INTO market_candles (hour, proven_at, matches, row) VALUES (?, ?, ?, ?) ON CONFLICT (hour) DO UPDATE SET proven_at = excluded.proven_at, matches = excluded.matches, row = excluded.row'),
    dropCandle: db.prepare('DELETE FROM market_candles WHERE hour = ?'),
    candles: db.prepare('SELECT * FROM market_candles WHERE hour >= ? AND hour <= ? ORDER BY hour DESC LIMIT ?'),
    candleFaults: db.prepare('SELECT COUNT(*) AS count FROM market_candles WHERE matches = 0'),
    bucket: db.prepare('SELECT * FROM market_buckets WHERE seconds = ? AND bucket = ?'),
    putBucket: db.prepare('INSERT INTO market_buckets (seconds, bucket, open, high, low, close, sats, micros, trades) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (seconds, bucket) DO UPDATE SET high = excluded.high, low = excluded.low, close = excluded.close, sats = excluded.sats, micros = excluded.micros, trades = excluded.trades'),
    buckets: db.prepare('SELECT * FROM market_buckets WHERE seconds = ? AND bucket >= ? AND bucket <= ? ORDER BY bucket DESC LIMIT ?'),
  };
  for (const role of ['owner', 'payer', 'recipient']) {
    q[`fills_${role}`] = db.prepare(`SELECT * FROM market_fills INDEXED BY market_fills_${role} WHERE ${role} = ? ORDER BY id DESC LIMIT ?`);
    q[`ended_${role}`] = db.prepare(`SELECT fill_id, height, idx, body FROM market_ended INDEXED BY market_ended_${role} WHERE ${role} = ? AND (height, idx) < (?, ?) ORDER BY height DESC, idx DESC LIMIT ?`);
  }
  const KEY = 'market:state';
  /// Where the index stands. One row, written in the same transaction as the tables it describes.
  /// - `applied`: every block up to this height has been looked at for actions of the market; `last_market` is the
  ///   newest that held one. `clean`: the height the book was last proven whole (null before the first time).
  /// - `next_order`, `next_fill`: the ids the next order and fill get, counted from the actions since the last
  ///   proven summary. An index that begins with the chain counts from 1; another learns them from its first proof.
  /// - `base`: the summary's sums when the tape began (zero for an index that begins with the chain); `tape`: the
  ///   sums of the tape since. `scan`: the next ids of a reading of every row, while one is under way.
  const fresh = () => {
    const whole = startHeight === 1;
    return { enabled: null, applied: startHeight - 1, last_market: 0, clean: null, next_order: whole ? 1 : null, next_fill: whole ? 1 : null,
      base: whole ? { trades: '0', sats: '0', seconds_micros: '0' } : null, tape_from: whole ? 1 : null,
      tape: { trades: '0', sats: '0', seconds_micros: '0', unvalued: 0, faults: 0, last_price: null }, scan: null, scanned: false, rescan_not_before: 0, rescans: 0,
      consistent: null, reconciled: null, undecoded: 0, summary: null, summary_height: null, genesis_time_micros: null, hour_micros: null, profile: null, candles_through: startHeight - 1 };
  };
  let cached = null;
  const load = () => { if (cached === null) { const stored = q.get.get(KEY)?.value; cached = stored === undefined ? fresh() : JSON.parse(stored); } return structuredClone(cached); };
  const save = (st) => { q.put.run(KEY, JSON.stringify(st)); cached = structuredClone(st); };
  /// A transaction of this store: when it fails, what was read of the state row is read again.
  const atomic = (work) => { try { return transaction(work); } catch (error) { cached = null; throw error; } };
  const mark = (kind, id) => { if (id !== null) q.mark.run(kind, id); };
  /// What is known of an order without a rule: its proven row, or the action that made it since the last proof.
  const orderFacts = (id) => {
    if (id === null) return null;
    const held = q.order.get(id);
    if (held) return { owner: held.owner, side: held.side, price: String(held.price) };
    return q.newOrderOf.get(id) ?? null;
  };
  function bucketsOf(timeMicros, price, sats, seconds) {
    for (const length of Object.values(COMPUTED_INTERVALS)) {
      const bucket = Math.floor(timeMicros / (length * 1e6)), held = q.bucket.get(length, bucket), p = BigInt(price);
      if (!held) q.putBucket.run(length, bucket, price, price, price, price, sats, seconds, 1);
      else q.putBucket.run(length, bucket, held.open, (p > BigInt(held.high) ? p : BigInt(held.high)).toString(), (p < BigInt(held.low) ? p : BigInt(held.low)).toString(), price, sum(held.sats, sats), sum(held.micros, seconds), held.trades + 1);
    }
  }
  /// The tape of the chain's hour `hour`, as a candle row, or null when it holds no trade of that hour.
  function tapeCandle(st, hour) {
    const from = Number(BigInt(st.genesis_time_micros) + BigInt(hour) * BigInt(st.hour_micros)), rows = q.tradesBetween.all(from, from + Number(st.hour_micros)).filter((row) => row.price !== null && row.sats !== null);
    if (rows.length === 0) return null;
    const prices = rows.map((row) => BigInt(row.price)), most = prices.reduce((a, b) => (b > a ? b : a)), least = prices.reduce((a, b) => (b < a ? b : a));
    return { close: rows.at(-1).price, high: most.toString(), low: least.toString(), open: rows[0].price, sats: rows.reduce((total, row) => total + BigInt(row.sats), 0n).toString(), seconds_micros: rows.reduce((total, row) => total + BigInt(row.seconds), 0n).toString(), trades: String(rows.length) };
  }
  /// Marks the chain's candles of the hours in which trades were followed since the last time. The length of the
  /// chain's hour comes with the first proof, so until then nothing is marked. Returns whether `st` changed.
  function markHours(st) {
    if (st.hour_micros === null || st.candles_through >= st.applied) return false;
    for (const row of q.tradeHours.all(Number(st.genesis_time_micros), Number(st.hour_micros), st.candles_through)) if (row.hour >= 0) q.mark.run('c', row.hour);
    st.candles_through = st.applied;
    return true;
  }
  const sameCandle = (a, b) => a !== null && b !== null && ['close', 'high', 'low', 'open', 'sats', 'seconds_micros', 'trades'].every((field) => a[field] === b[field]);

  const store = {
    state: load,
    /// Whether the network has the market, as a proof said: true, false, or null while none has been read.
    enabled: () => load().enabled,
    setEnabled(value) { atomic(() => { const st = load(); if (st.enabled !== value) { st.enabled = value; save(st); } }); },
    /// The first block above `after`, up to `through`, that holds an action of the market, or null.
    nextBlock: (after, through) => q.nextBlock.get(after, through).height ?? null,
    pending: () => q.marks.get().count,
    /// Every block up to `height` has been looked at and holds nothing more of the market.
    reach(height) { atomic(() => { const st = load(); if (st.applied < height) { st.applied = height; save(st); } }); },
    /// An index that does not begin with the chain, before its first proof: the blocks up to `height` are not
    /// followed. Their trades are not in the tape, and the book is read whole at the first proof.
    skip(height) { atomic(() => { const st = load(); if (st.next_order === null && st.applied < height) { st.applied = height; st.candles_through = height; save(st); } }); },
    /// Nothing is left to read: the book stands as proven through `height`.
    settle(height) { atomic(() => { const st = load(); if (st.clean !== null && st.clean < height) { st.clean = height; save(st); } }); },
    startScan(why) { atomic(() => { const st = load(); st.scan = { order: 1, fill: 1 }; st.scanned = false; st.rescans += 1; save(st); }); return why; },

    /// Follows the actions of the market in block `height`, in their order: marks the rows they touch, counts the
    /// ids of new orders and fills, and writes the tape. Returns the events of the block, for the event stream.
    apply(height) {
      return atomic(() => {
        const st = load(), block = q.block.get(height), events = [];
        for (const row of q.actions.all(height)) {
          const at = { id: `${height}.${row.idx}`, source: 'index', proven: false, hash: row.hash, height: String(height), index: row.idx, time: block.time };
          let action = null;
          try { action = SDK.decodeAction(new Uint8Array(row.raw)); } catch { action = null; }
          const p = action?.payload, sender = action?.from, order = idOf(p?.order), fill = idOf(p?.fill);
          const kind = action && action.networkId === networkId && action.kind >= MARKET_FIRST_KIND && action.kind <= MARKET_LAST_KIND ? action.kind : null;
          if (kind === null || ([51, 52, 53, 58].includes(kind) && order === null) || ([54, 55, 56, 57].includes(kind) && fill === null)) {
            // An action of the market that this build cannot read. What it touched is not known: every row is read again.
            st.undecoded += 1; st.consistent = false; st.scan = { order: 1, fill: 1 }; st.scanned = false;
            continue;
          }
          if (kind === 50) {
            const id = st.next_order++;
            q.newOrder.run(id, sender, p.side, p.price); q.made.run(height, row.idx, 'o', id); mark('o', id);
            events.push({ ...at, type: 'order', order: String(id), side: p.side, owner: sender, price: p.price, amount_micros: p.amount_micros });
          } else if (kind === 51 || kind === 58) {
            mark('o', order);
            events.push({ ...at, type: kind === 51 ? 'order_cancelled' : 'order_scripts', order: p.order, owner: sender });
          } else if (kind === 52 || kind === 53) {
            // The fill's seconds and satoshis are in the action; its price and the other party are the order's.
            const id = st.next_fill++, of = orderFacts(order), sell = kind === 52;
            const made = { order: p.order, side: sell ? 'sell' : 'buy', owner: sell ? of?.owner ?? null : sender, payer: sell ? sender : of?.owner ?? null, to: sell ? p.to : of?.owner ?? null, price: of?.price ?? null, amount_micros: p.amount_micros, sats: p.sats };
            q.putLedger.run(id, order, made.side, made.owner, made.payer, made.to, made.price, made.amount_micros, made.sats, 'derived_row');
            q.made.run(height, row.idx, 'f', id); mark('f', id); mark('o', order);
            events.push({ ...at, type: 'fill', fill: String(id), ...made });
          } else {
            const held = q.ledger.get(fill) ?? null;
            const parties = { fill: p.fill, order: held?.order_id == null ? null : String(held.order_id), side: held?.side ?? null, owner: held?.owner ?? null, payer: held?.payer ?? null, to: held?.recipient ?? null, price: held?.price ?? null };
            const end = (how, unpaid) => {
              q.putEnded.run(fill, height, row.idx, parties.owner, parties.payer, parties.to, JSON.stringify({ ...at, type: 'fill_ended', ...parties, how, unpaid_micros: unpaid?.amount ?? null, unpaid_sats: unpaid?.sats ?? null }));
              q.dropLedger.run(fill);
            };
            if (kind === 54) {
              let paid = null;
              try { paid = transactionOutputs(p.transaction)[Number(p.vout)]?.sats ?? null; } catch { paid = null; }
              const counts = held && paid !== null ? paymentOf(held.amount, held.sats, paid) : null;
              const trade = { ...at, type: 'payment', ...parties, sats: counts?.counted ?? null, seconds_micros: counts?.seconds ?? null, paid_sats: paid, full: counts?.full ?? null,
                bitcoin_txid: bitcoinTxid(p.transaction), vout: p.vout, bitcoin_block_hash: p.block_hash, basis: held?.basis ?? null };
              q.putTrade.run(height, row.idx, block.time_micros, fill, trade.price, trade.sats, trade.seconds_micros, JSON.stringify(trade));
              st.tape.trades = sum(st.tape.trades, 1);
              if (counts) {
                st.tape.sats = sum(st.tape.sats, counts.counted); st.tape.seconds_micros = sum(st.tape.seconds_micros, counts.seconds);
                if (trade.price !== null) { st.tape.last_price = trade.price; bucketsOf(block.time_micros, trade.price, counts.counted, counts.seconds); }
                if (counts.full) end('paid', { amount: '0', sats: '0' });
                else q.lowerLedger.run((BigInt(held.amount) - BigInt(counts.seconds)).toString(), (BigInt(held.sats) - BigInt(paid)).toString(), fill);
              }
              // The fill, its price or the output is not known here: the entry lacks numbers, and the tape says so.
              if (!counts || trade.price === null) st.tape.unvalued += 1;
              events.push(trade);
            } else {
              const how = { 55: 'expired', 56: 'released', 57: 'settled' }[kind];
              end(how, held ? { amount: held.amount, sats: held.sats } : null);
              events.push({ ...at, type: 'fill_ended', ...parties, how, unpaid_micros: held?.amount ?? null, unpaid_sats: held?.sats ?? null });
            }
            mark('f', fill);
            if (held?.order_id != null) mark('o', held.order_id);
          }
        }
        st.applied = height; st.last_market = height;
        save(st);
        return events;
      });
    },

    /// The rows one read asks for: those marked, then those of a reading of every row, at most as many of each
    /// as a selection names. The hours of trades applied since the last pass are marked first.
    wanted() {
      return atomic(() => {
        const st = load();
        if (markHours(st)) save(st);
        const most = SDK.MARKET_SELECTION, take = (kind, limit) => q.marked.all(kind, limit).map((row) => row.id);
        const orders = take('o', most.market_orders), fills = take('f', most.market_fills), candles = take('c', most.market_candles), scan = { order: null, fill: null };
        // A reading of every row waits for the first summary, which says how far the ids go.
        if (st.scan && st.next_order !== null) {
          for (const [name, list, limit, end] of [['order', orders, most.market_orders, st.next_order], ['fill', fills, most.market_fills, st.next_fill]]) {
            let next = st.scan[name];
            for (; list.length < limit && next < end; next++) if (!list.includes(next)) list.push(next);
            scan[name] = next;
          }
        }
        return { orders, fills, candles, scan: st.scan && st.next_order !== null ? scan : null };
      });
    },

    /// Stores what one verified read at `height` proved, and judges the index when nothing is left to read.
    /// `rows`: { orders, fills, candles } as maps from id to the proven row or null; `asked`: what `wanted` gave.
    /// Returns { complete, notes }: `notes` are the differences found, for the operator's log.
    proven({ height, genesis, hourMicros, profile, summary, rows, asked, now }) {
      return atomic(() => {
        const st = load(), notes = [], was = { consistent: st.consistent, reconciled: st.reconciled };
        const rescan = () => { st.scan = { order: 1, fill: 1 }; st.scanned = false; st.rescans += 1; st.consistent = false; };
        if (st.genesis_time_micros !== null && (st.genesis_time_micros !== genesis || st.hour_micros !== hourMicros)) throw new Error('The proven state is of another network than the one this index was filled from');
        st.enabled = true; st.genesis_time_micros = genesis; st.hour_micros = hourMicros; st.profile = profile;
        const nextOrder = idOf(summary.next_order), nextFill = idOf(summary.next_fill);
        if (nextOrder === null || nextFill === null) throw new Error('The proven summary counts more ids than this index can hold');
        if (st.next_order === null) {
          // The first proof of an index that does not begin with the chain: the tape begins after this height.
          st.base = { trades: summary.trades, sats: summary.sats, seconds_micros: summary.seconds_micros }; st.tape_from = height + 1;
          st.next_order = nextOrder; st.next_fill = nextFill; st.scan = { order: 1, fill: 1 };
        } else if (st.next_order !== nextOrder || st.next_fill !== nextFill) {
          notes.push(`the ids counted from the actions (next order ${st.next_order}, next fill ${st.next_fill}) are not the proven ones (${nextOrder}, ${nextFill}): every row is read again`);
          st.next_order = nextOrder; st.next_fill = nextFill; rescan();
        }
        for (const [id, row] of rows.orders) {
          if (row) q.putOrder.run(id, row.side, Number(row.price), row.owner, row.open && row.amount_micros !== '0' ? 1 : 0, height, JSON.stringify(row)); else q.dropOrder.run(id);
          q.unmark.run('o', id);
        }
        for (const [id, row] of rows.fills) {
          const held = q.ledger.get(id) ?? null;
          if (row) {
            // The working copy must be the proven row: a difference means the tape was written from wrong numbers.
            if (held && (held.amount !== row.amount_micros || held.sats !== row.sats || (held.price !== null && held.price !== row.price))) { notes.push(`fill ${id}: the tape's copy (${held.amount} microseconds, ${held.sats} satoshis) is not the proven row (${row.amount_micros}, ${row.sats})`); st.tape.faults += 1; }
            // A fill the tape took for ended (a payment counted as in full, an action read as its end) and that the state still holds.
            if (q.ended.get(id)) { notes.push(`fill ${id} was taken for ended and the state still holds it`); q.dropEnded.run(id); st.tape.faults += 1; }
            q.putFill.run(id, Number(row.order), row.owner, row.payer, row.to, height, JSON.stringify(row));
            q.putLedger.run(id, Number(row.order), row.side, row.owner, row.payer, row.to, row.price, row.amount_micros, row.sats, 'proven_row');
          } else {
            q.dropFill.run(id);
            if (held) {
              // The fill is gone and no action seen here ended it.
              notes.push(`fill ${id} has ended and no indexed action ended it`); st.tape.faults += 1;
              if (!q.ended.get(id)) q.putEnded.run(id, height, 0, held.owner, held.payer, held.recipient, JSON.stringify({ id: null, source: 'index', proven: false, hash: null, height: null, index: null, time: null, type: 'fill_ended', fill: String(id), order: held.order_id == null ? null : String(held.order_id), side: held.side, owner: held.owner, payer: held.payer, to: held.recipient, price: held.price, how: 'unknown', unpaid_micros: null, unpaid_sats: null }));
              q.dropLedger.run(id);
            }
          }
          q.unmark.run('f', id);
        }
        for (const [hour, row] of rows.candles) {
          // A tape that began after the chain's first trade may lack trades of an hour: nothing is said of its candles.
          const whole = st.base.trades === '0', ours = tapeCandle(st, hour);
          if (row) {
            const same = sameCandle(row, ours);
            q.putCandle.run(hour, height, whole ? (same ? 1 : 0) : null, JSON.stringify(row));
            if (whole && !same) notes.push(`hour ${hour}: the tape is not the candle the chain keeps`);
          } else {
            q.dropCandle.run(hour);
            if (ours !== null) notes.push(`hour ${hour}: the tape holds trades and the chain keeps no candle`);
          }
          q.unmark.run('c', hour);
        }
        if (asked.scan && st.scan) {
          st.scan = { order: Math.max(st.scan.order, asked.scan.order), fill: Math.max(st.scan.fill, asked.scan.fill) };
          if (st.scan.order >= st.next_order && st.scan.fill >= st.next_fill) { st.scan = null; st.scanned = true; }
        }
        st.summary = summary; st.summary_height = height;
        markHours(st);
        const complete = q.marks.get().count === 0 && st.scan === null;
        if (complete) {
          // Everything held is as proven at this height or unchanged since its proof: now the counts must agree.
          const orders = q.orders.get().count, fills = q.fills.get().count;
          if (String(orders) === summary.orders && String(fills) === summary.fills) st.consistent = true;
          else {
            // Said when it is found, and again after each whole reading that did not mend it; not at every pass between.
            if (was.consistent !== false || st.scanned) notes.push(`the index holds ${orders} orders and ${fills} fills, the proven summary counts ${summary.orders} and ${summary.fills}`);
            st.consistent = false;
            // Read every row again: at once after a first difference, after a pause when a whole reading did not mend it.
            if (st.scanned) st.rescan_not_before = now + RESCAN_PAUSE_MS; else rescan();
          }
          const expected = { trades: sum(st.base.trades, st.tape.trades), sats: sum(st.base.sats, st.tape.sats), seconds_micros: sum(st.base.seconds_micros, st.tape.seconds_micros) };
          const sums = expected.trades === summary.trades && expected.sats === summary.sats && expected.seconds_micros === summary.seconds_micros;
          const last = st.tape.last_price === null || st.tape.last_price === summary.last_price;
          const faults = q.candleFaults.get().count;
          // A tape that disagrees stays so: it is said once, when it is found.
          const first = was.reconciled !== false;
          if (!sums && first) notes.push(`the tape adds up to ${expected.trades} trades, ${expected.sats} satoshis and ${expected.seconds_micros} microseconds, the proven summary to ${summary.trades}, ${summary.sats} and ${summary.seconds_micros}`);
          if (!last && first) notes.push(`the last price of the tape (${st.tape.last_price}) is not the summary's (${summary.last_price})`);
          if (faults && first) notes.push(`${faults} of the chain's candles differ from the tape`);
          st.reconciled = sums && last && st.tape.unvalued === 0 && st.tape.faults === 0 && faults === 0;
          st.scanned = false;
          if (st.scan === null) { st.clean = Math.max(st.clean ?? 0, height); q.dropNewOrders.run(); }
        }
        save(st);
        return { complete: complete && st.scan === null, notes };
      });
    },

    // ---- what the API reads
    /// The book of one side, best price first: sell ascending, buy descending, ties by id. `after`: { price, id } or null.
    /// The order or the fill that the action at place `idx` of block `height` made, as this index counted it:
    /// `{ order }` for an order (kind 50), `{ fill }` for a take or a sale (kinds 52, 53), and null for an action
    /// that made neither. `undefined` while the index has not followed that block: the caller says "not yet".
    /// The id is counted from the actions in their order (ids are dense), and held to the proven counters at every
    /// proof; it is the index's word, like every list. The row itself is asked with its proof, by this id.
    madeBy(height, idx) {
      const st = load();
      if (st.next_order === null || st.applied < height) return undefined;
      const found = q.madeAt.get(height, idx);
      return found ? { [found.kind === 'o' ? 'order' : 'fill']: String(found.id) } : null;
    },
    book(side, after, limit) {
      const from = after ?? (side === 'sell' ? { price: 0, id: 0 } : { price: Number.MAX_SAFE_INTEGER, id: 0 });
      return q[side === 'sell' ? 'sells' : 'buys'].all(from.price, from.price, from.id, limit);
    },
    /// The first `levels` prices of one side with what stands at each, and whether more rows than DEPTH_SCAN were needed.
    depth(side, levels) {
      const out = [];
      let after = null, read = 0, cut = false;
      scan: for (;;) {
        const rows = store.book(side, after, 500);
        for (const row of rows) {
          const order = JSON.parse(row.row), price = String(row.price);
          if (out.at(-1)?.price !== price) { if (out.length === levels) break scan; out.push({ price, amount: 0n, orders: 0, takeable: 0n }); }
          const level = out.at(-1), amount = BigInt(order.amount_micros);
          level.amount += amount; level.orders += 1;
          if (takesFill(order)) level.takeable += amount;
          after = { price: row.price, id: row.id };
          if (++read >= DEPTH_SCAN) { cut = true; break scan; }
        }
        if (rows.length < 500) break;
      }
      return { levels: out.map((level) => ({ price: level.price, amount_micros: level.amount.toString(), takeable_micros: level.takeable.toString(), sats: SDK.marketSats(level.amount.toString(), level.price), orders: level.orders })), truncated: cut };
    },
    order: (id) => q.order.get(id) ?? null,
    fill: (id) => q.fill.get(id) ?? null,
    ended: (id) => { const row = q.ended.get(id); return row ? JSON.parse(row.body) : null; },
    ordersOf: (owner, limit) => q.ordersOf.all(owner, limit),
    /// The open fills `account` has a part in, newest first, each with its roles.
    fillsOf(account, limit) {
      const found = new Map();
      for (const role of ['payer', 'owner', 'recipient']) for (const row of q[`fills_${role}`].all(account, limit)) { const entry = found.get(row.id) ?? { row, roles: [] }; entry.roles.push(role === 'recipient' ? 'to' : role); found.set(row.id, entry); }
      return [...found.values()].sort((a, b) => b.row.id - a.row.id);
    },
    /// The fills that ended and in which `account` had a part, newest first, below a place in the chain.
    endedOf(account, cursor, limit) {
      const found = new Map();
      for (const role of ['payer', 'owner', 'recipient']) for (const row of q[`ended_${role}`].all(account, cursor.height, cursor.index, limit)) { const entry = found.get(row.fill_id) ?? { ...row, roles: [] }; entry.roles.push(role === 'recipient' ? 'to' : role); found.set(row.fill_id, entry); }
      return [...found.values()].sort((a, b) => b.height - a.height || b.idx - a.idx).slice(0, limit);
    },
    trades: (order, cursor, limit) => q[`trades_${order}`].all(cursor.height, cursor.index, limit),
    tradesOfFill: (id, limit) => q.tradesOfFill.all(id, limit).map((row) => JSON.parse(row.body)),
    candles: (from, to, limit) => q.candles.all(from, to, limit),
    buckets: (seconds, from, to, limit) => q.buckets.all(seconds, from, to, limit),
    /// The newest relayed Bitcoin headers the index holds (kind 40), as the actions carry them: 80 bytes each, in hexadecimal.
    recentHeaders(actions) {
      const out = [];
      for (const row of q.headers.all(actions)) { try { const headers = SDK.decodeAction(new Uint8Array(row.raw)).payload?.headers; if (Array.isArray(headers)) out.push(...headers); } catch { /* not one this build reads */ } }
      return out;
    },
  };
  return store;
}
/// How long a reading of every row that did not mend a difference waits before the next one.
export const RESCAN_PAUSE_MS = 60000;

/// Whether an order can take a fill now, as far as its own row says: it is open, offers something, and has a
/// receiving script that has not served (sell) or a free place among its open fills (buy). Not judged here:
/// whether its owner still stands (spec/market.md, 6.10) and whether the Bitcoin header chain is fresh.
export function takesFill(order) {
  if (!order.open || order.amount_micros === '0') return false;
  return order.side === 'sell' ? order.scripts.some((entry) => entry.fill === undefined && entry.used !== true) : Number(order.fills) < SDK.MARKET_LIMITS.buyFills;
}
/// An order as a list shows it: the proven row's own fields, and what is counted from them.
export function orderView(stored) {
  const row = JSON.parse(stored.row), sell = row.side === 'sell';
  return {
    id: row.id, side: row.side, owner: row.owner, price: row.price, amount_micros: row.amount_micros, sats: SDK.marketSats(row.amount_micros, row.price), min_sats: row.min_sats,
    confirmations: row.confirmations, pay_blocks: row.pay_blocks, deposit_ppm: row.deposit_ppm, min_deposit_micros: row.min_deposit_micros, bond_micros: row.bond_micros,
    open: row.open, takes_fill: takesFill(row), open_fills: sell ? row.scripts.filter((entry) => entry.fill !== undefined).length : Number(row.fills),
    free_scripts: sell ? row.scripts.filter((entry) => entry.fill === undefined && entry.used !== true).length : null, forms: sell ? null : row.forms,
    key: row.key, created: row.created, proven_at_height: String(stored.proven_at),
  };
}
/// A fill as a list shows it: the proven row, the last Bitcoin height that still counts for it, and when it was proven.
export function fillView(stored) {
  const row = JSON.parse(stored.row);
  return { ...row, last_height: SDK.marketFillLastHeight(row), proven_at_height: String(stored.proven_at) };
}

/// A refusal of the node or of the verifier that will not change for this height: the node no longer keeps the
/// state (it keeps its last blocks), or the height lies below what this service's light client can verify.
const UNPROVABLE = /proof version pruned|HEADER_ROLLBACK|below the highest trusted|CHECKPOINT_ROLLBACK/;

/// Follows the indexed blocks and keeps the market's tables right. Options:
/// - `store`: the index (openIndex), whose `market` is the store above;
/// - `read(selection, height)`: a verified state at exactly that height ({ state }), or a rejection;
/// - `enabled()`: whether the network has the market, as far as the service knows from any proof (true, false, null);
/// - `onEvents(events)`: called with the events of a block once they are stored;
/// - `batchesPerStep` (32): reads of one round; `auditMs` (600000): how often an idle index reads the summary and
///   compares again; `pauseMs` (1000): the pause after a height that could not be read; `now`, `log`.
export function createMarketFollower({ store, read, enabled = () => null, onEvents = () => {}, now = Date.now, log = () => {}, batchesPerStep = 32, auditMs = 600000, pauseMs = 1000, pollMs = 500 }) {
  const market = store.market;
  const status = { last_error: null, failures: 0, catching_up: false, not_before: 0, audited_at: null, running: false };
  let stopped = true, running = null, timer = null, wake = null, again = false;

  /// One read at `height` and what it proved, stored. Returns whether nothing is left to read.
  async function pass(height) {
    const asked = market.wanted();
    const selection = { include_market: true, ...(asked.orders.length ? { market_orders: asked.orders.map(String) } : {}), ...(asked.fills.length ? { market_fills: asked.fills.map(String) } : {}), ...(asked.candles.length ? { market_candles: asked.candles.map(String) } : {}) };
    const { state } = await read(selection, height);
    if (String(state?.height) !== String(height)) throw new Error('The state read is not of the height asked');
    if (!SDK.marketSetting(state)) { market.setEnabled(false); return true; }
    // The SDK's readers check the form of every row once more and refuse a row that was not asked for.
    const rows = { orders: new Map(asked.orders.map((id) => [id, SDK.marketOrder(state, String(id))])), fills: new Map(asked.fills.map((id) => [id, SDK.marketFill(state, String(id))])), candles: new Map(asked.candles.map((hour) => [hour, SDK.marketCandle(state, String(hour))])) };
    const rules = SDK.marketRules(state);
    const result = market.proven({ height, genesis: String(state.genesis.genesis_time_micros), hourMicros: rules.hourMicros, profile: rules.profile, summary: SDK.marketSummary(state), rows, asked, now: now() });
    for (const note of result.notes) log('error', 'the market index differs from the proven state', { height, detail: note });
    return result.complete;
  }

  /// One round: follow the new blocks, then read what they touched. Returns true when there is more to do at once.
  async function step() {
    if (enabled() === false || market.enabled() === false) return false;
    const high = store.high();
    if (high === null) return false;
    // A state is proven by the header of the next block: the newest state that can be read is the one before the
    // newest indexed block. So the newest block is not followed yet. Everything followed then lies at or below the
    // height that is read, and what is read is compared with what was followed, row for row and sum for sum.
    const height = high - 1;
    let st = market.state();
    if (st.next_order === null) {
      // Not from the chain's first block and nothing proven yet: the index begins with the state that is read first.
      if (height < 1) return false;
      market.skip(height);
    } else {
      for (let next, done = 0; (next = market.nextBlock(st.applied, height)) !== null; st = market.state()) {
        const events = market.apply(next);
        if (events.length) { try { onEvents(events); } catch (error) { log('error', 'a listener of market events failed', { error: String(error?.message).slice(0, 120) }); } }
        // A long history is followed without holding up the requests that are being answered.
        if (++done % 50 === 0) await new Promise((resolve) => setImmediate(resolve));
      }
      market.reach(height);
    }
    // When the newest block holds no action of the market, the rows of the state before it are its rows too.
    const reached = market.nextBlock(height, high) === null ? high : height;
    st = market.state();
    const due = st.clean === null || st.scan !== null || market.pending() > 0;
    // A whole reading did not mend a difference with the summary: after its pause, every row is read once more.
    if (!due && st.consistent === false && now() >= st.rescan_not_before) { market.startScan(); return true; }
    const audit = !due && (status.audited_at === null || now() - status.audited_at >= auditMs);
    if (!due && !audit) { market.settle(reached); return false; }
    if (height < 1 || now() < status.not_before) return false;
    try {
      for (let batch = 0; batch < batchesPerStep; batch++) {
        if (await pass(height)) { status.audited_at = now(); status.failures = 0; status.last_error = null; status.catching_up = false; market.settle(reached); return false; }
        if (enabled() === false || market.enabled() === false) return false;
      }
      status.failures = 0; status.last_error = null; status.catching_up = false;
      return true;
    } catch (error) {
      const text = String(error?.cause ?? error?.message ?? error);
      status.failures += 1; status.not_before = now() + pauseMs;
      if (UNPROVABLE.test(text)) { status.catching_up = true; status.last_error = { code: 'state_not_held', at: now() }; return false; }
      status.last_error = { code: 'read_failed', at: now() };
      // The first failure and every twentieth are logged; the count is in the status meanwhile.
      if (status.failures % 20 === 1) log('warn', 'the market index could not read a proven state; trying again', { height, failures: status.failures, detail: text.replace(/[^\x20-\x7e]/g, ' ').slice(0, 160) });
      return false;
    }
  }

  return {
    step,
    /// Follows the index until `stop()`. A new block wakes it (`wake`).
    start() {
      if (!stopped) return; stopped = false; status.running = true;
      const loop = async () => {
        while (!stopped) {
          let more = false;
          try { more = await step(); } catch (error) { log('error', 'the market index failed a round', { error: String(error?.message).replace(/[^\x20-\x7e]/g, ' ').slice(0, 160) }); }
          if (stopped) break;
          if (more || again) { again = false; continue; }
          await new Promise((resolve) => { wake = resolve; timer = setTimeout(resolve, pollMs); timer.unref?.(); });
          wake = null;
        }
      };
      running = loop();
    },
    wake() { again = true; wake?.(); },
    async stop() { stopped = true; status.running = false; clearTimeout(timer); wake?.(); await running; running = null; },
    /// Where the index of the market stands, as every answer of the market says it.
    status() {
      const st = market.state();
      return {
        as_of_height: st.clean === null ? null : String(st.clean), ready: st.clean !== null, consistent: st.clean !== null && st.consistent === true,
        pending_rows: market.pending(), reading_every_row: st.scan !== null,
        tape_reconciled: st.clean === null ? null : st.reconciled, tape_from_height: st.tape_from === null ? null : String(st.tape_from), tape_complete: st.tape_from === 1,
        tape_trades: st.tape.trades, tape_unvalued: st.tape.unvalued, tape_faults: st.tape.faults, unread_actions: st.undecoded,
        waiting_for_indexer: status.catching_up, last_error: status.last_error && { code: status.last_error.code, at: new Date(status.last_error.at).toISOString() },
      };
    },
  };
}
