// The market's index (market-index.mjs) and the market routes of the HTTP API (api.mjs).
//
// - The chain is a fake: a small model of the market's rules (spec/market.md, section 6) that answers a verified
//   state at any height it still "keeps", as a node does. It is the test's stand-in for the engine, not a part of the
//   index: the index never works a row out, and these tests compare what it holds with what the model proves.
// - The actions are real bytes: built and decoded by the SDK, and for one test the thirteen actions the engine itself
//   signed and accepted (spec/market-vectors.json), with their real Bitcoin transactions.
// - One test reads through the real verifier: the engine's proven rows (verifier-v4/fixtures/market-engine.json),
//   served by a fake RPC, honest and then altered.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { openIndex, describeAction, IndexerError, KIND_NAMES } from './indexer.mjs';
import { createMarketFollower, paymentOf, COMPUTED_INTERVALS } from './market-index.mjs';
import { createApiService, createStateReader, ROUTES } from './api.mjs';
import { transactionOutputs } from './bitcoin-address.mjs';

const SDK = globalThis.TimeSDK;
const engine = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/market-engine.json', import.meta.url), 'utf8'));
const vectors = JSON.parse(await readFile(new URL('../spec/market-vectors.json', import.meta.url), 'utf8'));
const NETWORK = vectors.network_id, TRUST = engine.cases.trading.trust, CHAIN = TRUST.chain_id;
const GENESIS = Number(TRUST.genesis_time_micros), HOUR = 60e6, PRICE = '250000000';
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const W = (byte) => `0014${byte.repeat(20)}`;
const keyOf = (account) => sha(Buffer.from(`key of ${account}`)).toString('hex');
const real = vectors.actions.find((action) => action.name === 'proof').payload;

/// A signed action as a block carries it. The signature is not looked at by an index: validators did that.
const act = (kind, payload, from, nonce = '1') => Buffer.from(SDK.concat(SDK.buildAction({ networkId: NETWORK, from, nonce, authEpoch: '0', publicKey: keyOf(from), kind, payload }), new Uint8Array(64)));
/// A Bitcoin transaction without witness data that pays `sats` to `script` in its one output.
function payment(script, sats, salt = 1) {
  const value = Buffer.alloc(8); value.writeBigUInt64LE(BigInt(sats));
  const to = Buffer.from(script, 'hex');
  return Buffer.concat([Buffer.from('02000000', 'hex'), Buffer.from([1]), Buffer.alloc(32, salt), Buffer.alloc(4), Buffer.from([0]), Buffer.from('ffffffff', 'hex'), Buffer.from([1]), value, Buffer.from([to.length]), to, Buffer.alloc(4)]).toString('hex');
}
const make = {
  sell: (from, amount, scripts, more = {}) => act(50, SDK.marketSellOrder({ amountMicros: amount, price: PRICE, scripts, confirmations: '1', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0', ...more }), from),
  buy: (from, amount, more = {}) => act(50, SDK.marketBuyOrder({ amountMicros: amount, price: PRICE, forms: ['p2wpkh'], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '100000', ...more }), from),
  cancel: (from, order) => act(51, SDK.marketCancel({ order }), from),
  take: (from, order, amount, to = from, price = PRICE) => act(52, SDK.marketTake({ order, amountMicros: amount, price, to }), from),
  sellTo: (from, order, amount, script, price = PRICE) => act(53, SDK.marketSell({ order, amountMicros: amount, price, confirmations: '1', script }), from),
  proof: (from, fill, script, sats, salt = 1) => act(54, SDK.marketProof({ fill, blockHash: 'ab'.repeat(32), transaction: payment(script, sats, salt), coinbase: real.coinbase, vout: '0', merkleProof: real.merkle_proof }), from),
  expire: (from, fill) => act(55, SDK.marketExpire({ fill }), from),
  release: (from, fill) => act(56, SDK.marketRelease({ fill }), from),
  settle: (from, fill) => act(57, SDK.marketSettle({ fill }), from),
  scripts: (from, order, scripts) => act(58, SDK.marketNewScripts({ order, scripts }), from),
};

/// The fake chain: one block a second from the genesis time, a model of the market's rows, and the state of every
/// height. `oldest` is the oldest state the "node" still keeps; `mangle(state, height)` lets a test make it lie.
function fakeChain({ market = true } = {}) {
  const m = { orders: new Map(), fills: new Map(), candles: new Map(), scripts: new Map(), summary: { fills: 0, next_fill: 1, next_order: 1, orders: 0, sats: 0n, seconds: 0n, trades: 0, last_price: null } };
  const states = new Map(), blocks = [];
  const chain = { tip: 0, oldest: 1, down: false, mangle: null, reads: [], spendKeys: new Map(), frozen: new Set(), blocks, bestTip: '30d79b56c402e15b89927969bf0246170cdec94d70f57040620b03717c61e3cb', halted: null };
  const timeOf = (height) => GENESIS + height * 1e6;
  chain.timeOf = timeOf;
  const big = (text) => BigInt(text), str = (value) => value.toString();
  function endFill(fill, back) {
    const order = m.orders.get(fill.order);
    if (fill.side === 'sell') {
      const slot = order.scripts.find((entry) => entry.fill === fill.id);
      delete slot.fill; slot.used = true;
      if (back && order.open) order.amount_micros = str(big(order.amount_micros) + big(fill.amount_micros));
    } else order.fills = str(big(order.fills) - 1n);
    m.scripts.set(fill.script, {});
    m.fills.delete(fill.id); m.summary.fills -= 1;
    const open = [...m.fills.values()].filter((other) => other.order === order.id).length;
    if (open === 0 && (!order.open || order.amount_micros === '0')) drop(order);
  }
  function drop(order) {
    for (const entry of order.scripts ?? []) if (entry.used !== true) m.scripts.delete(entry.script);
    m.orders.delete(order.id); m.summary.orders -= 1;
  }
  function apply(raw, height) {
    const a = SDK.decodeAction(new Uint8Array(raw)), p = a.payload, moment = { height: String(height), time_micros: String(timeOf(height)) };
    if (a.kind === 50) {
      const id = String(m.summary.next_order++), shared = { amount_micros: p.amount_micros, confirmations: p.confirmations, created: moment, deposit_ppm: p.deposit_ppm, id, key: a.publicKey, min_sats: p.min_sats, open: true, owner: a.from, pay_blocks: p.pay_blocks, price: p.price, side: p.side };
      if (p.side === 'sell') { m.orders.set(id, { ...shared, bond_micros: '0', min_deposit_micros: p.min_deposit_micros, scripts: p.scripts.map((script) => ({ script })) }); for (const script of p.scripts) m.scripts.set(script, { order: id }); }
      else m.orders.set(id, { ...shared, bond_micros: str((big(p.amount_micros) * big(p.deposit_ppm) + 999999n) / 1000000n), min_deposit_micros: '0', fills: '0', forms: p.forms });
      m.summary.orders += 1;
    } else if (a.kind === 51) {
      const order = m.orders.get(p.order);
      order.amount_micros = '0'; order.bond_micros = '0';
      if ([...m.fills.values()].some((fill) => fill.order === order.id)) order.open = false; else drop(order);
    } else if (a.kind === 52 || a.kind === 53) {
      const order = m.orders.get(p.order), id = String(m.summary.next_fill++), sell = a.kind === 52, amount = big(p.amount_micros);
      const shared = { amount_micros: p.amount_micros, created: moment, id, opened_micros: String(timeOf(height) - GENESIS), order: order.id, pay_blocks: order.pay_blocks, price: order.price, sats: p.sats, start_hash: '11'.repeat(32), start_height: '5' };
      if (sell) {
        const slot = order.scripts.find((entry) => entry.fill === undefined && entry.used !== true), share = (amount * big(order.deposit_ppm) + 999999n) / 1000000n;
        slot.fill = id;
        m.fills.set(id, { ...shared, confirmations: order.confirmations, deposit_micros: str(share > big(order.min_deposit_micros) ? share : big(order.min_deposit_micros)), owner: order.owner, payer: a.from, script: slot.script, side: 'sell', to: p.to });
      } else {
        const deposit = amount === big(order.amount_micros) ? big(order.bond_micros) : big(order.bond_micros) * amount / big(order.amount_micros);
        order.bond_micros = str(big(order.bond_micros) - deposit); order.fills = str(big(order.fills) + 1n);
        m.fills.set(id, { ...shared, confirmations: p.confirmations, deposit_micros: str(deposit), owner: a.from, payer: order.owner, script: p.script, side: 'buy', to: order.owner });
        m.scripts.set(p.script, { fill: id });
      }
      order.amount_micros = str(big(order.amount_micros) - amount); m.summary.fills += 1;
    } else if (a.kind === 54) {
      const fill = m.fills.get(p.fill), paid = big(transactionOutputs(p.transaction)[Number(p.vout)].sats), due = big(fill.sats), amount = big(fill.amount_micros), full = paid >= due;
      const seconds = full ? amount : amount * paid / due, counted = full ? due : paid, hour = String(Math.floor((timeOf(height) - GENESIS) / HOUR)), price = big(fill.price);
      const candle = m.candles.get(hour) ?? { close: fill.price, high: fill.price, low: fill.price, open: fill.price, sats: '0', seconds_micros: '0', trades: '0' };
      m.candles.set(hour, { close: fill.price, high: str(price > big(candle.high) ? price : big(candle.high)), low: str(price < big(candle.low) ? price : big(candle.low)), open: candle.open, sats: str(big(candle.sats) + counted), seconds_micros: str(big(candle.seconds_micros) + seconds), trades: str(big(candle.trades) + 1n) });
      m.summary.trades += 1; m.summary.sats += counted; m.summary.seconds += seconds; m.summary.last_price = fill.price;
      if (full) endFill(fill, false);
      else { const back = big(fill.deposit_micros) * seconds / amount; fill.amount_micros = str(amount - seconds); fill.sats = str(due - paid); fill.deposit_micros = str(big(fill.deposit_micros) - back); }
    } else if (a.kind === 55 || a.kind === 56) endFill(m.fills.get(p.fill), true);
    else if (a.kind === 57) endFill(m.fills.get(p.fill), false);
    else if (a.kind === 58) {
      const order = m.orders.get(p.order);
      order.scripts = [...order.scripts.filter((entry) => entry.used !== true), ...p.scripts.map((script) => ({ script }))]; order.key = a.publicKey;
      for (const script of p.scripts) m.scripts.set(script, { order: order.id });
    }
  }
  const copy = () => structuredClone({ orders: [...m.orders], fills: [...m.fills], candles: [...m.candles], scripts: [...m.scripts], summary: { ...m.summary, sats: str(m.summary.sats), seconds: str(m.summary.seconds) } });
  /// Adds one block with these actions and returns its height.
  chain.block = (...raws) => {
    const height = ++chain.tip;
    for (const raw of raws) apply(raw, height);
    blocks.push(raws); states.set(height, copy());
    return height;
  };
  /// Adds a block whose actions the model does not execute (bytes no rule of the model knows).
  chain.quiet = (...raws) => { const height = ++chain.tip; blocks.push(raws); states.set(height, copy()); return height; };
  chain.at = (height) => { const s = structuredClone(states.get(height)); return { orders: new Map(s.orders), fills: new Map(s.fills), candles: new Map(s.candles), scripts: new Map(s.scripts), summary: s.summary }; };
  chain.state = (height, selection = {}) => {
    const s = chain.at(height), pick = (list, rows) => Object.fromEntries((list ?? []).map((id) => [id, market ? rows.get(id) ?? null : null]));
    const summary = { fills: String(s.summary.fills), ...(s.summary.trades ? { last_price: s.summary.last_price } : {}), next_fill: String(s.summary.next_fill), next_order: String(s.summary.next_order), orders: String(s.summary.orders), sats: s.summary.sats, seconds_micros: s.summary.seconds, trades: String(s.summary.trades) };
    const state = {
      network_id: NETWORK, height: String(height), time_micros: String(timeOf(height)), genesis: { genesis_time_micros: String(GENESIS) }, stopped_micros: '0',
      config: market ? { market: true, profile: 'laboratory', waits_survive_stops: true } : { waits_survive_stops: true }, ...(market ? { market_micros: '0' } : {}),
      accounts: (selection.ids ?? []).map((id) => ({ id, name: `person_${id}`, balance: '1000000000', nonce: '1', auth_epoch: '0', devices: [{ public_key: chain.spendKeys.get(id) ?? keyOf(id), can_manage: true, can_spend: true }] })),
      security: (selection.ids ?? []).filter((id) => chain.frozen.has(id)).map((id) => ({ account: id, frozen_until_elapsed_micros: String(timeOf(height) - GENESIS + 1e9), pending_root: null })),
      ...(selection.include_bitcoin ? { bitcoin: { meta: { best_height: 7, best_tip: chain.bestTip, halted: chain.halted, config: { network: 'regtest', max_tip_age_secs: 7200, max_future_secs: 7200 } } } } : {}),
      market: { ...(selection.include_market ? { summary: market ? summary : null, heights: market ? { entries: [{ at: '0', height: '0' }, { at: '5000000', height: '7' }] } : null } : {}),
        orders: pick(selection.market_orders, s.orders), fills: pick(selection.market_fills, s.fills), accounts: {}, scripts: pick(selection.market_scripts, s.scripts), candles: pick(selection.market_candles, s.candles) },
    };
    return chain.mangle ? chain.mangle(state, height, selection) ?? state : state;
  };
  /// The reader of a state at a height, as the service's own: it refuses a height the node no longer keeps, and one
  /// whose next block is not made yet.
  chain.readAt = async (selection, { at } = {}) => {
    const height = Number(at);
    chain.reads.push({ height, selection });
    if (chain.down) throw new Error('node behind');
    if (height < chain.oldest) throw new Error('Could not obtain compatible certified V4 state: Pinned state unavailable: proof version pruned');
    if (height >= chain.tip) throw new Error('Could not obtain compatible certified V4 state: The RPC refused the request');
    return { verified: true, requested: selection, proof: { height: String(height), entries: [] }, state: chain.state(height, selection) };
  };
  chain.readHead = async (selection) => { if (chain.down) throw new Error('node behind'); return { verified: true, requested: selection, proof: { height: String(chain.tip - 1), entries: [] }, state: chain.state(chain.tip - 1, selection) }; };
  return chain;
}
/// Writes the chain's blocks from `from` up to `through` into an index, as the indexer does.
function indexBlocks(store, chain, through = chain.tip, from = (store.high() ?? store.startHeight - 1) + 1) {
  for (let height = from; height <= through; height++) {
    const raws = chain.blocks[height - 1];
    const actions = raws.map((raw, idx) => ({ ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx }));
    store.writeBlock({ previousChecked: height > store.startHeight, events: [], actions,
      block: { height, hash: sha(Buffer.from(`block ${height}`)).toString('hex'), previous_hash: sha(Buffer.from(`block ${height - 1}`)).toString('hex'), time_micros: chain.timeOf(height), time: new Date(chain.timeOf(height) / 1000).toISOString().replace('Z', '000Z'), proposer: 'AA'.repeat(20), app_hash: 'BB'.repeat(32), data_hash: 'CC'.repeat(32) } });
  }
}
/// An index with the market's follower over a fake chain.
async function follow(run, { chain = fakeChain(), startHeight = 1, ...options } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-market-'));
  const store = openIndex({ filename: path.join(directory, 'index.sqlite'), networkId: NETWORK, chainId: CHAIN, startHeight });
  const lab = { chain, store, logs: [], events: [], clock: 1000 };
  lab.follower = createMarketFollower({ store, read: (selection, height) => chain.readAt(selection, { at: String(height) }), now: () => lab.clock, pauseMs: 0, auditMs: 1e12,
    log: (level, message, fields) => lab.logs.push({ level, message, ...fields }), onEvents: (events) => lab.events.push(...events), ...options });
  /// Indexes what the chain has and lets the follower work until it has nothing more to do.
  lab.sync = async (through) => { indexBlocks(store, chain, through); for (let i = 0; i < 200 && await lab.follower.step(); i++); return lab.follower.status(); };
  try { await run(lab); } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
}
/// What the index holds, against what the chain proves at `height`: every order and fill row, and nothing more.
function sameBook(store, chain, height) {
  const proven = chain.at(height), ids = (rows) => [...rows.keys()].sort((a, b) => Number(a) - Number(b));
  for (const [kind, rows, held] of [['order', proven.orders, (id) => store.market.order(Number(id))], ['fill', proven.fills, (id) => store.market.fill(Number(id))]]) {
    for (const id of ids(rows)) assert.deepEqual(JSON.parse(held(id)?.row ?? 'null'), rows.get(id), `${kind} ${id} at height ${height}`);
    for (let id = 1; id < proven.summary[kind === 'order' ? 'next_order' : 'next_fill']; id++) if (!rows.has(String(id))) assert.equal(held(String(id)), null, `${kind} ${id} is gone at height ${height}`);
  }
}
const tapeOf = (store) => store.market.trades('asc', { height: 0, index: 0 }, 1000).map((row) => JSON.parse(row.body));

test('the SDK names the kinds of the market, and the rule of a payment is the SDK\'s', () => {
  assert.deepEqual(Object.fromEntries(Object.entries(SDK.MARKET_KINDS).map(([name, kind]) => [`market_${name}`, kind])), Object.fromEntries(Object.entries(SDK.KINDS).filter(([, kind]) => kind >= 50 && kind <= 58)));
  assert.deepEqual([KIND_NAMES[50], KIND_NAMES[54], KIND_NAMES[58]], ['market_order', 'market_proof', 'market_scripts']);
  // What the index counts for a payment is what TimeSDK.marketFillBuys gives, on the engine's own proven fill.
  const fill = engine.cases.trading.market.fills['2'];
  for (const paid of ['1', '1499', '1500', '2999', '3000', '3001', '900000']) {
    const counted = paymentOf(fill.amount_micros, fill.sats, paid);
    assert.equal(counted.seconds, SDK.marketFillBuys(fill, paid), paid);
    assert.deepEqual([counted.full, counted.counted], [BigInt(paid) >= 3000n, BigInt(paid) >= 3000n ? '3000' : paid], paid);
  }
});

test('the book is the proven book of each height: orders, fills, parts, the rest, two proofs in one block', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    chain.block(make.sell('5', '100000000', [W('01'), W('02'), W('03')]));
    // The state of a block is proven by the header of the next one: the newest block is not followed yet, and nothing is guessed.
    let status = await lab.sync();
    assert.deepEqual([status.ready, status.as_of_height, status.pending_rows, chain.reads.length, lab.events.length], [false, null, 0, 0, 0]);
    chain.block();
    status = await lab.sync();
    assert.deepEqual([status.ready, status.as_of_height, status.consistent, status.tape_reconciled, status.tape_complete, status.pending_rows], [true, '2', true, true, true, 0]);
    sameBook(store, chain, 1);
    chain.block(make.buy('6', '50000000'), make.take('6', '1', '40000000', '8'));
    chain.block(make.sellTo('5', '2', '20000000', W('04')));
    chain.block();
    status = await lab.sync();
    assert.deepEqual([status.as_of_height, status.consistent], ['5', true]);
    sameBook(store, chain, 4);
    assert.equal(JSON.parse(store.market.fill(1).row).sats, '10000');
    // A part, then two proofs for the same fill in one block: a second part and the rest.
    chain.block(make.proof('7', '1', W('01'), '4000', 1));
    chain.block();
    await lab.sync();
    sameBook(store, chain, 6);
    assert.deepEqual([JSON.parse(store.market.fill(1).row).sats, JSON.parse(store.market.fill(1).row).amount_micros], ['6000', '24000000']);
    chain.block(make.proof('7', '1', W('01'), '2500', 2), make.proof('8', '1', W('01'), '9999', 3));
    chain.block();
    status = await lab.sync();
    sameBook(store, chain, 8);
    assert.equal(store.market.fill(1), null);
    const tape = tapeOf(store);
    assert.deepEqual(tape.map((t) => [t.id, t.fill, t.price, t.paid_sats, t.sats, t.seconds_micros, t.full, t.basis]), [
      ['6.0', '1', PRICE, '4000', '4000', '16000000', false, 'proven_row'],
      // The row before the second proof of the block is the proven row; before the third it is that row less the part.
      ['8.0', '1', PRICE, '2500', '2500', '10000000', false, 'proven_row'],
      ['8.1', '1', PRICE, '9999', '3500', '14000000', true, 'derived_row'],
    ]);
    assert.deepEqual([tape[0].owner, tape[0].payer, tape[0].to, tape[0].order, tape[0].side, tape[0].vout, tape[0].bitcoin_block_hash], ['5', '6', '8', '1', 'sell', '0', 'ab'.repeat(32)]);
    assert.match(tape[0].bitcoin_txid, /^[0-9a-f]{64}$/);
    // The sums of the tape are the summary's at the same height, and the hour's candle is the chain's.
    const proven = chain.at(8).summary;
    assert.deepEqual([proven.trades, proven.sats, proven.seconds], [3, '10000', '40000000']);
    assert.deepEqual([status.tape_reconciled, status.tape_trades, status.tape_unvalued, status.consistent], [true, '3', 0, true]);
    assert.deepEqual(store.market.candles(0, 10, 10).map((row) => [row.hour, row.matches, JSON.parse(row.row)]), [[0, 1, chain.at(8).candles.get('0')]]);
    assert.deepEqual(store.market.ended(1).how, 'paid');
    assert.equal(lab.logs.length, 0, JSON.stringify(lab.logs));
    // The events of the blocks, in their order, for a stream.
    assert.deepEqual(lab.events.map((e) => [e.id, e.type]), [['1.0', 'order'], ['3.0', 'order'], ['3.1', 'fill'], ['4.0', 'fill'], ['6.0', 'payment'], ['8.0', 'payment'], ['8.1', 'payment']]);
    assert.deepEqual([lab.events[2].fill, lab.events[2].order, lab.events[2].owner, lab.events[2].payer, lab.events[2].to, lab.events[2].sats], ['1', '1', '5', '6', '8', '10000']);
    assert.deepEqual([lab.events[3].fill, lab.events[3].side, lab.events[3].owner, lab.events[3].payer, lab.events[3].to], ['2', 'buy', '5', '6', '6']);
    // Blocks without an action of the market cost no read, and the book stays as of the newest block.
    const reads = chain.reads.length;
    chain.block(); chain.block();
    assert.deepEqual([(await lab.sync()).as_of_height, chain.reads.length], ['11', reads]);
  });
});

test('a fill ends by expiry, by release and by settling; an order is cancelled while a fill is open', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    chain.block(make.sell('5', '100000000', [W('01'), W('02'), W('03'), W('04')]), make.buy('6', '50000000'));
    chain.block(make.take('6', '1', '20000000'), make.take('7', '1', '20000000', '9'), make.take('8', '1', '20000000'), make.sellTo('8', '2', '50000000', W('09')));
    chain.block(make.expire('3', '1'));
    chain.block(make.release('9', '2'));
    chain.block(make.proof('8', '3', W('03'), '1000'));
    chain.block();
    let status = await lab.sync();
    sameBook(store, chain, 5);
    assert.deepEqual([store.market.ended(1).how, store.market.ended(2).how, store.market.ended(3), status.consistent, status.tape_reconciled], ['expired', 'released', null, true, true]);
    assert.deepEqual([store.market.ended(2).owner, store.market.ended(2).payer, store.market.ended(2).to, store.market.ended(2).unpaid_micros, store.market.ended(2).unpaid_sats], ['5', '7', '9', '20000000', '5000']);
    // The order is cancelled while fill 3 is open: its row stays, closed, with nothing on offer; the book does not list it.
    chain.block(make.cancel('5', '1'));
    chain.block();
    await lab.sync();
    sameBook(store, chain, 7);
    assert.deepEqual([JSON.parse(store.market.order(1).row).open, store.market.order(1).offered, store.market.book('sell', null, 10).length], [false, 0, 0]);
    // The seller settles the rest of fill 3: the fill ends, and the closed order goes with its last fill.
    chain.block(make.settle('5', '3'), make.settle('8', '4'));
    chain.block();
    status = await lab.sync();
    sameBook(store, chain, 9);
    assert.deepEqual([store.market.order(1), store.market.order(2), store.market.fill(3), store.market.ended(3).how, store.market.ended(4).how], [null, null, null, 'settled', 'settled']);
    assert.deepEqual([store.market.ended(3).unpaid_sats, store.market.ended(3).unpaid_micros], ['4000', '16000000']);
    assert.deepEqual([status.consistent, status.tape_reconciled, status.tape_trades], [true, true, '1']);
    // What an account has ended, with its role in each, newest first.
    assert.deepEqual(store.market.endedOf('8', { height: Number.MAX_SAFE_INTEGER, index: 0 }, 10).map((row) => [row.fill_id, row.roles, JSON.parse(row.body).how]), [[4, ['owner'], 'settled'], [3, ['payer', 'to'], 'settled']]);
    assert.deepEqual(store.market.endedOf('9', { height: Number.MAX_SAFE_INTEGER, index: 0 }, 10).map((row) => [row.fill_id, row.roles]), [[2, ['to']]]);
    assert.equal(lab.logs.length, 0, JSON.stringify(lab.logs));
  });
});

test('the engine\'s own actions (spec/market-vectors.json): the tape counts what the chain counted', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    // The thirteen actions in the order the engine accepted them, one in a block, as bytes it signed.
    for (const action of vectors.actions) chain.block(Buffer.from(action.signed_hex, 'hex'));
    chain.block();
    const status = await lab.sync();
    sameBook(store, chain, 13);
    assert.deepEqual([status.consistent, status.tape_reconciled, status.tape_complete, status.unread_actions], [true, true, true, 0]);
    // Fill 1 was 40 seconds for 10,000 satoshis: an output of 4,000 bought 16 seconds, and one of 6,000 the rest.
    assert.deepEqual(tapeOf(store).map((t) => [t.fill, t.paid_sats, t.sats, t.seconds_micros, t.full, t.vout]), [['1', '4000', '4000', '16000000', false, '0'], ['1', '6000', '6000', '24000000', true, '1']]);
    assert.deepEqual([store.market.ended(1).how, store.market.ended(2).how, store.market.ended(3).how, store.market.ended(4).how], ['paid', 'settled', 'released', 'expired']);
    assert.deepEqual(lab.events.map((e) => e.type), ['order', 'order', 'order_scripts', 'fill', 'fill', 'payment', 'payment', 'fill', 'fill_ended', 'fill_ended', 'fill', 'fill_ended', 'order_cancelled']);
  });
});

test('a first sync far behind the head ends with the right book and a whole tape', async () => {
  const chain = fakeChain();
  chain.block(make.sell('5', '100000000', [W('01'), W('02'), W('03')]), make.buy('6', '50000000'));
  chain.block(make.take('6', '1', '40000000', '8'));
  chain.block(make.proof('7', '1', W('01'), '4000', 1));
  chain.block(make.proof('7', '1', W('01'), '6000', 2), make.take('9', '1', '20000000'));
  chain.block(make.release('9', '2'));
  chain.block(make.sell('7', '8000000', [W('07')], { price: '300000000' }), make.take('8', '3', '8000000', '8', '300000000'));
  chain.block(make.proof('8', '3', W('07'), '2400', 3));
  for (let i = 0; i < 60; i++) chain.block();
  chain.block(make.cancel('6', '2'));
  for (let i = 0; i < 40; i++) chain.block();
  chain.block(make.take('6', '1', '20000000'));
  chain.block();
  await follow(async (lab) => {
    const { store } = lab;
    // The node keeps the states of its last blocks only. The indexer comes up in steps; until it is within reach,
    // no state of its height can be read, and the book is not served.
    chain.oldest = chain.tip - 5;
    for (const through of [3, 8, 50, 90]) {
      const status = await lab.sync(through);
      assert.deepEqual([status.ready, status.as_of_height, status.waiting_for_indexer], [false, null, true], `at ${through}`);
    }
    assert.ok(store.market.pending() > 0);
    const status = await lab.sync();
    assert.deepEqual([status.ready, status.as_of_height, status.consistent, status.tape_reconciled, status.tape_complete, status.waiting_for_indexer, status.pending_rows], [true, String(chain.tip), true, true, true, false, 0]);
    sameBook(store, chain, chain.tip - 1);
    // Every read was at one height the node kept, never a mix.
    assert.deepEqual([...new Set(chain.reads.filter((read) => read.height >= chain.oldest).map((read) => read.height))], [chain.tip - 1]);
    // The trades of the blocks whose state was never read: counted from the actions, and the sums are the summary's.
    assert.deepEqual(tapeOf(store).map((t) => [t.id, t.fill, t.price, t.sats, t.seconds_micros, t.full, t.basis]), [
      ['3.0', '1', PRICE, '4000', '16000000', false, 'derived_row'], ['4.0', '1', PRICE, '6000', '24000000', true, 'derived_row'], ['7.0', '3', '300000000', '2400', '8000000', true, 'derived_row']]);
    assert.deepEqual([store.market.ended(1).how, store.market.ended(2).how, store.market.ended(3).how, store.market.ended(3).owner], ['paid', 'released', 'paid', '7']);
    // The chain's candle of the first minute is the tape's; so are the computed ones.
    assert.deepEqual(store.market.candles(0, 5, 5).map((row) => [row.hour, row.matches, JSON.parse(row.row).trades, JSON.parse(row.row).high, JSON.parse(row.row).low]), [[0, 1, '3', '300000000', PRICE]]);
    const minute = store.market.buckets(60, 0, Number.MAX_SAFE_INTEGER, 5);
    assert.deepEqual(minute.map((b) => [b.open, b.high, b.low, b.close, b.sats, b.micros, b.trades]), [[PRICE, '300000000', PRICE, '300000000', '12400', '48000000', 3]]);
    assert.equal(lab.logs.filter((entry) => entry.level === 'error').length, 0, JSON.stringify(lab.logs));
  }, { chain });
  // An index that begins later than the chain: the book is read whole at its first proof, and the tape begins there.
  await follow(async (lab) => {
    const status = await lab.sync();
    assert.deepEqual([status.ready, status.as_of_height, status.consistent, status.tape_reconciled, status.tape_complete, status.tape_from_height, status.tape_trades], [true, String(chain.tip), true, true, false, String(chain.tip), '0']);
    sameBook(lab.store, chain, chain.tip - 1);
    // A candle from before the tape began is kept as proven, and nothing is said about the tape of its hour.
    chain.block(make.proof('6', '4', W('02'), '5000', 9));
    chain.block();
    const after = await lab.sync();
    sameBook(lab.store, chain, chain.tip - 1);
    assert.deepEqual([after.tape_reconciled, after.tape_trades, tapeOf(lab.store)[0].basis, tapeOf(lab.store)[0].seconds_micros], [true, '1', 'proven_row', '20000000']);
    assert.deepEqual(lab.store.market.candles(0, 5, 5).map((row) => [row.hour, row.matches]), [[1, null]]);
  }, { chain, startHeight: 100 });
});

test('counts that disagree with the summary: every row is read again, and answers say so meanwhile', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    chain.block(make.sell('5', '100000000', [W('01')]), make.sell('6', '50000000', [W('02')]), make.buy('7', '50000000'));
    chain.block();
    assert.equal((await lab.sync()).consistent, true);
    // A read that leaves a row out which the summary counts. (A real proof cannot do this; a fault in the index
    // could lose a row all the same, and the count is what finds it.)
    chain.mangle = (state) => { if (state.market.orders['2']) state.market.orders['2'] = null; };
    chain.block(make.scripts('6', '2', [W('08')]));
    chain.block();
    let status = await lab.sync();
    assert.deepEqual([status.consistent, status.ready, store.market.order(2)], [false, true, null]);
    assert.ok(lab.logs.some((entry) => entry.level === 'error' && /holds 2 orders and 0 fills, the proven summary counts 3 and 0/.test(entry.detail)), JSON.stringify(lab.logs));
    // The reading of every row did not mend it, so the next one waits; it is not tried in a loop.
    const reads = chain.reads.length;
    await lab.sync();
    assert.equal(chain.reads.length, reads);
    // The fault is gone: after the pause every row is read again, and the index agrees with the summary.
    chain.mangle = null;
    lab.clock += 61000;
    status = await lab.sync();
    assert.deepEqual([status.consistent, status.reading_every_row], [true, false]);
    sameBook(store, chain, chain.tip - 1);
    // An action of the market that the SDK of this service cannot read (a form of a later release, say): what it
    // touched is not known, so every row is read again, and the index says how many such actions it met.
    const body = Buffer.from('{"order":"1","until":"9"}'), length = Buffer.alloc(4); length.writeUInt32BE(body.length);
    const numbers = Buffer.alloc(24); numbers.writeBigUInt64BE(5n, 0); numbers.writeBigUInt64BE(9n, 8);
    const unreadable = Buffer.concat([Buffer.from('TCDEVNET-ACTION-V1\0'), Buffer.from(NETWORK, 'hex'), Buffer.from([51]), numbers, Buffer.from(keyOf('5'), 'hex'), length, body, Buffer.alloc(64)]);
    assert.deepEqual([describeAction(unreadable, NETWORK).opaque, describeAction(unreadable, NETWORK).kind], [true, 51]);
    chain.quiet(unreadable);
    chain.block();
    const before = chain.reads.length;
    status = await lab.sync();
    assert.deepEqual([status.unread_actions, status.consistent, status.reading_every_row, lab.events.length], [1, true, false, 4]);
    // Orders 1 to 3 were all read again, at the one height.
    assert.deepEqual(chain.reads.slice(before).flatMap((read) => read.selection.market_orders ?? []).sort(), ['1', '2', '3']);
    sameBook(store, chain, chain.tip - 1);
  });
});

test('a tape that disagrees with the chain is said in the status and in the log, once, and never served as right', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    chain.block(make.sell('5', '100000000', [W('01'), W('02')]));
    chain.block(make.take('6', '1', '40000000'));
    chain.block(make.proof('6', '1', W('01'), '4000', 1));
    chain.block();
    assert.equal((await lab.sync()).tape_reconciled, true);
    // The chain counted another sum than the index did (a rule this index reads differently, say).
    chain.mangle = (state) => { if (state.market.summary) state.market.summary.sats = String(BigInt(state.market.summary.sats) + 1n); };
    chain.block(make.take('7', '1', '20000000'));
    chain.block();
    let status = await lab.sync();
    assert.deepEqual([status.tape_reconciled, status.consistent, status.ready], [false, true, true]);
    const said = () => lab.logs.filter((entry) => entry.level === 'error' && /the tape adds up to 1 trades, 4000 satoshis and 16000000 microseconds, the proven summary to 1, 4001 and 16000000/.test(entry.detail)).length;
    assert.equal(said(), 1, JSON.stringify(lab.logs));
    chain.block(make.cancel('5', '1'));
    chain.block();
    status = await lab.sync();
    assert.deepEqual([status.tape_reconciled, said()], [false, 1]);
    // A proven fill row that is not what the tape had counted from: the tape was written from wrong numbers, and
    // no later agreement of the sums makes it right again.
    chain.mangle = (state) => { if (state.market.fills['2']) state.market.fills['2'].sats = '2499'; };
    chain.block(make.proof('7', '2', W('02'), '2500', 2));
    chain.block();
    status = await lab.sync();
    assert.deepEqual([status.tape_reconciled, status.tape_faults], [false, 1]);
    assert.ok(lab.logs.some((entry) => /fill 2: the tape's copy \(10000000 microseconds, 2500 satoshis\) is not the proven row \(10000000, 2499\)/.test(entry.detail)), JSON.stringify(lab.logs));
    chain.mangle = null;
    chain.block(); chain.block(make.release('7', '2')); chain.block();
    status = await lab.sync();
    assert.deepEqual([status.tape_reconciled, status.tape_faults, status.consistent, store.market.fill(2)], [false, 1, true, null]);
  });
});

test('a node that is down, or that answers what no proof covers, changes nothing', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    chain.block(make.sell('5', '100000000', [W('01')]));
    chain.block();
    await lab.sync();
    chain.block(make.take('6', '1', '40000000'));
    chain.block();
    chain.down = true;
    let status = await lab.sync();
    assert.deepEqual([status.as_of_height, status.pending_rows, status.last_error.code, JSON.parse(store.market.order(1).row).amount_micros, store.market.fill(1)], ['2', 2, 'read_failed', '100000000', null]);
    assert.ok(lab.logs.some((entry) => entry.level === 'warn' && /could not read a proven state/.test(entry.message)));
    // A state of another height than the one asked is refused, whatever it holds.
    chain.down = false;
    chain.mangle = (state) => ({ ...state, height: String(Number(state.height) + 1) });
    status = await lab.sync();
    assert.deepEqual([status.as_of_height, status.pending_rows, status.last_error.code], ['2', 2, 'read_failed']);
    // A row in a form the SDK does not know is refused with the whole read.
    chain.mangle = (state) => { if (state.market.fills['1']) state.market.fills['1'].sats = '0'; };
    status = await lab.sync();
    assert.deepEqual([status.as_of_height, status.pending_rows, store.market.fill(1)], ['2', 2, null]);
    chain.mangle = null;
    status = await lab.sync();
    assert.deepEqual([status.as_of_height, status.pending_rows, status.last_error, status.consistent], ['4', 0, null, true]);
    sameBook(store, chain, 3);
  });
});

test('an action of the market in every block: the book follows one block behind, and the running follower keeps up', async () => {
  await follow(async (lab) => {
    const { chain, store } = lab;
    chain.block(make.sell('5', '100000000', [W('01'), W('02'), W('03'), W('04')]));
    const seen = [];
    for (const [i, action] of [make.take('6', '1', '10000000'), make.take('7', '1', '10000000'), make.proof('6', '1', W('01'), '2500', 1), make.release('7', '2'), make.take('8', '1', '10000000')].entries()) {
      chain.block(action);
      const status = await lab.sync();
      // The newest block always holds an action, so its state is read with the next one.
      seen.push([status.as_of_height, status.consistent, status.tape_reconciled]);
      sameBook(store, chain, i + 1);
    }
    assert.deepEqual(seen, [['1', true, true], ['2', true, true], ['3', true, true], ['4', true, true], ['5', true, true]]);
    // Started, the follower is woken by new blocks and works by itself.
    lab.follower.start();
    chain.block(make.proof('8', '3', W('03'), '2500', 2)); chain.block(make.cancel('5', '1')); chain.block();
    indexBlocks(store, chain); lab.follower.wake();
    for (let i = 0; i < 400 && lab.follower.status().as_of_height !== String(chain.tip); i++) await new Promise((resolve) => setTimeout(resolve, 5));
    await lab.follower.stop();
    assert.deepEqual([lab.follower.status().as_of_height, lab.follower.status().tape_trades, store.market.order(1)], [String(chain.tip), '2', null]);
    sameBook(store, chain, chain.tip - 1);
    assert.equal(lab.logs.length, 0, JSON.stringify(lab.logs));
  });
});

/// A CometBFT RPC that serves the engine's own proof of the fixture `name`: its signed header and validators, and
/// the proof entries as the node's query answers them. `alter(entries)` changes what the node says.
function fixtureRpc(name, alter = (entries) => entries) {
  const item = engine.cases[name], light = item.proof.light_block, header = light.signed_header.header;
  return async (method, parameters = {}) => {
    if (method === '/commit') { if (parameters.height !== undefined && parameters.height !== header.height) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { signed_header: light.signed_header }; }
    if (method === '/validators') return { block_height: parameters.height, total: String(light.validators.length), validators: parameters.height === header.height ? light.validators : light.next_validators };
    if (method === '/abci_query') {
      if (parameters.height !== item.proof.height) return { response: { code: 1, log: 'proof version pruned' } };
      const body = { height: item.proof.height, root: header.app_hash.toLowerCase(), entries: alter(structuredClone(item.proof.entries)), history_proofs: item.proof.history_proofs };
      return { response: { code: 0, height: item.proof.height, value: Buffer.from(JSON.stringify(body)).toString('base64') } };
    }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}
/// The installed verifier at the fixture's own time.
const verifierAt = (nowMs) => ({ verifyTrust: (trust) => verifier.verifyTrust(trust, nowMs), verifyLightUpdate: (block, trust) => verifier.verifyLightUpdate(block, trust, nowMs), verifyViewProof: (proof, trust, request) => verifier.verifyViewProof(proof, trust, request, nowMs) });
const memory = () => { const held = new Map(); return { getItem: async (key) => held.get(key) ?? null, setItem: async (key, value) => { held.set(key, value); } }; };

test('with the real verifier: the engine\'s proven rows fill the index, and a row the node altered or withheld is refused', async () => {
  const item = engine.cases.trading, height = Number(item.proof.height);
  const reader = (alter) => createStateReader({ rpc: fixtureRpc('trading', alter), trust: item.trust, verifier: verifierAt(item.now_ms), storage: memory() });
  // The index begins two blocks before the proven state; the chain's own blocks are not needed for this.
  const run = async (alter, check) => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'time-market-real-'));
    const store = openIndex({ filename: path.join(directory, 'index.sqlite'), networkId: NETWORK, chainId: CHAIN, startHeight: height });
    const logs = [], read = reader(alter);
    const follower = createMarketFollower({ store, read: (selection, at) => read(selection, { at: String(at) }), pauseMs: 0, log: (level, message, fields) => logs.push({ level, message, ...fields }) });
    try {
      const empty = { blocks: [[], []], timeOf: (h) => GENESIS + h * 1e6 };
      for (const h of [height, height + 1]) { empty.blocks[h - 1] = []; indexBlocks(store, empty, h, h); }
      for (let i = 0; i < 20 && await follower.step(); i++);
      await check({ store, status: follower.status(), logs });
    } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
  };
  await run(undefined, ({ store, status, logs }) => {
    assert.deepEqual([status.ready, status.as_of_height, status.consistent, status.tape_reconciled, status.tape_complete, status.tape_from_height], [true, String(height + 1), true, true, false, String(height + 1)]);
    for (const id of ['1', '2']) assert.deepEqual(JSON.parse(store.market.order(Number(id)).row), item.market.orders[id]);
    for (const id of ['2', '3']) assert.deepEqual(JSON.parse(store.market.fill(Number(id)).row), item.market.fills[id]);
    assert.deepEqual([store.market.fill(1), store.market.order(3), store.market.state().summary], [null, null, item.market.summary]);
    assert.equal(logs.length, 0, JSON.stringify(logs));
  });
  // The node changes one byte of a proven row, or leaves the row's proof out: the verifier refuses the answer, and
  // nothing of it reaches the index.
  const orderKey = Buffer.concat([Buffer.from('market/order/'), Buffer.from('0000000000000001', 'hex')]).toString('hex');
  assert.ok(item.proof.entries.some((entry) => entry.key_hex === orderKey));
  // More seconds on offer than the order has: the row as a node that lies would give it.
  const altered = (entries) => entries.map((entry) => (entry.key_hex === orderKey ? { ...entry, value_b64: Buffer.from(Buffer.from(entry.value_b64, 'base64').toString('utf8').replace('"amount_micros":"40000000"', '"amount_micros":"90000000"')).toString('base64') } : entry));
  assert.notDeepEqual(altered(item.proof.entries), item.proof.entries);
  const withheld = (key) => (entries) => entries.filter((entry) => entry.key_hex !== key);
  // An altered row is refused wherever it stands in an answer. The summary is asked first, by itself: where the
  // node only withholds another row, the summary's own proof is whole and is taken, and the read of the rows is refused.
  for (const [alter, summary] of [[altered, null], [withheld(orderKey), item.market.summary], [withheld(Buffer.from('market/meta').toString('hex')), null]]) {
    await run(alter, ({ store, status, logs }) => {
      assert.deepEqual([status.ready, status.as_of_height, status.last_error?.code, store.market.order(1), store.market.order(2), store.market.fill(2), store.market.state().summary], [false, null, 'read_failed', null, null, null, summary]);
      assert.ok(logs.some((entry) => entry.level === 'warn'));
    });
  }
});

// ------------------------------------------------------------------ the routes of the API
const openapi = JSON.parse(await readFile(new URL('./api/openapi.json', import.meta.url), 'utf8'));
const deref = (schema) => { while (schema?.$ref) schema = schema.$ref.split('/').slice(1).reduce((at, key) => at[key], openapi); return schema; };
/// The properties and required fields of a schema, with those of its `allOf` parts.
function shape(schema) {
  const s = deref(schema) ?? {}, out = { properties: { ...(s.properties ?? {}) }, required: [...(s.required ?? [])] };
  for (const part of s.allOf ?? []) { const inner = shape(part); Object.assign(out.properties, inner.properties); out.required.push(...inner.required); }
  return out;
}
/// Checks an answer against its description: every required field is there, and no field is undescribed, in the
/// answer itself and in the items of its lists.
function described(route, status, body) {
  const template = Object.keys(openapi.paths).find((p) => new RegExp(`^${p.replace(/\{[a-z]+\}/g, '[^/]+')}$`).test(route.split('?')[0]));
  const answer = deref(openapi.paths[template].get.responses[String(status)]);
  assert.ok(answer, `${route}: status ${status} is not described`);
  const check = (value, schema, at) => {
    const s = shape(schema);
    for (const field of s.required) assert.ok(Object.hasOwn(value, field), `${at}: ${field} is missing`);
    for (const [field, inner] of Object.entries(value)) {
      assert.ok(Object.hasOwn(s.properties, field), `${at}: ${field} is not described`);
      const items = deref(s.properties[field])?.items;
      if (Array.isArray(inner) && items && inner[0] && typeof inner[0] === 'object') check(inner[0], items, `${at}.${field}[0]`);
    }
  };
  check(body, answer.content['application/json'].schema, `${route} ${status}`);
}
/// The API over a fake chain: blocks are written to its index as the indexer would, and the market's follower is
/// stepped by hand.
async function serve(run, { chain = fakeChain(), ...options } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-market-api-'));
  const lab = { chain, logs: [], clock: GENESIS / 1000 + 600000 };
  let service;
  try {
    service = await createApiService({ trust: TRUST, rpc: async () => { throw new IndexerError('RPC_REFUSED', 'no node in this test'); }, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false,
      now: () => lab.clock, log: (level, message, fields) => lab.logs.push({ level, message, ...fields }), readState: chain.readHead, readMarketState: chain.readAt, marketTiming: { pauseMs: 0, auditMs: 1e12 }, rateLimit: { perSecond: 1000, burst: 100000 }, ...options });
    lab.service = service; lab.store = service.store;
    lab.sync = async () => { indexBlocks(service.store, chain); for (let i = 0; i < 200 && await service.market.step(); i++); lab.clock += 1001; return service.market.status(); };
    lab.get = async (route) => {
      const response = await fetch(service.url + route), body = await response.json();
      described(route, response.status, body);
      return { status: response.status, body, headers: response.headers };
    };
    await run(lab);
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}

test('a network without the market answers plainly, with the proof where a state was read', async () => {
  const chain = fakeChain({ market: false });
  chain.block(); chain.block(); chain.block();
  await serve(async (lab) => {
    const status = await lab.sync();
    assert.deepEqual([status.ready, status.as_of_height], [false, null]);
    // A route that reads the state gives the proof of the state whose configuration has no market.
    const market = await lab.get('/v1/market');
    assert.deepEqual([market.status, market.body.error.code, market.body.source, market.body.state_height, typeof market.body.proof.how], [404, 'no_market', 'state_proof', '2', 'string']);
    for (const route of ['/v1/market/orders/1', '/v1/market/fills/1', `/v1/market/scripts/${W('01')}`]) {
      const answer = await lab.get(route);
      assert.deepEqual([answer.status, answer.body.error.code, answer.body.source], [404, 'no_market', 'state_proof'], route);
    }
    for (const route of ['/v1/market/orders?side=sell', '/v1/market/depth', '/v1/market/trades', '/v1/market/candles?interval=hour', '/v1/accounts/5/market']) {
      const answer = await lab.get(route);
      assert.deepEqual([answer.status, answer.body.error.code], [404, 'no_market'], route);
    }
    // The index of the market reads nothing more once a proof has said that there is no market.
    const reads = chain.reads.length;
    chain.block(); chain.block();
    await lab.sync();
    assert.equal(chain.reads.length, reads);
    assert.equal(lab.store.market.enabled(), false);
    assert.equal((await (await fetch(`${lab.service.url}/v1/health`)).json()).market, null);
  }, { chain });
});

test('the market routes: the book, the depth, single rows with their proof, an account, trades and candles', async () => {
  await serve(async (lab) => {
    const { chain } = lab;
    chain.block(make.sell('5', '100000000', [W('01'), W('02')]), make.sell('6', '30000000', [W('11')], { price: '240000000' }), make.sell('7', '10000000', [W('21')]));
    chain.block(make.buy('8', '50000000', { price: '200000000' }), make.buy('9', '20000000', { price: '210000000' }), make.buy('5', '20000000', { price: '200000000' }));
    // Before the book has been proven once, a list says so; a single row is answered with its proof all the same.
    indexBlocks(lab.store, chain);
    const early = await lab.get('/v1/market/orders?side=sell');
    assert.deepEqual([early.status, early.body.error.code, early.headers.get('retry-after'), early.body.market_index.ready], [503, 'market_index_not_ready', '5', false]);
    assert.equal((await lab.get('/v1/market/orders/1')).status, 200);
    chain.block();
    let status = await lab.sync();
    assert.deepEqual([status.ready, status.as_of_height, status.consistent], [true, '3', true]);

    // The market itself: the proven summary and rules, the header chain, and where the index stands.
    const market = (await lab.get('/v1/market')).body;
    assert.deepEqual([market.source, market.state_height, market.market, market.rules.profile, market.rules.hourMicros, market.summary.orders, market.summary.next_order, market.last_recorded_price, market.held_micros], ['state_proof', '2', true, 'laboratory', '60000000', '6', '7', null, '0']);
    assert.deepEqual([market.bitcoin.network, market.bitcoin.best_height, market.bitcoin.halted, market.bitcoin.fresh, market.market_index.as_of_height, market.market_index.consistent, market.clock.hour], ['regtest', '7', false, null, '3', true, '0']);
    assert.deepEqual(market.proof.query, { include_market: true, include_bitcoin: true });

    // The book: sell by rising price, buy by falling price, ties by id; pages by cursor.
    const sells = (await lab.get('/v1/market/orders?side=sell')).body;
    assert.deepEqual([sells.source, sells.proven, sells.side, sells.has_more, sells.market_index.as_of_height, sells.index.indexed_height], ['index', false, 'sell', false, '3', '3']);
    assert.deepEqual(sells.items.map((o) => [o.id, o.price, o.owner, o.amount_micros, o.sats, o.min_sats, o.free_scripts, o.open_fills, o.takes_fill, o.proven_at_height]), [['2', '240000000', '6', '30000000', '7200', '1000', 1, 0, true, '2'], ['1', PRICE, '5', '100000000', '25000', '1000', 2, 0, true, '2'], ['3', PRICE, '7', '10000000', '2500', '1000', 1, 0, true, '2']]);
    assert.deepEqual([sells.items[0].confirmations, sells.items[0].pay_blocks, sells.items[0].deposit_ppm, sells.items[0].min_deposit_micros, sells.items[0].forms, sells.items[0].created.height], ['1', '6', '50000', '0', null, '1']);
    const paged = [];
    for (let cursor = null, page; ; cursor = page.next_cursor) {
      page = (await lab.get(`/v1/market/orders?side=sell&limit=1${cursor ? `&cursor=${cursor}` : ''}`)).body;
      paged.push(...page.items.map((o) => o.id));
      if (!page.has_more) { assert.equal(page.next_cursor, '250000000.3'); break; }
    }
    assert.deepEqual(paged, ['2', '1', '3']);
    const buys = (await lab.get('/v1/market/orders?side=buy&limit=2')).body;
    assert.deepEqual([buys.items.map((o) => [o.id, o.price, o.bond_micros, o.forms, o.free_scripts]), buys.has_more, buys.next_cursor], [[['5', '210000000', '2000000', ['p2wpkh'], null], ['4', '200000000', '5000000', ['p2wpkh'], null]], true, '200000000.4']);
    assert.deepEqual((await lab.get(`/v1/market/orders?side=buy&cursor=${buys.next_cursor}`)).body.items.map((o) => o.id), ['6']);
    for (const [route, code] of [['/v1/market/orders', 'invalid_side'], ['/v1/market/orders?side=up', 'invalid_side'], ['/v1/market/orders?side=sell&cursor=3.0', 'invalid_cursor'], ['/v1/market/orders?side=sell&price=1', 'unknown_parameter'], ['/v1/market/depth?levels=0', 'invalid_levels'],
      ['/v1/market/orders/0', 'invalid_order'], ['/v1/market/fills/x', 'invalid_fill'], ['/v1/market/scripts/0014ab', 'invalid_script'], ['/v1/market/candles', 'invalid_interval'], ['/v1/market/candles?interval=1h', 'invalid_interval'], ['/v1/market/candles?interval=hour&from=9&to=8', 'invalid_time'], ['/v1/market/candles?interval=hour&from=01', 'invalid_time']]) {
      const refused = await lab.get(route);
      assert.deepEqual([refused.status, refused.body.error.code], [400, code], route);
    }
    const depth = (await lab.get('/v1/market/depth?levels=2')).body;
    assert.deepEqual([depth.levels, depth.truncated, depth.last_recorded_price, depth.sell, depth.buy.map((l) => [l.price, l.amount_micros, l.orders])], [2, false, null,
      [{ price: '240000000', amount_micros: '30000000', takeable_micros: '30000000', sats: '7200', orders: 1 }, { price: PRICE, amount_micros: '110000000', takeable_micros: '110000000', sats: '27500', orders: 2 }], [['210000000', '20000000', 1], ['200000000', '70000000', 2]]]);

    // Fills: 8 takes for 9 from order 1; 6 takes the only script of order 3; 7 sells to the buy order of 9.
    chain.block(make.take('8', '1', '40000000', '9'), make.take('6', '3', '4000000'), make.sellTo('7', '5', '20000000', W('31'), '210000000'));
    chain.block(make.proof('3', '1', W('01'), '4000', 1));
    chain.block(make.proof('3', '1', W('01'), '6000', 2), make.release('6', '2'));
    chain.block();
    status = await lab.sync();
    assert.deepEqual([status.as_of_height, status.consistent, status.tape_reconciled, status.tape_trades], ['7', true, true, '2']);
    // An order whose scripts have all served is on offer and takes no fill: the depth counts it apart.
    const after = (await lab.get('/v1/market/depth')).body;
    assert.deepEqual([after.last_recorded_price, after.sell[1]], [PRICE, { price: PRICE, amount_micros: '70000000', takeable_micros: '60000000', sats: '17500', orders: 2 }]);
    assert.deepEqual((await lab.get('/v1/market/orders?side=sell')).body.items.map((o) => [o.id, o.amount_micros, o.free_scripts, o.takes_fill]), [['2', '30000000', 1, true], ['1', '60000000', 1, true], ['3', '10000000', 0, false]]);

    // One order with its proof, and whether its owner stands at that state.
    const order = (await lab.get('/v1/market/orders/1')).body;
    assert.deepEqual([order.source, order.state_height, order.order, order.sats, order.takes_fill, order.owner_stands], ['state_proof', '6', chain.at(6).orders.get('1'), '15000', true, { stands: true, key_can_spend: true, frozen: false }]);
    assert.deepEqual(order.proof.query, { market_orders: ['1'], ids: ['5'], include_security: true });
    // The key that made the order is no longer a spending key of its owner; then the owner is frozen.
    chain.spendKeys.set('5', keyOf('another device')); lab.clock += 1001;
    assert.deepEqual((await lab.get('/v1/market/orders/1')).body.owner_stands, { stands: false, key_can_spend: false, frozen: false });
    chain.spendKeys.delete('5'); chain.frozen.add('5'); lab.clock += 1001;
    assert.deepEqual((await lab.get('/v1/market/orders/1')).body.owner_stands, { stands: false, key_can_spend: true, frozen: true });
    chain.frozen.clear(); lab.clock += 1001;
    const none = await lab.get('/v1/market/orders/9');
    assert.deepEqual([none.status, none.body.error.code, none.body.order, none.body.source, none.body.state_height], [404, 'order_not_found', null, 'state_proof', '6']);

    // One fill with its proof: what is still to pay, its order, and what the index saw of it.
    const fill = (await lab.get('/v1/market/fills/3')).body;
    assert.deepEqual([fill.fill, fill.order.id, fill.last_height, fill.expiry.possible, fill.expiry.reason, fill.indexed.ended, fill.indexed.payments], [chain.at(6).fills.get('3'), '5', '11', false, 'height', null, []]);
    assert.deepEqual([fill.fill.side, fill.fill.owner, fill.fill.payer, fill.fill.to, fill.fill.sats, fill.fill.script], ['buy', '7', '9', '9', '4200', W('31')]);
    const paid = await lab.get('/v1/market/fills/1');
    assert.deepEqual([paid.status, paid.body.error.code, paid.body.fill, paid.body.indexed.ended.how, paid.body.indexed.payments.map((t) => [t.sats, t.seconds_micros, t.full])], [404, 'fill_not_found', null, 'paid', [['4000', '16000000', false], ['6000', '24000000', true]]]);
    assert.deepEqual([(await lab.get('/v1/market/fills/2')).body.indexed.ended.how, (await lab.get('/v1/market/fills/8')).body.indexed.ended], ['released', null]);

    // A receiving script: free, listed by an order, the script of a fill against a buy order, used.
    const script = async (text) => { const body = (await lab.get(`/v1/market/scripts/${text}`)).body; return [body.status, body.order ?? null, body.fill ?? null, body.form, body.source]; };
    assert.deepEqual([await script(W('77')), await script(W('02')), await script(W('31')), await script(W('01'))], [['free', null, null, 'p2wpkh', 'state_proof'], ['listed', '1', null, 'p2wpkh', 'state_proof'], ['in_use', null, '3', 'p2wpkh', 'state_proof'], ['used', null, null, 'p2wpkh', 'state_proof']]);

    // An account's market: the orders it owns, the open fills with its roles, and what ended.
    const seller = (await lab.get('/v1/accounts/7/market')).body;
    assert.deepEqual([seller.account, seller.orders.map((o) => [o.id, o.roles]), seller.fills.map((f) => [f.id, f.roles, f.last_height, f.proven_at_height]), seller.fills_truncated, seller.ended.items.map((e) => [e.fill, e.how, e.roles])],
      ['7', [['3', ['owner']]], [['3', ['owner'], '11', '6']], false, [['2', 'released', ['owner']]]]);
    // The buyer of a fill against its own buy order pays it and gets its seconds; the chain's own list has that one.
    assert.deepEqual((await lab.get('/v1/accounts/9/market')).body.fills.map((f) => [f.id, f.roles]), [['3', ['payer', 'to']]]);
    // The account a fill's seconds went to, when another account paid: the chain's own list never had it.
    const nine = (await lab.get('/v1/accounts/9/market')).body.ended;
    assert.deepEqual([nine.items.map((e) => [e.fill, e.how, e.roles, e.unpaid_sats, e.id]), nine.has_more], [[['1', 'paid', ['to'], '0', '6.0']], false]);
    const five = (await lab.get('/v1/accounts/5/market?limit=1')).body;
    assert.deepEqual([five.orders.map((o) => o.id), five.ended.items.map((e) => [e.fill, e.roles]), five.ended.has_more, five.ended.next_cursor], [['1', '6'], [['1', ['owner']]], false, '6.0']);
    assert.deepEqual((await lab.get('/v1/accounts/6/market')).body.ended.items.map((e) => [e.fill, e.how, e.roles, e.unpaid_micros]), [['2', 'released', ['payer', 'to'], '4000000']]);

    // The trades, newest first; then oldest first by cursor. The blocks that made and paid fill 1 were indexed together,
    // so its row was never proven before the payments: the numbers are counted from the action that made it.
    const trades = (await lab.get('/v1/market/trades')).body;
    assert.deepEqual([trades.order, trades.has_more, trades.market_index.tape_reconciled, trades.market_index.tape_complete, trades.items.map((t) => [t.id, t.type, t.fill, t.price, t.sats, t.seconds_micros, t.paid_sats, t.full, t.basis, t.owner, t.to])],
      ['desc', false, true, true, [['6.0', 'payment', '1', PRICE, '6000', '24000000', '6000', true, 'derived_row', '5', '9'], ['5.0', 'payment', '1', PRICE, '4000', '16000000', '4000', false, 'derived_row', '5', '9']]]);
    const first = (await lab.get('/v1/market/trades?order=asc&limit=1')).body;
    assert.deepEqual([first.items.map((t) => t.id), first.has_more, first.next_cursor], [['5.0'], true, '5.0']);
    assert.deepEqual((await lab.get(`/v1/market/trades?order=asc&cursor=${first.next_cursor}`)).body.items.map((t) => t.id), ['6.0']);
    // An action of the tape is looked up like any other.
    // Its fee is the network's, once more for every 256 bytes of its payload: the list cannot say it, the action can.
    const proof = (await (await fetch(`${lab.service.url}/v1/actions/${trades.items[0].hash}`)).json()).action;
    assert.deepEqual([proof.kind_name, proof.fee_rule, proof.fee_micros], ['market_proof', 'market_fee', SDK.marketActionFee(54, proof.payload, '1000')]);
    assert.ok(BigInt(proof.fee_micros) > 1000n);
    const listed = (await (await fetch(`${lab.service.url}/v1/blocks/6/actions`)).json()).items;
    assert.deepEqual(listed.map((item) => [item.kind_name, item.fee_rule, item.fee_micros]), [['market_proof', 'market_fee', null], ['market_release', 'network_fee', '1000']]);
    // An order, a take and a sale make a row whose id is not in the action: the answer for the action names it, as the
    // index counted it. In the order of the chain the ids are 1, 2, 3 …, and an action that makes nothing says nothing.
    const made = { order: [], fill: [] };
    let other = 0;
    for (let height = 1; height <= Number(trades.index.indexed_height); height++) {
      for (const item of (await (await fetch(`${lab.service.url}/v1/blocks/${height}/actions`)).json()).items) {
        const answer = await (await fetch(`${lab.service.url}/v1/actions/${item.hash}`)).json();
        if (['market_order', 'market_take', 'market_sell'].includes(item.kind_name)) {
          assert.deepEqual([answer.market.source, answer.market.proven, Object.keys(answer.market.made)], ['index', false, [item.kind_name === 'market_order' ? 'order' : 'fill']], item.kind_name);
          made[item.kind_name === 'market_order' ? 'order' : 'fill'].push(answer.market.made.order ?? answer.market.made.fill);
        } else { assert.equal(answer.market, undefined, item.kind_name); other += 1; }
      }
    }
    assert.ok(made.order.length >= 2 && made.fill.length >= 2 && other >= 2);
    assert.deepEqual([made.order, made.fill], [made.order.map((_, at) => String(at + 1)), made.fill.map((_, at) => String(at + 1))]);

    // Candles: the chain's own, stored as proven, and a computed interval, which says that it is computed.
    const hours = (await lab.get('/v1/market/candles?interval=hour')).body;
    assert.deepEqual([hours.interval, hours.interval_micros, hours.has_more, hours.items], ['hour', '60000000', false, [{ number: '0', start_time_micros: String(GENESIS), start_time: new Date(GENESIS / 1000).toISOString(),
      recorded_prices: { open: PRICE, high: PRICE, low: PRICE, close: PRICE }, sats: '10000', seconds_micros: '40000000', trades: '2', source: 'state_row', proven_at_height: '6', matches_tape: true }]]);
    const minutes = (await lab.get('/v1/market/candles?interval=1m')).body;
    assert.deepEqual([minutes.interval_micros, minutes.items.map((c) => [c.source, c.recorded_prices.close, c.sats, c.seconds_micros, c.trades, c.number]), Object.hasOwn(minutes.items[0], 'proven_at_height')], ['60000000', [['computed', PRICE, '10000', '40000000', '2', String(Math.floor(GENESIS / 60e6))]], false]);
    assert.deepEqual((await lab.get('/v1/market/candles?interval=1d')).body.items.map((c) => [c.trades, c.start_time_micros]), [['2', String(Math.floor(GENESIS / 86400e6) * 86400e6)]]);
    assert.deepEqual([(await lab.get(`/v1/market/candles?interval=hour&to=${GENESIS - 1}`)).body.items, (await lab.get(`/v1/market/candles?interval=1m&from=${GENESIS + 60e6}`)).body.items], [[], []]);
    assert.deepEqual(Object.keys(COMPUTED_INTERVALS), ['1m', '5m', '15m', '1d']);

    // The health answer carries where the index of the market stands, for the operator's alarm.
    const health = (await (await fetch(`${lab.service.url}/v1/health`)).json()).market;
    assert.deepEqual([health.ready, health.consistent, health.tape_reconciled, health.as_of_height], [true, true, true, '7']);
    // A list costs 1 from the rate-limit budget and a row with its proof 5, like their neighbours.
    const market_routes = ROUTES.filter((route) => route.path.includes('/market'));
    assert.deepEqual(market_routes.map((route) => [route.path, route.cost, route.proof === true]).sort(), [['/v1/accounts/{id}/market', 1, false], ['/v1/market', 5, true], ['/v1/market/candles', 1, false], ['/v1/market/depth', 1, false], ['/v1/market/fills/{fillid}', 5, true],
      ['/v1/market/orders', 1, false], ['/v1/market/orders/{orderid}', 5, true], ['/v1/market/scripts/{script}', 5, true], ['/v1/market/trades', 1, false]]);
    assert.equal(lab.logs.filter((entry) => entry.level === 'error').length, 0, JSON.stringify(lab.logs));
  });
});

test('answers say when the index disagrees with the chain, and whether the header chain is fresh', async () => {
  await serve(async (lab) => {
    const { chain } = lab;
    chain.block(make.sell('5', '100000000', [W('01')]), make.sell('6', '50000000', [W('02')]));
    chain.block();
    await lab.sync();
    // A row is lost to the index: the count against the proven summary finds it, and every list says so until it is mended.
    chain.mangle = (state) => { if (state.market.orders['2']) state.market.orders['2'] = null; };
    chain.block(make.scripts('6', '2', [W('08')]));
    chain.block();
    await lab.sync();
    const listed = (await lab.get('/v1/market/orders?side=sell')).body;
    assert.deepEqual([listed.market_index.consistent, listed.market_index.ready, listed.items.map((o) => o.id)], [false, true, ['1']]);
    assert.equal((await lab.get('/v1/market')).body.market_index.consistent, false);
    assert.ok(lab.logs.some((entry) => entry.level === 'error' && /the market index differs from the proven state/.test(entry.message)));
    chain.mangle = null; lab.clock += 61000;
    await lab.sync();
    const mended = (await lab.get('/v1/market/orders?side=sell')).body;
    assert.deepEqual([mended.market_index.consistent, mended.items.map((o) => o.id)], [true, ['1', '2']]);

    // Whether the Bitcoin header chain is fresh hangs on the time of its best header, which the proven row does not
    // hold. The header whose hash is the proven `best_tip` gives it, when it was relayed in an indexed block.
    const header = (time) => { const bytes = Buffer.alloc(80, 3); bytes.writeUInt32LE(time, 68); return bytes.toString('hex'); };
    const tipOf = (hex) => Buffer.from(sha(sha(Buffer.from(hex, 'hex')))).reverse().toString('hex');
    assert.equal((await lab.get('/v1/market')).body.bitcoin.fresh, null);
    const at = Math.floor(chain.timeOf(chain.tip) / 1e6), young = header(at - 600), old = header(at - 3 * 3600);
    chain.quiet(Buffer.from(SDK.publicHeadersAction(NETWORK, [old, young])));
    chain.block();
    await lab.sync();
    chain.bestTip = tipOf(young);
    assert.deepEqual([(await lab.get('/v1/market')).body.bitcoin.fresh, (await lab.get('/v1/market')).body.bitcoin.best_header_time], [true, String(at - 600)]);
    chain.bestTip = tipOf(old); lab.clock += 1001;
    assert.equal((await lab.get('/v1/market')).body.bitcoin.fresh, false);
    chain.bestTip = tipOf(young); chain.halted = { reason: 'deep_reorg' }; lab.clock += 1001;
    const halted = (await lab.get('/v1/market')).body.bitcoin;
    assert.deepEqual([halted.halted, halted.fresh, halted.halt], [true, false, { reason: 'deep_reorg' }]);
  });
});
