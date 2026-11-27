// The market of seconds against bitcoin (spec/market.md), as a wallet reads it: the engine's own proven rows,
// verified end to end through the installed verifier, and every reader the SDK has for them.
//
// - verifier-v4/fixtures/market-state.fixture.json is the engine's file, copied unchanged (v5/tests/market.rs
//   writes it, V5_EXPORT_MARKET_FIXTURE, and holds its own copy to what the engine produces): for four states of a laboratory chain, the answer of `/v4/state` to a selection
//   that names the market's rows, its root, the rows as the state holds them, and whether the chain let the fill
//   in progress end without payment. The engine tests run without CometBFT, so it holds no signed header.
// - verifier-v4/fixtures/market-engine.json holds the same answers, each under a header signed by test validators
//   that carries exactly that application hash (verifier-v4/src/market_tests.rs writes it,
//   V4_EXPORT_MARKET_FIXTURE=1). The entries, the Merkle proofs, the metadata and the rows are the engine's; only
//   the signatures are stand-ins.
// The states: `trading` (an open sell order whose first address served a proven trade, whose second serves a fill
// that was paid in part and whose third is free; a buy order with a fill against it), `learnt` (the chain has learnt
// the last height of that fill), `due` (the fill can end without payment), `no_market` (a network without the
// setting, asked the same).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import './time-sdk.js';
import * as installed from './proof-verifier.mjs';

const sdk = globalThis.TimeSDK;
const wrapped = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/market-engine.json', import.meta.url), 'utf8'));
const engineBytes = await readFile(new URL('../verifier-v4/fixtures/market-state.fixture.json', import.meta.url)), engine = JSON.parse(engineBytes);
const cases = wrapped.cases, { accounts, scripts } = wrapped, hours = wrapped.candle_hours, PRICE = wrapped.price;
const verify = (item, proof = item.proof, request = item.request) => installed.verifyViewProof(proof, item.trust, request, item.now_ms);
const stateOf = async (name) => (await verify(cases[name])).state;
const copy = (value) => JSON.parse(JSON.stringify(value));
const hex = (text) => Buffer.from(text).toString('hex');
/// The hexadecimal key of a row with a numeric id, as the state holds it.
const idKey = (namespace, id) => hex(namespace) + BigInt(id).toString(16).padStart(16, '0');
const entryOf = (proof, key) => proof.entries.find((entry) => entry.key_hex === key);
/// The proof of `item` with one entry changed by `edit`.
function tampered(item, key, edit) {
  const proof = copy(item.proof), entry = entryOf(proof, key);
  assert.ok(entry, 'the fixture proves this key');
  edit(entry, proof);
  return proof;
}

test('the wrapped cases are the engine\'s answers, entry for entry', () => {
  assert.equal(wrapped.source_sha256, createHash('sha256').update(engineBytes).digest('hex'), 'regenerate verifier-v4/fixtures/market-engine.json from the engine fixture');
  assert.deepEqual(engine.cases.map((item) => item.name), ['trading', 'learnt', 'due', 'no_market']);
  assert.deepEqual(Object.keys(cases).sort(), engine.cases.map((item) => item.name).sort());
  for (const item of engine.cases) {
    const mine = cases[item.name];
    assert.deepEqual(mine.proof.entries, item.response.entries, item.name);
    assert.equal(mine.proof.height, item.response.height);
    assert.equal(mine.proof.light_block.signed_header.header.app_hash.toLowerCase(), item.app_hash, item.name);
    assert.equal(mine.proof.light_block.signed_header.header.height, String(BigInt(item.height) + 1n), item.name);
    assert.deepEqual(mine.market, item.market, item.name);
    assert.deepEqual(mine.request, item.request);
    // The bytes the engine stores under each key are the canonical JSON of the row.
    for (const entry of item.response.entries) {
      if (!entry.key_hex.startsWith(hex('market/')) || entry.value_b64 === null) continue;
      const stored = Buffer.from(entry.value_b64, 'base64').toString('utf8');
      assert.equal(JSON.stringify(JSON.parse(stored)), stored, item.name);
    }
  }
  assert.equal(engine.profile, 'laboratory');
});

test('every row of the engine verifies through the installed verifier and reaches the wallet as the engine stored it', async () => {
  for (const [name, item] of Object.entries(cases)) {
    const checked = await verify(item);
    assert.equal(checked.verified, true, name);
    assert.deepEqual(checked.state.market, item.market, name);
    assert.equal(checked.state.config.market, name === 'no_market' ? undefined : true, name);
    assert.equal(checked.state.market_micros, item.market_micros ?? undefined, name);
    // Not asked for, the state says nothing of the market; asked for a part, it holds that part.
    assert.equal(Object.hasOwn((await verify(item, item.proof, {})).state, 'market'), false, name);
    const part = (await verify(item, item.proof, { market_fills: ['2'] })).state.market;
    assert.deepEqual(part, { orders: {}, fills: { 2: item.market.fills['2'] }, accounts: {}, scripts: {}, candles: {} }, name);
  }
});

test('a proof that was changed, cut or relabelled is refused by the verifier', async () => {
  const item = cases.trading, fill = idKey('market/fill/', 2), ended = idKey('market/fill/', 1), order = idKey('market/order/', 1), other = idKey('market/order/', 2);
  const refused = (proof, pattern, request = item.request) => assert.rejects(verify(item, proof, request), pattern);
  // The fill a person is about to pay, with fewer satoshis, another address, or more time.
  for (const [field, value] of [['sats', '1'], ['script', scripts.unknown], ['pay_blocks', '144'], ['to', accounts.anyone]]) {
    const proof = tampered(item, fill, (entry) => {
      const row = JSON.parse(Buffer.from(entry.value_b64, 'base64').toString('utf8'));
      row[field] = value;
      entry.value_b64 = Buffer.from(JSON.stringify(row)).toString('base64');
    });
    await refused(proof, /invalid key\/value proof/);
  }
  // A fill that has ended claimed to exist, and one that exists claimed to be gone.
  await refused(tampered(item, ended, (entry, proof) => { entry.value_b64 = entryOf(proof, fill).value_b64; }), /invalid key\/value proof/);
  await refused(tampered(item, fill, (entry) => { entry.value_b64 = null; }), /invalid key\/value proof/);
  // The proof of another row under this row's key: another order, and a proof of absence.
  await refused(tampered(item, order, (entry, proof) => { Object.assign(entry, entryOf(proof, other), { key_hex: order }); }), /invalid key\/value proof/);
  await refused(tampered(item, fill, (entry, proof) => { Object.assign(entry, entryOf(proof, ended), { key_hex: fill }); }), /invalid key\/value proof/);
  // An entry left out is never read as "no such row", whichever row it is.
  for (const entry of item.proof.entries.filter((entry) => entry.key_hex.startsWith(hex('market/')))) {
    await refused({ ...item.proof, entries: item.proof.entries.filter((kept) => kept !== entry) }, new RegExp('missing requested proof for ' + entry.key_hex));
  }
  // A row the proof does not hold cannot be asked for after the fact.
  await refused(item.proof, /missing requested proof for /, { market_fills: ['9'] });
  await refused(item.proof, /missing requested proof for /, { market_scripts: ['0014' + 'ee'.repeat(20)] });
  // The bounds and the forms of a selection.
  const many = (count) => Array.from({ length: count }, (_, index) => String(index + 1));
  for (const [field, most] of Object.entries(sdk.MARKET_SELECTION)) {
    const list = field === 'market_scripts' ? many(most + 1).map((n) => '0014' + n.padStart(2, '0').repeat(20)) : many(most + 1);
    await refused(item.proof, /selection budget exceeded/, { [field]: list });
    if (field !== 'market_scripts') await refused(item.proof, /INVALID_DECIMAL/, { [field]: ['01'] });
  }
  await refused(item.proof, /five standard forms/, { market_scripts: ['6a0100'] });
  await refused(item.proof, /five standard forms/, { market_scripts: ['0014' + 'AB'.repeat(20)] });
  await refused(item.proof, /INVALID_JSON/, { include_market: 'yes' });
  await refused(item.proof, /INVALID_JSON/, { market_paid: ['1'] });
  // The state under another root.
  const moved = copy(item.proof);
  moved.light_block.signed_header.header.app_hash = '00'.repeat(32).toUpperCase();
  await assert.rejects(verify(item, moved));
});

test('the readers give each row as proven: the setting, the summary, orders, fills, indexes, candles and addresses', async () => {
  const state = await stateOf('trading'), market = cases.trading.market;
  assert.equal(sdk.marketSetting(state), true);
  assert.deepEqual(sdk.marketRules(state), { profile: 'laboratory', ...sdk.MARKET_RULES.laboratory, ...sdk.MARKET_LIMITS });
  assert.deepEqual(sdk.marketSummary(state), market.summary);
  assert.deepEqual(Object.keys(sdk.marketSummary(state)), ['fills', 'last_price', 'next_fill', 'next_order', 'orders', 'sats', 'seconds_micros', 'trades']);
  assert.deepEqual([market.summary.trades, market.summary.sats, market.summary.seconds_micros, market.summary.last_price, market.summary.orders, market.summary.fills], ['2', '12000', '48000000', PRICE, '2', '2']);
  assert.equal(sdk.marketHeldMicros(state), cases.trading.market_micros);
  assert.deepEqual(sdk.marketHeights(state), market.heights);
  // The sell order: three addresses, the first has served, the second serves fill 2, the third is free.
  const sell = sdk.marketOrder(state, '1');
  assert.deepEqual(sell, market.orders['1']);
  assert.deepEqual([sell.side, sell.owner, sell.price, sell.amount_micros, sell.confirmations, sell.pay_blocks, sell.open], ['sell', accounts.seller, PRICE, '40000000', '2', '6', true]);
  assert.deepEqual(sell.scripts, [{ script: scripts.served, used: true }, { fill: '2', script: scripts.serving }, { script: scripts.listed }]);
  assert.match(sell.key, /^[0-9a-f]{64}$/);
  const buy = sdk.marketOrder(state, '2');
  assert.deepEqual(buy, market.orders['2']);
  assert.deepEqual([buy.side, buy.owner, buy.fills, buy.forms, buy.amount_micros, buy.bond_micros], ['buy', accounts.other, '1', ['p2wpkh'], '40000000', '4000000']);
  assert.equal(sdk.marketOrder(state, '3'), null);
  // The fill in progress was paid in part: it holds what is still to pay.
  const fill = sdk.marketFill(state, '2');
  assert.deepEqual(fill, market.fills['2']);
  assert.deepEqual([fill.script, fill.sats, fill.amount_micros, fill.deposit_micros, fill.confirmations, fill.payer, fill.to, fill.owner, fill.order, fill.side],
    [scripts.serving, '3000', '12000000', '600000', '2', accounts.buyer, accounts.buyer, accounts.seller, '1', 'sell']);
  assert.match(fill.start_hash, /^[0-9a-f]{64}$/);
  const against = sdk.marketFill(state, '3');
  assert.deepEqual([against.side, against.script, against.payer, against.to, against.owner, against.order], ['buy', scripts.of_a_fill_against_a_buy_order, accounts.other, accounts.other, accounts.seller, '2']);
  assert.equal(sdk.marketFill(state, '1'), null, 'the fill of the proven trade has ended');
  assert.equal(sdk.marketFill(state, '4'), null);
  // An id may be given as a number a decimal string names; a reader gives a copy.
  assert.deepEqual(sdk.marketFill(state, 2n), fill);
  fill.sats = '1';
  assert.equal(sdk.marketFill(state, '2').sats, '3000');
  // Who has what open. An account without a row has nothing open.
  assert.deepEqual(sdk.marketAccount(state, accounts.seller), { fills: [], orders: ['1'] });
  assert.deepEqual(sdk.marketAccount(state, accounts.buyer), { fills: ['2'], orders: [] });
  assert.deepEqual(sdk.marketAccount(state, accounts.other), { fills: ['3'], orders: ['2'] });
  assert.equal(market.accounts[accounts.anyone], null);
  assert.deepEqual(sdk.marketAccount(state, accounts.anyone), { fills: [], orders: [] });
  // The four things an address can be.
  assert.deepEqual(sdk.marketScript(state, scripts.served), { status: 'used' });
  assert.deepEqual(sdk.marketScript(state, scripts.serving), { status: 'listed', order: '1' });
  assert.deepEqual(sdk.marketScript(state, scripts.listed), { status: 'listed', order: '1' });
  assert.deepEqual(sdk.marketScript(state, scripts.of_a_fill_against_a_buy_order), { status: 'in_use', fill: '3' });
  assert.deepEqual(sdk.marketScript(state, scripts.unknown), { status: 'free' });
  // The candles of the two payments, and an hour without one.
  const candles = hours.map((hour) => sdk.marketCandle(state, hour));
  assert.deepEqual(candles, hours.map((hour) => market.candles[hour]));
  assert.equal(candles.at(-1), null);
  const traded = candles.filter(Boolean);
  assert.equal(traded.reduce((sum, candle) => sum + BigInt(candle.trades), 0n), 2n);
  assert.equal(traded.reduce((sum, candle) => sum + BigInt(candle.sats), 0n), 12000n);
  for (const candle of traded) assert.deepEqual([candle.open, candle.close, candle.high, candle.low], [PRICE, PRICE, PRICE, PRICE]);
  assert.ok(BigInt(sdk.marketHour(state)) >= BigInt(hours[hours.length - 2]));
  assert.equal(sdk.marketHour(state), ((BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros)) / 60000000n).toString());
});

test('a row that was not asked for is an error, never "no such row"', async () => {
  const item = cases.trading, state = await stateOf('trading');
  assert.throws(() => sdk.marketOrder(state, '4'), /verified without that row of the market; ask for it with market_orders/);
  assert.throws(() => sdk.marketFill(state, '5'), /ask for it with market_fills/);
  assert.throws(() => sdk.marketAccount(state, '0'), /ask for it with market_accounts/);
  assert.throws(() => sdk.marketCandle(state, '1'), /ask for it with market_candles/);
  assert.throws(() => sdk.marketScript(state, '0014' + 'ee'.repeat(20)), /ask for it with market_scripts/);
  // A state read for rows only says nothing of the summary; one read without the market says nothing at all.
  const rowsOnly = (await verify(item, item.proof, { market_fills: ['2'] })).state;
  assert.equal(sdk.marketFill(rowsOnly, '2').sats, '3000');
  assert.throws(() => sdk.marketSummary(rowsOnly), /ask for it with include_market/);
  assert.throws(() => sdk.marketHeights(rowsOnly), /ask for it with include_market/);
  assert.throws(() => sdk.marketExpiry(rowsOnly, sdk.marketFill(rowsOnly, '2')), /ask for it with include_market/);
  const plain = (await verify(item, item.proof, {})).state;
  for (const read of [() => sdk.marketSummary(plain), () => sdk.marketOrder(plain, '1'), () => sdk.marketFill(plain, '2'), () => sdk.marketAccount(plain, accounts.buyer), () => sdk.marketCandle(plain, hours[0]), () => sdk.marketScript(plain, scripts.served)]) {
    assert.throws(read, /This state was verified without the market/);
  }
  // The setting and the total come with every verified state.
  assert.equal(sdk.marketSetting(plain), true);
  assert.equal(sdk.marketHeldMicros(plain), item.market_micros);
  // An id is a canonical decimal number and an address a standard script, here as in a selection.
  for (const id of ['01', '', '-1', '1.5', 'one', null]) assert.throws(() => sdk.marketFill(state, id), /canonical u64/);
  for (const script of ['6a0100', scripts.served.slice(2), '0014' + 'EE'.repeat(20), 7, undefined]) assert.throws(() => sdk.marketScript(state, script), /five standard forms/);
  for (const read of [() => sdk.marketSetting(undefined), () => sdk.marketSummary(null)]) assert.throws(read, /A verified state is required/);
  assert.throws(() => sdk.marketSetting({}), /carries the network configuration/);
  for (const written of [false, 'true', 1, null, {}]) assert.throws(() => sdk.marketSetting({ ...state, config: { ...state.config, market: written } }), /Unsupported setting for the market/);
});

test('a network without the market: the setting is absent and every row is proven absent', async () => {
  const state = await stateOf('no_market');
  assert.equal(sdk.marketSetting(state), false);
  assert.equal(sdk.marketHeldMicros(state), null);
  assert.equal(sdk.marketSummary(state), null);
  assert.equal(sdk.marketHeights(state), null);
  for (const id of ['1', '2', '3']) assert.equal(sdk.marketOrder(state, id), null);
  for (const id of ['1', '2', '3', '4']) assert.equal(sdk.marketFill(state, id), null);
  for (const hour of hours) assert.equal(sdk.marketCandle(state, hour), null);
  // What would be an interpretation of an absent row is not given: there is no market to be free or empty in.
  for (const read of [() => sdk.marketAccount(state, accounts.buyer), () => sdk.marketScript(state, scripts.unknown), () => sdk.marketRules(state), () => sdk.marketHour(state), () => sdk.marketExpiry(state, cases.trading.market.fills['2']), () => sdk.marketFillEarliestEnd(state, cases.trading.market.fills['2'])]) {
    assert.throws(read, /This network has no market/);
  }
  // A state that pairs the setting, the total and the rows in a way the engine never writes is refused.
  const market = cases.trading.market;
  assert.throws(() => sdk.marketFill({ ...state, market }, '2'), /Market rows belong to a network with the market/);
  assert.throws(() => sdk.marketSummary({ ...state, market }), /Market rows belong to a network with the market/);
  assert.throws(() => sdk.marketHeldMicros({ ...state, market_micros: '0' }), /belongs to a network with the market/);
  const withMarket = await stateOf('trading');
  assert.throws(() => sdk.marketHeldMicros({ ...withMarket, market_micros: undefined }), /belongs to a network with the market/);
  assert.throws(() => sdk.marketSummary({ ...withMarket, market: { ...withMarket.market, summary: null } }), /A network with the market holds its summary/);
  assert.throws(() => sdk.marketHeights({ ...withMarket, market: { ...withMarket.market, heights: null } }), /holds its clock of heights/);
});

test('a reader refuses a row in a form it does not know', async () => {
  const state = await stateOf('trading');
  const changed = (field, id, edit) => { const next = copy(state); edit(id === undefined ? next.market[field] : next.market[field][id], next.market); return next; };
  const drop = (name) => (row) => { delete row[name]; };
  const set = (name, value) => (row) => { row[name] = value; };
  for (const edit of [set('more', '1'), drop('trades'), set('orders', 2), set('orders', '02'), (row) => { row.orders = row.next_order; }, (row) => { row.fills = row.next_fill; }, drop('last_price'), set('trades', '0'), set('last_price', '0'), set('last_price', '1000000000000001')]) {
    assert.throws(() => sdk.marketSummary(changed('summary', undefined, edit)), /Unsupported market summary|canonical u64|A price is from 1 to 10\^15/);
  }
  for (const edit of [set('entries', []), set('entries', {}), set('more', []), (row) => row.entries.push({ at: '0', height: '0' }), (row) => row.entries.push({ at: row.entries.at(-1).at, height: row.entries.at(-1).height }),
    (row) => { row.entries[0].height = '4294967296'; }, (row) => { row.entries[0].hash = '00'; }, (row) => { row.entries[0].at = 0; }]) {
    assert.throws(() => sdk.marketHeights(changed('heights', undefined, edit)), /Unsupported market clock of heights|canonical u64/);
  }
  for (const edit of [set('note', 'x'), drop('key'), set('keys', 'ab'.repeat(32)), set('fills', '0'), set('side', 'both'), set('key', 'AB'.repeat(32)), set('open', 'true'), set('price', '0'), set('confirmations', '0'), set('confirmations', '101'),
    set('pay_blocks', '145'), set('deposit_ppm', '1000001'), set('min_sats', '0'), set('bond_micros', '1'), set('scripts', []), (row) => row.scripts.push(row.scripts[0]), (row) => { row.scripts[2].script = '6a0100'; },
    (row) => { row.scripts[0].used = false; }, (row) => { row.scripts[1].used = true; }, (row) => { row.scripts[2].order = '1'; }, set('created', { height: '4' }), (row) => { row.open = false; }, set('amount_micros', '040')]) {
    assert.throws(() => sdk.marketOrder(changed('orders', '1', edit), '1'), /Unsupported market order|canonical u64|canonical hexadecimal|A price is from 1 to 10\^15/);
  }
  for (const edit of [set('scripts', [{ script: scripts.unknown }]), set('min_deposit_micros', '1'), set('fills', '17'), set('forms', []), set('forms', ['p2wpkh', 'p2tr']), set('forms', ['p2pk']), drop('forms'),
    (row) => { row.open = false; row.amount_micros = '0'; row.bond_micros = '0'; row.fills = '0'; }]) {
    assert.throws(() => sdk.marketOrder(changed('orders', '2', edit), '2'), /Unsupported market order/);
  }
  // A closed order whose fill is still open is a form the engine writes.
  assert.equal(sdk.marketOrder(changed('orders', '2', (row) => { row.open = false; row.amount_micros = '0'; row.bond_micros = '0'; }), '2').open, false);
  // An order or a fill under another id is not the row that was asked for.
  assert.throws(() => sdk.marketOrder(changed('orders', '1', set('id', '2')), '1'), /The proven order is not the order asked for/);
  assert.throws(() => sdk.marketFill(changed('fills', '2', set('id', '3')), '2'), /The proven fill is not the fill asked for/);
  for (const edit of [set('paid', '1'), drop('start_hash'), set('amount_micros', '0'), set('confirmations', '0'), set('pay_blocks', '0'), set('start_height', '4294967296'), set('script', '0014'), set('script', '0014' + 'AB'.repeat(20)),
    set('start_hash', '0f'.repeat(31)), set('side', 'none'), (row) => { row.side = 'buy'; row.to = accounts.anyone; }, set('created', null), set('deposit_micros', 600000)]) {
    assert.throws(() => sdk.marketFill(changed('fills', '2', edit), '2'), /Unsupported market fill|canonical u64|canonical hexadecimal/);
  }
  // The satoshis a person is shown are what is still to pay: never nothing, and never more than the price of the
  // seconds the fill still holds. Less is a fill that was paid in part.
  for (const edit of [set('sats', '0'), set('sats', '3001'), set('price', '249800000'), set('amount_micros', '11990000')]) {
    assert.throws(() => sdk.marketFill(changed('fills', '2', edit), '2'), /The satoshis of the proven fill are none, or more than the price of its seconds/);
  }
  for (const sats of ['1', '2999', '3000']) assert.equal(sdk.marketFill(changed('fills', '2', set('sats', sats)), '2').sats, sats);
  for (const row of [{ fills: [], orders: [] }, { orders: ['1'] }, { fills: [], orders: ['2', '1'] }, { fills: ['1', '1'], orders: [] }, { fills: [], orders: [1] }, { fills: [], orders: ['1'], more: [] }, []]) {
    assert.throws(() => sdk.marketAccount(changed('accounts', undefined, (rows) => { rows[accounts.seller] = row; }), accounts.seller), /Unsupported market index|canonical u64/);
  }
  for (const row of [{ fill: '1', order: '1' }, { used: true }, { order: '01' }, [], 'used']) {
    assert.throws(() => sdk.marketScript(changed('scripts', undefined, (rows) => { rows[scripts.listed] = row; }), scripts.listed), /Unsupported market script|canonical u64/);
  }
  for (const edit of [set('volume', '1'), set('trades', '0'), set('low', '250000001'), set('high', '249999999'), set('open', '0'), drop('close')]) {
    assert.throws(() => sdk.marketCandle(changed('candles', hours[0], edit), hours[0]), /Unsupported market candle|A price is from 1 to 10\^15/);
  }
});

test('the price formula in whole numbers: the vectors of the engine', () => {
  // v5/src/market.rs, the_price_formula_rounds_up_for_the_cost_and_down_for_what_is_bought.
  const PRICE_MAX = '1000000000000000', U64 = sdk.MAX_U64;
  // One second at a price of one millionth of a satoshi costs a satoshi.
  assert.equal(sdk.marketSats('1000000', '1'), '1');
  assert.equal(sdk.marketSats('1', '1'), '1');
  // 1,000 seconds at 250 satoshis a second.
  assert.equal(sdk.marketSats('1000000000', '250000000'), '250000');
  assert.equal(sdk.marketBought('250000', '250000000'), '1000000000');
  // What a satoshi less buys costs at most what was paid.
  for (const [amount, price, expected] of [['999999', '3', '1'], ['7', '1000000000000', '7'], ['123456789', '987654321', '121933']]) {
    const cost = sdk.marketSats(amount, price);
    assert.equal(cost, expected);
    assert.ok(BigInt(sdk.marketBought(cost, price)) >= BigInt(amount), 'paying the cost buys the amount');
    if (BigInt(cost) > 1n) assert.ok(BigInt(sdk.marketBought((BigInt(cost) - 1n).toString(), price)) < BigInt(amount), 'a satoshi less does not');
  }
  assert.throws(() => sdk.marketSats(U64, PRICE_MAX), /More satoshis than exist/);
  assert.throws(() => sdk.marketSats('1', '0'), /A price is from 1 to 10\^15/);
  assert.throws(() => sdk.marketSats('1', '1000000000000001'), /A price is from 1 to 10\^15/);
  assert.equal(sdk.marketBought(U64, '1'), U64);
  // The bounds: every satoshi there is, and one more; the highest price.
  assert.equal(sdk.marketSats('2100000000000000', '1000000000000'), '2100000000000000');
  assert.throws(() => sdk.marketSats('2100000000000001', '1000000000000'), /More satoshis than exist/);
  assert.equal(sdk.marketSats('0', '5'), '0');
  assert.equal(sdk.marketSats('1', PRICE_MAX), '1000');
  assert.equal(sdk.marketBought('1', PRICE_MAX), '0');
  assert.equal(sdk.marketBought('1000', PRICE_MAX), '1');
  assert.equal(sdk.marketBought('0', '1'), '0');
  assert.throws(() => sdk.marketBought('1', '0'), /A price is from 1 to 10\^15/);
  // Whole numbers only, in their canonical form; a number a decimal string names is taken as that string.
  assert.equal(sdk.marketSats(1000000000n, 250000000n), '250000');
  for (const odd of ['01', '', '-1', '1.5', '1e3', '18446744073709551616', null, undefined]) {
    assert.throws(() => sdk.marketSats(odd, '1'), /canonical u64/);
    assert.throws(() => sdk.marketSats('1', odd), /canonical u64/);
    assert.throws(() => sdk.marketBought(odd, '1'), /canonical u64/);
  }
  // The rows of the engine go by it. A fill costs the price of its seconds when it is made; what is still to pay
  // after a payment of a part is that less what was paid, which the formula bounds and does not give.
  for (const item of Object.values(cases)) for (const fill of Object.values(item.market.fills)) if (fill) assert.ok(BigInt(fill.sats) >= 1n && BigInt(fill.sats) <= BigInt(sdk.marketSats(fill.amount_micros, fill.price)));
  assert.equal(sdk.marketBought('10000', PRICE), '40000000');
  assert.equal(sdk.marketSats('20000000', PRICE), '5000');
  assert.equal(sdk.marketSats('10000000', PRICE), cases.trading.market.fills['3'].sats);
});

test('what a payment to a fill buys: all of it, or the same part of it rounded down', async () => {
  const state = await stateOf('trading'), fill = sdk.marketFill(state, '2');
  // The fill was made for 20 seconds and 5,000 satoshis; 2,000 were paid and bought 8 seconds. 12 seconds are
  // left for 3,000 satoshis.
  assert.deepEqual([fill.amount_micros, fill.sats, fill.deposit_micros], ['12000000', '3000', '600000']);
  assert.equal(sdk.marketFillBuys({ ...fill, amount_micros: '20000000', sats: '5000', deposit_micros: '1000000' }, '2000'), '8000000');
  assert.equal(sdk.marketFillBuys(fill, '3000'), '12000000');
  assert.equal(sdk.marketFillBuys(fill, '99999'), '12000000', 'more than is still to pay buys what the fill holds, and no more');
  assert.equal(sdk.marketFillBuys(fill, '1500'), '6000000');
  assert.equal(sdk.marketFillBuys(fill, '2999'), '11996000');
  assert.equal(sdk.marketFillBuys(fill, '1'), '4000');
  assert.equal(sdk.marketFillBuys(fill, '0'), '0');
  // Rounded down: a third of the satoshis of a fill of ten microseconds buys three.
  const small = { ...fill, amount_micros: '10', sats: '3', price: '1000000000000' };
  assert.deepEqual(['1', '2', '3'].map((sats) => sdk.marketFillBuys(small, sats)), ['3', '6', '10']);
  for (const odd of ['01', '', '-1', '1.5', null]) assert.throws(() => sdk.marketFillBuys(fill, odd), /canonical u64/);
  assert.throws(() => sdk.marketFillBuys({ ...fill, sats: '0' }, '1'), /none, or more than the price of its seconds/);
});

test('the last height of a fill and the earliest moment it can end', async () => {
  const state = await stateOf('trading'), fill = sdk.marketFill(state, '2');
  assert.equal(sdk.marketFillLastHeight(fill), (BigInt(fill.start_height) + 6n + 2n - 1n).toString());
  // The laboratory profile: a block is taken to last a second, the grace is twenty seconds, sixteen blocks are spare.
  assert.equal(sdk.marketFillEarliestEnd(state, fill), (BigInt(fill.opened_micros) + (6n + 2n * 2n + 16n) * 1000000n + 20000000n).toString());
  // The production profile, and the example of the specification (5.5): a time to pay of 3 blocks and 3
  // confirmations, 280 minutes after the fill at the earliest.
  const production = { ...state, config: { ...state.config, profile: 'production' } }, MINUTE = 60000000n;
  const quick = { ...fill, pay_blocks: '3', confirmations: '3', opened_micros: '0' };
  assert.equal(sdk.marketFillEarliestEnd(production, quick), (280n * MINUTE).toString());
  assert.equal(sdk.marketFillEarliestEnd(production, { ...quick, opened_micros: '7' }), (280n * MINUTE + 7n).toString());
  assert.equal(sdk.marketFillEarliestEnd(production, { ...quick, pay_blocks: '144', confirmations: '100' }), ((144n + 200n + 16n) * 10n * MINUTE + 30n * MINUTE).toString());
  assert.equal(sdk.marketFillLastHeight({ ...quick, start_height: '900000' }), '900005');
  assert.deepEqual(sdk.marketRules(production), { profile: 'production', kMin: '3', nMin: '3', blockMicros: '600000000', graceMicros: '1800000000', bondMinPpm: '30000', minSats: '1000', hourMicros: '3600000000', ...sdk.MARKET_LIMITS });
  assert.equal(sdk.MARKET_LIMITS.spareBlocks, '16');
  // As a date: the clock of the waits stands while the chain stands, so it is the earliest possible one.
  const end = sdk.marketFillEarliestEnd(state, fill), date = sdk.securityDeadline(state, end);
  assert.equal(sdk.waitsSurviveStops(state), true, 'a network with the market counts its waits on the clock of the waits');
  assert.deepEqual([date.due, date.earliest], [false, true]);
  assert.equal(date.elapsedMicros, (BigInt(end) + BigInt(sdk.stoppedMicros(state))).toString());
  // Neither is computed from a row that is not a fill, or for a profile this build does not know.
  assert.throws(() => sdk.marketFillEarliestEnd(state, { ...fill, sats: '0' }), /none, or more than the price of its seconds/);
  assert.throws(() => sdk.marketFillEarliestEnd(state, null), /Unsupported market fill/);
  assert.throws(() => sdk.marketFillLastHeight({ ...fill, pay_blocks: 6 }), /canonical u64/);
  assert.throws(() => sdk.marketFillEarliestEnd({ ...state, config: { ...state.config, profile: 'other' } }, fill), /Unsupported network profile/);
  assert.throws(() => sdk.marketFill({ ...state, market: { ...state.market, fills: { 2: { ...fill, start_height: '4294967290' } } } }, '2'), /Unsupported market fill/);
});

test('whether a fill can end without payment: the engine\'s answer at three states, and each condition by itself', async () => {
  const heightsOf = {};
  for (const name of ['trading', 'learnt', 'due']) {
    const item = cases[name], state = await stateOf(name), fill = sdk.marketFill(state, item.expiry.fill);
    assert.equal(sdk.securityNow(state), item.clock_of_the_waits_micros, name);
    assert.equal(state.bitcoin.meta.best_height, item.bitcoin_best_height, name);
    // Read from the state's own proven rows: the clock of heights and the Bitcoin header chain.
    const answer = sdk.marketExpiry(state, fill);
    assert.equal(answer.possible, item.expiry.accepted, name + ': the engine ' + (item.expiry.accepted ? 'accepted' : 'refused') + ' the expiry in the next block');
    assert.equal(answer.lastHeight, sdk.marketFillLastHeight(fill));
    assert.equal(answer.earliestEndMicros, sdk.marketFillEarliestEnd(state, fill));
    // The same with the best height given by the caller.
    assert.deepEqual(sdk.marketExpiry(state, fill, { bestHeight: String(item.bitcoin_best_height), halted: false }), answer, name);
    heightsOf[name] = { state, fill, answer };
  }
  // Before the chain has learnt the last height: no entry of the clock reaches it, and the grace has not begun.
  const { trading, learnt, due } = heightsOf;
  assert.deepEqual([trading.answer.reason, trading.answer.knownMicros, trading.answer.notBeforeMicros], ['height', null, trading.answer.earliestEndMicros]);
  assert.match(cases.trading.expiry.refusal, /has not learnt the last height/);
  assert.equal(sdk.marketHeightKnown(sdk.marketHeights(trading.state), trading.answer.lastHeight), null);
  // Learnt: the grace runs from that moment, and the time the fill was given from its making is the longer wait here.
  const known = sdk.marketHeightKnown(sdk.marketHeights(learnt.state), learnt.answer.lastHeight);
  assert.deepEqual([learnt.answer.reason, learnt.answer.knownMicros], ['grace', known]);
  assert.match(cases.learnt.expiry.refusal, /time in which a proof of a payment made in time is accepted/);
  const graceOver = BigInt(known) + 20000000n, earliest = BigInt(learnt.answer.earliestEndMicros);
  assert.ok(graceOver < earliest);
  assert.equal(learnt.answer.notBeforeMicros, earliest.toString());
  const at = (nowMicros, more = {}) => sdk.marketExpiry(learnt.state, learnt.fill, { nowMicros: nowMicros.toString(), ...more });
  assert.equal(at(graceOver - 1n).reason, 'grace');
  assert.equal(at(graceOver).reason, 'time');
  assert.equal(at(earliest - 1n).reason, 'time');
  assert.deepEqual([at(earliest).possible, at(earliest).reason], [true, null]);
  assert.deepEqual([due.answer.possible, due.answer.reason, due.answer.knownMicros], [true, null, known]);
  // A halted header chain ends no fill, whatever the clocks say.
  assert.deepEqual([at(earliest, { bestHeight: String(cases.learnt.bitcoin_best_height), halted: true }).possible, at(earliest, { bestHeight: '4000', halted: true }).reason], [false, 'halted']);
  const haltedState = { ...due.state, bitcoin: { meta: { ...due.state.bitcoin.meta, halted: { reason: 'deep_reorg' } } } };
  assert.equal(sdk.marketExpiry(haltedState, due.fill).reason, 'halted');
  // A best height below the last height: the chain does not know it now, though the clock once did.
  const last = BigInt(due.answer.lastHeight);
  assert.deepEqual([at(earliest, { bestHeight: (last - 1n).toString(), halted: false }).reason, at(earliest, { bestHeight: (last - 1n).toString(), halted: false }).knownMicros], ['height', null]);
  assert.equal(at(earliest, { bestHeight: last.toString(), halted: false }).possible, true);
  // When the grace is the longer wait: the chain learns the height late.
  const lateState = copy(learnt.state), lateAt = earliest + 5000000n;
  lateState.market.heights.entries = lateState.market.heights.entries.map((entry) => (BigInt(entry.height) >= last ? { ...entry, at: lateAt.toString() } : entry));
  const late = (nowMicros) => sdk.marketExpiry(lateState, learnt.fill, { nowMicros: nowMicros.toString() });
  assert.equal(late(lateAt).notBeforeMicros, (lateAt + 20000000n).toString());
  assert.deepEqual([late(lateAt + 20000000n - 1n).reason, late(lateAt + 20000000n).possible], ['grace', true]);
  // The clock of heights: the oldest entry that reaches a height.
  const clock = { entries: [{ at: '0', height: '10' }, { at: '50', height: '14' }, { at: '90', height: '15' }] };
  assert.deepEqual(['3', '10', '11', '14', '15', '16'].map((height) => sdk.marketHeightKnown(clock, height)), ['0', '0', '50', '50', '90', null]);
  assert.throws(() => sdk.marketHeightKnown({ entries: [] }, '1'), /Unsupported market clock of heights/);
  assert.throws(() => sdk.marketHeightKnown(clock, '01'), /canonical u64/);
  // What the state does not prove must be given, whole.
  const unproven = { ...due.state, bitcoin: undefined };
  assert.throws(() => sdk.marketExpiry(unproven, due.fill), /ask for it with include_bitcoin, or give bestHeight and halted/);
  assert.throws(() => sdk.marketExpiry(unproven, due.fill, { bestHeight: '99' }), /is halted is true or false/);
  assert.throws(() => sdk.marketExpiry(due.state, due.fill, { halted: false }), /ask for it with include_bitcoin, or give bestHeight and halted/);
  assert.equal(sdk.marketExpiry(unproven, due.fill, { bestHeight: String(cases.due.bitcoin_best_height), halted: false }).possible, true);
  assert.throws(() => sdk.marketExpiry(due.state, { ...due.fill, sats: '0' }), /none, or more than the price of its seconds/);
});

test('a client asks for the rows of the market with every other selection, and takes no answer without them', async () => {
  const item = cases.trading, asked = [];
  const clocked = (verifyViewProof) => ({ verifyTrust: (trust) => installed.verifyTrust(trust, item.now_ms), verifyLightUpdate: (block, trust) => installed.verifyLightUpdate(block, trust, item.now_ms), verifyViewProof });
  const fetcher = async (url) => {
    const { pathname, searchParams } = new URL(url);
    if (pathname === '/api/view-proof') asked.push(JSON.parse(searchParams.get('query')));
    const answer = pathname === '/api/network' ? { protocolVersion: '4', networkId: item.trust.network_id, chainId: item.trust.chain_id } : pathname === '/api/view-proof' ? item.proof : { error: 'unexpected request' };
    return { ok: !answer.error, text: async () => JSON.stringify(answer) };
  };
  const client = sdk.createClient({ gateway: 'https://rpc.example', trust: item.trust, verifier: clocked((proof, trust, request) => installed.verifyViewProof(proof, trust, request, item.now_ms)), fetcher });
  const { state, requested } = await client.getVerifiedState(item.request);
  assert.deepEqual(state.market, item.market);
  assert.equal(sdk.marketFill(state, '2').script, scripts.serving);
  // The selection goes out as given, beside the fields every selection has.
  const usual = { names: [], ids: [], public_keys: [], owners: [], candidates: [], epochs: [], blocks: [], include_pos: false, include_bitcoin: true, include_policy: false };
  assert.deepEqual(asked[0], { ...usual, include_market: true, market_orders: item.request.market_orders, market_fills: item.request.market_fills, market_accounts: item.request.market_accounts, market_scripts: item.request.market_scripts, market_candles: item.request.market_candles });
  assert.deepEqual(requested, asked[0]);
  // A read that asks nothing of the market names none of its fields: a node that predates them refuses them.
  await client.getVerifiedState({ include_bitcoin: true, include_market: false, market_fills: [] });
  assert.deepEqual(asked[1], usual);
  // One part by itself, with an id given twice.
  const part = await client.getVerifiedState({ market_fills: ['2', '2'] });
  assert.deepEqual(asked[2], { ...usual, include_bitcoin: false, market_fills: ['2'] });
  assert.deepEqual(Object.keys(part.state.market.fills), ['2']);
  // Refused before anything is sent: the bounds, the form of an id and of a script, the types.
  const sent = asked.length, many = (count) => Array.from({ length: count }, (_, index) => String(index + 1));
  for (const [field, most] of Object.entries(sdk.MARKET_SELECTION)) {
    assert.equal([16, 16, 8, 16, 32][Object.keys(sdk.MARKET_SELECTION).indexOf(field)], most);
    const list = field === 'market_scripts' ? many(most + 1).map((n) => '0014' + n.padStart(2, '0').repeat(20)) : many(most + 1);
    await assert.rejects(client.getVerifiedState({ [field]: list }), /Proof selection exceeds budget/);
    await assert.rejects(client.getVerifiedState({ [field]: 'all' }), /Proof selections must be arrays/);
    await assert.rejects(client.getVerifiedState({ [field]: [field === 'market_scripts' ? '6a0100' : '01'] }), field === 'market_scripts' ? /five standard forms/ : /canonical u64/);
  }
  await assert.rejects(client.getVerifiedState({ market_fills: [2] }), /canonical u64/);
  await assert.rejects(client.getVerifiedState({ include_market: 'yes' }), /Proof flags must be booleans/);
  await assert.rejects(client.getVerifiedState({ market_paid: ['1'] }), /Invalid proof selection/);
  assert.equal(asked.length, sent);
  // A verifier that does not know the selection proves nothing of the market, and its answer is not taken.
  const blind = sdk.createClient({ gateway: 'https://rpc.example', trust: item.trust, fetcher, verifier: clocked(async (proof, trust, request) => {
    const checked = await installed.verifyViewProof(proof, trust, request, item.now_ms);
    delete checked.state.market;
    return checked;
  }) });
  await assert.rejects(blind.getVerifiedState({ market_fills: ['2'] }), /The verified state lacks the rows of the market that were asked for/);
  await assert.rejects(blind.getVerifiedState({ include_market: true }), /The verified state lacks the rows of the market that were asked for/);
  assert.equal((await blind.getVerifiedState({})).state.market, undefined);
});

test('the gateway passes the selection on, and a wallet behind it reads the market with its own verifier', async () => {
  const { createV4Servers } = await import('./server.mjs');
  const { mkdtemp, rm } = await import('node:fs/promises'), os = await import('node:os'), path = await import('node:path'), { fileURLToPath } = await import('node:url');
  const item = cases.trading, block = item.proof.light_block, at = block.signed_header.header.height, state = item.proof.height, selections = [];
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-market-http-')), originalNow = Date.now;
  Date.now = () => item.now_ms;
  // A node that answers `/v4/state` with the engine's entries, whatever is asked: the verifiers decide what they prove.
  const rpc = async (endpoint, p = {}) => {
    if (endpoint === '/commit') return { signed_header: block.signed_header };
    if (endpoint === '/validators') return { block_height: p.height, total: String(block.validators.length), validators: p.height === at ? block.validators : block.next_validators };
    if (endpoint === '/abci_query') {
      assert.equal(p.height, state);
      selections.push(JSON.parse(Buffer.from(p.data.slice(2), 'hex').toString('utf8')));
      return { response: { height: state, code: 0, value: Buffer.from(JSON.stringify({ height: state, history_proofs: item.proof.history_proofs, root: block.signed_header.header.app_hash.toLowerCase(), entries: item.proof.entries })).toString('base64') } };
    }
    throw Error('Unconfigured test RPC');
  };
  let servers;
  try {
    servers = await createV4Servers({ root: fileURLToPath(new URL('../', import.meta.url)), manifest: { networkId: item.trust.network_id, chainId: item.trust.chain_id, trust: item.trust }, rpc, walletPort: 0, merchantPort: 0, checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json') });
    const client = sdk.createClient({ gateway: servers.walletOrigin, trust: item.trust });
    const { state: verified } = await client.getVerifiedState(item.request);
    assert.deepEqual(verified.market, item.market);
    assert.deepEqual(sdk.marketScript(verified, scripts.served), { status: 'used' });
    const passed = selections.at(-1);
    assert.equal(passed.include_market, true);
    for (const field of Object.keys(sdk.MARKET_SELECTION)) assert.deepEqual(passed[field], item.request[field], field);
    // A read that asks nothing of the market reaches the node without any of its fields.
    await client.getVerifiedState({});
    assert.deepEqual(Object.keys(selections.at(-1)).filter((field) => field.includes('market')), []);
    // What the gateway refuses, it refuses before it asks the node.
    const before = selections.length, many = (count) => Array.from({ length: count }, (_, index) => String(index + 1));
    const ask = async (selection) => (await fetch(servers.walletOrigin + '/api/view-proof?query=' + encodeURIComponent(JSON.stringify(selection)))).status;
    for (const [field, most] of Object.entries(sdk.MARKET_SELECTION)) {
      const list = (count) => (field === 'market_scripts' ? many(count).map((n) => '0014' + n.padStart(2, '0').repeat(20)) : many(count));
      assert.equal(await ask({ [field]: list(most + 1) }), 400, field);
      assert.equal(await ask({ [field]: 'all' }), 400, field);
      assert.equal(await ask({ [field]: [field === 'market_scripts' ? '6a0100' : '01'] }), 400, field);
    }
    for (const selection of [{ include_market: 'yes' }, { market_paid: ['1'] }, { market_scripts: ['0014' + 'AB'.repeat(20)] }, { market_fills: [2] }]) assert.equal(await ask(selection), 400, JSON.stringify(selection));
    assert.equal(selections.length, before);
    // At the bounds a selection is passed on.
    assert.equal(await ask({ market_candles: many(32), market_accounts: many(8) }), 200);
    assert.equal(selections.length, before + 1);
  } finally {
    Date.now = originalNow;
    if (servers) await servers.close();
    await rm(directory, { recursive: true, force: true });
  }
});
