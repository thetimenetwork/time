// The market's actions in the SDK (client-v4/time-sdk.js, kinds 50 to 58; spec/market.md, section 6).
// - The engine's vectors (spec/market-vectors.json, written by v5/tests/market.rs from actions the engine accepted):
//   the SDK writes the same payload bytes, signs the same bytes with the same key, reads them back, and its builders
//   make the same payloads; the fee it names is the fee the engine took; the price of an amount is the engine's.
// - Every builder, and every refusal: the field set of each kind and side, numbers, bounds, scripts, forms, proofs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import './time-sdk.js';
import { scriptForm, stripWitness } from './bitcoin-address.mjs';

const sdk = globalThis.TimeSDK;
const engine = JSON.parse(await readFile(new URL('../spec/market-vectors.json', import.meta.url), 'utf8'));
const utf8 = new TextDecoder();
// An Ed25519 signing key from its 32-byte seed.
const keyOf = (seedHex) => crypto.subtle.importKey('pkcs8', sdk.concat(sdk.hexToBytes('302e020100300506032b657004220420'), sdk.hexToBytes(seedHex, 32)), { name: 'Ed25519' }, false, ['sign']);
const action = (name) => engine.actions.find(entry => entry.name === name);
const W = (byte) => `0014${byte.repeat(20)}`, TR = (byte) => `5120${byte.repeat(32)}`;
const SELL = Object.freeze({ amount_micros: '100000000', confirmations: '3', deposit_ppm: '50000', min_deposit_micros: '250000', min_sats: '1000', pay_blocks: '6', price: '250000000', scripts: [W('01'), TR('44')], side: 'sell' });
const BUY = Object.freeze({ amount_micros: '50000000', confirmations: '3', deposit_ppm: '100000', forms: ['p2tr', 'p2wpkh'], min_sats: '1000', pay_blocks: '6', price: '250000000', side: 'buy' });
const TAKE = Object.freeze({ amount_micros: '40000000', order: '1', sats: '10000', to: '8' });
const SALE = Object.freeze({ amount_micros: '20000000', confirmations: '2', order: '2', sats: '5000', script: W('07') });
const PROOF = Object.freeze({ ...action('proof_of_a_part').payload });
const shown = (value) => { try { return JSON.stringify(value, (_, item) => typeof item === 'bigint' ? `${item}n` : item)?.slice(0, 200); } catch { return String(value); } };
const refuses = (kind, payload, why) => assert.throws(() => sdk.marketActionPayload(kind, payload), why, shown(payload));
/// `base` with some fields changed; a value of `undefined` removes the field.
const but = (base, changes) => { const out = { ...base, ...changes }; for (const key of Object.keys(out)) if (out[key] === undefined) delete out[key]; return out; };

test('the vectors hold every kind, and the SDK names the kinds and the forms as the engine does', () => {
  assert.deepEqual(sdk.MARKET_KINDS, { order: 50, cancel: 51, take: 52, sell: 53, proof: 54, expire: 55, release: 56, settle: 57, scripts: 58 });
  assert.deepEqual(sdk.MARKET_FORMS, ['p2pkh', 'p2sh', 'p2tr', 'p2wpkh', 'p2wsh']);
  assert.ok(Object.isFrozen(sdk.MARKET_KINDS) && Object.isFrozen(sdk.MARKET_FORMS) && Object.isFrozen(sdk.MARKET_ACTION_LIMITS));
  assert.deepEqual([...new Set(engine.actions.map(entry => entry.kind))].sort(), [50, 51, 52, 53, 54, 55, 56, 57, 58]);
  assert.deepEqual(engine.actions.map(entry => entry.name), ['sell_order', 'buy_order', 'new_scripts', 'take_for_another', 'sell', 'proof_of_a_part', 'proof', 'take', 'release', 'settle', 'sell_the_rest', 'expire', 'cancel']);
  assert.equal(engine.bitcoin_network, 'regtest');
});

test('the vectors are the file the engine\'s test holds: its SHA-256 is the one pinned in v5/tests/market.rs', async () => {
  // The engine's test checks on every run that it still gives a text of this SHA-256, without reading the file
  // (the file is outside the engine's release). Here the file is held to the same line: a file that was not written
  // anew after the engine changed, or a pin that was not moved, fails one of the two.
  const source = await readFile(new URL('../v5/tests/market.rs', import.meta.url), 'utf8');
  const pinned = /const MARKET_VECTORS_SHA256: &str = "([0-9a-f]{64})";/.exec(source);
  assert.ok(pinned, 'the pin is in v5/tests/market.rs');
  const file = await readFile(new URL('../spec/market-vectors.json', import.meta.url));
  assert.equal(Buffer.from(await crypto.subtle.digest('SHA-256', file)).toString('hex'), pinned[1], 'spec/market-vectors.json is not the text the engine pins: run the export (V5_EXPORT_MARKET_VECTORS=1) and move the pin');
});

test('the SDK writes, signs and reads back each action exactly as the engine does', async () => {
  for (const vector of engine.actions) {
    const { name, kind, payload } = vector;
    assert.equal(utf8.decode(sdk.canonicalPayload(kind, payload)), vector.payload_json, name);
    assert.equal(JSON.stringify(payload), vector.payload_json, `${name}: the vector itself`);
    assert.deepEqual(sdk.marketActionPayload(kind, payload), payload, name);
    // The fields in another order, as a caller may hold them: the same bytes.
    const shuffled = Object.fromEntries(Object.entries(payload).reverse());
    assert.equal(utf8.decode(sdk.canonicalPayload(kind, shuffled)), vector.payload_json, name);
    const fields = { networkId: engine.network_id, kind, from: vector.from, nonce: vector.nonce, authEpoch: vector.auth_epoch, publicKey: vector.public_key, payload };
    const signed = await sdk.signAction(fields, await keyOf(vector.seed_hex));
    assert.equal(sdk.bytesToHex(signed), vector.signed_hex, name);
    assert.equal(sdk.bytesToHex(sdk.buildAction(fields)), vector.signed_hex.slice(0, -128), name);
    assert.deepEqual(sdk.decodeAction(sdk.hexToBytes(vector.signed_hex)), fields, name);
  }
});

test('each builder makes the payload of the engine\'s vector', () => {
  const made = {
    sell_order: p => sdk.marketSellOrder({ amountMicros: p.amount_micros, price: p.price, scripts: p.scripts, confirmations: p.confirmations, payBlocks: p.pay_blocks, minSats: p.min_sats, depositPpm: p.deposit_ppm, minDepositMicros: p.min_deposit_micros }),
    // The forms in another order: a buy order lists them ascending.
    buy_order: p => sdk.marketBuyOrder({ amountMicros: p.amount_micros, price: p.price, forms: [...p.forms].reverse(), confirmations: p.confirmations, payBlocks: p.pay_blocks, minSats: p.min_sats, depositPpm: p.deposit_ppm }),
    new_scripts: p => sdk.marketNewScripts({ order: p.order, scripts: p.scripts }),
    take_for_another: p => sdk.marketTake({ order: p.order, amountMicros: p.amount_micros, price: '250000000', to: p.to }),
    take: p => sdk.marketTake({ order: p.order, amountMicros: p.amount_micros, price: '250000000', to: p.to }),
    sell: p => sdk.marketSell({ order: p.order, amountMicros: p.amount_micros, price: '250000000', confirmations: p.confirmations, script: p.script }),
    sell_the_rest: p => sdk.marketSell({ order: p.order, amountMicros: p.amount_micros, price: '250000000', confirmations: p.confirmations, script: p.script }),
    proof_of_a_part: p => sdk.marketProof({ fill: p.fill, blockHash: p.block_hash, transaction: p.transaction, coinbase: p.coinbase, vout: p.vout, merkleProof: p.merkle_proof }),
    proof: p => sdk.marketProof({ fill: p.fill, blockHash: p.block_hash, transaction: p.transaction, coinbase: p.coinbase, vout: p.vout, merkleProof: p.merkle_proof }),
    release: p => sdk.marketRelease({ fill: p.fill }),
    settle: p => sdk.marketSettle({ fill: p.fill }),
    expire: p => sdk.marketExpire({ fill: p.fill }),
    cancel: p => sdk.marketCancel({ order: p.order }),
  };
  for (const vector of engine.actions) {
    const payload = made[vector.name](vector.payload);
    assert.deepEqual(payload, vector.payload, vector.name);
    assert.equal(JSON.stringify(payload), vector.payload_json, `${vector.name}: the fields are in the order they are signed`);
  }
  assert.deepEqual(Object.keys(made).sort(), engine.actions.map(entry => entry.name).sort());
});

test('a whole number is given to a builder as a decimal string, a BigInt or a safe integer, and as nothing else', () => {
  const expected = { amount_micros: '40000000', order: '7', sats: '10000', to: '8' };
  assert.deepEqual(sdk.marketTake({ order: '7', amountMicros: '40000000', price: '250000000', to: '8' }), expected);
  assert.deepEqual(sdk.marketTake({ order: 7n, amountMicros: 40000000n, price: 250000000n, to: 8n }), expected);
  assert.deepEqual(sdk.marketTake({ order: 7, amountMicros: 40000000, price: 250000000, to: 8 }), expected);
  assert.deepEqual(sdk.marketTake({ order: 7, amountMicros: 40000000, price: 250000000, to: 0 }).to, '0');
  for (const bad of ['07', '+7', '7.0', '7 ', ' 7', '', '0x7', '7e0', '-7', -7, 7.5, NaN, Infinity, 2 ** 53, -7n, 1n << 64n, '18446744073709551616', true, [7], { valueOf: () => 7 }, new String('7')]) {
    assert.throws(() => sdk.marketTake({ order: bad, amountMicros: '40000000', price: '250000000', to: '8' }), /order is a whole number from 0 to 2\^64-1/, String(bad));
    assert.throws(() => sdk.marketCancel({ order: bad }), /order is a whole number/);
    assert.throws(() => sdk.marketExpire({ fill: bad }), /fill is a whole number/);
  }
  assert.equal(sdk.marketCancel({ order: '18446744073709551615' }).order, '18446744073709551615');
});

test('a builder takes exactly its named arguments', () => {
  const builders = {
    marketSellOrder: { amountMicros: '100000000', price: '250000000', scripts: [W('01')], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0' },
    marketBuyOrder: { amountMicros: '100000000', price: '250000000', forms: ['p2wpkh'], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '50000' },
    marketCancel: { order: '1' },
    marketTake: { order: '1', amountMicros: '40000000', price: '250000000', to: '8' },
    marketSell: { order: '1', amountMicros: '40000000', price: '250000000', confirmations: '3', script: W('07') },
    marketProof: { fill: PROOF.fill, blockHash: PROOF.block_hash, transaction: PROOF.transaction, coinbase: PROOF.coinbase, vout: PROOF.vout, merkleProof: PROOF.merkle_proof },
    marketExpire: { fill: '1' }, marketRelease: { fill: '1' }, marketSettle: { fill: '1' },
    marketNewScripts: { order: '1', scripts: [W('02')] },
  };
  const KIND = { marketSellOrder: 50, marketBuyOrder: 50, marketCancel: 51, marketTake: 52, marketSell: 53, marketProof: 54, marketExpire: 55, marketRelease: 56, marketSettle: 57, marketNewScripts: 58 };
  for (const [name, given] of Object.entries(builders)) {
    const payload = sdk[name](given);
    assert.deepEqual(sdk.marketActionPayload(KIND[name], payload), payload, name);
    assert.deepEqual(Object.keys(payload), [...Object.keys(payload)].sort(), `${name}: fields ascending`);
    for (const missing of Object.keys(given)) {
      assert.throws(() => sdk[name](but(given, { [missing]: undefined })), new RegExp(`${name} needs ${missing}`));
      assert.throws(() => sdk[name]({ ...given, [missing]: null }), new RegExp(`${name} needs ${missing}`));
    }
    assert.throws(() => sdk[name]({ ...given, extra: '1' }), new RegExp(`${name} has no argument extra`));
    // A field's name in place of the argument's: the misspelling a builder is there to catch.
    assert.throws(() => sdk[name]({ ...given, amount_micros: '1' }), new RegExp(`${name} has no argument amount_micros`));
    for (const bad of [undefined, null, 'x', 5, [given], new Map(), Object.create(given)]) assert.throws(() => sdk[name](bad), new RegExp(`${name} takes one object of named arguments`));
  }
  // The lists are copied: a caller's list is not the payload's.
  const scripts = [W('01'), W('02')], order = sdk.marketSellOrder({ ...builders.marketSellOrder, scripts });
  scripts.push(W('03'));
  assert.deepEqual(order.scripts, [W('01'), W('02')]);
  const forms = ['p2wsh', 'p2pkh'], buy = sdk.marketBuyOrder({ ...builders.marketBuyOrder, forms });
  assert.deepEqual(buy.forms, ['p2pkh', 'p2wsh']);
  assert.deepEqual(forms, ['p2wsh', 'p2pkh'], 'the caller\'s list is left as it was');
  for (const bad of [null, 'p2wpkh', { 0: 'p2wpkh', length: 1 }, new Set(['p2wpkh'])]) {
    assert.throws(() => sdk.marketBuyOrder({ ...builders.marketBuyOrder, forms: bad }), /forms is a list|needs forms/);
    assert.throws(() => sdk.marketSellOrder({ ...builders.marketSellOrder, scripts: bad }), /scripts is a list|needs scripts/);
    assert.throws(() => sdk.marketNewScripts({ order: '1', scripts: bad }), /scripts is a list|needs scripts/);
  }
});

test('the satoshis of a fill are the engine\'s: ceil(amount × price / 10^12)', () => {
  assert.ok(engine.sats.length >= 20);
  let priced = 0, refused = 0;
  for (const { amount_micros: amount, price, sats } of engine.sats) {
    const take = () => sdk.marketTake({ order: '1', amountMicros: amount, price, to: '0' });
    const sale = () => sdk.marketSell({ order: '1', amountMicros: amount, price, confirmations: '1', script: W('07') });
    if (sats === null || amount === '0') { refused += 1; assert.throws(take, /price is from 1|more satoshis than exist|amount_micros is from 1/, `${amount} at ${price}`); assert.throws(sale); continue; }
    priced += 1;
    assert.equal(take().sats, sats, `${amount} at ${price}`);
    assert.equal(sale().sats, sats);
    // An order of that amount at that price is worth exactly as much: `min_sats` may be that, and not one more.
    const order = { ...SELL, amount_micros: amount, price, min_deposit_micros: '0' };
    assert.deepEqual(sdk.marketActionPayload(50, { ...order, min_sats: sats }).min_sats, sats);
    if (BigInt(sats) < 2100000000000000n) refuses(50, { ...order, min_sats: (BigInt(sats) + 1n).toString() }, /worth at least its smallest trade/);
  }
  assert.ok(priced >= 12 && refused >= 6, `${priced} priced, ${refused} refused`);
});

test('kind 50: what an order must be, as the engine has it', () => {
  assert.deepEqual(sdk.marketActionPayload(50, SELL), SELL);
  assert.deepEqual(sdk.marketActionPayload(50, BUY), BUY);
  // The cases of v5/tests/market.rs (what_an_order_and_a_fill_must_be), and more.
  const cases = [
    [{ price: '0' }, /price is from 1 to 1000000000000000/],
    [{ price: '1000000000000001' }, /price is from 1 to 1000000000000000/],
    [{ amount_micros: '0' }, /amount_micros is from 1/],
    [{ min_sats: '25001' }, /worth at least its smallest trade/],
    [{ min_sats: '0' }, /min_sats is from 1/],
    [{ confirmations: '0' }, /confirmations is from 1 to 100/],
    [{ confirmations: '101' }, /confirmations is from 1 to 100/],
    [{ pay_blocks: '0' }, /pay_blocks is from 1 to 144/],
    [{ pay_blocks: '145' }, /pay_blocks is from 1 to 144/],
    [{ deposit_ppm: '1000001' }, /deposit_ppm is from 0 to 1000000/],
    [{ amount_micros: '18446744073709551615', price: '1000000000000000' }, /more satoshis than exist/],
    [{ side: 'Sell' }, /side of an order is "sell" or "buy"/],
    [{ side: undefined }, /side of an order/],
    [{ side: ['sell'] }, /side of an order/],
  ];
  for (const base of [SELL, BUY]) for (const [change, why] of cases) refuses(50, but(base, change), why);
  for (const [change, why] of [
    [{ scripts: [] }, /1 to 16 receiving scripts/],
    [{ scripts: ['6a0100'] }, /five standard forms/],
    [{ scripts: [W('01'), W('01')] }, /listed once/],
    [{ scripts: [W('ab').toUpperCase()] }, /five standard forms/],
    [{ scripts: [`${W('01')}00`] }, /five standard forms/],
    [{ scripts: [W('01'), 5] }, /five standard forms/],
    [{ scripts: Array.from({ length: 17 }, (_, i) => W(i.toString(16).padStart(2, '0'))) }, /1 to 16 receiving scripts/],
    [{ scripts: null }, /1 to 16 receiving scripts/],
    [{ scripts: W('01') }, /1 to 16 receiving scripts/],
    [{ scripts: { 0: W('01'), length: 1 } }, /1 to 16 receiving scripts/],
    [{ scripts: undefined }, /has exactly the fields amount_micros, confirmations, deposit_ppm, min_deposit_micros, min_sats, pay_blocks, price, scripts, side/],
    [{ min_deposit_micros: undefined }, /has exactly the fields/],
    [{ forms: ['p2tr'] }, /has exactly the fields/],
    [{ forms: null }, /has exactly the fields/],
    [{ min_deposit_micros: '100000001' }, /least deposit of a fill is at most what the order offers/],
    [{ extra: '1' }, /has exactly the fields/],
  ]) refuses(50, but(SELL, change), why);
  assert.equal(sdk.marketActionPayload(50, { ...SELL, scripts: Array.from({ length: 16 }, (_, i) => W(i.toString(16).padStart(2, '0'))) }).scripts.length, 16);
  assert.equal(sdk.marketActionPayload(50, { ...SELL, min_deposit_micros: SELL.amount_micros }).min_deposit_micros, SELL.amount_micros);
  for (const [change, why] of [
    [{ forms: [] }, /forms is a list of at least one of/],
    [{ forms: ['p2wpkh', 'p2tr'] }, /in this order, each once/],
    [{ forms: ['p2tr', 'p2tr'] }, /in this order, each once/],
    [{ forms: ['p2pk'] }, /forms is a list/],
    [{ forms: ['P2TR'] }, /forms is a list/],
    [{ forms: null }, /forms is a list/],
    [{ forms: 'p2tr' }, /forms is a list/],
    [{ forms: [['p2tr']] }, /forms is a list/],
    [{ forms: undefined }, /has exactly the fields amount_micros, confirmations, deposit_ppm, forms, min_sats, pay_blocks, price, side/],
    [{ scripts: [W('04')] }, /has exactly the fields/],
    [{ scripts: null }, /has exactly the fields/],
    [{ min_deposit_micros: '0' }, /has exactly the fields/],
  ]) refuses(50, but(BUY, change), why);
  assert.deepEqual(sdk.marketActionPayload(50, { ...BUY, forms: [...sdk.MARKET_FORMS] }).forms, sdk.MARKET_FORMS);
  // The outer bounds pass here; a production network asks more of each (spec/market.md, 2.1) and refuses these itself.
  for (const change of [{ confirmations: '1' }, { confirmations: '100' }, { pay_blocks: '1' }, { pay_blocks: '144' }, { deposit_ppm: '0' }, { deposit_ppm: '1000000' }, { min_sats: '1' }]) assert.ok(sdk.marketActionPayload(50, but(BUY, change)));
});

test('every number of a payload is a decimal string without leading zeros, and nothing else', () => {
  const places = [[50, SELL, ['amount_micros', 'confirmations', 'deposit_ppm', 'min_deposit_micros', 'min_sats', 'pay_blocks', 'price']], [50, BUY, ['amount_micros', 'confirmations', 'deposit_ppm', 'min_sats', 'pay_blocks', 'price']],
    [51, { order: '1' }, ['order']], [52, TAKE, ['amount_micros', 'order', 'sats', 'to']], [53, SALE, ['amount_micros', 'confirmations', 'order', 'sats']], [54, PROOF, ['fill', 'vout']],
    [55, { fill: '1' }, ['fill']], [56, { fill: '1' }, ['fill']], [57, { fill: '1' }, ['fill']], [58, { order: '1', scripts: [W('02')] }, ['order']]];
  for (const [kind, base, fields] of places) {
    assert.deepEqual(sdk.marketActionPayload(kind, base), base);
    for (const field of fields) for (const bad of [Number(base[field]), BigInt(base[field]), `0${base[field]}`, `${base[field]} `, `+${base[field]}`, `${base[field]}.0`, '-1', '', '1e3', '0x10', '18446744073709551616', '99999999999999999999999', null, true, [base[field]], { toString: () => base[field] }]) {
      refuses(kind, { ...base, [field]: bad }, new RegExp(`${field} is a whole number as a decimal string without leading zeros`));
    }
  }
  // Orders and fills are numbered from 1; an account may be number 0; an output may be the first.
  for (const [kind, base, field] of [[51, { order: '1' }, 'order'], [52, TAKE, 'order'], [53, SALE, 'order'], [58, { order: '1', scripts: [W('02')] }, 'order'], [54, PROOF, 'fill'], [55, { fill: '1' }, 'fill'], [56, { fill: '1' }, 'fill'], [57, { fill: '1' }, 'fill']]) refuses(kind, { ...base, [field]: '0' }, new RegExp(`${field} is from 1`));
  assert.equal(sdk.marketActionPayload(52, { ...TAKE, to: '0' }).to, '0');
  assert.equal(sdk.marketActionPayload(54, { ...PROOF, vout: '0' }).vout, '0');
  assert.equal(sdk.marketActionPayload(54, { ...PROOF, vout: '4294967295' }).vout, '4294967295');
  refuses(54, { ...PROOF, vout: '4294967296' }, /vout is from 0 to 4294967295/);
});

test('kinds 51 to 53 and 55 to 58: exactly the fields of the kind', () => {
  const good = { 51: { order: '1' }, 52: TAKE, 53: SALE, 55: { fill: '1' }, 56: { fill: '1' }, 57: { fill: '1' }, 58: { order: '1', scripts: [W('02'), TR('03')] } };
  for (const [kind, payload] of Object.entries(good)) {
    assert.deepEqual(sdk.marketActionPayload(Number(kind), payload), payload);
    refuses(Number(kind), { ...payload, more: '1' }, /has exactly the fields/);
    for (const field of Object.keys(payload)) refuses(Number(kind), but(payload, { [field]: undefined }), /has exactly the fields/);
    refuses(Number(kind), {}, /has exactly the fields/);
  }
  // A payload with a field too many, as the engine's test has it; an order where a fill is named, and the reverse.
  refuses(55, { fill: '1', order: '1' }, /has exactly the fields fill/);
  for (const kind of [55, 56, 57]) refuses(kind, { order: '1' }, /has exactly the fields fill/);
  refuses(51, { fill: '1' }, /has exactly the fields order/);
  // Fills: an amount of nothing; satoshis that no price makes of the amount.
  refuses(52, { ...TAKE, amount_micros: '0' }, /amount_micros is from 1/);
  refuses(53, { ...SALE, amount_micros: '0' }, /amount_micros is from 1/);
  for (const [kind, base] of [[52, TAKE], [53, SALE]]) {
    refuses(kind, { ...base, sats: '0' }, /sats is from 1/);
    refuses(kind, { ...base, sats: '2100000000000001' }, /sats is from 1 to 2100000000000000/);
    // At the highest price a microsecond costs 1,000 satoshis; at the lowest, 10^12 microseconds cost one.
    refuses(kind, { ...base, amount_micros: '5', sats: '5001' }, /sats is the price of amount_micros/);
    assert.ok(sdk.marketActionPayload(kind, { ...base, amount_micros: '5', sats: '5000' }));
    refuses(kind, { ...base, amount_micros: '2000000000001', sats: '2' }, /sats is the price of amount_micros/);
    assert.ok(sdk.marketActionPayload(kind, { ...base, amount_micros: '2000000000001', sats: '3' }));
  }
  // A sale: the confirmations within the outer bounds, the script of a standard form.
  for (const bad of ['0', '101']) refuses(53, { ...SALE, confirmations: bad }, /confirmations is from 1 to 100/);
  for (const bad of ['6a0100', W('ab').toUpperCase(), `${W('07')}00`, W('07').slice(2), '', null, 7, [W('07')]]) refuses(53, { ...SALE, script: bad }, /five standard forms/);
  // New scripts.
  for (const [scripts, why] of [[[], /1 to 16/], [null, /1 to 16/], [[W('02'), W('02')], /listed once/], [['6a0100'], /five standard forms/], [Array.from({ length: 17 }, (_, i) => TR(i.toString(16).padStart(2, '0'))), /1 to 16/]]) refuses(58, { order: '1', scripts }, why);
});

test('kind 54: a proof carries a block hash, two transactions without witness data and a Merkle proof, within the engine\'s sizes', () => {
  assert.deepEqual(sdk.marketActionPayload(54, PROOF), PROOF);
  assert.deepEqual(Object.keys(PROOF), ['block_hash', 'coinbase', 'fill', 'merkle_proof', 'transaction', 'vout']);
  for (const field of Object.keys(PROOF)) refuses(54, but(PROOF, { [field]: undefined }), /has exactly the fields block_hash, coinbase, fill, merkle_proof, transaction, vout/);
  refuses(54, { ...PROOF, script: W('01') }, /has exactly the fields/);
  for (const bad of [PROOF.block_hash.toUpperCase(), PROOF.block_hash.slice(2), `${PROOF.block_hash}00`, `0x${PROOF.block_hash.slice(2)}`, '', null, 5, PROOF.block_hash.replace(/.$/, 'g')]) refuses(54, { ...PROOF, block_hash: bad }, /block_hash is 64 lowercase hexadecimal characters/);
  for (const [field, least, most] of [['transaction', 65, 100000], ['coinbase', 1, 150000]]) {
    for (const bad of [PROOF[field].toUpperCase().replace(/^[0-9]*$/, 'AB'), `${PROOF[field]}0`, `${PROOF[field]}zz`, '', null, 5, [PROOF[field]], `01000000${'11'.repeat(most - 3)}`]) refuses(54, { ...PROOF, [field]: bad }, new RegExp(`${field} is lowercase hexadecimal of ${least} to ${most} bytes`));
    // With witness data, as a Bitcoin node gives it: refused, and `stripWitness` makes it what a proof carries.
    for (const vector of engine.actions.filter(entry => entry.kind === 54)) {
      const given = vector.bitcoin_node[field];
      assert.notEqual(given, vector.payload[field]);
      refuses(54, { ...vector.payload, [field]: given }, new RegExp(`${field} is serialized without witness data`));
      assert.equal(stripWitness(given), vector.payload[field]);
    }
    assert.ok(sdk.marketActionPayload(54, { ...PROOF, [field]: `01000000${'11'.repeat(61)}` }), '65 bytes');
    assert.ok(sdk.marketActionPayload(54, { ...PROOF, [field]: `01000000${'11'.repeat(most - 4)}` }), 'the most a proof carries');
  }
  // The payment is longer than 64 bytes; the coinbase may be as short as a miner makes it.
  refuses(54, { ...PROOF, transaction: `01000000${'11'.repeat(60)}` }, /transaction is lowercase hexadecimal of 65 to 100000 bytes/);
  assert.ok(sdk.marketActionPayload(54, { ...PROOF, coinbase: `01000000${'11'.repeat(56)}` }), '60 bytes');
  for (const bad of [PROOF.merkle_proof.toUpperCase(), `${PROOF.merkle_proof}0`, '', null, '00'.repeat(85), '00'.repeat(4097)]) refuses(54, { ...PROOF, merkle_proof: bad }, /merkle_proof is lowercase hexadecimal of 86 to 4096 bytes/);
  assert.ok(sdk.marketActionPayload(54, { ...PROOF, merkle_proof: '00'.repeat(86) }));
  assert.ok(sdk.marketActionPayload(54, { ...PROOF, merkle_proof: '00'.repeat(4096) }));
  // The largest payment with the largest coinbase and the largest Merkle proof: in hexadecimal they fit one action.
  const largest = { ...PROOF, transaction: `01000000${'11'.repeat(100000 - 4)}`, coinbase: `01000000${'11'.repeat(150000 - 4)}`, merkle_proof: '00'.repeat(4096), fill: '18446744073709551615', vout: '4294967295' };
  const bytes = sdk.canonicalPayload(54, largest).length;
  assert.ok(bytes > 500000 && bytes <= 512 * 1024, String(bytes));
});

test('what is not a payload of the market is refused, whatever its kind', () => {
  for (const kind of [50, 51, 52, 53, 54, 55, 56, 57, 58]) {
    for (const bad of [undefined, null, 'x', 5, [], [{ fill: '1' }], new Map([['fill', '1']]), Object.create({ fill: '1' }), new (class Fill { constructor() { this.fill = '1'; } })(), Object.create(null)]) {
      refuses(kind, bad, /A market payload is a plain object/);
      assert.throws(() => sdk.canonicalPayload(kind, bad), /A market payload is a plain object/);
    }
  }
  for (const kind of [49, 59, 0, -1, 50.5, '50', '54', null, undefined, NaN]) assert.throws(() => sdk.marketActionPayload(kind, { fill: '1' }), /The kinds of the market are 50 to 58/);
  // The kinds beside the market's are what they were: 49 and 59 are no kinds, and an extension keeps its own rule.
  assert.throws(() => sdk.canonicalPayload(49, { fill: '1' }), /Unknown action or invalid payload/);
  assert.throws(() => sdk.canonicalPayload(59, { fill: '1' }), /Unknown action or invalid payload/);
  assert.equal(utf8.decode(sdk.canonicalPayload(60, { b: '1', a: '2' })), '{"a":"2","b":"1"}');
  // A field inherited, or read through a getter that changes its answer, is not a field of the payload.
  const inherited = Object.assign(Object.create({ side: 'sell' }), SELL); delete inherited.side;
  refuses(50, inherited, /A market payload is a plain object/);
});

test('an action that was signed is read back only if its payload is the one form', async () => {
  const vector = action('take'), key = await keyOf(vector.seed_hex);
  const fields = { networkId: engine.network_id, kind: 52, from: vector.from, nonce: vector.nonce, authEpoch: vector.auth_epoch, publicKey: vector.public_key, payload: vector.payload };
  const good = await sdk.signAction(fields, key);
  // The same envelope around a payload the SDK would not write: fields in another order, a number as a number.
  const around = (json) => { const body = new TextEncoder().encode(json), head = good.slice(0, 19 + 32 + 1 + 24 + 32), length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, body.length); return sdk.concat(head, length, body, new Uint8Array(64)); };
  assert.deepEqual(sdk.decodeAction(around(vector.payload_json)).payload, vector.payload);
  for (const json of ['{"to":"6","sats":"5000","order":"1","amount_micros":"20000000"}', vector.payload_json.replace('"5000"', '5000'), vector.payload_json.replace('{', '{ '), vector.payload_json.replace('}', ',"more":"1"}'), '{}']) {
    assert.throws(() => sdk.decodeAction(around(json)), /Noncanonical action payload|has exactly the fields|whole number/, json);
  }
  // An action is not built around a payload that is refused.
  assert.throws(() => sdk.buildAction({ ...fields, payload: { ...vector.payload, sats: '05000' } }), /sats is a whole number/);
  await assert.rejects(sdk.signAction({ ...fields, kind: 56, payload: vector.payload }, key), /has exactly the fields fill/);
});

test('the fee of an action is what the engine took', () => {
  for (const vector of engine.actions) assert.equal(sdk.marketActionFee(vector.kind, vector.payload, vector.network_fee_micros), vector.fee_micros, vector.name);
  const times = (name) => BigInt(action(name).fee_micros) / BigInt(action(name).network_fee_micros);
  // The vectors hold an order with three scripts, new scripts, a proof of one fee and a proof of more.
  assert.deepEqual([times('sell_order'), times('buy_order'), times('new_scripts')], [4n, 1n, 3n]);
  // A proof of an ordinary payment costs about a dozen fees; a larger one, more.
  assert.ok(times('proof_of_a_part') >= 4n && times('proof_of_a_part') <= 16n, String(times('proof_of_a_part')));
  assert.ok(times('proof') > 20n);
  for (const name of ['proof_of_a_part', 'proof']) assert.equal(times(name), 1n + BigInt(Math.floor(action(name).payload_json.length / 256)), name);
  // The fee once more for each script; once more for every 256 bytes of a proof's payload, counted as it is signed.
  assert.equal(sdk.marketActionFee(50, SELL, '1000'), '3000');
  assert.equal(sdk.marketActionFee(50, BUY, '1000'), '1000');
  assert.equal(sdk.marketActionFee(58, { order: '1', scripts: Array.from({ length: 16 }, (_, i) => W(i.toString(16).padStart(2, '0'))) }, 1000n), '17000');
  for (const [kind, payload] of [[51, { order: '1' }], [52, TAKE], [53, SALE], [55, { fill: '1' }], [56, { fill: '1' }], [57, { fill: '1' }]]) assert.equal(sdk.marketActionFee(kind, payload, 1000), '1000');
  const sized = (bytes) => { const empty = sdk.canonicalPayload(54, { ...PROOF, merkle_proof: '00'.repeat(86) }).length - 172; return { ...PROOF, merkle_proof: '00'.repeat((bytes - empty) / 2) }; };
  for (const [bytes, fees] of [[1022, 4], [1024, 5], [1278, 5], [1280, 6], [2048, 9], [8192, 33]]) {
    assert.equal(sdk.canonicalPayload(54, sized(bytes)).length, bytes);
    assert.equal(sdk.marketActionFee(54, sized(bytes), '1000'), String(1000 * fees), `${bytes} bytes`);
  }
  assert.equal(sdk.marketActionFee(51, { order: '1' }, '0'), '0');
  assert.throws(() => sdk.marketActionFee(51, { order: '0' }, '1000'), /order is from 1/);
  assert.throws(() => sdk.marketActionFee(51, { order: '1' }, '01000'), /networkFeeMicros is a whole number/);
  assert.throws(() => sdk.marketActionFee(50, SELL, '18446744073709551615'), /more than a balance can hold/);
});

test('the form of a script is the engine\'s and the address codec\'s', () => {
  for (const { form, script } of engine.forms) {
    if (form === null) { assert.throws(() => sdk.marketScriptForm(script), /five standard forms/); assert.throws(() => scriptForm(script)); }
    else { assert.equal(sdk.marketScriptForm(script), form); assert.equal(scriptForm(script), form); }
  }
  for (const bad of [undefined, null, 5, [], [W('01')], W('ab').toUpperCase(), ` ${W('01')}`, `${W('01')}\n`]) assert.throws(() => sdk.marketScriptForm(bad), /five standard forms/);
});
