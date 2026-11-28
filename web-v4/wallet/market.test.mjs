// What the wallet works out about the market of seconds against bitcoin without a page (market.mjs): the words of
// amounts and prices, the list of a person's Bitcoin addresses, which sell orders serve a purchase and how large each
// fill may be, the deposit, where a proven row differs from a listed one, the time a purchase leaves, what an action
// costs and counts against the daily limit, and an offer against the rest of the book.
//
// The arithmetic is held to the engine's own vectors (spec/market-vectors.json, written by v5/tests/market.rs) and to
// the SDK's two formulas; the addresses to the codec (web-v4/shared/bitcoin-address.mjs) and the engine's vectors.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import '../../client-v4/time-sdk.js';
import * as codec from '../shared/bitcoin-address.mjs';
import * as M from './market.mjs';

const sdk = globalThis.TimeSDK;
const vectors = JSON.parse(await readFile(new URL('../../spec/market-vectors.json', import.meta.url), 'utf8'));
const RULES = { profile: 'production', ...sdk.MARKET_RULES.production, ...sdk.MARKET_LIMITS }, LAB = { profile: 'laboratory', ...sdk.MARKET_RULES.laboratory, ...sdk.MARKET_LIMITS };
const W = byte => `0014${byte.repeat(20)}`;
const order = (extra = {}) => ({ id: '1', side: 'sell', owner: '5', price: '250000000', amount_micros: '40000000', sats: '10000', min_sats: '1000', confirmations: '3', pay_blocks: '6', deposit_ppm: '50000', min_deposit_micros: '0', bond_micros: '0', open: true, takes_fill: true, open_fills: 0, free_scripts: 2, forms: null, ...extra });
const seconds = micros => M.secondsText(micros);

test('amounts and prices are written exactly, and read back to the chain\'s whole numbers', () => {
  assert.deepEqual([M.btcText('12000'), M.btcText('1'), M.btcText('2100000000000000'), M.btcText('0')], ['0.00012000', '0.00000001', '21000000.00000000', '0.00000000']);
  assert.equal(M.bitcoinWords('12000'), '0.00012000 BTC (12,000 satoshis)'); assert.equal(M.bitcoinWords('1'), '0.00000001 BTC (1 satoshi)');
  assert.deepEqual([M.priceText('250000000'), M.priceText('250500'), M.priceText('1'), M.priceText('1000000000000000')], ['250', '0.2505', '0.000001', '1,000,000,000']);
  for (const [text, price] of [['250', '250000000'], ['0.25', '250000'], ['0.000001', '1'], ['1000000000', '1000000000000000'], [' 12.5 ', '12500000']]) { assert.equal(M.parsePrice(text), price); assert.equal(M.parsePrice(M.priceText(price).replaceAll(',', '')), price); }
  for (const bad of ['', '0', '0.0000001', '1e3', '-1', '1,5', '1000000001', '01', '.5', 'abc', '250 sats']) assert.throws(() => M.parsePrice(bad), /price/i, bad);
  assert.deepEqual([M.parseBtc('0.0005'), M.parseBtc('1'), M.parseBtc('0.00000001')], ['50000', '100000000', '1']);
  for (const bad of ['', '0', '0.000000001', '21000001', '1e-3', '-0.1', '0,5']) assert.throws(() => M.parseBtc(bad), /bitcoin/, bad);
  assert.equal(M.parsePercent('3', 'Deposit'), '30000'); assert.equal(M.parsePercent('2.5', 'Deposit'), '25000'); assert.equal(M.percentText('30000'), '3%'); assert.equal(M.percentText('25000'), '2.5%');
  assert.throws(() => M.parsePercent('101', 'Deposit'), /at most 100%/); assert.throws(() => M.parseWhole('2', 'Confirmations', 3, 100), /from 3 to 100/);
  // An address is grouped for comparing and never shortened: every character is there, in order.
  const address = 'bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9d';
  assert.equal(M.groupedAddress(address).replaceAll(' ', ''), address); assert.match(M.groupedAddress(address), /^(?:\S{4} )+\S{1,4}$/);
  assert.deepEqual([M.blocksDuration('6', '600000000'), M.blocksDuration('3', '600000000'), M.blocksDuration('144', '600000000'), M.blocksDuration('6', '1000000'), M.blocksDuration('6', null)], ['about 60 minutes', 'about 30 minutes', 'about 24 hours', 'about 6 seconds', 'as this test chain makes them']);
});

test('the deposit and the sizes follow the chain\'s formulas, on the engine\'s own vectors', () => {
  for (const item of vectors.sats) {
    if (item.price === '0' || item.amount_micros === '0') continue;
    let cost; try { cost = sdk.marketSats(item.amount_micros, item.price); } catch { continue; }
    assert.equal(cost, item.sats);
    // The smallest amount that costs at least these satoshis costs exactly them or more, and one microsecond less costs less.
    const least = BigInt(M.leastAmountFor(sdk, cost, item.price));
    assert.ok(BigInt(sdk.marketSats(least.toString(), item.price)) >= BigInt(cost), JSON.stringify(item));
    if (least > 1n) assert.ok(BigInt(sdk.marketSats((least - 1n).toString(), item.price)) < BigInt(cost), JSON.stringify(item));
  }
  for (const item of vectors.bought) if (item.price !== '0') assert.equal(sdk.marketBought(item.sats, item.price), item.bought_micros);
  // The engine's own take (kind 52) and its sell order (kind 50): the deposit of the take is 5% of its amount, or the least.
  const sell = vectors.actions.find(action => action.name === 'sell_order').payload, take = vectors.actions.find(action => action.kind === 52).payload;
  assert.equal(sdk.marketSats(take.amount_micros, sell.price), take.sats);
  assert.equal(M.takeDeposit(sell, take.amount_micros), ((BigInt(take.amount_micros) * 50000n + 999999n) / 1000000n > 250000n ? (BigInt(take.amount_micros) * 50000n + 999999n) / 1000000n : 250000n).toString());
  assert.equal(M.takeDeposit({ deposit_ppm: '50000', min_deposit_micros: '0' }, '12000000'), '600000'); assert.equal(M.takeDeposit({ deposit_ppm: '50000', min_deposit_micros: '900000' }, '12000000'), '900000');
  assert.equal(M.takeDeposit({ deposit_ppm: '1', min_deposit_micros: '0' }, '1'), '1', 'rounded up');
  assert.equal(M.buyBond('40000000', '100000'), '4000000');
});

test('the size of a fill: the smallest purchase, a rest that stays takeable, and all that is left', () => {
  const o = order();   // 40 s at 250 sats: 10,000 sats; smallest purchase 1,000 sats = 4 s
  // An order of a test network may ask a smallest purchase of one satoshi; Bitcoin still sends no less than its dust
  // amount, so the wallet makes no purchase it could not pay: 2.184 s cost 546 satoshis, 2.18 s 545.
  const tiny = order({ min_sats: '1' });
  assert.equal(M.sizeRefusal(sdk, tiny, '2184000', RULES), null);
  assert.match(M.sizeRefusal(sdk, tiny, '2180000', RULES), /less than 546 satoshis .* costs 545 satoshis: choose more/);
  assert.match(M.sizeRefusal(sdk, order({ min_sats: '1', amount_micros: '1000000' }), '1000000', { ...RULES, minSats: '1' }), /costs 250 satoshis: choose more/);
  assert.equal(M.fitAmount(sdk, tiny, '1000000', RULES), '0');
  assert.equal(M.sizeRefusal(sdk, o, '4000000', RULES), null); assert.equal(M.sizeRefusal(sdk, o, '40000000', RULES), null); assert.equal(M.sizeRefusal(sdk, o, '36000000', RULES), null);
  assert.equal(M.sizeRefusal(sdk, o, '3996001', RULES), null, 'a cost is rounded up: 3.996001 s cost 1,000 satoshis');
  assert.match(M.sizeRefusal(sdk, o, '3996000', RULES), /smallest purchase of this order costs 1,000 satoshis\. This amount costs 999\./);
  assert.match(M.sizeRefusal(sdk, o, '36004000', RULES), /That would leave 3\.996 seconds in the order, less than its smallest purchase\. Take all 40 seconds, or at most 36\.003999\./);
  assert.match(M.sizeRefusal(sdk, o, '40000001', RULES), /offers 40 seconds, no more/);
  // A rest below the order's smallest purchase can be taken whole when it costs at least the network's smallest trade.
  const rest = order({ amount_micros: '4000000', min_sats: '5000' });
  assert.equal(M.sizeRefusal(sdk, rest, '4000000', RULES), null); assert.match(M.sizeRefusal(sdk, order({ amount_micros: '3000000', min_sats: '5000' }), '3000000', RULES), /smallest trade of the network/);
  assert.equal(M.fitAmount(sdk, o, '10000000', RULES), '10000000'); assert.equal(M.fitAmount(sdk, o, '99000000', RULES), '40000000'); assert.equal(M.fitAmount(sdk, o, '38000000', RULES), '36003999'); assert.equal(M.fitAmount(sdk, o, '1000000', RULES), '0');
  // Whatever is asked, what fitAmount gives is a size the rule takes, and never more than asked.
  for (const wanted of ['1', '3999999', '4000000', '4000001', '17000000', '35999999', '36000001', '39999999', '40000000', '50000000']) { const got = M.fitAmount(sdk, o, wanted, RULES); if (got !== '0') { assert.equal(M.sizeRefusal(sdk, o, got, RULES), null, wanted); assert.ok(BigInt(got) <= BigInt(wanted), wanted); } }
});

test('a purchase is planned from the best prices, each fill within its order\'s rules, and never for more than was asked', () => {
  const book = [order({ id: '3', price: '300000000', amount_micros: '100000000' }), order({ id: '1' }), order({ id: '2', price: '250000000', amount_micros: '8000000' }), order({ id: '4', price: '100000000', free_scripts: 0 }), order({ id: '5', price: '90000000', open: false }), order({ id: '6', price: '80000000', owner: '9' }), order({ id: '7', side: 'buy', price: '500000000' })];
  // Left out: no free address (4), closed (5), the account's own (6, as account 9), the other side (7). Best first: 1 and 2 at 250, then 3.
  assert.deepEqual(M.takeable(book, '9').map(item => item.id), ['1', '2', '3']);
  const one = M.planPurchase(sdk, book, { amountMicros: '10000000' }, RULES, { ownAccount: '9' });
  assert.deepEqual([one.takes.length, one.takes[0].order, one.takes[0].amountMicros, one.takes[0].sats, one.takes[0].depositMicros, one.shortMicros], [1, '1', '10000000', '2500', '500000', '0']);
  const many = M.planPurchase(sdk, book, { amountMicros: '60000000' }, RULES, { ownAccount: '9' });
  assert.deepEqual(many.takes.map(take => [take.order, take.amountMicros, take.sats]), [['1', '40000000', '10000'], ['2', '8000000', '2000'], ['3', '12000000', '3600']]);
  assert.deepEqual([many.amountMicros, many.sats, many.shortMicros], ['60000000', '15600', '0']);
  // More than the book holds: what is short is said, not bought elsewhere.
  assert.equal(M.planPurchase(sdk, book, { amountMicros: '500000000' }, RULES, { ownAccount: '9' }).shortMicros, '352000000');
  // An order whose owner does not stand, or whose proven row differed, is skipped.
  assert.equal(M.planPurchase(sdk, book, { amountMicros: '10000000' }, RULES, { ownAccount: '9', skip: ['1'] }).takes[0].order, '2');
  // "I have X bitcoin": never more satoshis than X, and what it buys is the chain's rounding down.
  const have = M.planPurchase(sdk, book, { sats: '2501' }, RULES, { ownAccount: '9' });
  assert.deepEqual([have.takes[0].order, have.takes[0].amountMicros, have.takes[0].sats, have.shortSats], ['1', '10004000', '2501', '0']);
  assert.equal(have.takes[0].amountMicros, sdk.marketBought('2501', '250000000'));
  for (const sats of ['999', '1000', '1001', '9999', '10000', '12001', '50000']) { const plan = M.planPurchase(sdk, book, { sats }, RULES, { ownAccount: '9' }); assert.ok(BigInt(plan.sats) <= BigInt(sats), sats); for (const take of plan.takes) assert.equal(sdk.marketSats(take.amountMicros, take.price), take.sats); }
  // Less than the smallest purchase of every order buys nothing; no order is "rounded up" for the person.
  assert.deepEqual(M.planPurchase(sdk, book, { sats: '999' }, RULES, { ownAccount: '9' }).takes, []);
  assert.throws(() => M.planPurchase(sdk, book, { amountMicros: '0' }, RULES), /how many seconds/);
});

test('a proven order that is not what the list said stops the purchase, with the reason', () => {
  const plan = M.planPurchase(sdk, [order()], { amountMicros: '10000000' }, RULES).takes[0];
  const proven = { amount_micros: '40000000', bond_micros: '0', confirmations: '3', deposit_ppm: '50000', id: '1', key: 'aa'.repeat(32), min_deposit_micros: '0', min_sats: '1000', open: true, owner: '5', pay_blocks: '6', price: '250000000', scripts: [{ script: W('01') }], side: 'sell' };
  assert.deepEqual(M.planChanged(plan, proven), []);
  assert.match(M.changedWords(M.planChanged(plan, null)), /This order is gone.*Nothing was signed/);
  assert.match(M.changedWords(M.planChanged(plan, { ...proven, price: '900000000' })), /The price changed: the chain says 900 satoshis for one second, the list said 250 satoshis for one second\. Nothing was signed/);
  assert.match(M.changedWords(M.planChanged(plan, { ...proven, open: false, amount_micros: '0' })), /This order is closed/);
  assert.deepEqual(M.planChanged(plan, { ...proven, amount_micros: '9000000' }).map(change => change.field), ['amount_micros']);
  assert.deepEqual(M.planChanged(plan, { ...proven, min_deposit_micros: '5000000' }).map(change => change.field), ['deposit']);
  for (const [field, value] of [['owner', '6'], ['confirmations', '50'], ['pay_blocks', '3'], ['min_sats', '2000'], ['side', 'buy']]) assert.ok(M.planChanged(plan, { ...proven, [field]: value }).some(change => change.field === field), field);
  assert.match(M.changedWords(M.planChanged(plan, { ...proven, confirmations: '50' })), /not what the list said \(confirmations\)/);
  assert.deepEqual(M.orderChanged(order(), proven), []);
  // A fill a list named against the fill the chain proves.
  const fill = { order: '1', script: W('02'), price: '250000000', payer: '6', owner: '5', to: '6', side: 'sell', sats: '3000' };
  assert.deepEqual(M.fillChanged(fill, fill), []); assert.deepEqual(M.fillChanged(fill, null), ['gone']); assert.deepEqual(M.fillChanged(fill, { ...fill, script: W('03'), price: '1' }), ['script', 'price']);
});

test('whether an order\'s owner stands is judged on the owner\'s proven rows', () => {
  const key = 'aa'.repeat(32), o = { owner: '5', key }, state = (devices, security = []) => ({ time_micros: '2000000000', genesis: { genesis_time_micros: '1000000000' }, config: {}, accounts: [{ id: '5', devices }], security });
  const frozen = (row, now) => now < BigInt(row.frozen_until_elapsed_micros);
  assert.equal(M.ownerStands(sdk, state([{ public_key: key, can_spend: true }]), o, frozen), true);
  assert.equal(M.ownerStands(sdk, state([{ public_key: key, can_spend: false }, { public_key: 'bb'.repeat(32), can_spend: true }]), o, frozen), false, 'the key that made the order no longer spends');
  assert.equal(M.ownerStands(sdk, state([{ public_key: key, can_spend: true }], [{ account: '5', frozen_until_elapsed_micros: '2000000000' }]), o, frozen), false, 'frozen');
  assert.equal(M.ownerStands(sdk, state([{ public_key: key, can_spend: true }], [{ account: '5', frozen_until_elapsed_micros: '0' }]), o, frozen), true);
  assert.equal(M.ownerStands(sdk, { accounts: [], security: [] }, o, frozen), null, 'a state without the owner says nothing');
});

test('the list of a person\'s Bitcoin addresses: checked by the codec, each once, and read back strictly', async () => {
  const of = (script, network) => vectors.addresses.find(item => item.script === script && item.network === network).address;
  const good = [of(W('01'), 'regtest'), of('76a914111111111111111111111111111111111111111188ac', 'regtest'), of('5120' + '44'.repeat(32), 'regtest')];
  assert.deepEqual(M.pastedAddresses(` ${good[0]}\n${good[1]}, ${good[0]} ;${good[2]}\r\n`), good);
  assert.throws(() => M.pastedAddresses('  \n '), /at least one/); assert.throws(() => M.pastedAddresses(Array.from({ length: 201 }, (_, i) => 'x' + i).join(' ')), /At most 200/);
  const mainnet = of(W('01'), 'mainnet');
  const checked = await M.checkAddresses([...good, mainnet, 'not-an-address', good[0].slice(0, -1) + (good[0].endsWith('q') ? 'p' : 'q')], 'regtest', codec);
  assert.deepEqual(checked.map(entry => entry.ok), [true, true, true, false, false, false]);
  assert.deepEqual(checked.slice(0, 3).map(entry => [entry.script, entry.form]), [[W('01'), 'p2wpkh'], ['76a914111111111111111111111111111111111111111188ac', 'p2pkh'], ['5120' + '44'.repeat(32), 'p2tr']]);
  for (const bad of checked.slice(3)) assert.ok(typeof bad.reason === 'string' && bad.reason.length > 10 && bad.reason.length <= 200 && /^[\x20-\x7e]+$/.test(bad.reason), bad.reason);
  // Every address of the engine's vectors gives the engine's script, on its network.
  for (const item of vectors.addresses) assert.equal((await M.checkAddresses([item.address], item.network, codec))[0].script, item.script, item.address);
  const added = M.withAddresses([], checked), again = M.withAddresses(added.items, checked);
  assert.deepEqual([added.added, added.items.length, again.added, again.items.length], [3, 3, 0, 3]);
  const stored = M.writeAddressBook(added.items, 'regtest');
  assert.deepEqual(JSON.parse(stored), { v: 1, bitcoin: 'regtest', items: added.items.map(({ address, script }) => ({ address, script })) });
  assert.deepEqual((await M.readAddressBook(stored, 'regtest', codec)).items, added.items);
  // A record of another Bitcoin network, a damaged record, and an entry whose script is not its address's are not used.
  assert.deepEqual(await M.readAddressBook(stored, 'testnet3', codec), { items: [], dropped: 3 });
  assert.deepEqual(await M.readAddressBook('{', 'regtest', codec), { items: [], dropped: 0 }); assert.deepEqual(await M.readAddressBook(null, 'regtest', codec), { items: [], dropped: 0 });
  const swapped = JSON.parse(stored); swapped.items[0].script = W('09'); swapped.items.push({ address: mainnet, script: W('01') }, { address: good[1], script: swapped.items[1].script });
  const read = await M.readAddressBook(JSON.stringify(swapped), 'regtest', codec);
  assert.deepEqual([read.items.map(item => item.address), read.dropped], [[good[1], good[2]], 3]);
  assert.deepEqual(M.withoutAddress(added.items, W('01')).map(item => item.address), [good[1], good[2]]);
  assert.equal(M.addressKey('ab'.repeat(32), 'carol'), `timecurrency.market-addresses.v1:${'ab'.repeat(32)}:carol`);
});

test('what an address serves is said from the proven script row and the order\'s own entry', () => {
  const o = { scripts: [{ script: W('01'), used: true }, { script: W('02'), fill: '2' }, { script: W('03') }] };
  assert.deepEqual([M.addressState({ status: 'free', script: W('05') }).key, M.addressState({ status: 'used', script: W('01') }).key, M.addressState({ status: 'in_use', fill: '3', script: W('04') }).key], ['free', 'used', 'in_use']);
  assert.deepEqual([M.addressState({ status: 'listed', order: '1', script: W('03') }, o).key, M.addressState({ status: 'listed', order: '1', script: W('02') }, o).key, M.addressState({ status: 'listed', order: '1', script: W('02') }, o).fill], ['listed', 'in_use', '2']);
  assert.equal(M.addressState({ status: 'free', script: W('05') }).usable, true);
  for (const status of [{ status: 'used' }, { status: 'in_use', fill: '3' }, { status: 'listed', order: '1', script: W('03') }]) assert.equal(M.addressState(status, o).usable, false);
  assert.match(M.addressState({ status: 'used' }).detail, /serves once.*buys nothing/);
  assert.deepEqual(M.pieces([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
});

test('a purchase in progress: the time it leaves, what is still to pay, and the link for a Bitcoin wallet', () => {
  const fill = { amount_micros: '12000000', confirmations: '2', deposit_micros: '600000', id: '2', order: '1', owner: '5', pay_blocks: '6', payer: '6', price: '250000000', sats: '3000', script: W('02'), side: 'sell', start_height: '5', to: '6' };
  const state = best => ({ bitcoin: { meta: { best_height: best, halted: null } } });
  assert.deepEqual(M.payWindow(sdk, state(7), fill), { payBy: '11', lastHeight: '12', blocksLeft: '4', over: false, halted: false, best: '7' });
  assert.deepEqual([M.payWindow(sdk, state(11), fill).blocksLeft, M.payWindow(sdk, state(11), fill).over, M.payWindow(sdk, state(12), fill).over], ['0', true, true]);
  assert.equal(M.payWindow(sdk, { bitcoin: { meta: { best_height: 7, halted: { reason: 'x' } } } }, fill).halted, true);
  assert.throws(() => M.payWindow(sdk, {}, fill), /does not prove the Bitcoin header chain/);
  assert.deepEqual(M.purchaseState(fill, { firstSats: '3000' }), { key: 'waiting', sats: '3000' });
  assert.deepEqual(M.purchaseState(fill, { firstSats: '5000' }), { key: 'part', paidSats: '2000', sats: '3000' });
  assert.deepEqual(M.purchaseState(fill, null), { key: 'waiting', sats: '3000' }, 'without a note the proven row alone is said');
  assert.deepEqual([M.purchaseState(null, null, 'paid'), M.purchaseState(null, null, 'expired'), M.purchaseState(null, null, null), M.purchaseState(null, null, '<b>')], [{ key: 'ended', how: 'paid' }, { key: 'ended', how: 'expired' }, { key: 'ended', how: 'unknown' }, { key: 'ended', how: 'unknown' }]);
  assert.equal(M.bitcoinLink('bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9d', '3000'), 'bitcoin:bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9d?amount=0.00003000');
  assert.throws(() => M.bitcoinLink('x?amount=9&y', '3000'));
  // The notes of this browser's fills, and the id an action has just made.
  const notes = M.withNote(null, '7', { firstSats: '3000', order: '1' });
  assert.deepEqual(M.readNotes(notes), { 7: { firstSats: '3000', order: '1' } }); assert.deepEqual(M.readNotes('{"v":1,"fills":{"x":{},"8":{"firstSats":"-1","order":"1"}}}'), {});
  assert.deepEqual([M.newId(['1', '2'], ['1', '2', '9']), M.newId([], ['3', '10']), M.newId(['1'], ['1'])], ['9', '10', null]);
});

test('the terms of an order are held to the network\'s rules, and the form starts from them', () => {
  assert.deepEqual(M.sellDefaults(RULES), { confirmations: '3', payBlocks: '6', depositPpm: '30000', minDepositMicros: '0' });
  assert.deepEqual(M.sellDefaults(LAB), { confirmations: '1', payBlocks: '6', depositPpm: '30000', minDepositMicros: '0' });
  // The smallest purchase suggested: the order's price shared over its addresses, at least the network's smallest trade.
  assert.deepEqual([M.suggestedMinSats(sdk, '40000000', '250000000', 1, RULES), M.suggestedMinSats(sdk, '40000000', '250000000', 3, RULES), M.suggestedMinSats(sdk, '40000000', '250000000', 16, RULES), M.suggestedMinSats(sdk, '2000000', '250000000', 4, RULES)], ['10000', '3334', '1000', '500']);
  const terms = (extra = {}) => ({ side: 'sell', amountMicros: '40000000', price: '250000000', confirmations: '3', payBlocks: '6', depositPpm: '30000', minDepositMicros: '0', minSats: '1000', scripts: [W('01')], ...extra });
  assert.equal(M.termsRefusal(sdk, terms(), RULES), null);
  for (const [extra, words] of [[{ confirmations: '2' }, /Confirmations: from 3 to 100/], [{ payBlocks: '2' }, /Time to pay: from 3 to 144/], [{ minSats: '999' }, /at least 1,000 satoshis/], [{ minSats: '10001' }, /costs 10,000 satoshis, less than its smallest purchase of 10,001/],
    [{ depositPpm: '1000001' }, /at most 100%/], [{ minDepositMicros: '40000001' }, /least deposit is at most/], [{ scripts: [] }, /at least one of your Bitcoin addresses/], [{ scripts: Array.from({ length: 17 }, (_, i) => W(i.toString(16).padStart(2, '0'))) }, /at most 16 addresses/], [{ price: '1000000000000000', amountMicros: '9000000000000000' }, /more bitcoin than exists/]]) assert.match(M.termsRefusal(sdk, terms(extra), RULES), words);
  assert.equal(M.termsRefusal(sdk, terms({ confirmations: '1', payBlocks: '1', minSats: '1' }), LAB), null, 'a laboratory network takes less');
  assert.match(M.termsRefusal(sdk, { ...terms(), side: 'buy', forms: ['p2wpkh'], depositPpm: '29999' }, RULES), /bond of a buy order is at least 3%/);
  assert.match(M.termsRefusal(sdk, { ...terms(), side: 'buy', forms: [] }, RULES), /at least one kind of address/);
  assert.equal(M.termsRefusal(sdk, { ...terms(), side: 'buy', forms: ['p2wpkh'] }, RULES), null);
});

test('what an action costs and counts against the daily limit, and each refusal in words', () => {
  const say = (charge, extra = {}) => M.limitWords({ charge, balance: '100000000', secured: true, allowance: 600000000n, frozen: false, limit: 600000000n, seconds, ...extra });
  // A sell order of 40 s with two addresses on a network whose fee is 0.001 s: 3 fees, and the seconds leave the balance.
  const sell = M.marketCharge({ fee: '3000', locked: '40000000' });
  assert.deepEqual([sell.outflow, sell.count], [40003000n, 40003000n]);
  assert.equal(say(sell).line, '40.003 seconds count against your daily limit, like a payment: 600 is left today, 559.997 after this.');
  // A settle counts the seconds it hands over although the balance does not fall by them; so do a release and new addresses.
  const settle = M.marketCharge({ fee: '1000', extra: '12000000' });
  assert.deepEqual([settle.outflow, settle.count], [1000n, 12001000n]);
  // A cancel that brings back more than its fee costs nothing and counts nothing: a frozen account can still do it.
  const cancel = M.marketCharge({ fee: '1000', back: '40000000' });
  assert.deepEqual([cancel.outflow, cancel.count], [0n, 0n]);
  assert.equal(say(cancel, { frozen: true }).line, 'Nothing of your daily limit is used.');
  assert.match(say(sell, { frozen: true }).refusal, /^Your account is frozen/);
  assert.match(say(settle, { frozen: true }).refusal, /^Your account is frozen/);
  assert.match(say(sell, { balance: '40002999' }).refusal, /You do not have enough seconds for this: it needs 40\.003 seconds \(40 locked and 0\.003 in fees\), and your balance is 40\.002999\./);
  assert.match(say(sell, { allowance: 30000000n }).refusal, /^Daily limit reached\. This counts 40\.003 seconds against your daily limit, like a payment: more than the 30 seconds left of your daily limit today/);
  assert.match(say(sell, { allowance: 30000000n, limit: 30000000n }).refusal, /more than your daily limit of 30 seconds\. Raise the limit on Home/);
  assert.match(say(settle, { allowance: 12000999n }).refusal, /^Daily limit reached/, 'what a settle hands over counts');
  // An account with one key has no limit and no freeze: only its balance is asked.
  assert.deepEqual(M.limitWords({ charge: sell, balance: '100000000', secured: false, seconds }), { line: null });
  assert.match(M.limitWords({ charge: sell, balance: '1', secured: false, seconds }).refusal, /not have enough seconds/);
  assert.match(M.limitWords({ charge: M.marketCharge({ fee: '1000' }), balance: '999', secured: false, seconds }).refusal, /it needs 0\.001 seconds in fees/);
});

test('an offer far above the rest of the list is said before a person pays', () => {
  assert.deepEqual(M.againstBook('250000000', ['250000000', '260000000']), { far: false, alone: false, best: '250000000' });
  assert.equal(M.againstBook('300000000', ['250000000']).far, false, 'a fifth above is not far'); assert.equal(M.againstBook('300000001', ['250000000']).far, true);
  assert.deepEqual(M.againstBook('900000000', []), { far: false, alone: true, best: null });
  assert.match(M.againstBookWords('900000000', M.againstBook('900000000', ['250000000'])), /far above another offer on the list: 900 satoshis for one second, against 250 satoshis for one second\. Check before you pay\./);
  assert.match(M.againstBookWords('900000000', M.againstBook('900000000', [])), /No other offer/);
});

test('the Bitcoin network of the market is the proven one, and mainnet is closed', () => {
  assert.equal(M.bitcoinNetworkOf({ config: { bitcoin: { network: 'testnet3' } } }), 'testnet3');
  assert.throws(() => M.bitcoinNetworkOf({ config: { bitcoin: { network: 'signet' } } })); assert.throws(() => M.bitcoinNetworkOf({}));
  assert.match(M.testBitcoinWords('testnet3'), /test bitcoin \(Bitcoin testnet\)\. It has no value\. Never send real bitcoin/); assert.match(M.testBitcoinWords('regtest'), /test bitcoin/);
  assert.match(M.testBitcoinWords('mainnet'), /closed on this network/);
});

test('the module reaches no page, no storage and no network, and its warnings are plain sentences', async () => {
  const source = (await readFile(new URL('./market.mjs', import.meta.url), 'utf8')).split('\n').filter(line => !/^\s*\/\//.test(line)).join('\n');
  assert.doesNotMatch(source, /\bdocument\b|\bwindow\b|localStorage|sessionStorage|\bfetch\(|XMLHttpRequest|innerHTML|console\.|\bimport\s/);
  for (const words of [M.ADDRESS_WORDS, M.PAY_WORDS, M.SELL_WORDS]) for (const [key, text] of Object.entries(words)) assert.ok(/^[A-Z].*[.:]$/.test(text) && !/guarantee|profit|invest|safe to/i.test(text), key);
  // Each case of spec/market.md, section 10, that the pay screen must say: late, short, a batch too large to prove, the proof, giving up.
  assert.match(M.PAY_WORDS.exchange, /send late.*less than the amount.*batch.*larger than 100,000 bytes cannot be proven/);
  assert.match(M.PAY_WORDS.late, /after this purchase has ended, the bitcoin is with the seller and you get no seconds/);
  assert.match(M.PAY_WORDS.exact, /Paying more buys nothing more.*the rest stays to pay, to the same address/);
  assert.match(M.PAY_WORDS.proof, /an hour after the confirmations, anyone who runs a Bitcoin node can send the proof: note the number of this purchase.*deploy\/market-prover\/README\.md/);
  assert.match(M.PAY_WORDS.giveUp, /costs the deposit/); assert.match(M.SELL_WORDS.settle, /without any proof/); assert.match(M.ADDRESS_WORDS.exchange, /Never paste an address of an exchange account/);
});

// The engine's own proven rows (verifier-v4/fixtures/market-engine.json: the answers of the engine to a selection of the
// market, under headers signed by test validators), verified here by the installed verifier, and read as the wallet
// reads them. This is the one place where what the wallet works out meets rows the engine wrote.
test('on the engine\'s proven rows: the address and the amount of a fill, its time, the states of addresses, and the deposit', async () => {
  const installed = await import('../../client-v4/proof-verifier.mjs');
  const wrapped = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/market-engine.json', import.meta.url), 'utf8')), item = wrapped.cases.trading;
  const state = (await installed.verifyViewProof(item.proof, item.trust, item.request, item.now_ms)).state;
  assert.equal(sdk.marketSetting(state), true); assert.equal(M.bitcoinNetworkOf(state), 'regtest'); assert.deepEqual(M.headerChain(state), { best: 7n, halted: false });
  // Fill 2 was paid in part: what is still to pay is the row's `sats`, and its address is its script through the codec.
  const fill = sdk.marketFill(state, '2'), order = sdk.marketOrder(state, fill.order);
  assert.equal(fill.sats, '3000'); assert.equal(await codec.scriptToAddress(fill.script, M.bitcoinNetworkOf(state)), vectors.addresses.find(entry => entry.script === fill.script && entry.network === 'regtest')?.address ?? await codec.scriptToAddress(fill.script, 'regtest'));
  assert.equal(await codec.addressToScript(await codec.scriptToAddress(fill.script, 'regtest'), 'regtest'), fill.script);
  assert.deepEqual(M.payWindow(sdk, state, fill), { payBy: '11', lastHeight: '12', blocksLeft: '4', over: false, halted: false, best: '7' });
  assert.deepEqual(M.purchaseState(fill, { firstSats: '5000' }), { key: 'part', paidSats: '2000', sats: '3000' });
  // The deposit the fill still holds is the order's share of the seconds it still holds.
  assert.equal(M.takeDeposit(order, fill.amount_micros), fill.deposit_micros);
  // The five scripts of the fixture: used, in use by a fill of the order, listed, in use by a fill against a buy order, free.
  const said = script => M.addressState({ ...sdk.marketScript(state, script), script }, order).key;
  assert.deepEqual([wrapped.scripts.served, wrapped.scripts.serving, wrapped.scripts.listed, wrapped.scripts.of_a_fill_against_a_buy_order, wrapped.scripts.unknown].map(said), ['used', 'in_use', 'listed', 'in_use', 'free']);
  assert.equal(M.sizeRefusal(sdk, order, '4000000', sdk.marketRules(state)), null); assert.equal(M.fitAmount(sdk, order, '999000000', sdk.marketRules(state)), order.amount_micros);
  assert.deepEqual(M.orderChanged({ side: 'sell', owner: order.owner, price: order.price, amount_micros: order.amount_micros, min_sats: order.min_sats, confirmations: order.confirmations, pay_blocks: order.pay_blocks, open: true }, order), []);
});
