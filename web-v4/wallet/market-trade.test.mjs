// The traders' side of the wallet's market: what is worked out without a page (market-trade.mjs: the depth, the
// chart's geometry, the stop orders with their triggers and refusals), and the traders' view on the stand-in page
// (market-trade-ui.mjs over tests/market-world.mjs). The chain is tests/mock-market-chain.mjs, not the engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { world, sdk, W, addressOf, textOf, all, byText, NET } from './tests/market-world.mjs';
import * as T from './market-trade.mjs';
import { TRADE_WORDS } from './market-trade-ui.mjs';
import { addressKey, SELL_WORDS } from './market.mjs';

const A = { one: await addressOf(W('01')), two: await addressOf(W('02')) };
const sellOrder = (extra = {}) => sdk.marketSellOrder({ amountMicros: '40000000', price: '250000000', scripts: [W('a1'), W('a2')], confirmations: '2', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0', ...extra });
const buyOrder = (extra = {}) => sdk.marketBuyOrder({ amountMicros: '40000000', price: '240000000', forms: ['p2wpkh'], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '100000', ...extra });
const stock = w => w.storage.set(addressKey(NET, 'carol'), JSON.stringify({ v: 1, bitcoin: 'regtest', items: [{ address: A.one, script: W('01') }, { address: A.two, script: W('02') }] }));
const fieldsOf = review => Object.fromEntries(review.fields);
const listed = (id, price, amount, extra = {}) => ({ id, side: 'sell', owner: '5', price, amount_micros: amount, open: true, takes_fill: true, ...extra });
const STOP = { id: 'ab'.repeat(8), side: 'sell', limit: '240000000', amountMicros: '20000000', trigger: { source: 'book', when: 'at_or_below', price: '245000000', minMicros: '10000000' }, script: W('01'), address: A.one };

test('the depth of the book: orders at one price are one level, and the depth adds up from the best price', () => {
  const book = T.bookLevels([listed('1', '250000000', '40000000'), listed('2', '250000000', '10000000', { takes_fill: false }), listed('3', '260000000', '5000000'), listed('4', '270000000', '0'), listed('5', '280000000', '9000000', { open: false })]);
  assert.deepEqual(book, { totalMicros: '55000000', levels: [{ price: '250000000', amountMicros: '50000000', sumMicros: '50000000', orders: ['1', '2'], takes: true }, { price: '260000000', amountMicros: '5000000', sumMicros: '55000000', orders: ['3'], takes: true }] });
  assert.equal(T.bookLevels(Array.from({ length: 30 }, (_, i) => listed(String(i + 1), String(250000000 + i), '1000000')), 12).levels.length, 12);
  assert.deepEqual([T.share('50000000', '55000000'), T.share('55000000', '55000000'), T.share('0', '0')], [909, 1000, 0]);
});

test('the chart: every candle stands inside the drawing, the scale is the lowest and highest price drawn, and nothing is smoothed', () => {
  const candles = [{ open: '240', high: '250', low: '235', close: '246' }, { open: '246', high: '262', low: '246', close: '251' }, { open: '251', high: '251', low: '240', close: '242' }];
  const shape = T.candleGeometry(candles, 640, 240);
  assert.deepEqual([shape.low, shape.high, shape.bars.length], ['235', '262', 3]);
  for (const bar of shape.bars) { assert.ok(bar.top >= 8 && bar.bottom <= 232 && bar.top <= bar.bodyTop && bar.bodyTop + bar.bodyHeight <= bar.bottom + 1 && bar.x >= 8 && bar.x + bar.width <= 632, JSON.stringify(bar)); }
  assert.deepEqual(shape.bars.map(bar => bar.up), [true, true, false]);
  assert.ok(shape.bars[0].x < shape.bars[1].x && shape.bars[1].x < shape.bars[2].x, 'oldest on the left');
  // The highest price is at the top and the lowest at the bottom, exactly.
  assert.equal(shape.bars[1].top, 8); assert.equal(shape.bars[0].bottom, 232);
  // One price only: a mark in the middle. More candles than are drawn: the newest. None: nothing.
  const flat = T.candleGeometry([{ open: '250', high: '250', low: '250', close: '250' }], 640, 240).bars[0];
  assert.deepEqual([flat.top, flat.bottom, flat.bodyHeight], [120, 120, 1]);
  assert.equal(T.candleGeometry(Array.from({ length: 90 }, () => candles[0]), 640, 240, { most: 60 }).bars.length, 60);
  assert.deepEqual(T.candleGeometry([], 640, 240), { bars: [], low: null, high: null });
  // The list's candles against the chain's rows.
  const row = { open: '240', high: '250', low: '235', close: '246', sats: '10', seconds_micros: '5', trades: '2' }, given = [{ number: '7', ...row }, { number: '8', ...row }, { number: '9', ...row }];
  assert.deepEqual(T.candlesDiffer(given, hour => ({ 7: row, 8: { ...row, close: '300' }, 9: null })[hour]), ['8', '9']);
  assert.deepEqual(T.candlesDiffer(given, () => row), []);
});

test('a stop order always has a limit price, a trigger that one small trade cannot move, and for a sale an address kept aside', () => {
  assert.deepEqual(T.stopOrder(STOP), { ...STOP, state: 'armed' });
  for (const limit of [undefined, null, '']) assert.throws(() => T.stopOrder({ ...STOP, limit }), new RegExp('^Error: ' + T.STOP_WORDS.noLimit.replace(/[.]/g, '\\.') + '$'));
  assert.throws(() => T.stopOrder({ ...STOP, limit: '0' }), /A price is from/);
  assert.throws(() => T.stopOrder({ ...STOP, trigger: { source: 'last', when: 'at_or_below', price: '245000000' } }), /Choose what the stop order watches/, 'the last recorded price alone is not a trigger');
  assert.throws(() => T.stopOrder({ ...STOP, trigger: { ...STOP.trigger, minMicros: '0' } }), /one tiny order must not move it/);
  for (const count of [1, 2, 21, 2.5, undefined]) assert.throws(() => T.stopOrder({ ...STOP, trigger: { source: 'trades', when: 'at_or_below', price: '245000000', count } }), /counts 3 to 20 trades in a row/);
  assert.equal(T.stopOrder({ ...STOP, trigger: { source: 'trades', when: 'at_or_below', price: '245000000', count: 3 } }).trigger.count, 3);
  for (const extra of [{ script: undefined }, { address: '' }, { script: 'xyz' }]) assert.throws(() => T.stopOrder({ ...STOP, ...extra }), /needs a free address of your own Bitcoin wallet/);
  assert.equal(T.stopOrder({ ...STOP, side: 'buy', script: undefined, address: undefined }).script, undefined, 'a purchase needs no address');
  assert.throws(() => T.stopOrder({ ...STOP, amountMicros: '0' }), /how many seconds/); assert.throws(() => T.stopOrder({ ...STOP, id: 'x' }), /has an id/); assert.throws(() => T.stopOrder({ ...STOP, side: 'hold' }), /sells or buys/);
  // The least size that counts must be more than what the network's smallest trade buys.
  assert.match(T.stopRefusal(T.stopOrder({ ...STOP, trigger: { ...STOP.trigger, minMicros: '3999999' } }), '4000000'), /too small/); assert.equal(T.stopRefusal(T.stopOrder(STOP), '4000000'), null);
  // Stored and read back strictly; an entry in another form is not a stop order.
  const stored = T.writeStops([T.stopOrder(STOP)]);
  assert.deepEqual(T.readStops(stored), [{ ...STOP, state: 'armed' }]);
  assert.deepEqual(T.readStops(JSON.stringify({ v: 1, stops: [{ ...STOP, limit: '' }, { ...STOP, auto: true, state: 'fired', fired: { height: '9', seen: '244000000' } }, 'x'] })), [{ ...STOP, state: 'fired', fired: { height: '9', seen: '244000000' } }], 'a field this wallet does not know, such as one that says "sign by itself", is not kept');
  assert.deepEqual([T.readStops('{'), T.readStops(null), T.readStops('{"v":2,"stops":[]}')], [[], [], []]);
  assert.deepEqual(T.reservedScripts([T.stopOrder(STOP), T.stopOrder({ ...STOP, state: 'done', script: W('02') }), T.stopOrder({ ...STOP, side: 'buy' })]), [W('01')]);
  assert.equal(T.stopsKey('ab'.repeat(32), 'carol'), `timecurrency.market-stops.v1:${'ab'.repeat(32)}:carol`);
});

test('a stop order fires on the proven book with a least size, or on several recorded trades and the chain\'s last recorded price; never on one trade', () => {
  const bid = (price, amount, extra = {}) => ({ side: 'buy', open: true, owner: '8', price, amount_micros: amount, fills: '0', ...extra });
  const ask = (price, amount, extra = {}) => ({ side: 'sell', open: true, owner: '5', price, amount_micros: amount, scripts: [{ script: W('a1') }], ...extra });
  const stop = T.stopOrder(STOP);
  // A sale looks at the best buy price among orders of at least 10 s: a tiny bid, the account's own, a closed one and the other side do not count.
  const rows = [bid('300000000', '9999999'), bid('290000000', '50000000', { owner: '6' }), bid('280000000', '50000000', { open: false }), ask('100000000', '50000000'), bid('246000000', '10000000'), bid('244000000', '90000000'), null];
  assert.equal(T.bookPrice(stop, rows, '6'), '246000000');
  assert.deepEqual(T.stopFires(stop, { book: '246000000' }), { fires: false, seen: '246000000' });
  assert.deepEqual(T.stopFires(stop, { book: '245000000' }), { fires: true, seen: '245000000' });
  assert.equal(T.bookPrice(stop, [bid('300000000', '1')], '6'), null); assert.deepEqual(T.stopFires(stop, { book: null }), { fires: false }, 'an empty book fires nothing');
  // A purchase looks at the best sell price, among sell orders with a free address.
  const buy = T.stopOrder({ ...STOP, side: 'buy', trigger: { source: 'book', when: 'at_or_above', price: '260000000', minMicros: '10000000' } });
  assert.equal(T.bookPrice(buy, [ask('250000000', '50000000', { scripts: [{ script: W('a1'), used: true }] }), ask('255000000', '50000000', { scripts: [{ script: W('a1'), fill: '3' }] }), ask('265000000', '50000000'), ask('270000000', '50000000')], '6'), '265000000');
  assert.equal(T.stopFires(buy, { book: '265000000' }).fires, true); assert.equal(T.stopFires(buy, { book: '259999999' }).fires, false);
  // Recorded trades: every one of the newest three, and the chain's own last recorded price.
  const tape = T.stopOrder({ ...STOP, trigger: { source: 'trades', when: 'at_or_below', price: '245000000', count: 3 } });
  assert.equal(T.stopFires(tape, { trades: ['244000000', '245000000', '240000000', '900000000'], last: '244000000' }).fires, true);
  assert.equal(T.stopFires(tape, { trades: ['1', '246000000', '240000000'], last: '1' }).fires, false, 'one trade at any price fires nothing');
  assert.equal(T.stopFires(tape, { trades: ['244000000', '245000000'], last: '244000000' }).fires, false, 'fewer trades than it counts');
  assert.equal(T.stopFires(tape, { trades: ['244000000', '245000000', '240000000'], last: '250000000' }).fires, false, 'the list says so, the chain\'s own last price does not');
  assert.equal(T.stopFires(tape, { trades: ['244000000', '245000000', '240000000'], last: null }).fires, false);
  // A stop order that has fired, or is done, does not fire again.
  assert.equal(T.stopFires({ ...stop, state: 'fired' }, { book: '1' }).fires, false); assert.equal(T.stopFires({ ...stop, state: 'done' }, { book: '1' }).fires, false);
});

test('the words say "recorded" of every past price, and what a stop order is and is not', async () => {
  assert.match(T.RECORD_WORDS.chart, /^Recorded prices.*A record, not a quote and not what a second is worth\. Anyone can trade with themselves at any price/);
  assert.match(T.STOP_WORDS.what, /a rule this wallet keeps in this browser: the chain has no stop orders.*only while this wallet is open and unlocked here\./);
  assert.match(T.STOP_WORDS.limit, /always has a limit price.*never an order at any price/); assert.match(T.STOP_WORDS.asks, /You review and sign it, like every action: this wallet signs nothing by itself/);
  assert.match(T.STOP_WORDS.hidden, /A service that hides orders can make a stop fire early, or not at all\. The limit price is what protects you\./);
  for (const file of ['market-trade.mjs', 'market-trade-ui.mjs']) {
    const code = (await readFile(new URL(file, import.meta.url), 'utf8')).split('\n').filter(line => !/^\s*\/\//.test(line)).join('\n');
    assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setAttribute\(\s*['"](?:style|on)|\.style\b|console\.|XMLHttpRequest|https?:\/\/(?!www\.w3\.org\/2000\/svg)|\bfetch\(|\bsendSigned\b|privateKey|\.sign\(/, file);
  }
});

// ---------------------------------------------------------------- the traders' view on the stand-in page
test('traders: the book with its depth, the trades and the chart are shown as the list\'s, with the service\'s flags when they are not clean', async () => {
  const w = world();
  w.send(5, 50, sellOrder()); w.send(8, 50, sellOrder({ price: '260000000', scripts: [W('b1')] })); w.send(8, 50, buyOrder());
  await w.open('trade');
  assert.match(textOf(w.$('market-asks')), /Price Seconds Depth 250 40 40 · order 1 Take 260 40 80 · order 2 Take/);
  assert.match(textOf(w.$('market-bids')), /240 40 40 · order 3 Sell/);
  assert.deepEqual(all(w.$('market-asks'), node => node.tag === 'progress').map(node => [node.value, node.max]), [[500, 1000], [1000, 1000]]);
  for (const words of [T.RECORD_WORDS.book, T.RECORD_WORDS.chart, T.RECORD_WORDS.trades]) assert.ok(w.text().includes(words), words);
  assert.match(w.text(), /No payment has been proven yet, so there is nothing to draw\./);
  for (const id of ['market-book', 'market-chart-section', 'market-trades']) assert.equal(all(w.$(id), node => node.className === 'nudge').length, 0, `a clean list carries no flag: ${id}`);
  // Payments are proven: the tape and the chart follow, and the chain's own candles are checked against proven rows.
  w.send(6, 52, sdk.marketTake({ order: '1', amountMicros: '8000000', price: '250000000', to: '6' })); w.chain.pay('1', '2000', w.clock.now, w.clock.height);
  w.send(6, 52, sdk.marketTake({ order: '2', amountMicros: '8000000', price: '260000000', to: '6' })); w.chain.pay('2', '2080', w.clock.now + 60000000n, w.clock.height);
  await w.ui.go('trade');
  assert.match(textOf(w.$('market-tape')), /Block Recorded price Seconds BTC \d+ 260 8 0\.00002080 \d+ 250 8 0\.00002000/);
  const chart = all(w.view(), node => node.tag === 'svg')[0];
  assert.equal(all(chart, node => node.tag === 'rect').length, 2); assert.equal(all(chart, node => node.tag === 'line' && node.attrs.class === 'candle-wick').length, 2);
  assert.match(chart.attrs['aria-label'], /Recorded prices of 2 intervals, from 250 to 260 satoshis for one second/); assert.equal(chart.attrs.role, 'img');
  assert.match(w.text(), /The 2 newest candles are the rows the chain keeps: checked by this browser at block \d+\./);
  assert.ok(w.reads.some(read => Array.isArray(read.market_candles) && read.market_candles.length === 2));
  assert.match(textOf(w.$('market-candles')), /Interval Open High Low Close Seconds/);
  // A list whose candle is not the chain's row is said; so are an index that disagrees with the chain, a tape that does not add up, and a list that is behind.
  w.control.api = (route, query) => { if (route !== '/v1/market/candles') return null; const answer = w.chain.api(route, query, w.clock.now, w.clock.height); answer.body.items[0].recorded_prices.close = '259000000'; answer.body.items[0].recorded_prices.low = '259000000'; return answer; };
  await w.ui.go('trade');
  assert.match(w.text(), /The list's candles are not what the chain holds for 1 of the 2 newest intervals.*Do not rely on this chart\./);
  w.control.api = null; Object.assign(w.chain.index, { consistent: false, tapeReconciled: false, lag: 40 });
  await w.ui.go('trade');
  assert.match(w.text(), /The service says its list does not agree with the chain right now/); assert.match(w.text(), /its list of trades does not add up to what the chain counted/); assert.match(w.text(), /The list is as of block \d+; this browser has checked the chain at block \d+\. The list is behind\./);
  // The service says the headers are stale: a warning on the book, not a promise either way.
  Object.assign(w.chain.index, { consistent: true, tapeReconciled: true, lag: 0 }); w.chain.bitcoin.fresh = false;
  await w.ui.go('trade');
  assert.match(textOf(w.$('market-book')), /The market's service says that the chain is not receiving Bitcoin's block headers right now\./);
});

test('traders: taking an order shows and signs the proven row whatever the list says, also for another account', async () => {
  const w = world();
  w.send(5, 50, sellOrder({ scripts: [W('a1'), W('a2'), W('a3')] }));
  w.chain.index.lie = { order: '1', with: { price: '100000000' } };
  await w.open('trade');
  assert.match(textOf(w.$('market-asks')), /100 40/, 'the list, as the service gave it');
  await w.press(byText(w.$('market-asks'), 'button', 'Take')[0]);
  assert.equal(w.$('market-take-order').value, '1', 'a press on the book fills in the order, and nothing is signed by it');
  w.type('market-take-amount', '10');
  await w.press(w.$('market-take-form'), 'submit');
  const lines = fieldsOf(w.reviews[0]);
  assert.match(lines.Order, /^Sell order 1 of account 5, read from the chain at block \d+$/);
  assert.deepEqual([lines.Price, lines['To pay in bitcoin'], lines.Total], ['250 satoshis for one second', '0.00002500 BTC (2,500 satoshis)', '0.501 seconds leave your balance now']);
  assert.deepEqual(w.signed[0].payload, { amount_micros: '10000000', order: '1', sats: '2500', to: '6' });
  assert.equal(w.ui.view(), 'pay'); assert.equal(w.$('market-pay-amount').textContent, '0.00002500 BTC');
  // For another account: the review says whose purchase it is and what the taker risks.
  await w.ui.go('trade');
  w.type('market-take-order', '1'); w.type('market-take-amount', '8'); w.type('market-take-to', '8');
  await w.press(w.$('market-take-form'), 'submit');
  const other = w.reviews[1];
  assert.equal(fieldsOf(other)['For another account'], TRADE_WORDS.forOther); assert.equal(other.acknowledge, 'Account 8 will pay. If it does not, I lose the deposit.');
  assert.equal(w.signed[1].payload.to, '8'); assert.match(w.text(), /You prepared this purchase for account 8\. Only that account can give it up\./);
  assert.equal(w.$('market-pay-release'), null, 'the taker cannot give up a purchase made for another account');
  // An order that is not there, an account that is not there, a size the order does not take: said, and nothing signed.
  for (const [order, amount, to, words] of [['9', '10', '6', /no open sell order with this number/], ['1', '10', '99', /There is no account 99 on the chain/], ['1', '1', '6', /smallest purchase of this order/], ['x', '10', '6', /Order: enter a whole number/]]) {
    await w.ui.go('trade'); w.type('market-take-order', order); w.type('market-take-amount', amount); w.type('market-take-to', to);
    await w.press(w.$('market-take-form'), 'submit');
    assert.match(w.lastSaid(), words);
  }
  assert.equal(w.signed.length, 2);
});

test('traders: selling into a buy order names one free address of a kind the buyer pays to; a buy order locks its bond and says what it asks', async () => {
  const w = world();
  stock(w);
  w.send(8, 50, buyOrder()); w.send(8, 50, buyOrder({ forms: ['p2tr'], price: '230000000' }));
  await w.open('trade');
  await w.press(byText(w.$('market-bids'), 'button', 'Sell')[0]);
  assert.equal(w.$('market-into-order').value, '1');
  for (const words of [TRADE_WORDS.into, SELL_WORDS.publicNow, SELL_WORDS.only, SELL_WORDS.final]) assert.ok(w.text().includes(words), words);
  w.type('market-into-amount', '10'); w.type('market-into-address', W('01'));
  await w.press(w.$('market-into-form'), 'submit');
  const lines = fieldsOf(w.reviews[0]);
  assert.deepEqual([lines['You sell'], lines.Price, lines['Your address'].replaceAll(' ', ''), lines.Confirmations, lines.Total], ['10 seconds', '240 satoshis for one second', A.one, '3', '10.001 seconds leave your balance now']);
  assert.match(lines['You receive'], /^0\.00002400 BTC \(2,400 satoshis\), paid to your address$/);
  assert.deepEqual([w.signed[0].kind, w.signed[0].payload], ['market_sell', { amount_micros: '10000000', confirmations: '3', order: '1', sats: '2400', script: W('01') }]);
  assert.match(w.lastSaid(), /The sale is on the chain as purchase 1\./);
  assert.match(w.text(), /Your sales into buy orders Purchase 1 by account 8: 10 seconds Still to pay to you: 0\.00002400 BTC/);
  // The other buy order pays to Taproot only: this address is refused before anything is signed.
  await w.ui.go('trade'); await w.press(w.$('market-form-into'));
  w.type('market-into-order', '2'); w.type('market-into-amount', '10'); w.type('market-into-address', W('02'));
  await w.press(w.$('market-into-form'), 'submit');
  assert.match(w.lastSaid(), /This buyer cannot pay to this kind of address \(p2wpkh\)\. They pay to: p2tr\. Nothing was signed\./);
  // An address that someone lists while the form is open is refused on its proven row.
  w.send(5, 50, sellOrder({ scripts: [W('02')] }));
  w.type('market-into-order', '1'); w.type('market-into-address', W('02'));
  await w.press(w.$('market-into-form'), 'submit');
  assert.match(w.lastSaid(), /no longer free/);
  assert.equal(w.signed.length, 1);
  // A buy order: the bond, the kinds of address, and the sentence about being there to pay.
  await w.press(w.$('market-form-buy'));
  assert.ok(w.text().includes(TRADE_WORDS.awake));
  w.type('market-bid-amount', '40'); w.type('market-bid-price', '235');
  await w.press(w.$('market-bid-form'), 'submit');
  const bid = w.reviews[w.reviews.length - 1], said = fieldsOf(bid);
  assert.deepEqual([bid.title, bid.confirm, said.Bond, said['You can pay to'], said.Warning], ['Post a buy order', 'Lock 2 s and post', '2 seconds (5%), locked now. What is left of it comes back when you cancel.', 'p2wpkh, p2tr', TRADE_WORDS.awake]);
  assert.deepEqual([w.signed[1].kind, w.signed[1].payload], ['market_order', { amount_micros: '40000000', confirmations: '6', deposit_ppm: '50000', forms: ['p2tr', 'p2wpkh'], min_sats: '1', pay_blocks: '6', price: '235000000', side: 'buy' }]);
  assert.match(w.lastSaid(), /Your buy order 4 is on the chain\. Keep this wallet near/);
  // On a production network a bond below 3% is refused in words before anything is asked of the chain.
  const prod = world({ profile: 'production' });
  await prod.open('trade'); await prod.press(prod.$('market-form-buy'));
  prod.type('market-bid-amount', '40'); prod.type('market-bid-price', '235'); prod.type('market-bid-bond', '2');
  await prod.press(prod.$('market-bid-form'), 'submit');
  assert.match(prod.lastSaid(), /The bond of a buy order is at least 3% on this network\./); assert.equal(prod.signed.length, 0);
});
