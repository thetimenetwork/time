// Stop orders in the wallet (market-trade-ui.mjs, on the stand-in page of tests/market-world.mjs): what the form says
// and refuses, what is kept, how a stop order fires on proven rows and on several recorded trades, and that firing
// signs nothing: the order it stands for goes through the usual review, at its limit price, with the payment password
// on a protected account. The rules themselves are in market-trade.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, sdk, W, addressOf, textOf, all, NET } from './tests/market-world.mjs';
import * as T from './market-trade.mjs';
import { addressKey } from './market.mjs';
import { MARKET_WORDS } from './market-ui.mjs';

const A = { one: await addressOf(W('01')), two: await addressOf(W('02')) };
const buyOrder = (extra = {}) => sdk.marketBuyOrder({ amountMicros: '40000000', price: '240000000', forms: ['p2wpkh'], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '100000', ...extra });
const sellOrder = (extra = {}) => sdk.marketSellOrder({ amountMicros: '40000000', price: '250000000', scripts: [W('a1'), W('a2'), W('a3'), W('a4')], confirmations: '2', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0', ...extra });
const stock = w => w.storage.set(addressKey(NET, 'carol'), JSON.stringify({ v: 1, bitcoin: 'regtest', items: [{ address: A.one, script: W('01') }, { address: A.two, script: W('02') }] }));
const kept = w => T.readStops(w.storage.get(T.stopsKey(NET, 'carol')) ?? null);
const fieldsOf = review => Object.fromEntries(review.fields);
/// Fills the form of a new stop order and sends it.
async function keep(w, { side = 'sell', amount = '20', source = 'book', when = 'at_or_below', trigger = '245', size = '10', count = '3', limit = '240', address = W('01') } = {}) {
  await w.ui.go('trade');
  w.type('market-stop-side', side); w.type('market-stop-amount', amount); w.type('market-stop-source', source); w.type('market-stop-when', when); w.type('market-stop-trigger', trigger);
  w.type('market-stop-size', size); w.type('market-stop-count', count); w.type('market-stop-limit', limit); if (w.$('market-stop-address')) w.type('market-stop-address', address);
  await w.press(w.$('market-stop-form'), 'submit');
}

test('a stop order is kept in this browser and says what it is; one without a limit, or with a trigger a small trade could move, is refused', async () => {
  const w = world({ profile: 'production' });
  stock(w);
  await w.open('trade');
  for (const words of [T.STOP_WORDS.what, T.STOP_WORDS.limit, T.STOP_WORDS.asks, T.STOP_WORDS.book, T.STOP_WORDS.trades, T.STOP_WORDS.hidden]) assert.ok(w.text().includes(words), words);
  assert.match(textOf(w.$('market-stops')), /No stop order\./);
  await keep(w, { limit: '' });
  assert.equal(w.lastSaid(), T.STOP_WORDS.noLimit);
  await keep(w, { source: 'trades', count: '2' });
  assert.match(w.lastSaid(), /counts 3 to 20 trades in a row: one trade alone can be made by anyone, at any price\./);
  await keep(w, { size: '' });
  assert.match(w.lastSaid(), /Set the least size of an order that counts for the trigger: one tiny order must not move it\./);
  // On a production network the smallest trade is 1,000 satoshis: an order of 3 seconds (735 satoshis at 245) could be placed to move the trigger.
  await keep(w, { size: '3' });
  assert.match(w.lastSaid(), /The least size that counts for the trigger is too small/);
  assert.deepEqual(kept(w), []);
  // A good one: kept, nothing signed, nothing sent, and its address is set aside.
  await keep(w);
  assert.match(kept(w)[0].id, /^[0-9a-f]{16}$/);
  assert.deepEqual(kept(w), [{ id: kept(w)[0].id, side: 'sell', limit: '240000000', amountMicros: '20000000', state: 'armed', trigger: { source: 'book', when: 'at_or_below', price: '245000000', minMicros: '10000000' }, script: W('01'), address: A.one }]);
  assert.equal(w.lastSaid(), 'The stop order is kept in this browser. Nothing was signed and nothing was sent to the chain. It is watched only while this wallet is open and unlocked here.');
  assert.match(textOf(w.$('market-stop-list')), /Watching Sell 20 seconds at a limit of 240 satoshis for one second, when the best buy price among orders of at least 10 seconds is at or below 245\./);
  assert.match(textOf(w.$('market-stop-list')), /This address is kept aside for this stop order\./);
  assert.equal(w.signed.length + w.reviews.length, 0);
  // The sell form no longer offers that address, and the list of addresses says why.
  await w.ui.go('sell');
  assert.deepEqual(all(w.view(), node => node.className === 'market-address').map(node => node.textContent.replaceAll(' ', '')), [A.two]);
  await w.ui.go('addresses');
  assert.match(w.text(), /A stop order of this wallet keeps it aside\./);
  // A stop order that sells needs an address: without a free one it is refused, in words.
  const none = world();
  await none.open('trade');
  assert.ok(textOf(none.$('market-stops')).includes(T.STOP_WORDS.noAddress));
  await keep(none);
  assert.equal(none.lastSaid(), T.STOP_WORDS.noAddress); assert.deepEqual(kept(none), []);
  // A purchase needs none.
  await keep(none, { side: 'buy', when: 'at_or_above', trigger: '260', limit: '265' });
  assert.deepEqual(kept(none).map(stop => [stop.side, stop.limit, stop.script]), [['buy', '265000000', undefined]]);
  // Removing it signs nothing.
  await none.press(none.$(`market-stop-remove-${kept(none)[0].id}`));
  assert.deepEqual(kept(none), []); assert.equal(none.lastSaid(), 'The stop order was removed. Nothing was signed.');
});

test('a stop order fires on the proven book and signs nothing; its order is then reviewed and signed at the limit price', async () => {
  const w = world();
  stock(w);
  await w.open('trade');
  await keep(w);
  // A bid well above the trigger, and a tiny one far below it: one small order moves nothing.
  w.send(8, 50, buyOrder({ price: '300000000' })); w.send(8, 50, buyOrder({ price: '100000000', amountMicros: '9000000', minSats: '500' }));
  await w.tick();
  assert.equal(kept(w)[0].state, 'armed'); assert.equal(w.signed.length, 0);
  assert.ok(w.reads.some(read => JSON.stringify(read.market_orders) === '["1"]'), 'the order that counts was read through the verifier');
  // The large bid goes, and a bid of enough size stands at 240: the stop order fires, says so, and signs nothing.
  w.send(8, 51, { order: '1' }); w.send(8, 50, buyOrder({ price: '240000000' }));
  await w.tick();
  assert.deepEqual([kept(w)[0].state, kept(w)[0].fired.seen], ['fired', '240000000']);
  assert.match(w.lastSaid(), /^A stop order of this wallet fired\. Sell 20 seconds at a limit of 240 satoshis for one second, when .* Nothing was signed: open Market, For traders, and review the order it prepared\.$/);
  assert.equal(w.$('home-market').textContent, 'Stop order fired');
  assert.equal(w.signed.length + w.reviews.length, 0, 'firing asks nothing of a key');
  assert.match(textOf(w.$('market-stop-list')), /Fired .* It fired at block \d+: the price it watches was 240\. Nothing was signed\. Review the order it prepared\./);
  // It does not fire twice.
  await w.tick(); await w.tick();
  assert.equal(w.said.filter(([text]) => /A stop order of this wallet fired/.test(text)).length, 1);
  // The person reviews: why it fired, what it watches now, the limit, the address. Cancelled: nothing is signed, and it stays fired.
  w.control.answer = false;
  await w.press(w.$('market-stop-sign-0000000000000001'));
  const review = w.reviews[0], lines = fieldsOf(review);
  assert.equal(review.title, 'A stop order fired: sell at your limit');
  assert.match(lines.Why, /^Your stop order fired at block \d+: the price it watches was 240\.$/); assert.match(lines.Now, /^The price it watches is 240 now, at block \d+\.$/);
  assert.deepEqual([lines['You sell'], lines['Limit price'], lines.Address.replaceAll(' ', '')], ['20 seconds', '240 satoshis for one second', A.one]);
  assert.deepEqual([w.signed.length, kept(w)[0].state, w.lastSaid()], [0, 'fired', 'Nothing was signed.']);
  // Confirmed: a sell order at the limit price with the address kept aside, read back from the chain.
  w.control.answer = true;
  await w.ui.go('trade'); await w.press(w.$('market-stop-sign-0000000000000001'));
  assert.deepEqual([w.signed[0].kind, w.signed[0].payload.price, w.signed[0].payload.scripts, w.signed[0].payload.side, w.signed[0].payload.amount_micros], ['market_order', '240000000', [W('01')], 'sell', '20000000']);
  assert.equal(kept(w)[0].state, 'done'); assert.match(textOf(w.$('market-made')), /is on the chain/);
});

test('a list that hides orders can make a stop order fire early, and the limit price is what the order is then made at', async () => {
  const w = world();
  stock(w);
  await w.open('trade');
  await keep(w);
  w.send(8, 50, buyOrder({ price: '300000000' })); w.send(8, 50, buyOrder({ price: '240000000' }));
  // The service leaves the best bid out of its list. The bid it does name is real, and is read proven: the stop order fires.
  w.control.api = (route, query) => { if (route !== '/v1/market/orders' || query.side !== 'buy') return null; const answer = w.chain.api(route, query, w.clock.now, w.clock.height); answer.body.items = answer.body.items.filter(item => item.id !== '1'); return answer; };
  await w.tick();
  assert.equal(kept(w)[0].state, 'fired');
  // A service that invents a bid cannot fire it: the row it names is not on the chain.
  const f = world();
  stock(f); await f.open('trade'); await keep(f);
  f.send(8, 50, buyOrder({ price: '300000000' }));
  f.control.api = (route, query) => { if (route !== '/v1/market/orders' || query.side !== 'buy') return null; const answer = f.chain.api(route, query, f.clock.now, f.clock.height); answer.body.items = [{ ...answer.body.items[0], id: '7', price: '200000000' }]; return answer; };
  await f.tick();
  assert.equal(kept(f)[0].state, 'armed');
  // Nor one that names a real order at another price: the proven row's price is what is judged.
  f.control.api = null; f.chain.index.lie = { order: '1', with: { price: '200000000' } };
  await f.tick();
  assert.equal(kept(f)[0].state, 'armed');
  // What the early firing can do: the order that is prepared is at the limit, never below it.
  await w.ui.go('trade'); await w.press(w.$('market-stop-sign-0000000000000001'));
  assert.equal(w.signed[0].payload.price, '240000000');
});

test('a stop order on recorded trades needs several in a row and the chain\'s own last recorded price; on a protected account its order needs the payment password', async () => {
  const w = world({ secured: true });
  await w.open('trade');
  await keep(w, { side: 'buy', source: 'trades', when: 'at_or_above', trigger: '255', limit: '262', count: '3' });
  assert.match(textOf(w.$('market-stop-list')), /Buy 20 seconds at a limit of 262 satoshis for one second, when the last 3 recorded trades, and the chain's last recorded price, are all at or above 255\./);
  const trade = (price, script) => { w.send(5, 50, sellOrder({ price, scripts: [script], amountMicros: '8000000' })); const order = String(w.chain.orders.size ? [...w.chain.orders.keys()].pop() : 1); w.send(8, 52, sdk.marketTake({ order, amountMicros: '8000000', price, to: '8' })); const fill = [...w.chain.fills.keys()].pop(); w.chain.pay(fill, sdk.marketSats('8000000', price), w.clock.now, w.clock.height); };
  // Two trades above the trigger are not three.
  trade('256000000', W('c1')); trade('257000000', W('c2'));
  await w.tick();
  assert.equal(kept(w)[0].state, 'armed');
  // The list claims a third; the chain's own count and last price are what they are: the proven last price is judged too.
  w.control.api = (route, query) => { if (route !== '/v1/market/trades') return null; const answer = w.chain.api(route, query, w.clock.now, w.clock.height); answer.body.items.unshift({ ...answer.body.items[0], price: '900000000' }); return answer; };
  trade('250000000', W('c3'));
  await w.tick();
  assert.equal(kept(w)[0].state, 'armed', 'the chain\'s last recorded price is below the trigger');
  // Three real trades in a row at or above it.
  w.control.api = null;
  trade('256000000', W('c4')); trade('258000000', W('c5')); trade('259000000', W('c6'));
  await w.tick();
  assert.deepEqual([kept(w)[0].state, kept(w)[0].fired.seen], ['fired', '259000000']);
  assert.equal(w.signed.length, 0);
  // The order it stands for is signed like any other: not without the payment password, and with the review.
  await w.ui.go('trade');
  assert.equal(w.$('market-payment-wrap').hidden, false);
  await w.press(w.$('market-stop-sign-0000000000000001'));
  assert.equal(w.lastSaid(), MARKET_WORDS.password); assert.equal(w.reviews.length + w.signed.length, 0);
  w.type('market-payment', 'payment-password'); await w.press(w.$('market-stop-sign-0000000000000001'));
  const lines = fieldsOf(w.reviews[0]);
  assert.deepEqual([w.reviews[0].title, lines['Limit price'], lines['Signed by']], ['A stop order fired: buy at your limit', '262 satoshis for one second', 'Your payment key, with your payment password']);
  assert.deepEqual([w.signed[0].kind, w.signed[0].payload.side, w.signed[0].payload.price], ['market_order', 'buy', '262000000']);
  assert.equal(kept(w)[0].state, 'done');
});
