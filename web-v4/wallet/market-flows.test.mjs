// Buying and selling seconds for bitcoin in the wallet (market-ui.mjs), on the stand-in page over the stand-in chain
// (tests/market-world.mjs, tests/mock-market-chain.mjs: a reading of spec/market.md, not the engine). What is held:
// the page reads the rows it shows and signs from the "verified state" and never from the list; a proven row that
// differs from the list stops it; every refusal is in words before anything is signed; each warning is on its screen.
import test from 'node:test';
import assert from 'node:assert/strict';
import { world, sdk, W, addressOf, textOf, all, byText, NET } from './tests/market-world.mjs';
import { PAY_WORDS as PAY, SELL_WORDS as SELL, addressKey } from './market.mjs';
import { MARKET_WORDS } from './market-ui.mjs';

const A = { one: await addressOf(W('01')), two: await addressOf(W('02')), three: await addressOf(W('03')) };
const PASSWORD = 'payment-password';
const sellOrder = (extra = {}) => sdk.marketSellOrder({ amountMicros: '40000000', price: '250000000', scripts: [W('a1'), W('a2')], confirmations: '2', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0', ...extra });
const stockAddresses = w => w.storage.set(addressKey(NET, 'carol'), JSON.stringify({ v: 1, bitcoin: 'regtest', items: [{ address: A.one, script: W('01') }, { address: A.two, script: W('02') }, { address: A.three, script: W('03') }] }));
const fieldsOf = review => Object.fromEntries(review.fields);
/// carol asks for seconds (or says what bitcoin she has) and gets to the offer.
async function offerFor(w, text = '10', mode = 'seconds') {
  await w.open('buy');
  if (mode === 'bitcoin') await w.press(w.$('market-buy-bitcoin'));
  w.type('market-buy-amount', text);
  await w.press(w.$('market-buy-form'), 'submit');
}
/// carol fills the sell form: 40 s at 250, the first two addresses.
async function sellForm(w, { amount = '40', price = '250', tick = [0, 1] } = {}) {
  await w.open('sell');
  w.type('market-sell-amount', amount); w.type('market-sell-price', price);
  for (const index of [0, 1, 2]) { const box = w.$(`market-sell-address-${index}`); if (box) box.checked = tick.includes(index); }
}

test('buy: the offer is the proven order, the take is reviewed and signed, and the pay screen shows the proven address and amount', async () => {
  const w = world();
  w.send(5, 50, sellOrder());
  w.send(8, 50, sellOrder({ price: '300000000', scripts: [W('b1')] }));
  await offerFor(w, '10');
  // The list was asked for, then the order and its owner were read through the verifier before anything was shown.
  const asked = w.asked.find(([path]) => path === '/v1/market/orders?side=sell&limit=200');
  assert.deepEqual([asked[1].credentials, asked[1].redirect, asked[1].referrerPolicy], ['omit', 'error', 'no-referrer']);
  assert.ok(w.reads.some(read => JSON.stringify(read.market_orders) === '["1"]' && JSON.stringify(read.ids) === '["5"]' && read.include_security === true && read.include_market === true));
  assert.equal(w.$('market-offer-amount').textContent, '10 seconds');
  assert.match(w.text(), /for 0\.00002500 BTC \(2,500 satoshis\)/); assert.match(w.text(), /Price 250 satoshis for one second/);
  assert.match(w.text(), /Deposit 0\.5 seconds, locked now\. It comes back when your payment is proven\. You lose it to the seller if you do not pay in time, or if you give up\./);
  assert.match(w.text(), /Time to pay 6 Bitcoin blocks, about 6 seconds/); assert.match(w.text(), /Confirmations 2,/); assert.match(w.text(), /Fee 0\.001 seconds/);
  assert.match(w.text(), /Read from the chain and checked by this browser at block/);
  assert.equal(w.signed.length, 0);
  await w.press(w.$('market-buy-review'));
  // The review: every line, the total that leaves the balance, and a sentence to tick.
  const review = w.reviews[0], lines = fieldsOf(review);
  assert.deepEqual([review.title, review.confirm], ['Buy seconds with bitcoin', 'Lock 0.5 s and show the address']);
  assert.deepEqual([lines['You buy'], lines.Price, lines.Fee, lines.Total], ['10 seconds', '250 satoshis for one second', '0.001 seconds', '0.501 seconds leave your balance now']);
  assert.match(lines['You will pay'], /^0\.00002500 BTC \(2,500 satoshis\), from your own Bitcoin wallet/); assert.match(review.acknowledge, /If I do not, I lose the deposit\./);
  assert.deepEqual(w.signed.map(item => [item.kind, item.payload]), [['market_take', { amount_micros: '10000000', order: '1', sats: '2500', to: '6' }]]);
  // The pay screen. The fill was found in the account's proven row and read proven; nothing of it came from the list.
  assert.equal(w.ui.view(), 'pay');
  const address = await addressOf(W('a1'));
  assert.equal(w.$('market-pay-address').textContent.replaceAll(' ', ''), address); assert.match(w.$('market-pay-address').textContent, /^(?:\S{4} )+\S{1,4}$/);
  assert.equal(w.$('market-pay-amount').textContent, '0.00002500 BTC'); assert.match(w.text(), /2,500 satoshis, still to pay/);
  assert.equal(w.$('market-pay-link').href, `bitcoin:${address}?amount=0.00002500`);
  assert.match(textOf(w.$('market-pay-state')), /Waiting for payment Nothing is counted yet\./);
  assert.match(w.text(), /Pay by Bitcoin block 106 at the latest\. The chain now knows block 100: 6 blocks left, about 6 seconds\./); assert.match(w.text(), /Confirmations 2 after that, by block 107/);
  assert.match(w.text(), /Purchase number Fill 1/);
  for (const words of [PAY.exact, PAY.exchange, PAY.late, PAY.proof, PAY.publicNote, PAY.compare, PAY.giveUp]) assert.ok(w.text().includes(words), words);
  assert.ok(w.reads.some(read => JSON.stringify(read.market_fills) === '["1"]'));
  assert.equal(w.me().balance, String(100000000n - 500000n - 1000n));
  await w.press(w.$('market-copy-address')); await w.press(w.$('market-copy-amount'));
  assert.deepEqual(w.copied, [address, '0.00002500']);
  // A part is paid: what is still to pay is READ from the fill, and the screen says that a part was counted.
  w.chain.pay('1', '1000', w.clock.now, w.clock.height);
  await w.press(w.$('market-pay-refresh'));
  assert.equal(w.$('market-pay-amount').textContent, '0.00001500 BTC'); assert.match(textOf(w.$('market-pay-state')), /Part counted 0\.00001000 BTC \(1,000 satoshis\) counted so far\. The rest is still to pay\./);
  assert.equal(w.$('market-pay-link').href, `bitcoin:${address}?amount=0.00001500`);
  // The rest is paid: the fill is gone from the chain, the list says how it ended, and the balance is the proven one.
  w.chain.pay('1', '1500', w.clock.now, w.clock.height);
  await w.press(w.$('market-pay-refresh'));
  assert.match(textOf(w.$('market-pay-state')), /Paid This purchase has ended: the chain holds it no more\./); assert.match(w.text(), /The market's list says it was paid in full/);
  assert.match(w.text(), /Your balance, checked by this browser: 109\.999 seconds\./); assert.match(w.text(), /Do not pay to its address any more/);
  assert.equal(w.$('market-pay-address'), null, 'no address is shown for a purchase that has ended');
});

test('buy: "I have bitcoin" never costs more than was typed; a purchase survives a reload and a new device', async () => {
  const w = world();
  w.send(5, 50, sellOrder());
  await offerFor(w, '0.00002501', 'bitcoin');
  assert.equal(w.$('market-offer-amount').textContent, '10.004 seconds'); assert.match(w.text(), /for 0\.00002501 BTC \(2,501 satoshis\)/);
  await w.press(w.$('market-buy-review'));
  assert.deepEqual(w.signed[0].payload, { amount_micros: '10004000', order: '1', sats: '2501', to: '6' });
  // Another device: nothing in its storage. The purchase is found again in the account's proven row.
  w.storage.clear(); w.ui.reset();
  await w.open();
  assert.match(w.text(), /You have 1 open purchase to pay\./); assert.equal(w.$('home-market').textContent, '1 to pay');
  await w.ui.go('mine');
  assert.match(textOf(w.$('market-purchases')), /Purchase 1: 10\.004 seconds Still to pay: 0\.00002501 BTC \(2,501 satoshis\)\. Pay by Bitcoin block 106/);
  await w.press(byText(w.$('market-purchases'), 'button', 'Open')[0]);
  assert.equal(w.$('market-pay-amount').textContent, '0.00002501 BTC'); assert.equal(w.$('market-pay-address').textContent.replaceAll(' ', ''), await addressOf(W('a1')));
});

test('buy: a list that says another price than the chain stops the purchase; an order that changes before the review does too', async () => {
  const w = world();
  w.send(5, 50, sellOrder());
  w.send(8, 50, sellOrder({ price: '260000000', scripts: [W('b1')] }));
  w.chain.index.lie = { order: '1', with: { price: '100000000' } };
  await offerFor(w, '10');
  assert.equal(w.$('market-offer'), null);
  assert.match(w.text(), /The price changed: the chain says 250 satoshis for one second, the list said 100 satoshis for one second\. Nothing was signed\./);
  assert.equal(w.reviews.length, 0); assert.equal(w.signed.length, 0);
  // The next offer can be asked for; it is read proven like the first.
  await w.press(w.$('market-buy-next'));
  assert.match(w.text(), /Seller Account 8, order 2/);
  // Between the offer and the review its owner cancels it: the review never opens.
  w.chain.index.lie = null; w.send(8, 51, { order: '2' });
  await w.press(w.$('market-buy-review'));
  assert.match(w.lastSaid(), /This order is gone: it was cancelled or sold\. Nothing was signed\./);
  assert.equal(w.reviews.length, 0); assert.equal(w.signed.length, 0);
  // A seller who is frozen is passed over, and the page says so; a cancelled review signs nothing.
  const f = world();
  f.send(5, 50, sellOrder()); f.send(8, 50, sellOrder({ price: '260000000', scripts: [W('b1')] }));
  f.guard.frozenAccounts.add('5');
  await offerFor(f, '10');
  assert.match(f.text(), /The seller of order 1 cannot sell right now.*so the next offer is shown\./); assert.match(f.text(), /Seller Account 8, order 2/);
  f.control.answer = false;
  await f.press(f.$('market-buy-review'));
  assert.equal(f.lastSaid(), 'Nothing was signed.'); assert.equal(f.signed.length, 0);
  // Nothing on offer, and an amount below every smallest purchase.
  const empty = world();
  await offerFor(empty, '10');
  assert.match(empty.text(), /Nobody offers seconds for bitcoin right now\./);
  const small = world(); small.send(5, 50, sellOrder());
  await offerFor(small, '1');
  assert.match(small.text(), /below the smallest purchase of every order/);
});

test('buy: the refusals are said in words before anything is signed, and a refusal of the chain is worded by the wallet', async () => {
  // Not enough seconds for the deposit and the fee.
  const poor = world({ balance: '400000' });
  poor.send(5, 50, sellOrder());
  await offerFor(poor, '10'); await poor.press(poor.$('market-buy-review'));
  assert.match(poor.lastSaid(), /^You do not have enough seconds for this: it needs 0\.501 seconds \(0\.5 locked and 0\.001 in fees\), and your balance is 0\.4\.$/);
  assert.equal(poor.reviews.length, 0);
  // A protected account: the payment password is asked first; the deposit counts against the daily limit; a frozen account is told.
  const s = world({ secured: true, limit: 400000n });
  s.send(5, 50, sellOrder());
  await offerFor(s, '10');
  assert.equal(s.$('market-payment-wrap').hidden, false);
  await s.press(s.$('market-buy-review'));
  assert.equal(s.lastSaid(), MARKET_WORDS.password);
  s.type('market-payment', PASSWORD); await s.press(s.$('market-buy-review'));
  assert.match(s.lastSaid(), /^Daily limit reached\. The deposit and the fee counts 0\.501 seconds against your daily limit, like a payment: more than your daily limit of 0\.4 seconds\./);
  assert.equal(s.$('market-payment').value, '', 'the password does not stay in the field');
  const frozen = world({ secured: true, frozen: true });
  frozen.send(5, 50, sellOrder());
  await offerFor(frozen, '10'); frozen.type('market-payment', PASSWORD); await frozen.press(frozen.$('market-buy-review'));
  assert.match(frozen.lastSaid(), /^Your account is frozen, so it cannot do this until the freeze ends\./);
  assert.equal(frozen.reviews.length + frozen.signed.length, 0);
  // Within the limit: the review says what it uses and which key signs, and the action is signed with the password.
  const ok = world({ secured: true });
  ok.send(5, 50, sellOrder());
  await offerFor(ok, '10'); ok.type('market-payment', PASSWORD); await ok.press(ok.$('market-buy-review'));
  assert.equal(fieldsOf(ok.reviews[0])['Daily limit'], '0.501 seconds count against your daily limit, like a payment: 600 is left today, 599.499 after this.');
  assert.equal(fieldsOf(ok.reviews[0])['Signed by'], 'Your payment key, with your payment password');
  assert.deepEqual([ok.signed.length, ok.signed[0].charge.count, ok.$('market-payment').value], [1, 501000n, '']);
  // The header chain is halted (proven): no purchase starts.
  const halted = world();
  halted.send(5, 50, sellOrder()); await offerFor(halted, '10'); halted.chain.bitcoin.halted = true;
  await halted.press(halted.$('market-buy-review'));
  assert.equal(halted.lastSaid(), MARKET_WORDS.halted); assert.equal(halted.reviews.length, 0);
  // The service says the headers are stale: a warning in the review, never a promise; the chain then refuses, and the
  // wallet says what that means in its own sentence, with the gateway's words after it.
  const stale = world();
  stale.send(5, 50, sellOrder()); await offerFor(stale, '10'); stale.chain.bitcoin.fresh = false;
  await stale.press(stale.$('market-buy-review'));
  assert.equal(fieldsOf(stale.reviews[0]).Warning, MARKET_WORDS.notFresh);
  assert.equal(stale.lastSaid(), 'The chain refused this: it is not receiving Bitcoin\'s block headers right now, and no purchase can start until it does. Nothing was locked. Try again later. The gateway says: the Bitcoin header chain is not fresh');
  assert.equal(stale.me().balance, '100000000', 'a refusal changes nothing');
});

test('buy: giving up costs the deposit and says so; a purchase someone else prepared is shown against the book', async () => {
  const w = world();
  w.send(5, 50, sellOrder());
  await offerFor(w, '10'); await w.press(w.$('market-buy-review'));
  await w.press(w.$('market-pay-release'));
  const review = w.reviews[1], lines = fieldsOf(review);
  assert.deepEqual([review.title, review.confirm], ['Give up this purchase', 'Give up and lose the deposit']);
  assert.equal(lines['You lose'], 'Your deposit of 0.5 seconds. It goes to the seller.'); assert.match(lines.Bitcoin, /stays with the seller and buys nothing/); assert.match(review.acknowledge, /I have sent no bitcoin/);
  assert.deepEqual([w.signed[1].kind, w.signed[1].payload, w.signed[1].charge.count], ['market_release', { fill: '1' }, 10501000n]);
  assert.match(w.text(), /The market's list says it was given up\. The deposit went to the seller\./);
  assert.equal(w.accounts.find(account => account.id === '5').balance, String(500000000n - 3000n - 40000000n + 500000n));
  // The helper (account 7) takes the dearest order for carol. She finds it through the list; every number is read proven.
  w.send(8, 50, sellOrder({ price: '900000000', scripts: [W('b1')] }));
  w.send(7, 52, sdk.marketTake({ order: '2', amountMicros: '8000000', price: '900000000', to: '6' }));
  await w.ui.go('mine');
  assert.match(textOf(w.$('market-purchases')), /Purchase 2: 8 seconds .* Prepared for you by account 7\./);
  await w.press(byText(w.$('market-purchases'), 'button', 'Open')[0]);
  assert.ok(w.text().includes(`${PAY.helper} Account 7 prepared it.`));
  assert.match(w.text(), /This seller's price is far above another offer on the list: 900 satoshis for one second, against 250 satoshis for one second\. Check before you pay\./);
  assert.equal(w.$('market-pay-address').textContent.replaceAll(' ', ''), await addressOf(W('b1'))); assert.equal(w.$('market-pay-amount').textContent, '0.00007200 BTC');
  assert.match(w.text(), /locked by account 7/);
  // A list that names a fill in which this account has no part: the proven row decides, and it is left out.
  w.send(8, 52, sdk.marketTake({ order: '1', amountMicros: '8000000', price: '250000000', to: '8' }));
  w.control.api = route => { if (route !== '/v1/accounts/6/market') return null; const answer = w.chain.api(route, {}, w.clock.now, w.clock.height); answer.body.fills.push({ ...w.chain.fills.get('3'), roles: ['to'] }); return answer; };
  await w.ui.go('mine');
  assert.doesNotMatch(textOf(w.$('market-purchases')), /Purchase 3/);
});

test('sell: the order is reviewed with every address whole, signed, and read back from the chain', async () => {
  const none = world();
  await none.open('sell');
  assert.match(none.text(), /You need a free receiving address of your own Bitcoin wallet first/);
  const w = world();
  stockAddresses(w);
  // Someone records a trade first: the form shows it as a record, not as a quote.
  w.send(5, 50, sellOrder()); w.send(8, 52, sdk.marketTake({ order: '1', amountMicros: '8000000', price: '250000000', to: '8' })); w.chain.pay('1', '2000', w.clock.now, w.clock.height);
  await sellForm(w);
  assert.match(w.text(), /Last recorded trade: 250 satoshis for one second\. A record of one trade, not a quote and not what a second is worth: anyone can record a trade with themselves at any price\./);
  for (const words of [SELL.publicNow, SELL.only, SELL.hold, SELL.final]) assert.ok(w.text().includes(words), words);
  assert.deepEqual([w.$('market-sell-confirmations').value, w.$('market-sell-blocks').value, w.$('market-sell-deposit').value, w.$('market-sell-min-deposit').value], ['1', '6', '3', '0'], 'the terms start from the rules of the network');
  await w.press(w.$('market-sell-form'), 'submit');
  const review = w.reviews[0], lines = fieldsOf(review);
  assert.deepEqual([review.title, review.confirm, lines['You sell'], lines.Price, lines.Fee], ['Sell seconds for bitcoin', 'Offer 40 seconds', '40 seconds', '250 satoshis for one second', '0.003 seconds']);
  assert.deepEqual([lines['Address 1'].replaceAll(' ', ''), lines['Address 2'].replaceAll(' ', '')], [A.one, A.two]);
  assert.match(lines['You receive'], /^0\.00010000 BTC \(10,000 satoshis\) when all of it is sold/); assert.equal(lines['Smallest purchase'], '5,000 satoshis'); assert.equal(lines.Public, SELL.publicNow);
  assert.equal(lines.Total, '40.003 seconds leave your balance now. What is not sold comes back when you cancel.'); assert.match(review.acknowledge, /in my own Bitcoin wallet, and I use them for nothing else/);
  // The addresses were read PROVEN as free before the review.
  assert.ok(w.reads.some(read => JSON.stringify(read.market_scripts) === JSON.stringify([W('01'), W('02')]) && JSON.stringify(read.market_accounts) === '["6"]'));
  assert.deepEqual([w.signed[0].kind, w.signed[0].label, w.signed[0].charge.count], ['market_order', 'Offer 40 s for bitcoin', 40003000n]);
  assert.deepEqual(w.signed[0].payload, { amount_micros: '40000000', confirmations: '1', deposit_ppm: '30000', min_deposit_micros: '0', min_sats: '5000', pay_blocks: '6', price: '250000000', scripts: [W('01'), W('02')], side: 'sell' });
  // Read back: the order's proven row, its addresses as addresses, and that they are the ones chosen.
  assert.equal(w.ui.view(), 'mine');
  const made = w.$('market-made');
  assert.match(textOf(made), /Order 2 is on the chain/); assert.ok(textOf(made).includes(SELL.readBack));
  assert.deepEqual(all(made, node => node.className === 'market-address').map(node => node.textContent.replaceAll(' ', '')), [A.one, A.two]);
  assert.doesNotMatch(textOf(made), /does not hold all the addresses/);
  assert.match(textOf(w.$('market-order-2')), /Sell order 2 40 seconds left, at 250 satoshis for one second/); assert.match(textOf(w.$('market-order-2')), /Free The next purchase gets it\./);
});

test('sell: an address someone listed first stops the order; a purchase can be settled, with its warning, or ended when unpaid', async () => {
  const w = world();
  stockAddresses(w);
  await sellForm(w);
  // Someone copies the first address into an order of their own before this one is signed (spec/market.md, 10.11).
  w.send(5, 50, sellOrder({ scripts: [W('01')] }));
  await w.press(w.$('market-sell-form'), 'submit');
  assert.equal(w.lastSaid(), `The address ${A.one} is no longer free: an order lists it, or a purchase used it. Nothing was signed. Choose another.`);
  assert.equal(w.reviews.length + w.signed.length, 0);
  await sellForm(w, { tick: [0, 1] });   // the form now offers the two that are still free
  await w.press(w.$('market-sell-form'), 'submit');
  assert.deepEqual(w.signed[0].payload.scripts, [W('02'), W('03')]);
  // A buyer takes 20 s of it.
  w.send(8, 52, sdk.marketTake({ order: '2', amountMicros: '20000000', price: '250000000', to: '8' }));
  await w.ui.go('mine');
  const block = () => textOf(w.$('market-order-2'));
  assert.match(block(), /Purchase 1 by account 8: 20 seconds Still to pay to you: 0\.00005000 BTC \(5,000 satoshis\)\. The buyer has until Bitcoin block 106/); assert.match(block(), /In use Purchase 1 pays to it\./);
  assert.equal(byText(w.view(), 'button', 'End it: not paid in time').length, 0, 'not while the buyer has time');
  // Settle: the warning, a sentence to tick, and what it counts.
  await w.press(byText(w.view(), 'button', 'Hand over without proof')[0]);
  const settle = w.reviews[1], lines = fieldsOf(settle);
  assert.deepEqual([settle.title, lines['You hand over'], lines.Warning], ['Hand over without proof', '20 seconds, to account 8', SELL.settle]);
  assert.match(lines['Not proven'], /0\.00005000 BTC \(5,000 satoshis\): the chain has seen no proof of it/); assert.match(settle.acknowledge, /I see the whole payment in my own Bitcoin wallet/);
  assert.deepEqual([w.signed[1].kind, w.signed[1].payload, w.signed[1].charge.count], ['market_settle', { fill: '1' }, 20001000n]);
  assert.equal(w.accounts.find(account => account.id === '8').balance, String(500000000n - 1000n + 20000000n));
  // Another purchase is not paid. When the chain lets it end, the owner can end it and keeps the deposit.
  w.send(8, 52, sdk.marketTake({ order: '2', amountMicros: '20000000', price: '250000000', to: '8' }));
  w.chain.learn(120, w.clock.now); w.clock.now += 90000000n;
  await w.ui.go('mine');
  await w.press(byText(w.view(), 'button', 'End it: not paid in time')[0]);
  assert.deepEqual([w.signed[2].kind, w.signed[2].payload, w.signed[2].charge.count], ['market_expire', { fill: '2' }, 0n]);
  assert.match(w.lastSaid(), /The purchase was ended\./);
});

test('sell: new addresses for an order count like a new order and are read back; an order is cancelled with what comes back', async () => {
  const w = world({ secured: true, balance: '1000000000' });
  stockAddresses(w);
  await sellForm(w, { tick: [0] });
  // Without the payment password nothing is asked of the chain; with it the order is made.
  await w.press(w.$('market-sell-form'), 'submit');
  assert.equal(w.lastSaid(), MARKET_WORDS.password);
  w.type('market-payment', PASSWORD); await w.press(w.$('market-sell-form'), 'submit');
  assert.equal(w.signed[0].kind, 'market_order');
  // More than what is left of the daily limit: said before the review.
  await sellForm(w, { amount: '590', tick: [0] });
  w.type('market-payment', PASSWORD); await w.press(w.$('market-sell-form'), 'submit');
  assert.match(w.lastSaid(), /^Daily limit reached\. The seconds you offer and the fees counts 590\.002 seconds against your daily limit, like a payment: more than the 559\.998 seconds left of your daily limit today\./);
  // New addresses (kind 58): the order's seconds count again.
  await w.ui.go('mine');
  await w.press(w.$('market-add-1'));
  assert.equal(w.ui.view(), 'add'); assert.match(w.text(), /New addresses count against your daily limit like a new order/);
  w.type('market-payment', PASSWORD); await w.press(w.$('market-add-form'), 'submit');
  const add = w.reviews[w.reviews.length - 1];
  assert.deepEqual([add.title, fieldsOf(add)['Address 1'].replaceAll(' ', '')], ['New addresses for your order', A.two]);
  assert.deepEqual([w.signed[1].kind, w.signed[1].payload, w.signed[1].charge.count], ['market_scripts', { order: '1', scripts: [W('02')] }, 40002000n]);
  assert.deepEqual(all(w.$('market-made'), node => node.className === 'market-address').map(node => node.textContent.replaceAll(' ', '')), [A.one, A.two]);
  // Cancel: what comes back, and nothing of the limit is used.
  w.type('market-payment', PASSWORD); await w.press(w.$('market-cancel-1'));
  const cancel = w.reviews[w.reviews.length - 1], lines = fieldsOf(cancel);
  assert.deepEqual([cancel.title, lines['Comes back'], lines['Open purchases'], lines['Daily limit']], ['Cancel this order', '40 seconds, to your balance', 'None', 'Nothing of your daily limit is used.']);
  assert.deepEqual([w.signed[2].kind, w.signed[2].payload], ['market_cancel', { order: '1' }]);
  assert.match(textOf(w.$('market-orders')), /No open order\./);
});
