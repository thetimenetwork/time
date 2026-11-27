// The market's screens (market-ui.mjs) on a stand-in page over a stand-in chain (tests/market-world.mjs): what a
// person is shown, what is read from proven state before it, what is refused and what is signed. The chain is
// tests/mock-market-chain.mjs, a reading of spec/market.md and not the engine; the "verified state" is made of its
// rows and taken as proven. The pure rules are in market.test.mjs; the real page in Chrome is tests/preview-drive.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { world, sdk, W, addressOf, textOf, all, byId, byText, NET, codec } from './tests/market-world.mjs';
import { ADDRESS_WORDS, addressKey } from './market.mjs';
import { MARKET_WORDS } from './market-ui.mjs';

const root = new URL('../../', import.meta.url);
const A = { one: await addressOf(W('01')), two: await addressOf(W('02')), three: await addressOf(W('03')), four: await addressOf(W('04')) };
const sellOrder = (extra = {}) => sdk.marketSellOrder({ amountMicros: '40000000', price: '250000000', scripts: [W('a1'), W('a2')], confirmations: '2', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0', ...extra });
const buttons = (w, text) => byText(w.view(), 'button', text);

test('the market is nowhere on a network without it, and says whose bitcoin it is on one that has it', async () => {
  const none = world({ market: false });
  await none.open();
  assert.deepEqual([none.$('tab-market').hidden, none.$('home-market-row').hidden, none.text()], [true, true, '']);
  assert.equal(none.asked.length, 0, 'no list is asked for');
  const w = world();
  await w.open();
  assert.deepEqual([w.$('tab-market').hidden, w.$('home-market-row').hidden], [false, false]);
  assert.match(w.$('market-test-note').textContent, /^The bitcoin here is test bitcoin \(a Bitcoin test chain \(regtest\)\)\. It has no value\. Never send real bitcoin to an address shown here\.$/);
  assert.match(w.text(), /Nobody holds the bitcoin in between/); assert.match(w.text(), /This wallet holds no Bitcoin key and never sends bitcoin\./);
  // Locked: nothing of the market stays on the page.
  w.ui.reset();
  assert.deepEqual([w.$('tab-market').hidden, w.$('home-market-row').hidden, w.text()], [true, true, '']);
  // Bitcoin mainnet is closed in this version: the panel offers nothing there.
  const main = world({ network: 'mainnet' });
  await main.open();
  assert.equal(main.text(), 'The market is closed on this network.'); assert.match(main.$('market-test-note').textContent, /closed on this network/);
});

test('A: addresses are checked, kept in this browser, shown whole, and their state is read from proven rows', async () => {
  const w = world();
  await w.open('addresses');
  for (const words of [ADDRESS_WORDS.what, ADDRESS_WORDS.publicLater, ADDRESS_WORDS.exchange, ADDRESS_WORDS.once, ADDRESS_WORDS.kept]) assert.ok(w.text().includes(words), words);
  assert.match(w.text(), /No address yet/);
  // Pasted: two good ones (one twice), one of another network, one that is no address.
  const mainnet = await codec.scriptToAddress(W('01'), 'mainnet');
  w.type('market-address-input', `${A.one}\n${A.two} ${A.one}\n${mainnet}\nhello`);
  await w.press(w.$('market-address-form'), 'submit');
  const kept = JSON.parse(w.storage.get(addressKey(NET, 'carol')));
  assert.deepEqual(kept, { v: 1, bitcoin: 'regtest', items: [{ address: A.one, script: W('01') }, { address: A.two, script: W('02') }] });
  assert.match(w.text(), /2 addresses added\. Nothing was published\./);
  assert.equal(all(w.view(), node => node.className === 'warning' && /^Not added: /.test(node.textContent)).length, 2);
  assert.equal(w.$('market-address-input').value, `${mainnet}\nhello`, 'what was not taken stays in the field');
  // Each address is on the page whole, in groups of four, and nowhere shortened.
  const shown = all(w.view(), node => node.className === 'market-address').map(node => node.textContent);
  assert.deepEqual(shown.map(text => text.replaceAll(' ', '')), [A.one, A.two]);
  assert.ok(shown.every(text => /^(?:\S{4} )+\S{1,4}$/.test(text)));
  assert.doesNotMatch(w.text(), /…|\.\.\./);
  // Their state came from a proven read that named exactly these scripts.
  assert.ok(w.reads.some(read => read.include_market === true && JSON.stringify(read.market_scripts) === JSON.stringify([W('01'), W('02')])));
  assert.equal(all(w.view(), node => /\bmarket-free\b/.test(node.className)).length, 2);
  assert.match(w.text(), /read from the chain and checked by this browser at block 900/);
  assert.deepEqual(w.asked.map(([path]) => path), ['/v1/accounts/6/market'], 'the addresses ask no list of a server: only the menu did, for purchases someone prepared for the account');
  // Someone lists the first in an order, a purchase uses it, and it ends: the states follow the chain.
  w.send(5, 50, sellOrder({ scripts: [W('01'), W('09')] }));
  await w.ui.go('addresses');
  assert.match(w.text(), /Listed Order 1 lists this address\. It is public\./);
  w.send(8, 52, sdk.marketTake({ order: '1', amountMicros: '8000000', price: '250000000', to: '8' }));
  await w.ui.go('addresses');
  assert.match(w.text(), /In use Purchase 1 of your order 1 pays to this address\./);
  w.chain.pay('1', '2000', w.clock.now, w.clock.height);
  await w.ui.go('addresses');
  assert.match(w.text(), /Used A purchase used this address and has ended\. An address serves once/);
  assert.deepEqual(all(w.view(), node => /\btag\b/.test(node.className)).map(node => node.textContent), ['Used', 'Free']);
  // Removing takes it from this list only, and says so.
  await w.press(buttons(w, 'Remove from my list')[0]);
  assert.deepEqual(JSON.parse(w.storage.get(addressKey(NET, 'carol'))).items.map(item => item.address), [A.two]);
  assert.equal(w.lastSaid(), ADDRESS_WORDS.removed);
  await w.press(buttons(w, 'Copy')[0]);
  assert.deepEqual(w.copied, [A.two]);
  assert.equal(w.signed.length, 0, 'nothing of this is an action of the chain');
});

test('A: a stored list that was changed is not trusted: an entry whose script is not its address\'s is left out, and said', async () => {
  const w = world();
  w.storage.set(addressKey(NET, 'carol'), JSON.stringify({ v: 1, bitcoin: 'regtest', items: [{ address: A.one, script: W('01') }, { address: A.two, script: W('07') }] }));
  await w.open('addresses');
  assert.deepEqual(all(w.view(), node => node.className === 'market-address').map(node => node.textContent.replaceAll(' ', '')), [A.one]);
  assert.match(w.text(), /1 stored entry was left out/);
  // A list of another Bitcoin network is not this network's list.
  const other = world({ network: 'testnet3' });
  other.storage.set(addressKey(NET, 'carol'), JSON.stringify({ v: 1, bitcoin: 'regtest', items: [{ address: A.one, script: W('01') }] }));
  await other.open('addresses');
  assert.match(other.text(), /No address yet/);
  // More addresses than one selection names are read in several proven reads, each within the bound.
  const many = world(), scripts = Array.from({ length: 20 }, (_, i) => W((0x20 + i).toString(16)));
  many.storage.set(addressKey(NET, 'carol'), JSON.stringify({ v: 1, bitcoin: 'regtest', items: await Promise.all(scripts.map(async script => ({ address: await addressOf(script), script }))) }));
  await many.open('addresses');
  assert.deepEqual(many.reads.filter(read => read.market_scripts).map(read => read.market_scripts.length), [16, 4]);
  assert.equal(all(many.view(), node => node.className === 'market-address').length, 20);
});

test('the page code writes no HTML, loads nothing from elsewhere and logs nothing', async () => {
  for (const file of ['market-ui.mjs', 'market-api.mjs', 'market.mjs']) {
    const code = (await readFile(new URL(`web-v4/wallet/${file}`, root), 'utf8')).split('\n').filter(line => !/^\s*\/\//.test(line)).join('\n');
    assert.doesNotMatch(code, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function|setAttribute\(\s*['"](?:style|on)|\.style\b|console\.|XMLHttpRequest|https?:\/\/|\.type\s*=\s*['"]password/, file);
  }
  const page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8');
  const panel = page.slice(page.indexOf('id="panel-market"'), page.indexOf('id="enrollment-panel"'));
  assert.ok(panel.length > 300 && !/style=|onclick=|<script|https?:/.test(panel));
  // The one secret field of the market is in the page itself, marked like every payment password field.
  assert.match(panel, /<input id="market-payment" type="password" autocomplete="one-time-code" autocapitalize="off" autocorrect="off" spellcheck="false" data-1p-ignore data-lpignore="true" data-bwignore data-protonpass-ignore maxlength="2048">/);
  assert.ok(typeof MARKET_WORDS.lede === 'string');
});
