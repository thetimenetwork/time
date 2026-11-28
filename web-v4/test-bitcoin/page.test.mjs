// The test-bitcoin page (web-v4/test-bitcoin/): what it works out without a browser. Reading a payment link, the
// amounts, what fills the form from the page's own address, the words it shows; and that the page's file holds no
// script and no style of its own, and every element its script asks for.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { amountProblem, btcOfSats, checkAddress, describePayment, grouped, parsePayTarget, prefillFromAddress, progressWords, readKept, receivedWords, satsOfBtc, waitSeconds } from './app.mjs';
import { scriptToAddress } from '../shared/bitcoin-address.mjs';

const ADDRESS = await scriptToAddress(`0014${'7a'.repeat(20)}`, 'regtest'), TAPROOT = await scriptToAddress(`5120${'7b'.repeat(32)}`, 'regtest');

test('satoshis and bitcoin: whole-number arithmetic, all eight places, nothing rounded', () => {
  assert.equal(btcOfSats('1'), '0.00000001');
  assert.equal(btcOfSats('12345'), '0.00012345');
  assert.equal(btcOfSats('100000000'), '1.00000000');
  assert.equal(btcOfSats('5000000'), '0.05000000');
  assert.equal(btcOfSats('1499999999999'), '14999.99999999');
  assert.equal(btcOfSats('0'), '0.00000000');
  for (const bad of ['', '1.5', '-1', '01', 'abc', '1e3', 12345, null, undefined, '12345678901234567']) assert.equal(btcOfSats(bad), null, String(bad));
  // A link's amount is in bitcoin, with up to eight places.
  assert.equal(satsOfBtc('0.0001'), '10000');
  assert.equal(satsOfBtc('1'), '100000000');
  assert.equal(satsOfBtc('0.00012345'), '12345');
  assert.equal(satsOfBtc('0.1'), '10000000');
  assert.equal(satsOfBtc('0.3'), '30000000', 'a tenth and two tenths are three tenths here');
  assert.equal(satsOfBtc('20999999.99999999'), '2099999999999999');
  assert.equal(satsOfBtc('0'), '0');
  for (const bad of ['', '.5', '1.', '0.000000001', '1e-4', '-1', '+1', '1,5', ' 1', '0x10', '123456789', 0.0001, null]) assert.equal(satsOfBtc(bad), null, String(bad));
  for (const sats of ['1', '294', '99999999', '100000001', '2099999999999999']) assert.equal(satsOfBtc(btcOfSats(sats)), sats);
  assert.equal(grouped('12345'), '12,345');
  assert.equal(grouped('1000000'), '1,000,000');
  assert.equal(grouped('999'), '999');
  assert.equal(grouped('0'), '0');
  assert.equal(grouped('not a number'), 'not a number');
});

test('the pay field takes an address or a whole payment link, and fills the amount from the link', () => {
  assert.deepEqual(parsePayTarget(ADDRESS), { address: ADDRESS, sats: null });
  assert.deepEqual(parsePayTarget(`  ${ADDRESS}\n`), { address: ADDRESS, sats: null });
  assert.deepEqual(parsePayTarget(`bitcoin:${ADDRESS}`), { address: ADDRESS, sats: null });
  assert.deepEqual(parsePayTarget(`bitcoin:${ADDRESS}?amount=0.0001`), { address: ADDRESS, sats: '10000' });
  assert.deepEqual(parsePayTarget(`BITCOIN:${ADDRESS.toUpperCase()}?amount=0.00012345`), { address: ADDRESS.toUpperCase(), sats: '12345' }, 'as a code to scan writes it');
  assert.deepEqual(parsePayTarget(`bitcoin:${TAPROOT}?label=Order%2017&amount=1&message=seconds`), { address: TAPROOT, sats: '100000000' }, 'what the page does not use is passed over');
  assert.deepEqual(parsePayTarget(`bitcoin:${ADDRESS}?`), { address: ADDRESS, sats: null });
  // Refused in words, never guessed at.
  for (const [text, pattern] of [['', /Enter an address/], ['   ', /Enter an address/], ['two words', /not an address/], [`${ADDRESS} `.repeat(2), /not an address/], ['<script>alert(1)</script>', /not an address/], ['bitcoin:', /holds no address/], ['bitcoin:?amount=1', /holds no address/],
    [`bitcoin:${ADDRESS}?amount=abc`, /amount of this payment link/], [`bitcoin:${ADDRESS}?amount=0.000000001`, /at most eight places/], [`bitcoin:${ADDRESS}?amount=1&amount=2`, /"amount" twice/], [`bitcoin:${ADDRESS}?req-somethingnew=1`, /does not know/],
    [`bitcoin:${ADDRESS}?amount=%E0%A4%A`, /not written correctly/], [`https://example.com/${ADDRESS}`, /not an address/], [`bitcoin://${ADDRESS}`, /holds no address/]]) {
    const parsed = parsePayTarget(text);
    assert.match(parsed.error ?? '', pattern, text);
    assert.equal(parsed.address, undefined);
  }
  assert.match(parsePayTarget(null).error, /Enter an address/);
});

test('an address is checked by the codec the market uses: this test chain only', async () => {
  assert.deepEqual(await checkAddress(ADDRESS), { ok: true, form: 'p2wpkh', words: 'This is a SegWit address of this test chain.' });
  assert.deepEqual(await checkAddress(TAPROOT), { ok: true, form: 'p2tr', words: 'This is a Taproot address of this test chain.' });
  assert.equal((await checkAddress(ADDRESS.toUpperCase())).ok, true);
  const mainnet = await checkAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  assert.deepEqual([mainnet.ok, /Bitcoin mainnet/.test(mainnet.words)], [false, true]);
  const mistyped = await checkAddress(`${ADDRESS.slice(0, -1)}${ADDRESS.endsWith('q') ? 'p' : 'q'}`);
  assert.deepEqual([mistyped.ok, /checksum/.test(mistyped.words)], [false, true]);
  assert.equal((await checkAddress('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')).ok, false);
  assert.equal((await checkAddress('')).ok, false);
});

test('the page\'s own address fills the form, in the forms the page takes and no other', () => {
  assert.deepEqual(prefillFromAddress(`?address=${ADDRESS}&sats=12345`), { address: ADDRESS, sats: '12345' });
  assert.deepEqual(prefillFromAddress(`?sats=1&address=${ADDRESS}`), { address: ADDRESS, sats: '1' });
  assert.deepEqual(prefillFromAddress(`?address=${ADDRESS}`), { address: ADDRESS, sats: '' });
  assert.deepEqual(prefillFromAddress('?sats=500'), { address: '', sats: '500' });
  assert.deepEqual(prefillFromAddress(''), { address: '', sats: '' });
  for (const bad of ['?address=%3Cscript%3E', '?address=a%20b', '?address=short', `?address=${'a'.repeat(91)}`, '?address=%E2%80%AEabcdefghijklmnop']) assert.equal(prefillFromAddress(bad).address, '', bad);
  for (const bad of ['?sats=0', '?sats=1.5', '?sats=-1', '?sats=01', '?sats=1e3', '?sats=12345678901234567', '?sats=%3Cb%3E']) assert.equal(prefillFromAddress(bad).sats, '', bad);
  // It never pays by itself: the script puts the two into the fields and waits for the person.
  return readFile(new URL('./app.mjs', import.meta.url), 'utf8').then((script) => {
    assert.ok(script.includes("if (named.address) $('target').value = named.address;"));
    assert.equal([...script.matchAll(/ask\('payments', /g)].length, 1, 'one place sends a payment');
    assert.match(script, /async function pay\(event\) \{\s+event\.preventDefault\(\);/);
    assert.ok(!/\bpay\(\)/.test(script), 'and nothing but the form\'s submit calls it');
  });
});

test('an amount: what is wrong with it, in words', () => {
  const status = { max_payment_sats: '5000000', left_today_for_caller_sats: '300000' };
  assert.equal(amountProblem('10000', status), '');
  assert.equal(amountProblem('300000', status), '');
  assert.match(amountProblem('', status), /Enter an amount/);
  for (const bad of ['0', '1.5', '-5', 'ten', '1 000', '01']) assert.match(amountProblem(bad, status), /whole number of satoshis/, bad);
  assert.equal(amountProblem('5000001', status), 'One payment is at most 5,000,000 satoshis.');
  assert.equal(amountProblem('300001', status), 'You can be paid 300,000 satoshis more today.');
  // Before the service has answered, only the form is judged; the service judges the rest.
  assert.equal(amountProblem('999999999', null), '');
});

test('what the page says of a payment, of its confirmations and of an address', () => {
  const txid = 'ab'.repeat(32);
  assert.deepEqual(describePayment(200, { txid, address: ADDRESS, sats: '12345', seconds_to_next_block: 14 }), { ok: true, title: 'Sent', txid, text: `12,345 satoshis (0.00012345 BTC) of play bitcoin to ${ADDRESS}. It will be in a block within about 14 seconds.` });
  assert.match(describePayment(200, { txid, address: ADDRESS, sats: '12345', seconds_to_next_block: 0 }).text, /within about 1 seconds/);
  assert.deepEqual(describePayment(429, { error: { code: 'caller_limit', message: 'One caller gets 30 payments in an hour' } }), { ok: false, title: 'Not sent', txid: null, text: 'One caller gets 30 payments in an hour' });
  assert.deepEqual(describePayment(502, null), { ok: false, title: 'Not sent', txid: null, text: 'The service answered 502.' });
  assert.equal(describePayment(200, { txid: '<b>x</b>' }).ok, false, 'an answer without a transaction id is not a payment');

  assert.equal(progressWords(null), 'Looking for it…');
  assert.equal(progressWords({ confirmations: 0, height: null, seconds_to_next_block: 9 }), 'Not in a block yet. The next block comes in about 9 seconds.');
  assert.equal(progressWords({ confirmations: 1, height: 205 }), 'In block 205: 1 confirmation.');
  assert.equal(progressWords({ confirmations: 3, height: 205 }, ' This page has stopped looking after five minutes.'), 'In block 205: 3 confirmations. This page has stopped looking after five minutes.');
  assert.equal(progressWords({ confirmations: 6, height: 205 }), 'In block 205: 6 confirmations. That is as many as this page counts.');

  assert.equal(receivedWords(null), 'Not looked at yet.');
  assert.equal(receivedWords({ received_sats: '0', unconfirmed_sats: '0', payments: [] }), 'Nothing in a block yet.');
  assert.equal(receivedWords({ received_sats: '0', unconfirmed_sats: '700', payments: [{ height: null }] }), 'Nothing in a block yet. 700 more wait for the next block.');
  assert.equal(receivedWords({ received_sats: '12345', unconfirmed_sats: '0', payments: [{ height: 102 }] }), 'Received 12,345 satoshis (0.00012345 BTC) in 1 payment.');
  assert.equal(receivedWords({ received_sats: '20333', unconfirmed_sats: '1000', payments: [{ height: null }, { height: 103 }, { height: 102 }] }), 'Received 20,333 satoshis (0.00020333 BTC) in 2 payments. 1,000 more wait for the next block.');
  assert.match(receivedWords({ received_sats: '99999', unconfirmed_sats: '0', payments: Array.from({ length: 50 }, () => ({ height: 5 })) }), /in more than 50 payments/);
});

test('a question that came too soon is asked again after the wait the service names, never a payment', async () => {
  assert.deepEqual(['1', '2', '5', '30', '0', undefined, null, 'soon', '-3', '1.5'].map(waitSeconds), [1, 2, 5, 5, 1, 1, 1, 1, 1, 1]);
  const script = await readFile(new URL('./app.mjs', import.meta.url), 'utf8');
  assert.ok(script.includes('if (body === undefined && response.status === 429 && tries < 2 &&'), 'only a request without a body is repeated');
});

test('the list kept in the browser is read back only as far as it is such a list', () => {
  assert.deepEqual(readKept(JSON.stringify([{ address: ADDRESS, form: 'p2wpkh', extra: 1 }, { address: TAPROOT, form: 'p2tr' }])), [{ address: ADDRESS, form: 'p2wpkh' }, { address: TAPROOT, form: 'p2tr' }]);
  for (const text of ['', 'not json', 'null', '{}', '"text"', '[1, null, "x"]', JSON.stringify([{ address: '<img src=x>', form: 'p2wpkh' }]), JSON.stringify([{ address: ADDRESS, form: 'p2pkh' }]), JSON.stringify([{ form: 'p2tr' }])]) assert.deepEqual(readKept(text), [], text);
  assert.equal(readKept(JSON.stringify(Array.from({ length: 80 }, () => ({ address: ADDRESS, form: 'p2wpkh' })))).length, 50);
});

test('the page\'s file: its title, its first line, no script or style of its own, and every element the script asks for', async () => {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8'), script = await readFile(new URL('./app.mjs', import.meta.url), 'utf8'), css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  assert.match(html, /<title>Test bitcoin<\/title>/);
  assert.match(html, /<h1>Test bitcoin<\/h1>\s*<p class="lede">Play bitcoin on a private chain of this test network\. It is worth nothing\. It is here only for trying the market of seconds against bitcoin\.<\/p>/);
  assert.match(html, /held by the test network's Bitcoin node\. What arrives at it is shown here and cannot be spent by you/);
  // The policy the page is served with allows no inline script, no inline style and nothing from elsewhere.
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), 'no script in the page itself');
  assert.ok(!/<style\b|\sstyle=|\son[a-z]+=/i.test(html), 'no style and no handler in the page itself');
  assert.ok(!/(?:href|src)="(?:[a-z]+:)?\/\//i.test(html), 'nothing from another server');
  assert.deepEqual([...html.matchAll(/(?:href|src)="([^"]+)"/g)].map((match) => match[1]), ['test-bitcoin/styles.css', 'test-bitcoin/app.mjs', 'shared/network-menu.js'], 'relative to the path the page is served under');
  assert.ok(!/@import|url\(/.test(css), 'the styles load nothing');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(script), 'what the service answers is shown as text');
  for (const id of new Set([...script.matchAll(/\$\('([a-z-]+)'\)/g)].map((match) => match[1]))) assert.ok(html.includes(`id="${id}"`), `the page has no element ${id}`);
  // Every field has its label, and the answers are announced.
  for (const id of ['target', 'sats', 'kind']) assert.ok(html.includes(`<label for="${id}">`), id);
  assert.match(html, /id="result" class="result" role="status" aria-live="polite"/);
  // Requests go to the page's own server, under the path it is served at, and the list is kept behind a try.
  assert.match(script, /new URL\(`v1\/\$\{route\}`, document\.baseURI\)/);
  assert.equal([...script.matchAll(/localStorage/g)].length, 2);
  assert.match(script, /try \{ window\.localStorage\.setItem\(/);
  assert.match(script, /try \{ kept = readKept\(window\.localStorage\.getItem\(/);
});
