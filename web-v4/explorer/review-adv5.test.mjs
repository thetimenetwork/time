// Adversarial review, part 5: smaller things, each with its input and what the page shows.
import test from 'node:test';
import assert from 'node:assert/strict';
import '../../client-v4/time-sdk.js';
import { createStrings } from './strings.mjs';
import { createExplorer } from './views.mjs';
import { differences } from './describe.mjs';
import { ApiFailure, createApi, createLive } from './client.mjs';
import { CheckFailure, createChecker } from './check.mjs';
import { formatAmount, formatMicros, formatShare, timeOfIso, formatTime, cleanText } from './format.mjs';
import { parseSearch, parseRoute } from './route.mjs';
import { page, textOf, within, buttons, fakeTimers } from './review-fake-page.mjs';

const SDK = globalThis.TimeSDK;
const NETWORK = 'ab'.repeat(32), HASH = 'C3'.repeat(32), KEY = '1f'.repeat(32), KEY2 = '2e'.repeat(32);
const NOW = Date.UTC(2026, 10, 17, 12, 0, 0), micros = (ms) => String(ms * 1000), iso = (ms) => new Date(ms).toISOString().replace('Z', '000Z');
const GENESIS = micros(NOW - 3 * 3600 * 1000 - 4000);
const index = { network_id: NETWORK, chain_id: 'time-devnet-v4-test', start_height: '1', indexed_height: '120', indexed_block_time: iso(NOW - 4000), seconds_behind: 4 };
const decoded = (kind, payload, from = '7') => SDK.decodeAction(SDK.concat(SDK.buildAction({ networkId: NETWORK, kind, from, nonce: '42', authEpoch: '3', publicKey: KEY2, payload }), new Uint8Array(64)));
async function open(hash, { api = {}, checker = {}, origin = '', live = null, timers = fakeTimers() } = {}) {
  const p = page(hash);
  const fullApi = { origin, status: async () => ({ network: { network_id: NETWORK, chain_id: 'time-devnet-v4-test', fee_micros: '1000' }, indexer: { indexed_height: '120', indexed_block_time: iso(NOW - 4000), seconds_behind: 4 } }),
    activity: async () => ({ items: [], has_more: false, index }), ...api };
  const fullChecker = { async trust() { return { networkId: NETWORK, chainId: 'time-devnet-v4-test', genesisTimeMicros: GENESIS, anchorHeight: '100', anchorHash: 'F0'.repeat(32) }; }, expectNetwork() {}, ...checker };
  const explorer = createExplorer({ document: p.document, window: p.window, api: fullApi, checker: fullChecker, live, t: createStrings('en'), now: () => NOW, timers, locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  return { ...p, view: p.$('view'), text: () => textOf(p.$('view')), explorer, timers };
}
const served = (kind, payload, more = {}) => ({ source: 'index', proven: false, index, action: { hash: HASH, height: '118', index: 0, time: iso(NOW - 6000), kind, opaque: false, sender: '7', nonce: '42', recipient: null, amount: null, reference: null, transfers: false,
  fee_rule: 'network_fee', fee_micros: '1000', results_checked: true, request_hash: null, request_status: null, unattributed: false, public_key: KEY2, auth_epoch: '3', payload, raw: 'AAAA', repeated: 1, ...more }, verify: { hash: HASH, height: '118', index: 0, total: '1', root_hash: 'AB'.repeat(32), leaf_hash: 'AAAA', aunts: [] } });
const checked = (action, more = {}) => ({ async checkAction(hash) { return { hash, height: '118', index: 0, blockHash: 'AA'.repeat(32), mode: 'history', resultsChecked: true, anchorHeight: '121', rawHex: '00', action, ...more }; } });

test('F2c: a completed waiting payment: the recipient and amount are the index\'s word, the bytes do not carry them, and the page says the description agrees with the bytes', async () => {
  const bytesSay = decoded(75, { type: 'execute', id: '2' });
  const p = await open(`#/action/${HASH}`, { api: { action: async () => served(75, { type: 'execute', id: '2' }, { recipient: '5', amount: '3600000000000' }) }, checker: checked(bytesSay) });
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.explorer.settled();
  const result = textOf(within(p.view, 'check-result')[0]);
  console.log(p.text().match(/account 7 completed a waiting payment[^.]*\./)?.[0], '||', result.slice(0, 260));
  assert.doesNotMatch(result, /The service's description above agrees with the checked bytes\./, 'the bytes say neither account 5 nor 1,000 h');
});

test('nit: a fee rule named like a property of every object is put on the page as code text', async () => {
  for (const rule of ['constructor', 'toString', '__proto__']) {
    const p = await open(`#/action/${HASH}`, { api: { action: async () => served(3, { to: '5', amount: '5' }, { fee_rule: rule }) }, checker: checked(null) });
    console.log(rule, '->', p.text().match(/Fee .*? Result/)?.[0]);
  }
});

test('home: the poll while the stream is down ignores 429 and Retry-After, and goes on in a hidden tab', async () => {
  let asked = 0;
  const live = { listen() {}, start() {}, stop() {}, state: () => 'waiting' };
  const p = await open('#/', { live, api: { blocks: async () => { asked += 1; throw new ApiFailure('http', { status: 429, code: 'rate_limited', retryAfter: 3600 }); } } });
  const poll = p.timers.intervals.find((entry) => entry.ms === 10000);
  const before = asked;
  for (let i = 0; i < 30; i++) { poll.fn(); await p.explorer.settled(); }
  console.log('the service said "wait 3600 s"; in the next five minutes the page asked', asked - before, 'more times');
  assert(asked - before <= 5, 'no backing off');
});

test('the stream: a service that says hello and bye is reconnected to twice a second, for ever (cost 10 each)', async () => {
  const timers = fakeTimers(); let opened = 0; const sources = [];
  const live = createLive({ api: createApi({ origin: 'https://api.example', fetcher: async () => { throw new Error('unused'); } }), timers, open: () => { opened += 1; const listeners = {}; const source = { addEventListener: (type, fn) => { listeners[type] = fn; }, close() {}, emit: (type, event = {}) => listeners[type]?.(event) }; sources.push(source); return source; } });
  live.listen({}); live.start();
  const waits = [];
  for (let i = 0; i < 20; i++) { sources.at(-1).emit('hello'); sources.at(-1).emit('bye'); const timer = timers.timeouts.at(-1); waits.push(timer.ms); timer.fn(); }
  console.log('pauses between 20 reconnections:', [...new Set(waits)], 'ms; opened', opened);
  assert(waits.at(-1) > 500, 'the pause after "bye" never grows');
});

test('format: amounts at every magnitude are exact, and no shown amount is larger than the real one', () => {
  for (const [input, human, exact] of [['0', '0 s', '0 µs'], ['1', '0.000001 s', '1 µs'], ['999999', '0.999999 s', '999,999 µs'], ['1000000', '1 s', '1,000,000 µs'], ['59999999', '59.999999 s', '59,999,999 µs'], ['60000000', '1 min', '60,000,000 µs'], ['3599999999', '59 min 59.999999 s', '3,599,999,999 µs'], ['3600000000', '1 h', '3,600,000,000 µs'],
    ['9007199254740993', '2,501,999 h 47 min 34.740993 s', '9,007,199,254,740,993 µs'], ['18446744073709551615', '5,124,095,576 h 1 min 49.551615 s', '18,446,744,073,709,551,615 µs']]) {
    assert.equal(formatAmount(input), human); assert.equal(formatMicros(input), exact);
    // Read back: the words give the same number of microseconds.
    const m = /^(?:([\d,]+) h)? ?(?:(\d+) min)? ?(?:(\d+)(?:\.(\d+))? s)?$/.exec(human);
    const back = BigInt((m[1] ?? '0').replaceAll(',', '')) * 3600000000n + BigInt(m[2] ?? '0') * 60000000n + BigInt(m[3] ?? '0') * 1000000n + BigInt((m[4] ?? '').padEnd(6, '0') || '0');
    assert.equal(back.toString(), input);
  }
  for (const bad of ['-1', '01', '1.5', '1e3', ' 1', '18446744073709551616', '', null, 5, 5n, '٣', '１']) { assert.equal(formatAmount(bad), null, String(bad)); assert.equal(formatMicros(bad), null); }
  assert.equal(formatShare('1', '3'), '33.33'); assert.equal(formatShare('2', '3'), '66.66'); assert.equal(formatShare('3', '3'), '100.00'); assert.equal(formatShare('4', '3'), null);
  // Times: only the API's form, and the two zones.
  assert.equal(timeOfIso('2026-11-17T10:00:00.000000Z'), Date.UTC(2026, 10, 17, 10)); assert.equal(timeOfIso('2026-11-17T10:00:00+01:00'), null); assert.equal(timeOfIso('2026-13-45T10:00:00Z'), null);
  assert.match(formatTime(Date.UTC(2026, 2, 29, 0, 30), { locale: 'en-GB', timeZone: 'Europe/Paris' }), /29 Mar 2026, 01:30:00 CET/);
  assert.match(formatTime(Date.UTC(2026, 2, 29, 1, 30), { locale: 'en-GB', timeZone: 'Europe/Paris' }), /29 Mar 2026, 03:30:00 CEST/);
  assert.match(formatTime(Date.UTC(2026, 2, 29, 1, 30), { locale: 'en-GB', utc: true, timeZone: 'Europe/Paris' }), /01:30:00 UTC/);
  // Free text: no control, direction or look-alike character survives.
  const dirty = 'pay‮me​ рaypal\u0000\n<b>';
  assert.equal(cleanText(dirty).text, 'pay\\u{202e}me\\u{200b} \\u{440}aypal\\u{0}\\u{a}<b>');
  // The search box and addresses.
  assert.deepEqual(parseSearch('‮7'), { kind: 'invalid', reason: 'search.invalid' });
  assert.deepEqual(parseRoute('#/account/@аlice'), { view: 'unknown' }); // a Cyrillic a
  assert.deepEqual(parseRoute('#/find/1e3'), { view: 'unknown' });
  assert.deepEqual(parseRoute('#/account/%40alice'), { view: 'unknown' });
});
