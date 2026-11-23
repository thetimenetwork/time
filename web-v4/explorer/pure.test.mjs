// The parts of the explorer that only compute: what the search box means, addresses, paging,
// amounts and times, an action in words for every kind the API returns, the API client and the
// event stream's reconnection.
import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import '../../client-v4/time-sdk.js';
import { KIND_NAMES } from '../../client-v4/indexer.mjs';
import { createStrings, STRINGS } from './strings.mjs';
import { parseSearch, routeOfSearch, parseRoute, hrefOf, SAFE_HREF, newPager, pagerLoaded, pagerCursor, pagerNext, pagerPrevious, canNext, canPrevious } from './route.mjs';
import { formatAmount, formatMicros, formatNumber, formatShare, formatTime, timeOfMicros, timeOfIso, ago, shortHex, hexOfBase64, hexLines, cleanText, isCursor, isAccountId, isHeight, isMicros, isName, OUTSIDE_HREF, outsideAddress, isPeer, readJoin } from './format.mjs';
import { describeAction, differences, compareAction, CATEGORIES } from './describe.mjs';
import { createApi, createLive, apiOrigin, ApiFailure } from './client.mjs';

const SDK = globalThis.TimeSDK, HASH = 'C3'.repeat(32), KEY = '1f'.repeat(32), REFERENCE = '5e'.repeat(32);

test('the search box: a hash, a number, a name, and what is none of them', () => {
  assert.deepEqual(parseSearch(`  ${HASH.toLowerCase()}\n`), { kind: 'action', hash: HASH });
  assert.deepEqual(parseSearch('1'.repeat(64)), { kind: 'action', hash: '1'.repeat(64) }, '64 digits are a hash, not a number');
  assert.deepEqual(parseSearch('118'), { kind: 'number', value: '118' });
  assert.deepEqual(parseSearch('0'), { kind: 'account', id: '0' }, 'heights start at one');
  assert.deepEqual(parseSearch('18446744073709551614'), { kind: 'account', id: '18446744073709551614' }, 'too long for a height');
  assert.deepEqual(parseSearch('18446744073709551615'), { kind: 'invalid', reason: 'search.tooLarge' });
  assert.deepEqual(parseSearch('007'), { kind: 'invalid', reason: 'search.leadingZero' });
  assert.deepEqual(parseSearch('alice_01'), { kind: 'account', name: 'alice_01' });
  assert.deepEqual(parseSearch('@Alice'), { kind: 'account', name: 'alice' });
  assert.deepEqual(parseSearch('@42'), { kind: 'account', name: '42' }, 'with @, digits are a name');
  assert.deepEqual(parseSearch('ab'), { kind: 'account', name: 'ab' });
  assert.deepEqual(parseSearch('abcdef0123456789abcdef'), { kind: 'invalid', reason: 'search.hashLength' });
  for (const value of ['', '   ', null, undefined, 12]) assert.deepEqual(parseSearch(value), { kind: 'empty' });
  for (const value of ['a', 'two words', 'näme', '@', '#/block/1', '<script>', 'x'.repeat(81), '-1', '1.5', '１２３', 'https://evil.example']) assert.equal(parseSearch(value).kind, 'invalid', value);
  assert.deepEqual(routeOfSearch(parseSearch('118')), { view: 'find', number: '118' });
  assert.deepEqual(routeOfSearch(parseSearch('@bob')), { view: 'account', name: 'bob' });
  assert.deepEqual(routeOfSearch(parseSearch('0')), { view: 'account', id: '0' });
  assert.equal(routeOfSearch(parseSearch('?')), null);
  // Every search that leads somewhere leads to an address the page accepts and reads back the same.
  for (const value of [HASH, '118', '0', '@bob', 'alice_01']) { const route = routeOfSearch(parseSearch(value)), href = hrefOf(route); assert.match(href, SAFE_HREF); assert.deepEqual(parseRoute(href), route); }
});

test('addresses: each view has one form, and nothing else is an address', () => {
  assert.deepEqual(parseRoute(''), { view: 'home' });
  assert.deepEqual(parseRoute('#/'), { view: 'home' });
  assert.deepEqual(parseRoute('#/validators'), { view: 'validators' });
  assert.deepEqual(parseRoute('#/block/12'), { view: 'block', height: '12' });
  assert.deepEqual(parseRoute(`#/action/${HASH}`), { view: 'action', hash: HASH });
  assert.deepEqual(parseRoute('#/account/0'), { view: 'account', id: '0' });
  assert.deepEqual(parseRoute('#/account/@a_1'), { view: 'account', name: 'a_1' });
  for (const address of ['#/block/0', '#/block/012', '#/block/1/', '#/block/1?cursor=2', `#/action/${HASH.toLowerCase()}`, '#/action/xyz', '#/account/@A', '#/account/@a', '#/account/18446744073709551615', '#/account/@' + 'a'.repeat(16), '#/validators/', '#/find/0', '#block/1', '#/../x', '#/block/%31'])
    assert.deepEqual(parseRoute(address), { view: 'unknown' }, String(address));
  for (const none of [5, null, undefined]) assert.deepEqual(parseRoute(none), { view: 'home' }, 'no address at all is the home page');
  // An address is only made from accepted values.
  for (const route of [{ view: 'block', height: '0' }, { view: 'block', height: '1/../x' }, { view: 'action', hash: 'javascript:alert(1)' }, { view: 'account', id: '-1' }, { view: 'account', name: '<b>' }, { view: 'account' }, { view: 'elsewhere' }, null, { view: 'find', number: 'x' }]) assert.equal(hrefOf(route), null, JSON.stringify(route));
  assert.equal(hrefOf({ view: 'action', hash: HASH.toLowerCase() }), `#/action/${HASH}`);
  for (const bad of ['#/block/1"onclick="x', 'javascript:alert(1)', '//evil.example', 'https://evil.example', '#/account/@a b', '/v1/status', '#/block/1#x']) assert.doesNotMatch(bad, SAFE_HREF);
});

test('outside addresses: only a wallet\'s https origin and a join script at its one path, each reading back unchanged', () => {
  const host253 = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`;
  for (const [value, kind] of [['https://wallet.example', 'origin'], ['https://d4api.cloudfront.net', 'origin'], ['https://wallet.example:8443', 'origin'], ['https://localhost:9443', 'origin'], ['https://a-b.x1.example', 'origin'], ['https://1a.example', 'origin'], [`https://${host253}`, 'origin'],
    ['https://join.example/join/join.sh', 'script'], ['https://join.example:8443/join/join.sh', 'script'], ['https://xn--bcher-kva.example/join/join.sh', 'script']]) assert.equal(outsideAddress(value), kind, value);
  for (const value of ['http://wallet.example', 'http://join.example/join/join.sh', 'https://wallet.example/', 'https://wallet.example/app', 'https://wallet.example:443', 'https://join.example:443/join/join.sh', 'https://wallet.example:0', 'https://wallet.example:65536', 'https://wallet.example:08443',
    'https://user@wallet.example', 'https://user:pw@wallet.example', 'https://user:pw@join.example/join/join.sh', 'https://Wallet.example', 'https://wallet.example.', 'https://.wallet.example', 'https://-wallet.example', 'https://wallet-.example', 'https://wal_let.example', `https://${host253}e`, `https://${'a'.repeat(64)}.example`,
    'https://127.0.0.1', 'https://0x7f.1', 'https://1.2.3.4/join/join.sh', 'https://[::1]', 'https://wallet.example?x', 'https://wallet.example#x', 'https://join.example/join/join.sh/', 'https://join.example/join/JOIN.sh', 'https://join.example/join/join.sh?', 'https://join.example/join/join.sh#',
    'https://join.example/join/join%2Esh', 'https://join.example//join/join.sh', 'https://join.example/join/../join/join.sh', 'https://join.example/join/other.sh', 'https:\\\\wallet.example', 'javascript:alert(1)', 'javascript://wallet.example', 'data:text/html,x', '//wallet.example', 'wallet.example',
    ' https://wallet.example', 'https://wallet.example ', 'https://wal let.example', 'https://wallet.example\n', 'https://wallet.example\u0000', 'https://wallet.еxample', '', null, 42, {}, ['https://wallet.example']]) assert.equal(outsideAddress(value), null, JSON.stringify(value));
  assert.match('https://wallet.example', OUTSIDE_HREF);
  // An outside address is never an address of the explorer, and the other way round.
  for (const value of ['https://wallet.example', 'https://join.example/join/join.sh']) assert.doesNotMatch(value, SAFE_HREF);
  for (const value of ['#/', '#/validators', `#/action/${HASH}`]) assert.equal(outsideAddress(value), null);
});

test('this network\'s join.json: every value by its own test, nothing missing, nothing added, and a copy of only what was tested', () => {
  const JOIN = { script_url: 'https://join.example/join/join.sh', wallet_url: 'https://wallet.example', chain_id: 'time-devnet-v4-abc0', min_self_bond_micros: '1000000',
    files: { node_sha256: 'a1'.repeat(32), cometbft_sha256: 'b2'.repeat(32), genesis_sha256: 'c3'.repeat(32) }, peers: [`${'0f'.repeat(20)}@203.0.113.7:26656`, `${'1e'.repeat(20)}@0.0.0.0:1`], pace: '500ms' };
  const read = readJoin(JSON.stringify(JOIN));
  assert.deepEqual(read, JOIN);
  assert(Object.isFrozen(read) && Object.isFrozen(read.files) && Object.isFrozen(read.peers));
  const { pace, ...unpaced } = JOIN;
  assert.deepEqual(readJoin(JSON.stringify(unpaced)), unpaced, 'pace is optional');
  for (const ok of [{ pace: '100ms' }, { pace: '999ms' }, { pace: '1s' }, { pace: '5s' }, { min_self_bond_micros: '1' }, { min_self_bond_micros: '1000000000000000' }, { chain_id: 'abc' }, { chain_id: 'a'.repeat(64) },
    { peers: Array.from({ length: 8 }, (_, i) => `${'0f'.repeat(20)}@255.255.255.${i}:65535`) }]) assert.notEqual(readJoin(JSON.stringify({ ...JOIN, ...ok })), null, JSON.stringify(ok));
  for (const bad of [{ pace: '99ms' }, { pace: '1000ms' }, { pace: '0s' }, { pace: '6s' }, { pace: '500 ms' }, { pace: null }, { min_self_bond_micros: '0' }, { min_self_bond_micros: '1000000000000001' }, { min_self_bond_micros: '1e6' }, { min_self_bond_micros: '-1' }, { min_self_bond_micros: 1 },
    { chain_id: 'ab' }, { chain_id: 'a'.repeat(65) }, { chain_id: 'Time' }, { chain_id: 'a_b' }, { chain_id: 'a b' }, { chain_id: 7 },
    { files: { ...JOIN.files, node_sha256: 'A1'.repeat(32) } }, { files: { ...JOIN.files, extra: 'a1'.repeat(32) } }, { files: [JOIN.files.node_sha256, JOIN.files.cometbft_sha256, JOIN.files.genesis_sha256] }, { files: { node_sha256: 'a1'.repeat(32), cometbft_sha256: 'b2'.repeat(32), genesis: 'c3'.repeat(32) } },
    { peers: [] }, { peers: Array.from({ length: 9 }, (_, i) => `${'0f'.repeat(20)}@10.0.0.${i}:26656`) }, { peers: [JOIN.peers[0], JOIN.peers[0]] }, { peers: [`${'0F'.repeat(20)}@203.0.113.7:26656`] }, { peers: [`${'0f'.repeat(20)}@256.0.113.7:26656`] }, { peers: [`${'0f'.repeat(20)}@203.0.113.7:65536`] },
    { peers: [`${'0f'.repeat(20)}@203.0.113.7:026656`] }, { peers: [`${'0f'.repeat(20)}@node.example:26656`] }, { peers: [`${'0f'.repeat(20)}@[::1]:26656`] }, { peers: [`tcp://${'0f'.repeat(20)}@203.0.113.7:26656`] }, { peers: [` ${JOIN.peers[0]}`] }, { peers: [7] },
    { script_url: 'https://join.example/join/join.sh?x' }, { wallet_url: 'https://wallet.example/' }, { extra: true }]) assert.equal(readJoin(JSON.stringify({ ...JOIN, ...bad })), null, JSON.stringify(bad));
  for (const key of Object.keys(unpaced)) { const { [key]: _, ...without } = JOIN; assert.equal(readJoin(JSON.stringify(without)), null, `without ${key}`); }
  for (const text of [JOIN, null, undefined, 42, '', 'null', '[]', '"x"', '42', '{', JSON.stringify(JOIN).replace('{', '{"__proto__":{},'), `${JSON.stringify(JOIN)} `.padEnd(16385, ' ')]) assert.equal(readJoin(text), null, String(text).slice(0, 40));
  assert.notEqual(readJoin(`${JSON.stringify(JOIN)}\n`), null, 'the text of a file, with its last line break');
  // Entry nodes on their own.
  for (const value of [`${'0f'.repeat(20)}@203.0.113.7:26656`, `${'0f'.repeat(20)}@255.255.255.255:65535`, `${'0f'.repeat(20)}@0.0.0.0:1`]) assert.equal(isPeer(value), true, value);
  for (const value of [`${'0f'.repeat(20)}@203.0.113.7:0`, `${'0f'.repeat(20)}@203.0.113.7:99999`, `${'0f'.repeat(20)}@203.0.113.7`, `${'0f'.repeat(20)}@1.2.3`, `${'0f'.repeat(20)}@1.2.3.4.5`, `${'0f'.repeat(20)}@01.2.3.4:1`, `${'0f'.repeat(19)}0@1.2.3.4:1x`, `${'0f'.repeat(21)}@1.2.3.4:1`, '@1.2.3.4:1', null]) assert.equal(isPeer(value), false, String(value));
});

test('paging: forward by the cursor of the answer, back by the cursors already seen', () => {
  let pager = newPager();
  assert.deepEqual([pagerCursor(pager), canNext(pager), canPrevious(pager)], [null, false, false]);
  pager = pagerLoaded(pager, { has_more: true, next_cursor: '118.24' });
  assert.equal(canNext(pager), true);
  pager = pagerNext(pager);
  assert.deepEqual([pagerCursor(pager), pager.page, canNext(pager), canPrevious(pager)], ['118.24', 1, false, true]);
  pager = pagerLoaded(pager, { has_more: true, next_cursor: '117.3' });
  pager = pagerNext(pager);
  pager = pagerLoaded(pager, { has_more: false, next_cursor: '90.0' });
  assert.deepEqual([pagerCursor(pager), pager.page, canNext(pager)], ['117.3', 2, false]);
  assert.equal(pagerNext(pager), pager, 'no page after the last');
  pager = pagerPrevious(pager);
  assert.deepEqual([pagerCursor(pager), pager.page, canNext(pager), pagerCursor(pagerNext(pager))], ['118.24', 1, true, '117.3']);
  pager = pagerPrevious(pager);
  assert.deepEqual([pagerCursor(pager), pager.page, canPrevious(pager)], [null, 0, false]);
  assert.equal(pagerPrevious(pager), pager);
  // A cursor that does not have the form of one is not kept: it would go into an address.
  for (const cursor of ['1&limit=200', '../x', '', null, 5, '1.2.3', '01', '1.01', '1 OR 1', 'a'.repeat(50)]) { assert.equal(isCursor(cursor), false, String(cursor)); assert.equal(canNext(pagerLoaded(newPager(), { has_more: true, next_cursor: cursor })), false); }
  assert.equal(canNext(pagerLoaded(newPager(), { has_more: 'yes', next_cursor: '5' })), false);
  assert.equal(canNext(pagerLoaded(newPager(), null)), false);
});

test('amounts of time: as a person reads them, exact, and never a wrong figure for a wrong input', () => {
  const cases = { 0: '0 s', 1: '0.000001 s', 1000: '0.001 s', 250000: '0.25 s', 1000000: '1 s', 59999999: '59.999999 s', 60000000: '1 min', 61500000: '1 min 1.5 s', 3600000000: '1 h', 3603000000: '1 h 3 s', 7503250000: '2 h 5 min 3.25 s', 86400000000: '24 h', 31536000000000: '8,760 h',
    '18446744073709551615': '5,124,095,576 h 1 min 49.551615 s' };
  for (const [micros, text] of Object.entries(cases)) assert.equal(formatAmount(String(micros)), text, String(micros));
  assert.equal(formatAmount('7503250000', { h: 'Std', min: 'Min', s: 'Sek', thousands: '.', decimal: ',' }), '2 Std 5 Min 3,25 Sek');
  assert.equal(formatMicros('7503250000'), '7,503,250,000 µs');
  assert.equal(formatMicros('0'), '0 µs');
  // The parts add up to the amount again, for a spread of values.
  for (const micros of [1n, 999999n, 1000001n, 3599999999n, 3600000001n, 123456789012345n]) {
    const [, h = '0', m = '0', s = '0'] = /^(?:([\d,]+) h)? ?(?:(\d+) min)? ?(?:([\d.]+) s)?$/.exec(formatAmount(micros.toString()));
    const [whole, fraction = ''] = s.split('.');
    assert.equal(BigInt(h.replace(/,/g, '')) * 3600000000n + BigInt(m) * 60000000n + BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0')), micros);
  }
  for (const value of [7503250000, '-1', '1.5', '1e6', '01', '', ' 5', '18446744073709551616', null, undefined, {}, '5\n', '٥']) { assert.equal(formatAmount(value), null, String(value)); assert.equal(formatMicros(value), null); assert.equal(isMicros(value), false); }
  assert.equal(formatNumber('1234567'), '1,234,567');
  assert.equal(formatNumber(12), '12');
  for (const value of [-1, 1.5, '1,000', '0x10', NaN, null]) assert.equal(formatNumber(value), null);
  assert.deepEqual([formatShare('1', '3'), formatShare('2', '3'), formatShare('3', '3'), formatShare('0', '7')], ['33.33', '66.66', '100.00', '0.00']);
  for (const [part, total] of [['4', '3'], ['1', '0'], ['x', '3'], [1, 3]]) assert.equal(formatShare(part, total), null);
  assert.deepEqual([isAccountId('18446744073709551614'), isAccountId('18446744073709551615'), isHeight('0'), isHeight('1'), isName('a'), isName('ab'), isName('Ab')], [true, false, false, true, false, true, false]);
});

test('times: in the reader\'s zone or in UTC, how long ago, and nothing for a wrong input', () => {
  const ms = Date.UTC(2026, 10, 17, 11, 59, 56);
  assert.equal(timeOfMicros(String(ms * 1000)), ms);
  assert.equal(timeOfIso('2026-11-17T11:59:56.123456Z'), ms + 123);
  assert.equal(timeOfIso('2026-11-17T11:59:56Z'), ms);
  for (const text of ['2026-11-17', '2026-11-17T11:59:56+01:00', 'Tue Nov 17 2026', '2026-13-45T99:99:99Z', '', null, 5, '2026-11-17T11:59:56Z<b>']) assert.equal(timeOfIso(text), null, String(text));
  for (const value of ['x', '-1', null, '9'.repeat(20)]) assert.equal(timeOfMicros(value), null);
  assert.equal(formatTime(ms, { locale: 'en-GB', timeZone: 'Europe/Paris' }), '17 Nov 2026, 12:59:56 CET');
  assert.equal(formatTime(ms, { locale: 'en-GB', timeZone: 'America/New_York' }), '17 Nov 2026, 06:59:56 GMT-5');
  assert.equal(formatTime(ms, { locale: 'en-GB', timeZone: 'Europe/Paris', utc: true }), '17 Nov 2026, 11:59:56 UTC');
  for (const value of [NaN, Infinity, '5', null, 9e15]) assert.equal(formatTime(value, { locale: 'en-GB' }), null);
  assert.equal(formatTime(ms, { locale: 'en-GB', timeZone: 'Not/AZone' }), null);
  const past = (seconds) => ago(ms - seconds * 1000, ms);
  assert.deepEqual([past(0), past(4), past(5), past(59), past(60), past(3599), past(3600), past(86399), past(86400 * 3)], [{ unit: 'now', count: 0 }, { unit: 'now', count: 0 }, { unit: 's', count: 5 }, { unit: 's', count: 59 }, { unit: 'min', count: 1 }, { unit: 'min', count: 59 }, { unit: 'h', count: 1 }, { unit: 'h', count: 23 }, { unit: 'd', count: 3 }]);
  assert.deepEqual([past(-30), past(-600)], [{ unit: 'now', count: 0 }, { unit: 'future', count: 0 }], 'a clock that differs a little is not "in the future"');
  assert.equal(ago('x', ms), null);
  assert.equal(shortHex(HASH), 'C3C3C3C3…C3C3C3');
  assert.equal(shortHex('<b>'), null);
  assert.equal(hexOfBase64(Buffer.from([0, 1, 254, 255, 16]).toString('base64')), '0001feff 10');
  for (const value of ['not base64!', null, '<b>']) assert.equal(hexOfBase64(value), null);
  // Bytes already written in hexadecimal (what a check proved) are laid out the same way.
  const bytes = Buffer.from(Array.from({ length: 40 }, (_, i) => i));
  assert.equal(hexLines(bytes.toString('hex')), hexOfBase64(bytes.toString('base64')));
  assert.equal(hexLines(bytes.toString('hex')).replace(/\s/g, ''), bytes.toString('hex'));
  assert.deepEqual([hexLines('C0FFEE'), hexLines(''), hexLines('00010203 '), hexLines('abc'), hexLines('zz'), hexLines(null), hexLines('<b>')], ['c0ffee', '', null, null, null, null, null]);
});

test('text from outside is made plain: no control character, no direction override, no look-alike letter, no end', () => {
  assert.deepEqual(cleanText('plain text 123'), { text: 'plain text 123', cut: false });
  assert.deepEqual(cleanText('a‮b\u0000c\nd'), { text: 'a\\u{202e}b\\u{0}c\\u{a}d', cut: false });
  assert.deepEqual(cleanText('раураl'), { text: '\\u{440}\\u{430}\\u{443}\\u{440}\\u{430}l', cut: false }, 'Cyrillic letters that look like Latin ones are shown as codes');
  assert.deepEqual(cleanText('😀'), { text: '\\u{1f600}', cut: false });
  assert.deepEqual(cleanText('x'.repeat(500), 10), { text: 'xxxxxxxxxx', cut: true });
  assert.deepEqual(cleanText('a\nb\tc', 50, { lines: true }), { text: 'a\nb\\u{9}c', cut: false });
  assert.deepEqual([cleanText(null).text, cleanText(undefined).text, cleanText(12).text, cleanText({}).text], ['', '', '12', '[object Object]']);
});

test('an action in words: every kind the API returns has its sentence, and every sentence its values', () => {
  const t = createStrings('en');
  const item = (kind, more = {}) => ({ kind, opaque: false, sender: '7', nonce: '1', recipient: null, amount: null, reference: null, transfers: false, request_status: null, request_hash: null, unattributed: false, ...more });
  // Every kind the indexer names (the SDK's kinds) is put into words, as a list item (without
  // payload) and as a detail (with it); none falls back to "cannot read".
  const payloads = { 1: { commitment: KEY, expires_elapsed_micros: '5' }, 2: { name: 'alice', salt: KEY }, 4: { epoch: '3', weight: '10' }, 5: { operator: '2', amount: '1000000', min_shares: '1' }, 6: { operator: '2', shares: '10', min_amount: '1' }, 7: { entry: '4' },
    8: { public_key: KEY, can_manage: false, can_spend: true, proof: KEY + KEY }, 9: { public_key: KEY }, 11: { guardians: ['3', '4'], threshold: '2', delay_seconds: '60' }, 12: { target: '9', policy_version: '1', accept: true }, 13: { target: '9', new_public_key: KEY },
    17: { commission_bps: 1000, consensus_key: KEY, proof: KEY }, 18: { amount: '5000000' }, 19: { amount: '5000000', min_amount: '1' }, 21: { entry: '2' }, 44: { public_key: KEY },
    45: { name: 'alice', salt: KEY, security: { keys: [{ proof: KEY + KEY, public_key: KEY, role: 'spend' }], policy: { daily_limit_micros: '60000000', delay_seconds: '172800', freeze_seconds: '172800', threshold: '2' } } }, 70: { keys: [{ public_key: KEY, role: 'spend' }], policy: { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '86400', freeze_seconds: '600' } },
    71: { add: [{ public_key: KEY }], remove: [KEY] }, 72: { freezes: '0', version: '1', expires_elapsed_micros: '9' }, 73: { op: { type: 'replace', keys: [{ public_key: KEY, role: 'recover' }], policy: { daily_limit_micros: '5' } }, approvals: [{ public_key: KEY }] }, 74: { version: '2' },
    75: { type: 'execute', id: '2' }, 76: { type: 'payment', id: '2' }, 77: { daily_limit_micros: '120000000' }, 80: { activate_elapsed_micros: '1814400000000', spec: KEY, version: '5' } };
  const sentences = new Set();
  for (const [kindText, name] of Object.entries(KIND_NAMES)) {
    const kind = Number(kindText);
    // A payment comes with its recipient and amount in the list item, as the API gives them.
    const paid = kind === 3 || kind === 10 ? { recipient: '5', amount: '5', reference: kind === 10 ? REFERENCE : null, transfers: true } : {};
    for (const action of [item(kind, paid), item(kind, { ...paid, payload: payloads[kind] ?? {} })]) {
      const said = describeAction(action);
      assert(Object.hasOwn(CATEGORIES, kind), `${name} has a category`);
      assert.notEqual(said.category, 'unknown', name);
      assert(!['act.opaque', 'act.unreadable'].includes(said.sentence), name);
      assert(Object.hasOwn(STRINGS.en, said.sentence), `${name}: ${said.sentence}`);
      // Every place of the sentence has a value, and a value that was given has the type the page shows.
      for (const [, place] of t(said.sentence).matchAll(/\{([a-zA-Z]+)\}/g)) assert(said.params[place], `${name}: ${said.sentence} has no ${place}`);
      for (const { label } of said.details) assert(Object.hasOwn(STRINGS.en, label), `${name}: ${label}`);
      if (action.payload && kind !== 40) for (const [, place] of t(said.sentence).matchAll(/\{([a-zA-Z]+)\}/g)) assert.notEqual(said.params[place].type, 'invalid', `${name}: ${place} of ${said.sentence}`);
      sentences.add(said.sentence);
    }
  }
  // The table holds no sentence for an action that no action can produce.
  const more = [item(3, { recipient: '5', amount: '5' }), item(10, { recipient: '5', amount: '5', reference: REFERENCE }), item(12, { payload: { target: '9', accept: false } }), item(2, { payload: {} }),
    item(73, { recipient: '5', amount: '5', payload: { op: { type: 'pay', to: '5', amount: '5' } } }), item(73, { payload: { op: { type: 'cancel' } } }), item(73, { payload: { op: { type: 'unfreeze' } } }), item(73),
    item(75, { payload: { type: 'request', to: '5', amount: '5' }, recipient: '5', amount: '5', request_status: 'waiting' }), item(75, { recipient: '5', amount: '5', transfers: true, request_hash: HASH, payload: { type: 'execute', id: '1' } }), item(75, { unattributed: true }), item(75),
    item(76, { payload: { type: 'limit', id: '1' } }), item(76), item(77), item(80, { payload: {} }), item(23, { opaque: true }), item(63, { opaque: true }), item(200), { kind: null, opaque: true, sender: null },
    { kind: 75, from: '7', nonce: '1', payload: { type: 'execute', id: '1' } }];
  for (const action of more) sentences.add(describeAction(action).sentence);
  for (const key of Object.keys(STRINGS.en).filter((entry) => entry.startsWith('act.'))) assert(sentences.has(key), `no action says ${key}`);

  // The cases the task names, read back in full.
  const words = (action) => { const said = describeAction(action); return [said.sentence, said.params, said.status]; };
  assert.deepEqual(words(item(10, { recipient: '5', amount: '7503250000', reference: REFERENCE, transfers: true })), ['act.shopPayment', { from: { type: 'account', id: '7' }, to: { type: 'account', id: '5' }, amount: { type: 'amount', micros: '7503250000' }, reference: { type: 'reference', hex: REFERENCE } }, null]);
  assert.deepEqual(words(item(75, { recipient: '5', amount: '900', request_status: 'cancelled', payload: { type: 'request', to: '5', amount: '900' } })).slice(0, 3), ['act.waitingRequest', { from: { type: 'account', id: '7' }, to: { type: 'account', id: '5' }, amount: { type: 'amount', micros: '900' } }, 'pending.cancelled']);
  for (const status of ['waiting', 'completed', 'cancelled', 'dropped', 'ended', 'unknown']) assert.equal(describeAction(item(75, { recipient: '5', amount: '9', request_status: status })).status, `pending.${status}`);
  assert.equal(describeAction(item(75, { recipient: '5', amount: '9', request_status: '<b>paid</b>' })).status, 'pending.unknown', 'a status the page does not know is not repeated');
  assert.equal(describeAction(item(75, { recipient: '5', amount: '9', request_hash: HASH, transfers: true })).details[0].value.hash, HASH);
  assert.deepEqual(describeAction(item(70, { payload: payloads[70] })).details.map((detail) => detail.label), ['detail.key.spend', 'detail.dailyLimit', 'detail.delay', 'detail.freezeLength', 'detail.threshold']);
  // A registration that carries a set of keys (45): a name, from nobody, with the keys and rules of its first block.
  assert.deepEqual(words({ ...item(45, { payload: payloads[45] }), sender: null }), ['act.registerProtected', { from: { type: 'nobody' }, name: { type: 'name', name: 'alice' } }, null]);
  assert.deepEqual(describeAction(item(45, { payload: payloads[45] })).details.map((detail) => detail.label), ['detail.key.spend', 'detail.dailyLimit', 'detail.delay', 'detail.freezeLength', 'detail.threshold']);
  assert.deepEqual([describeAction(item(45)).sentence, describeAction(item(45)).category, CATEGORIES[45]], ['act.registerProtectedPlain', 'name', 'name']);
  assert.equal(t('act.registerProtected'), '{from} took the name {name} for a new account that has separate keys for signing in, spending and recovery, and a daily limit, from its first block.');
  // The engine's own registration, read by the SDK: the four keys of its set in their roles, and its rules.
  const engineRegistration = JSON.parse(readFileSync(new URL('../../client-v4/protected-registration.fixture.json', import.meta.url), 'utf8'));
  const registered = describeAction(SDK.decodeAction(SDK.hexToBytes(engineRegistration.registration.action_hex)));
  assert.deepEqual([registered.sentence, registered.params], ['act.registerProtected', { from: { type: 'nobody' }, name: { type: 'name', name: engineRegistration.name } }]);
  assert.deepEqual(registered.details.map((detail) => [detail.label, detail.value.hex ?? detail.value.micros ?? detail.value.value]), [
    ...engineRegistration.security.keys.map((entry) => [`detail.key.${entry.role}`, entry.public_key]),
    ['detail.dailyLimit', '500000'], ['detail.delay', '60000000'], ['detail.freezeLength', '120000000'], ['detail.threshold', '2']]);
  assert.deepEqual(describeAction(item(5, { payload: payloads[5] })).params.validator, { type: 'account', id: '2' });
  assert.deepEqual(describeAction({ kind: 40, opaque: false, sender: null }).params.from, { type: 'nobody' });
  assert.deepEqual(describeAction(item(23, { opaque: true })).params.kind, { type: 'number', value: '23' });
  // A validator's upgrade signal (kind 80): the plan it supports, a withdrawal, and a list item, which carries no content.
  assert.deepEqual(words(item(80, { payload: payloads[80] })), ['act.signalSupport', { from: { type: 'account', id: '7' }, version: { type: 'number', value: '5' } }, null]);
  assert.deepEqual(describeAction(item(80, { payload: payloads[80] })).details, [{ label: 'detail.signalStart', value: { type: 'sinceStart', micros: '1814400000000' } }, { label: 'detail.signalSpec', value: { type: 'hash', hex: KEY } }]);
  assert.deepEqual([describeAction(item(80, { payload: payloads[80] })).category, CATEGORIES[80]], ['validator', 'validator']);
  assert.deepEqual(words(item(80, { payload: {} })), ['act.signalWithdraw', { from: { type: 'account', id: '7' } }, null]);
  assert.deepEqual(words(item(80)), ['act.signalPlain', { from: { type: 'account', id: '7' } }, null]);
  // A row an older index stored without reading it: said as a signal, of which form is not known.
  assert.deepEqual([describeAction(item(80, { opaque: true })).sentence, describeAction(item(80, { opaque: true })).category], ['act.signalPlain', 'validator']);
  // Content that is not a plan is not put into the words of one, and no part of it is shown.
  for (const payload of [{ version: '5' }, { ...payloads[80], version: '05' }, { ...payloads[80], spec: KEY.toUpperCase() }, { ...payloads[80], activate_elapsed_micros: 5 }, { withdraw: true }]) assert.deepEqual([describeAction(item(80, { payload })).sentence, describeAction(item(80, { payload })).details], ['act.signalPlain', []], JSON.stringify(payload));
  assert.equal(t('act.signalSupport'), '{from} signalled that its validator supports moving the network to version {version} of its rules.');
  // The engine's own signed signals, read by the SDK and put into words.
  const engineSignals = JSON.parse(readFileSync(new URL('../../v5/tests/fixtures/upgrade-state.fixture.json', import.meta.url), 'utf8')).actions;
  const support = describeAction(SDK.decodeAction(SDK.hexToBytes(engineSignals.support.action_hex))), withdrawal = describeAction(SDK.decodeAction(SDK.hexToBytes(engineSignals.withdraw.action_hex)));
  assert.deepEqual([support.sentence, support.params, support.details.map((detail) => detail.value)], ['act.signalSupport', { from: { type: 'account', id: '0' }, version: { type: 'number', value: '5' } }, [{ type: 'sinceStart', micros: '421000000' }, { type: 'hash', hex: '55'.repeat(32) }]]);
  assert.deepEqual([withdrawal.sentence, withdrawal.params], ['act.signalWithdraw', { from: { type: 'account', id: '2' } }]);
  // What the index says of a signal against what its proven bytes say.
  const signalBytes = SDK.decodeAction(SDK.hexToBytes(engineSignals.support.action_hex));
  const servedSignal = { kind: 80, opaque: false, sender: '0', nonce: signalBytes.nonce, recipient: null, amount: null, reference: null, height: '4', index: 0, payload: { ...signalBytes.payload } };
  assert.deepEqual(compareAction(servedSignal, { action: signalBytes, envelope: null, height: '4', index: 0 }), { read: 'content', differing: [], unconfirmed: [] });
  assert.deepEqual(compareAction({ ...servedSignal, payload: { ...signalBytes.payload, spec: KEY } }, { action: signalBytes, envelope: null, height: '4', index: 0 }).differing, ['payload'], 'a service that names another hash than the bytes hold is contradicted');
  assert.deepEqual(compareAction({ ...servedSignal, payload: {} }, { action: signalBytes, envelope: null, height: '4', index: 0 }).differing, ['payload']);
  // Values that are not what they should be become "unreadable", never text.
  const hostile = '<img src=x onerror=alert(1)>';
  for (const kind of Object.keys(KIND_NAMES).map(Number)) {
    const said = describeAction({ kind, opaque: false, sender: hostile, recipient: hostile, amount: hostile, reference: hostile, request_status: hostile, request_hash: hostile, payload: { to: hostile, amount: hostile, name: hostile, operator: hostile, target: hostile, public_key: hostile, type: hostile, op: { type: hostile, keys: [{ public_key: hostile, role: hostile }, hostile] }, keys: hostile, add: [hostile], remove: [hostile], approvals: [hostile], guardians: [hostile], policy: hostile, daily_limit_micros: hostile, weight: hostile, epoch: hostile, id: hostile, entry: hostile, commission_bps: hostile, consensus_key: hostile } });
    assert(!JSON.stringify(said).includes('onerror'), `kind ${kind}`);
    assert(Object.hasOwn(STRINGS.en, said.sentence), `kind ${kind}: ${said.sentence}`);
  }
  for (const value of [null, undefined, 'x', 5, [], { kind: '3' }, { kind: 3.5 }, { kind: -1 }, { kind: 999 }]) assert.equal(describeAction(value).category, 'unknown');

  // What the index said against what proven bytes say: the SDK's decoder is read the same way.
  const decoded = SDK.decodeAction(SDK.concat(SDK.buildAction({ networkId: 'ab'.repeat(32), kind: 10, from: '7', nonce: '1', authEpoch: '0', publicKey: KEY, payload: { to: '5', amount: '7503250000', reference: REFERENCE } }), new Uint8Array(64)));
  assert.equal(describeAction(decoded).sentence, 'act.shopPayment');
  assert.deepEqual(describeAction(decoded).params.amount, { type: 'amount', micros: '7503250000' });
  const indexed = item(10, { recipient: '5', amount: '7503250000', reference: REFERENCE, transfers: true });
  assert.deepEqual(differences(indexed, decoded), []);
  assert.deepEqual(differences({ ...indexed, amount: '1', recipient: '9', sender: '8', kind: 3, reference: null }, decoded), ['kind', 'sender', 'recipient', 'amount', 'reference']);
  // A completed waiting payment: its recipient and amount are the index's attribution, not in the bytes.
  assert.deepEqual(differences(item(75, { recipient: '5', amount: '9' }), { kind: 75, from: '7', payload: { type: 'execute', id: '1' } }), []);

  // The whole of what the service said against the whole of what was checked.
  const served = (more = {}) => ({ ...indexed, height: '118', index: 0, nonce: '1', auth_epoch: '0', public_key: KEY, payload: { to: '5', amount: '7503250000', reference: REFERENCE }, ...more });
  const proof = (more = {}) => ({ action: decoded, envelope: null, height: '118', index: 0, ...more });
  assert.deepEqual(compareAction(served(), proof()), { read: 'content', differing: [], unconfirmed: [] });
  assert.deepEqual(compareAction(served({ payload: { reference: REFERENCE, amount: '7503250000', to: '5' } }), proof()).differing, [], 'the order of the fields of the content does not matter');
  for (const [change, differing] of [[{ payload: { to: '5', amount: '7503250001', reference: REFERENCE } }, ['payload']], [{ payload: { to: '5', amount: '7503250000', reference: REFERENCE, more: '1' } }, ['payload']], [{ nonce: '2' }, ['nonce']], [{ auth_epoch: '1' }, ['authEpoch']], [{ public_key: '2e'.repeat(32) }, ['publicKey']],
    [{ height: '9' }, ['height']], [{ index: 3 }, ['position']], [{ kind: 3 }, ['kind']], [{ sender: null }, ['sender']], [{ amount: '1', recipient: '9', reference: null }, ['recipient', 'amount', 'reference']], [{ height: '9', index: 1, nonce: '2', payload: {} }, ['height', 'position', 'nonce', 'payload']]])
    assert.deepEqual(compareAction(served(change), proof()).differing, differing, JSON.stringify(change));
  // A position that the check could not fix is not compared; one the service did not state is.
  assert.deepEqual(compareAction(served({ index: 5 }), proof({ index: null })).differing, []);
  assert.deepEqual(compareAction(served({ index: undefined }), proof()).differing, ['position']);
  // Where the service is silent (a list item has no content, key or key generation) nothing differs.
  assert.deepEqual(compareAction({ ...indexed, height: '118', index: 0, nonce: '1' }, proof()), { read: 'content', differing: [], unconfirmed: [] });
  // A completed waiting payment: what the bytes do not carry is unconfirmed, not confirmed and not contradicted.
  const execute = { kind: 75, from: '7', nonce: '1', authEpoch: '0', publicKey: KEY, payload: { type: 'execute', id: '2' } };
  assert.deepEqual(compareAction({ kind: 75, sender: '7', nonce: '1', height: '118', index: 0, recipient: '5', amount: '9', reference: null, payload: { type: 'execute', id: '2' } }, { action: execute, height: '118', index: 0 }), { read: 'content', differing: [], unconfirmed: ['recipient', 'amount'] });
  assert.deepEqual(compareAction({ kind: 75, sender: '7', nonce: '1', height: '118', index: 0, recipient: null, amount: null, payload: { type: 'execute', id: '2' } }, { action: execute, height: '118', index: 0 }).unconfirmed, []);
  // Only the frame could be read (a kind the SDK does not know), or nothing at all.
  const frame = { kind: 23, sender: '7', nonce: '1', authEpoch: '0', publicKey: KEY };
  assert.deepEqual(compareAction({ kind: 23, sender: '7', nonce: '1', height: '118', index: 0, payload: { anything: '1' } }, { action: null, envelope: frame, height: '118', index: 0 }), { read: 'frame', differing: [], unconfirmed: [] });
  assert.deepEqual(compareAction(served(), { action: null, envelope: frame, height: '118', index: 0 }), { read: 'frame', differing: ['kind'], unconfirmed: [] });
  assert.deepEqual(compareAction(served({ height: '7' }), { action: null, envelope: null, height: '118', index: 0 }), { read: 'nothing', differing: ['height'], unconfirmed: [] });
  for (const hostile of [null, undefined, 'x', 5, [], { kind: {} }]) assert.equal(compareAction(hostile, { action: null, envelope: null, height: '1', index: 0 }).read, 'nothing');
  // Proven bytes of a completion are put into words without a recipient or an amount.
  assert.equal(describeAction(execute).sentence, 'act.waitingExecuteBytes');
});

test('the API client: addresses from checked values only, and each kind of failure told apart', async () => {
  const requests = [];
  const answer = (status, body, headers = {}) => ({ ok: status >= 200 && status < 300, status, headers: new Headers(headers), text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) });
  let next = () => answer(200, { ok: true });
  const api = createApi({ origin: 'https://api.example', fetcher: async (url, options) => { requests.push([url, options]); return next(); } });
  await api.status(); await api.blocks({ limit: 50 }); await api.blocks({ limit: 10, cursor: '71' }); await api.block('12'); await api.blockActions('12', { limit: 25, cursor: '12.3' }); await api.blockActions('12', { cursor: null });
  await api.action(HASH.toLowerCase()); await api.account({ id: '7' }); await api.account({ name: '42' }); await api.accountState('7'); await api.activity('7', { limit: 25 }); await api.validators(); await api.blockProof('12'); await api.lightBlock('13');
  assert.deepEqual(requests.map(([url]) => url.replace('https://api.example', '')), ['/v1/status', '/v1/blocks?limit=50', '/v1/blocks?limit=10&cursor=71', '/v1/blocks/12', '/v1/blocks/12/actions?limit=25&cursor=12.3', '/v1/blocks/12/actions',
    `/v1/actions/${HASH}`, '/v1/accounts/7', '/v1/accounts/@42', '/v1/accounts/7/state', '/v1/accounts/7/activity?limit=25', '/v1/validators', '/v1/blocks/12/proof', '/v1/light-blocks/13']);
  for (const [, options] of requests) assert.deepEqual([options.method, options.credentials, options.redirect, options.cache, options.referrerPolicy], ['GET', 'omit', 'error', 'no-store', 'no-referrer']);
  // Nothing that is not in its accepted form reaches an address.
  const before = requests.length;
  const refused = (work) => assert.rejects(async () => work(), (error) => error instanceof ApiFailure && error.kind === 'invalid');
  for (const work of [() => api.block('1/../../x'), () => api.block('0'), () => api.block(12), () => api.blockActions('1?x'), () => api.action('abc'), () => api.account({ id: '07' }), () => api.account({ name: 'A/../b' }), () => api.account({}), () => api.accountState('x'), () => api.activity('7', { cursor: '1&order=asc' }),
    () => api.activity('7', { limit: 500 }), () => api.blocks({ limit: '5' }), () => api.blockProof('#'), () => api.lightBlock('1 ')]) await refused(work);
  assert.equal(requests.length, before);
  assert.equal(api.streamUrl(), 'https://api.example/v1/stream');
  assert.equal(api.streamUrl('120.3'), 'https://api.example/v1/stream?after=120.3');
  assert.equal(api.streamUrl('120&account=7'), 'https://api.example/v1/stream');
  // Failures.
  const failure = async (make) => { next = make; try { await api.status(); } catch (error) { return error; } return null; };
  let error = await failure(() => answer(429, { error: { code: 'rate_limited', message: 'Too many' } }, { 'retry-after': '12' }));
  assert.deepEqual([error.kind, error.status, error.code, error.serverMessage, error.retryAfter], ['http', 429, 'rate_limited', 'Too many', 12]);
  error = await failure(() => answer(503, { error: { code: 'busy', message: 'm' } }));
  assert.deepEqual([error.status, error.retryAfter], [503, 5], 'a wait the page cannot read (another origin) is a short default');
  error = await failure(() => answer(503, { error: {} }, { 'retry-after': '999999' }));
  assert.equal(error.retryAfter, 5);
  error = await failure(() => answer(404, { error: { code: '<script>', message: 5 }, index: { indexed_height: '4' } }));
  assert.deepEqual([error.status, error.code, error.serverMessage, error.retryAfter, error.body.index.indexed_height], [404, null, null, null, '4']);
  error = await failure(() => answer(502, '<html>Bad gateway</html>'));
  assert.deepEqual([error.kind, error.status, error.body], ['http', 502, null]);
  for (const body of ['not json', '[1,2]', 'null', '"text"', '5']) assert.equal((await failure(() => answer(200, body))).kind, 'invalid', body);
  assert.equal((await failure(() => { throw new TypeError('fetch failed'); })).kind, 'network');
  assert.equal((await failure(() => ({ ok: true, status: 200, text: async () => { throw new Error('aborted'); } }))).kind, 'network');
  assert.equal((await createApi({ origin: '', maxBytes: 10, fetcher: async () => answer(200, { long: 'x'.repeat(50) }) }).status().catch((e) => e)).kind, 'invalid');
  // The page's one setting.
  assert.equal(apiOrigin(''), ''); assert.equal(apiOrigin(undefined), ''); assert.equal(apiOrigin('https://api.example'), 'https://api.example'); assert.equal(apiOrigin('http://127.0.0.1:8930'), 'http://127.0.0.1:8930');
  for (const value of ['https://api.example/', 'https://api.example/v1', 'https://user:pw@api.example', 'javascript:alert(1)', 'ftp://api.example', '//api.example', 'api.example', 'https://api.example?x=1', ' https://api.example']) assert.throws(() => apiOrigin(value), /API origin/, value);
});

test('the event stream: reconnects by itself from the last event, after a pause that grows', () => {
  const opened = [], timers = { pending: [], setTimeout: (fn, ms) => { const entry = { fn, ms }; timers.pending.push(entry); return entry; }, clearTimeout: (entry) => { timers.pending = timers.pending.filter((other) => other !== entry); } };
  const source = (url) => { const s = { url, listeners: {}, closed: false, addEventListener: (type, fn) => { s.listeners[type] = fn; }, close: () => { s.closed = true; }, emit: (type, data, lastEventId = '') => s.listeners[type]?.({ data: typeof data === 'string' ? data : JSON.stringify(data), lastEventId }) }; opened.push(s); return s; };
  const api = createApi({ origin: 'https://api.example', fetcher: async () => { throw new Error('unused'); } });
  const events = [], states = [];
  const live = createLive({ api, open: source, timers, pauses: [1000, 4000] });
  live.listen({ onEvent: (event) => events.push(event), onState: (state) => states.push(state) });
  live.start(); live.start();
  assert.equal(opened.length, 1);
  assert.equal(opened[0].url, 'https://api.example/v1/stream');
  opened[0].emit('hello', {});
  opened[0].emit('payment', { hash: 'A' }, '120.0');
  opened[0].emit('block', { height: '120' }, '120');
  opened[0].emit('block', 'not json', '121');
  opened[0].emit('block', '"text"', 'evil&after=1');
  assert.deepEqual(events, [{ type: 'payment', data: { hash: 'A' } }, { type: 'block', data: { height: '120' } }]);
  assert.deepEqual([states, live.state()], [['connecting', 'live'], 'live']);
  // The connection drops: closed, and opened again after the first pause, after the last good event.
  opened[0].emit('error', {});
  assert.deepEqual([opened[0].closed, live.state(), timers.pending.map((entry) => entry.ms)], [true, 'waiting', [1000]]);
  opened[0].emit('block', { height: '999' }, '999');
  assert.equal(events.length, 2, 'a closed source is not listened to');
  timers.pending.shift().fn();
  assert.equal(opened[1].url, 'https://api.example/v1/stream?after=121');
  // Refused again and again (429, 503): the pause grows to its limit and stays there.
  opened[1].emit('error', {}); assert.equal(timers.pending[0].ms, 4000); timers.pending.shift().fn();
  opened[2].emit('error', {}); assert.equal(timers.pending[0].ms, 4000); timers.pending.shift().fn();
  // Back: the count starts over. The server ending the stream ("bye") is not a failure.
  opened[3].emit('hello', {}); opened[3].emit('gap', { from_height: '5' }); opened[3].emit('bye', {});
  assert.deepEqual([events.at(-1), timers.pending[0].ms, opened[3].closed], [{ type: 'gap', data: { from_height: '5' } }, 500, true]);
  timers.pending.shift().fn();
  // A server that keeps ending streams that carried nothing is come back to later and later; one event in between starts the count anew.
  const byePauses = [];
  for (let i = 0; i < 4; i++) { opened.at(-1).emit('hello', {}); opened.at(-1).emit('bye', {}); byePauses.push(timers.pending[0].ms); timers.pending.shift().fn(); }
  assert.deepEqual(byePauses, [1000, 4000, 4000, 4000]);
  opened.at(-1).emit('hello', {}); opened.at(-1).emit('block', { height: '130' }, '130'); opened.at(-1).emit('bye', {});
  assert.equal(timers.pending[0].ms, 500);
  timers.pending.shift().fn();
  opened.at(-1).emit('error', {}); assert.equal(timers.pending[0].ms, 1000);
  // Stopped: nothing is opened any more.
  live.stop();
  const count = opened.length;
  assert.deepEqual([timers.pending.length, live.state()], [0, 'idle']);
  live.start(); assert.equal(opened.length, count + 1);
  // An EventSource that cannot even be made is a failure like any other.
  const broken = createLive({ api, open: () => { throw new Error('blocked'); }, timers, pauses: [1000] });
  broken.start(); assert.equal(broken.state(), 'waiting'); broken.stop();
});
