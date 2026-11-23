// The main page of a test network, web-v4/site. Kept here, not in that folder, so that the folder holds exactly the
// files a static server serves. The functions of app.js run under Node; its DOM part runs only in a page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { checkAddress, plainText, checkDate, readConfig, dateWords, endsWords, timeOfIso, groupDigits, agoWords, statusWords, follow, NOT_ANSWERING, EVERY_MS, KEYS } from '../web-v4/site/app.js';

const folder = new URL('../web-v4/site/', import.meta.url);
const file = name => readFile(new URL(name, folder), 'utf8');

test('an address becomes a link only if it is https:// (or http://127.0.0.1 with a port), without a user name or password', () => {
  assert.equal(checkAddress('https://wallet.example'), 'https://wallet.example/');
  assert.equal(checkAddress('https://api.example/explorer/'), 'https://api.example/explorer/');
  assert.equal(checkAddress('https://wallet.example:8443/x?y=1#z'), 'https://wallet.example:8443/x?y=1#z');
  assert.equal(checkAddress('http://127.0.0.1:8908'), 'http://127.0.0.1:8908/');
  for (const bad of ['http://wallet.example', 'http://127.0.0.1', 'http://localhost:8080', 'http://127.0.0.2:80', 'javascript:alert(1)', 'data:text/html,x', 'ftp://wallet.example', 'https://user:pw@wallet.example', 'https://user@wallet.example', ' https://wallet.example', 'https://wal\nlet.example', 'https://wallet.example\t', '//wallet.example', 'wallet.example', '', 'https://', 5, null, undefined, ['https://wallet.example'], 'https://' + 'a'.repeat(2000)]) assert.equal(checkAddress(bad), null, String(bad));
  // The API is an origin: it becomes `<api>/v1/status` and the page's Content-Security-Policy names it.
  assert.equal(checkAddress('https://api.example', { origin: true }), 'https://api.example');
  assert.equal(checkAddress('https://api.example/', { origin: true }), 'https://api.example');
  assert.equal(checkAddress('http://127.0.0.1:8930', { origin: true }), 'http://127.0.0.1:8930');
  for (const bad of ['https://api.example/v1', 'https://api.example/?x', 'https://api.example/#x', 'http://api.example']) assert.equal(checkAddress(bad, { origin: true }), null, bad);
});

test('the settings file: every value checked, the problems said, the example complete', async () => {
  const example = JSON.parse(await file('site-config.example.json'));
  assert.deepEqual(Object.keys(example), KEYS);
  assert.deepEqual(readConfig(example), { config: { wallet: 'https://wallet.example/', faucet: 'https://faucet.example/', explorer: 'https://api.example/explorer/', blog: 'https://blog.example/', api: 'https://api.example', network_name: 'Time test network', ends: '2026-12-20' }, problems: [] });
  const empty = readConfig({});
  assert.deepEqual(empty.config, Object.fromEntries(KEYS.map(key => [key, null])));
  assert.deepEqual(empty.problems, KEYS.map(key => `"${key}" is not set.`));
  const wrong = readConfig({ ...example, wallet: 'javascript:alert(1)', api: 'https://api.example/v1', network_name: 'a‮b', ends: '2026-02-30', extra: 1 });
  assert.equal(wrong.config.wallet, null); assert.equal(wrong.config.api, null); assert.equal(wrong.config.network_name, null); assert.equal(wrong.config.ends, null); assert.equal(wrong.config.faucet, 'https://faucet.example/');
  assert.deepEqual(wrong.problems, ['"wallet" is not an https:// address.', '"api" is not an https:// origin without a path.', '"network_name" is not a short plain name.', '"ends" is not a date written YYYY-MM-DD.', '"extra" is not a setting of this page.']);
  for (const bad of [null, [], 'x', 5]) assert.deepEqual(readConfig(bad).problems, ['The settings file is not a JSON object.']);
  assert.equal(plainText('  Time test network 2 '), 'Time test network 2'); assert.equal(plainText('x'.repeat(61)), null); assert.equal(plainText('a\u0000b'), null); assert.equal(plainText(''), null);
  assert.equal(checkDate('2026-12-20'), '2026-12-20'); assert.equal(checkDate('2028-02-29'), '2028-02-29');
  for (const bad of ['2026-2-1', '2027-02-29', '2026-13-01', '2026-12-20T00:00:00Z', 20261220]) assert.equal(checkDate(bad), null, String(bad));
  assert.equal(dateWords('2026-12-20'), '20 December 2026');
  assert.equal(endsWords('2026-12-20', Date.UTC(2026, 10, 20)), 'This test network ends on 20 December 2026.');
  assert.equal(endsWords('2026-12-20', Date.UTC(2026, 11, 20, 23, 59)), 'This test network ends on 20 December 2026.');
  assert.equal(endsWords('2026-12-20', Date.UTC(2026, 11, 21)), 'This test network ended on 20 December 2026.');
  assert.equal(endsWords(null), 'The end date of this test network is not set on this page.');
});

test('an answer of /v1/status becomes the newest block and its time, and what is wrong is said', () => {
  const now = Date.UTC(2026, 10, 20, 14, 5, 16, 500);
  // The shape client-v4/api.mjs answers (GET /v1/status).
  const answer = (indexer) => ({ api: 'v1', service_started_at: '2026-11-20T10:00:00.000Z', network: { network_id: 'ab'.repeat(32), chain_id: 'time-devnet-v4-test', protocol_version: '4' }, indexer, limits: {}, notice: 'x' });
  const fresh = { start_height: '1', indexed_height: '1234567', indexed_block_time: '2026-11-20T14:05:12.123456Z', seconds_behind: 4, tip_height_reported: '1234567' };
  assert.deepEqual(statusWords(answer(fresh), { now, timeZone: 'UTC' }), { ok: true, headline: 'Newest block: 1,234,567', detail: 'Made at 14:05:12, 4 seconds ago.' });
  assert.deepEqual(statusWords(answer({ ...fresh, indexed_block_time: '2026-11-20T14:01:00Z' }), { now, timeZone: 'UTC' }), { ok: false, headline: 'Newest block: 1,234,567', detail: 'Made at 14:01:00, 4 minutes ago. No new block for more than two minutes: the network may have stopped.' });
  assert.equal(statusWords(answer({ ...fresh, indexed_block_time: '2026-11-18T09:00:00Z' }), { now, timeZone: 'UTC' }).detail, 'Made at 18 November 2026 at 09:00:00, 2 days ago. No new block for more than two minutes: the network may have stopped.');
  assert.equal(statusWords(answer(fresh), { now, timeZone: 'Asia/Tokyo' }).detail, 'Made at 23:05:12, 4 seconds ago.');
  assert.deepEqual(statusWords(answer({ ...fresh, indexed_block_time: null }), { now }), { ok: true, headline: 'Newest block: 1,234,567', detail: '' });
  assert.deepEqual(statusWords(answer({ ...fresh, indexed_height: null, indexed_block_time: null }), { now }), { ok: true, headline: 'No block yet.', detail: 'The network\'s service has not recorded a block yet.' });
  for (const bad of [null, 'x', {}, answer(null), answer({ ...fresh, indexed_height: 12 }), answer({ ...fresh, indexed_height: '<b>1</b>' }), answer({ ...fresh, indexed_height: '01' })]) assert.deepEqual(statusWords(bad, { now }), { ok: false, headline: 'The network\'s answer could not be read.', detail: 'This page asks again every 10 seconds.' });
  assert.deepEqual(NOT_ANSWERING, { ok: false, headline: 'The network is not answering.', detail: 'This page asks again every 10 seconds.' });
  assert.equal(timeOfIso('2026-11-20T14:05:12Z'), Date.UTC(2026, 10, 20, 14, 5, 12)); assert.equal(timeOfIso('2026-11-20T14:05:12.5Z'), Date.UTC(2026, 10, 20, 14, 5, 12, 500));
  for (const bad of ['2026-11-20T24:00:00Z', '2026-02-30T00:00:00Z', '2026-11-20 14:05:12Z', '2026-11-20T14:05:12+01:00', 5]) assert.equal(timeOfIso(bad), null, String(bad));
  assert.equal(groupDigits('1234567'), '1,234,567'); assert.equal(groupDigits('999'), '999');
  assert.deepEqual([500, 1000, 59999, 60000, 7200000, 172800000].map(agoWords), ['just now', '1 second ago', '59 seconds ago', '1 minute ago', '2 hours ago', '2 days ago']);
});

test('the live figures are asked at most every 10 seconds, and not while the page is hidden', async () => {
  let clock = 1000000; const timers = [], asked = [], shown = [], listeners = {};
  const doc = { hidden: false, addEventListener: (type, listener) => { listeners[type] = listener; } };
  const later = (fn, ms) => { const timer = { fn, at: clock + ms }; timers.push(timer); return timer; };
  const cancel = timer => { const i = timers.indexOf(timer); if (i >= 0) timers.splice(i, 1); };
  let failing = false;
  const fetch = async (url, options) => { asked.push({ url, at: clock, credentials: options.credentials }); if (failing) throw new TypeError('Failed to fetch'); return { ok: true, json: async () => ({ indexer: { indexed_height: String(asked.length), indexed_block_time: null } }) }; };
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const run = async until => { for (;;) { timers.sort((a, b) => a.at - b.at); const next = timers[0]; if (!next || next.at > until) break; timers.shift(); clock = next.at; next.fn(); await settle(); await settle(); } clock = until; };
  follow('https://api.example', { doc, fetch, show: words => shown.push(words.headline), now: () => clock, later, cancel });
  await run(clock);
  assert.deepEqual(asked.map(a => a.url), ['https://api.example/v1/status']); assert.equal(asked[0].credentials, 'omit');
  await run(clock + 35000);
  assert.deepEqual(asked.map(a => a.at - 1000000), [0, 10000, 20000, 30000]);
  // Hidden: nothing is asked; shown again after 25 s: asked at once, then every 10 s.
  doc.hidden = true; listeners.visibilitychange(); await run(clock + 60000);
  assert.equal(asked.length, 4); assert.equal(timers.length, 0);
  doc.hidden = false; listeners.visibilitychange(); await run(clock);
  assert.equal(asked.length, 5); assert.equal(asked[4].at - 1000000, 95000);
  // Shown, hidden and shown again within the 10 seconds: no question before they have passed.
  clock += 3000; doc.hidden = true; listeners.visibilitychange(); doc.hidden = false; listeners.visibilitychange(); listeners.visibilitychange();
  await run(clock + 20000);
  const gaps = asked.slice(1).map((a, i) => a.at - asked[i].at);
  assert(gaps.every(gap => gap >= EVERY_MS), String(gaps)); assert.equal(asked.at(-1).at - asked.at(-2).at, EVERY_MS);
  assert.equal(timers.length, 1, 'one question waits at a time');
  failing = true; await run(clock + EVERY_MS);
  assert.equal(shown.at(-1), 'The network is not answering.'); assert.equal(shown[0], 'Newest block: 1');
});

test('the page: exactly its files, nothing loaded from outside its folder, no inline script or style, and the words it must say', async () => {
  assert.deepEqual((await readdir(folder)).sort(), ['app.js', 'index.html', 'site-config.example.json', 'styles.css']);
  const html = await file('index.html'), script = await file('app.js'), styles = await file('styles.css');
  const references = [...html.matchAll(/\s(?:src|href)="([^"]*)"/g)].map(match => match[1]);
  // Besides its own two files, the menu of the public networks that every page carries: the proxy hands it out by
  // that name from web-v4/shared (testnet/services.mjs), not from this folder.
  assert.deepEqual(references.sort(), ['app.js', 'styles.css', 'web-v4/shared/network-menu.js']);
  assert(!/<script(?![^>]*\ssrc=)[^>]*>|<style|\sstyle=|\son[a-z]+=|javascript:|<iframe|<img|<form/i.test(html), 'no inline script, style, handler, frame, image or form');
  assert.match(html, /<script type="module" src="app.js"><\/script>/);
  // The script imports nothing, writes no markup, and asks only its own settings file and the configured API.
  assert(!/^\s*import\s|\bimport\(|innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/m.test(script));
  const literals = [...script.matchAll(/'[^'\n]*'|"[^"\n]*"|`[^`]*`/g)].map(match => match[0]);
  assert.deepEqual(literals.filter(text => /https?:\/\/\w|\/\/[\w-]+\.[\w-]/.test(text)), [], 'no address of another site in the script');
  assert.deepEqual([...script.matchAll(/fetch\(([^,)]+)/g)].map(match => match[1]), ["`${api}/v1/status`", "'site-config.json'"]);
  assert(!/url\(|@import|https?:\/\//.test(styles));
  for (const words of ['Test network.', 'have no value', 'may be reset at any time', 'has not had its outside audit', 'Create your account', 'Get test time', 'Send some to a friend', 'Sign in to the demo blog', 'Your keys in one minute', 'The backup file', 'Protect my account', 'recovery sheet', 'recovery passphrase', 'Look up any account or payment, and check it in your own browser.', 'one for the whole network and not one per person']) assert(html.includes(words), words);
  // The four steps, the wallet's explanation of keys, the explorer.
  assert.equal((html.match(/data-link="/g) || []).length, 6);
  for (const key of html.matchAll(/data-link="([^"]+)"/g)) assert(['wallet', 'faucet', 'explorer', 'blog'].includes(key[1]), key[1]);
  assert(!/Seconds devnet|LOCAL DEVNET|laboratory|\bLAB\b|devnet/i.test(html + script), 'old names');
});
