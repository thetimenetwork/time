// The main page of a test network, web-v4/site. Kept here, not in that folder, so that the folder holds exactly the
// files a static server serves. The functions of app.js run under Node; its DOM part runs only in a page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { checkAddress, plainText, checkDate, readConfig, dateWords, endsWords, timeOfIso, groupDigits, agoWords, statusWords, follow, NOT_ANSWERING, EVERY_MS, KEYS, REQUIRED_KEYS, APP_KEYS, derivedLinks, statsView, secondsText, durationWords, clockText, shareText } from '../web-v4/site/app.js';

const LINK_KEYS_OF_PAGE = ['wallet', 'faucet', 'explorer', 'blog'];
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
  assert.deepEqual(readConfig(example), { config: { wallet: 'https://wallet.example/', faucet: 'https://faucet.example/', explorer: 'https://api.example/explorer/', blog: 'https://blog.example/', api: 'https://api.example', network_name: 'Time test network', ends: '2026-12-20', hardware: 'https://hardware.example/', source: 'https://source.example/time', chat: 'https://chat.example/' }, problems: [] });
  const empty = readConfig({});
  assert.deepEqual(empty.config, Object.fromEntries(KEYS.map(key => [key, null])));
  // An app's address may be left out: its card is not shown, and nothing is said.
  assert.deepEqual(empty.problems, REQUIRED_KEYS.map(key => `"${key}" is not set.`));
  assert.deepEqual(KEYS, [...REQUIRED_KEYS, ...APP_KEYS]);
  assert.deepEqual(readConfig({ ...example, chat: 'http://chat.example' }).problems, ['"chat" is not an https:// address.']);
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
  // The settings, and the API's two routes (follow: `${api}${path}`, path /v1/status or /v1/stats).
  assert.deepEqual([...script.matchAll(/fetch\(([^,)]+)/g)].map(match => match[1]), ["`${api}${path}`", "'site-config.json'"]);
  assert.deepEqual([...script.matchAll(/path(?: =|:) '([^']+)'/g)].map(match => match[1]).sort(), ['/v1/stats', '/v1/status']);
  assert(!/url\(|@import|https?:\/\//.test(styles));
  for (const words of ['Test network.', 'have no value', 'may be reset at any time', 'has not had its outside audit', 'Create your account', 'Get test time', 'Send some to a friend', 'Sign in to the demo blog', 'Your keys in one minute', 'The backup file', 'Protect my account', 'five recovery words', 'written by hand on paper', 'Look up any account or payment, and check it in your own browser.', 'one for the whole network and not one per person', 'Seconds in existence', 'Who holds time', 'Every person\'s account is shown as Anonymous.', 'its word, not a proof', 'Apps']) assert(html.includes(words), words);
  // The four steps, the wallet's explanation of keys, and the ten apps. An app the network may not have (data-app-of)
  // is hidden by the script when its address is not set; the network's own pages are always offered.
  assert.equal((html.match(/data-link="/g) || []).length, 15);
  const derived = Object.keys(derivedLinks({}));
  for (const key of html.matchAll(/data-link="([^"]+)"/g)) assert([...LINK_KEYS_OF_PAGE, ...APP_KEYS, ...derived].includes(key[1]), key[1]);
  for (const card of html.matchAll(/data-app-of="([^"]+)"/g)) assert(APP_KEYS.includes(card[1]), card[1]);
  // Every app card is one link, with its name and its sentence; the icons are drawn inline, not loaded.
  assert.equal((html.match(/class="app"/g) || []).length, 10);
  assert.equal((html.match(/class="app-about"/g) || []).length, 10);
  assert(!/Seconds devnet|LOCAL DEVNET|laboratory|\bLAB\b|devnet/i.test(html + script), 'old names');
});

test('the links made from the settings, and amounts, lengths and shares in words', () => {
  assert.deepEqual(derivedLinks({ explorer: 'https://explorer.example/explorer/', wallet: 'https://wallet.example/', source: 'https://source.example/time' }), {
    validators: 'https://explorer.example/explorer/#/validators', device: 'https://wallet.example/device-check.html', developers: 'https://source.example/time/blob/main/docs/integration-guide.md' });
  assert.deepEqual(derivedLinks({}), { validators: null, device: null, developers: null });
  assert.deepEqual([0n, 999n, 1000n, 44000n, 300000n, 59963000n, 999999499n, 999999500n, 11653445000000n, null, -1n].map(secondsText),
    ['0', 'less than 0.001', '0.001', '0.044', '0.3', '59.963', '999.999', '1,000', '11,653,445', '–', '–']);
  assert.deepEqual([0, 59000, 3600000, 3661000, 203472000, 86400000 * 400].map(durationWords), ['0 seconds', '59 seconds', '1 hour', '1 hour 1 minute', '2 days 8 hours 31 minutes', '400 days']);
  assert.deepEqual([5000, 3725000, 86400000 + 61000, 2 * 86400000 + 30672000].map(clockText), ['00:00:05', '01:02:05', '1 day 00:01:01', '2 days 08:31:12']);
  assert.deepEqual([[0n, 10n], [1n, 3n], [1n, 20000n], [5n, 10n], [1n, 0n], [null, 1n]].map(([a, b]) => shareText(a, b)), ['0%', '33.3%', 'less than 0.1%', '50.0%', '–', '–']);
});

test('an answer of /v1/stats becomes the figures, and nothing malformed reaches the page', () => {
  // The shape client-v4/api.mjs answers (GET /v1/stats, openapi.json Stats).
  const answer = {
    chain: { source: 'state_proof', state_height: '248120', state_time_micros: String(1795800000000000n), genesis_time_micros: String(1795800000000000n - 203_472_000_000n), elapsed_micros: String(203_472_000_000n),
      supply_micros: String(203_472_000_000n), supply_equals_elapsed: true, supply_parts_micros: { in_accounts: '62000000000', staked: String(141_107_000_000n), not_yet_paid: '365000000', auction_reserve: '0' }, accounts: '85', validators: 5 },
    activity: { source: 'index', proven: false, blocks: 248120, actions: 3812, payments: 1204, moved_micros: '52310500000', last_24_hours: { blocks: 100000, actions: 456, payments: 1, moved_micros: '1234000000' },
      days: [{ day: '2026-11-25', blocks: 1, actions: 2, payments: 3, moved_micros: '4000000' }, { day: '2026-02-30', blocks: 1, actions: 1, payments: 1, moved_micros: '1' }, { day: '2026-11-26', blocks: 1, actions: 5, payments: 0, moved_micros: '0' }],
      block_interval_ms: 860 },
    holders: { source: 'state_proof', from_height: '248000', to_height: '248010', read_at: '2026-11-27T17:30:00.123Z', every_seconds: 300, accounts_read: 85, complete: true, holding: 41, held_micros: '62000000000',
      top: [{ rank: 1, anonymous: false, account: '66', name: 'faucet', balance_micros: '12000000000', staked_micros: '0' }, { rank: 2, anonymous: true, account: null, name: null, balance_micros: '60000000', staked_micros: '0' },
        { rank: 3, anonymous: false, account: '7', name: '<b>x</b>‮', balance_micros: '1', staked_micros: '0' }] },
  };
  const view = statsView(answer);
  assert.equal(view.chain.figure, '203,472');
  assert.equal(view.chain.words, '2 days 8 hours 31 minutes of chain time, at block 248,120.');
  assert.match(view.chain.check, /^Equal to the time the chain has run/);
  assert.deepEqual(view.chain.parts.map(p => [p.name, p.text, p.share]), [['On accounts', '62,000 s', '30.5%'], ['Staked in pools', '141,107 s', '69.3%'], ['Not yet paid out', '365 s', '0.2%']]);
  assert.equal(view.chain.since, 'Since 25 November 2026, 08:48 UTC');
  assert.equal(view.chain.genesisMs, Number((1795800000000000n - 203_472_000_000n) / 1000n));
  assert.deepEqual([view.chain.accounts, view.chain.validators], ['85', 5]);
  assert.deepEqual([view.activity.actions, view.activity.payments, view.activity.moved, view.activity.pace], ['3,812', '1,204 payments among them', '52,311 s', 'A block every 0.86 s']);
  assert.deepEqual(view.activity.day, { payments: '1 payment', detail: '1,234 s moved, 456 actions' });
  // A day that does not exist is left out.
  assert.deepEqual(view.activity.days.map(d => [d.day, d.label, d.payments, d.moved]), [['2026-11-25', '25 November 2026', 3, '4 s'], ['2026-11-26', '26 November 2026', 0, '0 s']]);
  assert.equal(view.holders.holding, '41 accounts hold time');
  assert.equal(view.holders.summary, '41 accounts hold 62,000 s between them.');
  assert.equal(view.holders.when, 'Counted account by account between blocks 248,000 and 248,010, at 27 November 2026, 17:30 UTC, again every 5 minutes.');
  // A name the server says is the network's own is shown only if it is plain text; anything else is anonymous.
  assert.deepEqual(view.holders.rows.map(r => [r.rank, r.name, r.anonymous, r.held, r.share]), [['1', 'faucet', false, '12,000 s', '5.9%'], ['2', null, true, '60 s', 'less than 0.1%'], ['3', null, true, 'less than 0.001 s', 'less than 0.1%']]);
  // Each part on its own: a broken part is null, the others stand.
  const broken = statsView({ ...answer, chain: { ...answer.chain, supply_micros: '1e9' }, holders: { ...answer.holders, top: 'x' } });
  assert.equal(broken.chain, null); assert.equal(broken.holders, null); assert.equal(broken.activity.actions, '3,812');
  assert.equal(statsView({ ...answer, chain: { ...answer.chain, supply_equals_elapsed: false } }).chain.check, null);
  for (const bad of [null, 'x', 5, [], {}]) assert.deepEqual(statsView(bad), { chain: null, activity: null, holders: null });
  assert.deepEqual(statsView({ activity: { ...answer.activity, actions: -1 } }).activity, null);
});
