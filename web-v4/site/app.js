// The main page of a Time test network. It reads site-config.json from its own folder, checks every value before
// it becomes a link, and shows the newest block as the network's API reports it. Nothing read from the settings or
// the API is put into the page as markup: only textContent and the href of a link that passed checkAddress.
// The functions above the line `if (typeof document ...)` run under Node too (client-v4/site-page.test.mjs).

export const LINK_KEYS = Object.freeze(['wallet', 'faucet', 'explorer', 'blog']);
export const KEYS = Object.freeze([...LINK_KEYS, 'api', 'network_name', 'ends']);
export const EVERY_MS = 10000;
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const UNSAFE = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/;

/// An address this page may link to or ask: https:// with a host name and no user name or password, or, for tests,
/// http://127.0.0.1 with a port. With `origin`, an origin only (no path, query or fragment), returned without a slash.
/// Anything else is null.
export function checkAddress(value, { origin = false } = {}) {
  if (typeof value !== 'string' || value.length > 2000 || /[\s\u0000-\u001F\u007F]/.test(value)) return null;
  let url; try { url = new URL(value); } catch { return null; }
  if (url.username || url.password) return null;
  const secure = url.protocol === 'https:' && url.hostname !== '', loopback = url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port !== '';
  if (!secure && !loopback) return null;
  if (origin) return url.pathname === '/' && !url.search && !url.hash ? url.origin : null;
  return url.href;
}
/// A short plain text (the network's name): 1 to `max` characters, no control or direction characters; else null.
export function plainText(value, max = 60) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text && [...text].length <= max && !UNSAFE.test(text) && text.isWellFormed() ? text : null;
}
/// A calendar date written YYYY-MM-DD that exists; else null.
export function checkDate(value) {
  const match = typeof value === 'string' && /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return null;
  const [year, month, day] = match.slice(1).map(Number), date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day ? value : null;
}
/// What the page takes from site-config.json: each value checked, null where it is missing or wrong, and the
/// problems in words for the person who runs the site.
export function readConfig(value) {
  const config = Object.fromEntries(KEYS.map(key => [key, null])), problems = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { config, problems: ['The settings file is not a JSON object.'] };
  const say = (key, wrong) => problems.push(value[key] === undefined ? `"${key}" is not set.` : `"${key}" ${wrong}.`);
  for (const key of LINK_KEYS) if ((config[key] = checkAddress(value[key])) === null) say(key, 'is not an https:// address');
  if ((config.api = checkAddress(value.api, { origin: true })) === null) say('api', 'is not an https:// origin without a path');
  if ((config.network_name = plainText(value.network_name)) === null) say('network_name', 'is not a short plain name');
  if ((config.ends = checkDate(value.ends)) === null) say('ends', 'is not a date written YYYY-MM-DD');
  for (const key of Object.keys(value)) if (!KEYS.includes(key)) problems.push(`"${plainText(key, 40) ?? '?'}" is not a setting of this page.`);
  return { config, problems };
}
/// "2026-12-20" -> "20 December 2026".
export const dateWords = iso => { const [year, month, day] = iso.split('-').map(Number); return `${day} ${MONTHS[month - 1]} ${year}`; };
/// The last line of the test-network box. The network ends at the end of that day, UTC.
export function endsWords(iso, now = Date.now()) {
  if (iso === null) return 'The end date of this test network is not set on this page.';
  const [year, month, day] = iso.split('-').map(Number);
  return now >= Date.UTC(year, month - 1, day + 1) ? `This test network ended on ${dateWords(iso)}.` : `This test network ends on ${dateWords(iso)}.`;
}
/// The time of an ISO 8601 UTC time with up to nine digits of a second, in milliseconds; else null.
export function timeOfIso(value) {
  const match = typeof value === 'string' && /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number), time = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(time);
  if (date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) return null;
  return time + Number((match[7] ?? '').padEnd(3, '0').slice(0, 3));
}
export const groupDigits = digits => digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
export function agoWords(ms) {
  const plural = (n, unit) => `${n} ${unit}${n === 1 ? '' : 's'} ago`;
  if (ms < 1000) return 'just now';
  if (ms < 60000) return plural(Math.floor(ms / 1000), 'second');
  if (ms < 3600000) return plural(Math.floor(ms / 60000), 'minute');
  if (ms < 172800000) return plural(Math.floor(ms / 3600000), 'hour');
  return plural(Math.floor(ms / 86400000), 'day');
}
export const NOT_ANSWERING = Object.freeze({ ok: false, headline: 'The network is not answering.', detail: `This page asks again every ${EVERY_MS / 1000} seconds.` });
/// The words shown for an answer of GET <api>/v1/status (client-v4/api/openapi.json, Status): the newest block the
/// API has indexed and when it was made. `timeZone` is the reader's (undefined) in the page and fixed in tests.
export function statusWords(body, { now = Date.now(), timeZone } = {}) {
  const indexer = body && typeof body === 'object' ? body.indexer : null;
  if (!indexer || typeof indexer !== 'object') return { ok: false, headline: 'The network\'s answer could not be read.', detail: NOT_ANSWERING.detail };
  if (indexer.indexed_height === null) return { ok: true, headline: 'No block yet.', detail: 'The network\'s service has not recorded a block yet.' };
  if (typeof indexer.indexed_height !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(indexer.indexed_height)) return { ok: false, headline: 'The network\'s answer could not be read.', detail: NOT_ANSWERING.detail };
  const headline = `Newest block: ${groupDigits(indexer.indexed_height)}`, made = timeOfIso(indexer.indexed_block_time);
  if (made === null) return { ok: true, headline, detail: '' };
  const age = Math.max(0, now - made), long = age >= 43200000;
  const at = new Intl.DateTimeFormat('en-GB', { timeZone, hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', ...(long ? { day: 'numeric', month: 'long', year: 'numeric' } : {}) }).format(made);
  const stopped = age > 120000 ? ' No new block for more than two minutes: the network may have stopped.' : '';
  return { ok: stopped === '', headline, detail: `Made at ${at}, ${agoWords(age)}.${stopped}` };
}

/// The live figures: asks `<api>/v1/status` at once, then EVERY_MS after the previous question, never more often and
/// never while the page is hidden; a page shown again is asked as soon as EVERY_MS has passed since the last question.
/// Every answer goes to `show` as statusWords, and every failure as NOT_ANSWERING.
export function follow(api, { doc, fetch, show, now = Date.now, later = setTimeout, cancel = clearTimeout, timeZone }) {
  let timer = null, last = -Infinity, asking = false;
  const schedule = () => { cancel(timer); timer = null; if (!doc.hidden && !asking) timer = later(ask, Math.max(0, last + EVERY_MS - now())); };
  async function ask() {
    timer = null;
    if (asking || doc.hidden) return;
    asking = true; last = now();
    try {
      const response = await fetch(`${api}/v1/status`, { cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(8000) });
      if (!response.ok) throw new Error(String(response.status));
      show(statusWords(await response.json(), { now: now(), timeZone }));
    } catch { show(NOT_ANSWERING); } finally { asking = false; schedule(); }
  }
  doc.addEventListener('visibilitychange', schedule);
  schedule();
}

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  const note = text => { $('config-note').textContent = text; $('config-note').hidden = false; };
  const live = words => { $('live-headline').textContent = words.headline; $('live-detail').textContent = words.detail; $('live-headline').classList.toggle('bad', !words.ok); };
  (async () => {
    let read = null;
    try {
      const response = await fetch('site-config.json', { cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
      if (response.status === 404) throw Object.assign(new Error('missing'), { missing: true });
      if (!response.ok) throw new Error(String(response.status));
      read = readConfig(await response.json());
    } catch (error) {
      note(error.missing ? 'This page has no settings file yet (site-config.json), so its buttons lead nowhere. If you run this site, copy site-config.example.json to site-config.json and fill it in.' : 'The settings file of this page (site-config.json) could not be read, so its buttons lead nowhere.');
      read = readConfig({});
    }
    const { config, problems } = read;
    if (problems.length && !$('config-note').textContent) note(`Some parts of this page are not set: ${problems.join(' ')}`);
    for (const link of document.querySelectorAll('[data-link]')) {
      const address = config[link.dataset.link];
      if (address) { link.href = address; link.removeAttribute('aria-disabled'); } else { link.removeAttribute('href'); link.setAttribute('aria-disabled', 'true'); }
    }
    $('ends').textContent = endsWords(config.ends);
    if (config.network_name) { $('network-name').textContent = `Network: ${config.network_name}`; $('network-name').hidden = false; }
    if (config.api) follow(config.api, { doc: document, fetch: globalThis.fetch.bind(globalThis), show: live }); else live({ ok: false, headline: 'The address of the network\'s service is not set on this page.', detail: '' });
  })();
}
