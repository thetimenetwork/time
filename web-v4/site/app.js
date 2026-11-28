// The main page of a Time test network. It reads site-config.json from its own folder, checks every value before
// it becomes a link, and shows the network in figures as the network's API reports them. Nothing read from the
// settings or the API is put into the page as markup: only textContent, attributes of elements it makes itself, and
// the href of a link that passed checkAddress.
// The functions above the line `if (typeof document ...)` run under Node too (client-v4/site-page.test.mjs).

export const LINK_KEYS = Object.freeze(['wallet', 'faucet', 'explorer', 'blog']);
/// Apps of the project that a network may not have: each card is shown only when its address is set.
/// `test_bitcoin` is set on a network that has the market of seconds against bitcoin: the address of the page that
/// hands out its play bitcoin. The market's own card is shown with it and leads to the wallet, where the market is.
export const APP_KEYS = Object.freeze(['hardware', 'source', 'chat', 'test_bitcoin']);
export const REQUIRED_KEYS = Object.freeze([...LINK_KEYS, 'api', 'network_name', 'ends']);
export const KEYS = Object.freeze([...REQUIRED_KEYS, ...APP_KEYS]);
export const EVERY_MS = 10000;
/// How often the figures (GET /v1/stats) are asked: each answer is a read of the state with a proof.
export const STATS_EVERY_MS = 30000;
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const UNSAFE = /[\u0000-\u001F\u007F-\u009F‪-‮⁦-⁩]/;

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
/// problems in words for the person who runs the site. An app's address may be left out (its card is not shown).
export function readConfig(value) {
  const config = Object.fromEntries(KEYS.map(key => [key, null])), problems = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { config, problems: ['The settings file is not a JSON object.'] };
  const say = (key, wrong) => problems.push(value[key] === undefined ? `"${key}" is not set.` : `"${key}" ${wrong}.`);
  for (const key of LINK_KEYS) if ((config[key] = checkAddress(value[key])) === null) say(key, 'is not an https:// address');
  if ((config.api = checkAddress(value.api, { origin: true })) === null) say('api', 'is not an https:// origin without a path');
  if ((config.network_name = plainText(value.network_name)) === null) say('network_name', 'is not a short plain name');
  if ((config.ends = checkDate(value.ends)) === null) say('ends', 'is not a date written YYYY-MM-DD');
  for (const key of APP_KEYS) if (value[key] !== undefined && (config[key] = checkAddress(value[key])) === null) say(key, 'is not an https:// address');
  for (const key of Object.keys(value)) if (!KEYS.includes(key)) problems.push(`"${plainText(key, 40) ?? '?'}" is not a setting of this page.`);
  return { config, problems };
}
/// The links made from the settings: the explorer's Validators page, the wallet's "Check this device" page, the
/// guide for developers in the source, and the market (in the wallet, on a network that has it). Null where the
/// setting they come from is not set.
export function derivedLinks(config) {
  return {
    validators: config.explorer ? new URL('#/validators', config.explorer).href : null,
    device: config.wallet ? new URL('device-check.html', config.wallet).href : null,
    developers: config.source ? `${config.source.replace(/\/+$/, '')}/blob/main/docs/integration-guide.md` : null,
    market: config.test_bitcoin && config.wallet ? config.wallet : null,
  };
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

// ------------------------------------------------------------------ the network in figures
const WHOLE = /^(0|[1-9][0-9]{0,24})$/;
/// A whole number of the API's answer (a decimal string): a BigInt, else null.
export const wholeOf = value => (typeof value === 'string' && WHOLE.test(value) ? BigInt(value) : null);
/// Micros as seconds in words: grouped whole seconds from 1,000 s up; below, up to three decimals; a tiny amount
/// that is not nothing is "less than 0.001". Never rounds to a value it is not near: 999.9996 s is "1,000".
export function secondsText(micros) {
  if (micros === null || micros < 0n) return '–';
  if (micros >= 999_999_500n) return groupDigits(((micros + 500_000n) / 1_000_000n).toString());
  if (micros > 0n && micros < 1000n) return 'less than 0.001';
  const thousandths = (micros + 500n) / 1000n, whole = thousandths / 1000n, rest = (thousandths % 1000n).toString().padStart(3, '0').replace(/0+$/, '');
  return `${groupDigits(whole.toString())}${rest ? `.${rest}` : ''}`;
}
/// A length of time in words, largest units first: "2 days 8 hours 31 minutes"; seconds are named below an hour.
export function durationWords(ms) {
  const seconds = Math.max(0, Math.floor(ms / 1000)), units = [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]], out = [];
  let left = seconds;
  for (const [name, size] of units) {
    const n = Math.floor(left / size); left -= n * size;
    if (name === 'second' && seconds >= 3600) continue;
    if (n > 0) out.push(`${n} ${name}${n === 1 ? '' : 's'}`);
  }
  return out.length ? out.join(' ') : '0 seconds';
}
/// The running clock: "2 days 08:31:12".
export function clockText(ms) {
  const seconds = Math.max(0, Math.floor(ms / 1000)), days = Math.floor(seconds / 86400), two = n => String(n).padStart(2, '0');
  const hms = `${two(Math.floor(seconds % 86400 / 3600))}:${two(Math.floor(seconds % 3600 / 60))}:${two(seconds % 60)}`;
  return days > 0 ? `${days} day${days === 1 ? '' : 's'} ${hms}` : hms;
}
/// A share in percent with one decimal: "12.3%", "less than 0.1%", "0%".
export function shareText(part, whole) {
  if (part === null || whole === null || whole <= 0n) return '–';
  if (part === 0n) return '0%';
  const tenths = (part * 1000n + whole / 2n) / whole;
  return tenths === 0n ? 'less than 0.1%' : `${tenths / 10n}.${tenths % 10n}%`;
}
const count = (n, one, many = `${one}s`) => `${groupDigits(String(n))} ${n === 1 ? one : many}`;
const utcWords = ms => { const d = new Date(ms); return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')} UTC`; };
const integer = value => (Number.isSafeInteger(value) && value >= 0 ? value : null);
const SPLIT = [['in_accounts', 'On accounts'], ['staked', 'Staked in pools'], ['not_yet_paid', 'Not yet paid out'], ['auction_reserve', 'Auction reserve']];
/// What the page shows of an answer of GET <api>/v1/stats (client-v4/api/openapi.json, Stats), as words and numbers.
/// Every value is checked; what is missing or malformed is null, and its part of the page says so or keeps quiet.
export function statsView(body) {
  const view = { chain: null, activity: null, holders: null };
  if (!body || typeof body !== 'object') return view;
  const c = body.chain;
  if (c && typeof c === 'object') {
    const supply = wholeOf(c.supply_micros), elapsed = wholeOf(c.elapsed_micros), genesis = wholeOf(c.genesis_time_micros), height = wholeOf(c.state_height);
    const parts = SPLIT.map(([key, name]) => ({ key, name, micros: wholeOf(c.supply_parts_micros?.[key]) }));
    if (supply !== null && elapsed !== null && genesis !== null && height !== null && parts.every(p => p.micros !== null)) {
      const accounts = wholeOf(c.accounts);
      view.chain = {
        supply, figure: secondsText(supply), genesisMs: Number(genesis / 1000n), height: groupDigits(height.toString()),
        words: `${durationWords(Number(elapsed / 1000n))} of chain time, at block ${groupDigits(height.toString())}.`,
        check: c.supply_equals_elapsed === true ? 'Equal to the time the chain has run: the chain\'s own counters, read with a proof.' : null,
        parts: parts.filter(p => p.micros > 0n || p.key !== 'auction_reserve').map(p => ({ ...p, text: `${secondsText(p.micros)} s`, share: shareText(p.micros, supply) })),
        since: `Since ${utcWords(Number(genesis / 1000n))}`,
        accounts: accounts === null ? null : groupDigits(accounts.toString()), validators: integer(c.validators),
      };
    }
  }
  const a = body.activity;
  if (a && typeof a === 'object' && [a.blocks, a.actions, a.payments].every(n => integer(n) !== null) && wholeOf(a.moved_micros) !== null) {
    const day = a.last_24_hours && typeof a.last_24_hours === 'object' && integer(a.last_24_hours.payments) !== null && integer(a.last_24_hours.actions) !== null && wholeOf(a.last_24_hours.moved_micros) !== null ? a.last_24_hours : null;
    const days = Array.isArray(a.days) ? a.days.filter(d => d && /^\d{4}-\d{2}-\d{2}$/.test(d.day ?? '') && checkDate(d.day) && integer(d.payments) !== null && integer(d.actions) !== null && wholeOf(d.moved_micros) !== null).slice(-30) : [];
    const pace = integer(a.block_interval_ms);
    view.activity = {
      actions: groupDigits(String(a.actions)), payments: `${count(a.payments, 'payment')} among them`, moved: `${secondsText(wholeOf(a.moved_micros))} s`,
      day: day ? { payments: count(day.payments, 'payment'), detail: `${secondsText(wholeOf(day.moved_micros))} s moved, ${count(day.actions, 'action')}` } : null,
      pace: pace ? `A block every ${(pace / 1000).toFixed(2).replace(/0$/, '')} s` : null,
      days: days.map(d => ({ day: d.day, label: dateWords(d.day), payments: d.payments, actions: d.actions, moved: `${secondsText(wholeOf(d.moved_micros))} s` })),
    };
  }
  const h = body.holders;
  if (h && typeof h === 'object' && integer(h.holding) !== null && wholeOf(h.held_micros) !== null && Array.isArray(h.top)) {
    const read = timeOfIso(h.read_at), supply = view.chain?.supply ?? null;
    view.holders = {
      holding: count(h.holding, 'account holds time', 'accounts hold time'),
      rows: h.top.filter(r => r && integer(r.rank) !== null && wholeOf(r.balance_micros) !== null && wholeOf(r.staked_micros) !== null).slice(0, 10).map(r => {
        const held = wholeOf(r.balance_micros) + wholeOf(r.staked_micros), name = r.anonymous === false ? plainText(r.name, 64) : null;
        return { rank: String(r.rank), name, anonymous: name === null, held: `${secondsText(held)} s`, share: shareText(held, supply) };
      }),
      summary: `${count(h.holding, 'account holds', 'accounts hold')} ${secondsText(wholeOf(h.held_micros))} s between them${h.complete === false ? ', among the accounts this service reads' : ''}.`,
      when: read === null ? '' : `Counted account by account between blocks ${groupDigits(String(wholeOf(h.from_height) ?? '?'))} and ${groupDigits(String(wholeOf(h.to_height) ?? '?'))}, at ${utcWords(read)}${integer(h.every_seconds) ? `, again every ${Math.round(h.every_seconds / 60)} minutes` : ''}.`,
    };
  }
  return view;
}

/// Follows `<api><path>`: asks at once, then `every` ms after the previous question, never more often and never
/// while the page is hidden; a page shown again is asked as soon as `every` has passed since the last question.
/// Every answer goes to `show` as `words(body)`, and every failure as `failed`.
export function follow(api, { doc, fetch, show, now = Date.now, later = setTimeout, cancel = clearTimeout, timeZone, path = '/v1/status', every = EVERY_MS, words = (body, at) => statusWords(body, { now: at, timeZone }), failed = NOT_ANSWERING }) {
  let timer = null, last = -Infinity, asking = false;
  const schedule = () => { cancel(timer); timer = null; if (!doc.hidden && !asking) timer = later(ask, Math.max(0, last + every - now())); };
  async function ask() {
    timer = null;
    if (asking || doc.hidden) return;
    asking = true; last = now();
    try {
      const response = await fetch(`${api}${path}`, { cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(8000) });
      if (!response.ok) throw new Error(String(response.status));
      show(words(await response.json(), now()));
    } catch { show(failed); } finally { asking = false; schedule(); }
  }
  doc.addEventListener('visibilitychange', schedule);
  schedule();
}

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  const make = (tag, className, text) => { const el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; };
  // The namespace of the drawings, taken from the page's own mark: the script names no other site's address.
  const SVG = document.querySelector('svg.brand-mark').namespaceURI;
  const svg = (tag, attributes = {}) => { const el = document.createElementNS(SVG, tag); for (const [name, value] of Object.entries(attributes)) el.setAttribute(name, String(value)); return el; };
  const note = text => { $('config-note').textContent = text; $('config-note').hidden = false; };
  const live = words => { $('live-headline').textContent = words.headline; $('live-detail').textContent = words.detail; $('live-headline').classList.toggle('bad', !words.ok); };
  const set = (id, text) => { $(id).textContent = text ?? ''; };

  // The running clock: from the genesis the chain proved, on this device's clock, once a second while shown.
  let genesisMs = null;
  const tick = () => { if (genesisMs !== null && !document.hidden) set('running', clockText(Date.now() - genesisMs)); };
  setInterval(tick, 1000);

  // Where the seconds are: one thin bar split in parts, with a legend that names each and gives its amount.
  function drawSplit(parts, supply) {
    const box = $('split-bar'), width = Math.max(120, Math.floor(box.clientWidth || 300)), height = 8, gap = 2;
    const shown = parts.filter(p => p.micros > 0n), room = width - gap * Math.max(0, shown.length - 1);
    const drawing = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, 'aria-hidden': 'true', focusable: 'false' });
    let x = 0;
    shown.forEach((p, i) => {
      const w = i === shown.length - 1 ? width - x : Math.max(2, Math.round(Number(p.micros * BigInt(room) / supply)));
      drawing.append(svg('rect', { x, y: 0, width: Math.max(0, w), height, rx: 4, class: `part-${p.key}` }));
      x += w + gap;
    });
    box.replaceChildren(drawing);
    box.setAttribute('aria-label', `Where the seconds are: ${parts.map(p => `${p.name} ${p.text} (${p.share})`).join(', ')}`);
    $('split-legend').replaceChildren(...parts.map(p => {
      const item = make('li'), key = svg('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true', focusable: 'false' });
      key.append(svg('rect', { x: 0, y: 0, width: 12, height: 12, rx: 3, class: `part-${p.key}` }));
      item.append(key, make('span', 'legend-name', p.name), make('span', 'legend-value', `${p.text} · ${p.share}`));
      return item;
    }));
  }

  // Payments per day: one bar a day, the tallest the height of the drawing; each bar a target for the pointer and
  // the keyboard, whose figures the line under the chart reads out. The table view holds every value too.
  let lastDays = [];
  function drawDays(days) {
    lastDays = days;
    const box = $('days-chart'), width = Math.max(240, Math.floor(box.clientWidth || 600)), height = 168, top = 20, bottom = 24, plot = height - top - bottom;
    const max = Math.max(1, ...days.map(d => d.payments)), band = width / Math.max(1, days.length), bar = Math.min(24, Math.max(4, band * 0.6));
    const drawing = svg('svg', { width, height, viewBox: `0 0 ${width} ${height}`, role: 'group', 'aria-labelledby': 'days-title' });
    drawing.append(svg('line', { x1: 0, x2: width, y1: top + plot + 0.5, y2: top + plot + 0.5, class: 'axis' }));
    const peak = svg('text', { x: 0, y: 12, class: 'tick' }); peak.textContent = `${groupDigits(String(max))} a day at most`; drawing.append(peak);
    const readout = $('days-readout'), sayDay = d => { readout.textContent = `${d.label}: ${count(d.payments, 'payment')}, ${d.moved} moved, ${count(d.actions, 'action')}.`; };
    const labelEvery = days.length <= 10 ? 1 : days.length <= 20 ? 2 : 5;
    days.forEach((d, i) => {
      const cx = band * i + band / 2, h = d.payments === 0 ? 0 : Math.max(2, Math.round(d.payments / max * plot)), x = cx - bar / 2, y = top + plot - h, r = Math.min(4, h, bar / 2);
      const group = svg('g', { class: 'day', tabindex: 0, role: 'img', 'aria-label': `${d.label}: ${count(d.payments, 'payment')}, ${d.moved} moved` });
      group.append(svg('rect', { x: band * i, y: 0, width: band, height: top + plot, class: 'hit' }));
      if (h > 0) group.append(svg('path', { d: `M${x},${top + plot}V${y + r}Q${x},${y} ${x + r},${y}H${x + bar - r}Q${x + bar},${y} ${x + bar},${y + r}V${top + plot}Z`, class: 'bar' }));
      for (const type of ['pointerenter', 'focus']) group.addEventListener(type, () => sayDay(d));
      drawing.append(group);
      if (i % labelEvery === 0 || i === days.length - 1) { const t = svg('text', { x: cx, y: height - 6, class: 'tick', 'text-anchor': 'middle' }); t.textContent = `${Number(d.day.slice(8))} ${MONTHS[Number(d.day.slice(5, 7)) - 1].slice(0, 3)}`; drawing.append(t); }
    });
    box.replaceChildren(drawing);
    if (days.length) sayDay(days.at(-1));
    $('days-table').replaceChildren(...[...days].reverse().map(d => { const row = make('tr'); row.append(make('th', '', d.label), make('td', 'num', groupDigits(String(d.payments))), make('td', 'num', d.moved), make('td', 'num', groupDigits(String(d.actions)))); row.firstChild.scope = 'row'; return row; }));
  }

  let lastView = null;
  function showStats(view, failed = false) {
    if (failed) { if (!lastView) set('supply-words', 'The network\'s figures could not be read just now. This page asks again in 30 seconds.'); return; }
    const { chain, activity, holders } = view;
    if (chain) {
      set('supply-figure', chain.figure); set('supply-words', chain.words);
      $('supply-check').hidden = !chain.check; set('supply-check-words', chain.check);
      $('supply-split').hidden = false; drawSplit(chain.parts, chain.supply);
      genesisMs = chain.genesisMs; tick(); set('running-since', chain.since);
      set('accounts', chain.accounts ?? '–'); set('validators', chain.validators === null ? '–' : String(chain.validators));
    } else if (!lastView?.chain) set('supply-words', 'The chain\'s state could not be read with a proof just now. This page asks again in 30 seconds.');
    if (activity) {
      set('actions', activity.actions); set('actions-payments', activity.payments); set('moved', activity.moved); set('moved-since', 'Since the first block');
      set('day-payments', activity.day?.payments ?? '–'); set('day-detail', activity.day?.detail ?? ''); set('block-pace', activity.pace ?? '');
      $('days-part').hidden = activity.days.length === 0; if (activity.days.length) drawDays(activity.days);
    }
    if (holders) set('accounts-holding', holders.holding);
    $('holders-part').hidden = !(holders ?? lastView?.holders);
    if (holders) {
      set('holders-summary', holders.summary); set('holders-when', holders.when);
      $('holders-table').replaceChildren(...holders.rows.map(r => {
        const row = make('tr'); row.append(make('td', 'num', r.rank), make('td', r.anonymous ? 'anonymous' : 'named', r.anonymous ? 'Anonymous' : r.name), make('td', 'num', r.held), make('td', 'num', r.share));
        return row;
      }));
    }
    lastView = { chain: chain ?? lastView?.chain ?? null, activity: activity ?? lastView?.activity ?? null, holders: holders ?? lastView?.holders ?? null };
  }
  let resizing = null;
  window.addEventListener('resize', () => { clearTimeout(resizing); resizing = setTimeout(() => { if (lastView?.chain) drawSplit(lastView.chain.parts, lastView.chain.supply); if (lastDays.length) drawDays(lastDays); }, 150); });

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
    const { config, problems } = read, links = { ...config, ...derivedLinks(config) };
    if (problems.length && !$('config-note').textContent) note(`Some parts of this page are not set: ${problems.join(' ')}`);
    // An app the network does not have is not offered; a missing address of the network's own pages is said.
    for (const card of document.querySelectorAll('[data-app-of]')) card.hidden = !config[card.dataset.appOf];
    for (const link of document.querySelectorAll('[data-link]')) {
      // A hidden card is not offered at all: its link is neither a link nor a button that leads nowhere.
      if (link.closest('[data-app-of]')?.hidden) { link.removeAttribute('href'); continue; }
      const address = links[link.dataset.link];
      if (address) { link.href = address; link.removeAttribute('aria-disabled'); } else { link.removeAttribute('href'); link.setAttribute('aria-disabled', 'true'); }
    }
    $('ends').textContent = endsWords(config.ends);
    if (config.network_name) { $('network-name').textContent = `Network: ${config.network_name}`; $('network-name').hidden = false; }
    if (!config.api) { live({ ok: false, headline: 'The address of the network\'s service is not set on this page.', detail: '' }); set('supply-words', ''); return; }
    const fetcher = globalThis.fetch.bind(globalThis);
    follow(config.api, { doc: document, fetch: fetcher, show: live });
    follow(config.api, { doc: document, fetch: fetcher, path: '/v1/stats', every: STATS_EVERY_MS, words: body => statsView(body), failed: null, show: view => (view ? showStats(view) : showStats(null, true)) });
  })();
}
