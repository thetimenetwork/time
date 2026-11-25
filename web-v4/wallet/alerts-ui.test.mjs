// The Alerts panel's wiring (alerts-ui.mjs) with stand-in elements and a stand-in browser: what the panel shows from a
// proven state, when the marker is stored, the live hint and how its reads are spaced, and every state of the switch
// with each refusal's sentence. The real page with the real app.js is in alerts-page.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import '../../client-v4/time-sdk.js';
import { createAlertsUI, PANEL, LIVE_GAP_MS, PUSH_WAIT_MS, SHOWN_PREFIX, PUSH_PREFIX, STATUS_GAP_MS, readShown, readEndpoint } from './alerts-ui.mjs';
import { WORDS } from './alerts-push.mjs';
import { markerKey } from './alerts.mjs';

const sdk = globalThis.TimeSDK;
const NET = 'c6'.repeat(32), ORIGIN = 'https://wallet.example', H = 3600000000n, DAY = 24n * H, GENESIS = 1790000000000000n, NOW = 100n * DAY;
class El {
  constructor(tag) { Object.assign(this, { tag, hidden: false, textContent: '', className: '', children: [], listeners: {} }); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  async fire(type) { for (const fn of this.listeners[type] || []) await fn({ preventDefault() {} }); }
  append(...c) { this.children.push(...c); } replaceChildren(...c) { this.children = c; }
}
globalThis.document = { createElement: tag => new El(tag) };
const textOf = el => (typeof el === 'string' ? el : [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ')).replace(/\s+/g, ' ').trim();
/// A browser storage whose keys can be listed, as localStorage's can.
class Store { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
function Storage() { return new Proxy(new Store(), { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => (t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : undefined), get: (t, k) => (typeof t[k] === 'function' ? t[k].bind(t) : t[k]) }); }
const keyOf = async () => { const pair = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']); return { privateKey: pair.privateKey, publicKey: Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('hex') }; };
const login = await keyOf();
const ACCOUNT = { id: '14', name: 'carol', balance: '9000000', nonce: '7', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: '22'.repeat(32), can_manage: false, can_spend: true }, { public_key: '33'.repeat(32), can_manage: true, can_spend: false }] };
const row = (extra = {}) => ({ account: '14', version: '1', policy: { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '600000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null, ...extra });
const state = (security = row(), account = ACCOUNT) => ({ network_id: NET, height: '900', time_micros: String(GENESIS + NOW), genesis: { genesis_time_micros: String(GENESIS) }, config: {}, accounts: [account], security: [security], recovery_cases: [] });
const waiting = () => row({ next_id: '2', pending_payments: [{ id: '1', to: '2', amount: '900000000', ready_elapsed_micros: String(NOW + 47n * H) }] });

/// A stand-in browser: EventSource, the service worker and push, notifications, and the alert service's answers.
function browserWith({ secure = true, sw = true, push = true, permission = 'default', grant = 'granted', subscribed = null, answers = {}, userAgent = 'Chrome/140', standalone = false } = {}) {
  const calls = [], streams = [];
  let sub = subscribed;
  const registration = { pushManager: { getSubscription: async () => sub, subscribe: async (options) => { calls.push(['subscribe', options.userVisibleOnly, options.applicationServerKey.length]); sub = { endpoint: 'https://fcm.googleapis.com/fcm/send/new', toJSON: () => ({ endpoint: sub.endpoint, expirationTime: null, keys: { p256dh: 'B' + 'A'.repeat(86), auth: 'x'.repeat(22) } }), unsubscribe: async () => { calls.push(['browser-unsubscribe']); sub = null; return true; } }; return sub; } } };
  let registered = Boolean(subscribed);
  class EventSource {
    constructor(url) { this.url = url; this.listeners = {}; this.readyState = 0; this.closed = false; streams.push(this); }
    addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
    emit(type, data) { if (type === 'open') this.readyState = 1; for (const fn of this.listeners[type] || []) fn({ data }); }
    close() { this.closed = true; this.readyState = 2; }
  }
  const win = {
    isSecureContext: secure, location: { origin: ORIGIN },
    navigator: { userAgent, platform: /iPhone/.test(userAgent) ? 'iPhone' : 'Win32', maxTouchPoints: 0, ...(standalone ? { standalone: true } : {}),
      ...(sw ? { serviceWorker: { getRegistration: async () => (registered ? registration : undefined), register: async (url, options) => { calls.push(['register', url, options.scope]); registered = true; return registration; }, ready: Promise.resolve(registration) } } : {}) },
    ...(push ? { PushManager: function PushManager() {} } : {}),
    Notification: Object.assign(function Notification() {}, { permission, requestPermission: async () => { calls.push(['permission']); return grant; } }),
    matchMedia: () => ({ matches: false }), EventSource,
    fetch: async (url, options = {}) => {
      const body = options.body ? JSON.parse(options.body) : undefined; calls.push([options.method, url, body]);
      assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit'); assert.ok(options.signal instanceof AbortSignal);
      const route = url.replace('/alerts/v1/', ''), given = answers[route] ?? { key: [200, { public_key: 'B' + 'A'.repeat(86) }], challenge: [200, null], subscribe: [200, { subscribed: true, account: '14' }], unsubscribe: [200, { removed: 1 }] }[route];
      const [status, answer] = typeof given === 'function' ? given(body) : given;
      return { status, text: async () => JSON.stringify(answer ?? challengeFor()) };
    },
  };
  return { win, calls, streams, sub: () => sub };
}
const challengeFor = () => ({ purpose: 'login', origin: ORIGIN, networkId: NET, nonce: 'ab'.repeat(32), issuedAt: Date.now(), expiresAt: Date.now() + 170000 });

/// The panel's elements, the page's notice, and the panel made with them.
function panelWith(browser, { storage = new Storage(), clock = { at: 1_000_000 }, timers = [], extra = {} } = {}) {
  const dom = new Map(), $ = id => { if (!dom.has(id)) dom.set(id, new El('#' + id)); return dom.get(id); };
  const said = [], reads = [];
  const ui = createAlertsUI({ sdk, $, network: () => ({ networkId: NET }), session: () => ({ binding: { publicKey: login.publicKey }, privateKey: login.privateKey }), ownAccount: () => ACCOUNT, storage,
    run: async fn => { try { await fn(); } catch (error) { said.push([error.message, 'error']); } }, notice: (text, kind = '') => said.push([text, kind]), setBusy: () => {}, readAgain: () => reads.push(clock.at),
    ...extra, win: browser.win, now: () => clock.at, setTimer: (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, clearTimer: id => { if (timers[id - 1]) timers[id - 1].cleared = true; }, formatDate: d => d.toISOString().slice(0, 16) });
  const view = () => ({ panel: !$('alerts-panel').hidden, banner: $('alerts-banner').hidden ? null : $('alerts-banner').textContent, list: $('alerts-list').children.map(textOf), none: !$('alerts-none').hidden, confirm: !$('alerts-confirm').hidden, live: $('alerts-live').textContent,
    state: $('alerts-switch-state').textContent, why: $('alerts-switch-why').hidden ? '' : $('alerts-switch-why').textContent, buttons: ['alerts-turn-on', 'alerts-turn-off', 'alerts-off-everywhere'].filter(id => !$(id).hidden), what: !$('alerts-switch-what').hidden });
  return { ui, $, view, said, reads, storage, clock, timers };
}
// Nothing here waits for real time: a render is waited for with the panel's idle() (what it started in the background:
// the switch and the question to the service), and a press with the promise its listener hands back (El.fire awaits it).
// Waiting 20 ms instead failed on a busy machine: the proof of a turn-on is a WebCrypto signature, done off the thread.

test('from a proven state: the list, most urgent first, one urgent banner, and on a first look the marker is stored at once', async () => {
  const p = panelWith(browserWith());
  p.ui.render(ACCOUNT, state(waiting()));
  const seen = p.view();
  assert.deepEqual([seen.panel, seen.banner, seen.none, seen.confirm], [true, 'A payment is waiting', false, true]);
  assert.equal(seen.list.length, 1);
  assert.match(seen.list[0], /^A payment is waiting Urgent A payment of 900 seconds to account 2 is waiting\. It can go through at .* unless it is cancelled\. If you did not start it, cancel it now on Home, under “Waiting on your account”, then freeze your account now with the Freeze switch on Home\.$/);
  // The first look: the marker of this state is stored at once; nothing is confirmed by that.
  const marker = JSON.parse(p.storage.getItem(markerKey(NET, '14')));
  assert.deepEqual([marker.account, marker.next_id, marker.version], ['14', '2', '1']);
  assert.equal(p.storage.getItem(SHOWN_PREFIX + `${NET}:14`), null);
  // A calm account: one quiet line, no banner, nothing to confirm.
  const calm = panelWith(browserWith()); calm.ui.render(ACCOUNT, state());
  assert.deepEqual([calm.view().none, calm.view().banner, calm.view().confirm, calm.view().list], [true, null, false, []]);
});

test('"I have seen these" stores the marker and the ids shown: the banner goes, what is still true stays listed, a change since is gone; only the button does it', async () => {
  const p = panelWith(browserWith());
  p.ui.render(ACCOUNT, state());
  const first = p.storage.getItem(markerKey(NET, '14'));
  // A login key added since: a change, and a payment waits: true now.
  const more = { ...ACCOUNT, auth_epoch: '3', nonce: '8', devices: [...ACCOUNT.devices, { public_key: '44'.repeat(32), can_manage: false, can_spend: false }] };
  for (let i = 0; i < 3; i++) p.ui.render(more, state(waiting(), more));
  assert.equal(p.storage.getItem(markerKey(NET, '14')), first, 'reading again stores nothing');
  assert.deepEqual([p.view().banner, p.view().list.length, p.view().confirm], ['A payment is waiting', 2, true]);
  await p.$('alerts-confirm').fire('click');
  assert.notEqual(p.storage.getItem(markerKey(NET, '14')), first);
  assert.deepEqual(readShown(p.storage.getItem(SHOWN_PREFIX + `${NET}:14`), '14').length, 2);
  const after = p.view();
  assert.deepEqual([after.banner, after.confirm, after.list.length], [null, false, 1]);
  assert.match(after.list[0], /^A payment is waiting/);
  // The next read: still no banner for what was confirmed; a new waiting payment (another id) brings it back.
  p.ui.render(more, state(waiting(), more));
  assert.deepEqual([p.view().banner, p.view().confirm], [null, false]);
  const two = row({ next_id: '3', pending_payments: [...waiting().pending_payments, { id: '2', to: '2', amount: '5', ready_elapsed_micros: String(NOW + H) }] });
  p.ui.render(more, state(two, more));
  assert.deepEqual([p.view().banner, p.view().confirm, p.view().list.length], ['A payment is waiting', true, 2]);
  // What is kept is read strictly.
  for (const bad of ['x', '[1]', JSON.stringify(['15:payment-waiting:1']), JSON.stringify(Array(65).fill('14:a'))]) assert.deepEqual(readShown(bad, '14'), []);
  assert.deepEqual([readEndpoint('https://fcm.googleapis.com/x'), readEndpoint('http://x'), readEndpoint(null)], ['https://fcm.googleapis.com/x', null, null]);
});

test('live: one stream for the account, a touch asks for one read, touches together are one read, two seconds apart at least, and one read when the stream comes back', async () => {
  const b = browserWith(), p = panelWith(b);
  p.ui.render(ACCOUNT, state());
  assert.deepEqual(b.streams.map(s => s.url), ['/v1/touches?account=14']);
  const stream = b.streams[0];
  assert.equal(p.view().live, PANEL.checked);
  stream.emit('open'); assert.equal(p.view().live, PANEL.live);
  // A touch for another account, or anything that is not a touch, asks for nothing.
  for (const data of [JSON.stringify({ source: 'index', proven: false, account: '15', height: '5' }), 'not json', JSON.stringify({ source: 'index', proven: true, account: '14', height: '5' })]) stream.emit('touch', data);
  assert.equal(p.timers.length, 0);
  const touch = height => stream.emit('touch', JSON.stringify({ source: 'index', proven: false, account: '14', height }));
  touch('5'); touch('5'); touch('6');
  assert.deepEqual(p.timers.map(t => t.ms), [0], 'three touches, one read');
  p.timers[0].fn(); assert.equal(p.reads.length, 1);
  // The next touch, half a second later: its read waits until two seconds after the first.
  p.clock.at += 500; touch('7'); touch('8');
  assert.deepEqual(p.timers.map(t => t.ms), [0, LIVE_GAP_MS - 500]);
  p.clock.at += 1500; p.timers[1].fn(); assert.equal(p.reads.length, 2);
  // The stream breaks and comes back: one read.
  stream.emit('error'); assert.equal(p.view().live, PANEL.checked);
  stream.emit('open'); assert.equal(p.view().live, PANEL.live);
  assert.equal(p.timers.length, 3);
  // A stream the browser gives up (no such route): the page goes on with its timer, and the panel says only when it checked.
  stream.readyState = 2; stream.emit('error');
  assert.deepEqual([stream.closed, p.view().live], [true, PANEL.checked]);
  // Another account: the stream of the first is closed, one of its own is opened. Locked: closed, and nothing is left.
  const other = { ...ACCOUNT, id: '15' };
  p.ui.render(other, state(row({ account: '15' }), other));
  assert.deepEqual(b.streams.map(s => [s.url, s.closed]), [['/v1/touches?account=14', true], ['/v1/touches?account=15', false]]);
  p.ui.reset();
  assert.equal(b.streams[1].closed, true);
  assert.deepEqual([p.view().panel, p.view().banner, p.view().list, p.view().live, p.view().state], [false, null, [], '', '']);
  // A browser without EventSource: no stream, no word about it.
  const plain = browserWith(); delete plain.win.EventSource; const q = panelWith(plain);
  q.ui.render(ACCOUNT, state()); assert.equal(q.view().live, PANEL.checked);
});

test('the switch tells what this browser can do: why not, off with why it matters, on only with a subscription this account was given', async () => {
  const shown = async (options, storage) => { const p = panelWith(browserWith(options), { storage }); p.ui.render(ACCOUNT, state()); await p.ui.idle(); return p.view(); };
  assert.deepEqual(await shown({ sw: false }), { ...await shown({ sw: false }), state: WORDS.off, why: WORDS.unsupported, buttons: [], what: false });
  assert.equal((await shown({ secure: false })).why, WORDS.insecure);
  assert.equal((await shown({ push: false, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Safari/604.1' })).why, WORDS.iosHomeScreen);
  assert.equal((await shown({ userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Safari/604.1', standalone: true })).state, WORDS.offMatters);
  assert.equal((await shown({ permission: 'denied' })).why, WORDS.denied);
  const notOffered = await shown({ answers: { key: [404, { error: 'Not found' }] } });
  assert.deepEqual([notOffered.state, notOffered.why, notOffered.buttons], [WORDS.off, WORDS.notOffered, []]);
  const off = await shown({});
  assert.deepEqual([off.state, off.why, off.buttons, off.what], [WORDS.offMatters, '', ['alerts-turn-on', 'alerts-off-everywhere'], true]);
  // A push subscription of this browser that this account was not given: off.
  const subscribed = { endpoint: 'https://fcm.googleapis.com/fcm/send/old', unsubscribe: async () => true };
  assert.equal((await shown({ subscribed })).state, WORDS.offMatters);
  const storage = new Storage(); storage.setItem(PUSH_PREFIX + `${NET}:14`, subscribed.endpoint);
  const on = await shown({ subscribed }, storage);
  assert.deepEqual([on.state, on.buttons], [WORDS.on, ['alerts-turn-off', 'alerts-off-everywhere']]);
  // Its record without the subscription (the browser dropped it): off.
  assert.equal((await shown({}, storage)).state, WORDS.offMatters);
});

test('turning on: the browser asks first, then the key, the subscription, the challenge for this wallet, the proof of the login key; "on" only after the service took it', async () => {
  const b = browserWith(), p = panelWith(b);
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  await p.$('alerts-turn-on').fire('click');
  assert.deepEqual(b.calls.map(c => c.slice(0, 2)), [['GET', '/alerts/v1/key'], ['permission'], ['register', './sw.js'], ['subscribe', true], ['POST', '/alerts/v1/challenge'], ['POST', '/alerts/v1/subscribe']]);
  const asked = b.calls.find(c => c[1] === '/alerts/v1/challenge')[2], given = b.calls.find(c => c[1] === '/alerts/v1/subscribe')[2];
  assert.deepEqual(Object.keys(asked), ['action', 'subscription']);
  assert.deepEqual(Object.keys(given.subscription), ['endpoint', 'keys']);
  // The proof is a login of the sign-in key, for the challenge of this wallet's own origin, and it verifies.
  const message = given.proof.message;
  assert.deepEqual([message.purpose, message.origin, message.networkId, message.accountId, message.authEpoch, message.publicKey], ['login', ORIGIN, NET, '14', '2', login.publicKey]);
  const key = await crypto.subtle.importKey('raw', Buffer.from(login.publicKey, 'hex'), 'Ed25519', false, ['verify']);
  assert.ok(await crypto.subtle.verify('Ed25519', key, Buffer.from(given.proof.signature, 'hex'), sdk.loginBytes(message)));
  assert.deepEqual([p.view().state, p.said.at(-1)], [WORDS.on, [WORDS.on, '']]);
  assert.equal(p.storage.getItem(PUSH_PREFIX + `${NET}:14`), 'https://fcm.googleapis.com/fcm/send/new');
});

test('turning on is refused in the wallet\'s words, and the switch never says on: no permission, a frozen account, no service, a challenge for another website', async () => {
  // `drain`: the waits the panel sets while the service is busy (busy.mjs) are run as they come, the clock moved by each.
  const attempt = async (options, { drain = false } = {}) => {
    const b = browserWith(options), p = panelWith(b); p.ui.render(ACCOUNT, state()); await p.ui.idle();
    let done = false; const pressing = p.$('alerts-turn-on').fire('click').finally(() => { done = true; });
    while (drain && !done) { for (const timer of p.timers.filter(t => !t.ran && !t.cleared && t.ms <= 30000)) { timer.ran = true; p.clock.at += timer.ms; timer.fn(); } await new Promise(resolve => setImmediate(resolve)); }
    await pressing;
    return { b, p, said: p.said.at(-1), state: p.view().state, kept: p.storage.getItem(PUSH_PREFIX + `${NET}:14`) };
  };
  const denied = await attempt({ grant: 'denied' });
  assert.deepEqual([denied.said, denied.state, denied.kept], [[WORDS.denied, 'error'], WORDS.offMatters, null]);
  assert.ok(!denied.b.calls.some(c => c[0] === 'register'), 'nothing is registered before the person allows notifications');
  const dismissed = await attempt({ grant: 'default' });
  assert.deepEqual(dismissed.said, [WORDS.failed, 'error']);
  const frozen = await attempt({ answers: { subscribe: [403, { error: 'The account was not proven: The account is frozen: nobody signs in until the freeze ends or its keys are replaced' }] } });
  assert.deepEqual([frozen.said, frozen.state, frozen.kept], [[WORDS.frozen, 'error'], WORDS.offMatters, null]);
  // A busy service (503) is asked again after each wait, four times within twenty seconds, then said in its own words.
  const busy = await attempt({ answers: { challenge: [503, { error: 'Too many challenges are open' }] } }, { drain: true });
  assert.deepEqual([busy.said, busy.kept, busy.state], [[WORDS.busy, 'error'], null, WORDS.offMatters]);
  assert.equal(busy.b.calls.filter(c => c[1] === '/alerts/v1/challenge').length, 4);
  assert.ok(!busy.b.calls.some(c => c[1] === '/alerts/v1/subscribe'), 'nothing was sent after the challenge');
  const gone = await attempt({ answers: { subscribe: [404, { error: 'No such route' }] } });
  assert.deepEqual(gone.said, [WORDS.notOffered, 'error']);
  // A challenge that names another origin is not signed: no proof leaves this wallet.
  const other = await attempt({ answers: { challenge: [200, { ...challengeFor(), origin: 'https://shop.example' }] } });
  assert.match(other.said[0], /Nothing was signed/);
  assert.ok(!other.b.calls.some(c => c[1] === '/alerts/v1/subscribe'), 'nothing was sent after the challenge');
  assert.equal(other.state, WORDS.offMatters);
});

test('turning off: this browser by its address, and every browser of the account by a proof', async () => {
  const subscribed = { endpoint: 'https://fcm.googleapis.com/fcm/send/old', unsubscribe: async () => { ended += 1; return true; } };
  let ended = 0;
  const storage = new Storage(); storage.setItem(PUSH_PREFIX + `${NET}:14`, subscribed.endpoint); storage.setItem(PUSH_PREFIX + `${NET}:15`, subscribed.endpoint);
  const b = browserWith({ subscribed }), p = panelWith(b, { storage });
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  assert.equal(p.view().state, WORDS.on);
  await p.$('alerts-turn-off').fire('click');
  // Opened with alerts on, the page asked once whether the service still has this browser (K-3); then it turned them off.
  assert.deepEqual(b.calls.filter(c => c[0] === 'POST').map(c => [c[1], c[2]]), [['/alerts/v1/status', { endpoint: subscribed.endpoint }], ['/alerts/v1/unsubscribe', { endpoint: subscribed.endpoint }]]);
  assert.deepEqual([ended, storage.getItem(PUSH_PREFIX + `${NET}:14`), storage.getItem(PUSH_PREFIX + `${NET}:15`), p.said.at(-1)], [1, null, null, [WORDS.off, '']]);
  const c = browserWith(); const r = panelWith(c, { storage });
  r.ui.render(ACCOUNT, state()); await r.ui.idle();
  await r.$('alerts-off-everywhere').fire('click');
  const posted = c.calls.filter(x => x[0] === 'POST');
  assert.deepEqual(posted.map(x => [x[1], Object.keys(x[2])]), [['/alerts/v1/challenge', ['action']], ['/alerts/v1/unsubscribe', ['proof']]]);
  assert.deepEqual(r.said.at(-1), [PANEL.offEverywhere, '']);
});

test('a browser whose push service refuses or never answers (a headless one): the wallet says so in its words, sends nothing and never says on', async () => {
  // Refused: the subscription fails at once, as in a browser without a push service of its own.
  const refusing = browserWith(), p = panelWith(refusing);
  refusing.win.navigator.serviceWorker.getRegistration = async () => undefined;
  const pushManager = { getSubscription: async () => null, subscribe: async () => { throw Object.assign(new Error('Registration failed - push service not available'), { name: 'AbortError' }); } };
  refusing.win.navigator.serviceWorker.register = async () => ({ pushManager });
  refusing.win.navigator.serviceWorker.ready = Promise.resolve({ pushManager });
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  await p.$('alerts-turn-on').fire('click');
  assert.deepEqual([p.said.at(-1), p.view().state, p.storage.getItem(PUSH_PREFIX + `${NET}:14`)], [[WORDS.failed, 'error'], WORDS.offMatters, null]);
  assert.ok(!refusing.calls.some(c => c[0] === 'POST'), 'nothing went to the alert service');
  // Never answers: the wallet waits PUSH_WAIT_MS, then says so; it does not stay busy.
  const silent = browserWith(), timers = [], q = panelWith(silent, { timers });
  let reached; const reaching = new Promise(resolve => { reached = resolve; });
  const stuck = { getSubscription: async () => null, subscribe: () => { reached(); return new Promise(() => {}); } };
  silent.win.navigator.serviceWorker.register = async () => ({ pushManager: stuck });
  silent.win.navigator.serviceWorker.ready = Promise.resolve({ pushManager: stuck });
  q.ui.render(ACCOUNT, state()); await q.ui.idle();
  const pressed = q.$('alerts-turn-on').fire('click'); await reaching;
  const waits = timers.filter(t => t.ms === PUSH_WAIT_MS && !t.cleared);
  assert.equal(waits.length, 1, 'one wait for the subscription that does not answer');
  waits[0].fn(); await pressed;
  assert.deepEqual([q.said.at(-1), q.view().state], [[WORDS.failed, 'error'], WORDS.offMatters]);
  assert.ok(!silent.calls.some(c => c[0] === 'POST'));
  assert.ok(timers.filter(t => t.ms === PUSH_WAIT_MS).every(t => t.cleared || t === waits[0]), 'every other wait was ended when its step answered');
});

// Web audit of November 2026, K-3 (the wallet's side): the login key alone can remove every subscription of the account
// at the alert service, and the switch kept saying "on" from this browser's own record.
test('the switch asks the service whether it still has this browser: once when the account opens, then at most once a minute; false is an urgent alert', async () => {
  const subscribed = { endpoint: 'https://fcm.googleapis.com/fcm/send/mine', unsubscribe: async () => true };
  let answer = [200, { subscribed: true }];
  const storage = new Storage(); storage.setItem(PUSH_PREFIX + `${NET}:14`, subscribed.endpoint);
  const b = browserWith({ subscribed, answers: { status: () => answer } }), p = panelWith(b, { storage });
  const asked = () => b.calls.filter(c => c[1] === '/alerts/v1/status');
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  assert.deepEqual(asked().map(c => c[2]), [{ endpoint: subscribed.endpoint }], 'asked once when the account opened');
  assert.equal(p.view().state, WORDS.on);
  // Within the minute: not again. After it: again.
  p.clock.at += STATUS_GAP_MS - 1; p.ui.render(ACCOUNT, state()); await p.ui.idle();
  assert.equal(asked().length, 1);
  p.clock.at += 1; p.ui.render(ACCOUNT, state()); await p.ui.idle();
  assert.equal(asked().length, 2);
  // A service without the route (404), or an answer in no form: nothing changes.
  for (const odd of [[404, { error: 'Not found' }], [200, { subscribed: 'no' }], [200, { subscribed: false, extra: 1 }], [500, null]]) {
    answer = odd; p.clock.at += STATUS_GAP_MS; p.ui.render(ACCOUNT, state()); await p.ui.idle();
    assert.deepEqual([p.storage.getItem(PUSH_PREFIX + `${NET}:14`), p.view().state, p.view().list.length], [subscribed.endpoint, WORDS.on, 0], JSON.stringify(odd));
  }
  // The service no longer has it: the record is forgotten, the switch says off, and the panel's first item is urgent.
  answer = [200, { subscribed: false }]; p.clock.at += STATUS_GAP_MS; p.ui.render(ACCOUNT, state()); await p.ui.idle();
  const seen = p.view();
  assert.equal(p.storage.getItem(PUSH_PREFIX + `${NET}:14`), null);
  assert.equal(seen.state, WORDS.offMatters);
  assert.equal(seen.banner, 'Alerts were turned off for this browser');
  assert.equal(seen.list[0], 'Alerts were turned off for this browser Urgent Alerts were turned off for this browser, and this browser did not do it. Someone who can sign in as you can do that. Turn them on again, then make a new login password under Keys.');
  // It stays through the next reads (no record now, so nothing more is asked), until alerts are on again.
  p.clock.at += STATUS_GAP_MS; p.ui.render(ACCOUNT, state()); await p.ui.idle();
  assert.equal(asked().length, 7);
  assert.equal(p.view().list[0].startsWith('Alerts were turned off for this browser'), true);
  answer = [200, { subscribed: true }];
  await p.$('alerts-turn-on').fire('click');
  assert.deepEqual([p.view().state, p.view().list.length, p.storage.getItem(PUSH_PREFIX + `${NET}:14`) !== null], [WORDS.on, 0, true]);
  // A browser whose record says off asks nothing.
  const c = browserWith(), q = panelWith(c);
  q.ui.render(ACCOUNT, state()); await q.ui.idle();
  assert.equal(c.calls.filter(x => x[1] === '/alerts/v1/status').length, 0);
});

test('a ninth browser of the account is refused by the service (409): the wallet says what to do', async () => {
  const b = browserWith({ answers: { subscribe: [409, { error: 'full' }] } }), p = panelWith(b);
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  await p.$('alerts-turn-on').fire('click');
  assert.deepEqual(p.said.at(-1), ['This account already has alerts on eight browsers. Use “Turn off alerts on every browser of this account”, then turn them on here.', 'error']);
  assert.notEqual(p.view().state, WORDS.on);
  // The other 409 of the service (this browser follows as many accounts as it may) is not said as eight browsers.
  const c = browserWith({ answers: { subscribe: [409, { error: 'This browser follows as many accounts as it may' }] } }), q = panelWith(c);
  q.ui.render(ACCOUNT, state()); await q.ui.idle();
  await q.$('alerts-turn-on').fire('click');
  assert.deepEqual(q.said.at(-1), [WORDS.failed, 'error']);
});

test('K-4: the panel tells alerts.mjs how many actions this browser sent since its marker, from the page', async () => {
  const counted = [], storage = new Storage();
  const p = panelWith(browserWith(), { storage, extra: { sentSince: nonce => { counted.push(nonce); return 0; } } });
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  assert.deepEqual(counted, [], 'a first look has no marker to count from');
  p.ui.render({ ...ACCOUNT, nonce: '11' }, state(row(), { ...ACCOUNT, nonce: '11' })); await p.ui.idle();
  assert.deepEqual(counted, ['7']);
  const item = p.view().list.find(line => line.startsWith('Actions were signed with your keys'));
  assert.ok(item && item.includes('Urgent') && item.includes('4 actions were signed with your keys since you last looked here. This browser sent none of them.'), item);
});

test('a proof refused for a stale challenge (the service restarted) is made once more with a new challenge; a frozen account is not asked again', async () => {
  const stale = [403, { error: 'This challenge expired or was used already: ask for a new one' }];
  const challenges = b => b.calls.filter(c => c[1] === '/alerts/v1/challenge').length;
  // Refused once, then taken: on, after two challenges.
  let subscribeAnswers = [stale, [200, { subscribed: true, account: '14' }]];
  const b = browserWith({ answers: { subscribe: () => subscribeAnswers.shift() } }), p = panelWith(b);
  p.ui.render(ACCOUNT, state()); await p.ui.idle();
  await p.$('alerts-turn-on').fire('click');
  assert.deepEqual([p.view().state, challenges(b), b.calls.filter(c => c[1] === '/alerts/v1/subscribe').length], [WORDS.on, 2, 2]);
  // Refused twice: the plain failure, and no third try.
  subscribeAnswers = [stale, stale];
  const c = browserWith({ answers: { subscribe: () => subscribeAnswers.shift() } }), q = panelWith(c);
  q.ui.render(ACCOUNT, state()); await q.ui.idle();
  await q.$('alerts-turn-on').fire('click');
  assert.deepEqual([q.said.at(-1), challenges(c)], [[WORDS.failed, 'error'], 2]);
  // A frozen account: told so, after one challenge.
  const d = browserWith({ answers: { subscribe: [403, { error: 'The account was not proven: The account is frozen: nobody signs in until the freeze ends or its keys are replaced' }] } }), r = panelWith(d);
  r.ui.render(ACCOUNT, state()); await r.ui.idle();
  await r.$('alerts-turn-on').fire('click');
  assert.deepEqual([r.said.at(-1), challenges(d)], [[WORDS.frozen, 'error'], 1]);
  // "On every browser" the same way.
  let unsubscribeAnswers = [stale, [200, { removed: 2 }]];
  const e = browserWith({ answers: { unsubscribe: () => unsubscribeAnswers.shift() } }), s = panelWith(e);
  s.ui.render(ACCOUNT, state()); await s.ui.idle();
  await s.$('alerts-off-everywhere').fire('click');
  assert.deepEqual([s.said.at(-1), challenges(e)], [[PANEL.offEverywhere, ''], 2]);
});
