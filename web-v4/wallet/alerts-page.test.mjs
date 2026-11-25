// The Alerts panel on Home with the real app.js (alerts-ui.mjs wired in by app.js), on the stand-in page of
// protection-card.test.mjs (copied from there: a page that makes its elements on demand, a browser storage, the real
// SDK and wallet modules, a stand-in for the compiled verifier and a gateway that answers from a mock chain), with a
// stand-in EventSource. What is held here: nothing of it on the start screen; the first look stores the marker; a
// state with something waiting gives the banner and the list, and "I have seen these" stores the marker; the live hint
// reads the account again without a press; locking closes the stream and leaves nothing on the page. The switch's
// states and refusals, with a stand-in browser that has push, are in alerts-ui.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';

const root = new URL('../../', import.meta.url);
const verifierStub = 'data:text/javascript,' + encodeURIComponent('const v=()=>globalThis.standInVerifier;' + ['verifyTrust', 'verifyLightUpdate', 'verifyViewProof', 'verifyReceipt', 'verifyFastReceipt'].map(name => `export const ${name}=(...given)=>v().${name}(...given);`).join(''));
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '/sdk/proof-verifier.js') return { url: verifierStub, shortCircuit: true };
  return next(specifier === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : specifier, context);
} });
await import(new URL('client-v4/time-sdk.js', root).href);
const { markerKey } = await import(new URL('web-v4/wallet/alerts.mjs', root).href);
const { WORDS } = await import(new URL('web-v4/wallet/alerts-push.mjs', root).href);
const { PANEL, SHOWN_PREFIX } = await import(new URL('web-v4/wallet/alerts-ui.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');

// ------------------------------------------------------------------ a stand-in page, which can be loaded again
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', files: [], classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); } remove() {} click() {}
  showModal() { this.open = true; } close() { this.open = false; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map();
const storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const textOf = el => (typeof el === 'string' ? el : [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ')).replace(/\s+/g, ' ').trim();
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener() {}, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: (name, options, fn) => fn() }, clipboard: { writeText: async () => {} } } });
globalThis.window = { addEventListener() {}, opener: null, print() {} };
globalThis.location = { origin: 'https://wallet.example', pathname: '/' };
globalThis.isSecureContext = true;
globalThis.hashwasm = { argon2id };
globalThis.BroadcastChannel = undefined;
globalThis.setInterval = fn => { intervals.push(fn); return intervals.length; };
globalThis.clearInterval = id => { if (id) intervals[id - 1] = null; };
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...given) => { const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
/// The browser's EventSource, as far as the page uses it: each stream the page opens, which the test can make speak.
const streams = [];
globalThis.EventSource = class {
  constructor(url) { this.url = url; this.listeners = {}; this.readyState = 0; this.closed = false; streams.push(this); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  emit(type, data) { if (type === 'open') this.readyState = 1; for (const fn of this.listeners[type] || []) fn({ data }); }
  close() { this.closed = true; this.readyState = 2; }
};
const until = async (condition, what) => { for (let turn = 0; turn < 4000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a mock chain behind a gateway
const NET = 'c6'.repeat(32), GENESIS = 1700000000000000n, HOUR = 3600000000n, DAY = 24n * HOUR;
const PASSWORD = 'correct horse battery staple 41';
const chain = { height: 900, now: 100n * DAY, security: {}, reads: 0, accounts: [{ id: '2', name: 'bob', balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '2'.repeat(64), can_manage: true, can_spend: true }] }] };
function stateFor(query) {
  const ids = query.ids || [], names = query.names || [];
  const state = { protocol_version: '4', network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000', all_new_time_to_validators: true },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: [],
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name)), recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, null])) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = null;
  return structuredClone(state);
}
const block = height => ({ signed_header: { header: { height: String(height) } } });
globalThis.standInVerifier = {
  verifyTrust: async () => ({}),
  verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
  verifyViewProof: async (_proof, _trust, query) => { chain.reads += 1; return { verified: true, completeAccountSet: false, state: stateFor(query) }; },
  verifyReceipt: async () => { throw new Error('no receipts here'); }, verifyFastReceipt: async () => { throw new Error('no receipts here'); },
};
const fetched = [];
globalThis.fetch = async (url) => {
  const address = new URL(String(url), location.origin), route = address.pathname; fetched.push(route);
  const trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  let answer;
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/notifications') answer = { items: [] };
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 404 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ carol_p, protected, whose login key this browser holds
const { newDevice, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const login = await newDevice();
chain.accounts.push({ id: '14', name: 'carol_p', balance: '9000000', nonce: '7', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: '5'.repeat(64), can_manage: false, can_spend: true }, { public_key: '6'.repeat(64), can_manage: true, can_spend: false }, { public_key: '7'.repeat(64), can_manage: true, can_spend: false }] });
const freshRow = () => ({ account: '14', version: '1', policy: { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '600000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null });
chain.security['14'] = freshRow();
storage.setItem(`timecurrency.vault.v1:${NET}:carol_p`, JSON.stringify(await sealLegacy({ ...login.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId: NET, name: 'carol_p', publicKey: login.publicKey }, argon2id)));

let pages = 0;
async function freshPage() {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map();
  for (const id of HIDDEN) $(id).hidden = true;
  await import(new URL(`web-v4/wallet/app.js?alerts=${++pages}`, root).href);
  await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
}
async function unlock(name) {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; await $('auth-form').fire('submit');
  await until(() => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser', `the dashboard of ${name}`);
}
const panel = () => ({ shown: !$('alerts-panel').hidden, banner: $('alerts-banner').hidden ? null : $('alerts-banner').textContent, list: $('alerts-list').children.map(textOf), none: !$('alerts-none').hidden, confirm: !$('alerts-confirm').hidden, live: $('alerts-live').textContent, state: $('alerts-switch-state').textContent, why: $('alerts-switch-why').hidden ? '' : $('alerts-switch-why').textContent });
const marker = () => storage.getItem(markerKey(NET, '14'));

await freshPage();

test('the page: the banner and the panel are at the top of Home, above the balance, with the ids the wallet and the browser check use', () => {
  const home = page.slice(page.indexOf('id="panel-home"'), page.indexOf('id="panel-send"'));
  const at = id => home.indexOf(`id="${id}"`);
  for (const id of ['alerts-banner', 'alerts-panel', 'alerts-list', 'alerts-confirm', 'alerts-live', 'alerts-none', 'alerts-switch-state', 'alerts-turn-on', 'alerts-turn-off', 'alerts-off-everywhere', 'alerts-switch-why', 'alerts-switch-what']) assert.ok(at(id) > 0, id);
  assert.ok(at('alerts-banner') < at('alerts-panel') && at('alerts-panel') < home.indexOf('class="card balance-card"') && at('alerts-panel') < at('protect-card'), 'above the balance and every other card of Home');
  assert.match(home, /<p id="alerts-banner" class="alerts-banner" role="alert" hidden><\/p>/);
  assert.match(home, /<p id="alerts-none" class="subtle" hidden>Nothing needs your attention\.<\/p>/);
  assert.match(home, /<button id="alerts-confirm" type="button" class="secondary" hidden>I have seen these<\/button>/);
  assert.equal(PANEL.none, 'Nothing needs your attention.');
  assert.equal(PANEL.confirm, 'I have seen these');
  // No style and no script in the page's own markup: the panel is drawn by the stylesheet and alerts-ui.mjs.
  assert.doesNotMatch(home, /style=|onclick=|<script/);
});

test('on the start screen nothing of the alerts shows; opened, the first look stores the marker and shows what is true now, and the stream follows the account', async () => {
  assert.deepEqual([$('alerts-panel').hidden, $('alerts-banner').hidden, $('alerts-list').children.length], [true, true, 0]);
  assert.equal(marker(), null);
  await unlock('carol_p');
  const first = panel();
  assert.deepEqual([first.shown, first.banner, first.none, first.confirm, first.list], [true, null, true, false, []]);
  assert.ok(marker() !== null, 'the first look stored the marker');
  assert.deepEqual(JSON.parse(marker()).account, '14');
  assert.equal(storage.getItem(SHOWN_PREFIX + `${NET}:14`), null, 'nothing was confirmed');
  assert.deepEqual(streams.filter(s => !s.closed).map(s => s.url), ['/v1/touches?account=14']);
  // This stand-in browser has no service worker: the switch says so, and offers nothing.
  assert.deepEqual([first.state, first.why], [WORDS.off, WORDS.unsupported]);
  assert.ok(!fetched.includes('/alerts/v1/key'), 'a browser that cannot have alerts does not ask the service');
});

test('something waits on the chain: the banner and the list; "I have seen these" stores the marker and the banner goes; reading again confirms nothing', async () => {
  const before = marker();
  chain.security['14'] = { ...freshRow(), next_id: '2', pending_payments: [{ id: '1', to: '2', amount: '900000000', ready_elapsed_micros: String(chain.now + 47n * HOUR) }] };
  await $('refresh').fire('click');
  await until(() => panel().banner === 'A payment is waiting', 'the banner');
  const shown = panel();
  assert.equal(shown.list.length, 1);
  assert.match(shown.list[0], /^A payment is waiting Urgent A payment of 900 seconds to account 2 is waiting\. .* cancel it now on Home, under “Waiting on your account”/);
  assert.deepEqual([shown.none, shown.confirm], [false, true]);
  for (let i = 0; i < 3; i++) await $('refresh').fire('click');
  assert.equal(marker(), before, 'reads store nothing');
  await $('alerts-confirm').fire('click');
  const after = panel();
  assert.deepEqual([after.banner, after.confirm, after.list.length], [null, false, 1]);
  assert.notEqual(marker(), before);
  assert.deepEqual(JSON.parse(storage.getItem(SHOWN_PREFIX + `${NET}:14`)), ['14:payment-waiting:1']);
});

test('live: a touch reads the account again without a press, and the panel shows what the new state says', async () => {
  const stream = streams.find(s => !s.closed);
  stream.emit('open');
  assert.equal(panel().live, PANEL.live);
  const reads = chain.reads;
  // The account is frozen meanwhile: nobody pressed anything here.
  chain.security['14'] = { ...chain.security['14'], freezes: '1', frozen_until_elapsed_micros: String(chain.now + 40n * HOUR), pending_payments: [] };
  stream.emit('touch', JSON.stringify({ source: 'index', proven: false, account: '14', height: String(chain.height + 1) }));
  await until(() => panel().banner === 'Your account is frozen', 'the live read');
  assert.ok(chain.reads > reads);
  assert.match(panel().list[0], /^Your account is frozen Urgent /);
  // A touch for another account reads nothing.
  const now = chain.reads;
  stream.emit('touch', JSON.stringify({ source: 'index', proven: false, account: '15', height: '1' }));
  await new Promise(resolve => realTimeout(resolve, 50));
  assert.equal(chain.reads, now);
});

test('locked: the stream is closed and nothing of the alerts stays on the page; opened again, the same marker is read, not stored anew', async () => {
  const kept = marker();
  await $('lock-button').fire('click');
  assert.ok(streams.every(s => s.closed), 'every stream is closed');
  const after = panel();
  assert.deepEqual([after.shown, after.banner, after.list, after.live, after.state], [false, null, [], '', '']);
  await unlock('carol_p');
  assert.equal(marker(), kept);
  assert.equal(panel().banner, 'Your account is frozen', 'an alert not confirmed is shown again');
  assert.equal(streams.filter(s => !s.closed).length, 1);
});

test('the history this browser kept can no longer be read (keys made by a recovery, a store replaced): it starts empty, the actions this browser sent are not called signed elsewhere, and counting starts again from there', async () => {
  const actions = () => panel().list.filter(line => line.startsWith('Actions were signed with your keys'));
  // This browser sent the three actions since the marker (nonces 8 to 10): its activity keeps them, as an earlier version
  // kept it in the clear (encrypted at this unlock, locked-store.mjs).
  await $('lock-button').fire('click');
  assert.equal(JSON.parse(marker()).nonce, '7');
  const sent = [8, 9, 10].map(n => ({ hash: n.toString(16).padStart(2, '0').repeat(32).toUpperCase(), height: String(900 + n), label: 'Send 1 s to @bob', at: n, nonce: String(n) }));
  storage.setItem(`timecurrency.activity.v1:${NET}:carol_p`, JSON.stringify(sent));
  chain.accounts.find(a => a.id === '14').nonce = '10';
  await unlock('carol_p');
  assert.deepEqual(actions(), [], 'the three are this browser\'s own');
  assert.equal(storage.getItem(`timecurrency.activity.v1:${NET}:carol_p`), null);
  // The history cannot be read any more: the wrapped key of the store is gone. Without the start it knows, the page would
  // count none of the three as its own, and say that three actions were signed elsewhere.
  await $('lock-button').fire('click');
  storage.removeItem(`timecurrency.store-key.v1:${NET}:carol_p`);
  await unlock('carol_p');
  assert.deepEqual(actions(), [], 'no alert about actions this browser may have sent');
  assert.equal(textOf($('activity-list')), 'Nothing from this browser yet.');
  // Once the owner has seen the state of now, an action signed elsewhere is told again.
  await $('alerts-confirm').fire('click');
  assert.equal(JSON.parse(marker()).nonce, '10');
  chain.accounts.find(a => a.id === '14').nonce = '11';
  await $('refresh').fire('click');
  await until(() => actions().length === 1, 'the alert about the action signed elsewhere');
  assert.match(actions()[0], /1 action was signed with your keys since you last looked here\. This browser sent none of them\./);
});

test('a session that keeps its history in the page\'s memory only (what the browser keeps opens with another login key of this browser) counts no action as signed elsewhere: it cannot see what other tabs sent', async () => {
  const actions = () => panel().list.filter(line => line.startsWith('Actions were signed with your keys'));
  const { createPrivateStore } = await import(new URL('web-v4/wallet/locked-store.mjs', root).href);
  await $('lock-button').fire('click');
  // A login key kept aside for a change of keys (as "Someone has my login" leaves it until the network has it) holds the
  // store; carol_p's own login key has no wrap there, so her session keeps its history in memory only.
  const aside = await newDevice(globalThis.crypto, { networkId: NET, name: 'carol_p' });
  storage.setItem(`timecurrency.vault-next.v1:${NET}:carol_p:signin`, JSON.stringify(await sealLegacy({ pkcs8: aside.secret.pkcs8 }, PASSWORD, { networkId: NET, name: 'carol_p', publicKey: aside.publicKey }, argon2id, globalThis.crypto, 'signin')));
  const theirs = createPrivateStore({ storage });
  await theirs.open({ networkId: NET, name: 'carol_p', publicKey: aside.publicKey, storageKey: aside.storageKey }); theirs.close(); await theirs.flushed();
  await unlock('carol_p');
  assert.deepEqual(Object.keys(JSON.parse(storage.getItem(`timecurrency.store-key.v1:${NET}:carol_p`)).wraps), [aside.publicKey], 'the store stays the kept key\'s');
  await $('alerts-confirm').fire('click');
  const seen = JSON.parse(marker()).nonce;
  // Three actions on the chain since: another tab of this browser may have sent them, and this session cannot know.
  chain.accounts.find(a => a.id === '14').nonce = String(BigInt(seen) + 3n);
  const reads = chain.reads;
  await $('refresh').fire('click');
  assert.ok(chain.reads > reads, 'the account was read again');
  assert.deepEqual(actions(), [], 'no alert about actions this session cannot account for');
  storage.removeItem(`timecurrency.vault-next.v1:${NET}:carol_p:signin`);
});
