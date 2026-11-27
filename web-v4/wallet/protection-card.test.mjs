// The card "Protection" on Home (index.html; security-ui.mjs; protection.mjs), and the limit that "Protect my account"
// suggests.
//
// The real app.js on the stand-in page of name-warning.test.mjs (copied from there: a page that makes its elements on
// demand, a browser storage, the real SDK and wallet modules, a stand-in for the compiled verifier and a gateway that
// answers from a mock chain). Added here:
// - the page starts as index.html does: whatever carries `hidden` there is hidden, and it knows its screens, so that a
//   test sees which one is shown;
// - the mock chain applies the actions of a protected account by tests/mock-security-chain.mjs, which is a reading of
//   the engine's rules and not the engine (see there), and can be moved on in time.
// No browser runs here: that a switch can be tapped and read on a phone is for a person to see (the wallet's README).
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
const SDK = globalThis.TimeSDK;
const security = await import(new URL('client-v4/account-security.mjs', root).href);
const P = await import(new URL('web-v4/wallet/protection.mjs', root).href);
const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const { createSecurityChain, level } = await import(new URL('web-v4/wallet/tests/mock-security-chain.mjs', root).href);
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
  focus() { focused = this.id; } select() {} scrollIntoView() {}
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map(), focused = '';
const storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const textOf = el => [el.textContent, ...(el.children || []).map(textOf)].filter(Boolean).join(' ');
// The screens of the page (index.html, class "workspace-panel"), and what the page hides until its script shows it.
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
// The button of a review works only after a short delay (app.js, REVIEW_ARM_MS). Here the timer of that delay waits
// for the test (`armed`), as in name-warning.test.mjs, so that nothing asserted about the button races a clock.
const ARM_MS = Number(/\nconst REVIEW_ARM_MS = ([0-9]+);/.exec(await readFile(new URL('./app.js', import.meta.url), 'utf8'))?.[1]);
assert.ok(ARM_MS > 0, 'app.js names the delay of a review');
const arming = [];
globalThis.setTimeout = (fn, ms, ...given) => { if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; } const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer; };
const until = async (condition, what) => { for (let turn = 0; turn < 4000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a mock chain behind a gateway
const NET = 'c6'.repeat(32), GENESIS = 1700000000000000n, HOUR = 3600000000n, DAY = 24n * HOUR, FEE = 1000n;
const PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const other = (id, name) => ({ id: String(id), name, balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: String(id % 10).repeat(64), can_manage: true, can_spend: true }] });
// The accounts of this chain. alice (5, one key) and carol_p (14, protected) are added below, with this browser's keys.
const chain = { height: 900, now: 100n * DAY, security: {}, included: new Map(), posted: [], accounts: [other(1, 'faucet'), other(2, 'bob')] };
const row = name => chain.accounts.find(item => item.name === name);
const secured = createSecurityChain({ sdk: SDK, security, networkId: NET, accounts: chain.accounts, rows: chain.security, fee: FEE });
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
/// One block that holds this signed action: of a protected account by the rules of mock-security-chain.mjs; else a
/// transfer of an account with one key.
async function include(tx) {
  const action = SDK.decodeAction(tx), from = chain.accounts.find(item => item.id === action.from);
  const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
  if (!from || !await crypto.subtle.verify('Ed25519', key, tx.slice(-64), tx.slice(0, -64))) throw new Error('invalid action signature');
  if (secured.takes(action)) await secured.apply(action, chain.now);
  else {
    const to = chain.accounts.find(item => item.id === action.payload.to);
    if (action.kind !== SDK.KINDS.transfer || !to || BigInt(action.nonce) !== BigInt(from.nonce) + 1n || !from.devices.some(d => d.public_key === action.publicKey && d.can_spend && d.can_manage)) throw new Error('refused');
    from.balance = String(BigInt(from.balance) - BigInt(action.payload.amount) - FEE); to.balance = String(BigInt(to.balance) + BigInt(action.payload.amount)); from.nonce = action.nonce;
  }
  chain.height += 1; chain.now += 1000000n;
  const hash = (await SDK.transactionHash(tx)).toUpperCase(); chain.included.set(hash, { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
  return hash;
}
const block = height => ({ signed_header: { header: { height: String(height) } } });
globalThis.standInVerifier = {
  verifyTrust: async () => ({}),
  verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
  verifyViewProof: async (_proof, _trust, query) => ({ verified: true, completeAccountSet: false, state: stateFor(query) }),
  verifyReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
  verifyFastReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
};
globalThis.fetch = async (url, options = {}) => {
  const address = new URL(String(url), location.origin), route = address.pathname;
  let answer;
  const trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  if (route === '/api/network') answer = { protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false };
  else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') answer = { light_block: block(chain.height) };
  else if (route === '/api/submit') { const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64')); chain.posted.push(SDK.decodeAction(tx)); try { answer = { hash: await include(tx) }; } catch (error) { answer = { error: error.message }; } }
  else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }; }
  else if (route === '/api/notifications') answer = { items: [] };
  else answer = { error: 'not served by this stand-in gateway' };
  return { ok: !answer.error, status: answer.error ? 400 : 200, text: async () => JSON.stringify(answer), json: async () => answer };
};

// ------------------------------------------------------------------ the wallet: alice with one key, carol_p protected
const { newDevice, hex } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const aliceKey = await newDevice(), login = await newDevice(), spend = await newDevice(), phrase = await newDevice();
// A recovery sheet as the wallet makes one: its words on paper, and the key they give.
const sheetSeed = F.newSheetSeed(), SHEET = await F.encodeSheet(sheetSeed), sheet = await F.keyFromSeed(sheetSeed);
chain.accounts.push({ id: '5', name: 'alice', balance: '9000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: aliceKey.publicKey, can_manage: true, can_spend: true }] });
// The account as "Protect my account" leaves it: this browser's key is the login key, a payment key is kept under the payment password, two recovery keys on paper.
const LIMIT = 600000000n;
chain.accounts.push({ id: '14', name: 'carol_p', balance: '9000000', nonce: '7', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }, { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }] });
const freshRow = () => ({ account: '14', version: '1', policy: { threshold: '2', daily_limit_micros: LIMIT.toString(), delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: LIMIT.toString(), allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null });
chain.security['14'] = freshRow();
const vault = async (name, device) => storage.setItem(`timecurrency.vault.v1:${NET}:${name}`, JSON.stringify(await sealLegacy({ ...device.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId: NET, name, publicKey: device.publicKey }, argon2id)));
await vault('alice', aliceKey); await vault('carol_p', login);
storage.setItem(`timecurrency.spend-vault.v1:${NET}:carol_p`, JSON.stringify(await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'carol_p', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')));
const pauseRecord = () => { const raw = storage.getItem(P.pauseKey(NET, 'carol_p')); return raw === null ? null : JSON.parse(raw); };
const mine = () => chain.security['14'];
const postedBy = action => (action.publicKey === spend.publicKey ? 'payment key' : action.publicKey === sheet.publicKey ? 'recovery sheet' : action.publicKey === login.publicKey ? 'login key' : 'another key');

let pages = 0;
/// Loads the wallet's page again, as a reload does: the page before it is locked and its elements are gone; the storage stays.
async function freshPage() {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map(); focused = '';
  for (const id of HIDDEN) $(id).hidden = true;
  await import(new URL(`web-v4/wallet/app.js?card=${++pages}`, root).href);
  await until(() => /^Connected to the Time test network/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
  assert.match($('notice').textContent, /^Connected to the Time test network/);
}
async function unlock(name) {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = PASSWORD; await $('auth-form').fire('submit');
  await until(() => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser', `the dashboard of ${name}`);
}
/// "Check again" on Home: a verified read, after which every screen is drawn from it.
const refreshNow = async () => { await $('refresh').fire('click'); };
/// The time of the chain as the page writes it.
const when = at => new Date(Number((GENESIS + BigInt(at)) / 1000n)).toLocaleString();

// ------------------------------------------------------------------ a review, as a person meets it
const opened = () => until(() => $('review-dialog').open, 'the review');
const armed = async () => { assert.ok(arming.length > 0, 'a review set the timer of its delay'); for (const fire of arming.splice(0)) fire(); };
async function close(button) { $('review-dialog').returnValue = button; $('review-dialog').open = false; await $('review-dialog').fire('close'); }
async function tick() { $('review-ack').checked = true; await $('review-ack').fire('change'); }
/// The open review: its title, its fields, and its box and button.
function shown() {
  const list = $('review-body').children.find(item => item.id === 'dl'), fields = {};
  for (let at = 0; at + 1 < (list?.children.length ?? 0); at += 2) fields[list.children[at].textContent] = list.children[at + 1].textContent;
  return { title: $('review-title').textContent, confirm: $('review-confirm').textContent, fields, asks: $('review-ack-wrap').hidden ? null : $('review-ack-text').textContent, disabled: $('review-confirm').disabled };
}
/// The end of what a press started: the wallet says something that is not "busy", and no review is open.
const settled = what => until(() => !$('review-dialog').open && !$('notice').className.includes('busy') && $('notice').textContent !== '', what);
/// Presses something that leads to a review, and waits for the review. What it gives back waits for the end of what
/// was pressed when called (the promise itself would be waited for here, before the review is answered).
async function reviewAfter(press) { $('notice').textContent = ''; $('notice').className = 'notice'; const running = press(); await opened(); return () => running; }
/// Confirms the open review once its button can be pressed (ticking its box if it has one), and waits for the wallet's answer.
async function confirm({ ticked = true } = {}) { const seen = shown(); if (seen.asks && ticked) await tick(); await armed(); await close('confirm'); await settled(`the end of "${seen.title}"`); return seen; }
async function cancel() { const seen = shown(); await close('cancel'); await settled(`the end of "${seen.title}"`); return seen; }
/// A person moves a switch: the browser turns the box, and tells the page.
async function flip(id) { $(id).checked = !$(id).checked; await $(id).fire('change'); }
/// What the Protection card shows.
const card = () => ({ shown: !$('protect-card').hidden, none: !$('protect-none').hidden, on: !$('protect-on').hidden, status: $('protect-status').textContent, alert: /\bwarning\b/.test($('protect-status').className),
  freeze: [$('freeze-switch').checked, $('freeze-switch-state').textContent], pause: [$('pause-switch').checked, $('pause-switch-state').textContent], bar: $('limit-bar').value, limit: $('limit-text').textContent, waiting: $('protect-waiting').textContent });
const steps = () => ['freeze-form', 'unfreeze-form', 'limit-form', 'pause-form', 'resume-step'].filter(id => !$(id).hidden);
const waitingRows = () => $('security-inbox').children.map(item => textOf(item.children[0]));
const cancelButton = title => $('security-inbox').children.find(item => textOf(item.children[0]).startsWith(title)).children.find(item => item.textContent === 'Cancel');

await freshPage();

test('the page: the card is on Home with real switches, their labels and one sentence about switching off; what it covers is not under "Change something" as well', async () => {
  const home = page.slice(page.indexOf('id="panel-home"'), page.indexOf('id="panel-send"')), change = page.slice(page.indexOf('id="keys-change"'), page.indexOf('id="panel-more"'));
  assert.match(home, /<section class="card protect" id="protect-card" aria-labelledby="protect-title" hidden>\s*<h2 id="protect-title">Protection<\/h2>/);
  // Each switch is a checkbox with the role of a switch, inside the label that names it: the browser gives it its state, the keyboard and the tap on the whole row.
  for (const [id, name] of [['freeze-switch', 'Freeze'], ['pause-switch', 'Pause payments']]) {
    assert.match(home, new RegExp(`<label class="switch-row" for="${id}"><span class="switch-name">${name}</span><span class="switch-state" id="${id}-state" aria-hidden="true">Off</span><input id="${id}" class="switch" type="checkbox" role="switch" autocomplete="off" aria-describedby="[a-z-]+"></label>`));
  }
  assert.match(home, /<button id="limit-open" type="button" class="secondary" aria-label="Change the daily limit">Change<\/button>/);
  assert.match(home, /<progress id="limit-bar" class="bar" max="1000" value="0" aria-labelledby="limit-title" aria-describedby="limit-text"><\/progress>/);
  assert.match(home, /<p id="protect-rule" class="protect-rule">Switching protection on is immediate; switching it off waits, or needs a recovery paper, because nobody can reverse a theft here, so a thief who has your payment password must not be able to undo the protection\.<\/p>/);
  assert.match(home, /<p class="protect-status"><strong>Not protected yet<\/strong><\/p>\s*<p>One key can move everything, and a forgotten password cannot be replaced\.<\/p>\s*<div class="button-row"><button type="button" id="protect-start">Protect my account<\/button><\/div>/);
  // The list of what waits comes directly after the card: under it on a phone, at the top of the column beside it on a wide screen.
  assert.match(home, /<\/section>\s*<\/div>\s*<div class="home-side">\s*<div class="card" id="security-inbox-card" hidden>\s*<h2>Waiting on your account<\/h2>/);
  // Freeze, the end of a freeze and the daily limit are in the card, and nowhere else.
  for (const id of ['freeze-form', 'unfreeze-form', 'limit-form', 'pause-form', 'resume-step']) assert.equal(page.split(`id="${id}"`).length - 1, 1, id);
  for (const id of ['freeze-form', 'unfreeze-form', 'limit-form']) assert.ok(home.includes(`id="${id}"`) && !change.includes(`id="${id}"`), id);
  assert.deepEqual([...change.matchAll(/<h3>([^<]+)<\/h3>/g)].map(found => found[1]).filter(title => /^New /.test(title)), ['New login password', 'New recovery words', 'New payment password']);
  assert.doesNotMatch(change, /Freeze my account|<h3>Daily limit<\/h3>/);
  // The card and every step of it are hidden until the script has read the account.
  for (const id of ['protect-card', 'protect-none', 'protect-on', 'freeze-form', 'unfreeze-form', 'limit-form', 'pause-form', 'resume-step', 'freeze-more']) assert.ok(HIDDEN.includes(id), id);
  // The switches, the bar and the steps are drawn with the stylesheet's own colours: its variables, and none of their own.
  const styles = await readFile(new URL('./styles.css', import.meta.url), 'utf8');
  const palette = new Set([...styles.slice(styles.indexOf(':root {'), styles.indexOf('}', styles.indexOf(':root {'))).matchAll(/(--[a-z-]+):/g)].map(found => found[1]));
  const rules = styles.slice(styles.indexOf('/* Home: the Protection card.'), styles.indexOf('/* Lists of things */'));
  assert.ok(palette.has('--ink') && palette.has('--soft') && rules.includes('input.switch') && rules.includes('progress.bar') && rules.includes('.step {'), 'the stylesheet has the rules of the card');
  assert.doesNotMatch(rules, /#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/, 'no colour outside the palette');
  for (const [, name] of rules.matchAll(/var\((--[a-z-]+)\)/g)) assert.ok(palette.has(name), `${name} is a colour of the palette`);
  for (const [, property, value] of rules.matchAll(/[{;]\s*(background|color|border-color):\s*([^;}]+)[;}]/g)) assert.match(value.trim(), /^var\(--[a-z-]+\)$/, `${property}: ${value}`);
  // A switch is wide enough to see and its row tall enough to tap (2.75rem is 44 pixels); it shows when it has the focus and when it cannot be used.
  assert.match(rules, /^\.switch-row \{[^}]*min-height: 2\.75rem;[^}]*cursor: pointer;[^}]*\}$/m);
  assert.match(rules, /^input\.switch \{[^}]*width: 3\.5rem; height: 2rem;[^}]*\}$/m);
  assert.match(rules, /^input\.switch:checked \{[^}]*\}$/m); assert.match(rules, /^input\.switch:disabled \{[^}]*\}$/m);
  assert.match(styles, /^a:focus-visible, button:focus-visible, input:focus-visible,[^{]*\{ outline: 3px solid var\(--link\); outline-offset: 2px; \}$/m);
});

test('an account that is not protected yet: Home says so with one button, which opens "Protect my account" with a limit of 600 suggested; the account is used as before', async () => {
  await unlock('alice');
  assert.deepEqual([card().shown, card().none, card().on], [true, true, false]);
  assert.deepEqual([$('tab-home').textContent, $('send-payment-wrap').hidden, $('security-inbox-card').hidden], ['Home', true, true]);
  // The button: Keys, with the form open and the focus on its first field.
  await $('protect-start').fire('click');
  // This stand-in page cannot lock keys to a device: the wallet makes the passwords, and the first field is the limit.
  assert.deepEqual([$('panel-security').hidden, $('panel-home').hidden, $('secure-open').open, focused, $('secure-chosen').hidden], [false, true, true, 'secure-limit', true]);
  // The daily limit is there already, and said in words; both come from one constant.
  assert.equal(F.DEFAULT_DAILY_LIMIT_SECONDS, '600');
  assert.deepEqual([$('secure-limit').value, $('secure-limit-suggested').textContent], ['600', 'Suggested: 10 minutes of seconds a day (600). Change it if you like.']);
  // The page and the screens' script name no limit of their own: both take the constant.
  assert.doesNotMatch(page, /id="secure-limit"[^>]*(?:value|placeholder)=/, 'the page itself names no limit: the constant does');
  const ui = await readFile(new URL('./security-ui.mjs', import.meta.url), 'utf8');
  assert.equal(ui.split('DEFAULT_DAILY_LIMIT_SECONDS').length - 1, 2, 'imported once and used once');
  assert.doesNotMatch(ui, /['"`]600['"`]/);
  // Through the form with the suggested limit: the review states it. (It is cancelled here: this mock chain protects no account.)
  for (const id of ['secure-login', 'secure-login-confirm']) $(id).value = 'violet otters dance beneath moonlight 41';
  for (const id of ['secure-payment', 'secure-payment-confirm']) $(id).value = PAYMENT;
  $('secure-delay').value = $('secure-freeze').value = '48'; $('secure-threshold').value = '2';
  $('notice').textContent = ''; await $('secure-form').fire('submit');
  // The passwords the wallet made come first, in their dialog, before the words (the rule, vault.mjs RULE).
  await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the passwords the wallet made');
  assert.deepEqual([/^[a-z]{6}(-[a-z]{6}){3}$/.test($('made-login-shown').textContent), /^[a-z]{6}(-[a-z]{6}){3}$/.test($('made-payment-shown').textContent)], [true, true], $('notice').textContent);
  $('made-dialog').returnValue = 'done'; $('made-dialog').open = false; await $('made-dialog').fire('close');
  await until(() => $('secure-phrase-shown').textContent.length > 20 || $('notice').className.includes('error'), 'the recovery words');
  assert.match($('secure-phrase-shown').textContent, /^[a-z]{6}( [a-z]{6}){4}$/, $('notice').textContent);
  // The step: the five words, and the button that goes on, from the start. Nothing is asked back: the review comes next.
  assert.deepEqual([$('secure-submit').hidden, $('notice').textContent], [false, 'Write down your recovery words. They are shown only now.']);
  const running = await reviewAfter(() => $('secure-submit').fire('click')), seen = await cancel(); await running();
  assert.equal(seen.title, 'Protect my account');
  assert.match(seen.fields.Payments, /^Up to 600 seconds at once with your payment password, fees included\. The limit refills over 24 hours, so up to about 1200 seconds can leave in any 24 hours\. More waits 48 hours, or needs a recovery paper too\.$/);
  await $('secure-cancel').fire('click');
  // A limit the person typed stays theirs over the next reading of the account; an emptied field stays empty.
  $('secure-limit').value = '45'; await $('secure-limit').fire('input'); await refreshNow();
  assert.equal($('secure-limit').value, '45');
  $('secure-limit').value = ''; await refreshNow();
  assert.equal($('secure-limit').value, '');
  // Nothing of the card stands in the way of using the account: a payment goes out as before.
  const before = chain.posted.length;
  $('recipient').value = 'bob'; $('amount').value = '0.5';
  const paying = await reviewAfter(() => $('send-form').fire('submit')); await confirm(); await paying();
  assert.match($('notice').textContent, /^Sent\. @bob has the 0\.5 seconds now/);
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).kind], [1, SDK.KINDS.transfer]);
});

test('a protected account: the card reads its state from proven state: protected, nothing paused or frozen, what can be paid now out of the limit, nothing waiting', async () => {
  await $('lock-button').fire('click');
  assert.deepEqual([card().shown, card().status, card().freeze[0], card().pause[0], card().limit], [false, '', false, false, ''], 'a locked wallet shows nothing of the card');
  await unlock('carol_p');
  assert.deepEqual(card(), { shown: true, none: false, on: true, status: 'Your account is protected.', alert: false, freeze: [false, 'Off'], pause: [false, 'Off'], bar: 1000,
    limit: 'You can pay 600 of 600 seconds now without waiting, fees included.', waiting: 'Nothing is waiting.' });
  assert.equal($('freeze-note').textContent, 'For 48 hours: no payment with your payment password alone, and no sign-in to websites. It ends by itself. What is waiting is dropped.');
  assert.equal($('pause-note').textContent, 'While paused, nothing can be paid at once. A payment started then waits 48 hours and you can cancel it.');
  assert.deepEqual([steps(), $('freeze-more').hidden, $('limit-open').hidden, $('security-inbox-card').hidden, $('tab-home').textContent], [[], true, false, true, 'Home']);
  assert.deepEqual(['freeze-switch', 'pause-switch', 'limit-open'].map(id => $(id).disabled), [false, false, false]);
  // What was spent today shows in the bar and in the sentence; it is the chain's number, read again.
  mine().allowance_micros = '150000000'; mine().allowance_elapsed_micros = String(chain.now); await refreshNow();
  assert.deepEqual([card().bar, card().limit], [250, 'You can pay 150 of 600 seconds now without waiting, fees included. It refills over 24 hours.']);
  mine().allowance_micros = '900'; mine().allowance_elapsed_micros = String(chain.now); await refreshNow();
  assert.deepEqual([card().bar, card().limit], [0, 'Nothing can be paid right now: less than one fee is left of your 600 seconds a day. It refills over 24 hours.']);
  // The browser's own memory decides nothing: a remembered limit does not make the card say "paused".
  storage.setItem(P.pauseKey(NET, 'carol_p'), JSON.stringify({ limit: '5000000', at: Date.now() }));
  chain.security['14'] = freshRow(); await refreshNow();
  assert.deepEqual([card().pause, card().status], [[false, 'Off'], 'Your account is protected.']);
  storage.removeItem(P.pauseKey(NET, 'carol_p'));
});

test('"Change" opens the limit change, which says before anything is confirmed whether the new limit applies at once, waits, or applies at once with a recovery paper', async () => {
  await $('limit-open').fire('click');
  assert.deepEqual([steps(), focused], [['limit-form'], 'limit-amount']);
  const says = async (amount, paper = '') => { $('limit-amount').value = amount; $('limit-secret').value = paper; await $('limit-amount').fire('input'); return $('limit-when').textContent; };
  assert.equal(await says(''), '');
  assert.equal(await says('300'), 'Lower than now: it applies at once.');
  assert.equal(await says('600'), 'That is your limit now.');
  assert.equal(await says('900'), 'Higher than now: it waits 48 hours, and you can cancel it meanwhile. With a recovery paper it applies at once.');
  assert.equal(await says('900', SHEET), 'Higher than now, with a recovery paper: it applies at once. What is waiting is cancelled, and websites sign you out.');
  assert.equal(await says('0.001'), 'A limit must be above the network fee of 0.001 seconds. To stop payments, use “Pause payments”.');
  // A lower limit: one review that says "At once", signed by the payment key.
  const before = chain.posted.length;
  await says('300'); $('limit-payment').value = PAYMENT;
  let running = await reviewAfter(() => $('limit-form').fire('submit')), seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.fields.When, seen.confirm], ['Lower the daily limit', 'At once.', 'Lower the limit']);
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).kind, chain.posted.at(-1).payload, postedBy(chain.posted.at(-1)), mine().policy.daily_limit_micros, $('limit-payment').value, steps()], [1, 77, { daily_limit_micros: '300000000' }, 'payment key', '300000000', '', []]);
  // A higher one without a paper waits, and the card says so; with a paper it is in force at once.
  await $('limit-open').fire('click'); await says('600'); $('limit-payment').value = PAYMENT;
  running = await reviewAfter(() => $('limit-form').fire('submit')); seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.fields.When], ['Raise the daily limit', 'After 48 hours. You can cancel it meanwhile on Home, under “Waiting on your account”.']);
  assert.deepEqual([mine().policy.daily_limit_micros, mine().pending_limit.daily_limit_micros], ['300000000', '600000000']);
  assert.match(card().limit, / A raise to 600 seconds is waiting: it applies at /);
  assert.deepEqual([card().waiting, $('tab-home').textContent, $('security-inbox-card').hidden], ['1 change is waiting. See “Waiting on your account” below: each can be cancelled.', 'Home (1)', false]);
  await $('limit-open').fire('click'); await says('600', SHEET); $('limit-payment').value = PAYMENT; 
  running = await reviewAfter(() => $('limit-form').fire('submit')); seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.confirm, seen.fields['Approved by']], ['Raise the daily limit now', 'Raise the limit now', 'Your payment password and one recovery paper']);
  assert.equal(seen.fields.Also, 'What is waiting on your account (1 change) is cancelled. Websites sign you out.');
  const root = chain.posted.at(-1);
  assert.deepEqual([root.kind, root.payload.op.type, root.payload.op.policy.daily_limit_micros, root.payload.approvals.length, mine().policy.daily_limit_micros, mine().pending_limit, $('limit-secret').value], [73, 'replace', '600000000', 2, '600000000', null, '']);
  assert.match($('notice').textContent, /^Your daily limit is 600 seconds now\. What you can pay at once fills up over 24 hours\.$/);
  assert.deepEqual([card().waiting, $('tab-home').textContent], ['Nothing is waiting.', 'Home']);
});

test('pause on: the switch asks for the payment password only, signs a limit of exactly one fee at once, remembers the limit that was, and a payment started then waits', async () => {
  chain.security['14'] = freshRow(); row('carol_p').auth_epoch = '2'; await refreshNow();
  const before = chain.posted.length;
  // The switch shows what the chain says: pressed, it goes back and opens its step.
  await flip('pause-switch');
  assert.deepEqual([$('pause-switch').checked, steps(), focused, chain.posted.length], [false, ['pause-form'], 'pause-payment', before]);
  assert.equal($('pause-step-note').textContent, 'Sets your daily limit to 0.001 seconds, the fee of one action, at once: nothing can be paid at once. A payment started while paused waits 48 hours and you can cancel it. Ending the pause waits 48 hours too, or needs a recovery paper, and what you can pay at once then fills up again over 24 hours. Seconds sent to you still arrive.');
  // A wrong payment password signs nothing and remembers nothing.
  $('pause-payment').value = 'not the payment password 7731';
  let running = await reviewAfter(() => $('pause-form').fire('submit')); await confirm(); await running();
  assert.deepEqual([chain.posted.length, pauseRecord(), $('notice').className.includes('error'), $('pause-payment').value, card().pause], [before, null, true, '', [false, 'Off']]);
  // The right one. The review says what the pause is and how it ends.
  $('pause-payment').value = PAYMENT;
  running = await reviewAfter(() => $('pause-form').fire('submit'));
  const seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.confirm, seen.asks], ['Pause payments', 'Pause payments', null]);
  assert.deepEqual(seen.fields, {
    'Daily limit now': '600 seconds a day',
    'While paused': 'Your payment password alone can pay nothing at once. A payment started then waits 48 hours, and you can cancel it.',
    How: 'The limit becomes 0.001 seconds, the fee of one action: enough to start one payment that waits, or to ask for your limit back, once a day.',
    'To end the pause': 'Your limit comes back after 48 hours of waiting, or at once with a recovery paper. What you can pay at once then fills up again over 24 hours.',
    Fee: '0.001 seconds' });
  // One action: the daily limit, set to the fee and not to zero, signed by the payment key.
  const sent = chain.posted.at(-1);
  assert.deepEqual([chain.posted.length - before, sent.kind, sent.payload, postedBy(sent)], [1, 77, { daily_limit_micros: FEE.toString() }, 'payment key']);
  assert.deepEqual([mine().policy.daily_limit_micros, mine().allowance_micros], ['1000', '1000']);
  // The limit the account had is remembered in this browser, and nothing else is.
  assert.deepEqual([pauseRecord().limit, Object.keys(pauseRecord()).sort()], [LIMIT.toString(), ['at', 'limit']]);
  // The card, from the state that proves it.
  assert.equal($('notice').textContent, 'Payments are paused. A payment started now waits 48 hours and you can cancel it.');
  assert.deepEqual(card(), { shown: true, none: false, on: true, status: 'Payments are paused.', alert: false, freeze: [false, 'Off'], pause: [true, 'On'], bar: 0, limit: 'Paused: nothing can be paid at once.', waiting: 'Nothing is waiting.' });
  assert.equal($('pause-note').textContent, 'Nothing can be paid at once. A payment started now waits 48 hours and you can cancel it.');
  assert.deepEqual([steps(), $('limit-open').hidden, $('security-limit').textContent], [[], true, '0.001 s']);
  // Keys does not name the paused limit as what the payment password pays.
  assert.match(textOf($('keys-cards')), /Payments are paused \(see Home\): it pays nothing at once now\./);
  assert.doesNotMatch(textOf($('keys-cards')), /Pays up to 0\.001 seconds/);
  // A payment now is not sent: it can only be made to wait, and it then waits on the chain.
  const bob = row('bob').balance;
  $('recipient').value = 'bob'; $('amount').value = '0.5'; $('send-payment').value = PAYMENT; $('notice').textContent = '';
  await $('send-form').fire('submit');
  assert.deepEqual([$('send-over-limit').hidden, $('review-dialog').open, $('send-wait').disabled], [false, false, false]);
  assert.match($('send-wait-note').textContent, /^It waits 48 hours, then you send it from Home, under “Waiting on your account”\. Until then you can cancel it\.$/);
  $('send-payment').value = PAYMENT;
  running = await reviewAfter(() => $('send-wait').fire('click')); await confirm(); await running();
  assert.match($('notice').textContent, /^Your payment is waiting\. You can send it from Home after 48 hours\./);
  assert.deepEqual([chain.posted.at(-1).kind, chain.posted.at(-1).payload, mine().pending_payments.length, row('bob').balance], [75, { type: 'request', to: '2', amount: '500000' }, 1, bob]);
  // It is listed under the card with its "Cancel", and counted on Home.
  assert.deepEqual([card().waiting, $('tab-home').textContent, $('security-inbox-card').hidden, $('inbox-keys').hidden], ['1 payment is waiting. See “Waiting on your account” below: each can be cancelled.', 'Home (1)', false, false]);
  // The name of the account it goes to is read with a proof; this browser's own record says it was started here (W-5).
  await until(() => /@bob/.test(waitingRows()[0]), 'the name of the account the payment goes to');
  assert.match(waitingRows()[0], /^Waiting payment: 0\.5 seconds to @bob · account 2 Can be sent after .* Started in this browser\.$/);
  assert.equal(cancelButton('Waiting payment').textContent, 'Cancel');
  // The fee of that step used what the paused limit covers in a day: the card says when the next one fits.
  assert.match($('pause-note').textContent, /^Nothing can be paid at once\. A payment started now waits 48 hours and you can cancel it\. Starting one costs a fee, and your paused limit covers one fee a day: the next one in about 24 hours\.$/);
});

test('pause off: the limit that was is offered again, by waiting or at once with a recovery paper, and each way does what it says', async () => {
  const before = chain.posted.length;
  await flip('pause-switch');
  assert.deepEqual([$('pause-switch').checked, steps(), focused], [true, ['resume-step'], 'resume-payment'], 'the switch stays where the chain is');
  // The limit before the pause, from this browser's memory, as a number the person can change.
  assert.deepEqual([$('resume-amount').value, $('resume-amount-note').textContent], ['600', 'Your limit before the pause, as this browser remembers it: 600 seconds. Change it if you like.']);
  // Both ways are on the screen. Waiting is not possible this minute, and the step says why: the paused limit covers one fee a day.
  assert.match($('resume-wait-note').textContent, /^Not possible right now: asking costs a fee, and your paused limit covers one fee a day\. It covers the next one in about 24 hours\.$/);
  assert.deepEqual([$('resume-wait').disabled, $('resume-now').disabled], [true, false]);
  $('resume-payment').value = PAYMENT; $('notice').textContent = ''; await $('resume-wait').fire('click');
  assert.match($('notice').textContent, /^Not possible right now: asking costs a fee/);
  assert.equal(chain.posted.length, before);
  // A day later the limit covers a fee again: the way by waiting is open.
  chain.now += DAY; await refreshNow();
  assert.deepEqual([$('resume-wait').disabled, $('resume-wait-note').textContent, steps()], [false, 'Your limit comes back after 48 hours. You can cancel that meanwhile.', ['resume-step']]);
  $('resume-payment').value = PAYMENT;
  let running = await reviewAfter(() => $('resume-wait').fire('click')), seen = await confirm(); await running();
  const due = chain.now - 1000000n + 172800000000n;
  assert.deepEqual([seen.title, seen.confirm], ['End the pause after the waiting period', 'Ask for my limit back']);
  assert.deepEqual(seen.fields, { 'Daily limit': 'Back to 600 seconds a day', When: `After 48 hours, at about ${when(due)}. Until then payments stay paused, and you can cancel this under “Waiting on your account”.`, Then: 'What you can pay at once fills up over the following 24 hours.', Fee: '0.001 seconds' });
  assert.deepEqual([chain.posted.at(-1).kind, chain.posted.at(-1).payload, postedBy(chain.posted.at(-1))], [77, { daily_limit_micros: LIMIT.toString() }, 'payment key']);
  // Asked for, not yet in force: the account is still paused, and the card says until when.
  assert.deepEqual([mine().policy.daily_limit_micros, mine().pending_limit.daily_limit_micros, mine().pending_limit.ready_elapsed_micros], ['1000', LIMIT.toString(), due.toString()]);
  assert.deepEqual([card().pause, card().status, card().waiting, steps()], [[true, 'On'], 'Payments are paused.', '1 payment and 1 change are waiting. See “Waiting on your account” below: each can be cancelled.', []]);
  assert.ok($('pause-note').textContent.includes(` The pause ends at ${when(due)} (about 48 hours): your limit is then 600 seconds.`), $('pause-note').textContent);
  assert.match(waitingRows().join(' | '), /Waiting raise of the daily limit to 600 seconds Applies at /);
  // The other way, at once: the payment password and one recovery paper.
  await flip('pause-switch');
  assert.deepEqual([steps(), $('resume-amount').value], [['resume-step'], '600']);
  $('resume-payment').value = PAYMENT; $('resume-secret').value = SHEET;
  running = await reviewAfter(() => $('resume-now').fire('click')); seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.confirm], ['End the pause now with a recovery paper', 'End the pause now']);
  assert.deepEqual(seen.fields, { 'Daily limit': '600 seconds a day, at once (now 0.001 seconds)', 'Approved by': 'Your payment password and one recovery paper',
    Also: 'What is waiting on your account (1 payment and 1 change) is cancelled. Websites sign you out.', Then: 'What you can pay at once starts at 0 seconds and fills up over 24 hours.', Fee: '0.001 seconds' });
  // One root operation: every key kept in its role, the policy as it was but for the limit, approved by the payment key and the sheet.
  const root = chain.posted.at(-1), account = row('carol_p');
  assert.deepEqual([root.kind, root.nonce, postedBy(root), root.payload.op.type], [73, '0', 'payment key', 'replace']);
  assert.deepEqual(root.payload.op.policy, { threshold: '2', daily_limit_micros: LIMIT.toString(), delay_seconds: '172800', freeze_seconds: '172800' });
  assert.deepEqual(root.payload.op.keys, [[login.publicKey, 'signin'], [spend.publicKey, 'spend'], [sheet.publicKey, 'recover'], [phrase.publicKey, 'recover']].map(([public_key, role]) => ({ public_key, role })).sort((a, b) => (a.public_key < b.public_key ? -1 : 1)));
  assert.deepEqual(root.payload.approvals.map(item => item.public_key).sort(), [spend.publicKey, sheet.publicKey].sort());
  assert.deepEqual(account.devices.map(d => d.public_key).sort(), [login.publicKey, spend.publicKey, sheet.publicKey, phrase.publicKey].sort(), 'no key changed');
  // The limit is restored at once; what was waiting is gone; what can be paid at once starts low and refills.
  assert.deepEqual([mine().policy.daily_limit_micros, mine().pending_limit, mine().pending_payments, account.auth_epoch], [LIMIT.toString(), null, [], '3']);
  assert.equal($('notice').textContent, 'Payments are no longer paused. Your daily limit is 600 seconds. What you can pay at once fills up over 24 hours.');
  assert.deepEqual([card().pause, card().status, card().waiting, $('security-limit').textContent, $('tab-home').textContent, steps(), $('limit-open').hidden], [[false, 'Off'], 'Your account is protected.', 'Nothing is waiting.', '600 s', 'Home', [], false]);
  assert.ok(level(mine(), chain.now) < 10000000n && card().bar < 20, 'the allowance was not filled by ending the pause');
  assert.deepEqual([pauseRecord(), $('resume-payment').value, $('resume-secret').value, $('resume-amount').value], [null, '', '', '']);
});

test('pause off in a browser that remembers no limit asks for the number, and a limit below the fee can only be ended with a recovery paper', async () => {
  // Paused from another browser: this one holds no record.
  chain.security['14'] = { ...freshRow(), policy: { ...freshRow().policy, daily_limit_micros: '1000' }, allowance_micros: '1000', allowance_elapsed_micros: String(chain.now) };
  storage.removeItem(P.pauseKey(NET, 'carol_p')); await refreshNow();
  assert.deepEqual([card().pause, card().status], [[true, 'On'], 'Payments are paused.']);
  await flip('pause-switch');
  assert.deepEqual([steps(), focused, $('resume-amount').value, $('resume-amount-note').textContent], [['resume-step'], 'resume-amount', '', 'This browser does not remember the limit you had before the pause. Enter the limit you want.']);
  const before = chain.posted.length;
  $('resume-payment').value = PAYMENT; $('notice').textContent = ''; await $('resume-wait').fire('click');
  assert.deepEqual([$('notice').textContent, chain.posted.length, $('resume-payment').value], ['Enter seconds with up to six decimal places.', before, '']);
  // With a number, the request is signed for that number.
  $('resume-amount').value = '45'; $('resume-payment').value = PAYMENT;
  const running = await reviewAfter(() => $('resume-wait').fire('click')), seen = await confirm(); await running();
  assert.deepEqual([seen.fields['Daily limit'], chain.posted.at(-1).payload], ['Back to 45 seconds a day', { daily_limit_micros: '45000000' }]);
  await $('resume-cancel').fire('click');
  // A limit of zero, as another wallet may set it: the card says what that is, and the way by waiting is closed.
  chain.security['14'] = { ...freshRow(), policy: { ...freshRow().policy, daily_limit_micros: '0' }, allowance_micros: '0', allowance_elapsed_micros: String(chain.now) }; await refreshNow();
  assert.deepEqual([card().pause, card().limit], [[true, 'On'], 'Paused: nothing can be paid at once.']);
  assert.equal($('pause-note').textContent, 'Your daily limit is 0 seconds, less than the fee of one action. Your payment password alone can neither pay nor start a payment that waits. It can still freeze the account and cancel what is waiting.');
  await flip('pause-switch');
  assert.deepEqual([$('resume-wait').disabled, $('resume-now').disabled, $('resume-wait-note').textContent], [true, false, 'Not possible: with a limit below the fee, your payment password alone cannot ask for a higher one.']);
  await $('resume-cancel').fire('click');
  assert.deepEqual(steps(), []);
});

test('the freeze switch: on at once with the payment password or a recovery paper; frozen, the card says until when, that it ends by itself and how it is kept on; off needs two keys', async () => {
  chain.security['14'] = freshRow(); await refreshNow();
  const before = chain.posted.length;
  await flip('freeze-switch');
  assert.deepEqual([$('freeze-switch').checked, steps(), focused, chain.posted.length], [false, ['freeze-form'], 'freeze-secret', before]);
  assert.equal($('freeze-step-note').textContent, 'Freezes the account for 48 hours. Your payment password with a recovery paper can still pay, and can end the freeze early. Seconds sent to you still arrive.');
  // With the payment password: one field, one review, one action that takes no nonce.
  $('freeze-method').value = 'payment'; $('freeze-secret').value = PAYMENT;
  let running = await reviewAfter(() => $('freeze-form').fire('submit')), seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.confirm], ['Freeze account', 'Freeze account']);
  assert.equal(seen.fields.Effect, 'No payment with your payment password alone and no sign-in to websites for 48 hours. Anything waiting is dropped.');
  assert.equal(seen.fields.Ends, 'By itself after 48 hours, or earlier with your payment password and one recovery paper. It is not renewed by itself: to keep the account frozen longer, freeze again in the second half of the freeze.');
  const until = BigInt(mine().frozen_until_elapsed_micros);
  assert.deepEqual([chain.posted.length - before, chain.posted.at(-1).kind, chain.posted.at(-1).nonce, postedBy(chain.posted.at(-1)), until], [1, 72, '0', 'payment key', chain.now - 1000000n + 172800000000n]);
  assert.equal($('notice').textContent, 'Your account is frozen. If you did not lose a device, replace the key that leaked.');
  // The card says it prominently, with the time it ends, and the truth about keeping it on.
  assert.deepEqual([card().status, card().alert, card().freeze, steps(), $('freeze-secret').value], [`Your account is frozen until ${when(until)} (about 48 hours).`, true, [true, 'On'], [], '']);
  assert.equal($('freeze-note').textContent, `It ends by itself at that time and is not renewed by itself. To keep the account frozen longer, freeze again after ${when(until - 86400000000n)}: a freeze can be renewed in its second half only.`);
  assert.deepEqual([$('freeze-more').hidden, $('freeze-again').hidden], [false, true], '"End the freeze" is offered; renewing is not, in the first half');
  assert.deepEqual([card().bar, card().limit], [0, 'Nothing can be paid with your payment password alone while the account is frozen. Your daily limit is 600 seconds.']);
  assert.equal($('security-title').textContent, 'Your account is frozen.');
  // Frozen, nothing else of the card can be switched: pausing and the limit are refused by the chain while frozen.
  assert.deepEqual(['freeze-switch', 'pause-switch', 'limit-open'].map(id => $(id).disabled), [false, true, true]);
  // In its second half the freeze can be renewed, and the card offers it.
  chain.now += 30n * HOUR; await refreshNow();
  assert.deepEqual([$('freeze-again').hidden, $('freeze-again').textContent], [false, 'Freeze for another 48 hours']);
  assert.equal($('freeze-note').textContent, 'It ends by itself at that time and is not renewed by itself. To keep the account frozen, freeze again now: the freeze then lasts 48 hours from that moment.');
  await $('freeze-again').fire('click');
  assert.deepEqual(steps(), ['freeze-form']);
  // This time with a recovery paper alone: it freezes too.
  $('freeze-method').value = 'paper'; $('freeze-secret').value = SHEET;
  running = await reviewAfter(() => $('freeze-form').fire('submit')); await confirm(); await running();
  assert.deepEqual([chain.posted.at(-1).kind, postedBy(chain.posted.at(-1)), mine().freezes, BigInt(mine().frozen_until_elapsed_micros)], [72, 'recovery sheet', '2', chain.now - 1000000n + 172800000000n]);
  // Switching it off: the switch stays on, and "End the freeze" asks for the payment password and one recovery paper.
  await flip('freeze-switch');
  assert.deepEqual([$('freeze-switch').checked, steps(), focused], [true, ['unfreeze-form'], 'unfreeze-payment']);
  await $('unfreeze-cancel').fire('click'); await $('unfreeze-open').fire('click');
  assert.deepEqual(steps(), ['unfreeze-form']);
  $('unfreeze-payment').value = PAYMENT; $('unfreeze-secret').value = SHEET;
  running = await reviewAfter(() => $('unfreeze-form').fire('submit')); seen = await confirm(); await running();
  assert.deepEqual([seen.title, seen.fields['Approved by'], chain.posted.at(-1).kind, chain.posted.at(-1).payload.op.type, chain.posted.at(-1).payload.approvals.length, mine().frozen_until_elapsed_micros], ['Unfreeze account', 'Your payment password and one recovery key', 73, 'unfreeze', 2, '0']);
  assert.deepEqual([card().status, card().alert, card().freeze, $('freeze-more').hidden, steps(), $('unfreeze-payment').value, $('unfreeze-secret').value], ['Your account is protected.', false, [false, 'Off'], true, [], '', '']);
  assert.deepEqual(['freeze-switch', 'pause-switch', 'limit-open'].map(id => $(id).disabled), [false, false, false]);
});

test('a step of the card that proven state has overtaken is closed with what was typed into it, and locking the wallet empties the card', async () => {
  // The pause step is open with a password typed; meanwhile the account is frozen from another device.
  await flip('pause-switch'); $('pause-payment').value = PAYMENT;
  assert.deepEqual(steps(), ['pause-form']);
  mine().frozen_until_elapsed_micros = String(chain.now + 172800000000n); await refreshNow();
  assert.deepEqual([steps(), $('pause-payment').value, card().freeze], [[], '', [true, 'On']]);
  // One step is open at a time: opening another closes the first and clears its fields.
  await $('unfreeze-open').fire('click'); $('unfreeze-payment').value = PAYMENT; $('unfreeze-secret').value = SHEET;
  mine().frozen_until_elapsed_micros = String(chain.now + 3600000000n); await refreshNow();
  await $('freeze-again').fire('click');
  assert.deepEqual([steps(), $('unfreeze-payment').value, $('unfreeze-secret').value], [['freeze-form'], '', '']);
  $('freeze-secret').value = 'typed and not sent';
  await $('lock-button').fire('click');
  assert.deepEqual([card().shown, card().status, card().freeze[0], card().pause[0], card().limit, card().waiting, steps(), $('freeze-secret').value, $('tab-home').textContent], [false, '', false, false, '', '', [], '', 'Home']);
  mine().frozen_until_elapsed_micros = '0';
});

test('an unfunded account sees the fee before unlocking; a signed limit survives reload and late receipts for both signing routes', async () => {
  const account = row('carol_p'), retained = new Set(), checks = [];
  let withhold = true;
  const waiting = hash => Object.assign(new Error('Receipt timed out.'), { code: 'TX_PENDING', hash });
  globalThis.TimeSDK = { ...SDK, createClient(options) {
    const client = SDK.createClient(options);
    return { ...client,
      async submit(tx, options) {
        const sent = await client.submit(tx, { ...options, wait: false });
        retained.add(sent.hash);
        throw waiting(sent.hash);
      },
      async waitReceipt(hash, options) {
        checks.push(hash);
        if (withhold) throw waiting(hash);
        return client.waitReceipt(hash, options);
      },
    };
  } };
  try {
    chain.security['14'] = freshRow(); account.balance = '0';
    await freshPage(); await unlock('carol_p');
    assert.equal($('limit-open').disabled, true);
    assert.equal($('limit-fee-note').hidden, false);
    assert.match($('limit-fee-note').textContent, /fee.*0\.001|0\.001.*fee/i);
    assert.match($('limit-fee-note').textContent, /Receive/);
    assert.ok($('limit-form').hidden);
    account.balance = '9000000'; await refreshNow();
    assert.equal($('limit-open').disabled, false);
    const pendingCheck = () => $('limit-pending').children[0].children.find(button => button.textContent === 'Check status');
    for (const [amount, paper, kind] of [['750', '', 77], ['900', SHEET, 73]]) {
      const before = chain.posted.length;
      withhold = true;
      await $('limit-open').fire('click'); $('limit-amount').value = amount;
      $('limit-payment').value = PAYMENT; $('limit-secret').value = paper;
      const run = await reviewAfter(() => $('limit-form').fire('submit')); await confirm(); await run();
      assert.equal(chain.posted.at(-1).kind, kind);
      assert.match($('notice').textContent, /Check status/);
      assert.ok(!$('notice').className.includes('error'));
      assert.ok($('limit-form').hidden && !$('limit-pending').hidden);
      const hash = [...retained].at(-1);
      assert.ok(textOf($('limit-pending')).includes(hash));
      await freshPage(); await unlock('carol_p');
      assert.equal($('limit-open').disabled, true);
      await pendingCheck().fire('click');
      assert.match($('notice').textContent, /still pending/);
      assert.ok(textOf($('limit-pending')).includes(hash));
      withhold = false; await pendingCheck().fire('click');
      assert.ok($('limit-pending').hidden);
      assert.match($('notice').textContent, kind === 77 ? /verified.*current daily limit is 600 seconds.*750 seconds is scheduled/i : /verified.*current daily limit is 900 seconds/i);
      assert.deepEqual(checks.slice(-2), [hash, hash]);
      assert.equal(chain.posted.length, before + 1, 'each status check reads only the original hash');
    }
  } finally { globalThis.TimeSDK = SDK; }
});
