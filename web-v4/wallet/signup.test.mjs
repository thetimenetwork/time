// Signing up protected (signup.mjs, signup-ui.mjs, and their lines in app.js and index.html): on a network whose genesis
// has `protected_registration`, "Create an account" ends with an account that is protected from its first block, made by
// client.registerProtected through the registration service; every interruption is gone on from by opening the account
// with its login password; each refusal is said in words; and on a network without the setting the sign-up is as it was.
//
// The real app.js on the stand-in page of protection-card.test.mjs (copied from there), with the real SDK and wallet
// modules. Stood in for: the compiled verifier (it passes on what this chain holds), and the chain with its gateway and
// the registration service (the faucet of a test network), which apply the rules of spec/settings.md, section 4.1, that a
// sponsor's action (kind 44), a registration that carries keys (kind 45) and a reveal (kind 2) meet, with the SDK's own
// functions, as client-v4/protected-signup.test.mjs does. That the engine takes the bytes of kind 45 is shown there.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { registerHooks } from 'node:module';
import { createHash, createHmac, randomBytes } from 'node:crypto';

const root = new URL('../../', import.meta.url);
const verifierStub = 'data:text/javascript,' + encodeURIComponent('const v=()=>globalThis.standInVerifier;' + ['verifyTrust', 'verifyLightUpdate', 'verifyViewProof', 'verifyReceipt', 'verifyFastReceipt'].map(name => `export const ${name}=(...given)=>v().${name}(...given);`).join(''));
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '/sdk/proof-verifier.js') return { url: verifierStub, shortCircuit: true };
  return next(specifier === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : specifier, context);
} });
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;
const F = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const S = await import(new URL('web-v4/wallet/signup.mjs', root).href);
const { createSignupUI, KEPT, PAPERS_ACTIVITY, PAPERS_IDLE, DROPPED } = await import(new URL('web-v4/wallet/signup-ui.mjs', root).href);
const { openVault, openUnder, newDevice, validateVaultRecord, madeForm, vaultUnder, vaultDevice } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy, sealsKept, provenSeals } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const { LOCK_WORDS, DEVICE_KEY_PLACE, deviceSecrets, saltOfRecord } = await import(new URL('web-v4/wallet/device-lock.mjs', root).href);
const { NOT_HAD } = await import(new URL('web-v4/wallet/made-dialog.mjs', root).href);
const { REMADE_ONE } = await import(new URL('web-v4/wallet/device-lock-ui.mjs', root).href);
const { BACKUP_FORMAT } = await import(new URL('web-v4/wallet/vault-backup.mjs', root).href);
const umdSource = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');

// ------------------------------------------------------------------ a stand-in page, which can be loaded again
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, checked: false, open: false, returnValue: '', dataset: {}, type: 'text', children: [], listeners: {}, className: '', files: [], required: false, classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn, options) { (this.listeners[type] ??= []).push({ fn, once: options?.once === true }); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); } after(el) { this.nextElementSibling = el; } remove() {} click() {}
  showModal() { this.open = true; } close() { this.open = false; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  getClientRects() { return this.hidden ? [] : [{}]; }
  dispatchEvent(event) { return this.fire(event.type); }
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map();
const storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
// What the page listens for on the whole document, with the options it asked for: a test sends such an event (`act`).
const documentListeners = {};
// What the page hands to the browser as a file (app.js, downloadJSON): the object URL of each blob, and the links made for them.
const downloads = [], anchors = [];
URL.createObjectURL = blob => { const url = `blob:download-${downloads.length}`; downloads.push({ url, blob }); return url; };
URL.revokeObjectURL = () => {};
globalThis.document = { getElementById: $, createElement: tag => { const el = new El(tag); if (tag === 'a') anchors.push(el); return el; }, querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener(type, fn, options) { (documentListeners[type] ??= []).push({ fn, options }); }, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
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
const ARM_MS = Number(/\nconst REVIEW_ARM_MS = ([0-9]+);/.exec(await readFile(new URL('./app.js', import.meta.url), 'utf8'))?.[1]);
const arming = [];
// The idle time of the wallet (guards.mjs, IDLE_LOCK_MS) passes when a test says so (`idleFor`), on a clock of its own.
const { IDLE_LOCK_MS } = await import(new URL('web-v4/wallet/guards.mjs', root).href);
const idleTimers = new Map(); let idleClock = 0;
globalThis.setTimeout = (fn, ms, ...given) => {
  if (ms === ARM_MS) { arming.push(() => fn(...given)); return null; }
  if (ms === IDLE_LOCK_MS) { const id = { idle: idleClock }; idleTimers.set(id, { due: idleClock + ms, run: () => fn(...given) }); return id; }
  const timer = realTimeout(fn, ms, ...given); if (ms >= 60000) timer.unref(); return timer;
};
const realClear = globalThis.clearTimeout;
globalThis.clearTimeout = id => { if (idleTimers.has(id)) idleTimers.delete(id); else realClear(id); };
/// `ms` of the idle clock pass: the idle timers that are due run, the earliest first.
async function idleFor(ms) {
  idleClock += ms;
  for (const [id, timer] of [...idleTimers].sort((a, b) => a[1].due - b[1].due)) if (timer.due <= idleClock && idleTimers.has(id)) { idleTimers.delete(id); await timer.run(); }
}
/// A person uses the page: the browser sends an event of `type` to the document's listeners.
const act = async type => { for (const { fn } of documentListeners[type] || []) await fn({ type }); };
const until = async (condition, what) => { for (let turn = 0; turn < 6000; turn++) { if (await condition()) return; await new Promise(resolve => realTimeout(resolve, 5)); } assert.fail(`waited in vain for: ${what} (the wallet's notice: ${$('notice').textContent})`); };

// ------------------------------------------------------------------ a stand-in chain, its gateway and its registration service
const NET = 'c6'.repeat(32), FAUCET = 'https://faucet.example', GENESIS = 1700000000000000n, DAY = 86400000000n;
const LOGIN = 'violet otters dance beneath moonlight 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const verify = async (publicKey, signature, message) => crypto.subtle.verify('Ed25519', await crypto.subtle.importKey('raw', SDK.hexToBytes(publicKey, 32), 'Ed25519', false, ['verify']), SDK.hexToBytes(signature, 64), message);
const faucetKey = await newDevice(), otherKey = await newDevice();
// `protect`: the genesis has protected_registration. `down`: the gateway answers no read (a connection that is gone).
// `drop(action)`: the gateway, or for kind 44 the registration service, is not reached: the connection fails before the
// action reaches the chain. `refuse(action)`: the chain refuses it in these words. `service`: how the registration
// service answers ('sponsor', 'account_limit', or 'other key': it pays for another key's commitment and names that).
const chain = { height: 900, now: 100n * DAY, protect: true, down: false, accounts: [], security: {}, commits: [], included: new Map(), posted: [], nextId: 20, asked: 0, service: 'sponsor', drop: () => false, refuse: () => null, after: () => {} };
chain.accounts.push({ id: '1', name: 'faucet', public_key: faucetKey.publicKey, balance: '900000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: faucetKey.publicKey, can_manage: true, can_spend: true }] });
chain.accounts.push({ id: '2', name: 'bob', public_key: '2'.repeat(64), balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '2'.repeat(64), can_manage: true, can_spend: true }] });
const byName = name => chain.accounts.find(item => item.name === name);
const commitOf = key => chain.commits.find(item => item.public_key === key && BigInt(item.expires_elapsed_micros) >= chain.now);
function stateFor(query) {
  if (chain.down) throw new Error('the gateway answers no read');
  const ids = query.ids || [], names = query.names || [], keys = query.public_keys || [];
  const state = { protocol_version: '4', network_id: NET, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
    config: { recovery_min_delay_micros: '30000000', all_new_time_to_validators: true, registration: { fee_micros: '10000', max_lifetime_micros: '86400000000', bucket_micros: '3600000000' }, ...(chain.protect ? { protected_registration: true } : {}) },
    bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, recovery_cases: [], candidates: Object.fromEntries((query.candidates || []).map(id => [id, null])),
    accounts: chain.accounts.filter(item => ids.includes(item.id) || names.includes(item.name) || keys.some(key => item.public_key === key || item.devices.some(d => d.public_key === key))),
    name_commits: chain.commits.filter(item => keys.includes(item.public_key) && BigInt(item.expires_elapsed_micros) >= chain.now) };
  if (query.include_security) state.security = state.accounts.map(item => chain.security[item.id]).filter(Boolean);
  if (query.include_pos) state.pos = { profile: 'production', candidate_ids: [], active: [], scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (query.include_upgrade) state.upgrade = null;
  return structuredClone(state);
}
/// The rules of a sponsor's action, a registration that carries keys and a reveal (spec/settings.md, 4.1): a refusal, or the change.
async function judge(action, tx) {
  if (action.networkId !== NET) return 'wrong network';
  if (!await verify(action.publicKey, SDK.bytesToHex(tx.slice(-64)), tx.slice(0, -64))) return 'invalid action signature';
  const p = action.payload;
  if (action.kind === SDK.KINDS.transfer) {
    const from = chain.accounts.find(a => a.id === action.from), to = chain.accounts.find(a => a.id === p.to);
    if (!from?.devices.some(d => d.public_key === action.publicKey && d.can_spend) || !to) return 'unauthorized transfer';
    const total = BigInt(p.amount) + 1000n;
    if (BigInt(action.nonce) !== BigInt(from.nonce) + 1n || BigInt(from.balance) < total) return 'invalid transfer';
    return () => {
      from.nonce = action.nonce; from.balance = String(BigInt(from.balance) - total);
      to.balance = String(BigInt(to.balance) + BigInt(p.amount));
    };
  }
  if (action.kind === 44) {
    const from = chain.accounts.find(a => a.id === action.from);
    if (!from || !from.devices.some(d => d.public_key === action.publicKey && d.can_spend) || BigInt(action.nonce) !== BigInt(from.nonce) + 1n) return 'spending device required';
    if (!await verify(p.public_key, p.proof, SDK.sponsorConsentBytes({ networkId: NET, sponsorAccount: action.from, publicKey: p.public_key, commitment: p.commitment, expiresElapsedMicros: p.expires_elapsed_micros }))) return 'invalid sponsorship consent';
    if (commitOf(p.public_key)) return 'a registration of this key is pending';
    return () => { from.nonce = action.nonce; chain.commits.push({ public_key: p.public_key, commitment: p.commitment, sponsor: action.from, expires_elapsed_micros: p.expires_elapsed_micros, height: String(chain.height) }); };
  }
  if (action.kind === 2 || action.kind === 45) {
    if (action.kind === 45 && !chain.protect) return 'unknown action kind';
    const reg = action.publicKey, commit = commitOf(reg);
    if (byName(p.name)) return `name ${p.name} is taken`;
    if (!commit || BigInt(commit.height) > chain.height) return 'no paid commitment of this registration key from an earlier block';
    let expected = null;
    try { expected = action.kind === 2 ? await SDK.nameCommitment({ networkId: NET, publicKey: reg, name: p.name, salt: p.salt }) : await SDK.protectedNameCommitment({ networkId: NET, publicKey: reg, name: p.name, salt: p.salt, security: p.security }); } catch { expected = null; }
    if (expected !== commit.commitment) return 'the registration does not match its commitment';
    const made = id => { chain.commits.splice(chain.commits.indexOf(commit), 1); chain.nextId += 1; return id; };
    if (action.kind === 2) return () => { const id = made(String(chain.nextId)); chain.accounts.push({ id, name: p.name, public_key: reg, balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: reg, can_manage: true, can_spend: true }] }); };
    for (const entry of p.security.keys) if (!await verify(entry.public_key, entry.proof, SDK.registrationRoleBytes({ networkId: NET, registrationKey: reg, role: entry.role, publicKey: entry.public_key }))) return 'an acceptance does not verify';
    return () => {
      const id = made(String(chain.nextId));
      chain.accounts.push({ id, name: p.name, public_key: reg, balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: p.security.keys.map(e => ({ public_key: e.public_key, can_manage: e.role === 'recover', can_spend: e.role === 'spend' })) });
      chain.security[id] = { account: id, version: '1', policy: { ...p.security.policy }, allowance_micros: p.security.policy.daily_limit_micros, allowance_elapsed_micros: chain.now.toString(), frozen_until_elapsed_micros: '0', freezes: '0', next_id: '1', pending_limit: null, pending_payments: [], pending_root: null };
    };
  }
  return 'not taken by this stand-in chain';
}
/// What a node does with signed bytes: null when a block took them, otherwise the refusal.
async function broadcast(tx) {
  const action = SDK.decodeAction(tx); chain.posted.push(action);
  const said = chain.refuse(action); if (said) return said;
  const outcome = await judge(action, tx);
  if (typeof outcome === 'string') return outcome;
  chain.height += 1; chain.now += 1000000n; outcome();
  chain.included.set((await SDK.transactionHash(tx)).toUpperCase(), { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
  // The chain goes on making blocks: one more after a sponsor's action, in which a registration can then come.
  if (action.kind === 44) { chain.height += 1; chain.now += 1000000n; }
  chain.after(action);
  return null;
}
/// The registration service: it signs the sponsor's action with its own key and sends it (deploy/faucet/README.md).
async function sponsor(body) {
  if (chain.drop({ kind: 44 })) throw new TypeError('Failed to fetch');
  chain.asked += 1;
  // A limit of a day, as a browser sees it from another origin: a 429 without a Retry-After it may read, in the
  // service's own form, so the wallet reads it as the service's answer (busy.mjs, inOwnForm).
  if (chain.service === 'account_limit') return { status: 429, answer: { error: { code: 'account_limit', message: 'The key was sponsored in the last 24 hours' } } };
  const faucet = chain.accounts.find(a => a.id === '1');
  let payload = { public_key: body.public_key, commitment: body.commitment, expires_elapsed_micros: body.expires_elapsed_micros, proof: body.proof };
  if (chain.service === 'other key') {
    // A dishonest service pays for a commitment of another key, and names that action.
    const commitment = 'ab'.repeat(32), consent = SDK.sponsorConsentBytes({ networkId: NET, sponsorAccount: '1', publicKey: otherKey.publicKey, commitment, expiresElapsedMicros: body.expires_elapsed_micros });
    payload = { public_key: otherKey.publicKey, commitment, expires_elapsed_micros: body.expires_elapsed_micros, proof: SDK.bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', otherKey.privateKey, consent))) };
  }
  const tx = await SDK.signAction({ networkId: NET, kind: SDK.KINDS.sponsor_registration, from: '1', nonce: (BigInt(faucet.nonce) + 1n).toString(), authEpoch: faucet.auth_epoch, publicKey: faucetKey.publicKey, payload }, faucetKey.privateKey);
  const refused = await broadcast(tx);
  return refused ? { status: 503, answer: { error: { code: 'node_refused', message: refused } } } : { status: 202, answer: { hash: (await SDK.transactionHash(tx)).toLowerCase() } };
}
const block = height => ({ signed_header: { header: { height: String(height) } } });
globalThis.standInVerifier = {
  verifyTrust: async () => ({}),
  verifyLightUpdate: async candidateBlock => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidateBlock.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidateBlock } }),
  verifyViewProof: async (_proof, _trust, query) => ({ verified: true, completeAccountSet: false, state: stateFor(query) }),
  verifyReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
  verifyFastReceipt: async proof => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
};
const answer = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers });
/// What a proxy in front refuses for load (busy.mjs): `chain.busy` lists {route, count, status}; each refused request
/// takes one from its count, and is answered in plain text with a Retry-After of one second.
function busyAnswer(route) {
  const plan = chain.busy.find(item => item.route === route && item.count > 0); if (!plan) return null;
  plan.count -= 1; plan.refused = (plan.refused ?? 0) + 1;
  return new Response('Too many requests. Wait a moment.', { status: plan.status, headers: { 'Content-Type': 'text/plain', 'Retry-After': '1' } });
}
globalThis.fetch = async (url, options = {}) => {
  const refusedForLoad = busyAnswer(new URL(String(url), location.origin).pathname); if (refusedForLoad) return refusedForLoad;
  if (String(url).startsWith(FAUCET + '/')) {
    const route = new URL(String(url)).pathname;
    // A service that does not answer: the request fails, as one to a stopped service does.
    if (route === '/v1/faucet') { if (!chain.facts) throw new TypeError('Failed to fetch'); return answer(200, { network_id: NET, account: '1', giving: true, registrations: { sponsored: true } }); }
    if (route !== '/v1/faucet/registrations') return answer(404, {});
    const got = await sponsor(JSON.parse(options.body)); return answer(got.status, got.answer, got.headers);
  }
  const address = new URL(String(url), location.origin), route = address.pathname;
  const trust = { app_version: '4', network_id: NET, chain_id: 'time-devnet-v4-test' };
  if (route === '/trust-manifest.json') return { ok: true, status: 200, json: async () => trust, text: async () => JSON.stringify(trust) };
  let body;
  if (route === '/api/network') body = { protocolVersion: '4', networkId: NET, chainId: trust.chain_id, mode: 'local-devnet', publicLaunchAllowed: false, registrationService: FAUCET };
  else if (route === '/api/light-block') body = block(address.searchParams.get('height') || chain.height);
  else if (route === '/api/view-proof') body = chain.down ? { error: 'the gateway answers no read' } : { light_block: block(chain.height) };
  else if (route === '/api/submit') {
    const tx = new Uint8Array(Buffer.from(JSON.parse(options.body).tx, 'base64'));
    if (chain.drop(SDK.decodeAction(tx))) throw new TypeError('Failed to fetch');
    const refused = await broadcast(tx); body = refused ? { error: refused } : { hash: (await SDK.transactionHash(tx)).toUpperCase() };
  }
  // A receipt that no block holds is an error at once (as a gateway's refusal is), so that the SDK stops asking.
  else if (route === '/api/receipt') { const hash = address.searchParams.get('hash'), found = chain.included.get(hash); body = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { error: 'no such transaction' }; }
  else if (route === '/api/notifications') body = { items: [] };
  else body = { error: 'not served by this stand-in gateway' };
  return { ok: !body.error, status: body.error ? 400 : 200, text: async () => JSON.stringify(body), json: async () => body };
};

// ------------------------------------------------------------------ the person, at the wallet
let pages = 0;
async function freshPage() {
  if (pages > 0) await $('lock-button').fire('click');
  dom = new Map();
  for (const id of HIDDEN) $(id).hidden = true;
  await import(new URL(`web-v4/wallet/app.js?signup=${++pages}`, root).href);
  await until(() => /^(Connected to the Time test network|Creating @|Open @|The new keys of @)/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
}
const slots = name => F.vaultSlots(NET, name);
/// What this browser keeps for a name on this network, by kind of place.
function kept(name) {
  const s = slots(name), read = key => { const raw = storage.getItem(key); return raw === null ? null : JSON.parse(raw); };
  return { login: read(s.login), spend: read(s.spend), nextLogin: read(s.nextLogin), nextSpend: read(s.nextSpend), note: read(s.nextNote) };
}
const everything = () => [...storage.m.values()].join('\n');
/// The passwords of each account made here: those the wallet made and showed (read from the page, as a person writes them
/// down), or, with the device, those typed. What `unlock` types.
const passwords = {};
/// How the vault records of a name are sealed (tests/legacy-vault.mjs, sealsKept): [place, version, seal].
const sealsOf = name => sealsKept([...storage.m].filter(([key]) => key.endsWith(`:${name}`) || key.includes(`:${name}:`))).map(s => [s.place, s.version, s.seal]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
/// The dialog of passwords the wallet made (made-dialog.mjs), when it is open: what it shows, then "I have them" (the
/// button sends the dialog's form, which closes it with the button's value). `how`: 'escape' (the browser's cancel event,
/// then the close it makes) or 'close' (closed by a script, with no value) instead.
async function madeShown(how = 'done') {
  const shown = { why: $('made-why').textContent, title: $('made-title').textContent, label: $('made-login-name').textContent, note: $('made-login-note').textContent, button: $('made-done').textContent, login: $('made-login-shown').textContent, payment: $('made-payment-shown').textContent, name: $('made-name').value, field: $('made-login').value };
  if (how === 'done') $('made-dialog').returnValue = 'done';
  if (how === 'escape') { await $('made-dialog').fire('cancel'); assert.equal($('made-dialog').open, false, 'Escape closes the dialog'); }
  if (how === 'close') $('made-dialog').close();
  $('made-dialog').open = false; await $('made-dialog').fire('close');
  assert.deepEqual([$('made-login-shown').textContent, $('made-payment-shown').textContent, $('made-login').value, $('made-name').value], ['', '', '', ''], 'what was shown left the page');
  return shown;
}
/// The form is drawn once the browser has said what the device can do (device-lock-ui.mjs, wayChoice): until then it shows
/// neither the choice nor the sentence of a device that cannot lock keys. Waits for one of them (on a network without
/// protected sign-up, app.js's sentence stands there at once).
const formDrawn = (prefix = 'auth') => until(() => $(`${prefix}-ways`).hidden === false || $(`${prefix}-seal-note`).hidden === false, 'the wallet to draw the form');
/// Where the device can lock keys, the form shows the choice of the two ways, neither chosen (device-lock-ui.mjs, wayChoice):
/// waits until the wallet has drawn it.
const choiceDrawn = async (prefix = 'auth') => {
  await until(() => $(`${prefix}-ways`).hidden === false, 'the choice of how to lock the new keys');
  assert.deepEqual([$(`${prefix}-way-device`).checked, $(`${prefix}-way-made`).checked, $(`${prefix}-seal-note`).hidden], [false, false, true], 'neither way is chosen beforehand');
};
/// The person picks a way ('device' or 'made'), as a click on its radio does: it is checked, the other one is not, and the
/// browser sends its change event.
async function choose(way, prefix = 'auth') {
  const picked = $(`${prefix}-way-${way}`), other = $(`${prefix}-way-${way === 'device' ? 'made' : 'device'}`);
  picked.checked = true; other.checked = false;
  await picked.fire('change');
}
/// Step 1: the form of "Create an account", sent. Where the device can lock keys (`device`), the form shows the choice,
/// and the person picks one way: the lock, with the passwords typed, or with `decline` the passwords the wallet makes;
/// with `switched` the other way first, then that one; with `chosen`, the test drew the form and chose already. Where the
/// wallet makes the passwords, nothing is typed but the name, and the passwords are read from the dialog that shows them.
/// Waits for the step of the recovery words, or for the wallet's answer.
async function step1(name, { device = false, decline = false, switched = false, chosen = false } = {}) {
  if (!chosen) { await $('mode-create').fire('click'); if (!device) await formDrawn(); }
  if (device && !chosen) {
    await choiceDrawn();
    if (switched) await choose(decline ? 'device' : 'made');
    await choose(decline ? 'made' : 'device');
  }
  if (device) assert.deepEqual([$('password').hidden, $('signup-chosen').hidden], [decline, decline], 'the fields of the passwords only once the lock is chosen');
  const typed = device && !decline;
  $('username').value = name;
  if (typed) { $('password').value = $('password-confirm').value = LOGIN; $('signup-payment').value = $('signup-payment-confirm').value = PAYMENT; }
  $('notice').textContent = ''; $('notice').className = 'notice';
  // The form's step waits for the person to close the dialog of the passwords: it is not awaited before that.
  const sent = $('auth-form').fire('submit');
  await until(() => $('made-dialog').open || $('signup-phrase-shown').textContent.length > 20 || $('notice').className.includes('error'), 'the passwords or the recovery words');
  let made = null;
  if ($('made-dialog').open) made = await madeShown();
  if (made || typed) passwords[name] = made ? { login: made.login, payment: made.payment } : { login: LOGIN, payment: PAYMENT };
  await sent;
  await until(() => $('signup-phrase-shown').textContent.length > 20 || $('notice').className.includes('error'), 'the recovery words');
  return { phrase: $('signup-phrase-shown').textContent, made, ...passwords[name] };
}
/// The registration key of a kept sign-up, as the login password opens it: the login key kept aside, then the key kept
/// under it (vault version 4).
async function registrationOf(name) {
  const k = kept(name), login = await openVault(k.nextLogin, passwords[name].login, argon2id, globalThis.crypto, 'signin');
  return openUnder(k.login, { publicKey: login.binding.publicKey, pkcs8: login.secret.pkcs8 });
}
/// Step 2: "I wrote them down. Create my account". Nothing is downloaded, printed or asked back.
async function step3() {
  $('notice').textContent = ''; $('notice').className = 'notice';
  await $('signup-submit').fire('click');
}
const opened = name => until(() => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser', `the account ${name} open`);
async function unlock(name) {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = passwords[name]?.login ?? LOGIN; $('notice').textContent = ''; $('notice').className = 'notice';
  await $('auth-form').fire('submit');
}
const roles = account => Object.fromEntries(['signin', 'spend', 'recover'].map(role => [role, account.devices.filter(d => (role === 'recover' ? d.can_manage : role === 'spend' ? d.can_spend : !d.can_manage && !d.can_spend)).map(d => d.public_key)]));
const PROTECTED_READY = 'Your account is ready, protected from its first block. This browser checked it with the network. Next time, open it with your name and your login password.';
const reset = () => { Object.assign(chain, { down: false, protect: true, facts: true, service: 'sponsor', drop: () => false, refuse: () => null, after: () => {}, busy: [] }); };
chain.facts = true; chain.busy = [];
/// A time of the chain (microseconds since genesis) as the page writes it.
const chainDate = elapsed => new Date(Number((GENESIS + BigInt(elapsed)) / 1000n)).toLocaleString();
/// The fields of the open review.
function fieldsOf() {
  const list = $('review-body').children.find(item => item.id === 'dl'), fields = {};
  for (let at = 0; at + 1 < (list?.children.length ?? 0); at += 2) fields[list.children[at].textContent] = list.children[at + 1].textContent;
  return fields;
}
/// "Let this sign-up go" pressed: the review it opened, confirmed or not, and the wallet's answer. `during()` runs while the
/// review is open.
async function letGo({ confirm = false, during = () => {} } = {}) {
  $('notice').textContent = ''; $('notice').className = 'notice';
  const running = $('signup-letgo').fire('click');
  await until(() => $('review-dialog').open || ($('notice').textContent !== '' && !$('notice').className.includes('busy')), 'an answer or a review');
  let review = null;
  if ($('review-dialog').open) {
    review = { title: $('review-title').textContent, confirm: $('review-confirm').textContent, fields: fieldsOf() };
    await during();
    for (const fire of arming.splice(0)) fire();
    $('review-dialog').returnValue = confirm ? 'confirm' : 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close');
  }
  await running;
  await until(() => !$('notice').className.includes('busy'), 'the answer');
  return { review, notice: $('notice').textContent, error: $('notice').className.includes('error') };
}
/// Everything this browser keeps of a name's sign-up, as it is stored: to see that nothing of it changed.
const raw = name => { const s = slots(name); return [s.login, s.spend, s.nextLogin, s.nextSpend, s.nextNote, S.consentKey(NET, name)].map(key => storage.getItem(key)); };

await freshPage();

test('the form: manual signup asks for a name and explains how to keep both generated passwords and five recovery words', async () => {
  await formDrawn();
  for (const id of ['password', 'password-label', 'password-confirm', 'confirm-label', 'password-note']) {
    assert.ok(HIDDEN.includes(id), `${id} stays out of the initial screen while the network is checked`);
  }
  // This stand-in page has no device that can lock keys (no WebAuthn): no password field is asked (the rule, vault.mjs RULE),
  // and no choice is shown: the wallet makes the passwords and says so.
  assert.deepEqual([$('password-label').textContent, $('confirm-label').textContent, $('password-note').hidden, $('signup-login-note').hidden, $('signup-protected').hidden], ['Login password', 'Login password again', true, true, false]);
  assert.deepEqual(['password-label', 'password', 'confirm-label', 'password-confirm', 'signup-chosen'].map(id => $(id).hidden), [true, true, true, true, true]);
  assert.deepEqual([$('auth-seal-note').hidden, $('auth-seal-note').textContent, $('auth-ways').hidden, $('auth-way-device').checked, $('auth-way-made').checked], [false, LOCK_WORDS.birthMade, true, false, false]);
  assert.equal(page.includes('id="signup-limit"'), false, 'the spending limit is a setting after signup');
  assert.equal($('auth-submit').textContent, 'Next: my recovery words');
  assert.equal($('signup-manual-note').hidden, false, 'this unpaired wallet shows why it uses manual setup');
  assert.equal($('auth-copy').textContent, 'Pick a name. The wallet makes your login password and your payment password and shows them to you, then five recovery words for you to write on paper. Your account is protected from its first moment.');
  assert.deepEqual(['password', 'password-confirm', 'signup-payment', 'signup-payment-confirm'].map(id => $(id).required), [false, false, false, false]);
  for (const words of ['<span class="tag day">Every day</span> Opens this wallet and signs you in to websites. It cannot pay. Nobody can reset it.', '<span class="tag day">When you pay</span> Pays up to your daily limit. It must differ from your login password. Do not let the browser save it.']) assert.ok(page.includes(words), words);
  // The step, in this order: what the words are for, why paper, the words, how to keep them, two copies (an instruction:
  // web audit of November 2026, K-1), what the words can do in other hands and that only they stop it, and the button,
  // there from the start.
  const step = page.slice(page.indexOf('<div id="signup-sheet-step"'), page.indexOf('</div></div>', page.indexOf('<div id="signup-sheet-step"')));
  const parts = ['<h2>Write down your recovery words <span class="tag safe">Keep safe</span></h2>', '<p>These five words bring your account back if you lose your passwords or this device. Take a pen and write them on paper.</p>', '<p>Paper is the safest place for them: nothing online can reach it. That is why the wallet saves them nowhere and offers no file here.</p>', '<p class="sheet" id="signup-phrase-shown"></p>', '<p class="field-note">On paper only: not in a photo, a note or a message. Nobody can show them to you again.</p>', '<p id="signup-tip">Write them twice and keep the two papers in different places. If one is lost, the other brings your account back. If one is taken, the other lets you stop whoever took it. The fridge door does not count.</p>', '<p>Anyone who has these words can ask to take over your account. That waits your waiting period. You can stop it only with these words, so a paper that is your only copy must never be lost or taken. The Alerts at the top of Home tell you if it happens.</p>', '<button id="signup-submit" type="button">I wrote them down. Create my account</button>', '<button id="signup-cancel" type="button" class="secondary">Start over</button>'];
  const at = parts.map(part => step.indexOf(part));
  assert.ok(at.every(i => i >= 0), JSON.stringify(parts.filter((_, i) => at[i] < 0)));
  assert.deepEqual(at, [...at].sort((a, b) => a - b), 'in this order');
  // Nothing to download or print at sign-up: no kit, no sheet, no file.
  for (const gone of ['signup-kit-download', 'signup-print', 'signup-kit-saved', 'id="signup-sheet"', 'Recovery Kit']) assert.ok(!step.includes(gone), gone);
  // No field of the protected form is required in the page itself: hidden, it must not stop the form of another mode.
  assert.doesNotMatch(page.slice(page.indexOf('id="signup-protected"'), page.indexOf('id="auth-submit"')), /\srequired/);
  // The choice of how new keys are locked, on each form that makes them (device-lock-ui.mjs, wayChoice): real radios, each
  // in its label, in a fieldset with a legend, styled as the wallet's other choices (styles.css, .kinds and .kind), hidden
  // until the wallet draws it, and neither checked nor required by the page. Its words come from the wallet's script.
  for (const prefix of ['auth', 'secure', 'lost', 'move']) {
    const from = page.indexOf(`<fieldset id="${prefix}-ways"`), set = page.slice(from, page.indexOf('</fieldset>', from));
    assert.ok(from > 0 && set.startsWith(`<fieldset id="${prefix}-ways" class="kinds" hidden><legend id="${prefix}-ways-legend"></legend>`), prefix);
    for (const way of ['device', 'made']) assert.ok(set.includes(`<label class="kind" for="${prefix}-way-${way}"><input id="${prefix}-way-${way}" name="${prefix}-way" type="radio" value="${way}"><span><strong id="${prefix}-way-${way}-title"></strong><span class="field-note" id="${prefix}-way-${way}-note"></span></span></label>`), `${prefix}: ${way}`);
    assert.doesNotMatch(set, /\s(checked|required|style|on[a-z]+)[\s>=]/, prefix);
  }
  assert.doesNotMatch(page, /-instead\b/, 'no button to decline is left');
  // Opening an account: the form as before.
  await $('mode-unlock').fire('click');
  assert.deepEqual([$('password-label').textContent, $('signup-protected').hidden, $('password-note').hidden], ['Password', true, false]);
  await $('mode-create').fire('click');
});

test('signing up protected: five recovery words on paper come before anything is kept or sent, nothing is downloaded or asked back, both recovery keys come from the words, and the account is protected from its first block with the 600-second limit', async () => {
  reset(); const posted = chain.posted.length, files = downloads.length;
  const papers = await step1('erin_p');
  assert.match(papers.phrase, /^[a-z]{6} [a-z]{6} [a-z]{6} [a-z]{6} [a-z]{6}$/, $('notice').textContent);
  // The passwords the wallet made were shown once, before the words, in their own look (four words with dashes); the login
  // password under the account's name for the password manager, the payment password in no field.
  assert.ok(papers.made, 'the dialog of the passwords the wallet made was shown');
  assert.deepEqual([madeForm(papers.login), madeForm(papers.payment), papers.made.name, papers.made.field], [papers.login, papers.payment, 'erin_p', papers.login]);
  assert.notEqual(papers.login, papers.payment);
  assert.deepEqual([$('made-login-shown').textContent, $('made-payment-shown').textContent, $('made-login').value], ['', '', ''], 'what was shown left the page');
  // The step: the five words and the button that goes on, from the start.
  assert.deepEqual([$('auth-form').hidden, $('signup-sheet-step').hidden, $('signup-submit').hidden, $('signup-tip').hidden, $('signup-payment').value, $('password').value], [true, false, false, false, '', '']);
  assert.equal($('notice').textContent, 'Write down your recovery words. They are shown only now.');
  // Nothing is kept and nothing is sent before the button.
  assert.deepEqual(kept('erin_p'), { login: null, spend: null, nextLogin: null, nextSpend: null, note: null });
  assert.deepEqual([chain.posted.length - posted, chain.asked], [0, 0]);
  // "I wrote them down. Create my account": the account is made through the registration service, and opened.
  $('notice').textContent = ''; $('notice').className = 'notice';
  await $('signup-submit').fire('click');
  await opened('erin_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  assert.equal(downloads.length, files, 'nothing was downloaded');
  // The form the step stood in for is back: the start screen of this page has its fields again when it is shown.
  assert.deepEqual([$('auth-form').hidden, $('signup-sheet-step').hidden, $('signup-phrase-shown').textContent], [false, true, '']);
  const account = byName('erin_p'), row = chain.security[account.id];
  assert.deepEqual(chain.posted.slice(posted).map(a => a.kind), [44, 45], 'the sponsor\'s action, then the registration that carries the keys');
  assert.deepEqual(row.policy, { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800' });
  const keys = roles(account);
  assert.deepEqual([keys.signin.length, keys.spend.length, keys.recover.length, account.devices.some(d => d.public_key === account.public_key)], [1, 1, 2, false], 'four keys in their roles; the registration key is on no role');
  // The Protection card: protected at once, with the limit of 600 seconds.
  assert.deepEqual([$('protect-on').hidden, $('protect-none').hidden, $('protect-status').textContent, $('limit-text').textContent], [false, true, 'Your account is protected.', 'You can pay 600 of 600 seconds now without waiting, fees included.']);
  // What this browser keeps: the login key under the login password, the payment key under the payment password; the
  // registration key is gone, and nothing is kept aside any more. No password and no paper is in the storage.
  const now = kept('erin_p');
  assert.deepEqual([now.login.version, now.login.intent, now.login.binding.publicKey, now.spend.intent, now.spend.binding.publicKey, now.nextLogin, now.nextSpend, now.note], [2, 'signin', keys.signin[0], 'spend', keys.spend[0], null, null, null]);
  for (const secret of [papers.login, papers.payment, papers.phrase, '"pkcs8"']) assert.ok(!everything().includes(secret), secret);
  assert.equal((await openVault(now.spend, papers.payment, argon2id, globalThis.crypto, 'spend')).binding.publicKey, keys.spend[0]);
  // The rule: both keys under the passwords the wallet made, marked so; nothing under a password a person chose.
  assert.deepEqual(sealsOf('erin_p'), [['timecurrency.spend-vault.v1', 2, 'made'], ['timecurrency.vault.v1', 2, 'made']]);
  // Both recovery keys come from the words (their salts name the account's identity key): the first and the second key
  // of "words only". The wallet finds the first so: a freeze signed with the words is signed by that key.
  const byIdentity = await F.passphraseKey({ passphrase: papers.phrase, networkId: NET, registrationKey: account.public_key, argon2id });
  const second = await F.recoveryWordsSecondKey({ passphrase: papers.phrase, networkId: NET, registrationKey: account.public_key, argon2id });
  assert.deepEqual([...keys.recover].sort(), [byIdentity.publicKey, second.publicKey].sort());
  // This browser remembers the kind with the two public keys, and nothing else: Keys says what words only means.
  assert.deepEqual(JSON.parse(storage.getItem(F.recoveryKindKey(NET, 'erin_p'))), { kind: 'words', keys: [byIdentity.publicKey, second.publicKey].sort() });
  const before = chain.posted.length;
  await $('freeze-switch').fire('change'); $('freeze-method').value = 'paper'; $('freeze-secret').value = papers.phrase;
  const freezing = $('freeze-form').fire('submit');
  await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the review of the freeze');
  for (const fire of arming.splice(0)) fire();
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close'); await freezing;
  await until(() => chain.posted.length > before, 'the freeze to be sent');
  assert.deepEqual([chain.posted.at(-1).kind, chain.posted.at(-1).publicKey], [72, byIdentity.publicKey]);
  for (const key of Object.keys(storage.m).filter(k => k.startsWith('timecurrency.pending.v1:'))) storage.removeItem(key);
  // Locked and opened again with the login password: the same account.
  await $('lock-button').fire('click');
  assert.deepEqual([$('auth-panel').hidden, $('auth-form').hidden, $('auth-submit').textContent, $('auth-submit').disabled], [false, false, 'Open my account', false], 'the locked wallet shows the form that opens it');
  await unlock('erin_p'); await opened('erin_p');
  assert.equal($('notice').textContent, 'Your account is open. This browser checked your balance with the network.');
});

test('a sign-up through a busy network (busy.mjs): refused questions and submits are waited for and sent again, the same bytes, and the account is made and opened with signing on', async () => {
  reset(); await $('lock-button').fire('click');
  const posted = chain.posted.length, asked = chain.asked;
  const papers = await step1('wren_p');
  assert.match(papers.phrase, /^[a-z]{6}( [a-z]{6}){4}$/, $('notice').textContent);
  // The registration service's question once (a 503), the two submits of the sign-up twice (429s, plain text).
  chain.busy = [{ route: '/v1/faucet', count: 1, status: 503 }, { route: '/api/submit', count: 2, status: 429 }];
  await step3();
  await opened('wren_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  assert.deepEqual(chain.busy.map(item => [item.route, item.count, item.refused]), [['/v1/faucet', 0, 1], ['/api/submit', 0, 2]]);
  assert.deepEqual(chain.posted.slice(posted).map(a => a.kind), [44, 45], 'one sponsorship and one registration: nothing signed twice');
  assert.equal(chain.asked - asked, 1, 'the sponsor was asked once');
  assert.equal($('send-form').querySelector().disabled, false, 'signing is on');
  assert.notEqual($('network-status').textContent, 'Cannot check the network · signing is off');
});

test('the default spending limit applies, and the recovery words are never skipped: "Start over" and locking forget them, and nothing is kept', async () => {
  reset(); await $('lock-button').fire('click');
  let papers = await step1('finn_p');
  await $('signup-cancel').fire('click');
  assert.deepEqual([$('signup-phrase-shown').textContent, $('signup-sheet-step').hidden, $('auth-form').hidden, kept('finn_p').note, $('notice').textContent], ['', true, false, null, DROPPED]);
  assert.equal(DROPPED, 'Nothing was created. The recovery words that were shown will never work: destroy the paper if you wrote them down.');
  papers = await step1('finn_p');
  await $('lock-button').fire('click');
  assert.deepEqual([$('signup-phrase-shown').textContent, $('signup-sheet-step').hidden, kept('finn_p').note], ['', true, null]);
  await $('mode-create').fire('click');
  papers = await step1('finn_p');
  assert.equal($('signup-submit').hidden, false, 'the button is there from the start of a new step too');
  await step3(papers); await opened('finn_p');
  assert.equal(chain.security[byName('finn_p').id].policy.daily_limit_micros, '600000000');
  await $('lock-button').fire('click');
});

test('the step of the recovery words follows the idle rule of the lock: after five minutes without use it is closed, and the person is told that nothing was created', async () => {
  reset(); await $('lock-button').fire('click');
  const posted = chain.posted.length, asked = chain.asked, nothing = { login: null, spend: null, nextLogin: null, nextSpend: null, note: null };
  let papers = await step1('sami_p');
  await idleFor(IDLE_LOCK_MS - 1);
  assert.equal($('signup-phrase-shown').textContent, papers.phrase, 'on the page until the five minutes are over');
  await idleFor(1);
  assert.deepEqual([$('signup-phrase-shown').textContent, $('signup-sheet-step').hidden, $('signup-submit').hidden, $('auth-form').hidden, $('notice').textContent], ['', true, true, false, PAPERS_IDLE]);
  assert.equal(PAPERS_IDLE, 'Your recovery words were hidden after 5 minutes without use, and nothing was created. They will never work: destroy the paper if you wrote them down. Start again to get new ones.');
  // Nothing was kept or sent, and the keys are forgotten: "Create my account" has nothing left to create.
  assert.deepEqual([kept('sami_p'), chain.posted.length - posted, chain.asked - asked, idleTimers.size], [nothing, 0, 0, 0]);
  await $('signup-submit').fire('click');
  assert.deepEqual([$('notice').textContent, kept('sami_p')], ['Start again from the beginning.', nothing]);
  // "Start over" leaves no idle rule behind.
  papers = await step1('sami_p'); await $('signup-cancel').fire('click');
  assert.equal(idleTimers.size, 0);
});

test('a person writing the words down slowly is not cut off while using the page: each kind of use counts, a pointer that only moves does not', async () => {
  reset();
  assert.deepEqual([...PAPERS_ACTIVITY], ['pointerdown', 'keydown', 'input', 'wheel', 'scroll', 'touchmove']);
  // Heard on the way down, so that scrolling inside an element of the page counts too.
  assert.ok(PAPERS_ACTIVITY.every(type => (documentListeners[type] || []).some(item => item.options?.capture === true && item.options?.passive === true)), 'every kind of use is listened for, on the way down');
  for (const type of PAPERS_ACTIVITY) {
    const papers = await step1('tess_p');
    await idleFor(IDLE_LOCK_MS - 1000); await act(type); await idleFor(IDLE_LOCK_MS - 1000);
    assert.equal($('signup-phrase-shown').textContent, papers.phrase, `${type} keeps the words on the page`);
    await idleFor(1000);
    assert.equal($('signup-phrase-shown').textContent, '', `${type}: hidden five minutes after the last use`);
  }
  // Not use: a pointer that moves over the page, a field that takes the focus.
  let papers = await step1('tess_p');
  await idleFor(IDLE_LOCK_MS - 1000); await act('pointermove'); await act('focusin'); await idleFor(1000);
  assert.equal($('signup-phrase-shown').textContent, '');
  // Twelve minutes on the step, using the page every minute: nothing is hidden, and the account is made.
  papers = await step1('tess_p');
  for (let minute = 0; minute < 8; minute++) { await idleFor(60000); await act(minute % 2 ? 'wheel' : 'scroll'); }
  for (let minute = 0; minute < 4; minute++) { await idleFor(60000); await act('keydown'); await act('input'); }
  assert.deepEqual([$('signup-sheet-step').hidden, $('signup-phrase-shown').textContent], [false, papers.phrase]);
  await step3(papers); await opened('tess_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  await idleFor(IDLE_LOCK_MS);
  assert.notEqual($('notice').textContent, PAPERS_IDLE, 'the account exists: no recovery key is said void after it');
  await $('lock-button').fire('click');
});

test('a registration service that does not answer: nothing is made and no paper is shown', async () => {
  reset(); chain.facts = false;
  await $('mode-create').fire('click'); await formDrawn();
  $('username').value = 'lars_p'; $('password').value = $('password-confirm').value = LOGIN; $('signup-payment').value = $('signup-payment-confirm').value = PAYMENT;
  $('notice').textContent = ''; await $('auth-form').fire('submit');
  await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.deepEqual([$('notice').textContent, $('signup-sheet').textContent, $('signup-sheet-step').hidden, kept('lars_p').login], ['The registration service of this wallet does not answer. Nothing was sent. Try again in a minute.', '', true, null]);
  reset();
  // A name the chain holds already: said at once, before any key or paper is made.
  const asked = chain.asked;
  $('username').value = 'bob'; $('password').value = $('password-confirm').value = LOGIN; $('signup-payment').value = $('signup-payment-confirm').value = PAYMENT;
  $('notice').textContent = ''; $('notice').className = 'notice'; await $('auth-form').fire('submit');
  await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.deepEqual([$('notice').textContent, $('signup-sheet').textContent, kept('bob').login, chain.asked - asked], ['That username is already registered.', '', null, 0]);
});

test('closed after the passwords, before "Create my account": on return nothing is kept, nothing was sent, and the form is there to start again', async () => {
  reset(); const posted = chain.posted.length, asked = chain.asked;
  await step1('gwen_p');
  await freshPage();
  assert.deepEqual([kept('gwen_p'), chain.posted.length - posted, chain.asked - asked], [{ login: null, spend: null, nextLogin: null, nextSpend: null, note: null }, 0, 0]);
  // This browser keeps other accounts, so the page opens on "Open my account" for one of them; nothing names gwen_p.
  assert.deepEqual([$('auth-heading').textContent, $('signup-sheet').textContent, $('signup-sheet-step').hidden], ['Open your account', '', true]);
  assert.notEqual($('username').value, 'gwen_p');
  await $('mode-create').fire('click');
  assert.deepEqual([$('auth-heading').textContent, $('password-label').textContent, $('signup-protected').hidden], ['Create your account', 'Login password', false]);
});

test('closed after the sponsor paid, before the registration: on return the name is filled in, the login password goes on, and the sponsor is not asked again', async () => {
  reset(); const asked = chain.asked;
  chain.drop = action => action.kind === 45;
  const papers = await step1('hugo_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  assert.ok($('notice').textContent.startsWith(KEPT), $('notice').textContent);
  assert.deepEqual([$('dashboard').hidden, byName('hugo_p'), chain.asked - asked], [true, undefined, 1]);
  const keptNow = kept('hugo_p');
  assert.deepEqual([keptNow.login.version, keptNow.nextLogin.intent, keptNow.nextSpend.intent, keptNow.note.kind], [4, 'signin', 'spend', 45]);
  // The rule, while a sign-up is kept: the registration key under the login key kept aside, both keys under made passwords.
  assert.equal(vaultUnder(keptNow.login).publicKey, keptNow.nextLogin.binding.publicKey);
  assert.deepEqual(sealsOf('hugo_p'), [['timecurrency.vault-next.v1:signin', 2, 'made'], ['timecurrency.vault-next.v1:spend', 2, 'made'], ['timecurrency.vault.v1', 4, 'under']]);
  // The page is closed and opened again. The registration service does not answer now: it is not needed, since the
  // chain holds the commitment it paid for.
  chain.drop = () => false; await freshPage();
  assert.deepEqual([$('username').value, $('auth-heading').textContent, $('notice').textContent], ['hugo_p', 'Open your account', 'Creating @hugo_p was not finished. Open it with your login password: this browser goes on from what the network shows.']);
  chain.facts = false;
  await unlock('hugo_p'); await opened('hugo_p');
  chain.facts = true;
  assert.equal($('notice').textContent, PROTECTED_READY);
  assert.deepEqual([chain.asked - asked, chain.posted.filter(a => a.kind === 44 && a.payload.public_key === byName('hugo_p').public_key).length], [1, 1], 'the sponsor paid once');
  assert.deepEqual([kept('hugo_p').login.intent, kept('hugo_p').note], ['signin', null]);
  await $('lock-button').fire('click');
});

test('gone on with no sponsor passed: when the commitment the wallet saw is gone by the time the SDK reads the chain, the registration service is asked then', async () => {
  reset(); const asked = chain.asked;
  chain.drop = action => action.kind === 45;
  const papers = await step1('rhea_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  assert.equal(chain.asked - asked, 1);
  // The wallet's own read shows the commitment, so it passes no sponsor; the SDK's read, a moment later, no longer does (it
  // ran out): the SDK says SPONSOR_REQUIRED before it signs anything, and the wallet asks the registration service then.
  reset(); const verify = globalThis.standInVerifier.verifyViewProof; let ranOut = false;
  globalThis.standInVerifier.verifyViewProof = async (proof, trust, query) => {
    if (!ranOut && !query.include_pos && query.public_keys?.length) { ranOut = true; chain.commits = chain.commits.filter(item => !query.public_keys.includes(item.public_key)); }
    return verify(proof, trust, query);
  };
  try { await unlock('rhea_p'); await opened('rhea_p'); } finally { globalThis.standInVerifier.verifyViewProof = verify; }
  assert.equal(ranOut, true, 'the SDK read the chain itself');
  assert.equal($('notice').textContent, PROTECTED_READY);
  assert.deepEqual([chain.asked - asked, chain.posted.filter(a => a.kind === 44 && a.payload.public_key === byName('rhea_p').public_key).length], [2, 2], 'asked once more, after the SDK said a sponsor is needed');
  await $('lock-button').fire('click');
});

test('closed after the registration, before the keys were put in place: the page puts them in place when it opens, or the login password does', async () => {
  // The registration reaches a block, and the gateway answers no read after it: the wallet stops before its keys move.
  reset(); chain.after = action => { if (action.kind === 45) chain.down = true; };
  let papers = await step1('ines_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  assert.ok(byName('ines_p'), 'the account is on the chain');
  assert.deepEqual([kept('ines_p').login.version, kept('ines_p').note.kind], [4, 45], 'the registration key, kept under the login key, still holds the login place');
  // Reopened: the page sees the account hold the kept keys, and puts them in place before anything is typed.
  reset(); await freshPage();
  assert.equal($('notice').textContent, 'The new keys of @ines_p are active on this browser. Unlock with the login password chosen for them.');
  assert.deepEqual([kept('ines_p').login.intent, kept('ines_p').note], ['signin', null]);
  await unlock('ines_p'); await opened('ines_p');
  await $('lock-button').fire('click');
  // The same stop, and the page is not reopened: the login password opens the registration key, which goes on from what
  // the chain shows (the account is there) and opens the account with its new login key.
  chain.after = action => { if (action.kind === 45) chain.down = true; };
  papers = await step1('jade_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  reset(); await unlock('jade_p'); await opened('jade_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  assert.deepEqual([kept('jade_p').login.intent, kept('jade_p').note, chain.posted.filter(a => a.kind === 45 && a.payload.name === 'jade_p').length], ['signin', null, 1]);
  await $('lock-button').fire('click');
});

test('each refusal in words: the name taken meanwhile, a service that pays for something else, one that paid already, another commitment, another set of keys, a network that does not take it', async () => {
  reset();
  // The name is taken by someone else between the words and the registration: nothing of the person's is on the chain.
  let papers = await step1('kurt_p');
  chain.accounts.push({ id: String(chain.nextId++), name: 'kurt_p', public_key: '4'.repeat(64), balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '4'.repeat(64), can_manage: true, can_spend: true }] });
  await step3(papers); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.signupWords({ code: 'NAME_TAKEN' }, 'kurt_p'));
  assert.equal($('notice').textContent, 'Someone else took the name @kurt_p before your account was made. Nothing of yours is on the network. The recovery words you wrote down for @kurt_p will never work: destroy the paper. Create your account with another name.');
  assert.deepEqual([$('auth-heading').textContent, $('dashboard').hidden], ['Create your account', true], 'the form for a new account');
  // The service answers with an action that pays for another key's commitment: not used, nothing registered.
  chain.service = 'other key'; papers = await step1('lena_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.deepEqual([$('notice').textContent, byName('lena_p')], [S.signupWords({ code: 'SPONSOR_MISMATCH' }, 'lena_p'), undefined]);
  assert.equal(chain.posted.filter(a => a.kind === 45 && a.payload.name === 'lena_p').length, 0, 'the registration was not signed');
  // The service paid for this key in the last 24 hours (its code account_limit): the wallet's sentence, the service's word.
  chain.service = 'account_limit'; await unlock('lena_p');
  await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, 'The registration service says that it paid for this sign-up in the last 24 hours, and that this payment ran out before your account was made. It pays again 24 hours after the first time: then open your account with your login password, and this browser goes on. Your recovery words stay valid.');
  reset();
  // A commitment of this sign-up's key with other details on the chain: nothing signed.
  chain.drop = action => action.kind === 44; papers = await step1('mona_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  const registration = await registrationOf('mona_p');
  chain.commits.push({ public_key: registration.binding.publicKey, commitment: 'cd'.repeat(32), sponsor: '1', expires_elapsed_micros: String(chain.now + DAY), height: String(chain.height - 1) });
  reset(); await unlock('mona_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.signupWords({ code: 'COMMITMENT_MISMATCH' }, 'mona_p'));
  chain.commits = chain.commits.filter(item => item.public_key !== registration.binding.publicKey);
  // The account of this sign-up holds other keys than the ones kept here (changed by someone with the recovery words).
  chain.after = action => { if (action.kind === 45) chain.down = true; };
  papers = await step1('nora_p'); await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  reset(); byName('nora_p').devices = byName('nora_p').devices.filter(d => d.can_manage || d.can_spend).concat([{ public_key: '5'.repeat(64), can_manage: false, can_spend: false }]);
  await unlock('nora_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.signupWords({ code: 'REGISTRATION_MISMATCH' }, 'nora_p'));
  // A network that does not take such a registration (here: its genesis lost the setting, which a real one cannot).
  chain.drop = action => action.kind === 44; papers = await step1('omar_p'); await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  reset(); chain.protect = false; await unlock('omar_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.signupWords({ code: 'PROTECTED_REGISTRATION_UNAVAILABLE' }, 'omar_p'));
  reset(); await freshPage();
});

test('a name that the network refuses as too close to one that exists: the wallet\'s sentence, the recovery keys of that name said void, and the form for a new account', async () => {
  reset(); chain.accounts.push({ id: String(chain.nextId++), name: 'paypal', public_key: '6'.repeat(64), balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '6'.repeat(64), can_manage: true, can_spend: true }] });
  // The chain refuses the registration with the engine's words; the gateway passes them on.
  chain.refuse = action => (action.kind === 45 ? `the name ${action.payload.name} is too close to the existing name paypal` : null);
  const papers = await step1('paypa1');
  await step3(papers); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, 'That name is too close to @paypal, which already exists. Choose another. The recovery words you wrote down for @paypa1 will never work: destroy the paper.');
  assert.deepEqual([$('auth-heading').textContent, byName('paypa1'), chain.posted.at(-1).kind], ['Create your account', undefined, 45]);
  reset();
});

test('a sign-up kept in this browser is used only as it was kept: a payment key put in its place by whatever can write the storage is refused before anything is sent', async () => {
  reset(); chain.drop = action => action.kind === 44;
  const papers = await step1('pia_p'); await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  // Someone with write access to this browser's storage puts a payment key of their own into the kept sign-up.
  const s = slots('pia_p'), kept0 = storage.getItem(s.nextNote), note = JSON.parse(kept0), thief = await newDevice();
  note.keys = note.keys.map(k => (k.role === 'spend' ? { ...k, public_key: thief.publicKey } : k));
  storage.setItem(s.nextNote, JSON.stringify(note));
  reset(); const posted = chain.posted.length, asked = chain.asked;
  await unlock('pia_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.CHANGED);
  assert.deepEqual([chain.posted.length - posted, chain.asked - asked, byName('pia_p')], [0, 0, undefined], 'nothing was sent');
  // The note as it was, and a payment key of someone else's in the place kept aside for the payment key: refused too.
  storage.setItem(s.nextNote, kept0);
  const spendKept = storage.getItem(s.nextSpend), other = await F.sealedKey({ networkId: NET, name: 'pia_p', intent: 'spend', argon2id });
  storage.setItem(s.nextSpend, JSON.stringify(other.record));
  await unlock('pia_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.deepEqual([$('notice').textContent, chain.posted.length - posted, byName('pia_p')], [S.CHANGED, 0, undefined]);
  storage.setItem(s.nextSpend, spendKept);
  // The note's form and signature, checked apart from the page.
  const registration = await registrationOf('pia_p');
  await assert.rejects(S.readNote(JSON.stringify(note), { networkId: NET, name: 'pia_p', registrationKey: registration.binding.publicKey }), { message: S.CHANGED });
  assert.equal((await S.readNote(kept0, { networkId: NET, name: 'pia_p', registrationKey: registration.binding.publicKey })).name, 'pia_p', 'the note as it was is read');
  // A note is read only for its own name, network and registration key, its signature notwithstanding.
  for (const other of [{ name: 'pia_q' }, { networkId: 'd7'.repeat(32) }, { registrationKey: '7'.repeat(64) }]) await assert.rejects(S.readNote(kept0, { networkId: NET, name: 'pia_p', registrationKey: registration.binding.publicKey, ...other }), { message: S.CHANGED }, JSON.stringify(other));
  validateVaultRecord(kept('pia_p').nextSpend, 'spend');
  await freshPage();
});

test('a kept sign-up that the network shows nothing of is let go, once its last consent ran out, through a review; the name can be signed up again', async () => {
  // The words were shown and the keys kept, the consent signed, and the registration service was not reached.
  reset(); chain.drop = action => action.kind === 44;
  const papers = await step1('uma_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  // The expiry of that consent is kept, signed by the registration key: the one the SDK gave, five minutes ahead.
  const record = JSON.parse(storage.getItem(S.consentKey(NET, 'uma_p'))), expires = chain.now + 300000000n;
  assert.deepEqual([record.expires_elapsed_micros, record.registration, kept('uma_p').login.binding.publicKey], [expires.toString(), kept('uma_p').login.binding.publicKey, record.registration]);
  assert.equal(await S.readConsent(storage.getItem(S.consentKey(NET, 'uma_p')), { networkId: NET, name: 'uma_p', registrationKey: record.registration }), expires);
  // The page is opened again: it names a sign-up it keeps (the first it finds: earlier tests left others), offers to let it
  // go, and removes nothing by itself.
  reset(); const before = raw('uma_p'); await freshPage();
  assert.deepEqual([/^Creating @[a-z_]+ was not finished\./.test($('notice').textContent), $('signup-letgo-row').hidden, raw('uma_p')], [true, false, before]);
  $('username').value = 'uma_p';
  // The person forgot the login password. Not yet: that consent could still make a registration.
  let done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('uma_p')], [null, S.letGoWords({ why: 'consent', kept: true, until: expires }, 'uma_p', chainDate), before]);
  assert.equal(done.notice, `Nothing of this sign-up is on the network now, but a registration of it that was asked for could still reach it until ${chainDate(expires)}. Come back after that time to let it go.`);
  // After it: the review says what is given up; cancelled, nothing changes.
  chain.now = expires + 1n;
  done = await letGo();
  assert.deepEqual(done.review, { title: 'Let this sign-up go', confirm: 'Let it go', fields: { Name: '@uma_p is free again, for anyone. This browser forgets the keys it made for this sign-up; it cannot be undone.', 'Recovery words': 'The recovery words you wrote down for @uma_p will never work: destroy the paper.' } });
  assert.deepEqual([done.notice, raw('uma_p')], ['Nothing was changed. The sign-up is still kept in this browser.', before]);
  // Another tab of this browser goes on with the sign-up while the review is open (its person remembered the password):
  // the consent it gives is kept as a newer record, and the check after the review reads it, and stops.
  const registration = await registrationOf('uma_p'), newer = chain.now + 300000000n;
  done = await letGo({ confirm: true, during: async () => { storage.setItem(S.consentKey(NET, 'uma_p'), JSON.stringify(await S.signConsent({ networkId: NET, name: 'uma_p', registration: { publicKey: registration.binding.publicKey, privateKey: registration.privateKey }, expiresElapsedMicros: newer }))); } });
  assert.deepEqual([done.review?.title, done.notice], ['Let this sign-up go', S.letGoWords({ why: 'consent', kept: true, until: newer }, 'uma_p', chainDate)]);
  assert.deepEqual(raw('uma_p').slice(0, 5), before.slice(0, 5), 'nothing was removed');
  storage.setItem(S.consentKey(NET, 'uma_p'), before[5]);
  // Confirmed: everything of the sign-up is gone from this browser, and nothing else.
  const own = slots('uma_p'), others = [...storage.m.keys()].filter(key => ![own.login, own.nextLogin, own.nextSpend, own.nextNote, S.consentKey(NET, 'uma_p')].includes(key));
  done = await letGo({ confirm: true });
  assert.deepEqual([done.notice, raw('uma_p'), $('signup-letgo-row').hidden], [S.letGoneWords('uma_p'), [null, null, null, null, null, null], true]);
  assert.equal(done.notice, 'This browser let the sign-up of @uma_p go. Destroy the paper of its recovery words.');
  assert.deepEqual(others.filter(key => !storage.m.has(key)), [], 'nothing else was removed');
  assert.equal(chain.accounts.some(a => a.name === 'uma_p'), false);
  // The name can be signed up again in this browser.
  const again = await step1('uma_p'); await step3(again); await opened('uma_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  await $('lock-button').fire('click');
});

test('not let go while the network holds a commitment or the account of the sign-up: the wallet says what to do instead; without a record of the consent, this page waits ten minutes itself', async () => {
  // A commitment: the sponsor paid, and the registration did not reach a block.
  reset(); chain.drop = action => action.kind === 45;
  let papers = await step1('vera_p'); await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  const commit = chain.commits.find(item => item.public_key === kept('vera_p').login.binding.publicKey), ends = BigInt(commit.expires_elapsed_micros);
  reset(); $('username').value = 'vera_p'; const before = raw('vera_p');
  let done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('vera_p')], [null, `A registration of @vera_p from this sign-up waits on the network until ${chainDate(ends)}, so this browser keeps the sign-up. If you remember your login password, open your account with it before then; if not, come back after that time to let it go.`, before]);
  // The commitment ran out, and this browser keeps no record of the consent (a sign-up kept before there was one, or a
  // record that whatever writes the storage removed): the page itself waits ten minutes from its first such reading.
  storage.removeItem(S.consentKey(NET, 'vera_p')); chain.now = ends + 1n;
  const first = chain.now, wait = `Nothing of this sign-up is on the network now. This browser does not know when a registration of it was last asked for, so it waits ten minutes to be sure that none can reach the network any more: keep this page open, and press "Let this sign-up go" again after ${chainDate(first + 600000000n)}.`;
  done = await letGo();
  assert.deepEqual([done.review, done.notice], [null, wait]);
  chain.now += 600000000n; done = await letGo();
  assert.deepEqual([done.review, done.notice], [null, wait], 'the wait is counted from the first reading, and not started again');
  chain.now += 1n; done = await letGo();
  assert.equal(done.review?.title, 'Let this sign-up go');
  // The network is read again once the review is confirmed: a commitment of the sign-up that came while it was open (a
  // consent this page did not know of, used by a sponsor) stops it, and nothing is removed.
  const late = { public_key: kept('vera_p').login.binding.publicKey, commitment: 'ef'.repeat(32), sponsor: '1', expires_elapsed_micros: String(chain.now + 60000000n), height: String(chain.height) };
  done = await letGo({ confirm: true, during: () => { chain.commits.push(late); } });
  assert.deepEqual([done.review?.title, done.notice, raw('vera_p')], ['Let this sign-up go', `A registration of @vera_p from this sign-up waits on the network until ${chainDate(BigInt(late.expires_elapsed_micros))}, so this browser keeps the sign-up. If you remember your login password, open your account with it before then; if not, come back after that time to let it go.`, before.map((value, at) => (at === 5 ? null : value))]);
  chain.commits = chain.commits.filter(item => item !== late);
  // A page opened again knows nothing of that first reading: it waits again.
  await freshPage(); $('username').value = 'vera_p';
  done = await letGo();
  assert.deepEqual([done.review, done.notice], [null, wait.replace(chainDate(first + 600000000n), chainDate(chain.now + 600000000n))]);
  // The account: the registration reached a block, and the keys were not put in place.
  reset(); chain.after = action => { if (action.kind === 45) chain.down = true; };
  papers = await step1('wyn_p'); await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  reset(); $('username').value = 'wyn_p'; const made = raw('wyn_p');
  done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('wyn_p')], [null, 'The network holds the account @wyn_p that this sign-up made, so this browser keeps what opens it. Open it with the login password you chose for it; if you forgot that, recover the account with your recovery words, under "Other ways in".', made]);
  await unlock('wyn_p'); await opened('wyn_p'); await $('lock-button').fire('click');
});

test('what can write this browser\'s storage cannot make the wallet let a real account go: a changed note, a forged record of the consent, a sign-up written over a real account', async () => {
  reset(); chain.drop = action => action.kind === 44;
  const papers = await step1('xia_p'); await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  reset(); $('username').value = 'xia_p';
  const s = slots('xia_p'), before = raw('xia_p'), registrationKey = kept('xia_p').login.binding.publicKey;
  // A note whose payment key was swapped: not this sign-up's any more, and not let go.
  const note = JSON.parse(before[4]), thief = await newDevice();
  storage.setItem(s.nextNote, JSON.stringify({ ...note, keys: note.keys.map(k => (k.role === 'spend' ? { ...k, public_key: thief.publicKey } : k)) }));
  let done = await letGo();
  assert.deepEqual([done.review, done.notice], [null, S.LET_GO_CHANGED]);
  storage.setItem(s.nextNote, before[4]);
  // The note as it was, and a payment key of someone else's in the place kept aside for the payment key, or a login key
  // of someone else's in its place: refused too, and nothing is removed.
  for (const [place, intent] of [[s.nextSpend, 'spend'], [s.nextLogin, 'signin']]) {
    const other = await F.sealedKey({ networkId: NET, name: 'xia_p', intent, argon2id });
    storage.setItem(place, JSON.stringify(other.record));
    done = await letGo();
    assert.deepEqual([done.review, done.notice], [null, S.LET_GO_CHANGED], intent);
    storage.setItem(place, before[place === s.nextSpend ? 3 : 2]);
  }
  assert.deepEqual(raw('xia_p'), before);
  // A record of the consent with an early expiry, not signed by the registration key, or signed for another name: it is
  // not used, and the page waits by itself, although the chain's time is past what the record says.
  const other = await newDevice(), real = BigInt(JSON.parse(before[5]).expires_elapsed_micros);
  for (const forged of [{ ...JSON.parse(before[5]), expires_elapsed_micros: '1' }, await S.signConsent({ networkId: NET, name: 'xia_p', registration: other, expiresElapsedMicros: '1' }), await S.signConsent({ networkId: NET, name: 'xia_q', registration: { publicKey: registrationKey, privateKey: other.privateKey }, expiresElapsedMicros: '1' })]) {
    storage.setItem(S.consentKey(NET, 'xia_p'), JSON.stringify(forged));
    assert.equal(await S.readConsent(JSON.stringify(forged), { networkId: NET, name: 'xia_p', registrationKey }), null);
    done = await letGo();
    assert.equal(done.review, null); assert.match(done.notice, /^Nothing of this sign-up is on the network now\. This browser does not know when a registration of it was last asked for/);
  }
  assert.ok(chain.now < real, 'the real consent has not run out');
  storage.setItem(S.consentKey(NET, 'xia_p'), before[5]);
  assert.deepEqual(raw('xia_p'), before, 'nothing was removed');
  // A sign-up of its own written over a real protected account (erin_p, made above): a registration key of its own in the
  // login place (which already destroys that account's login key in this browser), a note it signed, and keys aside. The
  // network shows nothing of that sign-up, but this browser keeps the account's payment key: nothing is let go.
  const e = slots('erin_p'), erin = raw('erin_p'), fake = await newDevice();
  const signin = await F.sealedKey({ networkId: NET, name: 'erin_p', intent: 'signin', argon2id }), spend = await F.sealedKey({ networkId: NET, name: 'erin_p', intent: 'spend', argon2id });
  const fakeKeys = [['signin', signin.key.publicKey], ['spend', spend.key.publicKey], ['recover', '7'.repeat(64)], ['recover', '8'.repeat(64)]].map(([role, public_key]) => ({ public_key, role, proof: 'ab'.repeat(64) }));
  storage.setItem(e.login, JSON.stringify(await sealLegacy({ ...fake.secret, nameSalt: 'cd'.repeat(32), intent: 'device' }, LOGIN, { networkId: NET, name: 'erin_p', publicKey: fake.publicKey }, argon2id)));
  storage.setItem(e.nextNote, JSON.stringify(await S.signNote({ networkId: NET, name: 'erin_p', registration: fake, keys: fakeKeys, policy: { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800' } })));
  storage.setItem(e.nextLogin, JSON.stringify(signin.record)); storage.setItem(e.nextSpend, JSON.stringify(spend.record));
  const written = raw('erin_p');
  $('username').value = 'erin_p';
  done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('erin_p')], [null, 'This browser keeps a payment key of an account @erin_p, so it does not let a sign-up of that name go. Open that account with its login password.', written]);
  assert.equal(written[1], erin[1], 'the account\'s payment key is still kept');
  // The account's payment key removed as well: the network holds an account of that name, and that is enough. A sign-up
  // whose name another account holds is not let go (signup.mjs, letGoState: 'taken'), so the person is never told there
  // to destroy recovery words that may be that account's.
  const taken = 'The name @erin_p belongs to another account on the network, so this sign-up can never finish, and this browser keeps it as it is. If that account is yours, open it with its login password, or recover it with your recovery words; if not, create your account with another name.';
  storage.removeItem(e.spend);
  done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('erin_p')], [null, taken, written.map((value, at) => (at === 1 ? null : value))]);
  // The same for a sign-up of its own whose name someone else took meanwhile (kurt_p, above).
  $('username').value = 'kurt_p'; const kurt = raw('kurt_p');
  done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('kurt_p')], [null, taken.replaceAll('erin_p', 'kurt_p'), kurt]);
  for (const [at, key] of [e.login, e.spend, e.nextLogin, e.nextSpend, e.nextNote, S.consentKey(NET, 'erin_p')].entries()) { if (erin[at] === null) storage.removeItem(key); else storage.setItem(key, erin[at]); }
  // No name typed that this browser keeps a sign-up of: nothing to let go.
  $('username').value = 'bob'; done = await letGo();
  assert.deepEqual([done.review, done.notice], [null, 'This browser keeps no unfinished sign-up of that name. Type the name you signed up with.']);
  // Cleaned up: xia_p let go once its consent ran out.
  chain.now = real + 1n; $('username').value = 'xia_p';
  done = await letGo({ confirm: true });
  assert.deepEqual([done.notice, raw('xia_p')], [S.letGoneWords('xia_p'), [null, null, null, null, null, null]]);
});

// ------------------------------------------------------------------ keys locked to the device from birth (the rule)
/// A device that locks keys, put on the stand-in page's window (the fake authenticator of device-lock.test.mjs: it makes
/// keys, checks the person and gives PRF secrets as CTAP2 hmac-secret does). `getErrors`: one error name per request.
/// `hold`: a promise the browser's answers to what the device can do wait for (one that never settles: no answer).
function deviceOnPage(s = {}) {
  const keys = []; let gets = 0, creates = 0;
  const buffer = bytes => { const copy = new ArrayBuffer(bytes.length); new Uint8Array(copy).set(bytes); return copy; };
  const authData = () => { const b = new Uint8Array(37); b[32] = 0x05; return buffer(b); };
  const prfOf = (key, salt) => createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest();
  class PublicKeyCredential { static async isUserVerifyingPlatformAuthenticatorAvailable() { await s.hold; return true; } static async getClientCapabilities() { await s.hold; return { userVerifyingPlatformAuthenticator: true, 'extension:prf': true }; } }
  const credentials = {
    async create(options) { creates += 1; const key = { id: randomBytes(32), secret: randomBytes(32) }; keys.push(key); return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: () => authData() }, getClientExtensionResults: () => ({ prf: { enabled: true } }) }; },
    async get(options) {
      gets += 1; const error = s.getErrors?.[gets - 1]; if (error) throw new DOMException('x', error);
      const key = keys.at(-1), salts = options.publicKey.extensions.prf.eval;
      return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: authData() }, getClientExtensionResults: () => ({ prf: { results: { first: buffer(prfOf(key.secret, salts.first)), ...(salts.second ? { second: buffer(prfOf(key.secret, salts.second)) } : {}) } } }) };
    },
  };
  Object.assign(globalThis.window, { isSecureContext: true, PublicKeyCredential, navigator: { credentials, userAgent: 'stand-in' }, crypto: globalThis.crypto });
  return { gets: () => gets, creates: () => creates, off() { for (const k of ['isSecureContext', 'PublicKeyCredential', 'navigator', 'crypto']) delete globalThis.window[k]; storage.removeItem(DEVICE_KEY_PLACE); } };
}

test('where the device can lock keys, the form shows one choice of two ways, neither chosen; with none chosen it does not go on and says so; a way chosen and changed before sending: the fields of the passwords come with the lock only', async () => {
  reset(); const device = deviceOnPage();
  try {
    await freshPage();
    await $('mode-create').fire('click');
    await choiceDrawn();
    // The choice, in the wallet's words (device-lock.mjs, LOCK_WORDS.ways, the one place of them), and no field of a password.
    assert.deepEqual(['auth-ways-legend', 'auth-way-device-title', 'auth-way-device-note', 'auth-way-made-title', 'auth-way-made-note'].map(id => $(id).textContent), [LOCK_WORDS.ways.legend, LOCK_WORDS.ways.device.title, LOCK_WORDS.ways.device.note, LOCK_WORDS.ways.made.title, LOCK_WORDS.ways.made.note]);
    assert.deepEqual(JSON.parse(JSON.stringify(LOCK_WORDS.ways)), {
      legend: 'Choose how to lock your new keys',
      device: { title: 'Lock them to this device', note: 'They open with your fingerprint, face or screen lock and passwords you choose. If this device loses its key, your recovery words get you back in after the waiting period; to change devices, use “Move my account to another device”.' },
      made: { title: 'Let the wallet make the passwords', note: 'Nothing of this device is used. The wallet makes two passwords and shows them to you once: keep both, and type the payment password at each payment.' },
      pick: 'First choose how to lock your new keys: to this device, or with passwords the wallet makes.',
      asking: 'One moment: checking what this device can do.',
    });
    assert.deepEqual(['password', 'password-confirm', 'signup-chosen', 'signup-login-note'].map(id => $(id).hidden).concat(['password', 'signup-payment'].map(id => $(id).required)), [true, true, true, true, false, false]);
    assert.equal($('auth-copy').textContent, 'Pick a name and how to lock your keys. The wallet then shows five recovery words for you to write on paper. Your account is protected from its first moment.');
    // Sent with no way chosen: one sentence, and nothing read, made, kept or sent; the device is asked nothing.
    const posted = chain.posted.length;
    $('username').value = 'non_p'; $('notice').textContent = ''; $('notice').className = 'notice';
    await $('auth-form').fire('submit');
    await until(() => $('notice').className.includes('error'), 'the wallet to refuse');
    assert.equal($('notice').textContent, LOCK_WORDS.ways.pick);
    assert.deepEqual([kept('non_p'), chain.posted.length - posted, device.creates(), device.gets(), $('made-dialog').open, $('signup-sheet-step').hidden], [{ login: null, spend: null, nextLogin: null, nextSpend: null, note: null }, 0, 0, 0, false, true]);
    assert.deepEqual([$('auth-ways').hidden, $('auth-way-device').checked, $('auth-way-made').checked], [false, false, false], 'the choice is still there, and still not made');
    // The lock chosen: the fields of the chosen passwords, asked. The other way then: they go, and so does what was typed.
    await choose('device');
    assert.deepEqual([$('password').hidden, $('password-confirm').hidden, $('signup-chosen').hidden, $('signup-login-note').hidden, $('password').required, $('signup-payment').required], [false, false, false, false, true, true]);
    assert.equal($('auth-copy').textContent, 'Pick a name, a login password and a payment password: your device locks your keys with them. The wallet then shows five recovery words for you to write on paper. Your account is protected from its first moment.');
    $('password').value = $('password-confirm').value = LOGIN; $('signup-payment').value = $('signup-payment-confirm').value = PAYMENT;
    await choose('made');
    assert.deepEqual([$('password').hidden, $('signup-chosen').hidden, $('password').required, $('signup-payment').required, $('auth-way-device').checked, $('auth-way-made').checked], [true, true, false, false, false, true]);
    assert.deepEqual(['password', 'password-confirm', 'signup-payment', 'signup-payment-confirm'].map(id => $(id).value), ['', '', '', ''], 'what was typed went with the fields');
    // "Open my account" shows no choice; back on "Create an account", the form is drawn again with neither way chosen.
    await $('mode-unlock').fire('click'); assert.equal($('auth-ways').hidden, true);
    await $('mode-create').fire('click'); await choiceDrawn();
    // Chosen and changed before sending: the lock with the passwords typed, then the passwords the wallet makes, the lock
    // again, and the passwords the wallet makes, which are sent. What was typed while the lock was chosen seals nothing;
    // the device is asked nothing.
    for (const way of ['device', 'made', 'device']) { await choose(way); if (way === 'device') { $('password').value = $('password-confirm').value = LOGIN; $('signup-payment').value = $('signup-payment-confirm').value = PAYMENT; } }
    await choose('made');
    const changed = await step1('chg_p', { device: true, decline: true, chosen: true });
    assert.ok(changed.made, 'the passwords were made and shown');
    assert.deepEqual([device.creates(), device.gets()], [0, 0], 'the device was asked nothing');
    await step3(changed); await opened('chg_p');
    assert.deepEqual(await provenFor('chg_p', [changed.login, changed.payment], [LOGIN, PAYMENT]), []);
    await $('lock-button').fire('click');
  } finally { device.off(); reset(); }
});

test('where the device can lock keys and the person chooses the lock (after the other way first): the passwords chosen, the device asked three times, nothing a password alone opens is kept; the sign-up kept, the page loaded again: gone on with, the keys stay locked, and opening asks the device once', async () => {
  reset(); const device = deviceOnPage();
  try {
    await freshPage();
    // What the page says before the device asks (sealAtBirth).
    assert.equal(LOCK_WORDS.birth, 'Your device will lock your new keys: it asks for your fingerprint, face or screen lock, two or three times. You choose the passwords.');
    // Kept, and the registration stopped before it reached a block: what this browser keeps while the sign-up waits.
    chain.drop = action => action.kind === 45;
    const papers = await step1('dev_p', { device: true, switched: true });
    assert.equal(papers.made, null, 'no password was made: none was shown');
    assert.deepEqual([device.creates(), device.gets()], [1, 2], 'the device made its key and was asked twice');
    await step3(papers); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
    assert.deepEqual(sealsOf('dev_p'), [['timecurrency.vault-next.v1:signin', 3, 'device'], ['timecurrency.vault-next.v1:spend', 3, 'device'], ['timecurrency.vault.v1', 4, 'under']]);
    // The page loaded again: it opens on "Open my account" (this browser keeps vaults), which shows no choice. Gone on with
    // the login password: the device asked once, for the login key kept aside, which opens the registration key.
    chain.drop = () => false;
    await freshPage();
    assert.equal($('auth-ways').hidden, true);
    const asked = device.gets();
    await unlock('dev_p'); await opened('dev_p');
    assert.equal($('notice').textContent, PROTECTED_READY);
    assert.equal(device.gets() - asked, 1, 'one request to go on, and none more to open the account');
    assert.deepEqual(sealsOf('dev_p'), [['timecurrency.spend-vault.v1', 3, 'device'], ['timecurrency.vault.v1', 3, 'device']]);
    // The passwords alone open nothing.
    await assert.rejects(openVault(kept('dev_p').login, LOGIN, argon2id, globalThis.crypto, 'signin'), error => error.deviceNeeded === true);
    await $('lock-button').fire('click');
  } finally { device.off(); reset(); }
});

test('where the device can lock keys and the person chooses the passwords the wallet makes, and where the device fails after the lock was chosen: the wallet makes both passwords and shows them; the sign-up goes on, also after the page was loaded again', async () => {
  reset(); let device = deviceOnPage();
  try {
    await freshPage();
    // Kept, and the registration stopped before it reached a block; the page loaded again, then gone on with the login
    // password the wallet made: the keys stay under the passwords the wallet made, as chosen, and the device is asked nothing.
    chain.drop = action => action.kind === 45;
    const declined = await step1('dec_p', { device: true, decline: true });
    assert.ok(declined.made, 'the passwords were made and shown');
    assert.equal(declined.made.why, 'The wallet made the passwords of your new account. Let your browser save the login password; write the payment password down, apart from your recovery words.');
    assert.deepEqual([device.creates(), device.gets()], [0, 0], 'the device was asked nothing');
    await step3(declined); await until(() => $('notice').className.includes('error'), 'the wallet to stop');
    assert.deepEqual(sealsOf('dec_p'), [['timecurrency.vault-next.v1:signin', 2, 'made'], ['timecurrency.vault-next.v1:spend', 2, 'made'], ['timecurrency.vault.v1', 4, 'under']]);
    chain.drop = () => false;
    await freshPage();
    assert.equal($('auth-ways').hidden, true);
    await unlock('dec_p'); await opened('dec_p');
    assert.equal($('notice').textContent, PROTECTED_READY);
    assert.deepEqual([device.creates(), device.gets()], [0, 0], 'the device was asked nothing');
    assert.deepEqual(sealsOf('dec_p'), [['timecurrency.spend-vault.v1', 2, 'made'], ['timecurrency.vault.v1', 2, 'made']]);
    assert.deepEqual(await provenFor('dec_p', [declined.login, declined.payment]), []);
    await $('lock-button').fire('click');
    // The person chose the lock, then cancels the device's second request: the passwords typed seal nothing; the wallet made
    // them, and says why.
    device.off(); device = deviceOnPage({ getErrors: [null, 'NotAllowedError'] });
    await freshPage();
    const failed = await step1('fal_p', { device: true });
    assert.ok(failed.made, 'the passwords were made and shown');
    assert.equal(failed.made.why, `The device did not give its key, so your keys are not locked to it. ${LOCK_WORDS.fellBack}`);
    assert.notEqual(failed.login, LOGIN);
    await step3(failed); await opened('fal_p');
    assert.deepEqual(sealsOf('fal_p'), [['timecurrency.spend-vault.v1', 2, 'made'], ['timecurrency.vault.v1', 2, 'made']]);
    await assert.rejects(openVault(kept('fal_p').spend, PAYMENT, argon2id, globalThis.crypto, 'spend'), error => error.madeForm === true, 'the payment password typed opens nothing');
    await $('lock-button').fire('click');
  } finally { device.off(); reset(); }
});

test('until the browser has said what the device can do, the form shows neither the choice nor the sentence of a device that cannot lock keys, and a send is refused in one sentence and makes nothing; the answer draws the choice, and the form goes on; an answer that never comes is taken, after a few seconds, as a device that cannot lock keys', async () => {
  const { WAY_ANSWER_MS } = await import(new URL('web-v4/wallet/device-lock-ui.mjs', root).href);
  assert.ok(WAY_ANSWER_MS >= 2000 && WAY_ANSWER_MS <= 5000, 'a few seconds');
  assert.equal(LOCK_WORDS.ways.asking, 'One moment: checking what this device can do.');
  reset(); let answer; let device = deviceOnPage({ hold: new Promise(resolve => { answer = resolve; }) });
  /// The form while the browser has not answered: no choice, no sentence, no field of a password.
  const asking = () => assert.deepEqual([$('auth-ways').hidden, $('auth-seal-note').hidden, $('auth-seal-note').textContent, $('password').hidden, $('signup-chosen').hidden], [true, true, '', true, true], 'neither state is shown');
  try {
    await freshPage();
    await $('mode-create').fire('click');
    asking();
    // Sent before the answer: one sentence, and nothing read, made, kept or sent; the device is asked nothing more.
    const posted = chain.posted.length;
    $('username').value = 'ask_p'; $('notice').textContent = ''; $('notice').className = 'notice';
    await $('auth-form').fire('submit');
    await until(() => $('notice').className.includes('error'), 'the wallet to refuse');
    assert.equal($('notice').textContent, LOCK_WORDS.ways.asking);
    assert.deepEqual([kept('ask_p'), chain.posted.length - posted, device.creates(), device.gets(), $('made-dialog').open, $('signup-sheet-step').hidden], [{ login: null, spend: null, nextLogin: null, nextSpend: null, note: null }, 0, 0, 0, false, true]);
    asking();
    // The answer: the choice, neither way chosen; a way chosen, the form goes on.
    answer();
    await choiceDrawn();
    await choose('made');
    const made = await step1('ask_p', { device: true, decline: true, chosen: true });
    assert.ok(made.made, 'the passwords were made and shown');
    assert.deepEqual([device.creates(), device.gets()], [0, 0]);
    await $('signup-cancel').fire('click');
  } finally { device.off(); reset(); }
  // A browser that never answers: after WAY_ANSWER_MS the form is the one of a device that cannot lock keys, and goes on.
  device = deviceOnPage({ hold: new Promise(() => {}) });
  try {
    await freshPage();
    await $('mode-create').fire('click');
    asking();
    const since = Date.now();
    await until(() => $('auth-seal-note').hidden === false, 'the form of a device that cannot lock keys');
    assert.ok(Date.now() - since >= WAY_ANSWER_MS - 200, 'not before the few seconds');
    assert.deepEqual([$('auth-seal-note').textContent, $('auth-ways').hidden, $('password').hidden], [LOCK_WORDS.birthMade, true, true]);
    const made = await step1('sil_p', { chosen: true });
    assert.ok(made.made, 'the passwords were made and shown');
    assert.deepEqual([device.creates(), device.gets()], [0, 0]);
    await $('signup-cancel').fire('click');
  } finally { device.off(); reset(); }
});

test('on a network without the setting: one key, a reveal, and the card "Not protected yet"; the wallet makes the password of the key, shows it before the key is kept, and nothing typed seals it', async () => {
  reset(); chain.protect = false;
  try {
    await freshPage();
    // The form is the page's own: the script touched none of the protected fields (the stand-in page starts them empty,
    // and hidden as index.html has them).
    assert.deepEqual([$('password-label').textContent, $('confirm-label').textContent, $('signup-protected').hidden, $('signup-login-note').hidden], ['', '', true, true], 'nothing of the protected form was drawn');
    await $('mode-create').fire('click');
    assert.deepEqual([$('auth-copy').textContent, $('auth-submit').textContent, $('signup-protected').hidden, $('password-label').textContent, $('auth-ways').hidden], ['Pick a name that others can send seconds to. The wallet makes your password and shows it to you.', 'Create my account', true, '', true]);
    // No password field is asked (the rule): the wallet makes it.
    assert.deepEqual([$('password').hidden, $('password-confirm').hidden, $('password').required, $('auth-seal-note').hidden, $('auth-seal-note').textContent], [true, true, false, false, 'The wallet makes your password and shows it to you next.']);
    const posted = chain.posted.length;
    $('username').value = 'quin'; $('password').value = $('password-confirm').value = LOGIN;
    $('notice').textContent = ''; $('notice').className = 'notice';
    const sent = $('auth-form').fire('submit');
    await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the password the wallet made');
    // Shown before the key is kept, and before anything is sent.
    assert.deepEqual([kept('quin').login, chain.posted.length - posted], [null, 0]);
    const shown = await madeShown(); await sent;
    assert.deepEqual([madeForm(shown.login), shown.payment, shown.name], [shown.login, '', 'quin']);
    passwords.quin = { login: shown.login };
    await opened('quin');
    assert.equal($('notice').textContent, 'Your account is ready. This browser checked it with the network. Next: keep your account safe under Keys.');
    assert.deepEqual(chain.posted.slice(posted).map(a => a.kind), [44, 2], 'the sponsor\'s action, then the reveal');
    const account = byName('quin');
    assert.deepEqual([account.devices.length, account.devices[0].can_manage && account.devices[0].can_spend, chain.security[account.id]], [1, true, undefined]);
    assert.deepEqual([$('protect-none').hidden, $('protect-on').hidden, kept('quin').login.version, kept('quin').login.password, kept('quin').note], [false, true, 1, 'made', null]);
    assert.deepEqual(sealsOf('quin'), [['timecurrency.vault.v1', 1, 'made']]);
    // What was typed in the hidden field seals nothing; the password shown opens the key.
    await assert.rejects(openVault(kept('quin').login, LOGIN, argon2id), error => error.madeForm === true);
    assert.equal((await openVault(kept('quin').login, shown.login, argon2id)).binding.name, 'quin');
    await $('lock-button').fire('click'); await unlock('quin'); await opened('quin');
  } finally { reset(); await freshPage(); }
});

// ------------------------------------------------------------------ the passwords the wallet made, closed without "I have them"
/// The review of the page (app.js, review), confirmed once it may be.
async function confirmReview() {
  await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the review');
  assert.equal($('review-dialog').open, true, $('notice').textContent);
  for (const fire of arming.splice(0)) fire();
  $('review-dialog').returnValue = 'confirm'; $('review-dialog').open = false; await $('review-dialog').fire('close');
}
/// The wallet's answer once the dialog of the passwords it made was closed without "I have them": an error, in these words.
async function refusedWith(words) {
  await until(() => $('notice').className.includes('error'), 'the wallet to say that nothing was kept');
  assert.equal($('notice').textContent, words);
}
const fresh = () => { $('notice').textContent = ''; $('notice').className = 'notice'; };
/// The vault records this browser keeps for a name, as [key, value] pairs.
const entriesOf = name => [...storage.m].filter(([key]) => key.endsWith(`:${name}`) || key.includes(`:${name}:`));
/// What tests/legacy-vault.mjs (provenSeals) finds wrong in them, by opening them: `shown`, the passwords the step showed;
/// `typed`, what the person typed; `device`, the secret of this page's device for a record locked to it.
const provenFor = (name, shown, typed = [], { files = [], device = null } = {}) => provenSeals({ entries: entriesOf(name), files, shown, typed, device, argon2id });
/// "Create an account" with the name only, sent; the dialog of the passwords the wallet made closed `how`.
async function createClosed(name, how) {
  await $('mode-create').fire('click'); await formDrawn(); $('username').value = name; fresh();
  const sent = $('auth-form').fire('submit');
  await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the passwords the wallet made');
  const shown = await madeShown(how); await sent;
  return shown;
}

test('the passwords the wallet made go on only with "I have them": closed by Escape or by a script at a sign-up or at the creation of an account with one key, nothing is kept or sent, and the wallet says so', async () => {
  reset();
  try {
    await freshPage();
    for (const how of ['close', 'escape']) {
      const posted = chain.posted.length, shown = await createClosed('esc_p', how);
      assert.ok(madeForm(shown.login) && madeForm(shown.payment), how);
      await refusedWith(NOT_HAD.two);
      assert.deepEqual([kept('esc_p'), chain.posted.length - posted, $('signup-phrase-shown').textContent, $('signup-sheet-step').hidden], [{ login: null, spend: null, nextLogin: null, nextSpend: null, note: null }, 0, '', true], how);
    }
    // With "I have them", the same name goes on to the recovery words, and to the account: each record kept opens with
    // the passwords shown (review of 24 November, finding 7).
    const papers = await step1('esc_p');
    assert.ok(papers.made); assert.match(papers.phrase, /^[a-z]{6}( [a-z]{6}){4}$/);
    await step3(); await opened('esc_p');
    assert.deepEqual(await provenFor('esc_p', [papers.login, papers.payment]), []);
    await $('lock-button').fire('click');
    // On a network without protected sign-up: the one key of an account.
    chain.protect = false; await freshPage();
    for (const how of ['close', 'escape']) {
      const posted = chain.posted.length, shown = await createClosed('esc_one', how);
      assert.deepEqual([madeForm(shown.login), shown.payment, shown.button], [shown.login, '', 'I have it'], how);
      await refusedWith(NOT_HAD.one);
      assert.deepEqual([kept('esc_one').login, chain.posted.length - posted, byName('esc_one'), $('dashboard').hidden], [null, 0, undefined, true], how);
    }
    const one = await createClosed('esc_one', 'done'); await opened('esc_one');
    assert.deepEqual(await provenFor('esc_one', [one.login]), []);
    await $('lock-button').fire('click');
  } finally { reset(); await freshPage(); }
});

test('turning the lock off: the passwords the wallet made are shown before anything is replaced; closed without "I have them", the keys stay locked; with it, they open with what was shown', async () => {
  reset(); const device = deviceOnPage();
  try {
    await freshPage();
    const papers = await step1('off_p', { device: true }); await step3(papers); await opened('off_p');
    const locked = () => [kept('off_p').login, kept('off_p').spend].map(record => JSON.stringify(record)), before = locked();
    assert.deepEqual(sealsOf('off_p'), [['timecurrency.spend-vault.v1', 3, 'device'], ['timecurrency.vault.v1', 3, 'device']]);
    // Locked from birth, proven: each record opens with the device's secret and a password typed, and with no other secret.
    const env = { secureContext: true, credentials: globalThis.window.navigator.credentials, PublicKeyCredential: globalThis.window.PublicKeyCredential, crypto: globalThis.crypto };
    const secretOf = async record => (await deviceSecrets(env, { credentialId: vaultDevice(record), salts: [saltOfRecord(record)] }))[0];
    assert.deepEqual(await provenFor('off_p', [], [LOGIN, PAYMENT], { device: secretOf }), []);
    for (const how of ['close', 'escape', 'done']) {
      $('lock-off-login').value = LOGIN; $('lock-off-payment').value = PAYMENT; fresh();
      await $('lock-off-form').fire('submit');
      await confirmReview();
      await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the passwords the wallet made');
      const shown = await madeShown(how);
      assert.equal(shown.why, LOCK_WORDS.offMade, how);
      if (how !== 'done') { await refusedWith(NOT_HAD.two); assert.deepEqual(locked(), before, `${how}: nothing was replaced`); continue; }
      await until(() => $('notice').textContent === LOCK_WORDS.off || $('notice').className.includes('error'), 'the lock turned off');
      assert.equal($('notice').textContent, LOCK_WORDS.off);
      assert.deepEqual(sealsOf('off_p'), [['timecurrency.spend-vault.v1', 2, 'made'], ['timecurrency.vault.v1', 2, 'made']]);
      // Proven: each record opens with the password shown, and not with the passwords typed before.
      assert.deepEqual(await provenFor('off_p', [shown.login, shown.payment], [LOGIN, PAYMENT]), []);
    }
    await $('lock-button').fire('click');
  } finally { device.off(); reset(); }
});

test('"Let the wallet make my passwords" and a backup file of a chosen password, for an account with one key: closed without "I have it", nothing is replaced or kept, and the wallet says so', async () => {
  reset(); chain.protect = false;
  try {
    await freshPage();
    // An account with one key, and this browser's record of it as the wallet made it before the rule: under a chosen password.
    const shown = await createClosed('old_one', 'done'); await opened('old_one'); await $('lock-button').fire('click');
    const s = slots('old_one'), key = await openVault(kept('old_one').login, shown.login, argon2id);
    const legacy = JSON.stringify(await sealLegacy(key.secret, LOGIN, key.binding, argon2id));
    storage.setItem(s.login, legacy); passwords.old_one = { login: LOGIN };
    await unlock('old_one'); await opened('old_one');
    for (const how of ['close', 'escape']) {
      $('remake-login').value = LOGIN; fresh();
      await $('remake-form').fire('submit');
      await confirmReview();
      await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the password the wallet made');
      const made = await madeShown(how);
      assert.deepEqual([madeForm(made.login), made.payment], [made.login, ''], how);
      // The one password of an account with one key: it opens the wallet and pays (review of 24 November, finding 8).
      assert.deepEqual([made.title, made.label, made.note, made.button, made.why], ['Your new password', 'Password', 'Opens this wallet and pays from it. Let your browser save it, or write it down.', 'I have it', REMADE_ONE], how);
      await refusedWith(NOT_HAD.one);
      assert.equal(storage.getItem(s.login), legacy, `${how}: the record of the chosen password is still the one kept`);
    }
    // With "I have it": the same key, under the password shown, which the chosen password no longer opens (proven).
    $('remake-login').value = LOGIN; fresh();
    await $('remake-form').fire('submit'); await confirmReview();
    await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the password the wallet made');
    const remade = await madeShown();
    await until(() => $('notice').textContent === LOCK_WORDS.remade || $('notice').className.includes('error'), 'the passwords remade');
    assert.deepEqual([$('notice').textContent, sealsOf('old_one')], [LOCK_WORDS.remade, [['timecurrency.vault.v1', 1, 'made']]]);
    assert.deepEqual(await provenFor('old_one', [remade.login], [LOGIN]), []);
    // A backup file of that chosen password, restored in a browser that keeps nothing of the account.
    await $('lock-button').fire('click');
    const text = JSON.stringify({ format: BACKUP_FORMAT, version: 1, vault: JSON.parse(legacy) }, null, 2) + '\n';
    storage.removeItem(s.login);
    for (const how of ['close', 'escape']) {
      $('backup-file').files = [{ size: text.length, text: async () => text }]; $('backup-password').value = LOGIN; fresh();
      const restoring = $('backup-import-form').fire('submit');
      await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the password the wallet made for the restored key');
      const made = await madeShown(how); await restoring;
      assert.deepEqual([madeForm(made.login), made.payment, made.name], [made.login, '', 'old_one'], how);
      await refusedWith(NOT_HAD.one);
      assert.equal(storage.getItem(s.login), null, `${how}: nothing was restored`);
    }
    // With "I have it", the key is kept under the password shown. The file still opens with the chosen password, which can
    // be guessed offline: Home suggests a new file and says why, until one is downloaded (review of 24 November, finding 9).
    $('backup-file').files = [{ size: text.length, text: async () => text }]; $('backup-password').value = LOGIN; fresh();
    const restoring = $('backup-import-form').fire('submit');
    await until(() => $('made-dialog').open || $('notice').className.includes('error'), 'the password the wallet made for the restored key');
    const restored = await madeShown(); await restoring;
    assert.equal($('notice').textContent, 'Backup restored. Open your account with the password the wallet just made for it. No new key was made. Your old backup file still opens with the password you chose: once your account is open, download a new file under Keys, and destroy the old one.');
    assert.deepEqual(sealsOf('old_one'), [['timecurrency.vault.v1', 1, 'made']]);
    assert.deepEqual(await provenFor('old_one', [restored.login], [LOGIN]), []);
    passwords.old_one = { login: restored.login };
    await unlock('old_one'); await opened('old_one');
    await until(() => $('home-backup').hidden === false, 'Home suggests a new backup file');
    assert.equal($('home-backup-why').textContent, 'The backup file you restored opens with a password you chose, which someone with a copy of it could guess. ');
    $('backup-export-password').value = restored.login; fresh();
    const files = downloads.length;
    await $('backup-export-form').fire('submit');
    await until(() => $('notice').textContent.startsWith('Backup file downloaded') || $('notice').className.includes('error'), 'the new backup file');
    assert.deepEqual([$('notice').textContent.startsWith('Backup file downloaded'), $('home-backup').hidden, downloads.length - files], [true, true, 1], $('notice').textContent);
    // The new file, proven: it opens with the password shown, and not with the chosen one.
    assert.deepEqual(await provenFor('old_one', [restored.login], [LOGIN], { files: [await downloads.at(-1).blob.text()] }), []);
    await $('lock-button').fire('click');
  } finally { reset(); await freshPage(); }
});

test('managed signup opens in the submit gesture, stages encrypted keys, and registers only after Time Vault saves', async () => {
  const oldPage = dom;
  dom = new Map();
  try {
    const { parseSeconds } = await import('./guards.mjs');
    const local = new Storage();
    const events = [];
    let result = 'saved', created = 0, saved = null, proven = stateFor({});
    const ui = createSignupUI({
      sdk: SDK, network: () => ({ networkId: NET }), state: () => proven,
      verifiedState: async query => { events.push('read'); return stateFor(query); },
      registrationSponsor: async () => ({}), capture: () => () => {}, argon2id: () => argon2id,
      storage: local, locks: () => navigator.locks, fee: () => '1000', parseSeconds, setBusy() {}, notice() {},
      typedPassword(shown) { $('password').hidden = $('password-confirm').hidden = !shown; },
      showMade: () => assert.fail('managed secrets must stay out of the password dialog'),
      managerAvailable: () => true,
      startManager() {
        events.push('open');
        return {
          async save(payload) {
            events.push('save');
            assert.equal(ui.staged(payload.name), true);
            assert.equal(ui.managed(payload.name), true);
            assert.equal(payload.networkId, NET);
            assert.equal(madeForm(payload.secrets.signin), payload.secrets.signin);
            assert.equal(madeForm(payload.secrets.spend), payload.secrets.spend);
            assert.notEqual(payload.secrets.signin, payload.secrets.spend);
            assert.equal(payload.secrets.recover.split(' ').length, 5);
            const stored = [...local.m.values()].join('');
            for (const secret of Object.values(payload.secrets)) assert.equal(stored.includes(secret), false);
            const note = JSON.parse(local.getItem(slots(payload.name).nextNote));
            assert.equal(note.policy.daily_limit_micros, '600000000');
            if (result === 'cancel') throw Object.assign(new Error('Cancelled before save'), { unsaved: true });
            if (result === 'ambiguous') throw new Error('Window closed');
            saved = payload;
          },
          close() { events.push('close'); },
        };
      },
      created: async ({ name, managed }) => { assert.equal(managed, true); assert.equal(saved.name, name); events.push('register'); created++; },
    });
    $('username').value = 'chosen_early';
    ui.form(true);
    assert.equal($('username').value, 'chosen_early', 'verification finishing preserves a name already typed');
    ui.form(false);
    $('username').value = 'old_account';
    ui.form(true);
    const suggestion = $('username').value;
    assert.match(suggestion, /^time_[a-f0-9]{10}$/);
    assert.equal($('signup-method').textContent, 'Set up manually');
    assert.equal($('auth-submit').textContent, 'Create account');
    assert.deepEqual(['auth-ways', 'auth-seal-note', 'signup-protected', 'password', 'password-confirm'].map(id => $(id).hidden), Array(5).fill(true));
    const first = ui.begin({ name: suggestion });
    assert.deepEqual(events.slice(0, 2), ['open', 'read']);
    await first;
    assert.deepEqual(events, ['open', 'read', 'save', 'register', 'close']);
    assert.equal(ui.managed(suggestion), true);
    const signin = JSON.parse(local.getItem(slots(suggestion).nextLogin));
    assert.equal((await openVault(signin, saved.secrets.signin, argon2id, crypto, 'signin')).binding.publicKey, signin.binding.publicKey);
    const identity = JSON.parse(local.getItem(slots(suggestion).login)).binding.publicKey;
    local.removeItem(slots(suggestion).nextNote);
    const rotated = { ...signin, binding: { ...signin.binding, publicKey: otherKey.publicKey } };
    local.setItem(slots(suggestion).login, JSON.stringify(rotated));
    assert.equal(ui.managed(suggestion), true, 'a cold start offers the paired manager after a role rotation');
    proven = { ...proven, accounts: [{ name: suggestion, public_key: identity }] };
    assert.equal(ui.managed(suggestion), true, 'the immutable identity matches after rotation');
    proven = { ...proven, accounts: [{ name: suggestion, public_key: faucetKey.publicKey }] };
    assert.equal(ui.managed(suggestion), false, 'another proven identity with this name is refused');
    result = 'cancel';
    await assert.rejects(ui.begin({ name: 'cancel_managed' }), /Cancelled before save/);
    assert.equal(ui.staged('cancel_managed'), false);
    assert.equal(ui.managed('cancel_managed'), false);
    result = 'ambiguous';
    await assert.rejects(ui.begin({ name: 'resume_managed' }), /Open my account and try opening @resume_managed with Time Vault/);
    assert.equal(ui.staged('resume_managed'), true);
    assert.equal(ui.managed('resume_managed'), true);
    assert.equal(created, 1);
    await $('signup-method').fire('click');
    assert.equal($('signup-protected').hidden, false);
    assert.equal($('signup-method').textContent, 'Use password manager');
  } finally { dom = oldPage; }
});

test('paired wallet resumes a saved signup after a lost vault reply using only the sign-in credential', async () => {
  const priorWindow = window, priorOrigin = location.origin, priorStorage = storage.m;
  const listeners = new Set(), popups = [], requests = [], roles = [];
  const vaultOrigin = 'https://vault.testnet.thetimenetwork.org';
  let saved;
  reset(); storage.m = new Map(); location.origin = 'https://wallet.testnet.thetimenetwork.org';
  globalThis.window = {
    ...priorWindow, crypto, location, setTimeout, clearTimeout, setInterval, clearInterval,
    addEventListener(type, fn) { if (type === 'message') listeners.add(fn); },
    removeEventListener(type, fn) { if (type === 'message') listeners.delete(fn); },
    open(url) {
      assert.equal(url, vaultOrigin + '/');
      const deliver = data => { for (const fn of listeners) fn({ origin: vaultOrigin, data, source: popup }); };
      const popup = {
        closed: false, close() { this.closed = true; },
        postMessage(message, target) {
          assert.equal(target, vaultOrigin);
          const request = structuredClone(message);
          requests.push(request.operation);
          const reply = { v: 1, type: 'time:vault-result', id: request.id };
          if (request.operation === 'save') {
            saved = request;
            queueMicrotask(() => deliver({ ...reply, ok: false, error: 'Save acknowledgment interrupted' }));
          } else {
            roles.push(request.role);
            assert.deepEqual([request.name, request.networkId], [saved.name, NET]);
            queueMicrotask(() => deliver({ ...reply, ok: true, value: saved.secrets[request.role] }));
          }
        },
      };
      popups.push(popup);
      queueMicrotask(() => deliver({ v: 1, type: 'time:vault-ready' }));
      return popup;
    },
  };
  try {
    await freshPage();
    assert.equal($('auth-submit').textContent, 'Create account');
    const name = $('username').value;
    const asked = chain.asked;
    const first = $('auth-form').fire('submit');
    await $('auth-form').fire('submit');
    await first;
    assert.equal(popups.length, 1, 'repeated submit opens one window');
    assert.deepEqual(requests, ['save']);
    assert.equal(saved.name, name);
    assert.equal(chain.asked, asked, 'no sponsorship was sent while the manager reply was missing');
    assert.equal(byName(name), undefined);
    assert.ok(kept(name).note);
    assert.equal($('signup-phrase-shown').textContent, '');
    assert.equal($('made-dialog').open, false);
    await freshPage();
    assert.equal($('username').value, name);
    assert.equal($('password').hidden, true);
    assert.match($('notice').textContent, /with Time Vault to finish/);
    chain.drop = action => action.kind === 45;
    await $('auth-form').fire('submit');
    assert.match($('notice').textContent, /with Time Vault to finish/);
    assert.doesNotMatch($('notice').textContent, /login password/);
    assert.equal(byName(name), undefined);
    chain.drop = () => false;
    await $('auth-form').fire('submit');
    await opened(name);
    assert.equal(chain.asked, asked + 1);
    assert.deepEqual(requests, ['save', 'get', 'get']);
    assert.equal(kept(name).note, null);
    assert.equal(chain.security[byName(name).id].policy.daily_limit_micros, '600000000');
    assert.deepEqual(roles, ['signin', 'signin']);

    const payer = byName(name), recipient = byName('bob'), before = chain.posted.length;
    payer.balance = '5000000';
    const recipientBefore = BigInt(recipient.balance);
    $('recipient').value = 'bob'; $('amount').value = '1';
    const payment = $('send-payment');
    await payment.nextElementSibling.fire('click');
    assert.deepEqual(roles, ['signin', 'signin', 'spend']);
    assert.ok(payment.value && payment.value !== saved.secrets.spend, 'only a disposable token is in the field');
    const cancelled = $('send-form').fire('submit');
    await until(() => $('review-dialog').open || $('notice').className.includes('error'), 'the payment review');
    assert.equal($('review-title').textContent, 'Send seconds', $('notice').textContent);
    $('review-dialog').returnValue = 'cancel'; $('review-dialog').open = false; await $('review-dialog').fire('close');
    await cancelled;
    assert.equal(chain.posted.length, before);
    assert.equal(payment.value, '');
    await payment.nextElementSibling.fire('click');
    const confirmed = $('send-form').fire('submit');
    await confirmReview();
    await confirmed;
    assert.deepEqual(roles, ['signin', 'signin', 'spend', 'spend']);
    const transfer = chain.posted.at(-1);
    assert.equal(chain.posted.length, before + 1, $('notice').textContent);
    assert.deepEqual([transfer.kind, transfer.payload.to, transfer.payload.amount, transfer.publicKey],
      [SDK.KINDS.transfer, recipient.id, '1000000', kept(name).spend.binding.publicKey]);
    assert.equal(BigInt(recipient.balance), recipientBefore + 1000000n);
    assert.ok(popups.every(popup => popup.closed));
  } finally { globalThis.window = priorWindow; location.origin = priorOrigin; storage.m = priorStorage; }
});
