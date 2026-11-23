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
const { KEPT, PAPERS_ACTIVITY, PAPERS_IDLE } = await import(new URL('web-v4/wallet/signup-ui.mjs', root).href);
const { openVault, newDevice, validateVaultRecord, sealVault } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
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
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); } remove() {} click() {}
  showModal() { this.open = true; } close() { this.open = false; }
  setAttribute(name, value) { (this.attributes ??= {})[name] = String(value); } getAttribute(name) { return this.attributes?.[name] ?? null; } removeAttribute(name) { delete this.attributes?.[name]; }
  focus() {} select() {} scrollIntoView() {}
  async fire(type) { const list = this.listeners[type] || []; this.listeners[type] = list.filter(item => !item.once); await Promise.all(list.map(item => item.fn({ preventDefault() {}, data: null }))); }
}
let dom = new Map();
const storage = new Storage(), intervals = [];
const $ = id => { if (!dom.has(id)) dom.set(id, new El(id)); return dom.get(id); };
const PANELS = [...page.matchAll(/<section class="workspace-panel" id="panel-([a-z]+)"/g)].map(found => found[1]);
const HIDDEN = [...page.matchAll(/<[a-z0-9]+\b[^>]*>/g)].map(found => found[0]).filter(tag => /\shidden(?=[\s>])/.test(tag)).map(tag => /\bid="([^"]+)"/.exec(tag)?.[1]).filter(Boolean);
// What the page listens for on the whole document, with the options it asked for: a test sends such an event (`act`).
const documentListeners = {};
globalThis.document = { getElementById: $, createElement: tag => new El(tag), querySelectorAll: selector => (selector === '.workspace-panel' ? PANELS.map(name => $('panel-' + name)) : []), addEventListener(type, fn, options) { (documentListeners[type] ??= []).push({ fn, options }); }, body: { append() {}, classList: { add() {}, remove() {} } }, title: '' };
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
const answer = (status, body) => new Response(JSON.stringify(body), { status });
globalThis.fetch = async (url, options = {}) => {
  if (String(url).startsWith(FAUCET + '/')) {
    const route = new URL(String(url)).pathname;
    if (route === '/v1/faucet') return chain.facts ? answer(200, { network_id: NET, account: '1', giving: true, registrations: { sponsored: true } }) : answer(503, { error: { code: 'faucet_unavailable', message: 'down' } });
    if (route !== '/v1/faucet/registrations') return answer(404, {});
    const got = await sponsor(JSON.parse(options.body)); return answer(got.status, got.answer);
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
  await until(() => /^(Connected to the Time test network|Creating @|The new keys of @)/.test($('notice').textContent) || $('notice').className.includes('error'), 'the wallet to start');
}
const slots = name => F.vaultSlots(NET, name);
/// What this browser keeps for a name on this network, by kind of place.
function kept(name) {
  const s = slots(name), read = key => { const raw = storage.getItem(key); return raw === null ? null : JSON.parse(raw); };
  return { login: read(s.login), spend: read(s.spend), nextLogin: read(s.nextLogin), nextSpend: read(s.nextSpend), note: read(s.nextNote) };
}
const everything = () => [...storage.m.values()].join('\n');
/// Step 1: the form of "Create an account", sent. Waits for the papers, or for the wallet's answer.
async function step1(name, { limit = null } = {}) {
  await $('mode-create').fire('click');
  $('username').value = name; $('password').value = $('password-confirm').value = LOGIN;
  $('signup-payment').value = $('signup-payment-confirm').value = PAYMENT;
  if (limit !== null) { $('signup-limit').value = limit; await $('signup-limit').fire('input'); }
  $('notice').textContent = ''; $('notice').className = 'notice';
  await $('auth-form').fire('submit');
  await until(() => $('signup-sheet').textContent.length > 20 || $('notice').className.includes('error'), 'the recovery papers');
  return { sheet: $('signup-sheet').textContent, phrase: $('signup-phrase-shown').textContent, title: $('signup-sheet-title').textContent };
}
/// Steps 2 and 3: "I wrote both down", the two groups and the passphrase typed back, "Create my account".
async function step3(papers, { wrong = false } = {}) {
  await $('signup-sheet-done').fire('click');
  const groups = papers.sheet.split(' '), group = id => groups[Number($(id + '-label').textContent.replace('Group ', '')) - 1];
  $('signup-confirm-a').value = wrong ? 'ZZZZ' : group('signup-confirm-a'); $('signup-confirm-b').value = group('signup-confirm-b'); $('signup-confirm-phrase').value = papers.phrase;
  $('notice').textContent = ''; $('notice').className = 'notice';
  await $('signup-submit').fire('click');
}
const opened = name => until(() => $('dashboard').hidden === false && $('account-name').textContent === '@' + name && $('account-verification').textContent === 'Checked by this browser', `the account ${name} open`);
async function unlock(name) {
  await $('mode-unlock').fire('click');
  $('username').value = name; $('password').value = LOGIN; $('notice').textContent = ''; $('notice').className = 'notice';
  await $('auth-form').fire('submit');
}
const roles = account => Object.fromEntries(['signin', 'spend', 'recover'].map(role => [role, account.devices.filter(d => (role === 'recover' ? d.can_manage : role === 'spend' ? d.can_spend : !d.can_manage && !d.can_spend)).map(d => d.public_key)]));
const PROTECTED_READY = 'Your account is ready, protected from its first block. This browser checked it with the network. Next time, open it with your name and your login password.';
const reset = () => { Object.assign(chain, { down: false, protect: true, facts: true, service: 'sponsor', drop: () => false, refuse: () => null, after: () => {} }); };
chain.facts = true;
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

test('the form: a login password, a payment password and a daily limit of 600 seconds, each said in one sentence', async () => {
  assert.deepEqual([$('password-label').textContent, $('confirm-label').textContent, $('password-note').hidden, $('signup-login-note').hidden, $('signup-protected').hidden], ['Login password', 'Login password again', true, false, false]);
  assert.deepEqual([$('signup-limit').value, $('signup-limit-suggested').textContent, $('auth-submit').textContent], ['600', 'Suggested: 10 minutes of seconds a day (600).', 'Next: my recovery papers']);
  assert.equal($('auth-copy').textContent, 'Pick a name, a login password and a payment password. The wallet then makes two recovery papers for you to keep. Your account is protected from its first moment.');
  assert.deepEqual(['signup-payment', 'signup-payment-confirm', 'signup-limit'].map(id => $(id).required), [true, true, true]);
  // The page: what each one is for, in one sentence with its mark, as the cards of Keys say it; the papers to keep safe.
  for (const words of ['<span class="tag day">Every day</span> Opens this wallet and signs you in to websites. It cannot pay. Nobody can reset it.', '<span class="tag day">When you pay</span> Pays up to your daily limit. It must differ from your login password. Do not let the browser save it.', '<h2>Your recovery sheet <span class="tag safe">Keep safe</span></h2>', '<h2>Your recovery passphrase <span class="tag safe">Keep safe</span></h2>', '<button id="signup-sheet-done" type="button">I wrote both down</button>', '<button id="signup-submit" type="button">Create my account</button>']) assert.ok(page.includes(words), words);
  // No field of the protected form is required in the page itself: hidden, it must not stop the form of another mode.
  assert.doesNotMatch(page.slice(page.indexOf('id="signup-protected"'), page.indexOf('id="auth-submit"')), /\srequired/);
  // Opening an account: the form as before.
  await $('mode-unlock').fire('click');
  assert.deepEqual([$('password-label').textContent, $('signup-protected').hidden, $('password-note').hidden], ['Password', true, false]);
  await $('mode-create').fire('click');
});

test('signing up protected: the papers come before anything is kept or sent, are asked back, and the account is protected from its first block with the 600-second limit', async () => {
  reset(); const posted = chain.posted.length;
  const papers = await step1('erin_p');
  assert.match(papers.sheet, /^([0-9A-Z]{4} ){13}[0-9A-Z]{4}$/, $('notice').textContent);
  assert.match(papers.phrase, /^[a-z]{6} [a-z]{6} [a-z]{6} [a-z]{6}$/);
  assert.deepEqual([papers.title, $('auth-form').hidden, $('signup-sheet-step').hidden, $('signup-payment').value, $('password').value], [`Recovery sheet for @erin_p · network ${NET.slice(0, 12)}`, true, false, '', '']);
  // Nothing is kept and nothing is sent before the papers are checked.
  assert.deepEqual(kept('erin_p'), { login: null, spend: null, nextLogin: null, nextSpend: null, note: null });
  assert.deepEqual([chain.posted.length - posted, chain.asked], [0, 0]);
  // A paper typed back wrong: the papers again, and still nothing kept.
  await step3(papers, { wrong: true });
  assert.deepEqual([$('notice').className.includes('error'), $('signup-sheet-step').hidden, $('signup-sheet').textContent, kept('erin_p').note], [true, false, papers.sheet, null]);
  // Right: the account is made through the registration service, and opened.
  await step3(papers);
  await opened('erin_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  // The form the papers stood in for is back: the start screen of this page has its fields again when it is shown.
  assert.deepEqual([$('auth-form').hidden, $('signup-sheet-step').hidden, $('signup-confirm-step').hidden], [false, true, true]);
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
  for (const secret of [LOGIN, PAYMENT, papers.phrase, papers.sheet, '"pkcs8"']) assert.ok(!everything().includes(secret), secret);
  assert.equal((await openVault(now.spend, PAYMENT, argon2id, globalThis.crypto, 'spend')).binding.publicKey, keys.spend[0]);
  // The recovery passphrase is one of the account's recovery keys (its salt names the account's identity key), and the
  // wallet finds it so: a freeze signed with it is signed by that key.
  const byIdentity = await F.passphraseKey({ passphrase: papers.phrase, networkId: NET, registrationKey: account.public_key, argon2id });
  assert.ok(keys.recover.includes(byIdentity.publicKey));
  const before = chain.posted.length;
  await $('freeze-switch').fire('change'); $('freeze-method').value = 'phrase'; $('freeze-secret').value = papers.phrase;
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

test('a limit the person typed is the account\'s, and the papers are never skipped: "Start over" and locking forget them, and nothing is kept', async () => {
  reset(); await $('lock-button').fire('click');
  let papers = await step1('finn_p', { limit: '45' });
  await $('signup-cancel').fire('click');
  assert.deepEqual([$('signup-sheet').textContent, $('signup-sheet-step').hidden, $('auth-form').hidden, kept('finn_p').note, $('notice').textContent], ['', true, false, null, 'Nothing was created. The recovery papers that were shown will never work: destroy them if you wrote them down.']);
  papers = await step1('finn_p', { limit: '45' });
  await $('lock-button').fire('click');
  assert.deepEqual([$('signup-sheet').textContent, $('signup-sheet-step').hidden, kept('finn_p').note], ['', true, null]);
  await $('mode-create').fire('click');
  papers = await step1('finn_p', { limit: '45' }); await step3(papers); await opened('finn_p');
  assert.equal(chain.security[byName('finn_p').id].policy.daily_limit_micros, '45000000');
  await $('lock-button').fire('click');
});

test('the papers follow the idle rule of the lock: after five minutes without use they are hidden, and the person is told that nothing was created', async () => {
  reset(); await $('lock-button').fire('click');
  const posted = chain.posted.length, asked = chain.asked, nothing = { login: null, spend: null, nextLogin: null, nextSpend: null, note: null };
  let papers = await step1('sami_p');
  await idleFor(IDLE_LOCK_MS - 1);
  assert.equal($('signup-sheet').textContent, papers.sheet, 'on the page until the five minutes are over');
  await idleFor(1);
  assert.deepEqual([$('signup-sheet').textContent, $('signup-phrase-shown').textContent, $('signup-sheet-title').textContent, $('signup-sheet-step').hidden, $('signup-confirm-step').hidden, $('auth-form').hidden, $('notice').textContent], ['', '', '', true, true, false, PAPERS_IDLE]);
  assert.equal(PAPERS_IDLE, 'Your recovery papers were hidden after 5 minutes without use, and nothing was created. The papers that were shown will never work: destroy them if you wrote them down. Start again to get new ones.');
  // Nothing was kept or sent, and the keys are forgotten: "Create my account" has nothing left to create.
  assert.deepEqual([kept('sami_p'), chain.posted.length - posted, chain.asked - asked, idleTimers.size], [nothing, 0, 0, 0]);
  await $('signup-submit').fire('click');
  assert.deepEqual([$('notice').textContent, kept('sami_p')], ['Start again from the beginning.', nothing]);
  // The same while the papers are asked back, and after a paper typed back wrong showed them again.
  papers = await step1('sami_p'); await $('signup-sheet-done').fire('click');
  await idleFor(IDLE_LOCK_MS);
  assert.deepEqual([$('signup-confirm-step').hidden, $('auth-form').hidden, $('notice').textContent], [true, false, PAPERS_IDLE]);
  papers = await step1('sami_p'); await step3(papers, { wrong: true });
  assert.equal($('signup-sheet').textContent, papers.sheet);
  await idleFor(IDLE_LOCK_MS);
  assert.deepEqual([$('signup-sheet').textContent, $('notice').textContent, kept('sami_p'), chain.posted.length - posted], ['', PAPERS_IDLE, nothing, 0]);
  // "Start over" leaves no idle rule behind.
  papers = await step1('sami_p'); await $('signup-cancel').fire('click');
  assert.equal(idleTimers.size, 0);
});

test('a person writing the papers down slowly is not cut off while using the page: each kind of use counts, a pointer that only moves does not', async () => {
  reset();
  assert.deepEqual([...PAPERS_ACTIVITY], ['pointerdown', 'keydown', 'input', 'wheel', 'scroll', 'touchmove']);
  // Heard on the way down, so that scrolling inside an element of the page counts too.
  assert.ok(PAPERS_ACTIVITY.every(type => (documentListeners[type] || []).some(item => item.options?.capture === true && item.options?.passive === true)), 'every kind of use is listened for, on the way down');
  for (const type of PAPERS_ACTIVITY) {
    const papers = await step1('tess_p');
    await idleFor(IDLE_LOCK_MS - 1000); await act(type); await idleFor(IDLE_LOCK_MS - 1000);
    assert.equal($('signup-sheet').textContent, papers.sheet, `${type} keeps the papers on the page`);
    await idleFor(1000);
    assert.equal($('signup-sheet').textContent, '', `${type}: hidden five minutes after the last use`);
  }
  // Not use: a pointer that moves over the page, a field that takes the focus.
  let papers = await step1('tess_p');
  await idleFor(IDLE_LOCK_MS - 1000); await act('pointermove'); await act('focusin'); await idleFor(1000);
  assert.equal($('signup-sheet').textContent, '');
  // Twelve minutes on the papers and on the check, using the page every minute: nothing is hidden, and the account is made.
  papers = await step1('tess_p');
  for (let minute = 0; minute < 8; minute++) { await idleFor(60000); await act(minute % 2 ? 'wheel' : 'scroll'); }
  assert.equal($('signup-sheet').textContent, papers.sheet);
  await $('signup-sheet-done').fire('click');
  for (let minute = 0; minute < 4; minute++) { await idleFor(60000); await act('keydown'); await act('input'); }
  assert.equal($('signup-confirm-step').hidden, false);
  await step3(papers); await opened('tess_p');
  assert.equal($('notice').textContent, PROTECTED_READY);
  await idleFor(IDLE_LOCK_MS);
  assert.notEqual($('notice').textContent, PAPERS_IDLE, 'the account exists: no paper is said void after it');
  await $('lock-button').fire('click');
});

test('a registration service that does not answer: nothing is made and no paper is shown', async () => {
  reset(); chain.facts = false;
  await $('mode-create').fire('click');
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

test('closed after the passwords, before the papers were checked: on return nothing is kept, nothing was sent, and the form is there to start again', async () => {
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
  assert.deepEqual([keptNow.login.version, keptNow.nextLogin.intent, keptNow.nextSpend.intent, keptNow.note.kind], [1, 'signin', 'spend', 45]);
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
  assert.deepEqual([kept('ines_p').login.version, kept('ines_p').note.kind], [1, 45], 'the registration key still holds the login place');
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
  // The name is taken by someone else between the papers and the registration: nothing of the person's is on the chain.
  let papers = await step1('kurt_p');
  chain.accounts.push({ id: String(chain.nextId++), name: 'kurt_p', public_key: '4'.repeat(64), balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '4'.repeat(64), can_manage: true, can_spend: true }] });
  await step3(papers); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.signupWords({ code: 'NAME_TAKEN' }, 'kurt_p'));
  assert.equal($('notice').textContent, 'Someone else took the name @kurt_p before your account was made. Nothing of yours is on the network. The recovery papers you wrote down for @kurt_p will never work: destroy them. Create your account with another name.');
  assert.deepEqual([$('auth-heading').textContent, $('dashboard').hidden], ['Create your account', true], 'the form for a new account');
  // The service answers with an action that pays for another key's commitment: not used, nothing registered.
  chain.service = 'other key'; papers = await step1('lena_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.deepEqual([$('notice').textContent, byName('lena_p')], [S.signupWords({ code: 'SPONSOR_MISMATCH' }, 'lena_p'), undefined]);
  assert.equal(chain.posted.filter(a => a.kind === 45 && a.payload.name === 'lena_p').length, 0, 'the registration was not signed');
  // The service paid for this key in the last 24 hours (its code account_limit): the wallet's sentence, the service's word.
  chain.service = 'account_limit'; await unlock('lena_p');
  await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, 'The registration service says that it paid for this sign-up in the last 24 hours, and that this payment ran out before your account was made. It pays again 24 hours after the first time: then open your account with your login password, and this browser goes on. Your recovery papers stay valid.');
  reset();
  // A commitment of this sign-up's key with other details on the chain: nothing signed.
  chain.drop = action => action.kind === 44; papers = await step1('mona_p'); await step3(papers);
  await until(() => $('notice').className.includes('error'), 'the wallet to stop');
  const registration = await openVault(kept('mona_p').login, LOGIN, argon2id);
  chain.commits.push({ public_key: registration.binding.publicKey, commitment: 'cd'.repeat(32), sponsor: '1', expires_elapsed_micros: String(chain.now + DAY), height: String(chain.height - 1) });
  reset(); await unlock('mona_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, S.signupWords({ code: 'COMMITMENT_MISMATCH' }, 'mona_p'));
  chain.commits = chain.commits.filter(item => item.public_key !== registration.binding.publicKey);
  // The account of this sign-up holds other keys than the ones kept here (changed by someone with the papers).
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

test('a name that the network refuses as too close to one that exists: the wallet\'s sentence, the papers of that name said void, and the form for a new account', async () => {
  reset(); chain.accounts.push({ id: String(chain.nextId++), name: 'paypal', public_key: '6'.repeat(64), balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '6'.repeat(64), can_manage: true, can_spend: true }] });
  // The chain refuses the registration with the engine's words; the gateway passes them on.
  chain.refuse = action => (action.kind === 45 ? `the name ${action.payload.name} is too close to the existing name paypal` : null);
  const papers = await step1('paypa1');
  await step3(papers); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.equal($('notice').textContent, 'That name is too close to @paypal, which already exists. Choose another. The recovery papers you wrote down for @paypa1 will never work: destroy them.');
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
  const spendKept = storage.getItem(s.nextSpend), other = await F.sealedKey({ password: PAYMENT, networkId: NET, name: 'pia_p', intent: 'spend', argon2id });
  storage.setItem(s.nextSpend, JSON.stringify(other.record));
  await unlock('pia_p'); await until(() => $('notice').className.includes('error'), 'the refusal');
  assert.deepEqual([$('notice').textContent, chain.posted.length - posted, byName('pia_p')], [S.CHANGED, 0, undefined]);
  storage.setItem(s.nextSpend, spendKept);
  // The note's form and signature, checked apart from the page.
  const registration = await openVault(kept('pia_p').login, LOGIN, argon2id);
  await assert.rejects(S.readNote(JSON.stringify(note), { networkId: NET, name: 'pia_p', registrationKey: registration.binding.publicKey }), { message: S.CHANGED });
  assert.equal((await S.readNote(kept0, { networkId: NET, name: 'pia_p', registrationKey: registration.binding.publicKey })).name, 'pia_p', 'the note as it was is read');
  // A note is read only for its own name, network and registration key, its signature notwithstanding.
  for (const other of [{ name: 'pia_q' }, { networkId: 'd7'.repeat(32) }, { registrationKey: '7'.repeat(64) }]) await assert.rejects(S.readNote(kept0, { networkId: NET, name: 'pia_p', registrationKey: registration.binding.publicKey, ...other }), { message: S.CHANGED }, JSON.stringify(other));
  validateVaultRecord(kept('pia_p').nextSpend, 'spend');
  await freshPage();
});

test('a kept sign-up that the network shows nothing of is let go, once its last consent ran out, through a review; the name can be signed up again', async () => {
  // The papers were checked and kept, the consent signed, and the registration service was not reached.
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
  assert.deepEqual(done.review, { title: 'Let this sign-up go', confirm: 'Let it go', fields: { Name: '@uma_p is free again, for anyone. This browser forgets the keys it made for this sign-up; it cannot be undone.', 'Recovery papers': 'The recovery sheet and passphrase you wrote down for @uma_p will never work: destroy them.' } });
  assert.deepEqual([done.notice, raw('uma_p')], ['Nothing was changed. The sign-up is still kept in this browser.', before]);
  // Another tab of this browser goes on with the sign-up while the review is open (its person remembered the password):
  // the consent it gives is kept as a newer record, and the check after the review reads it, and stops.
  const registration = await openVault(kept('uma_p').login, LOGIN, argon2id), newer = chain.now + 300000000n;
  done = await letGo({ confirm: true, during: async () => { storage.setItem(S.consentKey(NET, 'uma_p'), JSON.stringify(await S.signConsent({ networkId: NET, name: 'uma_p', registration: { publicKey: registration.binding.publicKey, privateKey: registration.privateKey }, expiresElapsedMicros: newer }))); } });
  assert.deepEqual([done.review?.title, done.notice], ['Let this sign-up go', S.letGoWords({ why: 'consent', kept: true, until: newer }, 'uma_p', chainDate)]);
  assert.deepEqual(raw('uma_p').slice(0, 5), before.slice(0, 5), 'nothing was removed');
  storage.setItem(S.consentKey(NET, 'uma_p'), before[5]);
  // Confirmed: everything of the sign-up is gone from this browser, and nothing else.
  const own = slots('uma_p'), others = [...storage.m.keys()].filter(key => ![own.login, own.nextLogin, own.nextSpend, own.nextNote, S.consentKey(NET, 'uma_p')].includes(key));
  done = await letGo({ confirm: true });
  assert.deepEqual([done.notice, raw('uma_p'), $('signup-letgo-row').hidden], [S.letGoneWords('uma_p'), [null, null, null, null, null, null], true]);
  assert.equal(done.notice, 'This browser let the sign-up of @uma_p go. Destroy the recovery papers you wrote down for it.');
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
  assert.deepEqual([done.review, done.notice, raw('wyn_p')], [null, 'The network holds the account @wyn_p that this sign-up made, so this browser keeps what opens it. Open it with the login password you chose for it; if you forgot that, recover the account with your recovery sheet and your recovery passphrase, under "Other ways in".', made]);
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
  for (const [place, intent, password] of [[s.nextSpend, 'spend', PAYMENT], [s.nextLogin, 'signin', LOGIN]]) {
    const other = await F.sealedKey({ password, networkId: NET, name: 'xia_p', intent, argon2id });
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
  const signin = await F.sealedKey({ password: LOGIN, networkId: NET, name: 'erin_p', intent: 'signin', argon2id }), spend = await F.sealedKey({ password: PAYMENT, networkId: NET, name: 'erin_p', intent: 'spend', argon2id });
  const fakeKeys = [['signin', signin.key.publicKey], ['spend', spend.key.publicKey], ['recover', '7'.repeat(64)], ['recover', '8'.repeat(64)]].map(([role, public_key]) => ({ public_key, role, proof: 'ab'.repeat(64) }));
  storage.setItem(e.login, JSON.stringify(await sealVault({ ...fake.secret, nameSalt: 'cd'.repeat(32), intent: 'device' }, LOGIN, { networkId: NET, name: 'erin_p', publicKey: fake.publicKey }, argon2id)));
  storage.setItem(e.nextNote, JSON.stringify(await S.signNote({ networkId: NET, name: 'erin_p', registration: fake, keys: fakeKeys, policy: { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800' } })));
  storage.setItem(e.nextLogin, JSON.stringify(signin.record)); storage.setItem(e.nextSpend, JSON.stringify(spend.record));
  const written = raw('erin_p');
  $('username').value = 'erin_p';
  done = await letGo();
  assert.deepEqual([done.review, done.notice, raw('erin_p')], [null, 'This browser keeps a payment key of an account @erin_p, so it does not let a sign-up of that name go. Open that account with its login password.', written]);
  assert.equal(written[1], erin[1], 'the account\'s payment key is still kept');
  // The account's payment key removed as well: the network holds an account of that name, and that is enough. A sign-up
  // whose name another account holds is not let go (signup.mjs, letGoState: 'taken'), so the person is never told there
  // to destroy recovery papers that may be that account's.
  const taken = 'The name @erin_p belongs to another account on the network, so this sign-up can never finish, and this browser keeps it as it is. If that account is yours, open it with its login password, or recover it with your recovery sheet and your recovery passphrase; if not, create your account with another name.';
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

test('on a network without the setting the sign-up is as it was: the same form, one key, a reveal, and the card "Not protected yet"', async () => {
  reset(); chain.protect = false;
  try {
    await freshPage();
    // The form is the page's own: the script touched none of the protected fields (the stand-in page starts them empty,
    // and hidden as index.html has them).
    assert.deepEqual([$('password-label').textContent, $('confirm-label').textContent, $('signup-protected').hidden, $('signup-login-note').hidden, $('password-note').hidden, $('signup-limit').value], ['', '', true, true, false, ''], 'nothing of the protected form was drawn');
    await $('mode-create').fire('click');
    assert.deepEqual([$('auth-copy').textContent, $('auth-submit').textContent, $('signup-protected').hidden, $('password-label').textContent], ['Pick a name that others can send seconds to, and a password.', 'Create my account', true, '']);
    const posted = chain.posted.length;
    $('username').value = 'quin'; $('password').value = $('password-confirm').value = LOGIN;
    await $('auth-form').fire('submit'); await opened('quin');
    assert.equal($('notice').textContent, 'Your account is ready. This browser checked it with the network. Next: keep your account safe under Keys.');
    assert.deepEqual(chain.posted.slice(posted).map(a => a.kind), [44, 2], 'the sponsor\'s action, then the reveal');
    const account = byName('quin');
    assert.deepEqual([account.devices.length, account.devices[0].can_manage && account.devices[0].can_spend, chain.security[account.id]], [1, true, undefined]);
    assert.deepEqual([$('protect-none').hidden, $('protect-on').hidden, kept('quin').login.version, kept('quin').note], [false, true, 1, null]);
  } finally { reset(); await freshPage(); }
});
