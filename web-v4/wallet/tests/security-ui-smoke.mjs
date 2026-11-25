// Smoke run of security-ui.mjs without a browser: a minimal fake DOM and a mock chain that applies
// kinds 70, 72, 73, 74 and 75 roughly as the engine does. It drives the real module through
// securing an account, paying within and above the allowance, freezing, and recovering on a new
// device. It checks wiring (ids, handlers, storage, which key signs what), not the engine rules,
// which client-v4/account-security.test.mjs and ../security.test.mjs cover.
// Run: node web-v4/wallet/tests/security-ui-smoke.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const root = new URL('../../../', import.meta.url);
import { registerHooks } from 'node:module';
registerHooks({ resolve(s, context, next) { return next(s === '/sdk/account-security.mjs' ? new URL('client-v4/account-security.mjs', root).href : s, context); } });
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;
const source = await readFile(new URL('web-v4/wallet/vendor/argon2-4.12.0.umd.min.js', root), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', source)(umd, umd.exports);

// ------------------------------------------------------------------ fake page
class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } key(i) { return [...this.m.keys()][i]; } get length() { return this.m.size; } }
class El {
  constructor(id) { Object.assign(this, { id, value: '', hidden: false, textContent: '', disabled: false, dataset: {}, type: 'text', children: [], listeners: {}, className: '', classList: { add() {}, remove() {}, toggle() {} } }); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  querySelectorAll() { return [this.querySelector()]; } querySelector() { return this.button ??= new El(this.id + '-button'); }
  replaceChildren(...c) { this.children = c; } append(...c) { this.children.push(...c); }
  async fire(type) { await Promise.all((this.listeners[type] || []).map(fn => fn({ preventDefault() {} }))); while (runs.length) await runs.shift(); }
}
const els = {}, runs = [];
globalThis.document = { getElementById: id => els[id] ??= new El(id), createElement: tag => new El(tag), querySelectorAll: () => [], body: { classList: { add() {}, remove() {} } } };
const storage = new Storage();
Object.defineProperty(globalThis, 'localStorage', { value: new Proxy(storage, { ownKeys: t => [...t.m.keys()], getOwnPropertyDescriptor: (t, k) => t.m.has(k) ? { enumerable: true, configurable: true, value: t.m.get(k) } : Reflect.getOwnPropertyDescriptor(t, k), get: (t, k) => typeof t[k] === 'function' ? t[k].bind(t) : t[k] }) });
Object.defineProperty(globalThis, 'navigator', { value: { locks: { request: (name, options, fn) => fn() } } });
globalThis.window = { print() {} };
const $ = id => document.getElementById(id);

const { createSecurityUI } = await import(new URL('web-v4/wallet/security-ui.mjs', root).href);
const { newDevice } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { sealLegacy } = await import(new URL('web-v4/wallet/tests/legacy-vault.mjs', root).href);
const { PendingReservations, formatSeconds } = await import(new URL('web-v4/wallet/guards.mjs', root).href);
const { assertSpendKeyKind } = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const security = await import(new URL('client-v4/account-security.mjs', root).href);

// ------------------------------------------------------------------ mock chain
const networkId = 'c6'.repeat(32), fee = '1000';
const chain = { time: 1000000000n, accounts: [], rows: {} };
const stateOf = () => structuredClone({ network_id: networkId, height: '9', time_micros: chain.time.toString(), genesis: { genesis_time_micros: '0' }, config: { recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '86400000000' }, accounts: chain.accounts, security: Object.values(chain.rows) });
const role = r => ({ can_manage: r === 'recover', can_spend: r === 'spend' });
const signed = [];
function apply(action) {
  const account = chain.accounts.find(a => a.id === action.from), p = action.payload, now = chain.time;
  signed.push({ kind: action.kind, by: account.devices.find(d => d.public_key === action.publicKey) ? security.roleOf(account.devices.find(d => d.public_key === action.publicKey)) : 'outside', payload: p });
  if (action.kind === 70) { account.devices = p.keys.map(k => ({ public_key: k.public_key, ...role(k.role) })); account.nonce = action.nonce; chain.rows[account.id] = { account: account.id, version: '1', policy: p.policy, allowance_micros: p.policy.daily_limit_micros, allowance_elapsed_micros: now.toString(), frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null }; }
  const row = chain.rows[account.id];
  if (action.kind === 3) { account.nonce = action.nonce; row.allowance_micros = (security.allowance(row, now) - BigInt(p.amount) - BigInt(fee)).toString(); row.allowance_elapsed_micros = now.toString(); }
  if (action.kind === 75) { account.nonce = action.nonce; row.pending_payments.push({ id: row.next_id, to: p.to, amount: p.amount, ready_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * 1000000n).toString() }); row.next_id = String(BigInt(row.next_id) + 1n); }
  if (action.kind === 72) { row.freezes = String(BigInt(row.freezes) + 1n); row.frozen_until_elapsed_micros = (now + BigInt(row.policy.freeze_seconds) * 1000000n).toString(); }
  if (action.kind === 73) {
    if (p.op.type === 'replace' && !security.proofs(account, p.approvals.map(a => a.public_key)).spend) row.pending_root = { devices: p.op.keys.map(k => ({ public_key: k.public_key, ...role(k.role) })), policy: p.op.policy, ready_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * 1000000n).toString(), expires_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * 1000000n + 86400000000n).toString() };
    if (p.op.type === 'unfreeze') row.frozen_until_elapsed_micros = '0';
    row.version = String(BigInt(row.version) + 1n);
  }
  if (action.kind === 77) { account.nonce = action.nonce; if (BigInt(p.daily_limit_micros) > BigInt(row.policy.daily_limit_micros)) { row.pending_limit = { id: row.next_id, daily_limit_micros: p.daily_limit_micros, ready_elapsed_micros: (now + BigInt(row.policy.delay_seconds) * 1000000n).toString() }; row.next_id = String(BigInt(row.next_id) + 1n); } else row.policy.daily_limit_micros = p.daily_limit_micros; }
  if (action.kind === 76) { if (p.type === 'payment') row.pending_payments = row.pending_payments.filter(x => x.id !== p.id); else row.pending_limit = null; }
  if (action.kind === 71) { account.nonce = action.nonce; account.devices = account.devices.filter(d => !p.remove.includes(d.public_key)).concat(p.add.map(k => ({ public_key: k.public_key, can_manage: false, can_spend: false }))); }
  if (action.kind === 73 && p.op.type === 'replace' && security.proofs(account, p.approvals.map(a => a.public_key)).spend) account.devices = p.op.keys.map(k => ({ public_key: k.public_key, ...role(k.role) }));
  if (action.kind === 5 || action.kind === 6) {
    const device = account.devices.find(d => d.public_key === action.publicKey);
    if (!device?.can_spend) throw new Error('spending device required');
    if (action.nonce !== String(BigInt(account.nonce) + 1n) || action.authEpoch !== account.auth_epoch) throw new Error('stale authority or incorrect nonce');
    const before = BigInt(account.balance), after = before - (action.kind === 5 ? BigInt(p.amount) : 0n) - BigInt(fee), outflow = before - after;
    if (row && outflow > 0n) {
      if (security.frozen(row, now)) throw new Error('account is frozen');
      const left = security.allowance(row, now); if (outflow > left) throw new Error('daily limit exceeded');
      row.allowance_micros = (left - outflow).toString(); row.allowance_elapsed_micros = now.toString();
    }
    account.balance = after.toString(); account.nonce = action.nonce;
  }
  if (action.kind === 74) { account.devices = row.pending_root.devices; row.pending_root = null; row.version = String(BigInt(row.version) + 1n); }
}
const client = { submit: async tx => { const action = SDK.decodeAction(tx); apply(action); return { verified: true, hash: await SDK.transactionHash(tx), height: '10', action }; }, waitReceipt: async () => { throw new Error('none'); } };

// ------------------------------------------------------------------ the wallet around it
let session = null, latest = null, locked = null, unlockName = null;
const reviews = [], notices = [], errors = [], sent = [];
const ownAccount = (state = latest) => state?.accounts.find(a => a.name === (session?.binding.name || 'alice'));
const c = {
  sdk: SDK, client: () => client, network: () => ({ networkId }), session: () => session, state: () => latest, ownAccount,
  verifiedState: async () => (latest = stateOf()), refresh: async () => {}, review: async title => { reviews.push(title); return true; },
  notice: message => notices.push(message), run: fn => { const p = (async () => { try { await fn(); } catch (error) { errors.push(error.message); } })(); runs.push(p); return p; }, setBusy() {}, capture: () => () => {},
  seconds: v => formatSeconds(String(v)), fee: () => fee, pending: new PendingReservations(localStorage), record() {}, lock: message => { locked = message; session = null; }, argon2id: () => umd.exports.argon2id,
  showUnlock: name => { unlockName = name; },
  sendSigned: async (kind, payload, label, { signer }) => { assertSpendKeyKind(kind); sent.push({ kind, signer: signer.publicKey }); const account = ownAccount(stateOf()); const tx = await SDK.signAction({ networkId, kind, from: account.id, nonce: String(BigInt(account.nonce) + 1n), authEpoch: account.auth_epoch, publicKey: signer.publicKey, payload }, signer.privateKey); return client.submit(tx); },
};
const ui = createSecurityUI(c);
const check = (label) => { assert.deepEqual(errors, [], label + ': ' + errors.join(' | ')); };

// ------------------------------------------------------------------ 1. secure my account
const full = await newDevice();
chain.accounts.push({ id: '5', name: 'alice', balance: '100000000', nonce: '3', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: full.publicKey, can_manage: true, can_spend: true }] });
chain.accounts.push({ id: '9', name: 'bob', balance: '0', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [] });
storage.setItem(`timecurrency.vault.v1:${networkId}:alice`, JSON.stringify(await sealLegacy(full.secret, 'an old protocol four password', { networkId, name: 'alice', publicKey: full.publicKey }, umd.exports.argon2id)));
session = { binding: { networkId, name: 'alice', publicKey: full.publicKey }, privateKey: full.privateKey };
latest = stateOf(); ui.render(ownAccount(), latest); ui.availability(true);
assert.equal($('security-adopt').hidden, false); assert.equal($('security-dashboard').hidden, true);
const login = 'violet otters dance beneath moonlight 41', payment = 'quiet harbour lanterns at dawn 77';
Object.assign(els, {}); for (const [id, v] of [['secure-login', login], ['secure-login-confirm', login], ['secure-payment', payment], ['secure-payment-confirm', payment], ['secure-limit', '60'], ['secure-delay', '48'], ['secure-freeze', '48'], ['secure-threshold', '2']]) $(id).value = v;
await $('secure-form').fire('submit'); check('secure step 1');
const phrase = $('secure-phrase-shown').textContent; assert.match(phrase, /^[a-z]{6}( [a-z]{6}){4}$/, 'the wallet made five recovery words');
assert.equal($('secure-login').value + $('secure-payment').value, '', 'secret fields are cleared');
assert.equal($('secure-submit').hidden, false, 'words only: the button is there from the start');
await $('secure-submit').fire('click'); check('secure submit');
assert.equal(signed.at(-1).kind, 70); assert.equal(locked, 'Your account is protected. Open it with your login password.');
const loginRecord = JSON.parse(storage.getItem(`timecurrency.vault.v1:${networkId}:alice`)), spendRecord = JSON.parse(storage.getItem(`timecurrency.spend-vault.v1:${networkId}:alice`));
assert.equal(loginRecord.intent, 'signin'); assert.equal(spendRecord.intent, 'spend');
assert.ok(![...storage.m.values()].some(v => v.includes(full.publicKey)), 'the protocol-4 key is gone from storage');
assert.ok(![...storage.m.values()].some(v => v.includes(phrase)), 'no recovery secret is stored');
const alice = chain.accounts[0];
assert.deepEqual(alice.devices.map(d => security.roleOf(d)).sort(), ['recover', 'recover', 'signin', 'spend']);

// ------------------------------------------------------------------ 2-3. unlocked with the sign-in key; pay
session = { binding: { networkId, name: 'alice', publicKey: loginRecord.binding.publicKey }, privateKey: null };
latest = stateOf(); ui.render(ownAccount(), latest); ui.availability(true);
assert.equal($('security-dashboard').hidden, false); assert.equal($('send-payment-wrap').hidden, false);
assert.match($('send-allowance').textContent, /You can pay 60 more seconds today/);
assert.equal(ui.loginRefusal(latest, ownAccount()), null);
$('send-payment').value = payment;
await c.run(() => ui.pay({ name: 'bob', to: { id: '9' }, amount: '10000000', state: latest, account: ownAccount() })); check('pay within');
assert.equal(sent.at(-1).kind, 'transfer'); assert.equal(sent.at(-1).signer, spendRecord.binding.publicKey); assert.equal($('send-payment').value, '');
latest = stateOf();
await c.run(() => ui.pay({ name: 'bob', to: { id: '9' }, amount: '55000000', state: latest, account: ownAccount() })); check('pay over');
assert.equal($('send-over-limit').hidden, false);
$('send-payment').value = payment; await $('send-wait').fire('click'); check('waiting payment');
assert.equal(signed.at(-1).kind, 75); assert.equal(signed.at(-1).by, 'spend');
latest = stateOf(); await c.run(() => ui.pay({ name: 'bob', to: { id: '9' }, amount: '55000000', state: latest, account: ownAccount() }));
$('send-payment').value = payment; $('send-recovery-secret').value = phrase.toUpperCase();
await $('send-now').fire('click'); check('pay now');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).payload.op.type, signed.at(-1).payload.approvals.length], [73, 'pay', 2]);

// ------------------------------------------------------------------ 4-5. inbox and freeze
latest = stateOf(); ui.render(ownAccount(), latest);
assert.ok($('security-inbox').children.some(r => r.children[0]?.children[0]?.textContent.startsWith('Waiting payment')));
assert.equal($('inbox-keys').hidden, false);
$('freeze-method').value = 'paper'; $('freeze-secret').value = phrase;
await $('freeze-form').fire('submit'); check('freeze');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by], [72, 'recover']);
latest = stateOf(); ui.render(ownAccount(), latest);
assert.equal($('security-title').textContent, 'Your account is frozen.');
// The Protection card says so and its switch is on; "End the freeze" opens the step that needs two keys.
assert.deepEqual([$('freeze-switch').checked, $('freeze-more').hidden, $('unfreeze-form').hidden], [true, false, true]);
await $('unfreeze-open').fire('click'); assert.equal($('unfreeze-form').hidden, false);
assert.match(ui.loginRefusal(latest, ownAccount()), /frozen/);
$('unfreeze-payment').value = payment; $('unfreeze-secret').value = phrase;
await $('unfreeze-form').fire('submit'); check('unfreeze');
assert.equal(signed.at(-1).payload.op.type, 'unfreeze');

// ------------------------------------------------------------------ 9. limit, inbox cancel; 6-7. replace login and payment key
latest = stateOf(); ui.render(ownAccount(), latest);
$('limit-amount').value = '120'; $('limit-payment').value = payment; await $('limit-form').fire('submit'); check('raise limit');
assert.equal(signed.at(-1).kind, 77); latest = stateOf(); ui.render(ownAccount(), latest);
const raiseRow = $('security-inbox').children.find(r => r.children[0]?.children[0]?.textContent.startsWith('Waiting raise'));
assert.ok(raiseRow, 'the raise is in the inbox');
$('inbox-secret').value = phrase; await raiseRow.children.find(b => b.textContent === 'Cancel').fire('click'); check('cancel raise');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by, signed.at(-1).payload.type], [76, 'recover', 'limit']);
const oldLogin = session.binding.publicKey, newLogin = 'another login password for alice 7';
$('replace-login-new').value = newLogin; $('replace-login-confirm').value = newLogin; $('replace-login-payment').value = payment;
await $('replace-login-form').fire('submit'); check('replace login');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by], [71, 'spend']); assert.match(locked, /new login password/);
const login3 = JSON.parse(storage.getItem(`timecurrency.vault.v1:${networkId}:alice`));
assert.notEqual(login3.binding.publicKey, oldLogin); assert.ok(alice.devices.some(d => d.public_key === login3.binding.publicKey) && !alice.devices.some(d => d.public_key === oldLogin));
session = { binding: { networkId, name: 'alice', publicKey: login3.binding.publicKey }, privateKey: null }; latest = stateOf(); ui.render(ownAccount(), latest);
const payment3 = 'a fresh payment password for alice 8';
const login5 = 'the login after replacing the payment key 5';
$('replace-spend-payment').value = payment; $('replace-spend-new').value = payment3; $('replace-spend-confirm').value = payment3; $('replace-spend-login').value = login5; $('replace-spend-login-confirm').value = login5; $('replace-spend-secret').value = phrase;
await $('replace-spend-form').fire('submit'); check('replace spend');
assert.match(locked, /new login password/);
const login5Record = JSON.parse(storage.getItem(`timecurrency.vault.v1:${networkId}:alice`));
assert.ok(!alice.devices.some(d => d.public_key === login3.binding.publicKey), 'the old login key went with the old payment key');
session = { binding: { networkId, name: 'alice', publicKey: login5Record.binding.publicKey }, privateKey: null };
assert.deepEqual([signed.at(-1).kind, signed.at(-1).payload.op.type], [73, 'replace']);
const spend3 = JSON.parse(storage.getItem(`timecurrency.spend-vault.v1:${networkId}:alice`));
assert.notEqual(spend3.binding.publicKey, spendRecord.binding.publicKey); assert.ok(alice.devices.some(d => d.public_key === spend3.binding.publicKey && d.can_spend));
assert.ok(!alice.devices.some(d => d.public_key === spendRecord.binding.publicKey), 'the old payment key is gone');

// ------------------------------------------------------------------ other tabs on a secured account, one inbox with a count
latest = stateOf(); ui.render(ownAccount(), latest);
assert.equal($('devices-secured-card').hidden, false); assert.equal($('add-device-card').hidden, true);
assert.equal($('guardian-card').hidden, true); assert.equal($('guardian-help-card').hidden, true); assert.equal($('recovery-secured-card').hidden, false);
assert.equal($('earn-secured-note').hidden, false); assert.equal($('devices-title').textContent, 'The keys of your account');
assert.deepEqual($('device-list').children.map(r => r.children[0].children[0].textContent).sort(), ['Login key of this browser', 'Payment key of this browser', 'Recovery key', 'Recovery key']);
assert.equal($('tab-home').textContent, 'Home (1)', 'the waiting payment is counted, on Home, where the list of what waits is');

// ------------------------------------------------------------------ 3b. stake and unbond from a secured account
alice.balance = '1000000000000';
latest = stateOf(); ui.render(ownAccount(), latest);
assert.equal($('stake-payment-wrap').hidden, false); assert.equal($('auction-secured-note').hidden, false);
assert.match($('stake-allowance').textContent, /you can stake [0-9.]+ more seconds, fee included/);
const leftBefore = security.allowance(chain.rows['5'], chain.time);
$('stake-payment').value = payment3;
await c.run(() => ui.stake({ operator: '9', amount: '2000000', quotedShares: '2000000', state: latest, account: ownAccount() })); check('stake');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by], [5, 'spend']); assert.equal(sent.at(-1).signer, spend3.binding.publicKey); assert.equal($('stake-payment').value, '');
assert.equal(security.allowance(chain.rows['5'], chain.time), leftBefore - 2001000n, 'amount and fee count against the limit');
// Above what is left today: nothing is signed, and the two honest choices appear.
latest = stateOf(); let count = signed.length;
await c.run(() => ui.stake({ operator: '9', amount: '500000000', quotedShares: '1', state: latest, account: ownAccount() })); check('stake over');
assert.equal(signed.length, count); assert.equal($('stake-over-limit').hidden, false);
await $('stake-fit-today').fire('click');
assert.equal($('stake-amount').value, formatSeconds(String(security.allowance(chain.rows['5'], chain.time) - 1000n)));
await c.run(() => ui.stake({ operator: '9', amount: '500000000', quotedShares: '1', state: latest, account: ownAccount() }));
await $('stake-raise-limit').fire('click'); assert.equal($('limit-amount').value, '501'); assert.equal($('stake-over-limit').hidden, true);
// Unbonding through the pos-ui path, with the payment key.
$('stake-payment').value = payment3;
await c.run(() => ui.stakeAction('undelegate', { operator: '9', shares: '2000000', min_amount: '2000000' }, 'Unbond delegation')); check('unbond');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by], [6, 'spend']);
// A validator's registration is signed by the payment key too (pos-ui.mjs, Validator operator), and charged its bond:
// a state that names no staking profile gives no bond, and nothing is unlocked or signed. Any other kind is refused.
count = signed.length; $('stake-payment').value = payment3;
await c.run(() => ui.stakeAction('register_validator', { commission_bps: 0, consensus_key: 'ab'.repeat(32), proof: 'ab'.repeat(64) }, 'Register validator'));
assert.match(errors.pop(), /does not know the least bond/); assert.equal(signed.length, count); $('stake-payment').value = payment3;
await c.run(() => ui.stakeAction('claim_auction', {}, 'Claim')); assert.match(errors.pop(), /payments and staking only/); assert.equal(signed.length, count); $('stake-payment').value = '';
// Frozen: refused with a pointer to Keys, and nothing reaches the chain.
chain.rows['5'].frozen_until_elapsed_micros = String(chain.time + 1000000n); latest = stateOf(); ui.render(ownAccount(), latest);
assert.equal($('stake-frozen-note').hidden, false);
$('stake-payment').value = payment3;
await c.run(() => ui.stake({ operator: '9', amount: '1000000', quotedShares: '1', state: latest, account: ownAccount() })); assert.match(errors.pop(), /frozen.*See Home\./);
await c.run(() => ui.stakeAction('undelegate', { operator: '9', shares: '1', min_amount: '1' }, 'Unbond')); assert.match(errors.pop(), /frozen/);
assert.equal(signed.length, count); $('stake-payment').value = '';
chain.rows['5'].frozen_until_elapsed_micros = '0';

// ------------------------------------------------------------------ 1b. this browser's login key was removed elsewhere
session = { binding: { networkId, name: 'alice', publicKey: oldLogin }, privateKey: null };
latest = stateOf();
assert.equal(await ui.withoutDevice(ownAccount(), latest), true);
assert.equal($('security-removed-panel').hidden, false); assert.equal($('enrollment-panel').hidden, true);
assert.equal($('removed-login-form').hidden, false, 'the payment password path is offered');
assert.match($('removed-status').textContent, /still has your payment key/);
const login4 = 'a login password made after removal 5';
$('removed-login-new').value = login4; $('removed-login-confirm').value = login4; $('removed-payment').value = payment3;
await $('removed-login-form').fire('submit'); check('new login after removal');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by], [71, 'spend']); assert.match(locked, /new login password/);
const login4Record = JSON.parse(storage.getItem(`timecurrency.vault.v1:${networkId}:alice`));
assert.ok(alice.devices.some(d => d.public_key === login4Record.binding.publicKey));
// Without the payment key on this browser only the recovery path is offered, and it opens prefilled.
const savedSpend = storage.getItem(`timecurrency.spend-vault.v1:${networkId}:alice`); storage.removeItem(`timecurrency.spend-vault.v1:${networkId}:alice`);
session = { binding: { networkId, name: 'alice', publicKey: oldLogin }, privateKey: null }; latest = stateOf();
await ui.withoutDevice(ownAccount(), latest);
assert.equal($('removed-login-form').hidden, true); assert.match($('removed-status').textContent, /no payment key/);
await $('removed-lost').fire('click'); check('removed to lost');
assert.equal($('security-recover-panel').hidden, false); assert.equal($('lost-form').hidden, false); assert.equal($('lost-name').value, 'alice');
storage.setItem(`timecurrency.spend-vault.v1:${networkId}:alice`, savedSpend); $('lost-name').value = '';

// ------------------------------------------------------------------ 8. lost device on a fresh browser
storage.m.clear(); session = null; locked = null; ui.reset();
// This browser still holds the record of a login key the account no longer has: the recovery replaces it.
storage.setItem(`timecurrency.vault.v1:${networkId}:alice`, JSON.stringify(loginRecord));
$('lost-name').value = 'alice'; $('lost-sheet').value = ''; $('lost-phrase').value = phrase;
const login2 = 'brand new login words for alice 2026', payment2 = 'brand new payment words for alice 99';
for (const [id, v] of [['lost-login', login2], ['lost-login-confirm', login2], ['lost-payment', payment2], ['lost-payment-confirm', payment2]]) $(id).value = v;
await $('lost-form').fire('submit'); check('lost request');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by, signed.at(-1).payload.op.type], [73, 'recover', 'replace']);
assert.match($('lost-status-text').textContent, /is waiting/);
const progress = JSON.parse(storage.getItem(`timecurrency.security-recovery.v1:${networkId}:alice`));
assert.equal(JSON.parse(storage.getItem(`timecurrency.vault.v1:${networkId}:alice`)).binding.publicKey, progress.signin, 'the stale login record was replaced');
assert.deepEqual(Object.keys(progress).sort(), ['accountId', 'name', 'networkId', 'signin', 'spend', 'version']);
assert.ok(![...storage.m.values()].some(v => v.includes(phrase)), 'no recovery secret is stored while waiting');
// A reload: a fresh module instance finds the progress and shows the status.
for (const el of Object.values(els)) el.listeners = {};
const ui2 = createSecurityUI(c); await ui2.start(); check('reload');
chain.time += 48n * 3600n * 1000000n; await $('lost-check').fire('click'); check('ready');
assert.equal($('lost-finish-form').hidden, false);
$('lost-finish-payment').value = payment2; await $('lost-finish-form').fire('submit'); check('finish');
assert.deepEqual([signed.at(-1).kind, signed.at(-1).by], [74, 'outside']);
assert.equal(unlockName, 'alice'); assert.equal(storage.getItem(`timecurrency.security-recovery.v1:${networkId}:alice`), null);
assert.ok(alice.devices.some(d => d.public_key === progress.spend && d.can_spend));
console.log('security UI smoke: ok', signed.map(s => s.kind).join(','), '| reviews:', reviews.length);
