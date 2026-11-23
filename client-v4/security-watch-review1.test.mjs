// Adversarial probes of the security watch. Each test asserts the behaviour the watch SHOULD have;
// a failure is a reproduced defect. Helpers copied from security-watch.test.mjs.
//
// Adapted by the watch's author where a fix changed an API (assertions otherwise as reviewed):
// - delivery is per target and asynchronous: `fanOut` is gone (targets are passed to the watch),
//   and tests wait for `watch.settled()` before reading what was delivered;
// - per-account ids left `status()` (served on /health) for `details()`;
// - F-F: the payment hidden by the gateway can never be told as waiting (the watch never sees it);
//   the fix is that the held-back state counts as stale and the owner gets an urgent
//   `watch_blind` before that payment could go through, then `waiting_unseen`;
// - F-G: the batch time limit defaults to 30 s (a light-client update can take a while); the test
//   passes 1 s to fit its 1.5 s race;
// - F-I: measured in real time with a receiver that hangs, since the queues now run concurrently
//   and a shared virtual clock would add up waits that overlap;
// - F-N: inverted to assert the fix (timestamped signature, maximum age, event id signed).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import './time-sdk.js';
import { diffSecurity, snapshotOf } from './security-watch.mjs';
import { createSecurityWatch, memoryStore, fileStore, webhookAdapter, createFeed, createAlertServer } from './security-watch-service.mjs';
import { start } from '../deploy/watch/start.mjs';

const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const GENESIS = '1794260994671000', FEE = 1000n, S = 1_000_000n;
const key = Object.fromEntries(fixture.secure.payload.keys.map((k) => [k.public_key.slice(0, 4), k.public_key]));
const device = (publicKey, role) => ({ public_key: publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const DEVICES = fixture.secure.payload.keys.map((k) => device(k.public_key, k.role));
const BASE = { ...fixture.allowance.security, pending_limit: null, account: '5' };
const T0 = 2_407_000_000n;
function verified({ height, elapsed, balance = 50n * S, nonce = '3', epoch = '1', devices = DEVICES, security = BASE, others = [] }) {
  const accounts = [{ id: '5', name: 'alice', public_key: key['70df'], balance: String(balance), nonce, auth_epoch: epoch, devices, delegations: [], unbonding: [] },
    ...others.map((id) => ({ id, name: `a${id}`, public_key: key['70df'], balance: String(50n * S), nonce: '0', auth_epoch: '1', devices: DEVICES, delegations: [], unbonding: [] }))];
  const rows = security ? [security, ...others.map((id) => ({ ...BASE, account: id }))] : [];
  return { verified: true, height: String(height), state: { network_id: fixture.network_id, height: String(height), time_micros: (BigInt(GENESIS) + BigInt(elapsed)).toString(), genesis: { genesis_time_micros: GENESIS }, accounts, security: rows, config: {} } };
}
const snap = (o) => snapshotOf(verified(o), '5');
const types = (events) => events.map((e) => e.type);
const payment = { id: '2', to: '42', amount: String(12_500_000n), ready_elapsed_micros: String(T0 + 60n * S) };
const withPayment = { ...BASE, pending_payments: [payment], next_id: '3' };
const chainMs = (elapsed) => Number((BigInt(GENESIS) + elapsed) / 1000n);

// ------------------------------------------------------------------ wrong facts / missed events
test('F-A executed payment + an inflow just above the fee is reported "most likely did not go through"', () => {
  const waiting = snap({ height: 11, elapsed: T0 + 5n * S, security: withPayment, balance: 50n * S - FEE });
  // Engine: PAYMENT/execute debits 12.5 s + fee. Meanwhile someone sends 0.002 s in (2 x fee).
  const after = snap({ height: 30, elapsed: T0 + 70n * S, security: { ...BASE, next_id: '3' }, balance: 50n * S - FEE - 12_500_000n - FEE + 2n * FEE });
  const gone = diffSecurity(waiting, after).find((e) => e.type === 'payment_gone');
  console.log('F-A outcome:', gone.outcome, '| certain:', gone.certain, '| urgent:', gone.urgent, '\n  message:', gone.message);
  assert.notEqual(gone.outcome, 'cancelled', 'an executed payment must not be reported as most likely cancelled');
});

test('F-B a sign-in key added and removed between two polls produces no event', () => {
  const before = snap({ height: 10, elapsed: T0, epoch: '1', nonce: '3' });
  // Engine: two SIGNIN actions (add, then remove): auth_epoch 1 -> 3, nonce 3 -> 5, devices unchanged.
  const after = snap({ height: 12, elapsed: T0 + 20n * S, epoch: '3', nonce: '5' });
  const events = diffSecurity(before, after);
  console.log('F-B events:', types(events));
  assert.ok(events.some((e) => e.urgent), 'the spend key was used to add a sign-in key: urgent');
});

test('F-C an immediate root payment (spend key + approvals) drains the account with no event', () => {
  const before = snap({ height: 10, elapsed: T0, balance: 50n * S });
  // Engine ROOT {type:pay}: debit amount, version 1 -> 2, full fee; nothing else in the rows changes.
  const after = snap({ height: 11, elapsed: T0 + S, balance: 50n * S - 49n * S - FEE, security: { ...BASE, version: '2' } });
  const events = diffSecurity(before, after);
  console.log('F-C events:', types(events));
  assert.ok(events.length > 0, 'a root operation moved 49 s out at once');
});

test('F-D a limit raise that skipped the wait (root replace keeping the keys) is only a non-urgent event', () => {
  const before = snap({ height: 10, elapsed: T0 });
  // Engine install(): same devices, policy daily limit 0.5 s -> 1000 s, version+1, nonce+1, epoch+1, no wait.
  const after = snap({ height: 11, elapsed: T0 + S, nonce: '4', epoch: '2', security: { ...BASE, version: '2', policy: { ...BASE.policy, daily_limit_micros: String(1000n * S) } } });
  const events = diffSecurity(before, after);
  console.log('F-D events:', events.map((e) => `${e.type} urgent=${e.urgent}: ${e.message}`));
  assert.ok(events.some((e) => e.urgent), 'the limit went up 2000x without the waiting period');
});

test('F-D2 a freeze lifted early by a root operation is non-urgent', () => {
  const frozen = snap({ height: 10, elapsed: T0, security: { ...BASE, freezes: '1', frozen_until_elapsed_micros: String(T0 + 120n * S) } });
  const lifted = snap({ height: 11, elapsed: T0 + 5n * S, security: { ...BASE, version: '2', freezes: '1', frozen_until_elapsed_micros: '0' } });
  const events = diffSecurity(frozen, lifted);
  console.log('F-D2 events:', events.map((e) => `${e.type} urgent=${e.urgent}`));
  assert.ok(events.some((e) => e.urgent), 'someone with the spend key and approvals lifted the owner\'s freeze');
});

test('F-E a raise that took effect and was then lowered (still above the old limit) is reported as cancelled', () => {
  const raise = { id: '1', daily_limit_micros: '2000000', ready_elapsed_micros: String(T0 + 60n * S) };
  const before = snap({ height: 10, elapsed: T0, security: { ...BASE, pending_limit: raise } });
  // Engine: raise ready at T0+60 s; at T0+100 s LIMIT 1 s: settle applies the raise (2 s), then lowers to 1 s.
  const after = snap({ height: 40, elapsed: T0 + 100n * S, nonce: '4', security: { ...BASE, policy: { ...BASE.policy, daily_limit_micros: '1000000' } } });
  const events = diffSecurity(before, after);
  console.log('F-E events:', events.map((e) => `${e.type}: ${e.message}`));
  assert.ok(!events.some((e) => e.type === 'limit_raise_cancelled'), 'the raise took effect; it was not cancelled');
});

// ------------------------------------------------------------------ gateway: silencing and delay
test('F-F a gateway that holds back state < max_lag hides a whole 60 s payment; nothing is flagged stale', async () => {
  // Polls every 30 s. Chain: payment requested at T0+1 s (ready T0+61 s), executed at T0+62 s.
  // The gateway keeps answering with the genuine state of height 10 (time T0) for 61 s, then
  // answers with height 40 (after the execution). Its lag never passes 61 s (< 300 s default).
  let state = { height: 10, elapsed: T0 }, wall = chainMs(T0) + 500;
  const got = [], deliveredAt = {};
  const watch = createSecurityWatch({ verifiedState: async () => verified(state), accounts: ['5'], onEvent: async (e) => { got.push(e); deliveredAt[e.id] = wall; }, now: () => wall });
  await watch.poll(); await watch.settled();
  const staleFlags = [];
  for (let i = 0; i < 2; i++) { wall += 30_000; const r = await watch.poll(); await watch.settled(); staleFlags.push(r.stale); }
  assert.deepEqual(staleFlags, [true, true], 'state held back for longer than half the 60 s delay is stale');
  wall += 30_000;
  state = { height: 40, elapsed: T0 + 63n * S, balance: 50n * S - 12_500_000n - 2n * FEE, security: { ...BASE, next_id: '3' } };
  const r = await watch.poll(); await watch.settled();
  console.log('F-F delivered:', types(got), '| stale flags:', r.stale, '| status:', JSON.stringify(watch.status()));
  const blind = got.find((e) => e.type === 'watch_blind');
  assert.ok(blind?.urgent, 'the owner is told, urgently, that the watch cannot see the account');
  assert.ok(deliveredAt[blind.id] < chainMs(T0 + 61n * S), 'and told before the hidden payment could go through');
  assert.ok(got.some((e) => e.type === 'waiting_unseen') && got.some((e) => e.type === 'watch_restored'));
  await watch.stop();
});

test('F-F2 a stale state is only logged: the owner gets no event and the account is not counted as failed', async () => {
  const got = [], logs = [];
  const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 10, elapsed: T0 }), accounts: ['5'], onEvent: async (e) => got.push(e), now: () => chainMs(T0) + 86_400_000, log: (l, m) => logs.push(`${l} ${m}`) });
  const r = await watch.poll(); await watch.settled();
  console.log('F-F2 report:', JSON.stringify(r), '| events:', got.length, '| logs:', logs);
  assert.ok(got.length > 0 || r.failed.length > 0, 'a day-old state must reach the owner or count as a failure');
});

test('F-G a gateway that never answers stalls every account forever, with no log and no failure', async () => {
  const logs = [];
  const watch = createSecurityWatch({ verifiedState: () => new Promise(() => {}), accounts: ['5'], onEvent: async () => {}, batchTimeoutMs: 1000, log: (l, m) => logs.push(`${l} ${m}`) });
  const outcome = await Promise.race([watch.poll().then(() => 'finished'), new Promise((r) => setTimeout(() => r('still hanging after 1.5 s'), 1500))]);
  const stopped = await Promise.race([watch.stop().then(() => 'stopped'), new Promise((r) => setTimeout(() => r('stop() hangs too'), 500))]);
  console.log('F-G poll:', outcome, '| stop:', stopped, '| logs:', logs, '| status:', JSON.stringify(watch.status()));
  assert.equal(outcome, 'finished', 'a poll must time out and count the batch as failed');
});

test('F-H a store snapshot newer than the chain (re-genesis, restored store) silences the account while /health looks healthy', async () => {
  const store = memoryStore({ format: 1, snapshots: { 5: snap({ height: 1000, elapsed: T0 }) }, delivered: {}, outbox: [] });
  const got = [], logs = [];
  const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 50, elapsed: T0 + 100n * S, security: withPayment }), accounts: ['5'], onEvent: async (e) => got.push(e), store, now: () => chainMs(T0 + 100n * S), log: (l, m) => logs.push(`${l} ${m}`) });
  const r = await watch.poll(); await watch.poll(); await watch.settled();
  console.log('F-H report:', JSON.stringify(r), '| status:', JSON.stringify(watch.status()), '| logs:', logs);
  assert.ok(got.length > 0 || watch.details().failed_accounts.length > 0, 'a waiting payment on the live chain is never told and nothing reports a failure');
});

// ------------------------------------------------------------------ delivery
test('F-I one dead webhook delays every other account\'s urgent alert (head-of-line), with the default timings', async () => {
  // Real time: account 42's receiver accepts and never answers (default 10 s timeout, retries with backoff).
  const t0 = Date.now(); const deliveredAt = {}; let hanging = 0;
  const dead = webhookAdapter({ url: 'https://dead.example/hook', secret: 'x'.repeat(16), fetcher: (_u, o) => { hanging += 1; return new Promise((_, reject) => o.signal.addEventListener('abort', () => reject(o.signal.reason), { once: true })); } });
  const good = { deliver: async (e) => { deliveredAt[e.id] = Date.now() - t0; } };
  const targets = [{ id: 'feed', accounts: null, adapter: good }, { id: 'webhook-42', accounts: new Set(['42']), adapter: dead }];
  // Three events of account 42 left in the outbox (its receiver is down).
  const stuck = [1, 2, 3].map((n) => ({ id: `42:frozen:${n}`, account: '42', type: 'frozen', urgent: true, message: 'x' }));
  const store = memoryStore({ format: 1, snapshots: { 5: snap({ height: 10, elapsed: T0 }) }, delivered: {}, outbox: stuck });
  const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 11, elapsed: T0 + 5n * S, security: withPayment }), accounts: ['5'], targets, store, now: () => chainMs(T0 + 5n * S) });
  await watch.poll();
  await new Promise((r) => setTimeout(r, 50));
  console.log('F-I account 5 payment_waiting handed over after', deliveredAt['5:payment_waiting:2'], 'ms while the receiver of account 42 hangs (', hanging, 'request open)');
  assert.ok(deliveredAt['5:payment_waiting:2'] < 1000, 'account 5 is told at once, whatever the receiver of account 42 does');
  assert.equal(hanging, 1, 'the dead receiver is still on its first attempt');
  const stopped = await Promise.race([watch.stop().then(() => 'stopped'), new Promise((r) => setTimeout(() => r('hung'), 500))]);
  assert.equal(stopped, 'stopped', 'stop() aborts the hanging delivery');
});

test('F-I2 real time: the next poll is held up by retries to a hanging receiver', async () => {
  const hang = http.createServer(() => {}); // accepts, never answers
  await new Promise((r) => hang.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${hang.address().port}/hook`;
  try {
    const dead = webhookAdapter({ url, secret: 'x'.repeat(16), timeoutMs: 200, baseDelayMs: 50 });
    const targets = [{ id: 'w42', accounts: new Set(['42']), adapter: dead }, { id: 'feed', accounts: null, adapter: { deliver: async () => {} } }];
    const stuck = [1, 2, 3].map((n) => ({ id: `42:frozen:${n}`, account: '42', type: 'frozen', urgent: true, message: 'x' }));
    const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 10, elapsed: T0 }), accounts: ['5'], targets, store: memoryStore({ format: 1, snapshots: {}, delivered: {}, outbox: stuck }), now: () => chainMs(T0) });
    const t = Date.now(); await watch.poll(); const ms = Date.now() - t;
    console.log(`F-I2 one poll took ${ms} ms with timeoutMs=200 (x 50 = ${ms * 50 / 1000} s at the default 10 s timeout); outbox still ${watch.status().outbox}`);
    assert.ok(ms < 1000);
    await watch.stop();
  } finally { hang.closeAllConnections(); hang.close(); }
});

test('F-J the alert server answers any Host header (DNS rebinding reads alerts and the watched account list)', async () => {
  const feed = createFeed();
  await feed.push({ id: '5:payment_waiting:2', account: '5', type: 'payment_waiting', message: 'A payment of 12.5 s to account 42', urgent: true });
  const server = createAlertServer({ feed, accounts: ['5'], status: () => ({ last_heights: { 5: '11', 77: '11' } }) });
  const origin = new URL(await server.listen());
  try {
    const get = (p) => new Promise((resolve, reject) => http.get({ host: origin.hostname, port: origin.port, path: p, headers: { host: `attacker.example:${origin.port}`, origin: 'http://attacker.example' } }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); }).on('error', reject));
    const alerts = await get('/alerts?account=5'), health = await get('/health');
    console.log('F-J Host: attacker.example ->', alerts.status, alerts.body, '|', health.status, health.body);
    assert.notEqual(alerts.status, 200, 'a request for another host name must be refused');
  } finally { await server.close(); }
});

// ------------------------------------------------------------------ durability
test('F-K a lock left by a crashed run whose pid is now this process (container restart: pid 1 again) blocks start forever', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv-watch-lock-'));
  try {
    await writeFile(path.join(directory, 'watch.lock'), String(process.pid));
    const cfg = { gateway: 'https://wallet.example', trust: { app_version: '4', network_id: fixture.network_id, chain_id: 't' }, data_directory: directory, port: 19_500 + Math.floor(Math.random() * 400), subscriptions: [{ account: '5' }] };
    let error = null, running = null;
    try { running = await start(cfg, { verifiedState: async () => verified({ height: 10, elapsed: T0 }), log: () => {} }); } catch (e) { error = e; }
    await running?.close();
    console.log('F-K start():', error ? error.message : 'started');
    // An empty lock (crash between open(wx) and the pid write): Number('') is 0.
    await writeFile(path.join(directory, 'watch.lock'), '');
    let error0 = null; running = null;
    try { running = await start(cfg, { verifiedState: async () => verified({ height: 10, elapsed: T0 }), log: () => {} }); } catch (e) { error0 = e; }
    await running?.close();
    console.log('F-K empty lock -> start():', error0 ? error0.message : 'started');
    assert.equal(error, null, 'a lock holding our own pid is stale by definition');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('F-L a truncated store (power loss after rename without fsync) makes every poll crash forever', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv-watch-store-'));
  try {
    const file = path.join(directory, 'watch.json');
    await writeFile(file, '{"format":1,"snapshots":{"5":{"acc');
    const logs = [];
    const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 11, elapsed: T0, security: withPayment }), accounts: ['5'], onEvent: async () => {}, store: fileStore(file), now: () => chainMs(T0), log: (l, m, f) => logs.push(`${l} ${m} ${JSON.stringify(f)}`) });
    const results = [];
    for (let i = 0; i < 3; i++) results.push(await watch.poll().then(() => 'ok', (e) => `rejected: ${e.message}`));
    console.log('F-L polls:', results, '| status:', JSON.stringify(watch.status()));
    assert.equal(results[2], 'ok', 'the watch must recover (or fail loudly to the owner) rather than stay silent');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('F-M "the freeze has ended, payments work again" while a replacement still keeps the account frozen', () => {
  const NEW = fixture.root.operation.keys.map((k) => device(k.public_key, k.role));
  const root = { devices: NEW, policy: BASE.policy, ready_elapsed_micros: String(T0 + 70n * S), expires_elapsed_micros: String(T0 + 3670n * S) };
  // Freeze at T0 (until T0+120 s); recovery keys ask a replacement at T0+10 s (engine: frozen() = freeze || pending_root).
  const before = snap({ height: 10, elapsed: T0 + 20n * S, security: { ...BASE, version: '2', freezes: '1', frozen_until_elapsed_micros: String(T0 + 120n * S), pending_root: root } });
  const after = snap({ height: 40, elapsed: T0 + 130n * S, security: before.security });
  const events = diffSecurity(before, after);
  console.log('F-M events:', events.map((e) => `${e.type}: ${e.message}`));
  assert.ok(!events.some((e) => e.type === 'unfrozen'), 'Security::frozen is still true: a replacement waits');
});

test('F-N the signature covers x-watch-event and a delivery time: an old capture, or one under another header id, does not verify', async () => {
  const { signWebhook, verifyWebhookSignature } = await import('./security-watch-service.mjs');
  const id = '5:replacement_cancelled:1', secret = 'subscription-secret-0123456789';
  const body = JSON.stringify({ id, account: '5', type: 'replacement_cancelled', message: 'Your keys stay as they were.' });
  const yearOld = signWebhook(body, id, secret, Date.now() / 1000 - 365 * 86400);
  // Replayed a year later: refused.
  assert.equal(verifyWebhookSignature(body, { 'x-watch-signature': yearOld, 'x-watch-event': id }, secret), false);
  // Fresh, but with another event id in the header: refused.
  const fresh = signWebhook(body, id, secret, Date.now() / 1000);
  assert.equal(verifyWebhookSignature(body, { 'x-watch-signature': fresh, 'x-watch-event': '5:replacement_cancelled:2' }, secret), false);
  assert.equal(verifyWebhookSignature(body, { 'x-watch-signature': fresh, 'x-watch-event': id }, secret), true);
});
