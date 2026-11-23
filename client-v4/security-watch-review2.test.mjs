// Second adversarial pass over the rewritten watch. Each test asserts what the watch SHOULD do; a
// failure is a reproduced defect. Helpers as in security-watch-review1.test.mjs.
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import './time-sdk.js';
import { diffSecurity, snapshotOf } from './security-watch.mjs';
import { createSecurityWatch, memoryStore, webhookAdapter, verifyWebhookSignature } from './security-watch-service.mjs';
import { start, claim } from '../deploy/watch/start.mjs';

const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const GENESIS = '1794260994671000', FEE = 1000n, S = 1_000_000n;
const key = Object.fromEntries(fixture.secure.payload.keys.map((k) => [k.public_key.slice(0, 4), k.public_key]));
const device = (publicKey, role) => ({ public_key: publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const DEVICES = fixture.secure.payload.keys.map((k) => device(k.public_key, k.role));
const NEW = fixture.root.operation.keys.map((k) => device(k.public_key, k.role));
const BASE = { ...fixture.allowance.security, pending_limit: null, account: '5' };
const T0 = 2_407_000_000n;
function verified({ height, elapsed, balance = 50n * S, nonce = '3', epoch = '1', devices = DEVICES, security = BASE, others = [], genesis = GENESIS }) {
  const accounts = [{ id: '5', name: 'alice', public_key: key['70df'], balance: String(balance), nonce, auth_epoch: epoch, devices, delegations: [], unbonding: [] },
    ...others.map((id) => ({ id, name: `a${id}`, public_key: key['70df'], balance: String(50n * S), nonce: '0', auth_epoch: '1', devices: DEVICES, delegations: [], unbonding: [] }))];
  const rows = security ? [security, ...others.map((id) => ({ ...BASE, account: id }))] : [];
  return { verified: true, height: String(height), state: { network_id: fixture.network_id, height: String(height), time_micros: (BigInt(genesis) + BigInt(elapsed)).toString(), genesis: { genesis_time_micros: genesis }, accounts, security: rows, config: {} } };
}
const snap = (o) => snapshotOf(verified(o), '5');
const types = (events) => events.map((e) => e.type);
const payment = { id: '2', to: '42', amount: String(12_500_000n), ready_elapsed_micros: String(T0 + 60n * S) };
const withPayment = { ...BASE, pending_payments: [payment], next_id: '3' };
const chainMs = (elapsed) => Number((BigInt(GENESIS) + elapsed) / 1000n);
const elapsedAt = (ms) => BigInt(ms) * 1000n - BigInt(GENESIS);

// ------------------------------------------------------------------ N1 watchdog flapping
test('N1 honest gateway, default poll 30 s, delay 60 s: the watch spams watch_blind / watch_restored every cycle', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: chainMs(T0) });
  const got = [];
  try {
    let height = 10;
    // A fresh, honest gateway: the newest block is 2 s old when asked.
    const vs = async () => verified({ height: ++height, elapsed: elapsedAt(Date.now() - 2000) });
    const watch = createSecurityWatch({ verifiedState: vs, accounts: ['5'], onEvent: async (e) => got.push(e), now: () => Date.now() });
    watch.start(30_000);
    for (let s = 0; s < 300; s++) { mock.timers.tick(1000); for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); }
    mock.timers.reset();
    await watch.stop();
  } finally { mock.timers.reset(); }
  const blind = got.filter((e) => e.type === 'watch_blind'), restored = got.filter((e) => e.type === 'watch_restored');
  console.log(`N1 in 5 minutes: ${blind.length} urgent watch_blind, ${restored.length} watch_restored; first: ${blind[0]?.message}`);
  assert.equal(blind.length, 0, 'nothing was hidden: the gateway answered fresh state every 30 s');
});

// ------------------------------------------------------------------ N2 counter accounting
test('N2 a root payment hides behind a replacement that lapsed: only a non-urgent "was cancelled"', () => {
  const W = 3600n * S, ready = T0 + 60n * S;
  const R = { devices: NEW, policy: BASE.policy, ready_elapsed_micros: String(ready), expires_elapsed_micros: String(ready + W) };
  const before = snap({ height: 10, elapsed: T0 + 70n * S, security: { ...BASE, version: '2', pending_root: R } });
  // R lapses (settle drops it, no version move). Then ROOT {pay 49 s} with spend + 1 recovery key: version 2 -> 3.
  const after = snap({ height: 900, elapsed: ready + W + 100n * S, balance: 50n * S - 49n * S - FEE, security: { ...BASE, version: '3' } });
  const events = diffSecurity(before, after);
  console.log('N2 events:', events.map((e) => `${e.type} urgent=${e.urgent}: ${e.message}`));
  assert.ok(events.some((e) => e.urgent), '49 s left the account by a root operation');
});

// ------------------------------------------------------------------ N3 target ids follow the config order
test('N3 queues are keyed "webhook-<index>": reordering subscriptions sends account 5\'s alert to account 42\'s webhook, signed with 42\'s secret', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv2-order-'));
  const A = { url: 'https://hooks.alice.example/a', secret: 'alice-secret-0123456789' }, B = { url: 'https://hooks.bob.example/b', secret: 'bob-secret-0123456789xx' };
  const trust = { app_version: '4', network_id: fixture.network_id, chain_id: 't' };
  const vs = async (sel) => verified({ height: 11, elapsed: T0 + 5n * S, security: withPayment, others: sel.ids.filter((id) => id !== '5') });
  const now = () => chainMs(T0 + 5n * S) + 500;
  const posted = [];
  try {
    // Run 1: alice's receiver hangs; her payment_waiting stays queued under "webhook-0".
    const hang = (_u, o) => new Promise((_, reject) => o.signal.addEventListener('abort', () => reject(o.signal.reason), { once: true }));
    let running = await start({ gateway: 'https://wallet.example', trust, data_directory: directory, port: 19_100 + Math.floor(Math.random() * 300), subscriptions: [{ account: '5', webhook: A.url, secret: A.secret }, { account: '42' }] }, { verifiedState: vs, webhookFetcher: hang, now, log: () => {} });
    await running.watch.poll(); await new Promise((r) => setTimeout(r, 50));
    await running.close();
    // Run 2: the operator gives bob a webhook and lists him first.
    const record = async (url, o) => { posted.push({ url, body: o.body, headers: o.headers }); return new Response(null, { status: 204 }); };
    running = await start({ gateway: 'https://wallet.example', trust, data_directory: directory, port: 19_500 + Math.floor(Math.random() * 300), subscriptions: [{ account: '42', webhook: B.url, secret: B.secret }, { account: '5', webhook: A.url, secret: A.secret }] }, { verifiedState: vs, webhookFetcher: record, now, log: () => {} });
    await running.watch.poll(); await running.watch.settled();
    await running.close();
  } finally { await rm(directory, { recursive: true, force: true }); }
  for (const p of posted) console.log('N3 POST', p.url, JSON.parse(p.body).id, '| valid under bob\'s secret:', verifyWebhookSignature(p.body, p.headers, B.secret));
  assert.ok(!posted.some((p) => p.url === B.url && JSON.parse(p.body).account === '5'), "alice's alert must not go to bob's webhook");
  assert.ok(posted.some((p) => p.url === A.url && JSON.parse(p.body).id === '5:payment_waiting:2'), 'alice must still get her alert');
});

// ------------------------------------------------------------------ N4 dead letters
test('N4 a receiver whose clock is 6 min ahead answers 401 to every event: each urgent alert is dead-lettered after one try, the owner is never told', async () => {
  const secret = 'subscription-secret-0123456789';
  const receiver = http.createServer((req, res) => {
    const chunks = []; req.on('data', (c) => chunks.push(c));
    req.on('end', () => { const ok = verifyWebhookSignature(Buffer.concat(chunks), req.headers, secret, { now: () => Date.now() + 360_000 }); res.writeHead(ok ? 204 : 401); res.end(); });
  });
  await new Promise((r) => receiver.listen(0, '127.0.0.1', r));
  let tries = 0;
  try {
    const hook = webhookAdapter({ url: `http://127.0.0.1:${receiver.address().port}/h`, secret, fetcher: (u, o) => { tries += 1; return fetch(u, o); } });
    const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 11, elapsed: T0 + 5n * S, security: withPayment }), accounts: ['5'], targets: [{ id: 'w', accounts: null, adapter: hook }], now: () => chainMs(T0 + 5n * S) + 500 });
    await watch.poll(); await watch.settled(); await watch.poll(); await watch.settled();
    const d = watch.details();
    console.log(`N4 tries: ${tries}; queued: ${d.queues.w}; dead letters: ${d.dead.w.map((x) => `${x.event.id} (${x.error})`)}`);
    await watch.stop();
    assert.equal(d.dead.w.length, 0, 'a 4xx from a receiver that cannot check the signature must not drop an urgent alert for good');
  } finally { receiver.close(); }
});

// ------------------------------------------------------------------ N5 the breaker turns a short outage into a long silence
test('N5 after a 10-minute receiver outage, a new urgent alert waits for the breaker (up to 15 min) though the receiver is back', async () => {
  let wall = chainMs(T0) + 500, up = false, height = 10;
  const deliveredAt = {};
  const hook = webhookAdapter({ url: 'https://hook.example/x', secret: 'x'.repeat(16), sleep: async () => {}, now: () => wall, fetcher: async (_u, o) => {
    if (!up) return new Response(null, { status: 503 });
    deliveredAt[JSON.parse(o.body).id] ??= wall; return new Response(null, { status: 204 });
  } });
  let security = withPayment, frozenAt = null;
  const watch = createSecurityWatch({ verifiedState: async () => verified({ height: ++height, elapsed: elapsedAt(wall - 1000), security }), accounts: ['5'], targets: [{ id: 'w', accounts: null, adapter: hook }], now: () => wall });
  for (let t = 0; t <= 40 * 60_000; t += 30_000) {
    if (t === 10 * 60_000) { up = true; security = { ...BASE, next_id: '3', freezes: '1', frozen_until_elapsed_micros: String(elapsedAt(wall) + 3600n * S) }; frozenAt = wall; }
    await watch.poll(); await watch.settled();
    if (deliveredAt['5:frozen:1']) break;
    wall += 30_000;
  }
  await watch.stop();
  const delay = deliveredAt['5:frozen:1'] ? (deliveredAt['5:frozen:1'] - frozenAt) / 1000 : 'never';
  console.log(`N5 the urgent "frozen" alert reached the (healthy) receiver ${delay} s after the watch saw it`);
  assert.ok(typeof delay === 'number' && delay <= 60, 'a receiver that is back must get a new urgent alert within a poll or two');
});

// ------------------------------------------------------------------ N6 F-G with the shipped default
test('N6 F-G with the default batch timeout (30 s): a poll against a silent gateway ends and counts as failed', { timeout: 40_000 }, async () => {
  const watch = createSecurityWatch({ verifiedState: () => new Promise(() => {}), accounts: ['5'], onEvent: async () => {} });
  const t = Date.now(); const r = await watch.poll();
  console.log(`N6 poll ended after ${Math.round((Date.now() - t) / 1000)} s, failed: ${r.failed}`);
  await watch.stop();
  assert.deepEqual(r.failed, ['5']);
});

// ------------------------------------------------------------------ N7 the lock
test('N7 lock: empty and own-pid locks are taken over; a dead run whose pid now belongs to an unrelated process still blocks', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv2-lock-'));
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20000)'], { stdio: 'ignore' });
  try {
    await writeFile(path.join(directory, 'watch.lock'), '');
    const r1 = await claim(directory); await r1();
    await writeFile(path.join(directory, 'watch.lock'), JSON.stringify({ pid: process.pid, run: 'an-earlier-run' }));
    const r2 = await claim(directory); await r2();
    // After a reboot the dead watch's pid belongs to some other program.
    await writeFile(path.join(directory, 'watch.lock'), JSON.stringify({ pid: child.pid, run: 'an-earlier-run' }));
    let error = null; try { const r3 = await claim(directory); await r3(); } catch (e) { error = e.message; }
    console.log('N7 empty: taken | own pid, other run: taken | unrelated live pid:', error ?? 'taken');
    assert.equal(error, null, 'a pid alone does not prove the lock holder is a watch');
  } finally { child.kill(); await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
});

// ------------------------------------------------------------------ N8 migration from format 1
test('N8 a format-1 store has no network: the first chain seen is adopted even if its genesis differs from every stored snapshot', async () => {
  const OLD_GENESIS = String(BigInt(GENESIS) - 10n ** 12n);
  const old = snapshotOf(verified({ height: 10, elapsed: T0, genesis: OLD_GENESIS, security: withPayment }), '5');
  const got = [];
  const watch = createSecurityWatch({ verifiedState: async () => verified({ height: 20, elapsed: T0 + 5n * S }), accounts: ['5'], onEvent: async (e) => got.push(e), store: memoryStore({ format: 1, snapshots: { 5: old }, delivered: {}, outbox: [] }), now: () => chainMs(T0 + 5n * S) + 500 });
  const r = await watch.poll(); await watch.settled(); await watch.stop();
  console.log('N8 failed:', r.failed, '| events from comparing two networks:', got.map((e) => `${e.type}: ${e.message.slice(0, 80)}`));
  assert.ok(r.failed.length > 0, 'a snapshot of another genesis must not be compared');
});
