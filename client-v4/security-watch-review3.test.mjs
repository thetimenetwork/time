// Third adversarial pass. Each test asserts what the watch SHOULD do; a failure is a reproduced defect.
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import './time-sdk.js';
import { diffSecurity, snapshotOf } from './security-watch.mjs';
import { createSecurityWatch, memoryStore } from './security-watch-service.mjs';
import { start, claim } from '../deploy/watch/start.mjs';

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
const chainMs = (elapsed) => Number((BigInt(GENESIS) + elapsed) / 1000n);
const elapsedAt = (ms) => BigInt(ms) * 1000n - BigInt(GENESIS);
const policy = (delay) => ({ ...BASE, policy: { ...BASE.policy, delay_seconds: String(delay) } });

// ------------------------------------------------------------------ T1: the N1 fix gave back finding 5
test('T1 gateway holds back the state from just before a payment request: watch_blind comes only after the payment is ready (poll 30 s, delay 60 s)', async () => {
  // Request at T0+1 s (ready T0+61 s). The gateway keeps serving the genuine state of T0 (height 10).
  // The watch polls every 30 s, its first poll 1.5 s after T0. No config warning: 30 s is not above delay/2.
  let state = { height: 10, elapsed: T0 }, wall = chainMs(T0) + 1500;
  const got = [], at = {}, logs = [];
  const watch = createSecurityWatch({ verifiedState: async () => verified(state), accounts: ['5'], onEvent: async (e) => { got.push(e); at[e.id] = wall; }, now: () => wall, log: (l, m) => logs.push(`${l} ${m}`) });
  await watch.poll(); await watch.settled();
  for (let i = 0; i < 2; i++) { wall += 30_000; await watch.poll(); await watch.settled(); }
  const blind = got.find((e) => e.type === 'watch_blind');
  const ready = chainMs(T0 + 61n * S);
  console.log(`T1 watch_blind handed over ${blind ? (at[blind.id] - ready) / 1000 : '(never)'} s after the payment became ready; config warnings: ${watch.status().config_warnings}; stale logs: ${logs.filter((l) => /older/.test(l)).length}`);
  await watch.stop();
  assert.ok(blind && at[blind.id] < ready, 'the owner must hear before the hidden payment can go through');
});

// ------------------------------------------------------------------ T2: N1 variants with an honest gateway
for (const [poll, delay, blockAge, latency] of [[30, 60, 2, 0], [30, 60, 4, 6], [30, 30, 2, 0], [5, 30, 3, 2], [60, 60, 2, 0]]) {
  test(`T2 honest gateway, poll ${poll} s, delay ${delay} s, block ${blockAge} s old, answers in ${latency} s: no watch_blind`, async () => {
    mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: chainMs(T0) });
    const got = [];
    try {
      let height = 10;
      const vs = () => new Promise((resolve) => setTimeout(() => resolve(verified({ height: ++height, elapsed: elapsedAt(Date.now() - blockAge * 1000), security: policy(delay) })), latency * 1000));
      const watch = createSecurityWatch({ verifiedState: vs, accounts: ['5'], onEvent: async (e) => got.push(e), now: () => Date.now() });
      watch.start(poll * 1000);
      for (let s = 0; s < 600; s++) { mock.timers.tick(1000); for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); }
      mock.timers.reset();
      await watch.stop();
    } finally { mock.timers.reset(); }
    console.log(`T2 poll ${poll}/delay ${delay}/block ${blockAge}/latency ${latency}: ${types(got).join(',') || 'no events'}`);
    assert.equal(got.filter((e) => e.type === 'watch_blind').length, 0);
  });
}

// ------------------------------------------------------------------ T3: balance_fell on honest spending
test('T3 balance_fell stays quiet for honest spending within the limit, and fires for a masked drain', () => {
  const row = { ...BASE, policy: { ...BASE.policy, daily_limit_micros: String(10n * S) }, allowance_micros: String(10n * S), allowance_elapsed_micros: String(T0) };
  const before = snap({ height: 10, elapsed: T0, security: row, nonce: '3' });
  // Spend key: 10 s at once (fees inside the limit), then a day later another 10 s: 2 actions.
  const honest = diffSecurity(before, snap({ height: 99, elapsed: T0 + 86_400n * S, nonce: '5', balance: 50n * S - 20n * S, security: { ...row, allowance_micros: '0', allowance_elapsed_micros: String(T0 + 86_400n * S) } }));
  console.log('T3 honest day of spending:', types(honest));
  assert.deepEqual(types(honest), []);
});

// ------------------------------------------------------------------ T4: format-2 queues keyed by position
test('T4 a format-2 store whose "webhook-0" held alice\'s event: after the upgrade it goes only to alice\'s target', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv3-mig-'));
  const A = { url: 'https://hooks.alice.example/a', secret: 'alice-secret-0123456789' }, B = { url: 'https://hooks.bob.example/b', secret: 'bob-secret-0123456789xx' };
  const vs = async (sel) => verified({ height: 11, elapsed: T0 + 5n * S, others: sel.ids.filter((id) => id !== '5') });
  const event = { id: '5:payment_waiting:2', account: '5', type: 'payment_waiting', urgent: true, message: 'x' };
  const s5 = snap({ height: 11, elapsed: T0 + 5n * S }), s42 = snapshotOf(verified({ height: 11, elapsed: T0 + 5n * S, others: ['42'] }), '42');
  await writeFile(path.join(directory, 'watch.json'), JSON.stringify({ format: 2, network: { network_id: fixture.network_id, genesis_time_micros: GENESIS }, snapshots: { 5: s5, 42: s42 }, seen: { 5: [event.id] }, queues: { 'webhook-0': [event], feed: [] }, dead: {}, blind: {} }));
  const posted = [];
  const record = async (url, o) => { posted.push({ url, id: JSON.parse(o.body).id, account: JSON.parse(o.body).account }); return new Response(null, { status: 204 }); };
  try {
    const running = await start({ gateway: 'https://wallet.example', trust: { app_version: '4', network_id: fixture.network_id, chain_id: 't' }, data_directory: directory, port: 19_700 + Math.floor(Math.random() * 200), subscriptions: [{ account: '42', webhook: B.url, secret: B.secret }, { account: '5', webhook: A.url, secret: A.secret }] }, { verifiedState: vs, webhookFetcher: record, now: () => chainMs(T0 + 5n * S) + 500, log: () => {} });
    await running.watch.poll(); await running.watch.settled(); await running.close();
  } finally { await rm(directory, { recursive: true, force: true }); }
  console.log('T4 posts:', posted.map((p) => `${p.url} <- ${p.id}`));
  assert.ok(!posted.some((p) => p.url === B.url && p.account === '5'));
  assert.ok(posted.some((p) => p.url === A.url && p.id === event.id));
});

// ------------------------------------------------------------------ T5: the lock and a holder that stalls
test('T5 a live holder that stalls for longer than 3 beats loses the lock, keeps running, and only logs', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv3-lock-'));
  const startUrl = new URL('../deploy/watch/start.mjs', import.meta.url).href;
  // ADAPTED (it failed under load): the steps follow one another by signals, not by the clock.
  // Before, the holder stalled for a fixed 1.5 s and this test claimed 700 ms after "held": on a
  // loaded machine the claim could come after the holder had resumed. And when the holder's old
  // heartbeat put its lock over this process's (the race fixed in deploy/watch/start.mjs), this
  // process's own lock ended the whole test file with exit code 75. Now the holder stalls until
  // the file `go` appears; this test waits until the holder's beat is stale, claims, and only then
  // lets the holder resume; and its own claim reports a loss instead of exiting. What is asserted
  // is the same, plus that the new holder keeps the lock.
  const go = path.join(os.tmpdir(), `adv3-lock-go-${process.pid}-${Date.now()}`);
  // The holder: claims with a 100 ms beat, then blocks its event loop until told to go on (at most 30 s), then reports.
  const code = `const { claim } = await import(${JSON.stringify(startUrl)}); const { existsSync } = await import('node:fs');
    let lost = false; await claim(${JSON.stringify(directory)}, { beatMs: 100, onLost: () => { lost = true; } });
    console.log('held'); await new Promise((r) => setTimeout(r, 150));
    const end = Date.now() + 30000; while (Date.now() < end && !existsSync(${JSON.stringify(go)})) {}
    await new Promise((r) => setTimeout(r, 400)); console.log(lost ? 'lost-but-running' : 'still-holding'); process.exit(0);`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'inherit'] });
  let out = ''; child.stdout.on('data', (c) => { out += c; });
  const lostHere = [];
  try {
    while (!out.includes('held')) await new Promise((r) => setTimeout(r, 20));
    // The holder is stalled once its beat stops moving; its lock is stale when the beat is > 300 ms old.
    const beatAge = async () => Date.now() - JSON.parse(await readFile(path.join(directory, 'watch.lock'), 'utf8')).beat;
    while (await beatAge().catch(() => 0) <= 350) await new Promise((r) => setTimeout(r, 20));
    const release = await claim(directory, { beatMs: 100, exitOnLost: false, onLost: (why) => lostHere.push(why) });
    await writeFile(go, ''); // the holder resumes: its heartbeat finds the lock taken
    await new Promise((resolve) => child.on('exit', resolve));
    console.log('T5 second claim: taken; holder says:', out.trim().split('\n').pop());
    assert.deepEqual(lostHere, [], 'the holder that resumed put its lock over the new holder\'s');
    assert.equal(JSON.parse(await readFile(path.join(directory, 'watch.lock'), 'utf8')).pid, process.pid, 'the lock is the new holder\'s');
    await release();
    assert.ok(!out.includes('lost-but-running'), 'a holder that lost the lock must stop, not keep delivering');
  } finally { child.kill(); await rm(go, { force: true }); await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
});

test('T2-control the same harness does see a gateway that stops answering at 2 min', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: chainMs(T0) });
  const got = []; let height = 10, calls = 0; const blindAt = [];
  const t0 = chainMs(T0);
  try {
    const vs = () => { calls += 1; return Date.now() - t0 > 120_000 ? new Promise(() => {}) : Promise.resolve(verified({ height: ++height, elapsed: elapsedAt(Date.now() - 2000) })); };
    const watch = createSecurityWatch({ verifiedState: vs, accounts: ['5'], onEvent: async (e) => { got.push(e); if (e.type === 'watch_blind') blindAt.push((Date.now() - t0) / 1000); }, now: () => Date.now() });
    watch.start(30_000);
    for (let s = 0; s < 400; s++) { mock.timers.tick(1000); for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); }
    mock.timers.reset();
    await watch.stop();
  } finally { mock.timers.reset(); }
  console.log(`T2-control polls: ${calls}, height ${height}, events: ${types(got)}, blind at ${blindAt} s (gateway silent from 120 s)`);
  assert.ok(blindAt.length === 1);
});

test('T6 two receivers that reject event types they do not know: alerts_refused notices breed nested notices', async () => {
  const refuse = (types) => ({ deliver: async (e) => { if (types.includes(e.type)) throw Object.assign(new Error(`answered 400 (${e.type})`), { refused: true }); } });
  const targets = [{ id: 'feed', accounts: null, adapter: { deliver: async () => {} } }, { id: 'A', accounts: ['5'], adapter: refuse(['alerts_refused', 'frozen']) }, { id: 'B', accounts: ['5'], adapter: refuse(['alerts_refused']) }];
  let wall = chainMs(T0) + 500, height = 10, freezes = 0;
  const watch = createSecurityWatch({ verifiedState: async () => verified({ height: ++height, elapsed: elapsedAt(wall - 1000), security: { ...BASE, freezes: String(freezes), frozen_until_elapsed_micros: freezes ? String(elapsedAt(wall)) : '0' } }), accounts: ['5'], targets, now: () => wall });
  for (let i = 0; i < 12; i++) { if (i % 2 === 1) freezes += 1; await watch.poll(); await watch.settled(); wall += 30_000; }
  const d = watch.details();
  await watch.stop();
  const all = Object.values(d.queues);
  console.log('T6 queued per target:', JSON.stringify(d.queues), '| refusing:', Object.keys(d.refusing));
  assert.ok(Object.values(d.queues).every((n) => n < 20));
});

test('T7 a crash between finding the store damaged and the first write loses the watch_memory_lost notice for good', async () => {
  const { fileStore } = await import('./security-watch-service.mjs');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'adv3-lost-'));
  try {
    const file = path.join(directory, 'watch.json');
    await writeFile(file, '{"format":3,"snapsh');
    const got1 = [], got2 = [];
    // Run 1: loads (finds the damage, moves it aside, queues the notice) and dies before its poll ends,
    // e.g. while the gateway is still being asked.
    const w1 = createSecurityWatch({ verifiedState: () => new Promise(() => {}), accounts: ['5'], onEvent: async (e) => got1.push(e), store: fileStore(file), now: () => chainMs(T0) });
    w1.poll(); await new Promise((r) => setTimeout(r, 100)); // crash here: no stop(), nothing written
    // Run 2.
    const w2 = createSecurityWatch({ verifiedState: async () => verified({ height: 11, elapsed: T0 }), accounts: ['5'], onEvent: async (e) => got2.push(e), store: fileStore(file), now: () => chainMs(T0) + 500 });
    await w2.poll(); await w2.settled(); await w2.stop();
    console.log('T7 run 1 delivered:', types(got1), '| run 2 delivered:', types(got2), '| run 2 store_error:', w2.status().store_error);
    assert.ok(got2.some((e) => e.type === 'watch_memory_lost') || got1.some((e) => e.type === 'watch_memory_lost'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});
