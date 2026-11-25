// The findings of the audit of 24 November 2026 against the alert service (alert-push.mjs), each as the attack its
// reviewers ran; each test fails on the service before the fix (merge cef954a) and passes after:
// - D-2 / K-2: a thief's accounts woken in the same block before the owner took every place and the owner's push was
//   dropped. Now no push is dropped for want of a place: it waits, accounts are served in turn, and one account holds
//   at most two places;
// - K-3: the login key alone removed every browser of the account in silence, and a ninth browser pushed the oldest
//   out. Now every removal that its browser's owner may not have asked for wakes the browsers concerned first, a
//   ninth is refused, and a browser can ask whether it is still subscribed (POST /alerts/v1/status);
// - D-5: the table of open challenges was filled from one /48 and honest browsers were refused. Now a challenge keeps
//   nothing in the service until it is used;
// - D-6: the public health answer told whether an account has alerts on. Now its counts go to the machine itself only;
// - D-7: every subscription wrote the whole list, and saves queued without bound. Now writes are coalesced.
// The service follows every block in order, however far behind (section 5 of the request): alert-push.test.mjs,
// "following the chain".
import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import { IndexerError } from './indexer.mjs';
import * as A from './alert-push.mjs';

const SDK = globalThis.TimeSDK;
const NETWORK = 'c6'.repeat(32), CHAIN = 'time-devnet-v4-alerts-test', ORIGIN = 'https://wallet.example';
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function newBrowser() { const ecdh = createECDH('prime256v1'); ecdh.generateKeys(); return { ecdh, auth: randomBytes(16) }; }
const subscriptionOf = (browser, endpoint) => ({ endpoint, expirationTime: null, keys: { p256dh: A.b64url(browser.ecdh.getPublicKey()), auth: A.b64url(browser.auth) } });
/// A subscription as the list keeps it, for accounts that subscribe without going through the routes.
const kept = (endpoint) => A.checkSubscription(subscriptionOf(newBrowser(), endpoint));
const ed = () => { const { privateKey, publicKey } = generateKeyPairSync('ed25519'); return { privateKey, publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex') }; };
const KEYS = { signin: ed(), spend: ed(), sheet: ed() };
const device = (k, role) => ({ public_key: k.publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const ACCOUNT = { id: '5', name: 'alice', balance: '1000000', nonce: '3', auth_epoch: '2', recovery_policy: null, devices: [device(KEYS.signin, 'signin'), device(KEYS.spend, 'spend'), device(KEYS.sheet, 'recover')].sort((x, y) => (x.public_key < y.public_key ? -1 : 1)) };
const ROW = { account: '5', version: '1', policy: { threshold: '1', daily_limit_micros: '1000', delay_seconds: '60', freeze_seconds: '60' }, allowance_micros: '0', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
const chainState = async (selection) => ({ verified: true, state: { network_id: NETWORK, height: '10', time_micros: '1000000000', genesis: { genesis_time_micros: '0' }, config: {}, accounts: [ACCOUNT], recovery_cases: [], ...(selection.include_security ? { security: [ROW] } : {}) } });
const fakeRpc = (chain) => async (method, parameters = {}) => {
  if (method === '/status') return { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(chain.tip) } };
  if (method === '/block') return { block: { header: { height: parameters.height, chain_id: CHAIN }, data: { txs: (chain.blocks[parameters.height] ?? []).map((raw) => Buffer.from(raw).toString('base64')) } } };
  throw new IndexerError('RPC_REFUSED', 'not here');
};
/// A freeze sent by `from`: it wakes its sender, and costs nothing on an empty account.
const freeze = (from) => SDK.concat(SDK.buildAction({ networkId: NETWORK, kind: 72, from, nonce: '0', authEpoch: '0', publicKey: KEYS.spend.publicKey, payload: { freezes: '0', version: '1', expires_elapsed_micros: '99' } }), new Uint8Array(64));
/// A push service that answers after `ms`, or never (it is then given up by the push's time limit).
const answering = (record, ms) => async (url, init) => { record.push({ url, at: Date.now() }); if (ms === null) return new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason))); await pause(ms); return new Response(null, { status: 201 }); };
const OWNER = 'https://fcm.googleapis.com/fcm/send/OWNER';

async function service({ subscriptions, chain = { tip: 3, blocks: {} }, ...options } = {}) {
  return A.createAlertService({ rpc: fakeRpc(chain), trust: { network_id: NETWORK, chain_id: CHAIN }, verifiedState: chainState, origin: ORIGIN, subscriptions: subscriptions ?? await A.openSubscriptions({ file: null, networkId: NETWORK }),
    // No test reaches a real push service: without a fetcher of its own, a test's push fails here.
    vapid: A.checkVapid({ version: 1, ...A.newVapidKeys() }), subject: ORIGIN, port: 0, autoStart: false, verify: async () => {}, fetcher: async () => { throw new Error('no network in tests'); }, ...options });
}
async function call(s, method, route, body, headers = {}) {
  const response = await fetch(s.url + route, { method, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, body: json, text };
}
/// What the wallet page does: a challenge bound to the request, signed with the account's sign-in key.
async function prove(s, request) {
  const challenge = (await call(s, 'POST', '/alerts/v1/challenge', request)).body;
  const message = SDK.loginMessage(challenge, { account: ACCOUNT, publicKey: KEYS.signin.publicKey });
  return { message, signature: sign(null, SDK.loginBytes(message), KEYS.signin.privateKey).toString('hex') };
}
async function subscribe(s, endpoint) {
  const subscription = subscriptionOf(newBrowser(), endpoint);
  return call(s, 'POST', '/alerts/v1/subscribe', { proof: await prove(s, { action: 'subscribe', subscription }), subscription });
}
/// A request with headers fetch does not let a caller set (Host, X-Forwarded-For).
function raw(s, { method = 'GET', route, headers = {}, body, agent }) {
  const u = new URL(s.url), text = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const request = http.request({ host: u.hostname, port: u.port, path: route, method, agent, headers: { ...(text ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) } : {}), ...headers } }, (response) => {
      const chunks = []; response.on('data', (c) => chunks.push(c)); response.on('end', () => resolve({ status: response.statusCode, text: Buffer.concat(chunks).toString() }));
    });
    request.on('error', reject); request.end(text);
  });
}

// ------------------------------------------------------------------ D-2 / K-2
test('D-2/K-2: eight accounts of a thief, eight browsers each, woken in the same block before the owner, do not crowd the owner\'s push out', async () => {
  const subscriptions = await A.openSubscriptions({ file: null, networkId: NETWORK });
  for (let a = 0; a < 8; a++) for (let i = 0; i < 8; i++) await subscriptions.add(String(100 + a), kept(`https://fcm.googleapis.com/fcm/send/thief-${a}-${i}`));
  await subscriptions.add('14', kept(OWNER));
  const started = [];
  const s = await service({ subscriptions, chain: { tip: 3, blocks: { 4: [...Array.from({ length: 8 }, (_, a) => freeze(String(100 + a))), freeze('14')] } }, fetcher: answering(started, 50) });
  try {
    await (await s.readBlock(4)).pushes;
    assert.equal(started.length, 65, 'every push was sent: none was dropped');
    assert.ok(started.some((p) => p.url === OWNER), 'the owner\'s phone was pushed');
    assert.deepEqual([s.stats.pushes_sent, s.stats.pushes_abandoned], [65, 0]);
    // In turn: the first nine pushes started are one of each account, the owner's among them.
    const accountOf = (url) => (url === OWNER ? 'owner' : url.split('-')[1]);
    assert.equal(new Set(started.slice(0, 9).map((p) => accountOf(p.url))).size, 9);
  } finally { await s.close(); }
});

test('D-2/K-2: one account holds at most two places, also with pushes of an earlier block still under way; a newly woken account goes first', async () => {
  const subscriptions = await A.openSubscriptions({ file: null, networkId: NETWORK });
  for (let i = 0; i < 8; i++) await subscriptions.add('100', kept(`https://fcm.googleapis.com/fcm/send/slow-${i}`));
  await subscriptions.add('14', kept(OWNER));
  const started = [];
  // Two places in all: the thief's account takes both with its first block; its six other browsers wait.
  const s = await service({ subscriptions, chain: { tip: 3, blocks: { 4: [freeze('100')], 5: [freeze('100'), freeze('14')] } }, fetcher: answering(started, 400), maxInFlight: 2 });
  try {
    const first = (await s.readBlock(4)).pushes;
    await pause(20);
    assert.equal(started.length, 2);
    // The next block wakes the thief's account again and the owner: the owner's push starts at the first free place,
    // before the thief's third.
    const second = (await s.readBlock(5)).pushes;
    await Promise.all([first, second]);
    assert.equal(started[2].url, OWNER, started.map((p) => p.url.split('/').at(-1)).join(' '));
    // Eight for the first block; for the second, the owner's and the two browsers whose first push was under way (the
    // six still waiting were not put in line twice).
    assert.equal(started.length, 11);
  } finally { await s.close(); }
});

test('D-2/K-2: a stranger who leads every block with wake actions of forty accounts of his own, eight slow browsers each, delays the owner\'s first push by at most one push\'s time limit', async () => {
  // The bound: the first push of an account woken in a block starts within T x (1 + ceil(A / 64)) of the block being
  // read, where T is a push's time limit and A the accounts whose first push waits before it (only those of the same
  // block can: earlier blocks' accounts already had theirs). Here A <= 40, so 2T; the stranger's 320 browsers time out.
  const T = 200, subscriptions = await A.openSubscriptions({ file: null, networkId: NETWORK });
  const stranger = Array.from({ length: 40 }, (_, a) => String(200 + a));
  for (const a of stranger) for (let i = 0; i < 8; i++) await subscriptions.add(a, kept(`https://fcm.googleapis.com/fcm/send/s${a}-${i}`));
  await subscriptions.add('14', kept(OWNER));
  const blocks = {};
  for (let h = 4; h <= 9; h++) blocks[h] = [...stranger.map(freeze), ...(h === 6 ? [freeze('14')] : [])];
  const started = [];
  const s = await service({ subscriptions, chain: { tip: 3, blocks }, fetcher: answering(started, null), pushTimeoutMs: T });
  try {
    const all = [];
    let read6 = 0;
    for (let h = 4; h <= 9; h++) { const result = await s.readBlock(h); if (h === 6) read6 = Date.now(); all.push(result.pushes); await pause(T / 2); }
    const owner = started.find((p) => p.url === OWNER);
    assert.ok(owner, 'the owner\'s push started');
    // (300 ms more for the timers of a busy machine.)
    assert.ok(owner.at - read6 <= 2 * T + 300, `the owner's first push started ${owner.at - read6} ms after its block was read; the bound is ${2 * T} ms`);
    await s.close();
    await Promise.all(all);
  } finally { await s.close(); }
});

test('D-2/K-2: a push that waits longer than its deadline is abandoned and counted, and the operator is told without an account or a browser', async () => {
  const subscriptions = await A.openSubscriptions({ file: null, networkId: NETWORK });
  for (let a = 0; a < 4; a++) await subscriptions.add(String(300 + a), kept(`https://fcm.googleapis.com/fcm/send/w${a}`));
  const logs = [], started = [];
  const s = await service({ subscriptions, chain: { tip: 3, blocks: { 4: ['300', '301', '302', '303'].map(freeze) } }, fetcher: answering(started, null), pushTimeoutMs: 400, maxInFlight: 1, pushWaitMs: 150,
    log: (level, message, fields) => logs.push(JSON.stringify({ level, message, ...fields })) });
  try {
    await (await s.readBlock(4)).pushes;
    assert.equal(started.length, 1);
    assert.equal(s.stats.pushes_abandoned, 3);
    const told = logs.filter((line) => line.includes('pushes were abandoned'));
    assert.ok(told.length >= 1, logs.join('\n'));
    for (const line of told) { assert.doesNotMatch(line, /30[0-3]|fcm|w[0-3]/); assert.deepEqual(Object.keys(JSON.parse(line)).sort(), ['abandoned', 'in_flight', 'level', 'message', 'waiting']); }
    // The counter is on the health answer of the machine itself.
    assert.equal((await call(s, 'GET', '/alerts/v1/health')).body.pushes_abandoned, 3);
  } finally { await s.close(); }
});

test('D-2/K-2: a full line abandons the newest push of the account with the most waiting, never another account\'s only one', async () => {
  const line = A.createPushLine({ send: async () => {}, maxInFlight: 0, maxWaiting: 5, sweepMs: 60000 });
  const add = (account, n) => line.add(account, kept(`https://fcm.googleapis.com/fcm/send/${account}${n}`));
  const a = [1, 2, 3, 4].map((n) => add('A', n)), b1 = add('B', 1);
  assert.equal(line.waiting(), 5);
  const c1 = add('C', 1); // C's first: A's newest goes
  assert.equal(await Promise.race([a[3], pause(20).then(() => 'waiting')]), 'abandoned');
  const b2 = add('B', 2); // B's second: A has the most (3), its newest goes
  assert.equal(await Promise.race([a[2], pause(20).then(() => 'waiting')]), 'abandoned');
  const a5 = add('A', 5); // A has the most itself (2): the new one goes
  assert.equal(await Promise.race([a5, pause(20).then(() => 'waiting')]), 'abandoned');
  for (const still of [a[0], a[1], b1, b2, c1]) assert.equal(await Promise.race([still, pause(20).then(() => 'waiting')]), 'waiting');
  assert.equal(line.waiting(), 5);
  line.close();
  // Every account with at most one waiting: a first push is taken over the cap, a second is abandoned.
  const small = A.createPushLine({ send: async () => {}, maxInFlight: 0, maxWaiting: 2, sweepMs: 60000 });
  const x = small.add('X', kept('https://fcm.googleapis.com/fcm/send/x')), y = small.add('Y', kept('https://fcm.googleapis.com/fcm/send/y'));
  const z1 = small.add('Z', kept('https://fcm.googleapis.com/fcm/send/z1')), z2 = small.add('Z', kept('https://fcm.googleapis.com/fcm/send/z2'));
  assert.equal(small.waiting(), 3);
  assert.equal(await Promise.race([z2, pause(20).then(() => 'waiting')]), 'abandoned');
  for (const still of [x, y, z1]) assert.equal(await Promise.race([still, pause(20).then(() => 'waiting')]), 'waiting');
  small.close();
});

test('D-2/K-2: the wakes before removals go first but take at most half of the places; the pushes of the blocks keep the rest', async () => {
  const held = [];
  const line = A.createPushLine({ send: (item) => new Promise((resolve) => held.push({ item, resolve })), maxInFlight: 4, sweepMs: 60000 });
  for (let i = 0; i < 6; i++) line.addUrgent('U', kept(`https://fcm.googleapis.com/fcm/send/u${i}`), 60000);
  for (let i = 0; i < 6; i++) line.add(String(400 + i), kept(`https://fcm.googleapis.com/fcm/send/n${i}`));
  line.dispatch();
  // Two urgent ones, in their order, and two of the blocks (whose order is the turns').
  assert.deepEqual(held.map((h) => h.item.endpoint.split('/').at(-1)).slice(0, 2), ['u0', 'u1']);
  assert.deepEqual(held.map((h) => h.item.endpoint.split('/').at(-1)[0]), ['u', 'u', 'n', 'n']);
  // An urgent push that ends lets the next urgent one in; a block's push that ends lets the next of the blocks in.
  held[0].resolve(); await pause(5);
  assert.equal(held.at(-1).item.endpoint.split('/').at(-1)[0], 'u');
  held[2].resolve(); await pause(5);
  assert.equal(held.at(-1).item.endpoint.split('/').at(-1)[0], 'n');
  line.close();
});

// ------------------------------------------------------------------ K-3
test('K-3: "off everywhere" with the login key wakes every browser of the account first, then removes them; a slow push service does not hold it up', async () => {
  const pushed = [];
  let s;
  s = await service({ fetcher: async (url) => { pushed.push({ url, stillSubscribed: s.subscriptions.subscribed(url) }); return new Response(null, { status: 201 }); } });
  try {
    for (const name of ['phone', 'laptop']) assert.equal((await subscribe(s, `https://web.push.apple.com/${name}`)).status, 200);
    const off = await call(s, 'POST', '/alerts/v1/unsubscribe', { proof: await prove(s, { action: 'unsubscribe' }) });
    assert.deepEqual([off.status, off.body], [200, { removed: 2 }]);
    assert.deepEqual(pushed.map((p) => [p.url.split('/').at(-1), p.stillSubscribed]).sort(), [['laptop', true], ['phone', true]], 'each browser was pushed while it was still subscribed, before the answer');
    assert.equal(s.subscriptions.counts().subscriptions, 0);
  } finally { await s.close(); }
  // A push service that never answers: the removal waits at most twice a push's time limit.
  s = await service({ fetcher: answering([], null), pushTimeoutMs: 100 });
  try {
    await subscribe(s, 'https://web.push.apple.com/stuck');
    const at = Date.now();
    const off = await call(s, 'POST', '/alerts/v1/unsubscribe', { proof: await prove(s, { action: 'unsubscribe' }) });
    assert.deepEqual(off.body, { removed: 1 });
    assert.ok(Date.now() - at < 1000, `${Date.now() - at} ms`);
  } finally { await s.close(); }
});

test('K-3: a browser that turns itself off (or whoever holds its push address) is removed, and the other browsers of every account it followed are woken', async () => {
  const pushed = [];
  const s = await service({ fetcher: async (url) => { pushed.push(url); return new Response(null, { status: 201 }); } });
  try {
    for (const name of ['phone', 'laptop', 'tablet']) await subscribe(s, `https://web.push.apple.com/${name}`);
    // The phone also follows account 6, which has a browser of its own.
    await s.subscriptions.add('6', kept('https://web.push.apple.com/phone'));
    await s.subscriptions.add('6', kept('https://web.push.apple.com/other'));
    const off = await call(s, 'POST', '/alerts/v1/unsubscribe', { endpoint: 'https://web.push.apple.com/phone' });
    assert.deepEqual(off.body, { removed: 2 });
    await pause(50);
    assert.deepEqual(pushed.map((url) => url.split('/').at(-1)).sort(), ['laptop', 'other', 'tablet']);
    // Nothing is woken for a browser that was not subscribed.
    pushed.length = 0;
    assert.deepEqual((await call(s, 'POST', '/alerts/v1/unsubscribe', { endpoint: 'https://web.push.apple.com/phone' })).body, { removed: 0 });
    await pause(50);
    assert.deepEqual(pushed, []);
  } finally { await s.close(); }
});

test('K-3: POST /alerts/v1/status answers {"subscribed":true|false} for a push address, and nothing else', async () => {
  const s = await service({ rateLimit: { perSecond: 1, burst: 12 } });
  try {
    await subscribe(s, 'https://web.push.apple.com/here');
    const yes = await call(s, 'POST', '/alerts/v1/status', { endpoint: 'https://web.push.apple.com/here' });
    assert.deepEqual([yes.status, yes.text], [200, '{"subscribed":true}']);
    const no = await call(s, 'POST', '/alerts/v1/status', { endpoint: 'https://web.push.apple.com/gone' });
    assert.deepEqual([no.status, no.text], [200, '{"subscribed":false}']);
    for (const bad of [{ endpoint: 'https://attacker.example/x' }, { endpoint: 'https://web.push.apple.com/here', account: '5' }, {}, { endpoint: 42 }]) assert.equal((await call(s, 'POST', '/alerts/v1/status', bad)).status, 400, JSON.stringify(bad));
    assert.equal((await call(s, 'GET', '/alerts/v1/status')).status, 405);
    let limited = 0;
    for (let i = 0; i < 20; i++) if ((await call(s, 'POST', '/alerts/v1/status', { endpoint: 'https://web.push.apple.com/here' })).status === 429) limited += 1;
    assert.ok(limited > 0, 'rate-limited like every route');
  } finally { await s.close(); }
});

// ------------------------------------------------------------------ D-5
test('D-5: ten thousand challenges asked from 1,250 /64s of one /48 keep nothing in the service, and an honest browser still subscribes', async () => {
  const s = await service({ trustedProxies: ['127.0.0.1'] });
  const agent = new http.Agent({ keepAlive: true, maxSockets: 64 });
  try {
    const counts = {};
    for (let net = 0; net < 1250; net += 50) {
      const batch = [];
      for (let n = net; n < net + 50; n++) for (let i = 0; i < 8; i++) batch.push(raw(s, { method: 'POST', route: '/alerts/v1/challenge', agent, body: { action: 'unsubscribe' }, headers: { Host: 'wallet.example', 'X-Forwarded-For': `2001:db8:7:${n.toString(16)}::${i + 1}` } }));
      for (const { status } of await Promise.all(batch)) counts[status] = (counts[status] ?? 0) + 1;
    }
    assert.deepEqual(counts, { 200: 10000 });
    assert.equal(s.challenges.used(), 0);
    assert.equal((await subscribe(s, 'https://web.push.apple.com/honest')).status, 200);
  } finally { agent.destroy(); await s.close(); }
});

test('D-5: a challenge is made by this service for one request and serves once; forgetting used nonces past the cap never lets one serve again', () => {
  let clock = 1_000_000;
  const c = A.createChallenges({ origin: ORIGIN, networkId: NETWORK, maxUsed: 3, now: () => clock });
  const binding = A.bindingOf('unsubscribe'), other = A.bindingOf('subscribe', kept('https://web.push.apple.com/x'));
  const refused = (message, words) => assert.throws(() => c.take(message, binding), (error) => error.status === 403 && words.test(error.message));
  const issued = Array.from({ length: 5 }, () => { clock += 1; return c.issue(binding); });
  assert.deepEqual(Object.keys(issued[0]), ['purpose', 'origin', 'networkId', 'nonce', 'issuedAt', 'expiresAt']);
  assert.match(issued[0].nonce, /^[0-9a-f]{64}$/);
  const unused = issued[4];
  for (const challenge of issued.slice(0, 4)) assert.deepEqual(c.take(challenge, binding), challenge);
  // Only three are remembered: the oldest went, and the floor rose to when it was given out.
  assert.equal(c.used(), 3);
  assert.equal(c.floor(), issued[0].issuedAt);
  for (const challenge of issued.slice(0, 4)) refused(challenge, /expired or was used already/);
  // For another request, changed, from another key (another service, or this one after a restart): not this service's.
  assert.throws(() => c.take(unused, other), /made for another request/);
  refused({ ...unused, expiresAt: unused.expiresAt + 1 }, /made for another request/);
  refused(A.createChallenges({ origin: ORIGIN, networkId: NETWORK, now: () => clock }).issue(binding), /made for another request/);
  assert.deepEqual(c.take(unused, binding), unused);
  // Expired.
  const late = c.issue(binding); clock += A.CHALLENGE_MS;
  refused(late, /expired or was used already/);
  // The floor's cost: a challenge given out before it and not yet used must be asked for again.
  clock += 10;
  const early = c.issue(binding);
  for (let i = 0; i < 3; i++) { clock += 1; c.take(c.issue(binding), binding); }
  clock += 1; c.take(c.issue(binding), binding);
  assert.ok(c.floor() >= early.issuedAt);
  refused(early, /expired or was used already/);
});

// ------------------------------------------------------------------ D-6
test('D-6: the public health answer is {"ok":true} and nothing else; the counts go to the machine itself, as the supervisor asks', async () => {
  const s = await service({ trustedProxies: ['127.0.0.1'] });
  try {
    const port = new URL(s.url).port;
    // Through the proxy: the wallet's host name, X-Forwarded-For.
    assert.equal((await raw(s, { route: '/alerts/v1/health', headers: { Host: 'wallet.example', 'X-Forwarded-For': '198.51.100.20' } })).text, '{"ok":true}');
    // The loopback host name but a forwarded request, or another way of naming a proxy: still public.
    for (const name of ['X-Forwarded-For', 'Forwarded', 'X-Real-IP']) assert.equal((await raw(s, { route: '/alerts/v1/health', headers: { Host: `127.0.0.1:${port}`, [name]: '198.51.100.20' } })).text, '{"ok":true}', name);
    // The supervisor (testnet/services.mjs): fetch(`http://127.0.0.1:${port}/alerts/v1/health`).
    const own = await fetch(`http://127.0.0.1:${port}/alerts/v1/health`, { signal: AbortSignal.timeout(5000) });
    assert.equal(own.status, 200);
    const counts = await own.json();
    for (const key of ['ok', 'network_id', 'followed_height', 'behind', 'subscriptions', 'accounts', 'pushes_waiting', 'pushes_in_flight', 'pushes_sent', 'pushes_failed', 'pushes_abandoned', 'subscriptions_gone', 'blocks_read', 'blocks_verified', 'blocks_refused']) assert.ok(key in counts, key);
  } finally { await s.close(); }
});

// ------------------------------------------------------------------ D-7
test('D-7: forty subscriptions at once write the list at most twice, each answered once a write that holds it is done; a change costs the account\'s own browsers only', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-alerts-save-'));
  try {
    const file = path.join(directory, 'subscriptions.json');
    const list = await A.openSubscriptions({ file, networkId: NETWORK });
    await Promise.all(Array.from({ length: 2000 }, (_, i) => list.add(String(1000 + Math.floor(i / 8)), kept(`https://fcm.googleapis.com/fcm/send/many-${i}`))));
    await list.settled();
    assert.ok(list.writes() <= 2, `${list.writes()} writes for 2,000 subscriptions`);
    const before = list.writes();
    const adds = Array.from({ length: 40 }, (_, i) => list.add(String(5000 + i), kept(`https://fcm.googleapis.com/fcm/send/burst-${i}`)));
    const first = await adds[0];
    assert.equal(first, 1);
    assert.ok(JSON.parse(await readFile(file, 'utf8')).subscriptions.some((s) => s.endpoint.endsWith('/burst-0')), 'the first add was answered after a write that holds it');
    await Promise.all(adds);
    assert.ok(list.writes() - before <= 2, `${list.writes() - before} writes for 40 subscriptions`);
    const saved = JSON.parse(await readFile(file, 'utf8')).subscriptions;
    assert.equal(saved.length, 2040);
    assert.equal(saved.filter((s) => s.endpoint.includes('/burst-')).length, 40);
    // Opened again: the same list, by account and by browser.
    const again = await A.openSubscriptions({ file, networkId: NETWORK });
    assert.deepEqual(again.counts(), { subscriptions: 2040, accounts: 290 });
    assert.deepEqual(again.accountsOf('https://fcm.googleapis.com/fcm/send/burst-7'), ['5007']);
    assert.equal(again.subscribed('https://fcm.googleapis.com/fcm/send/nobody'), false);
    // A list in which one browser of an account appears twice was not written by this service: it is damaged.
    const doubled = JSON.parse(await readFile(file, 'utf8')); doubled.subscriptions.push(doubled.subscriptions[0]);
    await (await import('node:fs/promises')).writeFile(file, JSON.stringify(doubled));
    await assert.rejects(A.openSubscriptions({ file, networkId: NETWORK }), /damaged/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
