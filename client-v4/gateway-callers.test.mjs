// The wallet's gateway and one stranger (web audit of 23 and 24 November 2026, G-1 and W-9; its proof scripts
// poc1.mjs part B, poc3.mjs and poc4.mjs), and the trial of 24 November 2026 that followed the first fix: four wallets
// behind one address, as the real-browser check runs them, met refusals that broke their flows.
// - Without trustedProxies nothing changes: every request is the same caller and no forwarded header is read.
// - With them, the address that the gateway's own reverse proxy writes in X-Forwarded-For is the caller, and its work
//   is counted per caller (IPv4 or /64) and per /48 at rates that only keep one caller from taking a large part of the
//   gateway; the totals are out of any one caller's reach.
// - The checks wait in a fair line: the caller with fewest under way goes first, and when the line is full the one
//   that asks most is refused. Unsaturated, it refuses nobody.
// - A refusal says when to ask again: 429 RATE_LIMITED or 503 GATEWAY_BUSY, Retry-After, and the same in JSON.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createV4Servers, pageFiles, GATEWAY_LIMITS, GATEWAY_BUSY, RATE_LIMITED } from './server.mjs';
import { createProxy, SITE_LIMITS } from '../testnet/proxy.mjs';
import { validateSettings } from '../deploy/gateway/start.mjs';
import { createFairLine } from './callers.mjs';

const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const b = fixture.proof.light_block;
// The node of the verifier's fixture; it takes a submitted action, and has no transaction index (a receipt is pending).
const rpc = async (endpoint, p = {}) => {
  if (endpoint === '/commit') return { signed_header: b.signed_header };
  if (endpoint === '/validators') return { block_height: p.height, total: '4', validators: p.height === '6' ? b.validators : b.next_validators };
  if (endpoint === '/abci_query') return { response: { height: '5', code: 0, value: Buffer.from(JSON.stringify({ height: '5', root: b.signed_header.header.app_hash.toLowerCase(), entries: fixture.proof.entries, history_proofs: fixture.proof.history_proofs })).toString('base64') } };
  if (endpoint === '/broadcast_tx_sync') return { code: 0, hash: 'AB'.repeat(32) };
  throw Error('Unexpected RPC');
};
const root = fileURLToPath(new URL('../', import.meta.url));
/// A gateway on loopback with the verifier's fixture. `frozen`: its clock stands still, so every request of a test
/// falls in the same second; otherwise it runs from the fixture's time.
async function withGateway(options, work, { frozen = true } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-gateway-callers-')), originalNow = Date.now, start = originalNow();
  let servers = null;
  try {
    Date.now = frozen ? () => fixture.now_ms : () => fixture.now_ms + (originalNow() - start);
    servers = await createV4Servers({ root, manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0,
      checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), upgradeCheck: { everyMs: 0 }, onRefusal: () => {}, ...options });
    return await work(servers);
  } finally { Date.now = originalNow; await servers?.close(); await rm(directory, { recursive: true, force: true }); }
}
// At most 200 connections at once: more at once are refused by the listening socket on some systems (Windows).
const agent = new http.Agent({ keepAlive: true, maxSockets: 200 });
after(() => agent.destroy());
/// A request as the gateway's reverse proxy would send it: from 127.0.0.1, with the caller's address appended.
function ask(origin, pathname, { caller, method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(pathname, origin), started = performance.now();
    const r = http.request({ agent, hostname: '127.0.0.1', port: u.port, method, path: u.pathname + u.search, headers: { Host: u.host, ...(caller ? { 'X-Forwarded-For': caller } : {}), ...headers } }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(chunks)); } catch {} resolve({ status: res.statusCode, headers: res.headers, json, ms: performance.now() - started }); });
    });
    r.on('error', reject); r.end(body);
  });
}
const statuses = (list) => list.map((r) => r.status);
const count = (list, value) => list.filter((status) => status === value).length;
const READ = '/api/notifications?account=0';
const LIMITED = { error: 'Local request limit reached', code: RATE_LIMITED, retryAfterSeconds: 1 };
const BUSY = { error: 'The gateway is checking many requests just now. Try again in a few seconds.', code: GATEWAY_BUSY, retryAfterSeconds: 2 };

test('without trustedProxies no forwarded header is read: 50 a second for everybody together, whatever X-Forwarded-For says; the refusal says when to ask again', async () => {
  await withGateway({}, async (servers) => {
    const W = servers.walletListenOrigin;
    const answered = await Promise.all(Array.from({ length: 60 }, (_, i) => ask(W, '/api/network', { caller: `198.51.100.${i + 1}` })));
    assert.deepEqual([count(statuses(answered), 200), count(statuses(answered), 429)], [GATEWAY_LIMITS.work, 10]);
    const refused = await ask(W, '/api/network', { caller: '203.0.113.200' });
    assert.deepEqual([refused.status, refused.headers['retry-after'], refused.headers['content-type'], refused.json], [429, '1', 'application/json; charset=utf-8', LIMITED], 'a new address in the header is not a new caller');
  });
});

test('with trustedProxies, work is counted per caller and per /48, and no one caller\'s burst uses up everybody\'s second (poc1.mjs part B)', async () => {
  await withGateway({ trustedProxies: ['127.0.0.1'] }, async (servers) => {
    const W = servers.walletListenOrigin, S = servers.merchantListenOrigin, { caller, network, work } = GATEWAY_LIMITS.perCaller;
    assert.deepEqual([caller.perSecond, caller.burst, network.perSecond, network.burst, work], [15, 300, 30, 600, 1000]);
    // poc1.mjs part B, harder: one client's 400 at once, from 400 addresses of its /64, then another user in the same
    // second (before the first fix: 429; the first fix allowed 30 and refused the rest).
    const burst = await Promise.all(Array.from({ length: 400 }, (_, i) => ask(W, '/api/network', { caller: `2001:db8:1:2::${(i + 1).toString(16)}` })));
    assert.deepEqual([count(statuses(burst), 200), count(statuses(burst), 429)], [caller.burst, 400 - caller.burst]);
    const refused = burst.find((r) => r.status === 429);
    assert.deepEqual([refused.headers['retry-after'], refused.json], ['1', LIMITED]);
    assert.equal((await ask(W, '/api/network', { caller: '198.51.100.7' })).status, 200, 'another user in the same second');
    // The /64s of one /48 share twice a caller's limit: thirty /64s with twenty each pass the 300 the /48 has left.
    const spread = await Promise.all(Array.from({ length: 600 }, (_, i) => ask(W, '/api/network', { caller: `2001:db8:1:${(100 + (i % 30)).toString(16)}::1` })));
    assert.equal(count(statuses(spread), 200), network.burst - caller.burst);
    assert.equal((await ask(W, '/api/network', { caller: '2001:db8:2::1' })).status, 200, 'another /48 in the same second');
    // Everybody together: 1000 a second, of which 602 are used; two more callers at their bursts reach it.
    const many = await Promise.all(Array.from({ length: 600 }, (_, i) => ask(W, '/api/network', { caller: `203.0.113.${(i % 2) + 1}` })));
    assert.equal(count(statuses(many), 200), work - caller.burst - 1 - (network.burst - caller.burst) - 1);
    // The page's files are not work, and the blog's origin has budgets of its own.
    assert.equal((await ask(W, '/styles.css', { caller: '2001:db8:1:2::1' })).status, 200);
    assert.equal((await ask(S, '/api/config', { caller: '2001:db8:1:2::1' })).status, 200);
  });
});

test('a forwarded header is read from the trusted proxy only, and only its right-most address; the setting takes loopback only', async () => {
  await withGateway({ trustedProxies: ['127.0.0.1'] }, async (servers) => {
    const W = servers.walletListenOrigin, { burst } = GATEWAY_LIMITS.perCaller.caller;
    // What a caller writes to the left of the proxy's own entry is not believed: made-up first addresses, one real last
    // address, one caller.
    const forged = await Promise.all(Array.from({ length: burst + 50 }, (_, i) => ask(W, '/api/network', { caller: `10.0.${Math.floor(i / 250)}.${(i % 250) + 1}, 198.51.100.50` })));
    assert.equal(count(statuses(forged), 200), burst);
    // A request of the proxy without an address of a caller is the proxy's own.
    const own = await Promise.all(Array.from({ length: burst + 50 }, () => ask(W, '/api/network', { caller: 'not an address' })));
    assert.equal(count(statuses(own), 200), burst);
  });
  for (const bad of [['10.0.0.1'], ['203.0.113.9'], 'loopback', [42]]) await assert.rejects(withGateway({ trustedProxies: bad }, async () => {}), /trustedProxies lists loopback addresses/, JSON.stringify(bad));
  // The operator's settings file: the one address the gateway can name, its own machine's.
  const windows = process.platform === 'win32';
  const valid = { manifest_file: windows ? 'C:\\operator\\pinned.json' : '/operator/pinned.json', manifest_sha256: 'a'.repeat(64), native_rpc_url: 'http://127.0.0.1:26657/', data_directory: windows ? 'C:\\gateway-data' : '/data/gateway', recipient: '0', wallet_port: 8907, merchant_port: 8908, public_origins: { wallet: 'https://wallet.example', merchant: 'https://app.example' } };
  assert.equal(validateSettings({ ...valid, trusted_proxies: ['127.0.0.1'] }).trusted_proxies[0], '127.0.0.1');
  for (const bad of [[], ['10.0.0.1'], ['127.0.0.1', '::1'], '127.0.0.1', [null]]) assert.throws(() => validateSettings({ ...valid, trusted_proxies: bad }), /trusted_proxies is \["127\.0\.0\.1"\]/, JSON.stringify(bad));
});

test('the fair line: unsaturated it refuses nobody; flooded by one caller, one /64 or one /48, another caller is answered first (poc3.mjs, poc4.mjs)', async () => {
  // Six households behind six addresses, each with five wallets reading at once: nobody is refused.
  await withGateway({ trustedProxies: ['127.0.0.1'] }, async (servers) => {
    const W = servers.walletListenOrigin;
    const reads = await Promise.all(Array.from({ length: 6 * 5 * 4 }, (_, i) => ask(W, READ, { caller: `198.51.100.${(i % 6) + 1}` })));
    assert.deepEqual([...new Set(statuses(reads))], [200]);
    assert.equal(servers.verificationLine().refused, 0);
  }, { frozen: false });
  // One caller asks for 290 verified reads at once (within its rate burst of 300); then a victim asks for its own.
  // The flooding caller may have half the line under way and is refused beyond; the victim goes first.
  for (const [label, attacker] of [['one caller', () => '2001:db8:66:1::1'], ['one /64', (i) => `2001:db8:66:1::${(i + 1).toString(16)}`], ['one /48', (i) => `2001:db8:66:${(i % 64).toString(16)}::1`]]) {
    await withGateway({ trustedProxies: ['127.0.0.1'] }, async (servers) => {
      const W = servers.walletListenOrigin;
      await ask(W, READ, { caller: '192.0.2.1' });
      const flood = Promise.all(Array.from({ length: 290 }, (_, i) => ask(W, READ, { caller: attacker(i) })));
      await new Promise((resolve) => setTimeout(resolve, 20));
      const victim = [];
      for (let i = 0; i < 5; i++) victim.push(await ask(W, READ, { caller: '198.51.100.9' }));
      const flooded = await flood, line = servers.verificationLine();
      assert.deepEqual([...new Set(statuses(victim))], [200], `${label}: the victim is answered`);
      const slowestVictim = Math.max(...victim.map((r) => r.ms)), slowestAttacker = Math.max(...flooded.filter((r) => r.status === 200).map((r) => r.ms));
      assert.ok(slowestVictim < slowestAttacker / 2, `${label}: the victim waits less than the flood (${slowestVictim.toFixed(0)} ms against ${slowestAttacker.toFixed(0)} ms)`);
      assert.ok(line.mostOfOne <= GATEWAY_LIMITS.verifying.size * GATEWAY_LIMITS.verifying.callerShare, JSON.stringify(line));
      for (const r of flooded.filter((x) => x.status !== 200)) assert.deepEqual([r.status, r.headers['retry-after'], r.headers['content-type'], r.json], [503, '2', 'application/json; charset=utf-8', BUSY], label);
      assert.ok(flooded.some((r) => r.status === 503), `${label}: the caller that asked most was told the gateway is busy`);
    }, { frozen: false });
  }
});

test('the fair line itself: who goes first, what one caller and one /48 may hold, who is refused when it is full', async () => {
  const busy = () => Object.assign(new Error('busy'), { code: 'BUSY' });
  const held = []; const hold = (name) => () => new Promise((resolve) => held.push({ name, resolve }));
  const done = [], settle = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };
  const next = async () => { const step = held.shift(); done.push(step.name); step.resolve(); await settle(); };
  // A caller that asks for one goes before one that asks for many, whenever it came; a /48 asking from many /64s goes
  // after both.
  const line = createFairLine({ slots: 1, size: 64, busy });
  const heavy = { caller: '203.0.113.1', network: null };
  for (let i = 0; i < 5; i++) line.run(heavy, hold('heavy' + i));
  for (let i = 0; i < 8; i++) line.run({ caller: `2001:db8:1:${i}::/64`, network: '2001:db8:1::/48' }, hold('net' + i));
  await settle(); line.run({ caller: '198.51.100.9', network: null }, hold('light'));
  await settle();
  for (let i = 0; i < 14; i++) await next();
  assert.deepEqual(done, ['heavy0', 'light', 'heavy1', 'heavy2', 'heavy3', 'heavy4', 'net0', 'net1', 'net2', 'net3', 'net4', 'net5', 'net6', 'net7']);
  // Shares: one caller may have half the line under way, one /48 three quarters; beyond, refused at once.
  const never = () => new Promise(() => {});
  const one = createFairLine({ slots: 1, size: 8, busy }), mine = [];
  for (let i = 0; i < 6; i++) one.run({ caller: 'a', network: null }, never).catch((e) => mine.push(e.code));
  await settle(); assert.deepEqual([mine, one.status().mostOfOne], [['BUSY', 'BUSY'], 4]);
  const net = createFairLine({ slots: 1, size: 8, busy }), ours = [];
  for (let i = 0; i < 8; i++) net.run({ caller: `b${i}`, network: 'n' }, never).catch((e) => ours.push(e.code));
  await settle(); assert.deepEqual([ours, net.status().running + net.status().waiting], [['BUSY', 'BUSY'], 6]);
  // Full: a newcomer that asks less takes the place of the newest of the one that asks most; one that asks alike is refused.
  const full = createFairLine({ slots: 1, size: 3, callerShare: 1, networkShare: 1, busy }), out = [];
  const forever = (name) => full.run({ caller: name[0], network: null }, never).catch(() => out.push('refused ' + name));
  for (const name of ['a1', 'a2', 'a3', 'a4', 'b1', 'c1', 'b2']) { forever(name); await settle(); }
  assert.deepEqual(out, ['refused a4', 'refused a3', 'refused b2']);
  assert.deepEqual(full.status(), { running: 1, waiting: 3, most: 4, mostOfOne: 3, refused: 3 }, 'a4: a caller holds at most the share of the line (here all of it, 3)');
  // Callers not told apart are one: first come, first served, the newest refused when full; the service's own work runs at once.
  const plain = createFairLine({ slots: 1, size: 2, busy }), order = [];
  for (const name of ['x', 'y', 'z', 'w']) plain.run({ caller: null, network: null }, hold(name)).then(() => order.push(name), () => order.push('refused ' + name));
  assert.equal(await plain.run(undefined, () => 'own'), 'own');
  await settle(); while (held.length) await next();
  assert.deepEqual(order, ['refused w', 'x', 'y', 'z']);
  // A place waited for too long is refused.
  const slow = createFairLine({ slots: 1, size: 4, waitMs: 30, busy }), late = [];
  slow.run({ caller: 'a', network: null }, never);
  await slow.run({ caller: 'b', network: null }, () => 'never').catch((e) => late.push(e.code));
  assert.deepEqual(late, ['BUSY']);
});

// ---------------------------------------------------------------- four wallets behind one address
// What one wallet asks of its gateway, from the measurement of 24 November 2026 (six wallets with the wallet's own code
// in Chrome against the wallet's preview; and the routes of a sign-up and of a payment that waits for its receipt): the
// page's files and five reads when the page opens, four reads to unlock, a sign-up's reads and its waits for receipts, a
// payment and its receipt, and the reads of the refresh every five seconds (here every half second).
const FILES = (await pageFiles(root, 'wallet')).keys(), WALLET_FILES = [...FILES].filter((p) => !/device-|icons\/|manifest|\/sw\.js$/.test(p)).slice(0, 36);
const TX = Buffer.alloc(96, 7).toString('base64'), HASH = 'AB'.repeat(32);
const PROOF = '/api/view-proof?query=' + encodeURIComponent('{"ids":["0"]}');
const PHASES = {
  open: [...WALLET_FILES.map((p) => ['GET', p]), ['GET', '/api/network'], ['GET', '/api/network'], ['GET', PROOF], ['GET', PROOF], ['GET', '/api/light-block']],
  unlock: [['GET', PROOF], ['GET', PROOF], ['GET', PROOF], ['GET', READ]],
  signup: [['GET', PROOF], ['GET', PROOF], ['GET', '/api/light-block'], ['GET', `/api/receipt?hash=${HASH}&wait=0`], ['GET', PROOF], ['GET', PROOF], ['POST', '/api/submit'], ['GET', `/api/receipt?hash=${HASH}&wait=0&fast=1`], ['GET', PROOF], ['GET', READ]],
  pay: [['POST', '/api/submit'], ['GET', `/api/receipt?hash=${HASH}&wait=0&fast=1`], ['GET', PROOF], ['GET', PROOF], ['GET', READ]],
  refresh: [['GET', PROOF], ['GET', READ]],
};
/// One wallet's day, compressed: each phase's requests at once, a short pause between phases, six refreshes.
async function wallet(send, flow) {
  const answers = [];
  for (const phase of ['open', flow, flow === 'signup' ? 'unlock' : 'pay', ...Array(6).fill('refresh')]) {
    answers.push(...await Promise.all(PHASES[phase].map(([method, pathname]) => send(method, pathname))));
    await new Promise((resolve) => setTimeout(resolve, phase === 'refresh' ? 500 : 50));
  }
  return answers;
}

test('four wallets behind one address, through the proxy to the gateway: none is refused, also while another address floods (the trial of 24 November)', async () => {
  await withGateway({ trustedProxies: ['127.0.0.1'] }, async (servers) => {
    const port = Number(new URL(servers.walletListenOrigin).port), key = 'k'.repeat(64);
    const proxy = createProxy({ originKey: key, routes: { wallet: { port, host: `127.0.0.1:${port}`, forwardCaller: true } } });
    await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
    const via = (viewer) => (method, pathname) => new Promise((resolve) => {
      const started = performance.now();
      const r = http.request({ agent, host: '127.0.0.1', port: proxy.address().port, path: pathname, method, headers: { 'x-time-origin-key': key, 'x-time-site': 'wallet', 'x-forwarded-for': viewer, ...(method === 'POST' ? { 'content-type': 'application/json', origin: servers.walletListenOrigin } : {}) } }, (res) => { res.resume(); res.on('end', () => resolve({ status: res.statusCode, pathname, ms: performance.now() - started })); });
      r.on('error', () => resolve({ status: 'error', pathname, ms: 0 })); r.end(method === 'POST' ? JSON.stringify({ tx: TX }) : undefined);
    });
    const household = (viewer) => Promise.all(['signup', 'signup', 'pay', 'pay'].map((flow) => wallet(via(viewer), flow))).then((all) => all.flat());
    try {
      // Alone: every request of the four is answered.
      const alone = await household('198.51.100.40');
      const work = alone.filter((r) => r.pathname.startsWith('/api/'));
      assert.ok(work.length >= 100 && alone.length - work.length === 4 * WALLET_FILES.length, `${work.length} requests to the gateway, ${alone.length - work.length} files`);
      assert.deepEqual([...new Set(statuses(alone))], [200], JSON.stringify(alone.filter((r) => r.status !== 200).slice(0, 5)));
      // Again, while one address floods the gateway's verified reads as fast as it can (and its /48 with it).
      let flooding = true; const flood = [];
      const attackers = Array.from({ length: 24 }, (_, i) => (async () => { while (flooding) flood.push(await via(i % 2 ? '203.0.113.66' : `2001:db8:bad:${i.toString(16)}::1`)('GET', READ)); })());
      await new Promise((resolve) => setTimeout(resolve, 300));
      const meanwhile = await household('198.51.100.41');
      flooding = false; await Promise.all(attackers);
      assert.deepEqual([...new Set(statuses(meanwhile))], [200], JSON.stringify(meanwhile.filter((r) => r.status !== 200).slice(0, 5)));
      const slowest = Math.max(...meanwhile.map((r) => r.ms));
      assert.ok(slowest < 5000, `no request of the four waited long (${slowest.toFixed(0)} ms)`);
      assert.ok(flood.length >= 100, `the other address flooded (${flood.length} asked, ${count(statuses(flood), 429)} held to its rate, ${count(statuses(flood), 503)} told the gateway was busy)`);
    } finally { proxy.closeAllConnections(); await new Promise((resolve) => proxy.close(resolve)); }
  }, { frozen: false });
});

test('through the test network\'s proxy in front: the gateway is told each caller, and one /64 cannot starve another caller', async () => {
  await withGateway({ trustedProxies: ['127.0.0.1'] }, async (servers) => {
    const port = Number(new URL(servers.walletListenOrigin).port), key = 'k'.repeat(64);
    const proxy = createProxy({ originKey: key, routes: { wallet: { port, host: `127.0.0.1:${port}`, forwardCaller: true } } });
    await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve));
    const viaProxy = (pathname, viewer) => new Promise((resolve) => { http.get({ agent, host: '127.0.0.1', port: proxy.address().port, path: pathname, headers: { 'x-time-origin-key': key, 'x-time-site': 'wallet', 'x-forwarded-for': viewer } }, (r) => { const chunks = []; r.on('data', (c) => chunks.push(c)); r.on('end', () => resolve({ status: r.statusCode, retry: r.headers['retry-after'], body: Buffer.concat(chunks).toString() })); }).on('error', () => resolve({ status: 'error' })); });
    try {
      const attack = await Promise.all(Array.from({ length: 600 }, (_, i) => viaProxy('/api/network', `2001:db8:9:9::${(i + 1).toString(16)}`)));
      assert.equal(count(statuses(attack), 200), SITE_LIMITS.wallet.work.burst, 'the proxy holds the /64 to its burst');
      const refused = attack.find((r) => r.status === 429);
      assert.deepEqual([refused.retry, JSON.parse(refused.body)], ['1', { error: 'Too many requests from your address. Wait a few seconds.', code: 'RATE_LIMITED', retryAfterSeconds: 1 }]);
      assert.deepEqual([(await viaProxy('/api/network', '198.51.100.70')).status, (await viaProxy('/api/network', '2001:db8:10::1')).status, (await viaProxy('/', '2001:db8:9:9::1')).status], [200, 200, 200]);
    } finally { proxy.closeAllConnections(); await new Promise((resolve) => proxy.close(resolve)); }
  });
});
