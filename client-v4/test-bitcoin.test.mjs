// The test-bitcoin service (test-bitcoin.mjs, deploy/test-bitcoin/start.mjs) over a Bitcoin node that exists in
// the test only (test-bitcoin-kit.mjs): the amounts, the client of the node's RPC, the limits, the archive, the
// routes and the config. The test against the real Bitcoin Core is test-bitcoin-regtest.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { addressToScript, scriptToAddress, transactionOutputs } from './bitcoin-address.mjs';
import { BitcoinRpcError } from './bitcoin-rpc.mjs';
import { ADDRESS_FORMS, DUST_SATS, METHODS, MAX_BODY_BYTES, REGTEST_GENESIS, ROUTES, ServiceError, btcText, createArchive, createChain, createLimits, createNodeRunner, createTestBitcoinService, createWalletRpc, nodeArguments, parseSats, satsOfBtc } from './test-bitcoin.mjs';
import { createFakeRegtest, createLog } from './test-bitcoin-kit.mjs';
import { validateConfig } from '../deploy/test-bitcoin/start.mjs';

const START = 1_800_000_000_000;
const clientOf = (node, options = {}) => createWalletRpc({ url: 'http://127.0.0.1:18443/', login: async () => node.password, wallet: 'test', fetcher: node.fetcher, timeoutMs: 300, ...options });
const refused = (code, pattern) => (error) => error instanceof BitcoinRpcError && error.code === code && (!pattern || pattern.test(error.message));
const temporary = async (t) => { const directory = await mkdtemp(path.join(os.tmpdir(), 'time-test-bitcoin-')); t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })); return directory; };
/// A service over a fake node, with a clock of the test's and no timer: the test calls `tick()`. Requests are not
/// limited by their number unless the test gives a `rateLimit` (one test does).
async function serviceOn(t, { node = createFakeRegtest(), archive = null, at = START, ...options } = {}) {
  const clock = { at }, log = createLog();
  node.now = () => clock.at;
  const service = await createTestBitcoinService({ rpc: clientOf(node), archive, port: 0, autoMine: false, now: () => clock.at, log, sleep: async () => {}, rateLimit: { perSecond: 1000, burst: 100000 }, ...options });
  t.after(() => service.close());
  /// One block, `seconds` later (the pace of the service, unless given).
  const block = async (seconds = options.blockSeconds ?? 20) => { clock.at += seconds * 1000; await service.tick(); };
  return { service, node, clock, log, block };
}
async function freePort() { const server = net.createServer(); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); const port = server.address().port; await new Promise((resolve) => server.close(resolve)); return port; }
function call(service, route, { method = 'GET', headers = {}, body, json, base = '/bitcoin' } = {}) {
  const url = new URL(service.url);
  return new Promise((resolve, reject) => {
    const request = http.request({ host: url.hostname, port: url.port, path: `${base}${route}`, method, headers: { ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let parsed = null; try { parsed = JSON.parse(text); } catch { /* not JSON */ } resolve({ status: response.statusCode, headers: response.headers, text, body: parsed }); });
    });
    request.on('error', reject);
    request.end(json !== undefined ? JSON.stringify(json) : body);
  });
}
const pay = (service, address, sats, headers = {}) => call(service, '/v1/payments', { method: 'POST', json: { address, sats: String(sats) }, headers });
const newAddress = async (service, form) => (await call(service, '/v1/addresses', { method: 'POST', ...(form ? { json: { form } } : {}) })).body.address;
const foreign = (byte, form = '0014') => scriptToAddress(`${form}${byte.repeat(form === '0014' ? 20 : 32)}`, 'regtest');

// ---------------------------------------------------------------- amounts
test('satoshis become Bitcoin Core\'s decimal text, and back, by whole-number arithmetic', () => {
  assert.equal(btcText(1n), '0.00000001');
  assert.equal(btcText('12345'), '0.00012345');
  assert.equal(btcText(5_000_000n), '0.05000000');
  assert.equal(btcText(123_456_789_012n), '1234.56789012');
  assert.equal(btcText(2_100_000_000_000_000n), '21000000.00000000');
  for (const bad of [0n, -1n, 2_100_000_000_000_001n]) assert.throws(() => btcText(bad));
  // A value a binary fraction cannot hold: 0.1 + 0.2 is not 0.3 there, and 0.30000000 is thirty million here.
  assert.equal(satsOfBtc('0.30000000'), 30_000_000n);
  assert.equal(satsOfBtc('14999.99999999'), 1_499_999_999_999n);
  assert.equal(satsOfBtc('-0.00002190'), -2190n);
  assert.equal(satsOfBtc('0.00000000'), 0n);
  for (const sats of [1n, 294n, 99_999_999n, 100_000_000n, 2_099_999_999_999_999n]) assert.equal(satsOfBtc(btcText(sats)), sats);
  // Only the form the node writes, and only as text: a number has lost its digits already.
  for (const bad of [0.3, '0.3', '1', '1.000000001', '1e-8', ' 0.00000001', '0.00000001 ', '', null, undefined, '１.00000000']) assert.throws(() => satsOfBtc(bad), /not an amount/);
  assert.equal(parseSats('5000000'), 5_000_000n);
  assert.equal(parseSats('0'), 0n);
  for (const bad of ['', '01', '1.0', '-1', '1e3', ' 1', '12345678901234567', 5, null, undefined, '0x10']) assert.equal(parseSats(bad), null, String(bad));
});

// ---------------------------------------------------------------- the node's RPC
test('the client sends a node nothing but the question until it has said regtest, and asks again after a failure', async () => {
  const node = createFakeRegtest(), rpc = clientOf(node);
  node.chain = 'main';
  await assert.rejects(rpc.call('createwallet', { wallet_name: 'test' }), refused('WRONG_CHAIN', /not on regtest/));
  await assert.rejects(rpc.call('send', { outputs: [{ x: '1.00000000' }] }), refused('WRONG_CHAIN'));
  await assert.rejects(rpc.chainInfo(), refused('WRONG_CHAIN'));
  assert.deepEqual(node.methodsCalled(), ['getblockchaininfo'], 'a node of another network was asked what its chain is, three times, and nothing else');
  assert.equal(node.calls.length, 3);
  assert.deepEqual(node.wallets(), []);

  node.chain = 'regtest';
  await rpc.call('createwallet', { wallet_name: 'test' });
  await rpc.call('listwallets');
  assert.deepEqual(node.calls.slice(3).map(([method]) => method), ['getblockchaininfo', 'createwallet', 'listwallets'], 'asked once, then believed');
  // A call without an answer: the node on the port may be another one now.
  node.fault = 'silent';
  await assert.rejects(rpc.call('listwallets'), refused('UNAVAILABLE', /ECONNREFUSED/));
  node.fault = null; node.chain = 'test';
  const before = node.calls.length;
  await assert.rejects(rpc.call('getnewaddress', ['', 'bech32']), refused('WRONG_CHAIN'));
  assert.deepEqual(node.calls.slice(before).map(([method]) => method), ['getblockchaininfo']);
  // A refusal of the node is an answer: the node is the same one.
  node.chain = 'regtest';
  await assert.rejects(rpc.call('loadwallet', ['none']), refused('REFUSED'));
  const count = node.calls.length;
  await rpc.call('listwallets');
  assert.equal(node.calls.length, count + 1);
});

test('the client sends the methods of its list only, wallet calls to the wallet, and keeps an amount as the node wrote it', async () => {
  const node = createFakeRegtest(), rpc = clientOf(node);
  for (const method of ['dumpprivkey', 'getblockchaininfo', 'sendmany', 'sendtoaddress', 'walletpassphrase', 'invalidateblock', 'importprivkey', 'backupwallet', '']) await assert.rejects(rpc.call(method, []), /not used by this service/);
  assert.equal(node.calls.length, 0);
  assert.deepEqual([...METHODS].sort(), ['createwallet', 'generatetoaddress', 'getaddressinfo', 'getbalances', 'getblock', 'getblockchaininfo', 'getblockhash', 'getnewaddress', 'gettransaction', 'importdescriptors', 'listdescriptors', 'listwallets', 'loadwallet', 'send', 'stop', 'submitblock']);
  await rpc.call('createwallet', { wallet_name: 'test' });
  const address = await rpc.call('getnewaddress', ['mining', 'p2sh-segwit']);
  await rpc.call('generatetoaddress', [101, address]);
  assert.deepEqual(node.calls.map(([method, , wallet]) => [method, wallet]), [['getblockchaininfo', null], ['createwallet', null], ['getnewaddress', 'test'], ['generatetoaddress', null]]);
  const balances = await rpc.call('getbalances');
  assert.deepEqual(balances.mine, { trusted: '50.00000000', untrusted_pending: '0.00000000', immature: '5000.00000000' }, 'the digits the node wrote, as text');
  assert.equal(balances.lastprocessedblock.height, 101, 'a whole number stays a number');
  assert.deepEqual(await rpc.chainInfo(), { blocks: 101, bestHash: node.tip() });
  // The password goes to the node and into no error.
  const wrong = clientOf(node, { login: async () => 'user:not-the-password' });
  await assert.rejects(wrong.chainInfo(), (error) => refused('UNAUTHORIZED')(error) && !error.message.includes('not-the-password'));
  node.fault = 'slow';
  await assert.rejects(rpc.chainInfo(), refused('UNAVAILABLE', /in time/));
  assert.throws(() => createWalletRpc({ url: 'http://user:pw@127.0.0.1:18443/', login: async () => '', wallet: 'test' }), /origin/);
  assert.throws(() => createWalletRpc({ url: 'http://127.0.0.1:18443/', login: async () => '', wallet: '../x' }), /name of the wallet/);
});

test('the node is started private: regtest, no peer-to-peer side, RPC on the loopback address', () => {
  const args = nodeArguments({ datadir: '/var/lib/time-test-bitcoin/node', rpcPort: 18443 });
  for (const wanted of ['-regtest', '-listen=0', '-connect=0', '-networkactive=0', '-dnsseed=0', '-discover=0', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-rpcport=18443', '-datadir=/var/lib/time-test-bitcoin/node']) assert.ok(args.includes(wanted), wanted);
  assert.ok(!args.some((arg) => /^-(?:rpcuser|rpcpassword|rpcauth|main|testnet|signet)/.test(arg)));
});

// ---------------------------------------------------------------- the node as a child process
test('the runner starts the program, starts it again when it ends, and kills it when it does not stop', async () => {
  const spawned = [], log = createLog();
  let up = false;
  const spawner = (program, args) => { const child = new EventEmitter(); child.kill = (signal) => { child.killed = signal ?? true; up = false; setImmediate(() => child.emit('exit', null, 'SIGKILL')); }; spawned.push({ program, args, child }); setImmediate(() => { up = true; }); return child; };
  const runner = createNodeRunner({ program: '/opt/bitcoin/bin/bitcoind', datadir: '/nowhere', rpcPort: 18443, answers: async () => up, log, spawner, sleep: async () => { await new Promise((resolve) => setImmediate(resolve)); }, stopMs: 50 });
  await runner.start();
  assert.equal(spawned.length, 1);
  assert.deepEqual([spawned[0].program, spawned[0].args.includes('-regtest'), runner.running(), runner.restarts()], ['/opt/bitcoin/bin/bitcoind', true, true, 0]);
  // The node ends by itself: it is started again, and the log says so.
  up = false; spawned[0].child.emit('exit', 1, null);
  for (let i = 0; i < 50 && !(spawned.length === 2 && up); i++) await new Promise((resolve) => setImmediate(resolve));
  for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual([spawned.length, runner.running(), runner.restarts()], [2, true, 1]);
  assert.equal(log.said(/ended and is started again/).length, 1);
  assert.equal(log.said(/answers again/).length, 1);
  // Told to stop and still there after the wait: killed. It is not started a third time.
  let asked = 0;
  await runner.stop(async () => { asked += 1; });
  assert.deepEqual([asked, spawned[1].child.killed, spawned.length, runner.running()], [1, 'SIGKILL', 2, false]);
  assert.equal(log.said(/was killed/).length, 1);
});

test('a program that ends while it starts is an error, and a node the runner did not start is not told to stop', async () => {
  const spawner = () => { const child = new EventEmitter(); child.kill = () => {}; setImmediate(() => child.emit('exit', 1, null)); return child; };
  const runner = createNodeRunner({ program: 'bitcoind', datadir: path.join(os.tmpdir(), 'no-such-node'), rpcPort: 18443, answers: async () => false, spawner, sleep: async () => { await new Promise((resolve) => setImmediate(resolve)); } });
  await assert.rejects(runner.start(), /ended while starting/);
  let asked = 0;
  const other = createNodeRunner({ program: 'bitcoind', datadir: '/nowhere', rpcPort: 18443, answers: async () => true, spawner });
  await other.stop(async () => { asked += 1; });
  assert.equal(asked, 0, 'never started here: someone else\'s node');
});

// ---------------------------------------------------------------- limits
test('limits: thirty payments an hour and an amount a day for one caller, a total for all, and a count given back', () => {
  const clock = { at: START };
  const limits = createLimits({ perCallerPerDaySats: 1000n, paymentsPerCallerPerHour: 3, totalPerDaySats: 2500n, totalPaymentsPerDay: 100, addressesPerCallerPerDay: 2, totalAddressesPerDay: 3, now: () => clock.at });
  const refusedAs = (code, pattern) => (error) => error instanceof ServiceError && error.status === 429 && error.code === code && pattern.test(error.message) && error.extra.retryAfter >= 1;
  assert.equal(limits.left('a'), 1000n);
  limits.payment('a', 100n); clock.at += 60_000; limits.payment('a', 100n); clock.at += 60_000; limits.payment('a', 100n);
  assert.throws(() => limits.payment('a', 1n), refusedAs('caller_limit', /3 payments in an hour/));
  try { limits.payment('a', 1n); } catch (error) { assert.equal(error.extra.retryAfter, 3600 - 120, 'until the oldest of the hour is an hour old'); }
  assert.equal(limits.left('a'), 700n);
  // Another caller is another count.
  limits.payment('b', 1000n);
  assert.equal(limits.left('b'), 0n);
  assert.throws(() => limits.payment('b', 1n), refusedAs('caller_limit', /1000 satoshis in 24 hours/));
  // An hour later the first caller may pay again, up to its amount of the day and not a satoshi more.
  clock.at += 3_600_000;
  assert.throws(() => limits.payment('a', 701n), refusedAs('caller_limit', /24 hours/));
  const giveBack = limits.payment('a', 700n);
  assert.equal(limits.left('a'), 0n);
  // A payment the node certainly did not make does not count.
  giveBack();
  assert.equal(limits.left('a'), 700n);
  limits.payment('a', 700n);
  // The total of all callers: 2,000 of 2,500 are given.
  assert.equal(limits.left('c'), 500n, 'what is left of the total, when that is less than a caller\'s own');
  assert.throws(() => limits.payment('c', 501n), refusedAs('daily_total', /24 hours/));
  limits.payment('c', 500n);
  assert.throws(() => limits.payment('d', 1n), refusedAs('daily_total', /24 hours/));
  // 24 hours after the first payments, their amounts are free again.
  clock.at = START + 86_400_000 + 120_001;
  assert.equal(limits.left('a'), 300n + 0n, 'the three payments of the first minutes have left the window');
  assert.equal(limits.left('d'), 1000n, 'a caller that has had nothing: its own amount, which the total still covers');
  // Addresses: two a caller, three in all.
  limits.address('a'); const back = limits.address('a');
  assert.throws(() => limits.address('a'), refusedAs('caller_limit', /2 new addresses/));
  back(); limits.address('a'); limits.address('b');
  assert.throws(() => limits.address('c'), refusedAs('daily_total', /addresses/));
  clock.at += 86_400_001;
  limits.address('c');
});

test('a count of payments in all, apart from their amounts', () => {
  const limits = createLimits({ perCallerPerDaySats: 1000n, paymentsPerCallerPerHour: 30, totalPerDaySats: 100_000n, totalPaymentsPerDay: 2, addressesPerCallerPerDay: 2, totalAddressesPerDay: 3, now: () => START });
  limits.payment('a', 1n); limits.payment('b', 1n);
  assert.throws(() => limits.payment('c', 1n), (error) => error.code === 'daily_total' && /all the payments/.test(error.message));
});

// ---------------------------------------------------------------- the archive
const filesOf = async (directory) => (await readdir(directory)).sort();
const linesOf = async (directory, name) => (await readFile(path.join(directory, name), 'utf8')).split('\n').filter(Boolean);

test('the archive: files of a fixed number of blocks, the last one written again as it grows, each written whole', async (t) => {
  const directory = await temporary(t), node = createFakeRegtest(), rpc = clientOf(node);
  const archive = createArchive(directory, { chunk: 5 }), chain = createChain({ rpc, archive });
  await archive.prepare();
  assert.equal(await chain.load(), 0);
  const mining = `76a914${'11'.repeat(20)}88ac`, to = await scriptToAddress(mining, 'regtest');
  await rpc.call('generatetoaddress', [3, to]);
  assert.deepEqual(await chain.follow(), { height: 3, fork: null, restored: 0, archiveFault: null });
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt']);
  assert.deepEqual(await linesOf(directory, 'blocks-00000001.txt'), [1, 2, 3].map((height) => node.blockAt(height).hex));
  // The same file again, longer; then it is full and the next one begins.
  await rpc.call('generatetoaddress', [1, to]); await chain.follow();
  assert.equal((await linesOf(directory, 'blocks-00000001.txt')).length, 4);
  await rpc.call('generatetoaddress', [1, to]); await chain.follow();
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt']);
  assert.equal((await linesOf(directory, 'blocks-00000001.txt')).length, 5);
  await rpc.call('generatetoaddress', [1, to]); await chain.follow();
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt', 'blocks-00000006.txt']);
  // Many blocks at once (a chain read for the first time): every file but the last is full.
  await rpc.call('generatetoaddress', [11, to]); await chain.follow();
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt', 'blocks-00000006.txt', 'blocks-00000011.txt', 'blocks-00000016.txt']);
  assert.deepEqual(await Promise.all((await filesOf(directory)).map(async (name) => (await linesOf(directory, name)).length)), [5, 5, 5, 2]);
  const all = [];
  for await (const block of archive.blocks()) all.push(block);
  assert.deepEqual(all.map((block) => block.height), Array.from({ length: 17 }, (unused, index) => index + 1));
  assert.deepEqual(all.map((block) => block.hex), all.map((block) => node.blockAt(block.height).hex), 'in the chain\'s order, byte for byte');
  assert.equal(chain.bestHash(), node.tip());
  assert.equal(chain.hashAt(0), REGTEST_GENESIS);
  // Nothing is written when nothing is new.
  const before = (await stat(path.join(directory, 'blocks-00000016.txt'))).mtimeMs;
  await new Promise((resolve) => setTimeout(resolve, 20));
  await chain.follow();
  assert.equal((await stat(path.join(directory, 'blocks-00000016.txt'))).mtimeMs, before);
  // What a run that was cut short left under a temporary name is removed, and never read as a block file.
  await writeFile(path.join(directory, 'blocks-00000016.txt.4242.tmp'), 'half a block');
  await archive.prepare();
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt', 'blocks-00000006.txt', 'blocks-00000011.txt', 'blocks-00000016.txt']);
});

test('the archive: a new node is handed every block in order, and stands on the same best block', async (t) => {
  const directory = await temporary(t), first = createFakeRegtest({ name: 'first' }), to = await scriptToAddress(`76a914${'11'.repeat(20)}88ac`, 'regtest');
  const before = createChain({ rpc: clientOf(first), archive: createArchive(directory, { chunk: 5 }) });
  await clientOf(first).call('generatetoaddress', [13, to]); await before.follow();

  const second = createFakeRegtest({ name: 'second' }), rpc = clientOf(second), log = createLog();
  const chain = createChain({ rpc, archive: createArchive(directory, { chunk: 5 }), log });
  assert.equal(await chain.load(), 13);
  assert.deepEqual(await chain.follow({ refuseForeign: true }), { height: 13, fork: null, restored: 13, archiveFault: null });
  const submitted = second.calls.filter(([method]) => method === 'submitblock').map(([, params]) => params[0]);
  assert.deepEqual(submitted, Array.from({ length: 13 }, (unused, index) => first.blockAt(index + 1).hex), 'every block, lowest first');
  assert.equal(second.tip(), first.tip());
  assert.equal(log.said(/REORGANISATION/).length, 0);
  // It goes on from there: the next block is the fourteenth, in the third file.
  await rpc.call('generatetoaddress', [1, to]); await chain.follow();
  assert.equal((await linesOf(directory, 'blocks-00000011.txt')).length, 4);

  // A node that lost its newest blocks (killed before it wrote them to its disk) gets them back, before anything is read from it.
  second.forget(6);
  const calls = second.calls.length;
  assert.deepEqual(await chain.follow(), { height: 14, fork: null, restored: 6, archiveFault: null });
  assert.deepEqual(second.calls.slice(calls).filter(([method]) => method === 'submitblock').length, 6);
  assert.equal(second.height(), 14);
  assert.equal(chain.bestHash(), second.tip());
  assert.equal(log.said(/REORGANISATION/).length, 0);
});

test('the archive: a reorganisation of the node is believed, and the files are rewritten from the first block that differs', async (t) => {
  const directory = await temporary(t), node = createFakeRegtest(), rpc = clientOf(node), log = createLog();
  const archive = createArchive(directory, { chunk: 5 }), chain = createChain({ rpc, archive, log });
  const to = await scriptToAddress(`76a914${'11'.repeat(20)}88ac`, 'regtest');
  await rpc.call('generatetoaddress', [13, to]); await chain.follow();
  const kept = await linesOf(directory, 'blocks-00000006.txt');
  // The node leaves its newest five blocks (9 to 13) for seven others (9 to 15).
  node.reorganise(5, 7);
  assert.deepEqual(await chain.follow(), { height: 15, fork: 8, restored: 0, archiveFault: null });
  assert.deepEqual(log.said(/REORGANISATION/).map((line) => [line.level, line.last_common_height, line.blocks_dropped, line.node_height]), [['error', 8, 5, 15]]);
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt', 'blocks-00000006.txt', 'blocks-00000011.txt']);
  const rewritten = await linesOf(directory, 'blocks-00000006.txt');
  assert.deepEqual(rewritten.slice(0, 3), kept.slice(0, 3), 'heights 6 to 8 are the blocks they were');
  assert.notDeepEqual(rewritten.slice(3), kept.slice(3));
  const all = [];
  for await (const block of archive.blocks()) all.push(block.hex);
  assert.deepEqual(all, Array.from({ length: 15 }, (unused, index) => node.blockAt(index + 1).hex));
  // A shorter chain that differs: the files above it go.
  node.reorganise(12, 1);
  assert.deepEqual(await chain.follow(), { height: 4, fork: 3, restored: 0, archiveFault: null });
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt']);
  assert.deepEqual(await linesOf(directory, 'blocks-00000001.txt'), [1, 2, 3, 4].map((height) => node.blockAt(height).hex));
  // A fork at the first line of a file: that file holds the new block, and nothing of the old one.
  await rpc.call('generatetoaddress', [2, to]); await chain.follow();
  const left = node.blockAt(6).hex;
  node.reorganise(1, 1);
  assert.deepEqual(await chain.follow(), { height: 6, fork: 5, restored: 0, archiveFault: null });
  assert.deepEqual(await linesOf(directory, 'blocks-00000006.txt'), [node.blockAt(6).hex]);
  assert.notEqual(node.blockAt(6).hex, left);
  assert.equal((await linesOf(directory, 'blocks-00000001.txt')).length, 5);
});

test('the archive: the files of another chain are refused at a start and left as they are; a gap or a bad line stops the reading', async (t) => {
  const directory = await temporary(t), first = createFakeRegtest({ name: 'first' }), to = await scriptToAddress(`76a914${'11'.repeat(20)}88ac`, 'regtest');
  const before = createChain({ rpc: clientOf(first), archive: createArchive(directory, { chunk: 5 }) });
  await clientOf(first).call('generatetoaddress', [7, to]); await before.follow();
  const files = await Promise.all((await filesOf(directory)).map((name) => readFile(path.join(directory, name), 'utf8')));
  // A node with a chain of its own, and the archive of another.
  const other = createFakeRegtest({ name: 'other' });
  await clientOf(other).call('generatetoaddress', [3, to]);
  const chain = createChain({ rpc: clientOf(other), archive: createArchive(directory, { chunk: 5 }) });
  await chain.load();
  await assert.rejects(chain.follow({ refuseForeign: true }), /another chain than the Bitcoin node's: nothing was overwritten/);
  assert.deepEqual(await Promise.all((await filesOf(directory)).map((name) => readFile(path.join(directory, name), 'utf8'))), files);
  assert.equal(other.calls.filter(([method]) => method === 'submitblock').length, 0);

  // A file missing in between, a file that is not the last and not full, a line that is no block, a block out of place.
  const broken = async (change, pattern) => {
    const copy = await temporary(t);
    for (const [index, name] of ['blocks-00000001.txt', 'blocks-00000006.txt'].entries()) await writeFile(path.join(copy, name), files[index]);
    await change(copy);
    await assert.rejects(createChain({ rpc: clientOf(createFakeRegtest()), archive: createArchive(copy, { chunk: 5 }) }).load(), pattern);
  };
  await broken((copy) => rm(path.join(copy, 'blocks-00000001.txt')), /no file blocks-00000001.txt before blocks-00000006.txt/);
  await broken((copy) => writeFile(path.join(copy, 'blocks-00000001.txt'), files[0].split('\n').slice(0, 3).join('\n') + '\n'), /holds 3 blocks and is not the last/);
  await broken((copy) => writeFile(path.join(copy, 'blocks-00000006.txt'), 'not a block\n'), /not a list of at most 5 blocks/);
  await broken((copy) => writeFile(path.join(copy, 'blocks-00000006.txt'), files[1].split('\n').reverse().filter(Boolean).join('\n') + '\n'), /height 6 is not a block of its chain/);
  await broken((copy) => writeFile(path.join(copy, 'blocks-00000006.txt'), files[1].slice(0, -1)), /does not end with a line break/);
});

test('the archive: a file that cannot be written does not stop the chain, and is written when it can be', async (t) => {
  const directory = await temporary(t), node = createFakeRegtest(), rpc = clientOf(node), to = await scriptToAddress(`76a914${'11'.repeat(20)}88ac`, 'regtest');
  const real = createArchive(directory, { chunk: 5 });
  let failing = true;
  const archive = { ...real, write: async (...given) => { if (failing) throw new Error('ENOSPC: no space left on device'); return real.write(...given); } };
  const chain = createChain({ rpc, archive });
  await rpc.call('generatetoaddress', [7, to]);
  assert.deepEqual(await chain.follow(), { height: 7, fork: null, restored: 0, archiveFault: 'ENOSPC: no space left on device' });
  assert.equal(chain.bestHash(), node.tip(), 'the chain is followed all the same');
  assert.deepEqual(await filesOf(directory), []);
  await rpc.call('generatetoaddress', [1, to]);
  failing = false;
  assert.deepEqual(await chain.follow(), { height: 8, fork: null, restored: 0, archiveFault: null });
  assert.deepEqual(await Promise.all((await filesOf(directory)).map(async (name) => (await linesOf(directory, name)).length)), [5, 3]);
});

// ---------------------------------------------------------------- the service: its start
test('the service starts a new chain with 101 blocks, keeps the wallet\'s keys in the archive, and mines one block a round', async (t) => {
  const directory = await temporary(t);
  const { service, node, block, log } = await serviceOn(t, { archive: createArchive(directory) });
  assert.deepEqual(service.started, { archived: 0, restored: 0, wallet: 'made', height: 101, balance_sats: '5000000000' });
  assert.deepEqual(node.wallets(), ['test']);
  assert.deepEqual(await filesOf(directory), ['blocks-00000001.txt', 'wallet.json']);
  const wallet = JSON.parse(await readFile(path.join(directory, 'wallet.json'), 'utf8'));
  assert.equal(wallet.format, 'time-test-bitcoin-wallet-1');
  assert.equal(wallet.descriptors.length, 8);
  assert.ok(wallet.descriptors.every((entry) => /^(?:pkh|wpkh|tr|sh\(wpkh)\(tprv/.test(entry.desc)), 'with the private keys');
  if (process.platform !== 'win32') assert.equal((await stat(path.join(directory, 'wallet.json'))).mode & 0o777, 0o600);
  // The mining address is of a form no tester is given.
  const mining = node.calls.find(([method]) => method === 'generatetoaddress')[1][1];
  assert.match(mining, /^2/);
  await block(); await block();
  assert.equal(node.height(), 103);
  assert.equal(service.chain.height(), 103);
  assert.equal((await linesOf(directory, 'blocks-00000001.txt')).length, 103);
  assert.deepEqual(node.calls.filter(([method]) => method === 'generatetoaddress').map(([, params]) => params[0]), [101, 1, 1], 'one block a round, never more');
  assert.ok(node.methodsCalled().every((method) => METHODS.includes(method)));
  assert.equal(log.lines.filter((line) => line.level === 'error').length, 0);
  // No line of the log holds a key.
  assert.ok(!JSON.stringify(log.lines).includes('tprv'));
});

test('a new machine: a second node with the same archive stands on the same block, holds the same coins and knows the same addresses', async (t) => {
  const directory = await temporary(t);
  const one = await serviceOn(t, { archive: createArchive(directory, { chunk: 50 }), addressesPerCallerPerDay: 100 });
  const address = await newAddress(one.service), taproot = await newAddress(one.service, 'p2tr');
  // Twenty more addresses that nobody pays, then one that is paid: further along than a wallet looks ahead by itself.
  for (let i = 0; i < 19; i++) await newAddress(one.service);
  const far = await newAddress(one.service);
  assert.equal((await pay(one.service, address, 12_345)).status, 200);
  assert.equal((await pay(one.service, taproot, 700)).status, 200);
  assert.equal((await pay(one.service, far, 5000)).status, 200);
  assert.equal((await pay(one.service, await foreign('7a'), 40_000)).status, 200);
  await one.block(); await one.block();
  const status = (await call(one.service, '/v1/status')).body, seen = (await call(one.service, `/v1/addresses/${address}`)).body;
  assert.equal(seen.received_sats, '12345');
  await one.service.close();

  const node = createFakeRegtest({ name: 'new-machine' });
  const two = await serviceOn(t, { node, archive: createArchive(directory, { chunk: 50 }) });
  assert.deepEqual(two.service.started, { archived: 103, restored: 103, wallet: 'restored', height: 103, balance_sats: status.balance_sats });
  assert.equal(two.log.said(/wallet of the archive was put into it/).length, 1);
  assert.equal(two.log.said(/blocks it lacked were handed to it/).length, 1);
  const again = (await call(two.service, '/v1/status')).body;
  assert.deepEqual([again.height, again.best_hash, again.balance_sats], [status.height, status.best_hash, status.balance_sats]);
  assert.equal(node.tip(), one.node.tip());
  assert.deepEqual((await call(two.service, `/v1/addresses/${address}`)).body, { ...seen, payments: seen.payments });
  assert.equal((await call(two.service, `/v1/addresses/${taproot}`)).body.received_sats, '700');
  assert.equal((await call(two.service, `/v1/addresses/${far}`)).body.received_sats, '5000');
  // The wallet was imported before the first block was handed over, from the first block on, and past the last address the file knew.
  const calls = node.calls.map(([method]) => method);
  assert.ok(calls.indexOf('importdescriptors') < calls.indexOf('submitblock'));
  assert.ok(node.imported.every((entry) => entry.timestamp === 0 && entry.active === true && entry.range[0] === 0 && entry.range[1] >= entry.next_index + 1000));
  assert.equal(node.imported.find((entry) => /^wpkh/.test(entry.desc) && !entry.internal).next_index, 21);
  assert.deepEqual(node.calls.filter(([method]) => method === 'generatetoaddress'), [], 'nothing was mined at the start: the chain is the one that was');
  // An address made now is not one that was given out before.
  const fresh = await newAddress(two.service);
  assert.ok(![address, far].includes(fresh));
  assert.deepEqual((await readdir(directory)).filter((name) => /replaced/.test(name)), [], 'the wallet of the archive is the node\'s wallet');
  await two.block();
  assert.equal(node.height(), 104);
});

test('a chain whose newest block is older than a pace gets its next block before the service says it is ready', async (t) => {
  const directory = await temporary(t);
  const one = await serviceOn(t, { archive: createArchive(directory) });
  await one.block();
  assert.equal((await call(one.service, '/v1/health')).status, 200);
  await one.service.close();
  // An hour later, on a new machine.
  const node = createFakeRegtest({ name: 'an-hour-later' });
  const two = await serviceOn(t, { node, archive: createArchive(directory), at: START + 3_600_000 });
  assert.deepEqual([two.service.started.archived, two.service.started.restored, two.service.started.height], [102, 102, 102], 'what was found');
  assert.deepEqual(node.calls.filter(([method]) => method === 'generatetoaddress').map(([, params]) => params[0]), [1], 'one block, on top of the chain that was');
  assert.equal(node.blockAt(102).hash, one.node.tip());
  const health = await call(two.service, '/v1/health');
  assert.deepEqual([health.status, health.body.status, health.body.height, health.body.seconds_since_block], [200, 'ok', 103, 0]);
  assert.equal((await call(two.service, '/v1/status')).body.seconds_to_next_block, 20, 'and the next one a pace later');
});

test('blocks without the keys of their coins, or the wallet of another chain: the service says so and does not start', async (t) => {
  const directory = await temporary(t);
  const one = await serviceOn(t, { archive: createArchive(directory) });
  await one.service.close();
  await rm(path.join(directory, 'wallet.json'));
  const node = createFakeRegtest({ name: 'second' });
  await assert.rejects(serviceOn(t, { node, archive: createArchive(directory) }), /holds blocks and no wallet\.json/);
  assert.deepEqual(node.wallets(), [], 'said before a wallet was made');
  assert.equal(node.height(), 0);
  // A node that is not on regtest is asked what its chain is, and nothing else.
  const main = createFakeRegtest({ name: 'main' }); main.chain = 'main';
  await assert.rejects(serviceOn(t, { node: main }), refused('WRONG_CHAIN'));
  assert.deepEqual(main.methodsCalled(), ['getblockchaininfo']);
});

// ---------------------------------------------------------------- the service: its routes
test('status and health say what the service gives and whether it works', async (t) => {
  const { service, node, clock, block } = await serviceOn(t);
  const status = await call(service, '/v1/status');
  assert.equal(status.status, 200);
  assert.deepEqual(status.body, {
    network: 'regtest', height: 101, best_hash: node.tip(), block_seconds: 20, seconds_to_next_block: 20, max_payment_sats: '5000000', per_caller_per_day_sats: '100000000', left_today_for_caller_sats: '100000000',
    balance_sats: '5000000000', paying: true, addresses_per_caller_per_day: 20, notice: status.body.notice,
  });
  assert.match(status.body.notice, /worth nothing/);
  assert.equal(status.headers['cache-control'], 'no-store');
  assert.equal(status.headers['content-security-policy'], "default-src 'none'; frame-ancestors 'none'");
  assert.equal(status.headers['x-content-type-options'], 'nosniff');
  assert.equal(status.headers['access-control-allow-origin'], undefined);
  clock.at += 7000;
  assert.equal((await call(service, '/v1/status')).body.seconds_to_next_block, 13);
  const health = await call(service, '/v1/health');
  assert.deepEqual([health.status, health.body], [200, { status: 'ok', network: 'regtest', height: 101, seconds_since_block: 7, block_seconds: 20, balance_sats: '5000000000', archive: 'none', node_restarts: 0 }]);

  // The node stops answering: the round fails, and after three paces without a block the health answer says so.
  node.fault = 'silent';
  await block(13);
  assert.deepEqual([(await call(service, '/v1/health')).status, (await call(service, '/v1/health')).body.status], [503, 'node_unreachable']);
  assert.equal((await pay(service, await foreign('7a'), 1000)).body.error.code, 'node_unavailable');
  node.fault = null;
  await block();
  assert.equal((await call(service, '/v1/health')).body.status, 'ok');
  assert.equal(node.height(), 102);
  clock.at += 61_000;
  assert.deepEqual([(await call(service, '/v1/health')).status, (await call(service, '/v1/health')).body.status], [503, 'no_new_block']);
  assert.equal((await call(service, '/v1/status')).body.paying, false);
  // A node of another network in its place: nothing is mined on it, and the health answer names it.
  node.chain = 'main'; node.fault = 'silent'; await block(); node.fault = null;
  const before = node.calls.length;
  await block();
  assert.equal((await call(service, '/v1/health')).body.status, 'not_regtest');
  assert.deepEqual(node.calls.slice(before).map(([method]) => method), ['getblockchaininfo']);
});

test('a receiving address is the wallet\'s own, of the form asked for, and only such an address is shown', async (t) => {
  const { service, node, block } = await serviceOn(t);
  const made = await call(service, '/v1/addresses', { method: 'POST' });
  assert.equal(made.status, 200);
  assert.deepEqual([made.body.form, await addressToScript(made.body.address, 'regtest').then((script) => script.slice(0, 4))], ['p2wpkh', '0014']);
  assert.match(made.body.note, /cannot be spent by you/);
  const taproot = await call(service, '/v1/addresses', { method: 'POST', json: { form: 'p2tr' } });
  assert.match(taproot.body.address, /^bcrt1p/);
  assert.deepEqual(Object.keys(ADDRESS_FORMS), ['p2wpkh', 'p2tr']);
  for (const json of [{ form: 'p2pkh' }, { form: 'P2TR' }, { form: 'p2tr', label: 'x' }, { kind: 'p2tr' }]) assert.equal((await call(service, '/v1/addresses', { method: 'POST', json })).body.error.code, 'invalid_body', JSON.stringify(json));
  assert.deepEqual(node.calls.filter(([method]) => method === 'getnewaddress').map(([, params]) => params), [['mining', 'p2sh-segwit'], ['tester', 'bech32'], ['tester', 'bech32m']]);

  const address = made.body.address;
  const empty = await call(service, `/v1/addresses/${address}`);
  assert.deepEqual([empty.status, empty.body], [200, { address, form: 'p2wpkh', received_sats: '0', unconfirmed_sats: '0', payments: [], height: 101, notice: empty.body.notice }]);
  const first = (await pay(service, address, 20_000)).body.txid;
  const waiting = (await call(service, `/v1/addresses/${address}`)).body;
  assert.deepEqual([waiting.received_sats, waiting.unconfirmed_sats, waiting.payments], ['0', '20000', [{ txid: first, sats: '20000', height: null, confirmations: 0 }]]);
  await block();
  const second = (await pay(service, address, 333)).body.txid;
  await block(); await block();
  const third = (await pay(service, address, 1000)).body.txid;
  const seen = (await call(service, `/v1/addresses/${address}`)).body;
  assert.deepEqual([seen.received_sats, seen.unconfirmed_sats, seen.height], ['20333', '1000', 104]);
  assert.deepEqual(seen.payments, [{ txid: third, sats: '1000', height: null, confirmations: 0 }, { txid: second, sats: '333', height: 103, confirmations: 2 }, { txid: first, sats: '20000', height: 102, confirmations: 3 }], 'the newest first');

  // Not the wallet's: an address of someone else, the wallet's own mining address, its change, an address of another network, and no address at all.
  const mining = node.calls.find(([method]) => method === 'generatetoaddress')[1][1];
  const change = await scriptToAddress(transactionOutputs(node.blockAt(102).transactions[1])[1].script, 'regtest');
  assert.equal((await call(service, `/v1/addresses/${await foreign('7a')}`)).body.error.code, 'unknown_address');
  assert.deepEqual([(await call(service, `/v1/addresses/${mining}`)).status, (await call(service, `/v1/addresses/${mining}`)).body.error.code], [404, 'unknown_address']);
  assert.equal((await call(service, `/v1/addresses/${change}`)).body.error.code, 'unknown_address', 'the wallet\'s own change is not an address a tester was given');
  assert.deepEqual([(await call(service, '/v1/addresses/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).status, (await call(service, '/v1/addresses/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).body.error.code], [400, 'invalid_address']);
  assert.match((await call(service, '/v1/addresses/bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')).body.error.message, /mainnet/);
  assert.equal((await call(service, '/v1/addresses/short')).body.error.code, 'invalid_address');
  // Only an address the codec took was ever shown to the node.
  for (const [, params] of node.calls.filter(([method]) => method === 'getaddressinfo')) await addressToScript(params[0], 'regtest');
});

test('a payment arrives whole, at an address of the test chain only, within the limits', async (t) => {
  const { service, node, block } = await serviceOn(t, { maxPaymentSats: 50_000n, perCallerPerDaySats: 120_000n, paymentsPerCallerPerHour: 6, totalPerDaySats: 1_000_000n });
  const target = await foreign('7a');
  const paid = await pay(service, target, 12_345);
  assert.equal(paid.status, 200);
  assert.deepEqual(paid.body, { txid: paid.body.txid, address: target, sats: '12345', seconds_to_next_block: 20, notice: paid.body.notice });
  assert.match(paid.body.txid, /^[0-9a-f]{64}$/);
  // What the node was told: the amount in bitcoin as text, nothing that takes the fee out of it, a fee rate and a
  // ceiling that keep the transaction small, and nothing the caller wrote but the address.
  const sent = node.calls.find(([method]) => method === 'send');
  assert.deepEqual(sent, ['send', { outputs: [{ [target]: '0.00012345' }], fee_rate: 31, options: { max_tx_weight: 4000 } }, 'test']);
  assert.deepEqual(node.waiting(), [paid.body.txid]);
  assert.equal((await call(service, '/v1/status')).body.left_today_for_caller_sats, '107655');
  // Its confirmations, as they come.
  assert.deepEqual((await call(service, `/v1/payments/${paid.body.txid}`)).body, { txid: paid.body.txid, confirmations: 0, height: null, seconds_to_next_block: 20 });
  await block();
  assert.deepEqual((await call(service, `/v1/payments/${paid.body.txid.toUpperCase()}`)).body, { txid: paid.body.txid, confirmations: 1, height: 102, seconds_to_next_block: 20 });
  await block(); await block();
  assert.equal((await call(service, `/v1/payments/${paid.body.txid}`)).body.confirmations, 3);
  assert.deepEqual([(await call(service, `/v1/payments/${'ab'.repeat(32)}`)).status, (await call(service, `/v1/payments/${'ab'.repeat(32)}`)).body.error.code], [404, 'not_found']);
  assert.equal((await call(service, '/v1/payments/xyz')).body.error.code, 'invalid_txid');

  // Every form of address the market takes is paid; an all-capitals address is the same address.
  for (const [form, byte] of [['76a914', 'b1'], ['a914', 'b2'], ['0020', 'b3'], ['5120', 'b4']]) {
    const script = form === '76a914' ? `76a914${byte.repeat(20)}88ac` : form === 'a914' ? `a914${byte.repeat(20)}87` : `${form}${byte.repeat(32)}`;
    assert.equal((await pay(service, await scriptToAddress(script, 'regtest'), 600)).status, 200, form);
  }
  assert.equal((await pay(service, target.toUpperCase(), 600)).body.address, target);

  // What is refused before the node hears of it.
  const calls = node.calls.filter(([method]) => method === 'send').length;
  const refusal = async (address, sats, status, code, pattern = /./) => { const answer = await pay(service, address, sats); assert.deepEqual([answer.status, answer.body.error.code], [status, code], `${address} ${sats}`); assert.match(answer.body.error.message, pattern); };
  await refusal('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 1000, 400, 'invalid_address', /address of Bitcoin mainnet/);
  await refusal('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 1000, 400, 'invalid_address', /testnet3/);
  await refusal(`${target.slice(0, -1)}${target.endsWith('q') ? 'p' : 'q'}`, 1000, 400, 'invalid_address', /checksum/);
  await refusal('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 1000, 400, 'invalid_address');
  await refusal('not-an-address', 1000, 400, 'invalid_address');
  await refusal(target, 0, 400, 'invalid_amount');
  await refusal(target, '-5', 400, 'invalid_amount');
  await refusal(target, '1.5', 400, 'invalid_amount');
  await refusal(target, '0012', 400, 'invalid_amount');
  await refusal(target, 50_001, 400, 'amount_too_large', /at most 50000 satoshis/);
  await refusal(target, 293, 400, 'amount_too_small', /294 satoshis/);
  await refusal(await scriptToAddress(`76a914${'b1'.repeat(20)}88ac`, 'regtest'), 545, 400, 'amount_too_small', /546/);
  for (const json of [{ address: target }, { sats: '1000' }, { address: target, sats: '1000', fee: '1' }, {}]) assert.equal((await call(service, '/v1/payments', { method: 'POST', json })).body.error.code, 'invalid_body');
  assert.equal((await call(service, '/v1/payments', { method: 'POST', body: JSON.stringify({ address: target, sats: 1000 }), headers: { 'Content-Type': 'application/json' } })).body.error.code, 'invalid_body', 'an amount is a string, never a number');
  assert.equal(node.calls.filter(([method]) => method === 'send').length, calls, 'none of these reached the node');

  // The limits of one caller: six payments an hour here (this is the seventh request that would be paid).
  const hourly = await pay(service, target, 600);
  assert.deepEqual([hourly.status, hourly.body.error.code, Number(hourly.headers['retry-after']) > 0], [429, 'caller_limit', true]);
  assert.match(hourly.body.error.message, /6 payments in an hour/);
});

test('the amount a caller gets in a day, the total of all callers, and a caller told apart behind the proxy', async (t) => {
  const { service, clock, block } = await serviceOn(t, { maxPaymentSats: 50_000n, perCallerPerDaySats: 120_000n, totalPerDaySats: 200_000n, trustedProxies: ['127.0.0.1'] });
  const target = await foreign('7a'), from = (address) => ({ 'X-Forwarded-For': address });
  assert.equal((await pay(service, target, 50_000, from('198.51.100.7'))).status, 200);
  assert.equal((await pay(service, target, 50_000, from('198.51.100.7'))).status, 200);
  const over = await pay(service, target, 20_001, from('198.51.100.7'));
  assert.deepEqual([over.status, over.body.error.code], [429, 'caller_limit']);
  assert.match(over.body.error.message, /120000 satoshis in 24 hours/);
  assert.equal((await call(service, '/v1/status', { headers: from('198.51.100.7') })).body.left_today_for_caller_sats, '20000');
  // Another caller behind the same proxy has its own amount; what a caller writes to the left of the proxy's entry is not believed.
  assert.equal((await call(service, '/v1/status', { headers: from('203.0.113.9') })).body.left_today_for_caller_sats, '100000', 'its own 120,000, or what is left of the total');
  assert.equal((await pay(service, target, 20_001, from('203.0.113.9, 198.51.100.7'))).body.error.code, 'caller_limit', 'the rightmost entry is who the proxy saw');
  assert.equal((await pay(service, target, 50_000, from('198.51.100.7, 203.0.113.9'))).status, 200);
  // One IPv6 /64 is one caller.
  assert.equal((await pay(service, target, 30_000, from('2001:db8:1:2::1'))).status, 200);
  assert.equal((await call(service, '/v1/status', { headers: from('2001:db8:1:2:ffff::9') })).body.left_today_for_caller_sats, '20000');
  // The total: 180,000 of 200,000 are given. A payment that would pass it is refused; one that fits is made.
  const total = await pay(service, target, 20_001, from('192.0.2.50'));
  assert.deepEqual([total.status, total.body.error.code], [429, 'daily_total']);
  assert.equal((await pay(service, target, 20_000, from('192.0.2.50'))).status, 200);
  assert.equal((await call(service, '/v1/status', { headers: from('192.0.2.51') })).body.left_today_for_caller_sats, '0');
  // A day later the amounts are free again.
  await block(); clock.at += 86_400_000; await block();
  assert.equal((await call(service, '/v1/status', { headers: from('198.51.100.7') })).body.left_today_for_caller_sats, '120000');
  assert.equal((await pay(service, target, 50_000, from('198.51.100.7'))).status, 200);
});

test('new addresses are counted per caller too', async (t) => {
  const { service } = await serviceOn(t, { addressesPerCallerPerDay: 2 });
  await newAddress(service); await newAddress(service, 'p2tr');
  const third = await call(service, '/v1/addresses', { method: 'POST' });
  assert.deepEqual([third.status, third.body.error.code], [429, 'caller_limit']);
});

test('a wallet that cannot pay says so, and the payment it could not make does not count', async (t) => {
  const { service, node } = await serviceOn(t, { maxPaymentSats: 4_000_000_000n, perCallerPerDaySats: 10_000_000_000n, totalPerDaySats: 20_000_000_000n });
  const target = await foreign('7a');
  // 50 bitcoin can be spent. 40 leave; the next 40 are not there.
  assert.equal((await pay(service, target, 4_000_000_000)).status, 200);
  assert.equal((await call(service, '/v1/status')).body.balance_sats, '999998590', 'what is left, less the fee, as the node counts it');
  const sent = node.calls.filter(([method]) => method === 'send').length;
  const empty = await pay(service, target, 4_000_000_000);
  assert.deepEqual([empty.status, empty.body.error.code], [503, 'wallet_empty']);
  assert.equal(node.calls.filter(([method]) => method === 'send').length, sent);
  assert.deepEqual([(await call(service, '/v1/health')).status, (await call(service, '/v1/health')).body.status], [503, 'wallet_cannot_pay']);
  assert.equal((await call(service, '/v1/status')).body.left_today_for_caller_sats, '6000000000');
  // A smaller payment is still made, and the node's own "insufficient funds" is answered in this service's words.
  assert.equal((await pay(service, target, 900_000_000)).status, 200);
  const short = await pay(service, target, 99_990_000);
  assert.deepEqual([short.status, short.body.error.code], [503, 'wallet_empty']);
  assert.ok(!/Insufficient/i.test(short.text));
});

test('the node\'s own words never reach a caller: a refusal, a tied-up wallet, a payment whose fate is not known', async (t) => {
  const node = createFakeRegtest({ unconfirmedLimit: 2 });
  const { service, block, log } = await serviceOn(t, { node });
  const target = await foreign('7a');
  assert.equal((await pay(service, target, 1000)).status, 200);
  assert.equal((await pay(service, target, 1000)).status, 200);
  const busy = await pay(service, target, 1000);
  assert.deepEqual([busy.status, busy.body.error.code, busy.headers['retry-after']], [503, 'wallet_busy', '21']);
  assert.ok(!/mempool|UTXO/i.test(busy.text), 'this service\'s words, not the node\'s');
  assert.equal(log.said(/refused a payment/).length, 1);
  assert.match(log.said(/refused a payment/)[0].error, /Unconfirmed UTXOs/, 'the node\'s words are in the log');
  assert.equal(log.said(/refused a payment/)[0].rpc_code, -4);
  assert.equal((await call(service, '/v1/status')).body.left_today_for_caller_sats, '99998000', 'a payment the node refused does not count');
  await block();
  assert.equal((await pay(service, target, 1000)).status, 200);
  // No answer at all: it may have been sent. It counts, and the caller is told what is not known.
  node.fault = 'slow';
  const unknown = await pay(service, target, 5000);
  node.fault = null;
  assert.deepEqual([unknown.status, unknown.body.error.code], [503, 'node_unavailable']);
  assert.match(unknown.body.error.message, /not known whether the payment was sent/);
  assert.equal((await call(service, '/v1/status')).body.left_today_for_caller_sats, '99992000');
  // What the node says when it refuses decides the answer; none of its words are in it.
  for (const [words, status, code] of [['Insufficient funds', 503, 'wallet_empty'], ['The inputs size exceeds the maximum weight. Please try sending a smaller amount or manually consolidating your wallet\'s UTXOs', 503, 'wallet_busy'],
    ['Transaction amount too small', 400, 'amount_too_small'], ['Error: something of the node\'s own in /var/lib/time-test-bitcoin/node', 502, 'node_refused']]) {
    node.refuseWith = words;
    const answer = await pay(service, target, 4000);
    assert.deepEqual([answer.status, answer.body.error.code], [status, code], words);
    assert.ok(!answer.text.includes(words) && !/var\/lib|UTXO/.test(answer.text), words);
  }
  node.refuseWith = null;
  assert.equal((await call(service, '/v1/status')).body.left_today_for_caller_sats, '99992000', 'none of them counts');
  // A wallet that made a payment and could not sign it sent nothing: refused, and not counted.
  node.unsigned = true;
  const unsigned = await pay(service, target, 4000);
  node.unsigned = false;
  assert.deepEqual([unsigned.status, unsigned.body.error.code], [502, 'node_refused']);
  assert.equal((await call(service, '/v1/status')).body.left_today_for_caller_sats, '99992000');
  // A node that sends less than it was asked: the log says so in capitals.
  node.shortPay = true;
  assert.equal((await pay(service, target, 2000)).status, 200);
  assert.equal(log.said(/DOES NOT PAY WHAT WAS ASKED/).length, 1);
  node.shortPay = false;
  // A wallet that a restarted node has not loaded is loaded, and the payment made.
  await block();
  node.unload();
  assert.equal((await pay(service, target, 3000)).status, 200);
});

test('from a browser only the listed origins and the service\'s own page may ask; a host it does not know is refused', async (t) => {
  const { service } = await serviceOn(t, { hosts: ['faucet.testnet.example'], origins: ['https://faucet.testnet.example', 'https://wallet.testnet.example'] });
  const port = new URL(service.url).port, own = `http://127.0.0.1:${port}`;
  const target = await foreign('7a');
  // A program on the machine: no Origin, the machine's own name.
  assert.equal((await call(service, '/v1/status')).status, 200);
  assert.equal((await pay(service, target, 1000)).status, 200);
  // The service's own page opened on this machine, and its page behind the proxy under its public name.
  const local = await pay(service, target, 1000, { Origin: own, 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors' });
  assert.deepEqual([local.status, local.headers['access-control-allow-origin']], [200, undefined]);
  const page = await pay(service, target, 1000, { Host: 'faucet.testnet.example', Origin: 'https://faucet.testnet.example', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors' });
  assert.deepEqual([page.status, page.headers['access-control-allow-origin'], page.headers.vary], [200, 'https://faucet.testnet.example', 'Origin']);
  assert.equal((await call(service, '/v1/status', { headers: { Host: 'faucet.testnet.example:443' } })).status, 200);
  // A listed page of another origin: its request is answered with the headers a browser needs, and its preflight too.
  const wallet = await call(service, '/v1/status', { headers: { Host: 'faucet.testnet.example', Origin: 'https://wallet.testnet.example', 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Mode': 'cors' } });
  assert.deepEqual([wallet.status, wallet.headers['access-control-allow-origin'], wallet.headers['access-control-expose-headers']], [200, 'https://wallet.testnet.example', 'Retry-After']);
  const preflight = await call(service, '/v1/payments', { method: 'OPTIONS', headers: { Host: 'faucet.testnet.example', Origin: 'https://wallet.testnet.example', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
  assert.deepEqual([preflight.status, preflight.headers['access-control-allow-methods'], preflight.headers['access-control-allow-headers'], preflight.headers['access-control-allow-origin']], [204, 'GET, POST', 'Content-Type', 'https://wallet.testnet.example']);
  // Any other page, and any way of loading the address into a page of another site.
  for (const headers of [{ Origin: 'https://evil.example' }, { Origin: 'null' }, { Origin: `http://localhost:${port}` }, { Host: 'faucet.testnet.example', Origin: 'http://faucet.testnet.example' }, { Host: 'faucet.testnet.example', Origin: 'https://faucet.testnet.example.evil.example' },
    { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'no-cors', 'Sec-Fetch-Dest': 'image' }, { 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Mode': 'no-cors', 'Sec-Fetch-Dest': 'script' }, { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'iframe' }]) {
    const answer = await call(service, '/v1/status', { headers });
    assert.deepEqual([answer.status, answer.body.error.code, answer.headers['access-control-allow-origin']], [403, 'origin_not_allowed', undefined], JSON.stringify(headers));
  }
  assert.equal((await pay(service, target, 1000, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await call(service, '/v1/payments', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } })).status, 403);
  // A link followed from another site opens the page.
  assert.equal((await call(service, '/', { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } })).status, 200);
  // Another host name: a page of another site cannot reach the service through a name of its own.
  const rebound = await call(service, '/v1/status', { headers: { Host: 'attacker.example' } });
  assert.deepEqual([rebound.status, rebound.body.error.code], [421, 'unknown_host']);
});

test('routes, methods and bodies that are not the service\'s are refused in words, and too many requests of one caller wait', async (t) => {
  const { service } = await serviceOn(t);
  const target = await foreign('7a');
  assert.deepEqual([(await call(service, '/v1/nothing')).status, (await call(service, '/v1/nothing')).body.error.code], [404, 'unknown_route']);
  assert.equal((await call(service, '/v1/status', { base: '' })).body.error.code, 'unknown_route');
  assert.equal((await call(service, '/v1/status', { base: '/bitcoinx' })).body.error.code, 'unknown_route');
  const wrong = await call(service, '/v1/status', { method: 'POST' });
  assert.deepEqual([wrong.status, wrong.headers.allow], [405, 'GET']);
  assert.equal((await call(service, '/v1/payments', { method: 'OPTIONS' })).status, 405);
  assert.equal((await call(service, '/v1/status?x=1')).body.error.code, 'invalid_url');
  assert.equal((await call(service, '/v1/../v1/status')).body.error.code, 'invalid_url');
  assert.equal((await call(service, `/v1/${'a'.repeat(600)}`)).status, 414);
  assert.equal((await call(service, '/v1/payments', { method: 'POST', body: 'address=x', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })).status, 415);
  assert.equal((await call(service, '/v1/payments', { method: 'POST', body: '{', headers: { 'Content-Type': 'application/json' } })).body.error.code, 'invalid_json');
  assert.equal((await call(service, '/v1/payments', { method: 'POST', body: `{"address":"${target}","address":"${target}","sats":"1"}`, headers: { 'Content-Type': 'application/json' } })).body.error.code, 'invalid_body');
  const large = await call(service, '/v1/payments', { method: 'POST', body: JSON.stringify({ address: 'a'.repeat(MAX_BODY_BYTES), sats: '1' }), headers: { 'Content-Type': 'application/json' } });
  assert.deepEqual([large.status, large.body.error.code], [413, 'body_too_large']);

  // Too many requests of one caller: with 5 a second and 20 at once, a GET takes one and a POST ten.
  const limited = await serviceOn(t, { rateLimit: {}, trustedProxies: ['127.0.0.1'] });
  const from = (address) => ({ 'X-Forwarded-For': address });
  assert.equal((await pay(limited.service, target, 1000, from('198.51.100.7'))).status, 200);
  assert.equal((await pay(limited.service, target, 1000, from('198.51.100.7'))).status, 200);
  const third = await pay(limited.service, target, 1000, from('198.51.100.7'));
  assert.deepEqual([third.status, third.body.error.code, third.headers['retry-after']], [429, 'rate_limited', '2']);
  assert.equal((await call(limited.service, '/v1/status', { headers: from('198.51.100.7') })).status, 429);
  // Another caller is not held up by it, and gets twenty GETs at once.
  for (let i = 0; i < 20; i++) assert.equal((await call(limited.service, '/v1/status', { headers: from('203.0.113.9') })).status, 200);
  assert.equal((await call(limited.service, '/v1/status', { headers: from('203.0.113.9') })).status, 429);
  // Two seconds later the first caller has ten tokens again: one POST.
  limited.clock.at += 2000;
  assert.equal((await pay(limited.service, target, 1000, from('198.51.100.7'))).status, 200);
});

test('the page is served under the base path with its files and a strict policy, and takes an address and an amount in its own address', async (t) => {
  const { service } = await serviceOn(t);
  const page = await call(service, '/');
  assert.equal(page.status, 200);
  assert.equal(page.headers['content-type'], 'text/html; charset=utf-8');
  assert.equal(page.headers['content-security-policy'], "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  assert.equal(page.headers['x-frame-options'], 'DENY');
  assert.equal(page.text, await readFile(new URL('../web-v4/test-bitcoin/index.html', import.meta.url), 'utf8'));
  // Every file the page names is served, each from the repository as it is.
  const named = [...page.text.matchAll(/(?:href|src)="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(named.sort(), ['shared/network-menu.js', 'test-bitcoin/app.mjs', 'test-bitcoin/styles.css']);
  for (const [route, file, type] of [['/test-bitcoin/app.mjs', 'test-bitcoin/app.mjs', 'text/javascript; charset=utf-8'], ['/test-bitcoin/styles.css', 'test-bitcoin/styles.css', 'text/css; charset=utf-8'], ['/shared/bitcoin-address.mjs', 'shared/bitcoin-address.mjs', 'text/javascript; charset=utf-8'],
    ['/shared/network-menu.js', 'shared/network-menu.js', 'text/javascript; charset=utf-8'], ['/shared/network-menu.css', 'shared/network-menu.css', 'text/css; charset=utf-8']]) {
    const answer = await call(service, route);
    assert.deepEqual([answer.status, answer.headers['content-type']], [200, type], route);
    assert.equal(answer.text, await readFile(new URL(`../web-v4/${file}`, import.meta.url), 'utf8'), route);
  }
  assert.ok(ROUTES.includes('GET /shared/bitcoin-address.mjs'));
  // The script loads the address codec by the path it has in the repository, which is its path under the base path too.
  assert.match(await readFile(new URL('../web-v4/test-bitcoin/app.mjs', import.meta.url), 'utf8'), /from '\.\.\/shared\/bitcoin-address\.mjs'/);
  const bare = await call(service, '', {});
  assert.deepEqual([bare.status, bare.headers.location], [308, '/bitcoin/']);
  assert.equal((await call(service, '/', { method: 'HEAD' })).text, '');
  assert.equal((await call(service, '/', { method: 'POST' })).status, 405);
  // The page with its pay form filled: an address, an amount, or both, and nothing else.
  const address = await foreign('7a');
  for (const query of [`?address=${address}`, '?sats=12345', `?address=${address}&sats=12345`, `?sats=12345&address=${address}`]) assert.equal((await call(service, `/${query}`)).status, 200, query);
  for (const query of ['?address=', `?address=${address}&address=${address}`, '?sats=1.5', `?address=${address}&sats=1&x=1`, '?next=https://evil.example', '?address=%3Cscript%3E']) assert.equal((await call(service, `/${query}`)).body?.error.code, 'invalid_url', query);
  // Without the page, the routes are the same and the page is not there.
  const bareService = await serviceOn(t, { servePage: false });
  assert.equal((await call(bareService.service, '/')).status, 404);
  assert.equal((await call(bareService.service, '/v1/status')).status, 200);
});

test('the routes answer "starting" until the chain and the wallet are in place, and a second service on the port does not touch its node', async (t) => {
  // A node that does not answer until the test lets it.
  let open;
  const gate = new Promise((resolve) => { open = resolve; }), node = createFakeRegtest(), fetcher = node.fetcher;
  node.fetcher = async (url, init) => { await gate; return fetcher(url, init); };
  const port = await freePort(), at = { url: `http://127.0.0.1:${port}` };
  const starting = createTestBitcoinService({ rpc: clientOf(node, { timeoutMs: 20_000 }), port, autoMine: false, sleep: async () => {} });
  let health = null;
  for (let i = 0; i < 100 && !health; i++) health = await call(at, '/v1/health').catch(() => new Promise((resolve) => setTimeout(() => resolve(null), 20)));
  assert.deepEqual([health.status, health.body.status, health.body.seconds_since_block], [503, 'starting', null]);
  for (const [route, options] of [['/v1/status', {}], ['/v1/addresses', { method: 'POST' }], [`/v1/payments/${'ab'.repeat(32)}`, {}]]) {
    const answer = await call(at, route, options);
    assert.deepEqual([answer.status, answer.body.error.code, answer.headers['retry-after']], [503, 'starting', '5'], route);
  }
  assert.equal((await call(at, '/')).status, 200, 'the page is there already');
  // A second service on the same port stops at the port: it neither starts a node nor stops one.
  const other = createFakeRegtest({ name: 'other' }), touched = [];
  const runner = { start: async () => { touched.push('start'); }, stop: async () => { touched.push('stop'); }, ensure() {}, restarts: () => 0 };
  await assert.rejects(createTestBitcoinService({ rpc: clientOf(other), port, autoMine: false, runner }), /EADDRINUSE/);
  assert.deepEqual([other.calls.length, touched.includes('start')], [0, false]);
  open();
  const service = await starting;
  t.after(() => service.close());
  assert.deepEqual([(await call(service, '/v1/health')).status, (await call(service, '/v1/status')).status], [200, 200]);
});

// ---------------------------------------------------------------- the config
const OWN = { bitcoind_program: path.resolve('/opt/bitcoin/bitcoin-32.1/bin/bitcoind'), bitcoin_data_directory: path.resolve('/var/lib/time-test-bitcoin/node') };
test('a config: the defaults, and every setting written out', async () => {
  const filled = validateConfig(OWN);
  assert.deepEqual(filled, {
    ...OWN, bitcoin_rpc_port: 18443, wallet: 'test', block_seconds: 20, base_path: '/bitcoin', max_payment_sats: 5_000_000n, per_caller_per_day_sats: 100_000_000n, total_per_day_sats: 20_000_000_000n,
    payments_per_caller_per_hour: 30, total_payments_per_day: 10000, addresses_per_caller_per_day: 20, total_addresses_per_day: 5000, host: '127.0.0.1', port: 8960, hosts: [], origins: [], rate_limit: { per_second: 5, burst: 20 }, trusted_proxies: [],
    rpc_timeout_seconds: 15, serve_page: true,
  });
  // The example of the README is a config, with every setting.
  const example = JSON.parse(await readFile(new URL('../deploy/test-bitcoin/config.example.json', import.meta.url), 'utf8'));
  const read = validateConfig(example);
  assert.deepEqual(Object.keys(example).sort(), ['addresses_per_caller_per_day', 'archive_directory', 'base_path', 'bitcoin_data_directory', 'bitcoin_rpc_port', 'bitcoind_program', 'block_seconds', 'data_directory', 'host', 'hosts', 'max_payment_sats', 'origins',
    'payments_per_caller_per_hour', 'per_caller_per_day_sats', 'port', 'rate_limit', 'rpc_timeout_seconds', 'serve_page', 'total_addresses_per_day', 'total_payments_per_day', 'total_per_day_sats', 'trusted_proxies', 'wallet']);
  const apart = { archive_directory: undefined, data_directory: undefined, hosts: undefined, origins: undefined, trusted_proxies: undefined };
  assert.deepEqual({ ...read, ...apart }, { ...filled, bitcoind_program: read.bitcoind_program, bitcoin_data_directory: read.bitcoin_data_directory, ...apart }, 'apart from the directories and the public names, the example states the defaults');
  assert.deepEqual([read.hosts, read.origins, read.trusted_proxies], [['faucet.testnet.example'], ['https://faucet.testnet.example'], ['127.0.0.1']]);
  // A node that already runs.
  const other = validateConfig({ bitcoin_node: { url: 'http://127.0.0.1:18443', cookie_file: path.resolve('/var/lib/bitcoind/regtest/.cookie') } });
  assert.deepEqual(other.bitcoin_node, { url: 'http://127.0.0.1:18443/', cookie_file: path.resolve('/var/lib/bitcoind/regtest/.cookie') });
  assert.equal(other.bitcoind_program, undefined);
});

test('a config that is not right is refused, and no message repeats a value of it', () => {
  const refusedFor = (config, pattern) => assert.throws(() => validateConfig(config), (error) => pattern.test(error.message), JSON.stringify(config));
  refusedFor(null, /JSON object/); refusedFor([], /JSON object/);
  refusedFor({ ...OWN, block_secs: 20 }, /Unknown config setting \(1\)/);
  assert.throws(() => validateConfig({ ...OWN, 'hunter2-secret': true }), (error) => !error.message.includes('hunter2'));
  // The node: one or the other.
  refusedFor({}, /either bitcoind_program/);
  refusedFor({ ...OWN, bitcoin_node: { url: 'http://127.0.0.1:18443/', cookie_file: path.resolve('/c') } }, /not both/);
  refusedFor({ bitcoind_program: OWN.bitcoind_program }, /go together/);
  refusedFor({ ...OWN, bitcoind_program: 'bitcoind' }, /bitcoind_program is an absolute path/);
  refusedFor({ ...OWN, bitcoin_data_directory: 'data' }, /absolute path/);
  refusedFor({ ...OWN, bitcoin_rpc_port: 80 }, /bitcoin_rpc_port/);
  refusedFor({ ...OWN, rpc_port: 18443 }, /Unknown config setting/);
  refusedFor({ bitcoin_node: { url: 'http://127.0.0.1:18443/', cookie_file: path.resolve('/c') }, bitcoin_rpc_port: 18443 }, /bitcoin_rpc_port is the port of a node this service runs/);
  for (const url of ['https://bitcoin.example/', 'http://10.0.0.5:18443/', 'http://user:pw@127.0.0.1:18443/', 'http://127.0.0.1:18443/wallet/x', 'nonsense', 5]) refusedFor({ bitcoin_node: { url, cookie_file: path.resolve('/c') } }, /bitcoin_node\.url/);
  refusedFor({ bitcoin_node: { url: 'http://127.0.0.1:18443/', cookie_file: 'cookie' } }, /cookie_file/);
  refusedFor({ bitcoin_node: { url: 'http://127.0.0.1:18443/', cookie_file: path.resolve('/c'), password: 'x' } }, /takes url and cookie_file/);
  // The pace, the wallet, the path.
  for (const seconds of [4, 601, 20.5, '20']) refusedFor({ ...OWN, block_seconds: seconds }, /block_seconds is a whole number from 5 to 600/);
  for (const wallet of ['', 'Test', '../x', 'a b', 5]) refusedFor({ ...OWN, wallet }, /wallet is the name/);
  for (const base of ['bitcoin', '/bitcoin/', '/Bitcoin', '/a/../b', '/a b', 5]) refusedFor({ ...OWN, base_path: base }, /base_path/);
  assert.equal(validateConfig({ ...OWN, base_path: '' }).base_path, '');
  // Amounts are decimal strings, never numbers, and stand in order.
  for (const value of [5000000, '0', '-1', '1.5', '05', '']) refusedFor({ ...OWN, max_payment_sats: value }, /max_payment_sats is a whole number of satoshis/);
  refusedFor({ ...OWN, max_payment_sats: '545' }, /below the smallest amount/);
  refusedFor({ ...OWN, per_caller_per_day_sats: '4999999' }, /below one payment/);
  refusedFor({ ...OWN, total_per_day_sats: '99999999' }, /below per_caller_per_day_sats/);
  refusedFor({ ...OWN, payments_per_caller_per_hour: 0 }, /payments_per_caller_per_hour/);
  refusedFor({ ...OWN, addresses_per_caller_per_day: '20' }, /addresses_per_caller_per_day/);
  // The listening side.
  refusedFor({ ...OWN, port: 80 }, /port is a whole number/);
  refusedFor({ ...OWN, hosts: ['Faucet.Example'] }, /hosts lists/);
  refusedFor({ ...OWN, hosts: 'faucet.example' }, /hosts lists/);
  // The origins of pages, each whole; and the page's own origin among them when the page is served under a public name.
  for (const origins of [['faucet.example'], ['https://faucet.example/'], ['https://*.example'], ['https://faucet.example/bitcoin'], 'https://faucet.example', [5]]) refusedFor({ ...OWN, origins }, /origins lists exact origins/);
  refusedFor({ ...OWN, hosts: ['faucet.example'] }, /origins lists no origin under one of those names/);
  refusedFor({ ...OWN, hosts: ['faucet.example'], origins: ['https://wallet.example'] }, /origins lists no origin under one of those names/);
  assert.deepEqual(validateConfig({ ...OWN, hosts: ['faucet.example'], origins: ['https://faucet.example', 'https://wallet.example'] }).origins, ['https://faucet.example', 'https://wallet.example']);
  assert.deepEqual(validateConfig({ ...OWN, hosts: ['faucet.example'], serve_page: false }).origins, []);
  refusedFor({ ...OWN, data_directory: 'data' }, /data_directory is an absolute path/);
  assert.equal(validateConfig({ ...OWN, data_directory: path.resolve('/var/lib/time-test-bitcoin/service') }).data_directory, path.resolve('/var/lib/time-test-bitcoin/service'));
  refusedFor({ ...OWN, trusted_proxies: ['proxy.example'] }, /trusted_proxies/);
  refusedFor({ ...OWN, rate_limit: { per_minute: 5 } }, /rate_limit takes/);
  refusedFor({ ...OWN, rate_limit: { per_second: 10, burst: 5 } }, /rate_limit\.burst/);
  refusedFor({ ...OWN, serve_page: 'yes' }, /serve_page/);
  // The archive is a directory of its own.
  refusedFor({ ...OWN, archive_directory: 'archive' }, /absolute path/);
  refusedFor({ ...OWN, archive_directory: path.join(OWN.bitcoin_data_directory, 'archive') }, /neither inside the other/);
  refusedFor({ ...OWN, archive_directory: path.dirname(OWN.bitcoin_data_directory) }, /neither inside the other/);
  refusedFor({ ...OWN, archive_directory: OWN.bitcoin_data_directory }, /neither inside the other/);
  assert.equal(validateConfig({ ...OWN, archive_directory: path.resolve('/var/lib/time-test-bitcoin/archive') }).archive_directory, path.resolve('/var/lib/time-test-bitcoin/archive'));
});

test('dust: the smallest amount the service sends to each form of address (held to Bitcoin Core in test-bitcoin-regtest.test.mjs)', () => {
  assert.deepEqual({ ...DUST_SATS }, { p2pkh: 546n, p2sh: 540n, p2wpkh: 294n, p2wsh: 330n, p2tr: 330n });
});
