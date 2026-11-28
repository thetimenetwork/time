// The test-bitcoin service against a real Bitcoin Core, started by the service itself from its start script
// (deploy/test-bitcoin/start.mjs) as it is started on a machine: a new chain, an address, payments, a node that
// is killed while it runs, and then a second service on an EMPTY node directory with the same archive, which
// must stand on the same block and show the same amounts.
//
// It needs Bitcoin Core 32.1 in .tools/bitcoin-core-32.1 of this repository, of the repository folder beside it
// (../production), or in the folder TIME_BITCOIN_CORE_DIR names (the folder that holds bitcoind). Without it the
// test is skipped. It takes about a minute: the service mines a block every five seconds here, its fastest pace.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { access, mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { addressToScript, scriptToAddress, stripWitness, transactionOutputs } from './bitcoin-address.mjs';
import { BitcoinRpcError, headerHash, nodeLogin } from './bitcoin-rpc.mjs';
import { DUST_SATS, btcText, createWalletRpc } from './test-bitcoin.mjs';
import { createLog } from './test-bitcoin-kit.mjs';
import { cookieFileOf, start } from '../deploy/test-bitcoin/start.mjs';

const root = fileURLToPath(new URL('../', import.meta.url)), exe = process.platform === 'win32' ? '.exe' : '';
async function coreDirectory() {
  const places = [process.env.TIME_BITCOIN_CORE_DIR, path.join(root, '.tools/bitcoin-core-32.1/bitcoin-32.1/bin'), path.join(root, '../production/.tools/bitcoin-core-32.1/bitcoin-32.1/bin')].filter(Boolean);
  for (const place of places) if (await access(path.join(place, `bitcoind${exe}`)).then(() => true, () => false)) return place;
  return null;
}
const coreDir = await coreDirectory();
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
async function freePort() { const server = net.createServer(); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); const port = server.address().port; await new Promise((resolve) => server.close(resolve)); return port; }
function call(url, route, { method = 'GET', json } = {}) {
  const at = new URL(url);
  return new Promise((resolve, reject) => {
    const request = http.request({ host: at.hostname, port: at.port, path: `/bitcoin${route}`, method, headers: json !== undefined ? { 'Content-Type': 'application/json' } : {} }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let body = null; try { body = JSON.parse(text); } catch { /* not JSON */ } resolve({ status: response.statusCode, body, text }); });
    });
    request.on('error', reject);
    request.end(json !== undefined ? JSON.stringify(json) : undefined);
  });
}
/// Asks until `done(answer)` is true, twice a second, for at most `seconds`.
async function until(ask, done, seconds, what) {
  for (const end = Date.now() + seconds * 1000; ; await sleep(500)) {
    const answer = await ask().catch(() => null);
    if (answer && done(answer)) return answer;
    if (Date.now() > end) assert.fail(`${what} did not happen within ${seconds} seconds (last answer: ${JSON.stringify(answer?.body ?? null).slice(0, 300)})`);
  }
}

test('against Bitcoin Core in regtest: a new chain, an address paid, a killed node, and the same chain again on an empty node from the archive', { skip: coreDir ? false : 'Bitcoin Core 32.1 is not in .tools/bitcoin-core-32.1 here or in ../production, and TIME_BITCOIN_CORE_DIR is not set', timeout: 400_000 }, async (t) => {
  const base = await mkdtemp(path.join(os.tmpdir(), 'time-test-bitcoin-core-'));
  const children = [];
  t.after(async () => { for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill(); await rm(base, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); });
  const archive = path.join(base, 'archive'), port = await freePort(), rpcPort = await freePort();
  const configOf = (name) => ({
    bitcoind_program: path.join(coreDir, `bitcoind${exe}`), bitcoin_data_directory: path.join(base, `node-${name}`), bitcoin_rpc_port: rpcPort, wallet: 'test', data_directory: path.join(base, `service-${name}`), archive_directory: archive,
    block_seconds: 5, port, max_payment_sats: '5000000', per_caller_per_day_sats: '100000000', total_per_day_sats: '20000000000', rate_limit: { per_second: 1000, burst: 10000 },
  });
  const spawner = (program, args, options) => { const child = spawn(program, args, options); children.push(child); return child; };
  const foreign = await scriptToAddress(`0014${'7a'.repeat(20)}`, 'regtest');

  // ---------------------------------------------------------------- the first machine
  const log = createLog(), first = await start(configOf('a'), { log, spawner });
  let tipHeight, tipHash, balance, address, taproot, paid;
  try {
    assert.equal(log.said(/^test bitcoin started$/).length, 1, 'the line a launcher waits for');
    const status = (await call(first.url, '/v1/status')).body;
    assert.deepEqual([status.network, status.height, status.block_seconds, status.balance_sats, status.paying], ['regtest', 101, 5, '5000000000', true]);
    assert.equal((await call(first.url, '/v1/health')).status, 200);
    assert.equal((await call(first.url, '/')).status, 200);
    // The cookie the header relay and the prover are given: there, and not for everyone.
    const cookie = await stat(cookieFileOf(configOf('a').bitcoin_data_directory));
    if (process.platform !== 'win32') assert.equal(cookie.mode & 0o007, 0, 'the cookie is not readable by everyone');

    address = (await call(first.url, '/v1/addresses', { method: 'POST' })).body.address;
    taproot = (await call(first.url, '/v1/addresses', { method: 'POST', json: { form: 'p2tr' } })).body.address;
    assert.match(address, /^bcrt1q/); assert.match(taproot, /^bcrt1p/);
    paid = await call(first.url, '/v1/payments', { method: 'POST', json: { address, sats: '12345' } });
    assert.equal(paid.status, 200, paid.text);
    assert.equal((await call(first.url, '/v1/payments', { method: 'POST', json: { address: taproot, sats: '700' } })).status, 200);
    assert.equal((await call(first.url, '/v1/payments', { method: 'POST', json: { address: foreign, sats: '40000' } })).status, 200);
    const waiting = (await call(first.url, `/v1/addresses/${address}`)).body;
    assert.deepEqual([waiting.received_sats, waiting.unconfirmed_sats, waiting.payments.map((payment) => [payment.txid, payment.sats, payment.height])], ['0', '12345', [[paid.body.txid, '12345', null]]]);
    // In a block within the pace, and then with confirmations as they come.
    const confirmed = await until(() => call(first.url, `/v1/payments/${paid.body.txid}`), (answer) => answer.body?.confirmations >= 2, 90, 'two confirmations of the payment');
    assert.equal(confirmed.body.height, 102);
    const seen = (await call(first.url, `/v1/addresses/${address}`)).body;
    assert.deepEqual([seen.received_sats, seen.unconfirmed_sats, seen.payments.map((payment) => [payment.txid, payment.sats, payment.height])], ['12345', '0', [[paid.body.txid, '12345', 102]]]);
    assert.equal((await call(first.url, `/v1/addresses/${taproot}`)).body.received_sats, '700');
    assert.equal((await call(first.url, `/v1/addresses/${foreign}`)).status, 404, 'an address of someone else');

    // What Bitcoin Core itself sends: the smallest amount for each form of address is the one the service states,
    // and a satoshi less is refused by the node. Asked of the node directly, with the service's own client.
    const rpc = createWalletRpc({ url: `http://127.0.0.1:${rpcPort}/`, login: nodeLogin({ cookieFile: cookieFileOf(configOf('a').bitcoin_data_directory) }), wallet: 'test' });
    const scripts = { p2pkh: `76a914${'c1'.repeat(20)}88ac`, p2sh: `a914${'c2'.repeat(20)}87`, p2wpkh: `0014${'c3'.repeat(20)}`, p2wsh: `0020${'c4'.repeat(32)}`, p2tr: `5120${'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'}` };
    for (const [form, script] of Object.entries(scripts)) {
      const to = await scriptToAddress(script, 'regtest');
      await assert.rejects(rpc.call('send', { outputs: [{ [to]: btcText(DUST_SATS[form] - 1n) }], fee_rate: 31, options: { max_tx_weight: 4000 } }), (error) => error instanceof BitcoinRpcError && error.rpcCode === -4 && /too small/i.test(error.message), form);
      const sent = await call(first.url, '/v1/payments', { method: 'POST', json: { address: to, sats: DUST_SATS[form].toString() } });
      assert.equal(sent.status, 200, `${form}: ${sent.text}`);
      // The payment as the node holds it: an output with the script and exactly the amount, in a small transaction.
      const made = await rpc.call('gettransaction', [sent.body.txid]);
      assert.ok(transactionOutputs(made.hex).some((out) => out.script === script && out.sats === DUST_SATS[form].toString()), form);
      assert.ok(stripWitness(made.hex).length / 2 <= 400, `${form}: ${stripWitness(made.hex).length / 2} bytes without witness data`);
    }

    // ---- the node is killed while the service runs (no clean stop: what it had not written to its disk is gone)
    const before = { height: first.service.chain.height(), hash: first.service.chain.bestHash() };
    children[0].kill('SIGKILL');
    await until(() => call(first.url, '/v1/health'), (answer) => answer.status === 200 && answer.body.height >= before.height + 2 && answer.body.node_restarts >= 1, 180, 'the service mining again after its node was killed');
    assert.equal(first.service.chain.hashAt(before.height), before.hash, 'the chain goes on from the block it stood on: nothing was mined beside it');
    assert.equal(log.said(/REORGANISATION/).length, 0);
    assert.equal(children.length, 2, 'the node was started again, once');
    t.diagnostic(`after the kill: ${log.said(/blocks it lacked were handed to it/).map((line) => `${line.blocks} blocks handed back from the archive`).join(', ') || 'Bitcoin Core had lost no block'}; node restarts: ${(await call(first.url, '/v1/health')).body.node_restarts}`);
    // Everything paid is in a block before the service is stopped, so that the archive holds all of it.
    const last = await call(first.url, '/v1/payments', { method: 'POST', json: { address, sats: '5000' } });
    assert.equal(last.status, 200, last.text);
    await until(() => call(first.url, `/v1/payments/${last.body.txid}`), (answer) => answer.body?.confirmations >= 1, 90, 'the last payment in a block');
  } finally { await first.close(); }
  tipHeight = first.service.chain.height(); tipHash = first.service.chain.bestHash(); balance = first.service.health().body.balance_sats;
  assert.equal(children.every((child) => child.exitCode !== null || child.signalCode !== null), true, 'no node is left running');

  // ---------------------------------------------------------------- what the archive holds
  const names = (await readdir(archive)).sort();
  assert.deepEqual(names, ['blocks-00000001.txt', 'wallet.json']);
  const lines = (await readFile(path.join(archive, 'blocks-00000001.txt'), 'utf8')).split('\n').filter(Boolean);
  assert.equal(lines.length, tipHeight, 'one line for each block above the first');
  assert.equal(headerHash(lines[lines.length - 1].slice(0, 160)), tipHash);
  const wallet = JSON.parse(await readFile(path.join(archive, 'wallet.json'), 'utf8'));
  assert.ok(wallet.descriptors.length >= 8 && wallet.descriptors.every((entry) => /prv/.test(entry.desc)), 'the descriptors, with their private keys');
  if (process.platform !== 'win32') assert.equal((await stat(path.join(archive, 'wallet.json'))).mode & 0o777, 0o600);
  assert.ok(!JSON.stringify(log.lines).includes('prv'), 'no key in the log');

  // ---------------------------------------------------------------- a new machine: an empty node, the same archive
  const log2 = createLog(), second = await start(configOf('b'), { log: log2, spawner });
  try {
    assert.deepEqual(second.service.started, { archived: tipHeight, restored: tipHeight, wallet: 'restored', height: tipHeight, balance_sats: balance }, 'every block handed over, the wallet\'s coins as they were');
    // The first block of the new machine comes a pace after its start; whatever was mined since, the old chain is under it.
    const status = (await call(second.url, '/v1/status')).body;
    assert.equal(second.service.chain.hashAt(tipHeight), tipHash, 'the same best block');
    if (status.height === tipHeight) assert.equal(status.best_hash, tipHash);
    assert.ok(status.height >= tipHeight);
    const again = (await call(second.url, `/v1/addresses/${address}`)).body;
    assert.deepEqual([again.received_sats, again.payments.map((payment) => [payment.txid, payment.sats, payment.height]).at(-1)], ['17345', [paid.body.txid, '12345', 102]], 'the same received amount, the same payment');
    assert.equal((await call(second.url, `/v1/addresses/${taproot}`)).body.received_sats, '700');
    assert.equal((await call(second.url, `/v1/payments/${paid.body.txid}`)).body.height, 102);
    // It goes on: a new address that is not an old one, a payment, a block.
    const fresh = (await call(second.url, '/v1/addresses', { method: 'POST' })).body.address;
    assert.ok(fresh !== address && await addressToScript(fresh, 'regtest'));
    const more = await call(second.url, '/v1/payments', { method: 'POST', json: { address: fresh, sats: '1000' } });
    assert.equal(more.status, 200, more.text);
    await until(() => call(second.url, `/v1/payments/${more.body.txid}`), (answer) => answer.body?.confirmations >= 1, 90, 'a payment of the new machine in a block');
    assert.equal((await call(second.url, '/v1/health')).status, 200);
    assert.deepEqual(log2.lines.filter((line) => line.level === 'error'), []);
    assert.deepEqual((await readdir(archive)).sort(), ['blocks-00000001.txt', 'wallet.json'], 'the wallet of the archive is the node\'s wallet: nothing was moved aside');
  } finally { await second.close(); }
  assert.equal(children.every((child) => child.exitCode !== null || child.signalCode !== null), true, 'no node is left running');
});
