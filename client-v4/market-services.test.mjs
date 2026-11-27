// The two services of the market as an operator starts them (deploy/market-relay, deploy/market-prover): their
// configs, their start, their health answers over HTTP, the one-shot tool, and their documents and lists held
// against the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import './time-sdk.js';
import { IndexerError } from './indexer.mjs';
import { refusalKind } from './market-prover.mjs';
import { headersRefusal } from './market-relay.mjs';
import { createTimeEndpoint, EndpointError, loadSigningKey } from './market-service.mjs';
import { createFakeBitcoin, createFakeChain, createLog, makePayment } from './market-test-kit.mjs';
import { readServiceConfig, start as startRelay, validateConfig as relayConfig } from '../deploy/market-relay/start.mjs';
import { start as startProver, validateConfig as proverConfig } from '../deploy/market-prover/start.mjs';
import { proveOnce } from '../deploy/market-prover/prove.mjs';
import { inspect } from '../tools/export-public.mjs';
import { CLIENT_FILES as V4_FILES } from '../tools/release-v4.mjs';
import { CLIENT_FILES as V5_FILES } from '../tools/release-v5.mjs';

const SDK = globalThis.TimeSDK;
const root = new URL('../', import.meta.url);
const text = (file) => readFile(new URL(file, root), 'utf8');
const [relayReadme, proverReadme, relaySource, proverSource, relayStart, proverStart, guide] = await Promise.all(['deploy/market-relay/README.md', 'deploy/market-prover/README.md', 'client-v4/market-relay.mjs', 'client-v4/market-prover.mjs', 'deploy/market-relay/start.mjs', 'deploy/market-prover/start.mjs', 'docs/integration-guide.md'].map(text));
const relayExample = JSON.parse(await text('deploy/market-relay/config.example.json')), proverExample = JSON.parse(await text('deploy/market-prover/config.example.json'));
const NETWORK = 'cd'.repeat(32), SEED = '0b'.repeat(32), PASSWORD = 'a-password-of-a-bitcoin-node';
const SECURITY = { allowance_elapsed_micros: '0', allowance_micros: '600000000', freezes: '0', frozen_until_elapsed_micros: '0', next_id: '1', pending_limit: null, pending_payments: [], pending_root: null, policy: { daily_limit_micros: '600000000', delay_seconds: '86400', freeze_seconds: '86400', threshold: '2' }, version: '1' };
const SCRIPT = `0014${'3d'.repeat(20)}`;
const freePort = () => new Promise((resolve) => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); }); });
/// The settings of the first Markdown table after `heading`: the names in backticks of each row's first cell.
function settingsOf(document, heading) {
  const lines = document.slice(document.indexOf(heading)).split('\n'), from = lines.findIndex((line) => line.startsWith('| Setting'));
  const names = [];
  for (const line of lines.slice(from + 2)) { if (!line.startsWith('|')) break; names.push(...[...line.split('|')[1].matchAll(/`([a-z_]+)`/g)].map((match) => match[1])); }
  return names;
}
const keysOf = (source) => [...source.match(/const KEYS = \[([^\]]+)\]/)[1].matchAll(/'([a-z_]+)'/g)].map((match) => match[1]);
/// A config an operator could have written, in a directory of the test, with a Bitcoin node and a chain of the test.
async function place(kind, more = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), `time-market-${kind}-`)), cookie = path.join(directory, 'cookie');
  await writeFile(cookie, `${PASSWORD}\n`, { mode: 0o600 });
  const config = {
    rpc_url: 'http://127.0.0.1:26657/', trust: { app_version: '4', network_id: NETWORK, chain_id: 'time-devnet-v4-test' }, bitcoin_nodes: [{ name: 'own', url: 'http://127.0.0.1:18443/', cookie_file: cookie }],
    data_directory: path.join(directory, 'data'), port: await freePort(), ...(kind === 'prover' ? { account: '7', key_file: path.join(directory, 'spend'), max_balance_micros: '5000000', max_fee_per_proof_micros: '100000', max_fees_per_day_micros: '1000000' } : {}), ...more,
  };
  if (kind === 'prover') await writeFile(path.join(directory, 'spend'), `${SEED}\n`, { mode: 0o600 });
  return { directory, config, remove: () => rm(directory, { recursive: true, force: true }) };
}
async function world() {
  const bitcoin = createFakeBitcoin(), chain = createFakeChain({ bitcoin, networkId: NETWORK }), node = bitcoin.node({ password: PASSWORD });
  const key = await loadSigningKey({ env: 'K' }, { K: SEED });
  bitcoin.mineMany(5);
  chain.addAccount({ id: '7', balance: '1000000', publicKey: key.publicKey, security: SECURITY });
  chain.addAccount({ id: '6', publicKey: 'a6'.repeat(32) });
  chain.addOrder({ amount_micros: '40000000', bond_micros: '0', confirmations: '1', created: { height: '3', time_micros: '1800000000000000' }, deposit_ppm: '50000', id: '1', key: 'aa'.repeat(32), min_deposit_micros: '0', min_sats: '1000', open: true, owner: '5', pay_blocks: '6', price: '250000000', scripts: [{ fill: '1', script: SCRIPT }], side: 'sell' });
  return { bitcoin, chain, node };
}
const fillRow = { id: '1', order: '1', owner: '5', payer: '6', to: '6', side: 'sell', price: '250000000', amount_micros: '40000000', deposit_micros: '2000000', sats: '10000', confirmations: '1', pay_blocks: '6', script: SCRIPT };

test('the relay\'s config: the example is one, a setting it does not know is refused, and no message quotes a value', () => {
  const example = { ...relayExample, trust: { ...relayExample.trust, network_id: NETWORK } };
  const checked = relayConfig(example);
  assert.deepEqual([checked.poll_seconds, checked.max_actions_per_round, checked.deep_reorg, checked.max_header_age_seconds, checked.max_behind_seconds, checked.max_disagree_seconds, checked.host, checked.port], [10, 4, 'stop', 3600, 300, 1800, '127.0.0.1', 8950]);
  assert.deepEqual(checked.bitcoin_nodes.map((node) => Object.keys(node)), [['name', 'url', 'cookie_file'], ['name', 'url', 'user', 'password_file']]);
  // The defaults are the example's own values: leaving a setting out changes nothing.
  const minimal = { rpc_url: example.rpc_url, trust: example.trust, bitcoin_nodes: example.bitcoin_nodes, data_directory: example.data_directory };
  assert.deepEqual(relayConfig(minimal), checked);
  const refused = (change, pattern) => assert.throws(() => relayConfig({ ...minimal, ...change }), (error) => pattern.test(error.message) && !/hunter2|s3cret/.test(error.message), JSON.stringify(Object.keys(change)));
  refused({ bitcoin_key: 's3cret' }, /^Unknown config setting \(1\); allowed: /);
  refused({ gateway: 'https://wallet.example/' }, /exactly one of rpc_url/);
  refused({ rpc_url: undefined }, /exactly one of rpc_url/);
  refused({ rpc_url: 'http://node.example:26657/' }, /https:\/\/ \(http:\/\/ only on this machine\)/);
  refused({ rpc_url: 'https://user:hunter2@node.example/' }, /without user name or password/);
  refused({ rpc_url: 'https://node.example/rpc' }, /origin only/);
  refused({ trust: { app_version: '4' } }, /trust is the application-4 trust manifest/);
  refused({ data_directory: 'relative' }, /absolute path/);
  refused({ deep_reorg: 'yes' }, /"stop" or "relay"/);
  refused({ poll_seconds: 0 }, /poll_seconds is a whole number from 1 to 600/);
  refused({ max_actions_per_round: 65 }, /from 1 to 64/);
  refused({ port: 80 }, /port is a whole number from 1024/);
  refused({ hosts: ['Relay.Example'] }, /hosts lists extra Host header values/);
  const node = (entry) => ({ bitcoin_nodes: [{ name: 'own', url: 'http://127.0.0.1:18443/', ...entry }] });
  refused({ bitcoin_nodes: [] }, /one to eight Bitcoin nodes/);
  refused(node({}), /give cookie_file, or user with password_file/);
  refused(node({ cookie_file: '/c', user: 'u', password: 'hunter2' }), /give cookie_file, or user with password_file/);
  refused(node({ cookie_file: 'relative' }), /cookie_file is an absolute path/);
  refused(node({ user: 'u' }), /exactly one of password_file and password/);
  refused(node({ user: 'u:v', password: 'hunter2' }), /without a colon/);
  refused(node({ cookie_file: '/c', wallet: 'hunter2' }), /takes name, url, cookie_file, user, password, password_file/);
  refused({ bitcoin_nodes: [{ name: 'own', url: 'http://10.0.0.5:8332/', cookie_file: '/c' }] }, /http:\/\/ only on this machine/);
  refused({ bitcoin_nodes: [{ name: 'own', url: 'http://rpc:hunter2@127.0.0.1:8332/', cookie_file: '/c' }] }, /without user name, password or path/);
  refused({ bitcoin_nodes: [{ name: 'Own Node', url: 'http://127.0.0.1:8332/', cookie_file: '/c' }] }, /short name of your own/);
  refused({ bitcoin_nodes: [{ name: 'a', url: 'http://127.0.0.1:1/', cookie_file: '/c' }, { name: 'a', url: 'http://127.0.0.1:2/', cookie_file: '/c' }] }, /same name/);
  assert.equal(relayConfig({ ...minimal, ...node({ user: 'relay', password: 'hunter2' }) }).bitcoin_nodes[0].password, 'hunter2');
  // The gateway way, for someone without a Time node.
  assert.equal(relayConfig({ ...minimal, rpc_url: undefined, gateway: 'https://wallet.example' }).gateway, 'https://wallet.example/');
});

test('the prover\'s config: nothing about money has a default, and the key is named by the operator, in one place', () => {
  const example = { ...proverExample, account: '12', trust: { ...proverExample.trust, network_id: NETWORK } };
  const checked = proverConfig(example);
  assert.deepEqual([checked.account, checked.max_balance_micros, checked.min_balance_micros, checked.max_fee_per_proof_micros, checked.max_fees_per_day_micros, checked.expire, checked.allow_unsecured_account, checked.poll_seconds, checked.max_blocks_per_round, checked.port],
    ['12', 5000000n, 500000n, 100000n, 2000000n, false, false, 10, 64, 8951]);
  assert.equal(Object.hasOwn(checked, 'key_env'), false);
  assert.equal(path.isAbsolute(checked.key_file), true);
  const refused = (change, pattern) => assert.throws(() => proverConfig({ ...example, ...change }), (error) => pattern.test(error.message) && !/s3cret/.test(error.message), JSON.stringify(Object.keys(change)));
  assert.throws(() => proverConfig(proverExample), /account is the number of the prover's own account/, 'the example names no account: the operator writes it');
  for (const name of ['max_balance_micros', 'max_fee_per_proof_micros', 'max_fees_per_day_micros']) refused({ [name]: undefined }, new RegExp(`${name} is a whole number of microseconds as a decimal string`));
  refused({ max_balance_micros: 5000000 }, /decimal string/);
  refused({ max_fees_per_day_micros: '99999' }, /max_fees_per_day_micros at least one proof/);
  refused({ max_balance_micros: '99999' }, /below one proof/);
  refused({ min_balance_micros: '5000001' }, /above max_balance_micros/);
  refused({ key_env: 'PROVER_KEY' }, /exactly one of key_env .* and key_file/);
  refused({ key_file: undefined }, /exactly one of key_env .* and key_file/);
  refused({ key_file: 'spend.key' }, /key_file is the absolute path/);
  refused({ key_file: undefined, key_env: 'not a name' }, /key_env is the name of an environment variable/);
  refused({ key: 's3cret' }, /^Unknown config setting \(1\)/);
  refused({ expire: 'yes' }, /expire is true or false/);
  refused({ account: '@prover' }, /account is the number/);
  assert.equal(proverConfig({ ...example, key_file: undefined, key_env: 'PROVER_KEY' }).key_env, 'PROVER_KEY');
});

test('every setting is in its README, every status and warning of a health answer too, and both examples are whole', () => {
  for (const [name, readme, source, example] of [['relay', relayReadme, relayStart, relayExample], ['prover', proverReadme, proverStart, proverExample]]) {
    const keys = keysOf(source), documented = settingsOf(readme, '## Running it');
    assert.deepEqual([...documented].sort(), [...keys].sort(), `${name}: the table of settings and the code name the same settings`);
    // The example holds every setting but the alternatives of the ones it shows.
    const alternatives = { relay: ['gateway'], prover: ['gateway', 'key_env'] }[name];
    assert.deepEqual(Object.keys(example).sort(), keys.filter((key) => !alternatives.includes(key)).sort(), `${name}: the example config`);
  }
  // What a health answer can say is what the README lists: a monitor's rule is written from the README.
  const said = (source, pattern) => [...new Set([...source.matchAll(pattern)].map((match) => match[1]))];
  const relayStatuses = ['ok', 'catching_up', 'stalled', 'chain_behind', 'halted', 'deep_reorganisation', 'refused_network', 'no_bitcoin_node', 'time_unreachable'];
  for (const status of relayStatuses) { assert.ok(relaySource.includes(`'${status}'`), status); assert.ok(relayReadme.includes(`\`${status}\``), `relay README: ${status}`); }
  for (const warning of said(relaySource, /warnings\.push\('([a-z_]+)'\)/g)) assert.ok(relayReadme.includes(`\`${warning}\``), `relay README: ${warning}`);
  const proverStatuses = ['ok', 'catching_up', 'waiting_for_a_block', 'stalled', 'halted', 'key_or_account', 'daily_fee_budget_used_up', 'balance_too_low', 'daily_limit_of_the_account_used_up', 'cannot_pay', 'no_node_sees_the_chains_best_block', 'no_bitcoin_node', 'time_unreachable', 'refused_network', 'no_market'];
  for (const status of proverStatuses) { assert.ok(proverSource.includes(`'${status}'`) || proverSource.includes(`${status}:`), status); assert.ok(proverReadme.includes(`\`${status}\``), `prover README: ${status}`); }
  for (const warning of [...said(proverSource, /warnings\.push\('([a-z_]+)'\)/g), ...said(proverSource, /warnings\.add\('([a-z_]+)'\)/g)]) assert.ok(proverReadme.includes(`\`${warning}\``), `prover README: ${warning}`);
  // The numbers the READMEs give are the code's.
  assert.match(relaySource, /CLOCK_ACTIONS_PER_GRACE = 64;/); assert.match(relayReadme, /sends at most 64 actions in any window of `GRACE`/);
  assert.match(proverSource, /MAX_PAYMENT_BYTES = 100_000, MAX_COINBASE_BYTES = 150_000, START_SLACK = 6/);
  assert.match(proverReadme, /above 100,000 bytes/); assert.match(proverReadme, /above 150,000 bytes/); assert.match(proverReadme, /fewer than six blocks below/);
  // The guide says who runs the two services and what happens when nobody does.
  assert.match(guide, /deploy\/market-relay/); assert.match(guide, /deploy\/market-prover/);
  // The first words on setting the prover up: an account of its own, the security rules, a daily limit, only the fees.
  assert.match(proverReadme, /## The prover's account and key\n\n\*\*The prover has an account of its own, which has adopted the chain's security rules with a daily limit and holds only what the proofs' fees need\.\*\*/);
});

test('every module the two services import is in both distributions, every new file is published, and none trips the publication scan', async () => {
  const seen = new Set(), queue = ['deploy/market-relay/start.mjs', 'deploy/market-prover/start.mjs', 'deploy/market-prover/prove.mjs'];
  const here = fileURLToPath(root);
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const source = await readFile(path.join(here, file), 'utf8');
    for (const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\bnew URL\(\s*)(['"])(\.{1,2}\/[^'"]*)\1/g)) {
      if (match[2].endsWith('/')) continue;
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), match[2]));
      if (/\.m?js$/.test(target)) queue.push(target); else seen.add(target);
    }
  }
  for (const file of ['client-v4/bitcoin-rpc.mjs', 'client-v4/market-service.mjs', 'client-v4/market-relay.mjs', 'client-v4/market-prover.mjs', 'client-v4/bitcoin-address.mjs', 'web-v4/shared/bitcoin-address.mjs', 'client-v4/time-sdk.js', 'client-v4/proof-verifier.mjs', 'web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm']) assert.ok(seen.has(file), file);
  const shipped = [...seen, 'deploy/market-relay/README.md', 'deploy/market-relay/config.example.json', 'deploy/market-prover/README.md', 'deploy/market-prover/config.example.json'];
  for (const [name, list] of [['v4', V4_FILES], ['v5', V5_FILES]]) for (const file of shipped) assert.ok(list.includes(file), `${name} distribution lacks ${file}`);
  const manifest = JSON.parse(await text('public-manifest.json')), published = new Set(manifest.publish.flatMap((group) => group.paths));
  const added = ['client-v4/bitcoin-rpc.mjs', 'client-v4/bitcoin-rpc.test.mjs', 'client-v4/market-service.mjs', 'client-v4/market-relay.mjs', 'client-v4/market-relay.test.mjs', 'client-v4/market-prover.mjs', 'client-v4/market-prover.test.mjs', 'client-v4/market-services.test.mjs', 'client-v4/market-services-regtest.test.mjs', 'client-v4/market-test-kit.mjs',
    'deploy/market-relay/README.md', 'deploy/market-relay/config.example.json', 'deploy/market-relay/start.mjs', 'deploy/market-prover/README.md', 'deploy/market-prover/config.example.json', 'deploy/market-prover/start.mjs', 'deploy/market-prover/prove.mjs', 'bitcoin-bridge/tests/prover.rs'];
  for (const file of added) {
    assert.ok(published.has(file), `public-manifest.json lacks ${file}`);
    assert.deepEqual(inspect(file, await readFile(path.join(here, file)), manifest.scan ?? {}), [], `${file} trips the publication scan`);
  }
});

test('the relay as started: its health answer over HTTP, one instance per data directory, and no secret in a line of its log', async () => {
  const { chain, node, bitcoin } = await world(), spot = await place('relay'), log = createLog();
  try {
    const running = await startRelay(spot.config, { endpoint: chain.endpoint, bitcoinFetcher: node.fetcher, log, autoStart: false });
    try {
      const ask = async (headers = {}) => { const response = await fetch(`${running.url}/health`, { headers }); return { status: response.status, body: await response.json() }; };
      assert.deepEqual([(await ask()).status, (await ask()).body.status], [503, 'starting'], 'no round yet: not healthy');
      await running.relay.round(); await running.relay.round();
      const healthy = await ask();
      assert.deepEqual([healthy.status, healthy.body.ok, healthy.body.status, healthy.body.header_chain.best_height, healthy.body.header_chain.best_block], [200, true, 'ok', 5, bitcoin.best.hash]);
      assert.equal(chain.bestHeight, 5);
      // The header chain halts: the answer fails at the next round.
      chain.live.halted = { reason: 'deep_reorg', old_tip: chain.bestTip, candidate: 'ab'.repeat(32), common_height: 1 }; chain.commit();
      await running.relay.round();
      assert.deepEqual([(await ask()).status, (await ask()).body.status], [503, 'halted']);
      // Only this machine's names are answered, only GET, only /health.
      // (A request under another name, as a page of another site would make one after rebinding its name to 127.0.0.1.)
      const underName = (host) => new Promise((resolve, reject) => { http.get(`${running.url}/health`, { headers: { host } }, (response) => { response.resume(); resolve(response.statusCode); }).on('error', reject); });
      assert.equal(await underName('evil.example'), 421);
      assert.equal(await underName(`localhost:${new URL(running.url).port}`), 503);
      assert.equal((await fetch(`${running.url}/health`, { method: 'POST' })).status, 405);
      assert.equal((await fetch(`${running.url}/`)).status, 404);
      // A second relay on the same data directory does not start.
      await assert.rejects(startRelay({ ...spot.config, port: await freePort() }, { endpoint: chain.endpoint, bitcoinFetcher: node.fetcher, log, autoStart: false }), /already uses|Another instance/);
      const everything = log.text() + JSON.stringify((await ask()).body);
      assert.doesNotMatch(everything, new RegExp(`${PASSWORD}|cookie|18443`));
      assert.deepEqual(log.said(/market header relay started/).map((line) => [line.bitcoin_nodes, line.deep_reorg, line.network_id]), [[['own'], 'stop', NETWORK]]);
    } finally { await running.close(); }
    // Closed: the lock is released, and the port is free.
    const again = await startRelay(spot.config, { endpoint: chain.endpoint, bitcoinFetcher: node.fetcher, log, autoStart: false });
    await again.close();
  } finally { await spot.remove(); }
});

test('the prover as started: the key and the account are checked before anything runs, and a proof goes out end to end', async () => {
  const { chain, node, bitcoin } = await world(), spot = await place('prover'), log = createLog();
  const parts = { endpoint: chain.endpoint, bitcoinFetcher: node.fetcher, log, autoStart: false, sleep: async () => {} };
  try {
    chain.follow();
    chain.addFill(fillRow);
    // More than the ceiling: no start, and the data directory is free again.
    chain.live.accounts.get('7').balance = '5000001'; chain.commit();
    await assert.rejects(startProver(spot.config, parts), /The prover does not start: the prover's account holds more than max_balance_micros/);
    chain.live.accounts.get('7').balance = '1000000'; chain.commit();
    // A key file that others can read: no start (where the system keeps file modes).
    if (process.platform !== 'win32') { await chmod(spot.config.key_file, 0o644); await assert.rejects(startProver(spot.config, parts), /The key file can be read by other users of this machine/); await chmod(spot.config.key_file, 0o600); }
    const running = await startProver(spot.config, parts);
    try {
      bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }])]); chain.follow();
      await running.prover.round();
      assert.deepEqual(chain.proofs.map((proof) => [proof.fill, proof.sats, proof.full]), [['1', '10000', true]]);
      const response = await fetch(`${running.url}/health`), body = await response.json();
      assert.deepEqual([response.status, body.status, body.payments.proven_since_start, body.fees.proofs, body.balance_micros], [200, 'ok', 1, 1, '996000']);
      // What it remembers is in its data directory, and holds no key.
      const kept = await readFile(path.join(spot.config.data_directory, 'prover.json'), 'utf8');
      assert.deepEqual([JSON.parse(kept).spent_micros, JSON.parse(kept).account, JSON.parse(kept).network_id], ['4000', '7', NETWORK]);
      const everything = log.text() + JSON.stringify(body) + kept;
      assert.doesNotMatch(everything, new RegExp(`${SEED}|${PASSWORD}|spend|cookie`));
      assert.deepEqual(log.said(/market prover started/).map((line) => [line.account, line.max_balance_micros, line.expire]), [['7', '5000000', false]]);
    } finally { await running.close(); }
  } finally { await spot.remove(); }
});

test('the one-shot tool: one fill, its payment found and proven, in plain lines, with an exit code that says what happened', async () => {
  const { chain, node, bitcoin } = await world(), spot = await place('prover');
  const lines = [], options = { write: (line) => lines.push(line), inject: { endpoint: chain.endpoint, bitcoinFetcher: node.fetcher, sleep: async () => {} } };
  try {
    chain.follow();
    chain.addFill(fillRow); chain.addFill({ ...fillRow, id: '2', script: `0014${'4e'.repeat(20)}`, confirmations: '3' });
    // Nothing paid yet.
    assert.equal(await proveOnce(spot.config, '1', options), 2);
    assert.match(lines.join('\n'), /Fill 1 is open: 10000 satoshis are still to pay.*\nNo payment to the address of fill 1 was found in the Bitcoin blocks the chain knows \(up to height 5\)/);
    // Both fills are paid in one block. Fill 2 asks three confirmations and has one.
    bitcoin.mine([makePayment([{ sats: 10000, script: SCRIPT }]), makePayment([{ sats: 10000, script: `0014${'4e'.repeat(20)}` }])]); chain.follow();
    lines.length = 0;
    assert.equal(await proveOnce(spot.config, '2', options), 3);
    assert.match(lines.join('\n'), /Payment [0-9a-f]{64}:0 of 10000 satoshis in block [0-9a-f]{64} \(height 6\): not proven yet\.\nA payment was found and is not proven: it lacks confirmations on the chain's view of Bitcoin \(the fill asks 3\)/);
    assert.equal(chain.submitted.length, 0);
    lines.length = 0;
    assert.equal(await proveOnce(spot.config, '1', options), 0);
    assert.match(lines.join('\n'), /proof counted: the fill is paid in full and has ended .*"fill":"1".*\nFill 1 has no row: it has ended, or it was never made\.\nPayment [0-9a-f]{64}:0 of 10000 satoshis in block [0-9a-f]{64} \(height 6\): proven\./);
    assert.deepEqual(chain.proofs.map((proof) => proof.fill), ['1'], 'the other fill was left alone');
    // Again: nothing is proven twice, and a fill that has ended is nothing to do.
    assert.equal(await proveOnce(spot.config, '1', options), 0);
    assert.equal(chain.submitted.length, 1);
    assert.doesNotMatch(lines.join('\n'), new RegExp(`${SEED}|${PASSWORD}`));
    await assert.rejects(proveOnce(spot.config, 'one', options), /--fill takes the id of a fill/);
  } finally { await spot.remove(); }
});

test('the words of a refusal that the services read are the engine\'s own, and the test chain speaks them too', async () => {
  // A refusal is the node's word, and the services decide from it where to look next and how long to wait. If
  // the engine changed a sentence, the relay would stop finding forks and the prover would wait for nothing: this
  // test fails first.
  const [headers, payment, market, kit] = await Promise.all(['bitcoin-bridge/src/chain.rs', 'bitcoin-bridge/src/payment.rs', 'v5/src/market.rs', 'client-v4/market-test-kit.mjs'].map(text));
  const written = (source, phrase) => source.replace(/\s+/g, ' ').includes(phrase);
  for (const [phrase, meaning] of [['Bitcoin relay contains no new headers', 'nothing_new'], ['Bitcoin relay has no retained state effect', 'nothing_new'], ['unknown or pruned Bitcoin parent', 'unknown_parent'], ['Bitcoin bridge is paused after a reorganization', 'halted'], ['Bitcoin header too far in consensus-time future', 'refused'], ['Bitcoin exact difficulty mismatch', 'refused']]) {
    assert.ok(written(headers, phrase), `bitcoin-bridge/src/chain.rs: ${phrase}`);
    assert.equal(headersRefusal(phrase), meaning, phrase);
  }
  for (const [source, name, phrase, meaning] of [
    [market, 'v5/src/market.rs', 'this Bitcoin output has paid for a fill already', 'counted'], [market, 'v5/src/market.rs', 'no such fill', 'ended'],
    [payment, 'bitcoin-bridge/src/payment.rs', 'Bitcoin payment is not after the starting block', 'before'], [payment, 'bitcoin-bridge/src/payment.rs', 'Bitcoin payment is not after the starting block, which is no longer held', 'before'],
    [payment, 'bitcoin-bridge/src/payment.rs', 'Bitcoin payment lacks confirmations', 'later'], [payment, 'bitcoin-bridge/src/payment.rs', 'payment block is above the best height', 'later'], [payment, 'bitcoin-bridge/src/payment.rs', 'payment Bitcoin block unknown or pruned', 'later'],
    [payment, 'bitcoin-bridge/src/payment.rs', 'payment is not on greatest-work Bitcoin chain', 'later'], [payment, 'bitcoin-bridge/src/payment.rs', 'after a reorganisation a payment counts when the chain has its confirmations past the starting height', 'later'],
    [market, 'v5/src/market.rs', 'the chain has not learnt the last height of this fill', 'later'], [market, 'v5/src/market.rs', 'a fill ends after the time in which a proof of a payment made in time is accepted', 'later'], [market, 'v5/src/market.rs', 'a fill ends after its time to pay and to confirm, counted from when it was made', 'later'],
    [market, 'v5/src/market.rs', 'the sender cannot pay the fee of this proof', 'funds'], [market, 'v5/src/market.rs', 'a frozen account sends no proof that costs it more than it brings', 'funds'],
    [payment, 'bitcoin-bridge/src/payment.rs', 'Bitcoin bridge paused after reorganization', 'halted'], [market, 'v5/src/market.rs', 'the Bitcoin header chain is halted: a fill ends by a release or by its owner\'s settle', 'halted'],
    [market, 'v5/src/market.rs', 'a payment of a part is at least the order\'s smallest trade, or half of what the fill still needs', 'small'], [market, 'v5/src/market.rs', 'the payment buys less than a microsecond', 'small'],
    [payment, 'bitcoin-bridge/src/payment.rs', 'Bitcoin merkle proof does not match exactly the coinbase and the payment', 'other'],
  ]) {
    assert.ok(written(source, phrase), `${name}: ${phrase}`);
    assert.equal(refusalKind(phrase), meaning, phrase);
    // The chain of the tests refuses in the same words (an apostrophe is written \' in its source). It does not
    // freeze accounts, so it never makes that one refusal.
    if (!phrase.startsWith('a frozen account')) assert.ok(kit.includes(phrase.replaceAll('\'', '\\\'')), `client-v4/market-test-kit.mjs: ${phrase}`);
  }
  for (const phrase of ['Bitcoin relay contains no new headers', 'unknown or pruned Bitcoin parent', 'Bitcoin bridge is paused after a reorganization']) assert.ok(kit.includes(phrase), phrase);
});

test('a config that holds a password in its own text is refused when others can read the file', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-market-config-'));
  try {
    const file = path.join(directory, 'config.json'), withPassword = { bitcoin_nodes: [{ name: 'own', url: 'http://127.0.0.1:18443/', user: 'relay', password: PASSWORD }] };
    await writeFile(file, JSON.stringify(withPassword), { mode: 0o600 });
    assert.deepEqual(await readServiceConfig(file), withPassword);
    await writeFile(path.join(directory, 'broken.json'), `{"bitcoin_nodes":[{"password":"${PASSWORD}"`);
    await assert.rejects(readServiceConfig(path.join(directory, 'broken.json')), (error) => /not valid JSON/.test(error.message) && !error.message.includes(PASSWORD));
    if (process.platform === 'win32') return t.diagnostic('Windows keeps no file modes: the check of who can read the config is the operator\'s there');
    await chmod(file, 0o640);
    await assert.rejects(readServiceConfig(file), /The config file holds a secret and can be read by other users of this machine: chmod 600 it/);
    // A config that names files and holds no secret itself may be read by others.
    await writeFile(file, JSON.stringify({ bitcoin_nodes: [{ name: 'own', url: 'http://127.0.0.1:18443/', cookie_file: '/c' }] }), { mode: 0o644 });
    await chmod(file, 0o644);
    await readServiceConfig(file);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('how an action is handed to the chain: taken, held already, refused in the node\'s words, or no answer', async () => {
  const trust = { app_version: '4', network_id: NETWORK, chain_id: 'time-devnet-v4-test' }, bytes = SDK.publicHeadersAction(NETWORK, ['ab'.repeat(80)]), calls = [];
  let answer;
  const rpc = async (method, parameters) => { calls.push([method, parameters]); if (answer instanceof Error) throw answer; return answer; };
  const node = createTimeEndpoint({ rpcUrl: 'http://127.0.0.1:26657/', trust, verifier: {}, rpc });
  answer = { code: 0, hash: 'AB'.repeat(32) };
  assert.deepEqual(await node.submit(bytes), { accepted: true });
  assert.deepEqual(calls[0], ['/broadcast_tx_sync', { tx: `0x${Buffer.from(bytes).toString('hex')}` }]);
  answer = { code: 1, log: 'unknown or pruned Bitcoin parent\u0007\nsecond line' };
  assert.deepEqual(await node.submit(bytes), { accepted: false, reason: 'unknown or pruned Bitcoin parent  second line' });
  answer = Object.assign(new IndexerError('RPC_REFUSED', 'The RPC refused the request'), { rpcMessage: 'tx already exists in cache' });
  assert.deepEqual(await node.submit(bytes), { accepted: true, known: true });
  answer = new IndexerError('RPC_UNAVAILABLE', 'The RPC could not be reached');
  await assert.rejects(node.submit(bytes), (error) => error instanceof EndpointError && error.code === 'UNAVAILABLE');
  assert.deepEqual([node.kind, node.origin], ['rpc', 'http://127.0.0.1:26657']);
  // Through a wallet gateway: the same four, from its answers.
  let reply;
  const fetcher = async (url, options) => { calls.push([new URL(url).pathname, options.method, JSON.parse(options.body)]); if (reply instanceof Error) throw reply; return new Response(JSON.stringify(reply.body), { status: reply.status, headers: { 'content-type': 'application/json' } }); };
  const gateway = createTimeEndpoint({ gateway: 'https://wallet.example/', trust, verifier: {}, fetcher });
  reply = { status: 200, body: { hash: 'AB'.repeat(32), pending: true } };
  assert.deepEqual(await gateway.submit(bytes), { accepted: true });
  assert.deepEqual(calls.at(-1), ['/api/submit', 'POST', { tx: Buffer.from(bytes).toString('base64') }]);
  reply = { status: 400, body: { error: 'Bitcoin relay contains no new headers' } };
  assert.deepEqual(await gateway.submit(bytes), { accepted: false, reason: 'Bitcoin relay contains no new headers' });
  reply = { status: 400, body: { error: 'tx already exists in cache' } };
  assert.deepEqual(await gateway.submit(bytes), { accepted: true, known: true });
  reply = new TypeError('fetch failed');
  await assert.rejects(gateway.submit(bytes), (error) => error instanceof EndpointError);
  assert.deepEqual([gateway.kind, gateway.origin], ['gateway', 'https://wallet.example']);
  assert.throws(() => createTimeEndpoint({ trust, verifier: {} }), /exactly one of rpc_url and gateway/);
  assert.throws(() => createTimeEndpoint({ rpcUrl: 'http://127.0.0.1:1/', gateway: 'https://wallet.example/', trust, verifier: {} }), /exactly one of rpc_url and gateway/);
});
