// The faucet over a fake node. The faucet's account is the secured account of the engine's own
// fixture (account-security.fixture.json): its keys, its roles and the form of its security row.
// The fake node applies the rules a grant meets on the chain: one nonce after the other, the
// signature of a spend key, the daily limit. One test reads a real state proof (proof.json)
// through the real reader and verifier.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, generateKeyPairSync, sign as edSign } from 'node:crypto';
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { IndexerError } from './indexer.mjs';
import { createFaucetService, callerKey, readSpendKey, createTxLookup, openFaucetStore, MAX_BODY_BYTES, DAY_MS, ROUTES } from './faucet.mjs';
import { validateConfig, start } from '../deploy/faucet/start.mjs';
import { seconds, describe } from '../web-v4/faucet/app.js';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const proven = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const NETWORK = fixture.network_id, FAUCET = fixture.account.id;
// ADAPTED (finding 4): the faucet now starts only on a chain id of a test network (the prefix
// time-devnet-v4-, the one the installed verifier accepts), so the harness needs such an id.
// Original line:
//   const TRUST = { app_version: '4', network_id: NETWORK, chain_id: 'time-testnet-fixture', genesis_time_micros: '0', checkpoint: null };
const TRUST = { app_version: '4', network_id: NETWORK, chain_id: 'time-devnet-v4-fixture', genesis_time_micros: '0', checkpoint: null };
const seedOf = (name) => fixture.seeds.find((entry) => entry.name === name);
const keyOf = async (name) => ({ publicKey: seedOf(name).public_key, privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes(`302e020100300506032b657004220420${seedOf(name).seed_hex}`), { name: 'Ed25519' }, false, ['sign']) });
const SPEND = await keyOf('spend');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex').toUpperCase();
const FEE = 1000n, GRANT = 5000000n, REGISTRATION_FEE = 10000n;
const REFUSED_LIMIT = 'over the daily limit of this account: use a payment that waits, or a second proof';

/// A node and its chain, as far as a faucet meets them. `mode` says what a submission does:
/// 'take' (the default), 'lose' (no answer, and the node does not have the bytes), 'take-silently'
/// (no answer, but the node has them: a timeout after the fact).
function fakeNode() {
  const devices = [
    { public_key: seedOf('signin').public_key, can_manage: false, can_spend: false },
    { public_key: seedOf('spend').public_key, can_manage: false, can_spend: true },
    { public_key: seedOf('sheet').public_key, can_manage: true, can_spend: false },
    { public_key: seedOf('phrase').public_key, can_manage: true, can_spend: false },
  ];
  const node = {
    height: 20, elapsed: 5000000000n, mode: 'take', network: NETWORK, stateDown: false, lookupDown: false,
    accounts: new Map([
      [FAUCET, { id: FAUCET, name: 'faucet', balance: 900000000n, nonce: BigInt(fixture.account.after_secure.nonce), auth_epoch: fixture.account.after_secure.auth_epoch, devices }],
      ['7', { id: '7', name: 'dev', balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: 'aa'.repeat(32), can_manage: true, can_spend: true }] }],
      ['8', { id: '8', name: 'other', balance: 100n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: 'ab'.repeat(32), can_manage: true, can_spend: true }] }],
      ['9', { id: '9', name: 'rich', balance: 20000001n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: 'ac'.repeat(32), can_manage: true, can_spend: true }] }],
    ]),
    // The security row in the form the engine wrote it (the fixture's), with this test's numbers.
    security: { ...structuredClone(fixture.allowance.security), pending_limit: null, policy: { ...fixture.allowance.security.policy, daily_limit_micros: '600000000' } },
    allowance: 600000000n, hiddenSpend: 0n, secured: true,
    mempool: [], included: new Map(), commits: [], submissions: [], reads: 0, lookups: 0,
    account(id) { return node.accounts.get(String(id)); },
    costOf(action) { return action.kind === 3 ? BigInt(action.payload.amount) + FEE : REGISTRATION_FEE + FEE; },
    /// CheckTx: the faucet's next nonce in line, a signature of one of its spend keys, the daily limit.
    async check(raw) {
      const action = SDK.decodeAction(new Uint8Array(raw)), sender = node.account(action.from);
      if (action.networkId !== node.network) return 'wrong network';
      if (node.refuseAll) return node.refuseAll;
      const line = node.mempool.map((tx) => SDK.decodeAction(new Uint8Array(tx)).nonce);
      if (BigInt(action.nonce) !== sender.nonce + 1n + BigInt(line.length) || action.authEpoch !== sender.auth_epoch) return 'stale authority or incorrect nonce';
      if (!sender.devices.some((device) => device.public_key === action.publicKey && device.can_spend)) return 'spending device required';
      const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
      if (!(await crypto.subtle.verify('Ed25519', key, raw.subarray(raw.length - 64), raw.subarray(0, raw.length - 64)))) return 'invalid action signature';
      const waiting = node.mempool.reduce((sum, tx) => sum + node.costOf(SDK.decodeAction(new Uint8Array(tx))), 0n);
      if (node.costOf(action) + waiting > node.allowance - node.hiddenSpend) return REFUSED_LIMIT;
      return null;
    },
    rpc: async (method, parameters = {}) => {
      if (method !== '/broadcast_tx_sync') throw new IndexerError('RPC_REFUSED', 'not available on this node');
      const raw = Buffer.from(parameters.tx.slice(2), 'hex');
      node.submissions.push(raw.toString('hex'));
      if (node.mode === 'lose') throw new IndexerError('RPC_UNAVAILABLE', 'The RPC did not answer in time');
      if (node.mempool.some((tx) => tx.equals(raw))) { const error = new IndexerError('RPC_REFUSED', 'The RPC refused the request'); error.rpcMessage = 'tx already exists in cache'; throw error; }
      const refused = await node.check(raw);
      if (refused) return { code: 1, log: refused, hash: sha(raw) };
      node.mempool.push(raw);
      if (node.mode === 'take-silently') throw new IndexerError('RPC_UNAVAILABLE', 'The RPC did not answer in time');
      return { code: 0, hash: sha(raw) };
    },
    lookup: async (hash) => { node.lookups += 1; if (node.lookupDown) throw new IndexerError('RPC_REFUSED', 'no index'); return node.included.get(hash) ?? null; },
    /// Makes blocks: the first with everything that waits, the rest empty.
    mine(blocks = 1) {
      for (let i = 0; i < blocks; i++) {
        node.height += 1; node.elapsed += 1000000n;
        for (const raw of node.mempool.splice(0)) {
          const action = SDK.decodeAction(new Uint8Array(raw)), sender = node.account(action.from), cost = node.costOf(action);
          sender.nonce += 1n; sender.balance -= cost; node.allowance -= cost;
          if (action.kind === 3) node.account(action.payload.to).balance += BigInt(action.payload.amount);
          else node.commits.push({ public_key: action.payload.public_key, commitment: action.payload.commitment, expires_elapsed_micros: action.payload.expires_elapsed_micros, height: String(node.height), sponsor: action.from });
          node.included.set(sha(raw), { height: String(node.height), tx: raw.toString('base64') });
        }
      }
    },
    readState: async (selection) => {
      node.reads += 1;
      if (node.stateDown) throw new Error('node behind');
      const rows = [...node.accounts.values()].filter((a) => selection.ids?.includes(a.id) || selection.names?.includes(a.name) || selection.public_keys?.some((key) => a.devices.some((device) => device.public_key === key)));
      const view = (a) => ({ id: a.id, name: a.name, balance: a.balance.toString(), nonce: a.nonce.toString(), auth_epoch: a.auth_epoch, devices: a.devices, public_key: a.devices[0].public_key });
      return { verified: true, requested: selection, proof: {}, state: {
        network_id: node.network, height: String(node.height), time_micros: node.elapsed.toString(), genesis: { genesis_time_micros: '0' },
        config: { registration: { fee_micros: REGISTRATION_FEE.toString(), max_lifetime_micros: '86400000000', bucket_micros: '3600000000' } },
        accounts: rows.map(view), name_commits: node.commits,
        security: node.secured ? [{ account: FAUCET, ...node.security, allowance_micros: node.allowance.toString(), allowance_elapsed_micros: node.elapsed.toString() }] : [],
      } };
    },
  };
  return node;
}
const OPTIONS = () => ({
  trust: TRUST, networkId: NETWORK, testNetwork: true, account: FAUCET, key: SPEND, grantMicros: GRANT, minBalanceMicros: 10000000n, maxRecipientBalanceMicros: 20000000n, maxChainDailyLimitMicros: 600000000n,
  limits: { perAccountPerDay: 1, perAddressPerDay: 3, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 1 }, sponsorRegistrations: true,
  port: 0, autoStart: false, rateLimit: { perSecond: 1000, burst: 100000 }, supersededAfterMs: 60000, resubmitMs: 30000,
  // The service syncs every write to the disk. Here that would only slow the other suites down.
  storeSynchronous: 'OFF',
});
/// A faucet over a fake node. `reopen()` stops the service and starts another on the same store, as after a crash.
async function lab(run, options = {}, prepare = () => {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-faucet-'));
  const node = fakeNode(), world = { node, clock: 1700000000000, logs: [], service: null };
  prepare(node);
  const open = async (more = {}) => createFaucetService({ ...OPTIONS(), verifier, rpc: (...a) => node.rpc(...a), lookup: (...a) => node.lookup(...a), readState: (...a) => node.readState(...a), dataFile: path.join(directory, 'faucet.sqlite'), now: () => world.clock, log: (level, message, fields) => world.logs.push({ level, message, ...fields }), ...options, ...more });
  try {
    world.service = await open();
    world.reopen = async (more) => { await world.service.close(); world.service = await open(more); };
    await run(world);
  } finally { await world.service?.close(); await rm(directory, { recursive: true, force: true }); }
}
/// One request, with any header (fetch cannot set Host).
function call(service, route, { method = 'GET', headers = {}, body, json } = {}) {
  const url = new URL(service.url), payload = json !== undefined ? JSON.stringify(json) : body;
  return new Promise((resolve, reject) => {
    const request = http.request({ host: url.hostname, port: url.port, path: route, method, headers: { ...(json !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let parsed = null; try { parsed = JSON.parse(text); } catch { /* not JSON */ } resolve({ status: response.statusCode, headers: response.headers, text, body: parsed }); });
    });
    request.on('error', reject);
    request.end(payload);
  });
}
const ask = (service, account, headers = {}) => call(service, '/v1/faucet/grants', { method: 'POST', json: { account }, headers });
const distinct = (node) => new Set(node.submissions).size;

// ====================================================================== adversarial review
const devs = (node, from = 20, to = 120) => { for (let id = from; id < to; id++) node.accounts.set(String(id), { id: String(id), name: `dev${id}`, balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: id.toString(16).padStart(64, '0'), can_manage: true, can_spend: true }] }); };

test('R1 a node that answers "refused" and keeps the bytes: the grant is paid, not counted, and the same account is paid again', async () => {
  await lab(async ({ service, node }) => {
    // The node answers code 1 to every first sending, keeps the bytes, and puts them in the next block.
    const honest = node.rpc;
    node.rpc = async (method, parameters = {}) => {
      const answer = await honest(method, parameters);
      if (method === '/broadcast_tx_sync' && answer.code === 0) return { code: 1, log: 'try again later', hash: answer.hash };
      return answer;
    };
    const statuses = [];
    for (let round = 0; round < 5; round++) {
      const answer = await ask(service, '7');           // the same account, the same address, five times
      statuses.push([answer.status, answer.body.error?.code]);
      node.mine(); await service.settle();
    }
    const info = (await call(service, '/v1/faucet')).body;
    console.log('R1 answers:', JSON.stringify(statuses));
    console.log('R1 account 7 balance:', node.account('7').balance, 'faucet balance:', node.account(FAUCET).balance, 'faucet nonce:', node.account(FAUCET).nonce);
    console.log('R1 faucet says left today:', info.left.total_micros, 'of', info.gives.total_micros, '; per_account', info.gives.per_account, 'per_address', info.gives.per_address);
    console.log('R1 lookup of a paid hash:', JSON.stringify((await call(service, `/v1/faucet/grants/${sha(Buffer.from(node.submissions[0], 'hex'))}`)).body));
    // The limits say: one grant per account per 24 hours, three per address.
    assert.equal(node.account('7').balance, GRANT, 'one account was paid more than once in 24 hours');
  }, {}, undefined);
});

test('R2 a node without a transaction index: after 64 grants the faucet answers "busy" for good, and its health check says all is well', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    node.lookupDown = true; // README: "The node cannot look actions up (its transaction index is off). Grants whose nonce is used stay submitted, and count."
    let given = 0, first503 = null;
    for (let id = 20; id < 90; id++) {
      const answer = await ask(service, String(id), { 'X-Forwarded-For': `198.51.100.${id}` });
      if (answer.status === 202) given += 1; else { first503 ??= [id - 20 + 1, answer.status, answer.body.error.code, answer.body.error.message]; break; }
      node.mine(); world.clock += 6000; await service.settle();
    }
    console.log('R2 grants given before the stop:', given, 'then:', JSON.stringify(first503));
    assert.equal(node.account(FAUCET).nonce, BigInt(fixture.account.after_secure.nonce) + BigInt(given), 'every one of them is in a block');
    // Two days later, with every block made and nothing waiting anywhere: still closed.
    world.clock += 2 * DAY_MS; node.mine(5); await service.settle(); await service.settle();
    const later = await ask(service, '100', { 'X-Forwarded-For': '198.51.100.200' });
    const health = await call(service, '/v1/faucet/health'), info = (await call(service, '/v1/faucet')).body;
    console.log('R2 two days later:', later.status, JSON.stringify(later.body.error), '| health:', health.status, JSON.stringify(health.body), '| giving:', info.giving, info.reasons);
    assert.equal(later.status, 202, 'the faucet never gives again');
  }, { trustedProxies: ['127.0.0.1'], limits: { perAccountPerDay: 1, perAddressPerDay: 3, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 1 } }, (node) => devs(node));
});

test('R3 sixty-four grants withdrawn together (a freeze while they wait): nothing is ever signed again', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    // No block is made for a while; 64 requests are taken by the node and wait.
    for (let id = 20; id < 84; id++) assert.equal((await ask(service, String(id), { 'X-Forwarded-For': `198.51.100.${id}` })).status, 202);
    // The owner freezes the account for an hour (or the chain's limit is used up): the node drops what waits and refuses it.
    node.mempool.length = 0; node.refuseAll = 'account is frozen';
    world.clock += 31000; await service.settle();
    node.mine(3); world.clock += 31000; await service.settle();
    const rows = service.store.open();
    console.log('R3 open rows:', rows.length, 'statuses:', JSON.stringify([...new Set(rows.map((r) => r.status))]));
    // The freeze is over. Everything is fine on the chain. A day and more passes.
    node.refuseAll = null; world.clock += 2 * DAY_MS; node.mine(3); await service.settle(); await service.settle();
    const later = await ask(service, '100', { 'X-Forwarded-For': '198.51.100.200' });
    const health = await call(service, '/v1/faucet/health');
    console.log('R3 two days later:', later.status, JSON.stringify(later.body.error), '| health:', health.status, JSON.stringify(health.body));
    assert.equal(later.status, 202, 'the faucet never gives again');
  }, { trustedProxies: ['127.0.0.1'], maxChainDailyLimitMicros: 600000000n }, (node) => devs(node));
});

test('R4 a clock that jumps ahead for a moment: grants made before it are forgotten at once', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    assert.equal((await ask(service, '7')).status, 202);
    node.mine(); await service.settle();
    assert.equal((await ask(service, '7')).body.error.code, 'account_limit');
    world.clock += 2 * DAY_MS;           // the clock is wrong for a moment (a bad time source) ...
    const second = await ask(service, '7');
    world.clock -= 2 * DAY_MS;           // ... and is right again
    node.mine(); await service.settle();
    console.log('R4 second grant to the same account within the same real minute:', second.status, '| balance of 7:', node.account('7').balance);
    const third = await ask(service, '8');
    console.log('R4 afterwards another account asks:', third.status, third.body.status ?? third.body.error?.code, '| retry-after of account 7 (s):', (await ask(service, '7')).headers['retry-after']);
    assert.equal(node.account('7').balance, GRANT, 'one account was paid twice within a real minute');
  });
});

test('R5 the config: which chain ids pass the "does not read like a main network" check, and what the example states', async () => {
  const config = { test_network: true, network_id: NETWORK, rpc_url: 'http://127.0.0.1:26657/', trust: TRUST, data_directory: path.resolve('/var/lib/time-faucet'), account: FAUCET, key_file: path.resolve('/etc/time-faucet/spend.key'),
    grant_micros: '5000000', limits: { per_account_per_day: 1, per_address_per_day: 3, total_per_day_micros: '500000000', registrations_per_address_per_day: 1 }, min_balance_micros: '10000000', max_recipient_balance_micros: '20000000', max_chain_daily_limit_micros: '600000000', sponsor_registrations: true };
  const verdicts = {};
  for (const chain_id of ['time-1', 'time', 'time-v4-1', 'time-live-1', 'time-prod-1', 'time-production', 'time-devnet-v4-prod-rehearsal', 'time-testnet-1', 'time-testnet-domain-names', 'time-devnet-v4-remainder']) {
    try { validateConfig({ ...config, trust: { ...TRUST, chain_id } }); verdicts[chain_id] = 'accepted'; } catch (error) { verdicts[chain_id] = `refused: ${error.message.slice(0, 40)}`; }
  }
  console.log('R5', JSON.stringify(verdicts, null, 1));
  const example = JSON.parse(await readFile(new URL('../deploy/faucet/config.example.json', import.meta.url), 'utf8'));
  console.log('R5 the example config already states test_network:', example.test_network, '| its chain id:', example.trust.chain_id);
  assert.match(verdicts['time-1'], /refused/, 'a chain id that is not a test network\'s passes');
});

test('R6 what the faucet says and does when the key is used elsewhere: a waiting payment of the whole balance, a limit set to zero', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    // Somebody with the spend key asked for a payment of nearly everything; it waits delay_seconds and then goes out, outside the daily limit.
    node.security.pending_payments = [{ id: '1', to: '9', amount: '899000000', ready_elapsed_micros: (node.elapsed + 86400000000n).toString() }];
    node.security.next_id = '2';
    await service.settle();
    const info = (await call(service, '/v1/faucet')).body, health = await call(service, '/v1/faucet/health');
    const given = await ask(service, '7');
    console.log('R6 waiting payment: /v1/faucet giving =', info.giving, JSON.stringify(info.reasons), '| health', health.status, '| a grant all the same:', given.status, given.body.status, '| log lines at error level:', world.logs.filter((l) => l.level === 'error').length);
    // The same somebody lowers the daily limit to zero (immediate on the chain; only a root operation raises it again).
    node.security.pending_payments = []; node.security.policy.daily_limit_micros = '0'; node.allowance = 0n;
    node.mine(); await service.settle();
    const after = await ask(service, '8'), health2 = await call(service, '/v1/faucet/health'), info2 = (await call(service, '/v1/faucet')).body;
    console.log('R6 limit 0: grant', after.status, after.body.error?.code, '| health', health2.status, JSON.stringify(health2.body.reasons), '| giving =', info2.giving, '| log lines at error level:', world.logs.filter((l) => l.level === 'error').length);
    assert.deepEqual([given.status === 202 && info.giving === false, health2.status], [false, 503], 'the page and the service disagree; a faucet that can give nothing reports itself healthy');
  });
});

test('R7 the same request to an honest node: nothing above the limits (control for R1)', async () => {
  await lab(async ({ service, node }) => {
    const statuses = [];
    for (let round = 0; round < 5; round++) { const answer = await ask(service, '7'); statuses.push(answer.status); node.mine(); await service.settle(); }
    console.log('R7 honest node answers:', JSON.stringify(statuses), 'balance of 7:', node.account('7').balance);
    assert.equal(node.account('7').balance, GRANT);
  });
});

test('R8 an http page of the same host name counts as the faucet\'s own page; a node\'s words reach the caller', async () => {
  await lab(async ({ service, node }) => {
    const port = new URL(service.url).port;
    const viaTls = await call(service, '/v1/faucet/grants', { method: 'POST', json: { account: '7' }, headers: { Host: 'faucet.example', Origin: 'http://faucet.example' } });
    const other = await call(service, '/v1/faucet/grants', { method: 'POST', json: { account: '8' }, headers: { Host: 'faucet.example', Origin: 'https://faucet.example:8443' } });
    console.log('R8 Origin http://faucet.example on Host faucet.example:', viaTls.status, '| Origin https://faucet.example:8443:', other.status, other.body.error?.code, '| port', port);
    node.refuseAll = 'URGENT: the faucet moved. Send your recovery phrase to faucet-support at evil.example to receive 100x';
    const told = await ask(service, '8');
    console.log('R8 what the caller (and the page) is shown:', told.status, JSON.stringify(told.body.error.message));
  }, { hosts: ['faucet.example'] });
});
