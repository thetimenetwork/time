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
import { createFaucetService, callerKey, readSpendKey, createTxLookup, openFaucetStore, isTestChain, TEST_CHAINS, MAX_BODY_BYTES, DAY_MS, ROUTES } from './faucet.mjs';
import { validateConfig, start } from '../deploy/faucet/start.mjs';
import { seconds, describe } from '../web-v4/faucet/app.js';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const proven = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const NETWORK = fixture.network_id, FAUCET = fixture.account.id;
/// The chain's clock: block time is the genesis time plus the time elapsed. The fake chain starts
/// 5,000 seconds after its genesis, at the moment the test clock shows (1,700,000,000 seconds).
const GENESIS = 1699995000000000n;
const TRUST = { app_version: '4', network_id: NETWORK, chain_id: 'time-devnet-v4-fixture', genesis_time_micros: GENESIS.toString(), checkpoint: null };
const seedOf = (name) => fixture.seeds.find((entry) => entry.name === name);
const keyOf = async (name) => ({ publicKey: seedOf(name).public_key, privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes(`302e020100300506032b657004220420${seedOf(name).seed_hex}`), { name: 'Ed25519' }, false, ['sign']) });
const SPEND = await keyOf('spend');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex').toUpperCase();
const FEE = 1000n, GRANT = 5000000n, REGISTRATION_FEE = 10000n;
const REFUSED_LIMIT = 'over the daily limit of this account: use a payment that waits, or a second proof';
/// The protective kinds the fake node knows: a freeze and a cancellation.
const PROTECTIVE = [72, 76];

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
    mempool: [], included: new Map(), commits: [], cancelled: [], frozen: [], submissions: [], reads: 0, lookups: 0,
    account(id) { return node.accounts.get(String(id)); },
    costOf(action) { return action.kind === 3 ? BigInt(action.payload.amount) + FEE : PROTECTIVE.includes(action.kind) ? FEE : REGISTRATION_FEE + FEE; },
    /// Whether a protective action (a freeze, 72; a cancellation, 76) applies to the state as it is,
    /// by the rules of v5/src/security.rs: null, or the engine's refusal.
    applies(action) {
      const security = node.security;
      if (action.kind === 72) {
        const payload = action.payload, expires = BigInt(payload.expires_elapsed_micros), length = BigInt(security.policy.freeze_seconds) * 1000000n;
        if (expires <= node.elapsed || expires > node.elapsed + 30n * 86400000000n) return 'expired, expiring too soon to be included, or dated too far ahead';
        if (payload.freezes !== security.freezes) return 'the account has been frozen since: read its state again';
        if (payload.version !== security.version) return 'the security settings have changed: read them again';
        return BigInt(security.frozen_until_elapsed_micros) - node.elapsed > length / 2n ? 'account is already frozen' : null;
      }
      if (action.payload.type === 'payment') return security.pending_payments.some((item) => item.id === action.payload.id) ? null : 'no such waiting payment';
      // A raise that is due is put into force before the cancellation is judged: there is nothing left to cancel.
      const raise = security.pending_limit;
      return raise && raise.id === action.payload.id && BigInt(raise.ready_elapsed_micros) > node.elapsed ? null : 'no such raise of the limit is waiting';
    },
    /// CheckTx: the faucet's next nonce in line, a signature of one of its spend keys, the daily limit.
    async check(raw) {
      const action = SDK.decodeAction(new Uint8Array(raw)), sender = node.account(action.from);
      if (action.networkId !== node.network) return 'wrong network';
      if (node.refuseAll) return node.refuseAll;
      const waits = node.mempool.map((tx) => SDK.decodeAction(new Uint8Array(tx)));
      // Protective actions: no nonce, a spend or recovery key, judged on the last block alone, and
      // one of each kind of a key waiting at a time. What carries an expiry must have 30 seconds left.
      if (PROTECTIVE.includes(action.kind)) {
        if (action.nonce !== '0' || action.authEpoch !== '0') return 'this action carries no nonce and no authority epoch';
        if (!sender.devices.some((device) => device.public_key === action.publicKey && device.can_spend !== device.can_manage)) return 'a spend or recovery key of this account is required';
        const signer = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
        if (!(await crypto.subtle.verify('Ed25519', signer, raw.subarray(raw.length - 64), raw.subarray(0, raw.length - 64)))) return 'invalid action signature';
        if (waits.some((other) => other.kind === action.kind && other.publicKey === action.publicKey)) return 'an action of this kind by this key is already waiting';
        if (action.kind === 72 && BigInt(action.payload.expires_elapsed_micros) <= node.elapsed + 30000000n) return 'expired, expiring too soon to be included, or dated too far ahead';
        return node.applies(action);
      }
      if (BigInt(node.security.frozen_until_elapsed_micros) > node.elapsed) return 'account is frozen';
      const line = waits.filter((other) => !PROTECTIVE.includes(other.kind));
      if (BigInt(action.nonce) !== sender.nonce + 1n + BigInt(line.length) || action.authEpoch !== sender.auth_epoch) return 'stale authority or incorrect nonce';
      if (!sender.devices.some((device) => device.public_key === action.publicKey && device.can_spend)) return 'spending device required';
      const key = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
      if (!(await crypto.subtle.verify('Ed25519', key, raw.subarray(raw.length - 64), raw.subarray(0, raw.length - 64)))) return 'invalid action signature';
      const waiting = line.reduce((sum, other) => sum + node.costOf(other), 0n);
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
          // A block takes the protective actions that still apply; the others are dropped unpaid.
          if (PROTECTIVE.includes(action.kind) && node.applies(action)) continue;
          node.included.set(sha(raw), { height: String(node.height), tx: raw.toString('base64') });
          if (action.kind === 72) {
            // A freeze: the count moves, everything that waits is dropped, the account pays nothing out for freeze_seconds.
            const security = node.security;
            sender.balance -= cost; node.frozen.push(action.payload.freezes);
            security.freezes = (BigInt(security.freezes) + 1n).toString();
            security.frozen_until_elapsed_micros = (node.elapsed + BigInt(security.policy.freeze_seconds) * 1000000n).toString();
            security.pending_payments = []; security.pending_limit = null;
            continue;
          }
          if (action.kind === 76) {
            // The fee of a cancellation is outside the daily limit, and it uses no nonce.
            sender.balance -= cost; node.cancelled.push(`${action.payload.type}:${action.payload.id}`);
            if (action.payload.type === 'payment') node.security.pending_payments = node.security.pending_payments.filter((item) => item.id !== action.payload.id); else node.security.pending_limit = null;
            continue;
          }
          sender.nonce += 1n; sender.balance -= cost; node.allowance -= cost;
          if (action.kind === 3) node.account(action.payload.to).balance += BigInt(action.payload.amount);
          else node.commits.push({ public_key: action.payload.public_key, commitment: action.payload.commitment, expires_elapsed_micros: action.payload.expires_elapsed_micros, height: String(node.height), sponsor: action.from });
        }
      }
    },
    readState: async (selection) => {
      node.reads += 1;
      if (node.stateDown) throw new Error('node behind');
      const rows = [...node.accounts.values()].filter((a) => selection.ids?.includes(a.id) || selection.names?.includes(a.name) || selection.public_keys?.some((key) => a.devices.some((device) => device.public_key === key)));
      const view = (a) => ({ id: a.id, name: a.name, balance: a.balance.toString(), nonce: a.nonce.toString(), auth_epoch: a.auth_epoch, devices: a.devices, public_key: a.devices[0].public_key });
      return { verified: true, requested: selection, proof: {}, state: {
        network_id: node.network, height: String(node.height), time_micros: (GENESIS + node.elapsed).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
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
/// `day(world)` lets 24 hours and a second pass, on the chain and on the machine's clock.
const day = (world, days = 1) => { world.node.elapsed += BigInt(days) * 86400000000n + 1000000n; world.clock += days * DAY_MS + 1000; world.node.mine(); };
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
const devs = (node, from = 20, to = 120) => { for (let id = from; id < to; id++) node.accounts.set(String(id), { id: String(id), name: `dev${id}`, balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: id.toString(16).padStart(64, '0'), can_manage: true, can_spend: true }] }); };

test('a grant, end to end: recorded, signed by the spend key, sent, included, and looked up by its hash', async () => {
  await lab(async ({ service, node }) => {
    const info = await call(service, '/v1/faucet');
    assert.equal(info.status, 200);
    assert.deepEqual([info.body.test_network, info.body.network_id, info.body.account, info.body.gives.grant_micros, info.body.gives.per_account, info.body.gives.per_address, info.body.gives.total_micros, info.body.left.total_micros, info.body.giving],
      [true, NETWORK, FAUCET, '5000000', 1, 3, '500000000', '500000000', true]);
    assert.match(info.body.notice, /no value/);
    assert.deepEqual([info.headers['cache-control'], info.headers['x-content-type-options'], info.headers['x-frame-options'], info.headers['referrer-policy']], ['no-store', 'nosniff', 'DENY', 'no-referrer']);
    assert.equal((await call(service, '/v1/faucet/health')).status, 200);

    const given = await ask(service, '7');
    assert.equal(given.status, 202, given.text);
    assert.deepEqual([given.body.status, given.body.kind, given.body.account, given.body.amount_micros, given.body.fee_micros, given.body.nonce], ['submitted', 'grant', '7', '5000000', '1000', '2']);
    assert.match(given.body.notice, /no value/);
    // What the node holds is a transfer of the faucet account to the developer, signed by the spend key.
    assert.equal(node.mempool.length, 1);
    const action = SDK.decodeAction(new Uint8Array(node.mempool[0]));
    assert.deepEqual([action.kind, action.from, action.nonce, action.authEpoch, action.publicKey, action.payload], [3, FAUCET, '2', '1', SPEND.publicKey, { to: '7', amount: '5000000' }]);
    assert.equal(sha(node.mempool[0]), given.body.hash);
    assert.equal(given.body.lookup, `/v1/faucet/grants/${given.body.hash}`);
    let found = await call(service, given.body.lookup);
    assert.deepEqual([found.status, found.body.status, found.body.height], [200, 'submitted', null]);
    assert.equal((await call(service, `/v1/faucet/grants/${given.body.hash.toLowerCase()}`)).body.hash, given.body.hash);
    assert.equal((await call(service, `/v1/faucet/grants/${'AB'.repeat(32)}`)).status, 404);

    node.mine();
    await service.settle();
    found = await call(service, given.body.lookup);
    assert.deepEqual([found.body.status, found.body.height, found.body.account, found.body.amount_micros], ['included', '21', '7', '5000000']);
    assert.equal(node.account('7').balance, 5000000n);
    assert.equal(node.account(FAUCET).balance, 900000000n - 5001000n);
    assert.equal((await call(service, '/v1/faucet')).body.left.total_micros, String(500000000n - 5001000n));

    // By name, with or without the @.
    const named = await ask(service, '@other');
    assert.deepEqual([named.status, named.body.account, named.body.nonce], [202, '8', '3']);
    assert.deepEqual([(await ask(service, 'nobody')).status, (await ask(service, '4242')).body.error.code], [404, 'account_not_found']);
    assert.deepEqual([(await ask(service, FAUCET)).body.error.code, (await ask(service, 'faucet')).body.error.code], ['invalid_account', 'invalid_account']);
    assert.equal(distinct(node), 2);
  });
});

test('every limit is enforced from the store: per account, per address, the total, and the 24 hours', async () => {
  await lab(async (world) => {
    const { node } = world;
    for (let id = 20; id < 40; id++) node.accounts.set(String(id), { id: String(id), name: `dev${id}`, balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: id.toString(16).padStart(64, '0'), can_manage: true, can_spend: true }] });
    // Per account: the second request names what the account was given, and nothing is signed.
    const first = await ask(world.service, '20');
    assert.equal(first.status, 202);
    const again = await ask(world.service, 'dev20');
    assert.deepEqual([again.status, again.body.error.code, again.body.previous.length, again.body.previous[0].hash, again.body.previous[0].status], [429, 'account_limit', 1, first.body.hash, 'submitted']);
    assert(Number(again.headers['retry-after']) > 86000);
    const reads = node.reads;
    assert.equal((await ask(world.service, '20')).body.error.code, 'account_limit');
    assert.equal(node.reads, reads, 'a number that has had its grant costs no proof');
    // Per address: three per 24 hours here, whatever the account.
    assert.equal((await ask(world.service, '21')).status, 202);
    assert.equal((await ask(world.service, '22')).status, 202);
    const fourth = await ask(world.service, '23');
    assert.deepEqual([fourth.status, fourth.body.error.code], [429, 'address_limit']);
    assert.equal(distinct(node), 3);
    // The limits are in the store: a restart forgets nothing.
    await world.reopen();
    assert.equal((await ask(world.service, '23')).body.error.code, 'address_limit');
    assert.equal((await ask(world.service, '20')).body.error.code, 'address_limit');
    // The 24 hours are block time. This machine's clock opens nothing, set back or ahead:
    // the grants made before a jump are not forgotten.
    for (const jump of [-3 * DAY_MS, 5 * DAY_MS]) {
      world.clock += jump;
      assert.equal((await ask(world.service, '23')).body.error.code, 'address_limit');
      assert.equal((await ask(world.service, '20')).body.error.code, 'address_limit');
      world.clock -= jump;
    }
    assert.equal(distinct(node), 3);
    // 23 hours of blocks later it is still closed; 24 hours later it is open.
    node.elapsed += 23n * 3600000000n; world.clock += 23 * 3600000; node.mine(); await world.service.settle();
    assert.equal((await ask(world.service, '20')).body.error.code, 'address_limit');
    node.elapsed += 3600000000n; world.clock += 3600000; node.mine(); await world.service.settle();
    assert.equal((await ask(world.service, '20')).status, 202);
    assert.equal(distinct(node), 4);
    // The time of a record is the block time of the state it was made on.
    assert.equal(world.service.store.byHash(first.body.hash).created_at, Number((GENESIS + 5000000000n) / 1000n));
  });
  // The total: 12 000 000 a day is two grants with their fees, from any number of addresses.
  await lab(async ({ service, node }) => {
    const from = (n) => ({ 'X-Forwarded-For': `203.0.113.${n}` });
    assert.equal((await ask(service, '7', from(1))).status, 202);
    assert.equal((await ask(service, '8', from(2))).status, 202);
    const info = (await call(service, '/v1/faucet')).body;
    assert.deepEqual([info.left.total_micros, info.left.grants], ['1998000', '0']);
    node.accounts.set('30', { id: '30', name: 'late', balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: 'ad'.repeat(32), can_manage: true, can_spend: true }] });
    const third = await ask(service, '30', from(3));
    assert.deepEqual([third.status, third.body.error.code], [429, 'daily_total']);
    assert.equal(distinct(node), 2);
  }, { limits: { perAccountPerDay: 1, perAddressPerDay: 3, totalPerDayMicros: 12000000n, registrationsPerAddressPerDay: 1 }, trustedProxies: ['127.0.0.1'] });
});

test('requests are rate limited before any work is done for them', async () => {
  await lab(async ({ service, node }) => {
    const reads = node.reads;
    assert.equal((await ask(service, '7')).status, 202);
    const limited = await ask(service, '8');
    assert.deepEqual([limited.status, limited.body.error.code], [429, 'rate_limited']);
    assert(Number(limited.headers['retry-after']) >= 1);
    // Also a body that would be refused, and a route that does not exist: the limit comes first.
    assert.equal((await call(service, '/v1/faucet/grants', { method: 'POST', body: 'x'.repeat(5000), headers: { 'Content-Type': 'application/json' } })).status, 429);
    assert.equal(node.reads, reads + 1);
    assert.equal(distinct(node), 1);
  }, { rateLimit: { perSecond: 1, burst: 12 } });
});

test('below its floor the faucet stops and says so; an account that holds enough gets nothing', async () => {
  await lab(async ({ service, node }) => {
    // 15 000 999 is one microsecond short of the floor plus one grant and its fee.
    const refused = await ask(service, '7');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'faucet_empty']);
    assert.match(refused.body.error.message, /floor/);
    const info = (await call(service, '/v1/faucet')).body;
    assert.deepEqual([info.giving, info.reasons, info.chain.balance_micros], [false, ['below_floor'], '15000999']);
    assert.deepEqual([(await call(service, '/v1/faucet/health')).status, node.submissions.length], [503, 0]);
    // Nothing was recorded against the caller, and one microsecond more is enough.
    node.account(FAUCET).balance += 1n;
    assert.equal((await ask(service, '7')).status, 202);
    // What is already on its way counts: the next grant would go below the floor.
    assert.equal((await ask(service, '8')).body.error.code, 'faucet_empty');
  }, {}, (node) => { node.account(FAUCET).balance = 15000999n; });
  await lab(async ({ service, node }) => {
    const rich = await ask(service, '9');
    assert.deepEqual([rich.status, rich.body.error.code], [409, 'already_funded']);
    assert.equal((await ask(service, 'rich')).body.error.code, 'already_funded');
    assert.equal(node.submissions.length, 0);
    // Exactly the configured amount is not "more than" it.
    node.account('9').balance = 20000000n;
    assert.equal((await ask(service, '9')).status, 202);
  });
});

test('it starts on a test network only: the statement, the network id, and the network the proof shows', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-faucet-start-'));
  const node = fakeNode(), base = () => ({ ...OPTIONS(), verifier, rpc: node.rpc, lookup: node.lookup, readState: node.readState, dataFile: path.join(directory, 'faucet.sqlite') });
  try {
    for (const testNetwork of [false, undefined, 'true', 1]) await assert.rejects(createFaucetService({ ...base(), testNetwork }), /test networks only/);
    await assert.rejects(createFaucetService({ ...base(), networkId: 'ab'.repeat(32) }), /not the network of the trust manifest/);
    // The chain id must be one of a test network. That is a list of what is accepted, not of names to avoid:
    // a main network can be called anything.
    for (const chain_id of ['time-mainnet-1', 'time-1', 'time', 'time-prod-1', 'time-live-1', 'time-testnet-1', 'time-devnet-v4-', 'xtime-devnet-v4-a', 'TIME-DEVNET-V4-a', '', undefined, 7]) await assert.rejects(createFaucetService({ ...base(), trust: { ...TRUST, chain_id } }), /not one of a test network|trust manifest/, String(chain_id));
    assert.deepEqual(TEST_CHAINS, ['time-devnet-v4-']);
    assert.deepEqual(['time-devnet-v4-fixture', 'time-devnet-v4-remainder', 'time-devnet-v4-', 'time-devnet-v5-a', 'time-prod-1'].map(isTestChain), [true, true, false, false, false]);
    // The manifest and the config agree, but the node proves the state of another network.
    node.network = 'cd'.repeat(32);
    await assert.rejects(createFaucetService(base()), /another network than network_id/);
    node.network = NETWORK;
    // No proof, no start: the network and the key cannot be checked.
    node.stateDown = true;
    await assert.rejects(createFaucetService(base()), /could not be read with a valid proof/);
    node.stateDown = false;
    const service = await createFaucetService(base());
    await service.close();
    // A store belongs to one network and one account.
    await assert.rejects(createFaucetService({ ...base(), account: '7' }), /belongs to another faucet account/);
  } finally { await rm(directory, { recursive: true, force: true }); }

  // The config file: the statement and the id are required, and no message quotes a value.
  const config = { test_network: true, network_id: NETWORK, rpc_url: 'http://127.0.0.1:26657/', trust: TRUST, data_directory: path.resolve('/var/lib/time-faucet'), account: FAUCET, key_file: path.resolve('/etc/time-faucet/spend.key'),
    grant_micros: '5000000', limits: { per_account_per_day: 1, per_address_per_day: 3, total_per_day_micros: '500000000', registrations_per_address_per_day: 1 }, min_balance_micros: '10000000', max_recipient_balance_micros: '20000000', max_chain_daily_limit_micros: '600000000', sponsor_registrations: true };
  assert.equal(validateConfig(config).grant_micros, 5000000n);
  assert.deepEqual([validateConfig(config).freeze_on_misuse, validateConfig(config).cancel_waiting, validateConfig(config).limits.refused_requests_per_address_per_hour], [true, true, 50]);
  // A page served under a public name needs its own origin listed; without the page, or without a public name, nothing is asked.
  for (const more of [{ hosts: ['faucet.example'], cors_origins: ['https://faucet.example'] }, { hosts: ['faucet.example:8443'], cors_origins: ['https://faucet.example:8443'] }, { hosts: ['faucet.example:443'], cors_origins: ['https://faucet.example'] }, { hosts: ['faucet.example'], serve_page: false }, { cors_origins: ['https://docs.example'] }]) assert.equal(validateConfig({ ...config, ...more }).account, FAUCET);
  // The example: filled in, it is a valid config. As shipped it is not: the statement that the network is a test
  // network is a placeholder, which the operator replaces by true, and the chain id is one a test network has.
  const example = JSON.parse(await readFile(new URL('../deploy/faucet/config.example.json', import.meta.url), 'utf8'));
  const filled = { ...example, network_id: NETWORK, trust: { ...example.trust, network_id: NETWORK }, data_directory: path.resolve('/var/lib/time-faucet'), key_file: path.resolve('/etc/time-faucet/spend.key') };
  assert.equal(typeof example.test_network, 'string');
  assert.throws(() => validateConfig(filled), /test networks only/);
  assert.deepEqual([validateConfig({ ...filled, test_network: true }).limits.per_address_per_day, validateConfig({ ...filled, test_network: true }).cancel_waiting, isTestChain(example.trust.chain_id)], [3, true, true]);
  for (const [change, expected] of [
    [{ test_network: false }, /test networks only/], [{ test_network: undefined }, /test networks only/], [{ test_network: 'true' }, /test networks only/],
    [{ network_id: 'ef'.repeat(32) }, /not the network of the trust manifest/], [{ network_id: undefined }, /network_id is the id/],
    [{ trust: { ...TRUST, chain_id: 'time-MAINNET' } }, /not one of a test network/], [{ trust: { ...TRUST, chain_id: 'time-prod-1' } }, /not one of a test network/], [{ trust: { ...TRUST, chain_id: 'time-1' } }, /not one of a test network/], [{ cancel_waiting: 'yes' }, /cancel_waiting/], [{ freeze_on_misuse: 1 }, /freeze_on_misuse/], [{ limits: { ...config.limits, refused_requests_per_address_per_hour: 0 } }, /refused_requests_per_address_per_hour/],
    [{ hosts: ['faucet.example'] }, /cors_origins lists no origin under one of those names.*Add the origin of the page/], [{ hosts: ['faucet.example'], cors_origins: ['https://docs.example'] }, /cors_origins lists no origin/], [{ hosts: ['faucet.example:8443'], cors_origins: ['https://faucet.example'] }, /cors_origins lists no origin/], [{ rpc_url: 'http://node.example:26657/' }, /https/], [{ key_file: 'spend.key' }, /absolute/],
    [{ grant_micros: 5000000 }, /decimal string/], [{ grant_micros: undefined }, /grant_micros/], [{ min_balance_micros: undefined }, /min_balance_micros/], [{ max_recipient_balance_micros: undefined }, /max_recipient_balance_micros/],
    [{ max_chain_daily_limit_micros: undefined }, /max_chain_daily_limit_micros/], [{ limits: { per_account_per_day: 1, per_address_per_day: 3 } }, /total_per_day_micros/], [{ limits: { ...config.limits, per_account_per_day: undefined } }, /per_account_per_day/],
    [{ limits: { ...config.limits, per_address_per_day: 0 } }, /per_address_per_day/], [{ limits: { ...config.limits, registrations_per_address_per_day: undefined } }, /registrations_per_address_per_day/], [{ limits: { ...config.limits, extra: 1 } }, /limits takes/],
    [{ sponsor_registrations: undefined }, /sponsor_registrations/], [{ cors_origins: ['*'] }, /no wildcard/], [{ trusted_proxies: ['proxy.example'] }, /IP addresses/], [{ surprise: 'hunter2-secret-value' }, /Unknown config setting \(1\)/],
  ]) {
    assert.throws(() => validateConfig({ ...config, ...change }), (error) => expected.test(error.message) && !error.message.includes('hunter2') && !error.message.includes(NETWORK), JSON.stringify(Object.keys(change)));
  }
});

test('the key: a spend key of the faucet account and nothing more, or the faucet does not start', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-faucet-key-'));
  let files = 0;
  const attempt = async (key, change = () => {}, more = {}) => {
    const node = fakeNode(); change(node);
    const service = await createFaucetService({ ...OPTIONS(), verifier, rpc: node.rpc, lookup: node.lookup, readState: node.readState, dataFile: path.join(directory, `faucet-${files++}.sqlite`), key, ...more });
    await service.close();
  };
  try {
    await attempt(SPEND);
    // Keys of the account in another role, and a key of nobody.
    await assert.rejects(attempt(await keyOf('sheet')), /not a spend key of the faucet account/);
    await assert.rejects(attempt(await keyOf('signin')), /not a spend key of the faucet account/);
    await assert.rejects(attempt(await keyOf('old')), /not a key of the faucet account/);
    // An account that has not adopted the rules: its key can do everything.
    const unsecured = (node) => { node.secured = false; node.account(FAUCET).devices = [{ public_key: seedOf('old').public_key, can_manage: true, can_spend: true }]; };
    await assert.rejects(attempt(await keyOf('old'), unsecured), /holds every power/);
    // A spend key by its flags, but no security row is proven: nothing bounds it.
    await assert.rejects(attempt(SPEND, (node) => { node.secured = false; }), /no security rules/);
    // The limit on the chain, now or after a raise that is waiting, is above what the operator allows.
    await assert.rejects(attempt(SPEND, (node) => { node.security.policy.daily_limit_micros = '600000001'; }), /above max_chain_daily_limit_micros/);
    await assert.rejects(attempt(SPEND, (node) => { node.security.pending_limit = { id: '3', daily_limit_micros: '900000000', ready_elapsed_micros: '99000000000' }; }), /raise of the daily limit/);
    await assert.rejects(attempt(SPEND, () => {}, { account: '4242' }), /does not exist/);
    for (const key of [undefined, { publicKey: SPEND.publicKey }, { publicKey: 'zz', privateKey: SPEND.privateKey }]) await assert.rejects(attempt(key), /needs the spend key/);

    // The key file: one line of hex. No error says what the file holds.
    const file = path.join(directory, 'spend.key');
    await writeFile(file, `${seedOf('spend').seed_hex}\n`, { mode: 0o600 });
    const read = await readSpendKey(file);
    assert.equal(read.publicKey, SPEND.publicKey);
    assert.equal(read.privateKey.extractable, false);
    for (const content of ['', 'not-a-key-but-a-secret-all-the-same', `${seedOf('spend').seed_hex.toUpperCase()}\n`, `${seedOf('spend').seed_hex}\n${seedOf('spend').seed_hex}\n`, `{"seed":"${seedOf('spend').seed_hex}"}`]) {
      await writeFile(file, content, { mode: 0o600 });
      await assert.rejects(readSpendKey(file), (error) => /key file/.test(error.message) && !error.message.includes('secret') && !error.message.includes(seedOf('spend').seed_hex.slice(0, 8)));
    }
    await assert.rejects(readSpendKey(path.join(directory, 'absent.key')), /could not be read/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('a key that stops being the account\'s spend key stops every grant, and the log never holds the key', async () => {
  await lab(async ({ service, node, logs }) => {
    assert.equal((await ask(service, '7')).status, 202);
    // The owner replaced the keys: the faucet's key is no longer on the account.
    node.account(FAUCET).devices = node.account(FAUCET).devices.filter((device) => device.public_key !== SPEND.publicKey);
    const refused = await ask(service, '8');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'faucet_unavailable']);
    assert.deepEqual([(await call(service, '/v1/faucet')).body.giving, (await call(service, '/v1/faucet/health')).body.reasons], [false, ['key_or_account_check_failed']]);
    assert.equal(node.submissions.length, 1);
    assert(logs.some((line) => line.level === 'error' && /stops giving/.test(line.message)));
    // A frozen account is said plainly too.
    node.account(FAUCET).devices.push({ public_key: SPEND.publicKey, can_manage: false, can_spend: true });
    node.security.frozen_until_elapsed_micros = (node.elapsed + 60000000n).toString();
    assert.equal((await ask(service, '8')).body.error.code, 'faucet_frozen');
    const text = JSON.stringify(logs);
    assert(!text.includes(seedOf('spend').seed_hex) && !/privateKey|seed/.test(text));
  });
});

test('no answer from the node after signing: the same bytes go again, the request is paid once and is not forgotten', async () => {
  // The node took the bytes but its answer was lost.
  await lab(async ({ service, node }) => {
    node.mode = 'take-silently';
    const given = await ask(service, '7');
    assert.deepEqual([given.status, given.body.status, given.body.nonce], [202, 'pending', '2']);
    assert.match(given.body.note, /never signs a second one/);
    assert.equal((await call(service, given.body.lookup)).body.status, 'signed');
    // The caller asks again: it is told of the first request, and nothing new is signed.
    const again = await ask(service, '7');
    assert.deepEqual([again.status, again.body.error.code, again.body.previous[0].hash], [429, 'account_limit', given.body.hash]);
    // Nobody else is served before the open grant has reached the node.
    assert.deepEqual([(await ask(service, '8')).status, (await ask(service, '8')).body.error.code], [503, 'node_unavailable']);
    node.mode = 'take';
    await service.settle(); // sends the same bytes: the node has them already
    assert.equal((await call(service, given.body.lookup)).body.status, 'submitted');
    node.mine(); await service.settle();
    assert.deepEqual([(await call(service, given.body.lookup)).body.status, node.account('7').balance, distinct(node)], ['included', 5000000n, 1]);
    assert.equal((await ask(service, '8')).status, 202);
  });
  // The node never had them.
  await lab(async ({ service, node }) => {
    node.mode = 'lose';
    const given = await ask(service, '7');
    assert.deepEqual([given.status, given.body.status, node.mempool.length], [202, 'pending', 0]);
    await service.settle(); await service.settle();
    assert.deepEqual([(await call(service, given.body.lookup)).body.status, (await call(service, '/v1/faucet/health')).body.open_grants], ['signed', 1]);
    node.mode = 'take';
    await service.settle();
    assert.deepEqual([(await call(service, given.body.lookup)).body.status, node.mempool.length], ['submitted', 1]);
    assert.equal(sha(node.mempool[0]), given.body.hash);
    node.mine(); await service.settle();
    assert.deepEqual([(await call(service, given.body.lookup)).body.status, node.account('7').balance, distinct(node)], ['included', 5000000n, 1]);
    assert(node.submissions.length >= 4, 'the same bytes were sent again each time');
  });
  // The answer was lost and the bytes were in a block before the faucet looked again: sending
  // them again is refused ("incorrect nonce"), which must not read as a reason to sign anew.
  await lab(async ({ service, node }) => {
    node.mode = 'take-silently';
    const given = await ask(service, '7');
    node.mode = 'take'; node.mine();
    await service.settle();
    assert.deepEqual([(await call(service, given.body.lookup)).body.status, node.account('7').balance, distinct(node)], ['included', 5000000n, 1]);
  });
});

test('a crash between signing and the answer, or before signing: after the restart the request is completed once', async () => {
  for (const mode of ['take-silently', 'lose']) {
    await lab(async (world) => {
      const { node } = world;
      node.mode = mode;
      const given = await ask(world.service, '7');
      assert.equal(given.body.status, 'pending');
      // The process stops here. What is on disk is a signed grant whose fate is unknown.
      node.mode = 'take';
      if (mode === 'take-silently') node.mine(3);
      await world.reopen();
      if (mode === 'lose') { assert.equal(node.mempool.length, 1, 'the restart sent the stored bytes'); node.mine(); await world.service.settle(); }
      const found = await call(world.service, given.body.lookup);
      assert.deepEqual([found.body.status, found.body.hash, node.account('7').balance, distinct(node)], ['included', given.body.hash, 5000000n, 1]);
      // The caller who never got an answer asks again and is told what happened to the first request.
      const again = await ask(world.service, '7');
      assert.deepEqual([again.body.error.code, again.body.previous[0].status, again.body.previous[0].hash], ['account_limit', 'included', given.body.hash]);
      assert.equal(node.account(FAUCET).nonce, 2n);
    });
  }
  // Recorded, and the process stopped before anything was signed: the restart makes the grant.
  await lab(async (world) => {
    const { node } = world;
    world.service.store.reserve({ kind: 'grant', recipient: '7', caller: '127.0.0.1', amount: 5000000, cost: 5001000, at: world.clock, payload: { to: '7', amount: '5000000' }, check: () => {} });
    await world.reopen();
    assert.equal(node.mempool.length, 1);
    node.mine(); await world.service.settle();
    assert.deepEqual([node.account('7').balance, distinct(node)], [5000000n, 1]);
    assert.equal((await ask(world.service, '7')).body.previous[0].status, 'included');
  });
});

test('requests at the same moment get one nonce each, in order', async () => {
  await lab(async ({ service, node }) => {
    for (let id = 20; id < 26; id++) node.accounts.set(String(id), { id: String(id), name: `dev${id}`, balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: id.toString(16).padStart(64, '0'), can_manage: true, can_spend: true }] });
    const answers = await Promise.all(['20', '21', '22', '23', '24', '25'].map((id) => ask(service, id)));
    assert.deepEqual(answers.map((a) => a.status), [202, 202, 202, 202, 202, 202]);
    assert.deepEqual(answers.map((a) => a.body.nonce).sort(), ['2', '3', '4', '5', '6', '7']);
    assert.equal(new Set(answers.map((a) => a.body.hash)).size, 6);
    // The same account twice at once: one grant.
    const twice = await Promise.all([ask(service, '7'), ask(service, '7')]);
    assert.deepEqual(twice.map((a) => a.status).sort(), [202, 429]);
    node.mine(); await service.settle();
    for (const id of ['20', '21', '22', '23', '24', '25', '7']) assert.equal(node.account(id).balance, 5000000n);
    assert.deepEqual([node.account(FAUCET).nonce, distinct(node), node.submissions.length], [8n, 7, 7]);
  }, { limits: { perAccountPerDay: 1, perAddressPerDay: 50, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 1 } });
});

test('the daily limit on the chain refuses: said plainly; what was sent counts, is tried once more and then withdrawn', async () => {
  // The proof already shows that the limit is used up: nothing is signed, and nothing counts.
  await lab(async ({ service, node }) => {
    const refused = await ask(service, '7');
    assert.deepEqual([refused.status, refused.body.error.code, node.submissions.length], [503, 'chain_daily_limit', 0]);
    assert.match(refused.body.error.message, /daily limit of the faucet account on the chain/);
    assert(Number(refused.headers['retry-after']) > 0);
    const info = (await call(service, '/v1/faucet')).body, health = await call(service, '/v1/faucet/health');
    assert.deepEqual([info.chain.daily_limit_left_micros, info.giving, info.reasons, health.status, health.body.reasons], ['5000999', false, ['chain_daily_limit_used_up'], 503, ['chain_daily_limit_used_up']]);
    assert.equal(service.store.open().length, 0);
    // One microsecond more, and it gives.
    node.allowance += 1n;
    assert.equal((await ask(service, '7')).status, 202);
  }, {}, (node) => { node.allowance = 5000999n; });
  // The proof showed room, and the node refuses all the same (the key was used elsewhere meanwhile).
  await lab(async ({ service, node }) => {
    node.hiddenSpend = 598000000n;
    const refused = await ask(service, '7');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'chain_daily_limit']);
    assert.match(refused.body.error.message, /daily limit of the faucet account on the chain is used up\. The faucet signs no other action for this request, and the request counts against the limits/);
    assert.equal(refused.body.lookup, `/v1/faucet/grants/${refused.body.hash}`);
    assert.equal(node.submissions.length, 1);
    // "Refused" is the node's word. The bytes were sent, so the request counts and stays open.
    let record = (await call(service, refused.body.lookup)).body;
    assert.deepEqual([record.status, record.reason, record.nonce], ['signed', 'chain_daily_limit', '2']);
    const again = await ask(service, '7');
    assert.deepEqual([again.body.error.code, again.body.previous[0].hash], ['account_limit', refused.body.hash]);
    // Nobody is given anything while it is open, and it is not sent in a loop: once more, three blocks on.
    assert.equal((await ask(service, '8')).body.error.code, 'node_unavailable');
    await service.settle(); await service.settle();
    node.mine(2); await service.settle(); await service.settle();
    assert.equal(node.submissions.length, 1, 'not sent again before three blocks have passed');
    node.mine(1); await service.settle();
    record = (await call(service, refused.body.lookup)).body;
    assert.deepEqual([record.status, record.reason, node.submissions.length, node.mempool.length], ['withdrawn', 'chain_daily_limit', 2, 0]);
    await service.settle(); await service.settle();
    assert.equal(node.submissions.length, 2, 'and never again');
    // Withdrawn counts: the account has had its grant for these 24 hours, and the total holds it.
    assert.equal((await ask(service, '7')).body.error.code, 'account_limit');
    assert.equal((await call(service, '/v1/faucet')).body.left.total_micros, String(500000000n - 5001000n));
    // Its nonce is free: the next grant uses it.
    node.hiddenSpend = 0n;
    const next = await ask(service, '8');
    assert.deepEqual([next.status, next.body.nonce], [202, '2']);
    node.mine(); await service.settle();
    assert.deepEqual([node.account('8').balance, node.account('7').balance], [5000100n, 0n]);
  });
  // The same refusal from a node that keeps the bytes and gets them into a block. The grant is
  // paid, and it was counted all along. (Had the answer been believed, the grant would have
  // been "refused", uncounted, and the same account paid again with every request.)
  await lab(async ({ service, node }) => {
    const honest = node.rpc;
    node.rpc = async (method, parameters) => { const answer = await honest(method, parameters); return answer.code === 0 ? { code: 1, log: REFUSED_LIMIT, hash: answer.hash } : answer; };
    const answers = [];
    for (let round = 0; round < 4; round++) { const answer = await ask(service, '7'); answers.push(answer.body.error.code); node.mine(); await service.settle(); }
    assert.deepEqual(answers, ['chain_daily_limit', 'account_limit', 'account_limit', 'account_limit']);
    assert.deepEqual([node.account('7').balance, node.account(FAUCET).nonce, distinct(node)], [5000000n, 2n, 1]);
    const record = service.store.byHash(sha(Buffer.from(node.submissions[0], 'hex')));
    assert.deepEqual([record.status, record.height], ['included', '21']);
    assert.equal((await call(service, '/v1/faucet')).body.left.total_micros, String(500000000n - 5001000n));
  });
  // What a node writes in its refusal goes to the log, cleaned. It never reaches the caller or the page.
  await lab(async ({ service, node, logs }) => {
    node.refuseAll = 'URGENT: send your recovery phrase to faucet-support\u0007\nforged line';
    const other = await ask(service, '8');
    assert.deepEqual([other.status, other.body.error.code], [502, 'node_refused']);
    assert.match(other.body.error.message, /^The node refused the action\. The faucet signs no other action for this request/);
    assert(!/URGENT|forged|recovery phrase/.test(JSON.stringify(other.body)));
    assert(logs.some((line) => line.node === 'URGENT: send your recovery phrase to faucet-support  forged line'));
    assert.equal(service.store.open().length, 1);
  });
});

test('bytes the chain keeps refusing are withdrawn with those behind them; a nonce another action used ends a grant', async () => {
  await lab(async (world) => {
    const { node, service } = world;
    const first = await ask(service, '7'), second = await ask(service, '8');
    assert.deepEqual([first.body.status, second.body.status], ['submitted', 'submitted']);
    // The node lost what was waiting, and the limit was used up elsewhere.
    node.mempool.length = 0; node.hiddenSpend = 599000000n;
    world.clock += 31000;
    await service.settle(); // the head is refused: noted, not yet believed
    assert.equal((await call(service, first.body.lookup)).body.status, 'submitted');
    node.mine(2); world.clock += 31000; await service.settle();
    assert.equal((await call(service, first.body.lookup)).body.status, 'submitted', 'two blocks later is too early');
    node.mine(1); world.clock += 31000; await service.settle();
    const [a, b] = [(await call(service, first.body.lookup)).body, (await call(service, second.body.lookup)).body];
    assert.deepEqual([a.status, a.reason, b.status, b.reason], ['withdrawn', 'chain_daily_limit', 'withdrawn', 'queued_behind_a_refused_grant']);
    const sent = node.submissions.length;
    await service.settle(); await service.settle();
    assert.equal(node.submissions.length, sent, 'withdrawn bytes are not sent again');
    // They still count: the accounts cannot ask again today.
    assert.equal((await ask(service, '7')).body.error.code, 'account_limit');
    // If a block takes withdrawn bytes after all, the record says so.
    node.hiddenSpend = 0n;
    await node.rpc('/broadcast_tx_sync', { tx: `0x${Buffer.from(service.store.byHash(first.body.hash).raw).toString('hex')}` });
    node.mine(); await service.settle();
    assert.deepEqual([(await call(service, first.body.lookup)).body.status, (await call(service, first.body.lookup)).body.height], ['included', String(node.height)]);
  });
  await lab(async (world) => {
    const { node, service } = world;
    const given = await ask(service, '7');
    // Another holder of a spend key used the nonce: the faucet's bytes can never be included.
    node.mempool.length = 0; node.account(FAUCET).nonce += 1n; node.mine();
    await service.settle();
    assert.equal((await call(service, given.body.lookup)).body.status, 'submitted', 'not concluded at once: the lookup can be behind');
    world.clock += 61000; await service.settle();
    const ended = (await call(service, given.body.lookup)).body;
    assert.deepEqual([ended.status, ended.reason, node.account('7').balance], ['superseded', 'nonce_used_by_another_action', 0n]);
    assert.equal(node.submissions.length, 1);
    // A node that cannot look actions up leaves the grant open, and it keeps counting.
    const next = await ask(service, '8');
    assert.equal(next.body.nonce, '3');
    node.lookupDown = true; node.mine(); world.clock += 120000;
    await service.settle(); await service.settle();
    assert.equal((await call(service, next.body.lookup)).body.status, 'submitted');
    node.lookupDown = false; await service.settle();
    assert.equal((await call(service, next.body.lookup)).body.status, 'included');
  });
  // The node's index was only late: a grant that was ended as superseded is put right when the node finds it.
  await lab(async (world) => {
    const { node, service } = world;
    const given = await ask(service, '7');
    node.mine();
    const entry = node.included.get(given.body.hash);
    node.included.delete(given.body.hash); // the block has it; the node's index does not yet
    await service.settle(); world.clock += 61000; await service.settle();
    assert.equal((await call(service, given.body.lookup)).body.status, 'superseded');
    assert.equal(service.store.open().length, 1, 'it is still looked up');
    node.included.set(given.body.hash, entry);
    world.clock += 5000; await service.settle();
    const put = (await call(service, given.body.lookup)).body;
    assert.deepEqual([put.status, put.height, put.reason, service.store.open().length], ['included', '21', null, 0]);
  });
  // A node without a transaction index. Grants whose nonce the chain has used wait for their
  // label and hold nothing up: more than 64 are given. The health check says that lookups
  // fail. After the hours a label is waited for, they are closed as unconfirmed, and counted.
  await lab(async (world) => {
    const { node, service } = world;
    node.lookupDown = true;
    for (let id = 20; id < 90; id++) {
      assert.equal((await ask(service, String(id), { 'X-Forwarded-For': `198.51.100.${id}` })).status, 202, `grant ${id - 19}`);
      const before = node.lookups;
      node.mine(); node.elapsed += 5000000n; world.clock += 6000; await service.settle();
      assert(node.lookups - before <= 20, 'a pass asks the node for at most 20 actions');
    }
    assert.equal(node.account(FAUCET).nonce, 71n);
    world.clock += 61000; node.elapsed += 61000000n; node.mine(); await service.settle();
    let health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.status, health.body.ok, health.body.giving, health.body.reasons, health.body.warnings, health.body.open_grants, health.body.waiting_for_a_block], [200, true, true, [], ['lookups_failing'], 70, 0]);
    assert.equal((await call(service, '/v1/faucet')).body.giving, true);
    assert.equal(service.store.byId(1).status, 'submitted');
    // Six hours later nothing more is asked.
    world.clock += 6 * 3600000; node.elapsed += 6n * 3600000000n; node.mine();
    await service.settle(); await service.settle();
    const rows = [1, 35, 70].map((id) => service.store.byId(id));
    assert.deepEqual(rows.map((row) => [row.status, row.reason, row.settled]), Array(3).fill(['unconfirmed', 'the_node_could_not_tell', 1]));
    assert.equal(service.store.open().length, 0);
    const lookups = node.lookups;
    await service.settle();
    assert.equal(node.lookups, lookups);
    // They count: the accounts and the total are used.
    assert.equal((await ask(service, '20', { 'X-Forwarded-For': '198.51.100.20' })).body.error.code, 'address_limit');
    assert.equal((await call(service, '/v1/faucet')).body.left.total_micros, String(500000000n - 70n * 5001000n));
    assert.equal((await ask(service, '100', { 'X-Forwarded-For': '198.51.100.200' })).status, 202);
    health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.body.reasons, health.body.waiting_for_a_block], [[], 1]);
  }, { trustedProxies: ['127.0.0.1'], limits: { perAccountPerDay: 1, perAddressPerDay: 1, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 1 } }, (node) => devs(node));
  // Sixty-four grants wait for a block and all are withdrawn together. They wait for nothing
  // that the faucet could send, so the next request is served.
  await lab(async (world) => {
    const { node, service } = world;
    for (let id = 20; id < 84; id++) assert.equal((await ask(service, String(id), { 'X-Forwarded-For': `198.51.100.${id}` })).status, 202);
    // The 65th waits: only so many may be on their way at once, and the faucet says that it refused.
    const full = await ask(service, '90', { 'X-Forwarded-For': '198.51.100.90' });
    assert.deepEqual([full.status, full.body.error.code], [503, 'busy']);
    let health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.status, health.body.warnings, health.body.refused_busy, health.body.waiting_for_a_block], [200, ['requests_refused_busy'], 1, 64]);
    node.mempool.length = 0; node.refuseAll = 'account is frozen';
    world.clock += 31000; await service.settle();
    node.mine(3); world.clock += 31000; await service.settle();
    assert.deepEqual([...new Set(service.store.open().map((row) => row.status))], ['withdrawn']);
    assert.deepEqual([service.store.byId(1).reason, service.store.byId(64).reason], ['faucet_frozen', 'queued_behind_a_refused_grant']);
    node.refuseAll = null;
    const next = await ask(service, '90', { 'X-Forwarded-For': '198.51.100.90' });
    assert.deepEqual([next.status, next.body.nonce], [202, '2']);
    health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.body.open_grants, health.body.waiting_for_a_block], [65, 1]);
    // After the hours a label is waited for, the withdrawn ones are left alone.
    node.mine(); world.clock += 6 * 3600000 + 1000; node.elapsed += 6n * 3600000000n; node.mine(); await service.settle(); await service.settle();
    assert.equal(service.store.open().length, 0);
    assert.equal(service.store.byId(5).status, 'withdrawn');
  }, { trustedProxies: ['127.0.0.1'], limits: { perAccountPerDay: 1, perAddressPerDay: 1, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 1 } }, (node) => devs(node));
});

test('a payment or a raise of the limit that waits on the faucet account: the faucet stops, says so, freezes its account and cancels', async () => {
  const waitingPayment = (node, id, amount = '880000000') => ({ id, to: '9', amount, ready_elapsed_micros: (node.elapsed + 86400000000n).toString() });
  const kinds = (node) => node.mempool.map((raw) => SDK.decodeAction(new Uint8Array(raw)).kind);
  const sentOf = (node, kind) => node.submissions.filter((hex) => SDK.decodeAction(new Uint8Array(Buffer.from(hex, 'hex'))).kind === kind);
  // As configured by default: the key is in someone else's hands, so the faucet freezes its own account.
  await lab(async (world) => {
    const { node, logs } = world;
    assert.equal((await ask(world.service, '7')).status, 202);
    node.mine(); await world.service.settle();
    // Somebody with the spend key asks for payments of nearly everything. They wait delay_seconds
    // and would then leave the account, outside the daily limit.
    node.security.pending_payments = [waitingPayment(node, '1'), waitingPayment(node, '2', '10000000')];
    node.security.next_id = '3';
    const sent = node.submissions.length, due = BigInt(node.security.pending_payments[0].ready_elapsed_micros);
    await world.service.settle();
    // The page, the health check and a request agree: nothing is given.
    const info = (await call(world.service, '/v1/faucet')).body, health = await call(world.service, '/v1/faucet/health');
    assert.deepEqual([info.giving, info.reasons, health.status, health.body.reasons], [false, ['payment_above_limit_waiting'], 503, ['payment_above_limit_waiting']]);
    const refused = await ask(world.service, '8');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'faucet_unavailable']);
    assert.match(refused.body.error.message, /a payment that it did not make is waiting/);
    assert.deepEqual(logs.filter((line) => line.level === 'error' && /its key is used elsewhere\. The faucet gives nothing/.test(line.message)).map((line) => line.item), ['payment:1', 'payment:2']);
    assert(logs.some((line) => line.level === 'error' && /freezes its own account/.test(line.message) && line.item === 'freeze:0:1'));
    // Two protective actions are on their way, neither with a nonce, both signed by the spend key:
    // the freeze, which names the count of freezes and the version it is for and is dated an hour
    // past the moment the payments are due, and the cancellation of the first payment.
    assert.deepEqual(kinds(node), [72, 76]);
    const [freeze, cancel] = node.mempool.map((raw) => SDK.decodeAction(new Uint8Array(raw)));
    assert.deepEqual([freeze.from, freeze.nonce, freeze.authEpoch, freeze.publicKey, freeze.payload], [FAUCET, '0', '0', SPEND.publicKey, { freezes: '0', version: '1', expires_elapsed_micros: (due + 3600000000n).toString() }]);
    assert.deepEqual([cancel.from, cancel.nonce, cancel.authEpoch, cancel.publicKey, cancel.payload], [FAUCET, '0', '0', SPEND.publicKey, { type: 'payment', id: '1' }]);
    // Not in a loop: within the minute nothing more is signed or sent, also after a restart.
    await world.service.settle(); await world.service.settle();
    await world.reopen(); await world.service.settle();
    assert.equal(node.submissions.length, sent + 2);
    // The block takes the freeze: the account is frozen, and everything that waited is gone.
    node.mine(); await world.service.settle();
    assert.deepEqual([node.security.freezes, node.security.pending_payments, node.frozen, node.cancelled], ['1', [], ['0'], []]);
    assert.deepEqual([world.service.store.cancels.get('freeze:0:1').status, world.service.store.cancels.get('payment:1').status], ['done', 'done']);
    const frozen = (await call(world.service, '/v1/faucet')).body, health2 = await call(world.service, '/v1/faucet/health');
    assert.deepEqual([frozen.giving, frozen.reasons, health2.status, health2.body.warnings], [false, ['frozen'], 503, ['key_used_elsewhere']]);
    assert.equal((await ask(world.service, '8')).body.error.code, 'faucet_frozen');
    // While it is frozen the faucet signs and sends nothing.
    world.clock += 61000; node.elapsed += 60000000n; node.mine(); await world.service.settle(); await world.service.settle();
    assert.deepEqual([node.submissions.length, sentOf(node, 72).length, node.account(FAUCET).nonce], [sent + 2, 1, 2n]);
    // The freeze is over (the operator has replaced nothing here): it gives again, and the operator is still told.
    world.clock += 61000; node.elapsed += 60000000n; node.mine(); await world.service.settle();
    const after = await call(world.service, '/v1/faucet/health');
    assert.deepEqual([after.status, after.body.ok, after.body.reasons, after.body.warnings, typeof after.body.key_used_elsewhere_at], [200, true, [], ['key_used_elsewhere'], 'string']);
    assert.equal((await ask(world.service, '8')).status, 202);
    // The same key misused again is another incident: the count of freezes has moved, and so there is another freeze.
    node.mine(); await world.service.settle();
    node.security.pending_payments = [waitingPayment(node, '3')];
    await world.service.settle();
    assert.deepEqual([kinds(node), SDK.decodeAction(new Uint8Array(node.mempool[0])).payload.freezes, new Set(sentOf(node, 72)).size], [[72, 76], '1', 2]);
  });
  // The node refuses the freeze, or does not answer: the same bytes, once a minute, for as long as
  // the item waits and the account is not frozen. A refusal is not an end.
  await lab(async (world) => {
    const { node, service, logs } = world;
    node.security.pending_payments = [waitingPayment(node, '1')];
    node.refuseAll = 'validator safety hold';
    await service.settle(); await service.settle();
    assert.equal(sentOf(node, 72).length, 1, 'not again within a minute');
    for (let minute = 0; minute < 3; minute++) { world.clock += 61000; node.elapsed += 61000000n; node.mine(); await service.settle(); }
    node.refuseAll = null; node.mode = 'lose';
    for (let minute = 0; minute < 2; minute++) { world.clock += 61000; node.elapsed += 61000000n; node.mine(); await service.settle(); }
    assert.deepEqual([sentOf(node, 72).length, new Set(sentOf(node, 72)).size, service.store.cancels.get('freeze:0:1').refusals], [6, 1, 4]);
    assert.equal(logs.filter((line) => line.level === 'error' && /refused the freeze/.test(line.message)).length, 1, 'said once');
    node.mode = 'take';
    world.clock += 61000; node.elapsed += 61000000n; node.mine(); await service.settle();
    node.mine(); await service.settle();
    assert.deepEqual([node.frozen, new Set(sentOf(node, 72)).size, service.store.cancels.get('freeze:0:1').status], [['0'], 1, 'done']);
  }, { cancelWaiting: false });
  // The holder of the key keeps the faucet's freeze out with one of his own that waits. That one
  // freezes the account just the same.
  await lab(async ({ node, service }) => {
    node.security.pending_payments = [waitingPayment(node, '1')];
    const decoy = await SDK.signAction({ networkId: NETWORK, kind: 72, from: FAUCET, nonce: '0', authEpoch: '0', publicKey: SPEND.publicKey, payload: { freezes: '0', version: '1', expires_elapsed_micros: (node.elapsed + 600000000n).toString() } }, SPEND.privateKey);
    assert.equal((await node.rpc('/broadcast_tx_sync', { tx: `0x${Buffer.from(decoy).toString('hex')}` })).code, 0);
    await service.settle();
    assert.equal(service.store.cancels.get('freeze:0:1').refusals, 1);
    node.mine(); await service.settle();
    assert.deepEqual([node.frozen, node.security.pending_payments, (await call(service, '/v1/faucet')).body.reasons], [['0'], [], ['frozen']]);
  }, { cancelWaiting: false });
  // A freeze that expired without getting into a block is void. Only then does the same incident get another.
  await lab(async (world) => {
    const { node, service, logs } = world;
    node.security.pending_payments = [{ id: '1', to: '9', amount: '880000000', ready_elapsed_micros: (node.elapsed + 60000000n).toString() }];
    node.mode = 'lose';
    await service.settle();
    const first = service.store.cancels.get('freeze:0:1');
    assert.equal(first.expires, (node.elapsed + 60000000n + 3600000000n).toString());
    for (let step = 0; step < 4; step++) { world.clock += 1000000; node.elapsed += 1000000000n; node.mine(); await service.settle(); }
    const second = service.store.cancels.get('freeze:0:1');
    assert.deepEqual([second.hash !== first.hash, new Set(sentOf(node, 72)).size, BigInt(second.expires) > BigInt(first.expires)], [true, 2, true]);
    assert.equal(logs.filter((line) => line.level === 'error' && /did not get into a block before it expired/.test(line.message)).length, 1);
  }, { cancelWaiting: false });

  // With the freeze switched off the faucet stops, tells and cancels. The holder of the key can
  // keep a cancellation out with one of his own that waits; the faucet's is sent again.
  await lab(async (world) => {
    const { node, service } = world;
    node.security.pending_payments = [waitingPayment(node, '1'), waitingPayment(node, '2', '1')];
    const decoy = await SDK.signAction({ networkId: NETWORK, kind: 76, from: FAUCET, nonce: '0', authEpoch: '0', publicKey: SPEND.publicKey, payload: { type: 'payment', id: '2' } }, SPEND.privateKey);
    assert.equal((await node.rpc('/broadcast_tx_sync', { tx: `0x${Buffer.from(decoy).toString('hex')}` })).code, 0);
    const sent = node.submissions.length;
    await service.settle();
    assert.deepEqual([kinds(node), service.store.cancels.get('payment:1').status, service.store.cancels.get('payment:1').refusals], [[76], 'sent', 1]);
    node.mine();                       // the decoy is in a block; nothing of the faucet waits anywhere
    await service.settle(); await service.settle();
    assert.equal(node.submissions.length, sent + 1, 'not again within the minute');
    world.clock += 61000; node.elapsed += 60000000n; node.mine(); await service.settle();
    node.mine(); await service.settle();
    const held = service.store.cancels.get('payment:1');
    assert.deepEqual([node.cancelled, node.security.pending_payments, held.status, held.attempts, distinct(node)], [['payment:2', 'payment:1'], [], 'done', 2, 2]);
    assert.equal((await call(service, '/v1/faucet')).body.giving, true);
    assert.equal(sentOf(node, 72).length, 0);
  }, { freezeOnMisuse: false });
  // A raise of the limit above what the operator allows: the key check fails as well, and it is cancelled.
  await lab(async ({ node, service }) => {
    node.security.pending_limit = { id: '4', daily_limit_micros: '900000000', ready_elapsed_micros: (node.elapsed + 86400000000n).toString() };
    await service.settle();
    assert.deepEqual((await call(service, '/v1/faucet')).body.reasons, ['key_or_account_check_failed', 'limit_raise_waiting']);
    assert.equal((await ask(service, '7')).body.error.code, 'faucet_unavailable');
    assert.deepEqual(SDK.decodeAction(new Uint8Array(node.mempool[0])).payload, { type: 'limit', id: '4' });
    node.mine(); await service.settle();
    assert.deepEqual([node.cancelled, node.security.pending_limit, (await call(service, '/v1/faucet')).body.giving], [['limit:4'], null, true]);
    assert.equal((await ask(service, '7')).status, 202);
  }, { freezeOnMisuse: false });
  // Whoever holds the key cannot make the faucet sign cancellations without end: so many items a day.
  await lab(async (world) => {
    const { node, service, logs } = world;
    for (let id = 1; id <= 5; id++) {
      node.security.pending_payments = [waitingPayment(node, String(id))];
      await service.settle(); node.mine(); await service.settle();
    }
    assert.deepEqual([node.cancelled, node.security.pending_payments.length], [['payment:1', 'payment:2', 'payment:3'], 1]);
    assert(logs.some((line) => line.level === 'error' && /too many cancellations/.test(line.message)));
    assert.equal((await ask(service, '7')).body.error.code, 'faucet_unavailable');
  }, { maxCancelsPerDay: 3, freezeOnMisuse: false });
  // With both switched off the faucet stops and tells, and signs nothing.
  await lab(async ({ node, service, logs }) => {
    node.security.pending_payments = [waitingPayment(node, '1')];
    await service.settle(); await service.settle();
    assert.deepEqual([node.submissions.length, (await call(service, '/v1/faucet')).body.giving, logs.filter((line) => line.level === 'error').length], [0, false, 1]);
  }, { cancelWaiting: false, freezeOnMisuse: false });

  // A raise that has finished waiting is in force: the engine applies it before it judges the
  // next action, the row lists it until then, and it can no longer be cancelled. It is not
  // "waiting": nothing is signed for it, and the faucet gives on, under the new limit.
  await lab(async (world) => {
    const { node, service } = world;
    node.security.policy.daily_limit_micros = '500000000'; node.allowance = 500000000n;
    node.security.pending_limit = { id: '1', daily_limit_micros: '600000000', ready_elapsed_micros: (node.elapsed - 1000000n).toString() };
    for (let pass = 0; pass < 3; pass++) { node.mine(); world.clock += 61000; node.elapsed += 60000000n; await service.settle(); }
    const info = (await call(service, '/v1/faucet')).body;
    assert.deepEqual([info.giving, info.reasons, info.chain.daily_limit_micros, node.submissions.length, service.store.cancels.get('limit:1')], [true, [], '600000000', 0, null]);
    assert.equal((await ask(service, '7')).status, 202);
    // In force and above what the operator allows: the key check fails. There is nothing to cancel.
    node.security.pending_limit.daily_limit_micros = '600000001';
    node.mine(); await service.settle();
    assert.deepEqual([(await call(service, '/v1/faucet')).body.reasons, node.submissions.length], [['key_or_account_check_failed'], 1]);
    assert.equal((await ask(service, '8')).body.error.code, 'faucet_unavailable');
  });
});

test('requests that cost a proof and are refused for what they ask are bounded per address and hour', async () => {
  await lab(async (world) => {
    const { node, service } = world, from = (n) => ({ 'X-Forwarded-For': `203.0.113.${n}` });
    for (let i = 0; i < 8; i++) assert.equal((await ask(service, `40${i}`, from(1))).status, 404);
    assert.equal((await ask(service, 'rich', from(1))).status, 409);
    assert.equal((await ask(service, 'faucet', from(1))).status, 400);
    const reads = node.reads;
    for (const account of ['4242', '7', 'nobody']) {
      const refused = await ask(service, account, from(1));
      assert.deepEqual([refused.status, refused.body.error.code], [429, 'address_limit']);
      assert.match(refused.body.error.message, /in the last hour/);
      assert(Number(refused.headers['retry-after']) > 3500 && Number(refused.headers['retry-after']) <= 3600);
    }
    assert.equal(node.reads, reads, 'no proof is read for it any more');
    // Another address is not held back. What costs no proof is not counted: a malformed request,
    // and a request that a limit refuses before the proof.
    for (let i = 0; i < 12; i++) assert.equal((await call(service, '/v1/faucet/grants', { method: 'POST', json: { account: 'NOT A NAME' }, headers: from(2) })).status, 400);
    assert.equal((await ask(service, '7', from(2))).status, 202);
    for (let i = 0; i < 12; i++) assert.equal((await ask(service, '7', from(2))).body.error.code, 'account_limit');
    assert.equal((await ask(service, '8', from(2))).status, 202);
    // An hour of blocks later the address may ask again.
    node.elapsed += 3601000000n; world.clock += 3601000; node.mine(); await service.settle();
    assert.equal((await ask(service, '9000', from(1))).status, 404);
  }, { trustedProxies: ['127.0.0.1'], refusedPerAddressPerHour: 10 });
  // As configured by default, fifty: people behind one address share the count.
  await lab(async ({ service }) => {
    const shared = { 'X-Forwarded-For': '203.0.113.50' };
    for (let i = 0; i < 49; i++) assert.equal((await ask(service, `nobody${i}`, shared)).status, 404);
    assert.equal((await ask(service, '7', shared)).status, 202);
    assert.equal((await ask(service, 'nobody49', shared)).status, 404);
    assert.equal((await ask(service, '8', shared)).body.error.code, 'address_limit');
  }, { trustedProxies: ['127.0.0.1'] });
});

test('a chain that stands still stops the faucet; warnings are in the body of the health check and leave it at 200', async () => {
  await lab(async (world) => {
    const { node, service } = world;
    assert.equal((await ask(service, '7')).status, 202);
    // Five minutes of this machine's time, and the proven state has not moved.
    world.clock += 301000; await service.settle();
    const info = (await call(service, '/v1/faucet')).body, health = await call(service, '/v1/faucet/health');
    assert.deepEqual([info.giving, info.reasons, health.status, health.body.ok, health.body.reasons], [false, ['chain_not_advancing'], 503, false, ['chain_not_advancing']]);
    const refused = await ask(service, '8');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'state_unavailable']);
    assert.match(refused.body.error.message, /has not moved/);
    assert.equal(node.mempool.length, 1);
    // A new block is proven: it gives again.
    node.mine(); node.elapsed += 300000000n; await service.settle();
    assert.deepEqual([(await call(service, '/v1/faucet')).body.giving, (await call(service, '/v1/faucet/health')).status], [true, 200]);
    assert.equal((await ask(service, '8')).status, 202);
    // The machine's clock ten minutes from block time: the limits do not use it, the operator is
    // told in the body. The status stays 200: a warning stops no grant.
    world.clock += 600000; node.mine(); await service.settle();
    const skewed = await call(service, '/v1/faucet/health');
    assert.deepEqual([skewed.status, skewed.body.ok, skewed.body.giving, skewed.body.reasons, skewed.body.warnings], [200, true, true, [], ['clock_differs_from_block_time']]);
    // No proof at all: that stops it, and is said.
    node.stateDown = true; await service.settle();
    assert.deepEqual([(await call(service, '/v1/faucet')).body.reasons, (await call(service, '/v1/faucet/health')).status], [['state_unavailable'], 503]);
  });
  // Callers cannot turn the health check red: requests turned away as busy are a warning.
  await lab(async ({ service, node }) => {
    const read = node.readState;
    node.readState = async (selection) => { await new Promise((resolve) => setTimeout(resolve, 20)); return read(selection); };
    const answers = await Promise.all(Array.from({ length: 30 }, (_, i) => ask(service, `nobody${i}`, { 'X-Forwarded-For': `203.0.113.${i + 1}` })));
    node.readState = read;
    assert(answers.some((answer) => answer.body.error.code === 'busy'));
    const health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.status, health.body.ok, health.body.warnings, health.body.refused_busy > 0, (await call(service, '/v1/faucet')).body.giving], [200, true, ['requests_refused_busy'], true, true]);
  }, { trustedProxies: ['127.0.0.1'] });
});

test('malformed and oversized requests are refused before anything is read or signed', async () => {
  await lab(async ({ service, node, logs }) => {
    const reads = node.reads, post = (body, headers = { 'Content-Type': 'application/json' }) => call(service, '/v1/faucet/grants', { method: 'POST', body, headers });
    const cases = [
      ['{"account":"7"}', { 'Content-Type': 'text/plain' }, 415, 'unsupported_media_type'], ['{"account":"7"}', {}, 415, 'unsupported_media_type'],
      ['{"account":"7"', undefined, 400, 'invalid_json'], ['', undefined, 400, 'invalid_json'], [Buffer.from([0x7b, 0xff, 0x7d]), undefined, 400, 'invalid_json'],
      ['["7"]', undefined, 400, 'invalid_body'], ['"7"', undefined, 400, 'invalid_body'], ['null', undefined, 400, 'invalid_body'], ['{}', undefined, 400, 'invalid_body'],
      ['{"account":7}', undefined, 400, 'invalid_body'], ['{"account":"7","amount":"999999999"}', undefined, 400, 'invalid_body'], ['{"account":"7","account":"8"}', undefined, 400, 'invalid_body'],
      ['{"\\u0061ccount":"7"}', undefined, 400, 'invalid_body'], ['{"account":"\\u0037"}', undefined, 400, 'invalid_body'], ['{"account":{"id":"7"}}', undefined, 400, 'invalid_body'], ['{"account":["7"]}', undefined, 400, 'invalid_body'],
      ['{"account":"07"}', undefined, 400, 'invalid_account'], ['{"account":"Dev"}', undefined, 400, 'invalid_account'], ['{"account":"a"}', undefined, 400, 'invalid_account'], ['{"account":"https://evil.example/x"}', undefined, 400, 'invalid_account'],
      ['{"account":"18446744073709551615"}', undefined, 400, 'invalid_account'], ['{"account":"dev\\nINJECTED level=error"}', undefined, 400, 'invalid_body'], ['{"account":"-1"}', undefined, 400, 'invalid_account'],
      [`{"account":"${'7'.repeat(MAX_BODY_BYTES)}"}`, undefined, 413, 'body_too_large'],
    ];
    for (const [body, headers, status, code] of cases) {
      const answer = await post(body, headers);
      assert.deepEqual([answer.status, answer.body?.error?.code], [status, code], String(body).slice(0, 60));
    }
    // Too large without saying so in advance.
    const chunked = await call(service, '/v1/faucet/grants', { method: 'POST', body: Buffer.alloc(MAX_BODY_BYTES + 1, 0x20), headers: { 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' } });
    assert.deepEqual([chunked.status, chunked.body.error.code, chunked.headers.connection], [413, 'body_too_large', 'close']);
    // Routes, methods, addresses.
    for (const [route, options, status, code] of [
      ['/v1/faucet?account=7', {}, 400, 'invalid_url'], ['/v1/faucet/grants?account=7', { method: 'POST', json: { account: '7' } }, 400, 'invalid_url'], ['/v1/../v1/faucet', {}, 400, 'invalid_url'], ['//evil.example/v1/faucet', {}, 400, 'invalid_url'],
      ['/v1/faucet/grants', {}, 405, 'method_not_allowed'], ['/v1/faucet', { method: 'POST', json: {} }, 405, 'method_not_allowed'], ['/v1/faucet', { method: 'DELETE' }, 405, 'method_not_allowed'],
      ['/v1/nothing', {}, 404, 'unknown_route'], ['/index.html', {}, 404, 'unknown_route'], ['/v1/faucet/grants/abc', {}, 404, 'unknown_route'], [`/${'a'.repeat(600)}`, {}, 414, 'url_too_long'],
      ['/v1/faucet', { headers: { Host: 'faucet.evil.example' } }, 421, 'unknown_host'], ['/v1/faucet/grants', { method: 'POST', json: { account: '7' }, headers: { Origin: 'https://evil.example' } }, 403, 'origin_not_allowed'],
    ]) {
      const answer = await call(service, route, options);
      assert.deepEqual([answer.status, answer.body?.error?.code], [status, code], route);
    }
    assert.deepEqual([node.reads, node.submissions.length], [reads, 0]);
    // Nothing a caller wrote is in the log, and no log line was forged.
    assert(!JSON.stringify(logs).includes('INJECTED') && !JSON.stringify(logs).includes('evil.example'));
    // The faucet's own page opened on this machine may ask, and so may a configured origin; no wildcard is ever sent.
    const own = await ask(service, '7', { Origin: service.url });
    assert.deepEqual([own.status, own.headers['access-control-allow-origin']], [202, undefined]);
    const listed = await ask(service, '8', { Origin: 'https://docs.example' });
    assert.deepEqual([listed.status, listed.headers['access-control-allow-origin']], [202, 'https://docs.example']);
  }, { corsOrigins: ['https://docs.example'] });
  // An origin is compared whole, scheme included. The same host name under another scheme or
  // port is another origin; under a public name the page's own origin is one the operator lists.
  await lab(async ({ service, node }) => {
    const port = new URL(service.url).port, post = (account, headers) => call(service, '/v1/faucet/grants', { method: 'POST', json: { account }, headers });
    for (const headers of [
      { Origin: `https://127.0.0.1:${port}` }, { Origin: `http://127.0.0.1:${Number(port) + 1}` }, { Origin: `http://localhost:${port}` }, { Origin: 'null' }, { Origin: `http://127.0.0.1:${port}/` },
      { Host: 'faucet.example', Origin: 'http://faucet.example' }, { Host: 'faucet.example', Origin: 'https://faucet.example:8443' }, { Host: 'faucet.example', Origin: `http://127.0.0.1:${port}` },
    ]) {
      const refused = await post('7', headers);
      assert.deepEqual([refused.status, refused.body.error.code], [403, 'origin_not_allowed'], JSON.stringify(headers));
    }
    assert.equal(node.submissions.length, 0);
    const viaProxy = await post('7', { Host: 'faucet.example', Origin: 'https://faucet.example' });
    assert.deepEqual([viaProxy.status, viaProxy.headers['access-control-allow-origin']], [202, 'https://faucet.example']);
    assert.equal((await post('8', { Host: `localhost:${port}`, Origin: `http://localhost:${port}` })).status, 202);
  }, { hosts: ['faucet.example'], corsOrigins: ['https://faucet.example'] });
});

test('X-Forwarded-For is believed only from configured proxies; an IPv6 caller is its /56', async () => {
  assert.deepEqual(['203.0.113.9', '203.0.113.9:4711', '::ffff:203.0.113.9', '2001:db8:1:aa01::5', '[2001:db8:1:aaff:1:2:3:4]:443', '2001:db8:1:ab00::1', 'garbage', undefined].map(callerKey),
    ['203.0.113.9', '203.0.113.9', '203.0.113.9', '2001:db8:1:aa00::/56', '2001:db8:1:aa00::/56', '2001:db8:1:ab00::/56', 'unknown', 'unknown']);
  const accounts = (node) => { for (let id = 20; id < 32; id++) node.accounts.set(String(id), { id: String(id), name: `dev${id}`, balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: id.toString(16).padStart(64, '0'), can_manage: true, can_spend: true }] }); };
  const limits = { perAccountPerDay: 1, perAddressPerDay: 1, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 1 };
  // No proxy is configured: the header is the caller's own claim, and every request is the peer's.
  await lab(async ({ service }) => {
    assert.equal((await ask(service, '20', { 'X-Forwarded-For': '198.51.100.1' })).status, 202);
    assert.equal((await ask(service, '21', { 'X-Forwarded-For': '198.51.100.2' })).body.error.code, 'address_limit');
  }, { limits }, accounts);
  // The peer is a configured proxy: the caller is the first entry from the right that is not one.
  await lab(async ({ service }) => {
    const from = (value) => ({ 'X-Forwarded-For': value });
    assert.equal((await ask(service, '20', from('198.51.100.1'))).status, 202);
    assert.equal((await ask(service, '21', from('198.51.100.2'))).status, 202);
    // What stands left of the proxy's entry is the caller's claim: it changes nothing.
    assert.equal((await ask(service, '22', from('10.9.9.9, 198.51.100.1'))).body.error.code, 'address_limit');
    assert.equal((await ask(service, '22', from('198.51.100.77, 198.51.100.2, 10.0.0.5'))).body.error.code, 'address_limit');
    assert.equal((await ask(service, '22', from('198.51.100.3:55123, 10.0.0.5'))).status, 202);
    // One /56 is one caller; the next /56 is another.
    assert.equal((await ask(service, '23', from('2001:db8:1:aa01::5'))).status, 202);
    assert.equal((await ask(service, '24', from('2001:db8:1:aaff:9::1'))).body.error.code, 'address_limit');
    assert.equal((await ask(service, '24', from('2001:db8:1:ab00::1'))).status, 202);
    // No usable entry: the request is the proxy's own.
    assert.equal((await ask(service, '25', from('not-an-address'))).status, 202);
    assert.equal((await ask(service, '26')).body.error.code, 'address_limit');
  }, { limits, trustedProxies: ['127.0.0.1', '10.0.0.5'] }, accounts);
});

test('a registration is sponsored for a new key that consents, within its own limits', async () => {
  const newcomer = () => { const pair = generateKeyPairSync('ed25519'); return { publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), privateKey: pair.privateKey }; };
  const request = (node, who, { sponsor = FAUCET, commitment = 'c1'.repeat(32), expires = (node.elapsed + 90000000n).toString() } = {}) => ({
    public_key: who.publicKey, commitment, expires_elapsed_micros: expires,
    proof: edSign(null, Buffer.from(SDK.sponsorConsentBytes({ networkId: NETWORK, sponsorAccount: sponsor, publicKey: who.publicKey, commitment, expiresElapsedMicros: expires })), who.privateKey).toString('hex'),
  });
  const post = (service, json, headers = {}) => call(service, '/v1/faucet/registrations', { method: 'POST', json, headers });
  await lab(async ({ service, node }) => {
    const from = (n) => ({ 'X-Forwarded-For': `203.0.113.${n}` }), alice = newcomer(), wanted = request(node, alice);
    const given = await post(service, wanted, from(1));
    assert.equal(given.status, 202, given.text);
    assert.deepEqual([given.body.kind, given.body.status, given.body.public_key, given.body.amount_micros], ['registration', 'submitted', alice.publicKey, '10000']);
    const action = SDK.decodeAction(new Uint8Array(node.mempool[0]));
    assert.deepEqual([action.kind, action.from, action.publicKey, action.payload], [44, FAUCET, SPEND.publicKey, wanted]);
    node.mine(); await service.settle();
    assert.deepEqual([(await call(service, given.body.lookup)).body.status, node.commits.length, node.account(FAUCET).balance], ['included', 1, 900000000n - 11000n]);
    // The same key again, another key from the same address, a key that has an account, a commitment that waits.
    assert.equal((await post(service, request(node, alice, { commitment: 'c2'.repeat(32) }), from(2))).body.error.code, 'account_limit');
    assert.equal((await post(service, request(node, newcomer()), from(1))).body.error.code, 'address_limit');
    const waiting = newcomer();
    node.commits.push({ public_key: waiting.publicKey, commitment: 'c1'.repeat(32), expires_elapsed_micros: (node.elapsed + 50000000n).toString(), height: '5', sponsor: '3' });
    const committed = await post(service, request(node, waiting), from(3));
    assert.deepEqual([committed.status, committed.body.error.code, committed.body.same_commitment], [409, 'already_committed', true]);
    const holder = { publicKey: seedOf('signin').public_key, privateKey: (generateKeyPairSync('ed25519')).privateKey };
    assert.equal((await post(service, { ...request(node, newcomer()), public_key: holder.publicKey }, from(4))).body.error.code, 'invalid_consent');
    // A consent for another sponsor or other terms, an expiry outside the window, a malformed body.
    const bob = newcomer();
    assert.equal((await post(service, request(node, bob, { sponsor: '7' }), from(4))).body.error.code, 'invalid_consent');
    assert.equal((await post(service, { ...request(node, bob), commitment: 'c3'.repeat(32) }, from(4))).body.error.code, 'invalid_consent');
    assert.equal((await post(service, request(node, bob, { expires: (node.elapsed + 10000000n).toString() }), from(4))).body.error.code, 'invalid_expiry');
    assert.equal((await post(service, request(node, bob, { expires: (node.elapsed + 86400000001n).toString() }), from(4))).body.error.code, 'invalid_expiry');
    for (const broken of [{}, { ...request(node, bob), extra: '1' }, { ...request(node, bob), public_key: bob.publicKey.toUpperCase() }, { ...request(node, bob), expires_elapsed_micros: '0' }, { ...request(node, bob), proof: 'ab' }]) assert.equal((await post(service, broken, from(4))).body.error.code, 'invalid_body');
    assert.equal(distinct(node), 1);
    // A key of an existing account is refused on the proof.
    const registered = newcomer();
    node.accounts.set('50', { id: '50', name: 'has_one', balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: registered.publicKey, can_manage: true, can_spend: true }] });
    assert.equal((await post(service, request(node, registered), from(5))).body.error.code, 'already_registered');
    assert.equal((await call(service, '/v1/faucet')).body.registrations.sponsored, true);
  }, { trustedProxies: ['127.0.0.1'] });
  await lab(async ({ service, node }) => {
    const refused = await post(service, request(node, newcomer()));
    assert.deepEqual([refused.status, refused.body.error.code, node.submissions.length], [404, 'not_offered', 0]);
  }, { sponsorRegistrations: false });
});

test('the page: fixed files, text only, no inline script or style, and the headers of the other services', async () => {
  await lab(async ({ service }) => {
    const html = await call(service, '/');
    assert.deepEqual([html.status, html.headers['content-type'], html.headers['cache-control'], html.headers['x-content-type-options'], html.headers['x-frame-options'], html.headers['referrer-policy']], [200, 'text/html; charset=utf-8', 'no-store', 'nosniff', 'DENY', 'no-referrer']);
    const policy = html.headers['content-security-policy'];
    assert.match(policy, /default-src 'none'/); assert.match(policy, /script-src 'self'/); assert.match(policy, /style-src 'self'/); assert.match(policy, /frame-ancestors 'none'/);
    assert(!/unsafe-inline|unsafe-eval|https?:|\*/.test(policy));
    assert.match(html.text, /no value/);
    assert.equal((html.text.match(/<input/g) || []).length, 1); assert.equal((html.text.match(/<button/g) || []).length, 1);
    // No inline script, style or handler, and nothing loaded from elsewhere.
    assert(!/<script(?![^>]*\ssrc=)[^>]*>/.test(html.text) && !/<style|\sstyle=|\son[a-z]+=|javascript:/i.test(html.text));
    for (const reference of html.text.matchAll(/(?:src|href)="([^"]*)"/g)) assert.match(reference[1], /^\/(app\.js|styles\.css|web-v4\/shared\/network-menu\.js)$/);
    const script = await call(service, '/app.js'), styles = await call(service, '/styles.css');
    assert.deepEqual([script.status, script.headers['content-type'], styles.status, styles.headers['content-type']], [200, 'text/javascript; charset=utf-8', 200, 'text/css; charset=utf-8']);
    assert(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|https?:\/\//.test(script.text) && !/url\(|@import|https?:\/\//.test(styles.text));
    assert.equal((await call(service, '/', { method: 'POST', json: {} })).status, 405);
    for (const route of ['/app.js.map', '/styles.css/', '/web-v4/faucet/app.js', '/%2e%2e/client-v4/faucet.mjs', '/..%2fapp.js']) assert.notEqual((await call(service, route)).status, 200, route);
  });
  await lab(async ({ service }) => { assert.equal((await call(service, '/')).status, 404); assert.equal((await call(service, '/v1/faucet')).status, 200); }, { servePage: false });
  // What the page says about an answer is text made from checked fields.
  assert.equal(seconds('5000000'), '5 seconds (5000000 microseconds)');
  assert.equal(seconds('1000000'), '1 second (1000000 microseconds)');
  assert.equal(seconds('1500'), '0.0015 seconds (1500 microseconds)');
  assert.equal(seconds('<b>'), '<b>');
  assert.deepEqual(describe(202, { status: 'submitted', hash: 'AB'.repeat(32), account: '7', amount_micros: '5000000', note: 'Look it up.' }), { ok: true, title: 'Sent', hash: 'AB'.repeat(32), text: '5 seconds (5000000 microseconds) of test time for account 7. Look it up.' });
  assert.deepEqual(describe(429, { error: { code: 'account_limit', message: 'This account has had its 1.' }, previous: [{ hash: 'CD'.repeat(32), status: 'included', created_at: 'then' }] }), { ok: false, title: 'Not sent', text: 'This account has had its 1. The last one: included, then.', hash: 'CD'.repeat(32) });
  assert.deepEqual(describe(502, null), { ok: false, title: 'Not sent', text: 'The faucet answered 502', hash: null });
  assert.deepEqual(describe(503, { error: { code: 'chain_daily_limit', message: 'The node refused the payment.' }, hash: 'EF'.repeat(32), lookup: '/v1/faucet/grants/x' }), { ok: false, title: 'Refused by the node', text: 'The node refused the payment.', hash: 'EF'.repeat(32) });
  assert.equal(describe(503, { error: { message: 'x' }, hash: '<img src=x>' }).hash, null);
  assert.equal(ROUTES.length, 8);
  // The page speaks of sponsored registrations only when the faucet says that it sponsors them.
  const pageHtml = await readFile(new URL('../web-v4/faucet/index.html', import.meta.url), 'utf8'), pageScript = await readFile(new URL('../web-v4/faucet/app.js', import.meta.url), 'utf8');
  assert.match(pageHtml, /<p id="registration-note" class="small" hidden>/);
  assert(pageScript.includes("$('registration-note').hidden = !(body.registrations && body.registrations.sponsored === true);"));
});

test('the start script: one instance per data directory, the key from its file, and a real proof decides the start', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-faucet-run-'));
  const node = fakeNode(), logs = [], keyFile = path.join(directory, 'spend.key');
  await writeFile(keyFile, `${seedOf('spend').seed_hex}\n`, { mode: 0o600 });
  const config = { test_network: true, network_id: NETWORK, rpc_url: 'http://127.0.0.1:26657/', trust: TRUST, data_directory: path.join(directory, 'data'), account: FAUCET, key_file: keyFile, port: 18940 + Math.floor(Math.random() * 1000),
    grant_micros: '5000000', limits: { per_account_per_day: 1, per_address_per_day: 3, total_per_day_micros: '500000000', registrations_per_address_per_day: 1 }, min_balance_micros: '10000000', max_recipient_balance_micros: '20000000', max_chain_daily_limit_micros: '600000000', sponsor_registrations: false };
  const inject = { rpc: node.rpc, lookup: node.lookup, readState: node.readState, timings: { storeSynchronous: 'OFF' }, log: (level, message, fields) => logs.push({ level, message, ...fields }) };
  let running;
  try {
    running = await start(config, inject);
    await assert.rejects(start({ ...config, port: config.port + 1 }, inject), /already serves|Another faucet instance/);
    const given = await ask(running, '7');
    assert.equal(given.status, 202, given.text);
    assert.equal(SDK.decodeAction(new Uint8Array(node.mempool[0])).publicKey, SPEND.publicKey);
    const text = JSON.stringify(logs);
    assert(logs.some((line) => /started on a test network/.test(line.message)) && !text.includes(seedOf('spend').seed_hex) && !text.includes('spend.key'));
    await running.close(); running = null;
    // The lock is released: the same directory starts again, and remembers the grant.
    running = await start(config, inject);
    assert.equal((await ask(running, '7')).body.error.code, 'account_limit');
    await running.close(); running = null;
    await assert.rejects(start({ ...config, test_network: false }, inject), /test networks only/);
    await assert.rejects(start({ ...config, key_file: path.join(directory, 'absent.key') }, inject), /key file could not be read/);
  } finally { await running?.close(); await rm(directory, { recursive: true, force: true }); }

  // The real reader and verifier over the real proof (proof.json, the network "abab…"). The
  // faucet asks for its account together with its security row, and that proof holds neither the
  // row nor the proof that there is none: the verifier refuses it ("missing requested proof"), so
  // a node cannot hide the row, and the faucet does not start. With a network id that is not the
  // manifest's it does not get as far as reading.
  const light = proven.proof.light_block, calls = [];
  const rpc = async (method, parameters = {}) => {
    calls.push(method);
    if (method === '/commit') return { signed_header: light.signed_header };
    if (method === '/validators') return { block_height: parameters.height, total: String(light.validators.length), validators: parameters.height === '6' ? light.validators : light.next_validators };
    if (method === '/abci_query') return { response: { code: 0, height: proven.proof.height, value: Buffer.from(JSON.stringify({ height: proven.proof.height, root: light.signed_header.header.app_hash.toLowerCase(), entries: proven.proof.entries, history_proofs: proven.proof.history_proofs })).toString('base64') } };
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const proofDirectory = await mkdtemp(path.join(os.tmpdir(), 'time-faucet-proof-')), realNow = Date.now;
  try {
    Date.now = () => proven.now_ms;
    const real = { ...OPTIONS(), trust: proven.trust, networkId: proven.trust.network_id, account: '0', verifier, rpc, lookup: node.lookup, dataFile: path.join(proofDirectory, 'faucet.sqlite') };
    const lines = [];
    await assert.rejects(createFaucetService({ ...real, log: (level, message, fields) => lines.push({ level, message, ...fields }) }), /could not be read with a valid proof: the faucet does not start/);
    assert(calls.includes('/abci_query') && calls.includes('/commit'), 'the state was asked for with a proof');
    assert(lines.some((line) => /missing requested proof for 7365637572697479/.test(line.error)), 'the security row was asked for and its proof was required');
    calls.length = 0;
    await assert.rejects(createFaucetService({ ...real, networkId: NETWORK }), /not the network of the trust manifest/);
    assert.equal(calls.length, 0);
  } finally { Date.now = realNow; await rm(proofDirectory, { recursive: true, force: true }); }
});

test('the lookup of an action on the node: found, not found, and a node that cannot tell', async () => {
  const answers = new Map(), asked = [];
  const fetcher = async (url) => { asked.push(String(url)); const body = answers.get(new URL(url).searchParams.get('hash')); if (!body) throw new Error('down'); return new Response(JSON.stringify(body)); };
  const lookup = createTxLookup('http://127.0.0.1:26657/', { fetcher }), hash = 'AB'.repeat(32);
  answers.set(`0x${hash}`, { result: { hash, height: '77', tx: 'AAAA', tx_result: { code: 0 } } });
  assert.deepEqual(await lookup(hash), { height: '77', tx: 'AAAA' });
  assert.equal(asked[0], `http://127.0.0.1:26657/tx?hash=0x${hash}`);
  answers.set(`0x${hash}`, { error: { code: -32603, message: 'Internal error', data: `tx (${hash}) not found` } });
  assert.equal(await lookup(hash), null);
  answers.set(`0x${hash}`, { error: { code: -32603, message: 'Internal error', data: 'transaction indexing is disabled' } });
  await assert.rejects(lookup(hash), /transaction index/);
  answers.set(`0x${hash}`, { result: { hash, height: '77', tx: 'AAAA', tx_result: { code: 5 } } });
  await assert.rejects(lookup(hash), /failed result/);
  answers.delete(`0x${hash}`);
  await assert.rejects(lookup(hash), /could not be asked/);
  await assert.rejects(lookup('../status'), /64 hexadecimal/);
  // The store refuses to be opened for another network.
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-faucet-store-'));
  try {
    openFaucetStore({ filename: path.join(directory, 'f.sqlite'), networkId: NETWORK, account: '5' }).close();
    assert.throws(() => openFaucetStore({ filename: path.join(directory, 'f.sqlite'), networkId: 'ab'.repeat(32), account: '5' }), /belongs to another network/);
    // A file that is not a store of this version is refused as it is: nothing is written to it,
    // the message is the faucet's own, and the file is not held open.
    const { DatabaseSync } = await import('node:sqlite');
    const earlier = path.join(directory, 'first-version.sqlite'), raw = new DatabaseSync(earlier);
    raw.exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID; INSERT INTO meta VALUES ('network_id', '${NETWORK}'), ('account', '5');
      CREATE TABLE grants (id INTEGER PRIMARY KEY, kind TEXT, recipient TEXT, status TEXT); INSERT INTO grants (kind, recipient, status) VALUES ('grant', '7', 'refused');`);
    raw.close();
    assert.throws(() => openFaucetStore({ filename: earlier, networkId: NETWORK, account: '5' }), /^Error: This data directory holds the store of another version of the faucet; use a new one/);
    const after = new DatabaseSync(earlier);
    assert.deepEqual([after.prepare('SELECT key FROM meta ORDER BY key').all().map((row) => row.key), after.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name)], [['account', 'network_id'], ['grants', 'meta']]);
    after.close();
    await rm(earlier); // possible only when no handle is left open
    const other = path.join(directory, 'other.sqlite'), foreign = new DatabaseSync(other);
    foreign.exec('CREATE TABLE notes (text TEXT)'); foreign.close();
    assert.throws(() => openFaucetStore({ filename: other, networkId: NETWORK, account: '5' }), /another version of the faucet/);
    await writeFile(path.join(directory, 'garbage.sqlite'), 'this is not a database at all, but it is long enough to be read as one'.repeat(4));
    assert.throws(() => openFaucetStore({ filename: path.join(directory, 'garbage.sqlite'), networkId: NETWORK, account: '5' }), /not a store of the faucet/);
    await rm(other); await rm(path.join(directory, 'garbage.sqlite'));
    // The store does not grow for ever: records that nothing waits for are removed after 30 days
    // of block time, refused requests after one day. What is still open is kept whatever its age.
    const store = openFaucetStore({ filename: path.join(directory, 'f.sqlite'), networkId: NETWORK, account: '5', synchronous: 'OFF' });
    const day0 = 1700000000000, record = (at) => store.reserve({ kind: 'grant', recipient: '7', caller: '203.0.113.1', amount: 5, cost: 6, at, payload: { to: '7', amount: '5' }, check: () => {} });
    const [old, oldOpen, recent, cancelled] = [record(day0), record(day0), record(day0 + 29 * DAY_MS), record(day0 + 29 * DAY_MS)];
    store.finish(old, 'cancelled', 'internal', 1, day0); store.finish(cancelled, 'cancelled', 'internal', 1, day0);
    store.signed(recent, { nonce: '2', hash: 'AB'.repeat(32), raw: new Uint8Array([1]), height: '9' }); store.included(recent, '10');
    store.refusals.add('203.0.113.1', day0); store.refusals.add('203.0.113.1', day0 + 30 * DAY_MS);
    // A request that was never sent does not count; everything else does.
    assert.deepEqual([store.usage('grant', '7', '203.0.113.1', day0 + 28 * DAY_MS).recipient.n, store.usage('grant', '7', '203.0.113.1', day0 - 1).recipient.n], [1, 2]);
    store.prune(day0 + 30 * DAY_MS + 1, day0);
    assert.deepEqual([old, oldOpen, recent, cancelled].map((id) => store.byId(id)?.status ?? null), [null, 'reserved', 'included', 'cancelled']);
    assert.equal(store.refusals.count('203.0.113.1', 0).n, 1);
    store.close();
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('the total of 24 hours given: the faucet says that it is not giving, and the health check stays 200', async () => {
  const total = 2n * (GRANT + FEE), two = { perAccountPerDay: 1, perAddressPerDay: 3, totalPerDayMicros: total, registrationsPerAddressPerDay: 1 };
  // The daily limit on the chain is the config's total plus a little, as the README says (step 3).
  const limit = total + 1000n, withLimit = (node) => { devs(node); node.security.policy.daily_limit_micros = limit.toString(); node.allowance = limit; };
  await lab(async (world) => {
    const { node, service } = world;
    for (const id of ['20', '21']) assert.equal((await ask(service, id)).status, 202);
    node.mine(); await service.settle();
    // The page and a request are told the same; nothing is wrong, so the health check is not red. The faucet's
    // own two grants have used the limit on the chain as well, and that is no fault either: nobody else spent it.
    let info = (await call(service, '/v1/faucet')).body, health = await call(service, '/v1/faucet/health');
    assert.equal(node.allowance, 1000n);
    assert.deepEqual([info.left.total_micros, info.left.grants, info.giving, info.reasons], ['0', '0', false, ['chain_daily_limit_used_up', 'daily_total_given']]);
    assert.deepEqual([health.status, health.body.ok, health.body.giving, health.body.reasons, health.body.faults, health.body.warnings], [200, true, false, ['chain_daily_limit_used_up', 'daily_total_given'], [], []]);
    const third = await ask(service, '22');
    assert.deepEqual([third.status, third.body.error.code], [429, 'daily_total']);
    // When the grants leave the window it gives again.
    node.allowance = limit; day(world); await service.settle();
    info = (await call(service, '/v1/faucet')).body;
    assert.deepEqual([info.giving, info.reasons, (await call(service, '/v1/faucet/health')).status, (await ask(service, '22')).status], [true, [], 200, 202]);
  }, { limits: two }, withLimit);
  // The limit on the chain used up while the config's total is not: something else spent it, here another holder
  // of the spend key with one transfer. That is a fault, and the nonce the faucet did not sign is said as well.
  await lab(async (world) => {
    const { node, service } = world, faucet = node.account(FAUCET);
    await service.settle(true);
    const spent = Buffer.from(await SDK.signAction({ networkId: NETWORK, kind: 'transfer', from: FAUCET, nonce: (faucet.nonce + 1n).toString(), authEpoch: faucet.auth_epoch, publicKey: SPEND.publicKey, payload: { to: '9', amount: (limit - FEE - 1000n).toString() } }, SPEND.privateKey));
    assert.equal((await node.rpc('/broadcast_tx_sync', { tx: `0x${spent.toString('hex')}` })).code, 0);
    node.mine(); await service.settle(true);
    const health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.status, health.body.ok, health.body.giving, health.body.reasons, health.body.faults, health.body.warnings], [503, false, false, ['chain_daily_limit_used_up'], ['chain_daily_limit_used_up'], ['key_used_elsewhere']]);
  }, { limits: two }, withLimit);
});

test('the faucet\'s own timer notices a payment that waits on its account within ten seconds, and says the freeze one pass after its block', async () => {
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const until = async (what, probe) => { for (let i = 0; i < 300; i++) { if (await probe()) return; await pause(10); } assert.fail(`${what}: not within three seconds of real time`); };
  await lab(async (world) => {
    const { node, service } = world;
    // Several passes of the timer: nothing is open and the clock stands still, so the account is not read.
    await pause(150);
    const reads = node.reads;
    node.security.pending_payments = [{ id: '1', to: '9', amount: '880000000', ready_elapsed_micros: (node.elapsed + 86400000000n).toString() }];
    node.security.next_id = '2';
    world.clock += 9000; await pause(150);
    assert.equal(node.reads, reads, 'the account was read before ten seconds had passed');
    // Ten seconds after the last look the next pass reads the account, sees the payment and sends the freeze.
    world.clock += 1000;
    await until('the freeze is sent', () => node.mempool.some((raw) => SDK.decodeAction(new Uint8Array(raw)).kind === 72));
    const health = await call(service, '/v1/faucet/health');
    assert.deepEqual([health.status, health.body.reasons, health.body.faults], [503, ['payment_above_limit_waiting'], ['payment_above_limit_waiting']]);
    // A block takes the freeze. The clock stands still: the faucet looks again at its next pass, because an action
    // of its own is on its way, and then says that the account is frozen.
    node.mine();
    await until('the health check says frozen', async () => (await call(service, '/v1/faucet/health')).body.reasons.includes('frozen'));
    assert.deepEqual([node.security.freezes, node.security.pending_payments], ['1', []]);
    // The incident is over: the account is read at the idle pace again.
    await pause(100);
    const after = node.reads;
    await pause(150);
    assert.equal(node.reads, after, 'the account is still read at every pass after the incident');
  }, { autoStart: true, reconcileMs: 20 });
});

// ------------------------------------------------------------------ waits that survive a stop
// On a network whose genesis has `waits_survive_stops`, every proven state carries the total of the chain's stops
// (`stopped_micros`), and the moments of a security row are on the clock of the waits: the chain's time less that
// total (`TimeSDK.securityNow`). After a stop of more than five minutes the chain's time is past them. A faucet that
// reads them on the chain's time takes a freeze for over, a raise of its limit for done and its allowance for
// refilled, while the chain holds the opposite. These tests failed before the faucet read the clock of the waits.
const HOUR = 3600000000n;
/// The fake node on such a network: `node.stopped` is the total of stops, and `node.row` replaces fields of the
/// faucet's security row, written on the clock of the waits as the engine writes them there.
const onWaitsClock = (node) => {
  node.stopped = 0n; node.row = {};
  const read = node.readState;
  node.readState = async (selection) => {
    const result = await read(selection);
    result.state.config.waits_survive_stops = true; result.state.stopped_micros = node.stopped.toString();
    for (const row of result.state.security) Object.assign(row, structuredClone(node.row));
    return result;
  };
};
/// The chain stands still and comes back `hours` later. This stand-in counts the first hour of the gap and takes the
/// rest as a stop; the engine counts the first five minutes since 23 November 2026. The faucet reads the total of the
/// stops from the state and does not compute it, so the test holds for either rule.
const stopFor = (node, hours) => { node.elapsed += BigInt(hours) * HOUR; node.stopped += BigInt(hours - 1) * HOUR; node.height += 1; };
const sentKinds = (node) => node.submissions.map((hex) => SDK.decodeAction(new Uint8Array(Buffer.from(hex, 'hex'))));

test('after a stop, a freeze the chain still holds stops the faucet, and its allowance is the one the chain counts', async () => {
  await lab(async ({ node, service }) => {
    const at = node.elapsed;
    // Frozen for two hours from now, and the daily limit used up now, both on the clock of the waits.
    node.row = { freezes: '1', frozen_until_elapsed_micros: (at + 2n * HOUR).toString(), allowance_micros: '0', allowance_elapsed_micros: at.toString() };
    stopFor(node, 10);
    await service.settle();
    const info = (await call(service, '/v1/faucet')).body;
    // On the chain's time the freeze would have ended eight hours ago; on the clock of the waits it has an hour left.
    assert.deepEqual([info.giving, info.reasons], [false, ['frozen']]);
    // The limit refilled for the one hour of the gap that counts, a twenty-fourth of it, not for ten hours.
    assert.equal(info.chain.daily_limit_left_micros, (600000000n / 24n).toString());
    const refused = await ask(service, '7');
    assert.deepEqual([refused.status, refused.body.error.code, node.submissions.length], [503, 'faucet_frozen', 0]);
    // An hour and a second more of chain end the freeze, here as on the chain.
    node.elapsed += HOUR + 1000000n; node.height += 1;
    await service.settle();
    assert.deepEqual((await call(service, '/v1/faucet')).body.reasons, []);
  }, {}, onWaitsClock);
});

test('after a stop, a raise of the limit the faucet did not make still waits: the faucet stops, freezes and cancels it', async () => {
  await lab(async ({ node, service }) => {
    const at = node.elapsed, ready = at + 3n * HOUR;
    node.row = { policy: { ...node.security.policy, daily_limit_micros: '300000000' }, pending_limit: { id: '5', daily_limit_micros: '600000000', ready_elapsed_micros: ready.toString() }, next_id: '6' };
    stopFor(node, 10);
    await service.settle();
    // The raise has two hours left on the clock of the waits. Read on the chain's time it is in force, and nothing waits.
    assert.deepEqual((await call(service, '/v1/faucet')).body.reasons, ['limit_raise_waiting']);
    const sent = sentKinds(node);
    assert.deepEqual(sent.filter((action) => action.kind === 76).map((action) => action.payload), [{ type: 'limit', id: '5' }]);
    // The freeze is signed on the chain's time, which a signature always names: valid until an hour after the raise
    // could take effect at the earliest, its moment plus the stops so far.
    const freezes = sent.filter((action) => action.kind === 72);
    assert.deepEqual(freezes.map((action) => action.payload.expires_elapsed_micros), [(ready + node.stopped + HOUR).toString()]);
  }, {}, onWaitsClock);
});

test('after a stop, the faucet\'s freeze against a payment that waits stays valid until the payment could go through', async () => {
  await lab(async ({ node, service }) => {
    const at = node.elapsed, ready = at + 3n * HOUR;
    node.row = { pending_payments: [{ id: '5', to: '9', amount: '880000000', ready_elapsed_micros: ready.toString() }], next_id: '6' };
    stopFor(node, 10);
    await service.settle();
    assert.deepEqual((await call(service, '/v1/faucet')).body.reasons, ['payment_above_limit_waiting']);
    // The payment can go through twelve hours after `at` at the earliest (three of chain, nine of stop). A freeze dated
    // from the stored moment alone, or an hour from now, would lapse before that.
    const freeze = sentKinds(node).find((action) => action.kind === 72);
    assert.equal(freeze.payload.expires_elapsed_micros, (ready + node.stopped + HOUR).toString());
    assert.ok(BigInt(freeze.payload.expires_elapsed_micros) > at + 12n * HOUR);
  }, {}, onWaitsClock);
});
