// The third review of the faucet (2026-11-18, with the review of the integration guide): two findings, each
// with the review's own test. Those tests passed as written because they asserted what the faucet did
// wrong; here they assert what it does now, and every assertion that was changed says so in a comment that
// starts with ADAPTED. The helpers are those of faucet.test.mjs: the faucet over a fake node that applies
// the rules a grant meets on the chain.
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

// ---- M3
test('M3: with the total of 24 hours given, a spend of the refilled chain allowance by another holder of the key is seen by its nonce: an error in the log, key_used_elsewhere, and 503', async () => {
  const total = 2n * (GRANT + FEE);
  const two = { perAccountPerDay: 1, perAddressPerDay: 3, totalPerDayMicros: total, registrationsPerAddressPerDay: 1 };
  const health = async (service) => { const h = await call(service, '/v1/faucet/health'); return [h.status, h.body.ok, h.body.reasons, h.body.faults, h.body.warnings]; };
  const foreign = (world) => world.logs.filter((line) => line.level === 'error' && /a nonce of the faucet account used that the faucet did not sign/.test(line.message));
  await lab(async (world) => {
    const { node, service } = world;
    // The faucet gives its total: two grants. The limit on the chain is the same number, so it is used up as well.
    for (const id of ['20', '21']) assert.equal((await ask(service, id)).status, 202);
    node.mine(); await service.settle();
    assert.equal(node.allowance, 0n);
    assert.deepEqual(await health(service), [200, true, ['chain_daily_limit_used_up', 'daily_total_given'], [], []]);
    // Twelve hours later. The config's total is a window of 24 hours: nothing has left it, the faucet still gives nothing.
    // The allowance on the chain refills evenly (security.rs, `level`): half the limit is back.
    node.elapsed += 12n * 3600000000n; world.clock += 12 * 3600000; node.allowance = total / 2n; node.mine(); await service.settle();
    assert.deepEqual(await health(service), [200, true, ['daily_total_given'], [], []]);
    // The faucet's own two grants moved the nonce, and nothing was said: they are its own signatures.
    assert.deepEqual([foreign(world).length, (await call(service, '/v1/faucet/health')).body.key_used_elsewhere_at], [0, null]);
    // Whoever else holds the spend key pays the refilled allowance out with a plain transfer: within the limit, so
    // nothing waits on the account and the faucet's guard sees no item.
    const faucet = node.account(FAUCET), before = faucet.balance;
    const theft = Buffer.from(await SDK.signAction({ networkId: NETWORK, kind: 'transfer', from: FAUCET, nonce: (faucet.nonce + 1n).toString(), authEpoch: faucet.auth_epoch, publicKey: SPEND.publicKey, payload: { to: '9', amount: (total / 2n - FEE).toString() } }, SPEND.privateKey));
    assert.equal((await node.rpc('/broadcast_tx_sync', { tx: `0x${theft.toString('hex')}` })).code, 0);
    node.mine(); await service.settle();
    assert.deepEqual([before - faucet.balance, node.allowance], [total / 2n, 0n]);
    // ADAPTED: the review's test asserted the answer the faucet gave then: [200, true, [...], [], []], with
    // key_used_elsewhere_at null and nothing at error level. The faucet now sees a nonce it did not sign: the
    // warning is there, the used-up limit on the chain is a fault again (503), the time is kept and the log says it.
    assert.deepEqual(await health(service), [503, false, ['chain_daily_limit_used_up', 'daily_total_given'], ['chain_daily_limit_used_up'], ['key_used_elsewhere']]);
    assert.equal((await call(service, '/v1/faucet/health')).body.key_used_elsewhere_at, new Date(world.clock).toISOString());
    assert.deepEqual(foreign(world).map((line) => [line.proven_nonce, line.signed_up_to]), [[faucet.nonce.toString(), (faucet.nonce - 1n).toString()]]);
    // It is said once, not at every pass, and a restart does not say it again.
    await service.settle(true); await world.reopen(); await world.service.settle(true);
    assert.equal(foreign(world).length, 1);
    // A day after the last sighting the warning ends; the grants have left the window and the faucet gives again.
    node.allowance = total; day(world); await world.service.settle(true);
    assert.deepEqual(await health(world.service), [200, true, [], [], []]);
  }, { limits: two }, (node) => { devs(node); node.security.policy.daily_limit_micros = total.toString(); node.allowance = total; });
});

test('M3: a nonce the faucet did not sign is said also when nothing else is wrong, and a faucet that starts on an account with a history says nothing', async () => {
  const health = async (service) => { const h = await call(service, '/v1/faucet/health'); return [h.status, h.body.faults, h.body.warnings, h.body.key_used_elsewhere_at]; };
  const foreign = (world) => world.logs.filter((line) => line.level === 'error' && /a nonce of the faucet account used that the faucet did not sign/.test(line.message)).length;
  await lab(async (world) => {
    const { node } = world, faucet = node.account(FAUCET);
    // The account has used nonces before the faucet first looked (its funding, the adoption of the rules): not said.
    assert.ok(faucet.nonce > 0n);
    await world.service.settle(true);
    assert.deepEqual([await health(world.service), foreign(world)], [[200, [], [], null], 0]);
    // A grant of its own, then a restart, then another: its own signatures, before and after the restart.
    assert.equal((await ask(world.service, '20')).status, 202); node.mine(); await world.service.settle();
    await world.reopen(); await world.service.settle(true);
    assert.equal((await ask(world.service, '21')).status, 202); node.mine(); await world.service.settle();
    assert.deepEqual([await health(world.service), foreign(world)], [[200, [], [], null], 0]);
    // A small payment by another holder of the key, well within the limit: the limit is not used up, nothing waits.
    const small = Buffer.from(await SDK.signAction({ networkId: NETWORK, kind: 'transfer', from: FAUCET, nonce: (faucet.nonce + 1n).toString(), authEpoch: faucet.auth_epoch, publicKey: SPEND.publicKey, payload: { to: '9', amount: '1000' } }, SPEND.privateKey));
    assert.equal((await node.rpc('/broadcast_tx_sync', { tx: `0x${small.toString('hex')}` })).code, 0);
    node.mine(); await world.service.settle(true);
    assert.deepEqual([await health(world.service), foreign(world)], [[200, [], ['key_used_elsewhere'], new Date(world.clock).toISOString()], 1]);
    // The faucet goes on giving (the warning stops nothing), with the next free nonce.
    assert.equal((await ask(world.service, '22')).status, 202); node.mine(); await world.service.settle();
    assert.equal(foreign(world), 1);
  }, {}, (node) => devs(node));
});

// ---- L4
test('L4: with the default pass of 5 s and idle read of 10 s, a read that takes time still falls on every second pass: every 10 s', async (t) => {
  // The timers and the clock are the test runner's, so the passes fall exactly every 5 s and nothing depends on
  // this machine. A read of the proven state takes 40 ms here (the live run measured tens of ms).
  t.mock.timers.enable({ apis: ['setInterval', 'setTimeout', 'Date'], now: 1700000000000 });
  const flush = async () => { for (let i = 0; i < 4; i++) await new Promise((resolve) => setImmediate(resolve)); };
  const advance = async (ms) => { for (let passed = 0; passed < ms; passed += 10) { t.mock.timers.tick(10); await flush(); } };
  await lab(async (world) => {
    const { node } = world, read = node.readState, times = [];
    node.readState = async (selection) => { times.push(Date.now()); await new Promise((resolve) => setTimeout(resolve, 40)); return read(selection); };
    await advance(125000);
    const gaps = times.slice(1).map((at, i) => at - times[i]);
    // ADAPTED: the review's test asserted gaps of 15000 ms, which is what the faucet did: the 10 seconds were
    // counted from the answer of a read, so the pass 10 s after a read began came 40 ms too early. They are now
    // counted from the moment the read is asked for: every second pass, the 10 seconds the README gives.
    assert.ok(gaps.length >= 10, `only ${gaps.length} reads in 125 seconds`);
    assert.deepEqual([...new Set(gaps)], [10000], `the gaps between reads were ${gaps.join(', ')} ms`);
  }, { autoStart: true, now: () => Date.now() });
});

test('L4: after a read that failed the account is read at the next pass, not ten seconds later', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval', 'setTimeout', 'Date'], now: 1700000000000 });
  const flush = async () => { for (let i = 0; i < 4; i++) await new Promise((resolve) => setImmediate(resolve)); };
  const advance = async (ms) => { for (let passed = 0; passed < ms; passed += 10) { t.mock.timers.tick(10); await flush(); } };
  await lab(async (world) => {
    const { node } = world, read = node.readState, times = [];
    node.readState = async (selection) => { times.push(Date.now()); return read(selection); };
    await advance(6000);
    node.stateDown = true; await advance(20000);
    node.stateDown = false; await advance(25000);
    const gaps = times.slice(1).map((at, i) => at - times[i]);
    // The faucet read its account when it started. The read 10 s later fails (the node is down from 6 s to 26 s), and so
    // do those of the next three passes; the read at 30 s succeeds, and from then on the account is read every 10 s again.
    assert.deepEqual([times[0] - 1700000000000, gaps], [10000, [5000, 5000, 5000, 5000, 10000, 10000]], `the gaps between reads were ${gaps.join(', ')} ms`);
  }, { autoStart: true, now: () => Date.now() });
});

test('requests that make the faucet read the state do not put its own look at its account off', async () => {
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const foreign = (world) => world.logs.filter((line) => line.level === 'error' && /a nonce of the faucet account used that the faucet did not sign/.test(line.message)).length;
  await lab(async (world) => {
    const { node, service } = world, faucet = node.account(FAUCET);
    // The faucet has read its account at its start. Nothing is open, and the clock stands still: no further read.
    await pause(150);
    const settled = node.reads;
    // Another holder of the key pays within the limit: nothing waits on the account, only its nonce moves.
    const theft = Buffer.from(await SDK.signAction({ networkId: NETWORK, kind: 'transfer', from: FAUCET, nonce: (faucet.nonce + 1n).toString(), authEpoch: faucet.auth_epoch, publicKey: SPEND.publicKey, payload: { to: '9', amount: '1000' } }, SPEND.privateKey));
    assert.equal((await node.rpc('/broadcast_tx_sync', { tx: `0x${theft.toString('hex')}` })).code, 0);
    node.mine();
    // Nine seconds on, a request that is refused for what it asks, after the state was read for it. Requests like
    // it can be sent every few seconds, by the same holder of the key.
    world.clock += 9000;
    const refused = await ask(service, '9');
    assert.deepEqual([refused.status, refused.body.error.code, node.reads], [409, 'already_funded', settled + 1]);
    assert.equal(foreign(world), 0, 'a request does not watch the nonce');
    // Ten seconds after the faucet's own last read, its next pass reads the account all the same, and sees the nonce.
    // Counted from the read of the request, that pass would have been nine seconds early.
    world.clock += 1000;
    for (let i = 0; i < 200 && foreign(world) === 0; i++) await pause(10);
    assert.deepEqual([foreign(world), (await call(service, '/v1/faucet/health')).body.warnings], [1, ['key_used_elsewhere']]);
  }, { autoStart: true, reconcileMs: 20 }, (node) => devs(node));
});
