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
    mempool: [], included: new Map(), commits: [], cancelled: [], submissions: [], reads: 0, lookups: 0,
    account(id) { return node.accounts.get(String(id)); },
    costOf(action) { return action.kind === 3 ? BigInt(action.payload.amount) + FEE : action.kind === 76 ? FEE : REGISTRATION_FEE + FEE; },
    /// CheckTx: the faucet's next nonce in line, a signature of one of its spend keys, the daily limit.
    async check(raw) {
      const action = SDK.decodeAction(new Uint8Array(raw)), sender = node.account(action.from);
      if (action.networkId !== node.network) return 'wrong network';
      if (node.refuseAll) return node.refuseAll;
      const waits = node.mempool.map((tx) => SDK.decodeAction(new Uint8Array(tx)));
      // A cancellation (kind 76) is a protective action: no nonce, a spend or recovery key, one of a key waiting at a time.
      if (action.kind === 76) {
        if (action.nonce !== '0' || action.authEpoch !== '0') return 'this action carries no nonce and no authority epoch';
        if (!sender.devices.some((device) => device.public_key === action.publicKey && device.can_spend !== device.can_manage)) return 'a spend or recovery key is required';
        const signer = await crypto.subtle.importKey('raw', SDK.hexToBytes(action.publicKey, 32), 'Ed25519', false, ['verify']);
        if (!(await crypto.subtle.verify('Ed25519', signer, raw.subarray(raw.length - 64), raw.subarray(0, raw.length - 64)))) return 'invalid action signature';
        if (waits.some((other) => other.kind === 76 && other.publicKey === action.publicKey)) return 'a protective action of this key is waiting already';
        if (action.payload.type === 'payment') return node.security.pending_payments.some((item) => item.id === action.payload.id) ? null : 'no such waiting payment';
        return node.security.pending_limit?.id === action.payload.id ? null : 'no such raise of the limit is waiting';
      }
      const line = waits.filter((other) => other.kind !== 76);
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
          node.included.set(sha(raw), { height: String(node.height), tx: raw.toString('base64') });
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
  const open = async (more = {}) => createFaucetService({ ...OPTIONS(), verifier, rpc: (...a) => node.rpc(...a), lookup: (...a) => node.lookup(...a), readState: (...a) => node.readState(...a), dataFile: path.join(directory, 'faucet.sqlite'), callerKeyFile: path.join(directory, 'callers.key'), now: () => world.clock, log: (level, message, fields) => world.logs.push({ level, message, ...fields }), ...options, ...more });
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

// ====================================================================== adversarial review, round 2
const signCancel = (payload) => SDK.signAction({ networkId: NETWORK, kind: 76, from: FAUCET, nonce: '0', authEpoch: '0', publicKey: SPEND.publicKey, payload }, SPEND.privateKey);
const submitRaw = (node, raw) => node.rpc('/broadcast_tx_sync', { tx: `0x${Buffer.from(raw).toString('hex')}` });

test('N1 a raise of the limit that has finished waiting: the engine no longer lets it be cancelled, the row still shows it, and the faucet never gives again', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    // The engine (v5/src/security.rs:906, `security.settle(now)` before the kind is looked at) puts a
    // raise that is due into force before a cancellation is judged: "no such raise of the limit is
    // waiting". A refused action stores nothing, so the row keeps `pending_limit` until some action
    // of the account succeeds. The fake node is taught that rule here.
    const check = node.check;
    node.check = async (raw) => {
      const action = SDK.decodeAction(new Uint8Array(raw)), raise = node.security.pending_limit;
      if (action.kind === 76 && action.payload.type === 'limit' && raise && BigInt(raise.ready_elapsed_micros) <= node.elapsed) return 'no such raise of the limit is waiting';
      return check(raw);
    };
    // A raise within max_chain_daily_limit_micros, asked for a day ago (by the operator with cancel_waiting off, or by
    // somebody whose item the cancellation of the faucet did not reach in time). Its wait is over.
    node.security.policy.daily_limit_micros = '500000000'; node.allowance = 500000000n;
    node.security.pending_limit = { id: '1', daily_limit_micros: '600000000', ready_elapsed_micros: (node.elapsed - 1000000n).toString() };
    node.security.next_id = '2';
    for (let pass = 0; pass < 4; pass++) { node.mine(); world.clock += 61000; await service.settle(); }
    const first = await ask(service, '7');
    day(world, 3); await service.settle(); await service.settle();
    const later = await ask(service, '7'), health = await call(service, '/v1/faucet/health'), held = service.store.cancels.get('limit:1');
    console.log('N1 at once:', first.status, first.body.error?.code, '| three days later:', later.status, JSON.stringify(later.body.error), '| health:', health.status, JSON.stringify(health.body.reasons), '| submissions:', node.submissions.length, '| cancels row:', JSON.stringify(held && { status: held.status, attempts: held.attempts }));
    assert.equal(later.status, 202, 'the faucet never gives again, though nothing waits any more on the chain');
  });
});

test('N2 the automatic cancellation against the holder of the same key: one refusal ends it, and the payment keeps waiting', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    // The thief asked for two payments: the one that matters, and one to cancel himself. A key may have
    // one protective action waiting (v5/src/engine.rs:552-558), and the key of the thief IS the key of the faucet.
    node.security.pending_payments = [{ id: '1', to: '9', amount: '899000000', ready_elapsed_micros: (node.elapsed + 86400000000n).toString() }, { id: '2', to: '9', amount: '1', ready_elapsed_micros: (node.elapsed + 86400000000n).toString() }];
    node.security.next_id = '3';
    assert.equal((await submitRaw(node, await signCancel({ type: 'payment', id: '2' }))).code, 0); // the cancellation of the thief waits in the mempool
    await service.settle();                                  // the faucet sees both items and signs the cancellation of the first
    const firstStatus = service.store.cancels.get('payment:1').status;
    node.mine();                                             // the cancellation of the thief is in a block; nothing of the faucet waits anywhere
    for (let pass = 0; pass < 6; pass++) { world.clock += 61000; node.mine(); await service.settle(); }
    const held = service.store.cancels.get('payment:1');
    console.log('N2 the cancellation of the payment that matters:', JSON.stringify({ first: firstStatus, status: held.status, attempts: held.attempts }),
      '| still waiting on the chain:', JSON.stringify(node.security.pending_payments.map((p) => `${p.id}:${p.amount}`)), '| cancelled on the chain:', JSON.stringify(node.cancelled));
    assert.deepEqual(node.security.pending_payments.map((p) => p.id), [], 'the payment of 899 seconds still waits; the faucet does not try again');
  });
});

test('N3 ten requests for accounts that do not exist close an address for a day, for grants and for registrations', async () => {
  await lab(async (world) => {
    const { service, node } = world, shared = { 'X-Forwarded-For': '203.0.113.50' };
    const junk = [];
    for (let i = 0; i < 10; i++) junk.push((await ask(service, `nobody${i}`, shared)).status);
    const honest = await ask(service, '7', shared);
    const pair = generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), expires = (node.elapsed + 90000000n).toString(), commitment = 'c1'.repeat(32);
    const proof = edSign(null, Buffer.from(SDK.sponsorConsentBytes({ networkId: NETWORK, sponsorAccount: FAUCET, publicKey, commitment, expiresElapsedMicros: expires })), pair.privateKey).toString('hex');
    const registration = await call(service, '/v1/faucet/registrations', { method: 'POST', json: { public_key: publicKey, commitment, expires_elapsed_micros: expires, proof }, headers: shared });
    console.log('N3 ten requests:', JSON.stringify(junk), '| then somebody else behind the same address:', honest.status, honest.body.error?.code, JSON.stringify(honest.body.error?.message), 'retry-after', honest.headers['retry-after'], '| a registration:', registration.status, registration.body.error?.code);
    assert.equal(honest.status, 202, 'everybody behind the address is refused for 24 hours');
  }, { trustedProxies: ['127.0.0.1'] });
});

test('N4 callers can turn the health check red: requests turned away as busy make it answer 503 for five minutes while the faucet gives', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    const before = (await call(service, '/v1/faucet/health')).status;
    // A proof read takes a moment on a real node (here 40 ms). Forty requests from forty addresses arrive together.
    const read = node.readState; node.readState = async (selection) => { await new Promise((resolve) => setTimeout(resolve, 40)); return read(selection); };
    const answers = await Promise.all(Array.from({ length: 40 }, (_, i) => ask(service, `nobody${i}`, { 'X-Forwarded-For': `203.0.113.${i + 1}` })));
    node.readState = read;
    await service.settle();
    const health = await call(service, '/v1/faucet/health'), info = (await call(service, '/v1/faucet')).body;
    console.log('N4 health before:', before, '| forty requests at once:', JSON.stringify(answers.reduce((n, a) => ({ ...n, [a.status + ' ' + a.body.error.code]: (n[a.status + ' ' + a.body.error.code] || 0) + 1 }), {})), '| health:', health.status, JSON.stringify({ giving: health.body.giving, reasons: health.body.reasons, warnings: health.body.warnings, refused_busy: health.body.refused_busy }), '| /v1/faucet giving:', info.giving);
    world.clock += 290000; node.mine(); await service.settle();
    const later = await call(service, '/v1/faucet/health');
    console.log('N4 and 290 seconds later:', later.status, JSON.stringify({ reasons: later.body.reasons, warnings: later.body.warnings }));
    assert.equal(health.status, 200, 'the health check answers 503 while the faucet gives');
  }, { trustedProxies: ['127.0.0.1'] });
});

test('N5 "tried once more": a refused grant that is not at the head of the line is sent again at every pass', async () => {
  await lab(async (world) => {
    const { service, node } = world;
    const first = await ask(service, '7');
    node.hiddenSpend = 600000000n - 5001000n;                 // room on the chain for the one that waits, none for a second
    const second = await ask(service, '8');
    const sentBefore = node.submissions.length;
    // Blocks are made, and the first grant is not in them (it waits in the mempool of the node).
    for (let pass = 0; pass < 8; pass++) { node.height += 1; node.elapsed += 1000000n; world.clock += 5000; await service.settle(); }
    const sendsOfSecond = node.submissions.slice(sentBefore).filter((hex) => sha(Buffer.from(hex, 'hex')) === second.body.hash).length;
    const third = await ask(service, '9');
    console.log('N5 first:', first.status, first.body.status, '| second:', second.status, second.body.error?.code, '| the second was sent again', sendsOfSecond, 'times in 8 passes; its status:', service.store.byHash(second.body.hash).status, '| meanwhile another caller:', third.status, third.body.error?.code);
    // ADAPTED (decision N5): a refused grant is sent again only once it stands at the head of the
    // line. In these 8 passes the first grant is never in a block, so the second is never at the
    // head and is not sent at all; it is sent exactly once after that, when the first is in a block.
    // Original line:
    //   assert.equal(sendsOfSecond, 1, 'the README says the same bytes are tried once more');
    assert.equal(sendsOfSecond, 0, 'a refused grant that is not at the head of the line is not sent again');
    node.mine();                                              // the first grant is in a block: the second stands at the head
    for (let pass = 0; pass < 8; pass++) { node.height += 1; node.elapsed += 1000000n; world.clock += 5000; await service.settle(); }
    const sendsAtTheHead = node.submissions.slice(sentBefore).filter((hex) => sha(Buffer.from(hex, 'hex')) === second.body.hash).length;
    console.log('N5 once the first is in a block, the second was sent again', sendsAtTheHead, 'time in 8 passes; its status:', service.store.byHash(second.body.hash).status);
    assert.equal(sendsAtTheHead, 1, 'the same bytes are tried once more, at the head of the line');
    assert.equal(service.store.byHash(second.body.hash).status, 'withdrawn');
  }, {}, (node) => { node.account('9').balance = 0n; });
});

test('N6 the page the faucet serves, behind a TLS proxy: its button is refused unless the operator lists the origin of the page', async () => {
  await lab(async ({ service }) => {
    const page = await call(service, '/', { headers: { Host: 'faucet.example' } });
    const facts = await call(service, '/v1/faucet', { headers: { Host: 'faucet.example' } });
    const button = await call(service, '/v1/faucet/grants', { method: 'POST', json: { account: '7' }, headers: { Host: 'faucet.example', Origin: 'https://faucet.example' } });
    console.log('N6 hosts: ["faucet.example"], serve_page: true, cors_origins: [] ->', 'page', page.status, '| facts', facts.status, '| the POST of the page itself:', button.status, button.body.error?.code);
    let verdict;
    try {
      validateConfig({ test_network: true, network_id: NETWORK, rpc_url: 'http://127.0.0.1:26657/', trust: TRUST, data_directory: path.resolve('/var/lib/time-faucet'), account: FAUCET, key_file: path.resolve('/etc/time-faucet/spend.key'), grant_micros: '5000000',
        limits: { per_account_per_day: 1, per_address_per_day: 3, total_per_day_micros: '500000000', registrations_per_address_per_day: 1 }, min_balance_micros: '10000000', max_recipient_balance_micros: '20000000', max_chain_daily_limit_micros: '600000000', sponsor_registrations: true, hosts: ['faucet.example'], serve_page: true });
      verdict = 'accepted without a word';
    } catch (error) { verdict = error.message; }
    console.log('N6 the same config at start:', verdict);
    assert.equal(button.status, 202, 'the page the faucet serves cannot ask the faucet');
    // ADAPTED (decision N6): the start script now refuses a config that serves the page under `hosts`
    // without listing an origin of those hosts in cors_origins, and its message says what to add. A
    // config that passes the start script therefore lists the page's origin, and so does this service.
    // Original line:
    //   }, { hosts: ['faucet.example'] });
    assert.match(verdict, /cors_origins lists no origin under one of those names.*Add the origin of the page to cors_origins/);
  }, { hosts: ['faucet.example'], corsOrigins: ['https://faucet.example'] });
});
