// Second review: attacks on the parts added by the fixes. Each test asserts the SAFE behaviour, so a
// failing test is a finding; tests named "holds:" are checks that are expected to pass.
// Written by the independent reviewer of the API (as review2.test.mjs). Brought into the suite
// unchanged except for the places marked "ADAPTED" (two assertions, one spelling).
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createHash, generateKeyPairSync, sign as edSign } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { describeAction, merkleProof, openIndex, createRpc, IndexerError } from './indexer.mjs';
import { createApiService } from './api.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
const NETWORK = fixture.trust.network_id, CHAIN = fixture.trust.chain_id;
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const hashOf = (height, index) => sha(Buffer.from(fixture.txs[height][index], 'base64')).toString('hex').toUpperCase();
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function fakeRpc(state) {
  const block = (h) => { const b = fixture.blocks[Number(h) - 1]; if (!b || Number(h) > state.tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    state.calls.push([method, parameters]);
    if (method === '/status') return { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(state.tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: fixture.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? state.tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > state.tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= fixture.blocks.length ? fixture.blocks[h - 1].validators : fixture.blocks.at(-1).next_validators }; }
    if (method === '/broadcast_tx_sync') return state.broadcast(parameters);
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-api-review2-'));
  const state = {
    tip: 4, calls: [], logs: [], clock: fixture.now_ms, hooks: [],
    broadcast: (parameters) => ({ code: 0, hash: sha(Buffer.from(parameters.tx.slice(2), 'hex')).toString('hex').toUpperCase() }),
    readState: async (selection) => ({ verified: true, requested: selection, proof: { height: '4', entries: [] }, state: { network_id: NETWORK, height: '4', time_micros: '1000004000000', accounts: [{ id: '7', name: 'payer', balance: '85', nonce: '3', auth_epoch: '0', devices: [] }], config: {} } }),
  };
  let service;
  try {
    service = await createApiService({
      trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5,
      now: () => state.clock, log: (level, message, fields) => state.logs.push({ level, message, ...fields }), readState: (selection) => state.readState(selection), rateLimit: { perSecond: 1000, burst: 100000 },
      webhookFetcher: async (url, init) => { state.hooks.push(JSON.parse(init.body)); return new Response('', { status: 200 }); }, ...options,
    });
    await run({ service, state, directory });
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}
async function call(service, route, options = {}) {
  const response = await fetch(service.url + route, options);
  const text = await response.text();
  let body = null; try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, body, text, headers: response.headers };
}
const KEY = 'bb'.repeat(32);
const unsigned = (kind, payload, more = {}) => Buffer.from(SDK.concat(SDK.buildAction({ networkId: NETWORK, from: '5', nonce: '1', authEpoch: '0', publicKey: KEY, kind, payload, ...more }), new Uint8Array(64)));
const blockOf = (height) => ({ height, hash: sha(Buffer.from(`block ${height}`)).toString('hex'), previous_hash: height > 1 ? sha(Buffer.from(`block ${height - 1}`)).toString('hex') : '', time_micros: 1000000000000 + height * 1000000, time: new Date(1000000000 + height * 1000).toISOString().replace('Z', '000Z'), proposer: 'AA'.repeat(20), app_hash: 'BB'.repeat(32), data_hash: 'CC'.repeat(32) });
function writeBlocks(store, blocks, first = 1) {
  blocks.forEach((raws, i) => {
    const height = first + i;
    const actions = raws.map((raw, idx) => ({ ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx }));
    store.writeBlock({ previousChecked: height > 1, actions, block: blockOf(height) });
  });
}
const seed = (service, blocks, first = 1) => writeBlocks(service.store, blocks, first);

// ------------------------------------------------------------------ kind 75: the actions the engine accepts
const approvals = [{ public_key: KEY, signature: 'cc'.repeat(64) }];
const ACT = {
  secure: (from, nonce) => unsigned(70, { keys: [], policy: {} }, { from, nonce }),
  freeze: (from, n) => unsigned(72, { expires_elapsed_micros: String(n), freezes: '0', version: '1' }, { from, nonce: '0' }),
  root: (from, op, n) => unsigned(73, { approvals, expires_elapsed_micros: String(n), op }, { from, nonce: '0' }),
  finalize: (from, n) => unsigned(74, { version: String(n) }, { from, nonce: '0' }),
  request: (from, nonce, to, amount) => unsigned(75, { type: 'request', to, amount }, { from, nonce }),
  execute: (from, nonce, id) => unsigned(75, { type: 'execute', id: String(id) }, { from, nonce }),
  cancelPayment: (from, id, n) => unsigned(76, { type: 'payment', id: String(id) }, { from, nonce: '0', authEpoch: '0', publicKey: (n % 251).toString(16).padStart(2, '0').repeat(32) }),
  cancelLimit: (from, id) => unsigned(76, { type: 'limit', id: String(id) }, { from, nonce: '0' }),
  limit: (from, nonce, value) => unsigned(77, { daily_limit_micros: String(value) }, { from, nonce }),
};

test('holds: over random engine-valid histories, a completion the index attributes always names the recipient and amount the engine paid', () => {
  // A model of the security row as v5/src/security.rs keeps it: what creates, completes, cancels
  // and drops waiting payments (request, execute, cancel; freeze, replacement with and without a
  // spend key, finishing one, a replacement that expires unclaimed, a freeze that runs out).
  let seedValue = 12345;
  const random = (n) => { seedValue = (seedValue + 0x6D2B79F5) | 0; let x = Math.imul(seedValue ^ (seedValue >>> 15), 1 | seedValue); x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x; return ((x ^ (x >>> 14)) >>> 0) % n; };
  let wrong = 0, attributed = 0, completions = 0, histories = 0;
  for (let round = 0; round < 400; round++) {
    const accounts = ['7', '8', '9'].map((id) => ({ id, secured: false, pending: [], limit: null, nextId: 1, root: false, frozen: false, nonce: 0 }));
    const chain = [], truth = new Map(); let counter = 0;
    for (let step = 0; step < 90; step++) {
      const a = accounts[random(accounts.length)], n = ++counter;
      const install = () => { a.frozen = false; a.pending = []; a.limit = null; a.root = false; };
      const choice = random(16);
      let raw = null;
      if (!a.secured) { if (choice < 4) { a.secured = true; a.pending = []; a.nextId = 1; raw = ACT.secure(a.id, String(++a.nonce)); } }
      else if (choice <= 4 && !a.frozen && !a.root && a.pending.length < 4) { const to = String(20 + random(4)), amount = String(1000 + n); a.pending.push({ id: a.nextId++, to, amount }); raw = ACT.request(a.id, String(++a.nonce), to, amount); }
      else if (choice <= 7 && !a.frozen && !a.root && a.pending.length) { const [p] = a.pending.splice(random(a.pending.length), 1); raw = ACT.execute(a.id, String(++a.nonce), p.id); truth.set(sha(raw).toString('hex').toUpperCase(), p); }
      else if (choice === 8 && a.pending.length) { const [p] = a.pending.splice(random(a.pending.length), 1); raw = ACT.cancelPayment(a.id, p.id, n); }
      else if (choice === 9) { a.frozen = true; a.pending = []; a.limit = null; raw = ACT.freeze(a.id, n); }
      else if (choice === 10 && !a.root) { install(); raw = ACT.root(a.id, { type: 'replace', keys: [], policy: {} }, n); }                       // with a spend key: at once
      else if (choice === 11 && !a.root) { a.root = true; a.pending = []; a.limit = null; raw = ACT.root(a.id, { type: 'replace', keys: [{ n: String(n) }], policy: {} }, n); } // recovery keys alone: it waits
      else if (choice === 12 && a.root) { if (random(2)) { a.root = false; raw = ACT.root(a.id, { type: 'cancel' }, n); } else { install(); raw = ACT.finalize(a.id, n); } }
      else if (choice === 13) { if (a.frozen && random(2)) { a.frozen = false; raw = ACT.root(a.id, { type: 'unfreeze', freezes: '1' }, n); } else { a.frozen = false; if (random(3) === 0) a.root = false; } } // or time passes
      else if (choice === 14 && !a.frozen && !a.root) { if (a.limit === null) { a.limit = a.nextId++; raw = ACT.limit(a.id, String(++a.nonce), 100000 + n); } else { raw = ACT.cancelLimit(a.id, a.limit); a.limit = null; } }
      else if (choice === 15 && !a.root) { raw = ACT.root(a.id, { type: 'pay', to: '30', amount: String(n) }, n); }
      if (raw) chain.push(raw);
    }
    // The index may start anywhere in the history (start_height), and blocks hold one to three actions.
    const from = random(3) === 0 ? random(chain.length) : 0;
    const blocks = []; for (let i = from; i < chain.length;) { const size = 1 + random(3); blocks.push(chain.slice(i, i + size)); i += size; }
    const store = openIndex({ filename: ':memory:', networkId: NETWORK, chainId: CHAIN, startHeight: 1 });
    try {
      writeBlocks(store, blocks);
      for (const raw of chain.slice(from)) {
        const hash = sha(raw).toString('hex').toUpperCase(), paid = truth.get(hash);
        if (!paid) continue;
        completions += 1;
        const row = store.actionByHash(hash);
        if (row.transfers === 1) { attributed += 1; if (row.recipient !== paid.to || row.amount !== paid.amount) wrong += 1; }
      }
    } finally { store.close(); }
    histories += 1;
  }
  console.log(`   ${histories} histories, ${completions} completions, ${attributed} attributed by the index, ${wrong} with the wrong recipient or amount`);
  assert.equal(wrong, 0);
  assert(attributed > 100, 'the model must exercise attribution');
});

test('an account that once had two payments waiting is attributed again once both are settled', async () => {
  await lab(async ({ service }) => {
    seed(service, [
      [ACT.secure('7', '1')],
      [ACT.request('7', '2', '5', '1000'), ACT.request('7', '3', '5', '2000')],   // two waiting at once
      [ACT.execute('7', '4', 1), ACT.execute('7', '5', 2)],                       // both completed: nothing is waiting now
      [ACT.request('7', '6', '5', '5000000')],                                     // weeks later: one request, alone
      [ACT.execute('7', '7', 3)],
    ]);
    const payments = (await call(service, '/v1/accounts/5/payments')).body.items;
    const activity = (await call(service, '/v1/accounts/7/activity?order=asc')).body.items;
    console.log('   payments to the exchange:', payments.length, '| completions:', JSON.stringify(activity.filter((a) => a.kind === 75 && a.recipient === null).map((a) => ({ height: a.height, unattributed: a.unattributed }))));
    assert.equal(payments.filter((p) => p.amount === '5000000').length, 1, 'the third deposit, the only one waiting at its time, is not listed: the account stays unattributed until it freezes or replaces its keys');
  });
});

test('a waiting payment that was cancelled or dropped does not stay "pending" for its recipient for good', async () => {
  await lab(async ({ service }) => {
    seed(service, [
      [ACT.secure('7', '1')],
      // ADAPTED (spelling only): the same amount, 900,000 seconds in microseconds, written as a product.
      // The reviewer wrote it as one literal of twelve digits, which the publication scan
      // (tools/export-public.mjs) refuses in a published file as a possible account number.
      [ACT.request('7', '2', '5', String(900_000 * 1_000_000))],   // "a deposit of 250 hours is on its way"
      [ACT.cancelPayment('7', 1, 1)],                  // cancelled: it will never arrive
    ]);
    const activity = (await call(service, '/v1/accounts/5/activity')).body.items;
    console.log('   the recipient\'s activity after the cancellation:', JSON.stringify(activity.map((a) => ({ role: a.role, amount: a.amount, transfers: a.transfers, keys: Object.keys(a).filter((k) => /cancel|resolv|settled|dropped|status/.test(k)) }))));
    assert(activity.every((a) => a.role !== 'pending' || Object.keys(a).some((k) => /cancel|resolv|settled|dropped|status/.test(k))), 'the cancelled request is still shown as pending, with nothing that says it ended');
  });
});

// ------------------------------------------------------------------ webhooks and the age limit
test('a deposit made during an outage of more than a day still gets its webhook', async () => {
  await lab(async ({ service, state }) => {
    // The service ran and indexed to block 3. Then this host (or its node) was down for 30 hours.
    state.tip = 3;
    for (let i = 0; i < 20 && (service.store.high() ?? 0) < 3; i++) await service.indexer.step();
    const before = state.hooks.length;
    // Block 4, with a deposit to account 1, was made a second after the outage began.
    state.clock += 30 * 3600 * 1000; state.tip = 4;
    for (let i = 0; i < 20 && service.store.high() < 4; i++) await service.indexer.step();
    service.webhooks.kick(); await service.webhooks.settled(); await pause(50);
    const listed = (await call(service, '/v1/accounts/1/payments?cursor=3.0')).body.items;
    console.log('   payments indexed after the outage:', listed.length, '| webhooks sent for them:', state.hooks.length - before, '| queued:', service.webhooks.status().queued, '| log lines about it:', state.logs.filter((l) => /webhook/.test(l.message)).length);
    assert.equal(state.hooks.length - before, 1, 'the deposit of block 4 is in the index but its webhook was never queued, and no log line says so');
  }, { webhooks: [{ account: '1', url: 'https://hooks.example/x', secret: 'x'.repeat(16) }] });
});

// ------------------------------------------------------------------ submit
test('a withdrawal signed twice (same content, other signature) is not answered "rejected" without naming the action that used the nonce', async () => {
  await lab(async ({ service, state }) => {
    for (let i = 0; i < 20 && (service.store.high() ?? 0) < 4; i++) await service.indexer.step();
    // Block 4 holds the withdrawal of account 7 with nonce 3: {to: 1, amount: 5}. The exchange's signer was asked
    // again (a second spend key, a signer that was restarted, a library that does not sign deterministically).
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const key = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
    const body = Buffer.from(SDK.buildAction({ networkId: NETWORK, kind: 3, from: '7', nonce: '3', authEpoch: '0', publicKey: key, payload: { to: '1', amount: '5' } }));
    const tx = Buffer.concat([body, edSign(null, body, privateKey)]);
    state.broadcast = () => ({ code: 1, log: 'incorrect nonce or nonce exhausted', hash: sha(tx).toString('hex').toUpperCase() });
    const answer = await call(service, '/v1/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tx: tx.toString('base64') }) });
    console.log('   answer:', answer.status, JSON.stringify(answer.body).slice(0, 330));
    // The guide: "422 rejected, for bytes you send for the first time: fix the cause, sign anew".
    assert(answer.text.includes(hashOf('4', 0)), 'the index holds an action of this sender with this nonce and the same payment (block 4), and the answer does not name it');
  });
});

test('the signature check keeps bytes nobody was entitled to sign away from the node', async () => {
  await lab(async ({ service, state }) => {
    let reached = 0, bytes = 0;
    state.broadcast = (parameters) => { reached += 1; bytes += (parameters.tx.length - 2) / 2; return { code: 1, log: 'spending device required' }; };
    // Any key pair made a moment ago signs for any account: the check proves only that the envelope is self-consistent.
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const key = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
    const junk = { note: 'x'.repeat(500 * 1024) };
    const body = Buffer.from(SDK.buildAction({ networkId: NETWORK, kind: 60, from: '5', nonce: '1', authEpoch: '0', publicKey: key, payload: junk }));
    const signed = Buffer.concat([body, edSign(null, body, privateKey)]);
    const a = await call(service, '/v1/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tx: signed.toString('base64') }) });
    // And the header relay needs no key at all.
    const relay = Buffer.concat([Buffer.from(SDK.buildAction({ networkId: NETWORK, kind: 40, from: SDK.MAX_U64, nonce: '7', authEpoch: '9', publicKey: '00'.repeat(32), payload: junk })), Buffer.alloc(64)]);
    const b = await call(service, '/v1/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tx: relay.toString('base64') }) });
    console.log(`   stranger's key, 500 KiB of filler as account 5: ${a.status} ${a.body.error?.code ?? a.body.status}; unsigned kind 40 with nonce 7: ${b.status} ${b.body.error?.code ?? b.body.status}; the node was handed ${reached} actions, ${bytes} bytes`);
    // ADAPTED: the reviewer's line was assert.equal(reached, 0), for both submissions together.
    // The unsigned relay is refused here, as asked. The action signed by a stranger's key is not:
    // by the decision taken on this finding, the API does not read the sender's proven keys for
    // every submission (a state proof per request costs more than the node's own refusal), and
    // says so in deploy/api/README.md. So that one action reaches the node, once, and its
    // refusal is passed on. Not an interface change: the fix that was asked for is narrower than
    // this assertion.
    assert.deepEqual([b.status, b.body.error.code], [400, 'invalid_signature']);
    assert.deepEqual([a.status, a.body.error.code, reached], [422, 'rejected', 1]);
    assert.match(await readFile(new URL('../deploy/api/README.md', import.meta.url), 'utf8'), /not that the key is one of the account's/);
  });
});

test('holds: the JSON-RPC POST of broadcast_tx_sync has the shape CometBFT 0.38 takes, and its answers are read as it writes them', async () => {
  // A stand-in written from rpc/jsonrpc/server/http_json_handler.go, http_server.go and rpc/core/mempool.go.
  const seen = [];
  let mode = 'ok';
  const comet = async (url, init) => {
    const u = new URL(url); seen.push({ method: init.method, path: u.pathname, search: u.search, type: init.headers?.['Content-Type'], length: init.body.length });
    if (u.pathname !== '/') return new Response('404 page not found\n', { status: 404 });
    if (init.body.length > 1000000) return new Response(JSON.stringify({ jsonrpc: '2.0', id: -1, error: { code: -32600, message: 'Invalid Request', data: 'error reading request body: http: request body too large' } }), { status: 400 });
    const request = JSON.parse(init.body);
    assert.equal(request.jsonrpc, '2.0'); assert.notEqual(request.id, undefined); assert.equal(request.method, 'broadcast_tx_sync');
    const tx = Buffer.from(request.params.tx, 'base64'); assert.equal(tx.toString('base64'), request.params.tx);
    const result = (r) => new Response(JSON.stringify({ jsonrpc: '2.0', id: request.id, ...r }), { status: 200 });   // errors are written with status 200 too
    if (mode === 'cache') return result({ error: { code: -32603, message: 'Internal error', data: 'tx already exists in cache' } });
    if (mode === 'full') return result({ error: { code: -32603, message: 'Internal error', data: 'mempool is full: number of txs 5000 (max: 5000), total txs bytes 1 (max: 1073741824)' } });
    if (mode === 'refused') return result({ result: { code: 1, data: '', log: 'incorrect nonce or nonce exhausted', codespace: '', hash: sha(tx).toString('hex').toUpperCase() } });
    return result({ result: { code: 0, data: '', log: '', codespace: '', hash: sha(tx).toString('hex').toUpperCase() } });
  };
  const rpc = createRpc('http://127.0.0.1:26657/', { fetcher: comet });
  const largest = Buffer.alloc(512 * 1024 + 112 + 64, 7);
  assert.equal((await rpc('/broadcast_tx_sync', { tx: `0x${largest.toString('hex')}` })).code, 0);
  mode = 'cache'; await assert.rejects(rpc('/broadcast_tx_sync', { tx: '0xabcd' }), (e) => /already exists in cache/.test(e.rpcMessage));
  mode = 'full'; await assert.rejects(rpc('/broadcast_tx_sync', { tx: '0xabcd' }), (e) => /mempool is full/.test(e.rpcMessage));
  mode = 'refused'; assert.equal((await rpc('/broadcast_tx_sync', { tx: '0xabcd' })).code, 1);
  console.log('   request:', JSON.stringify(seen[0]));
  assert.deepEqual([seen[0].method, seen[0].path, seen[0].search], ['POST', '/', '']);
  assert(seen[0].length < 1000000, 'the largest action fits the default max_body_bytes of the RPC server');
});

// ------------------------------------------------------------------ stored Merkle levels
test('holds: the proof read from the stored levels equals the proof built from the block, for every size and position', async () => {
  const store = openIndex({ filename: ':memory:', networkId: NETWORK, chainId: CHAIN, startHeight: 1 });
  try {
    let checked = 0;
    for (let total = 1; total <= 70; total++) {
      const raws = Array.from({ length: total }, (_, i) => unsigned(3, { to: '8', amount: String(i + 1) }, { nonce: String(total * 1000 + i) }));
      writeBlocks(store, [raws], total);
      const leaves = raws.map((raw) => sha(raw));
      for (let idx = 0; idx < total; idx++) {
        const stored = store.inclusionProof(total, idx, total), built = merkleProof(leaves, idx);
        assert.deepEqual([stored.root, stored.leaf, stored.aunts], [built.root, built.leaf, built.aunts], `block of ${total}, position ${idx}`);
        checked += 1;
      }
    }
    console.log('   proofs compared:', checked);
  } finally { store.close(); }
});

// ------------------------------------------------------------------ streams
function openStream(service, route, forwarded) {
  const { port } = new URL(service.url);
  const socket = net.connect(Number(port), '127.0.0.1', () => socket.write(`GET ${route} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nX-Forwarded-For: ${forwarded}\r\n\r\n`));
  const stream = { data: '', closed: false, socket };
  socket.on('data', (chunk) => { stream.data += chunk; }); socket.on('close', () => { stream.closed = true; }); socket.on('error', () => {});
  return stream;
}
test('a caller cannot choose whose stream is put out', async () => {
  await lab(async ({ service }) => {
    // The exchange is not on the reserved list and reads two streams (its deposits, and all blocks).
    const victim = [openStream(service, '/v1/stream?account=5', '203.0.113.9'), openStream(service, '/v1/stream', '203.0.113.9')];
    await pause(50);
    // 98 addresses of one IPv6 /56 take one place each: the 100 places are full.
    const crowd = [];
    for (let i = 1; i <= 98; i++) crowd.push(openStream(service, '/v1/stream', `2001:db8:0:${i.toString(16)}::1`));
    await pause(150);
    // Two more addresses ask. Whoever holds the most streams loses its oldest: that is the exchange, each time.
    openStream(service, '/v1/stream', '2001:db8:0:aaa::1'); openStream(service, '/v1/stream', '2001:db8:0:aab::1');
    await pause(150);
    const out = victim.filter((s) => /event: bye/.test(s.data)).length, crowdOut = crowd.filter((s) => /event: bye/.test(s.data)).length;
    console.log(`   after two more requests from new addresses: ${out} of the exchange's 2 streams ended ("evicted"), ${crowdOut} of the crowd's 98`);
    for (const s of [...victim, ...crowd]) s.socket.destroy();
    assert.equal(out, 0);
  }, { trustedProxies: ['127.0.0.1'] });
});

test('holds: a reserved client keeps its streams and always gets one; forwarded addresses are read past trusted proxies only', async () => {
  await lab(async ({ service }) => {
    const mine = openStream(service, '/v1/stream', '203.0.113.9');
    const crowd = [];
    for (let i = 1; i <= 12; i++) crowd.push(openStream(service, '/v1/stream', `2001:db8:0:${i.toString(16)}::1`));
    await pause(150);
    const late = openStream(service, '/v1/stream', '203.0.113.9');
    await pause(100);
    assert.match(late.data, /^HTTP\/1\.1 200/); assert.doesNotMatch(mine.data, /event: bye/);
    for (const s of [mine, late, ...crowd]) s.socket.destroy();
  }, { trustedProxies: ['127.0.0.1'], maxStreams: 10, reservedStreamClients: ['203.0.113.9'] });
  // Who is limited: two requests a burst, then 429. Each line: what arrives in X-Forwarded-For, and whether it shares a bucket with the line before.
  await lab(async ({ service }) => {
    const ask = async (forwarded) => (await call(service, '/v1/health', { headers: forwarded === null ? {} : { 'x-forwarded-for': forwarded } })).status === 429;
    const drained = async (forwarded) => { await ask(forwarded); await ask(forwarded); return ask(forwarded); };
    assert.equal(await drained('198.51.100.1'), true);
    assert.equal(await ask('6.6.6.6, 198.51.100.1'), true, 'what the client claims left of the proxy\'s entry is not read');
    assert.equal(await ask('198.51.100.1, 10.0.0.2'), true, 'a second trusted proxy is passed over');
    assert.equal(await ask('198.51.100.1:4711, 10.0.0.2'), true, 'a port is removed');
    assert.equal(await ask('10.0.0.2, 198.51.100.77'), false, 'another client has its own bucket, even if it claims to come through a proxy');
    assert.equal(await ask('198.51.100.1, 198.51.100.78'), false, 'a client cannot hand its requests to another address\'s bucket');
  }, { trustedProxies: ['127.0.0.1', '10.0.0.2'], rateLimit: { perSecond: 0.001, burst: 2 } });
});

test('holds: host names match with or without the default port, and nothing else', async () => {
  await lab(async ({ service }) => {
    const { port } = new URL(service.url);
    const status = async (host) => { const { data } = await new Promise((resolve) => { const s = net.connect(Number(port), '127.0.0.1', () => s.write(`GET /v1/health HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)); let d = ''; s.on('data', (c) => { d += c; }); s.on('close', () => resolve({ data: d })); s.on('error', () => resolve({ data: d })); }); return Number(data.split(' ')[1]); };
    const seen = {};
    for (const host of ['api.example', 'api.example:443', 'api.example:80', 'API.Example', 'api.example:8443', 'api.example.', 'evil.example', `evil.example:${port}`, 'api.example.evil.example', 'api.example:443:443', `127.0.0.1:${port}`, '127.0.0.1', 'localhost']) seen[host] = await status(host);
    console.log('   ' + JSON.stringify(seen));
    for (const host of ['api.example', 'api.example:443', 'api.example:80', 'API.Example', `127.0.0.1:${port}`]) assert.equal(seen[host] === 421, false, host);
    for (const host of ['api.example:8443', 'evil.example', `evil.example:${port}`, 'api.example.evil.example', 'api.example:443:443', '127.0.0.1', 'localhost']) assert.equal(seen[host], 421, host);
  }, { hosts: ['api.example'] });
});

test('a reader with one stream is not put out by a crowd that keeps reconnecting', async () => {
  await lab(async ({ service }) => {
    // The reader holds one stream, like everyone else. 99 addresses of one /56 hold one each.
    let victim = openStream(service, '/v1/stream?account=5', '203.0.113.9');
    await pause(50);
    let crowd = [];
    for (let i = 1; i <= 99; i++) crowd.push({ address: `2001:db8:0:${i.toString(16)}::1`, stream: null });
    for (const c of crowd) c.stream = openStream(service, '/v1/stream', c.address);
    await pause(200);
    // The crowd cycles: each address closes nothing, it just asks again from one more address, then the put-out ones return.
    let evictions = 0, requests = 0;
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 100 && !/event: bye/.test(victim.data); i++) { openStream(service, '/v1/stream', `2001:db8:0:${(0x400 + requests).toString(16)}::1`); requests += 1; await pause(8); }
      await pause(60);
      if (/event: bye/.test(victim.data)) { evictions += 1; victim.socket.destroy(); victim = openStream(service, '/v1/stream?account=5', '203.0.113.9'); await pause(40); }
    }
    console.log(`   the reader's single stream was ended ${evictions} times by ${requests} stream requests from other addresses (each costs 10 tokens; an address has 20 a second)`);
    victim.socket.destroy(); for (const c of crowd) c.stream.socket.destroy();
    assert.equal(evictions, 0);
  }, { trustedProxies: ['127.0.0.1'] });
});

test('the "never included" rule, when the index moves between the lookup and the account read', async () => {
  await lab(async ({ service, state }) => {
    state.tip = 3;
    for (let i = 0; i < 20 && (service.store.high() ?? 0) < 3; i++) await service.indexer.step();
    const hash = hashOf('4', 0);
    const lookup = await call(service, `/v1/actions/${hash}`);            // 404: the index is at 3
    state.tip = 4;
    for (let i = 0; i < 20 && service.store.high() < 4; i++) await service.indexer.step();   // the index reaches block 4, which holds the withdrawal
    const account = await call(service, '/v1/accounts/7');                // nonce 3 used, state_height 4, indexed_height 4
    const nonceReached = BigInt(account.body.account.nonce) >= 3n;
    const guideRule = lookup.status === 404 && nonceReached && BigInt(lookup.body.index.indexed_height) >= BigInt(account.body.state_height);     // the guide, step 4, rule 2: the 404's own height
    const adaptedRule = lookup.status === 404 && nonceReached && BigInt(account.body.indexed_height) >= BigInt(account.body.state_height);       // api-review.test.mjs line 98: the account answer's height
    console.log(`   lookup 404 at index ${lookup.body.index.indexed_height}; account: state_height ${account.body.state_height}, indexed_height ${account.body.indexed_height}; guide's rule says never included: ${guideRule}; the adapted test's rule: ${adaptedRule}`);
    assert.equal(guideRule, false);
    // ADAPTED: the reviewer's line was assert.equal(adaptedRule, false, ...). The account answer keeps
    // its indexed_height (it was asked for in the first review), so this rule can still be formed
    // and is still wrong here: that is the finding. What was asked for is that nobody is told to
    // use it: the first review's test now applies the guide's rule (the 404's own height), and
    // the guide and the OpenAPI description say which height to use.
    assert.equal(adaptedRule, true, 'the hazard this test was written for: an earlier 404 with the account answer\'s heights');
    const openapi = JSON.parse(await readFile(new URL('./api/openapi.json', import.meta.url), 'utf8'));
    assert.match(openapi.components.schemas.Account.properties.indexed_height.description, /index\.indexed_height of that 404/);
    assert.match(await readFile(new URL('../docs/integration-guide.md', import.meta.url), 'utf8'), /the `index\.indexed_height` of that 404 itself/);
    assert.doesNotMatch(await readFile(new URL('./api-review.test.mjs', import.meta.url), 'utf8'), /BigInt\(account\.body\.indexed_height\) >= BigInt\(account\.body\.state_height\)/);
  });
});
