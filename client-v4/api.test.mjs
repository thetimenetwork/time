// The HTTP API over a fake CometBFT RPC that serves real signed blocks (fast-receipt.json) and a
// real state proof (proof.json), with the installed WASM verifier. Lists that need more rows than
// the fixture chain holds are read from an index seeded through the store's own writer.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHash, generateKeyPairSync, sign as edSign } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { createLightClient } from './light-client.mjs';
import { fetchLightBlock } from './certified-view.mjs';
import { verifyWebhookSignature } from './security-watch-service.mjs';
import { describeAction, IndexerError } from './indexer.mjs';
import { createApiService, createRateLimiter, clientKey, holderKey, normalIp, webhookTargetId, ROUTES, MAX_PAGE, MAX_BODY_BYTES, REPLAY_PAYMENTS, STREAM_MIN_AGE_MS, NEWER_ACTIONS } from './api.mjs';
import { validateConfig, start } from '../deploy/api/start.mjs';

const SDK = globalThis.TimeSDK;
const fixtures = new URL('../verifier-v4/fixtures/', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('fast-receipt.json', fixtures), 'utf8'));
const proven = JSON.parse(await readFile(new URL('proof.json', fixtures), 'utf8'));
const NETWORK = fixture.trust.network_id, CHAIN = fixture.trust.chain_id;
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const txBytes = (height, index) => Buffer.from(fixture.txs[height][index], 'base64');
const hashOf = (height, index) => sha(txBytes(height, index)).toString('hex').toUpperCase();
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/// A node at height `state.tip`, as in indexer.test.mjs, that also takes submitted transactions.
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
const ACCOUNTS = { 1: { id: '1', name: 'shop', balance: '15', nonce: '0', auth_epoch: '0', devices: [] }, 7: { id: '7', name: 'payer', balance: '85', nonce: '3', auth_epoch: '0', devices: [] } };
/// A service over the fixture chain. State reads are answered by `state.readState` unless a test
/// uses the real reader.
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-api-'));
  const state = {
    tip: 4, calls: [], logs: [], clock: fixture.now_ms, stateDown: false,
    broadcast: (parameters) => ({ code: 0, hash: sha(Buffer.from(parameters.tx.slice(2), 'hex')).toString('hex').toUpperCase() }),
    readState: async (selection) => {
      if (state.stateDown) throw new Error('node behind');
      const wanted = selection.ids?.[0] ?? selection.names?.[0];
      const account = Object.values(ACCOUNTS).find((a) => a.id === wanted || a.name === wanted);
      return { verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: NETWORK, height: '3', time_micros: '1000003000000', accounts: account ? [account] : [], config: {} } };
    },
  };
  let service;
  try {
    service = await createApiService({
      trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5,
      now: () => state.clock, log: (level, message, fields) => state.logs.push({ level, message, ...fields }), readState: (selection) => state.readState(selection), rateLimit: { perSecond: 1000, burst: 100000 }, ...options,
    });
    await run({ service, state, directory });
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}
async function indexAll(service, height = 4) {
  for (let i = 0; i < 50 && (service.store.high() ?? 0) < height; i++) await service.indexer.step();
  assert.equal(service.store.high(), height);
}
async function call(service, route, options = {}) {
  const response = await fetch(service.url + route, options);
  const text = await response.text();
  let body = null; try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, body, text, headers: response.headers };
}
const signedAction = (kind, payload, more = {}) => Buffer.from(SDK.concat(SDK.buildAction({ networkId: NETWORK, from: '5', nonce: '1', authEpoch: '0', publicKey: 'bb'.repeat(32), kind, payload, ...more }), new Uint8Array(64)));
/// Writes synthetic blocks to the index, each with the given signed actions.
function seed(service, blocks) {
  blocks.forEach((raws, i) => {
    const height = i + 1;
    const actions = raws.map((raw, idx) => ({ ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx }));
    service.store.writeBlock({ previousChecked: height > 1, events: [], actions,
      block: { height, hash: sha(Buffer.from(`block ${height}`)).toString('hex'), previous_hash: height > 1 ? sha(Buffer.from(`block ${height - 1}`)).toString('hex') : '', time_micros: 1000000000000 + height * 1000000, time: new Date(1000000000 + height * 1000).toISOString().replace('Z', '000Z'), proposer: 'AA'.repeat(20), app_hash: 'BB'.repeat(32), data_hash: 'CC'.repeat(32) } });
  });
}
/// Reads a server-sent event stream into a list.
async function openStream(service, route, headers = {}) {
  const controller = new AbortController();
  const response = await fetch(service.url + route, { headers, signal: controller.signal });
  const events = [];
  if (response.status !== 200) return { status: response.status, events, close: () => controller.abort(), body: await response.json() };
  const reader = response.body.getReader(), decoder = new TextDecoder();
  let buffer = '';
  const reading = (async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        buffer += decoder.decode(value, { stream: true });
        for (let end; (end = buffer.indexOf('\n\n')) >= 0; buffer = buffer.slice(end + 2)) {
          const event = {};
          for (const line of buffer.slice(0, end).split('\n')) { const at = line.indexOf(': '); if (at > 0) event[line.slice(0, at)] = line.slice(at + 2); }
          if (event.event) events.push({ event: event.event, id: event.id ?? null, data: JSON.parse(event.data) });
        }
      }
    } catch { /* closed */ }
  })();
  return {
    status: 200, events, headers: response.headers,
    waitFor: async (count) => { for (let i = 0; i < 400 && events.length < count; i++) await pause(5); assert(events.length >= count, `only ${events.length} of ${count} events arrived: ${JSON.stringify(events.map((e) => e.event))}`); },
    close: async () => { controller.abort(); await reading; },
  };
}

test('every lookup answers from the indexed chain, says so, and gives what verifies it', async () => {
  await lab(async ({ service, state }) => {
    // Before anything is indexed the service answers and says where it stands. No state can be
    // verified yet, so the fee of the network is not known, and it is not guessed.
    state.stateDown = true;
    let status = (await call(service, '/v1/status')).body;
    assert.deepEqual([status.network.fee_micros, status.network.fee_source], [null, null]);
    assert.deepEqual([status.api, status.network.network_id, status.network.chain_id, status.network.protocol_version, status.indexer.indexed_height, status.indexer.start_height], ['v1', NETWORK, CHAIN, '4', null, '1']);
    assert.equal((await call(service, '/v1/blocks/1')).status, 404);
    await indexAll(service);
    status = (await call(service, '/v1/status')).body;
    assert.deepEqual([status.indexer.indexed_height, status.indexer.tip_height_reported, status.indexer.blocks_behind_reported, status.indexer.fault], ['4', '4', 0, null]);
    assert.equal(typeof status.indexer.seconds_behind, 'number');

    // Blocks, newest first.
    const blocks = await call(service, '/v1/blocks');
    assert.equal(blocks.status, 200);
    assert.deepEqual([blocks.body.source, blocks.body.proven, blocks.body.index.indexed_height, blocks.body.index.network_id, blocks.body.has_more], ['index', false, '4', NETWORK, false]);
    assert.deepEqual(blocks.body.items.map((b) => [b.height, b.tx_count, b.payment_count, b.results_checked]), [['4', 1, 1, false], ['3', 0, 0, true], ['2', 2, 2, true], ['1', 0, 0, true]]);
    assert.equal(blocks.headers.get('cache-control'), 'no-store');
    assert.equal(blocks.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(blocks.headers.get('access-control-allow-origin'), null);
    const block = (await call(service, '/v1/blocks/2')).body;
    assert.deepEqual([block.source, block.proven, block.block.height, block.block.time, block.block.time_micros], ['index', false, '2', '1970-01-12T13:46:42.000000Z', '1000002000000']);
    assert.equal(block.block.hash, fixture.blocks[1].signed_header.commit.block_id.hash);
    assert.equal(block.block.previous_hash, fixture.blocks[0].signed_header.commit.block_id.hash);
    assert.equal(block.verify.block_hash, block.block.hash);
    const listed = (await call(service, '/v1/blocks/2/actions')).body;
    assert.deepEqual(listed.items.map((a) => [a.hash, a.index, a.kind, a.kind_name, a.sender, a.recipient, a.amount, a.transfers]), [[hashOf('2', 0), 0, 3, 'transfer', '7', '1', '5', true], [hashOf('2', 1), 1, 3, 'transfer', '7', '1', '5', true]]);

    // An action by hash, in either case of the hex.
    for (const hash of [hashOf('2', 1), hashOf('2', 1).toLowerCase()]) {
      const found = (await call(service, `/v1/actions/${hash}`)).body;
      assert.deepEqual([found.source, found.proven], ['index', false]);
      assert.deepEqual({ ...found.action, raw: undefined }, { hash: hashOf('2', 1), height: '2', index: 1, time: '1970-01-12T13:46:42.000000Z', kind: 3, kind_name: 'transfer', opaque: false, sender: '7', nonce: '2', recipient: '1', amount: '5', reference: null, transfers: true,
        fee_rule: 'network_fee', fee_micros: null, results_checked: true, request_hash: null, request_status: null, unattributed: false, public_key: 'fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618', auth_epoch: '0', payload: { to: '1', amount: '5' }, raw: undefined, repeated: false });
      assert.deepEqual(Buffer.from(found.action.raw, 'base64'), txBytes('2', 1));
      // The bytes are in the answer once.
      assert.equal(JSON.stringify(found).split(found.action.raw).length - 1, 1);
    }
    assert.equal((await call(service, `/v1/actions/${'AB'.repeat(32)}`)).status, 404);
    assert.equal((await call(service, `/v1/actions/${'AB'.repeat(32)}`)).body.index.indexed_height, '4');

    // What `verify` holds is enough: a caller's own light client verifies the block header, and the
    // installed verifier ties the bytes to it. Nothing of the API's word is used.
    const light = createLightClient({ trust: fixture.trust, verifier, now: () => fixture.now_ms, fetchBlock: (height) => fetchLightBlock({ rpc: fakeRpc({ tip: 4, calls: [] }), height }) });
    for (const [height, index] of [['2', 0], ['2', 1], ['4', 0]]) {
      const answer = (await call(service, `/v1/actions/${hashOf(height, index)}`)).body;
      const checkpoint = await light.updateTo(answer.verify.height);
      assert.equal(checkpoint.block_hash.toUpperCase(), answer.verify.block_hash);
      // The proof in the form of the node's own lookup, as `verify.how` says.
      const { action, verify } = answer;
      const tx = { hash: verify.hash, height: verify.height, index: verify.index, tx: action.raw, proof: { root_hash: verify.root_hash, data: action.raw, proof: { total: verify.total, index: String(verify.index), leaf_hash: verify.leaf_hash, aunts: verify.aunts } } };
      assert.equal(verify.root_hash, fixture.blocks[Number(height) - 1].signed_header.header.data_hash);
      const receipt = await verifier.verifyFastReceipt({ tx, headers: [checkpoint.block.signed_header.header] }, { ...light.getTrust(), checkpoint }, fixture.now_ms);
      assert.deepEqual([receipt.verified, receipt.executionVerified, receipt.txHash.toUpperCase(), receipt.height], [true, true, hashOf(height, index), height]);
      assert.deepEqual(Buffer.from(receipt.rawHex, 'hex'), txBytes(height, index));
      // The same proof with other bytes, or for the other position, does not verify.
      const forged = structuredClone(tx); forged.tx = forged.proof.data = fixture.txs['4'][0] === forged.tx ? fixture.txs['2'][0] : fixture.txs['4'][0];
      await assert.rejects(verifier.verifyFastReceipt({ tx: forged, headers: [checkpoint.block.signed_header.header] }, { ...light.getTrust(), checkpoint }, fixture.now_ms));
    }

    // An account: state from a proof, totals from the index, each marked.
    state.stateDown = false;
    const shop = await call(service, '/v1/accounts/1');
    assert.equal(shop.status, 200);
    assert.deepEqual([shop.body.source, shop.body.state_height, shop.body.indexed_height, shop.body.account.balance, shop.body.account.name], ['state_proof', '3', '4', '15', 'shop']);
    assert.deepEqual(shop.body.proof.query, { ids: ['1'] });
    assert.deepEqual([shop.body.indexed.source, shop.body.indexed.proven, shop.body.indexed.index.indexed_height], ['index', false, '4']);
    assert.deepEqual(shop.body.indexed.totals, { actions_sent: 0, payments_sent: 0, sent_micros: '0', payments_received: 3, received_micros: '15', first_height: '2', last_height: '4' });
    for (const name of ['payer', '@payer']) assert.deepEqual((await call(service, `/v1/accounts/${name}`)).body.indexed.totals, { actions_sent: 3, payments_sent: 3, sent_micros: '15', payments_received: 0, received_micros: '0', first_height: '2', last_height: '4' });
    const absent = await call(service, '/v1/accounts/999');
    assert.deepEqual([absent.status, absent.body.error.code, absent.body.source], [404, 'account_not_found', 'state_proof']);
    // The fee of the network is known once a state has been verified.
    assert.equal((await call(service, `/v1/actions/${hashOf('2', 0)}`)).body.action.fee_micros, '1000');
    assert.deepEqual([(await call(service, '/v1/status')).body.network.fee_micros, (await call(service, '/v1/status')).body.network.fee_source], ['1000', 'state_proof']);
    // When no proof can be had, the account is not answered from the index alone.
    state.stateDown = true;
    const down = await call(service, '/v1/accounts/1');
    assert.deepEqual([down.status, down.body.error.code, down.headers.get('retry-after')], [503, 'state_unavailable', '5']);
    assert.equal((await call(service, '/v1/accounts/1/payments')).status, 200);

    // Activity and payments.
    const activity = (await call(service, '/v1/accounts/7/activity')).body;
    assert.deepEqual([activity.source, activity.proven, activity.order, activity.has_more], ['index', false, 'desc', false]);
    assert.deepEqual(activity.items.map((a) => [a.height, a.index, a.role, a.nonce]), [['4', 0, 'sender', '3'], ['2', 1, 'sender', '2'], ['2', 0, 'sender', '1']]);
    const payments = (await call(service, '/v1/accounts/1/payments')).body;
    assert.deepEqual([payments.source, payments.proven, payments.order, payments.next_cursor], ['index', false, 'asc', '4.0']);
    assert.deepEqual(payments.items.map((a) => [a.hash, a.sender, a.amount, a.results_checked]), [[hashOf('2', 0), '7', '5', true], [hashOf('2', 1), '7', '5', true], [hashOf('4', 0), '7', '5', false]]);
    assert.deepEqual((await call(service, '/v1/accounts/7/payments')).body.items, []);

    // Health: fine while the newest block is recent, not once the index is old.
    const healthy = await call(service, '/v1/health');
    assert.equal(healthy.status, 503); // the indexer is not running in this lab
    assert.deepEqual(healthy.body.reasons, ['indexer_stopped']);
    service.indexer.start();
    assert.deepEqual([(await call(service, '/v1/health')).status, (await call(service, '/v1/health')).body.ok], [200, true]);
    state.clock += 3600 * 1000;
    const late = await call(service, '/v1/health');
    assert.deepEqual([late.status, late.body.ok, late.body.reasons, late.body.indexed_height], [503, false, ['index_behind'], '4']);
    assert(late.body.seconds_behind >= 3600);
  });
});

test('account state is read through the SDK with a real proof, and the proof is passed on', async () => {
  // The node of proof.json: one light block at height 6 and the state rows proven at height 5.
  const light = proven.proof.light_block, calls = [];
  const rpc = async (method, parameters = {}) => {
    calls.push(method);
    if (method === '/commit') return { signed_header: light.signed_header };
    if (method === '/validators') return { block_height: parameters.height, total: String(light.validators.length), validators: parameters.height === '6' ? light.validators : light.next_validators };
    if (method === '/abci_query') return { response: { code: 0, height: proven.proof.height, value: Buffer.from(JSON.stringify({ height: proven.proof.height, root: light.signed_header.header.app_hash.toLowerCase(), entries: proven.proof.entries, history_proofs: proven.proof.history_proofs })).toString('base64') } };
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-api-state-')), realNow = Date.now;
  let service;
  try {
    Date.now = () => proven.now_ms; // the proof is fresh at the time of the fixture
    service = await createApiService({ trust: proven.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false });
    const found = await call(service, '/v1/accounts/alice');
    assert.equal(found.status, 200, found.text);
    assert.deepEqual([found.body.source, found.body.state_height, found.body.account.id, found.body.account.name, found.body.account.balance, found.body.account.nonce], ['state_proof', '5', '0', 'alice', '0', '0']);
    assert.deepEqual(found.body.account.devices, [{ can_manage: true, can_spend: true, public_key: '197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61' }]);
    assert(calls.includes('/abci_query') && calls.includes('/commit'));
    // The caller verifies the passed-on proof again with its own copy of the trust anchor.
    const { query, view_proof: proof } = found.body.proof;
    assert.deepEqual(query.names, ['alice']);
    const checked = await verifier.verifyViewProof(proof, proven.trust, query, proven.now_ms);
    assert.equal(checked.verified, true);
    assert.equal(checked.state.accounts.find((a) => a.name === 'alice').balance, found.body.account.balance);
    // A proof that was tampered with on the way does not verify.
    const forged = structuredClone(proof); forged.entries[0].value_b64 = Buffer.from('{"balance":"999"}').toString('base64');
    await assert.rejects(verifier.verifyViewProof(forged, proven.trust, query, proven.now_ms));
    // An account that does not exist: the absence is proven too.
    const absent = await call(service, '/v1/accounts/999');
    assert.deepEqual([absent.status, absent.body.error.code, absent.body.source], [404, 'account_not_found', 'state_proof']);
    assert.equal((await verifier.verifyViewProof(absent.body.proof.view_proof, proven.trust, absent.body.proof.query, proven.now_ms)).verified, true);
    // The fee was learned from the verified state, not from a setting.
    assert.equal((await call(service, '/v1/status')).body.network.fee_micros, '1000');
    // A node that lies about the state is not believed: the answer is "unavailable", never the lie.
    proven.proof.entries[0].value_b64 = Buffer.from('{"balance":"999"}').toString('base64');
    const lied = await call(service, '/v1/accounts/alice');
    assert.deepEqual([lied.status, lied.body.error.code], [503, 'state_unavailable']);
    // Stale state (the node stopped a minute ago) is refused as well.
    Date.now = () => proven.now_ms + 120000;
    assert.equal((await call(service, '/v1/accounts/999')).status, 503);
  } finally { Date.now = realNow; await service?.close(); await rm(directory, { recursive: true, force: true }); }
});

test('lists page through every row exactly once, in both orders, and deposits are found by reference', async () => {
  await lab(async ({ service }) => {
    // 30 blocks: in each, three payments to account 8 (one with a reference, one from account 6)
    // and one action that is no payment.
    const reference = (n) => n.toString(16).padStart(64, '0');
    const blocks = Array.from({ length: 30 }, (_, b) => [
      signedAction(10, { to: '8', amount: String(1000 + b), reference: reference(b) }, { nonce: String(b * 4 + 1) }),
      signedAction(3, { to: '8', amount: '7' }, { nonce: String(b * 4 + 2) }),
      signedAction(3, { to: '8', amount: '9' }, { from: '6', nonce: String(b + 1) }),
      signedAction(75, { type: 'request', to: '8', amount: '5000000' }, { nonce: String(b * 4 + 3) }),
    ]);
    seed(service, blocks);
    const walk = async (route, limit, order) => {
      const seen = []; let cursor = null, pages = 0;
      for (;;) {
        const query = new URLSearchParams({ limit: String(limit), ...(order ? { order } : {}), ...(cursor ? { cursor } : {}) });
        const answer = await call(service, `${route}${route.includes('?') ? '&' : '?'}${query}`);
        assert.equal(answer.status, 200, answer.text);
        assert(answer.body.items.length <= limit);
        seen.push(...answer.body.items); pages += 1; cursor = answer.body.next_cursor;
        if (!answer.body.has_more) return { seen, pages, cursor };
      }
    };
    const position = (item) => Number(item.height) * 10 + item.index;
    // Payments to account 8: 90 rows, for page sizes that do and do not divide them.
    for (const limit of [1, 7, 45, 90, 200]) for (const order of ['asc', 'desc']) {
      const { seen, pages } = await walk('/v1/accounts/8/payments', limit, order);
      assert.equal(seen.length, 90, `${limit} ${order}`);
      assert.equal(pages, Math.max(1, Math.ceil(90 / limit) + (90 % limit === 0 && limit < 90 ? 0 : 0)), `${limit} ${order}`);
      assert.deepEqual(seen.map(position), seen.map(position).sort((a, b) => (order === 'asc' ? a - b : b - a)));
      assert.equal(new Set(seen.map((item) => item.hash)).size, 90);
      assert(seen.every((item) => item.recipient === '8' && item.transfers === true && item.kind !== 75));
    }
    // A poller that reached the end keeps its cursor and finds only what is new.
    const { cursor } = await walk('/v1/accounts/8/payments', 50, 'asc');
    assert.equal(cursor, '30.2');
    const idle = (await call(service, `/v1/accounts/8/payments?cursor=${cursor}`)).body;
    assert.deepEqual([idle.items, idle.has_more, idle.next_cursor], [[], false, '30.2']);
    service.store.writeBlock({ previousChecked: true, events: [], block: { height: 31, hash: 'ab'.repeat(32), previous_hash: 'cd'.repeat(32), time_micros: 1, time: '1970-01-01T00:00:00.000001Z', proposer: '', app_hash: '', data_hash: '' },
      actions: [signedAction(3, { to: '8', amount: '1' }, { nonce: '500' })].map((raw, idx) => ({ ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx })) });
    assert.deepEqual((await call(service, `/v1/accounts/8/payments?cursor=${cursor}`)).body.items.map((item) => [item.height, item.amount]), [['31', '1']]);
    // An empty list without a cursor has none to give back.
    assert.deepEqual((await call(service, '/v1/accounts/12345/payments')).body.next_cursor, null);

    // Deposit detection: by reference, by sender, by both.
    const byReference = (await call(service, `/v1/accounts/8/payments?reference=${reference(17)}`)).body;
    assert.deepEqual(byReference.items.map((item) => [item.height, item.index, item.amount, item.reference, item.kind_name]), [['18', 0, '1017', reference(17), 'merchant_payment']]);
    assert.deepEqual(byReference.filters, { reference: reference(17), from: null });
    assert.deepEqual((await call(service, `/v1/accounts/8/payments?reference=${reference(999)}`)).body.items, []);
    assert.deepEqual((await call(service, `/v1/accounts/9/payments?reference=${reference(17)}`)).body.items, [], 'a reference paid to another account is not a deposit here');
    assert.equal((await walk('/v1/accounts/8/payments?from=6', 13)).seen.length, 30);
    assert.deepEqual((await call(service, `/v1/accounts/8/payments?reference=${reference(3)}&from=5`)).body.items.length, 1);
    assert.deepEqual((await call(service, `/v1/accounts/8/payments?reference=${reference(3)}&from=6`)).body.items, []);
    // A request for a payment above the limit moved nothing: it is activity of its sender, not a payment.
    assert.equal((await walk('/v1/accounts/5/activity', 25)).seen.filter((item) => item.kind === 75 && item.recipient === '8' && item.transfers === false).length, 30);

    // Activity of account 5 (91 actions sent) and of account 8 (91 payments received), both ways.
    // Account 8 also sees the 30 requests that name it, as pending: nothing has moved for those.
    for (const [account, roles] of [['5', { sender: 91 }], ['8', { recipient: 91, pending: 30 }]]) for (const order of ['asc', 'desc']) {
      const { seen } = await walk(`/v1/accounts/${account}/activity`, 16, order);
      const counted = {}; for (const item of seen) counted[item.role] = (counted[item.role] || 0) + 1;
      assert.deepEqual(counted, roles, `${account} ${order}`);
      assert(seen.filter((item) => item.role === 'pending').every((item) => item.kind === 75 && item.transfers === false && item.recipient === '8' && item.amount === '5000000'));
      assert.deepEqual(seen.map(position), seen.map(position).sort((a, b) => (order === 'asc' ? a - b : b - a)));
    }
    // Blocks, and the actions of one block.
    for (const order of ['asc', 'desc']) {
      const { seen } = await walk('/v1/blocks', 4, order);
      assert.deepEqual(seen.map((b) => Number(b.height)), Array.from({ length: 31 }, (_, i) => (order === 'asc' ? i + 1 : 31 - i)));
    }
    assert.deepEqual((await call(service, '/v1/blocks?cursor=1')).body.items, []);
    assert.deepEqual((await call(service, '/v1/blocks?cursor=31&order=asc')).body.items, []);
    assert.deepEqual((await walk('/v1/blocks/5/actions', 3)).seen.map((a) => a.index), [0, 1, 2, 3]);
    assert.deepEqual((await call(service, '/v1/blocks/5/actions?cursor=5.3')).body.items, []);
    assert.equal((await call(service, '/v1/blocks/5/actions?cursor=6.0')).status, 400);
    // Totals add up without losing a microsecond.
    assert.deepEqual((await call(service, '/v1/accounts/1')).body.indexed.totals.received_micros, '0');
    assert.equal(service.store.account('8').received_micros, String(Array.from({ length: 30 }, (_, b) => 1000 + b + 7 + 9).reduce((a, b) => a + b, 0) + 1));
    // Amounts beyond what a 64-bit signed integer holds are summed exactly.
    service.store.writeBlock({ previousChecked: true, events: [], block: { height: 32, hash: 'ef'.repeat(32), previous_hash: 'ab'.repeat(32), time_micros: 2, time: '1970-01-01T00:00:00.000002Z', proposer: '', app_hash: '', data_hash: '' },
      actions: ['18446744073709551615', '18446744073709551615'].map((amount, idx) => { const raw = signedAction(3, { to: '77', amount }, { nonce: String(600 + idx) }); return { ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx }; }) });
    assert.equal(service.store.account('77').received_micros, '36893488147419103230');
  });
});

test('every parameter has one accepted form; anything else is refused before any work', async () => {
  await lab(async ({ service, state }) => {
    await indexAll(service);
    state.calls.length = 0;
    const refused = {
      '/v1/blocks/0': 'invalid_height', '/v1/blocks/01': 'invalid_height', '/v1/blocks/-1': 'invalid_height', '/v1/blocks/1e3': 'invalid_height', '/v1/blocks/abc': 'invalid_height', '/v1/blocks/99999999999999999999': 'invalid_height', '/v1/blocks/1%20': 'invalid_height', '/v1/blocks/%ZZ': 'invalid_path',
      '/v1/blocks?limit=0': 'invalid_limit', '/v1/blocks?limit=201': 'invalid_limit', '/v1/blocks?limit=-1': 'invalid_limit', '/v1/blocks?limit=1.5': 'invalid_limit', '/v1/blocks?limit=': 'invalid_limit', '/v1/blocks?limit=10&limit=20': 'repeated_parameter',
      '/v1/blocks?order=up': 'invalid_order', '/v1/blocks?cursor=2.0': 'invalid_height', '/v1/blocks?before=3': 'unknown_parameter', '/v1/blocks?__proto__=1': 'unknown_parameter', '/v1/blocks/2?limit=1': 'unknown_parameter',
      '/v1/blocks/2/actions?cursor=2': 'invalid_cursor', '/v1/blocks/2/actions?cursor=2.x': 'invalid_cursor', '/v1/blocks/2/actions?order=asc': 'unknown_parameter',
      '/v1/actions/abc': 'invalid_hash', [`/v1/actions/${'g'.repeat(64)}`]: 'invalid_hash', [`/v1/actions/${'a'.repeat(65)}`]: 'invalid_hash', [`/v1/actions/0x${'a'.repeat(62)}`]: 'invalid_hash',
      '/v1/accounts/Alice': 'invalid_account', '/v1/accounts/a': 'invalid_account', '/v1/accounts/name-with-dash': 'invalid_account', '/v1/accounts/18446744073709551615': 'invalid_account', '/v1/accounts/abcdefghijklmnop': 'invalid_account', "/v1/accounts/1'%20OR%20'1'='1": 'invalid_account',
      '/v1/accounts/alice/activity': 'invalid_account', '/v1/accounts/01/activity': 'invalid_account', '/v1/accounts/1/activity?cursor=abc': 'invalid_cursor', ['/v1/accounts/1/activity?reference=' + 'ab'.repeat(32)]: 'unknown_parameter',
      '/v1/accounts/1/payments?reference=abc': 'invalid_reference', ['/v1/accounts/1/payments?reference=' + 'AB'.repeat(32)]: 'invalid_reference', ['/v1/accounts/1/payments?refrence=' + 'ab'.repeat(32)]: 'unknown_parameter',
      '/v1/accounts/1/payments?from=alice': 'invalid_account', '/v1/accounts/1/payments?from=1&from=2': 'repeated_parameter', "/v1/accounts/1/payments?order=asc;DROP%20TABLE%20actions": 'invalid_order',
      '/v1/stream?account=x': 'invalid_account', '/v1/stream?after=0': 'invalid_position', '/v1/stream?after=1.2.3': 'invalid_position', '/v1/stream?url=http://127.0.0.1/': 'unknown_parameter',
      '/v1/status?verbose=1': 'unknown_parameter',
    };
    for (const [route, code] of Object.entries(refused)) {
      const answer = await call(service, route);
      assert.deepEqual([answer.status, answer.body?.error?.code], [400, code], route);
      assert.equal(typeof answer.body.error.message, 'string');
    }
    assert.equal((await openStream(service, '/v1/stream', { 'Last-Event-ID': 'nonsense' })).status, 400);
    // Unknown routes, other methods, and an address that is too long.
    for (const route of ['/', '/v1', '/v1/', '/v2/status', '/v1/blocks/2/', '/v1/actions', '/v1/accounts', '/v1/accounts/1/unknown', '/v1/openapi_json', '/v1/../v1/status/x'])
      assert.deepEqual([(await call(service, route)).status, (await call(service, route)).body.error.code], [404, 'unknown_route'], route);
    for (const [route, method, allow] of [['/v1/status', 'POST', 'GET'], ['/v1/blocks/2', 'DELETE', 'GET'], ['/v1/transactions', 'GET', 'POST'], ['/v1/transactions', 'PUT', 'POST'], ['/v1/status', 'OPTIONS', 'GET']]) {
      const answer = await call(service, route, { method });
      assert.deepEqual([answer.status, answer.body.error.code, answer.headers.get('allow')], [405, 'method_not_allowed', allow], `${method} ${route}`);
    }
    assert.equal((await call(service, `/v1/blocks?cursor=${'1'.repeat(3000)}`)).status, 414);
    // The table of the database is intact, and none of this reached the node.
    assert.equal(service.store.high(), 4);
    assert.deepEqual(state.calls, []);
    assert.equal(MAX_PAGE, 200);
  });
});

test('a signed action is submitted to the node, and every refusal has its own answer', async () => {
  await lab(async ({ service, state }) => {
    const post = (body, headers = { 'Content-Type': 'application/json' }) => call(service, '/v1/transactions', { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body) });
    const tx = fixture.txs['4'][0], hash = hashOf('4', 0);
    const accepted = await post({ tx });
    assert.equal(accepted.status, 202, accepted.text);
    assert.deepEqual({ ...accepted.body, note: undefined }, { hash, status: 'submitted', kind: 3, sender: '7', nonce: '3', note: undefined });
    assert.deepEqual(state.calls.filter(([method]) => method === '/broadcast_tx_sync'), [['/broadcast_tx_sync', { tx: `0x${txBytes('4', 0).toString('hex')}` }]]);
    // The node refuses it (CheckTx), already has it, is down, or answers for something else.
    state.broadcast = () => ({ code: 1, log: 'stale authority or incorrect nonce\u0000<script>', hash });
    const rejected = await post({ tx });
    assert.deepEqual([rejected.status, rejected.body.error.code, rejected.body.hash, rejected.body.index.indexed_height], [422, 'rejected', hash, null]);
    assert.match(rejected.body.error.message, /^The node refused the action: stale authority or incorrect nonce <script>\. If these bytes, or the same payment under another signature, were sent before, .* look the hash up and find which action used the nonce$/);
    state.broadcast = () => { throw Object.assign(new IndexerError('RPC_REFUSED', 'The RPC refused the request'), { rpcMessage: 'tx already exists in cache' }); };
    assert.deepEqual([(await post({ tx })).status, (await post({ tx })).body.error.code, (await post({ tx })).body.hash], [409, 'already_submitted', hash]);
    state.broadcast = () => { throw new IndexerError('RPC_UNAVAILABLE', 'The RPC could not be reached'); };
    const down = await post({ tx });
    assert.deepEqual([down.status, down.body.error.code, down.headers.get('retry-after')], [502, 'node_unavailable', '2']);
    state.broadcast = () => { throw new Error(['connect ECONNREFUSED http://user:hunter2', 'node.internal:26657/'].join('@')); };
    assert(!/hunter2|node\.internal/.test((await post({ tx })).text));
    state.broadcast = () => ({ code: 0, hash: 'AB'.repeat(32) });
    assert.deepEqual([(await post({ tx })).status, (await post({ tx })).body.error.code], [502, 'node_mismatch']);
    state.broadcast = () => ({ code: 'zero', hash });
    assert.equal((await post({ tx })).status, 422);

    // Bytes that are in an indexed block already are answered as such, whatever the node says:
    // before it is asked, and after it refused them ("incorrect nonce": the nonce they used themselves).
    state.broadcast = () => { service.store.high() ?? seed(service, [[txBytes('4', 0)]]); return { code: 1, log: 'incorrect nonce or nonce exhausted', hash }; };
    const meanwhile = await post({ tx });
    assert.deepEqual([meanwhile.status, meanwhile.body.status, meanwhile.body.hash, meanwhile.body.height, meanwhile.body.index], [200, 'already_included', hash, '1', 0]);
    state.broadcast = () => assert.fail('an included action is not sent to the node again');
    const again = await post({ tx });
    assert.deepEqual([again.status, again.body.status, again.body.height, again.body.sender, again.body.nonce], [200, 'already_included', '1', '7', '3']);

    // The same withdrawal signed a second time (another key, a signer asked again) has other bytes and
    // another hash. The index names the action that used the nonce, before the node is asked and after it refused.
    const second = async (payload, nonce = '3') => {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const body = Buffer.from(SDK.buildAction({ networkId: NETWORK, kind: 3, from: '7', nonce, authEpoch: '0', publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), payload }));
      return Buffer.concat([body, edSign(null, body, privateKey)]);
    };
    const twice = await post({ tx: (await second({ to: '1', amount: '5' })).toString('base64') });
    assert.deepEqual([twice.status, twice.body.error.code, twice.body.used_by.hash, twice.body.used_by.height, twice.body.used_by.same_content, twice.body.used_by.recipient, twice.body.used_by.amount, twice.body.used_by.kind],
      [409, 'nonce_used', hash, '1', true, '1', '5', 3]);
    // The same content is the same payment signed twice, or another payment that looks the same: the answer no
    // longer says "it is done", it says what decides (one hash settles one payment) and to verify the hash.
    assert.match(twice.body.error.message, /these bytes can never be included\. One hash is one payment: if used_by\.hash is not the hash of another payment in your records, this payment is made by it.*if it is, this payment is not made\. Verify used_by\.hash/);
    assert.doesNotMatch(twice.body.error.message, /it is done/);
    const differing = await post({ tx: (await second({ to: '1', amount: '6' })).toString('base64') });
    assert.deepEqual([differing.status, differing.body.error.code, differing.body.used_by.hash, differing.body.used_by.same_content], [409, 'nonce_used', hash, false]);
    assert.match(differing.body.error.message, /can never be included\. Verify used_by\.hash before you act on that/);
    // A nonce nobody used yet is not answered this way; nor is an action without a nonce.
    state.broadcast = () => ({ code: 1, log: 'insufficient funds', hash: 'AB'.repeat(32) });
    assert.deepEqual([(await post({ tx: (await second({ to: '1', amount: '5' }, '4')).toString('base64') })).body.error.code], ['rejected']);
    // After a refusal the index is asked again: the block with the first signature may have arrived meanwhile.
    const earlier = signedAction(3, { to: '8', amount: '9' }, { from: '7', nonce: '77' }), late = await second({ to: '8', amount: '9' }, '77');
    state.broadcast = () => {
      service.store.writeBlock({ previousChecked: true, block: { height: 2, hash: 'ab'.repeat(32), previous_hash: 'cd'.repeat(32), time_micros: 2, time: '1970-01-01T00:00:00.000002Z', proposer: '', app_hash: '', data_hash: '' },
        actions: [{ ...describeAction(earlier, NETWORK), hash: sha(earlier).toString('hex').toUpperCase(), raw: earlier, idx: 0 }] });
      return { code: 1, log: 'incorrect nonce' };
    };
    const arrived = await post({ tx: late.toString('base64') });
    assert.deepEqual([arrived.status, arrived.body.error.code, arrived.body.used_by.hash, arrived.body.used_by.height, arrived.body.used_by.same_content], [409, 'nonce_used', sha(earlier).toString('hex').toUpperCase(), '2', true]);

    // A validator's upgrade signal (kind 80) is an action like any other here: the signature is
    // checked, the bytes are passed on, and what the node answers is passed back. A node takes a
    // support signal only for a version and specification it implements itself, and says so.
    const signal = (payload, nonce) => {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519');
      const body = Buffer.from(SDK.buildAction({ networkId: NETWORK, kind: 'upgrade_signal', from: '7', nonce, authEpoch: '0', publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), payload }));
      return Buffer.concat([body, edSign(null, body, privateKey)]);
    };
    state.broadcast = (parameters) => ({ code: 0, hash: sha(Buffer.from(parameters.tx.slice(2), 'hex')).toString('hex').toUpperCase() });
    const withdrawal = await post({ tx: signal({}, '90').toString('base64') });
    assert.deepEqual([withdrawal.status, withdrawal.body.status, withdrawal.body.kind, withdrawal.body.sender, withdrawal.body.nonce], [202, 'submitted', 80, '7', '90']);
    state.broadcast = () => ({ code: 1, log: 'this node does not implement that version under that specification hash and neither admits nor proposes signals for it' });
    const unsupported = await post({ tx: signal({ activate_elapsed_micros: '1814400000000', spec: '5e'.repeat(32), version: '5' }, '91').toString('base64') });
    assert.deepEqual([unsupported.status, unsupported.body.error.code], [422, 'rejected']);
    assert.match(unsupported.body.error.message, /^The node refused the action: this node does not implement that version under that specification hash/);
    // Bytes of kind 80 whose content is not one of the two forms of a signal are not an action at all.
    const malformed = signal({}, '92'), spaced = Buffer.concat([malformed.subarray(0, 108), Buffer.from([0, 0, 0, 3]), Buffer.from('{ }'), malformed.subarray(-64)]);
    assert.deepEqual([malformed.length, malformed.readUInt32BE(108), spaced.length], [108 + 4 + 2 + 64, 2, 108 + 4 + 3 + 64]);
    assert.deepEqual([(await post({ tx: spaced.toString('base64') })).status, (await post({ tx: spaced.toString('base64') })).body.error.code], [400, 'invalid_action']);

    // What never reaches the node.
    state.calls.length = 0; state.broadcast = () => assert.fail('must not be submitted');
    const unsigned = Buffer.from(txBytes('2', 0)); unsigned[unsigned.length - 1] ^= 1;
    const tampered = Buffer.from(txBytes('2', 0)); tampered[tampered.length - 70] ^= 1; // a byte of the payload: another action, same signature
    for (const bytes of [unsigned, signedAction(3, { to: '8', amount: '5' }), signedAction(75, { type: 'request', to: '8', amount: '5' })])
      assert.deepEqual([(await post({ tx: bytes.toString('base64') })).status, (await post({ tx: bytes.toString('base64') })).body.error.code], [400, 'invalid_signature']);
    assert.equal((await post({ tx: tampered.toString('base64') })).status, 400);
    // The public relay of bitcoin headers has no signer; anything else with an empty signature is refused.
    // It has one form (sender, nonce and epoch fixed, no key), and it is passed on only once a proof
    // of the network's configuration has shown that the network takes it.
    const relay = Buffer.from(SDK.publicHeadersAction(NETWORK, ['ab'.repeat(80)])).toString('base64');
    const shaped = (more) => Buffer.concat([Buffer.from(SDK.buildAction({ networkId: NETWORK, kind: 40, from: SDK.MAX_U64, nonce: '0', authEpoch: '0', publicKey: '00'.repeat(32), payload: { headers: ['ab'.repeat(80)] }, ...more })), Buffer.alloc(64)]).toString('base64');
    state.stateDown = true;
    assert.deepEqual([(await post({ tx: relay })).status, (await post({ tx: relay })).body.error.code], [503, 'state_unavailable']);
    state.stateDown = false;
    for (const more of [{ nonce: '7' }, { authEpoch: '9' }, { from: '5' }, { publicKey: 'bb'.repeat(32) }]) assert.deepEqual([(await post({ tx: shaped(more) })).status, (await post({ tx: shaped(more) })).body.error.code], [400, 'invalid_signature'], JSON.stringify(more));
    state.broadcast = (parameters) => ({ code: 0, hash: sha(Buffer.from(parameters.tx.slice(2), 'hex')).toString('hex').toUpperCase() });
    assert.equal((await post({ tx: relay })).status, 202);
    assert.equal((await post({ tx: shaped({}) })).status, 202);
    state.calls.length = 0; state.broadcast = () => assert.fail('must not be submitted');
    // On a network that pays all new time to validators there is no auction: its kinds are refused here, as the engine refuses them.
    const without = state.readState;
    state.readState = async (selection) => ({ ...(await without(selection)), state: { ...(await without(selection)).state, config: { all_new_time_to_validators: true } } });
    await call(service, '/v1/accounts/1');
    assert.deepEqual([(await post({ tx: relay })).status, (await post({ tx: relay })).body.error.code], [400, 'not_on_this_network']);
    state.readState = without;
    const other = signedAction(3, { to: '8', amount: '5' }, { networkId: 'cd'.repeat(32) }).toString('base64');
    const cases = [
      [{ tx: other }, 400, 'wrong_network'], [{ tx: Buffer.from('not an action at all, just some bytes that are long enough to pass the size check').toString('base64') }, 400, 'invalid_action'],
      [{ tx: txBytes('4', 0).subarray(0, 150).toString('base64') }, 400, 'invalid_action'], [{ tx: tx.replace(/=*$/, '') + '=' }, 400, 'invalid_body'], [{ tx: `0x${txBytes('4', 0).toString('hex')}` }, 400, 'invalid_action'], [{ tx: txBytes('4', 0).toString('hex') + '!' }, 400, 'invalid_body'],
      [{ tx: 'AAAA' }, 400, 'invalid_body'], [{ tx: '' }, 400, 'invalid_body'], [{ tx: 5 }, 400, 'invalid_body'], [{ tx, wait: true }, 400, 'invalid_body'], [{}, 400, 'invalid_body'], [[tx], 400, 'invalid_body'], ['null', 400, 'invalid_body'], ['"tx"', 400, 'invalid_body'],
      ['{"tx": ', 400, 'invalid_json'], ['', 400, 'invalid_json'], [Buffer.from([0x7b, 0xff, 0x7d]).toString('latin1'), 400, 'invalid_json'],
    ];
    for (const [body, status, code] of cases) { const answer = await post(body); assert.deepEqual([answer.status, answer.body.error.code], [status, code], JSON.stringify(body).slice(0, 60)); }
    assert.deepEqual([(await post({ tx }, { 'Content-Type': 'text/plain' })).status, (await post({ tx }, {})).body.error.code], [415, 'unsupported_media_type']);
    assert.equal((await call(service, '/v1/transactions?wait=1', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tx }) })).body.error.code, 'unknown_parameter');
    assert.deepEqual(state.calls, []);
  });
});

test('an oversized or broken request is cut off, and the server keeps answering', async () => {
  await lab(async ({ service, state }) => {
    state.broadcast = () => assert.fail('must not be submitted');
    const { port } = new URL(service.url);
    /// Sends raw bytes and returns what comes back until the server closes or two seconds pass.
    const raw = (text, more = null) => new Promise((resolve) => {
      const socket = net.connect(Number(port), '127.0.0.1'); let answer = '';
      socket.on('data', (chunk) => { answer += chunk; });
      const done = () => { socket.destroy(); resolve(answer); };
      socket.on('close', done); socket.on('error', done); setTimeout(done, 2000).unref();
      socket.write(text); if (more) socket.write(more);
    });
    const head = (length, extra = '') => `POST /v1/transactions HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\n${length === null ? '' : `Content-Length: ${length}\r\n`}${extra}\r\n`;
    // A body announced above the limit is refused before it is read.
    const declared = await raw(head(MAX_BODY_BYTES + 1), '{"tx":"');
    assert.match(declared, /^HTTP\/1\.1 413 /); assert.match(declared, /"code":"body_too_large"/); assert.match(declared, /Connection: close/i);
    // A body that grows past the limit without announcing it (chunked) is cut off as well.
    const chunk = 'A'.repeat(65536), chunked = `${chunk.length.toString(16)}\r\n${chunk}\r\n`;
    const streamed = await raw(head(null, 'Transfer-Encoding: chunked\r\n'), chunked.repeat(14));
    assert.match(streamed, /^HTTP\/1\.1 413 /);
    // The largest body the route takes is read in full and judged on its content.
    const large = await call(service, '/v1/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tx: 'A'.repeat(MAX_BODY_BYTES - 9) }) });
    assert.deepEqual([large.status, large.body.error.code], [400, 'invalid_body']);
    // Not HTTP at all, a request line without end, headers that never finish.
    assert.match(await raw('\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 garbage\r\n\r\n'), /^(HTTP\/1\.1 400 |$)/);
    assert.match(await raw(`GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nX-Long: ${'a'.repeat(70000)}\r\n\r\n`), /^HTTP\/1\.1 431 /);
    assert.match(await raw(`GET /v1/blocks/${'9'.repeat(40000)} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`), /^HTTP\/1\.1 (414|431) /);
    // After all of it, an ordinary request is answered.
    assert.equal((await call(service, '/v1/status')).status, 200);
    assert(!state.logs.some((line) => line.level === 'error'), JSON.stringify(state.logs));
  });
});

test('each client has its own request budget; a trusted proxy may name the client, nobody else', async () => {
  await lab(async ({ service, state }) => {
    // Three at once, then one more every second.
    for (let i = 0; i < 3; i++) assert.equal((await call(service, '/v1/status')).status, 200);
    const limited = await call(service, '/v1/status');
    assert.deepEqual([limited.status, limited.body.error.code, limited.headers.get('retry-after')], [429, 'rate_limited', '1']);
    assert.equal((await call(service, '/v1/nothing')).status, 429, 'unknown routes count too');
    state.clock += 1000;
    assert.equal((await call(service, '/v1/status')).status, 200);
    assert.equal((await call(service, '/v1/status')).status, 429);
    // A dearer route waits longer: an account read costs five.
    state.clock += 2000;
    const dear = await call(service, '/v1/accounts/1');
    assert.deepEqual([dear.status, dear.headers.get('retry-after')], [429, '3']);
    // This peer is not a trusted proxy: the header it sends changes nothing.
    assert.equal((await call(service, '/v1/status', { headers: { 'X-Forwarded-For': '203.0.113.9' } })).status, 200);
    assert.equal((await call(service, '/v1/status', { headers: { 'X-Forwarded-For': '203.0.113.10' } })).status, 200);
    assert.equal((await call(service, '/v1/status', { headers: { 'X-Forwarded-For': '203.0.113.11' } })).status, 429);
  }, { rateLimit: { perSecond: 1, burst: 3 } });
  await lab(async ({ service }) => {
    // Behind a trusted proxy each forwarded client has its own budget, taken from the last entry
    // (the one the proxy wrote); earlier entries are the client's own claim.
    const as = (forwarded) => call(service, '/v1/status', { headers: { 'X-Forwarded-For': forwarded } });
    for (let i = 0; i < 2; i++) assert.equal((await as('203.0.113.9')).status, 200);
    assert.equal((await as('203.0.113.9')).status, 429);
    assert.equal((await as('198.51.100.1, 203.0.113.9')).status, 429);
    assert.equal((await as('203.0.113.9, 198.51.100.1')).status, 200);
    assert.equal((await as('2001:db8:1:2:aaaa::1')).status, 200);
    assert.equal((await as('2001:db8:1:2:bbbb::2')).status, 200);
    assert.equal((await as('2001:db8:1:2:cccc::3')).status, 429, 'one /64 is one client');
    assert.equal((await as('2001:db8:1:3::1')).status, 200);
  }, { rateLimit: { perSecond: 1, burst: 2 }, trustedProxies: ['127.0.0.1'] });
  await lab(async ({ service }) => {
    // Two of the operator's own proxies in a row, and entries that carry a port: the client is the
    // first entry from the right that is not one of the proxies.
    const as = (forwarded) => call(service, '/v1/status', { headers: { 'X-Forwarded-For': forwarded } });
    assert.equal((await as('203.0.113.9, 10.0.0.2')).status, 200);
    assert.equal((await as('203.0.113.9:4711, 10.0.0.2:80')).status, 200);
    assert.equal((await as('198.51.100.7, 203.0.113.9, 10.0.0.2, 10.0.0.2')).status, 429, 'the same client, however the chain is written');
    assert.equal((await as('[2001:db8:5::1]:443, 10.0.0.2')).status, 200);
    assert.equal((await as('2001:db8:5::2, 10.0.0.2')).status, 200);
    assert.equal((await as('2001:db8:5::3')).status, 429);
    // An entry that is no address stops the walk: the request counts against the proxy itself.
    assert.equal((await as('203.0.113.50, garbage, 10.0.0.2')).status, 200);
    assert.equal((await as('203.0.113.51, garbage, 10.0.0.2')).status, 200);
    assert.equal((await as('203.0.113.52, garbage, 10.0.0.2')).status, 429);
  }, { rateLimit: { perSecond: 1, burst: 2 }, trustedProxies: ['127.0.0.1', '10.0.0.2'] });
  assert.deepEqual(['203.0.113.9:80', '[2001:DB8::1]:443', '::ffff:10.0.0.1', ' 10.0.0.2 ', '10.0.0.2.', 'proxy.internal', '', '::1.2.3.4'].map(normalIp), ['203.0.113.9', '2001:db8:0:0:0:0:0:1', '10.0.0.1', '10.0.0.2', null, null, null, null]);
  // The limiter itself: keys, refill, and a bounded table.
  assert.deepEqual(['203.0.113.9', '::ffff:203.0.113.9', '2001:db8:1:2:3:4:5:6', '2001:db8::1', '::1', 'fe80::1%eth0', 'nonsense', undefined].map(clientKey), ['203.0.113.9', '203.0.113.9', '2001:db8:1:2::/64', '2001:db8:0:0::/64', '0:0:0:0::/64', 'fe80:0:0:0::/64', 'unknown', 'unknown']);
  let at = 0;
  const limiter = createRateLimiter({ perSecond: 2, burst: 4, maxClients: 100, now: () => at });
  assert.deepEqual([limiter.take('a', 4), limiter.take('a'), limiter.take('a', 4)], [0, 1, 2]);
  at += 500; assert.equal(limiter.take('a'), 0);
  for (let i = 0; i < 5000; i++) limiter.take(`client-${i}`);
  assert(limiter.size() <= 100);
  at += 10000; assert.equal(limiter.take('a', 4), 0);
  // A clock that is set back takes nothing away, and time runs on from where it now stands.
  at -= 3600 * 1000; assert.equal(limiter.take('b'), 0);
  at -= 3600 * 1000; assert.deepEqual([limiter.take('b', 3), limiter.take('b')], [0, 1]);
  at += 500; assert.equal(limiter.take('b'), 0);
});

test('browsers may call only from configured origins, and the server answers only under its own names', async () => {
  const request = (service, route, headers, method = 'GET') => new Promise((resolve, reject) => {
    const { port } = new URL(service.url);
    const req = http.request({ host: '127.0.0.1', port, path: route, method, headers }, (res) => { let text = ''; res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text })); });
    req.on('error', reject); req.end();
  });
  await lab(async ({ service }) => {
    // No origins configured: any cross-origin browser request is refused, a preflight too.
    for (const origin of ['https://evil.example', 'null', 'http://127.0.0.1:1']) {
      const answer = await call(service, '/v1/status', { headers: { Origin: origin } });
      assert.deepEqual([answer.status, answer.body.error.code, answer.headers.get('access-control-allow-origin')], [403, 'origin_not_allowed', null], origin);
    }
    assert.equal((await call(service, '/v1/transactions', { method: 'OPTIONS', headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' } })).status, 403);
    // Requests under another host name (DNS rebinding) are not answered.
    const { port } = new URL(service.url);
    for (const host of ['evil.example', `evil.example:${port}`, '127.0.0.1', `127.0.0.1:${Number(port) + 1}`]) assert.equal((await request(service, '/v1/status', { Host: host })).status, 421, host);
    for (const host of [`127.0.0.1:${port}`, `localhost:${port}`, `LOCALHOST:${port}`]) assert.equal((await request(service, '/v1/status', { Host: host })).status, 200, host);
  });
  await lab(async ({ service }) => {
    const allowed = await call(service, '/v1/status', { headers: { Origin: 'https://explorer.example' } });
    assert.deepEqual([allowed.status, allowed.headers.get('access-control-allow-origin'), allowed.headers.get('vary'), allowed.headers.get('access-control-allow-credentials')], [200, 'https://explorer.example', 'Origin', null]);
    const preflight = await call(service, '/v1/transactions', { method: 'OPTIONS', headers: { Origin: 'https://explorer.example', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
    assert.deepEqual([preflight.status, preflight.headers.get('access-control-allow-origin'), preflight.headers.get('access-control-allow-methods')], [204, 'https://explorer.example', 'GET, POST']);
    for (const origin of ['https://explorer.example.evil.example', 'http://explorer.example', 'https://explorer.example:8443', 'https://EXPLORER.example']) assert.equal((await call(service, '/v1/status', { headers: { Origin: origin } })).status, 403, origin);
    // The public name as clients send it: with the port, or without it on 443 and 80.
    for (const host of ['api.example:443', 'api.example', 'API.Example', 'other.example', 'other.example:443', 'third.example:8443']) assert.equal((await request(service, '/v1/status', { Host: host })).status, 200, host);
    for (const host of ['api.example:8443', 'third.example', 'evil.example', 'api.example.evil.example']) assert.equal((await request(service, '/v1/status', { Host: host })).status, 421, host);
  }, { corsOrigins: ['https://explorer.example'], hosts: ['api.example:443', 'other.example', 'third.example:8443'] });
  await lab(async ({ service }) => {
    const any = await call(service, '/v1/status', { headers: { Origin: 'https://anything.example' } });
    assert.deepEqual([any.status, any.headers.get('access-control-allow-origin'), any.headers.get('access-control-allow-credentials')], [200, '*', null]);
  }, { corsOrigins: ['*'] });
});

// Found by the first run of the explorer in a real browser (2026-11-19): Chrome names the page in `Origin` also
// when the page asks its own server, for a module script and for every request the scripts make. The server
// refused that like a foreign origin, and the explorer it serves loaded in no browser.
test('the server\'s own pages may ask it: an origin that is the very address asked needs no permission, and nothing else passes as one', async () => {
  const request = (service, route, headers) => new Promise((resolve, reject) => {
    const { port } = new URL(service.url);
    const req = http.request({ host: '127.0.0.1', port, path: route, method: 'GET', headers }, (res) => { let text = ''; res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text })); });
    req.on('error', reject); req.end();
  });
  await lab(async ({ service }) => {
    const { port } = new URL(service.url);
    // On this machine: the page was opened under http at the address that is asked.
    for (const host of [`127.0.0.1:${port}`, `localhost:${port}`]) {
      const answer = await request(service, '/v1/status', { Host: host, Origin: `http://${host}` });
      assert.deepEqual([answer.status, answer.headers['access-control-allow-origin'] ?? null], [200, null], host);
    }
    // Not the address asked: another port, another loopback name, https on a loopback name, or no such page at all.
    for (const [host, origin] of [[`127.0.0.1:${port}`, `http://127.0.0.1:${Number(port) + 1}`], [`127.0.0.1:${port}`, `http://localhost:${port}`], [`127.0.0.1:${port}`, `https://127.0.0.1:${port}`], [`127.0.0.1:${port}`, 'null'], [`127.0.0.1:${port}`, `http://127.0.0.1:${port}.evil.example`]])
      assert.equal((await request(service, '/v1/status', { Host: host, Origin: origin })).status, 403, `${host} asked from ${origin}`);
  });
  await lab(async ({ service }) => {
    // Behind a TLS proxy: https under one of the configured names, as the browser writes the origin.
    for (const [host, origin] of [['api.example', 'https://api.example'], ['api.example:443', 'https://api.example'], ['third.example:8443', 'https://third.example:8443']]) {
      const answer = await request(service, '/v1/status', { Host: host, Origin: origin });
      assert.deepEqual([answer.status, answer.headers['access-control-allow-origin'] ?? null], [200, null], `${host} asked from ${origin}`);
    }
    // Another of the server's names is another origin; so are http, another port, and a name that only starts alike.
    for (const [host, origin] of [['api.example', 'https://other.example'], ['api.example', 'http://api.example'], ['api.example', 'https://api.example:8443'], ['third.example:8443', 'https://third.example'], ['api.example', 'https://api.example.evil.example'], ['api.example', 'https://API.example']])
      assert.equal((await request(service, '/v1/status', { Host: host, Origin: origin })).status, 403, `${host} asked from ${origin}`);
    // A configured name is not a loopback name: http is this machine's own pages only.
    assert.equal((await request(service, '/v1/status', { Host: 'other.example', Origin: 'http://other.example' })).status, 403);
  }, { hosts: ['api.example:443', 'other.example', 'third.example:8443'] });
});

test('incoming payments to configured accounts are delivered as signed webhooks, each receiver on its own', async () => {
  const SECRET = 'a-webhook-secret-of-the-shop-0123456789', OTHER_SECRET = 'another-secret-for-the-second-receiver';
  const received = [], answers = { '/hook-path-of-the-shop': [], '/dead': [] };
  const receiver = http.createServer((request, response) => {
    let body = ''; request.on('data', (c) => { body += c; });
    request.on('end', () => {
      const route = new URL(request.url, 'http://x').pathname;
      const status = answers[route]?.shift() ?? (route === '/dead' ? 500 : 200);
      received.push({ route, url: request.url, headers: request.headers, body, status });
      response.writeHead(status); response.end('ignored');
    });
  });
  await new Promise((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${receiver.address().port}`;
  const webhooks = [
    { account: '1', url: `${base}/hook-path-of-the-shop?token=query-token-123`, secret: SECRET },
    { account: '1', url: `${base}/dead`, secret: OTHER_SECRET },
    { account: '7', url: `${base}/payer`, secret: OTHER_SECRET },
  ];
  try {
    await lab(async ({ service, state, directory }) => {
      // The first delivery is refused once (a receiver whose clock or secret is wrong): it is retried.
      answers['/hook-path-of-the-shop'].push(401);
      // The service starts while the chain is at block 1: its webhooks start there.
      state.tip = 1;
      await indexAll(service, 1);
      state.tip = 3;
      await indexAll(service, 3);
      for (let i = 0; i < 400 && received.filter((r) => r.route === '/hook-path-of-the-shop' && r.status === 200).length < 2; i++) await pause(5);
      const shop = received.filter((r) => r.route === '/hook-path-of-the-shop');
      assert.deepEqual(shop.map((r) => r.status), [401, 200, 200]);
      // In chain order, the retried one first, each with a signature the watch's own check accepts.
      const events = shop.filter((r) => r.status === 200).map((r) => JSON.parse(r.body));
      assert.deepEqual(events.map((e) => [e.id, e.type, e.source, e.proven, e.hash, e.height, e.index, e.sender, e.recipient, e.amount, e.reference, e.kind, e.transfers]),
        [0, 1].map((i) => [`payment:${hashOf('2', i)}`, 'payment', 'index', false, hashOf('2', i), '2', i, '7', '1', '5', null, 3, true]));
      // The same names as an item of the payments list.
      const listed = (await call(service, '/v1/accounts/1/payments')).body.items[0];
      for (const name of ['hash', 'height', 'index', 'time', 'kind', 'kind_name', 'sender', 'nonce', 'recipient', 'amount', 'reference', 'transfers', 'request_hash']) assert.deepEqual(events[0][name], listed[name], name);
      assert.equal(shop[0].body, shop[1].body, 'a retry sends the same event');
      for (const delivery of shop) {
        assert.equal(delivery.headers['x-watch-event'], JSON.parse(delivery.body).id);
        assert.equal(verifyWebhookSignature(delivery.body, delivery.headers, SECRET), true);
        assert.equal(verifyWebhookSignature(delivery.body, delivery.headers, OTHER_SECRET), false);
        assert.equal(verifyWebhookSignature(delivery.body.replace('"amount":"5"', '"amount":"5000000"'), delivery.headers, SECRET), false);
      }
      // The account that pays is not told of payments it sent, only of ones it receives.
      assert.equal(received.filter((r) => r.route === '/payer').length, 0);
      // The receiver that keeps failing delays nobody: its events wait in its own queue.
      assert(received.filter((r) => r.route === '/dead').length >= 1);
      for (let i = 0; i < 400 && (await call(service, '/v1/health')).body.webhooks.failing_targets < 1; i++) await pause(5);
      let health = (await call(service, '/v1/health')).body.webhooks;
      assert.deepEqual([health.targets, health.queued, health.dead_letters, health.failing_targets], [3, 2, 0, 1]);

      // A new block: delivered once, while the failing queue grows.
      state.tip = 4;
      await indexAll(service, 4);
      for (let i = 0; i < 400 && received.filter((r) => r.route === '/hook-path-of-the-shop').length < 4; i++) await pause(5);
      assert.equal(JSON.parse(received.filter((r) => r.route === '/hook-path-of-the-shop').at(-1).body).id, `payment:${hashOf('4', 0)}`);
      assert.equal((await call(service, '/v1/health')).body.webhooks.queued, 3);
      // The receiver ends the subscription for an event (410): it becomes a dead letter and the next ones follow.
      answers['/dead'].push(410, 200, 200);
      for (let i = 0; i < 600 && (await call(service, '/v1/health')).body.webhooks.queued > 0; i++) await pause(10);
      health = (await call(service, '/v1/health')).body.webhooks;
      assert.deepEqual([health.queued, health.dead_letters, health.failing_targets], [0, 1, 0]);
      assert.equal(received.filter((r) => r.route === '/dead' && r.status === 200).length, 2);

      // Nothing secret is in the log or in an answer: no secret, no path, no query of a webhook.
      const said = JSON.stringify(state.logs) + JSON.stringify((await call(service, '/v1/health')).body) + JSON.stringify((await call(service, '/v1/status')).body);
      for (const secret of [SECRET, OTHER_SECRET, 'hook-path-of-the-shop', 'query-token-123']) assert(!said.includes(secret), secret);
      assert(state.logs.some((line) => line.origin === base && /delivery failed/.test(line.message)));

      // A restart with one webhook removed: its queue is dropped, the others are not sent twice.
      await service.close();
      received.length = 0;
      const again = await createApiService({ trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, now: () => state.clock, webhooks: webhooks.slice(0, 1), webhookTiming: { retryMs: 20, attemptDelayMs: 1 } });
      try {
        again.webhooks.kick(); await pause(100);
        assert.equal(received.length, 0);
        assert.deepEqual((await call(again, '/v1/health')).body.webhooks, { targets: 1, queued: 0, dead_letters: 0, failing_targets: 0, refusing_targets: 0, skipped_history: 0, awaiting_start: 0 });
      } finally { await again.close(); }
    }, { webhooks, webhookTiming: { retryMs: 20, attemptDelayMs: 1 } });
  } finally { await new Promise((resolve) => { receiver.close(resolve); receiver.closeAllConnections(); }); }
  // A target is named by its account and its address, as the watch's are.
  assert.notEqual(webhookTargetId('1', `${base}/a`), webhookTargetId('1', `${base}/b`));
  assert.notEqual(webhookTargetId('1', `${base}/a`), webhookTargetId('2', `${base}/a`));
  // Webhooks that could reach a caller-chosen place inside the network, or carry credentials, are refused at start.
  for (const url of ['http://10.0.0.5/hook', 'http://example.com/hook', 'ftp://example.com/hook', ['https://user:pass', 'example.com/hook'].join('@'), 'not a url'])
    await assert.rejects(createApiService({ trust: fixture.trust, rpc: async () => ({}), verifier, dataFile: ':memory:', port: 0, autoStart: false, webhooks: [{ account: '1', url, secret: SECRET }] }), /webhook/i, url);
  await assert.rejects(createApiService({ trust: fixture.trust, rpc: async () => ({}), verifier, dataFile: ':memory:', port: 0, autoStart: false, webhooks: [{ account: '1', url: 'https://example.com/hook', secret: 'short' }] }), /secret/);
});

test('the event stream carries new blocks and payments, filters by account, and resumes after a break', async () => {
  await lab(async ({ service, state }) => {
    state.tip = 2;
    await indexAll(service, 2);
    const all = await openStream(service, '/v1/stream'), mine = await openStream(service, '/v1/stream?account=1'), other = await openStream(service, '/v1/stream?account=55');
    assert.match(all.headers.get('content-type'), /^text\/event-stream/);
    await all.waitFor(1); await mine.waitFor(1); await other.waitFor(1);
    assert.deepEqual([all.events[0].event, all.events[0].data.source, all.events[0].data.proven, all.events[0].data.index.indexed_height, mine.events[0].data.account], ['hello', 'index', false, '2', '1']);
    // Blocks 3 and 4 arrive: block 3 is empty, block 4 holds one payment from 7 to 1.
    state.tip = 4;
    await indexAll(service, 4);
    await all.waitFor(4); await mine.waitFor(4); await other.waitFor(3);
    assert.deepEqual(all.events.slice(1).map((e) => [e.event, e.id]), [['block', '3'], ['payment', '4.0'], ['block', '4']]);
    assert.deepEqual(mine.events.slice(1).map((e) => [e.event, e.id]), [['block', '3'], ['payment', '4.0'], ['block', '4']]);
    assert.deepEqual(other.events.slice(1).map((e) => [e.event, e.id]), [['block', '3'], ['block', '4']]);
    const payment = all.events[2].data, block = all.events[3].data;
    assert.deepEqual(payment, { id: `payment:${hashOf('4', 0)}`, type: 'payment', source: 'index', proven: false, hash: hashOf('4', 0), height: '4', index: 0, time: '1970-01-12T13:46:44.000000Z', kind: 3, kind_name: 'transfer',
      sender: '7', nonce: '3', recipient: '1', amount: '5', reference: null, transfers: true, request_hash: null, results_checked: false });
    assert.deepEqual([mine.events[0].data.direction, all.events[0].data.direction], ['in', null]);
    assert.deepEqual([block.source, block.proven, block.height, block.hash, block.tx_count, block.payment_count], ['index', false, '4', fixture.blocks[3].signed_header.commit.block_id.hash, 1, 1]);
    assert.equal((await call(service, '/v1/health')).body.streams, 3);
    await all.close(); await mine.close(); await other.close();
    for (let i = 0; i < 200 && (await call(service, '/v1/health')).body.streams > 0; i++) await pause(5);

    // A reader that last saw block 1 gets what it missed, then the stream goes on live.
    const resumed = await openStream(service, '/v1/stream', { 'Last-Event-ID': '1' });
    await resumed.waitFor(7);
    assert.deepEqual(resumed.events.map((e) => [e.event, e.id]), [['hello', null], ['payment', '2.0'], ['payment', '2.1'], ['block', '2'], ['block', '3'], ['payment', '4.0'], ['block', '4']]);
    assert.equal(resumed.events[3].data.results_checked, true);
    await resumed.close();
    // One that broke off between the two payments of block 2 gets the second, not the first again.
    // Account 7 only pays: its stream carries those payments when asked for the outgoing ones, and
    // none by default (a stream for deposits does not carry withdrawals).
    for (const [query, expected] of [['&direction=out', [['payment', '2.1'], ['block', '2'], ['block', '3'], ['payment', '4.0'], ['block', '4']]], ['&direction=both', [['payment', '2.1'], ['block', '2'], ['block', '3'], ['payment', '4.0'], ['block', '4']]],
      ['', [['block', '2'], ['block', '3'], ['block', '4']]], ['&direction=in', [['block', '2'], ['block', '3'], ['block', '4']]]]) {
      const midway = await openStream(service, `/v1/stream?after=2.0&account=7${query}`);
      await midway.waitFor(expected.length + 1);
      assert.deepEqual(midway.events.slice(1).map((e) => [e.event, e.id]), expected, query);
      await midway.close();
    }
    assert.equal((await openStream(service, '/v1/stream?direction=out')).status, 400);
    assert.equal((await openStream(service, '/v1/stream?account=7&direction=sideways')).status, 400);
    // Up to date, or ahead of the index: nothing is sent again.
    for (const after of ['4', '4.0', '900']) {
      const current = await openStream(service, `/v1/stream?after=${after}`);
      await current.waitFor(1); await pause(30);
      assert.deepEqual(current.events.map((e) => e.event), after === '4.0' ? ['hello', 'block'] : ['hello'], after);
      await current.close();
    }
  });
  // Too much missed: the reader is told which heights to read from the lists, and nothing is replayed.
  await lab(async ({ service }) => {
    seed(service, Array.from({ length: 300 }, (_, b) => [signedAction(3, { to: '8', amount: '1' }, { nonce: String(b + 1) })]));
    const far = await openStream(service, '/v1/stream?after=10');
    await far.waitFor(2);
    assert.deepEqual(far.events.map((e) => e.event), ['hello', 'gap']);
    assert.deepEqual([far.events[1].data.from_height, far.events[1].data.to_height], ['11', '300']);
    await far.close();
    const near = await openStream(service, '/v1/stream?after=290&account=8');
    await near.waitFor(21);
    assert.deepEqual(near.events.slice(1).map((e) => e.id), Array.from({ length: 10 }, (_, i) => [`${291 + i}.0`, `${291 + i}`]).flat());
    await near.close();
  });
  // Streams are bounded, in all and per client.
  await lab(async ({ service }) => {
    const open = [await openStream(service, '/v1/stream'), await openStream(service, '/v1/stream')];
    const refused = await openStream(service, '/v1/stream');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'too_many_streams']);
    await open[0].close();
    for (let i = 0; i < 200 && (await call(service, '/v1/health')).body.streams > 1; i++) await pause(5);
    const next = await openStream(service, '/v1/stream');
    assert.equal(next.status, 200);
    await next.close(); await open[1].close();
  }, { maxStreams: 2 });
});

test('a registration that carries a set of keys (kind 45) is named, listed in its block as sent by nobody, counted, and pays nothing', async () => {
  // The payload of the registration the engine accepted (protected-registration.fixture.json), signed for this network.
  const engine = JSON.parse(await readFile(new URL('./protected-registration.fixture.json', import.meta.url), 'utf8'));
  const payload = { name: engine.name, salt: engine.salt, security: engine.security };
  await lab(async ({ service }) => {
    const transfer = signedAction(3, { to: '8', amount: '5' }), registration = signedAction(45, payload, { from: SDK.MAX_U64, nonce: '0', publicKey: engine.seeds[0].public_key });
    seed(service, [[transfer, registration]]);
    const items = (await call(service, '/v1/blocks/1/actions')).body.items;
    assert.deepEqual(items.map((a) => [a.kind, a.kind_name, a.opaque, a.sender, a.nonce, a.recipient, a.amount, a.transfers, a.fee_rule, a.fee_micros]),
      [[3, 'transfer', false, '5', '1', '8', '5', true, 'network_fee', null], [45, 'register_protected', false, null, '0', null, null, false, 'none', '0']]);
    // The block counts both actions and one payment.
    assert.deepEqual([(await call(service, '/v1/blocks/1')).body.block.tx_count, (await call(service, '/v1/blocks/1')).body.block.payment_count], [2, 1]);
    // In detail: its name, its key and its whole payload, the set of keys and the policy included.
    const detail = (await call(service, `/v1/actions/${sha(registration).toString('hex').toUpperCase()}`)).body.action;
    assert.deepEqual([detail.kind_name, detail.sender, detail.public_key, detail.payload], ['register_protected', null, engine.seeds[0].public_key, payload]);
  });
});

test('an account\'s state comes with the clock its security row is on: on a network whose waits survive a stop, the chain\'s time less its stops', async () => {
  const H = 3600000000n, GENESIS = 1000000000000n, row = { account: '7', version: '1', frozen_until_elapsed_micros: String(2n * H), pending_payments: [], pending_limit: null, pending_root: null };
  await lab(async ({ service, state }) => {
    let config = { waits_survive_stops: true }, stopped = String(9n * H);
    state.readState = async (selection) => ({ verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: NETWORK, height: '3', time_micros: String(GENESIS + 10n * H), genesis: { genesis_time_micros: String(GENESIS) }, config, ...(stopped === undefined ? {} : { stopped_micros: stopped }),
      accounts: [ACCOUNTS[7]], security: [row], recovery_cases: [], stake_owners: { 7: null }, candidates: { 7: null } } });
    const ruled = (await call(service, '/v1/accounts/7/state')).body;
    // Ten hours of chain, nine of them stops: the clock of the waits stands at one hour, and the freeze (two) still runs.
    assert.deepEqual(ruled.security_clock, { waits_survive_stops: true, stopped_micros: String(9n * H), now_elapsed_micros: String(H) });
    assert.equal(ruled.security.frozen_until_elapsed_micros, String(2n * H));
    // Without the setting, the clock is the chain's time, as it always was.
    config = {}; stopped = undefined;
    state.clock += 1001; // past the second for which the service shares one read of a state
    assert.deepEqual((await call(service, '/v1/accounts/7/state')).body.security_clock, { waits_survive_stops: false, stopped_micros: '0', now_elapsed_micros: String(10n * H) });
  });
});

test('the OpenAPI description and the routes agree', async () => {
  const description = JSON.parse(await readFile(new URL('./api/openapi.json', import.meta.url), 'utf8'));
  assert.match(description.openapi, /^3\.1\./);
  // The names of kinds it lists are the SDK's, every one of them, in its order: `register_protected` (45) among them.
  assert.deepEqual(description.components.schemas.KindName.enum, [...Object.keys(SDK.KINDS), null]);
  assert.ok(description.components.schemas.KindName.enum.includes('register_protected'));
  // Every route is described and nothing else is.
  const described = Object.entries(description.paths).flatMap(([route, methods]) => Object.keys(methods).map((method) => `${method.toUpperCase()} ${route}`));
  assert.deepEqual([...described].sort(), ROUTES.map((route) => `${route.method} ${route.path}`).sort());
  const resolve = (node) => (node.$ref ? node.$ref.replace(/^#\//, '').split('/').reduce((at, key) => at?.[key], description) : node);
  for (const route of ROUTES) {
    const operation = description.paths[route.path][route.method.toLowerCase()];
    assert(operation.operationId && operation.summary, route.path);
    // The same path and query parameters, by name.
    const parameters = (operation.parameters || []).map(resolve);
    assert(parameters.every(Boolean), route.path);
    assert.deepEqual(parameters.filter((p) => p.in === 'path').map((p) => p.name), [...route.path.matchAll(/\{([a-z]+)\}/g)].map((m) => m[1]), route.path);
    assert(parameters.filter((p) => p.in === 'path').every((p) => p.required === true));
    assert.deepEqual(parameters.filter((p) => p.in === 'query').map((p) => p.name).sort(), Object.keys(route.query).sort(), route.path);
    assert(parameters.every((p) => p.schema?.pattern || p.schema?.enum), `${route.path}: every parameter states its accepted form`);
    // Every route can be rate limited; every route with parameters can refuse them.
    assert(operation.responses['429'], route.path);
    if (parameters.length || route.method === 'POST') assert(operation.responses['400'], route.path);
    assert.equal(Boolean(operation.requestBody), route.method === 'POST');
  }
  // Every reference in the file leads somewhere.
  const walk = (node) => { if (!node || typeof node !== 'object') return; if (typeof node.$ref === 'string') assert(resolve(node), node.$ref); for (const value of Object.values(node)) walk(value); };
  walk(description);
  // The accepted forms in the description are the ones the server applies.
  await lab(async ({ service }) => {
    await indexAll(service);
    assert.deepEqual((await call(service, '/v1/openapi.json')).body, description);
    const samples = { height: ['2', '0', '01'], hash: [hashOf('2', 0), 'abc'], id: ['1', '01', 'alice'], account: ['1', 'payer', '@payer', 'A', 'x'], limit: ['1', '200', '0', '201'], order: ['asc', 'down'], cursor: ['2.0', '2', 'x'], reference: ['ab'.repeat(32), 'AB'.repeat(32)], from: ['7', '07'], after: ['2', '2.0', '0'] };
    for (const route of ROUTES.filter((r) => r.method === 'GET' && r.path !== '/v1/stream')) {
      const operation = description.paths[route.path].get;
      for (const parameter of (operation.parameters || []).map(resolve)) for (const sample of samples[parameter.name]) {
        const fits = parameter.schema.enum ? parameter.schema.enum.includes(sample) : new RegExp(parameter.schema.pattern).test(sample);
        const filled = route.path.replace(/\{([a-z]+)\}/g, (_, name) => (parameter.in === 'path' && name === parameter.name ? sample : { height: '2', hash: hashOf('2', 0), id: '1', account: '1' }[name]));
        const answer = await call(service, parameter.in === 'query' ? `${filled}?${parameter.name}=${sample}` : filled);
        if (route.path === '/v1/blocks' && parameter.name === 'cursor') continue; // a height here, described in the route itself
        assert.equal(answer.status !== 400, fits, `${route.path} ${parameter.name}=${sample} answered ${answer.status}`);
      }
    }
  }, { rateLimit: { perSecond: 1000, burst: 10000 } });
});

test('the start script checks its config strictly and runs one instance per data directory', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-api-watch-start-'));
  const good = { rpc_url: 'http://127.0.0.1:26657/', trust: fixture.trust, data_directory: directory };
  try {
    const filled = validateConfig(good);
    assert.deepEqual({ ...filled, trust: undefined, data_directory: undefined }, { rpc_url: 'http://127.0.0.1:26657/', trust: undefined, data_directory: undefined, start_height: 1, host: '127.0.0.1', port: 8930, hosts: [], cors_origins: [],
      rate_limit: { per_second: 20, burst: 60 }, trusted_proxies: [], webhooks: [], max_lag_seconds: 120, rpc_timeout_seconds: 10, max_streams: 100, max_stream_seconds: 900, reserved_stream_clients: [] });
    // The public name is written as clients send it: with or without a port.
    for (const hosts of [['api.example'], ['api.example:443'], ['[2001:db8::1]:8443'], ['a.b-c.example', 'localhost:9000']]) assert.doesNotThrow(() => validateConfig({ ...good, hosts }));
    for (const hosts of [['api.example:'], ['-api.example'], ['api.example/path'], ['https://api.example'], ['api example'], [':443'], 'api.example']) assert.throws(() => validateConfig({ ...good, hosts }), /hosts lists/);
    for (const extra of [{ webhook_max_age_seconds: 60 }, { max_stream_seconds: 5 }, { reserved_stream_clients: ['office.example'] }, { reserved_stream_clients: '192.0.2.1' }]) assert.throws(() => validateConfig({ ...good, ...extra }));
    assert.doesNotThrow(() => validateConfig({ ...good, max_stream_seconds: 60, reserved_stream_clients: ['192.0.2.1', '2001:db8::7'] }));
    // A proxy's own address cannot be reserved: without X-Forwarded-For every caller behind it would be.
    for (const [proxy, client] of [['10.0.0.2', '10.0.0.2'], ['::ffff:10.0.0.2', '10.0.0.2'], ['2001:db8::1', '2001:DB8:0:0::1'], ['2001:db8::1', '2001:db8::99']])
      assert.throws(() => validateConfig({ ...good, trusted_proxies: [proxy], reserved_stream_clients: [client] }), /both in trusted_proxies and in reserved_stream_clients/);
    assert.doesNotThrow(() => validateConfig({ ...good, trusted_proxies: ['10.0.0.2'], reserved_stream_clients: ['10.0.0.3'] }));
    assert.doesNotThrow(() => validateConfig({ ...good, rpc_url: 'https://rpc.example/', cors_origins: ['*'], trusted_proxies: ['10.0.0.1', '::1'], hosts: ['api.example:443'], webhooks: [{ account: '5', url: 'https://hooks.example/x', secret: 'x'.repeat(16) }], rate_limit: { per_second: 5 } }));
    const example = JSON.parse(await readFile(new URL('../deploy/api/config.example.json', import.meta.url), 'utf8'));
    assert.doesNotThrow(() => validateConfig({ ...example, trust: fixture.trust }));
    const SECRET = 'super-secret-value-0123456789';
    const bad = {
      'not an object': [], 'unknown key': { ...good, webhook: [] }, 'rpc with password': { ...good, rpc_url: `http://user:${SECRET}@127.0.0.1:26657/` }, 'plain http to another machine': { ...good, rpc_url: 'http://rpc.example:26657/' },
      'rpc with a path': { ...good, rpc_url: 'http://127.0.0.1:26657/rpc' }, 'rpc that is no url': { ...good, rpc_url: SECRET }, 'no trust': { ...good, trust: undefined }, 'trust of another application': { ...good, trust: { ...fixture.trust, app_version: '3' } },
      'relative data directory': { ...good, data_directory: 'data' }, 'start height zero': { ...good, start_height: 0 }, 'start height as text': { ...good, start_height: '5' }, 'port too low': { ...good, port: 80 },
      'origin with a path': { ...good, cors_origins: ['https://explorer.example/app'] }, 'star among others': { ...good, cors_origins: ['*', 'https://explorer.example'] }, 'origin without scheme': { ...good, cors_origins: ['explorer.example'] },
      'proxy by name': { ...good, trusted_proxies: ['proxy.internal'] }, 'unknown rate setting': { ...good, rate_limit: { per_minute: 5 } }, 'rate of zero': { ...good, rate_limit: { per_second: 0 } }, 'burst below rate': { ...good, rate_limit: { per_second: 50, burst: 10 } },
      'webhook without secret': { ...good, webhooks: [{ account: '5', url: 'https://hooks.example/x' }] }, 'webhook with short secret': { ...good, webhooks: [{ account: '5', url: `https://hooks.example/${SECRET}`, secret: 'short' }] },
      'webhook over plain http': { ...good, webhooks: [{ account: '5', url: `http://hooks.example/${SECRET}`, secret: SECRET }] }, 'webhook with extra key': { ...good, webhooks: [{ account: '5', url: 'https://hooks.example/x', secret: SECRET, events: ['all'] }] },
      'webhook account as number': { ...good, webhooks: [{ account: 5, url: 'https://hooks.example/x', secret: SECRET }] }, 'webhook listed twice': { ...good, webhooks: [{ account: '5', url: 'https://hooks.example/x', secret: SECRET }, { account: '5', url: 'https://hooks.example/x', secret: `${SECRET}2` }] },
      'host list in upper case': { ...good, hosts: ['API.example:443'] }, 'lag too small': { ...good, max_lag_seconds: 1 },
    };
    for (const [name, config] of Object.entries(bad)) assert.throws(() => validateConfig(config), (error) => !error.message.includes(SECRET), name);

    // One instance per data directory; the log is JSON lines without the secret, the path or the query of a webhook.
    const lines = [], state = { tip: 4, calls: [], broadcast: () => ({}) };
    const log = (level, message, fields = {}) => lines.push(JSON.stringify({ at: new Date().toISOString(), level, message, ...fields }));
    const config = { ...good, port: 18930 + Math.floor(Math.random() * 2000), webhooks: [{ account: '1', url: `https://hooks.example/path-${SECRET}?token=${SECRET}`, secret: SECRET }] };
    const inject = { rpc: fakeRpc(state), log, now: () => fixture.now_ms, pollMs: 5, webhookFetcher: async () => new Response('', { status: 200 }), readState: async () => { throw new Error('no state here'); } };
    const running = await start(config, inject);
    try {
      // The lock is the watch's; its message is reworded, and the directory (which has "watch" in its name here) is not.
      await assert.rejects(start({ ...config, port: config.port + 1 }, inject), (error) => /^(This process already serves|Another API instance \(process \d+\) uses) /.test(error.message) && error.message.endsWith(directory));
      for (let i = 0; i < 400 && running.service.store.high() !== 4; i++) await pause(5);
      assert.equal(running.service.store.high(), 4, 'the started service indexes by itself');
      const status = await call(running, '/v1/status');
      assert.deepEqual([status.status, status.body.indexer.indexed_height, status.body.indexer.running], [200, '4', true]);
      for (const line of lines) { assert(!line.includes(SECRET), line); assert.equal(typeof JSON.parse(line).message, 'string'); }
      assert(lines.some((line) => JSON.parse(line).message === 'time api started' && JSON.parse(line).webhooks[0] === 'https://hooks.example'));
    } finally { await running.close(); }
    // After a clean stop the directory is free again, and the index is still there.
    const again = await start(config, inject);
    try { assert.equal(again.service.store.high(), 4); } finally { await again.close(); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('a stream has a longest life, gives way when places run out, and reserved addresses always get one', async () => {
  // Lifetime: after it, the server ends the stream with `bye`; the reader reconnects with its last id and misses nothing.
  await lab(async ({ service, state }) => {
    state.tip = 3;
    await indexAll(service, 3);
    const first = await openStream(service, '/v1/stream');
    await first.waitFor(1);
    state.clock += 59 * 1000; service.tendStreams();
    await pause(30);
    assert.deepEqual(first.events.map((e) => e.event), ['hello']);
    state.clock += 2 * 1000; service.tendStreams();
    await first.waitFor(2);
    assert.deepEqual([first.events[1].event, first.events[1].data.reason], ['bye', 'lifetime']);
    for (let i = 0; i < 200 && (await call(service, '/v1/health')).body.streams > 0; i++) await pause(5);
    assert.equal((await call(service, '/v1/health')).body.streams, 0);
    state.tip = 4;
    await indexAll(service, 4);
    const second = await openStream(service, '/v1/stream', { 'Last-Event-ID': '3' });
    await second.waitFor(3);
    assert.deepEqual(second.events.map((e) => [e.event, e.id]), [['hello', null], ['payment', '4.0'], ['block', '4']]);
    await second.close(); await first.close();
  }, { maxStreamSeconds: 60 });
  // Places: four clients hold all six. A newcomer gets the oldest stream of the client that holds most.
  await lab(async ({ service, state }) => {
    const as = (client, route = '/v1/stream') => openStream(service, route, { 'X-Forwarded-For': client });
    const held = [];
    for (const client of ['198.51.100.1', '198.51.100.1', '198.51.100.1', '198.51.100.2', '198.51.100.2', '198.51.100.3']) held.push(await as(client));
    for (const stream of held) await stream.waitFor(1);
    // A stream is not put out in its first seconds: a newcomer is refused until they have passed.
    const early = await as('203.0.113.9');
    assert.deepEqual([early.status, early.body.error.code], [503, 'too_many_streams']);
    state.clock += STREAM_MIN_AGE_MS;
    const newcomer = await as('203.0.113.9');
    assert.equal(newcomer.status, 200);
    await held[0].waitFor(2);
    assert.deepEqual([held[0].events[1].event, held[0].events[1].data.reason], ['bye', 'evicted']);
    await pause(30);
    assert(held.slice(1).every((stream) => stream.events.length === 1), 'only the oldest stream of the busiest client was ended');
    assert.equal((await call(service, '/v1/health')).body.streams, 6);
    // Now two clients hold two each. One of them asking for a third is refused; so is a fourth of anyone (three per client).
    const refused = await as('198.51.100.2');
    assert.deepEqual([refused.status, refused.body.error.code], [503, 'too_many_streams']);
    // Someone with one stream is no busier than the rest... but still below the busiest: it gets a place too.
    const another = await as('203.0.113.9');
    assert.equal(another.status, 200);
    // A reserved address is never counted against the places and never put out.
    const reserved = [await as('192.0.2.77'), await as('192.0.2.77'), await as('192.0.2.77')];
    assert.deepEqual(reserved.map((stream) => stream.status), [200, 200, 200]);
    assert.equal((await as('192.0.2.77')).status, 503, 'the limit per client holds for it as well');
    assert.equal((await call(service, '/v1/health')).body.streams, 9);
    for (const stream of [...held, newcomer, another, ...reserved]) await stream.close?.();
  }, { maxStreams: 6, maxStreamsPerClient: 3, trustedProxies: ['127.0.0.1'], reservedStreamClients: ['192.0.2.77'] });
});

test('a reconnecting stream reads only what it sends, and at most a bounded number of payments', async () => {
  await lab(async ({ service }) => {
    // 40 blocks: in each, 100 payments between other accounts, one to account 8 and two actions that are no payment.
    let nonce = 0;
    seed(service, Array.from({ length: 40 }, () => [
      ...Array.from({ length: 100 }, () => signedAction(3, { to: '9', amount: '1' }, { nonce: String(++nonce) })),
      signedAction(3, { to: '8', amount: '2' }, { from: '6', nonce: String(nonce) }),
      signedAction(75, { type: 'request', to: '8', amount: '5' }, { nonce: String(++nonce) }), signedAction(16, {}, { nonce: String(++nonce) }),
    ]));
    // Count what the replay reads from the index.
    let rows = 0, scans = 0;
    const span = service.store.paymentsSpan, scan = service.store.blockActions;
    service.store.paymentsSpan = (...args) => { const found = span(...args); rows += found.length; return found; };
    service.store.blockActions = (...args) => { scans += 1; return scan(...args); };
    // A stream for one account's deposits reads its 39 payments, not the 4,000 others.
    const mine = await openStream(service, '/v1/stream?account=8&after=1');
    await mine.waitFor(1 + 39 * 2);
    assert.deepEqual(mine.events.slice(1, 5).map((e) => [e.event, e.id]), [['payment', '2.100'], ['block', '2'], ['payment', '3.100'], ['block', '3']]);
    assert.deepEqual([rows, scans], [39, 0]);
    await mine.close();
    // An account without payments reads none.
    rows = 0;
    const none = await openStream(service, '/v1/stream?account=999&after=1');
    await none.waitFor(40);
    assert.deepEqual([none.events.filter((e) => e.event === 'block').length, rows, scans], [39, 0, 0]);
    await none.close();
    // Every payment: the stream stops at the bound and names the block to read the lists from.
    rows = 0;
    const all = await openStream(service, '/v1/stream?after=1');
    for (let i = 0; i < 400 && all.events.at(-1)?.event !== 'gap'; i++) await pause(5);
    const sent = all.events.filter((e) => e.event === 'payment').length, gap = all.events.at(-1);
    assert.equal(gap.event, 'gap');
    assert(sent <= REPLAY_PAYMENTS && rows <= REPLAY_PAYMENTS + 250, `${sent} sent, ${rows} read`);
    assert.deepEqual([gap.data.from_height, gap.data.to_height], [String(2 + Math.floor(sent / 101)), '40']);
    assert.equal(scans, 0);
    await all.close();
    service.store.paymentsSpan = span; service.store.blockActions = scan;
  });
});

test('the state reader is moved on by a timer, and a request names one host and a plain path', async () => {
  // The state reader's light client moves only when a state is read. Without account requests
  // it would stand still until its checkpoint expires, so the service reads a state on a timer.
  let reads = 0;
  await lab(async ({ service }) => {
    for (let i = 0; i < 200 && reads < 4; i++) await pause(10);
    assert(reads >= 4, `${reads} state reads without any account request`);
    // Raw requests: two Host headers, a fragment that would hide a filter, another host in the address.
    const { port } = new URL(service.url);
    const raw = (text) => new Promise((resolve) => {
      const socket = net.connect(Number(port), '127.0.0.1', () => socket.write(text)); let answer = '';
      socket.on('data', (chunk) => { answer += chunk; }); socket.on('error', () => resolve(answer));
      setTimeout(() => { socket.destroy(); resolve(answer); }, 150);
    });
    const host = `Host: 127.0.0.1:${port}\r\n`;
    const refused = {
      [`GET /v1/status HTTP/1.1\r\n${host}Host: evil.example\r\n\r\n`]: 'invalid_request',
      [`GET /v1/accounts/5/payments#?reference=zz HTTP/1.1\r\n${host}\r\n`]: 'invalid_url',
      [`GET http://evil.example/v1/status HTTP/1.1\r\n${host}\r\n`]: 'invalid_url',
      [`GET //evil.example/v1/status HTTP/1.1\r\n${host}\r\n`]: 'invalid_url',
      [`GET /v1/accounts/5/../6/payments HTTP/1.1\r\n${host}\r\n`]: 'invalid_url',
      [`GET /v1${String.fromCharCode(92)}status HTTP/1.1\r\n${host}\r\n`]: 'invalid_url', // a backslash
    };
    for (const [request, code] of Object.entries(refused)) {
      const answer = await raw(request);
      assert.match(answer, /^HTTP\/1\.1 400 /, request.split('\r\n')[0]);
      assert(answer.includes(`"code":"${code}"`), `${request.split('\r\n')[0]} -> ${answer.split('\r\n\r\n')[1]}`);
    }
    assert.match(await raw(`GET /v1/status?x=%23 HTTP/1.1\r\n${host}\r\n`), /"code":"unknown_parameter"/, 'an encoded # is an ordinary character');
  }, { autoStart: true, stateRefreshMs: 20, readState: async (selection) => { reads += 1; return { verified: true, requested: selection, state: { network_id: NETWORK, height: '3', time_micros: '1', accounts: [], config: {} } }; } });
});

test('a webhook starts at the height the chain had when it was configured, and nothing after that is left out', async () => {
  const hooks = [];
  const webhookFetcher = async (_url, init) => { hooks.push(JSON.parse(init.body)); return new Response('', { status: 200 }); };
  const shop = { account: '1', url: 'https://hooks.example/shop', secret: 'x'.repeat(16) }, books = { account: '1', url: 'https://hooks.example/books', secret: 'y'.repeat(16) };
  await lab(async ({ service, state, directory }) => {
    // A new index on a chain that is at block 3: the two payments of block 2 are history. They are
    // indexed, not sent, counted, and said in the log once.
    state.tip = 3;
    assert.equal((await call(service, '/v1/health')).body.webhooks.awaiting_start, 1);
    await indexAll(service, 3);
    service.webhooks.kick(); await service.webhooks.settled();
    assert.equal((await call(service, '/v1/accounts/1/payments')).body.items.length, 2);
    assert.deepEqual([hooks.length, (await call(service, '/v1/health')).body.webhooks.skipped_history, (await call(service, '/v1/health')).body.webhooks.awaiting_start, (await call(service, '/v1/health')).body.webhooks.queued], [0, 2, 0, 0]);
    assert.equal(state.logs.filter((line) => /indexed without a webhook/.test(line.message) && line.level === 'warn').length, 1);
    assert.deepEqual(state.logs.filter((line) => /webhooks start at this height/.test(line.message)).map((line) => [line.targets, line.from_height]), [[1, 3]]);

    // The service is stopped for 30 hours; block 4 was made a second after it stopped. On the way
    // back a second webhook is configured. The old one is told of block 4, however late; the new
    // one starts now, at block 4, the height of the chain when it was added.
    await service.close();
    state.clock += 30 * 3600 * 1000; state.tip = 4;
    const again = await createApiService({ trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, now: () => state.clock, webhooks: [shop, books], webhookFetcher,
      log: (level, message, fields) => state.logs.push({ level, message, ...fields }) });
    try {
      await indexAll(again, 4);
      again.webhooks.kick(); await again.webhooks.settled();
      for (let i = 0; i < 200 && hooks.length < 2; i++) await pause(5);
      assert.deepEqual(hooks.map((event) => [event.id, event.height]), [[`payment:${hashOf('4', 0)}`, '4'], [`payment:${hashOf('4', 0)}`, '4']]);
      assert.deepEqual((await call(again, '/v1/health')).body.webhooks, { targets: 2, queued: 0, dead_letters: 0, failing_targets: 0, refusing_targets: 0, skipped_history: 2, awaiting_start: 0 });
    } finally { await again.close(); }
  }, { webhooks: [shop], webhookFetcher });
  // A webhook configured only after its block was indexed starts later: what the first run indexed is history to it.
  await lab(async ({ service, state, directory }) => {
    await indexAll(service, 4);
    await service.close();
    hooks.length = 0;
    const again = await createApiService({ trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, now: () => state.clock, webhooks: [shop], webhookFetcher });
    try {
      await again.indexer.step();
      again.webhooks.kick(); await again.webhooks.settled();
      assert.deepEqual([hooks.length, (await call(again, '/v1/health')).body.webhooks.awaiting_start], [0, 1], 'nothing new on the chain: the start is not known yet, and nothing old is sent');
    } finally { await again.close(); }
  });
});

test('stream places: holders are counted by a wide IPv6 prefix, and a reader of deposits is not put out for a reader of everything', async () => {
  assert.deepEqual(['203.0.113.9', '2001:db8:0:1::/64', '2001:db8:0:ff::/64', '2001:db8:0:100::/64', '2001:db8:0:abcd::/64', 'unknown'].map(holderKey), ['203.0.113.9', '2001:db8:0:0::/56', '2001:db8:0:0::/56', '2001:db8:0:100::/56', '2001:db8:0:ab00::/56', 'unknown']);
  await lab(async ({ service, state }) => {
    const as = (client, route = '/v1/stream') => openStream(service, route, { 'X-Forwarded-For': client });
    // One /56 is one holder, whatever /64 its requests come from: three streams, then no more.
    const subscriber = [await as('2001:db8:7:1::1'), await as('2001:db8:7:2::1'), await as('2001:db8:7:ff::9')];
    assert.deepEqual(subscriber.map((s) => s.status), [200, 200, 200]);
    assert.equal((await as('2001:db8:7:80::1')).status, 503);
    assert.equal((await as('2001:db8:7:100::1')).status, 200, 'the next /56 is another holder');
  }, { maxStreams: 50, maxStreamsPerClient: 3, trustedProxies: ['127.0.0.1'] });
  await lab(async ({ service, state }) => {
    const as = (client, route = '/v1/stream') => openStream(service, route, { 'X-Forwarded-For': client });
    // The exchange (not reserved) reads its deposits and all blocks; two others hold one stream each. Every place is taken.
    const deposits = await as('203.0.113.9', '/v1/stream?account=5'), everything = await as('203.0.113.9');
    const others = [await as('198.51.100.1'), await as('198.51.100.2')];
    for (const stream of [deposits, everything, ...others]) await stream.waitFor(1);
    state.clock += STREAM_MIN_AGE_MS;
    // A newcomer that follows no account gets the exchange's unfiltered stream, never the one that follows its deposits.
    const first = await as('198.51.100.3');
    assert.equal(first.status, 200);
    await everything.waitFor(2);
    assert.deepEqual([everything.events[1].event, everything.events[1].data.reason], ['bye', 'evicted']);
    // Now everyone holds one. Further newcomers, with or without an account of their own to follow,
    // get the place of the oldest stream that follows none; the deposits stream stays.
    state.clock += STREAM_MIN_AGE_MS;
    const second = await as('198.51.100.4');
    assert.equal(second.status, 200);
    await others[0].waitFor(2);
    state.clock += STREAM_MIN_AGE_MS;
    const third = await as('198.51.100.5', '/v1/stream?account=9');
    assert.equal(third.status, 200);
    await others[1].waitFor(2);
    assert.deepEqual([others[0].events[1].data.reason, others[1].events[1].data.reason], ['evicted', 'evicted']);
    await pause(30);
    assert.deepEqual(deposits.events.map((e) => e.event), ['hello']);
    for (const stream of [deposits, everything, first, second, third, ...others]) await stream.close?.();
  }, { maxStreams: 4, maxStreamsPerClient: 3, trustedProxies: ['127.0.0.1'] });
  // The same address as trusted proxy and reserved client is refused, also when the service is built directly.
  await assert.rejects(createApiService({ trust: fixture.trust, rpc: async () => ({}), verifier, dataFile: ':memory:', port: 0, autoStart: false, trustedProxies: ['10.0.0.2'], reservedStreamClients: ['10.0.0.2'] }), /both a trusted proxy and a reserved stream client/);
});

test('an account answer says when the index holds an action of the account that the proven state does not count yet', async () => {
  await lab(async ({ service, state }) => {
    await indexAll(service);
    // The fixture chain: account 7 sent nonce 1 and 2 in block 2 and nonce 3 in block 4. A proof of height h counts the blocks up to h.
    const proves = (height, nonce, account = { ...ACCOUNTS[7], nonce }) => { state.readState = async (selection) => ({ verified: true, requested: selection, proof: { height, entries: [] }, state: { network_id: NETWORK, height, time_micros: '1000003000000', accounts: [account], config: {} } }); };
    const third = { hash: hashOf('4', 0), height: '4', nonce: '3', kind: 3 };
    // The proof is from height 3 and shows nonce 2. The index holds block 4, with the account's action of nonce 3:
    // the proven nonce is used already, and the answer says so, as the index's word.
    proves('3', '2');
    let body = (await call(service, '/v1/accounts/7')).body;
    assert.deepEqual([body.account.nonce, body.state_height, body.indexed_height, body.indexed.state_is_behind, body.indexed.newer_actions, body.indexed.last_sent], ['2', '3', '4', true, [third], third]);
    assert.deepEqual([body.source, body.indexed.source, body.indexed.proven], ['state_proof', 'index', false]);
    // A block later the proof counts that action: nothing is newer, and the last action is the one that carries the proven nonce.
    proves('4', '3');
    body = (await call(service, '/v1/accounts/7')).body;
    assert.deepEqual([body.indexed.state_is_behind, body.indexed.newer_actions, body.indexed.last_sent], [false, [], third]);
    // A proof from before every action: all of them are newer, in chain order.
    proves('1', '0');
    body = (await call(service, '/v1/accounts/7')).body;
    assert.deepEqual([body.indexed.state_is_behind, body.indexed.newer_actions.map((a) => [a.nonce, a.height, a.hash]), body.indexed.last_sent], [true, [['1', '2', hashOf('2', 0)], ['2', '2', hashOf('2', 1)], ['3', '4', hashOf('4', 0)]], third]);
    // An account that has sent nothing: what it received in the newer block is not an action of its own.
    proves('3', '0', ACCOUNTS[1]);
    body = (await call(service, '/v1/accounts/1')).body;
    assert.deepEqual([body.indexed.state_is_behind, body.indexed.newer_actions, body.indexed.last_sent, body.indexed.totals.payments_received], [false, [], null, 3]);
  });
});

test('an account answer lists a bounded number of newer actions, and its last_sent is the newest of all of them', async () => {
  await lab(async ({ service, state }) => {
    // Block 1 holds nothing of account 5; block 2 holds forty of its actions, nonces 1 to 40. The proof is of height 1.
    seed(service, [[signedAction(3, { to: '1', amount: '1' }, { from: '9', nonce: '1' })], Array.from({ length: 40 }, (_, i) => signedAction(3, { to: '1', amount: '1' }, { nonce: String(i + 1) }))]);
    state.readState = async (selection) => ({ verified: true, requested: selection, proof: { height: '1', entries: [] }, state: { network_id: NETWORK, height: '1', time_micros: '1000003000000', accounts: [{ id: '5', name: 'busy', balance: '0', nonce: '0', auth_epoch: '0', devices: [] }], config: {} } });
    const body = (await call(service, '/v1/accounts/5')).body;
    assert.deepEqual([body.indexed.state_is_behind, body.indexed.newer_actions.length, body.indexed.newer_actions[0].nonce, body.indexed.newer_actions.at(-1).nonce], [true, NEWER_ACTIONS, '1', String(NEWER_ACTIONS)]);
    // Before, last_sent was the last of the list: the sixteenth, with twenty-four newer ones in the index.
    assert.deepEqual([body.indexed.last_sent.nonce, body.indexed.last_sent.height], ['40', '2']);
  });
});

test('an action without a nonce in a block above the proof, and what follows a replacement of the keys there, make state_is_behind true', async () => {
  await lab(async ({ service, state }) => {
    // Account 5: nonce 1 in block 1. In block 2 a replacement of its keys (kind 73: it carries nonce 0 and uses
    // nonce 2) and then the first action of the new keys, nonce 3. No action carries the proven nonce plus one.
    const replace = signedAction(73, { op: { type: 'replace', keys: [], policy: {} }, expires_elapsed_micros: '9', approvals: [] }, { nonce: '0' }), after = signedAction(3, { to: '1', amount: '1' }, { nonce: '3', authEpoch: '1' });
    seed(service, [[signedAction(3, { to: '1', amount: '1' }, { nonce: '1' })], [replace, after]]);
    state.readState = async (selection) => ({ verified: true, requested: selection, proof: { height: '1', entries: [] }, state: { network_id: NETWORK, height: '1', time_micros: '1000003000000', accounts: [{ id: '5', name: 'exchange', balance: '0', nonce: '1', auth_epoch: '0', devices: [] }], config: {} } });
    const body = (await call(service, '/v1/accounts/5')).body, hashes = [replace, after].map((raw) => sha(raw).toString('hex').toUpperCase());
    assert.deepEqual([body.indexed.state_is_behind, body.indexed.newer_actions.map((a) => [a.kind, a.nonce, a.hash]), body.indexed.last_sent.nonce], [true, [[73, '0', hashes[0]], [3, '3', hashes[1]]], '3']);
  });
});

test('a cursor below the start of the index is refused with where the index starts; a list never begins later without a word', async () => {
  // The fixture chain pays account 1 twice in block 2 and once in block 4. A reader of deposits has read the first.
  let cursor;
  await lab(async ({ service }) => {
    await indexAll(service);
    const page = (await call(service, '/v1/accounts/1/payments?limit=1')).body;
    assert.deepEqual([page.items.map((item) => item.height), page.has_more, page.next_cursor], [['2'], true, '2.0']);
    cursor = page.next_cursor;
    assert.deepEqual((await call(service, `/v1/accounts/1/payments?cursor=${cursor}`)).body.items.map((item) => [item.height, item.index]), [['2', 1], ['4', 0]]);
  });
  // The index is rebuilt with start_height 3 (a new data directory; a node restored from a snapshot has no earlier block).
  await lab(async ({ service }) => {
    await indexAll(service);
    // Before, this answered 200 with the payment of block 4 alone: the second payment of block 2 was skipped for good.
    for (const route of [`/v1/accounts/1/payments?cursor=${cursor}`, `/v1/accounts/1/payments?cursor=${cursor}&from=7`, `/v1/accounts/1/activity?order=asc&cursor=${cursor}`, `/v1/accounts/1/activity?cursor=${cursor}`, '/v1/blocks?order=asc&cursor=1', '/v1/blocks?cursor=1']) {
      const refused = await call(service, route);
      assert.deepEqual([refused.status, refused.body.error.code, refused.body.index.start_height, refused.body.index.indexed_height], [409, 'cursor_below_index_start', '3', '4'], route);
      assert.match(refused.body.error.message, /^This index starts at height 3 and the cursor is at height [12]\. .*read it from an index that holds those heights, then go on here without a cursor/, route);
    }
    // Without a cursor the list begins at the start of this index, and says where that is.
    const first = (await call(service, '/v1/accounts/1/payments')).body;
    assert.deepEqual([first.items.map((item) => item.height), first.index.start_height], [['4'], '3']);
    // A cursor at or above the start is taken; for blocks, the block before the start is one too: nothing lies between.
    assert.deepEqual((await call(service, '/v1/accounts/1/payments?cursor=3.0')).body.items.map((item) => item.height), ['4']);
    assert.deepEqual((await call(service, '/v1/blocks?order=asc&cursor=2')).body.items.map((item) => item.height), ['3', '4']);
    // The stream: a reader that resumes below the start is told which heights this index does not hold, then sent what it holds.
    const resumed = await openStream(service, '/v1/stream?account=1&after=1');
    await resumed.waitFor(5);
    assert.deepEqual(resumed.events.map((e) => [e.event, e.id ?? null]), [['hello', null], ['gap', null], ['block', '3'], ['payment', '4.0'], ['block', '4']]);
    assert.deepEqual([resumed.events[1].data.from_height, resumed.events[1].data.to_height], ['2', '2']);
    assert.match(resumed.events[1].data.message, /^This index starts at height 3 and does not hold these heights/);
    await resumed.close();
    // A position inside the index gets no such event.
    const inside = await openStream(service, '/v1/stream?account=1&after=3');
    await inside.waitFor(3);
    assert.deepEqual(inside.events.map((e) => e.event), ['hello', 'payment', 'block']);
    await inside.close();
  }, { startHeight: 3 });
});
