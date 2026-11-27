// The indexer against real signed blocks (verifier-v4/fixtures/fast-receipt.json: four blocks of
// a four-validator chain, two transfers in block 2 and one in block 4) served by a fake CometBFT
// RPC, with the installed WASM verifier. What the RPC serves is changed case by case to check
// that nothing it makes up is ever indexed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm, readdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { createLightClient } from './light-client.mjs';
import { fetchLightBlock } from './certified-view.mjs';
import { openIndex, createIndexer, createRpc, headerHash, merkleRoot, merkleProof, successfulResultsRoot, describeAction, parseBlockTime, encodeCursor, decodeCursor, IndexerError, KIND_NAMES } from './indexer.mjs';

const SDK = globalThis.TimeSDK;
const fixtures = new URL('../verifier-v4/fixtures/', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('fast-receipt.json', fixtures), 'utf8'));
// A registration that carries a set of keys (kind 45), as the engine accepted it.
const protectedFixture = JSON.parse(await readFile(new URL('./protected-registration.fixture.json', import.meta.url), 'utf8'));
const NETWORK = fixture.trust.network_id, CHAIN = fixture.trust.chain_id;
const now = () => fixture.now_ms;
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const hashOf = (height, index) => sha(Buffer.from(fixture.txs[height][index], 'base64')).toString('hex').toUpperCase();

/// A node at height `state.tip`. `state.change(method, parameters, answer)` may alter any answer.
function fakeRpc(state) {
  const block = (h) => { const b = fixture.blocks[Number(h) - 1]; if (!b || Number(h) > state.tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    state.calls.push(method);
    if (state.down) throw new IndexerError('RPC_UNAVAILABLE', 'The RPC could not be reached');
    let answer;
    if (method === '/status') answer = { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(state.tip) } };
    else if (method === '/block') answer = { block: { header: block(parameters.height).signed_header.header, data: { txs: fixture.txs[parameters.height] } } };
    else if (method === '/blockchain') {
      answer = { block_metas: [] };
      for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) answer.block_metas.push({ header: block(h).signed_header.header });
    } else if (method === '/commit') answer = { signed_header: block(parameters.height ?? state.tip).signed_header };
    else if (method === '/validators') {
      const h = Number(parameters.height);
      if (h > state.tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available');
      answer = { block_height: parameters.height, total: '4', validators: h <= fixture.blocks.length ? fixture.blocks[h - 1].validators : fixture.blocks.at(-1).next_validators };
    } else throw new IndexerError('RPC_REFUSED', 'not available on this node');
    return state.change ? state.change(method, parameters, structuredClone(answer)) : answer;
  };
}
async function lab(run, { tip = 3, trust = fixture.trust, startHeight = 1 } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-indexer-'));
  const state = { tip, calls: [], change: null, down: false }, filename = path.join(directory, 'index.sqlite');
  const stores = [];
  const open = (options = {}) => {
    const store = openIndex({ filename, networkId: NETWORK, chainId: CHAIN, startHeight, ...options });
    stores.push(store);
    return { store, indexer: createIndexer({ rpc: fakeRpc(state), trust, store, verifier, now, pollMs: 5, ...options.indexer }) };
  };
  try { await run({ state, open, filename, directory }); } finally { for (const store of stores) store.close(); await rm(directory, { recursive: true, force: true }); }
}
/// Runs rounds until the index reaches `height`.
async function indexTo(indexer, store, height) {
  for (let i = 0; i < 50 && (store.high() ?? 0) < height; i++) await indexer.step();
  assert.equal(store.high(), height);
}

test('the header hash computed here is the one validators signed, for every header of every fixture', async () => {
  const seen = new Map();
  const visit = (value) => {
    if (!value || typeof value !== 'object') return;
    if (value.header && value.commit?.block_id?.hash) seen.set(value.commit.block_id.hash.toLowerCase(), value.header);
    if (typeof value.block_hash === 'string' && value.block?.signed_header) seen.set(value.block_hash.toLowerCase(), value.block.signed_header.header);
    for (const item of Object.values(value)) visit(item);
  };
  for (const name of await readdir(fixtures)) visit(JSON.parse(await readFile(new URL(name, fixtures), 'utf8')));
  // Synthetic headers and headers of a real CometBFT 0.38 network (the live fixtures).
  assert(seen.size >= 15, `only ${seen.size} headers found`);
  assert([...seen.values()].some((header) => /^time-devnet-v4-[0-9a-f]{16}$/.test(header.chain_id)));
  for (const [hash, header] of seen) assert.equal(headerHash(header).toString('hex'), hash, `height ${header.height} of ${header.chain_id}`);

  // Every field of a header is under its hash: changing any one changes the hash.
  const real = [...seen.values()].find((header) => /^time-devnet-v4-[0-9a-f]{16}$/.test(header.chain_id) && header.last_block_id?.hash);
  const original = headerHash(real).toString('hex');
  const flip = (hex) => (hex[0] === 'A' ? 'B' : 'A') + hex.slice(1);
  const changes = {
    'version.block': (h) => { h.version.block = '12'; }, 'version.app': (h) => { h.version.app = '5'; }, chain_id: (h) => { h.chain_id += 'x'; },
    height: (h) => { h.height = String(Number(h.height) + 1); }, time: (h) => { h.time = h.time.replace(/\d(?=Z$)/, (d) => String((Number(d) + 1) % 10)); },
    'last_block_id.hash': (h) => { h.last_block_id.hash = flip(h.last_block_id.hash); }, 'last_block_id.parts.hash': (h) => { h.last_block_id.parts.hash = flip(h.last_block_id.parts.hash); },
    'last_block_id.parts.total': (h) => { h.last_block_id.parts.total += 1; },
  };
  for (const name of ['last_commit_hash', 'data_hash', 'validators_hash', 'next_validators_hash', 'consensus_hash', 'app_hash', 'last_results_hash', 'evidence_hash', 'proposer_address']) changes[name] = (h) => { h[name] = flip(h[name]); };
  for (const [name, change] of Object.entries(changes)) {
    const header = structuredClone(real); change(header);
    assert.notEqual(headerHash(header).toString('hex'), original, name);
  }
  // Malformed headers are refused, never hashed loosely.
  for (const broken of [null, {}, { ...real, height: '0' }, { ...real, height: '01' }, { ...real, time: '2026-13-01T00:00:00Z' }, { ...real, time: '2026-11-09T22:18:24+01:00' }, { ...real, validators_hash: '' }, { ...real, data_hash: 'zz' }, { ...real, app_hash: 'AB' }, { ...real, chain_id: '' }])
    assert.throws(() => headerHash(broken), IndexerError);
});

test('Merkle roots and proofs follow CometBFT for every size, and the time of a block is read exactly', () => {
  // The recursive definition (RFC 6962): split at the largest power of two below the count.
  const leaf = (item) => sha(Buffer.concat([Buffer.from([0]), item])), node = (l, r) => sha(Buffer.concat([Buffer.from([1]), l, r]));
  const reference = (items) => { if (items.length === 1) return leaf(items[0]); let k = 1; while (k * 2 < items.length) k *= 2; return node(reference(items.slice(0, k)), reference(items.slice(k))); };
  for (let count = 1; count <= 33; count++) {
    const items = Array.from({ length: count }, (_, i) => sha(Buffer.from([i])));
    const root = merkleRoot(items);
    assert.deepEqual(root, reference(items), `root of ${count}`);
    for (let index = 0; index < count; index++) {
      // Recompute the root from the proof as a verifier does.
      const proof = merkleProof(items, index);
      const up = (i, total, hash, aunts) => { if (total === 1) return hash; let k = 1; while (k * 2 < total) k *= 2; const last = aunts.at(-1), rest = aunts.slice(0, -1); return i < k ? node(up(i, k, hash, rest), last) : node(last, up(i - k, total - k, hash, rest)); };
      assert.deepEqual(up(index, count, proof.leaf, proof.aunts), root, `proof ${index} of ${count}`);
    }
  }
  assert.equal(merkleRoot([]).toString('hex'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  // Block 3 of the fixture commits to the two successful results of block 2.
  assert.equal(successfulResultsRoot(2).toString('hex').toUpperCase(), fixture.blocks[2].signed_header.header.last_results_hash);
  assert.deepEqual(parseBlockTime('2026-11-09T22:18:24.8160186Z'), { seconds: 1794262704n, nanos: 816018600 });
  assert.deepEqual(parseBlockTime('1970-01-12T13:46:42Z'), { seconds: 1000002n, nanos: 0 });
  assert.deepEqual(decodeCursor(encodeCursor(12, 3)), { height: 12, index: 3, text: '12.3' });
  // A height no number holds exactly is read as the largest one, and the text is kept as given.
  assert.deepEqual(decodeCursor('9999999999999999.5'), { height: Number.MAX_SAFE_INTEGER, index: 5, text: '9999999999999999.5' });
  for (const bad of ['', '1', '0.0', '1.-1', '01.2', '1.02', '1.2.3', 'a.b', '1.1000000', null, 5]) assert.equal(decodeCursor(bad), null, String(bad));
});

test('every kind of action is described from the SDK decoder, and what it cannot decode is kept opaque', () => {
  const key = 'bb'.repeat(32), base = { networkId: NETWORK, from: '5', nonce: '9', authEpoch: '0', publicKey: key };
  const signed = (kind, payload, more = {}) => Buffer.from(SDK.concat(SDK.buildAction({ ...base, ...more, kind, payload }), new Uint8Array(64)));
  const describe = (kind, payload, more) => describeAction(signed(kind, payload, more), NETWORK);
  const approvals = [{ public_key: key, signature: 'cc'.repeat(64) }];
  // Payments: recipient, amount and (for a payment to a shop) the reference.
  assert.deepEqual(describe(3, { to: '8', amount: '1500000' }), { opaque: false, kind: 3, sender: '5', nonce: '9', recipient: '8', amount: '1500000', reference: null, transfers: true, feeRule: 'network_fee', waiting: null });
  assert.deepEqual(describe(10, { to: '8', amount: '7', reference: 'ab'.repeat(32) }), { opaque: false, kind: 10, sender: '5', nonce: '9', recipient: '8', amount: '7', reference: 'ab'.repeat(32), transfers: true, feeRule: 'network_fee', waiting: null });
  const rootPay = describe(73, { op: { type: 'pay', to: '8', amount: '99' }, expires_elapsed_micros: '5', approvals }, { nonce: '0' });
  assert.deepEqual([rootPay.recipient, rootPay.amount, rootPay.transfers, rootPay.feeRule], ['8', '99', true, 'network_fee']);
  // A payment above the limit only asks; completing it names neither recipient nor amount.
  const request = describe(75, { type: 'request', to: '8', amount: '1000' });
  assert.deepEqual([request.recipient, request.amount, request.transfers, request.waiting], ['8', '1000', false, 'request']);
  const execute = describe(75, { type: 'execute', id: '1' });
  assert.deepEqual([execute.recipient, execute.amount, execute.transfers, execute.waiting], [null, null, false, 'execute']);
  assert.equal(describe(76, { type: 'payment', id: '1' }, { nonce: '0' }).waiting, 'cancel');
  assert.equal(describe(76, { type: 'limit', id: '1' }, { nonce: '0' }).waiting, null);
  assert.equal(describe(75, { type: 'something else' }).waiting, null);
  // A root operation that pays with malformed fields is not taken for a payment.
  assert.equal(describe(73, { op: { type: 'pay', to: 8, amount: '99' }, expires_elapsed_micros: '5', approvals }, { nonce: '0' }).transfers, false);
  assert.equal(describe(73, { op: { type: 'pay', to: '8', amount: '-1' }, expires_elapsed_micros: '5', approvals }, { nonce: '0' }).transfers, false);
  // Fees, as far as the bytes tell.
  assert.equal(describe(72, { freezes: '0', version: '1', expires_elapsed_micros: '5' }, { nonce: '0' }).feeRule, 'at_most_network_fee');
  assert.equal(describe(73, { op: { type: 'replace', keys: [], policy: {} }, expires_elapsed_micros: '5', approvals }, { nonce: '0' }).feeRule, 'at_most_network_fee');
  assert.equal(describe(73, { op: { type: 'cancel' }, expires_elapsed_micros: '5', approvals }, { nonce: '0' }).feeRule, 'network_fee');
  assert.equal(describe(14, {}).feeRule, 'none');
  assert.equal(describe(15, { recovery_id: 'ab'.repeat(32) }).feeRule, 'none');
  assert.equal(describe(12, { target: '3', policy_version: '1', accept: false }).feeRule, 'none');
  assert.equal(describe(12, { target: '3', policy_version: '1', accept: true }).feeRule, 'network_fee');
  assert.equal(describe(42, { epoch: '4' }).feeRule, 'none');
  // The public relay of bitcoin headers has no sender.
  const relay = describeAction(Buffer.from(SDK.publicHeadersAction(NETWORK, ['ab'.repeat(80)])), NETWORK);
  assert.deepEqual([relay.kind, relay.sender, relay.feeRule, relay.opaque], [40, null, 'none', false]);
  // Every kind the SDK names decodes; none is taken for a payment unless it is one.
  const payloads = { 2: { name: 'alice', salt: 'ab'.repeat(32) }, 5: { operator: '1', amount: '5', min_shares: '1' }, 6: { operator: '1', shares: '5', min_amount: '1' }, 7: { entry: '1' }, 8: { public_key: key, can_manage: true, can_spend: false, proof: 'cc'.repeat(64) }, 9: { public_key: key },
    11: { guardians: ['1', '2'], threshold: '2', delay_seconds: '9' }, 13: { target: '1', policy_version: '1', recovery_id: 'ab'.repeat(32), new_public_key: key, expires_elapsed_micros: '9', proof: 'cc'.repeat(64) }, 16: {},
    80: { activate_elapsed_micros: '1814400000000', spec: '5e'.repeat(32), version: '5' },
    // The market's kinds (50 to 58), each in a form the SDK takes (spec/market.md, section 6).
    50: SDK.marketSellOrder({ amountMicros: '100000000', price: '250000000', scripts: [`0014${'01'.repeat(20)}`], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '50000', minDepositMicros: '0' }),
    51: SDK.marketCancel({ order: '1' }), 52: SDK.marketTake({ order: '1', amountMicros: '40000000', price: '250000000', to: '8' }),
    53: SDK.marketSell({ order: '2', amountMicros: '40000000', price: '250000000', confirmations: '3', script: `0014${'07'.repeat(20)}` }),
    54: SDK.marketProof({ fill: '1', blockHash: 'ab'.repeat(32), transaction: `0200000001${'07'.repeat(32)}0000000000ffffffff01a00f000000000000160014${'01'.repeat(20)}00000000`, coinbase: `0200000001${'00'.repeat(32)}ffffffff0100ffffffff0100f2052a010000000000000000`, vout: '0', merkleProof: 'ab'.repeat(86) }),
    55: SDK.marketExpire({ fill: '1' }), 56: SDK.marketRelease({ fill: '1' }), 57: SDK.marketSettle({ fill: '1' }), 58: SDK.marketNewScripts({ order: '1', scripts: [`0014${'02'.repeat(20)}`] }) };
  for (const [name, kind] of Object.entries(SDK.KINDS)) {
    assert.equal(KIND_NAMES[kind], name);
    if ([1, 4, 3, 10, 12, 14, 15, 40].includes(kind)) continue; // 1 and 4 cannot be built; the others are covered above
    const facts = describe(kind, payloads[kind] ?? { any: 'thing' });
    assert.deepEqual([facts.opaque, facts.kind, facts.sender, facts.transfers], [false, kind, '5', false], name);
  }
  // The market's kinds pay the network's fee, and three of them pay it more than once: a sell order and new scripts for
  // each script, a proof for its size. A buy order lists no script and pays it once.
  assert.deepEqual([50, 51, 52, 53, 54, 55, 56, 57, 58].map((kind) => describe(kind, payloads[kind]).feeRule), ['market_fee', 'network_fee', 'network_fee', 'network_fee', 'market_fee', 'network_fee', 'network_fee', 'network_fee', 'market_fee']);
  assert.equal(describe(50, SDK.marketBuyOrder({ amountMicros: '100000000', price: '250000000', forms: ['p2wpkh'], confirmations: '3', payBlocks: '6', minSats: '1000', depositPpm: '50000' })).feeRule, 'network_fee');
  // A validator's upgrade signal (80), in its two forms: decoded, never a payment, and it pays the network fee.
  for (const payload of [payloads[80], {}]) assert.deepEqual(describe(80, payload), { opaque: false, kind: 80, sender: '5', nonce: '9', recipient: null, amount: null, reference: null, transfers: false, feeRule: 'network_fee', waiting: null });
  assert.equal(KIND_NAMES[80], 'upgrade_signal');
  // A registration that carries a set of keys (45), the bytes the engine accepted: named, decoded, from nobody, never
  // a payment, and it pays nothing, like a reveal.
  const registration = protectedFixture;
  assert.equal(KIND_NAMES[45], 'register_protected');
  assert.deepEqual(describeAction(Buffer.from(registration.registration.action_hex, 'hex'), registration.network_id), { opaque: false, kind: 45, sender: null, nonce: '0', recipient: null, amount: null, reference: null, transfers: false, feeRule: 'none', waiting: null });
  // Kinds the engine knows and the SDK does not (23, 63, and 81, reserved for an emergency release), a kind of the future, and bytes that are no action at all.
  const envelope = (kind, body) => { const b = Buffer.from(body); const length = Buffer.alloc(4); length.writeUInt32BE(b.length); return Buffer.concat([Buffer.from('TCDEVNET-ACTION-V1\0'), Buffer.from(NETWORK, 'hex'), Buffer.from([kind]), Buffer.from(SDK.concat(...['5', '9', '0'].map((v) => { const u = Buffer.alloc(8); u.writeBigUInt64BE(BigInt(v)); return u; }))), Buffer.from(key, 'hex'), length, b, Buffer.alloc(64)]); };
  for (const kind of [23, 63, 81, 200]) assert.deepEqual(describeAction(envelope(kind, '{"x":"1"}'), NETWORK), { opaque: true, kind, sender: '5', nonce: '9', recipient: null, amount: null, reference: null, transfers: false, feeRule: 'unknown', waiting: null });
  // A signal whose payload is not one of the two byte strings the engine takes is not decoded as one.
  for (const body of ['{"x":"1"}', '{ }', '{"version":"5"}', `{"spec":"${'5e'.repeat(32)}","activate_elapsed_micros":"9","version":"5"}`]) assert.deepEqual([describeAction(envelope(80, body), NETWORK).opaque, describeAction(envelope(80, body), NETWORK).kind, describeAction(envelope(80, body), NETWORK).feeRule], [true, 80, 'unknown'], body);
  // A transfer whose payload is not in canonical form is not decoded as a payment.
  assert.deepEqual([describeAction(envelope(3, '{"amount":"5","to":"8"}'), NETWORK).opaque, describeAction(envelope(3, '{"amount":"5","to":"8"}'), NETWORK).transfers], [true, false]);
  // Another network's action, a wrong length, and noise.
  assert.equal(describeAction(signed(3, { to: '8', amount: '5' }, { networkId: 'cd'.repeat(32) }), NETWORK).kind, null);
  assert.equal(describeAction(Buffer.concat([envelope(63, '{}'), Buffer.from([0])]), NETWORK).kind, null);
  assert.deepEqual(describeAction(Buffer.from('not an action'), NETWORK), { opaque: true, kind: null, sender: null, nonce: null, recipient: null, amount: null, reference: null, transfers: false, feeRule: 'unknown', waiting: null });
});

test('blocks are indexed in order from verified headers, and indexing resumes after a restart', async () => {
  await lab(async ({ state, open }) => {
    const seen = [];
    let { store, indexer } = open({ indexer: { onBlock: (event) => seen.push(event) } });
    assert.equal(indexer.status().indexed_height, null);
    await indexTo(indexer, store, 3);
    assert.deepEqual(seen.map((e) => [e.block.height, e.payments.length]), [[1, 0], [2, 2], [3, 0]]);
    // Blocks: hash as validators signed it, time, counts; results of a block are checked by the next.
    for (const height of [1, 2, 3]) assert.equal(store.block(height).hash, fixture.blocks[height - 1].signed_header.commit.block_id.hash.toLowerCase());
    assert.deepEqual([1, 2, 3].map((h) => [store.block(h).tx_count, store.block(h).payment_count, store.block(h).results_checked]), [[0, 0, 1], [2, 2, 1], [0, 0, 0]]);
    assert.equal(store.block(2).time, '1970-01-12T13:46:42.000000Z');
    assert.equal(store.block(2).previous_hash, store.block(1).hash);
    // Actions: hash, position, kind, sender, recipient, amount.
    const first = store.actionByHash(hashOf('2', 0)), second = store.actionByHash(hashOf('2', 1));
    assert.deepEqual([first.height, first.idx, first.kind, first.sender, first.nonce, first.recipient, first.amount, first.transfers, first.fee_rule, first.repeated], [2, 0, 3, '7', '1', '1', '5', 1, 'network_fee', false]);
    assert.deepEqual([second.idx, second.nonce], [1, '2']);
    assert.deepEqual(Buffer.from(first.raw), Buffer.from(fixture.txs['2'][0], 'base64'));
    assert.equal(store.actionByHash(hashOf('4', 0)), null);
    // Totals and activity of both accounts.
    assert.deepEqual({ ...store.account('7') }, { account: '7', actions_sent: 2, payments_sent: 2, sent_micros: '10', payments_received: 0, received_micros: '0', first_height: 2, last_height: 2 });
    assert.deepEqual({ ...store.account('1') }, { account: '1', actions_sent: 0, payments_sent: 0, sent_micros: '0', payments_received: 2, received_micros: '10', first_height: 2, last_height: 2 });
    assert.deepEqual(store.activity('1', 'asc', { height: 0, index: 0 }, 10).map((r) => [r.height, r.idx, r.role]), [[2, 0, 'recipient'], [2, 1, 'recipient']]);
    assert.deepEqual(store.activity('7', 'desc', { height: Number.MAX_SAFE_INTEGER, index: 0 }, 10).map((r) => [r.height, r.idx, r.role]), [[2, 1, 'sender'], [2, 0, 'sender']]);
    assert.equal(store.verifiedCount(), 0);
    const status = indexer.status();
    assert.deepEqual([status.indexed_height, status.tip_height_reported, status.blocks_behind_reported, status.fault, status.last_error], [3, 3, 0, null, null]);
    assert.equal(status.seconds_behind, Math.round((fixture.now_ms - Date.parse('1970-01-12T13:46:43Z')) / 1000));
    // Nothing new: a round changes nothing.
    await indexer.step();
    assert.equal(store.high(), 3);

    // Restart: a new process opens the same file and goes on at block 4.
    store.close();
    state.tip = 4; state.calls.length = 0; seen.length = 0;
    ({ store, indexer } = open({ indexer: { onBlock: (event) => seen.push(event) } }));
    assert.equal(indexer.status().indexed_height, 3);
    await indexTo(indexer, store, 4);
    assert.deepEqual(seen.map((e) => e.block.height), [4]);
    assert.deepEqual(state.calls.filter((c) => c === '/block').length, 1, 'only the new block is fetched');
    assert.equal(store.block(3).results_checked, 1);
    assert.deepEqual({ ...store.account('1') }, { account: '1', actions_sent: 0, payments_sent: 0, sent_micros: '0', payments_received: 3, received_micros: '15', first_height: 2, last_height: 4 });
    assert.equal(store.actionByHash(hashOf('4', 0)).height, 4);
    assert.deepEqual(store.payments('1', {}, 'asc', { height: 2, index: 0 }, 10).map((r) => [r.height, r.idx]), [[2, 1], [4, 0]]);
    assert.deepEqual(store.payments('1', { sender: '7' }, 'desc', { height: 4, index: 0 }, 10).map((r) => [r.height, r.idx]), [[2, 1], [2, 0]]);
    assert.deepEqual(store.payments('1', { sender: '8' }, 'asc', { height: 0, index: 0 }, 10), []);
  });
});

test('an index started below the trust anchor is filled from the anchor down the chain of block hashes', async () => {
  // A light client of the test gets a verified checkpoint at height 4: the trust anchor of this run.
  const state = { tip: 4, calls: [], change: null, down: false };
  const light = createLightClient({ trust: fixture.trust, verifier, now, fetchBlock: (height) => fetchLightBlock({ rpc: fakeRpc(state), height }) });
  const checkpoint = await light.updateTo('4');
  await lab(async ({ state: served, open }) => {
    const { store, indexer } = open();
    await indexTo(indexer, store, 4);
    // No signature was needed again: the anchor vouches for block 4, and each header for the one before.
    assert(!served.calls.includes('/commit') && !served.calls.includes('/validators'));
    assert(served.calls.includes('/blockchain'));
    assert.equal(store.block(1).hash, fixture.blocks[0].signed_header.commit.block_id.hash.toLowerCase());
    assert.equal(store.account('1').received_micros, '15');
  }, { tip: 4, trust: { ...fixture.trust, checkpoint } });
  // And an index that starts at a later height holds nothing below it.
  await lab(async ({ open }) => {
    const { store, indexer } = open();
    await indexTo(indexer, store, 4);
    assert.equal(store.block(2), null);
    assert.deepEqual([store.block(3).results_checked, store.block(4).tx_count, indexer.status().start_height], [1, 1, 3]);
    assert.equal(store.account('1').received_micros, '5');
  }, { tip: 4, startHeight: 3 });
});

test('a block whose header does not verify is refused, whatever the RPC serves', async () => {
  const forge = {
    'a header with another application hash': (method, _p, answer) => { if (method === '/block') answer.block.header.app_hash = '11'.repeat(32).toUpperCase(); return answer; },
    'a header of another height': (method, p, answer) => { if (method === '/block' && p.height === '2') answer.block.header = structuredClone(fixture.blocks[2].signed_header.header); return answer; },
    'a later time': (method, _p, answer) => { if (method === '/block') answer.block.header.time = '1970-01-12T13:46:59Z'; return answer; },
    'a header that names another recipient set (transactions replaced, data hash recomputed)': (method, p, answer) => {
      if (method === '/block' && p.height === '2') { answer.block.data.txs = [fixture.txs['4'][0]]; answer.block.header.data_hash = merkleRoot([sha(Buffer.from(fixture.txs['4'][0], 'base64'))]).toString('hex').toUpperCase(); }
      return answer;
    },
    'forged headers on the way down from the verified block': (method, _p, answer) => { if (method === '/blockchain') for (const meta of answer.block_metas) meta.header.proposer_address = '00'.repeat(20); return answer; },
  };
  for (const [name, change] of Object.entries(forge)) {
    await lab(async ({ state, open }) => {
      state.change = change;
      const { store, indexer } = open();
      for (let i = 0; i < 6; i++) await assert.rejects(indexer.step(), (error) => error instanceof IndexerError && error.code === 'HEADER_MISMATCH', name);
      // Block 1 is the only one an honest answer could have covered in some cases; none of the forged ones is in.
      assert((store.high() ?? 0) <= 1, name);
      assert.equal(store.actionByHash(hashOf('4', 0)), null, name);
      assert.equal(store.account('1'), null, name);
      // Once the RPC is honest again the same index continues.
      state.change = null;
      await indexTo(indexer, store, 3);
    });
  }
});

test('transactions that are not the ones of the verified header are refused', async () => {
  const forge = {
    'one transaction replaced': (txs) => [txs[0], fixture.txs['4'][0]],
    'one transaction withheld': (txs) => [txs[0]],
    'all withheld': () => [],
    'order changed': (txs) => [txs[1], txs[0]],
    'one added': (txs) => [...txs, fixture.txs['4'][0]],
    'not base64': (txs) => [txs[0], '!!!!'],
    'not canonical base64': (txs) => [txs[0], txs[1].replace(/=*$/, '') + '='.repeat(txs[1].endsWith('=') ? 0 : 1)],
  };
  for (const [name, change] of Object.entries(forge)) {
    await lab(async ({ state, open }) => {
      state.change = (method, p, answer) => { if (method === '/block' && p.height === '2') answer.block.data.txs = change(answer.block.data.txs); return answer; };
      const { store, indexer } = open();
      await assert.rejects((async () => { for (let i = 0; i < 6; i++) await indexer.step(); })(), (error) => error instanceof IndexerError && ['DATA_MISMATCH', 'RPC_INVALID'].includes(error.code), name);
      assert.equal(store.high(), 1, name);
      assert.equal(store.account('1'), null, name);
    });
  }
  // A transaction invented for an empty block is refused as well.
  await lab(async ({ state, open }) => {
    state.change = (method, p, answer) => { if (method === '/block' && p.height === '1') answer.block.data.txs = [fixture.txs['2'][0]]; return answer; };
    const { store, indexer } = open();
    await assert.rejects(indexer.step(), (error) => error.code === 'DATA_MISMATCH');
    assert.equal(store.high(), null);
  });
});

test('a chain the light client does not verify is never indexed', async () => {
  const forge = {
    'too few signatures': (method, _p, answer) => { if (method === '/commit') answer.signed_header.commit.signatures = answer.signed_header.commit.signatures.map((s, i) => (i < 2 ? s : { block_id_flag: 1, validator_address: '', timestamp: '0001-01-01T00:00:00Z', signature: null })); return answer; },
    'another validator set': (method, _p, answer) => { if (method === '/validators') answer.validators = answer.validators.map((v) => ({ ...v, pub_key: { ...v.pub_key, value: Buffer.alloc(32, 7).toString('base64') } })); return answer; },
    'a signed header changed after signing': (method, _p, answer) => { if (method === '/commit') answer.signed_header.header.app_hash = '22'.repeat(32).toUpperCase(); return answer; },
    'a tip that does not exist': (method, _p, answer) => { if (method === '/status') answer.sync_info.latest_block_height = '900'; return answer; },
    'a node of another chain': (method, _p, answer) => { if (method === '/status') answer.node_info.network = 'another-chain'; return answer; },
    'no usable height': (method, _p, answer) => { if (method === '/status') answer.sync_info.latest_block_height = -5; return answer; },
  };
  for (const [name, change] of Object.entries(forge)) {
    await lab(async ({ state, open }) => {
      state.change = change;
      const { store, indexer } = open();
      for (let i = 0; i < 3; i++) await assert.rejects(indexer.step(), (error) => error instanceof IndexerError && ['LIGHT_CLIENT', 'RPC_INVALID', 'RPC_REFUSED'].includes(error.code), name);
      assert.equal(store.high(), null, name);
      assert.equal(store.verifiedCount(), 0, name);
    });
  }
  // An expired trust anchor is reported as such: it needs an operator, not a retry.
  await lab(async ({ open }) => {
    const { store } = open();
    const late = createIndexer({ rpc: fakeRpc({ tip: 3, calls: [] }), trust: fixture.trust, store, verifier, now: () => fixture.now_ms + 8 * 86400 * 1000 });
    await assert.rejects(late.step(), (error) => error.code === 'TRUST_EXPIRED');
    assert.equal(store.high(), null);
  });
});

test('a verified chain that contradicts the index stops the indexer for good', async () => {
  // Neither case can come from the RPC alone; the index file is changed here to produce them.
  const cases = {
    RESULTS_MISMATCH: 'UPDATE blocks SET tx_count = 3 WHERE height = 2',
    CHAIN_CONFLICT: `UPDATE blocks SET hash = '${'ab'.repeat(32)}' WHERE height = 2`,
  };
  for (const [code, sql] of Object.entries(cases)) {
    await lab(async ({ state, open, filename }) => {
      state.tip = 2;
      const logged = [];
      const { store, indexer } = open({ indexer: { log: (level, message, fields) => logged.push({ level, message, ...fields }) } });
      await indexTo(indexer, store, 2);
      const other = new DatabaseSync(filename); other.exec(sql); other.close();
      state.tip = 4;
      indexer.start();
      for (let i = 0; i < 200 && !indexer.status().fault; i++) await new Promise((resolve) => setTimeout(resolve, 5));
      assert.equal(indexer.status().fault?.code, code);
      // It stays stopped: more rounds index nothing, and the reason is in the log once.
      await new Promise((resolve) => setTimeout(resolve, 40));
      await indexer.stop();
      assert.equal(store.high(), 2);
      assert.equal(logged.filter((line) => line.code === code && line.level === 'error').length, 1);
    });
  }
});

test('an RPC that fails, stalls or lags is survived, and the lag is exposed', async () => {
  await lab(async ({ state, open }) => {
    const logged = [];
    const { store, indexer } = open({ indexer: { log: (level, message, fields) => logged.push({ level, message, ...fields }) } });
    state.down = true;
    indexer.start();
    for (let i = 0; i < 200 && indexer.status().consecutive_failures < 3; i++) await new Promise((resolve) => setTimeout(resolve, 5));
    let status = indexer.status();
    assert(status.consecutive_failures >= 3);
    assert.deepEqual([status.indexed_height, status.seconds_behind, status.last_error.code, status.fault, status.running], [null, null, 'RPC_UNAVAILABLE', null, true]);
    assert.equal(logged.filter((line) => line.level === 'warn').length, 1, 'one line for the first failure, not one per retry');
    // The node comes back: indexing goes on by itself.
    state.down = false;
    for (let i = 0; i < 400 && store.high() !== 3; i++) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(store.high(), 3);
    status = indexer.status();
    assert.deepEqual([status.consecutive_failures, status.last_error], [0, null]);
    // The node says the chain is at 4 but does not serve block 4: the index reports how far behind it is.
    state.change = (method, _p, answer) => { if (method === '/status') answer.sync_info.latest_block_height = '4'; return answer; };
    for (let i = 0; i < 200 && indexer.status().blocks_behind_reported !== 1; i++) await new Promise((resolve) => setTimeout(resolve, 5));
    status = indexer.status();
    assert.deepEqual([status.indexed_height, status.tip_height_reported, status.blocks_behind_reported], [3, 4, 1]);
    assert(status.seconds_behind > 0 && status.consecutive_failures > 0);
    await indexer.stop();
    assert.equal(indexer.status().running, false);
  });
});

test('the RPC adapter bounds time and size, takes only string parameters and names no address in its errors', async () => {
  const answer = (body, status = 200) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });
  const asked = [];
  const rpc = createRpc('http://127.0.0.1:26657/', { fetcher: async (url) => { asked.push(String(url)); return answer({ result: { ok: true } }); } });
  assert.deepEqual(await rpc('/block', { height: '5' }), { ok: true });
  assert.equal(asked[0], 'http://127.0.0.1:26657/block?height=5');
  await assert.rejects(rpc('/unsafe_flush_mempool'), /not used by this service/);
  // A submitted action goes in the body of a JSON-RPC POST, as base64: the largest action fits no address.
  const posted = [];
  const submit = createRpc('http://127.0.0.1:26657/', { fetcher: async (url, options) => { posted.push({ url: String(url), ...options }); return answer({ result: { code: 0 } }); } });
  const large = Buffer.alloc(512 * 1024, 0xab);
  assert.deepEqual(await submit('/broadcast_tx_sync', { tx: `0x${large.toString('hex')}` }), { code: 0 });
  assert.deepEqual([posted[0].url, posted[0].method, posted[0].headers['Content-Type']], ['http://127.0.0.1:26657/', 'POST', 'application/json']);
  assert.deepEqual(JSON.parse(posted[0].body), { jsonrpc: '2.0', id: 1, method: 'broadcast_tx_sync', params: { tx: large.toString('base64') } });
  for (const tx of ['abcd', '0xABCD', '0xabc', '0x', undefined]) await assert.rejects(submit('/broadcast_tx_sync', { tx }), /0x-prefixed hexadecimal|parameters are strings/);
  await assert.rejects(rpc('/block', { height: 5 }), /parameters are strings/);
  const failing = (fetcher, options) => createRpc('http://user-secret.example:26657/', { fetcher, ...options })('/status');
  const codes = async (promise) => { try { await promise; return 'ok'; } catch (error) { assert(!/secret|26657/.test(error.message + (error.rpcMessage || '')), error.message); return error.code; } };
  // Never answers: given up after the time limit.
  assert.equal(await codes(failing((_url, { signal }) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason))), { timeoutMs: 30 })), 'RPC_UNAVAILABLE');
  assert.equal(await codes(failing(async () => { throw new Error('connect ECONNREFUSED user-secret.example:26657'); })), 'RPC_UNAVAILABLE');
  assert.equal(await codes(failing(async () => answer('x'.repeat(5000)), { maxBytes: 1000 })), 'RPC_INVALID');
  assert.equal(await codes(failing(async () => answer('<html>'))), 'RPC_INVALID');
  assert.equal(await codes(failing(async () => answer({ error: { message: 'Internal error', data: 'height 9 must be less than or equal to the current blockchain height 3' } }, 500))), 'RPC_REFUSED');
  assert.equal(await codes(failing(async () => answer({ jsonrpc: '2.0' }))), 'RPC_REFUSED');
  // What a node says about a refused request is passed on in plain characters, cut short.
  try { await failing(async () => answer({ error: { data: 'tx already exists in cache\n\u0007' + 'x'.repeat(500) } }, 500)); assert.fail(); } catch (error) { assert.match(error.rpcMessage, /^tx already exists in cache  x+$/); assert.equal(error.rpcMessage.length, 200); }
});

test('an index file belongs to one network and one start height', async () => {
  await lab(async ({ open, filename }) => {
    const { store } = open();
    store.close();
    assert.throws(() => openIndex({ filename, networkId: 'cd'.repeat(32), chainId: CHAIN }), /another network id/);
    assert.throws(() => openIndex({ filename, networkId: NETWORK, chainId: 'other' }), /another chain id/);
    assert.throws(() => openIndex({ filename, networkId: NETWORK, chainId: CHAIN, startHeight: 2 }), /starts at height 1/);
    assert.throws(() => openIndex({ filename, networkId: NETWORK, chainId: CHAIN, startHeight: 0 }), /whole number from 1/);
    assert.throws(() => openIndex({ filename, networkId: 'xyz', chainId: CHAIN }), /network id and chain id/);
    const again = openIndex({ filename, networkId: NETWORK, chainId: CHAIN });
    assert.throws(() => createIndexer({ rpc: async () => ({}), trust: { ...fixture.trust, network_id: 'cd'.repeat(32) }, store: again, verifier }), /different networks/);
    again.close();
  });
});

// Synthetic blocks written through the store's own writer, as the indexer writes them.
const built = (kind, payload, more = {}) => Buffer.from(SDK.concat(SDK.buildAction({ networkId: NETWORK, from: '7', nonce: '1', authEpoch: '0', publicKey: 'bb'.repeat(32), kind, payload, ...more }), new Uint8Array(64)));
function writeBlocks(store, blocks, first = 1, options = {}) {
  return blocks.map((raws, i) => {
    const height = first + i;
    const actions = raws.map((raw, idx) => ({ ...describeAction(raw, NETWORK), hash: sha(raw).toString('hex').toUpperCase(), raw, idx }));
    return store.writeBlock({ previousChecked: height > 1, actions, ...options,
      block: { height, hash: sha(Buffer.from(`block ${height}`)).toString('hex'), previous_hash: '', time_micros: height, time: '1970-01-01T00:00:00.000001Z', proposer: '', app_hash: '', data_hash: '' } });
  });
}

test('a completed payment above the daily limit is tied to its request only where the chain makes that certain', async () => {
  const request = (to, amount, nonce) => built(75, { type: 'request', to, amount }, { nonce });
  const execute = (id, nonce) => built(75, { type: 'execute', id }, { nonce });
  const hashesOf = (raw) => sha(raw).toString('hex').toUpperCase();
  await lab(async ({ open }) => {
    const { store } = open();
    const asked = request('5', '5000000', '2'), done = execute('1', '3');
    const written = writeBlocks(store, [
      [built(70, { keys: [], policy: {} }, { nonce: '1' })],   // account 7 adopts the rules: nothing is waiting
      [asked],                                                  // one request: 5,000,000 to account 5
      [done],                                                   // completed: it can only be that one
    ], 1, { webhookTargets: (account) => (account === '5' ? ['hook'] : []) });
    // The request moved nothing; the recipient sees it waiting.
    assert.deepEqual(written.map((w) => w.payments.length), [0, 0, 1]);
    assert.deepEqual(store.activity('5', 'asc', { height: 0, index: 0 }, 10).map((r) => [r.height, r.role, r.transfers, r.amount, r.request_status]), [[2, 'pending', 0, '5000000', 'completed'], [3, 'recipient', 1, '5000000', null]]);
    // The completion is a payment to the request's recipient, of the request's amount, and names the request.
    const payment = store.actionByHash(hashesOf(done));
    assert.deepEqual([payment.kind, payment.sender, payment.recipient, payment.amount, payment.transfers, payment.request_hash], [75, '7', '5', '5000000', 1, hashesOf(asked)]);
    assert.deepEqual(store.payments('5', {}, 'asc', { height: 0, index: 0 }, 10).map((r) => [r.height, r.kind, r.amount]), [[3, 75, '5000000']]);
    assert.deepEqual([store.account('5').payments_received, store.account('5').received_micros, store.account('7').sent_micros, store.block(3).payment_count], [1, '5000000', '5000000', 1]);
    assert.deepEqual(written[2].payments[0], { id: `payment:${hashesOf(done)}`, type: 'payment', source: 'index', proven: false, hash: hashesOf(done), height: '3', index: 0, time: '1970-01-01T00:00:00.000001Z', kind: 75, kind_name: 'waiting_payment',
      sender: '7', nonce: '3', recipient: '5', amount: '5000000', reference: null, transfers: true, request_hash: hashesOf(asked), results_checked: false });
    assert.deepEqual(store.outbox.counts().map((row) => ({ ...row })), [{ target: 'hook', dead: 0, count: 1 }]);

    // Two requests waiting at once: which one a completion pays cannot be told, so neither completion is
    // attributed. Once as many completions have been seen as requests, both are known to be completed
    // and nothing is waiting: the next request, alone, is followed like the first.
    const two = [request('5', '100', '4'), request('6', '200', '5')], unclear = [execute('2', '6'), execute('3', '7')];
    writeBlocks(store, [two, [unclear[0]]], 4);
    assert.deepEqual(two.map((raw) => store.actionByHash(hashesOf(raw)).request_status), ['waiting', 'waiting']);
    writeBlocks(store, [[unclear[1]]], 6);
    for (const raw of unclear) assert.deepEqual([store.actionByHash(hashesOf(raw)).recipient, store.actionByHash(hashesOf(raw)).transfers, store.actionByHash(hashesOf(raw)).request_hash], [null, 0, null]);
    assert.deepEqual(two.map((raw) => store.actionByHash(hashesOf(raw)).request_status), ['completed', 'completed']);
    const later = request('6', '300', '8'), afterTwo = execute('4', '9');
    writeBlocks(store, [[later], [afterTwo]], 7);
    assert.deepEqual([store.actionByHash(hashesOf(afterTwo)).recipient, store.actionByHash(hashesOf(afterTwo)).amount, store.actionByHash(hashesOf(afterTwo)).request_hash], ['6', '300', hashesOf(later)]);
    const fresh = request('6', '400', '10'), certain = execute('5', '11');
    writeBlocks(store, [[built(72, { freezes: '0', version: '1', expires_elapsed_micros: '9' }, { nonce: '0' })], [fresh], [certain]], 9);
    assert.deepEqual([store.actionByHash(hashesOf(certain)).recipient, store.actionByHash(hashesOf(certain)).amount, store.actionByHash(hashesOf(certain)).request_hash], ['6', '400', hashesOf(fresh)]);

    // A cancelled request is not paid by a later completion; and a cancellation of a limit raise changes nothing.
    const dropped = request('5', '500', '12'), kept = request('6', '600', '13'), paid = execute('7', '14');
    writeBlocks(store, [[dropped], [built(76, { type: 'limit', id: '9' }, { nonce: '0' })], [built(76, { type: 'payment', id: '6' }, { nonce: '0' })], [kept], [paid]], 12);
    assert.deepEqual([store.actionByHash(hashesOf(paid)).recipient, store.actionByHash(hashesOf(paid)).amount], ['6', '600']);
    assert.deepEqual([dropped, kept].map((raw) => store.actionByHash(hashesOf(raw)).request_status), ['cancelled', 'completed']);

    // An action of the account that could not be decoded may have been a request: no attribution until the next clean point.
    const frame = Buffer.from(built(75, { type: 'request', to: '5', amount: '1' }, { nonce: '15' }));
    // The same request with its fields in another order: the engine's frame, but not the one form the SDK decodes.
    const reordered = Buffer.from('{"to":"5","amount":"1","type":"request"}');
    const opaque = Buffer.concat([frame.subarray(0, frame.length - 64 - reordered.length), reordered, Buffer.alloc(64)]);
    assert.deepEqual([describeAction(opaque, NETWORK).opaque, describeAction(opaque, NETWORK).kind, describeAction(opaque, NETWORK).sender], [true, 75, '7']);
    const seen = request('6', '700', '16'), unknown = execute('8', '17');
    writeBlocks(store, [[opaque], [seen], [unknown]], 17);
    assert.equal(store.actionByHash(hashesOf(unknown)).transfers, 0);
    assert.equal(store.actionByHash(hashesOf(seen)).request_status, 'unknown');
    const clean = request('6', '800', '18'), sure = execute('9', '19');
    writeBlocks(store, [[built(74, { version: '2' }, { nonce: '0' })], [clean], [sure]], 20);
    assert.deepEqual([store.actionByHash(hashesOf(sure)).recipient, store.actionByHash(hashesOf(sure)).amount], ['6', '800']);

    // An account that was secured before the index began is not followed: its completions are not attributed.
    const early = built(75, { type: 'request', to: '5', amount: '900' }, { from: '8', nonce: '4' }), blind = built(75, { type: 'execute', id: '3' }, { from: '8', nonce: '5' });
    writeBlocks(store, [[early], [blind]], 23);
    assert.deepEqual([store.actionByHash(hashesOf(blind)).recipient, store.actionByHash(hashesOf(blind)).transfers, store.actionByHash(hashesOf(early)).request_status], [null, 0, 'unknown']);
    assert.deepEqual(store.activity('5', 'desc', { height: Number.MAX_SAFE_INTEGER, index: 0 }, 1).map((r) => [r.height, r.role, r.amount]), [[23, 'pending', '900']]);

    // How a request ends, where the index knows. Account 9: a freeze, and a replacement of the keys
    // (with or without a spend key), drop what waits; a request cancelled in the block that made it;
    // two waiting of which one is completed and one cancelled (which is which is not known).
    const of9 = (kind, payload, nonce) => built(kind, payload, { from: '9', nonce });
    const ask = (amount, nonce) => of9(75, { type: 'request', to: '5', amount }, nonce);
    const frozen = ask('1', '2'), replaced = ask('2', '3'), sameBlock = ask('3', '4'), mixed = [ask('4', '5'), ask('5', '6')], alone = ask('6', '9'), finished = of9(75, { type: 'execute', id: '7' }, '10');
    writeBlocks(store, [
      [of9(70, { keys: [], policy: {} }, '1')], [frozen], [of9(72, { freezes: '0', version: '1', expires_elapsed_micros: '9' }, '0')],
      [replaced], [of9(73, { op: { type: 'replace', keys: [], policy: {} }, expires_elapsed_micros: '9', approvals: [] }, '0')],
      [sameBlock, of9(76, { type: 'payment', id: '3' }, '0')],
      mixed, [of9(75, { type: 'execute', id: '4' }, '7')], [of9(76, { type: 'payment', id: '5' }, '0')],
      [alone], [finished],
    ], 25);
    assert.deepEqual([frozen, replaced, sameBlock, ...mixed, alone].map((raw) => store.actionByHash(hashesOf(raw)).request_status), ['dropped', 'dropped', 'cancelled', 'ended', 'ended', 'completed']);
    assert.deepEqual([store.actionByHash(hashesOf(finished)).recipient, store.actionByHash(hashesOf(finished)).amount], ['5', '6'], 'after the two were settled, a lone request is followed again');
    // Other root operations are no such point: a request made before one is still waiting after it.
    const before = ask('7', '11'), afterRoot = of9(75, { type: 'execute', id: '8' }, '12');
    writeBlocks(store, [[before], [of9(73, { op: { type: 'cancel' }, expires_elapsed_micros: '9', approvals: [] }, '0'), of9(73, { op: { type: 'unfreeze', freezes: '1' }, expires_elapsed_micros: '9', approvals: [] }, '0')], [afterRoot]], 36);
    assert.deepEqual([store.actionByHash(hashesOf(afterRoot)).recipient, store.actionByHash(hashesOf(afterRoot)).amount, store.actionByHash(hashesOf(before)).request_status], ['5', '7', 'completed']);
  });
});

test('an account protected from its first block is followed from its first request, which carries nonce 1', async () => {
  const hashesOf = (raw) => sha(raw).toString('hex').toUpperCase();
  await lab(async ({ open }) => {
    const { store } = open();
    // Account 12 was created by a registration that carries its keys (kind 45). Those bytes name no account: the
    // index cannot tie them to account 12. Every request takes the account's next nonce and only a request adds a
    // waiting payment, so before a first request with nonce 1 nothing can wait: it is followed from there.
    const engine = protectedFixture.registration, payload = SDK.decodeAction(SDK.hexToBytes(engine.action_hex)).payload;
    const registration = built(45, payload, { from: SDK.MAX_U64, nonce: '0' });
    const first = built(75, { type: 'request', to: '5', amount: '900' }, { from: '12', nonce: '1' }), done = built(75, { type: 'execute', id: '1' }, { from: '12', nonce: '2' });
    writeBlocks(store, [[registration], [first], [done]]);
    assert.deepEqual([store.actionByHash(hashesOf(registration)).kind, store.actionByHash(hashesOf(registration)).sender], [45, null]);
    const paid = store.actionByHash(hashesOf(done));
    assert.deepEqual([paid.recipient, paid.amount, paid.transfers, paid.request_hash, store.actionByHash(hashesOf(first)).request_status], ['5', '900', 1, hashesOf(first), 'completed']);
    // An account that adopted the rules (kind 70) spent a nonce on that, so its first request carries a later one:
    // one the index did not see adopt them stays unfollowed, as before.
    const late = built(75, { type: 'request', to: '5', amount: '901' }, { from: '13', nonce: '2' }), lateDone = built(75, { type: 'execute', id: '1' }, { from: '13', nonce: '3' });
    writeBlocks(store, [[late], [lateDone]], 4);
    assert.deepEqual([store.actionByHash(hashesOf(lateDone)).recipient, store.actionByHash(hashesOf(lateDone)).transfers, store.actionByHash(hashesOf(late)).request_status], [null, 0, 'unknown']);
    // A request with nonce 1 that the SDK cannot decode follows nothing.
    const frame = Buffer.from(built(75, { type: 'request', to: '5', amount: '1' }, { from: '14', nonce: '1' })), reordered = Buffer.from('{"to":"5","amount":"1","type":"request"}');
    const opaque = Buffer.concat([frame.subarray(0, frame.length - 64 - reordered.length), reordered, Buffer.alloc(64)]), next = built(75, { type: 'execute', id: '1' }, { from: '14', nonce: '2' });
    writeBlocks(store, [[opaque], [next]], 6);
    assert.deepEqual([store.actionByHash(hashesOf(next)).recipient, store.actionByHash(hashesOf(next)).transfers], [null, 0]);
  });
});

test('the Merkle proof read from the tree stored with a block is the one built from all its hashes', async () => {
  await lab(async ({ open }) => {
    const { store } = open();
    const sizes = [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33];
    let nonce = 0;
    const blocks = sizes.map((size) => Array.from({ length: size }, () => built(3, { to: '8', amount: '1' }, { nonce: String(++nonce) })));
    writeBlocks(store, blocks);
    blocks.forEach((raws, b) => {
      const hashes = raws.map((raw) => sha(raw));
      for (let index = 0; index < raws.length; index++) {
        const stored = store.inclusionProof(b + 1, index, raws.length), reference = merkleProof(hashes, index);
        assert.deepEqual([stored.root, stored.leaf, stored.aunts], [reference.root, reference.leaf, reference.aunts], `${index} of ${raws.length}`);
      }
      assert.deepEqual(store.inclusionProof(b + 1, 0, raws.length).root, merkleRoot(hashes));
    });
  });
});

test('a registered webhook target is told of payments from the first tip verified after it was registered', async () => {
  const targets = (account) => (account === '1' ? ['hook'] : []);
  const queued = (store) => store.outbox.counts().reduce((sum, row) => sum + row.count, 0);
  // Registered while the chain is at block 3: block 2 is history, block 4 is not, however late it is indexed.
  await lab(async ({ state, open }) => {
    const { store, indexer } = open({ indexer: { webhookTargets: targets, now: () => state.clock } });
    state.clock = fixture.now_ms;
    store.webhooks.register('hook');
    assert.deepEqual(store.webhooks.totals(), { skipped: 0, targets: 1, waiting: 1 });
    await indexTo(indexer, store, 3);
    assert.deepEqual([queued(store), store.webhooks.totals()], [0, { skipped: 2, targets: 1, waiting: 0 }]);
    state.clock += 3 * 86400 * 1000; state.tip = 4;   // three days pass before block 4 is indexed
    await indexTo(indexer, store, 4);
    assert.deepEqual([queued(store), store.webhooks.totals().skipped, store.account('1').payments_received], [1, 2, 3]);
    // Registering again changes nothing; a target that is forgotten and registered again starts anew.
    store.webhooks.register('hook');
    assert.equal(store.webhooks.totals().waiting, 0);
    store.webhooks.forget('hook'); store.webhooks.register('hook');
    assert.deepEqual(store.webhooks.totals(), { skipped: 0, targets: 1, waiting: 1 });
  });
  // Registered while the chain is at block 1: everything after is sent.
  await lab(async ({ state, open }) => {
    const { store, indexer } = open({ indexer: { webhookTargets: targets } });
    store.webhooks.register('hook');
    await indexTo(indexer, store, 1);
    state.tip = 4;
    await indexTo(indexer, store, 4);
    assert.deepEqual([queued(store), store.webhooks.totals().skipped], [3, 0]);
  }, { tip: 1 });
  // A target the store does not know (a caller of the store that keeps no start) is told of everything.
  await lab(async ({ open }) => {
    const { store, indexer } = open({ indexer: { webhookTargets: targets } });
    await indexTo(indexer, store, 3);
    assert.equal(queued(store), 2);
  });
  // The start comes from a tip the light client verified, never from a height the RPC only claims.
  await lab(async ({ state, open }) => {
    const { store, indexer } = open({ indexer: { webhookTargets: targets } });
    store.webhooks.register('hook');
    state.change = (method, _p, answer) => { if (method === '/status') answer.sync_info.latest_block_height = '900'; return answer; };
    await assert.rejects(indexer.step());
    assert.equal(store.webhooks.totals().waiting, 1);
  });
});
