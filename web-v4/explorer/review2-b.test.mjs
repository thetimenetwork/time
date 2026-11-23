// Second review, part B: the block-proof route with its remembered reach, sharing of state
// reads, and the caching and cost of the page's files. Through the real service of 0d76ddf.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createApiService, EXPLORER_FILES } from '../../client-v4/api.mjs';
import { IndexerError } from '../../client-v4/indexer.mjs';
import { createApi, ApiFailure } from './client.mjs';
import { createChecker } from './check.mjs';

const root = new URL('../../', import.meta.url);
const chain = JSON.parse(await readFile(new URL('verifier-v4/fixtures/fast-receipt.json', root), 'utf8'));
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const raw = (service, target, method = 'GET', headers = {}) => new Promise((resolve, reject) => {
  const url = new URL(service.url);
  const request = http.request({ host: url.hostname, port: url.port, path: target, method, headers }, (response) => { let size = 0; const chunks = []; response.on('data', (chunk) => { size += chunk.length; if (size < 200000) chunks.push(chunk); }); response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks), size })); });
  request.on('error', reject); request.end();
});
function fakeRpc(tip = 4) {
  const block = (h) => { const b = chain.blocks[Number(h) - 1]; if (!b || Number(h) > tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: chain.trust.chain_id }, sync_info: { latest_block_height: String(tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: chain.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= chain.blocks.length ? chain.blocks[h - 1].validators : chain.blocks.at(-1).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-review2-'));
  const service = await createApiService({ trust: chain.trust, rpc: fakeRpc(), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5, now: () => chain.now_ms, rateLimit: { perSecond: 1000, burst: 100000 },
    readState: async (selection) => ({ verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', accounts: [], config: {} } }), ...options });
  try {
    for (let i = 0; i < 50 && (service.store.high() ?? 0) < 4; i++) await service.indexer.step();
    await run(service);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
}

test('P1: a block older than the rows the state has dropped (14 days) is answered "not in history" without the state being asked, although its history proof still exists', async () => {
  // The engine drops the rows block/<h> and block_time/<h> of blocks older than the unbonding delay (pos::UNBOND_DELAY = 14 days) and
  // counts them in meta.history_pruned_through. The history PROOF of such a block stays: v4/tests/engine.rs,
  // "expired_canonical_rows_prune_in_bounded_batches_but_history_proofs_remain_verifiable" (history_proof(131, 1) verifies with
  // history_pruned_through at 64, 128, 130), and the verifier builds canonical_blocks from that proof alone (verifier-v4/src/view.rs:823-843).
  // So a verified state at height 1000 with history_pruned_through 900 still answers a question about blocks 2 and 3:
  const asked = [];
  const readState = async (selection) => {
    asked.push(JSON.stringify(selection));
    const blocks = Object.fromEntries((selection.blocks ?? []).filter((h) => Number(h) >= 1 && Number(h) <= 1000).map((h) => [h, { hash: sha(Buffer.from(h)).toString('hex'), time_micros: `10000${h}000000` }]));
    return { verified: true, requested: selection, proof: { height: '1000', entries: [], light_block: {} }, state: { network_id: chain.trust.network_id, height: '1000', time_micros: '1000003000000', history_pruned_through: '900', accounts: [], config: {}, canonical_blocks: blocks } };
  };
  await lab(async (service) => {
    const young = await raw(service, '/v1/blocks/950/proof'), old = await raw(service, '/v1/blocks/2/proof'), body = JSON.parse(old.body);
    console.log('block 950 ->', young.status, JSON.parse(young.body).error?.code, '| block 2 ->', old.status, body.error?.code, '|', body.error?.message, '| questions put to the state:', asked);
    // And what the page makes of that answer: it takes the path for the NEWEST blocks.
    const api = createApi({ origin: service.url });
    const hash = sha(Buffer.from(chain.txs['2'][0], 'base64')).toString('hex').toUpperCase();
    // A page whose trusted block is the newest one (as a manifest served by the API always is).
    const light = createLightClient({ trust: chain.trust, verifier, now: () => chain.now_ms, fetchBlock: async (h) => (await api.lightBlock(String(h))).light_block });
    const manifest = { ...chain.trust, checkpoint: await light.updateTo('4') };
    const checker = createChecker({ api, loadTrust: async () => manifest, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => chain.now_ms, pause: async () => {} });
    const failure = await checker.checkAction(hash).then((r) => r, (error) => error);
    console.log('page, action of the old block 2, trusted block 4 ->', failure.reason ?? failure.mode, '("Not checked yet: the block is too new. Try again in a few seconds.")');
    assert.equal(old.status, 200, 'the proof of an old block is there to be had; the route refuses before asking');
  }, { readState });
});

test('P2: what remembering the reach costs and saves', async () => {
  const asked = [];
  const readState = async (selection) => { asked.push(JSON.stringify(selection)); return { verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', accounts: [], config: {}, canonical_blocks: Object.fromEntries((selection.blocks ?? []).filter((h) => Number(h) <= 3).map((h) => [h, { hash: 'aa'.repeat(32), time_micros: '1' }])) } }; };
  let clock = chain.now_ms;
  await lab(async (service) => {
    for (const h of [3, 4, 5, 6, 7, 8]) await raw(service, `/v1/blocks/${h}/proof`);   // all too new: one look at the plain state serves them for a second
    const tooNew = asked.length; clock += 5000;
    for (let i = 0; i < 5; i++) await raw(service, '/v1/blocks/2/proof');                 // identical: shared
    const same = asked.length - tooNew; clock += 5000;
    for (let i = 0; i < 5; i++) { clock += 1500; await raw(service, '/v1/blocks/2/proof'); } // spaced by more than the sharing time: one read each
    console.log('6 too-new blocks ->', tooNew, 'state reads | 5 identical ->', same, '| 5 spaced by 1.5 s ->', asked.length - tooNew - same, '|', [...new Set(asked)]);
    assert(tooNew <= 1 && same <= 2);
  }, { readState, now: () => clock });
});

test('C1: the page\'s files at a tenth of a token: how much one address can make the service send', async () => {
  await lab(async (service) => {
    let bytes = 0, served = 0, refused = null;
    for (let i = 0; i < 700 && !refused; i++) { const answer = await raw(service, '/explorer/web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm'); if (answer.status === 200) { served += 1; bytes += answer.size; } else refused = answer.status; }
    let manifests = 0, manifestBytes = 0;
    console.log(`one address, default limit (burst 60, 20 a second), clock standing still: ${served} downloads of the verifier (${(bytes / 1e6).toFixed(0)} MB) before the first ${refused}; then 200 more a second (${(200 * 1.05).toFixed(0)} MB/s)`);
    assert(served <= 120, 'a megabyte for a tenth of a token');
  }, { explorer: true, rateLimit: {} });
  await lab(async (service) => {
    let manifests = 0, bytes = 0, refused = null;
    for (let i = 0; i < 700 && !refused; i++) { const answer = await raw(service, '/explorer/trust-manifest.json'); if (answer.status === 200) { manifests += 1; bytes += answer.size; } else refused = answer.status; }
    let junk = 0; refused = null;
    console.log(`the trust manifest (read from the database and built anew each time, ${Math.round(bytes / manifests)} bytes here with 4 validators): ${manifests} before the first 429`);
  }, { explorer: true, rateLimit: {} });
});

test('C2: caching: validators, what is kept, and what is never kept', async () => {
  await lab(async (service) => {
    const first = await raw(service, '/explorer/app.js');
    const again = await raw(service, '/explorer/app.js', 'GET', { 'If-None-Match': first.headers.etag });
    const manifest = await raw(service, '/explorer/trust-manifest.json'), missing = await raw(service, '/explorer/nothing.js'), api = await raw(service, '/v1/status');
    const index = await raw(service, '/explorer/'), weak = await raw(service, '/explorer/app.js', 'GET', { 'If-None-Match': `W/${first.headers.etag}` }), list = await raw(service, '/explorer/app.js', 'GET', { 'If-None-Match': `"x", ${first.headers.etag}` });
    console.log({ file: [first.status, first.headers['cache-control'], first.headers.etag, first.headers.vary], notChanged: [again.status, again.headers['cache-control'], again.size], page: [index.status, index.headers['cache-control']],
      manifest: manifest.headers['cache-control'], missing: [missing.status, missing.headers['cache-control']], api: api.headers['cache-control'], weak: weak.status, list: list.status });
    assert.deepEqual([again.status, manifest.headers['cache-control'], missing.headers['cache-control'], api.headers['cache-control']], [304, 'no-store', 'no-store', 'no-store']);
    // Every file has its own validator, and none is shared with the manifest or the API.
    const tags = new Set(); for (const [name] of EXPLORER_FILES) tags.add((await raw(service, `/explorer/${name}`)).headers.etag);
    assert.equal(tags.size, EXPLORER_FILES.length - 1, 'index.html is listed twice');
    // The page file itself is kept for five minutes too: after a new release a reader goes on with the old page, and the files it loads late come from the new one.
    assert.equal(index.headers['cache-control'], 'no-cache', 'the page file is the one that names all others: it should be asked about every time');
  }, { explorer: true });
});
