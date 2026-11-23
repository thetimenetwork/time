// Adversarial review, part 3: the new API routes and the serving setting, through the real service.
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
import { createApiService } from '../../client-v4/api.mjs';
import { IndexerError } from '../../client-v4/indexer.mjs';
import { createApi } from './client.mjs';
import { createChecker } from './check.mjs';

const root = new URL('../../', import.meta.url);
const chain = JSON.parse(await readFile(new URL('verifier-v4/fixtures/fast-receipt.json', root), 'utf8'));
const proven = JSON.parse(await readFile(new URL('verifier-v4/fixtures/proof.json', root), 'utf8'));
const sha = (bytes) => createHash('sha256').update(bytes).digest();
const raw = (service, target, method = 'GET', headers = {}) => new Promise((resolve, reject) => {
  const url = new URL(service.url);
  const request = http.request({ host: url.hostname, port: url.port, path: target, method, headers }, (response) => { const chunks = []; response.on('data', (chunk) => chunks.push(chunk)); response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) })); });
  request.on('error', reject); request.end();
});

test('S1: with the REAL state reader a block too new for the history answers 503, never 404 not_in_history: the "own signed header" path of the page is never taken', async () => {
  // 1. The verifier refuses a state whose question names a block the history does not hold yet.
  //    The engine gives a history proof only for height <= the state's height (v5/src/app.rs:1077, v4/src/app.rs:675);
  //    the state of proof.json is at height 5, so block 6 has none, exactly as on a live chain for "the next block".
  assert.equal((await verifier.verifyViewProof(proven.proof, proven.trust, { blocks: ['1', '2'] }, proven.now_ms)).verified, true);
  const refusal = await verifier.verifyViewProof(proven.proof, proven.trust, { blocks: ['2', '6'] }, proven.now_ms).then(() => null, (error) => String(error.message ?? error));
  console.log('verifier, question { blocks: [2, 6] } on a state of height 5 ->', refusal);
  assert.match(refusal, /requested canonical history proof missing/);

  // 2. So the service, with its real state reader (the node of serve.test.mjs's end-to-end test), cannot answer 404 not_in_history.
  const light = proven.proof.light_block, logs = [];
  const rpc = async (method, parameters = {}) => {
    if (method === '/commit') return { signed_header: light.signed_header };
    if (method === '/validators') return { block_height: parameters.height, total: String(light.validators.length), validators: parameters.height === light.signed_header.header.height ? light.validators : light.next_validators };
    if (method === '/abci_query') return { response: { code: 0, height: proven.proof.height, value: Buffer.from(JSON.stringify({ height: proven.proof.height, root: light.signed_header.header.app_hash.toLowerCase(), entries: proven.proof.entries, history_proofs: proven.proof.history_proofs })).toString('base64') } };
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-review-')), originalNow = Date.now;
  Date.now = () => proven.now_ms;
  let service;
  try {
    service = await createApiService({ trust: proven.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, log: (level, message, fields) => logs.push([level, message, fields?.error]) });
    // The newest block of this chain is 6 (the light block); the state is at 5. Blocks 5 and 6 are "the newest two".
    const answer = await raw(service, '/v1/blocks/5/proof'), body = JSON.parse(answer.body);
    console.log('GET /v1/blocks/5/proof ->', answer.status, body.error.code, '| log:', JSON.stringify(logs.at(-1)));
    // 3. And the page: "Check it yourself" on an action of block 5.
    const api = createApi({ origin: service.url });
    let lightBlocksAsked = 0;
    const page = { ...api, action: async () => ({ action: { raw: 'AAAA' }, verify: { height: '5', index: 0, total: '1', root_hash: 'AB'.repeat(32), leaf_hash: 'AAAA', aunts: [] } }), lightBlock: async (h) => { lightBlocksAsked += 1; return api.lightBlock(h); } };
    const checker = createChecker({ api: page, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms });
    const failure = await checker.checkAction('AB'.repeat(32)).then(() => null, (error) => error);
    console.log('page: check of an action in block 5 ->', failure?.reason, failure?.detail?.status, failure?.detail?.code, '| light blocks asked for:', lightBlocksAsked);
    assert.deepEqual([answer.status, body.error.code], [404, 'not_in_history'], 'the route says it answers 404 not_in_history for a block that is too new; the page takes its second path only on that answer');
  } finally { Date.now = originalNow; await service?.close(); await rm(directory, { recursive: true, force: true }); }
});

function fakeRpc(tip = 4) {
  const block = (h) => { const b = chain.blocks[Number(h) - 1]; if (!b || Number(h) > tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  const calls = [];
  const rpc = async (method, parameters = {}) => {
    calls.push(method);
    if (method === '/status') return { node_info: { network: chain.trust.chain_id }, sync_info: { latest_block_height: String(tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: chain.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= chain.blocks.length ? chain.blocks[h - 1].validators : chain.blocks.at(-1).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  rpc.calls = calls;
  return rpc;
}
async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-review-'));
  const rpc = options.rpc ?? fakeRpc();
  const service = await createApiService({ trust: chain.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5, now: () => chain.now_ms, rateLimit: { perSecond: 1000, burst: 100000 },
    readState: async (selection) => ({ verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', accounts: [], config: {} } }), ...options, rpc });
  try {
    for (let i = 0; i < 50 && (service.store.high() ?? 0) < 4; i++) await service.indexer.step();
    await run(service, rpc);
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
}

test('S2: a 34th path: the files "take no query", yet an empty query is served', async () => {
  await lab(async (service) => {
    const got = {};
    for (const target of ['/explorer/app.js?', '/explorer/?', '/explorer/index.html?', '/explorer/trust-manifest.json?', '/explorer?', '/explorer/app.js?x']) got[target] = (await raw(service, target)).status;
    console.log(got);
    assert.deepEqual(Object.entries(got).filter(([target, status]) => target.endsWith('?') && status < 400), []);
  }, { explorer: true });
});

test('S3: on a page hosted elsewhere, Retry-After is not readable (no Access-Control-Expose-Headers): the page cannot "wait as long as the service asks"', async () => {
  await lab(async (service) => {
    await raw(service, '/v1/status', 'GET', { Origin: 'https://explorer.example' });
    const limited = await raw(service, '/v1/validators', 'GET', { Origin: 'https://explorer.example' });
    console.log('status', limited.status, 'retry-after', limited.headers['retry-after'], 'allow-origin', limited.headers['access-control-allow-origin'], 'expose', limited.headers['access-control-expose-headers']);
    assert.equal(limited.status, 429);
    assert.match(String(limited.headers['access-control-expose-headers']), /retry-after/i);
  }, { corsOrigins: ['https://explorer.example'], rateLimit: { perSecond: 1, burst: 2 } });
});

test('S4: what one load of the home page costs against the default limit of the service (burst 60), and what a first check costs', async () => {
  await lab(async (service) => {
    const html = (await readFile(new URL('web-v4/explorer/index.html', root), 'utf8'));
    const files = new Set(['', ...[...html.matchAll(/\s(?:src|href)="([a-z][^"#]*)"/g)].map((m) => m[1])]);
    // Static imports, followed.
    const queue = [...files].filter((name) => /\.m?js$/.test(name));
    while (queue.length) { const name = queue.pop(); const source = await readFile(new URL(`web-v4/explorer/${name}`, root), 'utf8').catch(() => ''); for (const [, imported] of source.matchAll(/from\s*'\.\/([^']+)'/g)) if (!files.has(imported)) { files.add(imported); queue.push(imported); } }
    files.add('trust-manifest.json');
    let statuses = [];
    for (const name of files) statuses.push((await raw(service, `/explorer/${name}`)).status);
    const pageFiles = files.size;
    // The home view: status, blocks, the actions of up to five blocks, and the stream (cost 10).
    const homeTokens = 1 + 1 + 5 * 1 + 10;
    console.log('files of one load:', pageFiles, 'tokens:', pageFiles, '+ home API', homeTokens, '=', pageFiles + homeTokens, 'of a burst of 60; lazy for the first check: 4 more files + action 5 + block proof 5 (+ light blocks at 5 each)');
    assert(statuses.every((status) => status === 200));
  }, { explorer: true });
  // With the default limit: how many reloads of the home page from one address (an office, a campus, a mobile carrier's NAT) before a script is refused?
  await lab(async (service) => {
    const perLoad = ['', 'styles.css', 'sdk/time-sdk.js', 'app.js', 'strings.mjs', 'client.mjs', 'check.mjs', 'views.mjs', 'format.mjs', 'dom.mjs', 'route.mjs', 'describe.mjs', 'trust-manifest.json'];
    let loads = 0, refused = null;
    outer: for (; loads < 20; loads++) {
      for (const name of perLoad) { const answer = await raw(service, `/explorer/${name}`); if (answer.status !== 200) { refused = [name, answer.status, answer.headers['content-type']]; break outer; } }
      for (const target of ['/v1/status', '/v1/blocks?limit=50']) await raw(service, target);
      await raw(service, '/v1/validators'); await raw(service, '/v1/validators'); // stands in for the stream's 10 tokens
    }
    console.log('loads from one address before a file of the page is refused (frozen clock, default limit):', loads, refused);
    assert(loads >= 2);
  }, { explorer: true, rateLimit: {} });
});

test('S5: every explorer visitor makes the service prove anew; nothing is shared between identical questions', async () => {
  let reads = 0;
  await lab(async (service) => {
    for (let i = 0; i < 10; i++) await raw(service, '/v1/validators');
    for (let i = 0; i < 10; i++) await raw(service, '/v1/blocks/2/proof');
    console.log('20 identical requests ->', reads, 'state reads (each: a light block, a state query with proofs, and their verification)');
    assert(reads <= 4, 'identical questions within one block time could share one proof');
  }, { readState: async (selection) => { reads += 1; return { verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', accounts: [], config: {}, pos: {}, canonical_blocks: { 2: { hash: 'aa'.repeat(32), time_micros: '1' }, 3: { hash: 'bb'.repeat(32), time_micros: '2' } } } }; } });
});

test('S6: the served trust manifest when the service\'s own anchor has expired: what does the page get?', async () => {
  let clock = chain.now_ms;
  await lab(async (service) => {
    clock = chain.now_ms + 8 * 86400 * 1000; // the service ran, then eight days pass (it was down, or its node stood still)
    const manifest = JSON.parse((await raw(service, '/explorer/trust-manifest.json')).body);
    const status = await verifier.verifyTrust(manifest, clock).then(() => 'usable', (error) => String(error.message ?? error).slice(0, 60));
    console.log('served manifest, checkpoint', manifest.checkpoint?.height, 'after 8 days ->', status, '| headers cache-control:', (await raw(service, '/explorer/trust-manifest.json')).headers['cache-control']);
  }, { explorer: true, now: () => clock });
});
