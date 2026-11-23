// Adversarial review, part 4: can the service choose which of the three outcomes the reader sees?
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createApiService } from '../../client-v4/api.mjs';
import { IndexerError } from '../../client-v4/indexer.mjs';
import { createStrings } from './strings.mjs';
import { createExplorer } from './views.mjs';
import { ApiFailure, createApi } from './client.mjs';
import { createChecker } from './check.mjs';
import { page, textOf, within, buttons, fakeTimers } from './review-fake-page.mjs';

const SDK = globalThis.TimeSDK;
const proven = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const chain = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const sha = (bytes) => createHash('sha256').update(bytes).digest();

async function openReal(hash, api, { now = proven.now_ms, trust = proven.trust } = {}) {
  const p = page(hash);
  const checker = createChecker({ api, loadTrust: async () => trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => now });
  const explorer = createExplorer({ document: p.document, window: p.window, api, checker, live: null, t: createStrings('en'), now: () => now, timers: fakeTimers(), locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  return { ...p, view: p.$('view'), text: () => textOf(p.$('view')), explorer, checker };
}
const LIE = { id: '0', name: 'alice', balance: '3600000000000', nonce: '9', devices: [] }; // "1,000 h"; the chain says 0
const baseApi = (network = proven.trust.network_id) => ({
  origin: '',
  status: async () => ({ network: { network_id: network, chain_id: proven.trust.chain_id }, indexer: {} }),
  activity: async () => ({ items: [], has_more: false }),
  accountState: async () => { throw new ApiFailure('http', { status: 503, retryAfter: 5 }); },
});

test('F10a: a service whose proof would FAIL names another network id in /v1/status and its figures are shown after all', async () => {
  // A forged proof: one row changed. With the honest status the page withholds everything.
  const forged = clone(proven.proof); forged.entries[2].value_b64 = Buffer.from(JSON.stringify(LIE)).toString('base64');
  const body = () => ({ account: clone(LIE), proof: { view_proof: clone(forged) }, indexed: { totals: {} } });
  const withheld = await openReal('#/account/0', { ...baseApi(), account: async () => body() });
  assert.match(withheld.text(), /The check FAILED: the proof the service gave for this does not verify\. The figures are not shown\./);
  // The same forged answer, and a status that names another network.
  const shown = await openReal('#/account/0', { ...baseApi('ef'.repeat(32)), account: async () => body() });
  console.log('status names another network ->', shown.text().slice(0, 330));
  assert.doesNotMatch(shown.text(), /Balance 1,000 h/, 'the forged balance is on the page; the service chose "not checkable" over "failed"');
});

test('F10b: the service writes CHECKPOINT_REFRESH_REQUIRED into a field the verifier quotes: a failing proof becomes "the block this page trusts is too old" and the figures are shown', async () => {
  const forged = clone(proven.proof);
  forged.entries[2].value_b64 = Buffer.from(JSON.stringify(LIE)).toString('base64');
  const attempts = {
    'validator key type': (proof) => { proof.light_block.validators[0].pub_key = { type: 'CHECKPOINT_REFRESH_REQUIRED', value: proof.light_block.validators[0].pub_key.value }; },
    'unknown field of the light block': (proof) => { proof.light_block.CHECKPOINT_REFRESH_REQUIRED = 1; },
    'unknown field of the proof': (proof) => { proof.CHECKPOINT_REFRESH_REQUIRED = 1; },
    'height of the proof': (proof) => { proof.height = 'CHECKPOINT_REFRESH_REQUIRED'; },
  };
  const worked = [];
  for (const [name, change] of Object.entries(attempts)) {
    const proof = clone(forged); change(proof);
    const api = { ...baseApi(), account: async () => ({ account: clone(LIE), proof: { view_proof: clone(proof) }, indexed: { totals: {} } }) };
    const checker = createChecker({ api, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => proven.now_ms });
    const failure = await checker.checkState(() => api.account(), { ids: ['0'] }).then(() => null, (error) => error);
    console.log(`${name} ->`, failure?.reason, '|', String(failure?.detail).slice(0, 130));
    if (failure?.reason !== 'trust_expired') continue;
    const p = await openReal('#/account/0', api);
    console.log('   page ->', p.text().slice(0, 420));
    if (/Balance 1,000 h/.test(p.text())) worked.push(name);
  }
  assert.deepEqual(worked, [], 'a proof that does not verify is shown as "could not be checked: your trust manifest is too old", with the forged figures');
});

test('F11: in a new block without a successor the position is not bound: "These exact bytes are action number 3 of block 2" for the second action of two', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-explorer-review-'));
  const tip = 4, block = (h) => { const b = chain.blocks[Number(h) - 1]; if (!b || Number(h) > tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  const rpc = async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: chain.trust.chain_id }, sync_info: { latest_block_height: String(tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: chain.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= chain.blocks.length ? chain.blocks[h - 1].validators : chain.blocks.at(-1).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
  const service = await createApiService({ trust: chain.trust, rpc, verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5, now: () => chain.now_ms, rateLimit: { perSecond: 1000, burst: 100000 },
    readState: async (selection) => ({ verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: chain.trust.network_id, height: '3', time_micros: '1000003000000', accounts: [], config: {} } }) });
  try {
    for (let i = 0; i < 50 && (service.store.high() ?? 0) < tip; i++) await service.indexer.step();
    const api = createApi({ origin: service.url });
    const hash = sha(Buffer.from(chain.txs['2'][1], 'base64')).toString('hex').toUpperCase();
    const honest = await createChecker({ api, loadTrust: async () => chain.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => chain.now_ms }).checkAction(hash);
    // The attacker: position 2 of a block of 3 (in truth: 1 of 2), and "there is no next block" (which would have caught it).
    const lying = { ...api, action: async (wanted) => { const answer = clone(await api.action(wanted)); answer.verify.index = 2; answer.verify.total = '3'; return answer; },
      lightBlock: async (h) => { if (h === '3') throw new ApiFailure('http', { status: 404, code: 'not_found' }); return api.lightBlock(h); } };
    const result = await createChecker({ api: lying, loadTrust: async () => chain.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => chain.now_ms }).checkAction(hash).then((r) => r, (error) => error);
    console.log('honest index', honest.index, 'results', honest.resultsChecked, '| forged ->', result.index ?? result.reason, 'results', result.resultsChecked, String(result.detail ?? '').slice(0, 80));
    assert.notEqual(result.index, 2, 'the check passed with a position the block does not have');
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});
