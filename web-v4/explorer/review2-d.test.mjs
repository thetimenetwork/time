// Second review, part D: which class a failure lands in.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createStrings } from './strings.mjs';
import { createExplorer } from './views.mjs';
import { ApiFailure } from './client.mjs';
import { createChecker } from './check.mjs';
import { page, textOf, fakeTimers } from './review-fake-page.mjs';

const proven = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const LIE = { id: '0', name: 'alice', balance: '3600000000000', nonce: '9', devices: [] };
const api = () => ({ origin: 'https://api.example', status: async () => ({ network: { network_id: proven.trust.network_id, chain_id: proven.trust.chain_id }, indexer: {} }), activity: async () => ({ items: [] }),
  accountState: async () => { throw new ApiFailure('http', { status: 503, retryAfter: 5 }); }, account: async () => ({ account: clone(LIE), proof: { view_proof: clone(proven.proof) }, indexed: { totals: {} } }) });
async function open(checker, a) {
  const p = page('#/account/0');
  const explorer = createExplorer({ document: p.document, window: p.window, api: a, checker, live: null, t: createStrings('en'), now: () => proven.now_ms, timers: fakeTimers(), locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  return textOf(p.$('view'));
}

test('D1: the compiled verifier does not load (WebAssembly refused, the file limited or missing): said to be "the block this page trusts can no longer be used ... needs a newer trust manifest"', async () => {
  // In a browser the module proof-verifier.mjs loads, and the WebAssembly file only at the first call: this is that first call failing.
  const broken = Object.fromEntries(['verifyTrust', 'verifyLightUpdate', 'verifyViewProof', 'verifyReceipt', 'verifyFastReceipt'].map((name) => [name, async () => { throw new Error('WebAssembly.instantiateStreaming(): Refused to compile or instantiate WebAssembly module'); }]));
  const a = api();
  const checker = createChecker({ api: a, loadTrust: async () => proven.trust, loadVerifier: async () => broken, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms });
  const failure = await checker.checkState(() => a.account(), { ids: ['0'] }).then(() => null, (error) => error);
  const text = await open(checker, a);
  console.log(failure.reason, failure.offered, '|', text.slice(0, 420));
  assert.equal(failure.reason, 'no_verifier');
});

test('D2: the forged-proof tricks of the first review, once more, and new ones: none of them gets a figure onto the page', async () => {
  const forged = clone(proven.proof); forged.entries[2].value_b64 = Buffer.from(JSON.stringify(LIE)).toString('base64');
  const tricks = {
    'plain forgery': (p) => p,
    'CHECKPOINT_REFRESH_REQUIRED as a field': (p) => { p.CHECKPOINT_REFRESH_REQUIRED = 1; return p; },
    'STALE_STATE: as a field': (p) => { p['STALE_STATE: x'] = 1; return p; },
    'INVALID_CLOCK as a field': (p) => { p.light_block.INVALID_CLOCK = 1; return p; },
    'a validator key type named like the clock message': (p) => { p.light_block.validators[0].pub_key = { type: 'INVALID_LIGHT_BLOCK: header exceeds future clock bound', value: p.light_block.validators[0].pub_key.value }; return p; },
    'a height that is not one': (p) => { p.light_block.signed_header.header.height = 'STALE_STATE: 1'; return p; },
    'no light block': (p) => { delete p.light_block; return p; },
    'a proof that is a string': () => 'STALE_STATE: fresh current authority proof is required',
    'LIGHT_UPDATE_BUDGET: as a field': (p) => { p['LIGHT_UPDATE_BUDGET: x'] = 1; return p; },
  };
  const shown = [];
  for (const [name, change] of Object.entries(tricks)) {
    for (const status of [200, 404, 500]) {
      const a = api(), view_proof = change(clone(forged));
      a.account = async () => { const body = { account: clone(LIE), proof: { view_proof }, indexed: { totals: {} } }; if (status === 200) return body; throw new ApiFailure('http', { status, body, code: 'x' }); };
      const checker = createChecker({ api: a, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms, pause: async () => {} });
      const failure = await checker.checkState(() => a.account(), { ids: ['0'] }).then(() => null, (error) => error);
      const text = await open(checker, a);
      if (/1,000 h|Balance/.test(text)) shown.push(`${name} (${status}): ${failure?.reason}`);
      if (status === 200) console.log(name, '->', failure?.reason, failure?.offered);
    }
  }
  assert.deepEqual(shown, []);
});

test('D3: a device clock a quarter of a minute slow, and a trusted block that is the newest one (what the API serves as the manifest): nothing is checked, and the figures are shown as the service\'s word', async () => {
  // The trusted block of proof.json is block 6; its time is the newest the chain has. A device 15 s behind it:
  const header = proven.trust.checkpoint.block.signed_header.header, blockMs = Date.parse(header.time);
  const a = api(), now = blockMs - 15000;
  const checker = createChecker({ api: a, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => now });
  const failure = await checker.checkState(() => a.account(), { ids: ['0'] }).then(() => null, (error) => error);
  const p = page('#/account/0');
  const explorer = createExplorer({ document: p.document, window: p.window, api: a, checker, live: null, t: createStrings('en'), now: () => now, timers: fakeTimers(), locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  console.log(failure.reason, 'offered', failure.offered, '|', textOf(p.$('view')).slice(0, 380));
});
