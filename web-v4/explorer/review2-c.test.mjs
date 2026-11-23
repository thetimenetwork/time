// Second review, part C: files of two releases running together (each file is cached by itself for five minutes).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createStrings } from './strings.mjs';
import { createExplorer as olderViews } from './review2-old-views.mjs';   // views.mjs as it was one release earlier (e7b6f85), byte for byte
import { createChecker } from './check.mjs';                              // check.mjs of this release
import { page, textOf, fakeTimers } from './review-fake-page.mjs';

const proven = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
test('C3: one file of the previous release still in a browser\'s cache, the others new: an HONEST service, an account that exists, and "no such account, checked in your browser"', async () => {
  const api = { origin: '', status: async () => ({ network: { network_id: proven.trust.network_id, chain_id: proven.trust.chain_id }, indexer: {} }), activity: async () => ({ items: [] }), accountState: async () => ({}),
    account: async () => ({ account: { id: '0', name: 'alice' }, proof: { view_proof: structuredClone(proven.proof) }, indexed: { totals: {} } }) };
  const p = page('#/account/@alice');
  const checker = createChecker({ api, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: globalThis.TimeSDK, now: () => proven.now_ms });
  const explorer = olderViews({ document: p.document, window: p.window, api, checker, live: null, t: createStrings('en'), now: () => proven.now_ms, timers: fakeTimers() });
  await explorer.start();
  console.log(textOf(p.$('view')).slice(0, 200));
  assert.doesNotMatch(textOf(p.$('view')), /There is no such account\. Checked in your browser/);
});
