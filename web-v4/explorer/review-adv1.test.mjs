// Adversarial review, part 1: "checked" that is not. The page modules with the REAL verifier
// (the fixtures of verifier-v4), the service played as the attacker.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import '../../client-v4/time-sdk.js';
import * as verifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { createStrings } from './strings.mjs';
import { createExplorer } from './views.mjs';
import { ApiFailure } from './client.mjs';
import { createChecker, CheckFailure } from './check.mjs';
import { page, textOf, within, buttons, fakeTimers } from './review-fake-page.mjs';

const SDK = globalThis.TimeSDK;
const proven = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const sha = (bytes) => createHash('sha256').update(bytes).digest();

async function openReal(hash, api, { now = proven.now_ms, trust = proven.trust } = {}) {
  const p = page(hash);
  const checker = createChecker({ api, loadTrust: async () => trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => now });
  const explorer = createExplorer({ document: p.document, window: p.window, api, checker, live: null, t: createStrings('en'), now: () => now, timers: fakeTimers(), locale: 'en-GB', timeZone: 'UTC' });
  await explorer.start();
  return { ...p, view: p.$('view'), text: () => textOf(p.$('view')), explorer, checker };
}
const baseApi = () => ({
  origin: '',
  status: async () => ({ network: { network_id: proven.trust.network_id, chain_id: proven.trust.chain_id }, indexer: {} }),
  activity: async () => ({ items: [], has_more: false }),
  accountState: async () => { throw new ApiFailure('http', { status: 503, retryAfter: 5 }); },
});

test('F1: a 404 that carries a valid proof of an account that EXISTS is shown as "no such account, checked in your browser"', async () => {
  const wrong = [];
  for (const address of ['#/account/@alice', '#/account/0']) {
    // The honest service: the account exists and the page shows it as checked.
    const honest = await openReal(address, { ...baseApi(), account: async () => ({ account: { id: '0', name: 'alice' }, proof: { view_proof: clone(proven.proof) }, indexed: { totals: {} } }) });
    assert.match(honest.text(), /Name account name from the chain: @alice Number 0 Balance 0 s/, address);
    assert.match(honest.text(), /Checked in your browser against the state of block 5\./, address);
    // The attacker: the very same valid proof (alice exists in it), sent with status 404.
    const lying = await openReal(address, { ...baseApi(), account: async () => { throw new ApiFailure('http', { status: 404, code: 'account_not_found', body: { proof: { view_proof: clone(proven.proof) } } }); } });
    console.log(`${address} ->`, lying.text().slice(0, 190));
    if (/There is no such account\. Checked in your browser: the proof shows that the state of block 5 does not hold it\./.test(lying.text())) wrong.push(address);
  }
  assert.deepEqual(wrong, [], 'the proof shows the account EXISTS; the page says it proved the opposite');
});

test('holds: the figures of a checked account are those of the account asked for, and a proof for another question is refused', async () => {
  const honest = { account: { id: '0', name: 'alice', balance: '999999999999' }, proof: { query: { ids: ['31337'] }, view_proof: clone(proven.proof) }, indexed: { totals: {} } };
  // The service's own copy says 277 h; the proven row says 0.
  const p = await openReal('#/account/0', { ...baseApi(), account: async () => clone(honest) });
  assert.match(p.text(), /Number 0 Balance 0 s/); assert.doesNotMatch(p.text(), /277 h/);
  // Asked for account 999 (proven absent in this proof) while the service hands over alice: nothing of alice is shown.
  const other = await openReal('#/account/999', { ...baseApi(), account: async () => clone(honest) });
  assert.match(other.text(), /There is no such account\. Checked in your browser/); assert.doesNotMatch(other.text(), /alice|Balance/);
  // Asked for account 1, of which the proof says nothing at all: refused, nothing shown.
  const silent = await openReal('#/account/1', { ...baseApi(), account: async () => clone(honest) });
  assert.match(silent.text(), /The check FAILED/); assert.doesNotMatch(silent.text(), /alice|Balance/);
  // SDK-undecodable kinds exist on the chain by design (deploy/api/README.md: "the engine's 23 and 63, and any added later").
  const bytes = SDK.buildAction({ networkId: proven.trust.network_id, kind: 3, from: '7', nonce: '1', authEpoch: '0', publicKey: '11'.repeat(32), payload: { to: '5', amount: '5' } });
  const kindAt = new TextEncoder().encode('TCDEVNET-ACTION-V1\0').length + 32;
  for (const kind of [23, 63]) { const copy = SDK.concat(bytes, new Uint8Array(64)); copy[kindAt] = kind; assert.throws(() => SDK.decodeAction(copy), /Unknown action/, `kind ${kind} is not read by the SDK`); }
});

test('F3: bytes the SDK cannot read: the page says "Checked" and leaves the service\'s made-up description standing, without a word that it was not compared', async () => {
  const receipt = clone(proven.receipt), tx = receipt.tx;
  const hash = sha(Buffer.from(tx.tx, 'base64')).toString('hex').toUpperCase();
  const api = { ...baseApi(),
    // The service describes the action as a payment of 100 h to account 5. The bytes say nothing of the kind.
    action: async () => ({ source: 'index', proven: false, action: { hash, height: String(tx.height), index: 0, time: '2026-11-17T10:00:00.000000Z', kind: 3, opaque: false, sender: '7', nonce: '1', recipient: '5', amount: '360000000000', reference: null, transfers: true,
      fee_rule: 'network_fee', fee_micros: '1000', results_checked: true, payload: { to: '5', amount: '360000000000' }, raw: tx.tx, repeated: 1 },
    verify: { hash, height: String(tx.height), index: Number(tx.index), total: String(tx.proof.proof.total), root_hash: tx.proof.root_hash, leaf_hash: tx.proof.proof.leaf_hash, aunts: tx.proof.proof.aunts } }),
    blockProof: async () => ({ proof: { view_proof: clone(receipt.anchor) }, signed_header: receipt.signed_header, next_signed_header: receipt.next_signed_header }),
    lightBlock: async () => { throw new ApiFailure('http', { status: 404, code: 'not_found' }); } };
  const p = await openReal(`#/action/${hash}`, api);
  assert.match(p.text(), /account 7 paid account 5 100 h\./);
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.explorer.settled();
  const result = textOf(within(p.view, 'check-result')[0]);
  console.log('check result ->', result.slice(0, 400));
  assert.match(result, /^Checked: this action is in block 1 of the chain\./);
  // What a reader is left with: "account 7 paid account 5 100 h." above, "Checked" below, and no warning.
  assert.match(result, /does NOT agree|could not be compared|not compared|do not rely/i, 'the page must say that the description above was NOT confirmed by the checked bytes');
});

test('F5: a reader whose clock is one minute off (or a node 46 s behind) is told "The check FAILED: the proof ... does not verify"', async () => {
  const api = { ...baseApi(), account: async () => ({ account: { id: '0', name: 'alice' }, proof: { view_proof: clone(proven.proof) }, indexed: { totals: {} } }) };
  const wrong = [];
  for (const skew of [60000, -60000, -15000]) {
    const checker = createChecker({ api, loadTrust: async () => proven.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => proven.now_ms + skew });
    const failure = await checker.checkState(() => api.account(), { names: ['alice'] }).then(() => null, (error) => error);
    console.log(`clock ${skew} ms ->`, failure?.reason, String(failure?.detail).slice(0, 120));
    const p = await openReal('#/account/@alice', api, { now: proven.now_ms + skew });
    console.log('page ->', p.text().slice(0, 200));
    if (/The check FAILED: the proof the service gave for this does not verify/.test(p.text())) wrong.push(skew);
  }
  assert.deepEqual(wrong, [], 'clock off by this many ms: an honest, valid proof is reported as a failed proof');
});

test('F6: a valid proof one block older than what the page has already reached is reported as a FAILED proof', async () => {
  const chain = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
  // The page's light client has reached block 4 (it followed the newest block for some other check).
  const light4 = chain.blocks[3], light3 = chain.blocks[2];
  const api = { lightBlock: async (h) => ({ light_block: chain.blocks[Number(h) - 1] }) };
  const checker = createChecker({ api, loadTrust: async () => chain.trust, loadVerifier: async () => verifier, createLightClient, sdk: SDK, now: () => chain.now_ms });
  // Reach block 4 through a state read whose proof ends at block 4 (its content does not matter here: it fails later, after the light client moved).
  await checker.checkState(async () => ({ proof: { view_proof: { height: '3', entries: [], light_block: light4 } } }), {}).catch(() => {});
  // Now another backend of the same honest service, one block behind, answers with a proof at block 3.
  let asked = 0;
  const failure = await checker.checkState(async () => { asked += 1; return { proof: { view_proof: { height: '2', entries: [], light_block: light3 } } }; }, {}).then(() => null, (error) => error);
  console.log('older proof ->', failure?.reason, String(failure?.detail).slice(0, 100), 'asked', asked, 'times without a pause');
  assert.notEqual(failure?.reason, 'refused', 'an older block is "not usable now", not a proof that fails');
});
