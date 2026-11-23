// A test network reset under an open page (check.mjs, 'network_reset'): a new chain under the same addresses. The page
// still checks against the trust it loaded first, so every check fails. Before a failure is reported, the trust manifest
// is read again; when it names another network, the failure is 'network_reset' (the page says "The test network was
// reset. Reload this page."). The manifest is read again at most once every half minute, and only after a failure.
import test from 'node:test';
import assert from 'node:assert/strict';
import '../../client-v4/time-sdk.js';
import { createChecker, CheckFailure } from './check.mjs';

const SDK = globalThis.TimeSDK, OLD = 'a1'.repeat(32), NEW = 'b2'.repeat(32);
const trustOf = (networkId) => ({ app_version: '4', network_id: networkId, chain_id: 'time-devnet-v4-test' });
/// A checker over a verifier that runs, and a light client whose trusted block no longer verifies: the failure a page
/// open across a reset meets first. `served` is the network of the manifest the page's origin serves now.
function world() {
  const state = { served: OLD, reads: 0, clock: 1000000 };
  const checker = createChecker({
    api: { lightBlock: async () => { throw new Error('not asked'); } },
    sdk: SDK,
    now: () => state.clock,
    loadTrust: async () => { state.reads += 1; return trustOf(state.served); },
    loadVerifier: async () => ({ verifyTrust: async () => { throw new Error('INVALID_JSON: not a trust'); }, verifyLightUpdate() {}, verifyViewProof() {}, verifyReceipt() {}, verifyFastReceipt() {} }),
    createLightClient: async () => ({ ready: async () => { throw new Error('TRUST_EXPIRED: the trusted block is older than the trusting period'); }, getCheckpoint: () => null }),
  });
  return { state, checker };
}
const failsWith = (reason) => (error) => error instanceof CheckFailure && error.reason === reason;

test('the same network: the failure is said as before, and the manifest is read again at most once every half minute', async () => {
  const { state, checker } = world();
  await assert.rejects(checker.checkState(async () => ({}), {}), failsWith('trust_expired'));
  assert.equal(state.reads, 2, 'loaded once, and read again once after the failure');
  await assert.rejects(checker.checkState(async () => ({}), {}), failsWith('trust_expired'));
  assert.equal(state.reads, 2, 'not again within half a minute');
  state.clock += 30000;
  await assert.rejects(checker.checkAction('AB'.repeat(32)), failsWith('trust_expired'));
  assert.equal(state.reads, 3);
});

test('the site now serves another network: the failure is "network_reset", and stays so', async () => {
  const { state, checker } = world();
  await assert.rejects(checker.checkState(async () => ({}), {}), failsWith('trust_expired'));
  state.served = NEW; state.clock += 30000;
  await assert.rejects(checker.checkState(async () => ({}), {}), failsWith('network_reset'));
  await assert.rejects(checker.checkAction('AB'.repeat(32)), failsWith('network_reset'));
  // The service already answers for the new network: the page's own "wrong network" becomes the reset too.
  const other = world();
  assert.equal((await other.checker.trust()).networkId, OLD, 'the page loaded the old manifest');
  other.checker.expectNetwork(NEW); other.state.served = NEW;
  await assert.rejects(other.checker.checkState(async () => ({}), {}), failsWith('network_reset'));
  // Without the reset the same answer of the service is "wrong network", as before.
  const kept = world(); await kept.checker.trust(); kept.checker.expectNetwork(NEW);
  await assert.rejects(kept.checker.checkState(async () => ({}), {}), failsWith('wrong_network'));
});
