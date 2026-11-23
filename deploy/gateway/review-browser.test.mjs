// Review of the browser-check changes (commit 16d3e5d): the gateway setting `registration_service`.
// validateSettings checks `new URL(value).origin === value`. The URL parser keeps `*`, `;` and `,` in a host
// name, so these pass as "a canonical HTTPS origin", and createV4Servers writes them into the wallet page's
// Content-Security-Policy as they are: `https://*` lets the page connect to any host over https, `;` starts a
// directive of the value's choosing, `,` a second policy. None of them is one service the wallet could ask.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateSettings } from './start.mjs';

const valid = { manifest_file: process.platform === 'win32' ? 'C:\\operator\\manifest.json' : '/operator/manifest.json', manifest_sha256: '01'.repeat(32), native_rpc_url: 'http://127.0.0.1:26657/', data_directory: process.platform === 'win32' ? 'C:\\gateway-data' : '/data/gateway', recipient: '0', wallet_port: 8907, merchant_port: 8908, public_origins: { wallet: 'https://wallet.example', merchant: 'https://app.example' } };

test('registration_service names one host: a wildcard or a policy separator is refused', () => {
  const accepted = [];
  for (const value of ['https://*', 'https://*.example', 'https://faucet.example;sandbox', 'https://faucet.example,default-src']) {
    try { validateSettings({ ...valid, registration_service: value }); accepted.push(value); } catch (error) { assert.match(error.message, /registration_service must/, value); }
  }
  assert.deepEqual(accepted, [], 'validateSettings took these as a canonical HTTPS origin');
});
