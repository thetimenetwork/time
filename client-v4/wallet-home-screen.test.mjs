// The wallet on a phone's Home Screen, as the gateway serves it: the wallet page's policy allows a web app manifest
// from its own origin and changes in nothing else; the shop page's policy is unchanged; the manifest, its icons and the
// service worker are served with their types, and only on the wallet's origin. And the two other policies of both pages:
// what they may use of the browser (Permissions-Policy), and the wallet's tie to a page that opened it
// (Cross-Origin-Opener-Policy), cut everywhere but at /approve, the window a website opens and talks to.
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import http from 'node:http';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createV4Servers } from './server.mjs';

const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const b = fixture.proof.light_block;
const rpc = async (endpoint, p = {}) => {
  if (endpoint === '/commit') return { signed_header: b.signed_header };
  if (endpoint === '/validators') return { block_height: p.height, total: '4', validators: p.height === '6' ? b.validators : b.next_validators };
  if (endpoint === '/abci_query') return { response: { height: '5', code: 0, value: Buffer.from(JSON.stringify({ height: '5', root: b.signed_header.header.app_hash.toLowerCase(), entries: fixture.proof.entries, history_proofs: fixture.proof.history_proofs })).toString('base64') } };
  throw Error('Unexpected RPC');
};
const root = fileURLToPath(new URL('../', import.meta.url));
async function withGateway(work, publicOrigins) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-home-screen-')), originalNow = Date.now;
  let servers = null;
  try {
    Date.now = () => fixture.now_ms;
    servers = await createV4Servers({ root, manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, publicOrigins, walletPort: 0, merchantPort: 0,
      checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), upgradeCheck: { everyMs: 0 } });
    return await work(servers);
  } finally { Date.now = originalNow; await servers?.close(); await rm(directory, { recursive: true, force: true }); }
}
async function get(origin, pathname) {
  const response = await fetch(origin + pathname);
  return { status: response.status, type: response.headers.get('content-type'), policy: response.headers.get('content-security-policy'), opener: response.headers.get('cross-origin-opener-policy'), permissions: response.headers.get('permissions-policy'), bytes: Buffer.from(await response.arrayBuffer()) };
}

const SHOP_POLICY = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const WALLET_POLICY = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; worker-src 'self' blob:; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const NONE = 'accelerometer=(), bluetooth=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=(), xr-spatial-tracking=()';
const WALLET_PERMISSIONS = `${NONE}, publickey-credentials-create=(self), publickey-credentials-get=(self)`;
const SHOP_PERMISSIONS = `${NONE}, publickey-credentials-create=(), publickey-credentials-get=()`;

test('the wallet page alone may load a manifest, from its own origin, and nothing else of either policy changed', async () => {
  await withGateway(async (servers) => {
    const wallet = await get(servers.walletListenOrigin, '/'), shop = await get(servers.merchantListenOrigin, '/');
    assert.deepEqual([wallet.status, shop.status], [200, 200]);
    assert.equal(wallet.policy, WALLET_POLICY);
    assert.equal(shop.policy, SHOP_POLICY);
    assert.equal(wallet.policy.replace(" manifest-src 'self';", ''), shop.policy, 'the one difference is the manifest');
  });
});

test('both pages turn off what they do not use of the browser, and the wallet keeps no tie to an opener but at /approve', async () => {
  await withGateway(async (servers) => {
    const W = servers.walletListenOrigin, S = servers.merchantListenOrigin;
    for (const address of ['/', '/app.js', '/device-check.html', '/api/network', '/approve?x=1', '/nothing']) assert.equal((await get(W, address)).permissions, WALLET_PERMISSIONS, address);
    for (const address of ['/', '/app.js', '/api/config', '/approve']) assert.equal((await get(S, address)).permissions, SHOP_PERMISSIONS, address);
    // The wallet: same-origin on every page and answer, so a site that opened it cannot later send its tab elsewhere.
    for (const address of ['/', '/index.html', '/wallet/', '/device-check.html', '/app.js', '/api/network', '/approve/', '/wallet/approve', '/nothing']) assert.equal((await get(W, address)).opener, 'same-origin', address);
    // Except the window a website opens to ask for a sign-in or a payment: it answers its opener with postMessage.
    for (const address of ['/approve', '/approve?from=shop']) { const page = await get(W, address); assert.deepEqual([page.status, page.opener], [200, null], address); }
    // The blog opens that window and needs its reference to it: it has no opener policy of its own.
    for (const address of ['/', '/api/config']) assert.equal((await get(S, address)).opener, null, address);
  });
});

test('the canonical wallet keeps the manager popup and an approval window still answers its merchant', async () => {
  const wallet = 'https://wallet.testnet.thetimenetwork.org';
  await withGateway(async servers => {
    async function headers(route) {
      return new Promise((resolve, reject) => {
        http.get(servers.walletListenOrigin + route, { headers: { host: new URL(wallet).host } }, response => {
          response.resume();
          response.on('end', () => resolve([response.statusCode, response.headers['cross-origin-opener-policy']]));
        }).on('error', reject);
      });
    }
    assert.deepEqual(await headers('/'), [200, 'same-origin-allow-popups']);
    assert.deepEqual(await headers('/approve'), [200, undefined]);
    assert.deepEqual(await headers('/manager.css'), [404, 'same-origin-allow-popups']);
  }, { wallet, merchant: 'https://blog.testnet.thetimenetwork.org' });
});

test('the manifest, the icons and the service worker are served from the wallet origin with their types, and not from the shop', async () => {
  await withGateway(async (servers) => {
    const files = [
      ['/manifest.webmanifest', 'web-v4/wallet/manifest.webmanifest', 'application/manifest+json'],
      ['/icons/icon-192.png', 'web-v4/wallet/icons/icon-192.png', 'image/png'],
      ['/icons/icon-512.png', 'web-v4/wallet/icons/icon-512.png', 'image/png'],
      ['/icons/apple-touch-icon.png', 'web-v4/wallet/icons/apple-touch-icon.png', 'image/png'],
      ['/sw.js', 'web-v4/wallet/sw.js', 'text/javascript; charset=utf-8'],
      ['/wallet/manifest.webmanifest', 'web-v4/wallet/manifest.webmanifest', 'application/manifest+json'],
    ];
    for (const [address, file, type] of files) {
      const served = await get(servers.walletListenOrigin, address);
      assert.deepEqual([served.status, served.type], [200, type], address);
      assert.ok(served.bytes.equals(await readFile(path.join(root, file))), address);
    }
    for (const address of ['/manifest.webmanifest', '/icons/icon-192.png', '/sw.js']) assert.equal((await get(servers.merchantListenOrigin, address)).status, 404, address);
    // A test of the icons is not a browser asset, any more than the other tests.
    assert.equal((await get(servers.walletListenOrigin, '/icons.test.mjs')).status, 404);
  });
});
