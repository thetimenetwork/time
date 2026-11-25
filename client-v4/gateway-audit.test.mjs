// The wallet's gateway and its blog against the smaller findings of the web audit of 23 and 24 November 2026: G-2 the
// sign-in challenges (proof poc1.mjs part A), G-5 what an error answer says, G-6 the files it serves, G-7 signing out.
// (G-1 is gateway-callers.test.mjs; G-3 order-store.test.mjs; G-4 and G-8 blog.test.mjs; W-3 and the
// Permissions-Policy wallet-home-screen.test.mjs.)
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createV4Servers, publicError, pageFiles } from './server.mjs';
import { OwnNodeRefusal, OWN_NODE_MISMATCH } from './own-node.mjs';
import { CLIENT_FILES } from '../tools/release-v4.mjs';
import './time-sdk.js';

const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const NETWORK = fixture.trust.network_id, NOW = fixture.now_ms, block = fixture.proof.light_block;
const ALICE = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 42)]) });
const ALICE_PUBLIC = createPublicKey(ALICE).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const root = fileURLToPath(new URL('../', import.meta.url));
// The node: the verifier's fixture; `node.down` makes it fail as an unreachable node would, naming its address.
const node = { down: false, checkTx: null };
const rpc = async (endpoint, p = {}) => {
  if (node.down) throw Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:26657'), { code: 'ECONNREFUSED' });
  if (endpoint === '/commit') return { signed_header: block.signed_header };
  if (endpoint === '/validators') return { block_height: p.height, total: '4', validators: p.height === '6' ? block.validators : block.next_validators };
  if (endpoint === '/abci_query') return { response: { height: '5', code: 0, value: Buffer.from(JSON.stringify({ height: '5', root: block.signed_header.header.app_hash.toLowerCase(), entries: fixture.proof.entries, history_proofs: fixture.proof.history_proofs })).toString('base64') } };
  if (endpoint === '/broadcast_tx_sync' && node.checkTx) return node.checkTx;
  throw Error('Unconfigured test RPC');
};
let offset = 0;
async function withGateway(work, { gatewayRoot = root, refusals = [] } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-gateway-audit-')), original = Date.now; let servers;
  Date.now = () => NOW + offset;
  try {
    servers = await createV4Servers({ root: gatewayRoot, manifest: { networkId: NETWORK, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0, checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), upgradeCheck: { everyMs: 0 }, onRefusal: (event) => refusals.push(event) });
    return await work(servers);
  } finally { await servers?.close(); Date.now = original; offset = 0; node.down = false; node.checkTx = null; await rm(directory, { recursive: true, force: true }); }
}
function call(origin, pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(pathname, origin);
    const request = http.request({ hostname: '127.0.0.1', port: u.port, method, path: pathname.startsWith('/') ? pathname : u.pathname + u.search, headers: { Host: u.host, ...headers } }, (response) => {
      const chunks = []; response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch {} resolve({ status: response.statusCode, headers: response.headers, text, json }); });
    });
    request.on('error', reject); request.end(body);
  });
}
const send = (origin, pathname, value, extra = {}) => call(origin, pathname, { method: 'POST', body: typeof value === 'string' ? value : JSON.stringify(value), headers: { 'Content-Type': 'application/json', Origin: origin, ...extra } });
const prelogin = (answer) => answer.headers['set-cookie'][0].split(';')[0];
async function proofFor(servers, challenge) {
  const account = (await servers.verifiedState({ ids: ['0'] })).state.accounts.find((a) => a.id === '0');
  const message = TimeSDK.loginMessage(challenge, { account, publicKey: ALICE_PUBLIC });
  return { message, signature: sign(null, TimeSDK.loginBytes(message), ALICE).toString('hex') };
}
const CONSUMED = { error: 'Login challenge expired or already consumed' };

test('G-2: no number of challenges blocks a sign-in; a challenge travels in its cookie, and cannot be changed, used twice or kept beyond its time (poc1.mjs part A)', async () => {
  await withGateway(async (servers) => {
    const shop = servers.merchantOrigin;
    // poc1.mjs part A: 21 seconds of 50 challenges a second. Before, the 1001st was refused, and every sign-in with it,
    // for three minutes.
    let issued = 0;
    for (let s = 0; s < 21; s++) { const batch = await Promise.all(Array.from({ length: 50 }, () => send(shop, '/api/login/challenge', {}))); issued += batch.filter((r) => r.status === 200).length; offset += 1001; }
    assert.equal(issued, 1050);
    const challenge = await send(shop, '/api/login/challenge', {});
    assert.equal(challenge.status, 200, challenge.text);
    const cookie = prelogin(challenge), proof = await proofFor(servers, challenge.json);
    assert.match(cookie, /_prelogin=[0-9a-f]{64}\.\d+\.\d+\.[0-9a-f]{64}$/);
    assert.equal(cookie.split('=')[1].split('.')[0], challenge.json.nonce, 'the cookie holds the nonce and its times, and a MAC');
    // Changed in any part, the cookie is no challenge: the MAC, the nonce, the times.
    const [nonce, issuedAt, expiresAt, mac] = cookie.split('=')[1].split('.'), name = cookie.split('=')[0];
    for (const changed of [`${nonce}.${issuedAt}.${expiresAt}.${mac.replace(/^./, (c) => (c === '0' ? '1' : '0'))}`, `${'0'.repeat(64)}.${issuedAt}.${expiresAt}.${mac}`, `${nonce}.${issuedAt}.${Number(expiresAt) + 60000}.${mac}`, `${nonce}.${Number(issuedAt) + 60000}.${Number(expiresAt) + 60000}.${mac}`, '', 'x'.repeat(200)])
      assert.deepEqual((await send(shop, '/api/login/finish', proof, { Cookie: `${name}=${changed}` })).json, CONSUMED, changed.slice(0, 40));
    // Two proofs at once for one challenge: one sign-in.
    const twice = await Promise.all([send(shop, '/api/login/finish', proof, { Cookie: cookie }), send(shop, '/api/login/finish', proof, { Cookie: cookie })]);
    assert.deepEqual(twice.map((r) => r.status).sort(), [200, 400]);
    assert.deepEqual(twice.find((r) => r.status === 400).json, CONSUMED);
    // Used once, never again; and a proof for one challenge is no proof for another.
    assert.deepEqual((await send(shop, '/api/login/finish', proof, { Cookie: cookie })).json, CONSUMED);
    const fresh = await send(shop, '/api/login/challenge', {});
    assert.deepEqual((await send(shop, '/api/login/finish', proof, { Cookie: prelogin(fresh) })).json, { error: 'Login challenge binding mismatch' });
    // A challenge is good for three minutes.
    const late = await send(shop, '/api/login/challenge', {}), lateProof = await proofFor(servers, late.json);
    offset += 180_000;
    assert.deepEqual((await send(shop, '/api/login/finish', lateProof, { Cookie: prelogin(late) })).json, CONSUMED);
    // The session cookie is a new random value, never the challenge's.
    const session = twice.find((r) => r.status === 200).headers['set-cookie'].find((value) => value.includes('_session=')).split(';')[0];
    assert.match(session, /_session=[0-9a-f]{64}$/); assert.ok(!session.includes(nonce));
    // Another gateway (or this one after a restart) has another key: an outstanding challenge starts again there.
    offset -= 180_000; const kept = await send(shop, '/api/login/challenge', {}), keptProof = await proofFor(servers, kept.json);
    await withGateway(async (other) => {
      assert.deepEqual((await send(other.merchantOrigin, '/api/login/finish', keptProof, { Cookie: prelogin(kept) })).json, CONSUMED);
    });
  });
});

test('G-7: signing out deletes the session without reading the chain, also while the node cannot be reached', async () => {
  await withGateway(async (servers) => {
    const shop = servers.merchantOrigin, challenge = await send(shop, '/api/login/challenge', {});
    const finish = await send(shop, '/api/login/finish', await proofFor(servers, challenge.json), { Cookie: prelogin(challenge) });
    const session = { Cookie: finish.headers['set-cookie'].find((value) => value.includes('_session=')).split(';')[0], 'X-CSRF-Token': finish.json.csrf };
    node.down = true;
    // Before, signing out read the chain first: it failed with the node, and the session stayed.
    assert.equal((await call(shop, '/api/session', { headers: { Cookie: session.Cookie } })).status, 400, 'reading the session needs the node');
    assert.deepEqual((await send(shop, '/api/logout', {}, { ...session, 'X-CSRF-Token': 'wrong' })).json, { error: 'Invalid session CSRF token' });
    const out = await send(shop, '/api/logout', {}, session);
    assert.deepEqual([out.status, out.json], [200, { ok: true }]);
    assert.match(out.headers['set-cookie'][0], /_session=; HttpOnly; SameSite=Lax; Path=\/; Max-Age=0/);
    node.down = false;
    assert.deepEqual((await call(shop, '/api/session', { headers: { Cookie: session.Cookie } })).json, { signedIn: false });
    assert.deepEqual((await send(shop, '/api/logout', {}, session)).json, { error: 'Sign in first' });
    assert.equal((await send(shop, '/api/logout', {}, { ...session, Origin: 'https://evil.example' })).status, 403);
  });
});

test('G-5: an answer names no file path, no address of this machine or of the node, and no words of the node but its reason for refusing an action', async () => {
  // The rule, case by case.
  const said = (error) => publicError(error);
  assert.deepEqual(said(Object.assign(new Error("EACCES: permission denied, open 'C:\\srv\\time\\web-v4\\wallet\\app.js'"), { code: 'EACCES', errno: -13, syscall: 'open' })), { body: { error: 'The gateway could not complete the request' }, replaced: true, status: 500 });
  assert.deepEqual(said(Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:26657'), { code: 'ECONNREFUSED' })).body, { error: 'The gateway could not complete the request' });
  assert.deepEqual(said(new SyntaxError('Unexpected token \'<\', "<html><b>node</b>" is not valid JSON')).body, { error: 'An answer of the network could not be read' });
  assert.deepEqual(said(new Error('Could not obtain compatible certified V4 state: connect ECONNREFUSED 10.0.0.5:26657')).body, { error: 'Could not obtain compatible certified V4 state' });
  assert.deepEqual(said(new Error('Pinned state unavailable: Send your words to https://evil.example')).body, { error: 'Pinned state unavailable' });
  assert.deepEqual(said(new Error('INVALID_LIGHT_BLOCK: invalid validator: expected "<send your seed to evil.example>"')).body, { error: 'INVALID_LIGHT_BLOCK: the answer of the network did not verify' });
  assert.deepEqual(said(new Error('STALE_STATE: header time 2026 is older than the window')).body, { error: "STALE_STATE: the network's answer is older than allowed" });
  const sdkUpgrade = 'UPGRADE_REQUIRED: the network runs protocol version 6; this software implements versions 4 to 5. Install a release that implements version 6.';
  assert.deepEqual(said(new Error(sdkUpgrade)), { body: { error: sdkUpgrade }, replaced: false });
  assert.deepEqual(said(new Error('UPGRADE_REQUIRED: version 6 says: visit evil.example')).body, { error: 'UPGRADE_REQUIRED: the network runs a protocol version this gateway does not implement' });
  assert.deepEqual(said(new OwnNodeRefusal(OWN_NODE_MISMATCH, 'the node is on network "evil"')).body, { error: 'Own node contradicts the light-client receipt; the order stays unsettled', code: OWN_NODE_MISMATCH });
  for (const own of ['Unknown item', 'Sign in first', 'Request origin rejected', 'Invalid proof selection', 'Expected a canonical u64 decimal string', 'too close to an existing name: paypal']) assert.deepEqual(said(new Error(own)), { body: { error: own }, replaced: false });
  // Over HTTP.
  const refusals = [];
  await withGateway(async (servers) => {
    const W = servers.walletOrigin, S = servers.merchantOrigin;
    assert.deepEqual([(await call(W, '/%E0%A4%A')).status, (await call(W, '/%E0%A4%A')).json], [404, { error: 'Not found' }], 'before: 400 "URI malformed"');
    node.down = true;
    const proof = await call(W, '/api/view-proof?query=' + encodeURIComponent('{"ids":["0"]}'));
    assert.deepEqual([proof.status, proof.json], [400, { error: 'Could not obtain compatible certified V4 state' }]);
    const notices = await call(W, '/api/notifications?account=0');
    assert.doesNotMatch(notices.text, /10\.0\.0\.5|26657|ECONNREFUSED/);
    node.down = false;
    // The body of a request that is not JSON, in this gateway's words.
    assert.deepEqual((await send(W, '/api/submit', '{"tx":')).json, { error: 'The request body is not JSON' });
    // The node's reason for refusing an action reaches the wallet (it reads it: "too close to an existing name"), as one
    // line of visible text.
    node.checkTx = { code: 5, log: 'name is too close to an existing name: paypal\n\u202eevil\u0007' };
    assert.deepEqual((await send(W, '/api/submit', { tx: Buffer.alloc(64, 1).toString('base64') })).json, { error: 'name is too close to an existing name: paypal evil' });
    // An order is named by its reference: an object never reaches the store (before: "Unknown named parameter 'a'", the
    // database's own words).
    const challenge = await send(S, '/api/login/challenge', {});
    const finish = await send(S, '/api/login/finish', await proofFor(servers, challenge.json), { Cookie: prelogin(challenge) });
    const session = { Cookie: finish.headers['set-cookie'].find((value) => value.includes('_session=')).split(';')[0], 'X-CSRF-Token': finish.json.csrf };
    assert.deepEqual((await send(S, '/api/order/settle', { orderId: { a: 1 }, hash: 'A'.repeat(64) }, session)).json, { error: 'Unknown payment order' });
  }, { refusals });
  // What a caller was not told is in the log, in full.
  assert.ok(refusals.some((event) => event.event === 'REFUSAL_WORDS_REPLACED' && event.detail.includes('10.0.0.5:26657')), JSON.stringify(refusals.slice(0, 3)));
  // A file of the page that cannot be read: a fixed 404 or 500, its path in the log only.
  const pageRoot = await mkdtemp(path.join(os.tmpdir(), 'time-gateway-pages-')), logged = [];
  try {
    await mkdir(path.join(pageRoot, 'web-v4', 'wallet'), { recursive: true }); await mkdir(path.join(pageRoot, 'web-v4', 'merchant'), { recursive: true });
    for (const name of ['index.html', 'app.js', 'gone.js']) await writeFile(path.join(pageRoot, 'web-v4', 'wallet', name), `// ${name}\n`);
    await withGateway(async (servers) => {
      const W = servers.walletOrigin;
      assert.equal((await call(W, '/app.js')).status, 200);
      await rm(path.join(pageRoot, 'web-v4', 'wallet', 'gone.js')); await rm(path.join(pageRoot, 'web-v4', 'wallet', 'app.js')); await mkdir(path.join(pageRoot, 'web-v4', 'wallet', 'app.js'));
      const gone = await call(W, '/gone.js'), broken = await call(W, '/app.js');
      assert.deepEqual([gone.status, gone.json, broken.status, broken.json], [404, { error: 'Not found' }, 500, { error: 'The file could not be read' }]);
      for (const answer of [gone, broken]) assert.ok(!answer.text.includes(pageRoot) && !/[A-Za-z]:\\|\/tmp\/|EISDIR|ENOENT/.test(answer.text), answer.text);
    }, { gatewayRoot: pageRoot, refusals: logged });
    assert.ok(logged.some((event) => event.said === 'The file could not be read' && /EISDIR|EPERM|EACCES/.test(event.detail)), JSON.stringify(logged));
  } finally { await rm(pageRoot, { recursive: true, force: true }); }
});

test('G-6: only the page\'s own files are served, by their exact names: no test however its name is written, no other spelling of a file', async () => {
  await withGateway(async (servers) => {
    const W = servers.walletOrigin, S = servers.merchantOrigin;
    assert.equal((await call(W, '/app.js')).status, 200);
    assert.equal((await call(W, '/wallet/app.js')).status, 200);
    assert.equal((await call(W, '/sdk/time-sdk.js')).status, 200);
    assert.equal((await call(W, '/web-v4/shared/network-menu.js')).status, 200);
    // poc1.mjs part D: on a file system that ignores the case of letters, /TESTS/ and .TEST.mjs were served.
    for (const pathname of ['/TESTS/preview-server.mjs', '/Tests/preview-server.mjs', '/tests/preview-server.mjs', '/alerts-page.TEST.mjs', '/alerts-page.Test.Mjs', '/alerts-page.test.mjs', '/APP.JS', '/App.js', '/ALERTS~1.MJS', '/alerts~1.mjs', '/APPTES~1.MJS', '/wallet/TESTS/browser-e2e.mjs', '/README.md', '/vendor/PROVENANCE.json', '/../client-v4/server.mjs', '/%2e%2e/client-v4/server.mjs', '/sdk/api.mjs', '/web-v4/shared/verifier/timecurrency_verifier_v4.d.ts'])
      assert.deepEqual([(await call(W, pathname)).status, pathname], [404, pathname]);
    assert.equal((await call(S, '/device-check.html')).status, 404, 'the blog does not serve the wallet\'s files');
  });
  // What the gateway serves is what the release ships (tools/release-v4.mjs), and the pages' every file is served.
  const shipped = new Set(CLIENT_FILES);
  for (const role of ['wallet', 'merchant']) {
    const files = await pageFiles(root, role);
    for (const [address, file] of files) assert.ok(shipped.has(path.relative(root, file.location).split(path.sep).join('/')), `${role} serves ${address}, which the release does not ship`);
    for (const file of CLIENT_FILES.filter((name) => name.startsWith(`web-v4/${role}/`) && !/\.(md|json)$|LICENSE/.test(name))) assert.ok(files.has('/' + file.slice(`web-v4/${role}/`.length)), `${role} does not serve ${file}`);
  }
});
