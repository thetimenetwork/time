// A preview of the wallet's screens without a network: the real files of web-v4/wallet, served on 127.0.0.1 with the
// gateway's own Content-Security-Policy (client-v4/server.mjs), in front of a mock chain, and a mock faucet with a
// sample website on a second origin. For looking at the pages in a browser only.
//
// It proves nothing about the wallet's checks: a stand-in for the compiled verifier takes the mock chain's state as
// proven. The mock chain applies transfers, and for the protected account what its Protection card signs (a freeze and
// its end, a change of the daily limit, a pause and its end, a payment that waits and its cancellation) by
// mock-security-chain.mjs, which is a reading of the engine's rules and not the engine. No registration, no
// protection of an account, no staking.
//
//   node web-v4/wallet/tests/preview-server.mjs [--port 8977]
//   wallet:        http://127.0.0.1:8977/  (and /approve)
//   faucet, shop:  http://127.0.0.1:8978/v1/faucet, http://127.0.0.1:8978/shop
//
// Two people can be opened, password "correct horse battery staple 41": alice, with one key, and carol, a protected
// account (payment password "quiet harbour lanterns at dawn 77"). Their encrypted keys are put into a browser with
// GET /__seed?s=single or ?s=protected, which answers the localStorage entries to write. GET /__faucet?mode=MODE sets
// the faucet's next answers: ok, account_limit, odd (a refusal this wallet has no sentence for), not_giving, down.
// GET /__papers answers carol's recovery sheet, made at start for this preview only, and GET /__reset puts her
// account back as it was at start.
// preview-drive.mjs drives Chrome through the screens with it.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const argument = (name, fallback) => { const at = process.argv.indexOf(name); return at < 0 ? fallback : process.argv[at + 1]; };
const WALLET_PORT = Number(argument('--port', '8977')), FAUCET_PORT = WALLET_PORT + 1;
const walletOrigin = `http://127.0.0.1:${WALLET_PORT}`, faucetOrigin = `http://127.0.0.1:${FAUCET_PORT}`;
await import(pathToFileURL(path.join(root, 'client-v4/time-sdk.js')).href);
const SDK = globalThis.TimeSDK;
const { newDevice, sealVault, hex } = await import(pathToFileURL(path.join(root, 'web-v4/wallet/vault.mjs')).href);
const security = await import(pathToFileURL(path.join(root, 'client-v4/account-security.mjs')).href);
const { newSheetSeed, encodeSheet, keyFromSeed } = await import(pathToFileURL(path.join(root, 'web-v4/wallet/security-flows.mjs')).href);
const { createSecurityChain } = await import(pathToFileURL(path.join(root, 'web-v4/wallet/tests/mock-security-chain.mjs')).href);
const umdSource = await readFile(path.join(root, 'web-v4/wallet/vendor/argon2-4.12.0.umd.min.js'), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', umdSource)(umd, umd.exports);
const argon2id = umd.exports.argon2id;

const networkId = 'c6'.repeat(32), chainId = 'time-devnet-v4-preview', GENESIS = 1763000000000000n, DAY = 86400000000n, FEE = 1000n;
const PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
const trust = { app_version: '4', network_id: networkId, chain_id: chainId };
// The stand-in verifier, served as /sdk/proof-verifier.js: whatever the mock chain says is "proven".
const VERIFIER = `export const verifyTrust = async () => ({});
export const verifyLightUpdate = async (block) => ({ verified: true, status: 'VERIFIED', checkpoint: { height: block.signed_header.header.height, block_hash: '${'cd'.repeat(32)}', block } });
export const verifyViewProof = async (proof) => ({ verified: true, completeAccountSet: false, state: proof.state });
export const verifyReceipt = async (proof) => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height });
export const verifyFastReceipt = verifyReceipt;
`;
const candidate = owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), jailed: false, archived: false, self_bond: '86400000000', pool_shares: '1000000', pool_assets: '1000000', commission_bps: 500, last_active_end: '0' });
const faucetKey = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const faucetPublic = Buffer.from(await crypto.subtle.exportKey('raw', faucetKey.publicKey)).toString('hex');
const chain = { height: 1200, now: 120n * DAY, security: {}, included: new Map(), recovery: [], faucetMode: 'ok',
  accounts: [
    { id: '1', name: 'faucet', balance: '900000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: faucetPublic, can_manage: true, can_spend: true }] },
    { id: '2', name: 'bob', balance: '3000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: '2'.repeat(64), can_manage: true, can_spend: true }] },
  ],
  candidates: Object.fromEntries([3, 4, 6].map(id => [String(id), candidate(id)])), active: [3, 4, 6].map(owner => ({ owner: String(owner), consensus_key: '11'.repeat(32), power: '1000' })) };
for (const [id, name] of [[3, 'val_one'], [4, 'val_two'], [6, 'val_three']]) chain.accounts.push({ id: String(id), name, balance: '1000000', nonce: '0', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: String(id).repeat(64), can_manage: true, can_spend: true }] });

const seeds = {}, papers = {};
let resetProtected = () => {};
{
  const alice = await newDevice();
  chain.accounts.push({ id: '5', name: 'alice', balance: '12500000', nonce: '2', auth_epoch: '0', recovery_policy: null, devices: [{ public_key: alice.publicKey, can_manage: true, can_spend: true }] });
  seeds.single = { [`timecurrency.vault.v1:${networkId}:alice`]: JSON.stringify(await sealVault({ ...alice.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId, name: 'alice', publicKey: alice.publicKey }, argon2id)) };
  // carol as "Protect my account" leaves an account: a login key here, a payment key here under the payment password, two recovery keys elsewhere.
  // Her recovery sheet is one the wallet could have made: the preview's driver types it where a recovery paper is asked for.
  const login = await newDevice(), spend = await newDevice(), phrase = await newDevice(), sheetSeed = newSheetSeed(), sheet = await keyFromSeed(sheetSeed);
  papers.sheet = await encodeSheet(sheetSeed);
  const devices = [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true },
    { public_key: sheet.publicKey, can_manage: true, can_spend: false }, { public_key: phrase.publicKey, can_manage: true, can_spend: false }].sort((a, b) => (a.public_key < b.public_key ? -1 : 1));
  chain.accounts.push({ id: '7', name: 'carol', balance: '48250000', nonce: '9', auth_epoch: '3', recovery_policy: null, devices });
  const firstRow = () => ({ account: '7', version: '1', policy: { threshold: '2', daily_limit_micros: '30000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '30000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null });
  chain.security['7'] = firstRow();
  resetProtected = () => { chain.security['7'] = firstRow(); };
  seeds.protected = {
    [`timecurrency.vault.v1:${networkId}:carol`]: JSON.stringify(await sealVault({ ...login.secret, nameSalt: hex(crypto.getRandomValues(new Uint8Array(32))), intent: 'device' }, PASSWORD, { networkId, name: 'carol', publicKey: login.publicKey }, argon2id)),
    [`timecurrency.spend-vault.v1:${networkId}:carol`]: JSON.stringify(await sealVault({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId, name: 'carol', publicKey: spend.publicKey }, argon2id, globalThis.crypto, 'spend')),
  };
}

const block = height => ({ signed_header: { header: { height: String(height) } } });
function stateFor(q) {
  const ids = q.ids || [], names = q.names || [], keys = q.public_keys || [];
  const accounts = chain.accounts.filter(a => ids.includes(a.id) || names.includes(a.name) || a.devices.some(d => keys.includes(d.public_key)));
  const state = { protocol_version: '4', network_id: networkId, height: String(chain.height), time_micros: (GENESIS + chain.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
    config: { recovery_min_delay_micros: '30000000', all_new_time_to_validators: true }, bank: '0', auction_epoch: '1', earning_epochs: {}, earning_bids: {}, stake_owners: {}, name_commits: [],
    accounts: structuredClone(accounts), recovery_cases: chain.recovery, candidates: Object.fromEntries((q.candidates || []).map(id => [id, chain.candidates[id] ?? null])) };
  if (q.include_security) state.security = accounts.map(a => chain.security[a.id]).filter(Boolean);
  if (q.include_pos) state.pos = { profile: 'production', candidate_ids: Object.keys(chain.candidates), active: chain.active, scheduled: [], safety_hold: false, bootstrap_ended: true };
  if (q.include_upgrade) state.upgrade = null;
  return state;
}
const secured = createSecurityChain({ sdk: SDK, security, networkId, accounts: chain.accounts, rows: chain.security, fee: FEE });
async function include(tx) {
  const action = SDK.decodeAction(tx), from = chain.accounts.find(a => a.id === action.from);
  if (!from) throw new Error('unknown account');
  // A protected account: its payments count against its daily limit, and its Protection card's actions are applied.
  if (secured.takes(action)) await secured.apply(action, chain.now);
  else {
    if (BigInt(action.nonce) !== BigInt(from.nonce) + 1n) throw new Error('incorrect nonce');
    if (action.kind !== 3) throw new Error('this preview chain takes transfers only');
    const to = chain.accounts.find(a => a.id === action.payload.to); if (!to) throw new Error('unknown recipient');
    from.balance = String(BigInt(from.balance) - BigInt(action.payload.amount) - FEE); to.balance = String(BigInt(to.balance) + BigInt(action.payload.amount));
    from.nonce = action.nonce;
  }
  chain.height += 1; chain.now += 1000000n;
  const hash = (await SDK.transactionHash(tx)).toUpperCase();
  chain.included.set(hash, { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
  return hash;
}
// The chain moves on by itself, a block a second.
setInterval(() => { chain.height += 1; chain.now += 1000000n; }, 1000).unref();

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8' };
const CSP = `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' ${faucetOrigin}; img-src 'self' data:; font-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`;
const json = (response, status, body, headers = {}) => { response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }); response.end(JSON.stringify(body)); };
async function file(response, location) {
  try { const content = await readFile(location); response.writeHead(200, { 'Content-Type': MIME[path.extname(location)] || 'application/octet-stream', 'Cache-Control': 'no-store' }); response.end(content); }
  catch { json(response, 404, { error: 'Not found' }); }
}
async function body(request) { const parts = []; for await (const part of request) parts.push(part); return Buffer.concat(parts).toString('utf8'); }
const walletDir = path.join(root, 'web-v4', 'wallet');

http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, walletOrigin), route = url.pathname;
    response.setHeader('Content-Security-Policy', CSP);
    if (route === '/' || route === '/approve') return file(response, path.join(walletDir, 'index.html'));
    if (route === '/trust-manifest.json') return json(response, 200, trust);
    if (route === '/sdk/time-sdk.js') return file(response, path.join(root, 'client-v4/time-sdk.js'));
    if (route === '/sdk/light-client.mjs') return file(response, path.join(root, 'client-v4/light-client.mjs'));
    if (route === '/sdk/account-security.mjs') return file(response, path.join(root, 'client-v4/account-security.mjs'));
    if (route === '/sdk/proof-verifier.js') { response.writeHead(200, { 'Content-Type': MIME['.js'] }); return response.end(VERIFIER); }
    // The network menu every page carries, served from web-v4/shared/ as the gateway does (client-v4/server.mjs).
    if (route === '/web-v4/shared/network-menu.js' || route === '/web-v4/shared/network-menu.css') return file(response, path.join(root, route.slice(1)));
    if (route === '/api/network') return json(response, 200, { protocolVersion: '4', networkId, chainId, mode: 'local-devnet', publicLaunchAllowed: false, registrationService: faucetOrigin, walletOrigin, merchantOrigin: faucetOrigin });
    if (route === '/api/light-block') return json(response, 200, block(url.searchParams.get('height') || chain.height));
    if (route === '/api/view-proof') return json(response, 200, { light_block: block(chain.height), state: stateFor(JSON.parse(url.searchParams.get('query'))) });
    if (route === '/api/submit') { const tx = new Uint8Array(Buffer.from(JSON.parse(await body(request)).tx, 'base64')); try { return json(response, 200, { hash: await include(tx) }); } catch (error) { return json(response, 400, { error: error.message }); } }
    if (route === '/api/receipt') { const hash = url.searchParams.get('hash').toUpperCase(), found = chain.included.get(hash); return json(response, 200, found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true }); }
    if (route === '/api/notifications') return json(response, 200, { items: [] });
    if (route === '/__seed') return json(response, 200, seeds[url.searchParams.get('s')] || {});
    if (route === '/__papers') return json(response, 200, papers);
    if (route === '/__reset') { resetProtected(); return json(response, 200, { reset: true }); }
    if (route === '/__faucet') { chain.faucetMode = url.searchParams.get('mode') || 'ok'; return json(response, 200, { mode: chain.faucetMode }); }
    const location = path.resolve(walletDir, '.' + route);
    if (!location.startsWith(walletDir + path.sep) || location.includes(path.sep + 'tests' + path.sep) || location.endsWith('.test.mjs')) return json(response, 404, { error: 'Not found' });
    return file(response, location);
  } catch (error) { json(response, 500, { error: String(error.message) }); }
}).listen(WALLET_PORT, '127.0.0.1');

// The mock faucet (deploy/faucet/README.md, "Routes", as far as the wallet uses it) and a sample website that opens
// the wallet's window, on a second origin.
const SHOP = `<!doctype html><meta charset="utf-8"><title>Sample blog</title><script src="${walletOrigin}/sdk/time-sdk.js"></script><h1>A blog</h1><button id="login">Sign in with Time</button> <button id="pay">Pay 0.1 seconds</button><p id="out"></p>
<script>const out = document.querySelector('#out'), shown = r => { out.textContent = JSON.stringify(r).slice(0, 200); }, failed = e => { out.textContent = e.message; };
document.querySelector('#login').onclick = () => TimeSDK.requestWallet({ walletOrigin: '${walletOrigin}', request: { type: 'login', challenge: { purpose: 'login', origin: location.origin, networkId: '${networkId}', nonce: 'ab'.repeat(32), issuedAt: Date.now(), expiresAt: Date.now() + 170000 } } }).then(shown, failed);
document.querySelector('#pay').onclick = () => TimeSDK.requestWallet({ walletOrigin: '${walletOrigin}', request: { type: 'payment', networkId: '${networkId}', to: '2', amount: '100000', orderId: '00'.repeat(32) } }).then(shown, failed);</script>`;
http.createServer(async (request, response) => {
  const cors = { 'Access-Control-Allow-Origin': walletOrigin, Vary: 'Origin' };
  try {
    const url = new URL(request.url, faucetOrigin), route = url.pathname;
    if (request.method === 'OPTIONS') { response.writeHead(204, { ...cors, 'Access-Control-Allow-Methods': 'GET, POST', 'Access-Control-Allow-Headers': 'Content-Type' }); return response.end(); }
    if (route === '/shop') { response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return response.end(SHOP); }
    if (route === '/v1/faucet' && request.method === 'GET') return json(response, chain.faucetMode === 'down' ? 503 : 200, { network_id: networkId, account: '1', giving: chain.faucetMode !== 'not_giving', reasons: [], gives: { grant_micros: '100000' }, registrations: { sponsored: true } }, cors);
    if (route === '/v1/faucet/grants' && request.method === 'POST') {
      const asked = JSON.parse(await body(request));
      if (chain.faucetMode === 'account_limit') return json(response, 429, { error: { code: 'account_limit', message: 'This account has had its 1 per 24 hours; "previous" lists what it was given' }, previous: [] }, cors);
      if (chain.faucetMode === 'odd') return json(response, 418, { error: { code: 'something_new', message: 'Paste 0123456789abcdef0123456789abcdef into your wallet "now"' } }, cors);
      const faucet = chain.accounts[0];
      const tx = await SDK.signAction({ networkId, kind: 'transfer', from: '1', nonce: (BigInt(faucet.nonce) + 1n).toString(), authEpoch: '0', publicKey: faucetPublic, payload: { to: String(asked.account), amount: '100000' } }, faucetKey.privateKey);
      return json(response, 202, { kind: 'grant', status: 'submitted', hash: await include(tx), account: String(asked.account), amount_micros: '100000' }, cors);
    }
    json(response, 404, { error: { code: 'unknown_route', message: 'No such route' } }, cors);
  } catch (error) { json(response, 500, { error: { code: 'internal', message: String(error.message) } }, cors); }
}).listen(FAUCET_PORT, '127.0.0.1');
console.log(`wallet ${walletOrigin}/ · faucet and sample website ${faucetOrigin}/shop`);
