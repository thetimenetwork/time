// The gateway's optional `registrationService`: where a wallet page can have the registration of
// a new account sponsored (the faucet of a test network). The gateway holds no key for it and never
// calls it: it tells the wallet page the origin and lets that one page connect there.
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
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
async function withGateway(options, work) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-registration-service-')), originalNow = Date.now;
  let servers = null;
  try {
    Date.now = () => fixture.now_ms;
    servers = await createV4Servers({ root: fileURLToPath(new URL('../', import.meta.url)), manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0,
      checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), ...options });
    return await work(servers);
  } finally { Date.now = originalNow; await servers?.close(); await rm(directory, { recursive: true, force: true }); }
}
const connectSources = (csp) => /connect-src ([^;]*);/.exec(csp)?.[1];

test('a gateway that names a registration service tells the wallet page its origin and lets that page, and only it, connect there', async () => {
  await withGateway({ registrationService: 'https://faucet.example' }, async (servers) => {
    const network = await (await fetch(`${servers.walletListenOrigin}/api/network`)).json();
    assert.equal(network.registrationService, 'https://faucet.example');
    assert.equal(network.sponsorAccount, undefined, 'a gateway without a sponsor key names no sponsor account');
    const wallet = await fetch(`${servers.walletListenOrigin}/`), merchant = await fetch(`${servers.merchantListenOrigin}/`);
    await wallet.arrayBuffer(); await merchant.arrayBuffer();
    assert.equal(connectSources(wallet.headers.get('content-security-policy')), "'self' https://faucet.example");
    assert.equal(connectSources(merchant.headers.get('content-security-policy')), "'self'", 'the shop page gets no way to the registration service');
    // Nothing else of the page's policy changed: scripts still come from the page's own origin only.
    assert.match(wallet.headers.get('content-security-policy'), /^default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src /);
    // The gateway offers no sponsorship of its own.
    const refused = await fetch(`${servers.walletListenOrigin}/api/sponsor-registration`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: servers.walletOrigin }, body: JSON.stringify({ public_key: 'aa'.repeat(32), commitment: 'bb'.repeat(32), expires_elapsed_micros: '1', proof: 'cc'.repeat(64) }) });
    assert.ok(refused.status >= 400, 'the gateway sponsored a registration without a key');
    assert.match(await refused.text(), /sponsor is not configured/);
  });
});

test('without the option nothing changes: no origin in the network answer, and the wallet page connects to itself only', async () => {
  await withGateway({}, async (servers) => {
    const network = await (await fetch(`${servers.walletListenOrigin}/api/network`)).json();
    assert.equal('registrationService' in network, false);
    const wallet = await fetch(`${servers.walletListenOrigin}/`);
    await wallet.arrayBuffer();
    assert.equal(connectSources(wallet.headers.get('content-security-policy')), "'self'");
  });
});

test('the registration service is a canonical HTTPS origin, or plain HTTP on the loopback address for tests; anything else is refused before a server starts', async () => {
  const base = { root: fileURLToPath(new URL('../', import.meta.url)), manifest: { networkId: fixture.trust.network_id, chainId: fixture.trust.chain_id, trust: fixture.trust }, rpc, walletPort: 0, merchantPort: 0 };
  for (const bad of ['http://faucet.example', 'https://faucet.example/', 'https://faucet.example/v1', 'https://user:secret@faucet.example', 'faucet.example', '', "https://faucet.example; script-src *", 'https://faucet.example https://evil.example', 'http://localhost:8940', 42, null])
    await assert.rejects(createV4Servers({ ...base, registrationService: bad }), /registration service must be a canonical HTTPS origin/, String(bad));
  await withGateway({ registrationService: 'http://127.0.0.1:8940' }, async (servers) => {
    assert.equal((await (await fetch(`${servers.walletListenOrigin}/api/network`)).json()).registrationService, 'http://127.0.0.1:8940');
  });
});
