// Bitcoin Core regression harness. Only isolated, network-disabled regtest is
// supported. Cookie credentials and wallet private keys never leave this API.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const ext = process.platform === 'win32' ? '.exe' : '';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function freePort() { const server = net.createServer(); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
function insideLocal(directory) { const relative = path.relative(path.join(root, '.local'), directory); if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Core datadir must be a named directory inside production/.local'); }
function uint64(value, field) { const n = BigInt(value); if (n < 0n || n > 0xffffffffffffffffn) throw new Error(field + ' is outside uint64'); return n; }
export function bidCommitment(context) {
  if (!/^[a-f0-9]{64}$/.test(context.timeNetworkHex)) throw new Error('Time network must be canonical 32-byte hex');
  const payload = Buffer.alloc(64); payload.write('TIMEBID1', 0, 'ascii'); Buffer.from(context.timeNetworkHex, 'hex').copy(payload, 8);
  const account = uint64(context.account, 'account'); if (account === 0xffffffffffffffffn) throw new Error('Reserved Time account');
  payload.writeBigUInt64BE(account, 40); payload.writeBigUInt64BE(uint64(context.auctionEpoch, 'epoch'), 48); payload.writeBigUInt64BE(uint64(context.policyRevision, 'revision'), 56); return payload;
}
function btcString(satoshis) { const n = BigInt(satoshis); if (n <= 0n || n > 2_100_000_000_000_000n) throw new Error('Bitcoin satoshi amount bound'); return `${n / 100_000_000n}.${String(n % 100_000_000n).padStart(8, '0')}`; }

export async function createRegtest(options = {}) {
  const directory = path.resolve(options.directory ?? path.join(root, '.local', `bitcoin-regtest-${randomUUID()}`)); insideLocal(directory);
  const coreDir = path.resolve(options.coreDir ?? path.join(root, '.tools/bitcoin-core-32.1/bitcoin-32.1/bin'));
  const executable = path.join(coreDir, 'bitcoind' + ext); await access(executable); await mkdir(directory, { recursive: true });
  const rpcPort = options.rpcPort ?? await freePort(); if (!Number.isInteger(rpcPort) || rpcPort < 1024 || rpcPort > 65535) throw new Error('Invalid private Core RPC port');
  const rpcUrl = `http://127.0.0.1:${rpcPort}`;
  const cookiePath = path.join(directory, 'regtest', '.cookie');
  const stdout = createWriteStream(path.join(directory, 'core.stdout.log'), { flags: 'a' });
  const stderr = createWriteStream(path.join(directory, 'core.stderr.log'), { flags: 'a' });
  const args = ['-regtest', '-server=1', `-datadir=${directory}`, '-listen=0', '-listenonion=0', '-discover=0', '-dnsseed=0', '-connect=0', '-networkactive=0', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', `-rpcport=${rpcPort}`, '-fallbackfee=0.0002', '-keypool=16'];
  const child = spawn(executable, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.pipe(stdout); child.stderr.pipe(stderr);
  let exited = false, exitCode = null, stopped = false, requestId = 0;
  const exit = new Promise(resolve => { child.once('error', error => { exited = true; resolve({ error: error.message }); }); child.once('close', code => { exited = true; exitCode = code; resolve({ code }); }); });
  let cookie = null;
  async function rpc(method, params = [], settings = {}) {
    if (!cookie) cookie = (await readFile(cookiePath, 'utf8')).trim();
    const endpoint = settings.wallet ? `/wallet/${encodeURIComponent(settings.wallet)}` : '';
    const response = await fetch(rpcUrl + endpoint, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Basic ' + Buffer.from(cookie).toString('base64') }, body: JSON.stringify({ jsonrpc: '2.0', id: ++requestId, method, params }), signal: AbortSignal.timeout(settings.timeoutMs ?? 30_000) });
    const result = await response.json();
    if (result.error) { const error = new Error(`Core ${method}: ${result.error.code} ${result.error.message}`); error.code = result.error.code; throw error; }
    if (!response.ok) throw new Error(`Core ${method}: HTTP ${response.status}`);
    return result.result;
  }
  async function stop() {
    if (stopped) return; stopped = true;
    if (!exited) { try { await rpc('stop', [], { timeoutMs: 10_000 }); } catch { /* The owned process may still be starting. */ } }
    let timer; const timeout = new Promise(resolve => { timer = setTimeout(() => resolve(null), 15_000); }); const ended = await Promise.race([exit, timeout]); clearTimeout(timer);
    if (!ended && !exited) { child.kill(); await exit; }
    cookie = null;
  }
  try {
    const deadline = Date.now() + 60_000;
    while (true) {
      if (exited) throw new Error(`Owned Core regtest exited during startup (${exitCode}); inspect its private logs`);
      try { const info = await rpc('getblockchaininfo', [], { timeoutMs: 2000 }); if (info.chain !== 'regtest') throw new Error('Core chain is not regtest'); break; }
      catch (error) { cookie = null; if (Date.now() >= deadline) throw new Error(`Core regtest readiness failed: ${error.message}`); await sleep(100); }
    }
    const wallet = 'time-regtest-fixture';
    const loaded = await rpc('listwallets');
    if (!loaded.includes(wallet)) {
      try { await rpc('loadwallet', [wallet]); }
      catch (error) { if (error.code !== -18 && error.code !== -4) throw error; await rpc('createwallet', [wallet]); }
    }
    const publicPath = path.join(directory, 'fixture-public.json');
    let publicState;
    try { publicState = JSON.parse(await readFile(publicPath, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; publicState = { schema_version: 1, miningAddress: await rpc('getnewaddress', ['mining', 'bech32'], { wallet }), policies: {} }; await writeFile(publicPath, JSON.stringify(publicState, null, 2) + '\n', { flag: 'wx' }); }
    async function savePublic() { await writeFile(publicPath, JSON.stringify(publicState, null, 2) + '\n'); }
    async function mine(count, settings = {}) {
      if (!Number.isInteger(count) || count < 1 || count > 1000) throw new Error('Regtest mining bound 1..1000');
      return rpc('generatetoaddress', [count, settings.address ?? publicState.miningAddress], { timeoutMs: 120_000 });
    }
    async function headers(fromHeight = 1, toHeight = null) {
      const tip = toHeight ?? await rpc('getblockcount'); if (!Number.isInteger(fromHeight) || fromHeight < 0 || tip - fromHeight > 20_000) throw new Error('Header export bound');
      const result = []; for (let height = fromHeight; height <= tip; height++) { const hash = await rpc('getblockhash', [height]); result.push(await rpc('getblockheader', [hash, false])); } return result;
    }
    async function foundationPolicy(settings = {}) {
      const threshold = settings.threshold ?? 4, members = settings.members ?? 7;
      if (members !== 7 || ![4, 5].includes(threshold)) throw new Error('Fixture policies are 4-of-7 or 5-of-7');
      const key = `${threshold}of${members}`;
      if (!settings.pubkeys && publicState.policies[key]) return publicState.policies[key];
      let pubkeys = settings.pubkeys;
      if (!pubkeys) { pubkeys = []; for (let i = 0; i < members; i++) { const address = await rpc('getnewaddress', [`custodian-${i}`, 'bech32'], { wallet }); const info = await rpc('getaddressinfo', [address], { wallet }); pubkeys.push(info.pubkey); } }
      if (pubkeys.length !== 7 || new Set(pubkeys).size !== 7 || pubkeys.some(p => !/^(02|03)[a-f0-9]{64}$/.test(p))) throw new Error('Seven distinct compressed fixture public keys required');
      pubkeys = [...pubkeys].sort(); const multi = await rpc('createmultisig', [threshold, pubkeys, 'bech32']); const address = await rpc('validateaddress', [multi.address]);
      const policy = { network: 'regtest', threshold, members, pubkeys, address: multi.address, witnessScriptHex: multi.redeemScript, scriptPubKeyHex: address.scriptPubKey };
      publicState.policies[key] = policy; await savePublic(); return policy;
    }
    async function bidReceipt({ context, policy, amountSats, confirmations = 12 }) {
      if (policy.network !== 'regtest' || !Number.isInteger(confirmations) || confirmations < 1 || confirmations > 144) throw new Error('Regtest receipt network/confirmation bound');
      const height = await rpc('getblockcount'); if (height < 101) await mine(101 - height);
      const commitment = bidCommitment(context); const raw = await rpc('createrawtransaction', [[], [{ [policy.address]: btcString(amountSats) }, { data: commitment.toString('hex') }]]);
      const funded = await rpc('fundrawtransaction', [raw], { wallet }); const signed = await rpc('signrawtransactionwithwallet', [funded.hex], { wallet }); if (!signed.complete) throw new Error('Regtest fixture transaction did not sign completely');
      // Fail BEFORE broadcasting any BTC. The Time v4 hex wire reserves 4KiB
      // for a partial Merkle proof and caps supported funding transactions.
      if(!/^(?:[0-9a-f]{2})+$/.test(signed.hex)||signed.hex.length>240*1024*2)throw new Error('Funding transaction exceeds Time v4 prepayment receipt budget; nothing was broadcast');
      const txid = await rpc('sendrawtransaction', [signed.hex]); const mined = await mine(confirmations); const blockHash = mined[0];
      const transactionHex = await rpc('getrawtransaction', [txid, false, blockHash]); const decoded = await rpc('decoderawtransaction', [transactionHex]);
      const vouts = decoded.vout.filter(out => out.scriptPubKey.hex === policy.scriptPubKeyHex && Math.round(out.value * 100_000_000) === Number(BigInt(amountSats)));
      if (vouts.length !== 1) throw new Error('Fixture transaction does not have exactly the intended treasury output');
      const proofHex = await rpc('gettxoutproof', [[txid], blockHash]); const best = await rpc('getblockchaininfo');
      return { network: 'regtest', txid, blockHash, tipHash: best.bestblockhash, tipHeight: best.blocks, commitmentHex: commitment.toString('hex'), transactionHex, proofHex,
        receipt: { network: 'regtest', block_hash: blockHash, transaction: [...Buffer.from(transactionHex, 'hex')], vout: vouts[0].n, expected_sats: Number(BigInt(amountSats)), merkle_proof: [...Buffer.from(proofHex, 'hex')] }, headersHex: await headers() };
    }
    async function reorgAfter(blockHash, blocks) { await rpc('invalidateblock', [blockHash]); return mine(blocks); }
    return { network: 'regtest', datadir: directory, pid: child.pid, rpcPort, rpc, mine, headers, foundationPolicy, bidReceipt, reorgAfter, stop, exited: exit };
  } catch (error) { await stop(); throw error; }
}

export const startRegtest = createRegtest;
