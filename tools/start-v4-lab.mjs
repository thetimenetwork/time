#!/usr/bin/env node
// Durable, loopback-only seven-node protocol-4 and Bitcoin Core laboratory.
import { spawn, execFile } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { access, mkdir, readFile, writeFile, unlink, rename } from 'node:fs/promises';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createV4Servers } from '../client-v4/server.mjs';
import { acquireLabLock } from '../sdk/lab-lock.mjs';
import { createRegtest } from './bitcoin-regtest.mjs';
import { runV4NetworkProbe } from './v4-network-probe.mjs';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../', import.meta.url));
const ext = process.platform === 'win32' ? '.exe' : '';
const options = { lab: path.join(root, '.local', 'lab-v4-current'), comet: path.join(root, '.tools', 'bin', 'cometbft' + ext), app: path.join(root, 'v4', 'target', 'debug', 'time-node-v4' + ext), walletPort: 8907, merchantPort: 8908, runFor: 0, stop: false };
options.protocol = 4;
const explicit = new Set();
for (let i = 2; i < process.argv.length; i++) {
  const flag = process.argv[i];
  explicit.add(flag);
  if(flag==='--validate'){options.validate=true;continue;}
  if (flag === '--stop') { options.stop = true; continue; }
  if (flag === '--help') { console.log('node production/tools/start-v4-lab.mjs [--lab PATH_WITHIN_PRODUCTION_LOCAL] [--wallet-port 8907] [--merchant-port 8908] [--run-for SECONDS] [--stop]\nPreserves all keys, genesis, signer state, Bitcoin regtest chain and balances. Seven local processes, four initial voting keys. Real stake admission changes voting authority at H+2. No public or real Bitcoin network.'); process.exit(0); }
  const mapping = { '--lab': 'lab', '--comet': 'comet', '--app': 'app', '--wallet-port': 'walletPort', '--merchant-port': 'merchantPort', '--run-for': 'runFor' };
  const key = mapping[flag]; if (!key || !process.argv[i + 1]) throw new Error('Unsupported/incomplete option: ' + flag);
  options[key] = ['walletPort', 'merchantPort', 'runFor', 'protocol'].includes(key) ? Number(process.argv[++i]) : path.resolve(process.cwd(), process.argv[++i]);
}
const NODE_COUNT=7;
const networkDomain = `TCDEVNET-NETWORK-V${options.protocol}\0`;
const relative = path.relative(path.join(root, '.local'), options.lab);
if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Lab must be a named directory inside production/.local');
for (const key of ['walletPort', 'merchantPort']) if (!Number.isInteger(options[key]) || options[key] < 0 || options[key] > 65535) throw new Error('Invalid port');
if (!Number.isSafeInteger(options.runFor) || options.runFor < 0 || options.runFor > 86400) throw new Error('Invalid --run-for seconds');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const children = []; const reservations = []; const nodes = []; let servers; let lock; let bitcoin; let interrupted = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { interrupted = true; });
// Automation can request an orderly stop without platform-specific process killing.
process.stdin.setEncoding('utf8'); process.stdin.on('data', data => { if (data.trim() === 'stop') interrupted = true; });
function check(condition, text) { if (!condition) throw new Error(text); }
async function exists(file) { try { await access(file); return true; } catch { return false; } }
async function wait(label, fn, timeout = 45000) { const deadline = Date.now() + timeout; let reason; while (!interrupted && Date.now() < deadline) { for (const child of children) if (!child.expectedStop) check(!child.error && !child.exited, child.label + ' stopped; see ignored local log'); try { const value = await fn(); if (value) return value; } catch (error) { reason = error; } await sleep(150); } throw new Error(label + ' timed out' + (reason ? ': ' + reason.message : '')); }
async function reserve() { const server = net.createServer(socket => socket.destroy()); await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); }); server.unref(); const item = { server, port: server.address().port }; reservations.push(item); return item; }
async function release(item) { if (item.released) return; item.released = true; await new Promise(resolve => item.server.close(resolve)); }
function tomlSet(source, section, key, value) { let current = ''; let count = 0; const result = source.split(/\r?\n/).map(line => { const match = /^\s*\[([^\]]+)\]/.exec(line); if (match) current = match[1]; if (current === section && new RegExp('^\\s*' + key + '\\s*=').test(line)) { count++; return key + ' = ' + value; } return line; }); check(count === 1, 'Missing/duplicate TOML configuration ' + section + '.' + key); return result.join('\n'); }
function launch(binary, args, label, log) {
  const output = createWriteStream(log, { flags: 'a', mode: 0o600 }); const child = spawn(binary, args, { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); const handle = { child, label, exited: false, error: null };
  handle.done = new Promise(resolve => { child.once('error', error => { handle.error = error; }); child.once('close', () => { handle.exited = true; output.end(resolve); }); }); output.on('error', error => { handle.error ??= error; }); child.stdout.pipe(output, { end: false }); child.stderr.pipe(output, { end: false }); children.push(handle); return handle;
}
async function stop(handle) { if (handle.exited) return; handle.child.kill('SIGTERM'); await Promise.race([handle.done, sleep(3500)]); if (!handle.exited) { handle.child.kill('SIGKILL'); await Promise.race([handle.done, sleep(3500)]); } check(handle.exited, 'Child failed to stop: ' + handle.label); }
async function rpc(endpoint, parameters = {}, index = 0) { const url = new URL(endpoint, `http://127.0.0.1:${nodes[index].ports.rpc.port}`); for (const [key, value] of Object.entries(parameters)) url.searchParams.set(key, value); const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(4000) }); const payload = await response.json(); check(response.ok && !payload.error && payload.result, 'Comet RPC unavailable: ' + endpoint + (payload.error ? ': ' + String(payload.error.message || '') + ' ' + String(payload.error.data || '').slice(0, 240) : '')); return payload.result; }
const manifestPath = path.join(options.lab, 'network-manifest.json');

async function main() {
  if (options.stop) { const runtime = JSON.parse(await readFile(path.join(options.lab, 'runtime.json'), 'utf8')); check(Number.isSafeInteger(runtime.pid) && runtime.pid > 0, 'Invalid owned lab process'); const temporary = path.join(options.lab, `.stop-request.${process.pid}.tmp`); await writeFile(temporary, JSON.stringify({ pid: runtime.pid }), { mode: 0o600 }); await rename(temporary, path.join(options.lab, '.stop-request.json')); console.log('Requested orderly stop for this local lab.'); return; }
  await Promise.all([access(options.comet), access(options.app)]);
  const preflight = await Promise.all([exec(options.comet, ['version'], { cwd: root, windowsHide: true, timeout: 10000 }), exec(options.app, ['--version'], { cwd: root, windowsHide: true, timeout: 10000 })]);
  const versions = { comet: preflight[0].stdout.trim(), app: preflight[1].stdout.trim(), node: process.version };
  check(versions.comet.startsWith('0.38.26') && versions.app.includes('publicLaunchAllowed=false'), 'Expected the pinned local-devnet binaries');
  const binaries = Object.fromEntries(await Promise.all(['comet', 'app'].map(async name => [name, { path: options[name], sha256: createHash('sha256').update(await readFile(options[name])).digest('hex') }])));
  await mkdir(options.lab, { recursive: true, mode: 0o700 }); lock = await acquireLabLock(options.lab);
  bitcoin=await createRegtest({directory:path.join(options.lab,'bitcoin')});
  try { await unlink(path.join(options.lab, '.stop-request.json')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  let manifest;
  const resuming = await exists(manifestPath);
  if (!resuming) {
    check(!await exists(path.join(options.lab, 'node0')), 'Incomplete prior initialization preserved. Start with a different --lab path for a fresh laboratory.');
    await exec(options.comet, ['testnet', '--v', String(NODE_COUNT), '--o', options.lab, '--populate-persistent-peers=false'], { cwd: root, windowsHide: true, timeout: 20000, maxBuffer: 512 * 1024 });
    const genesis = JSON.parse(await readFile(path.join(options.lab, 'node0', 'config', 'genesis.json'), 'utf8'));
    check(genesis.validators.length === NODE_COUNT, 'Seven distinct local keys required'); const authKeys = [];
    const accounts = genesis.validators.map((_, index) => { const pair = generateKeyPairSync('ed25519'); const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'); authKeys.push({ accountId: String(index), publicKey, privateKeyPkcs8: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64') }); return { id: String(index), name: 'operator_' + index, public_key: publicKey }; });
    const allValidators=genesis.validators;genesis.validators=allValidators.slice(0,4).map(v=>({...v,power:'1'}));
    genesis.chain_id = `time-devnet-v${options.protocol}-` + randomBytes(8).toString('hex'); genesis.genesis_time = new Date().toISOString();
    genesis.consensus_params.block.max_bytes = '1048576';
    genesis.consensus_params.evidence.max_bytes = '65536';
    genesis.consensus_params.version.app = String(options.protocol);
    const foundation=await bitcoin.foundationPolicy({threshold:4,members:7});
    const council=Array.from({length:7},()=>{const pair=generateKeyPairSync('ed25519');return {public_key:pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'),private_key_pkcs8:pair.privateKey.export({format:'der',type:'pkcs8'}).toString('base64')};});
    genesis.app_state = {history_version:1,bitcoin_receipt_version:1,reward_version:1,ledger:{chain_id:genesis.chain_id,genesis_time_micros:String(BigInt(Date.parse(genesis.genesis_time))*1000n),accounts,economics:{mode:'bank_only',auction_epoch_seconds:'10',unbond_seconds:'1209600',operators:[]}},profile:'laboratory',validators:genesis.validators.map((validator,index)=>({owner:String(index),consensus_key:Buffer.from(validator.pub_key.value,'base64').toString('hex'),commission_bps:1000})),bitcoin:{network:'regtest',confirmations:12,max_batch:256,max_fork_tips:32,retention:8192,max_reorg:144,max_tip_age_secs:7200,max_future_secs:7200,mainnet_receipts_enabled:false},treasury:{revision:1,treasury_keys:foundation.pubkeys,governance_keys:council.map(k=>k.public_key)},auction:{epoch_seconds:'10',bid_lead_epochs:'2',max_future_epochs:'48',min_sats:'1000',max_sats:'2100000000000000'},registration:{fee_micros:'10000',max_lifetime_micros:'86400000000',bucket_micros:'3600000000'},recovery_min_delay_micros:'30000000',recovery_approval_window_micros:'604800000000',trusting_period_seconds:'604800'};
    const networkId = createHash('sha256').update(networkDomain).update(JSON.stringify(genesis.app_state)).digest('hex');
    manifest = { schemaVersion:4,protocolVersion:'4',networkId,chainId:genesis.chain_id,publicLaunchAllowed:false,sponsorAccount:'0',genesis:genesis.app_state,trust:{chain_id:genesis.chain_id,network_id:networkId,app_version:'4',genesis_time_micros:genesis.app_state.ledger.genesis_time_micros,trusting_period_seconds:'604800',unbonding_period_seconds:'1209600',initial_validators:genesis.validators.map(value=>({address:value.address,pub_key:value.pub_key,voting_power:String(value.power),proposer_priority:'0'}))}};
    for (let index = 0; index < NODE_COUNT; index++) await writeFile(path.join(options.lab, 'node' + index, 'config', 'genesis.json'), JSON.stringify(genesis, null, 2), { mode: 0o600 });
    await writeFile(path.join(options.lab, 'operator-auth.json'), JSON.stringify(authKeys), { mode: 0o600, flag: 'wx' });
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600, flag: 'wx' });
    await writeFile(path.join(options.lab,'test-governance-auth.json'),JSON.stringify(council),{mode:0o600,flag:'wx'});
    await writeFile(path.join(options.lab,'bitcoin-foundation-public.json'),JSON.stringify(foundation,null,2),{mode:0o600,flag:'wx'});
  } else { manifest = JSON.parse(await readFile(manifestPath, 'utf8')); check(manifest.publicLaunchAllowed === false && manifest.chainId.startsWith('time-devnet-') && manifest.protocolVersion === String(options.protocol), 'Existing lab has a different protocol; its data is preserved'); }
  // Independent genesis files must match; never replace signer state or app DB.
  const genesisFiles = await Promise.all(Array.from({length:NODE_COUNT},(_,index)=>readFile(path.join(options.lab,'node'+index,'config','genesis.json'),'utf8')));
  check(genesisFiles.every(value => value === genesisFiles[0]), 'Validators disagree about pinned genesis');
  const genesis = JSON.parse(genesisFiles[0]);
  check(genesis.app_state.reward_version===1&&genesis.app_state.history_version===1&&genesis.app_state.bitcoin_receipt_version===1,'Earlier development contract is preserved. Use a new lab path; no automatic migration is performed.');
  check(createHash('sha256').update(networkDomain).update(JSON.stringify(genesis.app_state)).digest('hex') === manifest.networkId, 'Pinned genesis network identity changed');
  const genesisBlockMax = BigInt(genesis.consensus_params.block.max_bytes);
  check(resuming || genesisBlockMax + 1048576n <= 8388608n, 'New genesis block budget plus request margin exceeds the application transport frame');
  for (let index = 0; index < NODE_COUNT; index++) { const home = path.join(options.lab, 'node' + index); const result = await exec(options.comet, ['show-node-id', '--home', home], { cwd: root, windowsHide: true, timeout: 10000 }); const nodeId = result.stdout.trim(); check(/^[a-f0-9]{40}$/i.test(nodeId), 'Invalid peer identifier'); nodes.push({ home, nodeId, ports: { app: await reserve(), rpc: await reserve(), p2p: await reserve() } }); }
  for (const node of nodes) {
    const filename = path.join(node.home, 'config', 'config.toml'); let config = await readFile(filename, 'utf8');
    const peers = nodes.filter(other => other !== node).map(other => `${other.nodeId}@127.0.0.1:${other.ports.p2p.port}`).join(',');
    const settings = [['', 'proxy_app', JSON.stringify(`tcp://127.0.0.1:${node.ports.app.port}`)], ['', 'log_level', '"error"'], ['rpc', 'laddr', JSON.stringify(`tcp://127.0.0.1:${node.ports.rpc.port}`)], ['p2p', 'laddr', JSON.stringify(`tcp://127.0.0.1:${node.ports.p2p.port}`)], ['p2p', 'persistent_peers', JSON.stringify(peers)], ['p2p', 'persistent_peers_max_dial_period', '"1s"'], ['p2p', 'allow_duplicate_ip', 'true'], ['p2p', 'addr_book_strict', 'false'], ['p2p', 'pex', 'false'], ['consensus', 'timeout_commit', '"1s"'], ['consensus', 'timeout_propose', '"2s"']];
    if (!resuming) settings.push(['mempool', 'size', '1000'], ['mempool', 'max_tx_bytes', '524480'], ['mempool', 'max_txs_bytes', '16777216']);
    for (const [section, key, value] of settings) config = tomlSet(config, section, key, value);
    await writeFile(filename, config, { mode: 0o600 });
  }
  for (let index = 0; index < nodes.length; index++) { const node = nodes[index]; await release(node.ports.app); node.application = launch(options.app, ['--devnet', '--db', path.join(node.home, 'data', 'application.redb'), '--listen', `127.0.0.1:${node.ports.app.port}`], 'app' + index, path.join(node.home, 'application.log')); }
  await wait('ABCI listeners', async () => (await Promise.all(nodes.map(node => new Promise(resolve => { const socket = net.connect(node.ports.app.port, '127.0.0.1'); socket.setTimeout(300); socket.once('connect', () => { socket.destroy(); resolve(true); }); socket.once('error', () => resolve(false)); socket.once('timeout', () => { socket.destroy(); resolve(false); }); })))).every(Boolean), 15000);
  for (let index = 0; index < nodes.length; index++) { const node = nodes[index]; await Promise.all([release(node.ports.rpc), release(node.ports.p2p)]); node.consensus = launch(options.comet, ['start', '--home', node.home, '--log_level', 'error'], 'comet' + index, path.join(node.home, 'consensus.log')); }
  const baseline = await wait('All four consensus RPC listeners', async () => Promise.all(nodes.map((_, index) => rpc('/status', {}, index))));
  const baselineMax = baseline.reduce((maximum, value) => BigInt(value.sync_info.latest_block_height) > maximum ? BigInt(value.sync_info.latest_block_height) : maximum, 0n);
  const advancing = await wait('Four validators advancing with fresh timestamps', async () => {
    const statuses = await Promise.all(nodes.map((_, index) => rpc('/status', {}, index)));
    return statuses.every(value => { const age = Date.now() - Date.parse(value.sync_info.latest_block_time); return BigInt(value.sync_info.latest_block_height) >= baselineMax + 2n && Number.isFinite(age) && age >= -10000 && age <= 30000; }) ? statuses : false;
  });
  const commonHeight = advancing.reduce((minimum, value) => BigInt(value.sync_info.latest_block_height) < minimum ? BigInt(value.sync_info.latest_block_height) : minimum, BigInt(advancing[0].sync_info.latest_block_height));
  const heads = await Promise.all(nodes.map((_, index) => rpc('/block', { height: commonHeight.toString() }, index)));
  check(heads.every(value => value.block_id.hash === heads[0].block_id.hash && value.block.header.app_hash === heads[0].block.header.app_hash), 'Validators disagree at the same fresh committed height');
  const actual = await rpc('/validators', { height: '1', per_page: '100' });
  check(actual.validators.length === 4 && actual.validators.every(value => manifest.trust.initial_validators.some(pinned => pinned.address === value.address && pinned.pub_key.value === value.pub_key.value && pinned.voting_power === value.voting_power)), 'Consensus membership differs from trusted genesis');
  manifest.trust.initial_validators = actual.validators;
  const effectiveParams = await wait('Consensus parameters at the common committed height', () => rpc('/consensus_params', { height: commonHeight.toString() }));
  const effectiveBlockMax = BigInt(effectiveParams.consensus_params.block.max_bytes);
  const resourceContract = { diagnostic: true, retainedGenesisBlockMaxBytes: genesisBlockMax.toString(), effectiveBlockMaxBytes: effectiveBlockMax.toString(), appFrameMaxBytes: '8388608', reservedRequestMarginBytes: '1048576', maxCanonicalActionBytes: '524480', compatible: effectiveBlockMax + 1048576n <= 8388608n };
  if (!resourceContract.compatible) console.warn('Retained laboratory consensus block budget exceeds the application transport envelope. Oversized Byzantine proposals are a public-network liveness blocker; this test lab remains private.');
  check(resuming || resourceContract.compatible, 'New laboratory consensus parameters exceed the request envelope');
  manifest = { ...manifest, resourceContract };
  const onRegtestBid=async({account,epoch})=>bitcoin.bidReceipt({context:{timeNetworkHex:manifest.networkId,account:String(account),auctionEpoch:String(epoch),policyRevision:'1'},policy:JSON.parse(await readFile(path.join(options.lab,'bitcoin-foundation-public.json'),'utf8')),amountSats:10000,confirmations:12});
  let sponsorQueue=Promise.resolve(),sponsorClient,sponsorKey;
  const onSponsorRegistration=payload=>{
    const operation=sponsorQueue.then(async()=>{
      check(manifest.genesis.profile==='laboratory'&&manifest.genesis.bitcoin.network==='regtest'&&manifest.sponsorAccount==='0','Sponsorship callback is private laboratory only');
      const auth=JSON.parse(await readFile(path.join(options.lab,'operator-auth.json'),'utf8'))[0];
      sponsorKey??=await crypto.subtle.importKey('pkcs8',Buffer.from(auth.privateKeyPkcs8,'base64'),'Ed25519',false,['sign']);
      sponsorClient??=globalThis.TimeSDK.createClient({gateway:servers.walletOrigin,trust:manifest.trust});
      const required=BigInt(manifest.genesis.registration.fee_micros)+1000n;
      await wait('fresh proved minted sponsorship balance',async()=>{const checked=await sponsorClient.getVerifiedState({ids:['0']});return BigInt(checked.state.accounts.find(a=>a.id==='0').balance)>=required;},60000);
      const receipt=await sponsorClient.perform({kind:44,account:{id:'0'},publicKey:auth.publicKey,privateKey:sponsorKey,payload});
      return {hash:receipt.hash};
    });
    sponsorQueue=operation.catch(()=>{});return operation;
  };
  servers = await createV4Servers({ root, manifest, rpc, walletPort: options.walletPort, merchantPort: options.merchantPort, checkpointPath: path.join(options.lab, 'merchant-checkpoint.json'), ordersPath: path.join(options.lab, 'orders.json'),onRegtestBid,onSponsorRegistration });
  const startupProof = await wait('Fresh independently verified state commitment', () => servers.verifiedState());
  const sourceHashes=Object.fromEntries(await Promise.all(['tools/start-v4-lab.mjs','tools/v4-network-probe.mjs','tools/bitcoin-regtest.mjs','client-v4/server.mjs','client-v4/time-sdk.js','client-v4/proof-verifier.mjs','client-v4/light-client.mjs','web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm'].map(async file=>[file,createHash('sha256').update(await readFile(path.join(root,file))).digest('hex')])));
  const runtime = { ...manifest, walletOrigin: servers.walletOrigin, merchantOrigin: servers.merchantOrigin, rpcUrls: nodes.map(node => `http://127.0.0.1:${node.ports.rpc.port}`), pid: process.pid, labDirectory: options.lab, startedAt: new Date().toISOString(), versions, binaries, sourceHashes, resuming, startup: { baselineMaxHeight: baselineMax.toString(), commonHeight: commonHeight.toString(), verifiedStateHeight: startupProof.height, checkpoint: startupProof.checkpoint } };
  await writeFile(path.join(options.lab, 'runtime.json'), JSON.stringify(runtime, null, 2), { mode: 0o600 });
  if(options.validate){await runV4NetworkProbe({root,options,nodes,launch,stop,rpc,wait,servers,runtime});return;}
  console.log(`LOCAL PROTOCOL 4 TEST COINS; public launch disabled.\nWallet: ${servers.walletOrigin}\nYour app: ${servers.merchantOrigin}\nNetwork: ${manifest.networkId}\nFiles: ${options.lab}\n${resuming?'Resumed saved chain, keys, signer state and databases.':'Created zero-supply Time chain and private Bitcoin regtest chain.'}\nVerified state height ${startupProof.height}. Seven nodes on one computer; four initial validators, funded PoS successors take effect at H+2.\nCtrl+C or --stop preserves all local state.`);
  const until = options.runFor ? Date.now() + options.runFor * 1000 : Infinity;
  while (!interrupted && Date.now() < until) { for (const handle of children) check(!handle.exited && !handle.error, handle.label + ' stopped unexpectedly; inspect local logs'); try { const control = JSON.parse(await readFile(path.join(options.lab, '.stop-request.json'), 'utf8')); if (control.pid === process.pid) interrupted = true; } catch (error) { if (error.code !== 'ENOENT') throw error; } await sleep(400); }
}
try { await main(); } catch (error) { console.error('Local lab failed: ' + error.message); process.exitCode = 1; }
finally {
  process.stdin.pause();
  await servers?.close();
  await bitcoin?.stop();
  const result = await Promise.allSettled([...children].reverse().map(stop)); for (const item of result) if (item.status === 'rejected') { console.error(item.reason.message); process.exitCode = 1; }
  await Promise.allSettled(reservations.map(release));
  if (lock) { await lock.close(); await unlink(path.join(options.lab, '.running.lock')); }
}
