#!/usr/bin/env node
// Real Bitcoin Core regtest payment/proof/reorg evidence. No external network.
import { createRegtest } from './bitcoin-regtest.mjs';
import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { access, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const dir = path.join(root, 'bitcoin-bridge/results', 'core-regtest-' + randomUUID());
await mkdir(dir, { recursive: true });
const executable = path.join(root, 'bitcoin-bridge/target/debug/bitcoin-bridge-check' + (process.platform === 'win32' ? '.exe' : ''));
await access(executable);
async function hash(file) { const h = createHash('sha256'); for await (const bytes of createReadStream(file)) h.update(bytes); return h.digest('hex'); }
const sourceFiles = ['bitcoin-bridge/Cargo.toml', 'bitcoin-bridge/Cargo.lock', 'tools/bitcoin-regtest.mjs', 'tools/bitcoin-bridge-e2e.mjs'];
async function collect(relative) { for (const e of await readdir(path.join(root, relative), { withFileTypes: true })) { const file = path.posix.join(relative, e.name); if (e.isDirectory()) await collect(file); else if (e.isFile()) sourceFiles.push(file); } }
await collect('bitcoin-bridge/src'); sourceFiles.sort();
async function sourceHashes() { return Object.fromEntries(await Promise.all(sourceFiles.map(async file => [file, await hash(path.join(root, file))]))); }
const before = await sourceHashes(), binaryHash = await hash(executable), started = new Date().toISOString();
let core;
try {
  core = await createRegtest();
  const policy = await core.foundationPolicy({ threshold: 4, members: 7 });
  const context = { timeNetworkHex: createHash('sha256').update('time-bitcoin-regtest-e2e-v1').digest('hex'), account: 42, auctionEpoch: 7, policyRevision: 3 };
  const bid = await core.bidReceipt({ context, policy, amountSats: 100_000, confirmations: 12 });
  const originalInfo = await core.rpc('getblockchaininfo'); const network = await core.rpc('getnetworkinfo');
  const originalBlock = await core.rpc('getblockheader', [bid.blockHash]);
  await core.reorgAfter(bid.blockHash, 13);
  const reorgInfo = await core.rpc('getblockchaininfo');
  const reorgHeaders = await core.headers(originalBlock.height);
  const now = Math.floor(Date.now() / 1000);
  const scenario = { network: 'regtest', now_secs: now, headers_hex: bid.headersHex, expected_best_hash: bid.tipHash,
    policy: { network: 'regtest', time_network: [...Buffer.from(context.timeNetworkHex, 'hex')], revision: context.policyRevision, script_pubkey: [...Buffer.from(policy.scriptPubKeyHex, 'hex')], min_sats: 1, max_sats: 1_000_000, btc_start_height: 1, btc_end_height: null, time_start_micros: 0, time_end_micros: null },
    context: { time_network: [...Buffer.from(context.timeNetworkHex, 'hex')], account: context.account, auction_epoch: context.auctionEpoch, policy_revision: context.policyRevision, time_micros: now * 1_000_000 }, receipt: bid.receipt, reorg_headers_hex: reorgHeaders };
  const input = path.join(dir, 'scenario.json'), output = path.join(dir, 'native-result.json'); await writeFile(input, JSON.stringify(scenario), { flag: 'wx' });
  const child = spawn(executable, [input, output], { windowsHide: true, cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; child.stdout.on('data', c => stdout += c); child.stderr.on('data', c => stderr += c);
  const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', code => resolve(code)); });
  await writeFile(path.join(dir, 'native.stdout.log'), stdout); await writeFile(path.join(dir, 'native.stderr.log'), stderr);
  if (status !== 0) throw new Error('Native bridge regression failed: ' + stderr);
  const native = JSON.parse(await readFile(output, 'utf8'));
  const checks = { isolated_regtest: originalInfo.chain === 'regtest' && reorgInfo.chain === 'regtest', no_external_peers: network.connections === 0 && network.networkactive === false,
    real_p2wsh_4of7: policy.threshold === 4 && policy.members === 7 && policy.pubkeys.length === 7 && policy.scriptPubKeyHex.startsWith('0020'),
    bitcoin_core_tip_matches_spv: native.tip_hash === originalInfo.bestblockhash && native.tip_height === originalInfo.blocks,
    bitcoin_core_chainwork_matches_spv: BigInt('0x' + native.tip_chainwork) === BigInt('0x' + originalInfo.chainwork),
    exact_output_value: native.receipt.sats === 100_000, exact_time_account_epoch_revision: native.receipt.account === 42 && native.receipt.auction_epoch === 7 && native.receipt.policy_revision === 3,
    twelve_confirmations: native.receipt.confirmations >= 12, duplicate_outpoint_rejected: native.duplicate_outpoint_rejected, forged_output_value_rejected: native.forged_value_rejected,
    real_core_reorganization_pauses: native.real_core_receipt_reorg_paused && reorgInfo.bestblockhash !== originalInfo.bestblockhash, mainnet_acceptance_disabled: native.mainnet_receipts_enabled === false };
  const after = await sourceHashes(); checks.source_unchanged = JSON.stringify(before) === JSON.stringify(after); checks.binary_unchanged = binaryHash === await hash(executable);
  if (!Object.values(checks).every(Boolean)) throw new Error('Core bridge evidence invariant failed: ' + JSON.stringify(checks));
  const report = { schema_version: 1, started_utc: started, completed_utc: new Date().toISOString(), public_launch_allowed: false, mainnet_receipts_enabled: false, checks,
    scope: 'Network-disabled Bitcoin Core regtest; real wallet funding/signing, P2WSH4of7,64-byteTIMEBID1,Merkle proof,12 confirmations and subsequent real Core reorg. No real BTC or independently distributed custody keys.',
    core: { version: network.version, subversion: network.subversion, datadir: path.relative(root, core.datadir), rpc_port: core.rpcPort, original_tip: originalInfo.bestblockhash, original_height: originalInfo.blocks, original_chainwork: originalInfo.chainwork, reorg_tip: reorgInfo.bestblockhash, reorg_height: reorgInfo.blocks },
    policy, transaction_id: bid.txid, original_receipt_block: bid.blockHash, native,
    evidence: { executable: path.relative(root, executable), binary_sha256: binaryHash, source_sha256_before: before, source_sha256_after: after, scenario_sha256: await hash(input), native_result_sha256: await hash(output) } };
  const reportPath = path.join(dir, 'report.json'); await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(`Bitcoin Core regtest receipt/reorg verified: ${Object.keys(checks).length} checks. ${path.relative(root, reportPath)}`);
} finally { if (core) await core.stop(); }
