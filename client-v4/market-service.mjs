// What the two services of the market share (market-relay.mjs, market-prover.mjs): how they reach the Time chain,
// how they read what it holds of Bitcoin, how the prover's key is read, and the health answer.
//
// HOW THE CHAIN IS REACHED. One of two, as the operator chooses:
// - `rpc_url`: the CometBFT RPC of a Time node, as the API and the faucet use it. State is read with a proof
//   (`createStateReader` of api.mjs: the SDK's verifying client over the node's RPC) and actions are handed to the
//   node (`broadcast_tx_sync`). For an operator who runs a node.
// - `gateway`: the public origin of a wallet gateway, as the security watch uses it. State is read with a proof
//   through the SDK's client, and actions are sent to the gateway's `/api/submit`, as a wallet sends them. For
//   someone who runs a Bitcoin node and no Time node.
// Either way every row a service acts on is PROVEN: checked against the validators' signatures from the trust
// manifest, by the verifier installed with this code. The endpoint cannot make a service believe in a fill, a
// balance or a Bitcoin height the chain does not hold. It can withhold: answer nothing, answer with an older state,
// or take an action and never pass it on. The services say so in their health answer when the state they read
// stops moving, and when what they sent does not reach a block.
// What an endpoint says when it refuses an action (the node's reason) is its word, not a proof. The services use
// those words to decide how long to wait before the next try, never to decide what is true of a payment's worth.
import http from 'node:http';
import { open, readFile, rename, stat } from 'node:fs/promises';
import './time-sdk.js';
import { createStateReader } from './api.mjs';
import { createRpc, IndexerError, plainText } from './indexer.mjs';

const SDK = globalThis.TimeSDK;
const HASH = /^[0-9a-f]{64}$/;
/// The Bitcoin networks a service works on. Mainnet is closed in this version of the market: the engine refuses
/// every fill and every proof there (spec/market.md, section 2), and the services refuse it too.
export const OPEN_NETWORKS = Object.freeze(['regtest', 'testnet3']);

/// Why the chain could not be asked or told. `code` is UNAVAILABLE: a later try can succeed.
export class EndpointError extends Error {
  constructor(message) { super(message); this.name = 'EndpointError'; this.code = 'UNAVAILABLE'; }
}
/// `work`, or a rejection after `ms`. The work is not stopped (the SDK takes no signal for a whole read).
function within(work, ms, what) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new EndpointError(`${what} did not answer within ${Math.round(ms / 1000)} s`)), ms);
    Promise.resolve(work).then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}
/// Where the light client keeps the newest checkpoint it verified, so that a restart goes on from it.
export function checkpointFile(file) {
  const load = async () => { try { return JSON.parse(await readFile(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return {}; throw error; } };
  return {
    async getItem(key) { return (await load())[key] ?? null; },
    async setItem(key, value) {
      const all = await load(); all[key] = value;
      const temporary = `${file}.${process.pid}.tmp`, handle = await open(temporary, 'w', 0o600);
      try { await handle.writeFile(JSON.stringify(all)); await handle.sync(); } finally { await handle.close(); }
      await rename(temporary, file);
    },
  };
}

/// The chain, as a service uses it: `{ kind, origin, readState(selection), submit(bytes) }`.
/// - `readState` gives `{ state }`, verified; it throws when no proof could be had or verified.
/// - `submit` hands a signed action in and gives `{ accepted: true }` (the node took it; it is not in a block yet),
///   `{ accepted: true, known: true }` (the node holds these bytes already), or `{ accepted: false, reason }` (the
///   node refused it: `reason` is its word, as one line of plain text). It throws an EndpointError when nobody
///   answered: the same bytes can be sent again.
/// For tests: `rpc` (a function like createRpc's) and `fetcher` replace the network.
export function createTimeEndpoint({ rpcUrl, gateway, trust, verifier, storage, timeoutMs = 30000, rpc, fetcher }) {
  if ((rpcUrl === undefined) === (gateway === undefined)) throw new Error('The chain is reached through exactly one of rpc_url and gateway');
  const known = (text) => /already exists in cache/i.test(text);
  if (rpcUrl !== undefined) {
    const call = rpc ?? createRpc(rpcUrl, { timeoutMs, ...(fetcher ? { fetcher } : {}) }), read = createStateReader({ rpc: call, trust, verifier, storage });
    return Object.freeze({
      kind: 'rpc', origin: new URL(rpcUrl).origin,
      readState: (selection) => within(read(selection), timeoutMs * 2, 'The Time node'),
      async submit(bytes) {
        let result;
        try { result = await call('/broadcast_tx_sync', { tx: `0x${Buffer.from(bytes).toString('hex')}` }); } catch (error) {
          if (error instanceof IndexerError && known(error.rpcMessage || '')) return { accepted: true, known: true };
          throw new EndpointError('The Time node did not take the action');
        }
        const code = Object.hasOwn(result ?? {}, 'code') ? result.code : 0;
        return code === 0 ? { accepted: true } : { accepted: false, reason: plainText(result?.log, 200) || 'no reason given' };
      },
    });
  }
  const bounded = (url, options = {}) => (fetcher ?? globalThis.fetch)(url, { ...options, signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs) });
  const client = SDK.createClient({ gateway, trust, verifier, checkpointStorage: storage, fetcher: bounded });
  return Object.freeze({
    kind: 'gateway', origin: new URL(gateway).origin,
    readState: (selection) => within(client.getVerifiedState(selection), timeoutMs * 2, 'The gateway'),
    async submit(bytes) {
      try { await client.request('/api/submit', { method: 'POST', body: JSON.stringify({ tx: SDK.base64(bytes) }) }, { again: true }); return { accepted: true }; } catch (error) {
        // `gateway: true` marks the gateway's own words (the node's reason, passed on); anything else is no answer.
        if (error?.gateway !== true) throw new EndpointError('The gateway did not take the action');
        if (known(error.message)) return { accepted: true, known: true };
        return { accepted: false, reason: plainText(error.message, 200) || 'no reason given' };
      }
    },
  });
}

/// The Bitcoin header chain the Time chain follows, read from a verified state that was asked for with
/// `include_bitcoin` (the row `bitcoin/meta`): `{ network, bestHeight, bestTip, bestWork, tips, halted, maxBatch,
/// maxReorg, maxTipAgeSecs, creditedHeight, prunedBelow }`. `tips` are the ends of every branch the chain holds, the
/// best one among them; `bestWork` is the total work of the best branch, as a number (what Bitcoin Core calls
/// `chainwork`); `halted` is null, or `{ reason, commonHeight }` once a reorganisation has halted the header chain.
export function headerChainOf(state) {
  const meta = state?.bitcoin?.meta, config = meta?.config;
  const whole = (value, most = 0xffffffff) => Number.isInteger(value) && value >= 0 && value <= most;
  const sound = meta && typeof meta === 'object' && config && typeof config === 'object' && ['mainnet', ...OPEN_NETWORKS].includes(config.network)
    && whole(meta.best_height) && HASH.test(meta.best_tip ?? '') && HASH.test(meta.best_work ?? '') && Array.isArray(meta.tips) && meta.tips.length >= 1 && meta.tips.every((tip) => HASH.test(tip ?? '')) && meta.tips.includes(meta.best_tip)
    && Object.hasOwn(meta, 'halted') && (meta.halted === null || (typeof meta.halted === 'object' && typeof meta.halted.reason === 'string'))
    && whole(config.max_batch, 256) && config.max_batch >= 1 && whole(config.max_reorg) && whole(config.max_tip_age_secs, Number.MAX_SAFE_INTEGER) && whole(meta.credited_height) && whole(meta.pruned_below);
  if (!sound) throw new Error('The state does not prove the Bitcoin header chain; ask for it with include_bitcoin');
  return {
    network: config.network, bestHeight: meta.best_height, bestTip: meta.best_tip, bestWork: BigInt(`0x${meta.best_work}`), tips: [...meta.tips],
    halted: meta.halted === null ? null : { reason: plainText(meta.halted.reason, 40), commonHeight: whole(meta.halted.common_height) ? meta.halted.common_height : null },
    maxBatch: config.max_batch, maxReorg: config.max_reorg, maxTipAgeSecs: config.max_tip_age_secs, creditedHeight: meta.credited_height, prunedBelow: meta.pruned_below,
  };
}

/// Reads a signing key: the 32-byte Ed25519 seed as 64 lowercase hexadecimal characters, from the environment
/// variable `env` names or from the file `file` names (exactly one of the two). Returns the public key (hex) and a
/// private key that cannot be exported.
/// - The variable is removed from this process's environment once it is read, so that nothing started later
///   inherits it.
/// - The file must be readable by its owner only (Windows keeps no such modes: the check is the operator's there).
/// - No error names what the variable or the file holds.
export async function loadSigningKey({ env, file }, environment = process.env) {
  if ((env === undefined) === (file === undefined)) throw new Error('The key comes from exactly one of key_env and key_file');
  let text;
  if (env !== undefined) {
    text = environment[env];
    if (typeof text !== 'string' || text === '') throw new Error('The environment variable that key_env names is not set');
    delete environment[env];
  } else {
    let info;
    try { info = await stat(file); text = await readFile(file, 'utf8'); } catch { throw new Error('The key file could not be read'); }
    if (!info.isFile()) throw new Error('key_file is not a file');
    if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) throw new Error('The key file can be read by other users of this machine: chmod 600 it');
  }
  const match = /^([0-9a-f]{64})\r?\n?$/.exec(text);
  text = undefined;
  if (!match) throw new Error('The key is one line: the 32-byte Ed25519 seed as 64 lowercase hexadecimal characters');
  const der = SDK.hexToBytes(`302e020100300506032b657004220420${match[1]}`);
  try {
    const exportable = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
    const publicKey = SDK.bytesToHex(new Uint8Array(Buffer.from((await crypto.subtle.exportKey('jwk', exportable)).x, 'base64url')));
    return { publicKey, privateKey: await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']) };
  } catch { throw new Error('The key is not a usable Ed25519 key'); } finally { der.fill(0); }
}

/// Refuses a file that holds a secret and that other users of this machine can read. Windows keeps no such modes.
export async function ownerOnly(file, what) {
  let info;
  try { info = await stat(file); } catch { throw new Error(`${what} could not be read`); }
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) throw new Error(`${what} holds a secret and can be read by other users of this machine: chmod 600 it`);
}

/// The health answer of a service, on a local port: `GET /health` and nothing else. `status()` gives
/// `{ ok, body }`: the answer is 200 when `ok`, 503 when not, so that a monitor needs no parsing to raise an alarm.
/// It answers under this machine's own names and those in `hosts` only (another name gets 421, which stops a web
/// page from reading it through DNS rebinding). The body holds heights, counts and times, never a key, a password,
/// the address of a node or an account.
export function createHealthServer({ status, host = '127.0.0.1', port = 0, hosts = [] }) {
  const send = (response, code, value) => {
    response.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    response.end(JSON.stringify(value));
  };
  const server = http.createServer((request, response) => {
    const bound = server.address()?.port;
    const allowed = new Set([`127.0.0.1:${bound}`, `localhost:${bound}`, `[::1]:${bound}`, ...hosts]);
    if (!allowed.has(String(request.headers.host || '').toLowerCase())) return send(response, 421, { error: 'unknown host' });
    if (request.method !== 'GET') return send(response, 405, { error: 'read-only' });
    if (new URL(request.url, 'http://health.invalid').pathname !== '/health') return send(response, 404, { error: 'not found' });
    let answer;
    try { answer = status(); } catch { return send(response, 503, { ok: false, status: 'health_unavailable' }); }
    return send(response, answer.ok ? 200 : 503, answer.body);
  });
  return {
    listen: () => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { const a = server.address(); resolve(`http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`); }); }),
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}

/// A message said once: `once(key)` is true the first time a key is seen, and again after `again` milliseconds.
/// The log of a service that meets the same trouble every round then holds it once, and a reminder now and then.
export function createOnce({ again = 3_600_000, now = Date.now, most = 4096 } = {}) {
  const seen = new Map();
  const once = (key) => {
    const at = now(), last = seen.get(key);
    if (last !== undefined && at - last < again) return false;
    seen.delete(key); seen.set(key, at);
    if (seen.size > most) seen.delete(seen.keys().next().value);
    return true;
  };
  once.forget = (key) => { seen.delete(key); };
  return once;
}
