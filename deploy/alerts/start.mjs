#!/usr/bin/env node
// The alert service process: wakes the closed wallets of a Time network with a browser push that claims nothing
// (client-v4/alert-push.mjs says what it does and why). Reads one JSON config file.
// It holds no key of any account and signs nothing on the chain: it reads blocks, verifies them, and sends the
// constant {"v":1} to the browsers that subscribed. Its only key is its own VAPID key, for the push services.
//
// What it writes in its data directory, and nothing else: subscriptions.json (the address list), vapid.json (its
// VAPID key), checkpoint.json (the newest block headers its light clients verified), and, while it runs, the lock
// that keeps a second instance off the same directory (deploy/watch/start.mjs, claim).
import { mkdir, open, readFile, rename, chmod } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../../client-v4/time-sdk.js';
import * as installedVerifier from '../../client-v4/proof-verifier.mjs';
import { createLightClient } from '../../client-v4/light-client.mjs';
import { fetchLightBlock } from '../../client-v4/certified-view.mjs';
import { createRpc } from '../../client-v4/indexer.mjs';
import { createStateReader } from '../../client-v4/api.mjs';
import { createAlertService, openSubscriptions, newVapidKeys, checkVapid, checkpointFile, FILES } from '../../client-v4/alert-push.mjs';
import { claim, jsonLog, readConfig, LOCK_LOST_EXIT } from '../watch/start.mjs';

const KEYS = ['rpc_url', 'trust', 'data_directory', 'origin', 'hosts', 'host', 'port', 'trusted_proxies', 'contact', 'rate_limit', 'rpc_timeout_seconds', 'max_subscriptions'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/// Checks a config and fills in the defaults. Throws on anything unknown or malformed, and never puts a value of the
/// config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  let rpc;
  try { rpc = new URL(config.rpc_url); } catch { throw new Error('rpc_url is the address of a CometBFT RPC'); }
  if (typeof config.rpc_url !== 'string' || rpc.username || rpc.password || !(rpc.protocol === 'https:' || (rpc.protocol === 'http:' && LOOPBACK.has(rpc.hostname))) || `${rpc.origin}/` !== rpc.href) throw new Error('rpc_url is an https:// origin (http:// only on this machine), with no path and no user name');
  const trust = config.trust;
  if (!trust || typeof trust !== 'object' || String(trust.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust.network_id ?? '') || typeof trust.chain_id !== 'string' || !trust.chain_id) throw new Error('trust is the application-4 trust manifest the SDK takes (app_version, network_id, chain_id, ...)');
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  // The wallet's public origin: where the pages come from, which every proof names, and where the requests come from.
  let origin;
  try { origin = new URL(config.origin); } catch { throw new Error('origin is the public origin of the wallet, such as https://wallet.example'); }
  if (typeof config.origin !== 'string' || origin.origin !== config.origin || origin.username || !(origin.protocol === 'https:' || (origin.protocol === 'http:' && LOOPBACK.has(origin.hostname)))) throw new Error('origin is the public https:// origin of the wallet, with no path (http:// only on this machine)');
  const hosts = config.hosts ?? [];
  if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string' && /^(?:\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?$/.test(h))) throw new Error('hosts lists extra Host header values in lower case, each "name" or "name:port"');
  const proxies = config.trusted_proxies ?? [];
  if (!Array.isArray(proxies) || !proxies.every((p) => typeof p === 'string' && net.isIP(p) !== 0)) throw new Error('trusted_proxies lists the IP addresses of your own reverse proxies');
  // The operator's contact for the push services (the `sub` of VAPID): an https address. The wallet's origin unless given.
  const contact = config.contact ?? config.origin;
  let contactUrl; try { contactUrl = new URL(contact); } catch { contactUrl = null; }
  if (typeof contact !== 'string' || !contactUrl || !(contactUrl.protocol === 'https:' || (contactUrl.protocol === 'http:' && LOOPBACK.has(contactUrl.hostname))) || contactUrl.username || contactUrl.password) throw new Error('contact is an https:// address where the operator of this service can be reached');
  const limit = config.rate_limit ?? {};
  if (!limit || typeof limit !== 'object' || Array.isArray(limit) || Object.keys(limit).some((k) => !['per_second', 'burst'].includes(k))) throw new Error('rate_limit takes per_second and burst');
  const integer = (value, name, fallback, min, max) => {
    const number = value ?? fallback;
    if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
    return number;
  };
  const perSecond = integer(limit.per_second, 'rate_limit.per_second', 2, 1, 100);
  return {
    rpc_url: rpc.href, trust, data_directory: path.resolve(config.data_directory), origin: config.origin, hosts: hosts.map((h) => h.toLowerCase()),
    host: typeof config.host === 'string' && config.host ? config.host : '127.0.0.1', port: integer(config.port, 'port', 8950, 1024, 65535),
    trusted_proxies: [...proxies], contact, rate_limit: { per_second: perSecond, burst: integer(limit.burst, 'rate_limit.burst', 30, perSecond, 1000) },
    rpc_timeout_seconds: integer(config.rpc_timeout_seconds, 'rpc_timeout_seconds', 10, 1, 120),
    max_subscriptions: integer(config.max_subscriptions, 'max_subscriptions', 50000, 1, 1000000),
  };
}

/// The service's VAPID key: read from vapid.json, or made once and written there, readable by this user only.
export async function vapidOf(directory) {
  const file = path.join(directory, FILES.vapid);
  let text = null;
  try { text = await readFile(file, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (text !== null) { let value; try { value = JSON.parse(text); } catch { throw new Error('vapid.json is damaged: it is not JSON'); } return checkVapid(value); }
  const keys = { version: 1, ...newVapidKeys() };
  const temporary = `${file}.${process.pid}.tmp`, handle = await open(temporary, 'w', 0o600);
  try { await handle.writeFile(JSON.stringify(keys)); await handle.sync(); } finally { await handle.close(); }
  await chmod(temporary, 0o600).catch(() => {});
  await rename(temporary, file);
  return checkVapid(keys);
}

/// Starts the service. `inject` replaces parts for tests: rpc, verifiedState, light, verify, fetcher, log, now, autoStart.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let service, checkpoints;
  let release;
  try {
    release = await claim(config.data_directory, {
      onLost: async (why) => {
        log('error', `this alert service lost the lock of its data directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}, so that only one instance sends`);
        await service?.close().catch(() => {});
      },
    });
  } catch (error) {
    throw new Error(String(error.message).replace(/^Another watch \(/, 'Another alert service (').replace(/^This process already watches /, 'This process already serves '));
  }
  try {
    const vapid = await vapidOf(config.data_directory);
    const subscriptions = await openSubscriptions({ file: path.join(config.data_directory, FILES.subscriptions), networkId: config.trust.network_id, maxTotal: config.max_subscriptions });
    checkpoints = checkpointFile(path.join(config.data_directory, FILES.checkpoint));
    const rpc = inject.rpc || createRpc(config.rpc_url, { timeoutMs: config.rpc_timeout_seconds * 1000 });
    const light = inject.light || createLightClient({ trust: config.trust, verifier: installedVerifier, storage: checkpoints.scope('blocks'), fetchBlock: (height) => fetchLightBlock({ rpc, height }) });
    const reader = inject.verifiedState || createStateReader({ rpc, trust: config.trust, verifier: installedVerifier, storage: checkpoints.scope('state') });
    // A verified read that takes too long is given up: whoever asked is refused and may ask again.
    const verifiedState = (selection) => Promise.race([reader(selection), new Promise((_, reject) => { const t = setTimeout(() => reject(new Error('The node did not answer in time')), config.rpc_timeout_seconds * 1500); t.unref?.(); })]);
    service = await createAlertService({
      rpc, trust: config.trust, light, verifiedState, origin: config.origin, hosts: config.hosts, subscriptions, vapid, subject: config.contact,
      host: config.host, port: config.port, trustedProxies: config.trusted_proxies, rateLimit: { perSecond: config.rate_limit.per_second, burst: config.rate_limit.burst },
      log, ...(inject.fetcher ? { fetcher: inject.fetcher } : {}), ...(inject.now ? { now: inject.now } : {}), ...(inject.verify ? { verify: inject.verify } : {}), ...(inject.autoStart === false ? { autoStart: false } : {}),
    });
    // Origins and counts only: no endpoint, no key, no path of the RPC.
    log('info', 'time alerts started', { listening: service.url, rpc: new URL(config.rpc_url).origin, network_id: config.trust.network_id, origin: config.origin, ...subscriptions.counts(), trusted_proxies: config.trusted_proxies.length });
    let closing;
    return { url: service.url, service, close: () => closing ??= (async () => { await service.close(); await checkpoints.flush(); await release(); })() };
  } catch (error) {
    await service?.close().catch(() => {}); await checkpoints?.flush().catch(() => {}); await release();
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/alerts/start.mjs CONFIG_JSON');
    const running = await start(await readConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
