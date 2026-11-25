#!/usr/bin/env node
// The API process: indexes a Time network from a CometBFT RPC and serves the public HTTP API
// (client-v4/api.mjs) for exchanges, wallets, shops and an explorer.
// Reads one JSON config file. It holds no key of any account and signs nothing: it reads,
// verifies, indexes and passes signed actions on.
import { mkdir } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as installedVerifier from '../../client-v4/proof-verifier.mjs';
import { createApiService, clientKey, checkExplorerJoin } from '../../client-v4/api.mjs';
import { createRpc } from '../../client-v4/indexer.mjs';
import { checkWebhookURL, webhookSecretProblem, WEBHOOK_SECRET_RULE } from '../../client-v4/security-watch-service.mjs';
// The lock, the log format and the config reader are the watch's, unchanged: one instance per
// data directory, JSON lines, and a config error that never quotes the file.
import { claim, jsonLog, readConfig, LOCK_LOST_EXIT } from '../watch/start.mjs';

const KEYS = ['rpc_url', 'trust', 'data_directory', 'start_height', 'host', 'port', 'hosts', 'cors_origins', 'rate_limit', 'trusted_proxies', 'webhooks', 'max_lag_seconds', 'rpc_timeout_seconds', 'max_streams', 'max_stream_seconds', 'reserved_stream_clients', 'serve_explorer', 'explorer_join', 'max_touch_streams', 'max_touch_streams_per_client', 'unfiltered_stream_percent', 'max_proof_reads_per_client'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const canonicalId = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 18446744073709551615n;

/// Checks a config and fills in the defaults. Throws on anything unknown or malformed, and never
/// puts a value of the config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  let rpc;
  try { rpc = new URL(config.rpc_url); } catch { throw new Error('rpc_url is the address of a CometBFT RPC'); }
  if (typeof config.rpc_url !== 'string' || rpc.username || rpc.password || !(rpc.protocol === 'https:' || (rpc.protocol === 'http:' && LOOPBACK.has(rpc.hostname)))) throw new Error('rpc_url must be https:// (http:// only on this machine), without user name or password. A node on another machine is reached through a tunnel to this machine or a TLS proxy: see "A node on another machine" in deploy/api/README.md');
  if (`${rpc.origin}/` !== rpc.href) throw new Error('rpc_url is an origin only: no path, query or fragment');
  const trust = config.trust;
  if (!trust || typeof trust !== 'object' || String(trust.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust.network_id ?? '') || typeof trust.chain_id !== 'string' || !trust.chain_id) throw new Error('trust is the application-4 trust manifest the SDK takes (app_version, network_id, chain_id, ...)');
  if (trust.nodes_report_upgrades !== undefined && typeof trust.nodes_report_upgrades !== 'boolean') throw new Error('trust.nodes_report_upgrades is true or false');
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  const integer = (value, name, fallback, min, max) => {
    const number = value ?? fallback;
    if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
    return number;
  };
  const host = config.host ?? '127.0.0.1';
  if (typeof host !== 'string' || !host) throw new Error('host is the address to listen on');
  const hosts = config.hosts ?? [];
  // A name as clients send it in Host: with a port, or without one when the port is 80 or 443.
  if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string' && /^(?:\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?$/.test(h))) throw new Error('hosts lists extra Host header values in lower case, each "name" or "name:port"');
  const origins = config.cors_origins ?? [];
  const isOrigin = (value) => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && url.origin === value; } catch { return false; } };
  if (!Array.isArray(origins) || !(origins.every((o) => typeof o === 'string' && isOrigin(o)) || (origins.length === 1 && origins[0] === '*'))) throw new Error('cors_origins lists exact origins such as "https://explorer.example", or is ["*"] alone');
  const limit = config.rate_limit ?? {};
  if (!limit || typeof limit !== 'object' || Array.isArray(limit) || Object.keys(limit).some((k) => !['per_second', 'burst'].includes(k))) throw new Error('rate_limit takes per_second and burst');
  const proxies = config.trusted_proxies ?? [];
  if (!Array.isArray(proxies) || !proxies.every((p) => typeof p === 'string' && net.isIP(p) !== 0)) throw new Error('trusted_proxies lists the IP addresses of your own reverse proxies');
  const reservedClients = config.reserved_stream_clients ?? [];
  if (!Array.isArray(reservedClients) || !reservedClients.every((p) => typeof p === 'string' && net.isIP(p) !== 0)) throw new Error('reserved_stream_clients lists IP addresses that always get an event stream');
  // A proxy that is also reserved would make every request it passes on without X-Forwarded-For a reserved one.
  const sameAddress = (a, b) => clientKey(a) === clientKey(b);
  if (reservedClients.some((client) => proxies.some((proxy) => sameAddress(client, proxy)))) throw new Error('An address cannot be both in trusted_proxies and in reserved_stream_clients');
  const hooks = config.webhooks ?? [];
  if (!Array.isArray(hooks)) throw new Error('webhooks is a list');
  const webhooks = hooks.map((hook, i) => {
    if (!hook || typeof hook !== 'object' || Object.keys(hook).sort().join(',') !== 'account,secret,url') throw new Error(`webhook ${i}: account, url and secret, nothing else`);
    if (!canonicalId(hook.account)) throw new Error(`webhook ${i}: account is a decimal account number in quotes`);
    try { checkWebhookURL(hook.url); } catch (error) { throw new Error(`webhook ${i}: ${error.message}`); }
    const problem = webhookSecretProblem(hook.secret);
    if (problem) throw new Error(`webhook ${i}: the secret ${problem}. ${WEBHOOK_SECRET_RULE}`);
    return { account: hook.account, url: hook.url, secret: hook.secret };
  });
  const pairs = webhooks.map((hook) => JSON.stringify([hook.account, hook.url]));
  if (new Set(pairs).size !== pairs.length) throw new Error('A webhook is listed twice for the same account');
  if (config.serve_explorer !== undefined && typeof config.serve_explorer !== 'boolean') throw new Error('serve_explorer is true or false');
  // This network's facts for the explorer's "Run a validator": only for the explorer this service serves.
  if (config.explorer_join !== undefined && config.serve_explorer !== true) throw new Error('explorer_join is shown by the explorer this service serves: it needs "serve_explorer": true');
  const join = config.explorer_join === undefined ? null : checkExplorerJoin(config.explorer_join, trust.chain_id);
  const perSecond = integer(limit.per_second, 'rate_limit.per_second', 20, 1, 1000);
  return {
    rpc_url: rpc.href, trust, data_directory: path.resolve(config.data_directory),
    start_height: integer(config.start_height, 'start_height', 1, 1, Number.MAX_SAFE_INTEGER),
    host, port: integer(config.port, 'port', 8930, 1024, 65535), hosts: hosts.map((h) => h.toLowerCase()), cors_origins: [...origins],
    rate_limit: { per_second: perSecond, burst: integer(limit.burst, 'rate_limit.burst', Math.max(60, perSecond), perSecond, 10000) },
    trusted_proxies: [...proxies], webhooks,
    max_lag_seconds: integer(config.max_lag_seconds, 'max_lag_seconds', 120, 5, 86400),
    rpc_timeout_seconds: integer(config.rpc_timeout_seconds, 'rpc_timeout_seconds', 10, 1, 120),
    max_streams: integer(config.max_streams, 'max_streams', 100, 0, 10000),
    max_stream_seconds: integer(config.max_stream_seconds, 'max_stream_seconds', 900, 30, 86400),
    reserved_stream_clients: [...reservedClients],
    // The places kept for streams that follow no account, and the proof reads one client may have under way (README).
    unfiltered_stream_percent: integer(config.unfiltered_stream_percent, 'unfiltered_stream_percent', 20, 0, 90),
    max_proof_reads_per_client: integer(config.max_proof_reads_per_client, 'max_proof_reads_per_client', 2, 1, 64),
    // Off unless asked for: the API then also serves the explorer's pages under /explorer/.
    ...(config.serve_explorer === true ? { serve_explorer: true } : {}),
    ...(join ? { explorer_join: join } : {}),
    // The hints for wallets (GET /v1/touches), only when set: 2000 places, 16 per client, unless the config says otherwise.
    ...(config.max_touch_streams === undefined ? {} : { max_touch_streams: integer(config.max_touch_streams, 'max_touch_streams', 2000, 0, 100000) }),
    ...(config.max_touch_streams_per_client === undefined ? {} : { max_touch_streams_per_client: integer(config.max_touch_streams_per_client, 'max_touch_streams_per_client', 16, 1, 1000) }),
  };
}

/// Starts the service. `inject` replaces parts for tests: rpc, readState, webhookFetcher, log, now, pollMs.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let service;
  let release;
  try {
    release = await claim(config.data_directory, {
      // Another instance took over while this one stalled: stop indexing and delivering, and exit non-zero.
      onLost: async (why) => {
        log('error', `this API lost the lock of its data directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}, so that only one instance indexes and delivers`);
        await service?.close().catch(() => {});
      },
    });
  } catch (error) {
    // The lock is the watch's, and two of its messages speak of a watch. Only their fixed first
    // words are replaced: a directory that has "watch" in its name is left as it is.
    throw new Error(String(error.message).replace(/^Another watch \(/, 'Another API instance (').replace(/^This process already watches /, 'This process already serves '));
  }
  try {
    service = await createApiService({
      trust: config.trust, verifier: installedVerifier,
      rpc: inject.rpc || createRpc(config.rpc_url, { timeoutMs: config.rpc_timeout_seconds * 1000 }),
      dataFile: path.join(config.data_directory, 'index.sqlite'), startHeight: config.start_height,
      host: config.host, port: config.port, hosts: config.hosts, corsOrigins: config.cors_origins,
      rateLimit: { perSecond: config.rate_limit.per_second, burst: config.rate_limit.burst }, trustedProxies: config.trusted_proxies,
      webhooks: config.webhooks, maxLagSeconds: config.max_lag_seconds,
      maxStreams: config.max_streams, maxStreamSeconds: config.max_stream_seconds, reservedStreamClients: config.reserved_stream_clients,
      unfilteredStreamPercent: config.unfiltered_stream_percent, maxProofReadsPerClient: config.max_proof_reads_per_client,
      ...(config.max_touch_streams === undefined ? {} : { maxTouchStreams: config.max_touch_streams }), ...(config.max_touch_streams_per_client === undefined ? {} : { maxTouchStreamsPerClient: config.max_touch_streams_per_client }),
      explorer: config.serve_explorer === true, explorerJoin: config.explorer_join ?? null, log,
      ...(inject.readState ? { readState: inject.readState } : {}), ...(inject.webhookFetcher ? { webhookFetcher: inject.webhookFetcher } : {}),
      ...(inject.now ? { now: inject.now } : {}), ...(inject.pollMs ? { pollMs: inject.pollMs } : {}),
    });
    // Origins and counts only: no secret, and no path or query of the RPC or of a webhook.
    log('info', 'time api started', {
      listening: service.url, rpc: new URL(config.rpc_url).origin, network_id: config.trust.network_id, chain_id: config.trust.chain_id,
      // From the trust data: whether every verified read carries the question about scheduled upgrades.
      nodes_report_upgrades: config.trust.nodes_report_upgrades === true,
      start_height: config.start_height, webhooks: config.webhooks.map((hook) => new URL(hook.url).origin), cors_origins: config.cors_origins.length, trusted_proxies: config.trusted_proxies.length, serve_explorer: config.serve_explorer === true, explorer_join: config.explorer_join !== undefined,
    });
    let closing;
    return { url: service.url, service, close: () => closing ??= (async () => { await service.close(); await release(); })() };
  } catch (error) {
    await service?.close().catch(() => {}); await release();
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/api/start.mjs CONFIG_JSON');
    const running = await start(await readConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
