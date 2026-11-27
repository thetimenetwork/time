#!/usr/bin/env node
// The relay of Bitcoin block headers for a Time network with the market (client-v4/market-relay.mjs).
// Reads one JSON config file, asks the operator's Bitcoin nodes for headers the chain does not hold yet, and hands
// them to the chain as kind 40 actions, which are unsigned and free. It holds no key of any kind: no Time key, no
// bitcoin key, and it never asks for one.
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../../client-v4/time-sdk.js';
import * as installedVerifier from '../../client-v4/proof-verifier.mjs';
import { createBitcoinNodes, createBitcoinRpc, nodeLogin } from '../../client-v4/bitcoin-rpc.mjs';
import { checkpointFile, createHealthServer, createTimeEndpoint, ownerOnly } from '../../client-v4/market-service.mjs';
import { createRelay } from '../../client-v4/market-relay.mjs';
// The lock, the log format and the config reader are the watch's, unchanged: one instance per data directory,
// JSON lines, and a config error that never quotes the file.
import { claim, jsonLog, readConfig, LOCK_LOST_EXIT } from '../watch/start.mjs';

const KEYS = ['rpc_url', 'gateway', 'trust', 'bitcoin_nodes', 'data_directory', 'poll_seconds', 'max_actions_per_round', 'deep_reorg', 'max_header_age_seconds', 'max_behind_seconds', 'max_disagree_seconds',
  'bitcoin_timeout_seconds', 'time_timeout_seconds', 'host', 'port', 'hosts'];
const NODE_KEYS = ['name', 'url', 'cookie_file', 'user', 'password', 'password_file'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/// A whole number of the config, or its default; refused outside its bounds.
export function wholeOf(config, name, fallback, min, max) {
  const value = config[name] ?? fallback;
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
  return value;
}
/// How the chain is reached: exactly one of `rpc_url` (the CometBFT RPC of a Time node) and `gateway` (the public
/// origin of a wallet gateway), with the trust manifest. Returns `{ rpc_url }` or `{ gateway }`, and `trust`.
export function validateEndpoint(config) {
  const trust = config.trust;
  if (!trust || typeof trust !== 'object' || String(trust.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust.network_id ?? '') || typeof trust.chain_id !== 'string' || !trust.chain_id) throw new Error('trust is the application-4 trust manifest the SDK takes (app_version, network_id, chain_id, ...)');
  if ((config.rpc_url === undefined) === (config.gateway === undefined)) throw new Error('Give exactly one of rpc_url (the CometBFT RPC of a Time node) and gateway (the public origin of a wallet gateway)');
  const name = config.rpc_url === undefined ? 'gateway' : 'rpc_url';
  let url;
  try { url = new URL(config[name]); } catch { throw new Error(`${name} is an address`); }
  if (typeof config[name] !== 'string' || url.username || url.password || !(url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname)))) throw new Error(`${name} must be https:// (http:// only on this machine), without user name or password`);
  if (`${url.origin}/` !== url.href) throw new Error(`${name} is an origin only: no path, query or fragment`);
  return { [name]: url.href, trust };
}
/// The Bitcoin nodes of a config: one to eight, each `{ name, url }` with a cookie file, or a user name with a
/// password or a password file. An address is https://, or http:// on this machine: Bitcoin Core's RPC has no
/// encryption of its own, and its password would cross a network in the clear.
export function validateNodes(config) {
  const list = config.bitcoin_nodes;
  if (!Array.isArray(list) || list.length < 1 || list.length > 8) throw new Error('bitcoin_nodes lists one to eight Bitcoin nodes');
  const nodes = list.map((entry, index) => {
    const where = `bitcoin_nodes[${index}]`;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).some((key) => !NODE_KEYS.includes(key))) throw new Error(`${where} takes ${NODE_KEYS.join(', ')}`);
    if (typeof entry.name !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(entry.name)) throw new Error(`${where}: name is a short name of your own, in lower case (letters, digits, - and _)`);
    let url;
    try { url = new URL(entry.url); } catch { throw new Error(`${where}: url is the RPC address of a Bitcoin node`); }
    if (typeof entry.url !== 'string' || url.username || url.password || `${url.origin}/` !== url.href || !(url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname)))) throw new Error(`${where}: url must be https:// (http:// only on this machine), an origin without user name, password or path. A node on another machine is reached through a tunnel to this machine or a TLS proxy`);
    const file = (key) => { if (typeof entry[key] !== 'string' || !path.isAbsolute(entry[key])) throw new Error(`${where}: ${key} is an absolute path`); return path.resolve(entry[key]); };
    const withCookie = entry.cookie_file !== undefined, withUser = entry.user !== undefined;
    if (withCookie === withUser || (withCookie && (entry.password !== undefined || entry.password_file !== undefined))) throw new Error(`${where}: give cookie_file, or user with password_file (or password)`);
    if (withCookie) return { name: entry.name, url: url.href, cookie_file: file('cookie_file') };
    if (typeof entry.user !== 'string' || !/^[\x21-\x39\x3b-\x7e]{1,64}$/.test(entry.user)) throw new Error(`${where}: user is the RPC user name, without a colon`);
    if ((entry.password === undefined) === (entry.password_file === undefined)) throw new Error(`${where}: give exactly one of password_file and password`);
    if (entry.password_file !== undefined) return { name: entry.name, url: url.href, user: entry.user, password_file: file('password_file') };
    if (typeof entry.password !== 'string' || entry.password.length < 1 || entry.password.length > 256) throw new Error(`${where}: password is the RPC password`);
    return { name: entry.name, url: url.href, user: entry.user, password: entry.password };
  });
  if (new Set(nodes.map((node) => node.name)).size !== nodes.length) throw new Error('Two Bitcoin nodes have the same name');
  return nodes;
}
/// Where the health answer is served: `host`, `port` and extra `hosts`.
export function validateListening(config, port) {
  const host = config.host ?? '127.0.0.1';
  if (typeof host !== 'string' || !host) throw new Error('host is the address to listen on');
  const hosts = config.hosts ?? [];
  if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string' && /^[a-z0-9.[\]:-]+:[0-9]{1,5}$/.test(h))) throw new Error('hosts lists extra Host header values, each "name:port" in lower case');
  return { host, port: wholeOf(config, 'port', port, 1024, 65535), hosts: [...hosts] };
}
/// Whether a config holds a secret in its own text (the password of a Bitcoin node).
export const holdsSecret = (config) => Array.isArray(config?.bitcoin_nodes) && config.bitcoin_nodes.some((node) => node && typeof node === 'object' && node.password !== undefined);

/// Checks a config and fills in the defaults. Throws on anything unknown or malformed, and never puts a value of
/// the config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  const deep = config.deep_reorg ?? 'stop';
  if (!['stop', 'relay'].includes(deep)) throw new Error('deep_reorg is "stop" or "relay"');
  return {
    ...validateEndpoint(config), bitcoin_nodes: validateNodes(config), data_directory: path.resolve(config.data_directory),
    poll_seconds: wholeOf(config, 'poll_seconds', 10, 1, 600), max_actions_per_round: wholeOf(config, 'max_actions_per_round', 4, 1, 64), deep_reorg: deep,
    max_header_age_seconds: wholeOf(config, 'max_header_age_seconds', 3600, 60, 1209600), max_behind_seconds: wholeOf(config, 'max_behind_seconds', 300, 30, 86400), max_disagree_seconds: wholeOf(config, 'max_disagree_seconds', 1800, 60, 86400),
    bitcoin_timeout_seconds: wholeOf(config, 'bitcoin_timeout_seconds', 15, 1, 120), time_timeout_seconds: wholeOf(config, 'time_timeout_seconds', 30, 2, 300),
    ...validateListening(config, 8950),
  };
}

/// The configured Bitcoin nodes as one source (client-v4/bitcoin-rpc.mjs). `fetcher` replaces the network in tests.
export function bitcoinNodesOf(config, fetcher) {
  return createBitcoinNodes(config.bitcoin_nodes.map((node) => ({
    name: node.name,
    rpc: createBitcoinRpc({ url: node.url, login: nodeLogin({ cookieFile: node.cookie_file, user: node.user, password: node.password, passwordFile: node.password_file }), timeoutMs: config.bitcoin_timeout_seconds * 1000, ...(fetcher ? { fetcher } : {}) }),
  })));
}
/// The Time endpoint of a config (client-v4/market-service.mjs), with the light client's checkpoint kept in the
/// data directory.
export function timeEndpointOf(config, inject = {}) {
  return createTimeEndpoint({ rpcUrl: config.rpc_url, gateway: config.gateway, trust: config.trust, verifier: installedVerifier, storage: checkpointFile(path.join(config.data_directory, 'checkpoint.json')), timeoutMs: config.time_timeout_seconds * 1000, ...(inject.timeRpc ? { rpc: inject.timeRpc } : {}), ...(inject.timeFetcher ? { fetcher: inject.timeFetcher } : {}) });
}
/// Claims the data directory for one instance of `what`, with the watch's lock.
export async function claimFor(directory, what, log, onLost) {
  try {
    return await claim(directory, { onLost: async (why) => { log('error', `this ${what} lost the lock of its data directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}, so that only one instance runs`); await onLost(); } });
  } catch (error) {
    throw new Error(String(error.message).replace(/^Another watch \(/, `Another instance (`).replace(/^This process already watches /, 'This process already uses '));
  }
}

/// Starts the relay. `inject` replaces parts for tests: endpoint ({ readState, submit }), bitcoinFetcher, log, now.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let relay, server;
  const release = await claimFor(config.data_directory, 'relay', log, async () => { await relay?.stop(); await server?.close().catch(() => {}); });
  try {
    const endpoint = inject.endpoint || timeEndpointOf(config, inject);
    relay = createRelay({
      nodes: bitcoinNodesOf(config, inject.bitcoinFetcher), readState: endpoint.readState, submit: endpoint.submit, networkId: config.trust.network_id, log, ...(inject.now ? { now: inject.now } : {}),
      settings: { maxActionsPerRound: config.max_actions_per_round, deepReorg: config.deep_reorg, maxHeaderAgeSeconds: config.max_header_age_seconds, maxBehindSeconds: config.max_behind_seconds, maxDisagreeSeconds: config.max_disagree_seconds, pollMs: config.poll_seconds * 1000 },
    });
    server = createHealthServer({ status: () => relay.health(), host: config.host, port: config.port, hosts: config.hosts });
    const listening = await server.listen();
    // Names, origins and numbers only: never a password, a cookie or the path of one.
    log('info', 'market header relay started', {
      health: `${listening}/health`, time_endpoint: endpoint.origin ?? null, reached_through: endpoint.kind ?? null, network_id: config.trust.network_id, chain_id: config.trust.chain_id,
      bitcoin_nodes: config.bitcoin_nodes.map((node) => node.name), poll_seconds: config.poll_seconds, max_actions_per_round: config.max_actions_per_round, deep_reorg: config.deep_reorg,
    });
    if (config.deep_reorg === 'relay') log('warn', 'deep_reorg is "relay": a branch that halts the chain\'s header chain for good is handed in without a person looking first');
    if (inject.autoStart !== false) relay.start();
    let closing;
    return { url: listening, relay, close: () => closing ??= (async () => { await relay.stop(); await server.close(); await release(); })() };
  } catch (error) {
    await relay?.stop(); await server?.close().catch(() => {}); await release();
    throw error;
  }
}

/// Reads a config file for a service of the market. A config that holds a password in its own text is refused
/// when other users of this machine can read the file.
export async function readServiceConfig(file) {
  const config = await readConfig(file);
  if (holdsSecret(config)) await ownerOnly(file, 'The config file');
  return config;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/market-relay/start.mjs CONFIG_JSON');
    const running = await start(await readServiceConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
