#!/usr/bin/env node
// The test-bitcoin service of a Time TEST network (client-v4/test-bitcoin.mjs): runs a private Bitcoin node in
// regtest, mines its blocks on a fixed pace, makes receiving addresses for testers and pays any regtest address
// on request. Play money: a regtest chain is worth nothing. Reads one JSON config file. It holds no Time key.
// It refuses a Bitcoin node whose chain is not regtest, and sends such a node nothing but the question.
import { mkdir } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { nodeLogin } from '../../client-v4/bitcoin-rpc.mjs';
import { createArchive, createNodeRunner, createTestBitcoinService, createWalletRpc } from '../../client-v4/test-bitcoin.mjs';
// The lock, the log format and the config reader are the watch's, unchanged: one instance per directory, JSON
// lines, and a config error that never quotes the file.
import { claim, jsonLog, readConfig, LOCK_LOST_EXIT } from '../watch/start.mjs';

const KEYS = ['bitcoind_program', 'bitcoin_data_directory', 'bitcoin_rpc_port', 'bitcoin_node', 'wallet', 'data_directory', 'block_seconds', 'archive_directory', 'base_path',
  'max_payment_sats', 'per_caller_per_day_sats', 'payments_per_caller_per_hour', 'total_per_day_sats', 'total_payments_per_day', 'addresses_per_caller_per_day', 'total_addresses_per_day',
  'host', 'port', 'hosts', 'origins', 'rate_limit', 'trusted_proxies', 'rpc_timeout_seconds', 'serve_page'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/// Checks a config and fills in the defaults. Throws on anything unknown or malformed, and never puts a value of
/// the config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  const integer = (value, name, fallback, min, max) => {
    const number = value ?? fallback;
    if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
    return number;
  };
  const sats = (name, fallback) => {
    const value = config[name] ?? fallback;
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,15}$/.test(value) || BigInt(value) > 2_100_000_000_000_000n) throw new Error(`${name} is a whole number of satoshis from 1, as a decimal string`);
    return BigInt(value);
  };
  const directory = (name) => {
    if (typeof config[name] !== 'string' || !path.isAbsolute(config[name])) throw new Error(`${name} is an absolute path`);
    return path.resolve(config[name]);
  };

  // The node: one this service runs (the program and its data directory), or one that already runs.
  const own = config.bitcoind_program !== undefined || config.bitcoin_data_directory !== undefined;
  if (own === (config.bitcoin_node !== undefined)) throw new Error('Give either bitcoind_program with bitcoin_data_directory (the service runs the Bitcoin node), or bitcoin_node (a regtest node that already runs), not both and not neither');
  let node;
  if (own) {
    if (config.bitcoind_program === undefined || config.bitcoin_data_directory === undefined) throw new Error('bitcoind_program and bitcoin_data_directory go together');
    node = { bitcoind_program: directory('bitcoind_program'), bitcoin_data_directory: directory('bitcoin_data_directory'), bitcoin_rpc_port: integer(config.bitcoin_rpc_port, 'bitcoin_rpc_port', 18443, 1024, 65535) };
  } else {
    if (config.bitcoin_rpc_port !== undefined) throw new Error('bitcoin_rpc_port is the port of a node this service runs; a node that already runs is named by bitcoin_node.url');
    const given = config.bitcoin_node;
    if (!given || typeof given !== 'object' || Array.isArray(given) || Object.keys(given).some((key) => !['url', 'cookie_file'].includes(key))) throw new Error('bitcoin_node takes url and cookie_file');
    let url;
    try { url = new URL(given.url); } catch { throw new Error('bitcoin_node.url is the RPC address of a Bitcoin node'); }
    // The wallet's calls go there: a regtest node on this machine and nowhere else.
    if (typeof given.url !== 'string' || url.protocol !== 'http:' || !LOOPBACK.has(url.hostname) || url.username || url.password || `${url.origin}/` !== url.href) throw new Error('bitcoin_node.url is http:// on this machine (127.0.0.1, localhost or [::1]) with a port, without user name, password or path');
    if (typeof given.cookie_file !== 'string' || !path.isAbsolute(given.cookie_file)) throw new Error('bitcoin_node.cookie_file is the absolute path of the node\'s .cookie file');
    node = { bitcoin_node: { url: url.href, cookie_file: path.resolve(given.cookie_file) } };
  }
  const wallet = config.wallet ?? 'test';
  if (typeof wallet !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(wallet)) throw new Error('wallet is the name of the wallet: 1 to 32 lower-case letters, digits, - and _');
  const base = config.base_path ?? '/bitcoin';
  if (typeof base !== 'string' || !/^(?:\/[a-z0-9][a-z0-9-]{0,31}){0,4}$/.test(base)) throw new Error('base_path is the path the service answers under, such as "/bitcoin" (lower-case letters, digits and -), or "" for none');

  const max = sats('max_payment_sats', '5000000'), perCaller = sats('per_caller_per_day_sats', '100000000'), total = sats('total_per_day_sats', '20000000000');
  if (max < 546n) throw new Error('max_payment_sats is below the smallest amount a Bitcoin node passes on (546 satoshis)');
  if (perCaller < max) throw new Error('per_caller_per_day_sats is below one payment of max_payment_sats');
  if (total < perCaller) throw new Error('total_per_day_sats is below per_caller_per_day_sats');

  const host = config.host ?? '127.0.0.1';
  if (typeof host !== 'string' || !host) throw new Error('host is the address to listen on');
  const hosts = config.hosts ?? [];
  if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string' && /^(?:\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?$/.test(h))) throw new Error('hosts lists extra Host header values in lower case, each "name" or "name:port"');
  const origins = config.origins ?? [];
  const isOrigin = (value) => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && url.origin === value && !value.includes('*'); } catch { return false; } };
  if (!Array.isArray(origins) || !origins.every((o) => typeof o === 'string' && isOrigin(o))) throw new Error('origins lists exact origins such as "https://faucet.example"; there is no wildcard');
  if (config.serve_page !== undefined && typeof config.serve_page !== 'boolean') throw new Error('serve_page is true or false');
  // The page is served under the names in `hosts`, and its buttons call the service from the page's own origin.
  // The process cannot know the scheme it is reached under behind a proxy, so that origin must be listed; without
  // it the page would be served and its buttons refused. (The faucet's rule, deploy/faucet/start.mjs.)
  const publicName = (value) => value.toLowerCase().replace(/:(?:80|443)$/, '');
  if ((config.serve_page ?? true) && hosts.length > 0 && !origins.some((origin) => hosts.some((name) => publicName(new URL(origin).host) === publicName(name)))) {
    throw new Error('serve_page is on and hosts names where the service is reached, but origins lists no origin under one of those names: the page would be served and its own buttons refused. Add the origin of the page to origins, such as "https://" followed by the name in hosts, or set serve_page to false');
  }
  const rate = config.rate_limit ?? {};
  if (!rate || typeof rate !== 'object' || Array.isArray(rate) || Object.keys(rate).some((k) => !['per_second', 'burst'].includes(k))) throw new Error('rate_limit takes per_second and burst');
  const proxies = config.trusted_proxies ?? [];
  if (!Array.isArray(proxies) || !proxies.every((p) => typeof p === 'string' && net.isIP(p) !== 0)) throw new Error('trusted_proxies lists the IP addresses of your own reverse proxies');
  const perSecond = integer(rate.per_second, 'rate_limit.per_second', 5, 1, 1000);
  const archive = config.archive_directory === undefined ? {} : { archive_directory: directory('archive_directory') };
  // The service's own folder: it holds the lock that keeps a second service off the same node, and nothing else.
  const data = config.data_directory === undefined ? {} : { data_directory: directory('data_directory') };
  // The archive is copied elsewhere by another process, and the node rewrites its own directory as it likes: one inside the other would mix the two.
  if (own && archive.archive_directory) {
    const inside = (parent, child) => { const relative = path.relative(parent, child); return !relative || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)); };
    if (inside(node.bitcoin_data_directory, archive.archive_directory) || inside(archive.archive_directory, node.bitcoin_data_directory)) throw new Error('archive_directory and bitcoin_data_directory must be two directories, neither inside the other');
  }
  return {
    ...node, wallet, ...data, block_seconds: integer(config.block_seconds, 'block_seconds', 20, 5, 600), ...archive, base_path: base,
    max_payment_sats: max, per_caller_per_day_sats: perCaller, total_per_day_sats: total,
    payments_per_caller_per_hour: integer(config.payments_per_caller_per_hour, 'payments_per_caller_per_hour', 30, 1, 100000), total_payments_per_day: integer(config.total_payments_per_day, 'total_payments_per_day', 10000, 1, 1000000),
    addresses_per_caller_per_day: integer(config.addresses_per_caller_per_day, 'addresses_per_caller_per_day', 20, 1, 100000), total_addresses_per_day: integer(config.total_addresses_per_day, 'total_addresses_per_day', 5000, 1, 1000000),
    host, port: integer(config.port, 'port', 8960, 1024, 65535), hosts: hosts.map((h) => h.toLowerCase()), origins: [...origins],
    rate_limit: { per_second: perSecond, burst: integer(rate.burst, 'rate_limit.burst', Math.max(20, perSecond), perSecond, 10000) },
    trusted_proxies: [...proxies], rpc_timeout_seconds: integer(config.rpc_timeout_seconds, 'rpc_timeout_seconds', 15, 1, 120), serve_page: config.serve_page ?? true,
  };
}

/// Where a node this service runs keeps its cookie: the file the header relay and the prover are given too.
export const cookieFileOf = (dataDirectory) => path.join(dataDirectory, 'regtest', '.cookie');

/// Starts the service. `inject` replaces parts for tests: fetcher (the node's RPC), spawner, log, now, autoMine.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  const own = config.bitcoind_program !== undefined;
  const url = own ? `http://127.0.0.1:${config.bitcoin_rpc_port}/` : config.bitcoin_node.url, cookieFile = own ? cookieFileOf(config.bitcoin_data_directory) : config.bitcoin_node.cookie_file;
  const rpc = createWalletRpc({ url, login: nodeLogin({ cookieFile }), wallet: config.wallet, timeoutMs: config.rpc_timeout_seconds * 1000, ...(inject.fetcher ? { fetcher: inject.fetcher } : {}) });
  const runner = own ? createNodeRunner({
    program: config.bitcoind_program, datadir: config.bitcoin_data_directory, rpcPort: config.bitcoin_rpc_port, log, ...(inject.spawner ? { spawner: inject.spawner } : {}),
    answers: async () => { try { await rpc.chainInfo({ timeoutMs: 3000 }); return true; } catch { return false; } },
  }) : null;
  // One service per node: two would mine at twice the pace and write one archive. The lock is kept in the
  // service's own folder (data_directory); without one, in the node's data directory when the service runs the
  // node. A service without either has no lock.
  const lockIn = config.data_directory ?? (own ? config.bitcoin_data_directory : null);
  if (own) await mkdir(config.bitcoin_data_directory, { recursive: true, mode: 0o700 });
  let service, release = async () => {};
  if (lockIn) {
    await mkdir(lockIn, { recursive: true, mode: 0o700 });
    try {
      release = await claim(lockIn, { onLost: async (why) => {
        log('error', `this service lost the lock of its directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}, so that only one instance mines`);
        await service?.close().catch(() => {});
      } });
    } catch (error) {
      throw new Error(String(error.message).replace(/^Another watch \(/, 'Another test-bitcoin service (').replace(/^This process already watches /, 'This process already uses '));
    }
  }
  try {
    service = await createTestBitcoinService({
      rpc, runner, archive: config.archive_directory ? createArchive(config.archive_directory) : null, blockSeconds: config.block_seconds,
      maxPaymentSats: config.max_payment_sats, perCallerPerDaySats: config.per_caller_per_day_sats, totalPerDaySats: config.total_per_day_sats,
      paymentsPerCallerPerHour: config.payments_per_caller_per_hour, totalPaymentsPerDay: config.total_payments_per_day, addressesPerCallerPerDay: config.addresses_per_caller_per_day, totalAddressesPerDay: config.total_addresses_per_day,
      host: config.host, port: config.port, hosts: config.hosts, origins: config.origins, basePath: config.base_path, rateLimit: { perSecond: config.rate_limit.per_second, burst: config.rate_limit.burst }, trustedProxies: config.trusted_proxies, servePage: config.serve_page, log,
      ...(inject.now ? { now: inject.now } : {}), ...(inject.autoMine === false ? { autoMine: false } : {}),
    });
  } catch (error) { await release(); throw error; }
  // Numbers, names and origins only: never the cookie, and no key of the wallet.
  log('info', 'test bitcoin started', {
    listening: `${service.url}${config.base_path}/`, health: `${service.url}${config.base_path}/v1/health`, network: 'regtest', bitcoin_rpc: new URL(url).origin, runs_the_node: own, wallet: config.wallet,
    height: service.started.height, balance_sats: service.started.balance_sats, block_seconds: config.block_seconds, archive: config.archive_directory ? 'on' : 'off', blocks_from_archive: service.started.archived, blocks_handed_to_node: service.started.restored, wallet_was: service.started.wallet,
    max_payment_sats: config.max_payment_sats.toString(), per_caller_per_day_sats: config.per_caller_per_day_sats.toString(), total_per_day_sats: config.total_per_day_sats.toString(), trusted_proxies: config.trusted_proxies.length,
  });
  if (!config.archive_directory) log('warn', 'no archive_directory: a lost machine, or a Bitcoin node that is killed before it wrote its newest blocks to disk, means a chain that begins again or steps back, which whoever follows this chain sees as a reorganisation');
  let closing;
  return { url: service.url, service, close: () => closing ??= (async () => { await service.close(); await release(); })() };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/test-bitcoin/start.mjs CONFIG_JSON');
    const running = await start(await readConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
