#!/usr/bin/env node
// The faucet process of a Time TEST network (client-v4/faucet.mjs): gives a fixed amount of test
// time to developers who ask, and can sponsor the registration of their first account.
// Reads one JSON config file and one key file. NEVER run it on a network whose time has value:
// it refuses to start unless the config states "test_network": true and names the network id it
// then finds in the trust manifest and in a proven state.
import { mkdir, stat } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as installedVerifier from '../../client-v4/proof-verifier.mjs';
import { createFaucetService, createTxLookup, readSpendKey, isTestChain, TEST_CHAINS } from '../../client-v4/faucet.mjs';
import { createRpc } from '../../client-v4/indexer.mjs';
// The lock, the log format and the config reader are the watch's, unchanged: one instance per
// data directory, JSON lines, and a config error that never quotes the file.
import { claim, jsonLog, readConfig, LOCK_LOST_EXIT } from '../watch/start.mjs';

const KEYS = ['test_network', 'network_id', 'rpc_url', 'trust', 'data_directory', 'account', 'key_file', 'grant_micros', 'limits', 'min_balance_micros', 'max_recipient_balance_micros',
  'max_chain_daily_limit_micros', 'sponsor_registrations', 'cancel_waiting', 'freeze_on_misuse', 'host', 'port', 'hosts', 'cors_origins', 'rate_limit', 'trusted_proxies', 'rpc_timeout_seconds', 'serve_page'];
const LIMIT_KEYS = ['per_account_per_day', 'per_address_per_day', 'total_per_day_micros', 'registrations_per_address_per_day', 'refused_requests_per_address_per_hour'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const canonicalId = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 18446744073709551615n;

/// Checks a config and fills in the defaults of the listening side. Everything about money has no
/// default: the amount, every limit and the floor must be written. Throws on anything unknown or
/// malformed, and never puts a value of the config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  if (config.test_network !== true) throw new Error('The faucet runs on test networks only. Its config must state "test_network": true, written by you for this network; never run it on a network whose time has value');
  const trust = config.trust;
  if (!trust || typeof trust !== 'object' || String(trust.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust.network_id ?? '') || typeof trust.chain_id !== 'string' || !trust.chain_id) throw new Error('trust is the application-4 trust manifest the SDK takes (app_version, network_id, chain_id, ...)');
  if (typeof config.network_id !== 'string' || !/^[0-9a-f]{64}$/.test(config.network_id)) throw new Error('network_id is the id of the test network this faucet serves: 64 lower-case hexadecimal characters');
  if (config.network_id !== trust.network_id) throw new Error('network_id is not the network of the trust manifest');
  // Not a list of names to avoid, which any new name passes: the chain ids of test networks, which the faucet itself knows.
  if (!isTestChain(trust.chain_id)) throw new Error(`The chain id of the trust manifest is not one of a test network (${TEST_CHAINS.map((prefix) => `${prefix}…`).join(', ')}): the faucet does not start`);
  let rpc;
  try { rpc = new URL(config.rpc_url); } catch { throw new Error('rpc_url is the address of a CometBFT RPC'); }
  if (typeof config.rpc_url !== 'string' || rpc.username || rpc.password || !(rpc.protocol === 'https:' || (rpc.protocol === 'http:' && LOOPBACK.has(rpc.hostname)))) throw new Error('rpc_url must be https:// (http:// only on this machine), without user name or password. A node on another machine is reached through a tunnel to this machine or a TLS proxy: see "A node on another machine" in deploy/api/README.md');
  if (`${rpc.origin}/` !== rpc.href) throw new Error('rpc_url is an origin only: no path, query or fragment');
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  if (!canonicalId(config.account)) throw new Error('account is the number of the faucet account, in decimal and in quotes');
  if (typeof config.key_file !== 'string' || !path.isAbsolute(config.key_file)) throw new Error('key_file is the absolute path of the file that holds the spend key');
  const amount = (value, name, min = 1n) => {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(value) || BigInt(value) < min || BigInt(value) > 1_000_000_000_000_000n) throw new Error(`${name} is a whole number of microseconds as a decimal string, from ${min}`);
    return BigInt(value);
  };
  const integer = (value, name, fallback, min, max) => {
    const number = value ?? fallback;
    if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
    return number;
  };
  const limits = config.limits;
  if (!limits || typeof limits !== 'object' || Array.isArray(limits) || Object.keys(limits).some((k) => !LIMIT_KEYS.includes(k))) throw new Error(`limits takes ${LIMIT_KEYS.join(', ')}`);
  if (typeof config.sponsor_registrations !== 'boolean') throw new Error('sponsor_registrations is true or false');
  if (config.cancel_waiting !== undefined && typeof config.cancel_waiting !== 'boolean') throw new Error('cancel_waiting is true or false');
  if (config.freeze_on_misuse !== undefined && typeof config.freeze_on_misuse !== 'boolean') throw new Error('freeze_on_misuse is true or false');
  const grant = amount(config.grant_micros, 'grant_micros'), total = amount(limits.total_per_day_micros, 'limits.total_per_day_micros');
  if (total < grant) throw new Error('limits.total_per_day_micros is below one grant');
  const host = config.host ?? '127.0.0.1';
  if (typeof host !== 'string' || !host) throw new Error('host is the address to listen on');
  const hosts = config.hosts ?? [];
  if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string' && /^(?:\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?$/.test(h))) throw new Error('hosts lists extra Host header values in lower case, each "name" or "name:port"');
  const origins = config.cors_origins ?? [];
  const isOrigin = (value) => { try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && url.origin === value; } catch { return false; } };
  if (!Array.isArray(origins) || !origins.every((o) => typeof o === 'string' && isOrigin(o))) throw new Error('cors_origins lists exact origins such as "https://docs.example"; there is no wildcard');
  const rate = config.rate_limit ?? {};
  if (!rate || typeof rate !== 'object' || Array.isArray(rate) || Object.keys(rate).some((k) => !['per_second', 'burst'].includes(k))) throw new Error('rate_limit takes per_second and burst');
  const proxies = config.trusted_proxies ?? [];
  if (!Array.isArray(proxies) || !proxies.every((p) => typeof p === 'string' && net.isIP(p) !== 0)) throw new Error('trusted_proxies lists the IP addresses of your own reverse proxies');
  if (config.serve_page !== undefined && typeof config.serve_page !== 'boolean') throw new Error('serve_page is true or false');
  // The page is served under the names in `hosts`, and its button calls the faucet from the
  // page's own origin. The process cannot know the scheme it is reached under behind a proxy, so
  // that origin must be listed; without it the page would be served and its button refused.
  const publicName = (value) => value.toLowerCase().replace(/:(?:80|443)$/, '');
  if ((config.serve_page ?? true) && hosts.length > 0 && !origins.some((origin) => hosts.some((name) => publicName(new URL(origin).host) === publicName(name)))) {
    throw new Error('serve_page is on and hosts names where the faucet is reached, but cors_origins lists no origin under one of those names: the page would be served and its own button refused. Add the origin of the page to cors_origins, such as "https://" followed by the name in hosts, or set serve_page to false');
  }
  const perSecond = integer(rate.per_second, 'rate_limit.per_second', 5, 1, 1000);
  return {
    test_network: true, network_id: config.network_id, rpc_url: rpc.href, trust, data_directory: path.resolve(config.data_directory), account: config.account, key_file: path.resolve(config.key_file),
    grant_micros: grant,
    limits: {
      per_account_per_day: integer(limits.per_account_per_day, 'limits.per_account_per_day', undefined, 1, 1000),
      per_address_per_day: integer(limits.per_address_per_day, 'limits.per_address_per_day', undefined, 1, 100000),
      total_per_day_micros: total,
      registrations_per_address_per_day: config.sponsor_registrations ? integer(limits.registrations_per_address_per_day, 'limits.registrations_per_address_per_day', undefined, 1, 1000) : 1,
      refused_requests_per_address_per_hour: integer(limits.refused_requests_per_address_per_hour, 'limits.refused_requests_per_address_per_hour', 50, 1, 100000),
    },
    min_balance_micros: amount(config.min_balance_micros, 'min_balance_micros', 0n),
    max_recipient_balance_micros: amount(config.max_recipient_balance_micros, 'max_recipient_balance_micros', 0n),
    max_chain_daily_limit_micros: amount(config.max_chain_daily_limit_micros, 'max_chain_daily_limit_micros'),
    sponsor_registrations: config.sponsor_registrations, cancel_waiting: config.cancel_waiting ?? true, freeze_on_misuse: config.freeze_on_misuse ?? true,
    host, port: integer(config.port, 'port', 8940, 1024, 65535), hosts: hosts.map((h) => h.toLowerCase()), cors_origins: [...origins],
    rate_limit: { per_second: perSecond, burst: integer(rate.burst, 'rate_limit.burst', Math.max(20, perSecond), perSecond, 10000) },
    trusted_proxies: [...proxies], rpc_timeout_seconds: integer(config.rpc_timeout_seconds, 'rpc_timeout_seconds', 10, 1, 120), serve_page: config.serve_page ?? true,
  };
}

/// Reads the key file after checking who else can read it. On Windows the file's permissions
/// are not in its mode, and the check is left to the operator.
async function loadKey(file) {
  let info;
  try { info = await stat(file); } catch { throw new Error('The key file could not be read'); }
  if (!info.isFile()) throw new Error('key_file is not a file');
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) throw new Error('The key file can be read by other users of this machine: chmod 600 it');
  return readSpendKey(file);
}

/// Starts the faucet. `inject` replaces parts for tests: rpc, lookup, readState, key, log, now and the timings.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  const key = inject.key || await loadKey(config.key_file);
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let service;
  let release;
  try {
    release = await claim(config.data_directory, {
      // Another instance took over while this one stalled: two faucets on one store would give out the same nonce.
      onLost: async (why) => {
        log('error', `this faucet lost the lock of its data directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}, so that only one instance signs`);
        await service?.close().catch(() => {});
      },
    });
  } catch (error) {
    throw new Error(String(error.message).replace(/^Another watch \(/, 'Another faucet instance (').replace(/^This process already watches /, 'This process already serves '));
  }
  try {
    service = await createFaucetService({
      trust: config.trust, networkId: config.network_id, testNetwork: config.test_network, verifier: installedVerifier,
      rpc: inject.rpc || createRpc(config.rpc_url, { timeoutMs: config.rpc_timeout_seconds * 1000 }),
      lookup: inject.lookup || createTxLookup(config.rpc_url, { timeoutMs: config.rpc_timeout_seconds * 1000 }),
      dataFile: path.join(config.data_directory, 'faucet.sqlite'), account: config.account, key,
      grantMicros: config.grant_micros, minBalanceMicros: config.min_balance_micros, maxRecipientBalanceMicros: config.max_recipient_balance_micros, maxChainDailyLimitMicros: config.max_chain_daily_limit_micros,
      limits: { perAccountPerDay: config.limits.per_account_per_day, perAddressPerDay: config.limits.per_address_per_day, totalPerDayMicros: config.limits.total_per_day_micros, registrationsPerAddressPerDay: config.limits.registrations_per_address_per_day },
      sponsorRegistrations: config.sponsor_registrations, cancelWaiting: config.cancel_waiting, freezeOnMisuse: config.freeze_on_misuse, refusedPerAddressPerHour: config.limits.refused_requests_per_address_per_hour, host: config.host, port: config.port, hosts: config.hosts, corsOrigins: config.cors_origins,
      rateLimit: { perSecond: config.rate_limit.per_second, burst: config.rate_limit.burst }, trustedProxies: config.trusted_proxies, servePage: config.serve_page, log,
      ...(inject.readState ? { readState: inject.readState } : {}), ...(inject.now ? { now: inject.now } : {}), ...(inject.timings || {}),
    });
    // Origins, numbers and counts only: never the key or its path.
    log('info', 'time faucet started on a test network', {
      listening: service.url, rpc: new URL(config.rpc_url).origin, network_id: config.network_id, chain_id: config.trust.chain_id, account: config.account,
      grant_micros: config.grant_micros.toString(), total_per_day_micros: config.limits.total_per_day_micros.toString(), sponsor_registrations: config.sponsor_registrations, trusted_proxies: config.trusted_proxies.length,
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
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/faucet/start.mjs CONFIG_JSON');
    const running = await start(await readConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
