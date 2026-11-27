#!/usr/bin/env node
// The prover of Bitcoin payments for a Time network with the market (client-v4/market-prover.mjs).
// Reads one JSON config file, finds the payments to the addresses of open fills on the operator's Bitcoin nodes, and
// sends the proofs (kind 54) from an account of its own, so that a buyer gets the seconds without doing anything.
// It holds one key: a spend key of that account, which holds only what the proofs' fees need. It holds no bitcoin
// key and never asks for one.
import { mkdir, open, readFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../../client-v4/time-sdk.js';
import { createHealthServer, loadSigningKey } from '../../client-v4/market-service.mjs';
import { createProver } from '../../client-v4/market-prover.mjs';
import { jsonLog } from '../watch/start.mjs';
// How the chain and the Bitcoin nodes are reached, the lock and the config reader are the relay's, unchanged.
import { bitcoinNodesOf, claimFor, readServiceConfig, timeEndpointOf, validateEndpoint, validateListening, validateNodes, wholeOf } from '../market-relay/start.mjs';

const KEYS = ['rpc_url', 'gateway', 'trust', 'bitcoin_nodes', 'data_directory', 'account', 'key_env', 'key_file', 'max_balance_micros', 'min_balance_micros', 'max_fee_per_proof_micros', 'max_fees_per_day_micros',
  'expire', 'allow_unsecured_account', 'poll_seconds', 'max_blocks_per_round', 'bitcoin_timeout_seconds', 'time_timeout_seconds', 'host', 'port', 'hosts'];
const canonicalId = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 18446744073709551615n;

/// Checks a config and fills in the defaults. Everything about money has no default: the ceiling of the account
/// and the two budgets must be written. Throws on anything unknown or malformed, and never puts a value of the
/// config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  if (!canonicalId(config.account)) throw new Error('account is the number of the prover\'s own account, in decimal and in quotes');
  // The key is named by the operator: a variable of the environment, or a file. There is no default place.
  if ((config.key_env === undefined) === (config.key_file === undefined)) throw new Error('Give exactly one of key_env (the name of an environment variable that holds the key) and key_file (the absolute path of a file that holds it)');
  if (config.key_env !== undefined && (typeof config.key_env !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(config.key_env))) throw new Error('key_env is the name of an environment variable');
  if (config.key_file !== undefined && (typeof config.key_file !== 'string' || !path.isAbsolute(config.key_file))) throw new Error('key_file is the absolute path of the file that holds the spend key');
  const amount = (name, required = true) => {
    const value = config[name];
    if (value === undefined && !required) return 0n;
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,15})$/.test(value)) throw new Error(`${name} is a whole number of microseconds as a decimal string`);
    return BigInt(value);
  };
  const ceiling = amount('max_balance_micros'), perProof = amount('max_fee_per_proof_micros'), perDay = amount('max_fees_per_day_micros'), low = amount('min_balance_micros', false);
  if (perProof < 1n || perDay < perProof) throw new Error('max_fee_per_proof_micros is at least 1, and max_fees_per_day_micros at least one proof');
  if (ceiling < perProof) throw new Error('max_balance_micros is below one proof: the account could never pay for one');
  if (low > ceiling) throw new Error('min_balance_micros is above max_balance_micros');
  for (const name of ['expire', 'allow_unsecured_account']) if (config[name] !== undefined && typeof config[name] !== 'boolean') throw new Error(`${name} is true or false`);
  return {
    ...validateEndpoint(config), bitcoin_nodes: validateNodes(config), data_directory: path.resolve(config.data_directory), account: config.account,
    ...(config.key_env !== undefined ? { key_env: config.key_env } : { key_file: path.resolve(config.key_file) }),
    max_balance_micros: ceiling, min_balance_micros: low, max_fee_per_proof_micros: perProof, max_fees_per_day_micros: perDay, expire: config.expire ?? false, allow_unsecured_account: config.allow_unsecured_account ?? false,
    poll_seconds: wholeOf(config, 'poll_seconds', 10, 1, 600), max_blocks_per_round: wholeOf(config, 'max_blocks_per_round', 64, 1, 1024),
    bitcoin_timeout_seconds: wholeOf(config, 'bitcoin_timeout_seconds', 15, 1, 120), time_timeout_seconds: wholeOf(config, 'time_timeout_seconds', 30, 2, 300),
    ...validateListening(config, 8951),
  };
}

/// What the prover remembers between starts (which fills it has looked at, what it spent today), in one file that
/// is written whole and put in place. A file that cannot be read is an error: the prover then starts afresh and
/// says so.
export function fileStore(file) {
  return {
    async load() { try { return JSON.parse(await readFile(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } },
    async save(value) {
      const temporary = `${file}.${process.pid}.tmp`, handle = await open(temporary, 'w', 0o600);
      try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); } finally { await handle.close(); }
      await rename(temporary, file);
    },
  };
}

/// The prover of a config, with its lock held. `settings` adds to the prover's own (the one-shot tool's `only`).
/// `inject` replaces parts for tests: endpoint ({ readState, submit }), bitcoinFetcher, key, log, now, sleep.
/// Returns `{ prover, release }`. The key and the account are checked with a proof before this returns: a key that
/// is not the account's, an account without the security rules, or one that holds more than the ceiling stops here.
export async function prepare(rawConfig, inject = {}, settings = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  const key = inject.key || await loadSigningKey({ env: config.key_env, file: config.key_file });
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let prover;
  const release = await claimFor(config.data_directory, 'prover', log, async () => { await prover?.stop(); });
  try {
    const endpoint = inject.endpoint || timeEndpointOf(config, inject);
    prover = createProver({
      nodes: bitcoinNodesOf(config, inject.bitcoinFetcher), readState: endpoint.readState, submit: endpoint.submit, networkId: config.trust.network_id, account: config.account, key,
      store: inject.store || fileStore(path.join(config.data_directory, 'prover.json')), log, ...(inject.now ? { now: inject.now } : {}), ...(inject.sleep ? { sleep: inject.sleep } : {}),
      settings: {
        maxBalanceMicros: config.max_balance_micros, minBalanceMicros: config.min_balance_micros, maxFeePerProofMicros: config.max_fee_per_proof_micros, maxFeesPerDayMicros: config.max_fees_per_day_micros,
        expire: config.expire, allowUnsecured: config.allow_unsecured_account, maxBlocksPerRound: config.max_blocks_per_round, pollMs: config.poll_seconds * 1000, ...settings,
      },
    });
    const { balance } = await prover.check();
    return { config, prover, release, endpoint, balance, log };
  } catch (error) { await release(); throw error; }
}

/// Starts the prover.
export async function start(rawConfig, inject = {}) {
  const { config, prover, release, endpoint, balance, log } = await prepare(rawConfig, inject);
  let server;
  try {
    server = createHealthServer({ status: () => prover.health(), host: config.host, port: config.port, hosts: config.hosts });
    const listening = await server.listen();
    // Names, origins and numbers only: never the key, where it came from, a password or a cookie.
    log('info', 'market prover started', {
      health: `${listening}/health`, time_endpoint: endpoint.origin ?? null, reached_through: endpoint.kind ?? null, network_id: config.trust.network_id, chain_id: config.trust.chain_id, account: config.account,
      bitcoin_nodes: config.bitcoin_nodes.map((node) => node.name), balance_micros: balance.toString(), max_balance_micros: config.max_balance_micros.toString(),
      max_fee_per_proof_micros: config.max_fee_per_proof_micros.toString(), max_fees_per_day_micros: config.max_fees_per_day_micros.toString(), expire: config.expire, poll_seconds: config.poll_seconds,
    });
    if (config.allow_unsecured_account) log('warn', 'allow_unsecured_account is on: no daily limit of the chain bounds what this key can move. The ceiling max_balance_micros is the only bound');
    if (inject.autoStart !== false) prover.start();
    let closing;
    return { url: listening, prover, close: () => closing ??= (async () => { await prover.stop(); await server.close(); await release(); })() };
  } catch (error) {
    await prover.stop(); await server?.close().catch(() => {}); await release();
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    // The key never comes on the command line: what is typed there is shown to every user of the machine.
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/market-prover/start.mjs CONFIG_JSON');
    const running = await start(await readServiceConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
