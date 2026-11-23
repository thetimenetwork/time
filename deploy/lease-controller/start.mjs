#!/usr/bin/env node
// The signer-lease controller: issues the short leases without which the kit's guard
// (deploy/operator.mjs) runs no validator. It reads one JSON config file and one key file,
// keeps its state in numbered files, and answers the host agents (deploy/lease-agent.mjs).
// It holds the lease authority key and no other: no consensus key, no account key.
// The decisions are in core.mjs; docs/design/signer-lease-controller.md is the specification and
// README.md the operator's guide. What a lease does NOT do is section 10 of the design: read it.
import { createServer } from 'node:http';
import { mkdir, readFile } from 'node:fs/promises';
import { sign } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { signingBytes } from '../lib.mjs';
import { GUARD_MAX_LEASE_MS, KEY_PURPOSES, MAX_BODY_BYTES, NAME, readKeyFile } from '../lease-protocol.mjs';
import { ClockRefused, applyStart, checkBinding, checkClock, decide, emptyState, stamped, timing, validateState } from './core.mjs';
import { Conflict, KEPT_FILES, LOCK_LOST_EXIT, claim, fileStore } from './store.mjs';

const KEYS = ['data_directory', 'host', 'port', 'authority_key_file', 'fence_domain', 'network', 'hosts', 'lease_seconds', 'clock_skew_seconds', 'stop_seconds'];
const HOST_KEYS = ['id', 'public_key_hex', 'signer_identity', 'signer_fencing'];
const HEX32 = /^[a-f0-9]{64}$/, TEXT = /^[\x21-\x7e][\x20-\x7e]{0,127}$/;
export const MAX_WAITING = 64;

/// Checks a config and fills in the defaults. Throws on anything unknown or malformed.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((key) => !KEYS.includes(key));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  if (typeof config.authority_key_file !== 'string' || !path.isAbsolute(config.authority_key_file)) throw new Error('authority_key_file is the absolute path of the lease authority key (made with: ctl.mjs keygen authority FILE ID)');
  if (typeof config.fence_domain !== 'string' || !NAME.test(config.fence_domain)) throw new Error('fence_domain names this controller\'s fence tokens: 1 to 64 characters, lower-case letters, digits, dot, dash, underscore');
  const network = config.network;
  if (!network || typeof network !== 'object' || Array.isArray(network) || Object.keys(network).sort().join(',') !== 'chain_id,engine,genesis_sha256') throw new Error('network is {chain_id, genesis_sha256, engine}');
  if (typeof network.chain_id !== 'string' || !TEXT.test(network.chain_id)) throw new Error('network.chain_id is the chain id of the network, as in the operator settings');
  if (typeof network.genesis_sha256 !== 'string' || !HEX32.test(network.genesis_sha256)) throw new Error('network.genesis_sha256 is 64 lower-case hexadecimal characters');
  if (!['v4', 'v5'].includes(network.engine)) throw new Error('network.engine is "v4" or "v5": the engine every validator of this network runs. It cannot be read from the genesis; state it');
  if (!Array.isArray(config.hosts)) throw new Error('hosts is a list (it may be empty)');
  const hosts = config.hosts.map((host, index) => {
    if (!host || typeof host !== 'object' || Array.isArray(host) || Object.keys(host).some((key) => !HOST_KEYS.includes(key))) throw new Error(`host ${index}: only ${HOST_KEYS.join(', ')}`);
    if (typeof host.id !== 'string' || !NAME.test(host.id)) throw new Error(`host ${index}: id is 1 to 64 characters, lower-case letters, digits, dot, dash, underscore`);
    if (typeof host.public_key_hex !== 'string' || !HEX32.test(host.public_key_hex)) throw new Error(`host ${index}: public_key_hex is the public key the host's agent printed at keygen`);
    if (typeof host.signer_identity !== 'string' || !TEXT.test(host.signer_identity)) throw new Error(`host ${index}: signer_identity is the signer_identity of that host's operator settings`);
    if (!['EVERY_SIGNATURE', 'NOT_DECLARED'].includes(host.signer_fencing)) throw new Error(`host ${index}: signer_fencing is "EVERY_SIGNATURE" or "NOT_DECLARED". "EVERY_SIGNATURE" is your declaration about that host's signer: read "The declaration about the signer" in the README before you write it`);
    return { id: host.id, public_key_hex: host.public_key_hex, signer_identity: host.signer_identity, signer_fencing: host.signer_fencing };
  });
  for (const field of ['id', 'public_key_hex', 'signer_identity']) if (new Set(hosts.map((host) => host[field])).size !== hosts.length) throw new Error(`Two hosts have the same ${field}. Each host has its own id, its own key and its own signer`);
  const integer = (name, fallback, min, max) => {
    const value = config[name] ?? fallback;
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
    return value;
  };
  const checked = {
    data_directory: path.resolve(config.data_directory), authority_key_file: path.resolve(config.authority_key_file), fence_domain: config.fence_domain,
    network: { chain_id: network.chain_id, genesis_sha256: network.genesis_sha256, engine: network.engine }, hosts,
    host: config.host ?? '127.0.0.1', port: integer('port', 8960, 1, 65535),
    lease_seconds: integer('lease_seconds', 240, 60, 280), clock_skew_seconds: integer('clock_skew_seconds', 10, 1, 20), stop_seconds: integer('stop_seconds', 40, 30, 600),
  };
  if (typeof checked.host !== 'string' || !checked.host) throw new Error('host is the address to listen on');
  // The argument for the start rule (design, 5.3) needs stop_seconds above clock_skew_seconds.
  // The two ranges above give that; this line keeps it true if a range is ever widened.
  if (checked.stop_seconds <= checked.clock_skew_seconds) throw new Error('stop_seconds must be more than clock_skew_seconds');
  const t = timing(checked);
  if (t.leaseMs + t.backdateMs > GUARD_MAX_LEASE_MS) throw new Error('lease_seconds plus twice clock_skew_seconds must not pass 300: the guard refuses a lease whose dates are further apart');
  if (4 * t.spacingMs > t.leaseMs) throw new Error('lease_seconds must be at least four times (3 x clock_skew_seconds + 1), so that a host can renew several times within one lease');
  return checked;
}

/// Lines of JSON on stdout. Nothing secret is ever passed in: the state and the requests hold none.
export function jsonLog(write = (line) => process.stdout.write(`${line}\n`)) {
  return (level, message, fields = {}) => write(JSON.stringify({ at: new Date().toISOString(), level, message, ...fields }));
}

/// The one function that uses the authority key. A variant that signs elsewhere replaces only this.
export function signer(authority) {
  return (payload) => ({ issuer: authority.id, payload, signature: sign(null, signingBytes(payload), authority.privateKey).toString('base64') });
}

/// Something happened that the running service cannot follow safely. It stops, and from then on
/// answers nothing. A start afterwards is always safe: the start rule applies.
export class Fatal extends Error {}

/// The controller without its HTTP face: a state, a store and one request at a time.
/// `now` is the wall clock every date is taken from. `monotonic` is a clock that only counts
/// elapsed time and is never set (milliseconds); the two are compared to notice a wall clock that
/// was changed under the running service (design, 5.5). A test that passes only `now` moves one
/// clock that is both.
export function createController({ config, store, sign: signLease, now = Date.now, monotonic = now === Date.now ? () => performance.now() : now, log = () => {} }) {
  let current = null, queue = Promise.resolve(), waiting = 0, dead = null, opened = null;
  const { skewMs } = timing(config);
  const die = (error) => { dead ??= error; throw dead; };
  /// Old state files go, KEPT_FILES behind the one this service holds. The command line never
  /// removes any: it cannot know how far a running service has followed.
  const tidy = async () => { try { await store.prune?.(current.seq - KEPT_FILES); } catch { /* a file that stays does no harm */ } };
  /// The wall clock must have moved as much as time passed since the start, within one skew.
  /// If not, it was set while the service ran (or the machine was suspended): every wait was
  /// counted on the old clock, and only a new start counts them again.
  const checkWallClock = () => {
    if (dead) throw dead;
    const drift = (now() - opened.wall) - (monotonic() - opened.monotonic);
    if (Math.abs(drift) > skewMs) die(new Fatal(`The machine's clock was changed by ${Math.round(drift / 1000)} s while the controller ran (it was set, or the machine was suspended). Every wait was counted on the clock as it was. The controller stops and issues nothing. Check the clock against a time source you trust, then start the controller again: the start rule then counts every wait on the corrected clock.`));
  };
  /// The newest state file must be the one this service holds, or descend from it file by file.
  /// Anything else means files were put into the directory under the running service: it must
  /// not follow them, because no start rule was applied to them.
  const follow = async () => {
    const replaced = (what) => die(new Fatal(`The controller state files were replaced while the controller ran (${what}). A running controller follows only its own line of state files: each file names the one it was made from. The controller stops and issues nothing. Start it again: the start rule then applies to the files that are there.`));
    const newest = await store.read();
    if (!newest || newest.seq < current.seq) replaced('the newest file is older than the state the controller holds');
    if (newest.seq === current.seq) { if (newest.sha256 !== current.sha256) replaced('the newest file is not the one the controller wrote'); return; }
    // Newer files: the command line wrote them. Each must name the one before it.
    let previous = current.sha256, last = null;
    for (let seq = current.seq + 1; seq <= newest.seq; seq++) {
      last = seq === newest.seq ? newest : await store.readAt(seq);
      if (!last) replaced(`file number ${seq} is missing`);
      if (last.parent !== previous) replaced(`file number ${seq} was not made from the file before it`);
      previous = last.sha256;
    }
    let state;
    try { state = checkClock(checkBinding(validateState(last.state), config), config, now()); } catch (error) { if (error instanceof ClockRefused) die(new Fatal(error.message)); throw error; }
    current = { seq: last.seq, sha256: last.sha256, state };
    await tidy();
  };
  async function handle(envelope) {
    checkWallClock();
    await follow();
    for (let attempt = 0; attempt < 4; attempt++) {
      const at = now(), { reply, next, event } = decide(current.state, config, envelope, at, signLease);
      if (next !== null) {
        // The state is written and synced BEFORE the answer is returned. A lease that is in the
        // state and never arrives is harmless; a lease that arrived and is not in the state is not.
        const state = stamped(next, at);
        let sha256;
        try { sha256 = await store.write(current.seq + 1, state, current.sha256); } catch (error) {
          if (!(error instanceof Conflict)) throw error;
          await follow(); continue; // the command line wrote first: decide again on its state
        }
        current = { seq: current.seq + 1, sha256, state };
        await tidy();
      }
      if (event.code === 'FROZEN_NOW') log('error', 'a key was frozen: two machines act as one host, or a host lost its lease file or agent state; no lease for the key until an operator runs unfreeze', event);
      else log(event.code === 'GRANTED' || event.code === 'REPEATED' ? 'info' : 'warn', event.code === 'GRANTED' ? 'lease issued' : event.code === 'REPEATED' ? 'stored lease sent again' : 'request refused', event);
      return reply;
    }
    return { status: 'refused', code: 'BUSY', message: 'The controller state changed several times while this request was decided. Ask again.', retry_after_ms: 2000 };
  }
  return {
    /// Loads the state, or starts an empty one, applies the start rule and writes the result.
    /// Nothing may be answered before this has returned. Refuses to start on a state that holds
    /// a time later than the clock.
    async open() {
      for (let attempt = 0; attempt < 4; attempt++) {
        // The two clocks are read together, before the write: the time the write takes passes on both.
        const loaded = await store.read(), at = now(), elapsed = monotonic();
        const base = loaded ? checkClock(checkBinding(validateState(loaded.state), config), config, at) : emptyState(config, at);
        const started = applyStart(base, config, at), seq = (loaded?.seq ?? 0) + 1;
        let sha256;
        try { sha256 = await store.write(seq, started, loaded?.sha256 ?? null); } catch (error) { if (error instanceof Conflict) continue; throw error; }
        current = { seq, sha256, state: started };
        opened = { wall: at, monotonic: elapsed };
        await tidy();
        return { seq, fresh: !loaded, keys: Object.keys(started.keys).length, waiting: Object.values(started.keys).filter((key) => key.holder && at < key.not_before_ms).length };
      }
      throw new Error('The controller state kept changing during the start. Is a second controller or a command running on this directory?');
    },
    /// Decides one request; requests are taken one after the other. After a Fatal error every
    /// request is rejected with that same error: a stopped controller answers nothing.
    submit(envelope) {
      if (current === null) return Promise.reject(new Error('The controller is not open'));
      if (dead) return Promise.reject(dead);
      if (waiting >= MAX_WAITING) return Promise.resolve({ status: 'refused', code: 'BUSY', message: 'Too many requests are waiting. Ask again.', retry_after_ms: 2000 });
      waiting++;
      const result = queue.then(() => handle(envelope)).finally(() => { waiting--; });
      queue = result.catch(() => {});
      return result;
    },
    /// For the service's timer: throws the Fatal error if the wall clock was changed.
    checkWallClock,
    current: () => current,
  };
}

async function body(request) {
  const chunks = []; let length = 0;
  for await (const chunk of request) { length += chunk.length; if (length > MAX_BODY_BYTES) return null; chunks.push(chunk); }
  return Buffer.concat(chunks).toString('utf8');
}

/// Starts the service. `inject` replaces parts for tests: store, authority, now, log, onFatal.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log ?? jsonLog(), t = timing(config);
  const authority = inject.authority ?? await readKeyFile(config.authority_key_file, KEY_PURPOSES.authority);
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let server = null, closing = null, clockTimer = null, release = async () => {};
  const closeServer = () => new Promise((resolve) => { if (!server) return resolve(); server.close(() => resolve()); server.closeAllConnections?.(); });
  const fatal = inject.onFatal ?? ((error) => { log('error', 'the controller stops: ' + error.message); closeServer().then(release).finally(() => process.exit(1)); });
  release = await claim(config.data_directory, {
    onLost: async (why) => {
      log('error', `this controller lost the lock of its data directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}`);
      await closeServer();
      if (inject.exitOnLost !== false) process.exit(LOCK_LOST_EXIT);
    },
  });
  try {
    const controller = createController({ config, store: inject.store ?? fileStore(config.data_directory), sign: signer(authority), now: inject.now, monotonic: inject.monotonic, log });
    const opened = await controller.open();
    // The wall clock is compared with elapsed time every second, not only when a request comes.
    clockTimer = setInterval(() => { try { controller.checkWallClock(); } catch (error) { clearInterval(clockTimer); fatal(error); } }, 1000);
    clockTimer.unref?.();
    server = createServer(async (request, response) => {
      const send = (status, value) => { const text = JSON.stringify(value); response.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store' }); response.end(text); };
      try {
        if (request.method === 'GET' && request.url === '/health') return send(200, { status: 'ok' });
        if (request.method !== 'POST' || request.url !== '/v1/lease') return send(404, { status: 'refused', code: 'BAD_REQUEST', message: 'POST /v1/lease is the only request' });
        const text = await body(request);
        if (text === null) return send(413, { status: 'refused', code: 'BAD_REQUEST', message: 'A request is at most ' + MAX_BODY_BYTES + ' bytes' });
        let envelope;
        try { envelope = JSON.parse(text); } catch { return send(400, { status: 'refused', code: 'BAD_REQUEST', message: 'The request is not JSON' }); }
        const reply = await controller.submit(envelope);
        send(reply.status === 'granted' ? 200 : reply.code === 'BAD_REQUEST' ? 400 : reply.code === 'BUSY' ? 503 : 409, reply);
      } catch (error) {
        // Nothing was sent, so no lease left. The reason goes to the log, not to the network.
        log('error', 'request failed: ' + error.message);
        try { send(503, { status: 'refused', code: 'BUSY', message: 'The controller could not decide or save this request. Nothing was issued. Ask again.', retry_after_ms: 5000 }); } catch { /* the connection is gone */ }
        if (error instanceof Fatal) fatal(error);
      }
    });
    server.requestTimeout = 10_000; server.headersTimeout = 5_000; server.keepAliveTimeout = 2_000;
    const address = await new Promise((resolve, reject) => { server.once('error', reject); server.listen(inject.port ?? config.port, config.host, () => resolve(server.address())); });
    const url = `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`;
    log('info', 'signer-lease controller started', {
      listening: url, chain_id: config.network.chain_id, genesis_sha256: config.network.genesis_sha256, engine: config.network.engine, fence_domain: config.fence_domain,
      authority: authority.id, authority_public_key_hex: authority.publicKeyHex, state_number: opened.seq, state_was_empty: opened.fresh, keys: opened.keys, keys_waiting: opened.waiting,
      lease_seconds: config.lease_seconds, clock_skew_seconds: config.clock_skew_seconds, stop_seconds: config.stop_seconds, margin_seconds: t.marginMs / 1000, start_wait_seconds: t.startWaitMs / 1000,
      hosts: config.hosts.map((host) => ({ id: host.id, signer_fencing: host.signer_fencing })),
    });
    const declared = config.hosts.filter((host) => host.signer_fencing === 'EVERY_SIGNATURE').map((host) => host.id);
    if (declared.length) log('warn', 'leases for these hosts say enforcement EVERY_SIGNATURE on the operator\'s declaration alone; this controller checks no signer', { hosts: declared });
    return { url, controller, server, close: () => closing ??= (async () => { clearInterval(clockTimer); await closeServer(); await release(); })() };
  } catch (error) {
    clearInterval(clockTimer); await closeServer(); await release();
    throw error;
  }
}

/// Reads and parses a config file. A parse error is reported by position only.
export async function readConfig(file) {
  const text = await readFile(file, 'utf8');
  try { return JSON.parse(text); } catch (error) {
    const at = /position (\d+)/.exec(error.message)?.[1];
    throw new Error(`The config file is not valid JSON${at ? ` (near character ${at})` : ''}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    if (process.argv.length !== 3) throw new Error('Usage: node deploy/lease-controller/start.mjs CONFIG_JSON');
    const running = await start(await readConfig(process.argv[2]));
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
