#!/usr/bin/env node
// The lease agent of one validator host: asks the signer-lease controller for the lease the
// guard (deploy/operator.mjs) demands, checks the answer with that same guard, and puts it in
// place by renaming a finished file. It runs on the host, outside the containers, as a user that
// may write the operator directory. It holds the host key and no other key.
// docs/design/signer-lease-controller.md, section 8.3, is the specification;
// deploy/lease-controller/README.md is the operator's guide.
// It imports nothing outside deploy/, so a release context holds everything it needs.
import { open, readFile, readdir, rename, stat, unlink } from 'node:fs/promises';
import { randomUUID, verify } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exactU64, json, rawEd25519, releaseEngine, signingBytes, validateRelease } from './lib.mjs';
import { checkSettingsKeys, guard } from './operator.mjs';
import { KEY_PURPOSES, NAME, NONCE, buildRequest, generateKeyRecord, newNonce, readKeyFile, scopeOf, writeKeyFile } from './lease-protocol.mjs';

const KEYS = ['controller_url', 'allow_plain_http', 'host_id', 'host_key_file', 'settings_file', 'operator_directory', 'state_file', 'request_timeout_seconds'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
/// The settings name these files as the containers see them, under /operator.
const SETTINGS_FILES = ['release_manifest', 'genesis_file', 'trust_file', 'signer_lease_file'];
const MAX_REPLY_BYTES = 64 * 1024;
/// The lease file is read by the containers' user (UID 10001), which is not the agent's: it is
/// readable by everyone and writable by the agent alone. A lease is not a secret.
export const LEASE_FILE_MODE = 0o644;
export const RETRY_MS = 10_000;

/// Checks the agent's config and fills in the defaults.
export function validateAgentConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((key) => !KEYS.includes(key));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  let url;
  try { url = new URL(config.controller_url); } catch { throw new Error('controller_url is the address of the lease controller'); }
  if (typeof config.controller_url !== 'string' || url.username || url.password || !['http:', 'https:'].includes(url.protocol) || `${url.origin}/` !== url.href) throw new Error('controller_url is an origin such as "https://lease.example:8960": no path, user name or password');
  if (config.allow_plain_http !== undefined && typeof config.allow_plain_http !== 'boolean') throw new Error('allow_plain_http is true or false');
  if (url.protocol === 'http:' && !LOOPBACK.has(url.hostname) && config.allow_plain_http !== true) throw new Error('controller_url is plain http:// to another machine. That is sound only on a private link between this host and the controller: leases and requests are signed, but anyone on the path can read and drop them. If the link is private, state "allow_plain_http": true; otherwise use https://');
  if (typeof config.host_id !== 'string' || !NAME.test(config.host_id)) throw new Error('host_id is this host\'s id in the controller config');
  for (const name of ['host_key_file', 'settings_file']) if (typeof config[name] !== 'string' || !path.isAbsolute(config[name])) throw new Error(`${name} is an absolute path`);
  for (const name of ['operator_directory', 'state_file']) if (config[name] !== undefined && (typeof config[name] !== 'string' || !path.isAbsolute(config[name]))) throw new Error(`${name} is an absolute path`);
  const timeout = config.request_timeout_seconds ?? 10;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 60) throw new Error('request_timeout_seconds is a whole number from 1 to 60');
  return {
    controller_url: url.origin, host_id: config.host_id, host_key_file: path.resolve(config.host_key_file), settings_file: path.resolve(config.settings_file),
    operator_directory: config.operator_directory === undefined ? null : path.resolve(config.operator_directory),
    state_file: path.resolve(config.state_file ?? path.join(path.dirname(config.host_key_file), 'lease-agent-state.json')), request_timeout_seconds: timeout,
  };
}

/// The operator settings as this process sees the files: a path under /operator/ is read from
/// `operatorDirectory` when one is given. Everything else is unchanged.
export function hostView(settings, operatorDirectory) {
  checkSettingsKeys(settings);
  if (!operatorDirectory) return settings;
  const view = { ...settings };
  for (const name of SETTINGS_FILES) {
    const value = settings[name];
    if (typeof value !== 'string' || !value.startsWith('/operator/')) continue;
    const rest = value.slice('/operator/'.length);
    if (!rest || rest.split('/').some((part) => !part || part === '.' || part === '..')) throw new Error(`The settings name an unusual path for ${name}`);
    view[name] = path.join(operatorDirectory, ...rest.split('/'));
  }
  return view;
}

/// A refusal that came as the answer. It is NOT signed: anyone on the network path can have
/// written it. The message says so, because it ends up in front of an operator, and the agent
/// acts on none of it except to wait.
export class Refused extends Error {
  constructor(reply) { super(`The answer is a refusal (${reply.code}). It is unsigned: take it as the controller's unverified word, and do nothing it asks without checking on the controller itself. It says: ${reply.message}`); this.code = reply.code; this.retryAfterMs = reply.retry_after_ms; }
}

/// Writes `text` to `file` so that a reader sees the old file or the new one, never a part:
/// a synced temporary file in the same directory, renamed into place.
async function replaceFile(file, text, mode) {
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${randomUUID()}.tmp`);
  const handle = await open(temporary, 'wx', mode);
  try { await handle.writeFile(text); await handle.sync(); } finally { await handle.close(); }
  await moveIntoPlace(temporary, file);
}
async function moveIntoPlace(temporary, file) {
  try {
    // Windows refuses the replacement while another program has the file open: try again briefly.
    for (let attempt = 0; ; attempt++) {
      try { await rename(temporary, file); break; } catch (error) {
        if (attempt >= 20 || !['EPERM', 'EBUSY', 'EACCES'].includes(error.code)) throw error;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
  } catch (error) { await unlink(temporary).catch(() => {}); throw error; }
  if (process.platform !== 'win32') { const directory = await open(path.dirname(file), 'r'); try { await directory.sync(); } finally { await directory.close(); } }
}

/// The lease that is installed, as far as this agent may rely on it: its id always (the next
/// request names it), its token and expiry only when its signature is from a pinned lease authority.
async function installedLease(view) {
  let lease;
  // Only "the file is not there" means that this host holds no lease. A file that cannot be read
  // for a moment (permissions being reset, a disk error) must not be reported as "no lease":
  // to the controller a host that names no lease while it was given one looks like a second
  // machine, and the key would be frozen. The round is given up instead.
  const unreadable = (why) => new Error(`The installed lease file cannot be read as a lease (${why}). Nothing was asked this round. If the file is damaged for good, remove it by hand. If this host was given a lease before, the controller then takes it for a second machine: the key is frozen and needs "unfreeze". A host that was never given a lease is simply served.`);
  // A regular file that holds nothing was never a lease: a provisioning tool creates one to set
  // its owner. It is the same as no file, and can hide no second machine.
  try { const info = await stat(view.signer_lease_file); if (info.isFile() && info.size === 0) return null; } catch (error) { if (error.code === 'ENOENT') return null; /* anything else is judged below */ }
  try { lease = await json(view.signer_lease_file); } catch (error) { if (error.code === 'ENOENT') return null; throw unreadable(error.code ?? error.message); }
  const payload = lease?.payload, id = typeof payload?.lease_id === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(payload.lease_id) ? payload.lease_id : '';
  if (!id) throw unreadable('it holds no lease id');
  try {
    const authority = (await json(view.trust_file)).authorities.find((item) => item.id === lease.issuer && item.roles?.includes('signer_lease'));
    if (!verify(null, signingBytes(payload), rawEd25519(authority.public_key_hex), Buffer.from(lease.signature, 'base64'))) throw new Error('signature');
    const expires = Date.parse(payload.expires_utc);
    if (!Number.isFinite(expires)) throw new Error('dates');
    return { id, trusted: true, token: exactU64(payload.fence_token), domain: payload.fence_domain, expires };
  } catch { return { id, trusted: false }; }
}

/// The nonce of the request that names `previous` as the installed lease. It is written and
/// synced before the request is sent, and used again for every repeat of that request, so that
/// the controller can tell a repeat from a second machine that acts as this host.
async function nonceFor(file, previous) {
  try {
    const stored = JSON.parse(await readFile(file, 'utf8'));
    if (stored?.previous_lease_id === previous && typeof stored.nonce === 'string' && NONCE.test(stored.nonce)) return stored.nonce;
  } catch (error) { if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error; }
  const nonce = newNonce();
  await replaceFile(file, JSON.stringify({ previous_lease_id: previous, nonce }) + '\n', 0o600);
  return nonce;
}

/// One round: ask, check, install. Returns `{installed, lease_id, expires_ms, fence_token}`.
/// Throws Refused when the controller refuses, and an Error when the answer may not be installed.
/// `inject`: key (the host key), fetcher, now.
export async function round(config, inject = {}) {
  const now = inject.now ?? Date.now, fetcher = inject.fetcher ?? globalThis.fetch;
  const key = inject.key ?? await readKeyFile(config.host_key_file, KEY_PURPOSES.host);
  if (key.id !== config.host_id) throw new Error('The host key file was made for another host id than host_id of this config');
  const view = hostView(await json(config.settings_file), config.operator_directory);
  const manifest = validateRelease(await json(view.release_manifest));
  if (manifest.release_id !== view.release_id) throw new Error('The operator settings pin another release_id than the release manifest has');
  const current = await installedLease(view), previous = current?.id ?? '';
  const nonce = await nonceFor(config.state_file, previous);
  const request = buildRequest({ hostId: config.host_id, privateKey: key.privateKey, timeMs: now(), nonce, previousLeaseId: previous, scope: scopeOf(view, releaseEngine(manifest)) });

  let response, text;
  try {
    response = await fetcher(`${config.controller_url}/v1/lease`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), redirect: 'error', signal: AbortSignal.timeout(config.request_timeout_seconds * 1000) });
    const chunks = []; let length = 0;
    for await (const chunk of response.body ?? []) { length += chunk.length; if (length > MAX_REPLY_BYTES) break; chunks.push(chunk); }
    text = length > MAX_REPLY_BYTES ? null : Buffer.concat(chunks).toString('utf8');
  } catch (error) { throw new Error('The controller could not be reached: ' + (error.cause?.code ?? error.name ?? 'error')); }
  if (text === null) throw new Error('The controller\'s answer is too large');
  let reply;
  try { reply = JSON.parse(text); } catch { throw new Error('The controller\'s answer is not JSON (HTTP status ' + response.status + ')'); }
  if (reply?.status === 'refused' && typeof reply.code === 'string' && typeof reply.message === 'string') throw new Refused({ code: reply.code.slice(0, 64), message: reply.message.slice(0, 2000), retry_after_ms: Number.isSafeInteger(reply.retry_after_ms) ? reply.retry_after_ms : undefined });
  // Only the three parts of an attestation are ever written: whatever else stands beside them
  // in the answer is not signed.
  const lease = { issuer: reply?.lease?.issuer, payload: reply?.lease?.payload, signature: reply?.lease?.signature }, payload = lease.payload;
  if (reply?.status !== 'granted' || !payload || typeof payload !== 'object' || typeof lease.issuer !== 'string' || typeof lease.signature !== 'string') throw new Error('The controller\'s answer has an unexpected form');

  // Is it the answer to this request, for this host? An older lease put in its place on the way
  // has another nonce. (Not yet proof of anything: the guard below decides whether it is signed.)
  if (payload.host_id !== config.host_id || payload.request_nonce !== nonce) throw new Error('The lease is not the answer to this host\'s request: it is not installed');
  // The kit's own guard decides whether this lease is one this host may run on: the pinned
  // authority, this release, genesis, chain, key, signer identity and engine, the dates, the
  // lifetime. It reads the candidate from a finished file beside the lease file. Nothing of the
  // answer is relied on before this has passed.
  const target = view.signer_lease_file, prefix = `.${path.basename(target)}.`, candidate = path.join(path.dirname(target), `${prefix}${process.pid}.${randomUUID()}.tmp`);
  // Candidates an earlier run left behind when it was killed. They were never the lease file.
  for (const name of await readdir(path.dirname(target)).catch(() => [])) if (name.startsWith(prefix) && name.endsWith('.tmp')) await unlink(path.join(path.dirname(target), name)).catch(() => {});
  const handle = await open(candidate, 'wx', LEASE_FILE_MODE);
  // The mode is set outright: under a umask of 077, which the kit's own unit uses, the file
  // would otherwise be unreadable for the containers' user and the validator would stop.
  try { await handle.writeFile(JSON.stringify(lease) + '\n'); await handle.chmod(LEASE_FILE_MODE); await handle.sync(); } finally { await handle.close(); }
  const giveUp = async (message) => { await unlink(candidate).catch(() => {}); throw new Error(message); };
  try { await guard({ ...view, signer_lease_file: candidate }, now()); } catch (error) {
    await giveUp('The guard refuses the lease the controller sent, so it is not installed: ' + error.message + (/future-dated/.test(error.message) ? ' (if the lease is dated ahead of this host\'s clock, the clock is behind: check NTP)' : ''));
  }
  // The lease is genuine and for this host. Is it the newest the controller has for this request?
  // After renew_by_utc the controller no longer sends a lease again: it issues a new one in its
  // place. A lease that arrives past that time is an old answer, held back on the way.
  const renewBy = Date.parse(payload.renew_by_utc), expires = Date.parse(payload.expires_utc);
  if (payload.renew_by_utc !== undefined && !(now() < renewBy)) await giveUp('The lease is one the controller no longer sends: a newer one has taken its place. It is an old answer and is not installed');
  if (current?.trusted && payload.fence_domain === current.domain) {
    const token = exactU64(payload.fence_token);
    if (token < current.token) await giveUp('The lease carries a lower fence token than the installed one: it is not installed. Is a second controller answering?');
    if (payload.lease_id === current.id) { await unlink(candidate).catch(() => {}); return { installed: false, lease_id: current.id, expires_ms: current.expires, fence_token: payload.fence_token }; }
    // Within one tenure (one token) a lease that does not end later than the installed one is older.
    if (token === current.token && !(expires > current.expires)) await giveUp('The lease ends before the installed one of the same tenure: it is older and is not installed');
  }
  await moveIntoPlace(candidate, target);
  return { installed: true, lease_id: payload.lease_id, expires_ms: expires, fence_token: payload.fence_token };
}

/// What the guard says about the installed lease right now.
export async function status(config, inject = {}) {
  const now = (inject.now ?? Date.now)(), view = hostView(await json(config.settings_file), config.operator_directory);
  try {
    const { lease } = await guard(view, now);
    return { valid: true, seconds_left: Math.floor((Date.parse(lease.expires_utc) - now) / 1000), lease_id: lease.lease_id, fence_token: lease.fence_token, expires_utc: lease.expires_utc };
  } catch (error) { return { valid: false, seconds_left: 0, reason: error.message }; }
}

const jsonLog = (level, message, fields = {}) => process.stdout.write(JSON.stringify({ at: new Date().toISOString(), level, message, ...fields }) + '\n');

/// Asks again and again until stopped. After a lease is installed it waits a quarter of the
/// lease's remaining life; after a failure, ten seconds, or what the controller named, up to a minute.
export async function run(config, inject = {}) {
  const log = inject.log ?? jsonLog, now = inject.now ?? Date.now, sleep = inject.sleep ?? ((ms, signal) => new Promise((resolve) => { const timer = setTimeout(resolve, ms); signal.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true }); }));
  const stop = inject.signal ?? new AbortController().signal;
  log('info', 'lease agent started', { controller: config.controller_url, host_id: config.host_id });
  while (!stop.aborted) {
    let wait = RETRY_MS;
    try {
      const result = await round(config, inject);
      wait = Math.min(120_000, Math.max(5_000, Math.floor((result.expires_ms - now()) / 4)));
      log('info', result.installed ? 'lease installed' : 'the installed lease is the newest', { lease_id: result.lease_id, fence_token: result.fence_token, seconds_left: Math.floor((result.expires_ms - now()) / 1000), next_request_in_seconds: Math.round(wait / 1000) });
    } catch (error) {
      if (error instanceof Refused && error.retryAfterMs !== undefined) wait = Math.min(60_000, Math.max(1_000, error.retryAfterMs));
      const left = await status(config, inject).catch(() => ({ valid: false, seconds_left: 0 }));
      log(left.valid && error instanceof Refused && error.code === 'TOO_SOON' ? 'info' : 'error', 'no new lease: ' + error.message, { ...(error instanceof Refused ? { refusal_code: error.code, refusal_is_unsigned: true } : {}), installed_lease_valid: left.valid, installed_lease_seconds_left: left.seconds_left, validator_stops_when_it_ends: true, next_request_in_seconds: Math.round(wait / 1000) });
    }
    await sleep(wait, stop);
  }
  log('info', 'lease agent stopped');
}

export const USAGE = `Usage:
  node deploy/lease-agent.mjs run CONFIG_JSON                 keep the lease file fresh until stopped
  node deploy/lease-agent.mjs once CONFIG_JSON                one request; exit code 0 if a valid lease is installed afterwards
  node deploy/lease-agent.mjs status CONFIG_JSON [SECONDS]    what the guard says about the installed lease; exit code 2 under SECONDS left (default 60)
  node deploy/lease-agent.mjs keygen NEW_KEY_FILE HOST_ID     make this host's key; prints the entry for the controller config`;

async function readConfig(file) {
  const text = await readFile(file, 'utf8');
  try { return validateAgentConfig(JSON.parse(text)); } catch (error) { if (error instanceof SyntaxError) throw new Error('The config file is not valid JSON'); throw error; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    const [action, first, second] = process.argv.slice(2);
    if (action === 'keygen' && process.argv.length === 5) {
      const made = await writeKeyFile(path.resolve(first), generateKeyRecord(KEY_PURPOSES.host, second));
      console.log(JSON.stringify({ made: 'host key', controller_config_host_entry: { id: made.id, public_key_hex: made.public_key_hex, signer_identity: 'REPLACE_WITH_SIGNER_IDENTITY_OF_THE_OPERATOR_SETTINGS', signer_fencing: 'NOT_DECLARED' } }, null, 2));
    } else if (action === 'run' && process.argv.length === 4) {
      const stopping = new AbortController();
      process.once('SIGTERM', () => stopping.abort()); process.once('SIGINT', () => stopping.abort());
      await run(await readConfig(first), { signal: stopping.signal });
    } else if (action === 'once' && process.argv.length === 4) {
      const config = await readConfig(first);
      try { console.log(JSON.stringify(await round(config))); } catch (error) { console.error(error.message); }
      const after = await status(config); console.log(JSON.stringify(after)); if (!after.valid) process.exitCode = 1;
    } else if (action === 'status' && (process.argv.length === 4 || process.argv.length === 5)) {
      const least = second === undefined ? 60 : Number(second);
      if (!Number.isInteger(least) || least < 0) throw new Error(USAGE);
      const result = await status(await readConfig(first)); console.log(JSON.stringify(result));
      if (!result.valid || result.seconds_left < least) process.exitCode = 2;
    } else throw new Error(USAGE);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
