#!/usr/bin/env node
// Security watch process: tells owners what their accounts' security rules are waiting on.
// Reads one JSON config file, polls verified state through the SDK's verifying client, delivers
// events to webhooks, and serves the recent events of each account on a local port.
// It holds no key of any account: it reads, verifies and tells, and signs nothing.
import { readFile, writeFile, rename, mkdir, link, unlink, open } from 'node:fs/promises';
import { readFileSync, renameSync } from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../../client-v4/time-sdk.js';
import * as installedVerifier from '../../client-v4/proof-verifier.mjs';
import { createSecurityWatch, createFeed, createAlertServer, fileStore, webhookAdapter, checkWebhookURL, webhookSecretProblem, WEBHOOK_SECRET_RULE } from '../../client-v4/security-watch-service.mjs';

const KEYS = ['gateway', 'trust', 'subscriptions', 'poll_seconds', 'port', 'host', 'hosts', 'feed_token', 'data_directory', 'reminder_hours', 'max_lag_seconds', 'gateway_timeout_seconds'];
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const canonicalId = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 18446744073709551615n;
/// This run of this process. A lock that names our pid but another run was left by an earlier
/// process that had the same pid (a container restarted gives pid 1 again): it is stale.
const RUN = randomUUID();

/// Checks a config and fills in the defaults. Throws on anything unknown or malformed, and never
/// puts a value of the config in the message.
export function validateConfig(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('The config is a JSON object');
  const unknown = Object.keys(config).filter((k) => !KEYS.includes(k));
  if (unknown.length) throw new Error(`Unknown config setting (${unknown.length}); allowed: ${KEYS.join(', ')}`);
  let gateway;
  try { gateway = new URL(config.gateway); } catch { throw new Error('gateway is the URL of a wallet gateway'); }
  if (gateway.username || gateway.password || !(gateway.protocol === 'https:' || (gateway.protocol === 'http:' && LOOPBACK.has(gateway.hostname)))) throw new Error('gateway must be https:// (http:// only on this machine, for a gateway that was started without public origins): give the public origin of the wallet gateway');
  const trust = config.trust;
  if (!trust || typeof trust !== 'object' || String(trust.app_version) !== '4' || !/^[0-9a-f]{64}$/.test(trust.network_id ?? '') || typeof trust.chain_id !== 'string') throw new Error('trust is the application-4 trust manifest the SDK takes (app_version, network_id, chain_id, ...)');
  if (trust.nodes_report_upgrades !== undefined && typeof trust.nodes_report_upgrades !== 'boolean') throw new Error('trust.nodes_report_upgrades is true or false');
  if (!Array.isArray(config.subscriptions) || config.subscriptions.length === 0) throw new Error('subscriptions lists at least one account');
  const subscriptions = config.subscriptions.map((s, i) => {
    if (!s || typeof s !== 'object' || Object.keys(s).some((k) => !['account', 'webhook', 'secret'].includes(k))) throw new Error(`subscription ${i}: only account, webhook and secret`);
    if (!canonicalId(s.account)) throw new Error(`subscription ${i}: account is a decimal account id in quotes`);
    if (s.webhook === undefined && s.secret === undefined) return { account: s.account };
    checkWebhookURL(s.webhook);
    const problem = webhookSecretProblem(s.secret);
    if (problem) throw new Error(`subscription ${i}: the secret ${problem}. ${WEBHOOK_SECRET_RULE}`);
    return { account: s.account, webhook: s.webhook, secret: s.secret };
  });
  const pairs = subscriptions.filter((s) => s.webhook).map((s) => JSON.stringify([s.account, s.webhook]));
  if (new Set(pairs).size !== pairs.length) throw new Error('A webhook is listed twice for the same account');
  const integer = (name, fallback, min, max) => {
    const value = config[name] ?? fallback;
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${name} is a whole number from ${min} to ${max}`);
    return value;
  };
  const reminder = config.reminder_hours ?? 6;
  if (typeof reminder !== 'number' || !(reminder > 0) || reminder > 720) throw new Error('reminder_hours is a number of hours above 0, at most 720');
  if (typeof config.data_directory !== 'string' || !path.isAbsolute(config.data_directory)) throw new Error('data_directory is an absolute path');
  const host = config.host ?? '127.0.0.1';
  if (typeof host !== 'string' || !host) throw new Error('host is the address to listen on');
  const hosts = config.hosts ?? [];
  if (!Array.isArray(hosts) || !hosts.every((h) => typeof h === 'string' && /^[a-z0-9.[\]:-]+:[0-9]{1,5}$/.test(h))) throw new Error('hosts lists extra Host header values, each "name:port" in lower case');
  const token = config.feed_token ?? null;
  if (token !== null && (typeof token !== 'string' || token.length < 24)) throw new Error('feed_token is a string of at least 24 characters');
  if (!LOOPBACK.has(host) && !token) throw new Error('A feed listening beyond this machine needs a feed_token');
  return {
    gateway: gateway.href, trust, subscriptions,
    poll_seconds: integer('poll_seconds', 30, 5, 3600),
    port: integer('port', 8920, 1024, 65535),
    host, hosts: hosts.map((h) => h.toLowerCase()), feed_token: token, data_directory: path.resolve(config.data_directory),
    reminder_hours: reminder,
    max_lag_seconds: integer('max_lag_seconds', 300, 2, 86400),
    gateway_timeout_seconds: integer('gateway_timeout_seconds', 30, 2, 600),
  };
}

/// Lines of JSON on stdout. Callers pass no secret and no webhook path: only origins and counts.
export function jsonLog(write = (line) => process.stdout.write(`${line}\n`)) {
  return (level, message, fields = {}) => write(JSON.stringify({ at: new Date().toISOString(), level, message, ...fields }));
}

/// Where the light client keeps the highest checkpoint it verified, so that a restart goes on
/// from it rather than from the manifest's.
function checkpointFile(file) {
  return {
    async getItem(key) {
      try { return JSON.parse(await readFile(file, 'utf8'))[key] ?? null; } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    },
    async setItem(key, value) {
      let all = {};
      try { all = JSON.parse(await readFile(file, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      all[key] = value;
      const temporary = `${file}.${process.pid}.tmp`;
      const handle = await open(temporary, 'w', 0o600);
      try { await handle.writeFile(JSON.stringify(all)); await handle.sync(); } finally { await handle.close(); }
      await rename(temporary, file);
    },
  };
}

/// How often the holder of the lock rewrites its time in it; a lock not rewritten for three times
/// as long is stale, whatever process now has its pid (pids are reused after a reboot).
export const LOCK_BEAT_MS = 10_000;

/// One watch per data directory: two would deliver every event twice.
/// - The lock {pid, run, beat} is written whole to a temporary file and linked into place, so it
///   is never seen empty, and rewritten (atomically) every LOCK_BEAT_MS while the watch runs.
/// - It is stale when it cannot be read, when its beat is older than 3 × LOCK_BEAT_MS, when its pid
///   is dead, or when it names this pid with another run (a restarted container is pid 1 again).
/// - A stale lock is taken by renaming it to a name of our own and checking that what was renamed
///   is what was judged stale; two watches starting together cannot both take it.
/// - A holder that finds its lock gone or taken (it stalled for longer than the stale time) calls
///   `onLost(why)` (given 5 s to stop what it runs) and exits with LOCK_LOST_EXIT, unless
///   `exitOnLost` is false. Errors reading or rewriting the lock are retried at the next beat.
/// - A heartbeat rewrites the lock only if the lock is this run's at the moment it is replaced:
///   the run id is read again and the file replaced in one synchronous step, so that nothing this
///   process does (a stalled event loop, a release, another heartbeat) can come between the look
///   and the write. One heartbeat runs at a time.
/// - Once the function that releases the lock has resolved, no heartbeat of this process writes
///   or renames the lock again: the timer is stopped, a heartbeat in flight is waited for and
///   finds the release, and a heartbeat that starts later does nothing.
/// Returns the function that releases the lock.
/// For tests: `interval(callback, ms)` and `cancel(timer)` stand in for setInterval and
/// clearInterval (the callback returns the heartbeat's promise), and `pause(point)` is awaited
/// inside a heartbeat at the named point ('heartbeat-written': its new lock is written to a
/// temporary file and not yet put in place).
export const LOCK_LOST_EXIT = 75;
export async function claim(directory, { beatMs = LOCK_BEAT_MS, now = Date.now, onLost = () => {}, exitOnLost = true, interval = (callback, ms) => setInterval(callback, ms), cancel = (timer) => clearInterval(timer), pause = async () => {} } = {}) {
  const file = path.join(directory, 'watch.lock'), mine = () => JSON.stringify({ pid: process.pid, run: RUN, beat: now() });
  const temporary = path.join(directory, `watch.lock.${process.pid}.${RUN}.tmp`);
  const place = async () => {
    await writeFile(temporary, mine(), { mode: 0o600 });
    try { await link(temporary, file); } catch (error) {
      // A file system without hard links: create the lock exclusively and write it at once.
      if (!['EPERM', 'ENOTSUP', 'ENOSYS', 'EXDEV'].includes(error.code)) throw error;
      const handle = await open(file, 'wx', 0o600);
      try { await handle.writeFile(mine()); await handle.sync(); } finally { await handle.close(); }
    } finally { await unlink(temporary).catch(() => {}); }
  };
  for (let tries = 0; tries < 5; tries++) {
    try { await place(); return holding(); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    let text = null, holder = null;
    try { text = await readFile(file, 'utf8'); holder = JSON.parse(text); } catch (error) { if (error.code === 'ENOENT') continue; holder = null; }
    const pid = holder?.pid;
    if (pid === process.pid && holder?.run === RUN) throw new Error(`This process already watches ${directory}`);
    const fresh = Number.isFinite(holder?.beat) && now() - holder.beat <= 3 * beatMs;
    let alive = false;
    if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) { try { process.kill(pid, 0); alive = true; } catch (e) { alive = e.code === 'EPERM'; } }
    if (fresh && alive) throw new Error(`Another watch (process ${pid}) uses ${directory}`);
    // Stale: take it aside under a name of our own, and make sure it is the one we judged.
    const aside = `${file}.stale.${process.pid}.${RUN}.${tries}`;
    try { await rename(file, aside); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    const taken = await readFile(aside, 'utf8').catch(() => null);
    if (taken !== text) await link(aside, file).catch(() => {}); // another starter's fresh lock: put it back
    await unlink(aside).catch(() => {});
  }
  throw new Error(`Could not claim ${directory}`);

  function holding() {
    let lost = false, released = false, inFlight = null, releasing = null;
    // The lock is gone or another run holds it (this process stalled past the stale time, and a
    // second watch took over): stop, so that only one watch delivers and writes the store.
    const giveUp = async (why) => {
      if (lost || released) return; lost = true; cancel(beat);
      try { await Promise.race([Promise.resolve(onLost(why)), new Promise((r) => setTimeout(r, 5000).unref?.())]); } catch { /* stopping anyway */ }
      if (exitOnLost) process.exit(LOCK_LOST_EXIT);
    };
    // Giving up runs on its own (it waits for `onLost`, then exits): the heartbeat that found the
    // loss ends at once, so a release that waits for a heartbeat in flight never waits for it.
    const lose = (why) => { giveUp(why).catch(() => {}); };
    // Puts `next` in place of the lock if, and only if, the lock is this run's right now. The look
    // and the replacement are synchronous and adjacent: no await, so no turn of this process's
    // event loop, lies between them. A heartbeat that looked first and replaced later could put
    // this run's lock over the lock of a run that took over in between (after a stall), or back
    // in place after a release had removed it.
    const replaceIfOurs = (next) => {
      let current;
      try { current = JSON.parse(readFileSync(file, 'utf8')); } catch (error) { return error.code === 'ENOENT' ? 'gone' : 'retry'; }
      if (current?.run !== RUN) return 'taken';
      try { renameSync(next, file); return 'replaced'; } catch { return 'retry'; } // busy (Windows): the next beat writes it
    };
    const heartbeat = async () => {
      let holder;
      try { holder = JSON.parse(await readFile(file, 'utf8')); } catch (error) {
        if (released || lost) return;
        if (error.code === 'ENOENT') lose('the lock file is gone');
        return; // otherwise busy or half-replaced (Windows): look again at the next beat
      }
      if (released || lost) return;
      if (holder?.run !== RUN) return lose('another process holds the lock');
      const next = `${file}.${process.pid}.beat`;
      let outcome = 'retry';
      try {
        await writeFile(next, mine(), { mode: 0o600 });
        await pause('heartbeat-written');
        // A release or a loss that began while this heartbeat was under way ends it here.
        // Windows refuses the replacement while another program (a virus scanner, an indexer) has
        // one of the two files open: it is tried again a few times, each time with a fresh look
        // at whose lock it is, and never after a release or a loss.
        for (let attempt = 0; attempt < 5; attempt++) {
          if (attempt) await new Promise((resolve) => setTimeout(resolve, 20));
          if (released || lost) break;
          outcome = replaceIfOurs(next);
          if (outcome !== 'retry') break;
        }
      } catch { /* busy: the next beat writes it */ }
      if (outcome !== 'replaced') await unlink(next).catch(() => {});
      if (outcome === 'gone') lose('the lock file is gone');
      if (outcome === 'taken') lose('another process holds the lock');
    };
    // One heartbeat at a time; none after a release or a loss.
    const beat = interval(() => {
      if (lost || released) return inFlight ?? undefined;
      inFlight ??= heartbeat().catch(() => {}).finally(() => { inFlight = null; });
      return inFlight;
    }, beatMs);
    beat?.unref?.();
    return () => releasing ??= (async () => {
      released = true; cancel(beat);
      // A heartbeat in flight finishes first. It sees `released` before it would replace the lock,
      // or it has replaced it already; either way nothing of it is left when the lock is removed.
      await inFlight;
      try { if (JSON.parse(await readFile(file, 'utf8')).run === RUN) await unlink(file); } catch { /* gone already */ }
    })();
  }
}

/// The id of a webhook target names what it is: its accounts and its URL. A queue kept under it
/// can only ever go to that URL for those accounts, however the config is reordered or edited.
/// (The secret is not part of it: a new secret signs the same receiver's queued events.)
export function targetId(accounts, url) {
  return `webhook-${createHash('sha256').update(JSON.stringify([[...accounts].map(String).sort(), url])).digest('hex').slice(0, 24)}`;
}

/// A fetch for the SDK that gives up on any request after `ms`, body included: the SDK itself
/// sets no time limit, and a gateway that trickles bytes would otherwise hold a request forever.
export function boundedFetch(ms, fetcher = globalThis.fetch) {
  return (url, options = {}) => fetcher(url, { ...options, signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(ms)]) : AbortSignal.timeout(ms) });
}

/// What the start log says when the trust data does not declare that the nodes report upgrades.
export const UPGRADES_NOT_DECLARED = 'the trust data does not say that this network\'s nodes report upgrades (trust.nodes_report_upgrades is not true): the question about scheduled upgrades is asked apart from the account checks, and a gateway that leaves it unanswered fails no account check. If the nodes are time-node-v5 0.7.0 or later, install the trust data that says so.';

/// Starts the watch. `inject` replaces parts for tests: verifiedState, upgradeStatus, fetcher,
/// webhookFetcher, log, now. `inject.forgetUpgradeAnswer` is the command line's
/// --forget-upgrade-answer: the watch forgets that a node ever answered the upgrade question.
export async function start(rawConfig, inject = {}) {
  const config = validateConfig(rawConfig), log = inject.log || jsonLog();
  await mkdir(config.data_directory, { recursive: true, mode: 0o700 });
  let watch, server;
  const release = await claim(config.data_directory, {
    // Another watch took over while this one stalled: stop delivering and writing, and exit non-zero.
    onLost: async (why) => {
      log('error', `this watch lost the lock of its data directory (${why}) and stops, exit code ${LOCK_LOST_EXIT}, so that only one watch delivers`);
      await watch?.stop(); await server?.close().catch(() => {});
    },
  });
  try {
    let verifiedState = inject.verifiedState, upgradeStatus = inject.upgradeStatus ?? null;
    // Whether this network's nodes answer the question about scheduled upgrades is part of the
    // pinned trust data (`trust.nodes_report_upgrades`), never something a gateway tells. If they
    // do, every account check carries the question from the first poll on, and nothing about it is
    // learned or stored. If the trust data does not say so, the question is asked apart from the
    // account checks, which is the weaker way: the start log and /health say which one it is.
    const upgradeDeclared = globalThis.TimeSDK.nodesReportUpgrades(config.trust);
    if (!verifiedState) {
      const client = globalThis.TimeSDK.createClient({ gateway: config.gateway, trust: config.trust, verifier: installedVerifier, checkpointStorage: checkpointFile(path.join(config.data_directory, 'checkpoint.json')), fetcher: boundedFetch(config.gateway_timeout_seconds * 1000, inject.fetcher) });
      verifiedState = (selection) => client.getVerifiedState(selection);
      // A scheduled change of the protocol version, read from proven state (never the gateway's word).
      upgradeStatus = () => client.getUpgradeStatus();
    }
    const accounts = [...new Set(config.subscriptions.map((s) => s.account))];
    const feed = await createFeed({ limit: 100, store: fileStore(path.join(config.data_directory, 'feed.json')) }).load();
    const targets = [{ id: 'feed', accounts: null, adapter: feed.adapter }];
    for (const s of config.subscriptions) {
      if (s.webhook) targets.push({ id: targetId([s.account], s.webhook), accounts: [s.account], adapter: webhookAdapter({ url: s.webhook, secret: s.secret, ...(inject.webhookFetcher ? { fetcher: inject.webhookFetcher } : {}) }) });
    }
    watch = createSecurityWatch({
      verifiedState, upgradeDeclared, upgradeStatus, forgetUpgradeAnswer: inject.forgetUpgradeAnswer === true, accounts, targets, log, ...(inject.now ? { now: inject.now } : {}),
      // feed.json and checkpoint.json are written only after watch.json exists: if they are there
      // and watch.json is not, the watch lost its memory, and the owners are told.
      store: fileStore(path.join(config.data_directory, 'watch.json'), { companions: [path.join(config.data_directory, 'feed.json'), path.join(config.data_directory, 'checkpoint.json')] }),
      reminderSeconds: config.reminder_hours * 3600, maxLagSeconds: config.max_lag_seconds, batchTimeoutMs: config.gateway_timeout_seconds * 1000,
    });
    server = createAlertServer({ feed, accounts, status: () => watch.status(), port: config.port, host: config.host, hosts: config.hosts, token: config.feed_token });
    const listening = await server.listen();
    log('info', 'security watch started', {
      gateway: new URL(config.gateway).origin, network_id: config.trust.network_id, nodes_report_upgrades: upgradeDeclared, accounts: accounts.length,
      webhooks: targets.filter((t) => t.adapter.name === 'webhook').map((t) => t.adapter.origin), alerts: listening, poll_seconds: config.poll_seconds, feed_token: Boolean(config.feed_token),
    });
    if (!upgradeDeclared) log('warn', UPGRADES_NOT_DECLARED);
    watch.start(config.poll_seconds * 1000);
    let closing;
    return { url: listening, watch, feed, close: () => closing ??= (async () => { await watch.stop(); await server.close(); await release(); })() };
  } catch (error) {
    await watch?.stop(); await server?.close().catch(() => {}); await release();
    throw error;
  }
}

/// Reads and parses the config file. A parse error is reported by position only: some versions of
/// Node quote the text around the error, which may be a secret.
export async function readConfig(file) {
  const text = await readFile(file, 'utf8');
  try { return JSON.parse(text); } catch (error) {
    const at = /position (\d+)/.exec(error.message)?.[1];
    throw new Error(`The config file is not valid JSON${at ? ` (near character ${at})` : ''}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    const forget = process.argv[3] === '--forget-upgrade-answer';
    if (process.argv.length !== (forget ? 4 : 3)) throw new Error('Usage: node deploy/watch/start.mjs CONFIG_JSON [--forget-upgrade-answer]');
    const running = await start(await readConfig(process.argv[2]), forget ? { forgetUpgradeAnswer: true } : {});
    const close = async () => { await running.close(); };
    process.once('SIGTERM', close); process.once('SIGINT', close);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
