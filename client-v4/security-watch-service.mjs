// Security watch, the running part: polls verified state for a list of accounts, compares each
// with its last snapshot (security-watch.mjs), and delivers every new event to its targets.
//
// Reading:
// - State comes from `verifiedState(selection)`, normally the SDK client's getVerifiedState, which
//   checks every answer against validator signatures with the wallet's own light client. The SDK
//   accepts at most 8 account ids in one selection, so accounts are asked in batches.
// - Each batch has a time limit. A gateway that does not answer, answers with an older chain than
//   the one already seen, with another network, or with state older than the account's allowed
//   lag (at most half its `delay_seconds`) counts as a failure for those accounts.
// - An account counts as unseen ("blind") when, at a poll, its newest verified state is older than
//   its allowed lag (the gateway answered with old state, or did not answer), or when it cannot be
//   read at all. The owner then gets an urgent `watch_blind`, once per episode, saying what was
//   observed, while half the wait is still ahead; and `watch_restored` once a poll gives a fresh
//   view again. Between polls an honest view ages by up to one poll interval, so the watchdog, which
//   judges only when a poll is overdue, allows that interval on top. With `poll_seconds` above a
//   quarter of an account's delay a single failed poll can already make it blind; that is warned.
// - A change of the network's protocol version. This watch reads state with a verifier that
//   implements certain versions. Once the network runs a later one, every read fails with the
//   verifier's refusal: an error whose `code` is 'UPGRADE_REQUIRED'. Only the verifier's wrapper
//   and the SDK's own version check set that code; an error that repeats what a gateway said
//   never has it, and this watch tests the code, never the words. That refusal is not a gateway
//   that does not answer: the owner gets an urgent `watch_outdated` at that very poll, without
//   waiting for the allowed lag, in this watch's own words.
// - The upgrade signal of a watched account's validator (action kind 80): `upgrade_signal_changed`
//   when the account's entry among the signals is another one than at the last reading (support
//   for a plan, or a withdrawal; urgent, because only a key of the account that may spend can do
//   it), and `upgrade_signal_dropped` when the network dropped it. Read from the upgrade entry of
//   the same verified read as the account, so only where every account check carries that entry
//   (`upgradeDeclared`). See diffSignal in security-watch.mjs.
// - A scheduled change (`upgradeStatus`, read from proven state): every owner gets
//   `upgrade_scheduled` once per plan; `upgrade_cancelled` if the plan is withdrawn; while this
//   build does not implement the scheduled version, a `watch_outdated` reminder once a day; and
//   `watch_ready` once if the watch is updated while the plan stands.
//   The question is never between an urgent event and its delivery, and what a gateway says
//   never decides whether it is asked:
//   - `upgradeDeclared` (the network's pinned trust data says that its nodes report upgrades,
//     `trust.nodes_report_upgrades`): every account check carries `include_upgrade` from the first
//     poll on. Nothing is learned and nothing is stored about it. A gateway that holds, refuses
//     or leaves out the question fails the account check itself, and the owner is told like for
//     any other blindness.
//   - Otherwise (`upgradeStatus` given, an older network): the question is never part of an
//     account check. It is asked apart with `upgradeStatus()`, after every poll has stored and
//     sent what it found, with the gateway time limit, one at a time. A gateway that holds or
//     refuses it therefore cannot delay or fail an account check, not even once.
//     - Until a node has answered it, a failure is logged once and nothing is said to owners.
//     - Once a node has answered (remembered in the store), a retry that is not answered begins
//       an episode. It ends only when several retries in a row are answered
//       (UPGRADE_ANSWERS_TO_RESTORE), so a gateway that answers now and then cannot flip the
//       watch. Each answer in between is still used: a plan is announced at once.
//     - Owners are told with event types of their own, which say nothing about whether the watch
//       sees the account: `upgrade_question_unanswered`, at most once in 24 hours while an
//       episode is on, and `upgrade_question_answered`, once for each of those when its episode
//       has ended. Neither is urgent.
//     - The operator can make the watch forget that it ever had an answer (`forgetUpgradeAnswer`).
//
// Delivering:
// - Every target (a webhook, the feed, any adapter) has its own queue and its own pump, which runs
//   on its own: polling never waits for a delivery, and a dead receiver delays only its own queue.
//   A target's id must name what it is (start.mjs hashes its accounts and URL), so that after a
//   change of configuration a queue can never reach another receiver.
// - The first delivery of an event may retry inside the adapter (the webhook does, with backoff).
//   After it has failed once, it gets one attempt per poll. After `breaker.failures` failures in a
//   row a target rests, at most for the allowed lag of its accounts (and never more than 15 min);
//   an urgent event queued meanwhile is still tried once at once, and a success ends the rest.
// - A receiver that refuses events (a 4xx) keeps them queued and retried, and the owner is told
//   through the other targets, urgently, that the alert endpoint refuses alerts. Only an error
//   marked `permanent` (the webhook's 410 Gone) moves an event to the dead letters.
//
// Remembering: the last snapshot of each account, the ids of the events produced and of those
// queued per target, the queues, the dead letters and the network the snapshots belong to live in
// one JSON document (`store`: get/put). A restart starts from the last snapshots, so it misses
// nothing that happened meanwhile and queues nothing twice. Delivery is at least once: a crash
// after a delivery and before the store is written sends that event again, with the same id. If
// the store is lost, every owner is told that the watch lost its memory.
//
// Adapters have one method, `deliver(event, { first, signal })`, which resolves once the event is
// handed over and throws to have it tried again (`permanent: true` dead-letters it, `refused: true`
// marks a receiver that refuses). Two are here: a signed webhook and an in-memory feed that
// `createAlertServer` exposes read-only. Email, SMS or push need a provider nobody has chosen yet;
// each would be one more adapter.
import { readFile, rename, mkdir, open, readdir, access } from 'node:fs/promises';
import { createHmac, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import './time-sdk.js';
import { diffSecurity, diffSignal, snapshotOf, utc } from './security-watch.mjs';

const SDK = globalThis.TimeSDK;

export const MAX_IDS_PER_QUERY = 8;
const STORE_FORMAT = 3;
/// On a network that does not declare that its nodes report upgrades: how many retries of the
/// upgrade question in a row must be answered before an unanswered episode is over, and how long
/// an owner is not told again that it is unanswered.
export const UPGRADE_ANSWERS_TO_RESTORE = 3;
const UPGRADE_TELL_AGAIN_MS = 86_400_000;
const canonicalId = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 18446744073709551615n;
const clone = (value) => (value == null ? value : JSON.parse(JSON.stringify(value)));

/// Account ids in groups the SDK accepts in one selection.
export function batches(ids, size = MAX_IDS_PER_QUERY) {
  if (!Number.isInteger(size) || size < 1 || size > MAX_IDS_PER_QUERY) throw new Error(`A batch holds 1 to ${MAX_IDS_PER_QUERY} accounts`);
  const out = [];
  for (let i = 0; i < ids.length; i += size) out.push(ids.slice(i, i + size));
  return out;
}
/// `promise`, or a rejection after `ms` or when `signal` aborts. The work behind `promise` is not
/// stopped (the SDK takes no signal); the caller just stops waiting for it.
export function withTimeout(promise, ms, signal, what = 'gateway') {
  return new Promise((resolve, reject) => {
    const fail = (message) => { cleanup(); reject(Object.assign(new Error(message), { timeout: true })); };
    const timer = setTimeout(() => fail(`${what} did not answer within ${Math.round(ms / 1000)} s`), ms);
    const onAbort = () => fail('stopped');
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort); };
    if (signal?.aborted) return onAbort();
    signal?.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then((value) => { cleanup(); resolve(value); }, (error) => { cleanup(); reject(error); });
  });
}
const sleeping = (ms, signal) => new Promise((resolve) => {
  if (signal?.aborted) return resolve();
  const timer = setTimeout(resolve, ms);
  signal?.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
});

// ------------------------------------------------------------------ stores
/// A store in memory: for tests, and for a watch that may forget on restart.
export function memoryStore(initial = null) {
  let value = clone(initial);
  return { get: async () => clone(value), put: async (next) => { value = clone(next); } };
}
/// A store in one JSON file. A write goes to a temporary file that is flushed to disk, the current
/// file becomes `.bak`, the temporary file takes its place, and the directory is flushed. A read
/// that finds the file missing or torn uses `.bak`; if that fails too both are moved aside
/// (`.corrupt-<time>`) and the read throws, so that the watch starts afresh and says so.
/// A store that is simply missing is new, unless a damaged copy was set aside earlier (and nothing
/// was written since), or one of `companions` exists (files that are written only after the store
/// is): then its memory was lost, and the read throws too.
export function fileStore(file, { companions = [] } = {}) {
  const backup = `${file}.bak`;
  const parse = async (name) => JSON.parse(await readFile(name, 'utf8'));
  const exists = (name) => access(name).then(() => true, () => false);
  return {
    async get() {
      let problem = null;
      try { return await parse(file); } catch (error) { if (error.code !== 'ENOENT') problem = error; }
      try { return await parse(backup); } catch (error) { if (error.code !== 'ENOENT') problem ??= error; }
      if (!problem) {
        const base = path.basename(file), names = await readdir(path.dirname(file)).catch(() => []);
        if (names.some((name) => name.startsWith(`${base}.corrupt-`))) throw Object.assign(new Error('The watch store is missing and a damaged copy was set aside earlier'), { lost: 'its records were damaged and set aside' });
        for (const companion of companions) if (await exists(companion)) throw Object.assign(new Error('The watch store is missing though the watch has run here before'), { lost: 'its records are missing' });
        return null;
      }
      const stamp = Date.now();
      await rename(file, `${file}.corrupt-${stamp}`).catch(() => {});
      await rename(backup, `${backup}.corrupt-${stamp}`).catch(() => {});
      throw Object.assign(new Error(`The watch store was unreadable and was moved aside (${problem.message})`), { lost: 'its records were damaged and set aside' });
    },
    async put(value) {
      const directory = path.dirname(file);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const temporary = `${file}.${process.pid}.tmp`;
      const handle = await open(temporary, 'w', 0o600);
      try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); } finally { await handle.close(); }
      await rename(file, backup).catch((error) => { if (error.code !== 'ENOENT') throw error; });
      await rename(temporary, file);
      // Flushing a directory is how POSIX makes a rename durable; Windows has no such call.
      if (process.platform !== 'win32') { const dir = await open(directory, 'r'); try { await dir.sync(); } finally { await dir.close(); } }
    },
  };
}

// ------------------------------------------------------------------ the runner
/// Options:
/// - `verifiedState(selection)`: the SDK's verified result.
/// - `upgradeDeclared` (boolean): the network's pinned trust data says that its nodes report
///   upgrades. Every account check then asks `verifiedState` with `include_upgrade: true`, and
///   the state must carry its `upgrade` entry, which `upgradeOf(state)` reads (the SDK's
///   upgradeStatusOf; a test can stand in for a later build).
/// - `upgradeStatus()` (optional, for a network that does not declare it): the SDK's
///   getUpgradeStatus, `{version, scheduled, known}` read from proven state. It is called after
///   every poll, apart from the account checks. Without either option the watch sends no notice
///   of a scheduled upgrade.
/// - `forgetUpgradeAnswer` (boolean): forget, at start, that a node ever answered the question
///   (after the network's nodes were replaced by older ones). The owners are then not told that
///   it is unanswered, as on a network whose nodes never answered it.
/// - `accounts`: ids to watch.
/// - `targets`: [{ id, accounts (ids, or null for all), adapter }]; or `onEvent(event)` for one target.
///   The id must change whenever the receiver or its accounts change (start.mjs hashes both).
/// - `store` (get/put); `now()` (ms); `log(level, message, fields)`.
/// - `reminderSeconds` (6 hours); `maxLagSeconds` (300; an account's own limit is at most half its
///   delay_seconds); `batchTimeoutMs` (30 s); `watchdogMs` (3 poll intervals, at least 60 s).
/// - `breaker` { failures: 3, baseMs: 30 s, maxMs: 15 min }; `keepSeen` (1000 ids per account and
///   per target); `maxQueue` (1000 events per target); `maxDead` (100 per target).
export function createSecurityWatch({ verifiedState, upgradeDeclared = false, upgradeStatus = null, upgradeOf = (state) => SDK.upgradeStatusOf(state), forgetUpgradeAnswer = false, accounts, targets, onEvent, store = memoryStore(), now = Date.now, reminderSeconds, maxLagSeconds = 300, batchTimeoutMs = 30000, watchdogMs = null, breaker = {}, keepSeen = 1000, maxQueue = 1000, maxDead = 100, log = () => {} }) {
  if (typeof verifiedState !== 'function') throw new Error('verifiedState is a function');
  if (upgradeStatus !== null && typeof upgradeStatus !== 'function') throw new Error('upgradeStatus is a function');
  if (typeof upgradeDeclared !== 'boolean' || typeof forgetUpgradeAnswer !== 'boolean') throw new Error('upgradeDeclared and forgetUpgradeAnswer are true or false');
  if (upgradeDeclared) upgradeStatus = null; // nothing is probed or learned on a network that declares it
  if (!targets && typeof onEvent === 'function') targets = [{ id: 'default', accounts: null, adapter: { deliver: (event) => onEvent(event) } }];
  if (!Array.isArray(targets) || targets.length === 0 || !targets.every((t) => t && typeof t.id === 'string' && typeof t.adapter?.deliver === 'function')) throw new Error('targets are [{ id, accounts, adapter: { deliver } }], or pass onEvent');
  if (new Set(targets.map((t) => t.id)).size !== targets.length) throw new Error('Target ids must differ');
  if (!Array.isArray(accounts) || accounts.length === 0 || !accounts.every(canonicalId)) throw new Error('Accounts are canonical decimal account ids');
  const ids = [...new Set(accounts)];
  const rest = { failures: 3, baseMs: 30000, maxMs: 900000, ...breaker };
  const wants = new Map(targets.map((t) => [t.id, t.accounts ? new Set([...t.accounts].map(String)) : null]));
  const wanted = (targetId, account) => !wants.get(targetId) || wants.get(targetId).has(account);
  const pumps = new Map(targets.map((t) => [t.id, { running: null, failures: 0, openUntil: 0, backoffMs: rest.baseMs, tried: new Set(), attempted: new Set() }]));
  const stopper = new AbortController();
  let data = null, startedAt = null, running = null, timer = null, watchdog = null, stopped = true, intervalMs = 30000, lastPollEnd = null;
  let writing = Promise.resolve(), queuedWrite = null;
  const problems = {}; // account -> why the last poll did not give a fresh view of it
  const warned = new Set();
  const status = { last_poll_at: null, last_success_at: null, lag_seconds: null, store_error: null, alarm: false, config_warnings: 0, upgrade_scheduled: null, upgrade_known: null, upgrade_declared: upgradeDeclared, upgrade_read: upgradeDeclared || upgradeStatus ? 'not yet' : 'off' };
  let upgradeUnread = false, upgradeProbe = null, queuedEvents = 0;
  /// The refusal of a protocol version the verifier does not implement: the code that only the
  /// verifier's wrapper (proof-verifier.mjs) and the SDK's own version check set. Never the words:
  /// a gateway can send any words.
  const outdatedError = (error) => typeof error === 'object' && error !== null && error.code === 'UPGRADE_REQUIRED';
  /// The version the verifier named, if the refusal is exactly its own sentence. Digits only.
  const refusedVersion = (text) => /^UPGRADE_REQUIRED: the network runs protocol version ([1-9][0-9]{0,19}); /.exec(String(text))?.[1] ?? null;

  // ---- the store
  const empty = () => ({ format: STORE_FORMAT, network: null, snapshots: {}, seen: {}, taken: {}, queues: {}, dead: {}, blind: {}, refusing: {}, upgrade: { capable: false, plan: null, unanswered: null, told_unanswered: null, told_answered: null } });
  /// What the store remembers about upgrades, in the one form this code uses. Anything else (a
  /// store edited by hand, or written by a build that kept it otherwise) is the default: nothing
  /// learned, no plan announced. A malformed field must never stop the account checks.
  /// - `capable`: a node of this network has answered the question (a network that does not
  ///   declare it);
  /// - `plan`: the plan the owners were last told about;
  /// - `unanswered`: the episode in which the question is not answered, `{since, answers}`, with
  ///   the retries answered in a row since the last unanswered one;
  /// - `told_unanswered`: when the owners were last told that it is unanswered (kept across a
  ///   forgotten answer, so that they are not told twice in 24 hours);
  /// - `told_answered`: the `told_unanswered` that the last "answered again" belonged to.
  function upgradeMemory(value) {
    const blank = { capable: false, plan: null, unanswered: null, told_unanswered: null, told_answered: null };
    if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.capable !== 'boolean') return blank;
    const p = value.plan, u = value.unanswered;
    const plan = p && typeof p === 'object' && !Array.isArray(p) && ['key', 'version', 'spec', 'starts'].every((field) => typeof p[field] === 'string') && /^[1-9][0-9]{0,19}$/.test(p.version) && typeof p.known === 'boolean'
      ? { key: p.key, version: p.version, spec: p.spec, starts: p.starts, known: p.known } : null;
    const count = (n) => (Number.isSafeInteger(n) && n >= 0 ? n : null);
    const unanswered = value.capable && u && typeof u === 'object' && count(u.since) !== null ? { since: u.since, answers: Math.min(count(u.answers) ?? 0, UPGRADE_ANSWERS_TO_RESTORE - 1) } : null;
    return { capable: value.capable, plan, unanswered, told_unanswered: count(value.told_unanswered), told_answered: count(value.told_answered) };
  }
  /// Older formats are brought to this one. A format-1 store names no network: its snapshots must
  /// agree on one genesis (and network, where they name it), which the store then belongs to.
  /// The memory of upgrades is taken only in its expected form (`upgradeMemory`); older formats
  /// have none.
  function migrate(saved) {
    if (!saved) return empty();
    if (![1, 2, STORE_FORMAT].includes(saved.format)) throw new Error('The watch store has an unknown format');
    if (saved.format === STORE_FORMAT) return { ...empty(), ...saved, upgrade: upgradeMemory(saved.upgrade) };
    const next = { ...empty(), snapshots: saved.snapshots || {}, network: saved.network || null, dead: saved.dead || {}, blind: saved.blind || {} };
    // Events already produced: format 1 kept delivered ids per account, format 2 seen ids per account.
    next.seen = saved.format === 1 ? (saved.delivered || {}) : (saved.seen || {});
    const pending = saved.format === 1 ? (saved.outbox || []) : Object.values(saved.queues || {}).flat();
    for (const event of pending) (next.seen[event.account] ||= []).includes(event.id) || next.seen[event.account].push(event.id);
    next.orphans = pending; // queued again below, to the targets that want them
    if (!next.network) {
      const snaps = Object.values(next.snapshots);
      const geneses = new Set(snaps.map((s) => s.genesis_time_micros)), networks = new Set(snaps.map((s) => s.network_id).filter(Boolean));
      if (geneses.size > 1 || networks.size > 1) {
        next.reset = 'the snapshots of the old store disagree on the network';
        next.snapshots = {};
      } else if (geneses.size === 1) next.network = { network_id: [...networks][0] ?? null, genesis_time_micros: [...geneses][0] };
    }
    return next;
  }
  let loading = null;
  /// Loads the store once; concurrent callers wait for the same load.
  function load() { loading ??= loadOnce(); return loading; }
  async function loadOnce() {
    startedAt ??= now();
    let saved = null, lost = null;
    try { saved = await store.get(); } catch (error) {
      // /health gets a fixed text: a parser's message may quote the store, which names accounts.
      lost = error.lost || 'its records were damaged and set aside';
      status.store_error = 'the store was unreadable or missing; the watch started afresh and may send some events again';
      log('error', 'watch store unreadable or missing: starting afresh; owners are told', { error: error.message });
    }
    data = migrate(saved);
    if (forgetUpgradeAnswer && (data.upgrade.capable || data.upgrade.unanswered)) { data.upgrade.capable = false; data.upgrade.unanswered = null; log('info', 'forgot that a node of this network answered the upgrade question: owners are not told that it is unanswered until a node has answered it again'); }
    if (data.reset) { lost = data.reset; status.store_error = 'the old store was set aside: its snapshots disagree on the network'; log('error', 'old store set aside: its snapshots disagree on the network'); delete data.reset; }
    for (const t of targets) { data.queues[t.id] ||= []; data.dead[t.id] ||= []; data.taken[t.id] ||= []; }
    // Queues of targets no longer configured: what they still held goes to the targets that now
    // serve the same accounts and have not had it; nothing goes to a receiver of other accounts.
    const orphans = [...(data.orphans || [])]; delete data.orphans;
    let dropped = 0;
    for (const id of Object.keys(data.queues)) {
      if (wants.has(id)) continue;
      dropped += data.queues[id].length; orphans.push(...data.queues[id]);
      delete data.queues[id]; delete data.taken[id]; delete data.dead[id]; delete data.refusing[id];
    }
    let moved = 0;
    for (const event of orphans) moved += queueTo(event);
    if (dropped) log('warn', 'queues of targets no longer configured were removed', { events: dropped, requeued: moved });
    if (lost) for (const account of ids) memoryLost(account, lost);
    // Written at once, before any poll: a new store exists from the first moment (so a missing one
    // later means lost memory), and the notices of a reset survive a crash during the first poll.
    await persist();
    if (lost) kick();
    return data;
  }
  /// Writes are serialized, and a write asked for while one is waiting is the same write.
  function persist() {
    if (queuedWrite) return queuedWrite;
    queuedWrite = writing.then(async () => {
      queuedWrite = null;
      try { await store.put(data); if (status.store_error?.startsWith('write')) status.store_error = null; } catch (error) {
        status.store_error = `write failed (${error.code || 'error'})`;
        log('error', 'watch store write failed: a restart may resend or miss events', { error: error.message });
      }
    });
    writing = queuedWrite;
    return queuedWrite;
  }

  // ---- queuing and delivering
  const remember = (list, id) => { list.push(id); if (list.length > keepSeen) list.splice(0, list.length - keepSeen); };
  /// Queues `event` to every target that wants its account and has not had it. Returns how many.
  function queueTo(event, only = () => true) {
    let count = 0;
    for (const t of targets) {
      if (!wanted(t.id, event.account) || !only(t.id)) continue;
      const taken = data.taken[t.id];
      if (taken.includes(event.id)) continue;
      remember(taken, event.id);
      const queue = data.queues[t.id];
      queue.push(event); count += 1;
      if (queue.length > maxQueue) { const dropped = queue.splice(0, queue.length - maxQueue); log('error', 'delivery queue full: oldest events dropped', { target: t.id, dropped: dropped.length }); }
    }
    return count;
  }
  /// A new event of a comparison: produced once per account, queued once per target.
  function enqueue(event, only) {
    const seen = (data.seen[event.account] ||= []);
    if (seen.includes(event.id)) return false;
    remember(seen, event.id);
    queueTo(event, only);
    queuedEvents += 1;
    return true;
  }
  function memoryLost(account, why) {
    const at = now();
    enqueue({ id: `${account}:watch_memory_lost:${at}`, account, type: 'watch_memory_lost', at_height: null, chain_time: null, urgent: true, reason: why,
      message: `The alert service for your account ${account} lost its memory at ${new Date(at).toISOString().replace('T', ' ').slice(0, 16)} UTC (${why}). Alerts that were waiting to be sent may be lost: check your account's waiting payments, raises of the limit and replacements of keys in your wallet now.` });
  }
  const accountsOf = (targetId) => (wants.get(targetId) ? [...wants.get(targetId)] : ids);
  /// How long a target may rest: never more than the allowed lag of the accounts it serves.
  const restCap = (targetId) => Math.min(rest.maxMs, ...accountsOf(targetId).map((a) => allowedLagSeconds(data.snapshots[a]) * 1000));
  /// `newRound`: a poll starts a new round, in which each queued event gets one attempt per target.
  function kick(newRound = false) { for (const t of targets) { if (newRound) pumps.get(t.id).attempted = new Set(); pumpOne(t); } }
  function pumpOne(target) {
    const p = pumps.get(target.id);
    if (stopper.signal.aborted) return p.running;
    // A kick while the pump runs (an event queued as it finishes) gets one more pass after it.
    if (p.running) { p.again = true; return p.running; }
    // Resting: only urgent events never tried yet may go, one attempt each (a probe).
    const resting = now() < p.openUntil;
    if (resting && !data.queues[target.id].some((e) => e.urgent && !p.tried.has(e.id))) return null;
    p.again = false;
    p.running = drain(target, p, resting).catch((error) => log('error', 'delivery pump crashed', { target: target.id, error: error.message })).finally(() => {
      p.running = null;
      if (p.again) { p.again = false; pumpOne(target); }
    });
    return p.running;
  }
  async function drain(target, p, probing) {
    while (!stopper.signal.aborted) {
      const attempted = p.attempted; // one attempt per event per round; a round starts at each poll
      const queue = data.queues[target.id];
      // Defence: an event for an account this target does not serve never leaves (and is dropped).
      const foreign = queue.filter((e) => !wanted(target.id, e.account));
      if (foreign.length) { data.queues[target.id] = queue.filter((e) => wanted(target.id, e.account)); log('error', 'events for other accounts removed from a queue', { target: target.id, events: foreign.length }); persist(); continue; }
      const event = queue.find((e) => !attempted.has(e.id) && (!probing || (e.urgent && !p.tried.has(e.id))));
      if (!event) return;
      attempted.add(event.id);
      const first = !p.tried.has(event.id);
      try {
        await target.adapter.deliver(clone(event), { first, signal: stopper.signal });
      } catch (error) {
        if (stopper.signal.aborted) return;
        p.tried.add(event.id);
        if (error.permanent) {
          data.queues[target.id] = data.queues[target.id].filter((e) => e.id !== event.id);
          const dead = data.dead[target.id]; dead.push({ event, error: error.message, at: now() });
          if (dead.length > maxDead) dead.splice(0, dead.length - maxDead);
          log('error', 'receiver gave up on this subscription (410): event kept in dead letters', { target: target.id, event: event.id });
          persist();
          continue;
        }
        if (error.refused) refusing(target, event, error);
        p.failures += 1;
        log('warn', 'delivery failed; tried again at the next poll', { target: target.id, event: event.id, error: error.message });
        if (p.failures >= rest.failures) {
          const ms = Math.min(p.backoffMs, restCap(target.id));
          p.openUntil = now() + ms;
          log('warn', 'target resting after repeated failures', { target: target.id, seconds: Math.round(ms / 1000) });
          p.backoffMs = Math.min(p.backoffMs * 2, rest.maxMs);
          return;
        }
        if (probing) return;
        continue;
      }
      data.queues[target.id] = data.queues[target.id].filter((e) => e.id !== event.id);
      p.tried.delete(event.id); p.failures = 0; p.backoffMs = rest.baseMs; p.openUntil = 0;
      if (data.refusing[target.id]) { delete data.refusing[target.id]; log('info', 'a receiver accepts events again', { target: target.id }); }
      probing = false; // the target answers: back to normal delivery
      persist();
    }
  }
  /// A receiver answers 4xx: it cannot (or will not) take the events. They stay queued and are
  /// retried; once per episode the owners are told, through every other target, urgently.
  function refusing(target, event, error) {
    if (data.refusing[target.id]) return;
    data.refusing[target.id] = { since: event.id };
    const where = target.adapter.origin ? ` (${target.adapter.origin})` : '';
    for (const account of accountsOf(target.id)) {
      enqueue({ id: `${account}:alerts_refused:${target.id}:${event.id}`, account, type: 'alerts_refused', at_height: event.at_height ?? null, chain_time: event.chain_time ?? null, urgent: true, target: target.id,
        message: `Your alert endpoint${where} refuses the alerts this watch sends for account ${account} (${error.message.replace(/^webhook \S+ /, '')}). Until it accepts them you are not told there: check its clock, its secret and its address. This watch keeps the alerts and tries again.` },
      (id) => id !== target.id);
    }
    log('error', 'a receiver refuses events: owners told through the other targets', { target: target.id });
    persist(); kick();
  }

  // ---- reading
  const chainMsOf = (snapshot) => Number((BigInt(snapshot.genesis_time_micros) + BigInt(snapshot.elapsed)) / 1000n);
  /// How old the state of an account may be when read: at most half its delay, so that the owner
  /// still has half the wait to act on something that started just after the last look.
  function allowedLagSeconds(snapshot) {
    const delay = snapshot?.security ? Number(snapshot.security.policy.delay_seconds) : Infinity;
    return Math.max(1, Math.min(maxLagSeconds, delay / 2));
  }
  const fail = (report, account, reason, detail) => { problems[account] = { reason, detail }; report.failed.push(account); };
  const sameNetwork = (stored, seen) => stored.genesis_time_micros === seen.genesis_time_micros && (!stored.network_id || stored.network_id === seen.network_id);

  /// One verified read of a batch of accounts, with or without the upgrade question.
  const readBatch = async (batch, question) => {
    const answer = await withTimeout(verifiedState({ ids: batch, include_security: true, ...(question ? { include_upgrade: true } : {}) }), batchTimeoutMs, stopper.signal);
    if (answer?.verified !== true || !answer.state) throw new Error('The state was not verified');
    return answer;
  };
  async function check(batch, report) {
    let verified;
    try {
      // The upgrade question rides on the account checks only on a network whose trust data
      // declares that its nodes answer it: there a check without the proven entry fails. On any
      // other network it is asked apart (probeUpgrade) and can neither delay nor fail a check.
      verified = await readBatch(batch, upgradeDeclared);
      // A state without the entry it was asked for proves nothing about upgrades: the check failed.
      if (upgradeDeclared && !report.upgrade) report.upgrade = upgradeOf(verified.state);
    } catch (error) {
      // The network runs a protocol version this watch does not implement: no gateway can change
      // that answer, and the owners are told at this poll (judge), not after the allowed lag.
      const outdated = outdatedError(error);
      for (const account of batch) fail(report, account, outdated ? 'outdated' : 'unreachable', error.message);
      if (outdated) log('error', 'the network runs a protocol version this watch does not implement: it sees no account until it is updated', { accounts: batch.length, error: error.message });
      else log('warn', 'poll failed; these accounts are checked again at the next poll', { accounts: batch.length, error: error.message });
      return Boolean(error.timeout);
    }
    const state = verified.state, network = { network_id: state.network_id, genesis_time_micros: String(state.genesis.genesis_time_micros) };
    if (!data.network) data.network = network;
    if (report.upgrade && !report.upgradeNoted && sameNetwork(data.network, network)) {
      report.upgradeNoted = true; status.upgrade_read = 'ok';
      // Whatever goes wrong in telling of a plan must not stop the account checks below.
      try { noteUpgrade(report.upgrade); } catch (error) { log('error', 'the upgrade status could not be compared with what was announced', { error: error.message }); }
    }
    if (!sameNetwork(data.network, network)) {
      for (const account of batch) fail(report, account, 'network_mismatch');
      log('error', 'the store belongs to another network or genesis: the operator must check the data directory', { stored: String(data.network.network_id ?? '').slice(0, 16), seen: network.network_id.slice(0, 16) });
      return false;
    }
    data.network.network_id ??= network.network_id;
    const lag = Math.max(0, Math.round((now() - Number(BigInt(state.time_micros) / 1000n)) / 1000));
    report.lag_seconds = Math.max(report.lag_seconds ?? 0, lag);
    for (const account of batch) {
      // A state whose clock of the waits cannot be read (a setting or a total of stops in a form the engine does not
      // write) is not judged: the account counts as not seen at this poll, and the operator is told.
      let snapshot;
      try { snapshot = snapshotOf(verified, account); } catch (error) { fail(report, account, 'unreachable', error.message); log('error', 'the verified state cannot be read on the clock of the waits; the account is not judged on it', { account, error: error.message }); continue; }
      if (!snapshot) { fail(report, account, 'not_found'); log('warn', 'account not found in verified state', { account }); continue; }
      const previous = data.snapshots[account] || null;
      if (previous && BigInt(snapshot.height) < BigInt(previous.height)) {
        fail(report, account, 'store_ahead');
        log('error', 'the chain is behind what the store saw: an old gateway, a re-genesis or a restored store', { account, stored: previous.height, seen: snapshot.height });
        continue;
      }
      for (const event of diffSecurity(previous, snapshot, { reminderSeconds })) if (enqueue(event)) report.found += 1;
      // The upgrade signal of the account's validator, from the same verified read (it carries the upgrade entry
      // on a network that declares that its nodes report upgrades; on any other network the account check does
      // not, and nothing is said about signals). It comes after the security alerts and cannot hold them back:
      // whatever goes wrong in comparing it is logged, and the account counts as checked.
      try { for (const event of diffSignal(previous, snapshot)) if (enqueue(event)) report.found += 1; }
      catch (error) { log('error', 'the upgrade signal of an account could not be compared with what was seen before', { account, error: error.message }); }
      // A read without the upgrade entry says nothing about the signal: what was read before stays what is known.
      if (snapshot.signal === undefined && previous && previous.signal !== undefined) snapshot.signal = previous.signal;
      data.snapshots[account] = snapshot;
      report.checked += 1;
      const allowed = allowedLagSeconds(snapshot);
      // Above a quarter of the delay, one late or failed poll leaves less than half the wait.
      if (snapshot.security && intervalMs / 1000 > Number(snapshot.security.policy.delay_seconds) / 4 && !warned.has(account)) {
        warned.add(account); status.config_warnings = warned.size;
        log('warn', 'poll_seconds is longer than a quarter of the delay of a watched account: one failed poll can leave its owner less than half the wait', { poll_seconds: intervalMs / 1000, delay_seconds: Number(snapshot.security.policy.delay_seconds) });
      }
      if (lag > allowed) {
        fail(report, account, 'stale', { seconds: lag, newest: utc(snapshot.genesis_time_micros, snapshot.elapsed) });
        report.stale = true;
        log('warn', 'verified state is older than this account allows: the chain or the gateway is behind', { account, lag_seconds: lag, allowed_seconds: allowed });
      } else delete problems[account];
    }
    return false;
  }

  /// Tells owners whose account this watch cannot see well enough, and when it can again.
  function judge(atPoll) {
    if (!data) return 0;
    const at = now();
    let blindCount = 0;
    for (const account of ids) {
      const snapshot = data.snapshots[account], problem = problems[account];
      const lastView = snapshot ? chainMsOf(snapshot) : startedAt;
      // At a poll the view must be within the allowed lag; between polls (the watchdog) it ages by
      // up to one interval honestly, which is allowed on top.
      const lagging = at - lastView > allowedLagSeconds(snapshot) * 1000 + (atPoll ? 0 : intervalMs);
      const outdated = problem?.reason === 'outdated';
      const broken = problem && ['not_found', 'store_ahead', 'network_mismatch', 'outdated'].includes(problem.reason);
      const height = snapshot?.height ?? '0', since = snapshot ? utc(snapshot.genesis_time_micros, snapshot.elapsed) : null;
      if (lagging || broken) {
        blindCount += 1;
        // One message per episode. An episode that began for another reason and turns out to be
        // an upgrade this watch does not implement is said once more, as what it is.
        if (data.blind[account] && !(outdated && data.blind[account].reason !== 'outdated')) continue;
        if (outdated) {
          data.blind[account] = { height, reason: 'outdated' };
          const version = refusedVersion(problem.detail);
          enqueue({ id: `${account}:watch_outdated:h${height}`, account, type: 'watch_outdated', at_height: height, chain_time: since, urgent: true, reason: 'outdated', ...(version ? { version } : {}),
            message: `This watch can no longer see your account ${account}: the network has moved to ${version ? `version ${version} of its rules` : 'a newer version of its rules'}, and this watch has not been updated for it. ${since ? `The newest state of your account that it could verify is from ${since}.` : 'It has not been able to verify any state of your account yet.'} Until whoever runs this watch updates it, you are not told what waits on your account: check it yourself in your wallet.` });
          log('error', 'an account cannot be seen until this watch is updated: owner told', { reason: 'outdated' });
          continue;
        }
        const reason = problem?.reason || (atPoll ? 'unreachable' : 'overdue');
        const words = {
          unreachable: 'the network gateway did not answer its last checks',
          stale: `the network gateway answers, but only with old state (the newest is from ${problem?.detail?.newest ?? since})`,
          overdue: 'its checks of the network have stopped completing',
          not_found: 'the account is not on the chain this watch reads',
          store_ahead: 'its records are ahead of the chain it reads',
          network_mismatch: 'its records belong to another network',
        };
        // One episode, one id: the last height seen when it began.
        data.blind[account] = { height, reason };
        enqueue({ id: `${account}:watch_blind:h${height}`, account, type: 'watch_blind', at_height: height, chain_time: since, urgent: true, reason,
          message: `This watch cannot see your account ${account} at the moment: ${words[reason] || words.unreachable}. ${since ? `The newest state of it that it could verify is from ${since}.` : 'It has not been able to verify any state of it yet.'} Something could be waiting on your account without you being told: check it yourself in your wallet until this watch says it sees the account again.` });
        log('error', 'an account is not seen well enough: owner told', { reason });
      } else if (data.blind[account] && atPoll && !problem && snapshot && BigInt(snapshot.height) > BigInt(data.blind[account].height)) {
        // Restored only by a fresh view from a poll, not by the clock.
        const was = data.blind[account]; delete data.blind[account];
        enqueue({ id: `${account}:watch_restored:h${was.height}`, account, type: 'watch_restored', at_height: height, chain_time: since, urgent: false,
          message: `This watch sees your account ${account} again, as of ${since}. Whatever changed meanwhile is in the messages that come with this one.` });
      }
    }
    return blindCount;
  }

  const dateOf = (genesisTimeMicros, elapsedMicros) => { try { return utc(genesisTimeMicros, elapsedMicros); } catch { return 'a date beyond the calendar'; } };
  /// What a proven upgrade status (`{version, scheduled, known}`) means for the owners, compared
  /// with the plan this watch last told them about (kept in the store):
  /// - a plan they were not told about: `upgrade_scheduled`, once. Its id names the version, the
  ///   specification, the start and the time it was scheduled, so a plan that is cancelled and
  ///   scheduled again with the same start is a new plan;
  /// - while this build does not implement the scheduled version: `watch_outdated`, once a day;
  /// - this build implements it now and did not when the plan was announced: `watch_ready`, once;
  /// - the plan is gone and the version in force is still below it: `upgrade_cancelled`, once.
  /// Synchronous: it only queues. Returns nothing; the caller persists and starts delivery.
  function noteUpgrade(found) {
    const plan = found?.scheduled ?? null, before = data.upgrade.plan;
    status.upgrade_scheduled = plan ? String(plan.version) : null; status.upgrade_known = plan ? found.known === true : null;
    if (!data.network) return;
    if (!plan) {
      if (!before) return;
      data.upgrade.plan = null;
      // The version in force reached the plan's: it was activated, not cancelled.
      if (BigInt(found.version) >= BigInt(before.version)) return;
      for (const account of ids) {
        enqueue({ id: `${account}:upgrade_cancelled:${before.key}`, account, type: 'upgrade_cancelled', at_height: null, chain_time: null, urgent: false, version: before.version, spec: before.spec, starts: before.starts,
          message: `The change of the rules of your account ${account}'s network to version ${before.version}, which was scheduled for ${before.starts}, has been cancelled: too few validators still support it. The network stays on version ${found.version}. You need to do nothing.` });
      }
      log('info', 'the scheduled protocol version was cancelled: owners told', { version: before.version });
      return;
    }
    const version = String(plan.version), known = found.known === true;
    const starts = dateOf(data.network.genesis_time_micros, plan.activate_elapsed_micros);
    const key = `v${version}:${String(plan.spec).slice(0, 16)}:${plan.activate_elapsed_micros}:${plan.scheduled_elapsed_micros}`;
    // Another plan took the place of the one the owners know without a look in between.
    if (before && before.key !== key) {
      for (const account of ids) {
        enqueue({ id: `${account}:upgrade_cancelled:${before.key}`, account, type: 'upgrade_cancelled', at_height: null, chain_time: null, urgent: false, version: before.version, spec: before.spec, starts: before.starts,
          message: `The change of the rules of your account ${account}'s network to version ${before.version}, which was scheduled for ${before.starts}, has been cancelled. Another one is scheduled; see the message that comes with this one.` });
      }
    }
    const becameReady = before && before.key === key && before.known === false && known;
    const day = Math.floor(now() / 86_400_000);
    for (const account of ids) {
      enqueue({ id: `${account}:upgrade_scheduled:${key}`, account, type: 'upgrade_scheduled', at_height: null, chain_time: null, urgent: false, version, spec: plan.spec, starts, known,
        message: `The network of your account ${account} has scheduled a change of its rules: version ${version} starts on ${starts}. ${known ? 'This watch is ready for it and keeps watching.' : 'This watch has not been updated for that version. If it is not updated by then, it stops seeing your account at that time; it will tell you when that happens.'} Your wallet has to be up to date by then as well.` });
      if (!known) enqueue({ id: `${account}:watch_outdated:${key}:day${day}`, account, type: 'watch_outdated', at_height: null, chain_time: null, urgent: false, reason: 'scheduled', version, starts,
        message: `This watch does not implement version ${version} of the network's rules, which starts on ${starts}. From then on it cannot see your account ${account} until whoever runs it installs a newer version. If that has not happened by then, check your account yourself in your wallet.` });
      if (becameReady) enqueue({ id: `${account}:watch_ready:${key}`, account, type: 'watch_ready', at_height: null, chain_time: null, urgent: false, version, starts,
        message: `This watch has been updated: it now implements version ${version} of the network's rules, which starts on ${starts}, and keeps watching your account ${account} across the change.` });
    }
    if (!known) log('warn', 'a protocol version this watch does not implement is scheduled: update the watch before it starts', { version, starts });
    data.upgrade.plan = { key, version, spec: plan.spec, starts, known };
  }
  /// On a network that does not declare it, the question was not answered (refused, held to the
  /// time limit, or answered without the proven entry). Returns nothing; the caller persists.
  function questionUnanswered(error) {
    status.upgrade_scheduled = null; status.upgrade_known = null;
    // No node of this network has ever answered (a network on older nodes): logged once, shown
    // on /health, and nothing is said to the owners. No answer is not "nothing scheduled".
    if (!data.upgrade.capable) {
      if (!upgradeUnread) log('warn', 'the upgrade status could not be read: no notice of a scheduled upgrade until it can', { error: String(error?.message ?? error) });
      upgradeUnread = true; status.upgrade_read = 'failing';
      return;
    }
    // A node answered before. The episode begins, or its count of answers in a row starts again.
    const at = now();
    if (!data.upgrade.unanswered) {
      data.upgrade.unanswered = { since: at, answers: 0 };
      log('error', 'the upgrade question is not answered though it was before: no notice of a scheduled upgrade until it is; owners are told at most once in 24 hours (if the network\'s nodes no longer answer it, start the watch once with --forget-upgrade-answer)', { error: String(error?.message ?? error) });
    } else data.upgrade.unanswered.answers = 0;
    status.upgrade_read = 'unanswered';
    const told = data.upgrade.told_unanswered;
    if (told !== null && at >= told && at - told < UPGRADE_TELL_AGAIN_MS) return;
    data.upgrade.told_unanswered = at;
    for (const account of ids) {
      enqueue({ id: `${account}:upgrade_question_unanswered:${at}`, account, type: 'upgrade_question_unanswered', at_height: null, chain_time: null, urgent: false,
        message: `This message is only about scheduled changes of the network's rules, not about what this watch sees of your account ${account}. The network gateway does not answer this watch's question about such changes, which it answered before, so this watch cannot tell you of one for now. Your wallet shows a scheduled change if there is one. Whoever runs this watch should find out why. While this lasts you get this message at most once a day.` });
    }
  }
  /// The question was answered. During an episode the answer is used at once (a plan is
  /// announced), but the episode ends only with UPGRADE_ANSWERS_TO_RESTORE answers in a row.
  function questionAnswered(found) {
    upgradeUnread = false; data.upgrade.capable = true;
    const episode = data.upgrade.unanswered;
    if (episode && (episode.answers += 1) >= UPGRADE_ANSWERS_TO_RESTORE) {
      data.upgrade.unanswered = null;
      // "Answered again" goes only to owners whose last word about it was "unanswered", once.
      const told = data.upgrade.told_unanswered;
      if (told !== null && data.upgrade.told_answered !== told) {
        data.upgrade.told_answered = told;
        for (const account of ids) {
          enqueue({ id: `${account}:upgrade_question_answered:${told}`, account, type: 'upgrade_question_answered', at_height: null, chain_time: null, urgent: false,
            message: `This message is only about scheduled changes of the network's rules, not about what this watch sees of your account ${account}. The network gateway answers this watch's question about such changes again, so this watch can tell you of one. If one was scheduled meanwhile, a message about it comes with this one.` });
        }
      }
      log('info', 'the upgrade question is answered again');
    }
    status.upgrade_read = data.upgrade.unanswered ? 'unanswered' : 'ok';
    try { noteUpgrade(found); } catch (error) { log('error', 'the upgrade status could not be compared with what was announced', { error: error.message }); }
  }
  /// On a network that does not declare that its nodes report upgrades: asks the question with
  /// `upgradeStatus()`, apart from the account checks, after the poll has stored and sent what it
  /// found. Nothing waits for it, and one runs at a time, so a held question holds only itself.
  function probeUpgrade() {
    if (!upgradeStatus || upgradeProbe || stopper.signal.aborted) return;
    upgradeProbe = (async () => {
      const before = JSON.stringify(data.upgrade), queuedBefore = queuedEvents;
      let found = null;
      try {
        found = await withTimeout(Promise.resolve().then(upgradeStatus), batchTimeoutMs, stopper.signal, 'the upgrade question');
        if (!found || typeof found !== 'object' || typeof found.version !== 'string') { found = null; throw new Error('the upgrade status has an unexpected form'); }
      } catch (error) {
        if (stopper.signal.aborted) return;
        // After an activation the account checks meet the same refusal and tell the owners.
        if (outdatedError(error)) { upgradeUnread = true; status.upgrade_read = 'failing'; status.upgrade_scheduled = null; status.upgrade_known = null; return; }
        questionUnanswered(error);
      }
      if (found) questionAnswered(found);
      if (JSON.stringify(data.upgrade) !== before || queuedEvents !== queuedBefore) { await persist(); kick(); }
    })().catch((error) => log('error', 'the upgrade question crashed', { error: error.message })).finally(() => { upgradeProbe = null; });
  }

  async function pollOnce() {
    await load();
    const report = { checked: 0, found: 0, failed: [], stale: false, lag_seconds: null, blind: 0 };
    status.last_poll_at = now();
    let skip = false;
    for (const batch of batches(ids)) {
      if (stopper.signal.aborted) break;
      // After a batch timed out the gateway is taken as down for the rest of this poll.
      if (skip) { for (const account of batch) fail(report, account, 'unreachable', 'skipped after a timeout'); continue; }
      skip = await check(batch, report);
    }
    report.blind = judge(true);
    lastPollEnd = now();
    await persist();
    kick(true);
    status.lag_seconds = report.lag_seconds;
    if (report.failed.length === 0) status.last_success_at = status.last_poll_at;
    // On a network that declares it, the question rode on the account checks and none answered it.
    if (upgradeDeclared && !report.upgradeNoted) status.upgrade_read = 'failing';
    // Only now, with everything found stored and on its way: the upgrade question, on its own.
    probeUpgrade();
    delete report.upgrade; delete report.upgradeNoted;
    return report;
  }
  /// One poll. Polls never overlap: a call during a poll waits for it. Delivery is not awaited.
  function poll() {
    running ??= pollOnce().finally(() => { running = null; });
    return running;
  }
  /// Between polls: when a poll is overdue (stuck, or the loop stopped), judge the accounts anyway.
  function watch() {
    if (!data) return;
    const quiet = now() - (status.last_success_at ?? startedAt ?? now());
    const limit = watchdogMs ?? Math.max(60000, 3 * intervalMs);
    status.alarm = quiet > limit;
    if (status.alarm) log('error', 'no successful poll for a while', { seconds: Math.round(quiet / 1000) });
    const overdue = now() - (lastPollEnd ?? startedAt) > intervalMs + 10000;
    if (overdue && judge(false)) { persist(); kick(); }
  }
  const sum = (lists) => Object.values(lists || {}).reduce((n, list) => n + list.length, 0);
  return {
    poll,
    /// Polls now and then every `ms` after the end of the previous poll; a watchdog runs between polls.
    start(ms) {
      if (!stopped || stopper.signal.aborted) return; stopped = false; intervalMs = ms;
      const loop = async () => {
        try { await poll(); } catch (error) { log('error', 'poll crashed', { error: error.message }); }
        if (!stopped) timer = setTimeout(loop, intervalMs);
      };
      watchdog = setInterval(watch, Math.min(intervalMs, 10000));
      loop();
    },
    /// Stops polling and delivery (an attempt in flight is aborted) and writes the store once more.
    async stop() {
      stopped = true; clearTimeout(timer); clearInterval(watchdog);
      stopper.abort();
      await Promise.allSettled([running, upgradeProbe, ...[...pumps.values()].map((p) => p.running)]);
      if (data) await persist();
    },
    /// For /health: counts only, no account ids.
    status: () => ({
      ...clone(status), accounts: ids.length, failing: Object.keys(problems).length, blind: data ? Object.keys(data.blind).length : 0,
      outdated: Object.values(problems).filter((p) => p.reason === 'outdated').length,
      queued: data ? sum(data.queues) : 0, dead_letters: data ? sum(data.dead) : 0,
      resting_targets: [...pumps.values()].filter((p) => now() < p.openUntil).length,
      refusing_targets: data ? Object.keys(data.refusing).length : 0,
    }),
    /// For the operator, in process: which accounts fail and why, queues per target, dead letters.
    details: () => ({
      failed_accounts: Object.keys(problems), problems: clone(problems), blind_accounts: data ? Object.keys(data.blind) : [],
      last_heights: data ? Object.fromEntries(Object.entries(data.snapshots).map(([a, s]) => [a, s.height])) : {},
      queues: data ? Object.fromEntries(Object.entries(data.queues).map(([t, q]) => [t, q.length])) : {}, dead: clone(data?.dead || {}),
      refusing: clone(data?.refusing || {}),
    }),
    /// Waits until every target's pump is idle (for tests and for a clean stop).
    settled: async () => {
      await upgradeProbe;
      for (let i = 0; i < 100 && [...pumps.values()].some((p) => p.running); i++) await Promise.allSettled([...pumps.values()].map((p) => p.running));
      await writing;
    },
    snapshot: async (account) => clone((await load()).snapshots[account] || null),
  };
}

// ------------------------------------------------------------------ webhook adapter
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
/// Webhooks are HTTPS. Plain HTTP only to this machine, for tests. No credentials in the URL.
export function checkWebhookURL(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('The webhook is not a URL'); }
  if (url.username || url.password) throw new Error('A webhook URL carries no user name or password');
  if (url.protocol === 'https:') return url;
  if (url.protocol === 'http:' && LOOPBACK.has(url.hostname)) return url;
  throw new Error('A webhook must be an https:// URL (http:// only for localhost)');
}
export const SIGNATURE_HEADER = 'x-watch-signature';
export const EVENT_HEADER = 'x-watch-event';
/// The signature header: "t=<unix seconds>,sha256=<hex>", the HMAC-SHA256 under the secret of
/// "t=<unix seconds>,id=<event id>." followed by the exact body.
export function signWebhook(body, eventId, secret, unixSeconds) {
  const t = String(Math.floor(unixSeconds));
  return `t=${t},sha256=${createHmac('sha256', secret).update(`t=${t},id=${eventId}.`).update(body).digest('hex')}`;
}
/// For receivers: true if the request is a fresh delivery signed with `secret`. `headers` holds
/// x-watch-signature and x-watch-event (a plain object with lower-case names, or a Headers);
/// `body` is the raw body. A signature older (or further ahead) than `maxAgeSeconds` is refused,
/// so a captured request cannot be replayed later; within that time, drop ids already seen.
/// Answer 401 when this returns false: the watch retries, so a receiver whose clock is fixed gets
/// the event. Answer 410 only to end the subscription: the watch then stops sending that event.
export function verifyWebhookSignature(body, headers, secret, { maxAgeSeconds = 300, now = Date.now } = {}) {
  const header = (name) => (typeof headers?.get === 'function' ? headers.get(name) : headers?.[name]);
  const signature = header(SIGNATURE_HEADER), eventId = header(EVENT_HEADER);
  const match = typeof signature === 'string' && /^t=([0-9]{1,12}),sha256=([0-9a-f]{64})$/.exec(signature);
  if (!match || typeof eventId !== 'string' || !eventId) return false;
  if (Math.abs(now() / 1000 - Number(match[1])) > maxAgeSeconds) return false;
  const expected = Buffer.from(signWebhook(body, eventId, secret, Number(match[1]))), given = Buffer.from(signature);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return false;
  try { return JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') : String(body)).id === eventId; } catch { return false; }
}
/// POSTs each event as JSON, signed with the subscription's secret and the time of the attempt.
/// The first delivery of an event retries a failure that may pass (no answer, 408, 429, 5xx) with
/// backoff: 1 s, 2 s, 4 s by default; later deliveries try once. Another 4xx is a refusal: the
/// event stays queued (the watch retries it at its own pace and tells the owner). Only 410 Gone
/// is final. The answer's body is never read.
export function webhookAdapter({ url, secret, fetcher = globalThis.fetch, attempts = 4, baseDelayMs = 1000, timeoutMs = 10000, sleep = sleeping, now = Date.now }) {
  const target = checkWebhookURL(url);
  if (typeof secret !== 'string' || secret.length < 16) throw new Error('A webhook needs a secret of at least 16 characters');
  return {
    name: 'webhook',
    /// Where events go, without path or query (which may carry a token): safe to log.
    origin: target.origin,
    async deliver(event, { first = true, signal } = {}) {
      const body = JSON.stringify(event);
      let last;
      const tries = first ? attempts : 1;
      for (let attempt = 0; attempt < tries; attempt++) {
        if (attempt > 0) { await sleep(baseDelayMs * 2 ** (attempt - 1), signal); if (signal?.aborted) break; }
        const headers = { 'content-type': 'application/json', [EVENT_HEADER]: event.id, [SIGNATURE_HEADER]: signWebhook(body, event.id, secret, now() / 1000) };
        const limit = signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
        try {
          const response = await fetcher(target.href, { method: 'POST', headers, body, redirect: 'error', signal: limit });
          // Never read the answer: a receiver must not be able to fill this process's memory.
          try { await response.body?.cancel(); } catch { /* already closed */ }
          if (response.ok) return;
          last = new Error(`webhook ${target.origin} answered ${response.status}`);
          if (response.status === 410) { last.permanent = true; break; }
          if (![408, 429].includes(response.status) && response.status < 500) { last.refused = true; break; }
        } catch (error) { last = new Error(`webhook ${target.origin} unreachable: ${error.name === 'TimeoutError' ? 'timeout' : error.message}`); }
      }
      throw last;
    },
  };
}

// ------------------------------------------------------------------ feed adapter and its server
/// The recent events of each account, newest first, kept in memory (and in `store` if given, so
/// that a restart keeps them). An event whose id it has had (among the last 10 × limit) is ignored.
export function createFeed({ limit = 100, store = null } = {}) {
  let byAccount = {}, seen = {};
  const feed = {
    async load() { const saved = await store?.get().catch(() => null); byAccount = saved?.accounts || {}; seen = saved?.seen || {}; return feed; },
    async push(event) {
      const list = (byAccount[event.account] ||= []), ids = (seen[event.account] ||= []);
      if (ids.includes(event.id)) return;
      ids.push(event.id); if (ids.length > 10 * limit) ids.splice(0, ids.length - 10 * limit);
      list.unshift(clone(event));
      if (list.length > limit) list.length = limit;
      await store?.put({ accounts: byAccount, seen });
    },
    list: (account) => clone(byAccount[account] || []),
    adapter: { name: 'feed', deliver: (event) => feed.push(event) },
  };
  return feed;
}
/// Read-only HTTP: GET /alerts?account=<id> gives that account's recent events; GET /health the
/// state of the watch (counts only). Listens on 127.0.0.1 unless told otherwise. Requests must name
/// this server in Host (127.0.0.1, localhost or [::1] with its port, or one of `hosts`), so that a
/// web page cannot read it through DNS rebinding. With `token`, every request needs
/// "Authorization: Bearer <token>".
export function createAlertServer({ feed, accounts, status = () => ({}), port = 0, host = '127.0.0.1', hosts = [], token = null }) {
  const watched = new Set(accounts);
  const expected = token ? Buffer.from(`Bearer ${token}`) : null;
  const send = (response, code, value) => {
    response.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    response.end(JSON.stringify(value));
  };
  const server = http.createServer((request, response) => {
    const bound = server.address()?.port;
    const allowed = new Set([`127.0.0.1:${bound}`, `localhost:${bound}`, `[::1]:${bound}`, ...hosts]);
    if (!allowed.has(String(request.headers.host || '').toLowerCase())) return send(response, 421, { error: 'unknown host' });
    if (expected) {
      const given = Buffer.from(String(request.headers.authorization || ''));
      if (given.length !== expected.length || !timingSafeEqual(given, expected)) return send(response, 401, { error: 'token required' });
    }
    const url = new URL(request.url, 'http://watch.invalid');
    if (request.method !== 'GET') return send(response, 405, { error: 'read-only' });
    if (url.pathname === '/health') return send(response, 200, status());
    if (url.pathname !== '/alerts') return send(response, 404, { error: 'not found' });
    const account = url.searchParams.get('account');
    if (!canonicalId(account)) return send(response, 400, { error: 'account must be an account id' });
    if (!watched.has(account)) return send(response, 404, { error: 'this account is not watched here' });
    return send(response, 200, { account, events: feed.list(account) });
  });
  return {
    server,
    listen: () => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { const a = server.address(); resolve(`http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`); }); }),
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}
