// Security watch, the pure part: what changed in the security rules of one account between two
// readings of verified state, said in words an owner understands.
//
// The protections of v5/src/security.rs (a payment over the daily limit waits, a raise of the
// limit waits, a replacement of the keys asked for by recovery keys alone waits with the account
// frozen, a freeze, sign-in keys added or removed) only help an owner who notices in time. Nothing
// on the chain tells the owner. This module compares two snapshots of one account and returns the
// events to tell; security-watch-service.mjs polls, remembers and delivers them.
//
// A snapshot is { account, security, elapsed, height, genesis_time_micros, fee_micros }: the
// account row and the security row (or null) from verified state, and the chain's elapsed time
// (time_micros - genesis_time_micros) at that height. `snapshotOf` builds one.
//
// On a network whose waits survive a stop (`waits_survive_stops` in its genesis) a snapshot also
// carries `waits_survive_stops: true` and `stopped_micros`, the total of the chain's stops. The
// moments of a security row are then on the clock of the waits, the chain's time less that total
// (`TimeSDK.securityNow`): every comparison with them is made on that clock (`clockOf`), and a
// moment is shown as a date by adding the total, which gives the earliest it can come ("at the
// earliest": a later stop moves it). Read on the chain's time they come too early by the total of
// the stops, and the watch would tell an owner that a freeze is over or a payment can go through
// while the chain holds the opposite. On a network without the setting nothing of this changes.
//
// Every event has an `id` derived from what the rows name (the number of a waiting item, the
// freeze count, the version of the security row, a key and the authority epoch), never from when
// it was seen, so that a replayed poll produces the same id and a delivery can be skipped.
//
// Between two snapshots several actions may have happened. Three counters only grow and say how
// many: `next_id` (waiting items started), `version` (root operations and replacements) and the
// account's `auth_epoch` (key changes). Where a counter moved further than the visible changes
// explain, the watch says so as an urgent event rather than staying silent.
//
// Messages give dates in UTC only. A relative time ("in 5 minutes") would be counted from the
// chain time of the snapshot and be wrong by however late the state or the delivery was.
import './time-sdk.js';
import { roleOf, allowance } from './account-security.mjs';

const SDK = globalThis.TimeSDK;
const DAY_MICROS = 86_400_000_000n;
export const DEFAULT_REMINDER_SECONDS = 6 * 3600;
export const EVENT_TYPES = Object.freeze([
  'rules_adopted', 'payment_waiting', 'payment_gone', 'limit_raise_waiting', 'limit_raise_cancelled', 'limit_changed',
  'rules_changed', 'replacement_waiting', 'replacement_cancelled', 'keys_replaced', 'frozen', 'unfrozen',
  'signin_key_added', 'signin_key_removed', 'signin_keys_changed', 'root_operation', 'balance_fell', 'waiting_unseen', 'reminder',
  // Raised by the service, not by a comparison of rows:
  'watch_blind', 'watch_restored', 'watch_memory_lost', 'alerts_refused',
  // A change of the network's protocol version (docs/design/upgrade-mechanism.md):
  'upgrade_scheduled', 'upgrade_cancelled', 'watch_outdated', 'watch_ready',
  // Only on a network whose trust data does not say that its nodes report upgrades: the question
  // about scheduled upgrades was answered before and is not now, and is answered again. Types of
  // their own: they say nothing about whether the watch sees the account.
  'upgrade_question_unanswered', 'upgrade_question_answered',
  // The upgrade signal of a watched account's validator (action kind 80), from the upgrade entry of proven state:
  'upgrade_signal_changed', 'upgrade_signal_dropped',
]);

const big = (value) => BigInt(value);
const clone = (value) => (value == null ? value : JSON.parse(JSON.stringify(value)));

/// The snapshot of `accountId` in a verified state (the result of the SDK's getVerifiedState,
/// asked with `include_security: true`), or null if the state holds no such account.
export function snapshotOf(verified, accountId) {
  const state = verified?.state ?? verified, id = String(accountId);
  const row = (state.accounts || []).find((a) => String(a.id) === id);
  if (!row) return null;
  const security = (state.security || []).find((r) => r.account === id) || null;
  let fee = null;
  try { fee = SDK.networkFee(state); } catch { fee = null; }
  const signal = signalOf(state, id);
  // The total of stops, on a network whose waits survive a stop. A state that is not one the engine writes (the
  // setting in another form, the total without the setting or above the chain's time) throws: the account is then
  // not judged on a clock that may be wrong. (A state without its configuration, which only tests give, is read as before.)
  const stopped = state.config === undefined && state.stopped_micros === undefined ? null : SDK.waitsSurviveStops(state) ? SDK.stoppedMicros(state) : null;
  return {
    // Only when this state carries the upgrade entry: without it nothing is known of the account's signal.
    ...(signal === undefined ? {} : { signal }),
    account: { id, name: row.name ?? null, balance: String(row.balance ?? '0'), nonce: String(row.nonce ?? '0'), auth_epoch: String(row.auth_epoch ?? '0'), devices: clone(row.devices || []) },
    security: clone(security),
    elapsed: (big(state.time_micros) - big(state.genesis.genesis_time_micros)).toString(),
    height: String(state.height),
    network_id: state.network_id ?? null,
    genesis_time_micros: String(state.genesis.genesis_time_micros),
    fee_micros: fee,
    ...(stopped === null ? {} : { waits_survive_stops: true, stopped_micros: stopped }),
  };
}

// ------------------------------------------------------------------ the clock of the waits
/// The clock the moments of a security row are compared with at a snapshot: the chain's time less the stops so far.
/// `reference` is the newer snapshot of a pair. A snapshot stored by a watch from before the setting was read carries
/// no total; stops only grow, so the newer total is the most it can have been, and the older clock is taken at its
/// lowest: what waited then is taken to have waited longer, never less.
export function clockOf(snapshot, reference = snapshot) {
  const stopped = snapshot.stopped_micros ?? reference?.stopped_micros ?? '0', clock = big(snapshot.elapsed) - big(stopped);
  return clock < 0n ? 0n : clock;
}
/// A moment of a security row as a date. On a network whose waits survive a stop it is the moment plus the stops so far,
/// and while it has not come that is the earliest it can come: `earliest` is then true and the words say so.
function storedMoment(snapshot, micros) {
  const ruled = snapshot.waits_survive_stops === true, at = big(micros) + big(snapshot.stopped_micros ?? '0');
  const earliest = ruled && big(micros) > clockOf(snapshot), date = utc(snapshot.genesis_time_micros, at);
  return { date, earliest, words: earliest ? `${date} at the earliest` : date };
}
/// The `earliest` field of an event, only on a network whose waits survive a stop: elsewhere events are as they were.
const earliestField = (moment) => (moment.earliest ? { earliest: true } : {});

// ------------------------------------------------------------------ the upgrade signal of the account's validator
// The owner account of a validator signals support for a change of the network's rules (a
// version, the hash of its specification, a start time) or withdraws it: action kind 80, signed
// by a key of the account that may spend (docs/design/upgrade-mechanism.md). The design answers
// a stolen spend key with "the owner freezes"; for that the owner must learn of a signal it did
// not send, and nothing on the chain tells it. The signals are in the upgrade entry of proven
// state, one per owner at most.

/// The signal of account `id` in a verified state:
/// - undefined when the state was read without the upgrade entry, or the entry is not in the
///   form this build knows: nothing is known, and nothing may be said;
/// - null when the state carries the entry and it holds no signal of the account;
/// - { withdrawn: true, changed_elapsed_micros } for a withdrawal;
/// - { version, spec, activate_elapsed_micros, changed_elapsed_micros } for support of a plan.
export function signalOf(state, id) {
  if (!state || typeof state !== 'object' || !Object.hasOwn(state, 'upgrade')) return undefined;
  if (state.upgrade === null) return null;
  const signals = state.upgrade?.signals;
  if (!Array.isArray(signals)) return undefined;
  const entry = signals.find((item) => item && String(item.owner) === String(id));
  if (!entry) return null;
  const decimal = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value);
  if (!decimal(entry.changed_elapsed_micros)) return undefined;
  if (entry.version === undefined && entry.spec === undefined && entry.activate_elapsed_micros === undefined) return { withdrawn: true, changed_elapsed_micros: entry.changed_elapsed_micros };
  if (!decimal(entry.version) || !decimal(entry.activate_elapsed_micros) || typeof entry.spec !== 'string' || !/^[0-9a-f]{64}$/.test(entry.spec)) return undefined;
  return { version: entry.version, spec: entry.spec, activate_elapsed_micros: entry.activate_elapsed_micros, changed_elapsed_micros: entry.changed_elapsed_micros };
}
/// A specification hash in eight groups of eight: to be compared with the release announcement,
/// group by group, and not a value to copy. The signal may be someone else's.
export const groupHash = (hex) => hex.match(/.{8}/g).join(' ');
const signalKey = (entry) => (entry.withdrawn ? `withdrawn-${entry.changed_elapsed_micros}` : `${entry.version}-${entry.spec}-${entry.activate_elapsed_micros}-${entry.changed_elapsed_micros}`);

/// The events about the upgrade signal of one account between two snapshots.
/// - Nothing when the current snapshot does not know the signal (its state was read without the
///   upgrade entry): a missing reading is never "no signal".
/// - `upgrade_signal_changed`, urgent, when the entry is another one than in the previous
///   snapshot: support for a plan, or a withdrawal. Only a signed action of the account does that.
/// - `upgrade_signal_changed`, not urgent and marked `first_sight`, when this watch reads the
///   account's signal for the first time and it supports a plan: what stands now is told, as
///   elsewhere in this watch, and the watch cannot say whether it is new. A withdrawal standing
///   at the first reading is not told.
/// - `upgrade_signal_dropped`, not urgent, when a signal of support is gone: no action removes
///   an entry, the network drops it.
/// The id names the entry itself (what it supports and when the chain says it last changed),
/// never when it was seen: the same entry is one event, however often and by whomever it is read.
export function diffSignal(previous, current) {
  if (!current || current.signal === undefined) return [];
  if (previous && (previous.account.id !== current.account.id || big(current.height) < big(previous.height))) return [];
  const account = current.account.id, before = previous ? previous.signal : undefined, now = current.signal;
  const event = (type, key, urgent, message, fields) => ({ id: `${account}:${type}:${key}`, account, type, at_height: current.height, chain_time: when(current, current.elapsed), urgent, message, ...fields });
  const planWords = (entry) => `version ${entry.version}, start ${when(current, entry.activate_elapsed_micros)} at the earliest, specification hash ${groupHash(entry.spec)}`;
  if (now === null) {
    if (!before || before.withdrawn) return [];
    return [event('upgrade_signal_dropped', signalKey(before), false,
      `The signal of the validator of ${yours(current)} is no longer on the chain. It supported ${planWords(before)}. No action of an account removes a signal: the network drops one whose start has come too close, whose version is no longer the next one, or whose validator was retired. Your validator supports no plan now.`,
      { previous: before, signal: null })];
  }
  if (before && signalKey(before) === signalKey(now)) return [];
  const seen = before !== undefined;
  if (!seen && now.withdrawn) return [];
  const secured = Boolean(current.security);
  const thief = secured ? 'someone has your spend key' : 'someone has a key of your account that may spend';
  const stop = secured ? 'freeze your account now and replace your keys' : 'remove every key you do not know from the account now, in the wallet (Devices)';
  const later = secured ? ' once the account can sign again (a frozen account can neither signal nor withdraw)' : '';
  const sent = `The signal was sent at ${when(current, now.changed_elapsed_micros)}.`;
  if (now.withdrawn) {
    return [event('upgrade_signal_changed', signalKey(now), true,
      `The validator of ${yours(current)} no longer supports a change of the network's rules: its support${before ? ` for ${planWords(before)}` : ''} was withdrawn. ${sent} If you withdrew it, nothing is to do. If you did not, ${thief}: ${stop}. Then signal again in the wallet, tab "Validator signal"${later}, if your validator should support the plan.`,
      { signal: now, previous: before ?? null, first_sight: false })];
  }
  const what = `${seen ? 'now supports' : 'supports'} a change of the network's rules: ${planWords(now)}`;
  const first = seen ? '' : ' This watch reads the signal of this account for the first time, so it cannot say whether it is new.';
  return [event('upgrade_signal_changed', signalKey(now), seen,
    `The validator of ${yours(current)} ${what}. ${sent}${first} If you sent it, compare the hash with the release announcement, group by group; nothing else is to do. If you did not send it, ${thief}: ${stop}. Then withdraw the signal in the wallet, tab "Validator signal"${later}.`,
    { signal: now, previous: before ?? null, first_sight: !seen })];
}

/// The row as the engine sees it at `elapsed` (Security::settle): a raise of the limit whose wait
/// is over is in force, and a replacement nobody finished within its window is gone. The stored
/// row changes only when an action touches the account, so a watch that compared raw rows would
/// tell of a raise late, or never.
export function settle(security, elapsed) {
  if (!security) return null;
  const row = clone(security), now = big(elapsed), raise = row.pending_limit;
  row.raise_applied = null;
  if (raise && big(raise.ready_elapsed_micros) <= now) {
    row.policy = { ...row.policy, daily_limit_micros: raise.daily_limit_micros };
    row.pending_limit = null;
    row.raise_applied = raise;
  }
  if (row.pending_root && big(row.pending_root.expires_elapsed_micros) < now) row.pending_root = null;
  return row;
}
/// Frozen as the engine counts it (Security::frozen): by a freeze, or while a replacement waits.
/// `security` is a settled row.
export const frozenAt = (security, elapsed) => freezeActive(security, elapsed) || Boolean(security.pending_root);
const freezeActive = (security, elapsed) => big(elapsed) < big(security.frozen_until_elapsed_micros);

// ------------------------------------------------------------------ words
/// Microseconds of time as seconds: "12.5 s".
export function amount(micros) {
  const value = big(micros), sign = value < 0n ? '-' : '', abs = value < 0n ? -value : value;
  const fraction = (abs % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return `${sign}${abs / 1000000n}${fraction ? `.${fraction}` : ''} s`;
}
/// A length of time in words: "about 6 hours".
export function duration(micros) {
  const s = Number(big(micros) < 0n ? 0n : big(micros)) / 1e6;
  const unit = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  if (s < 90) return unit(Math.max(1, Math.round(s)), 'second');
  if (s < 90 * 60) return `about ${unit(Math.round(s / 60), 'minute')}`;
  if (s < 36 * 3600) return `about ${unit(Math.round(s / 3600), 'hour')}`;
  return `about ${unit(Math.round(s / 86400), 'day')}`;
}
/// A moment of the chain's clock, as a date: "2026-11-16 14:05 UTC".
export function utc(genesisTimeMicros, elapsedMicros) {
  const at = big(genesisTimeMicros) + big(elapsedMicros);
  return new Date(Number(at / 1000n)).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}
const when = (snapshot, elapsedMicros) => utc(snapshot.genesis_time_micros, elapsedMicros);
const short = (key) => `${key.slice(0, 8)}…`;
const yours = (snapshot) => `your account ${snapshot.account.id}${snapshot.account.name ? ` (${snapshot.account.name})` : ''}`;
const Yours = (snapshot) => `Y${yours(snapshot).slice(1)}`;
const plural = (count, word) => `${count} ${word}${count === 1n || count === 1 ? '' : 's'}`;
function keyCounts(devices) {
  const n = { spend: 0, recover: 0, signin: 0 };
  for (const d of devices) { const role = roleOf(d); if (role) n[role] += 1; }
  return `${plural(n.spend, 'spend key')}, ${plural(n.recover, 'recovery key')} and ${plural(n.signin, 'sign-in key')}`;
}
const span = (seconds) => duration(big(seconds) * 1000000n).replace(/^about /, '');
function policyWords(policy) {
  return `payments above ${amount(policy.daily_limit_micros)} a day wait ${span(policy.delay_seconds)}, a freeze lasts ${span(policy.freeze_seconds)}, and a change of keys needs ${policy.threshold} approvals`;
}
/// Who can act at once: the spend key and threshold − 1 recovery keys (all spend keys count as one proof).
const spendPlus = (policy) => `your spend key and ${plural(big(policy.threshold) - 1n, 'recovery key')}`;
const STEAL = 'someone has one of your keys';

// ------------------------------------------------------------------ the comparison
const signinKeys = (devices) => new Set(devices.filter((d) => roleOf(d) === 'signin').map((d) => d.public_key));
const powerKeys = (devices) => devices.filter((d) => roleOf(d) !== 'signin').map((d) => `${roleOf(d)}:${d.public_key}`).sort().join(',');
const sameDevices = (a, b) => JSON.stringify([...a].map((d) => `${roleOf(d)}:${d.public_key}`).sort()) === JSON.stringify([...b].map((d) => `${roleOf(d)}:${d.public_key}`).sort());

/// The events between two snapshots of one account. `previous` null means the account is seen
/// for the first time: what is waiting or frozen now is told, nothing about the past.
/// `options.reminderSeconds`: how long before a waiting item is ready a reminder goes out.
export function diffSecurity(previous, current, options = {}) {
  if (!current) return [];
  if (previous && big(current.height) < big(previous.height)) return []; // never compare backwards
  const account = current.account.id;
  if (previous && previous.account.id !== account) throw new Error('Two snapshots of different accounts');
  // `elapsed` and `then` are the clock of the waits at the two snapshots (the chain's time on a network without the
  // setting): every moment of the rows is compared with them. `chainTime` is the chain's time of the current one.
  const then = previous ? clockOf(previous, current) : null, elapsed = clockOf(current);
  const before = previous ? settle(previous.security, then) : null, now = settle(current.security, elapsed);
  if (!now) return [];
  const events = [];
  const chainTime = when(current, current.elapsed), moment = (micros) => storedMoment(current, micros);
  const add = (type, key, urgent, message, fields = {}) => events.push({
    id: `${account}:${type}${key === '' ? '' : `:${key}`}`, account, type, at_height: current.height, chain_time: chainTime, urgent, message, ...fields,
  });
  const first = !previous, adopted = Boolean(previous) && !before;
  const was = before || { pending_payments: [], pending_limit: null, pending_root: null, freezes: adopted ? '0' : now.freezes, frozen_until_elapsed_micros: '0', version: now.version, policy: now.policy, next_id: now.next_id };
  const fall = previous ? big(previous.account.balance) - big(current.account.balance) : 0n;
  const fee = current.fee_micros == null ? null : big(current.fee_micros);

  if (adopted) add('rules_adopted', '', false, `${Yours(current)} now has separate sign-in, spend and recovery keys: ${policyWords(now.policy)}. This watch will tell you when something waits.`, { policy: now.policy });

  // ---- what the counters and the rows say happened
  const versionMoved = Boolean(before) && big(now.version) > big(before.version);
  const finished = Boolean(before?.pending_root) && !now.pending_root && sameDevices(current.account.devices, before.pending_root.devices);
  const replaced = versionMoved && (powerKeys(previous.account.devices) !== powerKeys(current.account.devices) || finished);
  const oldLimit = big(was.policy.daily_limit_micros), newLimit = big(now.policy.daily_limit_micros);
  const raise = was.pending_limit, raiseGone = Boolean(raise) && !(now.pending_limit && now.pending_limit.id === raise.id);
  // The fate of a raise that was waiting and is no longer. After its ready time the engine applies
  // it before anything else (settle), so it cannot be cancelled or dropped after that; but the
  // watch cannot tell whether it was cancelled just before its ready time without more evidence.
  let raiseFate = null;
  if (raiseGone) {
    if (big(raise.ready_elapsed_micros) > elapsed) raiseFate = now.pending_limit ? 'replaced' : newLimit < oldLimit ? 'lowered' : 'cancelled';
    else if (now.raise_applied?.id === raise.id || newLimit === big(raise.daily_limit_micros)) raiseFate = 'took_effect';
    else if (newLimit > oldLimit && !versionMoved) raiseFate = 'took_effect_then_lowered'; // nothing else raises a limit without the version
    else raiseFate = 'unknown';
  }
  const raiseExplains = raiseFate === 'took_effect' || raiseFate === 'took_effect_then_lowered';
  const otherRules = ['threshold', 'delay_seconds', 'freeze_seconds'].filter((f) => before && before.policy[f] !== now.policy[f]);
  // A root operation with the spend key that kept the keys: rules changed, or the limit rose without waiting.
  const installedSameKeys = versionMoved && !replaced && (otherRules.length > 0 || (newLimit > oldLimit && !raiseExplains));
  const asked = Boolean(now.pending_root) && (!was.pending_root || was.pending_root.ready_elapsed_micros !== now.pending_root.ready_elapsed_micros);
  const rootGone = Boolean(was.pending_root) && (!now.pending_root || now.pending_root.ready_elapsed_micros !== was.pending_root.ready_elapsed_micros);
  // Past its expiry a request is gone by itself (settle), so its going explains no operation, even
  // if it may have been cancelled before. An install (keys replaced, or rules changed with the
  // spend key) drops a waiting request as part of that one operation. Counting fewer operations
  // than may have happened makes `root_operation` fire: when in doubt, the owner is told.
  const rootLapsed = rootGone && elapsed > big(was.pending_root.expires_elapsed_micros);
  const rootExpired = rootLapsed && !versionMoved;
  const rootCancelled = rootGone && !rootLapsed && !replaced && !installedSameKeys;
  const lifted = Boolean(before) && freezeActive(before, then) && now.frozen_until_elapsed_micros === '0' && !replaced && !installedSameKeys;
  const freezesRose = big(now.freezes) > big(was.freezes);
  const cause = freezesRose ? 'freeze' : (asked && !first) ? 'replacement_asked' : (replaced || installedSameKeys) ? 'keys_replaced' : null;
  const causeWords = { freeze: 'the freeze of your account dropped it', replacement_asked: 'the replacement of your keys that was asked for dropped it', keys_replaced: 'the change of your keys and rules dropped it' };

  if (replaced) {
    add('keys_replaced', `v${now.version}`, true,
      `The keys of ${yours(current)} were replaced. It now has ${keyCounts(current.account.devices)}, and ${policyWords(now.policy)}. Everything that was waiting was dropped. If you did not do this, the account is no longer under your control: get help now.`,
      { version: now.version, devices: current.account.devices, policy: now.policy, finished_waiting_replacement: finished });
  }

  // ---- freezes. The count only grows, so a freeze is seen even if it began and ended between polls.
  if (freezesRose || (first && freezeActive(now, elapsed))) {
    const until = now.frozen_until_elapsed_micros, active = freezeActive(now, elapsed), stillFrozen = frozenAt(now, elapsed), end = moment(until);
    const count = big(now.freezes) - big(was.freezes), several = count > 1n ? ` (${count} freezes since the last look)` : '';
    const advice = `If you did not freeze it, ${STEAL}: replace your keys.`;
    const message = active
      ? `${Yours(current)} is frozen until ${end.words}${several}${now.pending_root ? ', and longer while a replacement of its keys waits' : ''}. Until then its spend key alone cannot pay from it, nobody signs in with it, and what was waiting is dropped. ${advice}`
      : stillFrozen
        ? `${Yours(current)} was frozen${several}; that freeze ended at ${end.words}, but the account stays frozen while a replacement of its keys waits. ${advice}`
        : `${Yours(current)} was frozen${several}, and the freeze is already over. ${advice}`;
    add('frozen', now.freezes, true, message, { freezes: now.freezes, frozen_until_elapsed_micros: until, frozen_until: end.date, already_over: !stillFrozen, ...earliestField(end) });
  } else if (before && freezeActive(before, then) && !frozenAt(now, elapsed)) {
    // Only when nothing keeps the account frozen any more (a waiting replacement does).
    const reason = now.frozen_until_elapsed_micros === '0' ? (lifted ? 'lifted' : 'keys_replaced') : 'ended';
    const words = {
      ended: `The freeze of ${yours(current)} has ended. Payments and sign-ins work again.`,
      lifted: `The freeze of ${yours(current)} was lifted early. That takes ${spendPlus(now.policy)} together. If you did not lift it, someone holds those keys: get help now.`,
      keys_replaced: `The freeze of ${yours(current)} ended when its keys or rules were changed.`,
    };
    add('unfrozen', now.freezes, reason === 'lifted', words[reason], { freezes: now.freezes, reason });
  }

  // ---- a replacement of the keys asked for by recovery keys alone
  if (now.pending_root && (first || asked)) {
    const r = now.pending_root, ready = moment(r.ready_elapsed_micros), lapse = moment(r.expires_elapsed_micros);
    add('replacement_waiting', r.ready_elapsed_micros, true,
      `Recovery keys asked to replace all the keys of ${yours(current)}. The account is frozen meanwhile. The new keys can take over from ${ready.words}; if nobody finishes it by ${lapse.words}, it lapses. If you did not ask for it, replace your keys yourself now with ${spendPlus(now.policy)}: that takes effect at once and drops this request. Cancelling the request instead takes ${now.policy.threshold} approvals, and the same recovery keys can ask again at once.`,
      { ready_elapsed_micros: r.ready_elapsed_micros, ready_at: ready.date, expires_elapsed_micros: r.expires_elapsed_micros, expires_at: lapse.date, new_keys: r.devices, new_policy: r.policy, ...earliestField(ready) });
  }
  if (rootGone && !replaced) {
    const r = was.pending_root, free = !frozenAt(now, elapsed) ? ' The account is no longer frozen.' : '';
    const reason = rootExpired ? 'expired' : rootLapsed ? 'expired_or_cancelled' : installedSameKeys ? 'dropped' : 'cancelled';
    const words = {
      expired: `lapsed: nobody finished it by ${moment(r.expires_elapsed_micros).words}`,
      expired_or_cancelled: `is gone: it was cancelled, or it lapsed at ${moment(r.expires_elapsed_micros).words}`,
      dropped: 'was dropped when the rules of the account were changed',
      cancelled: 'was cancelled',
    };
    add('replacement_cancelled', r.ready_elapsed_micros, false,
      `The replacement of the keys of ${yours(current)} that was waiting ${words[reason]}. The keys it named did not take over.${free}`,
      { ready_elapsed_micros: r.ready_elapsed_micros, reason });
  }

  // ---- payments above the daily limit
  const waitingIds = new Set(now.pending_payments.map((p) => p.id)), wasIds = new Set(was.pending_payments.map((p) => p.id));
  for (const p of now.pending_payments) {
    if (wasIds.has(p.id)) continue;
    const ready = moment(p.ready_elapsed_micros);
    add('payment_waiting', p.id, true,
      `A payment of ${amount(p.amount)} from ${yours(current)} to account ${p.to} is waiting and can go through from ${ready.words} unless you cancel it. If you did not start it, freeze your account now.`,
      { payment_id: p.id, to: p.to, amount_micros: p.amount, ready_elapsed_micros: p.ready_elapsed_micros, ready_at: ready.date, ...earliestField(ready) });
  }
  const gone = was.pending_payments.filter((p) => !waitingIds.has(p.id));
  // Whether a payment that left the list went through is not written in the rows. One that was
  // not ready yet cannot have. One that was ready went through for certain only if the balance
  // fell by exactly what the ready ones and their fees add up to; anything else (money in, other
  // payments, a cancel fee) leaves it open, and the owner is told to look.
  const ripe = gone.filter((p) => big(p.ready_elapsed_micros) <= elapsed);
  const ripeCost = ripe.reduce((sum, p) => sum + big(p.amount), 0n) + (fee ?? 0n) * BigInt(ripe.length);
  const allExecuted = ripe.length > 0 && fee !== null && fall === ripeCost;
  for (const p of gone) {
    const pay = `The waiting payment of ${amount(p.amount)} to account ${p.to}`;
    let outcome, certain, urgent = false, message;
    if (big(p.ready_elapsed_micros) > elapsed) {
      outcome = cause ? 'dropped' : 'cancelled'; certain = true;
      message = cause ? `${pay} did not go through: ${causeWords[cause]}.` : `${pay} was cancelled and did not go through.`;
    } else if (allExecuted) {
      outcome = 'executed'; certain = true;
      message = `${pay} went through: your balance fell by ${amount(fall)}, ${ripe.length === 1 ? 'the payment and its fee' : 'these payments and their fees'}.`;
    } else {
      outcome = 'unknown'; certain = false; urgent = true;
      const moved = fall > 0n ? `the balance fell by ${amount(fall)}` : fall < 0n ? `the balance rose by ${amount(-fall)}` : 'the balance did not change';
      message = `${pay} is no longer waiting. This watch cannot tell whether it went through: other money moved at the same time (${moved}). Check the history of ${yours(current)} now.`;
    }
    add('payment_gone', p.id, urgent, message, { payment_id: p.id, to: p.to, amount_micros: p.amount, outcome, certain, cause: outcome === 'dropped' ? cause : null, balance_fall_micros: fall.toString() });
  }

  // ---- waiting items that came and went between two looks. `next_id` is never reused.
  if (before) {
    const visible = new Set([...now.pending_payments.map((p) => p.id), now.pending_limit?.id, now.raise_applied?.id].filter(Boolean));
    const unseen = [];
    for (let id = big(before.next_id); id < big(now.next_id) && unseen.length < 64; id++) if (!visible.has(id.toString())) unseen.push(id.toString());
    if (unseen.length) {
      const n = unseen.length, items = n === 1 ? '1 waiting item (a payment above the daily limit, or a raise of the limit) was' : `${n} waiting items (payments above the daily limit, or raises of the limit) were`;
      add('waiting_unseen', `${unseen[0]}-${unseen[n - 1]}`, true,
        `While this watch could not look, ${items} started on ${yours(current)} and ${n === 1 ? 'is' : 'are'} no longer waiting. ${fall > 0n ? `The balance fell by ${amount(fall)} meanwhile.` : 'The balance did not fall meanwhile.'} If you did not start ${n === 1 ? 'it' : 'them'}, check the account's history and freeze your account.`,
        { item_ids: unseen, balance_fall_micros: fall.toString() });
    }
  }

  // ---- the daily limit: a raise waits, a lowering is at once, a root operation is at once
  const fresh = now.pending_limit && (!was.pending_limit || was.pending_limit.id !== now.pending_limit.id) ? now.pending_limit : null;
  if (fresh) {
    const ready = moment(fresh.ready_elapsed_micros);
    add('limit_raise_waiting', fresh.id, true,
      `A raise of the daily limit of ${yours(current)} from ${amount(now.policy.daily_limit_micros)} to ${amount(fresh.daily_limit_micros)} is waiting and takes effect at ${ready.words} unless you cancel it. If you did not ask for it, freeze your account now.`,
      { raise_id: fresh.id, from_micros: now.policy.daily_limit_micros, to_micros: fresh.daily_limit_micros, ready_elapsed_micros: fresh.ready_elapsed_micros, ready_at: ready.date, ...earliestField(ready) });
  }
  if (!replaced && (raiseFate === 'cancelled' || (raiseFate === 'unknown' && newLimit === oldLimit))) {
    const known = raiseFate === 'cancelled';
    add('limit_raise_cancelled', raise.id, false,
      known
        ? `The raise of your daily limit to ${amount(raise.daily_limit_micros)} that was waiting ${cause ? `did not take effect: ${causeWords[cause]}` : 'was cancelled'}. The limit stays at ${amount(newLimit)}.`
        : `The raise of your daily limit to ${amount(raise.daily_limit_micros)} is no longer waiting and the limit is ${amount(newLimit)}, as before: it was cancelled, or it took effect and the limit was lowered again.`,
      { raise_id: raise.id, reason: known ? (cause || 'cancelled') : 'unknown' });
  }
  if (before && !replaced && oldLimit !== newLimit) {
    const up = newLimit > oldLimit;
    const viaRaise = raiseExplains;
    const key = viaRaise ? `raise-${raise.id}` : `n${current.account.nonce}-v${now.version}-${now.policy.daily_limit_micros}`;
    let message, urgent = false;
    if (raiseFate === 'took_effect') message = `The daily limit of ${yours(current)} is now ${amount(newLimit)} (it was ${amount(oldLimit)}): the raise that waited took effect. A spend key can now move that much a day without waiting.`;
    else if (raiseFate === 'took_effect_then_lowered') message = `The raise of the daily limit of ${yours(current)} to ${amount(raise.daily_limit_micros)} took effect, and the limit was then lowered to ${amount(newLimit)} (it was ${amount(oldLimit)} before the raise).`;
    else if (up) {
      urgent = true;
      message = `The daily limit of ${yours(current)} rose at once from ${amount(oldLimit)} to ${amount(newLimit)}, without the waiting period. That takes ${spendPlus(now.policy)} together. If you did not approve it, someone holds those keys: get help now.`;
    } else {
      message = `The daily limit of ${yours(current)} is now ${amount(newLimit)} (it was ${amount(oldLimit)})${raiseFate ? `; the raise to ${amount(raise.daily_limit_micros)} that was waiting is gone` : ''}. If you did not lower it, ${STEAL}: freeze your account and replace your keys.`;
    }
    add('limit_changed', key, urgent, message, { from_micros: oldLimit.toString(), to_micros: newLimit.toString(), raised: up, waited: viaRaise, raise_outcome: raiseFate });
  }

  // ---- the other rules, changed by a root operation that kept the keys
  if (before && !replaced && otherRules.length) {
    add('rules_changed', `v${now.version}`, true,
      `The rules of ${yours(current)} changed at once: now ${policyWords(now.policy)}. That takes ${spendPlus(now.policy)} together. If you did not change them, someone holds those keys: get help now.`,
      { from: before.policy, to: now.policy });
  }

  // ---- root operations the rows do not show: an immediate payment, a cancel or an unfreeze of
  // something never seen. Each one moves the version by one.
  if (versionMoved) {
    const explained = (replaced ? 1n : 0n) + (installedSameKeys ? 1n : 0n) + (asked && !first ? 1n : 0n) + (rootCancelled ? 1n : 0n) + (lifted ? 1n : 0n);
    const moved = big(now.version) - big(before.version);
    if (moved > explained) {
      const n = moved - explained;
      add('root_operation', `v${before.version}-v${now.version}`, true,
        `${n === 1n ? 'An operation' : `${n} operations`} approved by several keys of ${yours(current)} took place that this watch cannot show in detail: an immediate payment, or lifting or cancelling something it never saw. ${fall > 0n ? `The balance fell by ${amount(fall)} meanwhile.` : 'The balance did not fall meanwhile.'} That takes ${spendPlus(now.policy)} together. If you did not approve it, someone holds those keys: get help now.`,
        { version_from: before.version, version_to: now.version, unexplained: n.toString(), balance_fall_micros: fall.toString() });
    }
  }

  // ---- a fall of the balance larger than the spend key alone could cause, not told above. The
  // spend key moves at most what was left of the daily limit plus what refilled since, and the
  // waiting payments that were ready; every action costs at most a fee. Anything beyond that left
  // by a way the watch cannot name, and the owner hears of it. The limit refills on the clock of
  // the waits: a stop gives the spend key nothing more to move.
  if (before && fall > 0n && !events.some((e) => e.type === 'root_operation' || e.type === 'waiting_unseen')) {
    const since = elapsed > then ? elapsed - then : 0n, limit = [big(previous.security.policy.daily_limit_micros), big(previous.security.pending_limit?.daily_limit_micros ?? 0), newLimit].reduce((a, b) => (a > b ? a : b));
    const actions = big(current.account.nonce) - big(previous.account.nonce) + big(now.version) - big(before.version) + big(now.freezes) - big(before.freezes) + BigInt(gone.length) + 2n;
    const budget = big(allowance(previous.security, then)) + limit * since / DAY_MICROS + ripe.reduce((sum, p) => sum + big(p.amount), 0n) + (fee ?? 1000n) * (actions > 0n ? actions : 2n);
    if (fall > budget) {
      add('balance_fell', `h${previous.height}-h${current.height}`, true,
        `The balance of ${yours(current)} fell by ${amount(fall)} between two looks, more than its spend key alone could move in that time (at most ${amount(budget)}). The money left in a way this watch cannot show in detail, such as a payment approved with several keys. If you did not approve it, get help now.`,
        { balance_fall_micros: fall.toString(), spend_key_budget_micros: budget.toString() });
    }
  }

  // ---- sign-in keys: a spend key adds and removes them at once, each action moving the authority epoch by one
  if (before && !replaced) {
    const had = signinKeys(previous.account.devices), has = signinKeys(current.account.devices), epoch = current.account.auth_epoch;
    let visible = 0n;
    for (const key of has) if (!had.has(key)) { visible += 1n; add('signin_key_added', `${key}:${epoch}`, true,
      `A sign-in key (${short(key)}) was added to ${yours(current)}. It can sign in to websites as you. If you did not add it, someone has your spend key: freeze your account now.`, { public_key: key }); }
    for (const key of had) if (!has.has(key)) { visible += 1n; add('signin_key_removed', `${key}:${epoch}`, true,
      `A sign-in key (${short(key)}) was removed from ${yours(current)}; the device that held it can no longer sign in. If you did not remove it, someone has your spend key: freeze your account now.`, { public_key: key }); }
    // One action may change several keys, so each visible change may explain one step of the epoch.
    const moved = big(epoch) - big(previous.account.auth_epoch), explained = visible + (installedSameKeys ? 1n : 0n);
    if (moved > explained) {
      add('signin_keys_changed', `e${previous.account.auth_epoch}-e${epoch}`, true,
        `The sign-in keys of ${yours(current)} were changed while this watch was not looking: ${plural(moved - explained, 'change')} it could not see one by one, such as a key added and removed again. It now has ${plural(has.size, 'sign-in key')}. If you did not change them, someone has your spend key: freeze your account now.`,
        { epoch_from: previous.account.auth_epoch, epoch_to: epoch, unexplained: (moved - explained).toString(), signin_keys: [...has] });
    }
  }

  events.push(...reminders(previous, current, options));
  return events;
}

/// Reminders: a waiting item the owner has already been told about, whose ready time came within
/// `reminderSeconds` (default 6 hours) between the two snapshots. One reminder per item. The
/// window is counted on the clock of the waits, which a stop does not move.
export function reminders(previous, current, { reminderSeconds = DEFAULT_REMINDER_SECONDS } = {}) {
  if (!previous || !current || big(current.height) < big(previous.height)) return [];
  const then = clockOf(previous, current), at = clockOf(current);
  const before = settle(previous.security, then), now = settle(current.security, at);
  if (!before || !now) return [];
  const window = BigInt(Math.round(reminderSeconds * 1e6));
  const account = current.account.id, out = [];
  const items = (row) => [
    ...row.pending_payments.map((p) => ({ kind: 'payment', key: p.id, ready: p.ready_elapsed_micros, what: `the payment of ${amount(p.amount)} to account ${p.to}`, act: 'Cancel it before then if you did not start it.' })),
    ...(row.pending_limit ? [{ kind: 'limit', key: row.pending_limit.id, ready: row.pending_limit.ready_elapsed_micros, what: `the raise of your daily limit to ${amount(row.pending_limit.daily_limit_micros)}`, act: 'Cancel it before then if you did not ask for it.' }] : []),
    ...(row.pending_root ? [{ kind: 'replacement', key: row.pending_root.ready_elapsed_micros, ready: row.pending_root.ready_elapsed_micros, what: 'the replacement of all your keys', act: `If you did not ask for it, replace your keys now with ${spendPlus(row.policy)}.` }] : []),
  ];
  const known = new Set(items(before).map((i) => `${i.kind}:${i.key}`));
  for (const item of items(now)) {
    if (!known.has(`${item.kind}:${item.key}`)) continue;
    const ready = big(item.ready), from = ready - window;
    if (!(then < from && at >= from)) continue;
    const go = item.kind === 'limit' ? 'takes effect' : item.kind === 'replacement' ? 'can be finished' : 'can go through', due = storedMoment(current, item.ready);
    const message = at >= ready
      ? `Reminder: ${item.what} ${go} now (from ${due.words}). It can still be stopped until it happens. ${item.act}`
      : `Reminder: ${item.what} ${go} from ${due.words}. ${item.act}`;
    out.push({ id: `${account}:reminder:${item.kind}:${item.key}`, account, type: 'reminder', at_height: current.height, chain_time: when(current, current.elapsed), urgent: true, message, item: item.kind, item_key: item.key, ready_elapsed_micros: item.ready, ready_at: due.date, ...earliestField(due) });
  }
  return out;
}
