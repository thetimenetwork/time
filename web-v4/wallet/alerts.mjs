// Alerts for the wallet: what about an account needs its owner's attention, worked out from ONE verified state.
//
// A notification carries no information; the chain does. The hint of the API ("your account was touched at height
// H") and the browser push of the alert service ("open your wallet") claim nothing. When either comes, or when the
// page opens, the wallet reads its account's state with a proof, and this module says what that state means for
// the owner. It never says a sentence the state did not prove: every alert comes from the rows of that one state,
// and from `seen`, what this browser recorded the last time its owner confirmed what it saw.
//
// Two kinds of alert:
// - a condition that is true now: the keys are being replaced (asked for by recovery keys alone), guardians are
//   recovering the account (protocol 4), the account is frozen, a payment waits, a raise of the daily limit waits.
//   It stays as long as the state says so;
// - a change since `seen`: a login key added or removed, a key added or removed (protocol 4), the keys replaced, the
//   recovery words replaced, the account protected with new keys, the rules or the daily limit changed, a freeze
//   that came and went, and, when a counter that only grows moved further than the visible changes explain,
//   "something changed that this wallet cannot show" (as the security watch does: client-v4/security-watch.mjs), and
//   actions signed with the account's keys that this browser did not send (the account's nonce moved by more than the
//   actions this browser's own record holds since the marker; web audit of November 2026, K-4).
//   It stays until the owner confirms and the page stores the new marker as `seen`. On a first look (`seen` null)
//   there is no change to tell: only what is true now.
// An alert the owner can act on says where, in the words the page uses there: what waits is cancelled on Home, under
// "Waiting on your account" (with the payment password, and for a change of keys the recovery words too), a freeze is
// the Freeze switch on Home, new passwords and new recovery words are under Keys, "Change something".
//
// Every alert has an id derived from what the rows name (the number of a waiting item, the freeze count, the version
// of the security row, a key and the authority epoch), never from when it was read: the same condition is one alert
// however often it is read. Sentences are fixed and written here; nothing in them comes from outside the proven state
// but numbers, account numbers and the first characters of a public key. Dates are on the clock of the waits
// (TimeSDK.securityDeadline, as security-flows.mjs momentOf reads them): on a network whose waits survive a stop of
// the chain, a date that has not come is the earliest it can come, and the words say "not before".
//
// A received payment is not an alert here. This module touches no page, no storage and no network.
import { formatSeconds } from './guards.mjs';
import { momentOf, dateOf } from './security-flows.mjs';

const big = value => BigInt(value);
const decimal = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 1n << 64n;
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// ------------------------------------------------------------------ the marker of what this browser has seen
/// Where the page keeps the marker of an account on a network.
export const MARKER_PREFIX = 'timecurrency.alerts-seen.v1:';
export function markerKey(networkId, accountId) {
  if (!hex64(networkId) || !decimal(String(accountId))) throw new Error('A marker belongs to one account of one network.');
  return `${MARKER_PREFIX}${networkId}:${accountId}`;
}
const KEY_ROLES = ['signin', 'spend', 'recover', 'full'];
const POLICY = ['daily_limit_micros', 'delay_seconds', 'freeze_seconds', 'threshold'];
const MARKER_FIELDS = ['account', 'auth_epoch', 'clock', 'freezes', 'frozen_until', 'keys', 'next_id', 'nonce', 'policy', 'recovery_version', 'root', 'secured', 'v', 'version'];
/// The marker if `value` (an object, or the text the page stored) is a well-formed marker of `accountId`, or null.
/// Anything else counts as nothing seen: a first look. Version 2 is the same marker, written by a page that keeps the
/// nonce of every action it sends (app.js, recordReceipt): only from such a marker on are the actions this browser sent
/// counted against the nonce. A version-1 marker is read as before, and gives no alert about actions signed elsewhere.
export function readMarker(value, accountId) {
  let m = value;
  if (typeof value === 'string') { if (value.length > 8192) return null; try { m = JSON.parse(value); } catch { return null; } }
  try {
    if (!record(m) || Object.keys(m).sort().join(',') !== MARKER_FIELDS.join(',') || (m.v !== 1 && m.v !== 2) || m.account !== String(accountId) || !decimal(m.account)) return null;
    if (typeof m.secured !== 'boolean' || !['auth_epoch', 'nonce', 'clock'].every(f => decimal(m[f]))) return null;
    if (m.recovery_version !== null && !decimal(m.recovery_version)) return null;
    if (!record(m.keys) || Object.keys(m.keys).sort().join(',') !== [...KEY_ROLES].sort().join(',')) return null;
    for (const role of KEY_ROLES) {
      const list = m.keys[role];
      if (!Array.isArray(list) || list.length > 16 || !list.every(hex64) || !list.every((k, i) => i === 0 || list[i - 1] < k)) return null;
    }
    const security = ['version', 'freezes', 'next_id', 'frozen_until'];
    if (m.secured) {
      if (!security.every(f => decimal(m[f]))) return null;
      if (!record(m.policy) || Object.keys(m.policy).sort().join(',') !== POLICY.join(',') || !POLICY.every(f => decimal(m.policy[f]))) return null;
      if (m.root !== null && (!record(m.root) || Object.keys(m.root).sort().join(',') !== 'expires,ready' || !decimal(m.root.ready) || !decimal(m.root.expires))) return null;
    } else if (!security.every(f => m[f] === null) || m.policy !== null || m.root !== null) return null;
    return m;
  } catch { return null; }
}

// ------------------------------------------------------------------ the rows
const roleOf = d => d.can_manage ? (d.can_spend ? 'full' : 'recover') : d.can_spend ? 'spend' : 'signin';
function keysOf(account) {
  const keys = { signin: [], spend: [], recover: [], full: [] };
  for (const d of account.devices || []) if (hex64(d.public_key)) keys[roleOf(d)].push(d.public_key);
  for (const role of KEY_ROLES) keys[role].sort();
  return keys;
}
/// The row as the engine sees it at `now` (security.rs, Security::settle): a raise whose wait is over is in force,
/// and a replacement nobody finished within its window is gone.
function settle(row, now) {
  const r = JSON.parse(JSON.stringify(row));
  r.raise_applied = null;
  if (r.pending_limit && big(r.pending_limit.ready_elapsed_micros) <= now) { r.policy = { ...r.policy, daily_limit_micros: r.pending_limit.daily_limit_micros }; r.raise_applied = r.pending_limit; r.pending_limit = null; }
  if (r.pending_root && big(r.pending_root.expires_elapsed_micros) < now) r.pending_root = null;
  return r;
}
/// The clock of the waits at this state (TimeSDK.securityNow); a state without its configuration, which only tests
/// give, is read on the chain's time, as client-v4/server-auth.mjs does.
const elapsedOf = state => big(state.time_micros) - big(state.genesis.genesis_time_micros);
const clockOf = (sdk, state) => (state.config === undefined && state.stopped_micros === undefined ? elapsedOf(state) : big(sdk.securityNow(state)));

// ------------------------------------------------------------------ words
const utc = date => `${date.toISOString().replace('T', ' ').slice(0, 16)} UTC`;
const seconds = micros => `${formatSeconds(String(micros))} seconds`;
const short = key => `${key.slice(0, 8)}…`;
function span(secondsText) {
  const s = big(secondsText), unit = (n, word) => `${n} ${word}${n === 1n ? '' : 's'}`;
  if (s > 0n && s % 3600n === 0n) return unit(s / 3600n, 'hour');
  if (s > 0n && s % 60n === 0n) return unit(s / 60n, 'minute');
  return unit(s, 'second');
}
const rulesWords = p => `payments above the daily limit wait ${span(p.delay_seconds)}, a freeze lasts ${span(p.freeze_seconds)}, and big changes need ${p.threshold} approvals`;
/// Who can do at once what several keys approve: the payment key and threshold - 1 recovery keys (security.rs).
function together(policy) {
  const papers = big(policy.threshold) - 1n;
  return `That takes your payment password and ${papers === 1n ? 'your recovery words' : `${papers} recovery keys`} together.`;
}
/// Where the owner acts, in the words of the page (index.html).
const WAITING = 'on Home, under \u201cWaiting on your account\u201d', CHANGE = 'under Keys, \u201cChange something\u201d', FREEZE = 'freeze your account now with the Freeze switch on Home';
/// A key of a protocol-4 account, by what it may do.
const P4_KEY = { full: 'A key that can pay and manage', spend: 'A key that can pay', recover: 'A key that can manage', signin: 'A key that can only sign in' };

/// What needs the owner's attention about `account` (its number, or its row) in `state`, a state the wallet's light
/// client verified, read with `include_security` when the account may have a security row (no key of it holds both
/// powers). `seen` is the marker this browser stored when its owner last confirmed, or null. `formatDate` turns a
/// Date into words (by default "2026-11-23 14:05 UTC"). `sent`: how many actions this browser itself sent since `seen`, by
/// its own record (app.js counts its activity above the marker's nonce), or null when it cannot say.
/// Returns { alerts, marker }: the alerts, most urgent first, each { id, urgent, title, text, until?, notBefore? };
/// and the marker of this state, which the page stores as `seen` once the owner confirms.
export function alertsOf({ sdk, state, account, seen = null, formatDate = utc, sent = null }) {
  const accountId = String(record(account) ? account.id : account);
  const row = (state?.accounts || []).find(a => String(a.id) === accountId);
  if (!row) throw new Error('This account is not in the verified state.');
  const needsRow = Boolean(row.devices?.length) && !row.devices.some(d => d.can_manage && d.can_spend);
  if (needsRow && !Array.isArray(state.security)) throw new Error('The security state of this account was not proven. Read it again with its security rows.');
  const stored = needsRow ? state.security.find(r => String(r.account) === accountId) ?? null : null;
  const now = clockOf(sdk, state), chain = elapsedOf(state);
  const security = stored ? settle(stored, now) : null;
  const keys = keysOf(row);
  const marker = {
    v: 2, account: accountId, secured: Boolean(security), auth_epoch: String(row.auth_epoch ?? '0'), nonce: String(row.nonce ?? '0'),
    recovery_version: decimal(String(row.recovery_version ?? '')) ? String(row.recovery_version) : null, clock: now.toString(), keys,
    version: security ? String(security.version) : null, freezes: security ? String(security.freezes) : null, next_id: security ? String(security.next_id) : null,
    frozen_until: security ? String(security.frozen_until_elapsed_micros) : null,
    root: security?.pending_root ? { ready: String(security.pending_root.ready_elapsed_micros), expires: String(security.pending_root.expires_elapsed_micros) } : null,
    policy: security ? Object.fromEntries(POLICY.map(f => [f, String(security.policy[f])])) : null,
  };
  const alerts = [];
  const add = (id, urgent, title, text, moment) => alerts.push({ id: `${accountId}:${id}`, urgent, title, text, ...(moment ? { until: moment.date, notBefore: moment.later } : {}) });
  /// A moment of the security row in words: "at <date>", or "not before <date>" where a stop of the chain moves it.
  const due = micros => momentOf(sdk, state, String(micros));
  const at = moment => `${moment.later ? 'not before' : 'at'} ${formatDate(moment.date)}`;

  // ---- what is true now
  if (security?.pending_root) {
    const r = security.pending_root, ready = due(r.ready_elapsed_micros), lapse = due(r.expires_elapsed_micros);
    add(`keys-waiting:${r.ready_elapsed_micros}`, true, 'Your keys are being replaced',
      `Your recovery words were used to ask for new keys for this account. Until this is finished or stopped, the account is frozen: nothing can be paid with your payment password alone, and nobody can sign in. ${big(r.ready_elapsed_micros) <= now ? `The new keys can take over now, until ${formatDate(lapse.date)}.` : `The new keys can take over ${at(ready)}.`} If you did not ask for this, make new recovery words now, ${CHANGE}: it needs your payment password and your recovery words, it ends this change at once, and the words that were used stop working. Cancelling it ${WAITING} needs the same, but whoever asked keeps your words and can ask again. Without your recovery words you cannot stop this.`,
      ready);
  }
  for (const c of (state.recovery_cases || []).filter(c => String(c.target) === accountId && decimal(String(c.expires_elapsed_micros)) && big(c.expires_elapsed_micros) >= chain)) {
    const ready = c.ready_elapsed_micros === null || c.ready_elapsed_micros === undefined ? null : { date: dateOf(state, c.ready_elapsed_micros), later: false };
    add(`guardians:${c.recovery_id}`, true, 'Your guardians are recovering this account',
      ready
        ? `Your guardians approved giving this account to a new key. Until this is finished or cancelled, nobody can sign in with it. The new key can take over ${at(ready)}. If you did not ask for this, cancel it now under More, Guardian recovery.`
        : 'A guardian asked to give this account to a new key. More guardians must approve before it can go on. If you did not ask for this, cancel it now under More, Guardian recovery.',
      ready);
  }
  if (security && now < big(security.frozen_until_elapsed_micros)) {
    const end = due(security.frozen_until_elapsed_micros);
    add(`frozen:${security.freezes}`, true, 'Your account is frozen',
      `Nothing can be paid with your payment password alone, and nobody can sign in with this account. The freeze ends by itself ${at(end)}.${security.pending_root ? ' The replacement of your keys keeps the account frozen after that.' : ''} If you did not freeze it, someone has your payment password or your recovery words: make new ones ${CHANGE}.`,
      end);
  }
  for (const p of security?.pending_payments || []) {
    const ready = due(p.ready_elapsed_micros);
    add(`payment-waiting:${p.id}`, true, 'A payment is waiting',
      `A payment of ${seconds(p.amount)} to account ${p.to} is waiting. It can go through ${big(p.ready_elapsed_micros) <= now ? 'now' : at(ready)} unless it is cancelled. If you did not start it, cancel it now ${WAITING}, then ${FREEZE}.`,
      ready);
  }
  if (security?.pending_limit) {
    const raise = security.pending_limit, ready = due(raise.ready_elapsed_micros);
    add(`limit-waiting:${raise.id}`, true, 'A higher daily limit is waiting',
      `Your daily limit is to rise from ${seconds(security.policy.daily_limit_micros)} to ${seconds(raise.daily_limit_micros)}. It takes effect ${at(ready)} unless it is cancelled. If you did not ask for it, cancel it now ${WAITING}, then ${FREEZE}.`,
      ready);
  }

  // ---- what changed since this browser last confirmed
  const before = readMarker(seen, accountId);
  const goesBack = before && (big(marker.auth_epoch) < big(before.auth_epoch) || big(marker.nonce) < big(before.nonce) || (before.secured && !marker.secured)
    || (before.secured && marker.secured && ['version', 'freezes', 'next_id'].some(f => big(marker[f]) < big(before[f]))));
  // A counter that went back is not of this account as it was seen (another chain under the same name, or a marker
  // stored by something else): nothing is said about changes, as on a first look.
  if (before && !goesBack) {
    const added = role => keys[role].filter(k => !before.keys[role].includes(k)), removed = role => before.keys[role].filter(k => !keys[role].includes(k));
    const epoch = marker.auth_epoch;
    const secured = !before.secured && marker.secured;
    const powers = role => added(role).length + removed(role).length > 0;
    let explainedEpoch = 0n, explainedVersion = 0n, unexplained = [], installs = 0n;
    if (secured) {
      add(`secured:${epoch}`, true, 'Your account was protected with new keys',
        'This account now has a login password, a payment password and recovery words in place of its old key. If you did not do this, the account is no longer under your control: get help now.');
      explainedEpoch += 1n;
    }
    if (!before.secured && !marker.secured) {
      // Protocol 4: a key is added or removed (kinds 8 and 9), one per action, each moving the authority epoch by one.
      for (const role of KEY_ROLES) {
        for (const k of added(role)) { add(`key-added:${k}:${epoch}`, true, 'A key was added to your account', `${P4_KEY[role]} (${short(k)}) was added to this account. If you did not add it, someone has a key of this account: remove every key you do not know now, under More, Devices.`); explainedEpoch += 1n; }
        for (const k of removed(role)) { add(`key-removed:${k}:${epoch}`, true, 'A key was removed from your account', `${P4_KEY[role]} (${short(k)}) was removed from this account. The browser that held it can no longer use the account. If you did not remove it, someone has a key of this account: get help now.`); explainedEpoch += 1n; }
      }
      // A guardian policy set or changed (kind 11) moves the recovery version and the epoch together.
      if (marker.recovery_version !== null && before.recovery_version !== null && big(marker.recovery_version) > big(before.recovery_version)) explainedEpoch += big(marker.recovery_version) - big(before.recovery_version);
    } else if (before.secured && marker.secured) {
      const was = before, is = marker, versionMoved = big(is.version) > big(was.version);
      const replaced = versionMoved && (powers('spend') || powers('recover'));
      const rulesChanged = ['threshold', 'delay_seconds', 'freeze_seconds'].some(f => was.policy[f] !== is.policy[f]);
      const oldLimit = big(was.policy.daily_limit_micros), newLimit = big(is.policy.daily_limit_micros);
      // A raise that waited is in force without an operation of several keys. Nothing else raises the limit without
      // moving the version (a raise by the payment key waits; one at once is a root operation), whether the engine
      // applied it at a later action of the account or only this read does (settle).
      const raiseTookEffect = newLimit > oldLimit && !versionMoved;
      const installedSameKeys = versionMoved && !replaced && (rulesChanged || (newLimit > oldLimit && !raiseTookEffect));
      if (replaced) {
        if (powers('spend')) add(`keys-replaced:v${is.version}:e${epoch}`, true, 'Your keys were replaced',
          `The payment key of this account was replaced${powers('recover') ? ', and its recovery words too' : ''}. Everything that was waiting was dropped. If you did not do this, the account is no longer under your control: get help now.`);
        else add(`recovery-replaced:v${is.version}:e${epoch}`, true, 'Your recovery words were replaced',
          'The recovery words of this account were replaced: the old ones no longer work. Everything that was waiting was dropped. If you did not do this, someone holds your payment password and your recovery words: get help now.');
      }
      if (rulesChanged && versionMoved) add(`rules-changed:v${is.version}`, true, 'The rules of your account changed', `The rules of this account changed at once: now ${rulesWords(is.policy)}. ${together(was.policy)} If you did not change them, someone holds those keys: get help now.`);
      if (newLimit !== oldLimit) {
        const id = `limit-changed:${oldLimit}-${newLimit}:v${is.version}`;
        if (newLimit < oldLimit) add(id, false, 'Your daily limit was lowered', `Your daily limit is now ${seconds(newLimit)} (it was ${seconds(oldLimit)}). If you did not lower it, someone has your payment password: ${FREEZE}, then make a new payment password ${CHANGE}.`);
        else if (raiseTookEffect) add(id, false, 'Your daily limit was raised', `Your daily limit is now ${seconds(newLimit)} (it was ${seconds(oldLimit)}): the raise that waited took effect. Your payment key can now pay that much a day without waiting.`);
        else add(id, true, 'Your daily limit was raised', `Your daily limit rose at once from ${seconds(oldLimit)} to ${seconds(newLimit)}, without the wait. ${together(was.policy)} If you did not ask for it, someone holds those keys: get help now.`);
      }
      // Login keys: a payment key adds and removes them at once, each action moving the authority epoch by one.
      if (!replaced) {
        for (const k of added('signin')) { add(`signin-added:${k}:${epoch}`, true, 'A login key was added', `A login key (${short(k)}) was added to this account. It can sign in to websites as you. If you did not add it, someone has your payment password: ${FREEZE}.`); explainedEpoch += 1n; }
        for (const k of removed('signin')) { add(`signin-removed:${k}:${epoch}`, true, 'A login key was removed', `A login key (${short(k)}) was removed from this account. The browser that held it can no longer sign in. If you did not remove it, someone has your payment password: ${FREEZE}.`); explainedEpoch += 1n; }
      }
      // Freezes: the count only grows, so a freeze that began and ended between two looks is still seen.
      const freezes = big(is.freezes) - big(was.freezes), active = now < big(security.frozen_until_elapsed_micros);
      if (freezes > (active ? 1n : 0n)) add(`freeze-over:${was.freezes}-${is.freezes}`, true, 'Your account was frozen meanwhile',
        `Since this browser last looked, this account was frozen, and that freeze is over. If you did not freeze it, someone has your payment password or your recovery words: make new ones ${CHANGE}.`);
      // What explains the version: each operation of several keys moves it by one.
      const asked = Boolean(is.root) && (!was.root || was.root.ready !== is.root.ready);
      const rootGone = Boolean(was.root) && (!is.root || was.root.ready !== is.root.ready);
      const rootCancelled = rootGone && big(was.root.expires) >= now && !replaced && !installedSameKeys;
      const lifted = big(was.frozen_until) > big(was.clock) && is.frozen_until === '0' && !replaced && !installedSameKeys;
      explainedVersion = (replaced ? 1n : 0n) + (installedSameKeys ? 1n : 0n) + (asked ? 1n : 0n) + (rootCancelled ? 1n : 0n) + (lifted ? 1n : 0n);
      if (big(is.version) - big(was.version) > explainedVersion) unexplained.push(`v${was.version}-${is.version}`);
      if (replaced || installedSameKeys) { explainedEpoch += 1n; installs = 1n; }
      // What explains the number of waiting items: those waiting now, and a raise that took effect.
      const started = big(is.next_id) - big(was.next_id);
      const visible = BigInt(security.pending_payments.filter(p => big(p.id) >= big(was.next_id)).length) + (security.pending_limit && big(security.pending_limit.id) >= big(was.next_id) ? 1n : 0n) + (raiseTookEffect ? 1n : 0n);
      if (started > visible) unexplained.push(`n${was.next_id}-${is.next_id}`);
    }
    if (big(epoch) - big(before.auth_epoch) > explainedEpoch) unexplained.push(`e${before.auth_epoch}-${epoch}`);
    if (unexplained.length) add(`unexplained:${unexplained.join(':')}`, true, 'Something changed that this wallet cannot show',
      `Since this browser last looked, something happened on this account that this wallet cannot show in detail, such as a payment approved with several keys, a change of keys made and undone, or a payment or a change of the limit that waited and is gone. If it was not you, someone holds your keys: ${FREEZE}, then get help.`);
    // Actions signed with the account's keys: each ordinary action takes the account's next nonce, and a change of keys
    // put in force at once moves it by one more (security.rs, `install`). Payments wake nobody, so a stolen payment key
    // is seen here or nowhere. Counted only from a marker of a page that keeps the nonce of what it sends.
    const signed = big(marker.nonce) - big(before.nonce) - installs;
    if (before.v === 2 && Number.isSafeInteger(sent) && sent >= 0 && signed > 0n) {
      const mine = BigInt(sent) < signed ? BigInt(sent) : signed;
      if (signed > mine) add(`actions:n${before.nonce}-${marker.nonce}`, mine === 0n && signed >= 3n, 'Actions were signed with your keys',
        `${signed} action${signed === 1n ? ' was' : 's were'} signed with your keys since you last looked here. This browser sent ${mine === 0n ? 'none' : mine} of them. If the others were not you on another device, ${marker.secured ? `make a new payment password ${CHANGE}` : 'someone has a key of this account: remove every key you do not know now, under More, Devices'}.`);
    }
  }

  // Most urgent first; within the same urgency, in the order above.
  const ordered = [...alerts.filter(a => a.urgent), ...alerts.filter(a => !a.urgent)];
  return { alerts: ordered, marker };
}
