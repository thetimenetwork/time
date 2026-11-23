// The card "Protection" on Home: what it says for each state of a protected account, and what "Pause payments" is.
//
// Everything here is a function of its arguments: no page and no network, and the one record it keeps in the browser
// (the limit an account had before a pause) goes through a storage that is passed in. security-ui.mjs draws the card
// from it and signs; security-flows.mjs builds what is signed.
//
// What the card stands on are the engine's rules for a protected account (v5/src/security.rs, read on 2026-11-22):
// - The daily limit is an allowance that refills evenly over 24 hours and never holds more than the limit (`level`).
//   Every action the payment key signs with a nonce is charged to it, fee included (`charge`): a payment, the two steps
//   of a payment that waits (kind 75), a change of the limit (kind 77), a change of login keys (kind 71), staking.
// - A lower limit applies at once and cuts what is left to it; a higher one waits `delay_seconds` and can be cancelled
//   (kind 77). No limit is refused for being small: zero is accepted.
// - A freeze (kind 72) lasts `freeze_seconds` from the block that holds it, ends by itself, drops what was waiting, and
//   can be placed again only once half of it has passed. It is charged to the balance, not to the allowance.
// - The payment key and one recovery key together change the keys or the policy at once (kind 73, "replace"). The
//   allowance is not filled by that: it keeps what was left under the old limit and refills from there. What was
//   waiting is dropped, a freeze ends, and the account's authority epoch moves on.
//
// What follows for a pause. A limit of zero is accepted, and with it the payment key alone can do nothing that costs a
// fee: it cannot even start a payment that waits, or ask for a higher limit, because the fee of either is charged to
// an allowance that stays at zero. So "Pause payments" sets the limit to exactly the fee of one action (`pauseLimit`):
// no payment of any amount fits (a payment costs its amount and the fee), and the payment key can still start what
// waits in the open and can be cancelled. An account whose limit is below the fee (set by another wallet) is shown as
// what it is (`shut`): only the payment key with a recovery paper sets a limit again.
const MICROS = 1000000n, DAY_MICROS = 86400n * MICROS;
const U64 = 1n << 64n;
/// A moment of the card in words: `word` and its date ("at 12/1/2026, 10:00:00 AM"), or "not before" and its date while
/// that date is only the earliest the moment can come (`words.later`: on a network whose waits survive a stop of the
/// chain, a later stop moves it). Every moment here is on the clock of the waits (security-flows.mjs, waitsOf).
const moment = (words, at, word) => `${words.later?.(at) ? 'not before' : word} ${words.when(at)}`;

// ------------------------------------------------------------------ the row as the chain will next read it
/// The daily limit in force at `now`: a raise whose waiting period is over applies, although the stored row still
/// shows the old limit until the account's next action (the engine brings the row up to date first, `settle`).
export function effectiveLimit(row, now) {
  const raise = row.pending_limit;
  return raise && BigInt(raise.ready_elapsed_micros) <= BigInt(now) ? BigInt(raise.daily_limit_micros) : BigInt(row.policy.daily_limit_micros);
}
/// The raise of the limit that is still waiting at `now`, or null.
export function waitingRaise(row, now) {
  const raise = row.pending_limit;
  return raise && BigInt(raise.ready_elapsed_micros) > BigInt(now) ? { id: raise.id, limit: BigInt(raise.daily_limit_micros), ready: BigInt(raise.ready_elapsed_micros) } : null;
}

// ------------------------------------------------------------------ pause
/// The limit of a paused account: the fee of one action, and nothing above it.
export const pauseLimit = feeMicros => BigInt(feeMicros).toString();
/// 'off': payments within the limit work. 'paused': the limit is exactly one fee, so nothing is paid at once and what
/// waits can still be started. 'shut': the limit is below one fee, so the payment key alone can start nothing.
export function pauseState(row, now, feeMicros) {
  const limit = effectiveLimit(row, now), fee = BigInt(feeMicros);
  return limit > fee ? 'off' : limit === fee ? 'paused' : 'shut';
}
/// How long until an allowance of `allowance` under `limit` holds `fee` again, in microseconds (0 if it does).
export function untilFeeCovered({ allowance, limit, feeMicros }) {
  const fee = BigInt(feeMicros), left = BigInt(allowance), cap = BigInt(limit);
  if (left >= fee) return 0n;
  if (cap < fee || cap === 0n) return null;
  return ((fee - left) * DAY_MICROS + cap - 1n) / cap;
}

// The limit the account had before the pause, remembered in this browser so that ending the pause can offer it.
// Nothing secret: the limit is public on the chain while it is in force. It is a suggestion and no more: the person
// sees the number before signing, and whatever can write this browser's storage can change it.
export const pauseKey = (networkId, name) => `timecurrency.pause.v1:${networkId}:${name}`;
const limitText = value => (typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) < U64 ? value : null);
export function rememberLimit(storage, key, limitMicros, atMs) {
  const limit = limitText(String(limitMicros)); if (limit === null) return false;
  try { storage.setItem(key, JSON.stringify({ limit, at: Number(atMs) })); return true; } catch { return false; }
}
/// The remembered limit in microseconds (a string), or null: nothing is kept, or what is kept is not a limit.
export function rememberedLimit(storage, key) {
  try { return limitText(JSON.parse(storage.getItem(key) ?? 'null')?.limit); } catch { return null; }
}
export function forgetLimit(storage, key) { try { storage.removeItem(key); } catch { /* nothing to forget */ } }
/// A record no pause stands behind is dropped: the account is not paused, and the record is older than ten minutes
/// (a pause signed a moment ago may not be in proven state yet).
export const REMEMBER_GRACE_MS = 10 * 60 * 1000;
export function settleRemembered(storage, key, paused, nowMs) {
  if (paused) return;
  let raw = null; try { raw = storage.getItem(key); } catch { return; }
  if (raw === null) return;
  let at = null; try { at = JSON.parse(raw)?.at ?? null; } catch { at = null; }
  if (!(typeof at === 'number' && nowMs - at < REMEMBER_GRACE_MS)) forgetLimit(storage, key);
}

// ------------------------------------------------------------------ the card
/// What the card shows for a protected account, from its proven security row.
/// `allowance` and `frozen` are the wallet library's readings of the row at `now` (client-v4/account-security.mjs).
/// `waiting`: how many payments and how many changes (a raise of the limit, a change of all keys) wait.
/// `words`: how the page writes amounts and times: `seconds(micros)` ("600 seconds"), `plain(micros)` ("600"),
/// `duration(secondsText)` ("48 hours"), `when(elapsedMicros)` (a date), `roughly(micros)` ("about 47 hours"), and
/// `later(elapsedMicros)`, true when that date is only the earliest the moment can come (left out: never).
/// `now` is the clock of the waits (security-flows.mjs, waitsOf), and so is every moment of the row.
export function protectionView({ row, now, feeMicros, allowance, frozen, waiting = { payments: 0, changes: 0 }, words }) {
  const at = BigInt(now), fee = BigInt(feeMicros), left = BigInt(allowance), limit = effectiveLimit(row, at);
  const until = BigInt(row.frozen_until_elapsed_micros), length = BigInt(row.policy.freeze_seconds) * MICROS;
  const byFreeze = until > at, replacing = Boolean(frozen) && Boolean(row.pending_root), raise = waitingRaise(row, at);
  const pause = pauseState(row, at, fee), delay = words.duration(row.policy.delay_seconds), lasts = words.duration(row.policy.freeze_seconds);

  // The freeze: how long it lasts, that it ends by itself, and how it is kept on.
  const canRenew = byFreeze && until - at <= length / 2n;
  let freezeNote;
  if (byFreeze) {
    freezeNote = 'It ends by itself at that time and is not renewed by itself. ' + (canRenew
      ? `To keep the account frozen, freeze again now: the freeze then lasts ${lasts} from that moment.`
      : `To keep the account frozen longer, freeze again ${moment(words, until - length / 2n, 'after')}: a freeze can be renewed in its second half only.`);
    if (replacing) freezeNote += ' A change of all your keys is waiting too: the account stays frozen until that is finished or cancelled.';
  } else if (frozen) freezeNote = 'The account stays frozen until that change is finished or cancelled. See “Waiting on your account” below.';
  else freezeNote = `For ${lasts}: no payment with your payment password alone, and no sign-in to websites. It ends by itself. What is waiting is dropped.`;

  // The daily limit: what can be paid now without waiting, out of the limit. Paused or frozen, that is nothing.
  let limitWords;
  if (pause !== 'off') limitWords = 'Paused: nothing can be paid at once.';
  else if (frozen) limitWords = `Nothing can be paid with your payment password alone while the account is frozen. Your daily limit is ${words.seconds(limit)}.`;
  else if (left <= fee) limitWords = `Nothing can be paid right now: less than one fee is left of your ${words.seconds(limit)} a day. It refills over 24 hours.`;
  else limitWords = `You can pay ${words.plain(left)} of ${words.seconds(limit)} now without waiting, fees included.${left < limit ? ' It refills over 24 hours.' : ''}`;
  if (raise && pause === 'off') limitWords += ` A raise to ${words.seconds(raise.limit)} is waiting: it applies ${moment(words, raise.ready, 'at')}.`;

  // The pause: what still can happen, said plainly.
  const feeIn = untilFeeCovered({ allowance: left, limit, feeMicros: fee });
  let pauseNote, waitNote = '';
  if (pause === 'off') pauseNote = frozen ? 'The account is frozen: nothing can be paid at once, paused or not.' : `While paused, nothing can be paid at once. A payment started then waits ${delay} and you can cancel it.`;
  else if (pause === 'paused') {
    pauseNote = `Nothing can be paid at once. A payment started now waits ${delay} and you can cancel it.`;
    if (feeIn > 0n) pauseNote += ` Starting one costs a fee, and your paused limit covers one fee a day: the next one in ${words.roughly(feeIn)}.`;
  } else pauseNote = `Your daily limit is ${words.seconds(limit)}, less than the fee of one action. Your payment password alone can neither pay nor start a payment that waits. It can still freeze the account and cancel what is waiting.`;
  if (pause !== 'off' && raise) pauseNote += ` The pause ends ${moment(words, raise.ready, 'at')} (${words.roughly(raise.ready - at)}): your limit is then ${words.seconds(raise.limit)}.`;
  if (pause !== 'off' && frozen) pauseNote += ' The account is frozen as well.';
  const waitPossible = pause === 'paused' && !frozen && feeIn === 0n;
  if (pause === 'shut') waitNote = 'Not possible: with a limit below the fee, your payment password alone cannot ask for a higher one.';
  else if (pause === 'paused' && frozen) waitNote = 'Not possible while the account is frozen.';
  else if (pause === 'paused' && feeIn > 0n) waitNote = `Not possible right now: asking costs a fee, and your paused limit covers one fee a day. It covers the next one in ${words.roughly(feeIn)}.`;
  else if (pause === 'paused') waitNote = `Your limit comes back after ${delay}. You can cancel that meanwhile.${raise ? ' A request is waiting already: asking again starts the wait again.' : ''}`;

  let status;
  if (byFreeze) status = { alert: true, text: words.later?.(until) ? `Your account is frozen. It ends not before ${words.when(until)} (${words.roughly(until - at)}).` : `Your account is frozen until ${words.when(until)} (${words.roughly(until - at)}).` };
  else if (frozen) status = { alert: true, text: 'Your account is frozen while a change of all your keys waits.' };
  else if (pause !== 'off') status = { alert: false, text: 'Payments are paused.' };
  else status = { alert: false, text: 'Your account is protected.' };

  return {
    status,
    // `locked`: the switch cannot be used: the account is frozen by a waiting change of keys, not by a freeze.
    freeze: { on: Boolean(frozen), byFreeze, locked: Boolean(frozen) && !byFreeze, state: frozen ? 'On' : 'Off', note: freezeNote, canRenew, canEnd: byFreeze, lasts },
    limit: { perMille: pause !== 'off' || frozen || limit === 0n ? 0 : Number(left * 1000n / limit), text: limitWords, canChange: pause === 'off' && !frozen, value: limit },
    pause: { on: pause !== 'off', kind: pause, locked: Boolean(frozen), state: pause === 'off' ? 'Off' : 'On', note: pauseNote, waitPossible, waitNote, ending: pause !== 'off' ? raise : null },
    waiting: waitingWords(waiting),
  };
}
/// One line on what waits: the items themselves, each with its "Cancel", are in the list under the card.
export function waitingWords({ payments = 0, changes = 0 } = {}) {
  if (!payments && !changes) return 'Nothing is waiting.';
  const parts = [];
  if (payments) parts.push(`${payments} payment${payments === 1 ? '' : 's'}`);
  if (changes) parts.push(`${changes} change${changes === 1 ? '' : 's'}`);
  return `${parts.join(' and ')} ${payments + changes === 1 ? 'is' : 'are'} waiting. See “Waiting on your account” below: each can be cancelled.`;
}

// ------------------------------------------------------------------ what a change of the limit will do, said before it is confirmed
/// 'empty' | 'too-low' | 'same' | 'lower' | 'raise-wait' | 'raise-now', with the sentence the form shows.
/// `next` is the typed limit in microseconds or null; `withPaper`: a recovery paper was typed.
export function limitChange({ current, next, feeMicros, delay, withPaper = false, words }) {
  if (next === null || next === undefined) return { kind: 'empty', text: '' };
  const now = BigInt(current), then = BigInt(next), fee = BigInt(feeMicros);
  if (then <= fee) return { kind: 'too-low', text: `A limit must be above the network fee of ${words.seconds(fee)}. To stop payments, use “Pause payments”.` };
  if (then === now) return { kind: 'same', text: 'That is your limit now.' };
  if (then < now) return { kind: 'lower', text: 'Lower than now: it applies at once.' };
  if (withPaper) return { kind: 'raise-now', text: 'Higher than now, with a recovery paper: it applies at once. What is waiting is cancelled, and websites sign you out.' };
  return { kind: 'raise-wait', text: `Higher than now: it waits ${delay}, and you can cancel it meanwhile. With a recovery paper it applies at once.` };
}

// ------------------------------------------------------------------ the reviews of the card's own steps
// Each is the list of fields the review shows before anything is signed. They say what the chain will do.
export function pauseReview({ row, now, feeMicros, words }) {
  const fee = BigInt(feeMicros), delay = words.duration(row.policy.delay_seconds), raise = waitingRaise(row, now);
  return [
    ['Daily limit now', `${words.seconds(effectiveLimit(row, now))} a day`],
    ['While paused', `Your payment password alone can pay nothing at once. A payment started then waits ${delay}, and you can cancel it.`],
    ['How', `The limit becomes ${words.seconds(fee)}, the fee of one action: enough to start one payment that waits, or to ask for your limit back, once a day.`],
    ...(raise ? [['Also', `The waiting raise of your limit to ${words.seconds(raise.limit)} is dropped.`]] : []),
    ['To end the pause', `Your limit comes back after ${delay} of waiting, or at once with a recovery paper. What you can pay at once then fills up again over 24 hours.`],
    ['Fee', words.seconds(fee)],
  ];
}
export function resumeWaitReview({ row, now, limitMicros, feeMicros, words }) {
  const delay = words.duration(row.policy.delay_seconds), ready = BigInt(now) + BigInt(row.policy.delay_seconds) * MICROS;
  return [
    ['Daily limit', `Back to ${words.seconds(limitMicros)} a day`],
    ['When', `After ${delay}, ${words.later?.(ready) ? 'not before' : 'at about'} ${words.when(ready)}. Until then payments stay paused, and you can cancel this under “Waiting on your account”.`],
    ['Then', 'What you can pay at once fills up over the following 24 hours.'],
    ['Fee', words.seconds(feeMicros)],
  ];
}
/// A limit set at once by the payment key and one recovery paper: to end a pause, or to raise a limit without waiting.
export function limitNowReview({ row, now, limitMicros, allowance, feeMicros, waiting = { payments: 0, changes: 0 }, words }) {
  const kept = BigInt(allowance) < BigInt(limitMicros) ? BigInt(allowance) : BigInt(limitMicros), count = waiting.payments + waiting.changes;
  return [
    ['Daily limit', `${words.seconds(limitMicros)} a day, at once (now ${words.seconds(effectiveLimit(row, now))})`],
    ['Approved by', 'Your payment password and one recovery paper'],
    ['Also', `${count ? `What is waiting on your account (${waitingCount(waiting)}) is cancelled. ` : 'Anything waiting on your account is cancelled. '}Websites sign you out.`],
    ['Then', `What you can pay at once starts at ${words.seconds(kept)} and fills up over 24 hours.`],
    ['Fee', words.seconds(feeMicros)],
  ];
}
const waitingCount = ({ payments, changes }) => [payments ? `${payments} payment${payments === 1 ? '' : 's'}` : '', changes ? `${changes} change${changes === 1 ? '' : 's'}` : ''].filter(Boolean).join(' and ');

// ------------------------------------------------------------------ a validator's operation with the payment key
// What the engine does with a validator's registration (kind 17), an addition to its bond (18), taking the bond out
// (19), retiring it (24), and the withdrawal of what was taken out (21), signed by a protected account (v5/src/engine.rs,
// `apply`, the branch of kinds 5 to 7 and 17 to 24, read on 2026-11-23):
// - only a key with `can_spend` signs them: the payment key, never the login key or a recovery key;
// - what the action takes out of the balance, fee included, is charged to the allowance, after the action ran
//   (`security.spend(before.saturating_sub(balance), now)`, on the clock of the waits): the bond and the fee of a
//   registration, the amount and the fee of an addition, the fee of taking out and of retiring. A withdrawal brings the
//   seconds back, and is charged only what it brings back less than the fee;
// - while the account is frozen such a charge is refused (security.rs, `Security::spend`), and so is one above what is
//   left of the allowance (`charge`);
// - nothing of it waits and no recovery paper pays it: what waits is a payment (kind 75), and a root operation pays
//   transfers only (security.rs, `Operation::Pay`). The limit itself can be raised: that waits `delay_seconds`, or
//   applies at once with a recovery paper, and either way the allowance then fills up under the new limit over 24 hours.
// So the wallet says why it is refused, and what to do, before any review (`refusal`), and the review says what it
// uses of the daily limit (`line`). `check`: security-flows.mjs, checkStake, at `now`, the clock of the waits. `kind`: of
// security-flows.mjs, VALIDATOR_KINDS, or 'withdraw_stake' or 'undelegate'. `words` as for protectionView.
const USES = { register_validator: ['The bond and the fee', true], self_bond: ['The amount and the fee', true] };
const DOING = { register_validator: 'registering a validator', self_bond: 'adding to a validator\'s bond', self_unbond: 'taking a validator\'s bond out', retire_validator: 'retiring a validator' };
const wholeSeconds = micros => ((BigInt(micros) + MICROS - 1n) / MICROS) * MICROS;
export function validatorLimit({ kind, check, row, now, words }) {
  const [what, both] = USES[kind] ?? ['The fee', false], are = both ? 'are' : 'is';
  const total = BigInt(check.total), left = BigInt(check.allowance);
  if (check.mode === 'frozen') return { refusal: DOING[kind] ? `Your account is frozen, so ${DOING[kind]} is refused until the freeze ends. See Home.` : check.reason };
  if (check.mode === 'blocked') return { refusal: `The account does not hold ${what.toLowerCase()}, ${words.seconds(total)}.` };
  if (check.mode === 'over') {
    const limit = effectiveLimit(row, now), none = 'and the network lets none of it wait or be paid with a recovery paper';
    if (total > limit) return { refusal: `${what}, ${words.seconds(total)}, ${are} more than your daily limit of ${words.seconds(limit)}, ${none}: raise the limit on Home to at least ${words.seconds(wholeSeconds(total))} (it waits ${words.duration(row.policy.delay_seconds)}, or applies at once with a recovery paper), then try again once it has filled up, within a day.` };
    const back = BigInt(now) + ((total - left) * DAY_MICROS + limit - 1n) / limit;
    return { refusal: `${what}, ${words.seconds(total)}, ${are} more than the ${words.seconds(left)} left of your daily limit today, ${none}: try again ${moment(words, back, 'after')}, when enough of it has come back.` };
  }
  if (kind === 'withdraw_stake') return { line: 'The seconds come back to your balance: nothing of your daily limit is used, unless less than the fee comes back.' };
  return { line: `${what}, ${words.seconds(total)}, ${both ? 'count' : 'counts'} against your daily limit: ${words.seconds(left)} is left today, ${words.seconds(left - total)} after this.` };
}
