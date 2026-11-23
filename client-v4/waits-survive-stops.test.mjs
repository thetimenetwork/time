// Waits that survive a stop (`waits_survive_stops` in a network's genesis): what the SDK reads of the rule
// from a verified state, the clock it gives the wallet library, and how it turns a moment stored in a
// security row into a date. The rule itself is the engine's (v5/src/security.rs, "The clock of the waits")
// and is tested there (v5/tests/waits_survive_stops.rs); the numbers of the first example below are the ones
// of that file's test of a waiting payment.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import './time-sdk.js';
import * as security from './account-security.mjs';
import { createLoginService } from './server-auth.mjs';

const SDK = globalThis.TimeSDK;
const SECOND = 1_000_000n, MINUTE = 60n * SECOND, HOUR = 60n * MINUTE, DAY = 24n * HOUR;
// The genesis time of the engine's test networks, in microseconds since 1970.
const GENESIS = 1_800_000_000n * SECOND;
/// The part of a verified state the helpers read: the chain's time, the genesis time, the setting and,
/// on a network with the rule, the total of its stops.
function stateAt(elapsed, stopped) {
  const state = { time_micros: (GENESIS + elapsed).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: {} };
  if (stopped !== undefined) { state.config.waits_survive_stops = true; state.stopped_micros = stopped.toString(); }
  return state;
}

test('the rule and the total of stops are read from a verified state, and from nothing else', () => {
  const without = stateAt(5n * HOUR), withRule = stateAt(5n * HOUR, 3n * HOUR);
  assert.equal(SDK.waitsSurviveStops(without), false);
  assert.equal(SDK.waitsSurviveStops(withRule), true);
  assert.equal(SDK.stoppedMicros(without), '0');
  assert.equal(SDK.stoppedMicros(withRule), (3n * HOUR).toString());
  // A network writes the setting as `true` or leaves it out; nothing else is a setting.
  for (const written of [false, 'true', 1, null, {}]) {
    assert.throws(() => SDK.waitsSurviveStops({ ...withRule, config: { waits_survive_stops: written } }), /Unsupported setting for waits/);
  }
  // No state, or a state without the network configuration, says nothing about the rule.
  assert.throws(() => SDK.waitsSurviveStops(undefined), /A verified state is required/);
  assert.throws(() => SDK.waitsSurviveStops({ time_micros: '1', genesis: { genesis_time_micros: '0' } }), /carries the network configuration/);
  assert.throws(() => SDK.stoppedMicros({ time_micros: '1', genesis: { genesis_time_micros: '0' } }), /carries the network configuration/);
  // The engine writes the total exactly on a network with the rule. Any other pairing is refused, never guessed.
  assert.throws(() => SDK.stoppedMicros({ ...without, stopped_micros: '0' }), /belongs to a network whose waits survive a stop/);
  assert.throws(() => SDK.stoppedMicros({ ...withRule, stopped_micros: undefined }), /belongs to a network whose waits survive a stop/);
  for (const written of [7, '07', '-1', '1.5', '', null]) {
    assert.throws(() => SDK.stoppedMicros({ ...withRule, stopped_micros: written }), /belongs to a network|canonical u64/);
  }
  // More stops than time is not a state of any chain.
  assert.throws(() => SDK.stoppedMicros(stateAt(HOUR, HOUR + 1n)), /The stops exceed the time of the chain/);
  assert.equal(SDK.stoppedMicros(stateAt(HOUR, HOUR)), HOUR.toString());
});

test('the clock of account security is the time of the chain minus its stops', () => {
  assert.equal(SDK.securityNow(stateAt(5n * HOUR)), (5n * HOUR).toString());
  assert.equal(SDK.securityNow(stateAt(5n * HOUR, 0n)), (5n * HOUR).toString());
  assert.equal(SDK.securityNow(stateAt(5n * HOUR, 3n * HOUR)), (2n * HOUR).toString());
  assert.equal(SDK.securityNow(stateAt(3n * DAY, 3n * DAY - HOUR)), HOUR.toString());
});

test('a stored moment becomes a date: exact without the rule, the earliest possible one with it', () => {
  // A payment asked for when the chain had run for 22 minutes, with a wait of three hours.
  const asked = 22n * MINUTE, stored = asked + 3n * HOUR;
  // Without the rule the stored moment is the time of the chain, as it always was.
  const plain = SDK.securityDeadline(stateAt(asked + HOUR), stored.toString());
  assert.deepEqual(plain, { due: false, remainingMicros: (2n * HOUR).toString(), elapsedMicros: stored.toString(), timeMicros: (GENESIS + stored).toString(), earliest: false });
  assert.equal(SDK.securityDeadline(stateAt(stored), stored).due, true);
  assert.equal(SDK.securityDeadline(stateAt(stored - 1n), stored).due, false);

  // With the rule: the chain ran for an hour, then stood still for ten hours, of which one counts.
  const afterStop = stateAt(asked + HOUR + 10n * HOUR, 9n * HOUR);
  assert.equal(SDK.securityNow(afterStop), (asked + 2n * HOUR).toString());
  const waiting = SDK.securityDeadline(afterStop, stored.toString());
  assert.deepEqual(waiting, {
    due: false, remainingMicros: HOUR.toString(),
    // One more hour of chain: at the earliest when the chain's time is the stored moment plus the stops so far.
    elapsedMicros: (stored + 9n * HOUR).toString(), timeMicros: (GENESIS + stored + 9n * HOUR).toString(), earliest: true,
  });
  // Read as a time of the chain, the stored moment lies nine hours in the past: a client that does not know
  // the rule shows the payment as ready, and the chain refuses to complete it.
  assert.ok(stored < BigInt(afterStop.time_micros) - GENESIS);
  assert.equal(BigInt(waiting.timeMicros) - (GENESIS + stored), 9n * HOUR);
  // Another stop moves the date; the hour of it that counts brings the moment.
  const secondStop = stateAt(asked + 11n * HOUR + 5n * HOUR, 9n * HOUR + 4n * HOUR);
  assert.deepEqual(SDK.securityDeadline(secondStop, stored), { due: true, remainingMicros: '0', elapsedMicros: (stored + 13n * HOUR).toString(), timeMicros: (GENESIS + stored + 13n * HOUR).toString(), earliest: false });
  // Without a second stop it comes after the hour of chain that was left, exactly.
  const ran = stateAt(asked + 12n * HOUR, 9n * HOUR);
  assert.equal(SDK.securityDeadline(ran, stored).due, true);
  assert.equal(SDK.securityDeadline(ran, stored).elapsedMicros, (asked + 12n * HOUR).toString());
  assert.equal(SDK.securityDeadline(stateAt(asked + 12n * HOUR - 1n, 9n * HOUR), stored).due, false);
  // A stored moment is a canonical decimal, as the engine writes it.
  for (const written of ['01', '-5', 'soon', '']) assert.throws(() => SDK.securityDeadline(afterStop, written), /canonical u64/);
});

test('the wallet library reads a security row on that clock: a freeze, a wait and the allowance', () => {
  // An account frozen for four hours when the chain had run for two; then a stop of twelve hours.
  const frozenAt = 2n * HOUR, until = frozenAt + 4n * HOUR, limit = 480_000n;
  const row = {
    version: '1', policy: security.policy({ threshold: 2, dailyLimitMicros: limit, delaySeconds: 10800, freezeSeconds: 14400 }),
    allowance_micros: '0', allowance_elapsed_micros: frozenAt.toString(), frozen_until_elapsed_micros: until.toString(), freezes: '1',
    pending_limit: null, pending_payments: [], next_id: '1', pending_root: null,
  };
  const state = stateAt(frozenAt + 30n * MINUTE + 12n * HOUR, 11n * HOUR);
  const now = SDK.securityNow(state), chainTime = (BigInt(state.time_micros) - GENESIS).toString();
  assert.equal(now, (frozenAt + 90n * MINUTE).toString());
  // On the clock of the rules the account is frozen, as the chain holds it. On the chain's time it would
  // look free: this is what a client shows wrongly if it passes the chain's time.
  assert.equal(security.frozen(row, now), true);
  assert.equal(security.frozen(row, chainTime), false);
  assert.deepEqual(SDK.securityDeadline(state, row.frozen_until_elapsed_micros), {
    due: false, remainingMicros: (150n * MINUTE).toString(), elapsedMicros: (until + 11n * HOUR).toString(), timeMicros: (GENESIS + until + 11n * HOUR).toString(), earliest: true,
  });
  // The allowance refills on the same clock: an hour and a half of chain gives a sixteenth of the day's
  // limit, not the whole of it.
  assert.equal(security.allowance(row, now), limit / 16n);
  assert.equal(security.allowance(row, chainTime), limit * 25n / 48n);
  // A waiting replacement freezes until its claim window ends, on that clock as well.
  const replacing = { ...row, frozen_until_elapsed_micros: '0', pending_root: { ready_elapsed_micros: (frozenAt + HOUR).toString(), expires_elapsed_micros: (frozenAt + HOUR + 7n * DAY).toString() } };
  const late = stateAt(frozenAt + 20n * DAY, 19n * DAY);
  assert.equal(security.frozen(replacing, SDK.securityNow(late)), true);
  assert.equal(security.frozen(replacing, (20n * DAY + frozenAt).toString()), false);
});

test('a website keeps a frozen account signed out until the chain ends the freeze, whatever the stops', async () => {
  const origin = 'https://merchant.example', networkId = 'ab'.repeat(32);
  const pair = generateKeyPairSync('ed25519'), key = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const account = { id: '7', name: 'bob', auth_epoch: '2', devices: [{ public_key: key, can_manage: false, can_spend: false }, { public_key: other, can_manage: false, can_spend: true }].sort((a, b) => (a.public_key < b.public_key ? -1 : 1)) };
  const until = 6n * HOUR;
  const row = { account: '7', version: '1', policy: security.policy({ threshold: 2, dailyLimitMicros: 5, delaySeconds: 10800, freezeSeconds: 14400 }), allowance_micros: '5', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: until.toString(), freezes: '1', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  let at = stateAt(3n * HOUR, 0n);
  const service = createLoginService({ origin, networkId, verifiedState: async (query) => ({ verified: true, state: { ...at, network_id: networkId, height: '9', accounts: [account], recovery_cases: [], ...(query.include_security ? { security: [row] } : {}) } }) });
  const login = async () => {
    const issued = service.issue(), message = SDK.loginMessage(issued.challenge, { account, publicKey: key });
    return service.finish(issued.cookie, { message, signature: sign(null, SDK.loginBytes(message), pair.privateKey).toString('hex') });
  };
  await assert.rejects(login(), /frozen/);
  // The chain stood still for a day. Its time is far past the stored moment; the freeze has three hours of
  // chain left, less the one hour of the stop that counts.
  at = stateAt(3n * HOUR + DAY, DAY - HOUR);
  await assert.rejects(login(), /frozen/);
  at = stateAt(5n * HOUR + DAY - 1n, DAY - HOUR);
  await assert.rejects(login(), /frozen/);
  // Two more hours of chain end it.
  at = stateAt(5n * HOUR + DAY, DAY - HOUR);
  assert.equal((await login()).session.name, 'bob');
  // On a network without the rule the stored moment is the chain's time, as before.
  at = stateAt(until - 1n);
  await assert.rejects(login(), /frozen/);
  at = stateAt(until);
  assert.equal((await login()).session.name, 'bob');
  // A state that carries a total of stops without the rule is not one the engine writes: no sign-in on it.
  at = { ...stateAt(until), stopped_micros: '0' };
  await assert.rejects(login(), /belongs to a network whose waits survive a stop/);
});

test('a frozen owner of a validator is read on the same clock when signals are counted', () => {
  // signalFactsOf says whether an owner account is frozen; the engine counts a signal on the clock of the
  // account security rules.
  const key = 'cd'.repeat(32);
  const account = { id: '3', devices: [{ public_key: key, can_manage: false, can_spend: true }, { public_key: 'ef'.repeat(32), can_manage: true, can_spend: false }] };
  const row = { account: '3', frozen_until_elapsed_micros: (6n * HOUR).toString(), pending_root: null };
  const facts = (state) => SDK.signalFactsOf({ ...state, accounts: [account], recovery_cases: [], security: [row] }, ['3']).get('3');
  assert.equal(facts(stateAt(5n * HOUR)).stopped, 'frozen');
  assert.equal(facts(stateAt(6n * HOUR)).stopped, null);
  // A day of stop later the chain's time is past the stored moment, and the account is still frozen.
  assert.equal(facts(stateAt(4n * HOUR + DAY, DAY - HOUR)).stopped, 'frozen');
  assert.equal(facts(stateAt(5n * HOUR + DAY - 1n, DAY - HOUR)).stopped, 'frozen');
  assert.equal(facts(stateAt(5n * HOUR + DAY, DAY - HOUR)).stopped, null);
});
