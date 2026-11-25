import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import './time-sdk.js';
import { diffSecurity, reminders, snapshotOf, settle, EVENT_TYPES } from './security-watch.mjs';
import { createSecurityWatch, batches, memoryStore, fileStore, webhookAdapter, checkWebhookURL, verifyWebhookSignature, signWebhook, webhookSecretProblem, createFeed, createAlertServer, SIGNATURE_HEADER, EVENT_HEADER } from './security-watch-service.mjs';
import { validateConfig, start, readConfig, boundedFetch, claim, targetId } from '../deploy/watch/start.mjs';
import { spawn } from 'node:child_process';

const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const SDK = globalThis.TimeSDK;
// Real numbers: the genesis time of the live devnet fixture, the keys and the security row of the
// engine's export (account 5: one spend key, one sign-in key, three recovery keys, threshold 2,
// a daily limit of 0.5 s, waits of 60 s, freezes of 120 s), and the protocol fee of 1000 µs.
const GENESIS = '1794260994671000', FEE = 1000n, S = 1_000_000n;
const key = Object.fromEntries(fixture.secure.payload.keys.map((k) => [k.public_key.slice(0, 4), k.public_key]));
const device = (publicKey, role) => ({ public_key: publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const DEVICES = fixture.secure.payload.keys.map((k) => device(k.public_key, k.role));
const NEW_DEVICES = fixture.root.operation.keys.map((k) => device(k.public_key, k.role));
const BASE = { ...fixture.allowance.security, pending_limit: null, account: '5' };
const T0 = 2_407_000_000n; // elapsed micros of the fixture row

/// A verified state as the SDK returns it, for account 5 and any others.
function verified({ height, elapsed, balance = 50n * S, nonce = '3', epoch = '1', devices = DEVICES, security = BASE, others = [] }) {
  const accounts = [{ id: '5', name: 'alice', public_key: key['70df'], balance: String(balance), nonce, auth_epoch: epoch, devices, delegations: [], unbonding: [] }, ...others.map((id) => ({ id, name: `a${id}`, public_key: key['70df'], balance: '1', nonce: '0', auth_epoch: '0', devices: [], delegations: [], unbonding: [] }))];
  return { verified: true, height: String(height), state: { network_id: fixture.network_id, height: String(height), time_micros: (BigInt(GENESIS) + BigInt(elapsed)).toString(), genesis: { genesis_time_micros: GENESIS }, accounts, security: security ? [security] : [], config: {} } };
}
const snap = (options) => snapshotOf(verified(options), '5');
const types = (events) => events.map((e) => e.type);
const only = (events, type) => { const found = events.filter((e) => e.type === type); assert.equal(found.length, 1, `one ${type} in ${types(events)}`); return found[0]; };
const payment = { id: '2', to: '42', amount: String(12_500_000n), ready_elapsed_micros: String(T0 + 60n * S) };
const withPayment = { ...BASE, pending_payments: [payment], next_id: '3' };

test('every event carries a stable id, the account, its type, the height, a message and an urgency flag', () => {
  const events = diffSecurity(snap({ height: 10, elapsed: T0 }), snap({ height: 11, elapsed: T0 + 5n * S, security: withPayment, balance: 50n * S - FEE }));
  const event = only(events, 'payment_waiting');
  assert.deepEqual(Object.keys(event).slice(0, 7), ['id', 'account', 'type', 'at_height', 'chain_time', 'urgent', 'message']);
  assert.equal(event.id, '5:payment_waiting:2');
  assert.equal(event.at_height, '11');
  assert.equal(event.urgent, true);
  assert.match(event.message, /^A payment of 12\.5 s from your account 5 \(alice\) to account 42 is waiting and can go through from 2026-11-\d\d \d\d:\d\d UTC unless you cancel it\. If you did not start it, freeze your account now\.$/);
  assert.ok(EVENT_TYPES.includes(event.type));
  // The same transition seen again (a replayed poll, at another height) gives the same id.
  assert.equal(diffSecurity(snap({ height: 10, elapsed: T0 }), snap({ height: 12, elapsed: T0 + 7n * S, security: withPayment }))[0].id, event.id);
});

test('an unchanged row gives no event, however much time passes and the allowance refills', () => {
  const a = snap({ height: 10, elapsed: T0 });
  assert.deepEqual(diffSecurity(a, a), []);
  assert.deepEqual(diffSecurity(a, snap({ height: 20, elapsed: T0 + 3600n * S })), []);
  // A small payment within the limit changes the allowance, the nonce and the balance: nothing to tell.
  assert.deepEqual(diffSecurity(a, snap({ height: 21, elapsed: T0 + 3601n * S, nonce: '4', balance: 50n * S - 150_000n - FEE, security: { ...BASE, allowance_micros: '1000', allowance_elapsed_micros: String(T0 + 3601n * S) } })), []);
  // More than the spend key alone can move in that time (0.198 s left + one hour of refill) is told.
  const drained = only(diffSecurity(a, snap({ height: 21, elapsed: T0 + 3601n * S, nonce: '4', balance: 49n * S })), 'balance_fell');
  assert.equal(drained.urgent, true);
  assert.match(drained.message, /fell by 1 s between two looks, more than its spend key alone could move/);
  // An older state than the last one seen is never compared.
  assert.deepEqual(diffSecurity(snap({ height: 11, elapsed: T0, security: withPayment }), snap({ height: 10, elapsed: T0 })), []);
});

test('adopting the rules is told once, without inventing a past', () => {
  const event = only(diffSecurity(snap({ height: 1, elapsed: T0, security: null, devices: [device(key['70df'], 'full')].map((d) => ({ ...d, can_manage: true, can_spend: true })) }), snap({ height: 2, elapsed: T0 })), 'rules_adopted');
  assert.equal(event.id, '5:rules_adopted');
  assert.match(event.message, /payments above 0\.5 s a day wait 60 seconds/);
  // First sight of an account that adopted the rules long ago: no rules_adopted, but what waits now is told.
  const first = diffSecurity(null, snap({ height: 9, elapsed: T0 + 5n * S, security: { ...withPayment, freezes: '1', frozen_until_elapsed_micros: String(T0 + 100n * S) } }));
  assert.deepEqual(types(first).sort(), ['frozen', 'payment_waiting']);
});

test('a waiting payment followed by its execution', () => {
  const waiting = snap({ height: 11, elapsed: T0 + 5n * S, security: withPayment, balance: 50n * S - FEE });
  const after = snap({ height: 30, elapsed: T0 + 70n * S, security: { ...BASE, next_id: '3', allowance_micros: '1000' }, balance: 50n * S - FEE - 12_500_000n - FEE });
  const gone = only(diffSecurity(waiting, after), 'payment_gone');
  assert.equal(gone.id, '5:payment_gone:2');
  assert.equal(gone.outcome, 'executed');
  assert.equal(gone.certain, true);
  assert.match(gone.message, /^The waiting payment of 12\.5 s to account 42 went through: your balance fell by 12\.501 s/);
  // Any other movement of money in the same interval: the watch cannot tell, says so, and it is urgent.
  const noisy = only(diffSecurity(waiting, snap({ height: 30, elapsed: T0 + 70n * S, security: { ...BASE, next_id: '3' }, balance: 50n * S - FEE - 12_500_000n - 5n * FEE })), 'payment_gone');
  assert.deepEqual([noisy.outcome, noisy.certain, noisy.urgent], ['unknown', false, true]);
  assert.match(noisy.message, /cannot tell whether it went through.*Check the history/);
});

test('a waiting payment followed by its cancellation, by a freeze, or by an outcome the watch cannot tell', () => {
  const waiting = snap({ height: 11, elapsed: T0 + 5n * S, security: withPayment, balance: 50n * S - FEE });
  // Cancelled before it was ready: certainly not executed.
  const cancelled = only(diffSecurity(waiting, snap({ height: 12, elapsed: T0 + 20n * S, security: { ...BASE, next_id: '3' }, balance: 50n * S - 2n * FEE })), 'payment_gone');
  assert.deepEqual([cancelled.outcome, cancelled.certain], ['cancelled', true]);
  assert.match(cancelled.message, /was cancelled and did not go through/);
  // Dropped by a freeze.
  const frozenRow = { ...BASE, next_id: '3', freezes: '1', frozen_until_elapsed_micros: String(T0 + 140n * S) };
  const events = diffSecurity(waiting, snap({ height: 12, elapsed: T0 + 20n * S, security: frozenRow, balance: 50n * S - 2n * FEE }));
  assert.deepEqual(types(events), ['frozen', 'payment_gone']);
  assert.deepEqual([events[1].outcome, events[1].cause], ['dropped', 'freeze']);
  // Gone after it was ready, balance down by a fee only: cancelled, or executed while as much came in.
  const late = only(diffSecurity(waiting, snap({ height: 40, elapsed: T0 + 90n * S, security: { ...BASE, next_id: '3' }, balance: 50n * S - 2n * FEE })), 'payment_gone');
  assert.deepEqual([late.outcome, late.certain, late.urgent], ['unknown', false, true]);
  assert.match(late.message, /Check the history/);
  // Gone after it was ready while the balance rose: the watch says it cannot tell.
  const unknown = only(diffSecurity(waiting, snap({ height: 40, elapsed: T0 + 90n * S, security: { ...BASE, next_id: '3' }, balance: 70n * S })), 'payment_gone');
  assert.deepEqual([unknown.outcome, unknown.certain], ['unknown', false]);
  assert.match(unknown.message, /cannot tell whether it went through/);
});

test('a raise of the limit waits, then takes effect even before the engine rewrites the row', () => {
  const raise = fixture.allowance.security.pending_limit; // the engine's row: 0.5 s → 2 s, id 1
  const before = snap({ height: 10, elapsed: T0 - 10n * S });
  const waiting = snap({ height: 11, elapsed: T0, security: { ...BASE, pending_limit: raise } });
  const event = only(diffSecurity(before, waiting), 'limit_raise_waiting');
  assert.equal(event.id, '5:limit_raise_waiting:1');
  assert.match(event.message, /from 0\.5 s to 2 s is waiting and takes effect at 2026-.* UTC unless you cancel it/);
  // Past its ready time the stored row still shows the raise as waiting; the engine applies it
  // at the next action (Security::settle). The watch tells it now.
  const due = snap({ height: 30, elapsed: T0 + 70n * S, security: { ...BASE, pending_limit: raise } });
  const changed = only(diffSecurity(waiting, due), 'limit_changed');
  assert.equal(changed.id, '5:limit_changed:raise-1');
  assert.match(changed.message, /is now 2 s \(it was 0\.5 s\)/);
  assert.equal(settle(due.security, due.elapsed).policy.daily_limit_micros, '2000000');
  // When an action rewrites the row, nothing new.
  const rewritten = snap({ height: 31, elapsed: T0 + 71n * S, nonce: '4', security: { ...BASE, policy: { ...BASE.policy, daily_limit_micros: '2000000' } } });
  assert.deepEqual(diffSecurity(due, rewritten), []);
  // A raise cancelled before its time.
  const cancelled = only(diffSecurity(waiting, snap({ height: 12, elapsed: T0 + 10n * S })), 'limit_raise_cancelled');
  assert.match(cancelled.message, /was cancelled\. The limit stays at 0\.5 s/);
  // A lowering is at once and is told with what it may mean.
  const lowered = only(diffSecurity(before, snap({ height: 12, elapsed: T0, nonce: '4', security: { ...BASE, policy: { ...BASE.policy, daily_limit_micros: '500' } } })), 'limit_changed');
  assert.equal(lowered.raised, false);
  assert.match(lowered.message, /If you did not lower it/);
});

test('a replacement of the keys waits with the account frozen, and is cancelled, lapses or finishes', () => {
  const window = 3600n * S, ready = T0 + 60n * S;
  const pendingRoot = { devices: NEW_DEVICES, policy: BASE.policy, ready_elapsed_micros: String(ready), expires_elapsed_micros: String(ready + window) };
  const before = snap({ height: 10, elapsed: T0 - S, security: withPayment });
  const asked = snap({ height: 11, elapsed: T0, security: { ...BASE, version: '2', next_id: '3', pending_root: pendingRoot } });
  const events = diffSecurity(before, asked);
  assert.deepEqual(types(events), ['replacement_waiting', 'payment_gone']);
  assert.equal(events[0].id, `5:replacement_waiting:${ready}`);
  assert.equal(events[0].expires_elapsed_micros, String(ready + window));
  assert.match(events[0].message, /frozen meanwhile.*lapses.*replace your keys yourself now with your spend key and 1 recovery key: that takes effect at once.*Cancelling the request instead takes 2 approvals/);
  assert.deepEqual([events[1].outcome, events[1].cause], ['dropped', 'replacement_asked']);
  // Cancelled with threshold proofs: the version moves, the keys stay.
  const cancelled = only(diffSecurity(asked, snap({ height: 12, elapsed: T0 + 10n * S, security: { ...BASE, version: '3', next_id: '3' } })), 'replacement_cancelled');
  assert.equal(cancelled.reason, 'cancelled');
  // Nobody finished it in its window: gone without any action on the chain.
  const lapsed = only(diffSecurity(asked, snap({ height: 900, elapsed: ready + window + S, security: { ...BASE, version: '2', next_id: '3', pending_root: pendingRoot } })), 'replacement_cancelled');
  assert.equal(lapsed.reason, 'expired');
  // Finished by a key of the new set: the keys are replaced, sign-in changes are part of it.
  const finished = diffSecurity(asked, snap({ height: 20, elapsed: ready + S, nonce: '4', epoch: '2', devices: NEW_DEVICES, security: { ...BASE, version: '3', next_id: '3' } }));
  const replaced = only(finished, 'keys_replaced');
  assert.equal(replaced.id, '5:keys_replaced:v3');
  assert.equal(replaced.finished_waiting_replacement, true);
  assert.match(replaced.message, /now has 1 spend key, 3 recovery keys and 1 sign-in key/);
  assert.deepEqual(types(finished), ['keys_replaced']);
});

test('a freeze and its end, on time or lifted early', () => {
  const until = T0 + 120n * S;
  const before = snap({ height: 10, elapsed: T0 - S });
  const frozen = snap({ height: 11, elapsed: T0, security: { ...BASE, freezes: '1', frozen_until_elapsed_micros: String(until) } });
  const event = only(diffSecurity(before, frozen), 'frozen');
  assert.equal(event.id, '5:frozen:1');
  assert.equal(event.frozen_until, new Date(Number((BigInt(GENESIS) + until) / 1000n)).toISOString().replace('T', ' ').slice(0, 16) + ' UTC');
  assert.match(event.message, /is frozen until 2026-[^(]* UTC\. Until then its spend key alone cannot pay from it/);
  const ended = only(diffSecurity(frozen, snap({ height: 40, elapsed: until + S, security: frozen.security })), 'unfrozen');
  assert.deepEqual([ended.id, ended.reason], ['5:unfrozen:1', 'ended']);
  const lifted = only(diffSecurity(frozen, snap({ height: 12, elapsed: T0 + 5n * S, security: { ...BASE, version: '2', freezes: '1', frozen_until_elapsed_micros: '0' } })), 'unfrozen');
  assert.deepEqual([lifted.reason, lifted.urgent], ['lifted', true]);
  assert.equal(ended.urgent, false);
  // A freeze that began and ended between two looks is still told.
  const missed = only(diffSecurity(before, snap({ height: 60, elapsed: until + 10n * S, security: frozen.security })), 'frozen');
  assert.equal(missed.already_over, true);
});

test('sign-in keys added and removed by a spend key', () => {
  const extra = 'ab'.repeat(32);
  const before = snap({ height: 10, elapsed: T0 });
  const added = only(diffSecurity(before, snap({ height: 11, elapsed: T0 + S, epoch: '2', nonce: '4', devices: [...DEVICES, device(extra, 'signin')] })), 'signin_key_added');
  assert.equal(added.id, `5:signin_key_added:${extra}:2`);
  assert.match(added.message, /A sign-in key \(abababab…\) was added .* If you did not add it, someone has your spend key: freeze your account now\./);
  const removed = only(diffSecurity(before, snap({ height: 11, elapsed: T0 + S, epoch: '2', nonce: '4', devices: DEVICES.filter((d) => d.public_key !== key['5526']) })), 'signin_key_removed');
  assert.equal(removed.public_key, key['5526']);
});

test('counting root operations: an install that drops a waiting request is one; a lapsed request explains none', () => {
  const ready = T0 + 60n * S, R = { devices: NEW_DEVICES, policy: BASE.policy, ready_elapsed_micros: String(ready), expires_elapsed_micros: String(ready + 3600n * S) };
  const asked = snap({ height: 10, elapsed: T0, security: { ...BASE, version: '2', pending_root: R } });
  // The owner answers with the spend key: other keys at once, which drops the request. One operation.
  const own = DEVICES.filter((d) => d.public_key !== key['677a']);
  const answered = diffSecurity(asked, snap({ height: 11, elapsed: T0 + 5n * S, nonce: '4', epoch: '2', devices: own, security: { ...BASE, version: '3' } }));
  assert.deepEqual(types(answered), ['keys_replaced']);
  // Rules changed with the spend key while a request waits: dropped with it, still one operation.
  const ruled = diffSecurity(asked, snap({ height: 11, elapsed: T0 + 5n * S, nonce: '4', epoch: '2', security: { ...BASE, version: '3', policy: { ...BASE.policy, threshold: '3' } } }));
  assert.deepEqual(types(ruled).sort(), ['replacement_cancelled', 'rules_changed']);
  assert.equal(only(ruled, 'replacement_cancelled').reason, 'dropped');
  // Lapsed, and the version moved: the lapse explains nothing, so the move is told.
  const lapsed = diffSecurity(asked, snap({ height: 900, elapsed: ready + 3700n * S, security: { ...BASE, version: '3' } }));
  assert.deepEqual(types(lapsed).sort(), ['replacement_cancelled', 'root_operation']);
  assert.equal(only(lapsed, 'replacement_cancelled').reason, 'expired_or_cancelled');
});

test('other rules changed by a root operation that kept the keys', () => {
  const event = only(diffSecurity(snap({ height: 10, elapsed: T0 }), snap({ height: 11, elapsed: T0, security: { ...BASE, version: '2', policy: { ...BASE.policy, threshold: '3', delay_seconds: '86400' } } })), 'rules_changed');
  assert.match(event.message, /wait 24 hours.*needs 3 approvals/);
});

test('reminders: once, when a waiting item comes within the window (6 hours unless configured)', () => {
  const ready = T0 + 86_400n * S, hour = 3600n * S;
  const row = { ...BASE, policy: { ...BASE.policy, delay_seconds: '86400' }, pending_payments: [{ ...payment, ready_elapsed_micros: String(ready) }], next_id: '3' };
  const at = (height, elapsed) => snap({ height, elapsed, security: row });
  assert.deepEqual(reminders(at(10, ready - 7n * hour), at(11, ready - 6n * hour - S)), []);
  const due = reminders(at(11, ready - 6n * hour - S), at(12, ready - 5n * hour));
  assert.equal(due.length, 1);
  assert.equal(due[0].id, '5:reminder:payment:2');
  assert.match(due[0].message, /^Reminder: the payment of 12\.5 s to account 42 can go through from 2026-[^(]* UTC\. Cancel it before then/);
  assert.deepEqual(reminders(at(12, ready - 5n * hour), at(13, ready - 4n * hour)), []);
  // Configurable, and part of diffSecurity.
  assert.deepEqual(diffSecurity(at(11, ready - 6n * hour - S), at(12, ready - 5n * hour), { reminderSeconds: 3600 }), []);
  assert.deepEqual(types(diffSecurity(at(12, ready - 2n * hour), at(13, ready - hour + S), { reminderSeconds: 3600 })), ['reminder']);
  // An item first seen inside the window is told by its waiting event, not by a reminder too.
  assert.deepEqual(types(diffSecurity(snap({ height: 1, elapsed: ready - 2n * hour, security: { ...row, pending_payments: [] } }), at(2, ready - hour))), ['payment_waiting']);
});

// ------------------------------------------------------------------ the runner
function chain(initial) {
  // A verified-state function over a scripted chain; `set` moves it.
  let options = initial, failing = false;
  const calls = [];
  const fn = async (selection) => {
    calls.push(selection);
    if (failing) throw new Error('gateway unreachable');
    const v = verified({ ...options, others: selection.ids.filter((id) => id !== '5') });
    return v;
  };
  return { fn, calls, set: (next) => { options = { ...options, ...next }; }, fail: (value) => { failing = value; } };
}
const quietClock = () => Number((BigInt(GENESIS) + T0) / 1000n) + 1000;

test('accounts are asked in batches the SDK accepts (at most 8 ids per query)', async () => {
  const ids = ['5', ...Array.from({ length: 18 }, (_, i) => String(100 + i))];
  const scripted = chain({ height: 10, elapsed: T0 });
  const watch = createSecurityWatch({ verifiedState: scripted.fn, accounts: ids, onEvent: async () => {}, now: quietClock });
  const report = await watch.poll();
  assert.deepEqual(scripted.calls.map((c) => c.ids.length), [8, 8, 3]);
  assert.ok(scripted.calls.every((c) => c.include_security === true));
  assert.deepEqual(scripted.calls.flatMap((c) => c.ids), ids);
  assert.equal(report.checked, 19);
  assert.deepEqual(batches(['1', '2', '3'], 2), [['1', '2'], ['3']]);
  assert.throws(() => batches(['1'], 9));
  // The SDK refuses a ninth id before it asks anything: this is why the watch batches.
  const client = SDK.createClient({ gateway: 'https://rpc.example', trust: { app_version: '4', network_id: fixture.network_id, chain_id: 'time-devnet-v4-test' }, fetcher: async () => { throw new Error('no network in tests'); } });
  await assert.rejects(client.getVerifiedState({ ids: ids.slice(0, 9), include_security: true }), /exceeds budget/);
});

test('a restart neither resends nor misses events (file store), and undelivered events wait in their queue', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-'));
  try {
    const file = path.join(directory, 'watch.json'), scripted = chain({ height: 10, elapsed: T0 });
    const got = [];
    // Each run: a new process with the same store, one poll, deliveries finished, stopped.
    const run = async (onEvent) => { const w = createSecurityWatch({ verifiedState: scripted.fn, accounts: ['5'], onEvent, store: fileStore(file), now: quietClock }); const report = await w.poll(); await w.settled(); await w.stop(); return report; };
    await run(async (e) => got.push(e.id));
    scripted.set({ height: 11, elapsed: T0 + 5n * S, security: withPayment });
    await run(async (e) => got.push(e.id));
    assert.deepEqual(got, ['5:payment_waiting:2']);
    // Restart, same chain: nothing is sent again.
    await run(async (e) => got.push(e.id));
    assert.deepEqual(got, ['5:payment_waiting:2']);
    // While the watch is down the payment goes through and the account is frozen; after the restart both are told.
    scripted.set({ height: 40, elapsed: T0 + 70n * S, balance: 50n * S - 12_500_000n - FEE, security: { ...BASE, next_id: '3', freezes: '1', frozen_until_elapsed_micros: String(T0 + 190n * S) } });
    // The first process fails to deliver, then stops: its events stay queued on disk.
    await run(async () => { throw new Error('receiver down'); });
    const saved = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(saved.queues.default.length, 2);
    assert.deepEqual(saved.network, { network_id: fixture.network_id, genesis_time_micros: GENESIS });
    await run(async (e) => got.push(e.id));
    assert.deepEqual(got, ['5:payment_waiting:2', '5:frozen:1', '5:payment_gone:2']);
    await run(async (e) => got.push(e.id));
    assert.equal(got.length, 3);
    // A lost snapshot (the store cleared for this account) does not resend what was delivered.
    const again = JSON.parse(await readFile(file, 'utf8')); delete again.snapshots['5'];
    await fileStore(file).put(again);
    await run(async (e) => got.push(e.id));
    assert.equal(got.length, 3);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('the file store survives a torn write: it falls back to the previous version, or starts afresh and says so', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-torn-'));
  try {
    const file = path.join(directory, 'watch.json'), store = fileStore(file);
    await store.put({ format: 2, n: 1 }); await store.put({ format: 2, n: 2 });
    assert.equal(JSON.parse(await readFile(`${file}.bak`, 'utf8')).n, 1);
    await writeFile(file, '{"format":2,"n":'); // power lost after the rename, before the data reached the disk
    assert.equal((await store.get()).n, 1);
    await writeFile(`${file}.bak`, '{"form');
    await assert.rejects(store.get(), /unreadable and was moved aside/);
    // A crash now, before anything is written: the next read still knows the memory was lost.
    const leftover = await store.get().catch((e) => e);
    assert.match(leftover.message, /missing and a damaged copy was set aside earlier/);
    assert.equal(leftover.lost, 'its records were damaged and set aside');
    // The runner reports the problem in its status, keeps going, and tells every owner it lost its memory.
    await writeFile(file, '{"format":2,"snap');
    const got = [];
    const watch = createSecurityWatch({ verifiedState: chain({ height: 10, elapsed: T0, others: [] }).fn, accounts: ['5', '7'], onEvent: async (e) => got.push(e), store, now: quietClock });
    await watch.poll(); await watch.settled();
    assert.match(watch.status().store_error, /unreadable/);
    const lost = got.filter((e) => e.type === 'watch_memory_lost');
    assert.deepEqual(lost.map((e) => [e.account, e.urgent]), [['5', true], ['7', true]]);
    assert.match(lost[0].message, /lost its memory at 2026-.* UTC \(its records were damaged and set aside\)\. Alerts that were waiting to be sent may be lost: check your account's waiting payments/);
    await watch.stop();
    // Not repeated after a restart with the new store.
    const again = createSecurityWatch({ verifiedState: chain({ height: 11, elapsed: T0, others: [] }).fn, accounts: ['5', '7'], onEvent: async (e) => got.push(e), store, now: quietClock });
    await again.poll(); await again.settled(); await again.stop();
    assert.equal(got.filter((e) => e.type === 'watch_memory_lost').length, 2);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('the store is written before the first poll; a store missing next to the files written after it means lost memory', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-companions-'));
  try {
    const file = path.join(directory, 'watch.json'), feedFile = path.join(directory, 'feed.json');
    const store = fileStore(file, { companions: [feedFile, path.join(directory, 'checkpoint.json')] });
    assert.equal(await store.get(), null); // a first start
    // The store exists as soon as the watch has loaded, even if the first poll never ends.
    const hung = createSecurityWatch({ verifiedState: () => new Promise(() => {}), accounts: ['5'], onEvent: async () => {}, store, now: quietClock, batchTimeoutMs: 60_000 });
    // ADAPTED (2026-11-18): this waited a fixed 100 ms and then read the file. On a busy machine the write took
    // longer twice (once in each of two full runs of the suite). Now it reads until the file is there, for at
    // most ten seconds. What it asserts is unchanged: the store is written although the first poll never ends.
    hung.poll();
    let written = null;
    for (let waited = 0; waited < 10_000 && written === null; waited += 25) { await new Promise((r) => setTimeout(r, 25)); written = await readFile(file, 'utf8').catch(() => null); }
    assert.equal(JSON.parse(written).format, 3);
    await hung.stop();
    // Later the store disappears (a wrong restore, a deleted file) while the feed it fed is there.
    await writeFile(feedFile, '{}'); await rm(file); await rm(`${file}.bak`, { force: true });
    const got = [];
    const watch = createSecurityWatch({ verifiedState: chain({ height: 10, elapsed: T0 }).fn, accounts: ['5'], onEvent: async (e) => got.push(e), store, now: quietClock });
    await watch.poll(); await watch.settled(); await watch.stop();
    const lost = only(got, 'watch_memory_lost');
    assert.match(lost.message, /\(its records are missing\)/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('an old store whose snapshots disagree on their network is set aside, and owners are told', async () => {
  const other = String(BigInt(GENESIS) - 10n ** 12n), got = [];
  const a = snapshotOf(verified({ height: 10, elapsed: T0 }), '5'), b = { ...a, account: { ...a.account, id: '7' }, genesis_time_micros: other };
  const watch = createSecurityWatch({ verifiedState: chain({ height: 20, elapsed: T0 }).fn, accounts: ['5', '7'], onEvent: async (e) => got.push(e), now: quietClock, store: memoryStore({ format: 1, snapshots: { 5: a, 7: b }, delivered: {}, outbox: [] }) });
  await watch.poll(); await watch.settled();
  assert.match(watch.status().store_error, /set aside/);
  assert.deepEqual(got.filter((e) => e.type === 'watch_memory_lost').map((e) => e.account), ['5', '7']);
  assert.match(got[0].message, /disagree on the network/);
  await watch.stop();
});

test('targets are named by what they are: a changed URL gets what the old one still held, a removed one is dropped, nothing reaches another account\'s receiver', async () => {
  const store = memoryStore(), logs = [], scripted = chain({ height: 10, elapsed: T0 });
  const A = 'https://hooks.alice.example/a', A2 = 'https://hooks.alice.example/new', B = 'https://hooks.bob.example/b';
  const feed = [], sent = {};
  const record = (url) => ({ deliver: async (e) => { (sent[url] ||= []).push(e.id); } });
  const down = { deliver: async () => { throw new Error('down'); } };
  const run = async (targets, change) => {
    const w = createSecurityWatch({ verifiedState: scripted.fn, accounts: ['5', '42'], store, now: quietClock, log: (l, m, f) => logs.push(JSON.stringify({ m, ...f })), targets: [{ id: 'feed', accounts: null, adapter: { deliver: async (e) => feed.push(e.id) } }, ...targets] });
    change?.(); await w.poll(); await w.settled(); await w.stop(); return w;
  };
  assert.notEqual(targetId(['5'], A), targetId(['5'], A2));
  assert.equal(targetId(['5', '42'], A), targetId(['42', '5'], A));
  // Run 1: alice's receiver is down; her alert waits under her target.
  await run([{ id: targetId(['5'], A), accounts: ['5'], adapter: down }, { id: targetId(['42'], B), accounts: ['42'], adapter: record(B) }], () => scripted.set({ height: 11, elapsed: T0 + 5n * S, security: withPayment, others: [] }));
  // Run 2: bob listed first, alice moved to a new URL: her alert goes to her new URL, never to bob.
  await run([{ id: targetId(['42'], B), accounts: ['42'], adapter: record(B) }, { id: targetId(['5'], A2), accounts: ['5'], adapter: record(A2) }]);
  assert.deepEqual(sent, { [A2]: ['5:payment_waiting:2'] });
  assert.deepEqual(feed, ['5:payment_waiting:2']); // the feed got it once
  assert.ok(logs.some((l) => /no longer configured/.test(l) && /"events":1/.test(l)));
  assert.ok(!logs.some((l) => /payment_waiting/.test(l) && /no longer configured/.test(l))); // counts, never content
  // A forged entry for account 5 in bob's queue is removed, not sent.
  const saved = await store.get();
  saved.queues[targetId(['42'], B)].push({ id: '5:forged:1', account: '5', type: 'frozen', urgent: true, message: 'x' });
  await store.put(saved);
  await run([{ id: targetId(['42'], B), accounts: ['42'], adapter: record(B) }, { id: targetId(['5'], A2), accounts: ['5'], adapter: record(A2) }]);
  assert.equal(sent[B], undefined);
  // Alice unsubscribes: her target and its queue are gone.
  await run([{ id: targetId(['42'], B), accounts: ['42'], adapter: record(B) }]);
  assert.deepEqual(Object.keys((await store.get()).queues).sort(), ['feed', targetId(['42'], B)].sort());
});

test('a receiver that refuses (4xx) keeps its alerts queued, and the owner is told through the other targets', async () => {
  let refuse = true; const feed = [], hook = [];
  const watch = createSecurityWatch({
    verifiedState: chain({ height: 11, elapsed: T0 + 5n * S, security: withPayment }).fn, accounts: ['5'], now: quietClock,
    targets: [
      { id: 'feed', accounts: null, adapter: { deliver: async (e) => feed.push(e) } },
      { id: 'hook', accounts: ['5'], adapter: { origin: 'https://hooks.alice.example', deliver: async (e) => { if (refuse) throw Object.assign(new Error('webhook https://hooks.alice.example answered 401'), { refused: true }); hook.push(e.id); } } },
    ],
  });
  await watch.poll(); await watch.settled();
  const notice = feed.find((e) => e.type === 'alerts_refused');
  assert.equal(notice.urgent, true);
  assert.match(notice.message, /Your alert endpoint \(https:\/\/hooks\.alice\.example\) refuses the alerts this watch sends for account 5 \(answered 401\)/);
  assert.deepEqual([watch.status().refusing_targets, watch.status().dead_letters, watch.details().queues.hook], [1, 0, 1]);
  await watch.poll(); await watch.settled();
  assert.equal(feed.filter((e) => e.type === 'alerts_refused').length, 1); // once per episode
  refuse = false; await watch.poll(); await watch.settled();
  assert.deepEqual(hook, ['5:payment_waiting:2']);
  assert.equal(watch.status().refusing_targets, 0);
  await watch.stop();
});

test('the lock: a live watch with a fresh heartbeat keeps it; the heartbeat moves; release removes it', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-lock-'));
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 20000)'], { stdio: 'ignore' });
  const file = path.join(directory, 'watch.lock');
  // Released in every case: a heartbeat left running after a failed assertion would write into the removed
  // folder and end this file's process, and the tests after this one would not run at all.
  let release = null;
  try {
    await writeFile(file, JSON.stringify({ pid: child.pid, run: 'another', beat: Date.now() }));
    await assert.rejects(claim(directory), /Another watch/);
    await writeFile(file, JSON.stringify({ pid: child.pid, run: 'another', beat: Date.now() - 31_000 }));
    release = await claim(directory, { beatMs: 40 });
    const first = JSON.parse(await readFile(file, 'utf8'));
    // ADAPTED (it failed once in forty runs on Windows): this waited a fixed 150 ms and then read
    // the lock. Windows refuses to replace the lock (EPERM) for as long as another program, such
    // as a virus scanner, has it open, and that lasted longer than 150 ms. The heartbeat then
    // leaves the lock as it is and the next one writes it. Now the test reads until the beat has
    // moved, for at most twenty seconds (five were not enough once, in a folder a scanner was still reading on
    // a busy machine). What it asserts is unchanged.
    let later = first;
    for (let waited = 0; waited < 20000 && later.beat <= first.beat; waited += 40) { await new Promise((r) => setTimeout(r, 40)); later = JSON.parse(await readFile(file, 'utf8')); }
    assert.equal(later.run, first.run);
    assert.ok(later.beat > first.beat);
    await assert.rejects(claim(directory, { beatMs: 40 }), /already watches/);
    await release(); release = null;
    await assert.rejects(readFile(file, 'utf8'), /ENOENT/);
  } finally { if (release) await release().catch(() => {}); child.kill(); await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
});

test('the runner survives a failed poll and catches up', async () => {
  const scripted = chain({ height: 10, elapsed: T0 }), got = [], logs = [];
  const watch = createSecurityWatch({ verifiedState: scripted.fn, accounts: ['5'], onEvent: async (e) => got.push(e), store: memoryStore(), now: quietClock, log: (level, message) => logs.push(`${level} ${message}`) });
  const polled = async () => { const report = await watch.poll(); await watch.settled(); return report; };
  await polled();
  scripted.fail(true);
  scripted.set({ height: 11, elapsed: T0 + 5n * S, security: withPayment });
  const failed = await polled();
  assert.deepEqual(failed.failed, ['5']);
  assert.deepEqual(watch.details().failed_accounts, ['5']);
  assert.equal(watch.status().failing, 1);
  assert.ok(logs.some((l) => l.startsWith('warn poll failed')));
  scripted.set({ height: 30, elapsed: T0 + 70n * S, balance: 50n * S - 12_500_000n - 2n * FEE, security: { ...BASE, next_id: '3' } });
  scripted.fail(false);
  await polled();
  // The payment came and went while the gateway was unreachable. It was never seen, but the
  // counter of waiting items moved, so the owner is told that something was started and is gone.
  const unseen = only(got, 'waiting_unseen');
  assert.deepEqual(unseen.item_ids, ['2']);
  assert.match(unseen.message, /While this watch could not look, 1 waiting item .* The balance fell by 12\.502 s meanwhile\./);
  got.length = 0;
  // A change that persists across the outage is told once the gateway answers again.
  scripted.fail(true);
  scripted.set({ height: 31, elapsed: T0 + 71n * S, security: { ...BASE, next_id: '4', pending_payments: [{ ...payment, id: '3', ready_elapsed_micros: String(T0 + 131n * S) }] } });
  await polled(); scripted.fail(false); await polled();
  assert.deepEqual(got.map((e) => e.id), ['5:payment_waiting:3']);
  assert.equal(watch.details().failed_accounts.length, 0);
  await watch.stop();
});

test('an account the watch cannot see for longer than half its delay: the owner is told what was observed, once, and told again when it can', async () => {
  // delay_seconds is 60, so the allowed lag is 30 s whatever max_lag_seconds says; at a poll the
  // view must be within it (the owner still has half the wait).
  let wall = quietClock(); const scripted = chain({ height: 10, elapsed: T0 }), got = [];
  const watch = createSecurityWatch({ verifiedState: scripted.fn, accounts: ['5'], onEvent: async (e) => got.push(e), now: () => wall, maxLagSeconds: 300 });
  const polled = async () => { const report = await watch.poll(); await watch.settled(); return report; };
  await polled();
  scripted.fail(true); wall += 20_000; await polled();
  assert.deepEqual(got, []); // 21 s without a view: within the limit
  wall += 15_000; await polled(); // 36 s: past half the wait
  const blind = only(got, 'watch_blind');
  assert.deepEqual([blind.id, blind.urgent, blind.reason], ['5:watch_blind:h10', true, 'unreachable']);
  assert.match(blind.message, /cannot see your account 5 at the moment: the network gateway did not answer its last checks\. The newest state of it that it could verify is from 2026-.* UTC/);
  wall += 30_000; await polled();
  assert.equal(got.length, 1); // told once per episode
  assert.equal(watch.status().blind, 1);
  // The gateway answers again, but with old state: still blind, and a stale answer does not restore.
  scripted.fail(false); scripted.set({ height: 12, elapsed: T0 + 20n * S }); await polled();
  assert.equal(got.length, 1);
  scripted.set({ height: 20, elapsed: T0 + 65n * S }); await polled();
  assert.deepEqual(got.map((e) => e.type), ['watch_blind', 'watch_restored']);
  assert.equal(got[1].id, '5:watch_restored:h10');
  assert.equal(watch.status().blind, 0);
  // A new episode has its own id; a gateway that serves only old state is named as such.
  scripted.set({ height: 21, elapsed: T0 + 66n * S }); wall += 31_000; await polled();
  const stale = got.at(-1);
  assert.deepEqual([stale.type, stale.id, stale.reason], ['watch_blind', '5:watch_blind:h21', 'stale']);
  assert.match(stale.message, /answers, but only with old state \(the newest is from 2026-.* UTC\)/);
  await watch.stop();
});

test('the watchdog at default intervals, honest gateway: no false alarm; poll_seconds above a quarter of a delay is warned about', async () => {
  mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: Number((BigInt(GENESIS) + T0) / 1000n) });
  const got = [], logs = [];
  try {
    let height = 10;
    const fresh = async (q) => verified({ height: ++height, elapsed: BigInt(Date.now() - 1500) * 1000n - BigInt(GENESIS), others: q.ids.filter((id) => id !== '5') });
    const watch = createSecurityWatch({ verifiedState: fresh, accounts: ['5'], onEvent: async (e) => got.push(e), now: () => Date.now(), log: (l, m) => logs.push(`${l} ${m}`) });
    watch.start(20_000); // above a quarter of the 60 s delay of account 5 (and below half of it)
    for (let s = 0; s < 600; s++) { mock.timers.tick(1000); for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r)); }
    mock.timers.reset();
    await watch.stop();
    assert.deepEqual(got.map((e) => e.type), []);
    assert.equal(logs.filter((l) => /poll_seconds is longer than a quarter of the delay/.test(l)).length, 1);
    assert.equal(watch.status().config_warnings, 1);
  } finally { mock.timers.reset(); }
});

test('accounts missing from the chain, a store ahead of the chain, or another network count as failures and alert', async () => {
  const got = [], logs = [];
  const missing = createSecurityWatch({ verifiedState: async (q) => verified({ height: 10, elapsed: T0, others: [] }), accounts: ['5', '77'], onEvent: async (e) => got.push(e), now: quietClock, log: (l, m) => logs.push(m) });
  const report = await missing.poll(); await missing.settled();
  assert.deepEqual(report.failed, ['77']);
  assert.deepEqual(got.map((e) => e.id), ['77:watch_blind:h0']);
  assert.match(got[0].message, /not on the chain this watch reads/);
  await missing.stop();
  // A store from another network (or genesis) is refused, not mixed with this one.
  got.length = 0;
  const other = memoryStore({ format: 2, network: { network_id: 'cd'.repeat(32), genesis_time_micros: GENESIS }, snapshots: {}, seen: {}, queues: {}, dead: {}, blind: {} });
  const foreign = createSecurityWatch({ verifiedState: async () => verified({ height: 10, elapsed: T0 }), accounts: ['5'], onEvent: async (e) => got.push(e), store: other, now: quietClock, log: (l, m) => logs.push(m) });
  assert.deepEqual((await foreign.poll()).failed, ['5']); await foreign.settled();
  assert.equal(only(got, 'watch_blind').reason, 'network_mismatch');
  assert.ok(logs.some((m) => /another network/.test(m)));
  await foreign.stop();
});

test('a gateway that never answers: the batch times out, the rest of the poll is skipped, and stop() finishes', async () => {
  const logs = [], calls = [];
  const watch = createSecurityWatch({ verifiedState: (q) => { calls.push(q); return new Promise(() => {}); }, accounts: Array.from({ length: 10 }, (_, i) => String(i + 1)), onEvent: async () => {}, now: quietClock, batchTimeoutMs: 100, log: (l, m, f) => logs.push(`${l} ${m} ${JSON.stringify(f)}`) });
  const started = Date.now(), report = await watch.poll();
  assert.ok(Date.now() - started < 1000);
  assert.equal(calls.length, 1); // the second batch is not sent to a gateway that just timed out
  assert.equal(report.failed.length, 10);
  assert.ok(logs.some((l) => /did not answer within/.test(l)));
  // stop() during a hanging poll returns at once.
  const again = watch.poll();
  const stopped = await Promise.race([watch.stop().then(() => 'stopped'), new Promise((r) => setTimeout(() => r('hung'), 500))]);
  assert.equal(stopped, 'stopped');
  await again;
});

test('a state far behind the clock is reported stale', async () => {
  const scripted = chain({ height: 10, elapsed: T0 }), logs = [];
  const watch = createSecurityWatch({ verifiedState: scripted.fn, accounts: ['5'], onEvent: async () => {}, now: () => quietClock() + 3600_000, log: (level, message, fields) => logs.push({ level, message, ...fields }) });
  const report = await watch.poll();
  assert.equal(report.stale, true);
  assert.ok(logs.some((l) => /old/.test(l.message) && l.lag_seconds >= 3600));
});

// ------------------------------------------------------------------ delivery
async function receiver(statuses = []) {
  const received = [];
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (c) => chunks.push(c));
    request.on('end', () => { received.push({ headers: request.headers, body: Buffer.concat(chunks).toString(), url: request.url }); response.writeHead(statuses.shift() ?? 200); response.end(); });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { received, url: `http://localhost:${server.address().port}/hooks/abc?token=xyz`, close: () => new Promise((resolve) => server.close(resolve)) };
}
const sample = () => diffSecurity(snap({ height: 10, elapsed: T0 }), snap({ height: 11, elapsed: T0 + 5n * S, security: withPayment }))[0];

/// A webhook secret as the READMEs say to make one: 32 random bytes in hexadecimal (openssl rand -hex 32).
const HOOK_SECRET = randomBytes(32).toString('hex');

test('a webhook secret is 32 random bytes or more in hexadecimal; one a person chose or could type from memory is refused, with the command that makes one, and never quoted', async () => {
  // Made by a command: taken, in either case, up to 128 bytes.
  for (const secret of [HOOK_SECRET, randomBytes(32).toString('hex').toUpperCase(), randomBytes(48).toString('hex'), randomBytes(128).toString('hex')]) assert.equal(webhookSecretProblem(secret), null);
  // A thousand made by the command are all taken: the checks for a pattern do not refuse what a generator writes.
  for (let i = 0; i < 1000; i++) assert.equal(webhookSecretProblem(randomBytes(32).toString('hex')), null);
  const refused = {
    'is not 64 hexadecimal characters (32 random bytes)': ['x'.repeat(16), 'subscription-secret-0123456789', 'correct horse battery staple and then some more words to be long', randomBytes(24).toString('hex'), randomBytes(32).toString('base64'), `${randomBytes(32).toString('hex')}0`, randomBytes(129).toString('hex'), '', undefined, 42, Buffer.alloc(32)],
    'repeats itself, as no random generator writes': ['a'.repeat(64), '0'.repeat(64), 'deadbeef'.repeat(8), '0123456789abcdef'.repeat(4), 'c0ffee'.repeat(10) + 'c0ff', `${'1234567890ab'.repeat(5)}1234`],
    'is text written in hexadecimal, which a person chose': [Buffer.from('our shop says this is the secret').toString('hex'), Buffer.from('Tr0ub4dor&3 is my webhook secret!!').toString('hex')],
  };
  for (const [problem, secrets] of Object.entries(refused)) for (const secret of secrets) assert.equal(webhookSecretProblem(secret), problem, String(secret));
  // The adapter refuses it before anything is sent, says what to run, and never repeats the secret.
  for (const secret of [...refused['repeats itself, as no random generator writes'], 'subscription-secret-0123456789']) {
    assert.throws(() => webhookAdapter({ url: 'https://hooks.example/x', secret }), (error) => /^The secret of a webhook .*openssl rand -hex 32.*randomBytes\(32\)/.test(error.message) && !error.message.includes(secret), secret);
  }
});

test('the webhook POSTs the event as JSON with an HMAC-SHA256 signature the receiver verifies with the secret', async () => {
  const hook = await receiver(), secret = HOOK_SECRET;
  try {
    const event = sample();
    await webhookAdapter({ url: hook.url, secret }).deliver(event);
    const [got] = hook.received;
    assert.equal(got.headers['content-type'], 'application/json');
    assert.equal(got.headers[EVENT_HEADER], event.id);
    assert.deepEqual(JSON.parse(got.body), event);
    // Verifiable with the secret alone, by any HMAC implementation: over "t=<time>,id=<event id>." and the body.
    const t = /^t=(\d+),sha256=/.exec(got.headers[SIGNATURE_HEADER])[1];
    assert.ok(Math.abs(Number(t) - Date.now() / 1000) < 5);
    assert.equal(got.headers[SIGNATURE_HEADER], `t=${t},sha256=${createHmac('sha256', secret).update(`t=${t},id=${event.id}.${got.body}`).digest('hex')}`);
    assert.equal(verifyWebhookSignature(got.body, got.headers, secret), true);
    assert.equal(verifyWebhookSignature(Buffer.from(got.body), new Headers(got.headers), secret), true);
    assert.equal(verifyWebhookSignature(got.body, got.headers, 'another-secret-0123456789'), false);
    assert.equal(verifyWebhookSignature(got.body.replace('12500000', '12500001'), got.headers, secret), false);
    assert.equal(verifyWebhookSignature(got.body, { ...got.headers, [SIGNATURE_HEADER]: got.headers[SIGNATURE_HEADER].slice(0, -1) }, secret), false);
    // Another event id in the header than the one signed (and in the body) is refused.
    assert.equal(verifyWebhookSignature(got.body, { ...got.headers, [EVENT_HEADER]: '5:replacement_cancelled:1' }, secret), false);
    // A capture replayed later than the allowed age (5 minutes by default) is refused.
    assert.equal(verifyWebhookSignature(got.body, got.headers, secret, { now: () => Date.now() + 301_000 }), false);
    assert.equal(verifyWebhookSignature(got.body, got.headers, secret, { now: () => Date.now() + 3_000_000, maxAgeSeconds: 3600 }), true);
    const old = signWebhook(got.body, event.id, secret, Date.now() / 1000 - 400);
    assert.equal(verifyWebhookSignature(got.body, { ...got.headers, [SIGNATURE_HEADER]: old }, secret), false);
  } finally { await hook.close(); }
});

test('the webhook retries a first delivery with backoff, tries a failed event once per poll, and gives up on a refusal', async () => {
  const hook = await receiver([503, 503, 200, 503]), slept = [];
  try {
    const adapter = webhookAdapter({ url: hook.url, secret: HOOK_SECRET, sleep: async (ms) => slept.push(ms) });
    await adapter.deliver(sample());
    assert.equal(hook.received.length, 3);
    assert.deepEqual(slept, [1000, 2000]);
    hook.received.length = 0; slept.length = 0;
    await assert.rejects(adapter.deliver(sample(), { first: false }), /answered 503/);
    assert.deepEqual([hook.received.length, slept], [1, []]);
    // A 4xx is a refusal: no retry inside the call, not final (the watch retries it later).
    const refused = await receiver([401, 410]);
    try {
      const refuser = webhookAdapter({ url: refused.url, secret: HOOK_SECRET, sleep: async (ms) => slept.push(ms) });
      const refusal = await refuser.deliver(sample()).catch((e) => e);
      assert.match(refusal.message, /answered 401/);
      assert.deepEqual([refusal.refused, refusal.permanent], [true, undefined]);
      assert.deepEqual(slept, []);
      // Only 410 Gone is final.
      const gone = await refuser.deliver(sample()).catch((e) => e);
      assert.deepEqual([gone.permanent, refused.received.length], [true, 2]);
    } finally { await refused.close(); }
  } finally { await hook.close(); }
});

test('the webhook never reads the answer: a receiver streaming without end cannot fill memory (probe-body)', async () => {
  const chunk = Buffer.alloc(1 << 20, 97);
  const server = http.createServer((request, response) => { request.resume(); response.writeHead(200); const pump = () => { while (response.write(chunk)) { /* fill */ } }; response.on('drain', pump); pump(); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const before = process.memoryUsage().rss, started = Date.now();
    await webhookAdapter({ url: `http://127.0.0.1:${server.address().port}/h`, secret: HOOK_SECRET, timeoutMs: 1500 }).deliver({ id: 'e', account: '5' });
    assert.ok(Date.now() - started < 1000, 'delivered without waiting for the body');
    assert.ok(process.memoryUsage().rss - before < 64 * 2 ** 20, 'the body was not buffered');
  } finally { server.closeAllConnections(); server.close(); }
});

test('webhooks must be https:// (http:// only for localhost)', () => {
  for (const bad of ['http://example.com/hook', 'http://10.0.0.5/hook', 'ftp://example.com/', 'ws://localhost/', 'https://user:pass@example.com/', 'http://user@localhost/', 'not a url'])
    assert.throws(() => checkWebhookURL(bad), /webhook/i, bad);
  for (const good of ['https://hooks.example.com/time', 'http://localhost:9000/x', 'http://127.0.0.1:9000/x', 'http://[::1]:9000/x']) assert.equal(checkWebhookURL(good).href, new URL(good).href);
  assert.throws(() => webhookAdapter({ url: 'http://example.com/', secret: HOOK_SECRET }), /https/);
  assert.throws(() => webhookAdapter({ url: 'https://example.com/', secret: 'short' }), /secret/);
});

test('each target has its own queue: one that fails neither holds up nor duplicates the others; refusals go to dead letters; a failing target rests', async () => {
  let down = true, wall = quietClock(); const a = [], b = [], c = [], attempts = [];
  const scripted = chain({ height: 10, elapsed: T0 });
  const watch = createSecurityWatch({
    verifiedState: scripted.fn, accounts: ['5'], now: () => wall, breaker: { failures: 3, baseMs: 60_000 },
    targets: [
      { id: 'a', accounts: null, adapter: { deliver: async (e) => a.push(e.id) } },
      { id: 'b', accounts: ['5'], adapter: { deliver: async (e, { first }) => { attempts.push(first); if (down) throw new Error('down'); b.push(e.id); } } },
      { id: 'c', accounts: ['6'], adapter: { deliver: async () => { throw new Error('never called for account 5'); } } },
      { id: 'refuses', accounts: null, adapter: { deliver: async () => { throw Object.assign(new Error('answered 410'), { permanent: true }); } } },
    ],
  });
  const polled = async () => { await watch.poll(); await watch.settled(); };
  await polled();
  scripted.set({ height: 11, elapsed: T0 + 5n * S, security: withPayment }); await polled();
  assert.deepEqual([a, b, c], [['5:payment_waiting:2'], [], []]);
  assert.deepEqual(attempts, [true]); // the first delivery (its retries are the adapter's)
  assert.deepEqual(watch.details().dead.refuses.map((d) => d.event.id), ['5:payment_waiting:2']);
  assert.equal(watch.status().dead_letters, 1);
  await polled(); await polled();
  assert.deepEqual(attempts, [true, false, false]); // then one attempt per poll
  assert.equal(watch.status().resting_targets, 1); // three failures in a row: b rests
  await polled();
  assert.equal(attempts.length, 3);
  down = false; wall += 61_000; scripted.set({ height: 12, elapsed: T0 + 66n * S }); await polled();
  assert.deepEqual([a, b], [['5:payment_waiting:2'], ['5:payment_waiting:2']]); // each target got it once
  assert.equal(watch.status().resting_targets, 0);
  await watch.stop();
});

test('the feed is read-only over HTTP, per watched account', async () => {
  const feed = createFeed({ limit: 2 });
  const events = [sample(), { ...sample(), id: '5:x:1' }, { ...sample(), id: '5:x:2' }];
  for (const e of [...events, events[0]]) await feed.push(e);
  const server = createAlertServer({ feed, accounts: ['5', '7'], status: () => ({ ok: true }) });
  const origin = await server.listen();
  try {
    assert.match(origin, /^http:\/\/127\.0\.0\.1:/);
    const list = await (await fetch(`${origin}/alerts?account=5`)).json();
    // The first event, pushed again after it left the list, stays out.
    assert.deepEqual(list.events.map((e) => e.id), ['5:x:2', '5:x:1']);
    assert.deepEqual((await (await fetch(`${origin}/alerts?account=7`)).json()).events, []);
    assert.equal((await fetch(`${origin}/alerts?account=8`)).status, 404);
    assert.equal((await fetch(`${origin}/alerts?account=05`)).status, 400);
    assert.equal((await fetch(`${origin}/alerts?account=5`, { method: 'POST' })).status, 405);
    assert.equal((await fetch(`${origin}/alerts?account=5`, { method: 'DELETE' })).status, 405);
    assert.deepEqual(await (await fetch(`${origin}/health`)).json(), { ok: true });
    // DNS rebinding: a page on another name that resolves to 127.0.0.1 is refused.
    const port = new URL(origin).port;
    const raw = (headers) => new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port, path: '/alerts?account=5', headers }, (r) => { r.resume(); resolve(r.statusCode); }).on('error', reject));
    assert.equal(await raw({ host: `attacker.example:${port}` }), 421);
    assert.equal(await raw({ host: `localhost:${port}` }), 200);
    assert.equal(await raw({ host: `127.0.0.1:${Number(port) + 1}` }), 421);
  } finally { await server.close(); }
  // With a token, every request needs it; extra host names can be allowed.
  const guarded = createAlertServer({ feed, accounts: ['5'], token: 't'.repeat(24), hosts: ['watch.internal:443'] });
  const at = await guarded.listen();
  try {
    assert.equal((await fetch(`${at}/alerts?account=5`)).status, 401);
    assert.equal((await fetch(`${at}/alerts?account=5`, { headers: { authorization: `Bearer ${'t'.repeat(23)}x` } })).status, 401);
    assert.equal((await fetch(`${at}/alerts?account=5`, { headers: { authorization: `Bearer ${'t'.repeat(24)}` } })).status, 200);
    const port = new URL(at).port;
    const status = await new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port, path: '/health', headers: { host: 'watch.internal:443', authorization: `Bearer ${'t'.repeat(24)}` } }, (r) => { r.resume(); resolve(r.statusCode); }).on('error', reject));
    assert.equal(status, 200);
  } finally { await guarded.close(); }
});

test('the health of the watch names no account', async () => {
  const watch = createSecurityWatch({ verifiedState: chain({ height: 10, elapsed: T0 }).fn, accounts: ['5', '4242'], onEvent: async () => {}, now: quietClock });
  await watch.poll(); await watch.settled();
  const text = JSON.stringify(watch.status());
  assert.doesNotMatch(text, /4242|"5"/);
  assert.equal(watch.status().accounts, 2);
  await watch.stop();
});

// ------------------------------------------------------------------ the deployable entry point
const trust = { app_version: '4', network_id: fixture.network_id, chain_id: 'time-devnet-v4-test' };
const config = (directory, extra = {}) => ({ gateway: 'https://wallet.example', trust, data_directory: directory, port: 18_000 + Math.floor(Math.random() * 1000), subscriptions: [{ account: '5', webhook: 'https://hooks.example/time/SECRETPATH', secret: HOOK_SECRET }], ...extra });

test('the watch config: defaults, and refusals', () => {
  const ok = validateConfig(config(path.resolve('/watch-data'), { port: undefined }));
  assert.deepEqual([ok.poll_seconds, ok.port, ok.host, ok.reminder_hours], [30, 8920, '127.0.0.1', 6]);
  for (const patch of [{ gateway: 'http://wallet.example' }, { gateway: 'https://u:p@wallet.example' }, { trust: { ...trust, app_version: '3' } }, { subscriptions: [] },
    { subscriptions: [{ account: '05' }] }, { subscriptions: [{ account: '5', webhook: 'http://hooks.example/x', secret: 'x'.repeat(16) }] }, { subscriptions: [{ account: '5', webhook: 'https://hooks.example/x' }] },
    { subscriptions: [{ account: '5', email: 'a@b.c' }] }, { poll_seconds: 1 }, { data_directory: 'relative' }, { sms: true },
    { host: '0.0.0.0' }, { feed_token: 'short' }, { hosts: ['Watch.Example'] }, { gateway_timeout_seconds: 0 }])
    assert.throws(() => validateConfig(config(path.resolve('/watch-data'), patch)), undefined, JSON.stringify(patch));
  // Beyond this machine only with a token.
  assert.equal(validateConfig(config(path.resolve('/watch-data'), { host: '0.0.0.0', feed_token: 'f'.repeat(24), hosts: ['watch.example:8920'] })).feed_token, 'f'.repeat(24));
  // An error never repeats a value of the config.
  for (const patch of [{ subscriptions: [{ account: '5', webhook: 'http://hooks.example/SECRETPATH', secret: 'TOPSECRET-0123456789' }] }, { subscriptions: [{ account: '5', webhook: 'https://hooks.example/SECRETPATH', secret: 'TOPSECRET-0123456789' }] }, { TOPSECRET: 1 }]) {
    const error = (() => { try { validateConfig(config(path.resolve('/watch-data'), patch)); } catch (e) { return e; } })();
    assert.doesNotMatch(error.message, /SECRETPATH|TOPSECRET/);
  }
  // A secret a person chose is refused, and the refusal says how to make one; the example is refused until its secret
  // is replaced by one that a command made.
  assert.throws(() => validateConfig(config(path.resolve('/watch-data'), { subscriptions: [{ account: '5', webhook: 'https://hooks.example/x', secret: 'subscription-secret-0123456789' }] })), /^Error: subscription 0: the secret is not 64 hexadecimal characters.*openssl rand -hex 32/);
  assert.throws(() => validateConfig(config(path.resolve('/watch-data'), { subscriptions: [{ account: '5', webhook: 'https://hooks.example/x', secret: 'ab'.repeat(32) }] })), /subscription 0: the secret repeats itself/);
  const example = JSON.parse(readFileSync(new URL('../deploy/watch/config.example.json', import.meta.url), 'utf8'));
  const filled = { ...example, trust, data_directory: path.resolve('/watch-data') };
  assert.throws(() => validateConfig(filled), /subscription 0: the secret is not 64 hexadecimal characters/);
  assert.equal(validateConfig({ ...filled, subscriptions: filled.subscriptions.map((s) => (s.secret ? { ...s, secret: randomBytes(32).toString('hex') } : s)) }).subscriptions.length, 2);
});

test('a config file that is not JSON is reported by position only, never by its text', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-config-'));
  try {
    for (const text of ['{"subscriptions":[{"account":"5","webhook":"https://hooks.example/x","secret":"TOPSECRET-0123456789abcdef"}] "x":1}', '{"secret": "TOPSECRET-0123456789abcdef",\n}', 'secret: TOPSECRET-0123456789abcdef']) {
      const file = path.join(directory, 'config.json');
      await writeFile(file, text);
      const error = await readConfig(file).catch((e) => e);
      assert.match(error.message, /^The config file is not valid JSON/);
      assert.doesNotMatch(error.message, /TOPSECRET|hooks\.example/);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('every request of the SDK to the gateway has a time limit, body included', async () => {
  const fetcher = (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
  const started = Date.now();
  await assert.rejects(boundedFetch(100, fetcher)('https://wallet.example/api/network', {}), /timeout|abort/i);
  assert.ok(Date.now() - started < 1000);
  // The SDK's own signal still works alongside.
  const own = new AbortController(); setTimeout(() => own.abort(), 20);
  await assert.rejects(boundedFetch(10_000, fetcher)('https://wallet.example/', { signal: own.signal }));
});

test('the watchdog tells owners and raises the alarm while a poll is stuck', async () => {
  let wall = quietClock(); const got = [];
  const watch = createSecurityWatch({ verifiedState: () => new Promise(() => {}), accounts: ['5'], onEvent: async (e) => got.push(e), now: () => wall, batchTimeoutMs: 3_600_000, watchdogMs: 1000, maxLagSeconds: 30 });
  watch.start(40);
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(watch.status().alarm, false);
  wall += 31_000;
  await new Promise((r) => setTimeout(r, 120));
  await watch.settled();
  assert.equal(watch.status().alarm, true);
  assert.deepEqual(got.map((e) => [e.type, e.urgent]), [['watch_blind', true]]);
  const stopped = await Promise.race([watch.stop().then(() => 'stopped'), new Promise((r) => setTimeout(() => r('hung'), 500))]);
  assert.equal(stopped, 'stopped');
});

test('the watch process serves recent events, delivers webhooks and logs no secret', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-start-'));
  const lines = [], scripted = chain({ height: 10, elapsed: T0 }), posted = [];
  const webhookFetcher = async (url, options) => { posted.push({ url, options }); return new Response(null, { status: 204 }); };
  let running;
  try {
    const settings = config(directory, { poll_seconds: 5 });
    running = await start(settings, { verifiedState: scripted.fn, webhookFetcher, now: quietClock, log: (level, message, fields) => lines.push(JSON.stringify({ level, message, ...fields })) });
    scripted.set({ height: 11, elapsed: T0 + 5n * S, security: withPayment });
    await running.watch.poll(); await running.watch.settled();
    const alerts = await (await fetch(`${running.url}/alerts?account=5`)).json();
    assert.deepEqual(alerts.events.map((e) => e.type), ['payment_waiting']);
    assert.equal(posted.length, 1);
    assert.equal(posted[0].url, 'https://hooks.example/time/SECRETPATH');
    assert.equal(verifyWebhookSignature(posted[0].options.body, posted[0].options.headers, settings.subscriptions[0].secret), true);
    await assert.rejects(start(settings, { verifiedState: scripted.fn, log: () => {} }), /already watches/);
    const log = lines.join('\n');
    assert.match(log, /security watch started/);
    assert.match(log, /https:\/\/hooks\.example/);
    assert.equal(log.includes(HOOK_SECRET), false);
    assert.doesNotMatch(log, /SECRETPATH/);
  } finally { await running?.close(); await rm(directory, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ waits that survive a stop
// On a network whose genesis has `waits_survive_stops`, every verified state carries the total of the chain's stops
// (`stopped_micros`), and the moments of a security row are on the clock of the waits: the chain's time less that
// total. After a stop the chain's time is far past them. A watch that reads them on the chain's time tells an owner
// that a freeze is over, that a raise took effect, or that a payment can go through now, while the chain holds the
// opposite: an owner who relies on the alert is misled exactly when it matters. These tests failed before the watch
// read the clock of the waits.
const HOUR = 3600n * S;
/// A snapshot of account 5 on such a network: `elapsed` is the chain's time since genesis, `stopped` the total of stops.
const ruled = (options, stopped) => { const v = verified(options); v.state.config = { waits_survive_stops: true }; v.state.stopped_micros = String(stopped); return snapshotOf(v, '5'); };
const frozenRow = { ...BASE, freezes: '1', frozen_until_elapsed_micros: String(T0 + 2n * HOUR) };

test('after a stop, a freeze the chain still holds is told as running, with its end at the earliest, and no "it has ended" comes early', () => {
  // First sight, after the chain stood still for ten hours, of which one counts: the freeze has an hour left.
  const event = only(diffSecurity(null, ruled({ height: 20, elapsed: T0 + 10n * HOUR, security: frozenRow }, 9n * HOUR)), 'frozen');
  assert.equal(event.already_over, false);
  assert.equal(event.frozen_until, '2026-11-10 09:30 UTC', 'the stored moment plus the nine hours of stop');
  assert.equal(event.earliest, true);
  assert.match(event.message, /^Your account 5 \(alice\) is frozen until 2026-11-10 09:30 UTC at the earliest\. Until then its spend key alone cannot pay from it/);
  // Seen before the stop and again after it: nothing has ended.
  const before = ruled({ height: 10, elapsed: T0, security: frozenRow }, 0n);
  assert.deepEqual(diffSecurity(before, ruled({ height: 20, elapsed: T0 + 10n * HOUR, security: frozenRow }, 9n * HOUR)), []);
  // An hour and a second of chain later it has.
  const ended = only(diffSecurity(ruled({ height: 20, elapsed: T0 + 10n * HOUR, security: frozenRow }, 9n * HOUR), ruled({ height: 30, elapsed: T0 + 11n * HOUR + S, security: frozenRow }, 9n * HOUR)), 'unfrozen');
  assert.equal(ended.reason, 'ended');
  // On a network without the rule the snapshot is what it was, and the same row is read on the chain's time: that
  // freeze ended eight hours ago, and a first sight tells nothing of it.
  const plain = snap({ height: 20, elapsed: T0 + 10n * HOUR, security: frozenRow });
  assert.deepEqual(['stopped_micros', 'waits_survive_stops'].filter((field) => field in plain), []);
  assert.deepEqual(diffSecurity(null, plain), []);
});

test('after a stop, a waiting payment keeps its earliest date, and its reminder comes on the clock of the waits, not early', () => {
  const pay = { ...BASE, pending_payments: [{ ...payment, ready_elapsed_micros: String(T0 + 3n * HOUR) }], next_id: '3' };
  const told = only(diffSecurity(ruled({ height: 10, elapsed: T0 }, 0n), ruled({ height: 11, elapsed: T0 + S, security: pay, balance: 50n * S - FEE }, 0n)), 'payment_waiting');
  assert.match(told.message, /can go through from 2026-11-10 01:30 UTC at the earliest unless you cancel it\./);
  assert.deepEqual([told.ready_at, told.earliest], ['2026-11-10 01:30 UTC', true]);
  // Ten hours later on the chain's time, one of which counts: two hours still to wait. No reminder says "now".
  const seen = ruled({ height: 11, elapsed: T0 + S, security: pay }, 0n), stopped = ruled({ height: 20, elapsed: T0 + 10n * HOUR + S, security: pay }, 9n * HOUR);
  assert.deepEqual(diffSecurity(seen, stopped, { reminderSeconds: 3600 }), []);
  // An hour of chain later the payment is an hour away: the reminder, with the date moved by the stop.
  const reminder = only(diffSecurity(stopped, ruled({ height: 30, elapsed: T0 + 11n * HOUR + S, security: pay }, 9n * HOUR), { reminderSeconds: 3600 }), 'reminder');
  assert.equal(reminder.message, 'Reminder: the payment of 12.5 s to account 42 can go through from 2026-11-10 10:30 UTC at the earliest. Cancel it before then if you did not start it.');
  assert.deepEqual([reminder.ready_at, reminder.earliest], ['2026-11-10 10:30 UTC', true]);
  // A payment that leaves the list before its time was cancelled, also when the chain's time is past it.
  const gone = only(diffSecurity(seen, ruled({ height: 20, elapsed: T0 + 10n * HOUR + S, security: { ...pay, pending_payments: [] } }, 9n * HOUR)), 'payment_gone');
  assert.deepEqual([gone.outcome, gone.certain, gone.urgent], ['cancelled', true, false]);
});

test('after a stop, a raise of the limit still waits, and the refill the spend key had is counted on the clock of the waits', () => {
  const raise = { ...BASE, pending_limit: { id: '2', daily_limit_micros: '2000000', ready_elapsed_micros: String(T0 + 3n * HOUR) }, next_id: '3' };
  // Read on the chain's time the raise would be in force ("took effect"); the chain still holds it for two hours.
  assert.deepEqual(diffSecurity(ruled({ height: 10, elapsed: T0, security: raise }, 0n), ruled({ height: 20, elapsed: T0 + 10n * HOUR, security: raise }, 9n * HOUR)), []);
  // A day of stop: the spend key could move one hour's worth of the limit, 0.5 s / 24, and a few fees. A fall of
  // 0.3 s is far more; on the chain's time a whole day's limit would have explained it.
  const drained = { ...BASE, allowance_micros: '0', allowance_elapsed_micros: String(T0) };
  const fell = only(diffSecurity(ruled({ height: 10, elapsed: T0, security: drained }, 0n), ruled({ height: 20, elapsed: T0 + 24n * HOUR, security: drained, nonce: '4', balance: 50n * S - 300000n }, 23n * HOUR)), 'balance_fell');
  assert.equal(fell.spend_key_budget_micros, String(500000n / 24n + 3n * FEE));
});

test('a snapshot stored before the watch knew the rule is compared without a false alarm', () => {
  // Stored by an older watch after a stop: no total of stops in it. Stops only grow, so the newer total is used.
  const old = ruled({ height: 20, elapsed: T0 + 10n * HOUR, security: frozenRow }, 9n * HOUR);
  delete old.stopped_micros; delete old.waits_survive_stops;
  assert.deepEqual(diffSecurity(old, ruled({ height: 21, elapsed: T0 + 10n * HOUR + 5n * S, security: frozenRow }, 9n * HOUR)), []);
});
