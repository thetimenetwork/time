// The alert watch and a change of the protocol version (docs/design/upgrade-mechanism.md, 8.2).
//
// Before this, a watch that met a version it does not implement behaved as if its gateway had
// stopped answering: an urgent `watch_blind` saying "the network gateway did not answer", and only
// once the allowed lag had passed. Now:
// - at the activation it sends an urgent `watch_outdated` at that very poll, in its own words, and
//   only for the verifier's own refusal (the code 'UPGRADE_REQUIRED'), never for words;
// - while the validators have scheduled a version, every owner gets `upgrade_scheduled` once per
//   plan, `upgrade_cancelled` if it is withdrawn, a daily `watch_outdated` reminder while this
//   build does not implement that version, and `watch_ready` once if the watch is updated;
// - the upgrade question never stands between an urgent event and its delivery. On a network
//   whose trust data declares that its nodes report upgrades it rides on every account check;
//   on any other network it is asked apart, after each poll, and never inside an account check.
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import './time-sdk.js';
import { EVENT_TYPES } from './security-watch.mjs';
import { createSecurityWatch, memoryStore, UPGRADE_ANSWERS_TO_RESTORE } from './security-watch-service.mjs';
import { start, UPGRADES_NOT_DECLARED } from '../deploy/watch/start.mjs';

const sdk = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const GENESIS = '1794260994671000', S = 1_000_000n, T0 = 2_407_000_000n;
const key = fixture.secure.payload.keys[0].public_key;
const DEVICES = fixture.secure.payload.keys.map((k) => ({ public_key: k.public_key, can_manage: k.role === 'recover', can_spend: k.role === 'spend' }));
const BASE = { ...fixture.allowance.security, pending_limit: null, account: '5' };
const chainMs = (elapsed) => Number((BigInt(GENESIS) + elapsed) / 1000n);
const REFUSAL = 'UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.';
/// The refusal as proof-verifier.mjs raises it: the verifier's sentence, with the code.
const refusal = (text = REFUSAL) => Object.assign(new Error(text), { code: 'UPGRADE_REQUIRED' });
const plan = { activate_elapsed_micros: String(T0 + 21n * 86_400n * S), scheduled_elapsed_micros: String(T0), spec: '5e'.repeat(32), version: '5' };
const types = (events) => events.map((e) => e.type);
/// A chain the test moves. `at.upgrade` is the row `upgrade/state` (null: proven absent); the state
/// carries it only when the selection asks, as a node answers. `at.fail` is what the read throws;
/// `at.hold(selection)` holds a read for ever; `at.refuse(selection)` refuses it as a gateway does.
function chain(ids = ['5']) {
  const at = { height: 10, elapsed: T0, fail: null, upgrade: null, hold: () => false, selections: [] };
  const state = (selection) => ({ protocol_version: '4', network_id: fixture.network_id, height: String(at.height), time_micros: (BigInt(GENESIS) + BigInt(at.elapsed)).toString(), genesis: { genesis_time_micros: GENESIS },
    accounts: ids.map((id) => ({ id, name: `a${id}`, public_key: key, balance: String(50n * S), nonce: '3', auth_epoch: '1', devices: DEVICES, delegations: [], unbonding: [] })),
    security: ids.map((id) => ({ ...BASE, account: id, ...(at.security ?? {}) })), config: {}, ...(selection?.include_upgrade && !at.omit ? { upgrade: at.upgrade } : {}) });
  const read = async (selection) => {
    at.selections.push(selection);
    if (at.hold(selection)) return new Promise(() => {});
    if (at.refuse?.(selection)) throw Object.assign(new Error('Pinned state unavailable: unknown field `include_upgrade`'), { gateway: true });
    if (at.fail) throw at.fail;
    return { verified: true, height: String(at.height), state: state(selection) };
  };
  return { at, fn: read, upgradeStatus: async () => sdk.upgradeStatusOf((await read({ include_upgrade: true })).state) };
}
/// A watch on `net` with a clock the test moves; `polled()` is one poll with everything delivered.
function watching(net, { ids = ['5'], ...options } = {}) {
  const got = [], logs = [], clock = { wall: chainMs(T0) + 500 };
  const watch = createSecurityWatch({ verifiedState: net.fn, upgradeStatus: net.upgradeStatus, accounts: ids, onEvent: async (e) => got.push(e), now: () => clock.wall, log: (level, message, fields) => logs.push({ level, message, ...fields }), ...options });
  const polled = async (advanceMs = 0) => { clock.wall += advanceMs; net.at.height += 1; net.at.elapsed = BigInt(clock.wall - 500) * 1000n - BigInt(GENESIS); const report = await watch.poll(); await watch.settled(); return report; };
  return { watch, got, logs, clock, polled };
}

test('the events of an upgrade are event types of the watch', () => {
  for (const type of ['upgrade_scheduled', 'upgrade_cancelled', 'watch_outdated', 'watch_ready', 'upgrade_question_unanswered', 'upgrade_question_answered']) assert.ok(EVENT_TYPES.includes(type), type);
  assert.equal(new Set(EVENT_TYPES).size, EVENT_TYPES.length);
});

// ---- the activation

test('at the activation the owner is told at once that the watch is outdated, not later that the gateway is silent', async () => {
  const net = chain(), { watch, got, logs, polled } = watching(net, { upgradeStatus: null });
  await polled(); assert.deepEqual(got, []);
  // One second later the network runs version 5: the verifier refuses the state.
  net.at.fail = refusal();
  const report = await polled(1000);
  assert.deepEqual(report.failed, ['5']); assert.equal(report.blind, 1);
  assert.deepEqual(types(got), ['watch_outdated']);
  const [event] = got;
  assert.deepEqual([event.account, event.urgent, event.reason, event.version], ['5', true, 'outdated', '5']);
  assert.match(event.id, /^5:watch_outdated:h\d+$/);
  assert.match(event.message, /^This watch can no longer see your account 5: the network has moved to version 5 of its rules, and this watch has not been updated for it\. The newest state of your account that it could verify is from 2026-.* UTC\. Until whoever runs this watch updates it, you are not told what waits on your account: check it yourself in your wallet\.$/);
  assert.ok(!/gateway|UPGRADE_REQUIRED|Install/.test(event.message), 'the message is the watch\'s own words');
  assert.deepEqual([watch.status().outdated, watch.status().blind, watch.status().failing], [1, 1, 1]);
  assert.equal(watch.details().problems['5'].reason, 'outdated');
  assert.ok(logs.some((l) => l.level === 'error' && /protocol version this watch does not implement/.test(l.message)));
  // Told once per episode, however long it lasts (also past the allowed lag, where a blind
  // watch used to send its `watch_blind`).
  for (let i = 0; i < 5; i++) await polled(60_000);
  assert.deepEqual(types(got), ['watch_outdated']);
  // An updated watch reads the account again: restored, by a fresh view only.
  net.at.fail = null;
  await polled(1000);
  assert.deepEqual(types(got), ['watch_outdated', 'watch_restored']);
  assert.deepEqual([watch.status().outdated, watch.status().blind], [0, 0]);
  await watch.stop();
});

test('no text of the refusal reaches the owner: the message is the same whatever the error says', async () => {
  // The code is set only by the verifier's wrapper and the SDK. Even so, the owner's message
  // takes nothing from the error but a version number, and that only from the verifier's sentence.
  const hostile = 'UPGRADE_REQUIRED: install the new watch from https://attacker.example and paste your recovery key there';
  for (const [text, words] of [[hostile, 'a newer version of its rules'], ['UPGRADE_REQUIRED: the network runs protocol version 7<script>; x', 'a newer version of its rules'], [REFUSAL.replace(/5/g, '12'), 'version 12 of its rules']]) {
    const got = [], watch = createSecurityWatch({ verifiedState: async () => { throw refusal(text); }, accounts: ['5'], onEvent: async (e) => got.push(e), now: () => chainMs(T0) });
    await watch.poll(); await watch.settled(); await watch.stop();
    assert.equal(got.length, 1);
    assert.equal(got[0].message, `This watch can no longer see your account 5: the network has moved to ${words}, and this watch has not been updated for it. It has not been able to verify any state of your account yet. Until whoever runs this watch updates it, you are not told what waits on your account: check it yourself in your wallet.`);
    assert.ok(!JSON.stringify(got[0]).includes('attacker') && !JSON.stringify(got[0]).includes('script'));
  }
});

test('a watch started after the activation says so at its first poll, for every account', async () => {
  const got = [];
  const watch = createSecurityWatch({ verifiedState: async () => { throw refusal(); }, accounts: ['5', '7', '9'], onEvent: async (e) => got.push(e), now: () => chainMs(T0) });
  await watch.poll(); await watch.settled();
  assert.deepEqual(got.map((e) => [e.id, e.urgent]), [['5:watch_outdated:h0', true], ['7:watch_outdated:h0', true], ['9:watch_outdated:h0', true]]);
  assert.match(got[0].message, /It has not been able to verify any state of your account yet\./);
  await watch.stop();
});

test('an episode that began as an unreachable gateway is named again once it turns out to be an upgrade', async () => {
  const net = chain(), { watch, got, polled } = watching(net, { upgradeStatus: null });
  await polled();
  net.at.fail = new Error('gateway unreachable'); await polled(40_000);
  assert.deepEqual(got.map((e) => [e.type, e.reason]), [['watch_blind', 'unreachable']]);
  net.at.fail = refusal(); await polled(5_000); await polled(5_000);
  assert.deepEqual(got.map((e) => [e.type, e.reason]), [['watch_blind', 'unreachable'], ['watch_outdated', 'outdated']]);
  await watch.stop();
});

test('the words alone are never the refusal: without the code it is a gateway that does not answer', async () => {
  // What a gateway can make the SDK throw, in every form: its words as they are, behind the SDK's
  // prefix, or as the text of an error it sent inside an array. None carries the code.
  for (const error of [new Error(REFUSAL), new Error('The gateway reports: ' + REFUSAL), new Error('The gateway reports: ["' + REFUSAL + '"]'), Object.assign(new Error(REFUSAL), { gateway: true }), Object.assign(new Error(REFUSAL), { code: 'upgrade_required' }), REFUSAL]) {
    const net = chain(), { watch, got, polled } = watching(net, { upgradeStatus: null });
    await polled();
    net.at.fail = error; await polled(1000);
    assert.deepEqual(got, [], String(error?.message ?? error)); assert.equal(watch.details().problems['5'].reason, 'unreachable');
    await polled(40_000);
    assert.deepEqual(got.map((e) => [e.type, e.reason]), [['watch_blind', 'unreachable']]);
    assert.ok(!got[0].message.includes('UPGRADE_REQUIRED'));
    await watch.stop();
  }
});

// ---- a scheduled plan

test('a scheduled upgrade: told once per plan, daily while this watch does not implement it, and its cancellation too', async () => {
  const net = chain(['5', '7']), { watch, got, logs, polled } = watching(net, { ids: ['5', '7'] });
  await polled(); assert.deepEqual(got, []);
  assert.deepEqual([watch.status().upgrade_scheduled, watch.status().upgrade_known, watch.status().upgrade_read], [null, null, 'ok']);
  // This network's trust data does not declare that its nodes report upgrades: the question is
  // asked apart, after the account check of every poll, and never rides on an account check.
  assert.deepEqual(net.at.selections.slice(0, 2), [{ ids: ['5', '7'], include_security: true }, { include_upgrade: true }]);
  await polled(30_000);
  assert.deepEqual(net.at.selections.slice(2), [{ ids: ['5', '7'], include_security: true }, { include_upgrade: true }]);
  // The validators schedule version 5, which this build does not implement.
  net.at.upgrade = { plan, signals: [] };
  await polled(30_000);
  assert.deepEqual(got.map((e) => [e.account, e.type, e.urgent]), [['5', 'upgrade_scheduled', false], ['5', 'watch_outdated', false], ['7', 'upgrade_scheduled', false], ['7', 'watch_outdated', false]]);
  const [scheduled, outdated] = got;
  assert.equal(scheduled.id, `5:upgrade_scheduled:v5:${'5e'.repeat(8)}:${plan.activate_elapsed_micros}:${plan.scheduled_elapsed_micros}`);
  assert.deepEqual([scheduled.version, scheduled.spec, scheduled.known], ['5', plan.spec, false]);
  assert.match(scheduled.starts, /^2026-\d\d-\d\d \d\d:\d\d UTC$/);
  assert.match(scheduled.message, /^The network of your account 5 has scheduled a change of its rules: version 5 starts on 2026-.* UTC\. This watch has not been updated for that version\./);
  assert.equal(outdated.reason, 'scheduled');
  assert.match(outdated.message, /^This watch does not implement version 5 of the network's rules, which starts on 2026-.* UTC\./);
  assert.deepEqual([watch.status().upgrade_scheduled, watch.status().upgrade_known], ['5', false]);
  assert.ok(logs.some((l) => l.level === 'warn' && /a protocol version this watch does not implement is scheduled/.test(l.message)));
  // Polled many times the same day: nothing more.
  for (let i = 0; i < 20; i++) await polled(30_000);
  assert.equal(got.length, 4);
  // The next days: the reminder once a day, the plan itself never again.
  for (let day = 1; day <= 3; day++) { await polled(86_400_000); await polled(30_000); }
  assert.deepEqual(types(got.slice(4)), Array(6).fill('watch_outdated'));
  assert.equal(new Set(got.map((e) => e.id)).size, got.length);
  // The plan is cancelled (signals remain, the plan is gone): the owners are told, once.
  let before = got.length;
  net.at.upgrade = { signals: [] }; await polled(30_000); await polled(30_000);
  assert.deepEqual(got.slice(before).map((e) => [e.account, e.type, e.urgent]), [['5', 'upgrade_cancelled', false], ['7', 'upgrade_cancelled', false]]);
  assert.match(got[before].message, /^The change of the rules of your account 5's network to version 5, which was scheduled for 2026-.* UTC, has been cancelled: too few validators still support it\. The network stays on version 4\. You need to do nothing\.$/);
  assert.deepEqual([watch.status().upgrade_scheduled, watch.status().upgrade_known], [null, null]);
  // Scheduled again with the same version, specification and start: a new plan, because it was
  // scheduled at another time. It is announced.
  before = got.length;
  net.at.upgrade = { plan: { ...plan, scheduled_elapsed_micros: String(T0 + 5n * 86_400n * S) }, signals: [] }; await polled(30_000);
  assert.deepEqual(types(got.slice(before)), ['upgrade_scheduled', 'watch_outdated', 'upgrade_scheduled', 'watch_outdated']);
  assert.notEqual(got[before].id, scheduled.id);
  // Replaced by another plan without a look in between: the old one is cancelled, the new one told.
  before = got.length;
  net.at.upgrade = { plan: { ...plan, activate_elapsed_micros: String(BigInt(plan.activate_elapsed_micros) + 86_400n * S), scheduled_elapsed_micros: String(T0 + 6n * 86_400n * S) }, signals: [] }; await polled(30_000);
  assert.deepEqual(got.slice(before).filter((e) => e.account === '5').map((e) => e.type), ['upgrade_cancelled', 'upgrade_scheduled', 'watch_outdated']);
  await watch.stop();
});

test('a watch updated while a plan stands tells the owner once that it is now ready', async () => {
  const net = chain(), store = memoryStore(); net.at.upgrade = { plan, signals: [] };
  const old = watching(net, { store });
  await old.polled(); await old.polled(30_000);
  assert.deepEqual(types(old.got), ['upgrade_scheduled', 'watch_outdated']);
  await old.watch.stop();
  // The same store under a build that implements version 5.
  const updated = watching(net, { store, upgradeStatus: async () => ({ ...(await net.upgradeStatus()), known: true }) });
  updated.clock.wall = old.clock.wall;
  await updated.polled(30_000); await updated.polled(30_000); await updated.polled(86_400_000);
  assert.deepEqual(types(updated.got), ['watch_ready']);
  assert.match(updated.got[0].message, /^This watch has been updated: it now implements version 5 of the network's rules, which starts on 2026-.* UTC, and keeps watching your account 5 across the change\.$/);
  assert.deepEqual([updated.watch.status().upgrade_scheduled, updated.watch.status().upgrade_known], ['5', true]);
  await updated.watch.stop();
  // A build that implements the version from the start says "ready" in the announcement itself.
  const fresh = watching(chainWith({ plan, signals: [] }), { upgradeStatus: async () => ({ version: '4', scheduled: plan, known: true }), upgradeOf: (state) => ({ ...sdk.upgradeStatusOf(state), known: true }) });
  await fresh.polled(); await fresh.polled(30_000);
  assert.deepEqual(types(fresh.got), ['upgrade_scheduled']);
  assert.match(fresh.got[0].message, /This watch is ready for it and keeps watching\./);
  await fresh.watch.stop();
  // The same on a network that declares it, where the status is read from the account checks (`upgradeOf`).
  const declaredReady = watching(chainWith({ plan, signals: [] }), { upgradeDeclared: true, upgradeOf: (state) => ({ ...sdk.upgradeStatusOf(state), known: true }) });
  await declaredReady.polled(); await declaredReady.polled(30_000);
  assert.deepEqual(types(declaredReady.got), ['upgrade_scheduled']);
  assert.match(declaredReady.got[0].message, /This watch is ready for it and keeps watching\./);
  await declaredReady.watch.stop();
});
function chainWith(upgrade) { const net = chain(); net.at.upgrade = upgrade; return net; }

// ---- the question never holds an alert, and cannot be singled out

test('an urgent account event is delivered before the upgrade question is even asked', async () => {
  const net = chain(), order = [];
  const { watch, got, polled } = watching(net, { upgradeStatus: async () => { order.push('upgrade question'); return new Promise(() => {}); }, onEvent: async (e) => { order.push(e.type); got.push(e); }, batchTimeoutMs: 400 });
  await polled();
  net.at.security = { pending_payments: [{ id: '2', to: '42', amount: '12500000', ready_elapsed_micros: String(net.at.elapsed + 65n * S) }], next_id: '3' };
  order.length = 0;
  const began = performance.now(); let deliveredAfter = null;
  const poll = watch.poll(); await poll; deliveredAfter = performance.now() - began;
  await watch.settled();
  assert.deepEqual(order.slice(0, 2), ['payment_waiting', 'upgrade question'], 'the alert left first');
  assert.ok(deliveredAfter < 300, `the poll took ${Math.round(deliveredAfter)} ms: it waited for the upgrade question`);
  assert.equal(got.find((e) => e.type === 'payment_waiting').urgent, true);
  assert.equal(watch.status().upgrade_read, 'failing');
  await watch.stop();
});

const singledOut = (selection) => selection?.include_upgrade === true;
function attack(net, kind) {
  if (kind === 'hold') net.at.hold = singledOut;
  if (kind === 'refuse') net.at.refuse = singledOut;
  if (kind === 'omit') net.at.omit = true;
  return () => { net.at.hold = () => false; net.at.refuse = null; net.at.omit = false; };
}

test('a network whose trust data declares it: the question is on every account check from the first poll, nothing is learned, and singling it out fails the check', async () => {
  for (const kind of ['hold', 'refuse', 'omit']) {
    const net = chain(), store = memoryStore(); let probed = 0;
    const { watch, got, polled } = watching(net, { upgradeDeclared: true, upgradeStatus: async () => { probed += 1; return { version: '4', scheduled: null, known: true }; }, batchTimeoutMs: 200, store });
    await polled();
    // From the very first read, and never by a question of its own.
    assert.deepEqual(net.at.selections, [{ ids: ['5'], include_security: true, include_upgrade: true }]);
    assert.equal(probed, 0);
    assert.deepEqual([watch.status().upgrade_read, (await store.get()).upgrade.capable], ['ok', false], 'nothing is learned or stored about it');
    // A plan is told as on any network.
    net.at.upgrade = { plan, signals: [] }; await polled(30_000);
    assert.deepEqual(types(got), ['upgrade_scheduled', 'watch_outdated']);
    // The gateway singles the question out: the account check itself fails. No fallback.
    attack(net, kind);
    const report = await polled(1000);
    assert.deepEqual(report.failed, ['5'], kind);
    assert.equal(watch.details().problems['5'].reason, 'unreachable', kind);
    assert.ok(net.at.selections.every((selection) => selection.include_upgrade === true), 'no check was made without the question');
    assert.equal(got.length, 2, kind);
    // Past the allowed lag the owner is told that the watch cannot see the account.
    await polled(40_000);
    assert.deepEqual(got.slice(2).map((e) => [e.type, e.urgent, e.reason]), [['watch_blind', true, 'unreachable']], kind);
    assert.deepEqual([probed, (await store.get()).upgrade.capable, (await store.get()).upgrade.unanswered], [0, false, null]);
    await watch.stop();
  }
  assert.throws(() => createSecurityWatch({ verifiedState: async () => ({}), upgradeDeclared: 'yes', accounts: ['5'], onEvent: async () => {} }), /upgradeDeclared and forgetUpgradeAnswer are true or false/);
});

const payment = (net) => ({ pending_payments: [{ id: '2', to: '42', amount: '12500000', ready_elapsed_micros: String(net.at.elapsed + 95n * S) }], next_id: '3' });

test('a network that does not declare it: the question is asked apart, so singling it out neither fails nor delays an account check, and the owner is told with an event type of its own', async () => {
  for (const kind of ['hold', 'refuse', 'omit']) {
    const net = chain(), store = memoryStore(), times = {};
    const { watch, got, logs, polled } = watching(net, { batchTimeoutMs: 300, store, onEvent: async (e) => { times[e.type] ??= performance.now(); got.push(e); } });
    await polled(); await polled(30_000);
    assert.equal((await store.get()).upgrade.capable, true, 'a node has answered');
    assert.deepEqual([watch.status().upgrade_declared, watch.status().upgrade_read], [false, 'ok']);
    // From here the gateway singles out every request that carries the question, while a payment starts waiting.
    const undo = attack(net, kind);
    net.at.security = payment(net);
    watch.status(); const began = performance.now();
    const report = await watch.poll(), pollMs = performance.now() - began;
    await watch.settled();
    assert.deepEqual(report.failed, [], kind);
    // The urgent alert left at once: it did not wait for the question, not even this first time.
    assert.ok(pollMs < 200 && times.payment_waiting - began < 200, `${kind}: the poll took ${Math.round(pollMs)} ms`);
    assert.deepEqual(got.map((e) => [e.type, e.urgent, e.reason ?? null]), [['payment_waiting', true, null], ['upgrade_question_unanswered', false, null]], kind);
    assert.match(got[1].message, /^This message is only about scheduled changes of the network's rules, not about what this watch sees of your account 5\. The network gateway does not answer this watch's question about such changes, which it answered before/);
    assert.ok(!/did not answer its last checks|include_upgrade|unknown field|cannot see your account/.test(got[1].message), 'its own words, and nothing about the account being unseen');
    assert.deepEqual([watch.status().failing, watch.status().blind, watch.status().upgrade_read], [0, 0, 'unanswered'], kind);
    assert.ok(logs.some((l) => l.level === 'error' && /--forget-upgrade-answer/.test(l.message)));
    // It lasts: told once, no account check fails, and no account check ever carries the question.
    for (let i = 0; i < 3; i++) assert.deepEqual((await polled(20_000)).failed, []);
    assert.equal(got.length, 2, kind);
    assert.ok(net.at.selections.filter((selection) => selection.ids).every((selection) => !Object.hasOwn(selection, 'include_upgrade')));
    // The gateway answers again, and a plan was scheduled meanwhile. The first answer is used at
    // once (the plan is announced), but the episode is over only after several answers in a row.
    undo(); net.at.upgrade = { plan, signals: [] };
    await polled(20_000);
    assert.deepEqual(types(got.slice(2)), ['upgrade_scheduled', 'watch_outdated'], kind);
    assert.deepEqual([watch.status().upgrade_read, (await store.get()).upgrade.unanswered.answers], ['unanswered', 1]);
    for (let i = 1; i < UPGRADE_ANSWERS_TO_RESTORE; i++) await polled(20_000);
    assert.deepEqual(got.slice(4).map((e) => [e.type, e.urgent]), [['upgrade_question_answered', false]], kind);
    assert.match(got[4].message, /^This message is only about scheduled changes of the network's rules, not about what this watch sees of your account 5\. The network gateway answers this watch's question about such changes again/);
    assert.deepEqual([watch.status().upgrade_read, (await store.get()).upgrade.unanswered], ['ok', null]);
    await polled(20_000); await polled(20_000);
    assert.equal(got.length, 5, 'nothing is said twice');
    await watch.stop();
  }
});

test('a gateway that answers the question now and then cannot flip the watch: at most one message in 24 hours, and "answered again" only after several answers in a row', async () => {
  assert.equal(UPGRADE_ANSWERS_TO_RESTORE, 3);
  const net = chain(), store = memoryStore(); let asked = 0, answers = () => true;
  const upgradeStatus = async () => { if (!answers(asked++)) throw Object.assign(new Error('Pinned state unavailable: unknown field `include_upgrade`'), { gateway: true }); return { version: '4', scheduled: null, known: true }; };
  const { watch, got, polled } = watching(net, { store, upgradeStatus });
  await polled();
  assert.equal((await store.get()).upgrade.capable, true);
  // Every other question is refused, for 40 polls (20 minutes at the default interval).
  asked = 0; answers = (n) => n % 2 === 1;
  for (let i = 0; i < 40; i++) assert.deepEqual((await polled(30_000)).failed, []);
  assert.deepEqual(got.map((e) => [e.type, e.urgent]), [['upgrade_question_unanswered', false]], 'one message, however often it flips');
  assert.equal(watch.status().upgrade_read, 'unanswered');
  // A refusal and then two answers in a row, again and again: still not "answered".
  asked = 0; answers = (n) => n % 3 !== 0;
  for (let i = 0; i < 30; i++) await polled(30_000);
  assert.equal(got.length, 1);
  // Three in a row: "answered again", once.
  answers = () => true;
  for (let i = 0; i < 5; i++) await polled(30_000);
  assert.deepEqual(types(got), ['upgrade_question_unanswered', 'upgrade_question_answered']);
  assert.equal(watch.status().upgrade_read, 'ok');
  // Refused again within the same 24 hours: a new episode on /health, and no second message.
  answers = () => false;
  for (let i = 0; i < 5; i++) await polled(30_000);
  assert.equal(got.length, 2);
  assert.equal(watch.status().upgrade_read, 'unanswered');
  // 24 hours after the first message, still unanswered: the owner is told again, once.
  await polled(86_400_000); await polled(30_000); await polled(30_000);
  assert.deepEqual(types(got.slice(2)), ['upgrade_question_unanswered']);
  // Answered three times in a row: one "answered again" for that message, and no more.
  answers = () => true;
  for (let i = 0; i < 6; i++) await polled(30_000);
  assert.deepEqual(types(got.slice(3)), ['upgrade_question_answered']);
  assert.equal(new Set(got.map((e) => e.id)).size, 4);
  // No account check was ever failed, delayed or asked with the question.
  assert.ok(net.at.selections.every((selection) => selection.ids && !Object.hasOwn(selection, 'include_upgrade')));
  await watch.stop();
});

test('the two messages about the question are the last word only about the question: a watch that is blind says so with watch_blind, and is never called restored by them', async () => {
  const net = chain(), store = memoryStore(), { watch, got, polled } = watching(net, { store });
  await polled(); await polled(30_000);
  // The gateway goes dark for the account checks but answers the question alone.
  net.at.refuse = (selection) => Array.isArray(selection?.ids);
  for (let i = 0; i < 12; i++) await polled(30_000);
  assert.deepEqual(got.map((e) => [e.type, e.urgent, e.reason]), [['watch_blind', true, 'unreachable']]);
  assert.equal(watch.status().upgrade_read, 'ok', 'the question is answered, and that says nothing about the account');
  // Now the other way round and back: the question's own messages come and go while the account stays unseen.
  net.at.refuse = () => true;
  await polled(30_000);
  net.at.refuse = (selection) => Array.isArray(selection?.ids);
  for (let i = 0; i < UPGRADE_ANSWERS_TO_RESTORE; i++) await polled(30_000);
  assert.deepEqual(types(got.slice(1)), ['upgrade_question_unanswered', 'upgrade_question_answered']);
  assert.ok(got.every((e) => e.type !== 'watch_restored'), 'nothing says the watch is restored');
  assert.equal(watch.status().blind, 1);
  for (const e of got.slice(1)) assert.match(e.message, /^This message is only about scheduled changes of the network's rules, not about what this watch sees of your account 5\./);
  // Only a fresh view of the account restores it.
  net.at.refuse = null; await polled(30_000);
  assert.deepEqual(got.slice(3).map((e) => [e.type, e.reason ?? null]), [['watch_restored', null]]);
  await watch.stop();
});

test('the operator can make the watch forget a learned answer; a store whose memory of upgrades is not as expected is treated as none', async () => {
  const net = chain(), store = memoryStore();
  const first = watching(net, { store });
  await first.polled(); await first.polled(30_000);
  assert.equal((await store.get()).upgrade.capable, true);
  // The node was replaced by one that does not know the question: the owner is told.
  net.at.refuse = singledOut;
  await first.polled(30_000);
  assert.deepEqual(types(first.got), ['upgrade_question_unanswered']);
  await first.watch.stop();
  const told = (await store.get()).upgrade.told_unanswered;
  assert.equal(told, first.clock.wall);
  // Started once with the option: the earlier answer is forgotten. From then on this is a network
  // whose nodes never answered, about which nothing is said to owners, also on the next days.
  const forgetful = watching(net, { store, forgetUpgradeAnswer: true });
  forgetful.clock.wall = first.clock.wall;
  for (const wait of [30_000, 30_000, 86_400_000, 86_400_000]) assert.deepEqual((await forgetful.polled(wait)).failed, []);
  assert.deepEqual(forgetful.got, []);
  assert.deepEqual([(await store.get()).upgrade.capable, (await store.get()).upgrade.unanswered, (await store.get()).upgrade.told_unanswered, forgetful.watch.status().upgrade_read], [false, null, told, 'failing']);
  assert.ok(forgetful.logs.some((l) => l.level === 'info' && /forgot that a node of this network answered/.test(l.message)));
  assert.equal(forgetful.logs.filter((l) => /upgrade status could not be read/.test(l.message)).length, 1);
  await forgetful.watch.stop();
  // What the store may hold in `upgrade` after an edit by hand or another build: never a reason to stop.
  for (const memory of [null, 'yes', 7, [], {}, { capable: 'no' }, { capable: true, plan: {} }, { capable: true, plan: { key: 1 } }, { capable: false, unanswered: { since: 'x' } }, { capable: true, unanswered: { since: 5, answers: 'many' }, told_unanswered: 'yesterday', told_answered: -1 }, { capable: true, unanswered: { since: 5, answers: 99 } }]) {
    const damaged = memoryStore(), plain = chain();
    const before = watching(plain, { store: damaged }); await before.polled(); await before.watch.stop();
    const saved = await damaged.get(); saved.upgrade = memory; await damaged.put(saved);
    const after = watching(plain, { store: damaged }); after.clock.wall = before.clock.wall;
    assert.deepEqual((await after.polled(30_000)).failed, [], JSON.stringify(memory));
    const kept = (await damaged.get()).upgrade;
    assert.equal(typeof kept.capable, 'boolean');
    assert.ok(kept.unanswered === null || (kept.unanswered.answers >= 0 && kept.unanswered.answers < UPGRADE_ANSWERS_TO_RESTORE), JSON.stringify(memory));
    assert.ok([kept.told_unanswered, kept.told_answered].every((t) => t === null || Number.isSafeInteger(t)), JSON.stringify(memory));
    await after.watch.stop();
  }
});

test('a question that cannot be answered is logged once, shown on /health, and changes nothing else', async () => {
  const net = chain(), store = memoryStore();
  let answer = async () => { throw new Error('missing requested proof for 757067726164652f7374617465'); };
  const first = watching(net, { store, upgradeStatus: () => answer() });
  for (let i = 0; i < 3; i++) assert.deepEqual((await first.polled(30_000)).failed, []);
  assert.deepEqual(first.got, []);
  assert.equal(first.logs.filter((l) => /upgrade status could not be read/.test(l.message)).length, 1);
  assert.equal(first.watch.status().upgrade_read, 'failing');
  assert.ok(net.at.selections.every((selection) => !Object.hasOwn(selection, 'include_upgrade')), 'the account checks do not carry the question');
  // It can be answered; then the watch restarts on the same store and keeps asking apart.
  net.at.upgrade = { plan, signals: [] }; answer = net.upgradeStatus;
  await first.polled(30_000); assert.deepEqual(types(first.got), ['upgrade_scheduled', 'watch_outdated']);
  assert.equal(first.watch.status().upgrade_read, 'ok');
  await first.watch.stop();
  const second = watching(net, { store });
  second.clock.wall = first.clock.wall;
  net.at.selections.length = 0;
  await second.polled(30_000);
  assert.deepEqual(second.got, [], 'nothing is announced twice after a restart');
  assert.deepEqual(net.at.selections, [{ ids: ['5'], include_security: true }, { include_upgrade: true }]);
  await second.watch.stop();
  assert.throws(() => createSecurityWatch({ verifiedState: net.fn, upgradeStatus: 'yes', accounts: ['5'], onEvent: async () => {} }), /upgradeStatus is a function/);
  // A watch without the option never asks.
  const plain = chain(), none = watching(plain, { upgradeStatus: null });
  await none.polled(); await none.polled(30_000);
  assert.deepEqual(plain.at.selections, [{ ids: ['5'], include_security: true }, { ids: ['5'], include_security: true }]);
  assert.equal(none.watch.status().upgrade_read, 'off');
  await none.watch.stop();
});

test('the watch process asks for the plan and delivers both notices to the feed', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-upgrade-')), net = chain(); net.at.upgrade = { plan, signals: [] };
  const settings = { gateway: 'https://gateway.example', trust: { app_version: '4', network_id: fixture.network_id, chain_id: 'time-devnet-v4-test' }, subscriptions: [{ account: '5' }], data_directory: directory, port: 18931, poll_seconds: 3600 };
  let running;
  try {
    const lines = [];
    running = await start(settings, { verifiedState: net.fn, upgradeStatus: net.upgradeStatus, now: () => chainMs(T0) + 500, log: (level, message, fields) => lines.push({ level, message, ...fields }) });
    // This trust data does not say that the nodes report upgrades: the start log says so, and warns.
    assert.equal(lines.find((l) => l.message === 'security watch started').nodes_report_upgrades, false);
    assert.equal(lines.filter((l) => l.level === 'warn' && l.message === UPGRADES_NOT_DECLARED).length, 1);
    assert.match(UPGRADES_NOT_DECLARED, /^the trust data does not say that this network's nodes report upgrades \(trust\.nodes_report_upgrades is not true\)/);
    await running.watch.poll(); await running.watch.settled();
    const answer = await (await fetch(`${running.url}/alerts?account=5`)).json();
    assert.deepEqual(answer.events.map((e) => e.type).sort(), ['upgrade_scheduled', 'watch_outdated']);
    const health = await (await fetch(`${running.url}/health`)).json();
    assert.deepEqual([health.upgrade_scheduled, health.upgrade_known, health.upgrade_read, health.outdated, health.upgrade_declared], ['5', false, 'ok', 0, false]);
  } finally { await running?.close(); await rm(directory, { recursive: true, force: true }); }
  // The trust anchor of the watch names the first version and only that.
  await assert.rejects(start({ ...settings, trust: { ...settings.trust, app_version: '5' } }, { verifiedState: net.fn, log: () => {} }), /application-4 trust manifest/);
  // Whether the nodes report upgrades is read from that trust data: true, false or absent, nothing else.
  for (const said of ['true', 1, null]) await assert.rejects(start({ ...settings, trust: { ...settings.trust, nodes_report_upgrades: said } }, { verifiedState: net.fn, log: () => {} }), /trust\.nodes_report_upgrades is true or false/);
  const declaredDirectory = await mkdtemp(path.join(os.tmpdir(), 'time-watch-declared-')), declaredNet = chain(); declaredNet.at.upgrade = { plan, signals: [] };
  let declared;
  try {
    const lines = [];
    declared = await start({ ...settings, data_directory: declaredDirectory, port: 18932, trust: { ...settings.trust, nodes_report_upgrades: true } }, { verifiedState: declaredNet.fn, upgradeStatus: async () => { throw new Error('a declared network is never probed'); }, now: () => chainMs(T0) + 500, log: (level, message, fields) => lines.push({ level, message, ...fields }) });
    await declared.watch.poll(); await declared.watch.settled();
    assert.equal(lines.find((l) => l.message === 'security watch started').nodes_report_upgrades, true);
    assert.equal(lines.some((l) => l.message === UPGRADES_NOT_DECLARED), false);
    assert.equal((await (await fetch(`${declared.url}/health`)).json()).upgrade_declared, true);
    assert.equal(declaredNet.at.selections.find((selection) => selection.ids).include_upgrade, true, 'carried from the first poll');
    assert.ok(declaredNet.at.selections.every((selection) => selection.ids), 'no question of its own');
    assert.deepEqual((await (await fetch(`${declared.url}/alerts?account=5`)).json()).events.map((e) => e.type).sort(), ['upgrade_scheduled', 'watch_outdated']);
  } finally { await declared?.close(); await rm(declaredDirectory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
});
