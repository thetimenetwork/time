// The alert watch and the upgrade signal of a watched account's validator (action kind 80).
//
// A signal is signed by a key of the account that may spend. The design answers a stolen spend
// key with "the owner freezes" (docs/design/upgrade-mechanism.md, 5.2); for that the owner must
// learn of a signal it did not send. These tests hold that in place:
// - the pure part (security-watch.mjs `signalOf`, `diffSignal`): what is told for which change,
//   in which words, and that a reading without the upgrade entry is never "no signal";
// - the service: the event comes from the same verified read as the account, is told once, is
//   remembered across a restart, takes an older store without a false alarm, and cannot hold
//   back a security alert.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import './time-sdk.js';
import { EVENT_TYPES, snapshotOf, signalOf, diffSignal, groupHash } from './security-watch.mjs';
import { createSecurityWatch, memoryStore } from './security-watch-service.mjs';

const fixture = JSON.parse(await readFile(new URL('./account-security.fixture.json', import.meta.url), 'utf8'));
const GENESIS = '1794260994671000', S = 1_000_000n, DAY = 86_400n * S, T0 = 2_407n * S;
const key = fixture.secure.payload.keys[0].public_key;
const DEVICES = fixture.secure.payload.keys.map((k) => ({ public_key: k.public_key, can_manage: k.role === 'recover', can_spend: k.role === 'spend' }));
const BASE = { ...fixture.allowance.security, pending_limit: null, account: '5' };
const chainMs = (elapsed) => Number((BigInt(GENESIS) + elapsed) / 1000n);
const SPEC = '5e7a91c3'.repeat(8), OTHER = '5e7a91c3'.repeat(7) + '5e7a91c4';
const planOf = (spec = SPEC) => ({ version: '5', spec, activate_elapsed_micros: String(T0 + 30n * DAY) });
const entry = (owner, plan, changed) => ({ ...(plan || {}), changed_elapsed_micros: String(changed), owner: String(owner) });
const types = (events) => events.map((e) => e.type);
const utcOf = (elapsed) => new Date(chainMs(BigInt(elapsed))).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

/// A chain the test moves. `at.signals` are the entries of the upgrade row; the state carries the row only
/// when the selection asks for it, as a node answers. `at.secured` false: accounts with plain keys, no security row.
function chain(ids = ['5']) {
  const at = { height: 10, elapsed: T0, signals: [], secured: true, security: {}, selections: [] };
  const state = (selection) => ({ protocol_version: '4', network_id: fixture.network_id, height: String(at.height), time_micros: (BigInt(GENESIS) + BigInt(at.elapsed)).toString(), genesis: { genesis_time_micros: GENESIS },
    accounts: ids.map((id) => ({ id, name: `a${id}`, public_key: key, balance: String(50n * S), nonce: '3', auth_epoch: '1', devices: at.secured ? DEVICES : [{ public_key: key, can_manage: true, can_spend: true }], delegations: [], unbonding: [] })),
    security: at.secured ? ids.map((id) => ({ ...BASE, account: id, ...at.security })) : [], config: {},
    ...(selection?.include_upgrade ? { upgrade: at.signals.length ? { signals: [...at.signals].sort((a, b) => (BigInt(a.owner) < BigInt(b.owner) ? -1 : 1)) } : null } : {}) });
  return { at, state, fn: async (selection) => { at.selections.push(selection); return { verified: true, height: String(at.height), state: state(selection) }; } };
}
/// A watch on `net` with a clock the test moves; `polled()` is one poll with everything delivered.
/// `declared`: the network's trust data says that its nodes report upgrades, so every account check carries the entry.
function watching(net, { ids = ['5'], declared = true, ...options } = {}) {
  const got = [], logs = [], clock = { wall: chainMs(BigInt(net.at.elapsed)) + 500 };
  const watch = createSecurityWatch({ verifiedState: net.fn, upgradeDeclared: declared, accounts: ids, onEvent: async (e) => got.push(e), now: () => clock.wall, log: (level, message, fields) => logs.push({ level, message, ...fields }), ...options });
  const polled = async (advanceMs = 30000) => { clock.wall += advanceMs; net.at.height += 1; net.at.elapsed = BigInt(clock.wall - 500) * 1000n - BigInt(GENESIS); const report = await watch.poll(); await watch.settled(); return report; };
  return { watch, got, logs, clock, polled };
}
const snap = (net, selection = { include_upgrade: true }) => snapshotOf({ state: net.state(selection) }, '5');

test('the signal of an account in a verified state: unknown without the upgrade entry, never "no signal" by default', () => {
  const net = chain();
  // A state read without the upgrade entry says nothing, and the snapshot has no `signal` at all.
  assert.equal(signalOf(net.state({}), '5'), undefined);
  assert.equal(Object.hasOwn(snap(net, {}), 'signal'), false);
  // With the entry: no signal of the account is proven absent; a withdrawal and support are told apart.
  assert.deepEqual([signalOf(net.state({ include_upgrade: true }), '5'), snap(net).signal], [null, null]);
  net.at.signals = [entry(4, planOf(), 5), entry(5, null, 7), entry(6, planOf(OTHER), 9)];
  assert.deepEqual(snap(net).signal, { withdrawn: true, changed_elapsed_micros: '7' });
  net.at.signals = [entry(5, planOf(), 7), entry(6, planOf(OTHER), 9)];
  assert.deepEqual(snap(net).signal, { ...planOf(), changed_elapsed_micros: '7' });
  assert.equal(signalOf(net.state({ include_upgrade: true }), '7'), null);
  // An entry that is not in the form this build knows is unknown, not absent and not an error: the account's
  // security alerts must not depend on it.
  for (const damaged of [{ ...entry(5, planOf(), 7), spec: SPEC.toUpperCase() }, { ...entry(5, planOf(), 7), spec: SPEC.slice(1) }, { ...entry(5, planOf(), 7), version: 5 }, { owner: '5', changed_elapsed_micros: '7', version: '5' }, { owner: '5' }, { ...entry(5, planOf(), 7), activate_elapsed_micros: '-1' }]) {
    assert.equal(signalOf({ upgrade: { signals: [damaged] } }, '5'), undefined, JSON.stringify(damaged));
  }
  assert.deepEqual([signalOf({ upgrade: { signals: 'x' } }, '5'), signalOf({ upgrade: {} }, '5'), signalOf(null, '5'), signalOf({ upgrade: null }, '5')], [undefined, undefined, undefined, null]);
  assert.equal(groupHash(SPEC), '5e7a91c3 5e7a91c3 5e7a91c3 5e7a91c3 5e7a91c3 5e7a91c3 5e7a91c3 5e7a91c3');
  for (const type of ['upgrade_signal_changed', 'upgrade_signal_dropped']) assert.ok(EVENT_TYPES.includes(type), type);
  assert.equal(new Set(EVENT_TYPES).size, EVENT_TYPES.length);
});

test('what is told for which change of the signal, and in which words', () => {
  const net = chain(), none = snap(net), changed = T0 + 60n * S;
  const later = (signals, more = {}) => { net.at.signals = signals; net.at.height += 1; Object.assign(net.at, more); return snap(net); };
  // Nothing before and nothing now; a reading that does not know says nothing, whatever was before.
  assert.deepEqual(diffSignal(none, later([])), []);
  const supported = later([entry(5, planOf(), changed)]);
  assert.deepEqual([diffSignal(none, snap(net, {})), diffSignal(supported, snap(net, {})), diffSignal(null, snap(net, {})), diffSignal(supported, null)], [[], [], [], []]);
  // Support appears: urgent, with the version, the whole hash in groups, the start and the time of the signal in UTC.
  const [told] = diffSignal(none, supported);
  assert.deepEqual([told.type, told.urgent, told.account, told.id, told.first_sight, told.signal, told.previous, told.at_height], ['upgrade_signal_changed', true, '5', `5:upgrade_signal_changed:5-${SPEC}-${planOf().activate_elapsed_micros}-${changed}`, false, { ...planOf(), changed_elapsed_micros: String(changed) }, null, supported.height]);
  assert.equal(told.message, `The validator of your account 5 (a5) now supports a change of the network's rules: version 5, start ${utcOf(planOf().activate_elapsed_micros)} at the earliest, specification hash ${groupHash(SPEC)}. The signal was sent at ${utcOf(changed)}. If you sent it, compare the hash with the release announcement, group by group; nothing else is to do. If you did not send it, someone has your spend key: freeze your account now and replace your keys. Then withdraw the signal in the wallet, tab "Validator signal" once the account can sign again (a frozen account can neither signal nor withdraw).`);
  assert.equal(/[0-9a-f]{64}/.test(told.message), false, 'the hash is not in the text as one run that can be copied');
  // The same entry read again, at any later height: nothing. The id never depends on when it was seen.
  assert.deepEqual(diffSignal(supported, later([entry(5, planOf(), changed)])), []);
  assert.equal(diffSignal(none, later([entry(5, planOf(), changed)]))[0].id, told.id);
  // Another plan, or the same plan signalled again later: a new entry, a new event.
  const other = diffSignal(supported, later([entry(5, planOf(OTHER), changed + 700n * S)]));
  assert.deepEqual([types(other), other[0].urgent, other[0].previous.spec, other[0].message.includes(groupHash(OTHER)), other[0].id === told.id], [['upgrade_signal_changed'], true, SPEC, true, false]);
  assert.notEqual(diffSignal(supported, later([entry(5, planOf(), changed + 700n * S)]))[0].id, told.id);
  // A withdrawal: urgent, names what was supported.
  const [withdrawn] = diffSignal(supported, later([entry(5, null, changed + 700n * S)]));
  assert.deepEqual([withdrawn.type, withdrawn.urgent, withdrawn.id, withdrawn.signal], ['upgrade_signal_changed', true, `5:upgrade_signal_changed:withdrawn-${changed + 700n * S}`, { withdrawn: true, changed_elapsed_micros: String(changed + 700n * S) }]);
  assert.equal(withdrawn.message, `The validator of your account 5 (a5) no longer supports a change of the network's rules: its support for version 5, start ${utcOf(planOf().activate_elapsed_micros)} at the earliest, specification hash ${groupHash(SPEC)} was withdrawn. The signal was sent at ${utcOf(changed + 700n * S)}. If you withdrew it, nothing is to do. If you did not, someone has your spend key: freeze your account now and replace your keys. Then signal again in the wallet, tab "Validator signal" once the account can sign again (a frozen account can neither signal nor withdraw), if your validator should support the plan.`);
  // An account with plain keys (no security row) is told what it can do: there is no freeze.
  const plainNone = later([], { secured: false }), [plain] = diffSignal(plainNone, later([entry(5, planOf(), changed)]));
  assert.match(plain.message, /If you did not send it, someone has a key of your account that may spend: remove every key you do not know from the account now, in the wallet \(Devices\)\. Then withdraw the signal in the wallet, tab "Validator signal"\.$/);
  net.at.secured = true;
  // The first reading of an account's signal (a new watch, or a store of a build before this one): what stands
  // is told once, not as an alarm, and the watch says that it cannot know whether it is new. A withdrawal that
  // stands is not told.
  const standing = later([entry(5, planOf(), changed)]), unknown = { ...none }; delete unknown.signal;
  for (const before of [null, unknown]) {
    const [first] = diffSignal(before, standing);
    assert.deepEqual([first.type, first.urgent, first.first_sight, first.id], ['upgrade_signal_changed', false, true, told.id]);
    assert.match(first.message, /^The validator of your account 5 \(a5\) supports a change of the network's rules: version 5, .* The signal was sent at .* UTC\. This watch reads the signal of this account for the first time, so it cannot say whether it is new\. If you sent it, compare the hash/);
    assert.deepEqual(diffSignal(before, later([entry(5, null, changed)])), []);
    assert.deepEqual(diffSignal(before, later([])), []);
  }
  // The entry is gone: the network dropped it. One calm event; a withdrawal that is pruned says nothing.
  const [dropped] = diffSignal(supported, later([]));
  assert.deepEqual([dropped.type, dropped.urgent, dropped.id, dropped.signal], ['upgrade_signal_dropped', false, `5:upgrade_signal_dropped:5-${SPEC}-${planOf().activate_elapsed_micros}-${changed}`, null]);
  assert.equal(dropped.message, `The signal of the validator of your account 5 (a5) is no longer on the chain. It supported version 5, start ${utcOf(planOf().activate_elapsed_micros)} at the earliest, specification hash ${groupHash(SPEC)}. No action of an account removes a signal: the network drops one whose start has come too close, whose version is no longer the next one, or whose validator was retired. Your validator supports no plan now.`);
  assert.deepEqual(diffSignal(later([entry(5, null, changed)]), later([])), []);
  // Never backwards, and never across accounts.
  assert.deepEqual(diffSignal({ ...supported, height: '999' }, later([])), []);
  assert.deepEqual(diffSignal({ ...supported, account: { ...supported.account, id: '6' } }, later([])), []);
});

test('the service: told once from the account\'s own verified read, remembered across a restart, and silent for accounts that never signalled', async () => {
  const net = chain(['5', '6']), store = memoryStore();
  let run = watching(net, { ids: ['5', '6'], store });
  await run.polled();
  // No signal: nothing new is told, and no read is added. Every account check asks for the upgrade entry (declared).
  assert.deepEqual([types(run.got).filter((type) => type.startsWith('upgrade_signal')), net.at.selections.length, net.at.selections.every((selection) => selection.include_upgrade === true && selection.include_security === true)], [[], 1, true]);
  // Account 5 signals; account 6 does not.
  const changed = BigInt(net.at.elapsed) + 5n * S; net.at.signals = [entry(5, planOf(), changed)];
  await run.polled();
  const told = run.got.filter((event) => event.type === 'upgrade_signal_changed');
  assert.deepEqual(told.map((event) => [event.account, event.urgent, event.first_sight, event.message.includes(groupHash(SPEC))]), [['5', true, false, true]]);
  assert.equal(net.at.selections.length, 2, 'the signal is read with the account, not in a read of its own');
  // The same state again, and after a restart on the same store: told once.
  await run.polled(); await run.watch.stop();
  run = watching(net, { ids: ['5', '6'], store }); await run.polled(); await run.polled();
  assert.deepEqual(types(run.got).filter((type) => type.startsWith('upgrade_signal')), []);
  assert.deepEqual((await run.watch.snapshot('5')).signal, { ...planOf(), changed_elapsed_micros: String(changed) });
  // A change while the watch was down is found at the first poll after the restart, against what the store remembers.
  await run.watch.stop(); net.at.signals = [entry(5, null, changed + 700n * S)];
  run = watching(net, { ids: ['5', '6'], store }); await run.polled();
  assert.deepEqual(run.got.filter((event) => event.type.startsWith('upgrade_signal')).map((event) => [event.account, event.urgent, event.signal.withdrawn, event.previous.spec]), [['5', true, true, SPEC]]);
  // Dropped by the network (here: a signal of support of account 6 that comes and goes).
  net.at.signals = [entry(6, planOf(OTHER), changed)]; await run.polled(); net.at.signals = []; await run.polled();
  assert.deepEqual(run.got.filter((event) => event.account === '6').map((event) => [event.type, event.urgent]), [['upgrade_signal_changed', true], ['upgrade_signal_dropped', false]]);
  await run.watch.stop();
});

test('the service: a network that does not declare the upgrade entry says nothing about signals, and a store from before is not an alarm', async () => {
  const net = chain(), store = memoryStore();
  net.at.signals = [entry(5, planOf(), T0)];
  // Not declared: the account check does not carry the entry. Nothing is said, though a signal stands, and the
  // snapshot does not pretend to know. This is the store an older build leaves, too.
  let run = watching(net, { declared: false, store });
  await run.polled(); await run.polled();
  assert.deepEqual([types(run.got).filter((type) => type.startsWith('upgrade_signal')), net.at.selections.some((selection) => selection.include_upgrade), Object.hasOwn(await run.watch.snapshot('5'), 'signal')], [[], false, false]);
  await run.watch.stop();
  // The same store under a watch that reads the entry: the standing signal is told once, calmly, as a first reading.
  run = watching(net, { store }); await run.polled(); await run.polled();
  assert.deepEqual(run.got.filter((event) => event.type.startsWith('upgrade_signal')).map((event) => [event.type, event.urgent, event.first_sight]), [['upgrade_signal_changed', false, true]]);
  // A later read without the entry does not erase what is known: the next read with it compares against it.
  const known = (await run.watch.snapshot('5')).signal; await run.watch.stop();
  run = watching(net, { declared: false, store }); await run.polled();
  assert.deepEqual((await run.watch.snapshot('5')).signal, known);
  await run.watch.stop(); net.at.signals = [entry(5, planOf(OTHER), T0 + 900n * S)];
  run = watching(net, { store }); await run.polled();
  assert.deepEqual(run.got.filter((event) => event.type.startsWith('upgrade_signal')).map((event) => [event.urgent, event.first_sight, event.previous.spec, event.signal.spec]), [[true, false, SPEC, OTHER]]);
  await run.watch.stop();
});

test('the service: a signal that cannot be compared does not hold back a security alert, and a security alert does not hold back the signal', async () => {
  // A store whose remembered signal is damaged (a field is missing): comparing it fails. The freeze of the same
  // poll is told all the same, the failure is logged, and the account counts as checked.
  const net = chain(), store = memoryStore();
  net.at.signals = [entry(5, planOf(), T0)];
  let run = watching(net, { store }); await run.polled(); await run.watch.stop();
  const saved = await store.get(); saved.snapshots['5'].signal = { version: '5', changed_elapsed_micros: '1' }; await store.put(saved);
  net.at.signals = []; net.at.security = { freezes: String(BigInt(BASE.freezes ?? '0') + 1n), frozen_until_elapsed_micros: String(BigInt(net.at.elapsed) + 2n * DAY) };
  run = watching(net, { store });
  const report = await run.polled();
  assert.deepEqual([types(run.got).includes('frozen'), report.checked, run.logs.filter((line) => line.level === 'error').map((line) => line.message)], [true, 1, ['the upgrade signal of an account could not be compared with what was seen before']]);
  // The other way round: a freeze and a signal in one poll are both told, the security alert first.
  await run.watch.stop();
  const fresh = chain(), second = watching(fresh); await second.polled();
  fresh.at.signals = [entry(5, planOf(), BigInt(fresh.at.elapsed) + S)]; fresh.at.security = { freezes: String(BigInt(BASE.freezes ?? '0') + 1n), frozen_until_elapsed_micros: String(BigInt(fresh.at.elapsed) + 2n * DAY) };
  await second.polled();
  const order = types(second.got).filter((type) => type === 'frozen' || type === 'upgrade_signal_changed');
  assert.deepEqual(order, ['frozen', 'upgrade_signal_changed']);
  await second.watch.stop();
});
