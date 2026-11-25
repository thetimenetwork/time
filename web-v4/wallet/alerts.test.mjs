// What the wallet tells its owner about an account from one verified state (alerts.mjs): the conditions that are true
// now, the changes since this browser last confirmed what it saw, the marker it keeps of that, and the clock of the
// waits on a network whose waits survive a stop of the chain.
//
// The states here have the shape the SDK's verifying client returns (as in protection.test.mjs and security.test.mjs):
// the account row, the security row of a protected account, the network's configuration and genesis time, and on a
// network with `waits_survive_stops` the total of the chain's stops. The rules these alerts stand on are the engine's
// (v5/src/security.rs, src/ledger/recovery.rs); they are not run here.
import test from 'node:test';
import assert from 'node:assert/strict';
import '../../client-v4/time-sdk.js';
import { alertsOf, readMarker, markerKey, MARKER_PREFIX } from './alerts.mjs';

const sdk = globalThis.TimeSDK;
const H = 3600000000n, DAY = 24n * H;
const GENESIS = 1790000000000000n; // 2026-09-21 13:33:20 UTC, in microseconds
const NETWORK = 'c6'.repeat(32);
const key = n => n.toString(16).padStart(2, '0').repeat(32);
const KEYS = { signin: key(0x11), spend: key(0x22), sheet: key(0x33), phrase: key(0x44), signin2: key(0x55), spend2: key(0x66), sheet2: key(0x77), phrase2: key(0x88), full: key(0x99), full2: key(0xaa) };
const device = (k, role) => ({ public_key: k, can_manage: role === 'recover' || role === 'full', can_spend: role === 'spend' || role === 'full' });
const byKey = list => [...list].sort((a, b) => (a.public_key < b.public_key ? -1 : 1));
const protectedAccount = (extra = {}, devices = [[KEYS.signin, 'signin'], [KEYS.spend, 'spend'], [KEYS.sheet, 'recover'], [KEYS.phrase, 'recover']]) =>
  ({ id: '5', name: 'alice', balance: '9000000000', nonce: '7', auth_epoch: '3', recovery_policy: null, recovery_version: '0', devices: byKey(devices.map(([k, r]) => device(k, r))), ...extra });
const NOW = 100n * DAY; // the chain's time since genesis in these states
const policy = (extra = {}) => ({ threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800', ...extra });
const row = (extra = {}) => ({ account: '5', version: '4', policy: policy(), allowance_micros: '600000000', allowance_elapsed_micros: String(NOW - H), frozen_until_elapsed_micros: '0', freezes: '2', pending_limit: null, pending_payments: [], next_id: '9', pending_root: null, ...extra });
/// A verified state of one account. `stopped`: the total of the chain's stops on a network whose waits survive a stop.
function state({ account = protectedAccount(), security = row(), elapsed = NOW, stopped, cases = [] } = {}) {
  return {
    network_id: NETWORK, height: '1000', time_micros: String(GENESIS + elapsed), genesis: { genesis_time_micros: String(GENESIS) },
    config: stopped === undefined ? {} : { waits_survive_stops: true }, ...(stopped === undefined ? {} : { stopped_micros: String(stopped) }),
    accounts: [account], security: security ? [security] : [], recovery_cases: cases,
  };
}
const read = (s, seen = null) => alertsOf({ sdk, state: s, account: '5', seen });
const ids = result => result.alerts.map(a => a.id);
const date = micros => new Date(Number((GENESIS + micros) / 1000n)).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

test('a calm protected account: nothing to say, and the marker records the counters and the keys by role', () => {
  const { alerts, marker } = read(state());
  assert.deepEqual(alerts, []);
  assert.deepEqual(marker, {
    v: 2, account: '5', secured: true, auth_epoch: '3', nonce: '7', recovery_version: '0', clock: String(NOW),
    keys: { signin: [KEYS.signin], spend: [KEYS.spend], recover: [KEYS.phrase, KEYS.sheet].sort(), full: [] },
    version: '4', freezes: '2', next_id: '9', frozen_until: '0', root: null, policy: { daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800', threshold: '2' },
  });
  // The page stores it as text; read back, it is the same marker.
  assert.deepEqual(readMarker(JSON.stringify(marker), '5'), marker);
  // A received payment is not an alert: only the balance moved.
  assert.deepEqual(read(state({ account: protectedAccount({ balance: '9900000000' }) }), marker).alerts, []);
});

test('what is true now, most urgent first: keys being replaced, frozen, payments waiting, a raise waiting', () => {
  const root = { devices: [device(KEYS.spend2, 'spend'), device(KEYS.sheet, 'recover'), device(KEYS.phrase, 'recover')], policy: policy(), ready_elapsed_micros: String(NOW + DAY), expires_elapsed_micros: String(NOW + 8n * DAY) };
  const busy = row({
    pending_root: root, frozen_until_elapsed_micros: String(NOW + 2n * H), freezes: '3',
    pending_payments: [{ id: '7', to: '12', amount: '900000000', ready_elapsed_micros: String(NOW + 47n * H) }, { id: '8', to: '13', amount: '1500000', ready_elapsed_micros: String(NOW - H) }],
  });
  const { alerts } = read(state({ security: busy }));
  assert.deepEqual(alerts.map(a => [a.id, a.urgent, a.title]), [
    ['5:keys-waiting:' + (NOW + DAY), true, 'Your keys are being replaced'],
    ['5:frozen:3', true, 'Your account is frozen'],
    ['5:payment-waiting:7', true, 'A payment is waiting'],
    ['5:payment-waiting:8', true, 'A payment is waiting'],
  ]);
  assert.equal(alerts[0].text, `Your recovery words were used to ask for new keys for this account. Until this is finished or stopped, the account is frozen: nothing can be paid with your payment password alone, and nobody can sign in. The new keys can take over at ${date(NOW + DAY)}. If you did not ask for this, make new recovery words now, under Keys, “Change something”: it needs your payment password and your recovery words, it ends this change at once, and the words that were used stop working. Cancelling it on Home, under “Waiting on your account” needs the same, but whoever asked keeps your words and can ask again. Without your recovery words you cannot stop this.`);
  assert.deepEqual([alerts[0].until.getTime(), alerts[0].notBefore], [Number((GENESIS + NOW + DAY) / 1000n), false]);
  assert.equal(alerts[1].text, `Nothing can be paid with your payment password alone, and nobody can sign in with this account. The freeze ends by itself at ${date(NOW + 2n * H)}. The replacement of your keys keeps the account frozen after that. If you did not freeze it, someone has your payment password or your recovery words: make new ones under Keys, “Change something”.`);
  assert.equal(alerts[2].text, `A payment of 900 seconds to account 12 is waiting. It can go through at ${date(NOW + 47n * H)} unless it is cancelled. If you did not start it, cancel it now on Home, under “Waiting on your account”, then freeze your account now with the Freeze switch on Home.`);
  assert.equal(alerts[3].text, 'A payment of 1.5 seconds to account 13 is waiting. It can go through now unless it is cancelled. If you did not start it, cancel it now on Home, under “Waiting on your account”, then freeze your account now with the Freeze switch on Home.');
  // A raise of the daily limit that waits.
  const raising = read(state({ security: row({ pending_limit: { id: '9', daily_limit_micros: '3600000000', ready_elapsed_micros: String(NOW + 48n * H) }, next_id: '10' }) })).alerts;
  assert.deepEqual(raising.map(a => [a.id, a.urgent]), [['5:limit-waiting:9', true]]);
  assert.equal(raising[0].text, `Your daily limit is to rise from 600 seconds to 3600 seconds. It takes effect at ${date(NOW + 48n * H)} unless it is cancelled. If you did not ask for it, cancel it now on Home, under “Waiting on your account”, then freeze your account now with the Freeze switch on Home.`);
  // The new keys may take over already: the words say until when.
  const ready = read(state({ security: row({ pending_root: { ...root, ready_elapsed_micros: String(NOW - H) } }) })).alerts[0];
  assert.match(ready.text, new RegExp(`The new keys can take over now, until ${date(NOW + 8n * DAY)}\\.`));
});

test('what is over is not said: a freeze that ended, a replacement past its window, a raise in force', () => {
  const over = row({
    frozen_until_elapsed_micros: String(NOW), pending_root: { devices: [], policy: policy(), ready_elapsed_micros: String(NOW - 9n * DAY), expires_elapsed_micros: String(NOW - 1n) },
    pending_limit: { id: '8', daily_limit_micros: '3600000000', ready_elapsed_micros: String(NOW) },
  });
  const { alerts, marker } = read(state({ security: over }));
  assert.deepEqual(alerts, []);
  // The marker is of the row as the engine sees it now: the raise is in force, the replacement is gone.
  assert.deepEqual([marker.policy.daily_limit_micros, marker.root], ['3600000000', null]);
});

test('ids come from the rows, never from when they are read: the same condition is one alert however often it is read', () => {
  const security = row({ frozen_until_elapsed_micros: String(NOW + 10n * H), pending_payments: [{ id: '8', to: '12', amount: '5', ready_elapsed_micros: String(NOW + 20n * H) }] });
  const first = read(state({ security })), later = read(state({ security, elapsed: NOW + 3n * H }), first.marker), again = read(state({ security, elapsed: NOW + 4n * H }));
  assert.deepEqual(ids(first), ['5:frozen:2', '5:payment-waiting:8']);
  assert.deepEqual(ids(later), ids(first));
  assert.deepEqual(ids(again), ids(first));
});

test('on a network whose waits survive a stop: the clock of the waits decides, and a date that has not come is "not before"', () => {
  const STOP = 6n * H, clock = NOW - STOP;
  // Frozen until one hour after the clock of the waits: on the chain's time that moment passed five hours ago.
  const security = row({ frozen_until_elapsed_micros: String(clock + H), freezes: '3', allowance_elapsed_micros: String(clock - H),
    pending_payments: [{ id: '7', to: '12', amount: '5000000', ready_elapsed_micros: String(clock - H) }, { id: '8', to: '12', amount: '5000000', ready_elapsed_micros: String(clock + 2n * H) }] });
  const { alerts, marker } = read(state({ security, stopped: STOP }));
  assert.deepEqual(ids({ alerts }), ['5:frozen:3', '5:payment-waiting:7', '5:payment-waiting:8']);
  assert.equal(marker.clock, String(clock));
  // A moment shown as a date is the stored moment plus the stops so far, the earliest it can come.
  assert.deepEqual([alerts[0].until.getTime(), alerts[0].notBefore], [Number((GENESIS + clock + H + STOP) / 1000n), true]);
  assert.match(alerts[0].text, new RegExp(`The freeze ends by itself not before ${date(clock + H + STOP)}\\.`));
  assert.match(alerts[1].text, /It can go through now unless it is cancelled\./);
  assert.match(alerts[2].text, new RegExp(`It can go through not before ${date(clock + 2n * H + STOP)} unless`));
  // The same row on a network without the setting: the chain's time decides, and the freeze is over.
  assert.deepEqual(ids(read(state({ security }))), ['5:payment-waiting:7', '5:payment-waiting:8']);
  // A page may give its own way of writing a date.
  const local = alertsOf({ sdk, state: state({ security, stopped: STOP }), account: '5', formatDate: d => `<${d.getTime()}>` }).alerts[0];
  assert.match(local.text, /not before <\d+>\./);
});

test('changes since this browser last looked: login keys added and removed, one alert each, explained by the epoch', () => {
  const seen = read(state()).marker;
  const two = protectedAccount({ auth_epoch: '4', nonce: '8' }, [[KEYS.signin, 'signin'], [KEYS.signin2, 'signin'], [KEYS.spend, 'spend'], [KEYS.sheet, 'recover'], [KEYS.phrase, 'recover']]);
  const added = read(state({ account: two }), seen);
  assert.deepEqual(ids(added), [`5:signin-added:${KEYS.signin2}:4`]);
  assert.equal(added.alerts[0].text, 'A login key (55555555…) was added to this account. It can sign in to websites as you. If you did not add it, someone has your payment password: freeze your account now with the Freeze switch on Home.');
  // One action may add one key and remove another: the epoch moved once, and both are said.
  const swapped = protectedAccount({ auth_epoch: '4', nonce: '8' }, [[KEYS.signin2, 'signin'], [KEYS.spend, 'spend'], [KEYS.sheet, 'recover'], [KEYS.phrase, 'recover']]);
  assert.deepEqual(ids(read(state({ account: swapped }), seen)), [`5:signin-added:${KEYS.signin2}:4`, `5:signin-removed:${KEYS.signin}:4`]);
  // Once the owner confirms, the new marker is `seen`, and nothing is left to say.
  assert.deepEqual(read(state({ account: two }), added.marker).alerts, []);
  // The epoch moved twice, but one change is visible: a key added and removed again went by unseen.
  const twice = read(state({ account: { ...two, auth_epoch: '6' } }), seen);
  assert.deepEqual(ids(twice), [`5:signin-added:${KEYS.signin2}:6`, '5:unexplained:e3-6']);
  assert.equal(twice.alerts[1].title, 'Something changed that this wallet cannot show');
});

test('changes since this browser last looked: keys replaced, recovery words replaced, rules changed, each counted once', () => {
  const seen = read(state()).marker;
  // Payment and login keys replaced at once with a recovery paper: one operation, the version and the epoch move by one.
  const replaced = protectedAccount({ auth_epoch: '4', nonce: '8' }, [[KEYS.signin2, 'signin'], [KEYS.spend2, 'spend'], [KEYS.sheet, 'recover'], [KEYS.phrase, 'recover']]);
  const r = read(state({ account: replaced, security: row({ version: '5' }) }), seen);
  assert.deepEqual(r.alerts.map(a => [a.id, a.urgent]), [[`5:keys-replaced:v5:e4`, true]]);
  assert.equal(r.alerts[0].text, 'The payment key of this account was replaced. Everything that was waiting was dropped. If you did not do this, the account is no longer under your control: get help now.');
  const all = protectedAccount({ auth_epoch: '4', nonce: '8' }, [[KEYS.signin, 'signin'], [KEYS.spend2, 'spend'], [KEYS.sheet2, 'recover'], [KEYS.phrase2, 'recover']]);
  assert.match(read(state({ account: all, security: row({ version: '5' }) }), seen).alerts[0].text, /^The payment key of this account was replaced, and its recovery words too\./);
  // New recovery papers only.
  const papers = protectedAccount({ auth_epoch: '4', nonce: '8' }, [[KEYS.signin, 'signin'], [KEYS.spend, 'spend'], [KEYS.sheet2, 'recover'], [KEYS.phrase2, 'recover']]);
  assert.deepEqual(ids(read(state({ account: papers, security: row({ version: '5' }) }), seen)), ['5:recovery-replaced:v5:e4']);
  // The rules changed at once, keys kept.
  const rules = read(state({ account: protectedAccount({ auth_epoch: '4', nonce: '8' }), security: row({ version: '5', policy: policy({ delay_seconds: '7200' }) }) }), seen);
  assert.deepEqual(ids(rules), ['5:rules-changed:v5']);
  assert.equal(rules.alerts[0].text, 'The rules of this account changed at once: now payments above the daily limit wait 2 hours, a freeze lasts 48 hours, and big changes need 2 approvals. That takes your payment password and your recovery words together. If you did not change them, someone holds those keys: get help now.');
});

test('changes since this browser last looked: the daily limit, lowered, raised after its wait, or raised at once', () => {
  const seen = read(state()).marker;
  const lowered = read(state({ account: protectedAccount({ nonce: '8' }), security: row({ policy: policy({ daily_limit_micros: '1000' }), allowance_micros: '1000' }) }), seen);
  assert.deepEqual(lowered.alerts.map(a => [a.id, a.urgent, a.title]), [['5:limit-changed:600000000-1000:v4', false, 'Your daily limit was lowered']]);
  // A raise that waited is in force without any action: the stored row still holds it as waiting.
  const waited = row({ next_id: '10', pending_limit: { id: '9', daily_limit_micros: '3600000000', ready_elapsed_micros: String(NOW - H) } });
  const done = read(state({ account: protectedAccount({ nonce: '8' }), security: waited }), seen);
  assert.deepEqual(done.alerts.map(a => [a.id, a.urgent]), [['5:limit-changed:600000000-3600000000:v4', false]]);
  assert.equal(done.alerts[0].text, 'Your daily limit is now 3600 seconds (it was 600 seconds): the raise that waited took effect. Your payment key can now pay that much a day without waiting.');
  // The same raise, once a later action of the account wrote it into the row: still the raise that waited.
  const written = read(state({ account: protectedAccount({ nonce: '9' }), security: row({ next_id: '10', policy: policy({ daily_limit_micros: '3600000000' }) }) }), seen);
  assert.deepEqual(written.alerts.map(a => [a.id, a.urgent, a.title]), [['5:limit-changed:600000000-3600000000:v4', false, 'Your daily limit was raised']]);
  // Raised at once by several keys: the version and the epoch moved by one.
  const atOnce = read(state({ account: protectedAccount({ auth_epoch: '4', nonce: '8' }), security: row({ version: '5', policy: policy({ daily_limit_micros: '3600000000' }) }) }), seen);
  assert.deepEqual(atOnce.alerts.map(a => [a.id, a.urgent]), [['5:limit-changed:600000000-3600000000:v5', true]]);
  assert.match(atOnce.alerts[0].text, /^Your daily limit rose at once from 600 seconds to 3600 seconds, without the wait\. That takes your payment password and your recovery words together\./);
});

test('what the counters show beyond the visible changes is said as "cannot show", urgent', () => {
  const seen = read(state()).marker;
  // A payment approved by several keys moves the version and shows nowhere else.
  assert.deepEqual(ids(read(state({ account: protectedAccount({ balance: '1000' }), security: row({ version: '5' }) }), seen)), ['5:unexplained:v4-5']);
  // A waiting payment that came and went between two looks.
  assert.deepEqual(ids(read(state({ account: protectedAccount({ nonce: '9' }), security: row({ next_id: '10' }) }), seen)), ['5:unexplained:n9-10']);
  // A freeze that came and went is said as such.
  const frozenMeanwhile = read(state({ security: row({ freezes: '3', frozen_until_elapsed_micros: String(NOW - H) }) }), seen);
  assert.deepEqual(frozenMeanwhile.alerts.map(a => [a.id, a.title]), [['5:freeze-over:2-3', 'Your account was frozen meanwhile']]);
  // A freeze that holds now is said once, as what is true now.
  assert.deepEqual(ids(read(state({ security: row({ freezes: '3', frozen_until_elapsed_micros: String(NOW + H) }) }), seen)), ['5:frozen:3']);
  // What explains the version: a replacement asked for, a waiting one cancelled, a freeze lifted early.
  const root = { devices: [], policy: policy(), ready_elapsed_micros: String(NOW + DAY), expires_elapsed_micros: String(NOW + 8n * DAY) };
  const asked = read(state({ security: row({ version: '5', pending_root: root }) }), seen);
  assert.deepEqual(ids(asked), [`5:keys-waiting:${NOW + DAY}`]);
  assert.deepEqual(read(state({ security: row({ version: '6' }) }), asked.marker).alerts, [], 'the waiting replacement was cancelled');
  const frozenSeen = read(state({ security: row({ freezes: '3', frozen_until_elapsed_micros: String(NOW + H) }) })).marker;
  assert.deepEqual(read(state({ security: row({ version: '5', freezes: '3', frozen_until_elapsed_micros: '0' }) }), frozenSeen).alerts, [], 'the freeze was lifted early');
});

test('a protocol-4 account: keys added and removed, a guardian policy, and guardians recovering it', () => {
  const p4 = (extra = {}, keys = [[KEYS.full, 'full']]) => protectedAccount({ recovery_version: '1', ...extra }, keys);
  const calm = read(state({ account: p4(), security: null }));
  assert.deepEqual([calm.alerts, calm.marker.secured, calm.marker.version, calm.marker.policy, calm.marker.keys.full], [[], false, null, null, [KEYS.full]]);
  const added = read(state({ account: p4({ auth_epoch: '4' }, [[KEYS.full, 'full'], [KEYS.full2, 'full']]), security: null }), calm.marker);
  assert.deepEqual(ids(added), [`5:key-added:${KEYS.full2}:4`]);
  assert.equal(added.alerts[0].text, 'A key that can pay and manage (aaaaaaaa…) was added to this account. If you did not add it, someone has a key of this account: remove every key you do not know now, under More, Devices.');
  // A guardian policy moves the recovery version and the epoch together: nothing unexplained.
  assert.deepEqual(read(state({ account: p4({ auth_epoch: '4', recovery_version: '2' }), security: null }), calm.marker).alerts, []);
  // Guardians recovering the account: waiting for approvals, then with a date (the chain's time: these waits are protocol 4's).
  const asking = { target: '5', recovery_id: 'ab'.repeat(32), new_public_key: KEYS.full2, expires_elapsed_micros: String(NOW + 9n * DAY), ready_elapsed_micros: null, approvals: ['3'] };
  const one = read(state({ account: p4(), security: null, cases: [asking] }));
  assert.deepEqual(one.alerts.map(a => [a.id, a.urgent, a.until]), [[`5:guardians:${'ab'.repeat(32)}`, true, undefined]]);
  assert.equal(one.alerts[0].text, 'A guardian asked to give this account to a new key. More guardians must approve before it can go on. If you did not ask for this, cancel it now under More, Guardian recovery.');
  const approved = read(state({ account: p4(), security: null, cases: [{ ...asking, ready_elapsed_micros: String(NOW + DAY), approvals: ['3', '4'] }] })).alerts[0];
  assert.match(approved.text, new RegExp(`The new key can take over at ${date(NOW + DAY)}\\.`));
  // A case of another account, or one past its window, says nothing.
  assert.deepEqual(read(state({ account: p4(), security: null, cases: [{ ...asking, target: '6' }, { ...asking, recovery_id: 'cd'.repeat(32), expires_elapsed_micros: String(NOW - 1n) }] })).alerts, []);
  // Protected with new keys since: one alert, for the whole change.
  const secured = read(state({ account: protectedAccount({ auth_epoch: '4', nonce: '8' }), security: row({ version: '1', freezes: '0', next_id: '1' }) }), calm.marker);
  assert.deepEqual(ids(secured), ['5:secured:4']);
});

test('a marker is read strictly: anything that is not one this module wrote, for this account, counts as nothing seen', () => {
  const good = read(state()).marker, text = JSON.stringify(good);
  assert.deepEqual(readMarker(text, '5'), good);
  assert.deepEqual(readMarker(good, '5'), good);
  const variants = [
    'not json', 'null', '[]', '{}', text.slice(0, -1), 'x'.repeat(9000),
    { ...good, v: 3 }, { ...good, v: '2' }, { ...good, account: '6' }, { ...good, extra: 1 }, (({ nonce, ...rest }) => rest)(good), { ...good, nonce: '07' }, { ...good, nonce: 7 },
    { ...good, secured: 'yes' }, { ...good, version: null }, { ...good, policy: { ...good.policy, threshold: 'two' } }, { ...good, policy: { ...good.policy, extra: '1' } },
    { ...good, keys: { ...good.keys, recover: [...good.keys.recover].reverse() } }, { ...good, keys: { ...good.keys, spend: [KEYS.full2.toUpperCase()] } }, { ...good, keys: { ...good.keys, other: [] } },
    { ...good, root: { ready: '1' } }, { ...good, secured: false }, { ...good, recovery_version: 'x' },
  ];
  for (const bad of variants) assert.equal(readMarker(typeof bad === 'string' ? bad : JSON.stringify(bad), '5'), null, typeof bad === 'string' ? bad.slice(0, 20) : JSON.stringify(bad).slice(0, 80));
  assert.equal(readMarker(text, '6'), null, 'the marker of another account');
  // A malformed `seen` is a first look: what is true now, no change.
  const later = state({ account: protectedAccount({ auth_epoch: '9' }), security: row({ version: '9' }) });
  for (const seen of ['garbage', { ...good, v: 3 }, null]) assert.deepEqual(read(later, seen).alerts, [], String(seen).slice(0, 20));
  // A marker of version 1, stored before the page kept the nonce of what it sends, is read as before.
  assert.deepEqual(readMarker(JSON.stringify({ ...good, v: 1 }), '5'), { ...good, v: 1 });
  // So is a marker whose counters are ahead of the state: not of this account as it is now (another chain under the same name).
  assert.deepEqual(read(state(), { ...good, auth_epoch: '9' }).alerts, []);
  assert.deepEqual(read(state(), { ...good, version: '9' }).alerts, []);
  // Where the page keeps it: one marker per account per network.
  assert.equal(markerKey(NETWORK, '5'), `${MARKER_PREFIX}${NETWORK}:5`);
  assert.equal(MARKER_PREFIX, 'timecurrency.alerts-seen.v1:');
  for (const [network, account] of [['c6', '5'], [NETWORK, '05'], [NETWORK, 'alice'], [NETWORK.toUpperCase(), '5']]) assert.throws(() => markerKey(network, account), /one account of one network/);
});

test('nothing is said that the state did not prove', () => {
  // The account is not in the state, or its security row was not read: no alerts, an error.
  assert.throws(() => read({ ...state(), accounts: [] }), /not in the verified state/);
  assert.throws(() => read({ ...state(), security: undefined }), /security state of this account was not proven/);
  // An account with a key that holds both powers can have no security row: it is read without one.
  assert.deepEqual(read({ ...state({ account: protectedAccount({}, [[KEYS.full, 'full']]) }), security: undefined }).alerts, []);
});

test('every sentence is plain: fixed words, no dash, no link, no quotation of anything outside the proven numbers', () => {
  const root = { devices: [], policy: policy(), ready_elapsed_micros: String(NOW + DAY), expires_elapsed_micros: String(NOW + 8n * DAY) };
  const seen = read(state()).marker;
  const texts = [
    ...read(state({ security: row({ pending_root: root, frozen_until_elapsed_micros: String(NOW + H), pending_payments: [{ id: '8', to: '12', amount: '5', ready_elapsed_micros: String(NOW + H) }], pending_limit: { id: '9', daily_limit_micros: '900000000', ready_elapsed_micros: String(NOW + H) }, next_id: '10' }) })).alerts,
    ...read(state({ account: protectedAccount({ auth_epoch: '9', nonce: '8' }, [[KEYS.signin2, 'signin'], [KEYS.spend2, 'spend'], [KEYS.sheet, 'recover'], [KEYS.phrase, 'recover']]), security: row({ version: '7', freezes: '4', next_id: '12', policy: policy({ daily_limit_micros: '1000', freeze_seconds: '60' }) }) }), seen).alerts,
  ];
  assert.ok(texts.length >= 7);
  for (const a of texts) {
    assert.deepEqual(Object.keys(a).filter(k => !['until', 'notBefore'].includes(k)), ['id', 'urgent', 'title', 'text']);
    assert.ok(!/[\u2013\u2014]|https?:|www\.|<|>/.test(a.title + a.text), a.text);
    assert.match(a.text, /\.$/);
    assert.ok(a.title.length <= 60 && !/\.$/.test(a.title), a.title);
  }
});

// Web audit of November 2026, K-4: payments signed with a stolen payment key raised no alert (payments wake nobody, and
// the nonce in the marker was not used). The page passes how many actions this browser sent since the marker.
test('K-4: actions signed with the account\'s keys that this browser did not send are an alert; urgent when it sent none of three or more', () => {
  const seen = read(state()).marker; // nonce 7, version 2
  const later = nonce => state({ account: protectedAccount({ nonce }) });
  const actions = (s, sent, marker = seen) => alertsOf({ sdk, state: s, account: '5', seen: marker, sent }).alerts.filter(a => a.id.includes(':actions:'));
  // Five actions on the chain, two of them from this browser: an alert, not urgent.
  const five = actions(later('12'), 2);
  assert.deepEqual(five.map(a => [a.id, a.urgent, a.title]), [['5:actions:n7-12', false, 'Actions were signed with your keys']]);
  assert.equal(five[0].text, '5 actions were signed with your keys since you last looked here. This browser sent 2 of them. If the others were not you on another device, make a new payment password under Keys, “Change something”.');
  // Three or more and none from this browser: urgent. One: not urgent, in the singular.
  const head = a => a.text.split(' If the others')[0];
  assert.deepEqual(actions(later('10'), 0).map(a => [a.urgent, head(a)]), [[true, '3 actions were signed with your keys since you last looked here. This browser sent none of them.']]);
  assert.deepEqual(actions(later('8'), 0).map(a => [a.urgent, head(a)]), [[false, '1 action was signed with your keys since you last looked here. This browser sent none of them.']]);
  // All of them from this browser, or more by its count: nothing. Nothing moved: nothing.
  for (const [nonce, sent] of [['12', 5], ['12', 9], ['7', 0]]) assert.deepEqual(actions(later(nonce), sent), [], `${nonce} ${sent}`);
  // Without a count (null), or from a marker of version 1 (stored before the page kept the nonce of what it sends): nothing.
  assert.deepEqual(actions(later('12'), null), []);
  assert.deepEqual(actions(later('12'), 0, { ...seen, v: 1 }), []);
  // A change of keys put in force at once moves the nonce by one more (security.rs, install): not counted as an action.
  const replaced = protectedAccount({ auth_epoch: '4', nonce: '9' }, [[KEYS.signin, 'signin'], [KEYS.spend, 'spend'], [KEYS.sheet2, 'recover'], [KEYS.phrase2, 'recover']]);
  assert.deepEqual(actions(state({ account: replaced, security: row({ version: '5' }) }), 1), [], 'one action of this browser and the install');
  assert.deepEqual(actions(state({ account: replaced, security: row({ version: '5' }) }), 0).map(a => a.text.slice(0, 40)), ['1 action was signed with your keys since']);
  // An account with one key: the way out is its devices.
  const plain = { ...protectedAccount({ nonce: '7' }, [[KEYS.full, 'full']]) };
  const before = alertsOf({ sdk, state: state({ account: plain, security: null }), account: '5' }).marker;
  const after = alertsOf({ sdk, state: state({ account: { ...plain, nonce: '11' }, security: null }), account: '5', seen: before, sent: 1 }).alerts.find(a => a.id.includes(':actions:'));
  assert.match(after.text, /^4 actions were signed .* This browser sent 1 of them\. If the others were not you on another device, someone has a key of this account: remove every key you do not know now, under More, Devices\.$/);
});
