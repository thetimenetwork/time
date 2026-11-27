// What the Protection card says for each state of a protected account (protection.mjs), and what "Pause payments"
// and a limit set at once sign (security-flows.mjs, buildPause and buildLimitNow). Functions only: the card on the
// page, with the real app.js, is in protection-card.test.mjs.
//
// The rules these words stand on are the engine's (v5/src/security.rs). They are not run here. What is checked against
// the engine itself is the form of what is signed: the approvals of the root operation verify against the message the
// wallet library builds, which client-v4/account-security.test.mjs compares byte for byte with actions the engine took.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import '../../client-v4/time-sdk.js';
import * as security from '../../client-v4/account-security.mjs';
import { formatSeconds, parseSeconds } from './guards.mjs';
import * as F from './security-flows.mjs';
import * as P from './protection.mjs';

const SDK = globalThis.TimeSDK;
const HOUR = 3600000000n, DAY = 24n * HOUR, FEE = '1000', now = 100n * DAY;
// Amounts and times as plain marks, so that a test reads which number went where.
const words = { seconds: micros => `${formatSeconds(String(micros))} seconds`, plain: micros => formatSeconds(String(micros)), duration: seconds => `${BigInt(seconds) / 3600n} hours`, when: at => `<${at}>`, roughly: micros => `~${BigInt(micros) / HOUR}h` };
const row = (extra = {}, policy = {}) => ({ account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800', ...policy }, allowance_micros: '600000000', allowance_elapsed_micros: String(now), frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null, ...extra });
const view = (r, waiting, at = now) => P.protectionView({ row: r, now: at, feeMicros: FEE, allowance: security.allowance(r, at), frozen: security.frozen(r, at), waiting, words });

test('a protected account: protected, both switches off, and what can be paid now out of the limit, with the chain\'s own numbers', () => {
  const v = view(row());
  assert.deepEqual(v.status, { alert: false, text: 'Your account is protected.' });
  assert.deepEqual([v.freeze.on, v.freeze.state, v.freeze.locked, v.freeze.canEnd, v.freeze.canRenew, v.freeze.lasts], [false, 'Off', false, false, false, '48 hours']);
  assert.equal(v.freeze.note, 'For 48 hours: no payment with your payment password alone, and no sign-in to websites. It ends by itself. What is waiting is dropped.');
  assert.deepEqual([v.pause.on, v.pause.state, v.pause.kind, v.pause.locked, v.pause.ending], [false, 'Off', 'off', false, null]);
  assert.equal(v.pause.note, 'While paused, nothing can be paid at once. A payment started then waits 48 hours and you can cancel it.');
  assert.deepEqual(v.limit, { perMille: 1000, text: 'You can pay 600 of 600 seconds now without waiting, fees included.', canChange: true, value: 600000000n });
  assert.equal(v.waiting, 'Nothing is waiting.');
  // A quarter is left: the bar and the sentence say so, and that it refills.
  const spent = view(row({ allowance_micros: '150000000' }));
  assert.deepEqual([spent.limit.perMille, spent.limit.text], [250, 'You can pay 150 of 600 seconds now without waiting, fees included. It refills over 24 hours.']);
  // Six hours later a quarter of the limit is back: the card follows the chain's arithmetic, not a number it kept.
  assert.equal(view(row({ allowance_micros: '150000000' }), undefined, now + 6n * HOUR).limit.text, 'You can pay 300 of 600 seconds now without waiting, fees included. It refills over 24 hours.');
  // One fee or less is left: no payment fits, whatever the number.
  for (const left of ['1000', '999', '0']) assert.deepEqual([view(row({ allowance_micros: left })).limit.perMille, view(row({ allowance_micros: left })).limit.text], [0, 'Nothing can be paid right now: less than one fee is left of your 600 seconds a day. It refills over 24 hours.'], left);
  assert.equal(view(row({ allowance_micros: '1001' })).limit.text, 'You can pay 0.001001 of 600 seconds now without waiting, fees included. It refills over 24 hours.');
  // The account's own periods are the ones said.
  const other = view(row({}, { delay_seconds: '7200', freeze_seconds: '10800' }));
  assert.match(other.pause.note, /A payment started then waits 2 hours and you can cancel it\.$/);
  assert.match(other.freeze.note, /^For 3 hours: /);
});

test('what waits is counted in words, and a waiting raise of the limit is said where the limit is', () => {
  assert.equal(P.waitingWords(), 'Nothing is waiting.');
  assert.equal(P.waitingWords({ payments: 1, changes: 0 }), '1 payment is waiting. See “Waiting on your account” below: each can be cancelled.');
  assert.equal(P.waitingWords({ payments: 0, changes: 1 }), '1 change is waiting. See “Waiting on your account” below: each can be cancelled.');
  assert.equal(P.waitingWords({ payments: 2, changes: 1 }), '2 payments and 1 change are waiting. See “Waiting on your account” below: each can be cancelled.');
  assert.equal(view(row(), { payments: 3, changes: 2 }).waiting, '3 payments and 2 changes are waiting. See “Waiting on your account” below: each can be cancelled.');
  const raising = view(row({ pending_limit: { id: '4', daily_limit_micros: '900000000', ready_elapsed_micros: String(now + DAY) } }));
  assert.equal(raising.limit.text, `You can pay 600 of 600 seconds now without waiting, fees included. A raise to 900 seconds is waiting: it applies at <${now + DAY}>.`);
  assert.deepEqual([raising.pause.on, raising.pause.ending, raising.limit.value], [false, null, 600000000n]);
});

test('a frozen account: until when, that the freeze ends by itself, and how it is kept on: renewed only in its second half', () => {
  // Forty hours of forty-eight are left: too early to renew.
  const until = now + 40n * HOUR, early = view(row({ frozen_until_elapsed_micros: String(until), freezes: '1' }));
  assert.deepEqual(early.status, { alert: true, text: `Your account is frozen until <${until}> (~40h).` });
  assert.deepEqual([early.freeze.on, early.freeze.state, early.freeze.byFreeze, early.freeze.locked, early.freeze.canEnd, early.freeze.canRenew], [true, 'On', true, false, true, false]);
  assert.equal(early.freeze.note, `It ends by itself at that time and is not renewed by itself. To keep the account frozen longer, freeze again after <${until - DAY}>: a freeze can be renewed in its second half only.`);
  // The limit cannot be changed and payments cannot be paused or resumed while frozen, and the card says that nothing is paid.
  assert.deepEqual([early.limit.canChange, early.pause.locked, early.pause.waitPossible], [false, true, false]);
  assert.deepEqual([early.limit.perMille, early.limit.text], [0, 'Nothing can be paid with your payment password alone while the account is frozen. Your daily limit is 600 seconds.']);
  assert.equal(early.pause.note, 'The account is frozen: nothing can be paid at once, paused or not.');
  // Exactly half is left: it can be renewed, as the engine allows from then on.
  for (const left of [24n * HOUR, HOUR, 1n]) {
    const late = view(row({ frozen_until_elapsed_micros: String(now + left), freezes: '1' }));
    assert.deepEqual([late.freeze.canRenew, late.freeze.note], [true, 'It ends by itself at that time and is not renewed by itself. To keep the account frozen, freeze again now: the freeze then lasts 48 hours from that moment.'], String(left));
  }
  assert.equal(view(row({ frozen_until_elapsed_micros: String(now + 24n * HOUR + 1n) })).freeze.canRenew, false);
  // A freeze that has run out is no freeze: nothing in the browser keeps it on.
  const over = view(row({ frozen_until_elapsed_micros: String(now), freezes: '1' }));
  assert.deepEqual([over.status.text, over.freeze.on, over.limit.canChange], ['Your account is protected.', false, true]);
  // Frozen while a change of all keys waits: that is no freeze to end, and the switch cannot be used.
  const replacing = view(row({ pending_root: { devices: [], policy: row().policy, ready_elapsed_micros: String(now + DAY), expires_elapsed_micros: String(now + 2n * DAY) } }));
  assert.deepEqual(replacing.status, { alert: true, text: 'Your account is frozen while a change of all your keys waits.' });
  assert.deepEqual([replacing.freeze.on, replacing.freeze.byFreeze, replacing.freeze.locked, replacing.freeze.canEnd, replacing.freeze.canRenew], [true, false, true, false, false]);
  assert.equal(replacing.freeze.note, 'The account stays frozen until that change is finished or cancelled. See “Waiting on your account” below.');
  // Both at once: the freeze is said with its time, and that the change keeps the account frozen beyond it.
  const both = view(row({ frozen_until_elapsed_micros: String(until), pending_root: { devices: [], policy: row().policy, ready_elapsed_micros: String(now + DAY), expires_elapsed_micros: String(now + 2n * DAY) } }));
  assert.match(both.freeze.note, / A change of all your keys is waiting too: the account stays frozen until that is finished or cancelled\.$/);
  assert.deepEqual([both.freeze.locked, both.freeze.canEnd], [false, true]);
});

test('a paused account: the limit is one fee, nothing is paid at once, and what still can happen is said with the account\'s waiting period', () => {
  const paused = (extra = {}) => row({ allowance_micros: '1000', ...extra }, { daily_limit_micros: '1000' });
  const v = view(paused());
  assert.deepEqual(v.status, { alert: false, text: 'Payments are paused.' });
  assert.deepEqual([v.pause.on, v.pause.state, v.pause.kind, v.pause.locked, v.pause.waitPossible], [true, 'On', 'paused', false, true]);
  assert.equal(v.pause.note, 'Nothing can be paid at once. A payment started now waits 48 hours and you can cancel it.');
  assert.equal(v.pause.waitNote, 'Your limit comes back after 48 hours. You can cancel that meanwhile.');
  assert.deepEqual(v.limit, { perMille: 0, text: 'Paused: nothing can be paid at once.', canChange: false, value: 1000n });
  // The fee of a step taken while paused uses what the paused limit covers in a day: the card says when the next one fits.
  const used = view(paused({ allowance_micros: '0' }));
  assert.deepEqual([used.pause.waitPossible, used.pause.waitNote], [false, 'Not possible right now: asking costs a fee, and your paused limit covers one fee a day. It covers the next one in ~24h.']);
  assert.equal(used.pause.note, 'Nothing can be paid at once. A payment started now waits 48 hours and you can cancel it. Starting one costs a fee, and your paused limit covers one fee a day: the next one in ~24h.');
  assert.equal(view(paused({ allowance_micros: '0' }), undefined, now + 18n * HOUR).pause.waitNote, 'Not possible right now: asking costs a fee, and your paused limit covers one fee a day. It covers the next one in ~6h.');
  assert.equal(view(paused({ allowance_micros: '0' }), undefined, now + DAY).pause.waitPossible, true);
  // Ending by waiting has been asked for: still paused, and until when.
  const ending = view(paused({ pending_limit: { id: '2', daily_limit_micros: '600000000', ready_elapsed_micros: String(now + 30n * HOUR) } }));
  assert.deepEqual([ending.pause.on, ending.pause.ending], [true, { id: '2', limit: 600000000n, ready: now + 30n * HOUR }]);
  assert.equal(ending.pause.note, `Nothing can be paid at once. A payment started now waits 48 hours and you can cancel it. The pause ends at <${now + 30n * HOUR}> (~30h): your limit is then 600 seconds.`);
  assert.equal(ending.pause.waitNote, 'Your limit comes back after 48 hours. You can cancel that meanwhile. A request is waiting already: asking again starts the wait again.');
  // Once that wait is over the limit is in force, although the stored row still shows the paused one until the account's next action.
  const matured = paused({ pending_limit: { id: '2', daily_limit_micros: '600000000', ready_elapsed_micros: String(now - 1n) } });
  assert.deepEqual([P.effectiveLimit(matured, now), P.waitingRaise(matured, now), P.pauseState(matured, now, FEE), view(matured).status.text, view(matured).pause.on, view(matured).limit.value], [600000000n, null, 'off', 'Your account is protected.', false, 600000000n]);
  assert.deepEqual([P.effectiveLimit(matured, now - 2n), P.pauseState(matured, now - 2n, FEE)], [1000n, 'paused']);
  // Paused and frozen: neither way of ending the pause is open.
  const frozenToo = view(paused({ frozen_until_elapsed_micros: String(now + HOUR) }));
  assert.deepEqual([frozenToo.pause.locked, frozenToo.pause.waitPossible, frozenToo.pause.waitNote], [true, false, 'Not possible while the account is frozen.']);
  assert.match(frozenToo.pause.note, / The account is frozen as well\.$/);
});

test('a limit below the fee, zero included, is shown as what it is: the payment password alone starts nothing, and only a recovery paper sets a limit again', () => {
  for (const limit of ['0', '1', '999']) {
    const r = row({ allowance_micros: limit }, { daily_limit_micros: limit }), v = view(r);
    assert.deepEqual([P.pauseState(r, now, FEE), v.pause.on, v.pause.kind, v.pause.waitPossible, v.limit.perMille], ['shut', true, 'shut', false, 0], limit);
    assert.equal(v.pause.note, `Your daily limit is ${formatSeconds(limit)} seconds, less than the fee of one action. Your payment password alone can neither pay nor start a payment that waits. It can still freeze the account and cancel what is waiting.`);
    assert.equal(v.pause.waitNote, 'Not possible: with a limit below the fee, your payment password alone cannot ask for a higher one.');
    assert.equal(v.status.text, 'Payments are paused.');
  }
  assert.deepEqual([P.pauseState(row({}, { daily_limit_micros: '1001' }), now, FEE), P.pauseState(row({}, { daily_limit_micros: '1000' }), now, FEE)], ['off', 'paused']);
  // The pause this wallet sets is the fee itself: never zero, on any network's fee.
  assert.deepEqual(['1000', '10', '1'].map(P.pauseLimit), ['1000', '10', '1']);
  for (const fee of ['1000', '10', '1']) assert.equal(P.pauseState(row({}, { daily_limit_micros: P.pauseLimit(fee) }), now, fee), 'paused');
});

test('how long until a paused limit covers a fee again', () => {
  const until = (allowance, limit = '1000') => P.untilFeeCovered({ allowance, limit, feeMicros: FEE });
  assert.deepEqual([until('1000'), until('5000', '600000000'), until('0'), until('500'), until('999')], [0n, 0n, DAY, DAY / 2n, 86400000n]);
  assert.deepEqual([until('0', '999'), until('0', '0')], [null, null], 'a limit below the fee never covers one');
  assert.equal(until('0', '600000000'), 144000n, 'under an ordinary limit a fee is back in a moment');
});

test('the limit before a pause is remembered in the browser as a suggestion, and a record no pause stands behind is dropped', () => {
  class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
  const storage = new Storage(), key = P.pauseKey('c6'.repeat(32), 'alice');
  assert.equal(key, `timecurrency.pause.v1:${'c6'.repeat(32)}:alice`);
  assert.equal(P.rememberedLimit(storage, key), null);
  assert.equal(P.rememberLimit(storage, key, 600000000n, 1000), true);
  assert.deepEqual([storage.getItem(key), P.rememberedLimit(storage, key)], ['{"limit":"600000000","at":1000}', '600000000']);
  // One record per account and per network.
  assert.equal(P.rememberedLimit(storage, P.pauseKey('c6'.repeat(32), 'bob')), null);
  assert.equal(P.rememberedLimit(storage, P.pauseKey('d7'.repeat(32), 'alice')), null);
  // What is not a limit is not remembered, and what was stored by something else is not taken for one.
  for (const bad of [0n, -5n, '12.5', 'x', 1n << 64n]) assert.equal(P.rememberLimit(new Storage(), key, bad, 1), false, String(bad));
  for (const stored of ['not json', 'null', '{}', '{"limit":600}', '{"limit":"0"}', '{"limit":"06"}', '{"limit":"1e9"}', `{"limit":"${1n << 64n}"}`, '["600"]']) { storage.setItem(key, stored); assert.equal(P.rememberedLimit(storage, key), null, stored); }
  // While the account is paused the record stays, however old. Not paused: it stays for ten minutes (the pause that
  // was just signed may not be in proven state yet), then it goes.
  const at = 5000000;
  P.rememberLimit(storage, key, '600000000', at);
  P.settleRemembered(storage, key, true, at + 10 * P.REMEMBER_GRACE_MS); assert.equal(P.rememberedLimit(storage, key), '600000000');
  P.settleRemembered(storage, key, false, at + P.REMEMBER_GRACE_MS - 1); assert.equal(P.rememberedLimit(storage, key), '600000000');
  P.settleRemembered(storage, key, false, at + P.REMEMBER_GRACE_MS); assert.equal(storage.getItem(key), null);
  storage.setItem(key, 'not json'); P.settleRemembered(storage, key, false, at); assert.equal(storage.getItem(key), null, 'a record without a time goes at once');
  P.settleRemembered(storage, key, false, at); assert.equal(storage.getItem(key), null);
  // A browser that refuses to store: nothing is remembered, and nothing fails.
  const refusing = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceededError'); }, removeItem() { throw new Error('SecurityError'); } };
  assert.equal(P.rememberLimit(refusing, key, 5n, 1), false); assert.equal(P.rememberedLimit(refusing, key), null); P.forgetLimit(refusing, key); P.settleRemembered(refusing, key, false, at);
  P.rememberLimit(storage, key, 7n, 1); P.forgetLimit(storage, key); assert.equal(storage.getItem(key), null);
});

test('a change of the limit says what it will do before it is confirmed: at once, after the wait, or at once with a recovery paper', () => {
  const says = (next, withPaper = false) => P.limitChange({ current: 600000000n, next, feeMicros: FEE, delay: '48 hours', withPaper, words });
  assert.deepEqual(says(null), { kind: 'empty', text: '' });
  assert.deepEqual(says('300000000'), { kind: 'lower', text: 'Lower than now: it applies at once.' });
  assert.deepEqual(says('300000000', true), { kind: 'lower', text: 'Lower than now: it applies at once.' }, 'a paper typed for a lower limit changes nothing');
  assert.deepEqual(says('600000000'), { kind: 'same', text: 'That is your limit now.' });
  assert.deepEqual(says('600000001'), { kind: 'raise-wait', text: 'Higher than now: it waits 48 hours, and you can cancel it meanwhile. With a recovery paper it applies at once.' });
  assert.deepEqual(says('600000001', true), { kind: 'raise-now', text: 'Higher than now, with a recovery paper: it applies at once. What is waiting is cancelled, and websites sign you out.' });
  for (const low of ['1000', '999', '1']) assert.deepEqual(says(low), { kind: 'too-low', text: 'A limit must be above the network fee of 0.001 seconds. To stop payments, use “Pause payments”.' });
  assert.equal(says('1001').kind, 'lower');
});

test('the reviews of the card\'s steps say what the chain will do: the pause, its end by waiting, and a limit set at once', () => {
  assert.deepEqual(P.pauseReview({ row: row(), now, feeMicros: FEE, words }), [
    ['Daily limit now', '600 seconds a day'],
    ['While paused', 'Your payment password alone can pay nothing at once. A payment started then waits 48 hours, and you can cancel it.'],
    ['How', 'The limit becomes 0.001 seconds, the fee of one action: enough to start one payment that waits, or to ask for your limit back, once a day.'],
    ['To end the pause', 'Your limit comes back after 48 hours of waiting, or at once with a recovery paper. What you can pay at once then fills up again over 24 hours.'],
    ['Fee', '0.001 seconds']]);
  // A raise that waits is dropped by a lower limit: the review of the pause says so.
  const raising = P.pauseReview({ row: row({ pending_limit: { id: '4', daily_limit_micros: '900000000', ready_elapsed_micros: String(now + DAY) } }), now, feeMicros: FEE, words });
  assert.deepEqual(raising[3], ['Also', 'The waiting raise of your limit to 900 seconds is dropped.']);
  assert.deepEqual(P.resumeWaitReview({ row: row({}, { daily_limit_micros: '1000' }), now, limitMicros: '600000000', feeMicros: FEE, words }), [
    ['Daily limit', 'Back to 600 seconds a day'],
    ['When', `After 48 hours, at about <${now + 48n * HOUR}>. Until then payments stay paused, and you can cancel this under “Waiting on your account”.`],
    ['Then', 'What you can pay at once fills up over the following 24 hours.'],
    ['Fee', '0.001 seconds']]);
  // At once with a recovery paper: what else that does, and that the allowance is not filled by it.
  const at = P.limitNowReview({ row: row({}, { daily_limit_micros: '1000' }), now, limitMicros: '600000000', allowance: 400n, feeMicros: FEE, waiting: { payments: 2, changes: 1 }, words });
  assert.deepEqual(at, [
    ['Daily limit', '600 seconds a day, at once (now 0.001 seconds)'],
    ['Approved by', 'Your payment password and one recovery paper'],
    ['Also', 'What is waiting on your account (2 payments and 1 change) is cancelled. Websites sign you out.'],
    ['Then', 'What you can pay at once starts at 0.0004 seconds and fills up over 24 hours.'],
    ['Fee', '0.001 seconds']]);
  const none = P.limitNowReview({ row: row(), now, limitMicros: '900000000', allowance: 600000000n, feeMicros: FEE, words });
  assert.deepEqual([none[2], none[3]], [['Also', 'Anything waiting on your account is cancelled. Websites sign you out.'], ['Then', 'What you can pay at once starts at 600 seconds and fills up over 24 hours.']]);
  // A lower limit set that way cuts what is left to it, as the engine does.
  assert.deepEqual(P.limitNowReview({ row: row(), now, limitMicros: '100000000', allowance: 600000000n, feeMicros: FEE, words })[3], ['Then', 'What you can pay at once starts at 100 seconds and fills up over 24 hours.']);
});

// ------------------------------------------------------------------ what is signed
const fixture = JSON.parse(await readFile(new URL('../../client-v4/account-security.fixture.json', import.meta.url), 'utf8'));
const networkId = fixture.network_id, accountId = fixture.account.id, keys = {};
for (const entry of fixture.seeds) keys[entry.name] = { publicKey: entry.public_key, privateKey: await crypto.subtle.importKey('pkcs8', SDK.hexToBytes('302e020100300506032b657004220420' + entry.seed_hex), { name: 'Ed25519' }, false, ['sign']) };
const flows = F.createSecurityFlows({ security });
const device = (name, role) => ({ public_key: keys[name].publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const account = (extra = {}) => ({ id: accountId, name: 'alice', balance: '10000000', nonce: '7', auth_epoch: '3', recovery_policy: null,
  devices: [device('signin', 'signin'), device('spend', 'spend'), device('sheet', 'recover'), device('phrase', 'recover')].sort((a, b) => (a.public_key < b.public_key ? -1 : 1)), ...extra });
const verifies = async (publicKey, signature, message) => crypto.subtle.verify('Ed25519', await crypto.subtle.importKey('raw', SDK.hexToBytes(publicKey), 'Ed25519', false, ['verify']), SDK.hexToBytes(signature), message);

test('"Pause payments" signs one change of the limit to exactly the fee, with the payment key, and is refused where the chain would refuse it', async () => {
  const built = await flows.buildPause({ networkId, account: account(), security: row({ account: accountId }), spend: keys.spend, feeMicros: FEE, now });
  const action = SDK.decodeAction(built.tx);
  assert.deepEqual([action.kind, action.from, action.nonce, action.authEpoch, action.publicKey, action.payload], [77, accountId, '8', '3', keys.spend.publicKey, { daily_limit_micros: '1000' }]);
  assert.deepEqual([built.kind, built.sequenced, built.nonce], [77, true, '8']);
  // Whatever the network's fee is, the paused limit is that fee and not zero.
  for (const fee of ['10', '1']) assert.deepEqual(SDK.decodeAction((await flows.buildPause({ networkId, account: account(), security: row({ account: accountId }), spend: keys.spend, feeMicros: fee, now })).tx).payload, { daily_limit_micros: fee });
  const refuses = (extra, policy, words, signer = keys.spend) => assert.rejects(flows.buildPause({ networkId, account: account(), security: row({ account: accountId, ...extra }, policy), spend: signer, feeMicros: FEE, now }), words);
  // The fee of the pause itself is charged to the allowance: with less than a fee left, the chain refuses it.
  await refuses({ allowance_micros: '999' }, {}, /^Error: Pausing costs the network fee, and less than that is left of your daily limit right now\. Freeze the account instead, or try again later\.$/);
  await refuses({ allowance_micros: '1000' }, { daily_limit_micros: '1000' }, /Payments are paused already\./);
  await refuses({ allowance_micros: '0' }, { daily_limit_micros: '0' }, /Payments are paused already\./);
  await refuses({ frozen_until_elapsed_micros: String(now + 1n) }, {}, /The account is frozen/);
  await assert.rejects(flows.buildPause({ networkId, account: account({ balance: '999' }), security: row({ account: accountId }), spend: keys.spend, feeMicros: FEE, now }), /Pausing costs the network fee, and the account holds less\. Freeze the account instead/);
  await refuses({}, {}, /login key cannot/, keys.signin);
  await refuses({}, {}, /This key cannot do this/, keys.sheet);
  assert.ok(await flows.buildPause({ networkId, account: account(), security: row({ account: accountId, allowance_micros: '1000' }), spend: keys.spend, feeMicros: FEE, now }), 'exactly one fee left is enough');
});

test('a limit set at once is one root operation approved by the payment key and a recovery key: every key kept in its role, the policy as it was but for the limit', async () => {
  const paused = row({ account: accountId, version: '4', allowance_micros: '1000' }, { daily_limit_micros: '1000' });
  const built = await flows.buildLimitNow({ networkId, account: account(), security: paused, spend: keys.spend, recovery: keys.sheet, dailyLimitMicros: '600000000', feeMicros: FEE, now });
  const action = SDK.decodeAction(built.tx), op = action.payload.op;
  // A protective action: no nonce, submitted by the payment key.
  assert.deepEqual([action.kind, action.nonce, action.authEpoch, action.publicKey, built.sequenced, built.version, built.spend], [73, '0', '0', keys.spend.publicKey, false, '4', true]);
  assert.deepEqual(op.policy, { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '172800', freeze_seconds: '172800' });
  // The keys of the account, each in the role it has, none with a new acceptance: nothing is added and nothing removed.
  assert.deepEqual(op.keys, account().devices.map(d => ({ public_key: d.public_key, role: security.roleOf(d) })));
  assert.deepEqual([op.type, Object.keys(op).sort()], ['replace', ['keys', 'policy', 'type']]);
  // The two approvals verify against the message the engine checks: this account, this version, this operation, these approvers.
  assert.deepEqual(action.payload.approvals.map(a => a.public_key).sort(), [keys.spend.publicKey, keys.sheet.publicKey].sort());
  const message = await security.rootMessage({ networkId, accountId, version: '4', expiresElapsedMicros: action.payload.expires_elapsed_micros, operation: op, approvers: [keys.spend.publicKey, keys.sheet.publicKey] });
  for (const approval of action.payload.approvals) assert.ok(await verifies(approval.public_key, approval.signature, message));
  assert.equal(BigInt(action.payload.expires_elapsed_micros) - now, F.APPROVAL_LIFETIME_MICROS);
  // It also raises an ordinary limit at once, with the passphrase's key as well as the sheet's.
  const raise = SDK.decodeAction((await flows.buildLimitNow({ networkId, account: account(), security: row({ account: accountId }), spend: keys.spend, recovery: keys.phrase, dailyLimitMicros: '900000000', feeMicros: FEE, now })).tx);
  assert.deepEqual([raise.payload.op.policy.daily_limit_micros, raise.payload.approvals.map(a => a.public_key).sort()], ['900000000', [keys.spend.publicKey, keys.phrase.publicKey].sort()]);
  const refuses = (input, words) => assert.rejects(flows.buildLimitNow({ networkId, account: account(), security: paused, spend: keys.spend, recovery: keys.sheet, dailyLimitMicros: '600000000', feeMicros: FEE, now, ...input }), words);
  await refuses({ recovery: keys.next }, /does not belong to @alice/);
  await refuses({ recovery: keys.signin }, /does not belong to @alice/);
  await refuses({ dailyLimitMicros: '1000' }, /above the network fee/);
  await refuses({ dailyLimitMicros: '0' }, /above the network fee/);
  await refuses({ security: row({ account: accountId }), dailyLimitMicros: '600000000' }, /already has this value/);
  // Not for a frozen account: being a replacement, it would end the freeze as well.
  await refuses({ security: { ...paused, frozen_until_elapsed_micros: String(now + 1n) } }, /The account is frozen\. End the freeze first\./);
  await refuses({ account: account({ balance: '999' }) }, /network fee of 0\.001 seconds\. Your balance is 0\.000999 seconds/);
  // A raise that has waited is in force: the limit it brought is the one a new limit is compared with.
  const matured = row({ account: accountId, pending_limit: { id: '2', daily_limit_micros: '900000000', ready_elapsed_micros: String(now - 1n) } });
  await refuses({ security: matured, dailyLimitMicros: '900000000' }, /already has this value/);
  assert.equal((await flows.buildLimit({ networkId, account: account(), security: matured, spend: keys.spend, dailyLimitMicros: '700000000', feeMicros: FEE, now })).raise, false, 'below the limit in force: a lowering');
  assert.equal((await flows.buildLimit({ networkId, account: account(), security: matured, spend: keys.spend, dailyLimitMicros: '700000000', feeMicros: FEE })).raise, true, 'without the time, compared with the stored row as before');
});

test('a limit change checks its fee, freeze and remaining allowance before signing', async () => {
  const build = (balance, changes = {}) => flows.buildLimit({
    networkId, account: account({ balance }), security: row({ account: accountId, ...changes }),
    spend: keys.spend, dailyLimitMicros: '700000000', feeMicros: FEE, now,
  });
  await assert.rejects(build('0'), /network fee of 0\.001 seconds\. Your balance is 0 seconds/);
  await assert.rejects(build(FEE, { frozen_until_elapsed_micros: String(now + 1n) }), /account is frozen/);
  await assert.rejects(build(FEE, { allowance_micros: '999' }), /allowance needs to refill/);
  assert.equal((await build(FEE, { allowance_micros: String(FEE) })).kind, 77);
});

test('"Protect my account" suggests a daily limit of 600 seconds, written for a person, from one constant', async () => {
  assert.equal(F.DEFAULT_DAILY_LIMIT_SECONDS, '600');
  assert.equal(F.dailyLimitWords(), '10 minutes of seconds a day (600)');
  assert.deepEqual(['60', '3600', '7200', '90', '1', '86400'].map(F.dailyLimitWords), ['1 minute of seconds a day (60)', '1 hour of seconds a day (3600)', '2 hours of seconds a day (7200)', '90 seconds a day', '1 second a day', '24 hours of seconds a day (86400)']);
  // The suggestion is a limit the policy takes.
  assert.equal(F.choosePolicy({ dailyLimitMicros: parseSeconds(F.DEFAULT_DAILY_LIMIT_SECONDS), feeMicros: FEE, minDelayMicros: '0' }).daily_limit_micros, '600000000');
  // That the page takes its number and its words from here is tested with the page (protection-card.test.mjs).
});
