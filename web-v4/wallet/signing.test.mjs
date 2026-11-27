// signing.mjs: the wallet's `sendSigned`, called directly. Which key may sign which kind of
// action is decided there, before any key signs, and each rule has a test here that fails when
// the rule is taken out:
// - a payment key signs only the kinds listed for it, and a validator's upgrade signal;
// - on a secured account an action without a payment key is refused, whatever the key of the
//   session may do;
// - the Validator signal tab's signer has kind 80 signed and nothing else, by the payment key on
//   a secured account and by this browser's key otherwise.
// app.test.mjs runs the same through the real app.js on a stand-in page.
import test from 'node:test';
import assert from 'node:assert/strict';

const root = new URL('../../', import.meta.url);
await import(new URL('client-v4/time-sdk.js', root).href);
const SDK = globalThis.TimeSDK;
const { createSendSigned, signalSigner } = await import(new URL('web-v4/wallet/signing.mjs', root).href);
const { SPEND_KEY_KINDS, MARKET_KINDS, accountSecured } = await import(new URL('web-v4/wallet/security-flows.mjs', root).href);
const { newDevice } = await import(new URL('web-v4/wallet/vault.mjs', root).href);
const { PendingReservations, PaymentMarkers } = await import(new URL('web-v4/wallet/guards.mjs', root).href);

class Storage { m = new Map(); getItem(k) { return this.m.has(k) ? this.m.get(k) : null; } setItem(k, v) { this.m.set(k, String(v)); } removeItem(k) { this.m.delete(k); } }
const networkId = 'c6'.repeat(32), GENESIS = 1700000000000000n, DAY = 86400000000n;
const PLAN = { activate_elapsed_micros: (130n * DAY).toString(), spec: 'a3b1c5d7'.repeat(8), version: '5' };
const SECURITY_ROW = { account: '5', version: '1', policy: { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '172800', freeze_seconds: '172800' }, allowance_micros: '60000000', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };

/// A wallet with one account (5, "alice"). `secured`: the account has a security row, the session's key is its
/// login key and `w.spend` its payment key. `sessionMay`: what the session's key may do on the chain.
async function wallet({ secured = false, sessionMay = secured ? { can_manage: false, can_spend: false } : { can_manage: true, can_spend: true } } = {}) {
  const login = await newDevice(), spend = await newDevice();
  const w = { login, spend, submitted: [], recorded: [], notices: [], pending: new PendingReservations(new Storage()), whileSubmitting: null, recovery: [] };
  w.account = { id: '5', name: 'alice', balance: '5000000', nonce: '3', auth_epoch: '0', devices: [{ public_key: login.publicKey, ...sessionMay }, ...(secured ? [{ public_key: spend.publicKey, can_manage: false, can_spend: true }] : [])] };
  w.state = () => structuredClone({ protocol_version: '4', network_id: networkId, height: '900', time_micros: (GENESIS + 100n * DAY).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: {}, accounts: [w.account], recovery_cases: w.recovery, ...(secured ? { security: [SECURITY_ROW] } : {}) });
  const session = { binding: { networkId, name: 'alice', publicKey: login.publicKey }, privateKey: login.privateKey };
  const ownAccount = (state = w.state()) => state.accounts.find(item => item.name === session.binding.name);
  w.sendSigned = createSendSigned({ sdk: SDK, session: () => w.locked ? null : session, network: () => ({ networkId }), locks: () => ({ request: (_name, _options, fn) => fn() }), capture: () => () => {}, ownAccount, verifiedState: async () => w.state(),
    pending: w.pending, paymentMarkers: new PaymentMarkers(new Storage()), notice: (text, type) => w.notices.push({ text, type }), record: (receipt, label) => w.recorded.push(label),
    client: () => ({ submit: async tx => { const action = SDK.decodeAction(tx); w.submitted.push(action); if (w.whileSubmitting) await w.whileSubmitting(); return { verified: true, hash: await SDK.transactionHash(tx), height: '901', action }; } }) });
  w.signer = { publicKey: spend.publicKey, privateKey: spend.privateKey };
  return w;
}
const nothingSigned = w => assert.deepEqual([w.submitted.length, w.pending.get(networkId, '5'), w.recorded.length], [0, null, 0], 'something was signed, kept or sent');

test('an account with one key: this browser\'s key signs, the pending record is written before the bytes leave and cleared by the receipt', async () => {
  const w = await wallet();
  w.whileSubmitting = async () => { w.held = w.pending.get(networkId, '5'); };
  const receipt = await w.sendSigned('upgrade_signal', PLAN, 'Signal: support version 5');
  assert.deepEqual([w.submitted.length, w.submitted[0].kind, SDK.KINDS.upgrade_signal, w.submitted[0].publicKey, w.submitted[0].from, w.submitted[0].nonce, w.submitted[0].payload], [1, 80, 80, w.login.publicKey, '5', '4', PLAN]);
  assert.deepEqual([receipt.verified, w.held.kind, w.held.nonce, w.pending.get(networkId, '5'), w.recorded], [true, 'upgrade_signal', '4', null, ['Signal: support version 5']]);
  // One signed action at a time: while one is pending, nothing else is signed.
  w.pending.put(networkId, '5', { hash: 'AB'.repeat(32), tx: 'AA==', nonce: '4', authEpoch: '0', kind: 'transfer', label: 'Send', at: 1 });
  await assert.rejects(w.sendSigned('upgrade_signal', {}, 'Signal: withdraw support'), /^Error: A signed action is already pending \(A(BA)+B\)\. Check its receipt before signing again\.$/);
  assert.equal(w.submitted.length, 1);
  // A locked wallet signs nothing, and a guardian recovery that has its approvals freezes the account.
  w.pending.clear(networkId, '5', 'AB'.repeat(32)); w.recovery = [{ target: '5', recovery_id: '1', new_public_key: '77'.repeat(32), ready_elapsed_micros: '5', expires_elapsed_micros: (200n * DAY).toString() }];
  await assert.rejects(w.sendSigned('upgrade_signal', PLAN, 'Signal'), /Guardian recovery freezes this account\./);
  w.recovery = []; w.locked = true;
  await assert.rejects(w.sendSigned('upgrade_signal', PLAN, 'Signal'), /^Error: Unlock this device first\.$/);
  assert.equal(w.submitted.length, 1);
});

test('the receipt is recorded, and its encrypted write waited for, before the pending action is cleared; a website\'s order is marked before the bytes leave', async () => {
  // A record that is written a moment later (locked-store.mjs encrypts it): until then the pending action stays, so a
  // page closed in between keeps it, and the next opening checks the receipt and records it.
  const { createPrivateStore, orderMarkers } = await import(new URL('web-v4/wallet/locked-store.mjs', root).href);
  const w = await wallet(), seen = [];
  let release; const written = new Promise(resolve => { release = resolve; });
  const store = createPrivateStore({ storage: new Storage() });
  const made = await newDevice(globalThis.crypto, { networkId, name: 'alice' });
  await store.open({ networkId, name: 'alice', publicKey: made.publicKey, storageKey: made.storageKey });
  const markers = orderMarkers(store);
  const sendSigned = createSendSigned({ sdk: SDK, session: () => ({ binding: { networkId, name: 'alice', publicKey: w.login.publicKey }, privateKey: w.login.privateKey }), network: () => ({ networkId }), locks: () => ({ request: (_name, _options, fn) => fn() }), capture: () => () => {},
    ownAccount: (state = w.state()) => state.accounts.find(item => item.name === 'alice'), verifiedState: async () => w.state(), pending: w.pending, paymentMarkers: markers, notice: () => {},
    record: (receipt, label) => { seen.push(['record', label, Boolean(w.pending.get(networkId, '5'))]); return written; }, cleared: () => seen.push(['cleared', Boolean(w.pending.get(networkId, '5'))]),
    client: () => ({ submit: async tx => { const action = SDK.decodeAction(tx); seen.push(['submit', markers.get(networkId, '5', action.payload.reference)?.status ?? null]); return { verified: true, hash: await SDK.transactionHash(tx), height: '901', action }; } }) });
  const reference = SDK.orderReference({ nonce: '4', expiresElapsedMicros: (101n * DAY).toString() });
  const sending = sendSigned('merchant_payment', { to: '1', amount: '5', reference }, `Website payment ${reference}`, { merchantOrigin: 'https://shop.example' });
  for (let i = 0; i < 50 && seen.length < 2; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.deepEqual(seen, [['submit', 'pending'], ['record', `Website payment ${reference}`, true]], 'the order was marked before the bytes left, and the receipt is being recorded with the action still pending');
  assert.ok(w.pending.get(networkId, '5'), 'nothing is cleared while the record is being written');
  release(true); await sending;
  assert.deepEqual([seen.at(-1), w.pending.get(networkId, '5')], [['cleared', false], null]);
  // The same order again: refused before anything is signed.
  w.account.nonce = '4';
  await assert.rejects(sendSigned('merchant_payment', { to: '1', amount: '5', reference }, 'again'), /already has a signed payment record/);
});

test('a page that keeps its history in memory only pays a website order and writes nothing of it; once the payment is in a block, the same order is refused before any key signs, by the quote\'s nonce', async () => {
  // The wallet's mark of an order is a courtesy (locked-store.mjs, orderMarkers): what pays an order once at most is the
  // reference, which carries the sender's next nonce (the engine's rule since protocol 4; the SDK's checkMerchantQuote).
  const { createPrivateStore, orderMarkers } = await import(new URL('web-v4/wallet/locked-store.mjs', root).href);
  const w = await wallet(), storage = new Storage(), reference = SDK.orderReference({ nonce: '4', expiresElapsedMicros: (101n * DAY).toString() });
  async function pageInMemoryOnly() {
    const store = createPrivateStore({ storage });
    assert.equal((await store.open({ networkId, name: 'alice', publicKey: w.login.publicKey, storageKey: null })).memory, true);
    return createSendSigned({ sdk: SDK, session: () => ({ binding: { networkId, name: 'alice', publicKey: w.login.publicKey }, privateKey: w.login.privateKey }), network: () => ({ networkId }), locks: () => ({ request: (_name, _options, fn) => fn() }), capture: () => () => {},
      ownAccount: (state = w.state()) => state.accounts.find(item => item.name === 'alice'), verifiedState: async () => w.state(), pending: w.pending, paymentMarkers: orderMarkers(store), notice: () => {}, record: async () => true,
      // The stand-in chain takes the action, and the account's nonce moves as the engine moves it.
      client: () => ({ submit: async tx => { const action = SDK.decodeAction(tx); w.submitted.push(action); w.account.nonce = action.nonce; return { verified: true, hash: await SDK.transactionHash(tx), height: '901', action }; } }) });
  }
  await (await pageInMemoryOnly())('merchant_payment', { to: '1', amount: '5', reference }, `Website payment ${reference}`, { merchantOrigin: 'https://shop.example' });
  assert.deepEqual([w.submitted.length, storage.m.size], [1, 0], 'paid, and nothing of the order or the website is written');
  await assert.rejects((await pageInMemoryOnly())('merchant_payment', { to: '1', amount: '5', reference }, 'again', { merchantOrigin: 'https://shop.example' }), /reserved another nonce/);
  assert.deepEqual([w.submitted.length, w.pending.get(networkId, '5')], [1, null], 'nothing was signed or kept');
});

test('a payment key signs only the kinds listed for it and a validator\'s upgrade signal: every other kind is refused before anything is signed', async () => {
  const w = await wallet({ secured: true });
  // The list (payments, staking and the operation of a validator), and the one addition. A signal and its withdrawal are
  // signed by the payment key, not by the session's key.
  assert.deepEqual(SPEND_KEY_KINDS, ['transfer', 'merchant_payment', 'delegate', 'undelegate', 'withdraw_stake', 'register_validator', 'self_bond', 'self_unbond', 'retire_validator']);
  await w.sendSigned('upgrade_signal', PLAN, 'Signal: support version 5', { signer: w.signer });
  w.account.nonce = '4';
  await w.sendSigned('upgrade_signal', {}, 'Signal: withdraw support', { signer: w.signer });
  assert.deepEqual(w.submitted.map(action => [action.kind, action.publicKey === w.spend.publicKey, action.nonce]), [[80, true, '4'], [80, true, '5']]);
  w.account.nonce = '5'; await w.sendSigned('transfer', { to: '1', amount: '5' }, 'Send', { signer: w.signer });
  assert.deepEqual([w.submitted.length, w.submitted[2].kind, w.submitted[2].publicKey], [3, SDK.KINDS.transfer, w.spend.publicKey]);
  // Every other kind the SDK knows, with payloads the kinds would take, and a kind that does not exist.
  w.submitted.length = 0; w.recorded.length = 0;
  const others = Object.keys(SDK.KINDS).filter(kind => kind !== 'upgrade_signal' && !SPEND_KEY_KINDS.includes(kind) && !MARKET_KINDS.includes(kind));
  assert.ok(others.length >= 15 && ['add_device', 'revoke_device', 'cancel_pending', 'finalize_recovery', 'reveal', 'withdraw', 'double_vote', 'bitcoin_bid', 'market_proof'].every(kind => others.includes(kind)), others.join(' '));
  for (const kind of [...others, 'no_such_kind', undefined, 80]) for (const payload of [{}, { public_key: w.spend.publicKey }]) {
    await assert.rejects(w.sendSigned(kind, payload, 'x', { signer: w.signer }), /^Error: The payment key signs payments and staking only\. This action cannot be signed with it\.$/, String(kind));
  }
  nothingSigned(w);
  // A payment key registers nothing and finishes no recovery, whatever the kind is called.
  for (const options of [{ anonymous: true }, { recoveryFinalization: true }]) for (const kind of ['upgrade_signal', 'transfer', 'reveal', 'finalize_recovery']) {
    await assert.rejects(w.sendSigned(kind, {}, 'x', { ...options, signer: w.signer }), /^Error: A payment key signs payments, staking and a validator's upgrade signal only\.$/);
  }
  nothingSigned(w);
});

// The market of seconds against bitcoin (market-ui.mjs): its eight actions join what the payment key signs, each named, and
// nothing else of the market does. A proof of payment (kind 54) is not among them: this wallet builds none.
test('the payment key signs the eight actions of the market that a person takes, each by name, and no proof of payment', async () => {
  assert.deepEqual(MARKET_KINDS, ['market_order', 'market_cancel', 'market_take', 'market_sell', 'market_expire', 'market_release', 'market_settle', 'market_scripts']);
  assert.deepEqual(MARKET_KINDS.map(kind => SDK.KINDS[kind]), [50, 51, 52, 53, 55, 56, 57, 58]);
  assert.ok(MARKET_KINDS.every(kind => !SPEND_KEY_KINDS.includes(kind)), 'the list of payments and staking is unchanged');
  const w = await wallet({ secured: true });
  await w.sendSigned('market_cancel', { order: '7' }, 'Cancel order 7', { signer: w.signer });
  assert.deepEqual(w.submitted.map(action => [action.kind, action.publicKey === w.spend.publicKey, action.payload]), [[51, true, { order: '7' }]]);
  // Without the payment key nothing of the market is signed on a secured account, and a payload in another form is refused before any key signs.
  w.submitted.length = 0; w.recorded.length = 0; w.account.nonce = '4';
  await assert.rejects(w.sendSigned('market_cancel', { order: '7' }, 'x'), /^Error: This account is secured\. Its login key cannot sign this; use your payment password\.$/);
  await assert.rejects(w.sendSigned('market_cancel', { order: '7', to: '9' }, 'x', { signer: w.signer }), /A payload of kind 51 has exactly the fields order/);
  await assert.rejects(w.sendSigned('market_proof', { fill: '1' }, 'x', { signer: w.signer }), /^Error: The payment key signs payments and staking only\. This action cannot be signed with it\.$/);
  for (const kind of [51, 'Market_cancel', ' market_cancel', ['market_cancel']]) await assert.rejects(w.sendSigned(kind, { order: '7' }, 'x', { signer: w.signer }), /payments and staking only/, String(kind));
  nothingSigned(w);
});

test('on a secured account nothing is signed without the payment key, whatever the session\'s key may do on the chain', async () => {
  // The session's key as the Security tab leaves it (it may neither spend nor manage), and two keys that the chain
  // would take an action from: only this wallet's rule stands between them and a signature.
  for (const sessionMay of [{ can_manage: false, can_spend: false }, { can_manage: true, can_spend: false }, { can_manage: false, can_spend: true }]) {
    const w = await wallet({ secured: true, sessionMay });
    assert.equal(accountSecured(w.state(), w.account), true);
    for (const [kind, payload] of [['upgrade_signal', PLAN], ['upgrade_signal', {}], ['transfer', { to: '1', amount: '5' }], ['cancel_pending', {}], ['retire_validator', {}], ['revoke_device', { public_key: w.spend.publicKey }]]) {
      await assert.rejects(w.sendSigned(kind, payload, 'x'), /^Error: This account is secured\. Its login key cannot sign this; use your payment password\.$/, `${kind} ${JSON.stringify(sessionMay)}`);
    }
    nothingSigned(w);
  }
  // Whether the account is secured is read from the state verified for this action: a state that carries the
  // security rows and a row of the account. Without the rows the account's keys decide, as on any account.
  const plain = await wallet();
  assert.deepEqual([accountSecured(plain.state(), plain.account), accountSecured({ ...plain.state(), security: [] }, plain.account), accountSecured({ ...plain.state(), security: [{ ...SECURITY_ROW, account: '6' }] }, plain.account), accountSecured({ ...plain.state(), security: [SECURITY_ROW] }, plain.account), accountSecured({ security: [SECURITY_ROW] }, null)], [false, false, false, true, false]);
});

test('the Validator signal tab\'s signer: kind 80 and nothing else, by the payment key on a secured account and by this browser\'s key otherwise', async () => {
  const calls = [];
  let secured = false;
  const sign = signalSigner({ secured: () => secured, signalAction: async (...given) => { calls.push(['payment key', ...given]); return 'by the payment key'; }, sendSigned: async (...given) => { calls.push(['this browser\'s key', ...given]); return 'by this browser\'s key'; } });
  assert.equal(await sign(PLAN, 'Signal: support version 5'), 'by this browser\'s key');
  secured = true;
  assert.equal(await sign({}, 'Signal: withdraw support'), 'by the payment key');
  // Asked each time: the account was secured between two signals.
  secured = false; await sign({}, 'Signal: withdraw support');
  assert.deepEqual(calls, [['this browser\'s key', 'upgrade_signal', PLAN, 'Signal: support version 5'], ['payment key', {}, 'Signal: withdraw support'], ['this browser\'s key', 'upgrade_signal', {}, 'Signal: withdraw support']]);
  // With the real sendSigned behind it: an account with one key signs kind 80 with that key; on a secured account
  // the same call without the payment key is refused by sendSigned itself, so a wrong answer of `secured` signs nothing.
  const one = await wallet();
  await signalSigner({ secured: () => false, signalAction: () => assert.fail('not secured'), sendSigned: one.sendSigned })(PLAN, 'Signal: support version 5');
  assert.deepEqual(one.submitted.map(action => [action.kind, action.publicKey]), [[80, one.login.publicKey]]);
  const two = await wallet({ secured: true });
  await assert.rejects(signalSigner({ secured: () => false, signalAction: () => assert.fail('not asked'), sendSigned: two.sendSigned })(PLAN, 'Signal'), /This account is secured\. Its login key cannot sign this/);
  nothingSigned(two);
});
