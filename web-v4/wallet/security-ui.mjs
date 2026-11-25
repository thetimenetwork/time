// The Security tab, the payment password on Send, Earn and website payments, and recovery of a
// lost device. The decisions are in security-flows.mjs; this module reads inputs, shows the
// review dialog, unlocks a key for one action and submits. Secrets typed here are read once and
// their fields are cleared whatever happens (also when a review is cancelled or a step fails);
// they are never logged or stored.
//
// The rule (vault.mjs, RULE): every key made here is sealed with the device's secret and a password together, or under a
// password the wallet makes and shows once before anything it seals is kept or sent (c.showMade). Where the device can lock
// keys, "Protect my account" and "Recover my account" let the person choose how the new keys are locked, with neither way
// chosen beforehand (device-lock-ui.mjs, wayChoice; device-lock.mjs, newKeysByRule): locked to this device from birth, or
// under passwords the wallet makes; a new login or payment password, a login asked of another device and a new login after
// this browser's was removed seal with the device when the account's keys here are locked to it, and else under
// passwords the wallet makes.
import * as security from '/sdk/account-security.mjs';
import { openVault, validateName, b64, fromB64, forgetSecret, vaultDevice } from './vault.mjs';
import { lockOf, settleSwap, lockPlaces, newKeysByRule, LOCK_WORDS } from './device-lock.mjs';
import { wayChoice } from './device-lock-ui.mjs';
import { withSigningLock, parseSeconds } from './guards.mjs';
import { failureNotice, sentNotice } from './actions.mjs';
import { isBusyError, busyProtective } from './busy.mjs';
import { accountSecured } from './security-flows.mjs';
import {
  createSecurityFlows, elapsedOf, waitsOf, momentOf, encodeSheet, sheetKey, keyFromSeed, newSheetSeed, passphraseKey, generatePassphrase, parsePassphrase, recoveryPaperKind, accountWordsKeys, rememberRecoveryKind,
  checkPasswords, choosePolicy, defaultHours, minimumHours, vaultSlots, stageVaults, stagedSeenAt, stagedNote, settleStaged, discardStaged, hasStaged, stagedNames,
  spendRecord, progressKey, parseProgress, progressRecord, recoveryStatus, protectiveSlot, protectiveObsolete, lostDeviceSlots, protocol4Actions, deviceRows, assertSpendKeyKind, stakeOutflow, SIGNAL_KIND, minSelfBond,
  parseSigninRequest, limitExposure, storeLoginRequest, loginRequestOf, withdrawLoginRequest, settleLoginRequest, fingerprint,
  DEFAULT_DAILY_LIMIT_SECONDS, dailyLimitWords, accountPassphraseKey, sealedKeys,
} from './security-flows.mjs';
import { makeRecoveryKeys as makePapers, forgetRecoveryKeys, printSheet, paperSteps, saveKit, SAVE_NOW, WRITE_NOW } from './papers.mjs';
import { readRecoveryKit, openRecoveryKit, recoveryKitMismatch, MAX_RECOVERY_KIT_BYTES } from './recovery-file.mjs';
import { protectionView, effectiveLimit, pauseState, pauseKey, rememberLimit, rememberedLimit, forgetLimit, settleRemembered, limitChange, pauseReview, resumeWaitReview, limitNowReview, validatorLimit } from './protection.mjs';

const $ = id => document.getElementById(id);
const assert = (value, message) => { if (!value) throw new Error(message); };
function node(tag, text, className) { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; }
/// Reads a secret field once and clears it.
function take(id) { const el = $(id), value = el.value; el.value = ''; return value; }
const scrub = ids => { for (const id of ids) $(id).value = ''; };
function duration(secondsText) {
  const s = BigInt(secondsText);
  if (s % 3600n === 0n) return `${s / 3600n} hour${s === 3600n ? '' : 's'}`;
  if (s % 60n === 0n) return `${s / 60n} minute${s === 60n ? '' : 's'}`;
  return `${s} seconds`;
}
const roughly = micros => { const s = (BigInt(micros) + 999999n) / 1000000n; return s >= 7200n ? `about ${(s + 1799n) / 3600n} hours` : s >= 120n ? `about ${(s + 59n) / 60n} minutes` : `${s} seconds`; };
const PROTECTIVE = [72, 73, 74, 76];
const LABEL = { 72: 'Freeze', 73: 'Key change or payment with two keys', 74: 'Finishing a recovery', 76: 'Cancellation' };
const SECRET_FIELDS = {
  secure: ['secure-login', 'secure-login-confirm', 'secure-payment', 'secure-payment-confirm'],
  lost: ['lost-sheet', 'lost-phrase', 'lost-login', 'lost-login-confirm', 'lost-payment', 'lost-payment-confirm'],
  rr: ['rr-payment', 'rr-secret'],
  replaceSpend: ['replace-spend-payment', 'replace-spend-new', 'replace-spend-confirm', 'replace-spend-login', 'replace-spend-login-confirm', 'replace-spend-secret'],
  replaceLogin: ['replace-login-new', 'replace-login-confirm', 'replace-login-payment'],
  removed: ['removed-login-new', 'removed-login-confirm', 'removed-payment'],
  newlogin: ['newlogin-password', 'newlogin-confirm'],
  other: ['send-payment', 'send-recovery-secret', 'approval-payment', 'freeze-secret', 'unfreeze-payment', 'unfreeze-secret', 'limit-payment', 'limit-secret', 'pause-payment', 'resume-payment', 'resume-secret', 'inbox-payment', 'inbox-secret', 'lost-finish-payment', 'stake-payment', 'add-login-payment', 'signal-payment', 'validator-payment'],
};
// The small steps of the Protection card on Home, each with the secret fields it holds: one is open at a time, and a
// step that closes takes what was typed into it along.
const STEPS = { 'freeze-form': ['freeze-secret'], 'unfreeze-form': ['unfreeze-payment', 'unfreeze-secret'], 'limit-form': ['limit-payment', 'limit-secret'], 'pause-form': ['pause-payment'], 'resume-step': ['resume-payment', 'resume-secret'] };

export function createSecurityUI(c) {
  const flows = createSecurityFlows({ security });
  const net = () => c.network().networkId;
  const argon = () => c.argon2id();
  const fee = () => c.fee();
  const seconds = value => c.seconds(value) + ' seconds';
  let draft = null, rrDraft = null, overDraft = null, stakeOver = null, inboxRows = [], removed = null, lostProgress = null;
  // What the Protection card last drew from proven state (protection.mjs, protectionView), or null: no protected account is shown.
  let card = null;
  /// Runs a form action and clears its secret fields however it ends.
  const guarded = (ids, fn) => c.run(async () => { try { await fn(); } finally { scrub(ids); } });
  // Two clocks (security-flows.mjs, waitsOf). Every moment a security row stores is compared with the clock of the
  // waits, `waits(state)`, and shown as a date with `dated` ("not before" while a stop of the chain can still move it).
  // What a key signs (the expiry of a freeze, of approvals, of a login request) is dated on the chain's time, elapsedOf,
  // and `retired` compares those signed expiries with that time too. On a network without `waits_survive_stops` the
  // two clocks are the same and every date is exact.
  const waits = state => waitsOf(c.sdk, state);
  const dated = (state, at) => momentOf(c.sdk, state, at);
  /// "not before <date>" while the date can still move later, else `word` and the date.
  const timeWords = (state, at, word) => { const m = dated(state, at); return `${m.later ? 'not before' : word} ${m.date.toLocaleString()}`; };
  /// How the card and its reviews write amounts and times of a verified state.
  const words = state => ({ seconds, plain: value => c.seconds(value), duration, roughly, when: at => dated(state, at).date.toLocaleString(), later: at => dated(state, at).later });

  // ---------------------------------------------------------------- state and keys
  const readState = (input = {}) => c.verifiedState({ ...input, include_security: true });
  /// Whether this network takes registrations that carry a set of keys (signup-ui.mjs), by the wallet's latest verified state.
  const registeredHere = () => { try { return c.sdk.protectedRegistration(c.state()) === true; } catch { return false; } };
  function secured(state, account) { return accountSecured(state, account); }
  async function recoveryKey(method, secret, account) {
    assert(typeof secret === 'string' && secret.trim(), method === 'sheet' ? 'Enter your printed recovery sheet.' : 'Enter your recovery words.');
    c.setBusy(true, method === 'sheet' ? 'Reading your printed recovery sheet…' : 'Recreating your recovery key from your recovery words. This takes a few seconds…');
    // The words name the account by its number, or, for the first keys of an account signed up protected, by its
    // registration key (security-flows.mjs, accountPassphraseKey): the second is tried only on a network that takes such
    // sign-ups, and only when the first is not one of the account's keys.
    const key = method === 'sheet' ? await sheetKey(secret) : await accountPassphraseKey({ passphrase: secret, networkId: net(), account, registered: registeredHere(), isRecovery: found => flows.roleOf(account, found.publicKey) === 'recover', argon2id: argon() });
    assert(flows.roleOf(account, key.publicKey) === 'recover', method === 'sheet' ? 'This printed recovery sheet is not one of this account\'s recovery keys. Check it against the paper, or type your recovery words instead.' : 'These recovery words are not one of this account\'s recovery keys. Check them against what you wrote down.');
    return key;
  }
  /// The one recovery key a form asks for, in its one field: the recovery words, or a printed recovery sheet; which
  /// one was typed is told by the text itself (security-flows.mjs, recoveryPaperKind).
  const recoveryPaper = (secret, account) => recoveryKey(recoveryPaperKind(secret) === 'words' ? 'phrase' : 'sheet', secret, account);
  const takeRecovery = (secretId, account) => recoveryPaper(take(secretId), account);
  async function unlockSpend(password, name) {
    assert(typeof password === 'string' && password, 'Enter your payment password.');
    const record = spendRecord(localStorage, vaultSlots(net(), name));
    assert(record, 'This browser has no payment key for this account.');
    // A payment key locked to this device (device-lock.mjs) needs the device's answer too: one request, said before it
    // comes, and kept a minute in case the password was mistyped.
    const device = vaultDevice(record) ? await c.lockAsker().secretsFor([record]) : null;
    c.setBusy(true, 'Unlocking your payment key…');
    let opened;
    try { opened = await openVault(record, password, argon(), globalThis.crypto, 'spend', device?.[0] ?? null); } finally { device?.forEach(secret => secret.fill(0)); }
    if (device) c.lockAsker().release([record]);
    forgetSecret(opened.secret);
    assert(opened.binding.networkId === net() && opened.binding.name === name, 'This payment key belongs to another account.');
    return { publicKey: opened.binding.publicKey, privateKey: opened.privateKey };
  }
  /// Unlocks the spend key for one action and forgets it afterwards.
  async function withSpend(password, name, callback) {
    const signer = await unlockSpend(password, name);
    try { return await callback(signer); } finally { signer.privateKey = null; }
  }
  /// Whether the keys of this account in this browser are locked to this device (device-lock.mjs): then new keys are too,
  /// with the passwords the person chooses; else the wallet makes their passwords.
  const lockedHere = name => Boolean(lockOf(localStorage, vaultSlots(net(), name)).credential);
  /// New keys (one or two, `[{ intent, password }]`), by the rule. While this account's keys are locked to this device
  /// (device-lock.mjs), they are sealed with the device and the passwords typed, all of them in one request to it; else
  /// under passwords the wallet makes (each entry's `made`), and nothing typed is used. Nothing is kept here: the caller
  /// shows the made passwords (showMadeOf) and only then lets a new login key open what the account keeps privately (kept).
  async function newKeys(wanted, name) {
    const lock = lockOf(localStorage, vaultSlots(net(), name));
    return sealedKeys({ wanted: lock.credential ? wanted : wanted.map(w => ({ intent: w.intent })), networkId: net(), name, argon2id: argon(),
      lock: lock.credential ? async keys => ({ credential: lock.credential, secrets: await c.lockAsker().forNew(lock.credential, keys.map(k => ({ ...k, networkId: net(), name }))) }) : null });
  }
  /// The login keys among `made` may open what the account keeps privately in this browser (app.js, keepPrivate;
  /// locked-store.mjs): the activity and the names paid survive the change of keys. Their storage keys go then. Called
  /// after the made passwords were shown and had.
  async function kept(made) {
    for (const one of made) {
      if (one.storageKey && typeof c.keepPrivate === 'function') { try { await c.keepPrivate({ publicKey: one.key.publicKey, storageKey: one.storageKey }); } catch { /* the history then starts again */ } }
      one.storageKey = null;
    }
    return made;
  }
  /// Shows the passwords the wallet made for `made` (entries of newKeys), once, before anything they seal is kept or
  /// sent; nothing when the keys are locked to this device. Only "I have them" goes on: closed any other way (made-dialog.mjs),
  /// the new keys are forgotten and the error ends the step, before anything is kept or sent.
  async function showMadeOf(name, made, why) {
    const login = made.find(m => m.record.intent === 'signin')?.made ?? null, payment = made.find(m => m.record.intent === 'spend')?.made ?? null;
    if (!login && !payment) return;
    c.setBusy(false);
    try { await c.showMade({ name, login, payment, why }); }
    catch (error) { for (const one of made) { one.key.privateKey = null; one.storageKey = null; } throw error; }
  }
  /// How the keys of "Protect my account" and of "Recover my account" are sealed (the rule), as the person chooses it
  /// (device-lock-ui.mjs, wayChoice): 'none' (the device can lock keys, and no way is chosen yet: `ready` refuses the form),
  /// 'device' (locked to this device from birth, with the passwords chosen), 'declined' (passwords the wallet makes) or
  /// 'made' (this device cannot lock keys). `prefix`: the form's ids; the fields of the chosen passwords (`chosen`, in
  /// `<prefix>-chosen`) are shown only once the lock is chosen, and emptied when it is not.
  function sealChoice(prefix, chosen, { lead = '', legendLead = '' } = {}) {
    return wayChoice(prefix, { env: () => c.env?.(), lead, legendLead, drawn: mode => { $(`${prefix}-chosen`).hidden = mode !== 'device'; if (mode !== 'device') scrub(chosen); } });
  }
  /// The fields of a new login or payment password: asked only while the keys here are locked to this device.
  function chosenFields(locked) {
    for (const [box, note] of [['replace-login-chosen', 'replace-login-made-note'], ['replace-spend-chosen', 'replace-spend-made-note'], ['removed-login-chosen', 'removed-login-made-note'], ['newlogin-chosen', 'newlogin-made-note']]) { $(box).hidden = !locked; $(note).hidden = locked; }
  }

  // ---------------------------------------------------------------- submitting
  /// Signs and submits one action of kinds 70 to 77 under the account's signing lock, after a fresh
  /// verified read. Kinds with a nonce use the account's reservation slot; protective kinds have one
  /// slot each, since nonce rules cannot retire them.
  async function sendSecurity({ label, accountId, names = [], build, beforeSubmit, afterReceipt }) {
    const check = c.capture(), networkId = net();
    return withSigningLock(navigator.locks, networkId, String(accountId), async () => {
      check();
      const state = await readState({ ids: [String(accountId)], names }); check();
      const account = state.accounts.find(a => String(a.id) === String(accountId)); assert(account, 'The account was not found.');
      const row = flows.rowOf(state, account), now = elapsedOf(state), waitsNow = waits(state);
      const built = await build({ state, account, row, now, waitsNow }); check();
      const slot = built.sequenced ? String(account.id) : protectiveSlot(built.kind, account.id);
      let old = c.pending.get(networkId, slot);
      if (old && !built.sequenced && retired(old, row, now)) { c.pending.clear(networkId, slot, old.hash); old = null; }
      assert(!old, `A signed action is still waiting for its receipt (${old?.hash || ''}). Check it before signing again.`);
      const hash = await c.sdk.transactionHash(built.tx); check();
      if (beforeSubmit) await beforeSubmit({ account, built, hash }); check();
      c.pending.put(networkId, slot, { hash, tx: b64(built.tx), nonce: built.nonce, authEpoch: built.authEpoch, kind: built.kind, label, at: Date.now(), ...(built.version ? { version: built.version } : {}) });
      c.notice(`Submitting: ${label.toLowerCase()}. Waiting for a verified receipt…`, 'busy');
      let receipt;
      try { receipt = await c.client().submit(built.tx, patience(built.kind)); }
      catch (error) { if (busyKept(error, slot, label)) error.noticeShown = true; throw error; }
      check();
      assert(receipt?.verified === true, 'No verified receipt yet. The signed action is kept; check it again later.');
      if (afterReceipt) afterReceipt(receipt);
      // Recorded (its write waited for) before the reservation is cleared, as in signing.mjs.
      await settle(slot, hash, receipt, label);
      return { receipt, built };
    });
  }
  /// `now` is the chain's time (elapsedOf), not the clock of the waits: the expiries this compares are the ones a key
  /// signed (of a freeze, of approvals), and those are dated on the chain's time on every network.
  function retired(reservation, row, now) {
    const action = c.sdk.decodeAction(fromB64(reservation.tx, 512 * 1024 + 512));
    return protectiveObsolete({ kind: action.kind, payload: action.payload, version: reservation.version }, row, now);
  }
  /// How long the same bytes may be sent again while the network is busy: the longest patience (two minutes, the SDK's
  /// BUSY.protectiveBudgetMs) for an action that protects the account; the SDK's own for any other.
  const patience = kind => (PROTECTIVE.includes(kind) && c.sdk.BUSY ? { busyBudgetMs: c.sdk.BUSY.protectiveBudgetMs } : {});
  /// An action that protects the account and that the busy network did not take: never dropped silently. The page says so
  /// in an urgent notice whose "Try again" sends the same signed bytes (the reservation of `slot`). True when said.
  function busyKept(error, slot, label) {
    if (!isBusyError(error) || typeof c.urgent !== 'function') return false;
    const item = c.pending.get(net(), slot); if (!item || !PROTECTIVE.includes(item.kind)) return false;
    c.urgent(busyProtective(label), 'Try again', async () => {
      const kept = c.pending.get(net(), slot); assert(kept, 'This action is no longer waiting: check what waits on your account, on Home.');
      try { await resend(slot, kept); } catch (again) { if (busyKept(again, slot, label)) again.noticeShown = true; throw again; }
      c.setBusy(false); await c.refresh(); c.notice(`${label}: sent and verified.`);
    });
    return true;
  }
  /// Resends the exact bytes of a reservation after checking them against its hash.
  async function resend(slot, item) {
    const tx = fromB64(item.tx, 512 * 1024 + 512);
    assert(await c.sdk.transactionHash(tx) === item.hash.toUpperCase(), 'The stored signed action is damaged. It was not sent.');
    c.setBusy(true, 'Sending the same signed action again…');
    const receipt = await c.client().submit(tx, patience(item.kind));
    assert(receipt?.verified === true, 'No verified receipt yet. The signed action is kept; check it again later.');
    await settle(slot, item.hash, receipt, item.label);
    return receipt;
  }
  async function checkReceipt(slot, item) {
    c.setBusy(true); const receipt = await c.client().waitReceipt(item.hash, { timeoutMs: 10000 });
    await settle(slot, item.hash, receipt, item.label); return receipt;
  }
  /// A verified receipt of a reservation: recorded (app.js keeps it encrypted, and its write is waited for), then the
  /// reservation is cleared. A page that closes in between keeps the reservation, and the receipt is checked again.
  async function settle(slot, hash, receipt, label) {
    try { await c.record(receipt, label); } finally { c.pending.clear(net(), slot, hash); c.cleared?.(); }
  }
  /// Keys made for an action are kept aside with what would put them on the chain, and the height
  /// at which that was seen: they leave only when the chain holds them, or on proof the action is void.
  function staging(slots, records) {
    return {
      beforeSubmit: ({ built, hash }) => stageVaults(localStorage, slots, records, built.sequenced ? { kind: built.kind, nonce: built.nonce, authEpoch: built.authEpoch, hash } : { kind: built.kind, version: built.version, expires: built.payload.expires_elapsed_micros, hash }),
      afterReceipt: receipt => stagedSeenAt(localStorage, slots, receipt.height),
    };
  }
  function settleWithProof(slots, account, row, state) {
    const promoted = settleStaged(localStorage, slots, account);
    discardStaged(localStorage, slots, account, { security: row, state });
    return promoted;
  }

  // ---------------------------------------------------------------- new recovery keys (securing, replacing them)
  /// New recovery keys of `kind` (papers.mjs): words only, or words and a recovery sheet for a Recovery Kit. Nothing is
  /// stored.
  async function makeRecoveryKeys(account, kind) {
    c.setBusy(true, 'Making your recovery keys. The keys of your recovery words take a few seconds…');
    return makePapers({ networkId: net(), accountId: account.id, argon2id: argon(), kind });
  }

  // ---------------------------------------------------------------- 1. secure my account
  // Words only (papers.mjs): five words on paper, and both recovery keys come from them. A kit can be added later under
  // "New recovery words".
  const secureSteps = paperSteps('secure', $);
  const secureSealing = sealChoice('secure', SECRET_FIELDS.secure);
  let secureDrawnFor = null;
  function resetSecure() {
    if (draft) forgetRecoveryKeys(draft);
    draft = null; scrub(SECRET_FIELDS.secure);
    secureSteps.clear(); $('secure-form').hidden = false;
  }
  $('secure-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.secure, async () => {
    // Nothing is read or made before the browser said what the device can do and, where it can lock keys, the person chose
    // a way (LOCK_WORDS.ways.asking, .pick).
    secureSealing.ready();
    const check = c.capture(), session = c.session(); assert(session, 'Unlock your wallet first.');
    const name = session.binding.name, byDevice = secureSealing.byDevice;
    const login = take('secure-login'), loginAgain = take('secure-login-confirm'), payment = take('secure-payment'), paymentAgain = take('secure-payment-confirm');
    // The passwords a person chose seal the keys only with the device (the rule); else the wallet makes them.
    if (byDevice) {
      assert(login === loginAgain, 'The two login passwords differ.'); assert(payment === paymentAgain, 'The two payment passwords differ.');
      checkPasswords({ login, payment, name });
    }
    const state = await readState(); check();
    const account = c.ownAccount(state); assert(account, 'Account not found.');
    flows.assertSigner(account, session.binding.publicKey, flows.KIND.secure);
    assert(!account.recovery_policy, 'Turn guardian recovery off before securing this account.');
    assert(!hasStaged(localStorage, vaultSlots(net(), name)), 'A change of keys from this browser is still waiting for the network. Check it under Keys first.');
    const policy = choosePolicy({ dailyLimitMicros: parseSeconds($('secure-limit').value.trim()), delayHours: $('secure-delay').value.trim(), freezeHours: $('secure-freeze').value.trim(), threshold: $('secure-threshold').value.trim(), recoveryKeys: 2, feeMicros: fee(), minDelayMicros: state.config.recovery_min_delay_micros });
    c.setBusy(true, byDevice ? 'Creating your keys and locking them to this device. This takes a few seconds…' : 'Creating your keys and their passwords. This takes a few seconds…');
    const made = await newKeysByRule({ byDevice, storage: localStorage, env: c.env?.(), wanted: [{ intent: 'signin', password: login }, { intent: 'spend', password: payment }], networkId: net(), name, argon2id: argon(), say: text => c.notice(text, 'busy') });
    check(); const [signin, spend] = made.keys;
    const recovery = await makeRecoveryKeys(account, 'words'); check();
    if (!made.locked) {
      try { await showMadeOf(name, made.keys, made.fallback ?? 'The wallet made the passwords of your protected account. Let your browser save the login password; write the payment password down, apart from your recovery words.'); }
      catch (error) { forgetRecoveryKeys(recovery); throw error; }
      check();
    }
    await kept(made.keys);
    draft = { name, accountId: String(account.id), policy, signin: signin.key, spend: spend.key, records: { signin: signin.record, spend: spend.record }, ...recovery };
    $('secure-form').hidden = true; secureSteps.show(draft);
    c.notice(WRITE_NOW);
  }); });
  $('secure-cancel').addEventListener('click', () => { resetSecure(); c.notice('Nothing was changed. Your new keys and recovery words were discarded: destroy the paper if you wrote them down.'); });
  $('secure-submit').addEventListener('click', () => c.run(async () => {
    assert(draft, 'Start again from the beginning.');
    const check = c.capture(), session = c.session(), current = draft;
    const state = await readState(); check(); const account = c.ownAccount(state);
    const others = account.devices.filter(d => d.public_key !== session.binding.publicKey).length, exposure = limitExposure(current.policy.daily_limit_micros);
    if (!await c.review('Protect my account', [
      ['Account', '@' + current.name],
      ['Login', 'This browser signs in with a new login key, under your login password.'],
      ['Payments', `Up to ${seconds(exposure.atOnce)} at once with your payment password, fees included. The limit refills over 24 hours, so up to about ${seconds(exposure.within24h)} can leave in any 24 hours. More waits ${duration(current.policy.delay_seconds)}, or needs a recovery paper too.`],
      ['Recovery', `Your recovery words, on paper: both recovery keys come from them. They replace lost keys after ${duration(current.policy.delay_seconds)}, and whoever has the paper can ask for that too: it waits, frozen, and only your recovery words can stop it. Keep two copies in different places.`],
      ['Freeze', `Your payment password or your recovery words freeze the account for ${duration(current.policy.freeze_seconds)}.`],
      ['Other devices', others ? `${others} other device${others === 1 ? '' : 's'} of this account will lose access.` : 'None.'],
      ['Guardian recovery', 'Not used once the account is protected.'],
      ['Your backup file of today', 'Stops working: the key in it leaves the account.'],
      ['Fee', seconds(fee())],
    ], 'Protect my account')) return;
    check(); c.setBusy(true, 'Securing your account…');
    const slots = vaultSlots(net(), current.name);
    const result = await sendSecurity({ label: 'Secure account', accountId: current.accountId, build: ({ account }) => flows.buildSecure({
      networkId: net(), account, fullKey: { publicKey: session.binding.publicKey, privateKey: session.privateKey },
      signin: current.signin, spend: current.spend, recovery: [current.sheet, current.phrase], policy: current.policy, feeMicros: fee(),
    }), ...staging(slots, current.records) });
    check();
    const after = await readState(); check();
    settleStaged(localStorage, slots, c.ownAccount(after));
    // Keys says what words only means for this account (security-flows.mjs, recoveryKindOf).
    rememberRecoveryKind(localStorage, net(), current.name, current);
    resetSecure();
    // The protocol-4 key is on no account now. Locking forgets it; its vault was replaced by the login key's.
    c.lock(result ? 'Your account is protected. Open it with your login password.' : 'Open your account with your login password.');
  }));

  // ---------------------------------------------------------------- 3. pay
  // Every review of a payment to a name hands that name to the review (`payee`): the page then says whether this
  // account has paid it from this browser before, and warns of a name that looks like one it has (app.js, payeeLines).
  async function pay({ name, to, amount, state, account }) {
    try {
      const row = flows.rowOf(state, account), now = waits(state);
      const choice = flows.choosePayment({ security: row, now, amount, feeMicros: fee(), balance: account.balance });
      if (choice.mode === 'blocked') throw new Error(choice.reason);
      if (choice.mode === 'over' || choice.mode === 'frozen') {
        overDraft = { name, to: String(to.id), amount: String(amount), accountId: String(account.id), waitPossible: choice.waitPossible };
        $('send-over-detail').textContent = choice.mode === 'frozen'
          ? `${seconds(amount)} to @${name}. Your account is frozen, so your payment password alone cannot pay, and nothing can wait. Your payment password with one recovery key can still pay.`
          : `${seconds(amount)} to @${name}, plus the fee of ${seconds(fee())}. You can pay ${seconds(choice.allowance)} more today with your payment password alone.`;
        $('send-wait-note').textContent = choice.waitPossible ? `It waits ${duration(row.policy.delay_seconds)}, then you send it from Home, under “Waiting on your account”. Until then you can cancel it.` : choice.waitReason;
        $('send-over-limit').hidden = false;
        c.notice(choice.mode === 'frozen' ? 'Your account is frozen. Choose below, or see Home.' : 'This payment is above what you can pay today. Choose how to pay it below.');
        return;
      }
      if (!await c.review('Send seconds', [['To', `@${name} · account ${to.id}`], ['Amount', seconds(amount)], ['Fee', seconds(fee())], ['Total', seconds(choice.total)], ['Left to pay today after this', seconds(choice.allowance - choice.total)]], undefined, { payee: name })) { scrub(['send-payment']); return; }
      await withSpend(take('send-payment'), c.session().binding.name, signer => c.sendSigned('transfer', { to: String(to.id), amount: String(amount) }, `Send ${c.seconds(amount)} s to @${name}`, { signer }));
      await c.refresh(); $('amount').value = '';
      sent(name, amount);
    } catch (error) { scrub(['send-payment', 'send-recovery-secret']); throw error; }
  }
  /// "Sent": where the page shows it (app.js, showSent), or in the notice.
  function sent(name, amount) { if (typeof c.sent === 'function') c.sent(name, c.seconds(amount)); else c.notice(sentNotice(name, c.seconds(amount))); }
  function hideOver() { overDraft = null; $('send-over-limit').hidden = true; scrub(['send-recovery-secret']); }
  $('send-over-cancel').addEventListener('click', () => { hideOver(); scrub(['send-payment']); c.notice('Nothing was sent.'); });
  $('send-wait').addEventListener('click', () => guarded(['send-payment', 'send-recovery-secret'], async () => {
    const pay = overDraft; assert(pay, 'Enter the payment again.');
    const check = c.capture(), state = await readState({ ids: [pay.to] }); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account), now = waits(state), ready = dated(state, now + BigInt(row.policy.delay_seconds) * 1000000n);
    if (!await c.review('Pay after the waiting period', [['Recipient', `@${pay.name} · account ${pay.to}`], ['Amount', seconds(pay.amount)], ['Waits', ready.later ? `${duration(row.policy.delay_seconds)}: it can be sent not before ${ready.date.toLocaleString()}` : `${duration(row.policy.delay_seconds)}, until about ${ready.date.toLocaleString()}`], ['Then', 'Send it from Home, under “Waiting on your account”. Until then it can be cancelled.'], ['Fee', `${seconds(fee())} now, and the same again when it is sent`]], 'Sign waiting payment', { payee: pay.name })) return;
    await withSpend(take('send-payment'), c.session().binding.name, spend => sendSecurity({ label: `Waiting payment of ${c.seconds(pay.amount)} s to @${pay.name}`, accountId: pay.accountId, build: ({ account }) => flows.buildWaitingPayment({ networkId: net(), account, spend, to: pay.to, amount: pay.amount }) }));
    hideOver(); $('amount').value = ''; await c.refresh();
    c.notice(`Your payment is waiting. You can send it from Home after ${duration(row.policy.delay_seconds)}. The other person gets nothing until then.`);
  }));
  $('send-now').addEventListener('click', () => guarded(['send-payment', 'send-recovery-secret'], async () => {
    const pay = overDraft; assert(pay, 'Enter the payment again.');
    const check = c.capture(), state = await readState({ ids: [pay.to] }); check();
    const account = c.ownAccount(state);
    if (!await c.review('Pay now with a recovery paper', [['To', `@${pay.name} · account ${pay.to}`], ['Amount', seconds(pay.amount)], ['Fee', seconds(fee())], ['Total', seconds(BigInt(pay.amount) + BigInt(fee()))], ['Approved by', 'Your payment password and one recovery paper']], 'Pay now', { payee: pay.name })) return;
    const password = take('send-payment');
    const recovery = await takeRecovery('send-recovery-secret', account); check();
    try {
      await withSpend(password, c.session().binding.name, spend => sendSecurity({ label: `Send ${c.seconds(pay.amount)} s to @${pay.name} with a recovery proof`, accountId: pay.accountId, build: ({ account, row, now }) => flows.buildPayNow({ networkId: net(), account, security: row, spend, recovery, to: pay.to, amount: pay.amount, now }) }));
    } finally { recovery.privateKey = null; }
    hideOver(); $('amount').value = ''; await c.refresh();
    sent(pay.name, pay.amount);
  }));
  /// A website payment from a secured account: within today's allowance, with the payment password.
  async function payWebsite({ request: r, origin, account, state, recipient }) {
    try {
      const row = flows.rowOf(state, account), now = waits(state);
      const choice = flows.choosePayment({ security: row, now, amount: r.amount, feeMicros: fee(), balance: account.balance });
      assert(choice.mode !== 'blocked' && choice.mode !== 'frozen', choice.reason);
      assert(choice.mode === 'transfer', `This payment is more than you can pay today with your payment password (${seconds(choice.allowance)} left, fees included). Ask the website for a smaller amount, or pay later.`);
      if (!await c.review('Approve website payment', [['Website', origin], ['Order', r.orderId], ['Recipient', `@${recipient.name} · account ${recipient.id}`], ['Amount', seconds(r.amount)], ['Fee', seconds(fee())], ['Total', seconds(choice.total)], ['Left to pay today after this', seconds(choice.allowance - choice.total)]], 'Pay & sign', { payee: recipient.name })) return null;
      return await withSpend(take('approval-payment'), c.session().binding.name, signer => c.sendSigned('merchant_payment', { to: r.to, amount: r.amount, reference: r.orderId }, `Website payment ${r.orderId}`, { merchantOrigin: origin, signer }));
    } finally { scrub(['approval-payment']); }
  }
  /// Why the sign-in key may not sign a website login now (the website applies the same rule).
  function loginRefusal(state, account) {
    if (!secured(state, account)) return null;
    return security.signInRefusal({ account, security: security.securityOf(state, account.id), publicKey: c.session().binding.publicKey, nowElapsedMicros: waits(state).toString() });
  }

  // ---------------------------------------------------------------- 3b. stake with the payment key
  /// Delegation from the Earn tab of a secured account: signed by the spend key, within today's limit.
  async function stake({ operator, amount, quotedShares, state, account }) {
    try {
      hideStakeOver();
      const row = flows.rowOf(state, account);
      const check = flows.checkStake({ security: row, now: waits(state), outflowMicros: stakeOutflow('delegate', { amount: String(amount) }, fee()), feeMicros: fee(), balance: account.balance });
      if (check.mode === 'frozen' || check.mode === 'blocked') throw new Error(check.reason);
      if (check.mode === 'over') return showStakeOver(check, row);
      if (!await c.review('Delegate seconds', [['Operator account', operator], ['Amount', seconds(amount)], ['Current share estimate', quotedShares + ' shares; priced at pool NAV when finalized'], ['Fee', seconds(fee())], ['Left of today\'s limit after this', seconds(check.allowance - check.total)], ['Signed by', 'Your payment key, with your payment password'], ['Availability', 'Voting power removal at H+2 followed by the full 14-day slash window.']], 'Stake & sign')) return;
      await withSpend(take('stake-payment'), account.name, signer => c.sendSigned('delegate', { operator, amount: String(amount), min_shares: '1' }, 'Delegate seconds', { signer }));
      $('stake-amount').value = ''; await c.refresh(); c.notice('Delegation finalized. Pool shares are now bonded.');
    } finally { scrub(['stake-payment']); }
  }
  /// What an action of pos-ui.mjs does to the daily limit of a secured account, by a verified state: the review's line,
  /// or why it cannot be signed now (protection.mjs, validatorLimit). Compared on the clock of the waits.
  function limitOf(kind, payload, state) {
    const account = c.ownAccount(state), row = flows.rowOf(state, account);
    assert(row, 'This account is not secured.');
    const now = waits(state), bondMicros = kind === 'register_validator' && payload.self_bond === undefined ? minSelfBond(state) : undefined;
    const check = flows.checkStake({ security: row, now, outflowMicros: stakeOutflow(kind, payload, fee(), { bondMicros }), feeMicros: fee(), balance: account.balance });
    return { account, ...validatorLimit({ kind, check, row, now, words: words(state) }) };
  }
  /// Asked by pos-ui.mjs before its review (Validator operator; and unbonding and withdrawing in Staking): the review's
  /// lines for a secured account, or the refusal in words, before anything is unlocked or signed.
  async function stakeLimit(kind, payload) {
    assertSpendKeyKind(kind);
    const check = c.capture(), state = await readState(); check();
    const said = limitOf(kind, payload, state);
    assert(!said.refusal, said.refusal);
    return [['Daily limit', said.line], ['Signed by', 'Your payment key, with your payment password']];
  }
  /// Staking and the operation of a validator, reviewed by pos-ui.mjs first, signed by the payment key. Nothing outside the
  /// spend-key list gets here. The payment password is read from the field of the screen the action came from: the
  /// Validator operator's (`payment: 'validator-payment'`) or Staking's.
  async function stakeAction(kind, payload, label, { payment } = {}) {
    const field = payment === 'validator-payment' ? 'validator-payment' : 'stake-payment';
    try {
      assertSpendKeyKind(kind);
      const check = c.capture(), state = await readState(); check();
      const said = limitOf(kind, payload, state);
      assert(!said.refusal, said.refusal);
      return await withSpend(take(field), said.account.name, signer => c.sendSigned(kind, payload, label, { signer }));
    } finally { scrub([field]); }
  }
  // ---------------------------------------------------------------- 3c. a validator's upgrade signal with the payment key
  /// Why a secured account cannot send an upgrade signal now (frozen, or the fee does not fit
  /// today's limit), or null. Asked by upgrade-signal-ui.mjs before it shows a review.
  async function signalRefusal() {
    const check = c.capture(), state = await readState(); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account);
    assert(row, 'This account is not secured.');
    const result = flows.checkSignal({ security: row, now: waits(state), feeMicros: fee(), balance: account.balance });
    return result.mode === 'ok' ? null : result.reason;
  }
  /// Signs an upgrade signal (reviewed by upgrade-signal-ui.mjs first) with the spend key. The
  /// payment password is read from the tab's own field and used for this one action.
  async function signalAction(payload, label) {
    try {
      const refusal = await signalRefusal(); assert(!refusal, refusal);
      return await withSpend(take('signal-payment'), c.session().binding.name, signer => c.sendSigned(SIGNAL_KIND, payload, label, { signer }));
    } finally { scrub(['signal-payment']); }
  }
  function showStakeOver(check, row) {
    const whole = ((check.total + 999999n) / 1000000n) * 1000000n;
    stakeOver = { fitsToday: check.fitsToday, suggestedLimit: whole > check.dailyLimit ? whole : check.dailyLimit };
    $('stake-over-detail').textContent = `This stake and its fee need ${seconds(check.total)} of your daily limit. ${seconds(check.allowance)} is left today, and your limit is ${seconds(check.dailyLimit)} a day. You can raise the limit (a higher limit applies after ${duration(row.policy.delay_seconds)}), or stake a part now and the rest on later days.`;
    $('stake-over-limit').hidden = false;
    c.notice('This stake is more than your daily limit allows today. Choose below.');
  }
  function hideStakeOver() { stakeOver = null; $('stake-over-limit').hidden = true; }
  $('stake-fit-today').addEventListener('click', () => {
    if (!stakeOver || stakeOver.fitsToday <= 0n) return;
    $('stake-amount').value = c.seconds(stakeOver.fitsToday); hideStakeOver();
    c.notice('The amount now fits today\'s limit. Review it, and stake the rest on later days.');
  });
  $('stake-raise-limit').addEventListener('click', () => {
    if (!stakeOver) return;
    $('limit-amount').value = c.seconds(stakeOver.suggestedLimit); hideStakeOver();
    c.showPanel?.('home'); openStep('limit-form', 'limit-payment'); sayLimitChange();
    c.notice('On Home, under Protection, “Daily limit”: enter your payment password to ask for this higher limit. It applies after your waiting period, and you can cancel it meanwhile.');
  });
  $('stake-over-cancel').addEventListener('click', () => { hideStakeOver(); scrub(['stake-payment']); c.notice('Nothing was staked.'); });
  /// Keys, with its part "Change something" open: where the replacements of keys and papers are.
  function showChange() { $('tab-security').click?.(); $('keys-change').open = true; }

  // ---------------------------------------------------------------- 4. freeze
  // Freeze with the payment password or the recovery words (a printed sheet works too): the one choice left of a form.
  $('freeze-method').addEventListener('change', () => { $('freeze-paper-note').hidden = $('freeze-method').value !== 'paper'; $('freeze-secret').value = ''; });
  $('freeze-form').addEventListener('submit', event => { event.preventDefault(); guarded(['freeze-secret'], async () => {
    const check = c.capture(), state = await readState(); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account), method = $('freeze-method').value;
    flows.freezePayload({ security: row, now: elapsedOf(state), waitsNow: waits(state) });
    const lasts = duration(row.policy.freeze_seconds);
    if (!await c.review('Freeze account', [['Account', '@' + account.name], ['Effect', `No payment with your payment password alone and no sign-in to websites for ${lasts}. Anything waiting is dropped.`], ['Ends', `By itself after ${lasts}, or earlier with your payment password and one recovery paper. It is not renewed by itself: to keep the account frozen longer, freeze again in the second half of the freeze.`], ['Still possible', 'Your payment password with a recovery paper can pay. Seconds sent to you arrive.'], ['Fee', seconds(fee())]], 'Freeze account')) return;
    const secret = take('freeze-secret');
    const run = signer => sendSecurity({ label: 'Freeze account', accountId: account.id, build: ({ account, row, now, waitsNow }) => flows.buildFreeze({ networkId: net(), account, security: row, signer, now, waitsNow }) });
    if (method === 'payment') await withSpend(secret, account.name, run);
    else { const key = await recoveryPaper(secret, account); try { await run(key); } finally { key.privateKey = null; } }
    closeSteps(); await c.refresh(); c.notice('Your account is frozen. If you did not lose a device, replace the key that leaked.');
  }); });
  $('unfreeze-form').addEventListener('submit', event => { event.preventDefault(); guarded(['unfreeze-payment', 'unfreeze-secret'], async () => {
    const check = c.capture(), state = await readState(); check();
    const account = c.ownAccount(state);
    if (!await c.review('Unfreeze account', [['Account', '@' + account.name], ['Approved by', 'Your payment password and one recovery key'], ['Remember', 'The key that froze the account can freeze it again. If you did not freeze it, replace your keys.'], ['Fee', seconds(fee())]], 'Unfreeze')) return;
    const password = take('unfreeze-payment');
    const recovery = await takeRecovery('unfreeze-secret', account); check();
    try { await withSpend(password, account.name, spend => sendSecurity({ label: 'Unfreeze account', accountId: account.id, build: ({ account, row, now, waitsNow }) => flows.buildUnfreeze({ networkId: net(), account, security: row, spend, recovery, now, waitsNow }) })); }
    finally { recovery.privateKey = null; }
    closeSteps(); await c.refresh(); c.notice('Your account is no longer frozen.');
  }); });

  // ---------------------------------------------------------------- 4b. the Protection card on Home (protection.mjs)
  // A switch shows what proven state says, never what was pressed. A press puts the switch back at once and opens the
  // small step that asks for what the chain needs for it; the switch moves when a verified state shows the change.
  function hideStep(id) { if (!$(id).hidden) { $(id).hidden = true; scrub(STEPS[id]); } }
  const closeSteps = () => { for (const id of Object.keys(STEPS)) hideStep(id); };
  function openStep(id, focus) { for (const other of Object.keys(STEPS)) if (other !== id) hideStep(other); $(id).hidden = false; $(focus).focus?.(); }
  /// The payments and the changes that wait, counted from the same list "Waiting on your account" shows.
  function waitingOf(account, row, now) {
    const events = flows.inboxEvents({ account, security: row, now });
    return { payments: events.filter(e => e.type === 'payment').length, changes: events.filter(e => e.type === 'limit' || e.type === 'replacement').length };
  }
  function viewOf(account, row, state) {
    const now = waits(state);
    return protectionView({ row, now, feeMicros: fee(), allowance: security.allowance(row, now), frozen: security.frozen(row, now), waiting: waitingOf(account, row, now), words: words(state) });
  }
  const put = (id, text) => { const el = $(id); if (el.textContent !== text) el.textContent = text; };
  function drawCard(view, row) {
    put('protect-status', view.status.text); $('protect-status').className = view.status.alert ? 'protect-status warning' : 'protect-status';
    $('freeze-switch').checked = view.freeze.on; put('freeze-switch-state', view.freeze.state); put('freeze-note', view.freeze.note);
    $('freeze-more').hidden = !view.freeze.byFreeze; $('freeze-again').hidden = !view.freeze.canRenew; put('freeze-again', `Freeze for another ${view.freeze.lasts}`);
    put('freeze-step-note', `Freezes the account for ${view.freeze.lasts}${view.freeze.byFreeze ? ' from now' : ''}. Your payment password with a recovery paper can still pay, and can end the freeze early. Seconds sent to you still arrive.`);
    $('limit-bar').value = view.limit.perMille; put('limit-text', view.limit.text); $('limit-open').hidden = view.pause.on;
    $('pause-switch').checked = view.pause.on; put('pause-switch-state', view.pause.state); put('pause-note', view.pause.note);
    put('pause-step-note', `Sets your daily limit to ${seconds(fee())}, the fee of one action, at once: nothing can be paid at once. A payment started while paused waits ${duration(row.policy.delay_seconds)} and you can cancel it. Ending the pause waits ${duration(row.policy.delay_seconds)} too, or needs a recovery paper, and what you can pay at once then fills up again over 24 hours. Seconds sent to you still arrive.`);
    put('resume-wait-note', view.pause.waitNote); put('protect-waiting', view.waiting);
    // A step whose question proven state has answered meanwhile is closed.
    if (view.freeze.on && !view.freeze.canRenew) hideStep('freeze-form');
    if (!view.freeze.canEnd) hideStep('unfreeze-form');
    if (!view.limit.canChange) hideStep('limit-form');
    if (view.pause.on || view.pause.locked) hideStep('pause-form');
    if (!view.pause.on || view.pause.locked) hideStep('resume-step');
  }
  $('freeze-switch').addEventListener('change', () => {
    $('freeze-switch').checked = Boolean(card?.freeze.on);
    if (!card || card.freeze.locked) return;
    if (!card.freeze.on) openStep('freeze-form', 'freeze-secret'); else openStep('unfreeze-form', 'unfreeze-payment');
  });
  $('freeze-again').addEventListener('click', () => openStep('freeze-form', 'freeze-secret'));
  $('unfreeze-open').addEventListener('click', () => openStep('unfreeze-form', 'unfreeze-payment'));
  $('pause-switch').addEventListener('change', () => {
    $('pause-switch').checked = Boolean(card?.pause.on);
    if (!card || card.pause.locked) return;
    if (!card.pause.on) return openStep('pause-form', 'pause-payment');
    // Ending a pause: back to the limit the account had before it, if this browser remembers it; else the person says.
    const remembered = rememberedLimit(localStorage, pauseKey(net(), c.session().binding.name));
    if (!$('resume-amount').value && remembered !== null) $('resume-amount').value = c.seconds(remembered);
    $('resume-amount-note').textContent = remembered === null ? 'This browser does not remember the limit you had before the pause. Enter the limit you want.' : `Your limit before the pause, as this browser remembers it: ${seconds(remembered)}. Change it if you like.`;
    openStep('resume-step', remembered === null ? 'resume-amount' : 'resume-payment');
  });
  $('limit-open').addEventListener('click', () => { openStep('limit-form', 'limit-amount'); sayLimitChange(); });
  for (const id of ['freeze-cancel', 'unfreeze-cancel', 'limit-cancel', 'pause-cancel', 'resume-cancel']) $(id).addEventListener('click', closeSteps);
  $('pause-form').addEventListener('submit', event => { event.preventDefault(); guarded(['pause-payment'], async () => {
    const check = c.capture(), state = await readState(); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account), now = waits(state), key = pauseKey(net(), account.name);
    assert(pauseState(row, now, fee()) === 'off', 'Payments are paused already.');
    assert(!security.frozen(row, now), 'The account is frozen: nothing can be paid at once, paused or not.');
    assert(security.allowance(row, now) >= BigInt(fee()), 'Pausing costs the network fee, and less than that is left of your daily limit right now. Freeze the account instead, or try again later.');
    if (!await c.review('Pause payments', pauseReview({ row, now, feeMicros: fee(), words: words(state) }), 'Pause payments')) return;
    let before = null;
    await withSpend(take('pause-payment'), account.name, spend => sendSecurity({ label: 'Pause payments', accountId: account.id,
      build: ({ account, row, now, waitsNow }) => { before = effectiveLimit(row, waitsNow); return flows.buildPause({ networkId: net(), account, security: row, spend, feeMicros: fee(), now, waitsNow }); },
      // The limit of this moment is remembered before anything is sent: a lost receipt loses nothing.
      beforeSubmit: () => { rememberLimit(localStorage, key, before, Date.now()); } }));
    closeSteps(); await c.refresh();
    c.notice(`Payments are paused. A payment started now waits ${duration(row.policy.delay_seconds)} and you can cancel it.`);
  }); });
  /// A daily limit set at once with the payment password and one recovery paper (flows.buildLimitNow): how a pause is
  /// ended without waiting, and how a limit is raised without waiting. True once it is signed and in a block.
  async function limitNow({ account, row, state, amount, title, confirm, label, passwordId, secretId }) {
    const check = c.capture(), now = waits(state);
    assert(!security.frozen(row, now), 'The account is frozen. End the freeze first.');
    assert(BigInt(amount) > BigInt(fee()), 'Choose a daily limit above the network fee.');
    if (!await c.review(title, limitNowReview({ row, now, limitMicros: amount, allowance: security.allowance(row, now), feeMicros: fee(), waiting: waitingOf(account, row, now), words: words(state) }), confirm)) return false;
    const password = take(passwordId);
    const recovery = await takeRecovery(secretId, account); check();
    try { await withSpend(password, account.name, spend => sendSecurity({ label, accountId: account.id, build: ({ account, row, now, waitsNow }) => flows.buildLimitNow({ networkId: net(), account, security: row, spend, recovery, dailyLimitMicros: amount, feeMicros: fee(), now, waitsNow }) })); }
    finally { recovery.privateKey = null; }
    return true;
  }
  $('resume-wait').addEventListener('click', () => guarded(STEPS['resume-step'], async () => {
    const check = c.capture(), amount = parseSeconds($('resume-amount').value.trim()), state = await readState(); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account), now = waits(state), view = viewOf(account, row, state);
    assert(view.pause.on, 'Payments are not paused.');
    assert(view.pause.waitPossible, view.pause.waitNote);
    assert(BigInt(amount) > BigInt(fee()), 'Choose a daily limit above the network fee.');
    if (!await c.review('End the pause after the waiting period', resumeWaitReview({ row, now, limitMicros: amount, feeMicros: fee(), words: words(state) }), 'Ask for my limit back')) return;
    await withSpend(take('resume-payment'), account.name, spend => sendSecurity({ label: 'End the pause after the waiting period', accountId: account.id, build: ({ account, row, now, waitsNow }) => flows.buildLimit({ networkId: net(), account, security: row, spend, dailyLimitMicros: amount, feeMicros: fee(), now, waitsNow }) }));
    $('resume-amount').value = ''; closeSteps(); await c.refresh();
    c.notice(`Your limit comes back after ${duration(row.policy.delay_seconds)}. Until then payments stay paused. You can cancel this under “Waiting on your account”.`);
  }));
  $('resume-now').addEventListener('click', () => guarded(STEPS['resume-step'], async () => {
    const check = c.capture(), amount = parseSeconds($('resume-amount').value.trim()), state = await readState(); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account);
    assert(pauseState(row, waits(state), fee()) !== 'off', 'Payments are not paused.');
    if (!await limitNow({ account, row, state, amount, title: 'End the pause now with a recovery paper', confirm: 'End the pause now', label: 'End the pause with a recovery proof', passwordId: 'resume-payment', secretId: 'resume-secret' })) return;
    forgetLimit(localStorage, pauseKey(net(), account.name));
    $('resume-amount').value = ''; closeSteps(); await c.refresh();
    c.notice(`Payments are no longer paused. Your daily limit is ${seconds(amount)}. What you can pay at once fills up over 24 hours.`);
  }));

  // ---------------------------------------------------------------- 5. inbox
  // A waiting payment names an account by its number only. Its name is read with a proof (`ids`) before it is shown: on
  // the list on Home once, and again for the review of "Send now", which checks it like every payment to a name (the
  // payee check, with the tick for a look-alike). Whether it was started in this browser is what this browser's own
  // record says (app.js, its activity: the label of the waiting payment it signed), and nothing else (web audit, W-5).
  const payeeNames = new Map(), namesTried = new Set(); let namesAsked = null;
  const knownName = (id, state) => state?.accounts?.find(a => String(a.id) === String(id))?.name ?? payeeNames.get(String(id)) ?? null;
  const waitingLabel = (amount, name) => `Waiting payment of ${c.seconds(amount)} s to @${name}`;
  const startedHere = (e, name) => name !== null && c.sentHere?.(waitingLabel(e.amount, name)) === true;
  /// The names of the accounts that waiting payments go to and that the list does not know yet: each asked once on this
  /// page, with a proof. The list is drawn again when a name was learned.
  function askNames(ids) {
    const asked = ids.filter(id => !namesTried.has(id)).slice(0, 8);
    if (namesAsked || !asked.length) return;
    for (const id of asked) namesTried.add(id);
    namesAsked = readState({ ids: asked }).then(state => {
      let learned = false;
      for (const a of state.accounts || []) if (asked.includes(String(a.id))) { payeeNames.set(String(a.id), a.name); learned = true; }
      const account = c.ownAccount(c.state()), row = learned && account ? flows.rowOf(c.state(), account) : null;
      if (row) renderInbox(account, row, c.state());
    }).catch(() => {}).finally(() => { namesAsked = null; });
  }
  async function inboxSigner(account, { spendOnly = false } = {}) {
    const password = take('inbox-payment'), secret = take('inbox-secret');
    if (password) return { signer: await unlockSpend(password, account.name) };
    assert(!spendOnly, 'Enter your payment password.');
    return { signer: await recoveryPaper(secret, account) };
  }
  async function actOnEvent(event) {
    try {
      const check = c.capture(), state = await readState(event.type === 'payment' ? { ids: [String(event.to)] } : {}); check();
      const account = c.ownAccount(state), row = flows.rowOf(state, account);
      const fresh = flows.inboxEvents({ account, security: row, now: waits(state) }).find(e => e.type === event.type && e.id === event.id);
      assert(fresh, 'This item is no longer waiting.');
      if (event.action === 'execute') {
        const recipient = state.accounts.find(a => String(a.id) === String(fresh.to));
        assert(recipient, 'The account this payment goes to could not be read. Try again.');
        payeeNames.set(String(recipient.id), recipient.name);
        const here = startedHere(fresh, recipient.name);
        if (!await c.review('Send waiting payment', [['Recipient', `@${recipient.name} · account ${fresh.to}`], ['Amount', seconds(fresh.amount)], ['Started', here ? 'In this browser' : 'Not in this browser. Send it only if you started it on another device.'], ['Fee', seconds(fee())]], 'Send payment', { payee: recipient.name })) return;
        const { signer } = await inboxSigner(account, { spendOnly: true });
        try { await sendSecurity({ label: `Send waiting payment ${fresh.id}`, accountId: account.id, build: ({ account }) => flows.buildExecute({ networkId: net(), account, spend: signer, id: fresh.id }) }); } finally { signer.privateKey = null; }
        await c.refresh(); return c.notice('The waiting payment was sent and verified.');
      }
      if (fresh.type === 'replacement') {
        if (!await c.review('Cancel the change of keys', [['Effect', 'Your keys stay as they are and the account is no longer frozen by it.'], ['Approved by', 'Your payment password and one recovery key'], ['Then', 'Whoever started it has your recovery words and can ask again. Make new recovery words next, under Keys, “Change something”: that is what stops it.'], ['Fee', seconds(fee())]], 'Cancel change')) return;
        const password = take('inbox-payment');
        const recovery = await takeRecovery('inbox-secret', account); check();
        try { await withSpend(password, account.name, spend => sendSecurity({ label: 'Cancel change of keys', accountId: account.id, build: ({ account, row, now }) => flows.buildCancelReplacement({ networkId: net(), account, security: row, approvers: [spend, recovery], now }) })); }
        finally { recovery.privateKey = null; }
        await c.refresh(); return c.notice('The change of keys was cancelled. Whoever started it has your recovery words and can ask again: make new recovery words now, under Keys, “Change something”.');
      }
      const to = fresh.type === 'payment' ? knownName(fresh.to, state) : null;
      const what = fresh.type === 'payment' ? `Payment of ${seconds(fresh.amount)} to ${to ? `@${to} · ` : ''}account ${fresh.to}` : `Raise of the daily limit to ${seconds(fresh.dailyLimit)}`;
      if (!await c.review('Cancel waiting item', [['Item', what], ['Fee', seconds(fee())]], 'Cancel it')) return;
      const { signer } = await inboxSigner(account);
      try { await sendSecurity({ label: `Cancel ${fresh.type === 'payment' ? 'waiting payment' : 'limit raise'} ${fresh.id}`, accountId: account.id, build: ({ account }) => flows.buildCancel({ networkId: net(), account, signer, event: fresh }) }); }
      finally { signer.privateKey = null; }
      await c.refresh(); c.notice('Cancelled and verified.');
    } finally { scrub(['inbox-payment', 'inbox-secret']); }
  }
  function inboxRow(title, detail, buttons = [], warn = false) {
    const r = node('div', '', 'row' + (warn ? ' alert' : '')), copy = node('div', ''); copy.append(node('strong', title)); if (detail) copy.append(node('small', detail)); r.append(copy);
    for (const [label, handler] of buttons) { const b = node('button', label, 'secondary'); b.type = 'button'; b.dataset.securityAction = 'true'; b.addEventListener('click', () => c.run(handler)); r.append(b); }
    return r;
  }
  function renderInbox(account, row, state) {
    const now = waits(state), when = (at, word) => timeWords(state, at, word);
    const events = flows.inboxEvents({ account, security: row, now, ownKeys: [c.session().binding.publicKey] });
    $('security-inbox').replaceChildren(); inboxRows = events;
    let actionable = false;
    for (const e of events) {
      if (e.type === 'payment') {
        actionable = true;
        const name = knownName(e.to, state), started = startedHere(e, name) ? ' Started in this browser.' : '';
        $('security-inbox').append(inboxRow(`Waiting payment: ${seconds(e.amount)} to ${name ? `@${name} · ` : ''}account ${e.to}`, (e.readyNow ? 'Ready to send.' : `Can be sent ${when(e.ready, 'after')} (${roughly(e.ready - now)}).`) + started, [...(e.readyNow ? [['Send now', () => actOnEvent({ ...e, action: 'execute' })]] : []), ['Cancel', () => actOnEvent(e)]], true));
      }
      if (e.type === 'limit') { actionable = true; $('security-inbox').append(inboxRow(`Waiting raise of the daily limit to ${seconds(e.dailyLimit)}`, `Applies ${when(e.ready, 'at')} (${roughly(e.ready - now)}).`, [['Cancel', () => actOnEvent(e)]], true)); }
      if (e.type === 'replacement') {
        actionable = true;
        $('security-inbox').append(inboxRow('Waiting change of all your keys', `${e.keys.filter(k => !k.known).length} new key(s). The account is frozen. ${e.readyNow ? 'The waiting period is over: the new keys can take over now.' : `It can finish ${when(e.ready, 'after')} (${roughly(e.ready - now)}).`} If you did not start this, make new recovery words now, under Keys, “Change something”: it needs your payment password and your recovery words, it ends this change at once, and the words that were used stop working. Cancelling it here needs the same, but whoever started it keeps your words and can ask again. Without your recovery words you cannot stop this.`,
          [['Make new recovery words', () => startReplaceRecovery()], ['Cancel', () => actOnEvent(e)]], true));
      }
      // Whether the account is frozen, and until when, is said by the Protection card above this list.
      if (e.type === 'signin') $('security-inbox').append(inboxRow(e.mine ? 'Login key of this browser' : 'Login key of another device', e.publicKey));
    }
    $('inbox-keys').hidden = !actionable;
    askNames([...new Set(events.filter(e => e.type === 'payment' && knownName(e.to, state) === null).map(e => String(e.to)))]);
  }
  function pendingRows(accountId, row, state, kinds) {
    const rows = [];
    for (const kind of kinds) {
      const slot = protectiveSlot(kind, accountId); let item;
      try { item = c.pending.get(net(), slot); } catch (error) { rows.push(node('p', error.message, 'subtle')); continue; }
      if (!item) continue;
      if (retired(item, row, elapsedOf(state))) { c.pending.clear(net(), slot, item.hash); continue; }
      rows.push(inboxRow(`${item.label || LABEL[kind]}: waiting for its receipt`, item.hash, [
        ['Check receipt', async () => { await checkReceipt(slot, item); await afterPending(); c.notice('Verified.'); }],
        ['Send again', async () => { await resend(slot, item); await afterPending(); c.notice('Verified.'); }],
      ]));
    }
    return rows;
  }
  const afterPending = () => lostProgress && !c.session() ? renderLost(lostProgress) : c.refresh();

  // ---------------------------------------------------------------- 6. replace a stolen login
  $('replace-login-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.replaceLogin, async () => {
    const check = c.capture(), session = c.session(), name = session.binding.name, locked = lockedHere(name);
    const login = take('replace-login-new'), again = take('replace-login-confirm'), password = take('replace-login-payment');
    // A login password the person chooses only with the device (the rule); else the wallet makes it.
    if (locked) { assert(login === again, 'The two login passwords differ.'); checkPasswords({ login, payment: password, name, current: 'payment' }); }
    else assert(password, 'Enter your payment password.');
    const state = await readState(); check(); const account = c.ownAccount(state), slots = vaultSlots(net(), name);
    assert(!hasStaged(localStorage, slots), 'A change of keys from this browser is still waiting for the network.');
    const others = account.devices.filter(d => security.roleOf(d) === 'signin').length;
    if (!await c.review('Replace my login', [['New login key', locked ? 'Made on this browser, locked to this device with your new login password.' : 'Made on this browser, under a login password the wallet makes and shows you before anything is sent.'], ['Removed', `${others} login key${others === 1 ? '' : 's'}, including this browser's current one. Every website session ends.`], ['Fee', seconds(fee())]], 'Replace login')) return;
    // The payment key first: a mistyped payment password makes no key and no password.
    await withSpend(password, name, async spend => {
      c.setBusy(true, 'Creating your new login key…');
      const [signin] = await newKeys([{ intent: 'signin', password: login }], name); check();
      await showMadeOf(name, [signin], 'The wallet made your new login password. Let your browser save it, or write it down: it is shown only now.'); check(); await kept([signin]);
      return sendSecurity({ label: 'Replace login', accountId: account.id, build: ({ account }) => flows.buildReplaceSignin({ networkId: net(), account, spend, signin: signin.key }), ...staging(slots, { signin: signin.record }) });
    });
    const after = await readState(); check(); settleStaged(localStorage, slots, c.ownAccount(after));
    c.lock('Your login was replaced. Open your account with your new login password.');
  }); });

  // ---------------------------------------------------------------- 7. replace a stolen spend key (and this browser's login with it)
  $('replace-spend-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.replaceSpend, async () => {
    const check = c.capture(), name = c.session().binding.name, locked = lockedHere(name);
    const payment = take('replace-spend-new'), again = take('replace-spend-confirm'), login = take('replace-spend-login'), loginAgain = take('replace-spend-login-confirm');
    // New passwords the person chooses only with the device (the rule); else the wallet makes both.
    if (locked) {
      assert(payment === again, 'The two new payment passwords differ.'); assert(login === loginAgain, 'The two new login passwords differ.');
      checkPasswords({ login, payment, name });
    }
    const state = await readState(); check(); const account = c.ownAccount(state), slots = vaultSlots(net(), name);
    assert(!hasStaged(localStorage, slots), 'A change of keys from this browser is still waiting for the network.');
    const others = account.devices.filter(d => { const role = security.roleOf(d); return role === 'signin' || role === 'spend'; }).length;
    if (!await c.review('Replace my payment key', [['New keys', locked ? 'A payment key and a login key, made on this browser and locked to this device with your new passwords.' : 'A payment key and a login key, made on this browser under passwords the wallet makes and shows you before anything is sent.'], ['Removed', `${others} payment and login key${others === 1 ? '' : 's'}, at once, including any a thief added.`], ['Approved by', 'Your current payment password and one recovery key'], ['Kept', 'Your recovery keys.'], ['Fee', seconds(fee())]], 'Replace payment key')) return;
    const current = take('replace-spend-payment');
    const recovery = await takeRecovery('replace-spend-secret', account); check();
    let fresh = [];
    try {
      // The payment key of now first: a mistyped payment password makes no key and no password.
      await withSpend(current, name, async oldSpend => {
        c.setBusy(true, 'Creating your new keys…');
        fresh = await newKeys([{ intent: 'spend', password: payment }, { intent: 'signin', password: login }], name); check();
        const [spend, signin] = fresh;
        await showMadeOf(name, fresh, 'The wallet made your new payment password and your new login password. Write the payment password down now, apart from your recovery words; let your browser save the login password.'); check(); await kept(fresh);
        return sendSecurity({ label: 'Replace payment key', accountId: account.id, build: ({ account, row, now }) => flows.buildReplaceSpend({ networkId: net(), account, security: row, spend: oldSpend, recovery, newSpend: spend.key, newSignin: signin.key, now }), ...staging(slots, { signin: signin.record, spend: spend.record }) });
      });
    } finally { recovery.privateKey = null; for (const one of fresh) one.key.privateKey = null; }
    const after = await readState(); check(); settleStaged(localStorage, slots, c.ownAccount(after));
    c.lock('Your payment key and this browser\'s login key were replaced. Open your account with your new login password.');
  }); });

  // ---------------------------------------------------------------- H3. replace leaked recovery keys
  // "New recovery words": the person chooses the kind first, "Words only" (selected at first) or "Words and a Recovery
  // Kit" (papers.mjs). Words only is the step of "Protect my account"; with a kit, the kit is downloaded or printed first.
  // Then the payment password and one current recovery key approve the change.
  const rrSteps = paperSteps('rr', $, { kit: true });
  const rrKind = () => ($('rr-kind-kit').checked === true ? 'kit' : 'words');
  function resetReplaceRecovery() {
    if (rrDraft) forgetRecoveryKeys(rrDraft);
    rrDraft = null; scrub(SECRET_FIELDS.rr);
    rrSteps.clear(); $('rr-start').hidden = $('rr-kinds').hidden = false;
  }
  async function startReplaceRecovery() {
    const check = c.capture(), state = await readState(); check();
    const account = c.ownAccount(state); assert(flows.rowOf(state, account), 'This account is not secured.');
    const kind = rrKind();
    resetReplaceRecovery();
    rrDraft = { accountId: String(account.id), name: account.name, ...await makeRecoveryKeys(account, kind) }; check();
    $('rr-start').hidden = $('rr-kinds').hidden = true;
    rrSteps.show(rrDraft, `Printed recovery sheet for @${account.name} · network ${net().slice(0, 12)}`); showChange();
    c.notice(kind === 'kit' ? 'Save your new Recovery Kit and write down your new recovery words. They are shown only now.' : 'Write down your new recovery words. They are shown only now.');
  }
  $('rr-start').addEventListener('click', () => c.run(startReplaceRecovery));
  $('rr-print').addEventListener('click', () => { if (!rrDraft || rrDraft.kind !== 'kit') return resetReplaceRecovery(); rrSteps.printed(rrDraft); printSheet(); });
  $('rr-kit-download').addEventListener('click', () => c.run(async () => {
    assert(rrDraft?.kind === 'kit', 'Start again from the beginning.');
    const current = rrDraft, check = c.capture();
    await saveKit(c, rrSteps, current, { networkId: net(), name: current.name }, () => { check(); return rrDraft === current; });
  }));
  $('rr-cancel').addEventListener('click', () => {
    const kit = rrDraft?.kind === 'kit'; resetReplaceRecovery();
    c.notice(kit ? 'Nothing was changed. The new Recovery Kit and recovery words were discarded: delete the kit if you downloaded it, and destroy what you wrote down or printed.' : 'Nothing was changed. The new recovery words were discarded: destroy the paper if you wrote them down.');
  });
  $('rr-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.rr, async () => {
    assert(rrDraft, 'Start again from the beginning.');
    // With a kit, the button is shown once the new kit was downloaded or printed; a submission that comes some other way
    // (the Enter key in a field of the form) is refused all the same.
    assert(rrSteps.used(), 'Save your new Recovery Kit first: download it, or print it.');
    const check = c.capture(), current = rrDraft, kit = current.kind === 'kit';
    const state = await readState(); check(); const account = c.ownAccount(state), row = flows.rowOf(state, account);
    const ends = [row.pending_root ? 'the waiting change of keys ends' : null, row.pending_payments.length ? `${row.pending_payments.length} waiting payment${row.pending_payments.length === 1 ? ' is' : 's are'} cancelled` : null, row.pending_limit ? 'the waiting raise of the daily limit is cancelled' : null].filter(Boolean);
    const replaced = kit ? 'Your new Recovery Kit and recovery words replace every current recovery key. The old ones stop working at once: delete the old kit, and destroy the old words and any printed sheet.'
      : 'Your new recovery words replace every current recovery key: both come from them. The old ones stop working at once: destroy the old paper, and delete an old Recovery Kit if you had one.';
    if (!await c.review(kit ? 'Replace my recovery words and Recovery Kit' : 'Replace my recovery words', [['New recovery keys', replaced], ['Also', `${ends.length ? ends.join('; ') + '. ' : ''}Any freeze ends, and every waiting payment and waiting raise of the daily limit is cancelled.`], ['Kept', 'Your payment key and login keys.'], ['Approved by', 'Your payment password and one current recovery key'], ['Fee', seconds(fee())]], 'Replace recovery keys')) return;
    const password = take('rr-payment');
    const recovery = await takeRecovery('rr-secret', account); check();
    try { await withSpend(password, account.name, spend => sendSecurity({ label: 'Replace recovery keys', accountId: account.id, build: ({ account, row, now }) => flows.buildReplaceRecovery({ networkId: net(), account, security: row, spend, recovery, newSheet: current.sheet, newPhrase: current.phrase, now }) })); }
    finally { recovery.privateKey = null; }
    rememberRecoveryKind(localStorage, net(), account.name, current);
    resetReplaceRecovery(); await c.refresh();
    c.notice(kit ? 'Your new Recovery Kit and recovery words are active. The old ones no longer work.' : 'Your new recovery words are active. The old ones no longer work.');
  }); });

  // ---------------------------------------------------------------- 9. daily limit
  // A lower limit applies at once. A higher one waits, or applies at once when a recovery paper is typed too. Which
  // of these the typed number will be is said under the field while it is typed (protection.mjs, limitChange), and
  // again in the review.
  const limitChangeOf = (row, state, amount) => limitChange({ current: effectiveLimit(row, waits(state)), next: amount, feeMicros: fee(), delay: duration(row.policy.delay_seconds), withPaper: $('limit-secret').value.trim() !== '', words: words(state) });
  function sayLimitChange() {
    const state = c.state(), account = c.ownAccount(state), row = account && Array.isArray(state?.security) ? security.securityOf(state, account.id) : null;
    let amount = null; try { amount = parseSeconds($('limit-amount').value.trim()); } catch { amount = null; }
    $('limit-when').textContent = row ? limitChangeOf(row, state, amount).text : '';
  }
  for (const id of ['limit-amount', 'limit-secret']) $(id).addEventListener('input', sayLimitChange);
  $('limit-form').addEventListener('submit', event => { event.preventDefault(); guarded(STEPS['limit-form'], async () => {
    const check = c.capture(), amount = parseSeconds($('limit-amount').value.trim()), state = await readState(); check();
    const account = c.ownAccount(state), row = flows.rowOf(state, account), now = waits(state), current = effectiveLimit(row, now), change = limitChangeOf(row, state, amount);
    assert(change.kind !== 'same', 'The daily limit already has this value.');
    assert(change.kind !== 'too-low', change.text);
    if (change.kind === 'raise-now') {
      if (!await limitNow({ account, row, state, amount, title: 'Raise the daily limit now', confirm: 'Raise the limit now', label: 'Raise daily limit with a recovery proof', passwordId: 'limit-payment', secretId: 'limit-secret' })) return;
      $('limit-amount').value = ''; closeSteps(); await c.refresh();
      return c.notice(`Your daily limit is ${seconds(amount)} now. What you can pay at once fills up over 24 hours.`);
    }
    const raise = change.kind === 'raise-wait';
    if (!await c.review(raise ? 'Raise the daily limit' : 'Lower the daily limit', [['Now', seconds(current)], ['New', `${seconds(amount)} at once; up to about ${seconds(limitExposure(amount).within24h)} in any 24 hours as it refills`], ['When', raise ? `After ${duration(row.policy.delay_seconds)}. You can cancel it meanwhile on Home, under “Waiting on your account”.` : 'At once.'], ['Fee', seconds(fee())]], raise ? 'Ask for a higher limit' : 'Lower the limit')) return;
    await withSpend(take('limit-payment'), account.name, spend => sendSecurity({ label: raise ? 'Raise daily limit' : 'Lower daily limit', accountId: account.id, build: ({ account, row, now, waitsNow }) => flows.buildLimit({ networkId: net(), account, security: row, spend, dailyLimitMicros: amount, feeMicros: fee(), now, waitsNow }) }));
    $('limit-amount').value = ''; closeSteps(); await c.refresh();
    c.notice(raise ? `Your higher limit applies after ${duration(row.policy.delay_seconds)}.` : 'Your daily limit is lower now.');
  }); });

  // ---------------------------------------------------------------- M3. a login for another browser
  $('add-login-form').addEventListener('submit', event => { event.preventDefault(); guarded(['add-login-payment'], async () => {
    const check = c.capture(), state = await readState(); check();
    const account = c.ownAccount(state); assert(flows.rowOf(state, account), 'This account is not secured.');
    const request = parseSigninRequest($('add-login-request').value.trim(), { networkId: net(), account, now: elapsedOf(state) });
    if (!await c.review('Add a login for another browser', [['Account', '@' + account.name], ['Fingerprint · must match the one on the other browser', await fingerprint(request.public_key)], ['New login key', request.public_key], ['It can', 'Sign in to websites. It cannot pay, freeze or change keys.'], ['Fee', seconds(fee())]], 'Add login')) return;
    await withSpend(take('add-login-payment'), account.name, spend => sendSecurity({ label: 'Add a login', accountId: account.id, build: ({ account }) => flows.buildAddSignin({ networkId: net(), account, spend, request }) }));
    $('add-login-request').value = ''; await c.refresh();
    c.notice('The other browser is now a login of this account. Open the account there with the login password chosen there.');
  }); });
  $('newlogin-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.newlogin, async () => {
    const check = c.capture(), session = c.session(); assert(session && removed, 'Unlock again first.');
    const name = session.binding.name, slots = vaultSlots(net(), name), locked = lockedHere(name);
    const login = take('newlogin-password'), again = take('newlogin-confirm');
    // A login password chosen here only with the device (the rule); else the wallet makes it.
    if (locked) { assert(login === again, 'The two login passwords differ.'); checkPasswords({ login, name }); }
    const state = await readState(); check(); const account = c.ownAccount(state);
    assert(!loginRequestOf(localStorage, slots), 'This browser already asked for a login. Withdraw that request first.');
    c.setBusy(true, 'Creating a login key for this browser…');
    const [signin] = await newKeys([{ intent: 'signin', password: login }], name); check();
    await showMadeOf(name, [signin], 'The wallet made the login password of this browser. Let your browser save it, or write it down: it is shown only now. It opens this browser once your other device has added the login.'); check(); await kept([signin]);
    const request = await flows.signinRequest({ networkId: net(), account, key: signin.key, now: elapsedOf(state) }); signin.key.privateKey = null;
    // In its own slot: it blocks nothing this browser does, and it never replaces a key this browser still holds.
    storeLoginRequest(localStorage, slots, signin.record, request);
    await showRequest(request);
    c.notice('Paste this request on a device that has your payment password, under More, Devices, within a few hours. Compare the fingerprint on both. This page updates when the login is added.');
  }); });
  async function showRequest(request) {
    $('newlogin-code').value = JSON.stringify(request); $('newlogin-code').hidden = false; $('newlogin-form').hidden = true; $('newlogin-withdraw').hidden = false;
    $('newlogin-fingerprint').textContent = `Fingerprint: ${await fingerprint(request.publicKey)}. The other device shows the same before adding it.`; $('newlogin-fingerprint').hidden = false;
  }
  function hideRequest() { $('newlogin-code').value = ''; $('newlogin-code').hidden = $('newlogin-fingerprint').hidden = $('newlogin-withdraw').hidden = true; $('newlogin-form').hidden = false; }
  $('newlogin-withdraw').addEventListener('click', () => c.run(async () => {
    const name = removed?.name || c.session()?.binding.name; assert(name, 'Unlock again first.');
    withdrawLoginRequest(localStorage, vaultSlots(net(), name)); hideRequest();
    c.notice('The login request was withdrawn and its key deleted from this browser. If it was added meanwhile, it signs nothing on the chain, and "Someone has my login" removes it.');
  }));

  // ---------------------------------------------------------------- 8. lost device
  const progressKeys = () => Object.keys(localStorage).filter(k => k.startsWith(progressKey(net(), '')));
  // The new keys of a recovery: where the device can lock keys, locked to it from birth or under passwords the wallet
  // makes, as the person chooses; else the wallet makes their passwords.
  const lostSealing = sealChoice('lost', ['lost-login', 'lost-login-confirm', 'lost-payment', 'lost-payment-confirm'], { lead: '3. Your new passwords. ', legendLead: '3. ' });
  function showLost(showForm) {
    $('security-removed-panel').hidden = true; $('auth-panel').hidden = true; $('enrollment-panel').hidden = true; $('recovery-claim-panel').hidden = true;
    $('security-recover-panel').hidden = false; $('lost-form').hidden = !showForm; $('lost-status').hidden = showForm;
    if (showForm) lostSealing.redraw();
  }
  // The Recovery Kit on the recover panel (recovery-file.mjs). It is read as soon as it is chosen: its header names the
  // account and the network, and nothing in it is secret. The name is filled in from it when the field is empty, and the
  // panel says whose kit it is, or why it cannot be used here. The kit is opened only on submit, with the words typed.
  let kitReading = 0;
  const kitName = () => $('lost-name').value.trim().replace(/^@/, '');
  function sayKit(text, warn = false) { $('lost-file-status').textContent = text; $('lost-file-status').className = warn ? 'field-note warning' : 'field-note'; $('lost-file-status').hidden = !text; }
  async function kitChosen() {
    const file = $('lost-file').files?.[0] ?? null, reading = ++kitReading;
    if (!file) return sayKit('');
    let header = null, problem = null;
    try { assert(file.size <= MAX_RECOVERY_KIT_BYTES, 'This file is too large to be a Recovery Kit.'); header = readRecoveryKit(await file.text()); } catch (error) { problem = error.message; }
    if (reading !== kitReading) return;
    if (problem) return sayKit(problem, true);
    if (!kitName() && header.networkId === net()) $('lost-name').value = header.accountName;
    const mismatch = recoveryKitMismatch(header, { networkId: net(), name: kitName() });
    sayKit(mismatch ?? `This is the Recovery Kit of @${header.accountName}.`, Boolean(mismatch));
  }
  $('lost-file').addEventListener('change', () => { kitChosen().catch(() => {}); });
  $('lost-name').addEventListener('input', () => { if ($('lost-file').files?.length) kitChosen().catch(() => {}); });
  function forgetKit() { kitReading += 1; $('lost-file').value = ''; sayKit(''); }
  /// The Recovery Kit chosen for a recovery of `name`, read and checked before anything else is done: a kit of another
  /// account or network is refused here, before the network is asked or anything is derived. Null when no kit is chosen.
  async function chosenKit(file, name, check) {
    if (!file) return null;
    assert(file.size <= MAX_RECOVERY_KIT_BYTES, 'This file is too large to be a Recovery Kit.');
    const text = await file.text(); check();
    const mismatch = recoveryKitMismatch(readRecoveryKit(text), { networkId: net(), name }); assert(!mismatch, mismatch);
    return text;
  }
  /// Where the second recovery key of a recovery comes from: the sheet in the Recovery Kit when a kit is chosen (opened
  /// with the words typed, expecting this network and `name`), the printed sheet when one is typed, else the words
  /// themselves ("words only"; null here).
  async function lostSheet({ kit, typed, words, name, check }) {
    if (kit !== null) {
      c.setBusy(true, 'Opening your Recovery Kit with your recovery words. This takes a few seconds…');
      const { sheetText } = await openRecoveryKit(kit, words, { argon2id: argon(), expect: { networkId: net(), name } }); check();
      return { sheetText, from: 'kit' };
    }
    return typed.trim() ? { sheetText: typed, from: 'printed' } : null;
  }
  const APPROVED_BY = { words: 'Your recovery words', kit: 'Your Recovery Kit and your recovery words', printed: 'Your printed recovery sheet and your recovery words' };
  /// The two recovery keys of a recovery, and what the review says approves it. Without a sheet, both come from the
  /// words, which works only for an account that is "words only" (security-flows.mjs, accountWordsKeys): an account that
  /// also has a Recovery Kit is told so.
  async function lostKeys(source, words, account) {
    if (source === null) {
      assert(typeof words === 'string' && words.trim(), 'Enter your recovery words.');
      c.setBusy(true, 'Recreating your recovery keys from your recovery words. This takes a few seconds…');
      const isRecovery = found => flows.roleOf(account, found.publicKey) === 'recover';
      const { first, second } = await accountWordsKeys({ passphrase: words, networkId: net(), account, registered: registeredHere(), isRecovery, argon2id: argon() });
      if (!isRecovery(first)) { first.privateKey = null; throw new Error('These recovery words are not one of this account\'s recovery keys. Check them against what you wrote down.'); }
      if (!second) { first.privateKey = null; throw new Error('This account also needs its Recovery Kit. Choose the file, or type the printed sheet.'); }
      return { sheet: second, phraseKey: first, approvedBy: APPROVED_BY.words };
    }
    let sheet;
    try { sheet = await recoveryKey('sheet', source.sheetText, account); }
    catch (error) { throw source.from === 'kit' ? new Error('Your Recovery Kit opened, but the sheet in it is not one of this account\'s recovery keys any more: it is an older kit, from before new recovery words were made. Use the newest one.') : error; }
    try { return { sheet, phraseKey: await recoveryKey('phrase', words, account), approvedBy: APPROVED_BY[source.from] }; } catch (error) { sheet.privateKey = null; throw error; }
  }
  function closeLost() { scrub([...SECRET_FIELDS.lost, 'lost-finish-payment']); forgetKit(); $('security-recover-panel').hidden = true; if (!c.session()) $('auth-panel').hidden = false; }
  $('lost-open').addEventListener('click', () => c.run(async () => { const saved = progressKeys(); if (saved.length) return renderLost(parseProgress(localStorage.getItem(saved[0]))); if (!$('lost-name').value) $('lost-name').value = $('username').value; showLost(true); }));
  $('lost-close').addEventListener('click', closeLost);
  $('lost-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.lost, async () => {
    // Nothing is read or made before the browser said what the device can do and, where it can lock keys, the person chose
    // a way (LOCK_WORDS.ways.asking, .pick); the fields of secrets are emptied all the same, as after any step that stops.
    lostSealing.ready();
    // Every secret is read (and its field cleared) before anything can fail. The kit stays chosen until the recovery
    // was asked for: alone it opens nothing.
    const typed = take('lost-sheet'), phrase = take('lost-phrase'), login = take('lost-login'), loginAgain = take('lost-login-confirm'), payment = take('lost-payment'), paymentAgain = take('lost-payment-confirm');
    const file = $('lost-file').files?.[0] ?? null, byDevice = lostSealing.byDevice;
    const check = c.capture(), name = validateName($('lost-name').value.trim());
    // The passwords a person chose seal the new keys only with the device (the rule); else the wallet makes them.
    if (byDevice) {
      assert(login === loginAgain, 'The two login passwords differ.'); assert(payment === paymentAgain, 'The two payment passwords differ.');
      checkPasswords({ login, payment, name });
    }
    const kit = await chosenKit(file, name, check);
    const slots = vaultSlots(net(), name);
    assert(localStorage.getItem(progressKey(net(), name)) === null, `A recovery of @${name} is already in progress on this browser.`);
    const state = await readState({ names: [name] }); check();
    const account = state.accounts.find(a => a.name === name); assert(account, 'No account has that name.');
    const before = lostDeviceSlots(localStorage, slots, account); assert(!before.blocked, before.blocked);
    // Keys of this account that this browser kept locked to this device are replaced by the new ones: the recovery is the
    // way back when the device lost its key. The new keys follow the rule all the same. The review says so.
    const wasLocked = lockOf(localStorage, slots).on;
    const row = flows.rowOf(state, account); assert(row, `@${name} has not secured its account. Use guardian recovery instead.`);
    assert(!row.pending_root, 'A change of keys is already waiting for this account. If you did not start it, cancel it below with your recovery words.');
    const { sheet, phraseKey, approvedBy } = await lostKeys(await lostSheet({ kit, typed, words: phrase, name, check }), phrase, account); check();
    let fresh = [];
    try {
      const ready = dated(state, waits(state) + BigInt(row.policy.delay_seconds) * 1000000n);
      c.setBusy(false);
      if (!await c.review(`Recover @${name} on this browser`, [['New keys', byDevice ? 'A login key and a payment key, made on this browser and locked to this device with your new passwords.' : 'A login key and a payment key, made on this browser under passwords the wallet makes and shows you before anything is sent.'], ['Waiting period', `${duration(row.policy.delay_seconds)}. The account is frozen until then.`], ['Ready about', ready.later ? `Not before ${ready.date.toLocaleString()}` : ready.date.toLocaleString()], ['Old devices', 'Lose access when you finish. Until then it can be cancelled by your old payment password together with a recovery key, or by both recovery keys.'], ['Approved by', approvedBy], ...(wasLocked ? [['This browser', `Its keys of @${name} locked to this device are replaced by the new ones.`]] : []), ['Fee', `${seconds(fee())}, or what the account holds if less`]], 'Start recovery')) return;
      c.setBusy(true, byDevice ? 'Locking your new keys to this device. This takes a few seconds…' : 'Making your new keys and their passwords. This takes a few seconds…');
      // Locked from birth, or under passwords the wallet makes (device-lock.mjs, newKeysByRule): a device that fails at any
      // step does not end the recovery. The records this recovery replaces do not keep the device's key in use.
      const made = await newKeysByRule({ byDevice, storage: localStorage, env: c.env?.(), wanted: [{ intent: 'signin', password: login }, { intent: 'spend', password: payment }], networkId: net(), name, argon2id: argon(), say: text => c.notice(text, 'busy'), except: [slots.login, slots.spend] });
      fresh = made.keys; check();
      const [signin, spend] = fresh;
      const records = { signin: signin.record, spend: spend.record };
      // The passwords the wallet made are shown before anything is kept or sent: a key whose password nobody saw is not kept.
      if (!made.locked) { await showMadeOf(name, fresh, made.fallback ?? 'The wallet made the passwords of your new keys. Write them down now: you need the payment password to finish the recovery, and they are shown only now.'); check(); }
      c.setBusy(true, 'Asking for the recovery…');
      const progress = progressRecord({ networkId: net(), account, signin: signin.key.publicKey, spend: spend.key.publicKey });
      await sendSecurity({ label: 'Recovery request', accountId: account.id, names: [name], build: ({ account, row, now }) => flows.buildLostDeviceRequest({ networkId: net(), account, security: row, sheet, phrase: phraseKey, signin: signin.key, spend: spend.key, now }),
        // The encrypted keys and the public progress are written before anything is submitted, so a reload or a lost receipt loses nothing.
        beforeSubmit: () => navigator.locks.request(`timecurrency:vault:${net()}:${name}`, { mode: 'exclusive' }, async () => {
          // Checked again under the lock: only records whose keys the account no longer has are replaced.
          const slotsNow = lostDeviceSlots(localStorage, slots, account); assert(!slotsNow.blocked, slotsNow.blocked + ' Nothing was submitted.');
          for (const key of slotsNow.stale) localStorage.removeItem(key);
          localStorage.setItem(slots.login, JSON.stringify(records.signin)); localStorage.setItem(slots.spend, JSON.stringify(records.spend)); localStorage.setItem(progressKey(net(), name), JSON.stringify(progress));
        }) });
      check(); $('lost-name').value = ''; forgetKit();
      await renderLost(progress);
      if (made.fallback) c.notice(made.fallback);
    } finally { for (const one of fresh) { one.key.privateKey = null; one.storageKey = null; } sheet.privateKey = phraseKey.privateKey = null; }
  }); });
  /// A change of keys someone else started, cancelled with both recovery keys from a fresh browser.
  $('lost-cancel-waiting').addEventListener('click', () => guarded(SECRET_FIELDS.lost, async () => {
    const typed = take('lost-sheet'), phrase = take('lost-phrase'), file = $('lost-file').files?.[0] ?? null; scrub(SECRET_FIELDS.lost);
    const check = c.capture(), name = validateName($('lost-name').value.trim());
    const kit = await chosenKit(file, name, check);
    const state = await readState({ names: [name] }); check();
    const account = state.accounts.find(a => a.name === name); assert(account, 'No account has that name.');
    const row = flows.rowOf(state, account); assert(row?.pending_root, 'No change of keys is waiting for this account.');
    const { sheet, phraseKey, approvedBy } = await lostKeys(await lostSheet({ kit, typed, words: phrase, name, check }), phrase, account); check();
    try {
      c.setBusy(false);
      if (!await c.review(`Cancel the waiting change of keys of @${name}`, [['Effect', 'The change ends, and the account is no longer frozen by it.'], ['Approved by', approvedBy], ['Then', 'Whoever started it has your recovery keys and can ask again. Make new recovery words as soon as you can, from a device with your payment password.'], ['Fee', `${seconds(fee())}, or what the account holds if less`]], 'Cancel the change')) return;
      await sendSecurity({ label: 'Cancel change of keys', accountId: account.id, names: [name], build: ({ account, row, now }) => flows.buildCancelReplacement({ networkId: net(), account, security: row, approvers: [sheet, phraseKey], now }) });
      forgetKit();
      c.notice('The waiting change of keys was cancelled. Make new recovery words as soon as you can: whoever started it has them.');
    } finally { sheet.privateKey = phraseKey.privateKey = null; }
  }));
  async function renderLost(progress) {
    lostProgress = progress; showLost(false);
    const check = c.capture(), state = await readState({ names: [progress.name] }); check();
    const account = state.accounts.find(a => a.name === progress.name), row = account ? flows.rowOf(state, account) : null, now = waits(state);
    const status = recoveryStatus({ progress, account, security: row, now });
    const pending = pendingRows(progress.accountId, row, state, [73, 74]);
    $('lost-pending').replaceChildren(...pending);
    $('lost-finish-form').hidden = status.stage !== 'ready'; $('lost-restart').hidden = status.stage !== 'none' || pending.length > 0;
    if (status.stage === 'done') {
      localStorage.removeItem(progressKey(net(), progress.name)); closeLost(); lostProgress = null;
      c.showUnlock(progress.name); c.notice('Recovery finished. Open your account with your new login password.'); return;
    }
    $('lost-status-text').textContent = status.stage === 'waiting' ? `Recovery of @${progress.name} is waiting. You can finish it ${timeWords(state, status.ready, 'after')} (${roughly(status.remainingMicros)}). The account is frozen until then.`
      : status.stage === 'ready' ? `The waiting period is over. Enter your new payment password to finish the recovery of @${progress.name}.`
      : pending.length ? 'Your recovery request was signed but no receipt was seen yet. Check it, or send it again.'
      : `Nothing is waiting for this browser's new keys. The request did not reach the network, or someone with two of your keys cancelled it, or the time to finish it passed. You can start again.`;
  }
  $('lost-check').addEventListener('click', () => c.run(async () => { assert(lostProgress, 'Nothing to check.'); c.setBusy(true); await renderLost(lostProgress); }));
  $('lost-restart').addEventListener('click', () => c.run(async () => {
    const progress = lostProgress; assert(progress, 'Nothing to discard.');
    const state = await readState({ names: [progress.name] }), account = state.accounts.find(a => a.name === progress.name);
    assert(recoveryStatus({ progress, account, security: account ? flows.rowOf(state, account) : null, now: waits(state) }).stage === 'none', 'The recovery is still waiting. Refresh first.');
    const slots = vaultSlots(net(), progress.name);
    for (const [key, publicKey] of [[slots.login, progress.signin], [slots.spend, progress.spend]]) { try { if (JSON.parse(localStorage.getItem(key))?.binding?.publicKey === publicKey) localStorage.removeItem(key); } catch {} }
    localStorage.removeItem(progressKey(net(), progress.name)); lostProgress = null; showLost(true); c.notice('Start again with your recovery words.');
  }));
  $('lost-finish-form').addEventListener('submit', event => { event.preventDefault(); guarded(['lost-finish-payment'], async () => {
    const progress = lostProgress; assert(progress, 'Nothing to finish.');
    const check = c.capture(), state = await readState({ names: [progress.name] }); check();
    const account = state.accounts.find(a => a.name === progress.name), row = flows.rowOf(state, account);
    // A finish already signed and not seen yet is sent again as it is: the same bytes, no new signature.
    const slot = protectiveSlot(74, account.id), signed = c.pending.get(net(), slot);
    if (signed && !retired(signed, row, elapsedOf(state))) { await resend(slot, signed); check(); return renderLost(progress); }
    if (!await c.review('Finish recovery', [['Account', '@' + progress.name], ['Effect', 'Your new login and payment keys replace the old ones. Old devices lose access.'], ['Fee', `${seconds(fee())}, or what the account holds if less`]], 'Finish recovery')) return;
    await withSpend(take('lost-finish-payment'), progress.name, spend => {
      assert(spend.publicKey === progress.spend, 'This payment key is not the one in the waiting recovery.');
      return sendSecurity({ label: 'Finish recovery', accountId: account.id, names: [progress.name], build: ({ account, row, now, waitsNow }) => flows.buildFinalize({ networkId: net(), account, security: row, spend, now, waitsNow }) });
    });
    check(); await renderLost(progress);
  }); });

  // ---------------------------------------------------------------- 1b. this browser is not (or no longer) a login of the account
  function showRemoved(account, state) {
    const row = flows.rowOf(state, account), slots = vaultSlots(net(), account.name);
    let spendKey = null; try { spendKey = spendRecord(localStorage, slots)?.binding.publicKey || null; } catch {}
    let loginVersion = null; try { loginVersion = JSON.parse(localStorage.getItem(slots.login))?.version ?? null; } catch {}
    const status = flows.removedLogin({ account, security: row, spendKey, now: waits(state) });
    // A login key of a protected account is a version-2 record, or version 3 when it is locked to this device.
    const neverAdded = loginVersion !== 2 && loginVersion !== 3;
    removed = { name: account.name, accountId: String(account.id) };
    chosenFields(lockedHere(account.name));
    $('dashboard').hidden = true; $('enrollment-panel').hidden = true; $('recovery-claim-panel').hidden = true; $('security-recover-panel').hidden = true;
    $('security-removed-panel').hidden = false;
    $('removed-title').textContent = neverAdded ? `This browser is not a login of @${account.name} yet.` : `This browser's login key was removed from @${account.name}.`;
    $('removed-login-form').hidden = !status.spendUsable;
    $('removed-status').textContent = status.replacing ? 'A change of all your keys is waiting, and the account is frozen until it ends. If you did not start it, cancel it from a device with your payment password and your recovery words, or here with your recovery words (“Recover my account”).'
      : status.frozen ? 'The account is frozen. A new login key can be made when the freeze ends.'
      : status.spendUsable ? 'This browser still has your payment key.' : neverAdded ? 'Ask a device that has your payment password to add this browser, or recover with your recovery keys.' : 'This browser has no payment key of this account any more.';
    const pending = loginRequestOf(localStorage, slots);
    if (pending) showRequest(pending.request).catch(() => {}); else hideRequest();
    return status;
  }
  $('removed-lost').addEventListener('click', () => c.run(async () => {
    const name = removed?.name || c.session()?.binding.name;
    c.lock('Recover your account with your recovery words, and your Recovery Kit if your account has one.');
    $('lost-name').value = name || ''; showLost(true);
  }));
  $('removed-login-form').addEventListener('submit', event => { event.preventDefault(); guarded(SECRET_FIELDS.removed, async () => {
    const check = c.capture(), session = c.session(); assert(session && removed, 'Unlock again first.');
    const name = session.binding.name, login = take('removed-login-new'), again = take('removed-login-confirm'), password = take('removed-payment'), locked = lockedHere(name);
    // A login password the person chooses only with the device (the rule); else the wallet makes it.
    if (locked) { assert(login === again, 'The two login passwords differ.'); checkPasswords({ login, payment: password, name, current: 'payment' }); }
    else assert(password, 'Enter your payment password.');
    const state = await readState(); check(); const account = c.ownAccount(state), slots = vaultSlots(net(), name);
    const row = flows.rowOf(state, account);
    let spendKey = null; try { spendKey = spendRecord(localStorage, slots)?.binding.publicKey || null; } catch {}
    const status = flows.removedLogin({ account, security: row, spendKey, now: waits(state) });
    assert(status.canReplaceLogin, status.frozen ? 'The account is frozen. Try again when the freeze ends, or recover with your recovery words.' : 'This browser has no payment key of this account.');
    assert(!hasStaged(localStorage, slots), 'A change of keys from this browser is still waiting for the network.');
    const others = account.devices.filter(d => security.roleOf(d) === 'signin').length;
    if (!await c.review('Make a new login key', [['Account', '@' + name], ['New login key', locked ? 'Made on this browser, locked to this device with your new login password.' : 'Made on this browser, under a login password the wallet makes and shows you before anything is sent.'], ['Removed', others ? `${others} other login key${others === 1 ? '' : 's'}. Every website session ends.` : 'None: the account has no other login key.'], ['Next', 'Make a new payment password under Keys if you did not remove this browser\'s login yourself.'], ['Fee', seconds(fee())]], 'Make login key')) return;
    // The payment key first: a mistyped payment password makes no key and no password.
    await withSpend(password, name, async spend => {
      c.setBusy(true, 'Creating your new login key…');
      const [signin] = await newKeys([{ intent: 'signin', password: login }], name); check();
      await showMadeOf(name, [signin], 'The wallet made your new login password. Let your browser save it, or write it down: it is shown only now.'); check(); await kept([signin]);
      return sendSecurity({ label: 'New login key', accountId: account.id, build: ({ account }) => flows.buildReplaceSignin({ networkId: net(), account, spend, signin: signin.key }), ...staging(slots, { signin: signin.record }) });
    });
    const after = await readState(); check(); settleStaged(localStorage, slots, c.ownAccount(after));
    $('security-removed-panel').hidden = true; removed = null;
    c.lock('Your new login key is ready. Open your account with your new login password.');
  }); });

  // ---------------------------------------------------------------- hooks for app.js
  /// After a verified refresh with an unlocked key that is on the account.
  function render(account, state) {
    const session = c.session(), slots = vaultSlots(net(), account.name), row = Array.isArray(state.security) ? security.securityOf(state, account.id) : null;
    const role = flows.roleOf(account, session.binding.publicKey);
    // This browser holds a live key of the account: a login it asked of another device is void.
    try { if (settleWithProof(slots, account, row, state).length) c.notice('Your new keys are active on this browser.'); settleLoginRequest(localStorage, slots, account); }
    catch (error) { c.notice(failureNotice(error), 'error'); }
    const isSecured = Boolean(row);
    $('security-adopt').hidden = isSecured; $('security-dashboard').hidden = !isSecured;
    // Home: the Protection card of a protected account, or "Not protected yet" with the way to protect it.
    $('protect-card').hidden = false; $('protect-none').hidden = isSecured; $('protect-on').hidden = !isSecured;
    renderOtherTabs(account, state, isSecured);
    $('send-payment-wrap').hidden = !isSecured; $('approval-payment-wrap').hidden = !isSecured;
    // New passwords are asked only while the keys here are locked to this device; else the wallet makes them (the rule).
    chosenFields(lockedHere(account.name));
    if (!isSecured) {
      card = null; closeSteps();
      // "Protect my account": locked to this device from birth where it can, drawn once for the account that is open.
      if (secureDrawnFor !== account.name && !draft) { secureDrawnFor = account.name; secureSealing.redraw(); }
      // The daily limit the form suggests comes from one constant (security-flows.mjs), and so do its words.
      $('secure-limit-suggested').textContent = `Suggested: ${dailyLimitWords()}. Change it if you like.`;
      if (!draft && $('secure-limit').dataset.touched !== 'true' && !$('secure-limit').value) $('secure-limit').value = DEFAULT_DAILY_LIMIT_SECONDS;
      const blocked = role !== null ? 'Only a device that can both pay and manage this account can secure it.' : account.recovery_policy ? 'Guardian recovery is on for this account. Turn it off before securing the account.' : hasStaged(localStorage, slots) ? 'Protecting this account was started on this browser and is waiting for the network. Check its receipt under Activity.' : '';
      $('secure-blocked').textContent = blocked; $('secure-blocked').hidden = !blocked; $('secure-form').dataset.blocked = blocked ? 'true' : '';
      $('secure-minimum').textContent = `This network needs at least ${minimumHours(state) || 1n} hour(s) for both periods. Production networks need at least 48.`;
      if (!draft && $('secure-delay').dataset.touched !== 'true') { $('secure-delay').value = $('secure-freeze').value = defaultHours(state); }
      $('security-inbox').replaceChildren(node('p', 'Nothing from your keys is waiting. Guardian recoveries and network alerts for your account appear below.', 'subtle')); $('inbox-keys').hidden = true; $('security-pending').replaceChildren();
      badge(flows.inboxCount({ recoveryCases: state.recovery_cases || [], accountId: account.id }));
      return;
    }
    const now = waits(state), left = security.allowance(row, now), frozen = security.frozen(row, now), ends = dated(state, row.frozen_until_elapsed_micros);
    $('security-title').textContent = frozen ? 'Your account is frozen.' : 'Your account is protected.';
    $('security-detail').textContent = frozen ? (BigInt(row.frozen_until_elapsed_micros) > now ? (ends.later ? `No payments and no logins until the freeze ends, not before ${ends.date.toLocaleString()}.` : `No payments and no logins until ${ends.date.toLocaleString()}.`) : 'A change of all your keys is waiting.') : `Payments need your payment password. The daily limit refills over 24 hours, so up to about ${seconds(limitExposure(effectiveLimit(row, now)).within24h)} can leave in any 24 hours. Logins use this browser's login key.`;
    $('security-allowance').textContent = c.seconds(left) + ' s'; $('security-limit').textContent = c.seconds(effectiveLimit(row, now)) + ' s';
    $('security-delay').textContent = duration(row.policy.delay_seconds); $('security-freeze-length').textContent = duration(row.policy.freeze_seconds);
    $('send-allowance').textContent = `You can pay ${c.seconds(left)} more seconds today, fees included.${frozen ? ' The account is frozen.' : ''}`;
    $('stake-allowance').textContent = `Today's limit: you can stake ${c.seconds(left)} more seconds, fee included.`;
    $('stake-frozen-note').hidden = !frozen;
    card = viewOf(account, row, state); drawCard(card, row);
    settleRemembered(localStorage, pauseKey(net(), account.name), card.pause.on, Date.now());
    renderInbox(account, row, state);
    $('security-pending').replaceChildren(...pendingRows(account.id, row, state, PROTECTIVE));
    badge(flows.inboxCount({ events: inboxRows, recoveryCases: state.recovery_cases || [], accountId: account.id }));
  }
  /// What waits is listed on Home, under the Protection card: the count stands on Home's own button.
  function badge(count) { $('tab-home').textContent = count ? `Home (${count})` : 'Home'; }
  /// Devices, guardian Recovery and Earn describe what a secured account's keys do, and offer nothing the network would refuse.
  function renderOtherTabs(account, state, isSecured) {
    const offered = protocol4Actions(account, c.session().binding.publicKey, isSecured);
    $('devices-title').textContent = isSecured ? 'The keys of your account' : 'Browsers that can open this account';
    $('devices-secured-intro').hidden = !isSecured; $('backup-secured-note').hidden = !isSecured; $('backup-note').hidden = isSecured;
    $('devices-secured-card').hidden = !isSecured; $('add-device-card').hidden = !offered.addDevice && isSecured;
    $('recovery-secured-card').hidden = !isSecured; $('guardian-card').hidden = $('guardian-help-card').hidden = isSecured;
    $('auction-secured-note').hidden = !isSecured; $('stake-payment-wrap').hidden = $('stake-allowance').hidden = !isSecured;
    // Validator operator: a secured account signs there with its payment key (pos-ui.mjs; stakeLimit, stakeAction).
    $('validator-payment-wrap').hidden = !isSecured;
    if (!isSecured) { $('stake-frozen-note').hidden = true; hideStakeOver(); }
    if (!isSecured) return;
    let spendKey = null; try { spendKey = spendRecord(localStorage, vaultSlots(net(), account.name))?.binding.publicKey || null; } catch {}
    $('device-list').replaceChildren(...deviceRows(account, [c.session().binding.publicKey, spendKey]).map(k => inboxRow(k.title, `${k.detail} · ${k.publicKey}`)));
  }
  /// After a verified refresh whose unlocked key is not on the account. True if handled here.
  async function withoutDevice(account, state) {
    const slots = vaultSlots(net(), account.name), row = Array.isArray(state.security) ? security.securityOf(state, account.id) : null;
    if (settleWithProof(slots, account, row, state).includes('signin')) { c.lock('Your new keys are active on this browser. Unlock with your login password.'); return true; }
    if (settleLoginRequest(localStorage, slots, account) === 'promoted') { hideRequest(); c.lock(`This browser is now a login of @${account.name}. Unlock with the login password you chose for it.`); return true; }
    const progress = parseProgress(localStorage.getItem(progressKey(net(), account.name)));
    if (progress) { await renderLost(progress); return true; }
    if (row) { showRemoved(account, state); return true; }
    return false;
  }
  function availability(ready) {
    const session = c.session(), state = c.state(), account = c.ownAccount(state), row = account && Array.isArray(state?.security) ? security.securityOf(state, account.id) : null;
    const now = state ? waits(state) : 0n, frozenUntil = row ? BigInt(row.frozen_until_elapsed_micros) : 0n;
    for (const form of ['freeze-form', 'unfreeze-form', 'limit-form', 'pause-form', 'replace-login-form', 'replace-spend-form', 'rr-form', 'add-login-form']) for (const b of $(form).querySelectorAll('button')) b.disabled = !ready || !row;
    $('rr-start').disabled = !ready || !row;
    for (const b of document.querySelectorAll('[data-security-action]')) b.disabled = !ready || !row;
    if (row && frozenUntil - now > BigInt(row.policy.freeze_seconds) * 500000n) $('freeze-form').querySelector('button').disabled = true;
    if (row && security.frozen(row, now)) for (const form of ['limit-form', 'pause-form', 'replace-login-form', 'add-login-form']) $(form).querySelector('button').disabled = true;
    // The Protection card: its switches and buttons follow what the card last drew from proven state.
    const view = row ? card : null;
    $('freeze-switch').disabled = !ready || !view || view.freeze.locked; $('pause-switch').disabled = !ready || !view || view.pause.locked;
    $('limit-open').disabled = !ready || !view || !view.limit.canChange;
    for (const id of ['freeze-again', 'unfreeze-open', 'resume-cancel']) $(id).disabled = !ready || !view;
    $('resume-wait').disabled = !ready || !view || !view.pause.waitPossible; $('resume-now').disabled = !ready || !view || view.pause.locked;
    $('secure-form').querySelector('button').disabled = !ready || Boolean(row) || !session || flows.roleOf(account || { devices: [] }, session?.binding.publicKey) !== null || $('secure-form').dataset.blocked === 'true';
    $('secure-submit').disabled = !ready || !draft;
    if (row) for (const b of document.querySelectorAll('[data-chain-action]')) if (!b.closest?.('#activity-list, #delegations, #unbonding, #validator-exits')) b.disabled = true;
    if (row && security.frozen(row, now)) { for (const b of document.querySelectorAll('#delegations button, #unbonding button')) b.disabled = true; $('stake-form').querySelector('button').disabled = true; }
    $('stake-fit-today').disabled = !ready || !stakeOver || stakeOver.fitsToday <= 0n; $('stake-raise-limit').disabled = !ready || !stakeOver;
    for (const form of ['removed-login-form', 'newlogin-form']) for (const b of $(form).querySelectorAll('button')) b.disabled = !ready || !removed;
    $('removed-lost').disabled = !ready;
    for (const b of $('lost-form').querySelectorAll('button[type=submit]')) b.disabled = !ready;
    $('lost-cancel-waiting').disabled = !ready;
    $('send-wait').disabled = !ready || !overDraft?.waitPossible;
    $('send-now').disabled = !ready || !overDraft;
  }
  /// Called when the wallet locks: forget every draft and clear every secret field.
  function reset() {
    resetSecure(); resetReplaceRecovery(); hideOver(); hideStakeOver(); lostProgress = null; removed = null; secureDrawnFor = null;
    // The Protection card shows nothing of the account that was open: no state, no open step, nothing typed.
    card = null; closeSteps(); $('protect-card').hidden = true; $('freeze-switch').checked = $('pause-switch').checked = false;
    for (const id of ['limit-amount', 'resume-amount']) $(id).value = '';
    for (const id of ['protect-status', 'freeze-note', 'limit-text', 'limit-when', 'pause-note', 'resume-amount-note', 'resume-wait-note', 'protect-waiting']) $(id).textContent = '';
    for (const ids of Object.values(SECRET_FIELDS)) scrub(ids);
    forgetKit();
    $('stake-payment-wrap').hidden = $('stake-allowance').hidden = $('stake-frozen-note').hidden = $('validator-payment-wrap').hidden = true;
    hideRequest(); $('security-removed-panel').hidden = true; $('security-recover-panel').hidden = true; $('send-payment-wrap').hidden = $('approval-payment-wrap').hidden = true; badge(0);
  }
  /// On start, before any unlock. Keys kept aside are settled first, so that a reload in the middle
  /// of a change asks for the password of the key the account now has. Then a recovery waiting on
  /// this browser is shown.
  async function start() {
    // A lock turned on or off that a closed page left half way is finished first (device-lock.mjs, settleSwap).
    const swapping = `timecurrency.vault-lock.v1:${net()}:`;
    for (const name of new Set(Object.keys(localStorage).filter(k => k.startsWith(swapping)).map(k => k.slice(swapping.length).split(':')[0]))) {
      try { settleSwap(localStorage, vaultSlots(net(), name), lockPlaces(net(), name)); } catch { /* left for the next start */ }
    }
    for (const name of stagedNames(localStorage, Object.keys(localStorage), net())) {
      try {
        const state = await readState({ names: [name] }), account = state.accounts.find(a => a.name === name); if (!account) continue;
        const row = Array.isArray(state.security) ? security.securityOf(state, account.id) : null;
        const slots = vaultSlots(net(), name);
        if (settleWithProof(slots, account, row, state).includes('signin') || settleLoginRequest(localStorage, slots, account) === 'promoted') c.notice(`The new keys of @${name} are active on this browser. Unlock with the login password chosen for them.`);
      } catch (error) { c.notice(failureNotice(error), 'error'); }
    }
    const saved = progressKeys(); if (!saved.length) return;
    try { await renderLost(parseProgress(localStorage.getItem(saved[0]))); } catch (error) { c.notice(failureNotice(error), 'error'); }
  }
  $('secure-delay').addEventListener('input', () => { $('secure-delay').dataset.touched = 'true'; });
  // A daily limit the person typed, or emptied, is theirs: the suggestion is not put back over it.
  $('secure-limit').addEventListener('input', () => { $('secure-limit').dataset.touched = 'true'; });
  /// "Recover my account" for `name`: the way back when this device lost the key the account's keys here are locked to.
  function recover(name) { $('lost-name').value = name || ''; showLost(true); }
  // What "Move my account to another device" uses on the old device (move-ui.mjs): the payment key opened as everywhere
  // (with the device where the keys are locked), the field that takes the recovery words or a printed sheet, and the
  // wallet's path for security actions (a fresh verified read, the reservation, the receipt).
  const tools = Object.freeze({ withSpend, recoveryPaper, sendSecurity });
  return { tools, stake, stakeAction, stakeLimit, signalAction, signalRefusal, render, withoutDevice, availability, reset, start, pay, payWebsite, loginRefusal, secured, recover, canPay: () => Boolean(c.session()) && secured(c.state(), c.ownAccount()) };
}
