// Signing up protected, on the start screen (index.html, the form "auth-form" and the step "signup-sheet-step"). Only
// on a network that takes it (signup.mjs, protectedSignup); on any other "Create an account" is as it was, and nothing
// here touches the page.
//
// Managed signup proposes a name and uses the network's usual wallet policy. The local signed registration and
// encrypted private keys are staged before the password manager saves the role passwords and recovery words.
// Only after the manager confirms the offline recovery copy and durable save does registration start. The
// manual flow keeps the existing choice of sealing methods and confirms the paper recovery copy in the wallet.
import * as security from '/sdk/account-security.mjs';
import { newDevice, hex, forgetSecret } from './vault.mjs';
import { choosePolicy, checkPasswords, defaultHours, vaultSlots, stageVaults, stagedNote, settleStaged, dateOf, DEFAULT_DAILY_LIMIT_SECONDS, rememberRecoveryKind, sealedKeys } from './security-flows.mjs';
import { newKeysByRule, LOCK_WORDS } from './device-lock.mjs';
import { wayChoice } from './device-lock-ui.mjs';
import { makeRecoveryKeys, forgetRecoveryKeys, paperSteps, WRITE_NOW } from './papers.mjs';
import { protectedSignup, signNote, readNote, isSignupNote, keysByRole, noteKey, signupWords, tooCloseAddition, CHANGED,
  consentKey, signConsent, readConsent, letGoState, letGoWords, letGoReview, letGoneWords, LET_GO_CHANGED, keptPaymentKey } from './signup.mjs';
import { IDLE_LOCK_MS } from './guards.mjs';

const $ = id => document.getElementById(id);
// While the step of the recovery words is on the page no account exists, so the lock of an idle wallet (app.js,
// scheduleIdleLock) has nothing to lock. The same rule closes the step: after IDLE_LOCK_MS without use the keys and the
// words are forgotten, as by "Start over", and the person is told. What counts as use is what a person does who
// is writing the words down on this page: a tap or a click (`pointerdown`, also the first touch of a
// finger), a key (`keydown`), text that arrives without a key (`input`: pasting, dictation, a keyboard that composes), and
// scrolling, by a wheel or a trackpad (`wheel`), by a finger (`touchmove`), or by the scroll bar or the keyboard
// (`scroll`, heard on the way down to any element). A pointer that only moves over the page, focus and the page being
// shown again do not count: they also happen when nobody is there, and the lock does not count them either.
export const PAPERS_ACTIVITY = Object.freeze(['pointerdown', 'keydown', 'input', 'wheel', 'scroll', 'touchmove']);
export const PAPERS_IDLE = `Your recovery words were hidden after ${IDLE_LOCK_MS / 60000} minutes without use, and nothing was created. They will never work: destroy the paper if you wrote them down. Start again to get new ones.`;
/// "Start over" after the words were shown.
export const DROPPED = 'Nothing was created. The recovery words that were shown will never work: destroy the paper if you wrote them down.';
const assert = (value, message) => { if (!value) throw new Error(message); };
/// Reads a secret field once and clears it.
function take(id) { const el = $(id), value = el.value; el.value = ''; return value; }
const scrub = ids => { for (const id of ids) $(id).value = ''; };
const SECRET = ['signup-payment', 'signup-payment-confirm'];
export const KEPT = 'Your sign-up is kept in this browser, locked with your passwords. Open your account with its name and your login password to go on. ';
const CREATING = 'Creating your protected account on the network. This takes a few seconds…';

export function createSignupUI(c) {
  const net = () => c.network().networkId, argon = () => c.argon2id(), steps = paperSteps('signup', $);
  // `draft`: what step 1 made, in this page's memory only. `drawn`: the page shows the protected form. `shown`: the step
  // of the recovery words is on the page.
  let draft = null, drawn = false, shown = false, useManager = false, activeManager = null, suggestedName = null;
  let firstForm = true;
  const nameHelp = $('username-note').textContent;
  const managerPlace = name => `timecurrency.manager.v1:${net()}:${name}`;
  // This is a UI hint, never an authorization. Role keys can rotate. The registration public key is the
  // account's durable identity. Before a proof is available, the paired manager can be offered for a local
  // record of this network/name; opening it still requires the right password and the wallet's authority checks.
  function managed(name) {
    if (!name || !c.network()?.networkId) return false;
    try {
      const marker = JSON.parse(c.storage.getItem(managerPlace(name)));
      if (!/^[0-9a-f]{64}$/.test(marker?.registration) || !/^[0-9a-f]{64}$/.test(marker?.signin)) return false;
      const binding = JSON.parse(c.storage.getItem(vaultSlots(net(), name).login))?.binding;
      if (binding?.networkId !== net() || binding.name !== name) return false;
      const account = c.state()?.accounts?.find(item => item.name === name);
      if (account) return account.public_key === marker.registration;
      if (staged(name)) return binding.publicKey === marker.registration;
      return true;
    } catch { return false; }
  }
  // The idle rule while the step of the recovery words is on the page (PAPERS_ACTIVITY above): `idle` is its timer.
  let idle = null;
  const stillHere = () => { clearTimeout(idle); idle = shown ? setTimeout(idleOut, IDLE_LOCK_MS) : null; };
  function idleOut() { idle = null; if (!shown) return; reset(); c.notice(PAPERS_IDLE); }
  for (const type of PAPERS_ACTIVITY) document.addEventListener(type, () => { if (shown) stillHere(); }, { capture: true, passive: true });

  /// Whether this page makes protected accounts: the network takes them, by the wallet's latest verified state.
  const on = () => protectedSignup(c.sdk, c.state());
  // How the keys of a sign-up are sealed (the rule), as the person chose it (device-lock-ui.mjs, wayChoice): 'asking' (the
  // browser has not said yet what the device can do: the form does not go on), 'none' (the device can lock keys, and no
  // way is chosen yet: the form does not go on), 'device' (locked to this device from birth, the passwords chosen),
  // 'declined' (the wallet makes the passwords) or 'made' (this device cannot lock keys).
  const SEALING = Object.freeze({
    asking: 'Pick a name. The wallet then shows five recovery words for you to write on paper. Your account is protected from its first moment.',
    none: 'Pick a name and how to lock your keys. The wallet then shows five recovery words for you to write on paper. Your account is protected from its first moment.',
    device: 'Pick a name, a login password and a payment password: your device locks your keys with them. The wallet then shows five recovery words for you to write on paper. Your account is protected from its first moment.',
    declined: 'Pick a name. The wallet makes your login password and your payment password and shows them to you, then five recovery words for you to write on paper. Your account is protected from its first moment.',
    made: 'Pick a name. The wallet makes your login password and your payment password and shows them to you, then five recovery words for you to write on paper. Your account is protected from its first moment.',
  });
  /// The fields of the protected form for how its keys are sealed: the chosen passwords only once the lock is chosen.
  const sealing = wayChoice('auth', { env: () => c.env?.(), drawn: mode => {
    const typed = mode === 'device';
    c.typedPassword?.(typed, typed);
    $('signup-chosen').hidden = !typed; $('signup-login-note').hidden = !typed;
    for (const id of ['signup-payment', 'signup-payment-confirm']) $(id).required = typed;
    if (!typed) scrub(['password', 'password-confirm', ...SECRET]);
    $('auth-copy').textContent = SEALING[mode];
  } });
  /// The form of "Create an account": the protected one, or as it was. On a network without the setting it is never
  /// touched: `drawn` stays false.
  function form(protect) {
    const initialName = firstForm ? $('username').value.replace(/^@/, '') : '';
    firstForm = false;
    if (!protect && !drawn) return;
    drawn = protect;
    useManager = protect && Boolean(c.managerAvailable?.());
    $('signup-method').hidden = !useManager;
    $('signup-manual-note').hidden = !protect || useManager;
    if (useManager) {
      const newName = /^[a-z0-9_]{2,15}$/.test(initialName) && c.storage.getItem(vaultSlots(net(), initialName).login) === null;
      if (!newName) {
        suggestedName = 'time_' + hex(crypto.getRandomValues(new Uint8Array(5)));
        $('username').value = suggestedName;
      }
    } else if (suggestedName) {
      if ($('username').value === suggestedName && !managed(suggestedName)) $('username').value = '';
      suggestedName = null;
    }
    drawForm(protect);
  }
  function drawForm(protect) {
    $('username-note').textContent = useManager ? 'Use this public name or choose your own.' : nameHelp;
    $('password-label').textContent = protect ? 'Login password' : 'Password';
    $('confirm-label').textContent = protect ? 'Login password again' : 'Password again';
    $('signup-login-note').hidden = !protect || useManager; $('signup-protected').hidden = !protect || useManager;
    for (const id of ['signup-payment', 'signup-payment-confirm']) $(id).required = false;
    scrub(['signup-payment', 'signup-payment-confirm']);
    if (!protect) { sealing.forget(); return; }
    $('signup-method').textContent = useManager ? 'Set up manually' : 'Use password manager';
    if (useManager) {
      sealing.forget();
      c.typedPassword(false, false);
      scrub(['password', 'password-confirm']);
      $('auth-seal-note').hidden = $('auth-ways').hidden = true;
      $('auth-copy').textContent = 'Time Vault saves your wallet passwords and recovery words. Unlock them with your device and one master password.';
      $('auth-submit').textContent = 'Create account';
      return;
    }
    $('auth-submit').textContent = 'Next: my recovery words';
    // What the browser says it can do (it asks the person nothing): where the device can lock keys, the choice of the two
    // ways once it has said, with neither chosen.
    sealing.redraw();
  }
  $('signup-method').addEventListener('click', () => {
    if (!drawn || !c.managerAvailable?.() || activeManager) return;
    useManager = !useManager;
    drawForm(true);
  });
  /// Steps 1 and 2 forgotten: the keys, the words and whatever was typed. Nothing of them was kept.
  function reset() {
    clearTimeout(idle); idle = null;
    activeManager?.close(); activeManager = null;
    if (!draft && !shown) return;
    if (draft) { forgetRecoveryKeys(draft); draft.registration.privateKey = draft.signin.key.privateKey = draft.spend.key.privateKey = null; draft.registration.storageKey = draft.signin.storageKey = null; }
    draft = null; shown = false; scrub(SECRET); steps.clear(); $('auth-form').hidden = false;
  }
  window.addEventListener('pagehide', reset);

  // ---------------------------------------------------------------- step 1: name and credentials
  /// Called by app.js (auth) for "Create an account" on a network that takes protected accounts, once the name and the
  /// login password passed the wallet's rules and the wallet's service names a sponsor.
  async function begin({ name, login, again: loginAgain }) {
    // Opening the manager must happen within the original submit gesture, before a network read or key derivation.
    const manager = useManager ? c.startManager() : null;
    assert(!useManager || manager, 'Allow pop-ups for this wallet to open Time Vault, or choose Set up manually.');
    activeManager = manager;
    try { await prepare({ name, login, loginAgain, manager }); }
    finally { manager?.close(); if (activeManager === manager) activeManager = null; }
  }
  async function prepare({ name, login, loginAgain, manager }) {
    // Nothing is read or made before the browser said what the device can do and, where it can lock keys, the person chose
    // a way (LOCK_WORDS.ways.asking, .pick).
    if (!manager) sealing.ready();
    const check = c.capture(), payment = take('signup-payment'), again = take('signup-payment-confirm'), byDevice = !manager && sealing.byDevice;
    // The passwords a person chose are used only with the device (the rule); where the wallet makes them, nothing typed is.
    if (byDevice) {
      assert(login === loginAgain, 'Enter the same login password in both login fields.');
      assert(payment === again, 'Enter the same payment password in both payment fields.');
      checkPasswords({ login, payment, name });
    }
    const slots = vaultSlots(net(), name);
    c.setBusy(true, 'Checking the name with the network…');
    const state = await c.verifiedState({ names: [name] }); check();
    assert(protectedSignup(c.sdk, state), 'This network does not take accounts that are protected from the start. Reload this page.');
    assert(!state.accounts.some(a => a.name === name), 'That username is already registered.');
    assert(c.storage.getItem(slots.login) === null, 'An encrypted vault already exists for this account here. Unlock it instead.');
    assert(stagedNote(c.storage, slots) === null && c.storage.getItem(slots.nextLogin) === null && c.storage.getItem(slots.nextSpend) === null, 'Keys of an earlier sign-up of this name are still kept in this browser. Choose another name.');
    // The registration service answers, for this network, and sponsors now: else nothing is made, and no recovery key is shown.
    await c.registrationSponsor(); check();
    const hours = defaultHours(state);
    const policy = choosePolicy({ dailyLimitMicros: c.parseSeconds(DEFAULT_DAILY_LIMIT_SECONDS), delayHours: hours, freezeHours: hours, threshold: '2', recoveryKeys: 2, feeMicros: c.fee(), minDelayMicros: state.config.recovery_min_delay_micros });
    c.setBusy(true, byDevice ? 'Making your keys and your recovery words, and locking the keys to this device. This takes a few seconds…' : 'Making your keys, your passwords and your recovery words. This takes a few seconds…');
    // The registration key: it signs the sponsor's consent and the registration, and becomes the account's identity key,
    // on no role. Kept, with the salt of the name, under the new login key (vault version 4: the rule), which the login
    // password opens (with the device when the keys are locked to it). With its storage key: it opens what the sign-up's
    // receipts leave in the private store (app.js, signupCreated).
    const registration = await newDevice(globalThis.crypto, { networkId: net(), name }), salt = hex(crypto.getRandomValues(new Uint8Array(32)));
    let made;
    try {
      // Locked to this device from birth, or under passwords the wallet makes (device-lock.mjs, newKeysByRule): a device
      // that fails at any step does not end the sign-up; the wallet makes the passwords instead, and says what happened.
      const options = { networkId: net(), name, argon2id: argon(), under: { secret: { ...registration.secret, nameSalt: salt, intent: 'device' }, binding: { networkId: net(), name, publicKey: registration.publicKey } } };
      made = manager
        ? { keys: await sealedKeys({ ...options, wanted: [{ intent: 'signin' }, { intent: 'spend' }], askForExtraRandomness: false }), locked: false }
        : await newKeysByRule({ ...options, byDevice, storage: c.storage, env: c.env?.(), wanted: [{ intent: 'signin', password: login }, { intent: 'spend', password: payment }], say: text => c.notice(text, 'busy') });
    } finally { forgetSecret(registration.secret); }
    check();
    const [signin, spend] = made.keys;
    let papers = null;
    try {
      // Words only: both recovery keys come from the words (security-flows.mjs, recoveryWordsSecondKey).
      c.setBusy(true, 'Making your recovery words. This takes a few seconds…');
      papers = await makeRecoveryKeys({ networkId: net(), registrationKey: registration.publicKey, argon2id: argon(), kind: 'words' }); check();
      // The passwords the wallet made are shown once, before anything is kept: only "I have them" goes on to the recovery
      // words. Closed any other way (made-dialog.mjs), the step ends here and nothing was kept.
      if (!manager && !made.locked) {
        c.setBusy(false);
        await c.showMade({ name, login: signin.made, payment: spend.made, why: made.fallback ?? (byDevice ? LOCK_WORDS.fellBack : 'The wallet made the passwords of your new account. Let your browser save the login password; write the payment password down, apart from your recovery words.') });
        check();
      }
    } catch (error) {
      // Nothing of this sign-up stays in memory: its keys, the registration key and the recovery keys.
      if (papers) forgetRecoveryKeys(papers);
      registration.privateKey = signin.key.privateKey = spend.key.privateKey = null; registration.storageKey = signin.storageKey = spend.storageKey = null;
      throw error;
    }
    const current = { name, salt, policy, locked: made.locked, registration: { publicKey: registration.publicKey, privateKey: registration.privateKey, storageKey: registration.storageKey }, registrationRecord: signin.under, signin, spend, ...papers };
    papers = null;
    if (manager) {
      try {
        const stagedKeys = await stage(current, check, true);
        c.setBusy(true, 'Finish setup in Time Vault.');
        try {
          await manager.save({ networkId: net(), name, secrets: { signin: signin.made, spend: spend.made, recover: current.phraseText } });
        } catch (error) {
          if (error?.unsaved === true) await discardUnsaved(current, stagedKeys);
          else throw new Error(`Setup was interrupted while Time Vault was saving your passwords. Choose Open my account and try opening @${name} with Time Vault. If the vault has no entry for it, create an account with another name.`);
          throw error;
        }
        signin.made = spend.made = null;
        check();
        await finish(current, true);
      } finally {
        forgetRecoveryKeys(current);
        signin.made = spend.made = null;
        registration.privateKey = registration.storageKey = current.registration.privateKey = current.registration.storageKey = null;
        signin.key.privateKey = signin.storageKey = spend.key.privateKey = null;
      }
      return;
    }
    draft = current;
    $('auth-form').hidden = true; shown = true;
    steps.show(draft);
    stillHere();
    c.notice(WRITE_NOW);
  }

  // ---------------------------------------------------------------- step 2: the recovery words, on paper
  $('signup-cancel').addEventListener('click', () => { const had = Boolean(draft); reset(); if (had) c.notice(DROPPED); });
  $('signup-submit').addEventListener('click', () => c.run(async () => {
    // The keys are being kept: the step is not closed half way. If it is still on the page after this (a failure before
    // anything was kept), the idle rule starts again.
    clearTimeout(idle); idle = null;
    try {
      assert(draft, 'Start again from the beginning.');
      const current = draft;
      await stage(current, c.capture(), false);
      await finish(current, false);
    } finally { scrub(SECRET); if (shown) stillHere(); }
  }));
  async function stage(current, check, forManager) {
    c.setBusy(true, 'Keeping your new keys in this browser…');
    const accept = (role, key) => security.acceptRegistrationRole({ networkId: net(), registrationKey: current.registration.publicKey, role, publicKey: key.publicKey, privateKey: key.privateKey });
    const keys = [await accept('signin', current.signin.key), await accept('spend', current.spend.key), await accept('recover', current.sheet), await accept('recover', current.phrase)];
    const note = await signNote({ networkId: net(), name: current.name, registration: current.registration, keys, policy: current.policy }); check();
    const stagedKeys = await keep(current, note, forManager);
    try { check(); } catch (error) {
      if (forManager) await discardUnsaved(current, stagedKeys);
      throw error;
    }
    return stagedKeys;
  }
  async function finish(current, fromManager) {
    rememberRecoveryKind(c.storage, net(), current.name, current);
    draft = null; shown = false; forgetRecoveryKeys(current); current.spend.key.privateKey = null;
    steps.clear(); $('auth-form').hidden = false;
    await c.created({ name: current.name, registration: current.registration, salt: current.salt, signin: { ...current.signin.key, storageKey: current.signin.storageKey }, managed: fromManager });
  }
  /// What is kept from now on (signup.mjs): written before anything is sent, all of it or none of it.
  async function keep(current, note, forManager) {
    const slots = vaultSlots(net(), current.name), all = [slots.login, slots.nextLogin, slots.nextSpend, slots.nextNote];
    return c.locks().request(`timecurrency:vault:${net()}:${current.name}`, { mode: 'exclusive' }, async () => {
      assert(c.storage.getItem(slots.login) === null, 'An encrypted vault already exists for this account here. Unlock it instead.');
      assert(all.every(key => c.storage.getItem(key) === null), 'Keys of an earlier sign-up of this name are still kept in this browser. Choose another name.');
      try {
        stageVaults(c.storage, slots, { signin: current.signin.record, spend: current.spend.record }, note);
        c.storage.setItem(slots.login, JSON.stringify(current.registrationRecord));
        if (forManager) {
          all.push(managerPlace(current.name));
          c.storage.setItem(managerPlace(current.name), JSON.stringify({ registration: current.registration.publicKey, signin: current.signin.key.publicKey }));
          return all.map(key => [key, c.storage.getItem(key)]);
        }
      } catch (error) {
        // Nothing was sent, and every one of these places was empty: what this attempt wrote goes, so that it can be made again.
        for (const key of all) { try { c.storage.removeItem(key); } catch { /* nothing to remove */ } }
        throw error;
      }
    });
  }
  // Roll back only when the manager positively refused the save. A lost acknowledgment or closed tab can
  // follow a successful write on the other origin, in which case these records are needed to resume.
  async function discardUnsaved(current, stagedKeys) {
    const { name } = current;
    await c.locks().request(`timecurrency:vault:${net()}:${name}`, { mode: 'exclusive' }, async () => {
      if (!stagedKeys.every(([key, value]) => c.storage.getItem(key) === value)) return;
      if (c.storage.getItem(consentKey(net(), name)) !== null) return;
      for (const [key] of stagedKeys) c.storage.removeItem(key);
    });
  }

  // ---------------------------------------------------------------- the registration, first time and every time after
  /// Whether a sign-up of `name` is kept in this browser: a note of a sign-up beside staged keys, and in the login place
  /// the vault of that note's registration key (and `registrationKey`, when given, is that key).
  function staged(name, registrationKey) {
    if (typeof name !== 'string' || !/^[a-z0-9_]{2,15}$/.test(name)) return false;
    const slots = vaultSlots(net(), name), note = stagedNote(c.storage, slots);
    if (!isSignupNote(note)) return false;
    let held = null; try { held = JSON.parse(c.storage.getItem(slots.login))?.binding?.publicKey ?? null; } catch { held = null; }
    return held !== null && held === note.registration && (registrationKey === undefined || registrationKey === held);
  }
  /// Creates the account from what is kept, or goes on from what the chain shows, and puts its new keys in place. The
  /// session's key is the registration key (app.js: after the keys were kept, or the login password opened it).
  async function register({ name, registration, salt, check }) {
    const slots = vaultSlots(net(), name);
    // What was kept is used only as it was kept (signup.mjs, readNote): else nothing is sent, and going on cannot help.
    const changed = () => Object.assign(new Error(CHANGED), { signup: true });
    let note = null; try { note = await readNote(c.storage.getItem(slots.nextNote), { networkId: net(), name, registrationKey: registration.publicKey }); } catch { note = null; }
    check();
    if (!note) throw changed();
    // The keys kept aside are the note's: else the account would be made with keys this browser cannot open.
    const kept = key => { try { return JSON.parse(c.storage.getItem(key))?.binding?.publicKey ?? null; } catch { return null; } };
    if (kept(slots.nextLogin) !== noteKey(note, 'signin') || kept(slots.nextSpend) !== noteKey(note, 'spend')) throw changed();
    assert(typeof salt === 'string' && /^[0-9a-f]{64}$/.test(salt), 'The wallet could not read your saved signup details. Choose Open my account and unlock it again in this browser.');
    let made;
    try {
      // A sponsor is asked only when the chain holds neither the account nor a commitment of this key: the SDK pays once.
      // Where it holds one, no sponsor is passed. If the commitment is gone by the time the SDK reads the chain, the SDK
      // says so (SPONSOR_REQUIRED) before it signs anything, and the registration service is asked then.
      const state = await c.verifiedState(); check();
      const begun = state.accounts.some(a => a.name === name) || (state.name_commits || []).some(item => item.public_key === registration.publicKey);
      // The expiry of every consent the registration key signs is kept before the consent leaves this browser (signup.mjs,
      // "letting a kept sign-up go"). If it cannot be kept, nothing is signed or sent.
      const onConsent = ({ expiresElapsedMicros }) => keepConsent(name, registration, expiresElapsedMicros);
      const args = { name, salt, registration, keys: keysByRole(note), dailyLimitMicros: note.policy.daily_limit_micros, delaySeconds: note.policy.delay_seconds, freezeSeconds: note.policy.freeze_seconds, threshold: note.policy.threshold, onConsent };
      const sponsored = async () => { const sponsor = await c.registrationSponsor(); check(); c.setBusy(true, CREATING); return c.client().registerProtected({ ...args, sponsor }); };
      if (!begun) made = await sponsored();
      else {
        c.setBusy(true, CREATING);
        try { made = await c.client().registerProtected(args); } catch (error) { if (error?.code !== 'SPONSOR_REQUIRED') throw error; check(); made = await sponsored(); }
      }
    } catch (error) { throw await explain(error, name); }
    check();
    if (made.sponsorReceipt) c.record(made.sponsorReceipt, 'Name reserved for you (sponsored)');
    if (made.receipt) c.record(made.receipt, 'Account created, protected from its first block');
    // The chain holds the new keys: they take the places of the live keys, and the registration key is overwritten.
    const promoted = settleStaged(c.storage, slots, made.account);
    assert(promoted.includes('signin') && promoted.includes('spend'), `Your account was created, but this browser could not finish saving your keys. Reload the wallet, choose Open my account, and open @${name} with ${managed(name) ? 'Time Vault' : 'your login password'}.`);
    try { c.storage.removeItem(consentKey(net(), name)); } catch { /* it is used only to let a sign-up go, which an account refuses */ }
    return made;
  }
  /// Keeps the expiry of a consent the registration key is about to sign, signed by that key: the latest one is kept.
  async function keepConsent(name, registration, expiresElapsedMicros) {
    const key = consentKey(net(), name);
    const before = await readConsent(c.storage.getItem(key), { networkId: net(), name, registrationKey: registration.publicKey });
    if (before !== null && before >= BigInt(expiresElapsedMicros)) return;
    c.storage.setItem(key, JSON.stringify(await signConsent({ networkId: net(), name, registration, expiresElapsedMicros })));
  }

  // ---------------------------------------------------------------- letting a kept sign-up go
  /// The public key a kept vault is bound to, or null.
  const boundKey = key => { try { return JSON.parse(c.storage.getItem(key))?.binding?.publicKey ?? null; } catch { return null; } };
  /// "Let this sign-up go" is shown under the form while its name is that of a sign-up this browser keeps.
  function offer(name) {
    $('signup-letgo-row').hidden = !staged(name);
    $('signup-letgo-intro').textContent = managed(name) ? 'Trouble opening this signup with Time Vault?' : 'Forgot the login password you chose for this sign-up?';
  }
  // The chain's time of the first reading on this page that showed nothing of a sign-up without a record of its consent
  // (signup.mjs, letGoState): in this page's memory only, so that nothing written to the storage can shorten the wait.
  let firstSeen = null;
  /// Lets the kept sign-up of the name typed go, after the network was read and the person confirmed. Nothing is removed
  /// on the word of what this browser stores: the note must be the one the registration key signed, every place must
  /// still hold what it held when it was checked, and a state of the network verified now must show that nothing of the
  /// sign-up can be on it (signup.mjs, letGoState), before the review and again after it.
  async function letGo() {
    const name = $('username').value.trim().replace(/^@/, '');
    assert(staged(name), 'This browser keeps no unfinished sign-up of that name. Type the name you signed up with.');
    const fromManager = managed(name);
    const check = c.capture(), slots = vaultSlots(net(), name), registrationKey = boundKey(slots.login), raw = c.storage.getItem(slots.nextNote);
    let note = null; try { note = await readNote(raw, { networkId: net(), name, registrationKey }); } catch { note = null; }
    check();
    const unchanged = () => note !== null && boundKey(slots.login) === registrationKey && c.storage.getItem(slots.nextNote) === raw && boundKey(slots.nextLogin) === noteKey(note, 'signin') && boundKey(slots.nextSpend) === noteKey(note, 'spend');
    assert(unchanged(), LET_GO_CHANGED);
    // A payment key in the live place of this name is an account's, not this sign-up's.
    assert(c.storage.getItem(slots.spend) === null, keptPaymentKey(name, managed(name)));
    // Each check reads the record of the consent again: another tab that goes on with this sign-up keeps a newer one.
    const decide = async () => {
      const consent = await readConsent(c.storage.getItem(consentKey(net(), name)), { networkId: net(), name, registrationKey }); check();
      const read = await c.client().getVerifiedState({ names: [name], public_keys: [registrationKey] }); check();
      assert(read?.verified === true && read.state?.network_id === net(), 'This browser could not check what the network holds of this sign-up. Nothing was changed.');
      const decided = letGoState({ state: read.state, note, consentExpires: consent, firstNothing: firstSeen?.key === registrationKey ? firstSeen.at : null });
      if (decided.first !== undefined) firstSeen = { key: registrationKey, at: decided.first };
      if (!decided.offer) throw new Error(letGoWords(decided, name, at => dateOf(read.state, at).toLocaleString(), managed(name)));
      return decided;
    };
    await decide();
    if (!await c.review('Let this sign-up go', letGoReview(name), 'Let it go')) { c.notice('Nothing was changed. The sign-up is still kept in this browser.'); return; }
    check();
    // The network is read again: it may hold something of the sign-up now that it did not hold when the review opened.
    await decide();
    await c.locks().request(`timecurrency:vault:${net()}:${name}`, { mode: 'exclusive' }, async () => {
      assert(unchanged() && c.storage.getItem(slots.spend) === null, LET_GO_CHANGED);
      for (const key of [slots.nextLogin, slots.nextSpend, slots.nextNote, consentKey(net(), name), slots.login, managerPlace(name)]) c.storage.removeItem(key);
    });
    firstSeen = null; offer(name);
    c.notice(letGoneWords(name) + (fromManager ? ' The old entry in Time Vault belongs to the abandoned signup. Use a new name for your next signup.' : ''));
  }
  $('signup-letgo').addEventListener('click', () => c.run(letGo));
  /// A refusal in the person's words (signup.mjs), and what follows from it for app.js: `nameRefused` shows the form for a
  /// new account again; `signup` locks the page with the sentence as it is.
  async function explain(error, name) {
    if (c.sdk.isUpgradeRequired?.(error)) return error;
    const withVault = managed(name);
    const words = signupWords(error, name, withVault);
    if (words) return Object.assign(new Error(words), { signup: true, nameRefused: error?.code === 'NAME_TAKEN' });
    const refused = await c.nameRefusal(error);
    if (refused?.nameRefused === true) return Object.assign(new Error(refused.message + tooCloseAddition(name)), { signup: true, nameRefused: true });
    return Object.assign(new Error((withVault ? `Your signup is saved in this browser. Open @${name} with Time Vault to finish. ` : KEPT) + c.failureNotice(error)), { signup: true });
  }

  return { on, form, reset, begin, staged, register, offer, managed };
}
