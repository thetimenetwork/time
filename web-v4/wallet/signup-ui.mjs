// Signing up protected, on the start screen (index.html, the form "auth-form" and the steps "signup-sheet-step" and
// "signup-confirm-step"). Only on a network that takes it (signup.mjs, protectedSignup); on any other "Create an account"
// is as it was, and nothing here touches the page.
//
// What the person does, in three steps:
// 1. A name, a login password (every day: opens the wallet, signs in to websites, cannot pay), a payment password (when
//    you pay: up to the daily limit) and the daily limit, 600 seconds unless changed. The wallet checks the name with
//    the network and that the registration service answers, then makes the keys, locks them with the passwords, and
//    makes the two recovery papers. Nothing is kept yet.
// 2. The recovery sheet and the recovery passphrase, shown once, to write down or print: keep safe.
// 3. Two groups of the sheet and the passphrase, typed back. Only then is anything kept in this browser (signup.mjs says
//    what and how), and the account is created through the sponsor (`register`, client.registerProtected). The page then
//    opens it with its new login key (app.js, signupCreated).
//
// Every way the sign-up can stop after step 3 is gone on from by opening the account with its name and its login password
// (app.js, auth): `register` is called again with what was kept, and goes on from what the chain shows.
import * as security from '/sdk/account-security.mjs';
import { newDevice, sealVault, hex, forgetSecret } from './vault.mjs';
import { choosePolicy, checkPasswords, defaultHours, vaultSlots, stageVaults, stagedNote, settleStaged, sealedKey, dateOf, DEFAULT_DAILY_LIMIT_SECONDS, dailyLimitWords } from './security-flows.mjs';
import { makeRecoveryKeys, confirmRecoveryKeys, forgetRecoveryKeys, printSheet, paperSteps } from './papers.mjs';
import { protectedSignup, signNote, readNote, isSignupNote, keysByRole, noteKey, signupWords, tooCloseAddition, CHANGED,
  consentKey, signConsent, readConsent, letGoState, letGoWords, letGoReview, letGoneWords, LET_GO_CHANGED, keptPaymentKey } from './signup.mjs';
import { IDLE_LOCK_MS } from './guards.mjs';

const $ = id => document.getElementById(id);
// While the recovery papers are on the page no account exists, so the lock of an idle wallet (app.js, scheduleIdleLock)
// has nothing to lock. The same rule hides them: after IDLE_LOCK_MS without use the keys and the papers are forgotten, as
// by "Start over", and the person is told. What counts as use is what a person does who is writing the papers down or
// typing them back on this page: a tap or a click (`pointerdown`, also the first touch of a finger), a key (`keydown`), text
// that arrives without a key (`input`: pasting, dictation, a keyboard that composes), and scrolling, by a wheel or a
// trackpad (`wheel`), by a finger (`touchmove`), or by the scroll bar or the keyboard (`scroll`, heard on the way down to
// any element). A pointer that only moves over the page, focus and the page being shown again do not count: they also
// happen when nobody is there, and the lock does not count them either.
export const PAPERS_ACTIVITY = Object.freeze(['pointerdown', 'keydown', 'input', 'wheel', 'scroll', 'touchmove']);
export const PAPERS_IDLE = `Your recovery papers were hidden after ${IDLE_LOCK_MS / 60000} minutes without use, and nothing was created. The papers that were shown will never work: destroy them if you wrote them down. Start again to get new ones.`;
const assert = (value, message) => { if (!value) throw new Error(message); };
/// Reads a secret field once and clears it.
function take(id) { const el = $(id), value = el.value; el.value = ''; return value; }
const scrub = ids => { for (const id of ids) $(id).value = ''; };
const SECRET = ['signup-payment', 'signup-payment-confirm', 'signup-confirm-a', 'signup-confirm-b', 'signup-confirm-phrase'];
export const KEPT = 'Your sign-up is kept in this browser, locked with your passwords. Open your account with its name and your login password to go on. ';
const CREATING = 'Creating your protected account on the network. This takes a few seconds…';

export function createSignupUI(c) {
  const net = () => c.network().networkId, argon = () => c.argon2id(), steps = paperSteps('signup', $);
  // `draft`: what steps 1 and 2 made, in this page's memory only. `drawn`: the page shows the protected form. `shown`: a
  // step of the papers is on the page.
  let draft = null, drawn = false, shown = false;
  // The idle rule while a step of the papers is on the page (PAPERS_ACTIVITY above): `idle` is its timer.
  let idle = null;
  const stillHere = () => { clearTimeout(idle); idle = shown ? setTimeout(idleOut, IDLE_LOCK_MS) : null; };
  function idleOut() { idle = null; if (!shown) return; reset(); c.notice(PAPERS_IDLE); }
  for (const type of PAPERS_ACTIVITY) document.addEventListener(type, () => { if (shown) stillHere(); }, { capture: true, passive: true });

  /// Whether this page makes protected accounts: the network takes them, by the wallet's latest verified state.
  const on = () => protectedSignup(c.sdk, c.state());
  /// The form of "Create an account": the protected one, or as it was. On a network without the setting it is never
  /// touched: `drawn` stays false.
  function form(protect) {
    if (!protect && !drawn) return;
    drawn = protect;
    $('password-label').textContent = protect ? 'Login password' : 'Password';
    $('confirm-label').textContent = protect ? 'Login password again' : 'Password again';
    $('password-note').hidden = protect; $('signup-login-note').hidden = !protect; $('signup-protected').hidden = !protect;
    for (const id of ['signup-payment', 'signup-payment-confirm', 'signup-limit']) $(id).required = protect;
    scrub(['signup-payment', 'signup-payment-confirm']);
    if (!protect) return;
    $('auth-copy').textContent = 'Pick a name, a login password and a payment password. The wallet then makes two recovery papers for you to keep. Your account is protected from its first moment.';
    $('auth-submit').textContent = 'Next: my recovery papers';
    // The daily limit the form suggests comes from one constant (security-flows.mjs), as on Keys; one the person typed stays.
    $('signup-limit-suggested').textContent = `Suggested: ${dailyLimitWords()}.`;
    if ($('signup-limit').dataset.touched !== 'true' && !$('signup-limit').value) $('signup-limit').value = DEFAULT_DAILY_LIMIT_SECONDS;
  }
  /// Steps 1 and 2 forgotten: the keys, the papers and whatever was typed. Nothing of them was kept.
  function reset() {
    clearTimeout(idle); idle = null;
    if (!draft && !shown) return;
    if (draft) { forgetRecoveryKeys(draft); draft.registration.privateKey = draft.signin.key.privateKey = draft.spend.key.privateKey = null; }
    draft = null; shown = false; scrub(SECRET); steps.clear(); $('auth-form').hidden = false;
  }

  // ---------------------------------------------------------------- step 1: name, passwords, limit; keys and papers
  /// Called by app.js (auth) for "Create an account" on a network that takes protected accounts, once the name and the
  /// login password passed the wallet's rules and the wallet's service names a sponsor.
  async function begin({ name, login }) {
    const check = c.capture(), payment = take('signup-payment'), again = take('signup-payment-confirm');
    assert(payment === again, 'The two payment passwords differ.');
    checkPasswords({ login, payment, name });
    const slots = vaultSlots(net(), name);
    c.setBusy(true, 'Checking the name with the network…');
    const state = await c.verifiedState({ names: [name] }); check();
    assert(protectedSignup(c.sdk, state), 'This network does not take accounts that are protected from the start. Reload this page.');
    assert(!state.accounts.some(a => a.name === name), 'That username is already registered.');
    assert(c.storage.getItem(slots.login) === null, 'An encrypted vault already exists for this account here. Unlock it instead.');
    assert(stagedNote(c.storage, slots) === null && c.storage.getItem(slots.nextLogin) === null && c.storage.getItem(slots.nextSpend) === null, 'Keys of an earlier sign-up of this name are still kept in this browser. Choose another name.');
    // The registration service answers, for this network, and sponsors now: else nothing is made, and no papers are shown.
    await c.registrationSponsor(); check();
    const hours = defaultHours(state);
    const policy = choosePolicy({ dailyLimitMicros: c.parseSeconds($('signup-limit').value.trim()), delayHours: hours, freezeHours: hours, threshold: '2', recoveryKeys: 2, feeMicros: c.fee(), minDelayMicros: state.config.recovery_min_delay_micros });
    c.setBusy(true, 'Making your keys and your recovery papers, and locking them with your passwords. This takes a few seconds…');
    // The registration key: it signs the sponsor's consent and the registration, and becomes the account's identity key,
    // on no role. Kept under the login password with the salt of the name, as the key of every new account is.
    const registration = await newDevice(), salt = hex(crypto.getRandomValues(new Uint8Array(32)));
    let registrationRecord;
    try { registrationRecord = await sealVault({ ...registration.secret, nameSalt: salt, intent: 'device' }, login, { networkId: net(), name, publicKey: registration.publicKey }, argon()); } finally { forgetSecret(registration.secret); }
    check();
    const signin = await sealedKey({ password: login, networkId: net(), name, intent: 'signin', argon2id: argon() });
    const spend = await sealedKey({ password: payment, networkId: net(), name, intent: 'spend', argon2id: argon() }); check();
    const papers = await makeRecoveryKeys({ networkId: net(), registrationKey: registration.publicKey, argon2id: argon() }); check();
    reset();
    draft = { name, salt, policy, registration: { publicKey: registration.publicKey, privateKey: registration.privateKey }, registrationRecord, signin, spend, ...papers };
    $('auth-form').hidden = true; shown = true;
    steps.show(draft, `Recovery sheet for @${name} · network ${net().slice(0, 12)}`);
    stillHere();
    c.notice('Write down your recovery sheet and, on another paper, your recovery passphrase. They are shown only now.');
  }

  // ---------------------------------------------------------------- step 2: the papers, then step 3: asked back
  $('signup-print').addEventListener('click', printSheet);
  $('signup-sheet-done').addEventListener('click', () => { if (!draft) return reset(); steps.askBack(draft); });
  $('signup-cancel').addEventListener('click', () => { const had = Boolean(draft); reset(); if (had) c.notice('Nothing was created. The recovery papers that were shown will never work: destroy them if you wrote them down.'); });
  $('signup-limit').addEventListener('input', () => { $('signup-limit').dataset.touched = 'true'; });
  $('signup-submit').addEventListener('click', () => c.run(async () => {
    // The papers are being checked and kept: they are not hidden half way. If they are on the page again after this (a
    // paper typed back wrong, a failure before anything was kept), the idle rule starts again.
    clearTimeout(idle); idle = null;
    try {
      assert(draft, 'Start again from the beginning.');
      const current = draft, check = c.capture();
      try { confirmRecoveryKeys(current, take('signup-confirm-a'), take('signup-confirm-b'), take('signup-confirm-phrase')); }
      catch (error) { steps.show(current); throw error; }
      c.setBusy(true, 'Keeping your new keys in this browser…');
      // Each key accepts its role for this registration key: the papers' keys now, and then they are forgotten.
      const accept = (role, key) => security.acceptRegistrationRole({ networkId: net(), registrationKey: current.registration.publicKey, role, publicKey: key.publicKey, privateKey: key.privateKey });
      const keys = [await accept('signin', current.signin.key), await accept('spend', current.spend.key), await accept('recover', current.sheet), await accept('recover', current.phrase)];
      const note = await signNote({ networkId: net(), name: current.name, registration: current.registration, keys, policy: current.policy }); check();
      await keep(current, note); check();
      // The papers leave the page, and the form they stood in for is back under them: the account is opened next, and
      // when it is locked, or could not be made, the start screen has its name and password fields again. (Seen in a
      // browser on 2026-11-23: after a sign-up, "Lock" showed "Open your account" with no field and no button.)
      draft = null; shown = false; forgetRecoveryKeys(current); current.spend.key.privateKey = null; steps.clear(); $('auth-form').hidden = false;
      await c.created({ name: current.name, registration: current.registration, salt: current.salt, signin: current.signin.key });
    } finally { scrub(SECRET); if (shown) stillHere(); }
  }));
  /// What is kept from now on (signup.mjs): written before anything is sent, all of it or none of it.
  async function keep(current, note) {
    const slots = vaultSlots(net(), current.name), all = [slots.login, slots.nextLogin, slots.nextSpend, slots.nextNote];
    await c.locks().request(`timecurrency:vault:${net()}:${current.name}`, { mode: 'exclusive' }, async () => {
      assert(c.storage.getItem(slots.login) === null, 'An encrypted vault already exists for this account here. Unlock it instead.');
      assert(all.every(key => c.storage.getItem(key) === null), 'Keys of an earlier sign-up of this name are still kept in this browser. Choose another name.');
      try {
        stageVaults(c.storage, slots, { signin: current.signin.record, spend: current.spend.record }, note);
        c.storage.setItem(slots.login, JSON.stringify(current.registrationRecord));
      } catch (error) {
        // Nothing was sent, and every one of these places was empty: what this attempt wrote goes, so that it can be made again.
        for (const key of all) { try { c.storage.removeItem(key); } catch { /* nothing to remove */ } }
        throw error;
      }
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
  /// session's key is the registration key (app.js: after the papers were checked, or the login password opened it).
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
    assert(typeof salt === 'string' && /^[0-9a-f]{64}$/.test(salt), 'Registration salt is unavailable. Unlock your local vault again.');
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
    assert(promoted.includes('signin') && promoted.includes('spend'), 'Your account was made, and this browser could not put its keys in place. Reload this page and open your account with your login password.');
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
  function offer(name) { $('signup-letgo-row').hidden = !staged(name); }
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
    const check = c.capture(), slots = vaultSlots(net(), name), registrationKey = boundKey(slots.login), raw = c.storage.getItem(slots.nextNote);
    let note = null; try { note = await readNote(raw, { networkId: net(), name, registrationKey }); } catch { note = null; }
    check();
    const unchanged = () => note !== null && boundKey(slots.login) === registrationKey && c.storage.getItem(slots.nextNote) === raw && boundKey(slots.nextLogin) === noteKey(note, 'signin') && boundKey(slots.nextSpend) === noteKey(note, 'spend');
    assert(unchanged(), LET_GO_CHANGED);
    // A payment key in the live place of this name is an account's, not this sign-up's.
    assert(c.storage.getItem(slots.spend) === null, keptPaymentKey(name));
    // Each check reads the record of the consent again: another tab that goes on with this sign-up keeps a newer one.
    const decide = async () => {
      const consent = await readConsent(c.storage.getItem(consentKey(net(), name)), { networkId: net(), name, registrationKey }); check();
      const read = await c.client().getVerifiedState({ names: [name], public_keys: [registrationKey] }); check();
      assert(read?.verified === true && read.state?.network_id === net(), 'This browser could not check what the network holds of this sign-up. Nothing was changed.');
      const decided = letGoState({ state: read.state, note, consentExpires: consent, firstNothing: firstSeen?.key === registrationKey ? firstSeen.at : null });
      if (decided.first !== undefined) firstSeen = { key: registrationKey, at: decided.first };
      if (!decided.offer) throw new Error(letGoWords(decided, name, at => dateOf(read.state, at).toLocaleString()));
      return decided;
    };
    await decide();
    if (!await c.review('Let this sign-up go', letGoReview(name), 'Let it go')) { c.notice('Nothing was changed. The sign-up is still kept in this browser.'); return; }
    check();
    // The network is read again: it may hold something of the sign-up now that it did not hold when the review opened.
    await decide();
    await c.locks().request(`timecurrency:vault:${net()}:${name}`, { mode: 'exclusive' }, async () => {
      assert(unchanged() && c.storage.getItem(slots.spend) === null, LET_GO_CHANGED);
      for (const key of [slots.nextLogin, slots.nextSpend, slots.nextNote, consentKey(net(), name), slots.login]) c.storage.removeItem(key);
    });
    firstSeen = null; offer(name);
    c.notice(letGoneWords(name));
  }
  $('signup-letgo').addEventListener('click', () => c.run(letGo));
  /// A refusal in the person's words (signup.mjs), and what follows from it for app.js: `nameRefused` shows the form for a
  /// new account again; `signup` locks the page with the sentence as it is.
  async function explain(error, name) {
    if (c.sdk.isUpgradeRequired?.(error)) return error;
    const words = signupWords(error, name);
    if (words) return Object.assign(new Error(words), { signup: true, nameRefused: error?.code === 'NAME_TAKEN' });
    const refused = await c.nameRefusal(error);
    if (refused?.nameRefused === true) return Object.assign(new Error(refused.message + tooCloseAddition(name)), { signup: true, nameRefused: true });
    return Object.assign(new Error(KEPT + c.failureNotice(error)), { signup: true });
  }

  return { on, form, reset, begin, staged, register, offer };
}
