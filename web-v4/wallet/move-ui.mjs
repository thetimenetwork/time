// The pages of "Move my account to another device" (device-move.mjs holds every decision; this module reads the fields,
// says what happens, and calls it).
//
// - The new device, on the start screen: "Move my account here". The name; the account read in a verified state; the
//   browser asked whether what this page keeps lasts (lastingStorage), and the warning said where it may not; the new keys
//   made by the rule, as a sign-up makes them (device-lock.mjs, newKeysByRule: where the device can lock keys, locked to it
//   from birth or under passwords the wallet makes, as the person chooses, neither chosen beforehand: device-lock-ui.mjs,
//   wayChoice; else under passwords the wallet makes; made passwords are shown before anything they seal is kept); then
//   the request, in one field with a Copy button, and the code in four groups. Each stage the module returns has its
//   sentence. "Withdraw" while it waits. When the move lands, the account opens as after a sign-up: with the new login key
//   this page still holds, or, after a reload, with the login password. A request that waits is found again at the
//   start of the page, before any unlock.
// - The old device, on Keys of a protected account whose login key and payment key are both in this browser: "Move my
//   account to another device". The request pasted; what the module checked, said from `shown` (never from the request's
//   own text); the code typed under MOVE_WORDS.onlyYours; the payment password (and the device, where the keys are locked)
//   and the recovery words or a printed recovery sheet; a review of what happens at once; the replacement sent through
//   the wallet's path for security actions, noted before it is sent (rememberMove); and, after the receipt, the status
//   read until this browser forgot its keys, ending on the locked start screen. The page never shows the code it expects
//   and never shows the request back.
//
// Every text goes in by textContent. No secret is kept in a field after its step: the passwords and the recovery words
// are read once and their fields emptied however the step ends.
import { createDeviceMove, lastingStorage, moveSlots, MOVE_WORDS, moveWindowEnd } from './device-move.mjs';
import { newKeysByRule } from './device-lock.mjs';
import { wayChoice } from './device-lock-ui.mjs';
import { vaultSlots, checkPasswords, waitsOf, elapsedOf, dateOf, STAGED_PREFIX } from './security-flows.mjs';
import { openVault, validateName } from './vault.mjs';
import * as security from '/sdk/account-security.mjs';

const $ = id => document.getElementById(id);
const assert = (value, message) => { if (!value) throw new Error(message); };
/// The fields of the move that take a password or the recovery words: read once, emptied however the step ends.
export const MOVE_FIELDS = Object.freeze(['move-login', 'move-login-confirm', 'move-payment', 'move-payment-confirm', 'move-old-payment', 'move-old-secret']);
/// How often the new device reads the network while its request waits.
export const MOVE_CHECK_MS = 10000;

/// What the person reads on each device.
export const MOVE_PAGE_WORDS = Object.freeze({
  // The new device (what does not change stands in index.html, #move-panel).
  copied: 'The request was copied. Paste it on your other device, under Keys.',
  making: 'Making your new keys and their passwords. This takes a few seconds…',
  locking: 'Locking your new keys to this device. This takes a few seconds…',
  madeWhy: 'The wallet made the passwords of your new keys. Let your browser save the login password; write the payment password down now, apart from your recovery words. They are shown only now.',
  fleetingTitle: 'This browser may not keep your new keys',
  fleetingGo: 'Go on here',
  ready: 'Your request is ready. Copy it to your other device, and type the code there.',
  noAccount: 'No account has that name.',
  // What each stage of the new device says (device-move.mjs, resumeMove and withdrawMove).
  waiting: until => `Waiting for your other device. This request works until ${until}.`,
  stale: 'The keys of your account changed after this request was made, so your other device will refuse it. Withdraw it and make a new one.',
  closing: until => `This request has expired. If your other device sent the move just before, it can still arrive until ${until}, so this browser keeps its new keys until then.`,
  withdrawn: until => `You withdrew the request. This browser keeps its new keys until ${until}, in case your other device sent the move already.`,
  settled: 'Your account is here now. The keys of your other device no longer work.',
  settledOpen: name => `Your account is here now. Open @${name} with your new login password.`,
  mixed: 'Your account is here, and it also has other payment or login keys that this request did not name. Look at your keys under Keys, and replace them if you do not know them.',
  mixedOpen: name => `Your account is here, and it also has other payment or login keys that this request did not name. Open @${name} with your new login password, then look at your keys under Keys, and replace them if you do not know them.`,
  // The account holds the payment key of this request but not its login key: this browser has no key that opens it.
  noLogin: name => `The move arrived, but @${name} does not have the login key this browser made for it, so this browser cannot open the account. If you did not change its keys yourself, someone else may have: recover your account with your recovery words.`,
  damaged: 'This browser cannot read the new keys it kept for this request. Do not finish the move on your other device. Withdraw this request and make a new one.',
  damagedLanded: 'The move arrived, but this browser cannot read one of the new keys it kept. Leave this browser as it is and try again later. If it stays so, recover your account with your recovery words.',
  expired: 'The request expired, and nothing can arrive any more. This browser forgot its new keys. Make a new request if you still want to move.',
  forgotten: 'The request was withdrawn, and this browser forgot its new keys.',
  unread: 'The network cannot be read right now. This browser keeps the request and its keys, and checks again.',
  unreadDamaged: 'The network cannot be read right now, and this browser cannot read the new keys it kept. Do not finish the move on your other device.',
  // The old device (index.html, #move-card).
  checked: 'This request is from your other device, for this account. Next, type the code your other device shows.',
  codeOk: 'The code matches. Next, your payment password and your recovery words.',
  moving: 'Moving your account. Waiting for the network…',
  forgetting: 'Your account moved. This browser is forgetting its keys…',
  done: name => `@${name} is on your other device now. This browser forgot its keys, and they no longer work.`,
  stillMoving: name => `The move of @${name} was sent. This browser forgets its keys as soon as the network shows the move.`,
  mixedKeep: MOVE_WORDS.mixedKeep,
  sentWaiting: MOVE_WORDS.sentWaiting,
});

/// `c`: { sdk, network(), state(), verifiedState(input), session(), notice, setBusy, run, review, capture, fee(), seconds(v),
/// storage, locks(), env(), argon2id(), storageManager(), showMade, showUnlock(name), opened({ name, signin }), lock(text),
/// refresh(), tools: { withSpend, recoveryPaper, sendSecurity } (security-ui.mjs) }.
export function createMoveUI(c) {
  const dm = createDeviceMove({ security, locks: null });
  const net = () => c.network().networkId;
  const locks = () => c.locks();
  const take = id => { const el = $(id), value = el.value; el.value = ''; return value; };
  const scrub = () => { for (const id of MOVE_FIELDS) $(id).value = ''; };
  const when = (state, micros) => dateOf(state, micros).toLocaleString();
  // The new device: the name whose request is shown, the login key this page holds to open the account when the move
  // lands (null after a reload: the login password opens it then), and the timer that reads the network meanwhile.
  let shownName = null, held = null, timer = null, checking = false;
  // The old device: the request checked, and whether its code was typed right, for the account open.
  let pasted = null;

  // ---------------------------------------------------------------- how the new keys are sealed (the rule)
  // As "Protect my account" and "Recover my account" do it (device-lock-ui.mjs, wayChoice): 'none' (the device can lock
  // keys, and no way is chosen yet: the form does not go on), 'device' (locked to this device from birth, with the
  // passwords chosen), 'declined' (passwords the wallet makes) or 'made' (this device cannot lock keys). The fields of the
  // chosen passwords are shown only once the lock is chosen, and emptied when it is not.
  const sealing = wayChoice('move', { env: () => c.env?.(), drawn: mode => {
    $('move-chosen').hidden = mode !== 'device';
    if (mode !== 'device') for (const id of MOVE_FIELDS.slice(0, 4)) $(id).value = '';
  } });

  // ---------------------------------------------------------------- the new device: the panel
  function stopTimer() { if (timer !== null) { clearInterval(timer); timer = null; } }
  function forgetHeld() { if (held) { held.privateKey = null; held.storageKey = null; } held = null; }
  function showPanel() { $('auth-panel').hidden = true; $('move-panel').hidden = false; }
  function closePanel() { stopTimer(); scrub(); $('move-panel').hidden = true; if (!c.session()) $('auth-panel').hidden = false; }
  function showForm(name = '') {
    showPanel(); shownName = null; stopTimer();
    $('move-form').hidden = false; $('move-step').hidden = true; $('move-request').value = ''; $('move-code').textContent = ''; $('move-stage').textContent = '';
    if (name && !$('move-name').value) $('move-name').value = name;
    sealing.redraw();
  }
  /// The request and its code, shown again (a stage that waits), or hidden (any other); the stage's sentence.
  function showStage(name, result, state = null) {
    showPanel(); shownName = name;
    // Once no request of this browser can be shown any more (withdrawn, expired, forgotten), a new one can be made below.
    const again = ['withdrawn', 'expired', 'forgotten'].includes(result.stage);
    $('move-form').hidden = !again; $('move-step').hidden = false;
    if (again) { if (!$('move-name').value) $('move-name').value = name; sealing.redraw(); }
    const showing = typeof result.text === 'string' && typeof result.code === 'string';
    $('move-request-part').hidden = !showing; $('move-code-part').hidden = !showing;
    $('move-request').value = showing ? result.text : ''; $('move-code').textContent = showing ? result.code : '';
    $('move-stage').textContent = stageWords(result, state);
    // "Withdraw" while a request waits, or could still be used.
    $('move-withdraw').hidden = !['waiting', 'stale', 'closing', 'unread', 'damaged'].includes(result.stage) || result.landed === true;
    $('move-check').hidden = ['expired', 'forgotten', 'none', 'settled', 'mixed'].includes(result.stage);
    if (['waiting', 'stale', 'closing', 'withdrawn', 'unread'].includes(result.stage)) startTimer(); else stopTimer();
  }
  function stageWords(result, state) {
    const at = micros => (state ? when(state, micros) : String(micros));
    switch (result.stage) {
      case 'waiting': return MOVE_PAGE_WORDS.waiting(at(result.request.expires));
      case 'stale': return MOVE_PAGE_WORDS.stale;
      case 'closing': return MOVE_PAGE_WORDS.closing(at(result.until));
      case 'withdrawn': return MOVE_PAGE_WORDS.withdrawn(at(result.until));
      case 'settled': return MOVE_PAGE_WORDS.settled;
      case 'mixed': return MOVE_PAGE_WORDS.mixed;
      case 'damaged': return result.landed ? MOVE_PAGE_WORDS.damagedLanded : MOVE_PAGE_WORDS.damaged;
      case 'expired': return MOVE_PAGE_WORDS.expired;
      case 'forgotten': return MOVE_PAGE_WORDS.forgotten;
      case 'unread': return result.damaged ? MOVE_PAGE_WORDS.unreadDamaged : MOVE_PAGE_WORDS.unread;
      default: return '';
    }
  }
  function startTimer() { if (timer === null) timer = setInterval(() => { look().catch(() => {}); }, MOVE_CHECK_MS); }
  const readState = name => c.verifiedState({ names: [name], include_security: true });
  /// Reads the network for the request shown, and says what the module made of it. Quiet: an unread network is a stage.
  async function look() {
    const name = shownName; if (!name || checking) return null;
    checking = true;
    try {
      let state = null; try { state = await readState(name); } catch { state = null; }
      if (shownName !== name) return null;
      const result = await dm.resumeMove({ storage: c.storage, networkId: net(), name, state, locks: locks() });
      if (shownName !== name) return null;
      return arrived(name, result, state);
    } finally { checking = false; }
  }
  /// What a stage leads to: the account opened when the move landed, else the stage shown.
  async function arrived(name, result, state) {
    if (result.stage === 'none') { closePanel(); return result; }
    if (result.stage === 'settled' || result.stage === 'mixed') {
      stopTimer(); shownName = null;
      const mixed = result.stage === 'mixed', login = (result.settled ?? []).includes('signin');
      // The login key of the request is on the account and in its place here: the page opens it with the key it held, or
      // the login password does.
      let signin = null;
      if (login && held) { signin = held; held = null; } else forgetHeld();
      if (!login) {
        // Only the payment key of the request is on the account: no key of this browser opens it, and the unlock screen
        // would only fail. Said as it is, on the panel; nothing is left to withdraw or to check.
        showPanel(); $('move-form').hidden = true; $('move-step').hidden = false;
        $('move-request-part').hidden = $('move-code-part').hidden = true; $('move-request').value = ''; $('move-code').textContent = '';
        $('move-withdraw').hidden = $('move-check').hidden = true;
        $('move-stage').textContent = MOVE_PAGE_WORDS.noLogin(name);
        return result;
      }
      $('move-panel').hidden = true;
      if (signin) await c.opened({ name, signin, said: mixed ? MOVE_PAGE_WORDS.mixed : MOVE_PAGE_WORDS.settled });
      else { c.showUnlock(name); c.notice(mixed ? MOVE_PAGE_WORDS.mixedOpen(name) : MOVE_PAGE_WORDS.settledOpen(name)); }
      return result;
    }
    showStage(name, result, state);
    return result;
  }

  // "Move my account here": a request that waits for this name (or for the only name that has one) is shown again; else the form.
  $('move-open').addEventListener('click', () => c.run(async () => {
    const typed = $('username').value.trim().replace(/^@/, ''), waiting = movesHere();
    const name = waiting.includes(typed) ? typed : waiting.length === 1 ? waiting[0] : null;
    if (name) { shownName = name; showPanel(); $('move-form').hidden = true; $('move-step').hidden = false; await look(); return; }
    showForm(typed);
  }));
  $('move-close').addEventListener('click', closePanel);
  $('move-copy').addEventListener('click', () => c.run(async () => { await navigator.clipboard.writeText($('move-request').value); c.notice(MOVE_PAGE_WORDS.copied); }));
  $('move-check').addEventListener('click', () => c.run(async () => { c.setBusy(true); await look(); }));
  $('move-withdraw').addEventListener('click', () => c.run(async () => {
    const name = shownName; assert(name, 'There is no request to withdraw.');
    if (!await c.review('Withdraw this request', [['What happens', 'Your other device can no longer approve this request.'], ['Your new keys', 'This browser keeps them while a move your other device may already have sent can still arrive, then forgets them.']], 'Withdraw')) return;
    c.setBusy(true);
    const state = await readState(name);
    const result = await dm.withdrawMove({ storage: c.storage, networkId: net(), name, state, locks: locks() });
    if (result.stage === 'forgotten' || result.stage === 'none') { forgetHeld(); }
    await arrived(name, result.stage === 'none' ? { stage: 'forgotten' } : result, state);
  }));

  $('move-form').addEventListener('submit', event => {
    event.preventDefault();
    const login = take('move-login'), loginAgain = take('move-login-confirm'), payment = take('move-payment'), paymentAgain = take('move-payment-confirm'), byDevice = sealing.byDevice;
    c.run(async () => {
      // Nothing is made before the browser said what the device can do and, where it can lock keys, the person chose a way
      // (LOCK_WORDS.ways.asking, .pick). The fields of the chosen passwords are empty until the lock is chosen.
      sealing.ready();
      const check = c.capture(), name = validateName($('move-name').value.trim());
      // The passwords a person chose seal the new keys only with the device (the rule); else the wallet makes them.
      if (byDevice) { assert(login === loginAgain, 'The two login passwords differ.'); assert(payment === paymentAgain, 'The two payment passwords differ.'); checkPasswords({ login, payment, name }); }
      c.setBusy(true, 'Reading your account on the network…');
      const state = await readState(name); check();
      assert(state.accounts.some(a => a.name === name), MOVE_PAGE_WORDS.noAccount);
      // Storage the browser may clear: said, and the person chooses (device-move.mjs, prepareMove refuses without it).
      let lasting = await lastingStorage(c.storageManager?.()); check();
      if (lasting.lasting !== true) {
        c.setBusy(false);
        if (!await c.review(MOVE_PAGE_WORDS.fleetingTitle, [['What can happen', MOVE_WORDS.fleeting], ['Then', 'Open this browser again soon after the move, so that it puts your new keys in place.']], MOVE_PAGE_WORDS.fleetingGo)) return;
        check(); lasting = { ...lasting, accepted: true };
      }
      c.setBusy(true, byDevice ? MOVE_PAGE_WORDS.locking : MOVE_PAGE_WORDS.making);
      let locked = false, fallback = null, made = [], shown;
      const entryOf = publicKey => made.find(entry => entry.key.publicKey === publicKey);
      const ofIntent = intent => made.find(entry => entry.record.intent === intent);
      forgetHeld();
      try {
        shown = await dm.prepareMove({ storage: c.storage, networkId: net(), state, name, waitsNow: waitsOf(c.sdk, state), lasting, locks: locks(),
          // Made by the rule, as a sign-up makes them. The passwords the wallet made are shown here, before device-move.mjs
          // keeps anything. Closed any other way than "I have them" (Escape, a back gesture, the wallet locking:
          // made-dialog.mjs), showMade rejects with NOT_HAD: the step ends, nothing is kept, the keys made are forgotten
          // (finally, below) and no request is shown. No lock of the vault is held while they are shown, nor any key of the
          // account opened: prepareMove holds the lock only to read and to write, and checks again under it before writing.
          seal: async wanted => {
            const result = await newKeysByRule({ byDevice, storage: c.storage, env: c.env?.(), wanted: wanted.map(w => ({ intent: w.intent, password: w.intent === 'spend' ? payment : login })), networkId: net(), name, argon2id: c.argon2id(), say: text => c.notice(text, 'busy') });
            made = result.keys; locked = result.locked; fallback = result.fallback;
            check();
            if (!locked) {
              c.setBusy(false);
              try { await c.showMade({ name, login: ofIntent('signin').made, payment: ofIntent('spend').made, why: fallback ?? MOVE_PAGE_WORDS.madeWhy }); }
              catch (error) { for (const entry of made) { entry.made = null; entry.key.privateKey = null; entry.storageKey = null; } throw error; }
              check(); c.setBusy(true, 'Making your request…');
            }
            return made.map(e => ({ key: { publicKey: e.key.publicKey, privateKey: e.key.privateKey }, record: e.record }));
          },
          // Opened again before any request exists. Keys locked from birth were opened by sealAtBirth already, with a second
          // answer of the device: that proof's keys are given, and the device is not asked once more. Keys under passwords
          // the wallet made are opened with them.
          open: async record => {
            const entry = entryOf(record.binding.publicKey); assert(entry, 'This key was not made here.');
            if (locked) return { privateKey: entry.key.privateKey };
            return openVault(record, entry.made, c.argon2id(), globalThis.crypto, record.intent);
          } });
        check();
        // The login key, held by this page to open the account when the move lands while it stays open.
        const signin = ofIntent('signin');
        held = { publicKey: signin.key.publicKey, privateKey: signin.key.privateKey, storageKey: signin.storageKey ?? null };
      } finally {
        for (const entry of made) { entry.made = null; entry.key.privateKey = null; entry.storageKey = null; }
      }
      showStage(name, { stage: 'waiting', ...shown }, state);
      c.notice(fallback ? `${fallback} ${MOVE_PAGE_WORDS.ready}` : MOVE_PAGE_WORDS.ready);
    });
  });

  /// Every key the storage holds (localStorage: by its length and key(i), as device-lock.mjs reads it).
  function keysHere() {
    try {
      if (typeof c.storage.key === 'function' && Number.isInteger(c.storage.length)) { const keys = []; for (let i = 0; i < c.storage.length; i++) { const k = c.storage.key(i); if (k !== null) keys.push(k); } return keys; }
      return Object.keys(c.storage);
    } catch { return []; }
  }
  /// The names of this network whose notes of a move end with `suffix`: ':move' (a request kept here, the new device) or
  /// ':moved' (a move sent from here, the old device).
  function namesWith(suffix) {
    const prefix = `${STAGED_PREFIX}${net()}:`;
    return keysHere().filter(k => k.startsWith(prefix) && k.endsWith(suffix)).map(k => k.slice(prefix.length, -suffix.length)).filter(n => /^[a-z0-9_]{2,15}$/.test(n));
  }
  const movesHere = () => namesWith(':move');
  const sentHere = () => namesWith(':moved');

  // ---------------------------------------------------------------- the old device: the card on Keys
  function resetOld() { pasted = null; scrub(); $('move-old-request').value = ''; $('move-old-code').value = ''; $('move-old-form').hidden = false; $('move-old-review').hidden = true; $('move-old-secrets').hidden = true; $('move-old-shown').replaceChildren(); }
  /// The card: on a protected account whose login key and payment key are both in this browser.
  function render(account, state) {
    const name = account.name, slots = vaultSlots(net(), name), row = Array.isArray(state?.security) ? security.securityOf(state, account.id) : null;
    const keyOf = place => { try { return JSON.parse(c.storage.getItem(place))?.binding?.publicKey ?? null; } catch { return null; } };
    const role = key => { const d = account.devices.find(item => item.public_key === key); return d ? security.roleOf(d) : null; };
    const both = Boolean(row) && role(keyOf(slots.login)) === 'signin' && role(keyOf(slots.spend)) === 'spend';
    $('move-card').hidden = !both;
    const waiting = both && c.storage.getItem(moveSlots(net(), name).sent) !== null;
    $('move-old-note').textContent = waiting ? MOVE_PAGE_WORDS.sentWaiting : ''; $('move-old-note').hidden = !waiting;
    $('move-old-form').hidden = waiting || pasted !== null;
    if (!both || waiting) { pasted = null; $('move-old-review').hidden = $('move-old-secrets').hidden = true; }
  }
  /// What the old device read in the request, said in sentences from what the module checked (`shown`), never from the
  /// request's own text: no key, no signature, no code.
  function shownLines(shown, state) {
    const lines = [`Your account @${shown.account} moves to your other device.`,
      `Every payment key and login key of your account stops working at once: ${shown.removes} in all, this device's included.`,
      `Your recovery words stay, and so do your balance and your daily limit.`];
    if (shown.cancelsPayments) lines.push(`${shown.cancelsPayments} waiting payment${shown.cancelsPayments === 1 ? ' is' : 's are'} cancelled.`);
    if (shown.cancelsLimit) lines.push('The waiting raise of your daily limit is cancelled.');
    lines.push(`This request works until ${when(state, shown.expires)}.`);
    return lines;
  }
  const dropped = shown => [shown.cancelsPayments ? `${shown.cancelsPayments} waiting payment${shown.cancelsPayments === 1 ? '' : 's'}` : null, shown.cancelsLimit ? 'the waiting raise of your daily limit' : null].filter(Boolean);
  async function freshState(name) { const state = await readState(name); const account = state.accounts.find(a => a.name === name); assert(account, 'The account was not found.'); return { state, account, row: security.securityOf(state, account.id) }; }

  $('move-old-form').addEventListener('submit', event => {
    event.preventDefault();
    c.run(async () => {
      const session = c.session(); assert(session, 'Unlock your wallet first.');
      const check = c.capture(), name = session.binding.name, text = $('move-old-request').value;
      c.setBusy(true, 'Checking the request…');
      const { state, account, row } = await freshState(name); check();
      const review = await dm.reviewMove({ text, networkId: net(), account, security: row, now: elapsedOf(state), waitsNow: waitsOf(c.sdk, state), feeMicros: c.fee() }); check();
      pasted = { name, request: review.request, shown: review.shown, code: null };
      $('move-old-request').value = '';
      $('move-old-shown').replaceChildren(...shownLines(review.shown, state).map(line => { const li = document.createElement('li'); li.textContent = line; return li; }));
      $('move-old-only').textContent = MOVE_WORDS.onlyYours;
      $('move-old-form').hidden = true; $('move-old-review').hidden = false; $('move-old-secrets').hidden = true;
      c.notice(MOVE_PAGE_WORDS.checked);
    });
  });
  $('move-old-next').addEventListener('click', () => c.run(async () => {
    assert(pasted && c.session()?.binding.name === pasted.name, 'Paste the request again.');
    const typed = $('move-old-code').value;
    await dm.checkCode(pasted.request, typed);
    pasted.code = typed; $('move-old-code').value = '';
    $('move-old-secrets').hidden = false;
    c.notice(MOVE_PAGE_WORDS.codeOk);
  }));
  $('move-old-cancel').addEventListener('click', () => { resetOld(); c.notice('Nothing was sent. Paste a request again when you are ready.'); });
  $('move-old-submit').addEventListener('click', () => {
    const password = take('move-old-payment'), secret = take('move-old-secret');
    c.run(async () => {
      try {
        const session = c.session(); assert(session && pasted && session.binding.name === pasted.name && pasted.code, 'Paste the request again.');
        const check = c.capture(), name = pasted.name, current = pasted;
        assert(password, 'Enter your payment password.');
        const { account } = await freshState(name); check();
        const drop = dropped(current.shown);
        if (!await c.review('Move my account to another device', [
          ['At once', 'Your account works on your other device, and this device\'s keys stop working.'],
          ['Websites', 'They ask you to sign in again.'],
          ['Dropped', drop.length ? `${drop.join(' and ')}.` : 'Nothing is waiting.'],
          ['Kept', 'Your recovery words, your balance and your daily limit.'],
          ['Approved by', 'Your payment password and your recovery words (or your printed recovery sheet)'],
          ['Fee', `${c.seconds(c.fee())} seconds`]], 'Move my account')) return;
        check();
        // A wrong recovery word: nothing is opened or signed after it (recoveryPaper says which, in its words).
        const recovery = await c.tools.recoveryPaper(secret, account); check();
        try {
          c.setBusy(true, MOVE_PAGE_WORDS.moving);
          await c.tools.withSpend(password, name, spend => c.tools.sendSecurity({ label: 'Move to another device', accountId: account.id, names: [name],
            build: ({ account: now_, row, now, waitsNow }) => dm.buildMove({ networkId: net(), request: current.request, typedCode: current.code, account: now_, security: row, spend, recovery, now, waitsNow, feeMicros: c.fee() }),
            // Noted before it leaves: a page closed after this still forgets its keys once the move landed.
            beforeSubmit: ({ built }) => dm.rememberMove({ storage: c.storage, networkId: net(), name, request: built.request, built, locks: locks() }) }));
        } finally { recovery.privateKey = null; }
        check(); pasted = null;
        await finishOld(name, check);
      } finally { scrub(); }
    });
  });
  /// After the receipt: the status read until this browser forgot its keys (a verified state a block later may still be
  /// from before the move), then the locked start screen, which says where the account is.
  async function finishOld(name, check) {
    c.setBusy(true, MOVE_PAGE_WORDS.forgetting);
    for (let tries = 0; tries < 20; tries++) {
      let state = null; try { state = await readState(name); } catch { state = null; }
      check();
      const status = await dm.oldDeviceStatus({ storage: c.storage, networkId: net(), name, state, locks: locks() }); check();
      if (status.stage === 'forgotten' || status.stage === 'none') return c.lock(MOVE_PAGE_WORDS.done(name));
      if (status.stage === 'mixed') { c.setBusy(false); return c.notice(MOVE_PAGE_WORDS.mixedKeep, 'error'); }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    c.lock(MOVE_PAGE_WORDS.stillMoving(name));
  }

  // ---------------------------------------------------------------- the start of the page, before any unlock
  /// A request that waits on this browser is shown again; a move sent from it is finished (its keys forgotten once the
  /// network shows it). Each with a verified state of its own account.
  async function start() {
    for (const name of sentHere()) {
      try {
        let state = null; try { state = await readState(name); } catch { state = null; }
        const status = await dm.oldDeviceStatus({ storage: c.storage, networkId: net(), name, state, locks: locks() });
        if (status.stage === 'forgotten') c.notice(MOVE_PAGE_WORDS.done(name));
        else if (status.stage === 'mixed') c.notice(MOVE_PAGE_WORDS.mixedKeep, 'error');
      } catch (error) { c.notice(error.message, 'error'); }
    }
    const waiting = movesHere();
    if (!waiting.length) return;
    shownName = waiting[0]; showPanel(); $('move-form').hidden = true; $('move-step').hidden = false;
    try { await look(); } catch (error) { c.notice(error.message, 'error'); }
  }
  /// Called when the wallet locks: the old device's step ends; the new device's request stays kept and shown, but the
  /// login key this page held goes (the login password opens the account once the move landed).
  function reset() { resetOld(); forgetHeld(); scrub(); $('move-card').hidden = true; }
  function availability(ready) {
    for (const id of ['move-open', 'move-check', 'move-withdraw', 'move-old-next', 'move-old-submit']) $(id).disabled = !ready;
    for (const b of $('move-form').querySelectorAll('button[type=submit]')) b.disabled = !ready;
    for (const b of $('move-old-form').querySelectorAll('button[type=submit]')) b.disabled = !ready;
  }
  return { start, render, reset, availability, look, moveWindowEnd };
}
