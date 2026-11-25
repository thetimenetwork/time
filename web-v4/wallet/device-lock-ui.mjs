// "Lock my keys to this device", a card on Keys (index.html, #lock-card), the backup card's word while the lock is on,
// and the card of keys kept from before the rule under passwords a person chose (#legacy-card, "Let the wallet make my
// passwords"). The decisions are in device-lock.mjs; this module reads the passwords, shows the review, and says what
// happens. The lock is offered on a protected account whose login key and payment key are both in this browser, where the
// browser says it may be able to (device-key.mjs, deviceSupport: not on a device or browser that says it cannot). Every
// text goes in by textContent; the passwords are read once and their fields emptied however the step ends.
import { deviceSupport } from './device-key.mjs';
import { lockOf, turnOn, turnOff, remakePasswords, birthLockable, LOCK_WORDS } from './device-lock.mjs';
import { vaultSlots, sealsOf } from './security-flows.mjs';
import { BACKUP_MADE_ONLY } from './vault-backup.mjs';

const $ = id => document.getElementById(id);
const assert = (value, message) => { if (!value) throw new Error(message); };
export const LOCK_FIELDS = Object.freeze(['lock-login', 'lock-payment', 'lock-off-login', 'lock-off-payment', 'remake-login', 'remake-payment']);
/// What the card says of the lock's state.
export const LOCK_STATE = Object.freeze({
  off: 'Off. Your keys open in this browser with the passwords the wallet made.',
  offChosen: 'Off. Your keys open in this browser with the passwords you chose.',
  on: 'On. Your keys open here only with this device and your passwords together.',
});
/// The card of keys kept under passwords a person chose (records from before the rule, vault.mjs, RULE). It names only
/// what Keys offers: the lock to this device where its card is shown (`ways`, `past`), else the passwords the wallet makes
/// alone (review of 24 November 2026, finding 3).
export const LEGACY_WORDS = Object.freeze({
  what: 'Your keys in this browser are locked with passwords you chose. Someone with a copy of this browser\'s data could try to guess them on their own computer.',
  ways: 'Two ways out: lock your keys to this device, below. Or let the wallet make your passwords: the same keys, under passwords of four words that the wallet makes and shows you once.',
  past: 'Neither undoes the past: copies of this browser\'s data, and backup files, made before still open with your old passwords, until your keys themselves are replaced (a new login password, a new payment password).',
  wayRemake: 'Let the wallet make your passwords: the same keys, under passwords of four words that the wallet makes and shows you once.',
  pastRemake: 'It does not undo the past: copies of this browser\'s data, and backup files, made before still open with your old passwords, until your keys themselves are replaced (a new login password, a new payment password).',
  wayOne: 'Let the wallet make your password: the same key, under a password of four words that the wallet makes and shows you once.',
  pastOne: 'It does not undo the past: copies of this browser\'s data, and backup files, made before still open with your old password.',
});
/// Why the dialog of "Let the wallet make my passwords" shows what it shows: two keys, or the one key of an account.
export const REMADE = 'The wallet made new passwords for your keys. Write them down now: they are shown only now.';
export const REMADE_ONE = 'The wallet made a new password for your key. Let your browser save it, or write it down: it is shown only now.';

/// How long a form waits for the browser to say what the device can do before it takes the device as one that cannot
/// lock keys (wayChoice). device-key.mjs gives each of the browser's answers 10 seconds; the form does not wait for that.
export const WAY_ANSWER_MS = 4000;
/// How the new keys of a form are locked, where the device can lock them: the person chooses, and neither way is chosen
/// beforehand (the owner's decision of 25 November 2026). One choice for every form that makes an account's keys anew (a
/// sign-up, "Protect my account", "Recover my account", "Move my account here"; device-lock.mjs, newKeysByRule takes what
/// was chosen). `prefix` names the form's elements in index.html: `<prefix>-seal-note`, and the fieldset `<prefix>-ways`
/// with its legend and two radios, `<prefix>-way-device` and `<prefix>-way-made`, each with a title and a note. Their words
/// are LOCK_WORDS.ways, put in here. The mode:
/// - 'asking': the form was drawn and the browser has not said yet what the device can do (birthLockable): neither the
///   choice nor the note is shown, and `ready` refuses the form, with LOCK_WORDS.ways.asking. An answer that does not
///   come within WAY_ANSWER_MS is taken as a device that cannot lock keys; an answer after that changes nothing;
/// - 'made': this device cannot lock keys: no choice is shown, and the note says that the wallet makes the passwords
///   (also before a form's first drawing, while it is not on the page);
/// - 'none': the device can lock keys and no way is chosen yet: `ready` refuses the form, with LOCK_WORDS.ways.pick;
/// - 'device': the lock is chosen (the passwords are chosen too, and sealed with the device);
/// - 'declined': the passwords the wallet makes are chosen (nothing of the device is used).
/// `drawn(mode)` runs after each change: the form shows its fields for the passwords only in 'device'. `lead` goes before
/// the note, `legendLead` before the legend.
export function wayChoice(prefix, { env = () => undefined, lead = '', legendLead = '', drawn = () => {} } = {}) {
  const ways = $(`${prefix}-ways`), note = $(`${prefix}-seal-note`), radios = { device: $(`${prefix}-way-device`), declined: $(`${prefix}-way-made`) };
  let mode = 'made', asked = 0;
  const choosing = () => ['none', 'device', 'declined'].includes(mode);
  $(`${prefix}-ways-legend`).textContent = legendLead + LOCK_WORDS.ways.legend;
  for (const [way, words] of [['device', LOCK_WORDS.ways.device], ['made', LOCK_WORDS.ways.made]]) { $(`${prefix}-way-${way}-title`).textContent = words.title; $(`${prefix}-way-${way}-note`).textContent = words.note; }
  function draw(next) {
    mode = next;
    // The radios say the mode: drawn again ('asking', then 'made' or 'none'), nothing is chosen, for the wallet does not
    // choose for the person.
    radios.device.checked = next === 'device'; radios.declined.checked = next === 'declined';
    ways.hidden = !choosing();
    note.textContent = next === 'made' ? lead + LOCK_WORDS.birthMade : ''; note.hidden = next !== 'made';
    drawn(next);
  }
  for (const [way, radio] of Object.entries(radios)) radio.addEventListener('change', () => { if (choosing() && radio.checked) draw(way); });
  return {
    /// Drawn again: what the browser says it can do (nothing is asked of the person), and no way chosen. Until it has said,
    /// or WAY_ANSWER_MS have passed, neither state is shown and the form is not sent.
    redraw() {
      draw('asking');
      const question = ++asked;
      const answered = able => { if (question === asked && mode === 'asking') draw(able ? 'none' : 'made'); };
      const late = setTimeout(() => answered(false), WAY_ANSWER_MS); late?.unref?.();
      birthLockable(env()).then(able => { clearTimeout(late); answered(able); });
    },
    /// The browser's answer to the last drawing, still to come, draws nothing (the form left the page).
    forget() { asked += 1; },
    get mode() { return mode; },
    get byDevice() { return mode === 'device'; },
    /// Before anything is read or made: the browser has said what the device can do, and where it can lock keys a way was
    /// chosen.
    ready() {
      if (mode === 'asking') throw new Error(LOCK_WORDS.ways.asking);
      if (mode === 'none') { radios.device.focus?.(); throw new Error(LOCK_WORDS.ways.pick); }
    },
  };
}

/// `c`: { network(), session(), storage, locks(), env(), argon2id(), run, notice, setBusy, capture, refresh, review, showMade }.
export function createLockUI(c) {
  // `drawn` counts the drawings: the browser's answer to an earlier one, which may come after the lock was turned on or
  // off, draws nothing.
  let asking = null, shownFor = null, drawn = 0;
  const take = id => { const el = $(id), value = el.value; el.value = ''; return value; };
  const scrub = () => { for (const id of LOCK_FIELDS) $(id).value = ''; };
  /// What the browser says it can do (it asks the person nothing), asked again at each drawing: a device can be set up
  /// while the page is open. One question at a time.
  const supportOf = () => (asking ??= deviceSupport(c.env()).catch(() => ({ outcome: 8, prf: 'unknown' })).finally(() => { asking = null; }));
  function show({ card, on = false, offerOn = false, note = '', chosen = false }) {
    $('lock-card').hidden = !card;
    $('lock-state').textContent = card ? (on ? LOCK_STATE.on : chosen ? LOCK_STATE.offChosen : LOCK_STATE.off) : '';
    $('lock-facts').replaceChildren(...(card && !on ? LOCK_WORDS.facts.map(text => { const item = document.createElement('li'); item.textContent = text; return item; }) : []));
    $('lock-on-form').hidden = !(card && !on && offerOn); $('lock-off-form').hidden = !(card && on);
    $('lock-off-facts').textContent = card && on ? LOCK_WORDS.offFacts : '';
    $('lock-note').textContent = note; $('lock-note').hidden = !note;
  }
  /// The card of keys under passwords a person chose: shown while a live record of the account in this browser is one.
  /// `lockOffered`: the card of the lock offers to turn it on (render, once the browser said it may).
  function legacy(seals, isProtected, lockOffered = false) {
    const chosen = seals.chosen, one = !isProtected || !seals.spend;
    $('legacy-card').hidden = chosen.length === 0;
    $('legacy-what').textContent = chosen.length ? LEGACY_WORDS.what : '';
    $('legacy-ways').textContent = chosen.length ? (one ? LEGACY_WORDS.wayOne : lockOffered ? LEGACY_WORDS.ways : LEGACY_WORDS.wayRemake) : '';
    $('legacy-past').textContent = chosen.length ? (one ? LEGACY_WORDS.pastOne : lockOffered ? LEGACY_WORDS.past : LEGACY_WORDS.pastRemake) : '';
    // Only the passwords of the places that are of a chosen password are asked.
    $('remake-login-wrap').hidden = !chosen.includes('login'); $('remake-payment-wrap').hidden = !chosen.includes('spend');
    $('remake-login-label').textContent = isProtected ? 'Login password' : 'Password';
  }
  /// Draws the cards, and the backup card's word, from what this browser keeps for `account`.
  function render(account, isProtected) {
    const name = account.name, slots = vaultSlots(c.network().networkId, name), status = lockOf(c.storage, slots), seals = sealsOf(c.storage, slots), drawing = ++drawn;
    if (shownFor !== name) { scrub(); shownFor = name; }
    legacy(seals, isProtected);
    // While the lock is on, no backup file (a password alone opens it) is offered: one sentence says why. Nor of a key under
    // a password a person chose (vault-backup.mjs, BACKUP_MADE_ONLY): the file is made of a key whose password the wallet made.
    const madeLogin = seals.login === 'made';
    $('backup-export-form').hidden = status.on || !madeLogin;
    $('backup-locked-note').hidden = !status.on; $('backup-locked-note').textContent = status.on ? LOCK_WORDS.backup : '';
    $('backup-chosen-note').hidden = status.on || madeLogin; $('backup-chosen-note').textContent = status.on || madeLogin ? '' : BACKUP_MADE_ONLY;
    if (status.on) return show({ card: true, on: true, note: status.waiting ? LOCK_WORDS.waiting : '' });
    if (!isProtected || !status.both) return show({ card: false });
    supportOf().then(s => {
      if (drawing !== drawn || c.session()?.binding.name !== name) return;
      // Offered only where the device may do it: the browser did not say it cannot.
      const able = s.outcome === null && s.prf !== 'no';
      show({ card: able, offerOn: able && !status.waiting, note: status.waiting ? LOCK_WORDS.waiting : '', chosen: seals.chosen.length > 0 });
      // The card of chosen passwords names the lock only now that its card offers it.
      if (able && !status.waiting) legacy(seals, isProtected, true);
    });
  }
  function reset() { drawn += 1; scrub(); shownFor = null; show({ card: false }); $('legacy-card').hidden = true; $('backup-locked-note').hidden = true; $('backup-locked-note').textContent = ''; $('backup-chosen-note').hidden = true; $('backup-chosen-note').textContent = ''; $('backup-export-form').hidden = false; }
  /// The step on or off: the passwords read first, the review, then device-lock.mjs, saying before each request.
  function step(form, { on }) {
    $(form).addEventListener('submit', event => {
      event.preventDefault();
      const login = take(on ? 'lock-login' : 'lock-off-login'), payment = take(on ? 'lock-payment' : 'lock-off-payment');
      c.run(async () => {
        try {
          const session = c.session(); assert(session, 'Unlock your wallet first.');
          const name = session.binding.name, networkId = c.network().networkId, check = c.capture();
          assert(login && payment, 'Enter your login password and your payment password.');
          const fields = on ? [['What changes', LOCK_WORDS.facts[0]], ['If this device loses the key', LOCK_WORDS.facts[1]], ['On phones', LOCK_WORDS.facts[2]], ['Backup file', LOCK_WORDS.facts[3]], ['Your device', LOCK_WORDS.beforeOn]]
            : [['What changes', LOCK_WORDS.offFacts], ['Your device', LOCK_WORDS.before]];
          if (!await c.review(on ? 'Lock my keys to this device' : 'Turn the lock off', fields, on ? 'Lock my keys' : 'Turn the lock off')) return;
          check(); c.setBusy(true, LOCK_WORDS.checking);
          const args = { storage: c.storage, slots: vaultSlots(networkId, name), networkId, name, login, payment, argon2id: c.argon2id(), env: c.env(), locks: c.locks(), say: text => c.notice(text, 'busy') };
          // Off: the passwords the wallet makes are shown before anything is replaced (device-lock.mjs, turnOff).
          if (on) await turnOn(args);
          // A wallet locked while they are shown closes the dialog: then nothing is replaced (check).
          else await turnOff({ ...args, show: async made => { c.setBusy(false); await c.showMade({ name, ...made, why: LOCK_WORDS.offMade }); check(); } });
          check(); await c.refresh(); c.notice(on ? LOCK_WORDS.on : LOCK_WORDS.off);
        } finally { scrub(); }
      });
    });
  }
  step('lock-on-form', { on: true });
  step('lock-off-form', { on: false });
  // "Let the wallet make my passwords": the passwords of now, the review, then the new ones shown before anything is replaced.
  $('remake-form').addEventListener('submit', event => {
    event.preventDefault();
    const login = take('remake-login'), payment = take('remake-payment');
    c.run(async () => {
      try {
        const session = c.session(); assert(session, 'Unlock your wallet first.');
        const name = session.binding.name, networkId = c.network().networkId, check = c.capture(), slots = vaultSlots(networkId, name), seals = sealsOf(c.storage, slots);
        assert(seals.chosen.length, LOCK_WORDS.notChosen);
        assert((!seals.chosen.includes('login') || login) && (!seals.chosen.includes('spend') || payment), seals.chosen.length === 2 ? 'Enter your login password and your payment password.' : seals.chosen.includes('spend') ? 'Enter your payment password.' : 'Enter your password.');
        if (!await c.review('Let the wallet make my passwords', [['What changes', 'The same keys, under passwords the wallet makes now and shows you once. The passwords you chose stop opening them in this browser.'], ['What stays', seals.spend ? LEGACY_WORDS.pastRemake : LEGACY_WORDS.pastOne]], 'Make my passwords')) return;
        check(); c.setBusy(true, LOCK_WORDS.checking);
        // An account with one key (its one record holds a key of both powers, and no payment key is kept): its one password
        // opens the wallet and pays, and the dialog says so.
        const single = !seals.spend && seals.loginIntent === 'device';
        await remakePasswords({ storage: c.storage, slots, networkId, name, login, payment, argon2id: c.argon2id(), locks: c.locks(), say: text => c.notice(text, 'busy'),
          show: async made => { c.setBusy(false); await c.showMade({ name, ...made, single, why: single ? REMADE_ONE : REMADE }); check(); } });
        check(); await c.refresh(); c.notice(LOCK_WORDS.remade);
      } finally { scrub(); }
    });
  });
  return { render, reset };
}
