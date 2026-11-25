// The recovery keys of an account, and the step that has the person keep them. One copy of this, for every place that
// makes recovery keys: "Protect my account" and "New recovery words" on Keys (security-ui.mjs), and signing up
// protected on the start screen (signup-ui.mjs). How each key is made and read is in security-flows.mjs.
//
// Two kinds (the chain asks for two recovery keys in every case, and both for a big change):
// - "words only" (`kind: 'words'`), the default at sign-up and in "Protect my account": both keys come from five words
//   that the person writes on paper by hand (security-flows.mjs, passphraseKey and recoveryWordsSecondKey). One paper,
//   no file, nothing to download: it works the same on every phone. Whoever has the paper can ask for the account; that
//   waits the waiting period, frozen, and only the words can stop it (a replacement with the payment key and one recovery
//   key, "New recovery words", ends it at once): an owner whose only copy was taken cannot. So the step asks for two copies.
// - "words and a Recovery Kit" (`kind: 'kit'`), offered under "New recovery words": the second key is a random recovery
//   sheet, kept in a Recovery Kit (a file locked with the words, recovery-file.mjs) or printed. The paper alone is then
//   not enough; losing either the kit or the words ends recovery.
//
// Nothing here is stored. The keys live in the caller's memory until it signs with them or forgets them
// (`forgetRecoveryKeys`). The words are on the page while the step is; a sheet only after "Print it instead". The person
// is trusted to have kept what the step shows: nothing is asked back.
import { encodeSheet, keyFromSeed, newSheetSeed, passphraseKey, recoveryWordsSecondKey, generatePassphrase } from './security-flows.mjs';
import { sealRecoveryKit, recoveryKitName } from './recovery-file.mjs';

/// New recovery keys of `kind` ('words' or 'kit'): new wallet-made recovery words and their key, and the second key:
/// from the same words, or of a new recovery sheet (`sheetText`). The keys name the account by its number
/// (`accountId`), or, for the first keys of an account that is being signed up protected and has no number yet, by its
/// registration key (`registrationKey`). `sheet` is the second key in both kinds.
export async function makeRecoveryKeys({ networkId, accountId, registrationKey, argon2id, kind = 'words' }) {
  if (kind !== 'words' && kind !== 'kit') throw new Error('Unknown kind of recovery keys');
  const phraseText = generatePassphrase();
  const phrase = await passphraseKey({ passphrase: phraseText, networkId, accountId, registrationKey, argon2id });
  if (kind === 'words') {
    const sheet = await recoveryWordsSecondKey({ passphrase: phraseText, networkId, accountId, registrationKey, argon2id });
    return { kind, sheetText: null, sheet, phraseText, phrase, kit: null };
  }
  const seed = newSheetSeed(); let sheetText, sheet;
  try { sheetText = await encodeSheet(seed); sheet = await keyFromSeed(seed); } finally { seed.fill(0); }
  return { kind, sheetText, sheet, phraseText, phrase, kit: null };
}
export const forgetRecoveryKeys = keys => { if (keys) { keys.sheet.privateKey = keys.phrase.privateKey = null; keys.sheetText = keys.phraseText = ''; keys.kit = null; } };
/// Prints the sheet that is on the screen, and nothing else (styles.css, "Printing").
export function printSheet() { document.body.classList.add('print-sheet'); try { window.print(); } finally { document.body.classList.remove('print-sheet'); } }

/// What the page says when the step opens: words only, or with a kit.
export const WRITE_NOW = 'Write down your recovery words. They are shown only now.';
export const SAVE_NOW = 'Save your Recovery Kit and write down your recovery words. They are shown only now.';
/// The busy words while the kit is locked: one Argon2id of 256 MiB.
export const KIT_LOCKING = 'Locking your Recovery Kit. This takes a few seconds…';
/// Under "Download my Recovery Kit", once a download was started.
export const kitSaved = fileName => `Downloaded: ${fileName}. Keep it anywhere you will find it again: send it to your own email, or put it in your cloud storage. It cannot be opened without your recovery words.`;

/// The step on the page of a place, on its elements `<prefix>-sheet-step` (the whole step), `<prefix>-phrase-shown`
/// (the words) and `<prefix>-submit`. With words only the button that goes on is there from the start. A place that also
/// offers a kit (`kit: true`) has the parts of the kit too: `<prefix>-words-only` and `<prefix>-with-kit` (what is said
/// of each kind), `<prefix>-tip` and `<prefix>-paper-warning` (said of words only), `<prefix>-kit-download` and `<prefix>-kit-saved` (the kit and where it went),
/// `<prefix>-print`, `<prefix>-printed`, `<prefix>-sheet-title` and `<prefix>-sheet` (the printed recovery sheet); with a
/// kit, `<prefix>-submit` is shown once the kit was downloaded or printed in this step, and not before.
export function paperSteps(prefix, $ = id => document.getElementById(id), { kit = false } = {}) {
  const at = name => $(`${prefix}-${name}`);
  let used = false, title = '';
  const kitOff = () => { if (!kit) return; at('sheet').textContent = ''; at('sheet-title').textContent = ''; at('printed').hidden = true; at('kit-saved').textContent = ''; at('kit-saved').hidden = true; };
  const steps = {
    /// The step on the page: the words, and with a kit the two ways to keep it. The sheet is not on the page.
    show(keys, sheetTitle = '') {
      const withKit = keys.kind === 'kit';
      if (withKit && !kit) throw new Error('This place makes no Recovery Kit.');
      used = !withKit; title = sheetTitle; kitOff();
      if (kit) { at('words-only').hidden = withKit; at('with-kit').hidden = !withKit; at('tip').hidden = at('paper-warning').hidden = withKit; }
      at('submit').hidden = !used;
      at('phrase-shown').textContent = keys.phraseText;
      at('sheet-step').hidden = false;
    },
    /// "Print it instead": the sheet on the page, to be printed (printSheet).
    printed(keys) { at('sheet-title').textContent = title; at('sheet').textContent = keys.sheetText; at('printed').hidden = false; steps.use(); },
    /// A download of the kit was started.
    downloaded(fileName) { at('kit-saved').textContent = kitSaved(fileName); at('kit-saved').hidden = false; steps.use(); },
    use() { used = true; at('submit').hidden = false; },
    /// Whether the step may go on: with words only at once; with a kit once it was downloaded or printed.
    used: () => used,
    /// Nothing of the keys on the page.
    clear() {
      used = false; title = ''; kitOff();
      at('phrase-shown').textContent = ''; at('submit').hidden = true;
      at('sheet-step').hidden = true;
    },
  };
  return steps;
}

/// "Download my Recovery Kit": the kit of `keys`, locked once and downloaded again as it is on a later press, handed to
/// the page's download (app.js, downloadJSON) under its name. `current()` says whether these keys are still the ones of
/// the step after the calculation: if the step was closed meanwhile, nothing is downloaded.
export async function saveKit(c, steps, keys, { networkId, name }, current) {
  if (!keys.kit) {
    c.setBusy(true, KIT_LOCKING); c.notice(KIT_LOCKING, 'busy');
    const text = await sealRecoveryKit({ networkId, name, sheetText: keys.sheetText, words: keys.phraseText, argon2id: c.argon2id() });
    if (!current()) throw new Error('Start again from the beginning.');
    keys.kit = { text, fileName: recoveryKitName({ name, networkId }) };
  }
  c.download(keys.kit.text, keys.kit.fileName);
  steps.downloaded(keys.kit.fileName);
  c.notice(kitSaved(keys.kit.fileName));
}
