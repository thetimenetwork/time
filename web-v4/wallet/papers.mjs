// The two recovery papers: the recovery sheet and the recovery passphrase. Made in this browser, shown once, written
// down by the person, and asked back before anything uses them. One copy of this, for every place that makes papers:
// "Protect my account" and "New recovery papers" on Keys (security-ui.mjs), and signing up protected on the start
// screen (signup-ui.mjs). How each paper is made and read is in security-flows.mjs.
//
// Nothing here is stored. The keys of the papers live in the caller's memory until it signs with them or forgets them
// (`forgetRecoveryKeys`), and the words are on the screen only between `show` and `askBack`.
import { encodeSheet, keyFromSeed, newSheetSeed, passphraseKey, generatePassphrase, parsePassphrase, pickConfirmGroups, confirmGroups } from './security-flows.mjs';

/// A new recovery sheet and a new, wallet-made recovery passphrase, and their keys. The passphrase's key names the account
/// by its number (`accountId`), or, for the first papers of an account that is being signed up protected and has no
/// number yet, by its registration key (`registrationKey`; security-flows.mjs, registrationPassphraseSalt).
export async function makeRecoveryKeys({ networkId, accountId, registrationKey, argon2id }) {
  const phraseText = generatePassphrase();
  const phrase = await passphraseKey({ passphrase: phraseText, networkId, accountId, registrationKey, argon2id });
  const seed = newSheetSeed(); let sheetText, sheet;
  try { sheetText = await encodeSheet(seed); sheet = await keyFromSeed(seed); } finally { seed.fill(0); }
  return { sheetText, sheet, phraseText, phrase, picks: pickConfirmGroups() };
}
/// The person typed back two groups of the sheet and the whole passphrase: each must be what was shown.
export function confirmRecoveryKeys(keys, groupA, groupB, phraseTyped) {
  confirmGroups(keys.sheetText, keys.picks, [groupA, groupB]);
  let typed = null; try { typed = parsePassphrase(phraseTyped); } catch {}
  if (typed !== keys.phraseText) throw new Error('The recovery passphrase does not match the one shown. Check what you wrote down.');
}
export const forgetRecoveryKeys = keys => { if (keys) { keys.sheet.privateKey = keys.phrase.privateKey = null; keys.sheetText = keys.phraseText = ''; } };
/// Prints the sheet that is on the screen, and nothing else (styles.css, "Printing").
export function printSheet() { document.body.classList.add('print-sheet'); try { window.print(); } finally { document.body.classList.remove('print-sheet'); } }

/// The two steps of a page that shows the papers and asks them back, on its elements `<prefix>-sheet-step` (the sheet,
/// its title, the passphrase) and `<prefix>-confirm-step` (two groups and the passphrase typed back).
export function paperSteps(prefix, $ = id => document.getElementById(id)) {
  const at = name => $(`${prefix}-${name}`);
  return {
    /// The papers on the screen, to be written down.
    show(keys, title) {
      if (title !== undefined) at('sheet-title').textContent = title;
      at('sheet').textContent = keys.sheetText; at('phrase-shown').textContent = keys.phraseText;
      at('confirm-step').hidden = true; at('sheet-step').hidden = false;
    },
    /// "I wrote both down": the papers leave the screen, and two groups of the sheet and the passphrase are asked for.
    askBack(keys) {
      at('sheet').textContent = ''; at('phrase-shown').textContent = '';
      at('confirm-a-label').textContent = `Group ${keys.picks[0] + 1}`; at('confirm-b-label').textContent = `Group ${keys.picks[1] + 1}`;
      at('sheet-step').hidden = true; at('confirm-step').hidden = false;
    },
    /// Nothing of the papers on the screen.
    clear() {
      at('sheet').textContent = ''; at('sheet-title').textContent = ''; at('phrase-shown').textContent = '';
      at('sheet-step').hidden = at('confirm-step').hidden = true;
    },
  };
}
