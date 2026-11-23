// Names that look like other names.
//
// An account name is 2 to 15 characters of a-z, 0-9 and _ (vault.mjs, validateName): no capital letter, no accent and
// no space can imitate another name. What is left is a name that reads like another one: `paypa1` for `paypal`,
// `alice_` for `alice`, `barn` for `bam` in some fonts, and softer tricks such as `b1nance` for `binance` or one
// changed letter. Before a payment is signed the wallet compares the name it goes to with the names this account has
// paid from this browser, and warns when it looks like one of them (app.js, `review` and `payeeLines`).
//
// Everything here is a function of its arguments only: no storage, no network, no page.

/// The skeleton of a name: what is left of it once the differences a reader does not see are taken out.
/// In this order: every `_` is dropped; every `0` becomes `o`, every `1` becomes `l` and every `w` becomes `vv`; then,
/// in one pass from left to right without overlap, `rn` becomes `m` and `vv` becomes `w`. Reading `w` as `vv` first
/// gives `vw`, `wv` and `vvv` one skeleton. Two names with one skeleton read as one name.
export function nameSkeleton(name) {
  return String(name).replaceAll('_', '').replaceAll('0', 'o').replaceAll('1', 'l').replaceAll('w', 'vv').replace(/rn|vv/g, pair => (pair === 'rn' ? 'm' : 'w'));
}

/// A looser key, for the softer tricks: the skeleton, then `i` as `l`, and the digits that are written for letters
/// (`3` for `e`, `4` for `a`, `5` for `s`, `7` for `t`, `8` for `b`, `2` for `z`, `9` and `6` for `g`).
const LOOSE = Object.freeze({ i: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', 2: 'z', 9: 'g', 6: 'g' });
export function looseKey(name) {
  return nameSkeleton(name).replace(/[i2-9]/g, character => LOOSE[character]);
}

/// Whether two texts differ by exactly one edit: one character added, removed or changed, or two neighbouring
/// characters swapped.
function oneEdit(a, b) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  let at = 0;
  while (at < a.length && at < b.length && a[at] === b[at]) at++;
  if (a.length === b.length) {
    if (a.slice(at + 1) === b.slice(at + 1)) return true;
    return at + 1 < a.length && a[at] === b[at + 1] && a[at + 1] === b[at] && a.slice(at + 2) === b.slice(at + 2);
  }
  const [long, short] = a.length > b.length ? [a, b] : [b, a];
  return long.slice(at + 1) === short.slice(at);
}

/// Why two names look alike, from the strongest reason to the weakest.
export const REASONS = Object.freeze(['skeleton', 'loose', 'edit']);

/// Why `candidate` looks like `known`, or null when it does not.
/// - 'skeleton': their skeletons are equal.
/// - 'loose': their looser keys are equal.
/// - 'edit': both skeletons have at least 4 characters and differ by exactly one edit.
/// The same name twice is the same account, and never a look-alike.
export function resembles(candidate, known) {
  const a = String(candidate), b = String(known);
  if (a === b) return null;
  const skeletonA = nameSkeleton(a), skeletonB = nameSkeleton(b);
  if (skeletonA === skeletonB) return 'skeleton';
  if (looseKey(a) === looseKey(b)) return 'loose';
  if (skeletonA.length >= 4 && skeletonB.length >= 4 && oneEdit(skeletonA, skeletonB)) return 'edit';
  return null;
}

/// The first of `knownNames` that `candidate` looks like, or null. A name with an equal skeleton is preferred to
/// one with an equal looser key, and that one to a name one edit away, wherever they stand in the list.
export function lookAlike(candidate, knownNames) {
  const found = (Array.isArray(knownNames) ? knownNames : []).map(known => [known, resembles(candidate, known)]);
  for (const reason of REASONS) { const first = found.find(pair => pair[1] === reason); if (first) return first[0]; }
  return null;
}

// ---------------------------------------------------------------- the names this account has paid
// The wallet keeps them in the browser, per network and per account, beside its activity (app.js, `paidNames`).

/// How many paid names are kept. Beyond that the oldest is dropped, and a payment to it is a first payment again.
export const MAX_PAID_NAMES = 500;
const NAME = /^[a-z0-9_]{2,15}$/;

/// The paid names out of what the browser stored (`{"paid": [...]}`), whatever is in there: account names only,
/// each one once, the one paid last at the end, MAX_PAID_NAMES at most. Anything else gives an empty list.
export function paidNamesFrom(stored) {
  const list = Array.isArray(stored?.paid) ? stored.paid : [];
  return [...new Set(list.filter(name => typeof name === 'string' && NAME.test(name)))].slice(-MAX_PAID_NAMES);
}

/// The list with one more paid name, as its last one.
export function withPaidName(list, name) {
  return paidNamesFrom({ paid: [...list.filter(known => known !== name), name] });
}

/// The name a payment went to, from the label the wallet gave the action when it was signed: "Send 1.5 s to @bob"
/// (app.js, sendForm; security-ui.mjs, pay), the same with a recovery proof, and "Waiting payment of 40 s to @bob"
/// (a payment above the daily limit that was signed and waits). Any other label gives null.
const PAID_LABEL = /^(?:Send|Waiting payment of) [0-9]+(?:\.[0-9]+)? s to @([a-z0-9_]{2,15})(?: with a recovery proof)?$/;
export function paidNameOf(label) {
  return typeof label === 'string' ? PAID_LABEL.exec(label)?.[1] ?? null : null;
}

// ---------------------------------------------------------------- what the review says about the name
/// What the review of a payment to `name` has to say, given the names this account has paid and its own name:
/// - { kind: 'paid' }: it was paid before. Nothing new.
/// - { kind: 'own', other, reason }: it was never paid, and it looks like `other`, the account's own name.
/// - { kind: 'alike', other, reason }: it was never paid, and it looks like `other`, which was.
/// - { kind: 'first' }: it was never paid, and it looks like none of these.
/// A name that looks like the own name and like a paid one is told as the stronger likeness, and as the own name
/// when both are equally strong. Without `ownName` the answer is what it was before the own name was looked at.
export function payeeCheck(name, paidNames, ownName = '') {
  const paid = Array.isArray(paidNames) ? paidNames : [];
  if (paid.includes(name)) return { kind: 'paid' };
  const other = lookAlike(name, paid), reason = other === null ? null : resembles(name, other);
  const own = typeof ownName === 'string' && ownName !== '' ? resembles(name, ownName) : null;
  if (own !== null && (reason === null || REASONS.indexOf(own) <= REASONS.indexOf(reason))) return { kind: 'own', other: ownName, reason: own };
  return other === null ? { kind: 'first' } : { kind: 'alike', other, reason };
}

// Both sentences come in pieces. A piece that begins with `@` is a name, which the page shows in a font that tells
// `1` from `l` and `0` from `o`; put together, the pieces are the sentence.
/// The plain line for a name that was never paid and looks like no paid name: "First payment to @name."
export const firstPaymentWords = name => ['First payment to ', '@' + name, '.'];
/// The warning for a name that was never paid and looks like a paid one. It names both, so that the difference shows.
export const alikeWords = (name, other) => ['You have not paid ', '@' + name, ' before. It looks like ', '@' + other, ', which you have paid. Check every letter.'];
/// The same warning for a name that was never paid and looks like the account's own name: a payment "back to
/// yourself" that goes to someone else.
export const ownAlikeWords = (name, own) => ['You have not paid ', '@' + name, ' before. It looks like ', '@' + own, ', your own name. Check every letter.'];
/// The box of that review: the button that signs stays disabled until it is ticked.
export const NAME_ACKNOWLEDGE = 'I checked the name, letter by letter.';

// ---------------------------------------------------------------- the names typed for guardians
// Guardians can replace every key of an account (recovery.mjs). A name typed there that reads like another one may be
// someone else's account. Each typed name is compared with the account's own name, with the names it has paid from
// this browser (a name that is itself one of them is known, and is not compared with the others), and with the
// guardians typed before it in the same list.
/// The likenesses found, in the order of the list: { name, other, why } with `why` 'own', 'paid' or 'guardian'.
export function guardianChecks(names, { ownName = '', paidNames = [] } = {}) {
  const list = Array.isArray(names) ? names : [], paid = Array.isArray(paidNames) ? paidNames : [], found = [];
  list.forEach((name, index) => {
    if (typeof ownName === 'string' && ownName !== '' && resembles(name, ownName) !== null) found.push({ name, other: ownName, why: 'own' });
    const known = paid.includes(name) ? null : lookAlike(name, paid);
    if (known !== null) found.push({ name, other: known, why: 'paid' });
    const earlier = lookAlike(name, list.slice(0, index));
    if (earlier !== null) found.push({ name, other: earlier, why: 'guardian' });
  });
  return found;
}
/// The warning for one of them, in pieces like the sentences above.
export const guardianAlikeWords = ({ name, other, why }) => ['@' + name, ' looks like ', '@' + other, (why === 'own' ? ', your own name.' : why === 'paid' ? ', which you have paid.' : ', another guardian in this list.') + ' Check every letter.'];
/// The box of the review of guardians that carries such a warning.
export const GUARDIAN_ACKNOWLEDGE = 'I checked the guardian names, letter by letter.';

// ---------------------------------------------------------------- a new name that the chain refuses
/// A network may refuse to register a name that looks like a name it already has. Its refusal holds the words
/// "too close to an existing name", followed by that name. "too close to the existing name" is read the same way:
/// that is how the engine's sentence stood in its own branch when this was written ("the name paypa1 is too close to
/// the existing name paypal: choose a name that does not look like it").
/// This gives that name, or null: for any other error, and when what follows the words is not written as account
/// names are. Nothing but those words and the name after them is read.
/// The refusal reaches the wallet through its gateway, whose words the wallet does not take for its own. So the name
/// is only where to look: before the wallet says anything of it, it checks by its own rule that the two names look
/// alike, and in proven state that the other one exists (app.js, nameRefusal).
export function tooCloseName(error) {
  const text = typeof error?.message === 'string' ? error.message : '';
  return /too close to (?:an|the) existing name[^a-z0-9_]{0,8}([a-z0-9_]{2,15})(?![a-z0-9_])/.exec(text)?.[1] ?? null;
}
/// What the wallet says of a new name that was refused because it looks like `existing`.
export const tooCloseWords = existing => `That name is too close to @${existing}, which already exists. Choose another.`;
