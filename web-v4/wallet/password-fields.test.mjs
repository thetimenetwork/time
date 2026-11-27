// The fields of the wallet's page that take the payment password, the recovery words or a printed recovery sheet
// (web audit of November 2026, W-6). A browser that offers to save what is typed there, and then syncs it to the
// person's Google or Apple account, puts the account's highest secret next to its vault. What the page does about it
// (README.md, "What the browser is told about the secret fields"):
// - the field stays a password field (`type="password"`): masked, never kept in the browser's form history, no spell
//   check, and a phone keyboard treats it as a password and learns nothing from it;
// - it is marked as a one-time code (`autocomplete="one-time-code"`), which Chromium's password manager does not take
//   for a password where the form also holds a password field without the mark, and takes only as a last resort, with
//   no prompt of its own, where every password field of the form is marked (form_data_parser.cc, IsNotPasswordField;
//   seen in a real Chrome 158: README.md, "Seen in a real Chrome");
// - spell check, capitals and corrections are off, and the attributes that 1Password, LastPass, Bitwarden and Proton
//   Pass read to leave a field alone are set;
// - each field that takes recovery words says in one short line not to let the browser save them.
// The login password is the other way round: a password manager holding it is wanted, and it keeps "new-password" and
// "current-password".
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../../', import.meta.url);
const page = await readFile(new URL('web-v4/wallet/index.html', root), 'utf8');

/// Every input and textarea of the page, with its attributes.
function fields(html) {
  const found = new Map();
  for (const match of html.matchAll(/<(input|textarea)\b([^>]*)>/g)) {
    const attrs = new Map();
    for (const a of match[2].matchAll(/([a-z0-9-]+)(?:="([^"]*)")?/g)) attrs.set(a[1], a[2] ?? '');
    if (attrs.has('id')) found.set(attrs.get('id'), { tag: match[1], attrs, text: match[0] });
  }
  return found;
}
const all = fields(page);

/// The payment password, everywhere it is asked or chosen.
export const PAYMENT_FIELDS = ['approval-payment', 'signup-payment', 'signup-payment-confirm', 'unfreeze-payment', 'limit-payment', 'pause-payment', 'resume-payment',
  'inbox-payment', 'send-payment', 'secure-payment', 'secure-payment-confirm', 'replace-login-payment', 'rr-payment', 'replace-spend-payment', 'replace-spend-new',
  'replace-spend-confirm', 'stake-payment', 'add-login-payment', 'signal-payment', 'validator-payment', 'removed-payment', 'lost-payment', 'lost-payment-confirm', 'lost-finish-payment',
  'lock-payment', 'lock-off-payment', 'remake-payment', 'move-payment', 'move-payment-confirm', 'move-old-payment', 'market-payment'];
/// The recovery words (or a printed recovery sheet). The freeze takes the payment password or the words in one field.
export const RECOVERY_FIELDS = ['freeze-secret', 'unfreeze-secret', 'limit-secret', 'resume-secret', 'inbox-secret', 'send-recovery-secret', 'rr-secret', 'replace-spend-secret',
  'lost-phrase', 'lost-sheet', 'move-old-secret'];
/// The login password (and the password of a backup file, which is the login password): a password manager may keep it.
/// `made-login` holds the login password the wallet made (the rule, vault.mjs RULE), in the dialog that shows it once,
/// beside the account's name as the user name (`made-name`), so that the browser may offer to keep it.
export const LOGIN_FIELDS = { 'password': 'new-password', 'password-confirm': 'new-password', 'backup-password': 'current-password', 'backup-export-password': 'current-password',
  'secure-login': 'new-password', 'secure-login-confirm': 'new-password', 'replace-login-new': 'new-password', 'replace-login-confirm': 'new-password',
  'replace-spend-login': 'new-password', 'replace-spend-login-confirm': 'new-password', 'removed-login-new': 'new-password', 'removed-login-confirm': 'new-password',
  'newlogin-password': 'new-password', 'newlogin-confirm': 'new-password', 'lost-login': 'new-password', 'lost-login-confirm': 'new-password',
  'lock-login': 'current-password', 'lock-off-login': 'current-password', 'remake-login': 'current-password', 'made-login': 'new-password',
  'move-login': 'new-password', 'move-login-confirm': 'new-password' };
const MARKS = { 'type': 'password', 'autocomplete': 'one-time-code', 'autocapitalize': 'off', 'autocorrect': 'off', 'spellcheck': 'false', 'data-1p-ignore': '', 'data-lpignore': 'true', 'data-bwignore': '', 'data-protonpass-ignore': '' };

test('W-6: every field of the payment password, the recovery words and a recovery sheet is a password field that password managers are told to leave alone', () => {
  for (const id of [...PAYMENT_FIELDS, ...RECOVERY_FIELDS]) {
    const field = all.get(id); assert.ok(field, `the page has no field ${id}`);
    assert.equal(field.tag, 'input', id);
    for (const [name, value] of Object.entries(MARKS)) assert.equal(field.attrs.get(name), value, `${id}: ${name} in ${field.text}`);
    assert.equal(field.attrs.has('value'), false, `${id} is given a value by the page`);
  }
});

test('W-6: the login password keeps what lets a password manager keep it, and nothing that turns one away', () => {
  for (const [id, autocomplete] of Object.entries(LOGIN_FIELDS)) {
    const field = all.get(id); assert.ok(field, `the page has no field ${id}`);
    assert.equal(field.attrs.get('type'), 'password', id);
    assert.equal(field.attrs.get('autocomplete'), autocomplete, id);
    for (const name of ['data-1p-ignore', 'data-lpignore', 'data-bwignore', 'data-protonpass-ignore']) assert.equal(field.attrs.has(name), false, `${id} has ${name}`);
  }
});

test('W-6: no password field of the page is outside the two lists, and none says only autocomplete="off"', () => {
  const known = new Set([...PAYMENT_FIELDS, ...RECOVERY_FIELDS, ...Object.keys(LOGIN_FIELDS)]);
  const passwords = [...all.entries()].filter(([, field]) => field.attrs.get('type') === 'password').map(([id]) => id);
  assert.deepEqual(passwords.filter(id => !known.has(id)), []);
  assert.deepEqual(passwords.filter(id => all.get(id).attrs.get('autocomplete') === 'off'), []);
  // A field that takes secrets is never a plain text field: a phone keyboard learns from those.
  for (const [id, field] of all) if (/(payment|secret|phrase|sheet)$/.test(id) && field.tag === 'input') assert.equal(field.attrs.get('type'), 'password', id);
});

test('the rule: the payment password the wallet made is in no field of the page, only shown; the login password it made stands under the account\'s name for the password manager', () => {
  const dialog = page.slice(page.indexOf('<dialog id="made-dialog"'), page.indexOf('</dialog>', page.indexOf('<dialog id="made-dialog"')));
  const inDialog = fields(dialog);
  assert.deepEqual([...inDialog.keys()], ['made-name', 'made-login']);
  assert.equal(inDialog.get('made-name').attrs.get('autocomplete'), 'username');
  assert.deepEqual([inDialog.get('made-login').attrs.get('type'), inDialog.get('made-login').attrs.get('autocomplete')], ['password', 'new-password']);
  assert.match(dialog, /<p class="made-password" id="made-payment-shown"><\/p>/);
  assert.match(dialog, /Do not let the browser save it\./);
});

test('W-6: each field of recovery words says not to let the browser save them', () => {
  for (const id of RECOVERY_FIELDS) {
    const field = all.get(id), after = page.slice(page.indexOf(field.text) + field.text.length).replace(/^\s+/, '');
    const note = /^<p\b[^>]*class="field-note"[^>]*>([^<]*)<\/p>/.exec(after)?.[1] ?? '';
    assert.match(note, /Do not let the browser save them\.$/, `${id}: ${note}`);
  }
});

test('W-6: no script of the wallet makes a password field or changes what a field tells the browser, but the login password\'s word', async () => {
  for (const file of ['app.js', 'security-ui.mjs', 'security-flows.mjs', 'signup-ui.mjs', 'recovery.mjs', 'alerts-ui.mjs', 'pos-ui.mjs', 'upgrade-signal-ui.mjs', 'papers.mjs', 'protection.mjs', 'device-lock-ui.mjs', 'made-dialog.mjs', 'move-ui.mjs', 'market-ui.mjs', 'market.mjs', 'market-api.mjs']) {
    const code = await readFile(new URL(`web-v4/wallet/${file}`, root), 'utf8');
    assert.equal(/\.type\s*=\s*['"]password['"]|setAttribute\(\s*['"](?:type|autocomplete)['"]/.test(code), false, file);
    const changes = [...code.matchAll(/\$\('([a-z0-9-]+)'\)\.autocomplete\s*=/g)].map(m => m[1]);
    assert.deepEqual(changes, file === 'app.js' ? ['password'] : [], file);
  }
});

// Real Chrome (version 158, the browser check's step "wallet-password-manager", runs of 24 November 2026) offered to
// save a password only after it took a form as sent, and it took one as sent after a request made with XMLHttpRequest:
// the wallet's own requests, made with fetch, did not count, and its secret fields emptied at once read to Chrome as a
// login that failed. So no script the wallet's page loads may use XMLHttpRequest: with it Chrome would start to infer
// sent forms, and a later change of its rules for forms of secret fields only would then offer to save them. (A person
// can still save a secret by hand through the key in Chrome's address bar; that is why the fields say not to.)
test('W-6: no script the wallet\'s page loads uses XMLHttpRequest, the request after which Chrome takes a form as sent', async () => {
  const { readdir } = await import('node:fs/promises');
  const files = [];
  for (const dir of ['web-v4/wallet/', 'web-v4/wallet/vendor/', 'web-v4/shared/']) {
    for (const name of await readdir(new URL(dir, root))) if (/\.m?js$/.test(name) && !/\.test\.mjs$/.test(name)) files.push(dir + name);
  }
  files.push('client-v4/time-sdk.js');
  assert.ok(files.includes('web-v4/wallet/app.js') && files.some(f => f.startsWith('web-v4/wallet/vendor/')) && files.some(f => f.startsWith('web-v4/shared/')), 'the scripts of the page were found');
  for (const file of files) assert.equal((await readFile(new URL(file, root), 'utf8')).includes('XMLHttpRequest'), false, file);
});
