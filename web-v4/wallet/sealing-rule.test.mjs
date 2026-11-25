// The rule of the wallet (vault.mjs, RULE): it never seals a key under a password a person chose, alone. Every vault
// record and every file it writes is sealed (i) with the device's secret and the password together (vault version 3),
// (ii) under a password the wallet made (at least 72 random bits), or (iii) under a key derived from a key that is itself
// sealed one of those ways (vault version 4).
//
// Here: the guard at source level (which scripts of the page mention what seals or derives a key, how many times, each
// with its reason, and who imports a sealing name: a new use fails with the rule; what it cannot see is said with it),
// the primitive's refusals, the made password itself (72 bits, every value reachable, read
// forgivingly), the format's marks, and the flows of device-lock.mjs and security-flows.mjs that make or seal keys again,
// against the fake authenticator of device-lock.test.mjs. The flows of the page are driven in signup.test.mjs and
// security-review-ui.test.mjs, with the page's own dialog of the passwords the wallet made, and what they keep and the
// backup files they make proven by opening them (tests/legacy-vault.mjs, provenSeals).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { createHash, createHmac, randomBytes, webcrypto } from 'node:crypto';
import { RULE, MadePassword, makePassword, madeText, madeForm, readMadePassword, madeWords, MADE_PASSWORD, SYLLABLES, newDevice, sealVault, openVault, sealUnder, openUnder, validateVaultRecord, vaultMade, vaultUnder, sealOf, UNDER_NEEDED } from './vault.mjs';
import { sealedKeys, vaultSlots, sealsOf, generatePassphrase, PASSPHRASE } from './security-flows.mjs';
import { turnOn, turnOff, remakePasswords, sealAtBirth, newKeysByRule, lockOf, createLockAsker, LOCK_WORDS, DEVICE_KEY_PLACE } from './device-lock.mjs';
import { sealLegacy, breakingTheRule, sealsKept, provenSeals } from './tests/legacy-vault.mjs';

const root = new URL('../../', import.meta.url);
const NET = 'c6'.repeat(32), LOGIN = 'violet otters dance beneath moonlight 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
// A quick stand-in for Argon2id, as device-lock.test.mjs has it: vault.mjs fixes what it asks for; the real one runs in the
// other vault tests.
const argon2id = async ({ password, salt }) => new Uint8Array(createHash('sha256').update(Buffer.from(password)).update(Buffer.from(salt)).digest());

// ------------------------------------------------------------------ the guard at source level
// Every script the wallet's page loads is read: each .js and .mjs file under web-v4/wallet/ and web-v4/shared/, at any
// depth, but the tests, the helpers of the tests and EXEMPT; and the files of the SDK the page loads from /sdk/. In each,
// without its comments (a string, a template or a regular expression that holds `//` or `/*` is not one), the guard counts
// every mention of what seals or derives a key: sealVault, sealUnder and makePassword (vault.mjs), the Argon2id function
// (`argon2id`, and `hashwasm`, the vendored library that holds it), PBKDF2 and scrypt, and WebCrypto's encrypt, wrapKey,
// deriveKey and deriveBits, in code or in quotes (`subtle['encrypt']` is a mention, and so is `sealVault.call(…)`). It
// also counts every mention of a local name given to one of them as a value (`const kdf = hashwasm.argon2id`, `const
// argon = () => c.argon2id()`, `const enc = subtle.encrypt.bind(subtle)`, `const { argon2id: kdf } = …`). And it reads who
// imports sealVault, sealUnder or makePassword, under any name, and who imports vault.mjs whole or at run time.
//
// The counts of each file are pinned below: MAY_SEAL (modules that seal or derive, each with its reason) and PASSES_ON
// (modules that only hand the Argon2id function or a sealing name on, each with its reason). A file on neither list that
// mentions one, a count that is not the one pinned (a new call inside a listed module too), or an import that is not
// pinned fails with the rule: a new use is reviewed and pinned here, with its reason. (A branch that would add a file of
// the payment key opened by the payment password alone stops here at merge, and sealVault refuses it at run time.)
//
// What it still cannot see: a name built from pieces at run time (`subtle['en' + 'crypt']`, `globalThis['hash' +
// 'wasm']`); a function handed on as an argument under another name (a parameter `kdf` given argon2id by its caller),
// whose calls are counted only where it is named; the output of Argon2id kept as it is (a hash of a typed password needs
// no encrypt); a cipher written in JavaScript; code the page loads from elsewhere. The page's CSP refuses eval and new
// Function. The vendored Argon2id and the compiled verifier are not read (EXEMPT, with why).
// <guard>
export const TOKENS = Object.freeze(['sealVault', 'sealUnder', 'makePassword', 'argon2id', 'hashwasm', 'PBKDF2', 'scrypt', 'encrypt', 'wrapKey', 'deriveKey', 'deriveBits']);
const SEALING_IMPORTS = new Set(['sealVault', 'sealUnder', 'makePassword']);
/// The files under the folders read that the guard does not read, each with why.
const EXEMPT = Object.freeze({
  'web-v4/wallet/vendor/argon2-4.12.0.umd.min.js': 'The vendored Argon2id itself (hash-wasm 4.12.0): the function that every count of argon2id and hashwasm is about.',
  'web-v4/shared/verifier/timecurrency_verifier_v4.js': 'The loader of the compiled proof verifier (wasm-bindgen): it checks the proofs of the chain and holds no key.',
});
/// The helpers of the tests (web-v4/wallet/tests/): never loaded by the page. The test below checks that no script the
/// page loads imports one, and that the release ships none.
const TEST_HELPERS = /^web-v4\/wallet\/tests\//;
/// The files of the SDK that the page loads from /sdk/ (client-v4/server.mjs, SDK_FILES).
const SDK = Object.freeze(['client-v4/time-sdk.js', 'client-v4/account-security.mjs', 'client-v4/proof-verifier.mjs', 'client-v4/light-client.mjs']);
export async function walk(dir) {
  const out = [];
  for (const entry of await readdir(new URL(dir, root), { withFileTypes: true })) {
    if (entry.isDirectory()) out.push(...await walk(`${dir}${entry.name}/`));
    else if (/\.m?js$/.test(entry.name) && !/\.test\.mjs$/.test(entry.name)) out.push(dir + entry.name);
  }
  return out;
}
/// Every script the guard reads.
export async function scripts() {
  const files = [...await walk('web-v4/wallet/'), ...await walk('web-v4/shared/'), ...SDK];
  return files.filter(file => !Object.hasOwn(EXEMPT, file) && !TEST_HELPERS.test(file)).sort();
}
/// The code of a script without its comments: `//` to the end of the line and `/* … */`, outside strings, templates and
/// regular expressions. Strings and templates are kept as they are.
export function codeOf(text) {
  let out = '', i = 0, depth = 0;
  const n = text.length, templates = [];
  const regexMayStart = () => { const before = out.replace(/\s+$/, ''); return before === '' || /[(,=:[!&|?{};+\-*%<>~^]$/.test(before) || /(?:^|[^\w$.])(?:return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)$/.test(before); };
  const templateBody = () => {
    while (i < n) {
      const c = text[i];
      if (c === '\\') { out += text.slice(i, i + 2); i += 2; continue; }
      if (c === '`') { out += c; i += 1; return; }
      if (c === '$' && text[i + 1] === '{') { out += '${'; i += 2; templates.push(depth); depth += 1; return; }
      out += c; i += 1;
    }
  };
  while (i < n) {
    const c = text[i], d = text[i + 1];
    if (c === '/' && d === '/') { while (i < n && text[i] !== '\n') i += 1; continue; }
    if (c === '/' && d === '*') { const end = text.indexOf('*/', i + 2); i = end < 0 ? n : end + 2; out += ' '; continue; }
    if (c === '"' || c === "'") { let j = i + 1; while (j < n && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1; out += text.slice(i, j + 1); i = j + 1; continue; }
    if (c === '`') { out += c; i += 1; templateBody(); continue; }
    if (c === '{') { depth += 1; out += c; i += 1; continue; }
    if (c === '}') {
      depth -= 1; out += c; i += 1;
      if (templates.length && templates.at(-1) === depth) { templates.pop(); templateBody(); }
      continue;
    }
    if (c === '/' && regexMayStart()) {
      let j = i + 1, inClass = false;
      while (j < n && text[j] !== '\n') { if (text[j] === '\\') { j += 2; continue; } if (text[j] === '[') inClass = true; else if (text[j] === ']') inClass = false; else if (text[j] === '/' && !inClass) break; j += 1; }
      j += 1; while (j < n && /[a-z]/i.test(text[j])) j += 1;
      out += text.slice(i, j); i = j; continue;
    }
    out += c; i += 1;
  }
  return out;
}
const TOKEN = new RegExp(`\\b(?:${TOKENS.join('|')})\\b`);
/// A reference to a value, not a call with arguments: `a.b?.c`, `a['b']`, `a.b()`, `() => a.b()`, `a.b.bind(c)`.
const REFERENCE = String.raw`(?:async\s*)?(?:\(\s*\)\s*=>\s*)?(?:await\s+)?[\w$]+(?:\s*(?:\?\.|\.)\s*[\w$]+|\s*\[\s*['"][\w$]+['"]\s*\]|\s*\(\s*\))*(?:\s*\.\s*bind\s*\([^()]*\))?`;
/// Whether a reference gives one of TOKENS as a function: the Argon2id function however it is reached (`c.argon2id()` is
/// the getter of a caller's), any other one named and not called (`makePassword()` gives a password, not the function).
const givesFunction = reference => /\b(?:argon2id|hashwasm)\b/.test(reference) || new RegExp(`\\b(?:${TOKENS.filter(t => !['argon2id', 'hashwasm'].includes(t)).join('|')})\\b(?!\\s*\\()`).test(reference);
/// The local names a script gives to one of TOKENS as a value.
export function aliasesOf(code) {
  const names = new Set();
  for (const m of code.matchAll(new RegExp(String.raw`(?:\b(?:const|let|var)\s+|,\s*)([\w$]+)\s*=\s*(${REFERENCE})\s*(?=[;,\n)}])`, 'g'))) if (givesFunction(m[2]) && !TOKENS.includes(m[1])) names.add(m[1]);
  for (const m of code.matchAll(/\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*([^;\n]*)/g)) {
    for (const part of m[1].split(',')) {
      const [key, value] = part.split(':').map(s => s.replace(/=.*$/s, '').trim()), local = value || key;
      if (local && !TOKENS.includes(local) && (TOKEN.test(key) || (givesFunction(m[2]) && new RegExp(`^${REFERENCE}$`).test(m[2].trim())))) names.add(local);
    }
  }
  return [...names].sort();
}
/// What the guard counts in a script's code: each of TOKENS mentioned, and each local name of one (`alias <name>`).
export function countsOf(code) {
  const counts = {};
  for (const token of TOKENS) { const found = code.match(new RegExp(`\\b${token}\\b`, 'g'))?.length ?? 0; if (found) counts[token] = found; }
  for (const alias of aliasesOf(code)) counts[`alias ${alias}`] = code.match(new RegExp(`(?<![\\w$.])${alias.replace(/\$/g, '\\$')}(?![\\w$])`, 'g'))?.length ?? 0;
  return counts;
}
/// What a script imports or exports again of vault.mjs: the sealing names, as `name` or `name as other`; and whether it
/// takes the module whole (a namespace or a default import) or imports anything at run time (`import(…)`).
export function importsOf(code) {
  const sealing = [], whole = [];
  for (const m of code.matchAll(/\b(?:import|export)\s*(?:([\w$]+)\s*,?\s*)?(?:\{([^}]*)\}|\*\s*(?:as\s+([\w$]+))?)?\s*from\s*['"]([^'"]+)['"]/g)) {
    if (!/(?:^|\/)vault\.mjs$/.test(m[4])) continue;
    if (m[1] || m[3] || /\*/.test(m[0].split('from')[0])) whole.push(m[0].replace(/\s+/g, ' '));
    for (const part of (m[2] ?? '').split(',')) { const [name, as] = part.trim().split(/\s+as\s+/); if (SEALING_IMPORTS.has(name)) sealing.push(as ? `${name} as ${as}` : name); }
  }
  for (const m of code.matchAll(/(?<![\w$.])import\s*\(([^)]*)\)/g)) whole.push(`import(${m[1].trim()})`);
  return { sealing: sealing.sort(), whole };
}
// </guard>

/// The modules that seal or derive a key, each with its reason, and what the guard counts in each.
const MAY_SEAL = Object.freeze({
  'web-v4/wallet/vault.mjs': { reason: 'Defines sealVault, sealUnder and makePassword, which take nothing but the rule; derives the vault key (Argon2id of the password, HKDF with the device\'s secret), the key under a login key and the private store\'s key from a login key\'s seed.',
    counts: { sealVault: 1, sealUnder: 1, makePassword: 2, argon2id: 8, encrypt: 6, deriveKey: 6 } },
  'web-v4/wallet/security-flows.mjs': { reason: 'sealedKeys: new keys with the device and a chosen password, or under a password the wallet makes, and a registration key under the new login key; Argon2id of the recovery words (made by the wallet, 90 bits) gives recovery keys and seals nothing.',
    counts: { sealVault: 2, sealUnder: 2, makePassword: 2, argon2id: 17 } },
  'web-v4/wallet/device-lock.mjs': { reason: 'Seals an account\'s keys again: with the device (turning the lock on), or under passwords the wallet makes (turning it off, "Let the wallet make my passwords"); keys locked from birth through security-flows.mjs.',
    counts: { sealVault: 6, makePassword: 4, argon2id: 26 } },
  'web-v4/wallet/app.js': { reason: 'The key of an account with one key, under a password the wallet makes (makePassword) and shows once; takes Argon2id from the vendored library (hashwasm) and hands it to the modules that seal or open keys.',
    counts: { sealVault: 2, makePassword: 2, argon2id: 15, hashwasm: 9 } },
  'web-v4/wallet/vault-backup.mjs': { reason: 'Restoring a file made before the rule: its key sealed again under a password the wallet makes, shown before it is kept.',
    counts: { sealVault: 2, makePassword: 2, argon2id: 6 } },
  'web-v4/wallet/recovery-file.mjs': { reason: 'The Recovery Kit: a recovery sheet sealed under the recovery words, which the wallet makes (90 bits), with the words\' Argon2id of 256 MiB.',
    counts: { argon2id: 7, encrypt: 2 } },
  'web-v4/wallet/device-key.mjs': { reason: 'The trial page\'s record, under a key derived from the device\'s secret alone: nothing typed.',
    counts: { encrypt: 2, wrapKey: 3, deriveKey: 2 } },
  'web-v4/wallet/locked-store.mjs': { reason: 'What the browser keeps private, under a random data key wrapped by a key derived from a login key\'s seed: nothing typed.',
    counts: { encrypt: 2 } },
});
/// The modules that only hand the Argon2id function, or a sealing name, on, each with its reason, and what the guard counts.
const PASSES_ON = Object.freeze({
  'web-v4/wallet/device-lock-ui.mjs': { reason: 'Hands the page\'s Argon2id to device-lock.mjs: turning the lock on or off, "Let the wallet make my passwords".', counts: { argon2id: 4 } },
  'web-v4/wallet/papers.mjs': { reason: 'Hands the page\'s Argon2id to security-flows.mjs and recovery-file.mjs, for the recovery words the wallet makes.', counts: { argon2id: 5 } },
  'web-v4/wallet/security-ui.mjs': { reason: 'Hands the page\'s Argon2id (its name there: argon) to security-flows.mjs, device-lock.mjs and recovery-file.mjs, and to openVault to open a key.', counts: { argon2id: 8, 'alias argon': 9 } },
  'web-v4/wallet/signup-ui.mjs': { reason: 'Hands the page\'s Argon2id (its name there: argon) to device-lock.mjs and papers.mjs at a sign-up.', counts: { argon2id: 3, 'alias argon': 3 } },
  'web-v4/wallet/move-ui.mjs': { reason: 'Hands the page\'s Argon2id to device-lock.mjs for the new keys of a move (newKeysByRule), and to openVault to open again a key under a password the wallet made; device-move.mjs seals nothing.', counts: { argon2id: 3 } },
});
/// Who may import sealVault, sealUnder or makePassword from vault.mjs, and under which names.
const IMPORTS = Object.freeze({
  'web-v4/wallet/app.js': ['makePassword', 'sealVault'],
  'web-v4/wallet/device-lock.mjs': ['makePassword', 'sealVault'],
  'web-v4/wallet/security-flows.mjs': ['makePassword', 'sealUnder', 'sealVault'],
  'web-v4/wallet/vault-backup.mjs': ['makePassword', 'sealVault'],
});
/// The imports at run time of a module whose name is not written out, each with why.
const RUN_TIME = Object.freeze({
  'client-v4/proof-verifier.mjs': { reason: 'Loads the loader of the compiled verifier (EXEMPT) from its own folder.', imports: ['import(js.href)'] },
  'client-v4/time-sdk.js': { reason: 'Loads the SDK\'s own verifier and light client from /sdk/, files the guard reads.', imports: ["import(new URL('/sdk/proof-verifier.js', root.location.origin)", "import(root.process?.versions?.node?'./light-client.mjs':new URL('/sdk/light-client.mjs',root.location.origin)"] },
});
const listed = file => MAY_SEAL[file] ?? PASSES_ON[file] ?? null;
const ruleFails = (file, what) => `${file} ${what}. ${RULE} A new use of what seals or derives a key is reviewed, then pinned in sealing-rule.test.mjs (MAY_SEAL or PASSES_ON), with its reason.`;

test('the guard reads every script the page loads, at any depth, and the SDK it loads; the helpers of the tests are never loaded nor shipped', async () => {
  const files = await scripts(), everything = [...await walk('web-v4/wallet/'), ...await walk('web-v4/shared/')];
  assert.ok(['web-v4/wallet/vault.mjs', 'web-v4/wallet/app.js', 'web-v4/shared/network-menu.js', 'client-v4/time-sdk.js'].every(file => files.includes(file)), 'the scripts of the page were found');
  assert.ok(everything.includes('web-v4/wallet/tests/legacy-vault.mjs') && everything.includes('web-v4/shared/verifier/timecurrency_verifier_v4.js'), 'subfolders are read');
  for (const file of Object.keys(EXEMPT)) assert.ok(everything.includes(file), `${file} is exempt and exists`);
  for (const reason of [...Object.values(EXEMPT), ...Object.values(MAY_SEAL).map(e => e.reason), ...Object.values(PASSES_ON).map(e => e.reason)]) assert.ok(reason.length > 20 && !reason.includes('\n'), 'one line of reason each');
  // No script the page loads imports a helper of the tests, and the release ships none.
  for (const file of files) assert.doesNotMatch(codeOf(await readFile(new URL(file, root), 'utf8')), /from\s*['"][^'"]*\/tests\/|import\s*\(\s*['"][^'"]*\/tests\//, file);
  assert.doesNotMatch(await readFile(new URL('tools/release-v4.mjs', root), 'utf8'), /web-v4\/wallet\/tests\//);
});

test('the guard: what seals or derives a key is mentioned only where it is pinned, as many times as pinned; a new use fails with the rule', async () => {
  const files = await scripts(), seen = new Set();
  for (const file of files) {
    const code = codeOf(await readFile(new URL(file, root), 'utf8')), counts = countsOf(code), pinned = listed(file), imports = importsOf(code);
    assert.deepEqual(counts, pinned?.counts ?? {}, ruleFails(file, pinned ? 'mentions what seals or derives a key another number of times than pinned' : `mentions ${Object.keys(counts).join(', ')}, and is not on the lists of the guard`));
    assert.deepEqual(imports.sealing, IMPORTS[file] ?? [], ruleFails(file, 'imports another sealing name than pinned'));
    assert.deepEqual(imports.whole.filter(w => /vault\.mjs/.test(w)), [], ruleFails(file, 'imports vault.mjs whole'));
    assert.deepEqual(imports.whole.filter(w => !/^import\((['"])[^'"]+\1\)$/.test(w)), RUN_TIME[file]?.imports ?? [], ruleFails(file, 'imports a module at run time by a name that is not written out'));
    if (Object.keys(counts).length) seen.add(file);
  }
  // No file is left on a list once it mentions nothing any more.
  for (const file of [...Object.keys(MAY_SEAL), ...Object.keys(PASSES_ON)]) assert.ok(seen.has(file), `${file} is on a list of the guard of sealing-rule.test.mjs but is not a script the page loads, or mentions nothing: take it off.`);
  for (const file of Object.keys(IMPORTS)) assert.ok(Object.hasOwn(MAY_SEAL, file), `${file} imports a sealing name: it belongs in MAY_SEAL.`);
  for (const file of Object.keys(RUN_TIME)) assert.ok(files.includes(file), `${file} is pinned for its imports at run time but is not read.`);
});

test('the guard sees what the review of 24 November slipped past it: comments, other names, calls through call or bind, aliases, brackets, subfolders', () => {
  const seen = code => countsOf(codeOf(code));
  // The ways of the review (guard.mjs): each is seen in a file on no list.
  const slipped = {
    'a call after a block comment on the same line': "/* kept for the kit */ const r = await sealVault({ pkcs8 }, payment, binding, argon2id, crypto, 'spend');",
    'imported under another name': "import { sealVault as keepKey } from './vault.mjs';\nconst r = await keepKey({ pkcs8 }, payment, binding, argon2id);",
    'called through call': 'const r = await sealVault.call(null, { pkcs8 }, payment, binding, argon2id);',
    'Argon2id with an options variable': 'const options = { password: typed, salt }; const k = await argon2id(options);',
    'Argon2id through a local alias': 'const kdf = globalThis.hashwasm.argon2id; const k = await kdf({ password: typed, salt });',
    'destructured subtle': "const { subtle } = crypto; const box = await subtle.encrypt({ name: 'AES-GCM', iv }, aes, data);",
    'bracket access': "const box = await crypto.subtle['encrypt']({ name: 'AES-GCM', iv }, aes, data);",
    'a bound encrypt': "const aes = await crypto.subtle.importKey('raw', await sha(typed), 'AES-GCM', false, ['encrypt']); const enc = crypto.subtle.encrypt.bind(crypto.subtle); await enc({ name: 'AES-GCM', iv }, aes, data);",
    'the Argon2id of a caller, under a getter': 'const argon = () => c.argon2id(); const k = await argon()({ password: typed, salt });',
  };
  for (const [what, code] of Object.entries(slipped)) assert.notDeepEqual(seen(code), {}, what);
  assert.deepEqual(importsOf(codeOf(slipped['imported under another name'])).sealing, ['sealVault as keepKey']);
  assert.deepEqual(seen(slipped['Argon2id through a local alias']), { argon2id: 1, hashwasm: 1, 'alias kdf': 2 });
  assert.deepEqual(seen(slipped['a bound encrypt']), { encrypt: 2, 'alias enc': 2 });
  // Inside a listed module, one more call changes its count: the alias of a getter counts each use.
  const once = seen('const argon = () => c.argon2id(); await open({ argon2id: argon() });'), twice = seen('const argon = () => c.argon2id(); await open({ argon2id: argon() }); await argon()({ password: typed, salt });');
  assert.notDeepEqual(once, twice);
  // The whole module, or a module named at run time.
  assert.deepEqual(importsOf(codeOf("import * as V from './vault.mjs'; V['seal' + 'Vault'](a);")).whole.length, 1);
  assert.deepEqual(importsOf(codeOf('const m = await import(place);')).whole, ['import(place)']);
  // Comments, of both kinds, anywhere on a line, are not mentions; strings, templates and regular expressions that hold
  // what looks like a comment are read as code.
  assert.deepEqual(seen('/// sealVault(secret, password) is described here.\nconst a = 1; // then sealVault\n/* sealVault( */ const b = 2;'), {});
  assert.deepEqual(seen("const url = 'https://x/'; sealVault(a); const t = `//${b}`; makePassword(); const r = /\\/\\//; encrypt();"), { sealVault: 1, makePassword: 1, encrypt: 1 });
  assert.deepEqual(seen('const s = `a ${`b ${c}`} /* d */`; sealUnder(x);'), { sealUnder: 1 });
});

// ------------------------------------------------------------------ the primitive refuses what the rule does not allow
test('sealVault refuses a password a person chose, alone, before anything is derived; and a made password read back from what was typed', async () => {
  const key = await newDevice(webcrypto), binding = { networkId: NET, name: 'alice', publicKey: key.publicKey };
  let calls = 0; const counting = async input => { calls += 1; return argon2id(input); };
  for (const [intent, secret] of [['device', { ...key.secret }], ['signin', { pkcs8: key.secret.pkcs8 }], ['spend', { pkcs8: key.secret.pkcs8 }]]) {
    await assert.rejects(sealVault(secret, LOGIN, binding, counting, webcrypto, intent), error => error.message === RULE, intent);
    // A made password the person typed back opens a record, and seals one only with the device.
    await assert.rejects(sealVault(secret, readMadePassword(makePassword().text), binding, counting, webcrypto, intent), error => error.message === RULE, intent);
  }
  assert.equal(calls, 0);
  // A made password cannot be made outside vault.mjs.
  assert.throws(() => new MadePassword(Symbol('made by the wallet'), 'kerine-netoji-nesimo-vebine', true), /comes from makePassword/);
  assert.equal(MadePassword.is({ text: 'kerine-netoji-nesimo-vebine', fresh: true }), false);
  // A password the wallet has just made seals alone, and the record says so.
  const made = makePassword(), record = await sealVault({ pkcs8: key.secret.pkcs8 }, made, binding, argon2id, webcrypto, 'spend');
  assert.deepEqual([record.version, record.intent, record.password, vaultMade(record), sealOf(record)], [2, 'spend', 'made', true, 'made']);
  assert.deepEqual(Object.keys(record).sort(), ['binding', 'ciphertext', 'intent', 'iv', 'kdf', 'password', 'salt', 'version']);
  // With the device, a chosen password is taken (held to checkPassword), and the record is of version 3.
  const lock = { credential: Buffer.from(randomBytes(32)).toString('base64url'), secret: new Uint8Array(randomBytes(32)) };
  assert.equal((await sealVault({ pkcs8: key.secret.pkcs8 }, LOGIN, binding, argon2id, webcrypto, 'signin', lock)).version, 3);
  await assert.rejects(sealVault({ pkcs8: key.secret.pkcs8 }, 'short', binding, argon2id, webcrypto, 'signin', lock), /at least 15 characters/);
});

test('a made password: four words of three syllables, 72 bits from crypto.getRandomValues, every value reachable at every place, none likelier', () => {
  assert.equal(MADE_PASSWORD.bits, MADE_PASSWORD.words * MADE_PASSWORD.syllablesPerWord * 6);
  assert.deepEqual([MADE_PASSWORD.words, MADE_PASSWORD.bits, MADE_PASSWORD.bytes, SYLLABLES.consonants.length * SYLLABLES.vowels.length], [4, 72, 9, 64]);
  // The syllables of the recovery words.
  assert.equal(generatePassphrase({ getRandomValues: b => b.fill(0) }).split(' ')[0], 'bababa');
  const SHAPE = /^([bdfghjklmnprstvz][aeio]){3}(-([bdfghjklmnprstvz][aeio]){3}){3}$/;
  // Nine bytes, cut into twelve values of 6 bits in order: decoding the text gives the bytes back, so every value of the
  // 72 bits is a password of its own (no two byte strings give one password, and none is unreachable).
  const syllable = new Map(); for (let v = 0; v < 64; v++) syllable.set(SYLLABLES.consonants[v >> 2] + SYLLABLES.vowels[v & 3], v);
  const decode = text => { const values = text.replace(/-/g, '').match(/../g).map(s => syllable.get(s)); let bits = 0n; for (const v of values) bits = (bits << 6n) | BigInt(v); return bits; };
  // The bytes are read through madeText, which gives a plain text: a text seals nothing alone (sealVault), so no fixed
  // value of a test can become a password that seals.
  for (let i = 0; i < 300; i++) {
    const bytes = new Uint8Array(randomBytes(9)), text = madeText(bytes);
    assert.match(text, SHAPE);
    assert.equal(decode(text), BigInt('0x' + Buffer.from(bytes).toString('hex')));
    assert.equal(typeof text, 'string');
  }
  // Every value of 6 bits at each of the twelve places.
  for (let place = 0; place < 12; place++) for (let v = 0; v < 64; v++) {
    const bits = BigInt(v) << BigInt(6 * (11 - place)), bytes = Uint8Array.from(Buffer.from(bits.toString(16).padStart(18, '0'), 'hex'));
    const text = madeText(bytes).replace(/-/g, '');
    assert.equal(syllable.get(text.slice(2 * place, 2 * place + 2)), v, `value ${v} at place ${place}`);
  }
  for (const wrong of [new Uint8Array(0), new Uint8Array(8), new Uint8Array(12), new Array(9).fill(0), new Uint16Array(9), 'kerinenetoji']) assert.throws(() => madeText(wrong), /9 bytes/);
  // From the real generator: distinct, in the shape, and not the look of the recovery words (spaces).
  const seen = new Set(); for (let i = 0; i < 200; i++) { const t = makePassword().text; assert.match(t, SHAPE); seen.add(t); }
  assert.equal(seen.size, 200);
  assert.doesNotMatch(makePassword().text, / /); assert.match(generatePassphrase(), / /); assert.equal(PASSPHRASE.words, 5);
});

test('makePassword takes no randomness from outside: the browser\'s generator fills an array of its own, whatever it returns, wiped after; one made password seals one record, once', async () => {
  assert.equal(makePassword.length, 0, 'nothing can be handed in');
  // What a caller passes is not used: a source of zeros, typed bytes, an empty array, twelve bytes, a text.
  const sources = [{ getRandomValues: b => b.fill(0) }, { getRandomValues: () => new Uint8Array(9) }, { getRandomValues: () => new Uint8Array(0) }, { getRandomValues: () => new Uint8Array(12).fill(1) }, { getRandomValues: () => 'kerinenetojinesimovebine' }];
  const seen = new Set();
  for (const source of sources) { const made = makePassword(source); assert.notEqual(made.text, madeText(new Uint8Array(9)), 'not the password of nine zero bytes'); assert.equal(made.fresh, true); seen.add(made.text); }
  assert.equal(seen.size, sources.length);
  // The browser's own generator fills the password's own array of nine bytes; what it returns is ignored, and the array
  // is wiped after use.
  const fixed = new Uint8Array(randomBytes(9)); let given = null;
  globalThis.crypto.getRandomValues = b => { given = b; b.set(fixed); return new Uint8Array(9).fill(1); };
  let made;
  try { made = makePassword(); } finally { delete globalThis.crypto.getRandomValues; }
  assert.deepEqual([made.text, given.length, [...given]], [madeText(fixed), 9, new Array(9).fill(0)]);
  assert.equal(globalThis.crypto.getRandomValues(new Uint8Array(4)).length, 4, 'the generator is back');
  // One fresh password seals one record, once: after that it is only the text that opens it.
  const key = await newDevice(webcrypto), binding = { networkId: NET, name: 'alice', publicKey: key.publicKey };
  const once = makePassword(), record = await sealVault({ pkcs8: key.secret.pkcs8 }, once, binding, argon2id, webcrypto, 'spend');
  assert.equal(once.fresh, false);
  await assert.rejects(sealVault({ pkcs8: key.secret.pkcs8 }, once, binding, argon2id, webcrypto, 'spend'), error => error.message === RULE, 'a second record under the same made password');
  await assert.rejects(sealVault({ ...key.secret }, once, binding, argon2id, webcrypto), error => error.message === RULE, 'nor a record of another kind');
  assert.equal((await openVault(record, once.text, argon2id, webcrypto, 'spend')).binding.publicKey, key.publicKey);
  // Two seals started together: one of them only.
  const both = makePassword(), results = await Promise.allSettled([sealVault({ pkcs8: key.secret.pkcs8 }, both, binding, argon2id, webcrypto, 'signin'), sealVault({ pkcs8: key.secret.pkcs8 }, both, binding, argon2id, webcrypto, 'spend')]);
  assert.deepEqual(results.map(r => r.status).sort(), ['fulfilled', 'rejected']);
  // With the device too, a fresh made password is used up.
  const lock = { credential: Buffer.from(randomBytes(32)).toString('base64url'), secret: new Uint8Array(randomBytes(32)) }, locked = makePassword();
  assert.equal((await sealVault({ pkcs8: key.secret.pkcs8 }, locked, binding, argon2id, webcrypto, 'signin', lock)).version, 3);
  await assert.rejects(sealVault({ pkcs8: key.secret.pkcs8 }, locked, binding, argon2id, webcrypto, 'signin'), error => error.message === RULE);
});

test('a made password is read forgivingly into one canonical form: case, spaces and dashes do not matter; anything else is said in words', async () => {
  const made = makePassword(), [a, b, c, d] = made.text.split('-');
  for (const typed of [made.text, made.text.toUpperCase(), `${a} ${b} ${c} ${d}`, `  ${a}-${b} ${c}–${d}  `, `${a}${b}${c}${d}`, `${a.toUpperCase()}‐${b}—${c}−${d}`, `${a}\t${b}\n${c} - ${d}`]) assert.equal(madeForm(typed), made.text, JSON.stringify(typed));
  // A letter outside the syllables, where one of them certainly stands: every syllable is a consonant and a vowel
  // (vault.mjs, SYLLABLES), so the second letter is a vowel, made 'u', and the first a consonant, made 'c' (neither is one
  // of the syllables' letters). Before, every 'a' was made 'u', which changed nothing in a password with no 'a'.
  const vowelOff = `${made.text[0]}u${made.text.slice(2)}`, consonantOff = `c${made.text.slice(1)}`;
  assert.ok(vowelOff !== made.text && consonantOff !== made.text && !SYLLABLES.vowels.includes('u') && !SYLLABLES.consonants.includes('c') && SYLLABLES.vowels.includes(made.text[1]) && SYLLABLES.consonants.includes(made.text[0]));
  for (const typed of [`${a}-${b}-${c}`, `${made.text}-${a}`, vowelOff, consonantOff, `${a}_${b}_${c}_${d}`, '', 'x'.repeat(300), 42]) assert.equal(madeForm(typed), null, JSON.stringify(typed));
  // The record says how to read what is typed, before any derivation.
  const key = await newDevice(webcrypto), record = await sealVault({ pkcs8: key.secret.pkcs8 }, made, { networkId: NET, name: 'alice', publicKey: key.publicKey }, argon2id, webcrypto, 'signin');
  for (const typed of [made.text.toUpperCase(), `${a} ${b} ${c} ${d}`]) assert.equal((await openVault(record, typed, argon2id, webcrypto, 'signin')).binding.publicKey, key.publicKey);
  let calls = 0; const counting = async input => { calls += 1; return argon2id(input); };
  await assert.rejects(openVault(record, LOGIN, counting, webcrypto, 'signin'), error => error.madeForm === true && error.message === madeWords('signin'));
  assert.equal(calls, 0);
  await assert.rejects(openVault(record, makePassword().text, argon2id, webcrypto, 'signin'), /Could not unlock/);
  assert.match(madeWords('spend'), /^Your payment password is one the wallet made/); assert.match(madeWords('signin'), /^Your login password is one the wallet made/);
  // The mark is authenticated: taken away, or put on a record of a chosen password, the record opens for nobody.
  const { password, ...unmarked } = record;
  await assert.rejects(openVault(unmarked, made.text, argon2id, webcrypto, 'signin'), /Could not unlock/);
  const legacy = await sealLegacy({ pkcs8: key.secret.pkcs8 }, LOGIN, { networkId: NET, name: 'alice', publicKey: key.publicKey }, argon2id, webcrypto, 'signin');
  assert.equal(sealOf(legacy), 'chosen');
  assert.equal((await openVault(legacy, LOGIN, argon2id, webcrypto, 'signin')).intent, 'signin', 'a record from before the rule opens as before');
  await assert.rejects(openVault({ ...legacy, password: 'made' }, LOGIN, argon2id, webcrypto, 'signin'), error => error.madeForm === true);
  assert.throws(() => validateVaultRecord({ ...record, password: 'chosen' }, 'signin'), /Unsupported vault/);
});

test('a key kept under another key (vault version 4): opened only with that key, once opened itself; never with anything typed', async () => {
  const login = await newDevice(webcrypto), registration = await newDevice(webcrypto), binding = { networkId: NET, name: 'alice', publicKey: registration.publicKey };
  const secret = { ...registration.secret, nameSalt: 'cd'.repeat(32), intent: 'device' };
  const record = await sealUnder(secret, binding, { publicKey: login.publicKey, pkcs8: login.secret.pkcs8 }, webcrypto);
  assert.deepEqual(Object.keys(record).sort(), ['binding', 'ciphertext', 'iv', 'salt', 'under', 'version']);
  assert.deepEqual([record.version, record.under, vaultUnder(record), sealOf(record)], [4, { intent: 'signin', publicKey: login.publicKey }, { intent: 'signin', publicKey: login.publicKey }, 'under']);
  const opened = await openUnder(record, { publicKey: login.publicKey, pkcs8: login.secret.pkcs8 }, webcrypto);
  assert.deepEqual([opened.binding.publicKey, opened.secret.nameSalt, opened.intent, opened.storageKey !== null], [registration.publicKey, 'cd'.repeat(32), 'device', true]);
  // Nothing typed opens it; another login key does not; a header changed to name another key does not.
  await assert.rejects(openVault(record, LOGIN, argon2id, webcrypto), error => error.underNeeded === true && error.message === UNDER_NEEDED);
  const other = await newDevice(webcrypto);
  await assert.rejects(openUnder(record, { publicKey: other.publicKey, pkcs8: other.secret.pkcs8 }, webcrypto), /sealed under another login key/);
  await assert.rejects(openUnder({ ...record, under: { intent: 'signin', publicKey: other.publicKey } }, { publicKey: other.publicKey, pkcs8: other.secret.pkcs8 }, webcrypto), /Could not open/);
  await assert.rejects(openUnder(record, { publicKey: login.publicKey, pkcs8: other.secret.pkcs8 }, webcrypto), /Could not open/);
  assert.throws(() => validateVaultRecord({ ...record, kdf: {} }), /Unsupported vault/);
  await assert.rejects(sealUnder(secret, binding, { publicKey: registration.publicKey, pkcs8: registration.secret.pkcs8 }, webcrypto), /not sealed under itself/);
});

test('the proof of the tests (tests/legacy-vault.mjs, provenSeals) opens each record: a header that says "made" is not taken at its word, nor a file', async () => {
  const slots = vaultSlots(NET, 'alice'), key = await newDevice(webcrypto), spend = await newDevice(webcrypto), binding = { networkId: NET, name: 'alice', publicKey: key.publicKey };
  const made = makePassword(), text = made.text, record = await sealVault({ pkcs8: key.secret.pkcs8 }, made, binding, argon2id, webcrypto, 'signin');
  const prove = (entries, more = {}) => provenSeals({ entries, argon2id, cryptoImpl: webcrypto, ...more });
  assert.deepEqual(await prove([[slots.login, JSON.stringify(record)]], { shown: [text], typed: [LOGIN] }), []);
  assert.deepEqual(await prove([[slots.login, JSON.stringify(record)]], { shown: [makePassword().text] }), ['timecurrency.vault.v1: marked as made, and no password shown opens it']);
  assert.deepEqual(await prove([[slots.login, JSON.stringify(record)]], { shown: [text], typed: [text.toUpperCase()] }), ['timecurrency.vault.v1: opens with what was typed']);
  const chosen = await sealLegacy({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'alice', publicKey: spend.publicKey }, argon2id, webcrypto, 'spend');
  assert.deepEqual(await prove([[slots.spend, JSON.stringify(chosen)]]), ['timecurrency.spend-vault.v1: sealed under a chosen password alone']);
  // Locked to the device: opens with its secret and the password typed, never with another secret.
  const secret = new Uint8Array(randomBytes(32)), lock = { credential: Buffer.from(randomBytes(32)).toString('base64url'), secret };
  const locked = await sealVault({ pkcs8: spend.secret.pkcs8 }, PAYMENT, { networkId: NET, name: 'alice', publicKey: spend.publicKey }, argon2id, webcrypto, 'spend', lock);
  assert.deepEqual(await prove([[slots.spend, JSON.stringify(locked)]], { typed: [PAYMENT], device: async () => secret }), []);
  assert.deepEqual(await prove([[slots.spend, JSON.stringify(locked)]], { typed: [PAYMENT], device: async () => new Uint8Array(32).fill(1) }), ['timecurrency.spend-vault.v1: locked to the device, and opens with nothing typed or shown and the device\'s secret']);
  // Kept under a login key that the storage does not hold.
  const registration = await newDevice(webcrypto), under = await sealUnder({ ...registration.secret, nameSalt: 'ab'.repeat(32), intent: 'device' }, { networkId: NET, name: 'alice', publicKey: registration.publicKey }, { publicKey: key.publicKey, pkcs8: key.secret.pkcs8 }, webcrypto);
  assert.deepEqual(await prove([[slots.login, JSON.stringify(under)]]), ['timecurrency.vault.v1: kept under a login key that this storage does not hold']);
  assert.deepEqual(await prove([[slots.login, JSON.stringify(under)], [slots.nextLogin, JSON.stringify(record)]], { shown: [text] }), []);
  // Backup files: of a record whose password the wallet made, opening with the password shown.
  const file = r => JSON.stringify({ format: 'timecurrency-encrypted-vault', version: 1, vault: r });
  assert.deepEqual(await prove([], { files: [file(record)], shown: [text], typed: [LOGIN] }), []);
  const legacy = await sealLegacy({ pkcs8: key.secret.pkcs8 }, LOGIN, binding, argon2id, webcrypto, 'signin');
  assert.deepEqual(await prove([], { files: [file(legacy), 'not json'] }), ['file 2: not a backup file', 'file 1: sealed under a chosen password alone']);
});

test('sealedKeys: without the device every key gets a password the wallet makes, a typed password is refused; with it, version 3; a registration key goes under the login key', async () => {
  await assert.rejects(sealedKeys({ wanted: [{ intent: 'signin', password: LOGIN }], networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto }), error => error.message === RULE);
  const registration = await newDevice(webcrypto);
  const [signin, spend] = await sealedKeys({ wanted: [{ intent: 'signin' }, { intent: 'spend' }], networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto,
    under: { secret: { ...registration.secret, nameSalt: 'ab'.repeat(32), intent: 'device' }, binding: { networkId: NET, name: 'alice', publicKey: registration.publicKey } } });
  assert.deepEqual([signin.record.version, signin.record.password, spend.record.password, typeof signin.made, signin.made === spend.made], [2, 'made', 'made', 'string', false]);
  assert.equal(madeForm(signin.made), signin.made);
  assert.equal((await openVault(spend.record, spend.made, argon2id, webcrypto, 'spend')).binding.publicKey, spend.key.publicKey);
  assert.deepEqual([signin.under.version, signin.under.under.publicKey, spend.under], [4, signin.key.publicKey, undefined]);
  // The login key the made password opens opens the registration key.
  const login = await openVault(signin.record, signin.made, argon2id, webcrypto, 'signin');
  assert.equal((await openUnder(signin.under, { publicKey: login.binding.publicKey, pkcs8: login.secret.pkcs8 }, webcrypto)).binding.publicKey, registration.publicKey);
});

// ------------------------------------------------------------------ the flows of device-lock.mjs against a fake authenticator
class Storage {
  m = new Map();
  get length() { return this.m.size; }
  key(i) { return [...this.m.keys()][i] ?? null; }
  getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }
  setItem(k, v) { this.m.set(k, String(v)); }
  removeItem(k) { this.m.delete(k); }
}
const prfOf = (key, salt) => createHmac('sha256', key).update(createHash('sha256').update(Buffer.concat([Buffer.from('WebAuthn PRF'), Buffer.from([0]), Buffer.from(salt)])).digest()).digest();
const buffer = bytes => { const copy = new ArrayBuffer(bytes.length); new Uint8Array(copy).set(bytes); return copy; };
/// The fake device of device-lock.test.mjs: `getErrors` (one error name per request), `secondDiffers` (the n-th request
/// answers from another secret), `noPrf`, `none` (no built-in authenticator at all). Like a platform authenticator, it
/// replaces a key made with the user handle of an earlier one. It answers with its latest key, or with the one `pick(id)`
/// names (the person choosing a key); `list()` gives its keys' ids and user handles, in base64url.
function fakeDevice(s = {}) {
  const keys = []; let gets = 0, creates = 0, picked = null;
  const authData = () => { const b = new Uint8Array(37); b[32] = 0x05; return buffer(b); };
  class PublicKeyCredential { static async isUserVerifyingPlatformAuthenticatorAvailable() { return !s.none; } static async getClientCapabilities() { return { userVerifyingPlatformAuthenticator: !s.none, 'extension:prf': !s.noPrf }; } }
  const credentials = {
    async create(options) { creates += 1; const handle = Buffer.from(options.publicKey.user.id); for (let i = keys.length - 1; i >= 0; i--) if (keys[i].handle.equals(handle)) keys.splice(i, 1); const key = { id: randomBytes(32), secret: randomBytes(32), handle }; keys.push(key); return { type: 'public-key', rawId: buffer(key.id), response: { getAuthenticatorData: () => authData() }, getClientExtensionResults: () => ({ prf: { enabled: !s.noPrf } }) }; },
    async get(options) {
      gets += 1; const error = s.getErrors?.[gets - 1]; if (error) throw new DOMException('x', error);
      if (!keys.length) throw new DOMException('x', 'NotAllowedError');
      const key = keys.find(k => picked !== null && k.id.toString('base64url') === picked) ?? keys.at(-1), salts = options.publicKey.extensions.prf.eval, secret = s.secondDiffers === gets ? randomBytes(32) : key.secret;
      return { type: 'public-key', rawId: buffer(key.id), response: { authenticatorData: authData() }, getClientExtensionResults: () => ({ prf: { results: { first: buffer(prfOf(secret, salts.first)), ...(salts.second ? { second: buffer(prfOf(secret, salts.second)) } : {}) } } }) };
    },
  };
  return { env: { secureContext: true, credentials, PublicKeyCredential, crypto: webcrypto, phone: false }, gets: () => gets, creates: () => creates, remove: () => keys.splice(0),
    pick: id => { picked = id; }, list: () => keys.map(k => ({ id: k.id.toString('base64url'), handle: k.handle.toString('base64url') })) };
}
const wanted = [{ intent: 'signin', password: LOGIN }, { intent: 'spend', password: PAYMENT }];

test('keys locked from birth: the device made and asked twice (three times in all), every record of version 3, opening with the second answer; a device key in use is asked twice', async () => {
  const storage = new Storage(), device = fakeDevice(), said = [];
  const result = await sealAtBirth({ storage, env: device.env, wanted, networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto, say: text => said.push(text) });
  assert.deepEqual([device.creates(), device.gets(), result.madeKey, result.keys.map(k => [k.record.version, k.made])], [1, 2, true, [[3, null], [3, null]]]);
  assert.deepEqual(said, [LOCK_WORDS.birth, LOCK_WORDS.before]);
  assert.equal(JSON.parse(storage.getItem(DEVICE_KEY_PLACE)).credential, result.credential);
  // Kept as a sign-up keeps them, they use the device key: the next account's keys are locked with it, two requests.
  const slots = vaultSlots(NET, 'alice');
  storage.setItem(slots.login, JSON.stringify(result.keys[0].record)); storage.setItem(slots.spend, JSON.stringify(result.keys[1].record));
  assert.deepEqual(breakingTheRule([...storage.m]), []);
  const bob = await sealAtBirth({ storage, env: device.env, wanted, networkId: NET, name: 'bob', argon2id, cryptoImpl: webcrypto });
  assert.deepEqual([device.creates(), device.gets(), bob.madeKey, bob.credential], [1, 4, false, result.credential]);
});

test('a device that fails at any step never ends the flow: the wallet makes both passwords instead, and says what happened; nothing typed seals anything', async () => {
  const cases = [
    ['no built-in authenticator (nothing is asked)', { none: true }, /cannot lock keys with your fingerprint/, 0],
    ['no PRF', { noPrf: true }, /cannot lock keys with your fingerprint/, 0],
    ['the person cancels the first request', { getErrors: ['NotAllowedError'] }, /did not give its key/, 1],
    ['the person cancels the second request', { getErrors: [null, 'NotAllowedError'] }, /did not give its key/, 2],
    ['the second answer differs', { secondDiffers: 2 }, /another answer the second time/, 2],
  ];
  for (const [what, switches, words, gets] of cases) {
    const storage = new Storage(), device = fakeDevice(switches);
    const made = await newKeysByRule({ byDevice: true, storage, env: device.env, wanted, networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto });
    assert.equal(made.locked, false, what); assert.match(made.fallback, words, what); assert.ok(made.fallback.endsWith(LOCK_WORDS.fellBack), what);
    assert.equal(device.gets(), gets, what);
    for (const entry of made.keys) {
      assert.deepEqual([entry.record.version, entry.record.password], [2, 'made'], what);
      await assert.rejects(openVault(entry.record, entry.record.intent === 'spend' ? PAYMENT : LOGIN, argon2id, webcrypto, entry.record.intent), error => error.madeForm === true, `${what}: the typed password opens nothing`);
      assert.equal((await openVault(entry.record, entry.made, argon2id, webcrypto, entry.record.intent)).intent, entry.record.intent, what);
    }
  }
  // Declined (byDevice false): nothing is asked, and the wallet makes the passwords.
  const device = fakeDevice(), declined = await newKeysByRule({ byDevice: false, storage: new Storage(), env: device.env, wanted, networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto });
  assert.deepEqual([device.gets(), device.creates(), declined.locked, declined.fallback, declined.keys.every(k => k.record.password === 'made')], [0, 0, false, null, true]);
});

/// A browser that holds a protected account's keys: from before the rule (under chosen passwords), or made by it.
async function account(storage, { legacy = false, name = 'alice' } = {}) {
  const slots = vaultSlots(NET, name), keys = [await newDevice(webcrypto), await newDevice(webcrypto)], made = {};
  for (const [i, place, intent, password] of [[0, slots.login, 'signin', LOGIN], [1, slots.spend, 'spend', PAYMENT]]) {
    const binding = { networkId: NET, name, publicKey: keys[i].publicKey };
    if (legacy) storage.setItem(place, JSON.stringify(await sealLegacy({ pkcs8: keys[i].secret.pkcs8 }, password, binding, argon2id, webcrypto, intent)));
    else { const p = makePassword(); made[intent] = p.text; storage.setItem(place, JSON.stringify(await sealVault({ pkcs8: keys[i].secret.pkcs8 }, p, binding, argon2id, webcrypto, intent))); }
  }
  return { slots, name, login: legacy ? LOGIN : made.signin, payment: legacy ? PAYMENT : made.spend, keys };
}

test('turning the lock off: the keys are sealed under passwords the wallet makes, shown before anything is replaced; the passwords of before open nothing', async () => {
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  await turnOn({ storage, slots: a.slots, networkId: NET, name: 'alice', login: a.login.toUpperCase().replace(/-/g, ' '), payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto });
  // Locked with the made passwords, typed any way: the records keep the mark, so they are read the same way after.
  assert.deepEqual(sealsKept([...storage.m]).map(s => [s.version, s.seal]), [[3, 'device'], [3, 'device']]);
  assert.equal(JSON.parse(storage.getItem(a.slots.login)).password, 'made');
  let shown = null, keptWhenShown = null;
  const result = await turnOff({ storage, slots: a.slots, networkId: NET, name: 'alice', login: a.login, payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto,
    show: async made => { shown = made; keptWhenShown = [storage.getItem(a.slots.login), storage.getItem(a.slots.spend)].map(v => JSON.parse(v).version); } });
  assert.deepEqual(keptWhenShown, [3, 3], 'nothing was replaced before the passwords were shown');
  assert.deepEqual(result.made, shown); assert.ok(madeForm(shown.login) && madeForm(shown.payment) && shown.login !== a.login && shown.payment !== a.payment);
  assert.deepEqual(sealsKept([...storage.m]).map(s => [s.version, s.seal]), [[2, 'made'], [2, 'made']]);
  assert.deepEqual(await provenSeals({ entries: [...storage.m], shown: [shown.login, shown.payment], typed: [a.login, a.payment], argon2id, cryptoImpl: webcrypto }), []);
  assert.equal((await openVault(JSON.parse(storage.getItem(a.slots.spend)), shown.payment, argon2id, webcrypto, 'spend')).binding.publicKey, a.keys[1].publicKey);
  await assert.rejects(openVault(JSON.parse(storage.getItem(a.slots.spend)), a.payment, argon2id, webcrypto, 'spend'), /Could not unlock/);
  // Turned on again from a lock of chosen passwords (from before the rule): off, the wallet makes the passwords all the same.
  const old = new Storage(), legacy = await account(old, { legacy: true });
  await turnOn({ storage: old, slots: legacy.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, env: device.env, cryptoImpl: webcrypto });
  await turnOff({ storage: old, slots: legacy.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, env: device.env, cryptoImpl: webcrypto });
  assert.deepEqual(breakingTheRule([...old.m]), []);
});

/// Whether this browser's record at `place` opens now with `password` and the device's answer.
async function opensWithDevice(storage, device, place, password, intent) {
  const record = JSON.parse(storage.getItem(place));
  try { const [secret] = await createLockAsker({ env: device.env }).secretsFor([record]); await openVault(record, password, argon2id, webcrypto, intent, secret); return true; } catch { return false; }
}

test('a recovery on a browser whose keys are locked to this device asks for the kept device key first; a key made then gets a fresh user handle, so that the keys of now keep opening until the new ones are written', async () => {
  const replaced = slots => [slots.login, slots.spend];
  // The device still has the kept key: the new keys are locked with it, and nothing is made (two requests).
  const storage = new Storage(), device = fakeDevice(), a = await account(storage);
  await turnOn({ storage, slots: a.slots, networkId: NET, name: 'alice', login: a.login, payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto });
  const kept = JSON.parse(storage.getItem(DEVICE_KEY_PLACE)), gets = device.gets();
  const same = await newKeysByRule({ byDevice: true, storage, env: device.env, wanted, networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto, except: replaced(a.slots) });
  assert.deepEqual([same.locked, same.madeKey, device.creates(), device.gets() - gets, same.keys.every(k => k.record.device.credential === kept.credential)], [true, false, 1, 2, true]);
  assert.deepEqual(JSON.parse(storage.getItem(DEVICE_KEY_PLACE)), kept);
  assert.equal(await opensWithDevice(storage, device, a.slots.login, a.login, 'signin'), true, 'the login key of now still opens');
  // The device answers with another key: a new one is made with a fresh user handle; the kept key stays on the device, and
  // the keys of now open with it.
  await device.env.credentials.create({ publicKey: { user: { id: randomBytes(16) } } });
  const other = await newKeysByRule({ byDevice: true, storage, env: device.env, wanted, networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto, except: replaced(a.slots) });
  const now = JSON.parse(storage.getItem(DEVICE_KEY_PLACE));
  assert.deepEqual([other.locked, other.madeKey, device.creates(), now.credential === kept.credential, now.handle === kept.handle, device.list().some(k => k.id === kept.credential)], [true, true, 3, false, false, true]);
  device.pick(kept.credential);
  assert.equal(await opensWithDevice(storage, device, a.slots.login, a.login, 'signin'), true, 'the login key of now still opens');
  assert.equal(await opensWithDevice(storage, device, a.slots.spend, a.payment, 'spend'), true, 'the payment key of now still opens');
  // The device gives no key at all (it lost them): a new key with a fresh user handle locks the new keys.
  const bare = new Storage(), gone = fakeDevice(), b = await account(bare);
  await turnOn({ storage: bare, slots: b.slots, networkId: NET, name: 'alice', login: b.login, payment: b.payment, argon2id, env: gone.env, cryptoImpl: webcrypto });
  const before = JSON.parse(bare.getItem(DEVICE_KEY_PLACE)); gone.remove();
  const fresh = await newKeysByRule({ byDevice: true, storage: bare, env: gone.env, wanted, networkId: NET, name: 'alice', argon2id, cryptoImpl: webcrypto, except: replaced(b.slots) });
  assert.deepEqual([fresh.locked, fresh.madeKey, JSON.parse(bare.getItem(DEVICE_KEY_PLACE)).handle === before.handle, gone.list().length], [true, true, false, 1]);
});

/// Web Locks that count what is held, so that a test sees whether the lock of the vaults is held while passwords are shown.
const countingLocks = () => { const locks = { held: 0, async request(name, options, fn) { locks.held += 1; try { return await fn(); } finally { locks.held -= 1; } } }; return locks; };

test('turning the lock off and "Let the wallet make my passwords" show the passwords with the lock of the vaults let go; keys changed meanwhile in this browser are not replaced', async () => {
  // Turning the lock off.
  const storage = new Storage(), device = fakeDevice(), a = await account(storage), locks = countingLocks();
  await turnOn({ storage, slots: a.slots, networkId: NET, name: 'alice', login: a.login, payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto });
  let heldWhenShown = null;
  await turnOff({ storage, slots: a.slots, networkId: NET, name: 'alice', login: a.login, payment: a.payment, argon2id, env: device.env, cryptoImpl: webcrypto, locks, show: async () => { heldWhenShown = locks.held; } });
  assert.deepEqual([heldWhenShown, locks.held, sealsKept([...storage.m]).map(s => s.seal)], [0, 0, ['made', 'made']]);
  // Another tab changes the keys while the passwords are shown: nothing is replaced, and the person is told.
  const other = new Storage(), b = await account(other);
  await turnOn({ storage: other, slots: b.slots, networkId: NET, name: 'alice', login: b.login, payment: b.payment, argon2id, env: device.env, cryptoImpl: webcrypto });
  const meanwhile = JSON.stringify({ ...JSON.parse(other.getItem(b.slots.login)), salt: Buffer.alloc(16, 9).toString('base64') });
  await assert.rejects(turnOff({ storage: other, slots: b.slots, networkId: NET, name: 'alice', login: b.login, payment: b.payment, argon2id, env: device.env, cryptoImpl: webcrypto, locks, show: async () => { other.setItem(b.slots.login, meanwhile); } }), error => error.message === LOCK_WORDS.changed);
  assert.deepEqual([other.getItem(b.slots.login), JSON.parse(other.getItem(b.slots.spend)).version, locks.held], [meanwhile, 3, 0], 'nothing replaced');
  // "Let the wallet make my passwords".
  const old = new Storage(), c = await account(old, { legacy: true });
  heldWhenShown = null;
  await remakePasswords({ storage: old, slots: c.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, cryptoImpl: webcrypto, locks, show: async () => { heldWhenShown = locks.held; } });
  assert.deepEqual([heldWhenShown, locks.held, breakingTheRule([...old.m])], [0, 0, []]);
  const again = new Storage(), d = await account(again, { legacy: true }), spendBefore = again.getItem(d.slots.spend);
  await assert.rejects(remakePasswords({ storage: again, slots: d.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, cryptoImpl: webcrypto, locks, show: async () => { again.setItem(d.slots.nextLogin, '{"kept":"aside"}'); } }), error => error.message === LOCK_WORDS.changed);
  assert.deepEqual([again.getItem(d.slots.spend), breakingTheRule([...again.m]).length], [spendBefore, 2], 'nothing replaced');
  // The dialog closed without "I have them" (made-dialog.mjs): nothing is replaced.
  again.removeItem(d.slots.nextLogin);
  await assert.rejects(remakePasswords({ storage: again, slots: d.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, cryptoImpl: webcrypto, show: async () => { throw new Error('Nothing was kept.'); } }), /Nothing was kept/);
  assert.equal(again.getItem(d.slots.spend), spendBefore);
});

test('"Let the wallet make my passwords": keys from before the rule, the same keys sealed under made passwords, shown before they are replaced; an account with one key too', async () => {
  const storage = new Storage(), a = await account(storage, { legacy: true });
  assert.deepEqual(sealsOf(storage, a.slots).chosen, ['login', 'spend']);
  await assert.rejects(remakePasswords({ storage, slots: a.slots, networkId: NET, name: 'alice', login: LOGIN, payment: `${PAYMENT}x`, argon2id, cryptoImpl: webcrypto }), new RegExp(LOCK_WORDS.paymentWrong));
  assert.deepEqual(breakingTheRule([...storage.m]).length, 2, 'a wrong password changes nothing');
  let before = null;
  const made = await remakePasswords({ storage, slots: a.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, cryptoImpl: webcrypto, show: async () => { before = breakingTheRule([...storage.m]).length; } });
  assert.equal(before, 2, 'nothing was replaced before the passwords were shown');
  assert.deepEqual(await provenSeals({ entries: [...storage.m], shown: [made.login, made.payment], typed: [LOGIN, PAYMENT], argon2id, cryptoImpl: webcrypto }), []);
  assert.deepEqual(sealsOf(storage, a.slots), { login: 'made', spend: 'made', loginIntent: 'signin', chosen: [] });
  for (const [place, intent, password, key] of [[a.slots.login, 'signin', made.login, a.keys[0]], [a.slots.spend, 'spend', made.payment, a.keys[1]]]) {
    assert.equal((await openVault(JSON.parse(storage.getItem(place)), password, argon2id, webcrypto, intent)).binding.publicKey, key.publicKey, 'the same key');
  }
  await assert.rejects(remakePasswords({ storage, slots: a.slots, networkId: NET, name: 'alice', login: made.login, payment: made.payment, argon2id, cryptoImpl: webcrypto }), new RegExp(LOCK_WORDS.notChosen));
  // An account with one key (a network without protected registration): its one record, with its registration salt.
  const one = new Storage(), key = await newDevice(webcrypto), slots = vaultSlots(NET, 'quin');
  one.setItem(slots.login, JSON.stringify(await sealLegacy({ ...key.secret, nameSalt: 'ef'.repeat(32), intent: 'device' }, LOGIN, { networkId: NET, name: 'quin', publicKey: key.publicKey }, argon2id, webcrypto)));
  const remade = await remakePasswords({ storage: one, slots, networkId: NET, name: 'quin', login: LOGIN, argon2id, cryptoImpl: webcrypto });
  const opened = await openVault(JSON.parse(one.getItem(slots.login)), remade.login, argon2id, webcrypto);
  assert.deepEqual([opened.intent, opened.secret.nameSalt, JSON.parse(one.getItem(slots.login)).version, remade.payment], ['device', 'ef'.repeat(32), 1, undefined]);
  assert.deepEqual(breakingTheRule([...one.m]), []);
  // Refused while the lock is on.
  const locked = new Storage(), b = await account(locked, { legacy: true }), device = fakeDevice();
  await turnOn({ storage: locked, slots: b.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, env: device.env, cryptoImpl: webcrypto });
  assert.equal(lockOf(locked, b.slots).on, true);
  await assert.rejects(remakePasswords({ storage: locked, slots: b.slots, networkId: NET, name: 'alice', login: LOGIN, payment: PAYMENT, argon2id, cryptoImpl: webcrypto }), new RegExp(LOCK_WORDS.alreadyOn));
});
