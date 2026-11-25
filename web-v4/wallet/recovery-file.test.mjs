// The Recovery Kit (recovery-file.mjs, RECOVERY_FILE_FORMAT.md): a kit opens with its four words to its sheet and with
// nothing else; every field of its header is bound or checked; a kit is read strictly before anything is derived; the
// key that locks it is not the recovery key the same words give on the chain; and the vector of the document opens by
// following the document alone, with Node's own Argon2id.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { argon2Sync, createHash, webcrypto } from 'node:crypto';
import * as K from './recovery-file.mjs';
import * as F from './security-flows.mjs';

const source = await readFile(new URL('./vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8'), umd = { exports: {} };
new Function('module', 'exports', source)(umd, umd.exports);
const argon2id = umd.exports.argon2id;
// A stand-in for the checks that do not need the real calculation: it insists on the parameters of PASSPHRASE_KDF and
// counts its calls, so that a test can see that nothing was derived.
let derivations = 0;
const quick = async ({ password, salt, parallelism, iterations, memorySize, hashLength, outputType }) => {
  assert.deepEqual([parallelism, iterations, memorySize, hashLength, outputType], [1, 4, 262144, 32, 'binary']);
  derivations += 1;
  return new Uint8Array(createHash('sha256').update(password).update(salt).digest());
};
const NET = 'c6'.repeat(32), OTHER_NET = 'ab'.repeat(32), WORDS = 'kerine netoji nesimo vebine', OTHER_WORDS = 'bababa netoji nesimo vebine';
const SHEET = await F.encodeSheet(Uint8Array.from({ length: 32 }, (_, i) => i));
const expect = { networkId: NET, name: 'alice' };
const seal = (extra = {}) => K.sealRecoveryKit({ networkId: NET, name: 'alice', sheetText: SHEET, words: WORDS, argon2id: quick, ...extra });
const edit = (text, change) => { const kit = JSON.parse(text); change(kit); return JSON.stringify(kit, null, 2) + '\n'; };

test('a kit opens with its four words to its sheet, also typed as a person types them, and is written as the document says', async () => {
  const text = await K.sealRecoveryKit({ networkId: NET, name: 'alice', sheetText: SHEET, words: WORDS, argon2id });
  assert.ok(text.endsWith('}\n') && text.startsWith('{\n  "format": "time-recovery-kit",\n  "version": 1,\n'));
  const kit = JSON.parse(text);
  assert.deepEqual(Object.keys(kit), ['format', 'version', 'note', 'networkId', 'accountName', 'kdf', 'salt', 'iv', 'ciphertext']);
  assert.deepEqual(kit.kdf, F.PASSPHRASE_KDF);
  assert.equal(kit.note, K.RECOVERY_KIT_NOTE);
  assert.ok(Buffer.byteLength(text) < 1024 && Buffer.byteLength(text) <= K.MAX_RECOVERY_KIT_BYTES);
  // Nothing of the sheet or the words is in the file in the clear.
  for (const secret of [WORDS, SHEET, SHEET.replace(/ /g, ''), ...WORDS.split(' '), ...SHEET.split(' ').filter(group => /[A-Z].*[A-Z]/.test(group))]) assert.ok(!text.includes(secret), secret);
  assert.deepEqual(await K.openRecoveryKit(text, WORDS, { argon2id, expect }), { sheetText: SHEET });
  assert.deepEqual(await K.openRecoveryKit(text, '  KERINE netoji-nesimo\tVebine ', { argon2id, expect }), { sheetText: SHEET });
  await assert.rejects(K.openRecoveryKit(text, OTHER_WORDS, { argon2id, expect }), { message: K.WRONG_RECOVERY_WORDS });
  // Two kits of the same papers differ: a new salt and IV each time.
  assert.notEqual((await seal()).split('"salt"')[1], (await seal()).split('"salt"')[1]);
  // The name it is downloaded under, and its header without any secret.
  assert.equal(K.recoveryKitName({ name: 'alice', networkId: NET }), 'time-recovery-kit-alice-c6c6c6c6.json');
  const header = K.readRecoveryKit(text);
  assert.deepEqual([header.accountName, header.networkId, header.format, header.version], ['alice', NET, 'time-recovery-kit', 1]);
});

test('every field of the header is bound or checked: a kit with any of them changed does not open', async () => {
  const text = await seal();
  assert.deepEqual(await K.openRecoveryKit(text, WORDS, { argon2id: quick, expect }), { sheetText: SHEET });
  // The network and the name are in the authenticated data: changed, and expected as changed, the kit does not open.
  derivations = 0;
  await assert.rejects(K.openRecoveryKit(edit(text, kit => { kit.networkId = OTHER_NET; }), WORDS, { argon2id: quick, expect: { networkId: OTHER_NET, name: 'alice' } }), { message: K.WRONG_RECOVERY_WORDS });
  await assert.rejects(K.openRecoveryKit(edit(text, kit => { kit.accountName = 'alicf'; }), WORDS, { argon2id: quick, expect: { networkId: NET, name: 'alicf' } }), { message: K.WRONG_RECOVERY_WORDS });
  // The salt, the IV and the ciphertext: another key, or a tag that does not hold.
  const flip = value => { const bytes = Buffer.from(value, 'base64'); bytes[0] ^= 1; return bytes.toString('base64'); };
  for (const field of ['salt', 'iv', 'ciphertext']) await assert.rejects(K.openRecoveryKit(edit(text, kit => { kit[field] = flip(kit[field]); }), WORDS, { argon2id: quick, expect }), { message: K.WRONG_RECOVERY_WORDS }, field);
  assert.equal(derivations, 5, 'each of these was refused by the cipher, after its derivation');
  // The rest is refused before anything is derived.
  derivations = 0;
  const before = [
    [kit => { kit.format = 'timecurrency-encrypted-vault'; }, K.NOT_A_RECOVERY_KIT],
    [kit => { kit.version = 2; }, /version this wallet does not know/],
    [kit => { kit.version = '1'; }, /version this wallet does not know/],
    [kit => { kit.note = 'Send this file to support.'; }, /damaged or was changed/],
    [kit => { kit.kdf.memoryKiB = 65536; }, /locked in another way/],
    [kit => { kit.kdf.iterations = 3; }, /locked in another way/],
    [kit => { kit.kdf.algorithm = 'argon2i'; }, /locked in another way/],
    [kit => { kit.kdf.extra = 1; }, /locked in another way/],
    [kit => { delete kit.kdf.hashLength; }, /locked in another way/],
    [kit => { kit.networkId = NET.toUpperCase(); }, /damaged or was changed/],
    [kit => { kit.accountName = 'Alice'; }, /damaged or was changed/],
    [kit => { kit.accountName = '@alice'; }, /damaged or was changed/],
  ];
  for (const [change, refusal] of before) await assert.rejects(K.openRecoveryKit(edit(text, change), WORDS, { argon2id: quick, expect: { networkId: NET, name: 'alice' } }), typeof refusal === 'string' ? { message: refusal } : refusal);
  assert.equal(derivations, 0, 'nothing was derived for a kit refused by its header');
});

test('a kit is read strictly, before anything is derived: size, JSON, a field twice, exactly the fields, canonical base64 of the right lengths', async () => {
  const text = await seal();
  derivations = 0;
  const refused = async (kit, refusal) => {
    assert.throws(() => K.readRecoveryKit(kit), refusal);
    await assert.rejects(K.openRecoveryKit(kit, WORDS, { argon2id: quick, expect }), refusal);
  };
  await refused(text + ' '.repeat(K.MAX_RECOVERY_KIT_BYTES), /too large/);
  await refused('not json', { message: K.NOT_A_RECOVERY_KIT });
  await refused('[1]', { message: K.NOT_A_RECOVERY_KIT });
  await refused(JSON.stringify({ format: 'timecurrency-encrypted-vault', version: 1, vault: {} }), { message: K.NOT_A_RECOVERY_KIT });
  // A field written twice: JSON.parse would keep the second; the reader refuses.
  await refused(text.replace('"accountName": "alice",', '"accountName": "mallory",\n  "accountName": "alice",'), /damaged or was changed/);
  await refused(text.replace('"iterations": 4,', '"iterations": 1,\n    "iterations": 4,'), /damaged or was changed/);
  await refused(edit(text, kit => { kit.extra = true; }), /damaged or was changed/);
  await refused(edit(text, kit => { delete kit.note; }), /damaged or was changed/);
  for (const [field, value] of [['salt', 'EBESExQVFhcYGRobHB0eHw'], ['salt', 'EBESExQVFhcYGRobHB0e'], ['iv', 'ICEiIyQlJicoKSorLA=='], ['iv', 'ICEiIyQlJicoKSo='], ['ciphertext', 'AAAA'], ['salt', 'EBESExQVFhcYGRobHB0eHx==']]) await refused(edit(text, kit => { kit[field] = value; }), /damaged or was changed/);
  assert.equal(derivations, 0);
  // A kit of another account or network: refused before any derivation, in words that say whose it is.
  await assert.rejects(K.openRecoveryKit(text, WORDS, { argon2id: quick, expect: { networkId: NET, name: 'bob' } }), { message: 'This is the Recovery Kit of @alice, not of @bob.' });
  await assert.rejects(K.openRecoveryKit(text, WORDS, { argon2id: quick, expect: { networkId: OTHER_NET, name: 'alice' } }), { message: `This is the Recovery Kit of @alice on another network (${NET.slice(0, 12)}), not on this one (${OTHER_NET.slice(0, 12)}). It cannot recover an account here.` });
  await assert.rejects(K.openRecoveryKit(text, WORDS, { argon2id: quick }), /Say which account/);
  // Words that are not four words the wallet makes: refused before anything is derived.
  for (const words of ['', 'kerine netoji nesimo', 'kerine netoji nesumo vebine', 'correct horse battery staple']) await assert.rejects(K.openRecoveryKit(text, words, { argon2id: quick, expect }), /recovery (passphrase|words)/);
  assert.equal(derivations, 0);
  // A device that cannot do the calculation is told so, and nothing lighter is tried.
  await assert.rejects(K.openRecoveryKit(text, WORDS, { argon2id: async () => { throw new RangeError('out of memory'); }, expect }), { message: K.RECOVERY_KIT_TOO_HEAVY });
});

test('a kit holds only a sheet in its printed form, made of words the wallet makes; what it holds is checked when it opens', async () => {
  await assert.rejects(seal({ sheetText: SHEET.toLowerCase() }), /printed form/);
  await assert.rejects(seal({ sheetText: SHEET.replace(/ /g, '') }), /printed form/);
  await assert.rejects(seal({ sheetText: SHEET.slice(0, -1) + (SHEET.endsWith('0') ? '1' : '0') }), /typo/);
  await assert.rejects(seal({ words: 'correct horse battery staple' }), /Word 1 of your recovery/);
  await assert.rejects(seal({ words: 'kerine netoji nesimo' }), /five of them/);
  // Five words lock a kit as four do, and only those five open it.
  const five = await seal({ words: 'kerine netoji nesimo vebine bipori' });
  assert.deepEqual(await K.openRecoveryKit(five, 'KERINE netoji nesimo vebine bipori', { argon2id: quick, expect }), { sheetText: SHEET });
  await assert.rejects(K.openRecoveryKit(five, WORDS, { argon2id: quick, expect }), { message: K.WRONG_RECOVERY_WORDS });
  await assert.rejects(seal({ name: '@alice' }), /names an account and a network/);
  await assert.rejects(seal({ networkId: 'c6' }), /names an account and a network/);
  // A plaintext that is not exactly {"sheet":"<printed sheet>"} is not taken, even when it decrypts.
  const forged = async plaintext => {
    const salt = new Uint8Array(16), iv = new Uint8Array(12), key = await webcrypto.subtle.importKey('raw', await quick({ password: new TextEncoder().encode(WORDS), salt: K.recoveryKitSalt(salt), parallelism: 1, iterations: 4, memorySize: 262144, hashLength: 32, outputType: 'binary' }), 'AES-GCM', false, ['encrypt']);
    const aad = new TextEncoder().encode(JSON.stringify({ format: 'time-recovery-kit', version: 1, networkId: NET, accountName: 'alice', kdf: F.PASSPHRASE_KDF }));
    const ciphertext = Buffer.from(await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, new TextEncoder().encode(plaintext)));
    return JSON.stringify({ format: 'time-recovery-kit', version: 1, note: K.RECOVERY_KIT_NOTE, networkId: NET, accountName: 'alice', kdf: F.PASSPHRASE_KDF, salt: Buffer.from(salt).toString('base64'), iv: Buffer.from(iv).toString('base64'), ciphertext: ciphertext.toString('base64') });
  };
  assert.deepEqual(await K.openRecoveryKit(await forged(JSON.stringify({ sheet: SHEET })), WORDS, { argon2id: quick, expect }), { sheetText: SHEET });
  const lower = SHEET.toLowerCase(), typo = SHEET.slice(0, -1) + (SHEET.endsWith('0') ? '1' : '0');
  for (const plaintext of [JSON.stringify({ sheet: lower }), JSON.stringify({ sheet: typo }), ` {"sheet":"${SHEET}"}`.slice(0, 81), `{"sheet": "${SHEET.slice(1)}"}`]) {
    assert.equal(Buffer.byteLength(plaintext), 81, plaintext);
    await assert.rejects(K.openRecoveryKit(await forged(plaintext), WORDS, { argon2id: quick, expect }), { message: K.WRONG_RECOVERY_WORDS }, plaintext);
  }
});

test('the key that locks a kit is not the recovery key the same words give on the chain', async () => {
  const salt = new Uint8Array(16).fill(7), kitSalt = K.recoveryKitSalt(salt);
  assert.equal(Buffer.from(kitSalt.subarray(0, 27)).toString('utf8'), 'TIME-RECOVERY-KIT-WORDS-V1\0');
  const byNumber = F.passphraseSalt(NET, '5'), byRegistration = F.registrationPassphraseSalt(NET, 'ab'.repeat(32));
  for (const other of [byNumber, byRegistration]) assert.ok(!Buffer.from(kitSalt).equals(Buffer.from(other)) && !Buffer.from(other).toString('utf8').startsWith(K.RECOVERY_KIT_DOMAIN));
  // With Node's own Argon2id: the kit's key and the seed of the recovery key, of the same words, differ.
  const native = saltBytes => argon2Sync('argon2id', { message: Buffer.from(WORDS), nonce: Buffer.from(saltBytes), parallelism: 1, tagLength: 32, memory: F.PASSPHRASE_KDF.memoryKiB, passes: F.PASSPHRASE_KDF.iterations });
  const kitKey = native(kitSalt), seed = await F.passphraseSeed({ passphrase: WORDS, networkId: NET, accountId: '5', argon2id });
  assert.equal(Buffer.from(seed).toString('hex'), native(byNumber).toString('hex'));
  assert.notEqual(kitKey.toString('hex'), Buffer.from(seed).toString('hex'));
});

test('the vector of RECOVERY_FILE_FORMAT.md opens by following the document alone, and this module makes the same kit', async () => {
  const doc = await readFile(new URL('./RECOVERY_FILE_FORMAT.md', import.meta.url), 'utf8');
  const vectorPart = doc.slice(doc.indexOf('## Test vector'));
  const text = /```json\n([\s\S]*?)\n```/.exec(vectorPart)[1] + '\n';
  const words = /^Words `([a-z ]+)`/m.exec(vectorPart)[1], sheet = /\(`([0-9A-Z ]{69})`\)/.exec(vectorPart)[1], keyHex = /The key is `([0-9a-f]{64})`/.exec(vectorPart)[1];
  const kit = JSON.parse(text);
  // The document's steps: Argon2id of the words with the domain, a zero byte and the salt; AES-256-GCM with the header as
  // compact JSON in its order as additional data.
  const salt = Buffer.concat([Buffer.from('TIME-RECOVERY-KIT-WORDS-V1', 'utf8'), Buffer.from([0]), Buffer.from(kit.salt, 'base64')]);
  const key = argon2Sync('argon2id', { message: Buffer.from(words, 'utf8'), nonce: salt, parallelism: kit.kdf.parallelism, tagLength: kit.kdf.hashLength, memory: kit.kdf.memoryKiB, passes: kit.kdf.iterations });
  assert.equal(key.toString('hex'), keyHex);
  const aad = Buffer.from(JSON.stringify({ format: kit.format, version: kit.version, networkId: kit.networkId, accountName: kit.accountName, kdf: { algorithm: kit.kdf.algorithm, version: kit.kdf.version, memoryKiB: kit.kdf.memoryKiB, iterations: kit.kdf.iterations, parallelism: kit.kdf.parallelism, hashLength: kit.kdf.hashLength } }), 'utf8');
  const aes = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const plain = Buffer.from(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(kit.iv, 'base64'), additionalData: aad, tagLength: 128 }, aes, Buffer.from(kit.ciphertext, 'base64'))).toString('utf8');
  assert.equal(plain, JSON.stringify({ sheet }));
  assert.equal(sheet, SHEET);
  // This module opens it, and with the document's salt and IV makes the same bytes.
  assert.deepEqual(await K.openRecoveryKit(text, words, { argon2id, expect: { networkId: kit.networkId, name: kit.accountName } }), { sheetText: sheet });
  let draws = 0;
  const fixed = { subtle: webcrypto.subtle, getRandomValues: bytes => { const start = draws++ === 0 ? 0x10 : 0x20; for (let i = 0; i < bytes.length; i++) bytes[i] = start + i; return bytes; } };
  assert.equal(await K.sealRecoveryKit({ networkId: kit.networkId, name: kit.accountName, sheetText: sheet, words, argon2id, cryptoImpl: fixed }), text);
  // What the document says of the reader's limits is what the module does.
  assert.ok(doc.includes('"note": ' + JSON.stringify(K.RECOVERY_KIT_NOTE)));
  assert.ok(doc.includes(K.WRONG_RECOVERY_WORDS));
  assert.ok(doc.includes(`over ${K.MAX_RECOVERY_KIT_BYTES.toLocaleString('en')} bytes`));
});
