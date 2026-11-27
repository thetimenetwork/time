import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { build } from 'esbuild';
import { chromium } from 'playwright-core';
import {
  createIdentity, decryptText, encryptText, getPinnedKey, isPeerPinned,
  newMessageId, pinPeer, roomId, safetyNumber,
} from '../public/crypto.mjs';

const network = 'a'.repeat(64);

async function verifyPair(first, second) {
  const a = await safetyNumber(first, second.accountId, second.publicKey);
  const b = await safetyNumber(second, first.accountId, first.publicKey);
  assert.equal(a, b);
  await pinPeer(first, second.accountId, second.publicKey, b);
  await pinPeer(second, first.accountId, first.publicKey, a);
}

test('the safety number covers both keys, account numbers and the Time network', async () => {
  const [a, b, c] = await Promise.all(['2', '3', '4'].map(id => createIdentity(network, id)));
  const code = await safetyNumber(a, '3', b.publicKey);
  assert.equal(code, await safetyNumber(b, '2', a.publicKey));
  assert.notEqual(code, await safetyNumber(a, '4', b.publicKey));
  assert.notEqual(code, await safetyNumber(a, '3', c.publicKey));
  assert.equal(await isPeerPinned(a, '3', b.publicKey), false);
  await assert.rejects(pinPeer(a, '3', b.publicKey, code.slice(0, 8)));
  await verifyPair(a, b);
  assert.equal(await isPeerPinned(a, '3', b.publicKey), true);
  await pinPeer(a, '3', b.publicKey, code.toLowerCase());
  const replacementCode = await safetyNumber(a, '3', c.publicKey);
  await assert.rejects(pinPeer(a, '3', c.publicKey, replacementCode), /different verified key/);
  assert.equal(await getPinnedKey(a, '3'), b.publicKey);
  assert.equal(await isPeerPinned(a, '3', c.publicKey), false);
  await assert.rejects(safetyNumber(a, '3', a.publicKey));
  assert.equal(JSON.stringify(a).includes('PRIVATE KEY'), false);
});

test('signed group text decrypts for each verified participant and binds the entire conversation', async () => {
  const [a, b, c, other] = await Promise.all(['1', '2', '3', '4'].map(id => createIdentity(network, id)));
  const ids = ['2', '1', '3'];
  const chatId = await roomId(network, ids);
  assert.equal(chatId, await roomId(network, ['3', '2', '1']));
  const text = 'Hello 👨‍👩‍👧‍👧\n<plain text> 🙂';
  await verifyPair(a, b);
  await assert.rejects(encryptText({ identity: a, chatId, memberIds: ids, text }), /Compare safety numbers/);
  await verifyPair(a, c);
  const message = await encryptText({ identity: a, chatId, memberIds: ids, text });
  assert.equal(message.ciphertext.includes('Hello'), false);
  const args = { chatId, memberIds: ids, senderId: a.accountId, ...message };
  for (const identity of [a, b, c]) assert.equal(await decryptText({ identity, ...args }), text);
  await assert.rejects(decryptText({ identity: other, ...args }));
  await assert.rejects(decryptText({ identity: b, ...args, senderId: '2' }));
  await assert.rejects(decryptText({ identity: b, ...args, messageId: newMessageId() }), /does not match/);
  const direct = ['1', '2'];
  const directId = await roomId(network, direct);
  await assert.rejects(decryptText({ identity: b, ...args, memberIds: direct, chatId: directId }), /does not match/);
  await assert.rejects(encryptText({ identity: a, memberIds: ids, chatId: directId, text }));
  assert.notEqual(chatId, await roomId('b'.repeat(64), ids));
  await assert.rejects(roomId(network, [...ids, '1']));
});

test('the encrypted format accepts plain Unicode text and emoji only', async () => {
  const identity = await createIdentity(network, '17');
  const peer = await createIdentity(network, '21');
  await verifyPair(identity, peer);
  const memberIds = ['17', '21'];
  const chatId = await roomId(network, memberIds);
  for (const text of [null, { url: 'file' }, new Uint8Array([1]), '', ' \n ', '\u0000', 'x'.repeat(4097)]) {
    await assert.rejects(encryptText({ identity, memberIds, chatId, text }));
  }
  const text = '🐢'.repeat(4096);
  const message = await encryptText({ identity, memberIds, chatId, text });
  assert.equal(await decryptText({ identity: peer, memberIds, chatId, senderId: '17', ...message }), text);
});

const browserPath = [
  process.env.CHROME_PATH, chromium.executablePath(), '/usr/bin/chromium', '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
].find(value => value && existsSync(value));

test('IndexedDB seals one identity across concurrent tabs and reloads', {
  skip: browserPath ? false : 'Set CHROME_PATH to run the browser storage check',
}, async () => {
  const { outputFiles } = await build({
    entryPoints: [fileURLToPath(new URL('../public/crypto.mjs', import.meta.url))],
    write: false, bundle: true, platform: 'browser', format: 'esm',
  });
  const browser = await chromium.launch({ headless: true, executablePath: browserPath });
  try {
    const context = await browser.newContext();
    await context.route('http://127.0.0.1:31417/**', route =>
      route.request().url().endsWith('/crypto.mjs')
        ? route.fulfill({ contentType: 'text/javascript', body: outputFiles[0].text })
        : route.fulfill({ contentType: 'text/html', body: '<title>Local test</title>' }));
    const tabs = await Promise.all([context.newPage(), context.newPage()]);
    await Promise.all(tabs.map(tab => tab.goto('http://127.0.0.1:31417/')));
    const credential = tab => tab.evaluate(async () => (await import('/crypto.mjs')).installedApiCredential());
    const credentials = await Promise.all(tabs.map(credential));
    assert.ok(credentials[0] === credentials[1] && /^[0-9a-f]{64}$/.test(credentials[0]));
    const enroll = tab => tab.evaluate(async net => {
      const crypt = await import('/crypto.mjs');
      return (await crypt.loadIdentity(net, '42')).publicKey;
    }, network);
    const enrolled = await Promise.all(tabs.map(enroll));
    assert.equal(enrolled[0], enrolled[1]);
    const peer = await createIdentity(network, '81');
    await tabs[0].evaluate(async ([net, key]) => {
      const { loadIdentity, safetyNumber, pinPeer } = await import('/crypto.mjs');
      const identity = await loadIdentity(net, '42');
      await pinPeer(identity, '81', key, await safetyNumber(identity, '81', key));
    }, [network, peer.publicKey]);
    await tabs[1].reload();
    assert.ok(await credential(tabs[1]) === credentials[0]);
    assert.equal(await enroll(tabs[1]), enrolled[0]);
    assert.equal(await tabs[1].evaluate(async net => {
      const { loadIdentity, getPinnedKey } = await import('/crypto.mjs');
      return getPinnedKey(await loadIdentity(net, '42'), '81');
    }, network), peer.publicKey);
    const stored = await tabs[1].evaluate(async net => {
      const db = await new Promise((resolve, reject) => {
        const r = indexedDB.open('time-chat-keys-v1'); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
      });
      const record = await new Promise((resolve, reject) => {
        const r = db.transaction('identities').objectStore('identities').get([net, '42']);
        r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
      });
      db.close();
      return { fields: Object.keys(record).sort(), exportable: record.wrappingKey.extractable, bytes: record.sealed.byteLength };
    }, network);
    assert.deepEqual(stored.fields, ['iv', 'sealed', 'wrappingKey']);
    assert.equal(stored.exportable, false);
    assert.ok(stored.bytes > 32);
  } finally { await browser.close(); }
});
