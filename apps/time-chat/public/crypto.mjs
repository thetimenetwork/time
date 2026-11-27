import { publicKeyStart, messageStart } from './armor.mjs';
import {
  createMessage, decrypt, encrypt, enums, generateKey, readKey, readMessage, readPrivateKey,
} from 'openpgp';
import { messageIdentifier, plainText, validateEvent } from './thread.mjs';

// Each browser profile owns one chat identity per account and network. Time wallet keys
// never participate in message encryption. Long-lived OpenPGP keys do not provide
// forward secrecy. Trusted client code and uncompromised endpoints are required.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const pgp = {
  v6Keys: true,
  aeadProtect: true,
  preferredAEADAlgorithm: enums.aead.gcm,
  preferredCompressionAlgorithm: enums.compression.uncompressed,
  maxDecompressedMessageSize: 65536,
};
const localStores = new WeakMap();
const databaseName = 'time-chat-keys-v1';
let databasePromise;

function network(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid Time network ID.');
  return value;
}

function account(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 0xffffffffffffffffn)
    throw new Error('Invalid Time account number.');
  return value;
}

function members(ids) {
  if (!Array.isArray(ids) || ids.length < 2 || ids.length > 128 || new Set(ids).size !== ids.length)
    throw new Error('Invalid conversation membership.');
  return ids.map(account).sort();
}

function hex(bytes) {
  return Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
}

async function digest(value) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', value)));
}

export function newMessageId() {
  return crypto.randomUUID();
}

export async function roomId(networkId, memberIds) {
  return digest(encoder.encode(JSON.stringify(['time-chat/room/v1', network(networkId), members(memberIds)])));
}

function openDatabase() {
  if (!globalThis.indexedDB) throw new Error('This browser cannot store private chat keys.');
  if (!databasePromise) {
    databasePromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(databaseName, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore('identities');
        request.result.createObjectStore('verified-peers');
      };
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => { db.close(); databasePromise = undefined; };
        resolve(db);
      };
      request.onerror = () => { databasePromise = undefined; reject(request.error); };
    });
  }
  return databasePromise;
}

// The read and conditional add share one readwrite transaction. Two tabs enrolling
// simultaneously see the same winner. Existing keys can never be silently replaced.
function stored(db, storeName, key, initialValue) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, initialValue === undefined ? 'readonly' : 'readwrite');
    const store = tx.objectStore(storeName);
    const request = store.get(key);
    let value;
    request.onsuccess = () => {
      value = request.result;
      if (value === undefined && initialValue !== undefined) {
        value = initialValue;
        store.add(value, key);
      }
    };
    tx.oncomplete = () => resolve(value);
    tx.onabort = () => reject(tx.error || new Error('Could not save the chat key.'));
  });
}

// The installed loopback proxy binds its session to this browser origin. A cookie
// alone is shared by every port on the same host. One IDB transaction handles
// simultaneous first visits from two tabs without creating competing credentials.
export async function installedApiCredential() {
  const db = await openDatabase();
  return stored(db, 'identities', 'installed-api-credential/v1', hex(crypto.getRandomValues(new Uint8Array(32))));
}

function runtimeIdentity(networkId, accountId, privateKey, store) {
  const identity = { networkId, accountId, publicKey: privateKey.toPublic().armor() };
  // JSON.stringify(identity) is safe to use as public metadata.
  Object.defineProperty(identity, 'privateKey', { value: privateKey, enumerable: false });
  localStores.set(identity, store);
  return Object.freeze(identity);
}

async function generatePrivateKey() {
  // The public certificate is deliberately free of account names or email addresses.
  const { privateKey } = await generateKey({ type: 'curve25519', format: 'object', config: pgp });
  return privateKey;
}

// Ephemeral identity for clients such as the offline fixture tests.
export async function createIdentity(networkId, accountId) {
  network(networkId);
  account(accountId);
  return runtimeIdentity(networkId, accountId, await generatePrivateKey(), new Map());
}

export async function loadIdentity(networkId, accountId) {
  const key = [network(networkId), account(accountId)];
  const db = await openDatabase();
  const additionalData = encoder.encode(JSON.stringify(['time-chat/local-key/v1', ...key]));
  let record = await stored(db, 'identities', key);
  if (record === undefined) {
    const privateKey = await generatePrivateKey();
    const wrappingKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const secret = privateKey.write();
    let sealed;
    try {
      sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, wrappingKey, secret);
    } finally {
      secret.fill(0);
    }
    record = await stored(db, 'identities', key, { wrappingKey, iv, sealed });
  }
  const bytes = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: record.iv, additionalData }, record.wrappingKey, record.sealed,
  ));
  // OpenPGP may keep views of the binary passed to readPrivateKey for the lifetime
  // of the runtime identity. Only wipe our independent buffer.
  try {
    return runtimeIdentity(networkId, accountId, await readPrivateKey({ binaryKey: bytes.slice(), config: pgp }), db);
  } finally {
    bytes.fill(0);
  }
}

export async function parsePublic(armor) {
  if (typeof armor !== 'string' || armor.length > 16384 ||
      !armor.startsWith(publicKeyStart))
    throw new Error('Invalid public chat key.');
  const key = await readKey({ armoredKey: armor, config: pgp });
  if (key.isPrivate() || key.keyPacket.version !== 6 || key.keyPacket.algorithm !== enums.publicKey.ed25519 ||
      key.subkeys.length !== 1 || key.subkeys[0].keyPacket.algorithm !== enums.publicKey.x25519)
    throw new Error('Unsupported public chat key.');
  await key.verifyPrimaryKey();
  await key.getEncryptionKey();
  return key;
}

export async function safetyNumber(identity, peerId, peerPublicKey) {
  account(peerId);
  if (identity.accountId === peerId) throw new Error('Choose a different Time account.');
  const ownDigest = await digest(identity.privateKey.toPublic().write());
  const peerDigest = await digest((await parsePublic(peerPublicKey)).write());
  if (ownDigest === peerDigest) throw new Error('Two accounts cannot share a chat key.');
  const pair = [[identity.accountId, ownDigest], [peerId, peerDigest]]
    .sort(([a], [b]) => a === b ? 0 : a < b ? -1 : 1);
  const value = await digest(encoder.encode(JSON.stringify(['time-chat/safety-number/v1', identity.networkId, pair])));
  return value.toUpperCase().match(/.{4}/g).join(' ');
}

function peerEntry(identity, peerId, initialValue) {
  account(peerId);
  const store = localStores.get(identity);
  if (!store) throw new Error('Unlock the local chat identity first.');
  if (store instanceof Map) {
    if (!store.has(peerId) && initialValue !== undefined) store.set(peerId, initialValue);
    return store.get(peerId);
  }
  return stored(store, 'verified-peers', [identity.networkId, identity.accountId, peerId], initialValue);
}

export async function getPinnedKey(identity, peerId) {
  return (await peerEntry(identity, peerId)) ?? null;
}

export async function isPeerPinned(identity, peerId, peerPublicKey) {
  const previous = await getPinnedKey(identity, peerId);
  return previous !== null && previous === (await parsePublic(peerPublicKey)).armor();
}

export async function pinPeer(identity, peerId, peerPublicKey, comparedNumber) {
  const canonical = (await parsePublic(peerPublicKey)).armor();
  const expected = (await safetyNumber(identity, peerId, canonical)).replaceAll(' ', '');
  if (typeof comparedNumber !== 'string' || comparedNumber.replace(/\s/g, '').toUpperCase() !== expected)
    throw new Error('Safety numbers differ. Confirm the full number with your contact.');
  if (await peerEntry(identity, peerId, canonical) !== canonical)
    throw new Error('This contact already has a different verified key on this device.');
}

async function keyFor(identity, id) {
  if (id === identity.accountId) return identity.privateKey.toPublic();
  const key = await getPinnedKey(identity, id);
  if (!key) throw new Error('Compare safety numbers with the contact first.');
  return parsePublic(key);
}

async function signedContext(identity, chatId, memberIds, senderId, messageId) {
  const roster = members(memberIds);
  if (!roster.includes(identity.accountId) || !roster.includes(account(senderId)) ||
      chatId !== await roomId(identity.networkId, roster))
    throw new Error('The conversation or its participants changed.');
  return [identity.networkId, chatId, roster, senderId, messageIdentifier(messageId)];
}

export async function encryptEvent({ identity, chatId, memberIds, event, messageId = newMessageId() }) {
  const context = await signedContext(identity, chatId, memberIds, identity.accountId, messageId);
  const clocked = event?.type === 'edit' || event?.type === 'reaction';
  const checked = validateEvent(clocked ? { ...event, at: Date.now() } : event);
  if (checked.targetId === messageId) throw new Error('A message cannot act on itself.');
  // Plain texts keep the original encoding, including its signed type tag.
  const payload = checked.type === 'text'
    ? ['time-chat/text/v1', ...context, checked.text]
    : ['time-chat/event/v2', ...context, checked];
  const encryptionKeys = await Promise.all(context[2].map(id => keyFor(identity, id)));
  const ciphertext = await encrypt({
    message: await createMessage({ binary: encoder.encode(JSON.stringify(payload)) }), encryptionKeys,
    signingKeys: identity.privateKey, format: 'armored', config: pgp,
  });
  return { messageId, ciphertext };
}

export function encryptText({ text, ...options }) {
  return encryptEvent({ ...options, event: { type: 'text', text } });
}

export async function decryptEvent({ identity, chatId, memberIds, senderId, messageId, ciphertext }) {
  const expected = await signedContext(identity, chatId, memberIds, senderId, messageId);
  if (typeof ciphertext !== 'string' || ciphertext.length > 131072 ||
      !ciphertext.startsWith(messageStart)) throw new Error('Invalid encrypted message.');
  const message = await readMessage({ armoredMessage: ciphertext, config: pgp });
  const { data, signatures } = await decrypt({
    message, decryptionKeys: identity.privateKey, verificationKeys: await keyFor(identity, senderId),
    expectSigned: true, format: 'binary', config: pgp,
  });
  if (signatures.length !== 1 || data.length > 65536) throw new Error('Invalid signed chat message.');
  await signatures[0].verified;
  const payload = JSON.parse(decoder.decode(data));
  if (!Array.isArray(payload) || payload.length !== 7 || JSON.stringify(payload.slice(1, 6)) !== JSON.stringify(expected))
    throw new Error('The signed message does not match this conversation, author or message ID.');
  if (payload[0] === 'time-chat/text/v1') return { type: 'text', text: plainText(payload[6]) };
  if (payload[0] !== 'time-chat/event/v2') throw new Error('Unknown signed chat format.');
  const event = validateEvent(payload[6]);
  if (event.targetId === messageId) throw new Error('A message cannot act on itself.');
  return event;
}

export async function decryptText(options) {
  const event = await decryptEvent(options);
  if (event.type !== 'text') throw new Error('This message requires a conversation-aware client.');
  return event.text;
}
