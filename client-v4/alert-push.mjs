// The alert service: it wakes a closed wallet with a browser push that claims nothing.
//
// IT HOLDS NO KEY OF ANY ACCOUNT AND SIGNS NOTHING ON THE CHAIN. The one key it has is its own VAPID key (RFC 8292),
// with which it tells the browsers' push services who sends; that key can sign nothing a node takes.
//
// A notification carries no information; the chain does. When a verified block includes an action that changes the
// keys or the security row of an account, or starts a wait on it (client-v4/touches.mjs, "woken"), every browser
// subscribed to that account gets ONE push whose content is the constant {"v":1}. The wallet's service worker
// (web-v4/wallet/sw.js) shows a fixed sentence, "Open your wallet to check your account.", and the wallet, once
// opened, reads its account's state with a proof and says what it says (web-v4/wallet/alerts.mjs). So:
// - nobody can make text of their own reach a person's screen: there is no text to send;
// - an ordinary payment, in either direction, wakes nobody, and only a key of the account (or a guardian the account
//   named and who accepted) can cause an action that does: a stranger cannot make a person's phone ring;
// - a false push leads to "nothing new"; a missed one costs nothing, because the wallet reads its state when opened.
//
// What it keeps: the address list, and nothing else of anybody. For each subscription the account, the push
// service's address of the browser (its endpoint), the browser's two keys and when it was made, in one file written
// whole (subscriptions.json); and its own VAPID key beside it (vapid.json). Nothing is kept for a wallet or sent
// again: a push that cannot start at once waits in memory for a free place, a minute at most, and is then abandoned
// and counted; a push service that answers 404 or 410 has the subscription removed. (Its light client keeps the
// newest block header it verified in checkpoint.json, as every verifying service here does: the trust anchor of a
// network expires after seven days, and a service that forgot its checkpoint could verify nothing after a restart.
// It holds no account, endpoint or event.)
//
// Who may subscribe: whoever proves control of the account with its sign-in key, by the login proof of
// server-auth.mjs (verifyLogin): a challenge from this service for its own origin, bound to the request, signed by
// a key the account has in a VERIFIED state and that the login rule lets sign in. At most 8 browsers per account: a
// ninth is refused, nothing is pushed out. A browser unsubscribes with the same proof (all browsers of the account,
// each woken first) or with its endpoint alone (that browser; the account's other browsers are woken). The endpoint
// must be https on a host of a known browser push service, so that this service can be made to call no other address;
// no redirect is followed and every call has a time limit.
//
// What it answers (under /alerts/v1/): key (the VAPID public key), challenge, subscribe, unsubscribe, status
// (whether a browser is subscribed), and health ({"ok":true} to anyone; the counts to the machine itself only). It
// never returns or logs an endpoint or a key.
import http from 'node:http';
import { createECDH, createHash, createHmac, createCipheriv, createPrivateKey, createPublicKey, generateKeyPairSync, hkdfSync, randomBytes, randomInt, sign as signData, timingSafeEqual } from 'node:crypto';
import { open, readFile, rename, chmod, unlink } from 'node:fs/promises';
import path from 'node:path';
import './time-sdk.js';
import { verifyLogin } from './server-auth.mjs';
import { touchesOfBytes } from './touches.mjs';
import { createRateLimiter, clientKey, normalIp } from './api.mjs';
import { headerHash, transactionsRoot, successfulResultsRoot } from './indexer.mjs';

const SDK = globalThis.TimeSDK;
/// What every push carries. The service worker ignores it: it shows its own fixed words whatever comes.
export const PAYLOAD = Buffer.from('{"v":1}');
export const MAX_PER_ACCOUNT = 8;
/// How long a challenge lives, and how many used nonces are remembered (see createChallenges).
export const CHALLENGE_MS = 180000, MAX_USED_NONCES = 20000;
/// The pushes: at most 64 under way, 2 of one account; each gives up after 5 seconds; one that waits for a place is
/// abandoned after a minute (see createPushLine and the README).
export const PUSH = Object.freeze({ maxInFlight: 64, maxPerAccount: 2, timeoutMs: 5000, waitMs: 60000 });
/// The browser push services this service sends to, by host: Google's (Chrome, Edge on Android, most Android
/// browsers), Mozilla's (Firefox), Apple's (Safari, and a web app added to the Home Screen of an iPhone), Microsoft's
/// (Edge on Windows). Exactly that host, or any host under that domain.
export const PUSH_HOSTS = Object.freeze([{ exact: 'fcm.googleapis.com' }, { under: 'push.services.mozilla.com' }, { under: 'push.apple.com' }, { under: 'notify.windows.com' }]);
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const isAccount = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) < 18446744073709551615n;

// ------------------------------------------------------------------ base64url
export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
/// Bytes from canonical base64url without padding, of exactly `length` bytes, or null.
export function fromB64url(text, length) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const bytes = Buffer.from(text, 'base64url');
  return bytes.length === length && bytes.toString('base64url') === text ? bytes : null;
}

// ------------------------------------------------------------------ message encryption (RFC 8291, RFC 8188)
const KEY_INFO = Buffer.from('WebPush: info\0'), CEK_INFO = Buffer.from('Content-Encoding: aes128gcm\0'), NONCE_INFO = Buffer.from('Content-Encoding: nonce\0');
const hkdf = (ikm, salt, info, length) => Buffer.from(hkdfSync('sha256', ikm, salt, info, length));
/// The secrets of one message to a browser whose public key is `uaPublic` (65 bytes, uncompressed P-256) and whose
/// authentication secret is `authSecret` (16 bytes): RFC 8291, section 3.4. `asPrivate` (32 bytes) and `salt` (16)
/// are random unless given; tests give those of RFC 8291, Appendix A. A key that is not a point of P-256 throws.
export function pushSecrets({ uaPublic, authSecret, asPrivate, salt = randomBytes(16) }) {
  const ecdh = createECDH('prime256v1');
  if (asPrivate) ecdh.setPrivateKey(asPrivate); else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey();
  const ecdhSecret = ecdh.computeSecret(uaPublic);
  const ikm = hkdf(ecdhSecret, authSecret, Buffer.concat([KEY_INFO, uaPublic, asPublic]), 32);
  return { asPublic, ecdhSecret, ikm, salt: Buffer.from(salt), cek: hkdf(ikm, salt, CEK_INFO, 16), nonce: hkdf(ikm, salt, NONCE_INFO, 12) };
}
/// The body of a push message: one record of content coding aes128gcm (RFC 8188), whose header names the salt, a
/// record size of 4096 and the sender's public key (RFC 8291, section 4).
export function encryptPush({ payload = PAYLOAD, uaPublic, authSecret, asPrivate, salt, recordSize = 4096 }) {
  const s = pushSecrets({ uaPublic, authSecret, asPrivate, salt });
  if (payload.length + 1 + 16 > recordSize) throw new Error('A push message is one record');
  const cipher = createCipheriv('aes-128-gcm', s.cek, s.nonce);
  // The padding delimiter of the last record (0x02), no padding.
  const sealed = Buffer.concat([cipher.update(Buffer.concat([payload, Buffer.from([2])])), cipher.final(), cipher.getAuthTag()]);
  const header = Buffer.alloc(21); s.salt.copy(header, 0); header.writeUInt32BE(recordSize, 16); header[20] = s.asPublic.length;
  return Buffer.concat([header, s.asPublic, sealed]);
}

// ------------------------------------------------------------------ VAPID (RFC 8292)
/// A new VAPID key pair: the private key as a JWK, the public key as the browser takes it (base64url of the 65
/// bytes of the uncompressed point).
export function newVapidKeys() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' });
  return { private_jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, public_key: publicOf(jwk) };
}
const publicOf = (jwk) => b64url(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]));
/// The VAPID keys of a file's contents, checked: a P-256 private key whose public key is the one written beside it.
export function checkVapid(value) {
  if (!value || typeof value !== 'object' || Object.keys(value).sort().join(',') !== 'private_jwk,public_key,version' || value.version !== 1) throw new Error('vapid.json is not a key of this service');
  const jwk = value.private_jwk;
  if (!jwk || typeof jwk !== 'object' || Object.keys(jwk).sort().join(',') !== 'crv,d,kty,x,y' || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('vapid.json is not a key of this service');
  const key = createPrivateKey({ key: jwk, format: 'jwk' });
  const derived = createPublicKey(key).export({ format: 'jwk' });
  if (publicOf(derived) !== value.public_key || !fromB64url(value.public_key, 65)) throw new Error('vapid.json is not a key of this service');
  return { key, publicKey: value.public_key };
}
/// The Authorization header of a push to `endpoint`: a JWT signed with ES256 whose audience is the origin of the push
/// service, valid for `seconds` (at most a day), with `subject`, the operator's contact (an https address).
export function vapidHeader({ endpoint, vapid, subject, nowSeconds = Math.floor(Date.now() / 1000), seconds = 12 * 3600 }) {
  if (!(seconds > 0 && seconds <= 86400)) throw new Error('A VAPID token is valid for a day at most');
  const part = (value) => b64url(Buffer.from(JSON.stringify(value)));
  const unsigned = `${part({ typ: 'JWT', alg: 'ES256' })}.${part({ aud: new URL(endpoint).origin, exp: nowSeconds + seconds, sub: subject })}`;
  const signature = signData('sha256', Buffer.from(unsigned), { key: vapid.key, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${unsigned}.${b64url(signature)}, k=${vapid.publicKey}`;
}

// ------------------------------------------------------------------ what a browser subscribes with
/// The endpoint as a URL if it is https on a host of a known push service (PUSH_HOSTS), written as browsers write it;
/// throws otherwise. No user name, no port but 443, no fragment, at most 1024 characters.
export function checkEndpoint(text) {
  const refuse = () => { throw new Error('This is not the address of a browser push service this service sends to'); };
  if (typeof text !== 'string' || text.length > 1024) refuse();
  let url; try { url = new URL(text); } catch { refuse(); }
  if (url.href !== text || url.protocol !== 'https:' || url.username || url.password || url.port !== '' || url.hash || url.pathname.length < 2) refuse();
  const host = url.hostname, labels = host.split('.');
  if (!labels.every((label) => LABEL.test(label))) refuse();
  const known = PUSH_HOSTS.some((rule) => (rule.exact ? host === rule.exact : host.endsWith(`.${rule.under}`) && host.length > rule.under.length + 1));
  if (!known) refuse();
  return url;
}
/// A subscription as the browser gives it (PushSubscription.toJSON(): endpoint and the keys p256dh and auth, in
/// base64url), checked: the endpoint by checkEndpoint, p256dh a point of P-256, auth 16 bytes. Anything else in it
/// (expirationTime, always null in browsers) is not kept.
export function checkSubscription(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some((k) => !['endpoint', 'keys', 'expirationTime'].includes(k))) throw new Error('A subscription is {endpoint, keys: {p256dh, auth}}');
  checkEndpoint(value.endpoint);
  const keys = value.keys;
  if (!keys || typeof keys !== 'object' || Object.keys(keys).sort().join(',') !== 'auth,p256dh') throw new Error('A subscription is {endpoint, keys: {p256dh, auth}}');
  const ua = fromB64url(keys.p256dh, 65), auth = fromB64url(keys.auth, 16);
  if (!ua || ua[0] !== 4 || !auth) throw new Error('The keys of this subscription are not those of a browser');
  // A point of P-256: an agreement with it succeeds (Node refuses a point that is not on the curve).
  try { const probe = createECDH('prime256v1'); probe.generateKeys(); probe.computeSecret(ua); } catch { throw new Error('The keys of this subscription are not those of a browser'); }
  return { endpoint: value.endpoint, p256dh: keys.p256dh, auth: keys.auth };
}
/// What a challenge binds: the action and, for a subscription, the browser it names.
export const bindingOf = (action, subscription = null) => createHash('sha256').update(JSON.stringify(action === 'subscribe' ? ['subscribe', subscription.endpoint, subscription.p256dh, subscription.auth] : [action])).digest('hex');

// ------------------------------------------------------------------ the address list
/// rename(), tried again for a moment on Windows, where a reader of the old file (another program, a virus scanner)
/// makes it fail with EPERM, EACCES or EBUSY; anywhere else it is one call.
async function replace(from, to) {
  for (let attempt = 1; ; attempt += 1) {
    try { return await rename(from, to); } catch (error) {
      if (process.platform !== 'win32' || !['EPERM', 'EACCES', 'EBUSY'].includes(error.code) || attempt >= 10) throw error;
      await new Promise((resolve) => setTimeout(resolve, 25 * attempt));
    }
  }
}
const SUBSCRIPTION_FIELDS = 'account,auth,created,endpoint,p256dh';
/// The address list of one network, in memory and in one file written whole. `file` null keeps it in memory only.
/// In memory it is indexed by account and by endpoint, so that a change costs time in proportion to the browsers of
/// that account (at most 8) and of that endpoint (at most `maxAccountsPerEndpoint`), never to the whole list. The
/// file is written whole, by one write at a time: changes made while a write runs are taken by the next one, of
/// which there is at most one waiting (a list of 50,000 is one string of some 20 MB; two of them at most exist).
export async function openSubscriptions({ file, networkId, maxTotal = 50000, maxAccountsPerEndpoint = 16 }) {
  // account -> its browsers, oldest first; endpoint -> (account -> the same entry).
  const byAccount = new Map(), byEndpoint = new Map();
  let total = 0;
  const insert = (entry) => {
    if (!byAccount.has(entry.account)) byAccount.set(entry.account, []);
    byAccount.get(entry.account).push(entry);
    if (!byEndpoint.has(entry.endpoint)) byEndpoint.set(entry.endpoint, new Map());
    byEndpoint.get(entry.endpoint).set(entry.account, entry);
    total += 1;
  };
  const detach = (entry) => {
    const mine = byAccount.get(entry.account), at = mine ? mine.indexOf(entry) : -1;
    if (at < 0) return false;
    mine.splice(at, 1); if (mine.length === 0) byAccount.delete(entry.account);
    const accounts = byEndpoint.get(entry.endpoint); accounts?.delete(entry.account); if (accounts?.size === 0) byEndpoint.delete(entry.endpoint);
    total -= 1;
    return true;
  };
  if (file) {
    let text = null;
    try { text = await readFile(file, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (text !== null) {
      let saved; try { saved = JSON.parse(text); } catch { throw new Error('subscriptions.json is damaged: it is not JSON'); }
      if (!saved || Object.keys(saved).sort().join(',') !== 'network_id,subscriptions,version' || saved.version !== 1 || !Array.isArray(saved.subscriptions)) throw new Error('subscriptions.json is damaged');
      if (saved.network_id !== networkId) throw new Error('subscriptions.json belongs to another network');
      for (const s of saved.subscriptions) {
        if (!s || Object.keys(s).sort().join(',') !== SUBSCRIPTION_FIELDS || !isAccount(s.account) || typeof s.created !== 'string' || !Number.isFinite(Date.parse(s.created))) throw new Error('subscriptions.json is damaged');
        let checked; try { checked = checkSubscription({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }); } catch { throw new Error('subscriptions.json is damaged'); }
        // Written by this service, which keeps each browser once per account and at most 8 per account.
        if (byEndpoint.get(checked.endpoint)?.has(s.account) || (byAccount.get(s.account)?.length ?? 0) >= MAX_PER_ACCOUNT) throw new Error('subscriptions.json is damaged');
        insert({ account: s.account, ...checked, created: s.created });
      }
    }
  }
  // ---- writing the file: one write at a time, and at most one more waiting, which takes every change made until it
  // begins. Each caller gets the write that includes its change.
  let writing = null, next = null, writes = 0;
  async function writeNow() {
    writes += 1;
    const subscriptions = [];
    for (const mine of byAccount.values()) for (const { account, endpoint, p256dh, auth, created } of mine) subscriptions.push({ account, endpoint, p256dh, auth, created });
    const snapshot = JSON.stringify({ version: 1, network_id: networkId, subscriptions });
    const temporary = `${file}.${process.pid}.tmp`;
    try {
      const handle = await open(temporary, 'w', 0o600);
      try { await handle.writeFile(snapshot); await handle.sync(); } finally { await handle.close(); }
      await chmod(temporary, 0o600).catch(() => {}); // where the system has such modes
      await replace(temporary, file);
    } catch (error) { await unlink(temporary).catch(() => {}); throw error; }
  }
  const begin = () => { const task = writeNow().finally(() => { if (writing === task) writing = null; }); writing = task; return task; };
  function save() {
    if (!file) return Promise.resolve();
    if (next) return next;
    if (!writing) return begin();
    next = writing.catch(() => {}).then(() => { next = null; return begin(); });
    return next;
  }
  const of = (account) => [...(byAccount.get(account) ?? [])];
  return {
    /// Adds a browser to an account; the same browser again is renewed (it becomes the newest). A ninth browser of
    /// an account is refused (status 409, message "full"): nothing is pushed out to make room.
    async add(account, subscription, now = Date.now()) {
      const known = byEndpoint.get(subscription.endpoint)?.get(account);
      if (!known) {
        if ((byAccount.get(account)?.length ?? 0) >= MAX_PER_ACCOUNT) throw Object.assign(new Error('full'), { status: 409 });
        if ((byEndpoint.get(subscription.endpoint)?.size ?? 0) >= maxAccountsPerEndpoint) throw Object.assign(new Error('This browser follows as many accounts as it may'), { status: 409 });
        if (total >= maxTotal) throw Object.assign(new Error('This service takes no more subscriptions'), { status: 503 });
      } else detach(known);
      insert({ account, endpoint: subscription.endpoint, p256dh: subscription.p256dh, auth: subscription.auth, created: new Date(now).toISOString() });
      await save();
      return byAccount.get(account).length;
    },
    /// Removes a browser everywhere (by its endpoint), or every browser of an account. Returns how many went.
    async remove({ endpoint, account }) {
      const going = endpoint !== undefined ? [...(byEndpoint.get(endpoint)?.values() ?? [])] : of(account);
      let removed = 0;
      for (const entry of going) if (detach(entry)) removed += 1;
      if (removed) await save();
      return removed;
    },
    of,
    has: (account) => byAccount.has(account),
    /// The accounts a browser is subscribed to.
    accountsOf: (endpoint) => [...(byEndpoint.get(endpoint)?.keys() ?? [])],
    /// Whether a browser is subscribed to any account.
    subscribed: (endpoint) => byEndpoint.has(endpoint),
    counts: () => ({ subscriptions: total, accounts: byAccount.size }),
    /// How many times the file was written (for tests).
    writes: () => writes,
    /// Resolves once nothing is being written and nothing waits to be.
    settled: async () => { while (writing || next) await (next ?? writing).catch(() => {}); },
  };
}

// ------------------------------------------------------------------ challenges
/// The challenges of the proofs (subscribe, unsubscribe every browser of an account). Nothing is kept for a
/// challenge that was given out: its nonce is 16 random bytes and a tag of 16 bytes, an HMAC under a key made when
/// the service starts over the random bytes, what the challenge was asked for (its binding), its two times, the
/// origin and the network. A proof brings the challenge back inside its message; the tag shows that this service made
/// it, for that very request, and when. What is kept is the nonces that were USED, until they expire, so that a
/// challenge serves once. Their number is bounded by `maxUsed`: past it the nonce used longest ago is forgotten and
/// the floor rises to the time that challenge was given out; a challenge given out at or before the floor is refused.
/// So a forgotten nonce can never serve again (its time is at or below the floor, which only rises), and the cost of
/// forgetting is that challenges given out before the floor and not yet used must be asked for again. A restart makes
/// a new key: every challenge given out before it is refused.
export function createChallenges({ origin, networkId, ttlMs = CHALLENGE_MS, maxUsed = MAX_USED_NONCES, now = Date.now, key = randomBytes(32) }) {
  const used = new Map();
  let floor = -Infinity, prunedAt = -Infinity;
  const tagOf = (random, binding, issuedAt, expiresAt) => createHmac('sha256', key).update(JSON.stringify(['time-alerts-challenge-1', origin, networkId, random, binding, issuedAt, expiresAt])).digest().subarray(0, 16);
  const refuse = (message) => { throw new Refusal(403, message); };
  return {
    /// A challenge for a request whose binding is `binding` (bindingOf), in the form of every login challenge.
    issue(binding) {
      const random = randomBytes(16).toString('hex'), issuedAt = now(), expiresAt = issuedAt + ttlMs;
      return { purpose: 'login', origin, networkId, nonce: random + tagOf(random, binding, issuedAt, expiresAt).toString('hex'), issuedAt, expiresAt };
    },
    /// The challenge a proof's message names, if this service made it for `binding`, it has not expired and it was
    /// not used; marked used before anything else of the proof is checked. Throws a refusal otherwise.
    take(message, binding) {
      const nonce = message?.nonce, issuedAt = message?.issuedAt, expiresAt = message?.expiresAt;
      if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce) || !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt)) refuse('This challenge expired or was used already: ask for a new one');
      if (!timingSafeEqual(Buffer.from(nonce.slice(32), 'hex'), tagOf(nonce.slice(0, 32), binding, issuedAt, expiresAt))) refuse('This proof was made for another request');
      const at = now();
      if (expiresAt - issuedAt !== ttlMs || expiresAt <= at || issuedAt <= floor || used.has(nonce)) refuse('This challenge expired or was used already: ask for a new one');
      if (at - prunedAt >= 1000) { prunedAt = at; for (const [n, entry] of used) if (entry.expiresAt <= at || entry.issuedAt <= floor) used.delete(n); }
      while (used.size >= maxUsed) {
        const [oldest, entry] = used.entries().next().value;
        used.delete(oldest);
        if (entry.issuedAt > floor) floor = entry.issuedAt;
      }
      used.set(nonce, { issuedAt, expiresAt });
      return { purpose: 'login', origin, networkId, nonce, issuedAt, expiresAt };
    },
    used: () => used.size,
    floor: () => floor,
  };
}

// ------------------------------------------------------------------ the line of pushes
/// The pushes to be sent: those waiting for a free place, in memory only, and those under way. Nothing in it is
/// written anywhere, kept across a restart or sent again: a push that waited longer than `waitMs` is abandoned and
/// counted. What it guarantees:
/// - No push is dropped because others are under way: it waits for a free place.
/// - Accounts are served in turn: an account gets its first push started before any account gets its second, and so
///   on, across blocks too. An account stays in turn for as long as it has pushes waiting or under way, so pushes it
///   still has under way from an earlier block count: a new block does not give it a new first place.
/// - At most `maxInFlight` pushes are under way, and at most `maxPerAccount` of one account.
/// - The browsers of one account go oldest subscription first.
/// - A browser already waiting is not added again: one push reaches it.
/// - The line holds at most `maxWaiting` pushes. When it is full, the newest push of the account that has the most
///   waiting is abandoned to make room, never an account's only one; when every account has at most one waiting,
///   an account's first push is still taken (the line then exceeds the cap by at most one push per account, and the
///   accounts are bounded by the address list), and a second is abandoned.
/// - `urgent` pushes (the wake before a removal) go before all others, outside the turns, at most `maxUrgent` waiting
///   and at most half of the places under way: each one costs whoever causes it a proof or a subscription, but the
///   pushes of the blocks always keep the other half.
export function createPushLine({ send, maxInFlight = 64, maxPerAccount = 2, waitMs = 60000, maxWaiting = 50000, maxUrgent = 1024, maxUrgentInFlight = Math.max(1, Math.floor(maxInFlight / 2)), now = Date.now, log = () => {}, stats = {}, sweepMs = 1000 }) {
  const accounts = new Map(); // account -> { items, served, inFlight }
  const levels = new Map(); // pushes started -> the accounts with that many started and pushes waiting, in order of arrival
  const waitingAt = new Map(); // endpoint -> its waiting push (not the urgent ones)
  const urgent = [];
  let inFlight = 0, urgentInFlight = 0, waiting = 0, abandoned = 0, loggedAt = -Infinity, sweeper = null, closed = false;
  stats.pushes_abandoned ??= 0;
  const levelOf = (n) => { if (!levels.has(n)) levels.set(n, new Set()); return levels.get(n); };
  const leave = (account, entry) => { const set = levels.get(entry.served); if (set) { set.delete(account); if (set.size === 0) levels.delete(entry.served); } };
  const tidy = (account, entry) => { if (entry.items.length === 0 && entry.inFlight === 0 && accounts.get(account) === entry) accounts.delete(account); };
  function push(account, s, ms) {
    let resolve;
    const done = new Promise((r) => { resolve = r; });
    return { account, endpoint: s.endpoint, p256dh: s.p256dh, auth: s.auth, deadline: now() + ms, done, resolve };
  }
  function abandon(item) { stats.pushes_abandoned += 1; abandoned += 1; item.resolve('abandoned'); }
  function report(force = false) {
    if (!abandoned || (!force && now() - loggedAt < 5000)) return;
    // Counts only: no account, no browser.
    log('warn', 'pushes were abandoned: they waited too long for a free place, or the line was full', { abandoned, waiting, in_flight: inFlight });
    abandoned = 0; loggedAt = now();
  }
  function drop(entry, index) { const [item] = entry.items.splice(index, 1); waitingAt.delete(item.endpoint); waiting -= 1; abandon(item); }
  /// Drops what waited past its deadline from the front of an account's pushes (they are in order of arrival).
  function expire(account, entry, at) {
    while (entry.items.length && entry.items[0].deadline <= at) drop(entry, 0);
    if (entry.items.length === 0) { leave(account, entry); tidy(account, entry); }
  }
  /// Makes room in a full line for a push of `account`. False: the new push is to be abandoned.
  function room(account, entry) {
    let most = null, mostAccount = null;
    for (const [key, e] of accounts) if (e.items.length > (most?.items.length ?? 0)) { most = e; mostAccount = key; }
    if (most && most.items.length >= 2 && mostAccount !== account) { drop(most, most.items.length - 1); return true; }
    return entry.items.length === 0;
  }
  function next() {
    const at = now();
    while (urgent.length && urgentInFlight < maxUrgentInFlight) { const item = urgent.shift(); if (item.deadline <= at) { abandon(item); continue; } urgentInFlight += 1; return { item, entry: null }; }
    for (const level of [...levels.keys()].sort((a, b) => a - b)) {
      for (const account of [...levels.get(level) ?? []]) {
        const entry = accounts.get(account);
        expire(account, entry, at);
        if (entry.items.length === 0 || entry.inFlight >= maxPerAccount) continue;
        const item = entry.items.shift(); waitingAt.delete(item.endpoint); waiting -= 1;
        leave(account, entry);
        entry.served += 1; entry.inFlight += 1;
        if (entry.items.length) levelOf(entry.served).add(account);
        return { item, entry };
      }
    }
    return null;
  }
  function dispatch() {
    while (!closed && inFlight < maxInFlight) {
      const picked = next();
      if (!picked) break;
      inFlight += 1;
      run(picked);
    }
    report();
    if (!closed && (waiting || urgent.length) && !sweeper) { sweeper = setInterval(sweep, sweepMs); sweeper.unref?.(); }
    if (sweeper && !waiting && !urgent.length) { clearInterval(sweeper); sweeper = null; }
  }
  async function run({ item, entry }) {
    try { await send(item); } catch { /* send counts its own failures */ } finally {
      inFlight -= 1;
      if (entry) { entry.inFlight -= 1; tidy(item.account, entry); } else urgentInFlight -= 1;
      item.resolve('sent');
      dispatch();
    }
  }
  /// What waited past its deadline is abandoned even while no place frees up.
  function sweep() {
    const at = now();
    for (const [account, entry] of [...accounts]) expire(account, entry, at);
    for (let i = urgent.length - 1; i >= 0; i--) if (urgent[i].deadline <= at) abandon(urgent.splice(i, 1)[0]);
    report(true);
    dispatch();
  }
  return {
    /// Puts one push to subscription `s` of `account` in line. Returns a promise that settles once it was sent or
    /// abandoned. Call dispatch() after adding.
    add(account, s) {
      const known = waitingAt.get(s.endpoint);
      if (known) return known.done;
      let entry = accounts.get(account);
      if (!entry) { entry = { items: [], served: 0, inFlight: 0 }; accounts.set(account, entry); }
      const item = push(account, s, waitMs);
      if (waiting >= maxWaiting && !room(account, entry)) { abandon(item); tidy(account, entry); return item.done; }
      if (entry.items.length === 0) levelOf(entry.served).add(account);
      entry.items.push(item); waitingAt.set(item.endpoint, item); waiting += 1;
      return item.done;
    },
    /// Whether `count` more urgent pushes fit.
    roomForUrgent: (count) => urgent.length + count <= maxUrgent,
    /// An urgent push (before a removal): first in line, outside the turns, abandoned after `ms`.
    addUrgent(account, s, ms) {
      const item = push(account, s, ms);
      if (urgent.length >= maxUrgent) { abandon(item); return item.done; }
      urgent.push(item);
      return item.done;
    },
    dispatch,
    waiting: () => waiting + urgent.length,
    inFlight: () => inFlight,
    /// Stops: what still waits is let go (each settles as "closed"), and nothing more starts.
    close() {
      closed = true; if (sweeper) clearInterval(sweeper); sweeper = null;
      for (const entry of accounts.values()) for (const item of entry.items.splice(0)) item.resolve('closed');
      for (const item of urgent.splice(0)) item.resolve('closed');
      waitingAt.clear(); waiting = 0;
    },
  };
}

// ------------------------------------------------------------------ the blocks
/// Checks that `block` (the RPC's answer for height h) is the verified block h, and that every action in it was
/// taken: its header is the one the verified header of h + 1 names, its transactions are the ones its header
/// commits to, and h + 1 commits to successful results for each of them. `light` is a light client over the same
/// node (light-client.mjs). Throws on anything else.
export async function verifyBlock({ light, block, height, chainId }) {
  const header = block?.block?.header, txs = block?.block?.data?.txs ?? [];
  if (!header || String(header.height) !== String(height) || header.chain_id !== chainId || !Array.isArray(txs)) throw new Error('The node answered another block');
  const checkpoint = await light.updateTo(String(height + 1));
  const next = checkpoint?.block?.signed_header?.header;
  if (!next || headerHash(next).toString('hex') !== checkpoint.block_hash) throw new Error('The header of the next block is not the one the light client verified');
  if (String(next.last_block_id?.hash ?? '').toLowerCase() !== headerHash(header).toString('hex')) throw new Error('The block is not the one the verified chain names');
  const raws = txs.map((text) => Buffer.from(text, 'base64'));
  const root = transactionsRoot(raws.map((raw) => createHash('sha256').update(raw).digest()));
  if (raws.length && String(header.data_hash ?? '').toLowerCase() !== root.toString('hex')) throw new Error('The actions are not the ones the block commits to');
  if (raws.length && String(next.last_results_hash ?? '').toLowerCase() !== successfulResultsRoot(raws.length).toString('hex')) throw new Error('The next block does not commit to successful results for every action of this one');
  return raws;
}

// ------------------------------------------------------------------ the service
const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Cross-Origin-Resource-Policy': 'same-origin', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" };
export const MAX_BODY_BYTES = 8 * 1024;
class Refusal extends Error { constructor(status, message) { super(message); this.status = status; } }
const LOOPBACK = new Set(['127.0.0.1', '0:0:0:0:0:0:0:1']);
/// The accounts of a block in a random order: the order of the actions in the block, which whoever sends them
/// chooses, gives nobody a place in the line.
function shuffled(values) {
  const list = [...values];
  for (let i = list.length - 1; i > 0; i--) { const j = randomInt(i + 1); [list[i], list[j]] = [list[j], list[i]]; }
  return list;
}

/// Starts the alert service. Options:
/// - `rpc(method, parameters)`: the node's RPC (indexer.mjs, createRpc); `trust`: the network's trust manifest;
/// - `light`: a light client over that node (blocks); `verifiedState(selection)`: verified reads (api.mjs,
///   createStateReader), for the proof of whoever subscribes;
/// - `origin`: the wallet's public origin, where the pages and the requests come from and which proofs name;
///   `hosts`: Host header values answered (besides the loopback address the service listens on);
/// - `subscriptions` (openSubscriptions), `vapid` (checkVapid), `subject`: the operator's https contact for VAPID;
/// - `host`, `port`, `trustedProxies`, `rateLimit` { perSecond, burst };
/// - `fetcher` (fetch); the pushes: `pushTimeoutMs`, `maxInFlight`, `maxPerAccountInFlight`, `pushWaitMs`,
///   `maxWaiting` (createPushLine), and `wakeWaitMs`, how long an unsubscription waits for the wake of the browsers it
///   removes; `pollMs`, `warnBehind` (blocks behind the chain before the log says so), `refreshMs`, `log`, `now`, and
///   for tests `verify` (in place of verifyBlock) and `autoStart`.
export async function createAlertService({
  rpc, trust, light, verifiedState, origin, hosts = [], subscriptions, vapid, subject, host = '127.0.0.1', port = 8950, trustedProxies = [],
  rateLimit = {}, fetcher = globalThis.fetch, pushTimeoutMs = PUSH.timeoutMs, maxInFlight = PUSH.maxInFlight, maxPerAccountInFlight = PUSH.maxPerAccount, pushWaitMs = PUSH.waitMs,
  maxWaiting = 50000, wakeWaitMs = 2 * pushTimeoutMs, pollMs = 1000, warnBehind = 120, refreshMs = 3600000, log = () => {}, now = Date.now, verify, autoStart = true,
}) {
  const networkId = trust.network_id, chainId = trust.chain_id;
  if (typeof origin !== 'string' || new URL(origin).origin !== origin) throw new Error('origin is the wallet\'s public origin');
  const ownHosts = new Set([new URL(origin).host, ...hosts].map((h) => h.toLowerCase()));
  const proxies = new Set(trustedProxies.map(normalIp).filter(Boolean));
  const limiter = createRateLimiter({ perSecond: 2, burst: 30, ...rateLimit, now });
  const challenges = createChallenges({ origin, networkId, now });
  const stats = { pushes_sent: 0, pushes_failed: 0, pushes_abandoned: 0, subscriptions_gone: 0, blocks_read: 0, blocks_verified: 0, blocks_refused: 0 };
  let followed = null, behind = 0, warnedAt = -Infinity, stopped = false, timer = null, refresher = null, running = null;

  // ---- pushes
  /// One push to one browser. Its subscription travels with it, so that a push still goes to a browser that was
  /// removed after it was put in line (the wake before a removal).
  async function send(item) {
    try {
      // Checked again where it is used: nothing but an address of a push service is ever called.
      checkEndpoint(item.endpoint);
      const body = encryptPush({ uaPublic: Buffer.from(item.p256dh, 'base64url'), authSecret: Buffer.from(item.auth, 'base64url') });
      const response = await fetcher(item.endpoint, {
        method: 'POST', body, redirect: 'error', signal: AbortSignal.timeout(pushTimeoutMs),
        headers: { TTL: '43200', Urgency: 'high', Topic: 'account', 'Content-Type': 'application/octet-stream', 'Content-Encoding': 'aes128gcm', Authorization: vapidHeader({ endpoint: item.endpoint, vapid, subject, nowSeconds: Math.floor(now() / 1000) }) },
      });
      try { await response.body?.cancel(); } catch { /* nothing more is read */ }
      if (response.status === 404 || response.status === 410) {
        // The push service says this browser's subscription is gone: it is removed, from every account.
        // (Awaited first, then added: `+= await` would add to a count read before the wait.)
        const removed = await subscriptions.remove({ endpoint: item.endpoint });
        stats.subscriptions_gone += removed;
      } else if (response.status >= 200 && response.status < 300) stats.pushes_sent += 1;
      else stats.pushes_failed += 1;
    } catch { stats.pushes_failed += 1; }
  }
  const line = createPushLine({ send, maxInFlight, maxPerAccount: maxPerAccountInFlight, waitMs: pushWaitMs, maxWaiting, now, log, stats });
  /// Wakes the subscribed browsers of `accounts`: one push each, also for a browser subscribed to several of them.
  /// Resolves once every push was sent or abandoned.
  function wake(accounts) {
    const endpoints = new Map();
    for (const account of shuffled(accounts)) for (const s of subscriptions.of(account)) if (!endpoints.has(s.endpoint)) endpoints.set(s.endpoint, { account, s });
    const done = [...endpoints.values()].map(({ account, s }) => line.add(account, s));
    line.dispatch();
    return Promise.all(done);
  }
  /// The wake before a removal: the browsers `list` (of `account`) first in line. Resolves once each was sent or
  /// abandoned, or after `wakeWaitMs`, whichever comes first.
  async function wakeFirst(account, list) {
    if (!list.length) return;
    const done = list.map((s) => line.addUrgent(account, s, wakeWaitMs));
    line.dispatch();
    let timeout;
    await Promise.race([Promise.all(done), new Promise((resolve) => { timeout = setTimeout(resolve, wakeWaitMs); timeout.unref?.(); })]);
    clearTimeout(timeout);
  }

  // ---- the blocks
  /// Reads block `height`; wakes the subscribed accounts its actions wake, once the block is verified. Returns
  /// { pushes } (a promise the loop does not wait for: a slow push service holds nothing up), or nothing.
  async function readBlock(height) {
    const block = await rpc('/block', { height: String(height) });
    stats.blocks_read += 1;
    const txs = block?.block?.data?.txs;
    if (!Array.isArray(txs)) throw new Error('The node answered an unusable block');
    const woken = new Set();
    for (const text of txs) {
      if (typeof text !== 'string') continue;
      for (const account of touchesOfBytes(new Uint8Array(Buffer.from(text, 'base64')), networkId).wake) if (subscriptions.has(account)) woken.add(account);
    }
    // A block that wakes nobody who subscribed costs nothing more: no verification, no push.
    if (woken.size === 0) return;
    try { await (verify ?? verifyBlock)({ light, block, height, chainId }); stats.blocks_verified += 1; } catch (error) {
      stats.blocks_refused += 1;
      log('warn', 'a block was not verified: nobody is woken for it', { height, error: String(error?.message ?? error).slice(0, 160) });
      return;
    }
    return { pushes: wake(woken).catch(() => {}) };
  }
  /// One round: the newest height, then each block up to two below it. A block is verified with the one after it, and
  /// the light client verifies that one with the validators of the one after that: the newest block's next set may
  /// not be served yet (indexer.mjs reads below the newest for the same reason). At start the service begins after
  /// the newest block (nothing is sent for the past); from then on it reads every block in order, however far behind
  /// it falls: a block is never left out, because the action in it may be a theft whose wait is still running.
  async function step() {
    const status = await rpc('/status');
    if (status?.node_info?.network !== undefined && status.node_info.network !== chainId) throw new Error('The node is of another chain');
    const tip = Number(status?.sync_info?.latest_block_height);
    if (!Number.isSafeInteger(tip) || tip < 3) return;
    const last = tip - 2;
    if (followed === null) followed = last;
    behind = Math.max(0, last - followed);
    if (behind > warnBehind && now() - warnedAt >= 60000) { warnedAt = now(); log('warn', 'the service is behind the chain: it reads every block in order and catches up', { behind }); }
    while (!stopped && followed < last) { await readBlock(followed + 1); followed += 1; behind = Math.max(0, last - followed); }
  }
  async function loop() {
    let failures = 0;
    while (!stopped) {
      try { await step(); failures = 0; } catch (error) { failures += 1; if (failures % 20 === 1) log('warn', 'reading the chain failed; trying again', { error: String(error?.message ?? error).slice(0, 160), failures }); }
      if (stopped) break;
      await new Promise((resolve) => { timer = setTimeout(resolve, failures ? Math.min(30000, pollMs * 2 ** Math.min(failures, 5)) : pollMs); timer.unref?.(); });
    }
  }

  // ---- requests
  function clientOf(request) {
    const peer = normalIp(request.socket.remoteAddress);
    if (peer === null || !proxies.has(peer)) return clientKey(peer);
    const entries = String(request.headers['x-forwarded-for'] || '').split(',');
    for (let i = entries.length - 1; i >= 0; i--) { const ip = normalIp(entries[i]); if (ip === null) break; if (!proxies.has(ip)) return clientKey(ip); }
    return clientKey(peer);
  }
  /// A request of this machine itself, made straight to the service: from the loopback address, under the loopback
  /// host name, and through no proxy (a proxy on this machine forwards the public's requests from the same address,
  /// but under the wallet's host name and with X-Forwarded-For).
  function fromThisMachine(request) {
    const bound = server.address()?.port, asked = String(request.headers.host || '').toLowerCase();
    return LOOPBACK.has(normalIp(request.socket.remoteAddress)) && [`127.0.0.1:${bound}`, `localhost:${bound}`].includes(asked)
      && !['x-forwarded-for', 'forwarded', 'x-real-ip'].some((name) => request.headers[name] !== undefined);
  }
  async function readJson(request) {
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] || '')) throw new Refusal(415, 'Send JSON');
    if (Number(request.headers['content-length']) > MAX_BODY_BYTES) throw new Refusal(413, 'The request is too large');
    const chunks = []; let size = 0;
    for await (const chunk of request) { size += chunk.length; if (size > MAX_BODY_BYTES) throw new Refusal(413, 'The request is too large'); chunks.push(chunk); }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))); } catch { throw new Refusal(400, 'The body is not JSON'); }
  }
  const only = (body, keys) => { if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).sort().join(',') !== [...keys].sort().join(',')) throw new Refusal(400, `The body is {${keys.join(', ')}}`); };
  async function proven(proof, binding) {
    // The challenge is taken (marked used) before anything else of the proof is checked, as server-auth.mjs does.
    const challenge = challenges.take(proof?.message, binding);
    if (proving >= 8) throw new Refusal(503, 'Too many requests are being checked: try again in a moment');
    proving += 1;
    try { return await verifyLogin({ verifiedState, networkId, origin, challenge, proof, now }); } catch (error) {
      if (error instanceof Refusal) throw error;
      throw new Refusal(403, `The account was not proven: ${String(error?.message ?? error).slice(0, 160)}`);
    } finally { proving -= 1; }
  }
  /// Proofs being checked now: each reads a verified state, so only so many at once.
  let proving = 0;
  const busy = () => new Refusal(503, 'Too many browsers are being woken: try again in a moment');
  const ROUTES = {
    'GET /alerts/v1/key': () => ({ public_key: vapid.publicKey }),
    // To anyone: that it runs. The counts tell who has alerts on (wake an account, watch the pushes), so only the
    // machine itself reads them (its supervisor asks 127.0.0.1 directly).
    'GET /alerts/v1/health': (request) => (fromThisMachine(request)
      ? { ok: !stopped, network_id: networkId, followed_height: followed === null ? null : String(followed), behind, ...subscriptions.counts(), pushes_waiting: line.waiting(), pushes_in_flight: line.inFlight(), ...stats }
      : { ok: true }),
    'POST /alerts/v1/challenge': async (request) => {
      const body = await readJson(request);
      let binding;
      if (body?.action === 'subscribe') { only(body, ['action', 'subscription']); binding = bindingOf('subscribe', checkOr400(() => checkSubscription(body.subscription))); }
      else if (body?.action === 'unsubscribe') { only(body, ['action']); binding = bindingOf('unsubscribe'); }
      else throw new Refusal(400, 'action is subscribe or unsubscribe');
      return challenges.issue(binding);
    },
    'POST /alerts/v1/subscribe': async (request) => {
      const body = await readJson(request);
      only(body, ['proof', 'subscription']);
      const subscription = checkOr400(() => checkSubscription(body.subscription));
      const { account } = await proven(body.proof, bindingOf('subscribe', subscription));
      try { await subscriptions.add(String(account.id), subscription, now()); } catch (error) { throw new Refusal(error.status ?? 500, error.status ? error.message : 'The subscription could not be kept'); }
      log('info', 'a browser subscribed', { account: String(account.id) });
      return { subscribed: true, account: String(account.id) };
    },
    // Whether this browser is subscribed, to any account: the push address is the capability, as for unsubscribing
    // by it. The answer says nothing else, not even for which account.
    'POST /alerts/v1/status': async (request) => {
      const body = await readJson(request);
      only(body, ['endpoint']);
      checkOr400(() => checkEndpoint(body.endpoint));
      return { subscribed: subscriptions.subscribed(body.endpoint) };
    },
    'POST /alerts/v1/unsubscribe': async (request) => {
      const body = await readJson(request);
      if (body && typeof body === 'object' && Object.hasOwn(body, 'endpoint')) {
        // A browser that turns itself off (or whoever holds its push address): it goes, and the other browsers of the
        // accounts it followed are woken, so that their owner hears of it.
        only(body, ['endpoint']);
        checkOr400(() => checkEndpoint(body.endpoint));
        const accounts = subscriptions.accountsOf(body.endpoint);
        const others = new Map();
        for (const account of accounts) for (const s of subscriptions.of(account)) if (s.endpoint !== body.endpoint && !others.has(s.endpoint)) others.set(s.endpoint, { account, s });
        if (!line.roomForUrgent(others.size)) throw busy();
        const removed = await subscriptions.remove({ endpoint: body.endpoint });
        for (const { account, s } of others.values()) line.addUrgent(account, s, wakeWaitMs);
        line.dispatch();
        return { removed };
      }
      only(body, ['proof']);
      const { account } = await proven(body.proof, bindingOf('unsubscribe'));
      const id = String(account.id), browsers = subscriptions.of(id);
      // Every browser of the account is woken before it is removed: whoever asked holds the login key, which may not
      // be its owner's hand.
      if (!line.roomForUrgent(browsers.length)) throw busy();
      await wakeFirst(id, browsers);
      const removed = await subscriptions.remove({ account: id });
      log('info', 'the browsers of an account were woken and unsubscribed', { account: id, removed });
      return { removed };
    },
  };
  const checkOr400 = (work) => { try { return work(); } catch (error) { throw new Refusal(400, error.message); } };
  const COST = { 'GET /alerts/v1/key': 0.2, 'GET /alerts/v1/health': 1 };

  async function handle(request, response) {
    const reply = (status, body, extra = {}) => { const text = JSON.stringify(body); response.writeHead(status, { ...JSON_HEADERS, 'Content-Length': Buffer.byteLength(text), ...extra }); response.end(text); };
    try {
      if (request.rawHeaders.filter((name, i) => i % 2 === 0 && name.toLowerCase() === 'host').length > 1) throw new Refusal(400, 'A request names its host once');
      const bound = server.address()?.port, asked = String(request.headers.host || '').toLowerCase();
      if (!ownHosts.has(asked) && ![`127.0.0.1:${bound}`, `localhost:${bound}`].includes(asked)) throw new Refusal(421, 'This service does not answer under that host name');
      // Requests come from the wallet's own pages: a page of another origin is refused.
      if (request.headers.origin !== undefined && request.headers.origin !== origin) throw new Refusal(403, 'Requests come from the wallet\'s own pages');
      const target = String(request.url || '');
      const route = `${request.method} ${target}`, caller = clientOf(request);
      const wait = limiter.take(caller, COST[route] ?? 1);
      if (wait) throw new Refusal(429, 'Too many requests from this address');
      const handler = Object.hasOwn(ROUTES, route) ? ROUTES[route] : null;
      if (!handler) throw new Refusal(Object.keys(ROUTES).some((r) => r.endsWith(` ${target}`)) ? 405 : 404, 'No such route');
      reply(200, await handler(request));
    } catch (error) {
      if (response.headersSent) { response.destroy(); return; }
      if (error instanceof Refusal) { reply(error.status, { error: error.message }, error.status === 429 ? { 'Retry-After': '5' } : error.status === 413 ? { Connection: 'close' } : {}); return; }
      log('error', 'a request failed', { error: String(error?.message ?? error).slice(0, 160) });
      reply(500, { error: 'The request could not be answered' });
    }
  }
  const server = http.createServer((request, response) => { handle(request, response); });
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.keepAliveTimeout = 5000; server.maxConnections = 1024;
  server.on('clientError', (error, socket) => { socket.destroy(); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, () => { server.removeListener('error', reject); resolve(); }); });
  if (autoStart) {
    running = loop();
    // The light clients move only when something is verified; on a quiet chain they are moved on a timer, so that a
    // week without subscribers does not let the trust anchor expire.
    refresher = setInterval(() => { if (followed !== null) light?.updateTo?.(String(followed)).catch(() => {}); verifiedState?.({}).catch(() => {}); }, refreshMs);
    refresher.unref?.();
  }
  const address = server.address();
  let closing = null;
  return {
    url: `http://${address.family === 'IPv6' ? `[${address.address}]` : address.address}:${address.port}`,
    step, readBlock, wake, stats, subscriptions, challenges,
    waiting: () => line.waiting(), inFlight: () => line.inFlight(),
    close: () => closing ??= (async () => {
      stopped = true; clearTimeout(timer); clearInterval(refresher); line.close();
      await running;
      await new Promise((resolve) => { server.close(() => resolve()); server.closeAllConnections?.(); });
      await subscriptions.settled().catch(() => {});
    })(),
  };
}

/// Where the light clients of the service keep the newest checkpoint each verified: one small file, rewritten whole
/// at most every `everyMs` and when the service closes. It holds block headers of the chain and nothing else.
export function checkpointFile(file, { everyMs = 600000, now = Date.now } = {}) {
  let all = null, dirty = false, written = 0, writing = Promise.resolve();
  const load = async () => { if (all) return all; try { all = JSON.parse(await readFile(file, 'utf8')); if (!all || typeof all !== 'object' || Array.isArray(all)) all = {}; } catch { all = {}; } return all; };
  const flush = () => {
    if (!dirty) return writing;
    dirty = false; written = now();
    const text = JSON.stringify(all);
    writing = writing.catch(() => {}).then(async () => {
      const temporary = `${file}.${process.pid}.tmp`;
      const handle = await open(temporary, 'w', 0o600);
      try { await handle.writeFile(text); await handle.sync(); } finally { await handle.close(); }
      await chmod(temporary, 0o600).catch(() => {});
      await rename(temporary, file);
    }).catch(async () => { dirty = true; await unlink(`${file}.${process.pid}.tmp`).catch(() => {}); });
    return writing;
  };
  /// The storage of one light client: its key is kept under `scope`.
  const scope = (name) => ({
    async getItem(key) { return (await load())[`${name}:${key}`] ?? null; },
    async setItem(key, value) { (await load())[`${name}:${key}`] = value; dirty = true; if (now() - written >= everyMs) await flush(); },
  });
  return { scope, flush: () => flush() };
}

/// The directory a service's files are in, for its README: the three names it ever writes.
export const FILES = Object.freeze({ subscriptions: 'subscriptions.json', vapid: 'vapid.json', checkpoint: 'checkpoint.json' });
export const fileOf = (directory, name) => path.join(directory, FILES[name]);
