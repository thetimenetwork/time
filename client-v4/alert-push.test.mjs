// The alert service (alert-push.mjs, deploy/alerts/start.mjs): the encryption of RFC 8291 against the example of
// its Appendix A, a round trip where this test plays the browser, VAPID (RFC 8292), the allowlist of push services,
// the proof that subscribes a browser, the cap of 8, removal on 404 and 410, who is woken by which block, the
// verification of a block against a light client, and what the service writes. The findings of the audit of
// 24 November 2026 (D-2, D-5, D-6, D-7, K-2, K-3) are in alert-push-audit.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createECDH, createDecipheriv, createPublicKey, generateKeyPairSync, hkdfSync, randomBytes, sign, verify } from 'node:crypto';
import { readFile, readdir, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import http from 'node:http';
import path from 'node:path';
import './time-sdk.js';
import * as installedVerifier from './proof-verifier.mjs';
import { createLightClient } from './light-client.mjs';
import { fetchLightBlock } from './certified-view.mjs';
import { IndexerError } from './indexer.mjs';
import * as A from './alert-push.mjs';
import { validateConfig, start, vapidOf } from '../deploy/alerts/start.mjs';

const SDK = globalThis.TimeSDK;
const NETWORK = 'c6'.repeat(32), CHAIN = 'time-devnet-v4-alerts-test', ORIGIN = 'https://wallet.example';
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const b = (text) => Buffer.from(text, 'base64url');

// ------------------------------------------------------------------ RFC 8291
// The values of the example of RFC 8291 (Section 5) and of its Appendix A, read from the text of the RFC as
// rfc-editor.org publishes it (https://www.rfc-editor.org/rfc/rfc8291.txt) by a script that joined the wrapped lines:
// none of them was typed by hand.
const RFC8291 = Object.freeze({
  plaintext: 'V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24',
  as_public: 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  as_private: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  ua_public: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  ua_private: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  auth_secret: 'BTBZMqHH6r4Tts7J_aSIgg',
  ecdh_secret: 'kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs',
  prk_key: 'Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k',
  key_info: 'V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0EwbZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP',
  ikm: 'S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg',
  prk: '09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc',
  cek_info: 'Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA',
  cek: 'oIhVW04MRdy2XN9CiKLxTg',
  nonce_info: 'Q29udGVudC1FbmNvZGluZzogbm9uY2UA',
  nonce: '4h_95klXJ5E_qnoN',
  header: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  padded: 'V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C',
  ciphertext: '8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ',
  body: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
});

/// What a browser does with a push message (RFC 8188 and RFC 8291), written here apart from the module.
function browserOpens(body, { ecdh, auth }) {
  const salt = body.subarray(0, 16), size = body.readUInt32BE(16), idlen = body[20], asPublic = body.subarray(21, 21 + idlen), sealed = body.subarray(21 + idlen);
  assert.ok(size >= 18 && sealed.length <= size);
  const uaPublic = ecdh.getPublicKey();
  const ikm = Buffer.from(hkdfSync('sha256', ecdh.computeSecret(asPublic), auth, Buffer.concat([Buffer.from('WebPush: info\0'), uaPublic, asPublic]), 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16)), nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const decipher = createDecipheriv('aes-128-gcm', cek, nonce);
  decipher.setAuthTag(sealed.subarray(-16));
  const padded = Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
  let end = padded.length - 1; while (end >= 0 && padded[end] === 0) end -= 1;
  assert.equal(padded[end], 2, 'the delimiter of the last record');
  return padded.subarray(0, end);
}
function newBrowser() { const ecdh = createECDH('prime256v1'); ecdh.generateKeys(); return { ecdh, auth: randomBytes(16) }; }
const subscriptionOf = (browser, endpoint) => ({ endpoint, expirationTime: null, keys: { p256dh: A.b64url(browser.ecdh.getPublicKey()), auth: A.b64url(browser.auth) } });

test('encryption: the example of RFC 8291, value by value, to the byte', () => {
  const s = A.pushSecrets({ uaPublic: b(RFC8291.ua_public), authSecret: b(RFC8291.auth_secret), asPrivate: b(RFC8291.as_private), salt: b(RFC8291.salt) });
  assert.equal(A.b64url(s.asPublic), RFC8291.as_public);
  assert.equal(A.b64url(s.ecdhSecret), RFC8291.ecdh_secret);
  assert.equal(A.b64url(s.ikm), RFC8291.ikm);
  assert.equal(A.b64url(s.cek), RFC8291.cek);
  assert.equal(A.b64url(s.nonce), RFC8291.nonce);
  // The strings the RFC shows are the module's.
  assert.equal(A.b64url(Buffer.from('Content-Encoding: aes128gcm\0')), RFC8291.cek_info);
  assert.equal(A.b64url(Buffer.from('Content-Encoding: nonce\0')), RFC8291.nonce_info);
  assert.equal(A.b64url(Buffer.concat([Buffer.from('WebPush: info\0'), b(RFC8291.ua_public), b(RFC8291.as_public)])), RFC8291.key_info);
  const body = A.encryptPush({ payload: b(RFC8291.plaintext), uaPublic: b(RFC8291.ua_public), authSecret: b(RFC8291.auth_secret), asPrivate: b(RFC8291.as_private), salt: b(RFC8291.salt) });
  assert.equal(A.b64url(body.subarray(0, 86)), RFC8291.header);
  assert.equal(A.b64url(body.subarray(86)), RFC8291.ciphertext);
  assert.equal(A.b64url(body), RFC8291.body);
  // The receiver of the example opens it with its own private key.
  const receiver = createECDH('prime256v1'); receiver.setPrivateKey(b(RFC8291.ua_private));
  assert.equal(browserOpens(body, { ecdh: receiver, auth: b(RFC8291.auth_secret) }).toString(), 'When I grow up, I want to be a watermelon');
  assert.equal(A.b64url(Buffer.concat([b(RFC8291.plaintext), Buffer.from([2])])), RFC8291.padded);
});

test('encryption: a round trip where this test is the browser, and the payload is always the same constant', () => {
  const browser = newBrowser();
  const one = A.encryptPush({ uaPublic: browser.ecdh.getPublicKey(), authSecret: browser.auth }), two = A.encryptPush({ uaPublic: browser.ecdh.getPublicKey(), authSecret: browser.auth });
  assert.equal(browserOpens(one, browser).toString(), '{"v":1}');
  assert.equal(browserOpens(two, browser).toString(), '{"v":1}');
  assert.equal(A.PAYLOAD.toString(), '{"v":1}');
  // A new salt and key for every message: two messages share nothing an observer could link.
  assert.notDeepEqual(one.subarray(0, 86), two.subarray(0, 86));
  // Another browser cannot open it.
  assert.throws(() => browserOpens(one, newBrowser()));
  // A key that is not a point of P-256 is refused before anything is sent.
  assert.throws(() => A.encryptPush({ uaPublic: Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)]), authSecret: browser.auth }));
});

test('VAPID: an ES256 token for the origin of the push service, a day at most, with the operator\'s contact, and the key that signed it', () => {
  const keys = { version: 1, ...A.newVapidKeys() }, vapid = A.checkVapid(keys);
  const endpoint = 'https://fcm.googleapis.com/fcm/send/abc:def';
  const header = A.vapidHeader({ endpoint, vapid, subject: ORIGIN, nowSeconds: 1800000000 });
  const match = /^vapid t=([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+), k=([A-Za-z0-9_-]+)$/.exec(header);
  assert.ok(match, header);
  assert.deepEqual(JSON.parse(b(match[1])), { typ: 'JWT', alg: 'ES256' });
  assert.deepEqual(JSON.parse(b(match[2])), { aud: 'https://fcm.googleapis.com', exp: 1800000000 + 12 * 3600, sub: ORIGIN });
  assert.equal(match[4], keys.public_key);
  const point = b(match[4]);
  assert.deepEqual([point.length, point[0]], [65, 4]);
  const publicKey = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: A.b64url(point.subarray(1, 33)), y: A.b64url(point.subarray(33)) }, format: 'jwk' });
  assert.ok(verify('sha256', Buffer.from(`${match[1]}.${match[2]}`), { key: publicKey, dsaEncoding: 'ieee-p1363' }, b(match[3])));
  assert.throws(() => A.vapidHeader({ endpoint, vapid, subject: ORIGIN, seconds: 86401 }), /a day at most/);
  // A key file whose public key is not that of its private key is not taken.
  assert.throws(() => A.checkVapid({ ...keys, public_key: A.newVapidKeys().public_key }), /not a key of this service/);
  assert.throws(() => A.checkVapid({ ...keys, extra: 1 }), /not a key of this service/);
});

test('the endpoint is https on a host of a known push service, written as browsers write it, or it is refused', () => {
  for (const good of ['https://fcm.googleapis.com/fcm/send/dXk:APA91bH', 'https://updates.push.services.mozilla.com/wpush/v2/gAAAAAB', 'https://web.push.apple.com/QGuQyavXutnMH', 'https://wns2-par02p.notify.windows.com/w/?token=BQYAAAB'])
    assert.equal(A.checkEndpoint(good).href, good, good);
  for (const bad of [
    'http://fcm.googleapis.com/fcm/send/x', 'https://fcm.googleapis.com:8443/fcm/send/x', ['https://user', 'fcm.googleapis.com/fcm/send/x'].join('@'), 'https://fcm.googleapis.com/', 'https://fcm.googleapis.com',
    'https://fcm.googleapis.com.attacker.example/x', 'https://attacker.example/fcm.googleapis.com', 'https://evilpush.apple.com/x', 'https://push.apple.com/x', 'https://a.push.apple.com.attacker.example/x',
    'https://android.googleapis.com/gcm/send/x', 'https://127.0.0.1/x', 'https://[::1]/x', 'https://169.254.169.254/latest', 'https://FCM.googleapis.com/fcm/send/x', 'https://fcm.googleapis.com/fcm/send/x#y',
    'https://fcm.googleapis.com./x', 'https://xn--fcm.googleapis.com.attacker.example/x', `https://fcm.googleapis.com/${'a'.repeat(1100)}`, 'file:///etc/passwd', '', null, 42,
  ]) assert.throws(() => A.checkEndpoint(bad), /not the address of a browser push service/, String(bad).slice(0, 60));
});

test('a subscription is checked as a browser gives it: keys on the curve, nothing kept but endpoint and keys', () => {
  const browser = newBrowser(), good = subscriptionOf(browser, 'https://web.push.apple.com/abc');
  assert.deepEqual(A.checkSubscription(good), { endpoint: good.endpoint, p256dh: good.keys.p256dh, auth: good.keys.auth });
  const refuse = (value) => assert.throws(() => A.checkSubscription(value), undefined, JSON.stringify(value).slice(0, 80));
  refuse({ ...good, keys: { ...good.keys, p256dh: A.b64url(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)])) } });
  refuse({ ...good, keys: { ...good.keys, p256dh: `${good.keys.p256dh}=` } });
  refuse({ ...good, keys: { ...good.keys, auth: A.b64url(randomBytes(15)) } });
  refuse({ ...good, keys: { ...good.keys, extra: 'x' } });
  refuse({ ...good, other: 1 });
  refuse({ ...good, endpoint: 'https://attacker.example/abc' });
  refuse(null);
});

// ------------------------------------------------------------------ the service
const ed = () => { const { privateKey, publicKey } = generateKeyPairSync('ed25519'); return { privateKey, publicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex') }; };
const KEYS = { signin: ed(), spend: ed(), sheet: ed(), other: ed() };
const device = (k, role) => ({ public_key: k.publicKey, can_manage: role === 'recover', can_spend: role === 'spend' });
const ACCOUNT = { id: '5', name: 'alice', balance: '1000000', nonce: '3', auth_epoch: '2', recovery_policy: null, devices: [device(KEYS.signin, 'signin'), device(KEYS.spend, 'spend'), device(KEYS.sheet, 'recover')].sort((x, y) => (x.public_key < y.public_key ? -1 : 1)) };
const ROW = { account: '5', version: '1', policy: { threshold: '1', daily_limit_micros: '1000', delay_seconds: '60', freeze_seconds: '60' }, allowance_micros: '0', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
/// Verified reads of the account, as the SDK's verifying client gives them.
const chainState = (overrides = {}) => async (selection) => ({ verified: true, state: { network_id: NETWORK, height: '10', time_micros: '1000000000', genesis: { genesis_time_micros: '0' }, config: {}, accounts: [{ ...ACCOUNT, ...overrides.account }], recovery_cases: [], ...(selection.include_security ? { security: [{ ...ROW, ...overrides.row }] } : {}) } });
/// A node with synthetic blocks: `chain.blocks[h]` is the list of actions (bytes) of block h.
const fakeRpc = (chain) => async (method, parameters = {}) => {
  if (method === '/status') return { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(chain.tip) } };
  if (method === '/block') return { block: { header: { height: parameters.height, chain_id: CHAIN }, data: { txs: (chain.blocks[parameters.height] ?? []).map((raw) => Buffer.from(raw).toString('base64')) } } };
  throw new IndexerError('RPC_REFUSED', 'not here');
};
const action = (kind, payload, from = '5') => SDK.concat(SDK.buildAction({ networkId: NETWORK, kind, from, nonce: '0', authEpoch: '0', publicKey: KEYS.spend.publicKey, payload }), new Uint8Array(64));
const FREEZE = action(72, { freezes: '0', version: '1', expires_elapsed_micros: '99' }), LIMIT = action(77, { daily_limit_micros: '5' });
const PAY_TO_5 = action(3, { to: '5', amount: '10' }, '7'), PAY_FROM_5 = action(3, { to: '7', amount: '10' });

async function lab(run, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-alerts-'));
  const pushes = [], verified = [], logs = [], chain = { tip: 3, blocks: {} };
  const ctx = { directory, pushes, verified, logs, chain, offset: 0 };
  let service;
  try {
    const subscriptions = await A.openSubscriptions({ file: path.join(directory, 'subscriptions.json'), networkId: NETWORK });
    service = await A.createAlertService({
      rpc: fakeRpc(chain), trust: { network_id: NETWORK, chain_id: CHAIN }, verifiedState: chainState(options.state), origin: ORIGIN, subscriptions, vapid: A.checkVapid({ version: 1, ...A.newVapidKeys() }), subject: ORIGIN,
      port: 0, autoStart: false, now: () => Date.now() + ctx.offset, log: (level, message, fields) => logs.push(JSON.stringify({ level, message, ...fields })),
      verify: async ({ height }) => { verified.push(height); if (options.refuse) throw new Error('not verified'); },
      fetcher: async (url, init) => { pushes.push({ url, init }); return new Response(null, { status: 201 }); },
      ...options.service,
    });
    ctx.service = service;
    await run(ctx);
  } finally { await service?.close(); await rm(directory, { recursive: true, force: true }); }
}
async function call(service, method, route, body, headers = {}) {
  const response = await fetch(service.url + route, { method, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  const text = await response.text();
  let json = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, body: json, text };
}
/// What the wallet page does: a challenge bound to the request, signed with a key of the account.
async function prove(service, request, key = KEYS.signin, tamper = (message) => message) {
  const challenge = (await call(service, 'POST', '/alerts/v1/challenge', request)).body;
  const message = tamper(SDK.loginMessage(challenge, { account: ACCOUNT, publicKey: key.publicKey }));
  return { challenge, proof: { message, signature: sign(null, SDK.loginBytes(message), key.privateKey).toString('hex') } };
}
async function subscribe(service, browser, endpoint, key) {
  const subscription = subscriptionOf(browser, endpoint);
  const { proof } = await prove(service, { action: 'subscribe', subscription }, key);
  return call(service, 'POST', '/alerts/v1/subscribe', { proof, subscription });
}

test('subscribing: the account\'s sign-in key proves it, against a verified read; any other key, a replay, an expired or a moved proof is refused', async () => {
  await lab(async (ctx) => {
    const { service, directory } = ctx;
    const browser = newBrowser(), endpoint = 'https://web.push.apple.com/first';
    const key = await call(service, 'GET', '/alerts/v1/key');
    assert.match(key.body.public_key, /^B[A-Za-z0-9_-]{86}$/);
    const done = await subscribe(service, browser, endpoint);
    assert.deepEqual([done.status, done.body], [200, { subscribed: true, account: '5' }]);
    assert.equal((await call(service, 'GET', '/alerts/v1/health')).body.subscriptions, 1);
    // The payment key, a recovery key and a key that is not the account's are refused: only the sign-in key subscribes.
    for (const [who, words] of [[KEYS.spend, /sign in with a sign-in key/], [KEYS.sheet, /sign in with a sign-in key/], [KEYS.other, /Device authority changed or revoked/]]) {
      const refused = await subscribe(service, browser, 'https://web.push.apple.com/second', who);
      assert.equal(refused.status, 403); assert.match(refused.body.error, words);
    }
    // The same proof twice: the challenge was used.
    const subscription = subscriptionOf(browser, 'https://web.push.apple.com/third');
    const { proof } = await prove(service, { action: 'subscribe', subscription });
    assert.equal((await call(service, 'POST', '/alerts/v1/subscribe', { proof, subscription })).status, 200);
    const replay = await call(service, 'POST', '/alerts/v1/subscribe', { proof, subscription });
    assert.equal(replay.status, 403); assert.match(replay.body.error, /expired or was used already/);
    // A proof made for one browser does not subscribe another.
    const other = subscriptionOf(newBrowser(), 'https://web.push.apple.com/fourth');
    const moved = await call(service, 'POST', '/alerts/v1/subscribe', { proof: (await prove(service, { action: 'subscribe', subscription })).proof, subscription: other });
    assert.equal(moved.status, 403); assert.match(moved.body.error, /made for another request/);
    // A proof that names another origin than the one asked for, or another network, is refused.
    for (const tamper of [(m) => ({ ...m, origin: 'https://shop.example' }), (m) => ({ ...m, networkId: 'd7'.repeat(32) })]) {
      const changed = await prove(service, { action: 'subscribe', subscription: other }, KEYS.signin, tamper);
      const answer = await call(service, 'POST', '/alerts/v1/subscribe', { proof: changed.proof, subscription: other });
      assert.equal(answer.status, 403); assert.match(answer.body.error, /binding mismatch/);
    }
    // An expired challenge is refused.
    const late = await prove(service, { action: 'subscribe', subscription: other });
    ctx.offset = 181000; // 3 minutes and a second later
    const expired = await call(service, 'POST', '/alerts/v1/subscribe', { proof: late.proof, subscription: other });
    assert.equal(expired.status, 403);
    // The file holds the two browsers that were proven, and nothing else.
    const saved = JSON.parse(await readFile(path.join(directory, 'subscriptions.json'), 'utf8'));
    assert.deepEqual(Object.keys(saved).sort(), ['network_id', 'subscriptions', 'version']);
    assert.deepEqual(saved.subscriptions.map((s) => [s.account, s.endpoint, Object.keys(s).sort().join(',')]), [['5', endpoint, 'account,auth,created,endpoint,p256dh'], ['5', 'https://web.push.apple.com/third', 'account,auth,created,endpoint,p256dh']]);
  });
});

test('subscribing is refused while the account is frozen, as a sign-in is', async () => {
  await lab(async ({ service }) => {
    const refused = await subscribe(service, newBrowser(), 'https://web.push.apple.com/frozen');
    assert.equal(refused.status, 403); assert.match(refused.body.error, /frozen/);
  }, { state: { row: { frozen_until_elapsed_micros: '99999999999' } } });
});

test('at most 8 browsers per account: a ninth is refused with {"error":"full"} and nothing is pushed out; the same browser again is renewed', async () => {
  await lab(async ({ service }) => {
    const browsers = Array.from({ length: 9 }, () => newBrowser());
    for (const [i, browser] of browsers.slice(0, 8).entries()) assert.equal((await subscribe(service, browser, `https://web.push.apple.com/b${i}`)).status, 200);
    const ninth = await subscribe(service, browsers[8], 'https://web.push.apple.com/b8');
    assert.deepEqual([ninth.status, ninth.text], [409, '{"error":"full"}']);
    assert.deepEqual(service.subscriptions.of('5').map((s) => s.endpoint), Array.from({ length: 8 }, (_, i) => `https://web.push.apple.com/b${i}`));
    assert.equal((await subscribe(service, browsers[3], 'https://web.push.apple.com/b3')).status, 200);
    assert.equal(service.subscriptions.of('5').length, 8);
    assert.equal(service.subscriptions.of('5').at(-1).endpoint, 'https://web.push.apple.com/b3');
  });
});

test('unsubscribing: with the endpoint alone (that browser), or with the proof (every browser of the account)', async () => {
  await lab(async ({ service }) => {
    for (const i of [1, 2, 3]) await subscribe(service, newBrowser(), `https://web.push.apple.com/u${i}`);
    assert.deepEqual((await call(service, 'POST', '/alerts/v1/unsubscribe', { endpoint: 'https://web.push.apple.com/u2' })).body, { removed: 1 });
    assert.deepEqual((await call(service, 'POST', '/alerts/v1/unsubscribe', { endpoint: 'https://web.push.apple.com/u2' })).body, { removed: 0 });
    assert.equal((await call(service, 'POST', '/alerts/v1/unsubscribe', { endpoint: 'https://attacker.example/u1' })).status, 400);
    const { proof } = await prove(service, { action: 'unsubscribe' });
    assert.deepEqual((await call(service, 'POST', '/alerts/v1/unsubscribe', { proof })).body, { removed: 2 });
    assert.equal(service.subscriptions.counts().subscriptions, 0);
    // A proof made to subscribe does not unsubscribe.
    const subscription = subscriptionOf(newBrowser(), 'https://web.push.apple.com/u4');
    const made = await prove(service, { action: 'subscribe', subscription });
    assert.equal((await call(service, 'POST', '/alerts/v1/unsubscribe', { proof: made.proof })).status, 403);
  });
});

test('requests: from the wallet\'s own pages, under its names, small, on the routes it has, within the rate limit', async () => {
  await lab(async ({ service }) => {
    assert.equal((await call(service, 'GET', '/alerts/v1/key', undefined, { Origin: 'https://attacker.example' })).status, 403);
    assert.equal((await call(service, 'GET', '/alerts/v1/key', undefined, { Origin: ORIGIN })).status, 200);
    // Host is a header fetch will not let a caller set: asked with node:http.
    const withHost = (name) => new Promise((resolve, reject) => { const u = new URL(service.url); http.get({ host: u.hostname, port: u.port, path: '/alerts/v1/key', headers: { Host: name } }, (r) => { r.resume(); resolve(r.statusCode); }).on('error', reject); });
    assert.equal(await withHost('attacker.example'), 421);
    assert.equal(await withHost('wallet.example'), 200);
    assert.equal((await call(service, 'GET', '/alerts/v1/nothing')).status, 404);
    assert.equal((await call(service, 'GET', '/alerts/v1/key?x=1')).status, 404);
    assert.equal((await call(service, 'GET', '/alerts/v1/subscribe')).status, 405);
    assert.equal((await call(service, 'POST', '/alerts/v1/challenge', { action: 'subscribe', subscription: { endpoint: 'https://attacker.example/x', keys: {} } })).status, 400);
    assert.equal((await call(service, 'POST', '/alerts/v1/challenge', { action: 'other' })).status, 400);
    assert.equal((await call(service, 'POST', '/alerts/v1/challenge', 'x'.repeat(A.MAX_BODY_BYTES + 1))).status, 413);
    assert.equal((await call(service, 'POST', '/alerts/v1/challenge', 'not json')).status, 400);
    assert.equal((await fetch(`${service.url}/alerts/v1/challenge`, { method: 'POST', body: '{}', headers: { 'Content-Type': 'text/plain' } })).status, 415);
    // A challenge given out keeps nothing in the service (D-5): only a used one is remembered, until it expires.
    for (let i = 0; i < 9; i++) assert.equal((await call(service, 'POST', '/alerts/v1/challenge', { action: 'unsubscribe' })).status, 200);
    assert.equal(service.challenges.used(), 0);
    let limited = 0;
    for (let i = 0; i < 40; i++) if ((await call(service, 'GET', '/alerts/v1/health')).status === 429) limited += 1;
    assert.ok(limited > 0, 'the rate limit holds');
  }, { service: { rateLimit: { perSecond: 1, burst: 20 } } });
});

test('who is woken: a browser of the account, once per block, for an action of its own keys; never for a payment, never without a subscription', async () => {
  await lab(async ({ service, pushes, verified, chain, logs }) => {
    const mine = newBrowser(), shared = newBrowser();
    await subscribe(service, mine, 'https://fcm.googleapis.com/fcm/send/mine');
    await subscribe(service, shared, 'https://updates.push.services.mozilla.com/wpush/v2/shared');
    // A payment to the account and one from it: nobody is woken, and the block is not even verified.
    chain.blocks[4] = [PAY_TO_5, PAY_FROM_5];
    assert.equal(await service.readBlock(4), undefined);
    // An account with no subscription is woken by its freeze: it costs nothing.
    chain.blocks[5] = [action(72, { freezes: '0', version: '1', expires_elapsed_micros: '99' }, '6')];
    assert.equal(await service.readBlock(5), undefined);
    assert.deepEqual([pushes.length, verified], [0, []]);
    // A freeze and a change of the limit in one block: one push to each browser, after the block is verified.
    chain.blocks[6] = [FREEZE, LIMIT, PAY_TO_5];
    await (await service.readBlock(6)).pushes;
    assert.deepEqual(verified, [6]);
    assert.deepEqual(pushes.map((p) => p.url).sort(), ['https://fcm.googleapis.com/fcm/send/mine', 'https://updates.push.services.mozilla.com/wpush/v2/shared']);
    const push = pushes.find((p) => p.url.endsWith('/mine'));
    assert.equal(browserOpens(Buffer.from(push.init.body), mine).toString(), '{"v":1}');
    assert.equal(push.init.method, 'POST'); assert.equal(push.init.redirect, 'error'); assert.ok(push.init.signal instanceof AbortSignal);
    assert.deepEqual([push.init.headers['Content-Encoding'], push.init.headers.TTL, push.init.headers.Urgency, push.init.headers.Topic], ['aes128gcm', '43200', 'high', 'account']);
    assert.match(push.init.headers.Authorization, /^vapid t=[^,]+, k=B/);
    // A guardian's approval wakes the account it names, not the guardian.
    pushes.length = 0;
    chain.blocks[7] = [action(13, { target: '5', policy_version: '1', recovery_id: 'ab'.repeat(32), new_public_key: 'cd'.repeat(32), expires_elapsed_micros: '100', proof: 'ef'.repeat(64) }, '9')];
    await (await service.readBlock(7)).pushes;
    assert.equal(pushes.length, 2);
    // Nothing of a browser is ever in the log.
    for (const line of logs) assert.ok(!/fcm\.googleapis|mozilla|apple|p256dh|"auth"/.test(line), line);
  });
});

test('a block that is not verified wakes nobody; a push that fails is not sent again; 404 and 410 remove the browser', async () => {
  await lab(async ({ service, pushes, chain }) => {
    await subscribe(service, newBrowser(), 'https://web.push.apple.com/x');
    chain.blocks[4] = [FREEZE];
    assert.equal(await service.readBlock(4), undefined);
    assert.equal(pushes.length, 0);
    assert.equal(service.stats.blocks_refused, 1);
  }, { refuse: true });
  // The answer of each push service, one call each and no retry.
  const answers = { gone: 410, missing: 404, busy: 503, fine: 201 };
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-alerts-'));
  const calls = [];
  const subscriptions = await A.openSubscriptions({ file: path.join(directory, 'subscriptions.json'), networkId: NETWORK });
  const chain = { tip: 3, blocks: { 4: [FREEZE] } };
  const service = await A.createAlertService({ rpc: fakeRpc(chain), trust: { network_id: NETWORK, chain_id: CHAIN }, verifiedState: chainState(), origin: ORIGIN, subscriptions, vapid: A.checkVapid({ version: 1, ...A.newVapidKeys() }), subject: ORIGIN, port: 0, autoStart: false, verify: async () => {},
    fetcher: async (url) => { calls.push(url); return new Response(null, { status: answers[url.split('/').at(-1)] }); } });
  try {
    for (const name of Object.keys(answers)) assert.equal((await subscribe(service, newBrowser(), `https://web.push.apple.com/${name}`)).status, 200);
    await (await service.readBlock(4)).pushes;
    assert.equal(calls.length, 4);
    assert.deepEqual(service.subscriptions.of('5').map((s) => s.endpoint.split('/').at(-1)), ['busy', 'fine']);
    assert.deepEqual([service.stats.pushes_sent, service.stats.pushes_failed, service.stats.subscriptions_gone], [1, 1, 2]);
    await service.subscriptions.settled();
    assert.deepEqual(JSON.parse(await readFile(path.join(directory, 'subscriptions.json'), 'utf8')).subscriptions.map((s) => s.endpoint.split('/').at(-1)), ['busy', 'fine']);
    // A push service that does not answer in time is given up, and nothing waits for it.
    const slow = await A.createAlertService({ rpc: fakeRpc(chain), trust: { network_id: NETWORK, chain_id: CHAIN }, verifiedState: chainState(), origin: ORIGIN, subscriptions, vapid: A.checkVapid({ version: 1, ...A.newVapidKeys() }), subject: ORIGIN, port: 0, autoStart: false, verify: async () => {}, pushTimeoutMs: 50,
      fetcher: (url, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason))) });
    try {
      const started = Date.now();
      await (await slow.readBlock(4)).pushes;
      assert.ok(Date.now() - started < 2000);
      assert.equal(slow.stats.pushes_failed, 2);
    } finally { await slow.close(); }
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});

test('following the chain: from the newest block at start, then every block in order, however far behind; never a block left out', async () => {
  await lab(async ({ service, pushes, chain, logs }) => {
    await subscribe(service, newBrowser(), 'https://web.push.apple.com/f');
    chain.blocks[2] = [FREEZE]; // before the service looked: never sent
    chain.tip = 4; await service.step();
    assert.equal(pushes.length, 0);
    chain.blocks[3] = [FREEZE]; chain.tip = 5; await service.step(); await pause(20);
    assert.equal(pushes.length, 1);
    // A block is read once two more exist: block 4 waits for block 6.
    chain.blocks[4] = [FREEZE]; await service.step(); await pause(20);
    assert.equal(pushes.length, 1);
    chain.tip = 6; await service.step(); await pause(20);
    assert.equal(pushes.length, 2);
    // Far behind (a slow node, a stalled service, or an attacker who makes it verify many blocks): it reads every block
    // in order and catches up. A theft in block 300 is not left out, and the log says the service is behind.
    chain.blocks[300] = [FREEZE]; chain.tip = 500; await service.step(); await pause(20);
    assert.equal(service.stats.blocks_read, 498 - 2);
    assert.equal(pushes.length, 3);
    assert.ok(logs.some((line) => JSON.parse(line).message.startsWith('the service is behind the chain') && JSON.parse(line).behind === 494), logs.join('\n'));
    assert.equal('blocks_skipped' in service.stats, false);
  }, { service: { warnBehind: 100 } });
});

test('a block is verified against the light client: its header is the one the next verified header names, its actions are committed and succeeded', async () => {
  const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
  const tip = fixture.blocks.length, at = (h) => fixture.blocks[Number(h) - 1];
  const rpc = async (method, p = {}) => {
    if (method === '/commit') return { signed_header: at(p.height ?? tip).signed_header };
    if (method === '/validators') { const h = Number(p.height); return { block_height: p.height, total: '4', validators: h <= tip ? at(h).validators : at(tip).next_validators }; }
    throw new IndexerError('RPC_REFUSED', 'not here');
  };
  const light = createLightClient({ trust: fixture.trust, verifier: installedVerifier, now: () => fixture.now_ms, fetchBlock: (height) => fetchLightBlock({ rpc, height }) });
  const block = (h, txs = fixture.txs[h]) => ({ block: { header: at(h).signed_header.header, data: { txs } } });
  const raws = await A.verifyBlock({ light, block: block(2), height: 2, chainId: fixture.trust.chain_id });
  assert.equal(raws.length, 2);
  await assert.rejects(A.verifyBlock({ light, block: block(2, [fixture.txs[2][0]]), height: 2, chainId: fixture.trust.chain_id }), /not the ones the block commits to/);
  await assert.rejects(A.verifyBlock({ light, block: block(2), height: 3, chainId: fixture.trust.chain_id }), /another block/);
  await assert.rejects(A.verifyBlock({ light, block: block(1), height: 2, chainId: fixture.trust.chain_id }), /another block/);
  await assert.rejects(A.verifyBlock({ light, block: block(2), height: 2, chainId: 'time-devnet-v4-other' }), /another block/);
});

test('the process: its config, and what it writes: the address list, its key and the checkpoint, nothing else', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-alerts-start-'));
  const trust = { app_version: '4', network_id: NETWORK, chain_id: CHAIN };
  const good = { rpc_url: 'http://127.0.0.1:26657/', trust, data_directory: directory, origin: ORIGIN };
  try {
    assert.deepEqual({ ...validateConfig(good), trust: undefined, data_directory: undefined }, { rpc_url: 'http://127.0.0.1:26657/', trust: undefined, data_directory: undefined, origin: ORIGIN, hosts: [], host: '127.0.0.1', port: 8950, trusted_proxies: [], contact: ORIGIN, rate_limit: { per_second: 2, burst: 30 }, rpc_timeout_seconds: 10, max_subscriptions: 50000 });
    const example = JSON.parse(await readFile(new URL('../deploy/alerts/config.example.json', import.meta.url), 'utf8'));
    assert.doesNotThrow(() => validateConfig({ ...example, trust }));
    const SECRET = 'super-secret-value-0123456789';
    for (const bad of [{ ...good, extra: 1 }, { ...good, rpc_url: `http://u:${SECRET}@127.0.0.1:26657/` }, { ...good, rpc_url: 'http://rpc.example:26657/' }, { ...good, origin: 'https://wallet.example/' }, { ...good, origin: 'http://wallet.example' },
      { ...good, origin: SECRET }, { ...good, contact: `mailto:${SECRET}` }, { ...good, data_directory: 'relative' }, { ...good, trusted_proxies: ['proxy.example'] }, { ...good, hosts: ['Wallet.example'] }, { ...good, port: 80 }, { ...good, max_subscriptions: 0 }])
      assert.throws(() => validateConfig(bad), (error) => !error.message.includes(SECRET));
    const logs = [], chain = { tip: 3, blocks: { 4: [FREEZE] } }, pushed = [];
    const inject = { rpc: fakeRpc(chain), verifiedState: chainState(), verify: async () => {}, light: { updateTo: async () => ({}) }, autoStart: false, log: (level, message, fields) => logs.push(JSON.stringify({ level, message, ...fields })), fetcher: async (url) => { pushed.push(url); return new Response(null, { status: 201 }); } };
    const port = 20000 + Math.floor(Math.random() * 20000);
    const running = await start({ ...good, port }, inject);
    const browser = newBrowser(), endpoint = 'https://web.push.apple.com/kept';
    assert.equal((await subscribe(running.service, browser, endpoint)).status, 200);
    await (await running.service.readBlock(4)).pushes;
    assert.deepEqual(pushed, [endpoint]);
    const publicKey = (await call(running.service, 'GET', '/alerts/v1/key')).body.public_key;
    await running.close();
    // What is left in the directory: the address list and the key. (The checkpoint too, once a light client verified
    // something; here none did.) No event, no queue, no record of what was sent.
    const files = (await readdir(directory)).sort();
    assert.deepEqual(files, ['subscriptions.json', 'vapid.json']);
    const list = JSON.parse(await readFile(path.join(directory, 'subscriptions.json'), 'utf8'));
    assert.deepEqual(list, { version: 1, network_id: NETWORK, subscriptions: [{ account: '5', endpoint, p256dh: A.b64url(browser.ecdh.getPublicKey()), auth: A.b64url(browser.auth), created: list.subscriptions[0].created }] });
    assert.deepEqual(Object.keys(JSON.parse(await readFile(path.join(directory, 'vapid.json'), 'utf8'))).sort(), ['private_jwk', 'public_key', 'version']);
    if (process.platform !== 'win32') for (const name of files) assert.equal((await stat(path.join(directory, name))).mode & 0o777, 0o600, name);
    for (const line of logs) assert.ok(!line.includes(endpoint) && !line.includes(A.b64url(browser.auth)), line);
    // Started again: the same key, the same list.
    const again = await start({ ...good, port }, inject);
    try {
      assert.equal((await call(again.service, 'GET', '/alerts/v1/key')).body.public_key, publicKey);
      assert.equal(again.service.subscriptions.of('5').length, 1);
    } finally { await again.close(); }
    // A list or a key that is damaged, or of another network, stops the start: nothing is guessed.
    await writeFile(path.join(directory, 'subscriptions.json'), '{"version":1,"network_id":"' + 'd7'.repeat(32) + '","subscriptions":[]}');
    await assert.rejects(start({ ...good, port }, inject), /another network/);
    await writeFile(path.join(directory, 'subscriptions.json'), 'not json');
    await assert.rejects(start({ ...good, port }, inject), /damaged/);
    await writeFile(path.join(directory, 'vapid.json'), '{}');
    await assert.rejects(vapidOf(directory), /not a key of this service/);
    // The checkpoint file holds what the light clients gave it, under their scope, and nothing else.
    const checkpoints = A.checkpointFile(path.join(directory, 'checkpoint.json'), { everyMs: 0 });
    await checkpoints.scope('blocks').setItem('timecurrency-v4-checkpoint:x', '{"h":1}');
    assert.deepEqual(JSON.parse(await readFile(path.join(directory, 'checkpoint.json'), 'utf8')), { 'blocks:timecurrency-v4-checkpoint:x': '{"h":1}' });
    assert.equal(await A.checkpointFile(path.join(directory, 'checkpoint.json')).scope('blocks').getItem('timecurrency-v4-checkpoint:x'), '{"h":1}');
  } finally { await rm(directory, { recursive: true, force: true }); }
});
