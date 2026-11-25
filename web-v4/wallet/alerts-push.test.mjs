// What the page will use to turn alerts on and off (alerts-push.mjs): whether a browser can have them, the key for
// pushManager.subscribe, the challenge it may sign (only one for its own origin), the requests, and the words. The
// last test runs the requests against the alert service itself (client-v4/alert-push.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import '../../client-v4/time-sdk.js';
import * as service from '../../client-v4/alert-push.mjs';
import * as P from './alerts-push.mjs';

const sdk = globalThis.TimeSDK;
const NETWORK = 'c6'.repeat(32), ORIGIN = 'https://wallet.example';

test('the key of the alert service in the form pushManager.subscribe takes, and nothing else', () => {
  const { public_key: key } = service.newVapidKeys();
  const bytes = P.applicationServerKey(key);
  assert.ok(bytes instanceof Uint8Array);
  assert.deepEqual([bytes.length, bytes[0]], [65, 4]);
  assert.equal(Buffer.from(bytes).toString('base64url'), key);
  for (const bad of ['', 'not base64url!', Buffer.alloc(65, 4).toString('base64'), Buffer.alloc(64, 4).toString('base64url'), Buffer.alloc(65, 3).toString('base64url'), null]) assert.throws(() => P.applicationServerKey(bad), /no key this wallet can use/);
});

test('whether a browser can have alerts, and why not in words: secure page, service worker and push, the iPhone\'s Home Screen, blocked notifications', () => {
  const browser = ({ secure = true, ua = 'Mozilla/5.0 (Windows NT 10.0) Chrome/140', platform = 'Win32', touch = 0, standalone, displayStandalone = false, sw = true, push = true, permission = 'default' } = {}) => ({
    isSecureContext: secure, navigator: { userAgent: ua, platform, maxTouchPoints: touch, ...(standalone === undefined ? {} : { standalone }), ...(sw ? { serviceWorker: {} } : {}) },
    matchMedia: (q) => ({ matches: q === '(display-mode: standalone)' && displayStandalone }), ...(push ? { PushManager: function PushManager() {} } : {}), Notification: Object.assign(function Notification() {}, { permission }),
  });
  assert.deepEqual(P.pushSupport(browser()), { ok: true, reason: null, ios: false });
  assert.deepEqual(P.pushSupport(browser({ secure: false })), { ok: false, reason: P.WORDS.insecure, ios: false });
  assert.deepEqual(P.pushSupport(browser({ sw: false })), { ok: false, reason: P.WORDS.unsupported, ios: false });
  assert.deepEqual(P.pushSupport(browser({ push: false })), { ok: false, reason: P.WORDS.unsupported, ios: false });
  assert.deepEqual(P.pushSupport(browser({ permission: 'denied' })), { ok: false, reason: P.WORDS.denied, ios: false });
  // An iPhone in Safari: first to the Home Screen. Installed there, it can.
  const iphone = { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Safari/604.1', platform: 'iPhone', touch: 5 };
  assert.deepEqual(P.pushSupport(browser({ ...iphone, push: false, standalone: false })), { ok: false, reason: P.WORDS.iosHomeScreen, ios: true });
  assert.deepEqual(P.pushSupport(browser({ ...iphone, standalone: true })), { ok: true, reason: null, ios: true });
  assert.deepEqual(P.pushSupport(browser({ ...iphone, displayStandalone: true })), { ok: true, reason: null, ios: true });
  // An iPad says it is a Mac, with a touch screen.
  assert.equal(P.pushSupport(browser({ ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15', platform: 'MacIntel', touch: 5, push: false })).reason, P.WORDS.iosHomeScreen);
  assert.equal(P.pushSupport(browser({ ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15', platform: 'MacIntel', touch: 0 })).ok, true);
  assert.equal(P.pushSupport(undefined).ok, false);
});

const challenge = (extra = {}) => ({ purpose: 'login', origin: ORIGIN, networkId: NETWORK, nonce: 'ab'.repeat(32), issuedAt: 1000, expiresAt: 1000 + 180000, ...extra });
test('the wallet signs only a short login challenge for its own origin and network: never one that names a website', () => {
  assert.deepEqual(P.checkChallenge(challenge(), { origin: ORIGIN, networkId: NETWORK, nowMs: 2000 }), challenge());
  for (const bad of [
    challenge({ origin: 'https://shop.example' }), challenge({ origin: `${ORIGIN}/` }), challenge({ purpose: 'payment' }), challenge({ networkId: 'd7'.repeat(32) }), challenge({ nonce: 'AB'.repeat(32) }),
    challenge({ expiresAt: 1000 + 180001 }), challenge({ expiresAt: 1000 }), challenge({ issuedAt: '1000' }), { ...challenge(), extra: 1 }, (({ nonce, ...rest }) => rest)(challenge()), null, [],
  ]) assert.throws(() => P.checkChallenge(bad, { origin: ORIGIN, networkId: NETWORK, nowMs: 2000 }), /Nothing was signed/, JSON.stringify(bad));
  assert.throws(() => P.checkChallenge(challenge(), { origin: ORIGIN, networkId: NETWORK, nowMs: 1000 + 180000 }), /Nothing was signed/, 'expired');
});

test('the requests: a subscription is its endpoint and two keys, one way to unsubscribe at a time, and the hint of the open page', () => {
  const json = { endpoint: 'https://web.push.apple.com/abc', expirationTime: null, keys: { p256dh: 'BAAA', auth: 'xyz_-' } };
  assert.deepEqual(P.subscriptionOf({ toJSON: () => json }), { endpoint: json.endpoint, keys: { p256dh: 'BAAA', auth: 'xyz_-' } });
  for (const bad of [{ ...json, endpoint: 'http://web.push.apple.com/abc' }, { ...json, keys: { p256dh: 'B+A=', auth: 'x' } }, { endpoint: json.endpoint }, null]) assert.throws(() => P.subscriptionOf(bad), /no subscription/);
  assert.deepEqual(P.challengeBody('subscribe', json), { action: 'subscribe', subscription: { endpoint: json.endpoint, keys: json.keys } });
  assert.deepEqual(P.challengeBody('unsubscribe'), { action: 'unsubscribe' });
  assert.throws(() => P.challengeBody('other'));
  assert.deepEqual(P.unsubscribeBody({ endpoint: json.endpoint }), { endpoint: json.endpoint });
  assert.deepEqual(P.unsubscribeBody({ proof: { x: 1 } }), { proof: { x: 1 } });
  assert.throws(() => P.unsubscribeBody({ endpoint: json.endpoint, proof: {} }));
  assert.throws(() => P.unsubscribeBody({}));
  // A busy service (429 or 503, busy.mjs) has its own words: nothing was changed, and asking later is the answer.
  assert.deepEqual([P.refusalWords(404), P.refusalWords(403, 'The account was not proven: The account is frozen: nobody signs in'), P.refusalWords(500), P.refusalWords(503), P.refusalWords(429)], [P.WORDS.notOffered, P.WORDS.frozen, P.WORDS.failed, P.WORDS.busy, P.WORDS.busy]);
  // The hint while the page is open: exactly the frame of the API, for this account, or nothing.
  assert.equal(P.touchPath('5'), '/v1/touches?account=5');
  assert.throws(() => P.touchPath('05'));
  const frame = { source: 'index', proven: false, account: '5', height: '1234' };
  assert.equal(P.readTouch(JSON.stringify(frame), '5'), '1234');
  assert.equal(P.readTouch(frame, '5'), '1234');
  for (const bad of [{ ...frame, account: '6' }, { ...frame, proven: true }, { ...frame, text: 'Your account was emptied' }, { ...frame, height: '0' }, { ...frame, source: 'state_proof' }, 'not json', 'x'.repeat(600), null])
    assert.equal(P.readTouch(typeof bad === 'string' ? bad : JSON.stringify(bad), '5'), null, JSON.stringify(bad).slice(0, 60));
});

test('the words are plain: no dash, no link', () => {
  for (const [name, words] of Object.entries(P.WORDS)) {
    assert.ok(!/[\u2013\u2014]|https?:\/\/|www\.|<|>/.test(words), name);
    if (!['title', 'turnOn', 'turnOff', 'offElsewhere', 'removedTitle'].includes(name)) assert.match(words, /\.$/, name);
  }
});

test('the page\'s requests against the alert service: subscribed with the login key, refused with another, unsubscribed by the endpoint', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-alerts-page-'));
  const key = async () => { const pair = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']); return { privateKey: pair.privateKey, publicKey: Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('hex') }; };
  const login = await key(), spend = await key();
  const account = { id: '5', name: 'alice', balance: '1', nonce: '1', auth_epoch: '2', recovery_policy: null, devices: [{ public_key: login.publicKey, can_manage: false, can_spend: false }, { public_key: spend.publicKey, can_manage: false, can_spend: true }] };
  const row = { account: '5', version: '1', policy: { threshold: '1', daily_limit_micros: '1000', delay_seconds: '60', freeze_seconds: '60' }, allowance_micros: '0', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: '0', freezes: '0', pending_limit: null, pending_payments: [], next_id: '1', pending_root: null };
  const verifiedState = async (selection) => ({ verified: true, state: { network_id: NETWORK, height: '9', time_micros: '1000000000', genesis: { genesis_time_micros: '0' }, config: {}, accounts: [account], recovery_cases: [], ...(selection.include_security ? { security: [row] } : {}) } });
  const subscriptions = await service.openSubscriptions({ file: path.join(directory, 'subscriptions.json'), networkId: NETWORK });
  const running = await service.createAlertService({ rpc: async () => ({}), trust: { network_id: NETWORK, chain_id: 'time-devnet-v4-page' }, verifiedState, origin: ORIGIN, subscriptions, vapid: service.checkVapid({ version: 1, ...service.newVapidKeys() }), subject: ORIGIN, port: 0, autoStart: false });
  const post = async (route, body) => { const r = await fetch(`${running.url}${P.ALERTS_PATH}${route}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
  try {
    const key64 = (await (await fetch(`${running.url}${P.ALERTS_PATH}key`)).json()).public_key;
    assert.equal(P.applicationServerKey(key64).length, 65);
    // What pushManager.subscribe would give: a browser's key pair and secret.
    const { createECDH, randomBytes } = await import('node:crypto');
    const ecdh = createECDH('prime256v1'); ecdh.generateKeys();
    const given = { endpoint: 'https://fcm.googleapis.com/fcm/send/page-test', expirationTime: null, keys: { p256dh: ecdh.getPublicKey().toString('base64url'), auth: randomBytes(16).toString('base64url') } };
    const pushSubscription = { toJSON: () => given };
    const turnOn = async (signer) => {
      const asked = await post('challenge', P.challengeBody('subscribe', pushSubscription));
      const proof = await P.proveFor({ sdk, challenge: asked.body, origin: ORIGIN, networkId: NETWORK, account, key: signer });
      return post('subscribe', P.subscribeBody({ proof, subscription: pushSubscription }));
    };
    const refused = await turnOn(spend);
    assert.equal(refused.status, 403);
    assert.equal(P.refusalWords(refused.status, refused.body.error), P.WORDS.failed);
    assert.deepEqual(await turnOn(login), { status: 200, body: { subscribed: true, account: '5' } });
    assert.equal(subscriptions.counts().subscriptions, 1);
    assert.deepEqual(await post('unsubscribe', P.unsubscribeBody({ endpoint: P.subscriptionOf(pushSubscription).endpoint })), { status: 200, body: { removed: 1 } });
    assert.equal(subscriptions.counts().subscriptions, 0);
    // A challenge that names another origin is not signed at all.
    await assert.rejects(P.proveFor({ sdk, challenge: { ...challenge(), origin: 'https://shop.example', issuedAt: Date.now(), expiresAt: Date.now() + 60000 }, origin: ORIGIN, networkId: NETWORK, account, key: login }), /Nothing was signed/);
  } finally { await running.close(); await rm(directory, { recursive: true, force: true }); }
});
