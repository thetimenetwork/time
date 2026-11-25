// What the wallet page needs to turn alerts on and off for this browser, and to follow its account while it is open.
// Pure where it can be: no page, no storage. The page does the calls (fetch, the service worker, pushManager); this
// module says what to send, checks what comes back, and holds the words.
//
// Turning alerts on, as the page will do it:
//   1. pushSupport() says whether this browser can have them, and if not, why, in words for the owner;
//   2. GET /alerts/v1/key gives the alert service's public key; applicationServerKey() turns it into what
//      pushManager.subscribe({ userVisibleOnly: true, applicationServerKey }) takes;
//   3. POST /alerts/v1/challenge with challengeBody('subscribe', subscriptionOf(pushSubscription));
//   4. proveFor() checks that challenge (a login for THIS wallet's own origin and network, short-lived) and signs it
//      with the account's sign-in key; a challenge for any other origin is refused, so that the alert service can
//      never obtain from this wallet a login to a website;
//   5. POST /alerts/v1/subscribe with { proof, subscription }.
// Turning them off: POST /alerts/v1/unsubscribe with { endpoint } (this browser), then pushSubscription.unsubscribe().
// Whether this browser still has them: POST /alerts/v1/status with { endpoint }, answered 200 { subscribed: true|false }
// (statusBody, readStatus). A service without the route answers 404, and the page then changes nothing.
// While the page is open: an EventSource on touchPath(account); each event is checked by readTouch(), and the page
// then reads its account's state with a proof (alerts.mjs says what that state means). A touch says nothing itself.
import { BUSY_ALERTS } from './busy.mjs';
export const ALERTS_PATH = '/alerts/v1/';
export const TOUCH_PATH = '/v1/touches';
/// How long a challenge of the alert service may live (server-auth.mjs takes three minutes at most).
export const CHALLENGE_MAX_MS = 180000;

/// The sentences of the switch, in plain words.
export const WORDS = Object.freeze({
  title: 'Alerts',
  turnOn: 'Turn on alerts',
  turnOff: 'Turn off alerts',
  on: 'Alerts are on for this browser.',
  off: 'Alerts are off for this browser.',
  // What the panel says while alerts are off for a browser that can have them: why they matter.
  offMatters: 'Alerts are off for this browser. Turn them on to hear at once when someone asks to take over your account, even with the wallet closed.',
  what: 'When the keys or the rules of your account change, or a payment or a change starts to wait on it, this browser shows: "Open your wallet to check your account." It never says more. Open the wallet to see what it is.',
  privacy: 'The alert service keeps the address of this browser and nothing else. It never learns what happened, and it cannot send you any words of its own.',
  offElsewhere: 'Turn off alerts on every browser of this account',
  // Why a browser cannot have them.
  insecure: 'Alerts need the wallet to be opened over a secure connection (https).',
  unsupported: 'This browser cannot show alerts while the wallet is closed. Open the wallet now and then to see what changed.',
  iosHomeScreen: 'On an iPhone or iPad, alerts work only from the Home Screen. In Safari, tap Share, then Add to Home Screen, and open the wallet from there. Then turn alerts on.',
  denied: 'Notifications are blocked for this wallet in this browser\'s settings. Allow them there, then turn alerts on.',
  notOffered: 'This wallet\'s service does not send alerts.',
  needsLogin: 'Unlock the wallet to turn alerts on: it proves with your login key that the account is yours.',
  frozen: 'Alerts cannot be turned on while your account is frozen.',
  failed: 'Alerts could not be turned on in this browser. You can try again; if it keeps failing, this browser cannot receive them.',
  // The service stayed busy (429 or 503, busy.mjs): nothing was changed.
  busy: BUSY_ALERTS,
  // The service refused a ninth browser of the account (409, "full"): it does not push the others out.
  tooMany: 'This account already has alerts on eight browsers. Use “Turn off alerts on every browser of this account”, then turn them on here.',
  // The service no longer has this browser, and this browser did not turn it off (POST /alerts/v1/status).
  removedTitle: 'Alerts were turned off for this browser',
  removed: 'Alerts were turned off for this browser, and this browser did not do it. Someone who can sign in as you can do that. Turn them on again, then make a new login password under Keys.',
});

/// Whether this browser can have alerts, from the window it runs in: { ok, reason, ios }. `reason` is one of the
/// sentences above, or null when it can.
export function pushSupport(win = globalThis) {
  const nav = win?.navigator ?? {};
  const ios = /iPhone|iPad|iPod/.test(String(nav.userAgent ?? '')) || (nav.platform === 'MacIntel' && Number(nav.maxTouchPoints) > 1);
  const standalone = nav.standalone === true || Boolean(win?.matchMedia?.('(display-mode: standalone)')?.matches);
  const answer = (reason) => ({ ok: reason === null, reason, ios });
  if (win?.isSecureContext !== true) return answer(WORDS.insecure);
  // On an iPhone, Safari offers push to a web app that is on the Home Screen only, and shows no PushManager before.
  if (ios && !standalone) return answer(WORDS.iosHomeScreen);
  if (!nav.serviceWorker || typeof win.PushManager !== 'function' || typeof win.Notification !== 'function') return answer(WORDS.unsupported);
  if (win.Notification.permission === 'denied') return answer(WORDS.denied);
  return answer(null);
}

const B64URL = /^[A-Za-z0-9_-]+$/;
function fromB64url(text) {
  if (typeof text !== 'string' || !B64URL.test(text)) return null;
  const base = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  try { return Uint8Array.from(atob(base), (c) => c.charCodeAt(0)); } catch { return null; }
}
/// The alert service's public key (base64url of a P-256 point, as GET /alerts/v1/key gives it) in the form
/// pushManager.subscribe takes as `applicationServerKey`.
export function applicationServerKey(text) {
  const bytes = fromB64url(text);
  if (!bytes || bytes.length !== 65 || bytes[0] !== 4) throw new Error('The alert service gave no key this wallet can use.');
  return bytes;
}

/// What the alert service takes of a browser's subscription: its endpoint and its two keys, from
/// PushSubscription.toJSON() (or that object itself), nothing else.
export function subscriptionOf(subscription) {
  const json = typeof subscription?.toJSON === 'function' ? subscription.toJSON() : subscription;
  const keys = json?.keys;
  if (typeof json?.endpoint !== 'string' || !json.endpoint.startsWith('https://') || !keys || !B64URL.test(String(keys.p256dh)) || !B64URL.test(String(keys.auth))) throw new Error('This browser gave no subscription the alert service can take.');
  return { endpoint: json.endpoint, keys: { p256dh: keys.p256dh, auth: keys.auth } };
}
/// The body of POST /alerts/v1/challenge: a challenge bound to subscribing this browser, or to unsubscribing every
/// browser of the account.
export function challengeBody(action, subscription) {
  if (action === 'subscribe') return { action, subscription: subscriptionOf(subscription) };
  if (action === 'unsubscribe') return { action };
  throw new Error('Unknown action');
}

/// The challenge of the alert service, if it is one this wallet may sign: a login for THIS wallet's own origin and
/// network, with a fresh nonce, living at most three minutes and not yet expired. Throws otherwise, and nothing is
/// signed. The check that matters is the origin: a challenge that names a website would be a login to that website.
export function checkChallenge(challenge, { origin, networkId, nowMs = Date.now() }) {
  const refuse = () => { throw new Error('The alert service asked for something this wallet does not sign. Nothing was signed.'); };
  if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge) || Object.keys(challenge).sort().join(',') !== 'expiresAt,issuedAt,networkId,nonce,origin,purpose') refuse();
  if (challenge.purpose !== 'login' || challenge.origin !== origin || challenge.networkId !== networkId) refuse();
  if (typeof challenge.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(challenge.nonce)) refuse();
  if (!Number.isSafeInteger(challenge.issuedAt) || !Number.isSafeInteger(challenge.expiresAt)) refuse();
  const life = challenge.expiresAt - challenge.issuedAt;
  if (life <= 0 || life > CHALLENGE_MAX_MS || challenge.expiresAt <= nowMs) refuse();
  return challenge;
}
/// The proof for a challenge: checked by checkChallenge, then signed by the account's sign-in key (`key`:
/// { publicKey, privateKey }, a WebCrypto Ed25519 key) with the SDK's login signature. `origin` is the page's own
/// origin (location.origin), `networkId` the network the wallet is on.
export async function proveFor({ sdk, challenge, origin, networkId, account, key, nowMs = Date.now() }) {
  checkChallenge(challenge, { origin, networkId, nowMs });
  return sdk.signLogin(challenge, { account, publicKey: key.publicKey, privateKey: key.privateKey });
}
/// The body of POST /alerts/v1/subscribe.
export const subscribeBody = ({ proof, subscription }) => ({ proof, subscription: subscriptionOf(subscription) });
/// The body of POST /alerts/v1/unsubscribe: this browser by its endpoint, or every browser of the account by a proof.
export function unsubscribeBody({ endpoint, proof }) {
  if ((endpoint === undefined) === (proof === undefined)) throw new Error('Unsubscribe one browser by its endpoint, or every browser by a proof');
  return endpoint === undefined ? { proof } : { endpoint };
}
/// What the page says when the alert service refuses: by its status and words, one of the sentences above.
export function refusalWords(status, error = '') {
  if (status === 404) return WORDS.notOffered;
  if (status === 429 || status === 503) return WORDS.busy;
  if (status === 409 && String(error) === 'full') return WORDS.tooMany;
  if (status === 403 && /frozen/i.test(String(error))) return WORDS.frozen;
  return WORDS.failed;
}

/// The body of POST /alerts/v1/status: this browser, by its push address.
export function statusBody(endpoint) {
  if (typeof endpoint !== 'string' || !endpoint.startsWith('https://') || endpoint.length > 1024) throw new Error('This browser has no push address the alert service can take.');
  return { endpoint };
}
/// What the service said of this browser: true or false, or null for an answer that says neither (a service without the
/// route answers 404; anything that is not 200 with exactly { subscribed: true|false } changes nothing).
export function readStatus(status, body) {
  if (status !== 200 || !body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).join(',') !== 'subscribed' || typeof body.subscribed !== 'boolean') return null;
  return body.subscribed;
}

// ------------------------------------------------------------------ while the page is open
/// Where the page follows its account: GET /v1/touches?account=N on its own origin.
export function touchPath(accountId) {
  if (typeof accountId !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(accountId)) throw new Error('An account is its number');
  return `${TOUCH_PATH}?account=${accountId}`;
}
/// The height of a `touch` event for `accountId` (the event's data, as text or parsed), or null for anything else.
/// It says only that a block at that height named the account: the page then reads the state with a proof.
export function readTouch(data, accountId) {
  let value = data;
  if (typeof data === 'string') { if (data.length > 512) return null; try { value = JSON.parse(data); } catch { return null; } }
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'account,height,proven,source') return null;
  if (value.source !== 'index' || value.proven !== false || value.account !== accountId || typeof value.height !== 'string' || !/^[1-9][0-9]{0,15}$/.test(value.height)) return null;
  return value.height;
}
