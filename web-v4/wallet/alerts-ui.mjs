// The Alerts panel at the top of Home (index.html: #alerts-banner, #alerts-panel): what needs the owner's attention,
// worked out from the state the page has just verified; the hint that keeps it current while the wallet is unlocked;
// and the switch that lets the alert service wake this browser while the wallet is closed.
//
// - What it shows comes from alerts.mjs only: one verified state, and the marker this browser stored when its owner
//   last confirmed. The first time this browser sees an account (no marker), the marker is stored at once and only
//   what is true now is shown. Afterwards only "I have seen these" stores it: nothing is confirmed by itself.
// - The banner shows the first urgent alert the owner has not confirmed yet. "I have seen these" also keeps the ids of
//   the alerts it confirmed, so that a condition that is still true (a payment that still waits) stays in the list,
//   without the banner. Another one, with another id, brings the banner back.
// - Live: while the wallet is unlocked, an EventSource on /v1/touches?account=N (the API's hint, under the wallet's
//   own address). A touch says nothing by itself: it asks for one verified read, at most one every two seconds, and
//   the stream coming back asks for one. Without the stream (a deployment without the route) the page's refresh every
//   five seconds goes on, and nothing is said about it.
// - The switch: whether this browser can have alerts (alerts-push.mjs, pushSupport), whether it has them for this
//   account, and turning them on and off. "On" is said only while the browser holds a push subscription and this
//   browser's record says it gave that subscription to the alert service for this account.
// - Whether the service still has this browser (web audit of November 2026, K-3): the login key alone can remove every
//   subscription of the account. While unlocked, once when the account is opened and then at most once a minute, a
//   browser whose record says alerts are on asks (POST /alerts/v1/status). When the service no longer has it, the record
//   is forgotten, the switch says off, and the panel shows an urgent alert at its top until alerts are on again. A
//   service without the route (404) changes nothing.
// - Actions signed elsewhere (K-4): the panel passes alerts.mjs how many actions this browser sent since the marker
//   (`sentSince`, from the page's own record), so that one with more on the chain is an alert.
// What this browser keeps (localStorage, nothing secret): the marker (alerts.mjs, markerKey), the ids confirmed
// (`timecurrency.alerts-shown.v1:<network>:<account>`), and the push service's address of this browser for each
// account it subscribed (`timecurrency.alerts-push.v1:<network>:<account>`). The words are alerts.mjs's and
// alerts-push.mjs's; every one goes into the page by textContent.
import { alertsOf, readMarker, markerKey } from './alerts.mjs';
import { failureNotice } from './actions.mjs';
import { askWhenFree, isBusyError } from './busy.mjs';
import { WORDS, ALERTS_PATH, pushSupport, applicationServerKey, challengeBody, proveFor, subscribeBody, unsubscribeBody, refusalWords, touchPath, readTouch, statusBody, readStatus } from './alerts-push.mjs';

/// The words of the panel itself.
export const PANEL = Object.freeze({
  none: 'Nothing needs your attention.',
  confirm: 'I have seen these',
  urgent: 'Urgent',
  live: 'Watching live',
  checked: 'Checked a moment ago',
  busyOn: 'Turning on alerts for this browser…',
  busyOff: 'Turning off alerts…',
  offEverywhere: 'Alerts are off on every browser of this account.',
});
/// A read asked by the live hint waits at least this long after the one before.
export const LIVE_GAP_MS = 2000;
/// A step of the browser's push machinery (registering the worker, its readiness, a subscription) that has not
/// answered after this long is a failure: the wallet says so instead of staying busy.
export const PUSH_WAIT_MS = 30000;
/// How often an unlocked page asks the service whether it still has this browser, at most.
export const STATUS_GAP_MS = 60000;
export const SHOWN_PREFIX = 'timecurrency.alerts-shown.v1:';
export const PUSH_PREFIX = 'timecurrency.alerts-push.v1:';
const MAX_SHOWN = 64;

/// The ids an owner confirmed, as this browser kept them, strictly: a list of at most 64 ids of this account.
export function readShown(text, accountId) {
  if (typeof text !== 'string' || text.length > 16384) return [];
  let list; try { list = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(list) || list.length > MAX_SHOWN || !list.every(id => typeof id === 'string' && id.length <= 240 && id.startsWith(`${accountId}:`))) return [];
  return list;
}
/// The push service's address of this browser, as this browser kept it for an account, or null.
export function readEndpoint(text) {
  return typeof text === 'string' && text.length <= 1024 && /^https:\/\/[^\s]+$/.test(text) ? text : null;
}

export function createAlertsUI({ sdk, $ = id => document.getElementById(id), network, session, ownAccount, storage, run, notice, setBusy, readAgain, sentSince = () => null, onBusy = null, win = globalThis, now = Date.now, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = id => clearTimeout(id), formatDate = date => date.toLocaleString() }) {
  let current = null, followed = null, stream = null, live = false, lastAsk = 0, timer = null, read = false, offered = null, switchTurn = 0;
  // The last time this page asked whether the service still has this browser, for which account, and the alert of a
  // service that no longer has it (null: none).
  let statusAt = 0, statusFor = null, removedAlert = null;
  // What the last render started and did not wait for (the switch, the question to the service): `idle()` waits for it.
  let working = Promise.resolve();
  const net = () => network().networkId;
  const get = key => { try { return storage.getItem(key); } catch { return null; } };
  const put = (key, value) => { try { storage.setItem(key, value); return true; } catch { return false; } };
  const drop = key => { try { storage.removeItem(key); } catch { /* nothing kept */ } };
  const node = (tag, text, className) => { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; };

  // ---------------------------------------------------------------- what needs attention
  /// Draws the panel from a state the page has just verified for its own account.
  function render(account, state) {
    const id = String(account.id);
    let switched = null;
    if (id !== followed) { stopLive(); followed = id; current = null; removedAlert = null; startLive(); switched = syncSwitch().catch(() => {}); }
    working = Promise.all([switched, askStatus()]).then(() => {});
    const key = markerKey(net(), id), seen = readMarker(get(key), id);
    const result = alertsOf({ sdk, state, account: id, seen, formatDate, sent: seen ? sentSince(seen.nonce) : null });
    // The first look of this browser at the account: what it sees now is its starting point.
    if (!seen) put(key, JSON.stringify(result.marker));
    current = { id, marker: result.marker, alerts: result.alerts };
    read = true; draw();
  }
  function draw() {
    $('alerts-panel').hidden = !current;
    if (!current) return;
    const shown = new Set(readShown(get(SHOWN_PREFIX + `${net()}:${current.id}`), current.id));
    const alerts = removedAlert ? [removedAlert, ...current.alerts] : current.alerts;
    $('alerts-list').replaceChildren(...alerts.map(alert => {
      const item = node('li', '', alert.urgent ? 'urgent' : ''), head = node('strong', alert.title);
      if (alert.urgent) head.append(' ', node('span', PANEL.urgent, 'tag now'));
      item.append(head, node('p', alert.text));
      return item;
    }));
    $('alerts-none').hidden = alerts.length > 0;
    const fresh = alerts.filter(alert => !shown.has(alert.id)), first = fresh.find(alert => alert.urgent);
    $('alerts-banner').textContent = first ? first.title : '';
    $('alerts-banner').hidden = !first;
    $('alerts-confirm').hidden = fresh.length === 0;
    status();
  }
  /// "I have seen these": the marker of the state shown, and the ids of the alerts shown.
  function confirm() {
    if (!current) return;
    put(markerKey(net(), current.id), JSON.stringify(current.marker));
    put(SHOWN_PREFIX + `${net()}:${current.id}`, JSON.stringify([...(removedAlert ? [removedAlert] : []), ...current.alerts].map(alert => alert.id).slice(0, MAX_SHOWN)));
    // What was a change since the last look is not one any more; what is true now stays. The list is drawn again from
    // the same state, with the marker just stored as what was seen.
    if (lastState) current = { ...current, alerts: alertsOf({ sdk, state: lastState, account: current.id, seen: current.marker, formatDate, sent: 0 }).alerts };
    draw();
  }
  let lastState = null;
  function remember(state) { lastState = state; }

  // ---------------------------------------------------------------- live
  function status() {
    $('alerts-live').textContent = live ? PANEL.live : read ? PANEL.checked : '';
  }
  function startLive() {
    if (typeof win.EventSource !== 'function' || !followed) return;
    let source;
    try { source = new win.EventSource(touchPath(followed)); } catch { return; }
    stream = source;
    let broken = false;
    source.addEventListener('open', () => { if (stream !== source) return; live = true; status(); if (broken) { broken = false; ask(); } });
    source.addEventListener('touch', event => { if (stream !== source) return; if (readTouch(event?.data, followed) !== null) ask(); });
    source.addEventListener('error', () => {
      if (stream !== source) return;
      live = false; broken = true; status();
      // A stream the browser gave up (no such route here, or it was refused): the refresh of the page goes on alone.
      if (source.readyState === 2) { stream = null; source.close?.(); }
    });
  }
  function stopLive() {
    if (stream) { const old = stream; stream = null; old.close?.(); }
    live = false;
    if (timer !== null) { clearTimer(timer); timer = null; }
  }
  /// One verified read soon, at most one every LIVE_GAP_MS: touches that come together are one read.
  function ask() {
    if (timer !== null) return;
    const wait = Math.max(0, lastAsk + LIVE_GAP_MS - now());
    timer = setTimer(() => { timer = null; lastAsk = now(); readAgain(); }, wait);
  }

  // ---------------------------------------------------------------- the switch
  const pushKey = accountId => PUSH_PREFIX + `${net()}:${accountId}`;
  /// Whether the service still has this browser: asked once when an account is opened, then at most once a minute, and
  /// only by a browser whose record says alerts are on. False: the record is forgotten, the switch says off, and the
  /// panel shows the alert. Any other answer (404 from a service without the route, a failure) changes nothing. Returns
  /// the promise of the question when one is asked.
  function askStatus() {
    if (statusFor === followed && now() - statusAt < STATUS_GAP_MS) return;
    statusFor = followed; statusAt = now();
    const accountId = followed, endpoint = readEndpoint(get(pushKey(accountId)));
    if (!endpoint || !session()) return;
    return call('status', statusBody(endpoint), { once: true }).then(answer => {
      if (accountId !== followed || readStatus(answer.status, answer.body) !== false) return;
      drop(pushKey(accountId));
      removedAlert = { id: `${accountId}:alerts-removed:${statusAt}`, urgent: true, title: WORDS.removedTitle, text: WORDS.removed };
      draw(); return syncSwitch();
    }).catch(() => {});
  }
  /// The browser's answer, or the wallet's words for a failure (its own words are not the person's).
  function within(promise) {
    let id = null;
    const late = new Promise((_, reject) => { id = setTimer(() => reject(new Error(WORDS.failed)), PUSH_WAIT_MS); });
    return Promise.race([promise, late]).catch(() => { throw new Error(WORDS.failed); }).finally(() => clearTimer(id));
  }
  const registration = async () => { try { return (await win.navigator.serviceWorker.getRegistration('./')) ?? null; } catch { return null; } };
  const subscription = async reg => { try { return (await reg?.pushManager?.getSubscription()) ?? null; } catch { return null; } };
  /// One request to the alert service. A busy answer (429 or 503) is waited for and asked again (busy.mjs), unless
  /// `once`; one that stays busy is the answer {status, body: null, busy: true}. `onBusy` of the page is told of each.
  async function call(path, body, { once = false } = {}) {
    const send = () => win.fetch(ALERTS_PATH + path, { method: body === undefined ? 'GET' : 'POST', ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000) });
    let response;
    try { response = sdk?.BUSY ? await askWhenFree(send, { sdk, tries: once ? 1 : undefined, timing: { now, sleep: ms => new Promise(resolve => setTimer(resolve, ms)) }, onBusy: error => onBusy?.(error) }) : await send(); }
    catch (error) { if (isBusyError(error)) return { status: error.status, body: null, busy: true }; throw error; }
    let answer = null; try { answer = JSON.parse((await response.text()).slice(0, 8192)); } catch { answer = null; }
    return { status: response.status, body: answer };
  }
  /// The alert service's public key if it is reached under this wallet's address, else false (asked once per page;
  /// a failure to ask is asked again next time).
  async function isOffered() {
    if (offered !== null) return offered;
    try {
      const answer = await call('key');
      // Busy: not known yet. It is asked again next time, and nothing is said of the switch meanwhile.
      if (answer.busy) { offered = null; return null; }
      offered = answer.status === 200 && typeof answer.body?.public_key === 'string' ? answer.body.public_key : false; return offered;
    } catch { offered = null; return false; }
  }
  function showSwitch({ state, why = '', on = false, off = false, everywhere = false, what = false }) {
    $('alerts-switch-state').textContent = state;
    $('alerts-switch-why').textContent = why; $('alerts-switch-why').hidden = !why;
    $('alerts-turn-on').hidden = !on; $('alerts-turn-off').hidden = !off; $('alerts-off-everywhere').hidden = !everywhere;
    $('alerts-switch-what').textContent = what ? `${WORDS.what} ${WORDS.privacy}` : ''; $('alerts-switch-what').hidden = !what;
  }
  /// What the switch says, from what this browser can do and holds now. Never "on" without a subscription.
  async function syncSwitch() {
    const turn = ++switchTurn, accountId = followed;
    const support = pushSupport(win);
    if (!support.ok) return showSwitch({ state: WORDS.off, why: support.reason });
    const service = await isOffered();
    if (turn !== switchTurn) return;
    if (service === null) return;
    if (!service) return showSwitch({ state: WORDS.off, why: WORDS.notOffered });
    const sub = await subscription(await registration());
    if (turn !== switchTurn || accountId !== followed) return;
    const on = Boolean(sub) && readEndpoint(get(pushKey(accountId))) === sub.endpoint;
    if (on) return showSwitch({ state: WORDS.on, off: true, everywhere: true, what: true });
    showSwitch({ state: WORDS.offMatters, on: true, everywhere: true, what: true });
  }
  async function refused(answer) {
    await syncSwitch();
    notice(refusalWords(answer.status, answer.body?.error), 'error');
  }
  const signer = () => { const me = session(); return me?.privateKey ? { publicKey: me.binding.publicKey, privateKey: me.privateKey } : null; };
  /// A challenge for `action`, its proof with the login key, and `send(proof)`: the service's answer. A challenge the
  /// service refuses with 403 (one it gave out before it restarted, or one used already) is asked for again, once; a
  /// frozen account is not asked again. A refused challenge is the answer as it came.
  async function proven(action, sub, account, key, send) {
    for (let attempt = 0; ; attempt++) {
      const asked = await call('challenge', challengeBody(action, sub));
      if (asked.status !== 200) return asked;
      const answer = await send(await proveFor({ sdk, challenge: asked.body, origin: win.location.origin, networkId: net(), account, key }));
      if (answer.status !== 403 || attempt > 0 || /frozen/i.test(String(answer.body?.error))) return answer;
    }
  }
  async function turnOn() {
    // The browser asks the person first, within the press: nothing is sent before they allow it.
    const support = pushSupport(win);
    if (!support.ok) { await syncSwitch(); return notice(support.reason, 'error'); }
    const permission = await win.Notification.requestPermission();
    if (permission !== 'granted') { await syncSwitch(); return notice(permission === 'denied' ? WORDS.denied : WORDS.failed, 'error'); }
    await run(async () => {
      const account = ownAccount(), key = signer();
      if (!account || !key) return notice(WORDS.needsLogin, 'error');
      setBusy(true, PANEL.busyOn);
      const service = await isOffered();
      if (service === null) return notice(WORDS.busy, 'error');
      if (!service) { await syncSwitch(); return notice(WORDS.notOffered, 'error'); }
      const reg = await within(win.navigator.serviceWorker.register('./sw.js', { scope: './' }));
      await within(win.navigator.serviceWorker.ready);
      const options = { userVisibleOnly: true, applicationServerKey: applicationServerKey(service) };
      let sub;
      try { sub = await within(reg.pushManager.subscribe(options)); } catch {
        // A subscription made for another key of the service (it was set up again): it is ended, and made anew. A
        // browser without a push service of its own (a headless one) fails here: nothing was sent anywhere.
        const old = await subscription(reg); if (!old) throw new Error(WORDS.failed);
        await within(old.unsubscribe()); sub = await within(reg.pushManager.subscribe(options));
      }
      const answer = await proven('subscribe', sub, account, key, proof => call('subscribe', subscribeBody({ proof, subscription: sub })));
      if (answer.status !== 200) return refused(answer);
      put(pushKey(String(account.id)), sub.endpoint);
      removedAlert = null; draw();
      await syncSwitch(); notice(WORDS.on);
    });
  }
  async function turnOff() {
    await run(async () => {
      setBusy(true, PANEL.busyOff);
      const reg = await registration(), sub = await subscription(reg);
      if (sub) {
        // The service forgets this browser for every account; the browser ends the subscription in any case.
        await call('unsubscribe', unsubscribeBody({ endpoint: sub.endpoint })).catch(() => null);
        await sub.unsubscribe().catch(() => false);
      }
      for (const key of Object.keys(storage)) if (key.startsWith(PUSH_PREFIX + `${net()}:`)) drop(key);
      await syncSwitch(); notice(WORDS.off);
    });
  }
  async function offEverywhere() {
    await run(async () => {
      const account = ownAccount(), key = signer();
      if (!account || !key) return notice(WORDS.needsLogin, 'error');
      setBusy(true, PANEL.busyOff);
      const answer = await proven('unsubscribe', undefined, account, key, proof => call('unsubscribe', unsubscribeBody({ proof })));
      if (answer.status !== 200) return refused(answer);
      drop(pushKey(String(account.id)));
      await syncSwitch(); notice(PANEL.offEverywhere);
    });
  }

  /// The wallet was locked, or another account opened: nothing of the last account stays, and the stream is closed.
  function reset() {
    stopLive(); followed = null; current = null; read = false; lastState = null; switchTurn++; removedAlert = null; statusFor = null;
    $('alerts-list').replaceChildren(); $('alerts-banner').textContent = ''; $('alerts-banner').hidden = true;
    $('alerts-confirm').hidden = true; $('alerts-none').hidden = true; $('alerts-live').textContent = '';
    showSwitch({ state: '' }); $('alerts-panel').hidden = true;
  }

  $('alerts-confirm').addEventListener('click', () => confirm());
  $('alerts-turn-on').addEventListener('click', () => turnOn().catch(error => notice(failureNotice(error, WORDS.failed), 'error')));
  $('alerts-turn-off').addEventListener('click', () => turnOff());
  $('alerts-off-everywhere').addEventListener('click', () => offEverywhere());
  return { render: (account, state) => { remember(state); render(account, state); }, reset, confirm, syncSwitch, live: () => live, following: () => followed, idle: () => working };
}
