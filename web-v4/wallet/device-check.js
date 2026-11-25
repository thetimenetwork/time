// The page "Check this device" (device-check.html): runs the check of device-key.mjs on the visitor's own device and
// says, in plain words, what that device can do, and what happens instead when it cannot. A trial: the wallet does not
// use any of it yet. Under the gateway's Content-Security-Policy (client-v4/server.mjs): no inline script or style, and
// the page's text is set with textContent and createElement only.
//
// What this page keeps in the browser (localStorage, under KEPT): the id of the test key, its random user handle, and a
// random value locked with the key (a device-key.mjs record). Nothing that identifies the person, nothing that opens
// without the device. The handle is used again by the next check, so that the device replaces its earlier test key
// instead of listing one more; the record lets "Try the key made earlier" ask the same key again, later.
import { browserEnv, checkDevice, checkEarlierKey, deviceReport, DEVICE_MESSAGES, fromBase64url, validateDeviceRecord } from './device-key.mjs';

const KEPT = 'timecurrency.device-check.v1';
const $ = (id) => document.getElementById(id);
const env = browserEnv(window);

/// The steps as the person reads them: a new key, or the key made earlier (checkEarlierKey).
const GROUPS = {
  fresh: [
    ['What the browser says it can do', [['secure', 'This is a secure page'], ['webAuthn', 'The browser can use fingerprint or face'], ['builtIn', 'The device has its own fingerprint, face or screen lock check'], ['prfBefore', 'The browser says it can lock a key with it']]],
    ['Making the test key', [['keyMade', 'The device made the test key'], ['prfAtCreation', 'The browser says the key can lock a secret'], ['backedUp', 'The device says the key is copied to a backup']]],
    ['Asking the device twice', [['firstAnswer', 'The device answered the first time'], ['secondAnswer', 'The device answered the second time'], ['same', 'Both answers are the same']]],
    ['Locking and opening', [['opened', 'A test value locked with the first answer opened with the second']]],
  ],
  earlier: [
    ['What the browser says it can do', [['secure', 'This is a secure page'], ['webAuthn', 'The browser can use fingerprint or face'], ['builtIn', 'The device has its own fingerprint, face or screen lock check'], ['prfBefore', 'The browser says it can lock a key with it']]],
    ['The key made earlier', [['firstAnswer', 'The device answered with the key made earlier'], ['opened', 'The value locked earlier opened']]],
  ],
};
const WORDS = { yes: 'Yes', no: 'No', unknown: 'Does not say', 'not run': 'Not tried', earlier: 'Made earlier' };

function element(tag, { className, text } = {}) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}
function renderSteps(steps, kind) {
  const box = $('step-groups'), parts = [];
  for (const [title, fields] of GROUPS[kind]) {
    parts.push(element('h3', { text: title }));
    const list = element('div', { className: 'check-list' });
    for (const [field, label] of fields) {
      const value = steps?.[field] ?? 'not run', row = element('div', { className: 'row' });
      row.append(element('span', { text: label }), element('span', { className: value === 'yes' ? 'badge ok' : 'badge', text: WORDS[value] ?? WORDS.unknown }));
      list.append(row);
    }
    parts.push(list);
  }
  box.replaceChildren(...parts);
  $('check-steps').hidden = false;
}
function renderResult(result, kind) {
  const box = $('result-box'), outcome = result.outcome;
  if (outcome.number === 1) {
    const done = element('div', { className: 'result' });
    done.append(element('h3', { text: kind === 'earlier' ? 'The key made earlier still works' : 'It works' }), ...outcome.says.map((text) => element('p', { text })));
    box.replaceChildren(done);
  } else {
    const said = element('div', { className: 'notice' });
    said.append(...outcome.says.map((text) => element('p', { text })));
    box.replaceChildren(said);
  }
  $('instead').hidden = outcome.instead === null;
  $('instead-text').textContent = outcome.instead ?? '';
  // A test key is on the device: one made by this check, or the one made earlier that just answered.
  const onDevice = result.keyMade || (kind === 'earlier' && result.steps.firstAnswer === 'yes');
  $('remove-key').hidden = !onDevice;
  $('remove-text').textContent = onDevice ? DEVICE_MESSAGES.removeTestKey : '';
  $('check-result').hidden = false;
}
function renderReport(result) {
  $('report-text').value = deviceReport(result, { userAgent: navigator.userAgent, host: location.host });
  $('report-said').textContent = '';
  $('check-report').hidden = false;
}

// ---- what the browser keeps ------------------------------------------------------------------------------------------
function readKept() {
  try {
    const kept = JSON.parse(localStorage.getItem(KEPT) || 'null');
    if (!kept || typeof kept !== 'object' || Object.keys(kept).sort().join(',') !== 'credentialId,record,userHandle' || !fromBase64url(kept.credentialId) || !fromBase64url(kept.userHandle, 16, 64)) return null;
    validateDeviceRecord(kept.record);
    return kept;
  } catch { return null; }
}
function writeKept(kept) { try { localStorage.setItem(KEPT, JSON.stringify(kept)); } catch { /* a browser that keeps nothing: "Try the key made earlier" is not offered */ } }
function forgetKept() { try { localStorage.removeItem(KEPT); } catch { /* nothing was kept */ } }
function showKept() { const kept = readKept() !== null; $('check-earlier').hidden = !kept; $('forget-earlier').hidden = !kept; }

// ---- the run -----------------------------------------------------------------------------------------------------------
let running = false;
async function run(kind) {
  if (running) return;
  running = true;
  for (const id of ['check-start', 'check-earlier', 'report-copy', 'forget-earlier']) $(id).disabled = true;
  for (const id of ['check-result', 'check-report']) $(id).hidden = true;
  $('check-wait').textContent = 'Follow what your device asks. This page waits for it.';
  renderSteps({}, kind);
  const kept = readKept(), onStep = (_, steps) => renderSteps(steps, kind);
  const result = kind === 'earlier' && kept
    ? await checkEarlierKey(env, { credentialId: kept.credentialId, record: kept.record, onStep })
    : await checkDevice(env, { userHandle: kept ? fromBase64url(kept.userHandle, 16, 64) : undefined, onStep });
  if (result.kept) writeKept(result.kept);
  renderSteps(result.steps, kind); renderResult(result, kind); renderReport(result);
  $('check-wait').textContent = '';
  document.body.dataset.outcome = String(result.outcome.number);
  for (const id of ['check-start', 'check-earlier', 'report-copy', 'forget-earlier']) $(id).disabled = false;
  showKept();
  running = false;
  // The result is below the steps: brought into view. Its box is a status region, so a screen reader reads it out.
  $('check-result').scrollIntoView({ block: 'start' });
}

$('check-start').addEventListener('click', () => { run('fresh'); });
$('check-earlier').addEventListener('click', () => { run('earlier'); });
$('forget-earlier').addEventListener('click', () => {
  forgetKept(); showKept();
  $('report-said').textContent = "The test value is forgotten in this browser. The test key stays on the device until you remove it in the device's settings.";
});
$('report-copy').addEventListener('click', async () => {
  const area = $('report-text'), said = $('report-said');
  try {
    if (typeof navigator.clipboard?.writeText !== 'function') throw new Error('no clipboard');
    await navigator.clipboard.writeText(area.value);
    said.textContent = 'The report is copied. Paste it into a message to the people who run this wallet.';
  } catch {
    // The browser refused (no permission, not a secure page, an app's own window): the text is selected for the person.
    area.focus(); area.select(); area.setSelectionRange(0, area.value.length);
    said.textContent = "This browser did not let the page copy. The report is selected: copy it from the browser's menu or with your keyboard.";
  }
});
showKept();
$('check-start').disabled = false;
$('check-wait').textContent = '';
