import * as installedVerifier from '/sdk/proof-verifier.js';
import { newDevice, sealVault, openVault, checkPassword, validateName, hex, fromB64, forgetSecret } from './vault.mjs';
import { GenerationFence, PendingReservations, PaymentMarkers, withSigningLock, parseSeconds, formatSeconds, acceptApprovalEvent, IDLE_LOCK_MS } from './guards.mjs';
import { pendingIsObsolete, poolSharesForDeposit, registrationPendingDisposition, emergencyCancelSlot, nonceCancelSlot, recoveryFrozen, authorityReservationObsolete, emergencyReservationObsolete, createUpgradeMonitor, upgradeRequiredScreen, failureNotice, gatewayNotification, sponsorReceiptBinds, askFaucet, faucetReceiptPays, sentNotice, durationWords, keysView } from './actions.mjs';
import { createRecoveryUI } from './recovery.mjs';
import {createPosUI} from './pos-ui.mjs';
import {createEncryptedBackup,importEncryptedBackup,MAX_BACKUP_BYTES} from './vault-backup.mjs';
import { createSecurityUI } from './security-ui.mjs';
import { needsSecurityRow, vaultSlots, waitsOf } from './security-flows.mjs';
import { effectiveLimit, pauseState } from './protection.mjs';
import { createSendSigned, signalSigner } from './signing.mjs';
import { createSignalUI } from './upgrade-signal-ui.mjs';
import { createSignupUI } from './signup-ui.mjs';
import { resetSeen, elsewhere, oldEntries, resetWords, resetOpenWords, RESET_RELOAD, trustReader } from './reset.mjs';
import { payeeCheck, lookAlike, firstPaymentWords, alikeWords, ownAlikeWords, NAME_ACKNOWLEDGE, paidNamesFrom, withPaidName, paidNameOf, resembles, tooCloseName, tooCloseWords } from './names.mjs';

const $ = id => document.getElementById(id);
const sdk = globalThis.TimeSDK;
const fence = new GenerationFence();
const pending = new PendingReservations(localStorage);
const paymentMarkers = new PaymentMarkers(localStorage);
const vaultPrefix = 'timecurrency.vault.v1:';
let client, network, latest, session, mode = 'create', busy = false, approval, refreshTimer, idleTimer, lockChannel;
let activity = [];
// The names this account has paid from this browser (paidNamesNow): what the name of a payment is compared with.
let paidNames = [];
let backupGeneration=0;
let guardianTargetName='';
// The block of the newest receipt this page verified (recordReceipt), and until when verifiedState waits for proven
// state to reach it: half a minute after that receipt.
let receiptFloor = 0n, receiptFloorUntil = 0;
// Whether a refresh of the timer is still running: the timer starts no second one beside it.
let refreshing = false;
const checkedReceipts = new Set();
function notice(message, type = '') { $('notice').textContent = message; $('notice').className = `notice ${type}`; $('notice').hidden = !message; }
function assert(value, message) { if (!value) throw new Error(message); }
function textNode(tag, text, className) { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; }
// The protocol version shown is the one of the latest verified state, never the gateway's report
// (which names the network's first version for ever).
function showVersion(state) { $('protocol-badge').textContent = 'Network rules: version ' + state.protocol_version + '.'; }
// "Update this app": the network runs a version of its rules this app does not implement. Shown
// only for the refusal of this wallet's own verifier (see upgradeRequiredScreen); signing stops.
function upgradeRequired(error) {
  const screen = upgradeRequiredScreen(error); if (!screen) return false;
  latest = null; $('upgrade-banner').hidden = true;
  $('upgrade-required-title').textContent = screen.title; $('upgrade-required-text').replaceChildren(...screen.lines.map(line => textNode('p', line)));
  $('upgrade-required').hidden = false; $('network-status').textContent = 'Update needed · signing is off'; $('network-dot').className = '';
  renderAvailability(); return true;
}
// The banner while an upgrade is scheduled, read from proven state (createUpgradeMonitor in
// actions.mjs). On a network whose pinned trust data says that its nodes report upgrades, every
// verified read of this wallet carries the question from the first one (the SDK adds it), so a
// gateway cannot hold or refuse that one question while the wallet looks healthy. On a network
// that does not say so, the wallet asks in a read of its own, with a time limit, until a node
// has answered; a failure to read is one standing, quiet line, never "nothing is scheduled", and
// always in this app's own words. What a gateway says never chooses what is shown.
let upgrades;
function showUpgrade({ banner }) {
  $('upgrade-banner').textContent = banner?.text || ''; $('upgrade-banner').className = 'notice' + (banner?.urgent ? ' error' : ''); $('upgrade-banner').hidden = !banner;
  // The control to forget a learned answer is offered only while there is one.
  $('upgrade-forget-row').hidden = !upgrades?.learned();
}
async function checkUpgrade() {
  if (!client || !upgrades?.probeDue()) return; upgrades.probeStarted();
  try { const { state } = await client.getVerifiedState({ include_upgrade: true }, { timeoutMs: 15000 }); showUpgrade(upgrades.fromState(state, sdk.upgradeStatusOf(state))); }
  catch (error) { if (upgradeRequired(error)) return; showUpgrade(upgrades.probeFailed(error)); }
}
// What an action costs on this network, in microseconds. It is a setting of the network: the SDK
// reads it from every state this wallet verifies (`config.fee_micros`), and every screen that shows
// or uses it comes after such a state.
function networkFee() { assert(sdk.isFee(network?.feeMicros), 'The network fee is unavailable.'); return network.feeMicros; }
function vaultKey(name) { return vaultPrefix + network.networkId + ':' + name; }
function activityKey() { return `timecurrency.activity.v1:${network.networkId}:${session?.binding.name || ''}`; }
function namesKey() { return `timecurrency.names.v1:${network.networkId}:${session?.binding.name || ''}`; }
function setBusy(value, message = '') { busy = value; for (const el of document.querySelectorAll('button')) { if (el.id !== 'lock-button') el.disabled = value; } for(const input of document.querySelectorAll('#backup-import-form input, #backup-export-form input'))input.disabled=value; $('auth-progress').textContent = message; reviewGate(); if (!value) renderAvailability(); }
function currentDevice(account) { return account?.devices?.find(d => d.public_key === session?.binding.publicKey); }
function ownAccount(state = latest?.state) { return state?.accounts?.find(a => a.name === session?.binding.name); }
function renderAvailability() {
  const ready = Boolean(network && latest?.verified === true && !busy);
  $('auth-submit').disabled = !ready;
  const account = ownAccount(), device = currentDevice(account);
  // A protected account pays, stakes and runs its validator with its payment key (security-ui.mjs); it bids in no auction.
  for (const form of ['send-form', 'bid-form', 'stake-form','validator-register-form','self-bond-form','self-unbond-form']) for (const button of $(form).querySelectorAll('button')) button.disabled = !ready || !(device?.can_spend || (form !== 'bid-form' && securityUI.canPay()));
  $('approve-device-form').querySelector('button').disabled = !ready || !device?.can_manage;
  $('backup-export-submit').disabled=!ready||!device;
  $('backup-import-submit').disabled=!ready||Boolean(session);
  $('faucet-button').disabled = !ready || !device;
  const frozen = account && latest?.state ? recoveryFrozen(latest.state, account.id) : false;
  if (frozen) for (const form of ['send-form', 'bid-form', 'stake-form', 'approve-device-form','validator-register-form','self-bond-form','self-unbond-form']) for (const button of $(form).querySelectorAll('button')) button.disabled = true;
  $('validator-retire').disabled=!ready||!(device?.can_spend||securityUI.canPay())||frozen;
  $('approve-request').disabled = !ready || !device || !approval || approval.request.type === 'grant' || frozen;
  for (const button of document.querySelectorAll('[data-chain-action]')) button.disabled = !ready || frozen || !device;
  recoveryUI.availability(ready, device, frozen);
  securityUI.availability(ready);
  signalUI.availability(ready && Boolean(device), frozen);
}
function setMode(value) {
  mode = value;
  for (const m of ['create', 'unlock', 'link', 'recover']) $(`mode-${m}`).classList.toggle('active', m === value);
  $('auth-heading').textContent = value === 'unlock' ? 'Open your account' : value === 'recover' ? 'Recover with your guardians' : value === 'link' ? 'Add this browser to your account' : 'Create your account';
  $('auth-copy').textContent = value === 'unlock' ? 'The key of your account is kept in this browser, locked with your password.' : value === 'recover' ? 'Use a new browser. Type the name of your account and pick a password for this browser. It makes a new key and a request for your guardians. The account waits for its whole waiting period before this browser takes over.' : value === 'link' ? 'Type the name of your account and pick a password for this browser. This browser makes its own key and shows a request: approve it in a browser where your account is open.' : 'Pick a name that others can send seconds to, and a password.';
  $('auth-submit').textContent = value === 'unlock' ? 'Open my account' : value === 'recover' ? 'Make the request for my guardians' : value === 'link' ? 'Make the request' : 'Create my account';
  $('password').autocomplete = value === 'unlock' ? 'current-password' : 'new-password';
  $('password').placeholder = value === 'unlock' ? '' : 'At least 15 characters'; $('username-note').hidden = value === 'unlock';
  $('password-confirm').hidden = $('confirm-label').hidden = value === 'unlock';
  $('password-confirm').required = value !== 'unlock';
  $('password').value = $('password-confirm').value = '';
  // "Create an account" on a network that takes them is the protected sign-up (signup-ui.mjs). Its papers, if shown,
  // are forgotten whatever the mode now is.
  signupUI.reset(); signupUI.form(value === 'create' && signupUI.on());
  // "Open my account" with the name of a sign-up this browser keeps offers to let it go (signup-ui.mjs, letGo).
  signupUI.offer(value === 'unlock' ? $('username').value.trim() : null);
}
function scheduleIdleLock() { clearTimeout(idleTimer); if (session) idleTimer = setTimeout(() => lock('Locked after 5 minutes without use. Your key stays in this browser, locked with your password.'), IDLE_LOCK_MS); }
function lock(message = 'Locked. Your key stays in this browser, locked with your password.', broadcast = true) {
  const lockedName = session?.binding.name;
  if (broadcast && lockedName) lockChannel?.postMessage({ type: 'lock', name: lockedName });
  fence.bump(); clearInterval(refreshTimer); clearTimeout(idleTimer);
  backupGeneration++;
  if (session) { forgetSecret(session.secret); session.privateKey = null; }
  session = null; activity = []; paidNames = []; checkedReceipts.clear();guardianTargetName='';recoveryUI.resetTarget();securityUI.reset();signalUI.reset();
  $('password').value = $('password-confirm').value = '';
  $('backup-password').value=$('backup-export-password').value=$('backup-file').value='';
  $('enrollment-code').value = ''; $('device-request').value = '';
  $('dashboard').hidden = $('enrollment-panel').hidden = $('recovery-claim-panel').hidden = $('lock-button').hidden = true;
  // A review still open is closed as cancelled: it would stay over the start screen with the locked account's payment.
  if ($('review-dialog').open) $('review-dialog').close('cancel');
  clearHome(); showPanel('home');
  $('auth-panel').hidden = false; setMode('unlock'); setBusy(false); notice(message);
}
async function verifiedState(input = {}) {
  assert(client && network, 'The verified network connection is not ready.');
  const ownName = session?.binding.name || $('username').value.trim().replace(/^@/, '');
  const names = [...new Set([...(input.names || []), ...(guardianTargetName?[guardianTargetName]:[]), ...(/^[a-z0-9_]{2,15}$/.test(ownName) ? [ownName] : [])])];
  const owner=latest?.state?.accounts?.find(a=>a.name===ownName)?.id;
  const previousStake=owner?latest?.state?.stake_owners?.[owner]:null;
  const selectedCandidates=[...new Set([...(input.candidates||[]),...(owner?[owner]:[]),...(previousStake?.positions||[]).slice(0,12).map(p=>p.candidate)])].slice(0,16);
  const releaseBlocks=[...new Set(input.blocks||[])].slice(0,16);
  const epoch=latest?.state?.earning_epochs?Object.keys(latest.state.earning_epochs):[];
  const wantSecurity = Boolean(input.include_security) || needsSecurityRow(latest?.state?.accounts?.find(a=>a.name===ownName));
  const read = async () => {
    let value = await client.getVerifiedState({ ...input,names, ids: input.ids || [], public_keys: session?.binding.publicKey ? [session.binding.publicKey] : [],owners:owner?[owner]:[],candidates:selectedCandidates,blocks:releaseBlocks,include_pos:true,include_bitcoin:true,include_policy:true,include_security:wantSecurity,...(upgrades?.selection() || {}) });
    const actual=value.state.accounts.find(a=>a.name===ownName)?.id;
    if(actual&&actual!==owner)value=await client.getVerifiedState({...value.requested,owners:[actual],candidates:[...new Set([actual,...selectedCandidates])].slice(0,16)});
    // What the account has staked is priced with its validators' pools. The pools asked for above are those of the
    // read before this one, so a first stake with a validator would be shown as "unpriced" until the next read:
    // a validator the account has a position with, and whose pool is not in this state, is asked for at once.
    const unasked=[...new Set((value.state.stake_owners?.[actual||owner]?.positions||[]).map(p=>p.candidate).filter(id=>!value.state.candidates?.[id]))];
    if(unasked.length)value=await client.getVerifiedState({...value.requested,candidates:[...new Set([...(value.requested.candidates||[]),...unasked])].slice(0,16)});
    if(!value.requested.include_security&&needsSecurityRow(value.state.accounts.find(a=>a.name===ownName)))value=await client.getVerifiedState({...value.requested,include_security:true});
    assert(value?.verified === true && value.state?.network_id === network.networkId, 'Independent state verification failed. Signing is disabled.');
    return value;
  };
  // A receipt is verified a block ahead of the state the service proves next. After a receipt this wallet verified,
  // a state from before that block is not taken as the answer: the state is asked again. (Seen in a browser on
  // 2026-11-19, on a network with three blocks a second: an account read right after its own registration was
  // "not finalized yet".)
  // The wait has three ends, so that a service that stays behind cannot hold the wallet:
  // - twenty seconds for one read;
  // - half a minute after the receipt was verified (`receiptFloorUntil`): later reads do not wait at all;
  // - the wallet was locked or another session began meanwhile (the fence): the wait stops at once.
  // A state that is still behind then is a verified state all the same, and is the answer.
  const sameSession = fence.capture(), unchanged = () => { try { sameSession(); return true; } catch { return false; } };
  let value = await read();
  for (const end = Math.min(Date.now() + 20000, receiptFloorUntil); BigInt(value.state.height) < receiptFloor && Date.now() < end && unchanged(); ) {
    await new Promise(resolve => setTimeout(resolve, 300));
    if (!unchanged()) break;
    value = await read();
  }
  latest = value; showVersion(value.state);
  // A state read with the upgrade entry: the banner follows every refresh.
  if (upgrades && Object.hasOwn(value.state, 'upgrade')) showUpgrade(upgrades.fromState(value.state, sdk.upgradeStatusOf(value.state)));
  return value.state;
}
function downloadJSON(text,filename){
  const url=URL.createObjectURL(new Blob([text],{type:'application/json'})),anchor=document.createElement('a');
  anchor.href=url;anchor.download=filename;anchor.hidden=true;document.body.append(anchor);anchor.click();anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function exportBackup(event){event.preventDefault();await run(async()=>{
  assert(session&&network,'Unlock an approved account before exporting its backup.');
  const check=fence.capture(),binding={...session.binding},password=$('backup-export-password').value;
  $('backup-export-password').value='';setBusy(true,'Checking your encrypted backup and current device authority...');
  const raw=localStorage.getItem(vaultKey(binding.name));assert(raw,'The stored encrypted vault is unavailable.');
  const text=await createEncryptedBackup({record:JSON.parse(raw),password,expectedBinding:binding,networkId:network.networkId,client,argon2id:globalThis.hashwasm?.argon2id,check});check();
  downloadJSON(text,`time-${binding.name}-${binding.networkId.slice(0,8)}-${binding.publicKey.slice(0,8)}.vault.json`);
  backupSaved(binding,true);$('home-backup').hidden=true;
  notice('Backup file downloaded. Keep it somewhere other than this device. It opens your account only together with your password.');
});}
// Whether a backup file of this browser's key was downloaded here, or this key came from one: Home then stops
// suggesting it. Nothing secret: the name and the public key only.
function backupSaved(binding,set=false){
  const key=`timecurrency.backup-saved.v1:${binding.networkId}:${binding.name}:${binding.publicKey}`;
  try{if(set){localStorage.setItem(key,'1');return true;}return localStorage.getItem(key)==='1';}catch{return false;}
}
async function restoreBackup(event){event.preventDefault();await run(async()=>{
  assert(!session&&network,'Lock this wallet before restoring an encrypted backup.');
  const file=$('backup-file').files[0],password=$('backup-password').value,generation=backupGeneration,networkId=network.networkId,fenced=fence.capture();
  assert(file&&file.size<=MAX_BACKUP_BYTES,'Choose an encrypted backup file of at most 16 KiB.');
  const check=()=>{fenced();assert(generation===backupGeneration&&network.networkId===networkId&&!session,'The restore inputs or wallet session changed. Nothing was imported.');};
  $('backup-password').value='';setBusy(true,'Unlocking the backup and checking current account authority...');
  const text=await file.text();check();
  const imported=await importEncryptedBackup({text,password,networkId,client,argon2id:globalThis.hashwasm?.argon2id,storage:localStorage,locks:navigator.locks,check});check();
  $('username').value=imported.binding.name;$('backup-file').value='';setMode('unlock');backupSaved(imported.binding,true);
  notice('Backup restored. Open your account with the password of the backup file. No new key was made.');
});}
function seconds(value) { return formatSeconds(String(value || '0')); }
function row(title, detail, buttonText, action) {
  const r = textNode('div', '', 'row'), copy = document.createElement('div');
  copy.append(textNode('strong', title)); if (detail) copy.append(textNode('small', detail)); r.append(copy);
  if (buttonText) { const b = textNode('button', buttonText, 'secondary'); b.type = 'button'; b.dataset.chainAction = 'true'; b.addEventListener('click', () => run(action)); r.append(b); }
  return r;
}
// The review before anything is signed. With `acknowledge` (a sentence), the dialog shows a box with that sentence
// and the button that confirms stays disabled until the box is ticked: a second, deliberate step. When the dialog
// opens, the focus is put on its title (see below why). Before that, without the box, it was on the button that
// confirms, and a key held down on the form behind it pressed it at once; with the box, it was on the box, which
// the Enter key does not tick. A review closed as confirmed without the tick counts as cancelled,
// whatever enabled the button.
function reviewGate() { $('review-confirm').disabled = busy || !reviewArmed || (!$('review-ack-wrap').hidden && $('review-ack').checked !== true); }
// A review cannot be confirmed in its first moments. Its button is disabled for REVIEW_ARM_MS after it opened, and
// a review closed as confirmed before that counts as cancelled. What it is for: the second click of a double click
// on the button that asked for the review, or on a website's button behind a wallet window, lands where the
// confirming button has just appeared. Nobody reads a review in less time.
const REVIEW_ARM_MS = 700;
let reviewArmed = true, reviewOpened = 0;
// What the review of a payment says about the name it goes to (`payee`), above its fields (names.mjs, payeeCheck):
// - a name this account has paid from this browser: nothing;
// - a name it has not paid, which looks like one it has, or like the account's own name: a warning that shows both
//   names, in a font that tells 1 from l and 0 from o, and a box to tick ("I checked the name, letter by letter.")
//   before the button that signs works;
// - any other name it has not paid: one plain line, "First payment to @name.".
// It is a warning and not a refusal: the person may know both names. It knows the names paid from this browser only.
/// A sentence that comes in pieces (names.mjs): a piece that begins with `@` is a name, set in the font that tells 1 from l.
function nameLine(pieces, warning) {
  const line = textNode('p', '', warning ? 'warning name-check' : 'name-check');
  line.append(...pieces.map(piece => textNode(piece.startsWith('@') ? 'code' : 'span', piece)));
  return line;
}
function payeeLines(name) {
  const check = payeeCheck(name, paidNamesNow(), session?.binding.name || '');
  if (check.kind === 'paid') return { lines: [], acknowledge: '' };
  const alike = check.kind === 'alike' || check.kind === 'own';
  return { lines: [nameLine(check.kind === 'own' ? ownAlikeWords(name, check.other) : alike ? alikeWords(name, check.other) : firstPaymentWords(name), alike)], acknowledge: alike ? NAME_ACKNOWLEDGE : '' };
}
// `warnings`: sentences in pieces about names the review is about (the guardians of recovery.mjs), each shown as the
// warning of a payment's name is. The caller asks for the tick with `acknowledge`.
function review(title, fields, confirmLabel = 'Confirm & sign', { acknowledge = '', payee = '', warnings = [] } = {}) {
  assert(!$('review-dialog').open, 'Another review is already open.');
  $('review-title').textContent = title; $('review-confirm').textContent = confirmLabel;
  const list = document.createElement('dl');
  // The total is what leaves the account: its line stands out.
  for (const [key, value] of fields) list.append(textNode('dt', key, key === 'Total' ? 'total' : ''), textNode('dd', String(value), key === 'Total' ? 'total' : ''));
  // A payment names who it goes to (`payee`): what this browser knows of that name comes first, and a name that looks
  // like one paid before asks for a tick of its own. One box holds every sentence that is asked.
  const about = typeof payee === 'string' && payee !== '' ? payeeLines(payee) : { lines: [], acknowledge: '' };
  // A review that carries a warning about a name always asks for a tick, also when its caller named no sentence for it.
  const named = Array.isArray(warnings) && warnings.length > 0 && acknowledge === '' ? NAME_ACKNOWLEDGE : acknowledge;
  const sentence = [named, about.acknowledge].filter(text => typeof text === 'string' && text !== '').join(' ');
  const asked = sentence !== '';
  const opened = ++reviewOpened; reviewArmed = false; setTimeout(() => { if (reviewOpened === opened) { reviewArmed = true; reviewGate(); } }, REVIEW_ARM_MS);
  $('review-ack').checked = false; $('review-ack-text').textContent = sentence; $('review-ack-wrap').hidden = !asked; reviewGate();
  $('review-body').replaceChildren(...about.lines, ...(Array.isArray(warnings) ? warnings : []).map(pieces => nameLine(pieces, true)), list); $('review-dialog').returnValue = 'cancel'; $('review-dialog').showModal();
  // A key held down must not sign. The browser puts the focus on the first control of a dialog that opens: without
  // the box that is the button that confirms, and the Enter key that sent the form behind it, still held, pressed
  // it at once. The focus goes to the title instead, which no key presses; and a repeating key presses nothing in
  // the dialog (the listener is added where the page is wired, below).
  $('review-title').focus?.();
  return new Promise(resolve => $('review-dialog').addEventListener('close', () => { const ticked = $('review-ack').checked === true, armed = reviewArmed && reviewOpened === opened; $('review-ack').checked = false; reviewOpened += 1; reviewArmed = true; resolve($('review-dialog').returnValue === 'confirm' && armed && (!asked || ticked)); }, { once: true }));
}
// One action at a time, from its first instant: `busy` is set only after an action's first wait, and a key held
// down on a form sent it again and again until then (each later one failed with "Another review is already open").
let running = false;
async function run(action) {
  if (busy || running) return;
  running = true;
  const valid = fence.capture();
  const preparing = 'Preparing your request…'; notice(preparing, 'busy');
  try { await action(); valid(); if ($('notice').textContent === preparing) notice('Request completed. Review the result above.'); } catch (error) { try { valid(); upgradeRequired(error); notice(failureNotice(error), 'error'); networkReset().catch(() => {}); } catch {} }
  finally { running = false; try { valid(); setBusy(false); } catch {} }
}
function readActivity() { try { const parsed = JSON.parse(localStorage.getItem(activityKey()) || '[]'); activity = Array.isArray(parsed) ? parsed.slice(-40).filter(a => a && typeof a.hash === 'string' && /^[0-9a-f]{64}$/i.test(a.hash)) : []; } catch { activity = []; } }
// The names this account has paid from this browser, for the review of a payment (payeeLines). They are kept in this
// browser beside the activity, per network and per account, and hold nothing secret: names, and nothing is sent anywhere.
// - A name enters when this browser has verified the receipt of a payment to it that was signed here: the label of such
//   an action names who it goes to (names.mjs, paidNameOf), and the account a website was paid at is added where that
//   payment is made (approveWebsite), `paidNow`.
// - The activity kept from before this record existed fills it too: it is read here each time.
// - The stored list is read each time, so a payment made in another tab of this account counts at once.
// A list that cannot be read is an empty one, and one that cannot be written is remembered for this page only: the
// warning then knows less, and no payment fails for it.
function paidNamesNow(paidNow = null) {
  if (!session || !network) return [];
  let kept = []; try { kept = paidNamesFrom(JSON.parse(localStorage.getItem(namesKey()) || 'null')); } catch { kept = []; }
  let names = kept;
  for (const name of [...paidNames, ...activity.map(item => paidNameOf(item.label))]) if (name && !names.includes(name)) names = withPaidName(names, name);
  if (paidNow) names = withPaidName(names, paidNow);
  if (names.join() !== kept.join()) { try { localStorage.setItem(namesKey(), JSON.stringify({ paid: names })); } catch { /* remembered for this page only */ } }
  paidNames = names; return names;
}
function recordReceipt(receipt, label) {
  assert(receipt?.verified === true, 'A transaction cannot be marked verified without an inclusion proof.');
  // The block of the newest verified receipt: verifiedState does not take an older state as its answer.
  try { const height = BigInt(receipt.height); if (height > receiptFloor) { receiptFloor = height; receiptFloorUntil = Date.now() + 30000; } } catch { /* a receipt without a height moves nothing */ }
  const action = receipt.action;
  if (action?.kind === sdk.KINDS.merchant_payment && action.networkId === network.networkId) paymentMarkers.markVerified(network.networkId, action.from, action.payload.reference, receipt.hash);
  const hash = receipt.hash.toUpperCase(); checkedReceipts.add(hash);
  activity = activity.filter(a => a.hash !== hash); activity.push({ hash, height: String(receipt.height), label, at: Date.now() });
  // A payment to a name, now in a block: that name is one this account has paid.
  const paid = paidNameOf(label); if (paid) paidNamesNow(paid);
  activity = activity.slice(-40); localStorage.setItem(activityKey(), JSON.stringify(activity)); renderActivity();
}
function renderActivity() {
  $('activity-list').replaceChildren();
  if (!activity.length) $('activity-list').append(textNode('p', 'Nothing from this browser yet.', 'subtle'));
  // Home shows the newest three, without buttons; Activity shows them all.
  const recent = activity.slice(-3).reverse();
  $('home-activity').replaceChildren(...(recent.length ? recent.map(item => row(item.label || 'Action', checkedReceipts.has(item.hash) ? `Checked by this browser · block ${item.height}` : `Receipt kept from earlier · block ${item.height}`)) : [textNode('p', 'Nothing from this browser yet.', 'subtle')]));
  for (const item of activity.slice().reverse()) {
    const checked = checkedReceipts.has(item.hash);
    const r = row(item.label || 'Action', `${checked ? 'Checked by this browser' : 'Receipt kept from earlier · check it again'} · block ${item.height} · ${item.hash}`, checked ? null : 'Check again', async () => { setBusy(true); const receipt = await client.waitReceipt(item.hash, { timeoutMs: 10000 }); recordReceipt(receipt, item.label); notice('This browser checked the receipt: the action is in a block.'); });
    const save=textNode('button','Save public receipt','secondary');save.type='button';save.addEventListener('click',()=>run(async()=>{
      const check=fence.capture();setBusy(true);const evidence=await client.exportReceiptEvidence(item.hash);check();
      downloadJSON(JSON.stringify(evidence,null,2)+'\n',`seconds-receipt-${item.hash.toLowerCase()}.json`);
      notice('Public receipt evidence downloaded. Reanchor it against current canonical history before reuse; the current trusted checkpoint expires after seven days.');
    }));r.append(save);
    $('activity-list').append(r);
  }
  filterActivity(); renderPaidNames();
  renderPending();
}
// Whether "Cancel pending action" is offered: this browser's key may manage the account, and no guardian recovery freezes it.
function cancelOffered(account) { return Boolean(account && latest?.state && currentDevice(account)?.can_manage && !recoveryFrozen(latest.state, account.id)); }
function renderPending() {
  $('pending-panel').replaceChildren(); $('home-pending').hidden = true; const account = ownAccount(); if (!account) return;
  const item = pending.get(network.networkId, String(account.id)); if (!item) return;
  $('home-pending').hidden = false;
  $('pending-panel').append(textNode('p', `A signed action is waiting for its receipt: ${item.hash}. Do not sign the same again while nobody knows whether it was included.`));
  const b = textNode('button', 'Check pending receipt', 'secondary'); b.addEventListener('click', () => run(reconcilePending)); $('pending-panel').append(b);
  const retry = textNode('button', 'Retry the exact signed action', 'secondary'); retry.addEventListener('click', () => run(async () => {
    const check = fence.capture();
    await withSigningLock(navigator.locks, network.networkId, String(account.id), async () => {
      const existing = pending.get(network.networkId, String(account.id)); assert(existing, 'No pending action.');
      const tx = fromB64(existing.tx, 512*1024+512); assert((await sdk.transactionHash(tx)) === existing.hash.toUpperCase(), 'Pending transaction bytes are damaged.'); check();
      const action = sdk.decodeAction(tx); if (action.kind === sdk.KINDS.merchant_payment) paymentMarkers.reserve(network.networkId, action.from, action.payload.reference, existing.hash);
      setBusy(true); const receipt = await client.submit(tx); check(); pending.clear(network.networkId, String(account.id), existing.hash); recordReceipt(receipt, existing.label);
    }); await refresh(); notice('The exact pending action is finalized. Its nonce prevents a second execution.');
  })); $('pending-panel').append(retry);
  if (cancelOffered(account)) {
    const cancel = textNode('button', 'Cancel pending action', 'secondary'); cancel.addEventListener('click', () => run(async () => {
      const check = fence.capture(), fee = networkFee();
      assert(BigInt(account.balance) >= BigInt(fee), 'Cancelling a pending action costs the network fee, and this account holds less.');
      if (!await review('Cancel a pending signed action', [['Pending action hash', item.hash], ['Race warning', 'The old action may win the nonce race until a cancellation is finalized. A finalized payment cannot be reversed.'], ['Effect', 'Consume the next nonce and advance the authority epoch. Keep the device keys. Old signatures and website sessions become obsolete.'], ['Fee', seconds(fee) + ' seconds']], 'Sign cancellation')) return;
      check(); setBusy(true); await sendSigned('cancel_pending', {}, 'Cancel pending action'); await refresh(); notice('Cancellation finalized and verified. Older authority signatures are now obsolete. A finalized payment was not reversed.');
    })); $('pending-panel').append(cancel);
  }
}
async function reconcilePending() {
  const check = fence.capture(), account = ownAccount(); assert(account, 'Unlock an account first.');
  await withSigningLock(navigator.locks, network.networkId, String(account.id), async () => {
    check(); const item = pending.get(network.networkId, String(account.id)); if (!item) return;
    setBusy(true); notice('Checking the pending action against the chain…', 'busy');
    try {
      const receipt = await client.waitReceipt(item.hash, { timeoutMs: 10000 }); check();
      pending.clear(network.networkId, String(account.id), item.hash); recordReceipt(receipt, item.label); notice('Pending action is finalized and independently verified.');
    } catch (error) {
      const state = await verifiedState(); check(); const now = ownAccount(state);
      const oldAction = sdk.decodeAction(fromB64(item.tx, 512*1024+512));
      if (pendingIsObsolete(now, item, oldAction, state)) {
        pending.clear(network.networkId, String(account.id), item.hash);
        notice('The verified account has moved past this signed action. Its nonce or authority is obsolete, so it cannot be replayed. The original action outcome was not verified; inspect activity before making a new payment.', 'error');
      } else throw error;
    }
  }); await refresh();
}
// Signing and sending one action: signing.mjs, which holds the rules of which key may sign what.
const sendSigned = createSendSigned({ sdk, session: () => session, network: () => network, client: () => client, locks: () => navigator.locks, capture: () => fence.capture(), ownAccount, verifiedState, pending, paymentMarkers, notice, record: recordReceipt });
// Who sponsors the registration of a new account (see registerAccount).
// - A laboratory's gateway sponsors by itself: its network answer names `sponsorAccount`.
// - Otherwise the gateway may name a registration service, such as the faucet of a test network
//   (`registrationService`, an origin). The wallet asks that service which account sponsors and for which network,
//   signs its consent for exactly that account, and hands over the new public key, the commitment of the name (not
//   the name) and the consent. No password and no private key leaves the browser.
// The sponsor gets no power over the new account. What a sponsor answers is believed only as far as the chain
// confirms it: registerAccount checks the receipt of the sponsor's action and the commitment in proven state.
async function registrationSponsor() {
  if (network.sponsorAccount && /^(0|[1-9][0-9]*)$/.test(network.sponsorAccount)) return { account: network.sponsorAccount, ask: body => client.request('/api/sponsor-registration', { method: 'POST', body: JSON.stringify(body) }) };
  const origin = network.registrationService;
  assert(typeof origin === 'string' && origin !== '', 'This wallet cannot register a new account here: its service names no registration sponsor. Passwords and private keys are never shared with one.');
  const options = { cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' };
  // What the service answers is waited for fifteen seconds at most and read to 64 KiB at most: a service that
  // answers slowly, or without end, holds nothing.
  const read = async (path, init = {}) => {
    const response = await fetch(origin + path, { ...options, ...init, signal: AbortSignal.timeout(15000) });
    const reader = response.body?.getReader(), parts = []; let size = 0;
    if (reader) for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > 65536) { await reader.cancel().catch(() => {}); throw new Error('The answer of the registration service is too long.'); } parts.push(value); }
    const bytes = new Uint8Array(size); let at = 0; for (const part of parts) { bytes.set(part, at); at += part.byteLength; }
    let answer = null; try { answer = JSON.parse(new TextDecoder().decode(bytes)); } catch { answer = null; }
    return { ok: response.ok, status: response.status, answer };
  };
  let facts = null;
  try { const got = await read('/v1/faucet'); if (got.ok) facts = got.answer; } catch { facts = null; }
  assert(facts && typeof facts === 'object', 'The registration service of this wallet does not answer. Nothing was sent. Try again in a minute.');
  assert(facts.network_id === network.networkId, 'The registration service of this wallet answers for another network. Nothing was sent.');
  const account = String(facts.account ?? '');
  assert(facts.registrations?.sponsored === true && /^(0|[1-9][0-9]*)$/.test(account), 'The registration service is not sponsoring new accounts now. Nothing was sent.');
  return { account, ask: async body => {
    let got;
    try { got = await read('/v1/faucet/registrations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
    catch { throw new Error('The registration service could not be reached, or did not answer in time. Unlock again to go on: if the registration was sent after all, the wallet finds it on the chain.'); }
    const answer = got.answer;
    if (got.ok && typeof answer?.hash === 'string' && /^[0-9a-f]{64}$/i.test(answer.hash)) return { hash: answer.hash.toLowerCase() };
    // The registration of this key with this very commitment waits on the chain already: go on from proven state.
    if (answer?.error?.code === 'already_committed' && answer.same_commitment === true) return { alreadyCommitted: true };
    // The refusal is the service's own text. It is marked as such, so that the notice shows it as a gateway's words
    // are shown (actions.mjs, failureNotice): after a sentence that says whose words follow, plain, and last.
    // Its code goes with it (`serviceCode`), for the one a protected sign-up words itself (signup.mjs, `account_limit`).
    throw Object.assign(new Error(typeof answer?.error?.message === 'string' ? answer.error.message.slice(0, 200) : `status ${got.status}`), { registrationService: true, serviceCode: typeof answer?.error?.code === 'string' ? answer.error.code.slice(0, 40) : '' });
  } };
}
async function registerAccount() {
  const check = fence.capture();
  // A sign-up protected from its first block that this browser keeps (signup-ui.mjs) goes its own way, whether its
  // account exists yet or not. The session's key is then its registration key, which is a key of no account.
  if (signupUI.staged(session.binding.name, session.binding.publicKey)) { await signupUI.register({ name: session.binding.name, registration: { publicKey: session.binding.publicKey, privateKey: session.privateKey }, salt: session.secret?.nameSalt, check }); return; }
  let state = await verifiedState(); check();
  const registrationOwner = `register-${session.binding.publicKey}`;
  const existing = ownAccount(state);
  if (existing) {
    // An account none of whose keys holds both powers may be protected. Whether this browser's key is on it decides
    // nothing here: a protected account's identity key is on no account, and a login key may have been removed. What
    // this browser can still do there is read from the account's security row by refresh (security-ui.mjs, withoutDevice).
    if (!currentDevice(existing) && needsSecurityRow(existing)) return;
    assert(currentDevice(existing), 'This name belongs to another device. Use new-device approval.');
    const previous = pending.get(network.networkId, registrationOwner); if (previous) pending.clear(network.networkId, registrationOwner, previous.hash);
    return;
  }
  assert(session.secret?.nameSalt, 'Registration salt is unavailable. Unlock your local vault again.');
  await withSigningLock(navigator.locks, network.networkId, registrationOwner, async () => {
    check(); const previous = pending.get(network.networkId, registrationOwner); if (!previous) return;
    state = await verifiedState(); check(); const tx = fromB64(previous.tx, 512*1024+512), action = sdk.decodeAction(tx);
    assert((await sdk.transactionHash(tx)) === previous.hash.toUpperCase(), 'Pending registration bytes are damaged.');
    const disposition = registrationPendingDisposition(state, session.binding, action);
    if (disposition === 'retry_exact') { notice('Resuming the exact signed registration action…', 'busy'); const receipt = await client.submit(tx).catch(async error => { throw await nameRefusal(error); }); check(); recordReceipt(receipt, previous.label); }
    // Identity operations carry no funds. Verified state can establish the same key/name outcome or signed expiry without fabricating a historical receipt.
    pending.clear(network.networkId, registrationOwner, previous.hash);
  });
  state = await verifiedState(); check();
  if (ownAccount(state)) return;
  let commit = state.name_commits?.find(c => c.public_key === session.binding.publicKey);
  const expected = await sdk.nameCommitment({ networkId: network.networkId, publicKey: session.binding.publicKey, name: session.binding.name, salt: session.secret.nameSalt }); check();
  if (!commit) {
    const sponsor=await registrationSponsor();check();
    // How long the consent, and with it the registration that waits for its name, is good for: five minutes, or the
    // longest the network allows if that is less. Ninety seconds, as before, were less than the waits that can follow
    // (the sponsor's receipt, the commitment in proven state, the next block) behind a slow service.
    const longest=/^[1-9][0-9]*$/.test(String(state.config?.registration?.max_lifetime_micros??''))?BigInt(state.config.registration.max_lifetime_micros):90000000n;
    // Twenty seconds under the network's longest, because the sponsor counts from the state it has read, which may be older.
    let ahead=longest-20000000n;if(ahead>300000000n)ahead=300000000n;if(ahead<60000000n)ahead=60000000n;
    const deadline=(BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros)+ahead).toString();
    const consent=sdk.sponsorConsentBytes({networkId:network.networkId,sponsorAccount:sponsor.account,publicKey:session.binding.publicKey,commitment:expected,expiresElapsedMicros:deadline});
    const proof=hex(await crypto.subtle.sign('Ed25519',session.privateKey,consent));check();
    const issued=await sponsor.ask({public_key:session.binding.publicKey,commitment:expected,expires_elapsed_micros:deadline,proof});check();
    if(issued.hash){const receipt=await client.waitReceipt(issued.hash);check();assert(sponsorReceiptBinds(receipt,session.binding.publicKey,expected),'Sponsor receipt does not bind this device and name commitment');recordReceipt(receipt,'Name reserved for you (sponsored)');}else assert(issued.alreadyCommitted===true,'Sponsor outcome unavailable; check the current proved commitment before retrying');
    // A receipt is verified a block ahead of the state this wallet reads next. The state is asked again until it
    // shows the commitment. (Seen in a browser on 2026-11-19, on a network with three blocks a second: the first
    // read came from the block before the sponsor's action, and the wallet stopped with "commitment differs".)
    for (const end = Date.now() + 30000; ; ) { state = await verifiedState(); check(); commit = state.name_commits?.find(c => c.public_key === session.binding.publicKey); if (commit || Date.now() > end) break; await new Promise(resolve => setTimeout(resolve, 400)); }
  }
  assert(commit, 'The registration is not in proven state yet. Unlock again in a moment: the wallet goes on from what the chain shows.');
  assert(commit.commitment === expected, 'The chain commitment differs from this local registration.');
  const until = Date.now() + 45000;
  while (BigInt(state.height) <= BigInt(commit.height) && Date.now() < until) { await new Promise(resolve => setTimeout(resolve, 500)); check(); state = await verifiedState(); }
  check(); assert(BigInt(state.height) > BigInt(commit.height), 'Waiting for the next committed block. Unlock again to resume registration.');
  await sendSigned('reveal', { name: session.binding.name, salt: session.secret.nameSalt }, 'Account created', { anonymous: true }).catch(async error => { throw await nameRefusal(error); }); check();
}
// A network may refuse a new name that looks like a name it already has. Its refusal comes through the gateway and
// names the existing name after the words "too close to an existing name" (names.mjs, tooCloseName). A gateway's words
// are never shown as the wallet's own, so the wallet takes that name only as where to look, and says its own sentence
// ("That name is too close to @x, which already exists. Choose another.") only after it has found both halves itself:
// by its own rule the two names look alike (names.mjs, resembles), and proven state holds an account of that name.
// Otherwise the error stays what it was, and is shown as a gateway's words are.
// It is asked here only, for the person's own new name: in a payment such a sentence would point at another name.
// The error is marked, so that `auth` does not tell the person to unlock again and go on: with this name there is
// nothing to go on with.
async function nameRefusal(error) {
  const existing = tooCloseName(error), own = session?.binding.name;
  if (existing === null || !own || resembles(own, existing) === null) return error;
  try { const state = await verifiedState({ names: [existing] }); if (!state.accounts.some(a => a.name === existing)) return error; } catch { return error; }
  return Object.assign(new Error(tooCloseWords(existing)), { nameRefused: true });
}
async function auth(event) {
  event.preventDefault(); if (busy) return;
  const check = fence.capture(), name = validateName($('username').value), password = $('password').value;
  try {
    assert(network && latest?.verified, 'Waiting for an independently verified network.');
    if (mode !== 'unlock') { checkPassword(password, name); assert(password === $('password-confirm').value, 'Passwords do not match.'); }
    // A new account needs a sponsor for its registration. A wallet whose service names none says so before it makes
    // a key or stores a vault: nothing is left behind for a name that could not be registered.
    if (mode === 'create') assert((typeof network.sponsorAccount === 'string' && /^(0|[1-9][0-9]*)$/.test(network.sponsorAccount)) || (typeof network.registrationService === 'string' && network.registrationService !== ''), 'This wallet cannot register a new account here: its service names no registration sponsor. Nothing was created.');
    // On a network that takes them, a new account is protected from its first block (signup-ui.mjs): its recovery papers
    // come next, and the account is made once they are checked (signupCreated). Nothing is kept before.
    if (mode === 'create' && signupUI.on()) { await signupUI.begin({ name, login: password }); return; }
    setBusy(true, mode === 'unlock' ? 'Unlocking your key with your password. This takes a few seconds…' : 'Locking your new key with your password. This takes a few seconds…');
    let unlocked;
    if (mode === 'unlock') {
      const raw = localStorage.getItem(vaultKey(name));
      // The test network was reset, and this browser keeps accounts of the old one only (reset.mjs): that, and not "New device".
      if (!raw && resetSeen(Object.keys(localStorage), network.networkId)) throw new Error(resetOpenWords(name, elsewhere(Object.keys(localStorage), network.networkId).names));
      assert(raw, 'No encrypted vault for this account is stored in this browser. Choose New device to request approval.');
      unlocked = await openVault(JSON.parse(raw), password, globalThis.hashwasm?.argon2id); check();
      assert(unlocked.binding.networkId === network.networkId && unlocked.binding.name === name, 'Vault belongs to another account or network.');
    } else {
      unlocked = await navigator.locks.request(`timecurrency:vault:${network.networkId}:${name}`, { mode: 'exclusive' }, async () => {
        check(); assert(!localStorage.getItem(vaultKey(name)), 'An encrypted vault already exists for this account here. Unlock it instead.');
        const state = await verifiedState(); check(); const found = state.accounts.find(a => a.name === name);
        const existingMode = mode === 'link' || mode === 'recover';
        assert(existingMode ? Boolean(found) : !found, existingMode ? 'This account does not exist on the verified chain.' : 'That username is already registered.');
        const device = await newDevice(); check();
        const binding = { networkId: network.networkId, name, publicKey: device.publicKey };
        device.secret.nameSalt = hex(crypto.getRandomValues(new Uint8Array(32)));
        device.secret.intent = mode === 'recover' ? 'recovery' : 'device';
        const record = await sealVault(device.secret, password, binding, globalThis.hashwasm?.argon2id); check();
        // Write the encrypted vault before any registration transaction. Storage failure aborts signup.
        localStorage.setItem(vaultKey(name), JSON.stringify(record));
        return { ...device, binding };
      });
    }
    check(); session = unlocked; session.intent = unlocked.secret.intent; $('password').value = $('password-confirm').value = ''; $('lock-button').hidden = false; readActivity(); upgrades?.unlocked(); paidNamesNow();
    // A protected sign-up kept in this browser goes on from what the chain shows, also when its account exists already
    // and only its keys were not put in place (signup-ui.mjs). Its new login key then holds the place the login password
    // opened, and opens the account.
    const signingUp = mode === 'unlock' && signupUI.staged(name, session.binding.publicKey);
    if (mode === 'create' || signingUp || (mode === 'unlock' && !ownAccount())) { $('auth-progress').textContent = signingUp ? 'Creating your protected account on the network. This takes a few seconds…' : 'Registering your name on the network. This takes a few seconds…'; await registerAccount(); check(); }
    if (signingUp) await reopen(name, password, check);
    await opened(check, signingUp ? PROTECTED_READY : mode === 'create' ? 'Your account is ready. This browser checked it with the network. Next: keep your account safe under Keys.' : 'Your account is open. This browser checked your balance with the network.');
  // A name the network refused as too close to another (nameRefusal) cannot be gone on with: the wallet says so, as an error, and shows the form for a new account again.
  } catch (error) { openFailed(error, check); }
  finally { try { check(); $('password').value = $('password-confirm').value = ''; setBusy(false); } catch {} }
}
const PROTECTED_READY = 'Your account is ready, protected from its first block. This browser checked it with the network. Next time, open it with your name and your login password.';
/// The login place of a protected sign-up holds its new login key now (signup-ui.mjs, register): the session moves to it,
/// opened with the same password, and the registration key, which is on no account, is forgotten.
async function reopen(name, password, check) {
  const raw = localStorage.getItem(vaultKey(name)); assert(raw, 'Your account was made, and its login key is not in this browser. Reload this page.');
  const unlocked = await openVault(JSON.parse(raw), password, globalThis.hashwasm?.argon2id); check();
  assert(unlocked.binding.networkId === network.networkId && unlocked.binding.name === name, 'Vault belongs to another account or network.');
  forgetSecret(session.secret); session.privateKey = null; session = unlocked; session.intent = unlocked.secret.intent;
}
/// The end of a protected sign-up whose papers were checked and whose keys this browser keeps now (signup-ui.mjs): the
/// account is created with the registration key, and then opened with its new login key, which this page still holds.
async function signupCreated({ name, registration, salt, signin }) {
  const check = fence.capture();
  session = { privateKey: registration.privateKey, binding: { networkId: network.networkId, name, publicKey: registration.publicKey }, secret: { nameSalt: salt }, intent: 'device' };
  $('lock-button').hidden = false; readActivity(); upgrades?.unlocked(); paidNamesNow();
  try {
    setBusy(true, 'Creating your protected account on the network. This takes a few seconds…');
    await registerAccount(); check();
    session = { privateKey: signin.privateKey, binding: { networkId: network.networkId, name, publicKey: signin.publicKey }, secret: null };
    await opened(check, PROTECTED_READY);
  } catch (error) { openFailed(error, check); }
}
/// What follows opening an account: the first verified reading, then one every five seconds, and what the notice says.
async function opened(check, said) {
    await refresh(); check(); forgetSecret(session.secret); session.secret = null; scheduleIdleLock(); clearInterval(refreshTimer); refreshTimer = setInterval(() => {
      // One refresh at a time. And what a refresh reports is this session's business only: one that was still
      // running when the wallet was locked, or when another session began, says nothing and changes nothing.
      if (busy || !session || refreshing) return;
      const sameSession = fence.capture(); refreshing = true;
      refresh().catch(async e => { try { sameSession(); } catch { return; } latest = null; renderAvailability(); upgradeRequired(e); if (await networkReset()) return; try { sameSession(); } catch { return; } notice(`Verification paused. ${failureNotice(e, 'No reason was given.')}`, 'error'); }).finally(() => { refreshing = false; });
    }, 5000);
    if (currentDevice(ownAccount())) notice(said);
}
/// A failure while an account is opened or created. A refusal of a protected sign-up in its own words (signup-ui.mjs,
/// `signup`) is said as it is: what is kept goes on at the next opening.
function openFailed(error, check) {
  try { check(); const message=failureNotice(error,'Could not open wallet.');if(session&&error?.nameRefused===true){lock(message);setMode('create');notice(message,'error');}else if(session&&error?.signup===true){lock(message);notice(message,'error');}else if(session)lock('The encrypted vault is saved. Unlock again to resume safely. '+message);else notice(message,'error'); upgradeRequired(error); networkReset().catch(() => {}); } catch {}
}
// ---------------------------------------------------------------- a test network that was reset (reset.mjs)
// A page that is open while its network is reset fails to verify. After a failure it reads the site's trust file again
// (at most every half minute); when that names another network, it says only that, and signs nothing more.
const trustAgain = trustReader({ read: async () => { const response = await fetch('/trust-manifest.json', { cache: 'no-store', redirect: 'error' }); if (!response.ok) throw new Error('The trust file could not be read.'); return response.json(); } });
async function networkReset() {
  if (!network || !await trustAgain.changed(network.networkId)) return false;
  latest = null; renderAvailability(); notice(RESET_RELOAD, 'error'); return true;
}
/// The start screen of a browser that keeps accounts of the old network only: what happened, and one button that removes
/// what this browser keeps of the old network, and nothing else.
function showReset() {
  const keys = Object.keys(localStorage), shown = Boolean(network) && resetSeen(keys, network.networkId);
  $('reset-note').hidden = !shown; if (!shown) return;
  const { names } = elsewhere(keys, network.networkId);
  $('reset-text').textContent = resetWords(names);
  $('reset-forget').textContent = names.length === 1 ? 'Remove the old account from this browser' : 'Remove the old accounts from this browser';
}
async function forgetOldNetwork() {
  const keys = Object.keys(localStorage), gone = oldEntries(keys, network.networkId), { names } = elsewhere(keys, network.networkId);
  if (!gone.length) return showReset();
  if (!await review('Remove the old test network from this browser', [['Accounts', names.map(name => '@' + name).join(', ')], ['What goes', `What this browser kept of the test network before its reset: ${gone.length} entr${gone.length === 1 ? 'y' : 'ies'}, the old keys among them. They open nothing now.`], ['What stays', 'Everything of the test network that runs now.'], ['Afterwards', 'It cannot be undone.']], 'Remove them')) return;
  for (const key of oldEntries(Object.keys(localStorage), network.networkId)) localStorage.removeItem(key);
  showReset(); notice('Removed. This browser keeps nothing of the test network before its reset.');
}
async function refresh() {
  const check = fence.capture(); const state = await verifiedState(); check();
  $('network-status').textContent = `Network checked · block ${state.height}`; $('network-dot').className = 'good';
  $('upgrade-required').hidden = true; checkUpgrade().catch(() => {});
  if (!session) { renderAvailability(); return; }
  const account = ownAccount(state); assert(account, 'Account is not finalized yet. Unlock again to resume registration.');
  for (const slot of [String(account.id), emergencyCancelSlot(account.id), nonceCancelSlot(account.id)]) {
    const reservation = pending.get(network.networkId, slot);
    if (reservation && (slot !== String(account.id) ? emergencyReservationObsolete(account, reservation) : authorityReservationObsolete(account, reservation))) pending.clear(network.networkId, slot, reservation.hash);
  }
  const device = currentDevice(account);
  const wasAwaitingApproval = !$('enrollment-panel').hidden || !$('recovery-claim-panel').hidden;
  $('auth-panel').hidden = true; $('lock-button').hidden = false;
  $('dashboard').hidden = !device; $('enrollment-panel').hidden = Boolean(device) || session.intent === 'recovery'; $('recovery-claim-panel').hidden = Boolean(device) || session.intent !== 'recovery';
  if (!device) {
    if (await securityUI.withoutDevice(account, state)) { check(); renderAvailability(); return; }
    if (session.intent === 'recovery') { await recoveryUI.renderClaim(account, state); check(); notice('This new key needs the approvals of your guardians, then the whole waiting period.', 'busy'); }
    else { await showEnrollment(account); check(); notice('This browser is not approved yet. Paste its request in a browser where your account is open: More, Devices.', 'busy'); }
    renderAvailability(); return;
  }
  // Home: the balance, the name, and that this browser checked them against the network itself.
  $('account-name').textContent = $('receive-name').textContent = $('more-name').textContent = '@' + account.name;
  $('account-initial').textContent = $('more-initial').textContent = account.name.slice(0, 1).toUpperCase();
  $('account-number').textContent = `Account number ${account.id}`; $('receive-number').textContent = String(account.id); $('balance').textContent = seconds(account.balance);
  $('account-verification').textContent = 'Checked by this browser'; $('account-verification').className = 'badge ok'; $('proof-height').textContent = `against the network at block ${state.height}`;
  $('approval-account').textContent = `As @${account.name}. You have ${seconds(account.balance)} seconds.`; $('approval-account').hidden = false;
  $('fee-label').textContent = seconds(networkFee()); $('bank-pot').textContent = seconds(state.bank) + ' s'; $('auction-epoch').textContent = String(state.auction_epoch);
  // A network that pays all new time to validators and their stakers has no bitcoin auction: staking is how to earn.
  // The auction's card is in More, Staking, and only on a network that has it.
  const stakersEarnAll = state.config.all_new_time_to_validators === true;
  $('auction-card').hidden = stakersEarnAll; $('stake-intro').hidden = !stakersEarnAll;
  // What starting validators earn is staked for them only on a network without the stake hand-over rule
  // (v5/src/pos_adapter.rs, bond_bootstrap): the sentence that says so is shown there only.
  const handover = state.config.stake_handover === true;
  $('stake-intro-bonding').hidden = handover; $('stake-intro-handover').hidden = !handover;
  $('stake-eyebrow').textContent = stakersEarnAll ? 'Stake to earn' : 'Staking';
  $('stake-title').textContent = stakersEarnAll ? 'Earn new seconds by staking.' : 'Put some seconds to work.';
  posUI.render(account,state);
  const earningKey='timecurrency.v4.epochs:'+network.networkId+':'+account.id,epochs=JSON.parse(localStorage.getItem(earningKey)||'[]').slice(-8);
  $('earning-claims').replaceChildren();if(epochs.length){const earned=await client.getVerifiedState({ids:[account.id],epochs});check();for(const epoch of epochs){const summary=earned.state.earning_epochs[epoch],bid=earned.state.earning_bids[epoch+':'+account.id];if(bid)$('earning-claims').append(row(`Epoch ${epoch}: ${bid.sats} test sats`,bid.claimed?'Already claimed':summary?.closed?'Closed: ready to claim':'Waiting for epoch close',!bid.claimed&&summary?.closed?'Claim seconds':null,async()=>{if(!await review('Claim earned seconds',[['Epoch',epoch],['Credit','Your pro-rata share of the authenticated epoch pot. Fee zero.']]))return;setBusy(true);await sendSigned('claim_auction',{epoch},'Claim earned seconds');await refresh();notice('Earned seconds claimed and verified.');}));}}
  $('notification-list').replaceChildren();for(const claim of state.recovery_cases.filter(r=>r.target===account.id))$('notification-list').append(textNode('p',claim.ready_elapsed_micros!==null?'Your guardians approved a recovery: spending is frozen. If you did not ask for it, cancel it now (More, Guardian recovery).':'A guardian recovery of your account is waiting for approvals. Check the new key (More, Guardian recovery).'));
  client.request('/api/notifications?account='+account.id).then(inbox=>{if(session?.binding.name===account.name){for(const item of (Array.isArray(inbox?.items)?inbox.items:[]).slice(-8)){const line=gatewayNotification(item);if(line)$('notification-list').append(textNode('p',line,'subtle'));}syncInbox();}}).catch(()=>{});
  $('device-list').replaceChildren();
  for (const d of account.devices) {
    const mine = d.public_key === session.binding.publicKey;
    const r = row(mine ? 'This browser' : 'Another browser', `${d.public_key} · ${d.can_spend ? 'can pay' : 'cannot pay'} · ${d.can_manage ? 'can add and remove browsers' : 'cannot add or remove browsers'}`, device.can_manage ? 'Remove' : null, async () => {
      if (!await review('Remove a browser', [['Public key', d.public_key], ['Effect', mine ? 'This browser will lose access to the account.' : 'This key, and every backup file of it, will lose access to the account.'], ['Fee', seconds(networkFee()) + ' seconds']], 'Remove it')) return;
      setBusy(true); await sendSigned('revoke_device', { public_key: d.public_key }, 'Remove a browser');
      if (mine) lock('This browser was removed from the account. Its locked key stays here, but it can no longer sign for the account.'); else { await refresh(); notice('The browser was removed from the account.'); }
    }); $('device-list').append(r);
  }
  recoveryUI.render(account, state); securityUI.render(account, state); signalUI.render(account, state); renderKeys(account, state); renderActivity(); renderAvailability();
  if (wasAwaitingApproval && !busy) notice('This browser is now approved. It checked your account and balance with the network.');
}
// ---------------------------------------------------------------- Keys
// What the person holds, by the state of the account (actions.mjs, keysView). A protected account is one with a
// security row in the verified state (the same test as security-flows.mjs, accountSecured).
function securityRow(account, state) { return Array.isArray(state?.security) ? state.security.find(r => r.account === String(account.id)) || null : null; }
function renderKeys(account, state) {
  const row = securityRow(account, state), slots = vaultSlots(network.networkId, account.name);
  let paymentKeyHere = false; try { paymentKeyHere = localStorage.getItem(slots.spend) !== null; } catch { paymentKeyHere = false; }
  // The limit in force and whether payments are paused, as the Protection card on Home reads them (protection.mjs): on
  // the clock of the waits, which a stop of the chain does not move (security-flows.mjs, waitsOf).
  const now = waitsOf(sdk, state);
  const view = keysView({ protectedAccount: Boolean(row), name: account.name, limit: row ? seconds(effectiveLimit(row, now)) + ' seconds' : '', waiting: row ? durationWords(row.policy.delay_seconds) : '',
    paused: Boolean(row) && pauseState(row, now, networkFee()) !== 'off',
    paymentKeyHere, guardians: Boolean(account.recovery_policy), otherKeys: account.devices.filter(d => d.public_key !== session.binding.publicKey).length });
  $('keys-lede').textContent = view.lede;
  $('keys-cards').replaceChildren(...view.cards.map(keyCard));
  $('keys-note').textContent = view.note; $('keys-note').hidden = !view.note;
  $('keys-change').hidden = !row;
  $('backup-export-label').textContent = row ? 'Your login password, to unlock the file once' : 'Your password, to unlock the file once';
  $('home-backup').hidden = Boolean(row) || backupSaved(session.binding);
  syncInbox();
}
function keyCard(card) {
  const box = document.createElement('article'); box.className = 'key-card ' + card.mark; box.dataset.key = card.id;
  const head = document.createElement('header'); head.append(textNode('h3', card.title), textNode('span', card.markText, 'tag ' + card.mark)); box.append(head);
  const list = document.createElement('dl'); for (const [term, text] of card.rows) list.append(textNode('dt', term), textNode('dd', text)); box.append(list);
  return box;
}
// The card "Waiting on your account" (filled by security-ui.mjs and above): shown while something in it asks for
// the person: an item to send or cancel, a protective action without its receipt, a guardian recovery or an alert.
function syncInbox() {
  const has = id => ($(id).children?.length || 0) > 0;
  $('security-inbox-card').hidden = $('inbox-keys').hidden && !has('security-pending') && !has('notification-list');
}
function printKeys() { document.body.classList.add('print-keys'); try { window.print(); } finally { document.body.classList.remove('print-keys'); } }
// ---------------------------------------------------------------- the screens
// Home, Payments, Activity, Keys and More are the five places of the dashboard; Receive is the other half of Payments,
// and the rows of More open their own screens (staking, devices, ...). Nothing is lost by moving between them: a
// screen is only hidden.
const MORE_PANELS = new Set(['earn', 'devices', 'recovery', 'upgrade', 'integrate', 'validator']);
function showPanel(name) {
  for (const panel of document.querySelectorAll('.workspace-panel')) panel.hidden = panel.id !== 'panel-' + name;
  const lit = MORE_PANELS.has(name) ? 'more' : name === 'receive' ? 'send' : name;
  for (const button of document.querySelectorAll('.nav [data-panel]')) {
    const on = button.dataset.panel === lit; button.classList.toggle('active', on);
    if (on) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  }
}
function clearHome() {
  $('balance').textContent = '—'; $('account-name').textContent = '@—'; $('account-number').textContent = ''; $('proof-height').textContent = '';
  $('account-verification').textContent = 'Not checked yet'; $('account-verification').className = 'badge';
  $('approval-account').hidden = true; $('approval-account').textContent = '';
  $('send-result').hidden = true; $('send-result-text').textContent = ''; $('home-backup').hidden = true; $('home-pending').hidden = true;
  $('home-activity').replaceChildren(); $('keys-cards').replaceChildren(); $('keys-lede').textContent = '';
  // Nothing of the last account stays on the page: its initial, its name under More, the names it paid, what it staked,
  // a search, a payment typed and not sent, its activity and what it had pending, its name and number under Receive.
  $('account-initial').textContent = $('more-initial').textContent = $('more-name').textContent = ''; $('home-staked').textContent = $('bonded').textContent = '—';
  $('paid-names').replaceChildren(); $('paid-names-wrap').hidden = true; $('paid-names-alike').hidden = true; drawnPaidNames = null; $('activity-search').value = ''; $('activity-none').hidden = true;
  $('recipient').value = $('amount').value = $('send-payment').value = ''; $('activity-list').replaceChildren(); $('pending-panel').replaceChildren();
  $('receive-name').textContent = '@—'; $('receive-number').textContent = '';
}
// "Names you paid from this browser", under the name of a payment: a tap puts the name in the field, nothing else. They
// are the names the review compares a new name with (names.mjs), so a name taken from here is one already paid, and its
// review asks nothing more (the person ticked the check when it was new). Two of them that look alike are therefore both
// marked here, where one of the two is picked, with one sentence under them. The chips are drawn again only when the
// list changes, so a refresh does not take the focus from a chip or a tap from under a finger.
let drawnPaidNames = null;
function renderPaidNames() {
  const names = session ? paidNamesNow().slice(-6).reverse() : [], key = names.join(' ');
  if (key === drawnPaidNames) return; drawnPaidNames = key;
  let anyAlike = false;
  $('paid-names').replaceChildren(...names.map(name => {
    const alike = lookAlike(name, names.filter(other => other !== name)) !== null; anyAlike ||= alike;
    const chip = textNode('button', '@' + name, alike ? 'chip alike' : 'chip'); chip.type = 'button';
    chip.addEventListener('click', () => { $('recipient').value = name; $('send-result').hidden = true; $('amount').focus?.(); });
    return chip;
  }));
  $('paid-names-wrap').hidden = names.length === 0; $('paid-names-alike').hidden = !anyAlike;
}
// The search of Activity: it hides the rows whose words do not hold what was typed. It only reads the page.
function filterActivity() {
  const words = $('activity-search').value.trim().toLowerCase(); let shown = 0, rows = 0;
  for (const item of $('activity-list').children || []) {
    if (!String(item.className || '').split(/\s+/).includes('row')) continue;
    rows += 1; item.hidden = words !== '' && !(item.textContent || '').toLowerCase().includes(words); if (!item.hidden) shown += 1;
  }
  $('activity-none').hidden = !(rows > 0 && shown === 0);
}
// "Sent": in the notice, and where the person is, under the form.
function showSent(name, amountText) {
  const words = sentNotice(name, amountText);
  $('send-result-text').textContent = words.replace(/^Sent\. /, ''); $('send-result').hidden = false; notice(words);
}
// ---------------------------------------------------------------- "Get test time"
// One press asks the test faucet (the registration service the wallet's service names) for one grant for this account
// (actions.mjs, askFaucet). The faucet's word that it sent something is not taken: the wallet waits for the receipt of
// the action it names and checks that it is a transfer to this account (faucetReceiptPays), then reads the balance.
async function getTestTime() { await run(async () => {
  const check = fence.capture(), account = ownAccount(); assert(session && account && currentDevice(account), 'Open your account first.');
  setBusy(true, 'Asking the test faucet…'); notice('Asking the test faucet for test time…', 'busy');
  const { hash, faucetAccount } = await askFaucet({ origin: network.registrationService, account: String(account.id), networkId: network.networkId }); check();
  notice('The test faucet is sending test time. This browser is checking that it arrives…', 'busy');
  let receipt = null;
  try { receipt = await client.waitReceipt(hash, { timeoutMs: 30000 }); } catch (error) { if (sdk.isUpgradeRequired?.(error)) throw error; receipt = null; }
  check();
  if (receipt && faucetReceiptPays(receipt, String(account.id), faucetAccount)) {
    recordReceipt(receipt, 'Test time from the faucet'); await refresh(); check();
    notice(`You received ${seconds(receipt.action.payload.amount)} seconds of test time. This browser checked that it arrived.`);
  } else { await refresh(); check(); notice('The test faucet says that it sent test time. This browser has not seen it arrive yet: your balance changes by itself when it does.'); }
}); }
async function showEnrollment(account) {
  const check = fence.capture();
  const request = { version: 1, networkId: network.networkId, accountId: String(account.id), authEpoch: String(account.auth_epoch), publicKey: session.binding.publicKey, canManage: true, canSpend: true };
  const bytes = sdk.deviceProofBytes(request);
  request.proof = hex(await crypto.subtle.sign('Ed25519', session.privateKey, bytes)); check();
  $('enrollment-code').value = JSON.stringify(request);
}
async function sendForm(event) {
  event.preventDefault(); $('send-result').hidden = true; await run(async () => {
    const name = validateName($('recipient').value), amount = parseSeconds($('amount').value), check = fence.capture();
    const state = await verifiedState({ names: [name] }); check(); const to = state.accounts.find(a => a.name === name);
    assert(to, 'No account has that name on this network. Check the spelling.');
    const from = ownAccount(state), fee = networkFee();
    assert(from && BigInt(from.balance) >= BigInt(amount) + BigInt(fee), 'You do not have enough seconds for this amount and the fee.');
    assert(String(to.id) !== String(from.id), 'That is your own name. Send to someone else.');
    if (securityUI.secured(state, from)) return securityUI.pay({ name, to, amount, state, account: from });
    if (!await review('Send seconds', [['From', `@${from.name} · account ${from.id}`], ['To', `@${name} · account ${to.id}`], ['Amount', seconds(amount) + ' seconds'], ['Fee', seconds(fee) + ' seconds'], ['Total', seconds(BigInt(amount) + BigInt(fee)) + ' seconds'], ['Network', 'Time test network · ' + network.networkId], ['When', 'In the next block, within seconds. Once it is in a block, it cannot be undone.']], `Send ${seconds(amount)} seconds`, { payee: name })) return;
    check(); setBusy(true); await sendSigned('transfer', { to: String(to.id), amount }, `Send ${seconds(amount)} s to @${name}`); check(); await refresh(); $('amount').value = ''; showSent(name, seconds(amount));
  });
}
async function bidForm(event){event.preventDefault();await run(async()=>{
 const check=fence.capture(),state=await verifiedState(),account=ownAccount(state),config=state.config.auction,elapsed=BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros);
 assert(state.config.all_new_time_to_validators!==true,'This network has no bitcoin auction. Earn new seconds by staking.');
 assert(!state.treasury.paused&&!state.treasury.pending,'Treasury receiving is paused or rotating. Request a new funding quote after it resumes.');
 const epoch=(elapsed/(BigInt(config.epoch_seconds)*1000000n)+BigInt(config.bid_lead_epochs)+3n).toString();
 if(!await review('Fund a Bitcoin regtest earning bid',[['Account',account.id],['Target epoch',epoch],['Bitcoin network','REGTEST only. Locally mined test BTC has no monetary value.'],['Treasury policy',String(state.receiving_policy.revision)],['Credit','Exact account/network/epoch/policy commitment is checked by the ledger. A separate claim distributes seconds after close.']]))return;
 check();setBusy(true);notice('Mining and proving a Bitcoin regtest payment with private local Bitcoin Core?','busy');
 const result=await client.request('/api/regtest-bid',{method:'POST',body:JSON.stringify({account:account.id,epoch})});check();
 if(result.network!=='regtest'||!Array.isArray(result.headersHex)||!result.receipt)throw Error('Regtest fixture proof unavailable');
 let current=await verifiedState();check();const headerHeight=Number(current.bitcoin.meta.best_height),headers=result.headersHex.slice(headerHeight);for(let at=0;at<headers.length;at+=256){await client.submit(sdk.publicHeadersAction(network.networkId,headers.slice(at,at+256)));check();}
 const payload={epoch,policy_revision:String(state.receiving_policy.revision),receipt:sdk.compactBitcoinReceipt(result.receipt)};
 await sendSigned('bitcoin_bid',payload,'Bitcoin regtest earning receipt');
 const key='timecurrency.v4.epochs:'+network.networkId+':'+account.id,known=JSON.parse(localStorage.getItem(key)||'[]');if(!known.includes(epoch)){known.push(epoch);localStorage.setItem(key,JSON.stringify(known.slice(-64)));}await refresh();notice('Regtest BTC receipt finalized. Claim this epoch after it closes.');
});}
async function stakeForm(event) { event.preventDefault(); await run(async () => {
  const amount = parseSeconds($('stake-amount').value), operator = $('operator').value, check = fence.capture(); assert(/^[0-9]+$/.test(operator), 'Choose an operator pool.');
  const state=await verifiedState({candidates:[operator]});check();const candidate=state.candidates[operator];assert(candidate,'Unknown candidate');assert(!candidate.archived&&!candidate.jailed,'This pool is archived or jailed and cannot accept new delegation');const pool={total_shares:candidate.pool_shares,assets:candidate.pool_assets};
  const quotedShares = poolSharesForDeposit(pool, amount);
  if (securityUI.secured(state, ownAccount(state))) return securityUI.stake({ operator, amount, quotedShares, state, account: ownAccount(state) });
  if (!await review('Delegate test seconds', [['Operator account', operator], ['Amount', seconds(amount) + ' seconds'], ['Current share estimate', quotedShares + ' shares; priced at pool NAV when finalized'], ['Execution protection', 'At least 1 share and at most 0.1% integer-rounding loss, enforced by the ledger. Reward growth can fairly change the share count.'], ['Fee', seconds(networkFee()) + ' seconds'], ['Availability', 'Voting power removal at H+2 followed by the full 14-day slash window.']])) return;
  check(); setBusy(true); await sendSigned('delegate', { operator, amount, min_shares: '1' }, 'Delegate seconds'); await refresh(); notice('Delegation finalized. Pool shares are now bonded.');
}); }
async function approveDevice(event) { event.preventDefault(); await run(async () => {
  const raw = $('device-request').value; assert(raw.length < 4096, 'Enrollment request is too large.'); let r; try { r = JSON.parse(raw); } catch { throw new Error('Paste a valid public enrollment request.'); }
  assert(Object.keys(r).sort().join(',') === 'accountId,authEpoch,canManage,canSpend,networkId,proof,publicKey,version', 'Unknown or missing enrollment fields.');
  const state = await verifiedState(), account = ownAccount(state), check = fence.capture();
  assert(r.version === 1 && r.networkId === network.networkId && r.accountId === String(account.id) && r.authEpoch === String(account.auth_epoch), 'Request belongs to another account/network or has an obsolete authority epoch. Generate it again on the new device.');
  assert(typeof r.canManage === 'boolean' && typeof r.canSpend === 'boolean' && /^[0-9a-f]{64}$/.test(r.publicKey) && /^[0-9a-f]{128}$/.test(r.proof), 'Invalid enrollment proof fields.');
  const publicKey = await crypto.subtle.importKey('raw', sdk.hexToBytes(r.publicKey), 'Ed25519', false, ['verify']);
  assert(await crypto.subtle.verify('Ed25519', publicKey, sdk.hexToBytes(r.proof), sdk.deviceProofBytes(r)), 'New device proof of key possession failed.'); check();
  if (!await review('Approve a new device', [['New public key · compare on both devices', r.publicKey], ['Spend authority', r.canSpend ? 'Can send and stake your seconds' : 'No'], ['Management authority', r.canManage ? 'Can add and revoke devices' : 'No'], ['Fee', seconds(networkFee()) + ' seconds']], 'Approve this device')) return;
  check(); setBusy(true); await sendSigned('add_device', { public_key: r.publicKey, can_manage: r.canManage, can_spend: r.canSpend, proof: r.proof }, 'Approve new device'); await refresh(); $('device-request').value = ''; notice('The new browser is approved. In that browser, press “Check again” to start using the account.');
}); }
function setupApproval() {
  if (location.pathname !== '/approve') return;
  // The window a website opens: only the request and, while locked, the way to open the account.
  document.body.classList.add('approve-mode');
  $('approval-panel').hidden = false; $('approval-origin').textContent = '';
  $('approval-details').textContent = 'Open your account below. Nothing is approved by itself: you check the website and decide.';
  window.addEventListener('message', event => {
    try {
      if (approval || !event.data || event.data.type !== 'time:request') return;
      approval = acceptApprovalEvent(event, window.opener);
      const r = approval.request; $('approval-origin').textContent = approval.origin;
      $('approval-title').textContent = r.type === 'login' ? 'Sign in to this website?' : r.type === 'payment' ? 'Pay this website?' : 'Standing permissions are not available';
      $('approval-details').replaceChildren(textNode('p', r.type === 'login' ? 'Sign in only. The website learns which account you are, once. It cannot pay and cannot change anything.' : r.type === 'payment' ? `Pay exactly ${seconds(r.amount)} seconds to account ${r.to}, once. Nothing more.` : 'This wallet gives no website a standing permission to spend. Nothing will be granted.'));
      if (r.type === 'grant') notice('Standing permissions to spend are not available in this wallet.', 'error');
      renderAvailability();
    } catch (error) { notice(failureNotice(error), 'error'); }
  });
  // Only this non-sensitive readiness signal uses a wildcard. Results always target the verified requester origin.
  window.opener?.postMessage({ type: 'time:ready', version: 1 }, '*');
}
async function approveWebsite() { await run(async () => {
  assert(approval && session, 'Unlock an enrolled device before approval.');
  const requested = approval, check = fence.capture(), state = await verifiedState(requested.request.type === 'payment' ? { ids: [requested.request.to] } : {}), account = ownAccount(state);
  assert(currentDevice(account), 'This device is not approved.'); assert(requested.request.type !== 'grant', 'Standing spending grants are not supported.');
  assert(!recoveryFrozen(state, account.id), 'Account recovery is in its guardian delay. Website login and spending are frozen until canceled or finalized.');
  let result;
  if (requested.request.type === 'login') {
    const challenge = requested.request.challenge;
    assert(challenge.origin === requested.origin && challenge.networkId === network.networkId, 'Wrong login audience or network.');
    const refusal = securityUI.loginRefusal(state, account); assert(!refusal, refusal);
    if (!await review('Approve website login', [['Website', requested.origin], ['Account', '@' + account.name], ['Permission', 'Sign in only. It cannot pay, and cannot change your keys.'], ['Expires', new Date(challenge.expiresAt).toLocaleString()]], 'Sign in')) return;
    check(); setBusy(true);
    result = await sdk.signLogin(challenge, { account, publicKey: session.binding.publicKey, privateKey: session.privateKey }); check();
  } else {
    const r = requested.request;
    assert(r.networkId === network.networkId && typeof r.to === 'string' && /^[0-9]+$/.test(r.to) && typeof r.amount === 'string' && /^[1-9][0-9]*$/.test(r.amount), 'Invalid payment network, account or integer amount.');
    assert(typeof r.orderId === 'string' && /^[0-9a-f]{64}$/.test(r.orderId), 'Payment order must have a fresh 32-byte hexadecimal reference.');
    // Checked against the state just verified; checkMerchantQuote reads the version from it.
    sdk.checkMerchantQuote(r.orderId,(BigInt(account.nonce)+1n).toString(),state);
    const recipient = state.accounts.find(a => String(a.id) === r.to); assert(recipient, 'Recipient does not exist.');
    if (securityUI.secured(state, account)) {
      const receipt = await securityUI.payWebsite({ request: r, origin: requested.origin, account, state, recipient }); if (!receipt) return; check(); paidNamesNow(recipient.name);
      result = { receipt, transactionHash: receipt.hash, accountId: String(account.id), networkId: network.networkId, orderId: r.orderId };
    } else {
    assert(currentDevice(account).can_spend, 'This device cannot spend.');
    const fee = networkFee(); assert(BigInt(account.balance) >= BigInt(r.amount) + BigInt(fee), 'Insufficient seconds including the fee.');
    if (!await review('Approve website payment', [['Website', requested.origin], ['Order', r.orderId], ['Recipient', `@${recipient.name} · account ${recipient.id}`], ['Amount', seconds(r.amount) + ' seconds'], ['Fee', seconds(fee) + ' seconds'], ['Total', seconds(BigInt(r.amount) + BigInt(fee)) + ' seconds']], 'Pay & sign', { payee: recipient.name })) return;
    check(); setBusy(true); const receipt = await sendSigned('merchant_payment', { to: r.to, amount: r.amount, reference: r.orderId }, `Website payment ${r.orderId}`, { merchantOrigin: requested.origin }); check(); paidNamesNow(recipient.name);
    result = { receipt, transactionHash: receipt.hash, accountId: String(account.id), networkId: network.networkId, orderId: r.orderId };
    }
  }
  check(); window.opener?.postMessage({ type: 'time:response', version: 1, id: requested.id, result }, requested.origin);
  $('approve-request').disabled = true; approval = null; $('approval-title').textContent = 'Done'; $('approval-details').textContent = 'The answer went to this website only. You can close this window.';
}); }
async function start() {
  setupApproval();
  try {
    assert(globalThis.isSecureContext, 'Open the wallet on localhost or HTTPS. This origin cannot use secure browser cryptography.');
    assert(sdk && globalThis.hashwasm?.argon2id, 'A required local SDK or Argon2id asset is unavailable. No signing is allowed.');
    assert(navigator.locks?.request, 'Web Locks are required to coordinate safe signing across tabs.');
    const pinResponse=await fetch('/trust-manifest.json',{cache:'no-store',redirect:'error'});assert(pinResponse.ok,'Installed trust manifest unavailable');const trust=await pinResponse.json();client=sdk.createClient({trust,verifier:installedVerifier});network=await client.getNetwork();
    // No version is shown yet: the badge and the title take it from the first verified state (showVersion).
    assert(network.mode === 'local-devnet' && network.publicLaunchAllowed === false && /^[0-9a-f]{64}$/.test(network.networkId), 'This wallet works only on a test network whose service says so. It stopped here.');
    // "Get test time" is offered only where the wallet's service names a registration service: a test network's faucet.
    $('faucet-button').hidden = !(typeof network.registrationService === 'string' && network.registrationService !== '');
    upgrades = createUpgradeMonitor({ storage: localStorage, networkId: network.networkId, declared: client.nodesReportUpgrades === true });
    $('upgrade-forget-row').hidden = !upgrades.learned();
    if (typeof BroadcastChannel === 'function') {
      lockChannel = new BroadcastChannel('timecurrency.wallet-lock.v1:' + network.networkId);
      lockChannel.addEventListener('message', event => { if (event.data?.type === 'lock' && event.data.name === session?.binding.name) lock('This account was locked in another wallet tab.', false); });
    }
    $('merchant-link').href = network.merchantOrigin || '#'; await refresh();
    const saved = Object.keys(localStorage).filter(k => k.startsWith(vaultPrefix + network.networkId + ':'));
    if (saved.length) { $('username').value = saved[0].slice((vaultPrefix + network.networkId + ':').length); setMode('unlock'); }
    // On a network that takes them, "Create an account" is the protected sign-up (signup-ui.mjs).
    else if (signupUI.on()) setMode('create');
    notice('Connected to the Time test network, and checked by this browser. Create an account, or open yours.');
    // A protected sign-up that this browser keeps and that did not end: its name, and how to go on.
    const unfinished = saved.map(key => key.slice((vaultPrefix + network.networkId + ':').length)).find(name => signupUI.staged(name));
    if (unfinished) { $('username').value = unfinished; signupUI.offer(unfinished); notice(`Creating @${unfinished} was not finished. Open it with your login password: this browser goes on from what the network shows.`); }
    // The test network was reset, and this browser keeps accounts of the old one only (reset.mjs).
    showReset();
    await securityUI.start();
  } catch (error) { latest = null; $('network-status').textContent = 'Cannot check the network · signing is off'; notice(failureNotice(error), 'error'); renderAvailability(); upgradeRequired(error); }
}
// On a secured account, unbonding, withdrawing and the operation of its validator are signed by the payment key, and the
// review says first what each does to the daily limit (security-ui.mjs, stakeAction and stakeLimit).
const posUI=createPosUI({sdk,network:()=>network,ownAccount,verifiedState,sendSigned:(kind,payload,label,options)=>securityUI.secured(latest?.state,ownAccount())?securityUI.stakeAction(kind,payload,label,options):sendSigned(kind,payload,label,options),limitLines:(kind,payload)=>securityUI.secured(latest?.state,ownAccount())?securityUI.stakeLimit(kind,payload):null,refresh,review,notice,run,setBusy,capture:()=>fence.capture(),seconds,parseSeconds});
const securityUI = createSecurityUI({sdk, client: () => client, network: () => network, session: () => session, state: () => latest?.state, ownAccount, verifiedState, sendSigned, refresh, review, notice, run, setBusy, capture: () => fence.capture(), seconds, fee: networkFee, pending,
  record: (receipt, label) => { if (session) recordReceipt(receipt, label); }, lock, argon2id: () => globalThis.hashwasm?.argon2id,
  showUnlock: name => { $('username').value = name; setMode('unlock'); $('auth-panel').hidden = false; },
  // Home, where the Protection card is: a step of another screen that leads there (a stake above the limit) shows it.
  showPanel: name => showPanel(name),
  // "Sent", after a payment of a protected account, where the person is (showSent).
  sent: (name, amountText) => showSent(name, amountText)});
// The Validator signal tab (upgrade-signal-ui.mjs). A signal is signed like every other chain action: by sendSigned
// with this browser's key, or on a secured account by its payment key through security-ui.mjs.
const signalUI = createSignalUI({ sdk, client: () => client, network: () => network, session: () => session, state: () => latest?.state, ownAccount, refresh, review, notice, run, setBusy, capture: () => fence.capture(), seconds, fee: networkFee, pending,
  // What the tab remembers of the account's signal (what proven state showed, what was signed or discarded here): nothing secret.
  storage: localStorage, canCancelPending: () => cancelOffered(ownAccount()),
  secured: () => securityUI.secured(latest?.state, ownAccount()),
  spendRefusal: async () => (securityUI.secured(latest?.state, ownAccount()) ? securityUI.signalRefusal() : null),
  sign: signalSigner({ secured: () => securityUI.secured(latest?.state, ownAccount()), signalAction: (payload, label) => securityUI.signalAction(payload, label), sendSigned }) });
// "Create an account" on a network that takes accounts protected from their first block (signup-ui.mjs).
const signupUI = createSignupUI({ sdk, client: () => client, network: () => network, state: () => latest?.state, verifiedState, registrationSponsor, nameRefusal, failureNotice, notice, setBusy, run, review, capture: () => fence.capture(), fee: networkFee, parseSeconds,
  argon2id: () => globalThis.hashwasm?.argon2id, storage: localStorage, locks: () => navigator.locks, record: (receipt, label) => { if (session) recordReceipt(receipt, label); }, created: signupCreated });
const recoveryUI = createRecoveryUI({rememberGuardianTarget:name=>{guardianTargetName=name;},paidNames:()=>paidNamesNow(),sdk, network: () => network, session: () => session, state: () => latest?.state, ownAccount, verifiedState, sendSigned, refresh, review, notice, run, setBusy, capture: () => fence.capture(), fee: () => seconds(networkFee()) + ' seconds' });
for (const m of ['create', 'unlock', 'link', 'recover']) $(`mode-${m}`).addEventListener('click', () => {
  if (busy) return; setMode(m);
  // The two ways in under "Other ways in" use the form above them: bring it into view.
  if (m === 'link' || m === 'recover') { $('auth-heading').scrollIntoView?.({ block: 'start' }); $('username').focus?.(); }
});
$('review-ack').addEventListener('change', reviewGate);
// In a review a key that repeats because it is held down does nothing: it neither confirms nor ticks the box.
$('review-dialog').addEventListener('keydown', event => { if (event.repeat && (event.key === 'Enter' || event.key === ' ')) event.preventDefault(); });
$('auth-form').addEventListener('submit', auth); $('send-form').addEventListener('submit', sendForm); $('bid-form').addEventListener('submit', bidForm); $('stake-form').addEventListener('submit', stakeForm); $('approve-device-form').addEventListener('submit', approveDevice);
$('backup-export-form').addEventListener('submit',exportBackup);$('backup-import-form').addEventListener('submit',restoreBackup);
$('backup-file').addEventListener('change',()=>{backupGeneration++;});
$('lock-button').addEventListener('click', () => lock()); $('refresh').addEventListener('click', () => run(async () => { setBusy(true); await refresh(); notice('Your balance was checked again against the network.'); }));
for (const id of ['copy-name', 'copy-name-receive']) $(id).addEventListener('click', () => run(async () => { await navigator.clipboard.writeText('@' + ownAccount().name); notice('Your name was copied. Paste it to whoever sends you seconds.'); }));
$('faucet-button').addEventListener('click', getTestTime);
$('reset-forget').addEventListener('click', () => run(forgetOldNetwork));
$('keys-print').addEventListener('click', printKeys);
// "Protect my account" on Home's card of an account that is not protected yet: the form of Keys, open, in view, with the focus on its first field.
$('protect-start').addEventListener('click', () => { showPanel('security'); $('secure-open').open = true; $('secure-open').scrollIntoView?.({ block: 'start' }); $('secure-login').focus?.(); });
$('send-form').addEventListener('input', () => { $('send-result').hidden = true; });
$('activity-search').addEventListener('input', filterActivity);
// The Staked line on Home opens Staking (More, Staking). It has no data-panel: the browser check finds the row of More by it.
$('home-staked-row').addEventListener('click', () => showPanel('earn'));
$('copy-enrollment').addEventListener('click', () => run(async () => { await navigator.clipboard.writeText($('enrollment-code').value); notice('The request was copied. It holds no secret.'); }));
$('check-enrollment').addEventListener('click', () => run(async () => { setBusy(true); await refresh(); }));
$('approve-request').addEventListener('click', approveWebsite); $('deny-request').addEventListener('click', () => {
  if (approval) window.opener?.postMessage({ type: 'time:response', version: 1, id: approval.id, error: { code: 'USER_DENIED', message: 'Wallet user declined the request.' } }, approval.origin);
  approval = null; $('approval-title').textContent = 'Declined'; $('approval-details').textContent = 'Nothing was signed and nothing was given. You can close this window.'; renderAvailability();
});
for (const tab of document.querySelectorAll('[data-panel]')) tab.addEventListener('click', () => showPanel(tab.dataset.panel));
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, scheduleIdleLock, { passive: true });
window.addEventListener('storage', event => { if (event.key?.startsWith('timecurrency.pending.v1:') && session) renderPending(); });
window.addEventListener('pagehide', () => { fence.bump(); if (session) { forgetSecret(session.secret); session.privateKey = null; } session = null; });
window.addEventListener('pageshow', event => { if (event.persisted) lock('This wallet was locked when the page closed. Unlock it again to sign.'); });
start();

// After a node of an older laboratory network was replaced by one that does not answer the
// question about upgrades, every read of a wallet that remembers an answer fails. This drops the
// remembered answer, and nothing else: the vault and the checkpoint stay.
$('upgrade-forget').addEventListener('click',()=>run(async()=>{
  if(!upgrades?.forget()){notice('This wallet remembers no answer about upgrades for this network.');return;}
  $('upgrade-forget-row').hidden=true;await refresh();notice('Forgotten. This wallet asks about upgrades in a read of its own again.');
}));
$('trust-refresh-form').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
 const file=$('trust-checkpoint-file').files?.[0],expected=$('trust-checkpoint-hash').value.trim();assert(file&&file.size<=512*1024,'Choose a checkpoint file (JSON) of at most 512 KiB.');
 assert(/^[0-9a-f]{64}$/i.test(expected),'Enter the whole block hash, 64 characters, as you confirmed it through a channel you trust.');
 const parsed=JSON.parse(await file.text()),checkpoint=parsed.checkpoint||parsed;await client.importTrustedCheckpoint(checkpoint,expected);$('trust-checkpoint-file').value=$('trust-checkpoint-hash').value='';await refresh();notice('Checkpoint brought in. This browser checked the network and your account again.');
});});
