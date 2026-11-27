import { browserEnv, DeviceKeyError, deviceSecret, fromBase64url, makeDeviceKey } from '/wallet-lib/device-key.mjs';
import { checkPassword, madeText, MADE_PASSWORD } from '/wallet-lib/vault.mjs';
import { acceptRequest, changedRole, confirmMaster, masterKey, newProfile, openDatabase, prepareAccount, readRole, walletOrigin } from './store.mjs';

const $ = id => document.getElementById(id);
const env = browserEnv(window), origin = walletOrigin(location.origin), peer = window.opener;
const words = { signin: 'sign-in password', spend: 'payment password', recover: 'recovery words' };
const actions = { signin: 'Unlock sign-in password', spend: 'Unlock payment password', recover: 'Unlock recovery words' };
let db, active, timer, storageUnavailable = false, usedPopup = false;
const show = (id, on) => { $(id).hidden = !on; };
const say = message => { $('status').textContent = message; };
const generator = $('generator-controls');
const setupHint = 'Choose at least 15 characters or generate a passphrase on this device. Remember it or keep a paper copy.';

function displayGenerated(reveal) {
  $('generated-value').textContent = reveal ? $('master').value : '';
  show('generated-value', reveal);
  $('toggle-generated').textContent = reveal ? 'Hide passphrase' : 'Show passphrase';
  $('toggle-generated').setAttribute('aria-expanded', String(reveal));
}
function clearGenerated() {
  if (!generator) return;
  displayGenerated(false);
  show('toggle-generated', false);
  $('generate-master').textContent = 'Generate strong passphrase';
}

// Each nine-byte block encodes four pronounceable groups without discarding bits.
function randomMaster(name, previous) {
  const bytes = new Uint8Array(2 * MADE_PASSWORD.bytes);
  try {
    for (let attempt = 0; attempt < 16; attempt++) {
      crypto.getRandomValues(bytes);
      const first = madeText(bytes.subarray(0, MADE_PASSWORD.bytes));
      const second = madeText(bytes.subarray(MADE_PASSWORD.bytes));
      const candidate = (first + '-' + second).replaceAll('-', ' ');
      if (candidate === previous) continue;
      try { checkPassword(candidate, name); } catch { continue; }
      return candidate;
    }
    throw new Error('No suitable passphrase');
  } finally { bytes.fill(0); }
}

if (generator) {
  $('generate-master').addEventListener('click', () => {
    if (generator.hidden || !active || active.busy || active.profile || active.request.operation !== 'save') return;
    try {
      $('master').value = randomMaster(active.request.name, $('master').value);
      $('generate-master').textContent = 'Generate again';
      show('toggle-generated', true);
      displayGenerated(true);
      $('hint').textContent = 'Write down these eight groups in order. You’ll need this passphrase to open your vault.';
      say(''); arm();
    } catch { say('Could not generate a secure passphrase. Try again or enter one of your own.'); }
  });
  $('toggle-generated').addEventListener('click', () => { displayGenerated($('generated-value').hidden); arm(); });
  $('master').addEventListener('input', () => {
    if (generator.hidden) return;
    clearGenerated(); $('hint').textContent = setupHint; say('');
  });
}

function reset() {
  clearTimeout(timer);
  if (generator) { generator.hidden = true; clearGenerated(); $('generate-master').disabled = false; }
  if (active?.request?.secrets) delete active.request.secrets;
  active = null;
  for (const id of ['home', 'unlock', 'paper', 'display', 'context', 'cancel']) show(id, false);
  for (const id of ['words', 'value', 'context']) $(id).textContent = '';
  show('replacement-field', false); $('replacement').value = ''; $('replacement').required = false;
  $('master').value = ''; $('master').disabled = false; $('approve').disabled = false; $('saved').disabled = false;
}
function result(id, details) {
  if (peer && origin) peer.postMessage({ type: 'time:vault-result', v: 1, id, ...details }, origin);
}
function finish(details) {
  const { request, remote } = active;
  if (remote) result(request.id, details);
  reset();
  if (remote) {
    $('title').textContent = details.ok ? 'Done' : 'Vault locked';
    $('intro').textContent = 'You can return to your wallet.';
    say(details.ok ? '' : details.error);
  } else { home().catch(unavailable); }
}
function cancel(reason = 'cancelled') {
  if (!active) return;
  const details = { ok: false, reason, error: reason === 'expired' ? 'Time Vault locked after a period of inactivity. Open it again from the wallet.' : 'The vault request ended. Open the wallet to try again.' };
  if (active.request.operation === 'save' && active.knownEmpty && !active.startedWrite) details.unsaved = true;
  finish(details);
}
function arm(ms = 180000) {
  clearTimeout(timer);
  timer = setTimeout(() => cancel('expired'), ms);
}
function current(state) {
  if (active !== state || (state.remote && peer.closed)) throw new Error('Request closed');
}
function unavailable() {
  reset(); $('title').textContent = 'Vault unavailable';
  $('intro').textContent = 'Open Time Vault in your usual browser and allow this site to save data on your device.';
}
async function home() {
  reset(); say('');
  $('title').textContent = 'Saved accounts';
  $('intro').textContent = 'Your device and master passphrase unlock one password at a time.';
  const keys = await db.accounts();
  if (active) return;
  $('accounts').replaceChildren(...keys.map(key => {
    const [networkId, name] = key.split('/');
    return new Option('@' + name + ' · network ' + networkId.slice(0, 8), key);
  }));
  if (keys.length) show('home', true);
  else say('Create an account in the Time wallet to save its passwords here.');
}

async function begin(request, remote) {
  reset(); say('');
  const state = { request, remote, knownEmpty: false, startedWrite: false };
  active = state; arm(); show('cancel', true);
  try {
    const [profile, existing] = await Promise.all([db.profile(), db.account(request.networkId, request.name)]);
    current(state);
    state.profile = profile; state.existing = existing; state.knownEmpty = !existing;
    const saving = request.operation === 'save', first = !profile;
    if (!saving && (!existing || !profile)) {
      finish({ ok: false, reason: 'account_missing', error: 'This account has no passwords saved here. Open the wallet in the browser where you set up its vault.' }); return;
    }
    $('title').textContent = saving ? (first ? 'Set up your vault' : 'Save account passwords') : actions[request.role];
    $('context').textContent = '@' + request.name + ' · network ' + request.networkId.slice(0, 8);
    show('context', true);
    $('intro').textContent = saving ? 'Keep the passwords for this account encrypted in this browser.'
      : (remote ? 'Allow the Time wallet to use your ' + words[request.role] + ' for this account?' : 'Show your ' + words[request.role] + ' on this screen?');
    $('master-label').textContent = first ? 'Choose one master passphrase' : 'Master passphrase';
    if (generator) generator.hidden = !(saving && first);
    $('hint').textContent = first ? setupHint
      : 'Your device will ask for your fingerprint, face or screen lock.';
    $('approve').textContent = saving ? (first ? 'Protect with my device' : 'Unlock and save') : (remote ? 'Allow ' : 'Show ') + words[request.role];
    if (!remote && request.operation === 'update') {
      $('title').textContent = 'Update saved ' + words[request.role];
      $('intro').textContent = 'Use this after changing this credential in the wallet. ' + (request.role === 'recover' ? 'Keep the new words on paper too.' : 'Only this saved password will change.');
      show('replacement-field', true); $('replacement').required = true;
      $('replacement-label').textContent = 'New ' + words[request.role] + ' from the wallet';
      $('approve').textContent = 'Unlock and update';
    }
    if (existing && saving) say('This account is already saved. The vault will check that the passwords match.');
    show('unlock', true); $('master').focus();
  } catch { if (active === state) finish({ ok: false, reason: 'storage', error: 'Time Vault could not read the passwords saved in this browser. Reopen the vault and try again.' }); }
}

$('unlock').addEventListener('submit', async event => {
  event.preventDefault();
  const state = active;
  if (!state || state.busy) return;
  const { request } = state, first = !state.profile;
  let passphrase = $('master').value, replacement = $('replacement').value, device, unlocked = false;
  if (first) {
    try { checkPassword(passphrase, request.name); } catch (error) { say(error.message); return; }
  }
  state.busy = true; arm();
  if (generator) { clearGenerated(); $('generate-master').disabled = true; }
  $('master').value = ''; $('approve').disabled = true; $('master').disabled = true;
  $('replacement').value = '';
  say('Confirm with your device.');
  try {
    let profile = state.profile;
    if (first) {
      const made = await makeDeviceKey(env, { label: 'Time password vault' }); current(state);
      if (made.prfEnabled === false) throw new DeviceKeyError(5);
      if (made.userVerified === false) throw new DeviceKeyError(8);
      profile = newProfile(made.credentialId);
    }
    // Name the enrolled credential, including immediately after creation. Some platforms
    // retain a credential after a cancelled signup, or have other passkeys for this host.
    const authenticator = {
      create: opts => env.credentials.create(opts),
      get: ({ publicKey }) => env.credentials.get({ publicKey: { ...publicKey, allowCredentials: [
        { type: 'public-key', id: fromBase64url(profile.credential), transports: ['internal'] },
      ] } }),
    };
    ({ secret: device } = await deviceSecret({ ...env, credentials: authenticator },
      { credentialId: profile.credential, purpose: 'password-vault-v1' })); current(state);
    const master = await masterKey(profile, passphrase, device, globalThis.hashwasm.argon2id);
    passphrase = ''; device.fill(0); current(state);
    await confirmMaster(master, profile, first); current(state); unlocked = true;
    if (request.operation === 'save') {
      const record = await prepareAccount(master, profile, request, state.existing); current(state);
      state.record = record; state.initialProfile = first ? profile : null;
      // No database writes until the user confirms an independent recovery copy.
      $('words').textContent = request.secrets.recover;
      delete request.secrets;
      show('unlock', false); $('title').textContent = 'Keep an offline recovery copy';
      $('intro').textContent = 'These words recover your account if this device is lost.';
      show('paper', true); $('saved').focus(); say(''); arm();
    } else if (!state.remote && request.operation === 'update') {
      const next = await changedRole(master, profile, state.existing, request.role, replacement); current(state);
      await db.replace(state.existing, next); current(state);
      reset(); await home(); say('Updated the saved ' + words[request.role] + '.');
    } else {
      const value = await readRole(master, profile, state.existing, request.networkId, request.name, request.role); current(state);
      if (state.remote) finish({ ok: true, value });
      else {
        show('unlock', false); show('cancel', false); $('value').textContent = value;
        $('intro').textContent = 'This screen locks after one minute.';
        show('display', true); $('hide').focus(); say(''); arm(60000);
      }
    }
  } catch (error) {
    if (active !== state) return;
    if (peer?.closed && state.remote) { cancel(); return; }
    if (error.message === 'Credentials differ') {
      finish({ ok: false, reason: 'different_passwords', unsaved: true, error: 'This name already has different saved passwords. Open the original account or create an account with another name.' });
    } else if (error instanceof DeviceKeyError) {
      if (error.outcome === 4) say('Set up a screen lock in your device settings, then try again.');
      else if (first && [2, 3, 5].includes(error.outcome)) say('This browser cannot protect a vault with your screen lock. Update your browser and try again, or choose Cancel and then Set up manually.');
      else if (!first && [2, 3, 5].includes(error.outcome)) say('Open the vault in the browser where you set it up. If you already use that browser, check for browser and device updates.');
      else if (!first && error.outcome === 7) say('Use the device and passkey you used to set up this vault. If you lost that device, open the wallet and use your recovery words.');
      else say('The device check did not finish. Enter your master passphrase again and confirm with your fingerprint, face or screen lock.');
    } else if (request.operation === 'update' && error.message === 'Invalid recovery words') {
      say('Enter all the recovery words from your wallet in their original order, with a space between each word.');
    } else if (request.operation === 'update' && error.message === 'Invalid password') {
      say('Enter the new password from your wallet. It must have between 15 and 1,024 characters.');
    } else if (unlocked && request.operation === 'update') {
      say('The vault opened, but it could not confirm the update. Reopen the vault and check the saved ' + words[request.role] + '.');
    } else if (unlocked && request.operation === 'save') {
      say('The vault opened, but it could not prepare the passwords for this account. Cancel and start again from the wallet.');
    } else if (unlocked) {
      say('The vault opened, but it could not read the saved passwords for this account. Reopen it from the wallet and try again.');
    } else if (first) {
      say('Time Vault could not finish setup. Reopen it from the wallet and try again, or choose Set up manually.');
    } else {
      say('Could not unlock your vault. Check your master passphrase and try again on the device where you set it up.');
    }
  } finally {
    passphrase = ''; replacement = ''; device?.fill(0);
    if (active === state) {
      state.busy = false; $('approve').disabled = false; $('master').disabled = false;
      if (generator) { $('generate-master').disabled = false; if (first) $('hint').textContent = setupHint; }
    }
  }
});

$('saved').addEventListener('click', async () => {
  const state = active;
  if (!state?.record || state.busy) return;
  state.busy = true; $('saved').disabled = true;
  const { networkId, name } = state.request;
  try {
    current(state);
    if (!state.existing) {
      state.startedWrite = true;
      await db.add(state.initialProfile, state.record); current(state);
    }
    const saved = await db.account(networkId, name); current(state);
    if (JSON.stringify(saved) !== JSON.stringify(state.record)) throw new Error('Save did not persist');
    if (state.initialProfile && JSON.stringify(await db.profile()) !== JSON.stringify(state.initialProfile)) throw new Error('Profile did not persist');
    current(state); finish({ ok: true });
  } catch {
    if (active === state) finish({ ok: false, reason: 'save_unknown', error: 'Could not confirm the save. Return to the wallet and reopen this account to check it.' });
  }
});
function localAction(operation) {
  const [networkId, name] = $('accounts').value.split('/');
  begin({ operation, role: $('purpose').value, networkId, name }, false);
}
$('choose').addEventListener('click', () => localAction('get'));
$('update').addEventListener('click', () => localAction('update'));
$('hide').addEventListener('click', () => cancel());
$('cancel').addEventListener('click', () => cancel());
window.addEventListener('pagehide', () => { if (active?.remote) cancel(); else reset(); });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
document.addEventListener('visibilitychange', () => {
  if (document.hidden && generator && !$('generated-value').hidden) displayGenerated(false);
  if (document.hidden && !$('display').hidden) cancel();
});
window.addEventListener('message', event => {
  if ((!db && !storageUnavailable) || usedPopup || active || window.top !== window) return;
  const request = acceptRequest(event, location.origin, peer);
  if (!request) return;
  usedPopup = true;
  if (storageUnavailable) {
    result(request.id, { ok: false, reason: 'storage', ...(request.operation === 'save' ? { unsaved: true } : {}),
      error: 'Time Vault could not open its saved data. Allow this site to save data in your browser settings, then reopen the vault.' });
  } else begin(request, true);
});
try {
  if (!origin || window.top !== window || !window.isSecureContext) throw new Error('Unsupported origin');
  try { db = await openDatabase(); } catch { storageUnavailable = true; }
  if (storageUnavailable) unavailable();
  if (peer) {
    if (!storageUnavailable) {
      $('title').textContent = 'Time password vault';
      $('intro').textContent = 'Waiting for the Time wallet.';
    }
    peer.postMessage({ type: 'time:vault-ready', v: 1 }, origin);
  } else if (db) await home();
} catch { unavailable(); }
