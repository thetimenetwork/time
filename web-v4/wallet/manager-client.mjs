// The wallet can send credentials only to its paired vault. Never derive this
// address from a query string, a merchant, a gateway response or a message.
export function managerOrigin(origin) {
  switch (origin) {
    case 'https://wallet.testnet.thetimenetwork.org': return 'https://vault.testnet.thetimenetwork.org';
    case 'http://localhost:8780': return 'http://localhost:8786';
    default: return null;
  }
}

const roles = new Set(['signin', 'spend', 'recover']);
const interrupted = 'Time Vault closed before the request finished. Open it again to continue.';
const popupBlocked = 'Allow pop-ups for this wallet in your browser, then open Time Vault again.';
// Only closed reason codes select text for the wallet. An older vault can reply
// without a reason code. Its save/unsaved status is handled exactly the same way.
const vaultErrors = new Map([
  ['cancelled', 'The vault request was cancelled. Open Time Vault again to continue.'],
  ['expired', 'Time Vault locked after a period of inactivity. Open it again to continue.'],
  ['account_missing', 'Open this account in the browser where you set up its vault.'],
  ['storage', 'Allow Time Vault to save data in your browser settings, then open it again.'],
  ['different_passwords', 'Time Vault already has different passwords for this name. Open the original account or choose another name.'],
  ['save_unknown', 'Open this account with Time Vault to check whether its passwords were saved.']
]);

// Open during the user's gesture. Signup may still be preparing keys when the
// vault is ready. A handshake carries no account details or secrets.
export function openManager(win = window) {
  const origin = managerOrigin(win.location.origin);
  if (!origin) throw new Error('Time Vault is unavailable at this wallet address.');
  const id = win.crypto.randomUUID();
  let popup, request, resolve, reject, ready = false, sent = false, closed = false;
  let timeout, poll, whyClosed = interrupted;
  function stopped() {
    const error = new Error(whyClosed);
    if (!sent) error.unsaved = true;
    return error;
  }
  function close() {
    if (closed) return;
    closed = true;
    win.removeEventListener('message', message);
    win.removeEventListener('pagehide', close);
    win.clearTimeout(timeout);
    win.clearInterval(poll);
    try { popup?.close(); } catch { /* already closed */ }
    if (reject) reject(stopped());
    request = resolve = reject = null;
  }
  function send() {
    if (!ready || !request || sent || closed) return;
    try {
      popup.postMessage(request, origin);
      sent = true;
      // The result can only fulfill this request, even if the popup reloads.
      delete request.secrets;
    } catch { close(); }
  }
  function message(event) {
    if (closed || !popup || event.source !== popup || event.origin !== origin) return;
    const data = event.data;
    if (data?.v !== 1) return;
    if (data.type === 'time:vault-ready') {
      if (!ready) {
        ready = true;
        win.clearTimeout(timeout);
        timeout = win.setTimeout(() => {
          whyClosed = 'The vault window timed out. Open it again to continue.';
          close();
        }, 5 * 60 * 1000);
        send();
      }
      return;
    }
    if (!sent || data.type !== 'time:vault-result' || data.id !== id) return;
    if (data.ok === false) {
      const reason = new Error(vaultErrors.get(data.reason) ?? 'Time Vault could not finish. Open it again from the wallet and check your account.');
      if (data.unsaved === true && request.operation === 'save') reason.unsaved = true;
      reject(reason);
    } else if (data.ok === true && request.operation === 'save' && data.value === undefined) resolve();
    else if (data.ok === true && request.operation === 'get' && typeof data.value === 'string' && data.value.length > 0 && data.value.length <= 2048) resolve(data.value);
    else reject(new Error('The wallet could not confirm what happened in Time Vault. Reopen the vault and check your account.'));
    close();
  }
  win.addEventListener('message', message);
  win.addEventListener('pagehide', close);
  try {
    popup = win.open(origin + '/', '_blank', 'popup,width=540,height=720');
    if (!popup) throw new Error(popupBlocked);
    poll = win.setInterval(() => { if (popup.closed) close(); }, 350);
    timeout = win.setTimeout(() => {
      whyClosed = 'Time Vault took too long to open. Check your connection and try again. If you are creating an account, you can choose Set up manually.';
      close();
    }, 20000);
  } catch { close(); throw new Error(popupBlocked); }
  function run(operation, args) {
    if (closed || request) return Promise.reject(stopped());
    return new Promise((yes, no) => {
      resolve = yes; reject = no;
      request = { ...args, operation, type: 'time:vault-request', v: 1, id };
      send();
    });
  }
  return {
    save: ({ networkId, name, secrets }) => run('save', { networkId, name, secrets }),
    get: ({ networkId, name, role }) => {
      if (!roles.has(role)) { close(); throw new Error('Choose a sign-in, payment or recovery key.'); }
      return run('get', { networkId, name, role });
    },
    close
  };
}
