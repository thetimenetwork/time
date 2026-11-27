import { failureNotice } from './actions.mjs';

// The actual credential stays out of form history and third-party autofill.
// A field holds a disposable token until its existing action reads it once.
const pending = new Map();
const lifetime = 60000;

function forget(field) {
  const item = pending.get(field);
  if (!item) return;
  clearTimeout(item.timer);
  if (field.value === item.token) field.value = '';
  pending.delete(field);
  item.cleared?.();
}
export function clearWalletField(field) { forget(field); field.value = ''; }
export function clearVaultFields() {
  for (const field of pending.keys()) forget(field);
}
export function holdVaultField(field, secret, valid, cleared) {
  forget(field);
  const token = crypto.randomUUID();
  field.value = token;
  pending.set(field, { token, secret, valid, cleared, expires: Date.now() + lifetime, timer: setTimeout(() => forget(field), lifetime) });
}
export function takeWalletField(field) {
  const item = pending.get(field), value = field.value;
  forget(field);
  field.value = '';
  if (!item || value !== item.token) return value;
  if (item.expires <= Date.now() || !item.valid()) throw new Error('Unlock this field in Time Vault again.');
  return item.secret;
}

// Only fields that *consume* an existing credential may request one. New
// password/confirmation fields and the recovery file/sheet use other inputs.
const fieldRoles = {
  'approval-payment': 'spend', 'send-payment': 'spend', 'stake-payment': 'spend',
  'validator-payment': 'spend', 'signal-payment': 'spend', 'limit-payment': 'spend',
  'inbox-payment': 'spend', 'pause-payment': 'spend', 'resume-payment': 'spend',
  'unfreeze-payment': 'spend', 'replace-login-payment': 'spend', 'replace-spend-payment': 'spend',
  'rr-payment': 'spend', 'move-old-payment': 'spend', 'add-login-payment': 'spend',
  'removed-payment': 'spend', 'lock-payment': 'spend', 'remake-payment': 'spend', 'lock-off-payment': 'spend',
  'lock-login': 'signin', 'remake-login': 'signin', 'lock-off-login': 'signin', 'backup-export-password': 'signin',
  'send-recovery-secret': 'recover', 'unfreeze-secret': 'recover', 'resume-secret': 'recover',
  'limit-secret': 'recover', 'inbox-secret': 'recover', 'rr-secret': 'recover',
  'replace-spend-secret': 'recover', 'move-old-secret': 'recover', 'lost-phrase': 'recover',
  'freeze-secret': 'choice'
};

export function installVaultFields({ doc, context, startManager, notice }) {
  for (const [id, intent] of Object.entries(fieldRoles)) {
    const field = doc.getElementById(id);
    const button = doc.createElement('button');
    button.type = 'button';
    button.className = 'link vault-unlock';
    button.textContent = 'Unlock with Time Vault';
    field.after(button);
    const role = () => intent === 'choice' ? (doc.getElementById('freeze-method').value === 'payment' ? 'spend' : 'recover') : intent;
    field.addEventListener('input', () => { if (field.value !== pending.get(field)?.token) forget(field); });
    button.addEventListener('click', async () => {
      const requested = context(id), purpose = role();
      if (!requested) { notice('Enter the account name first.', 'error'); return; }
      const valid = () => {
        const current = context(id);
        return current?.name === requested.name && current?.networkId === requested.networkId && purpose === role();
      };
      let vault;
      button.disabled = true;
      forget(field);
      try {
        vault = startManager();
        const value = await vault.get({ ...requested, role: purpose });
        if (!valid() || field.disabled || !field.getClientRects().length) return;
        holdVaultField(field, value, valid, () => { button.textContent = 'Unlock with Time Vault'; });
        button.textContent = purpose === 'recover' ? 'Recovery words ready' : purpose === 'spend' ? 'Payment key ready' : 'Sign-in key ready';
        // Some forms react to the presence of a recovery credential.
        field.dispatchEvent(new Event('input', { bubbles: true }));
        field.dispatchEvent(new Event('change', { bubbles: true }));
        notice('Unlocked for this field. Continue within one minute.');
      } catch (error) {
        if (valid()) notice(failureNotice(error, 'Time Vault could not unlock this field. Open the vault and try again.'), 'error');
      } finally { button.disabled = false; vault?.close(); }
    });
  }
}
