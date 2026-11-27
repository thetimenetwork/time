// Only the browser adapter below persists data. Account names and network IDs are public.
// Every password and the passphrase verifier use their own AES-GCM key, salt and IV.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
export const ROLES = Object.freeze(['signin', 'spend', 'recover']);
export const CHECK = 'Time vault master passphrase verified';
const FORMAT = 'time-password-vault-v1';
const SECRET_WORD = '(?:[bdfghjklmnprstvz][aeio]){3}';
const MADE = new RegExp('^' + SECRET_WORD + '(?:-' + SECRET_WORD + '){3}$');
const PAPER = new RegExp('^' + SECRET_WORD + '(?: ' + SECRET_WORD + '){4}$');
const fields = (obj, keys) => obj && Object.getPrototypeOf(obj) === Object.prototype
  && Object.keys(obj).sort().join(',') === keys.split(' ').sort().join(',');

export function walletOrigin(manager) {
  if (manager === 'https://vault.testnet.thetimenetwork.org') return 'https://wallet.testnet.thetimenetwork.org';
  if (manager === 'http://localhost:8786') return 'http://localhost:8780';
  return null;
}

export function accountKey(networkId, name) {
  if (typeof networkId !== 'string' || !/^[0-9a-f]{64}$/.test(networkId)
    || typeof name !== 'string' || !/^[a-z0-9_]{2,15}$/.test(name)) throw new Error('Invalid account');
  return networkId + '/' + name;
}

export function acceptRequest(event, managerOrigin, opener) {
  const origin = walletOrigin(managerOrigin);
  if (!origin || !opener || event.origin !== origin || event.source !== opener) return null;
  const m = event.data;
  if (!m || m.type !== 'time:vault-request' || m.v !== 1 || typeof m.id !== 'string'
    || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(m.id)) return null;
  try { accountKey(m.networkId, m.name); } catch { return null; }
  const common = 'type v id operation networkId name ';
  if (m.operation === 'get' && fields(m, common + 'role') && ROLES.includes(m.role)) return m;
  if (m.operation === 'save' && fields(m, common + 'secrets') && fields(m.secrets, 'signin spend recover')
    && [m.secrets.signin, m.secrets.spend, m.secrets.recover].every(v => typeof v === 'string' && v.length <= 100)
    && MADE.test(m.secrets.signin) && MADE.test(m.secrets.spend) && m.secrets.signin !== m.secrets.spend
    && PAPER.test(m.secrets.recover)) return m;
  return null;
}

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const random = length => hex(crypto.getRandomValues(new Uint8Array(length)));
function bytes(value, min, max = min) {
  if (typeof value !== 'string' || value.length < min * 2 || value.length > max * 2
    || value.length % 2 || !/^[0-9a-f]+$/.test(value)) throw new Error('Invalid vault');
  return Uint8Array.from(value.match(/../g), s => parseInt(s, 16));
}

export function newProfile(credential) { return { format: FORMAT, credential, salt: random(16) }; }

// One Argon2id computation per approval. HKDF mixes the result with the authenticated
// PRF output. The imported master is non-extractable and only retained for this action.
export async function masterKey(profile, passphrase, device, argon2id) {
  if (profile.format !== FORMAT || typeof profile.credential !== 'string' || !/^[A-Za-z0-9_-]{22,1364}$/.test(profile.credential)
    || !(device instanceof Uint8Array) || device.length !== 32) throw new Error('Invalid device or vault');
  const password = encoder.encode(passphrase), combined = new Uint8Array(64);
  let digest;
  try {
    digest = await argon2id({ password, salt: bytes(profile.salt, 16), iterations: 3, memorySize: 65536,
      parallelism: 1, hashLength: 32, outputType: 'binary' });
    if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error('Invalid derivation');
    combined.set(digest); combined.set(device, 32);
    return await crypto.subtle.importKey('raw', combined, 'HKDF', false, ['deriveKey']);
  } finally { password.fill(0); digest?.fill(0); combined.fill(0); }
}

async function entryKey(master, profile, account, role, salt) {
  const context = encoder.encode(JSON.stringify([FORMAT, profile.credential, profile.salt, account, role]));
  const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: bytes(salt, 16), info: context },
    master, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  return { key, context };
}

async function seal(master, profile, account, role, value) {
  const salt = random(16), iv = random(12), plain = encoder.encode(value);
  try {
    const { key, context } = await entryKey(master, profile, account, role, salt);
    const result = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bytes(iv, 12), additionalData: context }, key, plain);
    return { salt, iv, ciphertext: hex(new Uint8Array(result)) };
  } finally { plain.fill(0); }
}
async function open(master, profile, account, role, record) {
  const { key, context } = await entryKey(master, profile, account, role, record.salt);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(record.iv, 12),
    additionalData: context }, key, bytes(record.ciphertext, 17, 4112)));
  try { return decoder.decode(plain); } finally { plain.fill(0); }
}

export async function confirmMaster(master, profile, creating) {
  if (creating) profile.check = await seal(master, profile, '', 'master-check', CHECK);
  if (await open(master, profile, '', 'master-check', profile.check) !== CHECK) throw new Error('Unable to unlock');
}

export async function readRole(master, profile, record, networkId, name, role) {
  const account = accountKey(networkId, name);
  if (!ROLES.includes(role) || record?.networkId !== networkId || record?.name !== name) throw new Error('Invalid account or purpose');
  return open(master, profile, account, role, record[role]);
}

// A replay only succeeds for exactly the same credentials. A retry can never replace
// an existing registration's credentials or accidentally acknowledge the wrong signup.
export async function prepareAccount(master, profile, request, existing) {
  const { networkId, name, secrets } = request, account = accountKey(networkId, name);
  const record = existing || { networkId, name };
  for (const role of ROLES) {
    if (!existing) record[role] = await seal(master, profile, account, role, secrets[role]);
    if (await readRole(master, profile, record, networkId, name, role) !== secrets[role]) throw new Error('Credentials differ');
  }
  return record;
}

// User-initiated edits from the vault's own page. Replacing recovery words supports
// the wallet's earlier four-word recovery papers as well as current five-word papers.
export async function changedRole(master, profile, record, role, replacement) {
  if (!ROLES.includes(role) || typeof replacement !== 'string' || [...replacement].length > 1024) throw new Error('Invalid password');
  if (role === 'recover') {
    replacement = replacement.trim().toLowerCase().replace(/[\s-]+/g, ' ');
    if (!new RegExp('^' + SECRET_WORD + '(?: ' + SECRET_WORD + '){3,4}$').test(replacement)) throw new Error('Invalid recovery words');
  } else if ([...replacement].length < 15) throw new Error('Invalid password');
  const { networkId, name } = record, account = accountKey(networkId, name);
  await readRole(master, profile, record, networkId, name, role);
  const updated = { ...record, [role]: await seal(master, profile, account, role, replacement) };
  if (await readRole(master, profile, updated, networkId, name, role) !== replacement) throw new Error('Could not verify update');
  return updated;
}

// The account and initial profile are added in a single transaction. add() (not put())
// and the unique account key prevent a second tab from overwriting the first.
export async function openDatabase(idb = indexedDB) {
  const db = await new Promise((resolve, reject) => {
    const req = idb.open(FORMAT, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('entries');
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('Close other vault tabs and try again.'));
    req.onsuccess = () => resolve(req.result);
  });
  db.onversionchange = () => db.close();
  const read = (op, arg) => new Promise((resolve, reject) => {
    const tx = db.transaction('entries', 'readonly');
    const store = tx.objectStore('entries'), req = op === 'get' ? store.get(arg) : store.getAllKeys();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return {
    profile: () => read('get', 'profile'),
    account: (networkId, name) => read('get', accountKey(networkId, name)),
    accounts: async () => (await read('keys')).filter(k => typeof k === 'string' && k.includes('/')),
    add: (profile, record) => new Promise((resolve, reject) => {
      const key = accountKey(record.networkId, record.name);
      const tx = db.transaction('entries', 'readwrite', { durability: 'strict' });
      tx.oncomplete = () => resolve(); tx.onabort = () => reject(tx.error || new Error('Save failed'));
      const entries = tx.objectStore('entries');
      if (profile) entries.add(profile, 'profile');
      entries.add(record, key);
    }),
    replace: (previous, next) => new Promise((resolve, reject) => {
      const key = accountKey(previous.networkId, previous.name);
      const tx = db.transaction('entries', 'readwrite', { durability: 'strict' });
      tx.oncomplete = () => resolve(); tx.onabort = () => reject(tx.error || new Error('Account changed'));
      const entries = tx.objectStore('entries'), req = entries.get(key);
      req.onsuccess = () => {
        if (JSON.stringify(req.result) !== JSON.stringify(previous)) { tx.abort(); return; }
        entries.put(next, key);
      };
    }),
  };
}
