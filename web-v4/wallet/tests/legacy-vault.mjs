// Vault records of versions 1 and 2 sealed under a password a person chose, alone: what the wallet made before the rule
// of 24 November 2026 (vault.mjs, RULE), and what a browser or a backup file may still hold. The wallet makes none any
// more, and they keep opening (BACKUP_FORMAT.md). Tests build them here, from the format alone, to stand for what was
// kept before: the same header, the same Argon2id of the exact password, the same AES-256-GCM. Never imported by a page.
import { KDF, b64, sealOf, validateVaultRecord, openVault, vaultIntent } from '../vault.mjs';

const encoder = new TextEncoder();

/// The places of vault records in a storage (`entries`: [key, value] pairs): the login and payment places, keys kept
/// aside, a login asked of another device, the swap journal.
const VAULT_PLACE = /^timecurrency\.(vault\.v1|spend-vault\.v1|vault-next\.v1|login-request\.v1|vault-lock\.v1):/;
const placeOf = key => key.split(':')[0] + (key.split(':').length > 3 ? ':' + key.split(':').slice(3).join(':') : '');
/// The vault records of a storage: [place, record].
function recordsOf(entries) {
  const out = [];
  for (const [key, value] of entries) {
    if (!VAULT_PLACE.test(key)) continue;
    let parsed = null; try { parsed = JSON.parse(value); } catch { /* not a record */ }
    const record = parsed?.ciphertext ? parsed : parsed?.record?.ciphertext ? parsed.record : null;
    if (record) out.push([placeOf(key), record]);
  }
  return out;
}
/// Every vault record a storage holds, with how its header says it is sealed (vault.mjs, sealOf): [{ place, version, seal }].
export function sealsKept(entries) {
  return recordsOf(entries).map(([place, record]) => { validateVaultRecord(record, ['device', 'signin', 'spend']); return { place, version: record.version, seal: sealOf(record) }; });
}
/// The records of a storage whose header says they break the rule (vault.mjs, RULE): sealed under a password a person
/// chose, alone. By the header only: provenSeals, below, proves the seals.
export const breakingTheRule = entries => sealsKept(entries).filter(item => item.seal === 'chosen');

/// The vault records of a storage (`entries`) and of the backup files a flow made (`files`: their text), proven against
/// the rule by opening them, as a list of what is wrong (empty when every one holds). `shown`: the passwords the step
/// showed (the dialog of the passwords the wallet made); `typed`: what the person typed in it; `device(record)`: the
/// secret the device gives for a record locked to it (the fake authenticator of a test), or null.
/// - A record of a chosen password alone is wrong.
/// - A record whose password the wallet made must open with one of `shown`, and with nothing of `typed`.
/// - A record locked to the device (version 3) must open with nothing of `typed` or `shown` and a secret that is not the
///   device's; with `device`, it must open with the device's secret and one of them.
/// - A record kept under another key (version 4) must name a login key whose record the same storage holds, proven too.
/// - A backup file must hold a record whose password the wallet made, proven as above.
export async function provenSeals({ entries = [], files = [], shown = [], typed = [], device = null, argon2id, cryptoImpl = globalThis.crypto }) {
  const wrong = [], records = recordsOf(entries);
  for (const [i, text] of files.entries()) {
    let record = null; try { record = JSON.parse(text).vault ?? null; } catch { record = null; }
    if (record) records.push([`file ${i + 1}`, record]); else wrong.push(`file ${i + 1}: not a backup file`);
  }
  const opens = async (record, password, secret = null) => { try { await openVault(record, password, argon2id, cryptoImpl, vaultIntent(record), secret); return true; } catch { return false; } };
  const any = async (record, passwords, secret = null) => { for (const password of passwords) if (await opens(record, password, secret)) return true; return false; };
  for (const [place, raw] of records) {
    let record;
    try { record = validateVaultRecord(raw, ['device', 'signin', 'spend']); } catch (error) { wrong.push(`${place}: ${error.message}`); continue; }
    const seal = sealOf(record);
    if (seal === 'chosen') { wrong.push(`${place}: sealed under a chosen password alone`); continue; }
    if (place.startsWith('file') && seal !== 'made') { wrong.push(`${place}: a file of a key whose password the wallet did not make`); continue; }
    if (seal === 'made') {
      if (!await any(record, shown)) wrong.push(`${place}: marked as made, and no password shown opens it`);
      if (await any(record, typed)) wrong.push(`${place}: opens with what was typed`);
    }
    if (seal === 'device') {
      if (await any(record, [...typed, ...shown], new Uint8Array(32).fill(7))) wrong.push(`${place}: opens without the device's secret`);
      if (device && !await any(record, [...typed, ...shown], await device(record))) wrong.push(`${place}: locked to the device, and opens with nothing typed or shown and the device's secret`);
    }
    if (seal === 'under' && !records.some(([, other]) => other.version !== 4 && other.binding?.publicKey === record.under.publicKey && vaultIntent(other) === 'signin')) wrong.push(`${place}: kept under a login key that this storage does not hold`);
  }
  return wrong;
}

/// A record as sealVault made it before the rule: version 1 for a key of `intent` 'device', version 2 for 'signin' or
/// 'spend' (the plaintext then holds `pkcs8` only).
export async function sealLegacy(secret, password, binding, argon2id, cryptoImpl = globalThis.crypto, intent = 'device') {
  if (typeof password !== 'string') throw new TypeError('A legacy record is sealed under a text.');
  const kept = { networkId: binding.networkId, name: binding.name, publicKey: binding.publicKey };
  const header = intent === 'device' ? { version: 1, binding: kept, kdf: { ...KDF } } : { version: 2, intent, binding: kept, kdf: { ...KDF } };
  if (intent !== 'device' && (!secret || Object.keys(secret).join(',') !== 'pkcs8')) throw new Error('Invalid vault contents');
  const salt = cryptoImpl.getRandomValues(new Uint8Array(16)), iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const derived = await argon2id({ password: encoder.encode(password), salt, parallelism: KDF.parallelism, iterations: KDF.iterations, memorySize: KDF.memoryKiB, hashLength: KDF.hashLength, outputType: 'binary' });
  const key = await cryptoImpl.subtle.importKey('raw', derived, { name: 'AES-GCM' }, false, ['encrypt']);
  derived.fill(0);
  const ciphertext = await cryptoImpl.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(JSON.stringify(header)), tagLength: 128 }, key, encoder.encode(JSON.stringify(secret)));
  return { ...header, salt: b64(salt), iv: b64(iv), ciphertext: b64(ciphertext) };
}
