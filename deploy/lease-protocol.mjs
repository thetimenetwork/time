// What the signer-lease controller (deploy/lease-controller/) and the host agent
// (deploy/lease-agent.mjs) must agree on: the request a host signs, the key files of both, and
// the limits. docs/design/signer-lease-controller.md, section 3, is the specification.
// No dependency outside Node's standard library and deploy/lib.mjs.
import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { lstat, open, readFile } from 'node:fs/promises';
import { canonical, rawEd25519 } from './lib.mjs';

/// A host signs these bytes: the prefix, then the canonical JSON of the request payload. The
/// prefix is not the attestation prefix of deploy/lib.mjs, so a host key can never sign something
/// that verifies as an attestation, even if its public key were put into a trust file by mistake.
export const REQUEST_PREFIX = 'TIME-LEASE-REQUEST-V1\0';
export const MAX_BODY_BYTES = 16 * 1024;
/// The guard refuses a lease whose expires_utc is more than this after its issued_utc.
export const GUARD_MAX_LEASE_MS = 300_000;
/// Host ids, authority ids and fence domains.
export const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const NONCE = /^[a-f0-9]{32}$/;
const HEX32 = /^[a-f0-9]{64}$/;
const SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
/// What a lease file may hold as its lease_id. The empty string says "this host holds no lease".
const PREVIOUS = /^[A-Za-z0-9._:-]{0,128}$/;
const TEXT = /^[\x21-\x7e][\x20-\x7e]{0,127}$/;
const PAYLOAD_KEYS = ['chain_id', 'genesis_sha256', 'host_id', 'kind', 'nonce', 'previous_lease_id', 'release_id', 'signer_identity', 'time_ms', 'validator_public_key_hex', 'version'];

export const requestBytes = (payload) => Buffer.from(REQUEST_PREFIX + canonical(payload));
export const newNonce = () => randomBytes(16).toString('hex');

/// What a host asks a lease for: taken from its operator settings and its pinned release.
/// `engine` is 'v4' or 'v5'; the request names it only for v5, as the lease does.
export function scopeOf(settings, engine) {
  return {
    release_id: settings.release_id, genesis_sha256: settings.genesis_sha256, chain_id: settings.chain_id,
    validator_public_key_hex: settings.validator_public_key_hex, signer_identity: settings.signer_identity,
    ...(engine === 'v5' ? { engine: 'v5' } : {}),
  };
}

/// The signed request of section 3.4.
export function buildRequest({ hostId, privateKey, timeMs, nonce, previousLeaseId, scope }) {
  const payload = { kind: 'lease_request', version: 1, host_id: hostId, time_ms: timeMs, nonce, previous_lease_id: previousLeaseId, ...scope };
  return { host_id: hostId, payload, signature: sign(null, requestBytes(payload), privateKey).toString('base64') };
}

/// Returns the payload of a request whose form is exactly the one of section 3.4. Throws with a
/// message that names the field and never quotes its value.
export function checkRequestShape(envelope) {
  const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
  if (!object(envelope) || Object.keys(envelope).sort().join(',') !== 'host_id,payload,signature') throw new Error('A request is {host_id, payload, signature}');
  const payload = envelope.payload;
  if (!object(payload)) throw new Error('payload is an object');
  const keys = Object.keys(payload).filter((key) => key !== 'engine').sort();
  if (keys.join(',') !== PAYLOAD_KEYS.join(',')) throw new Error('payload holds exactly ' + PAYLOAD_KEYS.join(', ') + ' and, on a v5 release, engine');
  if (payload.kind !== 'lease_request' || payload.version !== 1) throw new Error('kind is "lease_request" and version is 1');
  if (typeof payload.host_id !== 'string' || !NAME.test(payload.host_id) || envelope.host_id !== payload.host_id) throw new Error('host_id is a host name, the same inside and outside the payload');
  // 8.64e15 is the last millisecond a date can name; beyond it a time cannot even be printed.
  if (!Number.isSafeInteger(payload.time_ms) || payload.time_ms < 0 || payload.time_ms > 8_640_000_000_000_000) throw new Error('time_ms is the host clock in milliseconds');
  if (typeof payload.nonce !== 'string' || !NONCE.test(payload.nonce)) throw new Error('nonce is 32 hexadecimal characters');
  if (typeof payload.previous_lease_id !== 'string' || !PREVIOUS.test(payload.previous_lease_id)) throw new Error('previous_lease_id is the id of the installed lease, or empty');
  for (const name of ['release_id', 'genesis_sha256', 'validator_public_key_hex']) if (typeof payload[name] !== 'string' || !HEX32.test(payload[name])) throw new Error(name + ' is 64 hexadecimal characters');
  for (const name of ['chain_id', 'signer_identity']) if (typeof payload[name] !== 'string' || !TEXT.test(payload[name])) throw new Error(name + ' is 1 to 128 printable characters');
  if (Object.hasOwn(payload, 'engine') && payload.engine !== 'v5') throw new Error('engine is "v5", or absent for a v4 release');
  if (typeof envelope.signature !== 'string' || !SIGNATURE.test(envelope.signature)) throw new Error('signature is a base64 Ed25519 signature');
  return payload;
}

/// Whether the request carries the signature of this host key. The form must have been checked.
export function verifyRequest(envelope, publicKeyHex) {
  try { return verify(null, requestBytes(envelope.payload), rawEd25519(publicKeyHex), Buffer.from(envelope.signature, 'base64')); } catch { return false; }
}

// ---- Key files ------------------------------------------------------------------

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
export const KEY_PURPOSES = Object.freeze({ authority: 'signer-lease-authority', host: 'signer-lease-host' });

function fromSecret(secretHex) {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(secretHex, 'hex')]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKeyHex: createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex') };
}

/// A new key from the operating system's random source. The record is what the key file holds.
export function generateKeyRecord(purpose, id) {
  if (!Object.values(KEY_PURPOSES).includes(purpose)) throw new Error('Unknown key purpose');
  if (typeof id !== 'string' || !NAME.test(id)) throw new Error('The id is 1 to 64 characters: lower-case letters, digits, dot, dash, underscore; it starts with a letter or digit');
  const secret = randomBytes(32).toString('hex');
  return { schema_version: 1, purpose, id, public_key_hex: fromSecret(secret).publicKeyHex, secret_hex: secret };
}

/// Writes a key file. It never replaces a file, and only the owner can read it.
export async function writeKeyFile(file, record) {
  let handle;
  try { handle = await open(file, 'wx', 0o600); } catch (error) {
    if (error.code === 'EEXIST') throw new Error('A file is already there and is kept: choose a new name');
    throw error;
  }
  try { await handle.writeFile(JSON.stringify(record, null, 2) + '\n'); await handle.sync(); } finally { await handle.close(); }
  return { purpose: record.purpose, id: record.id, public_key_hex: record.public_key_hex };
}

/// Reads a key file after checking what it is and who else can read it. No message quotes the
/// file's contents. On Windows the permissions are not in the mode; they are left to the operator.
export async function readKeyFile(file, purpose) {
  let info;
  try { info = await lstat(file); } catch { throw new Error('The key file could not be read'); }
  if (info.isSymbolicLink() || !info.isFile() || info.size > 4096) throw new Error('The key file must be a small regular file, not a link');
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) throw new Error('The key file can be read by other users of this machine: chmod 600 it');
  let record;
  try { record = JSON.parse(await readFile(file, 'utf8')); } catch { throw new Error('The key file is not valid JSON'); }
  if (!record || record.schema_version !== 1 || record.purpose !== purpose) throw new Error('The key file is not a ' + purpose + ' key (made by the keygen command)');
  if (typeof record.id !== 'string' || !NAME.test(record.id) || typeof record.secret_hex !== 'string' || !HEX32.test(record.secret_hex)) throw new Error('The key file is damaged');
  const key = fromSecret(record.secret_hex);
  if (key.publicKeyHex !== record.public_key_hex) throw new Error('The key file is damaged: its public key is not the one of its secret');
  return { id: record.id, publicKeyHex: key.publicKeyHex, privateKey: key.privateKey };
}
