#!/usr/bin/env node
// The genesis of a production-profile network on the version-5 engine, as a ceremony that needs no trust in
// whoever runs it.
//
// Every input is public: a ceremony file (chain id, genesis time and the network's fee choices) and one entry per
// starting validator. Each operator makes its entry from its own enrollment (`deploy/keygen.mjs`) and signs it
// with its consensus key, so nobody else can change its owner account, that account's keys or its commission.
// The same inputs give the same genesis bytes. Every operator rebuilds the genesis with `check`, which also finds
// its own entry, unchanged, and pins the hash it computed itself, not one it was sent.
//
//   node tools/genesis-v5.mjs ceremony --chain-id time-devnet-v4-NAME --genesis-time 2026-12-01T12:00:00.000Z --out ceremony.json
//   node tools/genesis-v5.mjs account-key --out /offline/login-key.json          (once for each key, where it will be kept)
//   node tools/genesis-v5.mjs entry --enrollment DIR --chain-id time-devnet-v4-NAME --organization ORG --account-name NAME \
//     --commission-bps 1000 --provider aws --region eu-west-3 --owner-key-file /offline/payment-key.json \
//     --login-public-key HEX --recovery-public-keys HEX,HEX --daily-limit-seconds 3600
//   node tools/genesis-v5.mjs collect --out entries.json ENTRY_FILE...
//   node tools/genesis-v5.mjs build --ceremony ceremony.json --entries entries.json --out NEW_DIR
//   node tools/genesis-v5.mjs check --ceremony ceremony.json --entries entries.json --genesis genesis.json \
//     --network network.json --entry validator-entry.json [--sha256 HEX]
//
// Every file the tool reads must be in the form it writes: two-space JSON with one newline at the end. That form
// has one spelling for each content, so a file cannot show one thing to a reader and parse as another (a key
// written twice, say).
//
// What the engine requires of a production network, and this tool writes:
// - twenty starting validators, each with the production genesis power (one minimum bond, 86,400 seconds);
// - all new time to validators, with no bitcoin auction, and the stake hand-over rule;
// - distinct account names: the network refuses a new name that looks like a name that exists, so no two of the
//   twenty owners' account names may look alike (`nameSkeleton` below; the engine's rule is `v5/src/names.rs`);
// - waits that survive a stop, and registrations that can carry a set of keys (`waits_survive_stops` and
//   `protected_registration`; the engine's rules are in `v5/src/security.rs`);
// - service records from the first block (`service_records`, `v5/src/service.rs`): facts about validators, stake
//   and accounts that no rule reads yet, kept so that a later rule can measure the time before it;
// - an hourly auction epoch and recovery delays of at least two days.
// The engine lets a genesis list accounts that start protected; this tool requires it of every owner account.
// Each starts with a payment key, a login key and at least two recovery keys, a daily limit and waits of at
// least two days, written into the genesis (`protected_accounts`), so that no owner account ever has one key
// that can do everything.
// The bitcoin, treasury and auction sections are part of the protocol-4 format and are checked like any others,
// but on such a network their actions are refused (kinds 40 to 42 and 60 to 63). Their keys here are points
// derived from a hash, whose private keys nobody knows.
//
// The engine accepts only `time-devnet-v4-` chains and reports publicLaunchAllowed=false, so what this builds is a
// production-profile network for rehearsal, not a launch that may hold value.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstat, mkdir, readFile, realpath, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const VALIDATORS = 20;
/// `pos::Profile::Production.genesis_power()`: one minimum bond (86,400 seconds) in whole seconds.
export const GENESIS_POWER = '86400';
const DAY_MICROS = 86_400_000_000n;
/// The engine settings every production network carries after the protocol-4 fields, in the node's order. The
/// list of the owner accounts that start protected (`protected_accounts`) follows them, and then the settings
/// of FINAL_SETTINGS, last.
export const PRODUCTION_SETTINGS = Object.freeze({ all_new_time_to_validators: true, stake_handover: true, distinct_names: true, waits_survive_stops: true, protected_registration: true });
/// The settings the node writes after `protected_accounts`, which every production network carries as well: the
/// service records (`service_records`, `v5/src/service.rs`).
export const FINAL_SETTINGS = Object.freeze({ service_records: true });
/// What the application sets at InitChain (`v5/src/app.rs`, `consensus_params`): the genesis says the same, so
/// CometBFT never runs a block under parameters the application does not use.
export const CONSENSUS_PARAMS = Object.freeze({
  block: { max_bytes: String(4 * 1024 * 1024 + 256 * 1024), max_gas: '-1' },
  evidence: { max_age_num_blocks: '2000000', max_age_duration: String(14n * 86_400n * 1_000_000_000n), max_bytes: '65536' },
  validator: { pub_key_types: ['ed25519'] },
  version: { app: '4' },
  abci: { vote_extensions_enable_height: '0' },
});
/// An account id is `zone × 2^48 + number`, and zone 0 is this chain (docs/design/upgrade-mechanism.md, section 11).
/// The ids a genesis gives are below 2^48, so that every id of this chain keeps its value when zones arrive. The
/// node refuses a new network whose genesis names a higher one; this tool checks the same before it writes.
export const GENESIS_ID_BOUND = 2n ** 48n;
/// Refuses an application state whose account ids or validator owners are not canonical decimals below 2^48.
export function checkGenesisIds(appState) {
  const ids = [...appState.ledger.accounts.map((account) => account.id), ...appState.validators.map((validator) => validator.owner)];
  for (const id of ids) {
    if (typeof id !== 'string' || !/^(?:0|[1-9][0-9]{0,19})$/.test(id) || BigInt(id) >= GENESIS_ID_BOUND) throw Error('A genesis account id is a decimal below 2^48 (281474976710656); ids from there on are reserved for zones');
  }
}
const CEREMONY_KIND = 'time-v5-production-genesis-ceremony';
const ENTRY_KIND = 'time-v5-validator-entry';
const CEREMONY_FIELDS = ['schema_version', 'kind', 'chain_id', 'genesis_time', 'fee_micros', 'fees_to_validators_ppm', 'registration_fee_micros', 'recovery_min_delay_micros'];
const SIGNED_FIELDS = ['schema_version', 'kind', 'chain_id', 'organization', 'account_name', 'owner_public_key_hex', 'consensus_public_key_hex', 'consensus_address', 'node_id', 'commission_bps', 'provider', 'region', 'account_security'];
const ENTRY_FIELDS = [...SIGNED_FIELDS, 'consensus_signature'];
/// The roles of the keys of a protected account (`v5/src/security.rs`): a sign-in key signs website logins and
/// nothing the chain accepts, a spend key pays within the daily limit, a recovery key is one proof of two.
const ROLES = ['signin', 'spend', 'recover'];
const MAX_ACCOUNT_KEYS = 8;
/// The waiting periods of an account, in seconds: the engine's production minimum and its maximum.
const TWO_DAYS_SECONDS = 2n * 86_400n, THIRTY_DAYS_SECONDS = 30n * 86_400n;
const MAX_U64 = 2n ** 64n - 1n;

/// The one spelling of a JSON value this tool reads and writes.
export const canonicalText = (value) => JSON.stringify(value, null, 2) + '\n';
/// Parses `text` only if it is already in that spelling: a key written twice, padding, or another layout is refused.
export function parseCanonical(text, what) {
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw Error(`${what} is not JSON: ${error.message}`);
  }
  if (canonicalText(value) !== text) throw Error(`${what} is not in the form this tool writes (two-space JSON, each key once, one newline at the end); use the files the tool wrote, and "collect" for the list of entries`);
  return value;
}
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// --- Curve arithmetic, for checking keys and deriving keys nobody holds ---------------------------------------
function power(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}
const ED_P = 2n ** 255n - 19n;
const mod = (value) => ((value % ED_P) + ED_P) % ED_P;
const ED_D = mod(-121665n * power(121666n, ED_P - 2n, ED_P));
const ED_SQRT_M1 = power(2n, (ED_P - 1n) / 4n, ED_P);
const SECP_P = 2n ** 256n - 2n ** 32n - 977n;
const littleEndian = (bytes) => bytes.reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);

/// The point that 32 bytes encode on edwards25519, or null if they are not a canonical encoding (RFC 8032, 5.1.3).
function decodePoint(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) return null;
  const bytes = Buffer.from(hex, 'hex');
  const sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  const y = littleEndian(bytes);
  if (y >= ED_P) return null;
  const u = mod(y * y - 1n);
  const v = mod(ED_D * y * y + 1n);
  let x = mod(u * power(v, 3n, ED_P) * power(u * power(v, 7n, ED_P), (ED_P - 5n) / 8n, ED_P));
  const check = mod(v * x * x);
  if (check !== u) {
    if (check !== mod(-u)) return null;
    x = mod(x * ED_SQRT_M1);
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = mod(-x);
  return { x, y };
}
/// Whether `point` times the cofactor 8 is the identity: the eight points of small order, which
/// `ed25519_dalek::VerifyingKey::is_weak` refuses.
function smallOrder({ x, y }) {
  let [X, Y, Z] = [x, y, 1n];
  for (let i = 0; i < 3; i++) {
    // Doubling on -x^2 + y^2 = 1 + d x^2 y^2, projective (dbl-2008-hwcd with a = -1).
    const A = mod(X * X), B = mod(Y * Y), C = mod(2n * Z * Z), D = mod(-A);
    const E = mod((X + Y) * (X + Y) - A - B), G = mod(D + B), F = mod(G - C), H = mod(D - B);
    [X, Y, Z] = [mod(E * F), mod(G * H), mod(F * G)];
  }
  return X === 0n && Y === Z;
}
/// Whether `hex` is a public key the node accepts: lowercase hex, a canonical point, not of small order.
export function ed25519Point(hex) {
  const point = decodePoint(hex);
  return point !== null && !smallOrder(point);
}
function label(domain, chainId, index, counter) {
  return createHash('sha256').update(`${domain}\0${chainId}\0${index}\0${counter}`).digest();
}
/// The `index`th governance key of `chainId`: a point found by hashing, so nobody knows its private key.
export function inertGovernanceKey(chainId, index) {
  for (let counter = 0; ; counter++) {
    const bytes = label('TIME-V5-INERT-GOVERNANCE-KEY', chainId, index, counter);
    bytes[31] &= 0x7f;
    const hex = bytes.toString('hex');
    if (ed25519Point(hex)) return hex;
  }
}
/// The `index`th treasury key of `chainId`, a compressed secp256k1 point found the same way.
export function inertTreasuryKey(chainId, index) {
  for (let counter = 0; ; counter++) {
    const x = BigInt('0x' + label('TIME-V5-INERT-TREASURY-KEY', chainId, index, counter).toString('hex'));
    if (x >= SECP_P) continue;
    const square = (x * x * x + 7n) % SECP_P;
    const y = power(square, (SECP_P + 1n) / 4n, SECP_P);
    if ((y * y) % SECP_P === square) return '02' + x.toString(16).padStart(64, '0');
  }
}

// --- Entry signatures ------------------------------------------------------------------------------------------
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
/// What an operator's consensus key signs. It starts with two 0xff bytes, which no CometBFT sign-bytes can (they
/// start with the length of the message that follows), so the signature can never pass for a vote or a proposal.
export function entryMessage(entry) {
  const signed = Object.fromEntries(SIGNED_FIELDS.map((field) => [field, entry[field]]));
  return Buffer.concat([Buffer.from([0xff, 0xff]), Buffer.from('TIME-V5-VALIDATOR-ENTRY-V1\0'), Buffer.from(JSON.stringify(signed))]);
}
function verifyEntry(entry) {
  const signature = typeof entry.consensus_signature === 'string' ? Buffer.from(entry.consensus_signature, 'base64') : Buffer.alloc(0);
  if (signature.length !== 64 || signature.toString('base64') !== entry.consensus_signature) return false;
  const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519, Buffer.from(entry.consensus_public_key_hex, 'hex')]), format: 'der', type: 'spki' });
  return verify(null, entryMessage(entry), key, signature);
}

// --- Inputs ------------------------------------------------------------------------------------------------------
function exactFields(object, fields, what) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) throw Error(`${what} must be a JSON object`);
  const unknown = Object.keys(object).filter((key) => !fields.includes(key));
  const missing = fields.filter((key) => !Object.hasOwn(object, key));
  if (unknown.length) throw Error(`${what} has unknown fields: ${unknown.join(', ')}`);
  if (missing.length) throw Error(`${what} is missing: ${missing.join(', ')}`);
}
function decimal(value, what, min, max) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) throw Error(`${what} must be a whole number written as a string`);
  const number = BigInt(value);
  if (number < min || number > max) throw Error(`${what} must be from ${min} to ${max}`);
  return number;
}
/// `ledger::validate_genesis`: `time-devnet-` chains only, at most 50 characters; the v5 engine also requires
/// the `time-devnet-v4-` prefix.
export function checkChainId(chainId) {
  if (typeof chainId !== 'string' || !/^time-devnet-v4-[a-z0-9_-]+$/.test(chainId) || chainId.length > 50) {
    throw Error('chain_id must be time-devnet-v4- followed by lowercase letters, digits, _ or -, at most 50 characters in all');
  }
  return chainId;
}
/// A UTC time from 1970 to 9999 in the one form `Date#toISOString` writes for it: the node refuses earlier times,
/// and CometBFT cannot read later ones.
function canonicalTime(text) {
  const match = typeof text === 'string' ? /^(\d{4})-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.exec(text) : null;
  const ms = match ? Date.parse(text) : NaN;
  if (!match || Number(match[1]) < 1970 || !Number.isFinite(ms) || new Date(ms).toISOString() !== text) {
    throw Error('genesis_time must be a time from 1970 on, written like 2026-12-01T12:00:00.000Z');
  }
  return ms;
}
export function checkCeremony(ceremony) {
  exactFields(ceremony, CEREMONY_FIELDS, 'The ceremony');
  if (ceremony.schema_version !== 1 || ceremony.kind !== CEREMONY_KIND) throw Error(`The ceremony must be schema 1 of kind ${CEREMONY_KIND}`);
  checkChainId(ceremony.chain_id);
  canonicalTime(ceremony.genesis_time);
  decimal(ceremony.fee_micros, 'fee_micros', 1n, 1000n);
  decimal(ceremony.fees_to_validators_ppm, 'fees_to_validators_ppm', 0n, 1_000_000n);
  decimal(ceremony.registration_fee_micros, 'registration_fee_micros', 1000n, 18_446_744_073_709_551_615n);
  decimal(ceremony.recovery_min_delay_micros, 'recovery_min_delay_micros', 2n * DAY_MICROS, 30n * DAY_MICROS);
  return ceremony;
}
const consensusAddress = (publicKeyHex) => createHash('sha256').update(Buffer.from(publicKeyHex, 'hex')).digest().subarray(0, 20).toString('hex').toUpperCase();
/// Letters, digits and . , & ' ( ) _ - with single spaces between words: no space at either end, none doubled,
/// so two spellings of one name cannot look like two organizations.
const ORGANIZATION = /^[A-Za-z0-9](?:[A-Za-z0-9.,&'()_-]| (?=[^ ]))*$/;
const LABEL = /^[a-z0-9][a-z0-9-]{0,31}$/;
/// `ledger::valid_name`: 2 to 15 lowercase letters, digits or underscores.
const ACCOUNT_NAME = /^[a-z0-9_]{2,15}$/;
/// The skeleton of an account name, as the node computes it (`v5/src/names.rs`; the test vectors are
/// `spec/name-skeleton-vectors.json`): every _ is removed; every 0 becomes o and every 1 becomes l; then, in one
/// pass from left to right without overlap, rn becomes m and vv becomes w. Two names with the same skeleton look
/// alike. A production network has `distinct_names`: its node refuses a genesis in which two account names look
/// alike or a name is made of underscores alone, and later every new name that looks like a name that exists.
export function nameSkeleton(name) {
  if (typeof name !== 'string' || !ACCOUNT_NAME.test(name)) throw Error('An account name is 2 to 15 lowercase letters, digits or _');
  return name.replace(/_/g, '').replace(/0/g, 'o').replace(/1/g, 'l').replace(/w/g, 'vv').replace(/rn|vv/g, (pair) => (pair === 'rn' ? 'm' : 'w'));
}
function checkFields(entry, where, fields) {
  exactFields(entry, fields, where);
  if (entry.schema_version !== 1 || entry.kind !== ENTRY_KIND) throw Error(`${where} must be schema 1 of kind ${ENTRY_KIND}`);
  checkChainId(entry.chain_id);
  if (typeof entry.organization !== 'string' || entry.organization.length > 64 || !ORGANIZATION.test(entry.organization)) throw Error(`${where}: organization must be 1 to 64 letters, digits or . , & ' ( ) _ -, with single spaces between words`);
  if (typeof entry.account_name !== 'string' || !ACCOUNT_NAME.test(entry.account_name)) throw Error(`${where}: account_name must be 2 to 15 lowercase letters, digits or _`);
  if (nameSkeleton(entry.account_name) === '') throw Error(`${where}: account_name must hold a letter or a digit, not underscores alone`);
  for (const field of ['owner_public_key_hex', 'consensus_public_key_hex']) {
    if (!ed25519Point(entry[field])) throw Error(`${where}: ${field} must be a lowercase hex Ed25519 public key the node accepts`);
  }
  if (entry.owner_public_key_hex === entry.consensus_public_key_hex) throw Error(`${where}: the owner account key must not be the consensus key`);
  if (entry.consensus_address !== consensusAddress(entry.consensus_public_key_hex)) throw Error(`${where}: consensus_address does not belong to consensus_public_key_hex`);
  if (typeof entry.node_id !== 'string' || !/^[0-9a-f]{40}$/.test(entry.node_id)) throw Error(`${where}: node_id must be 40 lowercase hex characters`);
  if (!Number.isInteger(entry.commission_bps) || entry.commission_bps < 0 || entry.commission_bps > 2000) throw Error(`${where}: commission_bps must be a whole number from 0 to 2000`);
  for (const field of ['provider', 'region']) {
    if (typeof entry[field] !== 'string' || !LABEL.test(entry[field])) throw Error(`${where}: ${field} must be 1 to 32 lowercase letters, digits or -`);
  }
  checkAccountSecurity(entry, where);
}
/// The keys and the policy an owner account starts with, as an entry carries them and the genesis lists them
/// (`v5/src/genesis.rs`, `ProtectedAccount`, without the account's number): `{keys: [{public_key, role}], policy:
/// {threshold, daily_limit_micros, delay_seconds, freeze_seconds}}`, the keys sorted by public key. The payment
/// key is a spend key, the login key a sign-in key. `proofs` is how many proofs a root operation needs: the spend
/// keys together are one, each recovery key is one.
export function accountSecurity({ paymentPublicKeyHex, loginPublicKeyHex, recoveryPublicKeysHex, dailyLimitSeconds, waitDays = '2', freezeDays = '2', proofs = '2' }) {
  if (!Array.isArray(recoveryPublicKeysHex)) throw Error('Give the recovery public keys as a list');
  const whole = (value, what) => {
    if (!/^(0|[1-9][0-9]{0,19})$/.test(String(value))) throw Error(`${what} must be a whole number`);
    return BigInt(value);
  };
  const keys = [
    { public_key: paymentPublicKeyHex, role: 'spend' },
    { public_key: loginPublicKeyHex, role: 'signin' },
    ...recoveryPublicKeysHex.map((key) => ({ public_key: key, role: 'recover' })),
  ];
  for (const key of keys) if (typeof key.public_key !== 'string') throw Error('Give the payment, login and recovery public keys as lowercase hex');
  keys.sort((a, b) => (a.public_key < b.public_key ? -1 : a.public_key > b.public_key ? 1 : 0));
  return {
    keys,
    policy: {
      threshold: whole(proofs, 'proofs').toString(),
      daily_limit_micros: (whole(dailyLimitSeconds, 'daily-limit-seconds') * 1_000_000n).toString(),
      delay_seconds: (whole(waitDays, 'wait-days') * 86_400n).toString(),
      freeze_seconds: (whole(freezeDays, 'freeze-days') * 86_400n).toString(),
    },
  };
}
/// What the keys of an owner account must be, on top of what the node requires of any set of keys
/// (`security::check`: one to eight keys, sorted, each once, each in one role, at least one spend key, a threshold
/// from two to the number of recovery keys, waits within the network's bounds). A production ceremony also asks
/// for a login key and for two recovery keys, so that the account can be repaired without its payment key, and it
/// keeps the account's keys apart from the validator's consensus key.
function checkAccountSecurity(entry, where) {
  const setup = entry.account_security;
  const missing = `${where}: account_security must be {keys, policy}: the payment key, the login key and the recovery keys the owner account starts with, its daily limit and its waits`;
  if (!setup || typeof setup !== 'object' || Array.isArray(setup) || Object.keys(setup).join(',') !== 'keys,policy') throw Error(missing);
  const { keys, policy } = setup;
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > MAX_ACCOUNT_KEYS) throw Error(`${where}: an account has 1 to ${MAX_ACCOUNT_KEYS} keys`);
  keys.forEach((key, i) => {
    if (!key || typeof key !== 'object' || Array.isArray(key) || Object.keys(key).join(',') !== 'public_key,role') throw Error(`${where}: each account key is {public_key, role}`);
    if (!ed25519Point(key.public_key)) throw Error(`${where}: an account key must be a lowercase hex Ed25519 public key the node accepts`);
    if (!ROLES.includes(key.role)) throw Error(`${where}: the role of an account key is signin, spend or recover`);
    if (i > 0 && !(keys[i - 1].public_key < key.public_key)) throw Error(`${where}: the account keys must be sorted by public key, each key once and in one role`);
    if (key.public_key === entry.consensus_public_key_hex) throw Error(`${where}: an account key must not be the consensus key`);
  });
  const count = (role) => keys.filter((key) => key.role === role).length;
  if (count('spend') < 1) throw Error(`${where}: the account needs a payment key (role spend)`);
  if (count('signin') < 1) throw Error(`${where}: the account needs a login key (role signin)`);
  if (count('recover') < 2) throw Error(`${where}: the account needs at least two recovery keys (role recover), kept apart`);
  if (!keys.some((key) => key.role === 'spend' && key.public_key === entry.owner_public_key_hex)) throw Error(`${where}: owner_public_key_hex, the key the account is known by, must be its payment key`);
  if (!policy || typeof policy !== 'object' || Array.isArray(policy) || Object.keys(policy).join(',') !== 'threshold,daily_limit_micros,delay_seconds,freeze_seconds') throw Error(`${where}: the policy of the account is {threshold, daily_limit_micros, delay_seconds, freeze_seconds}`);
  decimal(policy.threshold, `${where}: the number of proofs (threshold)`, 2n, BigInt(count('recover')));
  decimal(policy.daily_limit_micros, `${where}: daily_limit_micros`, 0n, MAX_U64);
  for (const field of ['delay_seconds', 'freeze_seconds']) decimal(policy[field], `${where}: ${field}`, TWO_DAYS_SECONDS, THIRTY_DAYS_SECONDS);
}
/// Checks an entry, including that its consensus key signed exactly these fields.
export function checkEntry(entry, where = 'A validator entry') {
  checkFields(entry, where, ENTRY_FIELDS);
  if (!verifyEntry(entry)) throw Error(`${where}: the consensus key did not sign this entry as it stands`);
  return entry;
}
function checkEntries(entries, ceremony) {
  const chainId = ceremony.chain_id, minimumSeconds = BigInt(ceremony.recovery_min_delay_micros) / 1_000_000n;
  if (!Array.isArray(entries) || entries.length !== VALIDATORS) throw Error(`A production network starts with exactly ${VALIDATORS} validators; the list has ${Array.isArray(entries) ? entries.length : 'none'}`);
  entries.forEach((entry, i) => {
    checkEntry(entry, `Entry ${i + 1}`);
    if (entry.chain_id !== chainId) throw Error(`Entry ${i + 1} was made for ${entry.chain_id}, not for this ceremony's ${chainId}`);
    // The node refuses an account whose waits are shorter than the network's minimum, which this ceremony sets.
    for (const field of ['delay_seconds', 'freeze_seconds']) {
      if (BigInt(entry.account_security.policy[field]) < minimumSeconds) throw Error(`Entry ${i + 1} (${entry.organization}): ${field} of its account is below this ceremony's minimum of ${minimumSeconds / 86_400n} days. Its operator makes the entry again with --wait-days and --freeze-days of at least that`);
    }
  });
  // Naming both entries lets the coordinator ask the two operators which one copied the other's key.
  const unique = (field, what) => {
    const seen = new Map();
    for (const entry of entries) {
      const other = seen.get(entry[field]);
      if (other) throw Error(`Two entries share the same ${what}: ${other.organization} (${other.account_name}) and ${entry.organization} (${entry.account_name})`);
      seen.set(entry[field], entry);
    }
  };
  unique('account_name', 'account name');
  // The node refuses a genesis in which two account names look alike: found here, with both operators named.
  const skeletons = new Map();
  for (const entry of entries) {
    const skeleton = nameSkeleton(entry.account_name), other = skeletons.get(skeleton);
    if (other) throw Error(`Two entries have account names that look alike: ${other.organization} (${other.account_name}) and ${entry.organization} (${entry.account_name}). One of them chooses another name`);
    skeletons.set(skeleton, entry);
  }
  unique('owner_public_key_hex', 'owner account key');
  unique('consensus_public_key_hex', 'consensus key');
  unique('node_id', 'node id');
  const consensus = new Set(entries.map((e) => e.consensus_public_key_hex));
  if (entries.some((e) => consensus.has(e.owner_public_key_hex))) throw Error("An owner account key is another entry's consensus key");
  // Every key of every owner account, in whatever role: none is a consensus key, and none is on two accounts.
  // A key on two accounts means that one operator copied another's entry, or that one party holds both.
  const holders = new Map();
  for (const entry of entries) {
    for (const key of entry.account_security.keys) {
      if (consensus.has(key.public_key)) throw Error(`An account key of ${entry.organization} (${entry.account_name}) is another entry's consensus key`);
      const other = holders.get(key.public_key);
      if (other) throw Error(`Two entries share an account key: ${other.organization} (${other.account_name}) and ${entry.organization} (${entry.account_name})`);
      holders.set(key.public_key, entry);
    }
  }
  // One canonical order, whatever order the list came in: by consensus key.
  return [...entries].sort((a, b) => (a.consensus_public_key_hex < b.consensus_public_key_hex ? -1 : 1));
}

// --- The genesis -------------------------------------------------------------------------------------------------
/// Validators per value of `field`, counting names that differ only in letter case, spaces or punctuation as one
/// ("Org A", "org-a" and "OrgA" are one organization here).
function share(entries, field) {
  const counts = new Map();
  for (const entry of entries) {
    const key = entry[field].toLowerCase().replace(/[^a-z0-9]/g, '');
    const seen = counts.get(key) ?? { name: entry[field], validators: 0 };
    seen.validators += 1;
    counts.set(key, seen);
  }
  const all = [...counts.values()].sort((a, b) => b.validators - a.validators || (a.name < b.name ? -1 : 1));
  return { counts: all, largest: { ...all[0], share: all[0].validators / entries.length } };
}
/// The genesis of `ceremony` with `entries`: CometBFT's genesis file, its bytes and hash, the network manifest the
/// gateway and wallets load, and a report. Deterministic: nothing here reads the clock or draws randomness.
export function buildProductionGenesis({ ceremony, entries }) {
  checkCeremony(ceremony);
  const ordered = checkEntries(entries, ceremony);
  const chainId = ceremony.chain_id;
  const genesisTimeMicros = String(BigInt(canonicalTime(ceremony.genesis_time)) * 1000n);
  // The application state, field by field in the node's order (`v5/src/genesis.rs`): the network id is a hash of
  // these bytes, and the node checks them by encoding them again.
  const appState = {
    history_version: 1,
    bitcoin_receipt_version: 1,
    reward_version: 1,
    ledger: {
      chain_id: chainId,
      genesis_time_micros: genesisTimeMicros,
      accounts: ordered.map((e, i) => ({ id: String(i), name: e.account_name, public_key: e.owner_public_key_hex })),
      economics: { mode: 'bank_only', auction_epoch_seconds: '3600', unbond_seconds: '1209600', operators: [] },
    },
    profile: 'production',
    validators: ordered.map((e, i) => ({ owner: String(i), consensus_key: e.consensus_public_key_hex, commission_bps: e.commission_bps })),
    bitcoin: { network: 'regtest', confirmations: 12, max_batch: 256, max_fork_tips: 32, retention: 8192, max_reorg: 144, max_tip_age_secs: 7200, max_future_secs: 7200, mainnet_receipts_enabled: false },
    treasury: {
      revision: 1,
      treasury_keys: Array.from({ length: 7 }, (_, i) => inertTreasuryKey(chainId, i)).sort(),
      governance_keys: Array.from({ length: 7 }, (_, i) => inertGovernanceKey(chainId, i)),
    },
    auction: { epoch_seconds: '3600', bid_lead_epochs: '2', max_future_epochs: '48', min_sats: '1000', max_sats: '2100000000000000' },
    registration: { fee_micros: ceremony.registration_fee_micros, max_lifetime_micros: String(DAY_MICROS), bucket_micros: '3600000000' },
    recovery_min_delay_micros: ceremony.recovery_min_delay_micros,
    recovery_approval_window_micros: String(7n * DAY_MICROS),
    trusting_period_seconds: '604800',
  };
  // The optional settings are written only when they differ from the protocol-4 rule, as the node writes them.
  if (ceremony.fees_to_validators_ppm !== '0') appState.fees_to_validators_ppm = ceremony.fees_to_validators_ppm;
  if (ceremony.fee_micros !== '1000') appState.fee_micros = ceremony.fee_micros;
  Object.assign(appState, PRODUCTION_SETTINGS);
  // Every owner account starts protected: its keys in their roles and its policy, in the order of the account
  // ids and with each object's fields in the node's order (`ProtectedAccount`, `ProtectedKey`, `security::Policy`).
  appState.protected_accounts = ordered.map((e, i) => ({
    id: String(i),
    keys: e.account_security.keys.map((key) => ({ public_key: key.public_key, role: key.role })),
    policy: {
      threshold: e.account_security.policy.threshold,
      daily_limit_micros: e.account_security.policy.daily_limit_micros,
      delay_seconds: e.account_security.policy.delay_seconds,
      freeze_seconds: e.account_security.policy.freeze_seconds,
    },
  }));
  // After the protected accounts, last of all: the node writes the service records there.
  Object.assign(appState, FINAL_SETTINGS);
  // This tool numbers the accounts 0 to 19, far below the bound; the check holds for whatever writes them later.
  checkGenesisIds(appState);

  const validators = ordered.map((e) => ({
    address: e.consensus_address,
    pub_key: { type: 'tendermint/PubKeyEd25519', value: Buffer.from(e.consensus_public_key_hex, 'hex').toString('base64') },
    power: GENESIS_POWER,
    name: e.organization,
  }));
  const genesis = { genesis_time: ceremony.genesis_time, chain_id: chainId, initial_height: '1', consensus_params: structuredClone(CONSENSUS_PARAMS), validators, app_hash: '', app_state: appState };
  const genesisBytes = Buffer.from(JSON.stringify(genesis));
  const genesisSha256 = sha256(genesisBytes);
  const networkId = createHash('sha256').update('TCDEVNET-NETWORK-V4\0').update(JSON.stringify(appState)).digest('hex');
  // The same shape as the campaign's manifest (`campaign/lib/genesis.mjs`), which the gateway and wallets load.
  const manifest = {
    schemaVersion: 4, protocolVersion: '4', networkId, chainId, publicLaunchAllowed: false, genesis: appState,
    trust: {
      chain_id: chainId, network_id: networkId, app_version: '4', genesis_time_micros: genesisTimeMicros,
      trusting_period_seconds: '604800', unbonding_period_seconds: '1209600',
      initial_validators: validators.map((v) => ({ address: v.address, pub_key: v.pub_key, voting_power: GENESIS_POWER, proposer_priority: '0' })),
      // A production network starts on nodes that answer the question about scheduled upgrades
      // (time-node-v5 0.7.0 and later). Saying so here, in the trust data that wallets, servers and
      // the alert watch pin, makes them ask it with every verified read from the first one, so that
      // no gateway can hold or refuse the question. It is never learned from a gateway's answer.
      nodes_report_upgrades: true,
    },
  };
  const manifestBytes = Buffer.from(canonicalText(manifest));
  const concentration = { organization: share(ordered, 'organization'), provider: share(ordered, 'provider'), region: share(ordered, 'region') };
  const warnings = [];
  for (const [what, { largest }] of Object.entries(concentration)) {
    if (largest.share > 2 / 3) warnings.push(`One ${what} (${largest.name}) runs ${largest.validators} of ${VALIDATORS} starting validators, over two thirds of the votes: it alone can sign anything while the starting validators hold the power.`);
    else if (largest.share > 1 / 3) warnings.push(`One ${what} (${largest.name}) runs ${largest.validators} of ${VALIDATORS} starting validators, over a third of the votes: it alone can stop the network, and by signing twice it can help two conflicting blocks be finalized.`);
  }
  const report = {
    chain_id: chainId,
    network_id: networkId,
    genesis_sha256: genesisSha256,
    network_json_sha256: sha256(manifestBytes),
    inputs: { ceremony_sha256: sha256(canonicalText(ceremony)), entries_sha256: sha256(canonicalText(entries)) },
    genesis_time: ceremony.genesis_time,
    validators: VALIDATORS,
    power_each: GENESIS_POWER,
    settings: {
      profile: 'production',
      ...PRODUCTION_SETTINGS,
      ...FINAL_SETTINGS,
      fee_micros: ceremony.fee_micros,
      fees_to_validators_ppm: ceremony.fees_to_validators_ppm,
      registration_fee_micros: ceremony.registration_fee_micros,
      recovery_min_delay_hours: Number(BigInt(ceremony.recovery_min_delay_micros) / 3_600_000_000n),
    },
    concentration,
    concentration_note: 'Organizations, providers and regions are what each operator declared; nothing here can prove them.',
    warnings,
    public_launch_allowed: false,
    why_not_public: 'The engine accepts only time-devnet-v4- chains and reports publicLaunchAllowed=false. A launch that may hold value needs that guard lifted, an external audit and the launch gates of deploy/launch-check.mjs.',
  };
  return { genesis, genesisBytes, genesisSha256, networkId, manifest, manifestBytes, report };
}

/// A ceremony file with the protocol-4 fee choices unless told otherwise.
export function makeCeremony({ chainId, genesisTime, feeMicros = '1000', feesToValidatorsPpm = '0', registrationFeeMicros = '10000', recoveryMinDelayDays = '2', now = Date.now() }) {
  if (!/^[1-9][0-9]?$/.test(String(recoveryMinDelayDays))) throw Error('recovery-min-delay-days must be a whole number of days from 2 to 30');
  const ceremony = checkCeremony({
    schema_version: 1, kind: CEREMONY_KIND, chain_id: chainId, genesis_time: genesisTime,
    fee_micros: String(feeMicros), fees_to_validators_ppm: String(feesToValidatorsPpm),
    registration_fee_micros: String(registrationFeeMicros),
    recovery_min_delay_micros: String(BigInt(recoveryMinDelayDays) * DAY_MICROS),
  });
  if (canonicalTime(genesisTime) < now + 3_600_000) throw Error('Choose a genesis time at least an hour ahead, so every operator can rebuild the genesis and start in time');
  return ceremony;
}

async function absent(file) {
  try {
    await lstat(file);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  throw Error(`${file} exists already; nothing was written`);
}
/// Writes a new file that only the current user can read. On Windows, file modes mean nothing, so the file is
/// created empty, restricted to the user's security identifier with icacls, and only then written; if that fails,
/// nothing is kept. (The identifier, not the user name: on a domain a bare name can match another account.)
async function writeSecret(file, content) {
  if (process.platform !== 'win32') return writeFile(file, content, { flag: 'wx', mode: 0o600 });
  await writeFile(file, '', { flag: 'wx' });
  try {
    // Windows' own tools by full path: a `whoami` or `icacls` found first on the path (Git Bash has one) is not them.
    const system = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
    const sid = /"(S-1-[0-9-]+)"\s*$/.exec(execFileSync(path.join(system, 'whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' }))?.[1];
    if (!sid) throw Error('no security identifier');
    execFileSync(path.join(system, 'icacls.exe'), [file, '/inheritance:r', '/grant:r', `*${sid}:F`], { stdio: 'ignore' });
  } catch {
    await unlink(file);
    throw Error(`Could not restrict ${file} to your user with icacls; nothing was written`);
  }
  await writeFile(file, content, { flag: 'r+' });
}
/// Whether `child` would land inside `parent`, after following links and junctions: the real parent folder of
/// `child` is compared with the real `parent`, so neither `..name` nor a junction to `parent` gets past it.
async function inside(child, parent) {
  const real = async (p) => {
    try {
      return await realpath(p);
    } catch {
      return path.resolve(p);
    }
  };
  const target = path.join(await real(path.dirname(path.resolve(child))), path.basename(child));
  const relative = path.relative(await real(parent), target);
  return !(relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative));
}

/// A new Ed25519 key for an owner account, saved to `file`, which only the current user can read. Returns its
/// public key. Run it once for each key the entry needs a public key of (the login key, each recovery key), on
/// the machine or the medium where that key will be kept: two recovery keys made and left in one place are one
/// key to whoever finds the place.
export async function makeAccountKey({ file, label = 'account key' }) {
  if (typeof label !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$/.test(label)) throw Error('--label is 1 to 32 letters, digits, spaces, _ or -');
  await absent(file);
  const pair = generateKeyPairSync('ed25519');
  const publicKeyHex = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  await writeSecret(file, JSON.stringify({
    schema_version: 1, label, public_key_hex: publicKeyHex,
    private_key_pkcs8_base64: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    note: 'A key of a validator owner account. Its public key goes into the validator entry, in the role you chose for it. Keep this file offline, and apart from the account\'s other keys.',
  }, null, 2) + '\n');
  return { publicKeyHex, file };
}

/// The signed entry of one starting validator, from its enrollment directory (`deploy/keygen.mjs`), which holds
/// the consensus key that signs it. The owner account starts protected: the entry names its payment key, its
/// login key, its recovery keys, its daily limit and its waits (`accountSecurity`). The owner key is the payment
/// key, and the key the account is known by. Without one, the tool makes it and saves it to `ownerKeyFile`,
/// which must be outside the enrollment directory: that directory goes to the signer, the owner key must not.
/// The other keys are made beforehand, each where it will be kept (`makeAccountKey`), and given by public key.
export async function makeEntry({ enrollment, chainId, organization, accountName, commissionBps, provider, region, ownerPublicKeyHex, ownerKeyFile, loginPublicKeyHex, recoveryPublicKeysHex, dailyLimitSeconds, waitDays, freezeDays, proofs }) {
  if (loginPublicKeyHex === undefined || recoveryPublicKeysHex === undefined || dailyLimitSeconds === undefined) {
    throw Error('Give --login-public-key, --recovery-public-keys (two or more, separated by commas) and --daily-limit-seconds: the owner account starts with a payment key, a login key and recovery keys, and a limit on what the payment key moves in a day');
  }
  const identity = JSON.parse(await readFile(path.join(enrollment, 'public-identity.json'), 'utf8'));
  if (identity.schema_version !== 1 || identity.key_source !== 'OS_CSPRNG_ED25519') throw Error('Expected the public-identity.json written by deploy/keygen.mjs');
  const secret = JSON.parse(await readFile(path.join(enrollment, 'consensus-enrollment.json'), 'utf8'));
  const raw = Buffer.from(secret?.priv_key?.value ?? '', 'base64');
  if (secret?.priv_key?.type !== 'tendermint/PrivKeyEd25519' || raw.length !== 64) throw Error('Expected the consensus-enrollment.json written by deploy/keygen.mjs');
  const consensusKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, raw.subarray(0, 32)]), format: 'der', type: 'pkcs8' });
  raw.fill(0);
  const derived = createPublicKey(consensusKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  if (derived !== identity.consensus_public_key_hex) throw Error('consensus-enrollment.json and public-identity.json are not the same key');

  const entryFile = path.join(enrollment, 'validator-entry.json');
  await absent(entryFile);
  let pair = null;
  if (ownerPublicKeyHex === undefined) {
    if (ownerKeyFile === undefined) throw Error('Give --owner-key-file, a new file outside the enrollment directory for the owner account key, or --owner-public-key for a key you hold');
    if (await inside(ownerKeyFile, enrollment)) throw Error('The owner key file must be outside the enrollment directory, which goes to the signer');
    await absent(ownerKeyFile);
    pair = generateKeyPairSync('ed25519');
  } else if (ownerKeyFile !== undefined) {
    throw Error('Give either --owner-public-key or --owner-key-file, not both');
  }
  const owner = pair ? pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex') : ownerPublicKeyHex;
  const unsigned = {
    schema_version: 1, kind: ENTRY_KIND, chain_id: chainId, organization, account_name: accountName,
    owner_public_key_hex: owner, consensus_public_key_hex: identity.consensus_public_key_hex,
    consensus_address: identity.consensus_address, node_id: identity.node_id,
    commission_bps: commissionBps, provider, region,
    account_security: accountSecurity({ paymentPublicKeyHex: owner, loginPublicKeyHex, recoveryPublicKeysHex, dailyLimitSeconds, waitDays, freezeDays, proofs }),
  };
  // Everything is checked before anything is written, so a mistake leaves no key behind.
  checkFields(unsigned, 'The entry', SIGNED_FIELDS);
  const entry = checkEntry({ ...unsigned, consensus_signature: sign(null, entryMessage(unsigned), consensusKey).toString('base64') });
  if (pair) {
    await writeSecret(ownerKeyFile, JSON.stringify({
      schema_version: 1, account_name: accountName, chain_id: chainId, public_key_hex: owner,
      private_key_pkcs8_base64: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      note: 'The payment key of the account that owns this validator and receives its rewards, and the key the account is known by. It pays within the account\'s daily limit; anything else needs a recovery key as well. Keep it offline, and apart from the recovery keys.',
    }, null, 2) + '\n');
  }
  await writeFile(entryFile, canonicalText(entry), { flag: 'wx', mode: 0o644 });
  return { entry, ownerKeyFile: pair ? ownerKeyFile : null };
}

/// The list of entries in one canonical order, each checked. The coordinator runs this as entries arrive.
export function collectEntries(entries) {
  entries.forEach((entry, i) => checkEntry(entry, `Entry ${i + 1}`));
  if (new Set(entries.map((e) => e.consensus_public_key_hex)).size !== entries.length) throw Error('Two entries share the same consensus key');
  if (entries.length > VALIDATORS) throw Error(`A production network starts with ${VALIDATORS} validators; there are ${entries.length} entries`);
  return [...entries].sort((a, b) => (a.consensus_public_key_hex < b.consensus_public_key_hex ? -1 : 1));
}

/// Rebuilds the genesis and compares it with `genesisBytes`, byte for byte, and with a hash and a network manifest
/// if given. `ownEntry` is the entry this operator made: it must be in the list exactly as made.
export function checkProductionGenesis({ ceremony, entries, genesisBytes, ownEntry, networkBytes, expectedSha256, now = Date.now() }) {
  if (ownEntry === undefined) throw Error('Give your own validator-entry.json: check confirms it is in the list unchanged');
  if (networkBytes === undefined) throw Error('Give network.json: check confirms it is the manifest these inputs give');
  checkEntry(ownEntry, 'Your entry');
  const built = buildProductionGenesis({ ceremony, entries });
  const listed = entries.find((e) => e.consensus_public_key_hex === ownEntry.consensus_public_key_hex);
  if (!listed || canonicalText(listed) !== canonicalText(ownEntry)) throw Error('Your entry is not in the list as you made it: do not start with this genesis');
  if (!built.genesisBytes.equals(genesisBytes)) throw Error('This genesis is not the one these inputs give: do not start with it');
  if (expectedSha256 !== undefined && expectedSha256 !== built.genesisSha256) throw Error('The genesis hash you were given is not the hash of these inputs');
  if (!built.manifestBytes.equals(networkBytes)) throw Error('This network.json is not the one these inputs give: do not give it to a gateway');
  const report = structuredClone(built.report);
  report.your_validator = { account: String(built.genesis.app_state.ledger.accounts.findIndex((a) => a.public_key === ownEntry.owner_public_key_hex)), consensus_address: ownEntry.consensus_address };
  const ahead = canonicalTime(ceremony.genesis_time) - now;
  if (ahead < 0) report.warnings.push('The genesis time has passed: start now, or a network that is already running goes on without you.');
  else if (ahead < 600_000) report.warnings.push('The genesis time is less than ten minutes away.');
  return report;
}

async function newDirectory(directory) {
  await absent(directory);
  await mkdir(directory, { recursive: false, mode: 0o755 });
}
export async function writeGenesis(directory, built) {
  await newDirectory(directory);
  const files = {
    'genesis.json': built.genesisBytes,
    'genesis.sha256': built.genesisSha256 + '\n',
    'network.json': built.manifestBytes,
    'report.json': canonicalText(built.report),
  };
  for (const [name, content] of Object.entries(files)) await writeFile(path.join(directory, name), content, { flag: 'wx', mode: 0o644 });
  return Object.keys(files).map((name) => path.join(directory, name));
}

// --- Command line ------------------------------------------------------------------------------------------------
/// The options each command takes. Anything else is refused, so a misspelt option never passes as left out.
const COMMANDS = {
  ceremony: ['chain-id', 'genesis-time', 'out', 'fee-micros', 'fees-to-validators-ppm', 'registration-fee-micros', 'recovery-min-delay-days'],
  'account-key': ['out', 'label'],
  entry: ['enrollment', 'chain-id', 'organization', 'account-name', 'commission-bps', 'provider', 'region', 'owner-public-key', 'owner-key-file', 'login-public-key', 'recovery-public-keys', 'daily-limit-seconds', 'wait-days', 'freeze-days', 'proofs'],
  collect: ['out'],
  build: ['ceremony', 'entries', 'out'],
  check: ['ceremony', 'entries', 'genesis', 'network', 'entry', 'sha256'],
};
function options(command, argv) {
  const allowed = COMMANDS[command];
  if (!allowed) throw Error('Usage: genesis-v5.mjs ceremony|account-key|entry|collect|build|check --name value ... (see the top of the file)');
  const parsed = { files: [] };
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) {
      if (command !== 'collect') throw Error(`Unexpected ${argv[i]}: ${command} takes only --name value pairs`);
      parsed.files.push(argv[i]);
      continue;
    }
    const name = argv[i].slice(2);
    if (!allowed.includes(name)) throw Error(`${command} has no option --${name}; it takes --${allowed.join(', --')}`);
    if (Object.hasOwn(parsed, name)) throw Error(`--${name} is given twice`);
    if (argv[i + 1] === undefined || argv[i + 1].startsWith('--')) throw Error(`--${name} needs a value`);
    parsed[name] = argv[++i];
  }
  return parsed;
}
const canonicalFile = async (file) => parseCanonical(await readFile(file, 'utf8'), file);
function required(parsed, ...names) {
  for (const name of names) if (parsed[name] === undefined) throw Error(`--${name} is required`);
}
async function main([command, ...argv]) {
  const o = options(command, argv);
  if (command === 'ceremony') {
    required(o, 'chain-id', 'genesis-time', 'out');
    const ceremony = makeCeremony({
      chainId: o['chain-id'], genesisTime: o['genesis-time'],
      feeMicros: o['fee-micros'], feesToValidatorsPpm: o['fees-to-validators-ppm'],
      registrationFeeMicros: o['registration-fee-micros'], recoveryMinDelayDays: o['recovery-min-delay-days'],
    });
    await writeFile(o.out, canonicalText(ceremony), { flag: 'wx' });
    return ceremony;
  }
  if (command === 'account-key') {
    required(o, 'out');
    const made = await makeAccountKey({ file: o.out, label: o.label });
    return { public_key_hex: made.publicKeyHex, file: made.file, next: 'Give the public key to the entry command in the role you chose for this key. Keep the file offline, and apart from the other keys of the account.' };
  }
  if (command === 'entry') {
    required(o, 'enrollment', 'chain-id', 'organization', 'account-name', 'commission-bps', 'provider', 'region', 'login-public-key', 'recovery-public-keys', 'daily-limit-seconds');
    if (!/^(0|[1-9][0-9]{0,3})$/.test(o['commission-bps'])) throw Error('--commission-bps must be a whole number from 0 to 2000');
    const { entry, ownerKeyFile } = await makeEntry({
      enrollment: o.enrollment, chainId: o['chain-id'], organization: o.organization, accountName: o['account-name'],
      commissionBps: Number(o['commission-bps']), provider: o.provider, region: o.region,
      ownerPublicKeyHex: o['owner-public-key'], ownerKeyFile: o['owner-key-file'],
      loginPublicKeyHex: o['login-public-key'], recoveryPublicKeysHex: o['recovery-public-keys'].split(','),
      dailyLimitSeconds: o['daily-limit-seconds'], waitDays: o['wait-days'], freezeDays: o['freeze-days'], proofs: o.proofs,
    });
    return { entry, ownerKeyFile, next: 'Send validator-entry.json to the coordinator and keep a copy: check needs it. Keep the payment key, the login key and each recovery key offline, the recovery keys apart from each other and from the payment key.' };
  }
  if (command === 'collect') {
    required(o, 'out');
    if (!o.files.length) throw Error('Name the entry files to collect');
    const entries = collectEntries(await Promise.all(o.files.map(canonicalFile)));
    await writeFile(o.out, canonicalText(entries), { flag: 'wx' });
    return { entries: entries.length, of: VALIDATORS, sha256: sha256(canonicalText(entries)) };
  }
  if (command === 'build') {
    required(o, 'ceremony', 'entries', 'out');
    const built = buildProductionGenesis({ ceremony: await canonicalFile(o.ceremony), entries: await canonicalFile(o.entries) });
    return { files: await writeGenesis(o.out, built), ...built.report };
  }
  if (command === 'check') {
    required(o, 'ceremony', 'entries', 'genesis', 'network', 'entry');
    return checkProductionGenesis({
      ceremony: await canonicalFile(o.ceremony), entries: await canonicalFile(o.entries), ownEntry: await canonicalFile(o.entry),
      genesisBytes: await readFile(o.genesis), networkBytes: await readFile(o.network), expectedSha256: o.sha256,
    });
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2))
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error) => { console.error(error.message); process.exitCode = 1; });
}
