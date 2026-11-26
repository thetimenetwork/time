import { publicKeyStart, publicKeyEnd } from './public/armor.mjs';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const appDirectory = path.dirname(fileURLToPath(import.meta.url));
const testnetWallet = 'https://wallet.testnet.thetimenetwork.org';
const challengeLifetime = 3 * 60 * 1000;
const maxPendingBindings = 1024;
const hex32 = /^[0-9a-f]{64}$/;
const walletMessageFields = ['purpose', 'origin', 'networkId', 'accountId', 'authEpoch', 'publicKey', 'nonce', 'issuedAt', 'expiresAt'];
const ed25519Spki = Buffer.from('302a300506032b6570032100', 'hex');

function fail(message, status = 401) {
  throw Object.assign(new Error(message), { status });
}

function canonicalOrigin(value) {
  const url = new URL(value);
  const local = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if (url.origin !== value || !(url.protocol === 'https:' || (local && url.protocol === 'http:'))) {
    throw new Error('Use an HTTPS origin or a loopback HTTP origin.');
  }
  return value;
}

function publicArmor(value) {
  if (typeof value !== 'string' || value.length > 16_384) fail('Invalid chat public key.', 400);
  const armor = value.replaceAll('\r\n', '\n').trim() + '\n';
  if (!armor.startsWith(publicKeyStart + '\n') ||
      !armor.endsWith('\n' + publicKeyEnd + '\n') ||
      armor.includes('PRIVATE KEY') || armor.slice(1).includes('-----BEGIN ')) {
    fail('Expected a single armored chat public key.', 400);
  }
  return armor;
}

export function keyCommitment(salt, publicKey) {
  if (typeof salt !== 'string' || !hex32.test(salt)) fail('Invalid key binding salt.', 400);
  const input = JSON.stringify(['time-chat-key/v1', salt, publicArmor(publicKey)]);
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

async function checkpointFile(directory, networkId) {
  if (!directory) return undefined;
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const filename = path.join(directory, `time-checkpoint-${networkId}.json`);
  return {
    async getItem() {
      try { return await readFile(filename, 'utf8'); }
      catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    },
    async setItem(_key, value) {
      // The Time light client serializes and authenticates each checkpoint before this call.
      const temp = filename + '.' + randomBytes(12).toString('hex') + '.tmp';
      await writeFile(temp, value, { mode: 0o600, flag: 'wx', flush: true });
      await rename(temp, filename);
    }
  };
}

export async function createAuth({
  origin, dataDirectory, timeRoot = process.env.TIME_ROOT || path.join(appDirectory, '../..'),
  walletOrigin = process.env.TIME_WALLET_ORIGIN || testnetWallet,
  gateway = process.env.TIME_GATEWAY || walletOrigin,
  trustFile = process.env.TIME_TRUST_FILE || path.join(appDirectory, 'config/testnet-trust.json'),
  enrollmentOrigins = [origin], verifiedState: injectedReader, now = Date.now
}) {
  canonicalOrigin(origin);
  const acceptedEnrollments = new Set(enrollmentOrigins.map(canonicalOrigin));
  if (!acceptedEnrollments.has(origin)) throw new Error('The login origin must be an enrollment origin.');
  canonicalOrigin(walletOrigin);
  canonicalOrigin(gateway);
  const load = name => import(pathToFileURL(path.resolve(timeRoot, 'client-v4', name)).href);
  const [trust, helpers, security, verifier] = await Promise.all([
    readFile(trustFile, 'utf8').then(JSON.parse), load('server-auth.mjs'), load('account-security.mjs'), load('proof-verifier.mjs')
  ]);
  const networkId = trust.network_id;
  if (!hex32.test(networkId) || trust.app_version !== '4') throw new Error('Invalid pinned Time trust manifest.');
  const sdk = globalThis.TimeSDK;
  const client = sdk.createClient({ gateway, trust, verifier, checkpointStorage: await checkpointFile(dataDirectory, networkId) });
  // The optional reader is a programmatic unit-test dependency. Runtime startup uses the installed verifier.
  const read = injectedReader || (query => client.getVerifiedState(query, { timeoutMs: 18_000 }));
  async function verifiedState(query) {
    const result = await read(query);
    if (result?.verified !== true || result.state?.network_id !== networkId) fail('Time authority could not be verified.', 503);
    sdk.requireKnownVersion(result.state);
    return result;
  }
  const login = helpers.createLoginService({ origin, networkId, verifiedState, now });
  const pending = new Map();
  const user = session => ({ accountId: session.accountId, name: session.name, expiresAt: session.expiresAt });

  function issue(key) {
    if (key == null) {
      const { cookie, challenge } = login.issue();
      return { token: cookie, challenge };
    }
    const publicKey = publicArmor(key);
    const issuedAt = now();
    for (const [token, request] of pending) if (request.challenge.expiresAt <= issuedAt) pending.delete(token);
    if (pending.size >= maxPendingBindings) fail('Too many open key-binding requests. Try again shortly.', 429);
    const salt = randomBytes(32).toString('hex');
    const token = 'bind.' + randomBytes(32).toString('hex');
    const challenge = { purpose: 'login', origin, networkId, nonce: keyCommitment(salt, publicKey), issuedAt, expiresAt: issuedAt + challengeLifetime };
    pending.set(token, { publicKey, salt, challenge });
    return { token, challenge, salt };
  }

  async function current(token) {
    if (!token) return null;
    const active = await login.current(token);
    if (!active || login.session(token) !== active.session) return null;
    return user(active.session);
  }

  async function finish(token, proof, existingSessionToken) {
    if (typeof token !== 'string') fail('Open the Time wallet to sign in.');
    if (!token.startsWith('bind.')) {
      const result = await login.finish(token, proof);
      return { token: result.cookie, ...user(result.session), publicKey: null, attestation: null };
    }
    const request = pending.get(token);
    pending.delete(token);
    if (!request || request.challenge.expiresAt <= now()) fail('The key-binding request expired. Start again.');
    const session = login.session(existingSessionToken);
    if (!session || proof?.message?.accountId !== session.accountId) fail('Sign in to the same Time account before linking a key.');
    await helpers.verifyLogin({ verifiedState, networkId, origin, challenge: request.challenge, proof, now });
    if (!await current(existingSessionToken)) fail('Your Time session expired. Sign in again.');
    return {
      token: existingSessionToken, ...user(session), publicKey: request.publicKey,
      attestation: { version: 1, salt: request.salt, proof }
    };
  }

  async function resolveName(name) {
    if (typeof name !== 'string' || !/^[a-z0-9_]{2,15}$/.test(name)) fail('Invalid Time username.', 400);
    const { state } = await verifiedState({ names: [name] });
    const account = state.accounts.find(value => value.name === name);
    return account ? { accountId: String(account.id), name: account.name } : null;
  }

  async function verifyAttestation({ accountId, publicKey, attestation }) {
    const proof = attestation?.proof;
    const message = proof?.message;
    if (attestation?.version !== 1 || !message || Object.keys(message).join() !== walletMessageFields.join() ||
        message.purpose !== 'login' || !acceptedEnrollments.has(message.origin) || message.networkId !== networkId ||
        typeof accountId !== 'string' || sdk.decimal(accountId) !== accountId || message.accountId !== accountId ||
        typeof message.authEpoch !== 'string' || sdk.decimal(message.authEpoch) !== message.authEpoch ||
        typeof message.publicKey !== 'string' || !hex32.test(message.publicKey) ||
        typeof proof.signature !== 'string' || !/^[0-9a-f]{128}$/.test(proof.signature) ||
        message.nonce !== keyCommitment(attestation.salt, publicKey) ||
        !Number.isSafeInteger(message.issuedAt) || !Number.isSafeInteger(message.expiresAt) ||
        message.issuedAt < 0 || message.issuedAt > now() || message.expiresAt - message.issuedAt !== challengeLifetime) {
      fail('The chat key does not match its signed Time enrollment.');
    }
    // The SDK rejects an expired login challenge even when encoding its bytes. For historical
    // enrollment only, reconstruct its exact domain and canonical serialization. Never issue a session here.
    const bytes = Buffer.from('TCDEVNET-LOGIN-V1\0' + JSON.stringify(message));
    const key = createPublicKey({ key: Buffer.concat([ed25519Spki, Buffer.from(message.publicKey, 'hex')]), format: 'der', type: 'spki' });
    if (!verify(null, bytes, key, Buffer.from(proof.signature, 'hex'))) fail('Invalid Time enrollment signature.');
    const { state } = await verifiedState({ ids: [accountId], include_security: true });
    const account = state.accounts.find(value => String(value.id) === accountId);
    if (!account || !Array.isArray(state.security) || !Array.isArray(state.recovery_cases) ||
        String(account.auth_epoch) !== message.authEpoch) fail('The account authority for this chat key has changed.');
    const elapsed = BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
    const securityTime = state.config === undefined && state.stopped_micros === undefined ? elapsed : BigInt(sdk.securityNow(state));
    const refused = security.signInRefusal({ account, security: security.securityOf(state, accountId), publicKey: message.publicKey, nowElapsedMicros: securityTime });
    const frozen = state.recovery_cases.some(item => String(item.target) === accountId && item.ready_elapsed_micros != null && BigInt(item.expires_elapsed_micros) >= elapsed);
    if (refused || frozen) fail('The account no longer authorizes this signing key.');
    return { accountId, name: account.name };
  }

  async function verifyFreshLogin(challenge, proof) {
    const { account } = await helpers.verifyLogin({ verifiedState, networkId, origin, challenge, proof, now });
    return { accountId: String(account.id), name: account.name };
  }
  const refreshCheckpoint = () => verifiedState({ids:['0']});
  return { networkId, walletOrigin, sdkPath: path.resolve(timeRoot, 'client-v4/time-sdk.js'), issue, finish, current, logout: login.logout, resolveName, verifyAttestation, verifyFreshLogin, refreshCheckpoint };
}
