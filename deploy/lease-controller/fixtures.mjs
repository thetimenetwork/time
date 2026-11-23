// Shared by the tests of the signer-lease controller. Every key is made when a test runs;
// nothing here is a secret and nothing is read from the machine.
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { sha256 } from '../lib.mjs';
import { buildRequest, newNonce } from '../lease-protocol.mjs';
import { signer } from './start.mjs';

/// An Ed25519 key in the form readKeyFile returns.
export function keyPair(id) {
  const pair = generateKeyPairSync('ed25519');
  return { id, privateKey: pair.privateKey, publicKeyHex: pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex') };
}

/// A release manifest the kit's validateRelease accepts. `tag` makes different releases.
export function manifest(engine = 'v5', tag = 'one') {
  const pin = (letter) => 'image@sha256:' + letter.repeat(64);
  const identity = { schema_version: 2, protocol_version: 4, ...(engine === 'v5' ? { engine: 'v5' } : {}), platform: 'linux/amd64', image_pins: { rust: pin('a'), go: pin('b'), runtime: pin('c') }, source_files: [], generated_dockerignore_sha256: sha256(Buffer.from(tag)), binaries: [], evidence: [], sbom_sha256: sha256(Buffer.from('sbom ' + tag)) };
  return { ...identity, release_id: sha256(Buffer.from(JSON.stringify(identity))), status: 'DEVELOPMENT_CANDIDATE', public_funds_allowed: false, mainnet_receipts_enabled: false, monetary_enable_toggle: false };
}

/// A small network of one organization: an authority, hosts with their keys and signers,
/// consensus keys, a genesis, two releases and the controller config for them.
export function world({ engine = 'v5', hosts = ['host-a', 'host-b', 'host-c'], validators = 2, settings = {} } = {}) {
  const authority = keyPair('lease-authority-1'), chainId = 'time-devnet-v4-lease-test';
  const hostKeys = Object.fromEntries(hosts.map((id) => [id, keyPair(id)]));
  const validatorKeys = Array.from({ length: validators }, () => keyPair('validator').publicKeyHex);
  const genesisText = JSON.stringify({ chain_id: chainId, app_state: { ledger: { chain_id: chainId }, bitcoin: { mainnet_receipts_enabled: false }, validators: validatorKeys.map((key) => ({ consensus_key: key })) } });
  const config = {
    data_directory: path.resolve('/nonexistent/lease-controller-test'), authority_key_file: path.resolve('/nonexistent/authority.json'), fence_domain: 'test-domain',
    network: { chain_id: chainId, genesis_sha256: sha256(Buffer.from(genesisText)), engine },
    hosts: hosts.map((id) => ({ id, public_key_hex: hostKeys[id].publicKeyHex, signer_identity: 'signer-of-' + id, signer_fencing: 'EVERY_SIGNATURE' })),
    host: '127.0.0.1', port: 8960, lease_seconds: 240, clock_skew_seconds: 10, stop_seconds: 40, ...settings,
  };
  const trust = { schema_version: 1, release_organization: 'release-author', authorities: [{ id: authority.id, organization: 'operating-organization', public_key_hex: authority.publicKeyHex, roles: ['signer_lease'] }] };
  return { engine, authority, sign: signer(authority), hostKeys, validatorKeys, chainId, genesisText, config, trust, releases: { one: manifest(engine, 'one'), two: manifest(engine, 'two') } };
}

/// The request host `hostId` would sign at host time `timeMs` for consensus key `validatorKey`.
export function ask(w, hostId, validatorKey, { timeMs, nonce = newNonce(), previous = '', release = w.releases.one, key = w.hostKeys[hostId], scope = {} } = {}) {
  const engine = Object.hasOwn(release, 'engine') ? { engine: 'v5' } : {};
  return buildRequest({ hostId, privateKey: key.privateKey, timeMs, nonce, previousLeaseId: previous, scope: { release_id: release.release_id, genesis_sha256: w.config.network.genesis_sha256, chain_id: w.chainId, validator_public_key_hex: validatorKey, signer_identity: 'signer-of-' + hostId, ...engine, ...scope } });
}

const SENTRIES = ['a'.repeat(40) + '@sentry-one:26656', 'b'.repeat(40) + '@sentry-two:26656'];

/// The operator directory of one validator host, as the kit's guard reads it: genesis, release
/// manifest, trust file and settings. Returns the settings, with real paths in a new directory.
export async function operatorDirectory(w, hostId, validatorKey, { release = w.releases.one, trust = w.trust } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'time-lease-host-'));
  const file = (name) => path.join(directory, name);
  await writeFile(file('genesis.json'), w.genesisText);
  await writeFile(file('release.json'), JSON.stringify(release));
  await writeFile(file('trust.json'), JSON.stringify(trust));
  const settings = { release_manifest: file('release.json'), release_id: release.release_id, genesis_file: file('genesis.json'), genesis_sha256: w.config.network.genesis_sha256, chain_id: w.chainId, validator_public_key_hex: validatorKey, signer_identity: 'signer-of-' + hostId, signer_lease_file: file('signer-lease.json'), trust_file: file('trust.json'), sentry_peers: SENTRIES };
  await writeFile(file('settings.json'), JSON.stringify(settings));
  return { directory, settings, settingsFile: file('settings.json') };
}

/// A deterministic random source, so that a failing schedule can be run again from its seed.
export function random(seed) {
  let a = seed >>> 0;
  const next = () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  return { next, int: (low, high) => low + Math.floor(next() * (high - low + 1)), pick: (list) => list[Math.floor(next() * list.length)], chance: (p) => next() < p };
}
