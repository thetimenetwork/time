// Signing up protected, through a sponsor: `client.registerProtected` (time-sdk.js) creates a newcomer's account
// with its keys in their roles and its daily limit from its first block (kind 45), at no cost to the newcomer, on a
// network whose genesis has `protected_registration`; the registration service pays for the commitment (kind 44).
//
// What runs here as it is: the SDK's client and the faucet of a test network (faucet.mjs), which is the registration
// service a gateway names on a test network. What stands in: the chain with its gateway, and the verifier. The
// stand-in chain applies the rules of spec/settings.md, section 4.1, that a sponsor's action and a registration meet
// (the consent of the registration key, the commitment, the form of the set, the acceptances), with the SDK's own
// functions, and the stand-in verifier passes on what that chain holds. That the engine takes these bytes is shown
// apart from this file: the registration made here is byte for byte the one the engine accepted
// (protected-registration.fixture.json, written by v5/tests/protected_registration.rs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import { createFaucetService } from './faucet.mjs';
import { acceptRegistrationRole } from './account-security.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('./protected-registration.fixture.json', import.meta.url), 'utf8'));
const NETWORK = fixture.network_id, GENESIS = 1700000000000000n, FAUCET = '8';
const TRUST = { app_version: '4', network_id: NETWORK, chain_id: 'time-devnet-v4-signup', genesis_time_micros: GENESIS.toString(), checkpoint: null };
const importSeed = (seed) => crypto.subtle.importKey('pkcs8', SDK.hexToBytes(`302e020100300506032b657004220420${seed}`), { name: 'Ed25519' }, false, ['sign']);
/// The keys of the engine's fixture: the newcomer's registration key and the four keys of its set, and the sponsor's
/// key, which is here the spend key of the faucet's account.
const keys = {};
for (const entry of fixture.seeds) keys[entry.name] = { publicKey: entry.public_key, privateKey: await importSeed(entry.seed_hex), seed: entry.seed_hex };
const NEWCOMER = ['registration', 'signin', 'spend', 'sheet', 'phrase'];
/// A key of somebody else's: the dishonest service's own.
async function strangerKey() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  return { publicKey: SDK.bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), privateKey: pair.privateKey };
}
/// What the newcomer's wallet passes: the name, the salt, the registration key, the keys by role, the limit and the waits.
const signUp = (more = {}) => ({ name: fixture.name, salt: fixture.salt, registration: keys.registration, keys: { signin: [keys.signin], spend: [keys.spend], recover: [keys.phrase, keys.sheet] },
  dailyLimitMicros: fixture.policy.daily_limit_micros, delaySeconds: fixture.policy.delay_seconds, freezeSeconds: fixture.policy.freeze_seconds, waitMs: 3000, ...more });
const verify = async (publicKey, signature, message) => crypto.subtle.verify('Ed25519', await crypto.subtle.importKey('raw', SDK.hexToBytes(publicKey, 32), 'Ed25519', false, ['verify']), SDK.hexToBytes(signature, 64), message);

// ------------------------------------------------------------------ the stand-in chain
function standInChain({ protectedRegistration = true } = {}) {
  const chain = { height: 10, elapsed: 5000000000n, accounts: [], security: {}, commits: [], included: new Map(), posted: [], refused: [], nextId: 12, watch: null };
  // The faucet's account: secured, with the fixture's sponsor key as its spend key and a recovery key besides.
  chain.accounts.push({ id: FAUCET, name: 'faucet', public_key: keys.sponsor.publicKey, balance: 900000000n, nonce: 0n, auth_epoch: '1',
    devices: [{ public_key: keys.sponsor.publicKey, can_manage: false, can_spend: true }, { public_key: 'ee'.repeat(32), can_manage: true, can_spend: false }] });
  chain.security[FAUCET] = { account: FAUCET, version: '1', policy: { threshold: '2', daily_limit_micros: '600000000', delay_seconds: '60', freeze_seconds: '120' }, allowance_micros: '600000000', allowance_elapsed_micros: chain.elapsed.toString(),
    frozen_until_elapsed_micros: '0', freezes: '0', next_id: '1', pending_limit: null, pending_payments: [], pending_root: null };
  /// A verified state for a selection, as the verifier gives one: what was asked for and the metadata row.
  chain.stateFor = (query = {}) => {
    const ids = query.ids || [], names = query.names || [], asked = query.public_keys || [];
    const accounts = chain.accounts.filter((a) => ids.includes(a.id) || names.includes(a.name) || asked.some((key) => a.public_key === key || a.devices.some((d) => d.public_key === key)));
    return structuredClone({
      protocol_version: '4', network_id: NETWORK, height: String(chain.height), time_micros: (GENESIS + chain.elapsed).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
      config: { registration: { fee_micros: '10000', max_lifetime_micros: '86400000000', bucket_micros: '3600000000' }, recovery_min_delay_micros: '30000000', ...(protectedRegistration ? { protected_registration: true } : {}) },
      accounts: accounts.map((a) => ({ ...a, balance: String(a.balance), nonce: String(a.nonce) })), recovery_cases: [],
      name_commits: chain.commits.filter((c) => asked.includes(c.public_key) && BigInt(c.expires_elapsed_micros) >= chain.elapsed),
      ...(query.include_security ? { security: accounts.map((a) => chain.security[a.id]).filter(Boolean) } : {}),
    });
  };
  chain.block = () => { chain.height += 1; chain.elapsed += 1000000n; };
  const commitOf = (key) => chain.commits.find((c) => c.public_key === key && BigInt(c.expires_elapsed_micros) >= chain.elapsed);
  /// The rules a sponsor's action (44), a registration with a set (45) and a reveal (2) meet. A refusal, or the change.
  async function judge(action, tx) {
    if (action.networkId !== NETWORK) return 'wrong network';
    if (!(await verify(action.publicKey, SDK.bytesToHex(tx.slice(-64)), tx.slice(0, -64)))) return 'invalid action signature';
    const p = action.payload;
    if (action.kind === 44) {
      const from = chain.accounts.find((a) => a.id === action.from);
      if (!from || !from.devices.some((d) => d.public_key === action.publicKey && d.can_spend)) return 'spending device required';
      if (BigInt(action.nonce) !== from.nonce + 1n) return 'incorrect nonce';
      // The registration key consents to exactly this sponsor, network, commitment and expiry.
      if (!(await verify(p.public_key, p.proof, SDK.sponsorConsentBytes({ networkId: NETWORK, sponsorAccount: action.from, publicKey: p.public_key, commitment: p.commitment, expiresElapsedMicros: p.expires_elapsed_micros })))) return 'invalid sponsorship consent';
      if (commitOf(p.public_key)) return 'a registration of this key is pending';
      return () => { from.nonce += 1n; from.balance -= 11000n; chain.commits.push({ public_key: p.public_key, commitment: p.commitment, entry_id: 'ee'.repeat(32), sponsor: action.from, created_elapsed_micros: chain.elapsed.toString(), expires_elapsed_micros: p.expires_elapsed_micros, height: String(chain.height) }); };
    }
    if (action.kind === 2 || action.kind === 45) {
      if (action.kind === 45 && !protectedRegistration) return 'unknown action kind';
      if (action.from !== SDK.MAX_U64 || action.nonce !== '0' || action.authEpoch !== '0') return 'a registration has no account, no nonce and no authority epoch';
      const reg = action.publicKey;
      if (chain.accounts.some((a) => a.name === p.name)) return `name ${p.name} is taken`;
      if (chain.accounts.some((a) => a.public_key === reg)) return 'the registration key belongs to an account';
      // A paid commitment of this key from an earlier block (this registration goes into the next one).
      const commit = commitOf(reg);
      if (!commit || BigInt(commit.height) > chain.height) return 'no paid commitment of this registration key from an earlier block';
      let expected = null;
      try { expected = action.kind === 2 ? await SDK.nameCommitment({ networkId: NETWORK, publicKey: reg, name: p.name, salt: p.salt }) : await SDK.protectedNameCommitment({ networkId: NETWORK, publicKey: reg, name: p.name, salt: p.salt, security: p.security }); } catch { expected = null; }
      if (expected !== commit.commitment) return 'the registration does not match its commitment';
      if (action.kind === 2) return () => { const id = String(chain.nextId++); chain.accounts.push({ id, name: p.name, public_key: reg, balance: 0n, nonce: 0n, auth_epoch: '0', devices: [{ public_key: reg, can_manage: true, can_spend: true }] }); chain.commits.splice(chain.commits.indexOf(commit), 1); };
      try { if (JSON.stringify(SDK.protectedSetup(p.security, chain.stateFor())) !== JSON.stringify(p.security)) return 'the set is not in its one form'; } catch (error) { return error.message; }
      for (const entry of p.security.keys) if (!(await verify(entry.public_key, entry.proof, SDK.registrationRoleBytes({ networkId: NETWORK, registrationKey: reg, role: entry.role, publicKey: entry.public_key })))) return 'an acceptance does not verify';
      return () => {
        const id = String(chain.nextId++);
        chain.accounts.push({ id, name: p.name, public_key: reg, balance: 0n, nonce: 0n, auth_epoch: '0', devices: p.security.keys.map((e) => ({ public_key: e.public_key, can_manage: e.role === 'recover', can_spend: e.role === 'spend' })) });
        chain.security[id] = { account: id, version: '1', policy: { ...p.security.policy }, allowance_micros: p.security.policy.daily_limit_micros, allowance_elapsed_micros: chain.elapsed.toString(), frozen_until_elapsed_micros: '0', freezes: '0', next_id: '1', pending_limit: null, pending_payments: [], pending_root: null };
        chain.commits.splice(chain.commits.indexOf(commit), 1);
      };
    }
    return 'not taken by this stand-in chain';
  }
  /// What a node does with signed bytes: null when a block took them, otherwise the refusal.
  chain.broadcast = async (bytes) => {
    const tx = new Uint8Array(bytes);
    let action;
    try { action = SDK.decodeAction(tx); } catch { return 'invalid action'; }
    chain.posted.push(action);
    // Whoever sees what is broadcast (here: the dishonest party) can act before it is judged, once.
    if (chain.watch?.wants(action)) { const watch = chain.watch; chain.watch = null; await watch.run(action); }
    const outcome = await judge(action, tx);
    if (typeof outcome === 'string') { chain.refused.push({ kind: action.kind, publicKey: action.publicKey, refusal: outcome }); return outcome; }
    chain.block(); outcome();
    chain.included.set(await SDK.transactionHash(tx), { height: String(chain.height), rawHex: SDK.bytesToHex(tx) });
    return null;
  };
  chain.sign = (args, privateKey) => SDK.signAction({ networkId: NETWORK, ...args }, privateKey);
  return chain;
}

// ------------------------------------------------------------------ the newcomer's client, over a stand-in gateway and verifier
function clientOf(chain) {
  const block = (height) => ({ signed_header: { header: { height: String(height) } } });
  const fetcher = async (url, options = {}) => {
    const address = new URL(String(url)), route = address.pathname;
    let answer;
    if (route === '/api/network') answer = { protocolVersion: '4', networkId: NETWORK, chainId: TRUST.chain_id };
    else if (route === '/api/light-block') answer = block(address.searchParams.get('height') || chain.height);
    // Time passes between two reads: each finds one block more.
    else if (route === '/api/view-proof') { chain.block(); answer = { light_block: block(chain.height) }; }
    else if (route === '/api/submit') {
      const tx = Buffer.from(JSON.parse(options.body).tx, 'base64'), refusal = await chain.broadcast(tx);
      answer = refusal ? { error: refusal } : { hash: await SDK.transactionHash(new Uint8Array(tx)), pending: true };
    } else if (route === '/api/receipt') {
      const hash = address.searchParams.get('hash'), found = chain.included.get(hash);
      answer = found ? { hash, ...found, anchor: { light_block: block(chain.height) } } : { pending: true };
    } else answer = { error: 'not served by this stand-in gateway' };
    return new Response(JSON.stringify(answer), { status: answer.error ? 400 : 200, headers: { 'Content-Type': 'application/json' } });
  };
  const verifier = {
    verifyTrust: async () => ({}),
    verifyLightUpdate: async (candidate) => ({ verified: true, status: 'VERIFIED', checkpoint: { height: candidate.signed_header.header.height, block_hash: 'cd'.repeat(32), block: candidate } }),
    verifyViewProof: async (_proof, _trust, query) => ({ verified: true, completeAccountSet: false, state: chain.stateFor(query) }),
    verifyReceipt: async (proof) => ({ verified: true, executionVerified: true, hash: proof.hash, rawHex: proof.rawHex, height: proof.height }),
  };
  return SDK.createClient({ gateway: 'http://gateway.test', trust: TRUST, verifier, fetcher });
}

// ------------------------------------------------------------------ the registration service
/// The faucet of a test network over the stand-in chain, as deploy/faucet/start.mjs starts it.
async function withFaucet(chain, work) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-signup-'));
  let faucet = null;
  try {
    faucet = await createFaucetService({
      trust: TRUST, networkId: NETWORK, testNetwork: true, account: FAUCET, key: { publicKey: keys.sponsor.publicKey, privateKey: keys.sponsor.privateKey },
      grantMicros: 5000000n, minBalanceMicros: 10000000n, maxRecipientBalanceMicros: 20000000n, maxChainDailyLimitMicros: 600000000n,
      limits: { perAccountPerDay: 1, perAddressPerDay: 3, totalPerDayMicros: 500000000n, registrationsPerAddressPerDay: 5 }, sponsorRegistrations: true,
      rpc: async (method, parameters) => {
        const raw = Buffer.from(parameters.tx.slice(2), 'hex'), refusal = await chain.broadcast(raw), hash = await SDK.transactionHash(new Uint8Array(raw));
        return refusal ? { code: 1, log: refusal, hash } : { code: 0, hash };
      },
      lookup: async (hash) => { const found = chain.included.get(hash); return found ? { height: found.height, tx: Buffer.from(found.rawHex, 'hex').toString('base64') } : null; },
      readState: async (selection) => ({ verified: true, state: chain.stateFor(selection) }),
      dataFile: path.join(directory, 'faucet.sqlite'), port: 0, autoStart: false, servePage: false, rateLimit: { perSecond: 1000, burst: 100000 }, storeSynchronous: 'OFF',
    });
    await work(faucet);
  } finally { await faucet?.close(); await rm(directory, { recursive: true, force: true }); }
}
/// How a wallet asks a registration service (web-v4/wallet/app.js, `registrationSponsor`): which account sponsors, for
/// which network, and then the sponsorship. Every body sent is kept in `sent`, as the service received it.
async function serviceSponsor(origin, sent) {
  const facts = await (await fetch(`${origin}/v1/faucet`)).json();
  assert.deepEqual([facts.network_id, facts.registrations.sponsored], [NETWORK, true]);
  return { account: String(facts.account), ask: async (body) => {
    const text = JSON.stringify(body); sent.push(text);
    const response = await fetch(`${origin}/v1/faucet/registrations`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: text });
    const answer = await response.json();
    if (response.ok && /^[0-9a-f]{64}$/i.test(answer.hash ?? '')) return { hash: answer.hash.toLowerCase() };
    if (answer?.error?.code === 'already_committed' && answer.same_commitment === true) return { alreadyCommitted: true };
    throw new Error(answer?.error?.message ?? `status ${response.status}`);
  } };
}
/// Nothing the newcomer holds secret, and nothing the commitment hides, is in what a service was sent.
function holdsNoSecret(sent) {
  const hidden = [...NEWCOMER.map((name) => keys[name].seed), fixture.name, fixture.salt, ...fixture.acceptances.flatMap((entry) => [entry.public_key, entry.proof])];
  for (const text of sent) {
    assert.deepEqual(Object.keys(JSON.parse(text)).sort(), ['commitment', 'expires_elapsed_micros', 'proof', 'public_key']);
    for (const secret of hidden) assert.ok(!text.includes(secret), `a service was sent ${secret.slice(0, 12)}…`);
  }
}

test('a newcomer signs up protected through the faucet: the account exists with exactly its keys, and the faucet saw nothing secret', async () => {
  const chain = standInChain(), sent = [];
  await withFaucet(chain, async (faucet) => {
    const client = clientOf(chain), sponsor = await serviceSponsor(faucet.url, sent);
    const result = await client.registerProtected({ sponsor, ...signUp() });
    // What the faucet paid for is the commitment the engine's own test paid for, and the registration is its action.
    const paid = SDK.decodeAction(SDK.hexToBytes(result.sponsorReceipt.rawHex));
    assert.deepEqual([paid.kind, paid.from, paid.publicKey, paid.payload.public_key, paid.payload.commitment], [44, FAUCET, keys.sponsor.publicKey, keys.registration.publicKey, fixture.commitment]);
    assert.equal(result.receipt.rawHex, fixture.registration.action_hex);
    // The account, from a verified state: the registration key as its identity, its four keys in their roles, its
    // policy, nothing in it and nothing paid by it. The faucet paid the registration charge and its fee.
    assert.deepEqual([result.account.name, result.account.public_key, result.account.balance, result.account.nonce], [fixture.name, keys.registration.publicKey, '0', '0']);
    assert.deepEqual(result.account.devices.map((d) => [d.public_key, d.can_manage, d.can_spend]).sort(), fixture.security.keys.map((e) => [e.public_key, e.role === 'recover', e.role === 'spend']).sort());
    assert.deepEqual([result.security.version, result.security.policy], ['1', fixture.policy]);
    assert.equal(chain.accounts.find((a) => a.id === FAUCET).balance, 900000000n - 11000n);
    // The faucet was asked once, with four fields: no private key, no name, no salt, no key of the set.
    assert.equal(sent.length, 1);
    holdsNoSecret(sent);
    // Called again (a wallet that stopped half way and starts over) it finds the account: nothing is asked or paid twice.
    const again = await client.registerProtected({ sponsor, ...signUp() });
    assert.deepEqual([again.account.id, again.receipt, sent.length], [result.account.id, null, 1]);
  });
});

test('the capability is read from verified state: without protected_registration nothing is sent, and the sign-up of before works unchanged', async () => {
  const chain = standInChain({ protectedRegistration: false }), sent = [];
  await withFaucet(chain, async (faucet) => {
    const client = clientOf(chain), sponsor = await serviceSponsor(faucet.url, sent);
    const { state } = await client.getVerifiedState({});
    assert.equal(SDK.protectedRegistration(state), false);
    await assert.rejects(client.registerProtected({ sponsor, ...signUp() }), (error) => error.code === 'PROTECTED_REGISTRATION_UNAVAILABLE');
    assert.deepEqual([sent.length, chain.posted.length], [0, 0]);
    // The reveal of before, through the same faucet: the protocol-4 commitment, and an account with one key.
    const reg = keys.registration, commitment = await SDK.nameCommitment({ networkId: NETWORK, publicKey: reg.publicKey, name: fixture.name, salt: fixture.salt });
    const expires = (chain.elapsed + 120000000n).toString();
    const proof = SDK.bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', reg.privateKey, SDK.sponsorConsentBytes({ networkId: NETWORK, sponsorAccount: sponsor.account, publicKey: reg.publicKey, commitment, expiresElapsedMicros: expires }))));
    const { hash } = await sponsor.ask({ public_key: reg.publicKey, commitment, expires_elapsed_micros: expires, proof });
    await client.waitReceipt(hash);
    chain.block();
    await client.submit(await SDK.signAction({ networkId: NETWORK, kind: 'reveal', from: SDK.MAX_U64, nonce: '0', authEpoch: '0', publicKey: reg.publicKey, payload: { name: fixture.name, salt: fixture.salt } }, reg.privateKey));
    assert.deepEqual(chain.accounts.find((a) => a.name === fixture.name).devices, [{ public_key: reg.publicKey, can_manage: true, can_spend: true }]);
  });
});

test('no sponsor is needed where the chain holds the commitment or the account; where it holds neither, SPONSOR_REQUIRED before anything is signed', async () => {
  const chain = standInChain(), sent = [];
  await withFaucet(chain, async (faucet) => {
    const client = clientOf(chain), sponsor = await serviceSponsor(faucet.url, sent);
    // Neither is on the chain: refused with its code, and nothing is signed, sent or asked.
    await assert.rejects(client.registerProtected(signUp()), (error) => error.code === 'SPONSOR_REQUIRED' && /call again with a sponsor/.test(error.message));
    assert.deepEqual([sent.length, chain.posted.length], [0, 0]);
    // The sponsor pays, and the registration does not reach a block the first time.
    const broadcast = chain.broadcast; let dropped = 0;
    chain.broadcast = async (bytes) => (SDK.decodeAction(new Uint8Array(bytes)).kind === 45 && dropped++ === 0 ? 'the node is busy' : broadcast(bytes));
    await assert.rejects(client.registerProtected({ sponsor, ...signUp() }));
    assert.deepEqual([sent.length, chain.commits.length, chain.accounts.some((a) => a.name === fixture.name)], [1, 1, false]);
    // The commitment is on the chain: no sponsor is passed, none is asked, and the account is made.
    const made = await client.registerProtected(signUp());
    assert.deepEqual([made.account.name, made.sponsorReceipt, sent.length], [fixture.name, null, 1]);
    // The account is on the chain: no sponsor either.
    const again = await client.registerProtected(signUp());
    assert.deepEqual([again.account.id, again.receipt, sent.length], [made.account.id, null, 1]);
    // A sponsor that is not {account, ask} is still refused.
    for (const wrong of [{}, { account: '8' }, { ask: async () => ({}) }, { account: '08', ask: async () => ({}) }, 'sponsor']) await assert.rejects(client.registerProtected({ sponsor: wrong, ...signUp() }), /A sponsor is \{account, ask\(body\)\}/);
  });
});

test('the expiry of the sponsor\'s consent is given before the consent is signed and the sponsor asked: sponsorConsentExpiry of the state read', async () => {
  // The rule: five minutes ahead, or the network's longest less twenty seconds, and never less than a minute.
  const at = (elapsed, longest) => ({ time_micros: (GENESIS + elapsed).toString(), genesis: { genesis_time_micros: GENESIS.toString() }, config: { registration: longest === undefined ? {} : { max_lifetime_micros: longest } } });
  assert.equal(SDK.SPONSOR_CONSENT_MAX_AHEAD_MICROS, '300000000');
  assert.deepEqual([SDK.sponsorConsentExpiry(at(7n, '86400000000')), SDK.sponsorConsentExpiry(at(7n, '200000000')), SDK.sponsorConsentExpiry(at(7n, '30000000')), SDK.sponsorConsentExpiry(at(7n))], ['300000007', '180000007', '60000007', '70000007']);
  const chain = standInChain(), sent = [], order = [];
  await withFaucet(chain, async (faucet) => {
    const client = clientOf(chain), service = await serviceSponsor(faucet.url, sent);
    const sponsor = { account: service.account, ask: async (body) => { order.push(['ask', body.expires_elapsed_micros]); return service.ask(body); } };
    // A hook that throws: nothing is signed, sent or asked.
    await assert.rejects(client.registerProtected({ sponsor, ...signUp(), onConsent: async () => { throw new Error('this browser could not keep it'); } }), /could not keep it/);
    assert.deepEqual([sent.length, chain.posted.length, order], [0, 0, []]);
    await assert.rejects(client.registerProtected({ sponsor, ...signUp(), onConsent: 'later' }), /onConsent is a function/);
    // The hook is told first, the sponsor is asked with that very expiry, and the chain's commitment lasts until it.
    const result = await client.registerProtected({ sponsor, ...signUp(), onConsent: async (given) => { order.push(['consent', given.expiresElapsedMicros, given.publicKey, given.commitment, SDK.sponsorConsentExpiry(chain.stateFor())]); } });
    assert.equal(order.length, 2);
    const [[first, expires, publicKey, commitment, expected], [then, asked]] = order;
    assert.deepEqual([first, then, asked, publicKey, commitment], ['consent', 'ask', expires, keys.registration.publicKey, fixture.commitment]);
    // The state the hook ran on is the one the SDK read last, at most a block before the stand-in's own clock.
    assert.ok(BigInt(expected) - BigInt(expires) >= 0n && BigInt(expected) - BigInt(expires) <= 2000000n, `${expires} ${expected}`);
    assert.equal(SDK.decodeAction(SDK.hexToBytes(result.sponsorReceipt.rawHex)).payload.expires_elapsed_micros, expires);
  });
});

test('a dishonest registration service cannot put its own keys on the newcomer\'s account', async () => {
  /// The service's own set for the newcomer's registration key: its own keys, each with an acceptance it signs itself.
  const ownSet = async () => {
    const spend = await strangerKey(), one = await strangerKey(), two = await strangerKey(), registrationKey = keys.registration.publicKey;
    return { keys: [await acceptRegistrationRole({ networkId: NETWORK, registrationKey, role: 'spend', ...spend }), await acceptRegistrationRole({ networkId: NETWORK, registrationKey, role: 'recover', ...one }), await acceptRegistrationRole({ networkId: NETWORK, registrationKey, role: 'recover', ...two })],
      policy: { ...fixture.policy, daily_limit_micros: '9000000000000' }, keys_held: [spend, one, two] };
  };
  const faucet = () => chain.accounts.find((a) => a.id === FAUCET);
  let chain;
  /// The service pays from the faucet's account with the faucet's key, as it likes.
  const pay = async (payload) => { const tx = await chain.sign({ kind: 'sponsor_registration', from: FAUCET, nonce: (faucet().nonce + 1n).toString(), authEpoch: faucet().auth_epoch, publicKey: keys.sponsor.publicKey, payload }, keys.sponsor.privateKey); return { refusal: await chain.broadcast(tx), hash: await SDK.transactionHash(tx) }; };
  const nothingRegistered = () => { assert.ok(!chain.accounts.some((a) => a.name === fixture.name)); assert.ok(!chain.posted.some((a) => a.kind === 45)); };

  // 1. It pays for a commitment of its own set, for the newcomer's registration key, the name and the salt (as if it
  //    had learned them; the protocol never gives them to it). The chain wants the registration key's consent to
  //    exactly that commitment: the consent the newcomer gave names another one, and the service cannot sign one.
  chain = standInChain();
  {
    const client = clientOf(chain), sent = [], evil = await ownSet();
    const swapped = await SDK.protectedNameCommitment({ networkId: NETWORK, publicKey: keys.registration.publicKey, name: fixture.name, salt: fixture.salt, security: { keys: evil.keys, policy: evil.policy } });
    let answered = null;
    const sponsor = { account: FAUCET, ask: async (body) => {
      sent.push(JSON.stringify(body));
      const withTheirConsent = await pay({ ...body, commitment: swapped });
      const ownConsent = SDK.bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', evil.keys_held[0].privateKey, SDK.sponsorConsentBytes({ networkId: NETWORK, sponsorAccount: FAUCET, publicKey: body.public_key, commitment: swapped, expiresElapsedMicros: body.expires_elapsed_micros }))));
      const withOwnConsent = await pay({ ...body, commitment: swapped, proof: ownConsent });
      answered = [withTheirConsent.refusal, withOwnConsent.refusal];
      return { hash: withTheirConsent.hash.toLowerCase() };
    } };
    await assert.rejects(client.registerProtected({ sponsor, ...signUp() }), /pending/);
    assert.deepEqual(answered, ['invalid sponsorship consent', 'invalid sponsorship consent']);
    nothingRegistered(); holdsNoSecret(sent);
  }

  // 2. It names another action of its own (the sponsorship of a key of its own) as the one that paid.
  chain = standInChain();
  {
    const client = clientOf(chain), sent = [], other = await strangerKey(), commitment = 'ab'.repeat(32), expires = (chain.elapsed + 120000000n).toString();
    const proof = SDK.bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', other.privateKey, SDK.sponsorConsentBytes({ networkId: NETWORK, sponsorAccount: FAUCET, publicKey: other.publicKey, commitment, expiresElapsedMicros: expires }))));
    const sponsor = { account: FAUCET, ask: async (body) => { sent.push(JSON.stringify(body)); const paid = await pay({ public_key: other.publicKey, commitment, expires_elapsed_micros: expires, proof }); assert.equal(paid.refusal, null); return { hash: paid.hash.toLowerCase() }; } };
    await assert.rejects(client.registerProtected({ sponsor, ...signUp() }), (error) => error.code === 'SPONSOR_MISMATCH');
    nothingRegistered(); holdsNoSecret(sent);
  }

  // 3. It says the commitment is on the chain already, and pays nothing.
  chain = standInChain();
  {
    const client = clientOf(chain), sent = [];
    const sponsor = { account: FAUCET, ask: async (body) => { sent.push(JSON.stringify(body)); return { alreadyCommitted: true }; } };
    await assert.rejects(client.registerProtected({ sponsor, ...signUp() }), /not in a verified state yet/);
    nothingRegistered(); holdsNoSecret(sent);
  }

  // 4. It pays honestly, and runs the node: when the newcomer's registration reaches it, the name, the salt and the
  //    set are public, and it tries to get in first. With its own set under the newcomer's registration key, signed
  //    by itself; with the newcomer's own registration, the keys swapped; with the reveal of protocol 4, one key that
  //    can do everything. None has the registration key's signature, and none matches the commitment.
  chain = standInChain();
  {
    const client = clientOf(chain), sent = [], evil = await ownSet(), signer = evil.keys_held[0], tries = [];
    const sponsor = { account: FAUCET, ask: async (body) => { sent.push(JSON.stringify(body)); const paid = await pay(body); assert.equal(paid.refusal, null); return { hash: paid.hash.toLowerCase() }; } };
    chain.watch = { wants: (action) => action.kind === 45 && action.publicKey === keys.registration.publicKey, run: async (seen) => {
      const registration = keys.registration.publicKey, swapped = { ...seen.payload, security: { keys: evil.keys, policy: evil.policy } };
      const attempt = async (args) => { tries.push(await chain.broadcast(await chain.sign({ from: SDK.MAX_U64, nonce: '0', authEpoch: '0', ...args }, signer.privateKey))); };
      await attempt({ kind: 45, publicKey: registration, payload: swapped });
      await attempt({ kind: 45, publicKey: signer.publicKey, payload: swapped });
      await attempt({ kind: 'reveal', publicKey: registration, payload: { name: seen.payload.name, salt: seen.payload.salt } });
      await attempt({ kind: 'reveal', publicKey: signer.publicKey, payload: { name: seen.payload.name, salt: seen.payload.salt } });
    } };
    const result = await client.registerProtected({ sponsor, ...signUp() });
    assert.deepEqual(tries, ['invalid action signature', 'no paid commitment of this registration key from an earlier block', 'invalid action signature', 'no paid commitment of this registration key from an earlier block']);
    // The account has the newcomer's keys and policy, and none of the service's.
    assert.deepEqual(result.account.devices.map((d) => d.public_key).sort(), fixture.security.keys.map((e) => e.public_key).sort());
    assert.ok(!result.account.devices.some((d) => evil.keys.some((e) => e.public_key === d.public_key)));
    assert.deepEqual(result.security.policy, fixture.policy);
    holdsNoSecret(sent);
  }
});
