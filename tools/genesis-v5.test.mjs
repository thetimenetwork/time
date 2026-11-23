// Tests of the production genesis ceremony (`tools/genesis-v5.mjs`). The node's own checks of the result, from
// encoding to InitChain and the first blocks, are in `v5/tests/production_genesis.rs`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CONSENSUS_PARAMS, FINAL_SETTINGS, GENESIS_ID_BOUND, GENESIS_POWER, PRODUCTION_SETTINGS, VALIDATORS, accountSecurity, buildProductionGenesis, canonicalText, checkGenesisIds, checkProductionGenesis,
  collectEntries, ed25519Point, entryMessage, inertGovernanceKey, inertTreasuryKey, makeAccountKey, makeCeremony, makeEntry, nameSkeleton, parseCanonical, writeGenesis,
} from './genesis-v5.mjs';
import { generateOperatorKeys } from '../deploy/keygen.mjs';

const TOOL = fileURLToPath(new URL('./genesis-v5.mjs', import.meta.url));
const CHAIN = 'time-devnet-v4-prod-rehearsal';
const NOW = Date.parse('2029-12-01T00:00:00.000Z');
const ceremony = (over = {}) => ({ ...makeCeremony({ chainId: CHAIN, genesisTime: '2030-01-01T00:00:00.000Z', now: NOW }), ...over });
const raw = (publicKey) => publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
const publicKey = () => raw(generateKeyPairSync('ed25519').publicKey);
const address = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest().subarray(0, 20).toString('hex').toUpperCase();
/// The consensus private key of each test entry, to sign it again after a deliberate change.
const keys = new WeakMap();
function resign(entry, privateKey = keys.get(entry)) {
  const { consensus_signature: _, ...unsigned } = entry;
  entry.consensus_signature = sign(null, entryMessage(unsigned), privateKey).toString('base64');
  keys.set(entry, privateKey);
  return entry;
}
/// The keys and the policy of an owner account whose payment key is `owner`: a fresh login key and two fresh
/// recovery keys, an hour a day, waits of two days.
const security = (owner, over = {}) => accountSecurity({ paymentPublicKeyHex: owner, loginPublicKeyHex: publicKey(), recoveryPublicKeysHex: [publicKey(), publicKey()], dailyLimitSeconds: '3600', ...over });
/// Gives `entry` another owner key, with a set of keys that fits it. Not signed again.
function withOwner(entry, owner) {
  entry.owner_public_key_hex = owner;
  entry.account_security = security(owner);
  return entry;
}
function entry(i, over = {}) {
  const consensus = generateKeyPairSync('ed25519');
  const key = raw(consensus.publicKey), owner = publicKey();
  const made = {
    schema_version: 1, kind: 'time-v5-validator-entry', chain_id: CHAIN, organization: `Org ${i}`, account_name: `op_${i}`,
    owner_public_key_hex: owner, consensus_public_key_hex: key, consensus_address: address(key),
    node_id: randomBytes(20).toString('hex'), commission_bps: 1000, provider: i < 10 ? 'aws' : 'gcp',
    region: ['eu-west-3', 'us-east-1', 'ap-southeast-1'][i % 3], account_security: security(owner), ...over, consensus_signature: '',
  };
  return resign(made, consensus.privateKey);
}
const entries = () => Array.from({ length: VALIDATORS }, (_, i) => entry(i));
const refuses = (change, pattern) => {
  const list = entries();
  const c = ceremony();
  change(list, c);
  assert.throws(() => buildProductionGenesis({ ceremony: c, entries: list }), pattern);
};
// The eight points of small order include these encodings: the identity, the point of order two, and the two
// encodings of y = 0 (order four).
const SMALL_ORDER = ['01' + '00'.repeat(31), 'ec' + 'ff'.repeat(30) + '7f', '00'.repeat(32), '00'.repeat(31) + '80'];

test('the same inputs give the same bytes, in whatever order the entries come', () => {
  const list = entries();
  const a = buildProductionGenesis({ ceremony: ceremony(), entries: list });
  const b = buildProductionGenesis({ ceremony: ceremony(), entries: [...list].reverse() });
  assert.ok(a.genesisBytes.equals(b.genesisBytes));
  assert.ok(a.manifestBytes.equals(b.manifestBytes));
  assert.equal(a.genesisSha256, createHash('sha256').update(a.genesisBytes).digest('hex'));
  assert.equal(a.networkId, createHash('sha256').update('TCDEVNET-NETWORK-V4\0').update(JSON.stringify(a.genesis.app_state)).digest('hex'));
  assert.deepEqual(JSON.parse(a.genesisBytes), a.genesis);
});

test('a production network: twenty validators at the production power, all new time to validators, the hand-over rule', () => {
  const { genesis, manifest, report } = buildProductionGenesis({ ceremony: ceremony(), entries: entries() });
  const s = genesis.app_state;
  assert.equal(s.profile, 'production');
  assert.equal(s.validators.length, 20);
  assert.equal(s.ledger.accounts.length, 20, 'no account but the validator owners');
  assert.equal(s.auction.epoch_seconds, '3600');
  assert.ok(BigInt(s.recovery_min_delay_micros) >= 2n * 86_400_000_000n);
  for (const [key, value] of Object.entries({ ...PRODUCTION_SETTINGS, ...FINAL_SETTINGS })) assert.equal(s[key], value);
  // The node writes the settings last, in this order, and only when they differ from the protocol-4 rule; the
  // owner accounts that start protected follow them, and the service records come after those.
  assert.deepEqual(Object.keys(s).slice(-7), ['all_new_time_to_validators', 'stake_handover', 'distinct_names', 'waits_survive_stops', 'protected_registration', 'protected_accounts', 'service_records']);
  // What the production profile cannot do without: the node refuses a production genesis that lacks the
  // hand-over rule, distinct names, waits that survive a stop, registrations that can carry a set of keys or the
  // service records.
  assert.deepEqual(PRODUCTION_SETTINGS, { all_new_time_to_validators: true, stake_handover: true, distinct_names: true, waits_survive_stops: true, protected_registration: true });
  assert.deepEqual(Object.keys(PRODUCTION_SETTINGS), ['all_new_time_to_validators', 'stake_handover', 'distinct_names', 'waits_survive_stops', 'protected_registration']);
  assert.deepEqual(FINAL_SETTINGS, { service_records: true });
  assert.deepEqual({ waits: report.settings.waits_survive_stops, registration: report.settings.protected_registration, records: report.settings.service_records }, { waits: true, registration: true, records: true });
  assert.ok(!('fee_micros' in s) && !('fees_to_validators_ppm' in s));
  assert.ok(genesis.validators.every((v) => v.power === GENESIS_POWER));
  assert.ok(manifest.trust.initial_validators.every((v) => v.voting_power === GENESIS_POWER));
  assert.deepEqual(genesis.consensus_params, CONSENSUS_PARAMS);
  assert.equal(manifest.publicLaunchAllowed, false);
  assert.equal(report.public_launch_allowed, false);
  // Owners and validators line up: account i owns validator i, whose key is in CometBFT's list at place i.
  s.validators.forEach((v, i) => {
    assert.equal(v.owner, String(i));
    assert.equal(Buffer.from(genesis.validators[i].pub_key.value, 'base64').toString('hex'), v.consensus_key);
  });
});

test('fee choices are written where and only when the node writes them', () => {
  const { genesis } = buildProductionGenesis({ ceremony: ceremony({ fee_micros: '10', fees_to_validators_ppm: '1000000' }), entries: entries() });
  assert.deepEqual(Object.keys(genesis.app_state).slice(-9), ['fees_to_validators_ppm', 'fee_micros', 'all_new_time_to_validators', 'stake_handover', 'distinct_names', 'waits_survive_stops', 'protected_registration', 'protected_accounts', 'service_records']);
  assert.equal(genesis.app_state.fee_micros, '10');
});

test('every owner account starts protected: its keys in their roles and its policy are in the genesis', () => {
  const list = entries();
  const { genesis } = buildProductionGenesis({ ceremony: ceremony(), entries: list });
  const s = genesis.app_state;
  assert.equal(s.protected_accounts.length, VALIDATORS);
  s.protected_accounts.forEach((account, i) => {
    // Account i is the account of validator i: the entry with that consensus key, and no other.
    const made = list.find((e) => e.consensus_public_key_hex === s.validators[i].consensus_key);
    assert.equal(account.id, String(i));
    assert.equal(s.ledger.accounts[i].public_key, made.owner_public_key_hex);
    assert.deepEqual(account, { id: String(i), ...made.account_security });
    // In the node's form: the fields in its order, the keys sorted, each in one role.
    assert.deepEqual(Object.keys(account), ['id', 'keys', 'policy']);
    assert.deepEqual(Object.keys(account.policy), ['threshold', 'daily_limit_micros', 'delay_seconds', 'freeze_seconds']);
    assert.deepEqual(account.policy, { threshold: '2', daily_limit_micros: '3600000000', delay_seconds: '172800', freeze_seconds: '172800' });
    assert.equal(account.keys.length, 4);
    for (const key of account.keys) assert.deepEqual(Object.keys(key), ['public_key', 'role']);
    assert.deepEqual(account.keys.map((key) => key.public_key), account.keys.map((key) => key.public_key).sort());
    assert.deepEqual(account.keys.map((key) => key.role).sort(), ['recover', 'recover', 'signin', 'spend']);
    // The key the account is known by is its payment key. No key of it holds every power.
    assert.equal(account.keys.find((key) => key.role === 'spend').public_key, s.ledger.accounts[i].public_key);
  });
  // The list is followed only by the service records, so the genesis bytes end with the policy of account 19
  // and the one setting the node writes after the list.
  assert.ok(JSON.stringify(s).endsWith('"freeze_seconds":"172800"}}],"service_records":true}'));
});

test('an owner account needs a payment key, a login key and two recovery keys, with waits the network accepts', () => {
  const field = (change, pattern) => refuses((list) => { change(list[3]); resign(list[3]); }, pattern);
  const keysOf = (e, role) => e.account_security.keys.filter((key) => key.role === role);
  const without = (role) => (e) => { e.account_security.keys = e.account_security.keys.filter((key) => key.role !== role); };
  field((e) => { delete e.account_security; }, /missing: account_security/);
  field((e) => { e.account_security = {}; }, /account_security must be \{keys, policy\}/);
  field((e) => { e.account_security = { policy: e.account_security.policy, keys: e.account_security.keys }; }, /account_security must be \{keys, policy\}/);
  field((e) => { e.account_security.note = 'x'; }, /account_security must be \{keys, policy\}/);
  field(without('signin'), /needs a login key/);
  field(without('recover'), /needs at least two recovery keys/);
  field((e) => { const [first] = keysOf(e, 'recover'); e.account_security.keys = e.account_security.keys.filter((key) => key !== first); }, /needs at least two recovery keys/);
  // Without its payment key, or with another one than the key the account is known by.
  field(without('spend'), /needs a payment key/);
  field((e) => { e.owner_public_key_hex = publicKey(); }, /must be its payment key/);
  field((e) => { const [payment] = keysOf(e, 'spend'), [recovery] = keysOf(e, 'recover'); payment.role = 'recover'; recovery.role = 'spend'; }, /must be its payment key/);
  // A key the node would refuse, a role it does not know, a key with every power, a key twice, keys out of order.
  field((e) => { keysOf(e, 'signin')[0].public_key = SMALL_ORDER[0]; e.account_security.keys.sort((a, b) => (a.public_key < b.public_key ? -1 : 1)); }, /account key must be a lowercase hex Ed25519 public key the node accepts/);
  field((e) => { keysOf(e, 'signin')[0].role = 'owner'; }, /role of an account key is signin, spend or recover/);
  field((e) => { keysOf(e, 'signin')[0].can_spend = true; }, /each account key is \{public_key, role\}/);
  field((e) => { e.account_security.keys.push({ ...e.account_security.keys.at(-1), role: 'signin' }); }, /sorted by public key, each key once and in one role/);
  field((e) => { e.account_security.keys.reverse(); }, /sorted by public key/);
  field((e) => { e.account_security.keys = Array.from({ length: 9 }, () => ({ public_key: publicKey(), role: 'recover' })).sort((a, b) => (a.public_key < b.public_key ? -1 : 1)); }, /an account has 1 to 8 keys/);
  // No key of the account is the validator's consensus key, its own or another's, and none is on two accounts.
  field((e) => { keysOf(e, 'signin')[0].public_key = e.consensus_public_key_hex; e.account_security.keys.sort((a, b) => (a.public_key < b.public_key ? -1 : 1)); }, /an account key must not be the consensus key/);
  refuses((list) => { keysOf(list[3], 'recover')[0].public_key = list[5].consensus_public_key_hex; list[3].account_security.keys.sort((a, b) => (a.public_key < b.public_key ? -1 : 1)); resign(list[3]); }, /An account key of Org 3 \(op_3\) is another entry's consensus key/);
  refuses((list) => { keysOf(list[5], 'recover')[0].public_key = keysOf(list[3], 'signin')[0].public_key; list[5].account_security.keys.sort((a, b) => (a.public_key < b.public_key ? -1 : 1)); resign(list[5]); }, /Two entries share an account key: Org 3 \(op_3\) and Org 5 \(op_5\)/);
  // The policy: two proofs at least and no more than there are recovery keys; waits from two to thirty days.
  const policy = (change, pattern) => field((e) => { change(e.account_security.policy); }, pattern);
  policy((p) => { p.threshold = '1'; }, /number of proofs \(threshold\) must be from 2 to 2/);
  policy((p) => { p.threshold = '3'; }, /number of proofs \(threshold\) must be from 2 to 2/);
  policy((p) => { p.threshold = 2; }, /whole number written as a string/);
  policy((p) => { p.delay_seconds = '172799'; }, /delay_seconds must be from 172800 to 2592000/);
  policy((p) => { p.freeze_seconds = '2592001'; }, /freeze_seconds must be from 172800 to 2592000/);
  policy((p) => { p.daily_limit_micros = '-1'; }, /daily_limit_micros/);
  policy((p) => { p.daily_limit_micros = '18446744073709551616'; }, /daily_limit_micros/);
  policy((p) => { delete p.freeze_seconds; }, /policy of the account is/);
  policy((p) => { p.extra = '1'; }, /policy of the account is/);
  // A ceremony may ask for longer waits than two days: an account with shorter ones is refused, its operator named.
  const longer = String(5n * 86_400n * 1_000_000n);
  refuses((_, c) => { c.recovery_min_delay_micros = longer; }, /Entry 1 \(Org 0\): delay_seconds of its account is below this ceremony's minimum of 5 days/);
  const list = entries().map((e) => resign({ ...e, account_security: security(e.owner_public_key_hex, { waitDays: '5', freezeDays: '7' }) }, keys.get(e)));
  const { genesis } = buildProductionGenesis({ ceremony: ceremony({ recovery_min_delay_micros: longer }), entries: list });
  assert.deepEqual([genesis.app_state.protected_accounts[0].policy.delay_seconds, genesis.app_state.protected_accounts[0].policy.freeze_seconds], ['432000', '604800']);
  // Three recovery keys and three proofs, a limit of nothing: an operator's choice.
  const three = accountSecurity({ paymentPublicKeyHex: publicKey(), loginPublicKeyHex: publicKey(), recoveryPublicKeysHex: [publicKey(), publicKey(), publicKey()], dailyLimitSeconds: '0', proofs: '3' });
  assert.deepEqual([three.keys.length, three.policy.threshold, three.policy.daily_limit_micros], [5, '3', '0']);
  for (const wrong of [{ dailyLimitSeconds: '1.5' }, { waitDays: 'two' }, { proofs: '-2' }, { recoveryPublicKeysHex: 'ab' }]) {
    assert.throws(() => accountSecurity({ paymentPublicKeyHex: publicKey(), loginPublicKeyHex: publicKey(), recoveryPublicKeysHex: [publicKey(), publicKey()], dailyLimitSeconds: '1', ...wrong }), /whole number|as a list/);
  }
});

test('exactly twenty starting validators', () => {
  refuses((list) => list.pop(), /exactly 20 validators; the list has 19/);
  refuses((list) => list.push(entry(20)), /exactly 20 validators; the list has 21/);
});

test('no key, name or node is used twice', () => {
  refuses((list) => { Object.assign(list[1], { consensus_public_key_hex: list[0].consensus_public_key_hex, consensus_address: list[0].consensus_address }); resign(list[1], keys.get(list[0])); }, /same consensus key/);
  refuses((list) => { resign(withOwner(list[1], list[0].owner_public_key_hex)); }, /same owner account key: Org 0 \(op_0\) and Org 1 \(op_1\)/);
  refuses((list) => { list[1].account_name = list[0].account_name; resign(list[1]); }, /same account name/);
  refuses((list) => { list[1].node_id = list[0].node_id; resign(list[1]); }, /same node id/);
  refuses((list) => { resign(withOwner(list[1], list[0].consensus_public_key_hex)); }, /An owner account key is another entry's consensus key/);
  refuses((list) => { list[0].owner_public_key_hex = list[0].consensus_public_key_hex; resign(list[0]); }, /must not be the consensus key/);
});

test('the skeleton of a name is the one the node computes', async () => {
  // The vectors the engine and the SDK are tested against (v5/src/names.rs, client-v4/name-skeleton.test.mjs).
  const { vectors } = JSON.parse(await readFile(new URL('../spec/name-skeleton-vectors.json', import.meta.url), 'utf8'));
  assert.equal(vectors.length, 33);
  for (const { name, skeleton } of vectors) assert.equal(nameSkeleton(name), skeleton, name);
  for (const value of ['a', 'Alice', 'al ice', 'a'.repeat(16), undefined, 7]) assert.throws(() => nameSkeleton(value), /account name/);
});

test('no two account names look alike, and none is underscores alone', () => {
  // The node refuses such a genesis at InitChain (distinct_names). The ceremony finds it first and names both operators.
  const alike = (first, second) => refuses((list) => { list[0].account_name = first; resign(list[0]); list[1].account_name = second; resign(list[1]); }, new RegExp(`account names that look alike: Org 0 \\(${first}\\) and Org 1 \\(${second}\\)`));
  alike('paypal', 'paypa1');
  alike('alice', 'al_ice');
  alike('g00gle', 'google');
  alike('barn', 'bam');
  alike('vvv', 'wv');
  alike('op_x', 'opx');
  // A name of the list as it is: op_1 reads as opl.
  refuses((list) => { list[7].account_name = 'opl'; resign(list[7]); }, /look alike: Org 1 \(op_1\) and Org 7 \(opl\)/);
  // The same name twice is still called that.
  refuses((list) => { list[1].account_name = list[0].account_name; resign(list[1]); }, /same account name/);
  // Underscores alone: refused when the entry is checked, so also when it is made.
  refuses((list) => { list[3].account_name = '__'; resign(list[3]); }, /Entry \d+: account_name must hold a letter or a digit/);
  refuses((list) => { list[3].account_name = '_'.repeat(15); resign(list[3]); }, /must hold a letter or a digit/);
  // Names the rule leaves alone are taken: one changed letter, i for l, b1nance for binance.
  const list = entries();
  for (const [index, name] of ['binance', 'b1nance', 'mail', 'mall', 'op_a', 'op_b'].entries()) { list[index].account_name = name; resign(list[index]); }
  const { genesis } = buildProductionGenesis({ ceremony: ceremony(), entries: list });
  assert.equal(new Set(genesis.app_state.ledger.accounts.map((account) => nameSkeleton(account.name))).size, VALIDATORS);
  // The twenty names of an ordinary ceremony.
  assert.equal(new Set(entries().map((e) => nameSkeleton(e.account_name))).size, VALIDATORS);
});

test("only an entry's own consensus key can make or change it", () => {
  // The attack a coordinator could make on an unsigned list: keep a validator's keys, put in its own owner
  // account, or keep the account and put in keys of its own.
  refuses((list) => { withOwner(list[4], publicKey()); }, /Entry \d+: the consensus key did not sign/);
  refuses((list) => { const all = list[4].account_security.keys, recovery = all.find((key) => key.role === 'recover'), login = all.find((key) => key.role === 'signin'); recovery.role = 'signin'; login.role = 'recover'; }, /did not sign/);
  refuses((list) => { list[4].account_security.policy.daily_limit_micros = '86400000000000'; }, /did not sign/);
  refuses((list) => { list[4].account_security.policy.delay_seconds = '172801'; }, /did not sign/);
  refuses((list) => { list[4].commission_bps = 2000; }, /did not sign/);
  refuses((list) => { list[4].organization = 'Someone Else'; }, /did not sign/);
  refuses((list) => { resign(list[4], generateKeyPairSync('ed25519').privateKey); }, /did not sign/);
  refuses((list) => { list[4].consensus_signature = list[4].consensus_signature.replace(/=*$/, ''); }, /did not sign/);
  refuses((list) => { list[4].consensus_signature = list[5].consensus_signature; }, /did not sign/);
  // An entry made for another network cannot be replayed into this one.
  refuses((list) => { list[4].chain_id = 'time-devnet-v4-other'; resign(list[4]); }, /was made for time-devnet-v4-other/);
  // The signed message can never be read as CometBFT sign-bytes, which start with their length.
  assert.deepEqual([...entryMessage(entries()[0]).subarray(0, 2)], [0xff, 0xff]);
});

test('each entry is checked', () => {
  const field = (change, pattern) => refuses((list) => { change(list[3]); resign(list[3]); }, pattern);
  field((e) => { e.consensus_address = address(publicKey()); }, /consensus_address does not belong/);
  field((e) => { e.owner_public_key_hex = e.owner_public_key_hex.toUpperCase(); }, /owner_public_key_hex must be/);
  field((e) => { e.owner_public_key_hex = 'ff'.repeat(31) + '7f'; }, /owner_public_key_hex must be/); // y >= p
  for (const weak of SMALL_ORDER) field((e) => { e.owner_public_key_hex = weak; }, /owner_public_key_hex must be .* the node accepts/);
  field((e) => { e.commission_bps = 2001; }, /commission_bps/);
  field((e) => { e.commission_bps = '1000'; }, /commission_bps/);
  field((e) => { e.account_name = 'Op_3'; }, /account_name/);
  field((e) => { e.account_name = 'a'; }, /account_name/);
  field((e) => { e.account_name = 'a'.repeat(16); }, /account_name/);
  for (const name of ['Org\n3', 'Org A ', ' Org A', 'Org  A', 'O'.repeat(65)]) field((e) => { e.organization = name; }, /organization/);
  field((e) => { e.provider = 'AWS'; }, /provider/);
  field((e) => { e.node_id = 'zz'.repeat(20); }, /node_id/);
  field((e) => { e.extra = 1; }, /unknown fields: extra/);
  field((e) => { delete e.region; }, /missing: region/);
  field((e) => { e.schema_version = 2; }, /schema 1/);
  refuses((list) => { list[3] = JSON.parse('{"__proto__": 1}'); }, /unknown fields: __proto__/);
});

test('the ceremony is checked', () => {
  refuses((_, c) => { c.chain_id = 'time-devnet-prod'; }, /chain_id/);
  refuses((_, c) => { c.chain_id = 'time-devnet-v4-Prod'; }, /chain_id/);
  refuses((_, c) => { c.chain_id = 'time-devnet-v4-' + 'a'.repeat(36); }, /chain_id/);
  for (const time of ['2030-01-01T00:00:00Z', '+010000-01-01T00:00:00.000Z', '-000001-01-01T00:00:00.000Z', '1969-12-31T00:00:00.000Z', '2030-02-30T00:00:00.000Z']) {
    refuses((_, c) => { c.genesis_time = time; }, /genesis_time/);
  }
  refuses((_, c) => { c.fee_micros = '0'; }, /fee_micros/);
  refuses((_, c) => { c.fee_micros = '1001'; }, /fee_micros/);
  refuses((_, c) => { c.fee_micros = 10; }, /fee_micros/);
  refuses((_, c) => { c.fees_to_validators_ppm = '1000001'; }, /fees_to_validators_ppm/);
  refuses((_, c) => { c.registration_fee_micros = '999'; }, /registration_fee_micros/);
  refuses((_, c) => { c.recovery_min_delay_micros = String(2n * 86_400_000_000n - 1n); }, /recovery_min_delay_micros/);
  refuses((_, c) => { c.recovery_min_delay_micros = String(30n * 86_400_000_000n + 1n); }, /recovery_min_delay_micros/);
  refuses((_, c) => { c.profile = 'laboratory'; }, /unknown fields: profile/);
  // Entries made for the right chain do not fit a ceremony for another one.
  refuses((_, c) => { c.chain_id = 'time-devnet-v4-other'; }, /was made for/);
  assert.throws(() => makeCeremony({ chainId: 'time-devnet-v4-x', genesisTime: new Date(NOW + 60_000).toISOString(), now: NOW }), /an hour ahead/);
  assert.throws(() => makeCeremony({ chainId: 'time-devnet-v4-x', genesisTime: '2030-01-01T00:00:00.000Z', recoveryMinDelayDays: '2.5', now: NOW }), /whole number of days/);
});

test('the files read must be in the one form the tool writes', () => {
  const value = { a: 1, b: [1, 2] };
  assert.deepEqual(parseCanonical(canonicalText(value), 'f'), value);
  // A key written twice, so a reader sees one value and the parser keeps another.
  assert.throws(() => parseCanonical('{\n  "a": 1,\n  "a": 2,\n  "b": [\n    1,\n    2\n  ]\n}\n', 'f'), /not in the form/);
  assert.throws(() => parseCanonical(canonicalText(value).replace('\n', '\r\n'), 'f'), /not in the form/);
  assert.throws(() => parseCanonical(canonicalText(value).replace('"a": 1', '"a": 1' + ' '.repeat(200)), 'f'), /not in the form/);
  assert.throws(() => parseCanonical(JSON.stringify(value), 'f'), /not in the form/);
  assert.throws(() => parseCanonical('{', 'f'), /not JSON/);
});

test('the bitcoin and treasury keys are hash-derived points that nobody holds, one set per network', () => {
  const one = Array.from({ length: 7 }, (_, i) => inertGovernanceKey('time-devnet-v4-a', i));
  assert.equal(new Set(one).size, 7);
  assert.ok(one.every(ed25519Point));
  assert.deepEqual(one, Array.from({ length: 7 }, (_, i) => inertGovernanceKey('time-devnet-v4-a', i)));
  assert.notEqual(inertGovernanceKey('time-devnet-v4-b', 0), one[0]);
  const p = 2n ** 256n - 2n ** 32n - 977n;
  for (let i = 0; i < 7; i++) {
    const key = inertTreasuryKey('time-devnet-v4-a', i);
    assert.match(key, /^02[0-9a-f]{64}$/);
    const x = BigInt('0x' + key.slice(2));
    const rhs = (x ** 3n + 7n) % p;
    let y = 1n, base = rhs, e = (p + 1n) / 4n;
    while (e) { if (e & 1n) y = (y * base) % p; base = (base * base) % p; e >>= 1n; }
    assert.equal((y * y) % p, rhs, 'on the curve');
  }
  // Real keys pass; points of small order, which the node refuses, do not.
  for (let i = 0; i < 50; i++) assert.ok(ed25519Point(publicKey()));
  for (const weak of SMALL_ORDER) assert.equal(ed25519Point(weak), false, weak);
});

test('concentration is reported, and over a third or two thirds is a warning', () => {
  const list = entries().map((e, i) => resign({ ...e, provider: 'aws', organization: i < 7 ? (i % 2 ? 'Org A' : 'ORG a') : `Org ${i}` }, keys.get(e)));
  const { report } = buildProductionGenesis({ ceremony: ceremony(), entries: list });
  assert.equal(report.concentration.provider.largest.share, 1);
  assert.equal(report.concentration.organization.largest.validators, 7, 'names differing only in case count as one');
  assert.ok(report.warnings.some((w) => /provider \(aws\).*over two thirds/.test(w)));
  assert.ok(report.warnings.some((w) => /organization \(.*\).*over a third/.test(w)));
  const spread = buildProductionGenesis({ ceremony: ceremony(), entries: entries().map((e, i) => resign({ ...e, provider: ['aws', 'gcp', 'azure', 'ovh'][i % 4] }, keys.get(e))) });
  assert.ok(!spread.report.warnings.some((w) => /provider/.test(w)));
  for (const names of [['Org A', 'Org-A', 'Org_A'], ['Org A', 'Org A.', 'OrgA']]) {
    const variants = buildProductionGenesis({ ceremony: ceremony(), entries: entries().map((e, i) => resign({ ...e, organization: i < 14 ? names[i % 3] : `Org ${i}` }, keys.get(e))) });
    assert.equal(variants.report.concentration.organization.largest.validators, 14, names.join(' / '));
    assert.ok(variants.report.warnings.some((w) => /organization .* 14 of 20/.test(w)));
  }
  // Names that are also names of object properties are counted like any other.
  const proto = buildProductionGenesis({ ceremony: ceremony(), entries: entries().map((e, i) => resign({ ...e, organization: i < 14 ? 'constructor' : `Org ${i}` }, keys.get(e))) });
  assert.equal(proto.report.concentration.organization.largest.validators, 14);
});

test('collect checks each entry and writes one canonical list', () => {
  const list = entries();
  const collected = collectEntries([...list].reverse());
  assert.deepEqual(collected.map((e) => e.consensus_public_key_hex), [...list].map((e) => e.consensus_public_key_hex).sort());
  assert.throws(() => collectEntries([list[0], list[0]]), /same consensus key/);
  assert.throws(() => collectEntries([...list, entry(20)]), /20 validators; there are 21/);
  const changed = { ...list[2], commission_bps: 0 };
  assert.throws(() => collectEntries([changed]), /did not sign/);
});

test('check accepts the genesis these inputs give, with your own entry in it unchanged, and nothing else', () => {
  const list = entries();
  const mine = list[7];
  const built = buildProductionGenesis({ ceremony: ceremony(), entries: list });
  const ok = (over = {}) => checkProductionGenesis({ ceremony: ceremony(), entries: list, genesisBytes: built.genesisBytes, networkBytes: built.manifestBytes, ownEntry: mine, now: NOW, ...over });
  const report = ok({ expectedSha256: built.genesisSha256 });
  assert.throws(() => ok({ networkBytes: undefined }), /Give network.json/);
  assert.equal(report.genesis_sha256, built.genesisSha256);
  assert.equal(built.genesis.app_state.ledger.accounts[Number(report.your_validator.account)].public_key, mine.owner_public_key_hex);
  const changed = Buffer.from(built.genesisBytes);
  changed[changed.length - 3] ^= 1;
  assert.throws(() => ok({ genesisBytes: changed }), /not the one these inputs give/);
  assert.throws(() => ok({ genesisBytes: Buffer.from(JSON.stringify(built.genesis, null, 2)) }), /not the one/);
  assert.throws(() => ok({ expectedSha256: '0'.repeat(64) }), /hash you were given/);
  assert.throws(() => ok({ ownEntry: undefined }), /Give your own validator-entry.json/);
  // A network manifest with other validators in its trust anchor.
  const forged = structuredClone(built.manifest);
  forged.trust.initial_validators[0].pub_key.value = Buffer.from(publicKey(), 'hex').toString('base64');
  assert.throws(() => ok({ networkBytes: Buffer.from(canonicalText(forged)) }), /network.json is not the one/);
  // The list carries another entry signed with this operator's key (an older one, say), not the one it made.
  const older = resign({ ...mine, commission_bps: 1999 }, keys.get(mine));
  const swapped = list.map((e) => (e === mine ? older : e));
  const rebuilt = buildProductionGenesis({ ceremony: ceremony(), entries: swapped });
  assert.throws(() => checkProductionGenesis({ ceremony: ceremony(), entries: swapped, genesisBytes: rebuilt.genesisBytes, networkBytes: rebuilt.manifestBytes, ownEntry: mine, now: NOW }), /not in the list as you made it/);
  assert.throws(() => checkProductionGenesis({ ceremony: ceremony(), entries: list.filter((e) => e !== mine).concat(entry(30)), genesisBytes: built.genesisBytes, networkBytes: built.manifestBytes, ownEntry: mine, now: NOW }), /not in the list as you made it/);
  const late = ok({ now: Date.parse('2030-01-02T00:00:00.000Z') });
  assert.ok(late.warnings.some((w) => /has passed/.test(w)));
});

test('an operator signs its entry with the consensus key from its keygen enrollment, and its owner key is kept apart', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'genesis-v5-'));
  try {
    // The login key and the two recovery keys are made beforehand, each where it will be kept; the entry gets
    // their public keys.
    const login = await makeAccountKey({ file: path.join(dir, 'login.json'), label: 'login' });
    const recovery = [await makeAccountKey({ file: path.join(dir, 'recovery-1.json') }), await makeAccountKey({ file: path.join(dir, 'recovery-2.json') })];
    const account = { loginPublicKeyHex: login.publicKeyHex, recoveryPublicKeysHex: recovery.map((key) => key.publicKeyHex), dailyLimitSeconds: '7200' };
    const make = (enrollment, over = {}) => makeEntry({ enrollment, chainId: CHAIN, organization: 'Org A', accountName: 'op_a', commissionBps: 500, provider: 'aws', region: 'eu-west-3', ownerKeyFile: path.join(dir, path.basename(enrollment) + '-owner.json'), ...account, ...over });
    const enrollment = path.join(dir, 'operator');
    const identity = await generateOperatorKeys(enrollment);
    const { entry: made, ownerKeyFile } = await make(enrollment);
    assert.equal(made.consensus_public_key_hex, identity.consensus_public_key_hex);
    assert.equal(made.consensus_address, identity.consensus_address);
    assert.equal(made.node_id, identity.node_id);
    const secret = JSON.parse(await readFile(ownerKeyFile, 'utf8'));
    assert.equal(secret.public_key_hex, made.owner_public_key_hex);
    // The owner account starts protected: the key the tool made is its payment key, the three given keys have
    // their roles, and the limit and the waits are the ones asked for (two days unless said otherwise).
    const role = (key) => made.account_security.keys.find((entry) => entry.public_key === key)?.role;
    assert.deepEqual([role(made.owner_public_key_hex), role(login.publicKeyHex), ...recovery.map((key) => role(key.publicKeyHex))], ['spend', 'signin', 'recover', 'recover']);
    assert.equal(made.account_security.keys.length, 4);
    assert.deepEqual(made.account_security.policy, { threshold: '2', daily_limit_micros: '7200000000', delay_seconds: '172800', freeze_seconds: '172800' });
    assert.deepEqual(Object.keys(made).slice(-2), ['account_security', 'consensus_signature']);
    // A key file holds one key, names its public key, and is readable by its owner only, like the owner key.
    const loginFile = JSON.parse(await readFile(login.file, 'utf8'));
    assert.deepEqual([loginFile.label, loginFile.public_key_hex, typeof loginFile.private_key_pkcs8_base64], ['login', login.publicKeyHex, 'string']);
    assert.ok(ed25519Point(login.publicKeyHex) && new Set([login.publicKeyHex, ...recovery.map((key) => key.publicKeyHex)]).size === 3);
    await assert.rejects(makeAccountKey({ file: login.file }), /exists already/);
    await assert.rejects(makeAccountKey({ file: path.join(dir, 'x.json'), label: 'a\nb' }), /--label/);
    if (process.platform === 'win32') assert.ok(!/\(I\)/.test(execFileSync('icacls', [login.file], { encoding: 'utf8' })), 'an account key inherits no permissions');
    const written = await readFile(path.join(enrollment, 'validator-entry.json'), 'utf8');
    assert.deepEqual(parseCanonical(written, 'entry'), made);
    assert.ok(!/priv|pkcs8|secret/i.test(written), 'the entry is public');
    if (process.platform === 'win32') {
      const acl = execFileSync('icacls', [ownerKeyFile], { encoding: 'utf8' });
      assert.ok(!/\(I\)/.test(acl), `the owner key inherits no permissions: ${acl}`);
      assert.ok(acl.includes(os.userInfo().username), acl);
    }
    // Nothing is overwritten, and a refused entry writes nothing.
    await assert.rejects(make(enrollment), /exists already/);
    const other = path.join(dir, 'other');
    await generateOperatorKeys(other);
    const before = (await readdir(other)).sort();
    await assert.rejects(make(other, { accountName: 'Bad Name' }), /account_name/);
    await assert.rejects(make(other, { ownerKeyFile: path.join(other, 'owner.json') }), /outside the enrollment directory/);
    await assert.rejects(make(other, { ownerKeyFile: path.join(other, '..owner.json') }), /outside the enrollment directory/);
    await symlink(other, path.join(dir, 'link-to-other'), 'junction');
    await assert.rejects(make(other, { ownerKeyFile: path.join(dir, 'link-to-other', 'owner.json') }), /outside the enrollment directory/);
    await assert.rejects(make(other, { ownerKeyFile: undefined }), /--owner-key-file/);
    await assert.rejects(make(other, { ownerPublicKeyHex: publicKey() }), /either --owner-public-key or --owner-key-file/);
    // An entry without the keys of a protected account, or with a set the node would refuse, is not made.
    await assert.rejects(make(other, { loginPublicKeyHex: undefined }), /Give --login-public-key, --recovery-public-keys/);
    await assert.rejects(make(other, { recoveryPublicKeysHex: undefined }), /Give --login-public-key, --recovery-public-keys/);
    await assert.rejects(make(other, { dailyLimitSeconds: undefined }), /Give --login-public-key, --recovery-public-keys/);
    await assert.rejects(make(other, { recoveryPublicKeysHex: [recovery[0].publicKeyHex] }), /at least two recovery keys/);
    await assert.rejects(make(other, { recoveryPublicKeysHex: [recovery[0].publicKeyHex, recovery[0].publicKeyHex] }), /each key once and in one role/);
    await assert.rejects(make(other, { loginPublicKeyHex: recovery[0].publicKeyHex }), /each key once and in one role/);
    await assert.rejects(make(other, { loginPublicKeyHex: 'zz'.repeat(32) }), /account key must be a lowercase hex Ed25519 public key/);
    await assert.rejects(make(other, { waitDays: '1' }), /delay_seconds must be from 172800/);
    await assert.rejects(make(other, { freezeDays: '31' }), /freeze_seconds must be from 172800 to 2592000/);
    await assert.rejects(make(other, { proofs: '3' }), /number of proofs \(threshold\) must be from 2 to 2/);
    await assert.rejects(make(other, { dailyLimitSeconds: 'much' }), /daily-limit-seconds must be a whole number/);
    assert.deepEqual((await readdir(other)).sort(), before);
    assert.ok(!(await readdir(dir)).includes('other-owner.json'));
    // With its own owner key, no key file is made: that key is the payment key.
    const mine = publicKey();
    const result = await make(other, { ownerKeyFile: undefined, ownerPublicKeyHex: mine, waitDays: '3', freezeDays: '10' });
    assert.equal(result.ownerKeyFile, null);
    assert.equal(result.entry.account_security.keys.find((key) => key.role === 'spend').public_key, mine);
    assert.deepEqual([result.entry.account_security.policy.delay_seconds, result.entry.account_security.policy.freeze_seconds], ['259200', '864000']);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the documented commands, end to end: twenty enrollments, entries, collect, build and check', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'genesis-v5-cli-'));
  const run = (...args) => JSON.parse(execFileSync(process.execPath, [TOOL, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  try {
    const time = new Date(Date.now() + 2 * 3_600_000).toISOString().replace(/\.\d{3}Z$/, '.000Z');
    run('ceremony', '--chain-id', CHAIN, '--genesis-time', time, '--out', path.join(dir, 'ceremony.json'));
    const files = [];
    // The first operator makes its login key and its two recovery keys with the tool, one file each.
    const made = ['login', 'recovery-1', 'recovery-2'].map((label) => run('account-key', '--out', path.join(dir, `${label}.json`), '--label', label));
    assert.ok(made.every((key) => ed25519Point(key.public_key_hex)) && new Set(made.map((key) => key.public_key_hex)).size === 3);
    assert.throws(() => run('account-key', '--out', path.join(dir, 'login.json')), /exists already/);
    assert.throws(() => run('account-key'), /--out is required/);
    for (let i = 0; i < VALIDATORS; i++) {
      const enrollment = path.join(dir, `operator-${i}`);
      await generateOperatorKeys(enrollment);
      const [login, ...recovery] = i === 0 ? made.map((key) => key.public_key_hex) : [publicKey(), publicKey(), publicKey()];
      const answer = run('entry', '--enrollment', enrollment, '--chain-id', CHAIN, '--organization', `Org ${i}`, '--account-name', `op_${i}`,
        '--commission-bps', '1000', '--provider', 'aws', '--region', ['eu-west-3', 'us-east-1', 'ap-southeast-1', 'eu-central-1'][i % 4],
        '--owner-key-file', path.join(dir, `owner-${i}.json`), '--login-public-key', login, '--recovery-public-keys', recovery.join(','), '--daily-limit-seconds', '3600');
      assert.deepEqual(answer.entry.account_security.keys.map((key) => key.role).sort(), ['recover', 'recover', 'signin', 'spend']);
      files.push(path.join(enrollment, 'validator-entry.json'));
    }
    const account = ['--login-public-key', publicKey(), '--recovery-public-keys', `${publicKey()},${publicKey()}`, '--daily-limit-seconds', '3600'];
    assert.throws(() => run('entry', '--enrollment', path.join(dir, 'operator-0'), '--chain-id', CHAIN, '--organization', 'X', '--account-name', 'xx', '--commission-bps', '0x7d0', '--provider', 'aws', '--region', 'x', '--owner-key-file', path.join(dir, 'x.json'), ...account), /commission-bps/);
    // An entry without the keys of a protected account is not made: every owner account starts protected.
    assert.throws(() => run('entry', '--enrollment', path.join(dir, 'operator-0'), '--chain-id', CHAIN, '--organization', 'X', '--account-name', 'xx', '--commission-bps', '0', '--provider', 'aws', '--region', 'x', '--owner-key-file', path.join(dir, 'x.json')), /--login-public-key is required/);
    const spare = path.join(dir, 'operator-spare');
    await generateOperatorKeys(spare);
    assert.throws(() => run('entry', '--enrollment', spare, '--chain-id', CHAIN, '--organization', 'X', '--account-name', 'xx', '--commission-bps', '0', '--provider', 'aws', '--region', 'x', '--owner-key-file', path.join(dir, 'x.json'), ...account.slice(0, 2), '--daily-limit-seconds', '3600', '--recovery-public-keys', publicKey()), /at least two recovery keys/);
    assert.throws(() => run('entry', '--enrollment', spare, '--chain-id', CHAIN, '--organization', 'X', '--account-name', 'xx', '--commission-bps', '0', '--provider', 'aws', '--region', 'x', '--owner-key-file', path.join(dir, 'x.json'), ...account, '--wait-days', '1'), /delay_seconds must be from 172800/);
    assert.ok(!(await readdir(spare)).includes('validator-entry.json') && !(await readdir(dir)).includes('x.json'), 'a refused entry writes nothing');
    const collected = run('collect', '--out', path.join(dir, 'entries.json'), ...files);
    assert.equal(collected.entries, 20);
    const built = run('build', '--ceremony', path.join(dir, 'ceremony.json'), '--entries', path.join(dir, 'entries.json'), '--out', path.join(dir, 'genesis'));
    assert.equal(built.inputs.entries_sha256, collected.sha256);
    for (const i of [0, 13]) {
      const checked = run('check', '--ceremony', path.join(dir, 'ceremony.json'), '--entries', path.join(dir, 'entries.json'),
        '--genesis', path.join(dir, 'genesis', 'genesis.json'), '--network', path.join(dir, 'genesis', 'network.json'),
        '--entry', files[i], '--sha256', built.genesis_sha256);
      assert.equal(checked.genesis_sha256, built.genesis_sha256);
      assert.equal(checked.network_json_sha256, built.network_json_sha256);
    }
    const base = ['check', '--ceremony', path.join(dir, 'ceremony.json'), '--entries', path.join(dir, 'entries.json'), '--genesis', path.join(dir, 'genesis', 'genesis.json'), '--entry', files[0]];
    assert.throws(() => run(...base), /--network is required/);
    assert.throws(() => run(...base, '--netwrok', path.join(dir, 'genesis', 'network.json')), /check has no option --netwrok/);
    assert.throws(() => run(...base, '--network', path.join(dir, 'genesis', 'network.json'), '--entry', files[1]), /--entry is given twice/);
    assert.throws(() => run(...base, '--network', path.join(dir, 'genesis', 'network.json'), 'stray'), /Unexpected stray/);
    // A list with a key written twice is refused, though it parses.
    const text = await readFile(path.join(dir, 'entries.json'), 'utf8');
    await writeFile(path.join(dir, 'tampered.json'), text.replace('"commission_bps": 1000,', '"commission_bps": 1000,\n    "commission_bps": 2000,'));
    assert.throws(() => run('build', '--ceremony', path.join(dir, 'ceremony.json'), '--entries', path.join(dir, 'tampered.json'), '--out', path.join(dir, 'g2')), /not in the form/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('build writes four public files into a new directory and holds no private key', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'genesis-v5-'));
  try {
    const built = buildProductionGenesis({ ceremony: ceremony(), entries: entries() });
    const out = path.join(dir, 'out');
    await writeGenesis(out, built);
    assert.deepEqual((await readdir(out)).sort(), ['genesis.json', 'genesis.sha256', 'network.json', 'report.json']);
    assert.ok((await readFile(path.join(out, 'genesis.json'))).equals(built.genesisBytes));
    assert.ok((await readFile(path.join(out, 'network.json'))).equals(built.manifestBytes));
    assert.equal((await readFile(path.join(out, 'genesis.sha256'), 'utf8')).trim(), built.genesisSha256);
    for (const name of await readdir(out)) assert.ok(!/priv_key|pkcs8|private/i.test(await readFile(path.join(out, name), 'utf8')), name);
    await assert.rejects(writeGenesis(out, built), /exists already/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// docs/design/upgrade-mechanism.md: the genesis and the trust manifest name the network's first protocol version,
// which stays 4 whatever the network later upgrades to (section 8), and genesis account ids are below 2^48
// (section 11).
test('the genesis names first version 4 everywhere, and its account ids are below 2^48', () => {
  const { genesis, manifest } = buildProductionGenesis({ ceremony: ceremony(), entries: entries() });
  assert.equal(genesis.consensus_params.version.app, '4');
  assert.equal(CONSENSUS_PARAMS.version.app, '4');
  assert.equal(manifest.protocolVersion, '4');
  assert.equal(manifest.trust.app_version, '4');
  assert.equal(manifest.schemaVersion, 4);
  // Nothing about an upgrade is written at genesis: no plan, no signal, no further version field.
  assert.equal(JSON.stringify(genesis).includes('upgrade'), false);
  // The trust data of the manifest, which wallets, servers and the alert watch pin, says that this
  // network's nodes answer the question about scheduled upgrades (every release from 0.7.0 on does): its
  // clients then ask it with every verified read, from the first. It is the one statement about
  // upgrades in the manifest, a plain `true`, and the file a participant checks carries it.
  assert.equal(manifest.trust.nodes_report_upgrades, true);
  assert.deepEqual(Object.keys(manifest.trust).sort(), ['app_version', 'chain_id', 'genesis_time_micros', 'initial_validators', 'network_id', 'nodes_report_upgrades', 'trusting_period_seconds', 'unbonding_period_seconds']);
  assert.equal(JSON.stringify(manifest).split('upgrade').length - 1, 1);
  const again = buildProductionGenesis({ ceremony: ceremony(), entries: entries() });
  assert.equal(JSON.parse(again.manifestBytes.toString()).trust.nodes_report_upgrades, true);
  const s = genesis.app_state;
  assert.deepEqual(s.ledger.accounts.map((a) => a.id), Array.from({ length: 20 }, (_, i) => String(i)));
  assert.deepEqual(s.validators.map((v) => v.owner), s.ledger.accounts.map((a) => a.id));
  assert.equal(GENESIS_ID_BOUND, 281474976710656n);
  checkGenesisIds(s);
  const state = (id, ...owner) => ({ ledger: { accounts: [{ id: '0' }, { id }] }, validators: [{ owner: owner.length ? owner[0] : '0' }] });
  for (const id of ['0', '19', '281474976710655']) { checkGenesisIds(state(id)); checkGenesisIds(state('1', id)); }
  for (const id of ['281474976710656', '281474976710657', '18446744073709551614', '18446744073709551615', '18446744073709551616', '01', '-1', '1.0', ' 1', '', 1, 281474976710656, null, undefined]) {
    assert.throws(() => checkGenesisIds(state(id)), /below 2\^48/, 'account id ' + String(id));
    assert.throws(() => checkGenesisIds(state('1', id)), /below 2\^48/, 'validator owner ' + String(id));
  }
});
