// The harness's genesis builder: what it writes into the trust data that campaign clients pin.
// The genesis bytes themselves are compared with the node's own in v5/tests/fee_genesis_bytes.rs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { buildGenesis, GENESIS_SETTINGS } from './genesis.mjs';
import { PRODUCTION_SETTINGS, FINAL_SETTINGS, VALIDATORS, accountSecurity, buildProductionGenesis, entryMessage, makeCeremony } from '../../tools/genesis-v5.mjs';

const identity = (_, i) => ({ address: String(i).repeat(40), pub_key: { type: 'tendermint/PubKeyEd25519', value: generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') } });
const seven = Array.from({ length: 7 }, identity);
const consensusParams = { block: { max_bytes: '1', max_gas: '-1' }, evidence: { max_age_num_blocks: '1', max_age_duration: '1', max_bytes: '1' }, validator: { pub_key_types: ['ed25519'] }, version: { app: '0' }, abci: {} };
const build = (options = {}) => buildGenesis({ identities: seven, consensusParams, now: 1_800_000_000_000, ...options });

test('trust data says that nodes answer the upgrade question only when the campaign says so', () => {
  const plain = build(), declared = build({ nodesReportUpgrades: true });
  assert.equal('nodes_report_upgrades' in plain.manifest.trust, false, 'a network of older nodes must not claim it');
  assert.equal(declared.manifest.trust.nodes_report_upgrades, true);
  // The statement is for clients only. Nothing of it reaches the genesis that nodes read, and the trust data
  // gains this one field. (Each build makes its own account keys, so two builds are never the same network.)
  for (const g of [plain, declared]) assert.equal(JSON.stringify(g.genesis).includes('nodes_report_upgrades') || g.genesisBytes.includes('nodes_report_upgrades'), false);
  assert.deepEqual(Object.keys(declared.manifest.trust).filter((key) => !(key in plain.manifest.trust)), ['nodes_report_upgrades']);
  assert.deepEqual(Object.keys(plain.manifest.trust).filter((key) => !(key in declared.manifest.trust)), []);
});

test('the setting is true or false, nothing else', () => {
  for (const value of ['true', 1, null, 'yes']) assert.throws(() => build({ nodesReportUpgrades: value }), /nodesReportUpgrades must be true or false/);
});

test('names that look alike are refused only on a network that is built so, and the flag is the last field', async () => {
  await import('../../client-v4/time-sdk.js');
  const { nameSkeleton } = globalThis.TimeSDK;
  const plain = build(), declared = build({ distinctNames: true }), everything = build({ feesToValidatorsPpm: 1_000_000, feeMicros: 10, allNewTimeToValidators: true, stakeHandover: true, distinctNames: true });
  // Without the option nothing of it is written: the bytes and the network id of such a network are what they were.
  for (const g of [plain, build({ distinctNames: false })]) {
    assert.equal('distinct_names' in g.genesis.app_state, false);
    assert.equal(g.genesisBytes.includes('distinct_names') || JSON.stringify(g.manifest).includes('distinct_names'), false);
  }
  // With it: one field more, written as the node writes it, after every other optional setting.
  assert.equal(declared.genesis.app_state.distinct_names, true);
  assert.deepEqual(Object.keys(declared.genesis.app_state).filter((key) => !(key in plain.genesis.app_state)), ['distinct_names']);
  assert.equal(Object.keys(declared.genesis.app_state).at(-1), 'distinct_names');
  assert.deepEqual(Object.keys(everything.genesis.app_state).slice(-5), ['fees_to_validators_ppm', 'fee_micros', 'all_new_time_to_validators', 'stake_handover', 'distinct_names']);
  assert.deepEqual(declared.manifest.genesis, declared.genesis.app_state);
  for (const value of ['true', 1, null, 'yes']) assert.throws(() => build({ distinctNames: value }), /distinctNames must be true or false/);
  // The node refuses a genesis in which two account names look alike: the 64 names of this genesis do not.
  const names = declared.genesis.app_state.ledger.accounts.map((account) => account.name);
  assert.equal(names.length, 64);
  assert.equal(new Set(names.map(nameSkeleton)).size, 64);
  assert.ok(names.every((name) => nameSkeleton(name) !== ''));
  // Nor do they with the largest number of validators the builder takes.
  const forty = buildGenesis({ identities: Array.from({ length: 40 }, identity), consensusParams, distinctNames: true });
  assert.equal(new Set(forty.genesis.app_state.ledger.accounts.map((account) => nameSkeleton(account.name))).size, 64);
});

test('the four settings of spec/settings.md: each written as true when asked, in the node\'s order, last; nothing of them when not asked', () => {
  assert.deepEqual(GENESIS_SETTINGS.map(([, field]) => field), ['distinct_names', 'waits_survive_stops', 'protected_registration', 'service_records']);
  assert.deepEqual(GENESIS_SETTINGS.map(([option]) => option), ['distinctNames', 'waitsSurviveStops', 'protectedRegistration', 'serviceRecords']);
  const plain = build(), tail = (g) => Object.keys(g.genesis.app_state).filter((key) => !(key in plain.genesis.app_state));
  // Not asked, or asked with false: the bytes and the network id of a network from before the settings.
  const none = build(Object.fromEntries(GENESIS_SETTINGS.map(([option]) => [option, false])));
  for (const g of [plain, none]) for (const [, field] of GENESIS_SETTINGS) assert.equal(g.genesisBytes.includes(field) || JSON.stringify(g.manifest).includes(field), false, field);
  // Each alone, and every combination: the fields asked for, true, in the order of the list, after every other field.
  for (let mask = 1; mask < 2 ** GENESIS_SETTINGS.length; mask++) {
    const asked = GENESIS_SETTINGS.filter((_, k) => mask & (1 << k)), g = build(Object.fromEntries(asked.map(([option]) => [option, true])));
    assert.deepEqual(tail(g), asked.map(([, field]) => field), String(mask));
    assert.deepEqual(Object.keys(g.genesis.app_state).slice(-asked.length), asked.map(([, field]) => field));
    for (const [, field] of asked) assert.equal(g.genesis.app_state[field], true);
    assert.deepEqual(g.manifest.genesis, g.genesis.app_state);
    assert.equal(g.networkId, createHash('sha256').update('TCDEVNET-NETWORK-V4\0').update(JSON.stringify(g.genesis.app_state)).digest('hex'));
  }
  for (const [option] of GENESIS_SETTINGS) for (const value of ['true', 1, null, 'yes']) assert.throws(() => build({ [option]: value }), new RegExp(`${option} must be true or false`));
  // A word the builder does not know is refused: it must never be left out without a word, which is what the
  // test-network launcher checks for (testnet/plan.mjs, builderWrites) and what would give the node another genesis.
  assert.throws(() => build({ nextSetting: true }), /Unknown genesis option nextSetting/);
  assert.throws(() => build({ distinct_names: true }), /Unknown genesis option distinct_names/);
  assert.throws(() => build({ service_records: true }), /Unknown genesis option service_records/);
  assert.throws(() => build({ protectedAccounts: true }), /Unknown genesis option protectedAccounts/, 'the list of protected accounts is the ceremony\'s alone');
});

/// The entries of the ceremony's twenty validators, each signed with its consensus key, as tools/genesis-v5.mjs's own
/// tests make them.
function ceremonyEntries(chainId) {
  const raw = (key) => key.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), fresh = () => raw(generateKeyPairSync('ed25519').publicKey);
  return Array.from({ length: VALIDATORS }, (_, i) => {
    const consensus = generateKeyPairSync('ed25519'), key = raw(consensus.publicKey), owner = fresh();
    const entry = {
      schema_version: 1, kind: 'time-v5-validator-entry', chain_id: chainId, organization: `Org ${i}`, account_name: `op_${i}`,
      owner_public_key_hex: owner, consensus_public_key_hex: key, consensus_address: createHash('sha256').update(Buffer.from(key, 'hex')).digest().subarray(0, 20).toString('hex').toUpperCase(),
      node_id: randomBytes(20).toString('hex'), commission_bps: 1000, provider: 'aws', region: ['eu-west-3', 'us-east-1', 'ap-southeast-1', 'us-west-2'][i % 4],
      account_security: accountSecurity({ paymentPublicKeyHex: owner, loginPublicKeyHex: fresh(), recoveryPublicKeysHex: [fresh(), fresh()], dailyLimitSeconds: '3600' }),
    };
    return { ...entry, consensus_signature: sign(null, entryMessage(entry), consensus.privateKey).toString('base64') };
  });
}

test('the settings are written byte for byte as the production ceremony (tools/genesis-v5.mjs) writes them for the same choices', () => {
  const chainId = 'time-devnet-v4-harness-vs-ceremony';
  const ceremony = makeCeremony({ chainId, genesisTime: '2030-01-01T00:00:00.000Z', feeMicros: '10', feesToValidatorsPpm: '1000000', now: Date.parse('2029-12-01T00:00:00.000Z') });
  const produced = buildProductionGenesis({ ceremony, entries: ceremonyEntries(chainId) }).genesis.app_state;
  // The settings the ceremony writes, among those of this builder, in the ceremony's order: those before the list of
  // protected owner accounts (PRODUCTION_SETTINGS), then those after it (FINAL_SETTINGS).
  const written = [...Object.keys(PRODUCTION_SETTINGS), ...Object.keys(FINAL_SETTINGS)], ours = GENESIS_SETTINGS.filter(([, field]) => written.includes(field));
  assert.deepEqual(ours.map(([, field]) => field), written.filter((field) => GENESIS_SETTINGS.some(([, f]) => f === field)), 'the two tools write the settings in one order');
  assert.deepEqual(ours.map(([, field]) => field), ['distinct_names', 'waits_survive_stops', 'protected_registration', 'service_records'], 'the ceremony writes every setting of this builder');
  // The same choices in the harness's words: fee 10, every fee paid on, all new time to validators, the hand-over rule
  // and the settings the ceremony writes.
  const harness = build({ feeMicros: 10, feesToValidatorsPpm: 1_000_000, allNewTimeToValidators: true, stakeHandover: true, ...Object.fromEntries(ours.map(([option]) => [option, true])) }).genesisBytes.toString('utf8');
  const ceremonyBytes = JSON.stringify(produced);
  // Everything after the last protocol-4 field: the optional settings, which the network id hashes. Between
  // protected_registration and service_records the ceremony lists the owner accounts that start protected
  // (`protected_accounts`), which the harness does not: taken out, the two must be the same bytes.
  const after = (text) => text.slice(text.indexOf('"trusting_period_seconds":"604800"'));
  const ceremonyTail = after(ceremonyBytes), cut = ceremonyTail.indexOf(',"protected_accounts":'), resume = ceremonyTail.indexOf(',"service_records":', cut);
  assert.ok(cut > 0 && resume > cut, 'the ceremony lists the protected owner accounts after the settings, and the service records after them');
  assert.deepEqual(JSON.parse(ceremonyTail.slice(cut + ',"protected_accounts":'.length, resume)), produced.protected_accounts, 'what is taken out is the list of protected accounts and nothing else');
  assert.equal(ceremonyTail.at(-1), '}', 'the application state ends there');
  const ceremonySettings = ceremonyTail.slice(0, cut) + ceremonyTail.slice(resume, -1);
  assert.equal(after(harness).slice(0, -2), ceremonySettings, 'the bytes of the settings');
  assert.equal(after(harness).slice(-2), '}}', 'the settings are the last fields of the application state');
  assert.match(ceremonySettings, /,"fees_to_validators_ppm":"1000000","fee_micros":"10","all_new_time_to_validators":true,"stake_handover":true,"distinct_names":true,"waits_survive_stops":true,"protected_registration":true,"service_records":true$/);
});

test('the network starts at version 4', () => {
  const g = build({ nodesReportUpgrades: true });
  assert.equal(g.manifest.trust.app_version, '4');
  assert.equal(g.genesis.consensus_params.version.app, '4');
  assert.equal(g.manifest.protocolVersion, '4');
});
