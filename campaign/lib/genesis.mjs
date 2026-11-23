// Genesis for a private protocol-4 test network with N validators.
// Same application state as cloud-test/plan.mjs (reward version 1, laboratory profile,
// regtest-only Bitcoin settings, zero supply, no premine), generalized from exactly
// seven validators to any count, with larger blocks for throughput tests.
import { createHash, createECDH, generateKeyPairSync, randomBytes } from 'node:crypto';

export const MAX_GENESIS_ACCOUNTS = 64; // protocol-4 bound (v4/src/engine.rs)

/// The optional settings of spec/settings.md that this builder writes, each as `[option, field]`: the word a caller
/// passes (true or false) and the genesis field it writes as `true`. They are written in this order, after
/// `stake_handover` and after one another, which is the order of the node's encoding (v5/src/genesis.rs, `Genesis`):
/// the network id is a hash of these bytes. A node program that does not know one of them refuses a genesis that
/// carries it, and none can be switched on after the first block. Adding a setting is one entry here, in its place.
/// - distinctNames: a new account name that looks like a name that exists is refused (v5/src/names.rs). The genesis
///   account names below (operator_0, sponsor_7, ...) do not look alike.
/// - waitsSurviveStops: the waits and freezes of account security do not run while the chain is stopped.
/// - protectedRegistration: a registration can carry the account's keys (kind 45); the genesis lists no account that
///   starts protected (`protected_accounts`), which only the production ceremony writes.
/// - serviceRecords: the history of validators, stake and accounts, which no rule reads (v5/src/service.rs).
export const GENESIS_SETTINGS = Object.freeze([
  Object.freeze(['distinctNames', 'distinct_names']),
  Object.freeze(['waitsSurviveStops', 'waits_survive_stops']),
  Object.freeze(['protectedRegistration', 'protected_registration']),
  Object.freeze(['serviceRecords', 'service_records']),
]);

// identities: [{ address, pub_key: { type, value(base64) } }] from each host's own `cometbft init`.
// consensusParams: the consensus_params block of any freshly initialized genesis.json.
// feesToValidatorsPpm (version-5 engine only): parts per million of every fee paid on to validators; 0 leaves the
// field out, which is the protocol-4 rule (fees stay in the bank).
// feeMicros (version-5 engine only): what an action costs, in microseconds, from 1 to 1000; 1000 leaves the field
// out, which is the protocol-4 fee.
// allNewTimeToValidators (version-5 engine only): all new time goes to validators and their stakers, and the
// bitcoin auction is gone; false leaves the field out, which is the protocol-4 rule. Needs at least 5 validators.
// stakeHandover (version-5 engine only): the starting validators keep more than half of the voting power until
// independent stake has held a target for the hold period (genesis flag stake_handover); false leaves the field out,
// which is the protocol-4 calendar fade.
// nodesReportUpgrades (version-5 engine 0.7.0 and later only): the manifest's trust data says that the network's nodes
// answer the question about scheduled upgrades, so clients ask it with every verified read; false leaves the field out.
// The words of GENESIS_SETTINGS above (distinctNames, waitsSurviveStops, protectedRegistration, serviceRecords;
// version-5 engine only):
// each is true or false, false (the default) leaves its field out, which is the protocol-4 rule, and a network without
// any of them has the bytes and the network id it had before they existed.
export function buildGenesis({ identities, consensusParams, blockMaxBytes = 4 * 1024 * 1024, startInMs = 20_000, now = Date.now(), feesToValidatorsPpm = 0, feeMicros = 1000, allNewTimeToValidators = false, stakeHandover = false, nodesReportUpgrades = false, ...settings }) {
  const n = identities.length;
  if (n < 4 || n > 40) throw Error('Expected 4 to 40 validators');
  if (allNewTimeToValidators !== false && allNewTimeToValidators !== true) throw Error('allNewTimeToValidators must be true or false');
  if (stakeHandover !== false && stakeHandover !== true) throw Error('stakeHandover must be true or false');
  const unknown = Object.keys(settings).filter((word) => !GENESIS_SETTINGS.some(([option]) => option === word));
  if (unknown.length) throw Error(`Unknown genesis option ${unknown.join(', ')}`);
  for (const [option] of GENESIS_SETTINGS) if (settings[option] !== undefined && settings[option] !== false && settings[option] !== true) throw Error(`${option} must be true or false`);
  if (nodesReportUpgrades !== false && nodesReportUpgrades !== true) throw Error('nodesReportUpgrades must be true or false');
  if (allNewTimeToValidators && n < 5) throw Error('A network that pays all new time to validators needs at least 5 validators');

  // Zero-balance genesis accounts: validator owners first, then registration sponsors.
  const auth = Array.from({ length: MAX_GENESIS_ACCOUNTS }, (_, index) => {
    const pair = generateKeyPairSync('ed25519');
    return {
      accountId: String(index),
      role: index < n ? 'owner' : 'sponsor',
      publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
      privateKeyPkcs8: pair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    };
  });
  const chainId = 'time-devnet-v4-' + randomBytes(8).toString('hex');
  const genesisTime = new Date(now + startInMs).toISOString();
  const foundation = Array.from({ length: 7 }, () => { const k = createECDH('secp256k1'); k.generateKeys(); return k.getPublicKey('hex', 'compressed'); });
  const council = Array.from({ length: 7 }, () => generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'));
  const validators = identities.map((v, i) => ({ address: v.address, pub_key: v.pub_key, power: '1', name: 'campaign-' + i }));
  const appState = {
    history_version: 1, bitcoin_receipt_version: 1, reward_version: 1,
    ledger: {
      chain_id: chainId,
      genesis_time_micros: String(BigInt(Date.parse(genesisTime)) * 1000n),
      accounts: auth.map((a, i) => ({ id: String(i), name: (i < n ? 'operator_' : 'sponsor_') + i, public_key: a.publicKey })),
      economics: { mode: 'bank_only', auction_epoch_seconds: '10', unbond_seconds: '1209600', operators: [] },
    },
    profile: 'laboratory',
    validators: validators.map((v, i) => ({ owner: String(i), consensus_key: Buffer.from(v.pub_key.value, 'base64').toString('hex'), commission_bps: 1000 })),
    bitcoin: { network: 'regtest', confirmations: 12, max_batch: 256, max_fork_tips: 32, retention: 8192, max_reorg: 144, max_tip_age_secs: 7200, max_future_secs: 7200, mainnet_receipts_enabled: false },
    treasury: { revision: 1, treasury_keys: [...foundation].sort(), governance_keys: council },
    auction: { epoch_seconds: '10', bid_lead_epochs: '2', max_future_epochs: '48', min_sats: '1000', max_sats: '2100000000000000' },
    registration: { fee_micros: '10000', max_lifetime_micros: '86400000000', bucket_micros: '3600000000' },
    recovery_min_delay_micros: '30000000', recovery_approval_window_micros: '604800000000', trusting_period_seconds: '604800',
  };
  if (feesToValidatorsPpm !== 0) {
    if (!Number.isInteger(feesToValidatorsPpm) || feesToValidatorsPpm < 1 || feesToValidatorsPpm > 1_000_000) throw Error('feesToValidatorsPpm must be a whole number from 1 to 1000000');
    // After the protocol-4 fields, where the node's own encoding puts it: the network id is a hash of these bytes.
    appState.fees_to_validators_ppm = String(feesToValidatorsPpm);
  }
  if (feeMicros !== 1000) {
    if (!Number.isInteger(feeMicros) || feeMicros < 1 || feeMicros > 1000) throw Error('feeMicros must be a whole number from 1 to 1000');
    // Directly after fees_to_validators_ppm, or in its place when that is left out: the node writes them in this order.
    appState.fee_micros = String(feeMicros);
  }
  // Last, after fee_micros: the node writes the settings in this order, and the network id is a hash of these bytes.
  if (allNewTimeToValidators) appState.all_new_time_to_validators = true;
  // After all_new_time_to_validators: the node writes it there.
  if (stakeHandover) appState.stake_handover = true;
  // After stake_handover, in the order of GENESIS_SETTINGS, last of all: the node writes them there.
  for (const [option, field] of GENESIS_SETTINGS) if (settings[option] === true) appState[field] = true;
  const consensus = structuredClone(consensusParams);
  consensus.block.max_bytes = String(blockMaxBytes);
  consensus.evidence.max_bytes = '65536';
  consensus.version = { ...(consensus.version ?? {}), app: '4' };
  const genesis = { genesis_time: genesisTime, chain_id: chainId, initial_height: '1', consensus_params: consensus, validators, app_hash: '', app_state: appState };
  const networkId = createHash('sha256').update('TCDEVNET-NETWORK-V4\0').update(JSON.stringify(appState)).digest('hex');
  const manifest = {
    schemaVersion: 4, protocolVersion: '4', networkId, chainId, publicLaunchAllowed: false, genesis: appState,
    trust: {
      chain_id: chainId, network_id: networkId, app_version: '4', genesis_time_micros: appState.ledger.genesis_time_micros,
      trusting_period_seconds: '604800', unbonding_period_seconds: '1209600',
      initial_validators: validators.map((v) => ({ address: v.address, pub_key: v.pub_key, voting_power: '1', proposer_priority: '0' })),
      ...(nodesReportUpgrades ? { nodes_report_upgrades: true } : {}),
    },
  };
  return { genesis, genesisBytes: Buffer.from(JSON.stringify(genesis)), manifest, auth, chainId, networkId };
}
