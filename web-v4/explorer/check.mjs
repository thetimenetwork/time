// What the explorer checks itself, in the browser, instead of taking the service's word.
//
// The page is installed with a trust manifest (the network's id and a block its installer vouches
// for). From there a light client (client-v4/light-client.mjs) follows the chain by validator
// signatures, with the verifier compiled to WebAssembly (web-v4/shared/verifier). Two things are
// checked against the block it reaches:
//
// - A state: an account, the validators. The service passes on a proof; the verifier checks it
//   for the question this page asks (the page builds the question itself, it does not take the
//   service's copy of it).
// - An action: that these exact bytes are in a block of the chain. The usual way is through the
//   history of block hashes the state keeps (`verifyReceipt`), which works for a block of any
//   age. The newest two blocks are not in that history yet; for those the block's own signed
//   header is followed (`verifyFastReceipt`).
//
// One rule runs through this file: once the service has been asked for a proof, nothing the
// service says decides what the result is called. Whether an account exists is read from the
// verified state, never from the status of the answer; whether the page's own trust has expired
// is found by verifying that trust before the service is asked, never by reading an error text
// the service could have shaped.
//
// The parts are handed in (`loadTrust`, `loadVerifier`, `createLightClient`, `sdk`), so the same
// code runs in the browser and, in tests, under Node with the same verifier.
import { ApiFailure } from './client.mjs';
import { isHash, isHeight, isMicros } from './format.mjs';

/// Why a check gave no "checked". `reason`:
/// - 'no_trust': the page has no usable trust manifest (none installed, or it could not be loaded);
/// - 'wrong_network': the manifest is for another network than the service says it answers for;
/// - 'no_verifier': the verifier could not be loaded, or does not run (found by calling it once
///   before anything is judged with it);
/// - 'trust_expired': the page's own trusted block does not verify any more (too old);
/// - 'clock': this device's clock does not fit the chain's (the state looks stale, or a block
///   looks dated ahead);
/// - 'unavailable': the service did not give the material (`detail` is the ApiFailure);
/// - 'behind': the service answered with an older block than the page has already followed;
/// - 'too_new': the block is at the edge of the chain and the service's node cannot give its
///   signed header yet;
/// - 'not_kept': the service cannot prove a block that old (its node holds no history for it);
/// - 'upgrade_required': the network runs a version of the rules that this page's verifier does
///   not implement (the verifier read that from a header it authenticated);
/// - 'refused': the material was there and did NOT verify (`detail` is the verifier's text);
/// - 'network_reset': any of the above, while the page's trust manifest, read again, names another network than the one
///   the page checks against: the test network was reset under the same address, and the page must be loaded again.
/// `offered` tells whether the service had handed over proof material when the check ended. The
/// page shows the service's own figures (as its word) only for a failure with `offered` false:
/// once a proof was offered and did not pass, for whatever reason, the figures are withheld.
export class CheckFailure extends Error {
  constructor(reason, detail = null, { offered = false } = {}) { super(`check ${reason}`); this.reason = reason; this.detail = detail; this.offered = offered; }
}
/// The service's block is below the one this page already stands at: not a wrong proof.
class Behind extends Error {}

const usableTrust = (trust) => Boolean(trust) && typeof trust === 'object' && String(trust.app_version) === '4' && typeof trust.network_id === 'string' && /^[0-9a-f]{64}$/.test(trust.network_id) && typeof trust.chain_id === 'string' && trust.chain_id.length > 0;
const base64 = (value) => typeof value === 'string' && value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
const textOf = (error) => String(error?.message ?? error);
/// The verifier's fixed messages for a clock that does not fit the chain's. Each is compared
/// whole or by its fixed beginning; text a service can shape only ever comes after such a
/// beginning (the verifier puts its own code first), so it cannot produce one of these.
/// The verifier found, in a header it authenticated, a version of the rules it does not implement.
/// The mark is set on the error by the verifier's own wrapper (client-v4/proof-verifier.mjs) and
/// by nothing else.
const newerRules = (error) => error?.code === 'UPGRADE_REQUIRED';
const clockTrouble = (error) => { const text = textOf(error); return text === 'INVALID_CLOCK' || text.startsWith('STALE_STATE:') || text === 'INVALID_LIGHT_BLOCK: header exceeds future clock bound'; };

/// The frame every signed action has, read without the SDK: the SDK reads the content only of
/// the kinds it knows, and the chain holds others. Null if the bytes are not in that frame.
export function readEnvelope(bytes) {
  const domain = new TextEncoder().encode('TCDEVNET-ACTION-V1\0'), head = domain.length + 32 + 1 + 24 + 32 + 4;
  if (!(bytes instanceof Uint8Array) || bytes.length < head + 64 || !domain.every((value, at) => bytes[at] === value)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const hex = (from, to) => Array.from(bytes.subarray(from, to), (byte) => byte.toString(16).padStart(2, '0')).join('');
  let at = domain.length;
  const networkId = hex(at, at += 32), kind = bytes[at++];
  const sender = view.getBigUint64(at).toString(); at += 8;
  const nonce = view.getBigUint64(at).toString(); at += 8;
  const authEpoch = view.getBigUint64(at).toString(); at += 8;
  const publicKey = hex(at, at += 32), length = view.getUint32(at); at += 4;
  if (at + length + 64 !== bytes.length) return null;
  return { networkId, kind, sender: sender === '18446744073709551615' ? null : sender, nonce, authEpoch, publicKey };
}

export function createChecker({ api, loadTrust, loadVerifier, createLightClient, sdk, now = Date.now, pause = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); }), pauseMs = 800 }) {
  let trustLoad = null, session = null, queue = Promise.resolve(), network = null;
  /// Checks run one after the other: each moves the light client forward, and a proof must be
  /// checked against the block the client stands at when the proof arrives.
  const serial = (work) => { const result = queue.then(work); queue = result.catch(() => {}); return result; };
  /// The manifest, loaded once. A load that fails (the page's host limits requests, the connection
  /// drops) is not remembered: the next check loads it again. "None installed" is remembered.
  const trustOnce = () => (trustLoad ??= Promise.resolve().then(loadTrust).then((trust) => (usableTrust(trust) ? trust : null), () => { trustLoad = null; return null; }));
  async function open() {
    const trust = await trustOnce();
    if (!trust) throw new CheckFailure('no_trust');
    if (network !== null && trust.network_id !== network) throw new CheckFailure('wrong_network');
    let verifier;
    try { verifier = await loadVerifier(); } catch (error) { throw new CheckFailure('no_verifier', textOf(error)); }
    if (!['verifyTrust', 'verifyLightUpdate', 'verifyViewProof', 'verifyReceipt', 'verifyFastReceipt'].every((name) => typeof verifier?.[name] === 'function')) throw new CheckFailure('no_verifier');
    if (!['hexToBytes', 'transactionHash', 'decodeAction'].every((name) => typeof sdk?.[name] === 'function')) throw new CheckFailure('no_verifier');
    // The module is there; whether the compiled verifier behind it runs shows only at its first
    // call (WebAssembly may be refused, its file limited or missing). So it is called once, with
    // a trust that is none: a verifier that runs refuses that in its own fixed words. Anything
    // else means it does not run, and is said as that, before the page's trust is judged with it.
    const answer = await verifier.verifyTrust({}, 0).then(() => 'accepted a trust that is none', textOf);
    if (!answer.startsWith('INVALID_JSON:')) throw new CheckFailure('no_verifier', answer);
    // Whether this network's nodes report scheduled upgrades is part of the trust data
    // (`nodes_report_upgrades`), read by the SDK. A manifest that says it in no accepted form is
    // not a usable manifest.
    let reportsUpgrades = false;
    try { reportsUpgrades = typeof sdk.nodesReportUpgrades === 'function' && sdk.nodesReportUpgrades(trust) === true; } catch { throw new CheckFailure('no_trust'); }
    // `createLightClient` may load its module first (in a browser), so its answer is awaited.
    let light;
    try { light = await createLightClient({ trust, verifier, now, fetchBlock: async (height) => {
      if (!isHeight(String(height ?? ''))) throw new Error('A light block is asked for by its height');
      return (await api.lightBlock(String(height))).light_block;
    } }); } catch (error) { throw new CheckFailure('no_verifier', textOf(error)); }
    return { trust, verifier, light, reportsUpgrades };
  }
  const ready = () => (session ??= open().catch((error) => { session = null; throw error; }));
  /// Moves the light client to a block the service gave. A block below the one already reached
  /// is told apart by its height before anything is verified: it is "behind", not a failed proof.
  async function follow(light, block) {
    const reached = light.getCheckpoint(), given = block?.signed_header?.header?.height;
    if (reached && isHeight(given) && BigInt(given) < BigInt(reached.height)) throw new Behind();
    return light.updateToBlock(block);
  }
  /// Runs `work` with the session.
  /// - Before the service is asked for anything, the page's own trust is verified with the device's
  ///   clock. If that fails, nothing of the service was looked at: 'trust_expired' or 'clock'.
  /// - `work` sets `progress.offered` once the service has handed over proof material. Whatever
  ///   fails after that is classified here, and never from text the service could have shaped:
  ///   a failed request is 'unavailable'; an older block is 'behind' (asked again after a pause,
  ///   twice); the verifier's own clock messages are 'clock'; everything else is 'refused'.
  // A test network can be reset: a new chain under the same addresses (testnet/README.md). A page left open then fails
  // every check, against the trust it loaded first. Before a failure is reported, the trust manifest is read again, at
  // most once every half minute; if it names another network, the failure is 'network_reset'. Once it did, it stays so.
  let resetSeen = false, resetAsked = -Infinity;
  async function wasReset() {
    if (resetSeen) return true;
    const loaded = await trustOnce();
    if (!loaded || now() - resetAsked < 30000) return false;
    resetAsked = now();
    try { const fresh = await loadTrust(); resetSeen = usableTrust(fresh) && fresh.network_id !== loaded.network_id; } catch { return false; }
    return resetSeen;
  }
  async function attempt(work) {
    try { return await attemptOnce(work); } catch (error) {
      if (error instanceof CheckFailure && error.reason !== 'network_reset' && await wasReset()) throw new CheckFailure('network_reset', null, { offered: error.offered });
      throw error;
    }
  }
  async function attemptOnce(work) {
    const current = await ready();
    if (network !== null && current.trust.network_id !== network) throw new CheckFailure('wrong_network');
    try { await current.light.ready(); } catch (error) { throw new CheckFailure(newerRules(error) ? 'upgrade_required' : clockTrouble(error) ? 'clock' : 'trust_expired', textOf(error)); }
    const progress = { offered: false };
    for (let round = 0; ; round++) {
      try { return await work(current, progress); } catch (error) {
        if (error instanceof CheckFailure) throw error;
        if (error instanceof ApiFailure) throw new CheckFailure('unavailable', error, { offered: progress.offered });
        if (error instanceof Behind) { if (round < 2) { await pause(pauseMs); continue; } throw new CheckFailure('behind', null, { offered: true }); }
        // The light client's own budget for one update: it continues from where it got to.
        if (round < 2 && textOf(error).startsWith('LIGHT_UPDATE_BUDGET:')) continue;
        throw new CheckFailure(newerRules(error) ? 'upgrade_required' : clockTrouble(error) ? 'clock' : 'refused', textOf(error), { offered: progress.offered });
      }
    }
  }

  /// Checks a state the service answered with. `fetchBody` asks the service (it is asked again if
  /// its block was behind); `query` is the question this page asks, in the verifier's form.
  /// An error answer that carries a proof is checked like any answer: its status decides nothing.
  /// Returns { body, state, absent, names, height, timeMicros, anchorHeight }:
  /// - `state` is what the verifier proved, and the only thing a caller may show as checked;
  /// - `absent` lists the account numbers of the question that the proof shows do not exist;
  /// - `names` maps each name of the question to the number it belongs to, or to null if the
  ///   proof shows that no account has it.
  function checkState(fetchBody, query) {
    return serial(() => attempt(async ({ trust, verifier, light, reportsUpgrades }, progress) => {
      let body;
      try { body = await fetchBody(); } catch (error) {
        if (!(error instanceof ApiFailure) || !error.body?.proof?.view_proof) throw error;
        body = error.body;
      }
      progress.offered = true;
      const proof = body?.proof?.view_proof;
      if (!proof || typeof proof !== 'object' || !proof.light_block) throw new Error('The answer carries no proof');
      await follow(light, proof.light_block);
      // On a network whose trust data says that its nodes report scheduled upgrades, every
      // question carries that one too (the SDK's rule): a service can then never leave the
      // upgrade row out of one answer, and a state without the proven row is refused as a whole.
      const asked = reportsUpgrades ? { ...query, include_upgrade: true } : query;
      const result = await verifier.verifyViewProof(proof, light.getTrust(), asked, now());
      if (result?.verified !== true || !result.state || result.state.network_id !== trust.network_id) throw new Error('The state did not verify');
      if (reportsUpgrades && !Object.hasOwn(result.state, 'upgrade')) throw new Error('The state lacks the upgrade entry that was asked for');
      const names = {};
      for (const [name, id] of Object.entries(result.names && typeof result.names === 'object' ? result.names : {})) if (id === null || typeof id === 'string') names[name] = id;
      return { body, state: result.state, absent: Array.isArray(result.absentAccountIds) ? result.absentAccountIds.filter((id) => typeof id === 'string') : [], names,
        // For a page file of an earlier release that a browser may still hold next to this one:
        // that file looked for an account in `state` only when `found` was set. It is always set,
        // and means only what is true of every result here: a proof verified, look in `state`.
        // It never carries the status of the service's answer.
        found: true,
        height: String(result.state.height), timeMicros: String(result.state.time_micros), anchorHeight: light.getCheckpoint()?.height ?? null };
    }));
  }

  /// Checks that the action with this hash is in a block of the chain. Asks the service for the
  /// bytes and the proof material itself, so that what is checked is what the service says now.
  /// Returns { hash, height, index, total, blockHash, mode, resultsChecked, anchorHeight, rawHex, action, envelope }:
  /// - `index` and `total` (the position in the block and the block's number of actions) are
  ///   given only when the next block was checked too: its header fixes how many actions the
  ///   block has, and without it the same proof fits more than one position. Otherwise null.
  /// - `action` is the SDK's reading of the proven bytes, or null if it cannot read this kind;
  /// - `envelope` is the frame of the bytes (kind, sender, nonce, authEpoch, publicKey), read
  ///   without the SDK, or null if the bytes are not in the frame of an action.
  function checkAction(hash) {
    if (!isHash(hash)) return Promise.reject(new CheckFailure('refused', 'Not an action hash'));
    const wanted = hash.toUpperCase();
    return serial(() => attempt(async ({ trust, verifier, light }, progress) => {
      const found = await api.action(wanted), action = found?.action, material = found?.verify;
      progress.offered = true;
      if (!action || !material || !base64(action.raw) || !isHeight(material.height) || !Number.isSafeInteger(material.index) || material.index < 0 || !isMicros(String(material.total ?? ''))
        || typeof material.root_hash !== 'string' || !base64(material.leaf_hash) || !Array.isArray(material.aunts) || material.aunts.length > 64 || !material.aunts.every(base64)) throw new Error('The answer carries no usable proof material');
      // The form of the node's own transaction lookup, which the verifier takes.
      const tx = { hash: wanted, height: material.height, index: material.index, tx: action.raw,
        proof: { root_hash: material.root_hash, data: action.raw, proof: { total: String(material.total), index: String(material.index), leaf_hash: material.leaf_hash, aunts: material.aunts } } };
      let receipt, mode;
      const anchor = await api.blockProof(material.height).catch((error) => {
        if (error instanceof ApiFailure && error.status === 404 && error.code === 'not_in_history') return null;
        // The service's node holds no history for a block that old (it joined from a snapshot).
        if (error instanceof ApiFailure && error.status === 404 && error.code === 'history_not_held') throw new CheckFailure('not_kept', null, { offered: true });
        throw error;
      });
      if (anchor) {
        if (!anchor.proof?.view_proof?.light_block || !anchor.signed_header || !anchor.next_signed_header) throw new Error('The answer carries no proof of the block');
        await follow(light, anchor.proof.view_proof.light_block);
        receipt = await verifier.verifyReceipt({ tx, signed_header: anchor.signed_header, next_signed_header: anchor.next_signed_header, anchor: anchor.proof.view_proof }, light.getTrust(), now());
        mode = 'history';
      } else {
        // The service says its state does not reach this block yet. That can be true only of a
        // block at the edge of the chain. This page has followed the chain to `reached`: a block
        // more than one below that is not a new one, and a service that cannot prove it is said to
        // be that, not "too new".
        const reached = light.getCheckpoint();
        if (reached && BigInt(reached.height) > BigInt(material.height) + 1n) throw new CheckFailure('not_kept', null, { offered: true });
        // At the edge: follow the block's own signed header, and the next one if it exists (it
        // commits to the results of this block).
        const next = await api.lightBlock((BigInt(material.height) + 1n).toString()).then((answer) => answer.light_block, (failure) => { if (failure instanceof ApiFailure && failure.status === 404) return null; throw failure; });
        const own = await api.lightBlock(material.height).then((answer) => answer.light_block, (failure) => { if (failure instanceof ApiFailure && failure.status === 404) throw new CheckFailure('too_new', null, { offered: true }); throw failure; });
        const checkpoint = await follow(light, next ?? own);
        const headers = next ? [own?.signed_header?.header, checkpoint.block.signed_header.header] : [checkpoint.block.signed_header.header];
        receipt = await verifier.verifyFastReceipt({ tx, headers }, { ...light.getTrust(), checkpoint }, now());
        mode = 'own-block';
      }
      if (receipt?.verified !== true || receipt.executionVerified !== true || String(receipt.txHash).toUpperCase() !== wanted || receipt.height !== material.height) throw new Error('The receipt is not for this action');
      // The bytes the verifier proved, hashed and read again here.
      const bytes = sdk.hexToBytes(receipt.rawHex);
      if (await sdk.transactionHash(bytes) !== wanted) throw new Error('The proven bytes have another hash');
      const envelope = readEnvelope(bytes);
      let decoded = null;
      try { decoded = sdk.decodeAction(bytes); } catch { decoded = null; }
      if ((decoded && decoded.networkId !== trust.network_id) || (envelope && envelope.networkId !== trust.network_id)) throw new Error('The action is signed for another network');
      const resultsChecked = mode === 'history' || receipt.resultsChecked === true;
      return { hash: wanted, height: receipt.height, index: resultsChecked ? material.index : null, total: resultsChecked ? String(material.total) : null, blockHash: String(receipt.blockHash).toUpperCase(), mode, resultsChecked,
        anchorHeight: light.getCheckpoint()?.height ?? null, rawHex: receipt.rawHex, action: decoded,
        envelope: envelope ? { kind: envelope.kind, sender: envelope.sender, nonce: envelope.nonce, authEpoch: envelope.authEpoch, publicKey: envelope.publicKey } : null };
    }));
  }

  return {
    checkState, checkAction,
    /// The network the service says it answers for. If it is not the manifest's, nothing is
    /// checked and nothing of the service's state is shown: see CheckFailure, 'wrong_network'.
    expectNetwork(id) { if (typeof id === 'string' && /^[0-9a-f]{64}$/.test(id)) network = id; },
    /// Whether the installed SDK reads the upgrade row of a state. The row is in a checked state
    /// only if the page's trust data says that the network's nodes report upgrades (the checker
    /// then asks with every read); a state without it says nothing about upgrades, and a page
    /// says nothing either.
    readsUpgrade: typeof sdk?.upgradeStatusOf === 'function',
    /// { version, scheduled, known } of a state verified with `include_upgrade` (the SDK's
    /// `upgradeStatusOf`): `scheduled` is the plan, or null when the proof shows there is none.
    upgradeStatus(state) { if (typeof sdk?.upgradeStatusOf !== 'function') throw new Error('The installed SDK does not read upgrade plans'); return sdk.upgradeStatusOf(state); },
    /// What the page was installed to trust, for showing: null if it has no manifest (yet).
    async trust() {
      const trust = await trustOnce();
      if (!trust) return null;
      const checkpoint = trust.checkpoint && typeof trust.checkpoint === 'object' ? trust.checkpoint : null;
      return { networkId: trust.network_id, chainId: trust.chain_id, genesisTimeMicros: isMicros(trust.genesis_time_micros) ? trust.genesis_time_micros : null,
        anchorHeight: isHeight(checkpoint?.height) ? checkpoint.height : null, anchorHash: typeof checkpoint?.block_hash === 'string' && /^[0-9a-fA-F]{64}$/.test(checkpoint.block_hash) ? checkpoint.block_hash.toUpperCase() : null };
    },
  };
}
