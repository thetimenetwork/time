import { isBusyError, askWhenFree, BUSY_NOTHING, BUSY_KEPT, BUSY_KEPT_PRESS_AGAIN, BUSY_FAUCET, BUSY_FAUCET_ASKED } from './busy.mjs';
export function accountActionHeader({ account, publicKey, networkId, kind, payload }) {
  if (!account || !Array.isArray(account.devices)) throw new Error('Verified account required.');
  const device = account.devices.find(d => d.public_key === publicKey);
  const manage = ['add_device', 'revoke_device', 'set_recovery', 'consent_recovery', 'approve_recovery', 'cancel_recovery', 'cancel_pending'].includes(kind);
  if (!device || !(manage ? device.can_manage : device.can_spend)) throw new Error('Device permission is insufficient.');
  const nonce = BigInt(account.nonce) + 1n;
  if (nonce > 18446744073709551615n) throw new Error('Account nonce is exhausted.');
  return { networkId, kind, from: String(account.id), nonce: nonce.toString(), authEpoch: String(account.auth_epoch), publicKey, payload };
}
// Whether the rules that came with protocol version 4 apply to a verified state: at version 4 and
// at every later one (a version never changes what an existing action means). The version is the
// state's own `protocol_version`, which the verifier checked against the header the validators
// certified. What a gateway reports is never used for this.
export function sinceVersion4(state) {
  const version = state?.protocol_version;
  return typeof version === 'string' && /^[1-9][0-9]{0,19}$/.test(version) && BigInt(version) >= 4n;
}
// A time of the chain (microseconds since genesis) as a date, in UTC.
function chainDate(state, elapsedMicros) {
  const ms = (BigInt(state.genesis.genesis_time_micros) + BigInt(elapsedMicros)) / 1000n;
  if (ms > 8640000000000000n) return 'a date beyond the calendar';
  return new Date(Number(ms)).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}
// Why a read of the upgrade entry failed, as one of two words: 'timeout' (no answer within the
// time limit, a mark this wallet's own SDK sets) or 'unverified' (anything else: a refusal, an
// answer without the entry, a proof that fails). The error's text is never read and never shown:
// it may be a gateway's, and a gateway's words must not choose what the wallet says.
export function upgradeProblem(error) {
  return error?.timeout === true ? 'timeout' : 'unverified';
}
// The banner about a change of the protocol version, or null when there is nothing to say.
// - `status` is {version, scheduled, known} (the SDK's upgradeStatusOf), read from proven state:
//   the row `upgrade/state` or the proof that it is absent.
// - `problem` is 'timeout' or 'unverified' (upgradeProblem) when that answer could not be had. The
//   wallet then says that it could not check, for as long as that lasts: no answer is never shown
//   as "nothing is scheduled". This only happens on a network whose pinned trust data does not
//   say that its nodes report upgrades (an older laboratory network); the line says that too,
//   since on such a network the nodes may simply not know the question. It is a quiet line, not a
//   warning.
// - `state` is the verified state the status was read from (for the date of the start).
// Returns {text, urgent}. Every word is this app's own.
export function upgradeBanner({ status, problem, state }) {
  if (problem) return { text: 'This app could not check whether an upgrade of the network is scheduled: ' + (problem === 'timeout' ? 'the gateway did not answer in time' : 'the answer could not be verified') + '. This network does not state that its nodes report upgrades, so they may not be able to. This app keeps asking.', urgent: false };
  if (!status || status.scheduled === null) return null;
  const plan = status.scheduled, when = chainDate(state, plan.activate_elapsed_micros);
  if (status.known) return { text: `The network is scheduled to move to version ${plan.version} of its rules on ${when}. This app is ready for it. You need to do nothing.`, urgent: false };
  return { text: `The network is scheduled to move to version ${plan.version} of its rules on ${when}. This app only knows version ${status.version}: from that time on it stops working until it is updated. Your seconds are not affected. Update this app before then, from the place you got it.`, urgent: true };
}
// The "update this app" screen, or null for any other error. It is shown only for the refusal this
// wallet's own verifier raises for a protocol version it does not implement: an error with `code`
// 'UPGRADE_REQUIRED', which only the verifier's wrapper (proof-verifier.mjs) and the SDK's own
// version check set, never for anything a gateway sent. Every word on the screen is this app's
// own. The one thing taken from the error is the version number, and only when the message is
// exactly the verifier's sentence, in which that number comes from a certified header.
export function upgradeRequiredScreen(error) {
  if (typeof error !== 'object' || error === null || error.code !== 'UPGRADE_REQUIRED' || typeof error.message !== 'string' || !error.message.startsWith('UPGRADE_REQUIRED:')) return null;
  const version = /^UPGRADE_REQUIRED: the network runs protocol version ([1-9][0-9]{0,19}); this software implements versions [1-9][0-9]{0,19} to [1-9][0-9]{0,19}\. Install a release that implements version \1\.$/.exec(error.message)?.[1];
  return {
    title: 'Update this app',
    lines: [
      (version ? `The network now runs version ${version} of its rules, which this app does not know.` : 'The network now runs a newer version of its rules than this app knows.') + ' This app can no longer check your balance or sign for you, so it has stopped.',
      'Your account and your seconds are unchanged. The encrypted key stored in this browser stays where it is. You lose nothing by waiting.',
      'Get the new version of this app from the same place you got this one. Do not follow a link in a message or on a website that tells you to update: this screen comes from the app itself.',
    ],
  };
}
// What the wallet says when it was checking the receipt of an action and found, by its own
// verification, that the network now runs rules it does not know (the SDK's waitReceipt and
// exportReceiptEvidence then throw that finding with the hash of the action). Null for any other
// error. The wallet checks a receipt in three situations: after it signed and sent an action, on
// "Recheck" of a stored receipt, and on "Save public receipt" of one it verified before. The
// sentence is true in all three. The words are this app's own; the one thing taken from the
// error is the hash, in its fixed form.
export function upgradeWhileWaiting(error) {
  if (upgradeRequiredScreen(error) === null || typeof error.hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(error.hash)) return null;
  return `This app was checking the receipt of the action ${error.hash.toUpperCase()} when it stopped. It can no longer check receipts: neither whether an action you just signed was included, nor a receipt it checked before. An action listed as pending under Activity stays there. Do not sign it again: after you have updated this app, check it under Activity.`;
}
// A gateway's answer to a refused request, for the notice. The SDK marks such an error
// (`error.gateway === true`); its text is whatever the gateway chose to write. So it is never
// shown as this wallet's own sentence: it follows a fixed introduction that says whose words they
// are, and it is made plain first. Only printable characters of the basic alphabet are kept, quote
// marks are dropped, every run of 12 or more characters that could be part of a hash or a number
// is broken into groups of four (nothing in it can be pasted as a value), and it is cut to 160
// characters. Nothing of this wallet follows it, so a gateway cannot end its part and go on as
// the wallet.
export const GATEWAY_WORDS_INTRO = 'The gateway refused this request. Its answer follows; this wallet did not check it. Do not copy or enter anything from it: ';
// Whether a receipt is the one a registration waits for: the verified receipt of a registration sponsorship
// (kind 44) for this very key and this very commitment of the name. A sponsor that answers with the hash of any
// other action (another key's sponsorship, a payment) has shown nothing about this registration.
export function sponsorReceiptBinds(receipt, publicKey, commitment) {
  const action = receipt?.action;
  return receipt?.verified === true && action?.kind === 44 && typeof publicKey === 'string' && publicKey !== '' && typeof commitment === 'string' && commitment !== ''
    && action.payload?.public_key === publicKey && action.payload?.commitment === commitment;
}
const plainWords = error => {
  const text = typeof error?.message === 'string' ? error.message : '';
  return [...text].map(character => (character >= ' ' && character <= '~' && !'"\'`'.includes(character) ? character : ' ')).join('')
    .replace(/[0-9A-Fa-f]{12,}/g, run => run.match(/.{1,4}/g).join(' ')).replace(/\s+/g, ' ').trim().slice(0, 160) || '(no text)';
};
export function gatewayWords(error) { return GATEWAY_WORDS_INTRO + plainWords(error); }
// The same for a registration service (a test network's faucet, which the wallet asks to sponsor a new account,
// app.js, registrationSponsor): a party the wallet trusts no more than its gateway. Its refusal is marked
// (`error.registrationService === true`) and shown by the same rule, after a sentence that names it.
export const REGISTRATION_WORDS_INTRO = 'The registration service refused this request. Its answer follows; this wallet did not check it. Do not copy or enter anything from it: ';
export function registrationWords(error) { return REGISTRATION_WORDS_INTRO + plainWords(error); }
// The same for the test faucet, asked for a grant by "Get test time" (askFaucet below). It is the registration
// service of the same test network, and the wallet trusts it no more: a refusal it has no sentence of its own for is
// marked (`error.faucet === true`) and shown by the same rule, after a sentence that names it.
export const FAUCET_WORDS_INTRO = 'The test faucet refused this request. Its answer follows; this wallet did not check it. Do not copy or enter anything from it: ';
export function faucetWords(error) { return FAUCET_WORDS_INTRO + plainWords(error); }
// An error whose words are not the wallet's own is told by its kind, in fixed words (web audit of November 2026,
// W-2). The wallet's own refusals are plain Errors with its sentences, and so are the SDK's; the verifier's wrapper
// gives its own words or a code and fixed words (client-v4/proof-verifier.mjs). Anything else comes from the
// browser's or the engine's machinery, whose messages may quote what came from outside: JSON.parse quotes the start
// of a text it cannot read, BigInt the text it cannot convert, a module that does not load its address.
const FOREIGN_WORDS = Object.freeze({
  SyntaxError: 'An answer could not be read, so nothing was done with it.',
  TypeError: 'The network could not be reached, or an answer could not be used. Check your connection and try again.',
  RangeError: 'A number in an answer is out of range, so nothing was done with it.',
  AbortError: 'No answer came in time. Try again.',
  TimeoutError: 'No answer came in time. Try again.',
});
/// The kinds of error whose name the notice may add, in brackets, after the fixed words.
const FOREIGN_NAMES = new Set([...Object.keys(FOREIGN_WORDS), 'ReferenceError', 'EvalError', 'URIError', 'CompileError', 'LinkError', 'RuntimeError', 'NetworkError', 'NotAllowedError', 'SecurityError', 'InvalidStateError', 'QuotaExceededError', 'OperationError', 'DataError', 'NotSupportedError']);
export const FOREIGN_ERROR = 'Something went wrong that this wallet cannot describe. Nothing was signed that you did not review. Try again.';
export function foreignWords(error) {
  let name = ''; try { name = typeof error?.name === 'string' ? error.name : ''; } catch { name = ''; }
  return (Object.hasOwn(FOREIGN_WORDS, name) ? FOREIGN_WORDS[name] : FOREIGN_ERROR) + (FOREIGN_NAMES.has(name) ? ` (${name})` : '');
}
// What the notice says after a failed step: the wallet's sentence about a receipt it could no
// longer check, a gateway's answer marked as such, the error's own text when it is a plain Error
// (the wallet's, the SDK's or the verifier wrapper's), or fixed words for any other error.
export function failureNotice(error, fallback = 'Action failed.') {
  const waiting = upgradeWhileWaiting(error); if (waiting) return waiting;
  // A network that stayed busy (busy.mjs): before anything was sent, or with a signed action kept (it carries the hash).
  if (isBusyError(error)) return typeof error.hash !== 'string' ? BUSY_NOTHING : error.sameButton === true ? BUSY_KEPT_PRESS_AGAIN : BUSY_KEPT;
  if (typeof error === 'object' && error !== null && error.gateway === true) return gatewayWords(error);
  if (typeof error === 'object' && error !== null && error.registrationService === true) return registrationWords(error);
  if (typeof error === 'object' && error !== null && error.faucet === true) return faucetWords(error);
  if (!(error instanceof Error) || typeof error.message !== 'string' || error.message === '') return fallback;
  return Object.getPrototypeOf(error) === Error.prototype ? error.message : foreignWords(error);
}
// A line of the gateway's notification feed (/api/notifications), which no proof covers. Only a
// short name in small letters and a block height are taken from it, and the line says whose
// words they are. Anything else gives no line.
export function gatewayNotification(item) {
  const type = item?.type, height = String(item?.height ?? '');
  if (typeof type !== 'string' || !/^[a-z][a-z_]{0,39}$/.test(type) || !/^(0|[1-9][0-9]{0,19})$/.test(height)) return null;
  return `Reported by the gateway, not checked by this wallet: ${type.replaceAll('_', ' ')} at block ${height}.`;
}
// How the wallet asks about a scheduled upgrade, and what it shows. Whether a network's nodes
// answer the question comes from the network's pinned trust data (`declared`: the trust object
// says `nodes_report_upgrades: true`; the SDK client has it as `nodesReportUpgrades`), never
// from what a gateway answers.
// - Declared: every verified read carries `include_upgrade` from the first one (the SDK adds it).
//   There is no probe, and nothing is learned or stored. A gateway that holds, refuses or leaves
//   out the question fails the read itself.
// - Not declared (an older laboratory network): until a node has answered with the upgrade
//   entry, the wallet asks in a read of its own (a probe), with a time limit, so that reads
//   against older nodes keep working. While the probe fails, for whatever reason, the wallet
//   shows one standing, quiet line that it could not check, and keeps asking. Once a node has
//   answered, every verified read carries the question, and that is remembered in `storage` for
//   this network; `forget()` drops it again (after a node was replaced by an older one, every
//   read would otherwise fail).
export function createUpgradeMonitor({ storage, networkId, declared = false, now = Date.now, retryMs = 60000 }) {
  const key = 'timecurrency.upgrade-entry.v1:' + networkId;
  let learned = false, nextProbe = 0;
  if (!declared) { try { learned = storage?.getItem(key) === '1'; } catch { learned = false; } }
  return {
    declared: () => declared,
    // Whether the question rides on every read: declared by the network, or learned from an answer.
    capable: () => declared || learned,
    // Whether there is a learned answer that `forget()` would drop.
    learned: () => learned,
    selection: () => (declared || learned ? { include_upgrade: true } : {}),
    probeDue: () => !declared && !learned && now() >= nextProbe,
    probeStarted() { nextProbe = now() + retryMs; },
    // A verified state that carries the entry, with its status ({version, scheduled, known}).
    fromState(state, status) {
      if (!declared && !learned) { learned = true; try { storage?.setItem(key, '1'); } catch { /* remembered for this page only */ } }
      return { banner: upgradeBanner({ status, state }) };
    },
    // The probe failed: the standing line, whatever the reason. The error's text is not read.
    probeFailed(error) {
      nextProbe = now() + retryMs;
      return { banner: upgradeBanner({ problem: upgradeProblem(error) }) };
    },
    // Drops the learned answer: the wallet asks in a read of its own again. True if there was one.
    forget() {
      if (!learned) return false;
      learned = false; nextProbe = 0;
      try { storage?.removeItem(key); } catch { /* forgotten for this page */ }
      return true;
    },
    // A new unlock: the question is asked again at the next refresh.
    unlocked() { nextProbe = 0; },
  };
}
export function pendingIsObsolete(account, pending, action, state) {
  const expiredQuote=sinceVersion4(state)&&action.kind===10&&/^[0-9a-f]{64}$/.test(action.payload?.reference||'')
    &&BigInt('0x'+action.payload.reference.slice(16,32))<BigInt(state.time_micros)-BigInt(state.genesis.genesis_time_micros);
  return Boolean(account && (BigInt(account.nonce) >= BigInt(pending.nonce) || String(account.auth_epoch) !== pending.authEpoch || (action.kind === 4 && BigInt(action.payload.epoch) < BigInt(state.auction_epoch))||expiredQuote));
}
/// The smallest stake (microseconds) that a pool takes whatever the remainder of the division is: a pool gives
/// whole shares, and the ledger refuses a stake that loses more than 0.1% to that rounding. A stake of a thousand
/// times the price of one share loses less than that for certain; a smaller one may pass or not. An empty pool
/// takes anything.
export function leastSureStake(pool) {
  const shares = BigInt(pool.total_shares), assets = BigInt(pool.assets);
  return shares > 0n && assets > 0n ? (assets * 1000n + shares - 1n) / shares : 1n;
}
const microsAsSeconds = (micros) => { const whole = micros / 1000000n, part = (micros % 1000000n).toString().padStart(6, '0').replace(/0+$/, ''); return part ? `${whole}.${part}` : `${whole}`; };
export function poolSharesForDeposit(pool, amount) {
  const shares = BigInt(pool.total_shares), assets = BigInt(pool.assets), value = BigInt(amount);
  if (value <= 0n || (shares > 0n && assets <= 0n)) throw new Error('Invalid pool or amount.');
  const result = shares === 0n ? value : value * shares / assets;
  // The refusal says what would be taken: a person cannot work that out from "0.1%".
  const tooSmall = () => new Error(`This amount is too small for this validator's pool: at the pool's price today a stake there would lose more than 0.1% to the rounding of whole shares. A stake of ${microsAsSeconds(leastSureStake(pool))} seconds or more is always taken. Stake more, or choose another validator.`);
  if (result <= 0n) throw tooSmall();
  if (shares > 0n && (value * shares - result * assets) * 1000n > value * (shares + result)) throw tooSmall();
  return result.toString();
}
export function registrationPendingDisposition(state, binding, action) {
  if (action.networkId !== binding.networkId || action.publicKey !== binding.publicKey || ![1, 2].includes(action.kind)) throw new Error('Pending registration does not match this vault.');
  const account = state.accounts.find(a => a.name === binding.name);
  if (account) {
    if (!account.devices.some(d => d.public_key === binding.publicKey)) throw new Error('Name belongs to another device.');
    return 'known_account';
  }
  const elapsed = BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
  const commit = state.name_commits.find(c => c.public_key === binding.publicKey);
  if (action.kind === 1) {
    if (commit?.commitment === action.payload.commitment && String(commit.expires_elapsed_micros) === action.payload.expires_elapsed_micros) return 'known_commit';
    if (elapsed > BigInt(action.payload.expires_elapsed_micros)) return 'expired';
  } else if (!commit || elapsed > BigInt(commit.expires_elapsed_micros)) return 'expired';
  return 'retry_exact';
}
export const emergencyCancelSlot = accountId => 'emergency-cancel-' + accountId;
export const nonceCancelSlot = accountId => 'nonce-cancel-' + accountId;
export function recoveryFrozen(state, accountId) {
  const now = BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
  return (state.recovery_cases || []).some(r => r.target === String(accountId) && r.ready_elapsed_micros !== null && BigInt(r.expires_elapsed_micros) >= now);
}
export function authorityReservationObsolete(account, reservation) {
  return BigInt(account.auth_epoch) > BigInt(reservation.authEpoch);
}
export function emergencyReservationObsolete(account, reservation) {
  return authorityReservationObsolete(account, reservation) || BigInt(account.nonce) >= BigInt(reservation.nonce);
}

// ---------------------------------------------------------------- "Sent"
// What the wallet says after a payment it signed was included: what the other person must do (nothing), and that this
// browser checked the receipt itself. The same words after a payment of an account with one key (app.js) and of a
// protected account (security-ui.mjs).
export const sentNotice = (name, amountText) => `Sent. @${name} has the ${amountText} seconds now and needs to do nothing. This browser checked the network's receipt.`;
/// A number of seconds of a policy ("172800") as words: "48 hours", "1 minute", "90 seconds".
export function durationWords(secondsText) {
  const s = BigInt(secondsText);
  if (s > 0n && s % 3600n === 0n) return `${s / 3600n} hour${s === 3600n ? '' : 's'}`;
  if (s > 0n && s % 60n === 0n) return `${s / 60n} minute${s === 60n ? '' : 's'}`;
  return `${s} second${s === 1n ? '' : 's'}`;
}

// ---------------------------------------------------------------- "Get test time": a grant from the test faucet
// The faucet of a test network is the registration service that the wallet's own service names
// (`network.registrationService`, an origin; the page's Content-Security-Policy lets the page connect to it). Home
// offers "Get test time" only when there is one, and one press asks it for one grant for this account.
// - What is sent: `{"account": "<number>"}` to `POST <origin>/v1/faucet/grants`, nothing else (deploy/faucet/README.md,
//   "Routes"). The account goes by its number: a name of digits only would be read as a number by the faucet.
// - Before that the faucet's facts are read (`GET <origin>/v1/faucet`): nothing is asked of a faucet that answers for
//   another network or says that it is not giving now.
// - Each answer is waited for `timeoutMs` (fifteen seconds) at most and read to `maxBytes` (64 KiB) at most, as for a
//   registration (app.js, registrationSponsor). No cookie, no referrer, no redirect.
// - A refusal with a code listed in the faucet's README is told in this wallet's own sentence, which says that it is
//   what the faucet says (`FAUCET_SAYS`); the faucet's own words are then not shown. Any other refusal is the faucet's
//   own text, marked (`error.faucet`) and shown as a gateway's words are (`faucetWords`).
// - Whether the time arrived is not taken from the faucet's word: the caller waits for the receipt of the hash and
//   checks it (`faucetReceiptPays`).
const NOT_GIVING = 'The test faucet is not giving test time right now. Try again later.';
const SENT_LATER = 'The test faucet could not get its payment into the network yet. If it gets in later, your balance shows it.';
export const FAUCET_SAYS = Object.freeze({
  account_limit: 'The test faucet says that this account had test time in the last 24 hours. Try again later.',
  address_limit: 'The test faucet says that your internet address has had enough test time for now. Try again later.',
  daily_total: 'The test faucet says that it has given all it gives in 24 hours. Try again later.',
  already_funded: 'The test faucet says that this account holds enough test time already.',
  account_not_found: 'The test faucet does not see this account yet. Wait a few seconds and try again.',
  rate_limited: 'The test faucet says that you asked too often. Wait a minute and try again.',
  faucet_empty: NOT_GIVING, faucet_frozen: NOT_GIVING, faucet_unavailable: NOT_GIVING, chain_daily_limit: NOT_GIVING,
  node_unavailable: NOT_GIVING, busy: NOT_GIVING, state_unavailable: NOT_GIVING, wrong_network: NOT_GIVING,
  node_refused: SENT_LATER,
});
const HASH = /^[0-9a-fA-F]{64}$/, NUMBER = /^(0|[1-9][0-9]{0,19})$/;
/// `busy`: {sdk, timing, onBusy}, how a busy answer is waited for (busy.mjs, askWhenFree); without it, a busy answer is
/// read as any other refusal.
export async function askFaucet({ origin, account, networkId, fetch: get = globalThis.fetch, timeoutMs = 15000, maxBytes = 65536, busy = null }) {
  if (typeof origin !== 'string' || origin === '') throw new Error('The service of this wallet names no test faucet.');
  if (!NUMBER.test(String(account ?? ''))) throw new Error('Open your account first.');
  const options = { cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' };
  const read = async (path, init = {}) => {
    const send = () => get(origin + path, { ...options, ...init, signal: AbortSignal.timeout(timeoutMs) });
    let response;
    // The question is asked again after a busy answer; a request for test time is sent once, since a busy answer to it
    // may come after the faucet sent something (its refusals "the node refused it for now" say 503, Retry-After 30).
    // The faucet's own refusals to it (its limits of a day, "not giving now") are read as before (busy.mjs, inOwnForm).
    const once = init.method === 'POST';
    try { response = busy ? await askWhenFree(send, once ? { ...busy, tries: 1, ownForm: true } : busy) : await send(); }
    catch (error) { if (isBusyError(error)) throw Object.assign(new Error(once ? BUSY_FAUCET_ASKED : BUSY_FAUCET), { faucetBusy: true }); throw error; }
    const reader = response.body?.getReader(), parts = []; let size = 0;
    if (reader) for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > maxBytes) { await reader.cancel().catch(() => {}); throw new Error('The answer of the test faucet is too long.'); } parts.push(value); }
    const bytes = new Uint8Array(size); let at = 0; for (const part of parts) { bytes.set(part, at); at += part.byteLength; }
    let answer = null; try { answer = JSON.parse(new TextDecoder().decode(bytes)); } catch { answer = null; }
    return { ok: response.ok, status: response.status, answer };
  };
  let facts = null;
  try { const got = await read('/v1/faucet'); if (got.ok) facts = got.answer; } catch (error) { if (error.faucetBusy === true) throw error; facts = null; }
  if (!facts || typeof facts !== 'object') throw new Error('The test faucet does not answer. Nothing was asked. Try again in a minute.');
  if (facts.network_id !== networkId) throw new Error('The test faucet answers for another network. Nothing was asked.');
  if (facts.giving !== true) throw new Error(NOT_GIVING);
  let got;
  try { got = await read('/v1/faucet/grants', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account: String(account) }) }); }
  catch (error) { if (error.faucetBusy === true) throw error; throw new Error('The test faucet could not be reached, or did not answer in time. If it sent test time anyway, your balance shows it in a moment.'); }
  const answer = got.answer;
  if (got.status === 202 && HASH.test(String(answer?.hash ?? ''))) return { hash: answer.hash, faucetAccount: NUMBER.test(String(facts.account ?? '')) ? String(facts.account) : null };
  if (got.ok) throw new Error('The test faucet gave an answer that this wallet cannot use. If it sent test time anyway, your balance shows it in a moment.');
  const code = typeof answer?.error?.code === 'string' ? answer.error.code : '';
  // A refusal that comes with the hash of an action the faucet sent: the node refused it for now, and it may still be included.
  if ((code === 'chain_daily_limit' || code === 'node_refused') && HASH.test(String(answer?.hash ?? ''))) throw new Error(SENT_LATER);
  if (Object.hasOwn(FAUCET_SAYS, code)) throw new Error(FAUCET_SAYS[code]);
  throw Object.assign(new Error(typeof answer?.error?.message === 'string' ? answer.error.message.slice(0, 200) : `status ${got.status}`), { faucet: true });
}
// Whether a verified receipt is the faucet's grant to this account: a transfer (kind 3) to it of more than nothing, and,
// when the faucet named its account, from that account. A faucet that answers with the hash of some other action has
// shown nothing about a grant.
export function faucetReceiptPays(receipt, accountId, faucetAccount = null) {
  const action = receipt?.action;
  return receipt?.verified === true && action?.kind === 3 && typeof accountId === 'string' && accountId !== '' && action.payload?.to === accountId
    && typeof action.payload?.amount === 'string' && /^[1-9][0-9]*$/.test(action.payload.amount) && (faucetAccount === null || action.from === faucetAccount);
}

// ---------------------------------------------------------------- the Keys screen
/// The quiet line on the card of the recovery words of an account whose recovery is one paper (words only) and whose proven
/// balance is more than an hour of seconds: `text`, then `link`, which opens "New recovery words" with a kit selected.
export const KIT_HINT = Object.freeze({ text: 'Your recovery is one paper.', link: 'Add a Recovery Kit so that a paper alone is not enough.' });
export const KIT_HINT_ABOVE_MICROS = 3600n * 1000000n;
// What the Keys screen says: each thing that opens the account, what it does, where it is, when it is needed and
// what to do without it, marked in words as one for every day or one to keep safe. app.js draws it.
// - An account with one key: its name and its password every day, its backup file to keep safe.
// - A protected account (security-flows.mjs, accountSecured): the login password and the payment password every day,
//   the recovery words (and a Recovery Kit when the account has one) to keep safe, and this browser, which holds the
//   keys. What is said of recovery follows the kind of recovery keys this browser knows the account has.
// The sentences say only what the wallet's code does: which key signs what is in signing.mjs and security-flows.mjs,
// the backup file in vault-backup.mjs and BACKUP_FORMAT.md, recovery on another browser in security-ui.mjs.
// `limit` and `waiting` are words already ("60 seconds", "48 hours"). `paymentKeyHere`: this browser holds the payment
// key of a protected account. `guardians`: the account has a guardian policy. `otherKeys`: keys of an account with one
// key per browser that are not this browser's. `paused`: payments of a protected account are paused (Home,
// Protection): its limit is then no amount to name as what the payment password pays. `balanceMicros`: the proven balance,
// for the quiet line of a recovery that is one paper (KIT_HINT).
export function keysView({ protectedAccount, name, limit = '', waiting = '', paymentKeyHere = true, guardians = false, otherKeys = 0, paused = false, recoveryKind = null, balanceMicros = '0' }) {
  const day = (id, title, rows, mark = 'Every day') => ({ id, title, mark: 'day', markText: mark, rows });
  const safe = (id, title, rows) => ({ id, title, mark: 'safe', markText: 'Keep safe', rows });
  const lede = `@${name}: what you need every day, and what to keep safe.`;
  if (!protectedAccount) {
    const forgotten = guardians ? 'Nobody can reset it, and your backup file needs it too. The guardians you chose can approve a new key for you: see Guardian recovery under More.'
      : otherKeys > 0 ? 'Nobody can reset it, and your backup file needs it too. You can still open the account in your other browser, with its own password.'
      : 'Nobody can reset it, and your backup file needs it too. Without it, this account cannot be opened again.';
    return { lede, note: '', cards: [
      day('name', 'Your name', [['What it is for', `@${name}. Others send you seconds to it, and you type it to open your account.`], ['Where it is', 'On the network, where everyone can see it.']]),
      day('password', 'Your password', [['What it does', 'Unlocks the key of your account, which this browser keeps. That key signs every payment.'], ['Where it is', 'In your head, or in a password manager. It is never sent anywhere.'], ['When you need it', 'Each time you open the wallet, and to download your backup file.'], ['If you forget it', forgotten]]),
      safe('backup', 'Your backup file', [['What it is', 'A copy of the key of your account, locked with your password. It opens your account in another browser, or in this one after its data was cleared.'], ['Where to keep it', 'Somewhere other than this device: a USB stick, another computer, a drive you trust.'], ['Without it', 'If this browser\'s data is cleared (by clearing its history, a reset or a lost phone), the key in it is gone.' + (guardians || otherKeys > 0 ? '' : ' With no backup file, so is the account.')], ['Why it is safe', 'The file alone opens nothing: it needs your password. Your password alone opens nothing in another browser: it needs the file. Keep the two apart.']]),
    ] };
  }
  const wait = waiting || 'the waiting period';
  // What recovering needs, by the kind of recovery keys this browser knows the account has (security-flows.mjs,
  // recoveryKindOf): words only, words and a Recovery Kit, or not known here (keys made in another browser).
  const needs = recoveryKind === 'words' ? 'your recovery words' : recoveryKind === 'kit' ? 'your recovery words and your Recovery Kit' : 'your recovery words, and your Recovery Kit if your account has one';
  const note = recoveryKind === 'words' ? `Your recovery words, on paper, are all your account needs to be recovered: both recovery keys come from them. Whoever has them can ask for your account too; that waits ${wait}, frozen, and only these words can stop it: keep two copies in different places. Lost them? The account keeps working, but a lost password can no longer be replaced.`
    : recoveryKind === 'kit' ? 'Your recovery words and your Recovery Kit are your two recovery keys: the kit holds your recovery sheet, locked with the words. Recovering needs both. Lost either? The account keeps working, but a lost password can no longer be replaced.'
    : 'Your recovery words are your recovery, and your Recovery Kit too if you made one under “New recovery words”. Lost them? The account keeps working, but a lost password can no longer be replaced.';
  const words = safe('phrase', 'Recovery words', recoveryKind === 'kit' ? [
    ['What it does', 'They open your Recovery Kit, and are a recovery key themselves. Alone: they freeze the account. With your payment password: they pay more than the limit at once, end a freeze, or make new words.'],
    ['Where it is', 'On paper, kept in another place than the kit: not in a photo, a note or a message. The wallet stores them nowhere.'],
    ['When you need it', 'Never day to day. A step that uses them needs a lot of memory: do it on a computer.'],
    ['If you lose them', 'Your Recovery Kit does not open without them. If you printed it, make new words at once under “Change something”, with your payment password and the printed sheet. If not, nobody can replace a lost password any more: move your seconds to a new account while your passwords work.'],
  ] : [
    ['What it does', recoveryKind === 'words' ? `Both recovery keys of your account come from them. With them, lost passwords are replaced after ${wait}. Alone they also freeze the account; with your payment password they pay more than the limit at once, end a freeze, or make new words.` : `With your Recovery Kit if your account has one: they replace lost passwords, after ${wait}. Alone they freeze the account; with your payment password they pay more than the limit at once, end a freeze, or make new words.`],
    ['Where it is', 'On paper, written by hand: not in a photo, a note or a message. The wallet stores them nowhere.'],
    ['When you need it', 'Never day to day. A step that uses them needs a lot of memory: do it on a computer.'],
    ['If someone may have seen them', `Make new words at once under “Change something”, with your payment password and these words. Until then, whoever has them can ask for your account: that waits ${wait}, frozen, and only these words can stop it.`],
    ['If you lose them', 'New words cannot be made without them, and a lost password can no longer be replaced. The account keeps working: move your seconds to a new account while your passwords work.'],
  ]);
  const kit = safe('sheet', 'Recovery Kit', [['What it does', `With your recovery words: replaces lost passwords, after ${wait}. It holds your recovery sheet, locked with the words: alone it opens nothing.`], ['Where it is', 'A file you downloaded: in your own email, your cloud storage or a folder you will find again. Or on paper, if you printed it (your printed recovery sheet). The wallet stores it nowhere.'], ['When you need it', 'Never day to day. To recover your account: “Recover my account”.'], ['If you lose it', 'Make new words at once under “Change something”. It needs your payment password and your recovery words. The old kit and words then stop working.']]);
  // A recovery that is one paper, on an account that holds more than an hour of seconds: one quiet line on the card of the
  // words, which leads to "New recovery words" with a kit (app.js, offerKit). Nothing else asks for it.
  let more = false; try { more = BigInt(balanceMicros) > KIT_HINT_ABOVE_MICROS; } catch { more = false; }
  if (recoveryKind === 'words' && more) words.hint = KIT_HINT;
  return { lede, note, cards: [
    day('login', 'Login password', [['What it does', 'Opens this wallet and signs you in to websites. It cannot pay.'], ['Where it is', 'In your head, or in a password manager. It unlocks the login key that this browser keeps.'], ['When you need it', 'Each time you open the wallet.'], ['If you forget it', `In another browser, choose “Recover my account”. It needs ${needs}, and the account waits ${wait}, frozen, before that browser takes over.`], ['If someone may know it', 'Under “Change something” below, make a new login password. It needs your payment password.']]),
    day('payment', 'Payment password', [['What it does', paused ? 'Payments are paused (see Home): it pays nothing at once now. It can start a payment that waits, and it can freeze the account.' : `Pays up to ${limit || 'your daily limit'} at once, fees included: your daily limit, which refills over 24 hours. It can also freeze the account.`], ['Where it is', paymentKeyHere ? 'In your head, apart from the login password. It unlocks the payment key that this browser keeps.' : 'In your head. Its payment key is kept in another browser of yours, not in this one.'], ['When you need it', 'Each time you pay or stake.'], ['If you forget it', `Recover with ${needs} in another browser, as for the login password.`], ['If someone may know it', 'Freeze the account at once, on Home. Then make a new payment password under “Change something”: it needs your recovery words.']], 'When you pay'),
    ...(recoveryKind === 'kit' ? [kit] : []),
    words,
    day('browser', 'This browser', [['What it keeps', paymentKeyHere ? 'Your login key and your payment key, each locked by its own password.' : 'Your login key, locked by your login password.'], ['Where it is', 'In this browser\'s data, on this device.'], ['If it is lost', `Clearing this browser's data, or losing the device, deletes the keys in it. Recover with ${needs} in another browser. A backup file brings back the login key only.`]]),
  ] };
}
