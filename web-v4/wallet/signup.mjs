// Signing up protected: what does not touch the page. On a network whose genesis has `protected_registration`
// (TimeSDK.protectedRegistration of a verified state), "Create an account" makes an account that is protected from its
// first block: a login key, a payment key and two recovery papers in their roles, and a daily limit, registered through
// the sponsor by `client.registerProtected` (client-v4/time-sdk.js). signup-ui.mjs is the page part.
//
// What this browser keeps while a sign-up is under way, from the moment the papers were checked until the chain holds
// the account (security-flows.mjs, vaultSlots):
// - `login`: the registration key, sealed under the login password, as a vault of the kind every wallet of this name
//   opens (vault.mjs, version 1), with the salt of the name. Opening the account with the login password opens it, and the
//   wallet goes on from what the chain shows.
// - `nextLogin`, `nextSpend`: the login key under the login password and the payment key under the payment password,
//   kept aside (stageVaults) until the chain holds them; then they take the places of the live keys (settleStaged), and
//   the registration key, which is on no account, is overwritten.
// - `nextNote`: this note, the public half of the sign-up: the name, the registration key, the four keys with their
//   acceptances, and the policy. With the registration key and the salt it is everything `registerProtected` needs to be
//   called again with the same arguments. It holds no secret: the acceptances go on the chain anyway.
//
// The note is signed by the registration key (`signNote`) and is used only after that signature is checked (`readNote`).
// Whatever can write this browser's storage could otherwise put its own payment key into a sign-up that is resumed: the
// registration key's signature over the whole set would put it on the account. The registration key itself is opened only
// with the login password, so such a writer can stop a sign-up (by deleting what is kept) but not change it.
//
// Nothing is kept before the papers were checked: papers that were shown and not checked never reach the chain.
import { hex, unhex } from './vault.mjs';

export const SIGNUP_KIND = 45;
const NOTE_DOMAIN = new TextEncoder().encode('TCDEVNET-WALLET-SIGNUP-NOTE-V1\0');
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/, HEX32 = /^[0-9a-f]{64}$/, HEX64 = /^[0-9a-f]{128}$/;
const fail = message => { throw new Error(message); };
export const CHANGED = 'The sign-up kept in this browser was changed after it was made, so this browser does not use it, and sends nothing for it. Create your account with another name.';

/// Whether a network takes registrations that carry a set of keys, by a verified state of it. No state: no.
export function protectedSignup(sdk, state) { try { return Boolean(state) && sdk.protectedRegistration(state) === true; } catch { return false; } }

/// The note in its one form: these fields in this order, the keys sorted by public key.
function bodyOf(note) {
  const keys = [...note.keys].map(k => ({ public_key: k.public_key, role: k.role, proof: k.proof })).sort((a, b) => (a.public_key < b.public_key ? -1 : a.public_key > b.public_key ? 1 : 0));
  const p = note.policy;
  return { version: 1, kind: SIGNUP_KIND, networkId: note.networkId, name: note.name, registration: note.registration, keys, policy: { threshold: p.threshold, daily_limit_micros: p.daily_limit_micros, delay_seconds: p.delay_seconds, freeze_seconds: p.freeze_seconds } };
}
const noteMessage = note => { const text = new TextEncoder().encode(JSON.stringify(bodyOf(note))), out = new Uint8Array(NOTE_DOMAIN.length + text.length); out.set(NOTE_DOMAIN); out.set(text, NOTE_DOMAIN.length); return out; };
/// The note of a sign-up, signed by its registration key. `keys`: the four entries of the set ({public_key, role,
/// proof}: the acceptances of account-security.mjs, acceptRegistrationRole). `policy`: as security-flows.mjs, choosePolicy.
export async function signNote({ networkId, name, registration, keys, policy }, cryptoImpl = globalThis.crypto) {
  const body = bodyOf({ networkId, name, registration: registration.publicKey, keys, policy });
  check(body);
  return { ...body, signature: hex(new Uint8Array(await cryptoImpl.subtle.sign('Ed25519', registration.privateKey, noteMessage(body)))) };
}
function check(note) {
  const roles = note.keys.map(k => k.role).sort().join(',');
  if (roles !== 'recover,recover,signin,spend' || new Set(note.keys.map(k => k.public_key)).size !== 4 || note.keys.some(k => !HEX32.test(k.public_key) || !HEX64.test(k.proof)) || note.keys.some(k => k.public_key === note.registration)) fail(CHANGED);
  if (!HEX32.test(note.networkId) || !HEX32.test(note.registration) || !/^[a-z0-9_]{2,15}$/.test(note.name)) fail(CHANGED);
  if (!Object.values(note.policy).every(value => typeof value === 'string' && DECIMAL.test(value))) fail(CHANGED);
}
/// Whether a note kept beside staged keys (security-flows.mjs, stagedNote) is one of a sign-up.
export const isSignupNote = note => note !== null && typeof note === 'object' && note.kind === SIGNUP_KIND;
/// The note of a sign-up of `name`, read from storage and checked: its form, the network, the name, the registration key
/// that opens it, and the registration key's signature. Null when none is kept; an error when one is kept and fails.
export async function readNote(raw, { networkId, name, registrationKey }, cryptoImpl = globalThis.crypto) {
  if (raw === null || raw === undefined) return null;
  let note; try { note = JSON.parse(raw); } catch { fail(CHANGED); }
  if (!isSignupNote(note) || Object.keys(note).sort().join(',') !== 'keys,kind,name,networkId,policy,registration,signature,version' || note.version !== 1 || !Array.isArray(note.keys) || note.keys.length !== 4 || !note.policy || typeof note.policy !== 'object' || Object.keys(note.policy).sort().join(',') !== 'daily_limit_micros,delay_seconds,freeze_seconds,threshold' || typeof note.signature !== 'string' || !HEX64.test(note.signature)) fail(CHANGED);
  check(note);
  if (note.networkId !== networkId || note.name !== name || note.registration !== registrationKey) fail(CHANGED);
  const key = await cryptoImpl.subtle.importKey('raw', unhex(note.registration, 32), 'Ed25519', false, ['verify']);
  if (!await cryptoImpl.subtle.verify('Ed25519', key, unhex(note.signature, 64), noteMessage(note))) fail(CHANGED);
  return bodyOf(note);
}
/// The keys of the set as `registerProtected` takes them: by role, each with the acceptance signed when it was made.
export function keysByRole(note) {
  const of = role => note.keys.filter(k => k.role === role).map(k => ({ publicKey: k.public_key, proof: k.proof }));
  return { signin: of('signin'), spend: of('spend'), recover: of('recover') };
}
/// The public key of the set's one key in `role` ('signin' or 'spend').
export const noteKey = (note, role) => note.keys.find(k => k.role === role)?.public_key ?? null;

// ------------------------------------------------------------------ what a refusal means for the person
// The SDK's codes (time-sdk.js, registerProtected), and one of the registration service's (deploy/faucet/README.md,
// `account_limit`, marked by app.js, registrationSponsor, as `serviceCode`). Each sentence says what happened and what to
// do. A refusal without a sentence here is shown as before (app.js, failureNotice).
const papersVoid = name => `The recovery papers you wrote down for @${name} will never work: destroy them.`;
export function signupWords(error, name) {
  switch (error?.code) {
    case 'PROTECTED_REGISTRATION_UNAVAILABLE': return 'This network does not take accounts that are protected from the start, so nothing was sent. Reload this page: the wallet then makes your account the way this network takes it.';
    case 'NAME_TAKEN': return `Someone else took the name @${name} before your account was made. Nothing of yours is on the network. ${papersVoid(name)} Create your account with another name.`;
    case 'SPONSOR_MISMATCH': return 'The registration service named a payment that is not for your account, so this browser did not use it, and nothing was registered. Try again later: open your account with its name and your login password, and this browser goes on. Your recovery papers stay valid.';
    case 'COMMITMENT_MISMATCH': return 'The network holds a registration of this sign-up\'s key with other details than this browser keeps, so nothing was signed. That should not happen: this browser\'s data may have been changed. Wait an hour, then open your account with your login password to try again.';
    case 'REGISTRATION_MISMATCH': return `The account @${name} was made by this sign-up, but its keys or its limits are no longer the ones this browser made. If you changed them on another device, use that one. If you did not, someone has your recovery papers: recover the account with them at once.`;
    default: break;
  }
  if (error?.registrationService === true && error.serviceCode === 'account_limit') return 'The registration service says that it paid for this sign-up in the last 24 hours, and that this payment ran out before your account was made. It pays again 24 hours after the first time: then open your account with your login password, and this browser goes on. Your recovery papers stay valid.';
  return null;
}
/// What is added when the network refused the name as too close to one that exists (app.js, nameRefusal): the papers
/// of the refused name go with it.
export const tooCloseAddition = name => ` ${papersVoid(name)}`;

// ------------------------------------------------------------------ letting a kept sign-up go
// A sign-up that is kept blocks its name in this browser until it is finished, and finishing it needs the login password.
// A person who forgot it may let the sign-up go (signup-ui.mjs, letGo), and that must never forget an account, or keys that
// an account can still come to have. So it is offered only when nothing of the sign-up can ever be on the network:
// - no account of it: none whose identity key is the registration key, and none of its name that holds one of its keys;
// - no commitment of the registration key that the chain can still use (a registration needs one that has not run out:
//   v5/src/registration_adapter.rs, `for_reveal`);
// - no consent of the registration key that a sponsor could still use to make one: a consent is good until its expiry on
//   the chain's time (TimeSDK.sponsorConsentExpiry; registration/src/lib.rs, `commit`). Only the registration key signs a
//   consent, and only the login password opens it here: whoever forgot that password signs no new one.
// The expiry of the last consent this browser signed is kept beside the sign-up, written before the consent leaves the
// browser (`onConsent` of client.registerProtected) and signed by the registration key like the note: whatever can write
// this browser's storage cannot put an earlier expiry there, unless it kept an older record of this very sign-up. Without a
// record that holds, the page waits by itself: every consent signed before it first saw nothing on the network was dated at
// most five minutes ahead of the chain (SPONSOR_CONSENT_MAX_AHEAD_MICROS), so ten minutes of the chain's time after that
// reading (LET_GO_WAIT_MICROS, which leaves room for a state read up to a minute late) all of them have run out.
const CONSENT_DOMAIN = new TextEncoder().encode('TCDEVNET-WALLET-SIGNUP-CONSENT-V1\0');
export const consentKey = (networkId, name) => `timecurrency.signup-consent.v1:${networkId}:${name}`;
export const LET_GO_WAIT_MICROS = 600000000n;
const consentBody = (networkId, name, registration, expires) => ({ version: 1, networkId, name, registration, expires_elapsed_micros: expires });
const consentMessage = body => { const text = new TextEncoder().encode(JSON.stringify(body)), out = new Uint8Array(CONSENT_DOMAIN.length + text.length); out.set(CONSENT_DOMAIN); out.set(text, CONSENT_DOMAIN.length); return out; };
/// The record of a consent's expiry, signed by the registration key `{publicKey, privateKey}`.
export async function signConsent({ networkId, name, registration, expiresElapsedMicros }, cryptoImpl = globalThis.crypto) {
  const body = consentBody(networkId, name, registration.publicKey, String(expiresElapsedMicros));
  if (!DECIMAL.test(body.expires_elapsed_micros)) fail('The expiry of a consent is a whole number of microseconds.');
  return { ...body, signature: hex(new Uint8Array(await cryptoImpl.subtle.sign('Ed25519', registration.privateKey, consentMessage(body)))) };
}
/// The expiry a kept record holds (BigInt), or null: none is kept, or what is kept is not a record of this sign-up, of this
/// network and name, signed by its registration key.
export async function readConsent(raw, { networkId, name, registrationKey }, cryptoImpl = globalThis.crypto) {
  if (raw === null || raw === undefined || typeof registrationKey !== 'string' || !HEX32.test(registrationKey)) return null;
  try {
    const record = JSON.parse(raw);
    if (!record || typeof record !== 'object' || Object.keys(record).sort().join(',') !== 'expires_elapsed_micros,name,networkId,registration,signature,version' || record.version !== 1) return null;
    if (record.networkId !== networkId || record.name !== name || record.registration !== registrationKey || typeof record.expires_elapsed_micros !== 'string' || !DECIMAL.test(record.expires_elapsed_micros) || typeof record.signature !== 'string' || !HEX64.test(record.signature)) return null;
    const key = await cryptoImpl.subtle.importKey('raw', unhex(registrationKey, 32), 'Ed25519', false, ['verify']);
    const signed = await cryptoImpl.subtle.verify('Ed25519', key, unhex(record.signature, 64), consentMessage(consentBody(networkId, name, registrationKey, record.expires_elapsed_micros)));
    return signed ? BigInt(record.expires_elapsed_micros) : null;
  } catch { return null; }
}
/// What a verified state, read with `names: [name]` and `public_keys: [registration key]`, shows of a kept sign-up (its
/// note, as readNote gives it), and whether it may be let go: {offer: true}, or {offer: false, why: 'account' | 'commitment'
/// | 'taken' | 'consent', until}. `consentExpires`: of the record (readConsent), or
/// null. `firstNothing`: the chain's time of an earlier reading on this page that showed nothing, or null; a reading that
/// shows nothing for the first time without a record says so in `first`. Times are the chain's, since genesis.
export function letGoState({ state, note, consentExpires = null, firstNothing = null }) {
  const now = BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros), keys = new Set(note.keys.map(k => k.public_key)), accounts = state.accounts || [];
  const ofIt = account => account.public_key === note.registration || (account.devices || []).some(d => keys.has(d.public_key));
  if (accounts.some(a => a.public_key === note.registration || (a.name === note.name && ofIt(a)))) return { offer: false, why: 'account' };
  const commit = (state.name_commits || []).find(item => item.public_key === note.registration && BigInt(item.expires_elapsed_micros) >= now);
  if (commit) return { offer: false, why: 'commitment', until: BigInt(commit.expires_elapsed_micros) };
  // Another account of the name: this sign-up can never finish, and letting it go would free nothing. It is also the one
  // case in which an account of the name exists, so whatever wrote a sign-up of its own over that account's keys in this
  // storage could otherwise have the person told to destroy that account's recovery papers.
  if (accounts.some(a => a.name === note.name)) return { offer: false, why: 'taken' };
  if (consentExpires !== null) return consentExpires < now ? { offer: true } : { offer: false, why: 'consent', until: consentExpires, kept: true };
  if (firstNothing === null) return { offer: false, why: 'consent', until: now + LET_GO_WAIT_MICROS, kept: false, first: now };
  const until = BigInt(firstNothing) + LET_GO_WAIT_MICROS;
  return until < now ? { offer: true } : { offer: false, why: 'consent', until, kept: false };
}
/// Why a kept sign-up is not let go now, and what to do instead. `when(elapsed)`: a time of the chain as a date.
export function letGoWords(decided, name, when) {
  if (decided.why === 'account') return `The network holds the account @${name} that this sign-up made, so this browser keeps what opens it. Open it with the login password you chose for it; if you forgot that, recover the account with your recovery sheet and your recovery passphrase, under "Other ways in".`;
  if (decided.why === 'taken') return `The name @${name} belongs to another account on the network, so this sign-up can never finish, and this browser keeps it as it is. If that account is yours, open it with its login password, or recover it with your recovery sheet and your recovery passphrase; if not, create your account with another name.`;
  if (decided.why === 'commitment') return `A registration of @${name} from this sign-up waits on the network until ${when(decided.until)}, so this browser keeps the sign-up. If you remember your login password, open your account with it before then; if not, come back after that time to let it go.`;
  if (decided.kept) return `Nothing of this sign-up is on the network now, but a registration of it that was asked for could still reach it until ${when(decided.until)}. Come back after that time to let it go.`;
  return `Nothing of this sign-up is on the network now. This browser does not know when a registration of it was last asked for, so it waits ten minutes to be sure that none can reach the network any more: keep this page open, and press "Let this sign-up go" again after ${when(decided.until)}.`;
}
/// The review of letting a sign-up go: what is given up, in two sentences.
export const letGoReview = name => [
  ['Name', `@${name} is free again, for anyone. This browser forgets the keys it made for this sign-up; it cannot be undone.`],
  ['Recovery papers', `The recovery sheet and passphrase you wrote down for @${name} will never work: destroy them.`],
];
export const letGoneWords = name => `This browser let the sign-up of @${name} go. Destroy the recovery papers you wrote down for it.`;
export const LET_GO_CHANGED = 'The sign-up kept in this browser was changed after it was made, so this browser cannot tell which keys are this sign-up\'s, and does not let it go. Create your account with another name.';
export const keptPaymentKey = name => `This browser keeps a payment key of an account @${name}, so it does not let a sign-up of that name go. Open that account with its login password.`;
