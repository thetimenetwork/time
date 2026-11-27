// Who the wallet asks to sponsor the registration of a new account (app.js, registrationSponsor).
// The function is taken out of app.js as it is written there and run with stand-ins for the
// page's own service and for the registration service. The whole path, in a real browser against
// a real faucet, runs in the browser check of a campaign (campaign/README.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { failureNotice, sponsorReceiptBinds } from './actions.mjs';
import { askWhenFree, isBusyError, BUSY_REGISTRATION } from './busy.mjs';
import '../../client-v4/time-sdk.js';

test('the receipt a registration waits for: a verified sponsorship of this very key and this very commitment, and nothing else', () => {
  const key = 'aa'.repeat(32), commitment = 'bb'.repeat(32);
  const receipt = (change = {}) => ({ verified: true, height: '10', action: { kind: 44, from: '77', payload: { public_key: key, commitment, expires_elapsed_micros: '1' } }, ...change });
  assert.equal(sponsorReceiptBinds(receipt(), key, commitment), true);
  // The hash of some other action, however valid its receipt.
  assert.equal(sponsorReceiptBinds(receipt({ action: { kind: 3, payload: { to: '1', amount: '5' } } }), key, commitment), false, 'a payment');
  assert.equal(sponsorReceiptBinds(receipt({ action: { kind: 44, payload: { public_key: 'cc'.repeat(32), commitment } } }), key, commitment), false, 'another key');
  assert.equal(sponsorReceiptBinds(receipt({ action: { kind: 44, payload: { public_key: key, commitment: 'dd'.repeat(32) } } }), key, commitment), false, 'another commitment: the sponsor chose a name');
  assert.equal(sponsorReceiptBinds(receipt({ action: { kind: 2, payload: { public_key: key, commitment } } }), key, commitment), false, 'another kind with the same fields');
  // A receipt that was not verified is no receipt.
  assert.equal(sponsorReceiptBinds(receipt({ verified: false }), key, commitment), false);
  assert.equal(sponsorReceiptBinds({ action: receipt().action }, key, commitment), false);
  for (const nothing of [null, undefined, {}, { verified: true }, { verified: true, action: null }]) assert.equal(sponsorReceiptBinds(nothing, key, commitment), false);
  // Nothing to compare with compares equal to nothing.
  assert.equal(sponsorReceiptBinds(receipt({ action: { kind: 44, payload: {} } }), undefined, undefined), false);
  assert.equal(sponsorReceiptBinds(receipt({ action: { kind: 44, payload: { public_key: '', commitment: '' } } }), '', ''), false);
});

const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const start = source.indexOf('async function registrationSponsor() {'), end = source.indexOf('async function registerAccount() {');
assert.ok(start > 0 && end > start, 'app.js holds registrationSponsor right before registerAccount');
const sponsorFrom = new Function('network', 'client', 'assert', 'fetch', 'askWhenFree', 'isBusyError', 'BUSY_REGISTRATION', 'busyOptions', `${source.slice(start, end)}; return registrationSponsor;`);
// How the page waits for a busy service (app.js, busyOptions), with waits that take no time: each is recorded.
const waited = [];
const make = (network, client, assert, fetch) => sponsorFrom(network, client, assert, fetch, askWhenFree, isBusyError, BUSY_REGISTRATION, () => ({ sdk: globalThis.TimeSDK, timing: { sleep: async ms => { waited.push(ms); } } }));
const NETWORK = 'c6'.repeat(32), ORIGIN = 'https://faucet.example';
const check = (condition, message) => { if (!condition) throw new Error(message); };
const body = { public_key: 'aa'.repeat(32), commitment: 'bb'.repeat(32), expires_elapsed_micros: '90000000', proof: 'cc'.repeat(64) };

/// A registration service that answers `facts` and, to a registration, `answer` with `status`.
/// `retryAfter`: the Retry-After of the answer to a registration (the faucet's limits of a day say hours; its "the node
/// refused it for now" says 30 seconds).
function service({ facts = { network_id: NETWORK, account: '77', registrations: { sponsored: true } }, factsStatus = 200, status = 202, answer = { hash: 'AB'.repeat(32), status: 'submitted' }, down = false, retryAfter = null } = {}) {
  const calls = [];
  const fetch = async (url, options = {}) => {
    calls.push({ url: String(url), ...options });
    if (down) throw new TypeError('fetch failed');
    if (String(url) === `${ORIGIN}/v1/faucet`) return new Response(JSON.stringify(facts), { status: factsStatus });
    if (String(url) === `${ORIGIN}/v1/faucet/registrations`) return new Response(typeof answer === 'string' ? answer : JSON.stringify(answer), { status, headers: retryAfter === null ? {} : { 'Retry-After': retryAfter } });
    return new Response('{}', { status: 404 });
  };
  return { fetch, calls };
}
const never = { request: async () => { throw new Error('the page\'s own service was asked'); } };

test('a laboratory\'s service sponsors by itself: the wallet asks it, and no other origin', async () => {
  const asked = [], { fetch, calls } = service();
  const sponsor = await make({ networkId: NETWORK, sponsorAccount: '0', registrationService: ORIGIN }, { request: async (path, options) => { asked.push([path, options]); return { hash: 'ab'.repeat(32) }; } }, check, fetch)();
  assert.equal(sponsor.account, '0');
  assert.deepEqual(await sponsor.ask(body), { hash: 'ab'.repeat(32) });
  assert.equal(asked[0][0], '/api/sponsor-registration'); assert.deepEqual(JSON.parse(asked[0][1].body), body);
  assert.equal(calls.length, 0);
});

test('a registration service: the wallet consents to the account that service names for its own network, and sends key, commitment and consent only', async () => {
  const { fetch, calls } = service();
  const sponsor = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, fetch)();
  assert.equal(sponsor.account, '77');
  assert.deepEqual(await sponsor.ask(body), { hash: 'ab'.repeat(32) }, 'the hash is handed on in lower case, as the wallet looks receipts up');
  assert.deepEqual(calls.map((c) => [c.method ?? 'GET', c.url]), [['GET', `${ORIGIN}/v1/faucet`], ['POST', `${ORIGIN}/v1/faucet/registrations`]]);
  assert.deepEqual(JSON.parse(calls[1].body), body);
  assert.deepEqual(Object.keys(JSON.parse(calls[1].body)).sort(), ['commitment', 'expires_elapsed_micros', 'proof', 'public_key'], 'no name, no password, no key');
  for (const call of calls) { assert.equal(call.credentials, 'omit'); assert.equal(call.redirect, 'error'); assert.equal(call.referrerPolicy, 'no-referrer'); assert.equal(call.cache, 'no-store'); }
  // A service that gives its account as a number is read the same way.
  const numbered = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, service({ facts: { network_id: NETWORK, account: 77, registrations: { sponsored: true } } }).fetch)();
  assert.equal(numbered.account, '77');
});

test('nothing is sent to a service that answers for another network, does not sponsor, names no account, or does not answer', async () => {
  const cases = [
    [{ facts: { network_id: 'd7'.repeat(32), account: '77', registrations: { sponsored: true } } }, /answers for another network\. Nothing was sent/],
    [{ facts: { network_id: NETWORK, account: '77', registrations: { sponsored: false } } }, /not sponsoring new accounts now/],
    [{ facts: { network_id: NETWORK, account: '77' } }, /not sponsoring new accounts now/],
    [{ facts: { network_id: NETWORK, account: '-1', registrations: { sponsored: true } } }, /not sponsoring new accounts now/],
    [{ facts: { network_id: NETWORK, account: '07', registrations: { sponsored: true } } }, /not sponsoring new accounts now/],
    [{ facts: null }, /does not answer/],
    [{ down: true }, /does not answer/],
    // Busy (busy.mjs): asked four times, after waits of about 2, 4 and 8 seconds, then said in the wallet's words.
    [{ factsStatus: 503 }, error => error.message === BUSY_REGISTRATION],
    [{ factsStatus: 429 }, error => error.message === BUSY_REGISTRATION],
  ];
  for (const [options, expected] of cases) {
    const { fetch, calls } = service(options); waited.length = 0;
    await assert.rejects(make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, fetch)(), expected, JSON.stringify(options));
    assert.ok(calls.every((c) => (c.method ?? 'GET') === 'GET'), 'a registration was sent');
    if (options.factsStatus) {
      assert.equal(calls.length, 4, 'four questions');
      assert.ok(waited.length === 3 && waited.every((ms, at) => ms >= 2000 * 2 ** at && ms <= 2500 * 2 ** at), `waits ${waited}`);
    }
  }
});

test('a registration answered "busy" is not sent again by itself: the service may have acted, and the wallet goes on from the chain', async () => {
  // A refusal for load by what stands in front (plain text, or the gateway's JSON): the wallet's words, nothing of it read.
  for (const [status, retryAfter, answer] of [[503, '30', { error: 'The gateway is busy. Try again in a few seconds.', code: 'GATEWAY_BUSY', retryAfterSeconds: 30 }], [429, null, 'Too many requests'], [503, null, '']]) {
    const s = service({ status, retryAfter, answer });
    const sponsor = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, s.fetch)();
    const error = await sponsor.ask(body).then(() => assert.fail('taken'), e => e);
    assert.equal(error.message, BUSY_REGISTRATION, `${status} ${retryAfter}`);
    assert.equal(s.calls.filter(c => c.method === 'POST').length, 1, 'sent once');
  }
  // The service's own refusal in its own form (a 503 "the node refused it for now", Retry-After 30, which a browser does
  // not let the page read across origins): sent once, and read as the service's answer, as before.
  const own = service({ status: 503, answer: { error: { code: 'chain_daily_limit', message: 'The daily limit of the faucet account on the chain is used up' }, hash: 'CD'.repeat(32) } });
  const sponsor = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, own.fetch)();
  const error = await sponsor.ask(body).then(() => assert.fail('taken'), e => e);
  assert.deepEqual([error.registrationService, error.serviceCode, own.calls.filter(c => c.method === 'POST').length], [true, 'chain_daily_limit', 1]);
  assert.match(failureNotice(error), /signup service|registration|sponsor/i);
  assert.match(failureNotice(error), /later|tomorrow|24 hours|refill/i);
  assert.doesNotMatch(failureNotice(error), /chain_daily_limit|daily limit of the faucet account on the chain|[a-f\d]{16,}/i);
});

// That such a wallet makes no key and stores no vault is the business of `auth` in app.js, which asks the same
// question before it makes either; this function is what a sign-up that was begun earlier meets when it goes on.
test('a service that names neither a sponsor nor a registration service: the wallet finds no sponsor, asks nobody and says why', async () => {
  const { fetch, calls } = service();
  for (const network of [{ networkId: NETWORK }, { networkId: NETWORK, registrationService: '' }, { networkId: NETWORK, sponsorAccount: 'not a number' }])
    await assert.rejects(make(network, never, check, fetch)(), /names no registration sponsor/);
  assert.equal(calls.length, 0);
});

test('registration handles known limits, pending commitments, malformed replies and connection failures', async () => {
  const sponsorOf = async (options) => { const s = service(options); return { sponsor: await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, s.fetch)(), s }; };
  // A limit of a day: Retry-After in hours, longer than any busy wait (busy.mjs), so the answer is read as the service's.
  let made = await sponsorOf({ status: 429, retryAfter: '50000', answer: { error: { code: 'address_limit', message: 'This address has had its registrations of 24 hours' } } });
  // The service can identify a known condition. Its prose never becomes wallet guidance.
  const refused = (sponsor) => sponsor.ask(body).then(() => assert.fail('the request was taken'), (error) => error);
  let refusal = await refused(made.sponsor);
  assert.equal(refusal.registrationService, true);
  assert.match(failureNotice(refusal), /later|tomorrow|24 hours/i);
  assert.doesNotMatch(failureNotice(refusal), /address_limit|has had its registrations/i);
  // The registration of this key with this commitment waits on the chain: the wallet goes on from proven state.
  made = await sponsorOf({ status: 409, answer: { error: { code: 'already_committed', message: 'A registration of this key is waiting' }, same_commitment: true } });
  assert.deepEqual(await made.sponsor.ask(body), { alreadyCommitted: true });
  // Another commitment for this key: that is not this registration, and is a refusal.
  made = await sponsorOf({ status: 409, answer: { error: { code: 'already_committed', message: 'A registration of this key is waiting' }, same_commitment: false } });
  const otherCommitment = failureNotice(await refused(made.sponsor));
  assert.match(otherCommitment, /earlier request|waiting|pending/i);
  assert.match(otherCommitment, /reopen|open|unlock|resume|later|try again|check|continue/i);
  assert.doesNotMatch(otherCommitment, /already_committed|registration of this key/i);
  // An answer that says "accepted" without a hash is no acceptance.
  made = await sponsorOf({ status: 202, answer: { status: 'submitted' } });
  const unknown = failureNotice(await refused(made.sponsor));
  assert.match(unknown, /later|again|unlock|reopen|check/i);
  assert.doesNotMatch(unknown, /202|status 202|submitted/i);
  made = await sponsorOf({ status: 202, answer: { hash: 'not a hash' } });
  assert.equal((await refused(made.sponsor)).registrationService, true);
  // Length and content of an upstream diagnostic never affect the guidance.
  made = await sponsorOf({ status: 400, answer: { error: { code: 'x', message: 'm'.repeat(5000) } } });
  refusal = await refused(made.sponsor);
  assert.equal(refusal.message.length, 200);
  assert.equal(failureNotice(refusal), unknown);
  // The service went away between the two requests: these are the wallet's own words, and say how to go on.
  const s = service(); const sponsor = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, async (url, options) => { if (String(url).endsWith('/registrations')) throw new TypeError('fetch failed'); return s.fetch(url, options); })();
  refusal = await refused(sponsor);
  assert.notEqual(refusal.registrationService, true);
  assert.match(failureNotice(refusal), /^The registration service could not be reached, or did not answer in time\. Unlock again to go on/);
});
