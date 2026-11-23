// Who the wallet asks to sponsor the registration of a new account (app.js, registrationSponsor).
// The function is taken out of app.js as it is written there and run with stand-ins for the
// page's own service and for the registration service. The whole path, in a real browser against
// a real faucet, runs in the browser check of a campaign (campaign/README.md).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { failureNotice, REGISTRATION_WORDS_INTRO, sponsorReceiptBinds } from './actions.mjs';

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
const make = new Function('network', 'client', 'assert', 'fetch', `${source.slice(start, end)}; return registrationSponsor;`);
const NETWORK = 'c6'.repeat(32), ORIGIN = 'https://faucet.example';
const check = (condition, message) => { if (!condition) throw new Error(message); };
const body = { public_key: 'aa'.repeat(32), commitment: 'bb'.repeat(32), expires_elapsed_micros: '90000000', proof: 'cc'.repeat(64) };

/// A registration service that answers `facts` and, to a registration, `answer` with `status`.
function service({ facts = { network_id: NETWORK, account: '77', registrations: { sponsored: true } }, factsStatus = 200, status = 202, answer = { hash: 'AB'.repeat(32), status: 'submitted' }, down = false } = {}) {
  const calls = [];
  const fetch = async (url, options = {}) => {
    calls.push({ url: String(url), ...options });
    if (down) throw new TypeError('fetch failed');
    if (String(url) === `${ORIGIN}/v1/faucet`) return new Response(JSON.stringify(facts), { status: factsStatus });
    if (String(url) === `${ORIGIN}/v1/faucet/registrations`) return new Response(JSON.stringify(answer), { status });
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
    [{ factsStatus: 503 }, /does not answer/],
    [{ down: true }, /does not answer/],
  ];
  for (const [options, expected] of cases) {
    const { fetch, calls } = service(options);
    await assert.rejects(make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, fetch)(), expected, JSON.stringify(options));
    assert.ok(calls.every((c) => (c.method ?? 'GET') === 'GET'), 'a registration was sent');
  }
});

// That such a wallet makes no key and stores no vault is the business of `auth` in app.js, which asks the same
// question before it makes either; this function is what a sign-up that was begun earlier meets when it goes on.
test('a service that names neither a sponsor nor a registration service: the wallet finds no sponsor, asks nobody and says why', async () => {
  const { fetch, calls } = service();
  for (const network of [{ networkId: NETWORK }, { networkId: NETWORK, registrationService: '' }, { networkId: NETWORK, sponsorAccount: 'not a number' }])
    await assert.rejects(make(network, never, check, fetch)(), /names no registration sponsor/);
  assert.equal(calls.length, 0);
});

test('what the registration service answers to the request: a refusal in its words, the same commitment already waiting, or no answer', async () => {
  const sponsorOf = async (options) => { const s = service(options); return { sponsor: await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, s.fetch)(), s }; };
  let made = await sponsorOf({ status: 429, answer: { error: { code: 'address_limit', message: 'This address has had its registrations of 24 hours' } } });
  // A refusal is the service's own text. It is marked, and the notice shows it after the wallet's sentence that
  // says whose words follow (actions.mjs, failureNotice), never as a sentence of the wallet.
  const refused = (sponsor) => sponsor.ask(body).then(() => assert.fail('the request was taken'), (error) => error);
  let refusal = await refused(made.sponsor);
  assert.equal(refusal.registrationService, true);
  assert.equal(failureNotice(refusal), `${REGISTRATION_WORDS_INTRO}This address has had its registrations of 24 hours`);
  // The registration of this key with this commitment waits on the chain: the wallet goes on from proven state.
  made = await sponsorOf({ status: 409, answer: { error: { code: 'already_committed', message: 'A registration of this key is waiting' }, same_commitment: true } });
  assert.deepEqual(await made.sponsor.ask(body), { alreadyCommitted: true });
  // Another commitment for this key: that is not this registration, and is a refusal.
  made = await sponsorOf({ status: 409, answer: { error: { code: 'already_committed', message: 'A registration of this key is waiting' }, same_commitment: false } });
  assert.equal(failureNotice(await refused(made.sponsor)), `${REGISTRATION_WORDS_INTRO}A registration of this key is waiting`);
  // An answer that says "accepted" without a hash is no acceptance.
  made = await sponsorOf({ status: 202, answer: { status: 'submitted' } });
  assert.equal(failureNotice(await refused(made.sponsor)), `${REGISTRATION_WORDS_INTRO}status 202`);
  made = await sponsorOf({ status: 202, answer: { hash: 'not a hash' } });
  assert.equal((await refused(made.sponsor)).registrationService, true);
  // A long message of the service is cut, in what is thrown and in what is shown.
  made = await sponsorOf({ status: 400, answer: { error: { code: 'x', message: 'm'.repeat(5000) } } });
  refusal = await refused(made.sponsor);
  assert.equal(refusal.message.length, 200);
  assert.equal(failureNotice(refusal).length, REGISTRATION_WORDS_INTRO.length + 160);
  // The service went away between the two requests: these are the wallet's own words, and say how to go on.
  const s = service(); const sponsor = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, async (url, options) => { if (String(url).endsWith('/registrations')) throw new TypeError('fetch failed'); return s.fetch(url, options); })();
  refusal = await refused(sponsor);
  assert.notEqual(refusal.registrationService, true);
  assert.match(failureNotice(refusal), /^The registration service could not be reached, or did not answer in time\. Unlock again to go on/);
});
