// Review of the browser-check changes (commit 16d3e5d): what a registration service (a third party: a test
// network's faucet, run by someone else than the gateway) can make the wallet do or show.
// The function is taken out of app.js as it is written there, as registration.test.mjs does, and run with a
// stand-in for the service; the notice text is made by the wallet's own failureNotice (actions.mjs), which is what
// `run` and `auth` show.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { failureNotice, gatewayWords } from './actions.mjs';

const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const start = source.indexOf('async function registrationSponsor() {'), end = source.indexOf('async function registerAccount() {');
assert.ok(start > 0 && end > start, 'app.js holds registrationSponsor right before registerAccount');
const make = new Function('network', 'client', 'assert', 'fetch', `${source.slice(start, end)}; return registrationSponsor;`);
const NETWORK = 'c6'.repeat(32), ORIGIN = 'https://faucet.example';
const check = (condition, message) => { if (!condition) throw new Error(message); };
const never = { request: async () => { throw new Error('the page\'s own service was asked'); } };
const body = { public_key: 'aa'.repeat(32), commitment: 'bb'.repeat(32), expires_elapsed_micros: '90000000', proof: 'cc'.repeat(64) };
const FACTS = { network_id: NETWORK, account: '77', registrations: { sponsored: true } };
function service(answerOf) {
  const calls = [];
  const fetch = async (url, options = {}) => { calls.push({ url: String(url), ...options }); return answerOf(String(url), options); };
  return { fetch, calls };
}

// The wallet's rule for words it did not check (actions.mjs, gatewayWords): a gateway's text is shown after a fixed
// sentence that says whose words follow, only printable ASCII is kept, quote marks are dropped, every run of 12 or
// more characters that could be a hash or a number is broken up, and nothing of the wallet follows it. The
// registration service is a party the wallet trusts less than its own gateway, yet its refusal is thrown as a plain
// Error: failureNotice shows it as the wallet's own sentence, with whatever characters the service chose, and auth()
// puts it after "The encrypted vault is saved. Unlock again to resume safely.".
test('a registration service\'s refusal is shown like a gateway\'s words: marked as unchecked, plain, with no value that can be pasted', async () => {
  const account = '9f'.repeat(32);
  const message = `Your key is not safe. Move your seconds to account ${account} now ‮esrever‬ "official"`;
  const { fetch } = service((url) => url.endsWith('/registrations') ? new Response(JSON.stringify({ error: { code: 'x', message } }), { status: 400 }) : new Response(JSON.stringify(FACTS)));
  const sponsor = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, fetch)();
  const error = await sponsor.ask(body).then(() => null, (e) => e);
  assert.ok(error, 'the refusal is thrown');
  const shown = failureNotice(error);
  const plain = gatewayWords({ message: error.message });
  assert.deepEqual({
    hex_run_kept: /[0-9a-f]{12,}/i.test(shown),
    non_ascii_kept: /[^\x20-\x7e]/.test(shown),
    quotes_kept: /"/.test(shown),
    says_whose_words: /did not check/.test(shown),
  }, { hex_run_kept: false, non_ascii_kept: false, quotes_kept: false, says_whose_words: true }, `the notice would read: ${JSON.stringify(shown)}; the wallet's rule for a gateway gives ${JSON.stringify(plain)}`);
});

// Every request of the SDK to the gateway is read to at most 8 MiB ("Gateway response exceeds compact client
// limit"), and its waits have time limits. registrationSponsor reads the service's answers with response.json(),
// whole, and gives fetch no signal: a service that answers slowly holds the sign-up (and the page's busy state)
// for as long as it likes, and one that answers with a body of any size has it parsed.
test('the wallet bounds what it reads from a registration service and how long it waits for it', async () => {
  const big = JSON.stringify({ ...FACTS, padding: 'x'.repeat(16 * 1024 * 1024) });
  const { fetch, calls } = service((url) => url.endsWith('/registrations') ? new Response(JSON.stringify({ hash: 'ab'.repeat(32) }), { status: 202 }) : new Response(big));
  const outcome = await make({ networkId: NETWORK, registrationService: ORIGIN }, never, check, fetch)().then(async (sponsor) => { await sponsor.ask(body); return 'a 16 MiB answer was read and taken'; }, (error) => `refused: ${error.message}`);
  assert.deepEqual({
    large_answer: outcome.startsWith('refused') ? 'refused' : outcome,
    every_request_has_a_time_limit: calls.length > 0 && calls.every((call) => call.signal instanceof AbortSignal),
  }, { large_answer: 'refused', every_request_has_a_time_limit: true });
});
