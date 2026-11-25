// A service that is busy (time-sdk.js, BUSY): a 429 or a 503 is told by its status before anything of it is read,
// a read waits and asks again by itself (Retry-After held to 1 to 30 seconds, jitter of up to a quarter, at most four
// sends within twenty seconds), requests of one kind wait for the wait that kind was told, the same read joins the one
// that waits, and anything that is not a read is sent again only when its caller says it is the same bytes. The clock
// here is the test's: nothing waits for real time.
import test from 'node:test';
import assert from 'node:assert/strict';
import './time-sdk.js';

const SDK = globalThis.TimeSDK;
const TRUST = { app_version: '4', network_id: 'ab'.repeat(32), chain_id: 'time-test' };

/// A stand-in fetch: `script(url, init, n)` gives each answer as [status, body, headers]. Every send is recorded.
function service(script) {
  const sent = [];
  const fetcher = async (url, init = {}) => {
    sent.push({ url: String(url), method: init.method || 'GET', body: init.body ?? null });
    const [status, body = { ok: true }, headers = {}] = await script(String(url), init, sent.length);
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    let read = false;
    return {
      status, ok: status >= 200 && status < 300, headers: { get: name => headers[name] ?? headers[name.toLowerCase()] ?? null },
      body: { cancel: async () => {} },
      text: async () => { read = true; if (status === 429 || status === 503) throw new Error('the body of a busy answer was read'); return text; },
      get wasRead() { return read; },
    };
  };
  return { fetcher, sent };
}
/// The test's clock: sleeping moves it on at once; `random` gives the values it is handed, then 0.
function clockOf(randoms = []) {
  const slept = [], told = [];
  const clock = { at: 1_000_000, now: () => clock.at, sleep: async ms => { slept.push(ms); clock.at += ms; }, random: () => (randoms.length ? randoms.shift() : 0) };
  return { clock, slept, told };
}
const clientWith = (fetcher, clock, told = []) => SDK.createClient({ gateway: 'https://wallet.example', trust: TRUST, fetcher, timing: clock, onBusy: event => told.push(event) });

test('a 429 or a 503 is busy by its status: nothing of it is read, a plain-text one too, and the error says nothing of the body', async () => {
  for (const [status, body, headers] of [
    [429, 'Too many requests from your address. Wait a few seconds.', { 'Content-Type': 'text/plain' }],
    [503, { error: 'The gateway is busy. Try again in a few seconds.', code: 'GATEWAY_BUSY', retryAfterSeconds: 2 }, { 'Retry-After': '2' }],
    [429, { error: { code: 'too_many_reads', message: 'Slow down' } }, { 'Retry-After': '1' }],
    [503, '<html>Service Unavailable</html>', {}],
  ]) {
    const { fetcher, sent } = service(() => [status, body, headers]), { clock } = clockOf();
    const client = clientWith(fetcher, clock);
    await assert.rejects(client.request('/api/notifications?account=7'), error => {
      assert.ok(SDK.isBusy(error), `${status}: ${error.message}`);
      assert.equal(error.status, status);
      assert.equal(error.message, 'BUSY: the service is busy; ask again later');
      assert.ok(!(error instanceof SyntaxError) && !error.gateway, 'never "an answer could not be read", never the service\'s words');
      return true;
    });
    assert.equal(sent.length, 4, 'a read is sent four times at most');
  }
});

test('a read waits as Retry-After says, held to 1 to 30 seconds, and asks again; without it 2, 4, 8 seconds; jitter only lengthens, by a quarter at most', async () => {
  const answers = (afters) => (url, init, n) => (n <= afters.length ? [429, 'busy', afters[n - 1] === null ? {} : { 'Retry-After': afters[n - 1] }] : [200, { items: [] }]);
  // Retry-After 3, then an answer.
  let { fetcher, sent } = service(answers(['3'])), { clock, slept } = clockOf();
  assert.deepEqual(await clientWith(fetcher, clock).request('/api/notifications?account=7'), { items: [] });
  assert.deepEqual([sent.length, slept], [2, [3000]]);
  // Held: 0 s is 1 s, a date is not whole seconds (the default 2 s); 120 s is 30 s (longer than a read's budget, below).
  assert.equal(SDK.retryAfterMs('120'), 30000);
  for (const [after, wait] of [['15', 15000], ['0', 1000], ['Wed, 25 Nov 2026 10:00:00 GMT', 2000]]) {
    ({ fetcher } = service(answers([after]))); const c = clockOf();
    await clientWith(fetcher, c.clock).request('/api/notifications?account=7');
    assert.deepEqual(c.slept, [wait], after);
  }
  // Without Retry-After: 2, 4, 8 s, then the read gives up after its fourth send.
  ({ fetcher, sent } = service(answers([null, null, null, null]))); ({ clock, slept } = clockOf());
  await assert.rejects(clientWith(fetcher, clock).request('/api/notifications?account=7'), SDK.isBusy);
  assert.deepEqual([sent.length, slept], [4, [2000, 4000, 8000]]);
  // Jitter: random 0.5 adds an eighth, 0.999 almost a quarter; never past 30 s, never below what was asked.
  assert.equal(SDK.busyDelayMs(4000, 1, () => 0.5), 4500);
  assert.equal(SDK.busyDelayMs(4000, 1, () => 0.999), 4999);
  assert.equal(SDK.busyDelayMs(30000, 1, () => 0.999), 30000);
  assert.equal(SDK.busyDelayMs(null, 3, () => 0), 8000);
  assert.equal(SDK.busyDelayMs(null, 9, () => 1), 30000);
  for (let i = 0; i < 200; i++) { const r = Math.random(), wait = SDK.busyDelayMs(2000, 1, () => r); assert.ok(wait >= 2000 && wait <= 2500, String(wait)); }
  assert.deepEqual([SDK.retryAfterMs('5'), SDK.retryAfterMs(' 7 '), SDK.retryAfterMs('-1'), SDK.retryAfterMs('1.5'), SDK.retryAfterMs(null)], [5000, 7000, null, null, null]);
});

test('a read keeps to its budget of twenty seconds: it does not wait past it, and says busy at once when the wait it was told is longer', async () => {
  const { fetcher, sent } = service(() => [429, 'busy', { 'Retry-After': '12' }]), { clock, slept } = clockOf();
  const client = clientWith(fetcher, clock);
  const started = clock.now();
  await assert.rejects(client.request('/api/notifications?account=7'), SDK.isBusy);
  // 12 s, then a second send at 12 s; a third would come after 24 s, past the budget.
  assert.deepEqual([sent.length, slept, clock.now() - started], [2, [12000], 12000]);
  // Asked again at once: 12 s are left of the wait its kind was told, within a new read's budget, so it waits them and
  // sends once; the next wait (12 s) would end past its budget.
  await assert.rejects(client.request('/api/notifications?account=7'), SDK.isBusy);
  assert.equal(sent.length, 3);
  // A wait longer than the budget: no send at all.
  const long = service(() => [429, 'busy', { 'Retry-After': '30' }]), c = clockOf();
  const other = clientWith(long.fetcher, c.clock);
  await assert.rejects(other.request('/api/notifications?account=7'), SDK.isBusy);
  assert.equal(long.sent.length, 1, 'told 30 s, past the budget: it does not wait');
  await assert.rejects(other.request('/api/notifications?account=8'), error => SDK.isBusy(error) && error.retryAfterMs > 20000);
  assert.equal(long.sent.length, 1, 'another read of that kind does not go out while the wait runs');
});

test('no stacking: the same read asked again while it waits joins it, and another read of its kind waits for the same wait', async () => {
  let refuse = 1;
  const { fetcher, sent } = service((url) => (refuse-- > 0 ? [503, 'busy', { 'Retry-After': '4' }] : [200, { items: [url.slice(-1)] }]));
  const { clock, slept } = clockOf();
  const client = clientWith(fetcher, clock);
  const first = client.request('/api/notifications?account=7'), again = client.request('/api/notifications?account=7');
  const [a, b] = await Promise.all([first, again]);
  assert.deepEqual([a, b], [{ items: ['7'] }, { items: ['7'] }]);
  assert.notEqual(a, b, 'each caller has its own copy');
  assert.equal(sent.length, 2, 'one line: one refused send and one that was answered');
  // A read of the same kind with another question, while a wait runs: it sends nothing before the wait is over. The
  // sleeps here are held until the test lets them go.
  const held = [], times = [];
  const manual = { at: 0, now: () => manual.at, random: () => 0, sleep: ms => new Promise(resolve => held.push({ ms, resolve })) };
  let firstAnswer = true;
  const timed = service(() => { times.push(manual.at); if (firstAnswer) { firstAnswer = false; return [429, 'busy', { 'Retry-After': '5' }]; } return [200, { items: [] }]; });
  const c2 = clientWith(timed.fetcher, manual);
  const one = c2.request('/api/notifications?account=1');
  for (let i = 0; i < 50 && !held.length; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(held.length, 1, 'the first read waits');
  const two = c2.request('/api/notifications?account=2');
  for (let i = 0; i < 50 && held.length < 2; i++) await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual([held.length, timed.sent.length], [2, 1], 'the second waits too, and sent nothing');
  manual.at += 5000; for (const sleep of held.splice(0)) sleep.resolve();
  await Promise.all([one, two]);
  assert.deepEqual(times, [0, 5000, 5000]);
  assert.ok(slept.length >= 1);
});

test('a request that is not a read is not sent again unless its caller says it is the same bytes; the reads of its kind wait all the same', async () => {
  const told = [], { clock, slept } = clockOf();
  let n = 0;
  const { fetcher, sent } = service(() => (n++ < 2 ? [429, 'busy', { 'Retry-After': '2' }] : [200, { hash: 'AB'.repeat(32) }]));
  const client = clientWith(fetcher, clock, told);
  await assert.rejects(client.request('/api/regtest-bid', { method: 'POST', body: '{"a":1}' }), SDK.isBusy);
  assert.equal(sent.length, 1, 'a POST is sent once');
  // The same bytes, said so: sent again after the wait, the same body each time.
  const result = await client.request('/api/submit', { method: 'POST', body: '{"tx":"AAAA"}' }, { again: true, budgetMs: 30000, tries: 10 });
  assert.deepEqual(result, { hash: 'AB'.repeat(32) });
  assert.deepEqual(sent.slice(1).map(s => [s.method, s.body]), [['POST', '{"tx":"AAAA"}'], ['POST', '{"tx":"AAAA"}']]);
  assert.deepEqual(slept, [2000]);
  // The hook was told when the kind was busy, and when it answered again.
  assert.deepEqual(told.map(e => [e.kind, e.busy]), [['/api/regtest-bid', true], ['/api/submit', true], ['/api/submit', true], ['/api/submit', false]]);
});

test('busyAnswer reads the status and Retry-After of any answer, for the requests a wallet makes itself', () => {
  const answer = (status, after) => ({ status, headers: { get: () => after } });
  assert.equal(SDK.busyAnswer(answer(200, null)), null);
  assert.equal(SDK.busyAnswer(answer(404, '5')), null);
  const busy = SDK.busyAnswer(answer(429, '5'));
  assert.deepEqual([SDK.isBusy(busy), busy.status, busy.retryAfterMs], [true, 429, 5000]);
  assert.deepEqual([SDK.busyAnswer(answer(503, null)).retryAfterMs, SDK.isBusy(new Error('BUSY: x')), SDK.isBusy({ busy: true })], [null, false, false]);
  assert.deepEqual(SDK.BUSY, { tries: 4, budgetMs: 20000, submitBudgetMs: 30000, protectiveBudgetMs: 120000, submitTries: 10, minMs: 1000, maxMs: 30000, firstMs: 2000, jitter: 0.25 });
});
