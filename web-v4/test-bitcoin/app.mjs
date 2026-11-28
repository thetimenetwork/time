// The test-bitcoin page: pay an address of the test network's private Bitcoin chain, get a receiving address, see
// the chain. Play money. Everything the service answers is shown as text (textContent), never as markup; nothing
// is loaded from anywhere but this server; and the page pays only when the person presses Pay.
//
// Amounts are whole numbers of satoshis as decimal strings, and BigInt where they are counted: never a fraction.
import { addressToScript, scriptForm } from '../shared/bitcoin-address.mjs';

const SATS = /^(0|[1-9][0-9]{0,15})$/;
const ADDRESS = /^[A-Za-z0-9]{14,90}$/;
const FORM_WORDS = Object.freeze({ p2pkh: 'a legacy address', p2sh: 'a script address', p2wpkh: 'a SegWit address', p2wsh: 'a SegWit script address', p2tr: 'a Taproot address' });

// ---------------------------------------------------------------- what can be worked out without a page
/// "12345" -> "12,345". Anything that is not a whole number is given back as it came.
export function grouped(sats) {
  return typeof sats === 'string' && SATS.test(sats) ? sats.replace(/\B(?=(?:[0-9]{3})+$)/g, ',') : String(sats);
}
/// Satoshis as bitcoin, with all eight places: "12345" -> "0.00012345". Null for what is not a whole number of satoshis.
export function btcOfSats(sats) {
  if (typeof sats !== 'string' || !SATS.test(sats)) return null;
  const n = BigInt(sats);
  return `${n / 100000000n}.${String(n % 100000000n).padStart(8, '0')}`;
}
/// The satoshis of an amount in bitcoin as a payment link writes one ("0.0001", "1", "0.00012345"): a decimal string,
/// or null for anything else (more than eight places, an exponent, a sign, a comma).
export function satsOfBtc(amount) {
  const match = typeof amount === 'string' ? /^([0-9]{1,8})(?:\.([0-9]{1,8}))?$/.exec(amount) : null;
  if (!match) return null;
  return (BigInt(match[1]) * 100000000n + BigInt((match[2] ?? '').padEnd(8, '0'))).toString();
}
/// What a person put into the pay field: an address, or a whole payment link (`bitcoin:<address>?amount=<BTC>`).
/// Returns `{ address, sats }` (`sats` null when the text names no amount), or `{ error }` in words. The address
/// is only cut out here; whether it is an address of this chain is `checkAddress`.
export function parsePayTarget(text) {
  const given = typeof text === 'string' ? text.trim() : '';
  if (given === '') return { error: 'Enter an address.' };
  if (!/^bitcoin:/i.test(given)) return ADDRESS.test(given) ? { address: given, sats: null } : { error: 'This is not an address: an address is letters and digits only, without spaces.' };
  const rest = given.slice('bitcoin:'.length), at = rest.indexOf('?');
  const address = at < 0 ? rest : rest.slice(0, at);
  if (!ADDRESS.test(address)) return { error: 'This payment link holds no address.' };
  let sats = null;
  if (at >= 0) {
    const seen = new Set();
    for (const part of rest.slice(at + 1).split('&')) {
      if (part === '') continue;
      const equals = part.indexOf('=');
      let name, value;
      try { name = decodeURIComponent(equals < 0 ? part : part.slice(0, equals)); value = decodeURIComponent(equals < 0 ? '' : part.slice(equals + 1)); } catch { return { error: 'This payment link is not written correctly.' }; }
      if (seen.has(name)) return { error: `This payment link says "${name.slice(0, 20)}" twice.` };
      seen.add(name);
      // A link may say that it cannot be paid without something this page does not know (BIP 21: "req-").
      if (/^req-/i.test(name)) return { error: 'This payment link asks for something this page does not know.' };
      if (name === 'amount') {
        sats = satsOfBtc(value);
        if (sats === null) return { error: 'The amount of this payment link is not a number of bitcoin with at most eight places.' };
      }
    }
  }
  return { address, sats };
}
/// The address and the amount named in the page's own address (`?address=…&sats=…`), each only in the form the
/// page takes; '' for what is missing or not in that form. They fill the form: the page pays nothing by itself.
export function prefillFromAddress(search) {
  let params;
  try { params = new URLSearchParams(search); } catch { return { address: '', sats: '' }; }
  const address = params.get('address') ?? '', sats = params.get('sats') ?? '';
  return { address: ADDRESS.test(address) ? address : '', sats: /^[1-9][0-9]{0,15}$/.test(sats) ? sats : '' };
}
/// Whether a text is an address of the test chain, by the codec the market uses: `{ ok: true, form, words }`, or
/// `{ ok: false, words }` with the reason.
export async function checkAddress(address) {
  try {
    const form = scriptForm(await addressToScript(address, 'regtest'));
    return { ok: true, form, words: `This is ${FORM_WORDS[form]} of this test chain.` };
  } catch (error) {
    return { ok: false, words: String(error?.message ?? 'This is not an address of this test chain.').slice(0, 300) };
  }
}
/// What is wrong with an amount, in words, or '' when it can be paid. `status` is what the service last said of
/// itself (null when it has not answered).
export function amountProblem(sats, status) {
  if (sats === '') return 'Enter an amount.';
  if (!SATS.test(sats) || sats === '0') return 'An amount is a whole number of satoshis, from 1, in digits only.';
  if (status && SATS.test(String(status.max_payment_sats)) && BigInt(sats) > BigInt(status.max_payment_sats)) return `One payment is at most ${grouped(status.max_payment_sats)} satoshis.`;
  if (status && SATS.test(String(status.left_today_for_caller_sats)) && BigInt(sats) > BigInt(status.left_today_for_caller_sats)) return `You can be paid ${grouped(status.left_today_for_caller_sats)} satoshis more today.`;
  return '';
}
/// What the page says about an answer of POST v1/payments.
export function describePayment(status, body) {
  if (status === 200 && body && typeof body.txid === 'string' && /^[0-9a-f]{64}$/.test(body.txid)) {
    const seconds = Number.isInteger(body.seconds_to_next_block) ? body.seconds_to_next_block : null;
    return { ok: true, title: 'Sent', txid: body.txid, text: `${grouped(String(body.sats))} satoshis (${btcOfSats(String(body.sats)) ?? '?'} BTC) of play bitcoin to ${body.address}.${seconds === null ? '' : ` It will be in a block within about ${Math.max(1, seconds)} seconds.`}` };
  }
  const message = body && body.error && typeof body.error.message === 'string' ? body.error.message : `The service answered ${status}.`;
  return { ok: false, title: 'Not sent', txid: null, text: message };
}
/// The line under a payment while its confirmations come.
export function progressWords(answer, stopped = '') {
  if (!answer || !Number.isInteger(answer.confirmations)) return 'Looking for it…';
  if (answer.confirmations === 0) return `Not in a block yet. The next block comes in about ${Math.max(1, Number.isInteger(answer.seconds_to_next_block) ? answer.seconds_to_next_block : 1)} seconds.${stopped}`;
  const count = `${answer.confirmations} ${answer.confirmations === 1 ? 'confirmation' : 'confirmations'}`;
  return `In block ${answer.height}: ${count}${answer.confirmations >= 6 ? '. That is as many as this page counts.' : `.${stopped}`}`;
}
/// What an address has received, in words, from an answer of GET v1/addresses/{address}.
export function receivedWords(answer) {
  if (!answer || !SATS.test(String(answer.received_sats))) return 'Not looked at yet.';
  const count = Array.isArray(answer.payments) ? answer.payments.filter((payment) => payment && payment.height !== null).length : 0;
  const waiting = SATS.test(String(answer.unconfirmed_sats)) && answer.unconfirmed_sats !== '0' ? ` ${grouped(answer.unconfirmed_sats)} more wait for the next block.` : '';
  if (answer.received_sats === '0') return `Nothing in a block yet.${waiting}`;
  return `Received ${grouped(answer.received_sats)} satoshis (${btcOfSats(answer.received_sats)} BTC) in ${count >= 50 ? 'more than 50 payments' : count === 1 ? '1 payment' : `${count} payments`}.${waiting}`;
}
/// How long to wait before asking again, from a Retry-After header: its whole seconds, from 1 to 5.
export function waitSeconds(header) {
  const seconds = typeof header === 'string' && /^[0-9]{1,6}$/.test(header) ? Number(header) : 1;
  return Math.min(5, Math.max(1, seconds));
}
/// The list of addresses as it is kept in the browser: what `text` holds, if it is such a list; else nothing.
export function readKept(text) {
  let list;
  try { list = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(list)) return [];
  return list.filter((entry) => entry && typeof entry.address === 'string' && ADDRESS.test(entry.address) && (entry.form === 'p2wpkh' || entry.form === 'p2tr')).slice(0, 50).map((entry) => ({ address: entry.address, form: entry.form }));
}

// ---------------------------------------------------------------- the page
const KEY = 'time-test-bitcoin:addresses';
const $ = (id) => document.getElementById(id);
const node = (tag, className, text) => { const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = text; return element; };

function page() {
  let status = null, statusAt = 0, statusTimer = null, watching = null;
  let kept = [], storageWorks = true;
  const seen = new Map();
  // Requests go to this page's own server, under the path the page is served at.
  const routeOf = (route) => new URL(`v1/${route}`, document.baseURI).href;
  async function ask(route, body) {
    for (let tries = 0; ; tries++) {
      const response = await fetch(routeOf(route), { method: body === undefined ? 'GET' : 'POST', cache: 'no-store', credentials: 'omit', ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }) });
      let answer = null;
      try { answer = await response.json(); } catch { answer = null; }
      // The service counts requests per caller. A question (never a payment or a new address) that came too soon
      // is asked again after the wait the service names, twice at most.
      if (body === undefined && response.status === 429 && tries < 2 && answer && answer.error && answer.error.code === 'rate_limited') {
        await new Promise((resolve) => { setTimeout(resolve, waitSeconds(response.headers.get('Retry-After')) * 1000); });
        continue;
      }
      return { status: response.status, body: answer };
    }
  }
  const note = (id, words, bad = false) => { const element = $(id); element.textContent = words; element.classList.toggle('bad', bad); };

  // ---- the chain
  const secondsLeft = () => (status ? Math.max(0, status.seconds_to_next_block - Math.floor((Date.now() - statusAt) / 1000)) : null);
  function showChain() {
    if (!status) return;
    $('fact-height').textContent = grouped(String(status.height));
    $('fact-pace').textContent = `A block every ${status.block_seconds} seconds`;
    const left = secondsLeft();
    $('fact-next').textContent = left > 0 ? `In about ${left} ${left === 1 ? 'second' : 'seconds'}` : 'Any moment now';
    $('fact-max').textContent = `${grouped(String(status.max_payment_sats))} satoshis (${btcOfSats(String(status.max_payment_sats)) ?? '?'} BTC)`;
    $('fact-left').textContent = `${grouped(String(status.left_today_for_caller_sats))} satoshis`;
    $('chain-facts').hidden = false;
    $('chain-status').textContent = status.paying === false ? 'The service is not paying right now. The chain is shown as it was last seen.' : 'The chain is running.';
  }
  async function loadStatus() {
    clearTimeout(statusTimer);
    const before = status ? status.height : null;
    try {
      const answer = await ask('status');
      if (answer.status !== 200 || !answer.body || !Number.isInteger(answer.body.height) || !Number.isInteger(answer.body.seconds_to_next_block) || !Number.isInteger(answer.body.block_seconds)) throw new Error('unavailable');
      status = answer.body; statusAt = Date.now();
      showChain(); checkAmount();
      // A new block: what arrived at the addresses may have changed.
      if (before !== null && before !== status.height) refreshAll();
    } catch { $('chain-status').textContent = status ? 'The service could not be asked just now. The chain is shown as it was last seen.' : 'The service could not be asked. Try again shortly.'; }
    // Again a moment after the next block is due, and at least every thirty seconds.
    const wait = status ? Math.min(30, Math.max(3, (secondsLeft() ?? 0) + 2)) : 10;
    statusTimer = setTimeout(loadStatus, wait * 1000);
  }

  // ---- pay an address
  let checked = { text: null, result: null };
  async function checkTarget() {
    const field = $('target'), parsed = parsePayTarget(field.value);
    if (field.value.trim() === '') { note('target-note', ''); return null; }
    if (parsed.error) { note('target-note', parsed.error, true); return null; }
    // A whole payment link is taken apart: the address stays in this field, its amount goes to the other.
    if (parsed.address !== field.value.trim()) { field.value = parsed.address; if (parsed.sats !== null) { $('sats').value = parsed.sats; checkAmount(); } }
    if (checked.text !== parsed.address) checked = { text: parsed.address, result: await checkAddress(parsed.address) };
    if (field.value.trim() !== parsed.address) return null;
    note('target-note', checked.result.words, !checked.result.ok);
    return checked.result.ok ? parsed.address : null;
  }
  function checkAmount() {
    const sats = $('sats').value.trim(), btc = btcOfSats(sats);
    $('sats-btc').textContent = `= ${btc ?? '0.00000000'} BTC`;
    const problem = sats === '' ? '' : amountProblem(sats, status);
    note('sats-note', problem, problem !== '');
    return problem === '' && sats !== '' ? sats : null;
  }
  function showResult(result) {
    $('result').hidden = false;
    $('result').className = result.ok ? 'result good' : 'result bad';
    $('result-title').textContent = result.title;
    $('result-text').textContent = result.text;
    $('result-txid-line').hidden = !result.txid;
    $('result-txid').textContent = result.txid || '';
    $('result-progress').hidden = !result.txid;
    $('result-progress').textContent = result.txid ? 'Not in a block yet.' : '';
  }
  /// Follows one payment until it has six confirmations, or for five minutes.
  function watch(txid) {
    if (watching) clearTimeout(watching.timer);
    const mine = { txid, until: Date.now() + 5 * 60 * 1000, timer: null };
    watching = mine;
    const look = async () => {
      if (watching !== mine) return;
      let answer = null;
      try { const got = await ask(`payments/${txid}`); if (got.status === 200) answer = got.body; } catch { answer = null; }
      if (watching !== mine) return;
      const over = Date.now() >= mine.until, done = answer && answer.confirmations >= 6;
      if (answer) $('result-progress').textContent = progressWords(answer, over && !done ? ' This page has stopped looking after five minutes.' : '');
      else if (over) $('result-progress').textContent = 'This page has stopped looking after five minutes. The transaction id above stays valid.';
      if (done || over) { watching = null; return; }
      mine.timer = setTimeout(look, 3000);
    };
    mine.timer = setTimeout(look, 1500);
  }
  async function pay(event) {
    event.preventDefault();
    const button = $('pay-button');
    if (button.disabled) return;
    button.disabled = true;
    try {
      const address = await checkTarget(), sats = checkAmount();
      if ($('target').value.trim() === '') note('target-note', 'Enter an address.', true);
      if ($('sats').value.trim() === '') note('sats-note', 'Enter an amount.', true);
      if (!address || !sats) { ($('target-note').classList.contains('bad') ? $('target') : $('sats')).focus(); return; }
      let answer;
      try { answer = await ask('payments', { address, sats }); } catch {
        showResult({ ok: false, title: 'Not known', text: 'The service could not be reached. It is not known whether the payment was sent: look at the address before you pay again.', txid: null });
        return;
      }
      const result = describePayment(answer.status, answer.body);
      showResult(result);
      if (result.ok) { watch(result.txid); if (kept.some((entry) => entry.address === answer.body.address)) refresh(answer.body.address); }
      loadStatus();
    } finally { button.disabled = false; }
  }

  // ---- receiving addresses
  function keep() {
    try { window.localStorage.setItem(KEY, JSON.stringify(kept)); storageWorks = true; } catch { storageWorks = false; }
    $('storage-note').textContent = storageWorks ? 'The list is kept in this browser only. Forget takes an address off this list; the address itself goes on existing.' : 'This browser does not keep the list: it is gone when the page is closed. Copy the addresses you need.';
  }
  function draw() {
    const list = $('addresses');
    list.replaceChildren(...kept.map((entry) => {
      const item = node('li', 'address'), answer = seen.get(entry.address);
      const text = node('code', 'address-text', entry.address);
      const words = node('p', 'address-words', answer === 'unknown' ? 'The service does not know this address. The test chain may have been started anew since it was made.' : answer === 'failed' ? 'The service could not be asked about this address just now.' : receivedWords(answer ?? null));
      const tools = node('p', 'address-tools');
      const copy = node('button', 'quiet small-button', 'Copy');
      copy.type = 'button'; copy.setAttribute('aria-label', `Copy the address ${entry.address}`);
      copy.addEventListener('click', async () => {
        let copied = false;
        try { await navigator.clipboard.writeText(entry.address); copied = true; } catch { copied = false; }
        if (!copied) { const range = document.createRange(); range.selectNodeContents(text); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); }
        note('receive-note', copied ? 'Copied.' : 'The address is selected: copy it with your keyboard or the menu.');
      });
      const use = node('button', 'quiet small-button', 'Pay it');
      use.type = 'button'; use.setAttribute('aria-label', `Put the address ${entry.address} into the pay form`);
      use.addEventListener('click', () => { $('target').value = entry.address; checkTarget(); $('sats').focus(); });
      const forget = node('button', 'quiet small-button', 'Forget');
      forget.type = 'button'; forget.setAttribute('aria-label', `Forget the address ${entry.address}`);
      forget.addEventListener('click', () => { kept = kept.filter((other) => other.address !== entry.address); seen.delete(entry.address); keep(); draw(); note('receive-note', 'Taken off the list.'); $('new-address').focus(); });
      tools.append(copy, use, forget);
      item.append(text, words, tools);
      return item;
    }));
    $('addresses-empty').hidden = kept.length > 0;
    $('refresh').hidden = kept.length === 0;
  }
  async function refresh(address) {
    try {
      const answer = await ask(`addresses/${address}`);
      seen.set(address, answer.status === 200 && answer.body ? answer.body : answer.status === 404 ? 'unknown' : 'failed');
    } catch { seen.set(address, 'failed'); }
    draw();
  }
  async function refreshAll() { for (const entry of [...kept]) await refresh(entry.address); }
  async function makeAddress(event) {
    event.preventDefault();
    const button = $('new-address');
    if (button.disabled) return;
    if (kept.length >= 50) { note('receive-note', 'This list holds 50 addresses. Forget one before you make another.', true); return; }
    button.disabled = true;
    try {
      const answer = await ask('addresses', { form: $('kind').value });
      const made = answer.status === 200 && answer.body && typeof answer.body.address === 'string' && ADDRESS.test(answer.body.address) ? answer.body : null;
      if (!made) { note('receive-note', answer.body && answer.body.error && typeof answer.body.error.message === 'string' ? answer.body.error.message : `The service answered ${answer.status}.`, true); return; }
      // What the service gave is held to the same codec as an address that was typed.
      if (!(await checkAddress(made.address)).ok) { note('receive-note', 'The service gave something that is not an address of this test chain. Nothing was added.', true); return; }
      kept = [{ address: made.address, form: made.form === 'p2tr' ? 'p2tr' : 'p2wpkh' }, ...kept.filter((entry) => entry.address !== made.address)];
      keep(); draw();
      note('receive-note', 'A new address is at the top of the list.');
      refresh(made.address);
    } catch { note('receive-note', 'The service could not be reached. Try again shortly.', true); } finally { button.disabled = false; }
  }

  // ---- start
  try { kept = readKept(window.localStorage.getItem(KEY) ?? '[]'); } catch { kept = []; storageWorks = false; }
  if (!storageWorks) $('storage-note').textContent = 'This browser does not keep the list: it is gone when the page is closed. Copy the addresses you need.';
  const named = prefillFromAddress(window.location.search);
  if (named.address) $('target').value = named.address;
  if (named.sats) $('sats').value = named.sats;
  $('pay').addEventListener('submit', pay);
  $('target').addEventListener('change', checkTarget);
  $('target').addEventListener('paste', () => setTimeout(checkTarget, 0));
  $('sats').addEventListener('input', checkAmount);
  $('receive').addEventListener('submit', makeAddress);
  $('refresh').addEventListener('click', async () => { $('refresh').disabled = true; try { await refreshAll(); note('receive-note', 'Looked again.'); } finally { $('refresh').disabled = false; } });
  setInterval(showChain, 1000);
  draw(); checkAmount();
  if (named.address) checkTarget();
  loadStatus();
  refreshAll();
}

if (typeof document !== 'undefined') page();
