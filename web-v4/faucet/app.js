// The faucet page: one field, one button. Everything the service answers is shown as text
// (textContent), never as markup, and nothing is loaded from anywhere but this server.
const $ = (id) => document.getElementById(id);
const MICROS = 1000000n;
// An account as this page takes it: its number, or its name with or without the @.
const ACCOUNT = /^@?[a-z0-9_]{1,20}$/;

/// The account named in the page's address (`?account=alice`, as a link from the wallet or the main page may carry it),
/// lower-cased, if it passes the page's own rule; '' otherwise. A name is public: nothing secret travels this way.
export function accountFromAddress(search) {
  let value = null;
  try { value = new URLSearchParams(search).get('account'); } catch { return ''; }
  if (typeof value !== 'string') return '';
  value = value.trim().toLowerCase();
  return ACCOUNT.test(value) ? value : '';
}

/// "5000000" -> "5 seconds (5000000 microseconds)". Anything that is not a whole number is shown as it came.
export function seconds(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return String(value);
  const amount = BigInt(value), whole = amount / MICROS, rest = (amount % MICROS).toString().padStart(6, '0').replace(/0+$/, '');
  return `${whole}${rest ? `.${rest}` : ''} ${amount === MICROS ? 'second' : 'seconds'} (${amount} microseconds)`;
}
/// What the page says about an answer of POST /v1/faucet/grants.
export function describe(status, body) {
  if (status === 202 && body && typeof body.hash === 'string') {
    return { ok: true, title: body.status === 'submitted' ? 'Sent' : 'Recorded', hash: body.hash,
      text: `${seconds(body.amount_micros)} of test time for account ${body.account}. ${typeof body.note === 'string' ? body.note : ''}` };
  }
  const message = body && body.error && typeof body.error.message === 'string' ? body.error.message : `The faucet answered ${status}`;
  const previous = body && Array.isArray(body.previous) && body.previous[0] && typeof body.previous[0].hash === 'string' ? body.previous[0] : null;
  // A refusal of the node comes with the hash of the action that was sent: it can still be looked up.
  const sent = body && typeof body.hash === 'string' && /^[0-9A-F]{64}$/.test(body.hash) ? body.hash : null;
  return { ok: false, title: sent ? 'Refused by the node' : 'Not sent', text: previous ? `${message} The last one: ${previous.status}, ${previous.created_at}.` : message, hash: previous ? previous.hash : sent };
}
function show(result) {
  $('result').hidden = false;
  $('result').className = result.ok ? 'result good' : 'result bad';
  $('result-title').textContent = result.title;
  $('result-text').textContent = result.text;
  $('result-hash-line').hidden = !result.hash;
  $('result-hash').textContent = result.hash || '';
}
async function loadFacts() {
  try {
    const response = await fetch('/v1/faucet', { cache: 'no-store', credentials: 'omit' });
    const body = await response.json();
    if (!response.ok || !body.gives) throw new Error('unavailable');
    $('fact-grant').textContent = seconds(body.gives.grant_micros);
    $('fact-account').textContent = String(body.gives.per_account);
    $('fact-address').textContent = String(body.gives.per_address);
    $('fact-left').textContent = `${seconds(body.left.total_micros)}, about ${body.left.grants} grants`;
    $('fact-rich').textContent = seconds(body.gives.not_to_accounts_holding_more_than_micros);
    $('fact-network').textContent = `${body.chain_id} (${String(body.network_id).slice(0, 16)}…), test network`;
    $('facts').hidden = false;
    $('registration-note').hidden = !(body.registrations && body.registrations.sponsored === true);
    $('status').textContent = body.giving ? 'The faucet is giving.' : `The faucet is not giving right now (${(body.reasons || []).join(', ')}).`;
  } catch { $('status').textContent = 'The faucet could not be asked. Try again shortly.'; }
}
async function ask(event) {
  event.preventDefault();
  const button = $('send'), account = $('account').value.trim().toLowerCase();
  if (!ACCOUNT.test(account)) { show({ ok: false, title: 'Not sent', text: 'An account is its number, or its name of 2 to 15 lower-case letters, digits and underscores.', hash: null }); return; }
  button.disabled = true;
  try {
    const response = await fetch('/v1/faucet/grants', { method: 'POST', cache: 'no-store', credentials: 'omit', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ account }) });
    let body = null;
    try { body = await response.json(); } catch { body = null; }
    show(describe(response.status, body));
  } catch { show({ ok: false, title: 'Not sent', text: 'The faucet could not be reached. If you ask again and it was sent after all, the faucet will say so.', hash: null }); } finally { button.disabled = false; loadFacts(); }
}
if (typeof document !== 'undefined') {
  const named = accountFromAddress(window.location.search);
  if (named) $('account').value = named;
  $('ask').addEventListener('submit', ask);
  loadFacts();
}
