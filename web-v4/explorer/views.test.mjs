// The explorer's pages (views.mjs) driven on a fake page with a fake API and a fake checker, in
// the way the wallet's security-review-ui.test.mjs drives the wallet. What this exercises is the
// page logic: what is shown, from which source, in which state, and that nothing from the API
// can become markup, an address or the page's own words. It is not a browser: layout, focus as a
// browser moves it, and the real EventSource are not exercised here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createStrings, STRINGS } from './strings.mjs';
import { createExplorer, STATIC_TEXT } from './views.mjs';
import { ApiFailure } from './client.mjs';
import { CheckFailure } from './check.mjs';
import { SAFE_HREF } from './route.mjs';
import { outsideAddress, readJoin } from './format.mjs';

// ------------------------------------------------------------------ a fake page
class Text { constructor(text) { this.text = String(text); } get textContent() { return this.text; } }
class El {
  constructor(tag, id = '') { Object.assign(this, { tagName: tag, id, children: [], attributes: {}, listeners: {}, className: '', hidden: false, value: '', parent: null }); }
  set textContent(value) { this.children = [new Text(value)]; }
  get textContent() { return this.children.map((child) => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('innerHTML must never be used'); }
  set outerHTML(_) { throw new Error('outerHTML must never be used'); }
  append(...nodes) { for (const node of nodes) { assert(node instanceof El || node instanceof Text, 'only elements and text nodes are appended'); this.children.push(node); } }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
  focus() { this.ownerPage.focused = this; }
  fire(type, event = {}) { for (const listener of this.listeners[type] ?? []) listener({ preventDefault() {}, ...event }); }
}
function page(hash = '#/') {
  const byId = new Map(), state = { focused: null }, listeners = {};
  const make = (tag, id) => { const element = new El(tag, id); element.ownerPage = state; return element; };
  const document = { title: '', getElementById: (id) => { if (!byId.has(id)) byId.set(id, make('div', id)); return byId.get(id); }, createElement: (tag) => make(tag), createTextNode: (text) => new Text(text) };
  const window = { location: { hash }, addEventListener: (type, listener) => { (listeners[type] ??= []).push(listener); } };
  return { document, window, state, $: document.getElementById, go: (next) => { window.location.hash = next; for (const listener of listeners.hashchange ?? []) listener(); } };
}
const all = (node, out = []) => { if (node instanceof El) { out.push(node); for (const child of node.children) all(child, out); } return out; };
/// The text of a part of the page as a reader meets it: elements that start a new line or a new
/// cell are set apart by a space, text inside a sentence runs on.
const INLINE = new Set(['span', 'a', 'code', 'strong', 'bdi']);
const flow = (node) => (node instanceof Text ? node.text : (INLINE.has(node.tagName) ? '' : ' ') + node.children.map(flow).join('') + (INLINE.has(node.tagName) ? '' : ' '));
const textOf = (node) => flow(node).replace(/\s+/g, ' ').trim();
const within = (root, className) => all(root).filter((element) => element.className.split(' ').includes(className));
const buttons = (root, label) => all(root).filter((element) => element.tagName === 'button' && element.textContent === label);
const links = (root) => all(root).filter((element) => element.tagName === 'a').map((element) => element.attributes.href);

// ------------------------------------------------------------------ a fake service
const NETWORK = 'ab'.repeat(32), HASH = 'C3'.repeat(32), HASH2 = 'D4'.repeat(32), REFERENCE = '5e'.repeat(32), KEY = '1f'.repeat(32), KEY2 = '2e'.repeat(32), KEY3 = '3d'.repeat(32);
const NOW = Date.UTC(2026, 10, 17, 12, 0, 0), micros = (ms) => String(ms * 1000), iso = (ms) => new Date(ms).toISOString().replace('Z', '000Z');
const indexNote = () => ({ network_id: NETWORK, chain_id: 'time-devnet-v4-test', start_height: '1', indexed_height: '120', indexed_block_time: iso(NOW - 4000), seconds_behind: 4 });
const fromIndex = (body) => ({ source: 'index', proven: false, ...body, index: indexNote() });
const blockItem = (height, { tx = 0, payments = 0 } = {}) => ({ height: String(height), hash: 'AA'.repeat(32), previous_hash: 'BB'.repeat(32), time: iso(NOW - (120 - height) * 1000 - 4000), time_micros: micros(NOW - (120 - height) * 1000 - 4000), proposer: 'CC'.repeat(20), app_hash: 'DD'.repeat(32), data_hash: 'EE'.repeat(32), tx_count: tx, payment_count: payments, results_checked: true });
const actionItem = (more = {}) => ({ hash: HASH, height: '118', index: 0, time: iso(NOW - 6000), kind: 10, kind_name: 'merchant_payment', opaque: false, sender: '7', nonce: '42', recipient: '5', amount: '7503250000', reference: REFERENCE, transfers: true, fee_rule: 'network_fee', fee_micros: '1000', results_checked: true, request_hash: null, request_status: null, unattributed: false, ...more });
const ACCOUNT = { id: '7', name: 'payer', balance: '85000000', nonce: '42', auth_epoch: '3', public_key: KEY, devices: [{ public_key: KEY, can_manage: false, can_spend: false }, { public_key: KEY2, can_manage: false, can_spend: true }, { public_key: KEY3, can_manage: true, can_spend: false }], delegations: [], unbonding: [] };
const GENESIS = micros(NOW - 3 * 3600 * 1000 - 4000);
const SECURITY = { account: '7', version: '2', policy: { threshold: '2', daily_limit_micros: '60000000', delay_seconds: '86400', freeze_seconds: '604800' }, allowance_micros: '0', allowance_elapsed_micros: '0', frozen_until_elapsed_micros: String(4 * 3600 * 1000000), freezes: '1', next_id: '3',
  pending_payments: [{ id: '2', to: '5', amount: '900000000', ready_elapsed_micros: String(5 * 3600 * 1000000) }], pending_limit: null, pending_root: null };
const provenNote = (query) => ({ source: 'state_proof', checked_by: 'this server, with its own trust anchor', state_height: '121', state_time_micros: micros(NOW - 3000), indexed_height: '120', proof: { query, view_proof: { height: '121', entries: [], light_block: {} } } });
function service() {
  const calls = [];
  const answers = {
    status: () => ({ api: 'v1', network: { network_id: NETWORK, chain_id: 'time-devnet-v4-test', protocol_version: '4', fee_micros: '1000', fee_source: 'state_proof' }, indexer: { start_height: '1', indexed_height: '120', indexed_block_time: iso(NOW - 4000), seconds_behind: 4, running: true, fault: null } }),
    blocks: () => fromIndex({ has_more: true, next_cursor: '71', items: Array.from({ length: 50 }, (_, i) => blockItem(120 - i, i === 2 ? { tx: 1, payments: 1 } : {})) }),
    block: (height) => fromIndex({ block: blockItem(Number(height), { tx: 3, payments: 1 }) }),
    blockActions: (height, { cursor } = {}) => fromIndex(cursor ? { has_more: false, next_cursor: `${height}.2`, items: [actionItem({ hash: HASH2, index: 2, kind: 72, recipient: null, amount: null, reference: null, transfers: false })] }
      : { has_more: true, next_cursor: `${height}.1`, items: [actionItem({ height }), actionItem({ height, hash: 'E5'.repeat(32), index: 1, kind: 3, reference: null, amount: '5' })] }),
    action: () => fromIndex({ action: { ...actionItem(), public_key: KEY2, auth_epoch: '3', payload: { to: '5', amount: '7503250000', reference: REFERENCE }, raw: Buffer.from('signed bytes of the action').toString('base64'), repeated: 1 }, verify: { hash: HASH, height: '118', index: 0, total: '1', root_hash: 'AB'.repeat(32), leaf_hash: 'AAAA', aunts: [] } }),
    account: (asked) => ({ ...provenNote({ ids: ['7'] }), account: { ...structuredClone(ACCOUNT), ...(asked && typeof asked === 'object' && asked.id !== undefined ? { id: asked.id } : {}) }, indexed: fromIndex({ totals: { actions_sent: 42, payments_sent: 12, sent_micros: '3600000000', payments_received: 3, received_micros: '120000000', first_height: '2', last_height: '118' }, note: 'n' }) }),
    accountState: () => ({ ...provenNote({}), account: structuredClone(ACCOUNT), security: structuredClone(SECURITY), recovery_cases: [], stake: { owner: '7', positions: [{ candidate: '0', shares: '5000' }], exits: [] }, validator: null, genesis_time_micros: GENESIS }),
    activity: (id, { cursor } = {}) => fromIndex(cursor ? { account: id, order: 'desc', has_more: false, next_cursor: '90.0', items: [actionItem({ hash: HASH2, height: '90', kind: 3, reference: null })] } : { account: id, order: 'desc', has_more: true, next_cursor: '118.0', items: [actionItem({ role: 'sent' })] }),
    validators: () => ({ ...provenNote({ include_pos: true }), protocol_version: '4', pos: { active: [{ owner: '0', consensus_key: KEY, power: '2' }, { owner: '1', consensus_key: KEY2, power: '1' }], scheduled: [], safety_hold: false, bootstrap_ended: true }, upgrade: null }),
  };
  const api = {};
  for (const name of Object.keys(answers)) api[name] = async (...args) => { calls.push([name, ...args]); return structuredClone(await answers[name](...args)); };
  return { api, answers, calls };
}
/// A checker that "proves" whatever state the test hands it, so that the page can be seen to show
/// the proven state and not the service's own copy.
function fakeChecker({ trust = { networkId: NETWORK, chainId: 'time-devnet-v4-test', genesisTimeMicros: GENESIS, anchorHeight: '100', anchorHash: 'F0'.repeat(32) } } = {}) {
  const checker = {
    stateFailure: null, actionResult: null, actionFailure: null, queries: [], network: null, readsUpgrade: false,
    proven: (body, query) => ({ network_id: NETWORK, height: '121', time_micros: micros(NOW - 3000), protocol_version: '4', genesis: { genesis_time_micros: GENESIS },
      accounts: body.account ? [{ ...body.account, balance: body.account.balance === '85000000' ? '85000000' : '1' }] : [], security: body.security ? [body.security] : [], recovery_cases: body.recovery_cases ?? [],
      stake_owners: query.owners ? { [query.owners[0]]: body.stake ?? null } : {}, candidates: query.candidates ? { [query.candidates[0]]: body.validator ?? null } : {}, pos: body.pos, ...(query.include_upgrade ? { upgrade: body.upgrade } : {}) }),
    async checkState(fetchBody, query) {
      // As the real checker: on a network whose trust data says its nodes report upgrades, every question carries that one too.
      if (checker.reportsUpgrades) query = { ...query, include_upgrade: true };
      checker.queries.push(query);
      if (checker.stateFailure) throw checker.stateFailure;
      // As the real checker: an error answer with a proof is checked like any answer, and whether
      // an account exists comes from what was proved, not from the status. Here an account that
      // the "proof" does not hold counts as proven absent only if the answer was an error.
      let body, error404 = false;
      try { body = await fetchBody(); } catch (error) { if (error instanceof ApiFailure && error.body?.proof) { body = error.body; error404 = true; } else throw new CheckFailure('unavailable', error); }
      const state = checker.proven(body, query), held = (id) => state.accounts.some((account) => account.id === id), named = (name) => state.accounts.find((account) => account.name === name);
      return { body, state, absent: error404 ? (query.ids ?? []).filter((id) => !held(id)) : [], names: Object.fromEntries((query.names ?? []).filter((name) => named(name) || error404).map((name) => [name, named(name)?.id ?? null])), height: '121', timeMicros: micros(NOW - 3000), anchorHeight: '121', networkId: NETWORK };
    },
    async checkAction(hash) { if (checker.actionFailure) throw checker.actionFailure; return { hash, height: '118', index: 0, blockHash: 'AA'.repeat(32), total: '1', mode: 'history', resultsChecked: true, anchorHeight: '121', networkId: NETWORK, rawHex: '00', action: { networkId: NETWORK, kind: 10, from: '7', nonce: '42', authEpoch: '3', publicKey: KEY2, payload: { to: '5', amount: '7503250000', reference: REFERENCE } }, envelope: null, ...checker.actionResult }; },
    async trust() { return trust; },
    expectNetwork(id) { checker.network = id; },
  };
  return checker;
}
function fakeLive() {
  const live = { handlers: {}, started: 0, stopped: 0, current: 'idle', listen(handlers) { live.handlers = handlers; }, start() { live.started += 1; live.set('connecting'); }, stop() { live.stopped += 1; live.current = 'idle'; }, state: () => live.current,
    set(next) { live.current = next; live.handlers.onState?.(next); }, emit(type, data) { live.handlers.onEvent?.({ type, data }); } };
  return live;
}
function fakeTimers() {
  const timers = { timeouts: [], intervals: [], setTimeout: (fn, ms) => { const entry = { fn, ms, cleared: false }; timers.timeouts.push(entry); return entry; }, clearTimeout: (entry) => { if (entry) entry.cleared = true; },
    setInterval: (fn, ms) => { const entry = { fn, ms, cleared: false }; timers.intervals.push(entry); return entry; }, clearInterval: (entry) => { if (entry) entry.cleared = true; } };
  return timers;
}
async function open(hash, setup = () => {}, more = {}) {
  const p = page(hash), s = service(), checker = fakeChecker(), live = fakeLive(), timers = fakeTimers();
  await setup({ ...s, checker, live });
  const explorer = createExplorer({ document: p.document, window: p.window, api: s.api, checker, live, t: createStrings('en'), now: () => NOW, timers, locale: 'en-GB', timeZone: 'Europe/Paris', ...more });
  await explorer.start();
  const view = p.$('view');
  return { ...p, ...s, checker, live, timers, explorer, view, text: () => textOf(view), settle: () => explorer.settled() };
}
const fail = (status, more = {}) => async () => { throw new ApiFailure('http', { status, retryAfter: [429, 503].includes(status) ? 7 : null, ...more }); };

// ------------------------------------------------------------------ the views
test('home: the network, the time issued, the newest blocks and payments, each with its source', async () => {
  const p = await open('#/');
  const text = p.text();
  // Where a figure comes from stands before the figure.
  assert.match(text, /Newest block From the index, not checked by this page\. 120/);
  assert.match(text, /Made From the index, not checked by this page\. 17 Nov 2026, 12:59:56 CET \(just now\)/);
  // The fee is the service's word on the home page, and marked in words in front of the figure.
  assert.match(text, /Fee per action Not checked, the service's word: 0\.001 s/);
  assert.match(text, /Network id As the service names it: abab/);
  // The supply is the time since the start: three hours here.
  assert.match(text, /Time issued since the start The supply equals the time since the network started: .* 3 h Newest blocks From the index, not checked by this page\. block 120/);
  assert.match(text, /Newest payments From the index, not checked by this page\. Payments of the newest 50 blocks.* account 7 paid/);
  assert.equal(within(p.view, 'row').length, 10 + 2, 'ten blocks, and the two payments of the newest fifty blocks');
  assert.match(text, /block 120 · no actions · just now/);
  assert.match(text, /account 7 paid account 5 2 h 5 min 3\.25 s, with reference/);
  // Which network this is stands in the frame, in a box of its own, with the warning.
  assert.equal(textOf(p.$('network-warning')), 'Development network. Nothing shown here is money or has any value.');
  assert.equal(within(p.$('network-name'), 'chain-text').length, 1);
  assert.match(textOf(p.$('trust-body')), /Trusted block block 100 F0F0/);
  // The fake API has no origin of its own: the page was served by the service it reads, and says so.
  assert.match(textOf(p.$('trust-body')), /^This page, the network id and the block it trusts were all supplied by the service you are reading/);
  assert.equal(p.$('index-note').hidden, true);
  assert.equal(p.checker.network, NETWORK);
  // The reader's switches: exact microseconds, and UTC.
  p.$('toggle-exact').fire('click');
  assert.match(p.text(), /account 7 paid account 5 7,503,250,000 µs/);
  assert.equal(p.$('toggle-exact').attributes['aria-pressed'], 'true');
  p.$('toggle-utc').fire('click');
  assert.match(p.text(), /Made From the index, not checked by this page\. 17 Nov 2026, 11:59:56 UTC/);
  p.$('toggle-exact').fire('click');
  assert.match(p.text(), /2 h 5 min 3\.25 s/);
});

test('home follows the stream, says when it drops, and re-reads the lists meanwhile', async () => {
  const p = await open('#/');
  assert.equal(p.live.started, 1);
  p.live.set('live');
  assert.match(p.text(), /Live: new blocks and payments appear by themselves\./);
  p.live.emit('block', { ...p.answers.block(121).block, tx_count: 2 });
  p.live.emit('payment', { hash: HASH2, height: '121', index: 0, time: iso(NOW - 3000), kind: 3, sender: '9', recipient: '7', amount: '1000000', reference: null, transfers: true });
  assert.match(p.text(), /Newest block From the index, not checked by this page\. 121/);
  assert.match(p.text(), /block 121 · 2 actions/);
  assert.match(p.text(), /account 9 paid account 7 1 s\./);
  assert.equal(within(p.view, 'row').length, 10 + 3, 'the list of blocks stays at ten rows');
  // The same event twice, and an event that is not a block, change nothing.
  p.live.emit('block', { ...p.answers.block(121).block, tx_count: 2 });
  p.live.emit('block', { height: '<b>', time_micros: 'x', tx_count: -1 });
  p.live.emit('payment', { hash: 'nope' });
  p.live.emit('payment', { hash: HASH2, height: '121', index: 0, time: iso(NOW - 3000), kind: 3, sender: '9', recipient: '7', amount: '1000000', reference: null, transfers: true });
  assert.equal(within(p.view, 'row').length, 13);
  // The stream drops: the page says so and reads the lists itself until it is back.
  p.live.set('waiting');
  assert.match(p.text(), /Live updates are interrupted\. The page reconnects by itself/);
  const before = p.calls.filter(([name]) => name === 'blocks').length;
  p.timers.intervals.find((entry) => entry.ms === 10000).fn();
  await p.settle();
  assert.equal(p.calls.filter(([name]) => name === 'blocks').length, before + 1);
  p.live.emit('gap', { from_height: '100' });
  await p.settle();
  assert.match(p.text(), /Some updates were missed; the lists were read again\./);
  // Leaving the home page closes the stream and stops the reading.
  p.go('#/validators'); await p.settle();
  assert.equal(p.live.stopped, 1);
  assert.equal(p.timers.intervals.find((entry) => entry.ms === 10000).cleared, true);
});

test('home stays useful when the index is behind, has a fault, or the service does not answer', async () => {
  const behind = await open('#/', ({ answers }) => { const status = answers.status; answers.status = () => { const s = status(); s.indexer.seconds_behind = 900; s.indexer.indexed_block_time = iso(NOW - 900000); s.indexer.fault = { code: 'CHAIN_CONFLICT' }; s.network.fee_micros = null; return s; }; });
  assert.equal(behind.$('index-note').hidden, false);
  // How old the newest indexed block is, is worked out with this device's clock from the block's time, not taken from the service's own count.
  assert.match(textOf(behind.$('index-note')), /fault of its indexer.*The newest block the service has indexed is dated 15 min ago by this device's clock\./);
  const lagging = await open('#/', ({ answers }) => { const status = answers.status; answers.status = () => { const s = status(); s.indexer.seconds_behind = 0; s.indexer.indexed_block_time = iso(NOW - 300000); return s; }; });
  assert.match(textOf(lagging.$('index-note')), /dated 5 min ago by this device's clock/, 'a service that says it is not behind is not believed over the time of its newest block');
  assert.match(behind.text(), /Fee per action not known yet/);
  assert.match(behind.text(), /block 120/);
  // No trust manifest: the supply cannot be worked out, and the page says nothing can be checked.
  const bare = page('#/'), s = service(), checker = fakeChecker({ trust: null });
  const explorer = createExplorer({ document: bare.document, window: bare.window, api: s.api, checker, live: null, t: createStrings('en'), now: () => NOW, timers: fakeTimers() });
  await explorer.start();
  assert.match(textOf(bare.$('view')), /Time issued since the start unknown \(this page has no trust manifest/);
  assert.match(textOf(bare.$('trust-body')), /^This page has no trust manifest: none was installed with it, or it could not be loaded just now/);
  assert.match(textOf(bare.$('view')), /Live updates are off\./);
  // An empty index.
  const empty = await open('#/', ({ answers }) => { answers.blocks = () => fromIndex({ has_more: false, next_cursor: null, items: [] }); });
  assert.match(empty.text(), /The index holds no block yet\./);
  assert.match(empty.text(), /No payment in the newest 50 blocks\./);
  // 429 on the lists, 503 on the status: each part says so, waits as told and tries again by itself.
  const limited = await open('#/', ({ api }) => { api.blocks = fail(429, { code: 'rate_limited', serverMessage: 'Too many requests from this address' }); api.status = fail(503, { code: 'busy' }); });
  assert.match(limited.text(), /The service is limiting how often this address may ask\. .*Trying again in 7 s\./);
  assert.match(limited.text(), /The service cannot answer this right now\./);
  assert.match(textOf(limited.$('index-note')), /The state of the service could not be read|^$/);
  const retry = limited.timers.timeouts.filter((entry) => entry.ms === 7000);
  assert.equal(retry.length, 2);
  Object.assign(limited.api, service().api);
  for (const entry of retry) entry.fn();
  await limited.settle();
  assert.match(limited.text(), /block 120 · no actions/);
  assert.match(limited.text(), /Fee per action Not checked, the service's word: 0\.001 s/);
  // No connection at all.
  const offline = await open('#/', ({ api }) => { for (const name of Object.keys(api)) api[name] = async () => { throw new ApiFailure('network'); }; });
  assert.match(offline.text(), /The service could not be reached\./);
  assert.equal(buttons(offline.view, 'Try again').length, 2);
  // A part gives up retrying by itself after a few rounds; the button stays.
  for (let round = 0; round < 8; round++) { for (const entry of offline.timers.timeouts.splice(0)) if (!entry.cleared) entry.fn(); await offline.settle(); }
  assert.equal(offline.timers.timeouts.length, 0);
  assert.equal(buttons(offline.view, 'Try again').length, 2);
});

test('block: its facts, its actions page by page, and a block that is not there', async () => {
  const p = await open('#/block/118');
  assert.match(p.text(), /^Block 118 From the index \(it has read the chain up to block 120\), not checked by this page\. Height 118 Made 17 Nov 2026, 12:59:54 CET \(6 s ago\) Hash AAAA/);
  assert.match(p.text(), /Actions of this block From the index \(it has read the chain up to block 120\), not checked by this page\. account 7 paid account 5/);
  assert.match(p.text(), /Actions 3 actions Payments among them 1/);
  assert.match(p.text(), /Previous block block 117 Next block block 119/);
  assert.match(p.text(), /From the index \(it has read the chain up to block 120\), not checked by this page\./);
  assert.match(p.text(), /account 7 paid account 5 2 h 5 min 3\.25 s, with reference.*account 7 paid account 5 0\.000005 s\./);
  assert.match(p.text(), /Page 1/);
  assert.equal(buttons(p.view, 'Previous page')[0].attributes['aria-disabled'], 'true');
  buttons(p.view, 'Next page')[0].fire('click'); await p.settle();
  assert.deepEqual(p.calls.filter(([name]) => name === 'blockActions').map(([, height, options]) => [height, options.cursor]), [['118', null], ['118', '118.1']]);
  assert.match(p.text(), /account 7 froze its account.*Page 2/);
  assert.equal(buttons(p.view, 'Next page')[0].attributes['aria-disabled'], 'true');
  buttons(p.view, 'Next page')[0].fire('click'); await p.settle();
  assert.equal(p.calls.filter(([name]) => name === 'blockActions').length, 2, 'a disabled button asks for nothing');
  buttons(p.view, 'Previous page')[0].fire('click'); await p.settle();
  assert.match(p.text(), /Page 1/);
  // Not in the index, an empty block, and the first block (which has no previous one).
  const missing = await open('#/block/999', ({ api }) => { api.block = fail(404, { code: 'not_found' }); });
  assert.match(missing.text(), /The index holds no block 999\. It may not exist yet/);
  assert.equal(buttons(missing.view, 'Try again').length, 0);
  const empty = await open('#/block/1', ({ answers }) => { answers.blockActions = () => fromIndex({ has_more: false, next_cursor: null, items: [] }); });
  assert.match(empty.text(), /This block holds no action\./);
  assert.doesNotMatch(empty.text(), /Previous block/);
});


test('action: plain words, the facts, the raw bytes, and a check that replaces the description by what the checked bytes say', async () => {
  const p = await open(`#/action/${HASH}`);
  assert.match(p.text(), /^Action C3C3.* account 7 paid account 5 2 h 5 min 3\.25 s, with reference/);
  assert.match(p.text(), /In block 118 Position in the block number 1 of 1 Time 17 Nov 2026, 12:59:54 CET \(6 s ago\) Sent by account 7 Sender's action number 42 Kind kind 10 Fee the network fee: 0\.001 s Result succeeded: confirmed by the next block/);
  assert.match(p.text(), /Raw bytes From the index, not checked by this page\. The signed bytes, in hexadecimal 7369676e 65642062.* The content as the service decoded it/);
  // Before the check nothing claims to be checked.
  assert.doesNotMatch(p.text(), /Checked:|checked bytes and the checked block/);
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.settle();
  const result = within(p.view, 'check-result')[0], described = within(p.view, 'described')[0];
  assert.match(textOf(result), /^Checked: this action is in block 118 of the chain\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. The checked bytes and the checked block say what the service said: kind, sender, action number, key, content, block and position are the same\. The description above now comes from the checked bytes\./);
  assert.match(textOf(result), /What this proves These exact bytes are action number 1 of block 118\. Block 118 is part of the chain signed by the validators of this network, followed from the block this page trusts up to block 121\. The next block states that every action of block 118 succeeded\./);
  assert.match(textOf(result), /What it does not prove That the block this page trusts is the right one\. The service you are reading supplied it, together with this page.*Anything else on this page marked "from the index".*a reference does not name its payer\./);
  assert.equal(result.attributes['aria-live'], 'polite');
  // The description above is now built from the checked bytes and block; what only the index says stays marked as that.
  assert.match(textOf(described), /^Checked in your browser\. What follows was read by this page from the checked bytes and the checked block: account 7 paid account 5 2 h 5 min 3\.25 s, with reference .* In block 118 Position in the block number 1 of 1 Sent by account 7 Sender's action number 42 Kind kind 10 Read by this page from the checked bytes and the checked block\. From the index \(it has read the chain up to block 120\), not checked by this page\. Time 17 Nov 2026, 12:59:54 CET \(6 s ago\) Fee the network fee: 0\.001 s Result succeeded: confirmed by the next block/);
  // The bytes shown are now the checked ones (the fake check proved one zero byte), and the content what the page read from them.
  assert.match(p.text(), /Raw bytes Read by this page from the checked bytes and the checked block\. The signed bytes, in hexadecimal 00 The content, as this page read it from the checked bytes \{ "to": "5",/);
  assert.doesNotMatch(p.text(), /7369676e|as the service decoded it/);

  // The service described another payment than the bytes hold: the page says so, and shows what the bytes say.
  const lying = await open(`#/action/${HASH}`, ({ answers }) => { const action = answers.action; answers.action = () => { const a = action(); a.action.amount = '999000000'; a.action.recipient = '9'; a.action.nonce = '7'; a.action.height = '117'; a.action.index = 4; a.action.payload = { to: '9', amount: '999000000', reference: REFERENCE }; return a; }; });
  assert.match(lying.text(), /account 7 paid account 9 16 min 39 s/);
  buttons(lying.view, 'Check it yourself')[0].fire('click'); await lying.settle();
  assert.match(lying.text(), /Warning: what the service said does NOT agree with what was checked\. Differing: block, position in the block, sender's action number, content, recipient, amount\. Believe what was checked\./);
  assert.doesNotMatch(lying.text(), /say what the service said|account 9|16 min 39 s|In block 117|Sender's action number 7/, 'nothing of the contradicted description is left standing');
  assert.match(textOf(within(lying.view, 'described')[0]), /^Checked in your browser\..* account 7 paid account 5 2 h 5 min 3\.25 s.*In block 118 Position in the block number 1 of 1 Sent by account 7 Sender's action number 42/);
  // Only the key, or only the key generation, differs: still said.
  const key = await open(`#/action/${HASH}`, ({ answers }) => { const action = answers.action; answers.action = () => { const a = action(); a.action.public_key = KEY3; a.action.auth_epoch = '9'; return a; }; });
  buttons(key.view, 'Check it yourself')[0].fire('click'); await key.settle();
  assert.match(key.text(), /Differing: key generation of the account, signing key\./);

  // A newest block: the next block does not exist yet, so neither the results nor the position are stated.
  const fresh = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { mode: 'own-block', resultsChecked: false, index: null, total: null }; });
  buttons(fresh.view, 'Check it yourself')[0].fire('click'); await fresh.settle();
  assert.match(textOf(within(fresh.view, 'check-result')[0]), /These exact bytes are in block 118\. Their position in the block is not fixed until the next block exists and is checked\..*The next block, which states the results, does not exist yet/);
  assert.match(textOf(within(fresh.view, 'described')[0]), /Position in the block not fixed yet: the next block/);
  assert.doesNotMatch(fresh.text(), /action number 1 of block 118|number 1 of 1/);

  // Bytes of a kind the SDK does not read (the engine's 23 and 63, and later ones): only their frame is read.
  const frame = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { action: null, envelope: { kind: 23, sender: '7', nonce: '42', authEpoch: '3', publicKey: KEY2 } }; });
  buttons(frame.view, 'Check it yourself')[0].fire('click'); await frame.settle();
  assert.match(textOf(within(frame.view, 'check-result')[0]), /^Checked: this action is in block 118 of the chain\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. Warning: what the service said does NOT agree with what was checked\. Differing: kind\. Believe what was checked\. The service's description of what this action did could not be compared with the checked bytes: this page reads only their frame\. Do not rely on that description\./);
  assert.match(textOf(within(frame.view, 'described')[0]), /^Not confirmed: this page can read only the frame of the checked bytes.* account 7 sent an action of kind 23, which this page cannot put into words\. Read by this page from the checked bytes and the checked block\. The service describes it as: account 7 paid account 5 2 h 5 min 3\.25 s, with reference .* The service's word, not confirmed by the check\. In block 118 .* Kind kind 23/);
  // The frame agrees with the service: nothing differs, and the content is still called unconfirmed.
  const same = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { action: null, envelope: { kind: 10, sender: '7', nonce: '42', authEpoch: '3', publicKey: KEY2 } }; });
  buttons(same.view, 'Check it yourself')[0].fire('click'); await same.settle();
  assert.doesNotMatch(same.text(), /does NOT agree|say what the service said/);
  assert.match(same.text(), /could not be compared with the checked bytes: this page reads only their frame\. Do not rely on that description\./);
  // Bytes that are not even in the frame of an action.
  const blob = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { action: null, envelope: null }; });
  buttons(blob.view, 'Check it yourself')[0].fire('click'); await blob.settle();
  assert.match(textOf(within(blob.view, 'check-result')[0]), /The service's description could not be compared with the checked bytes: this page cannot read them\. Do not rely on that description\./);
  assert.match(textOf(within(blob.view, 'described')[0]), /^Not confirmed: this page cannot read the checked bytes.*The service describes it as: account 7 paid account 5.*The service's word, not confirmed by the check\./);

  // A completed waiting payment: the bytes hold a number; who was paid how much is the index's word, and is said to be.
  const execute = await open(`#/action/${HASH}`, ({ answers, checker }) => {
    const action = answers.action; answers.action = () => { const a = action(); Object.assign(a.action, { kind: 75, reference: null, recipient: '5', amount: '900000000', request_hash: HASH2, payload: { type: 'execute', id: '2' } }); return a; };
    checker.actionResult = { action: { networkId: NETWORK, kind: 75, from: '7', nonce: '42', authEpoch: '3', publicKey: KEY2, payload: { type: 'execute', id: '2' } } };
  });
  // Already before the check, and in every list, the line says whose word the recipient and the amount are.
  assert.match(execute.text(), /account 7 completed a waiting payment: account 5 received 15 min\. Recipient and amount are the index's attribution, unconfirmed: the bytes of this action do not carry them\./);
  buttons(execute.view, 'Check it yourself')[0].fire('click'); await execute.settle();
  assert.match(textOf(within(execute.view, 'check-result')[0]), /The checked bytes confirm what the service said, except what they do not carry: recipient, amount\. Those remain the service's word\./);
  assert.match(textOf(within(execute.view, 'described')[0]), /^Checked in your browser\..*: account 7 completed a waiting payment of its account\. The service says the payment completed here was 15 min to account 5\. The checked bytes hold only the number of the waiting payment, neither a recipient nor an amount: this page cannot confirm either\./);
  assert.doesNotMatch(execute.text(), /say what the service said|account 5 received/);

  // A proof that does not verify, and a check that could not run, read differently.
  for (const [failure, words, role] of [
    [new CheckFailure('refused', 'transaction inclusion is not bound to the signed header'), /The check FAILED\. The proof the service gave does not verify.*Technical detail technical text of the verifier, which may quote the service: transaction inclusion is not bound to the signed header/, 'alert'],
    [new CheckFailure('unavailable', new ApiFailure('http', { status: 503, code: 'state_unavailable' })), /Not checked: the service did not give the proof material\..*text from the service: state_unavailable/, 'status'],
    [new CheckFailure('no_trust'), /Not checked: this page has no trust manifest/, 'status'],
    [new CheckFailure('trust_expired'), /Not checked: the block this page trusts can no longer be used/, 'status'],
    [new CheckFailure('clock', 'STALE_STATE: fresh current authority proof is required'), /Not checked: this device's clock does not fit the time of the chain.*Check the clock of this device, or try again in a moment\./, 'status'],
    [new CheckFailure('behind'), /Not checked: the service answered with an older block than this page has already followed\. Try again in a moment\./, 'status'],
    [new CheckFailure('no_verifier', 'WebAssembly refused'), /Not checked: the verifier could not be loaded or does not run in this browser.*Technical detail technical text from loading the verifier: WebAssembly refused/, 'status'],
    [new CheckFailure('not_kept', null, { offered: true }), /Not checked: this service cannot prove a block that old\. Its node holds no history for the block/, 'status'],
    [new CheckFailure('wrong_network'), /Not checked: this page was installed for another network/, 'status'],
    [new CheckFailure('upgrade_required', 'UPGRADE_REQUIRED: the network runs protocol version 5', { offered: true }), /Not checked: this network runs a newer version of the rules than the verifier of this page implements\. The page needs a newer release/, 'status'],
    [new CheckFailure('too_new'), /Not checked yet: the block is at the edge of the chain and the service's node cannot give its signed header yet/, 'status'],
    [new Error('bug'), /Not checked: the service did not give the proof material/, 'status'],
  ]) {
    const failed = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionFailure = failure; });
    buttons(failed.view, 'Check it yourself')[0].fire('click'); await failed.settle();
    const box = within(failed.view, 'check-result')[0];
    assert.match(textOf(box), words);
    assert.doesNotMatch(textOf(box), /Checked: this action/);
    assert.equal(within(box, 'check')[0].attributes.role, role);
    // The service's description stays as it was: marked as the index's word.
    assert.match(textOf(within(failed.view, 'described')[0]), /^From the index \(it has read the chain up to block 120\), not checked by this page\. account 7 paid account 5 /);
  }
  // How often the same bytes are on the chain is the index's count, and labelled so, before and after a check.
  const repeated = await open(`#/action/${HASH}`, ({ answers }) => { const action = answers.action; answers.action = () => { const a = action(); a.action.repeated = 3; return a; }; });
  assert.match(repeated.text(), /From the index, not checked by this page\. The same bytes appear 3 times on the chain; this is the first\./);
  buttons(repeated.view, 'Check it yourself')[0].fire('click'); await repeated.settle();
  assert.match(repeated.text(), /From the index, not checked by this page\. The same bytes appear 3 times on the chain; this is the first\./);
  // Checked bytes the page could not read: they are shown, and the service's reading of their content stays, called unconfirmed.
  const unread = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { action: null, envelope: null, rawHex: 'c0ffee' }; });
  buttons(unread.view, 'Check it yourself')[0].fire('click'); await unread.settle();
  assert.match(unread.text(), /The signed bytes, in hexadecimal c0ffee The service's word, not confirmed by the check\. The content as the service decoded it \{/);
  // Not in the index.
  const missing = await open(`#/action/${HASH}`, ({ api }) => { api.action = fail(404, { code: 'not_found' }); });
  assert.match(missing.text(), /The index holds no action with this hash\. It may be waiting for a block/);
});

test('action: a waiting payment says whether it completed, was cancelled or still waits', async () => {
  for (const [status, words] of [['waiting', /Nothing was paid by this action\. Status: still waiting\. It has not been paid\./], ['completed', /Status: completed later by another action\. The payment was made\./], ['cancelled', /Status: cancelled\. It was never paid\./], ['dropped', /Status: dropped by a freeze/], ['ended', /cannot tell whether it was paid or cancelled/], ['unknown', /Status: unknown to the index\./]]) {
    const p = await open(`#/action/${HASH}`, ({ answers }) => { const action = answers.action; answers.action = () => { const a = action(); Object.assign(a.action, { kind: 75, transfers: false, reference: null, request_status: status, payload: { type: 'request', to: '5', amount: '7503250000' } }); return a; }; });
    assert.match(p.text(), /account 7 asked to pay account 5 2 h 5 min 3\.25 s, more than its daily limit allows at once\./);
    assert.match(p.text(), words);
  }
});

test('action: a validator\'s upgrade signal is put into words, with the plan it names, in lists and on its own page', async () => {
  // The plan: version 5, to start 30 days after the start of the network (which the page's trust manifest dates).
  const plan = { activate_elapsed_micros: String(30 * 86400 * 1000000), spec: REFERENCE, version: '5' };
  const signal = (payload) => ({ answers }) => { const action = answers.action; answers.action = () => { const a = action(); Object.assign(a.action, { kind: 80, kind_name: 'upgrade_signal', recipient: null, amount: null, reference: null, transfers: false, payload }); return a; }; };
  const p = await open(`#/action/${HASH}`, signal(plan));
  assert.match(p.text(), /^Action C3C3.* account 7 signalled that its validator supports moving the network to version 5 of its rules\./);
  assert.match(p.text(), /Kind kind 80 Fee the network fee: 0\.001 s/);
  // The start as a date (30 days after a start of 17 Nov 2026, 09:59:56 CET) and the hash in full.
  assert.match(p.text(), new RegExp(`More from the action The new rules would start, at the earliest 17 Dec 2026, 09:59:56 CET Rules it supports \\(hash of their specification\\) ${REFERENCE}`));
  assert.doesNotMatch(p.text(), /cannot put into words/);
  // Checked: the description is rebuilt from the checked bytes, and a service that named another hash is contradicted.
  p.checker.actionResult = { action: { networkId: NETWORK, kind: 80, from: '7', nonce: '42', authEpoch: '3', publicKey: KEY2, payload: { ...plan, spec: KEY3 } } };
  buttons(p.view, 'Check it yourself')[0].fire('click'); await p.settle();
  assert.match(textOf(within(p.view, 'check-result')[0]), /Warning: what the service said does NOT agree with what was checked\. Differing: content\. Believe what was checked\./);
  assert.match(textOf(within(p.view, 'described')[0]), new RegExp(`^Checked in your browser\\..* account 7 signalled that its validator supports moving the network to version 5 of its rules\\..*hash of their specification\\) ${KEY3}`));
  assert.doesNotMatch(textOf(within(p.view, 'described')[0]), new RegExp(REFERENCE));
  // A withdrawal, and a list item (which has no content).
  assert.match((await open(`#/action/${HASH}`, signal({}))).text(), /account 7 withdrew its validator's support for a change of the network's rules\./);
  const listed = await open('#/block/118', ({ answers }) => { answers.blockActions = () => fromIndex({ has_more: false, next_cursor: '118.0', items: [actionItem({ kind: 80, kind_name: 'upgrade_signal', recipient: null, amount: null, reference: null, transfers: false })] }); });
  assert.match(listed.text(), /account 7 sent a signal of its validator about a change of the network's rules: support for a plan, or the withdrawal of its support\./);
  // A page without a trust manifest has no start time: the start is said as time since the start of the network.
  const bare = await open(`#/action/${HASH}`, (context) => { signal(plan)(context); context.checker.trust = async () => null; });
  assert.match(bare.text(), /The new rules would start, at the earliest 720 h after the start of the network Rules it supports/);
});

// The web audit of 2026-11-24 (A-5): where the service serves the page, it also serves the trust manifest the page
// checks it against, and "Checked in your browser" said nothing of that beside the verdict (only the footer did).
test('A-5: every verdict of a check says, in one line, the network id it was checked against and to compare it with one from a source you trust', async () => {
  const same = await open('#/account/7');
  assert.match(same.text(), /Checked in your browser against the state of block 121\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. What was checked/);
  assert.equal(within(same.view, 'against').length, 2, 'beside the account and beside its security row');
  // A page hosted apart from the service: the id came with the page, from whoever hosts it.
  const apart = await open('#/account/7', ({ api }) => { api.origin = 'https://api.example'; });
  assert.match(apart.text(), /Checked in your browser against the state of block 121\. Checked against network id abababab…ababab, which came with this page; to be sure, compare it with the id from a source you trust\./);
  assert.doesNotMatch(apart.text(), /this same service supplied/);
  // A page whose check was not made says nothing of the kind.
  const unchecked = await open('#/account/7', ({ checker }) => { checker.stateFailure = new CheckFailure('no_trust'); });
  assert.equal(within(unchecked.view, 'against').length, 0);
});

test('account: figures from the state the browser proved, keys by role, what waits, activity by page', async () => {
  // The service's own copy of the account claims another balance than the proven state holds.
  const p = await open('#/account/7', ({ answers }) => { const account = answers.account; answers.account = () => { const a = account(); a.account.balance = '1000000000000'; return a; }; });
  const text = p.text();
  // That the figures were checked stands before them.
  assert.match(text, /^Account 7 Checked in your browser against the state of block 121\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. What was checked The service sent these figures with a proof\..* Name account name from the chain: @payer Number 7 Balance 0\.000001 s Actions sent so far 42/);
  assert.doesNotMatch(text, /Not checked/);
  assert.doesNotMatch(text, /277 h/, 'the unproven balance is not shown');
  assert.match(text, /Keys sign-in key: 1f1f.* spend key: 2e2e.* recovery key: 3d3d.* These are public keys/);
  assert.match(text, /Checked in your browser against the state of block 121\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. What was checked The service sent these figures with a proof\./);
  // The page asks its own questions of the proof, one request each.
  assert.deepEqual(p.checker.queries, [{ ids: ['7'] }, { ids: ['7'], owners: ['7'], candidates: ['7'], include_security: true }]);
  assert.deepEqual(p.calls.filter(([name]) => name.startsWith('account')).map(([name]) => name), ['account', 'accountState']);
  assert.match(text, /Security and stake Checked in your browser against the state of block 121\..* Frozen yes, until 17 Nov 2026, 13:59:56 CET Daily limit of its spend keys 1 min Waiting time for larger payments and key changes 24 h Waiting on this account A payment of 15 min to account 5, ready 17 Nov 2026, 14:59:56 CET\. Stake 5,000 shares with the validator of account 0\./);
  assert.match(text, /Payments in the index From the index, not checked by this page\. .* the balance above, checked in your browser, is what the account holds\. Paid out 1 h in 12 payments Received 2 min in 3 payments/);
  assert.match(text, /Activity From the index \(it has read the chain up to block 120\), not checked by this page\. account 7 paid account 5 2 h 5 min 3\.25 s.*Page 1/);
  buttons(p.view, 'Next page')[0].fire('click'); await p.settle();
  assert.deepEqual(p.calls.filter(([name]) => name === 'activity').map(([, id, options]) => [id, options.cursor]), [['7', null], ['7', '118.0']]);
  assert.match(p.text(), /Page 2/);
  // By name: the same account, found by the name in the proven state. Until then the name is only what the link says.
  const named = await open('#/account/@payer');
  assert.deepEqual(named.checker.queries[0], { names: ['payer'] });
  assert.match(named.text(), /^Account account name as written in the link, not yet confirmed by the chain: @payer Checked in your browser against the state of block 121\..* Name account name from the chain: @payer Number 7/);
  // An account without security rules, with nothing waiting and no stake.
  const bare = await open('#/account/7', ({ answers }) => { const s = answers.accountState; answers.accountState = () => ({ ...s(), security: null, stake: null }); });
  assert.match(bare.text(), /Frozen no Waiting on this account nothing Stake none This account has not set up separate keys or a daily limit\./);
  // A recovery through its helpers that has its approvals freezes the account, with or without a security row.
  const elapsed = 3 * 3600 * 1000000;
  const recovering = await open('#/account/7', ({ answers }) => { const s = answers.accountState; answers.accountState = () => ({ ...s(), security: null, recovery_cases: [{ target: '7', ready_elapsed_micros: String(elapsed + 60000000), expires_elapsed_micros: String(elapsed + 86400000000) }] }); });
  assert.match(recovering.text(), /Frozen yes: a recovery through its helpers has its approvals, and until it is completed, cancelled or expires the account cannot act Waiting on this account A recovery through its helpers is under way\./);
  // One that has not reached its approvals, or has expired, does not.
  for (const recovery of [{ target: '7', ready_elapsed_micros: null, expires_elapsed_micros: String(elapsed + 86400000000) }, { target: '7', ready_elapsed_micros: '5', expires_elapsed_micros: String(elapsed - 60000000) }, { target: '8', ready_elapsed_micros: '5', expires_elapsed_micros: String(elapsed + 86400000000) }]) {
    const open7 = await open('#/account/7', ({ answers }) => { const s = answers.accountState; answers.accountState = () => ({ ...s(), security: null, recovery_cases: [recovery] }); });
    assert.match(open7.text(), /Frozen no /, JSON.stringify(recovery));
  }
  // A proven state that does not speak of the stake or of the security row says "none" of neither.
  const silent = await open('#/account/7', ({ checker }) => { const proven = checker.proven; checker.proven = (body, query) => { const state = proven(body, query); if (query.owners) { delete state.stake_owners[7]; } return state; }; });
  assert.match(silent.text(), /Stake \(unreadable\)/);
  const noRow = await open('#/account/7', ({ checker }) => { const proven = checker.proven; checker.proven = (body, query) => { const state = proven(body, query); if (query.include_security) delete state.security; return state; }; });
  assert.match(noRow.text(), /Security and stake Not checked, and so not shown: .* The proof the service gave verifies, but it does not speak of what was asked/);
  assert.doesNotMatch(noRow.text(), /Frozen/);
});

test('account: on a network whose waits survive a stop, a freeze and what waits are read on the clock of the waits, their dates at the earliest', async () => {
  // Three hours of chain since genesis, two of them stops: the clock of the waits stands at one hour. The freeze ends
  // at two hours on that clock and the payment is ready at two and a half. On the chain's time both would look past.
  const H = 3600 * 1000000, row = { ...SECURITY, frozen_until_elapsed_micros: String(2 * H), pending_payments: [{ ...SECURITY.pending_payments[0], ready_elapsed_micros: String(2.5 * H) }] };
  const clock = { waits_survive_stops: true, stopped_micros: String(2 * H), now_elapsed_micros: String(H + 1000000) };
  const setup = ({ answers, checker }) => {
    const s = answers.accountState; answers.accountState = () => ({ ...s(), security: structuredClone(row), security_clock: clock });
    const proven = checker.proven; checker.proven = (body, query) => ({ ...proven(body, query), config: { waits_survive_stops: true }, stopped_micros: String(2 * H) });
  };
  const checked = await open('#/account/7', setup);
  // The dates are the stored moments plus the two hours of stops, the earliest they can come.
  assert.match(checked.text(), /Security and stake Checked in your browser against the state of block 121\..* Frozen yes, until 17 Nov 2026, 13:59:56 CET at the earliest .* Waiting on this account A payment of 15 min to account 5, ready 17 Nov 2026, 14:29:56 CET at the earliest\./);
  // The service's word gives the same clock with the row (`security_clock`), and the page reads it the same way.
  const unchecked = await open('#/account/7', (world) => { setup(world); world.checker.stateFailure = new CheckFailure('no_trust'); });
  assert.match(unchecked.text(), /Frozen Not checked, the service's word: yes, until 17 Nov 2026, 13:59:56 CET at the earliest .* A payment of 15 min to account 5, ready 17 Nov 2026, 14:29:56 CET at the earliest\./);
  // A proven state that says the network has the rule and gives no total of stops (or the total without the rule) is
  // not one the engine writes: nothing of the freeze or the waits is shown as if it were known.
  const broken = await open('#/account/7', ({ answers, checker }) => { setup({ answers, checker }); const proven = checker.proven; checker.proven = (body, query) => { const state = proven(body, query); delete state.stopped_micros; return state; }; });
  assert.match(broken.text(), /Frozen \(unreadable\)/);
  assert.doesNotMatch(broken.text(), /CET at the earliest|Frozen no/);
  // With half an hour of stops the clock stands at two and a half hours: the freeze is over, and a moment that has come
  // is a date without "at the earliest".
  const later = await open('#/account/7', ({ answers, checker }) => { setup({ answers, checker }); const proven = checker.proven; checker.proven = (body, query) => ({ ...proven(body, query), stopped_micros: String(0.5 * H) }); });
  assert.match(later.text(), /Frozen no .* A payment of 15 min to account 5, ready 17 Nov 2026, 12:59:56 CET\./);
});


test('account: not found, not checkable, and a proof that fails are different pages, and the status of an answer decides none of them', async () => {
  // The service proves that the account does not exist.
  const absent = await open('#/account/999', ({ api }) => { api.account = async () => { throw new ApiFailure('http', { status: 404, code: 'account_not_found', body: { ...provenNote({ ids: ['999'] }) } }); }; });
  assert.match(absent.text(), /There is no such account\. Checked in your browser: the proof shows that the state of block 121 does not hold it\./);
  const noName = await open('#/account/@nobody', ({ api }) => { api.account = async () => { throw new ApiFailure('http', { status: 404, code: 'account_not_found', body: { ...provenNote({ names: ['nobody'] }) } }); }; });
  assert.match(noName.text(), /There is no such account\. Checked in your browser/);
  // "Not found" as the status, with a proof in which the account exists: the proof is believed, not the status.
  for (const [address, status] of [['#/account/7', 404], ['#/account/@payer', 404], ['#/account/7', 500]]) {
    const lying = await open(address, ({ api }) => { api.account = async () => { throw new ApiFailure('http', { status, code: 'account_not_found', body: { ...provenNote({}), account: structuredClone(ACCOUNT) } }); }; });
    assert.match(lying.text(), /Checked in your browser against the state of block 121\..* Name account name from the chain: @payer Number 7 Balance 1 min 25 s /, address);
    assert.doesNotMatch(lying.text(), /no such account/, address);
  }
  // The proof verifies but says nothing of the account asked for (here: it holds another one): nothing is shown, and nothing is called absent.
  for (const address of ['#/account/8', '#/account/@other']) {
    const other = await open(address, ({ answers }) => { const account = answers.account; answers.account = () => account(); });
    assert.match(other.text(), /Not checked, and so not shown: this page shows nothing of what the service answered here\. The proof the service gave verifies, but it does not speak of what was asked: neither that it exists nor that it does not\./, address);
    assert.doesNotMatch(other.text(), /payer|Balance|no such account/, address);
  }
  // Nothing to check with (no trust manifest, no verifier, an expired trusted block, a clock that does not fit) and no proof looked at:
  // the figures are the service's word, the page says so and why, and it asks the service once.
  for (const [reason, words] of [['no_trust', /this page has no trust manifest/], ['no_verifier', /the verifier could not be loaded/], ['trust_expired', /the block this page trusts can no longer be used/], ['clock', /this device's clock does not fit/]]) {
    const unchecked = await open('#/account/7', ({ checker }) => { checker.stateFailure = new CheckFailure(reason); });
    // That nothing was checked stands before the figures, and in front of every one of them; the name is the service's, not "from the chain".
    assert.match(unchecked.text(), /^Account 7 Not checked\. What follows is the service's word: this page did not check any of it\. Why this was not checked Not checked: /, reason);
    assert.match(unchecked.text(), /Name Not checked, the service's word: account name as the service gives it: @payer Number Not checked, the service's word: 7 Balance Not checked, the service's word: 1 min 25 s Actions sent so far Not checked, the service's word: 42 Keys Not checked, the service's word: sign-in key/, reason);
    assert.match(unchecked.text(), /Security and stake Not checked\. What follows is the service's word.* Frozen Not checked, the service's word: yes, until .* Stake Not checked, the service's word: 5,000 shares/, reason);
    assert.doesNotMatch(unchecked.text(), /account name from the chain|Balance 1 min/, reason);
    assert.equal(within(unchecked.view, 'tag').length, 10, 'five figures of the account and five of its security and stake, each marked');
    assert.match(unchecked.text(), words, reason);
    assert.doesNotMatch(unchecked.text(), /Checked in your browser|is what the account holds|the truth/, reason);
    assert.deepEqual(unchecked.calls.filter(([name]) => name.startsWith('account')).map(([name]) => name), ['account', 'accountState'], reason);
  }
  // The proof does not verify: no figure at all.
  const refused = await open('#/account/7', ({ checker }) => { checker.stateFailure = new CheckFailure('refused', 'invalid state proof', { offered: true }); });
  assert.match(refused.text(), /The check FAILED: the proof the service gave for this does not verify\. The figures are not shown\./);
  assert.doesNotMatch(refused.text(), /Balance|payer|Keys/);
  // A proof was offered and did not pass for any other reason, or the service names another network: no figure either.
  for (const [failure, words] of [[new CheckFailure('clock', 'STALE_STATE: x', { offered: true }), /this device's clock does not fit/], [new CheckFailure('behind', null, { offered: true }), /an older block than this page has already followed/],
    [new CheckFailure('trust_expired', 'x', { offered: true }), /can no longer be used/], [new CheckFailure('wrong_network'), /installed for another network than the service says it answers for/], [new CheckFailure('no_trust', null, { offered: true }), /no trust manifest/]]) {
    const held = await open('#/account/7', ({ checker }) => { checker.stateFailure = failure; });
    assert.match(held.text(), /^Account 7 Not checked, and so not shown: this page shows nothing of what the service answered here\. Not checked: /, failure.reason);
    assert.match(held.text(), words, failure.reason);
    assert.doesNotMatch(held.text(), /Balance|payer|Keys|FAILED/, failure.reason);
    assert.equal(held.calls.filter(([name]) => name === 'account').length, 0, 'the fake checker failed before asking; the page does not ask again by itself');
    // It can be tried again.
    held.checker.stateFailure = null;
    buttons(held.view, 'Try again')[0].fire('click'); await held.settle();
    assert.match(held.text(), /Balance 1 min 25 s/, failure.reason);
  }
  // The service is busy: said as that, with the wait, and tried again.
  const busy = await open('#/account/7', ({ api }) => { api.account = fail(503, { code: 'state_unavailable', serverMessage: 'The current state could not be read with a valid proof' }); });
  assert.match(busy.text(), /The service cannot answer this right now\. What the service said text from the service: state_unavailable text from the service: The current state could not be read with a valid proof Trying again in 7 s\./);
  // Unknown without a proof.
  // "Not found" with no proof at all is the service's word and is said to be, whether or not the page could have checked a proof.
  for (const setup of [({ api, checker }) => { checker.stateFailure = new CheckFailure('no_verifier'); api.account = fail(404, { code: 'account_not_found' }); }, ({ api }) => { api.account = fail(404, { code: 'account_not_found' }); }]) {
    for (const address of ['#/account/7', '#/account/@payer']) {
      const missing = await open(address, setup);
      assert.match(missing.text(), /The service says there is no such account, and gave no proof of that\. This page could not check it\./, address);
      assert.doesNotMatch(missing.text(), /There is no such account\.|Checked in your browser/, address);
    }
  }
  // Nothing to check with, and an account whose number the service garbles: no figure, and no word of a proof (none was looked at).
  const garbled = await open('#/account/@payer', ({ answers, checker }) => { checker.stateFailure = new CheckFailure('no_trust'); const account = answers.account; answers.account = () => { const a = account(); a.account.id = 7; return a; }; });
  assert.match(garbled.text(), /Not checked\. What follows is the service's word.* The service's answer about this account is not in a form this page can read\. Nothing of it is shown\./);
  assert.doesNotMatch(garbled.text(), /proof the service gave|Balance/);
  // The security part fails by itself; the rest of the account stays.
  const half = await open('#/account/7', ({ api }) => { api.accountState = fail(429, { code: 'rate_limited' }); });
  assert.match(half.text(), /Balance 1 min 25 s.*Security and stake The service is limiting how often this address may ask\..*Activity From the index .* account 7 paid/);
});


test('validators: who validates with what share, announced changes, and an upgrade only when the proof was asked about it', async () => {
  const p = await open('#/validators');
  assert.match(p.text(), /Validators in force at block 121, largest first Account Share of the votes Votes Validator key account 0 66\.66 % 2 1f1f.* account 1 33\.33 % 1 2e2e/);
  assert.match(p.text(), /Who validates now Checked in your browser against the state of block 121\..* Validators in force at block 121.* 2 validators, 3 votes in all\./);
  assert.doesNotMatch(p.text(), /Not checked/);
  assert.match(p.text(), /No change of the validator set is announced\./);
  // The page's trust data does not say that this network's nodes report upgrades: nothing is asked about them and nothing denied.
  assert.deepEqual(p.checker.queries, [{ include_pos: true }]);
  assert.match(p.text(), /Scheduled upgrade This page does not read upgrade plans on this network: its trust manifest does not say that the network's nodes report them, so the page does not ask\. Whether an upgrade of the rules is scheduled is not shown here\. Run a validator Anyone can run/);
  assert.doesNotMatch(p.text(), /No upgrade/);
  assert.equal(p.$('nav-validators').attributes['aria-current'], 'page');
  // The service's own word about an upgrade is not repeated either.
  const told = await open('#/validators', ({ answers }) => { const v = answers.validators; answers.validators = () => ({ ...v(), upgrade: null }); });
  assert.match(told.text(), /This page does not read upgrade plans on this network/);
  // On a network whose trust data says so, the checker asks with every read, and the page reads the proven answer (TimeSDK.upgradeStatusOf, passed on by check.mjs).
  const aware = (checker) => { checker.reportsUpgrades = true; checker.upgradeStatus = (state) => { if (!Object.hasOwn(state, 'upgrade') || state.upgrade === undefined) throw new Error('This state was verified without the upgrade entry'); return { version: '4', scheduled: state.upgrade?.plan ?? null, known: true }; }; };
  const none = await open('#/validators', ({ answers, checker }) => { aware(checker); const v = answers.validators; answers.validators = () => ({ ...v(), upgrade: null }); });
  assert.deepEqual(none.checker.queries, [{ include_pos: true, include_upgrade: true }]);
  assert.match(none.text(), /Scheduled upgrade Checked in your browser against the state of block 121\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. No upgrade of the rules is scheduled: the proof shows that the state holds no plan\. Run a validator Anyone can run/);
  const planned = await open('#/validators', ({ answers, checker }) => { aware(checker); const v = answers.validators; answers.validators = () => ({ ...v(), pos: { ...v().pos, scheduled: [{}, {}], safety_hold: true }, upgrade: { plan: { version: '5', activate_elapsed_micros: String(30 * 3600 * 1000000), scheduled_elapsed_micros: '1', spec: '9a'.repeat(32) }, signals: [] } }); });
  assert.match(planned.text(), /A changed validator set is announced for 2 coming blocks\. A safety hold is on/);
  assert.match(planned.text(), /Scheduled upgrade Checked in your browser against the state of block 121\. Checked against network id abababab…ababab, which this same service supplied; to be sure, compare it with the id from a source you trust\. An upgrade is scheduled\. To version 5 Starts 18 Nov 2026, 15:59:56 CET Rules it switches to \(hash\) 9a9a/);
  // The proven state has no answer about the row although it was asked (or a row in an unknown form): not "none".
  const unread = await open('#/validators', ({ answers, checker }) => { aware(checker); checker.upgradeStatus = () => { throw new Error('Unsupported upgrade row'); }; const v = answers.validators; answers.validators = () => ({ ...v(), upgrade: { odd: '1' } }); });
  assert.match(unread.text(), /The upgrade row of the state is in a form this page does not know\. Whether an upgrade is scheduled is not shown\./);
  assert.doesNotMatch(unread.text(), /No upgrade/);
  // Not checked at all: nothing is said about upgrades.
  const unchecked = await open('#/validators', ({ answers, checker }) => { aware(checker); checker.stateFailure = new CheckFailure('no_trust'); const v = answers.validators; answers.validators = () => ({ ...v(), upgrade: null }); });
  assert.match(unchecked.text(), /Who validates now Not checked\. What follows is the service's word: this page did not check any of it\..* account 0 Not checked, the service's word: 66\.66 % .* Not checked, the service's word: 2 validators, 3 votes in all\..* Not checked, the service's word: No change of the validator set is announced\..*This page does not read upgrade plans on this network/);
  const noRow = await open('#/validators', ({ answers }) => { const v = answers.validators; answers.validators = () => ({ ...v(), pos: null }); });
  assert.match(noRow.text(), /The state of this network has no staking row to read validators from\./);
  const refused = await open('#/validators', ({ checker }) => { checker.stateFailure = new CheckFailure('refused', 'bad', { offered: true }); });
  assert.match(refused.text(), /The check FAILED/);
  assert.doesNotMatch(refused.text(), /66\.66/);
});

// ------------------------------------------------------------------ run a validator (join.json)
const JOIN = { script_url: 'https://join.example/join/join.sh', wallet_url: 'https://wallet.example', chain_id: 'time-devnet-v4-test', min_self_bond_micros: '1000000',
  files: { node_sha256: 'a1'.repeat(32), cometbft_sha256: 'b2'.repeat(32), genesis_sha256: 'c3'.repeat(32) }, peers: [`${'0f'.repeat(20)}@203.0.113.7:26656`], pace: '500ms' };
const COMMANDS = 'curl -fsSLO https://join.example/join/join.sh\nless join.sh\nsudo bash join.sh --account YOUR_ACCOUNT_NUMBER';
/// The section "Run a validator": a part of its own, after the validators and their parts.
const joinPart = (p) => all(p.view).find((element) => element.tagName === 'section' && element.children[0]?.tagName === 'h2' && element.children[0].textContent === 'Run a validator');
const GENERAL = /^Run a validator Anyone can run a validator on this network\. A validator is a computer that stays online, checks every block and signs it\. For each block it signs it is paid new seconds, in proportion to its votes\. How it works Two keys\. Your node makes a validator key, which stays on that machine and signs blocks\..* A bond\. Your account registers the validator's key on the chain and locks a bond with it, at least the network's minimum\. The bond is what you lose if your validator signs two different blocks at the same height\. Votes\. .* Who decides\. .* What you need A Linux computer or server that stays on: .* An account on this network that holds a little more than the bond\. If the account is protected, its daily limit must also have the bond and the fee left on the day you register\. Steps Create an account in the wallet\. Its account number is on the wallet's Home screen\. On the server, download the script, read it, then run it with your account number\. Whoever runs this network gives you the script for it\. This page was not set up with one\. The script prints a registration text\. In the wallet, open More, then Validator operator, paste the text and confirm\. If your account is protected, type its payment password there as well\. The bond is taken from your balance, and on a protected account it counts, with the fee, against the daily limit\. .* about half an hour for each day the network has run\. The script shows how far it is\. What the script does It downloads .* sudo bash join\.sh --status shows what the node is doing\. sudo bash join\.sh --uninstall removes the services and programs and keeps the key\. Take care Keep a copy of the validator key file \(\/var\/lib\/time-validator\/node\/config\/priv_validator_key\.json\) somewhere safe\. .* These instructions are part of this page, as it was installed for this network\. The page does not check the script: read it before you run it\.$/;
const UNREADABLE = 'This network\'s own instructions could not be read. What follows is the general explanation.';
/// What must hold of the section whatever join.json held: elements of the page's own kinds only, every link either
/// one of the explorer's own or one of the two outside addresses with rel="noopener noreferrer", no text of the file
/// in an attribute, and nothing of the file shown at all when it did not pass.
function assertJoinHarmless(p, text, context) {
  for (const element of all(p.view)) {
    for (const [name, value] of Object.entries(element.attributes)) {
      assert(/^(href|rel|id|role|scope|type|tabindex|aria-[a-z]+)$/.test(name), `${context}: attribute ${name}`);
      assert(!value.includes(MARK) && !value.includes('<'), `${context}: attribute ${name} = ${value}`);
    }
    const href = element.attributes.href;
    if (href !== undefined && !SAFE_HREF.test(href)) assert.deepEqual([element.tagName, outsideAddress(href) !== null, element.attributes.rel], ['a', true, 'noopener noreferrer'], `${context}: href ${href}`);
    if (element.attributes.rel !== undefined) assert(href !== undefined && outsideAddress(href) !== null, `${context}: rel without an outside link`);
    assert(!['img', 'script', 'iframe', 'style', 'object'].includes(element.tagName), `${context}: element ${element.tagName}`);
  }
  assert(!textOf(p.view).includes(MARK), `${context}: text of the file on the page`);
  if (readJoin(text) === null) {
    const join = joinPart(p);
    assert(textOf(join).startsWith(`Run a validator ${UNREADABLE} Anyone can run`), context);
    assert.match(textOf(join).replace(` ${UNREADABLE}`, ''), GENERAL, context);
    assert.deepEqual([links(join), all(join).filter((element) => element.tagName === 'pre').length], [[], 0], context);
  }
}

test('run a validator, without join.json: the general explanation after the validators, no commands, no outside link, no mark of "not checked"', async () => {
  let calls = 0;
  for (const more of [{}, { loadJoin: async () => { calls += 1; return null; } }]) {
    const p = await open('#/validators', () => {}, more), join = joinPart(p);
    assert(join, 'the section is there');
    // After the parts of the validators, which are as before.
    assert.match(p.text(), /2 validators, 3 votes in all\. .* Scheduled upgrade This page does not read upgrade plans .* Run a validator Anyone can run a validator/);
    assert.match(textOf(join), GENERAL);
    assert.doesNotMatch(textOf(join), /could not be read|curl|This network's files|faucet|Not checked/);
    assert.deepEqual([links(join), all(join).filter((element) => element.tagName === 'pre').length, within(join, 'tag').length], [[], 0, 0]);
    // Its own headings, in order.
    assert.deepEqual(all(join).filter((element) => element.tagName === 'h3').map((element) => element.textContent), ['How it works', 'What you need', 'Steps', 'What the script does', 'Take care']);
  }
  // None installed is remembered: the file is not asked for again at the next view.
  const p = await open('#/validators', () => {}, { loadJoin: async () => { calls += 1; return null; } });
  p.go('#/'); await p.settle(); p.go('#/validators'); await p.settle();
  assert.equal(calls, 2, 'once for the first page, once for this one');
});

test('run a validator, with this network\'s join.json: the three command lines, the two outside links, the network\'s files', async () => {
  let calls = 0;
  const p = await open('#/validators', () => {}, { loadJoin: async () => { calls += 1; return JSON.stringify(JOIN); } });
  const join = joinPart(p), text = textOf(join);
  assert.match(text, /^Run a validator Anyone can run a validator on this network\./);
  // The bond with the page's own formatter for amounts of seconds, and with the switch to microseconds.
  assert.match(text, /A bond\. Your account registers the validator's key on the chain and locks a bond with it: at least 1 s on this network\. The bond is what you lose/);
  assert.match(text, /An account on this network that holds a little more than the bond\. If the account is protected, its daily limit must also have the bond and the fee left on the day you register\. The faucet's test time is enough\. Steps Create an account in the wallet\. Its account number is on the wallet's Home screen\. On the server, download the script, read it, then run it with your account number: curl/);
  // The commands: one block, made as text, with exactly these three lines.
  const blocks = all(join).filter((element) => element.tagName === 'pre');
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].textContent, COMMANDS);
  assert.deepEqual([blocks[0].children.length, blocks[0].children[0] instanceof El, blocks[0].attributes['aria-label']], [1, false, 'Commands to type on the server']);
  // The two outside links: plain links, made from the checked addresses, that give the page they open nothing.
  assert.deepEqual(all(join).filter((element) => element.tagName === 'a').map((element) => [element.textContent, element.attributes.href, element.attributes.rel]),
    [['the wallet', 'https://wallet.example', 'noopener noreferrer'], ['https://join.example/join/join.sh', 'https://join.example/join/join.sh', 'noopener noreferrer']]);
  // The network's files as the page shows other facts, the hashes in its hexadecimal form.
  assert.match(text, new RegExp(`This network's files The script https://join\\.example/join/join\\.sh Chain time-devnet-v4-test Node program, SHA-256 ${'a1'.repeat(32)} CometBFT, SHA-256 of the archive ${'b2'.repeat(32)} Genesis file, SHA-256 ${'c3'.repeat(32)} Entry node ${'0f'.repeat(20)}@203\\.0\\.113\\.7:26656 Take care`));
  assert.equal(within(join, 'hex').length, 3);
  assert.equal(within(join, 'facts').length, 1);
  // Installed text: not the page's check and not the service's word, and said to be that at the end.
  assert.doesNotMatch(text, /could not be read|Whoever runs this network|at least the network's minimum|Not checked|Checked in your browser/);
  assert.equal(within(join, 'tag').length, 0);
  assert.match(text, /These instructions are part of this page, as it was installed for this network\. The page does not check the script: read it before you run it\.$/);
  assertJoinHarmless(p, JSON.stringify(JOIN), 'the example');
  p.$('toggle-exact').fire('click');
  assert.match(textOf(joinPart(p)), /at least 1,000,000 µs on this network/);
  // Read once: another view and back asks nothing again.
  p.go('#/'); await p.settle(); p.go('#/validators'); await p.settle();
  assert.equal(calls, 1);
  assert.equal(all(joinPart(p)).filter((element) => element.tagName === 'pre')[0].textContent, COMMANDS);
  // Several entry nodes are listed one under the other; no pace is needed.
  const { pace, ...unpaced } = JOIN;
  const many = await open('#/validators', () => {}, { loadJoin: async () => JSON.stringify({ ...unpaced, peers: [JOIN.peers[0], `${'1e'.repeat(20)}@198.51.100.20:26656`] }) });
  assert.match(textOf(joinPart(many)), new RegExp(`Entry nodes ${'0f'.repeat(20)}@203\\.0\\.113\\.7:26656 ${'1e'.repeat(20)}@198\\.51\\.100\\.20:26656 Take care`));
  assert.equal(pace, '500ms');
});

test('run a validator: a join.json that does not pass its checks shows the general explanation, says so, and makes no link', async () => {
  const join = (change) => JSON.stringify({ ...JOIN, ...change });
  const files = (change) => join({ files: { ...JOIN.files, ...change } });
  const { chain_id: _, ...withoutChain } = JOIN;
  const cases = {
    'http: script': join({ script_url: 'http://join.example/join/join.sh' }), 'http: wallet': join({ wallet_url: 'http://wallet.example' }),
    'another file name': join({ script_url: 'https://join.example/join/other.sh' }), 'another path': join({ script_url: 'https://join.example/x/join/join.sh' }), 'no path': join({ script_url: 'https://join.example' }),
    'a query': join({ script_url: 'https://join.example/join/join.sh?x=1' }), 'a fragment': join({ script_url: 'https://join.example/join/join.sh#x' }), 'an empty query': join({ script_url: 'https://join.example/join/join.sh?' }),
    'wallet with a path': join({ wallet_url: 'https://wallet.example/app' }), 'wallet with a slash': join({ wallet_url: 'https://wallet.example/' }), 'wallet that is the script': join({ wallet_url: JOIN.script_url }), 'script that is an origin': join({ script_url: JOIN.wallet_url }),
    'credentials': join({ script_url: 'https://user:secret@join.example/join/join.sh' }), 'user name': join({ wallet_url: 'https://user@wallet.example' }),
    'javascript: script': join({ script_url: 'javascript:alert(1)//https://join.example/join/join.sh' }), 'javascript: wallet': join({ wallet_url: 'javascript:alert(1)' }), 'data: address': join({ wallet_url: 'data:text/html,<script>alert(1)</script>' }),
    'no scheme': join({ script_url: '//join.example/join/join.sh' }), 'upper case host': join({ script_url: 'https://Join.example/join/join.sh' }), 'number host': join({ script_url: 'https://127.0.0.1/join/join.sh' }), 'hex number host': join({ wallet_url: 'https://0x7f.1' }),
    'port 443 written out': join({ wallet_url: 'https://wallet.example:443' }), 'port 0': join({ wallet_url: 'https://wallet.example:0' }), 'port too large': join({ wallet_url: 'https://wallet.example:70000' }), 'space before': join({ script_url: ' https://join.example/join/join.sh' }), 'backslash': join({ script_url: 'https:\\\\join.example\\join\\join.sh' }),
    'hash too short': files({ node_sha256: 'a1'.repeat(31) }), 'hash too long': files({ genesis_sha256: 'c3'.repeat(33) }), 'hash in upper case': files({ cometbft_sha256: 'B2'.repeat(32) }), 'hash missing': join({ files: { node_sha256: 'a1'.repeat(32), cometbft_sha256: 'b2'.repeat(32) } }), 'another file': files({ wallet_sha256: 'd4'.repeat(32) }),
    'a peer with a host name': join({ peers: [`${'0f'.repeat(20)}@node.example:26656`] }), 'a peer with a short id': join({ peers: [`${'0f'.repeat(19)}@203.0.113.7:26656`] }), 'a peer with a leading zero': join({ peers: [`${'0f'.repeat(20)}@203.0.113.07:26656`] }), 'a peer without port': join({ peers: [`${'0f'.repeat(20)}@203.0.113.7`] }),
    'no peer': join({ peers: [] }), 'nine peers': join({ peers: Array.from({ length: 9 }, (_, i) => `${'0f'.repeat(20)}@203.0.113.${i + 1}:26656`) }), 'a peer twice': join({ peers: [JOIN.peers[0], JOIN.peers[0]] }), 'peers as text': join({ peers: JOIN.peers[0] }),
    'chain id as markup': join({ chain_id: `<img src=x onerror=alert(1)>${MARK}` }), 'chain id in upper case': join({ chain_id: 'Time-devnet' }), 'chain id too long': join({ chain_id: 'a'.repeat(65) }),
    'bond of zero': join({ min_self_bond_micros: '0' }), 'bond as a number': join({ min_self_bond_micros: 1000000 }), 'bond too large': join({ min_self_bond_micros: '1000000000000001' }), 'bond with a leading zero': join({ min_self_bond_micros: '01000000' }),
    'pace of 50 ms': join({ pace: '50ms' }), 'pace of 6 s': join({ pace: '6s' }), 'pace as a number': join({ pace: 500 }),
    'an extra key': join({ extra: 1 }), 'a key missing': JSON.stringify(withoutChain), 'a prototype key': JSON.stringify(JOIN).replace('{', '{"__proto__":{"x":1},'),
    'a list': '[]', 'a string': '"https://join.example/join/join.sh"', 'null as the content': 'null', 'a number': '42', 'not JSON': '{script_url:', 'empty': '', 'too long': join({ chain_id: 'x'.repeat(20000) }),
  };
  for (const [name, text] of Object.entries(cases)) {
    assert.equal(readJoin(text), null, name);
    const p = await open('#/validators', () => {}, { loadJoin: async () => text });
    const part = joinPart(p);
    assert.equal(all(part).find((element) => element.tagName === 'p' && element.className === 'status')?.textContent, UNREADABLE, name);
    assertJoinHarmless(p, text, name);
    assert.doesNotMatch(textOf(p.view), /onerror|<img|join\.example|wallet\.example|203\.0\.113/, name);
    // The validators are there as before.
    assert.match(p.text(), /Validators in force at block 121, largest first .* 2 validators, 3 votes in all\./, name);
  }
});

test('run a validator: a loader that fails or is slow neither delays nor breaks the validators, and a failure is asked again later', async () => {
  // It fails: the general explanation, the sentence that this network's instructions could not be read, and the table.
  let calls = 0, failing = true;
  const p = await open('#/validators', () => {}, { loadJoin: async () => { calls += 1; if (failing) throw new Error('connection reset'); return JSON.stringify(JOIN); } });
  assert.match(p.text(), /2 validators, 3 votes in all\./);
  assert.match(textOf(joinPart(p)), new RegExp(`^Run a validator ${UNREADABLE.replace(/[.']/g, '\\$&')} Anyone can run`));
  assert.deepEqual([links(joinPart(p)), buttons(p.view, 'Try again').length, p.timers.timeouts.length], [[], 0, 0]);
  // Not kept: the next view asks again, and shows the file once it can be read.
  failing = false;
  p.go('#/'); await p.settle(); p.go('#/validators'); await p.settle();
  assert.equal(calls, 2);
  assert.equal(all(joinPart(p)).filter((element) => element.tagName === 'pre')[0]?.textContent, COMMANDS);
  // A loader that throws at once, without a promise.
  const sync = await open('#/validators', () => {}, { loadJoin: () => { throw new Error('no fetch'); } });
  assert.match(textOf(joinPart(sync)), new RegExp(UNREADABLE.replace(/[.']/g, '\\$&')));
  assert.match(sync.text(), /2 validators, 3 votes in all\./);
  // It is slow: the validators are shown while the section still loads; then the section is filled in.
  let release;
  const slow = page('#/validators'), s = service();
  const explorer = createExplorer({ document: slow.document, window: slow.window, api: s.api, checker: fakeChecker(), live: fakeLive(), t: createStrings('en'), now: () => NOW, timers: fakeTimers(), locale: 'en-GB', timeZone: 'Europe/Paris', loadJoin: () => new Promise((resolve) => { release = resolve; }) });
  const started = explorer.start();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.match(textOf(slow.$('view')), /2 validators, 3 votes in all\..* Run a validator Loading…$/);
  release(JSON.stringify(JOIN)); await started;
  assert.match(textOf(slow.$('view')), /2 validators, 3 votes in all\..* Run a validator Anyone can run.*curl -fsSLO https:\/\/join\.example\/join\/join\.sh/);
});

test('run a validator: no field of join.json, replaced by a hostile value, becomes markup, an attribute or a link of its own', async () => {
  let renders = 0;
  for (const path of leaves(JOIN)) for (const hostile of HOSTILE) {
    const text = JSON.stringify(replaced(JOIN, path, hostile)), context = `join.${path.join('.')} = ${String(JSON.stringify(hostile)).slice(0, 40)}`;
    let p;
    try { p = await open('#/validators', () => {}, { loadJoin: async () => text }); } catch (error) { assert.fail(`${context}: the page threw ${error?.stack}`); }
    assertJoinHarmless(p, text, context);
    renders += 1;
  }
  assert.equal(renders, leaves(JOIN).length * HOSTILE.length);
  assert(renders >= 200, `every field of join.json was replaced (${renders} pages)`);
});

test('the search box, addresses that can be shared, and what an unknown address shows', async () => {
  const p = await open('#/');
  const search = async (value) => { p.$('search-input').value = value; p.$('search-form').fire('submit'); const hash = p.window.location.hash; p.go(hash); await p.settle(); return hash; };
  assert.equal(await search(` ${HASH.toLowerCase()} `), `#/action/${HASH}`);
  assert.match(p.text(), /^Action/);
  assert.equal(await search('@payer'), '#/account/@payer');
  assert.equal(await search('Payer'), '#/account/@payer');
  assert.equal(await search('0'), '#/account/0');
  // A number can be a block or an account: both are looked up.
  assert.equal(await search('118'), '#/find/118');
  assert.match(p.text(), /^Number 118 A block height and an account number look the same\. Both are looked up: Block 118 From the index .* Open block 118, made 6 s ago\. Account 118 Checked in your browser against the state of block 121\..* Open account 118, named account name from the chain: @payer\./);
  assert.deepEqual(p.checker.queries.at(-1), { ids: ['118'] }, 'the account of a number is read through the check, like on its own page');
  // What cannot be anything is said in words, and the page stays where it is.
  for (const [value, words] of [['hello world', /That is not a block height/], ['007', /without leading zeros/], ['9'.repeat(30), /too large/], ['ABCDEF0123456789AB', /exactly 64 characters/], ['<script>alert(1)</script>', /That is not a block height/]]) {
    assert.equal(await search(value), '#/find/118');
    assert.match(textOf(p.$('search-error')), words);
    assert.equal(p.$('search-error').hidden, false);
  }
  assert.equal(await search(''), '#/find/118');
  assert.equal(p.$('search-error').hidden, true);
  // The skip link moves the focus to the content and leaves the address alone.
  let prevented = false;
  p.$('skip-link').fire('click', { preventDefault() { prevented = true; } });
  assert.deepEqual([prevented, p.state.focused, p.window.location.hash], [true, p.$('view'), '#/find/118']);
  // The heading of a new view takes the focus.
  p.go('#/block/5'); await p.settle();
  assert.equal(p.state.focused?.tagName, 'h1');
  // Addresses in any other form show the unknown page; nothing is asked of the service for them.
  for (const address of ['#/nothing', '#/block/0', '#/block/01', '#/action/abc', `#/action/${HASH.toLowerCase()}`, '#/account/@A', '#/account/7/extra', '#/block/5?x=1', '#/%2e%2e/', '#//evil.example', '#/account/javascript:alert(1)']) {
    const calls = p.calls.length;
    p.go(address); await p.settle();
    assert.match(p.text(), /^No such page This address is not a page of the explorer\./, address);
    assert.deepEqual(p.calls.slice(calls).map(([name]) => name).filter((name) => name !== 'status'), [], address);
  }
  // An answer that arrives after the reader moved on is dropped.
  let release;
  p.api.block = () => new Promise((resolve) => { release = () => resolve(p.answers.block(5)); });
  p.go('#/block/5'); p.go('#/validators'); release(); await p.settle();
  assert.match(p.text(), /^Validators/);
});

// ------------------------------------------------------------------ hostile answers
const MARK = 'HOSTILE';
const HOSTILE = [
  `<img src=x onerror=alert(1)>${MARK}`, `"><script>alert(1)</script>${MARK}`, `javascript:alert(1)//${MARK}`, `${MARK}‮gnp.exe\u0000\n\r`, `${MARK} ✔ Checked in your browser: account 7 paid you 100 h`,
  `${MARK}`.padEnd(5000, 'A'), '', '-1', '1e99', '0x10', '007', null, 12, -5, 1.5, NaN, true, {}, [], { toString: () => MARK }, ['7'],
  // Values that have the right form and are still not the page's words.
  'zz_hostile', 'ff'.repeat(32), '18446744073709551615', '99999999999999999999999',
];
/// Every path to a leaf of an answer, so that each field can be replaced on its own.
function leaves(value, path = [], out = []) {
  if (value !== null && typeof value === 'object') { for (const key of Object.keys(value)) leaves(value[key], [...path, key], out); if (Object.keys(value).length === 0) out.push(path); } else out.push(path);
  return out;
}
const replaced = (value, path, hostile) => { const copy = structuredClone(value); let at = copy; for (const key of path.slice(0, -1)) at = at[key]; at[path.at(-1)] = typeof hostile === 'object' && hostile !== null && !Array.isArray(hostile) && hostile.toString !== Object.prototype.toString ? MARK : hostile; return copy; };
/// What must hold on the page whatever the service answered.
function assertHarmless(p, context) {
  for (const root of [p.view, p.$('network-name'), p.$('index-note'), p.$('trust-body'), p.$('search-error')]) {
    for (const element of all(root)) {
      for (const [name, value] of Object.entries(element.attributes)) {
        assert(/^(href|id|role|scope|type|tabindex|aria-[a-z]+)$/.test(name), `${context}: attribute ${name}`);
        if (name === 'href') assert.match(value, SAFE_HREF, `${context}: href ${value}`);
        assert(!value.includes(MARK), `${context}: text from the service in attribute ${name}`);
      }
      assert.match(element.className, /^[a-z0-9 -]*$/, `${context}: class`);
      // Text from the service is only ever inside a box that marks it as quoted.
      for (const child of element.children) {
        if (!(child instanceof Text) || !(child.text.includes(MARK) || child.text.includes('zz_hostile'))) continue;
        let boxed = false;
        for (let at = element; at; at = at.parent) if (at.className.split(' ').includes('chain-text')) boxed = true;
        assert(boxed || insideQuoted(root, element), `${context}: unquoted text ${child.text.slice(0, 60)}`);
      }
    }
    assert.doesNotMatch(root.textContent, /[\u0000-\u0008\u000b-\u001f\u007f‪-‮⁦-⁩​-‏]/, `${context}: control or direction characters`);
  }
}
const insideQuoted = (root, element) => within(root, 'chain-text').some((box) => all(box).includes(element));

test('hostile answers: no field of any answer becomes markup, an address, an attribute or unquoted text', async () => {
  const views = { '#/': ['status', 'blocks', 'blockActions'], '#/block/118': ['block', 'blockActions'], [`#/action/${HASH}`]: ['action'], '#/account/7': ['account', 'accountState', 'activity'], '#/validators': ['validators'], '#/find/118': ['block', 'account'] };
  let renders = 0;
  for (const [address, names] of Object.entries(views)) for (const name of names) {
    const sample = service().answers[name]('118', {});
    for (const path of leaves(sample)) for (const hostile of HOSTILE) {
      const context = `${address} ${name}.${path.join('.')} = ${String(JSON.stringify(hostile)).slice(0, 40)}`;
      let p;
      try {
        p = await open(address, ({ answers, checker }) => {
          const original = answers[name];
          answers[name] = (...args) => replaced(original(...args), path, hostile);
          // The same hostile value also in what the checker "proved", so that proven fields are held to the same rule.
          const proven = checker.proven; checker.proven = (body, query) => proven(body, query);
        });
        if (address.startsWith('#/action')) { buttons(p.view, 'Check it yourself')[0]?.fire('click'); await p.settle(); }
      } catch (error) { assert.fail(`${context}: the page threw ${error?.stack}`); }
      assertHarmless(p, context);
      renders += 1;
    }
  }
  assert(renders > 3000, `every field of every answer was replaced (${renders} pages)`);
});

test('hostile answers: events of the stream, errors of the service, and what the checker returns', async () => {
  const p = await open('#/');
  for (const hostile of HOSTILE) {
    for (const path of leaves(p.answers.block(121).block)) p.live.emit('block', replaced({ ...p.answers.block(121).block, height: '122' }, path, hostile));
    for (const path of leaves(actionItem())) p.live.emit('payment', replaced(actionItem({ hash: HASH2 }), path, hostile));
    p.live.emit('gap', hostile); p.live.emit('block', hostile); p.live.set(hostile);
    await p.settle();
    assertHarmless(p, `stream ${String(hostile).slice(0, 30)}`);
  }
  // An error whose code and message are written by the attacker is shown quoted, cut, and never as the page's words.
  for (const hostile of HOSTILE.filter((value) => typeof value === 'string' && value)) {
    const failed = await open('#/block/118', ({ api }) => { api.block = async () => { throw new ApiFailure('http', { status: 500, code: 'internal', serverMessage: hostile }); }; api.status = async () => { throw new ApiFailure('http', { status: 418, serverMessage: hostile }); }; });
    assertHarmless(failed, 'error message');
    assert.match(failed.text(), /The service answered with an error \(HTTP 500\)\./);
    assert(failed.text().length < 1200, 'a long message is cut');
    // A check that fails with the attacker's text, and a "proven" action full of it.
    const checked = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionFailure = new CheckFailure('refused', hostile); });
    buttons(checked.view, 'Check it yourself')[0].fire('click'); await checked.settle();
    assertHarmless(checked, 'check failure');
    const decoded = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { height: hostile, anchorHeight: hostile, index: hostile, action: { kind: 10, from: hostile, payload: { to: hostile, amount: hostile, reference: hostile } } }; });
    buttons(decoded.view, 'Check it yourself')[0].fire('click'); await decoded.settle();
    assertHarmless(decoded, 'checked action');
    const framed = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionResult = { height: hostile, index: hostile, total: hostile, anchorHeight: hostile, mode: hostile, action: null, envelope: { kind: hostile, sender: hostile, nonce: hostile, authEpoch: hostile, publicKey: hostile } }; });
    buttons(framed.view, 'Check it yourself')[0].fire('click'); await framed.settle();
    assertHarmless(framed, 'checked frame');
    // A proven state is data from the chain too: a name or a key in it is held to the same rule.
    const state = await open('#/account/7', ({ checker }) => { checker.proven = (body) => ({ network_id: NETWORK, height: hostile, time_micros: hostile, genesis: { genesis_time_micros: hostile }, accounts: [{ id: '7', name: hostile, balance: hostile, nonce: hostile, devices: [{ public_key: hostile, can_spend: hostile }, hostile] }], security: [{ account: '7', policy: hostile, frozen_until_elapsed_micros: hostile, pending_payments: [hostile, { to: hostile, amount: hostile }], pending_root: hostile, pending_limit: { daily_limit_micros: hostile } }], recovery_cases: [], stake_owners: { 7: { positions: [{ candidate: hostile, shares: hostile }, hostile], exits: hostile } }, candidates: { 7: { self_bond: hostile } } }); });
    assertHarmless(state, 'proven state');
  }
  // A name that reads like the page's own words is always boxed and always next to the number.
  const named = await open('#/find/118', ({ answers }) => { const account = answers.account; answers.account = (asked) => { const a = account(asked); a.account.name = 'paid_100h_ok'; return a; }; });
  const box = within(named.view, 'chain-text').find((element) => element.textContent.includes('paid_100h_ok'));
  assert.equal(textOf(box), 'account name from the chain: @paid_100h_ok');
  assert.match(named.text(), /Open account 118, named account name from the chain: @paid_100h_ok\./);
  // The same name from a service whose word could not be checked is not called "from the chain".
  const loose = await open('#/find/118', ({ answers, checker }) => { checker.stateFailure = new CheckFailure('no_trust'); const account = answers.account; answers.account = (asked) => { const a = account(asked); a.account.name = 'paid_100h_ok'; return a; }; });
  assert.equal(textOf(within(loose.view, 'chain-text').find((element) => element.textContent.includes('paid_100h_ok'))), 'account name as the service gives it: @paid_100h_ok');
  assert.match(loose.text(), /Not checked, the service's word: Open account 118, named /);
});

// ------------------------------------------------------------------ the page file and the table of strings
test('the page file: no inline script or style, nothing from elsewhere, and every word from the table', async () => {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/i, 'no inline script');
  assert.doesNotMatch(html, /<style|\sstyle=|\son[a-z]+=/i, 'no inline style or handler');
  for (const [, address] of html.matchAll(/\s(?:src|href|action)="([^"]*)"/g)) assert.match(address, /^(?:#[a-z/]*|[a-z][a-z0-9./-]*\.(?:css|js))$/, `only this page's own files: ${address}`);
  assert.match(html, /<meta name="time-api-origin" content="">/);
  // Each fixed part of the page exists once and carries the English words of the table.
  const t = createStrings('en');
  for (const [id, key] of Object.entries(STATIC_TEXT)) {
    const found = [...html.matchAll(new RegExp(`<[a-z0-9]+[^>]*\\sid="${id}"[^>]*>([^<]*)<`, 'g'))];
    assert.equal(found.length, 1, id);
    assert.equal(found[0][1].replace(/&amp;/g, '&'), t(key), id);
  }
  for (const id of ['view', 'search-form', 'search-input', 'search-error', 'network-name', 'index-note', 'trust-body']) assert.equal(html.split(`id="${id}"`).length, 2, id);
  assert(html.includes(`<noscript><p class="state failed">${t('page.noscript')}</p></noscript>`));
  assert(html.includes(`<title>${t('page.title')}</title>`));
  // The scripts never build markup from text, evaluate text as code, or set a style.
  const names = ['app.js', 'strings.mjs', 'format.mjs', 'route.mjs', 'describe.mjs', 'client.mjs', 'check.mjs', 'dom.mjs', 'views.mjs'];
  const sources = Object.fromEntries(await Promise.all(names.map(async (name) => [name, await readFile(new URL(`./${name}`, import.meta.url), 'utf8')])));
  for (const [name, source] of Object.entries(sources)) {
    assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|\.style\b|setAttribute\('style'|srcdoc|\.cssText/, name);
    if (name !== 'dom.mjs') assert.doesNotMatch(source, /createElement|createTextNode/, `${name}: only dom.mjs makes elements`);
    if (name !== 'app.js') assert.doesNotMatch(source, /https?:\/\/(?!api\.example)/, `${name}: no outside address`);
  }
  // Every entry the code names exists, and the table holds no entry nothing uses.
  const table = STRINGS.en, code = Object.values(sources).join('\n').replace(/export const STRINGS[\s\S]*?\n\}\);\n/, '');
  const used = new Set([...code.matchAll(/'((?:page|unit|value|ago|quoted|account|block|action|role|source|state|error|unknown|search|find|home|actions|live|index|trust|pager|fee|check|field|act|pending|detail|validators|tag|origin)\.[A-Za-z0-9_.]+)'/g)].map((match) => match[1]));
  used.add('percent');
  for (const key of used) assert(Object.hasOwn(table, key) || Object.keys(table).some((entry) => entry.startsWith(key)), `missing entry: ${key}`);
  const dynamic = /^(ago|role|live|check|field|pending|detail\.key|actions\.count)\./;
  for (const key of Object.keys(table)) assert(used.has(key) || dynamic.test(key) || key === 'page.noscript' || key === 'page.title', `unused entry: ${key}`);
  assert.equal(t('no.such.entry'), '[no.such.entry]');
});

test('the find view: the account of a number is checked, or marked as the service\'s word, or not shown at all', async () => {
  // Proven absent.
  const absent = await open('#/find/9', ({ api }) => { api.account = async () => { throw new ApiFailure('http', { status: 404, code: 'account_not_found', body: { ...provenNote({ ids: ['9'] }) } }); }; });
  assert.match(absent.text(), /Account 9 Checked in your browser against the state of block 121\..* There is no account 9\. Checked in your browser: the proof shows that the state of block 121 does not hold it\./);
  // A bare denial.
  const bare = await open('#/find/9', ({ api }) => { api.account = fail(404, { code: 'account_not_found' }); });
  assert.match(bare.text(), /Account 9 The service says there is no account 9, and gave no proof of that\. This page could not check it\./);
  // Nothing to check with: the service's word, marked in front, and its name is not "from the chain".
  const unchecked = await open('#/find/118', ({ checker }) => { checker.stateFailure = new CheckFailure('no_trust'); });
  assert.match(unchecked.text(), /Account 118 Not checked\. What follows is the service's word: this page did not check any of it\..* Not checked, the service's word: Open account 118, named account name as the service gives it: @payer\./);
  assert.doesNotMatch(unchecked.text(), /account name from the chain/);
  // The service names another network, or its proof fails: nothing of the account is shown.
  for (const failure of [new CheckFailure('wrong_network'), new CheckFailure('refused', 'x', { offered: true })]) {
    const none = await open('#/find/118', ({ checker }) => { checker.stateFailure = failure; });
    assert.match(none.text(), /Account 118 (?:Not checked, and so not shown|The check FAILED)/, failure.reason);
    assert.doesNotMatch(none.text(), /payer|Open account/, failure.reason);
  }
  // The service answers for another account than the one asked: nothing of it either.
  const other = await open('#/find/118', ({ answers }) => { const account = answers.account; answers.account = () => account(); });
  assert.doesNotMatch(other.text(), /payer|Open account/);
});

test('lists: a completed waiting payment says whose word its recipient and amount are, wherever it is listed', async () => {
  const execute = (more = {}) => actionItem({ kind: 75, reference: null, recipient: '5', amount: '900000000', transfers: true, request_hash: HASH2, ...more });
  const note = /account 7 completed a waiting payment: account 5 received 15 min\. Recipient and amount are the index's attribution, unconfirmed: the bytes of this action do not carry them\./;
  const block = await open('#/block/118', ({ answers }) => { answers.blockActions = () => fromIndex({ has_more: false, next_cursor: null, items: [execute(), actionItem({ hash: 'E5'.repeat(32), kind: 3, reference: null })] }); });
  assert.match(block.text(), note);
  assert.equal(block.text().split('Recipient and amount are the index').length, 2, 'an ordinary payment carries its recipient and amount in its bytes and has no such note');
  const account = await open('#/account/7', ({ answers }) => { answers.activity = () => fromIndex({ has_more: false, next_cursor: null, items: [execute()] }); });
  assert.match(account.text(), note);
  const home = await open('#/', ({ answers }) => { answers.blockActions = () => fromIndex({ has_more: false, next_cursor: null, items: [execute()] }); });
  assert.match(home.text(), note);
  home.live.emit('payment', execute({ hash: 'F6'.repeat(32), height: '121' }));
  assert.equal(home.text().split('Recipient and amount are the index').length, 3);
  // A completion the index could not attribute has neither, and a request moved nothing: no note.
  const plainRows = await open('#/block/118', ({ answers }) => { answers.blockActions = () => fromIndex({ has_more: false, next_cursor: null, items: [execute({ recipient: null, amount: null, transfers: false, unattributed: true }), execute({ transfers: false, request_status: 'waiting' })] }); });
  assert.doesNotMatch(plainRows.text(), /Recipient and amount are the index/);
});

test('a test network reset under an open page (check.mjs, "network_reset"): one sentence in place of the figures and of the check of an action, and no "Try again"', async () => {
  const held = await open('#/account/7', ({ checker }) => { checker.stateFailure = new CheckFailure('network_reset', null, { offered: true }); });
  assert.equal(held.text(), 'Account 7 The test network was reset. Reload this page.');
  assert.equal(buttons(held.view, 'Try again').length, 0);
  const action = await open(`#/action/${HASH}`, ({ checker }) => { checker.actionFailure = new CheckFailure('network_reset', null, { offered: true }); });
  buttons(action.view, 'Check it yourself')[0].fire('click'); await action.settle();
  assert.equal(textOf(within(action.view, 'check-result')[0]), 'The test network was reset. Reload this page.');
});
