// A stand-in page and a stand-in chain for the tests of the market's screens (market-ui.test.mjs and the tests beside
// it): elements that keep what the page puts into them, a chain that applies the market's rules as
// mock-market-chain.mjs reads them, a "verified state" made of that chain's rows, the trading API's lists made of the
// same rows, and a signer that hands a built action to the chain. The real page with the real app.js is driven in
// Chrome by preview-drive.mjs.
//
// What this does NOT show: that the verifier checks a proof (the state here is taken as proven), or that the engine
// takes an action. It shows what the page reads, shows, refuses and signs.
import '../../../client-v4/time-sdk.js';
import * as codec from '../../shared/bitcoin-address.mjs';
import { createMarketChain } from './mock-market-chain.mjs';
import { createMarketApi } from '../market-api.mjs';
import { createMarketUI } from '../market-ui.mjs';
import { createTradeView } from '../market-trade-ui.mjs';
import { marketCharge, limitWords } from '../market.mjs';

export const sdk = globalThis.TimeSDK;
export const NET = 'c6'.repeat(32), GENESIS = 1790000000000000n, FEE = 1000n;
export const W = byte => `0014${byte.repeat(20)}`;
export const addressOf = script => codec.scriptToAddress(script, 'regtest');

export class El {
  constructor(tag) { Object.assign(this, { tag, hidden: false, textContent: '', className: '', value: '', checked: false, disabled: false, children: [], listeners: {}, attrs: {}, parent: null }); }
  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
  async fire(type, event = {}) { for (const fn of this.listeners[type] || []) await fn({ preventDefault() {}, target: this, ...event }); }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  append(...nodes) { for (const node of nodes) { if (typeof node === 'string') { this.children.push(node); continue; } node.parent?.remove(node); node.parent = this; this.children.push(node); } }
  remove(node) { this.children = this.children.filter(child => child !== node); }
  replaceChildren(...nodes) { for (const child of this.children) if (child && typeof child === 'object') child.parent = null; this.children = []; this.append(...nodes); }
  focus() {}
}
export const textOf = node => (typeof node === 'string' ? node : node.hidden ? '' : [node.textContent, ...node.children.map(textOf)].filter(Boolean).join(' ')).replace(/\s+/g, ' ').trim();
export function* walk(node) { if (typeof node === 'string') return; yield node; for (const child of node.children) yield* walk(child); }
export const all = (node, test) => [...walk(node)].filter(test);
export const byId = (node, id) => all(node, item => item.id === id)[0] ?? null;
export const byText = (node, tag, text) => all(node, item => item.tag === tag && (text instanceof RegExp ? text.test(item.textContent) : item.textContent === text));
const settle = () => new Promise(resolve => setTimeout(resolve, 0));

/// A world: accounts, the market chain, and the market's panel for one of them.
/// `secured`: the open account has the protection rules (a daily limit of `limit` microseconds, `frozen`).
export function world({ secured = false, limit = 600000000n, frozen = false, balance = '100000000', profile = 'laboratory', network = 'regtest', market = true } = {}) {
  const key = id => String(id).padStart(2, '0').repeat(32);
  const accounts = [5, 6, 7, 8].map(id => ({ id: String(id), name: { 5: 'seller', 6: 'carol', 7: 'helper', 8: 'buyer' }[id], balance: id === 6 ? balance : '500000000', nonce: '0', auth_epoch: '0', devices: [{ public_key: key(id), can_manage: true, can_spend: true }] }));
  const clock = { now: 20000000000n, height: 900 };
  const guard = { allowance: limit, frozen, frozenAccounts: new Set() };
  const chain = createMarketChain({ sdk, accounts, genesis: GENESIS, profile, fee: FEE, bitcoin: { network, best: 100, halted: false, fresh: true },
    spend: (account, count) => { if (secured && account.id === '6') { if (count > guard.allowance) throw new Error('over the daily limit of this account'); guard.allowance -= count; } },
    frozen: account => guard.frozenAccounts.has(account.id) || (secured && account.id === '6' && guard.frozen) });
  const me = () => accounts.find(account => account.id === '6');
  /// An action of any account, straight into the chain (the other people of a test).
  function send(from, kind, payload) { const account = accounts.find(item => item.id === String(from)); chain.apply({ kind, from: account.id, nonce: (BigInt(account.nonce) + 1n).toString(), publicKey: account.devices[0].public_key, payload }, clock.now, clock.height); clock.height += 1; clock.now += 1000000n; }
  const reads = [], asked = [], signed = [], reviews = [], said = [], copied = [];
  let latest = null;
  async function verifiedState(input = {}) {
    reads.push(input);
    const ids = new Set([...(input.ids || []), '6']);
    const state = { verified: true, network_id: NET, protocol_version: '4', height: String(clock.height), time_micros: (GENESIS + clock.now).toString(), genesis: { genesis_time_micros: GENESIS.toString() },
      config: market ? chain.config() : { profile, bitcoin: { network } }, ...(market ? { stopped_micros: '0', market_micros: chain.held(), market: chain.select(input) } : {}), bitcoin: chain.bitcoinRow(),
      accounts: structuredClone(accounts.filter(account => ids.has(account.id))),
      security: [...(secured ? [{ account: '6', frozen: guard.frozen }] : []), ...[...guard.frozenAccounts].filter(id => ids.has(id)).map(id => ({ account: id, frozen: true }))] };
    latest = state; return state;
  }
  const storage = new Map(), store = { getItem: name => (storage.has(name) ? storage.get(name) : null), setItem: (name, value) => { storage.set(name, String(value)); }, removeItem: name => { storage.delete(name); } };
  const statics = new Map(), root = new El('main');
  for (const id of ['market-card', 'market-view', 'market-back', 'market-test-note', 'market-payment-wrap', 'market-payment', 'tab-market', 'home-market-row', 'home-market']) { const node = new El(id === 'market-payment' ? 'input' : 'div'); node.id = id; statics.set(id, node); }
  root.append(statics.get('tab-market'), statics.get('home-market-row'), statics.get('market-card'));
  statics.get('market-card').append(statics.get('market-test-note'), statics.get('market-back'), statics.get('market-view'), statics.get('market-payment-wrap'));
  statics.get('market-payment-wrap').append(statics.get('market-payment')); statics.get('home-market-row').append(statics.get('home-market'));
  for (const id of ['tab-market', 'home-market-row', 'market-payment-wrap', 'market-back', 'market-test-note']) statics.get(id).hidden = true;
  const $ = id => statics.get(id) ?? byId(root, id);
  const doc = { createElement: tag => new El(tag), createElementNS: (space, tag) => new El(tag) };
  // What the review will answer: true confirms. A test may set `answer` to a function of the review.
  const control = { answer: true, locked: false, panel: null, stops: 0 };
  const seconds = value => { const micros = BigInt(value), fraction = (micros % 1000000n).toString().padStart(6, '0').replace(/0+$/, ''); return `${micros / 1000000n}${fraction ? '.' + fraction : ''}`; };
  const fetch = async (path, options = {}) => {
    asked.push([path, options]);
    const url = new URL(path, 'https://wallet.example'), answer = control.api?.(url.pathname, Object.fromEntries(url.searchParams)) ?? chain.api(url.pathname, Object.fromEntries(url.searchParams), clock.now, clock.height);
    return { status: answer.status, text: async () => (typeof answer.body === 'string' ? answer.body : JSON.stringify(answer.body)) };
  };
  const ui = createMarketUI({ sdk, codec, api: createMarketApi({ fetch, timeout: () => undefined }), storage: store, $, doc, formatDate: date => date.toISOString().slice(0, 16),
    network: () => ({ networkId: NET }), session: () => ({ binding: { name: 'carol', publicKey: key(6) } }), state: () => latest, ownAccount: (state = latest) => state?.accounts?.find(account => account.id === '6'),
    verifiedState, capture: () => () => { if (control.locked) throw new Error('locked'); }, refresh: async () => { await verifiedState(); },
    review: async (title, fields, confirm, options = {}) => { const review = { title, fields: fields.map(([name, value]) => [name, String(value)]), confirm, acknowledge: options.acknowledge ?? '' }; reviews.push(review); return typeof control.answer === 'function' ? control.answer(review) : control.answer; },
    notice: (text, kind = '') => said.push([text, kind]), setBusy: () => {}, run: async action => { try { await action(); } catch (error) { if (error.noticeShown !== true) said.push([error.message, 'error']); } },
    seconds, parseSeconds: text => { if (!/^(?:0|[1-9][0-9]{0,13})(?:\.[0-9]{1,6})?$/.test(text)) throw new Error('Enter seconds with up to six decimal places.'); const [whole, part = ''] = text.split('.'); return (BigInt(whole) * 1000000n + BigInt(part.padEnd(6, '0'))).toString(); },
    fee: () => FEE.toString(), secured: () => secured, frozen: row => row.frozen === true,
    limit: async (charge, what) => limitWords({ charge, what, balance: me().balance, secured: true, allowance: guard.allowance, frozen: guard.frozen, limit, seconds }),
    sign: async (kind, payload, label, options = {}) => {
      if (secured && options.password !== 'payment-password') throw new Error('The payment password is wrong.');
      // The bytes a key would sign are built and read back, as the SDK does it: a payload in another form is refused here.
      const account = me(), action = sdk.decodeAction(sdk.concat(sdk.buildAction({ networkId: NET, kind, from: '6', nonce: (BigInt(account.nonce) + 1n).toString(), authEpoch: '0', publicKey: key(6), payload }), new Uint8Array(64)));
      // A refusal of the chain reaches the wallet through its gateway, as text.
      try { chain.apply(action, clock.now, clock.height); } catch (error) { const refused = new Error(error.message); refused.gateway = true; throw refused; }
      clock.height += 1; clock.now += 1000000n;
      signed.push({ kind, payload: action.payload, label, charge: options.charge }); return { verified: true, height: String(clock.height) };
    },
    gatewayWords: error => `The gateway says: ${error.message}`, idle: () => true, trade: createTradeView, stopGapMs: 0, stopId: () => (++control.stops).toString(16).padStart(16, '0'),
    showPanel: name => { control.panel = name; }, copy: async text => { copied.push(text); } });
  ui.start();
  const view = () => statics.get('market-view');
  /// Draws the panel as a refresh of the open account does, and waits for it.
  async function open(name = null) { ui.render(me(), await verifiedState()); await settle(); await settle(); if (name) await ui.go(name); }
  /// A verified reading of the open account, as the wallet makes one every few seconds, and what it starts.
  async function tick() { ui.render(me(), await verifiedState()); for (let i = 0; i < 12; i += 1) await settle(); }
  /// Presses a button (or sends a form) and waits for what it started.
  async function press(node, type = 'click') { assert(node, 'the element is on the page'); await node.fire(type); await settle(); }
  const assert = (value, message) => { if (!value) throw new Error(message); };
  const type = (id, value) => { const node = $(id); assert(node, `the field ${id} is on the page`); node.value = value; return node; };
  return { ui, chain, accounts, clock, guard, me, send, reads, asked, signed, reviews, said, copied, storage, store, $, root, view, open, tick, press, type, control, verifiedState, seconds, lastSaid: () => said[said.length - 1]?.[0] ?? '', text: () => textOf(view()) };
}
export { codec, marketCharge };
