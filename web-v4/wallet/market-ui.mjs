// The market of seconds against bitcoin, in the wallet (spec/market.md): the simple part. A person keeps the receiving
// addresses of their own Bitcoin wallet here, buys seconds with bitcoin, sells seconds for bitcoin and looks after
// their orders and purchases. The traders' view is market-trade-ui.mjs, drawn into the same panel.
//
// THE RULE (market.mjs says it in full): nothing a person pays on is taken from a server's word. Lists come from the
// trading API (market-api.mjs) and are shown as lists. Every address and amount to pay, and every row an action is
// signed on, is read here through the wallet's own verifier (`proven`, below: app.js's verifiedState with a selection
// of the market) and those rows are what the page shows and signs. Where the proven row differs from the list, the
// page stops and says so.
//
// The page shows the market only on a network whose proven state says `market` (TimeSDK.marketSetting); on any other
// network `render` hides its two entries and draws nothing. The wallet holds no Bitcoin key and sends no bitcoin.
//
// Signing is the wallet's own, unchanged: a review sheet, then app.js's `sign` (signing.mjs's sendSigned; on a
// protected account the payment key, opened with the payment password for that one action: security-ui.mjs,
// marketAction). Nothing here holds a key, and nothing is signed without a review that was confirmed.
import {
  ADDRESS_WORDS, PAY_WORDS, SELL_WORDS, addressKey, notesKey, pastedAddresses, checkAddresses, readAddressBook, writeAddressBook, withAddresses, withoutAddress, addressState, pieces,
  bitcoinNetworkOf, testBitcoinWords, groupedAddress, bitcoinWords, btcText, grouped, priceWords, priceText, parsePrice, parseBtc, parseWhole, parsePercent, percentText, blocksDuration,
  planPurchase, planChanged, changedWords, fillChanged, ownerStands, sizeRefusal, takeDeposit, payWindow, purchaseState, bitcoinLink, headerChain,
  sellDefaults, suggestedMinSats, termsRefusal, marketCharge, limitWords, againstBook, againstBookWords, readNotes, withNote, newId,
  refusalWords,
} from './market.mjs';
import { indexWarnings } from './market-api.mjs';

const assert = (value, message) => { if (!value) throw new Error(message); };
export const MARKET_WORDS = Object.freeze({
  title: 'Market',
  lede: 'Buy seconds with bitcoin, or sell seconds for bitcoin, with other people. Nobody holds the bitcoin in between: the buyer pays it from their own Bitcoin wallet to an address of the seller, and the chain hands over the seconds when it has seen the proof.',
  slow: 'A trade takes as long as Bitcoin takes: tens of minutes, not seconds.',
  noKey: 'This wallet holds no Bitcoin key and never sends bitcoin.',
  nothingSigned: 'Nothing was signed.',
  password: 'Enter your payment password first: your account is protected, and its payment key signs this.',
  notFresh: 'The market\'s service says that the chain is not receiving Bitcoin\'s block headers right now. If that is so, the chain refuses a new purchase until it does; a refused purchase locks nothing and costs nothing.',
  halted: 'The chain has stopped following Bitcoin, so no purchase can start and no payment can be proven. Nothing was signed.',
  closed: 'The market is closed on this network.',
});

/// `c`: what app.js hands in. { sdk, codec, api, storage, network(), session(), state(), ownAccount(state?),
/// verifiedState(input), review, notice, run, setBusy, capture, refresh, seconds, parseSeconds, fee(), secured(),
/// limit(charge, what), sign(kind, payload, label, { password, charge }), frozen(row, now), showPanel(name),
/// copy(text) } and, for tests, `$`, `doc`, `formatDate`, `trade`. `codec`: the module, or a function that loads it.
export function createMarketUI(c) {
  const $ = c.$ ?? (id => document.getElementById(id)), doc = c.doc ?? globalThis.document, sdk = c.sdk;
  const formatDate = c.formatDate ?? (date => date.toLocaleString());
  let view = { name: 'menu' }, drawn = 0, lastHome = 0, lastPay = 0, on = false;
  // The codec between Bitcoin addresses and receiving scripts (web-v4/shared/bitcoin-address.mjs): loaded when the
  // market is first drawn, so that a network without the market never asks for it.
  let codec = null;
  const ready = async () => { codec ??= await (typeof c.codec === 'function' ? c.codec() : c.codec); assert(codec && typeof codec.addressToScript === 'function' && typeof codec.scriptToAddress === 'function', 'The wallet could not load its reader of Bitcoin addresses.'); };

  // ---------------------------------------------------------------- elements
  function el(tag, props = {}, ...children) {
    const node = doc.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (key === 'class') node.className = value; else if (key === 'text') node.textContent = value;
      else if (key === 'on') { for (const [type, handler] of Object.entries(value)) node.addEventListener(type, handler); }
      else if (key === 'attrs') { for (const [name, text] of Object.entries(value)) node.setAttribute(name, text); }
      else node[key] = value;
    }
    node.append(...children.flat().filter(Boolean));
    return node;
  }
  const p = (text, className = '') => el('p', { text, class: className });
  /// Appends what is there: a part that a view leaves out (null) is not put on the page as the word "null".
  const add = (node, ...children) => { node.append(...children.flat().filter(Boolean)); return node; };
  const button = (text, act, className = 'secondary', id = '') => el('button', { type: 'button', text, class: className, ...(id ? { id } : {}), on: { click: () => c.run(act) } });
  const go = (name, params = {}) => { view = { name, ...params }; return draw(true); };
  const link = (text, name, params = {}, id = '') => el('button', { type: 'button', text, class: 'link', ...(id ? { id } : {}), on: { click: () => { go(name, params).catch(() => {}); } } });
  const listRow = (title, detail, ...actions) => el('div', { class: 'row' }, el('div', {}, el('strong', { text: title }), detail ? el('small', { text: detail }) : null), ...actions);
  /// An address, whole, in groups of four, in the font that tells 1 from l and 0 from O.
  const addressNode = (address, id = '') => el('p', { class: 'market-address', text: groupedAddress(address), ...(id ? { id } : {}), attrs: { 'aria-label': `Address ${address}` } });
  const field = (id, label, props = {}, note = '') => [el('label', { text: label, htmlFor: id }), el('input', { id, autocomplete: 'off', spellcheck: false, ...props }), note ? p(note, 'field-note') : null];
  const facts = pairs => el('dl', { class: 'market-facts' }, ...pairs.flatMap(([key, value]) => [el('dt', { text: key }), el('dd', { text: String(value) })]));
  const warnings = (...texts) => el('ul', { class: 'plain-list market-warnings' }, ...texts.filter(Boolean).map(text => el('li', { text })));
  const checkedAt = state => p(`Read from the chain and checked by this browser at block ${state.height}.`, 'field-note');

  // ---------------------------------------------------------------- proven state, and who is asking
  /// A verified state with the rows of the market a selection names. Everything a person pays or signs on comes from one.
  async function proven(selection = {}) {
    const check = c.capture(), state = await c.verifiedState({ include_market: true, ...selection }); check();
    assert(sdk.marketSetting(state), 'This network has no market.');
    return state;
  }
  /// The order or the fill an action of this account has just made: the id its proven row holds now and did not hold
  /// before. A proven state is the state after a block, and the block after it carries its proof: right after a receipt
  /// the newest state that can be proven may still be the one before the action (seen on the first real network). So
  /// the row is read again, a second apart, a few times; null when it still does not show.
  async function madeNow(account, before, list) {
    for (let tries = 0; tries < 6; tries++) {
      if (tries) await new Promise(resolve => setTimeout(resolve, 1000));
      const id = newId(before, sdk.marketAccount(await proven({ market_accounts: [account] }), account)[list]);
      if (id !== null) return id;
    }
    return null;
  }
  const me = (state = c.state()) => { const account = c.ownAccount(state); assert(account, 'Open your account first.'); return account; };
  const name = () => c.session().binding.name, net = () => c.network().networkId;
  const bitcoin = (state = c.state()) => bitcoinNetworkOf(state);
  const seconds = micros => c.seconds(String(micros));
  const toAddress = (script, state) => codec.scriptToAddress(script, bitcoin(state));

  // ---------------------------------------------------------------- the payment password of a protected account
  // One field (index.html, market-payment-wrap), moved to where the action is. It is read once, when the review was
  // confirmed, and emptied whatever happens.
  // The two elements are found once, at the start, while they are in the page: a view that was drawn and then thrown
  // away (a newer one came first) cannot take them along.
  let payWrap = null, payInput = null, claimed = -1;
  const paymentField = () => payInput;
  function paymentBox() { claimed = drawn; if (payWrap) payWrap.hidden = !c.secured(); return payWrap; }
  function takePassword() { const value = payInput?.value ?? ''; if (payInput) payInput.value = ''; return value; }

  // ---------------------------------------------------------------- one signed action
  /// Review, then sign. `fields` are the review's lines; the fee, what the action uses of the daily limit and which
  /// key signs are added here. Gives the verified receipt, or null when the review was cancelled.
  /// `total(fee)`: the review's line of what leaves the balance now, when the action locks something.
  async function act({ kind, payload, label, title, fields, confirm, acknowledge = '', charge = {}, what = 'This', total = null }) {
    const check = c.capture();
    try {
      const fee = sdk.marketActionFee(sdk.KINDS[kind], payload, c.fee()), cost = marketCharge({ fee, ...charge });
      if (c.secured()) assert((paymentField()?.value ?? '') !== '', MARKET_WORDS.password);
      const state = await c.verifiedState(); check();
      const said = c.secured() ? await c.limit(cost, what) : limitWords({ charge: cost, balance: me(state).balance, secured: false, seconds, what });
      check(); assert(!said.refusal, said.refusal);
      const lines = [...fields, ['Fee', `${seconds(fee)} seconds`], ...(total ? [['Total', total(BigInt(fee))]] : []), ...(said.line ? [['Daily limit', said.line]] : []), ...(c.secured() ? [['Signed by', 'Your payment key, with your payment password']] : [])];
      if (!await c.review(title, lines, confirm, acknowledge ? { acknowledge } : {})) { c.notice(MARKET_WORDS.nothingSigned); return null; }
      check(); c.setBusy(true);
      let receipt;
      try { receipt = await c.sign(kind, payload, label, { password: takePassword(), charge: cost, what }); }
      catch (error) {
        // A refusal of the chain, which a gateway passed on: the wallet's own sentence first, then the gateway's words, marked as such.
        if (error?.gateway === true) { c.notice(`${refusalWords(error.message)} ${c.gatewayWords ? c.gatewayWords(error) : ''}`.trim(), 'error'); error.noticeShown = true; }
        throw error;
      }
      check();
      return receipt;
    } finally { takePassword(); }
  }

  // ---------------------------------------------------------------- A. my Bitcoin addresses
  const readBook = async (state = c.state()) => readAddressBook(c.storage.getItem(addressKey(net(), name())), bitcoin(state), codec);
  const writeBook = (items, state = c.state()) => c.storage.setItem(addressKey(net(), name()), writeAddressBook(items, bitcoin(state)));
  /// What each address of the list serves, from PROVEN rows: the script rows, and for a listed script its order's row.
  async function addressStates(items) {
    const states = new Map();
    let height = null;
    for (const piece of pieces(items, sdk.MARKET_SELECTION.market_scripts)) {
      const state = await proven({ market_scripts: piece.map(item => item.script) }); height = state.height;
      const status = new Map(piece.map(item => [item.script, { ...sdk.marketScript(state, item.script), script: item.script }]));
      const orders = [...new Set([...status.values()].filter(row => row.status === 'listed').map(row => row.order))];
      const rows = new Map();
      for (const ids of pieces(orders, sdk.MARKET_SELECTION.market_orders)) { const more = await proven({ market_orders: ids }); for (const id of ids) rows.set(id, sdk.marketOrder(more, id)); }
      for (const item of piece) { const row = status.get(item.script); states.set(item.script, addressState(row, row.status === 'listed' ? rows.get(row.order) ?? null : null)); }
    }
    return { states, height };
  }
  async function addressesView() {
    const state = c.state(), book = await readBook(state);
    const root = el('div', { id: 'market-addresses' }, el('h2', { text: 'My Bitcoin addresses' }), p(ADDRESS_WORDS.what), p(ADDRESS_WORDS.publicLater, 'subtle'), p(ADDRESS_WORDS.exchange, 'warning'), p(ADDRESS_WORDS.once, 'subtle'));
    const result = el('div', { id: 'market-address-result', attrs: { role: 'status' } });
    const input = el('textarea', { id: 'market-address-input', rows: 4, spellcheck: false, autocomplete: 'off', attrs: { autocapitalize: 'none', maxlength: '20000' } });
    const add = async () => {
      const texts = pastedAddresses(input.value), checked = await checkAddresses(texts, bitcoin(), codec);
      const now = await readBook(), next = withAddresses(now.items, checked), bad = checked.filter(entry => !entry.ok), known = checked.filter(entry => entry.ok).length - next.added;
      if (next.added) writeBook(next.items);
      await go('addresses');
      // What was not taken stays in the field, to be corrected; the list above it is drawn again.
      const again = $('market-address-input'), said = $('market-address-result');
      if (again) again.value = bad.map(entry => entry.text).join('\n');
      said.replaceChildren(p(`${next.added} address${next.added === 1 ? '' : 'es'} added. Nothing was published.${known ? ` ${known} ${known === 1 ? 'was' : 'were'} on the list already.` : ''}`),
        ...bad.map(entry => p(`Not added: ${entry.text.slice(0, 100)}. ${entry.reason}`, 'warning')));
      c.notice(bad.length ? `${bad.length} of the pasted texts ${bad.length === 1 ? 'is' : 'are'} not ${bad.length === 1 ? 'an address' : 'addresses'} this wallet can use on ${bitcoin()}. See below.` : 'The addresses were checked and added to your list. Nothing was published.');
    };
    root.append(el('form', { id: 'market-address-form', on: { submit: event => { event.preventDefault(); c.run(add); } } },
      el('label', { text: 'Paste one address, or several', htmlFor: 'market-address-input' }), input,
      p(`Addresses of ${bitcoin()} only. Each one is checked: its form, its network and its checksum.`, 'field-note'), el('button', { type: 'submit', text: 'Check and add', id: 'market-address-add' })), result);
    const list = el('div', { id: 'market-address-list' });
    root.append(el('h3', { text: book.items.length ? `Your list (${book.items.length})` : 'Your list' }), list);
    if (book.dropped) root.append(p(`${book.dropped} stored ${book.dropped === 1 ? 'entry was' : 'entries were'} left out: ${book.dropped === 1 ? 'it is' : 'they are'} not ${book.dropped === 1 ? 'an address' : 'addresses'} of ${bitcoin()} as this wallet reads them.`, 'warning'));
    if (!book.items.length) list.append(p('No address yet. Paste one from your own Bitcoin wallet: use "Receive" there and make a new address.', 'subtle'));
    else {
      const { states, height } = await addressStates(book.items);
      const aside = new Set(reserved());
      for (const item of book.items) {
        const proof = states.get(item.script), said = proof.usable && aside.has(item.script) ? { ...proof, detail: 'Not in any order. A stop order of this wallet keeps it aside.' } : proof;
        list.append(el('div', { class: 'market-address-row' }, addressNode(item.address), el('p', {}, el('span', { class: `tag market-${said.key}`, text: said.label }), el('span', { text: ` ${said.detail}`, class: 'subtle' })),
          el('div', { class: 'button-row' }, el('button', { type: 'button', class: 'secondary', text: 'Copy', on: { click: () => c.run(async () => { await c.copy(item.address); c.notice('The address was copied.'); }) } }),
            el('button', { type: 'button', class: 'secondary', text: 'Remove from my list', on: { click: () => c.run(async () => { writeBook(withoutAddress((await readBook()).items, item.script)); await go('addresses'); c.notice(ADDRESS_WORDS.removed); }) } }))));
      }
      list.append(p(`What each address serves was read from the chain and checked by this browser at block ${height}.`, 'field-note'));
    }
    root.append(p(ADDRESS_WORDS.kept, 'field-note'));
    return root;
  }

  // ---------------------------------------------------------------- B. buy seconds with bitcoin
  // The rules as the pages word them: on a private test chain the length of a block is left out (market.mjs, blocksDuration).
  const rules = (state = c.state()) => { const r = sdk.marketRules(state); return bitcoinNetworkOf(state) === 'regtest' ? { ...r, blockMicros: null } : r; };
  const readNote = id => readNotes(c.storage.getItem(notesKey(net(), name())))[id] ?? null;
  const freeScript = order => order.scripts.some(entry => entry.fill === undefined && entry.used !== true);
  // What the buy form holds between two drawings: what was typed, the offer found, and the orders set aside.
  const buy = { mode: 'seconds', text: '', offer: null, stopped: '', notes: [], skip: [], index: null };
  /// The best offer for what the form asks. The plan is made from the LIST; its first order is then read PROVEN, with
  /// its owner's rows, and compared. A proven order that is not what the list said stops here, in words. An order
  /// whose owner does not stand, or that has no free address, is set aside and the next one is looked at.
  async function findOffer(want) {
    const listed = await c.api.orders('sell'), account = me();
    buy.index = listed.index; buy.notes = []; buy.stopped = ''; buy.offer = null;
    for (let round = 0; round < 6; round += 1) {
      const plan = planPurchase(sdk, listed.items, want, rules(), { ownAccount: account.id, skip: buy.skip }), take = plan.takes[0];
      if (!take) { buy.stopped = buy.notes.length ? 'No other offer on the list can serve this right now.' : listed.items.length ? 'No offer on the list can serve this amount right now: it is below the smallest purchase of every order, or above what is on offer.' : 'Nobody offers seconds for bitcoin right now.'; return; }
      const state = await proven({ market_orders: [take.order], ids: [take.owner], include_security: true });
      const order = sdk.marketOrder(state, take.order), changes = planChanged(take, order);
      if (changes.length) { buy.stopped = changedWords(changes); buy.stoppedOrder = take.order; return; }
      if (ownerStands(sdk, state, order, c.frozen) === false) { buy.skip.push(take.order); buy.notes.push(`The seller of order ${take.order} cannot sell right now (the account is frozen, or its key was replaced), so the next offer is shown.`); continue; }
      if (!freeScript(order)) { buy.skip.push(take.order); buy.notes.push(`Order ${take.order} has no free address left, so the next offer is shown.`); continue; }
      const refusal = sizeRefusal(sdk, order, take.amountMicros, rules(state));
      assert(refusal === null, refusal);
      // Everything of the offer is the proven order's: its price, its terms, and what they make of the amount.
      buy.offer = { order: order.id, owner: order.owner, price: order.price, amountMicros: take.amountMicros, sats: sdk.marketSats(take.amountMicros, order.price), depositMicros: takeDeposit(order, take.amountMicros),
        confirmations: order.confirmations, payBlocks: order.pay_blocks, minSats: order.min_sats, height: state.height, more: plan.takes.length > 1 || (plan.shortMicros ?? plan.shortSats) !== '0', want };
      return;
    }
    buy.stopped = 'No offer on the list can be taken right now.';
  }
  async function searchOffer() {
    const text = ($('market-buy-amount')?.value ?? '').trim(); buy.text = text;
    const want = buy.mode === 'seconds' ? { amountMicros: c.parseSeconds(text) } : { sats: parseBtc(text) };
    c.setBusy(true);
    await findOffer(want);
    await go('buy');
    c.notice(buy.offer ? 'This is the best offer on the list, read from the chain. Nothing is signed yet.' : buy.stopped);
  }
  async function buyView() {
    const root = el('div', { id: 'market-buy' }, el('h2', { text: 'Buy seconds with bitcoin', id: 'market-view-title', tabIndex: -1 }),
      p('You lock a small deposit in seconds, pay the bitcoin from your own Bitcoin wallet to an address of the seller, and get the seconds when your payment has its confirmations.'));
    const mode = (key, text) => el('button', { type: 'button', text, id: `market-buy-${key}`, class: buy.mode === key ? 'active' : '', attrs: { 'aria-pressed': String(buy.mode === key) }, on: { click: () => { buy.mode = key; buy.text = ''; buy.offer = null; buy.stopped = ''; go('buy').catch(() => {}); } } });
    root.append(el('div', { class: 'pay-switch', attrs: { role: 'group', 'aria-label': 'What you know' } }, mode('seconds', 'I want seconds'), mode('bitcoin', 'I have bitcoin')));
    root.append(el('form', { id: 'market-buy-form', on: { submit: event => { event.preventDefault(); c.run(searchOffer); } } },
      ...field('market-buy-amount', buy.mode === 'seconds' ? 'Seconds you want' : 'Bitcoin you have, in BTC', { class: 'money', inputMode: 'decimal', value: buy.text, placeholder: buy.mode === 'seconds' ? '60' : '0.0005' }),
      el('button', { type: 'submit', text: 'Find the best offer', id: 'market-buy-find' })));
    for (const note of buy.notes) root.append(p(note, 'subtle'));
    if (buy.index) for (const text of indexWarningsOf(buy.index)) root.append(p(text, 'nudge'));
    if (buy.stopped) {
      root.append(p(buy.stopped, 'warning'));
      if (buy.stoppedOrder) root.append(el('div', { class: 'button-row' }, button('Show the next offer', async () => { buy.skip.push(buy.stoppedOrder); buy.stoppedOrder = null; await searchOffer(); }, 'secondary', 'market-buy-next')));
    }
    const offer = buy.offer;
    if (!offer) return root;
    const r = rules(), fee = sdk.marketActionFee(sdk.MARKET_KINDS.take, sdk.marketTake({ order: offer.order, amountMicros: offer.amountMicros, price: offer.price, to: me().id }), c.fee());
    const card = el('div', { class: 'market-pay', id: 'market-offer' }, el('p', { class: 'eyebrow', text: 'The best offer' }),
      el('p', { class: 'market-amount', id: 'market-offer-amount', text: `${seconds(offer.amountMicros)} seconds` }, el('small', { text: `for ${bitcoinWords(offer.sats)}` })),
      facts([['Price', priceWords(offer.price)], ['You pay', `${bitcoinWords(offer.sats)}, from your own Bitcoin wallet`],
        ['Deposit', `${seconds(offer.depositMicros)} seconds, locked now. It comes back when your payment is proven. You lose it to the seller if you do not pay in time, or if you give up.`],
        ['Time to pay', `${offer.payBlocks} Bitcoin blocks, ${blocksDuration(offer.payBlocks, r.blockMicros)}`], ['Confirmations', r.blockMicros === null ? `${offer.confirmations} more blocks, before the seconds are yours` : `${offer.confirmations}, ${blocksDuration(offer.confirmations, r.blockMicros)} more, before the seconds are yours`],
        ['Fee', `${seconds(fee)} seconds`], ['Seller', `Account ${offer.owner}, order ${offer.order}. Smallest purchase: ${grouped(offer.minSats)} satoshis.`]]),
      p(`Read from the chain and checked by this browser at block ${offer.height}.`, 'field-note'));
    if (offer.more) card.append(p('This offer covers a part of what you asked for. After this purchase, come back for the rest: each purchase is one payment in bitcoin.', 'subtle'));
    add(card, paymentBox(), el('div', { class: 'button-row' }, button('Review this purchase', reviewPurchase, '', 'market-buy-review')));
    root.append(card, warnings(PAY_WORDS.exchange, PAY_WORDS.late, PAY_WORDS.publicNote));
    return root;
  }
  /// What the service says of the header chain, as a warning and never as a promise: the chain itself decides.
  async function freshnessWarning() {
    try { const said = await c.api.bitcoin(); return said.fresh === false ? MARKET_WORDS.notFresh : ''; } catch { return ''; }
  }
  async function reviewPurchase() {
    const offer = buy.offer; assert(offer, 'Find an offer first.');
    const account = me(), state = await proven({ market_orders: [offer.order], ids: [offer.owner], include_security: true, market_accounts: [account.id] });
    // The order is read again, proven, at the moment of the review: what is signed is what the chain holds now.
    const order = sdk.marketOrder(state, offer.order), changes = planChanged(offer, order);
    if (changes.length) { buy.offer = null; buy.stopped = changedWords(changes); buy.stoppedOrder = offer.order; await go('buy'); throw new Error(buy.stopped); }
    assert(!headerChain(state).halted, MARKET_WORDS.halted);
    assert(ownerStands(sdk, state, order, c.frozen) !== false, 'The seller of this order cannot sell right now. Nothing was signed. Look for another offer.');
    assert(freeScript(order), 'This order has no free address left. Nothing was signed. Look for another offer.');
    const refusal = sizeRefusal(sdk, order, offer.amountMicros, rules(state)); assert(refusal === null, refusal);
    // The deposit, the confirmations and the time to pay are not in what a take signs (spec/market.md, 10.19): the review
    // takes each of them from the order row proven just now, never from the list or from the offer drawn before.
    const before = sdk.marketAccount(state, account.id).fills, r = rules(state), stale = await freshnessWarning(), deposit = takeDeposit(order, offer.amountMicros), sats = sdk.marketSats(offer.amountMicros, order.price);
    const receipt = await act({ kind: 'market_take', payload: sdk.marketTake({ order: order.id, amountMicros: offer.amountMicros, price: order.price, to: account.id }), label: `Buy ${seconds(offer.amountMicros)} s for bitcoin`, what: 'The deposit and the fee',
      title: 'Buy seconds with bitcoin', confirm: `Lock ${seconds(deposit)} s and show the address`, charge: { locked: deposit },
      acknowledge: 'I will pay the exact amount in time, from a Bitcoin wallet I control. If I do not, I lose the deposit.',
      fields: [['You buy', `${seconds(offer.amountMicros)} seconds`], ['Price', priceWords(order.price)], ['You will pay', `${bitcoinWords(sats)}, from your own Bitcoin wallet, to an address of the seller that is shown next`],
        ['Seller', `Account ${order.owner}, order ${order.id}`], ['Time to pay', `${order.pay_blocks} Bitcoin blocks, ${blocksDuration(order.pay_blocks, r.blockMicros)}. Then ${order.confirmations} confirmations.`],
        ...(stale ? [['Warning', stale]] : []),
        ['Deposit', `${seconds(deposit)} seconds, locked now. It comes back when your payment is proven. You lose it to the seller if you do not pay in time, or if you give up.`]],
      total: fee => `${seconds(BigInt(deposit) + fee)} seconds leave your balance now` });
    if (!receipt) return;
    // The fill this action made: the one the account's proven row holds now and did not hold before.
    const id = await madeNow(account.id, before, 'fills');
    buy.offer = null; buy.text = ''; buy.skip = []; buy.notes = [];
    await c.refresh();
    if (id === null) { await go('mine'); c.notice('The purchase was signed and is in a block, but this browser does not see it among your open purchases yet. Look under "My purchases and orders" in a moment.'); return; }
    const made = sdk.marketFill(await proven({ market_fills: [id] }), id);
    if (made) c.storage.setItem(notesKey(net(), name()), withNote(c.storage.getItem(notesKey(net(), name())), id, { firstSats: made.sats, order: made.order }));
    await go('pay', { fill: id });
    c.notice('The deposit is locked. Now pay the bitcoin from your own Bitcoin wallet: the address and the exact amount are below, read from the chain.');
  }
  const indexWarningsOf = note => indexWarnings(note, c.state()?.height ?? null);

  // ---------------------------------------------------------------- the pay screen of a purchase
  const HOW = Object.freeze({ paid: 'The market\'s list says it was paid in full: the seconds are in the balance of the account they were for, and the deposit came back.', expired: 'The market\'s list says it ended unpaid: its time had passed. The deposit went to the seller.',
    released: 'The market\'s list says it was given up. The deposit went to the seller.', settled: 'The market\'s list says the seller handed over the seconds without a proof, and the deposit came back.', unknown: 'The market\'s list does not say how it ended.' });
  async function payView() {
    const id = String(view.fill), note = readNote(id);
    let state = await proven({ market_fills: [id], ...(note ? { market_orders: [note.order] } : {}) }), fill = sdk.marketFill(state, id);
    const account = me(state);
    const root = el('div', { id: 'market-pay' }, el('h2', { text: `Purchase ${id}`, id: 'market-view-title', tabIndex: -1 }));
    if (fill === null) {
      let how = 'unknown';
      try { how = (await c.api.fillNote(id)).ended ?? 'unknown'; } catch { how = 'unknown'; }
      const ended = purchaseState(null, note, how);
      root.append(el('p', { class: 'market-state', id: 'market-pay-state' }, el('span', { class: 'tag', text: ended.how === 'paid' ? 'Paid' : 'Ended' }), el('span', { text: 'This purchase has ended: the chain holds it no more.' })), checkedAt(state),
        p(HOW[ended.how], 'subtle'), p(`Your balance, checked by this browser: ${seconds(account.balance)} seconds.`), p('Do not pay to its address any more: a payment now buys nothing.', 'warning'),
        el('div', { class: 'button-row' }, button('My purchases and orders', () => go('mine'), 'secondary')));
      return root;
    }
    assert(fill.to === account.id || fill.payer === account.id, 'This purchase is not one of your account.');
    if (!Object.hasOwn(state.market.orders ?? {}, fill.order)) { state = await proven({ market_fills: [id], market_orders: [fill.order] }); fill = sdk.marketFill(state, id); assert(fill, 'The purchase ended while it was read. Look again.'); }
    const order = sdk.marketOrder(state, fill.order), address = await toAddress(fill.script, state), r = rules(state);
    const status = purchaseState(fill, note), time = payWindow(sdk, state, fill), expiry = sdk.marketExpiry(state, fill), ends = sdk.securityDeadline(state, expiry.notBeforeMicros);
    const helper = fill.payer !== account.id, mine = fill.to === account.id;
    // The rest of the book, from the list: only to say when this seller's price stands far above it.
    let against = null;
    try { const listed = await c.api.orders('sell'); against = againstBook(fill.price, listed.items.filter(item => item.id !== fill.order && item.takes_fill).map(item => item.price)); } catch { against = null; }
    root.append(el('p', { class: 'market-state', id: 'market-pay-state' }, el('span', { class: 'tag market-in_use', text: status.key === 'part' ? 'Part counted' : 'Waiting for payment' }),
      el('span', { text: status.key === 'part' ? `${bitcoinWords(status.paidSats)} counted so far. The rest is still to pay.` : mine ? 'Nothing is counted yet.' : `You prepared this purchase for account ${fill.to}. Only that account can give it up.` })));
    if (time.halted) root.append(p(PAY_WORDS.halted, 'warning'));
    else if (time.over) root.append(p(PAY_WORDS.over, 'warning'));
    if (helper) root.append(p(`${PAY_WORDS.helper} Account ${fill.payer} prepared it.`, 'warning'));
    if (against && (helper || against.far)) root.append(p(againstBookWords(fill.price, against), against.far ? 'warning' : 'subtle'));
    root.append(el('div', { class: 'market-pay' }, el('p', { class: 'eyebrow', text: 'Pay exactly' }),
      el('p', { class: 'market-amount', id: 'market-pay-amount', text: `${btcText(fill.sats)} BTC` }, el('small', { text: `${grouped(fill.sats)} satoshis, still to pay` })),
      el('p', { class: 'eyebrow', text: 'To this address of the seller' }), addressNode(address, 'market-pay-address'),
      el('div', { class: 'button-row' }, el('button', { type: 'button', class: 'secondary', id: 'market-copy-address', text: 'Copy the address', on: { click: () => c.run(async () => { await c.copy(address); c.notice('The address was copied. Compare it in your Bitcoin wallet before you send.'); }) } }),
        el('button', { type: 'button', class: 'secondary', id: 'market-copy-amount', text: 'Copy the amount', on: { click: () => c.run(async () => { await c.copy(btcText(fill.sats)); c.notice('The amount in BTC was copied.'); }) } }),
        el('a', { class: 'button-link secondary', id: 'market-pay-link', href: bitcoinLink(address, fill.sats), text: 'Open in my Bitcoin wallet' })),
      p(PAY_WORDS.compare), checkedAt(state)));
    root.append(facts([['You get', `${seconds(fill.amount_micros)} seconds, to account ${fill.to}`], ['Price', priceWords(fill.price)],
      ['Pay by', time.over ? `Bitcoin block ${time.payBy} was the last. The chain already knows block ${time.best}.` : `Bitcoin block ${time.payBy} at the latest. The chain now knows block ${time.best}: ${time.blocksLeft} block${time.blocksLeft === '1' ? '' : 's'} left, ${blocksDuration(time.blocksLeft, r.blockMicros)}.`],
      ['Confirmations', `${fill.confirmations} after that, by block ${time.lastHeight}`], ['Can end unpaid', `${ends.earliest ? 'not before' : 'from'} ${formatDate(new Date(Number(BigInt(ends.timeMicros) / 1000n)))}`],
      ['Deposit', `${seconds(fill.deposit_micros)} seconds, locked by ${helper ? `account ${fill.payer}` : 'you'}. It comes back when the payment is proven.`], ['Seller', `Account ${fill.owner}, order ${fill.order}`], ['Purchase number', `Fill ${id}`]]));
    root.append(warnings(PAY_WORDS.exact, order ? `${PAY_WORDS.small} The smallest purchase of this seller is ${grouped(order.min_sats)} satoshis.` : PAY_WORDS.small, PAY_WORDS.exchange, PAY_WORDS.late, PAY_WORDS.proof, PAY_WORDS.publicNote));
    const actions = el('div', { class: 'button-row' }, button('Check again', async () => { await go('pay', { fill: id }); c.notice('This purchase was read again from the chain.'); }, 'secondary', 'market-pay-refresh'));
    if (mine) actions.append(button('Give up this purchase', () => giveUp(id), 'secondary', 'market-pay-release'));
    add(root, mine ? p(PAY_WORDS.giveUp, 'subtle') : null, mine ? paymentBox() : null, actions);
    return root;
  }
  async function giveUp(id) {
    const account = me(), state = await proven({ market_fills: [id] }), fill = sdk.marketFill(state, id);
    assert(fill, 'This purchase has ended already.'); assert(fill.to === account.id, 'Only the account the seconds would go to can give a purchase up.');
    const own = fill.payer === account.id, halted = headerChain(state).halted;
    const receipt = await act({ kind: 'market_release', payload: sdk.marketRelease({ fill: id }), label: `Give up purchase ${id}`, title: 'Give up this purchase', confirm: 'Give up and lose the deposit', what: 'Giving up',
      charge: { extra: ((halted ? 0n : BigInt(fill.amount_micros)) + (own ? BigInt(fill.deposit_micros) : 0n)).toString() },
      acknowledge: 'I have sent no bitcoin for this purchase, or I accept that it is lost.',
      fields: [['Purchase', `Fill ${id}`], ['You give up', `${seconds(fill.amount_micros)} seconds you would have got`], ['You lose', own ? `Your deposit of ${seconds(fill.deposit_micros)} seconds. It goes to the seller.` : `Nothing of yours: the deposit of account ${fill.payer}, ${seconds(fill.deposit_micros)} seconds, goes to the seller.`],
        ['Bitcoin', 'If you have sent bitcoin for this purchase, it stays with the seller and buys nothing.']] });
    if (!receipt) return;
    await c.refresh(); await go('pay', { fill: id }); c.notice('The purchase was given up. The deposit went to the seller.');
  }

  // ---------------------------------------------------------------- B. sell seconds for bitcoin
  let reserved = () => [];
  const checkbox = (id, script, address, checked) => { const input = el('input', { type: 'checkbox', id, checked, value: script }); return { input, node: el('label', { class: 'market-check', htmlFor: id }, input, addressNode(address)) }; };
  const ticked = (free, boxes) => free.filter((item, index) => boxes[index]?.input.checked === true);
  /// The addresses of the list that are free now, by proven rows.
  async function freeAddresses() {
    const book = await readBook();
    if (!book.items.length) return { book, free: [] };
    const { states } = await addressStates(book.items);
    // An address a stop order keeps aside (market-trade-ui.mjs) is not offered to another order.
    const aside = new Set(reserved());
    return { book, free: book.items.filter(item => states.get(item.script).usable && !aside.has(item.script)) };
  }
  const needAddresses = root => { root.append(p('You need a free receiving address of your own Bitcoin wallet first: buyers pay you there.'), el('div', { class: 'button-row' }, button('My Bitcoin addresses', () => go('addresses'), '', 'market-need-addresses'))); return root; };
  async function sellView() {
    const root = el('div', { id: 'market-sell' }, el('h2', { text: 'Sell seconds for bitcoin', id: 'market-view-title', tabIndex: -1 }),
      p('You offer seconds at your price. A buyer pays the bitcoin to one of your addresses, and gets the seconds when the payment has its confirmations. Until then your seconds are held by the chain.'));
    const { free } = await freeAddresses();
    if (!free.length) return needAddresses(root);
    const state = await proven(), r = rules(state), defaults = sellDefaults(r), last = sdk.marketSummary(state).last_price;
    const boxes = free.slice(0, r.scripts).map((item, index) => checkbox(`market-sell-address-${index}`, item.script, item.address, index === 0));
    root.append(el('form', { id: 'market-sell-form', on: { submit: event => { event.preventDefault(); c.run(() => reviewSell(free, boxes)); } } },
      ...field('market-sell-amount', 'Seconds to sell', { class: 'money', inputMode: 'decimal', placeholder: '60' }),
      ...field('market-sell-price', 'Your price, in satoshis for one second', { inputMode: 'decimal', placeholder: last ? priceText(last).replaceAll(',', '') : '250' }),
      p(last ? `Last recorded trade: ${priceWords(last)}. ${SELL_WORDS.record}` : `No trade has been recorded yet. A recorded trade would be a record, not a quote: ${SELL_WORDS.record.slice(SELL_WORDS.record.indexOf('anyone'))}`, 'field-note'),
      el('h3', { text: 'Where buyers pay you' }), p('Tick as many of your addresses as purchases you want this order to serve at once: each purchase uses one, once.', 'field-note'), ...boxes.map(box => box.node),
      el('details', { class: 'market-terms' }, el('summary', { text: 'Terms for buyers' }),
        ...field('market-sell-confirmations', 'Confirmations you ask of a payment', { inputMode: 'numeric', value: defaults.confirmations }, `From ${r.kMin} to ${r.kMax}. More is safer for you and slower for the buyer.`),
        ...field('market-sell-blocks', 'Time to pay, in Bitcoin blocks', { inputMode: 'numeric', value: defaults.payBlocks }, `From ${r.nMin} to ${r.nMax}. ${r.blockMicros === null ? 'On this test chain a block comes when its operator makes one.' : `${defaults.payBlocks} blocks are ${blocksDuration(defaults.payBlocks, r.blockMicros)}.`}`),
        ...field('market-sell-min', 'Smallest purchase, in satoshis', { inputMode: 'numeric', placeholder: 'suggested' }, `Left empty: the order shared over the addresses you ticked, so that they are enough to sell all of it; at least ${grouped(r.minSats)}.`),
        ...field('market-sell-deposit', 'Deposit a buyer locks, in percent', { inputMode: 'decimal', value: percentText(defaults.depositPpm).replace('%', '') }, 'What a buyer loses to you if they take your offer and do not pay.'),
        ...field('market-sell-min-deposit', 'Least deposit, in seconds', { inputMode: 'decimal', value: '0' }, 'So that small purchases cannot use up your addresses for almost nothing.')),
      warnings(SELL_WORDS.publicNow, SELL_WORDS.only, SELL_WORDS.hold, SELL_WORDS.final), paymentBox(),
      el('button', { type: 'submit', text: 'Review my offer', id: 'market-sell-review' })));
    return root;
  }
  const typed = id => ($(id)?.value ?? '').trim();
  const secondsOrZero = text => (text === '' || /^0(?:\.0{1,6})?$/.test(text) ? '0' : c.parseSeconds(text));
  /// Every address chosen is read PROVEN before it is signed into an order: it must be free now.
  async function provenFree(chosen, extra = {}) {
    const state = await proven({ market_scripts: chosen.map(item => item.script), ...extra });
    for (const item of chosen) assert(sdk.marketScript(state, item.script).status === 'free', `The address ${item.address} is no longer free: an order lists it, or a purchase used it. Nothing was signed. Choose another.`);
    return state;
  }
  /// After new addresses were signed into an order: the order is read back, proven, and what it holds is compared
  /// with what was chosen. `made` is what "My purchases and orders" then shows at its top.
  async function readBack(id, chosen) {
    const state = await proven({ market_orders: [id] }), order = sdk.marketOrder(state, id);
    assert(order, 'The order was signed, but the chain does not hold it now. Look under "My purchases and orders".');
    const held = order.scripts.filter(entry => entry.used !== true).map(entry => entry.script), addresses = [];
    for (const script of held) addresses.push(await toAddress(script, state));
    return { order: id, addresses, height: state.height, same: chosen.every(item => held.includes(item.script)) };
  }
  async function reviewSell(free, boxes) {
    const account = me(), r = rules(), chosen = ticked(free, boxes);
    const amountMicros = c.parseSeconds(typed('market-sell-amount')), price = parsePrice(typed('market-sell-price'));
    const confirmations = parseWhole(typed('market-sell-confirmations'), 'Confirmations', r.kMin, r.kMax), payBlocks = parseWhole(typed('market-sell-blocks'), 'Time to pay', r.nMin, r.nMax);
    const depositPpm = parsePercent(typed('market-sell-deposit'), 'Deposit'), minDepositMicros = secondsOrZero(typed('market-sell-min-deposit'));
    assert(chosen.length > 0, 'Tick at least one of your Bitcoin addresses. Each purchase uses one.');
    const minSats = typed('market-sell-min') === '' ? suggestedMinSats(sdk, amountMicros, price, chosen.length, r) : parseWhole(typed('market-sell-min'), 'Smallest purchase', r.minSats, r.satsMax);
    const refusal = termsRefusal(sdk, { side: 'sell', amountMicros, price, confirmations, payBlocks, depositPpm, minDepositMicros, minSats, scripts: chosen.map(item => item.script) }, r);
    assert(refusal === null, refusal);
    const state = await provenFree(chosen, { market_accounts: [account.id] }), before = sdk.marketAccount(state, account.id).orders, total = sdk.marketSats(amountMicros, price);
    const receipt = await act({ kind: 'market_order', payload: sdk.marketSellOrder({ amountMicros, price, scripts: chosen.map(item => item.script), confirmations, payBlocks, minSats, depositPpm, minDepositMicros }),
      label: `Offer ${seconds(amountMicros)} s for bitcoin`, title: 'Sell seconds for bitcoin', confirm: `Offer ${seconds(amountMicros)} seconds`, charge: { locked: amountMicros }, what: 'The seconds you offer and the fees',
      acknowledge: 'These addresses are in my own Bitcoin wallet, and I use them for nothing else.',
      fields: [['You sell', `${seconds(amountMicros)} seconds`], ['Price', priceWords(price)], ['You receive', `${bitcoinWords(total)} when all of it is sold, paid to your addresses below`],
        ...chosen.map((item, index) => [`Address ${index + 1}`, groupedAddress(item.address)]), ['Public', SELL_WORDS.publicNow],
        ['Smallest purchase', `${grouped(minSats)} satoshis`], ['Buyers pay within', `${payBlocks} Bitcoin blocks, ${blocksDuration(payBlocks, r.blockMicros)}`], ['Confirmations', confirmations],
        ['Deposit of a buyer', `${percentText(depositPpm)} of the purchase${minDepositMicros === '0' ? '' : `, at least ${seconds(minDepositMicros)} seconds`}`]],
      total: fee => `${seconds(BigInt(amountMicros) + fee)} seconds leave your balance now. What is not sold comes back when you cancel.` });
    if (!receipt) return;
    const id = await madeNow(account.id, before, 'orders');
    await c.refresh();
    if (id === null) { await go('mine'); c.notice('The order was signed and is in a block, but this browser does not see it among your orders yet. Look again in a moment.'); return; }
    await go('mine', { made: await readBack(id, chosen) });
    c.notice('Your order is on the chain. Compare the addresses it holds with your Bitcoin wallet.');
  }

  // ---------------------------------------------------------------- B. my purchases and orders
  /// Everything of the account in the market, from PROVEN rows: the account's own row names the orders it owns and the
  /// fills it pays; the list names the fills it has a part in without paying them, and each of those is then read
  /// proven and must name this account, or it is left out.
  async function readMine() {
    const account = me(), first = await proven({ market_accounts: [account.id] }), own = sdk.marketAccount(first, account.id);
    let listed = null, listError = '';
    try { listed = await c.api.account(account.id); } catch (error) { listError = error instanceof Error ? error.message : ''; }
    const orders = new Map(), fills = new Map();
    let state = first;
    for (const ids of pieces(own.orders, sdk.MARKET_SELECTION.market_orders)) { state = await proven({ market_orders: ids }); for (const id of ids) { const row = sdk.marketOrder(state, id); if (row && row.owner === account.id) orders.set(id, row); } }
    const named = [...orders.values()].flatMap(order => (order.side === 'sell' ? order.scripts.filter(entry => entry.fill !== undefined).map(entry => entry.fill) : []));
    const wanted = [...new Set([...own.fills, ...named, ...(listed ? listed.fills.map(fill => fill.id) : [])])];
    for (const ids of pieces(wanted, sdk.MARKET_SELECTION.market_fills)) {
      state = await proven({ market_fills: ids });
      for (const id of ids) { const row = sdk.marketFill(state, id); if (row && [row.payer, row.owner, row.to].includes(account.id)) fills.set(id, { row, time: payWindow(sdk, state, row), expiry: sdk.marketExpiry(state, row), state }); }
    }
    return { account, state, orders, fills, listed, listError };
  }
  async function mineView() {
    const { account, state, orders, fills, listed, listError } = await readMine(), r = rules(state);
    const root = el('div', { id: 'market-mine' }, el('h2', { text: 'My purchases and orders', id: 'market-view-title', tabIndex: -1 }));
    if (view.made) {
      const made = view.made;
      root.append(el('div', { class: 'result', id: 'market-made', attrs: { role: 'status' } }, el('h3', { text: `Order ${made.order} is on the chain` }), p(SELL_WORDS.readBack),
        ...made.addresses.map(address => addressNode(address)), p(`Read back and checked by this browser at block ${made.height}.`, 'field-note'),
        made.same ? null : p('The order on the chain does not hold all the addresses you chose. Cancel it now, below, and check your list of addresses.', 'warning')));
    }
    if (listError) root.append(p(`${listError} What is shown here is what the chain itself lists for your account; a sale into someone's buy order, or a purchase someone prepared for you, may be missing.`, 'nudge'));
    if (listed) for (const text of indexWarningsOf(listed.index)) root.append(p(text, 'nudge'));
    const pay = [...fills.values()].filter(({ row }) => row.to === account.id || row.payer === account.id);
    root.append(el('h3', { text: 'Purchases' }));
    const purchases = el('div', { class: 'market-list', id: 'market-purchases' });
    if (!pay.length) purchases.append(p('No open purchase.', 'subtle'));
    for (const { row, time } of pay) purchases.append(listRow(`Purchase ${row.id}: ${seconds(row.amount_micros)} seconds`,
      `Still to pay: ${bitcoinWords(row.sats)}. ${time.over ? 'The time to pay is over on the chain.' : `Pay by Bitcoin block ${time.payBy}: ${time.blocksLeft} left, ${blocksDuration(time.blocksLeft, r.blockMicros)}.`}${row.payer !== account.id ? ` Prepared for you by account ${row.payer}.` : row.to !== account.id ? ` You prepared it for account ${row.to}.` : ''}`,
      el('button', { type: 'button', class: 'secondary', text: 'Open', on: { click: () => { go('pay', { fill: row.id }).catch(() => {}); } } })));
    root.append(purchases, el('h3', { text: 'Orders' }));
    const sales = [...fills.values()].filter(({ row }) => row.owner === account.id);
    if (c.secured() && (orders.size || sales.length)) add(root, paymentBox(), p('Type your payment password, then press an action below. It is used for that one action.', 'field-note'));
    const list = el('div', { id: 'market-orders' });
    if (!orders.size) list.append(p('No open order.', 'subtle'));
    for (const order of orders.values()) list.append(await orderBlock(order, sales.filter(({ row }) => row.order === order.id), state, r));
    root.append(list);
    const into = sales.filter(({ row }) => !orders.has(row.order));
    if (into.length) { root.append(el('h3', { text: 'Your sales into buy orders' })); for (const sale of into) root.append(await saleRow(sale, r)); }
    if (listed?.ended.length) root.append(el('details', { class: 'market-terms' }, el('summary', { text: 'Ended, as the market\'s list says' }), ...listed.ended.slice(0, 20).map(item => p(`Fill ${item.fill}: ${item.how === 'unknown' ? 'ended' : item.how}.`, 'subtle'))));
    root.append(checkedAt(state));
    return root;
  }
  /// A purchase of the account's own seconds: who pays, what is still to pay, and the two things its owner can do.
  async function saleRow({ row, time, expiry, state }, r) {
    const address = await toAddress(row.script, state);
    return el('div', { class: 'market-address-row' }, el('p', {}, el('strong', { text: `Purchase ${row.id} by account ${row.payer}: ${seconds(row.amount_micros)} seconds` })),
      p(`Still to pay to you: ${bitcoinWords(row.sats)}. ${time.over ? 'The time to pay is over on the chain.' : `The buyer has until Bitcoin block ${time.payBy}: ${time.blocksLeft} left, ${blocksDuration(time.blocksLeft, r.blockMicros)}.`}`, 'subtle'), addressNode(address),
      el('div', { class: 'button-row' }, ...(expiry.possible ? [button('End it: not paid in time', () => endUnpaid(row.id))] : []), button('Hand over without proof', () => settle(row.id))));
  }
  async function orderBlock(order, sales, state, r) {
    const sell = order.side === 'sell', block = el('div', { class: 'market-pay', id: `market-order-${order.id}` });
    block.append(el('p', { class: 'eyebrow', text: `${sell ? 'Sell' : 'Buy'} order ${order.id}${order.open ? '' : ' · cancelled'}` }),
      el('p', { class: 'market-amount', text: `${seconds(order.amount_micros)} seconds` }, el('small', { text: `${order.open ? 'left' : 'nothing left'}, at ${priceWords(order.price)}` })));
    if (!order.open) block.append(p('You cancelled this order. It goes when its open purchases have ended.', 'subtle'));
    if (sell) {
      block.append(el('p', { class: 'eyebrow', text: 'Its addresses' }));
      for (const entry of order.scripts) block.append(addressNode(await toAddress(entry.script, state)), el('p', {}, el('span', { class: `tag market-${entry.used ? 'used' : entry.fill !== undefined ? 'in_use' : 'free'}`, text: entry.used ? 'Used' : entry.fill !== undefined ? 'In use' : 'Free' }),
        el('span', { class: 'subtle', text: entry.used ? ' A purchase used it. It is never offered again.' : entry.fill !== undefined ? ` Purchase ${entry.fill} pays to it.` : ' The next purchase gets it.' })));
      if (order.open && !freeScript(order)) block.append(p('No free address is left: nobody can take this order until you add one.', 'warning'));
    } else block.append(p(`Your bond for what is left: ${seconds(order.bond_micros)} seconds. When a seller fills this order you must pay within ${order.pay_blocks} Bitcoin blocks (${blocksDuration(order.pay_blocks, r.blockMicros)}), or you lose that part of the bond.`, 'subtle'));
    for (const sale of sales) block.append(await saleRow(sale, r));
    if (order.open) block.append(el('div', { class: 'button-row' }, ...(sell ? [button('Add addresses', () => go('add', { order: order.id }), 'secondary', `market-add-${order.id}`)] : []), button('Cancel this order', () => cancelOrder(order.id), 'secondary', `market-cancel-${order.id}`)));
    return block;
  }
  async function cancelOrder(id) {
    const account = me(), state = await proven({ market_orders: [id] }), order = sdk.marketOrder(state, id);
    assert(order && order.owner === account.id && order.open, 'This order is gone or cancelled already.');
    const back = order.side === 'sell' ? order.amount_micros : order.bond_micros, open = order.side === 'sell' ? order.scripts.filter(entry => entry.fill !== undefined).length : Number(order.fills);
    const receipt = await act({ kind: 'market_cancel', payload: sdk.marketCancel({ order: id }), label: `Cancel order ${id}`, title: 'Cancel this order', confirm: 'Cancel the order', charge: { back }, what: 'The fee',
      fields: [['Order', `${order.side === 'sell' ? 'Sell' : 'Buy'} order ${id}`], ['Comes back', `${seconds(back)} seconds, to your balance`], ['Open purchases', open ? `${open} still open. Each goes on until it is paid, given up or out of time.` : 'None']] });
    if (!receipt) return;
    await c.refresh(); await go('mine'); c.notice('The order was cancelled. What was left of it is back in your balance.');
  }
  async function settle(id) {
    const account = me(), state = await proven({ market_fills: [id] }), fill = sdk.marketFill(state, id);
    assert(fill && fill.owner === account.id, 'This purchase has ended, or its seconds are not yours.');
    const receipt = await act({ kind: 'market_settle', payload: sdk.marketSettle({ fill: id }), label: `Hand over purchase ${id} without proof`, title: 'Hand over without proof', confirm: 'Hand over the seconds', charge: { extra: fill.amount_micros }, what: 'Handing over',
      acknowledge: 'I see the whole payment in my own Bitcoin wallet, with enough confirmations.',
      fields: [['Purchase', `Fill ${id}`], ['You hand over', `${seconds(fill.amount_micros)} seconds, to account ${fill.to}`], ['Not proven', `${bitcoinWords(fill.sats)}: the chain has seen no proof of it`], ['Warning', SELL_WORDS.settle]] });
    if (!receipt) return;
    await c.refresh(); await go('mine'); c.notice('The seconds were handed over, without a proof of payment.');
  }
  async function endUnpaid(id) {
    const account = me(), state = await proven({ market_fills: [id] }), fill = sdk.marketFill(state, id);
    assert(fill, 'This purchase has ended already.'); assert(sdk.marketExpiry(state, fill).possible, 'This purchase cannot end yet: the buyer still has time, or a proof may still come.');
    const receipt = await act({ kind: 'market_expire', payload: sdk.marketExpire({ fill: id }), label: `End unpaid purchase ${id}`, title: 'End a purchase that was not paid', confirm: 'End the purchase', what: 'The fee',
      charge: { back: fill.owner === account.id ? fill.deposit_micros : '0' },
      fields: [['Purchase', `Fill ${id}`], ['Why', 'It was not paid in time.'], ['Its seconds', `${seconds(fill.amount_micros)} seconds go back to the order, or to its owner's balance`], ['The deposit', `${seconds(fill.deposit_micros)} seconds go to the owner of the seconds`]] });
    if (!receipt) return;
    await c.refresh(); await go('mine'); c.notice('The purchase was ended. Its seconds are back, and the deposit went to the seller.');
  }
  async function addView() {
    const id = String(view.order), root = el('div', { id: 'market-add' }, el('h2', { text: `New addresses for order ${id}`, id: 'market-view-title', tabIndex: -1 }),
      p('An order needs a free address for each new purchase. Used ones leave its list; the new ones join it.'));
    const { free } = await freeAddresses();
    if (!free.length) return needAddresses(root);
    const boxes = free.slice(0, 16).map((item, index) => checkbox(`market-add-address-${index}`, item.script, item.address, index === 0));
    root.append(el('form', { id: 'market-add-form', on: { submit: event => { event.preventDefault(); c.run(() => addAddresses(id, free, boxes)); } } }, ...boxes.map(box => box.node), warnings(SELL_WORDS.publicNow, SELL_WORDS.only,
      'New addresses count against your daily limit like a new order: the seconds the order still offers and those in its open purchases.'), paymentBox(), el('button', { type: 'submit', text: 'Review the new addresses', id: 'market-add-review' })));
    return root;
  }
  async function addAddresses(id, free, boxes) {
    const account = me(), chosen = ticked(free, boxes);
    assert(chosen.length > 0, 'Tick at least one address.');
    const state = await provenFree(chosen, { market_orders: [id] }), order = sdk.marketOrder(state, id);
    assert(order && order.owner === account.id && order.open && order.side === 'sell', 'This order is gone or cancelled.');
    const open = order.scripts.filter(entry => entry.fill !== undefined).map(entry => entry.fill), kept = order.scripts.filter(entry => entry.used !== true).length;
    assert(kept + chosen.length <= rules(state).scripts, `An order holds at most ${rules(state).scripts} addresses that have not served. This one has ${kept}.`);
    let inFills = 0n;
    if (open.length) { const more = await proven({ market_fills: open }); for (const fill of open) inFills += BigInt(sdk.marketFill(more, fill)?.amount_micros ?? '0'); }
    const receipt = await act({ kind: 'market_scripts', payload: sdk.marketNewScripts({ order: id, scripts: chosen.map(item => item.script) }), label: `New addresses for order ${id}`, title: 'New addresses for your order', confirm: 'Add these addresses',
      charge: { extra: (BigInt(order.amount_micros) + inFills).toString() }, what: 'New addresses', acknowledge: 'These addresses are in my own Bitcoin wallet, and I use them for nothing else.',
      fields: [['Order', `Sell order ${id}`], ...chosen.map((item, index) => [`Address ${index + 1}`, groupedAddress(item.address)]), ['Public', SELL_WORDS.publicNow]] });
    if (!receipt) return;
    await c.refresh(); await go('mine', { made: await readBack(id, chosen) }); c.notice('The new addresses are in your order. Compare them with your Bitcoin wallet.');
  }

  // ---------------------------------------------------------------- the menu
  async function menuView() {
    const root = el('div', { id: 'market-menu' }, el('h2', { text: 'Buy and sell seconds for bitcoin', id: 'market-view-title', tabIndex: -1 }), p(MARKET_WORDS.lede), p(`${MARKET_WORDS.slow} ${MARKET_WORDS.noKey}`, 'subtle'));
    const state = await proven({ market_accounts: [me().id] }), own = sdk.marketAccount(state, me().id);
    showHome(own);
    if (own.fills.length) root.append(el('p', { class: 'nudge', id: 'market-open-note' }, el('span', { text: `You have ${own.fills.length} open purchase${own.fills.length === 1 ? '' : 's'} to pay. ` }), link('See what to pay', 'mine')));
    // A purchase someone else prepared for this account is in no proven list of it (spec/market.md, 4): the market's
    // list points to it, and "My purchases and orders" then reads it from the chain.
    let prepared = 0;
    try { prepared = (await c.api.account(me().id)).fills.filter(fill => fill.to === me().id && fill.payer !== me().id).length; } catch { prepared = 0; }
    if (prepared) root.append(el('p', { class: 'nudge', id: 'market-prepared-note' }, el('span', { text: `The market's list names ${prepared} purchase${prepared === 1 ? '' : 's'} that someone else prepared for you. ` }), link('Check before you pay', 'mine')));
    const list = el('div', { class: 'market-list' });
    for (const [id, title, detail, target] of menuEntries()) list.append(listRow(title, detail, el('button', { type: 'button', class: 'secondary', id, text: 'Open', on: { click: () => { go(target).catch(() => {}); } } })));
    root.append(list);
    return root;
  }
  function menuEntries() {
    return [['market-open-buy', 'Buy seconds', 'Pay with bitcoin from your own Bitcoin wallet.', 'buy'], ['market-open-sell', 'Sell seconds', 'Get bitcoin to an address of your own Bitcoin wallet.', 'sell'],
      ['market-open-mine', 'My purchases and orders', 'What you still have to pay, what you offer, and what buyers owe you.', 'mine'], ['market-open-addresses', 'My Bitcoin addresses', 'Where buyers pay you. Needed before you sell.', 'addresses'],
      ...(c.trade ? [['market-open-trade', 'For traders', 'The order book, recorded trades, a chart, every order form, and stop orders kept by this wallet.', 'trade']] : [])];
  }
  /// What Home says of the market: how many purchases of this account are open, from its proven row.
  function showHome(own) { const node = $('home-market'); if (node) node.textContent = own.fills.length ? `${own.fills.length} to pay` : 'Open'; lastHome = Date.now(); }

  // ---------------------------------------------------------------- the traders' view (market-trade-ui.mjs)
  // It is drawn with the tools of this module: the same proven reads, the same review, the same signing.
  const noteFill = (id, row) => { if (row) c.storage.setItem(notesKey(net(), name()), withNote(c.storage.getItem(notesKey(net(), name())), id, { firstSats: row.sats, order: row.order })); };
  const kit = { $, el, p, button, link, field, facts, warnings, listRow, addressNode, checkedAt, proven, me, rules, seconds, act, go, freeAddresses, freshnessWarning, indexWarningsOf, paymentBox, typed, freeScript, toAddress, needAddresses, noteFill, provenFree, readBack, name, net,
    reserve: list => { reserved = list; }, viewName: () => view.name, home: text => { const node = $('home-market'); if (node) node.textContent = text; } };
  const trade = c.trade ? c.trade(kit, c) : null;

  // ---------------------------------------------------------------- drawing
  const VIEWS = { menu: menuView, addresses: addressesView, buy: buyView, pay: payView, sell: sellView, mine: mineView, add: addView, ...(trade ? { trade: trade.view } : {}) };
  /// `moved`: the person went to this view (its title then takes the focus); a view that is only read again keeps the focus where it is.
  async function draw(moved = false) {
    const turn = ++drawn, root = $('market-view');
    if (!root || !on) return;
    $('market-back').hidden = view.name === 'menu';
    let content;
    try { await ready(); content = bitcoin() === 'mainnet' ? p(MARKET_WORDS.closed) : await (VIEWS[view.name] ?? menuView)(); }
    catch (error) { content = el('div', {}, p(error instanceof Error && Object.getPrototypeOf(error) === Error.prototype ? error.message : 'This part of the market could not be shown.', 'warning'), button('Try again', () => draw())); }
    if (turn !== drawn) return;
    // The payment password field outlives every view: a view that did not ask for it leaves it at the foot, hidden.
    if (payWrap && claimed !== turn) { payWrap.hidden = true; $('market-card')?.append(payWrap); }
    root.replaceChildren(content);
    if (moved) $('market-view-title')?.focus?.();
  }
  /// From app.js, at every verified reading of the open account: whether this network has the market at all, and what
  /// Home says of it. A view that is open is not drawn again here: a person may be typing in it.
  function render(account, state) {
    let has = false;
    try { has = sdk.marketSetting(state) === true; } catch { has = false; }
    const was = on; on = has;
    for (const id of ['tab-market', 'home-market-row']) { const node = $(id); if (node) node.hidden = !has; }
    if (!has) { $('market-view')?.replaceChildren(); return; }
    const note = $('market-test-note'); if (note) { note.textContent = testBitcoinWords(bitcoin(state)); note.hidden = false; }
    if (!was) { draw().catch(() => {}); return; }
    // A purchase that is open on the page is read again, proven, as the wallet reads the account again: at most every
    // twenty seconds, so that a press is not lost to a page that changes under it. Home's line follows once a minute.
    // The stop orders this wallet keeps are looked at while it is open and unlocked (market-trade-ui.mjs, watch).
    trade?.watch?.().catch(() => {});
    const now = Date.now();
    if (view.name === 'pay' && now - lastPay > 20000 && c.idle?.() !== false) { lastPay = now; draw().catch(() => {}); }
    else if (now - lastHome > 60000) { lastHome = now; proven({ market_accounts: [account.id] }).then(state => showHome(sdk.marketAccount(state, account.id))).catch(() => {}); }
  }
  function reset() {
    on = false; view = { name: 'menu' }; drawn += 1; lastHome = 0; takePassword();
    for (const id of ['tab-market', 'home-market-row']) { const node = $(id); if (node) node.hidden = true; }
    if (payWrap) { payWrap.hidden = true; $('market-card')?.append(payWrap); }
    $('market-view')?.replaceChildren();
  }
  function start() {
    payWrap = $('market-payment-wrap'); payInput = $('market-payment');
    $('market-back')?.addEventListener('click', () => { go('menu').catch(() => {}); });
    $('home-market-row')?.addEventListener('click', () => { c.showPanel('market'); });
  }
  return { render, reset, start, go, view: () => view.name };
}
