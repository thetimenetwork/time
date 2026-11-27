// The traders' view of the wallet's market (spec/market.md): the order book with its depth, recorded trades, a candle
// chart drawn here (no library), every order form with every term, and the stop orders this wallet keeps. It is
// drawn into the market's panel by market-ui.mjs, which hands in its tools (`kit`): the same proven reads, the same
// review and the same signing as the simple part. Nothing here signs by another way.
//
// The book, the trades and the chart are LISTS of the market's service and are shown as such, with the service's own
// flags when they are not clean. An order form reads the order it acts on through the wallet's verifier and puts the
// proven row into the review. The chain's own hourly candles are checked against proven rows; the words say
// "recorded" wherever a price of the past is shown (market-trade.mjs).
import { RECORD_WORDS, STOP_WORDS, bookLevels, share, candleGeometry, candlesDiffer, stopsKey, readStops, writeStops, stopOrder, stopRefusal, bookPrice, stopFires, reservedScripts, STOP_TRADES_MIN, STOP_LIMIT } from './market-trade.mjs';
import { SELL_WORDS, priceText, priceWords, parsePrice, parseWhole, parsePercent, percentText, bitcoinWords, btcText, grouped, groupedAddress, blocksDuration, sizeRefusal, takeDeposit, buyBond, ownerStands, headerChain, termsRefusal, leastAmountFor, newId, sellDefaults, suggestedMinSats } from './market.mjs';

const assert = (value, message) => { if (!value) throw new Error(message); };
const SVG = 'http://www.w3.org/2000/svg';
export const TRADE_WORDS = Object.freeze({
  awake: 'A buy order needs you awake. When a seller fills it, you must pay the bitcoin within the time to pay, or you lose that part of your bond. Sixteen small sales mean sixteen payments.',
  forOther: 'You take this for another account. The deposit is yours, but only that account can give the purchase up: if it does not pay, your deposit goes to the seller.',
  into: 'You sell into a buy order. Your seconds are held by the chain until the buyer\'s payment is proven, the buyer gives up, or the time has passed. The buyer\'s bond is what you get if they do not pay.',
});

/// `kit`: market-ui.mjs's tools. `c`: what app.js handed market-ui.mjs.
export function createTradeView(kit, c) {
  const { el, p, button, field, facts, warnings, addressNode, proven, me, rules, seconds, act, go, freeAddresses, freshnessWarning, indexWarningsOf, paymentBox, typed, freeScript, toAddress } = kit;
  const sdk = c.sdk, doc = c.doc ?? globalThis.document;
  const svg = (tag, attrs = {}, ...children) => { const node = doc.createElementNS(SVG, tag); for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value)); node.append(...children); return node; };
  const cell = (text, className = '') => el('td', { text, class: className });
  const table = (id, heads, rows) => el('table', { class: 'market-table', id }, el('thead', {}, el('tr', {}, ...heads.map(text => el('th', { text, attrs: { scope: 'col' } })))), el('tbody', {}, ...rows));
  const part = async (title, make) => { try { return await make(); } catch (error) { return el('section', {}, el('h3', { text: title }), p(error instanceof Error && Object.getPrototypeOf(error) === Error.prototype ? error.message : 'This could not be shown.', 'nudge')); } };
  // What the screen keeps between two drawings.
  const kept = { interval: 'hour', form: 'take', order: '' };

  // ---------------------------------------------------------------- the book, with its depth
  async function bookSection() {
    const [sell, buy] = [await c.api.orders('sell'), await c.api.orders('buy')];
    const section = el('section', { id: 'market-book' }, el('h3', { text: 'Order book' }), p(RECORD_WORDS.book, 'field-note'));
    for (const text of indexWarningsOf(sell.index)) section.append(p(text, 'nudge'));
    const stale = await freshnessWarning(); if (stale) section.append(p(stale, 'nudge'));
    const side = (title, id, listed, form, word) => {
      const { levels, totalMicros } = bookLevels(listed.items);
      const rows = levels.map(level => el('tr', {}, cell(priceText(level.price), 'num'), cell(seconds(level.amountMicros), 'num'),
        el('td', {}, el('progress', { class: 'bar', max: 1000, value: share(level.sumMicros, totalMicros), attrs: { 'aria-label': `${seconds(level.sumMicros)} seconds up to this price` } }), el('small', { text: `${seconds(level.sumMicros)} · order ${level.orders.join(', ')}` })),
        el('td', {}, level.takes ? el('button', { type: 'button', class: 'secondary', text: word, on: { click: () => { kept.form = form; kept.order = level.orders[0]; go('trade').then(() => kit.$('market-trade-forms')?.scrollIntoView?.({ block: 'start' })).catch(() => {}); } } }) : el('small', { text: 'No free place' }))));
      return el('div', { class: 'market-side' }, el('h4', { text: title }), levels.length ? table(id, ['Price', 'Seconds', 'Depth', ''], rows) : p('None.', 'subtle'));
    };
    section.append(el('div', { class: 'market-sides' }, side('Sell orders, lowest price first', 'market-asks', sell, 'take', 'Take'), side('Buy orders, highest price first', 'market-bids', buy, 'into', 'Sell')), p('Prices are satoshis for one second.', 'field-note'));
    return section;
  }

  // ---------------------------------------------------------------- recorded trades
  async function tradesSection() {
    const listed = await c.api.trades(15);
    const section = el('section', { id: 'market-trades' }, el('h3', { text: 'Recorded trades' }), p(RECORD_WORDS.trades, 'field-note'));
    for (const text of indexWarningsOf(listed.index)) section.append(p(text, 'nudge'));
    const rows = listed.items.filter(item => item.price !== null).map(item => el('tr', {}, cell(item.height ?? '', 'num'), cell(priceText(item.price), 'num'), cell(seconds(item.seconds_micros ?? '0'), 'num'), cell(btcText(item.sats ?? '0'), 'num')));
    section.append(rows.length ? table('market-tape', ['Block', 'Recorded price', 'Seconds', 'BTC'], rows) : p('No payment has been proven yet.', 'subtle'));
    return section;
  }

  // ---------------------------------------------------------------- the chart of recorded prices
  const INTERVALS = [['hour', 'The chain\'s own'], ['15m', '15 minutes'], ['1d', 'Days']];
  async function chartSection() {
    const listed = await c.api.candles(kept.interval, 60), candles = listed.items.slice().reverse();
    const section = el('section', { id: 'market-chart-section' }, el('h3', { text: 'Recorded prices' }), p(RECORD_WORDS.chart, 'field-note'));
    section.append(el('div', { class: 'chips', attrs: { role: 'group', 'aria-label': 'Length of a candle' } }, ...INTERVALS.map(([key, text]) => el('button', { type: 'button', class: `chip${kept.interval === key ? ' active' : ''}`, text, attrs: { 'aria-pressed': String(kept.interval === key) }, on: { click: () => { kept.interval = key; go('trade').catch(() => {}); } } }))));
    for (const text of indexWarningsOf(listed.index)) section.append(p(text, 'nudge'));
    if (!candles.length) { section.append(p('No payment has been proven yet, so there is nothing to draw.', 'subtle')); return section; }
    const W = 640, H = 240, shape = candleGeometry(candles, W, H);
    const drawing = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'market-chart', role: 'img', 'aria-label': `Recorded prices of ${shape.bars.length} intervals, from ${priceText(shape.low)} to ${priceText(shape.high)} satoshis for one second. The numbers are in the table below.` },
      ...[0.25, 0.5, 0.75].map(at => svg('line', { class: 'chart-grid', x1: 0, x2: W, y1: H * at, y2: H * at })),
      ...shape.bars.flatMap(bar => [svg('line', { class: 'candle-wick', x1: bar.wickX, x2: bar.wickX, y1: bar.top, y2: bar.bottom }), svg('rect', { class: bar.up ? 'candle-up' : 'candle-down', x: bar.x, y: bar.bodyTop, width: bar.width, height: bar.bodyHeight })]));
    section.append(el('div', { class: 'market-chart-frame' }, p(`${priceText(shape.high)}`, 'chart-high'), drawing, p(`${priceText(shape.low)}`, 'chart-low')),
      p(`Satoshis for one second. Highest and lowest recorded in the ${shape.bars.length} intervals drawn; an interval without a proven payment is not drawn. A hollow candle closed at or above where it opened, a filled one below.`, 'field-note'));
    // The chain's own candles are rows of its state: the newest are read through the verifier and compared.
    if (kept.interval === 'hour') {
      try {
        const newest = candles.slice(-sdk.MARKET_SELECTION.market_candles), state = await proven({ market_candles: newest.map(candle => candle.number) }), differ = candlesDiffer(newest, hour => sdk.marketCandle(state, hour));
        section.append(differ.length ? p(`The list's candles are not what the chain holds for ${differ.length} of the ${newest.length} newest intervals (number ${differ.slice(0, 5).join(', ')}). Do not rely on this chart.`, 'warning')
          : p(`The ${newest.length} newest candles are the rows the chain keeps: checked by this browser at block ${state.height}.`, 'field-note'));
      } catch { section.append(p('The candles could not be checked against the chain right now.', 'nudge')); }
    } else section.append(p('These candles are added up by the market\'s service from its list of trades. This browser cannot check them.', 'field-note'));
    section.append(el('details', { class: 'market-terms' }, el('summary', { text: 'The numbers' }), table('market-candles', ['Interval', 'Open', 'High', 'Low', 'Close', 'Seconds'], candles.slice(-24).reverse().map(candle => el('tr', {}, cell(candle.number, 'num'), cell(priceText(candle.open), 'num'), cell(priceText(candle.high), 'num'), cell(priceText(candle.low), 'num'), cell(priceText(candle.close), 'num'), cell(seconds(candle.seconds_micros), 'num'))))));
    return section;
  }

  // ---------------------------------------------------------------- the order forms
  const FORMS = [['take', 'Take a sell order'], ['into', 'Sell into a buy order'], ['buy', 'Post a buy order'], ['sell', 'Post a sell order']];
  const SCRIPT_FORMS = [['p2wpkh', 'bc1q… (SegWit)'], ['p2tr', 'bc1p… (Taproot)'], ['p2wsh', 'bc1q…, long (SegWit script)'], ['p2sh', '3… or 2… (script hash)'], ['p2pkh', '1…, m… or n… (legacy)']];
  async function formsSection() {
    const section = el('section', { id: 'market-trade-forms' }, el('h3', { text: 'Orders' }));
    section.append(el('div', { class: 'chips', attrs: { role: 'group', 'aria-label': 'Which order' } }, ...FORMS.map(([key, text]) => el('button', { type: 'button', class: `chip${kept.form === key ? ' active' : ''}`, id: `market-form-${key}`, text, attrs: { 'aria-pressed': String(kept.form === key) }, on: { click: () => { if (key === 'sell') { go('sell').catch(() => {}); return; } kept.form = key; kept.order = ''; go('trade').catch(() => {}); } } }))));
    const r = rules();
    if (kept.form === 'take') section.append(el('form', { id: 'market-take-form', on: { submit: event => { event.preventDefault(); c.run(reviewTake); } } },
      ...field('market-take-order', 'Sell order, by its number', { inputMode: 'numeric', value: kept.order }), ...field('market-take-amount', 'Seconds to buy', { inputMode: 'decimal' }),
      ...field('market-take-to', 'For account, by its number', { inputMode: 'numeric', value: me().id }, 'Your own account, unless you take this for someone else.'),
      p('The order is read from the chain when you press Review, and the review shows what the chain holds: its price, its terms and its seller.', 'field-note'), el('button', { type: 'submit', text: 'Review the take', id: 'market-take-review' })));
    if (kept.form === 'into') {
      const { free } = await freeAddresses();
      if (!free.length) return kit.needAddresses(section);
      const choice = el('select', { id: 'market-into-address' }, ...free.map(item => el('option', { value: item.script, text: `${groupedAddress(item.address)} (${item.form})` })));
      section.append(el('form', { id: 'market-into-form', on: { submit: event => { event.preventDefault(); c.run(() => reviewInto(free)); } } },
        ...field('market-into-order', 'Buy order, by its number', { inputMode: 'numeric', value: kept.order }), ...field('market-into-amount', 'Seconds to sell', { inputMode: 'decimal' }),
        ...field('market-into-confirmations', 'Confirmations you ask of the payment', { inputMode: 'numeric', placeholder: 'as many as the buyer waits for' }, `At least ${r.kMin}, and at most what the buy order says.`),
        el('label', { text: 'Your address for this sale', htmlFor: 'market-into-address' }), choice, p('One address, for this sale only. It must be of a kind the buyer can pay to.', 'field-note'),
        warnings(TRADE_WORDS.into, SELL_WORDS.publicNow, SELL_WORDS.only, SELL_WORDS.final), el('button', { type: 'submit', text: 'Review the sale', id: 'market-into-review' })));
    }
    if (kept.form === 'buy') section.append(el('form', { id: 'market-bid-form', on: { submit: event => { event.preventDefault(); c.run(reviewBid); } } },
      ...field('market-bid-amount', 'Seconds you want', { inputMode: 'decimal' }), ...field('market-bid-price', 'Your price, in satoshis for one second', { inputMode: 'decimal' }),
      el('fieldset', { class: 'kinds' }, el('legend', { text: 'Addresses your Bitcoin wallet can pay to' }), ...SCRIPT_FORMS.map(([form, text], index) => el('label', { class: 'market-check', htmlFor: `market-bid-form-${form}` }, el('input', { type: 'checkbox', id: `market-bid-form-${form}`, value: form, checked: index < 2 }), el('span', { text })))),
      ...field('market-bid-confirmations', 'Most confirmations you wait for', { inputMode: 'numeric', value: String(Math.max(Number(r.kMin), 6)) }, `From ${r.kMin} to ${r.kMax}. A seller may ask fewer.`),
      ...field('market-bid-blocks', 'Time you give yourself to pay, in Bitcoin blocks', { inputMode: 'numeric', value: String(Math.max(Number(r.nMin), 6)) }, `From ${r.nMin} to ${r.nMax}.`),
      ...field('market-bid-min', 'Smallest sale, in satoshis', { inputMode: 'numeric', value: r.minSats }),
      ...field('market-bid-bond', 'Your bond, in percent', { inputMode: 'decimal', value: percentText(BigInt(r.bondMinPpm) > 50000n ? r.bondMinPpm : '50000').replace('%', '') }, `At least ${percentText(r.bondMinPpm)}. Locked now; a part of it is lost each time you do not pay a sale in time.`),
      warnings(TRADE_WORDS.awake), el('button', { type: 'submit', text: 'Review the buy order', id: 'market-bid-review' })));
    return section;
  }
  const account = id => parseWhole(id, 'Account', 0, '18446744073709551615');
  async function reviewTake() {
    const mine = me(), id = parseWhole(typed('market-take-order'), 'Order', 1, '18446744073709551615'), amountMicros = c.parseSeconds(typed('market-take-amount')), to = account(typed('market-take-to'));
    let state = await proven({ market_orders: [id], market_accounts: [mine.id] }), order = sdk.marketOrder(state, id);
    assert(order && order.side === 'sell' && order.open, 'There is no open sell order with this number on the chain. Nothing was signed.');
    // The seller's own rows, and the account the seconds go to, from one more proven read; the order is read again with them.
    state = await proven({ market_orders: [id], market_accounts: [mine.id], ids: [...new Set([order.owner, to])], include_security: true }); order = sdk.marketOrder(state, id);
    assert(order && order.side === 'sell' && order.open, 'This order went while it was read. Nothing was signed.');
    assert(state.accounts.some(item => String(item.id) === to), `There is no account ${to} on the chain. Nothing was signed.`);
    assert(!headerChain(state).halted, 'The chain has stopped following Bitcoin, so no purchase can start. Nothing was signed.');
    assert(ownerStands(sdk, state, order, c.frozen) !== false, 'The seller of this order cannot sell right now. Nothing was signed.');
    assert(freeScript(order), 'This order has no free address left. Nothing was signed.');
    const refusal = sizeRefusal(sdk, order, amountMicros, rules(state)); assert(refusal === null, refusal);
    const sats = sdk.marketSats(amountMicros, order.price), deposit = takeDeposit(order, amountMicros), r = rules(state), stale = await freshnessWarning(), before = sdk.marketAccount(state, mine.id).fills;
    const receipt = await act({ kind: 'market_take', payload: sdk.marketTake({ order: id, amountMicros, price: order.price, to }), label: `Take ${seconds(amountMicros)} s of order ${id}`, title: 'Take a sell order', confirm: `Lock ${seconds(deposit)} s and take`, charge: { locked: deposit }, what: 'The deposit and the fee',
      acknowledge: to === mine.id ? 'I will pay the exact amount in time, from a Bitcoin wallet I control. If I do not, I lose the deposit.' : `Account ${to} will pay. If it does not, I lose the deposit.`,
      fields: [['Order', `Sell order ${id} of account ${order.owner}, read from the chain at block ${state.height}`], ['You take', `${seconds(amountMicros)} seconds, for account ${to}`], ['Price', priceWords(order.price)], ['To pay in bitcoin', bitcoinWords(sats)],
        ['Time to pay', `${order.pay_blocks} Bitcoin blocks, ${blocksDuration(order.pay_blocks, r.blockMicros)}. Then ${order.confirmations} confirmations.`], ...(to === mine.id ? [] : [['For another account', TRADE_WORDS.forOther]]), ...(stale ? [['Warning', stale]] : []),
        ['Deposit', `${seconds(deposit)} seconds, locked now. It comes back when the payment is proven, and goes to the seller if it is not paid in time or the purchase is given up.`]],
      total: fee => `${seconds(BigInt(deposit) + fee)} seconds leave your balance now` });
    if (!receipt) return;
    const fill = newId(before, sdk.marketAccount(await proven({ market_accounts: [mine.id] }), mine.id).fills);
    await c.refresh();
    if (fill) { kit.noteFill(fill, sdk.marketFill(await proven({ market_fills: [fill] }), fill)); await go('pay', { fill }); } else await go('mine');
    c.notice('The order was taken. The address and the amount to pay are read from the chain.');
  }
  async function reviewInto(free) {
    const mine = me(), id = parseWhole(typed('market-into-order'), 'Order', 1, '18446744073709551615'), amountMicros = c.parseSeconds(typed('market-into-amount')), script = kit.$('market-into-address')?.value ?? '', chosen = free.find(item => item.script === script);
    assert(chosen, 'Choose one of your addresses.');
    let state = await proven({ market_orders: [id], market_scripts: [script] }), order = sdk.marketOrder(state, id);
    assert(order && order.side === 'buy' && order.open, 'There is no open buy order with this number on the chain. Nothing was signed.');
    state = await proven({ market_orders: [id], market_scripts: [script], ids: [order.owner], include_security: true }); order = sdk.marketOrder(state, id);
    assert(order && order.side === 'buy' && order.open, 'This order went while it was read. Nothing was signed.');
    assert(sdk.marketScript(state, script).status === 'free', `The address ${chosen.address} is no longer free. Nothing was signed. Choose another.`);
    assert(order.forms.includes(chosen.form), `This buyer cannot pay to this kind of address (${chosen.form}). They pay to: ${order.forms.join(', ')}. Nothing was signed.`);
    assert(!headerChain(state).halted, 'The chain has stopped following Bitcoin, so no sale can start. Nothing was signed.');
    assert(ownerStands(sdk, state, order, c.frozen) !== false, 'The owner of this buy order cannot trade right now. Nothing was signed.');
    assert(Number(order.fills) < rules(state).buyFills, 'This buy order has as many open sales as it can have. Nothing was signed.');
    const r = rules(state), confirmations = typed('market-into-confirmations') === '' ? order.confirmations : parseWhole(typed('market-into-confirmations'), 'Confirmations', r.kMin, order.confirmations);
    const refusal = sizeRefusal(sdk, order, amountMicros, r); assert(refusal === null, refusal);
    const sats = sdk.marketSats(amountMicros, order.price), stale = await freshnessWarning();
    const receipt = await act({ kind: 'market_sell', payload: sdk.marketSell({ order: id, amountMicros, price: order.price, confirmations, script }), label: `Sell ${seconds(amountMicros)} s into order ${id}`, title: 'Sell into a buy order', confirm: `Sell ${seconds(amountMicros)} seconds`, charge: { locked: amountMicros }, what: 'The seconds you sell and the fee',
      acknowledge: 'This address is in my own Bitcoin wallet, and I use it for nothing else.',
      fields: [['Order', `Buy order ${id} of account ${order.owner}, read from the chain at block ${state.height}`], ['You sell', `${seconds(amountMicros)} seconds`], ['Price', priceWords(order.price)], ['You receive', `${bitcoinWords(sats)}, paid to your address`], ['Your address', groupedAddress(chosen.address)],
        ['The buyer pays within', `${order.pay_blocks} Bitcoin blocks, ${blocksDuration(order.pay_blocks, r.blockMicros)}`], ['Confirmations', confirmations], ['If the buyer does not pay', 'Your seconds come back, with the buyer\'s bond for this sale.'], ['Public', SELL_WORDS.publicNow], ...(stale ? [['Warning', stale]] : [])],
      total: fee => `${seconds(BigInt(amountMicros) + fee)} seconds leave your balance now` });
    if (!receipt) return;
    await c.refresh(); await go('mine');
    // The fill this sale made is the one the chain now names for the address.
    const row = sdk.marketScript(await proven({ market_scripts: [script] }), script);
    c.notice(row.status === 'in_use' ? `The sale is on the chain as purchase ${row.fill}. The buyer pays to your address; it is listed under "My purchases and orders".` : 'The sale was signed. Look under "My purchases and orders".');
  }
  async function reviewBid() {
    const mine = me(), r = rules(), amountMicros = c.parseSeconds(typed('market-bid-amount')), price = parsePrice(typed('market-bid-price'));
    const forms = SCRIPT_FORMS.map(([form]) => form).filter(form => kit.$(`market-bid-form-${form}`)?.checked === true);
    const confirmations = parseWhole(typed('market-bid-confirmations'), 'Confirmations', r.kMin, r.kMax), payBlocks = parseWhole(typed('market-bid-blocks'), 'Time to pay', r.nMin, r.nMax), minSats = parseWhole(typed('market-bid-min'), 'Smallest sale', r.minSats, r.satsMax), depositPpm = parsePercent(typed('market-bid-bond'), 'Bond');
    const refusal = termsRefusal(sdk, { side: 'buy', amountMicros, price, confirmations, payBlocks, depositPpm, minSats, forms }, r); assert(refusal === null, refusal);
    const bond = buyBond(amountMicros, depositPpm), total = sdk.marketSats(amountMicros, price), before = sdk.marketAccount(await proven({ market_accounts: [mine.id] }), mine.id).orders;
    const receipt = await act({ kind: 'market_order', payload: sdk.marketBuyOrder({ amountMicros, price, forms, confirmations, payBlocks, minSats, depositPpm }), label: `Bid for ${seconds(amountMicros)} s`, title: 'Post a buy order', confirm: `Lock ${seconds(bond)} s and post`, charge: { locked: bond }, what: 'The bond and the fee',
      acknowledge: 'I will be here to pay each sale in time, or I lose that part of my bond.',
      fields: [['You want', `${seconds(amountMicros)} seconds`], ['Price', priceWords(price)], ['You would pay', `${bitcoinWords(total)} in all, in as many payments as sellers fill it with`], ['You can pay to', forms.join(', ')],
        ['Time to pay each sale', `${payBlocks} Bitcoin blocks, ${blocksDuration(payBlocks, r.blockMicros)}`], ['Confirmations', `at most ${confirmations}`], ['Smallest sale', `${grouped(minSats)} satoshis`], ['Warning', TRADE_WORDS.awake],
        ['Bond', `${seconds(bond)} seconds (${percentText(depositPpm)}), locked now. What is left of it comes back when you cancel.`]],
      total: fee => `${seconds(BigInt(bond) + fee)} seconds leave your balance now` });
    if (!receipt) return;
    await c.refresh(); await go('mine');
    const id = newId(before, sdk.marketAccount(await proven({ market_accounts: [mine.id] }), mine.id).orders);
    c.notice(id ? `Your buy order ${id} is on the chain. Keep this wallet near: a seller can fill it at any time.` : 'The buy order was signed. Look under "My purchases and orders".');
  }

  // ---------------------------------------------------------------- stop orders, kept by this wallet
  // A rule in this browser's storage (market-trade.mjs says what it is and is not). Nothing here signs: when a stop
  // order fires it is marked, the person is told, and the order it stands for is prepared for the usual review.
  const stopsPlace = () => stopsKey(kit.net(), kit.name());
  const loadStops = () => readStops(c.storage.getItem(stopsPlace()));
  const saveStops = stops => c.storage.setItem(stopsPlace(), writeStops(stops));
  kit.reserve(() => { try { return reservedScripts(loadStops()); } catch { return []; } });
  const newStopId = c.stopId ?? (() => Array.from(globalThis.crypto.getRandomValues(new Uint8Array(8)), byte => byte.toString(16).padStart(2, '0')).join(''));
  const choose = (id, options) => el('select', { id }, ...options.map(([value, text]) => el('option', { value, text })));
  function stopWords(stop) {
    const when = stop.trigger.when === 'at_or_below' ? 'at or below' : 'at or above';
    const watched = stop.trigger.source === 'book' ? `the best ${stop.side === 'sell' ? 'buy' : 'sell'} price among orders of at least ${seconds(stop.trigger.minMicros)} seconds is ${when} ${priceText(stop.trigger.price)}`
      : `the last ${stop.trigger.count} recorded trades, and the chain's last recorded price, are all ${when} ${priceText(stop.trigger.price)}`;
    return `${stop.side === 'sell' ? 'Sell' : 'Buy'} ${seconds(stop.amountMicros)} seconds at a limit of ${priceWords(stop.limit)}, when ${watched}.`;
  }
  /// What a stop order's trigger looks at now. The list only says which orders to read; each one that counts is read
  /// through the verifier, and the last recorded price is the chain's own.
  async function seenFor(stop) {
    if (stop.trigger.source === 'book') {
      const listed = await c.api.orders(stop.side === 'sell' ? 'buy' : 'sell'), ids = listed.items.filter(order => BigInt(order.amount_micros) >= BigInt(stop.trigger.minMicros)).slice(0, sdk.MARKET_SELECTION.market_orders).map(order => order.id);
      const state = await proven(ids.length ? { market_orders: ids } : {});
      return { book: ids.length ? bookPrice(stop, ids.map(id => sdk.marketOrder(state, id)), me(state).id) : null, height: state.height };
    }
    const listed = await c.api.trades(stop.trigger.count), state = await proven();
    return { trades: listed.items.filter(item => item.price !== null).map(item => item.price), last: sdk.marketSummary(state).last_price ?? null, height: state.height };
  }
  let lastWatch = 0, watching = false;
  /// From market-ui.mjs, at every verified reading of the open account: the armed stop orders are looked at, at most
  /// every thirty seconds. One that fires is marked and said; nothing is signed.
  async function watch() {
    const now = Date.now();
    if (watching || now - lastWatch < (c.stopGapMs ?? 30000)) return;
    let stops; try { stops = loadStops(); } catch { return; }
    if (!stops.some(stop => stop.state === 'armed')) return;
    watching = true; lastWatch = now;
    try {
      for (const stop of stops.filter(item => item.state === 'armed')) {
        let seen; try { seen = await seenFor(stop); } catch { continue; }
        const verdict = stopFires(stop, seen);
        if (!verdict.fires) continue;
        saveStops(loadStops().map(item => (item.id === stop.id && item.state === 'armed' ? { ...item, state: 'fired', fired: { height: seen.height, seen: verdict.seen } } : item)));
        kit.home('Stop order fired');
        c.notice(`A stop order of this wallet fired. ${stopWords(stop)} Nothing was signed: open Market, For traders, and review the order it prepared.`, 'error');
        if (kit.viewName() === 'trade' && c.idle?.() !== false) await go('trade');
      }
    } finally { watching = false; }
  }
  async function stopsSection() {
    const section = el('section', { id: 'market-stops' }, el('h3', { text: 'Stop orders' }), p(STOP_WORDS.what), p(`${STOP_WORDS.limit} ${STOP_WORDS.asks}`, 'subtle'));
    const stops = loadStops(), list = el('div', { id: 'market-stop-list' });
    if (!stops.length) list.append(p('No stop order.', 'subtle'));
    for (const stop of stops) list.append(el('div', { class: 'market-address-row', id: `market-stop-${stop.id}` },
      el('p', {}, el('span', { class: `tag market-${stop.state === 'fired' ? 'in_use' : stop.state === 'done' ? 'used' : 'free'}`, text: stop.state === 'fired' ? 'Fired' : stop.state === 'done' ? 'Done' : 'Watching' }), el('span', { text: ` ${stopWords(stop)}` })),
      stop.state === 'fired' ? p(`It fired at block ${stop.fired.height}: the price it watches was ${priceText(stop.fired.seen)}. Nothing was signed. Review the order it prepared.`, 'warning') : null,
      stop.side === 'sell' ? addressNode(stop.address) : null, stop.side === 'sell' && stop.state !== 'done' ? p('This address is kept aside for this stop order.', 'field-note') : null,
      el('div', { class: 'button-row' }, stop.state === 'fired' ? button('Review and sign the order', () => signStop(stop.id), '', `market-stop-sign-${stop.id}`) : null,
        button('Remove', async () => { saveStops(loadStops().filter(item => item.id !== stop.id)); await go('trade'); c.notice('The stop order was removed. Nothing was signed.'); }, 'secondary', `market-stop-remove-${stop.id}`))));
    section.append(list);
    const { free } = await freeAddresses();
    section.append(el('form', { id: 'market-stop-form', on: { submit: event => { event.preventDefault(); c.run(() => keepStop(free)); } } }, el('h4', { text: 'A new stop order' }),
      el('label', { text: 'When it fires, prepare', htmlFor: 'market-stop-side' }), choose('market-stop-side', [['sell', 'A sell order'], ['buy', 'A buy order']]),
      ...field('market-stop-amount', 'Seconds', { inputMode: 'decimal' }),
      el('label', { text: 'It watches', htmlFor: 'market-stop-source' }), choose('market-stop-source', [['book', 'The book: the best price among orders of a least size'], ['trades', 'Recorded trades: several in a row']]),
      p('For a sell order the book\'s best buy price is watched, for a buy order its best sell price.', 'field-note'),
      el('label', { text: 'It fires when that price is', htmlFor: 'market-stop-when' }), choose('market-stop-when', [['at_or_below', 'At or below the trigger price'], ['at_or_above', 'At or above the trigger price']]),
      ...field('market-stop-trigger', 'Trigger price, in satoshis for one second', { inputMode: 'decimal' }),
      ...field('market-stop-size', 'The book: least size of an order that counts, in seconds', { inputMode: 'decimal' }, STOP_WORDS.book),
      ...field('market-stop-count', 'Recorded trades: how many in a row', { inputMode: 'numeric', value: String(STOP_TRADES_MIN) }, STOP_WORDS.trades),
      ...field('market-stop-limit', 'Limit price of the order, in satoshis for one second', { inputMode: 'decimal' }, STOP_WORDS.limit),
      el('label', { text: 'For a sell order: the address kept aside for it', htmlFor: 'market-stop-address' }), free.length ? choose('market-stop-address', free.map(item => [item.script, `${groupedAddress(item.address)} (${item.form})`])) : p(STOP_WORDS.noAddress, 'nudge'),
      p(STOP_WORDS.hidden, 'field-note'), el('button', { type: 'submit', text: 'Keep this stop order', id: 'market-stop-keep' })));
    return section;
  }
  async function keepStop(free) {
    const side = kit.$('market-stop-side')?.value === 'buy' ? 'buy' : 'sell', source = kit.$('market-stop-source')?.value === 'trades' ? 'trades' : 'book', when = kit.$('market-stop-when')?.value === 'at_or_above' ? 'at_or_above' : 'at_or_below';
    const amountMicros = c.parseSeconds(typed('market-stop-amount')), trigger = parsePrice(typed('market-stop-trigger'));
    assert(typed('market-stop-limit') !== '', STOP_WORDS.noLimit);
    const limit = parsePrice(typed('market-stop-limit')), chosen = free.find(item => item.script === (kit.$('market-stop-address')?.value ?? ''));
    if (side === 'sell') { assert(chosen, STOP_WORDS.noAddress); await kit.provenFree([chosen]); }
    const stop = stopOrder({ id: newStopId(), side, limit, amountMicros, ...(side === 'sell' ? { script: chosen.script, address: chosen.address } : {}),
      trigger: source === 'book' ? { source, when, price: trigger, minMicros: typed('market-stop-size') === '' ? '0' : c.parseSeconds(typed('market-stop-size')) } : { source, when, price: trigger, count: Number(parseWhole(typed('market-stop-count'), 'Recorded trades in a row', 1, 99)) } });
    const refusal = stopRefusal(stop, leastAmountFor(sdk, rules().minSats, stop.trigger.price)); assert(refusal === null, refusal);
    const stops = loadStops(); assert(stops.length < STOP_LIMIT, `This wallet keeps at most ${STOP_LIMIT} stop orders. Remove one first.`);
    saveStops([...stops, stop]); lastWatch = 0;
    await go('trade');
    c.notice('The stop order is kept in this browser. Nothing was signed and nothing was sent to the chain. It is watched only while this wallet is open and unlocked here.');
  }
  /// The order a fired stop order stands for, at its limit price, through the usual review. Its trigger is looked at
  /// once more and the review says what it shows now.
  async function signStop(id) {
    const stop = loadStops().find(item => item.id === id); assert(stop && stop.state === 'fired', 'This stop order has not fired.');
    const mine = me(), r = rules(), now = await seenFor(stop), seenNow = stop.trigger.source === 'book' ? now.book : now.last;
    const why = [['Why', `Your stop order fired at block ${stop.fired.height}: the price it watches was ${priceText(stop.fired.seen)}.`], ['Now', seenNow === null || seenNow === undefined ? 'Nothing on the chain meets what it watches right now.' : `The price it watches is ${priceText(seenNow)} now, at block ${now.height}.`]];
    const before = sdk.marketAccount(await proven({ market_accounts: [mine.id] }), mine.id).orders, total = sdk.marketSats(stop.amountMicros, stop.limit);
    let receipt;
    if (stop.side === 'sell') {
      const chosen = [{ script: stop.script, address: stop.address }], terms = sellDefaults(r), minSats = suggestedMinSats(sdk, stop.amountMicros, stop.limit, 1, r);
      const refusal = termsRefusal(sdk, { side: 'sell', amountMicros: stop.amountMicros, price: stop.limit, ...terms, minSats, scripts: [stop.script] }, r); assert(refusal === null, refusal);
      await kit.provenFree(chosen).catch(() => { throw new Error('The address kept aside for this stop order is no longer free. Nothing was signed. Remove the stop order and make a new one with another address.'); });
      receipt = await act({ kind: 'market_order', payload: sdk.marketSellOrder({ amountMicros: stop.amountMicros, price: stop.limit, scripts: [stop.script], confirmations: terms.confirmations, payBlocks: terms.payBlocks, minSats, depositPpm: terms.depositPpm, minDepositMicros: terms.minDepositMicros }),
        label: `Stop order: offer ${seconds(stop.amountMicros)} s`, title: 'A stop order fired: sell at your limit', confirm: `Offer ${seconds(stop.amountMicros)} seconds`, charge: { locked: stop.amountMicros }, what: 'The seconds you offer and the fees',
        acknowledge: 'This address is in my own Bitcoin wallet, and I use it for nothing else.',
        fields: [...why, ['You sell', `${seconds(stop.amountMicros)} seconds`], ['Limit price', priceWords(stop.limit)], ['You receive', `${bitcoinWords(total)} when all of it is sold`], ['Address', groupedAddress(stop.address)], ['Public', SELL_WORDS.publicNow],
          ['Terms', `${terms.confirmations} confirmations, ${terms.payBlocks} Bitcoin blocks to pay, a deposit of ${percentText(terms.depositPpm)}, smallest purchase ${grouped(minSats)} satoshis`]],
        total: fee => `${seconds(BigInt(stop.amountMicros) + fee)} seconds leave your balance now. What is not sold comes back when you cancel.` });
    } else {
      const depositPpm = BigInt(r.bondMinPpm) > 50000n ? r.bondMinPpm : '50000', confirmations = String(Math.max(Number(r.kMin), 6)), payBlocks = String(Math.max(Number(r.nMin), 6)), forms = ['p2tr', 'p2wpkh'], bond = buyBond(stop.amountMicros, depositPpm);
      const refusal = termsRefusal(sdk, { side: 'buy', amountMicros: stop.amountMicros, price: stop.limit, confirmations, payBlocks, depositPpm, minSats: r.minSats, forms }, r); assert(refusal === null, refusal);
      receipt = await act({ kind: 'market_order', payload: sdk.marketBuyOrder({ amountMicros: stop.amountMicros, price: stop.limit, forms, confirmations, payBlocks, minSats: r.minSats, depositPpm }),
        label: `Stop order: bid for ${seconds(stop.amountMicros)} s`, title: 'A stop order fired: buy at your limit', confirm: `Lock ${seconds(bond)} s and post`, charge: { locked: bond }, what: 'The bond and the fee',
        acknowledge: 'I will be here to pay each sale in time, or I lose that part of my bond.',
        fields: [...why, ['You want', `${seconds(stop.amountMicros)} seconds`], ['Limit price', priceWords(stop.limit)], ['You would pay', `${bitcoinWords(total)} in all`], ['Warning', TRADE_WORDS.awake],
          ['Terms', `at most ${confirmations} confirmations, ${payBlocks} Bitcoin blocks to pay each sale, to SegWit or Taproot addresses, smallest sale ${grouped(r.minSats)} satoshis`], ['Bond', `${seconds(bond)} seconds (${percentText(depositPpm)}), locked now`]],
        total: fee => `${seconds(BigInt(bond) + fee)} seconds leave your balance now` });
    }
    if (!receipt) return;
    saveStops(loadStops().map(item => (item.id === id ? { ...item, state: 'done' } : item)));
    const made = newId(before, sdk.marketAccount(await proven({ market_accounts: [mine.id] }), mine.id).orders);
    await c.refresh();
    await go('mine', made && stop.side === 'sell' ? { made: await kit.readBack(made, [{ script: stop.script }]) } : {});
    c.notice('The order of your stop order is on the chain, at your limit price.');
  }

  // ---------------------------------------------------------------- the view
  async function view() {
    const root = el('div', { id: 'market-trade', class: 'market-trade' }, el('h2', { text: 'For traders', id: 'market-view-title', tabIndex: -1 }),
      p('The same market, wider: the book, recorded trades, a chart, and every order with every term. What you sign is read from the chain first, here too.'),
      p('To trade with a program of your own, see the trading guide (docs/trading.md).', 'field-note'));
    // One field for the payment password of a protected account, above the forms that need it.
    const password = c.secured() ? el('section', { id: 'market-trade-password' }, el('h3', { text: 'Your payment password' }), p('Your account is protected. Type the password before you press a Review button below. It is used for that one action.', 'field-note'), paymentBox()) : null;
    root.append(...[await part('Order book', bookSection), el('div', { class: 'market-two' }, await part('Recorded prices', chartSection), await part('Recorded trades', tradesSection)), password, await part('Orders', formsSection), await part('Stop orders', stopsSection)].filter(Boolean),
      el('section', {}, el('h3', { text: 'Your orders and purchases' }), el('div', { class: 'button-row' }, button('My purchases and orders', () => go('mine'), 'secondary', 'market-trade-mine'), button('My Bitcoin addresses', () => go('addresses'), 'secondary'))));
    return root;
  }
  return { view, watch };
}
