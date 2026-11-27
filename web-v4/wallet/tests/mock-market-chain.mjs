// The market of seconds against bitcoin, for the wallet's own tests and its preview: what the engine does with the
// actions of kinds 50 to 53 and 55 to 58, the rows it then holds, and the lists the trading API makes of them.
//
// This is a reading of spec/market.md, sections 4 to 7, written on 2026-11-26 for market-ui.test.mjs and
// preview-server.mjs. It is NOT the engine (v5/src/market.rs), and nothing here shows that the engine takes an action:
// the engine's own tests and a run on a network do. What it holds in place is that the wallet signs what these rules,
// as read, accept, reads rows in the form the SDK's readers take, and says what the rules then do. Left out: a proof
// of payment (kind 54: `pay` below does what an accepted proof does), the freshness of the header chain beyond a
// switch, the validator safety hold, the limits of 64 orders and fills, and the reorganisation rules.
//
// Rows are the JSON of proven state: every number a decimal string. `now` is elapsed microseconds since genesis, taken
// as the clock of the waits (this chain never stops).
const PPM = 1000000n;
const refuse = message => { throw new Error(message); };
const ensure = (condition, message) => { if (!condition) refuse(message); };
const str = value => value.toString();

/// `sdk`: TimeSDK. `accounts`: the chain's account rows (`{ id, balance, nonce, devices }`), changed in place.
/// `genesis`: the genesis time in microseconds. `spend(account, count, now)`: called with what an action counts against
/// a protected account's daily limit (it throws when the limit refuses it), and `frozen(account, now)` says whether an
/// account is frozen; both optional. `bitcoin`: `{ network, best, halted, fresh }`, changed by the caller.
export function createMarketChain({ sdk, accounts, genesis, profile = 'laboratory', fee = 1000n, bitcoin = { network: 'regtest', best: 100, halted: false, fresh: true }, spend = () => {}, frozen = () => false }) {
  const rules = { ...sdk.MARKET_RULES[profile], ...sdk.MARKET_LIMITS };
  const meta = { fills: 0n, next_fill: 1n, next_order: 1n, orders: 0n, sats: 0n, seconds_micros: 0n, trades: 0n, last_price: null };
  const orders = new Map(), fills = new Map(), scripts = new Map(), candles = new Map(), ended = new Map(), tape = [];
  const heights = [{ at: '0', height: '0' }];
  let held = 0n;
  // What the index says, apart from the rows: switches for the tests (a list that is behind, or that lies).
  const index = { ready: true, consistent: true, tapeReconciled: true, lag: 0, lie: null };
  const find = id => accounts.find(item => item.id === String(id));
  const credit = (id, amount) => { const account = find(id); account.balance = str(BigInt(account.balance) + amount); };
  const moment = (now, height) => ({ height: String(height), time_micros: str(BigInt(genesis) + now) });
  const sats = (amount, price) => BigInt(sdk.marketSats(str(amount), str(price)));
  const stands = (order, now) => { const owner = find(order.owner); return Boolean(owner) && owner.devices.some(device => device.can_spend && device.public_key === order.key) && !frozen(owner, now); };
  function learn(best, now) {
    bitcoin.best = best;
    while (heights.length && BigInt(heights[heights.length - 1].height) > BigInt(best)) heights.pop();
    if (!heights.length || BigInt(heights[heights.length - 1].height) < BigInt(best)) heights.push({ at: str(now), height: String(best) });
  }
  function sizeRight(order, amount) {
    const offer = BigInt(order.amount_micros);
    ensure(amount >= 1n && amount <= offer, 'the size of the fill is not one the order takes');
    const cost = sats(amount, order.price), least = BigInt(order.min_sats);
    ensure(cost >= least || (amount === offer && cost >= BigInt(rules.minSats)), 'the fill is smaller than the smallest trade of the order');
    ensure(amount === offer || sats(offer - amount, order.price) >= least, 'what stays on offer is smaller than the smallest trade of the order');
    return cost;
  }
  function endFill(fill, how) {
    fills.delete(fill.id); meta.fills -= 1n; ended.set(fill.id, how); scripts.set(fill.script, {});
    const order = orders.get(fill.order);
    if (order) {
      if (order.side === 'sell') { const entry = order.scripts.find(item => item.script === fill.script); delete entry.fill; entry.used = true; }
      else order.fills = str(BigInt(order.fills) - 1n);
      maybeGone(order);
    }
  }
  function maybeGone(order) {
    const open = order.side === 'sell' ? order.scripts.some(item => item.fill !== undefined) : order.fills !== '0';
    if (open || (order.open && order.amount_micros !== '0')) return;
    if (BigInt(order.bond_micros) > 0n) { credit(order.owner, BigInt(order.bond_micros)); held -= BigInt(order.bond_micros); }
    orders.delete(order.id); meta.orders -= 1n;
    if (order.side === 'sell') for (const entry of order.scripts) if (entry.used !== true) scripts.delete(entry.script);
  }
  const newScripts = (list, order) => { for (const script of list) { ensure(!scripts.has(script), 'a receiving script serves one order or fill, once'); } for (const script of list) scripts.set(script, { order }); };
  /// Applies a decoded action (TimeSDK.decodeAction) of the market at `now` and `height`. Throws the refusal.
  function apply(action, now, height) {
    const sender = find(action.from), kind = action.kind, p = action.payload;
    ensure(sender, 'unknown account');
    ensure(BigInt(action.nonce) === BigInt(sender.nonce) + 1n, 'incorrect nonce');
    ensure(sender.devices.some(device => device.can_spend && device.public_key === action.publicKey), 'spending device required');
    const cost = BigInt(sdk.marketActionFee(kind, p, str(fee))), before = BigInt(sender.balance);
    let extra = 0n;
    const take = amount => { ensure(BigInt(sender.balance) >= amount, 'insufficient funds'); sender.balance = str(BigInt(sender.balance) - amount); };
    const snapshot = structuredClone({ accounts, meta: Object.fromEntries(Object.entries(meta).map(([key, value]) => [key, value === null ? null : str(value)])), orders: [...orders], fills: [...fills], scripts: [...scripts], ended: [...ended], held: str(held) });
    try {
      take(cost);
      if (kind === 50) {
        const amount = BigInt(p.amount_micros), id = str(meta.next_order);
        ensure(BigInt(p.confirmations) >= BigInt(rules.kMin) && BigInt(p.pay_blocks) >= BigInt(rules.nMin) && BigInt(p.min_sats) >= BigInt(rules.minSats), 'the terms of the order are outside what the network takes');
        const row = { amount_micros: p.amount_micros, bond_micros: '0', confirmations: p.confirmations, created: moment(now, height), deposit_ppm: p.deposit_ppm, id, key: action.publicKey, min_deposit_micros: p.side === 'sell' ? p.min_deposit_micros : '0', min_sats: p.min_sats, open: true, owner: sender.id, pay_blocks: p.pay_blocks, price: p.price, side: p.side };
        if (p.side === 'sell') { newScripts(p.scripts, id); row.scripts = p.scripts.map(script => ({ script })); take(amount); held += amount; }
        else { ensure(BigInt(p.deposit_ppm) >= BigInt(rules.bondMinPpm), 'the bond of a buy order is below the least'); const bond = (amount * BigInt(p.deposit_ppm) + PPM - 1n) / PPM; row.bond_micros = str(bond); row.fills = '0'; row.forms = p.forms; take(bond); held += bond; }
        orders.set(id, row); meta.next_order += 1n; meta.orders += 1n;
      } else if (kind === 51) {
        const order = orders.get(p.order); ensure(order && order.owner === sender.id && order.open, 'only its owner cancels an open order');
        const back = BigInt(order.side === 'sell' ? order.amount_micros : order.bond_micros);
        credit(sender.id, back); held -= back; order.amount_micros = '0'; order.bond_micros = '0'; order.open = false; maybeGone(order);
      } else if (kind === 52) {
        const order = orders.get(p.order); ensure(order && order.side === 'sell' && order.open, 'not an open sell order');
        ensure(bitcoin.network !== 'mainnet', 'the market is closed on Bitcoin mainnet'); ensure(bitcoin.fresh && !bitcoin.halted, 'the Bitcoin header chain is not fresh');
        ensure(stands(order, now), 'the owner of this order is frozen');
        const amount = BigInt(p.amount_micros); ensure(sizeRight(order, amount) === BigInt(p.sats), 'the satoshis named are the price of the amount');
        const entry = order.scripts.find(item => item.fill === undefined && item.used !== true); ensure(entry, 'this order has no receiving script left');
        ensure(find(p.to), 'unknown account');
        const least = BigInt(order.min_deposit_micros), share = (amount * BigInt(order.deposit_ppm) + PPM - 1n) / PPM, deposit = share > least ? share : least, id = str(meta.next_fill);
        take(deposit); held += deposit; order.amount_micros = str(BigInt(order.amount_micros) - amount); entry.fill = id;
        fills.set(id, { amount_micros: str(amount), confirmations: order.confirmations, created: moment(now, height), deposit_micros: str(deposit), id, opened_micros: str(now), order: order.id, owner: order.owner, pay_blocks: order.pay_blocks, payer: sender.id, price: order.price, sats: p.sats, script: entry.script, side: 'sell', start_hash: 'ab'.repeat(32), start_height: String(bitcoin.best), to: p.to });
        meta.next_fill += 1n; meta.fills += 1n;
      } else if (kind === 53) {
        const order = orders.get(p.order); ensure(order && order.side === 'buy' && order.open, 'not an open buy order');
        ensure(bitcoin.fresh && !bitcoin.halted, 'the Bitcoin header chain is not fresh'); ensure(stands(order, now), 'the owner of this order is frozen');
        const amount = BigInt(p.amount_micros); ensure(sizeRight(order, amount) === BigInt(p.sats), 'the satoshis named are the price of the amount');
        ensure(BigInt(p.confirmations) >= BigInt(rules.kMin) && BigInt(p.confirmations) <= BigInt(order.confirmations), 'more confirmations than the buyer waits for');
        ensure(order.forms.includes(sdk.marketScriptForm(p.script)), 'the buyer cannot pay to this form of address'); ensure(!scripts.has(p.script), 'a receiving script serves one order or fill, once');
        const all = amount === BigInt(order.amount_micros), deposit = all ? BigInt(order.bond_micros) : BigInt(order.bond_micros) * amount / BigInt(order.amount_micros), id = str(meta.next_fill);
        take(amount); held += amount; order.amount_micros = str(BigInt(order.amount_micros) - amount); order.bond_micros = str(BigInt(order.bond_micros) - deposit); order.fills = str(BigInt(order.fills) + 1n);
        scripts.set(p.script, { fill: id });
        fills.set(id, { amount_micros: str(amount), confirmations: p.confirmations, created: moment(now, height), deposit_micros: str(deposit), id, opened_micros: str(now), order: order.id, owner: sender.id, pay_blocks: order.pay_blocks, payer: order.owner, price: order.price, sats: p.sats, script: p.script, side: 'buy', start_hash: 'ab'.repeat(32), start_height: String(bitcoin.best), to: order.owner });
        meta.next_fill += 1n; meta.fills += 1n;
      } else if (kind === 55 || kind === 56) {
        const fill = fills.get(p.fill); ensure(fill, 'this action names a fill');
        if (kind === 55) ensure(sdk.marketExpiry(stateOf({ include_market: true }, now, height), fill).possible, 'this fill cannot end yet');
        else { ensure(fill.to === sender.id, 'only the account its seconds go to releases a fill'); extra = (bitcoin.halted ? 0n : BigInt(fill.amount_micros)) + (fill.payer === sender.id ? BigInt(fill.deposit_micros) : 0n); }
        const order = orders.get(fill.order), amount = BigInt(fill.amount_micros), deposit = BigInt(fill.deposit_micros);
        if (fill.side === 'sell' && order?.open) order.amount_micros = str(BigInt(order.amount_micros) + amount); else { credit(fill.owner, amount); held -= amount; }
        credit(fill.owner, deposit); held -= deposit; endFill(fill, kind === 55 ? 'expired' : 'released');
      } else if (kind === 57) {
        const fill = fills.get(p.fill); ensure(fill && fill.owner === sender.id, 'only the owner of its seconds settles a fill');
        extra = BigInt(fill.amount_micros);
        credit(fill.to, BigInt(fill.amount_micros)); credit(fill.payer, BigInt(fill.deposit_micros)); held -= BigInt(fill.amount_micros) + BigInt(fill.deposit_micros); endFill(fill, 'settled');
      } else if (kind === 58) {
        const order = orders.get(p.order); ensure(order && order.owner === sender.id && order.open && order.side === 'sell', 'not an open sell order');
        const kept = order.scripts.filter(entry => entry.used !== true); ensure(kept.length + p.scripts.length <= 16, 'an order has at most sixteen receiving scripts that have not served');
        newScripts(p.scripts, order.id); order.scripts = [...kept, ...p.scripts.map(script => ({ script }))]; order.key = action.publicKey;
        extra = BigInt(order.amount_micros) + [...fills.values()].filter(fill => fill.order === order.id).reduce((sum, fill) => sum + BigInt(fill.amount_micros), 0n);
      } else refuse('this preview chain does not take this kind of action');
      const after = BigInt(sender.balance), outflow = before > after ? before - after : 0n;
      if (frozen(sender, now)) ensure(outflow === 0n && extra === 0n, 'the account is frozen');
      spend(sender, outflow + extra, now);
    } catch (error) {
      // A refusal changes nothing.
      for (const row of snapshot.accounts) Object.assign(find(row.id), row);
      for (const [key, value] of Object.entries(snapshot.meta)) meta[key] = value === null ? null : BigInt(value);
      orders.clear(); for (const [key, value] of snapshot.orders) orders.set(key, value);
      fills.clear(); for (const [key, value] of snapshot.fills) fills.set(key, value);
      scripts.clear(); for (const [key, value] of snapshot.scripts) scripts.set(key, value);
      ended.clear(); for (const [key, value] of snapshot.ended) ended.set(key, value);
      held = BigInt(snapshot.held);
      throw error;
    }
    sender.nonce = action.nonce;
  }
  /// What an accepted proof of a payment of `paid` satoshis to a fill's script does (spec/market.md, 6.5).
  function pay(fillId, paid, now, height) {
    const fill = fills.get(String(fillId)); ensure(fill, 'this action names a fill');
    const s = BigInt(paid), due = BigInt(fill.sats), amount = BigInt(fill.amount_micros), deposit = BigInt(fill.deposit_micros), full = s >= due;
    const bought = full ? amount : amount * s / due, back = full ? deposit : deposit * bought / amount;
    ensure(bought >= 1n, 'the payment buys less than a microsecond');
    credit(fill.to, bought); credit(fill.payer, back); held -= bought + back;
    const counted = full ? due : s, hour = str(now / BigInt(rules.hourMicros)), candle = candles.get(hour);
    if (candle) Object.assign(candle, { close: fill.price, high: str(BigInt(candle.high) > BigInt(fill.price) ? candle.high : fill.price), low: str(BigInt(candle.low) < BigInt(fill.price) ? candle.low : fill.price), sats: str(BigInt(candle.sats) + counted), seconds_micros: str(BigInt(candle.seconds_micros) + bought), trades: str(BigInt(candle.trades) + 1n) });
    else candles.set(hour, { close: fill.price, high: fill.price, low: fill.price, open: fill.price, sats: str(counted), seconds_micros: str(bought), trades: '1' });
    meta.trades += 1n; meta.sats += counted; meta.seconds_micros += bought; meta.last_price = BigInt(fill.price);
    tape.push({ fill: fill.id, order: fill.order, price: fill.price, sats: str(counted), seconds_micros: str(bought), paid_sats: str(s), full, height: String(height), time: new Date(Number((BigInt(genesis) + now) / 1000n)).toISOString(), bitcoin_txid: (tape.length + 1).toString(16).padStart(64, '0'), vout: '0' });
    if (full) endFill(fill, 'paid'); else { fill.amount_micros = str(amount - bought); fill.deposit_micros = str(deposit - back); fill.sats = str(due - s); }
  }
  const summary = () => ({ fills: str(meta.fills), ...(meta.last_price === null ? {} : { last_price: str(meta.last_price) }), next_fill: str(meta.next_fill), next_order: str(meta.next_order), orders: str(meta.orders), sats: str(meta.sats), seconds_micros: str(meta.seconds_micros), trades: str(meta.trades) });
  const accountRow = id => { const mine = { fills: [...fills.values()].filter(fill => fill.payer === id).map(fill => fill.id), orders: [...orders.values()].filter(order => order.owner === id).map(order => order.id) }; return mine.fills.length + mine.orders.length ? mine : null; };
  /// The `market` part of a verified state for a selection, as the verifier hands it on.
  function select(q) {
    const copy = value => (value === undefined || value === null ? null : structuredClone(value));
    return { ...(q.include_market ? { summary: summary(), heights: { entries: structuredClone(heights) } } : {}),
      orders: Object.fromEntries((q.market_orders || []).map(id => [id, copy(orders.get(id))])), fills: Object.fromEntries((q.market_fills || []).map(id => [id, copy(fills.get(id))])),
      accounts: Object.fromEntries((q.market_accounts || []).map(id => [id, accountRow(id)])), scripts: Object.fromEntries((q.market_scripts || []).map(script => [script, copy(scripts.get(script))])),
      candles: Object.fromEntries((q.market_candles || []).map(hour => [hour, copy(candles.get(hour))])) };
  }
  /// A state that carries what the SDK's readers of the market need (for `marketExpiry` here, and for tests).
  function stateOf(q, now, height) {
    return { height: String(height), time_micros: str(BigInt(genesis) + now), genesis: { genesis_time_micros: String(genesis) }, config: { ...config() }, market_micros: str(held), stopped_micros: '0', bitcoin: bitcoinRow(), market: select(q) };
  }
  const config = () => ({ market: true, waits_survive_stops: true, profile, bitcoin: { network: bitcoin.network, max_tip_age_secs: 7200 } });
  const bitcoinRow = () => ({ meta: { best_height: Number(bitcoin.best), best_tip: 'ab'.repeat(32), halted: bitcoin.halted ? { reason: 'reorganisation' } : null, config: { network: bitcoin.network } } });

  // ---------------------------------------------------------------- the lists of the trading API (an index's word)
  const note = height => ({ source: 'index', proven: false, index: { indexed_height: String(height - index.lag) }, market_index: { as_of_height: String(height - index.lag), ready: index.ready, consistent: index.consistent, pending_rows: index.consistent ? 0 : 3, reading_every_row: !index.consistent, tape_reconciled: index.tapeReconciled, tape_complete: true } });
  const takesFill = order => order.open && order.amount_micros !== '0' && (order.side === 'sell' ? order.scripts.some(entry => entry.fill === undefined && entry.used !== true) : BigInt(order.fills) < 16n);
  function orderItem(order, height) {
    const row = index.lie?.order === order.id ? { ...order, ...index.lie.with } : order;
    return { id: row.id, side: row.side, owner: row.owner, price: row.price, amount_micros: row.amount_micros, sats: str(sats(row.amount_micros, row.price)), min_sats: row.min_sats, confirmations: row.confirmations, pay_blocks: row.pay_blocks, deposit_ppm: row.deposit_ppm, min_deposit_micros: row.min_deposit_micros, bond_micros: row.bond_micros, open: row.open, takes_fill: takesFill(row),
      open_fills: row.side === 'sell' ? row.scripts.filter(entry => entry.fill !== undefined).length : Number(row.fills), free_scripts: row.side === 'sell' ? row.scripts.filter(entry => entry.fill === undefined && entry.used !== true).length : null, forms: row.side === 'buy' ? row.forms : null, key: row.key, created: row.created, proven_at_height: String(height) };
  }
  const byPrice = side => [...orders.values()].filter(order => order.side === side && order.open && order.amount_micros !== '0').sort((a, b) => { const d = BigInt(a.price) - BigInt(b.price); return Number(side === 'sell' ? d : -d) || Number(BigInt(a.id) - BigInt(b.id)); });
  function levels(side, most) {
    const out = [];
    for (const order of byPrice(side)) { let at = out.find(item => item.price === order.price); if (!at) { if (out.length >= most) break; at = { price: order.price, amount_micros: 0n, takeable_micros: 0n, orders: 0 }; out.push(at); } at.amount_micros += BigInt(order.amount_micros); if (takesFill(order)) at.takeable_micros += BigInt(order.amount_micros); at.orders += 1; }
    return out.map(item => ({ price: item.price, amount_micros: str(item.amount_micros), takeable_micros: str(item.takeable_micros), sats: str(sats(item.amount_micros, item.price)), orders: item.orders }));
  }
  /// The answer of a route of the trading API: `{ status, body }`.
  function api(route, query, now, height) {
    const marketIndex = note(height);
    if (!index.ready && route !== '/v1/market' && !/^\/v1\/market\/fills\//.test(route)) return { status: 503, body: { error: { code: 'market_index_not_ready', message: 'not ready' } } };
    if (route === '/v1/market') return { status: 200, body: { source: 'state_proof', market: true, summary: summary(), last_recorded_price: meta.last_price === null ? null : str(meta.last_price), bitcoin: { network: bitcoin.network, best_height: String(bitcoin.best), halted: bitcoin.halted, fresh: bitcoin.fresh }, market_index: marketIndex.market_index, index: marketIndex.index } };
    if (route === '/v1/market/orders') return { status: 200, body: { ...marketIndex, side: query.side, items: byPrice(query.side).map(order => orderItem(order, height)), has_more: false, next_cursor: null } };
    if (route === '/v1/market/depth') return { status: 200, body: { ...marketIndex, levels: 12, truncated: false, last_recorded_price: meta.last_price === null ? null : str(meta.last_price), sell: levels('sell', 12), buy: levels('buy', 12) } };
    if (route === '/v1/market/trades') return { status: 200, body: { ...marketIndex, items: tape.slice().reverse().slice(0, 50).map(item => ({ ...item, type: 'market_trade', basis: 'proven_row' })), has_more: false, next_cursor: null } };
    if (route === '/v1/market/candles') {
      const length = BigInt(rules.hourMicros);
      return { status: 200, body: { ...marketIndex, interval: query.interval, interval_micros: str(length), items: [...candles].sort((a, b) => Number(BigInt(b[0]) - BigInt(a[0]))).slice(0, 120).map(([hour, row]) => ({ number: hour, start_time_micros: str(BigInt(genesis) + BigInt(hour) * length), start_time: '', recorded_prices: { open: row.open, high: row.high, low: row.low, close: row.close }, sats: row.sats, seconds_micros: row.seconds_micros, trades: row.trades, source: query.interval === 'hour' ? 'state_row' : 'computed', proven_at_height: String(height), matches_tape: true })), has_more: false, next_to: null } };
    }
    const account = /^\/v1\/accounts\/([0-9]+)\/market$/.exec(route)?.[1];
    if (account) {
      const roles = fill => ['payer', 'owner', 'to'].filter(role => fill[role] === account);
      return { status: 200, body: { ...marketIndex, account, orders: [...orders.values()].filter(order => order.owner === account).map(order => orderItem(order, height)),
        fills: [...fills.values()].filter(fill => roles(fill).length).map(fill => ({ ...fill, last_height: sdk.marketFillLastHeight(fill), proven_at_height: String(height), roles: roles(fill) })), fills_truncated: false,
        ended: { has_more: false, next_cursor: null, items: [...ended].filter(([id]) => tape.some(item => item.fill === id) || true).map(([id, how]) => ({ fill: id, order: null, how, roles: [], height: String(height) })).reverse().slice(0, 50) } } };
    }
    const fillId = /^\/v1\/market\/fills\/([0-9]+)$/.exec(route)?.[1];
    if (fillId) {
      const fill = fills.get(fillId), indexed = { ...marketIndex, ended: ended.has(fillId) ? { fill: fillId, order: null, how: ended.get(fillId), roles: [], height: String(height) } : null, payments: tape.filter(item => item.fill === fillId).map(item => ({ ...item, type: 'market_trade' })) };
      return fill ? { status: 200, body: { source: 'state_proof', fill: structuredClone(fill), indexed } } : { status: 404, body: { error: { code: 'fill_not_found', message: 'No such fill' }, fill: null, indexed } };
    }
    return { status: 404, body: { error: { code: 'not_found', message: 'Not found' } } };
  }
  return { apply, pay, select, stateOf, api, learn, config, bitcoinRow, held: () => str(held), takes: action => action.kind >= 50 && action.kind <= 58 && action.kind !== 54, orders, fills, scripts, index, bitcoin, rules };
}
