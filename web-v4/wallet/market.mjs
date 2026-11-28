// The market of seconds against bitcoin (spec/market.md), as this wallet reasons about it: everything that can be
// worked out without a page, a storage or a network. market-ui.mjs draws with it and market-api.mjs reads the lists.
//
// THE RULE OF THIS WALLET'S MARKET. Nothing a person pays on is taken from a server's word. A list (the book, "my
// orders", the trades) may come from the API's index and is shown as a list. Before the wallet shows a Bitcoin address
// and an amount to pay, and before it signs anything, it reads the rows involved through its own verifier and uses
// those: `orderChanged` and `fillChanged` below say where a proven row differs from what a list said, and the page
// stops there. What is still to pay for a fill is read (`sats` of the proven fill), never computed here.
//
// Numbers: seconds are microseconds, bitcoin is satoshis, a price is millionths of a satoshi for one second; all are
// decimal strings or BigInt, never a floating-point number. `sdk` is TimeSDK, whose `marketSats` and `marketBought`
// are the chain's two formulas (spec/market.md, section 3).

const MICROS = 1000000n, PPM = 1000000n, SATS_PER_BTC = 100000000n, PRICE_UNIT = 1000000n;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
const assert = (value, message) => { if (!value) throw new Error(message); };
const big = (value) => { assert(typeof value === 'bigint' || (typeof value === 'string' && DECIMAL.test(value)), 'A whole number was expected.'); return BigInt(value); };
const max = (a, b) => (a > b ? a : b), min = (a, b) => (a < b ? a : b);

// ---------------------------------------------------------------- words a person reads
/// Digits in groups of three: 1,234,567.
export function grouped(value) { return big(String(value)).toString().replace(/\B(?=(\d{3})+$)/g, ','); }
/// Satoshis as bitcoin, exactly, with all eight decimals: 12000 -> "0.00012000".
export function btcText(sats) { const value = big(String(sats)); return `${value / SATS_PER_BTC}.${(value % SATS_PER_BTC).toString().padStart(8, '0')}`; }
/// "0.00012000 BTC (12,000 satoshis)": both, always, so that an amount can be compared in either.
export function bitcoinWords(sats) { return `${btcText(sats)} BTC (${grouped(sats)} satoshi${String(sats) === '1' ? '' : 's'})`; }
/// A price as satoshis for one second, exactly: "250", "0.25". (The chain counts it in millionths of a satoshi.)
export function priceText(price) {
  const value = big(String(price)), fraction = (value % PRICE_UNIT).toString().padStart(6, '0').replace(/0+$/, '');
  return `${grouped(value / PRICE_UNIT)}${fraction ? '.' + fraction : ''}`;
}
export function priceWords(price) { return `${priceText(price)} satoshis for one second`; }
/// A price typed as satoshis for one second, with up to six decimals: the chain's whole number. Refuses anything else.
export function parsePrice(text) {
  assert(typeof text === 'string' && /^(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,6})?$/.test(text.trim()), 'Enter the price as satoshis for one second, with up to six decimals, like 250 or 0.25.');
  const [whole, part = ''] = text.trim().split('.'), value = BigInt(whole) * PRICE_UNIT + BigInt(part.padEnd(6, '0'));
  assert(value >= 1n && value <= 1000000000000000n, 'A price is from 0.000001 to 1,000,000,000 satoshis for one second.');
  return value.toString();
}
/// Bitcoin typed as BTC, with up to eight decimals: satoshis.
export function parseBtc(text) {
  assert(typeof text === 'string' && /^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?$/.test(text.trim()), 'Enter bitcoin with up to eight decimals, like 0.0005.');
  const [whole, part = ''] = text.trim().split('.'), value = BigInt(whole) * SATS_PER_BTC + BigInt(part.padEnd(8, '0'));
  assert(value >= 1n && value <= 2100000000000000n, 'That is not an amount of bitcoin that can exist.');
  return value.toString();
}
/// A whole number typed by a person, within bounds, as a decimal string.
export function parseWhole(text, what, least, most) {
  assert(typeof text === 'string' && DECIMAL.test(text.trim()), `${what}: enter a whole number.`);
  const value = BigInt(text.trim());
  assert(value >= BigInt(least) && value <= BigInt(most), `${what}: from ${grouped(String(least))} to ${grouped(String(most))}.`);
  return value.toString();
}
/// A share typed in percent with up to four decimals: millionths. "3" -> "30000".
export function parsePercent(text, what) {
  assert(typeof text === 'string' && /^(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,4})?$/.test(text.trim()), `${what}: enter a percentage, like 3 or 2.5.`);
  const [whole, part = ''] = text.trim().split('.'), value = BigInt(whole) * 10000n + BigInt(part.padEnd(4, '0'));
  assert(value <= PPM, `${what}: at most 100%.`);
  return value.toString();
}
export function percentText(ppm) { const value = big(String(ppm)), fraction = (value % 10000n).toString().padStart(4, '0').replace(/0+$/, ''); return `${value / 10000n}${fraction ? '.' + fraction : ''}%`; }
/// An address in groups of four characters, for comparing by eye. It is never shortened: every character is there.
export function groupedAddress(address) { assert(typeof address === 'string' && address.length > 0 && address.length <= 100, 'An address was expected.'); return address.match(/.{1,4}/g).join(' '); }
/// About how long a number of Bitcoin blocks takes, by what the network takes a block to last (`blockMicros` of
/// marketRules): "about 60 minutes". It is an average: blocks come when miners find them.
/// On a private test chain (regtest) nobody can say: whoever runs the chain makes a block when they choose, and the
/// length the rules take a block to last there (one second, on a laboratory network) is not how long one takes. The
/// page passes null for such a chain (market-ui.mjs, `rules`), and the words say no duration.
export const TEST_CHAIN_PACE = 'as this test chain makes them';
export function blocksDuration(blocks, blockMicros) {
  if (blockMicros === null) return TEST_CHAIN_PACE;
  const micros = big(String(blocks)) * big(String(blockMicros)), seconds = micros / MICROS;
  if (seconds < 120n) return `about ${seconds} second${seconds === 1n ? '' : 's'}`;
  const minutes = (seconds + 30n) / 60n;
  if (minutes < 120n) return `about ${minutes} minutes`;
  const hours = (minutes + 30n) / 60n;
  return `about ${hours} hours`;
}

// ---------------------------------------------------------------- the Bitcoin network of this market
/// What the market says about the bitcoin of a network (`state.config.bitcoin.network`, proven). Mainnet is closed in
/// this version (spec/market.md, section 2): nothing can be traded there, and the page offers nothing.
export function bitcoinNetworkOf(state) {
  const network = state?.config?.bitcoin?.network;
  assert(network === 'mainnet' || network === 'testnet3' || network === 'regtest', 'This wallet does not know the Bitcoin network of this market.');
  return network;
}
export const BITCOIN_NAMES = Object.freeze({ mainnet: 'Bitcoin', testnet3: 'Bitcoin testnet', regtest: 'a Bitcoin test chain (regtest)' });
export function testBitcoinWords(network) {
  if (network === 'mainnet') return 'The market is closed on this network: trades against real bitcoin are not open in this version of Time.';
  return `The bitcoin here is test bitcoin (${BITCOIN_NAMES[network]}). It has no value. Never send real bitcoin to an address shown here.`;
}

// ---------------------------------------------------------------- my Bitcoin addresses
// The receiving addresses of the person's own Bitcoin wallet that the market may use. Kept in this browser, in the
// clear, like the wallet's other settings that hold no secret (web-v4/wallet/README.md, "What this browser keeps"):
// localStorage, under the wallet's own address, by network and account. An address is published only when an order
// lists it. What each one serves comes from PROVEN state (TimeSDK.marketScript), never from this record.
export const ADDRESS_PREFIX = 'timecurrency.market-addresses.v1:';
export const ADDRESS_LIMIT = 200;
export const addressKey = (networkId, name) => `${ADDRESS_PREFIX}${networkId}:${name}`;
/// The texts a person pasted, one address each: split at white space, commas and semicolons, each once, in order.
export function pastedAddresses(text) {
  assert(typeof text === 'string' && text.length <= 20000, 'That is too much text. Paste the addresses only.');
  const found = [...new Set(text.split(/[\s,;]+/).filter(Boolean))];
  assert(found.length > 0, 'Paste at least one Bitcoin address.');
  assert(found.length <= ADDRESS_LIMIT, `At most ${ADDRESS_LIMIT} addresses at a time.`);
  return found;
}
/// Checks pasted texts with the codec (web-v4/shared/bitcoin-address.mjs): form, network and checksum. Gives, for each,
/// `{ text, ok, address, script, form }` or `{ text, ok: false, reason }`. The address kept is the codec's own writing
/// of the script (small letters for Bech32), so that the list shows what the chain will show. Nothing is corrected.
export async function checkAddresses(texts, network, codec) {
  const out = [];
  for (const text of texts) {
    try {
      assert(typeof text === 'string' && text.length <= 100, 'This is too long to be a Bitcoin address.');
      const script = await codec.addressToScript(text, network), address = await codec.scriptToAddress(script, network);
      out.push({ text, ok: true, address, script, form: codec.scriptForm(script) });
    } catch (error) { out.push({ text, ok: false, reason: plainReason(error) }); }
  }
  return out;
}
/// A refusal of the codec in at most 200 plain characters (its sentences are this repository's own).
function plainReason(error) { const text = error instanceof Error && typeof error.message === 'string' ? error.message : ''; return (text || 'This is not a Bitcoin address this wallet can read.').replace(/[^\x20-\x7e]/g, ' ').slice(0, 200); }
/// The list as stored, read strictly: every entry's script is worked out again from its address with the codec, for
/// the Bitcoin network the proven state names, and an entry that does not agree is dropped (`dropped` counts them).
/// A record of another Bitcoin network is not this network's list.
export async function readAddressBook(stored, network, codec) {
  let parsed = null;
  try { parsed = typeof stored === 'string' ? JSON.parse(stored) : null; } catch { parsed = null; }
  if (!parsed || parsed.v !== 1 || parsed.bitcoin !== network || !Array.isArray(parsed.items)) return { items: [], dropped: parsed && Array.isArray(parsed.items) ? parsed.items.length : 0 };
  const items = [], seen = new Set();
  let dropped = 0;
  for (const item of parsed.items.slice(0, ADDRESS_LIMIT)) {
    let script = null;
    try { script = typeof item?.address === 'string' && item.address.length <= 100 ? await codec.addressToScript(item.address, network) : null; } catch { script = null; }
    if (script === null || script !== item.script || seen.has(script)) { dropped += 1; continue; }
    seen.add(script); items.push({ address: item.address, script, form: codec.scriptForm(script) });
  }
  return { items, dropped };
}
export function writeAddressBook(items, network) { return JSON.stringify({ v: 1, bitcoin: network, items: items.map(({ address, script }) => ({ address, script })) }); }
/// The list with `checked` entries added (those that passed), each script once. Gives the new list and how many were new.
export function withAddresses(items, checked) {
  const next = items.slice(), have = new Set(items.map(item => item.script));
  let added = 0;
  for (const entry of checked) if (entry.ok && !have.has(entry.script)) { have.add(entry.script); next.push({ address: entry.address, script: entry.script, form: entry.form }); added += 1; }
  assert(next.length <= ADDRESS_LIMIT, `This list holds at most ${ADDRESS_LIMIT} addresses. Remove some first.`);
  return { items: next, added };
}
export function withoutAddress(items, script) { return items.filter(item => item.script !== script); }
/// What a proven script row means for an address of the list (TimeSDK.marketScript; for a listed script the order's
/// own entry says whether a purchase is using it). `order`: the proven order row when the script is listed, or null.
export function addressState(status, order = null) {
  if (status.status === 'free') return { key: 'free', label: 'Free', detail: 'Not in any order. It can be put into a sell order.', usable: true };
  if (status.status === 'used') return { key: 'used', label: 'Used', detail: 'A purchase used this address and has ended. An address serves once: it is never offered again, and a payment to it now buys nothing.', usable: false };
  if (status.status === 'in_use') return { key: 'in_use', label: 'In use', detail: `Purchase ${status.fill} pays to this address.`, usable: false, fill: status.fill };
  const entry = order?.scripts?.find(item => item.script === status.script) ?? null;
  if (entry?.fill !== undefined) return { key: 'in_use', label: 'In use', detail: `Purchase ${entry.fill} of your order ${status.order} pays to this address.`, usable: false, fill: entry.fill, order: status.order };
  if (entry?.used === true) return { key: 'used', label: 'Used', detail: 'A purchase used this address and has ended. An address serves once: it is never offered again, and a payment to it now buys nothing.', usable: false };
  return { key: 'listed', label: 'Listed', detail: `Order ${status.order} lists this address. It is public.`, usable: false, order: status.order };
}
/// Pieces of at most `size`, for selections that name at most so many rows (TimeSDK.MARKET_SELECTION).
export function pieces(list, size) { const out = []; for (let at = 0; at < list.length; at += size) out.push(list.slice(at, at + size)); return out; }

export const ADDRESS_WORDS = Object.freeze({
  what: 'Addresses of your own Bitcoin wallet, where buyers pay you. This wallet holds no Bitcoin key: it never sends or receives bitcoin. It only puts these addresses into your sell orders.',
  publicLater: 'Nothing here is published until you put an address into an order. From then on it is public for good, next to your account.',
  exchange: 'Never paste an address of an exchange account, unless you are sure that deposits to it never change. You are paid only if the address is yours: bitcoin sent to an address you no longer hold is lost.',
  once: 'Each address serves one purchase, ever. Use it for nothing else: any payment to it counts for the purchase that uses it.',
  kept: 'This list is kept in this browser only. It is not locked: someone who can read this browser\'s storage can see it, and could change it. Before an order is signed, the review shows each address in full: compare it with your Bitcoin wallet.',
  removed: 'Removed from this list. If an order lists the address, it stays in that order.',
});

// ---------------------------------------------------------------- amounts of a purchase
/// The deposit a taker locks for `amountMicros` of a sell order (spec/market.md, 6.1): ceil(amount x deposit_ppm /
/// 10^6), or the order's least deposit, whichever is more.
export function takeDeposit(order, amountMicros) {
  const amount = big(String(amountMicros));
  return max((amount * big(order.deposit_ppm) + PPM - 1n) / PPM, big(order.min_deposit_micros)).toString();
}
/// The bond of a buy order (6.1): ceil(amount x deposit_ppm / 10^6).
export function buyBond(amountMicros, depositPpm) { return ((big(String(amountMicros)) * big(String(depositPpm)) + PPM - 1n) / PPM).toString(); }
/// The smallest amount, in microseconds, that costs at least `sats` satoshis at `price`.
export function leastAmountFor(sdk, sats, price) {
  const wanted = big(String(sats)); if (wanted <= 0n) return '1';
  // ceil(a x P / 10^12) >= s  <=>  a x P > (s - 1) x 10^12  <=>  a > (s - 1) x 10^12 / P.
  const least = (wanted - 1n) * 1000000000000n / big(String(price)) + 1n;
  assert(BigInt(sdk.marketSats(least.toString(), String(price))) >= wanted, 'The smallest amount was worked out wrongly.');
  return least.toString();
}
/// Why `amountMicros` of an order cannot be one fill (6.11), in words, or null when it can. `order` has
/// `amount_micros`, `price`, `min_sats`; `rules` is TimeSDK.marketRules of the network.
/// The least a Bitcoin payment to an address can carry: Bitcoin Core refuses to send, and to relay, an output below its
/// dust amount (at the default dust fee: 294 satoshis to a SegWit address, 330 to a Taproot one, 546 to the oldest form).
/// The rules of a test network let a trade cost less (its smallest trade can be one satoshi); such a purchase could
/// never be paid, so the wallet does not make one. Found by the market simulation on a test network, 27 November 2026.
export const BITCOIN_DUST_SATS = 546n;
const dustWords = (cost) => `Bitcoin does not send so little: a payment of less than ${grouped(BITCOIN_DUST_SATS.toString())} satoshis to an address is refused by Bitcoin wallets. This amount costs ${grouped(cost.toString())} satoshis: choose more.`;
/// Why an amount of an order cannot be one fill (spec/market.md, 6.11, and what Bitcoin sends), or null.
export function sizeRefusal(sdk, order, amountMicros, rules) {
  const amount = big(String(amountMicros)), offer = big(order.amount_micros);
  if (amount < 1n) return 'Enter an amount.';
  if (amount > offer) return `This order offers ${secondsText(offer)} seconds, no more.`;
  const cost = BigInt(sdk.marketSats(amount.toString(), order.price)), least = big(order.min_sats);
  if (amount === offer && cost >= big(rules.minSats) && cost < BITCOIN_DUST_SATS) return dustWords(cost);
  if (amount === offer) return cost >= big(rules.minSats) ? null : `What is left of this order costs less than the smallest trade of the network (${grouped(rules.minSats)} satoshis).`;
  if (cost < least) return `The smallest purchase of this order costs ${grouped(order.min_sats)} satoshis. This amount costs ${grouped(cost.toString())}.`;
  if (cost < BITCOIN_DUST_SATS) return dustWords(cost);
  const rest = BigInt(sdk.marketSats((offer - amount).toString(), order.price));
  if (rest < least) return `That would leave ${secondsText(offer - amount)} seconds in the order, less than its smallest purchase. Take all ${secondsText(offer)} seconds, or at most ${secondsText(offer - BigInt(leastAmountFor(sdk, order.min_sats, order.price)))}.`;
  return null;
}
/// The largest amount of an order, at most `wantedMicros`, that can be one fill (6.11), or '0' when none can.
export function fitAmount(sdk, order, wantedMicros, rules) {
  const offer = big(order.amount_micros), wanted = min(big(String(wantedMicros)), offer);
  if (wanted < 1n) return '0';
  if (sizeRefusal(sdk, order, wanted, rules) === null) return wanted.toString();
  if (wanted === offer) return '0';
  // A part that would leave too little: the largest part that leaves the order its smallest purchase.
  const part = offer - BigInt(leastAmountFor(sdk, order.min_sats, order.price));
  return part >= 1n && part <= wanted && sizeRefusal(sdk, order, part, rules) === null ? part.toString() : '0';
}
function secondsText(micros) { const value = big(String(micros)), fraction = (value % MICROS).toString().padStart(6, '0').replace(/0+$/, ''); return `${value / MICROS}${fraction ? '.' + fraction : ''}`; }
export { secondsText };

// ---------------------------------------------------------------- picking sell orders for a purchase
/// The sell orders of a list (the index's word: market-api.mjs, `orders`) that could take a fill, best first: lowest
/// price, then the older order. Left out: closed or empty orders, orders without a free address, the account's own.
export function takeable(orders, ownAccount) {
  return orders.filter(order => order.side === 'sell' && order.open === true && order.takes_fill !== false && order.free_scripts !== 0 && BigInt(order.amount_micros) > 0n && order.owner !== String(ownAccount))
    .sort((a, b) => (BigInt(a.price) < BigInt(b.price) ? -1 : BigInt(a.price) > BigInt(b.price) ? 1 : BigInt(a.id) < BigInt(b.id) ? -1 : 1));
}
/// A plan for "I want N seconds" (`want.amountMicros`) or "I have X bitcoin" (`want.sats`): the purchases to make, in
/// the order of the best price, each from one sell order, at most `most` of them. Each is one fill and one Bitcoin
/// payment. A plan is a proposal made from a LIST: before a purchase is signed its order is read again, proven, and
/// compared (orderChanged). `skip`: ids of orders not to use (their owner does not stand, or their proven row differed).
/// Gives `{ takes: [{ order, owner, price, amountMicros, sats, depositMicros, confirmations, payBlocks, minSats }],
/// amountMicros, sats, depositMicros, shortMicros | shortSats }`.
export function planPurchase(sdk, orders, want, rules, { ownAccount = '', skip = [], most = 4 } = {}) {
  const byAmount = want.amountMicros !== undefined;
  let left = big(String(byAmount ? want.amountMicros : want.sats));
  assert(left >= 1n, byAmount ? 'Enter how many seconds you want.' : 'Enter how much bitcoin you have.');
  const takes = [];
  for (const order of takeable(orders, ownAccount)) {
    if (left < 1n || takes.length >= most) break;
    if (skip.includes(order.id)) continue;
    const wanted = byAmount ? left : BigInt(sdk.marketBought(left.toString(), order.price));
    const amount = BigInt(fitAmount(sdk, order, wanted, rules));
    if (amount < 1n) continue;
    const sats = BigInt(sdk.marketSats(amount.toString(), order.price));
    // "I have X bitcoin": a purchase never costs more than what is left of X.
    if (!byAmount && sats > left) continue;
    takes.push({ order: order.id, owner: order.owner, price: order.price, amountMicros: amount.toString(), sats: sats.toString(), depositMicros: takeDeposit(order, amount), confirmations: order.confirmations, payBlocks: order.pay_blocks, minSats: order.min_sats });
    left -= byAmount ? amount : sats;
  }
  const sum = field => takes.reduce((total, take) => total + BigInt(take[field]), 0n).toString();
  return { takes, amountMicros: sum('amountMicros'), sats: sum('sats'), depositMicros: sum('depositMicros'), ...(byAmount ? { shortMicros: left.toString() } : { shortSats: left.toString() }) };
}

// ---------------------------------------------------------------- proven against listed
const ORDER_FIELDS = Object.freeze([['side', 'side'], ['owner', 'owner'], ['price', 'price'], ['amount_micros', 'amount on offer'], ['min_sats', 'smallest purchase'], ['confirmations', 'confirmations'], ['pay_blocks', 'time to pay'], ['deposit_ppm', 'deposit'], ['min_deposit_micros', 'least deposit'], ['open', 'open']]);
/// Where the proven row of an order differs from what a list said of it: `[{ field, name, listed, proven }]`, empty when
/// they agree. `proven` null (the order is gone) is one difference, `gone`. The page stops on any difference: what it
/// then shows and signs is the proven row, after the person has seen it.
export function orderChanged(listed, proven) {
  if (proven === null) return [{ field: 'gone', name: 'order', listed: 'there', proven: 'gone' }];
  const out = [];
  for (const [field, name] of ORDER_FIELDS) if (listed[field] !== undefined && String(listed[field]) !== String(proven[field])) out.push({ field, name, listed: String(listed[field]), proven: String(proven[field]) });
  return out;
}
/// The same for what was planned from an order (a price and the terms) against its proven row, with the amount the
/// plan would take: a proven order that no longer offers that amount is a difference too.
export function planChanged(take, proven) {
  if (proven === null) return [{ field: 'gone', name: 'order', listed: 'there', proven: 'gone' }];
  const out = orderChanged({ side: 'sell', owner: take.owner, price: take.price, min_sats: take.minSats, confirmations: take.confirmations, pay_blocks: take.payBlocks, open: true }, proven);
  if (BigInt(proven.amount_micros) < BigInt(take.amountMicros)) out.push({ field: 'amount_micros', name: 'amount on offer', listed: take.amountMicros, proven: proven.amount_micros });
  if (takeDeposit(proven, take.amountMicros) !== take.depositMicros) out.push({ field: 'deposit', name: 'deposit', listed: take.depositMicros, proven: takeDeposit(proven, take.amountMicros) });
  return out;
}
export function changedWords(changes) {
  if (changes.some(change => change.field === 'gone')) return 'This order is gone: it was cancelled or sold. Nothing was signed. Look for another offer.';
  if (changes.some(change => change.field === 'open')) return 'This order is closed: its owner cancelled it. Nothing was signed. Look for another offer.';
  const price = changes.find(change => change.field === 'price');
  if (price) return `The price changed: the chain says ${priceWords(price.proven)}, the list said ${priceWords(price.listed)}. Nothing was signed. Look at the offer again.`;
  return `The order is not what the list said (${changes.map(change => change.name).join(', ')}). Nothing was signed. Look at the offer again.`;
}
/// Whether a fill that a list named is the fill the chain proves: the same order, script, price, payer, owner and
/// receiver, and no more to pay than the list said. Gives the names of what differs.
export function fillChanged(listed, proven) {
  if (proven === null) return ['gone'];
  const out = [];
  for (const field of ['order', 'script', 'price', 'payer', 'owner', 'to', 'side']) if (listed[field] !== undefined && String(listed[field]) !== String(proven[field])) out.push(field);
  return out;
}
/// Whether the owner of a proven order stands (spec/market.md, 6.10), judged on rows of the same verified state: the
/// order's key is still a spending key of the owner, and the owner is not frozen. `frozen(row, now)` is the wallet
/// library's reading of a security row. Null when the state does not carry the owner.
export function ownerStands(sdk, state, order, frozen) {
  const account = (state.accounts ?? []).find(item => String(item.id) === order.owner);
  if (!account || !Array.isArray(account.devices) || !Array.isArray(state.security)) return null;
  if (!account.devices.some(device => device?.can_spend === true && device.public_key === order.key)) return false;
  const row = state.security.find(item => String(item.account) === order.owner) ?? null;
  return row === null ? true : !frozen(row, BigInt(sdk.securityNow(state)));
}

// ---------------------------------------------------------------- a purchase in progress
/// The Bitcoin header chain as a verified state proves it: `{ best, halted }`.
export function headerChain(state) {
  const meta = state?.bitcoin?.meta;
  assert(meta && Number.isInteger(meta.best_height) && meta.best_height >= 0, 'The state does not prove the Bitcoin header chain.');
  return { best: BigInt(meta.best_height), halted: meta.halted !== null && meta.halted !== undefined };
}
/// The time a proven fill leaves its payer, by Bitcoin heights (spec/market.md, 5.5):
/// - `payBy`: the last Bitcoin height a payment can be in and still get its confirmations in time
///   (start_height + pay_blocks);
/// - `lastHeight`: the height by which it must have them (TimeSDK.marketFillLastHeight);
/// - `blocksLeft`: payBy less the best height the chain knows ('0' when the time is over);
/// - `over`: the chain already knows a height above payBy.
export function payWindow(sdk, state, fill) {
  const chain = headerChain(state), payBy = BigInt(fill.start_height) + BigInt(fill.pay_blocks), left = payBy - chain.best;
  return { payBy: payBy.toString(), lastHeight: sdk.marketFillLastHeight(fill), blocksLeft: (left > 0n ? left : 0n).toString(), over: left <= 0n, halted: chain.halted, best: chain.best.toString() };
}
/// What the pay screen says of a purchase, from the proven fill row (or its proven absence) and what this browser
/// noted when the fill was made (`note.firstSats`: what was to pay then). `ended`: how the index says an ended fill
/// ended (the index's word, shown as such), or null.
/// - 'waiting': nothing counted yet, as far as this browser can tell;
/// - 'part': less is still to pay than at the start;
/// - 'ended': the chain holds no such fill any more.
export function purchaseState(fill, note = null, ended = null) {
  if (fill === null) return { key: 'ended', how: ['paid', 'expired', 'released', 'settled'].includes(ended) ? ended : 'unknown' };
  const first = note?.firstSats !== undefined && DECIMAL.test(String(note.firstSats)) ? BigInt(note.firstSats) : null, now = BigInt(fill.sats);
  if (first !== null && now < first) return { key: 'part', paidSats: (first - now).toString(), sats: fill.sats };
  return { key: 'waiting', sats: fill.sats };
}
/// A `bitcoin:` link for a payment (BIP 21): the address and the amount in BTC. A Bitcoin wallet shows both again.
export function bitcoinLink(address, sats) { assert(/^[0-9A-Za-z]{14,90}$/.test(address), 'An address was expected.'); return `bitcoin:${address}?amount=${btcText(sats)}`; }

export const PAY_WORDS = Object.freeze({
  exact: 'Pay exactly this amount, in one payment if you can. Paying more buys nothing more. If you pay less, that part is counted and the rest stays to pay, to the same address, while this purchase is open.',
  exchange: 'Paying from an exchange is risky. It may send late, send less than the amount because it keeps a fee, or send your payment in one large batch with many others: a payment in a transaction larger than 100,000 bytes cannot be proven. Pay from a Bitcoin wallet you control if you can.',
  late: 'If your payment gets into a Bitcoin block after this purchase has ended, the bitcoin is with the seller and you get no seconds for it. Nobody can undo that. Use a fee in your Bitcoin wallet that confirms in time.',
  compare: 'Before you send: compare this address with the one your Bitcoin wallet shows, character by character.',
  proof: 'A service shows the chain the proof of your payment for you. If your seconds have not arrived an hour after the confirmations, anyone who runs a Bitcoin node can send the proof: note the number of this purchase, and see "Proving one payment by hand" in the prover\'s guide (deploy/market-prover/README.md).',
  giveUp: 'Giving up costs the deposit: it goes to the seller.',
  publicNote: 'This purchase, its address and your Bitcoin payment are public on both chains, and tie your account to that payment.',
  halted: 'The chain has stopped following Bitcoin, so a payment cannot be proven now. Do not pay now. Only the seller can still hand over the seconds, and you can give up.',
  over: 'The time to pay is over on the chain. A payment sent now will probably come too late: the bitcoin would be with the seller, for nothing.',
  helper: 'Someone else prepared this purchase for you: another account chose the seller and locked the deposit. The price, the address and the time below are read from the chain, not from that account. Check them before you pay.',
  small: 'A part smaller than the seller\'s smallest purchase, and smaller than half of what is still to pay, is not counted. A rest of a few hundred satoshis may be too small for Bitcoin to carry: it can then only be paid by paying more.',
});
export const SELL_WORDS = Object.freeze({
  publicNow: 'The addresses you choose become public for good when the order is signed, next to your account.',
  only: 'Any payment to one of these addresses counts for the purchase that uses it. Use them for nothing else.',
  final: 'A sale is final as soon as the payment is proven. If Bitcoin later drops the block that held the payment, you have lost the seconds: that is what the confirmations are for.',
  hold: 'A buyer may take your offer and not pay. Your seconds are then held until the time to pay has passed, and you keep the deposit.',
  record: 'A record of one trade, not a quote and not what a second is worth: anyone can record a trade with themselves at any price.',
  settle: 'This gives the buyer the seconds without any proof that bitcoin arrived. Do it only if you see the whole payment in your own Bitcoin wallet, with enough confirmations. It cannot be undone.',
  readBack: 'Read back from the chain. Compare each address with your Bitcoin wallet: these are the addresses buyers will pay to.',
});

// ---------------------------------------------------------------- the terms of an order
/// The terms a sell form starts with, from the network's rules (TimeSDK.marketRules): the fewest confirmations the
/// network takes (3 on a production network: Bitcoin reorganises two blocks from time to time), six blocks to pay or
/// the network's least if that is more, a deposit of 3% (what a buyer's free choice has been valued at: spec 10.9).
export function sellDefaults(rules) {
  return { confirmations: rules.kMin, payBlocks: max(big(rules.nMin), 6n).toString(), depositPpm: max(big(rules.bondMinPpm), 30000n).toString(), minDepositMicros: '0' };
}
/// The smallest purchase a sell form suggests: the order's price shared over its addresses, so that the addresses
/// listed are enough to sell all of it (each purchase uses one), and at least the network's smallest trade.
export function suggestedMinSats(sdk, amountMicros, price, addresses, rules) {
  const total = BigInt(sdk.marketSats(String(amountMicros), String(price))), count = BigInt(Math.max(1, addresses));
  return min(max((total + count - 1n) / count, big(rules.minSats)), total).toString();
}
/// Why the terms of an order are not ones the network takes (6.1, 2.1), in words, or null.
export function termsRefusal(sdk, terms, rules) {
  const amount = big(terms.amountMicros), price = big(terms.price), confirmations = big(terms.confirmations), payBlocks = big(terms.payBlocks), deposit = big(terms.depositPpm), least = big(terms.minSats);
  if (amount < 1n) return 'Enter how many seconds.';
  let cost;
  try { cost = BigInt(sdk.marketSats(amount.toString(), price.toString())); } catch { return 'This amount at this price costs more bitcoin than exists.'; }
  if (confirmations < big(rules.kMin) || confirmations > big(rules.kMax)) return `Confirmations: from ${rules.kMin} to ${rules.kMax} on this network.`;
  if (payBlocks < big(rules.nMin) || payBlocks > big(rules.nMax)) return `Time to pay: from ${rules.nMin} to ${rules.nMax} Bitcoin blocks on this network.`;
  if (least < big(rules.minSats)) return `The smallest purchase is at least ${grouped(rules.minSats)} satoshis on this network.`;
  if (cost < least) return `All of this order costs ${grouped(cost.toString())} satoshis, less than its smallest purchase of ${grouped(least.toString())}.`;
  if (deposit > PPM) return 'A deposit is at most 100%.';
  if (terms.side === 'buy') {
    if (deposit < big(rules.bondMinPpm)) return `The bond of a buy order is at least ${percentText(rules.bondMinPpm)} on this network.`;
    if (!Array.isArray(terms.forms) || terms.forms.length < 1) return 'Choose at least one kind of address you can pay to.';
    return null;
  }
  if (big(terms.minDepositMicros) > amount) return 'The least deposit is at most the seconds on offer.';
  if (!Array.isArray(terms.scripts) || terms.scripts.length < 1) return 'Choose at least one of your Bitcoin addresses. Each purchase uses one.';
  if (terms.scripts.length > rules.scripts) return `An order lists at most ${rules.scripts} addresses that have not served.`;
  return null;
}

// ---------------------------------------------------------------- what an action costs, and the daily limit
/// What an action of the market takes from the sender's balance (`outflow`) and what it counts against a protected
/// account's daily limit (`count`), by spec/market.md, section 7. `fee` is all of its fees (TimeSDK.marketActionFee).
/// - an order: the seconds of a sell order, or the bond of a buy order (`locked`);
/// - a take: the deposit; a sale into a buy order: the seconds sold (`locked`);
/// - a cancel: nothing but the fee, and not even that when more comes back than the fee (`back`);
/// - a settle: the seconds handed over count although the balance does not fall by them (`extra`);
/// - a release: the seconds the fill still held, and the deposit if the sender locked it (`extra`);
/// - new addresses: the seconds the order has on offer and in its open purchases (`extra`);
/// - an expiry: the fee, less what comes back to the sender (`back`).
export function marketCharge({ fee, locked = '0', extra = '0', back = '0' }) {
  const paid = big(String(fee)) + big(String(locked)), returned = big(String(back)), outflow = paid > returned ? paid - returned : 0n;
  return { outflow, count: outflow + big(String(extra)), fee: big(String(fee)), locked: big(String(locked)), extra: big(String(extra)) };
}
/// Whether the action can be signed now, in words: the refusal, or for a protected account the line of the review
/// that says what it uses of the daily limit. `secured`: the account has the protection rules; then `allowance` (what
/// is left of today's limit), `frozen` and `limit` are read from its proven security row. `seconds(micros)` writes an
/// amount. A frozen account sends nothing that lowers its balance or counts against its limit; an action that brings
/// back at least what it costs passes.
export function limitWords({ charge, balance, secured, allowance = 0n, frozen = false, limit = 0n, seconds, what = 'This' }) {
  const have = big(String(balance));
  if (secured && frozen && (charge.outflow > 0n || charge.count > 0n)) return { refusal: 'Your account is frozen, so it cannot do this until the freeze ends. See Home, under Protection.' };
  if (have < charge.fee + charge.locked && charge.outflow > 0n) return { refusal: `You do not have enough seconds for this: it needs ${seconds(charge.fee + charge.locked)} seconds${charge.locked > 0n ? ` (${seconds(charge.locked)} locked and ${seconds(charge.fee)} in fees)` : ' in fees'}, and your balance is ${seconds(have)}.` };
  if (!secured) return { line: null };
  const left = BigInt(allowance);
  if (charge.count > left) {
    const reason = charge.count > BigInt(limit) ? `more than your daily limit of ${seconds(BigInt(limit))} seconds. Raise the limit on Home, under Protection (it waits, or applies at once with a recovery paper)` : `more than the ${seconds(left)} seconds left of your daily limit today. Try again when enough of it has come back, or raise the limit on Home, under Protection`;
    return { refusal: `Daily limit reached. ${what} counts ${seconds(charge.count)} seconds against your daily limit, like a payment: ${reason}.` };
  }
  if (charge.count === 0n) return { line: 'Nothing of your daily limit is used.' };
  return { line: `${seconds(charge.count)} seconds count against your daily limit, like a payment: ${seconds(left)} is left today, ${seconds(left - charge.count)} after this.` };
}

// ---------------------------------------------------------------- an offer against the rest of the book
/// How far a sell price stands above the other offers, for a warning before a person pays (the study of earlier
/// thefts: a helper, or a list, can point a buyer at a seller far from the market). `others`: the prices of the other
/// sell orders that take fills (the index's word). Far: more than a fifth above the lowest of them.
export function againstBook(price, others) {
  const mine = big(String(price)), rest = others.map(value => big(String(value))).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (rest.length === 0) return { far: false, alone: true, best: null };
  const best = rest[0];
  return { far: mine * 5n > best * 6n, alone: false, best: best.toString() };
}
export function againstBookWords(price, verdict) {
  if (verdict.alone) return 'No other offer is on the list to compare this price with.';
  if (verdict.far) return `This seller's price is far above another offer on the list: ${priceWords(price)}, against ${priceWords(verdict.best)}. Check before you pay.`;
  return `The lowest other offer on the list is ${priceWords(verdict.best)}.`;
}

// ---------------------------------------------------------------- what this browser notes of its purchases
// When this browser makes a fill it notes what was to pay then, so that the pay screen can say "a part was counted"
// later (the proven row holds only what is still to pay). Nothing secret; kept in the clear like the address list.
// A browser without the note (another device) says what the proven row says, and the index's list of payments beside it.
export const NOTES_PREFIX = 'timecurrency.market-fills.v1:';
export const notesKey = (networkId, name) => `${NOTES_PREFIX}${networkId}:${name}`;
export function readNotes(stored) {
  let parsed = null;
  try { parsed = typeof stored === 'string' ? JSON.parse(stored) : null; } catch { parsed = null; }
  const out = {};
  if (!parsed || parsed.v !== 1 || !parsed.fills || typeof parsed.fills !== 'object') return out;
  for (const [id, note] of Object.entries(parsed.fills).slice(-64)) if (DECIMAL.test(id) && note && DECIMAL.test(String(note.firstSats)) && DECIMAL.test(String(note.order))) out[id] = { firstSats: String(note.firstSats), order: String(note.order) };
  return out;
}
export function withNote(stored, id, note) { const fills = readNotes(stored); fills[String(id)] = { firstSats: String(note.firstSats), order: String(note.order) }; return JSON.stringify({ v: 1, fills: Object.fromEntries(Object.entries(fills).slice(-64)) }); }
/// The id that `after` holds and `before` does not: the order or the fill an action of this account has just made, read
/// from the account's proven row (`market/account/<id>`) before and after. The newest when several are new.
export function newId(before, after) { const had = new Set(before), fresh = after.filter(id => !had.has(id)); return fresh.length ? fresh.reduce((a, b) => (BigInt(a) > BigInt(b) ? a : b)) : null; }

// ---------------------------------------------------------------- a refusal of the chain, in the wallet's words
// When the chain refuses an action of the market, the refusal reaches the wallet through its gateway, as text. That
// text is never shown as the wallet's own. It is only read for a few of the engine's fixed words (v5/src/market.rs,
// bitcoin-bridge/src/chain.rs), to pick one of the sentences below; the page shows the gateway's words after it, marked
// as the gateway's, as everywhere. A refusal changes nothing on the chain: nothing was locked and nothing was lost.
const REFUSALS = Object.freeze([
  [/Bitcoin header tip stale|header chain is not fresh/i, 'The chain refused this: it is not receiving Bitcoin\'s block headers right now, and no purchase can start until it does. Nothing was locked. Try again later.'],
  [/header chain.*halted|halted/i, 'The chain refused this: it has stopped following Bitcoin. Nothing was locked.'],
  [/not an open sell order|not an open buy order|this action names an order/i, 'The chain refused this: the order is gone or closed. It was taken, sold or cancelled in the same moment. Nothing was locked. Look at the offers again.'],
  [/the owner of this order is frozen/i, 'The chain refused this: the owner of the order cannot trade right now. Nothing was locked. Look for another offer.'],
  [/satoshis named are the price|size of the fill|smallest trade/i, 'The chain refused this: the price or the size no longer fits the order. Nothing was locked. Look at the offer again.'],
  [/receiving script serves one order or fill|no receiving script left/i, 'The chain refused this: an address is already in an order or was used, or the order has no free address left. Nothing was locked.'],
  [/over the daily limit/i, 'The chain refused this: it is more than what is left of your daily limit. Nothing was locked. See Home, under Protection.'],
  [/frozen/i, 'The chain refused this: your account is frozen. Nothing was locked. See Home, under Protection.'],
  [/too many open/i, 'The chain refused this: the account has as many open orders or purchases as the chain allows. Nothing was locked.'],
  [/this action names a fill|cannot end yet/i, 'The chain refused this: the purchase has ended already, or cannot end yet. Nothing was changed.'],
  [/insufficient funds/i, 'The chain refused this: the account does not hold enough seconds. Nothing was locked.'],
]);
export const REFUSED = 'The chain refused this. Nothing was locked and nothing was lost.';
/// The wallet's sentence for a refusal whose text a gateway passed on. The text picks the sentence and is not in it.
export function refusalWords(text) { const said = typeof text === 'string' ? text.slice(0, 2000) : ''; return REFUSALS.find(([pattern]) => pattern.test(said))?.[1] ?? REFUSED; }
