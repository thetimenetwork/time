#!/usr/bin/env node
// A take of a sell order, and what to pay for it, with the SDK. The same trade as clients/python/examples/buy_taker.py,
// with one difference: here every row that decides something is PROVEN before it is used.
//
//   node client-v4/examples/market-take.mjs take --gateway https://wallet.example --trust trust.json --bitcoin-network regtest \
//        --account 6 --order 1 --amount-micros 20000000 --limit-price 250000000
//   node client-v4/examples/market-take.mjs pay  --gateway https://wallet.example --trust trust.json --bitcoin-network regtest \
//        --account 6 --fill 2
//
// `take` is a dry run unless it is given --act, with --key-env NAME (the environment variable that holds the signing
// key: never the key itself on the command line), --max-balance-micros and --max-daily-limit-micros (it refuses an
// account that holds more, or may move more in a day). `pay` signs nothing: it reads a fill and says what to pay.
//
// What it needs: a wallet gateway of the network (the SDK's `gateway`, as deploy/watch uses one) and the network's
// trust manifest, INSTALLED FROM A SOURCE INDEPENDENT OF THAT GATEWAY. The gateway supplies data. It cannot choose the
// validators the proofs are checked against: those come from the manifest.
//
// It holds no Bitcoin key. Paying is your own step, and so is proving the payment to the chain, unless a prover
// serves the network (deploy/market-prover/README.md).
//
// Not run by any test: the path of --act (the signature, the submission, the wait for the receipt). It needs a
// gateway and a chain. The tests beside this file run the dry run and `pay` against the engine's proven rows, through
// the installed verifier.
import { readFile } from 'node:fs/promises';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { parseArgs } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../time-sdk.js';
import * as installed from '../proof-verifier.mjs';
import { scriptToAddress } from '../bitcoin-address.mjs';

const SDK = globalThis.TimeSDK;
/// A reason not to go on: nothing was signed.
export class Refusal extends Error {}
const refuse = (words) => { throw new Refusal(words); };
/// Satoshis as the decimal number of bitcoin a wallet takes, exactly: 5000 is "0.00005000".
export const bitcoinAmount = (sats) => `${BigInt(sats) / 100000000n}.${String(BigInt(sats) % 100000000n).padStart(8, '0')}`;
const seconds = (micros) => `${BigInt(micros) / 1000000n}.${String(BigInt(micros) % 1000000n).padStart(6, '0')}`.replace(/\.?0+$/, '') + ' s';

// ---- THE DIFFERENCE FROM THE PYTHON EXAMPLE, IN TEN LINES ---------------------------------------------------------
// The Python script asks an API for the fill and believes the answer: an API that lies can name an address of its
// own. Here the answer comes with a proof. `getVerifiedState` checks it against the signatures of the validators,
// starting from your trust manifest, and throws when it does not hold. `marketFill` throws unless that row was
// proven, in its one form, and gives null for a fill PROVEN absent: it has ended, and a payment would buy nothing.
export async function provenFill(client, id) {
  const { state } = await client.getVerifiedState({ market_fills: [id], include_bitcoin: true });
  const fill = SDK.marketFill(state, id);
  if (fill === null) return null;
  const { state: more } = await client.getVerifiedState({ market_orders: [fill.order] });
  const chain = state.bitcoin?.meta ?? {};
  return { fill, order: SDK.marketOrder(more, fill.order), lastHeight: SDK.marketFillLastHeight(fill), network: chain.config?.network ?? null, bestHeight: chain.best_height ?? null, halted: (chain.halted ?? null) !== null };
}
// -------------------------------------------------------------------------------------------------------------------

/// What to pay for a fill, from proven rows: the lines for the person who pays. `expect` names what the fill must be
/// (its order, the account its seconds go to, its price, the scripts the order showed before the take).
export async function whatToPay(client, { fill: id, account, network, expect = {} }) {
  const proven = await provenFill(client, id);
  if (proven === null) refuse(`Fill ${id} is proven absent: it has ended, or it was never made. PAY NOTHING: a payment to its address now is for nothing.`);
  const { fill, lastHeight } = proven;
  if (proven.network !== network) refuse(`The chain follows Bitcoin ${proven.network}, and you named ${network}: an address of one is not an address of the other.`);
  if (fill.payer !== account) refuse(`Fill ${id} is not paid by account ${account}: nothing is paid to it.`);
  const differs = ['order', 'to', 'price'].filter((name) => expect[name] !== undefined && fill[name] !== expect[name]);
  if (expect.scripts && !expect.scripts.includes(fill.script)) differs.push('script');
  if (differs.length) refuse(`Fill ${id} is not what the take made (${differs.join(', ')} differ). PAY NOTHING.`);
  const address = await scriptToAddress(fill.script, network);
  return { fill, address, sats: fill.sats, lines: [
    `Fill ${id} (proven): ${seconds(fill.amount_micros)} for account ${fill.to}, at ${fill.price} millionths of a satoshi a second.`,
    `  PAY ${fill.sats} satoshis (${bitcoinAmount(fill.sats)} BTC) to ${address}`,
    `  Confirmations asked: ${fill.confirmations}, reached by Bitcoin height ${lastHeight} at the latest; the chain knows height ${proven.bestHeight} now${proven.halted ? ', and its header chain is HALTED: no payment can be proven' : ''}.`,
    `  A part counts if it is at least ${proven.order?.min_sats ?? '?'} satoshis, or at least half of what is still to pay. What is paid above ${fill.sats} buys nothing.`,
    `  Then the payment must be proven to the chain: a prover service does it, or you do (node deploy/market-prover/prove.mjs CONFIG --fill ${id}).`,
  ] };
}

/// The signing key from an environment variable, by the name the operator gives. The variable is removed from this
/// process at once; the key is imported so that it cannot be exported again, and is in no message.
export async function keyFromEnvironment(name) {
  if (typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) refuse('--key-env names an environment variable');
  const text = process.env[name];
  delete process.env[name];
  if (typeof text !== 'string' || !/^[0-9a-f]{64}$/.test(text)) refuse(`The environment variable ${name} does not hold a signing key: 64 lowercase hexadecimal characters`);
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(text, 'hex')]);
  return {
    publicKey: createPublicKey(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
    privateKey: await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign']),
  };
}

/// Takes `amountMicros` of sell order `order` for account `to`, if the PROVEN order asks at most `limitPrice`.
/// Without `act`: says what it would sign, and signs nothing. Returns { payload, lines, paid? }.
export async function take(client, { account, order, amountMicros, limitPrice, to = account, network, act = false, key = null, maxBalanceMicros, maxDailyLimitMicros }) {
  const lines = [];
  // The order, the fills this account pays already and the Bitcoin header chain, in one proof.
  const { state } = await client.getVerifiedState({ market_orders: [order], market_accounts: [account], include_bitcoin: true });
  const row = SDK.marketOrder(state, order), chain = state.bitcoin?.meta ?? {};
  if (row === null) refuse(`Order ${order} is proven absent: it was never made, or it is gone.`);
  if (chain.config?.network !== network || network === 'mainnet') refuse(`The chain follows Bitcoin ${chain.config?.network}; you named ${network}. Mainnet is closed in this version.`);
  if ((chain.halted ?? null) !== null) refuse('The chain\'s Bitcoin header chain is halted: no fill can be made.');
  if (row.side !== 'sell' || !row.open || row.owner === account) refuse(`Order ${order} is not an open sell order of somebody else.`);
  if (BigInt(row.price) > BigInt(limitPrice)) refuse(`Order ${order} asks ${row.price}, above your limit of ${limitPrice}: nothing is taken.`);
  const free = row.scripts.filter((entry) => entry.fill === undefined && entry.used !== true).map((entry) => entry.script);
  if (!free.length) refuse(`Order ${order} has no free receiving address: it takes no fill now.`);
  // `sats` is computed from the proven price and signed; the chain refuses the take if it is not the price of the amount.
  const payload = SDK.marketTake({ order, amountMicros, price: row.price, to });
  const byShare = (BigInt(amountMicros) * BigInt(row.deposit_ppm) + 999999n) / 1000000n, deposit = byShare > BigInt(row.min_deposit_micros) ? byShare : BigInt(row.min_deposit_micros);
  lines.push(`Order ${order} of account ${row.owner} (proven): ${seconds(amountMicros)} cost ${payload.sats} satoshis (${bitcoinAmount(payload.sats)} BTC) at ${row.price} millionths of a satoshi a second.`,
    `  A deposit of ${seconds(deposit)} is locked, and lost for what is not paid in time. Confirmations asked: ${row.confirmations}. Time to pay: ${row.pay_blocks} Bitcoin blocks.`,
    `  kind ${SDK.MARKET_KINDS.take}, payload ${JSON.stringify(payload)}`);
  if (!act) return { payload, lines: [...lines, '  DRY RUN: nothing was signed and nothing was sent. Run again with --act to send it.', `  The fill would get the order's first free address: ${await scriptToAddress(free[0], network)}. It is read from the proven fill before anything is paid.`] };

  // To act: the account itself, proven. The security rules, a daily limit and a balance under the operator's ceilings.
  if (!key || maxBalanceMicros === undefined || maxDailyLimitMicros === undefined) refuse('To act, give --key-env, --max-balance-micros and --max-daily-limit-micros.');
  const { state: mine } = await client.getVerifiedState({ ids: [account], include_security: true });
  const me = mine.accounts.find((item) => String(item.id) === account), security = (mine.security ?? []).find((item) => String(item.account) === account) ?? null;
  if (!me) refuse(`Account ${account} is proven absent.`);
  if (!security) refuse('This account has not adopted the account security rules: do that in your wallet first, with a daily limit.');
  if (BigInt(security.policy.daily_limit_micros) > BigInt(maxDailyLimitMicros) || (security.pending_limit && BigInt(security.pending_limit.daily_limit_micros) > BigInt(maxDailyLimitMicros))) refuse('The daily limit of this account, or a raise of it that is waiting, is higher than you allow.');
  if (BigInt(me.balance) > BigInt(maxBalanceMicros)) refuse('This account holds more than you allow: move the rest out first.');
  const before = SDK.marketAccount(state, account).fills;
  // perform reads the account once more with a proof, checks that the key may spend, signs with the proven nonce
  // plus one, submits, and waits for the receipt, which it verifies too.
  const receipt = await client.perform({ kind: SDK.MARKET_KINDS.take, account: { id: account }, publicKey: key.publicKey, privateKey: key.privateKey, payload });
  lines.push(`  The take is in a block (hash ${receipt.hash ?? 'see the receipt'}).`);
  // The chain's own, proven list of the fills this account pays: the new one is the fill.
  // A proven state is the state after a block, and the block after it carries its proof: right after the receipt the
  // newest state that can be proven may still be the one before the take. So the list is read again, a second apart,
  // until the fill shows (found on the first real network this example met: the first read came a block too early).
  let made = [];
  for (let tries = 0; tries < 15 && made.length === 0; tries++) {
    if (tries) await new Promise((resolve) => setTimeout(resolve, 1000));
    const { state: after } = await client.getVerifiedState({ market_accounts: [account] });
    made = SDK.marketAccount(after, account).fills.filter((id) => !before.includes(id));
  }
  if (made.length !== 1) refuse(`The take is in a block, and the account's proven list shows ${made.length} new fills, not one. Read the account's fills before anything is paid.`);
  const paid = await whatToPay(client, { fill: made[0], account, network, expect: { order, to, price: row.price, scripts: free } });
  return { payload, paid, lines: [...lines, ...paid.lines] };
}

/// The command line. Returns the exit code: 0 done, 2 refused, 1 anything else.
export async function main(argv, { write = (line) => process.stdout.write(`${line}\n`), verifier = installed, fetcher } = {}) {
  try {
    const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: {
      gateway: { type: 'string' }, trust: { type: 'string' }, 'bitcoin-network': { type: 'string' }, account: { type: 'string' }, order: { type: 'string' }, fill: { type: 'string' }, to: { type: 'string' },
      'amount-micros': { type: 'string' }, 'limit-price': { type: 'string' }, act: { type: 'boolean', default: false }, 'dry-run': { type: 'boolean', default: false }, 'key-env': { type: 'string' },
      'max-balance-micros': { type: 'string' }, 'max-daily-limit-micros': { type: 'string' } } });
    const [command] = positionals, network = values['bitcoin-network'];
    if (!['take', 'pay'].includes(command) || positionals.length !== 1 || !values.gateway || !values.trust || !values.account || !['regtest', 'testnet3'].includes(network) || (values.act && values['dry-run'])) {
      refuse('Usage: market-take.mjs take|pay --gateway URL --trust FILE --bitcoin-network regtest|testnet3 --account N, then for take: --order N --amount-micros A --limit-price P [--to N] [--act --key-env NAME --max-balance-micros B --max-daily-limit-micros L]; for pay: --fill N');
    }
    const trust = JSON.parse(await readFile(values.trust, 'utf8'));
    const client = SDK.createClient({ gateway: values.gateway, trust: trust.trust ?? trust, verifier, ...(fetcher ? { fetcher } : {}) });
    if (command === 'pay') {
      if (!values.fill) refuse('pay takes --fill N');
      for (const line of (await whatToPay(client, { fill: values.fill, account: values.account, network })).lines) write(line);
      write('  IF YOU HAVE PAID ALREADY, DO NOT PAY AGAIN.');
      return 0;
    }
    if (!values.order || !values['amount-micros'] || !values['limit-price']) refuse('take takes --order, --amount-micros and --limit-price');
    const key = values.act ? await keyFromEnvironment(values['key-env']) : null;
    const done = await take(client, { account: values.account, order: values.order, amountMicros: values['amount-micros'], limitPrice: values['limit-price'], to: values.to ?? values.account, network, act: values.act, key,
      maxBalanceMicros: values['max-balance-micros'], maxDailyLimitMicros: values['max-daily-limit-micros'] });
    for (const line of done.lines) write(line);
    return 0;
  } catch (error) {
    // A refusal says why. Anything else is a failed proof, an unreachable gateway or a bad argument: its message, no more.
    write(`${error instanceof Refusal ? 'REFUSED' : 'STOPPED'}: ${String(error?.message ?? error).replace(/[^\x20-\x7e]/g, ' ').slice(0, 400)}`);
    return error instanceof Refusal ? 2 : 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = await main(process.argv.slice(2));
