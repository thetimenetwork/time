#!/usr/bin/env node
// Proves the payment of one fill, once: for a person who has a Bitcoin node and runs no service.
//
//   node deploy/market-prover/prove.mjs CONFIG_JSON --fill N
//
// The config is the prover's (deploy/market-prover/README.md): how to reach the chain, the Bitcoin nodes, the
// account that pays the proof's fee, where its key is, and the budgets. The code is the service's own
// (client-v4/market-prover.mjs), told to look at one fill: it reads the fill with a proof, searches the blocks the
// fill can be paid in for outputs to its address, sends a proof for each payment that has its confirmations and
// counts, waits for a block, and says what the fill held before and holds after. It then stops.
//
// Exit codes: 0 a payment was proven, or the fill has ended and nothing is left to prove; 2 no payment to the
// fill's address was found; 3 a payment was found and could not be proven now (the reason is printed); 1 anything
// else (the config, the key, the chain or the nodes).
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readServiceConfig } from '../market-relay/start.mjs';
import { prepare } from './start.mjs';

/// Runs the one-shot proof. `write` prints a line; `inject` is `prepare`'s. Returns the exit code.
export async function proveOnce(rawConfig, fill, { write = (line) => process.stdout.write(`${line}\n`), inject = {}, maxRounds = 40 } = {}) {
  if (typeof fill !== 'string' || !/^[1-9][0-9]{0,19}$/.test(fill)) throw new Error('--fill takes the id of a fill: a whole number from 1');
  // The service's lines, as plain text: what was found, what was sent, what the chain did with it.
  const log = (level, message, fields = {}) => write(`${level === 'info' ? '' : `${level.toUpperCase()}: `}${message}${Object.keys(fields).length ? ` ${JSON.stringify(fields)}` : ''}`);
  const { prover, release } = await prepare(rawConfig, { ...inject, log }, { only: fill });
  try {
    // Rounds until every block is searched and nothing is on its way.
    for (let rounds = 0; rounds < maxRounds; rounds++) {
      const { more } = await prover.round(), health = prover.health().body;
      if (!more && !health.action_in_no_block_yet) break;
    }
    const { body } = prover.health(), report = prover.report(), found = report.payments, open = report.fills.find((row) => row.id === fill) ?? null;
    if (!['ok', 'catching_up', 'waiting_for_a_block'].includes(body.status)) { write(`Nothing could be done: ${body.problems.join('; ') || body.status}`); return 1; }
    write(open ? `Fill ${fill} is open: ${open.sats} satoshis are still to pay to its address, for ${open.amount_micros} microseconds.` : `Fill ${fill} has no row: it has ended, or it was never made.`);
    for (const payment of found) write(`Payment ${payment.txid}:${payment.vout} of ${payment.sats} satoshis in block ${payment.block} (height ${payment.height}): ${payment.proven ? 'proven' : payment.cannot ? `cannot be proven: ${payment.cannot}` : payment.never ? 'made before the fill: it does not count' : payment.too_small_now ? 'too small to count now' : 'not proven yet'}.`);
    if (found.some((payment) => payment.proven)) return 0;
    if (!open) return 0;
    if (found.length === 0) { write(`No payment to the address of fill ${fill} was found in the Bitcoin blocks the chain knows (up to height ${body.header_chain?.best_height}). A payment in a newer block is found when the chain has been told of that block.`); return 2; }
    if (body.action_in_no_block_yet) write('A proof was handed in and is in no block yet. Run this again in a moment: the same payment is not proven twice.');
    else write(`A payment was found and is not proven: it lacks confirmations on the chain's view of Bitcoin (the fill asks ${open.confirmations}), or see the lines above.`);
    return 3;
  } finally { await prover.stop(); await release(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => {
    const [file, flag, fill] = process.argv.slice(2);
    if (process.argv.length !== 5 || flag !== '--fill') throw new Error('Usage: node deploy/market-prover/prove.mjs CONFIG_JSON --fill N');
    process.exitCode = await proveOnce(await readServiceConfig(file), fill);
  })().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
