# Market prover

On a Time network with the market (`../../spec/market.md`) a buyer takes a sell order, pays bitcoin on the Bitcoin network to the address of the fill, and the chain hands the seconds over when someone shows it a proof of that payment (action kind 54). A proof needs the payment's transaction, the coinbase transaction of its block and a Merkle proof of the two, from a Bitcoin node. A wallet in a browser cannot ask a Bitcoin node. This process can.

It finds the payments to the addresses of open fills and sends the proofs, so that a buyer gets the seconds without doing anything. Anyone may prove any payment, and nobody is paid for it: each proof costs its sender a fee. So someone has to run this, and anyone can. It needs the header relay (`../market-relay/`) to be running somewhere: a proof counts only when the chain holds the payment's block.

## The prover's account and key

**The prover has an account of its own, which has adopted the chain's security rules with a daily limit and holds only what the proofs' fees need.** Set it up once, on a machine that is not the prover's:

1. **Register an account** for the prover and send it a little: a day or two of `max_fees_per_day_micros`. What is not there cannot be lost.
2. **Make five keys:** one spend key (for the service), one sign-in key, and three recovery keys.
3. **Adopt the security rules** with the account's first key (action kind 70, `payloads.secure` in `client-v4/account-security.mjs`): the keys with their roles, and a policy with `daily_limit_micros` at `max_fees_per_day_micros` or a little more, `threshold` 2, and `delay_seconds` and `freeze_seconds` of a day or more.
4. **Keep the recovery keys offline**, in different places. They never touch the prover's machine.
5. **Give the service the spend key only**: the 32-byte Ed25519 seed as 64 lowercase hexadecimal characters, on one line. Use this key for nothing else: the prover counts on being the only signer of the account.
6. **Have the account watched** (`../watch/`), and alert on `/health` answering anything but 200.

**Where the key comes from.** You name the place; there is no default one.

- `key_file`: the absolute path of a file that holds the line and nothing else. `chmod 600` it, owned by the user the prover runs as. The prover refuses a key file that other users of the machine can read.
- `key_env`: the name of an environment variable that holds the line. The prover removes the variable from its own environment as soon as it has read it. A service manager that can pass a secret as a variable without writing it to disk makes this the better choice.
- Never on the command line: what is typed there is shown to every user of the machine. Never in the config file.

The key is imported so that it cannot be exported again, and it is in no log line, no error, no health answer and no file the prover writes.

**What the prover checks, with a proof, before it starts and in every round.** It refuses to start, or stops sending, when:

- the key is not a key of the account, or may not spend;
- the key holds every power of the account (it must be a spend key only), or the account has not adopted the security rules. `allow_unsecured_account: true` turns these two off, for a laboratory network; the ceiling is then the only bound;
- **the account holds more than `max_balance_micros`.** That ceiling is yours to set, and it has no default. Someone who sends the account a large sum by mistake stops the prover until the surplus is moved away;
- the account is frozen.

**What a stolen prover key can do.** Spend the account's balance: at once within the daily limit, and all of it after `delay_seconds` unless the waiting payment is cancelled or the account frozen (`deploy/faucet/README.md`, "What a stolen faucet key can do", says it in full; the rules are the same). The balance is at most the ceiling. It can also use up the account's nonces, so that the prover's own proofs are refused and tried again. It cannot touch anyone's bitcoin: the prover holds no bitcoin key and never asks for one.

## Running it

Node 26 and this repository's `client-v4/` and `web-v4/shared/verifier/` are all it needs. It uses no npm packages. It contacts the Bitcoin nodes of its config and the one Time endpoint of its config, and nothing else.

```sh
cp deploy/market-prover/config.example.json /etc/time-market-prover/config.json   # then edit it
node deploy/market-prover/start.mjs /etc/time-market-prover/config.json
```

| Setting | Meaning |
|---|---|
| `rpc_url` or `gateway` | How the Time chain is reached: exactly one of the two, as for the relay (`../market-relay/README.md`). |
| `trust` | The trust manifest, the same object the SDK's `createClient({trust})` takes. Install it from a source independent of the endpoint. |
| `bitcoin_nodes` | One to eight Bitcoin Core nodes, as for the relay. The prover also reads blocks and transactions: `getblock`, `getrawtransaction` and `gettxoutproof` beside the relay's four calls. A pruned node must still hold the blocks open fills can be paid in. No transaction index (`txindex`) is needed: every call names the block. |
| `data_directory` | Holds `prover.json` (which fills it has looked at, what it spent today), `checkpoint.json` and `watch.lock`. One prover per directory. |
| `account` | The number of the prover's own account, in decimal and in quotes. |
| `key_file` or `key_env` | Where the spend key is: exactly one of the two. See above. |
| `max_balance_micros` | The ceiling. The prover does not start, and sends nothing, while its account holds more. No default. |
| `max_fee_per_proof_micros` | The most one proof may cost. A proof that would cost more is not sent, and the log and `/health` say so. No default. |
| `max_fees_per_day_micros` | The most a day (UTC) may cost. When it is used up the prover sends nothing until the next day, logs it once and answers 503. No default. |
| `min_balance_micros` | `/health` warns (`balance_low`) when the account holds less. Default 0. |
| `expire` | `true` to also end fills whose time has passed (kind 55). Default `false`. See "Ending fills that were not paid". |
| `allow_unsecured_account` | `true` to use an account without the security rules. Default `false`. |
| `poll_seconds` | How often it looks. Default 10. |
| `max_blocks_per_round` | The most Bitcoin blocks it reads in one round. Default 64. |
| `bitcoin_timeout_seconds`, `time_timeout_seconds` | Each call to a Bitcoin node, and each request to the Time endpoint, gives up after this long. Defaults 15 and 30. |
| `host`, `port`, `hosts` | Where the health answer is served. Default `127.0.0.1:8951`. |

Amounts are whole microseconds as decimal strings: `"5000000"` is five seconds. A setting the prover does not know is refused. A config file that holds a node's `password` in its own text is refused when other users of the machine can read it.

**What a proof costs.** The network's fee once, and once more for every 256 bytes of the proof's payload (`TimeSDK.marketActionFee`). At the usual fee of 1,000 microseconds: about 4,000 for a payment with two outputs in a block with a small coinbase, 23,000 for a payment an exchange sent with eighty others, a quarter of a second in a block whose coinbase pays a thousand miners, and two seconds at the largest sizes a proof may carry (`spec/market.md`, 10.16). `max_fee_per_proof_micros` decides which of these you pay for.

### Proving one payment by hand

For a person who has a Bitcoin node and runs no service:

```sh
node deploy/market-prover/prove.mjs /etc/time-market-prover/config.json --fill 17
```

The config is the same, and so is the code. It reads fill 17 with a proof, searches the Bitcoin blocks the fill can be paid in for outputs to its address, sends a proof for each payment that has its confirmations and counts, waits for a block, prints what the fill held before and holds after, and stops. It exits with 0 when a payment was proven (or the fill has ended), 2 when no payment was found, 3 when one was found and cannot be proven now (the reason is printed), and 1 for anything else. It takes the lock of the data directory: stop a prover that runs on the same directory first, or give the tool a directory of its own.

### The health answer

`GET /health` on the port: **200 when the prover does its work, 503 when it does not.** The body is JSON:

- `status`:
  - `starting` (503): no round has finished yet.
  - `ok`; `catching_up` (fills or blocks are left to read); `waiting_for_a_block` (an action it sent is in no block yet).
  - `stalled` (503): no round has gone well for three poll intervals, at least a minute.
  - `halted` (503): the chain's header chain is halted. No proof and no expiry is accepted; a fill ends by a release or a settle only.
  - `key_or_account` (503): one of the checks of "The prover's account and key" fails. `problems` says which.
  - `daily_fee_budget_used_up`, `balance_too_low`, `daily_limit_of_the_account_used_up`, `cannot_pay` (all 503): the prover has stopped sending.
  - `no_node_sees_the_chains_best_block`: no Bitcoin node has the chain's best Bitcoin block. The nodes are behind the chain, or have never seen its branch. 503 once that has lasted a minute.
  - `no_bitcoin_node`, `time_unreachable`: likewise.
  - `refused_network`, `no_market` (503): the Time network follows Bitcoin mainnet, or has no market.
- `warnings`: `balance_low`, `a_proof_costs_more_than_allowed`, `a_payment_cannot_be_proven`, `blocks_left_to_search`, `an_action_is_in_no_block_yet`, `nonce_used_elsewhere` (the account's nonce moved without the prover: the key is used by something else), `a_bitcoin_node_is_not_usable`, `a_bitcoin_node_does_not_see_the_chains_best_block`.
- `fills`: how many are open, the next id the chain will give, and which ids the prover has looked at.
- `payments`: how many wait (for confirmations, or for their turn), how many cannot be proven, how many are too small to count now, how many were proven since the start, and when the last one was.
- `fees`: the day, what was spent, the two budgets, and the numbers of proofs and expiries.
- `balance_micros`, `balance_low`, `max_balance_micros`.
- `header_chain`, `bitcoin_nodes`, `blocks_left_to_search`, `seconds_since_good_round`.

It holds no key, no address of a node, no password and no path. It does hold the balance of the prover's account, which is public on the chain.

## What it does each round

1. **It reads its own account**, the header chain and the market's summary, with a proof.
2. **It brings the set of open fills up to date, from proven rows only.** The ids of fills are dense, from 1 to `next_fill` - 1 of the summary, and a fill that has ended has no row and never has one again. The prover reads the rows sixteen at a time (what one proof may carry): the open ones again, then the ids that are new. At a first start it reads downwards from the newest id and stops when it has found as many open fills as the summary counts. No index and no API is asked which fills exist: an index can leave a fill out or invent one, and a proof cannot.
3. **It looks at Bitcoin through the chain's eyes.** It starts from the chain's best Bitcoin block, whose hash is proven, and walks down from it on a node: each header names the hash of its parent, and each header is held to the hash it was asked by. Every block it reads is therefore under the block the chain itself holds as its best, whatever the node says its own best chain is. It reads every such block from five blocks below the lowest starting height of an open fill, once for each fill, and searches it for outputs that pay a fill's script. A block is known by its hash, never by its height: after a reorganisation the walk finds other blocks at the same heights, and those are read. A block is held to its header (its transactions give the header's Merkle root), and an output's value is read from the bytes of its transaction, never from a decimal number.
4. **It proves what is ready**, one payment after the other:
   - the fill and the account are read again, with a proof;
   - the payment has the confirmations the fill asks **on the chain's view**: the chain's proven best height less the block's height, plus one. A node that is ahead of the chain does not make a payment ready;
   - it counts: it pays what is still to pay, or at least the order's smallest trade (`min_sats`), or at least half of what is still to pay, and buys at least a microsecond (`marketFillBuys`);
   - the proof is put together from a node (`getrawtransaction` for the payment and the coinbase, `gettxoutproof` for the two) and checked by `proofPayload`: both transactions without witness data, exactly two matches, the coinbase at the first place. A node that gives something else is passed over for the next;
   - its fee fits the budgets, the balance and the account's daily limit;
   - it is signed, handed in, and the prover waits for the account's nonce to show it in a block. Then it reads the fill once more and logs what changed: what the fill held before, what it holds after, what the proof cost.
5. **It ends fills that were not paid**, if asked to.

### Payments at or below the starting height

A payment counts in a block above the fill's starting block. At or below it, it counts only after a reorganisation: in a block that was not on the chain the fill started on, fewer than six blocks below, once the new branch is the fill's confirmations past the starting height (`spec/market.md`, 5.2, point 7). For a payment it finds there, the prover looks at the fill's starting block:

- still under the chain's best block: nothing below it was reorganised, and the payment was made before the fill. It does not count, and the prover says so once. (The address had received money before. `spec/market.md`, 10.2.)
- no longer there, and a node still has it: the prover walks the old branch down from it to the payment's height. Another block there means the payment is in the new branch, and it is proven once the new branch is long enough.
- no longer there, and no node has it: the prover cannot tell which chain the fill started on. It sends the proof and lets the chain say: a refusal costs nothing, and "not after the starting block" ends the tries for that payment.

### What it does not send twice

- **One action is on its way at a time.** The next is signed when the account's nonce shows the last one in a block.
- **What was sent is remembered by the output it proves.** A counted payment is not proven again.
- **An action that is in no block** is sent again as the same bytes, once a round; nothing new is signed while it waits. After five minutes it is given up, and the log says so.
- **A proof the chain refuses is in no block and costs no fee.** It is tried again after 10 seconds, then 20, 40 and so on, up to ten minutes. The log has the chain's reason once.
- **"This output has paid for a fill already"** ends it: someone else proved the payment. So does "not after the starting block". The rows that record counted outputs (`market/paid/`) cannot be read with a proof, so this is the endpoint's word. What the prover relies on is the fill's own row, read with a proof: its `sats` fall when a payment is counted, and the row goes when the fill is paid.

### What cannot be proven

Said once, as an error line that begins `A PAYMENT CANNOT BE PROVEN`, and counted in `/health`:

- **A payment in a transaction above 100,000 bytes** without its witness data. Only a miner puts such a transaction in a block.
- **A block whose coinbase transaction is above 150,000 bytes.** A miner who is the seller can do this to a payment in a block of their own (`spec/market.md`, 10.14).
- **An output of a coinbase transaction.**

For these only the seller's settle (kind 57) delivers the seconds. The prover never ends such a fill.

Said once as a warning:

- **A payment too small to count now**: less than the order's smallest trade and less than half of what the fill still needs. It is tried again when the fill needs less: a payment of 300 satoshis counts once 300 or fewer are still to pay.
- **A payment to the address of a fill that has ended.** It was counted by a proof of someone else, or it came too late and bought nothing: nobody can claim it (`spec/market.md`, 10.1).

### Ending fills that were not paid

Off unless `expire` is `true`. A fill that was not paid holds its seller's seconds until someone sends an expiry (kind 55), which anyone may. With `expire` on, the prover sends one for a fill when:

- the chain's own conditions hold (`TimeSDK.marketExpiry`: the chain has learnt the fill's last height, the grace has passed, and the time the fill was given has passed);
- **it knows of no payment to the fill's address**, and has searched every block the fill can be paid in up to the chain's best block. A fill with a payment that is too small, cannot be proven, or still waits for confirmations is never ended by the prover: that is someone's purchase.

An expiry costs the network's fee, from the same budgets. It gives the seconds back to the seller and the deposit to the seller too: turn it on only if you mean to do sellers that service.

## What it trusts

- **The trust manifest, and nothing else, for what the chain holds.** Fills, orders, the header chain, the clock of heights and the prover's own account are read with a proof. The endpoint cannot make the prover believe in a fill, a script or a balance the chain does not hold.
- **The Time endpoint can withhold.** It can answer nothing, answer with an older (genuine) state, or take a proof and never pass it on. The prover then says `time_unreachable` or `an_action_is_in_no_block_yet`, and a buyer waits. It cannot make the prover pay for nothing: an action costs a fee only in a block, and a block takes only what the validators accept.
- **What the endpoint says when it refuses is its word.** "Already paid", "no such fill" and "not after the starting block" end the tries for one output; every other reason sets a wait. A lying endpoint can make the prover give up on a payment, which it can do anyway by dropping the proof. The buyer can then prove the payment through another endpoint (`prove.mjs`), as long as the fill exists.
- **A Bitcoin node is trusted for nothing that decides anything.** The chain verifies every part of a proof by itself. A node that lies or lags can:
  - withhold a block or lag: the prover reads the block from another node, or waits and says which block it lacks;
  - give a block with other transactions: the block is held to its header and refused;
  - show a chain of its own: the prover does not look at the node's best chain. It walks down from the chain's proven best block by the parent each header names, and a header that is not the one asked for is refused.
  It cannot make the prover send a proof the chain accepts wrongly, or see a payment in a block the chain does not hold. It can keep a payment from being found, as long as it is the only node.
- **Validators.** A proof must enter a block before the fill is expired. Validators with more than two thirds of the votes can keep it out (`spec/market.md`, 10.6). The prover cannot change that.

## Limits

- **It needs the relay.** A payment is proven when the chain holds its block with the confirmations asked. Without headers nothing is ready.
- **It is one process with one account.** If its host is down, nobody proves until it is back; it then reads from where the open fills start. A buyer is not helpless meanwhile: `prove.mjs` on any machine with a Bitcoin node proves one payment.
- **It sees blocks, not the mempool.** A payment that is not in a block is not known. With `expire` on, a fill whose buyer paid so late that the payment is still unconfirmed when the chain's own conditions for an expiry hold can be ended by the prover; the chain's grace exists for exactly that buyer, and it has passed.
- **The day's budget is counted on this machine's clock**, in UTC. An action that was given up after five minutes and enters a block later is not counted in it.
- **Proofs go out one at a time**, each waiting for its block: a few a round. A market with hundreds of payments an hour needs more than one prover, each with an account of its own.
- **A first start on a chain with many ended fills** reads their ids sixteen at a time, at most 512 a round, until it has found every open one.
- **What has run, and what has not.** The prover's tests (`client-v4/market-prover.test.mjs`) run it against a Bitcoin node and a Time chain that exist in the test only. The two proofs the engine accepted (`spec/market-vectors.json`) are reproduced byte for byte, signature included, from the engine's own blocks; the rows of the engine's fixture are read through the installed verifier. The client of Bitcoin Core's RPC and the making of a proof are tested against a real Bitcoin Core 32.1 in regtest (`client-v4/market-services-regtest.test.mjs`). The three proofs of one such run (a payment to a `p2wpkh`, a `p2tr` and a `p2pkh` script, two of them outputs of one transaction) were accepted by the engine's own verifier, `verify_payment` of `bitcoin-bridge/`, on the header chain built from that run's headers (`bitcoin-bridge/tests/prover.rs`, run by hand on 26 November 2026; without its scenario file that test checks nothing). **The prover has not run against a Time node or on a network**: no proof of this prover has been in a block. The test chain judges a signed action by the engine's rules as this code's author read them, with the engine's words for each refusal, and is not the engine.
