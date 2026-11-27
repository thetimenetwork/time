# The market: seconds against bitcoin

**Status: a draft. Five independent reviews have been answered (section 13); the answers to the fifth, which are small, have not been read by anyone else. `v5/src/market.rs` follows this file on a branch; no network runs it.** `spec/protocol-4.md` gives the rules of a network without this setting, and `spec/settings.md` the settings that exist. This file says what one more setting, `market`, changes. Like `spec/settings.md`, it is not under the specification hash of version 4.

## 1. What it is

People who hold seconds and people who hold bitcoin trade with each other. Nobody holds the bitcoin in between: it is paid on the Bitcoin network, from the buyer's own wallet to an address of the seller. The chain holds only the seconds of a trade, and gives them to the buyer when it has seen a proof that the bitcoin was paid.

The chain can check such a proof by itself. It already follows the Bitcoin header chain (`bitcoin-bridge/`, kind 40): anyone may hand it Bitcoin block headers, and it checks their proof of work and keeps the chain with the most work. A payment is proven by its transaction and the Merkle branch that ties it to a header of that chain.

Three things follow from "nobody holds the bitcoin", and no rule below can change them:

- **A sell order is firm, a buy order is a promise.** Seconds can be locked by the chain; bitcoin cannot. Someone who sells seconds can leave an order and go away. Someone who wants to buy with bitcoin must pay when the time comes, and locks a deposit in seconds that is lost if they do not.
- **A trade takes as long as Bitcoin takes.** The seconds move when the payment has the confirmations the seller asked for: tens of minutes, not one second.
- **There is no pool.** A pool that prices trades by a formula has to hold both sides. Holding bitcoin for others needs a keeper, and this design has none.

## 2. The setting

- `"market": true`, a field of the genesis application state, written last, after `service_records`. Absent: none of the rows below exists, kinds 50 to 58 are refused, and a state that holds a row under `market/` is refused by the recount.
- **It needs `waits_survive_stops`** (`spec/settings.md`, section 3); a genesis with the market and without it is invalid. Every wait of the market is counted on the clock of the waits, which stands while the chain stands: otherwise a chain that was stopped for hours would come back with every open fill ready to end, and no payer could have sent a proof meanwhile.
- **It needs the header chain's usual numbers**: a reorganisation bound (`bitcoin.max_reorg`) of 144 blocks, a tip age (`bitcoin.max_tip_age_secs`) of at most two hours, and at least two fork tips kept (`bitcoin.max_fork_tips`). The rules below quote them; a genesis with the market and other numbers is invalid.
- It may stand with or without `all_new_time_to_validators`. On a network with the setting, kind 40 (Bitcoin headers) is accepted whether or not the network has a bitcoin auction. Kinds 41, 42 and 60 to 63 stay refused where `all_new_time_to_validators` refuses them.
- The header chain starts at the genesis block of the Bitcoin network the genesis names (`bitcoin.network`). A start from a trusted checkpoint is not in this version (section 11).
- **Bitcoin mainnet is closed in this version.** Kinds 52, 53 and 54 are refused on a network whose Bitcoin network is mainnet, whatever the gate of the bitcoin auction (`bitcoin.mainnet_receipts_enabled`) says.
- **The two networks that are open, regtest and testnet3, protect nothing.** On regtest anyone makes blocks. On testnet3 a block dated twenty minutes after its parent may have the lowest difficulty, so a private chain of any length costs seconds of computing. On both, a payment can be invented and "confirmed" by whoever wants the seconds of a fill. A network that uses them is for rehearsal, and its seconds must be worth nothing.

### 2.1 Numbers

| Name | Production profile | Laboratory profile |
|---|---|---|
| `K_MIN`, fewest confirmations | 3 | 1 |
| `K_MAX`, most confirmations | 100 | 100 |
| `N_MIN`, shortest time to pay, in Bitcoin blocks | 3 | 1 |
| `N_MAX`, longest time to pay, in Bitcoin blocks | 144 | 144 |
| `BLOCK`, what a Bitcoin block is taken to last | 10 minutes | 1 second |
| `SPARE`, blocks added to the time a fill is given | 16 | 16 |
| `GRACE`, on the clock of the waits | 30 minutes | 20 seconds |
| `BOND_MIN`, least deposit of a buy order, in millionths | 30,000 | 0 |
| `MIN_SATS`, smallest trade | 1,000 | 1 |
| `HOUR`, the length of a candle | 3,600 s | 60 s |
| `SLACK`, how far at or below its starting height a fill's payment may lie after a reorganisation, in blocks | 6 | 6 |
| the largest payment transaction a proof carries, in bytes | 100,000 | 100,000 |
| the largest coinbase transaction a proof carries, in bytes | 150,000 | 150,000 |
| open orders of one account, at most | 64 | 64 |
| open fills one account pays, at most | 64 | 64 |
| receiving scripts of one sell order that have not served, at most | 16 | 16 |
| open fills of one buy order, at most | 16 | 16 |

`K_MIN` is 3 because Bitcoin reorganises two blocks from time to time without anyone attacking it. `BOND_MIN` is 3% because that is what the free choice of a buyer who may still walk away has been valued at (10.9).

## 3. Amounts and prices

- Seconds are counted in microseconds, as everywhere (`amount_micros`). Bitcoin is counted in satoshis.
- A **price** is a whole number from 1 to 10^15: millionths of a satoshi for one second. At price `P`, `a` microseconds cost `sats(a, P) = ceil(a × P / 10^12)` satoshis. Every rule uses this one formula. The result must not exceed 2.1 × 10^15.
- For `s` satoshis at price `P`, `bought(s, P) = floor(s × 10^12 / P)` microseconds, and 2^64 − 1 where that is more; `bought(sats(a, P), P) ≥ a`. No rule uses it: it is for a wallet that asks what a sum buys before a fill is made. Once a fill is made, the satoshis agreed are fixed, and a payment of a part is shared in proportion to them (6.5).
- All products are computed in 128 bits.

## 4. State

Every row is canonical JSON with the fields in the order shown (it is alphabetical), no spaces, every number a decimal string. In keys, a number is 8 bytes big-endian.

| Key | Value |
|---|---|
| `market/meta` | `{"fills":N,"last_price":P,"next_fill":N,"next_order":N,"orders":N,"sats":N,"seconds_micros":N,"trades":N}`. `fills` and `orders` count the rows that exist; ids start at 1; `trades`, `seconds_micros` and `sats` add up every proven payment; `last_price` is written once one exists. |
| `market/order/` ‖ id | An order (4.1). |
| `market/fill/` ‖ id | A fill (4.2). |
| `market/script/` ‖ SHA-256 of a script | `{"order":N}` for a script a sell order lists, whether it is free or an open fill of that order is using it (the order's row says which, 4.1); `{"fill":N}` for the script of an open fill against a buy order; `{}` for a script whose fill has ended. A row `{}` is never removed. |
| `market/paid/` ‖ txid (32) ‖ output index (4, big-endian) | `{"fill":N,"height":H,"sats":S}`: a Bitcoin output that has paid for a fill. Never removed. |
| `market/account/` ‖ id | `{"fills":[N,…],"orders":[N,…]}`: the open orders the account owns and the open fills it pays, ascending. No row when both are empty. Two accounts find a fill of theirs in no list: the seller of a fill against a buy order, and the account a fill's seconds go to when another account pays. They keep the id from the action that made the fill, or ask an index of blocks; the fill's row is proven either way. |
| `market/heights` | `{"entries":[{"at":T,"height":H},…]}`: the clock of heights (5.4). |
| `market/candle/` ‖ hour | `{"close":P,"high":P,"low":P,"open":P,"sats":S,"seconds_micros":A,"trades":N}` (section 9). |

No other row has a key that starts with `market/`.

The metadata row has one more field, written last: `market_micros`, the total of all seconds the market holds. The field exists on a network with the setting and on no other. The supply rule of `spec/protocol-4.md`, section 3, gains this term: bank, liquid balances, staked assets, the auction reserve and `market_micros` add up to the chain time elapsed.

### 4.1 An order

`{"amount_micros":A,"bond_micros":B,"confirmations":K,"created":M,"deposit_ppm":D,"fills":N,"forms":[F,…],"id":N,"key":X,"min_deposit_micros":B,"min_sats":S,"open":true|false,"owner":O,"pay_blocks":N,"price":P,"scripts":[{"fill":N,"script":X,"used":true},…],"side":"sell"|"buy"}`

- `amount_micros`: what is still on offer, not counting what open fills hold.
- `key`: the public key that signed the order, or that last gave it new scripts (6.10), 64 lowercase hexadecimal characters.
- A **sell** order holds `amount_micros` seconds of its owner. `scripts` lists its Bitcoin receiving scripts, in the order the owner gave them; in an entry, `fill` is written while a fill uses the script and `used` (always `true`) once that fill has ended. It has no `fills` and no `forms`; `bond_micros` is `"0"`.
- A **buy** order holds no seconds to trade. `bond_micros` is its owner's deposit for what is still on offer. `fills` counts its open fills and `forms` lists the forms of receiving script its owner can pay to (5.1), ascending, each once, at least one. It has no `scripts`; `min_deposit_micros` is `"0"`.
- `open` turns `false` when the owner cancels while fills are open; `amount_micros` and `bond_micros` are then `"0"`. A closed order takes no new fill and goes when its last fill ends.
- `M` is a moment: `{"height":H,"time_micros":T}`, a block's height and its time.

### 4.2 A fill

`{"amount_micros":A,"confirmations":K,"created":M,"deposit_micros":B,"id":N,"opened_micros":T,"order":N,"owner":O,"pay_blocks":N,"payer":O,"price":P,"sats":S,"script":X,"side":"sell"|"buy","start_hash":H,"start_height":H,"to":O}`

A fill is one trade in progress. It holds `amount_micros` seconds of `owner` and a deposit of `payer`. `payer` is the account that promised the bitcoin; `to` is the account the seconds go to; `script` is where the bitcoin must arrive; `side` is the side of the order it came from. `sats` is what is still to pay: `sats(amount_micros, price)` when the fill is made, less every payment of a part since. **A fill shrinks as it is paid**: a payment of a part lowers `amount_micros`, `sats` and `deposit_micros` (6.5). `start_height` and `start_hash` name the best Bitcoin header the chain knew when the action that made the fill was executed (a kind 40 action earlier in the same block counts, a later one does not). `opened_micros` is that block's moment on the clock of the waits.

## 5. The Bitcoin side

### 5.1 Scripts

A receiving script is one of the five standard forms, in lowercase hexadecimal, matched whole:

| Name | Form | Bytes |
|---|---|---|
| `p2pkh` | pay to public key hash | 25 |
| `p2sh` | pay to script hash | 23 |
| `p2wpkh` | pay to witness public key hash | 22 |
| `p2wsh` | pay to witness script hash | 34 |
| `p2tr` | pay to taproot | 34 |

Every other script is refused.

**A script serves one fill, ever.** It has at most one row under `market/script/`. While an order lists it, no other order and no fill against a buy order can use it. When a fill that used it ends, in whatever way, the row becomes `{}` and stays: no order lists that script again and no fill uses it again. A sell order with `n` scripts has at most `n` fills; an owner who wants more gives the order new scripts (kind 58). A script of an order that goes without having served a fill loses its row and is free.

So any payment to a script is for one fill, and a payment that comes when that fill has ended is for nothing: nobody can claim it.

### 5.2 A payment that counts

A proof names a fill and carries a Bitcoin block hash, the payment's transaction and an output index, the block's coinbase transaction, and a Merkle proof of the two (the bytes Bitcoin Core's `gettxoutproof` returns for the two transaction ids). It counts when all of this holds. The points are in the order they are checked: the first four read the proof, the fill, its order and one more row, and a proof that fails later has cost a few reads of the header chain (point 8).

1. The payment is at most 100,000 bytes (what Bitcoin nodes relay as a standard transaction) and the coinbase at most 150,000; in hexadecimal the two fit one action. Each is canonically serialized **without witness data**, has at least one input and one output, and outputs that sum to at most 2.1 × 10^15 satoshis. The payment has a base size above 64 bytes; the coinbase may be as short as a miner makes it. (A transaction's id does not cover its witness. With witness data the same proof could be padded to half a megabyte that no Bitcoin miner was paid for.)
2. The payment is not a coinbase, has no input twice and none null. The named output pays exactly the fill's script, and its value `s` is at least 1. The other transaction is a coinbase.
3. No row `market/paid/` exists for the payment's output; `s` is at least the `min_sats` of the fill's order, or at least half of the fill's `sats`; and the sender can pay the fee of the proof (section 6) with what it holds and what this proof brings it.
4. The Merkle proof is at most 4,096 bytes, with at most 64 hashes and 1,024 flag bytes, canonically serialized, for the named block, and matches exactly two transactions: the coinbase at the first place of the block, and the payment after it. (The bytes of a proof are still not the only ones for a payment: the unused bits of the last flag byte are not read, and the number of transactions it states can differ where the tree keeps its height. Nothing counts twice by that: what is recorded is the output paid, 4.)
5. The header chain is not halted, and holds the block.
6. The block has at least the fill's `confirmations`: best height − block height + 1.
7. The block comes after the fill's starting block: its height is above `start_height`; or, if it is not, it is less than `SLACK` (6) blocks below it, the chain holds more than one block at that height, it still holds the starting block, the block is not the one at its height on the chain that ended in the starting block, and the best height is at least `start_height + confirmations`. (The second case is for a reorganisation that happens while a payment is on its way: the payment lands in a block of the new branch that is no higher than the old tip. Natural reorganisations are a block or two deep. The last condition is what a payment in the block after the start would need for its confirmations: without it, someone who mined a branch in private, with invented payments to the scripts of every sell order, would need a lead of one block over the honest chain, and not of the confirmations asked, before taking the orders and showing the branch.)
8. The block is on the chain of most work. Where the chain holds one block at the payment's height, that is so without a walk; where it holds several, which is near its tip, the chain is walked from its best block, for at most 1,008 blocks.

**Why the coinbase.** A Merkle proof of one transaction does not say how deep the tree is. Bitcoin's tree does not tell a transaction from an inner node, and an inner node is 64 bytes; so with a transaction of exactly 64 bytes in a block, someone can present a "transaction" that is not in the block at all, one level below it. That costs a search far smaller than mining the confirmations. The coinbase is a transaction at the first place of every block and cannot be an inner node: a proof that ties the payment to the header at the coinbase's depth cannot be one level too deep.

The header chain need not be fresh for a proof (5.3). There is no upper height, and no age but the header chain's own memory: it keeps the last 8,192 blocks (about 57 days), and it forgets a branch that lost about 144 blocks after the fork. So a payment counts as long as the fill exists and its block is held; and a payment that landed at or below the starting height after a reorganisation must be proven within about a day, while the chain still holds the branch that lost.

No output that carries data is asked for. The payment is an ordinary one, which any Bitcoin wallet and any exchange withdrawal can make. What ties it to a fill is the script, which serves that fill and nothing else, ever.

### 5.3 Fresh

The header chain is fresh in a block when it is not halted and the time of its best header is within the bridge's `max_tip_age_secs` (two hours) before and `max_future_secs` after the block's time (`HeaderChain::ensure_fresh`). A new fill needs a fresh chain. A proof and an expiry do not.

### 5.4 The clock of heights

The row `market/heights` records when the chain learnt of Bitcoin heights. At genesis it holds one entry: the starting height, at 0. After every kind 40 action, with `best` the best height and `now` the block's moment on the clock of the waits:

1. every entry with a height above `best` goes (the best height fell: those heights are not known any more);
2. if no entry is left, or the newest has a height below `best`, an entry `{"at":now,"height":best}` is added;
3. if there are more than 256 entries, the oldest go.

`known(X)` is the `at` of the oldest entry whose height is at least `X`, and undefined when no entry has such a height.

An entry is added for every action that raises the best height, not for every block of this chain. So more than 256 such actions within the grace push out entries that open fills wait on, and `known` of their last height then reads later than it was: those fills can end only when the grace has passed again. It delays an expiry and takes nothing. On Bitcoin mainnet new heights come every ten minutes and it cannot happen within the grace; after a long silence of the relays, a relay that hands in the missing headers one by one does it once, by accident (a relay fills its actions: `deploy/market-relay`). On regtest and testnet3, where a block costs nothing, anyone can do it for as long as they like: one more way in which those networks protect nothing (section 2).

### 5.5 When a fill can end without payment

The **last height** of a fill is `start_height + pay_blocks + confirmations − 1`: when the chain knows this height, a payment made in the last block of the time to pay has its confirmations. A fill can be expired in a block, with `now` its moment on the clock of the waits, when all of this holds:

1. the header chain is not halted;
2. its best height is at least the last height;
3. `known(last height)` is defined and `known(last height) + GRACE ≤ now`;
4. `opened_micros + (pay_blocks + 2 × confirmations + SPARE) × BLOCK + GRACE ≤ now`.

Point 3 leaves `GRACE` of chain activity, after the chain has learnt the last height, in which a proof of a payment made in time is accepted; a proof is accepted during a validator safety hold (section 7).

Point 4 is there because a fill may start behind Bitcoin: a header chain is fresh with a best header up to two hours old, so `start_height` can be a dozen blocks below Bitcoin's real height, and the time to pay, counted in heights, can be over before the payer has paid. When the relay catches up, the chain learns many heights at once, and point 3 alone would leave `GRACE` and no more. Point 4 gives the payer, from the moment of the fill, the time the blocks are taken to last, the confirmations once more, and sixteen blocks. For a payer who pays at once and whose payment is in the next block, the chance that the confirmations do not come before the grace begins is below one in ten million when blocks come every ten minutes on average, and about one in two thousand when they come every fifteen (which happens when miners leave between two adjustments of the difficulty). It is worse when blocks are slower still, or when the order asks for very many confirmations: an order that asks a hundred is a risk for its buyer. It delays nothing but the end of a fill that was not paid: with a time to pay of 3 blocks and 3 confirmations, 280 minutes after the fill at the earliest.

## 6. Actions

The envelope, the nonce, the fee and the spending key are those of every action (`spec/protocol-4.md`, section 4). Each payload is canonical JSON with exactly the fields shown; a field that is a list is written with a list or left out, never `null`. A refusal changes nothing.

Three kinds pay more than the fee, because they write more rows or take more room than a payment: kinds 50 and 58 pay the fee once more for each script they list, and kind 54 once more for every 256 bytes of its payload, which is the price of that room in ordinary actions (a proof of an ordinary payment costs about a dozen fees).

### 6.1 Kind 50: an order

A sell order: `{"amount_micros":A,"confirmations":K,"deposit_ppm":D,"min_deposit_micros":B,"min_sats":S,"pay_blocks":N,"price":P,"scripts":[X,…],"side":"sell"}`.

A buy order: `{"amount_micros":A,"confirmations":K,"deposit_ppm":D,"forms":[F,…],"min_sats":S,"pay_blocks":N,"price":P,"side":"buy"}`.

Accepted only if: the price is valid; `A ≥ 1`; `sats(A, P) ≥ S ≥ MIN_SATS`; `K_MIN ≤ K ≤ K_MAX`; `N_MIN ≤ N ≤ N_MAX`; `D ≤ 1,000,000`; the sender owns fewer open orders than the limit; and

- for a sell order: `B ≤ A`; 1 to 16 scripts, each of a standard form, each once, none with a row under `market/script/`;
- for a buy order: `D ≥ BOND_MIN`; the forms are names of 5.1, ascending, each once, at least one.

Then: the order gets the next id, and `key` is the public key that signed the action. A sell order takes `A` from the sender's balance and writes a row `{"order":id}` for each script. A buy order takes the bond, `ceil(A × D / 10^6)`. `market_micros` grows by what was taken. The account's index is written.

For a sell order, `confirmations` is what its owner asks of every payment, and a taker locks a deposit of `ceil(amount × deposit_ppm / 10^6)` or `min_deposit_micros`, whichever is more. For a buy order, `confirmations` is the most its owner will wait for, and `deposit_ppm` gave the bond.

### 6.2 Kind 51: cancel

`{"order":N}`. The sender owns the order and it is open.

Then: what is still on offer goes back to the owner's balance: `amount_micros` of a sell order, `bond_micros` of a buy order; both become `"0"`. If no fill of the order is open, the order goes (6.9). Otherwise `open` turns `false`.

### 6.3 Kind 52: take a sell order

`{"amount_micros":A,"order":N,"sats":S,"to":O}`. The sender is the payer.

Accepted only if: the network's Bitcoin network is not mainnet; the header chain is fresh; the order is an open sell order; its owner stands (6.10); the size is right (6.11); the order has a script that neither has a fill nor has had one; account `O` exists; the sender pays fewer open fills than the limit.

Then: the fill gets the next id and the first such script, in the order's own order. `A` moves from the order into the fill. The deposit (6.1) is taken from the sender's balance, and `market_micros` grows by it. `owner` is the order's owner, `payer` the sender, `to` is `O`.

`to` lets one account take for another: a newcomer who holds no seconds cannot pay a fee or a deposit, and someone else can make the fill in their name. The deposit belongs to the payer. Once made, the fill is the other account's: only `to` can give it up (6.7).

### 6.4 Kind 53: sell to a buy order

`{"amount_micros":A,"confirmations":K,"order":N,"sats":S,"script":X}`. The sender is the seller.

Accepted only if: the network's Bitcoin network is not mainnet; the header chain is fresh; the order is an open buy order; its owner stands (6.10); the size is right (6.11); `K_MIN ≤ K ≤` the order's `confirmations`; `X` is of a standard form that the order's `forms` name, and has no row under `market/script/`; the order has fewer open fills than the limit; its owner pays fewer open fills than the limit.

Then: `A` is taken from the sender's balance and `market_micros` grows by it. The deposit is `floor(bond_micros × A / amount_micros)` of the order, or all of `bond_micros` when `A` is all that was on offer; it moves from the order into the fill. `owner` is the sender; `payer` and `to` are the order's owner. The row `{"fill":id}` is written for the script.

### 6.5 Kind 54: proof of payment

`{"block_hash":H,"coinbase":X,"fill":N,"merkle_proof":X,"transaction":X,"vout":V}`. Any account may send it, for any payment.

Accepted only if: the network's Bitcoin network is not mainnet; the fill exists; the payment counts (5.2).

Then, with `s` the value paid:

- **If `s` is at least the fill's `sats`**, the payment is in full: all the seconds the fill holds go to the balance of `to`, the whole deposit goes back to `payer`, and the fill ends (6.9).
- **Otherwise it is a part**: `a = floor(amount_micros × s / sats)`, which must be at least 1, goes to the balance of `to`; `floor(deposit_micros × a / amount_micros)` of the deposit goes back to `payer`; the fill's `amount_micros` and `deposit_micros` fall by what left, and its `sats` falls by `s`. The fill goes on, with the same script, until the rest is paid, it is given up, settled, or its time has passed.

So a buyer pays, in all, exactly the satoshis agreed when the fill was made, in as many payments as they like, and what is still to pay is always that number less what was paid.

In both cases the row `market/paid/` is written, `market_micros` falls by what left the market, and the payment is counted (section 9) with the seconds it bought and `min(s, sats)` satoshis at the fill's price.

A payment of a part ends nothing, which is why anyone may prove any payment: what a seller pays to their own script buys its part for the buyer and changes nothing else. A part is no smaller than the order's smallest trade, so that a seller is not paid in thousands of outputs too small to spend; but half of what is still to pay always counts, whatever the smallest trade, so that a payment which came a little short is not lost, and its top-up neither. A payer whose exchange kept a fee out of the withdrawal gets what was paid for, and can pay the rest while the fill exists.

### 6.6 Kind 55: expire

`{"fill":N}`. Any account may send it. Accepted only if the fill can end (5.5).

Then: the seconds the fill still holds go back: into the order (`amount_micros` grows) when the fill came from a sell order that is open, and to the balance of `owner` otherwise. The deposit it still holds goes to `owner`. The fill ends (6.9).

### 6.7 Kind 56: release

`{"fill":N}`. The sender is the fill's `to`. Accepted also when the header chain is halted (not during a validator safety hold, section 7).

Then: as an expiry. The account the seconds go to gives the trade up, and the deposit is lost to the owner of the seconds. It counts against the sender's daily limit like a payment of the seconds given up (section 7); on a halted header chain, where nothing can be proven or expire, it counts the sender's deposit only.

For a fill someone made for another account, that is the other account and not the payer: whoever made the fill cannot end it while the other's bitcoin is on its way.

### 6.8 Kind 57: settle

`{"fill":N}`. The sender is the fill's `owner`. Accepted also when the header chain is halted (not during a validator safety hold, section 7).

Then: all the seconds the fill still holds go to `to`, the deposit it still holds goes back to `payer`, and the fill ends. No `market/paid/` row is written and nothing is counted. The owner says the bitcoin arrived and hands the seconds over.

Kinds 56 and 57 are the two ways out that need no view of Bitcoin: each side can only act against itself.

### 6.8a Kind 58: new receiving scripts for an order

`{"order":N,"scripts":[X,…]}`. The sender owns the order; it is an open sell order.

Accepted only if: 1 to 16 scripts, each of a standard form, each once, none with a row under `market/script/`; and the order's scripts that have not served, with the new ones, number at most 16.

Then: the entries of scripts that have served leave the order's list (their rows `{}` stay); the new scripts join it, each with a row `{"order":id}`; the order's `key` becomes the public key that signed this action. No seconds move.

**It counts against the daily limit like a new order**: the seconds the order has on offer and those in its open fills (section 7). New scripts decide where the bitcoin for the order's seconds is paid. If they counted nothing, someone with a stolen spending key would fill the order's own scripts with small fills, give it a script of their own, and take all the rest to an accomplice.

### 6.9 How a fill ends, and an order goes

When a fill ends: its row goes; it leaves its payer's index; `fills` of the metadata falls by one. Its script has served: its row becomes `{}`; in a sell order the entry loses `fill` and gains `used`; for a fill against a buy order the order's `fills` falls by one. `market_micros` falls by everything that left the market.

An order goes when it has no open fill and either is closed or has nothing on offer (`amount_micros` is 0; whatever bond is left then goes back to the owner). When it goes: its row goes; it leaves its owner's index; `orders` falls by one; for each of its scripts, the row goes if the script never had a fill, and stays `{}` if it had.

### 6.10 An owner who stands

An order takes a new fill only while its owner is not frozen under the account security rules (`security::frozen_at`, on the clock of the waits) and the order's `key` is still one of the owner's keys that can spend.

So when a stolen spending key is removed from an account, by a replacement of its keys or by a recovery, every order that key made takes nothing more, whoever made it. Adding a key, or changing a sign-in key or a recovery key, stops nothing. An account that adopts the account security rules and does not keep its one key as a spending key stops the orders that key made. The owner cancels an order whose key is gone, or, for a sell order, gives it new scripts with a present key (kind 58), which says it stands.

### 6.11 The size of a fill

`1 ≤ A ≤` the order's `amount_micros`; `S = sats(A, price)`; and

- `S ≥` the order's `min_sats`, or `A` is all that is on offer and `S ≥ MIN_SATS`;
- what stays on offer is nothing, or costs at least the order's `min_sats`.

A rest smaller than the order's smallest trade can arise when seconds come back into an order (6.6, 6.7); it can be taken whole if it costs at least `MIN_SATS`. A smaller rest stays until the owner cancels.

## 7. The account rules

- **Daily limit.** Whatever an action takes from the sender's balance counts against a secured account's daily limit, as for every action: the seconds of a sell order, a bond, a deposit, the seconds sold to a buy order, the fees. Three actions count something more, although the balance does not fall by it: a settle (kind 57) counts the seconds it hands over; a release (kind 56) counts the seconds the fill still held for the sender, and the deposit too if the sender locked it (the deposit only, while the header chain is halted); new scripts (kind 58) count the seconds the order has on offer and in its open fills. Without that, someone who holds a stolen spending key could empty an owner's sell orders, or the bonds of their buy orders, into an accomplice's account in one block, or end the owner's purchase from an accomplice while the owner's bitcoin is on its way. (So a secured buyer cannot give up a fill larger than what is left of the day's limit, and a buyer whose limit is smaller than the fill cannot give it up on any day; it ends when its time has passed.)
- **The limit caps honest selling.** An account with a daily limit of 600 seconds offers at most 600 seconds a day. An order that is cancelled and made again counts twice, and so does one that is given new scripts; seconds that were counted when the order was made count again if the owner settles. There is no way around it in this version (section 11). A seller with a limit lists enough scripts when the order is made, and asks a least deposit that makes it costly for others to use them up.
- **Freeze.** A frozen account sends no action that lowers its balance or counts against its limit, as everywhere: no order, no fill, no settle, no new scripts, no release. An action that brings back at least what it costs passes: a cancel that returns more than its fee, a proof of a payment for itself. Its orders take no new fill (6.10). Its open fills go on: their payers may have paid.
- **An account that never adopted the security rules** is never frozen by them. While guardians recover it, its orders still take fills.
- **Validator safety hold.** During a hold, kind 54 is accepted beside the kinds `spec/protocol-4.md` names, and kinds 50 to 53 and 55 to 58 are refused.
- **What comes back** (a cancelled order, an expired fill) is credited to the balance and does not give back any daily allowance.

## 8. The recount

On a network with the setting the recount (`--audit`) requires:

- `market_micros` is the sum of: `amount_micros` of every sell order, `bond_micros` of every buy order, and `amount_micros` plus `deposit_micros` of every fill.
- `orders` and `fills` of the metadata are the numbers of rows; `next_order` and `next_fill` are above every id.
- Every order has the shape of 4.1 and the bounds of 6.1 on its price, confirmations, time to pay, deposit, smallest trade, scripts, forms and key; a closed order offers nothing and has an open fill.
- Every fill names an order of its side and price that exists; the fills of a sell order are exactly those its scripts name; `fills` of a buy order is the number of its fills; a fill's `sats` is at least 1 and at most `sats(amount_micros, price)`.
- The rows under `market/script/` that name an order or a fill are exactly: one for every script of a sell order that has not served, one for the script of every open fill against a buy order. Every script of a sell order that has served has a row `{}`. Other rows `{}` are not counted against anything.
- The rows under `market/account/` list exactly the open orders by owner and the open fills by payer, and no list is longer than its limit.
- The candles add up to `trades`, `seconds_micros` and `sats` of the metadata; `last_price` is the `close` of the newest candle; there is one `market/paid/` row for every payment counted. (The sums stop at the largest number a row holds.)
- The entries of `market/heights` rise in height and do not fall in time; the newest height is not above the header chain's best height.

The recount does not check a fill's times and starting block against the header chain, nor an order's `key` against its owner's keys: those are true when written and need not stay true.

On a network without the setting: no row under `market/`, no `market_micros`.

## 9. What is kept for charts

A candle is the record of one `HOUR` of proven payments: the hour is the chain time since genesis divided by `HOUR`, rounded down. A proof (kind 54) that is accepted updates the candle of its block's hour: `open` is the price of its first payment, `close` of its newest, `high` and `low` the extremes, and `seconds_micros`, `sats` and `trades` are sums. The metadata's totals and `last_price` move with it. A sum that would pass the largest number a row holds stays there.

**No rule reads a candle or `last_price`.** They decide nothing. Two accounts of one person can trade with each other at any price. It need not even cost a Bitcoin fee: an order can list an address that belongs to someone else and receives payments anyway, and the "trades" are proven with those. These numbers say what was recorded, not what a second is worth. Nothing outside this chain should read them as a price either: wherever a thin market's own last price has been trusted by a rule, it has been moved on purpose.

Finer candles, the book of open orders and the history of an account are for a service that reads the chain (`client-v4/`), not for the state.

## 10. What these rules do not protect

1. **A payment that arrives late.** If a payer's transaction confirms after the fill has ended, or is not proven before it ends, the bitcoin is with the seller and nobody gets seconds for it. The time to pay (`pay_blocks`) is the order owner's choice; a wallet must tell the payer the last height and advise a fee that confirms in time. While the fill exists, a second payment to its address counts like the first. A payment of more than the fill needs buys nothing more. A rest smaller than what Bitcoin nodes relay (a few hundred satoshis) can only be paid by paying more. A payment in a transaction larger than 100,000 bytes, which only a miner can put in a block, cannot be proven.
2. **An address used for something else.** Any payment to a script counts for the fill that uses it. A seller who lists an address that also receives other money gives seconds for that money.
3. **A fake Bitcoin history.** A proof needs `confirmations` blocks of real proof of work on the chain of most work **that the Time chain knows**. Someone who mines that many blocks in private, and hands them in before honest headers of more work, takes the seconds of a fill without paying; the transaction in them can be invented, since the chain cannot check that its inputs exist. The cost is the block rewards given up, and **one private chain pays for every order at once**: the scripts of sell orders are public before any fill, and a payment in full returns the deposit, so someone who has mined such a chain can take every sell order on the book and prove them all, with nothing at risk but the blocks. What is at stake is all the seconds on offer and in fills, which no single seller controls. A large mining pool finds three blocks in a row from time to time without trying. On regtest and testnet3 the cost is nothing (section 2). A rule that bounds this is described in section 11 and must exist before mainnet is opened.
4. **Nobody relays headers.** The chain learns of Bitcoin only from kind 40 actions, which anyone may send and nobody is paid for. Where this was tried before (a header relay for Bitcoin on another chain, with a fee for relayers), one company ended up as the only relayer. With none, no fill is made, proven or expired; kinds 56 and 57 still work. A relay that is late makes fills start behind Bitcoin; 5.5, point 4 keeps that from costing a payer who pays at once, except in rare runs of slow blocks, and a wallet should hand in the headers it knows of before it makes a fill.
5. **A halted header chain.** A Bitcoin reorganisation deeper than the bridge's `max_reorg` (144 blocks) halts the header chain, and this version has no action that starts it again. On a network that also has the bitcoin auction, a reorganisation below a credited receipt halts it too. While it is halted, orders can be cancelled and fills released or settled, and nothing else moves: **an account that does not release, or is frozen and cannot, holds the seller's seconds until a software release, and a payer who has paid depends on the seller's settle.** On testnet3 such a reorganisation is cheap to make.
6. **Validators who order or refuse.** A proof must enter a block before the fill is expired. A proposer decides the order of actions in its own block, and validators with more than two thirds of the votes could keep a proof out. While one operator runs every validator, that operator can. Someone who fills blocks with proofs for the whole of `GRACE` pays for that room what ordinary actions pay; whether that keeps a payer's proof out depends on how proposers choose among waiting actions, which no rule fixes.
7. **A Bitcoin reorganisation after the seconds moved.** The seconds are final at once. If the payment's block later leaves the Bitcoin chain, the seller has lost them. That is what `confirmations` is for.
8. **A fill made for you by someone else, and a fill you make for someone else.** The account that makes a fill for a newcomer cannot give it up. But it chose the order, and it can be the seller: a wallet should show a newcomer the order's price, script and time before they pay, read from the chain and not from the helper. The other way round, the helper's deposit is in the newcomer's hands: a newcomer who does not pay, or gives the fill up, loses it to the seller, and a seller and a "newcomer" who are one person take a helper's deposit that way.
9. **The payer's free choice.** Between a fill and the end of its time to pay, the payer can wait and see where the price goes, and pay or not, or pay a part. The deposit is the price of that choice; a seller who asks none gives it away, and lets anyone hold their seconds and use up their addresses for a fee. With 3 blocks to pay and 3 confirmations, a fill that is not paid holds its seconds for at least 280 minutes. Trading software has been drained by takers who completed swaps only when the price had moved their way; where the choice was valued, it came to 2% to 3% of the amount.
10. **A buy order needs its owner awake.** When a seller fills it, the owner must pay within the time to pay or lose the bond's part. Sixteen small sales mean sixteen payments.
11. **Someone lists your address first.** An order, or new scripts for one, that list a script another person meant to list, copied from an action that has not entered a block yet, make that person's action fail. It costs the copier a fee and locks their own seconds. If the copier lets a fill use the script, it is used up for good.
12. **A proof that is refused costs its sender nothing**, because a proposer leaves it out. Validators check it for free; the checks are ordered so that this costs them little (5.2). One case is left: a sender with the security rules whose daily limit is used up is refused only after the proof was checked.
13. **Rows that stay for ever.** A row `{}` for a used script costs a few fees and no bitcoin (take your own order and give the fill up). A `market/paid/` row and a candle need a real payment.
14. **A miner who is the seller.** A proof carries the coinbase of the payment's block, and a coinbase larger than 150,000 bytes cannot be carried. A miner who finds the block with a buyer's payment in it can make its coinbase that large, at the price of the fees that room would have earned; the payment then cannot be proven and only the seller's settle delivers the seconds. A seller with a tenth of Bitcoin's hash rate can do this to one payment in ten. No coinbase of that size is known; a larger proof, or a shorter way to prove where the coinbase stands, is listed in section 11.
15. **An account that cannot act.** A fill made for an account that holds no seconds cannot be given up by it (it cannot pay a fee), and a fill can be made for an account nobody holds a key of; on a halted header chain such a fill ends only by the owner's settle.
16. **What a proof costs is set by others.** A proof pays for its bytes, and its bytes are the payment's transaction and the block's coinbase. A proof of an ordinary payment costs about a hundredth of a second at the usual fee; of a payment an exchange sent with two hundred others, six hundredths; in a block whose coinbase pays a thousand miners, a quarter of a second; at the largest sizes a proof may carry, two seconds. A newcomer who buys very little may need someone else to send the proof.
17. **Privacy.** Orders, fills, receiving scripts and the Bitcoin transactions that paid are public, on both chains, and tie an account to Bitcoin addresses.
18. **The price.** See section 9.
19. **A program that cannot check a proof.** A take signs the order's id, the amount, the satoshis and the account the seconds go to; a sale to a buy order signs the id, the amount, the satoshis, its confirmations and its script. Neither signs the deposit, the order's confirmations or its time to pay. An order's terms never change, so a wallet that reads the order from a proof signs what it saw. A script that reads the order from an API signs what the API said: an API that shows a small deposit and a long time to pay for an order that has a large one and a short one makes the script lose the deposit to the seller. The satoshis are signed, so the price cannot be misstated that way. Until 11 changes this, a script calls an API its operator runs.

## 11. Not in this version

To be decided before Bitcoin mainnet is opened:

- A start of the header chain from a trusted checkpoint.
- A way to start a halted header chain again, or a rule that follows the chain of most work without halting.
- **A bound against a private chain (10.3).** Both sides of the comparison are in satoshis, so it needs no price: the satoshis of all payments proven in Bitcoin blocks above a height may not exceed a fixed share (a half, say) of the block subsidies of the blocks above that height, for every height; a payment that would pass the bound waits for more blocks. A private chain of `n` blocks then releases less than the `n` rewards it cost. It caps what the market can settle per Bitcoin block, at a half of the subsidy; it means nothing on regtest and testnet3, whose subsidies are not money, which is why it is not in this version.
- A proof that can carry a coinbase of any size, or a shorter proof of where the coinbase stands (10.14).
- Who relays headers when nobody is paid to (10.4).
- A take and a sale that sign the terms they accept: the most deposit, the confirmations, the shortest time to pay (10.19).
- A proof of how old the header chain's best block is. The row a wallet can have proven (`bitcoin/meta`) holds the best block's hash and height, not its time: a wallet cannot prove that the header chain is fresh before it asks a person to sign a take. The chain refuses the take when it is not (5.3), so this costs a refused action and no seconds; but a wallet should be able to say it first, from a proof.

Never:

- Orders that wait for a price (stop orders) as rules of the chain. They would make the chain read its own last price, which costs nothing to move (section 9). A wallet or a script sends an order when it sees a price.
- A vote that freezes, moves or undoes the seconds of a named account or a named trade. On every chain where validators could do it, it was used again for something else, and it is the handle by which a market is stopped from outside.

Later:

- An order that carries two proofs like a root operation, or that names its future scripts when it is made, so that a secured account can offer more than its daily limit or renew an order without counting it again.
- Changing the price of an order. Cancel it and make a new one.
- Payments over the Lightning network, which would make a trade take seconds.
- Removing `market/paid/` rows and rows `{}` of scripts for blocks the header chain has pruned.

## 12. What this adds to `spec/protocol-4.md`

- Section 2 lists the row namespaces. With `market` there is one more, `market/`, and the metadata row has one more field.
- Section 3 gives the supply rule. With `market` it has one more term.
- Section 4 says that every other kind is refused. With `market`, kinds 50 to 58 are accepted, and kind 40 is accepted on a network that pays all new time to validators.
- Section 4 says what an action costs. With `market`, kinds 50, 54 and 58 can cost more than the fee (section 6).
- Section 4 names the kinds accepted during a validator safety hold. With `market`, kind 54 is one of them.

## 13. The reviews, and what they changed

Five independent readers were each given the rules, and from the second on the code, and asked to break them (25 and 26 November 2026). None found a way to break the supply rule or the recount. Each found that an answer to the reader before had opened something new; what they found grew less serious from one to the next.

**The first reader** (the first draft):

| Finding | Answer |
|---|---|
| Anyone could end a fill with a payment of one satoshi: the seller kept the deposit, and the payer's real payment arrived for nothing. | A payment of a part does not end a fill (6.5). |
| testnet3 protects as little as regtest. | Said in section 2 and 10.3. |
| The best height can fall; the clock of heights kept heights the chain had lost, and a payment below the starting height never counted. | 5.4, 5.5 point 2, 5.2 point 7. |
| A halt is permanent and lets a non-payer hold seconds. | Not solved. Said in 10.5; listed in section 11. |
| A relay that was behind could leave a payer `GRACE` and no more. | 5.5 point 4. |
| A script was free again after its fill, so a late or second payment belonged to whoever took it next. | A script serves one fill, ever (5.1). |
| Locking a seller's seconds was free. | `min_deposit_micros` (6.1); said in 10.9. |
| A seller could name a form of address the buyer cannot pay to. | `forms` (6.1, 6.4). |
| A release moved a bond without counting against the daily limit; a thief's orders outlived a change of keys. | Section 7; `key` (6.10). |
| A filled buy order stayed; a rest could be too small to take; the recount asked for bounds that did not hold. | 6.9, 6.11, section 8. |
| One private chain pays for every open fill. | Said in 10.3; listed in section 11. |
| The 64-byte rule guards one direction only. | The proof carries the coinbase (5.2). |
| Scripts can be squatted; a time to pay of one block is a trap. | Said in 10.11; `N_MIN` is 3 in production. |

**The second reader** (the answers above, and the code):

| Finding | Answer |
|---|---|
| A payer who proved a part handed most of the deposit to the fill's owner, uncounted and past a freeze. | A part gives back its share of the deposit and moves nothing to the owner (6.5). |
| The time floor did not protect a payer when a fill started behind Bitcoin. | 5.5 point 4, widened twice. |
| Someone who made a fill for a newcomer could give it up or end it while the newcomer's bitcoin was on its way. | Only `to` releases (6.7); a part ends nothing (6.5). |
| The authority epoch rises on ordinary actions, so an honest owner's orders stopped. | `key` (6.10). |
| An order whose scripts were used up held seconds nobody could take. | Kind 58 (6.8a). |
| A chart sum that overflowed refused every later proof. | Section 9. |
| The market's closure on mainnet hung on the auction's gate. | Its own gate (section 2). |

**The third reader** (the answers above):

| Finding | Answer |
|---|---|
| Kind 58 counted nothing against the daily limit: with a stolen spending key, an order of any size could be pointed at the thief's own address. | It counts like a new order (6.8a, section 7). |
| A proof could be padded with witness data to half a megabyte for one fee, and fill blocks through `GRACE`. | No witness data (5.2); a fee for size (section 6). |
| A refused proof could cost a validator thousands of reads. | The order of the checks and their bounds (5.2). |
| The time floor held only at exactly ten-minute blocks. | `2 × confirmations + 10` (5.5). |
| With a stolen spending key, the owner's own purchase could be ended by a dust payment, and the bitcoin kept by an accomplice. | A part ends nothing (6.5). |
| The market's waits need `waits_survive_stops`, and nothing required it. | Section 2. |
| Any change of the spending keys stopped every order, and a buy order could not be renewed. | `key` is the key that signed (6.10). |
| A fill made for another account had no way out while the header chain is halted. | `to` releases (6.7). |
| `null` was taken for an absent list. | Section 6. |

**The fourth reader** (the answers above):

| Finding | Answer |
|---|---|
| With a stolen spending key, the owner's purchase from an accomplice could still be ended, by a release, while the owner's bitcoin was on its way. | A release counts the seconds given up (6.7, section 7). |
| The miner of a block could make its payments unprovable: a coinbase too large to carry, or of exactly 64 bytes. | No length is asked of the coinbase; its largest size is said (5.2, 10.14); the rest is in section 11. |
| With parts, one Bitcoin transaction with thousands of outputs served thousands of large proofs, each cheaper than the room it took. | A proof pays for its room what ordinary actions pay (section 6). |
| A buyer could pay in thousands of dust outputs the seller cannot spend. | A part is at least the order's smallest trade (5.2, 6.5). |
| A refused proof still cost up to a thousand reads: a sender who could not pay the fee, a payment below the starting height, a losing branch. | The sender's means are checked first; no walk where the chain holds one block at a height (5.2). |
| The chances stated in 5.5 held only on a generous reading. | `SPARE` is 16, and the sentence says what it means (5.5). |
| A payment not proven within 1,008 blocks was lost, also after a long stop of the chain. | No age limit (5.2). |
| After parts, what was still to pay could be a satoshi more than the price less what was paid. | `sats` falls by what is paid (6.5). |

**The fifth reader** (the answers above) judged that the rules are converging: three of its findings were consequences of the fourth answers, and one had been there from the start.

| Finding | Answer |
|---|---|
| A payment a little short of a fill no larger than the order's smallest trade was refused, and its top-up too: the buyer lost it, and the seller gained by setting the smallest trade to the order's value. | Half of what is still to pay always counts (5.2, 6.5). |
| A branch mined in private needed a lead of one block, not of the confirmations asked, for its payments to count through the door for reorganisations. | The best height must be the confirmations past the starting height (5.2 point 7). |
| A secured account could not give up a fill larger than its daily limit; on a halted header chain nobody could end it. | On a halted chain a release counts the deposit only (6.7). |
| A frozen sender's proof was refused only after it was checked. | Refused first (5.2); the case of a used-up limit is said in 10.12. |
| "No age" was not true; several losses were not said; the genesis did not fix the header chain's numbers the rules quote. | 5.2, section 10, section 2. |

**From the study of earlier thefts** (a reading of published accounts made for this file on 26 November 2026; most of its facts rest on summaries of sources and are leads, not verified): proofs of Bitcoin payments have been forged in designs like this one only on paper, and the cheapest known way is the tree-depth trick the coinbase now closes (5.2); a verifier that matched a part of a script instead of the whole took a hash for another form (5.1); a natural reorganisation of two Bitcoin blocks happened in March 2026 (`K_MIN`); a buyer's free choice has been valued at 2% to 3% (`BOND_MIN`); a thin market's own last price, read by a rule, has been moved on purpose wherever it was tried (section 9, section 11 "Never"); the power to halt and the power to seize turned out to be one power (section 11 "Never"); and the bound against a private chain can be written without a price (section 11). What the study asks of the wallet, the services, the library for scripts and the way the network is run is not in this file.

Not tested by the engine's tests so far: a frozen owner, a waiting replacement of keys, the safety hold, a halted header chain and mainnet at the level of the engine, a best height that falls on a running chain (the clock's rule and the payment rule are each tested by themselves), the limits of 64 and 16, a recount that must fail on a changed row, the market on a network that pays all new time to validators, and every number of the production profile. The fuzzing harness runs without the market. No test or build has run on Linux.
