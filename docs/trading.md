# Trading seconds against bitcoin

For a person who trades through the API by hand, or writes a program that does. The rules are `spec/market.md`; this guide says how to use them, what each step costs, and what can go wrong. For deposits and withdrawals of seconds, see [`integration-guide.md`](integration-guide.md).

**Read this first.**

- **The rules are a draft, and no network runs them yet.** `spec/market.md` says what was reviewed and what was not.
- **Bitcoin mainnet is closed in this version.** A network that follows mainnet refuses every trade.
- **The two networks that are open, regtest and testnet3, protect nothing.** On both, a Bitcoin payment can be invented by whoever wants the seconds of a fill. They are for rehearsal, with seconds that are worth nothing.
- **Nothing in this guide has met a network.** Every command and every script line below was run against a stand-in for the API (`clients/python/tests/fake_api.py`, a small model of these rules), or is marked "not run". Section 9 says what a first real run should look at.
- This guide gives no advice on what to buy, what to sell, or at what price.

The examples use `API=http://127.0.0.1:8930`, a seller's account `5` and a buyer's account `6`. The scripts are in `clients/python/examples/` and are run from `clients/python`.

## 1. What this market is, and what it is not

It is an **order book** of seconds against bitcoin. People leave orders; other people take them.

- **A seller's order locks seconds at a price.** It lists Bitcoin addresses of the seller. Each address serves one purchase, ever.
- **A buyer takes an order.** That makes a **fill**: the chain sets the seconds aside, the buyer locks a deposit, and the fill names one of the seller's addresses.
- **The buyer pays the bitcoin with their own Bitcoin wallet**, as an ordinary payment to that address.
- **When the payment has its confirmations, anyone can show the chain a proof of it.** The chain checks the proof and hands the seconds over.
- A buyer can also leave a **buy order**, with a bond. A seller sells into it and names a fresh address.

Nobody holds the bitcoin in between. It goes from the buyer's wallet to the seller's address.

**It is not a pool, and a trade here is not a swap.** If you have used a pool where you send one coin and get the other in the same moment, three things are different:

- **Nothing is instant.** The seconds move when the Bitcoin payment has the confirmations the seller asked: tens of minutes, not one second. The chain cannot lock bitcoin, so it waits for Bitcoin to say that the payment happened.
- **There is no price formula.** A pool prices a trade from what it holds. It has to hold both coins, and holding bitcoin for others needs a keeper. This design has none. Every price here is a price some person wrote into an order.
- **The two sides are not alike.** A sell order is firm: the seconds are locked, and the seller can go away. A buy order is a promise: the buyer must pay when a seller comes, and loses the bond for what is not paid.

What the chain does not have:

- **No market order.** Every action that trades names its price. Nothing buys or sells "at the best price, whatever it is".
- **No stop order.** Section 5 says why, and how to write one yourself.
- **No oracle.** The chain reads no price from outside, and none of its rules reads its own last price.
- **No leverage and no lending.**

**Two services keep the market moving. Anyone can run them, and nobody is paid for it.**

- A **header relay** tells the chain about new Bitcoin blocks ([`deploy/market-relay/README.md`](../deploy/market-relay/README.md)). It holds no key. While nobody relays, the chain's view of Bitcoin stops: after two hours no fill can be made, and a payment in a block the chain was not told of cannot be proven.
- A **prover** finds the payments to the addresses of open fills and sends their proofs ([`deploy/market-prover/README.md`](../deploy/market-prover/README.md)). It costs its operator the fee of every proof it sends (section 2), from an account of its own; the operator sets the most one proof and one day may cost, and the prover sends nothing more that day when the day's sum is used up. While nobody proves, a buyer who has paid gets no seconds, and has lost the bitcoin if the fill is expired first.

Before you trade on a network, find out who runs these two there. If nobody does, run them, or do not trade.

## 2. The units

**Seconds** are counted in microseconds, as everywhere on this chain: `"20000000"` is 20 seconds. **Bitcoin** is counted in satoshis. Every number is a whole number, written as a decimal string. Never use a floating-point number for either.

**A price is millionths of a satoshi for one second.** 250 satoshis a second is `250000000`. A price is from 1 to 10^15.

**What an amount costs:** `sats = ceil(amount_micros × price / 10^12)`. Every rule uses this one formula. It rounds up, to the buyer's cost.

| Seconds | Price | Costs | In bitcoin |
|---|---|---|---|
| 20 | 250 satoshis a second | 5,000 satoshis | 0.00005000 |
| 40 | 250 satoshis a second | 10,000 satoshis | 0.00010000 |
| 100 | 250 satoshis a second | 25,000 satoshis | 0.00025000 |
| 0.999999 | 250 satoshis a second | 250 satoshis: the same as a whole second | 0.00000250 |
| 0.000001 | the lowest price, 1 | 1 satoshi: nothing costs less | 0.00000001 |

The other way round, `floor(sats × 10^12 / price)` is what a sum buys: 10,000 satoshis buy 40 seconds at 250 satoshis a second, and 9,999 buy 39.996. No rule uses this second formula. Once a fill exists, what it costs is fixed in the fill.

**The smallest trade.** An order names its smallest trade in satoshis (`min_sats`). A production network refuses an order whose smallest trade is under 1,000 satoshis. At 250 satoshis a second, 1,000 satoshis are 4 seconds. A fill must cost at least the order's `min_sats`, unless it takes all the order still offers; and it must not leave a rest on the order that costs less.

**The deposit of a taker.** Whoever takes a sell order locks a deposit in seconds: `deposit_ppm` millionths of what they take, or the order's `min_deposit_micros`, whichever is more. The seller chooses both numbers.

- With 5% (`deposit_ppm` 50,000) and a least deposit of 0.25 seconds: a take of 40 seconds locks 2 seconds, a take of 20 locks 1, and a take of 4 locks 0.25.
- The deposit comes back as the fill is paid. It goes to the seller for what is not paid in time.
- It is the price of the buyer's free choice: between the take and the end of the time to pay, a buyer can watch the price and then pay or not. A seller who asks no deposit gives that choice away.

**The bond of a buy order.** A buy order locks `deposit_ppm` millionths of its amount as a bond. A production network asks at least 3% (30,000). A buy order for 50 seconds at 10% locks 5 seconds. When a seller sells 20 of the 50 into it, 2 seconds of the bond move into that fill, and are lost to the seller if the buyer does not pay.

**Fees.** An action costs the network's fee, 1,000 microseconds (0.001 second) unless the network's genesis sets a lower one. Three kinds pay it more than once:

| Kind | Pays | Example |
|---|---|---|
| 50, a sell order | the fee once, and once more for each address it lists | 3 addresses: 4,000 microseconds |
| 58, new addresses for an order | the fee once, and once more for each address | 2 addresses: 3,000 microseconds |
| 54, a proof of payment | the fee once, and once more for every 256 bytes of the proof | the smallest proof the engine's tests made: 4,000 microseconds; a payment in a transaction with 82 outputs: 23,000 |

Every other kind, a buy order included, pays the fee once. The three examples are the fees the engine took in its own tests (`spec/market-vectors.json`, `fee_micros`). On Bitcoin's own blocks, whose first transaction is larger than a test's, `spec/market.md` (section 6) puts a proof of an ordinary payment at about a dozen fees. The proof's fee is paid by whoever sends the proof, which is usually a prover and not the buyer. `actions.action_fee(kind, payload, fee)` says what an action will cost.

**The daily limit counts all of it.** An account with the security rules can move at most its daily limit by a spending key (section 6). Everything an action locks counts against it: the seconds of a sell order, a bond, a deposit, the seconds sold to a buy order, every fee. Three actions count although the balance does not fall: a settle counts the seconds it hands over, a release counts what it gives up, and new addresses for an order count the order's seconds **again**. With a limit of 600 seconds you offer at most 600 seconds a day. What comes back (a cancelled order, an expired fill) gives no allowance back.

## 3. The life of a trade

The reads are `curl`; the answers are shortened here. A signed action is three lines of Python: the builder of `timemarket.actions` makes the payload, and `bot.Sender` signs it and sends it. Without a key it does a dry run: it says what it would send, and sends nothing. That is how every line below was run.

```python
from timemarket import TimeApi, actions, address_to_script, bot, keys

api = TimeApi("http://127.0.0.1:8930")          # the API you run yourself, beside your own node
buyer = bot.Sender(api, account=6).send          # a dry run. To act, give it the key, from where you keep it:
# buyer = bot.Sender(api, account=6, seed=keys.seed_from_env("TIME_BOT_KEY"), act=True).send
seller = bot.Sender(api, account=5).send
```

`Sender` reads the account's nonce just before it signs, signs one action at a time, sends the same bytes again when an answer was lost, and waits until the action is in a block. It never signs a second action for the same purpose. `integration-guide.md`, "The nonce: count it yourself", says why that matters; a program that sends more than one action at a time needs all of it.

### 3.1 Buying: you take a sell order

**1. Look at the book.** A list is the index's word (section 4).

```sh
curl -s "$API/v1/market/orders?side=sell"
```

```json
{"source":"index","proven":false,"side":"sell","items":[
  {"id":"1","owner":"5","price":"250000000","amount_micros":"60000000","sats":"15000","min_sats":"1000",
   "confirmations":"1","pay_blocks":"6","deposit_ppm":"50000","min_deposit_micros":"250000","takes_fill":true,"free_scripts":2}],
 "market_index":{"as_of_height":"350","ready":true,"consistent":true,"tape_reconciled":true}}
```

**2. Read the order itself.** This reads the current state, not the index.

```sh
curl -s $API/v1/market/orders/1
```

Check, in the answer: `order.side` is `sell` and `order.open` is true; `order.price` is at or under your limit; `takes_fill` is true; `owner_stands.stands` is not false (an order whose owner's key was replaced, or whose owner is frozen, takes no fill); `order.confirmations` and `order.pay_blocks` are terms you can meet (section 3.5); the deposit is one you accept. **The take does not name these terms**: it names the order, the amount and the satoshis. Read them here.

**3. Take.** You are the payer. `to` is the account the seconds go to: yours, or somebody else's.

```python
buyer(52, actions.take(order=1, amount_micros=20_000_000, price=250_000_000, to=6), "a take of 20 seconds")
```

```text
WOULD SEND: a take of 20 seconds
  kind 52, payload {"amount_micros":"20000000","order":"1","sats":"5000","to":"6"}
  fee 0.001 s (1000 microseconds)
  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)
```

`price` is the order's price as you read it. The builder computes `sats` from it, and you sign that number. The chain refuses the take unless the amount costs exactly those satoshis at the order's own price. So you never owe more satoshis than you signed.

The chain refuses a take when its view of Bitcoin is stale (no new header for two hours). That costs a refused action, and no seconds.

**4. Find the fill, and read it.** The chain gives the fill its number. The account's list shows it one block later:

```sh
curl -s $API/v1/accounts/6/market
curl -s $API/v1/market/fills/1
```

```json
{"source":"state_proof","fill":{"id":"1","order":"1","owner":"5","payer":"6","to":"8","price":"250000000",
  "amount_micros":"24000000","sats":"6000","deposit_micros":"1200000","confirmations":"1","pay_blocks":"6",
  "script":"00140101010101010101010101010101010101010101","start_height":"5"},
 "last_height":"11","expiry":{"possible":false},"bitcoin":{"network":"regtest","best_height":"5","halted":false}}
```

`fill.script` is where the bitcoin must arrive. `fill.sats` is what is still to pay. `last_height` is the Bitcoin height by which the payment must have its confirmations.

**5. Pay, from your own Bitcoin wallet.** Turn the script into an address (`script_to_address(script, "regtest")`), and pay exactly `fill.sats` to it, with a fee that confirms in the next block.

- **Read the fill again just before you pay.** A fill shrinks as it is paid, and a fill that has ended answers 404 `fill_not_found`: a payment to its address then buys nothing.
- Pay from a wallet whose transaction you control. Section 7 says what a withdrawal from an exchange can do.
- With a node wallet of yours (not run: no Bitcoin node was used for this guide):

```sh
# not run
bitcoin-cli -regtest sendtoaddress "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t" 0.00006000
```

**6. The payment is proven.** When the payment's block has the confirmations the fill asks, on the chain's view of Bitcoin, somebody sends the proof (kind 54). Anyone may.

- **A wallet in a browser cannot fetch a Bitcoin proof.** A proof needs the payment's transaction, the first transaction of its block and a Merkle proof of the two, from a Bitcoin node.
- So you depend on a prover that serves the network, or you prove the payment yourself. With a Bitcoin Core node of your own (not run here; its exit codes are 0 proven or the fill has ended, 2 no payment found, 3 found and not provable now, 1 anything else):

```sh
# not run
node deploy/market-prover/prove.mjs /etc/time-market-prover/config.json --fill 1
```

- In Python, `timemarket.bitcoin.proof_payload` makes the payload from what a node gives (`clients/python/README.md`, "A proof of payment"). This is the engine's own test payment, from the vectors:

```python
import json
from pathlib import Path
from timemarket import proof_payload

vectors = json.loads(Path("../../spec/market-vectors.json").read_text(encoding="utf-8"))["actions"]
entry = next(action for action in vectors if action["name"] == "proof_of_a_part")
payload = proof_payload(fill=1, script="0014" + "01" * 20, block_hash=entry["payload"]["block_hash"], merkle_proof=entry["payload"]["merkle_proof"],
                        transaction=entry["bitcoin_node"]["transaction"], coinbase=entry["bitcoin_node"]["coinbase"])   # as a node gives them, with witness data
print(payload == entry["payload"], actions.action_fee(54, payload, 1000))
```

```text
True 4000
```

**7. The seconds arrive.** A payment in full ends the fill: all its seconds go to `to`, and the whole deposit comes back. The fill then answers 404, and the account's list shows it under `ended` with `how: "paid"`.

The script that does steps 1 to 5 and then watches the fill:

```sh
python -m examples.buy_taker --api $API --account 6 --bitcoin-network regtest --max-daily-limit 600 --max-balance 3000 --amount 20 --limit-price 250000000
```

```text
buy_taker: account 6; DRY RUN
Order 1 of account 5: 20 s at 250 satoshis a second cost 5000 satoshis (0.00005000 BTC).
  A deposit of 1 s is locked. It comes back as the fill is paid, and goes to the seller for what is not paid in time.
  Confirmations the seller asks: 1. Time to pay: 6 Bitcoin blocks from the take.
WOULD SEND: a take of 20 s from order 1, for account 6
  kind 52, payload {"amount_micros":"20000000","order":"1","sats":"5000","to":"6"}
  fee 0.001 s (1000 microseconds)
  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)
  The fill would get the order's first free address: bcrt1pg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqapvxeu. It is read from the fill before anything is paid.
```

With `--act` and a key it sends the take, finds the fill, reads it again and prints what to pay. For a fill you already have, `--fill` prints the same and takes nothing:

```sh
python -m examples.buy_taker --api $API --account 6 --bitcoin-network regtest --max-daily-limit 600 --max-balance 3000 --fill 1 --watch-seconds 1   # exit code 4
```

```text
buy_taker: account 6; DRY RUN
Fill 1: 24 s for account 8, at 250 satoshis a second.
  PAY 6000 satoshis (0.00006000 BTC) to bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t
  Confirmations asked: 1, reached by Bitcoin height 11 at the latest; the chain knows height 5 now. Pay now, with a fee that confirms in the next block.
  With a node wallet of yours:  bitcoin-cli -regtest sendtoaddress "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t" 0.00006000
  Pay from a wallet whose transaction you control. A withdrawal from an exchange can come late, short, or in a transaction too large to prove.
  Then the payment must be proven to the chain: a prover service does it, or you do (node deploy/market-prover/prove.mjs CONFIG --fill 1).
  IF YOU HAVE PAID ALREADY, DO NOT PAY AGAIN: what is paid above what the fill needs buys nothing.
Fill 1 is open: 6000 satoshis are still to pay for 24 s.
Fill 1 is still open, and this script stops watching. Run it again with --fill 1 to go on; that never pays.
```

The fill of this example was made for 40 seconds and 10,000 satoshis. 4,000 were paid and proven, so it holds 24 seconds and 6,000 satoshis are still to pay: the numbers of section 3.4.

### 3.2 Selling: you leave a sell order

**1. Make receiving addresses in your own Bitcoin wallet**, on a machine that is not the bot's. One for each fill the order can have, at most 16 at a time.

- **An address serves one fill, ever.** List addresses that receive nothing else and that no order has listed before. A payment to an address counts for the fill that uses it, whoever sent it and why.
- Check that an address is free: `curl -s $API/v1/market/scripts/<script>` says `free`, `listed`, `in_use` or `used`.

```sh
curl -s $API/v1/market/scripts/00140101010101010101010101010101010101010101
```

**2. Make the order.** The seconds leave your balance until they are sold or you cancel.

```python
addresses = ["bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa", "bcrt1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcruj60yu", "bcrt1qqszqgpqyqszqgpqyqszqgpqyqszqgpqyuza2rq"]
seller(50, actions.sell_order(
    amount_micros=100_000_000, price=260_000_000,                      # 100 seconds at 260 satoshis a second, and not less
    scripts=[address_to_script(address, "regtest") for address in addresses],
    confirmations=3, pay_blocks=6, min_sats=1000,
    deposit_ppm=50_000, min_deposit_micros=1_000_000,                  # takers lock 5%, and a second at least
), "a sell order")
```

```text
WOULD SEND: a sell order
  kind 50, payload {"amount_micros":"100000000","confirmations":"3","deposit_ppm":"50000","min_deposit_micros":"1000000","min_sats":"1000","pay_blocks":"6","price":"260000000","scripts":["00140202020202020202020202020202020202020202","00140303030303030303030303030303030303030303","00140404040404040404040404040404040404040404"],"side":"sell"}
  fee 0.004 s (4000 microseconds)
  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)
```

(The addresses in this guide belong to scripts made of one repeated byte, as the test vectors use them. Nobody should pay to them.)

What you choose:

- `confirmations`: what you ask of every payment. More is safer for you and slower for the buyer. A production network asks at least 3, because Bitcoin reorganises two blocks from time to time without anyone attacking it.
- `pay_blocks`: the buyer's time to pay, in Bitcoin blocks. A production network asks at least 3.
- `min_sats`, `deposit_ppm`, `min_deposit_micros`: section 2.

**3. Wait.** You need not be there. When a buyer pays and the payment is proven, the seconds go to the buyer and the bitcoin is at your address. Your list shows the fills:

```sh
curl -s $API/v1/accounts/5/market
```

**4. Keep the order supplied with addresses.** Every fill uses one up. When they run out, the order holds seconds nobody can take.

```python
seller(58, actions.new_scripts(order=1, scripts=[address_to_script(addresses[0], "regtest")]), "a new address for order 1")
```

This counts the order's seconds against your daily limit again. List enough addresses when you make the order.

**5. End fills that were not paid.** An unpaid fill holds your seconds until somebody sends an expiry (kind 55), which anyone may, once the chain allows it (section 3.5). A prover does it only if its operator turned that on, and never for a fill it has seen a payment to. If none does, you do:

```python
seller(55, actions.expire(fill=1), "the end of a fill that was not paid")
```

The seconds return to the order, and what is left of the taker's deposit comes to you.

**6. Cancel** when you want the rest back. Open fills go on.

```python
seller(51, actions.cancel(order=1), "the cancellation of order 1")
```

There is no way to change an order's price. Cancel it and make a new one, with new addresses; both count against the daily limit.

The script that keeps one order, supplies it and (if asked) ends unpaid fills and cancels on exit:

```sh
python -m examples.sell_maker --api $API --account 5 --bitcoin-network regtest --max-daily-limit 600 --max-balance 3000 --address-file addresses.txt --amount 100 --price 260000000 --scripts 3
```

```text
sell_maker: account 5, one sell order at 260 satoshis a second; 4 free addresses in the file; DRY RUN
No open sell order at this price. A new one: 100 s at 260 satoshis a second, 26000 satoshis in all, paid to:
  bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa
  bcrt1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcruj60yu
  bcrt1qqszqgpqyqszqgpqyqszqgpqyqszqgpqyuza2rq
WOULD SEND: a sell order of 100 s at 260 satoshis a second
  kind 50, payload {"amount_micros":"100000000","confirmations":"3","deposit_ppm":"50000","min_deposit_micros":"1000000","min_sats":"1000","pay_blocks":"6","price":"260000000","scripts":["00140202020202020202020202020202020202020202","00140303030303030303030303030303030303030303","00140404040404040404040404040404040404040404"],"side":"sell"}
  fee 0.004 s (4000 microseconds)
  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)
```

### 3.3 The other direction: a buy order, and selling into it

**A buyer leaves a buy order.** It locks the bond and names the forms of address the buyer's wallet can pay to.

```python
buyer(50, actions.buy_order(amount_micros=50_000_000, price=250_000_000, forms=["p2wpkh", "p2wsh", "p2tr", "p2sh"],
                            confirmations=3, pay_blocks=6, min_sats=1000, deposit_ppm=100_000), "a buy order for 50 seconds")
```

- `confirmations` is the most the buyer will wait for. A seller may ask fewer, never more.
- **A buy order needs its owner awake.** When a seller sells into it, the buyer must pay within `pay_blocks`, or lose the bond's part. Sixteen small sales mean sixteen payments.

**A seller sells into it**, naming a fresh address of a form the order lists:

```python
seller(53, actions.sell(order=2, amount_micros=20_000_000, price=250_000_000, confirmations=2,
                        script=address_to_script("bcrt1qxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxveszjzva7", "regtest")), "a sale of 20 seconds to buy order 2")
```

```text
WOULD SEND: a sale of 20 seconds to buy order 2
  kind 53, payload {"amount_micros":"20000000","confirmations":"2","order":"2","sats":"5000","script":"00203333333333333333333333333333333333333333333333333333333333333333"}
  fee 0.001 s (1000 microseconds)
  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)
```

The 20 seconds leave the seller's balance into a fill. The buyer is now the payer, and pays as in section 3.1, steps 4 to 7. The seller finds the fill in their own list (`GET /v1/accounts/5/market`, with the role `owner`); the chain's own list of an account does not hold it.

### 3.4 The states of a fill, and how each ends

A fill is open from the action that made it until one of these:

| It ends | Who can do it | The seconds | The deposit | The API says |
|---|---|---|---|---|
| **Paid** in full: a proof of at least what was still to pay | anyone sends the proof | to the account the fill is for | back to the payer | `how: "paid"` |
| **Expired**: not paid in its time | anyone, once the chain allows it | back to the order, or to the seller | to the seller | `how: "expired"` |
| **Released**: given up | only the account the seconds would go to | back to the order, or to the seller | to the seller | `how: "released"` |
| **Settled**: handed over without a proof | only the seller | to the account the fill is for | back to the payer | `how: "settled"` |

**Paid in part** is not an end. A payment of less than what is still to pay buys its share and leaves the fill open, with the same address, for the rest:

- The fill of section 3.1 held 40 seconds for 10,000 satoshis, with a deposit of 2 seconds. A payment of 4,000 satoshis bought 16 seconds and returned 0.8 second of the deposit. The fill then held 24 seconds, 6,000 satoshis to pay and a deposit of 1.2 seconds. (These are the engine's own numbers: `spec/market-vectors.json`, `proof_of_a_part`.)
- **A part counts only if** it is at least the order's `min_sats`, or at least half of what is still to pay. With 6,000 satoshis to pay and a smallest trade of 1,000: 3,000 count, 1,000 count, 999 do not. With 1,500 to pay: 750 count (half), 749 do not.
- A payment that does not count stays with the seller and buys nothing, until what is still to pay has fallen to twice it or less.
- **What you pay above what the fill needs buys nothing more.**
- In all you pay exactly the satoshis agreed, in as many payments as you like.

The two ends that need no view of Bitcoin, for when something is stuck:

```python
bot.Sender(api, account=8).send(56, actions.release(fill=1), "giving fill 1 up")   # only the account the seconds would go to (here 8): the deposit is lost
seller(57, actions.settle(fill=1), "settling fill 1")                             # only the seller: says the bitcoin arrived, and hands the seconds over
```

A release counts the seconds given up against the daily limit of the account that sends it, and a settle the seconds handed over (section 2).

Each side can only act against itself. **Never settle because somebody tells you they paid.** Settle when your own Bitcoin wallet shows the payment, confirmed, at the fill's address.

### 3.5 The times

| What | Production network | Laboratory network |
|---|---|---|
| Fewest confirmations an order may ask | 3 | 1 |
| Shortest time to pay, in Bitcoin blocks | 3 | 1 |
| What a Bitcoin block is taken to last | 10 minutes | 1 second |
| The grace | 30 minutes | 20 seconds |

- **The last height** of a fill is `start_height + pay_blocks + confirmations − 1`. A payment in the last block of the time to pay has its confirmations when the chain knows that height. With 6 blocks to pay and 3 confirmations it is 8 above the start. The API gives it as `last_height`.
- **A fill may start behind Bitcoin.** `start_height` is the best Bitcoin block the chain knew, which can be up to two hours old. Do not count on having all of `pay_blocks`: pay at once.
- **A fill cannot be expired before** all of this holds: the chain knows the last height; the grace has passed since it learnt it; and, counted from the take, `(pay_blocks + 2 × confirmations + 16)` blocks' worth of time plus the grace have passed. With 3 blocks to pay and 3 confirmations that is 280 minutes; with 6 and 3, 310 minutes. For a seller, that is how long a buyer who never pays holds the seconds, at least.
- **A proof is accepted as long as the fill exists** and the chain still holds the payment's block. The grace is there so that a payment made in time can still be proven.
- **How long a purchase takes** when all goes well: the time until the payment is in a block, then the confirmations the seller asked, then the relay and the prover, each of which looks every ten seconds unless its operator set it otherwise. On Bitcoin that is tens of minutes, and sometimes much more.
- The fill's answer says whether it can be ended now, and why not: `expiry.possible`, `expiry.reason` (`halted`, `height`, `grace`, `time`).

## 4. Reading the market

```sh
curl -s $API/v1/market                          # the rules of this network, the chain's counts, the Bitcoin header chain, the index
curl -s "$API/v1/market/orders?side=buy"        # one side of the book, best price first
curl -s $API/v1/market/depth                    # both sides added up by price
curl -s $API/v1/market/trades                   # one entry for every proven payment
curl -s "$API/v1/market/candles?interval=hour"  # the candles the chain keeps; 1m, 5m, 15m, 1d are computed by the API
```

All of it at once, on the terminal and as CSV, with no key and no account:

```sh
python -m examples.watch_market --api $API
```

```text
The index is clean, as of height 350 (the state: height 350); 0 rows are being read again.
  ready: True, consistent: True, tape_reconciled: True, tape_complete: True, tape_unvalued: 0, tape_faults: 0, unread_actions: 0, waiting_for_indexer: False
Bitcoin regtest: the chain knows height 5; halted: False; fresh: True (the API's best guess; null is not known).
The chain counts: orders 2, open fills 1, proven payments 1 (4000 satoshis for 16 s in all).
Last recorded price: 250 satoshis a second (a record of one fill, not what a second is worth)

Sell orders, cheapest first (the index's word, as of height 350)
  order  owner      price  amount_micros   sats  min_sats  confirmations  pay_blocks  deposit_ppm  takes_fill
      1      5  250000000       60000000  15000      1000              1           6        50000         yes

Buy orders, dearest first (the index's word, as of height 350)
  order  owner      price  amount_micros   sats  min_sats  confirmations  pay_blocks  deposit_ppm  takes_fill
      2      6  250000000       50000000  12500      1000              3           6       100000         yes

Depth: each side added up by price
  side      price  amount_micros  takeable_micros   sats  orders
  sell  250000000       60000000         60000000  15000       1
   buy  250000000       50000000         50000000  12500       1

Trades, newest first: one for every proven payment
     id  fill      price  sats  seconds_micros  in_full       basis
  349.0     1  250000000  4000        16000000       no  proven_row

Candles (hour), newest first: records of trades, not a valuation
  number  start_time_micros       open       high        low      close  sats  seconds_micros  trades     source
     340   1800020400000000  250000000  250000000  250000000  250000000  4000        16000000       1  state_row
```

### What is proven, and what is an index

| You read | It is | Use it for |
|---|---|---|
| The book, the depth, the trades, the candles, an account's orders and fills (`"source": "index", "proven": false`) | The word of the server you asked. It stores rows the state proved to it; you cannot see that | Finding an order or a fill |
| One order, one fill, one script, the summary (`"source": "state_proof"`) | The current state, with a proof against validator signatures that the server checked and passes on | Acting: taking, paying |

**Find with the lists, act on the row.** Validators keep the rows and no list of them. The lists exist only in the API's index.

**A proof is proven for you only when you check it.** The JavaScript SDK can (`client-v4/`); a Python script cannot. Section 6 says what that means for a bot.

### The flags of the index

Every answer of the market carries `market_index`. `GET /v1/health` carries the same block under `market`.

| Flag | Means | A program should |
|---|---|---|
| `ready: false`, or 503 `market_index_not_ready` | The index has not proven the whole book once yet | Not use the lists. Single rows answer meanwhile |
| `consistent: false` | The index's count of orders and fills is not the chain's. It is reading every row again | Not act on any list |
| `tape_reconciled: false` | Its list of trades does not add up to what the chain counted. Nothing mends it but a rebuilt index | Not act on any list; tell the operator |
| `last_error` (`read_failed`, `state_not_held`), `waiting_for_indexer: true` | Its last read of the state failed, or it is too far behind to read one | Not act on any list |
| `as_of_height` | The height the lists are as of. One below the indexed height while the newest block holds an action of the market | Read the row itself before acting, always |
| `pending_rows` above 0 | Rows are being read again: a read is under way | Expect the lists a block behind |
| `tape_complete: false` | The index started later than the chain: its trades begin at `tape_from_height` | Not take the trades for the whole history |
| `tape_unvalued`, `tape_faults`, `unread_actions` above 0 | Entries without numbers; contradictions found; actions this server's software could not read | Tell the operator: the service needs a look, or a newer release |

**When the flags are not clean, stop acting, and do nothing else.** Do not cancel orders in a hurry: an order is firm and has a limit price, and it is as safe on a book you cannot read as on one you can. The example scripts stop with exit code 2 and say which flag it was. `watch_market` still shows what it was given, marked `NOT CLEAN`.

`bitcoin.halted` and `bitcoin.best_height` in `GET /v1/market` are proven. **`bitcoin.fresh` is the API's best guess**: the time of the header chain's best block is not in the row the state proves. `null` means the API does not know. The chain itself refuses a new fill on a stale header chain.

### A recorded price is not a quote

`last_recorded_price`, the trades and the candles say at which prices fills were paid. **No rule of the chain reads them, and you should not read them as what a second is worth.**

- **An order is a quote.** A sell order is seconds somebody locked at that price: you can take it. That is the only price you can act on.
- **A trade is a record.** It says that one fill was paid, at the price of its order.
- **One small trade moves it.** Two accounts of one person can trade with each other at any price. The smallest trade a production network allows is 1,000 satoshis: at 250 satoshis a second that is 4 seconds, and at 500 it is 2. The bitcoin goes from the person to the person. The cost is the fees of an order, a take and a proof: 7,000 microseconds with the smallest proof of section 2. After that, `last_recorded_price` is whatever they chose, and the candle of that hour has it as its high, its low or its close.
- It need not even cost a Bitcoin fee: an order can list an address that receives payments anyway, and those payments are "trades".
- **The book can be dressed too, and it costs more.** An order far from the others is free to post and to cancel, except for its fees and the daily limit. But while it stands it is real: anyone can take it.

Decide a price from your own view of what a second is worth to you. Never derive a limit from the recorded prices alone.

## 5. Stop loss and other triggers

**The chain has no stop order and will not have one.** A stop order makes the chain read its own last price, and section 4 says what that price costs to move. So a trigger runs in your wallet or in your script. That has two consequences:

- **It works only while it runs.** A script that is stopped, or cut off from its API, does not fire.
- **It is only as good as what it reads.** If one small trade can fire it, somebody will make that trade when your seconds are worth taking.

**How to write one that a single small trade cannot fire.**

1. **Judge on the book, with a size floor.** Ask "at what price are at least N seconds on offer from other people, in orders that take a fill?", not "what was the last price?". Whoever wants to fire your trigger must then lock N seconds on the book at that price, where anyone can take them.
2. **Ask more than once.** Require the trigger to hold in several readings in a row, each at a newer height of the index. An order posted for one block and cancelled is then not enough.
3. **Or judge on several trades**: the newest trades that add up to N seconds, from several different fills, all at or under the stop. This is weaker. Trades between two accounts of one person cost fees only, whatever their size; the floor only raises the seconds they must hold.
4. **Always act with a limit price.** Choose the least you accept, and sell at that or better: into a buy order that pays at least the limit, or with a sell order at the limit. The chain never gives you a worse price than the one in your action.
5. **Assume the trigger can be made to fire anyway.** Then your loss is the difference between what a second is worth to you and your limit. Nothing else bounds it. A limit far under the stop is a gift to whoever fires it.
6. **Refuse a trigger that is met when the script starts.** That is nearly always a wrong unit: a price in satoshis where millionths of a satoshi were meant.
7. **A reading that fails decides nothing.** No answer, or flags that are not clean, must never count as "the price fell".

`examples/stop_loss.py` is written this way. Met at the first reading, it refuses:

```sh
python -m examples.stop_loss --api $API --account 8 --bitcoin-network regtest --max-daily-limit 600 --max-balance 3000 --address-file addresses.txt --amount 20 --stop-price 250000000 --limit-price 250000000 --size-floor 20   # exit code 2
```

```text
stop_loss: account 8, 20 s; stop 250 satoshis a second, limit 250 satoshis a second; judged on the book for 20 s; DRY RUN
REFUSED: The trigger is met at the first reading (20 s can be had from other people's sell orders at 250 satoshis a second or less; your stop is 250 satoshis a second). That is nearly always a wrong unit or a wrong price: nothing is sold. If you mean it, run again with --allow-immediate
```

With a stop under the book it watches:

```sh
python -m examples.stop_loss --api $API --account 8 --bitcoin-network regtest --max-daily-limit 600 --max-balance 3000 --address-file addresses.txt --amount 20 --stop-price 240000000 --limit-price 235000000 --size-floor 20
```

```text
stop_loss: account 8, 20 s; stop 240 satoshis a second, limit 235 satoshis a second; judged on the book for 20 s; DRY RUN
As of height 350: 20 s can be had from other people's sell orders at 250 satoshis a second or less. The trigger does not hold.
```

And this is what it sends when the trigger holds (here forced, to show it):

```sh
python -m examples.stop_loss --api $API --account 8 --bitcoin-network regtest --max-daily-limit 600 --max-balance 3000 --address-file addresses.txt --amount 20 --stop-price 250000000 --limit-price 250000000 --size-floor 20 --allow-immediate --confirm-rounds 1
```

```text
stop_loss: account 8, 20 s; stop 250 satoshis a second, limit 250 satoshis a second; judged on the book for 20 s; DRY RUN
As of height 350: 20 s can be had from other people's sell orders at 250 satoshis a second or less. The trigger holds (1 of 1 readings in a row).
Buy order 2 of account 6 pays 250 satoshis a second, at or above your limit: selling 20 s into it for 5000 satoshis (0.00005000 BTC),
  to be paid to bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszazmwwa with 3 confirmations. The seconds leave the balance now; if the buyer does not pay, they come back with the buyer's bond for them.
WOULD SEND: a sale of 20 s to buy order 2
  kind 53, payload {"amount_micros":"20000000","confirmations":"3","order":"2","sats":"5000","script":"00140202020202020202020202020202020202020202"}
  fee 0.001 s (1000 microseconds)
  DRY RUN: nothing was signed and nothing was sent. (To send: --act for a script, act=True in your own code.)
```

The same holds for every other trigger: a take when the price falls to a level, an order that follows the book. Judge on what can be taken, for a size that matters, more than once, and act with a limit.

**Selling into a buy order is not the end of the risk.** The buyer still has to pay. If they do not, the seconds come back after the fill's time, with the bond's part, and the price may have moved meanwhile.

## 6. Running a bot safely

These points come from a study of earlier thefts from trading programs and bridges (`spec/market.md`, section 13). Keep every one.

**1. Its own account, with the security rules and a daily limit, holding only working capital.**

- Never the account that holds your savings. Make a new account for the bot.
- Adopt the account security rules for it in your wallet. The bot's key is then a spending key: it can move at most the daily limit by itself, an allowance that refills evenly over 24 hours. Your recovery keys stay with you, on paper or on another device, never on the bot's machine.
- Move to the account only what the bot should trade with this week. The limit bounds a thief by the day; the balance bounds them in all.
- Every example refuses to run unless the account has the rules, and its daily limit and its balance are under ceilings you give on the command line (`--max-daily-limit`, `--max-balance`). It also refuses a raise of the limit that is waiting, a frozen account, and a key that can manage the account.

**2. The key comes from the system's key store or an environment variable. Never from the code, never from the command line.**

- `--key-store SERVICE NAME` or `--key-env VARIABLE`: you name the place, and there is no default one. `clients/python/README.md`, "Your key: only from where you point", says how to put a key in the key store of each system.
- Other users of a machine can read command lines. A variable typed into a shell stays in that shell's history: let the service manager that starts the bot set it.
- Nothing the scripts print holds the key. Do not print it yourself.

**3. A selling bot needs no Bitcoin key at all.** It lists addresses, and buyers pay those addresses. Make the addresses in a wallet that is not on the bot's machine (a hardware wallet, a watch-only export), put them in a file, one on a line, and give the bot the file. If the machine is taken, the thief gets no bitcoin.

- The scripts mark an address in the file before they list it, and stop when the file runs out. They never list one twice.
- Copy addresses from your own wallet, and compare the first and the last characters after copying. Programs that swap an address in the clipboard exist.

**4. A buying bot must be able to pay bitcoin, and should hold little.** A Bitcoin wallet with a spending key has to be within its reach. `buy_taker` holds no Bitcoin key itself: by default it prints what to pay and you pay. With `--pay-with-bitcoin-rpc` it asks a Bitcoin Core wallet you run to send one payment. Keep in that wallet what the next trades need, and refill it by hand.

**5. Call an API you run yourself, beside a node you run yourself** (`deploy/api/README.md`). **A script cannot verify a proof.** The verifier exists in Rust and for the JavaScript SDK, not in Python. So a Python bot believes the API it calls, for every number it acts on.

What an API that lies **could** make these scripts do:

- **Pay bitcoin to the liar.** It names an address of its own as the fill's address, and the buying bot pays there. That bitcoin is gone. This is the worst case, and the reason for this point.
- **Lock a deposit on bad terms.** A take names the order, the amount and the satoshis, not the order's confirmations or its time to pay. A lying API can show good terms for an order that has bad ones, and the deposit is lost when the payment cannot make it.
- **Believe an action is in a block when it is not**, or the other way round. The script then waits for nothing, or stops.
- **Fire a trigger.** A false book makes `stop_loss` sell, at its limit and not under it.
- **Waste addresses and daily limit.** A false "no free address" makes `sell_maker` give its order new ones, each time counting the order's seconds against the limit.
- **Hide things**: your fills, a payment, a refusal. It can drop what you submit.

What it **could not** do, whatever it says:

- **Sign anything.** It has no key, and it cannot change what you signed: validators check the signature over every byte.
- **Make you trade at another price than the one you signed.** The satoshis of a take or a sale are in the signed action, and the chain refuses them unless they are the price of the amount at the order's real price. A sell order carries its price.
- **Move more than the account's daily limit in a day, or more than the account holds.** Validators enforce both. This is why point 1 comes first.
- **Take a selling bot's bitcoin, or change where it is paid.** The bot has no Bitcoin key, and the addresses it signs come from your file.
- **Make a seller hand seconds over without a payment.** Only a proof the validators check, or a settle the seller signs, does that; these scripts never settle.

The JavaScript SDK closes the first two: it checks the proof of the fill and of the order before it shows an address. `client-v4/examples/market-take.mjs` is the same take as `buy_taker.py`, and this is the whole difference:

```js
const { state } = await client.getVerifiedState({ market_fills: [id], include_bitcoin: true });   // checked against validator signatures, from YOUR trust manifest
const fill = SDK.marketFill(state, id);          // throws unless this row was proven, in its one form
if (fill === null) return null;                  // PROVEN absent: the fill has ended, and a payment would buy nothing
```

Its test serves the script a fill whose address was changed, as a lying server would: the script stops and prints no address. (Not run as a command for this guide: there is no gateway to ask. `client-v4/examples/market-take.test.mjs` runs it against the engine's proven rows.)

**6. Never act on an address or an amount without reading the fill again.** A fill shrinks as it is paid, and it ends. `buy_taker` reads the fill after the take, checks that it is the fill it made (its order, its payer, the account it is for, its price, and an address the order showed before the take), and reads it once more at the moment of paying. With `--fill` it never pays by itself: it cannot know whether you have paid already.

**7. Pin what you run.**

- Check out one commit of this repository and run that. Do not let the bot's machine update itself.
- The Python package needs one library, `cryptography`. Install it with hashes pinned (`clients/python/README.md`, "Installing: one dependency, pinned"), and nothing else you have not read a reason for. Packages with names one letter away from a well-known one exist to steal keys.
- Run the package's tests before the first use (`python -m unittest discover` in `clients/python`). They hold the signing code to the engine's vectors, byte for byte.

**8. What nobody will ever ask you for.**

- **Your signing key**, or the file, the variable or the key store entry that holds it. Not a developer, not an operator of the network, not "support", not a program that offers to "check" or "migrate" it.
- **Your recovery words or a recovery key.** A bot never needs them. Whoever asks for them is taking the account.
- **A payment to fix a trade.** No trade is "stuck" until you pay a fee, a tax or a "verification amount" to someone. What a fill costs is in the fill, on the chain. A fill that goes wrong ends by the rules of section 3.4, never by a payment to a person.
- **To run a command you were sent**, or to install another package "that this one needs".

**Three more, from how these scripts are written.**

- **A dry run is the default.** Every script says what it would send and sends nothing until it is given `--act`. Read a dry run before every first use and after every change of a number.
- **One action at a time, and the same bytes again.** A script that signs a second action because the first got no answer makes the order twice. The examples send the same bytes again, and stop with exit code 3 when an action is in no block after the wait. Then look the hash up before you run anything.
- **When in doubt, stop.** Each refusal ends the script with exit code 2 and one line that says why. A supervisor that restarts a bot on every exit turns a refusal into a loop: restart on exit code 1 at most.

## 7. What can go wrong, and what it costs

From `spec/market.md`, section 10, which is the full list.

**You pay late.** If your payment confirms after the fill has ended, or nobody proves it before the fill ends, the bitcoin is with the seller and you get no seconds for it. You have also lost the deposit. Nobody can give either back but the seller. Pay at once, with a fee that confirms in the next block, and watch `last_height`.

**You pay short.** A part buys its share if it counts (section 3.4). Pay the rest to the same address while the fill exists. A part that does not count buys nothing until the rest is small enough. A rest smaller than what Bitcoin nodes relay (a few hundred satoshis) can only be paid by paying more.

**You pay from an exchange.** A withdrawal is the exchange's transaction, not yours:

- it can leave hours later, after the fill has ended;
- it can arrive short, because the exchange kept a fee out of it;
- it can be one of hundreds of payments in one transaction. That proof costs its sender more (23 fees for a transaction with 82 outputs, in the engine's own test), and a prover with a low ceiling for one proof will not send it. A transaction above 100,000 bytes cannot be proven at all;
- you cannot raise its fee.

Withdraw to your own wallet first, then pay from there.

**The address is not yours** (for a seller). The chain cannot know who holds an address.

- An address you mistyped fails its checksum. An address that was swapped in your clipboard does not: the buyer pays a stranger, and the chain hands your seconds over.
- An address that also receives other money gives seconds for that money to whoever holds the fill.
- Somebody who sees your order before it is in a block can list your address first. Your action then fails. It costs them a fee and locks their own seconds.

**The chain's view of Bitcoin is stale.** Nobody relays headers, or the relay is behind. No new fill can be made (a refused action). A payment in a block the chain was not told of cannot be proven yet, and a fill whose last height the chain has not learnt cannot expire. Cancelling, releasing and settling still work. Nothing is lost by the delay itself; a payment is lost if the relay stays away until after the fill could end, so do not pay into a market whose relay is down.

**The header chain is halted.** A Bitcoin reorganisation deeper than 144 blocks halts it, and this version has no action that starts it again. Orders can be cancelled, fills released or settled; nothing else moves until a software release. A payer who has paid depends on the seller's settle. On testnet3 such a reorganisation is cheap to make.

**The seller disappears.** That alone costs you nothing: a sell order is firm, and a proof delivers the seconds without the seller. You depend on the seller only where a proof is impossible: a halted header chain, a payment in a transaction too large to carry, a block whose first transaction is too large to carry (which a miner who is the seller can cause). Then only their settle delivers.

**The buyer never pays** (for a seller). Your seconds are held for the fill's time: at least 280 minutes with 3 blocks to pay and 3 confirmations. Then somebody has to send the expiry, for one fee. You get the seconds back and what is left of the deposit. The deposit is your pay for that time: ask one. A taker can also use up your addresses with small fills; the least deposit is what makes that cost.

**Nobody proves your payment.** A prover is one process run by somebody. If it is down, prove the payment yourself (section 3.1, step 6) while the fill exists.

**Validators keep a proof out.** A proof must enter a block before the fill is expired. Validators with more than two thirds of the votes could keep it out, and while one operator runs every validator, that operator can.

**Bitcoin reorganises after the seconds moved** (for a seller). The seconds are final at once. If the payment's block later leaves the Bitcoin chain, you have lost them. That is what `confirmations` is for.

**Somebody mines a private Bitcoin chain.** A proof needs real proof of work on the chain of most work that the Time chain knows, and the chain cannot check that a payment's inputs exist. Someone who mines the confirmations in private can take the seconds of fills without paying, and one such chain pays for every order on the book at once. On regtest and testnet3 that costs nothing, which is why they protect nothing. A rule that bounds it must exist before mainnet is opened (`spec/market.md`, section 11).

**Everything is public.** Orders, fills, addresses and the Bitcoin transactions that paid are public on both chains, and tie an account to Bitcoin addresses.

## 8. Writing a client in another language

Three things make a client: the bytes of an action, the payload of each kind, and the vectors that say whether you got both right.

**The envelope** (`spec/protocol-4.md`, section 4). An action is these bytes, in this order, integers big-endian:

| Bytes | What |
|---|---|
| 19 | `TCDEVNET-ACTION-V1` and one zero byte, the same on every network |
| 32 | the network id |
| 1 | the kind (50 to 58) |
| 8, 8, 8 | the sender's account, the nonce (the account's nonce plus one), the authority epoch |
| 32 | the public key of the signer (Ed25519) |
| 4 | the length of the payload |
| … | the payload |
| 64 | the signature: Ed25519 over every byte before it |

An action is known by the SHA-256 of all its bytes, in capital hexadecimal. It is submitted as `{"tx": "<base64>"}` to `POST /v1/transactions`.

**The payloads** (`spec/market.md`, section 6). Each is canonical JSON: exactly the fields of its kind, keys in ascending order, no spaces, every number a decimal string without leading zeros, scripts and hashes in lowercase hexadecimal, a list written as a list and never as `null`. One wrong byte and you have signed something else. `clients/python/timemarket/actions.py` lists the field sets and what is checked before signing.

**The vectors** (`spec/market-vectors.json`). The engine's own tests write this file from actions the engine signed and accepted. For every kind it holds the payload, the network id, the sender, the nonce, the authority epoch, the signer's test key and the exact signed bytes (`signed_hex`), and the fee the engine took.

How to check your implementation against it:

1. For each entry of `actions`, build the action from `network_id`, `kind`, `from`, `nonce`, `auth_epoch`, `payload` and the key. Your bytes must be `signed_hex`, bit for bit. Ed25519 signatures are deterministic, so there is nothing to allow for. If your library adds randomness to signatures, compare everything before the last 64 bytes, and verify the signature.
2. Check your fee against `fee_micros`.
3. Check your price arithmetic against `sats` and `bought`, including the entries where the answer is `null`: the engine refuses those.
4. Check your address code against `addresses` and `forms`, and against `spec/bitcoin-address-vectors.json`.
5. Check your proof code against `transactions` (with and without witness data) and `merkle_proofs`.

The take of section 3.1 is the entry `take`: 239 bytes, of which 63 are the payload.

```python
from timemarket import wire

entry = next(action for action in vectors if action["name"] == "take")
signed = wire.sign_action(network_id="053ea6717e27b294bfc404fb1e65d2d336c8171346cd2ddf7204deec60763434", kind=52, sender=6, nonce=3, auth_epoch=0,
                          payload=actions.take(order=1, amount_micros=20_000_000, price=250_000_000, to=6), seed=entry["seed_hex"])   # a test key of the vectors
print(signed.hex() == entry["signed_hex"], len(signed), wire.transaction_hash(signed))
```

```text
True 239 AB0216EE760D4437533977CB25D3B3681C868F8D84D790E794DFD3AA195D82E5
```

Do this before your code touches a key that matters. The Python package and the JavaScript SDK are held to the same file by their tests.

**What your client must still not do** is trust an answer it cannot check. Unless you also port the verifier (`verifier-v4/`, in Rust), everything in section 6, point 5 holds for it.

## 9. What has run, and what has not

- **No network has the market.** No action of the market has been in a block of a network, and no payment has been proven on one.
- **What this guide's commands ran against** is a stand-in: `clients/python/tests/fake_api.py` answers in the forms of the API's source (`client-v4/api.mjs`) and follows the rules as its author read them. It is not the engine and not the API. `python -m tests.fake_api` (in `clients/python`) serves it, with the market this guide shows.
- **What is held to the engine:** what the scripts sign. The tests run each script through the stand-in and compare the bytes it submits with the bytes the engine signed and accepted for the same trade: a sell order, new addresses, a cancellation, a take, a sale to a buy order.
- **Run by the tests, against the stand-in:** every refusal of section 6, the dry runs, a lost answer, an action that is in no block, a fill that changed between two reads, the address file. The test that reads this guide runs every Python block and every script command in it and compares what they print with what is printed here.
- **Run nowhere:** `buy_taker --pay-with-bitcoin-rpc` against a Bitcoin node (the test's "wallet" is a few lines that answer one call); the key store on any system but as the package's own tests exercise it; the acting path of the JavaScript example; any script for longer than a test; any of it under load, or against an API that is slow, behind, or restarted.

**A first run on a real network should look at:**

1. Whether an action of each kind that these scripts sign is accepted by a node, with the fee this guide states.
2. How long the index takes to show a new order and a new fill, and whether `Sender`'s wait and the search for the new fill are long enough.
3. The answer of `GET /v1/actions/{hash}` for a market action: the scripts wait for `results_checked`.
4. The flags of `market_index` on a busy market: how often they are not clean, and for how long.
5. A whole purchase with a real payment on regtest: the relay, the prover, the time each step takes, and what `buy_taker` shows meanwhile.
6. `sendtoaddress` with the amount as a decimal text, against the version of Bitcoin Core in use.
7. The security rules on the bot's account as a wallet sets them up: that the bot's key is a spending key and nothing more, and what the scripts read of the limit.
