# timemarket: a Python client for the market of seconds against bitcoin

For people who trade with a script. It builds, checks and signs the nine actions of the market, turns Bitcoin addresses into the scripts an order lists, puts a proof of payment together, and talks to the public API.

**Read this first.**

- The rules of the market are `spec/market.md`. They are a draft, and no network runs them yet. Section 10 of that file says what the rules do not protect you from; read it before you trust this with anything.
- **Bitcoin mainnet is closed in this version**: a network whose Bitcoin network is mainnet refuses to trade. The two networks that are open, regtest and testnet3, protect nothing: a payment can be invented there by whoever wants the seconds. Use them to rehearse, with seconds that are worth nothing.
- **The guide for traders is [`docs/trading.md`](../../docs/trading.md)**: the units, the life of a trade step by step, how to read the market, how to write a trigger, and what can go wrong. Four example scripts are in `examples/` (see "The examples", below). They are examples: read one before you run it, and run it dry first.
- **A script cannot verify a proof.** The API gives a proof with every order, fill and account it reads from the state. Checking a proof takes the verifier, which exists in Rust and for the JavaScript SDK (`client-v4/`), not in Python. So a bot built on this package trusts the API it calls for every number it acts on: the address it pays bitcoin to, what a fill still needs, whether a fill exists. **Call an API you run yourself, beside a node you run yourself** (`deploy/api/README.md`). An API run by somebody else can make your bot pay to an address of theirs.
- Nothing here has run against a network. It is held to the engine by test vectors (see "One function signs").

## What nobody will ever ask you for

- **Your signing key**, or the file, the variable or the key store entry that holds it. Not a developer of this package, not an operator of the network, not "support", not a program that offers to "check" or "migrate" your key. This package reads your key only where you point it, and sends it nowhere.
- **Your recovery words, your recovery sheet or a recovery key.** A bot never needs them. Whoever asks for them is taking the account.
- **A payment to fix a trade.** No trade is "stuck" until you pay a fee, a tax, a deposit or a "verification amount" to someone. What a fill costs is in the fill, on the chain; what an action costs is its fee, taken by the chain. A fill that goes wrong ends by the rules (it is paid, given up, settled, or its time passes), never by a payment to a person.
- **To run a command you were sent**, or to install another package "that this one needs". This package needs one library, named below.

If something here seems to ask you for one of these, it is not this package.

## Start here: a bot on its own account

Before any code, three decisions keep a mistake, or a theft of the machine the bot runs on, small.

1. **Its own account.** Never the account that holds your savings. Make a new account for the bot.
2. **The account security rules, with a daily limit.** Adopt them for that account in your wallet (`v5/src/security.rs` has the rules): the bot's key becomes a spending key that can move at most the daily limit by itself, an allowance that refills evenly over 24 hours (so at most the limit at once, and at most twice the limit in any 24 hours, fees included). Your recovery keys stay with you, on paper or on another device, never on the bot's machine.
3. **Only working capital.** Move to the account only what the bot should trade with this week. The limit bounds a thief by the day; the balance bounds them in all.

What the limit does to the market (`spec/market.md`, section 7): everything an action locks counts against it (the seconds of a sell order, the bond of a buy order, the deposit of a fill, the seconds sold to a buy order, every fee); a settle counts the seconds it hands over, giving a fill up counts what it gives up, and new receiving scripts for an order count the order's seconds again. So **the limit also caps honest trading**: with a limit of 600 seconds the bot offers at most 600 seconds a day, and an order cancelled and made again counts twice. List enough receiving scripts when you make an order. What comes back (a cancelled order, an expired fill) gives no allowance back.

**A bot that only sells seconds needs no Bitcoin key at all.** It lists Bitcoin *addresses* in its orders, and buyers pay those addresses. Make the addresses in a wallet that is not on the bot's machine (a hardware wallet, a watch-only export) and give the bot the list. If the machine is taken, the thief gets no bitcoin.

**A bot that buys must be able to pay bitcoin**, so a Bitcoin wallet with a spending key has to be within its reach. Keep little in that wallet, refill it by hand, and remember that a buy order also locks a bond in seconds that is lost for what the bot does not pay in time.

The first example is the selling bot. It refuses to run unless the three decisions were made:

```python
from timemarket import TimeApi, actions, address_to_script, keys, sign_action, transaction_hash

ACCOUNT = 12                      # the bot's own account
MOST_DAILY_LIMIT = 600_000_000    # 600 seconds: refuse to run on an account that may move more a day
MOST_BALANCE = 3_000_000_000      # 3,000 seconds: refuse to run on an account that holds more
ADDRESSES = ["bcrt1q…", "bcrt1q…"]  # made elsewhere; each receives nothing else and is listed once, ever

api = TimeApi("https://api.example.org")                    # the API of the network you rehearse on
status, state = api.status(), api.account_state(ACCOUNT)    # read just before signing
account, security = state["account"], state["security"]

if security is None:
    raise SystemExit("This account has not adopted the account security rules: do that in your wallet first")
if int(security["policy"]["daily_limit_micros"]) > MOST_DAILY_LIMIT:
    raise SystemExit("The daily limit of this account is higher than this bot should ever move in a day")
if int(account["balance"]) > MOST_BALANCE:
    raise SystemExit("This account holds more than working capital: move the rest out before the bot runs")

payload = actions.sell_order(
    amount_micros=300_000_000,                              # 300 seconds
    price=250_000_000,                                      # the limit price: 250 satoshis a second, and not less
    scripts=[address_to_script(address, "regtest") for address in ADDRESSES],
    confirmations=3, pay_blocks=6, min_sats=1000,
    deposit_ppm=50_000, min_deposit_micros=1_000_000,       # takers lock 5%, and a second at least
)
print("fees:", actions.action_fee(50, payload, status["network"]["fee_micros"]), "microseconds")

seed = keys.seed_from_key_store("time-bot", "account-12")   # read only now, from where you put it
signed = sign_action(
    network_id=status["network"]["network_id"], kind=50,
    sender=ACCOUNT, nonce=int(account["nonce"]) + 1, auth_epoch=account["auth_epoch"],
    payload=payload, seed=seed,
)
print(transaction_hash(signed), api.submit(signed)["status"])
```

What the API says about the account is that server's word, not a proof: the checks above stop an honest mistake, not a lying server. The SDK in `client-v4/` verifies the state against validator signatures.

### Reading the market

```python
book = api.market_orders("sell", limit=20)                  # best price first; a list is the index of that server
if not (book["market_index"]["consistent"] and book["market_index"]["tape_reconciled"]):
    raise SystemExit("The API says its index of the market disagrees with the chain: do not act on its lists")
order = api.market_order(book["items"][0]["id"])            # the row itself, from the current state
if not order["takes_fill"] or order["owner_stands"]["stands"] is not True:
    raise SystemExit("This order takes no fill now")
mine = api.account_market(ACCOUNT)                          # my open orders, my fills with my role in each, what ended
for fill in mine["fills"]:
    if "payer" in fill["roles"]:
        now = api.market_fill(fill["id"])                   # read again before EVERY payment: a fill shrinks as it is paid
        print(now["fill"]["script"], now["fill"]["sats"], "satoshis by Bitcoin height", now["last_height"])
```

- **A list is where you look; the single row is what you act on.** `market_orders`, `market_depth`, `market_trades`, `market_candles` and `account_market` come from the server's index, and each says the height it is as of (`market_index.as_of_height`). `market_order`, `market_fill` and `market_script` read the current state. A fill that has ended is an `ApiError` with code `fill_not_found`: a payment to its address then buys nothing.
- **`account_market` finds fills the chain's own list does not.** The chain lists for an account the orders it owns and the fills it pays. Your fills as the seller to a buy order, and fills somebody else made for you, are found through the index: each fill carries your `roles` (`payer`, `owner`, `to`).
- **Prices of trades and candles are records, not a valuation.** `market()["last_recorded_price"]`, `market_trades()` and `market_candles(...)` say what was recorded. "Every trade names its price", below, says why a bot never takes its price from them alone.
- **Nothing is pushed.** Ask again: `account_market` for your fills, `market_trades(order="asc", cursor=...)` for new trades. Each costs 1 of the API's budget of requests; a single row costs 5.

**`submit` sends once and never retries.** "Submitted" is not "in a block": look the hash up (`api.action(hash)`) until it is. If the answer is lost or is an error, send **the same bytes** again; the chain takes them once. Do not sign a new action for the same purpose until you know the first did not happen, or you may make the order twice. `docs/integration-guide.md` ("The nonce: count it yourself") has the whole procedure, and it applies to a bot as it does to an exchange.

## The examples

Four scripts in `examples/`, each one file and a complete program. Run them from `clients/python`, as modules. **A dry run is the default**: a script says what it would send and sends nothing until it is given `--act`.

| Script | What it does | Needs |
|---|---|---|
| `python -m examples.watch_market --api URL` | Shows the book, the depth, the recent trades and the candles, on the terminal and as CSV (`--csv-dir`), with the flags of the API's index. | No key, no account |
| `python -m examples.sell_maker … --address-file FILE --amount SECONDS --price P` | Keeps one sell order at a price you give, fed with receiving addresses from a file you made with your own Bitcoin wallet. Gives the order new addresses as fills use them, ends unpaid fills (`--expire-unpaid`), cancels on exit (`--cancel-on-exit`). | A spending key of the account. **No Bitcoin key** |
| `python -m examples.buy_taker … --amount SECONDS --limit-price P` | Takes the best sell order at or under your limit, prints the address and the amount to pay, read again from the fill, and waits for the fill to end. With `--pay-with-bitcoin-rpc URL --bitcoin-cookie-file FILE` it asks a Bitcoin Core wallet you run to send the payment. | A spending key of the account. It holds no Bitcoin key itself |
| `python -m examples.stop_loss … --address-file FILE --amount SECONDS --stop-price P --limit-price P --size-floor SECONDS` | Watches the book and sells with a limit price when the trigger holds for real size, in several readings in a row. | A spending key of the account. **No Bitcoin key** |

The three that sign take the same first arguments (`…` above), and none has a default:

```
--api URL --account NUMBER --bitcoin-network regtest|testnet3 --max-daily-limit SECONDS --max-balance SECONDS
[--key-store SERVICE NAME | --key-env VARIABLE] [--act]
```

- **Each refuses to act** unless the account has adopted the security rules, its daily limit and its balance are under the two ceilings, the key is a spending key of the account and nothing more, the API says its index of the market is clean, and the order or the fill was read again, by itself, just before. A refusal ends the script with exit code 2 and one line that says why.
- **The key is read only through `timemarket.keys`**, from the key store or from an environment variable, under the names you pass. It is never an argument.
- **The address file** is one address on a line. A script writes `used` after an address before it lists it, and stops when the file runs out. It never lists one twice.
- **Exit codes:** 0 done; 2 refused (nothing was sent, or the chain refused it and nothing happened); 3 something was sent and is in no block yet (look the hash up before you run anything); 4 (`buy_taker`) the fill ended unpaid, or is still open; 1 the API, the key store or a file could not be read.
- **What they are tested against** is a stand-in for the API with a small model of the market (`tests/fake_api.py`), not a network. `python -m tests.fake_api` serves it on this machine, to try the scripts by hand. What the scripts sign is held to the engine's vectors, byte for byte.

## Installing: one dependency, pinned

Python 3.10 or later. **The package has no third-party dependency except one Ed25519 library**, because Python has no Ed25519 built in and this package writes no cryptography of its own. Everything else (the address codec, the payloads, the envelope, the proof, the HTTP client) uses the standard library alone.

- The library is **`cryptography`, version 42.0.0 or later**. (`PyNaCl`, version 1.5.0 or later, is used instead if `cryptography` is not installed.) The package refuses to sign with an older release. It was tested with `cryptography` 46.0.5 and `PyNaCl` 1.6.2.
- `cryptography` brings `cffi` and `pycparser` with it. Those three are all that is installed.

**Install with hashes pinned**, so that what is installed on the bot's machine is byte for byte what you looked at, and a changed or look-alike package is refused:

```
# requirements.txt, written once on a machine you trust (pip-compile --generate-hashes writes it for you):
cryptography==46.0.5 \
    --hash=sha256:<the hash of the file for your system, from pip hash or the package index>
cffi==<version> --hash=sha256:<…>
pycparser==<version> --hash=sha256:<…>

pip install --require-hashes --no-deps -r requirements.txt
```

`pip hash <downloaded file>` prints the hash of a file you downloaded. Check the name letter by letter: packages with names one letter away from a well-known one exist to steal keys. Install nothing else on the bot's machine that you have not read a reason for.

There is nothing to install for this package itself: put `clients/python` on your `PYTHONPATH`, or run your script from that folder.

## Your key: only from where you point

A signing key is its 32-byte seed, written as 64 lowercase hexadecimal characters. The bot needs a key of its account that can spend. It does not need, and must never be given, a recovery key.

**This package never looks for a key by itself.** There is no default file, no default variable, no search of your home folder. A key is read by a call you write, from the place you name:

```python
from timemarket import keys
seed = keys.seed_from_key_store("time-bot", "account-12")   # the operating system's key store
seed = keys.seed_from_env("TIME_BOT_SEED")                  # an environment variable set by whatever starts the bot
seed = keys.seed_from_file("/etc/time-bot/seed")            # a file only the bot's user can read: chmod 600
```

- **The key store** keeps the key encrypted under your login. You put the key there once, yourself, under names you choose:
  - macOS: `security add-generic-password -s time-bot -a account-12 -w` (it asks for the key; do not put the key on the command line);
  - Linux: `secret-tool store --label="time bot" service time-bot account account-12` (it asks for the key);
  - Windows: Control Panel, Credential Manager, Windows Credentials, "Add a generic credential": address `time-bot`, user name `account-12`, password the key.
- **An environment variable** is for a service manager that sets it from its own protected store. A variable typed into a shell stays in that shell's history.
- **A file** must be readable by its owner alone; on Linux and macOS a file that anyone else can read is refused. On Windows nothing can be checked: use the key store there.

**Nothing secret is printed or put in an error message.** The three functions return a `Seed`, which shows as `<signing key: not shown>` when it is printed, logged or caught in a traceback, and cannot be pickled. A message about a key that is not one says where it was read, never what was read. Do not print it yourself (`seed.reveal()` exists for the signing code, not for logs).

Never put the key in the script, on a command line (other users of the machine can read command lines), in a chat, a ticket or a repository. If the machine is shared, or the key was ever pasted somewhere, treat it as seen: replace it from your wallet with your recovery keys.

## Every trade names its price

**There is no "market order" here, and there will not be.** Every builder that trades takes the price as an argument you must give, and no function buys or sells "at the best price, whatever it is". Elsewhere, bots that traded at whatever price the book showed were emptied by someone who put a bad price in front of them for one block.

- `sell_order` and `buy_order` carry your limit price; the chain never fills them at a worse one.
- `take` and `sell` fill somebody else's order, and take that order's price **as you read it and accepted it**: what the amount costs at that price (`sats`) is computed here and signed. The chain checks that the amount costs exactly the satoshis you signed at the order's own price, and refuses the action otherwise. So you never pay more satoshis for your seconds, or get fewer satoshis for them, than the number you signed.
- Decide the limit in your own code, from your own view of what a second is worth. The chain's last price and its candles record what was traded, not what a second is worth, and can be moved on purpose (`spec/market.md`, section 9): never derive a limit from them alone.

## What each action does

Each builder takes its arguments by name and returns the payload, checked. A whole number is an `int` or a decimal string; amounts are microseconds, and a price is millionths of a satoshi for one second (250 satoshis a second is `250_000_000`).

| Kind | Builder (`timemarket.actions`) | In one sentence |
|---|---|---|
| 50 | `sell_order(amount_micros, price, scripts, confirmations, pay_blocks, min_sats, deposit_ppm, min_deposit_micros)` | Offers seconds at a price; they leave your balance until they are sold or you cancel. |
| 50 | `buy_order(amount_micros, price, forms, confirmations, pay_blocks, min_sats, deposit_ppm)` | Promises to pay bitcoin for seconds, and locks a bond that you lose for what you do not pay. |
| 51 | `cancel(order)` | Takes back what your order still offers. |
| 52 | `take(order, amount_micros, price, to)` | Takes part of a sell order at its price: you promise the bitcoin and lock a deposit, and the seconds wait for your payment. |
| 53 | `sell(order, amount_micros, price, confirmations, script)` | Sells seconds to a buy order at its price, to be paid to your `script`. |
| 54 | `proof(fill, block_hash, transaction, coinbase, vout, merkle_proof)` | Shows the chain a Bitcoin payment for a fill, which moves the seconds it paid for; anyone may send it. |
| 55 | `expire(fill)` | Ends a fill that was not paid in time; anyone may send it. |
| 56 | `release(fill)` | Gives up a fill whose seconds would be yours; the deposit is lost to the seller. |
| 57 | `settle(fill)` | Hands the seconds of your fill over without a proof, because you saw the bitcoin arrive. |
| 58 | `new_scripts(order, scripts)` | Gives your open sell order new receiving addresses. |

Things that cost money if you get them wrong:

- **A receiving script serves one fill, ever.** List addresses that receive nothing else and that no order has listed before. A payment to an address whose fill has ended buys nothing, and a seller who lists an address that receives other money gives seconds for that money.
- **Pay in time, and prove it in time.** A fill that is not paid and proven within its time ends, and the deposit goes to the seller. A payment that confirms after that is with the seller, and nobody gets seconds for it.
- **A fill can be paid in parts.** A part counts if it is at least the order's `min_sats`, or at least half of what the fill still needs, or all of it; it buys its share of the seconds and leaves the fill open for the rest, and in all you pay exactly the satoshis agreed. A smaller payment stays with the seller and buys nothing, and so does what you pay above what the fill needs. `amounts.part_counts` says whether a payment will count, and `amounts.fill_after_payment` what it will do to the fill.
- **Fees.** Kinds 50 and 58 pay the network's fee once more for each script they list. Kind 54 pays it once more for every 256 bytes of its payload: a proof of an ordinary payment costs about a dozen fees, and the chain refuses a proof whose sender cannot pay that. `actions.action_fee(kind, payload, network_fee_micros)` says what an action will cost.
- `confirmations` and `pay_blocks` are checked here against their widest bounds only (1 to 100, 1 to 144). A production network asks at least 3 of each and refuses less; so does it refuse a `min_sats` below 1,000 and a buy order's `deposit_ppm` below 30,000 (3%).

## Addresses

An order lists receiving scripts, not addresses. `timemarket.address` turns one into the other for the five standard forms (the addresses that begin with `1`, `3`, `bc1q` and `bc1p`, and their test-network forms) on `regtest`, `testnet3` and `mainnet`:

```python
from timemarket import address_to_script, script_to_address
script = address_to_script("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "regtest")
assert script_to_address(script, "regtest") == "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
```

It refuses whatever it is not sure of (a wrong checksum, mixed case, an address of another network, a form the market does not take) with a `ValueError` that says why, and never corrects an address. It cannot tell a testnet3 legacy address from a regtest one (they are the same text), and it cannot know whether anyone holds the key of an address: copy addresses from your own wallet, and compare the first and last characters after copying (programs that swap an address in the clipboard exist).

## A proof of payment

When the bitcoin for a fill has confirmed, anyone can show the chain. `timemarket.bitcoin.proof_payload` puts the payload together from what a Bitcoin node gives; it calls no node itself. With Bitcoin Core:

```
bitcoin-cli getblock <block hash> 2          # tx[0] is the coinbase: its txid and hex; find the payment's hex by its txid
bitcoin-cli gettxoutproof '["<coinbase txid>","<payment txid>"]' <block hash>
```

```python
from timemarket import proof_payload
payload = proof_payload(
    fill=7, script=fill_script,                        # the fill's script, read from the chain
    block_hash=block_hash, transaction=payment_hex, coinbase=coinbase_hex, merkle_proof=txoutproof_hex,
)                                                      # kind 54
```

The chain wants both transactions without their witness data (the payment at most 100,000 bytes, the coinbase at most 150,000); the function removes the witness data (`strip_witness`), finds the output that pays the fill's script, and checks the Merkle proof down to the block's root, so that a mistake is found before a dozen fees are paid. Whether the block has the confirmations the fill asks, and is on the chain the network knows, only the network can say.

## One function signs, and the vectors check it

**All signing goes through `timemarket.wire.sign_action`.** No other function of the package makes a signature (a test of the package holds it to that), and a bot built on it should sign nowhere else. Then one place decides what your key puts its name to, and that place signs only a payload that `actions.action_payload` has checked field by field.

If you write your own signer, in Python or in another language, or use someone else's, **check it against `spec/market-vectors.json` before it touches a key that matters.** That file is written by the engine's own tests (`v5/tests/market.rs`) from actions the engine signed and accepted: for every kind, the payload, the signer's seed (test keys), the network, the sender, the nonce, the authority epoch and the exact signed bytes. A correct implementation gives those bytes, bit for bit, for every entry; Ed25519 signatures are deterministic, so there is nothing to allow for. This package and the SDK in `client-v4/` are held to the same file by their tests, and an implementation that differs in one byte signs something the chain will refuse, or something you did not mean.

The file also holds the fee the engine took for each action, the price arithmetic at its edges, addresses and transactions as the engine's Bitcoin library writes them, and Merkle proofs with what each proves. `spec/bitcoin-address-vectors.json` holds the test vectors of BIP173 and BIP350 and Bitcoin Core's own address data.

## The other modules

- `timemarket.amounts`: `sats(amount_micros, price)` is what an amount costs, `ceil(amount × price / 10^12)`; `bought(paid_sats, price)` is what a payment buys at a price, `floor(sats × 10^12 / price)`; `part_seconds(amount_micros, sats, paid)` is what a payment of a part buys of a fill, `floor(amount × paid / sats)`; `part_counts(sats, paid, order_min_sats)` is whether the chain counts it; `fill_after_payment(amount_micros, sats, deposit_micros, paid)` is what a payment does to a fill. Whole numbers only; never use `float` for amounts.
- `timemarket.wire`: `sign_action`, `build_action` (the bytes that are signed), `decode_action` and `verify_action` (reading a signed action back), `public_key(seed)`, `canonical_json`, `transaction_hash`.
- `timemarket.bitcoin`: `proof_payload`, `strip_witness`, `transaction_id`, `transaction_outputs`, `merkle_proof_matches`.
- `timemarket.api`: `TimeApi(base_url, timeout=10.0)` with `status()`, `health()`, `account_state(account)`, `action(hash)`, `submit(signed)`, and for the market `market()`, `market_orders(side, limit=, cursor=)`, `market_depth(levels)`, `market_order(order)`, `market_fill(fill)`, `market_script(script)`, `market_trades(limit=, cursor=, order=)`, `market_candles(interval, from_micros=, to_micros=, limit=)`, `account_market(account, limit=, cursor=)`; `ApiError` with `status`, `code`, `body`, `retry_after`. Every request has a timeout, none is retried, and a redirect is refused. Nothing it returns is verified here.

- `timemarket.bot`: what a script checks before it acts, and what the examples share. `check_account(state, most_daily_limit_micros=, most_balance_micros=)`, `check_key(state, seed)`, `check_index(answer)` and `check_bitcoin(market, network)` raise `Refusal` with the reason; `allowance(state)` is what is left of the daily limit now; `AddressFile(path, network)` hands each receiving address out once and marks it in the file first; `Sender(api, account=, seed=, act=)` signs one action at a time through `wire.sign_action`, sends the same bytes again after a lost answer, and waits for the block (a dry run without `act`); `fill_made` and `order_made` find the row an action made; `micros`, `seconds`, `price_words` and `bitcoin_amount` write amounts as text. Every number these checks read is the API's word.

## Tests

```
cd clients/python
python -m unittest discover
```

The tests read the repository's vectors and need no network. They sign with both Ed25519 libraries when both are installed, and with the one that is otherwise. `tests/test_examples.py` runs each example through its `main` against the stand-in API, and runs every Python block and every script command of `docs/trading.md`, comparing what they print with what the guide shows.
