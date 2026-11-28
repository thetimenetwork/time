# Test bitcoin (test networks only)

**Play money.** This service gives away bitcoin of a private regtest chain, which is worth nothing by construction: anyone can make such a chain, and no other Bitcoin software can reach this one. It refuses a Bitcoin node whose chain is not `regtest`, and sends such a node nothing but the question.

A Time test network with the market of seconds against bitcoin (`../../spec/market.md`, `../../docs/trading.md`) has to follow a Bitcoin chain. Bitcoin mainnet is closed in this version, so the public test network follows a private regtest chain on its own services machine. Nobody outside can reach that chain: a tester could neither get its coins nor pay with them. This service is the way in:

- it **runs the Bitcoin node** (Bitcoin Core, in regtest, with no peer-to-peer side at all), or uses one that already runs;
- it **mines a block every `block_seconds`**, never on request, so that the page can say when the next one comes;
- it **makes receiving addresses** for testers, in the node's own wallet, and shows what arrives at them;
- it **pays any address of the test chain** on request, within limits;
- it **keeps an archive** of every block and of the wallet's keys in local files, and hands a node the blocks it lacks before anything is mined, so that the chain is the same chain after a lost machine or a killed node.

The header relay and the prover (`../market-relay/`, `../market-prover/`) read the same node over its RPC, with the node's cookie file.

## Running it

Node 26, Bitcoin Core (32.1 is what it was tried with), and this repository's `client-v4/`, `deploy/watch/start.mjs` (its lock and log code, which loads `web-v4/shared/verifier/`), `web-v4/test-bitcoin/` (the page) and `web-v4/shared/` (the address codec and the menu of networks the page carries). It uses no npm packages. It is not part of the gateway distribution.

```sh
cp deploy/test-bitcoin/config.example.json /etc/time-test-bitcoin/config.json   # then edit it
node deploy/test-bitcoin/start.mjs /etc/time-test-bitcoin/config.json
```

When the node answers, the chain and the wallet are in place and the port listens, it logs one line whose `message` is `test bitcoin started`. A new chain begins with 101 blocks at once, so that the first coins can be spent. A chain whose newest block is older than a pace (the service was down, or the chain came from the archive) gets its next block before that line, so that the health answer is true from the first moment. How long a start takes is Bitcoin Core's time for each block, which with its wallet loaded was 70 to 100 milliseconds on the Windows machine this was tried on: 8 to 17 seconds for a new chain, and about a minute and a half for every thousand blocks handed over from an archive (5,107 blocks took 499 seconds). **A chain of a month, 130,000 blocks at the default pace, would take hours to hand over at that speed.** It has not been timed on Linux, where the wallet's write for each block is likely cheaper. It stops on SIGTERM or SIGINT: the round in flight is finished, the node is told to stop (the RPC `stop`) and is killed if it has not ended after 45 seconds.

| Setting | Meaning |
|---|---|
| `bitcoind_program`, `bitcoin_data_directory` | The service runs the node: the absolute path of `bitcoind`, and the node's data directory (made if missing, mode 700). The node is started with `-regtest -server=1 -datadir=… -listen=0 -listenonion=0 -discover=0 -dnsseed=0 -fixedseeds=0 -connect=0 -networkactive=0 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=… -fallbackfee=0.0002 -keypool=16 -printtoconsole=0`: no listener but its RPC on the loopback address, no outgoing connection. It writes nothing outside its data directory. Its cookie is `<bitcoin_data_directory>/regtest/.cookie`. |
| `bitcoin_rpc_port` | The RPC port of the node the service runs. Default 18443. |
| `bitcoin_node` | Instead of the two settings above: `{ "url": "http://127.0.0.1:18443/", "cookie_file": "/…/regtest/.cookie" }`, a regtest node on this machine that someone else runs. The service then neither starts nor stops it. |
| `wallet` | The name of the one wallet. Default `test`. Made if the node has none of that name (see "The wallet"). |
| `data_directory` | Optional. The service's own folder: it holds the lock (`watch.lock`) that keeps a second service off the same node, and nothing else. Without it the lock is in `bitcoin_data_directory`; a service on a node someone else runs, without a `data_directory`, has no lock. |
| `archive_directory` | Optional, and **what makes the chain survive**: see "The archive". A directory of its own, not inside the node's and not around it. |
| `block_seconds` | The pace: one block every this many seconds. Default 20, from 5 to 600. |
| `max_payment_sats` | The most one payment sends. Default `"5000000"`. |
| `per_caller_per_day_sats` | The most one caller is paid in 24 hours. Default `"100000000"`. |
| `total_per_day_sats` | The most all callers together are paid in 24 hours. Default `"20000000000"`. |
| `payments_per_caller_per_hour` | Default 30. |
| `total_payments_per_day` | The most payments of all callers in 24 hours, whatever their amounts. Default 10000. It bounds how fast the chain, the wallet and the service's memory grow. |
| `addresses_per_caller_per_day` | New receiving addresses one caller gets in 24 hours. Default 20. |
| `total_addresses_per_day` | New receiving addresses of all callers in 24 hours. Default 5000. |
| `base_path` | The path everything is served under. Default `/bitcoin`: a proxy forwards `https://<name>/bitcoin/…` to the service unchanged. `""` for none. |
| `host`, `port` | Default `127.0.0.1:8960`. Put a TLS proxy in front for the public. |
| `hosts` | The names the service is reached under, as clients send them in `Host`. Any other name gets 421. Its own `127.0.0.1:<port>`, `localhost:<port>` and `[::1]:<port>` are always answered. |
| `origins` | The origins whose pages may call the service from a browser, each whole: scheme, name, port. **Behind a proxy, list the page's own public origin here** (`https://faucet.example`): the process cannot know under which scheme it is reached. When `serve_page` is on and `hosts` is set, the service does not start unless an origin under one of those names is listed. A request without an `Origin` header (a program) is not judged by it. There is no wildcard. |
| `rate_limit` | `{per_second, burst}` per caller, default 5 and 20. A GET takes 1, a POST 10. |
| `trusted_proxies` | IP addresses of your own reverse proxies. Only for a request from one of them is the caller taken from `X-Forwarded-For`, read from the right past entries that are trusted proxies too. **Behind a proxy you must set this,** or every caller is the proxy and shares one limit. |
| `rpc_timeout_seconds` | Each call to the node gives up after this long (mining 101 blocks, importing a wallet and handing over a block have longer waits of their own). Default 15. |
| `serve_page` | Default true: the page of `web-v4/test-bitcoin/` is served at `<base_path>/`. |

Amounts are whole satoshis as decimal strings. A setting the service does not know is refused.

**Permissions.** The service and the node it starts run as one Unix user, which needs to write `bitcoin_data_directory`, `data_directory` and `archive_directory`, to read the files of this repository, and to execute `bitcoind_program`. It writes nowhere else, and neither does the node (its pid file, its log `debug.log` and its cookie are inside its data directory). The header relay and the prover must be able to read `<bitcoin_data_directory>/regtest/.cookie`, which Bitcoin Core writes for its own user only at every start: run them as the same user.

**A caller** is an IPv4 address or an IPv6 /64. "In 24 hours" and "in an hour" are counted back from the request on this machine's clock, in memory: **a restart of the service forgets the counts**, and the day's amounts can then be had once more.

## Routes

All under `base_path` (`/bitcoin` below).

- `GET /bitcoin/v1/health`: **200 when all is well, 503 when not**, with a `status` word: `ok`; `starting` (the chain and the wallet are not in place yet); `node_unreachable`, `node_failing` (the node did not answer the last round, or answered what it should not); `not_regtest` (the node on the port is on another chain: nothing is sent to it); `no_new_block` (the newest block is older than three paces); `archive_failing` (a file of the archive could not be written; the chain goes on); `wallet_cannot_pay` (the wallet holds less than one largest payment). The body also holds `height`, `seconds_since_block`, `block_seconds`, `balance_sats`, `archive` (`written`, `failing` or `none`) and `node_restarts`. It is what the last round found, a pace old at most: the node is not asked for each request.
- `GET /bitcoin/v1/status`: `network` (`regtest`), `height`, `best_hash`, `block_seconds`, `seconds_to_next_block`, `max_payment_sats`, `per_caller_per_day_sats`, `left_today_for_caller_sats`, `balance_sats`, `paying`, `addresses_per_caller_per_day`.
- `POST /bitcoin/v1/addresses` with `{"form": "p2wpkh"}` or `{"form": "p2tr"}` (or no body, for `p2wpkh`): a new receiving address of the wallet, `{address, form}`.
- `GET /bitcoin/v1/addresses/{address}`: for an address this wallet made for a tester, and 404 for any other (an address of someone else, the wallet's change, its mining address): `{address, form, received_sats, unconfirmed_sats, payments: [{txid, sats, height, confirmations}], height}`. `received_sats` counts what is in blocks of the best chain; `unconfirmed_sats` what this run of the service sent and no block holds yet (`height` null). The payments are the newest 50, newest first; the two sums count all.
- `POST /bitcoin/v1/payments` with `{"address": "<a regtest address>", "sats": "<decimal string>"}`: pays the address from the wallet. `{txid, address, sats, seconds_to_next_block}`. **The address gets exactly `sats`**: the wallet pays the fee on top, because the market counts what the output holds. The five forms of address the market takes are paid (`p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2tr`). **The payment is a small transaction** (see "The wallet"): a proof of payment carries the whole transaction.
- `GET /bitcoin/v1/payments/{txid}`: `{txid, confirmations, height, seconds_to_next_block}` for a transaction of this chain that is not a coinbase (every such transaction is a payment the wallet made), and for a payment of this run that is in no block yet. 404 for anything else. The service keeps the newest 100,000.
- `GET /bitcoin/` and the files it names (`test-bitcoin/app.mjs`, `test-bitcoin/styles.css`, `shared/bitcoin-address.mjs`, `shared/network-menu.js`, `shared/network-menu.css`): the page. Fixed files read at start; no path of a request reaches the file system. `GET /bitcoin/?address=<address>&sats=<satoshis>` is the page too (either, or both): the page puts them into its pay form and pays nothing by itself. Every other route takes no query.

```sh
curl -s http://127.0.0.1:8960/bitcoin/v1/status
curl -s -X POST http://127.0.0.1:8960/bitcoin/v1/addresses -H 'Content-Type: application/json' -d '{"form":"p2wpkh"}'
curl -s -X POST http://127.0.0.1:8960/bitcoin/v1/payments -H 'Content-Type: application/json' -d '{"address":"bcrt1q…","sats":"10000"}'
```

Refusals are JSON, `{"error": {"code", "message"}}`, with a stable `code`:

| Code | Status | Meaning |
|---|---|---|
| `invalid_address` | 400 | Not an address of the test chain: the message says why (an address of Bitcoin mainnet or testnet, a wrong checksum, a form the market does not take). The codec is the market's own (`web-v4/shared/bitcoin-address.mjs`). Legacy addresses of testnet3 and of regtest are the same texts and are taken. |
| `invalid_amount`, `amount_too_large`, `amount_too_small` | 400 | Not a whole number of satoshis from 1 as a decimal string; above `max_payment_sats`; or below what Bitcoin nodes pass on to that form of address (546 satoshis to `p2pkh`, 540 to `p2sh`, 294 to `p2wpkh`, 330 to `p2wsh` and `p2tr`). |
| `caller_limit`, `daily_total` | 429 | A limit of one caller, or of all callers together, is reached. `Retry-After` says when the oldest count leaves its window. |
| `rate_limited` | 429 | Too many requests from this caller. |
| `wallet_empty` | 503 | The wallet does not hold the amount and a fee. |
| `wallet_busy` | 503 | The wallet has made as many payments as fit before the next block (Bitcoin Core lets a coin be spent on, unconfirmed, 25 times). `Retry-After` is the time to the next block. |
| `node_unavailable`, `busy`, `starting` | 503 | The node did not answer, 32 requests already wait for the wallet, or the service is starting. **After a payment that got no answer, the message says that it is not known whether it was sent**; it counts against the limits. |
| `node_refused` | 502 | The node refused the payment for another reason. Its own words are in the log only. |
| `unknown_address`, `not_found` | 404 | Not an address this service made; no record of that transaction. |
| `invalid_body`, `invalid_json`, `invalid_txid` | 400 | The body is not the one JSON object the route takes, each field once, as a plain string; the id is not 64 hexadecimal characters. |
| `unsupported_media_type`, `body_too_large`, `body_too_slow` | 415, 413, 408 | The body is not sent as `application/json`, is larger than 1024 bytes, or did not arrive within 5 seconds. |
| `invalid_url`, `url_too_long`, `invalid_request` | 400, 414, 400 | The address is not a plain path, is longer than 512 characters, or the request names its host twice. |
| `unknown_route`, `method_not_allowed` | 404, 405 | No such route, or not with this method. |
| `unknown_host`, `origin_not_allowed` | 421, 403 | The request names a host that is not in `hosts`; or it comes from a page whose origin is not in `origins`, or is an image, a script or a frame in a page of another site. |
| `internal` | 500 | The request could not be answered; the log has the reason. |

## The wallet

One wallet of the node does everything: the blocks are mined to it, the payments leave it, the testers' addresses are its own. So **a tester cannot spend what arrives at an address made here**: the key is the node's. The page says so. That is enough for a seller who tries the market, who needs an address to name in an order and a way to see the buyer's payment arrive. What arrives at such an address is the wallet's again, and is paid out to the next caller.

**How much there is.** Regtest halves the reward of a block every 150 blocks: 50 bitcoin at first, nothing after block 4,950, which at a block every 20 seconds is the second day. The wallet ends with a little under 15,000 bitcoin in all. From then on a block carries only the fees of its payments, and the service goes on as before: it mines the same blocks, and pays from what it holds. What is paid to addresses of the wallet comes back to it; what is paid to addresses of others is gone. At the default `total_per_day_sats` (200 bitcoin) the whole sum lasts 75 days even if every satoshi went to addresses of others. When the wallet holds less than one `max_payment_sats`, `/v1/health` answers 503 with `wallet_cannot_pay`.

The first reward can be spent 100 blocks after it was mined, so a new chain begins with 101 blocks at once. After that there is one more spendable reward with every block. Bitcoin Core lets one coin be spent on 25 times before a block confirms it: in the first minutes of a new chain, the 26th payment between two blocks is answered `wallet_busy`.

**A payment is kept small.** The chain's proof of a payment (kind 54) carries the payment's whole transaction, and its sender pays a fee for every 256 bytes of it; a prover with a ceiling on that fee would leave a large payment unproven. Left to itself, Bitcoin Core's wallet gathers its small coins into a payment whenever the fee rate is at or below the rate it thinks cheap (10 satoshis a virtual byte), and a regtest wallet has thousands of small coins once the rewards have shrunk: on a chain of 3,400 blocks, Bitcoin Core 32.1 paid 0.05 bitcoin with 62 coins, in a transaction of 5,668 virtual bytes, at a rate of 10. So the service pays with the RPC `send` at **31 satoshis a virtual byte** (above three times that rate the wallet looks for the lightest coins: the same payment took one coin and 164 virtual bytes) and with **a ceiling of 4,000 weight units** (`max_tx_weight`: at most 1,000 bytes without witness data), which the wallet holds to whatever the rate. The fee is the miner's, and the miner is the service. The blocks are mined to an address of the form `p2sh` (it begins with 2), which no tester is given, and whose coins are spent with few bytes outside the witness data.

## The archive

A machine can be lost. A Bitcoin node that begins a new regtest chain from zero has other blocks than the old one, which the Time chain, which follows the header chain, sees as a reorganisation from the first block: deep enough to halt its header chain for good (`../../spec/market.md`, 10.5). And a Bitcoin node that is killed (not stopped) forgets the blocks it had not yet written to its own index, which Bitcoin Core does from time to time and when it is stopped, not with every block. **In the test of 27 November 2026 a killed Bitcoin Core 32.1 came back with none of its 103 blocks.** Mining on from there would be the same deep reorganisation.

So, with `archive_directory`, the service keeps in local files:

```
blocks-00000001.txt   the blocks at heights 1 to 500, one on each line, in lowercase hexadecimal
blocks-00000501.txt   heights 501 to 1,000; and so on: only the last file holds fewer than 500 lines
wallet.json           the wallet's descriptors WITH THEIR PRIVATE KEYS, file mode 600
```

- A file is written whole under a temporary name (`<name>.<pid>.tmp`), synced and renamed into place. The last block file is written again once for each new block. `wallet.json` is written again when a descriptor's next index has moved (an address was made, or a payment left change), which is checked once for each block.
- **Before every block it mines, and at its start**, the service compares the node with what it holds. A node that has fewer blocks, all of them the archive's, is handed the blocks it lacks, in order (`submitblock`), and only then is the next block mined on top. A node without the wallet gets a blank wallet with the descriptors of `wallet.json`, before the first block is handed over, so that the wallet finds its coins as the blocks come. The log says both.
- **The same blocks give the same hashes.** Whoever followed the chain sees no reorganisation, as long as the archive held every block they had seen.
- A node that holds **another block** at some height (a reorganisation, which the service never makes itself) is believed: the log says `A REORGANISATION OF THE REGTEST CHAIN` at error level, and the files are rewritten from the first block that differs. At a start, a node that shares no block with a non-empty archive is refused instead, and nothing is overwritten: the directory belongs to another chain.
- A file that cannot be written does not stop the chain: the blocks stay in memory and are written when the directory can be written again, the log says `THE ARCHIVE COULD NOT BE WRITTEN`, and `/v1/health` answers 503 with `archive_failing`. A service does not *start* on an archive directory it cannot write.
- The archive is read whole at every start (each block is held to its parent). A file that is missing in between, a file that is not the last and not full, or a line that is not a block of the chain stops the start with the file's name.

Copying the directory to another place, and back to an empty directory before a start on a new machine, is someone else's work: the service reads and writes local files only. **What that copy must hold to: copy `wallet.json` again whenever it changes, and the block files as they grow.** A copy that lacks the newest blocks gives a chain that ends earlier; the blocks mined after the restore then stand beside the ones the Time chain has seen, a reorganisation as deep as the copy was behind. A `wallet.json` that is older than the newest addresses still gives a wallet that knows them, up to 1,000 addresses past the last one the file names.

Without `archive_directory` the service says so at every start, at warning level, and none of the above is done.

**`wallet.json` holds private keys.** They are keys to play money. Keep the file where the service's user alone reads it all the same: with them, anyone who can reach the node's RPC could not do more than they already can, but a habit of leaving key files readable is not one to form.

## What it trusts, and its limits

- **The node, for everything.** This is a test tool beside its own node on its own machine: it believes the blocks, the balances and the addresses the node gives. What it checks is that answers are what was asked for: a block is held to the hash asked and to its parent, an address the node makes is read by the market's codec, and a payment is read back from the bytes of its transaction (an output with the script and exactly the amount; a payment that differs is said in the log in capitals).
- **Only regtest.** The first call to a node, and the first after any call that got no answer, is `getblockchaininfo`; unless it says `regtest`, nothing else is sent. A node can lie about its chain; a node on mainnet does not.
- **Sixteen RPC methods and no other**: `getblockchaininfo`, `getblockhash`, `getblock`, `generatetoaddress`, `submitblock`, `listwallets`, `loadwallet`, `createwallet`, `stop`, `getnewaddress`, `getaddressinfo`, `getbalances`, `send`, `gettransaction`, `listdescriptors`, `importdescriptors` (`METHODS` in `client-v4/test-bitcoin.mjs`). What a caller writes reaches the node in two places: an address that the codec accepted as an address of the test chain (`send`, `getaddressinfo`), and nothing else: an amount is written by the service from a whole number, a transaction id is looked up in the service's own memory.
- **Amounts are never binary fractions.** Bitcoin Core writes amounts as decimal numbers of bitcoin; the service keeps the digits as text and counts in whole satoshis.
- **Addresses are cheap.** The limits per caller slow one person down; someone with many addresses is bound by `total_per_day_sats`, `total_payments_per_day` and `total_addresses_per_day` only, and can use them up for everybody. Nothing of value is lost by that.
- **In memory, lost at a restart:** the counts of the limits; which payments are in no block yet (a payment that was in no block when the service stopped is shown again when a block holds it). Everything else is read again from the archive or the node. A start reads every block: from the node, 5,000 blocks took 7.5 seconds where this was tried.
- **Memory grows with the chain:** about 80 bytes for each block, and about 250 bytes for each output that pays a SegWit or Taproot address (the payment and its change). At 10,000 payments a day for a month that is about 150 MB; at a tester's pace it is nothing.
- **One process.** The lock is the security watch's (`../watch/README.md`): a second service on the same directory refuses to start. A second service on the same port stops at the port, before it touches a node.
- **Logs** are JSON lines on stdout: heights, counts, amounts, transaction ids, error codes, and the node's refusals with everything but plain characters removed. Never a caller's address, never the cookie, never a key.
- **What has run, and what has not.** The tests (`client-v4/test-bitcoin.test.mjs`) run the service against a Bitcoin node that exists in the test only, with a stand-in for the wallet. One test (`client-v4/test-bitcoin-regtest.test.mjs`) runs it against a real Bitcoin Core 32.1, started by the service from its start script, on Windows, on 27 November 2026: a new chain, addresses of both forms, payments to all five forms and the node's own refusal a satoshi below each smallest amount, a node killed while the service ran (it came back empty, was handed its 103 blocks from the archive and mined on from the same block), and then a second service on an empty node directory with the same archive, which stood on the same block with the same coins and showed the same payments. By hand on the same day, with no test kept of it: 5,000 blocks were mined on the service's node at once, to pass block 4,950, after which blocks carry no reward. The service read them in one round (7.7 seconds), made three payments (each a transaction of 245 bytes; the block that held them was 985 bytes), saw them confirmed in block 5,103, and answered `ok`; a second service on an empty node directory was then handed the 5,107 blocks from the archive (499 seconds) and stood on the same block with the same coins and the same payments, paid, and mined on. The page was opened in Chrome against the service over the stand-in node: an address made, a `bitcoin:` link pasted, a payment followed to six confirmations.

**It has not run on Linux, under systemd, behind a proxy, next to the header relay and the prover, or for longer than a quarter of an hour.** No proof of a payment made by this service has been handed to a Time chain. No archive of more than 5,107 blocks has been handed over, and no copy of an archive to another place and back has been made. The limits have not been seen to end a day on a real clock. The page has not been opened on a phone, in another browser than Chrome, or by a tester.
