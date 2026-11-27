# Market header relay

A Time network with the market (`../../spec/market.md`) follows Bitcoin's header chain by itself: it checks the proof of work of every header and keeps the chain with the most. But it learns of Bitcoin only from kind 40 actions, which carry block headers, are unsigned and free, and can be sent by anyone. Nobody is paid to send them. **While nobody sends them, no fill is made, proven or expired** (`spec/market.md`, 10.4). This process sends them.

It asks Bitcoin nodes you run for the headers the chain does not hold yet and hands them in. It holds no key of any kind and signs nothing. Anyone can run one, and several can run side by side: a header the chain already holds is refused, and a refused action costs nothing.

## Running it

Node 26 and this repository's `client-v4/` and `web-v4/shared/verifier/` (the installed proof verifier) are all it needs. It uses no npm packages. It contacts the Bitcoin nodes of its config and the one Time endpoint of its config, and nothing else.

```sh
cp deploy/market-relay/config.example.json /etc/time-market-relay/config.json   # then edit it
node deploy/market-relay/start.mjs /etc/time-market-relay/config.json
```

| Setting | Meaning |
|---|---|
| `rpc_url` or `gateway` | How the Time chain is reached: exactly one of the two. `rpc_url` is the CometBFT RPC of a Time node, as `deploy/api` uses it: `https://`, or `http://` on this machine. `gateway` is the public `https://` origin of a wallet gateway, as `deploy/watch` uses it: for someone who runs a Bitcoin node and no Time node. See "What it trusts". |
| `trust` | The trust manifest, the same object the SDK's `createClient({trust})` takes. Install it from a source independent of the endpoint. |
| `bitcoin_nodes` | One to eight Bitcoin Core nodes, each `{name, url}` with `cookie_file`, or with `user` and `password_file` (or `password`). See "The Bitcoin nodes". |
| `data_directory` | Holds `checkpoint.json` (the light client's latest verified checkpoint) and `watch.lock`. One relay per directory. |
| `poll_seconds` | How often it looks. Default 10. |
| `max_actions_per_round` | The most kind 40 actions it sends in one round. Default 4, which is 1,024 headers. See "The pace". |
| `deep_reorg` | `"stop"` (the default) or `"relay"`. What to do with a branch that would halt the chain's header chain. See "A deep reorganisation". |
| `max_header_age_seconds` | The health answer warns when the newest header any node has is older. Default 3600. |
| `max_behind_seconds` | The health answer fails when the chain has lacked the nodes' best block for longer. Default 300. |
| `max_disagree_seconds` | The health answer warns when the nodes have had different best blocks for longer. Default 1800. |
| `bitcoin_timeout_seconds`, `time_timeout_seconds` | Each call to a Bitcoin node, and each request to the Time endpoint, gives up after this long. Defaults 15 and 30. |
| `host`, `port`, `hosts` | Where the health answer is served. Default `127.0.0.1:8950`. `hosts` lists extra `Host` header values it answers to, such as `relay.example:443` behind a proxy; any other name gets 421. |

A setting the relay does not know is refused, and so is a config that is not valid JSON; neither message quotes the file.

### The Bitcoin nodes

- **Run them yourself.** `url` is the node's RPC address: `http://` on this machine, or `https://`. Bitcoin Core's RPC has no encryption of its own, so a node on another machine is reached through a tunnel to this machine or through a TLS proxy.
- **The network must be the chain's.** The chain's genesis names the Bitcoin network it follows (`regtest` or `testnet3`), and the relay reads that with a proof. A node on another network is not used, and the health answer says so. **Bitcoin mainnet is closed in this version of the market**: on a Time network that follows mainnet the relay sends nothing.
- **Signing in.** Give `cookie_file` (the `.cookie` file Bitcoin Core writes in its data directory at every start), or `user` with `password_file` (a file that holds the password and nothing else). The relay reads the file at every call, so a restart of the node needs no restart of the relay.
  - A password file must be readable by its owner only (`chmod 600`). A cookie file may also be readable by its group, as Bitcoin Core's `rpccookieperms=group` makes it. A file that everyone can read is refused.
  - `password` in the config itself also works. The relay then refuses a config file that other users of the machine can read. Prefer a file.
  - The relay needs read calls only: `getblockchaininfo`, `getbestblockhash`, `getblockhash`, `getblockheader`. If your node has `rpcwhitelist`, allow those. It sends no other method, never a wallet call.
- **More than one.** With two nodes, one that is silent, behind or cut off from the network does not stop the relay: it goes on with the other, and the health answer names the one that fails. Each node's own name for itself (`name`) is all the log and the health answer ever show of it: never its address, its user name, its password or the path of a file.

### The health answer

`GET /health` on the port. It answers **200 when the relay does its work and 503 when it does not**, so a monitor needs no parsing. A stalled relay stops every purchase: alert on anything but 200.

The body is JSON:

- `status`:
  - `starting` (503): no round has finished yet.
  - `ok`: the chain holds the best block of every node that answers.
  - `catching_up`: headers are left to send; the next round follows at once.
  - `stalled` (503): no round has gone well for three poll intervals, at least a minute.
  - `chain_behind` (503): the chain has lacked the nodes' best block for longer than `max_behind_seconds`. The headers are sent and do not arrive in a block, or are refused.
  - `halted` (503): the chain's header chain is halted. See "A halted header chain".
  - `deep_reorganisation` (503): a node shows a branch the relay does not hand in. See "A deep reorganisation".
  - `refused_network` (503): the Time network follows Bitcoin mainnet.
  - `no_bitcoin_node`, `time_unreachable`: no node, or the Time endpoint, gave a usable answer in the last round. 503 once that has lasted a minute.
- `warnings`: `newest_bitcoin_header_is_old` (no node has a header younger than `max_header_age_seconds`: the nodes may all be cut off), `bitcoin_nodes_disagree`, `a_bitcoin_node_is_not_usable`, `a_bitcoin_node_is_still_downloading`, `every_bitcoin_node_is_behind_the_chain` (the chain holds more work than any node shows: the nodes are behind, and someone else relays), `headers_taken_but_in_no_block` (the endpoint took an action and no block held it within a minute), `headers_refused`.
- `header_chain`: the Bitcoin network, the chain's best height and best block, how many branches it holds, and whether it is halted, as the last proof showed them.
- `bitcoin_nodes`: for each node its name, whether it is usable, its height and best block, and what is wrong with it in a few words.
- `blocks_behind`, `behind_seconds`, `nodes_disagree_seconds`, `newest_bitcoin_header_age_seconds`, `seconds_since_good_round`.
- `headers_handed_in`, `last_handed_in_at`, `actions_in_grace_window`.

Nothing else is served, and nothing can be written. The answer holds no address, no password and no path.

## What it does each round

1. It reads, with a proof, the row `bitcoin/meta` of the chain: the best Bitcoin block the chain holds, the ends of every branch it holds, the batch size it accepts, and whether its header chain is halted.
2. It asks every Bitcoin node where it stands.
3. For each node whose best block is not the end of a branch the chain holds, it finds where the node's best chain leaves what the chain holds, and hands in the headers from there.

**Every valid branch a node shows is handed in.** The relay does not choose between branches. The chain checks the work of each header and keeps the branch with the most; a branch with less is kept as a branch. Two nodes on two branches give the chain both.

### Reorganisations

Only the ends of the branches are proven, not every header. So the relay asks the node about the chain's best block:

- **The node has it on its best chain.** The headers above it are new, and are sent.
- **The node has it on a branch it has left.** That is a reorganisation the node saw. The relay walks the node back, block by block, to the last block the two share, and sends the new branch from there. The log has one line with the height of the fork and its depth.
- **The node does not know it.** Someone else told the chain of that block, and this node never saw it. The relay offers the node's last header, then its last two, four, eight and so on. The chain takes a batch whose first header has a parent it holds and refuses the others. A refused action is in no block and costs nothing.

### A deep reorganisation

A branch with more work that leaves the chain's best chain more than 144 blocks below its tip **halts the chain's header chain for good**: this version has no action that starts it again (`spec/market.md`, 10.5). That is the chain's own rule, and it holds whoever sends the headers.

The relay does not pull that lever on the word of one node. With `deep_reorg: "stop"`:

- it does not hand such a branch in;
- it logs one error line (`A BITCOIN NODE SHOWS A BRANCH THAT LEAVES THE CHAIN'S BEST CHAIN DEEPER THAN THE CHAIN FOLLOWS`), with the node's name, the height of the fork, and the two heights;
- `/health` answers 503 with `status: "deep_reorganisation"` and the same numbers;
- it goes on serving the other nodes, and does not try the branch again every round.

Then a person looks. **A node pointed at the wrong chain looks exactly the same**: a regtest node that was started on an empty data directory and mined past the chain's height is a "deep reorganisation" from the genesis block. Check `getblockchaininfo` on the node, and compare the block at the fork's height with another node.

- If the node is wrong, fix or remove it. The relay sees the change at its next round.
- If Bitcoin really reorganised that deep, the old branch is no longer Bitcoin. While the chain still follows it, payments on it can still be proven although they no longer exist. Set `deep_reorg` to `"relay"` and start the relay again: it hands the branch in, the chain halts, and what `spec/market.md`, 10.5 says then applies. Anyone else can send the same headers at any time: holding them back protects nothing for long.

The relay also takes a branch for one that would halt when it forks below the chain's last credited receipt (a network that has the bitcoin auction beside the market halts there too).

### A halted header chain

Once the row says the header chain is halted, no header is accepted and nothing a relay sends can change that. The relay sends nothing more, logs one error line (`THE BITCOIN HEADER CHAIN OF THE TIME CHAIN IS HALTED`) with the reason the chain recorded, repeats it once an hour, and answers 503 with `status: "halted"`. It does not loop. Orders can still be cancelled, and fills released or settled; nothing else of the market moves until a software release.

### The pace

After every kind 40 action that raises the chain's best height, the chain's clock of heights (`spec/market.md`, 5.4) gains one entry, and it keeps 256. A fill can end without payment only `GRACE` (30 minutes; 20 seconds on a laboratory network) after the chain learnt the fill's last height, and "when the chain learnt it" is read from that clock. So what matters is the number of actions, not of headers.

- **Many headers in one action are harmless.** They cost one entry and tell the clock the truth: the chain learnt those heights at that moment. A fill that started behind Bitcoin loses its time in heights when the relay catches up; the rules give such a fill a floor in time for exactly that case (5.5, point 4). Holding headers back would help nobody: a proof needs the chain to hold the payment's block and its confirmations.
- **Many small actions are not.** More than 256 within `GRACE` push out every older entry. The clock then no longer knows when it learnt the last height of an open fill and reads the oldest entry it has left, which is younger than `GRACE`. No fill can end until the stream stops and `GRACE` has passed again, and sellers' seconds stay locked meanwhile.

So the relay:

- fills every action to the chain's batch size (256 headers);
- **while a fill is open, sends at most 64 actions in any window of `GRACE`**: a quarter of the clock. No entry younger than three times `GRACE` is ever pushed out by this relay. That is still 16,384 headers per `GRACE`;
- while no fill is open, where nothing reads the clock, is bound only by `max_actions_per_round`.

**A long gap** (a first start, or a relay that was down) is caught up at that pace: 4 actions a round, a round a second while headers are left. The relay does not wait for each batch to be in a block: the node that took a batch judges the next one on top of it. Whether a fill is open is read with the same proof as the header chain.

A header chain that starts at the genesis block of testnet3 has more than four million headers to catch up: more than an hour at the default pace while no fill is open, and as long as the Bitcoin node takes to give them. **While it catches up the chain's header chain is not fresh, and no fill can be made.**

## What it trusts

- **The trust manifest, and nothing else, for what the chain holds.** The row `bitcoin/meta` is read with a proof through the SDK's verifying client: the light client checks each answer against the validator set, starting from the trust anchor, with the verifier installed with this code. The endpoint cannot make the relay believe in a best block, a branch or a halt the chain does not hold.
- **The Time endpoint can withhold.** It can answer nothing, answer with an older (genuine) state, or take an action and never pass it on. The relay then says `time_unreachable`, or `headers_taken_but_in_no_block` and after `max_behind_seconds` `chain_behind`. It cannot make the relay send a wrong header: the relay sends what a Bitcoin node gave.
- **What the endpoint says when it refuses an action is its word.** The relay uses the node's reason ("unknown parent", "no new headers", "paused") to decide where to look next. A lying endpoint can make the relay stop offering headers for a while, which it can do anyway by dropping them. It cannot make the chain accept anything.
- **A Bitcoin node is trusted for nothing that decides anything.** The chain checks the proof of work, the difficulty and the links of every header. A node that lies or lags can:
  - withhold or lag: the relay uses another node, and the health answer says which one is silent or how old the newest header is;
  - show a losing branch or invented headers: the chain refuses headers without the work and keeps a valid branch with less work as a branch. A refused action costs nothing;
  - show a valid branch with more work that leaves the chain too deep: see "A deep reorganisation". That is the one case where the relay does not act by itself.
- **The relay holds no secret of the chain.** It has no key. A kind 40 action carries no account, no nonce and an empty signature. What it does hold is the password of your Bitcoin nodes: it goes to that node only, in the request's header, and into no log line, no error and no health answer.

## Limits

- **It is one process.** If its host is down, nobody relays. Run a second relay somewhere else, with other Bitcoin nodes: two relays do not disturb each other. Watch `/health` from somewhere else.
- **It needs a node that knows the fork.** When no configured node has ever seen the chain's best block, the relay finds the fork by offering headers, at most 144 blocks back. A branch that left earlier is reported as a deep reorganisation, whatever its work.
- **It reads two calls for every header** (`getblockhash`, `getblockheader`), eight at a time. A first catch-up over millions of headers takes as long as the node takes to answer them.
- **It does not judge headers.** It hands in what a node shows and lets the chain decide. On regtest and testnet3 anyone makes blocks at no cost, and whoever does can also send their headers without this relay: these networks protect nothing (`spec/market.md`, section 2).
- **What has run, and what has not.** The relay's tests (`client-v4/market-relay.test.mjs`) run it against a Bitcoin node and a Time chain that exist in the test only: new blocks, a gap of 1,500 headers, a reorganisation, a node that never saw the chain's branch, two nodes on two branches, a branch that would halt, a halted chain, nodes that are silent or lie, and the health answer. The client of Bitcoin Core's RPC is also tested against a real Bitcoin Core 32.1 in regtest (`client-v4/market-services-regtest.test.mjs`). The 103 headers of one such run were taken by the engine's own header code, in batches as the relay hands them in (`bitcoin-bridge/tests/prover.rs`, run by hand on 26 November 2026; without its scenario file that test checks nothing). **The relay has not run against a Time node**: no kind 40 action of this relay has been judged at a node's admission or been in a block, and the engine's words for its refusals, which the relay reads, are taken from its source.
