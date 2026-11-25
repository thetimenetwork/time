# Time faucet (test networks only)

**Never run this on a network whose time has value.** A faucet gives money away to anyone who asks. On a test network that is its job. On any other network it is a hole in an account.

Nobody holds any time when a network starts: all new time goes to validators and the people who stake with them. A developer on a test network therefore needs someone to send the first seconds, and someone to sponsor the registration of a first account. This process is that someone. It gives a fixed amount of test time per request, within limits, from an account of its own.

It refuses to start unless:

- the config states `"test_network": true`. The example config does not: it holds a placeholder there, which you replace by `true` yourself, for this network;
- the config names the `network_id` it serves, and that id is the one of the trust manifest;
- the state it reads from the node, with a proof checked against the manifest, is the state of that network;
- the chain id is one of a test network. The faucet's code holds the list (`TEST_CHAINS` in `client-v4/faucet.mjs`; today the ids that begin with `time-devnet-v4-`, the only ones the installed verifier accepts). No config setting adds to it.

None of this can tell whether a network's time has value: no chain knows that. The statement in the config is yours. The checks make sure the faucet serves the one network you made it for and no other.

## The faucet's account and key

The service holds one key, and that key must be able to do as little as possible. The account security rules of the chain (`v5/README.md`, "Account security") provide for that: a **spend key** pays at once only within a daily limit set on the chain.

Set the account up once, on a machine that is not the faucet's:

1. **Register an account** for the faucet and have a validator operator send it test time. Keep its balance near a few days of `limits.total_per_day_micros`, and refill it: what is not there cannot be lost.
2. **Make five keys:** one spend key (for the service), one sign-in key, and three recovery keys.
3. **Adopt the rules** with the account's first key (action kind 70, `payloads.secure` in `client-v4/account-security.mjs`): the keys with their roles, and a policy with
   - `daily_limit_micros`: what the faucet may give in a day. `limits.total_per_day_micros` of the config already holds the fees and the sponsored registrations, so the same number is right, or a little more;
   - `threshold`: 2, so that no key decides alone;
   - `delay_seconds` and `freeze_seconds`: a day or more. `delay_seconds` is the time you have to notice a stolen key (see below).
4. **Keep the recovery keys offline,** in different places. They never touch the faucet's machine.
5. **Give the service the spend key only:** a file with one line, the 32-byte Ed25519 seed as 64 lower-case hexadecimal characters. `chmod 600` it, owned by the user the faucet runs as. Put its path in `key_file`. Use this key for nothing else: the faucet counts on being the only signer of the account.
6. **Have the account watched.** Run the security watch (`deploy/watch/`) with the faucet's account in its subscriptions. Alert on `GET /v1/faucet/health` answering anything but 200, and on the warning `key_used_elsewhere` in its body (see "Routes"). A faucet that has given its total for 24 hours still answers 200: that is its work done, not a fault, and with the daily limit of step 3 the limit on the chain is then nearly used as well. That changes when the account's nonce moves without the faucet (see "What the faucet does when its key is used elsewhere").

### What a stolen faucet key can do

The daily limit bounds what leaves **at once**. It does not bound everything:

- **At once:** the daily limit, and at most twice the daily limit in any 24 hours (the allowance refills evenly).
- **After `delay_seconds`: the whole balance.** A spend key can ask for a payment of any amount (kind 75). It waits `delay_seconds` in the open and then leaves the account, outside the daily limit. Any spend or recovery key cancels it while it waits, and a freeze drops it. **The true bound of a stolen key is therefore the whole balance, unless the payment is cancelled or the account frozen within `delay_seconds`.** The same goes for a raise of the daily limit.
- **Stop the faucet:** set the daily limit to zero, at once (only a root operation with two proofs raises it again), or freeze the account again and again (a fee each time).
- **Use up nonces.** Every action the thief signs takes the nonce the faucet's next grant was signed for. Those grants end `superseded`: counted, and not paid.
- **Sign in as the faucet account.** A spend key adds and removes sign-in keys, so the thief can sign in on websites as the faucet account and sign you out. Each such change is an action of the account too, and voids the grants in flight like any other.
- **Burn fees:** start and cancel waiting payments, up to about twice the daily limit in fees a day.
- **With one recovery key as well:** everything, at once. The spend key and one recovery key are the two proofs a root operation needs. That is why the recovery keys stay offline and apart.

### What the faucet does when its key is used elsewhere

The faucet never asks for a waiting payment or a raise of the limit. When it sees one waiting on its account, somebody else holds its key, and it

- **stops giving** (`faucet_unavailable`), for as long as the item waits;
- **says so** at error level in the log, and in `/v1/faucet/health` (`payment_above_limit_waiting`, `limit_raise_waiting`; for a day afterwards the warning `key_used_elsewhere`);
- **freezes its own account** (kind 72), unless `freeze_on_misuse` is false. A freeze drops every waiting payment and raise at once, and for `freeze_seconds` no spend key lowers the balance: the thief gets neither the waiting payment nor the daily limit. One signature per incident, recorded before it is sent; the freeze names the count of freezes and the version of the account's settings, so the chain takes it once. The same bytes are sent again every minute while an item waits and the account is not frozen. Only a freeze that expired without getting into a block is replaced by a new one (it is dated an hour past the moment the last item is due, at the earliest: see "Waits that survive a stop" below);
- **cancels the item** (kind 76), unless `cancel_waiting` is false. One signature per waiting item, recorded before it is sent; the same bytes again once a minute for as long as the item waits; one cancellation on its way at a time; at most 24 items a day. A refusal of the node is not an end: the thief, who holds the same key, can keep a cancellation out for a moment with one of his own that waits, and the faucet's is sent again.

Neither takes a nonce, each costs one fee, and the fee is charged only when a block takes the action.

**A payment within the limit leaves nothing waiting,** so none of the above happens for it. What it does leave is the account's nonce: every payment a spend key makes within the limit carries the account's next nonce, and so does everything else that is charged to the daily limit. At every read of its own (the pace is below; the reads that requests cause do not count, so nobody who sends requests can put it off) the faucet compares the proven nonce with the highest nonce it has signed itself. A nonce above that was signed by someone else (or the account's keys were replaced, which uses a nonce as well), and the faucet

- **says so** at error level in the log ("the chain shows a nonce of the faucet account used that the faucet did not sign"), once per sighting, and with the warning `key_used_elsewhere` and its time (`key_used_elsewhere_at`) in `/v1/faucet/health` for a day;
- **counts a used-up limit on the chain as a fault again** for that day, also while its own total is given (see "Routes"): the answer is then 503.

It does not freeze the account for it and goes on giving: one payment within the limit is over when it is seen, and the daily limit is what bounds the next. The count starts at the nonce the faucet finds when it first reads the account; what the account did before (its funding, the adoption of the rules) is not said. A foreign action that takes a nonce the faucet had signed for a grant is not seen this way; that grant ends as `superseded`, with its own line in the log.

**How fast.** The faucet reads its account every 10 seconds when nothing else is going on, and every 5 seconds while something waits on the account or a freeze or cancellation of its own is on its way. A waiting item is therefore seen at most about 15 seconds after its block; the freeze is signed and sent in the same pass and is in a block a block or two later; `/v1/faucet/health` says `frozen` at the next pass. `delay_seconds` of a day leaves that with a wide margin. (On 2026-11-18 a live run measured 29.6 seconds from the misuse to the 503 and 30.7 seconds to the freeze in a block, when the account was still read every 30 seconds; the shorter pace has run under tests only.)

**After a freeze the faucet is down for `freeze_seconds`**, and so is the thief. Use the time: replace the account's keys with the recovery keys (a root replacement with a new spend key), give the faucet the new key file, and restart it. If you do nothing, the freeze ends, the faucet gives again, and the thief still holds the key: the next misuse is frozen again.

**The faucet takes your own actions for misuse too.** It cannot tell you from a thief: whatever waits on its account, it freezes and cancels. So:

- to move a larger amount out of the faucet account, use a root operation (`pay`, two proofs, at once), never a waiting payment;
- to raise the daily limit, use a root replacement that keeps the keys and carries the new policy (two proofs, at once), never a raise with a spend key, which waits. Raise `max_chain_daily_limit_micros` in the config first, or the faucet stops at the new limit;
- or stop the faucet first.

All of this buys time and nothing more. The thief can freeze the account himself whenever he likes, and can ask for new items faster than 24 a day. **The answer to a stolen key is yours:** replace the keys.

The service reads the account's proven state before it starts and before every grant, and gives nothing when:

- the key in `key_file` is not a key of the account, or is not a spend key;
- the account has not adopted the rules (the key then holds every power);
- the daily limit on the chain is above `max_chain_daily_limit_micros`, or a raise above it is waiting. A raise that has finished waiting counts as the limit: the chain puts it into force with the account's next action, and it can no longer be cancelled;
- a payment above the limit or a raise of the limit is waiting;
- the account is frozen.

The key is read once, kept as a key that cannot be exported, never logged, and no error message says what the file holds.

### Waits that survive a stop

On a network whose genesis has `waits_survive_stops` (`../../spec/settings.md`, section 3) the waits and freezes of an account do not run while the chain is stopped. The moments of the faucet account's security row are then on the clock of the waits: the chain's time less the total of the chain's stops, which every proven state carries (`stopped_micros`). The faucet reads them on that clock:
- whether its account is frozen, and until when;
- whether a waiting payment or a raise of the limit is ready, and so whether a raise is in force;
- how much of the daily limit has refilled.

Read on the chain's time, after a stop of more than five minutes, it would take a freeze for over and give, take a raise a thief started for done, and count its allowance as refilled.

What a key signs stays on the chain's time: the expiry of the faucet's own freeze, and of a registration consent. So a freeze the faucet signs is dated from the moment the waiting item can be completed at the earliest: its moment on the clock of the waits, plus the stops so far. A later stop only moves that moment later.

On any other network the clock of the waits is the chain's time, and nothing of this changes. The limits of the faucet's own config ("per day") are counted in block time on every network.

## Running it

Node 26 and this repository's `client-v4/`, `deploy/watch/start.mjs` (its lock and log code), `web-v4/shared/verifier/` (the installed proof verifier) and `web-v4/faucet/` (the page) with the menu of the public networks it carries (`web-v4/shared/network-menu.js` and `.css`) are all it needs. It uses no npm packages. It is not part of the gateway distribution.

```sh
cp deploy/faucet/config.example.json /etc/time-faucet/config.json   # then edit it
node deploy/faucet/start.mjs /etc/time-faucet/config.json
```

Everything about money has no default: leave one out and the faucet does not start.

| Setting | Meaning |
|---|---|
| `test_network` | Must be `true`, written by you. See the top of this page. |
| `network_id` | The id of the test network this faucet serves. Must equal `trust.network_id` and the network of the proven state. |
| `rpc_url` | The CometBFT RPC of a node of the network: `https://`, or `http://` on this machine. An origin only. Use a node you run, with its transaction index on (`tx_index.indexer = "kv"`): the faucet looks its own actions up by hash. A node on another machine is reached through a tunnel to this machine's loopback address or through a TLS proxy, never as plain `http://`: `../api/README.md`, "A node on another machine", says how. |
| `trust` | The trust manifest, the same object the SDK's `createClient({trust})` takes. Install it from a source independent of the RPC. Its `chain_id` must be one of a test network. If it says `nodes_report_upgrades: true` (`true`, `false` or absent; a network on time-node-v5 0.7.0 or later says so), every state the faucet verifies also carries the question about scheduled upgrades. |
| `data_directory` | Holds `faucet.sqlite` (every grant of the last 30 days, the limits, the light client's checkpoint, the freezes and cancellations it signed) and the lock file. One instance per directory. A store belongs to one network, one account and one version of the faucet for good: a file of another is refused untouched, except one of the two versions before (3 and 4), which is moved to this one (5) in place (see "Who asked, and for how long it is kept"). |
| `caller_key_file` | Optional. Where the key of the hashes of who asked is kept between starts: an absolute path on a file system in memory, such as `/dev/shm/time-faucet-callers.key` (or a directory of the faucet's user under `/run`). Never on a disk, never in `data_directory` (refused), never in a backup. The faucet makes the file (mode 600) if it is missing. Without it the key is held in memory only and every restart forgets the counts per caller and per network. See "Who asked, and for how long it is kept". |
| `account` | The number of the faucet's account, in quotes. |
| `key_file` | Absolute path of the file with the spend key (see above). Refused on Linux and macOS if other users can read it. |
| `grant_micros` | What one request gets, in microseconds, as a decimal string. The faucet pays the fee on top. |
| `limits.per_account_per_day` | Grants one receiving account gets in 24 hours. |
| `limits.per_address_per_day` | Grants one caller address gets in 24 hours: an IPv4 address, or an IPv6 /56. |
| `limits.per_network_per_day` | Grants the IPv6 /48 around a caller gets in 24 hours, all its /56s together. Default three times `per_address_per_day`. An IPv4 address has no network beyond itself. |
| `limits.total_per_day_micros` | What the faucet gives in 24 hours in all, fees and sponsored registrations included. A grant that would pass it is refused; a registration is not (see `registrations_per_day`). |
| `limits.registrations_per_address_per_day` | Sponsored registrations per caller address in 24 hours. Required when `sponsor_registrations` is true. |
| `limits.registrations_per_network_per_day` | Sponsored registrations of the IPv6 /48 around a caller in 24 hours. Default three times `registrations_per_address_per_day`. |
| `limits.registrations_per_day` | Sponsored registrations of all callers together in 24 hours: the total of the sign-ups, apart from the total of the grants. Default ten times `registrations_per_address_per_day`. |
| `limits.refused_requests_per_address_per_hour` | Default 50. How many requests of one address may, in an hour, cost a proof and then be refused for what they ask (an account that does not exist, one that holds enough). Above it the address waits until the oldest is an hour old. **People behind one address share this count** (an office, a university, a mobile carrier), which is why it is high and the wait short: set it higher if your developers sit behind one address. |
| `min_balance_micros` | The floor. A grant that would leave the account below it is refused with `faucet_empty`, and `/v1/faucet` says the faucet is not giving. |
| `max_recipient_balance_micros` | An account that already holds more than this gets nothing (`already_funded`). |
| `max_chain_daily_limit_micros` | The highest daily limit you accept on the faucet account. Above it the faucet stops: somebody raised the limit. |
| `sponsor_registrations` | Whether `POST /v1/faucet/registrations` is offered. |
| `cancel_waiting` | Default true: cancel a waiting payment or raise found on the faucet account (see "What the faucet does when its key is used elsewhere"). |
| `freeze_on_misuse` | Default true: freeze the faucet's own account when a payment or raise that the faucet did not make waits on it. With false the faucet stops, tells and cancels only. |
| `port`, `host` | Default `127.0.0.1:8940`. Put a TLS proxy in front for the public. |
| `hosts` | The names the faucet is reached under, as clients send them in `Host`. Any other name gets 421. |
| `cors_origins` | The origins whose pages may call the faucet, each whole: scheme, name, port. **Behind a proxy, list the page's own public origin here** (`https://faucet.example`): the process cannot know under which scheme it is reached, and accepts without being told only its own page opened on this machine (`http://127.0.0.1:<port>`). When `serve_page` is on and `hosts` is set, the faucet does not start unless an origin under one of those names is listed: the page would be served and its own button refused. There is no wildcard. |
| `rate_limit` | `{per_second, burst}` per caller, default 5 and 20. A GET takes 1, a POST 10. Applied before anything else is done for a request. |
| `trusted_proxies` | IP addresses of your own reverse proxies. Only for a request from one of them is the caller taken from `X-Forwarded-For`, read from the right past entries that are trusted proxies too. Default none: the caller is the peer address. **Behind a proxy you must set this,** or every caller is the proxy and shares one limit. |
| `rpc_timeout_seconds` | Default 10. |
| `serve_page` | Default true: the page of `web-v4/faucet/` is served at `/`. |

"Per day" is any 24 hours counted back from the request, **in block time**: the time of the proven state a grant was made on. This machine's clock opens no window, whether it is set back or jumps ahead. `created_at` of a grant is that block time.

### How the limits count

- **A caller** is an IPv4 address, or an IPv6 /56 (what one subscriber is commonly given). **Its network**, the IPv6 /48 around it, is counted too, at three times the limits of one caller unless set: one network is not 256 callers. Before 2026-11-24 it was, and one /48 could take every grant of the day and have 5,120 names a day sponsored.
- **Two totals.** The grants stop at `total_per_day_micros`, which counts the sponsored registrations too. The sign-ups stop at `registrations_per_day`, and only there: a day whose grants are given still signs people up (a wallet's sign-up keeps working), and sign-ups that use up their own total take from the grants no more than what they cost (on the test network 0.011 seconds each). Before 2026-11-24 both shared one total.
- **A new account gets one grant in its first 24 hours**: an account one of whose keys this faucet sponsored the registration of in the last 24 hours. A newcomer who signs up and asks for test time a minute later gets it; the second comes the next day. Before 2026-11-24 the faucet's own free registrations made the limit per account worth nothing ("register ten accounts, then ask two grants for each"): now every grant to an account made for free costs a sign-up of the day as well. An account the faucet did not sponsor has `per_account_per_day` from its first block.
- **What none of this stops.** Addresses are cheap. On the test network's numbers (20 grants and 20 sign-ups per address, 60 per /48, 200 sign-ups a day, two hours of grants a day), one IPv6 /48 takes at most 60 grants a day (an hour of the two) and 60 names; six IPv4 addresses, or two /48s, take every grant of the day; ten IPv4 addresses, or four /48s, take all 200 sign-ups of the day, and so close sign-up for everybody else until the oldest is 24 hours old (fifty IPv4 addresses do both with room to spare). Only a cost per request that addresses do not buy (a proof of work, or a sign-in) bounds that; neither is built.

## Routes

- `GET /v1/faucet`: what the faucet gives, the limits, what is left in the current 24 hours, whether it is giving (`giving`, and `reasons` when it is not), its account number and network id, and what the last proof showed of its account. The page and a request are told the same: while `giving` is false, every request for a grant is refused, for the reason listed. When the total of 24 hours is given, the reason is `daily_total_given` and a request is answered `daily_total`.
- `GET /v1/faucet/health`: 200 unless something is wrong, 503 when the faucet is not giving because of a fault. The body holds
  - `giving`: whether a request for a grant would be granted now, as in `GET /v1/faucet`;
  - `reasons`: everything that stops the giving. `faults` repeats those that are faults and make the answer 503: `state_unavailable`, `key_or_account_check_failed`, `payment_above_limit_waiting`, `limit_raise_waiting`, `frozen`, `chain_not_advancing` (the proven state has not moved for five minutes: the node is stalled or cut off), `below_floor`, `chain_daily_limit_used_up` (the allowance on the chain does not cover one grant), `node_not_taking_actions`;
  - one reason that is no fault and leaves the answer at 200: `daily_total_given`. The faucet has given `limits.total_per_day_micros` and gives again when the oldest grant is 24 hours old. Any caller can bring that about, so it must not turn the check red. While it holds, `chain_daily_limit_used_up` is no fault either: the limit on the chain is set to about the same number (step 3 above), so it is expected to be nearly used. Two cases are faults all the same. A limit on the chain that is used up while the config's total is not: something else spent it. And a limit that is used up while the total is given, when the account's nonce has moved without the faucet in the last 24 hours (`key_used_elsewhere`): the limit on the chain refills over the day while the config's total frees nothing until its oldest grant is 24 hours old, so "the faucet gave its total" must not explain away what another holder of the key paid out of the refilled limit;
  - `warnings`, which stop nothing and leave the answer at 200, so that no caller can turn the check red. **Alert on them from the body:** `key_used_elsewhere` at once (somebody else holds the key: a payment or a raise it did not make waited on the account, or the account's nonce moved without it; it stays for a day after the last sighting); `lookups_failing` (the node cannot look actions up: is its transaction index on?) and `clock_differs_from_block_time` (this machine's clock and the proven block time are more than five minutes apart) when they last. `requests_refused_busy` only says that requests were turned away as busy in the last five minutes (`refused_busy` counts them): callers can cause it, and it is load, not a fault.
- `POST /v1/faucet/grants` with `{"account": "<number or name>"}`: sends `grant_micros` to that account. 202 with the action's `hash`, `status` (`submitted`, or `pending` when the node did not confirm), `nonce` and `lookup`.
- `GET /v1/faucet/grants/{hash}`: what became of an action the faucet made (see the statuses below). This is the faucet's own record, kept for 30 days; to verify the payment itself, look the hash up on the Time API (`docs/integration-guide.md`, steps 2 and 4).
- `POST /v1/faucet/registrations` with `{"public_key", "commitment", "expires_elapsed_micros", "proof"}`: sponsors the registration of a new key (see below).
- `GET /`, `/app.js`, `/styles.css`: the page. Three fixed files read at start; no path of a request reaches the file system. `GET /?account=<number or name>` is the page too: the page puts the account into its field, where the person can change it, and asks for nothing by itself. It is the one query any address takes: `account`, once, in the form the page accepts (a number or a name of up to 20 letters, digits and underscores, with or without `@`); anything else is `invalid_url`.

`GET /v1/faucet` also says how the limits count: `gives.per_network` (the IPv6 /48), `gives.per_new_account` (a new account's grants in its first 24 hours: 1) and `registrations.per_network`, `registrations.per_day` and `registrations.left`.

```sh
curl -s -X POST http://127.0.0.1:8940/v1/faucet/grants -H 'Content-Type: application/json' -d '{"account":"alice"}'
```

Refusals are plain and have a stable `error.code`:

| Code | Status | Meaning |
|---|---|---|
| `account_limit`, `address_limit`, `daily_total` | 429 | A limit is reached. `Retry-After` says when the oldest grant leaves the window. `account_limit` lists what the account was given (`previous`), with hashes: a caller whose answer was lost learns here that the request went through. It is also the answer to the second grant of a new account in its first 24 hours, in words that say so. `address_limit` is the answer for the caller's address and for its IPv6 /48 (the message says which), and to an address that reached `limits.refused_requests_per_address_per_hour`. |
| `already_funded` | 409 | The account holds more than `max_recipient_balance_micros`. |
| `account_not_found` | 404 | No such account in the proven state. |
| `faucet_empty` | 503 | The floor is reached. |
| `chain_daily_limit` | 503 | The daily limit on the chain is used up. If the proof shows it, nothing is signed and nothing counts. If only the node says it, after the action was sent, the answer carries the `hash`: see below. |
| `faucet_frozen`, `faucet_unavailable` | 503 | The account is frozen, failed a safety check, or has something waiting on it that the faucet did not make. |
| `node_unavailable`, `busy`, `state_unavailable` | 503 | An earlier grant has not reached the node yet, too many wait for a block, no proof could be read, or the proven state stands still. |
| `node_refused` | 502 | The node refused the action for another reason. The answer carries the `hash`. The node's own words are in the log only. |
| `rate_limited` | 429 | Too many requests from this address. |
| `invalid_account` | 400 | The account is not a number or a name, or it is the faucet's own. |
| `invalid_body`, `invalid_json` | 400 | The body is not the one JSON object the route takes, each field once, as a plain string. |
| `unsupported_media_type`, `body_too_large`, `body_too_slow` | 415, 413, 408 | The body is not sent as `application/json`, is larger than 1024 bytes, or did not arrive within 5 seconds. A request that carries a body ends its connection with its answer: before 2026-11-24 a refused request (one over the rate limit too) kept its connection for as long as its body kept coming, a byte at a time. |
| `not_found` | 404 | `GET /v1/faucet/grants/{hash}`: the faucet has no record of an action with this hash (records are kept for 30 days). |
| `wrong_network` | 503 | The node proves the state of another network than the one the faucet is configured for. Nothing is given. |
| `invalid_url`, `url_too_long`, `invalid_request` | 400, 414, 400 | The address is not a plain path without a query, is longer than 512 characters, or the request names its host twice. |
| `unknown_route`, `method_not_allowed` | 404, 405 | No such route, or not with this method (`Allow` names the ones it takes). |
| `unknown_host`, `origin_not_allowed` | 421, 403 | The request names a host that is not in `hosts`, or comes from a page whose origin is not in `cors_origins`. |
| `internal` | 500 | The request could not be answered; the log has the reason. |

For a sponsored registration (`POST /v1/faucet/registrations`) the limits, the 503 answers and `node_refused` are the same, and there are these:

| Code | Status | Meaning |
|---|---|---|
| `not_offered` | 404 | This faucet does not sponsor registrations (`sponsor_registrations` is false). |
| `invalid_consent` | 400 | `proof` is not the signature of `public_key` over the sponsorship consent that names this faucet's account and network. |
| `invalid_expiry` | 400 | `expires_elapsed_micros` is less than 45 seconds or more than the network's registration lifetime after the newest proven state. |
| `already_registered` | 409 | The key already belongs to an account. |
| `already_committed` | 409 | A registration of this key is waiting on the chain already (`same_commitment` says whether it is this one): make the registration its commitment names (kind 2 or kind 45), or wait for it to expire. The same code, with the action's `hash` and without `same_commitment`, when the faucet sent its sponsorship and the node refused it because such a registration waits (someone else's, sent first): see "How a grant survives trouble". |
| `already_registered` | 409 | Also when the node refused the faucet's sponsorship because the key already belongs to an account (with the action's `hash`). |
| `account_limit` | 429 | The key was sponsored in the last 24 hours (`previous` lists it). |
| `address_limit`, `daily_total` | 429 | The caller's address or its IPv6 /48 has had its registrations of 24 hours, or all callers together have had `registrations_per_day`. |

## How a grant survives trouble

A grant goes through these steps, each written to the store (SQLite, synced to disk) before the next:

1. **`reserved`**: the limits are checked and the request is recorded, in one transaction.
2. **`signed`**: the action is signed with the next free nonce; its bytes, hash and nonce are stored. From here on these are the only bytes this request will ever have. A grant is never signed twice.
3. The bytes are sent. **From this moment the grant counts against the limits, whatever the node answers.** `submitted`: the node took them.
4. **`included`**: the proven state shows the nonce as used, and the node finds the hash in a block with exactly these bytes.

What can go wrong, and what happens:

- **The node does not answer, or the process stops, after signing.** The grant stays `signed`. The caller gets 202 with `status: "pending"` and the hash. On a timer, and at every start, the same bytes are sent again; the chain takes an action once. No new grant is signed for anyone until this one has reached the node.
- **The bytes are in a block already when they are sent again.** The node then refuses them ("incorrect nonce"), which looks like a reason to sign anew and is not. The faucet reads the proven nonce first: a nonce the chain has used is looked up by hash, never sent again.
- **The process stops between recording and signing.** At the next start the request is signed and sent, once, or cancelled if the faucet may not give at that moment.
- **The caller's answer is lost.** Asking again gives `account_limit` with the first grant and its hash.
- **Two requests at once.** Requests are handled one at a time from the proof to the node's answer. Each gets its own nonce.
- **The node refuses the bytes** (the daily limit on the chain, most likely). "Refused" is the node's word: a node that says it and keeps the bytes can still get them into a block. So the grant stays open and counted, and the caller is told (503 `chain_daily_limit`, or 502 `node_refused`, with the hash). The same bytes are then sent **one more time**, and only when two things hold: the grant stands at the head of the line (until then, what is ahead of it explains the refusal or decides it, and it is not sent at all), and three blocks have passed since the refusal (the proof is a block or two behind the node, and the bytes may just have entered a block). Refused there again, the grant is `withdrawn`, with everything queued behind it. Withdrawn bytes are not sent again, and count. If a block takes them after all, the record is corrected to `included`. One exception to "one more time": if that sending gets no answer, or the process stops before its answer is recorded, the same bytes go out again. That is harmless: the chain takes an action once.
- **The node refuses a sponsored registration for good** ("unexpired registration commitment already exists": someone's sponsorship of the same key went first; or "registration key already belongs to an account"). No sending changes that, so the action is withdrawn at once, at its first sending, when nothing signed after it holds a later nonce (nothing can: it was signed last). The caller gets 409 `already_committed` or `already_registered` with the hash. The action stays in the store, counts against the limits, is never sent again, and is looked up by its hash when its nonce is used, as every withdrawn action is: if a node that said "refused" kept the bytes and a block took them after all, the record says `included`, and the grant that was signed with the same nonce ends `superseded`. Before 2026-11-24 such an action waited three blocks for its one more sending, and since nothing new is signed while earlier bytes have not reached the node, every grant and sign-up of everybody waited with it (`node_unavailable`): anyone could bring that about at will.
- **Another action used the nonce.** If the node does not find the hash a minute after the nonce was seen used, the grant is `superseded`. Three things do this: the spend key is used elsewhere; the account's keys were replaced (which uses nonces); or a withdrawn grant was taken by a block after its nonce had been given to a later grant. The node's index can also simply be late: a superseded grant is looked up for six more hours and corrected to `included` if it is found.
- **The node cannot look actions up** (its transaction index is off). Grants whose nonce is used keep their status, count, and hold nothing up: only grants that can still take money (not sent yet, or sent with a nonce the chain has not used) are counted against the 64 that may wait at once. `/v1/faucet/health` warns (`lookups_failing`). After six hours such a grant is closed as `unconfirmed`.

Only `cancelled` (recorded and never sent) does not count. Everything else counts against the limits for 24 hours, whether it was paid or not. When in doubt the faucet gives less.

## Sponsored registrations

A new account needs a sponsor: an existing account signs action 44 for the new key, and pays the registration charge and the fee. The sponsor gets no power over the new account, and the new key gets none over the sponsor. A spend key may sign it, and it counts against the daily limit on the chain like a payment.

The new key consents by signing `TimeSDK.sponsorConsentBytes({networkId, sponsorAccount, publicKey, commitment, expiresElapsedMicros})`, where `sponsorAccount` and `networkId` are the `account` and `network_id` of `GET /v1/faucet`, `commitment` is the commitment of the registration the developer will make, and the expiry is in microseconds since the network's genesis, at least 45 seconds and at most the network's registration lifetime ahead. The faucet checks the signature, that the key has no account and no waiting registration, and the limits (one per key and `registrations_per_address_per_day` per address in 24 hours, inside the daily total). It then signs and sends action 44 and answers with its hash. When that is in a block, the developer signs, with the new key and in a later block, the registration the commitment names, and can then ask for a grant.

There are two kinds of registration:
- **The reveal (kind 2).** The commitment is `TimeSDK.nameCommitment(...)` for the wanted name. The account starts with one key that can do everything.
- **The registration that carries the account's keys (kind 45),** on a network whose genesis has `protected_registration`. The commitment is `TimeSDK.protectedNameCommitment(...)` of the name, a salt and the account's set of keys and policy. The account starts with its keys in their roles and its daily limit, from its first block.

The faucet cannot tell the two apart, and need not: the commitment is a hash. It pays for it either way, and the new key's consent, which names the commitment, keeps it from paying for any other. The answer's `next` says the same. `client.registerProtected` does a protected sign-up from end to end, with the faucet as its sponsor (`../../client-v4/README.md`, "Accounts protected from their first block").

On such a network the faucet's own account can start protected as well: one registration of kind 45 with the five keys and the policy of steps 2 and 3 above takes the place of both steps. A sponsor pays for it as for any other.

What this costs you: each registration takes the network's registration charge and one fee from the faucet, and adds a name to the test network that nobody can take back. The per-address limit is the only thing between the faucet and someone registering names for sport. Set `sponsor_registrations` to false if that matters on your network. The page mentions sponsored registrations only when they are on.

## What it trusts, and its limits

- **The trust anchor** for everything it reads of the state: the network id, its own account, key roles, limit, balance and nonce, what waits on the account, block time, and the recipient's balance. These come with proofs checked by the installed verifier.
- **The node, for two things.** It can drop or delay submissions (the faucet sends them again), and it can say "refused" of bytes it keeps (which is why sent bytes count). And its lookup by hash decides whether a grant whose nonce is used is labelled `included` or `superseded`. That answer is the node's word, compared with the stored bytes; it is not a proof. It decides a label, never a limit and never a second signature. Run your own node.
- **A node that stands still** is noticed by what it can prove: when the proven height has not grown for five minutes, the faucet stops (`chain_not_advancing`). This expects the network to make blocks also when nobody sends anything (CometBFT's `create_empty_blocks`, which is on by default and which this chain's issuance needs). On a network that makes no empty blocks, an idle faucet would stop itself.
- **Addresses can be had cheaply.** The per-address and per-network limits slow one person down; they do not stop someone with many addresses ("How the limits count" gives the numbers). The total per day and the daily limit on the chain are what bound the loss.
- **A grant included more than 24 hours after it was made** (bytes that sat in a waiting list that long) is no longer counted when it is paid.
- **Never restore an old `faucet.sqlite`.** A backup knows nothing of the grants made since it was taken: restored, the faucet gives them all again within the same 24 hours, and may sign new actions for requests it had already signed. If the store is lost, start with an empty directory and expect one more day's total to go out; the daily limit on the chain still holds.
- **A store of an earlier version of the faucet is refused** with a plain message, and nothing is written to it; only a store of version 3 or 4 is moved in place ("Who asked, and for how long it is kept"). Do not delete it lightly: it holds the grants of the last 24 hours. Start the new version on an empty directory only after a day without grants, or accept that one more day's total may go out; the daily limit on the chain still holds.
- **A single process.** The lock is the security watch's (`../watch/README.md`): a second instance on the same directory refuses to start, and one that loses the lock stops with exit code 75. Never run two faucets with the same key on two directories: they would give out the same nonces.
- **Logs** are JSON lines on stdout: grant numbers, account numbers, error codes, and a node's refusal text with everything but plain characters removed. Never a caller's address (before 2026-11-24 every grant and sponsorship was logged with it), never the key or its path, and nothing a caller wrote that was not checked first.

### Who asked, and for how long it is kept

The store never holds an address. Each request keeps a keyed hash (HMAC-SHA-256) of its caller (the IPv4 address or the IPv6 /56) and one of its IPv6 /48, and both are emptied once the request is 24 hours old: no limit looks further back. The rest of the record (account, amount, hash, status) is kept 30 days for its lookup; the account is on the chain anyway. Refused requests, which only the limit of `refused_requests_per_address_per_hour` counts, are kept an hour.

**The key of the hashes is not in the store.** There are only 2³² IPv4 addresses: with the key, a hash is turned back into its address in seconds. So the key is held in the faucet's memory and, with `caller_key_file`, in that file on a file system in memory (tmpfs). `faucet.sqlite`, a backup of it, a copy of the data directory or of the machine's disk gives back no caller: it holds the hashes and a check of the key (a keyed hash of a fixed text, which says nothing about the key), not the key. The file lets a restart of the faucet find the key again, and the limits per caller and per network count across the restart exactly as before. The start log says where the key came from (`caller_key`: `kept`, `new` or `memory`).

**When the key is lost** (a reboot empties `/dev/shm`; the file is missing, unreadable, readable by other users, a link, or holds no key; or there is no `caller_key_file`), the faucet makes a new key, says so in its log, and removes the hashes it can no longer match: the counts per caller and per IPv6 /48 of the last 24 hours start afresh, once. Everything that knows no caller still holds: one sponsorship per key, `per_account_per_day` grants per account (one in the first day of an account the faucet sponsored), `registrations_per_day` and `total_per_day_micros`. So a lost key lets one caller ask its 20 grants (on the test network's numbers) once more, which six IPv4 addresses could do at any time ("How the limits count"); it never lets the faucet give more in a day than its totals. A file that cannot be made or used leaves the key in memory only, with an error in the log: then every restart starts the counts per caller afresh.

**What is removed does not stay in the file.** The store overwrites deleted records and emptied fields with zeros (SQLite's `secure_delete`), and within ten minutes of a removal copies its log of writes (`faucet.sqlite-wal`) into the store and empties it; closing the faucet does the same. What the file system does with the blocks a file gives back is the operating system's business (see "What remains").

**Earlier stores** are moved in place at the first start, in one transaction, and the file is then written anew (`VACUUM`), so that nothing of the old version stays in it:
- version 4 (the first fix of 2026-11-24) kept the key in the store. Its key is removed from the file. Its hashes of the last 24 hours are kept as hashes under the new key, and the faucet run that moved the store, which holds the old key in memory, counts them for the callers that made them: the first start after the update limits callers as before. A later start no longer can: those requests then count for no caller (the totals still count them);
- version 3 kept the address groups themselves for 30 days: they are replaced by their hashes under the new key, and the limits count the same requests as before.

A backup of `faucet.sqlite` taken before the move still holds what it held: for version 4 the key beside the hashes of that day. Delete such copies.

**What remains.** Whoever has the machine while the faucet runs, as the faucet's user or as root, can read the key (from its file or from the process's memory) and the hashes, and so turn the hashes of the last 24 hours back into addresses; and can watch requests arrive, which the faucet cannot prevent. A file system in memory can be written to swap where the machine has swap. The blocks of the disk that SQLite gave back (a log of writes that was emptied, the end of a file that `VACUUM` shortened) are not overwritten by the file system: whoever reads the raw disk (root, or a block-level copy of the volume such as a snapshot) may find in them hashes without their key, and, on a machine whose store was moved from version 4, that version's key and its hashes of the day of the move.
- **What has run against a live network, and what has not.** On 2026-11-18 the faucet ran once on a live test network (seven validators in two regions on AWS), started from this start script with a config file and a key file as above, on an account prepared by the six steps of "The faucet's account and key", and checked by the test harness's scripted client for about two minutes. It sponsored one registration and gave grants; its own record of the grant the check followed said `included` 5 seconds after the request (it settles every 5 seconds), and the payment verified through the Time API. It refused by account, by address and by the total as the table says, and kept its limits and records over a stop and start. When its spend key was used elsewhere it stopped, froze its own account, and the watch told the owner: 29.6 seconds to the 503 and 30.7 seconds to the freeze in a block, at the pace it had then (see "How fast"). The misuse of that run was a payment above the limit, which waits; the sighting of a foreign nonce for a payment within the limit, and the idle read every 10 seconds, were written after it and have run under tests only. On 2026-11-19 a browser used it for the first time (Chrome 158, `campaign/README.md`, "The browser check"): the page loaded and said what the faucet gives; a wallet on another origin, listed in `cors_origins`, had the registration of a new account sponsored (2.2 seconds from the person's click to a verified account in the wallet); the page sent a grant to that account by its name, refused the second request in words, and did not send what is not a name. That was on a loopback address without a TLS proxy.

  What has not run: a browser other than Chrome on the page, or Chrome for longer than a minute; 24 hours (no window of a limit has been seen to end on a live chain, nor a freeze); the shorter pace, changed after that run (the health answer for a day's total, changed then too, ran in the harness's scripted check on 2026-11-23: 200, with `daily_total_given`); a node that loses submissions or stands still; requests from many addresses; a proxy in front; developers. The tests use a fake node that applies the nonce, signature, daily-limit and cancellation rules, the engine's own account-security fixture, and one real state proof. The clock of the waits and the sponsoring of a registration that carries the account's keys (kind 45) are tested in `client-v4/faucet.test.mjs` and `client-v4/protected-signup.test.mjs`. On 2026-11-23 the faucet ran on laboratory networks with both settings: the harness's scripted check passed on one of them after a stop of the chain of nine minutes, and in Chrome the wallet signed up protected accounts with the faucet as its registration service (`AUDIT-2026-11.md`, "Run on AWS and in a real browser (23 November 2026)"). The faucet has not run on a network with a stop of more than an hour.
