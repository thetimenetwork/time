# Security watch

Account security (`v5/src/security.rs`) makes the risky things wait in the open: a payment over the daily limit, a raise of the limit, a replacement of the keys asked for by recovery keys alone. It also lets any spend or recovery key freeze the account, and lets a spend key add or remove sign-in keys. All of this protects only an owner who notices in time, and nothing on the chain tells the owner. This process tells them.

It polls verified state for a list of accounts, compares each with what it saw last, and sends what changed as events: to a webhook per subscription, and to a read-only feed on a local port. It holds no key and signs nothing.

## Running it

Node 26 and this repository's `client-v4/` and `web-v4/shared/verifier/` (the installed proof verifier) are all it needs. It uses no npm packages.

```sh
cp deploy/watch/config.example.json /etc/time-watch/config.json   # then edit it, and chmod 600 it: it holds the webhook secrets
node deploy/watch/start.mjs /etc/time-watch/config.json
```

One option can follow the path, for one start only: `--forget-upgrade-answer` (see "A change of the network's rules" below). The start log and `/health` say whether the trust data declares that the network's nodes report upgrades (`nodes_report_upgrades`, `upgrade_declared`); when it does not, the start log warns.

| Setting | Meaning |
|---|---|
| `gateway` | The address of a wallet gateway, as wallets reach it: its public `https://` origin (`public_origins.wallet` in the gateway's settings). Use that name also when the gateway runs on this machine. See "Which gateway address" below. |
| `trust` | The trust manifest, the same object the SDK's `createClient({trust})` takes. Install it from a source independent of the gateway. If it says `nodes_report_upgrades: true` (a production network's does), every account check carries the question about scheduled upgrades from the first poll. That field is `true`, `false` or absent. Without it the watch takes the weaker way described under "A change of the network's rules", and says so in its start log: check that the trust data you install has it when the network's nodes are time-node-v5 0.7.0 or later. |
| `subscriptions` | `[{account, webhook, secret}]`. `webhook` must be `https://` (`http://` only to localhost). `secret` is 32 random bytes as 64 hexadecimal characters, made by `openssl rand -hex 32` (or `node -p "require('node:crypto').randomBytes(32).toString('hex')"`), one per subscription; a secret a person chose is refused (see "Webhooks"). Without `webhook` and `secret`, the account is in the feed only. |
| `poll_seconds` | Default 30. Keep it at most a quarter of the shortest `delay_seconds` of the watched accounts (see "What it trusts"). The watch learns each delay at the first poll. For each account whose delay is shorter than four times the poll interval, it then logs a warning and counts it in `/health` as `config_warnings`. |
| `gateway_timeout_seconds` | Each request to the gateway, and each batch of 8 accounts, gives up after this long. Default 30. |
| `max_lag_seconds` | The oldest verified state accepted as current. Default 300. Each account's own limit is at most half its `delay_seconds`. |
| `reminder_hours` | A reminder goes out when a waiting item is this close to its ready time. Default 6. |
| `port`, `host` | The feed. Default `127.0.0.1:8920`. A `host` beyond this machine needs `feed_token`. |
| `feed_token` | Optional (at least 24 characters). When set, every request to the feed needs `Authorization: Bearer <token>`. |
| `hosts` | Extra `Host` header values the feed answers to, such as `watch.example:443` behind a proxy. `127.0.0.1`, `localhost` and `[::1]` with the port always work; any other name gets 421, which stops DNS rebinding. |
| `data_directory` | Holds `watch.json` and `watch.json.bak`, `feed.json`, `checkpoint.json` (the light client's latest verified checkpoint) and `watch.lock`. One watch per directory. |

**Which gateway address.** A gateway started as its README says (`deploy/gateway/start.mjs`) answers only under its public HTTPS names, through its TLS proxy. Asked under this machine's loopback address (`http://127.0.0.1:8907`) it answers 403 "Loopback host rejected" to every request; a watch configured that way starts, sees no account, logs each failed poll, and tells every owner `watch_blind` once the allowed lag has passed. So the watch is given the gateway's public origin, and goes out through the proxy like a wallet. `http://` on this machine is accepted for one case only: a gateway started without public origins (`createV4Servers` without `publicOrigins`, as development set-ups and the test harness do), which serves nobody but this machine. The watch asks a gateway, not a node: it has no setting for a CometBFT RPC.

- `GET /alerts?account=<id>` returns that account's last 100 events, newest first. Accounts that are not watched get 404.
- `GET /health` returns counts only, never an account id:
  - the times of the last poll and the last good one;
  - accounts failing, and accounts the watch cannot see;
  - events queued and dead letters;
  - targets resting after failures;
  - store errors;
  - `alarm`, set when no poll has fully succeeded for 3 poll intervals (at least 60 s).
- Nothing else is served, and nothing can be written.

### Webhooks

Each event is POSTed as JSON, with these headers:
- `x-watch-event: <event id>`
- `x-watch-signature: t=<unix seconds>,sha256=<hex>`, where hex is the HMAC-SHA256, under the subscription's secret, of `t=<unix seconds>,id=<event id>.` followed by the raw body.

A receiver:
- **Checks the signature first.** `verifyWebhookSignature(body, headers, secret, {maxAgeSeconds})` in `client-v4/security-watch-service.mjs` does it all:
  - compares in constant time;
  - refuses a signature more than 5 minutes old or ahead (configurable), so a captured request cannot be replayed later;
  - refuses a header id that differs from the signed one and from the one in the body.
- **Drops an event id it has already seen.** Delivery is at least once.
- **Answers 2xx** when it has the event. The watch never reads the answer's body.
- **Answers 401 when the signature does not verify** (a wrong secret, or a clock out of step). The watch keeps the event and tries again, so a receiver whose clock is fixed still gets it. Any other 4xx works the same way.
- **Answers 410 Gone only to end the subscription.** It is the one final answer: the event goes to the dead letters and is not sent again.

**The secret** is made by a command, never chosen: `openssl rand -hex 32`, or wherever Node is, `node -p "require('node:crypto').randomBytes(32).toString('hex')"`. Give the receiver the same. The watch refuses to start with any other kind, and its message says this command: it takes 64 to 256 hexadecimal characters (32 bytes or more) that look made by a random generator, and refuses one with fewer than 10 different digits, one in which a pattern repeats, and text written in hexadecimal. Every delivery carries an HMAC-SHA256 under the secret: whoever captures one can test guesses offline at billions a second, so a secret a person chose or could type from memory falls, and with it the receiver's trust in every alert. Until 24 November 2026 any text of 16 characters was taken: replace such a secret before you update.

Each target (each webhook, and the feed) has its own queue and delivers on its own. Polling never waits for a delivery, and a dead receiver delays only its own events.
- **First delivery:** a timeout, 408, 429 or 5xx is retried at once, then after 1 s, 2 s and 4 s.
- **After that:** the event gets one attempt per poll.
- **Resting:** after 3 failures in a row a target rests. The rest starts at 30 s and doubles, but never exceeds the allowed lag of its accounts (at most half their delay) or 15 min. An urgent event queued meanwhile is still tried once at once; if it gets through, the rest ends.
- **Refusals:** any 4xx other than 408, 429 and 410 means the receiver refuses.
  - The events stay queued and are retried like any failure.
  - Once per episode, the owners are told urgently through every other target (the feed at least) that their alert endpoint refuses alerts.
  - `/health` counts refusing targets.
- **Gone:** a 410 moves the event to that target's dead letters, kept in the store and counted in `/health`.
- **Which receiver gets what.** A webhook's queue is named by a hash of its accounts and its URL.
  - Reordering the subscriptions changes nothing.
  - A changed URL (or account) makes a new target. The events the old one still held go to the targets that now serve the same accounts and have not had them.
  - A removed subscription's queue is dropped; the log gives counts, never content.
  - An event is never delivered to a target that does not serve its account.

### Events

Each event has `id`, `account`, `type`, `at_height`, `chain_time`, `urgent`, a plain-English `message`, and fields that depend on its type. Messages give dates in UTC only.

**On a network whose waits survive a stop** (`waits_survive_stops` in its genesis; `../../spec/settings.md`, section 3) the waits and freezes of an account do not run while the chain is stopped. The moments a security row stores are then on the clock of the waits: the chain's time less the total of its stops, which every verified state carries (`stopped_micros`).
- The watch compares every moment with that clock, never with the chain's time. Read on the chain's time, after a stop of more than five minutes, a freeze would look over and a payment ready while the chain holds the opposite.
- It gives a moment as a date by adding the stops so far. While the moment has not come, that date is the earliest it can come: a later stop moves it. The message then says "at the earliest" after the date, and the event carries `earliest: true`. This is so for `payment_waiting`, `limit_raise_waiting`, `replacement_waiting`, `frozen` and `reminder`.
- The date fields (`ready_at`, `frozen_until`, `expires_at`) stay plain dates. The `*_elapsed_micros` fields are the moments as the row stores them.
- The daily limit refills on the same clock: a stop gives a spend key nothing more to move, and the watch counts it so.
- A state whose total of stops the watch cannot read (the setting or the total in a form the engine does not write) is not judged. The account counts as not seen at that poll, and the log says why.
- A look the watch stored before it read this clock is compared at the lowest clock it can have had: what waited then is taken to have waited longer, never less.
- On any other network nothing of this changes, and no event carries `earliest`.

- **Adopting the rules:** `rules_adopted`.
- **Payments above the limit:** `payment_waiting` and `payment_gone`. `payment_gone` has an `outcome` (`executed`, `cancelled`, `dropped` or `unknown`) and a `certain` flag. `unknown` is urgent.
- **The daily limit:** `limit_raise_waiting`, `limit_raise_cancelled` and `limit_changed`. `limit_changed` is urgent when the limit rose without waiting.
- **Other rules:** `rules_changed`, urgent: it happened at once, with the spend key and approvals.
- **Replacing the keys:** `replacement_waiting`, `replacement_cancelled` and `keys_replaced`.
- **Freezes:** `frozen` and `unfrozen`. `unfrozen` is urgent when the freeze was lifted early.
- **Sign-in keys:** `signin_key_added` and `signin_key_removed`.
- **What the watch could not see one by one.** The counters of the rows moved further than the visible changes explain. All three are urgent.
  - `waiting_unseen`: a waiting item came and went between two looks.
  - `root_operation`: an immediate payment, or a cancel or unfreeze of something never seen. It includes the balance fall.
  - `signin_keys_changed`: for example, a sign-in key added and removed again.
  - `balance_fell`: the balance fell by more than the spend key alone could move in that time, and nothing above explains it.
- **Reminders:** `reminder`.
- **The watch itself:**
  - `watch_blind` (urgent) and `watch_restored`, described in the next section. Both are only ever about whether the watch sees the account;
  - `watch_memory_lost` (urgent), when the store had to be set aside;
  - `alerts_refused` (urgent), when an alert endpoint refuses alerts.
- **Your validator's upgrade signal** (only for a watched account that is the owner account of a validator). The owner account signals support for a change of the network's rules, or withdraws it, with a key that may spend. Whoever holds that key can do the same, and nothing on the chain tells the owner.
  - `upgrade_signal_changed` (urgent), once for each new signal of the account: support for a plan, or a withdrawal. It gives the version, the start in UTC, the whole specification hash in eight groups, and when the signal was sent. It says what to do. If you sent it: compare the hash with the release announcement, group by group. If you did not: on a secured account freeze the account and replace the keys, then withdraw the signal in the wallet (tab "Validator signal") once the account can sign again; on an account with plain keys remove every key you do not know, then withdraw.
  - The same event, not urgent and marked `first_sight`, when the watch reads the signal of an account for the first time and it supports a plan: a new subscription, or a store written by a build before this one. The watch then cannot say whether the signal is new, and says so.
  - `upgrade_signal_dropped`, not urgent, once, when a signal of support is gone from the chain. No action removes a signal: the network drops one whose start has come too close, whose version is no longer the next one, or whose validator was retired.
  - The hash is given in groups so that it can be compared and is not copied: the signal may be someone else's.
  - *What this does not cover.* The signals are part of the upgrade entry of proven state, which the watch reads with each account only on a network whose trust data says `nodes_report_upgrades: true` (a production network's does). On any other network the watch says nothing about signals, in either direction. Two signals of one account between two readings are told as one: the later. The watch does not say whether a signal counts (a frozen account's does not) or how much of the votes a plan has: the wallet's tab shows that.
- **A change of the network's rules** (a new protocol version, which the validators schedule at least 21 days ahead):
  - `upgrade_scheduled`, once per plan: which version starts when, and whether this watch is ready for it. The plan is read from proven state, like everything else. A plan that is cancelled and scheduled again, even with the same start, is a new plan and is announced again.
  - `upgrade_cancelled`, once, when a plan the owners were told about is withdrawn.
  - `watch_outdated`, once a day while the scheduled version is one this watch does not implement: it must be updated before the start.
  - `watch_ready`, once, when the watch is updated while the plan stands and now implements the version.
  - `upgrade_question_unanswered` and `upgrade_question_answered`, neither urgent, only on a network whose trust data does not say that its nodes report upgrades: the watch's question about scheduled changes was answered before and is not now, and is answered again. They are described below.
  - `watch_outdated` (urgent), at once, when the network runs a version this watch does not implement. Its verifier then refuses every state, the watch sees no account, and it says so at that poll instead of a `watch_blind` after the allowed lag. `watch_restored` follows once an updated watch reads the account again. Install the release that implements the version and start it on the same data directory.
  - **Only the verifier's own refusal counts.** The watch knows it by the code `UPGRADE_REQUIRED` on the error, which only the installed verifier's wrapper and the SDK's own version check set. A gateway that sends those words, in whatever form, is a gateway that does not answer: it gets no `watch_outdated`, and after the allowed lag a `watch_blind`. The owner's message is the watch's own words; the one thing taken from the refusal is the version number, and only from the verifier's exact sentence.
  - **The question never holds an alert, and a gateway's words never decide whether it is asked.**
    - *A network whose trust data says that its nodes report upgrades* (`nodes_report_upgrades: true` in `trust`; `tools/genesis-v5.mjs` writes it for a production network). Every account check carries the question (`include_upgrade`) from the first poll. Nothing is learned and nothing is stored about it. A gateway that holds, refuses or leaves out the question fails the account check itself, and the owner gets `watch_blind` like for any other blindness.
    - *A network that does not say so* (an older laboratory network). The question is never part of an account check. The watch asks it apart, after each poll has stored and sent what it found, with the gateway time limit, one question at a time. A gateway that holds or refuses it can therefore neither fail nor delay an account check, not even once. This is the weaker way: on such a network a gateway can keep a plan from the watch, and the most the owner hears is the message below.
    - *Until a node has answered the question* (nodes before time-node-v5 0.7.0 do not know it), a failure is logged once and shown in `/health`. Nothing is said to owners.
    - *Once a node has answered*, that is remembered in the store. If a later question is not answered, an episode begins: the log has an error, `/health` shows `upgrade_read: unanswered`, and every owner gets `upgrade_question_unanswered`. That message is not urgent, comes at most once in 24 hours while an episode is on, and says in its first sentence that it is only about scheduled changes of the rules, not about what the watch sees of the account.
    - *The episode ends* only when three questions in a row are answered. A gateway that answers now and then cannot flip the watch. Each answer in between is still used: a plan is announced at once. When the episode ends, the owners who were told get `upgrade_question_answered`, once for each `upgrade_question_unanswered`. So an owner gets at most these two messages in 24 hours, whatever the gateway does. If the question goes unanswered again within those 24 hours, `/health` shows it at once and the owner is told when the 24 hours have passed.
    - *These two types say nothing about the account.* Whether the watch sees the account is told only by `watch_blind` and `watch_restored`. A receiver that goes by the type alone can rely on that.
    - *To stop the daily message*, when the network's nodes really no longer answer the question: stop the watch and start it once with `node deploy/watch/start.mjs CONFIG_JSON --forget-upgrade-answer`. It forgets that a node ever answered, and from then on says nothing to owners about the question until a node has answered it again. Everything else in the store stays. Do not leave the option in a service's command line: the watch would forget at every start.
  - `/health` shows `outdated` (accounts concerned), `upgrade_declared` (whether the trust data says that the nodes report upgrades), `upgrade_scheduled` (the scheduled version, or null), `upgrade_known`, and `upgrade_read`: `ok`, `failing` (asked, no verified answer), `unanswered` (answered before and not now, or not yet three times in a row again), `not yet`, or `off`.

To add email, SMS or push, write an adapter `{ name, deliver(event, { first, signal }) }`. It throws when delivery fails: an error with `refused: true` marks a receiver that refuses, and one with `permanent: true` is not retried. Add it to the targets in `start.mjs`. None is built in, because each needs a provider.

## What it trusts

- **It verifies everything against validator signatures.** State comes from the SDK's `getVerifiedState`. The light client checks each answer against the validator set, starting from the trust anchor, using the verifier installed with this code, never code from the gateway.
- **It trusts only the trust anchor.** The gateway cannot make the watch report a payment, a freeze or a key that is not on the chain.
- **The gateway can still withhold or delay.** It can answer with old (but genuine) state, or not answer at all. The watch counts each of these as a failure for the accounts concerned:
  - no answer within `gateway_timeout_seconds`;
  - state older than the account allows (at most half its `delay_seconds`);
  - an older chain than one already seen;
  - another network or genesis than the one the store belongs to;
  - an account missing from the chain.
- **The owner is told when the watch is blind.**
  - **When.** At a poll, the newest state the watch could verify for an account is older than its allowed lag (at most half its delay). That happens when the gateway answers with old state or does not answer. It is also blind when the account cannot be read at all. Either way the owner still has half the wait.
  - **What the owner gets.** An urgent `watch_blind`, once per episode, under an id named after the last height seen. It says what was observed:
    - the gateway did not answer;
    - the gateway answered only with old state (and from when);
    - checks stopped completing;
    - the account is not on the chain;
    - the records do not match the chain.
  - **Restoring.** Only a poll that gives a fresh view sends `watch_restored`, never the clock alone.
  - **The watchdog** judges between polls, and only when a poll is overdue. Between polls an honest view ages by up to one poll interval, so the watchdog allows that interval on top of the allowed lag. A stuck poll does not silence the check, and an honest gateway raises no alarm.
- **The store is bound to its network.** It records the network id and genesis time of what it saw.
  - A store from another network, or with a chain behind it, is not mixed in. The operator must look: there is a log error, it shows in `/health`, and the owners get `watch_blind`.
  - An older store that names no network takes it from its snapshots, which must all agree. If they do not, the snapshots are set aside and every owner gets `watch_memory_lost`.
- **The checkpoint must stay fresh.** The light client refuses a checkpoint that is too old (`CHECKPOINT_REFRESH_REQUIRED`). While the watch runs it keeps the newest verified checkpoint in `checkpoint.json`. If it was stopped for longer than a checkpoint lives, install a newly authenticated trust manifest.

## Durability

- **The store.** `watch.json` is written to a temporary file and flushed to disk. The previous version becomes `watch.json.bak`, the new file takes its place, and the directory is flushed.
- **A torn store.** If `watch.json` is unreadable, `.bak` is used. If both are unreadable, they are moved aside (`.corrupt-<time>`) and the watch starts afresh.
  - `/health` shows `store_error`, and some events may be sent again with their usual ids.
  - Alerts still queued are lost with the store, so every watched owner gets an urgent `watch_memory_lost`. It says when, and tells them to check their account's waiting items in the wallet.
  - The notices are written to the new store at once, before the first poll, so a crash during that poll does not lose them.
  - Lost memory is also detected when the store is missing but a `.corrupt-*` copy is still there, or `feed.json` or `checkpoint.json` exists. Those files are written only after the store is, so their presence means the store existed and is now gone.
- **The lock.** `watch.lock` holds {pid, run, beat}. It is written whole and linked into place, and the watch rewrites its beat every 10 s.
  - **Stale** when it is unreadable, its beat is older than 30 s, its process is dead, or it names this process id from an earlier run (a container restarted with pid 1 again). A pid alone proves nothing, because pids are reused after a reboot.
  - **Taking a stale lock.** It is renamed to a name of the starter's own and checked before it is deleted, so two watches starting together cannot both take it.
  - **Rewriting the beat.** A heartbeat replaces the lock only if the lock is this run's at that moment: it looks again and replaces in one step, with nothing of its own process in between. One heartbeat runs at a time. A watch that stalled and resumes therefore does not put its lock over the lock of a watch that took over meanwhile; it finds the other's lock and stops.
  - **Releasing it.** A clean stop removes the lock. Once that is done, no heartbeat of the stopped watch writes the lock again: the timer is stopped and a heartbeat under way is waited for.
  - **Losing it.** A watch that stalled past the stale time may find its lock taken by another, or gone. It then logs an error, stops delivering and polling, and exits with code 75, so that only one watch delivers. A service manager restarts it; it then waits for the lock like any starter.

## Privacy

- **The operator** of the watch, and of the gateway it asks, learns which accounts are watched. The queries name them, eight at a time.
- **The webhook receiver** learns the events: amounts, recipients, times, key fingerprints. The same facts are public on the chain, but the events tie them to this subscriber.
- **The feed.** Anyone who can reach the feed port, pass the `Host` check and hold the token (if one is set) can read the events of watched accounts, and see which accounts are watched. That is why the feed listens on 127.0.0.1 by default.
- **`/health`** names no account.
- **Logs** hold account counts, origins and event ids. They never hold secrets or webhook paths or queries. A config file that is not valid JSON is reported by position only.

## Limits

- **It tells; it does not act.** Cancelling, freezing or replacing keys still needs the owner's keys.
- **The poll interval.**
  - **Above a quarter of an account's `delay_seconds`**, one failed or late poll can already leave the owner less than half the wait, and a single failed poll may raise `watch_blind`.
  - **Above half of it**, a waiting payment can start and go through between two polls. The owner learns of it afterwards, as `waiting_unseen` or `payment_gone`.
  - The watch warns about such accounts, but cannot refuse them before it has read their delay.
- **Whether a payment that left the waiting list went through** is not written in the rows. The watch is certain in two cases:
  - the payment was not ready yet, so it did not go through;
  - the balance fell by exactly the ready payments plus their fees, so they went through.
  - Anything else is `unknown`, and urgent.
- **Counters say how many changes, not what they were.** `root_operation` and `signin_keys_changed` give a number, not what each change was. When it is unclear whether a change already explains a counter's move (a waiting request that lapsed, then the version moved), the watch counts low, so that the owner is told.
- **`balance_fell` has a generous budget.** It allows what was left of the daily limit, the refill since, the ready waiting payments, and a fee per action. A fall below that budget that the owner did not cause is not reported, except as the events above. It also sees only the net fall: money that came in during the same interval can hide part of a drain, or all of it.
- **`alerts_refused` needs another target.** With one webhook per account, the notice that the webhook refuses alerts reaches only the local feed. The owner must look there, or the operator at `/health`.
- **Refused events are retried without end.** Events, including `alerts_refused` notices, that a refusing receiver keeps refusing stay queued and are retried each poll until it accepts them or answers 410. The queue is bounded (1000 events per target; the oldest are dropped, with a log line).
- **The lock is not race-free with three starters.** Two starters judging the same stale lock cannot both take it. But a third that reads in between, or a holder whose heartbeat replaces the lock in the instant between a starter's taking it aside and placing its own (two adjacent file operations on each side, with no stall of either process between them), can leave two holders for one beat. The later one then finds the lock taken and exits (code 75).
- **Delivery is at least once.** A crash between a delivery and the write of the store sends that event again, with the same id. A torn store that has to be set aside can resend more.
- **The SDK takes no abort signal.** A batch that times out leaves its request running in the background until the per-request limit ends it.
- **It is a single process with a single data directory**, and has no replication. If the host is down, nobody is told until it is back. It then reports what changed, coalesced, and `watch_blind` covers the gap only once it runs again. Watch `/health` from somewhere else.
- **What has run against a live network, and what has not.** On 2026-11-18 the watch ran once on a live test network (seven validators in two regions on AWS), started from this start script and a config file, watching two accounts with `poll_seconds` 5, and checked by the test harness's scripted client for about two minutes. The signed webhook for a payment above the limit arrived 4.9 seconds after the paying wallet had its verified receipt, with the amount, the recipient and the ready time the chain holds (the block of the request plus the account's delay, to the second). A freeze, and the waiting payment it dropped, were told 3.2 seconds after the freeze. What happened while the watch was stopped (a sign-in key replaced) was told once, 0.2 seconds after it started again, and nothing was told twice. The feed held the same events. The receiver of the run took 16 deliveries in all, from the watch and from the Time API together; each verified with its secret (`verifyWebhookSignature`), and none came twice.

  What has not run: hours (no reminder, no `watch_blind`, no resting target has been seen on a live network); a gateway behind its TLS proxy (that run asked a gateway without public origins on the watch's own machine: "Which gateway address"); a receiver on another machine, or one that fails; a scheduled upgrade; a torn store. The tests use real rows exported by the engine and inject verified state. The SDK's verification path is the one the wallet uses. The clock of the waits, and dates "at the earliest", are tested in `client-v4/security-watch.test.mjs`. On 2026-11-23 the harness's scripted check ran on a laboratory network after a real stop of nine minutes: the webhook of a waiting payment came with its date "at the earliest", and the state's total of stops was 249.2 seconds (`AUDIT-2026-11.md`, "Run on AWS and in a real browser (23 November 2026)"). The watch has not run on a network with a stop of more than an hour.
