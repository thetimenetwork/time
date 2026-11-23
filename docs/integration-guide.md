# Integrating with Time: deposits and withdrawals

For an exchange or a shop. Everything here is plain HTTP against the Time API (`deploy/api/README.md`), except signing a withdrawal and verifying a proof, which use the SDK in `client-v4/`.

The examples use `API=http://127.0.0.1:8930`, the exchange's account `5` and a customer's account `7`. Amounts are whole microseconds as decimal strings: `"2500000"` is 2.5 seconds.

## What is proven and what is only indexed

| You read | It is | Use it for |
|---|---|---|
| Lists of blocks, actions, activity, payments; an action by hash; the `indexed` part of an account answer (`indexed.state_is_behind`, `indexed.newer_actions`, `indexed.last_sent`, the totals); `used_by` in a refused submission; webhooks; the event stream (`"source": "index", "proven": false`) | This server's word. The server indexes only blocks it verified, but you cannot see that from outside | Finding a deposit; finding the action to verify; showing history |
| The state of an account (`"source": "state_proof"`) | A proof against validator signatures, checked by the server and passed on to you | Balance and nonce; proven once *you* have checked the proof |
| The `verify` part of an action | The Merkle proof that ties the action's bytes to a block header | Checking the payment yourself, with your own trust anchor |

Rule: **find with the index, credit on a proof.** Run your own API instance against your own node for the first; verify with the SDK (step 2) for the second. For large amounts also ask a full node you run (`client-v4/README.md`, "Large payments: confirm with your own node").

**A proof shows that something is in a block. Nothing proves that something is not.** "The index does not hold it" is the word of the server that says it. Where this guide lets you conclude that an action was not included (step 4), it first looks for a proof of what happened instead, and where only an absence is left it asks for an instance you run yourself, on a node of your own.

The index can be behind the chain, and it can start late. Every indexed answer says how far it is (`index.indexed_height`) and where it starts (`index.start_height`: an instance can be set up to index from a later block, and one that is rebuilt on a node restored from a snapshot has to be); an account answer shows `state_height` and `indexed_height` side by side. "The index does not show it" only ever means "not between `start_height` and `indexed_height`".

## 0. Check the service

```sh
curl -s $API/v1/status
```

`network.network_id` and `network.chain_id` must be the ones of the trust manifest you installed. `indexer.seconds_behind` is the age of the newest indexed block. `curl -s -o /dev/null -w '%{http_code}' $API/v1/health` gives 200 while the index keeps up.

## 1. Watch for a deposit

Two ways to know whose deposit a payment is.

**By sender.** The customer tells you their account number once (have them prove it with a wallet sign-in). Every payment from that account to yours is theirs:

```sh
curl -s "$API/v1/accounts/5/payments?from=7"
```

**By reference and sender.** A payment to a shop (kind 10) carries a 32-byte reference that you issue. The chain accepts a reference only from the payer's next nonce and until its expiry, so issue it per deposit:

```sh
curl -s $API/v1/accounts/7        # the payer: "account": {"nonce": "41", ...}, "state_time_micros": "...", "indexed": {"state_is_behind": false, ...}
```

The reference is 64 hex characters: the payer's next nonce (8 bytes, big-endian), the expiry in microseconds since the network's genesis (8 bytes; at most 24 hours ahead), and 16 random bytes. With the SDK: `TimeSDK.orderReference({ nonce: '42', expiresElapsedMicros })`, where elapsed time is `state_time_micros` minus the manifest's `genesis_time_micros`. Hand it to the customer's wallet with the amount (`TimeSDK.requestWallet`, type `payment`).

**The payer's nonce can have moved.** The answer proves the nonce one block behind the newest. If `indexed.state_is_behind` is true, the index already holds an action that the payer sent in a block the proof does not count (`indexed.newer_actions` lists it), and the nonce after the proven one may be used already: ask again a second later, and issue the reference from an answer where it is false. Even then the payer can act between your reading and their paying, and no answer shows an action that still waits for a block. The wallet then refuses the reference ("This payment quote reserved another nonce"), nothing is paid, and you issue a new one. **Keep looking for the old reference until its expiry all the same** (the query below, once for each reference you issued): the wallet refused it on what it knew of the payer's nonce at that moment, and that can turn out wrong. If the payer's other action never gets into a block, the old reference fits again and can be paid later, and a shop that asks for the new reference only never sees that payment. A reference that is never paid costs nothing.

Then look for the payment, **from that payer**:

```sh
curl -s "$API/v1/accounts/5/payments?reference=<64 hex>&from=7"
```

```json
{"source":"index","proven":false,"account":"5","order":"asc","has_more":false,"next_cursor":"210.0",
 "items":[{"hash":"0EA8…","height":"210","index":0,"time":"2026-11-09T22:18:24.816018Z","kind":10,"kind_name":"merchant_payment",
           "sender":"7","recipient":"5","amount":"2500000","reference":"…","transfers":true,"fee_micros":"1000","results_checked":true}],
 "index":{"indexed_height":"212","seconds_behind":1}}
```

**A reference does not name its payer.** The chain checks only that the nonce inside the reference is the sender's nonce and that it has not expired. Any account whose next nonce happens to be the same can pay with a reference it has seen, for any amount, before your customer does. So:

- always ask with `reference` **and** `from`;
- keep a record of the **hashes** you have credited, and credit each hash once. Never mark a reference as "used": that would let a stranger's payment of one microsecond block the real deposit;
- never take "the first payment with this reference" for the deposit. A payment from another account that carries your reference is that account's payment, like any payment without one.

An empty `items` means "not seen up to `index.indexed_height`". A misspelled parameter is refused (400), never ignored.

**All deposits, as they come.** Poll with a cursor, and keep the cursor with your own records:

```sh
curl -s "$API/v1/accounts/5/payments?limit=200"                    # first call: from the start
curl -s "$API/v1/accounts/5/payments?limit=200&cursor=210.0"       # then: what came after
```

The list is in chain order and only grows at its end, so a cursor never skips a payment that this index holds. When there is nothing new, `next_cursor` repeats your cursor.

**An index does not hold what lies below its start.** The list begins at `index.start_height`, which every answer carries. If the instance you poll is rebuilt with a later start (a new data directory on a node restored from a snapshot, say), the payments between your cursor and the new start are not in it. The service refuses such a cursor (409 `cursor_below_index_start`, with `index.start_height`) and never answers it from a later height without a word. Do not get around the refusal by starting again without a cursor: read the heights from your cursor up to that start from an index that holds them (another instance, or one built on a node that has those blocks, with a `start_height` at or below your cursor), credit what you find, and only then go on from the new start. The same holds for the very first call: a list read without a cursor says nothing about deposits made below `index.start_height`.

Instead of polling, configure a webhook for your account (`deploy/api/README.md`, "Webhooks") or read the stream:

```sh
curl -sN "$API/v1/stream?account=5"
```

With `account`, the stream carries the payments **to** that account (`direction=in`, the default). `direction=out` gives the payments it sends (your withdrawals), `both` gives both. A payment event has the fields of a list item under the same names (`sender`, `recipient`, `amount`, `reference`, `transfers`), plus `id` and `type`. The server ends a stream after 15 minutes, or earlier when places run out, with a `bye` event: reconnect with the id of the last event (`Last-Event-ID`, or `?after=`) and nothing is missed that the index holds. When too much was missed, or the id is from below the start of the index, the stream says so with a `gap` event that names the heights it does not send.

Both are at-least-once hints. Keep the poll as the source of truth: within the heights an index holds, the cursor cannot miss a payment, and a cursor from below them is refused, not skipped. A webhook covers the blocks made since it was configured, also those made while the API was down (they are sent when it is back); it does not cover the history before, a queue that overflowed, or an index that was rebuilt (webhooks then start again at the chain's height at that moment). If your deposit reader uses the stream, have the operator list its address in `reserved_stream_clients`: other readers can be put out when places run out.

### Deposits above the sender's daily limit (kind 75)

An account with security rules pays within a daily limit. Above it, the payment is asked for (`kind` 75, `request`), waits, and is completed by a second action (`kind` 75, `execute`). Large deposits arrive this way.

- **The request** is in your account's activity at once, with `"role": "pending"` and `"transfers": false`: `curl -s $API/v1/accounts/5/activity`. Nothing has moved, and the sender can still cancel. Do not credit it, and do not promise anything on it: anyone can make such a request to your account for one fee. Its `request_status` says how it ended as far as the index knows: `waiting`, `completed`, `cancelled`, `dropped` (a freeze or a replacement of the sender's keys took it), `ended` (settled together with other requests; completed or cancelled, the index cannot tell which), or `unknown` (the index does not follow this sender).
- **The completion** is in your payments list like any payment, with `"kind": 75` and `request_hash` naming the request, when the index could tie the two for certain: the sender had one request waiting. Credit it like any payment (step 2).
- **When it could not** (the sender had two or more requests waiting at once, or adopted the security rules before this index starts; an account that had them from its first block is followed from its first request, if this index holds it), the completing action has `"unattributed": true`, no recipient and no amount, and nothing appears in your payments. The money still arrived; your proven balance shows it. Handle it by hand:
  1. Ask the customer for two hashes: the request and the completion.
  2. Verify both as in step 2. The request must be kind 75 with `payload.type` `request`, `payload.to` your account and the amount. The completion must be kind 75 with `payload.type` `execute`, from the same account, in a later block.
  3. Show that this request is the one that was completed. Read the sender's activity (`/v1/accounts/7/activity?order=asc`) from its last action of kind 70, 72 or 74, or of kind 73 with a `replace` operation, before the request (after each of these nothing is waiting) up to now. In that span, list its requests in order, and the completions and cancellations of payments (kind 76 with `payload.type` `payment`; open each action to see its `payload.id`). If every request of the span is settled (completions plus cancellations equal the requests), sort the ids they name: the first request has the smallest id, the second the next, and so on. Your request was completed if its id is named by a completion. If the span holds an action the index could not decode (`opaque`), or does not start at one of those three kinds, this step proves nothing.
  4. Check your proven balance against your own books: it must hold a surplus of exactly that amount that nothing else explains.
  Credit once per completion hash, and only when step 3 is conclusive: the balance alone cannot tell two customers apart who claim the same surplus. If requests of the span are still waiting, ask the sender to complete or cancel them first.

## 2. Confirm it

Check, in this order:

1. **The item is what you expect:** `recipient` is your account, `sender` is the customer, `amount` is at least what you asked, `transfers` is true, and you have not credited this `hash` before.
2. **`results_checked` is true.** The next verified block has committed to a successful result for every action of this one. That takes about one block.
3. **The proof verifies with your own trust anchor.** Fetch the action:

```sh
curl -s $API/v1/actions/0EA89F53E44CB84A1A933EACA37F18061A8E6202F9BFE2747F4CC74C0D1E524E
```

`action.raw` holds the signed bytes (once). `verify` holds the block (`height`, `block_hash`) and the Merkle proof (`index`, `total`, `root_hash`, `leaf_hash`, `aunts`). With the SDK's light client and the installed verifier, and the RPC of a node (yours, ideally) for the header:

```js
import './client-v4/time-sdk.js';
import * as verifier from './client-v4/proof-verifier.mjs';
import { createLightClient } from './client-v4/light-client.mjs';
import { fetchLightBlock } from './client-v4/certified-view.mjs';
import { createRpc } from './client-v4/indexer.mjs';

const rpc = createRpc('http://127.0.0.1:26657/');
const light = createLightClient({ trust, verifier, fetchBlock: (height) => fetchLightBlock({ rpc, height }) });   // `trust`: your manifest
const { action, verify } = await (await fetch(`${API}/v1/actions/${hash}`)).json();
// The proof in the form of the node's own lookup, which the verifier takes.
const tx = { hash: verify.hash, height: verify.height, index: verify.index, tx: action.raw,
  proof: { root_hash: verify.root_hash, data: action.raw, proof: { total: verify.total, index: String(verify.index), leaf_hash: verify.leaf_hash, aunts: verify.aunts } } };
const checkpoint = await light.updateTo(verify.height);            // validator signatures, against your anchor
const receipt = await verifier.verifyFastReceipt({ tx, headers: [checkpoint.block.signed_header.header] }, { ...light.getTrust(), checkpoint });
const proven = TimeSDK.decodeAction(TimeSDK.hexToBytes(receipt.rawHex));   // decode the proven bytes yourself
// receipt.verified && receipt.executionVerified, and proven.from, proven.kind, proven.payload.to / amount / reference are what you credit on
```

A light client only moves forward. If yours is already past the payment's block, use a fresh one from the manifest, or ask a wallet gateway through the SDK instead: `TimeSDK.createClient({ gateway, trust, verifier }).waitReceipt(hash)` returns the same verified receipt for any height.

Credit on `proven`, not on the JSON of step 1. Record the hash: a hash you have credited once is never credited again.

A completion of kind 75 proves that the sender completed a waiting payment, not to whom: its bytes hold only an id. The index's `recipient` and `amount` for it follow from the sender's earlier actions (see above). To prove it yourself, verify the request it names (`request_hash`) as well, and the sender's actions in between.

## 3. Send a withdrawal

Sign with the SDK, submit the bytes, and keep the bytes. The one number to get right is the nonce.

**This step and step 4 are for actions that carry a nonce:** a transfer (kind 3), a payment to a shop (kind 10) and the two actions of a payment that waits (kind 75). Four kinds carry no nonce (the field is 0) and no authority epoch: a freeze (72), an operation approved by several keys, which includes a payment above the limit with a second proof (73), the finishing of a replacement of keys (74) and a cancellation (76). Nothing below that speaks of "the nonce" holds for them, and **step 4 must never be applied to them**: its first condition ("the account's nonce is at or above the one I signed") is true for nonce 0 from the start. What holds for them instead is in "Withdrawals above the daily limit".

### The nonce: count it yourself

Every action of those kinds carries the account's next nonce, and a nonce is used once. **Take the nonce from your own records, not from the chain.** The chain cannot tell you what you have signed: a proof shows the nonce one block behind the newest block, and neither a proof nor the index shows an action that still waits for a block. A signer that reads "nonce 17" twice signs two withdrawals with nonce 18, and only one of them can ever be included.

Keep one number per account, `next_nonce`, in the database that holds your withdrawals. Two facts carry everything that follows:

- **Two actions with one nonce can never both be included.** (A nonce of the kinds above, that is: the 0 in the field of the other four kinds is no nonce, and any number of those can be included.) So a second signature for a withdrawal under the *same* nonce is always safe, whatever became of the first: at most one of the two gets into a block.
- **A second signature under *another* nonce is how a customer gets paid twice.** It is safe only when the first bytes are known never to have been included and never to be includable. Step 4 says when that is known.

1. **A withdrawal gets its nonce and its signature once.** In one transaction of your database: take `next_nonce`, sign, store with the withdrawal the hash, the nonce, the signed bytes, the authority epoch you signed with, and the `state_height` of the account answer you read before signing (step 4 needs it: bytes cannot be in a block that was made before they existed), and add one to `next_nonce`. From then on these bytes are the withdrawal. Whatever happens when they are sent (no answer, an error, a restart of your signer), the same bytes are sent again. Anything else that is ever signed for this withdrawal carries that same nonce (point 3), until step 4 has shown that the withdrawal was not made and that its nonce is used.
2. **One at a time.** Send a withdrawal, and sign the next one only when this one was answered with something other than a refusal (the table below). Signing several ahead works (the node takes consecutive nonces in order), but then point 3 gets harder: read it first.
3. **A refused first sending gives the nonce back, and does not kill the bytes.** When the node refuses bytes that were never sent before (422 `rejected`: not enough balance, the daily limit, a frozen account, a recipient that does not exist), they are in no block, and they have not used their nonce. The refused bytes stay valid for as long as that nonce is free and the account's authority epoch is the one they were signed with: whoever has them can send them later, and the service you sent them to has them. So:
   - to try the same withdrawal again, send the same bytes again when the cause is gone;
   - to change it or drop it, or when the cause will not go away (a recipient that does not exist), and nothing was signed after it: the next action you sign for the account (the corrected withdrawal, or the next withdrawal) carries **that same nonce**. Set `next_nonce` back to it. This is always safe: of two actions with one nonce at most one is included. A corrected withdrawal then has two hashes under one nonce; keep both, look both up (step 4), and what is in a block is what happened. Treat the refused bytes as dead only when another action with that nonce is in a block and you have verified it (step 4), or when a proof shows the account's `auth_epoch` above the one they were signed with. Never give a withdrawal a second signature under another nonce while its first bytes could still be included: both would be paid;
   - if you had signed further withdrawals ahead, they were refused with it (a nonce is taken only after the one before it). Their bytes stay as they are, and `next_nonce` stays where it is. Sign one action with exactly the free nonce (the corrected withdrawal, or a payment of one microsecond to another account of yours), send it, and send the later ones again, the same bytes, in order. Do not renumber them.

   **An authority epoch that has moved kills every signature made before it, whatever its nonce.** Every action with a nonce names the authority epoch it was signed with, the node refuses one whose epoch is not the account's ("stale authority epoch"; for kind 75 "stale authority or incorrect nonce", the same words as for a wrong nonce), and the epoch only grows. It moves when an account adopts the security rules (kind 70), when a spend key adds or removes sign-in keys (71), when a replacement of the account's keys takes effect (kind 73 with a spend key among its approvers, or kind 74 after the wait), and, on an account without security rules, when its devices change or a recovery of the account is finished. When a proof of your account shows `auth_epoch` above the one a withdrawal was signed with, its bytes can never be included from then on. If the same proof shows `account.nonce` below the withdrawal's nonce, they never were, and their nonce is free: sign the withdrawal again under the same nonce with the new epoch (and the new key, after a replacement). Do the same for every withdrawal you had signed ahead of it, each under its own nonce: nothing else fills those nonces, and until they are filled every later action of the account is refused with "incorrect nonce". If the proof shows the withdrawal's nonce used, step 4 decides whether the bytes got into a block before the epoch moved.
4. **Where the count starts.** At the first withdrawal of an account for which nothing that was signed elsewhere can still be waiting, read it:

```sh
curl -s $API/v1/accounts/5        # "account": {"nonce": "17", "auth_epoch": "0", …}, "state_height": "…", "indexed": {"state_is_behind": false, "newer_actions": [], "last_sent": {…}}
```

   Set `next_nonce` to `account.nonce` plus one from an answer in which `indexed.state_is_behind` is false. When it is true, the index already holds an action that your account sent in a block the proof does not count yet (`indexed.newer_actions`), and the nonce after the proven one may be used already: ask again a second later.

   **After your records were lost** (a database restored from a backup, a signer set up anew) that reading is not enough, and nothing you can read makes it enough. Withdrawals that were signed after the backup may still be on their way: a node, or the service you sent them to, holds their bytes, and neither a proof nor an index shows an action that waits. A count set from the proof gives one of their nonces to a new withdrawal; the old bytes are included first; and later the old withdrawal, which the restored records show as not yet signed, is signed again and paid twice. So treat every signature the account has ever made as alive, and do this in order:
   1. Sign no withdrawal.
   2. **Move the account's authority epoch.** Sign one action that moves it: on a secured account kind 71 with a spend key (add or remove a sign-in key), or a replacement of the account's keys, which such a loss may call for anyway; on an account without security rules, add or revoke a device. Kind 71 and a change of devices carry `account.nonce` plus one and the proven `auth_epoch` (a replacement of keys carries no nonce). If an old withdrawal takes that nonce first, your action is not included: read the account again and sign it again with the next nonce. Go on until a proof shows `account.auth_epoch` above the one you started from. Signing it more than once does no harm: all it can do is move the epoch.
   3. From the `state_height` of that proof on, nothing with a nonce that was signed before can be included (point 3). Actions without a nonce carry no epoch. If the account has ever had a payment approved by several keys (kind 73), kind 71 does not end one that was signed before the loss: replace the keys instead. A replacement moves the version of the security settings that every such approval names, and nothing approved before it can be included after it.
   4. **Match every action the account sent** since the last record you trust against your withdrawals. Read the account's activity (`GET /v1/accounts/5/activity?order=asc`) from an index that covers that whole time: `index.start_height` at or below the `state_height` of your last trusted record, `index.indexed_height` at or above the `state_height` of the proof of step 2. Verify each action as in step 2 and mark the withdrawal it pays as paid, with its hash. An action that matches no withdrawal is a payment you have no record of: find out what it was before anything else is paid.
   5. Only then set `next_nonce` to `account.nonce` plus one, and sign the withdrawals that are still unpaid.
5. **When the chain is ahead of your count** (`account.nonce` is at or above `next_nonce`), something else used nonces of your account: a second signer, or a replacement of its keys. Find out what before you sign anything: `indexed.last_sent` (from an answer whose `indexed_height` has reached its `state_height`; before that the index may not hold the action yet) and the account's activity name the action, and step 2 verifies it. Then set `next_nonce` to `account.nonce` plus one. Two signers of one account need one count between them. The chain being behind your count is normal: your newest withdrawals wait for a block, or the proof is a block behind.

```js
import './client-v4/time-sdk.js';
const tx = await TimeSDK.signAction({
  networkId: trust.network_id, kind: 'transfer', from: '5',
  nonce: '18',                       // next_nonce, from your own records
  authEpoch: '0', publicKey,         // account.auth_epoch, and the hex of the spend key's public key
  payload: { to: '7', amount: '2500000' },
}, privateKey);                      // an Ed25519 CryptoKey; it never leaves your signer
const hash = await TimeSDK.transactionHash(tx);
console.log(hash, TimeSDK.base64(tx));
```

Store the hash, the nonce, the signed bytes, the authority epoch and the `state_height`, and advance `next_nonce`, **before** sending. Then:

```sh
curl -s -X POST $API/v1/transactions -H 'Content-Type: application/json' -d '{"tx":"<base64>"}'
```

| Answer | Meaning | Do |
|---|---|---|
| 202 `submitted` | The node took it into its waiting list. Not yet in a block | Go to step 4 |
| 200 `already_included` | These bytes are in an indexed block (the answer names its height) | Go to step 4 to verify it |
| 409 `already_submitted` | The node has these bytes already: in its waiting list, or in a block (a node remembers for a while what it has taken) | Go to step 4 |
| **No answer** (a timeout, a connection that dropped, an answer you could not read) | The node may have the bytes, or not | Send the same bytes again. If the node took the first sending and they still wait, the second is answered 409 `already_submitted` (the live check of 2026-11-18 got this one); if they are in an indexed block by then, 200 `already_included`; if the first never arrived, 202 `submitted`. In each case go to step 4. Sign nothing |
| 409 `nonce_used` | The index holds another action of your account with this nonce; `used_by` names it. This is the index's word | First verify `used_by.hash` as in step 2, and check in the proven bytes that it is an action of your account (`from`) with this nonce. Only then are your bytes dead: a nonce is used once. Then your records decide whether the withdrawal is paid. `used_by.same_content` is true when that action has the same kind and payload: it is this withdrawal under another signature, or another withdrawal of yours to the same recipient for the same amount. **A hash settles one withdrawal:** if `used_by.hash` already settles another withdrawal of yours, this one is not paid; if it settles none, record it for this one, which is paid. With `same_content` false this withdrawal is not paid. A withdrawal that is not paid is signed again with `next_nonce` |
| 502 `node_unavailable` | The node did not answer, or answered with an error. It may have taken the bytes all the same | Send the same bytes again |
| 422 `rejected`, for bytes you send **for the first time** | The node refused them, and they are in no block; `message` says why (not enough balance, the daily limit, a frozen account, a recipient that does not exist, a wrong nonce, a stale authority epoch) | The bytes have not used their nonce, and they stay valid for as long as it is free and the authority epoch has not moved: "The nonce", point 3. For "incorrect nonce", "stale authority epoch" and "stale authority or incorrect nonce", read your account. If `account.auth_epoch` is above the one you signed with, the bytes are dead (point 3, the authority epoch). If not, an earlier withdrawal of yours has not reached the node (send that one again first, then this one, the same bytes), or the chain is ahead of your count (point 5; whether these bytes can still be included is decided by step 4 alone) |
| 422 `rejected`, for bytes you have **sent before** | Nothing yet. A node refuses bytes that are already in a block with "incorrect nonce", because they used that nonce themselves, and the index may not have reached that block | Go to step 4, and sign nothing under another nonce. If step 4 does not find them in a block and the node goes on refusing them for a cause that will not go away (the first sending never arrived, and this is in truth the first refusal), the replacement is signed under the same nonce (point 3) |
| 400 | This service, or a proxy in front of it, refused the request: the body is not `{"tx": …}`, the bytes are not an action the service's SDK can decode, they are for another network, or the signature is not the key's | Fix the request. **A 400 judges the request, not the chain:** it does not say that these bytes can never be included (a node may know a kind this service does not), so sign nothing under another nonce because of it. If you must replace the bytes, sign under the same nonce (point 3) |

Sending the same bytes twice is safe: an action is included once. **Signing a second action for the same withdrawal is how a customer gets paid twice.** Do it under the same nonce ("The nonce", point 3), or after step 4 has shown that the first was never included and never can be.

The same content signed again is, as a rule, not the same bytes. A second spend key, a signer that has lost its records and takes another nonce (a restart, a failover), or a signer that adds randomness to its signatures gives other bytes and so another hash, and looking up the new hash finds nothing although the payment is made. (The SDK under Node gives the same signature for the same key, nonce and content; other signers do not, and nothing in this guide rests on two signatures being equal.) So before signing under another nonce, always find out **which action used the nonce**: send the bytes again and read the answer (409 `nonce_used` names it), or look for the nonce in your account's activity (`GET /v1/accounts/5/activity`; every item has its `nonce`), and verify that action as in step 2. If it has the same recipient and amount and its hash does not already settle another withdrawal of yours, it is this withdrawal: paid. Two withdrawals to one customer for the same amount look the same on the chain; your records tell them apart, one hash each.

### Withdrawals above the daily limit

A secured account pays within its daily limit (`v5/README.md`, "Account security"). A transfer above what is left of it is refused (422, "over the daily limit of this account"); its bytes stay valid and go through when the limit has refilled ("The nonce", point 3). **Keep withdrawals within the limit where you can:** set the limit of the paying account to what it pays out in a day, and let a larger withdrawal wait for the refill or go out in parts. Steps 3 and 4 then hold as they stand. Above the limit there are two ways, and neither is a transfer.

**A transfer that was refused for the limit is not dead.** Its bytes go through as soon as the limit has refilled far enough, whoever sends them then. Before the same withdrawal is paid another way, those bytes must be dead. The `request` of a payment that waits takes the transfer's own nonce ("The nonce", point 3), and that is enough: of the two at most one is included. A payment by second proof carries no nonce, so before its approvals are collected another action is signed under the transfer's nonce and verified in a block. The same holds between the two ways: a withdrawal is not paid by second proof while a request for it waits (cancel the request first, kind 76, and verify the cancellation), and not requested while a payment by second proof for it can still be included.

**The payment that waits (kind 75).** Two actions, each with a nonce, so "The nonce" and step 4 hold for each of them as for a transfer:

1. `request` (`payload: { type: 'request', to, amount }`). When it is in a block (step 4), the payment is **requested, not paid**: nothing has moved. For a request, 200 `already_included`, and 409 `nonce_used` with `same_content` true, mean "requested". The chain gives the request an id and holds it in the account's security row (at most four at a time). It can be completed from `ready_elapsed_micros` on: the time of the request's block plus the account's `delay_seconds`.
2. Read the id from the proven state: `GET /v1/accounts/5/state` lists what waits under `security.pending_payments`, each as `{ id, to, amount, ready_elapsed_micros }`. Make one request at a time, note the id that appeared with it, and store it with the withdrawal: one withdrawal, one id.
3. `execute` (`payload: { type: 'execute', id }`), once the time of the state has passed `ready_elapsed_micros`. **The withdrawal is paid when an `execute` that names its id is in a block,** verified as in step 2 with `results_checked` true. An id is completed once: a second `execute` for it is refused ("no such waiting payment") whatever its nonce, so signing `execute` again for the same id cannot pay twice. A second `request` can: it is a second payment that waits. Before you execute an id, make sure no other id of yours waits for the same withdrawal, and cancel the one that does (kind 76, `{ type: 'payment', id }`).
4. A payment that waits can end unpaid: any spend or recovery key cancels it (kind 76), and a freeze (72) or a replacement of the keys (73, also one that only starts to wait) drops everything that waits. When the id is gone from `security.pending_payments`, find what ended it before you request again: your `execute` in a block (paid); a cancellation that names the id (not paid; verify it as in step 2); or a freeze or replacement in a block after the request's whose time is before `ready_elapsed_micros` (not paid: before that time nothing could complete it; verify it as in step 2). After that time a freeze or replacement does not tell you: whether an `execute` came before it is a question to an index, and step 4 says which index may answer it. The index's own reading is `request_status` of the request, in the account's activity.

**On a network whose waits survive a stop** (`waits_survive_stops` in its genesis; `v5/README.md`, "Waits that survive a stop"), `ready_elapsed_micros` is not a time of the chain. It is a moment on the clock of the waits: the time of the state minus `stopped_micros`, the total of the chain's stops, which the metadata row of every proven state carries. Wherever the four steps above compare a time with `ready_elapsed_micros`, compare that clock (`TimeSDK.securityNow(state)`). Over HTTP it is `security_clock.now_elapsed_micros` of `GET /v1/accounts/5/state`, from the same proof as `security.pending_payments`. Otherwise an `execute` sent after a stop of more than five minutes comes too early and is refused ("the waiting period is not over"). On a network without the setting, and for the expiry of approvals below on every network, the time of the state is what counts.

**The second proof (kind 73, `pay`).** A spend key and as many recovery keys as the account's threshold still asks for (one, with a threshold of 2) approve the payment, and it is included at once, outside the limit. It carries no nonce, so none of the rules above protects it, and step 4 must not be applied to it. What holds instead:

- Store with the withdrawal the hash, the bytes, `expires_elapsed_micros`, and the version of the security settings that the approvals were made for (`version` in `approve`, `client-v4/account-security.mjs`; it is `security.version` of the state that was read).
- **It is paid when its hash is in a block,** verified as in step 2. Sending the same bytes again is safe, as for any action.
- A 404 for its hash says "not in a block this index holds", and nothing more. While it waits, the conditions of step 4 would all read as met.
- Its bytes are dead once a proof shows a state time past its `expires_elapsed_micros` (`state_time_micros` minus the manifest's `genesis_time_micros`), or shows `security.version` above the version it was approved for. Every operation approved by several keys moves that version, so **of two operations approved for one version at most one is ever included.**
- So a replacement (a later expiry, say) is approved for **the version you stored**, never for a version read anew: then at most one of the two can be included, whatever became of the first. Approvals for a new version are a second payment unless the first is dead **and** was never included, and "never included" is, as always, more than a 404: conditions 2 to 4 of step 4 on an instance of your own, with the proof that shows the bytes dead in the place of the first condition.

## 4. Look it up

```sh
curl -s $API/v1/actions/<hash>
```

- **200:** this index holds it, in block `action.height`. Wait for `results_checked`, then verify it as in step 2: the withdrawal is paid when its proof verifies with your own trust anchor, not when an index says so. Record the hash as what paid it.
- **404:** not in the index between `index.start_height` and `index.indexed_height`. It may be waiting, in a block the index has not reached, or in a block below the start of this index. Ask again; a block takes about a second. If it stays 404 and the node may have lost it (a restart), send the same bytes again.

**When may you conclude that it was never included and never will be?** Only for an action that carries a nonce. And the shortest way is a proof, not an absence: **find the action that used the nonce.**

1. A proof of your account shows that the nonce you signed is used: `GET /v1/accounts/5` gives `account.nonce` at or above it. Verify that proof yourself (`proof.view_proof`, as the answer's `proof.how` says; with the SDK, `client.getVerifiedState`). Note its `state_height`, S, and its `account.auth_epoch`.
2. Look for another action of your account that carries the nonce: in the account's activity (`GET /v1/accounts/5/activity`; every item has its `nonce`), or by sending the bytes again (409 `nonce_used` names it as `used_by`). **Verify it as in step 2, and check in the proven bytes that `from` is your account and `nonce` is this nonce.** That is a proof and needs no more: a nonce is used once, so your bytes were never included and never will be. Then your records decide, as in the table: if that action makes the same payment and its hash does not already settle another withdrawal of yours, it is this withdrawal under another signature, and it is paid; otherwise this withdrawal was not made, and is signed again with `next_nonce`.

**If no action that carries the nonce is found,** what is left is an absence, and an absence is the word of the index that reports it: nothing proves that an action is *not* in a block. Draw a conclusion from it only on an instance of the API that you run yourself, on a node of your own, and only when all four hold:

1. The proof above: the nonce is used, at `state_height` S.
2. The index has reached that state and does not hold the hash: `GET /v1/actions/<hash>` answers 404 with `index.indexed_height` at or above S. If the index is below S, wait and ask again; nothing can be concluded yet. The height that counts is the `index.indexed_height` of that 404 itself. The account answer also shows an `indexed_height`, but that is where the index was when the account was read: it says nothing about a 404 you received before. Read the account first and look the hash up afterwards, or compare with the 404's own height.
3. The indexer is not stopped by a fault: `GET /v1/health` does not list `indexer_fault`. (A stopped indexer never reaches S.)
4. **The index covers the whole time since you signed:** the `index.start_height` of that 404 is at or below the `state_height` you stored with the bytes when you signed them. An index that starts later (an instance rebuilt after its data directory was lost, on a node restored from a snapshot) says nothing about the blocks before its start: a withdrawal that is in one of them meets the first three conditions exactly like one that was never included.

Then the index holds neither your bytes nor any action with their nonce, although the nonce is used. Only one thing uses a nonce without an action that carries it: a replacement of the account's keys taking effect, and that always moves `account.auth_epoch` on (`v5/src/security.rs`, `install`). So look at the authority epoch of the proof:

- **It is still the one you signed with.** No replacement happened. An action used the nonce and this index does not show it; it may be your withdrawal. **Conclude nothing,** sign nothing, and find out what is wrong with the index.
- **It is above the one you signed with.** Your bytes are dead in any case (point 3 of "The nonce"). A replacement of the keys may have used the nonce: look for it in the account's activity, in a block above the `state_height` you signed at (kind 73 with a `replace` operation, or kind 74; open the action to see its payload), and verify it as in step 2. If it is there, then with the four conditions met your bytes were not included before they died: the withdrawal was not made. Sign it again with `next_nonce` and the new epoch. If it is not there either, this index does not show what used the nonce: conclude nothing.

Until then, a 404 only says where the index is. The nonce comes from the newest state of the chain and the 404 from an index that can be behind it, so "nonce used, hash not found" alone is exactly what a withdrawal looks like that went through one block ago.

If the nonce has not moved (`account.nonce` is below the one you signed), the bytes are in no block. They are still valid if `account.auth_epoch` is the one you signed with: send the same bytes again. If the epoch has moved they are dead and their nonce is free: sign the withdrawal again under the same nonce ("The nonce", point 3).

The customer can check the withdrawal the same way, from their side: `GET /v1/accounts/7/payments?from=5`.

## Networks with the account-safety settings

A network's genesis may carry three settings (`spec/settings.md`). Every proven state carries them: `TimeSDK.distinctNames(state)`, `TimeSDK.waitsSurviveStops(state)` and `TimeSDK.protectedRegistration(state)` read them. On a network without them nothing in this guide changes. With them:

- **Names that look alike (`distinct_names`).** A new name that looks like an existing one (`paypa1` beside `paypal`) is refused. Nothing changes for you: find and credit deposits by account number and by the payer's number (`from`), never by a name.
- **Waits that survive a stop (`waits_survive_stops`).** The moments in a security row are on the clock of the waits, the chain's time less the total of its stops (`stopped_micros`), not on the chain's time ("Withdrawals above the daily limit"). For your own paying account: compare `ready_elapsed_micros` and `frozen_until_elapsed_micros` with `security_clock.now_elapsed_micros`; as a date, a moment is itself plus `stopped_micros` plus the genesis time, and while it has not come that date is the earliest it can come ("not before"). The expiry of approvals you sign stays on the chain's time. An alert watch for your account (`deploy/watch/README.md`) counts the same way.
- **Accounts protected from their first block (`protected_registration`).** A customer's account may have been registered with its keys in their roles and a daily limit (kind 45, `kind_name` `register_protected`). The registration has no sender and moves nothing, so it is in no account's activity. Such an account pays within its daily limit from its first block: a larger deposit from it arrives as a payment that waits (kind 75, "Deposits above the sender's daily limit"). The index follows it from its first request, which carries nonce 1, and ties a completion to its request as for any followed account. Your own paying account on such a network is best registered so (a wallet does it with `client.registerProtected`, `client-v4/README.md`), so that no key of it ever holds every power.

## Limits and errors

- 429 `rate_limited`: wait `Retry-After` seconds. Each client address has a budget (60 at once, 20 more a second, unless the operator set it otherwise). A list or a block takes 1 from it; an action by hash, an account and every other answer that comes with a proof take 5; a submission or a stream 10. The table of routes in `deploy/api/README.md` has each one.
- 503 `state_unavailable`: no fresh proof of the state could be had (the node is behind or unreachable). Indexed routes still answer.
- `/v1/health` 503 with `index_behind`: the index is older than the operator allows. Do not conclude that a deposit is missing; wait.
- 409 `cursor_below_index_start`: your cursor is from below the start of this index (step 1, "An index does not hold what lies below its start"). Read the missing heights from an index that holds them before you go on without a cursor.
- Pages hold at most 200 rows. Every parameter has one accepted form, listed in `GET /v1/openapi.json`.

## What has run

On 2026-11-18 a script followed the steps of this guide, as they were then, against the API on a live test network (seven validators in two regions on AWS): the service was checked (step 0); a deposit by reference and sender was found, waited for and credited on its proof; deposits were polled with a cursor and announced by webhook; a withdrawal whose answer was dropped was sent again as the same bytes (the second sending was answered 409 `already_submitted`), looked up, verified and paid once; and bytes with a used nonce were concluded never to be included, on the three conditions step 4 had then, with the action that used the nonce found in the index. That was one run of about two minutes, with honest services, one index built from height 1, and plain transfers from an account without security rules.

That run read the nonce of the withdrawal from the proof of the account, as this guide then said. What was written after it:

- **Run on a second live network of the same kind, later on 2026-11-18** (the harness's check, `campaign/lib/services-check.mjs`: 52 of 52 steps in about two minutes, with the state of each account proven). Of "The nonce: count it yourself": points 1 and 2, point 3 as far as one refused first sending and its replacement under the same nonce, the first reading of point 4, and point 5 with a second signer. Also the row for 409 `nonce_used` with the named action verified; and the fourth condition of step 4 against a second instance with a later start, with the refusal of a cursor from below that start.
- **Under the API's own tests only:** an account answer whose proof is behind the index. In that run `indexed.state_is_behind` was read in every account answer and was never true.
- **Run nowhere:** withdrawals signed ahead of a refused one (point 3, last item); an authority epoch that moved (point 3); the procedure after a loss of records (point 4); a replacement of keys that used the nonce (step 4); keeping an old reference in view until its expiry (step 1); and everything in "Withdrawals above the daily limit". These rest on the engine's rules as read in `v5/src/security.rs` and `v5/src/engine.rs` and on a review, not on a run. Of "Networks with the account-safety settings", what the harness's check does ran on 2026-11-23, on laboratory networks on AWS with those settings: its 52 steps passed on three of them, one after a stop of the chain of nine minutes, with `security_clock` read against verified state (`AUDIT-2026-11.md`, "Run on AWS and in a real browser (23 November 2026)"). The rest of that section, a deposit from an account protected from its first block and the index following such an account, rests on the API's and the SDK's own tests.

No exchange has integrated by this guide, and none of it has run for longer than minutes or under load.
