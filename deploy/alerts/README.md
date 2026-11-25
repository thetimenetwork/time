# Alert service

A wallet whose page is closed cannot read its account. This service wakes it: when a verified block includes an action that changes the keys or the security rules of an account, or starts a wait on it, every browser subscribed to that account gets one push, and the wallet's service worker shows a fixed sentence: "Open your wallet to check your account." What happened is never in the push. The owner opens the wallet, the wallet reads its account's state with a proof, and it says what that state says ([`web-v4/wallet/alerts.mjs`](../../web-v4/wallet/alerts.mjs)).

It holds no key of any account and signs nothing on the chain. Its only key is its own VAPID key, with which it tells the browsers' push services who sends.

## What it does, and what it does not

- **A push carries the constant `{"v":1}`**, encrypted for the browser as Web Push requires (RFC 8291, content coding `aes128gcm` of RFC 8188, signed with VAPID of RFC 8292). The service worker ([`web-v4/wallet/sw.js`](../../web-v4/wallet/sw.js)) ignores it and shows its own words. Nobody can make text of their own reach a person's screen through this service: there is no text to send.
- **Who is woken:** the account that sends an action of its keys or security rules (kinds 8, 9, 11, 14, 15, 16 of protocol 4, and 70 to 77), and the account a guardian's consent or approval names (12, 13). [`client-v4/touches.mjs`](../../client-v4/touches.mjs) lists them and says why. An action of one of the sender's kinds whose payload this service cannot read (a node newer than it) still wakes its sender. Only a key of the account, or a guardian the account itself named and who accepted, can cause one of these: a stranger cannot make a person's phone ring. **A payment wakes nobody**, in either direction.
- **Only a verified block wakes anybody.** Before any push for block h, the service checks with its light client that the header of h is the one the verified header of h + 1 names, that the actions are those the header commits to, and that h + 1 commits to successful results for every one of them. So it reads a block once two more exist: a push comes two or three blocks after the action (a few seconds on the test network). A block that wakes no subscribed account costs one read of the block and nothing more.
- **Every block, in order.** At start the service begins after the newest block: nobody is woken for the past. From then on it reads every block in order, however far behind it falls (a slow node, a long verification, a burst of blocks that wake subscribed accounts): it never leaves a block out, because the action in it may be a theft whose wait is still running, and a push minutes late is worth more than none. More than 120 blocks behind, the log says so once a minute, with the count.
- **Nothing is kept for a wallet, and nothing is sent again.** A push that cannot start at once waits in memory for a free place, for a minute at most (below); a push that fails is not sent again. A wallet that missed one loses nothing, because it reads its state when it opens. Only the address list is written down.
- **One push per browser per block**, also for a browser subscribed to two accounts that the block wakes. The `Topic` header lets a push service keep only the newest one for a phone that is off.

### The pushes: places, turns, waiting

A thief who controls a block (he sends the action that matters, and can put actions of his own accounts before it) must not be able to make the owner's push not arrive. So:

- **No push is dropped because others are under way.** At most **64** are under way at once, and at most **2 of one account**. A push that cannot start waits in memory for a free place.
- **Accounts are served in turn.** Every account a block wakes gets its first push started before any account gets its second, and so on. This holds across blocks: an account stays in turn for as long as it has pushes waiting or under way, so an account woken again while its earlier pushes are still under way gets no new first place. The accounts of one block are put in line in a random order: the order of the actions in the block, which whoever sends them chooses, gives nobody a place.
- **Inside one account**, browsers go oldest subscription first. A browser already waiting is not put in line twice.
- **Each push gives up after 5 seconds.** A push service answers in well under a second; 5 seconds leave room for a slow network, and they bound what slow push services can hold: 64 places for 5 seconds at most, and one account's eight browsers hold two of them.
- **A push that waited a minute** for a place is abandoned, counted (`pushes_abandoned`), and the log says how many, with no account and no browser in it.
- **The line holds at most 50,000 pushes**, as many as the address list can hold (a browser waits once). When it is full, the newest push of the account with the most waiting is abandoned to make room, never an account's only one; when every account has at most one waiting, an account's first push is still taken.
- **The bound.** The first push of an account a block wakes starts within T x (1 + ceil(A / 64)) of the block being read, T being 5 seconds and A the accounts whose first push waits before it. Only accounts of the same block can wait before it (an account of an earlier block already had its first push), and their order in the block counts for nothing. A stranger who leads every block with forty accounts of his own, eight browsers each that never answer, delays the owner's first push by 2T at most (`client-v4/alert-push-audit.test.mjs`). Waking an account takes an action of that account in a block: a freeze costs no fee but can be placed again only in the second half of the one before; every other action that wakes costs a fee.

### Removals: the browsers concerned hear of them first

- **"Off on every browser of this account"** (unsubscribe with a proof) wakes every browser of the account, waits for those pushes (at most twice a push's time limit, 10 seconds), and only then removes them. The proof is the login key's, which may be in a thief's hand: the owner's browsers hear of it. The browser that asked is woken too.
- **A browser that turns itself off** (unsubscribe by its push address) is removed, and the other browsers of every account it followed are woken. Whoever holds that address (it is in the browser's storage) can do the same, and the owner's other browsers hear of it.
- **A ninth browser is refused**, with `409 {"error":"full"}`: nothing is pushed out to make room. The wallet then tells its owner to turn alerts off on every browser and on again.
- **A browser can ask whether it is still subscribed** (`POST /alerts/v1/status`), so that the wallet's switch says "on" only while it is.
- **The wakes before removals go first**, ahead of the pushes of the blocks, but take at most half of the places (32): each costs whoever causes it a proof or a subscription, and the pushes of the blocks always keep the other half. At most 1,024 wait; when that many wait, a removal is refused with 503 ("try again in a moment") rather than done without its wake.
- **A push service that answers 404 or 410** has that browser removed, from every account, without a wake: it says the browser's subscription no longer exists.
- **When a login key is removed from an account, the subscriptions it made stay.** They are the account's: removing them would let a thief who holds the payment key silence the owner by replacing the login key. An owner who changed keys after a theft should turn alerts off on every browser and on again, with the new login key: the old browsers, the thief's among them, are woken and removed.

### What the push services learn

The browser's push service (Google's for Chrome and most Android browsers, Apple's for Safari, Mozilla's for Firefox, Microsoft's for Edge on Windows) sees when a browser is woken, and by whom (this service's VAPID key and contact). The pushes come a few seconds after public blocks that hold an action of an account: over a few events the push service, which knows who uses that browser, can tie that person to an account number. The content (`{"v":1}`) is encrypted for the browser and tells it nothing. A person who does not want that tie should not turn alerts on.

### What a thief with the login key can still do

The login key (the login password with the browser's storage, or the backup file with the login password) proves a subscription. With it a thief can:

- **Fill the account's eight places first** with browsers of his own. The owner's browser is then refused ("full"). The owner turns alerts off on every browser (the thief's browsers are woken and removed) and on again; the thief can fill the free places again, but cannot push the owner out.
- **Remove the owner's browsers** with "off on every browser". They are woken first: the owner hears of it, and the wallet's switch says that alerts are off.
- **Go first inside the account.** Oldest subscription first means that browsers he subscribed before the owner's are pushed before it, two at a time: with push services that answer, a fraction of a second; at worst 4 x 5 seconds behind his eight that never answer. He cannot make a push service slow on purpose: an address must be on a host of a known push service, which answers fast.

No rule of this service tells the owner's browser from the thief's: both are proven by the same key. What ends it is a new login key (with the payment password, under Keys), then alerts off on every browser and on again. The same holds for whoever has the browser's push address, which removes that one browser (its other browsers hear of it).

## Running it

Node 26 and this repository's `client-v4/` and `web-v4/shared/verifier/` (the installed proof verifier). It uses no npm packages.

```sh
cp deploy/alerts/config.example.json /etc/time-alerts/config.json   # then edit it
node deploy/alerts/start.mjs /etc/time-alerts/config.json
```

| Setting | Meaning |
|---|---|
| `rpc_url` | The CometBFT RPC of a node of the network: `https://`, or `http://` on this machine only. An origin, nothing after it. |
| `trust` | The trust manifest, the same object the SDK's `createClient({trust})` takes, installed from a source independent of the node. |
| `data_directory` | Where it keeps its files (below). One service per directory. |
| `origin` | **The wallet's public origin**, such as `https://wallet.example`. The wallet's pages call this service from there, every proof of a subscription names it, and a request from another origin is refused. |
| `hosts` | Extra `Host` values answered. The host of `origin` always is, and the loopback address with the port. |
| `port`, `host` | Where it listens. Default `127.0.0.1:8950`. |
| `trusted_proxies` | The addresses of your reverse proxies: for a request from one of them the caller is read from `X-Forwarded-For` (from the right), as the API does. The rate limit is per caller. |
| `contact` | An `https://` address where the operator can be reached, which the push services see in every token (`sub`). Default: `origin`. |
| `rate_limit` | `{per_second, burst}` per caller. Default 2 and 30. Reading the key takes a fifth. |
| `rpc_timeout_seconds` | Each request to the node gives up after this long. Default 10. |
| `max_subscriptions` | The address list holds at most this many browsers. Default 50,000. |

### Its files

In `data_directory`, and nothing else:

- `subscriptions.json`: the address list. For each browser: the account, the push service's address of the browser (its endpoint), the browser's two public keys (`p256dh`, `auth`) and when it subscribed. Written whole to a temporary file, flushed, and renamed; readable by the service's user only where the system has such modes. One write at a time: changes made during a write go into the next one, of which at most one waits. In memory the list is indexed by account and by browser, so a subscription costs time in proportion to that account's browsers, not to the list.
- `vapid.json`: the service's own VAPID key, made at the first start. Keep it: a new key makes every browser's subscription worthless (the push services refuse it), and the wallets must subscribe again.
- `checkpoint.json`: the newest block headers its two light clients verified (one for blocks, one for the reads that check a proof). The trust anchor of a network expires after seven days: without this file, a service that starts again after a week could verify nothing. It holds no account, endpoint or event. Written at most every ten minutes and when the service stops.
- `watch.lock` while it runs (the lock of [`deploy/watch/start.mjs`](../watch/start.mjs)), so that a second instance does not send everything twice.

A damaged `subscriptions.json`, or one of another network, stops the start: nothing is guessed. Remove it to start with an empty list; the wallets subscribe again when their owners turn alerts on.

## The routes

Under `/alerts/v1/`, JSON, from the wallet's own pages. Every route is rate-limited per caller (an IPv4 address or an IPv6 /64). A refusal is `{"error": "<words>"}` with its status: 400 (a body that is not what the route takes), 403 (a proof that does not hold, or a page of another origin), 404, 405, 409, 413, 415, 421 (another host name), 429, 503.

| Route | Body | Answer |
|---|---|---|
| `GET /alerts/v1/key` | none | `200 {"public_key": "<base64url, 65 bytes>"}`: the VAPID public key, which the page gives to `pushManager.subscribe` as `applicationServerKey`. |
| `POST /alerts/v1/challenge` | `{"action":"subscribe","subscription":{endpoint, keys:{p256dh, auth}}}` or `{"action":"unsubscribe"}` | `200 {"purpose":"login","origin","networkId","nonce","issuedAt","expiresAt"}`: a login challenge for `origin`, bound to that request, valid for three minutes, used once. `subscription` is what `PushSubscription.toJSON()` gives (`expirationTime` may be in it). |
| `POST /alerts/v1/subscribe` | `{"proof":{message, signature},"subscription":{...}}` | `200 {"subscribed":true,"account":"<number>"}`. `proof` is `TimeSDK.signLogin(challenge, ...)` by the account's sign-in key. `409 {"error":"full"}` for a ninth browser of the account; 409 too for a browser that follows 16 accounts already; 503 when the list is full. |
| `POST /alerts/v1/unsubscribe` | `{"endpoint":"<push address>"}` | `200 {"removed": n}`: that browser, from every account; the other browsers of those accounts are woken. |
| `POST /alerts/v1/unsubscribe` | `{"proof":{...}}` made for `{"action":"unsubscribe"}` | `200 {"removed": n}`: every browser of the account, each woken first (the answer comes once those pushes were tried, 10 seconds at most). |
| `POST /alerts/v1/status` | `{"endpoint":"<push address>"}` | `200 {"subscribed": true}` when that browser is subscribed to any account, else `{"subscribed": false}`. No proof: knowing the address is the capability, as for unsubscribing by it. It never says for which account and never repeats anything. |
| `GET /alerts/v1/health` | none | `200 {"ok":true}` to anyone. The counts (below) only to the machine itself: a request from the loopback address, under the loopback host name (`127.0.0.1:<port>` or `localhost:<port>`), with no `X-Forwarded-For`, `Forwarded` or `X-Real-IP`. |

The counts of the health answer for the machine itself: `ok`, `network_id`, `followed_height`, `behind` (blocks), `subscriptions`, `accounts`, `pushes_waiting`, `pushes_in_flight`, `pushes_sent`, `pushes_failed`, `pushes_abandoned`, `subscriptions_gone`, `blocks_read`, `blocks_verified`, `blocks_refused`. They are not public because they tell who has alerts on: wake an account, then watch the pushes counted. The test network's supervisor asks `http://127.0.0.1:8950/alerts/v1/health` directly ([`testnet/services.mjs`](../../testnet/services.mjs)).

It never answers with, and never logs, an endpoint or a key of a browser.

### The proof

A subscription is asked for by whoever holds the account's sign-in key, proven as a website login is ([`client-v4/server-auth.mjs`](../../client-v4/server-auth.mjs), `verifyLogin`): the challenge is this service's, for `origin`; the message is signed by a key the account has in a **verified** state, at its authority epoch; and the login rule of the wallet library lets that key sign in now. So on an account with security rules only its sign-in key subscribes (not the payment key, not a recovery key), and nobody subscribes while the account is frozen. A challenge is used once, whether the proof checks or not, and binds the request it was asked for: a proof made for one browser does not subscribe another, and a proof made to subscribe does not unsubscribe. At most 8 browsers per account. One browser follows at most 16 accounts.

**A challenge keeps nothing in the service.** Its nonce is 16 random bytes and a tag of 16 bytes: an HMAC, under a key made when the service starts, over the random bytes, the request's binding, the challenge's two times, the origin and the network. A proof brings the challenge back in its message; the tag shows that this service made it, for that request, and when. Only nonces that were used are remembered, until they expire, at most 20,000: past that the one used longest ago is forgotten and a floor rises to the time its challenge was given out, and every challenge given out at or before the floor is refused. A forgotten nonce can never serve again (its time is at or below the floor, which only rises); the cost is that challenges given out before the floor and not yet used must be asked for again. Asking for challenges, from however many addresses, fills nothing. A restart makes a new key: challenges given out before it are refused, and the wallet asks again.

### The address of a push service

The endpoint of a subscription must be `https://` on a host of a known browser push service, written as browsers write it, port 443: `fcm.googleapis.com` (Chrome, and most browsers on Android), a host under `push.services.mozilla.com` (Firefox), under `push.apple.com` (Safari, and a web app on the Home Screen of an iPhone), under `notify.windows.com` (Edge on Windows). Anything else is refused, so that this service can be made to call no other address. No redirect is followed, and every push gives up after 5 seconds.

## How the wallet reaches it

The wallet's page may connect to its own origin only (`connect-src 'self'`). So this service is reached under the wallet's own host name, at `/alerts/`: the reverse proxy in front of the wallet's gateway passes every path that starts with `/alerts/` to this service, with the wallet's host name, and sets `X-Forwarded-For` to the caller's address. The public test network does that in [`testnet/proxy.mjs`](../../testnet/proxy.mjs) once its note turns the service on (`testnet/README.md`). Nothing changes in the page's Content-Security-Policy. Without the route, `/alerts/v1/key` answers 404 from the gateway, and the wallet says that alerts are not offered here.

With nginx in front, inside the wallet's `server` block (the proxy's address goes in `trusted_proxies`, here the same machine):

```nginx
location /alerts/ {
    proxy_pass http://127.0.0.1:8950;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    # The caller's own address, set here, never taken from the request: every caller is counted on its own.
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Forwarded "";
    proxy_set_header X-Real-IP "";
    client_max_body_size 8k;
}
```

`X-Forwarded-For` must be the caller's address (`$remote_addr`), not an empty value: with it empty, every caller is the proxy, and one caller's rate limit is everyone's.

## Limits

- A request body: 8 KiB. Proofs checked at once: 8 (each reads a verified state). Used nonces remembered: 20,000. Pushes: 64 under way, 2 of one account, 5 seconds each, a minute of waiting at most, 50,000 waiting. Wakes before removals: 32 under way at most, 1,024 waiting; a removal waits 10 seconds at most for its wake.
- The service follows one node. A node that lies can withhold blocks (then nobody is woken) but cannot make it wake anybody: blocks are verified first. A node that falls far behind delays the pushes; none is left out.
- A stop of the service is a gap: it starts again after the newest block, and nobody is woken for the blocks of the stop.
- What is not verified here: no real browser has received a push from this service yet, and no push service has been called by it in a test. The encryption is checked against the example of RFC 8291 and by a round trip in the tests; the token's form against RFC 8292.
