# Time explorer

Web pages where anyone can look up a block, an action or an account of a Time network. One page, plain HTML, CSS and JavaScript modules, no framework and no outside resource. It reads the public HTTP API ([`deploy/api/README.md`](../../deploy/api/README.md)) and checks proofs in the browser with the same compiled verifier and SDK the wallet uses.

The network has not launched. The page says at the top that it shows a development network and that nothing on it is money.

## What it shows

| View | Address | Shows |
|---|---|---|
| Home | `#/` | The network, the newest block and its time, the fee, the time issued since the start, the ten newest blocks and payments, updated live from the event stream. A search box for a block height, an action hash, an account number or an account name. |
| Block | `#/block/{height}` | Height, time, hash, number of actions, and its actions page by page. |
| Action | `#/action/{HASH}` | What it did in plain words, by kind; for a payment above the daily limit whether it completed, was cancelled or still waits; for a validator's upgrade signal the version it supports, the start and the hash of the rules, or that it withdrew; the raw bytes on request; and **Check it yourself**. |
| Account | `#/account/{number}` or `#/account/@{name}` | Name and number, balance, keys by role, whether it is frozen or has something waiting, its stake, indexed totals, and its activity page by page. |
| Validators | `#/validators` | Who validates now and with what share of the votes, and announced changes of the set. A scheduled upgrade only once the installed SDK reads the upgrade row (see below). Then "Run a validator": how joining as a validator works, what is needed, the steps, and with a `join.json` this network's script and files (see below). |
| A number | `#/find/{number}` | A block height and an account number look the same: both are looked up, the account through the same check as on its own page. |

Amounts are shown as a person reads them ("2 h 5 min 3.25 s", exact, never rounded); the "Exact microseconds" switch shows the whole microseconds. Times are in the reader's time zone; "Times in UTC" switches.

## What is checked and what is only indexed

Where a figure comes from is said before the figure: before each list, each group of facts, and on the home page before each single figure.

- **From the index.** Blocks, actions, activity, totals, the status of a waiting payment, times, how often the same bytes are on the chain. This is the API service's own record of the chain. The page has not checked it.
- **Checked in your browser.** An account's row (name, balance, keys), its security row, recoveries and stake, and the validators come with a proof. The page follows validator signatures from the block it trusts and verifies the proof for **the question it asks itself**, not the service's copy of the question.
- **Not checked, the service's word.** These words stand in front of every figure of this kind, and the group they are in is framed with a dashed line, so that such a figure cannot be taken for a checked one by its look or by a screen reader. A name is then labelled "as the service gives it", not "from the chain". It occurs in two places:
  - the fee on the home page, always: the home page checks nothing;
  - accounts, validators and the account of a looked-up number, when the page had nothing to check with and had therefore looked at no proof: no trust manifest, a verifier that does not load or run, a trusted block that has expired, a device clock that does not fit the chain's. The reason stands before the figures.
- **A service that hosts the page can bring that second case about.** It supplies the page's files and its trust manifest: it can leave the manifest out, or serve a verifier that does not load. Its figures then appear as its word, marked as above, never as checked. What it cannot do is get "checked" onto a figure the verifier did not prove.
- **A bare "not found" is the service's word too.** An honest service attaches the proof to its 404 for an account. Without a proof the page says "the service says there is no such account, and gave no proof of that".

One rule decides what is called checked: **after a proof has verified, nothing else the service said decides anything.**

- Whether an account exists is read from the verified state: it holds the account, or the proof shows that the number or name does not exist. The status of the service's answer (200, 404) is ignored. A proof that verifies and says neither is shown as answering nothing.
- "None" (no stake, no security row) is said only of what the proof was asked about and answered.
- **Once a proof was offered and did not pass, the figures it came with are not shown**, whatever the reason: it does not verify, the device's clock makes it look stale, the service's block is older than one the page has already followed. A service that names another network than the page's gets none of its accounts and validators shown either (its blocks and actions stay, as the index of whatever network it answers for, and the page says so). What kind of failure it was is never read from an error text the service could have shaped: whether the page's own trusted block has expired is found by verifying it before the service is asked.

**Check it yourself** on an action verifies that these exact bytes are in their block and that the block is part of the chain.

- A block is checked through the history of block hashes the state keeps (`verifyReceipt`). The age of a block is no obstacle: its history proof stays when the state drops the block's own rows after fourteen days. Two kinds of block cannot be proven this way:
  - the newest two, which the state does not reach yet. The service says so, and the page follows the block's own signed header instead (`verifyFastReceipt`). The page takes this path only for a block at the edge of the chain as it has followed it;
  - blocks from before the service's node joined the network, if it joined from a snapshot: such a node holds no history from before. The service says so (`history_not_held`), and the page says "this service cannot prove a block that old", not "too new". A service whose node has the history can.
- After a pass the bytes shown under "Raw bytes" are the checked ones, and their content what the page read from them.
- **After a pass the description is replaced.** The sentence, the block, the position, the sender, the action number and the details are built anew from the checked bytes and the checked block. The page then compares everything the service had said (kind, sender, action number, key and key generation, the whole content, block, position, and the indexed recipient, amount and reference) and lists what differed.
- **What the bytes cannot confirm is said, next to the fact.** A completed payment above the daily limit holds only the number of the waiting payment: its recipient and amount stay the service's word and are called unconfirmed. Bytes of a kind the SDK does not read (the engine's 23 and 63, and any later kind) are read for their frame only (kind, sender, action number); the service's description of their content stays, marked "not confirmed".
- **The position in the block** is stated only when the next block was checked too. Its header fixes how many actions the block has; without it the same proof fits more than one position.

What a passed check does **not** prove, and the page says: that the trusted block is the right one; anything else marked "from the index"; who is behind an account.

**An account is frozen** when its security row says so, while a replacement of its keys waits, or while a recovery through its helpers has its approvals and has not expired (the engine then refuses the account's actions). On a network whose waits survive a stop (`waits_survive_stops` in its genesis) the moments of the security row are on the clock of the waits, the chain's time less the total of its stops: the page compares them with that clock, from the checked state (or from `security_clock` of the service's answer when nothing was checked), and shows each date as the moment plus the stops so far, "at the earliest" while it has not come. A state that names the setting without the total, or the total without the setting, shows the freeze and the waits as unreadable.

**Upgrades.** A state says something about its upgrade row only when a proof is asked about it. Whether to ask is part of the trust data: a manifest with `nodes_report_upgrades: true` says that the network's nodes answer the question, and the page then asks it with every read (the SDK's rule), so that a service can never leave the row out of one answer; a state without the proven row is refused as a whole. The validators view then shows the scheduled plan, or "none" when the proof shows that there is none (`TimeSDK.upgradeStatusOf`). With a manifest that does not say so the page asks nothing and says that it does not read upgrade plans on this network; it never says "none". A network that already runs newer rules than the page's verifier implements is said to be that ("the page needs a newer release"), and nothing of it is shown as checked.

**Run a validator.** The last section of the Validators view tells a newcomer how joining as a validator works (two keys, the bond, votes, pay, being offline, signing twice, stopping, who decides), what is needed, the steps, what the join script does, and what to take care of. It is text of the page as it was installed, neither checked by the page nor the service's word about the chain, and it says so at its end, with the sentence that the page does not check the script. The facts of one network come from an optional file next to the page, `join.json`:

- **What it holds:** `script_url` (the join script, `https://` with a plain host and the path `/join/join.sh`), `wallet_url` (the wallet's `https://` origin), `chain_id`, `min_self_bond_micros` (the smallest bond), `files` (the SHA-256 of the node program, of the CometBFT archive and of the genesis file), `peers` (1 to 8 entry nodes, `<node id>@<IPv4 address>:<port>`) and optionally `pace`. With it the section shows the bond as an amount, the three commands that download, show and run the script, a link to the wallet, and a list of this network's files.
- **Where it comes from:** the page loads it from its own address, like the trust manifest, never from the API origin. When the API serves the explorer it is the API's `explorer_join` setting (`deploy/api/README.md`); a host elsewhere puts the file next to `index.html`.
- **It is optional.** Without it (a 404) the section gives the general explanation, says that whoever runs the network gives out the script, and shows no command and no outside link.
- **It is read as everything from outside is** (`format.mjs`, `readJoin`): every value has one accepted form, no key may be missing and none added. A file that cannot be loaded or does not pass is not shown at all: the section gives the general explanation and one sentence that this network's own instructions could not be read. Loading it never holds up the validators above: the section is a part of its own, and a load that failed is tried again at the next view.
- **Its two addresses are the only outside links of the page.** `dom.mjs` makes a link to an address outside the explorer only for the wallet's origin and the join script, after the test of `outsideAddress` (`https://`, a plain host in lower case whose last label starts with a letter, a port other than 443, no user name or password, and nothing after the origin but the script's one path), and gives it `rel="noopener noreferrer"`.

**The trust anchor.** The page loads `trust-manifest.json` from its own address, never from the API origin. When the API serves the explorer, that file is the API's configured manifest moved to the newest block the service itself verified: the page, the network id and the trusted block then all come from the service, and the footer and every "what this does not prove" say so. A check then shows that the service's answers fit that block; it cannot show that the block is the right one. Whoever wants to depend on nobody else hosts the page with a manifest from their own source. The footer shows the network id and the trusted block, to compare. Since 2026-11-24 every verdict of a check says the same in one line beside it: the network id it was checked against, shown short, which came with the page or (where the service serves the page) from that same service, and that a reader who wants to be sure compares it with the id from a source they trust.

## What comes from outside is not trusted

Account names, references, hashes, kinds, error texts and numbers are all written by someone else.

- Every value passes a format test (`format.mjs`) before use; one that fails is shown as "(unreadable)". A number goes into one of the page's own sentences only if it is a small whole number.
- Elements are made in one place (`dom.mjs`): fixed tags and attributes, text set as text, links only to the explorer's own addresses and to the two outside addresses of a `join.json` that passed its test (see "Run a validator"). No markup is ever built from text, there is no inline script or style, and the pages load nothing from another site.
- Text from the chain or the service (a name, a reference, the network's name, an error message) is shown in a dotted box and announced as quoted, with every character that is not printable ASCII written as its code. A name that reads "paid_100h_ok" cannot pass for the page's words, and a name always stands next to its account number. A name in a link is labelled as what the link says until the chain has answered. The verifier's own error text is labelled as the verifier's, which may quote the service.
- Kind names and error messages of the service are never used as the page's words: the page has its own sentence for each kind and each failure.

## Hosting

**With the API.** Set `"serve_explorer": true` in the API's config. The pages are then at `/explorer/` of the API, read the API at the same origin, and need no other setting. For this network's facts in "Run a validator", set `explorer_join` too.

**Elsewhere.** Put these files under one directory of any static host, in this layout:

```
index.html  styles.css  app.js  strings.mjs  format.mjs  route.mjs  describe.mjs  client.mjs  check.mjs  dom.mjs  views.mjs      (web-v4/explorer/)
trust-manifest.json                                             the trust manifest you install, as the wallet takes it
join.json                                                       optional: this network's facts for "Run a validator"
sdk/time-sdk.js  sdk/proof-verifier.mjs  sdk/light-client.mjs   (client-v4/)
web-v4/shared/verifier/timecurrency_verifier_v4.js              (web-v4/shared/verifier/)
web-v4/shared/verifier/timecurrency_verifier_v4_bg.wasm
```

Then:

1. Set the one configuration value, in `index.html`: `<meta name="time-api-origin" content="https://api.example">`. A plain origin, nothing after it.
2. Add the explorer's origin to the API's `cors_origins`. Without it the browser reports every request as a failed connection, and the page says that this may be the cause.
3. Send these headers with the files (the API sends them when it serves the pages):
   `Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' https://api.example; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`. Serve `.wasm` as `application/wasm` and `.mjs` as `text/javascript`.
4. Keep `trust-manifest.json` fresh: a manifest whose block is older than the trusting period (seven days) checks nothing, and the page says so. Do not let it be cached.
5. Let the page and its modules be asked about every time (`Cache-Control: no-cache` with an `ETag`), as the API does: files of two releases must not run together in one browser.

Without `trust-manifest.json` (a 404) the page still works; it then shows everything as the service's word. A manifest that could not be loaded for another reason is asked for again with every view. Without `join.json` the section "Run a validator" gives its general explanation; do not let that file be cached either.

## When things fail

- Each part of a view loads by itself. A part that fails says why in the page's words (no connection, the service limits requests, the service cannot answer now, not found), waits as long as the service asks (`Retry-After`, up to five minutes) and tries again by itself a few times; a "Try again" button stays.
- When the event stream drops, the home page says so, reconnects from the last event it received after a pause that grows, and re-reads the lists every ten seconds meanwhile: not in a hidden tab, and not before a wait the service asked for is over. A server that keeps ending streams which carried nothing is come back to later and later.
- When the newest indexed block is more than two minutes old by the device's clock, a note under the header says how old it is.
- A check that could not be made says which of these it was: the verifier does not load or run (found by calling it once, before the trusted block is judged with it); the device's clock does not fit the chain's (check the clock, or try again); the service answered with an older block than the page had followed (asked again twice after a pause, then "try again"); the block is at the edge of the chain and its signed header is not there yet; the service cannot prove a block that old; the service did not give the material; the proof does not verify.
- If the page's scripts cannot be loaded at all, the text in the page says so and asks to load it again.

## Reading and use

Works at phone width, with a keyboard alone (a skip link, visible focus, the heading of a new view takes the focus) and with a screen reader (headings, labelled lists and tables, status and alert regions). Light or dark by the system setting. Every visible word is in `strings.mjs`, so a translation is a second table.

## Tests

`node --test web-v4/explorer/*.test.mjs`

- `pure.test.mjs`: the search box, addresses, paging, amounts and times, an action in words for every kind, the comparison of a description with checked bytes, the API client, the stream's reconnection, the two outside addresses and the reading of `join.json`.
- `check.test.mjs`: the in-browser checks with the real verifier on the fixtures of `verifier-v4`, through the real API service: passing, refusing every tampered answer, and what decides the kind of a failure.
- `views.test.mjs`: every view on a fake page with a fake API: sources, empty, loading, not-found and error states, and every field of every answer replaced by hostile values; "Run a validator" without `join.json`, with one, with each kind of value that does not pass, with every field of it replaced by hostile values, and with a loader that fails or is slow.
- `serve.test.mjs`: the serving setting (only the fixed files, the headers, path tricks refused), `explorer_join` and `/explorer/join.json` (held to the same rules as the page's own reading), and the routes the explorer added to the API, with the real state reader where the fixtures allow it.
- `review-adv1.test.mjs` to `review-adv5.test.mjs` (helper `review-fake-page.mjs`) and `review2-a.test.mjs` to `review2-d.test.mjs` (helper `review2-old-views.mjs`, the page logic as it was before the first review, to run it against today's checker): the tests of the two independent reviews, unchanged. Each plays the service as the attacker and asserts what the page must then say.

What the fixtures do not allow: the path for the newest two blocks is run to the end only against a state reader that is a stand-in (the fixture with real blocks has no state proof, the one with a real state proof has no blocks 5 and 6). With the real state reader the tests show the service's 404 with its proof and that the page then asks for the block's signed headers.

**What has run against a live network.** On 2026-11-18 the API served these files on a live test network (seven validators in two regions on AWS), and the test harness ran the checker of this directory (`check.mjs`, with `client.mjs`) under Node against that service, starting from the trust manifest the service hands the pages. It verified the validators, an account's state with its security row, the proof that an account does not exist, an action through the history of the state, and an action in the newest blocks through its own block's signed header: the path the fixtures cannot run to the end. The files were fetched and compared byte for byte, with their headers. That was one run of about two minutes.

**These tests run under Node with a stand-in for the page.** A browser ran this code for the first time on 2026-11-19: Chrome 158, against a live test network, with the pages served by the API (`campaign/README.md`, "The browser check"). What that showed: the modules and the WebAssembly verifier load under the Content-Security-Policy; an action is checked against validator signatures in a quarter of a second; a block, an account found through the search field, a name nobody holds and the validators are shown with what was checked. It also found that the API refused its own page, so that no browser could load it; that is fixed in `client-v4/api.mjs`. What still needs a real browser: the real `EventSource`, caching of the files by a browser, layout on a phone, focus and screen-reader behaviour, the colours in both schemes, and any browser but Chrome.
