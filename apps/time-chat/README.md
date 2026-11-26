# Time Chat

Private text and emoji conversations for people with Time testnet accounts. Sign in with the Time wallet, link this browser's chat key, find a contact by exact Time name or account number, and compare the safety code using a separate trusted channel. Both people need to join the same relay. A group can have up to 16 members.

## Run it locally

Use Node 26. From the root of this repository, change to `apps/time-chat` before running these commands. The app uses the SDK and verifier from this checkout. Set `TIME_ROOT` to use another compatible checkout.

```sh
npm ci
npm start
```

Open **http://127.0.0.1:4175**. This starts the installed client and its own local SQLite relay. To choose a different port, pass `--port` to `node local.mjs`. Keep the same origin when you come back. Use separate browser profiles and separate wallets to try a conversation between two people on one computer. Independent computers need a common relay. Signing in uses the real testnet wallet. The second wallet approval at first sign-in binds the public chat key created in this browser to the Time account. Keep using that browser profile. Clearing its storage loses the device key. A Time wallet recovery restores the Time account alone.

### Use a shared relay with an independently installed client

Anyone who can replace a website's JavaScript can change what happens before encryption. For conversations meant to stay private from the relay operator, each participant runs their own trusted copy of the client. The browser loads scripts, crypto library, styles and service worker from this local installation. Its local proxy accepts the relay's JSON and change notifications, pins the Time network and wallet, verifies wallet signatures, and independently verifies the contact's chat-key binding against Time.

On a public relay, set both `TIME_CHAT_ORIGIN` and `TIME_CHAT_RELAY` to its external HTTPS origin. Set `TIME_CHAT_INSTALLED_ORIGIN` to `http://127.0.0.1:4175` to also accept independently installed clients. Each login is valid only at its configured origin. Both client types can verify enrollments and message each other. Preserve the external host or use the relay's loopback host when forwarding, stream SSE without buffering, and keep the runtime data directory private.

Relay terminal:

```powershell
$env:TIME_CHAT_ORIGIN = 'http://127.0.0.1:4174'
$env:TIME_CHAT_INSTALLED_ORIGIN = 'http://127.0.0.1:4175'
$env:TIME_CHAT_RELAY = 'http://127.0.0.1:4174'
$env:TIME_CHAT_PORT = '4174'
node server.mjs
```

Installed client terminal:

```powershell
$env:TIME_CHAT_RELAY = 'http://127.0.0.1:4174'
npm run client
```

Open **http://127.0.0.1:4175** on each installed client's computer. To connect to the Time testnet chat, set that client's `TIME_CHAT_RELAY` to **https://chat.testnet.thetimenetwork.org** before running `npm run client`. To use the hosted client, open that HTTPS address directly. Keep using the origin and browser profile you chose when you first linked the device. The installed client currently requires a computer that can run Node. The hosted web interface also works in a mobile browser, with its code supplied by that host.

## Messages and notifications

- Direct chats and fixed-membership groups support text and Unicode emoji. Contact discovery uses exact names or numeric IDs. Search decrypted messages on the device. An edit, reply, removal or emoji reaction travels in a signed encrypted event. Removal updates participants' views. Previously delivered copies and stored ciphertext can persist.
- A conversation ID commits to the network and the full member list. Adding someone means starting another conversation. Verification of each participant and confirmation of a group roster happen before the first message. The relay stores encrypted envelopes off-chain. It uses SQLite and sends a content-free hint so other tabs know when to fetch. A retried envelope with the same ID and bytes is stored once.
- Turn on notifications in Settings to register this browser for Web Push. A push opens Time Chat and contains no sender, conversation or preview. The browser's push service can observe delivery timing. Set `TIME_CHAT_PUSH_SUBJECT` to the relay operator's real `mailto:` or HTTPS contact for a shared service. Browser, operating-system and permission settings determine delivery.
- Blocking a contact hides shared conversations for the pair and suppresses new notifications from those rooms for them. Unblock in Settings to restore access to stored history.

## What participants can verify

1. **Account ownership.** The Time wallet signs an expiring, origin-bound challenge. The server uses the official SDK and Rust/WASM verifier with a pinned testnet manifest to check the account, signing role and current authority. The wallet never hands its private key to Time Chat. Enrollment binds the chat public key into a separate signed challenge. [Authentication](auth.mjs) · [Public trust manifest](config/testnet-trust.json)
2. **Contact identity.** Each device computes the same safety code from both public keys, both account IDs and the network. Compare it in person or through a channel whose participants you already know. The browser pins the verified key and rejects a replacement. An attendee who joins with a new browser cannot silently enroll over an existing key. [Client cryptography](public/crypto.mjs)
3. **Message authorship and integrity.** OpenPGP.js signs on the sender's device and encrypts for the entire verified membership, including the sender's device. On read, the client verifies the signature and the signed network ID, room ID, member list, sender ID and message ID before displaying content. A recipient can verify that a message came from the enrolled chat key. The relay can still delay, omit, reorder or replay traffic. History is not a publicly verifiable transcript. [OpenPGP.js](https://docs.openpgpjs.org/) · [Message verification](public/crypto.mjs)

## Privacy limits

The relay can see account names and IDs, membership, submission times, ciphertext sizes, read cursors, push endpoints and network addresses. The public Time chain is used for account authority. Message text, emoji, private chat keys and search queries stay off the chain. A recipient can copy a message or take a screenshot.

This release uses long-lived device encryption keys. A stolen private chat key can decrypt that device's recorded messages, including older ones. Browser storage wraps the local key using a non-extractable Web Crypto key. An unlocked or compromised browser can still use it. Signing out clears the active session and visible messages while retaining the device key for the next login. Keep separate OS/browser profiles on shared computers. Independent cryptographic review, forward secrecy, recovery to another device and testing push on physical phones remain open.

## Operation and verification

The default pin names the public testnet reset of 25 November 2026. The relay and installed client maintain their own verified checkpoints. A stale trust anchor or a network reset requires an independently authenticated checkpoint or manifest. An unavailable verifier causes sign-in to fail closed. Each network has its own message database and its own chat identities. [Time light-client guidance](../../client-v4/README.md)

| Configuration | Purpose |
| --- | --- |
| `TIME_ROOT`, `TIME_TRUST_FILE` | Override the installed Time source directory or public trust manifest. |
| `TIME_WALLET_ORIGIN`, `TIME_GATEWAY` | Configure the wallet and proof source for the pinned network. |
| `TIME_CHAT_DATA` | Directory for relay SQLite data, push credentials and verified checkpoint. |
| `TIME_CHAT_HOST`, `TIME_CHAT_PORT`, `TIME_CHAT_ORIGIN` | Relay listen address, port and exact hosted browser origin used in signed logins. |
| `TIME_CHAT_INSTALLED_ORIGIN` | Additional fixed loopback origin for signed logins from independently installed clients. The hosted relay refreshes both verifiers’ checkpoints every six hours. |
| `TIME_CHAT_RELAY`, `TIME_CHAT_CLIENT_PORT`, `TIME_CHAT_CLIENT_DATA` | Remote relay origin, installed client's local port and local checkpoint directory. |
| `CHROME_PATH` | Chromium executable for the browser tests if the system installation is not detected. |

```sh
npm test
```

The browser tests use separate profiles and temporary wallet identities that sign real Time SDK challenges against a fixture chain. They compare independently computed safety codes, exchange messages, reload history and inspect the relay requests and database for plaintext. The live testnet and real browser push delivery are separate from these local tests.

## Browser library

The build serves OpenPGP.js 6.3.3 as a separate, unmodified JavaScript module at `/vendor/openpgp.mjs` with its license at `/vendor/openpgp-license.txt`. The app imports that local module. The lockfile identifies the exact package and integrity digest. To inspect, replace or rebuild the module, use the corresponding library source and rerun the app build with your compatible replacement. [OpenPGP.js source](https://github.com/openpgpjs/openpgpjs/tree/v6.3.3) ? [Library license](https://github.com/openpgpjs/openpgpjs/blob/v6.3.3/LICENSE)
