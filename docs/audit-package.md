# Package for an external security audit

This document is for the engineers of a security firm asked to audit Time before a first network holds value. It says what the system is, what is in scope and in what order, which claims we ask you to break, what we already know to be weak, and how to build and test everything. It assumes you know CometBFT, ABCI, Merkle proofs, light clients and Ed25519, and nothing about this code.

Everything here was written by the project. The reviews it mentions were the project's own, not independent audits.

## 1. What we ask

In order of importance:

1. **Can currency be stolen, created or destroyed?** Any way to move an account's currency without a key its rules allow, or to make the totals of a block not add up.
2. **Can two honest nodes disagree?** Any input (a transaction, a block, a snapshot, evidence, a restart at a bad moment, an upgrade) on which two nodes that run the same release compute different state roots, or on which one stops and the other does not.
3. **Can a wallet, a shop or an explorer be shown something false?** Any balance, payment, account state or upgrade status that a client accepts as verified without the validators' signatures behind it.
4. **Can the network be stopped or made useless cheaply?** By one sender, by one validator, or by less than a third of the voting power.
5. **Can an account owner be locked out or robbed through the account security rules themselves?** The rules for sign-in, spend and recovery keys are new and are the part most likely to hold a design error.
6. **Can the operator tooling make a validator sign twice, start on the wrong network, or run a build other than the released one?**

A finding of class 1, 2 or 3 blocks a launch. We would rather have a short list of confirmed problems with a way to reproduce each than a long list of observations.

## 2. The system in brief

Time is a currency whose supply is the time since its genesis: one unit per second, counted in microseconds. There is one currency, no smart contracts and no user-defined data on the chain. An action is a fixed-format signed message of one of about forty kinds.

| Part | What it is | Trust |
|---|---|---|
| CometBFT 0.38.26 | Consensus and peer-to-peer. Upstream source, unchanged; only Go dependency versions are pinned (`consensus/`). | Trusted as upstream. Not in scope, except how the application uses it. |
| `time-node-v5` (`v5/`) | The application behind ABCI: executes blocks, keeps the state in memory under a sparse Merkle tree, answers proof queries, writes snapshots, offers and restores state-sync snapshots. | Every validator runs it. A bug here is a consensus bug. |
| Ledger crates (`src/`, `pos/`, `history/`, `registration/`, `treasury/`, `bitcoin-bridge/`) | Rules the application is built from: payments and keys, staking, the authenticated block history, paid registration of names, and the Bitcoin bridge with its treasury. | As above. The bridge and treasury are compiled in but refuse every action on a network that pays all new time to validators, which is the production profile. |
| Verifier (`verifier-v4/`) | Rust compiled to WebAssembly. Checks CometBFT light blocks and the application's state proofs. Runs in wallets, shops, servers and the explorer. | The root of what a client believes. |
| SDK and light client (`client-v4/time-sdk.js`, `light-client.mjs`) | Builds and signs actions, follows validator sets from a pinned trust anchor, verifies every answer with the verifier. | Runs on the user's side. Everything it talks to is untrusted. |
| Gateway, HTTP API with block index, faucet, alert watch (`client-v4/`, `deploy/`) | Servers between clients and nodes. | Untrusted by design: a client must be safe against a malicious one. They must still not be crashable or usable to mislead. |
| Wallet and explorer pages (`web-v4/`) | Browser code. The wallet holds keys, encrypted under the user's passwords. | The user's browser. |
| Deployment kit, release tools, genesis ceremony (`deploy/`, `tools/`) | How operators build, start and upgrade validators with a remote signer, and how twenty operators agree on a genesis. | Operators. |

The rules of a block, the state layout and the action envelope are in `spec/protocol-4.md` (two pages; it names every rule and the source file that defines it to the byte). `v5/README.md` describes the engine and every rule that differs from the earlier protocol-4 application. `docs/design/upgrade-mechanism.md` is the design of upgrades.

## 3. Scope, in the order we suggest

Sizes are lines of source without tests, counted on the commit named in section 8. They include comments.

| # | Component | Lines | Start with |
|---|---|---|---|
| 1 | Block execution and state: `v5/src/engine.rs`, `store.rs`, `merkle.rs`, `proof.rs`, `genesis.rs`, `abci.rs`, `transport.rs` | part of 18,700 in `v5/src` | `spec/protocol-4.md`, then `engine.rs` from its head comment |
| 2 | Account security rules: `v5/src/security.rs` (action kinds 70 to 77) | in `v5/src` | `v5/README.md`, "Account security"; `AUDIT-2026-11.md`, "Account security" |
| 3 | The protocol-1 ledger the engine still applies: `src/ledger/` | 5,300 | `v4/PROTOCOL.md` |
| 4 | Staking: `pos/src`, `v5/src/pos_adapter.rs` | 2,200 + adapter | `pos/README.md`; `v5/README.md`, "The stake hand-over rule" |
| 5 | Upgrades: `v5/src/upgrade.rs`, `rules.rs`, the stops in `main.rs` | in `v5/src` | `docs/design/upgrade-mechanism.md` |
| 6 | State sync, snapshots, pruning: `v5/src/statesync.rs`, `snapshot.rs`, `history/src` | in `v5/src` + 1,000 | `v5/README.md`, "State sync and pruning" |
| 7 | Verifier: `verifier-v4/src` | 1,900 | `client-v4/README.md`; `light.rs`, `view.rs`, `receipt.rs` |
| 8 | SDK, light client, order and sign-in server code: `client-v4/time-sdk.js`, `light-client.mjs`, `proof-verifier.mjs`, `server*.mjs` | part of 5,800 in `client-v4` | `client-v4/README.md` |
| 9 | Wallet: `web-v4/wallet` (key storage, the security flows) | 2,700 | `web-v4/wallet/README.md` |
| 10 | HTTP API and index, alert watch, faucet, explorer: `client-v4/indexer.mjs`, `api.mjs`, `security-watch*.mjs`, `faucet.mjs`, `web-v4/explorer` | rest of `client-v4` + 2,600 | `docs/integration-guide.md`; each service's README under `deploy/` |
| 11 | Deployment kit and release tools: `deploy/`, `tools/release-v5.mjs`, `tools/genesis-v5.mjs`, `tools/build-verifier.mjs`; within it the guard that checks signer leases (`deploy/operator.mjs`), the controller that issues them and its host agent (`deploy/lease-controller/`, `deploy/lease-agent.mjs`) | 1,600 + 1,300 for the leases + part of 4,200 in `tools` | `deploy/README.md`, `deploy/PRODUCTION-V5.md`, `docs/design/signer-lease-controller.md` |
| 12 | Registration: `registration/src`, `v5/src/registration_adapter.rs` | 700 | `v5/README.md` |

**Out of scope.**
- CometBFT itself.
- `v4/` and `v2/`: earlier applications, kept only because the engine's tests run every block through the protocol-4 application and compare the results. They never run on a network of this release.
- The Bitcoin bridge, auction and treasury (`bitcoin-bridge/`, `treasury/`, `v5/src/bitcoin_adapter.rs`, `auction.rs`, `treasury_adapter.rs`), except for one question: confirm that on a network with `all_new_time_to_validators` none of their actions (kinds 40 to 42, 60 to 63) can change state. The bridge has known critical weaknesses and is not safe for real bitcoin (`AUDIT-2026-11.md`, findings C1 and C2).
- The example shop page (`web-v4/merchant`) and the cloud test harness (`campaign/`).

## 4. Claims we ask you to break

Each claim names where it is enforced and where the project tests it. The documents give the exact rules; where a claim here and the code differ, that difference is a finding.

1. **Supply.** After every block, bank + liquid balances + staked assets + auction reserve equals the chain time since genesis, in microseconds. Enforced at the end of block execution in `v5/src/engine.rs`; recounted from the rows alone by `time-node-v5 --audit`.
2. **Authority.** An action changes an account only if it carries an Ed25519 signature by a key that the account's current rules allow for that kind, with the account's next nonce and current authority epoch, for this network id. No action is accepted twice.
3. **Account security** (`v5/README.md`, "Account security"; the table of thefts in `AUDIT-2026-11.md`).
   - A stolen sign-in key signs in to websites as the account until it is replaced. It moves no currency and changes nothing on the chain.
   - A copied spend key moves at most twice the daily limit in any 24 hours before the owner reacts. A larger payment waits and can be cancelled.
   - One stolen recovery key moves nothing and changes no key. It can keep the account frozen, at a fee.
   - Recovery keys alone, at their threshold, can only ask for a new set of keys. That waits, and an owner who still holds the spend key and one recovery key can stop it.
   - Whoever holds the spend key and one recovery key is the owner: that pair replaces every key at once. Nothing less does.
   - The waiting queue, the daily limit and the fee cannot be used by the holder of one stolen key to block the owner's protective actions (freeze, cancel, replace).
4. **One state for one history.** For the same blocks, every node computes the same state root, whatever its snapshots, restarts, thread count or the order in which it saw transactions in its mempool. A block with one invalid transaction is invalid for everyone. Tested by running every block through the protocol-4 application as well (`v5/tests/`, the differential and golden tests), and by recounts on every validator of the cloud runs.
5. **Proofs.** A state proof verifies only for the rows that are in the state under the root in a header signed by more than two thirds of the validators the client follows, and a proof of absence only for rows that are not there. `v5/src/proof.rs`, `verifier-v4/src`.
6. **Clients believe only what they verified.** The SDK, the wallet, the order and sign-in servers and the explorer take balances, payments, account state, the fee, validator sets and the upgrade status only from verified proofs, starting from a trust anchor that was installed independently of any gateway. A gateway or API can refuse or delay; it cannot make a client accept a false statement, sign something else than the user saw, or believe that the network runs rules the client does not know.
7. **Staking.** No key holds a third of the voting power or more through selection; changes of power are rationed; a validator that signs twice is punished from the evidence CometBFT reports, without an operator's action; the starting validators keep more than half of the power until independent stake has held its target for the hold period (`pos/`, `v5/README.md`).
8. **Upgrades** (`docs/design/upgrade-mechanism.md`, section 12 lists the threats considered).
   - A new version starts only if owners of validators with four fifths of the voting power signal it, and after the notice period; it is cancelled if support falls under three quarters.
   - At the switch, every program that implements the version continues on the same root, and every program that does not stops before executing a block under rules it lacks. No honest node executes a block under the wrong rules.
   - A version never changes what an existing action kind or payload does.
   - A minority cannot activate, and cannot keep a scheduled activation from being cancelled.
9. **State sync.** A node that restores a snapshot ends with exactly the state whose root is in a header its own CometBFT verified, or refuses it. A peer offering snapshots or chunks cannot crash the node, exhaust its memory or disk, or leave it with another state. A node that has executed blocks never restores.
10. **Services.**
    - *HTTP API:* what comes from its index is labelled as such and can be verified by the client; following `docs/integration-guide.md` literally, an exchange cannot be made to credit a deposit that did not happen or to pay a withdrawal twice.
    - *Alert watch:* an owner who runs it is told of a waiting payment or key replacement in time to stop it, and a gateway cannot hide one without the watch saying that it cannot see.
    - *Faucet:* its key can lose at most what its on-chain daily limit allows, whatever the nodes it talks to answer.
    - *Explorer:* a figure the page did not check is never shown as checked.
11. **Wallet.** The spend key and the sign-in key are stored under different passwords with each key's role bound into its encryption; no backup file carries a spend key; the wallet signs only what it showed the user and the user approved, whichever page asked for it. Since 2026-11-24: no key is sealed under a password a person chose, alone (`web-v4/wallet/vault.mjs`, `RULE`), and the old device of a move to another device signs only the request whose code was typed there (`web-v4/wallet/device-move.mjs`, `MOVE_CHECKS`).
12. **Operator tooling.** A validator started by the kit runs exactly the released build, and signs only while it holds a fresh lease for its key, release, genesis and engine, and the reference lease controller never has two leases for one key valid on two hosts at the same moment, under the assumptions its design states (`docs/design/signer-lease-controller.md`, claims S1 and S2). The lease is checked every five seconds by the guard, not by the signer at each signature: say what that leaves open with a real signer. A genesis built by the ceremony is the one every operator computed, and the coordinator cannot change any operator's entry.

## 5. What we already know

Do not spend time rediscovering these; do tell us if one is worse than we think.

- **`AUDIT-2026-11.md`** lists every finding of the project's own reviews with its state. Open ones include: ways to use up the hourly limit on validator-set changes cheaply (S3); staking re-validating its whole state on every action (S4); a rounding effect on delegation pool prices (S5); a damaged block-history file stops a validator with no rebuild command (D1); no budget per caller on sponsored sign-up (M2) in the gateway, and request limits per server (M3) in a gateway that is not told who its callers are (`trusted_proxies`).
- **Guessing offline** (`AUDIT-2026-11.md`, "What can be guessed offline, and what the browser keeps (24 November 2026, afternoon)" and "No key under a chosen password, a move to another device, and the live network's access (24 November 2026, evening)"). The recovery words are 90 bits made by the wallet, salted by network and account. Since 2026-11-24 the wallet seals no key under a password a person chose, alone: with the device's WebAuthn PRF secret and the password together where the device can (by default at sign-up), else under passwords the wallet makes (72 bits, marked as made in the record's authenticated header); `sealVault` refuses anything else. Keys sealed before under chosen passwords, and copies of them, can still be tried offline at the vault's Argon2id (64 MiB, three passes) until their owners act. The chain cannot tell how a recovery key was made.
- **Accepted limits of the design**, each explained in the document named:
  - The state is held in memory, about 2 KiB per account (`v5/README.md`, "Known limits").
  - Everything on the chain is public (`AUDIT-2026-11.md`, "Privacy").
  - A node restored from a snapshot cannot judge evidence about heights before its snapshot for about 23 days, and stops if such evidence is committed (`v5/README.md`, "State sync and pruning").
  - Catching up over many blocks, a light client trusts one third of the validators it last trusted, which is CometBFT's rule (D4).
  - While the starting validators hold more than half of the power, they can stop the network and decide which upgrades happen. That is the intended bootstrap, and it ends by rule (`v5/README.md`, "The stake hand-over rule").
- **In a browser since 2026-11-19, in Chrome only, for minutes at a time:** the wallet, the faucet page, the explorer and the sample shop, against a live test network (`campaign/README.md`, "The browser check": 26 scripted steps on 2026-11-19, 44, then 50, then 54 on 2026-11-24, of which the last four move an account to another browser; four defects found and fixed on the first day, among them a payment signed by one long key press and an explorer that loaded in no browser). Not run in any browser: the wallet's screens for a second browser, for replacing keys and for a validator's upgrade signal, and a recovery past its review; any other browser; a phone.
- **The deployment kit, on 2026-11-19 for under an hour, and on 2026-11-23 with a network that ran about seventy minutes:** with Docker, two remote signers (tmkms and Cosmos-KMS) and the lease controller, on eleven AWS machines in one region, by the test harness (`AUDIT-2026-11.md`, "The deployment kit, rehearsed": 23 of 25 steps; six defects of the kit found and fixed, without which it could not start; and "Run on AWS and in a real browser (23 November 2026)": 28 of 30 steps, among them a coordinated stop of all seven validators and the start of the chain that stood with a resume order). Not run: a key moved between hosts, a controller restart, power loss under a signer, a hardware or cloud key, a production genesis of twenty validators.
- **Never run on a live network, as of this writing:** a genesis ceremony with real operators. `AUDIT-2026-11.md` says for each part what was and was not run.

## 6. What has been done so far

- **Tests.** About 270 tests of the engine (unit, differential against the protocol-4 application, golden roots, tests that drive the built binary over its ABCI socket), 55 of staking, 44 of the verifier, and of the JavaScript, on 2026-11-24, 1,124 in the group of the clients (SDK, light client, servers, API, watch, faucet, alert service, gateway, wallet, explorer) and 216 in the group of the harness (215 pass, 1 is skipped), besides the groups of the release tools and the kit, the lease controller and the repository's own tools. `node tools/ci-checks.mjs --list` names every suite.
- **Reviews by the project.** Each new part was reviewed by a reviewer who was given the code and not the author's conclusions, was asked to break it, and wrote tests for what it found. The reviewers' tests are in the suites, named `review*`. `AUDIT-2026-11.md` gives, for each part, how many rounds there were and what the serious findings were. These reviews found real defects every time, which is the reason to expect that you will too.
- **Runs on AWS.** Networks of seven validators in up to three continents, built from source on Linux, with the real SDK as the wallet: latency, load up to 20,000 payments per second offered, validators stopped on purpose, the account security rules exercised by a script, and a recount on every validator at the end. `AUDIT-2026-11.md`, "Measured on AWS". On 2026-11-18 one such network of seven laboratory validators went once through a change of protocol version with two programs (signals, a plan scheduled and cancelled, the activation, a validator that was not replaced stopping with exit code 4 and returning, a coordinated stop at a height) and took in one node by state sync. `v5/README.md`, "What ran on a network, and what did not", says what that one run showed and what it did not: among the latter, the deployment kit, a chain that waits for more than a third of its validators, the emergency switch, pruning, and evidence about heights before a restored node's snapshot. On 2026-11-23 the emergency path (a switch at an agreed height, and the repair of a block that every node failed on) ran twice, each time on two such networks, by the harness and not through the kit, and every network of that day had the four optional genesis settings (`AUDIT-2026-11.md`, "Run on AWS and in a real browser (23 November 2026)").
- **Fuzzing.** Two campaigns on Linux on 2026-11-23, without a sanitizer: the seven targets of `fuzz/` (`docs/fuzzing.md`) for a quarter of an hour, 17.5 million runs, and for six hours, 422.1 million runs; no crash.
- **Not done.** No formal verification. No audit by anyone outside the project.

## 7. Build, test, reproduce

You need Rust 1.99.1 (`rust-toolchain.toml`), Node.js 26 and a C toolchain. The JavaScript has no dependencies outside the repository except one vendored library in the wallet (`web-v4/wallet/vendor`, Argon2 from hash-wasm, with its provenance file). Rust crates are locked by one `Cargo.lock` per crate, and every command below uses `--locked`.

```sh
node tools/ci-checks.mjs --list              # every check, by name
node tools/ci-checks.mjs --all --keep-going  # all of them
node tools/ci-checks.mjs rust-v5             # one
```

- `cargo build --release --locked --manifest-path v5/Cargo.toml` builds the node (`time-node-v5`) and a benchmark that drives the application the way CometBFT does, without a network (`time-bench-v5`).
- `time-node-v5 --devnet --db PATH --audit` recounts a stopped node's saved state from scratch: every hash in the tree, every account, the supply rule and the block history file.
- `cargo build --features rehearsal-v5` builds a node whose list of versions also holds a version 5 with the rules of version 4, to rehearse an activation.
- `node tools/build-verifier.mjs --check` rebuilds the WebAssembly verifier and compares it with the committed copy, byte for byte. Run it on Linux x86-64: the committed `.wasm` file is that system's build. On another system the same source gives a different file, and the check compares the other files and says that it left this one out.
- A local network of several validators on one computer: `START-HERE.md`.
- The node accepts only chains whose id starts with `time-devnet-v4-`, and every binary reports `publicLaunchAllowed=false`. This guard is lifted last, after your audit; please review the code with the guard in mind but not as a protection.

## 8. Versions

- The commit to audit is named in the request that comes with this document. Its engine reports `time-node-v5 0.10.0 protocol=4`.
- Protocol version 4 is defined by `spec/protocol-4.md`; the engine carries the SHA-256 of that file as `rules::SPEC_4` and a test compares the two. Four optional settings of a network's genesis (`distinct_names`, `waits_survive_stops`, `protected_registration`, `service_records`) are specified in `spec/settings.md`, which that hash does not cover.
- CometBFT 0.38.26, built from upstream source with the module versions in `consensus/go.mod` (`consensus/BUILD.md`).
- Third-party code and licences: `THIRD-PARTY-LICENSES.md`.

## 9. Reporting

Report findings as `SECURITY.md` describes, privately, and not in a public issue. For each finding we ask for: the claim of section 4 it breaks (or "other"), the commit, the smallest input or sequence of steps that shows it, what an attacker needs (a key, voting power, a position between a client and its gateway), and what they gain. A failing test in the style of the existing `review*` tests is the form we can act on fastest.
