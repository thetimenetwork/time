# Time

Time is a currency whose unit is time. The whole network issues one second of currency for each second of block time it accepts (one for the network, not one per person), counted in microseconds, so the supply always equals the time since the network started.
It runs on its own chain: CometBFT 0.38.26 orders the blocks and a Rust application (`v5/`) applies the ledger rules, with validators chosen by stake.
An account has a name and Ed25519 keys, and can give each key one role: signing in to websites, spending within a daily limit, or recovering the account.
A browser wallet, a JavaScript SDK and a gateway let a website ask for a login or a payment. A light-client verifier, written in Rust and compiled to WebAssembly, checks validator signatures and Merkle proofs, so a wallet does not have to believe the server it talks to.
A deployment kit and a genesis ceremony tool are there for the people who would run validators.

[Time Chat on the testnet](https://chat.testnet.thetimenetwork.org) uses the wallet to sign in and bind a separate encryption key to an account. Its direct and group conversations carry signed, end-to-end encrypted text and emoji. The [app guide](apps/time-chat/README.md) explains contact verification, the independently installed client and what the relay can see.

## Status

Read this before anything else.

- **The monetary network has not launched.** The public testnet is for development and its seconds have no monetary value.
- **The software accepts development chains only.** The node refuses any chain id that does not start with `time-devnet-v4-`, and every binary reports `publicLaunchAllowed=false`. There is no switch that turns this off.
- **There has been no external audit.** The code has had internal reviews; their findings, fixed and open, are in [AUDIT-2026-11.md](AUDIT-2026-11.md). That document is the project's own review, not an audit by an outside party.
- **Nothing here holds real value, and nothing built from it should.** What must be done before any launch with real value is listed at the end of the same document.

Some parts have run only in the project's own rehearsals, never with real operators: the deployment kit and its remote signers have run on laboratory networks that a test harness started and operated, and no genesis ceremony has been held with real operators. The wallet has run against live networks in one browser only (Chrome, headless), and some of its account-security screens have not run in any browser: a second browser, a recovery carried to its end (the browser check takes one up to its review), replacing keys and unfreezing. The repository says so where it matters; please keep it that way.

## What is in the repository

| Folder | What it is |
|---|---|
| `v5/` | The node application, `time-node-v5` (the version-5 engine): ledger rules, state in a Merkle tree, proofs, snapshots, the ABCI connection to CometBFT. Start with [v5/README.md](v5/README.md). |
| `pos/` | Staking: bonds, validator selection, rewards, penalties, and the rule by which the starting validators hand the network over. |
| `src/`, `tests/`, `examples/` | The protocol-1 ledger crate (`timecurrency-node`, built from the top-level `Cargo.toml`). The engine still uses its rules, unchanged, for several kinds of action. |
| `history/`, `registration/`, `treasury/`, `bitcoin-bridge/` | Crates the engine is built with: the authenticated block history, paid registration of names, and the Bitcoin treasury policy and receipt verification. A network that pays all new time to validators refuses the Bitcoin actions. |
| `v4/`, `v2/` | The two earlier node applications. They are here because the engine's tests run every block through the protocol-4 application as well and compare the results, and `v4` needs `v2` to build. They are not meant for new networks. |
| `verifier-v4/` | The light-client verifier: Rust, compiled to WebAssembly for wallets and shops. The compiled copy in `web-v4/shared/verifier/` is the build of Linux x86-64. There `node tools/build-verifier.mjs` rebuilds it from a staging folder, with local paths mapped away, so the same source gives the same bytes in any checkout, and `node tools/build-verifier.mjs --check` rebuilds and fails if the committed copy differs. A build on another system gives a different `.wasm` file from the same source (measured on Windows): there `--check` compares the other files, says that it did not compare the `.wasm` file and exits with 3, and `--local` writes that system's build for trying a change, never for committing. The staging folder is made in a short place; on Windows a place too long for the linker is refused before compiling, and `TIME_VERIFIER_STAGE` names another. |
| `client-v4/` | The JavaScript SDK (`time-sdk.js`), the light client, the gateway server for wallets, the block index and HTTP API for integrators (`indexer.mjs`, `api.mjs`, `api/openapi.json`), the account-security helpers, the alert watch and the test-network faucet. |
| `web-v4/` | The browser wallet (`wallet/`), the public explorer pages (`explorer/`), the faucet page (`faucet/`), a demo blog that people sign in to with the wallet (`merchant/`, served by the gateway's second origin), the main page of a test network (`site/`) and the compiled verifier they load (`shared/verifier/`). |
| `deploy/` | The validator deployment kit: image build, Compose files and systemd units, start-up guards, signer-lease and restore checks, a reference controller that issues the signer leases with the agent that keeps one fresh on a validator host (`lease-controller/`, `lease-agent.mjs`), and how to run the gateway, the HTTP API, the alert watch and the faucet as services. |
| `tools/` | Release packagers, the genesis ceremony, the local test network launcher, dependency checks, the licence inventory, the publication export, the build of the compiled verifier and the list of the repository's checks (`ci-checks.mjs`). |
| `consensus/` | The Go module versions the CometBFT binary is built with, and how it is built. CometBFT's own source is not in this repository. |
| `spec/` | The rules of protocol version 4 as the engine applies them (`protocol-4.md`; the engine names a version by the hash of this file), and the action format with test vectors. |
| `docs/` | The integration guide for exchanges, shops and wallets, and the design of the upgrade mechanism. |
| `campaign/lib/genesis.mjs` | The development genesis builder that the tests read. |

Each Rust crate has its own `Cargo.lock`; there is no workspace.

## Build and test

You need:

- Rust 1.99.1. `rustup` installs it from `rust-toolchain.toml` the first time you run `cargo` here.
- Node.js 26. The core checks use the JavaScript shipped in this repository. The optional Time Chat app installs its own locked npm dependencies.
- A C toolchain and linker, as for any Rust project.

Every check has a name in one list, `tools/ci-checks.mjs`:

```sh
node tools/ci-checks.mjs --list            # the checks and their groups
node tools/ci-checks.mjs rust-v5           # one check
node tools/ci-checks.mjs --group node      # every JavaScript suite
node tools/ci-checks.mjs --all --keep-going
```

`--setup` also installs what a check needs beyond Rust and Node (the WebAssembly target and `wasm-bindgen` for the verifier build, the crates for the licence check). The commands behind the names are these.

The Rust tests, one crate at a time:

```sh
cargo test --locked --manifest-path v5/Cargo.toml
CARGO_TARGET_DIR=v5/target-rehearsal cargo test --locked --manifest-path v5/Cargo.toml --features rehearsal-v5
cargo test --locked --manifest-path pos/Cargo.toml
cargo test --locked --manifest-path verifier-v4/Cargo.toml --lib
cargo test --locked
cargo test --locked --manifest-path v4/Cargo.toml
cargo test --locked --manifest-path v2/Cargo.toml
cargo test --locked --manifest-path history/Cargo.toml
cargo test --locked --manifest-path registration/Cargo.toml
cargo test --locked --manifest-path treasury/Cargo.toml
cargo test --locked --manifest-path bitcoin-bridge/Cargo.toml
```

The second line tests the rehearsal build of the engine (a version 5 with the rules of version 4, for rehearsing an upgrade). It needs a build directory of its own: both builds make a program of the same name. `v5/tests/production_genesis.rs` runs `tools/genesis-v5.mjs`, so the `v5` suite needs `node` on the path. On Windows, `.\tools\cargo.ps1` can be used in place of `cargo`.

The JavaScript tests:

```sh
node --test client-v4/*.test.mjs deploy/gateway/*.test.mjs web-v4/wallet/*.test.mjs web-v4/explorer/*.test.mjs
node --test tools/release-v4.test.mjs tools/release-v5.test.mjs tools/genesis-v5.test.mjs
node --test deploy/lease-controller/*.test.mjs
node --test tools/licenses.test.mjs tools/export-public.test.mjs tools/build-verifier.test.mjs tools/ci-checks.test.mjs
```

`node tools/build-verifier.mjs --check` rebuilds the compiled verifier and compares it, byte for byte, with the copy in `web-v4/shared/verifier`. The `.wasm` file is compared on Linux x86-64 only, where the committed copy is built. On another system the list prints this check as `PASSED IN PART` and says what it left out.

The files under `web-v4/wallet/tests/` are not part of these suites: they drive a real browser against a running local network.

`.github/workflows/ci.yml` runs all of the above on Linux, through the list.

### Running a node or a local network

`v5/README.md` describes the node's options. `time-bench-v5` (built from `v5/`) drives the application the way CometBFT does, without a network.

[START-HERE.md](START-HERE.md) and [v4/README.md](v4/README.md) describe the local test network (`tools/start-v4-lab.mjs`: several validators on one computer, a wallet and an example shop, test coins only). The launcher expects binaries you have built yourself: the node, CometBFT ([consensus/BUILD.md](consensus/BUILD.md)) and Bitcoin Core for its test mode. It does not download them.

## Where to read more

- [v5/README.md](v5/README.md): the engine, the rules that differ from protocol 4, account security, fees, issuance, the stake hand-over rule, known limits.
- [AUDIT-2026-11.md](AUDIT-2026-11.md): the internal security review, what was measured, what is still open.
- [docs/audit-package.md](docs/audit-package.md): what an external audit is asked to look at, the claims to break, and how to build and test everything.
- [pos/README.md](pos/README.md): staking.
- [spec/protocol-4.md](spec/protocol-4.md): the rules of protocol version 4, and [docs/design/upgrade-mechanism.md](docs/design/upgrade-mechanism.md): how validators schedule a new version and what every program does at the switch.
- [docs/integration-guide.md](docs/integration-guide.md) and [deploy/api/README.md](deploy/api/README.md): the HTTP API for exchanges, shops and wallets, with its recipes for deposits and withdrawals.
- [web-v4/explorer/README.md](web-v4/explorer/README.md): the explorer pages and what a visitor's browser checks for itself.
- [deploy/watch/README.md](deploy/watch/README.md): the alert watch. [deploy/faucet/README.md](deploy/faucet/README.md): the faucet of a test network.
- [v4/PROTOCOL.md](v4/PROTOCOL.md) and [v4/REQUIREMENTS.md](v4/REQUIREMENTS.md): the protocol-4 ledger that the engine implements.
- [client-v4/README.md](client-v4/README.md): the SDK, the trust a wallet starts from, how a website integrates.
- [web-v4/README.md](web-v4/README.md) and [web-v4/wallet/README.md](web-v4/wallet/README.md): the wallet.
- [deploy/README.md](deploy/README.md) and [deploy/PRODUCTION-V5.md](deploy/PRODUCTION-V5.md): running validators, and the order of work for starting a production-profile network.
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Older documents call the currency "Seconds" and the earlier applications "protocol 2" to "protocol 4"; the wallet's screens still say "Seconds".

## Third-party licences

[THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) lists every Rust crate the lockfiles name, the Go modules of the CometBFT build and the JavaScript vendored in the wallet, each with the licence it declares. `tools/licenses.mjs` writes that file and fails if a licence is not on its allowlist of permissive licences.

The tool reads licences from copies on disk, never from the network. Fetch the crates first, then point it at the Cargo registry:

```sh
for lock in Cargo.lock v2/Cargo.lock v4/Cargo.lock v5/Cargo.lock pos/Cargo.lock treasury/Cargo.lock \
    bitcoin-bridge/Cargo.lock history/Cargo.lock registration/Cargo.lock verifier-v4/Cargo.lock; do
  cargo fetch --locked --manifest-path "${lock%Cargo.lock}Cargo.toml"
done
node tools/licenses.mjs --registry "${CARGO_HOME:-$HOME/.cargo}" --out THIRD-PARTY-LICENSES.md
```

- `--registry DIR` is a `CARGO_HOME`, its `registry/src`, or the folder that holds the `name-version` folders. Without it the tool uses `TIME_CARGO_REGISTRY`, then `CARGO_HOME`, then `~/.cargo`.
- `--go-mod-cache DIR` (or `GOMODCACHE`, or `GOPATH`) is a Go module cache. It is optional. A Go module that is not in it is marked "to check" and does not fail the run.
- `--strict` also fails when the licence of a Rust crate could not be read, for example because the crate was never fetched.
- The allowlist, and the list of packages accepted one by one outside it, are at the top of `tools/licenses.mjs`. Changing either is a licensing decision.

The inventory records what each package's authors declare. It is not a legal review.

## Licence

Copyright 2026 The Time Network authors

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The project name and logo are trademarks and are not covered by the licence. You may use, change and redistribute the software under the licence; you may not present a changed version, or a network of your own, as this project.

The software is provided "as is", without warranty of any kind, as the licence says.

## For maintainers: preparing a public copy

`public-manifest.json` names every file that is published. `tools/export-public.mjs` copies exactly those files into a new directory outside the repository, and refuses to finish if any of them contains a private key or other PEM block, an AWS access key, a 12-digit number that could be an AWS account, an email address that is not allowlisted, a path inside someone's user folder, a placeholder the owner has not filled in yet, or a file name the release packager treats as secret. It also refuses when git tracks a file that the manifest neither publishes nor withholds. It publishes nothing itself.

```sh
node tools/export-public.mjs --out ../time-public-copy
```

`--forbid-file FILE` adds your own list of strings that must not appear (one per line; keep the file outside the repository).

Each publication is one commit of the public repository, made as [docs/publishing.md](docs/publishing.md) says; [CHANGELOG.md](CHANGELOG.md) lists what each one brought.
