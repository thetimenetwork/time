# Contributing

Thank you for looking at this. Read the "Status" section of `README.md` first: the network has not launched, the software accepts development chains only, and it has had no external audit.

Security problems are not reported here. See `SECURITY.md`.

## Build and test

You need Rust 1.99.1 (installed by `rustup` from `rust-toolchain.toml`), Node.js 26 and a C toolchain. Nothing is installed with npm.

Each Rust crate has its own `Cargo.lock`. Always pass `--locked`, so that the versions in the lockfile are the ones built.

```sh
cargo test --locked --manifest-path v5/Cargo.toml
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

The `v5` suite needs `node` on the path. On Windows, `.\tools\cargo.ps1` can be used in place of `cargo`; pass `'--'` in quotes through it.

```sh
node --test client-v4/*.test.mjs deploy/gateway/*.test.mjs web-v4/wallet/*.test.mjs
node --test tools/release-v4.test.mjs tools/release-v5.test.mjs tools/genesis-v5.test.mjs
node --test tools/licenses.test.mjs tools/export-public.test.mjs
```

Lints, as the project runs them:

```sh
cargo clippy --locked --all-targets -- -D warnings
```

Run the suites of everything your change touches before you open a pull request. Continuous integration runs all of them on Linux.

## Files are stored byte for byte

`.gitattributes` turns off line-ending conversion, because release identities and tests hash files. Two consequences:

- Do not reformat a file you are not changing, and do not change line endings. Set `core.autocrlf` to `false` for this repository.
- Some files are part of a release identity: the sources and lockfiles listed in `tools/release-v4.mjs` and `tools/release-v5.mjs`, the files of the deployment kit under `deploy/`, and the SDK, wallet and verifier files in `CLIENT_FILES`. Any change to one of them changes the identity of the next release. That is expected for a real change; it should not happen by accident. For this reason existing source files carry no licence header: the licence of the whole repository is in `LICENSE`.
- The compiled verifier in `web-v4/shared/verifier` is built from `verifier-v4/` and `history/`, and the committed copy is the build of Linux x86-64. If you change either crate, build the copy on Linux x86-64 (`node tools/build-verifier.mjs`) and commit the result with your change. A build on another system gives a different `.wasm` file from the same source (measured on Windows), and continuous integration refuses it. `node tools/build-verifier.mjs --local` writes such a build so that you can try your change; do not commit it.

If you add a file under `tools/` or `deploy/`, check whether the release allowlists need it (`tools/release-v4.mjs`, `tools/release-v5.mjs`) and whether the test counts in `deploy/verify.mjs` still hold, and say what you found in the pull request.

A new file is not published until it is named in `public-manifest.json`; `tools/export-public.test.mjs` fails while git tracks a file that the manifest neither publishes nor withholds.

## Dependencies

- Rust dependencies are pinned to exact versions in the manifests and locked. A change of dependency changes a `Cargo.lock`: run `node tools/licenses.mjs` (see `README.md`) and commit the new `THIRD-PARTY-LICENSES.md` with it. A licence that is not on the tool's allowlist needs the maintainer's decision first.
- The JavaScript has no npm dependencies. Do not add one without discussing it first. Code vendored into the wallet needs an entry like `web-v4/wallet/vendor/PROVENANCE.json`: where it came from, its hash and its licence.
- The CometBFT build and its Go module versions are described in `consensus/BUILD.md`.

## How changes are reviewed

- Every change goes through a pull request and is reviewed by someone other than its author before it is merged. While the project has one maintainer, the maintainer's own changes are the exception: each stays open as a pull request for at least two days, with every check passing, so that anyone can read it and comment, and is then merged.
- A change comes with tests that fail without it. For a fix, that is a test that reproduces the fault.
- Say in the pull request what you ran and what you could not run. "Not tested on Linux" or "not run against a live network" is useful; silence is not.
- Keep claims exact. Documentation here separates what is built, what is tested, what has run on a real network and what has not. Keep that separation in what you write.
- Small pull requests are reviewed sooner than large ones.

### Changes to consensus rules

A change to what a node accepts or computes is a protocol change: ledger rules, staking, fees, issuance, the genesis format, the encoding of state or of proofs, what the light client accepts. A different result on one node splits a network, and a wrong rule can lose money that is not yours.

**A protocol change needs a written design and an independent review before any code is merged.** The steps are in `GOVERNANCE.md`. In short: open an issue with the design, have someone other than the author review it, wait for the maintainer's decision, then write the code and its tests against the accepted design.

Such a change must also keep these true, and its tests must show it:

- Every node computes the same bytes from the same blocks. No clocks, random numbers, floating point, map iteration order or platform-dependent behaviour in block execution.
- The supply rule holds after every block, and the recount (`time-node-v5 --devnet --db PATH --audit`) still passes.
- A network that does not use a new setting keeps its genesis bytes, its network id and its state roots (`v5/tests/differential.rs` compares the engine with the protocol-4 application block by block).
- The devnet-only guard stays. Removing it is the owner's decision and needs more than a pull request (`deploy/PRODUCTION-V5.md`).

Performance work that leaves every result byte for byte the same is not a protocol change, but say how you checked that.

## Licence of contributions

The project is under the Apache License 2.0. Unless you say otherwise in writing, anything you submit for inclusion is under that licence, as its section 5 says.

Neither a sign-off line (Developer Certificate of Origin) nor a contributor agreement is required.

Only submit work you have the right to submit. Do not paste code from projects under a licence that is not on the allowlist in `tools/licenses.mjs`.

## Conduct

`CODE_OF_CONDUCT.md` applies to everything in this project.
