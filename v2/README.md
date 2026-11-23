# Seconds v2: incremental state laboratory

This separate Rust implementation replaces the v1 whole-registry snapshot with a durable authenticated map and compact selected-account proofs. The local wallet supports signup, earning synthetic seconds, transfers, staking, device approval, guardian recovery and extension-free website login/payment approval. **Public launch remains blocked; use test currency only.**

## Start and test it

From the project root:

```powershell
node production/tools/start-v2-lab.mjs
```

Open the [wallet](http://127.0.0.1:8887) and the [example application](http://127.0.0.1:8888). The launcher resumes `.local/lab-v2-compact` with its saved genesis, accounts, balances and validator signer state. Keep the process running. Ctrl+C stops its owned children; from another terminal:

```powershell
node production/tools/start-v2-lab.mjs --stop
```

The v1 lab on ports 8787/8788 remains separate and its data is preserved. A v1 transaction cannot replay on v2. The browsers' v1/v2 vault origins and application cookies are separate. Neither version accepts real Bitcoin.

1. Create an `@name` and a strong password of at least 15 characters. The browser generates a random device key and encrypts it locally. The account initially has zero balance.
2. Approve one synthetic earning bid and wait for the laboratory auction. This allocates already issued bank seconds; it is not a production earning mechanism.
3. Create a second account in a separate browser profile, then review and approve a small transfer. Check the verified receipt and recipient balance.
4. Enroll another device, or configure consenting guardians before losing access. The password alone cannot recover a key on a new device. Deleting browser data can remove access.
5. Open the example application, approve its sign-in popup, create an order, then separately approve its exact payment. Login grants no spending authority.

All UI assets are local. Signing and fresh balances require the network; opening an HTML file offline cannot send or receive a newly finalized payment. This software wallet does not provide hardware custody.

## Build and reproduce

From `production`, with the local v2 lab stopped before rebuilding its executable on Windows:

```powershell
$env:CARGO_BUILD_JOBS = '1'
.\tools\cargo.ps1 test --manifest-path v2/Cargo.toml --locked --all-features
.\tools\cargo.ps1 fmt --manifest-path v2/Cargo.toml --check
.\tools\cargo.ps1 clippy --manifest-path v2/Cargo.toml --locked --all-targets --all-features '--' -D warnings
.\tools\cargo.ps1 build --manifest-path v2/Cargo.toml --locked --bin time-node-v2
node tools/start-v2-lab.mjs --fault-test
```

The fault mode starts and owns its cluster, terminates only its own children, checks one-validator outage, quorum loss, recovery and native/signer restart, writes a timestamped report to `results-v2`, then stops. It preserves the lab's data. Do not run a second launcher against the same lab concurrently.

For an independent full supply/index recount, stop the lab first and use the offline auditor. It refuses missing databases and preserves existing report files:

```powershell
.\tools\cargo.ps1 build --manifest-path v2/Cargo.toml --locked --example audit
.\v2\target\debug\examples\audit.exe --devnet --db .local/lab-v2-compact/node0/data/application.redb --output results-v2/my-supply-audit.json
```

The auditor never signs, funds or imports accounts. It opens an existing database exclusively; redb can perform its normal crash repair when needed. A full large-registry scan can take over an hour. Current wallet proofs use authenticated aggregate counters instead of running this scan for each payment.

The pinned Rust toolchain, local tool wrapper and consensus build requirements are described in [the parent README](../README.md) and [consensus build instructions](../consensus/BUILD.md). A fresh checkout needs those tools installed; `.tools` and `.local` are private, ignored runtime directories.

This run used Node 26.13.0 and Chrome 156 on Windows. The wallet tests use native Node Argon2 as an independent cross-check, so use the recorded Node version when reproducing the complete suite.

With the lab running:

```powershell
node sdk-v2/smoke.mjs http://127.0.0.1:8887 results-v2/api-smoke-reproduced.json
node web-v2/wallet/tests/browser-e2e.mjs --url http://127.0.0.1:8887 --out results-v2/wallet-browser-reproduced.json --recovery
```

The browser test creates an isolated headless Chrome profile and synthetic accounts. It never attaches to your normal Chrome profile. Recovery and unbonding exercise actual laboratory delays.

## Million-account experiment

```powershell
.\tools\cargo.ps1 build --manifest-path v2/Cargo.toml --locked --release --features fixtures --bin time-scale-v2
node tools/run-v2-scale.mjs --accounts 1000000 --output results-v2/scale-million-reproduced.json
```

Use a new output path for every run. The runner preserves existing reports and databases. It creates deterministic zero-balance synthetic identities, funds a sender from existing elapsed bank issuance, measures normal signed transfer batches, verifies compact proofs, prunes history, cleanly reopens the database and performs a full streamed supply/index audit. It captures process resources and source/binary hashes. This can take tens of minutes and several gigabytes of disk on a shared workstation.

This is a storage/execution component experiment. Repeated prebuilt transfers between two accounts do not measure real mempool, independent-host consensus, million-active-user throughput or signup capacity. Small subprocess crash tests provide separate evidence; the million-account reopen is clean, not a power-loss experiment.

## Integration and release boundaries

- [SDK and proof contract](../sdk-v2/README.md): selected-account lookup, pinned validator trust and backend login/payment verification.
- [Wallet and custody details](../web-v2/wallet/README.md): vault, enrollment, recovery and explicit approvals.
- [Protocol/storage specification](SPEC.md) and [incremental engine invariants](ENGINE_INVARIANTS.md).
- [Current proposal resource bounds](RESOURCE-BOUNDS.md), including the unmeasured dense-account workload.
- [Concrete launch gates](LAUNCH_GATES.md): Sybil-resistant earning, real validator selection, wallet trust/recovery, payment idempotence, public services and operations.
- [Measured evidence](EVIDENCE.md) and [raw results](../results-v2/).

A compact proof authenticates selected accounts and aggregate counters against a quorum-certified root. It does not independently sum the entire registry. The separate native auditor does that full recount. No test or dependency scan proves that hacks can never occur, that custody equals Bitcoin's security, or that the network needs no maintenance.
