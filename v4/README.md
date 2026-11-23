# Test the Time protocol 4 candidate

This is the current implementation. It uses real Rust account rules, dynamic
CometBFT validators, independently verified WASM proofs, and a private Bitcoin
Core regtest chain. All coins are test coins. Public monetary operation and
mainnet Bitcoin acceptance remain disabled.

## Open the working lab

From the directory that holds this repository, with the repository checked out
as `production` (inside the repository, leave out the `production/` prefix):

```powershell
node production/tools/start-v4-lab.mjs
```

- Wallet: http://127.0.0.1:8907
- Your application example: http://127.0.0.1:8908

The launcher prints the actual URLs if those ports are occupied. It resumes
`production/.local/lab-v4-current` with the same genesis, accounts, keys, signer
state, databases and proof archives. Seven nodes run on this one computer.
The provided lab's funded handoff rehearsal has activated seven staked validators.
A fresh lab starts with four pinned bootstrap voters until funded successors
activate. These are processes, not independent organizations.

The installed binaries, UI, crypto assets and regtest coins run locally; normal
testing needs no external Bitcoin wallet or internet service. A stopped computer
cannot send or finalize transactions. A cached balance is historical data until
the client verifies a fresh state.

## Try the complete user journey

1. Create an `@name` and a long unique password in the wallet. The lab pays the
   signup fee from an operator's minted rewards. Your browser generates a random
   signing key and stores it encrypted; your password never goes to the example
   application or blockchain.
2. Use the earning screen to create a private regtest BTC payment and submit its
   proof. Wait for the selected earning epoch to close, then claim the seconds.
   The lab mines Bitcoin confirmations immediately. Real Bitcoin confirmations
   and auction lead times would be much slower; this is a UX rehearsal.
3. Create another account, resolve its `@name`, and send a small amount. Review
   the exact recipient, amount and fee. The wallet waits for an independently
   verified receipt and can export public receipt evidence.
4. Open the application example and choose **Sign in with Seconds**. Approve the
   login in the wallet. Then choose **Approve test payment** and approve that
   separate payment. The website never receives your password or private key.
5. In device/security controls, enroll a second device, revoke it, export an
   encrypted backup, and configure recovery guardians before relying on them.
   A backup copies the same device; it does not create independent hardware
   protection. The lab recovery delay is 30 seconds; production requires at
   least two days after guardian quorum. Guardians have a seven-day coordination
   window. Password-only recovery from a totally lost device is not supported.
6. Advanced operator controls expose self collateral, delegation and exits.
   Stake withdrawal still requires fourteen accepted days and the end of voting
   exposure, even in this lab. It is deliberately not shortened for a demo.

Stop cleanly, preserving all state:

```powershell
node production/tools/start-v4-lab.mjs --stop
```

Do not delete or mix a database, its adjacent `application.history` directory,
Comet data, or validator signer state to reset a balance. Older v1/v2/v3 lab
directories are preserved separately and are not silently migrated.

## Reproduce verification

Stop the lab before rebuilding or running an offline audit. Windows locks a
running executable.

```powershell
cd production
$env:CARGO_BUILD_JOBS='1'
.\tools\cargo.ps1 test --locked --manifest-path v4/Cargo.toml
.\tools\cargo.ps1 clippy --locked --manifest-path v4/Cargo.toml --all-targets '--' -D warnings
.\tools\cargo.ps1 build --locked --manifest-path v4/Cargo.toml
cd ..
node production/tools/audit-v4-lab.mjs --lab production/.local/lab-v4-current
```

The fresh-network handoff/fault rehearsal is destructive only to its own process
availability, and preserves its test data. Use a new named lab directory:

```powershell
node production/tools/start-v4-lab.mjs --lab production/.local/my-v4-rehearsal --validate
```

It exercises actual Core payments, receipt binding/replay refusal, pro-rata
earning, seven funded validators, H+2 updates, payments, minority outage, lost
quorum, restoration and native database/signer restart. It is not a WAN or
physical power-loss test. Browser, dependency, module and Linux evidence are
recorded separately under `production/results-v4`, `results-v4-engine`,
`bitcoin-bridge/results`, `deploy/results`, and `releases`.

## Integrate your own application

Use the [client SDK and server guide](../client-v4/README.md). Your backend issues
one-use login challenges and independently verifies finalized device authority.
For payments, it creates an exact nonce-bound quote and verifies the final
receipt before fulfilling an order. A login is never a spending permission.
Background allowances are not enabled. Keep merchant order/idempotency state
durable and shared by all replicas serving the same business orders.

The optional HTTPS gateway adapter and Nginx template provide explicit public
origins behind a local TLS proxy. They do not provision public DNS, certificates,
operators or real-funds deployment. See the [operator bundle](../deploy/README.md).

The [protocol contract](PROTOCOL.md), [dependency review](DEPENDENCIES.md) and
[remaining production requirements](REQUIREMENTS.md) describe the exact
assumptions and limitations. Passing these local tests does not establish
Bitcoin-equivalent security, million-user capacity, or immunity from unknown bugs.
