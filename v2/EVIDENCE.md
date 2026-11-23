# V2 measured evidence and remaining limits

This is the preserved **pre-fix baseline**. Its JSON/source fingerprints refer to that captured version. See [the new fixes and measurements](../FIXES.md) for bounded maintenance, stronger full auditing, certified proof queries, portable encrypted backups and the separate v3 payment rules.

**Local development milestone; public monetary launch remains blocked.** The implementation replaces the v1 complete-registry snapshot with incremental redb/JMT state and independently verified compact wallet proofs. The v1 lab and its data remain separate. See [the test guide](README.md) and [concrete launch gates](LAUNCH_GATES.md).

## Working wallet and network

The final four-validator local network uses protocol version 2 and network ID `7fe26af488a28fdbd0ea6a1678b949293e47d596468263c9b18f9d5389913167`. The [wallet](http://127.0.0.1:8887) and [example application](http://127.0.0.1:8888) run on loopback. All four validators are on the same computer.

The [final ready check](../results-v2/ready-check.json) independently verified the selected state at height 3,525, compared all four validators' certified roots, checked current binaries against startup fingerprints and matched native/client sources to their test evidence. Its own supply check uses authenticated counters; the separately listed offline network audit performs the full recount. Hashes bind captured files, not an independently reproducible build or security certification.

| Evidence | Observed result | Artifact |
| --- | --- | --- |
| Native state/engine/ABCI/CLI | 31 passed; one intentionally ignored subprocess entry point invoked by its parent crash test | [Observed commands](../results-v2/native-checks-observed.json) |
| Independent native verifier | 9 passed | [Client validation](../results-v2/client-validation.json), [native log](../results-v2/verifier-native.log) |
| JavaScript and actual WASM verifier | 58 passed, including 26 captured-real-header proof/receipt checks | [TAP log](../results-v2/client-js.tap) |
| Public local API | 25 assertions passed: account creation, synthetic earnings, transfer, website login, exact payment and replay rejection | [Final API run](../results-v2/api-smoke-final.json) |
| Real isolated Chrome | All 14 journeys passed, including recovery, freeze/cancellation persistence, device enrollment/revocation, 60-second unbonding and merchant approval | [Final browser report](../results-v2/wallet-browser-final.json) |
| Owned-process faults | Seven checks passed: one-validator outage, quorum halt, restore, convergence, native/signer restart and independent proof verification | [Fault report](../results-v2/devnet-faults-2026-11-09T13-15-18-764Z.json) |
| Offline full recount of the saved wallet network | 14 accounts at height 3,260; bank + liquid + escrow + pool assets = 4,633,794,703 microseconds, exactly matching accepted elapsed time since genesis | [Network full audit](../results-v2/offline-audit-network-final.json) |
| Rust formatting and strict Clippy | Passed for all v2 targets/features; ordinary network binary built without fixture feature | [Observed commands](../results-v2/native-checks-observed.json) |
| Known dependency advisories | Exact-version OSV queries covered 99 native and 121 verifier lockfile registry packages. Each reported `paste 1.0.15` maintenance advisory RUSTSEC-2024-0436; no other matches | [Native query](../results/v2-dependency-audit.json), [verifier query](../results/verifier-v2-dependency-audit.json) |

The dependency scans do not cover all first-party code, OS/compiler tools or the separately pinned CometBFT Go dependency graph. A maintenance warning remains visible rather than being relabeled a clean audit. No independent security certification is claimed.

Final observed UX timings were 10.90/11.04 seconds for two SDK signups, 4.56 seconds for an SDK transfer, 16.20/17.86 seconds for browser signups and 9.76 seconds for the complete browser send journey. The latter includes UI review handling and refresh. A two-account network proof was 40,900 bytes with 19 entries, including its signed header. These are individual local observations, not latency percentiles or throughput guarantees.

The gateway currently queries the latest native state, then waits for the following signed header that certifies it. Repeated proof requests compound those waits. A separately validated optimization could query the newest already certified historical version instead. This run deliberately freezes the measured implementation.

## Million-account component experiment

**Completed successfully:** 1,000,000 synthetic identities, 3,000,001 current authenticated rows, pruning, clean reopen and a subsequent full supply/index audit. [Native measurements](../results-v2/scale-million.json), [resource/source binding](../results-v2/scale-million.json.resources.json) and [eleven derived consistency checks](../results-v2/scale-million.analysis.json) are preserved. Native source, reused v1 source, lockfiles and the measured binary remained unchanged during the experiment.

| Registry size | Local proof bundle | Prepare 100 transfers | Durable commit | Observed component transactions/second |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 15,136 B | 6.88–8.10 ms | 2.85–3.77 ms | 8,421–9,703 |
| 10,000 | 18,902 B | 7.54–9.36 ms | 3.91–4.60 ms | 7,261–8,738 |
| 100,000 | 24,152 B | 6.71–10.27 ms | 5.18–12.82 ms | 4,331–8,411 |
| 1,000,000 | 26,701 B | 7.93–20.51 ms | 3,878–4,815 ms | **20.68–25.73** |

Each checkpoint has only three batches of 100 pre-signed transfers between the same two minimally populated accounts, with sequential nonces. The rate includes prepare and durable commit, but excludes signing, mempool admission, network consensus and user interaction. The million-account samples updated only two accounts, three rows and eighteen tree nodes per batch. Small-registry component rates are **not production network TPS**.

**The million-account durable-commit spike is the main measured performance problem.** Commit includes synchronous history pruning. This checkpoint still had 942,539 queued stale nodes after the bulk import, with a 50,000-record minimum pruning batch and 32 retained versions. Retiring those large fixture versions occurs on the commit path; filesystem sync and storage effects were not timed separately. The combined 300-transfer rate was 23.33 component transactions/second in that checkpoint. This is evidence of expensive commit work under history churn, not a measured permanent network ceiling. No post-drain transfer benchmark was run. Do not extrapolate the smaller checkpoints' thousands of component transactions/second to a million-account network.

The final drain left 32 retained roots, 3,000,032 versioned values and 4,143,137 tree nodes. The remaining 186 queued stale nodes and 31 values were still protected by the retention window. Final allocated file size was 3,305,439,232 bytes (3.08 GiB); its checkpoint high-water was about 4 GiB. File length includes allocated/free/history pages and does not measure live payload or disk write volume.

Observed process peak was 193,024,000 bytes (184.1 MiB), sampled through the OS high-water counter every 500 ms. A peak after the last sample could be missed. The process used one native thread; final CPU time was 2,448.08 seconds. This was a shared Windows workstation with an i9-12900H, 20 logical CPUs, about 31.7 GiB total RAM and about 3.6 GiB free at startup. Other tests and compilation ran concurrently. These are observed workloads, not saturation capacity measurements or a dedicated-server forecast.

Import reached one million at about 24.3 minutes. The entire native experiment took 68.85 minutes. Its full **post-pruning, post-reopen audit took 42.45 minutes**, which is a substantial operational cost. The clean reopen itself took 6.98 ms in the same process with warm OS cache; this is not cold boot, crash recovery or a power-loss test.

The final independently recounted conservation equation was:

```text
bank         1,013,200,242 µs
liquid         998,800,000 µs
escrow                   0 µs
--------------------------------
total        2,012,000,242 µs = accepted elapsed fixture time
```

The fixture deliberately advances its accepted clock by 2,000 seconds initially and funds a sender from existing bank issuance. This equation verifies exact accounting against that synthetic clock; it is not wall-clock earning or production distribution evidence.

Every enumerated account/index value in the audit is independently proof-checked against one pinned root. Enumeration completeness relies on the atomic raw-directory/JMT mirror invariant; the audit does not reconstruct the complete root from a separate trusted key manifest. The proof bundle above excludes the quorum header and HTTP transport. Its timing covers generation, serialization and verification, including a separate absent-name proof; it is not a pure single-account verification timing.

The next storage performance gate is deadline/budget-controlled reclamation with explicit backlog admission limits, followed by before/after-cleanup measurements, random counterparties and sustained mixed workloads. Simply disabling pruning would trade latency for unbounded history growth. A second gate is faster full auditing with progress/phase reporting. The [source-based resource bounds](RESOURCE-BOUNDS.md) also identify dense guardian/unbond dependency work that the minimal-account fixture does not exercise.

## Security work included

Regression tests cover an update-path authentication gap found during this audit, hidden duplicate identity/name indices, rejected-action cleanup leaking into accepted filtered batches, corrupted rows/tree values, stale prepared commits, exact Finalize/Commit retries, replay across restart, abandoned Finalize state, foreign database non-mutation, before/after-commit subprocess aborts and fixture-database isolation from the network binary.

The independent verifier also rejects malformed, omitted, substituted and incorrectly bound selected account proofs and receipts. Expired recovery claims are filtered using engine rules, and legitimate inert login devices do not make the account view unusable. V2 application cookies are separate from v1 despite browsers sharing cookies across localhost ports.

The engine's sixteen action rules are checked against the full v1 implementation and mixed deterministic workloads with independent recounts. Reusing rules gives useful regression evidence, while a shared design error can still affect both implementations. [The protocol specification](SPEC.md) states the authenticated-counter versus global-recount boundary explicitly.

## What the measurements do not establish

There is no demonstrated million-user onboarding rate, uniform active-account workload, sustained network TPS, independent-host WAN test, physical power-cut test, external audit, Bitcoin-equivalent custody or maintenance-free operation. The fixed validator roster is not selected or slashed by the staking pools. Synthetic bids provide no production Sybil resistance; global commitment/bid bounds can be saturated. Hardware wallets, password-only portable key recovery, changing-validator light clients, global duplicate-payment prevention and public service operations remain unfinished.

The next capacity experiment must use many independent senders through real CheckTx/mempool/ABCI/consensus, measure latency percentiles and overload, and include signup/auction/recovery traffic. Prebuilt sequential nonces accepted by the offline engine do not imply that the current mempool queues future nonces. Resolve the earning/admission and validator-security designs before a public launch.
