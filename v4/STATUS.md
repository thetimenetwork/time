# Verification status

Updated 10 November 2026. This is a private test candidate. Real Bitcoin
acceptance and public monetary launch remain disabled.

The wallet, earning rehearsal, transfers, device/recovery controls and separate
website login/payment approval are available through the [local guide](README.md).
The Rust protocol and client release artifacts remain pinned; new experiment
tooling does not silently replace them.

## Verified evidence

- Local seven-validator funded operation, actual private Bitcoin Core payments,
  receipt/replay rejection, payments, quorum loss/recovery and a complete
  authenticated supply/history recount.
- Browser wallet and separate-origin application journeys, Rust/WASM proofs,
  device/recovery rejection cases and durable merchant payment handling.
- Linux production-artifact tests and dependency reviews, with the unmaintained
  transitive dependency explicitly recorded in [DEPENDENCIES.md](DEPENDENCIES.md).
- A Linux database imported byte-for-byte from the Windows checkpoint, followed
  by a full ordinary authenticated audit before further writes.
- **1,000,000 paid registrations / 1,000,007 total accounts**, ordinary durable
  commits and physical cleanup, persisted reopen, sampled proofs, full
  authenticated state/history audit and an independent BigInt money recount.
  The final 620,320-registration tail averaged about **285.76 registrations/s**
  on the measured host/storage configuration, with no eligible cleanup backlog
  remaining. Root independently repeated the complete CSV/journal recount after
  downloading the encrypted S3 evidence. This measures native account-state
  capacity, not Comet mempool or million-user WAN service capacity.
- The fresh three-region WAN run finalized **746 of 746 offered payments**,
  exercised crash/region/quorum-loss recovery and an actual H+2 power update,
  and produced seven complete offline audits with the same height, state root
  and exact supply. The peak wallet phase measured **7.72 TPS / 463 TPM**
  including receipt drain; median verified receipt latency was about **5.17s**,
  p95 **6.65s**. This closed-loop 56-actor workflow hit client backpressure;
  it does not establish maximum consensus capacity or independent ownership.

The [verified WAN summary](../cloud-test/results/wan-three-region-20261110-03-summary.json)
binds those measurements to the actual source, binaries and workload.

The scale evidence is in [the million-account report](../bench-v4/results-linux-normal-1000000/report-1000000.json)
and [the independent recount](../bench-v4/results-linux-normal-1000000/root-independent-bigint-recount.json).
The [Linux methodology](../bench-v4/LINUX-EXPERIMENT.md) preserves the smaller
ordinary-maintenance baseline and distinguishes the earlier deferred-GC trial.

## Measurement limits

A separate run accepted one million paid registrations with physical reclamation
deferred. Its full audit began, but its final result was not retrieved before
the disposable host's termination deadline. **It is not a verified million-account
result.** It is excluded from the completed million-account result above, which
used ordinary physical cleanup. Neither component rate is a WAN TPS result.

The initial experiment's hosts and disks were confirmed absent on 10 November
at 16:34 UTC. A fresh experiment subsequently completed the WAN harness with
automatic encrypted outbound evidence collection. Its seven validator instances
were terminated after evidence retrieval. The separate native million-account
rerun has also passed; its benchmark host remains only while the closed database
is preserved. It does not measure a million active WAN users.

## Before public funds

The remaining [production requirements](REQUIREMENTS.md) include independent
security reviews, genuinely independent operators/custody, signer fencing,
adversarial sustained network testing, checkpoint distribution, operational
procedures and economic review. These checks cannot establish immunity to all
unknown attacks, Bitcoin-equivalent security or maintenance-free operation.
