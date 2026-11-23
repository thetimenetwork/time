# Reproduced findings and verification scope

This is an internal development audit log. It is not an independent auditor's
opinion and does not establish exploit absence. Each result applies to the
source/artifact hashes in its report. Earlier passing runs are preserved when
later review finds another issue.

| Finding | Mechanism | Candidate fix |
|---|---|---|
| Dust delegation hijacks rewards | The first one-microsecond delegated share switched an owner from receiving all R to receiving only commission, despite a one-day self bond | Explicit reward version one: proportional self/delegated gross shares, commission only on delegated gross; tests at 0/10/20% |
| H+2 exit reward windfall | Normalizing only remaining live capital can redirect departed self capital's old voting reward to a tiny remaining pool | Bounded pending-exit reward weights through the last rewarded voting height; that portion remains in bank |
| Withdrawal starts too early | Request H+2 plus fourteen days can precede the actual end of a self-exiting validator's voting exposure | Later of authenticated release and actual last removal, plus fourteen days |
| Candidate directory occupation | A dust claim could keep a retired slot occupied after the operator recovered its bond | Automatic inactive archiving preserving every claim; bounded active directory; stronger safe entrants can replace weaker inactive candidates |
| Free signup exhausts global resources | Free anonymous commits could occupy 256 slots or exhaust the old ten-million account cap | New-device-consented sponsored44, paid individual commitment rows, bounded expiry queues; remove arbitrary registry cap |
| Recovery requires ten-minute coordination | Claim expiry left almost no asynchronous approval window despite a two-day policy delay | Pinned seven-day coordination window; full post-quorum delay retained; legacy wrappers keep their old rule |
| Historical indexes grow in current tree forever | Four per-height rows per second accumulate about126 million rows/year | Compact authenticated canonical history plus fourteen-day recent indexes; durable external append archive |
| Stale prepared archive truncation | Archive-before-ledger commit could rewind a now-committed archive if a stale prepared block ran first | Check current authenticated head/summary before archive mutation; exclusive writer; durable-before-ack and crash-ahead recovery tests |
| Receipt archive poisoning | RPC could return another valid transaction under a requested hash; downstream rejected it but the archive entry became unusable | Verify exact requested hash before writing the archive |
| Guardian UI target disappears | Automatic own-account refresh discarded an explicitly looked-up nomination target | Preserve target in subsequent authenticated selections; test beyond refresh interval |
| Open vault survives failed signup | Network failure after local key creation could leave an unlocked temporary key without the normal idle lock | Lock/forget plaintext on failure; preserve the encrypted vault; real browser resume regression |
| Funding proof exceeds action budget | A Bitcoin transaction allowed by the SPV library could exceed the JSON action envelope | Compact hex wire and explicit240KiB signed-transaction/4KiB proof budget checked before broadcast |
| Policy-rotation receipt race | Already-included old-destination payments could lose admission at activation | Bounded one-day delivery grace using preserved old Bitcoin cutoff; no promise for late mining/deadlines |
| Emergency control blocked by shorter-work fork | A valid greatest-work Bitcoin fork can have lower height, making an all-coordinate monotonic check reject pause/cancel | Restrictive controls require monotonic Time; Bitcoin high-water remains preserved for resume, proposal and activation |

The reward finding is a particularly useful limit on supply tests: conservation
passed while the allocation was exploitable. With R=10,000 microseconds and10%
commission, one microsecond of delegated capital received9,000 while the owner
had86,400 seconds locked. The corrected equal-capital case pays owner5,500 and
pool4,500; dust and H+2-exit cases also need explicit rejection/withholding tests.

Reports before `reward_version:1` describe the earlier economic behavior. They
remain useful historical evidence but are not final reward-version-one passes.
The new explicit genesis field changes network identity; old laboratory databases
are preserved separately and never silently reinterpreted.

Coverage includes real Ed25519 and official Comet signing encodings, JMT presence
and absence proofs, malformed/mutated proofs, exact nonce and authority binding,
atomic staging, exact Finalize replay/restart, full state/index/escrow/supply
recounts, Core transaction inclusion/reorganization, funded validator changes,
quorum loss/restoration, encrypted browser vault/device/guardian flows and actual
HTTPS proxy validation. Each workload and limitation is recorded separately.

Remaining protocol/economic assumptions, missing external validation, maintained
dependencies and adoption bottlenecks are listed in [requirements](REQUIREMENTS.md).
The unmaintained `paste` dependency warning is retained in [dependency review](DEPENDENCIES.md).
