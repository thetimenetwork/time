# Production requirements and adoption limits

The current result is an executable private staging candidate. It is suitable
for testing the user journeys in the [guide](README.md), not for accepting
valuable Bitcoin or selling a security guarantee. The binary has no monetary
enable switch. Internal checks cannot commission an independent audit, operate
independent businesses, establish honest stake ownership, or test absent hardware.

## Implemented software and exercised evidence

| Component | Current behavior | Evidence boundary |
|---|---|---|
| Rust state machine | Zero premine; exact accepted-time minting; atomic account/module changes; durable JMT/CAS commits | Full seven-node recount and archive audits; not proof of accurate UTC |
| Consensus/PoS | Real H+2 updates, funded handoff, rolling weighted churn, escrow, evidence/slashing, exposure-aware exits, inactive candidate archiving and stronger-entry admission | Local tests and seven AWS hosts across three regions; production profile also simulated; one controlling operator |
| Bitcoin earning | Validated PoW/difficulty/fork choice, real transaction/output/Merkle proof, beneficiary/epoch/policy binding, permanent outpoint consumption, bounded old-policy delivery grace | Actual Core regtest payments and reorgs; SPV model, not full Bitcoin script/UTXO validation |
| Foundation | Four-of-seven Bitcoin script; separate five-of-seven policy control; dual acknowledgement, delays, pause/cancel, preserved old cutoffs | Prototype/native cryptographic tests; no real multisig ceremony, independent custody or disaster recovery |
| Account wallet | Local encrypted random keys, sponsored signup, verified balances, send/receive, devices, backup, delayed guardians | Desktop/mobile browser runs; no blanket hardware or native mobile app certification |
| Light client/history | Actual voting-power updates, bisection, seven-day trust expiry, independently pinned refresh, compact canonical history | Local Rust/WASM and real header/proof fixtures; relies on trusted wallet distribution and local checkpoint storage |
| Website SDK | Origin/session/authority-bound login, separate exact payment approval, durable orders, canonical receipts, TLS proxy adapter | Actual separate-origin browser journey and private-CA TLS tests; no background spending allowances |
| Operations/releases | Digest-pinned Linux build, source/binary/evidence identities, SBOM, private services, signer lease/restore guards, readiness and monitoring | Windows/Linux tests and bounded multi-host crash/recovery; external signer security and independent production operations remain gates |

Historical v2/v3 million-account or TPS reports describe their recorded code and
workload. They do not automatically apply to v4. The new v4 benchmark records
its own dataset, native block work, signing, commit/GC/audit costs and limitations.
Virtual accepted time used to generate a benchmark is not wall-clock earning.
Direct native block execution is not Comet mempool, WAN or end-user throughput.

## External gates before valuable use

- Independent protocol, implementation, wallet/recovery and Bitcoin reviews,
  remediation, and signed attestations for exact reviewed artifacts.
- A sustained adversarial testnet across genuinely independent hosts/operators,
  power/custody/provider diversity, realistic network delay, eclipse/partition
  tests, storage interruption, clock faults and upgrades. More than two thirds
  power finalizes; withholding at least one third can halt. Headcount alone is
  insufficient. The lab does not supply twenty independent bootstrap businesses.
- Production Bitcoin checkpoint/chainwork bootstrap, explicitly reviewed SPV
  assumptions and peer/connectivity policy, viable confirmation/auction timing,
  reorg-halt recovery, monitoring, custody procedures and fee funding. A policy
  change or missed admission window does not create an on-chain Bitcoin refund.
- A reviewed remote signer enforcing a monotonic fence on every signature,
  including cloned-machine/partition/restore tests. A PID, filesystem lock or
  signed startup lease is not a cross-host signing fence.
- Authenticated fresh-checkpoint distribution for new wallets after day seven,
  existing-device trust transfer, and a recovery process when all local trust
  state is lost. A fresh-looking RPC response cannot supply its own authority.
- Exact supported browser/device/OS/firmware testing. Hardware signing needs
  readable protocol-aware approval and vendor support. The external signer
  interface does not certify every Ledger, Trezor or other device.
- Real TLS/DNS deployment, authenticated software releases, backups/restore drills,
  archive availability, monitoring ownership, incident response and security
  maintenance. The temporary paid AWS experiment uses one controlling account;
  it does not establish independent production operators or a public monetary
  service.

The operator launch checker keeps external gates outstanding unless appropriately
scoped independent signed evidence is supplied. A generated `passed: true`, test
key, container count, or this document cannot satisfy them.

## Capacity and economic constraints to test

**One global issuance stream.** The entire network mints one currency second per
accepted second, shared by participants. A million people do not each mint one
second every second. A hundred production self bonds of one day need at least
100 days of global issuance. The nominal 90-day fade is not a funded handoff.

**Registration is priced, not made Sybil-proof.** Default signup costs the sponsor
10,000 microseconds plus the ordinary 1,000-microsecond action fee. A valid-key
spammer must now pay rather than monopolize a free global queue. Sustainable
pricing, sponsor budgets, paid-state growth and expiry backlogs still need
economic/load review. New-account allocation no longer stops at ten million.
One sponsor account normally admits only one current nonce per block through
the mempool; multiple sponsors or a future reviewed batching policy are needed
for high-volume onboarding. Login itself has no on-chain fee.

**Fee treatment matters beyond hardware TPS.** Ordinary charged operations cost
1,000 microseconds. Current fees return to the bank; the current auction reserves
80% of each populated epoch's newly minted supply, and validator rewards cover
at most 20% of accepted time. There is no general withdrawal of accumulated bank
fees. Consequently high sustained fee demand can drain circulating balances even
if computers can execute the transactions. At the current fee, 1,000 charged
transactions per accepted network second consumes one currency second in fees, equal
to the entire new issuance stream. Bursts can use existing balances; this is an
economic-flow calculation, not a measured technical TPS ceiling. Fee pricing and
bank redistribution need explicit review before broad adoption. They must not
be silently changed merely to advertise a larger throughput figure.

**Stake admission is bounded work.** The active candidacy directory has 256 slots
and the voting set at most 100. A stronger entrant can displace a weaker inactive
candidate outside its evidence exposure. Current/scheduled or still-exposed
authority is protected. Existing claims survive archiving. An archived operator
cannot reactivate old exit pools; it must settle claims or use a new account/key.
This avoids exposing old exit claims to new offenses, but is an operator UX
constraint when a delegator leaves an old claim uncollected.

Reward version one fixes the first-dust-delegator hijack and withholds departed
capital's reward through the H+2 lag. Per-block integer fractions round to the
bank. A very small pool can earn zero indefinitely until its collective share
crosses one microsecond per payment; no linear APY promise is made for dust.

**Proof/archive storage still grows.** The current canonical history frontier is
compact and recent per-height indexes are pruned outside fourteen days. Live
exit clocks remain until all referenced claims are gone. The separate history
archive format costs approximately 104 bytes per block, about 3.28 GB/year at
one block per second, before filesystem overhead. Accounts, receipt deduplication,
Comet history, orders and indexes add storage. Measure sustained disk growth and
proof service recovery; this is not a constant-disk or no-maintenance system.
The application currently returns `retain_height=0`, so Comet blockstore and
transaction indexes are retained separately. The 104-byte history format is
not a whole-node storage estimate.

**Funding has a supported envelope.** Compact receipt version one supports a
240 KiB Bitcoin transaction and 4 KiB Merkle proof. Check before broadcast.
Bitcoin confirmation time and auctions govern earning latency; payment finality
on Time is a separate measurement. The regtest's instant mining is not a forecast.

**Gateway scaling is separate.** The reference uses durable SQLite order storage
and one-writer checkpoint/archive state. Replicas for the same merchant need a
shared transactional idempotency store or a reviewed ownership/routing strategy.
Do not put SQLite on an arbitrary network filesystem or label one local gateway
as million-user service capacity. RPC/proof witnesses and old receipt archives
also need independent availability and abuse controls.

**Usernames do not make payments private.** Account names, balances, transfers
and authority relationships are visible to participants observing the ledger.
A password protects the local signing vault; it does not hide those public
records. A public product needs clear privacy disclosures and a reviewed
approach to account linking, recovery contacts and Bitcoin payment metadata.

## What security statements are justified

The recorded tests reproduce specific attacks, check their rejection, exercise
real signing/proof code, and independently recount specified invariants. They
are concrete evidence for those source hashes and workloads. They do not prove
that all exploits have been found, that validators will remain honest, that a
foundation quorum cannot be compromised, or that this young PoS network has
Bitcoin's security history. Public launch and zero-maintenance claims are not
established by the current work.
