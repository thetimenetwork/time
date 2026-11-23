# Development protocol v2: state and proof contract

Current implementation also supports explicit protocol-3 development genesis with nonce/expiry-bound merchant references. Existing v2 chains retain their rules. [Current fixes](../FIXES.md) supersede the historical performance observations.

This version changes authenticated storage and proofs. It remains a **private development network** with fixed validators and synthetic earnings. Public monetary launch is disabled. It does not implement permissionless validator selection, slashing, real Bitcoin auctions, audited hardware custody or independent-host operation.

## Identity, amounts and actions

The network identifier is `SHA256("TCDEVNET-NETWORK-V2\0" || canonical Genesis JSON)`. Account action bytes retain the existing 16 domain-separated signed action formats, exact integer decimal strings, next nonce and current authorization epoch. A v1 signature cannot replay because the network identifier differs. Comet headers advertise application version 2; the client rejects other versions.

Genesis starts with zero supply and at most 64 identities. The registry is a disk-backed authenticated map with a development ceiling of ten million identities. The offline scale fixture can create synthetic identities; it is not a demonstration that a million people registered through the wallet.

## Authenticated keys

Jellyfish Merkle Tree 0.12.0 uses SHA-256. A raw key is hashed as `SHA256("TCDEVNET-KEY-V2\0" || raw key)`. Values are exact canonical JSON bytes, not provider-supplied objects reconstructed after verification.

| Raw key | Value |
|---|---|
| `meta` | Protocol version, immutable bounded genesis/network, height/time, bank, aggregate liquid/escrow ownership, pools, bounded auctions/name commitments and next IDs |
| `account/` + eight-byte big-endian ID | Complete account, enrolled devices, nonces, delegations, escrow and recovery policy |
| `name/` + lowercase ASCII username | JSON decimal-string account ID |
| `pubkey/` + original 32-byte identity key | JSON decimal-string account ID |
| `recovery/` + eight-byte target ID | At most five recovery cases; absence is proved |
| `unbond/` + eight-byte entry ID | JSON decimal-string owner ID |

Authenticated global indices enforce uniqueness even when an action loads only a few accounts. Block processing reads dependencies from one pinned database snapshot and stages an overlay. A rejected action cannot publish rows, counters or cleanup effects. The existing signature, permission, recovery and economic rules execute against that bounded view. Every old update path is authenticated before a new Merkle root is derived.

## Conservation

Per-block work does not scan the registry. Changes in touched account liquid balances, unbond escrow and pool shares update authenticated aggregate counters with checked arithmetic. Bank plus aggregate liquid balances, pool assets and escrow must equal accepted elapsed time since genesis. Fees move existing value; shares are ownership records, not extra supply.

The full audit authenticates the complete JMT structure and leaf/value bindings, including auxiliary child kind/count metadata that is not itself bound by the root hash. It then verifies complete bijection with the current raw directory. Only that same immutable verified snapshot admits fast semantic scans to recount every account and pool ownership record, check both directions and cardinalities of identity/unbond indices, reject orphan recovery records and verify aggregate counters. This replaces the older directory-mirror completeness assumption. Working memory is bounded, while running time grows with the registry; CLI progress identifies each phase.

**A compact wallet proof authenticates the selected accounts and aggregate claims against a quorum-certified root. It does not independently sum all other accounts.** The full auditor and continuously validating nodes supply that separate evidence. This distinction is part of the security contract.

## Persistence and retention

One immediate-durability redb transaction atomically publishes current rows, versioned values, JMT nodes, the root, authenticated metadata, finalized-request fingerprint and pruning queues. Finalize prepares privately; Commit publishes. Exact retries return the same complete response; conflicting retries and stale prepared parents reject.

A 4 KiB immutable versioned file prefix separates this format from existing redb/v1 files. The same open file is checked before the offset backend admits redb writes or crash repair. Foreign files are refused without modification. No implicit v1 migration is supported.

The default query window retains 128 versions. The scale fixture uses 32. Commit advances the logical query floor and retirement queues atomically, with zero physical reclamation. Idle maintenance removes at most 128 nodes, 128 values and 16 roots per default transaction, with a cooperative 10 ms work budget. Individual I/O and final fsync can exceed that deadline; it is not a wall-clock guarantee. Queue deletions and a round-robin cursor are durable. Old roots outside the logical window reject immediately. Live shared nodes, retained-root MVCC baselines and old read snapshots remain protected, including deletion tombstones and resurrection.

The running native node starts a maintenance worker. It skips busy locks and unpublished Finalize state. Diagnostic backlog pressure can throttle local CheckTx admission, but never changes ProcessProposal, Finalize or valid-block acceptance. Stable sustained operation still requires sufficient maintenance/disk capacity for the offered workload. Long-lived readers can pin MVCC pages. File allocation can remain at a high-water mark; bounded logical history is not an automatic file-shrink guarantee.

The original genesis root remains recorded for InitChain replay even after its proof nodes leave the query window. Clean restart validates bounded metadata/root identity and authenticates rows as read. Full recount is an explicit audit, not an automatic registry scan at every startup.

## Limits and proof transport

- Consensus block: 1 MiB, including its consensus overhead; aggregate action bytes also capped at 1 MiB. ABCI framing: 8 MiB. Evidence: 64 KiB.
- Metadata: 256 KiB; account row: 32 KiB. Pending name commitments: 256; bids per epoch: 1,024. These are explicit development limits and remain public-distribution bottlenecks.
- `/compact-proof`: up to 32 raw keys at one retained height.
- `/v2/view`: at most eight names, eight IDs and eight original public keys, with sixteen selections combined; at most 256 expanded proof entries and a 3 MiB native response. Each selected name/key is linked to its account proof. Pool-operator rows are included; guardian dependencies expand only from explicitly selected accounts. Wider selections may need separate scoped requests.
- Gateway attaches the signed header at H+1 whose app hash commits the root at state H. The independent verifier checks pinned fixed validators, greater-than-two-thirds power, chain/version, freshness, checkpoint monotonicity, every requested inclusion/absence proof and reference binding. A server `verified` label is not evidence.

Expired or old-epoch recovery cases may remain stored lazily. They are authenticated, then filtered from the active wallet view using the same expiry/epoch rules as the engine. Inert devices with neither spending nor management permission retain the v1 login-by-key-presence behavior; they cannot sign monetary or management actions.

## Fixture boundary

Fixture import/funding methods require the Cargo `fixtures` feature, a dedicated `time-devnet-fixture-` chain identity and bank-only mode. Import proceeds in bounded chunks, with immutable synthetic versions and exact microsecond accounting. Funding moves existing fixture bank issuance to a test sender. The network binary rejects fixture chains both at InitChain and when opening an already-initialized fixture database.

The million-account experiment measures real stored identities, Merkle proofs, normal signed transaction execution, durability, pruning, clean reopen, a full post-pruning recount and process resources. It excludes user acquisition, live signup capacity, WAN/quorum throughput, same-account mempool pipelining and physical power-loss certification.

Primary implementation reference: [upstream JMT](https://github.com/penumbra-zone/jmt) and its [versioned tree API](https://docs.rs/jmt/0.12.0/jmt/struct.JellyfishMerkleTree.html). Using that library does not establish an audit of this integration.
