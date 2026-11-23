# Incremental engine v2: claims and limits

Current code also supports an explicit protocol-3 development genesis. Existing v2 networks retain their rules and network identifiers. See [the current fixes](../FIXES.md); the older v2 measurements remain historical evidence.

This is a private development ledger. These invariants and executable tests are engineering evidence, not a formal verification result or a public monetary launch approval.

## State and authenticated namespaces

Every committed block publishes one JMT root. The atomic store authenticates the same metadata bytes stored in its head. Account and index reads verify a JMT proof against the head pinned by one redb read transaction.

| Raw key | Canonical value |
| --- | --- |
| `meta` | `Meta` JSON, protocol version `"2"` or explicit new-network `"3"` |
| `account/` followed by an unsigned 64-bit big endian ID | v1 canonical `Account` JSON |
| `name/` followed by ASCII username | JSON string containing the decimal account ID |
| `pubkey/` followed by the original 32-byte public key | JSON string containing the decimal account ID |
| `recovery/` followed by an unsigned 64-bit big endian target ID | Up to five canonical recovery cases; absence means none |
| `unbond/` followed by an unsigned 64-bit big endian entry ID | JSON string containing the owner account ID |

The original public-key index identifies a permanent registration identity. It does not establish current signing authority. The account's device list and authority epoch establish that authority. A device key may be deliberately shared between accounts under the inherited v1 rules.

The network ID is `SHA256("TCDEVNET-NETWORK-V2\0" || canonical_genesis_json)`. It differs from v1 for the same genesis. Only canonical v1 action envelopes signed for this new network are accepted; legacy v0 transfer envelopes are rejected.

Only a new `time-devnet-v3-` genesis selects `TCDEVNET-NETWORK-V3\0` and protocol version 3. That version interprets a merchant reference as reserved nonce (8 bytes), expiry in elapsed microseconds (8 bytes), then a 16-byte random identifier. The signed action nonce must equal that reservation and the expiry must be current and at most one accepted day ahead. The existing account nonce rule then permits that same payer/order reference to execute at most once across devices. Another action can consume the reservation; the old quote must then be replaced with a newly approved order. No reference is silently rewritten. Different payer accounts are separate identities and the merchant binds its order to one payer.

## Conservation argument

At genesis, all account balances, bank assets, pool assets, and unbonding escrow are zero. There is no fixture funding path in the default build.

For every block, the engine loads only economic beneficiaries and accounts referenced by the block. It sums liquid balances, escrow, and delegation shares over changed original rows and their final replacements. Unchanged read-only guardians are excluded from both sides, and their unrelated escrow indices are not repeatedly checked. Changed accounts retain the old/new escrow ownership checks. Each aggregate uses checked `aggregate - original_changed + final_changed` arithmetic. It then requires:

```
bank + liquid_total + unbond_total + sum(pool.assets)
    == accepted_block_time - genesis_time

pool_share_totals[i] == pools[i].total_shares
```

The inherited strict v1 transaction rules conserve assets; the narrow trusted economics helper issues only the accepted time delta. `Meta::validate` checks the resulting aggregate equality and canonical bounded metadata before tree preparation. Failed preparation cannot publish either rows or metadata. Commit uses a durable parent comparison, so a stale candidate cannot replace a newer committed state.

This establishes an inductive full-node invariant from valid initialization and valid transitions. A compact account proof authenticates the selected row and aggregate claims under a consensus-authenticated root. It cannot independently count the entire supply. `Engine::audit` performs that separate check: it streams account rows, independently recomputes monetary and share totals, verifies both directions and cardinalities of registration/unbond indices, checks recovery references, and checks the highest allocated account ID. It does not construct a full account vector or trust the aggregate counters as its sum.

The current full audit first walks and authenticates the entire JMT, including exact child kind/count metadata, leaf/value bindings and path shape. It then verifies a bijection between all current raw directory rows and authenticated tree leaves. Only after that complete check does an immutable verified snapshot permit fast semantic lookups. This closes the older directory-completeness assumption. The tree traversal stack and a 4,096-node cache are bounded; per-phase progress is exposed to the offline CLI. The cache never crosses snapshots.

Physical reclamation runs in independent bounded durable transactions, outside consensus commits. Logical root retention still advances atomically with the head. Background maintenance skips a busy application or unpublished Finalize. Local backlog pressure can reject new mempool admission, while ProcessProposal and Finalize never depend on that machine-local pressure. Cooperative time budgets do not impose a hard bound on an individual OS I/O or fsync stall.

The default startup path verifies authenticated metadata and its head in bounded work. It intentionally does not run the whole streamed audit on every restart. The audit is an explicit operation; per-row reads still authenticate their values before execution.

## Bounded rule adapter

The full v1 `State::validate`, clone, and snapshot hash are never used on the account registry during v2 block execution. A small temporary v1 view contains:

- The source, recipient, recovery target, and configured guardian rows required by an action.
- All configured operators and the closing auction's bidders when economics need them.
- The actual highest allocated account as a registration sentinel.
- Bounded common economic metadata and only the relevant targets' recovery cases.

The v1 global registration scans are replaced by authenticated name/public-key indices and a global account count. New IDs must equal the authenticated next account ID. Initial identity keys are unique. Unbond entry ownership has its own authenticated index, so the independent audit detects duplicate IDs without retaining an in-memory set of every entry.

Recovery claims are stored per target. Expired claims are ignored and removed when their target is successfully touched. Up to five expired cases can remain physically stored per inactive target. They grant no authority and cannot freeze the account. Rejected proposal-filter candidates cannot publish their lazy cleanup; a regression test compares a filtered candidate's root with strict execution of exactly its accepted transactions.

## Explicit development limits

- At most 64 genesis accounts; genesis is not the million-account import path.
- At most 10,000,000 registered accounts. This is a configured bound, not demonstrated operating capacity.
- At most 256 pending name commitments and 1,024 bids in the current synthetic auction. These lower v2 laboratory limits are deliberate bounded-work limits. A million accounts cannot all participate in one such auction.
- Metadata is limited to 256 KiB; an account row is limited to 32 KiB. The inherited 1 MiB transaction-body and 20,000 transaction-count block limits also apply.
- Fixed economic operators remain laboratory fixtures. Free synthetic bids have no Sybil resistance, and no Bitcoin lock/bridge proof is implemented.
- Validator selection, economic adversary resistance, open-network admission, long-range trust, production recovery/privacy policy, and maintenance-free operation are not established by this storage redesign.

## Synthetic scale fixtures

The `fixtures` Cargo feature enables explicit methods used only by the offline scale tool. The default ABCI binary does not expose a fixture endpoint. Fixture chains must use the `time-devnet-fixture-` prefix and bank-only economics.

Each importer batch adds at most 10,000 new sequential identities with zero balances. It creates one synthetic one-microsecond block, credits that one microsecond to the bank, and advances the immutable JMT version. Explicit fixture funding transfers already accrued bank assets into an account and preserves conservation; it is not a network earning rule. Real signature verification, nonce/authority checks, transfer execution, atomic storage, and JMT proofs are then exercised against the large fixture registry. Fixture construction results must be reported separately from normal block throughput and actual user earnings.

## Executable evidence

`tests/engine.rs` compares all sixteen action kinds and deterministic mixed sequences against the existing full-state v1 implementation, with network-dependent proofs signed separately for each network. It covers registration races and hidden global collisions; guardian consent, freeze, cancel, finalization and opt-out; device possession and rotation; earning, transfer, merchant payment, staking, unbonding and withdrawal; nonce cancellation; strict/filter root agreement; failed-block rollback and stale commit rejection; exact InitChain genesis replay; durable reopen; semantic metadata corruption; independent index corruption detection; canonical decimals; and cross-network replay rejection.

These tests are bounded samples. They are not exhaustive model checking, a distributed WAN benchmark, a cryptographic audit, or proof that no exploit exists.
