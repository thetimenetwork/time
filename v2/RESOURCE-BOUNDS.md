# Current lab proposal resource bounds

Update: the dense read-only guardian loop identified below has been fixed. It is retained as a baseline finding: current `finish` processes escrow indices only for changed accounts. A regression builds five real guardians with 64 signed unbonds each and confirms that a policy action checks zero of those 320 unchanged escrow indices, while corruption of an actually changed account's escrow index still rejects. See [FIXES.md](../FIXES.md).

This is a conservative source-based analysis of the **current four-operator laboratory with a 1,000-transaction mempool**. It is not formal verification or a measured workload of heavily populated accounts. Native sources were not changed for this analysis.

## Assumptions and enforcement points

| Assumption | Current enforcement |
| --- | --- |
| At most 1,000 candidate transactions in an honest proposer's mempool | `../tools/start-v2-lab.mjs`: Comet mempool `size = 1000`; maximum transaction size 1,200 bytes and total mempool bytes 1,200,000 |
| At most 1 MiB of selected transaction bodies | `src/engine.rs`: `prepare_filtered` clamps the byte budget to `ledger::MAX_BLOCK_TX_BYTES`; `../src/ledger.rs`: 1,048,576 bytes |
| Four configured economic operators | Current laboratory genesis. This is a configuration assumption, not the maximum roster supported by the engine. |
| At most eight devices, 64 unbonding entries and five recovery guardians/cases per account | `../src/ledger.rs`: `MAX_DEVICES`, `MAX_UNBONDING`, `MAX_GUARDIANS`; `src/engine.rs`: row and case validation |
| At most 256 pending commitments and 1,024 current auction bids | `src/engine.rs`: `MAX_COMMITS`, `MAX_BIDS`, checked during each action |
| At most 32 KiB per account, 256 KiB metadata, 100,000 changed storage keys and 64 MiB raw incremental key/value bytes | `src/engine.rs`: `MAX_ACCOUNT_BYTES`, `MAX_META_BYTES`; `src/store.rs`: default `max_updates`, `MAX_BATCH_BYTES` |

The native application itself accepts bounded protocol requests; it does not enforce that an operator's external Comet configuration always retains the 1,000-transaction mempool setting. Larger mempools, larger rosters, or other launch settings require a new analysis. A resumed or manually changed configuration must be checked rather than assumed.

## Persisted batch upper bound

To overestimate canonical JSON size, assign **20 decimal digits to every integer field**, including fields whose real limits are much smaller. Use maximum-length usernames and 32-byte hex strings, all eight devices, all 64 unbonding entries, four delegations and a full five-guardian policy. Use `false` for every permission flag because its JSON spelling is longer; this intentionally overestimates even an invalid authority set. This gives an account-row upper estimate of **8,869 bytes**.

Likewise, overestimating five recovery cases with five approvals each gives **2,491 bytes per target's case array**. Those simultaneous approvals need not be reachable: this is an overestimate of serialization size, not a constructed valid state. Metadata with both global arrays full, four genesis identities/operators and overlarge numeric spellings is at most **136,184 bytes**, comfortably below its 256 KiB limit.

At most two account rows are changed by one action. Setting recovery can read five guardian accounts, but it changes only the source account. Economics can additionally change all four operator accounts and all 1,024 bidders at a closing boundary. The following deliberately counts mutually exclusive action patterns together:

| Persisted category | Overestimated count | Bytes charged per entry |
| --- | ---: | ---: |
| Changed accounts | `2 × 1,000 + 4 + 1,024 = 3,028` | `8,869 + 16` for account JSON and raw key |
| Changed recovery arrays | `2 × 1,000 = 2,000` | `2,491 + 17` |
| Unbond ownership indices | `1,000` | `22 + 15` |
| Name/registration-key indices | `2,000` | `22 + 39`, using the longer key for both kinds |
| Metadata | `1` | `136,184 + 4` |

The resulting sum is **32,214,968 bytes**, approximately **30.72 MiB**, versus the store's **67,108,864-byte / 64 MiB** incremental raw key/value limit. The entry count is at most 8,029, below 100,000. Account, case and index values are also below the store's individual value limit.

This bound addresses the specific concern that an honest proposer with the current mempool could accept individually valid actions and then fail in `overlay.finish` solely because its raw incremental batch exceeds 64 MiB. No reachable counterexample was found under these assumptions. It is not a bound on the physical redb transaction size or total process memory: JMT nodes, MVCC/history records, page buffers, repeated copies and encoding overhead are additional work.

## Aggregate commitment and bid limits

`CheckTx` sees committed state, so many competing actions may individually pass while only some can fit the next state. `Overlay::apply` checks commitment and bid capacity against the evolving proposal overlay before accepting each action. Once 256 commitments or 1,024 bids are reached, later competing actions return an error and proposal filtering skips them. Their successful predecessors remain within the limits. A closing auction clears its old bids before transaction execution; a bid signed for an earlier epoch is rejected rather than moved to the new epoch.

Account byte limits and the relevant post-action recovery checks also run before an accepted action publishes its staged changes to the overlay. The final metadata byte check is later, but the current four-operator bounded-array overestimate above remains below that limit. The supply/share checks in `finish` still matter independently; this size analysis does not replace their execution or tests.

## Loaded rows and CPU are different bounds

The overlay caches referenced accounts, including read-only guardians. A proposal with 1,000 recovery-policy actions can reference up to 6,000 distinct source/guardian rows. Adding the four operators and 1,024 closing bidders gives an overestimate of **7,028 loaded accounts**, even though far fewer rows may be persisted. Original and current cached rows, temporary views, transaction buffers and tree/storage work all consume memory. The 30.72 MiB write-batch estimate must not be presented as a heap or RSS ceiling.

There is also a concrete workload to measure next: `finish` currently visits all cached accounts and verifies old unbond ownership indices even for unchanged referenced rows. At 64 entries each, 7,028 cached accounts can cause up to **449,792 unbond-index lookups** in that loop, in addition to account/index reads and signature checks. The state can remain valid while that dependency-heavy proposal is much slower than transfers between two minimal accounts. This is bounded work under the current mempool, but a dense-account CPU/latency experiment has not been run. The sparse million-account fixture does not measure it.

The implementation therefore still needs sustained mixed-action, dense-account and adversarial admission tests before public use. See [LAUNCH_GATES.md](LAUNCH_GATES.md) for economic/Sybil, validator, custody and production capacity gates.
