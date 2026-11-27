# Version-5 engine

The protocol-4 ledger on a faster execution engine. Same accounts, same actions, same proofs for wallets. Development networks only: public monetary launch stays disabled.

## What changed, in one table

| | Protocol-4 node | Version-5 engine |
|---|---|---|
| State | Merkle tree in a disk database; every read re-proved from disk | Persistent Merkle tree in memory; roots and proofs byte-identical |
| Durability | Disk commit and two file syncs per block | Checksummed snapshots; CometBFT replays the blocks after the newest one |
| Block execution | Two or three times per block, under one global lock | Once: the result of validating the proposal is reused when the block is finalized |
| Signatures | Checked one by one, again on every execution | Checked once, on all cores, remembered by transaction hash |
| Mempool | Each transaction checked against the last block only | Checked against what is already waiting: nonce sequences are admitted, duplicates of a nonce are refused. What carries an expiry is admitted only if it is still valid 30 seconds after the last block |
| Queries | Wait for block execution | Read an immutable committed version; run in parallel with everything |
| Block size | 1 MiB of transactions (about 5,000 transfers) | 4 MiB (20,000 transfers) |

Five rules differ from protocol 4 on purpose; every validator of a network must therefore run the same engine:

1. A block may carry 4 MiB of transactions (and one block may change up to 200,000 rows or 256 MiB of state, twice what protocol 4 allowed; no block of 20,000 actions comes near either).
2. `CancelPending` pays the standard fee (it was free and unconditional).
3. `SetRecovery` with no guardians turns guardian recovery off (it was always rejected).
4. Double-signing evidence is verified with the signature rule consensus uses, so conflicting votes that consensus counts can always be proven.
5. The misbehavior CometBFT reports with a block (duplicate votes and light client attacks it has verified and committed as evidence) is punished before the block's transactions, exactly as a double-signing evidence action (kind 20) would punish it, without anyone having to submit one. Protocol 4 ignores that list. See "Misbehavior reported by CometBFT".

One set of rules is new: account security (kinds 70 to 77, below). The protocol-4 engine does not know these kinds, which is one more reason for every validator to run the same engine.

Two rules are settings of the network, off unless its genesis turns them on: `fees_to_validators_ppm` pays fees on to validators instead of leaving them in the bank (see "Fees paid on to validators"), and `fee_micros` lowers what an action costs (see "The amount of the fee"). A network without the settings keeps its protocol-4 encoding and network id.

So is a third rule, `distinct_names`: the network refuses a new account name that looks like a name that exists (see "Names that look alike"). The production profile requires it.

Two more settings protect accounts, and the production profile requires both. `waits_survive_stops`: the waits and freezes of account security do not run while the chain is stopped (see "Waits that survive a stop"). `protected_registration`: an account can exist with its keys in their roles from its first block (see "Accounts protected from the start").

One more keeps facts and changes no rule: `service_records`, the history of validators, stake and accounts from the first block, for rules that may come later (see "Service records"). The production profile requires it. `spec/settings.md` specifies these four settings.

## Running a node

```
time-node-v5 --devnet --db PATH [--listen 127.0.0.1:26658 | unix:/absolute/path] [--snapshot-seconds 120] [--clock-tolerance-seconds 30] [--stay-after-disconnect]
             [--state-sync-snapshot-blocks 0] [--state-sync-snapshots-kept 2] [--state-sync-max-mib 16384] [--keep-blocks 0]
             [--stop-after-height H] [--expect-root H:ROOT]
time-node-v5 --devnet --db PATH --audit
```

- `--listen unix:/path/abci.sock` creates a socket that only the node's own user can open; set `proxy_app = "unix:///path/abci.sock"` in CometBFT. A loopback TCP port (the default) can be reached by every program on the machine.
- `--clock-tolerance-seconds N` (default 30, from 1 to 60): `ProcessProposal` rejects a proposed block dated more than N seconds ahead of this machine's clock, and logs why. CometBFT has its own, wider limit, `consensus.block_time_tolerance` (60 seconds by default), so a value above that has no effect unless that is raised as well. Keep the clock synchronized (NTP, chrony). See "Block time and this node's clock".
- State is saved under `PATH.v5state/` (the two newest snapshots) and block history under `PATH.history/`.
- On start the node loads the newest snapshot that passes its checksum and whose rows hash to the recorded Merkle root. CometBFT then replays later blocks. If snapshot files exist and none is valid, the node refuses to start instead of silently replaying from genesis.
- CometBFT must keep the blocks since the oldest snapshot. By default the node asks CometBFT to keep every block. With `--keep-blocks` it lets old blocks go, but never one after its oldest snapshot (see "State sync and pruning").
- `--state-sync-snapshot-blocks N` makes the node offer snapshots to peers that join through CometBFT's state sync; any node can join that way. A node that did holds no block history from before it joined (see "State sync and pruning").
- `SIGTERM` writes a final snapshot before exit (code 0). Without `--stay-after-disconnect` the node also saves and exits when CometBFT disconnects, with code 3 so that a supervisor restarts it.
- Exit code 4 means the node stopped at a height on purpose: the chain moved to a protocol version this program does not implement, `--stop-after-height H` was reached, or a decided block carries a rule switch. A supervisor must not restart it blindly; the first line of its report says why (see "Upgrades").
- A start that fails ends with exit code 1. The node prints the reason, then the usage text (about 4,000 characters), then the reason again as its last line: `The node did not start: …`. A supervisor that keeps only the last lines of what a program printed still has the reason.
- `--expect-root H:ROOT` is for a restart on a state the validators agreed on, in an emergency: the node goes on from height `H` only if its state there has that root (see "The fix release and its switch").
- A decided block that fails a check of this program ends the node in the middle of that block, with exit code 1. Its last lines begin with `FAILED ON A DECIDED BLOCK` and name the block and the state the node is left at. Do not restart it in a loop: `docs/emergency-fix.md`.
- Keep CometBFT's mempool re-check on (its default): after every block it tells the application which pending transactions are still valid.
- `--audit` recounts the whole saved state from scratch: every hash in the tree, every account, the supply rule and the block history file.
- Worker threads default to all cores. Set `RAYON_NUM_THREADS` to leave cores for CometBFT.

CometBFT settings that matter for large blocks: `mempool.size`, `mempool.cache_size`, `p2p.send_rate`, `p2p.recv_rate`, `rpc.max_request_batch_size`, and `tx_index.indexer = "null"` on validators. The values used in the measurements are in `campaign/controller-v5.mjs`.

To run the validators of a production-profile network, use the deployment kit (`deploy/README.md`, the version-5 section) and the genesis ceremony (`deploy/PRODUCTION-V5.md`).

### Block time and this node's clock

Under CometBFT 0.38 a block's time is the median, weighted by voting power, of the times in the precommits its last commit carries. More than half of the signing power sets it, and so does just over a third when one of its validators proposes, because the proposer chooses which precommits (any two thirds) the block carries. The ledger rules only require it to advance. Two checks keep such a group from fast-forwarding what waits for time (the new time each block issues, the 14-day hold on unbonded stake, the 90-day fade of the starting validators' power):

- CometBFT itself refuses a block dated `consensus.block_time_tolerance` (60 seconds by default) or more ahead of the node's clock (`state/validation.go`). Its node prevotes nil on such a proposal, stops with a panic if two thirds prevote or commit it all the same, and refuses it in block sync.
- The application narrows that: in `ProcessProposal` a node rejects every proposal dated more than `--clock-tolerance-seconds` ahead of its own clock (`app::DEFAULT_CLOCK_TOLERANCE`, 30 seconds), before anything of it is executed or remembered, and logs the reason. This rejection only costs the node's prevote: CometBFT still precommits and commits a block that two thirds prevoted.

- Only live proposals are judged by the application. `FinalizeBlock` (a decided block, a replay after a restart, block sync) and `PrepareProposal` never look at the clock: the application never refuses a decided block for its date, and a proposer does not choose the block time. (CometBFT's own check applies to decided blocks too, before they reach the application.)
- Why 30 seconds: an honest block is dated in the past, when the validators voted on the block before it, as their own clocks read. Clocks kept by NTP agree within tens of milliseconds; one whose synchronization has failed drifts by about 4 seconds a day (50 parts per million), so 30 seconds covers about a week of that. What it leaves a group that sets block time is a one-time advance of the chain's clock by at most 30 seconds, which cannot grow because every proposal is compared with the clock again: half of what one block can issue, nothing measurable against the 14-day hold or the 90-day fade. (On a laboratory network, whose fade lasts 60 seconds, it is a large part of the fade.)
- Liveness: a validator whose clock lags the others by 30 to 60 seconds prevotes nil. If more than a third of the voting power does, rounds fail until the clocks reach the proposed time; the next proposals of that height carry about the same time (it comes from the votes of the height before), so the height is decided late, not never. A node 60 seconds or more behind is stopped by CometBFT's own check as soon as two thirds commit a block it deems from the future: keep clocks synchronized. If more than half of the power dates blocks ahead and more than a third keeps correct clocks, the chain slows down to the correct clocks instead of running ahead of them.
- Safety is not affected: CometBFT's agreement does not depend on how validators judge a proposal, and executing a decided block never reads the clock, so every node reaches the same state.
- More than two thirds of the voting power can decide blocks without anyone else's prevote, but no further ahead of the other nodes' clocks than CometBFT's tolerance: beyond it those nodes refuse the block, or stop rather than apply it.
- `App::open`, which tools, the benchmark and the tests use to drive chains with synthetic dates, judges no clock. The node binary always opens with `App::open_with_clock`.

### Misbehavior reported by CometBFT

CometBFT verifies evidence of double signing (duplicate votes) and of light client attacks, commits it in blocks, and hands it to the application with each block as `misbehavior` (type, validator address and power, height, time). The engine punishes each entry after the block's begin-block steps and before its transactions, exactly as an evidence action (kind 20) at the head of the block would: all self collateral and 5% of the delegated stake, live and departing, go to the bank, the validator is jailed and leaves the roster at H+2, and the validator safety hold is on while it is still in it. Nobody pays a fee or submits anything (`pos_adapter::misbehavior`).

- The offender is found by its consensus address in the roster of the offense height. A light client attack is reported at the common height, but when it is an equivocation CometBFT names validators of the later, conflicting height's set (`GetByzantineValidators`), which may have joined since: such an entry, if its address is not in the roster at the common height, names the current candidate with that address, provided it has been a validator after that height (in the roster now, or removed from it later). The 14-day window is still counted from the reported height. A duplicate vote always names a validator of its own height. The offender must still be a candidate: one that has left the roster but is not archived is punished, as kind 20 punishes it, because its stake stays exposed for 14 days after it last voted.
- Skipped, deterministically and with no effect: a type other than these two; an entry naming no validator, or an address that is not 20 bytes; a height that is not a committed height whose history the state still holds (not positive, not below the block's own height, or already cleaned up); an entry already punished (same type, address and height, earlier in the list or in an earlier block); an address of no validator of the roster at that height (but see light client attacks above); a validator that is no longer a candidate (archived or gone) or whose consensus key differs; a validator already jailed (by kind 20, by an earlier entry or block); an offense more than 14 days older than the block, which kind 20 refuses as well (CometBFT's own limit is the longer of 14 days and 2,000,000 blocks). Only a state that fails its own checks can make a block fail here, never the list.
- Each punished entry leaves the row `pos/misbehavior/` ‖ type (1 byte) ‖ address (20 bytes) ‖ height (8 bytes, big-endian), holding the height of the block that punished it. The recount (`--audit`) checks and counts these rows. On a network with service records the punishment is also recorded with the owner account, for good (see "Service records"), and so is one by kind 20.
- Kind 20 still works for evidence CometBFT never reported. For a validator already punished either way it is refused ("validator already jailed/slashed").
- The list is part of what a block is executed with, by the proposer (`PrepareProposal` selects the transactions on the state after the penalty), by validators and by `FinalizeBlock`, and part of the key under which a validated proposal is reused. A node that only sees `FinalizeBlock` (replay, block sync) reaches the same state.
- From the block that carries the evidence until the offender leaves the roster at H+2, the safety hold refuses ordinary actions, as after kind 20. If the roster cannot lose the offender (fewer than four validators would remain and funded candidates cannot make up the number, or one would hold more than a third of the power), the hold stays, as after kind 20.
- **Four validators: one report stops ordinary payments.** On a network of four validators, a single reported double vote jails one of them, which leaves three: the offender stays in the roster and the safety hold refuses every ordinary action, payments included, until a funded candidate registers (kind 17 is allowed during the hold) and can take its place at H+2. Kind 20 does the same, but now nobody has to act for it to happen: any double signing, including an operator's mistake such as two machines running one validator key, triggers it. Operators of four-validator networks (the AWS smoke topology among them) should expect this and keep a funded candidate ready, or run at least five validators.
- **New networks only.** The rule has no activation height. A chain that already holds blocks with evidence, built before this rule, replays to a different application hash under it. Start new networks with it.
- The protocol-4 engine ignores the list; `tests/differential.rs` never sends one.

Tests: `tests/evidence_auto.rs`.

## Layout

| File | Purpose |
|---|---|
| `src/merkle.rs` | Copy-on-write sparse Merkle tree; same hashing rules and proofs as JMT 0.12 |
| `src/store.rs` | Committed versions in memory, snapshot files, the snapshots offered to peers |
| `src/statesync.rs` | State sync (the chunk manifest, a restore in progress) and the `retain_height` rule |
| `src/sigcache.rs` | Parallel signature checks and the cache of verified transactions |
| `src/engine.rs` | Ledger rules (forked from protocol 4), account cache, transfer fast path, mempool check-state |
| `src/evidence.rs` | Double-signing evidence with the consensus signature rule |
| `src/security.rs` | Account security: sign-in, spend and recovery keys, daily limit, freeze, key replacement |
| `src/names.rs` | Names that look alike: the skeleton of a name and the rows of the rule |
| `src/service.rs` | Service records: what they keep, how a block and a change of stake write them, and their recount |
| `src/rules.rs` | The protocol versions this program implements and the gate `Rules::since` |
| `src/upgrade.rs` | Changing the version: the signal action, the plan, whose signal counts, the end-of-block step |
| `src/app.rs` | ABCI application: one execution per block, concurrent queries and mempool checks |
| `src/transport.rs` | Loopback ABCI socket server with batched mempool checks |
| `src/bin/bench.rs` | `time-bench-v5`: drives the application as CometBFT does, without a network |
| `tests/differential.rs` | Every block through the protocol-4 engine and this one: same decisions, same roots |
| `tests/merkle_vs_jmt.rs` | The tree against the JMT library |
| `tests/node.rs` | ABCI call order, restart and replay, mempool admission, the changed rules, concurrency |
| `tests/statesync.rs` | A node restored from a snapshot against one that replayed every block; hostile snapshots, chunks and offers, also through the ABCI transport; what pruning may release |
| `tests/statesync_memory.rs` | The memory a forged snapshot costs before it is refused |
| `tests/statesync_review.rs` | An independent review's tests: a restored node through evidence, exits and the cleanup; the recount beside a stray restore record |
| `tests/statesync_review2.rs` | Its second round: a restore that stopped before a restore that happened; forged rows for a state already held; large requests of other kinds over the transport |
| `tests/statesync_streaming.rs` | Its second round: the streaming root against the tree on awkward key sets |
| `tests/evidence_auto.rs` | Misbehavior reported by CometBFT, punished as kind 20 would punish it; proposals judged by the node's clock |
| `tests/security.rs` | What each kind of key can and cannot do, alone and together, including when it has been stolen |
| `tests/upgrade.rs` | Signals, scheduling, keeping and cancelling a plan, roster changes, frozen and recovering owners, the local policy, kind 81, the genesis id bound |
| `tests/upgrade_node.rs` | Two programs across an activation: the same last block, then the stop; restarts at the boundary; `--stop-after-height`; state sync; exit code 4 of the binary; the fixture for clients |
| `tests/upgrade_review.rs`, `tests/upgrade_review_node.rs` | The independent review's tests: one change of a signal per interval, a validator jailed at the start time, the three stops of the binary over its ABCI socket, a rehearsal build against a release build |
| `tests/upgrade_review2.rs`, `tests/upgrade_review2_node.rs` | Its second pass: a jailed supporter and the plan the others keep, the exact deadline after the start time, a laboratory pause across it, what cleaning leaves behind, the binary through a postponed activation, a stop height after an interrupted replay |
| `tests/emergency.rs` | The switch of a fix release on the engine: accepted once and under no other condition; the switch block against an empty block, row by row; a plan and a hold at the switch; a state past the switch; replay by a later release; a repaired block |
| `tests/emergency_node.rs` | The emergency path through the ABCI calls, with four validators and a stand-in for consensus: the stop, the agreed root, too few and enough validators on the fix release, the program that was not replaced, a fix release for a wrong height, a block that was decided and not executed; `--expect-root` on the binary; on a rehearsal build, the faulty rule |
| `tests/emergency_safety.rs` | The emergency path on a network with the account-safety settings: the stand before a switch block and the one after a repaired block, each counted once on the clock of the waits; a switch block and a repaired block with the three settings, row by row, the supply rule and the recount; a registration of kind 45 before, beside and after a switch |
| `tests/golden.rs` | Roots recorded before the upgrade mechanism, on six networks: a network on which nobody signals keeps its bytes |
| `tests/issuance.rs` | All new time to validators: issuance, the starting validators' staked rewards, the refused bitcoin actions |
| `tests/fees.rs` | Fees paid on to validators: every way an action is charged, missing signers, rounding, the recount |
| `tests/fees_model.rs` | The same rule on random blocks, against an independent recomputation after every block |
| `tests/fees_node.rs` | A node that pays fees on, stopped with fees owed and restarted |
| `tests/fees_genesis.rs` | The one accepted form of the setting; zero and every other form refused |
| `tests/fee_amount.rs` | The fee as a setting: every kind of action costs the fee or nothing, to the microsecond, on every path; a network without the setting is unchanged |
| `tests/distinct_names.rs` | Names that look alike: the setting and the genesis, what is refused and accepted, the state after a refusal, the recount, and a node through its mempool, its proofs, a restart and state sync |
| `tests/names_unchanged.rs` | Roots recorded before that rule, on two networks that register accounts: a network without the setting registers names as before |
| `tests/waits_survive_stops.rs` | Waits that survive a stop: the total of stops block by block; a waiting payment, a freeze, a raise of the limit and a replacement of the keys across long and short gaps; what a stop still takes; the recount; a node through a restart and state sync |
| `tests/protected_registration.rs` | Accounts protected from the start: a registration that carries a set of keys, the account's first block, the set judged as the adopting action judges it, the commitment that binds it, a genesis with protected accounts, what the production profile requires, a node through a restart and state sync |
| `tests/safety_unchanged.rs` | Roots recorded before those two rules, on two networks whose account security rules cross gaps of hours and days: a network without the settings keeps its waits and its registrations as before |
| `tests/stake_script/mod.rs` | A scripted run of 52 blocks on three networks that registers, bonds, delegates, takes stake out, punishes, retires and registers validators again, leaves signatures out and stops the chain: shared by the two files below |
| `tests/records_unchanged.rs` | Roots of that run recorded before the service records: a network without the setting keeps its stake and its roots as before |
| `tests/service_records.rs` | Service records: the setting; every other row the same with and without them, block by block; the records against an independent model; the age of stake; a punishment that cannot be washed; proposers that leave a signature out; the bounds over many weeks; the recount; a node through its proposals, a restart, state sync and proofs; a switch block |

## Tests

```
cargo test --locked --manifest-path v5/Cargo.toml
```

The upgrade tests are also run on the rehearsal build: `cargo test --locked --manifest-path v5/Cargo.toml --features rehearsal-v5 --lib --bins --test upgrade --test upgrade_node --test upgrade_review --test upgrade_review_node --test upgrade_review2 --test upgrade_review2_node`. **Run the two builds one after the other, or give each its own build directory** (`CARGO_TARGET_DIR`). The tests that start the node binary use the one executable Cargo builds for the package, and both builds write it to the same path: started at the same time in one build directory, one run finds the other's binary, or cannot replace it while it runs.

The AWS campaign (`campaign/bootstrap-v5.mjs`) builds the node from these sources on Linux, runs this suite in release mode there, and only then starts validators with the binary it built, checked by hash.

`tests/production_genesis.rs` starts the node from a genesis made by the production ceremony (`tools/genesis-v5.mjs`) and runs blocks on it. It also checks that the tool and the node accept exactly the same keys. It needs `node` on the path.

## Account security: sign-in, spend and recovery keys

An account can give each of its keys one role, stored in the two flags a device row already has. `AUDIT-2026-11.md` explains the design and what a stolen key can do; the doc comment of `src/security.rs` is the specification. In short:

| Role | `can_manage` | `can_spend` | Alone |
|---|---|---|---|
| Sign-in | no | no | Signs website logins. Signs nothing the chain accepts |
| Spend | no | yes | Pays within the daily limit; starts a larger payment or a raise of the limit (both wait); adds and removes sign-in keys; freezes; cancels what is waiting |
| Recovery | yes | no | Freezes; cancels what is waiting; is one proof of a root operation |

A root operation needs `threshold` proofs (all spend keys together are one, each recovery key is one). With a spend key among them it happens at once. With recovery keys only, the one operation possible is a replacement of the keys, which waits `delay_seconds` with the account frozen.

| Kind | Name | Signed by | Nonce | Payload |
|---|---|---|---|---|
| 70 | secure | the account's protocol-4 key (both flags) | next | `{keys: [{public_key, role, proof}], policy}` |
| 71 | sign-in keys | a spend key | next | `{add: [{public_key, proof}], remove: [public_key]}` |
| 72 | freeze | a spend or recovery key | none | `{freezes, version, expires_elapsed_micros}` |
| 73 | root operation | a spend or recovery key | none | `{op, expires_elapsed_micros, approvals: [{public_key, signature}]}` |
| 74 | finish a replacement | a spend or recovery key of the new set | none | `{version}` |
| 75 | payment above the limit | a spend key | next | `{type: "request", to, amount}` or `{type: "execute", id}` |
| 76 | cancel | a spend or recovery key | none | `{type: "payment" or "limit", id}` |
| 77 | daily limit | a spend key | next | `{daily_limit_micros}` |

- `policy` is `{threshold, daily_limit_micros, delay_seconds, freeze_seconds}`. The threshold is at least 2 and at most the number of recovery keys; the two periods are at least the network's minimum recovery delay and at most 30 days.
- `op` is `{type: "replace", keys, policy}`, `{type: "cancel"}`, `{type: "unfreeze", freezes}` or `{type: "pay", to, amount}`.
- All numbers are decimal strings, lists are sorted by public key, and a payload has exactly one accepted form.
- Kinds without a nonce carry nonce 0 and authority epoch 0. They are single-use through counters in the security row (`freezes`, the number of the waiting item, `version`) and pass a validator safety hold.
- Fees: a freeze, a cancellation, a replacement asked for by recovery keys alone and finishing one cost the fee or, if the account has less, what it has, so that an emptied account can still be frozen and recovered. Every other root operation needs the full fee in the account, and a payment with two proofs must leave it.
- A replacement names the whole new set. A sign-in key that it keeps without a fresh acceptance and that has been removed in the meantime is left out; any other key without acceptance must be on the account in the same role.
- In the mempool an account's protective actions are judged on the last block alone, not on what else is waiting, and one key has one of each kind waiting at a time. What carries an expiry (a freeze, the approvals of a root operation, a merchant reference) is admitted only if it is still valid 30 seconds after the last block (`ADMISSION_MARGIN_MICROS`); blocks themselves apply no margin.
- A key that joins a set signs `"TCDEVNET-ACCOUNT-KEY-V1\0" ‖ network (32) ‖ account (8) ‖ role (1: 0 sign-in, 1 spend, 2 recovery) ‖ public key (32)`.
- An approval signs `"TCDEVNET-ACCOUNT-ROOT-V1\0" ‖ network (32) ‖ account (8) ‖ version (8) ‖ expires (8) ‖ SHA-256 of the operation ‖ SHA-256 of the approving keys`. Integers are big-endian; the operation is hashed as JSON with sorted keys and no spaces; the approving keys are concatenated as 32 bytes each, sorted.
- The state of an account is the row `security/<account id, 8 bytes>`. A wallet reads it with `include_security: true` in a `/v4/state` selection and gets the row or the proof that there is none.
- A secured account does not use protocol 4's device management or guardian recovery (kinds 8, 9, 11 to 16), except withdrawing its consent to be someone else's guardian, which one recovery key signs and which is refused while a recovery of that account rests on an approval this account gave.

The wallet side is `client-v4/account-security.mjs` (payloads, the bytes keys sign, the remaining allowance, the login rule for websites). `client-v4/account-security.test.mjs` checks it byte for byte against actions the engine accepted; regenerate the fixture with `V5_EXPORT_SECURITY_FIXTURE=1 cargo test --test security export_the_fixture` after any change of format.

## Waits that survive a stop

The account security rules make things wait: a payment above the limit, a raise of the limit, a replacement of the keys by recovery keys alone. A freeze lasts for a set time. All of it is there so that an owner can cancel or repair in time. Under the protocol-4 rule these waits are compared with the chain's time. A chain of this kind can stop for hours or a day. When it starts again, the next block carries the real time, and every wait has run out while no owner could send anything. Whoever can stop the chain can then defeat the waits.

With the genesis setting `waits_survive_stops: true` the rules count on another clock. The setting is written after `distinct_names`, and only when set; `false` cannot be written, so networks without it keep their protocol-4 bytes and network id. The production profile requires it (`Genesis::validate_initial`).

**The active clock.** The chain's time since genesis, minus the total of all stops so far.

- A stop is the part of the gap between a block and its parent that is longer than five minutes (`security::STOP_THRESHOLD_MICROS`), in both profiles. That is the clock's own threshold. The upgrade rule keeps its hour (`upgrade::Params::max_gap`): a plan is still cancelled only by a block dated more than an hour after its parent.
- The total is one number in the metadata row, `stopped_micros`. The block that follows a long gap adds to it before anything in that block is judged. It costs one addition per block, whatever the number of accounts.
- So a block moves the active clock by the time since its parent, and by five minutes at most. The clock never moves back.
- Until 23 November 2026 the threshold was the upgrade rule's hour. No network ever ran with the setting, so nothing recorded under the hour needs to be carried over.

**What is counted on it** (`src/security.rs`, "The clock of the waits"):

- when a waiting payment, a raise of the limit and a replacement of the keys are ready;
- until when a replacement can be finished (seven days after it is ready);
- until when a freeze lasts, and when the same key may freeze again;
- the daily allowance, which refills on this clock. A stop then gives whoever holds a spend key no second day's worth to take before the owner can freeze;
- whether a validator's owner account is frozen when upgrade signals are counted.

The fields of the security row keep their names (`ready_elapsed_micros`, `expires_elapsed_micros`, `frozen_until_elapsed_micros`, `allowance_elapsed_micros`). On a network with the setting they hold moments on the active clock.

**What stays on the chain's time.**

- The dates that keys sign: the expiry of a freeze and of the approvals of a root operation. A signature says until when it may be used. A stop must never keep one alive past that moment, so a stop can only shorten what a signature allows. The owner signs again.
- Everything outside account security: issuance, staking, the 14-day hold on stake that leaves, the stake hand-over, the notice of an upgrade, registration commitments, the guardian recovery of protocol-4 accounts.

**What it does not do.**

- *The first five minutes of a stop count.* The chain cannot tell a stop from a slow block until they have passed. A wait with less than five minutes left is over after a stop of any length. Production waits are at least two days.
- *Gaps of up to five minutes count in full.* Someone who can stop the chain and let it make one block at will takes five minutes from every wait with each stop: 576 stops and restarts for a wait of two days. (With the hour this clock first had, it took 48.) A cancellation must get into one of those blocks.
- *Blocks more than five minutes apart slow the waits down, also when nothing is wrong.* A chain that works makes a block every second or so, also with no traffic: CometBFT makes empty blocks (`consensus.create_empty_blocks`, on by default; the deployment kit sets an interval of one second). A network that turns empty blocks off, or sets `create_empty_blocks_interval` above five minutes, and has a quiet hour, counts five minutes of it: its waits then last longer in real time than they say. A height that takes more than five minutes without that means that more than a third of the voting power, or the network between the validators, is gone, and then nobody can act either. The first block after genesis carries the genesis time, so a slow start shows as one stop in the second block, before anything can wait.
- *It does not help against validators that leave an owner's action out.* More than a third of the voting power can keep any action out of blocks by voting only for its own proposals. The waits run while it does. No clock can repair that.
- *Whoever sets block time can undo it.* A block's time is set by more than half of the signing power, or by just over a third when one of its validators proposes ("Block time and this node's clock"). After a stop, such a group can date the next blocks five minutes apart instead of jumping to the real time. Each of those five minutes then counts. Honest validators date a block by their own clocks, and the whole stop shows as one gap.
- *Waits do not last for ever.* Blocks dated far apart move the active clock by five minutes each. A node refuses a proposal dated more than 30 seconds ahead of its own clock (`--clock-tolerance-seconds`), so a gap cannot be made up by dating a block into the future.

**What clients must do.** A moment read from a security row is not a date any more. Compared with the chain's time, or shown as it stands, it comes too early by the total of the stops: a wallet shows a payment as ready, or a freeze as over, and the chain refuses.

- `TimeSDK.stoppedMicros(state)` reads the total from a verified state, and `TimeSDK.waitsSurviveStops(state)` the setting. Both come with every verified state, in the metadata row.
- `TimeSDK.securityNow(state)` is the clock to compare with. `client-v4/account-security.mjs` takes it as `nowElapsedMicros` (`allowance`, `frozen`, `signInRefusal`).
- `TimeSDK.securityDeadline(state, moment)` turns a stored moment into a date. With the setting, that date is the earliest possible one: a later stop moves it. Show it as "not before".
- The login service (`client-v4/server-auth.mjs`), the SDK's count of upgrade signals, the alert watch (`client-v4/security-watch.mjs`, which shows a moment as a date "at the earliest"), the faucet (`client-v4/faucet.mjs`) and the HTTP API (`client-v4/api.mjs`, `securityClockOf`) read the clock this way. So does the wallet (`web-v4/wallet`, `security-flows.mjs`, `waitsOf` and `momentOf`) since 23 November, which says such a date "not before"; it ran in Chrome on a laboratory network with the setting on 23 November, where the chain did not stop, and across a stop on a stand-in chain only (`web-v4/wallet/README.md`, "The clock of the waits").

**The recount** (`--audit`) adds up the stops among the block times the state holds. While no block time has been cleaned up (the first fourteen days), the sum must equal the total. After that it must not exceed it. The report then prints `"waits_survive_stops": true` and `"stopped_micros"`; on a network without the setting it is unchanged, and a metadata row that carries the number is refused.

A network without the setting has no such number. Its bytes, state roots and network id are what they were: `tests/safety_unchanged.rs` compares two networks whose waits cross gaps of hours and days with roots recorded before the rule existed.

Tests: `tests/waits_survive_stops.rs`, `tests/safety_unchanged.rs`, `client-v4/waits-survive-stops.test.mjs`. On a network: on 23 November 2026, on laboratory networks of seven validators on AWS, with one real stop (`campaign/README.md`, "The account security check on a network with the settings", campaign `tc-v5-stop1`). Every validator was stopped and started again 544.6 seconds later; `stopped_micros` grew by 249.2 seconds; a payment asked for with a wait of eight minutes was refused after the restart with 150 seconds left on the clock of the waits, when on the chain's time it would have been due 98 seconds before, and was completed 153 seconds after the first state after the stop. No stop of hours, and none near five minutes.

## Accounts protected from the start

An account adopts the security rules with an action (kind 70) that costs a fee. A new account holds nothing. So under protocol 4 every account starts with one key that can do everything, and stays that way until someone pays it and it adopts the rules. The owner accounts of the starting validators start that way too.

With the genesis setting `protected_registration: true` an account can exist with its keys in their roles from its first block. The setting is written after `waits_survive_stops`, and only when set; `false` cannot be written, so networks without it keep their protocol-4 bytes and network id. The production profile requires it.

**A registration that carries the set (kind 45).** It takes the place of the reveal (kind 2) that follows a sponsored registration (kind 44). The sponsor's action is unchanged, and so is what a registration costs. The reveal of protocol 4 stays valid.

| Kind | Name | Signed by | Nonce | Payload |
|---|---|---|---|---|
| 45 | protected registration | the registration key, with no account | none | `{name, salt, security: {keys: [{public_key, role, proof}], policy}}` |

- `security` is what kind 70 takes, and the same code judges it (`security::first_set`): one to eight keys, each in one role, at least one spend key, a threshold of at least two and at most the number of recovery keys, waits within the network's bounds, every key with its holder's acceptance.
- The account does not have a number yet. A key accepts its role for the registration key instead: it signs `"TCDEVNET-REGISTER-KEY-V1\0" ‖ network (32) ‖ registration key (32) ‖ role (1) ‖ public key (32)`. Such an acceptance is good for that registration and nothing else.
- **The commitment names the set.** The sponsor pays for SHA-256 of `"TCDEVNET-NAME-PROTECTED-V1\0" ‖ network (32) ‖ registration key (32) ‖ name ‖ 0 ‖ salt (32) ‖ SHA-256 of security`, where `security` is hashed as JSON with sorted keys and no spaces. The name is taken with exactly these keys and this policy, or not at all. A registration with other keys, another limit or another wait does not match, whoever signs it. Neither does the reveal of protocol 4, so the name cannot be taken with one key that can do everything. And a protocol-4 commitment cannot be used with a set.
- The registration key is the account's identity key, as after any registration. It is a key of the account only if the set lists it, in one role and with its acceptance.
- The account starts with balance and nonce zero and a security row at version 1: a full allowance, no freeze, nothing waiting. From its first block it does what any account under the rules does, and no more: its spend key pays within the limit, a recovery key freezes it (at no cost while it holds nothing), two proofs decide the rest.
- The action pays nothing, as a reveal pays nothing. A refusal changes nothing: the commitment stays until it expires, and the sponsor's charge is not returned. On a network with `distinct_names` the name must not look like a name that exists.
- During a validator safety hold it is refused, like a reveal.

**A genesis with protected accounts.** On the same networks the genesis can carry `protected_accounts`, written last: `[{id, keys: [{public_key, role}], policy}]`, sorted by account id. Each such account starts with these keys in place of its identity key, and with its security row. The keys and the policy are judged by the same rules when the chain is started. A genesis carries no acceptances: it is a document its operators agree on as a whole. The production ceremony (`tools/genesis-v5.mjs`) requires this of every validator's owner account (`deploy/PRODUCTION-V5.md`).

**The recount** (`--audit`) checks these rows like any security row and prints `"protected_registration": true`.

**What it does not do.**

- A registration without a set stays possible. A wallet that wants its accounts protected must build the registration with the set. `TimeSDK.protectedSetup`, `protectedNameCommitment` and `signProtectedRegistration` build it, and `acceptRegistrationRole` in `client-v4/account-security.mjs` signs an acceptance. The wallet (`web-v4/wallet`) signs up this way since 23 November, through `client.registerProtected` and `acceptRegistrationRole` (`web-v4/wallet/README.md`, "Signing up protected").
- The SDK names kind 45 `register_protected` in `TimeSDK.KINDS` (`TimeSDK.REGISTER_PROTECTED_KIND` is the number). The HTTP API gives that name (`kind_name`), and the explorer puts such an action into words like every named kind.
- The engine does not require that the owner account of a starting validator is protected. The ceremony does.
- The set is public from the registration on, like every account's settings. The commitment hides it until then.
- The list in the genesis is part of the metadata row, which comes with every verified state. Twenty accounts with four keys each add about ten kilobytes to it.

Tests: `tests/protected_registration.rs`, `tests/safety_unchanged.rs`, `tests/production_genesis.rs`, `client-v4/protected-registration.test.mjs` (the SDK byte for byte against actions the engine accepted; regenerate its fixture with `V5_EXPORT_REGISTRATION_FIXTURE=1 cargo test --test protected_registration export_the_fixture`), `tools/genesis-v5.test.mjs`. On a network: on 23 November 2026, on laboratory networks of seven validators on AWS: the harness's account security check registered a newcomer this way through a sponsor (`client.registerProtected`), and the wallet signed up accounts this way in Chrome (campaigns `tc-v5-final8`, `tc-v5-final9` and `tc-v5-stop1`; `AUDIT-2026-11.md`, "Run on AWS and in a real browser (23 November 2026)"). No genesis with `protected_accounts` has started a network of several nodes.

## Service records

Rules may one day give a say only to validators and stake with a long, clean history ("registered for six months, signed 95% of the blocks in that time, never punished, counted by stake that has been in place for six months"), or to accounts of a certain age. Under protocol 4 the chain keeps none of the facts such a rule would measure: a validator's row has no registration time, no count of blocks signed and no history of punishments; a delegation is a validator and a number of shares, with no age; an account has no creation time; and the rows of each block are cleaned up after fourteen days. Records that start with a later upgrade could never know what came before it.

With the genesis setting `service_records: true` the state keeps those facts from the first block (`src/service.rs`). **No rule reads them.** They are rows like any other: under the state root, in snapshots and state sync, proven present or absent like any row (`/compact-proof`), and checked by the recount. The setting is written last, after `protected_accounts`, and only when set; `false` cannot be written, so a network without it keeps its bytes, network id and state roots (`tests/records_unchanged.rs`). The production profile requires it. `spec/settings.md`, section 5, gives every row and its encoding.

**What is kept.**

| Row | What it says |
|---|---|
| `service/validator/` ‖ owner | When the owner account first registered a validator and when it last did, each as a height and a chain time; the consensus key of the last registration; how many registrations and punishments; its counts per week (below): the last 53 weeks one by one, the older ones as one sum, and the sum of all |
| `service/key/` ‖ consensus key | The owner that registered the key, when, and when the validator was punished under it |
| `service/punishment/` ‖ owner ‖ height | Every slash, never removed: the key, the cause (evidence action, reported duplicate vote, reported light client attack) and the height of the offense |
| `service/tally`, `service/weeks` | The counts of the week in progress for every validator, in one row; how many blocks each kept week had |
| `service/missed/` ‖ owner ‖ week | The blocks of that week whose commit left the validator's signature out, by the proposer of each |
| `service/bond/` ‖ validator, `service/delegation/` ‖ validator ‖ owner | The age of a stake position as lots, one per week in which stake came in |
| `service/account/` ‖ id | The block that created the account: genesis, a reveal (kind 2) or a protected registration (kind 45) |

A validator is its owner account: the staking rules have no change of consensus key, so a new key is a new registration of the same owner, which keeps its first registration, its counts and its punishments. Another owner account starts a record of its own and inherits nothing.

**How a block is counted.** Block `h` carries the commit of block `h - 1`, which the proposer of `h` put together from the precommits it had. For each validator of the set that was to sign `h - 1`, the week of `h` counts one block `in_set`, and one `signed` if the commit carries its signature (read exactly as the reward rule reads it). The validator of `h`'s own set whose address the block's header names as its proposer (ABCI `proposer_address`, which the node passes on from `PrepareProposal`, `ProcessProposal` and `FinalizeBlock`, and which is part of the key under which a validated proposal is reused) counts one block `proposed`, and one `omitted` for every signature the commit left out; each validator left out counts one block for that proposer in its missed row. A header that names no validator of the set counts in `unattributed`. Block 1 carries no commit. A week is seven days of chain time, sixty seconds in the laboratory profile.

**The age of stake.** A position (a validator's own bond, in microseconds, or a delegation, in shares of the pool) is a list of lots, one per week in which stake came in. A lot of week `w` has been in place for at least `current - w - 1` whole weeks.
- *What goes out leaves from the newest lot first*, when it is unbonded (not when it is withdrawn fourteen days later: from the unbonding on it is no longer stake). What the old lots then hold is exactly what has been in place without a break: the lots older than N weeks never hold more than the least the position held in those N weeks. Stake added last week does not count as old because older stake sits beside it, and stake added and taken out again leaves the old lots as they were. Taking the oldest first would instead punish an owner for a short top-up.
- *Moving stake is taking it out and putting it in.* The staking rules have no other way (undelegate, wait fourteen days, withdraw, delegate), so stake that moves, to another validator or back to the same one, arrives new.
- *Rewards that stay in a pool* raise what every share is worth, so they carry the age of the shares that earned them, pro rata: nobody can point them at one lot. *Rewards bonded into a starting validator's own bond* (only on a network that pays all new time to validators without the stake hand-over rule) are new stake.
- *A slash* takes the whole own bond, and its lots with it. A slash of the pool lowers what every share is worth and leaves the lots as they are.
- *Bounded:* whenever a position changes, lots older than 53 weeks are merged into one that keeps the week of the newest of them. A position never holds more than 55 lots.

**What a later rule can and cannot conclude.** The records hold what the chain sees, and the chain sees the commits proposers chose to put in their blocks. A missing signature means that the validator did not vote in time *or* that the proposer left the vote out; the chain cannot tell which. Validators that propose a share `p` of the blocks can lower a rival's measured share by up to `p`: two proposers of seven take more than a quarter (`tests/service_records.rs`).
- Each missed block names its proposer, so a rule can see that a rival's misses come only from some proposers' blocks and leave those blocks aside, or compare each proposer's `omitted` with the others'. That works against proposers that are slow, badly connected or censor openly.
- **It does not work against proposers that hide it.** The proposer a header names is the proposer's own word: CometBFT 0.38 checks only that the header names a validator of the set (`state/validation.go`, which says it cannot know in which round the block was proposed). An honest proposer names itself. A dishonest one can name any validator of the set, and so put its block, and the signatures it left out, on someone else, or spread them thinly over everyone until they look like the rival's own downtime. Knowing who really proposed a block would need the round of each decided block and CometBFT's order of proposers, which the engine does not follow.
- So the counts `in_set` and `signed` are exact counts of what the commits carried, and no more trustworthy than the proposers who chose them: a rule of "95% signed" can be pushed below its threshold, for a validator that signs everything, by a group that proposes more than 5% of the blocks. The attribution can excuse misses, never prove guilt, and against a careful group not even excuse. A rule that measures liveness should allow for the share of blocks a hostile group proposes.
- Nor can a rule link two owner accounts run by one operator: a punished operator can register a fresh owner account, which starts with no punishment but also with no history.

**What it costs.** One row written per block (the tally, whatever the number of accounts and transactions), one more per validator whose signature the block's commit leaves out, and, in the first block of a week, the list of weeks and one row per validator that was in the set or proposed (and the missed row of a week that leaves the 53, if it had one). A payment writes nothing. Creating an account writes one row; registering a validator three (its record, its key, its bond); bonding, unbonding, delegating or undelegating one; a punishment three, and a fourth if the validator had a bond of its own. `tests/service_records.rs` counts these rows; `time-bench-v5 --service-records` measures the time (see `AUDIT-2026-11.md`, "Service records").

**The recount** (`--audit`) rebuilds what other rows hold: one account row per account, in the order of the ids; one punishment for every row the staking rules leave when they punish; the lots of every own bond and every position add up to it; and for every week whose blocks the state still holds (fourteen days), the number of blocks and each validator's `in_set`, from the block times and the rosters. It checks the rest against itself: a validator's weeks add up to its total, its keys and punishments to its counts, the missed rows to what the validators missed and to what the proposers left out. It prints `"service_records": true`. On a network without the setting it refuses any row under `service/`, and its report is unchanged.

**What it does not do.**
- No rule, SDK function, wallet or explorer reads the records yet. A client reads them with `/compact-proof`.
- `in_set` counts blocks, not time: a week in which the chain stood still has fewer blocks.
- A validator that leaves the set keeps its last weeks one by one, and the missed rows of those weeks, until it is in the set again.
- Kept on networks of several nodes since 23 November 2026, for minutes: every laboratory network of seven validators that the AWS harness started that day had the setting, and each validator's recount gave one root. No step read the records or compared them with what happened on those networks. Not read by an independent reviewer.

Tests: `tests/service_records.rs`, `tests/records_unchanged.rs`, the unit tests of `src/service.rs`, `tests/production_genesis.rs` and `tools/genesis-v5.test.mjs` (the ceremony writes the setting).

## Fees paid on to validators

Every action pays a fixed fee: 1,000 microseconds unless the network sets a lower one (see "The amount of the fee"; the figures in this section are for 1,000). Under the protocol-4 rule the fee goes to the bank and stays there, so the currency in circulation shrinks with use. Validator rewards return one fifth of a second per second, which pays for about 200 actions a second in the long run, and for 1,000 at most if every auction sells.

A network can pay fees on instead. Its genesis then carries `"fees_to_validators_ppm": "1000000"` after the protocol-4 fields: parts per million of the fees of a block, a decimal string from 1 to one million. The rest stays in the bank. Zero is written by leaving the field out.

- While a block is executed the engine adds up the fees it charges. At the end of the block the validators' part of the sum is recorded in the row `pos/fee_pool`, a decimal string of microseconds. The money itself is still in the bank, so the supply rule is unchanged.
- The next block carries the signatures of that block. At its start the amount joins the new time those signers share, and one rule pays both: by voting power, with commission, delegators and starting validators treated as for new time. The row is removed.
- Fees are treated exactly like new time. What a validator that did not sign or is jailed would have received stays in the bank, and so does what the reward rule withholds for stake that is leaving and what does not divide. Nothing is carried to later blocks, so in the block that pays, what a signer receives does not depend on who else signed. A validator that is left out block after block earns nothing and its stake falls behind the others'; that was already so for new time, and fees add to it.
- The registration charge, slashing penalties and auction movements are not fees and go where they went before. Bitcoin receipts and auction claims (kinds 41 and 42) pay no fee.
- The setting is part of the genesis and therefore of the network id. The field is written only when it is set, after the protocol-4 fields (only `fee_micros` can follow it): a network without it has the same bytes and the same id as before, and the differential tests against the protocol-4 engine run that case.
- Code that charges a fee calls `ExtensionHost::fee_credit`, never `bank_credit`, or that fee is not paid on.
- The row never holds more than one full block can charge (20,000 fees of the network) or more than the bank. Blocks and the recount (`--audit`) refuse a state in which it does, or in which it exists on a network without the setting. On a network with the setting the recount also prints the setting (`fees_to_validators_ppm`) and what is owed (`fees_owed`); elsewhere its output is unchanged.

What this does to the long-run limit. With every validator signing, all fees return to circulation. The share of the fees that stays in the bank is the share of voting power whose signatures are missing, so the limit of about 200 actions a second becomes about 200 divided by that share: 20,000 a second from rewards alone when 1% is missing.

What it does to the fee as a cost. A validator gets back its own share of the fees it pays, so its own actions cost it less than anyone else's, and validators acting together get all of their fees back at a setting of one million. A lower setting keeps a part of every fee out of their reach, at the price of a lower long-run limit.

Tests: `tests/fees.rs` (each rule above, case by case), `tests/fees_model.rs` (random blocks on starting and on staked validators and every class of fee and of other bank income, compared after every block with an independent recomputation) `tests/fees_node.rs` (a node stopped with fees owed and restarted) and `tests/fees_genesis.rs` (the forms of the setting that are read and refused). `fees_model.rs` also checks, with no model, that what a set of signers is paid is the sum of what each is paid alone.

On AWS: `campaign/bootstrap-v5.mjs ... --fees-ppm 1000000` starts the campaign's networks with the setting, and `campaign/report-v5.mjs` prints where the fees went. This has not been run.

Not done: validators receive fees as spendable balance, not as stake.

## The amount of the fee

Protocol 4 fixed what an account action costs at 1,000 microseconds. A network can set a lower fee: its genesis then carries `"fee_micros": "10"`, a decimal string from 1 to 999, directly after `fees_to_validators_ppm` (or in its place when that is left out). The protocol-4 fee is written by leaving the field out; `"1000"`, `"0"`, anything above 1,000 and every other spelling are refused, by the node at InitChain and when a stored state is read. `Genesis::fee()` is the one place the engine reads the fee from.

- Every action that paid 1,000 pays the fee of the network: payments, payments to shops, keys and guardian recovery, `CancelPending`, staking, sponsored registration, the account security actions. What was free stays free (finishing or calling off a guardian recovery, withdrawing guardian consent, Bitcoin receipts and auction claims, kinds 41 and 42). The registration charge is another setting (`registration.fee_micros`) and does not change.
- A secured account's daily limit counts the amount and the fee of the network; the fee pool row (above) is bounded by 20,000 fees of the network.
- The protocol-4 rules (`src/ledger`, used unchanged for kinds 2, 8 to 16 and, in the reference execution, 3) charge 1,000 themselves. The engine makes them charge the fee of the network without touching them: for the duration of one action the payer is lent the difference inside the staged view, so that their check "balance >= amount + 1,000" is exactly "balance >= amount + fee"; afterwards the difference is taken out of the bank again if they charged, or out of the payer's balance if they did not, and the view must hold what it held before. Nothing of it can be paid out, kept or used for a fee, and nothing is published if the action fails. This is why the fee cannot be set above 1,000.
- The setting is part of the network id. A network without it has the same genesis bytes, network id, state roots and metadata as before.
- Wallets get the fee with the state they verify (`config.fee_micros` in the metadata row; absent means 1,000). `client-v4/time-sdk.js` reads it there (`TimeSDK.networkFee`), and the gateway reports it in `/api/network` once it has verified a state.

Tests: `tests/fee_amount.rs`. On AWS: `campaign/bootstrap-v5.mjs ... --fee-micros 10`. This has not been run.

## All new time to validators

A network can pay all of its new time to the validators who sign its blocks, and through them to the people who stake with them, instead of a fifth to validators and four fifths to the bitcoin auction. The genesis setting is `all_new_time_to_validators: true`. It is written last, after `fee_micros`, and only when set; `false` cannot be written, so networks without it keep their protocol-4 bytes and network id. The campaign harness sets it with `bootstrap-v5.mjs --all-new-time`.

With the setting:

- **Issuance.** Each block pays all of the time elapsed since the block before, at most 60 seconds, to the validators who signed that block, by voting power (`pos_adapter::begin_block`, `Genesis::validators_issuance`). Within each validator the protocol-4 rule splits the reward between its owner and its delegation pool; the validator keeps its commission, at most 20%, of the pool's part. The share of a validator that did not sign, and anything that does not divide evenly, stays in the bank.
- **At least five starting validators.** With four, one slashed validator leaves fewer clean validators than the roster needs. The validator safety hold then refuses every ordinary action, and only a newly registered validator could end it, which nobody would have the time to do.
- **No bitcoin auction.** Kinds 40 (bitcoin headers), 41 (bitcoin receipts), 42 (auction claims) and 60 to 63 (treasury governance) are refused before any other check (`Genesis::bitcoin_kind_allowed`, at the top of `Overlay::apply`). The SDK refuses to quote a bitcoin bid, and the wallet hides the auction. The genesis still carries the bitcoin, treasury and auction sections; they are checked as on any network and otherwise unused.
- **Without the stake hand-over rule, starting validators stake most of what they earn while the bootstrap lends them power.** With `stake_handover`, which the production profile requires, nothing is bonded for them: they are paid in full, and that rule keeps them above half of the votes ("The stake hand-over rule"). Without it: of a starting validator's own reward, one twentieth is paid out and the rest is added to its self bond (`pos::reward_bonding_bootstrap`, `pos::BOOTSTRAP_PAID_PARTS`). Commission is paid out. This lasts while the bootstrap rule lends it voting power, until `pos::Summary::bootstrap_ended`; after that, rewards are paid out as on any network.
  - *Why most is staked:* lent power does not grow with rewards. Without this, anyone who kept staking what it earns, and bought whatever the starting validators sell, would grow by up to the whole issuance while the starting validators stood still, and could end up outvoting them by waiting.
  - *Why a twentieth is paid out:* nobody holds time at genesis. With nothing paid out, nobody could pay the fee of any action while the bootstrap lasts: not report a validator that signed twice, not revoke a stolen key, not give anyone their first seconds.
  - *The worst case:* in the production profile, one buyer who acquired everything the starting validators are paid during the 90-day fade and staked it all would hold about 12 to 15% of all stake when the bootstrap ends. If a fifth were paid out it would reach about 46% of the votes. The bound ends with the bootstrap: from then on everything is paid out. The model is described in the audit.

What it means for a network's first months in the production profile, where the hand-over rule is on:
- The twenty starting validators are paid all the new time while they are the only validators: about 86,400 seconds a day between them, a twentieth of a minimum bond each, all of it spendable. Their lent power does not depend on it.
- When the hand-over comes depends on how much of that the operator passes on to independent validators that stake it. The table in "The stake hand-over rule" gives the day, 90 at the earliest.
- The bonding of nineteen twentieths described above, and its numbers, apply only to networks without the rule.

Tests: `tests/issuance.rs`. `tests/fee_genesis_bytes.rs` checks that the harness writes the setting with the node's bytes.

## The stake hand-over rule

Under protocol 4 the starting validators' lent voting power fades with the calendar alone. If nobody else stakes, seven minimum bonds of one owner then hold a third of the votes after day 29, two thirds after day 77 and all of them after day 90 (finding S2 of the audit). With the genesis setting `stake_handover: true` the starting validators keep the network until independent stake has proven itself, and then hand it over. The setting is written after `all_new_time_to_validators` (only `distinct_names` and the settings after it can follow), and only when set; `false` cannot be written. The production profile requires it. The campaign harness sets it with `bootstrap-v5.mjs --stake-handover`. The rule is `pos::StakeHandover`, applied in `pos::Summary::begin_block` and `reconcile`.

- **Target.** Twice the starting validators' power at genesis (forty bonds in production), plus a fifth of all the time issued since genesis. A fifth is what all validators together are paid under the protocol-4 issuance, so stake that only bonds its rewards never gains on the target by waiting.
- **Seated stake.** The voting power, in the roster in force, of validators other than the starting validators. The starting validators' own stake never counts, bonded rewards included, and neither does stake delegated to them. On a network whose starting validators are all run by one operator, that operator's stake can never end its own bootstrap.
- **What the starting validators hold.** Together, with their own bonds, the larger of the gap between the target and the seated stake, and what keeps them above everyone else once everyone else holds the stake it asks for, after the cap of 30% per validator. Every unjailed starting validator holds the same virtual part, rounded up to a hundredth of its genesis power, never less than that hundredth and never less than the calendar would leave it. Stake delegated to them comes on top of their part and never lowers it, since its owner can take it out at any moment. They move first, as one group charged as one change. Nobody else's raise may take them below half. While someone else's stake exit must fit, they stay as they are, so that exit never waits for them. A starting validator's own exit moves the whole group with it, in full or not at all.
- **The end.** All three must hold: the calendar period is over (day 90); seven funded validators other than theirs are in force; and seated stake has stayed at the target for fourteen days of block time (sixty seconds in the laboratory profile). Their virtual power is then gone for good, and they leave the roster as fast as the churn limit allows. What they hold of their own stays theirs. An operator that means to stop its validators takes its own stake out first, at the pace of the churn limit; otherwise the network loses the votes of that stake when they stop.
- **With `all_new_time_to_validators`.** Nothing is bonded for the starting validators; they are paid in full. The rule keeps them above half by itself, and independent stake can only come from what they are paid.

What it protects, and what it does not:
- Until the end, nobody else holds half of the votes, so no block is final without the starting validators. Block time cannot run ahead of the validators' own clocks by more than CometBFT's `block_time_tolerance` (60 seconds by default), narrowed to 30 seconds by this node's clock check (see "Block time and this node's clock"), so nobody can bring the fourteen-day hold forward by dating blocks.
- Anyone with more than a third of the votes can still halt the network by not voting, as on any network of this kind. The target is what a third of the votes costs.
- Who gets time to stake is partly the starting validators' choice. An operator that sells everything they are paid to one buyer lets that buyer approach half of the votes before the end: more than the third that halts the network, never half.
- A starting validator jailed for signing twice can leave them below half until the others' next move, which the churn limit may spread over an hour or more.
- At some moments the share of everyone else in force can stand a few points (at most 6.4 measured) above what the calendar rule would give. The calendar rule's smaller roster holds a large validator down harder under the 30% cap per validator.

Measured in `pos/tests/handover.rs` (production profile):
- Seven minimum bonds hold 5.9% of the votes on day 400; under the calendar they hold everything after day 90.
- Seven minimum bonds that bond all their rewards still hold 17.1% after 600 days. Under the calendar they pass two thirds on day 66.
- Seventy-seven bonds brought on day 100: the starting validators rise first, and the attacker holds at most 49.9%. Nothing ends before the fourteen-day hold, and taking the stake back out restores everything.
- When all new time goes to validators, the hand-over comes on the day shown, if the operator passes on that share of what the starting validators are paid to independent validators that stake it:

| Operator passes on | 100% | 50% | 25% | 10% | 5% |
|---|---|---|---|---|---|
| Hand-over | day 90 | day 102 | day 153 | day 269 | day 442 |

Tests: `pos/tests/handover.rs`; the attacks of three reviews in `pos/tests/review*.rs`; `tests/handover.rs`; and `tests/fee_genesis_bytes.rs`, which checks that the harness writes the setting with the node's bytes.

## Names that look alike

An account name is 2 to 15 bytes of `a-z`, `0-9` and `_`. Uppercase letters, letters of other alphabets and spaces cannot be written, so they cannot be used to imitate a name. What is left is inside that alphabet: `paypa1` for `paypal`, `al_ice` for `alice`, `barn` for `bam`. Under protocol 4 only the same name twice is refused.

With the genesis setting `distinct_names: true` the network also refuses a new name that looks like a name that exists. The setting is written after `stake_handover` (only `waits_survive_stops` and `protected_registration` can follow it), and only when set; `false` cannot be written, so networks without it keep their protocol-4 bytes and network id. The production profile requires it: the node refuses a production genesis without it at InitChain, as it refuses one without the hand-over rule (`Genesis::validate_initial`). The laboratory profile takes both. The rule is `src/names.rs`.

**The skeleton of a name.** Two names look alike when they have the same skeleton. It is computed in this order (`names::skeleton`):

1. Every `_` is removed.
2. Every `0` becomes `o`, every `1` becomes `l` and every `w` becomes `vv`.
3. In one pass from left to right over the result, without overlap, `rn` becomes `m` and `vv` becomes `w`.

| Name | Skeleton |
|---|---|
| `alice`, `al_ice`, `_alice_`, `a1ice` | `alice` |
| `paypal`, `paypa1` | `paypal` |
| `google`, `g00gle` | `google` |
| `bam`, `barn` | `bam` |
| `wv`, `vvv` | `wv` |
| `__` | none (empty) |
| `b1nance` | `blnance`, not `binance` |

The test vectors are in `spec/name-skeleton-vectors.json`. The engine, the SDK (`client-v4/time-sdk.js`) and the genesis ceremony (`tools/genesis-v5.mjs`) each compute the skeleton and are tested against that file. Beyond it, one test compares the engine with the ceremony on 6,000 names, and another the ceremony with the SDK on 86,420.

On a network with the setting:

- **One row per name.** The key is `name_skeleton/` followed by the skeleton. The value is the name of the account that owns it, as a JSON string: `name_skeleton/alice` holds `"alice"`. It is a row like any other: under the state root, in snapshots and in state sync, and proven present or absent like any row (the query `/compact-proof`).
- **Genesis.** Every genesis account name gets its row. A genesis in which two names have the same skeleton, or a name has no skeleton (underscores alone), is invalid (`Genesis::validate`).
- **Registration.** One action creates a name: the reveal (kind 2) that follows a sponsored registration (kind 44). The sponsor's action carries a commitment, not the name, so the reveal is where the name becomes known and binding. The protocol-4 rules judge the reveal first: the name is valid, it is the one that was paid for, and it is not taken. Then the engine refuses it if its skeleton is empty or has a row (`engine::Overlay::apply_legacy`).
- **The refusal names the existing name:** `the name paypa1 is too close to the existing name paypal: choose a name that does not look like it`. The mempool refuses the reveal with the same words, a proposer leaves it out, and a block that carries it is invalid.
- **A refusal changes nothing.** It is the refusal of any reveal, such as one for a name that is taken. No row is written. The paid commitment stays until it expires (a day at most) and is then cleaned up. The sponsor's charge and fee are not returned, and the same key cannot be sponsored again while its commitment lasts. A reveal itself pays nothing.
- **Two at once.** Of two reveals whose names look alike, the first in a block is registered and the second refused. The mempool judges a reveal with those already waiting.
- **The recount** (`--audit`) checks that every row names a registered name whose skeleton is the row's key, and that there are as many rows as accounts. It then prints `"distinct_names": true`. On a network without the setting it refuses any such row, and its output is unchanged.

A network without the setting has no such row. Its bytes, state roots and network id are what they were: `tests/names_unchanged.rs` compares two networks that register names that look alike with roots recorded before the rule existed, and the differential tests against the protocol-4 engine register accounts as before.

What the rule does not do:

- **Softer look-alikes.** One changed letter, `i` for `l`, `b1nance` for `binance`: all are registered. A wallet should warn about them.
- **`vw` beside `wv`: closed.** As first built, the pass read `vv` as `w` but not `w` as `vv`, so `vvv` and `wv` had one skeleton and `vw` another, although they look the same. Step 2 now reads every `w` as `vv` before the pass, so a row of `v` and `w` has one skeleton however it is cut. The vectors file holds these cases.
- **Names from before.** It protects the names of a network that had the setting from its first block. It cannot be switched on later: the genesis is part of the network id, and names registered without the rule may look alike already.
- **A wallet cannot yet ask, with a proof, whether a name is too close to another.** `TimeSDK.nameSkeleton(name)` computes the skeleton and `TimeSDK.distinctNames(state)` says whether the network of a verified state has the rule. Reading the row with a proof needs the verifier to know it: a field in the `/v4/state` selection, the same field in the gateway and in `verifier-v4`, and the compiled verifier built again. Until then a wallet learns of a look-alike when the reveal is refused, after the sponsor has paid.

Which networks have it: the production genesis ceremony writes it, and every network the campaign harness starts has it (`campaign/bootstrap-v5.mjs`; its load tools name their accounts so that no two look alike). The test-network launcher writes it since 23 November, when the node program it starts became the one certified that day, which knows the setting; a test network launched before keeps the genesis it had (`testnet/README.md`, "The four settings of a genesis").

Tests: `tests/distinct_names.rs`, `tests/names_unchanged.rs`, the unit tests of `src/names.rs`, `tests/fee_genesis_bytes.rs` and `tests/production_genesis.rs` (the harness and the ceremony write the setting with the node's bytes), `client-v4/name-skeleton.test.mjs`, `tools/genesis-v5.test.mjs`, `campaign/lib/common.test.mjs` and `testnet/launch-record.test.mjs`. On a network: on 23 November 2026, on laboratory networks of seven validators on AWS, where the harness's account security check registered `operator0` beside `operator_0` and the reveal was refused with the words above, with nothing made (`campaign/README.md`, "Names that look alike").

## Receipts for wallets

With this engine a wallet accepts a payment as soon as the block that contains it is final ("one-block receipt"): the gateway proves the transaction is in the block, and the block is tied to a checkpoint the wallet's own light client verified. The verifier function is `verify_fast_receipt` in `verifier-v4`; the gateway route is `/api/receipt?hash=…&wait=…`. See `AUDIT-2026-11.md` for the assumption it rests on.

## State sync and pruning

Two settings of one node. Neither changes a rule or a state root: a network cannot tell a node that uses them from one that does not, and nodes with and without them run together.

### Joining from a snapshot (state sync)

A new node no longer has to execute every block since genesis. CometBFT's state sync fetches a recent state from peers, the node checks it against an application hash CometBFT's light client verified, and continues from there.

**Offering snapshots.** A node started with `--state-sync-snapshot-blocks N` writes a snapshot for peers at every height that is a multiple of N, keeps the newest `--state-sync-snapshots-kept` (default 2) under `PATH.v5state/statesync/`, and answers CometBFT's `ListSnapshots` and `LoadSnapshotChunk` from them. The default is 0: no snapshots for peers.

- Use the same N on every node of a network. Snapshots of the same height are the same bytes on every node, so CometBFT pools them and fetches chunks from all of them; snapshots at different heights each have one source.
- A snapshot is the restart snapshot file format (`store.rs`), cut into chunks of 4 MiB. Its ABCI metadata lists the file length and the SHA-256 of every chunk; its ABCI hash is the SHA-256 of that metadata. Format number 1.
- They are separate from the `--snapshot-seconds` snapshots, which are unchanged: those are written on a timer at whatever height the node is at, the two newest are kept in `PATH.v5state/`, they are what the node restarts from, and they are never offered. A snapshot for peers is written at an agreed height, is never read at start, and costs one more full write of the state every N blocks and one file per snapshot kept.
- A snapshot leaves the offer when a newer one replaces it. A peer that is still fetching it is told the chunk is missing and turns to another snapshot or another node. Choose N so that N blocks last longer than a download: 1,000 or more at one block a second.
- Each chunk is checked against its hash before it is sent. A file found damaged is not served: the snapshot is withdrawn from the offer and its files are deleted, so it is not offered again after a restart either.
- Any peer may ask any node for any chunk, as often as it likes. A request for a chunk that is not offered is answered ("missing") and not logged, on a node that offers snapshots and on one that does not.
- The same thread writes both kinds of snapshot, one at a time. While it writes a snapshot for peers, the timer's snapshot and a stop request wait.
- CometBFT needs no setting to serve. The joining node's CometBFT must reach the RPC port of at least two nodes (`rpc_servers`), which is where its light client gets headers.

**Restoring.** A node that has executed no block restores when its CometBFT state-syncs (`[statesync] enable = true`, two `rpc_servers`, `trust_height`, `trust_hash`, `trust_period`), whatever its own flags. CometBFT only does so while its own block height is 0.

1. `OfferSnapshot` carries the snapshot's height, format, chunk count, hash and metadata as peers advertised them, and the application hash of that height from CometBFT's light client. Only that hash is trusted. The node refuses another format (`REJECT_FORMAT`); metadata that is not exactly a manifest, or that the hash or the chunk count disagree with (`REJECT_SENDER`: no honest node advertises that); a snapshot larger than `--state-sync-max-mib` (default 16,384); and a snapshot at or below the height the node already holds (other than exactly the height and hash it holds). It also refuses (`ABORT`) if it has executed blocks: see "Which nodes restore" below. Accepting changes nothing but an empty staging file, `PATH.v5state/restore.tmp`.
2. `ApplySnapshotChunk`: a chunk is written to the staging file only if it is the next one in order and has the length and SHA-256 the manifest names. Otherwise nothing is written, the chunk is refetched and its sender rejected (logged in full the first five times, then at most once a minute with a count: a peer can keep sending such chunks for as long as the sync lasts). That holds for a chunk of any size a peer can send: CometBFT 0.38 passes on whatever a peer sent as a chunk without looking at its size, up to its chunk message of 16,000,000 bytes, so the node's ABCI transport reads request frames of that size plus overhead (`transport::MAX_REQUEST_FRAME_BYTES`) and answers them. (Closing the connection instead would stop CometBFT, which ends itself when an ABCI connection ends.) The first chunk must carry the offered height and the trusted hash, or the snapshot is rejected with its sender. A chunk out of order ends the restore (`REJECT_SNAPSHOT`, nobody rejected: CometBFT applies chunks in order).
3. With the last chunk the node checks the file in two passes. The first keeps no row: it reads the file once, checks its checksum, that the rows come in key-hash order and that the metadata row is the one the header carries, and computes the Merkle root from the rows as they pass (`merkle::StreamingRoot`, the tree's own hashing rules, at most 256 hashes held). If that root is not the trusted hash, the snapshot is rejected with every peer that sent a chunk of it, the staging file is removed, and the node's state, in memory and on disk, is what it was. Every chunk matched the manifest that was advertised, so the snapshot itself is forged, and every peer that served a chunk of it served the forgery. Only a file that passed, which is the chain's state at that height and nothing else, is read a second time and built into the tree.
4. Then the file is renamed into place as the node's restart snapshot, the state in memory is replaced, and `Info` answers with the snapshot's height and that hash, which is what CometBFT checks next. Older restart snapshots are removed: CometBFT holds no blocks to replay from them.

- Memory while chunks arrive: one chunk as CometBFT hands it over and the manifest. A peer can make a chunk 16 MB; the transport holds it twice for a moment, as the frame it arrived in and as the decoded request, and gives the room back afterwards. A chunk of the wrong length or hash is never written to disk. The manifest takes 32 bytes per chunk, at most 100,000 chunks. Disk: the length the manifest declared, at most `--state-sync-max-mib`. CometBFT keeps its own copy of the chunks in its `temp_dir` until the restore ends, so plan for twice the snapshot.
- Memory at the end. A forged snapshot is refused in the first pass, which takes a 1 MiB read buffer, one row and at most 256 hashes whatever the file holds: `tests/statesync_memory.rs` measures 1.05 MB allocated for a forged file of 10 MB with a million rows (before this check the same file took 460 MB, 46 times its size, because every row was read and the whole tree built before the root was compared). An authentic snapshot is then loaded, and that takes what the state takes in the running node, plus a second copy of the row keys while the tree is built.
- A forged snapshot still costs its download: up to `--state-sync-max-mib` of disk and transfer before the first pass can refuse it. Any peer can advertise one (the hash it must carry is public), and CometBFT tries the highest advertised height first. Each such attempt costs the peers that served it their place in this sync.
- **Which nodes restore.** Only a node that has executed no block on the state it holds: one with no state, one at genesis, or one that holds a state it restored and has not built on. The last is a restore that the process, or CometBFT, did not live to record: CometBFT starts over at height 0 and offers a snapshot again. The same height and hash is accepted again and changes nothing; a later one replaces it. A snapshot of an earlier height, or of the same height with another hash, is refused.
- A node that has executed blocks keeps what it built: nothing replaces its state. The process that finalized, committed or judged a block refuses every offer with `ABORT` (a snapshot offered then does not come from a CometBFT that is joining). After a restart the node still refuses every later snapshot with `ABORT`, because a restore would drop the block history it recorded; only its own height and hash is accepted, and changes nothing. To join by state sync again, stop the node and remove `PATH.v5state` and `PATH.history` (and CometBFT's data, keeping `priv_validator_state.json`). A restore that is in progress when the node executes a block is dropped.
- A snapshot of another network is refused twice over: its rows do not hash to the hash CometBFT trusts for this chain, and if CometBFT itself follows the wrong chain, a node that holds a state refuses to replace it (`ABORT`).
- A restore that stops half way leaves the staging file; the next start removes it. Nothing is resumed.
- After a restore the node executes blocks, validates proposals, answers queries and writes snapshots exactly as a node that executed every block: `tests/statesync.rs` runs a restored node, the node it restored from and a node that replayed from genesis side by side and compares every answer.

**What a restored node does not have.** Its state is complete; its records of the past are not.

- *Its own check of the past.* It has not executed the blocks before the snapshot. It holds the state that more than two thirds of the validators signed for, as CometBFT's light client verified from the operator's `trust_height` and `trust_hash`. A node that replayed from genesis checked every rule on every block itself. Take the trust height and hash from a source you trust, not from the peers you sync from.
- *Block history proofs at or below the restored height.* The block history archive (`PATH.history/`, about 104 bytes per block) is not part of a snapshot. The state holds the root and the frontier of the history tree, which is all that appending needs, so the node writes that frontier into an otherwise empty archive (`history::archive::Archive::seed`) and records the height in `PATH.history/restored-<height>.json`. From the next block on it appends and proves as any node. A `/v4/state` query that asks for `blocks` at or below the restored height is refused with an error that says so. Receipts and checkpoints that need such a proof must come from a node that has the history. The rows `block/<height>` and `block_time/<height>` of the last 14 days are in the state and are proven as on any node.
- *The offline recount of that part.* `--audit` on a restored node recounts the archive from the block after the restored height, starting from the recorded frontier and ending at the authenticated one. Its report says `"history_archive_verified": false`, because the history since genesis was not verified, with `history_archive_from` (the first height that was) and `state_restored_at`; the status is still a pass. Only a node that holds and recounted the history from its first block reports `true`, and its report is unchanged. A script that requires `true` therefore refuses a restored node until it is told to accept the range. The recount cannot compare the cleanup clock or a release clock of an earlier height with a leaf it never had; those two comparisons are skipped below the restored height.
- *The record of the restore is not trusted.* `restored-<height>.json` is a file beside the archive. It is honoured only if the archive holds no entry at all at or below that height, which is what a restore leaves. Beside an archive that does hold such entries the recount ignores it and recounts everything from the first block, so a stray or planted record cannot make a damaged archive pass. A record above the height the node holds is what a restore left that stopped before it installed anything: it is removed when the node starts, and when the newest record does not apply the one before it is tried, so it cannot hide the record of the restore that happened.
- *Older state versions.* A running node keeps up to 32 versions for proofs. A restored node starts with one and has 32 again 31 blocks later.
- *Blocks in CometBFT.* Its block store starts after the restored height: `/block`, `/commit`, `/validators`, `/tx` and the transaction index have nothing older. See "What this means for the gateway".
- *Evidence about heights at or below the restored height.* See the next section: this one can stop the node.
- *One unauthenticated field.* A snapshot file carries the fingerprint of the `FinalizeBlock` request of its height, which the application hash does not cover. It is only used to recognise that same request if CometBFT sends it again, which it cannot after a state sync because it does not hold that block. A forged value changes no state and no root.

### Evidence about heights before a restore

This is CometBFT's behaviour, read from its source (`evidence/verify.go`, `consensus/state.go`, `blocksync/reactor.go`), not something the application decides, and it has not been run here.

To check evidence of double signing or of a light client attack, CometBFT needs the block header and the validator set of the height the evidence is about. A node restored at height S has neither for any height at or below S, and CometBFT 0.38 does not fetch them afterwards. For such a node a block that carries evidence about a height at or below S is an invalid block:

- as a validator it prevotes nil on the proposal;
- if more than two thirds commit the block anyway, its CometBFT stops with a panic ("+2/3 committed an invalid block");
- while it is still catching up by block sync, it rejects the block from every peer and stalls there.

This can happen for as long as such evidence is accepted: until the head is more than 2,000,000 blocks above S and more than 14 days later, about 23 days at one block a second. It needs a validator to have signed twice at or before S and the evidence to be committed after S; it does not happen by itself. Evidence about heights after S is checked as on any node, and so is the misbehavior the application punishes (it reads the state, which a restored node has in full).

What follows from it:

- *Recovery.* A node stopped this way cannot get past that block. Remove its data and state-sync again from a snapshot at or above the height of the block that carried the evidence (it then never has to judge that block), or sync from genesis.
- *Not too many at once.* Validators that restored within the last evidence window should hold less than a third of the voting power. With less than a third, the network commits the block and they stop and re-sync. With a third or more, a proposal that carries such evidence cannot gather two thirds of the prevotes: the network slows down, deciding only the proposals without it, until the evidence expires.
- *New validators.* A validator that joined by state sync is safest to activate once the window has passed since its restore, about 23 days. One that starts validating earlier should be prepared to re-sync, and should keep `priv_validator_state.json` when it does.
- There is no CometBFT 0.38 setting that makes a state-synced node fetch older headers. Pruning does not cause this: a pruning node keeps every block evidence can name.

### Keeping only recent blocks (pruning)

`--keep-blocks N` lets CometBFT delete old blocks: every `Commit` answers with a `retain_height`, and CometBFT removes what is below it. The default is 0: every block is kept and `retain_height` is always 0, as before.

`retain_height` is the highest height that still keeps all of the following (`statesync::retain_height`):

- the last N blocks;
- the block of the oldest restart snapshot on disk and every later one. After a restart the node loads its newest valid snapshot and CometBFT replays the blocks after it; if that file is damaged the node falls back to the older one. The first snapshot is the genesis state, so nothing is pruned before the node has written two snapshots of its own;
- the block of the oldest snapshot it offers to peers and every later one. A peer that restores it needs the headers of that height and the two after it, and every block after it;
- every block evidence can still name. The application sets the evidence age to 2,000,000 blocks and 14 days, and CometBFT accepts evidence until it is older than both. So a block is only released when more than 2,000,000 blocks are above it and it is more than 14 days older than the head by block time. The node takes the second from its own state: the heights whose block rows the ledger has already dropped for being older than 14 days (`history_pruned_through`).

For that reason N must be 0 or at least 2,000,000: a lower number would change nothing. At one block a second that is about 23 days of blocks.

- Pruning removes CometBFT's blocks and its old validator sets and consensus parameters. It does not touch the application: the state, the snapshots and the block history archive stay, and the node still proves block history from the height it started at.
- A pruning node cannot serve the blocks it deleted to a node that syncs from genesis. A network needs at least one node that keeps everything for as long as anyone should be able to do that, or to audit the chain from its first block.
- A node that lost its snapshots can no longer replay from genesis out of its own block store. It joins again by state sync.
- CometBFT 0.38 deletes the stored ABCI responses of pruned heights with them. It does not prune the transaction index.

### What this means for the gateway

`client-v4` was written for a node that holds every block. Behind a node that prunes or was restored from a snapshot:

- The gateway's light client (`server.mjs`) starts from a stored checkpoint, or from block 1 if it has none. If the blocks between its checkpoint and the tip are gone, the update fails and is not retried, and with it login, orders and sponsoring. It needs a checkpoint above the node's lowest block, or a node that has them. The same holds for a browser wallet's own start through `/api/light-block`.
- Old receipts (`/api/receipt`, late settlement of an order) read `/tx`, `/commit` at the payment's height and the next, and a block history proof for both. On a pruned node `/commit` fails and the answer stays "pending"; on a restored node the history proof is refused for heights at or below the restored one. The receipt archive (`archive.mjs`) stores the signed headers but not the history proof, and is only read when `/tx` fails.
- `own-node.mjs` confirms a payment with `/tx`, or `/block` and `/block_results` at its height. Recent payments are fine; a payment older than what the node holds is reported as unavailable and retried without end.
- New payments, the last few blocks and everything read from the current state work as before.

Point the gateway and a shop's own node at a node that keeps every block, was synced from genesis and runs with `indexer = "kv"`, as `client-v4/README.md` already asks. Validators and other nodes may prune. They may join by state sync, with the limits of "Evidence about heights before a restore".

### Flags

| Flag | Default | Accepted | Meaning |
|---|---|---|---|
| `--state-sync-snapshot-blocks N` | 0 | 0, or 10 to 1,000,000 | A snapshot for peers every N blocks; 0 offers none |
| `--state-sync-snapshots-kept N` | 2 | 1 to 10; needs the flag above | How many of them stay on disk and on offer |
| `--state-sync-max-mib N` | 16384 | 4 to 400,000 | The largest snapshot this node restores, in MiB |
| `--keep-blocks N` | 0 | 0, or 2,000,000 to 10^12 | Blocks CometBFT keeps; 0 keeps all |

Each is a plain whole number, given once. `--audit` takes none of them.

### What ran on a network, and what did not

The tests drive the application through the ABCI calls in the order CometBFT 0.38.26 makes them (`statesync/syncer.go`, `reactor.go`).

**State sync ran once, on 2026-11-18**, at the end of the upgrade rehearsal of the AWS harness (`campaign/README.md`, mode `v5upgrade`): seven laboratory validators in two regions under CometBFT 0.38.26, each started with `--state-sync-snapshot-blocks 100 --state-sync-snapshots-kept 10`. The harness starts the node and CometBFT directly. An eighth node, not a validator, was started with `[statesync] enable = true`, two validators as `rpc_servers`, and a trusted height and hash that the harness took from a light client of its own, started from the genesis.

- It restored the state of height 1,200 on a chain of about 1,200 blocks, fetched the blocks after it, and had caught up 25 seconds after it was started.
- At the same height its application gave the same root as a validator's, which is the application hash of the next header.
- Its CometBFT held blocks from 1,201 on and none earlier.
- Its recount (`--audit`) passed and said `"history_archive_verified": false`, `"history_archive_from": "1201"`, `"state_restored_at": "1200"`, with the root the validators recounted at that height.
- The snapshot was taken after an activation, so the node ran under version 5 from its first block ("Upgrades", below).

That is one run, with a state of 64 accounts, far smaller than one chunk. **Still not shown on a network:**

- a restored node that then validates;
- chunks fetched from several peers, and the same snapshot pooled from several nodes (the seven validators offered the same snapshots; what CometBFT made of that was not observed);
- a restore of a state of realistic size (time, memory, disk);
- a peer that serves a bad or oversized chunk being dropped by CometBFT;
- a node that has executed blocks refusing a snapshot;
- a snapshot from before an activation, and a program refusing a snapshot under a version it does not implement;
- what a restored node does when a block carries evidence about a height before its restore (read from CometBFT's source, above);
- pruning: CometBFT deleting blocks at the `retain_height` the node returns and restarting afterwards. `--keep-blocks` cannot go below 2,000,000 blocks, about 23 days at one block a second, so no short run shows it.

Tests: `tests/statesync.rs` (with the ABCI transport for chunks of every size), `tests/statesync_memory.rs` (what a forged snapshot costs in memory), `tests/statesync_review.rs` (an independent review's comparison through evidence, jailing, exits and the 14-day cleanup, and its checks of the recount), the unit tests of `src/statesync.rs`, of the streaming root in `src/merkle.rs`, of `src/store.rs` and of the flags in `src/main.rs`, and `history/src/archive.rs` for the seeded archive.

## Upgrades: changing the rules of a running network

Design: `docs/design/upgrade-mechanism.md`. The rules of this release: `spec/protocol-4.md`.

The rules a chain runs under have a number, the protocol version, 4 at genesis. It is in the state (`meta.protocol_version`) and in every block header (`version.app`). It changes only when the validators schedule a change on the chain, with notice. A program lists the versions it implements, each with the SHA-256 of its specification; this release implements version 4 only (`rules::IMPLEMENTED`).

**The rule every version keeps: a version never changes what an existing action kind or payload does.** An action carries no version, and bytes signed today may be included after an upgrade: they must mean the same then. New behaviour is a new kind, or a new field that is refused before its version, gated in code by `rules.since(N)`. A version may stop accepting a kind; it never makes one do something else. A test (`tests/upgrade.rs`) fails if `meta.protocol_version` is compared or written anywhere but in the gate, the metadata check and the one place that activates.

### How a change is decided

1. The owner account of a validator sends a **signal** (action kind 80) with a key that may spend: `{"activate_elapsed_micros":"D","spec":"H","version":"D"}` supports a plan (the next version, the hash of its specification, the chain time at which it starts), `{}` withdraws. It costs the fee.
2. When the signals for one plan hold at least **four fifths** of the voting power, in the roster in force and in every roster already announced, and its start is at least the notice ahead, the plan is **scheduled**.
3. A scheduled plan needs at least **three quarters** in every block until it starts, or it is cancelled. It is also cancelled in any block dated more than one hour after its parent: a halt uses up notice nobody could act on.
4. The start time is "not before". The first block dated at or after it **in which no validator safety hold is on** is the last under the old rules. It ends by writing the new version; the next block's header carries it. A hold postpones the switch and does not cancel the plan: a validator that signs twice just before the start time is jailed, the hold lasts until it has left the roster (two blocks), and the plan activates in the block after. A plan that has not activated one hour after its start time (60 seconds in the laboratory profile) is cancelled; that takes a hold that does not end.

A signal does not count while its owner account is frozen or in a recovery; the validator stays in the total. A validator that is **jailed** is left out of the count altogether, out of the total as well as out of the support, until it has left the roster two blocks later: the plan is judged by the validators that remain. So a supporter that signs twice (or whose consensus key was stolen) does not cancel a plan the others keep: with five equal validators and four supporters, three of the four that remain are still three quarters. Leaving a jailed validator out helps no change to happen that the roster does not support, because nothing is scheduled or activated while one is in a roster (a hold is on then). Whoever steals a spend key and signals with it is answered by a freeze, which any spend or recovery key of the account can place and which needs no nonce. A signal that does not count can only keep the rules as they are.

**A signal sent with a stolen key stays in the row.** A freeze only stops it from counting. It counts again when the freeze ends by time, and it is still there after the keys have been replaced, until the owner withdraws it (`{}`, with the new spend key) or signals for something else. An owner who recovers an account that owns a validator looks at its entry in `upgrade/state` and withdraws what is not theirs. While frozen the account can neither signal nor withdraw: the fee would lower its balance.

| | Production profile | Laboratory profile |
|---|---|---|
| Least notice from scheduling to start | 21 days | 120 seconds |
| Farthest start a signal may name | 120 days ahead | 1 hour ahead |
| Between two changes of one validator's signal | 10 minutes | 1 second |
| Longest a plan may wait after its start time (a validator safety hold postpones the switch) | 1 hour | 60 seconds |

The start of a plan is the time its signals name, not a time the chain computes: the notice is the least distance between the block that schedules the plan and that start. Signals that name different start times support different plans.

**With few validators the two thresholds are close.** Shares are compared exactly: `support × 5 ≥ total × 4` to schedule, `support × 4 ≥ total × 3` to stay scheduled. Seven equal validators need six supporters for either, so a plan that six scheduled is cancelled by one withdrawal. Twenty equal validators need sixteen to schedule and fifteen to stay scheduled. Blocks need more than two thirds of the voting power (five of seven, fourteen of twenty): that many must run the program that implements the plan at its start, or the chain waits.

The plan and the signals are one row, `upgrade/state`, absent when there is neither. A network on which nobody signals has no such row and the same state roots as before this mechanism existed (`tests/golden.rs`, `tests/differential.rs`). Each activation leaves a row `upgrade/activated/<version>` for ever.

**What this node does on its own account** (local policy, not a rule): it neither admits to its mempool nor proposes a support signal for a version and specification it does not implement, and at admission it wants the start time 30 seconds further away than a block would. A signal for rules no honest program implements therefore never enters a block made by an honest proposer. This release admits no support signal at all, since it implements no version 5. It still executes any decided block that carries one: the plan is consensus.

**What follows for the order of work.** A support signal is admitted only by nodes whose program implements the version it names, waits in their mempools, and enters a block when one of those nodes proposes. On a network where every validator runs a program that lacks the version, no signal for it ever enters a block. So the release that implements a version is installed on validators first (it runs the old rules until the activation), and owners signal afterwards, through a node that runs it. One validator on that program is enough for signals to be included, at its turns to propose; the more proposers run it, the less a signal waits.

### What an operator sees

- `/status` has a field `upgrade`: `implemented` (this program's versions and specification hashes), `scheduled` (the plan, or `null`), `implements_scheduled` (`true`, `false`, or `null` when nothing is scheduled) and `stop_after_height`. **`implements_scheduled: false` means: install the release that implements the plan before its start time.** The node also writes a warning to its log at start and every ten minutes while that is so. Do not read CometBFT's `node_info.protocol_version.app` for any of this: it is the value from when CometBFT started and goes stale.
- The version in force is `app_version` of the same `/status`: the version of the rules at the height the query asks for, with that height's `height` and `root`, and at the head when it names no height. Across an activation the two differ: the state of the activating block already names the new version, the state before it the old one.
- Which program runs: `time-node-v5 --version` prints one line and opens nothing. This release prints `time-node-v5 0.10.0 protocol=4 devnet-only publicLaunchAllowed=false`. A running node lists the versions it implements in `upgrade.implemented` and in the first lines of its log (`This program implements protocol version 4 (spec …).`).
- A wallet or any other client asks `/v4/state` with `"include_upgrade":true` and gets the row `upgrade/state` with its proof, or the proof that it is absent.
- At the activating block a program that does not implement the new version executes that block like everyone, commits **the same state**, and then **stops on purpose**: it answers the `Commit`, answers no consensus request after it (it neither accepts nor rejects the next proposal), refuses new transactions, saves its state, prints why, and ends with **exit code 4**. CometBFT, which gets no answer, signs nothing and ends too. Started again on that state the program prints the same and ends with code 4 before it opens its ABCI socket; `--audit` does the same. **Install the release that implements the version and start it on the same data. Delete nothing.** If more than a third of the voting power stopped this way, the chain waits for them.
- When this ran (below, "What ran on a network, and what did not"), CometBFT ended by itself within a second, with exit code 0. A supervisor that watches both processes must go by the node's exit code 4 and its first line: CometBFT's own exit looks like a stop on request. Started on the program that implements the version, on the same data, each stopped validator had caught up and signed again within ten seconds.

| Exit code | Meaning |
|---|---|
| 0 | Stopped on request (`SIGTERM`) |
| 1 | Failure |
| 3 | The consensus engine disconnected |
| 4 | Stopped at a height on purpose. The first line of the report says why |

| First line | Cause | What to do |
|---|---|---|
| `STOPPED FOR UPGRADE` | The chain runs a version this program does not implement, or implements under another specification hash | Install the release the following line names; start it on the same data |
| `STOPPED AS ASKED` | `--stop-after-height H`, and block `H` is committed | Start without the flag, or with a later height, to go on |
| `STOPPED AT A SWITCH` | A decided block carries action kind 81, a rule switch of an emergency release | Install that release; CometBFT hands it the block again |

The line after the first gives the heights and what to install. All of it goes to standard error, like the rest of the node's log.

### Stopping at a height, and emergencies

`--stop-after-height H` (at least 1): after the commit of block `H` the node takes the same stop path. It judges no proposal for `H + 1`. If operators holding more than a third of the voting power set the same `H`, no block at `H + 1` can be decided and the chain stands at `H` for everyone. Started with its state at `H` the node stops at once (code 4); started when it has already committed a block above `H` it changes nothing and fails with code 1 (it knows by the entries of its history archive, also when its newest snapshot is older than `H` and also when an earlier restart replayed only part of the way). This is the first step of the emergency procedure (section 10 of the design): nothing shortens the notice, so a fault is answered by stopping at an agreed height and resuming with a fix release.

Action kind 81 is reserved for that fix release. This release never accepts it: it is refused at admission, never proposed, and a proposal that carries it is rejected (one proposer must not be able to stop every node). A **decided** block that carries it is not executed: the node stops with its state at the block before, and CometBFT keeps the block for the program that is installed next.

### The fix release and its switch

The operator's procedure is `docs/emergency-fix.md`. This section says what the engine does.

**This release is not a fix release.** Its list of switches is empty (`rules::SWITCHES`), and everything below is code it never reaches: a network that never uses the emergency path has the bytes, state roots and network id it had (`tests/golden.rs`, `tests/differential.rs`, unchanged).

A fix release is this source with two lines changed, reviewed like any change: the new version with the hash of its specification in `rules::IMPLEMENTED`, and one switch in `rules::SWITCHES`. A switch names **one network** by its network id, the version it leads to, and one place. On any other network the program behaves as if it had none: a release runs on more than one network, and a height means nothing on another chain. Every later release keeps the line, so that it replays that chain from its first block.

**At an agreed height** (`NETWORK:after:H`, design section 10):

- Up to and including block `H` the fix release runs the old rules, like the release it replaces.
- As proposer of block `H + 1` it proposes exactly one transaction, the switch: the unsigned envelope of a header relay with kind 81 and the payload `{"spec":"H","version":"D"}` (`upgrade::switch_action`). It takes nothing from its mempool for that block, and the switch is never admitted to a mempool.
- As validator it accepts that block and rejects every other proposal for that height.
- The block charges nobody and changes no row that an empty block does not change. It ends by writing the new version and the row `upgrade/activated/<version>` with `"notice":"none"`, and removes any plan and all signal entries. A plan whose start time has passed does not activate in it: the switch wins. A validator safety hold does not postpone it.
- The header of block `H + 1` still carries the old version. Block `H + 2` is the first under the new one.
- The switch is accepted once. Before block `H + 1` and after it, kind 81 is refused as in this release.

What the fix release refuses, so that a wrong height cannot be papered over:

- A decided block `H + 1` that is anything but that one transaction is not executed: the node stops with its state at `H` (`STOPPED AT A SWITCH`, exit code 4), and says that the block is not its switch block.
- A state that is at or past block `H + 1` and still under the old version is not started on: the node is stopped before it serves, with the same first line, and says that the chain passed that block without the switch. `--audit` refuses such a state too, and a snapshot of such a state is not installed.
- If the chain is not under the version before the switch's at height `H`, it executes no block there.

**Old and new programs cannot make a block together.** The old program rejects the switch block; the fix release rejects every other block at that height. So block `H + 1` is decided only when more than two thirds of the voting power run the fix release, and until then no block is. A program that was not replaced then stops at the decided switch block, with its state at `H`; started on the fix release on the same data, it is handed that block again.

**A stop in the middle of a block** (`NETWORK:block:S:BLOCKHASH:PARENTROOT`). The design names no such case. A block can be decided and then fail a check on every node: each then prints `FAILED ON A DECIDED BLOCK` with the block (height and hash) and the state it is left at (height and root), and ends with exit code 1. The block is final, so the only way on is a program that executes it. A fix release that names that block, by its height and hash, and the state before it, by its root, executes it with the transactions it was decided with and ends it by writing the new version, as a switch block does. It executes no other block at that height, and that block on no other state. A fix gates what it corrects with `rules.since(N + 1)`; in the block it repairs, whose header still carries the old version, the engine marks the block instead (`Overlay::switch`).

**The agreed root.** `--expect-root H:ROOT` is for the one start on a state the validators agreed on: the node goes on from height `H` only if its state there has that root. Started at `H` with another root, or above `H`, it changes nothing and fails with exit code 1. Started below `H` (its newest snapshot is older, and CometBFT replays up to `H`), it fails closed at the commit of `H` if the root is another one. It changes no rule and no byte. A running node shows it in `/status` (`upgrade.expect_root`), and a fix release shows its switches there (`upgrade.switches`); neither field exists otherwise.

| First line | Exit code | Cause |
|---|---|---|
| `STOPPED AT A SWITCH` | 4 | A decided block carries a switch this program does not implement; or, on a fix release, the decided block at its switch height is not its switch block; or the state is past that block and still under the old version. The second line says which |
| `FAILED ON A DECIDED BLOCK` | 1 | A decided block failed a check of this program. The second line names the block and the state. Starting the same program again fails on the same block |

Who can do what with it:

- *Stolen signalling keys:* nothing. The switch reads no signal, and no signal brings one about.
- *A third of the voting power:* what it could do before, halt the chain by not voting. It cannot force a switch.
- *Two thirds of the voting power:* decide a switch block, if they all run a program that has the switch. They could run other software before; what is new is that honest nodes that did not install it stop at that block instead of following it.
- *One operator, or one proposer:* cannot stop a node or switch anything. A proposal that carries kind 81 where the judging program has no switch is rejected, and so is every other proposal at a fix release's switch height.
- *Whoever can get a program installed on two thirds of the voting power:* everything, at once and without notice. This is the risk the emergency path carries, and why each operator verifies a fix release by hand (`docs/emergency-fix.md`, section 4).

### With state sync

- A snapshot carries the whole state, version and plan included. A node restored from a snapshot taken after an activation runs under the new version from there, if its program implements it.
- A program **never installs a state under a version it does not implement** (or implements under another specification hash). It learns the version when the last chunk has been verified against the trusted application hash; it then keeps the state it had, on disk and in memory, tells CometBFT to abort the state sync, blames no peer, and logs what to install. It does not exit with code 4: nothing was stopped, the node is where it was.
- A snapshot from before an activation restores on any program. One that does not implement the plan then executes the blocks up to the activating one and stops after it, like a node that was there all along.
- Every release keeps every version back to 4. State sync does not make that unnecessary: a node replays from its own snapshots and from the snapshots peers offer, and either may be older than an activation.
- A stopped node offers and restores nothing. A node started with `--stop-after-height H` refuses snapshots above `H`, and stops if it restores exactly `H`.
- As for every restore, only a node that has executed no block on its state takes a snapshot ("Joining from a snapshot"). A node that executed its chain up to an activation it does not implement is not helped by state sync: it installs the release.

### Rehearsal build

`cargo build --features rehearsal-v5` builds a program whose list also holds a version 5 with the rules of version 4 (`rules::REHEARSAL_SPEC`; it is the hash of a sentence, not of a specification). It exists so that an activation can be rehearsed on a real network with two real programs: this build, and the release build that stops at the boundary. Its version line reads `time-node-v5 0.10.0 protocol=4 rehearsal=5 devnet-only publicLaunchAllowed=false`, which the kit and the release tool, comparing that line exactly with the release's (the same without `rehearsal=5`), refuse. At start it also logs `REHEARSAL BUILD: …`. Never run it on a network that matters.

**A rehearsal build can be a fix release.** Built with `TIME_REHEARSAL_SWITCH` in the compiler's environment, the rehearsal program carries one switch to its version 5, in either form of "The fix release and its switch": `NETWORK:after:H` or `NETWORK:block:S:BLOCKHASH:PARENTROOT`. Its version line then also says `switch=5@HEIGHT`, with the height of the switch block. A release build does not read the variable.

**A rehearsal build has one deliberately faulty rule,** for rehearsing a stop in the middle of a block: it cannot finalize a block that carries a payment of exactly 81,081 microseconds (`rules::REHEARSAL_FAULT_MICROS`). Such a payment is admitted, proposed and accepted like any other; the decided block then fails its check on every node (`App::rehearsal_fault`). The fault is gone once the rehearsal version is in force, and in the one block a fix release repairs. No release build contains it.

**The laboratory wait is short.** A plan activates from its start time to 60 seconds after it, or not at all (one hour in production). In a rehearsal this means: if no block is dated in the 60 seconds after the start time, the plan is cancelled, with no hold involved. That happens when the validators are paused or restarted across the start time, or when blocks are slower than a minute. The node logs `Upgrade cancelled: ... This block is dated N s after that start time, more than the 60 s a plan may wait`. Keep the network producing blocks through the start time, and stop or swap binaries before it or after the activation. In production the same pause would have to exceed an hour, which the gap rule cancels anyway.

### What ran on a network, and what did not

The tests drive the application through the ABCI calls, and the node binary over its ABCI socket as CometBFT's client speaks to it (a request, then Flush) for the three stops and their exit code.

**An upgrade ran once, on 2026-11-18**: the rehearsal of the AWS harness (`campaign/README.md`, mode `v5upgrade`). Seven laboratory validators with equal voting power in two regions, CometBFT 0.38.26, this release and its rehearsal build, 21 scripted steps, all passed. The harness starts the node and CometBFT directly, with a key file, and one script operated every validator. What it showed:

- *Signals.* A validator on this release refused a support signal at admission, with the sentence of its local policy. Once one validator ran the rehearsal build, signals handed to it entered blocks. No plan existed with five of seven supporters; the sixth scheduled it. With all seven supporting, one withdrawal left the plan scheduled and the second cancelled it. Each plan's start was the one its signals named, and its time of scheduling was the time in the certified header of the block that carried the deciding signal: 214 and 212 seconds before the start, for the two plans of the run.
- *Replacing the program.* Five validators were moved to the rehearsal build one at a time, one before any signal and four during the notice: stopped cleanly, started on the same data, caught up and signing again after 5 to 8 seconds each.
- *The activation.* The first block dated at or after the start (0.019 s after it) was the last under version 4. The certified header of the next block carries version 5, and proven state says version 5 and no plan. The two validators left on this release each committed that block, saved its state, printed `STOPPED FOR UPGRADE` with the version, the specification hash and both heights, and ended with exit code 4; their CometBFT ended by itself within a second, with exit code 0. The other five went on. The next block came as usual and the one after it took 2.6 s instead of 0.3 s: a pause of about 2.3 s, the longest wait among the eight blocks measured after the activating one.
- *Coming back.* Started on the rehearsal build on the same data, the two had caught up and signed again after 7 and 9 seconds. All seven then held the same block and application hash.
- *Clients.* A client that knows version 4 paid and verified a receipt before the activation; after it, its reads and a payment failed with the code `UPGRADE_REQUIRED`, nothing was sent, and its light client kept advancing. The alert watch library reported `upgrade_scheduled`, `upgrade_cancelled` and `watch_outdated`. A client made for the rehearsal (the committed verifier and SDK with the one constant and the one list changed) read version 5 from proven state and verified a payment in a block of that version.
- *The coordinated stop.* All seven were restarted with `--stop-after-height 1084`, a height about two minutes ahead. Each committed block 1,084, printed `STOPPED AS ASKED` and ended with exit code 4. None committed block 1,085, and all seven recounted the same root at 1,084. Started again with the flag, each stopped at once with exit code 4. Started without it, the chain went on: block 1,085 was seen about five seconds after the order to start. One validator started with the flag when it was already above that height printed `--stop-after-height 1084: this node is already at height 1096, above it. Nothing was changed.` and ended with exit code 1; started without the flag it signed again.
- *A node joining from a snapshot taken after the activation*: "State sync and pruning", above.

That is one run, on a laboratory network (a notice of 120 seconds, not 21 days). **Still not shown on a network:**

- the deployment kit: the image, the remote signer and its leases, the monitor and its alerts (`deploy/README.md`);
- an upgrade carried out by independent operators, with the production notice;
- a network on the production profile;
- a chain that waits: more than a third of the voting power on the old program at the start, and its resumption when they are replaced (in the rehearsal two of seven stopped, less than a third, and the chain went on);
- a restart at the boundary other than a clean one: a node that crashes between its own commit of the activating block and CometBFT's, which is what `discard_abci_responses = false` is for;
- a plan postponed by a validator safety hold (a real double-signing), and a plan cancelled because it could not activate in time or because a block came more than an hour after its parent;
- the emergency path with a fix release made by the release tool and started through the deployment kit, and by independent operators (it ran with the harness, below);
- a snapshot from before an activation, and a program refusing a snapshot under a version it does not implement.

**The emergency path ran on 2026-11-23**: the harness's rehearsal (`campaign/README.md`, mode `v5emergency`, "What its first runs showed"), twice, each on two networks of seven laboratory validators in two regions, with this release, its rehearsal build, and fix releases that the harness's builder made from the rehearsal build. The engine's tests run all of it on one computer as well, with a stand-in for consensus.

- *A stop at `H` by part of the validators.* Three of seven were restarted with `--stop-after-height H`, committed `H` and ended with exit code 4; the chain stood at `H` for the other four. All seven held one root at `H`.
- *`--expect-root`.* A fix release started with another root changed nothing and ended with exit code 1, naming both roots.
- *The switch block.* With three and with four of seven on the fix release no block came; with five, block `H + 1` held the switch alone under a header of version 4, and block `H + 2` carried version 5.
- *The handshake.* The validator left on this release stopped at the switch block with exit code 4 (`STOPPED AT A SWITCH`) and its state at `H`. Started on the fix release on the same data, it was handed that block again by CometBFT and signed 8 and 9 seconds later.
- *A stop in the middle of a block.* A payment of the rehearsal's faulty amount was decided, and all seven nodes ended with exit code 1 and `FAILED ON A DECIDED BLOCK`, each naming the same block and state; started again, a node failed on it again. A fix release naming that block and that state, on five of seven validators, executed the block, and the next carried version 5.
- Every recount: one root, version 5, notice "none". The times are in `docs/emergency-fix.md`, section 12.

Tests: `tests/emergency.rs` and `tests/emergency_node.rs` (the emergency path), `tests/upgrade.rs` (the rules on the engine), `tests/upgrade_node.rs` (the node: two programs, the stop, restarts, kind 81, the flag, state sync, a postponed switch, the binary), `tests/upgrade_review.rs`, `tests/upgrade_review_node.rs`, `tests/upgrade_review2.rs` and `tests/upgrade_review2_node.rs` (the independent review's tests, two passes: the interval, jailed validators, the deadline, the binary over its socket, the stop height after replays), `tests/golden.rs` (recorded roots), the unit tests of `src/upgrade.rs` (the state machine at its exact boundaries and under random input) and `src/rules.rs`.

## Known limits

- Memory grows with the number of accounts: about 2 KiB per account (four rows each, with their tree nodes), plus about 30 MB per retained version at 10,000 transfers per block (32 versions are kept for proofs).
- A network with `distinct_names` keeps a fifth row per account, for the skeleton of its name. What that adds to the memory per account has not been measured. The rule has gaps that are listed in "Names that look alike", it has run only on laboratory networks of seven validators (on 23 November 2026, for minutes), and a wallet cannot yet ask with a proof whether a name is too close to another.
- A snapshot rewrites the whole state. A node that offers snapshots to peers writes one more every `--state-sync-snapshot-blocks` blocks.
- State sync has run once with CometBFT, on a small laboratory network (one node joined from a snapshot and caught up); pruning has been tested against the ABCI calls only, because `--keep-blocks` cannot go below the evidence window of 2,000,000 blocks. A restored node cannot prove block history from before its restore, and for about 23 days a block that carries evidence about a height before its restore stops it. See "State sync and pruning".
- The proposer executes its own block twice (once to select transactions, once to validate), other validators once.
- The staking module re-validates its whole state on every block; this is small with few validators and should be made incremental before large validator sets.
- On a network without `fees_to_validators_ppm`, fees go to the bank and return to circulation only through validator rewards (one fifth of a second per second). The software can process far more transfers than that pays for in the long run. With the setting, fees are paid on and that bound rises with the share of validators that sign (see "Fees paid on to validators"). Whether to use it is a monetary-policy decision, not an engine limit, and so is the amount of the fee, which a network can lower in its genesis (see "The amount of the fee").
- An upgrade has run once with CometBFT, on a seven-validator laboratory network operated by one script: not with the deployment kit, independent operators or the production notice ("Upgrades", "What ran on a network, and what did not"). The design prevents a split, not a halt: if validators signal for a plan and more than a third of the voting power then does not run the program, the chain waits for them at the activation. Nothing shortens the notice; an emergency is answered by stopping at an agreed height and restarting on a fix release (`docs/emergency-fix.md`). That path is tested on one computer, and ran on 23 November 2026, twice, each time on two laboratory networks of seven validators, operated by the test harness and not through the deployment kit; no operator has followed it. See "Upgrades".
- Account security: the wallet's screens for it are built (`web-v4/wallet/README.md`). Nothing on the chain tells an owner that a payment or a replacement of keys is waiting. A wallet has to look, or a watch service has to tell it. The other limits are listed in `AUDIT-2026-11.md`.
- `waits_survive_stops` and `protected_registration` have run only on laboratory networks of seven validators, on 23 November 2026, with one real stop of nine minutes, and no independent reviewer has read them. A stop still takes up to five minutes off every wait, and gaps of up to five minutes count in full. The wallet reads the active clock and signs up accounts with their set of keys since 23 November: in Chrome on such a network, where the chain did not stop, and across a stop on stand-in chains only (`web-v4/wallet/README.md`). See "Waits that survive a stop" and "Accounts protected from the start".
