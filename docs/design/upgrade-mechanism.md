# Changing the rules of a running network

Revision 2. Design only; nothing here is built. It follows the review of revision 1 (`upgrade-review/review-1.md`) and the project lead's decisions on it. Written against engine 0.6.0 (commit `8ee2090`) and the CometBFT 0.38.26 source in `.tools/comet-secure-0.38.26`. I read the code and ran nothing.

Revision 3 brings the document in line with what was built and with the decisions taken after the independent review of the engine: a validator safety hold at the start time postpones the switch instead of cancelling the plan (5.3, 3.3, 5.4, 12); a scheduled plan is cancelled in any block dated more than one hour after its parent, not only the activating one (5.3); cleaning keeps the time of a candidate's last change, so the interval between two changes holds (5.3); `--stop-after-height` is judged against the last block a node committed (3.4). After the second review: a jailed validator is left out of the total as well as out of the support (5.2, 5.4, 12); the stop height is judged against a record of committed blocks that a replay does not shorten (3.4).

Revision 4 records the first run on a live network, on 2026-11-18 (section 19): which of the tests that section 14 asks for with real CometBFT it covered, and which doubts of section 18 it settled. It also states two things the run made plain and the text only implied: the order of work that the local policy imposes (5.1), and how close the two thresholds are on a small roster (5.4). No rule, number or byte changed.

Revision 5 (22 November 2026) records that the emergency path of section 10 is built in the engine and tested there, and what had to be decided where this document was silent (section 20). The rule of section 10 is unchanged and so is every byte of 3.1 and 3.2: there is still no fast lane. Two things are added that this document did not name: a fix release's switch names its network, and a fix release can repair one block that was decided and could not be executed. Nothing of it has run on a network (sections 18 to 20).

Two builders work from this document: one on the engine and node (`v5/`), one on the verifier, SDK, gateway, wallet, alert watch and kit. **Section 3 is the one place for every number, byte and name both must agree on.** Section 15 lists what release 1 builds.

## 1. The design in ten lines

1. The owner account of a validator sends one new action, a **signal** (kind 80). It names the rules the validator supports: a version number, the hash of that version's specification, and the chain time at which it should start.
2. When signals for one plan hold **four fifths** of the voting power in force, and its start is at least **21 days** ahead, the plan is **scheduled**.
3. A scheduled plan must keep **three quarters** of the votes in every block until it starts, or it is cancelled.
4. The start time is "not before". The first block dated at or after it in which no validator safety hold is on is the last under the old rules. It ends by writing the new version into the state. The next block is the first under the new rules, and its header carries the new version. A plan that has not started one hour after its start time is cancelled.
5. A program implements a list of versions. One that lacks the new version computes the same last block as everyone, stops answering, saves, prints what to install, and exits with code 4.
6. A version never changes what an existing action does. New behaviour is a new kind or a new field, refused before its version.
7. If nobody ever signals, no row is added and no byte changes.
8. Wallets take the version from the header their light client verified, and a coming upgrade from a proven state row, never from the gateway. Software that does not know the version raises `UPGRADE_REQUIRED`.
9. Nothing shortens the 21 days. For an emergency, release 1 carries two tools: a coordinated stop at a height, and a reserved action kind (81) that makes programs which were not replaced stop before the block that switches.
10. The design prevents a split. It does not prevent a halt: if validators signal and then do not run the program, the chain waits for them.

## 2. Words used

- **Version**: the number in `meta.protocol_version`, 4 today. It names the rules that execute the *next* block. CometBFT calls it `version.app`. The **first version** of a network is the one in its genesis and trust manifest; it never changes.
- **Spec hash**: SHA-256 of the published specification file of a version (`spec/protocol-N.md`).
- **Plan**: a version, its spec hash and a start time, in microseconds of chain time since genesis.
- **Roster in force**: the validators and voting powers CometBFT uses for the block being executed (`pos::Summary.active`) and the rosters already announced for the next two blocks (`Summary.scheduled`). Powers include what the bootstrap lends the starting validators.
- **Support** of a plan: section 5.2.
- **Activating block** `h`: the block that ends by writing a scheduled plan's version. It is the first block dated at or after the plan's start time in which no validator safety hold is on. **Activation height** `A = h + 1`: the first block under the new version.
- **Runnable**: a head whose version is in the program's list (section 6).

## 3. Numbers, bytes and names

### 3.1 Action kinds

The envelope is the existing one (`v5/src/wire.rs`), unchanged:

`"TCDEVNET-ACTION-V1\0"` (19 bytes) ‖ network id (32) ‖ kind (1) ‖ from (8) ‖ nonce (8) ‖ authority epoch (8) ‖ public key (32) ‖ payload length (4) ‖ payload ‖ signature (64). Integers are big-endian. The kind is the byte at offset 51.

**Kind 80, signal.** Signed, next nonce, current authority epoch, network fee. The payload is one of exactly two byte strings:

| Payload | Meaning |
|---|---|
| `{"activate_elapsed_micros":"D","spec":"H","version":"D"}` | Support this plan. |
| `{}` | Withdraw. |

`D` is a decimal `u64` without leading zeros; `H` is 64 lowercase hexadecimal characters. Keys in this order, no spaces. Anything else is refused.

**Kind 81, switch. Reserved.** Release 1 never accepts it (section 6.3) and tells it by the kind byte alone. The form a fix release will use: the unsigned envelope of kind 40 (from 2^64 − 1, nonce 0, epoch 0, key and signature all zero) with payload `{"spec":"H","version":"D"}`.

### 3.2 State rows

Values are canonical JSON: keys sorted, no spaces, integers as decimal strings.

**`upgrade/state`** (the key is these 13 ASCII bytes; the value is shown on two lines and stored without the break):

```
{"plan":{"activate_elapsed_micros":"D","scheduled_elapsed_micros":"D","spec":"H","version":"D"},
 "signals":[ENTRY,…]}
ENTRY, support:   {"activate_elapsed_micros":"D","changed_elapsed_micros":"D","owner":"D","spec":"H","version":"D"}
ENTRY, withdrawn: {"changed_elapsed_micros":"D","owner":"D"}
```

- `plan` is present only while a plan is scheduled. Its `activate_elapsed_micros` is "not before": while a validator safety hold lasts the plan stays in the row past that time, for at most the wait of 3.3.
- `signals` is sorted by `owner` as a number, one entry per candidate, at most 256, under 64 KiB in all.
- A withdrawn entry exists only to enforce the interval between changes.
- The row is absent when there is no plan and no entry.

**`upgrade/activated/` ‖ version (8 bytes, big-endian)**: `{"elapsed_micros":"D","height":"D","notice":"scheduled","spec":"H"}`. `height` is `A`; `elapsed_micros` is the time of the activating block; `notice` is `"scheduled"` or `"none"` (a switch, section 10). Written once per version, kept for ever.

### 3.3 Times and thresholds

| | Production profile | Laboratory profile |
|---|---|---|
| Support needed to schedule | at least 4/5 | same |
| Support needed to stay scheduled | at least 3/4 | same |
| Notice: least time from scheduling to start | 21 days | 120 seconds |
| Farthest start a signal may name | 120 days ahead | 1 hour ahead |
| Least time between two changes of one candidate's signal | 10 minutes | 1 second |
| Largest gap between a block and its parent that keeps a scheduled plan | 1 hour | 1 hour |
| Longest a plan may wait after its start time before it is cancelled (a validator safety hold postpones the switch) | 1 hour | 60 seconds |
| Mempool admission margin (`ADMISSION_MARGIN_MICROS`) | 30 seconds | same |

All times are chain time. Shares are compared in 128-bit integers: `support × 5 ≥ total × 4`, `support × 4 ≥ total × 3`.

### 3.4 Node flag, exit codes, status

**Flag** `--stop-after-height H` (decimal, at least 1). After the commit of block `H` the node takes the stop path. Started with its head at `H`, it takes it at once. Started when it has already committed a block above `H`, it exits with code 1. What it has committed is judged by the entries of its history archive, one per committed block, not only by its newest snapshot, which may be older. A replay after a restart does not cut the entries that follow the block it replays, so a replay that is itself cut short leaves that record whole; and the records a restore prepared without ever installing its state are not entries of blocks.

**Exit codes.** 0, 1 and 3 keep their meaning. **4 is new: stopped at a height on purpose.** The first line printed says why:

| First line | Cause |
|---|---|
| `STOPPED FOR UPGRADE` | The head is not runnable. |
| `STOPPED AS ASKED` | `--stop-after-height`. |
| `STOPPED AT A SWITCH` | A decided block carries kind 81. |

**The stop path**, in this order: answer the `Commit` in progress, if any; from then on answer no consensus request and refuse `CheckTx`; write the snapshot; print; exit 4.

**`/status`** gains one field. It is not consensus data.

```
"upgrade":{"implemented":[{"spec":"H","version":"4"}],
           "scheduled":null | {the plan object of 3.2},
           "implements_scheduled":null | true | false,
           "stop_after_height":null | "D"}
```

### 3.5 What a client sees

- **Request.** The `/v4/state` selection gains `"include_upgrade":true`, left out when false, like `include_security`.
- **Answer.** `entries` then holds one more entry, for the key `upgrade/state`: its value with a proof, or a proof that it is absent, in the format of every other entry.
- **Verified state.** The verifier's `view` adds `state.upgrade`: `null` when the row is proven absent, otherwise the row as stored, after checking its form. **A view that asked for it and has no entry for the key is refused**; it is never read as "no plan".
- **SDK.** `client.getUpgradeStatus()` returns `{version, scheduled, known}`: the version of the verified state, the plan object or `null`, and whether this build knows the scheduled version (`true` when nothing is scheduled).
- **The error.** Software that meets a version above what it knows fails with a message that begins `UPGRADE_REQUIRED:`, the convention of `CHECKPOINT_REFRESH_REQUIRED:` and `STALE_STATE:`. The verifier returns it; the SDK, the order and login servers, the wallet and the watch pass it on unchanged.
- Release 1 clients know versions 4 to 4.

## 4. What CometBFT 0.38.26 does with the version

The review confirmed each of these against the source.

- **Start.** The handshake copies `Info.app_version` into its state only while `LastBlockHeight == 0` (`consensus/replay.go:269`). Later it compares nothing. **CometBFT does not stop a program with other rules; the application has to.**
- **Every block.** `FinalizeBlock(h)` returns consensus parameters; the state takes their `version.app` (`state/execution.go:666`); header `h + 1` is built with it (`state/state.go:259`); a block with another version is invalid in consensus and in block sync (`state/validation.go:32`, `blocksync/reactor.go:604`). The engine already returns the version of the state *after* the block (`app.rs:592`), so nothing changes there.
- The version is in the header hash. It is not in `ConsensusHash`.
- **Peers** do not compare application versions (`p2p/node_info.go`, `CompatibleWith`). The value a node shows in `node_info.protocol_version.app` is from its start and goes stale: **nothing may monitor it.**
- **If the application stops answering or ends**, CometBFT signs nothing and ends its process (`proxy/multi_app_conn.go:129`, `consensus/state.go:1377`).
- **Restart at the boundary.** All three handshake cases work (`consensus/replay.go:405–452`). The case "application at `h`, CometBFT state at `h − 1`" replays the stored answer, so the design **depends on `discard_abci_responses = false`**, which the kit sets (`deploy/operator.mjs:18`) and must keep.
- **State sync.** When this was written the application refused snapshots; it now offers and restores them. The definition of "version" matches what CometBFT checks after a restore (`statesync/syncer.go:499`). A snapshot carries the version, the plan and the signals with the rest of the state. A program never installs a state under a version it does not implement, or implements under another specification hash: it keeps the state it had, aborts the state sync and says what to install. A snapshot from before an activation restores on any program, and an old one then stops after the activating block like a node that was there all along. A release therefore still keeps every version back to 4: a node replays from its own snapshots and from those peers offer, and either can predate an activation.

## 5. The plan on the chain

### 5.1 When a signal is accepted

A block accepts a kind-80 action only if all of these hold. Each refusal is a test.

1. The ordinary checks pass: nonce, authority epoch, a key with `can_spend`, the fee, and for a secured account the daily limit and "not frozen" (`engine.rs:2059–2083`).
2. The sender owns a validator candidate that is not archived (`pos/candidate/<from>`). It need not be in the roster.
3. The payload is one of the two forms of 3.1.
4. For support: `version` is the current version plus one.
5. For support: the start time is from the notice to the farthest start ahead of this block, or the three fields equal the scheduled plan's, so that validators joining later can support it.
6. It changes something: the same plan again, or a withdrawal with no support entry, is refused.
7. The candidate's entry, if any, changed at least the interval ago.

The entry is then replaced, with `changed_elapsed_micros` set to this block's time. Kind 80 joins 17, 18 and 20 in the list a validator safety hold lets through (`engine.rs:1989`), so support can be withdrawn during a hold.

**Which key.** As for every staking action: the single key of a protocol-4 account, or a spend key of a secured account. A sign-in key or a recovery key cannot signal. Delegators and ordinary accounts do not signal.

**Local policy, not a consensus rule.** At mempool admission and when it selects transactions in `PrepareProposal`, a node refuses a support signal whose version and spec hash are not in its own list, and applies the admission margin to the start time. `ProcessProposal` and `FinalizeBlock` apply neither. A signal for rules that no honest program implements therefore never enters a block made by an honest proposer. A release-1 node admits no support signal at all, since no version 5 exists.

**What the policy means for the order of work.** While every validator runs a program without the new version, no support signal for it enters a block: each node refuses it at admission, and no proposer would select it. The release that implements a version is therefore installed on validators before anyone signals, and a signal is handed to a node that runs it. It waits in the mempools of such nodes and is included when one of them proposes, so one validator on the new release is enough, and more of them shorten the wait. The live rehearsal ran exactly this (section 19): a release node refused the signal, and signals entered blocks once one of seven validators ran the build with the version.

### 5.2 Whose signal counts

A validator whose candidate is jailed is left out of the count altogether: it is in neither sum below. It leaves the roster two blocks after it was jailed, and until then the plan is judged by the validators that remain.

The support of a plan in a roster is the voting power of the validators in it that are not jailed and for which both of these hold, divided by the total power of the roster's validators that are not jailed:

- the owner's entry is a support entry with exactly this plan;
- **the owner account is neither frozen nor in a recovery** at this block's time. For a secured account: `Security::frozen` after `settle`, which is a freeze still running or a replacement of the keys waiting. For a protocol-4 account: a guardian recovery case that is ready (`engine.rs:2072`).

Support is computed in the roster in force and in each announced roster. The lowest value counts. A roster in which every validator is jailed supports nothing.

**Why a jailed validator is out of the total as well.** Left in the total, a jailed supporter lowered the share at once while its power still counted against the plan for two blocks: with five equal validators and four supporters, one supporter signing twice made it three of five and cancelled a plan that three of the four remaining validators support. Whoever stole the consensus key of one supporter could cancel every upgrade. A frozen or recovering owner is different: its validator stays in the roster and votes, so it stays in the total.

**What leaving a jailed non-supporter out can do.** It raises the others' share to their share of the validators that remain, which is the share they will have two blocks later anyway, when the roster without it is in force. It cannot bring a change about that the roster in force does not support: whenever a jailed validator is in a roster the tally looks at, a validator safety hold is on (`pos::Summary::safety_hold` is true exactly then), and during a hold nothing is scheduled and nothing is activated. So the rule decides one thing only: whether a plan that is already scheduled survives the blocks of a hold. By the time a plan can be scheduled or activated, no roster holds a jailed validator and the count is over the real rosters.

The second condition answers a stolen spend key. A thief who signals and then freezes the account, or keeps the owner's withdrawal out by using up nonces, gains nothing: the owner freezes with any spend or recovery key, which needs no nonce, and the signal stops counting. **It gives one recovery key of that account a veto over that one validator's signal**, since one recovery key can freeze. That is the safe side. A signal that does not count can only keep a plan from being scheduled or cancel one, which leaves the rules as they are; it can never bring a change about.

### 5.3 The end of every block

After the block's transactions and `pos_adapter::finalize`, and only if `upgrade/state` exists. The row is decoded at most once per block and written at most once, here.

1. **Clean.** Drop support entries whose owner is no longer a live candidate, whose version is not the current one plus one, or whose start time is closer than the notice and is not the scheduled plan's. Drop withdrawn entries older than the interval. A support entry dropped less than the interval after its last change leaves a withdrawn entry with that change time: without it a candidate could change its signal again as soon as the cleaning had removed its entry.
2. **Keep or cancel.** If a plan is scheduled and its support is below 3/4, or this block is dated more than one hour after its parent, remove it.
3. **Activate, postpone or cancel.** If a plan is still scheduled and this block's time is at or after its start: if more than the wait of 3.3 (one hour) has passed since its start time, remove the plan. Otherwise, if a validator safety hold is on, do nothing: the plan waits for the first block without a hold. Otherwise set `meta.protocol_version` to its version, write `upgrade/activated/<version>` and remove the plan and all entries.
4. **Schedule.** If no plan is scheduled, no hold is on, and a plan has support of at least 4/5 and a start at least the notice after this block, record it with this block's time. Two plans cannot both hold 4/5.
5. Write the row, or remove it if it is empty.

No input a transaction can create makes this step fail. Without the row its cost is one lookup.

### 5.4 Why these numbers

- **4/5 to schedule.** Blocks need more than two thirds; the margin is for validators that signalled and are not ready. The staking rule keeps any one key below a third of the votes, so a large validator can block an upgrade and none can force one.
- **What one validator can do at the start time.** A validator that signs twice is jailed, and a validator safety hold is on until it has left the roster, two blocks later. Were a hold at the start time to cancel the plan, one validator with the minimum bond, signalling or not, could cancel every plan at the price of its bond, 21 days each time. A hold therefore postpones the switch: the plan activates in the first block without a hold, if it still has 3/4. One validator can so delay a switch by the blocks its removal takes, and by nothing else. It cannot cancel a plan: for that a hold must last an hour past the start time, which happens only when a jailed validator cannot leave the roster because fewer than four clean validators would remain. That is a network in trouble, and it keeps its rules. A jailed validator, supporter or not, is also left out of the count (5.2): one supporter that signs twice no longer cancels a plan the others keep.
- **3/4 to keep**, so that a small change of the roster does not cancel a plan. The margins are thin: after scheduling at exactly 80%, new stake of 6.7% that does not signal cancels the plan and costs 21 days. A jailed signaller does not cancel it by being jailed: a jailed validator is left out of the support and of the total alike (5.2), so the share falls only a little (a signaller with 6% of the votes takes 80% to 78.7%), and it stays at three quarters or more as long as the jailed signallers hold a fifth of the votes or less. At exactly 75%, 8.3% of the votes that signalled and do not run the program halt the chain at `A`.
- **On a small roster the two thresholds meet.** The comparison is exact (3.3), so with seven equal validators six are needed to schedule and six to stay scheduled: a plan that six scheduled is cancelled by one withdrawal. With twenty equal validators it is sixteen and fifteen. Blocks need five of seven and fourteen of twenty.
- **21 days in chain time.** 14 days is the unbonding delay: whoever disagrees can take stake out first. 7 days is the light client's trust period: a wallet opened that often sees the plan with 14 days left. Blocks cannot be dated more than 30 to 60 seconds ahead of honest clocks, so making them faster does not shorten the notice.
- **A time, not a height.** No program is swapped at the switch: the new one is installed earlier and runs the old rules until then.
- **The one-hour gap** keeps a plan from activating after a halt, and a halt from using up notice nobody could act on: a block dated more than an hour after its parent cancels a scheduled plan, before its start time or at it. The plan may be scheduled again at once if 4/5 still support it and a full notice is still ahead.
- **The one-hour wait.** The start time is announced to wallets and operators; a switch that could slip without bound would make it meaningless. A plan activates from its start time to one hour after it, or not at all. In production the hour is the hour of the gap rule, so the first block at or after the start time is never too late without also being a gap: only a hold makes a plan wait.

### 5.5 While the starting validators hold more than half

Until the hand-over, nothing is scheduled without the starting validators and they can cancel any plan. They schedule alone only while they hold 4/5 or more, as in the first months. If one organization runs all twenty, it decides upgrades alone in that time, which is the trust the bootstrap already asks for; the mechanism still makes it give 21 days of proven notice. After the hand-over they count with their own stake.

## 6. What a node does

### 6.1 The list and the stop

A program holds `rules::IMPLEMENTED`, a list of versions with their spec hashes, contiguous from 4. In release 1 it is `[(4, SPEC_4)]`. The engine takes the list as a parameter, so that tests run with two versions. The head is **runnable** if its version is in the list and, above 4, `upgrade/activated/<version>` carries the same spec hash.

| When | A node that implements the plan | A node that does not |
|---|---|---|
| A plan is scheduled | Logs it once. | Warns at start and every ten minutes. `/status` shows `implements_scheduled: false`; the monitor alerts. |
| The activating block `h` | Executes it under the old rules. | Executes it and commits **the same state, byte for byte**: writing the number is part of the old rules. |
| After `Commit(h)` | Continues. | Takes the stop path (3.4): `STOPPED FOR UPGRADE`, exit 4. It answers nothing for `h + 1`: neither accept nor reject. |
| Started on a head that is not runnable | — | Prints the same and exits 4 before the ABCI socket opens. `--audit` refuses too. |

The node stops answering *before* it writes the snapshot: a snapshot can take longer than the second CometBFT waits before the next height.

> STOPPED FOR UPGRADE. This chain runs protocol version 5 (spec ab12…) from height 1,234,568. This program implements version 4. The state at height 1,234,567 is saved and valid. Install a release that implements version 5 and start it on the same data. Delete nothing.

The stopped node's state at `h` is everyone's state, and the new release continues from its snapshot. A validator that stopped signs nothing. If more than a third of the votes stopped, block `h + 1` waits for them. A program with other rules under the same number has another spec hash and stops too.

Engine 0.6.0 knows neither kind 80 nor these rules. It rejects every proposal that carries a signal and exits with code 1 if such a block is decided. The mechanism has to be in the first production release.

### 6.2 The coordinated stop

`--stop-after-height H` (3.4) exists for the emergency procedure. A node that has it does not judge any proposal for `H + 1`. If operators holding more than a third of the votes set it, no block at `H + 1` can gather two thirds of the prevotes, so no validator is locked on one and the chain stands at `H` for everyone.

### 6.3 Kind 81

A release-1 program:

- refuses it at mempool admission and never proposes it;
- **rejects** a proposal that carries it and goes on. It must not stop on a proposal: one proposer could then stop every node;
- on a **decided** block that carries it, executes nothing and takes the stop path: `STOPPED AT A SWITCH`, exit 4. Its state stays at the height before, and CometBFT keeps the block.

A block with kind 81 is decided only if two thirds of the votes run a program that accepts it.

## 7. How rules are gated in code

```rust
// v5/src/rules.rs
#[derive(Clone, Copy)]
pub struct Rules(u64);
impl Rules { pub fn since(self, version: u64) -> bool { self.0 >= version } }

// accepting something new
ensure!(self.rules.since(5), "this action needs protocol version 5");
```

- **A version never changes what an existing kind or payload does.** The action header carries no version, approvals of a root operation live up to 30 days, and a transaction signed at `h − 1` can land at `h + 1`. Bytes signed under one version must mean the same under the next. New behaviour is a new kind, or a new field that is refused before its version. A version may stop accepting a kind; it never makes one do something else.
- `Overlay` gets a field `rules`, set once when the block starts, from the committed head. Step 3 of 5.3 writes `meta.protocol_version` after the last transaction, so nothing in the activating block sees the new number.
- `meta.protocol_version` is written in one place and read in `rules.rs`, in `Meta::validate` ("4 or more", no longer "equal to 4") and where `app.rs` reports it. A test scans the source for other uses.
- New rows appear when first used. New fields of existing rows are written only when set.
- **No migration at the switch.** The activating block changes one number and the `upgrade/` rows.
- **After launch, every change a block can see is a version.**

**The differential tests.** `v5/tests/differential.rs` runs chains at version 4 on which nobody signals. All new code is behind kind 80, kind 81 or `since(5)`. The protocol-4 engine knows none of these and the tests send none. Neither `v4/` nor `differential.rs` is edited.

## 8. Clients

Two things are written "4" today:

- **The first version**: `trust.app_version`, the genesis, the gateway's `/api/network.protocolVersion`, the release manifest. **These stay "4" for ever.** A trust anchor is never reissued for an upgrade.
- **The version in force**, which must come from verified data.

### 8.1 Rules for the verifier (release 1)

1. **Headers** (`light.rs:137`): the version is at least the first version, and a candidate above the trusted checkpoint does not carry a lower version than it. There is no upper bound: checking a header uses no application rule, and the verifier crate never reads the version. A wallet's checkpoint so keeps advancing across an upgrade it does not know.
2. **Views** (`view.rs:469`): `meta.protocol_version` equals the certifying header's `version.app`. Above what the build knows: `UPGRADE_REQUIRED:`. Then 3.5.
3. **Receipts** (`receipt.rs:93`, `:275`): a header version above what the build knows gives `UPGRADE_REQUIRED:`.

### 8.2 Every place that pins 4

F = first version, stays. V = version in force, changes. "Later" = when a version 5 exists.

| Place | Kind | Change | If left as it is |
|---|---|---|---|
| `v5/src/engine.rs:346` `Meta::validate` | V | `>= 4`; runnable checked apart | An old node cannot tell an upgrade from a damaged state |
| `v5/src/engine.rs:2265` merchant reference rule | V | `since(4)` | **The rule switches off silently at 5** |
| `v5/src/main.rs:142` `--audit` prints `"protocol":"4"` | V | The head's version | A false report |
| `v5/src/main.rs:179`, `deploy/lib.mjs:27`, `deploy/build.mjs:17` version line | F | Later: `protocol=4..5` | — |
| `verifier-v4/src/light.rs:114` | F | None | — |
| `verifier-v4/src/light.rs:137`, `view.rs:469`, `receipt.rs:93, :275` | V | 8.1 | Checkpoints stop advancing at `A`; everything fails with a wrong reason |
| `client-v4/light-client.mjs:9` and stored `appVersion:'4'` | F | **None.** Changing the stored value would make every wallet discard its checkpoint | — |
| `client-v4/time-sdk.js:127` | F | None | — |
| `client-v4/time-sdk.js:150` `getNetwork()` | F | None. It refuses a gateway that reports anything but `'4'` | — |
| `client-v4/time-sdk.js:248` `submit` | F used as V | Decide from the verified state | Works by accident |
| `client-v4/time-sdk.js:39` `checkMerchantQuote` | V | "4 or later" | **Every merchant payment fails at 5** (it throws) |
| `client-v4/time-sdk.js:258` | V | "4 or later" | The quote check is skipped silently at 5 |
| `client-v4/time-sdk.js:172` `selection()` | — | `include_upgrade`; `getUpgradeStatus()` | — |
| `client-v4/server.mjs:53, :65, :292, :378` | F | None | — |
| `client-v4/server-auth.mjs:83, :95, :109, :140` | F | None | — |
| `client-v4/server-auth.mjs:111` merchant order issuance | V | A version this build knows, else `UPGRADE_REQUIRED:` | No order can be issued after `A` |
| Website logins (through the verifier) | V | 8.1; pass the error on | Logins fail with a wrong reason |
| `web-v4/wallet/actions.mjs:11` | V | "4 or later" | Check skipped silently |
| `web-v4/wallet/app.js:235, :476` | F used as V | Decide from the verified state. Not exploitable today: `getNetwork()` already refuses another value | Works by accident |
| `web-v4/wallet/app.js:499` badge | F shown as V | Show the verified version | Shows "V4" for ever |
| `web-v4/wallet/tests/browser-e2e.mjs:252` | — | Header version at least the trust version | The test fails after an upgrade |
| `client-v4/security-watch-service.mjs`; `deploy/watch/start.mjs:31` (F) | V | New events `upgrade_scheduled`, and `watch_outdated`: daily while the scheduled version is unknown to the build, and at once on `UPGRADE_REQUIRED:` | It sends `watch_blind` only after the allowed lag, with a misleading reason |
| `deploy/operator.mjs` `childOutcome` | — | Report exit code 4 with its cause | Reported as a generic failure |
| `deploy/operator.mjs` `appCommand` | — | Setting `stop_after_height` gives the flag | — |
| `deploy/operator.mjs:24` `checkHealth`; `deploy/lib.mjs:32`; `tools/release-v4.mjs:101` | F | Later: a range, with `protocol_max` in the manifest | Later releases cannot start |
| `deploy/monitor.mjs`, `alerts.yaml` | — | Alert on `implements_scheduled: false`; read the version from the application's `/status` | — |
| `deploy/gateway/start.mjs:34`; `tools/genesis-v5.mjs:51, :333`; `campaign/lib/genesis.mjs:75–81` | F | None, but the id bound of section 11 | — |

**Signer leases** name the release, last five minutes and are checked every five seconds (`deploy/operator.mjs`, `guard`). Every upgrade release needs leases before a validator can run it.

**What a gateway can do.** Refuse to answer; the wallet then shows "cannot verify". It cannot show a false version or hide a plan: the version comes from a certified header and a proven state, and a view without the `upgrade/state` entry is refused.

## 9. Byte compatibility

**Claim.** A network on which no signal is ever accepted has, block for block, the state roots, metadata bytes, rows and `FinalizeBlock` answers of engine 0.6.0. The review found the claim to hold as argued.

**Why.** No field is added to `Meta`, the genesis, account rows or staking rows. The only new rows are under `upgrade/`, and the first accepted signal writes the first. Kinds 80 and 81 are the only new actions. The edited checks answer the same at version 4. `/status` and the `--audit` report are not consensus data.

**Caveat.** Kinds 80 and 81 are rules, so release 1 is a fourth set of rules under the number 4 (section 17).

**Tests.**

1. `differential.rs` passes unedited.
2. **Recorded roots.** Before any change, record from `8ee2090` the root and the metadata hash after every block of scripted runs that cover what the protocol-4 engine cannot check: account security, both fee settings, all new time to validators, the hand-over rule, reported misbehavior. The same runs must give the same values afterwards.
3. After every block of every existing test no key starts with `upgrade/`, and `--audit` counts the leaves it counted before.
4. A snapshot written by 0.6.0 loads and continues to the recorded roots.
5. A local four-validator network with two 0.6.0 nodes and two release-1 nodes runs a load without signals. One differing byte stops it.

## 10. Emergency procedure

A finalized chain does not roll back, and the signal mechanism has no fast lane: one would turn theft of signalling keys into a rule change within hours.

1. **Agree on a height `H`** and stop there. Operators restart their validators with `--stop-after-height H`, keeping two thirds online until `H`. With more than a third of the votes stopping after `Commit(H)`, the chain stands at `H` (6.2). If too few set it and the chain goes on, pick a later `H`. If validators were stopped without agreement, restart the same release with the flag set to the next height until the chain stands.
2. **The fix release** defines version N + 1, often only "the faulty kinds are refused", with a compiled-in switch after `H`. It is reviewed, its spec hash published, its leases issued.
3. **Resume.** Two thirds of the votes start it. As proposer of `H + 1` it proposes exactly one transaction, the kind-81 switch for its version and spec hash. As validator it accepts only that block. The block ends with the new version and `upgrade/activated` with `"notice":"none"`, and removes any plan and all entries. **The switch wins over a scheduled plan** whose start time has passed: a plan never activates in a switch block. The fix applies from `H + 2`.
4. **Programs that were not replaced** stop at `H` with the block stored (6.3). Installing the fix release is all there is to do: CometBFT's handshake hands it block `H + 1` (`consensus/replay.go:428`). No rollback, no file to delete. Wallets and servers that do not know N + 1 get `UPGRADE_REQUIRED:`.

**What the fix release refuses**, so that a wrong `H` cannot be papered over:

- to start, when its head is above `H` and still at the old version;
- to execute a decided block `H + 1` that is not the switch block, wherever it comes from: it takes the stop path.

The second rule is how "no store holds a block above `H`" is enforced. The application cannot read CometBFT's block store at start; it receives what that store holds at the handshake, before anything else. Its own history archive is not checked at start, because after a crash it can hold the entry of the switch block itself.

Every later release keeps the switch in its list, so that it replays the chain from genesis.

What this costs: more than a third must cooperate to stop and two thirds to resume, and the faulty rules run until `H`. What makes it less likely to be needed: each feature is a new kind an account opts into; every release is rehearsed through a real activation; the first real upgrade changes almost nothing.

## 11. Account numbers and zones

**Today.** An account id is a 64-bit number. Genesis accounts carry the ids the genesis gives them (`src/ledger.rs:345`; the ceremony tool gives 0 to 19). Each registration takes `meta.next_account_id` and adds one (`src/ledger/v1.rs:422`, `v5/src/engine.rs:2542`). 2^64 − 1 is not an account: it is the sender of header relays. Ids are 8 big-endian bytes in keys and in the action header, and decimal strings in payloads and JSON.

**Reserved.** An id is `zone × 2^48 + number`. Zone 0 is this chain, so every existing id keeps its value. Zones 1 to 65,534 are for later; zone 65,535 is never used.

**The engine enforces now** one thing: a new network's genesis ids are below 2^48 (`Genesis::validate_new`; the genesis tools check the same). Registration counts up from there and cannot reach 2^48. A payment to an id at or above 2^48 already fails with "account does not exist".

**The SDK and the HTTP API promise now.**

1. An account id is a decimal string matching `^(0|[1-9][0-9]{0,19})$`, never a JSON number, at most 18446744073709551614. The value 18446744073709551615 appears as the sender of header relays and is not an account.
2. It is opaque: do not compute with it or assume it is short. Store it as text or as an unsigned 64-bit integer. The SDK sorts ids where the protocol requires it, as numbers.
3. It never changes, also when zones arrive.

Before zones: how an id with a zone is shown to people, whether names are unique across zones, and what a zone's network id is. Nothing in release 1 depends on these.

## 12. Threats

| Threat | What happens |
|---|---|
| **A plan no program implements** | Honest nodes neither admit nor propose its signals (5.1), so a mistyped hash, or stolen owner keys without a modified validator, never reaches a block. Past that, it needs 4/5 and then 3/4 in every block for 21 days while every node warns. If it activates all the same, every honest node stops at `h` with the same state, and a release that lists that version and spec hash restarts the chain. A halt, not a split. |
| **Signalling without running the program** | The chain cannot inspect a program, and a validator can send its signal through someone else's node. If more than a third of the votes lack the program at `A`, the chain waits for them. This is the halt the design does not prevent. What makes it unlikely: a node that lacks the plan warns its operator for 21 days and raises an alert; the release is public, since others run it; the plan must hold 3/4 in every block; and installing the release ends the halt with nothing lost. |
| **A stolen recovery key** | It can freeze and so silence that validator's signal until the keys are replaced. It can delay an upgrade and cannot cause one. |
| **A stolen consensus key of a supporter** | Signing twice with it jails that validator, at the price of its bond. It is left out of the count, total and support alike, and the plan is judged by the validators that remain: it is cancelled only if they hold less than 3/4 among themselves. |
| **A stolen consensus key of a validator that does not support the plan** | Jailing it takes it out of the total two blocks before it leaves the roster. Nothing is scheduled or activated in those blocks (a hold is on), so no change happens that the remaining roster does not support (5.2). |
| **A validator changes its mind** | At most once per interval. More than a quarter of the votes can cancel a plan; that keeps the old rules. |
| **The roster changes during the notice** | Support is recomputed every block against three rosters. |
| **A validator signs twice just before the start time** | It is jailed and loses its bond. The hold that follows postpones the switch by the blocks its removal takes; the plan activates in the first block without a hold. It cannot cancel the plan (5.4). |
| **A hold that does not end** | The plan is cancelled one hour after its start time. The rules stay as they are. |
| **Replay** | A signal carries the network id, nonce and authority epoch, and is invalid once its version is in force. |
| **Spam** | Candidates only; one change per candidate per interval; one decode and one write of the row per block. |
| **Two thirds running other software** | Nothing prevents it. Under honest programs there is no rule change without 21 days of proven notice, and full nodes that did not change stop instead of following. |

Answered where the rule is stated: a stolen spend key (5.2), old signatures under new rules (7), activation after a halt or during a hold (5.3), a lying gateway (8.2), kind 81 as a way to stop nodes (6.3), a bug in the new rules (10).

## 13. Alternatives rejected

- **The plan names a height.** A notice counted in blocks is shortened by making blocks faster.
- **A proposer role or one open proposal.** A slot a small validator can occupy.
- **Readiness signalled by the program** (vote extensions). It changes every vote on every network, and the application holds no key. The local policy of 5.1 gives part of the benefit.
- **A root operation to signal, or a withdrawal that needs no nonce.** The counting rule of 5.2 answers the same theft with no new action form.
- **A second majority among independent validators during the bootstrap.** The first small one would hold a veto.
- **A "client floor" that lets old wallets keep reading after an upgrade.** An old verifier cannot judge what it cannot read.

## 14. Tests and review checklist

**Engine**

- Each refusal of 5.1; the interval; the local policy in admission and proposal, and its absence in `ProcessProposal` and `FinalizeBlock`; the admission margin.
- Support: both fractions at their exact boundaries; the lowest of three rosters; jailed, frozen and recovering owners excluded, and counted again when the freeze ends by time alone.
- A hold at the start time: one that ends inside the hour (the plan activates in the first block without it); one that outlasts it (cancelled); support falling under 3/4 and a block gap above an hour while the plan waits; programs with and without the version agreeing on the postponed activating block.
- The interval between two changes of one candidate's signal, across entries the cleaning drops.
- The state machine under random signals, roster changes, holds and block times, checked after every block: a scheduled plan has 3/4; no activation before scheduling plus the notice, during a hold, after a gap above one hour, or more than an hour after its start time; a plan past its start time only during a hold; one change per candidate per interval; the version rises by one; no row when idle; one decode and one write per block.
- Hand-over: the starting validators at 55% cannot schedule alone and at 85% can.
- Two engines from one source, one given version 5 in its list: equal roots up to `h`; the old one stops after `Commit(h)` with code 4, answers nothing for `h + 1`, refuses to restart; the new one continues from the old one's snapshot.
- `--stop-after-height`: stop after `H`; start at `H`; start above `H`.
- Kind 81: refused in admission; proposal rejected and the node goes on; decided block not executed, exit 4, head unchanged.
- Restart with the snapshot before, at and after `h`; replay from genesis across the switch; a wrong spec hash under a known number.
- `--audit` counts the `upgrade/` rows, prints the real version, and refuses a head that is not runnable.
- Section 9, tests 1 to 5.

**With real CometBFT 0.38.26**, four laboratory validators and a build whose list holds a rehearsal version 5 with the rules of 4: header `h + 1` carries the new version; the stop race (the node stops answering before the next proposal); the three restart cases of section 4; two of four on the old program make the chain wait and resume; a stop at `H` by two of four. Section 19 says which of these ran on 2026-11-18, on seven validators, and which did not.

**Clients**

- A header with a lower version than an earlier one is refused; a higher unknown one is accepted as a checkpoint; a checkpoint stored before `A` still loads.
- A view whose metadata version differs from its header, or that lacks the requested `upgrade/state` entry, is refused; an unknown version gives `UPGRADE_REQUIRED:` from views and receipts.
- `getUpgradeStatus()` on a row that is absent, has entries only, or has a plan the build does not know.
- Merchant payments, order issuance and logins at a version the build knows; the passed-on error at one it does not.
- The watch sends `upgrade_scheduled` and `watch_outdated`.
- The kit reports exit code 4 with its cause and passes `stop_after_height`.

**Review checklist**

- [ ] No block at version 4 reaches new code except through kinds 80 and 81.
- [ ] No version changes what an existing kind or payload does.
- [ ] `meta.protocol_version` is written in one place and read through `Rules`.
- [ ] The old program's last block is identical, the `FinalizeBlock` answer included.
- [ ] No path answers accept for a proposal on a head that is not runnable; no proposal can stop a node.
- [ ] The node stops answering before it writes its snapshot.
- [ ] The tally uses the powers CometBFT uses, lent power included, and the block's own time for freezes.
- [ ] The end-of-block step cannot fail on any input a transaction can create.
- [ ] The local policy is in admission and proposal only.
- [ ] No client reads the version or the plan from unverified data, and none monitors `node_info.protocol_version.app`.
- [ ] `discard_abci_responses = false` is still set.
- [ ] `v4/` and `differential.rs` are untouched; the recorded roots were taken before the first change.

## 15. Release 1 builds this

**Engine and node**

| Item | Files |
|---|---|
| The list of implemented versions, as a parameter; `Rules::since`; the runnable check | `v5/src/rules.rs` (new), `engine.rs`, `app.rs` |
| Kind 80: decoding, the checks of 5.1, the fee, the hold list | `v5/src/upgrade.rs` (new), `wire.rs` (`extension_kind`), `engine.rs` (`Overlay::apply`, `:1989`) |
| The row, the counting rule, the end-of-block step, the audit | `upgrade.rs`, `engine.rs` (`finish`, the audit's leaf count), `security.rs` (a read-only "frozen or recovering at this time") |
| The local policy and the admission margin | `engine.rs` (`CheckState`, `prepare_filtered_with_misbehavior`) |
| The stop path, exit code 4 and its three messages; start checks; warnings | `app.rs`, `main.rs` |
| `--stop-after-height` | `main.rs`, `app.rs` |
| Kind 81: refuse, reject, stop on a decided block | `app.rs`, `engine.rs` |
| `/status.upgrade`; `include_upgrade` in the state selection | `app.rs` |
| The edited pins: `Meta::validate`, the merchant rule, the `--audit` report | `engine.rs:346, :2265`, `main.rs:142` |
| Genesis ids below 2^48 | `v5/src/genesis.rs` |
| A build feature that adds a rehearsal version 5 with the rules of 4, refused by the release tool | `v5/Cargo.toml`, `rules.rs`, `tools/release-v5.mjs` |
| Tests, the recorded roots, and a fixture of proven `upgrade/state` rows (absent, entries only, with a plan) for the client builder | `v5/tests/upgrade.rs`, `upgrade_node.rs`, `golden.rs` (new) |
| The rules of release 1, so that 4 has a hash | `spec/protocol-4.md` (new) |

**Clients and kit**

| Item | Files |
|---|---|
| The three verifier rules; `state.upgrade`; `UPGRADE_REQUIRED:` | `verifier-v4/src/light.rs`, `view.rs`, `receipt.rs`, tests and fixtures |
| The compiled verifier that the wallet, the SDK and the servers load, rebuilt from the changed source | `web-v4/shared/verifier/` (`tools/build-verifier.mjs`, on `main` since `7bb9c83`) |
| `include_upgrade`, `getUpgradeStatus()`, the edited checks, the error passed on | `client-v4/time-sdk.js` (`:39, :172, :248, :258`) |
| A test that a stored checkpoint survives headers of a higher version | `client-v4/light-client.test.mjs` |
| Order issuance and logins; a warning in the server's log while a plan it does not know is scheduled | `client-v4/server-auth.mjs:111`, `server.mjs` |
| `upgrade_scheduled` and `watch_outdated` | `client-v4/security-watch-service.mjs`, `security-watch.mjs` |
| Verified version for the checks and the badge; a banner while a plan is scheduled; an "update this app" screen | `web-v4/wallet/app.js` (`:235, :476, :499`), `actions.mjs:11`, `tests/browser-e2e.mjs:252` |
| Exit code 4; `stop_after_height`; the alert | `deploy/operator.mjs` (`childOutcome`, `appCommand`), `monitor.mjs`, `alerts.yaml`, `settings.example.json` |
| Genesis ids below 2^48 | `tools/genesis-v5.mjs`, `campaign/lib/genesis.mjs` |
| Runbooks: an upgrade, an emergency | `deploy/README.md`, `deploy/PRODUCTION-V5.md` |
| A rehearsal of both on several hosts | `campaign/` |

**Waits until a version 5 exists**

- The table of kinds and their first versions.
- The version line `protocol=4..5`, `protocol_max` in the release manifest, and the range in `checkHealth`.
- The check of `upgrade/activated/<version>` and its spec hash in wallet views.
- A wallet screen for a validator's owner to send a signal. The kit never signs one: it holds no account key. (Built since, without waiting for a version 5: the SDK builds kind 80 and reads the proven status, and the wallet has a "Validator signal" tab; see `client-v4/README.md` and `web-v4/wallet/README.md`. Not yet run in a browser or on a live network.)
- The execution of kind 81, which only a fix release ever contains. (Built since, without waiting for a version 5: the engine takes a fix release's switch as a parameter beside its list of versions, so tests run a fix release and a release 1 from one source; section 20. Release 1 itself carries no switch and still never accepts kind 81.)

`v4/`, `pos/`, `registration/` and `src/` do not change.

## 16. Decided

By the project lead, after the review:

- 4/5 to schedule and 3/4 to keep; no activation during a hold or after a gap above an hour. A hold postpones the switch and does not cancel the plan; a plan that has not started one hour after its start time is cancelled.
- 21 days of notice.
- The spend key signals; a frozen or recovering owner's signal does not count.
- No fast lane; emergencies by the procedure of section 10.
- The first real upgrade changes almost nothing.
- Account ids: 16 bits of zone, 48 of number; only the genesis bound is enforced.
- Software that does not know a version stops. That includes merchant order servers and login servers, which need the same 21 days of warning as wallets.
- Every release keeps all versions back to 4.

## 17. Open questions for the owner

1. **Production starts at version 4: sign this off explicitly.** `AUDIT-2026-11.md` advises the opposite, a new number before any shared network, because the protocol-4 engine, engine 0.5.0 and engine 0.6.0 all report 4, and release 1 will be a fourth set of rules under it. The reason to stay is byte compatibility and the differential tests. If accepted, two conditions: the earlier programs that report 4 are **never leased on the production chain**, and `spec/protocol-4.md` is written for the rules of release 1.
2. **Who runs the lease controller after the hand-over?** Leases last five minutes. Whoever signs them can stop every validator that uses the kit within minutes, and can veto any release by not signing for it. That is more power than any validator has under this design.
3. **A halt that ends before the start time uses up notice.** A plan scheduled on day 0, a halt from day 2 to day 20, activation on day 21: nobody could start to unbond during the halt, and wallets showed the plan for three days in all. The decided rule cancels only when the activating block itself follows the gap. Recommended: also cancel a scheduled plan in any block dated more than one hour after its parent. It is one more line in step 2 of 5.3. **Decided: built so (5.3, step 2).**
4. **May a new network start above version 4?** Recommended, with the reviewer: not now.

## 18. What I am unsure of

- Whether 4/5 is reachable in practice with many validators is argued, not simulated.
- The laboratory values are guesses sized to the 60-second fade. *Since the run of section 19:* the notice is a minimum and a signal names its own start. The plan that activated was named 226 seconds ahead and scheduled 212 seconds before its start; the four restarts made during that notice took about 21 seconds in all. No restart may straddle the start time, since a laboratory plan that sees no block for 60 seconds after its start is cancelled.
- The stop race against real CometBFT (the node stops answering before the next proposal arrives) and the three restart cases are settled by reading only. They are the first laboratory test to run. *Since the run of section 19:* the stop held on a real network, at an activation (two validators of seven) and at a coordinated stop (all seven): no stopped node committed the next block, and CometBFT ended when its application was gone. Of the restart cases only the clean one ran (application and CometBFT both at `h`); a crash between the two commits did not.
- The emergency procedure rests on the handshake replaying a stored block `H + 1` into a new program (`consensus/replay.go:428`). Read, not run. *Still so:* no block of the run carried kind 81. *Since revision 5:* the engine's side of it is tested (a program that stopped at the switch block, started as the fix release on the same data, executes that block when it is handed over again). CometBFT's side is still read, not run: the harness mode `v5emergency` is written to run exactly this, and has not run. *Since 23 November 2026:* it ran, twice (`campaign/README.md`, "An emergency fix, rehearsed"). On seven laboratory validators, a program that stopped at the switch block was started as the fix release on the same data, was handed that block again by CometBFT, and signed 8 and 9 seconds later.
- The decision says the fix release "refuses to start when any store holds a block above `H`". Section 10 enforces that for CometBFT's store when the block is handed over, not at start, for the reasons given there. The lead and the reviewer should confirm that reading.
- Kind 81 on a proposal is rejected, not obeyed (6.3). The decision says "stop, do not execute"; I apply that to decided blocks only, so that one proposer cannot stop the network.
- *Since revision 5:* everything in section 20 that this document did not decide. The lead and a reviewer should confirm each reading there. None of it was reviewed independently.

## 19. The first run on a live network (2026-11-18)

One run of the AWS harness's upgrade rehearsal (`campaign/README.md`, mode `v5upgrade`; all 21 steps passed). Seven laboratory validators with equal voting power in two regions, CometBFT 0.38.26, engine 0.7.0 as the release build and as the rehearsal build of section 15. The harness starts the node and CometBFT directly, with a key file, and one script operated every validator. `v5/README.md` ("What ran on a network, and what did not", under "Upgrades" and under "State sync and pruning") has the detail; this section says what it means for this document.

**What section 14 asks for with real CometBFT.**

| Asked | Ran? |
|---|---|
| Header `h + 1` carries the new version | Yes. The first block dated at or after the start (0.019 s after it) was the last under version 4; the certified header of the next block carries version 5, and proven state says version 5 and no plan. |
| The stop race | Yes, as far as a run can show it. The two validators on the release build committed block `h`, saved its state, printed `STOPPED FOR UPGRADE` and ended with exit code 4, with their state at `h`. Their CometBFT ended within a second, with exit code 0. What each did between its commit and its exit was not recorded. |
| The three restart cases of section 4 | One. The stopped validators were started on the other build with application and CometBFT both at `h`, and were signing again after 7 and 9 seconds. No node crashed between its own commit and CometBFT's. |
| Two of four on the old program make the chain wait and resume | No. Two of seven stopped, less than a third: the chain went on, with one block that took 2.6 s instead of 0.3 s. A chain that waits has not run. |
| A stop at `H` by two of four | Not in that form. All seven were started with `--stop-after-height H`: each committed `H` and ended with exit code 4, none committed `H + 1`, all seven recounted the same root at `H`, and the chain continued from `H + 1` when they were started without the flag. A stop by a part of the validators has not run. |

**Also ran.** Signals on a live network: refused by a node whose program lacks the version (5.1), no plan at five of seven supporters and a plan at six, a plan kept at six and cancelled at five (5.3, 5.4), the plan's times equal to what the signals named and to the certified time of the scheduling block. Clients across the activation (section 8): one that knows version 4 failed closed with `UPGRADE_REQUIRED`; one made for the rehearsal read the new version from proven state and verified a payment. The stop height below the committed one (3.4): exit code 1, nothing changed. A node joining by state sync from a snapshot taken after the activation (section 4).

**Did not run.** The deployment kit (image, remote signer, leases, monitor); independent operators and the notice of 21 days; the production profile; a chain that waits for more than a third of the votes; a switch postponed by a safety hold; a plan cancelled for lateness or for a gap of an hour; kind 81 and the emergency procedure of section 10 beyond the stop at a height; a snapshot from before an activation, and a program refusing a snapshot of a version it lacks; a restart after a crash at the boundary.

**What the clients lack for a rehearsal.** A client knows versions by one constant of the compiled verifier and one frozen list of the SDK, and neither has a rehearsal counterpart of the engine's build feature. The harness made its "updated client" by changing those two in a copy. At the time of the run the SDK built no signal either (section 15 leaves the wallet screen for later), so the harness built and signed kind 80 itself.

## 20. The emergency path as built (22 November 2026)

Section 10 is built in the engine (`v5/src/rules.rs`, `upgrade.rs`, `engine.rs`, `app.rs`, `main.rs`) and tested there (`v5/tests/emergency.rs`, `emergency_node.rs`). `docs/emergency-fix.md` is the operator's procedure and `v5/README.md`, "The fix release and its switch", says what the engine does. This section says where this document was followed, where it was silent, and what was decided there. Every decision took the reading under which a node stops instead of going on.

**Built as section 10 says.**

- The fix release proposes exactly one transaction for block `H + 1`, the kind-81 switch of 3.1 for its version and specification hash, and as validator accepts only that block.
- The block ends with the new version and `upgrade/activated` with `"notice":"none"`, and removes any plan and all entries. A plan never activates in a switch block.
- The fix release does not execute a decided block `H + 1` that is not the switch block: it takes the stop path. It executes nothing on a head above `H` that is still at the old version.
- Programs that were not replaced stop at the decided switch block with their state at `H` (6.3, unchanged), and the fix release started on that data executes the block when it is handed over again.
- Later releases keep the switch: the engine's list of switches is part of what a program implements, and a test replays a chain across its switch with a later list.

**Where this document was silent, and what was decided.**

| Question | Decision | Why |
|---|---|---|
| Which chain does "a compiled-in switch after `H`" apply to? | A switch names one network by its network id. On any other network the program has no switch. | A release runs on more than one network (a test network, production), and `H` means nothing on another chain. Without the name, a production fix release would demand a switch block at height `H + 1` of every network it is started on. |
| "Refuses to start" on a head above `H` at the old version: how? | The node opens stopped and ends with exit code 4 before it serves, as on a head it does not implement (6.1), with the first line `STOPPED AT A SWITCH`. `--audit` refuses too, and such a snapshot is not installed. | It is the engine's existing way of not starting on a head it has no rules for. Exit code 1 was the other reading; code 4 says "on purpose, do not restart blindly", which is what an operator must hear. |
| Which first line for a decided block `H + 1` that is not the switch block? | `STOPPED AT A SWITCH`, like every stop about a switch; the line after it says which of the three cases it is. | 3.4 gives three first lines. A fourth would not be known to the kit and the harness, which route on that line. The second line carries the difference and what to start. |
| Does a validator safety hold postpone a switch, as it postpones a plan? | No. | A hold postpones a plan because support is counted without the jailed validators (5.2). A switch counts nothing. A hold that does not end must not keep a fix out. |
| What if the chain is not under version `N` at height `H`? | The fix release executes no block at `H + 1`: it rejects every proposal and stops at a decided block. | Its switch leads from the version before to its own. On any other history the program was built wrongly. |
| May the switch be admitted to a mempool? | Never. The proposer writes it itself. | Admission would let anybody queue it, and a mempool is not where a rule change belongs. |
| Fee, sender, nonce of the switch? | None: the unsigned envelope of 3.1, byte for byte, and nothing else in the block. The block changes no row that an empty block does not change, but for the version and its row. A test compares the two states row by row. | 3.1 gives the form; "exactly one transaction" is section 10. |

**Added: the agreed root.** Section 10 has validators stop at `H` and start a fix release. It does not say how an operator knows that the node starts on the state the others hold. `--expect-root H:ROOT` makes the node check it: it goes on from `H` only on the state with that root (3.4 gains this flag; it is not consensus data).

**Added: a block that was decided and could not be executed.** Section 10 assumes a height can be agreed before the fault stops the chain. A fault can instead make every node fail on a decided block: the engine fails closed when a decided block fails a check. No height can be agreed then, and the block is final. What was built:

- The node says where it stands before it ends: `FAILED ON A DECIDED BLOCK`, the block's height and hash, and the height and root of its state (exit code 1).
- A fix release may name that one block instead of a height: the network, the block's height and hash, and the root of the state before it. It executes that block with the transactions it was decided with, under the corrected rule, and ends it by writing the new version and the row with `"notice":"none"`, as a switch block does. It executes no other block at that height and that block on no other state.
- The version must change there. A program without the fix that can execute the block ends it under the old version and another root, and the next header cannot carry both: old and new cannot go on together unnoticed.

This is unsafe in one way that software cannot remove. Wallets take inclusion in a final block as execution (`verifier-v4/src/receipt.rs`). A fix that leaves a transaction of that block out would mislead them; a fix that must execute every transaction cannot neutralize a harmful one. The engine therefore executes all of them or none: one transaction that is invalid under the fix makes the repair fail, as it makes any block fail. `docs/emergency-fix.md`, section 9, says this to operators.

**Unsafe as written, and not built that way.** Nothing in section 10 was found unsafe. One thing around it is: the deployment kit's CometBFT configuration (`double_sign_check_height = 100`) makes a validator refuse to join consensus when its key signed one of the last 100 blocks. After a coordinated stop every validator did, and the chain makes no new blocks, so no validator started by the kit could resume. The kit is not changed here; `docs/emergency-fix.md`, section 10, lists it first among what is missing. *Since 23 November 2026:* the kit has a resume order for this one case (`deploy/README.md`, "A chain that stood"), which ran once on seven validators, by the test harness.

**Not built.** A real version 5 and a real fix release; the release tool and the kit for one (its version line, its leases); a signed announcement of a release; anything on the client side. **Not run.** All of it on a network: the harness mode `v5emergency` (`campaign/README.md`) is written for that and has not run. *Since 23 November 2026:* it ran twice, each time on two networks of seven laboratory validators, both cases, with a fix release built from the rehearsal program, not a real one (`campaign/README.md`, "An emergency fix, rehearsed"; `AUDIT-2026-11.md`, "Run on AWS and in a real browser (23 November 2026)"). **Not reviewed.** No independent reviewer has read the code or these decisions.
