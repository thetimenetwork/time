# Protocol version 4

The rules of protocol version 4 as the first production release executes them (engine `timecurrency-v5` 0.7.0). The SHA-256 of this file is the specification hash of version 4: `rules::SPEC_4` in `v5/src/rules.rs`, shown by a node in `/status.upgrade.implemented`. A later version has its own file, `spec/protocol-N.md`, and its own hash.

This file names every rule and says where it is defined to the byte. Where it is silent, the engine source at the release commit decides. Earlier programs also reported the number 4 (the protocol-4 engine in `v4/`, engines 0.5.0 and 0.6.0); their rules differ from these and they must never run on a network of this release.

## 1. What a version is

- The version is the decimal number in the metadata row, `meta.protocol_version`. It names the rules that execute the next block and is the `version.app` of the next block's header.
- A network starts at version 4. The number changes only at the end of an activating block (section 6).
- **A version never changes what an existing action kind or payload does.** New behaviour is a new kind, or a new field that is refused before its version. A version may stop accepting a kind; it never makes one do something else.
- A program holds a list of the versions it implements, contiguous from 4, each with its specification hash. It executes nothing, validates nothing and admits nothing on a state whose version is not in the list, or is in the list above 4 under another hash than the row `upgrade/activated/<version>` carries.

## 2. State

The state is a set of rows under a sparse Merkle tree (`v5/src/merkle.rs`, `v5/src/proof.rs`); its root is the application hash. Values are canonical JSON: keys sorted, no spaces, integers as decimal strings. The row namespaces: `meta`, `account/`, `name/`, `pubkey/`, `recovery/`, `unbond/`, `block/`, `block_time/`, `history/`, `pos/`, `bitcoin/`, `auction/`, `treasury/`, `registration/`, `security/`, `upgrade/`. No other row exists. The network id is the hash of the genesis (`v5/src/genesis.rs`, `Genesis::network_id`).

Genesis account ids are below 2^48. An account id is a 64-bit number; the 16 bits above bit 47 are reserved as a zone number and are zero on this chain.

## 3. A block

A block is executed on the committed state in this order (`v5/src/engine.rs`):

1. The height is the previous height plus one and the time advances.
2. Begin: the new time is added to the bank; the validators who signed the previous block are paid; a roster announced two blocks earlier takes effect; expired rows are cleaned; block history older than the unbonding delay is pruned, at most 64 heights per block.
3. The misbehavior consensus reports with the block is punished (`v5/src/pos_adapter.rs`, `misbehavior`).
4. The transactions, in order. One invalid transaction makes the block invalid. At most 20,000 transactions and 4 MiB.
5. End: the validators' part of the fees is recorded; roster changes are announced for the block after next; the upgrade step (section 6); totals are checked; the metadata row is written.

The supply rule holds after every block: bank, liquid balances, staked assets and the auction reserve add up to the chain time elapsed since genesis, in microseconds.

## 4. Actions

The envelope is `"TCDEVNET-ACTION-V1\0"` (19 bytes), network id (32), kind (1), from (8), nonce (8), authority epoch (8), public key (32), payload length (4), payload, signature (64); integers big-endian; the signature is Ed25519 over everything before it. `spec/action-v1.json` holds test vectors.

| Kinds | Rules | Defined in |
|---|---|---|
| 2, 3, 8 to 16 | The protocol-4 ledger: revealing a sponsored registration (2), payments (3), device keys (8, 9), merchant payments (10), guardian recovery (11 to 15), cancelling what is pending (16). Kinds 1 and 4 are refused. | `src/ledger/`, as applied by `v5/src/engine.rs` |
| 5 to 7, 17 to 21, 23, 24 | Staking: candidates, bonds, delegation, exits, evidence. | `pos/`, `v5/src/pos_adapter.rs` |
| 40, 41, 42 | Bitcoin headers, receipts, auction claims. Refused on a network that pays all new time to validators. | `bitcoin-bridge/`, `v5/src/bitcoin_adapter.rs`, `v5/src/auction.rs` |
| 44 | Sponsored registration of an account. | `registration/`, `v5/src/registration_adapter.rs` |
| 60 to 63 | Treasury governance. Refused on a network that pays all new time to validators. | `treasury/`, `v5/src/treasury_adapter.rs` |
| 70 to 77 | Account security: keys with roles, daily limit, freeze, root operations. | `v5/src/security.rs` |
| 80 | Upgrade signal (section 6). | `v5/src/upgrade.rs` |
| 81 | Reserved for a rule switch. Never accepted (section 7). | `v5/src/upgrade.rs` |

Every other kind is refused. An action costs the network's fee (1,000 microseconds unless the genesis sets a lower one), except kinds 40, 41 and 42 and the cases `v5/src/security.rs` names. During a validator safety hold only kinds 17, 18, 20, 40, 80 and the protective account actions (72, 73, 74, 76) are accepted.

Where these rules differ from the protocol-4 engine in `v4/`, the head of `v5/src/engine.rs` lists the differences. The genesis settings `fees_to_validators_ppm`, `fee_micros`, `all_new_time_to_validators` and `stake_handover` are part of the network id and are defined in `v5/src/genesis.rs` and `pos/src/lib.rs`.

## 5. What is not a rule

A node's clock check on proposals, its mempool admission, what its proposer leaves out of a block, state sync, snapshots, pruning, `/status` and the offline recount are not rules: they change no state root.

## 6. Changing the version

The owner account of a validator candidate that is not archived sends kind 80 with its next nonce, its current authority epoch and a key that may spend. The payload is one of exactly two byte strings:

- `{"activate_elapsed_micros":"D","spec":"H","version":"D"}`: support this plan. `D` is a decimal 64-bit number without leading zeros, `H` is 64 lowercase hexadecimal characters.
- `{}`: withdraw.

A signal is accepted only if: the version is the version in force plus one; the start time lies from the notice to the farthest start ahead of the block's time, or the three fields are those of the scheduled plan; it changes the candidate's entry; and the entry, if there is one, changed at least the interval ago. The table holds at most 256 entries, one per candidate.

| | Production profile | Laboratory profile |
|---|---|---|
| Support needed to schedule | at least 4/5 | same |
| Support needed to stay scheduled | at least 3/4 | same |
| Notice | 21 days | 120 seconds |
| Farthest start | 120 days | 1 hour |
| Interval between two changes of one candidate | 10 minutes | 1 second |
| Largest gap between a block and its parent that keeps a plan | 1 hour | 1 hour |
| Longest a plan may wait after its start time | 1 hour | 60 seconds |

All times are chain time in microseconds since genesis. A validator whose candidate is jailed is left out of the count altogether, until it has left the roster. The support of a plan in a roster is the voting power of the roster's validators that are not jailed, whose owner's entry names exactly that plan, and whose owner account is neither frozen nor in a recovery at the block's time, over the total power of the roster's validators that are not jailed, compared in 128-bit integers. A roster in which every validator is jailed supports nothing. Support is taken in the roster in force and in each roster already announced; the lowest counts.

At the end of every block on which the row `upgrade/state` exists or a signal was accepted:

1. Support entries are dropped whose owner is no longer a live candidate, whose version is not the version in force plus one, or whose start is closer than the notice and is not the scheduled plan's. A support entry dropped less than the interval after its last change is replaced by a withdrawn entry with the same change time. Withdrawn entries are dropped once the interval has passed.
2. A scheduled plan is removed if its support is below 3/4, or if the block is dated more than one hour after its parent.
3. For a plan still scheduled whose start time is at or before the block's time: if the block's time is more than the wait after the start time, the plan is removed. Otherwise, if a validator safety hold is on, nothing happens: the plan waits. Otherwise `meta.protocol_version` becomes its version, the row `upgrade/activated/<version>` is written, and the plan and all entries are removed.
4. If no plan is scheduled, no hold is on and the block did not activate, the plan with support of at least 4/5 and a start at least the notice after the block is recorded with the block's time.
5. The row is written, or removed if it holds neither a plan nor an entry.

Rows: `upgrade/state` is `{"plan":{"activate_elapsed_micros","scheduled_elapsed_micros","spec","version"},"signals":[…]}` with `plan` present only while one is scheduled and `signals` sorted by owner as a number; an entry is `{"activate_elapsed_micros","changed_elapsed_micros","owner","spec","version"}` or, withdrawn, `{"changed_elapsed_micros","owner"}`. `upgrade/activated/` followed by the version as 8 big-endian bytes is `{"elapsed_micros","height","notice","spec"}`: the time of the activating block, the height of the first block under the version, and `"scheduled"`.

The start time of a plan is "not before": the plan activates in the first block, dated from its start time to the wait after it, in which no validator safety hold is on, or not at all. The activating block is executed entirely under the old version. Nothing else changes at an activation: no row is migrated.

## 7. Kind 81

Kind 81 is told by the byte at offset 51 alone. No version this release implements accepts it: it is refused at admission, never proposed, and a proposal that carries it is rejected. A program does not execute a decided block that carries it; it stops with its state at the block before.
