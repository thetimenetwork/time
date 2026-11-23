# Optional settings of a network

`spec/protocol-4.md` gives the rules of a network whose genesis carries none of the settings below. This file says what each of them changes. Where it is silent, the engine source decides: `v5/src/genesis.rs`, `v5/src/names.rs`, `v5/src/security.rs`, `v5/src/service.rs`, `v5/src/engine.rs`.

**This file is not under the specification hash of version 4.** That hash (`rules::SPEC_4`) is the SHA-256 of `spec/protocol-4.md` alone, which does not name these four settings. Until one hash covers both files, a program is known to implement these settings by its release, not by the hash it reports.

## 1. What a setting is

- A setting is a field of the genesis application state (`v5/src/genesis.rs`, `Genesis`). The network id is the hash of that state, so a setting is part of the network id and cannot be changed after the first block.
- A setting is written only when it is set. A boolean setting is written as `true`; `false`, `null` and every other value are refused. A list is written only when it holds an entry. A network without a setting has the genesis bytes, the network id and the state roots it would have had before the setting existed.
- The fields are written after the protocol-4 fields, in this order: `fees_to_validators_ppm`, `fee_micros`, `all_new_time_to_validators`, `stake_handover`, `distinct_names`, `waits_survive_stops`, `protected_registration`, `protected_accounts`, `service_records`. A tool that builds a genesis writes them in that order, or it computes another network id than the node.
- The first four are named in `spec/protocol-4.md`, section 4. This file specifies the other five fields, which make four settings.
- A genesis with the production profile must carry `stake_handover`, `distinct_names`, `waits_survive_stops`, `protected_registration` and `service_records`. The node refuses any other production genesis at InitChain (`Genesis::validate_initial`). The laboratory profile takes every combination.

## 2. `distinct_names`: names that look alike

A new account name is refused if it looks like a name that exists.

**The skeleton of a name.** Two names look alike when they have the same skeleton. For a name of 2 to 15 bytes of `a-z`, `0-9` and `_`, in this order:

1. every `_` is removed;
2. every `0` becomes `o`, every `1` becomes `l`, every `w` becomes `vv`;
3. in one pass from left to right over the result, without overlap, `rn` becomes `m` and `vv` becomes `w`.

`spec/name-skeleton-vectors.json` holds test vectors.

**State.** One row per account: the key is `name_skeleton/` followed by the skeleton, the value is the account's name as a JSON string. The namespace `name_skeleton/` exists on a network with the setting and on no other.

**Rules.**

- Genesis: every genesis account gets its row. A genesis in which two names have one skeleton, or a name has the empty skeleton, is invalid.
- An action that creates an account (kind 2, and kind 45 of section 4) is refused if the skeleton of its name is empty or has a row. Otherwise the row is written with the account. The check comes after the rules of the action itself and reads the state as the block has changed it so far.
- A refusal changes nothing, like any refusal.

## 3. `waits_survive_stops`: waits that survive a stop

The waits and freezes of the account security rules (`spec/protocol-4.md`, kinds 70 to 77) do not run while the chain is stopped.

**The number.** The metadata row has one more field, written last: `stopped_micros`, a decimal string, the total of all stops so far in microseconds. It is `"0"` at genesis. The field exists on a network with the setting and on no other.

**A stop.** When a block is begun, before anything else reads the clock: let `gap` be the block's time minus its parent's time (for the first block, minus the genesis time). The part of `gap` above five minutes (300,000,000 microseconds) is a stop and is added to `stopped_micros`. Five minutes is the threshold of this clock alone, in both profiles. It is not the hour after which a scheduled upgrade plan is removed (`spec/protocol-4.md`, section 6), which stays an hour. (No network used the setting while its threshold was the upgrade rule's hour, so no state was recorded under that rule.)

**The active clock** of a block is its chain time since genesis minus `stopped_micros`. A block moves it by `gap`, and by five minutes at most. It never moves back. A chain that makes no block for more than five minutes (CometBFT makes empty blocks every second or so unless `create_empty_blocks` is off) has its waits run slower than real time.

**What is counted on the active clock.** Every moment a security row stores, and every comparison with one:

- `ready_elapsed_micros` of a waiting payment, of a waiting raise of the limit and of a waiting replacement of the keys;
- `expires_elapsed_micros` of a waiting replacement (its claim window);
- `frozen_until_elapsed_micros`, including the rule that a freeze is placed again only when half of it has passed;
- `allowance_elapsed_micros`: the daily allowance refills on the active clock;
- whether the owner account of a validator is frozen when upgrade signals are counted (`spec/protocol-4.md`, section 6).

The fields keep their names and their encoding. On a network with the setting they hold moments on the active clock.

**What stays on the chain's time.** Every date a key signs: `expires_elapsed_micros` in the payload of a freeze (kind 72) and of a root operation (kind 73), and the one hour in which approvals for a payment can be used. So do all rules outside account security: issuance, staking, unbonding, the stake hand-over, the notice of an upgrade, registration commitments, guardian recovery of accounts that have not adopted the security rules.

**The recount** adds up the stops among the block times the state holds (`block_time/`). While none has been cleaned up, the sum must equal `stopped_micros`; afterwards it must not exceed it.

## 4. `protected_registration`: accounts protected from their first block

A registration can carry the account's set of keys and its policy, and a genesis can list accounts that start with one.

### 4.1 Kind 45

The envelope is the one of every action. From is 2^64 - 1, nonce and authority epoch are zero, as for kind 2. The public key is the registration key, which signs. The payload is canonical JSON with exactly three fields:

`{"name":N,"salt":S,"security":{"keys":[{"proof":P,"public_key":K,"role":R},…],"policy":{"daily_limit_micros":D,"delay_seconds":D,"freeze_seconds":D,"threshold":D}}}`

`security` is the payload of kind 70. `N` is an account name, `S` and `K` are 32 bytes and `P` 64 bytes in lowercase hexadecimal, `R` is `signin`, `spend` or `recover`, `D` is a decimal string.

**The commitment.** The registration uses a paid commitment of the registration key (kind 44). The commitment must equal the SHA-256 of:

`"TCDEVNET-NAME-PROTECTED-V1\0"` ‖ network id (32) ‖ registration key (32) ‖ name ‖ one zero byte ‖ salt (32) ‖ SHA-256 of `security` as it stands in the payload (keys sorted, no spaces)

This is not the commitment of kind 2, which has another domain and no set of keys. A commitment is good for one of the two kinds, and for one name, one salt and one `security` object.

**The acceptance.** Every key of the set carries `proof`, its Ed25519 signature over:

`"TCDEVNET-REGISTER-KEY-V1\0"` ‖ network id (32) ‖ registration key (32) ‖ role (1 byte: 0 sign-in, 1 spend, 2 recovery) ‖ the key (32)

**The action is accepted only if**, in this order:

1. the network has the setting, and no validator safety hold is on;
2. the envelope is as above and the registration key's signature verifies;
3. the payload has exactly that form;
4. the name is a valid account name and no account has it;
5. no account has the registration key as its identity key;
6. the registration key has a paid commitment that has not expired and was made in an earlier block;
7. the commitment equals the bytes above;
8. the set and the policy pass the rules of kind 70: one to eight keys, sorted by key, each once, each in one role, at least one spend key; a threshold from two to the number of recovery keys; `delay_seconds` and `freeze_seconds` from the network's minimum recovery delay to 30 days; every key carries its acceptance;
9. on a network with `distinct_names`, the name does not look like a name that exists (section 2);
10. every acceptance verifies.

**Then:** the account is created with the next account id, the name, the registration key as its identity key, balance, nonce and authority epoch zero, and the keys of the set in their roles. Its security row is written with version 1, the policy, a full allowance counted from this block's clock of the waits (section 3), no freeze and nothing waiting. The name and identity-key indexes are written, and the name's skeleton row on a network with `distinct_names`. The commitment is removed. The account count and the next account id move on.

The action pays no fee. A refusal changes nothing: the commitment stays until it expires, and what the sponsor paid is not returned.

The registration key is not a key of the account unless the set lists it. Kind 2 stays valid on such a network and creates an account with one key that holds every power.

### 4.2 `protected_accounts`

A list in the genesis, allowed only with `protected_registration`, written after it (only `service_records` can follow it):

`[{"id":D,"keys":[{"public_key":K,"role":R},…],"policy":{"threshold":D,"daily_limit_micros":D,"delay_seconds":D,"freeze_seconds":D}},…]`

- The entries are sorted by `id`, each a genesis account, each once.
- Keys and policy pass the rules of point 8 above, without acceptances: a genesis is agreed on as a whole.
- Such an account starts with these keys in place of the one key the protocol-4 rules give it, with nonce and authority epoch zero, and with the security row of 4.1, its allowance counted from zero. Its identity key is the one the genesis gives the account.

## 5. `service_records`: facts kept for later rules

The state keeps facts about validators, stake and accounts from the first block. **No rule reads them**: they decide nothing, refuse nothing and move nothing. They are kept because a later rule (for instance one that gives a say only to validators with a long and clean history, or to stake that has been in place for months) could not measure the time before the records began.

**The setting.** `"service_records": true`, written last, after `protected_accounts`. Absent: none of the rows below exists, and a state that holds one is refused by the recount.

**Encoding.** Every row is canonical JSON, with the fields in the order given here and every number a decimal string. In keys, numbers are 8 bytes big-endian and a consensus key is its 32 bytes. A moment is `M = {"height":H,"time_micros":T}`: a block's height and its time as its `block_time/` row holds it (height 0 and the genesis time for genesis). A count is `C = {"in_set":N,"signed":N,"proposed":N,"omitted":N}`.

**The week.** Chain time since genesis divided by seven days (sixty seconds in the laboratory profile), rounded down.

### 5.1 Rows

| Key | Value |
|---|---|
| `service/account/` ‖ id | `M`: the block that created the account |
| `service/validator/` ‖ owner | `{"owner":O,"first":M,"since":M,"consensus_key":K,"registrations":N,"punishments":N,"total":C,"older":C,"weeks":[{"week":W,"in_set":N,"signed":N,"proposed":N,"omitted":N},…]}` |
| `service/key/` ‖ consensus key | `{"owner":O,"registered":M}`, with `,"punished":M` once the validator was punished under that key |
| `service/punishment/` ‖ owner ‖ height | `{"consensus_key":K,"cause":X,"offense_height":H,"time_micros":T}`, `X` one of `evidence`, `duplicate_vote`, `light_client_attack` |
| `service/tally` | `{"week":W,"blocks":N,"unattributed":N,"validators":[{"owner":O,"in_set":N,"signed":N,"proposed":N,"omitted":N},…]}`, the entries by owner |
| `service/weeks` | `{"weeks":[{"week":W,"blocks":N,"unattributed":N},…]}`, oldest first |
| `service/missed/` ‖ owner ‖ week | `{"proposers":[{"proposer":P,"blocks":N},…]}`, by proposer; `P` = 2^64 - 1 for a block that named no proposer of its set |
| `service/bond/` ‖ validator | `{"lots":[{"week":W,"amount":A},…]}`, oldest first: the validator's own bond, in microseconds |
| `service/delegation/` ‖ validator ‖ owner | the same, in shares of the validator's pool |

No other row has a key that starts with `service/`.

### 5.2 Rules

`KEPT = 53` weeks.

- **Genesis.** The tally of week 0 with nothing in it, an empty list of weeks, an account row for every genesis account (height 0), and for every starting validator a validator row (`first` = `since` = genesis, one registration) and a key row.
- **An account is created** (kind 2, kind 45): its account row, with the moment of the block.
- **A validator is registered** (kind 17) by owner `O` with key `K`: the key row of `K`; `O`'s validator row is written (`first` = `since` = this block, one registration, no punishment, zero counts, no weeks), or, if it exists, its `since`, `consensus_key` and `registrations` change and nothing else.
- **A validator is punished** (kind 20, or misbehavior CometBFT reports with the block): the punishment row, `punishments` of the owner's row grows by one, `punished` is set on the key row.
- **Every block** `h`, at the end of the staking part of its begin-block steps (after the reward and the roster), before its misbehavior and its transactions:
  1. If its week is later than the tally's, the week ends: each entry of the tally is added to its validator's row as one entry of `weeks` and to `total`; the entries of `weeks` older than `week - KEPT` move into `older`, and the missed row of each of them goes; the week joins the list of weeks if it counted a block; weeks older than `week - KEPT` leave the list; the tally starts the new week, empty.
  2. If `h >= 2`: the tally counts one block. For each validator of the set that was to sign block `h - 1`: `in_set` grows by one, and `signed` too if the block's commit carries its signature as the reward rule reads it; if not, its missed row of this week counts one block for the proposer. The proposer is the validator of block `h`'s own set whose consensus address the block's header names (ABCI `proposer_address`): its `proposed` grows by one and its `omitted` by the number of signatures left out. A block that names no validator of that set counts in `unattributed`. (CometBFT 0.38 checks only that the header names a validator of the set, not that it names the validator that proposed the block: the proposer a record names is the proposer's own word.)
- **Stake.** Whenever a validator's own bond or the shares of a position change, its lots change: what comes in joins the lot of the current week; what goes out leaves from the newest lot first; then every lot older than `week - KEPT` is merged into one, which keeps the week of the newest of them. A position at zero has no row.

### 5.3 The recount

On a network with the setting the recount (`--audit`) requires: one account row per account, dated in the order of the ids, each at its block's time where that time is still in the state; for every validator row, `older` plus its weeks is `total`, its keys are the keys its owner reserved and number `registrations`, its punishment rows number `punishments`, and every candidate has a row with its present key; one punishment row for every row the staking rules leave when they punish (`pos/evidence/`, `pos/misbehavior/`), and one on every jailed validator's key; for every kept week, the blocks its validators proposed plus `unattributed` are its blocks, and the missed rows of the week, summed by proposer, are each proposer's `omitted`; one missed row for each week of a validator that missed a block, summing to what it missed; for every week whose blocks the state still holds (fourteen days), the number of blocks and each validator's `in_set`, counted again from the block times and the rosters; the lots of every own bond and every position adding up to it. On a network without the setting, no row under `service/`.

## 6. What this adds to `spec/protocol-4.md`

- Section 2 of that file lists the row namespaces and says that no other row exists. With `distinct_names` there is one more, `name_skeleton/`. With `waits_survive_stops` the metadata row has one more field. With `service_records` there is one more, `service/` (section 5.1).
- Section 4 says that every other kind is refused. With `protected_registration`, kind 45 is accepted. Without it, kind 45 is refused like any unknown kind.
- Section 4 lists four genesis settings. There are five more fields, listed in section 1 above.
- Section 6 judges whether an owner account is frozen "at the block's time". With `waits_survive_stops` that is the block's active clock.
- The header of a block names its proposer. Under protocol 4 no rule reads it. With `service_records` the records count it (section 5.2), and still no rule reads it.
