# A controller that issues signer leases

Revision 1 was written before the code, against the kit at commit `c9df2a4`: `deploy/operator.mjs` (the guard), `deploy/lib.mjs` (the attestation format), `deploy/compose.v5.yaml` and `deploy/README.md`. Line numbers of the guard in this document are those of that commit. Section 16 lists what is not verified.

Revision 2 brings the document in line with what was built. Three things changed while building. A tenure that the start rule begins takes its fence token from the clock plus five minutes, not from the clock: the random schedules of section 15 need it for claim S2 when a replacement controller's clock is behind the old one's (5.3, 5.4). The command for a token floor is `refence KEY --above N` (5.4, 6). And the change to the guard that section 14 proposed is made and tested. Sections 15 and 16 now say what the tests did and did not do.

Revision 3 follows an independent review; its tests are `deploy/lease-controller/review-*.test.mjs`. What changed: the clock at a start is no longer trusted blindly (5.5); a key that enters the state waits, and takes its token, from the command that brings it in (5.3, 5.4); a recorded request can no longer freeze a key, and a lease says until when it is sent again (8.1, 8.2); a state file names the one it was made from, and a running service follows only its own line (5.2); the guard's rule is "run until the expiry of the last lease that verified", with one stated bound (14); sentences that claimed more than the code gives are cut or carry their conditions.

Revision 4 follows the second review; its tests are `review2-*.test.mjs`. What changed: a start judges which tenures still run by the expiry of a lease that was issued, never by a cover (5.3); `clock-was-ahead` keeps such tenures (5.5); the nonce of an earlier request is refused once a later one was served (8.1); the guard counts a lease on the monotonic clock as well as on the wall clock, and looks at once when it starts a child (14.1); a service removes old state files only behind what it holds (3.6); four sentences in 5.2, 9, 10.1 and 14.1 said more than is true and are corrected.

The kit refuses to run a validator without a fresh **signer lease**, and nothing in the repository issues one. This document specifies a reference **controller** that an operating organization runs on its own host, the **agent** that keeps the lease file fresh on each validator host, and an operator command line. **Section 3 is the one place for every number, field and name.**

## 1. The design in ten lines

1. Every consensus key has at most one **holder**: one validator host, named in the controller's stored state. Only the holder is given leases for the key.
2. The holder changes only by an operator's command. The new holder gets its first lease only after the last lease of the old holder has run out on every clock, plus a margin for the old validator to stop.
3. Every change of holder gives the key a new, higher **fence token**. Tokens are taken from the clock, so a controller that lost its state cannot issue a token it issued before.
4. The controller writes and syncs its state before a lease leaves. State files are numbered and never overwritten; two writers cannot both write number `n + 1`.
5. After every start the controller assumes that an earlier controller process, whose state it may not have, issued leases up to the moment it stopped. Keys whose lease is still running go on with the same holder. Every other key waits five minutes plus the margin.
6. A host asks with a request signed by its own key. The request is fresh for a few seconds and names the last lease the host holds, so that a copy of a host is noticed and the key is frozen.
7. A lease is issued only for the network, the engine and a release the operator approved, and only to the signer identity registered for the host.
8. The agent checks every lease with the kit's own guard before it writes it, and writes it by renaming a finished file.
9. If the controller cannot be reached, the validator stops when its lease runs out, about four minutes later. Nothing fails over automatically.
10. **A lease is checked by the guard every five seconds. It is not checked by the signer.** The controller does not stop two signers that hold the same key from signing. Section 10 says what remains.

## 2. Words used

- **Guard**: `guard()` in `deploy/operator.mjs`. It runs before the node and CometBFT start and every five seconds after.
- **Lease**: a signed attestation of kind `signer_lease` (`deploy/README.md`, "Mandatory remote signer boundary").
- **Authority**: the Ed25519 key that signs leases. A host's trust file pins it with the role `signer_lease`.
- **Host**: one validator machine, known to the controller by a host id and a host key.
- **Holder** of a consensus key: the host the stored state names for it.
- **Tenure**: one holder with one fence token. A new tenure starts whenever the holder changes, when a key is unfrozen, when the operator asks for a new token, and for some keys at a controller start (section 5.3).
- **True time**: the time of a correct clock. `C` is the controller's clock, `H` a host's clock.
- **Live**: a lease is live on a host while the guard there would accept its dates: `issued_utc ≤ H < expires_utc`.

## 3. Numbers, fields and names

### 3.1 What the guard does with time (read from the code)

- It accepts a lease while `issued_utc ≤ now < expires_utc` on the host's own clock (`deploy/lib.mjs:18`). **It has no tolerance in either direction.** A lease dated one millisecond ahead of the host's clock is refused.
- `expires_utc − issued_utc` must be at most 300,000 ms (`deploy/operator.mjs:24`).
- It runs every 5,000 ms (`deploy/operator.mjs:195`). It reads the settings' files again each time, the trust file included.
- At commit `c9df2a4` a failed check sent `SIGTERM` to its one child, once, and did nothing else. Section 10.2 says what that left open. Section 14 is the rule now.

### 3.2 Settings of the controller

| Name | Default | Allowed | Meaning |
|---|---|---|---|
| `lease_seconds` (`L`) | 240 | 60 to 280 | From the controller's clock at issue to `expires_utc`. |
| `clock_skew_seconds` (`σ`) | 10 | 1 to 20 | Every clock that takes part is within `σ/2` of true time. Any two then differ by at most `σ`. |
| `stop_seconds` | 40 | 30 to 600 | How long after its lease ended a validator may still ask its signer for signatures. |

Derived, not settable:

| Name | Value | With the defaults |
|---|---|---|
| Back-dating: `issued_utc = C − 2σ` | `2σ` | 20 s |
| **Margin** `m` | `2σ + stop_seconds` | 60 s |
| Longest life of any lease after its issue | 300 s (the guard's limit) | 300 s |
| **Start wait** | `300 s + m` | 360 s |
| A request is fresh while | `−σ ≤ C − time_ms ≤ 2σ` | −10 s to +20 s |
| Least time between two new leases for one key | `3σ + 1 s` | 31 s |

The config is refused unless `L + 2σ ≤ 300` and `4 × (3σ + 1) ≤ L`.

### 3.3 The lease the controller signs

The kit's format, unchanged: `{issuer, payload, signature}`, signed over `TIME-OPERATOR-ATTESTATION-V1`, a zero byte and the canonical JSON of `payload`. The payload:

| Field | Value |
|---|---|
| `kind` | `"signer_lease"` |
| `release_id`, `genesis_sha256`, `chain_id`, `validator_public_key_hex` | As the request names them, after the checks of section 7. |
| `signer_identity` | The one registered for the host. |
| `engine` | `"v5"` on a v5 network. Absent on a v4 network. |
| `fence_domain` | The controller's, from its config. |
| `fence_token` | The tenure's, a decimal string. |
| `lease_id` | 32 hexadecimal characters, random. |
| `enforcement` | `"EVERY_SIGNATURE"`. Section 10.3 says on what basis. |
| `issued_utc`, `expires_utc` | `C − 2σ` and `C + L`, in milliseconds. |
| `host_id` | The host it was issued to. New. |
| `request_nonce` | The nonce of the request it answers. New. |
| `renew_by_utc` | `C + L − 2σ`. Until then the controller sends this lease again for the same request; after it a new lease takes its place (8.1). New. |
| `enforcement_basis` | `"OPERATOR_DECLARATION"`. New. |

The guard reads only the fields it knows, so the four new fields change nothing for it. The agent checks `host_id`, `request_nonce` and `renew_by_utc`.

### 3.4 The request a host signs

`POST /v1/lease`, at most 16 KiB:

```
{"host_id":"…","payload":{…},"signature":"…"}
payload: {"kind":"lease_request","version":1,"host_id":"…","time_ms":N,"nonce":"32 hex","previous_lease_id":"…",
          "release_id":"H","genesis_sha256":"H","chain_id":"…","validator_public_key_hex":"H","signer_identity":"…","engine":"v5"}
```

- `signature` is Ed25519 by the host key over `TIME-LEASE-REQUEST-V1`, a zero byte and the canonical JSON of `payload`. The prefix differs from the attestation prefix, so a host key can never sign something that reads as an attestation.
- `time_ms` is the host's clock. `previous_lease_id` is the `lease_id` in the host's lease file, or `""`. `engine` is left out on a v4 release.
- The answer is `{"status":"granted","lease":{…}}` or `{"status":"refused","code":"…","message":"…","retry_after_ms":N}`. A refusal is not signed.

### 3.5 Refusals

Each message says what to do. The codes: `BAD_REQUEST`, `UNKNOWN_HOST`, `BAD_SIGNATURE`, `CLOCK`, `WRONG_NETWORK`, `WRONG_ENGINE`, `RELEASE_NOT_APPROVED`, `RELEASE_ROLLBACK`, `KEY_NOT_ASSIGNED`, `NOT_HOLDER`, `HOST_KEY_CHANGED`, `SIGNER_MISMATCH`, `SIGNER_NOT_DECLARED`, `WAIT`, `TOO_SOON`, `FROZEN`, `BUSY`.

### 3.6 Files

- `DATA/state/state-NNNNNNNNNNNNNNNNNNNN.json`: the state, one file per change, twenty digits. Each holds its number, the checksum of its state, and the checksum of the state it was made from. A service removes the files that lie more than 32 behind the one it holds. The command line removes none: it cannot know how far a running service has followed.
- `DATA/controller.lock`: one service per directory.
- Key files hold `{schema_version, purpose, id, public_key_hex, secret_hex}`, mode 0600. `purpose` is `signer-lease-authority` or `signer-lease-host`.
- On a validator host: the lease file the settings name, and `lease-agent-state.json` beside the agent's key.

## 4. The safety property

**Claim S1.** Take one consensus key and one fence domain. Let two leases for it be issued to two different hosts. Then the two are never live at the same moment. More: the later one is first live at least `stop_seconds` of true time after the earlier one was last live.

**Claim S2.** For one key, a lease issued to a different host than the lease before it carries a strictly higher fence token, and tokens never go down in the order of issue.

**Assumptions.** The claims are made under these, and under nothing else.

- **A1, clocks.** At every moment the clock of each controller process and of each validator host is within `σ/2` of true time. The clocks are not required to agree more closely or to be free of steps inside that bound. Section 5.5 says what the controller checks about its own clock, and what stays an assumption.
- **A2, one controller at a time.** All processes that sign with one authority key use one state directory, or an earlier one has stopped for good before a later one starts. The controller cannot check this across machines.
- **A3.** The authority key and the host keys are not stolen.
- **A4.** The state directory is on a file system where a hard link is atomic and `fsync` holds what it says.
- **A5, a host is one machine.** Two machines with the same host key are one host to the controller. Section 8.4 says how a copy is noticed and what is bounded. The claims are about leases the controller issues. One lease file copied to a second machine together with the settings is accepted by the guard there: the guard does not know which machine it runs on (7, point 6).

**What is covered inside the assumptions:** a controller crash at any point, a restart, a restart from an older copy of the state or from no state, a host that is cut off, a request that is repeated or replayed, a command given at a bad moment, and a config edited by mistake.

**Why S1 holds.** Three rules of the controller carry it.

1. *A lease goes only to the holder, and not before the tenure's `not_before`.*
2. *A new tenure sets `not_before = last_expires + m`*, where `last_expires` is the latest `expires_utc` of any lease issued for the key. It is in the state, and the state is synced before a lease leaves (section 5).
3. *The start rule* (section 5.3) makes `last_expires` cover leases of a process whose state is lost.

Let lease 1 go to host `a` with expiry `E`, and let a later tenure give the key to host `b`. Host `a` finds lease 1 live only while `H_a < E`, so only at true times before `E + σ/2`. The controller issues to `b` when `C ≥ E + m`, so at a true time of at least `E + m − σ/2`. The distance is at least `m − σ = σ + stop_seconds`. The extra `σ` is slack.

**What the back-dating is for.** A host whose clock is behind the controller's would find a lease dated at `C` to be in the future, and the guard has no tolerance. Dating it `2σ` back makes it live at once on any host inside A1, and on any host whose request passed the freshness check.

**The freshness check is a tripwire, not the assumption.** The controller compares its clock when a request arrives with the time the host wrote in it, and refuses a time more than `σ` ahead or more than `2σ` behind. The time the request travelled counts as being behind. It works both ways: a controller whose own clock is wrong refuses every host with a right clock, and so issues nothing.

## 5. State and durability

### 5.1 What is stored

One JSON document:

- `network`: `chain_id`, `genesis_sha256`, `engine`. Written when the state is created, by the first start or the first command, and never changed. A config that names another network or engine is refused.
- `fence_domain`: likewise.
- `releases`: the approved releases, each `{release_id, engine, order}`.
- `floor_ms`: 300 s after the latest start.
- `clock_ms`: the latest clock reading of any process that wrote this line of states (5.5).
- Per consensus key:
  - `holder`: `{host_id, public_key_hex}`, or null. The host's key is stored, so a host key replaced in the config is another holder.
  - `fence_token`, `not_before_ms`, `tenure_leases` (how many leases this tenure has had).
  - `last_expires_ms`: the latest expiry any lease for the key can have, known to this state or not; it is raised at every start. `issued_expires_ms`: the latest expiry of a lease this line of states really issued. `last_grant_ms`. `last_request_ms`: the date of the last request that got a new lease.
  - `lease`, `lease_id`, `previous_lease_id`, `request_nonce`: the last lease issued and the request that got it. `replaced_lease_ids`: leases replaced in place for that same request (8.1). `served_nonces`: the nonces of the last eight requests that got a new lease (8.1).
  - `release_id`, `release_order`: the release of the last lease.
  - `frozen`: null, or when and why.

### 5.2 Written before a lease leaves

A change is written to a temporary file, synced, and hard-linked to the name with the next number. The link fails if that number exists. The directory is then synced. Only after that is a lease sent.

- A crash before the link: nothing was issued.
- A crash after the link and before the answer: the state says a lease was issued that no host has. `last_expires` already covers it. The host asks again with the same nonce and gets that same lease.
- The reverse order, an answer before the write, does not exist in the code: the function that builds the answer returns it only together with the state to write, and the service sends it only after the write returned.
- Two processes on one directory (the service and the command line, or two services by mistake) cannot both write number `n + 1`. The loser reads the newer state and decides again. This, not the lock, is what keeps them consistent. The lock only refuses a second service early.
- **A running service follows only its own line of files.** Every file names the checksum of the state it was made from. Before every request the service reads the newest file. It must be the file the service holds, or descend from it file by file; those are the command line's writes. A newest file that is older, another file under the same number, a gap, or a file that names another parent means that files were put into the directory under the service. No start rule was applied to them. The service stops, saying so, and answers nothing more; the next start applies the rule.
- A newest file that cannot be read or fails its checksum is never skipped: nothing falls back to an older file by itself. A start is refused with a message. A service that already runs stays alive and answers every request with an error (`BUSY`) until the file can be read, or an operator has moved it away and started the service again.

### 5.3 The start rule

At a start at controller time `s` the controller cannot know whether its state is the newest that ever existed. An older copy may have been restored, or the state may be empty because it was lost. So it assumes that some other process issued leases until just before `s`. None of those can be live more than 300 s after `s`, whatever that process's settings were, because the guard accepts no longer lease.

For every key, at start:

1. If a lease that was really issued for the key is still running (`s < issued_expires_ms`) and its tenure has had a lease: **the tenure goes on.** The holder can renew at once.
2. Otherwise: **a new tenure for the same holder**, with a new token taken from `s + 300 s`, and `not_before = s + 300 s + m`. "Otherwise" includes a tenure that has had no lease yet: a command given on an old state computed its wait from an expiry that may be too early.
3. In both cases `last_expires_ms` is raised to at least `s + 300 s`, so that a later change of holder waits for leases this state does not know.

`floor_ms` is set to `s + 300 s`. All this is written before the service listens.

**A key that enters the state**, by `assign`, is covered the same way, counted from the command: `last_expires = max(floor_ms, command clock + 300 s)`. Its first lease comes `300 s + m` after the command. The floor of the last start is not relied on alone: the clock at that start may have been wrong (5.5).

**Why case 1 is safe when the state is old.** Call the first lease of a tenure a *hand-over*. A process makes a hand-over no earlier than `300 s + m` after its own start, and no earlier than `m` after the latest expiry it knows (rule 2 and point 3). Take the last hand-over before `s`: to host `h`, at time `t`.

- A state that does not record this hand-over was written before it, by the same process or by an earlier one. Its `last_expires` for the key is a real expiry, or a start plus 300 s. Both lie at least `m` before `t`, less at most one `σ` when two machines' clocks are compared.
- `stop_seconds` is always more than `σ` (at least 30 against at most 20). So at any start after `t`, such a state is past its `last_expires`: case 2 applies to it, not case 1.
- So a state in which the key's lease still runs at `s` records the last hand-over. It names `h`, and going on with `h` conflicts with nobody.

The test for "still running" is on `issued_expires_ms`, a date taken from a lease that was issued. It is never on `last_expires_ms`: that is a cover, which a start on a clock that is ahead writes too high and which `clock-was-ahead` lowers, so it says nothing about what runs. Revision 3 tested the cover, and the second review showed two ways from there to two live leases, both with a clock outside A1 (its tests `FINDING (outside A1)`). This argument is not a formal proof. Section 15 attacks it with restores of arbitrary older states.

**What a start costs.** After an ordinary restart, hosts with a running lease notice nothing. After an outage longer than a lease, every key waits 360 s from the start. The first start of a new controller waits the same 360 s: an empty state with an existing authority key looks exactly like a lost state. A start while a key waits begins that key's wait again, so a controller that is restarted every few minutes never issues a first lease.

### 5.4 Lost or restored state

- **The lease-level claims hold without any action**, by the start rule, as long as A2 holds: the old controller must be stopped for good.
- **Fence tokens.** A tenure started by a command takes `max(previous token + 1, C in milliseconds)`. A tenure started by the start rule takes `max(previous token + 1, s + 300 s)`. A key that enters the state takes `max(command clock + 300 s, floor_ms)`: the state knows no token for it, exactly as at a start. So a token in a lease is never above the clock at its issue, except by the few milliseconds that several changes in one millisecond add. A controller whose state is old or gone cannot know which tokens were issued since. It takes its clock plus five minutes, and under A1 that is above the clock of any earlier controller at any earlier moment, with 290 s to spare. The clock alone would not do: the old controller's clock may be up to `σ` ahead of the new one's, and it may have given a key away seconds before it stopped. **If the operator cannot vouch for the old controller's clock**, they give a floor: `refence KEY --above N` starts a tenure with a token above `N`. The last lease file of each validator host shows the token it held.
- **What the operator sees after a restore.** A host that renewed after the copy was taken names a lease the restored state does not know. That is exactly what a copied host looks like, so the key is frozen. The operator checks that each host is one machine and runs `unfreeze`. Commands given after the copy was taken (a move, an approval) are gone and must be given again. `list` shows the state.
- **An empty state** knows no key. Every key must be assigned again and then waits.

### 5.5 The clock

Every wait is counted on the controller's clock, and A1 says that clock is right. A clock is most likely to be wrong on a machine that has just booted, which is when a lost controller is replaced. Three things are therefore checked.

1. **A state from a later clock.** Every state records the latest clock reading of any process that wrote it (`clock_ms`). A start, and every command, refuses a state whose `clock_ms` is more than `σ` later than the clock. One of the two readings is wrong, and the refusal says what to do first: check this machine's clock. This catches a machine whose clock is behind, when a state exists, and a state written while the clock was ahead.
2. **A clock set under the running service.** At its start the service notes its wall clock and a monotonic clock, which only counts elapsed time. Every second, and before every answer, it compares how far each has moved. If they differ by more than `σ`, the wall clock was set, or the machine was suspended. The service stops, saying why, and answers nothing more. Its supervisor starts it again, and the start rule counts every wait on the corrected clock. So a service started while its clock was behind does not keep the waits it counted from that clock. And what a start decides, the next start decides again on the corrected clock: which tenures still run is judged by the expiry of a lease that was issued, not by anything the wrong start wrote (5.3). A controller machine resumed from a snapshot stops the same way when its clock is set.
3. **A key that enters the state** waits from the clock of the command that brings it in (5.3), not from the clock at the last start.

**The way out when the clock was ahead.** A state written while the clock was ahead holds covers and waits counted from that clock, and check 1 refuses it once the clock is right. Waiting them out can take as long as the clock was ahead. `clock-was-ahead` is the command for it, to be given after the operator has checked the clock. For every key it sets `last_expires = max(issued_expires_ms, now + 300 s)` and brings the dates of the last grant and the last request back to the clock. A tenure whose issued lease still runs goes on, with its holder and its token. Every other tenure starts anew, with `not_before = last_expires + m` and a higher token. Why this is safe:

- It writes what a start on the checked clock writes (5.3), with one difference: it sets the covers instead of only raising them. The covers it lowers were computed, from the wrong clock, for leases the state could not know; it computes the same covers from the checked clock.
- A tenure it keeps is one a start on the checked clock would keep, for the same reason: its holder holds a lease that was issued and has not ended.
- It never goes below `issued_expires_ms`, the latest expiry of a lease this line of states really issued. If hosts' clocks were ahead too and a lease went out with dates from the wrong clock, that key waits until the lease has ended, and the command says so.
- Tokens only rise.
- It is refused when the state holds no time later than the clock.

It trusts one thing: the operator's check of the clock. Nothing in the controller can replace that check.

**A small error heals by waiting, and that is the better way.** Once the clock has passed the state's last stamp less one skew, a start is accepted and nothing was changed. After a clock that was one minute ahead for a few seconds that takes under a minute, and every running lease goes on. The command is for an error too large to wait out.

**What remains outside A1 after this.**

- **One bad time source for all.** A controller whose clock is wrong and stays wrong, with hosts whose clocks are wrong the same way, issues leases with wrong dates, and nothing here notices. When the clocks are corrected, such a lease can become live again later. If the state survives, the lease is recorded and waited for. If the state is lost as well, nothing covers it.
- **A clock corrected by slewing.** A clock that is brought back slowly is not seen by check 2: both clocks follow the slew. While it is off by more than the window of section 3.2, hosts with right clocks are refused and nothing is issued. Slewing ten seconds takes hours.
- **An empty state on a machine with a wrong clock.** Check 1 has nothing to compare. Check 2 stops the service when the clock is corrected, and until then hosts with right clocks are refused.
- **A command between a clock step and the service's stop.** The command line has no monotonic clock. A command given in that second may compute a wait from the stepped clock. The service stops before it answers anything, and the start rule replaces that wait.
- **A host's clock set back after it got a lease** (10.1).
- **A platform whose monotonic clock jumps with the wall clock.** None is known. The check was run with Node's `performance.now()` on one machine.

## 6. Giving a key to a host, and moving it

- `assign KEY HOST` when the key has no holder. `move KEY NEW --from OLD` when it has one; the command is refused if `OLD` is not the holder, so that the operator says what they believe. `unassign KEY` removes the holder.
- Each starts a new tenure: the old holder is refused from that moment, the token rises, and `not_before = last_expires + m`. With the defaults a move completes at most `L + m` = 300 s after the old host's last renewal, or 360 s after the controller's last start if that is later (5.3, point 3).
- There is no way to shorten the wait, and no way to undo a move without a second wait.
- `refence KEY` starts a new tenure for the same holder: a new token after a signer was restored (`deploy/README.md`, "acquire a NEW fencing token"). `--above N` names a token it must pass. A floor more than a hundred years ahead of the clock is refused: a token is a clock reading, and a key whose token reached the largest number could never get a new tenure. Such a key does not keep the controller from starting; it is frozen.
- A host holds one key. `assign` and `move` refuse a host that holds another.
- The commands change the numbered state files directly, beside the running service (5.2). Nothing listens for them.

**No automatic failover.** The controller cannot tell a dead host from one it cannot reach. More to the point, a failover needs a second host that already holds the key in a signer, and that is the arrangement most likely to sign twice when an assumption fails. A missing validator costs the network little: blocks need two thirds. A double signature is punished and can help finalize conflicting blocks. So a person decides, after checking that the old host is stopped and after moving the signer's state (section 10.1).

## 7. What a lease is bound to

A request is refused unless all of these hold.

1. **The chain and the genesis** are the ones in the state (`WRONG_NETWORK`).
2. **The engine** the request names is the network's (`WRONG_ENGINE`). The engine is declared in the config at the first start and stored with the genesis hash. This is the refusal the kit asks for: the guard cannot tell a v4 genesis from a v5 one, so the controller must never sign a v5 lease for a v4 network. A state bound to one engine never signs for the other.
3. **The release** is approved (`RELEASE_NOT_APPROVED`). `approve-release MANIFEST` reads the release manifest, checks it with the kit's `validateRelease`, and refuses a release whose engine is not the network's.
4. **One release at a time per key, forward only.** Approved releases are ordered by approval. A key that has had a lease for a release is refused an earlier one (`RELEASE_ROLLBACK`). For an upgrade the operator approves the next release; each host then installs it, changes its settings, and its agent asks for the new release; from that lease on the key cannot go back. Going back needs `approve-release MANIFEST --again`, which approves it anew. `retire-release ID` ends an approval and is refused while a key still runs it.
5. **The key** has a holder, and it is this host with this host key (`KEY_NOT_ASSIGNED`, `NOT_HOLDER`, `HOST_KEY_CHANGED`).
6. **The signer identity** is the one registered for the host (`SIGNER_MISMATCH`). No two hosts may register the same one. A lease copied to another host is then refused by that host's guard, unless its settings were copied too.
7. **The declaration of section 10.3** is in the config for the host (`SIGNER_NOT_DECLARED`).
8. The key is not frozen, the tenure may start (`WAIT`), and the last new lease is at least `3σ + 1 s` old (`TOO_SOON`).

## 8. How a host asks

### 8.1 Authentication, freshness, replay

- Each host has its own Ed25519 key, made on the host. The controller's config lists `{id, public_key_hex, signer_identity, signer_fencing}` per host.
- A request is accepted only with a valid signature of the registered key and a `time_ms` inside the window of section 3.2.
- **A recording sent again changes nothing that the host's own request would not change.** A request dated at or before the last request that got a new lease for the key is refused (`CLOCK`). A later one can only be a repeat of the request that is open: it carries the open request's nonce and gets the stored lease, or, in the last `2σ` of that lease, a new one in its place. 
- **The nonce of an earlier request that got a lease** is refused once a later request has been served, whatever its date. A host's clock may be set back inside A1, so that a recording carries a later date than the request that was served after it (the second review's test `FINDING (inside A1)`); the date alone does not show a recording. The controller remembers the nonces of the last eight requests that got a new lease for the key.
- **So, inside A1, and as long as the host has not lost its lease file or its agent state, a recording never freezes a key.** Every request such a host signs carries the open request's nonce or one that was served. A second machine draws a nonce the controller has never served, and is caught (8.4). What remains is a host that lost its agent state between two requests, and that loss is itself a cause for a freeze.
- The first form of this rule relied on the spacing of new leases and was wrong: a host's repeats of one request carry fresh dates, so a recorded repeat could arrive, still fresh, after the next lease, and freeze the key. The reviewer's test `FINDING replay` is that case.
- **A lease replaced in place stays a good answer** to "which lease do you hold": the host may have installed it before its replacement was issued. The controller remembers the ids of leases it replaced for the open request.

### 8.2 Transport

Plain HTTP, by default. Nothing in the protocol rests on the channel: requests are signed, leases are signed, and a lease names the nonce of the request it answers. Someone on the network path

- **can** read which host asks for which key and release, and read the leases;
- **can** drop or delay traffic, and so stop validators when their leases run out. TLS would not prevent that;
- **can** forge a refusal, since refusals are not signed. The agent logs a refusal as the controller's unverified word and acts on none of it except to wait;
- **cannot** obtain a lease for another holder or change one;
- **cannot** make the agent install a lease that answers another request (the nonce does not match), and can make it install an earlier lease for the same request only in a window of at most `σ`: a lease says until when it is sent again (`renew_by_utc`), and the agent installs none that is past that time on its own clock. If the host's clock is behind, the agent may install a lease the controller has just replaced; the controller accepts its id, so the key is not frozen and the host's next request is served;
- gains nothing from a lease it read: a lease lets the kit's guard pass on a host that already has the key in a signer. It signs nothing.

Run the service on a private link (a VPN or a private network between the controller and its hosts) and let the firewall admit only the validator hosts. The agent takes an `https://` address; a TLS proxy in front of the controller then hides the traffic. The agent refuses plain `http://` to another machine unless its config says `"allow_plain_http": true`. The service itself does not speak TLS: Node's standard library cannot make a certificate, so it could not be tested here.

### 8.3 The agent

One process per validator host, outside the containers. It needs to write one directory, the lease file's; a directory of its own for the lease keeps the trust file out of the agent's reach. Each round:

1. It reads the operator settings and the release manifest, and asks for exactly what they name.
2. It keeps one nonce per `previous_lease_id` in its state file, written and synced before the request is sent. A request repeated after a lost answer carries the same nonce.
3. It writes the three signed parts of the answer, and nothing else of it, to a temporary file beside the lease file, with mode 0644 whatever the umask, and runs **the kit's `guard()`** on the settings with that file as the lease. Nothing in the answer is relied on before the guard has accepted it. So it never installs a lease for another key, release, genesis, chain, engine or signer identity, from an authority the trust file does not pin, with wrong dates or a life above five minutes.
4. It also requires `host_id` and `request_nonce` to be its own, its clock to be before `renew_by_utc`, a fence token not below the installed lease's, and, within one token, a later expiry.
5. It renames the temporary file onto the lease file and syncs the directory. The guard reads the old file or the new one, never half of one.
6. It asks again after a quarter of the lease's remaining life, 60 s with the defaults. After a failure it tries every 10 s.
7. If the lease file is there and cannot be read as a lease, it asks nothing that round. Only "the file is not there" means "this host holds no lease"; an empty file counts as not there.
8. It logs a refusal with its text and says in the same line that the answer is unsigned.

Settings paths are written as the containers see them (`/operator/…`). The agent's config names the host directory that is mounted there.

### 8.4 A copy of a host

A cloned machine, or one restored from a backup, has the host key. A copy shares the original's nonce only for the request that was open when the copy was made. From the next request on each machine draws its own, and the second of them to ask names a lease that is not the last one issued. The controller **freezes the key**: no lease for it until `unfreeze KEY`, which starts a new tenure. What this bounds: both copies stop when the leases they hold run out, at most `L` after the freeze. What it does not: from the moment of the copy until then, both hold live leases, and the copy made of a running machine starts with one.

A host that was reinstalled, or whose lease file or agent state was replaced by an older one, looks the same and is frozen too. That is intended.

### 8.5 When the controller cannot be reached

- The agent logs each failed round with the seconds the installed lease still has. `lease-agent.mjs status` prints the same and exits non-zero under a threshold, for a monitor.
- The validator runs on until the lease ends: `L` after the last grant on the controller's clock, so between 3 and 4 minutes after the last successful round with the defaults.
- Then the guard fails with `Attestation expired or future-dated`, the node and CometBFT are stopped, the monitor reports not ready and `TimeOperatorNotReady` fires.
- Nothing restarts by itself. When the controller is back the agent installs a lease again, and the operator starts the stack.

## 9. The authority key

- **It is online by necessity**: it signs every few seconds. It lives in a file on the controller host, mode 0600, read once at start. The controller refuses a key file that others can read.
- **The controller host** runs nothing else, is not a validator host, and admits only the lease port from the validator hosts and the operator's login. Signing is one function, so a variant that signs in an HSM or a cloud key service replaces only that. This reference does not include one.
- **Rotation without stopping validators.** The guard reads the trust file at every check, so: (1) make a new key with a new authority id; (2) add it to every host's trust file beside the old one; (3) give the controller the new key and restart it, which hosts with a running lease do not notice; (4) five minutes later remove the old authority from every trust file.
- **After a theft:** the same steps at once, and step 4 first on any host that can spare the downtime. A guard refuses a removed authority at its next check that can read the lease file. While that file cannot be read, the validator runs on until its lease ends (14.1).

**What a thief of the authority key can do.** Sign any lease: for any key, host, release or engine. That removes every refusal in this document. It does **not** let them sign a block or a vote: that needs the consensus key. To make two hosts sign with one key they need all of:

1. the authority key;
2. a second machine that holds the same consensus key in a working signer, with the kit installed (a former holder that was not wiped is the likely case);
3. a way to put their lease into that machine's lease file: access to the machine, or a position on the network path between its agent and the controller.

With (1) alone they can do nothing to a validator. With (1) and (3) on a machine that has no key they can make the kit start a node that cannot sign.

## 10. What the lease does not do

### 10.1 It does not stop a signer from signing

The lease is checked by the guard, every five seconds. The signer never sees it. `deploy/README.md` demands a signer that consults a fencing authority at every signature and says that a lease "limits stale instances but does not replace per-signature enforcement". That stays true with this controller. The controller answers hosts; it offers nothing a signer could ask at every signature.

It is reported, and not checked by me, that no maintained remote signer for CometBFT 0.38 (tmkms 0.15.0, Horcrux 3.3.2, Cosmos-KMS 0.1.0) can consult an outside authority or a lease at every signature without custom code. So this section assumes an ordinary remote signer that only keeps its own record of the last height, round and step it signed.

With a remote signer that record is the only thing that stops a second signature at one height, round and step. The kit forbids CometBFT's own signer file (`priv_validator_state_file` points at a path that must not exist), so CometBFT keeps no record of its own.

**What remains with this controller and such a signer:**

| Case | What happens |
|---|---|
| **The key is given to a host whose signer does not have the old signer's record.** | The lease does nothing here. If the chain has moved past everything the old signer signed, the new one signs only later heights. **If the chain stands still** (more than a third of the votes are down, which is likely when one organization's validators stopped together), the new signer can be asked to sign the same height and round again, for another block. It is reported that tmkms and Horcrux start from height 0 when their state file is missing, and that Cosmos-KMS refuses to start unless told. |
| **A signer's state is copied or restored from an older copy.** | Two signers, or one that forgot, sign what was signed before. The lease does not see signer state. |
| **A machine is copied whole.** | Section 8.4: both run until their leases end. |
| **The seconds after a lease's end.** | CometBFT is told to stop within 5 s, and has been sent `SIGKILL` within 15 s, of the end of the last lease that verified (section 14). `stop_seconds` in the margin is for this. |
| **A validator machine whose clock is set back, or that is suspended and resumed.** | A clock set back after a lease verified no longer lengthens that lease: the guard also counts the lease's remaining life on the monotonic clock (14.1). Still not seen: a clock that was already behind when the lease first verified, and a suspension during which the monotonic clock stood still as well. Then the validator takes its lease for live when it is not. Only a check against the authority itself at every signature could close that. |

**What the operator must still do.**

- Never copy a signer's state. Never restore it from a backup. Move it, with the key, and delete it where it was.
- When a key moves to another signer, carry the old signer's last height, round and step over, or wait until the chain has passed that height. `deploy/restore-check.mjs` checks such a hand-over when the signer can attest its state. Do not move a key while the chain stands still unless the signer's state moves with it.
- Wipe the key from a former holder's signer.
- Never clone a validator machine or restore one from an image.
- Keep NTP running on every host and on the controller, and alert on clock offset.

### 10.2 What the guard stops, and what it leaves running (findings)

Read from `deploy/operator.mjs` and `deploy/compose.v5.yaml` at commit `c9df2a4`. Points 4 and 5 describe the guard before the change of section 14, which closes them.

1. **The signer is not under the guard.** `operator.mjs run` guards one child: the node in the `app` container, CometBFT in the `validator` container. The `signer` container runs the signer image's own entry point. When a lease ends, the guard does nothing to it.
2. **The signer stops only because Compose stops it.** The unit starts `docker compose up --abort-on-container-exit`, and that command stops every container when one exits. Started detached (`up -d`), or with the Compose client gone, the signer keeps running.
3. **A signer that keeps running has nobody to sign for only while CometBFT is gone.** In the remote-signer protocol CometBFT listens on `127.0.0.1:26659` and the signer connects. Once CometBFT has ended, nothing asks. So the lease reaches the signer through one thing only: the end of the CometBFT process.
4. **That end was not enforced.** The guard sent `SIGTERM` once (`operator.mjs:185`, `:195`) and never `SIGKILL`. A CometBFT that did not end on `SIGTERM` kept its connection to the signer and kept signing without a lease.
5. **A check that hung stopped nothing.** The timer stopped the child only when a check failed. A check that never returns, on a file system that stopped answering, never fails.

**The smallest change** closes 4 and 5, and with them 3; it is in section 14 and is made. Points 1 and 2 stand: the signer container is still not under the guard, and still runs on when Compose does not stop it. Putting the signer itself under the guard would need the guard to run inside an image this kit does not build, or to reach the container runtime, which the kit's containers are deliberately denied.

### 10.3 The field `enforcement: "EVERY_SIGNATURE"`

The guard refuses a lease without this exact value. The field is the authority's statement that the signer enforces fencing at every signature. **This controller cannot know that, and with the signers named above it is, as reported, not true.**

What the controller does, so as not to write it blindly:

- It issues for a host only if the config holds, for that host, `"signer_fencing": "EVERY_SIGNATURE"`. That is the operator's declaration that this host's signer refuses to sign unless a fencing check passes at every signature. Without it: `SIGNER_NOT_DECLARED`.
- Every lease says `"enforcement_basis": "OPERATOR_DECLARATION"`, and the service logs at start which hosts carry the declaration. A reader of a lease can see that the claim is the operator's and was not checked.
- The example config holds a placeholder that is refused.

This is honest only as far as the declaration is. **An operator who runs an ordinary signer and writes the declaration has declared something false.** Today that is every operator, if the report is right. The kit should not stay in that state. Two ways out:

- **(a) Build the per-signature check**: a small program between CometBFT and the signer that forwards a request only while a valid lease is on disk. It closes the seconds between a lease's end and the end of CometBFT (14.1). It does not close the first three rows of the table in 10.1, and a suspended machine still trusts its clock.
- **(b) Say what is true**: let the guard accept a second value for a lease that is enforced by the guard only, and only on a host whose settings ask for it by name, so that the weaker mode is a visible choice per host. `launch-check.mjs` keeps its `remote_signer_fencing` gate outstanding either way.

**Recommended: (b) now, and (a) later if it also carries the signer's last signed height from the old holder to the new one.** The reasons: a field that every real deployment must fill in falsely teaches operators and auditors to ignore it; the margin already allows 40 s for the seconds a per-signature check would save; and the large risks that remain are about signer state, which a lease check at every signature does not touch. Neither is done here: (b) changes a requirement the kit states on purpose, and that is the owner's decision.

## 11. Availability

- A controller that is down stops every validator it serves within `L`, and each must then be started by hand. It must be back within `L` less one round, about 3 minutes, for nobody to notice.
- A replacement controller (the key file and a copy of the state on another machine) follows the start rule: a key whose lease the copy shows as still running goes on with its holder at once, and every other key waits 360 s. A copy is rarely seconds old, so expect most validators to have stopped before it issues anything. It is a way to recover, not a way to stay up. Check its clock before the start (5.5).
- **Twenty validators of one organization behind one controller: one failure halts the network.**

**For a first network: several controllers, each for its own keys.**

- At least four. No controller serves validators with a third or more of the voting power: at most six of twenty equal validators. The loss of one controller then leaves fourteen, which is the two thirds blocks need.
- Each has its own host, authority key, fence domain and state. **Never two controllers for one key.**
- Each validator host pins only its own controller's authority in its trust file. The guard accepts any pinned authority with the role `signer_lease` for any key, so the trust file is what keeps another controller's lease out.
- Put a controller where its validators are: the same region, another host, other credentials. A region that fails then takes one group, which the network survives.

**Left out on purpose:** a controller replicated by a consensus protocol; a standby that takes over by itself; leases longer than the guard's five minutes; a controller for more than one network; any way for the operator to skip a wait.

## 12. Threats

| Threat | What happens |
|---|---|
| **The controller crashes between writing and sending** | The lease is recorded and never arrives. The host asks again and gets it. |
| **The controller's state is replaced by an older copy** | The start rule. Running leases go on with the same holder; the rest waits. Hosts that renewed since the copy are frozen. |
| **The state is lost** | No key has a holder. After `assign`, each waits 360 s from the start. Tokens come from the clock plus five minutes. |
| **State files are put back under a running service** | It stops at its next request: the files do not descend from the one it holds (5.2). The next start applies the start rule. |
| **Two services on one state directory** | The second is refused by the lock. If the lock fails, numbered files keep them consistent. One of the two that falls more than 32 files behind the other finds a file of its line removed, and stops with a message (3.6). |
| **A second controller elsewhere with the same authority key, while the first runs** | **Not prevented** (A2). Both issue. Each host's agent asks one address, which limits the damage to a move made on one and not the other. |
| **The operator moves a key while the old host runs** | The new host waits until the old lease has ended everywhere plus the margin. The old host gets no more. |
| **The operator edits a host's key in the config** | The tenure holds the old key: `HOST_KEY_CHANGED` until a `move`. |
| **The operator copies a validator machine** | Section 8.4: frozen at the copy's first request after the original's; bounded, not prevented. |
| **A host asks for a key that is not its own** | `NOT_HOLDER`. |
| **A host key is stolen** | The thief gets leases for that host's key and settings. They are of use only with that key's signer. Remove the host from the config. |
| **A request is replayed** | `CLOCK` if it is dated at or before the last request that got a new lease. Otherwise it is a repeat of the open request and gets what the host would get. Inside A1, and unless the host lost its lease file or agent state, a recording never freezes a key (8.1). |
| **An answer is replaced by an older lease on the way** | The lease of another request has another nonce. An earlier lease for the same request is refused once it is past `renew_by_utc` on the host's clock; if the host's clock is behind and it is installed all the same, the controller accepts its id (8.2). |
| **A host's clock is wrong beyond A1** | Mostly `CLOCK`. A clock set back after a grant is the last row of the table in 10.1. |
| **The controller's clock is wrong beyond A1** | Section 5.5. It stops when its clock is set under it; a start and every command refuse a state from a later clock. While it is wrong it refuses hosts with right clocks. If the hosts' clocks are wrong with it, S1 can fail. |
| **The wrong engine, genesis or chain** | Refused; the state is bound to one. |
| **A release nobody approved; an old release after an upgrade** | `RELEASE_NOT_APPROVED`; `RELEASE_ROLLBACK`. |
| **The authority key is stolen** | Section 9. |
| **Requests flood the service** | Bodies are capped, requests are handled one at a time, at most 64 wait. A flood from outside the firewall's list is the firewall's to stop. |
| **Whoever runs the controller** | Can stop every validator it serves by not signing, and veto a release. `docs/design/upgrade-mechanism.md`, question 2, stands. |

## 13. Alternatives rejected

- **The command line talks to the running service.** An administration port is something to attack. Numbered state files let the command line change the state beside the running service with nothing listening.
- **A counter for fence tokens.** A controller without its state would start again below tokens it issued. A token from the clock needs only the assumption everything else already needs.
- **A flag by which the operator says "this state is current" to skip the start wait.** It would be used under pressure, on exactly the day the state is not current.
- **A lease per host for all its keys.** One key per validator host is the kit's model.
- **Automatic failover.** Section 6.
- **Signed refusals.** They would let the agent trust the reason. The agent does not act on the reason.
- **TLS inside the service.** Section 8.2.
- **A new attestation kind, or a changed lease format.** The guard is the consumer; three ignored fields are enough.

## 14. Changes to the kit

The lease format and `deploy/lib.mjs` are unchanged. The controller's leases carry four fields the guard does not read.

### 14.1 The guard's rule, and the bound

`deploy/operator.mjs` is changed in two places: the five-second check of a running child is the exported function `leaseWatch`, and `guard()` judges a lease against the clock as it reads after the files were read.

**The rule.** A child may run until the expiry of the last lease that verified, and must be dead a bounded time after it.

- `validUntil` is the latest `expires_utc` of any lease that verified. The launcher verifies the lease again immediately before it starts the child, and that lease is the first. A lease that has ended when the watch is created stops the child at once, without waiting for the first check.
- **A lease counts on two clocks, and the child is stopped at whichever deadline comes first.** One is its `expires_utc` on the wall clock. The other is its remaining life at the moment it first verified, counted from then by a timer, which runs on the monotonic clock. So a wall clock that is set back after a lease verified does not lengthen it. A clock that was already wrong when the lease first verified is not seen.
- Every 5 s (`GUARD_PERIOD_MS`) the launcher compares its wall clock with `validUntil`. Once the clock has reached it, the child is told to stop.
- A check that **refuses** what it read stops the child at once: a lease that has ended, is for another key or release, comes from an authority that is no longer pinned, or cannot be parsed. That is what the guard did before.
- A check that **cannot read** its files (an error of the file system) or **does not return** is not a refusal. The child runs on until `validUntil`, and no longer.
- Stopping is `SIGTERM`. If the child is CometBFT and still runs 10 s later (`GUARD_KILL_MS`), it is sent `SIGKILL`. That timer is armed before anything else is done, and timers count on the monotonic clock. CometBFT recovers from a kill through its write-ahead log. The node is never killed, so that it can finish its snapshot.
- **No interval is measured between two readings of the wall clock.** A wall clock stepped forward, or a launcher that did not run for a while, stops nothing unless a deadline has in fact been reached. A wall clock set back by more than the lease's age plus two skews (its back-dating) stops the child at once: the guard then finds the lease dated in the future and refuses it. That is the safe side.
- A check that takes long does not extend anything: what it reports is the lease's own expiry, and `guard()` no longer answers "valid" for a lease that ended while it worked.

The first form of this change, in revision 2, counted a check as failed when none had succeeded for 12 s, measured between wall-clock readings from the moment a check finished. The review showed both faults: slow checks that overlapped kept a validator alive 60 s after its lease, and a clock stepped forward 13 s, or a directory that did not answer for 16 s, stopped a healthy one.

**The bound, stated once.** Let `E` be the `expires_utc` of the last lease that verified on a host.

- On the host's wall clock: the child is told to stop less than 5 s after `E`, and CometBFT has been sent `SIGKILL` less than **15 s** after `E` (`GUARD_PERIOD_MS + GUARD_KILL_MS`). The duration of a check adds nothing to this.
- In true time: the host's clock may be `σ/2` behind (A1), and a step inside A1 stays inside that. So CometBFT has been sent `SIGKILL` before `E + σ/2 + 15 s`.
- A wall clock set back after the lease first verified, by any amount, adds nothing to this: the timer for the lease's remaining life ends when `E` would have been reached on the clock as it was, and the kill comes 10 s after it.
- Not in the bound, because this code cannot bound them: the time the kernel takes to end a killed process, and a launcher that is not run at all (a stopped process, a frozen container) while CometBFT is. A launcher that is late by `d` is late with both signals by `d`.

**The margin, derived from it.** The next holder's first lease is issued when the controller's clock reads at least `E + m`, so at a true time of at least `E + m − σ/2`. The old CometBFT has been sent `SIGKILL` by then with `m − σ − 15 s = σ + stop_seconds − 15 s` to spare. With the defaults that is 35 s. With the smallest settings (`σ` = 1 s, `stop_seconds` = 30) it is 16 s. `stop_seconds` may not be set below 30, which is twice the bound.

### 14.2 Documents and lists

`deploy/README.md` and `deploy/PRODUCTION-V5.md` point to the controller, say what it does not do, and state the guard's rule. The README's list of lease fields now names `chain_id`, which the guard has always required. `tools/ci-checks.mjs` has a check `node-lease` for the tests. `public-manifest.json` names the new files. Everything under `deploy/` goes into a release context, as before; the agent and the controller import nothing outside `deploy/`, so a release context can run them. They are not added to the distribution for gateways and shops.

### 14.3 Considered and not done: the guard checks `host_id`

A lease file copied to a second machine together with the settings is accepted by the guard there. A setting that names the host, checked against the lease's `host_id`, would not change that: the setting is copied with the rest. For a lease file copied alone, the guard already refuses: the lease names the `signer_identity` of the host it was issued to, and the controller registers each identity for one host only (7, point 6). So the check would add a second field that does what one does already, and it is not made. What would bind a lease to a machine is something that is not in a file that can be copied; the kit has no such thing.

## 15. Tests

`node --test "deploy/lease-controller/*.test.mjs"` runs ten files: four of this work, three of the first review (`review-*.test.mjs`) and three of the second (`review2-*.test.mjs`). One test is skipped on Windows.

**The review's tests.** 19 tests named FINDING failed against revision 2 and pass now; 8 named HELD passed then and pass now. Where a test asserted the faulty behaviour itself, the line was changed and is marked `ADAPTED:` with what it asserted before. No check was weakened. The adaptations:

- The bench of the guard tests: its checks answered only "valid"; they now report the lease that verified, as `guard()` does. The stated bound in that file went from 27 s to 15 s.
- A key's wait after a lost state: asserted as counted from the controller's start; it is counted from the command, one second later.
- The clock an hour ahead: the test restarted the service and went on; the start is now refused, the test runs `clock-was-ahead`, and asserts the same bound on every wait.
- `refence --above` near the largest number: asserted as accepted; it is refused, and the test puts the state it used to leave behind in place to show that a start survives it.
- The older lease on the way: one line compared nonces through the lease file, which only held when the agent had installed the older lease.

**The second review's tests.** 10 tests named FINDING failed against revision 3 and pass now; 8 named HELD pass. Three assertions were changed, each marked `ADAPTED:`:

- The document finding on 14.1 asserted that nothing is sent after a clock is set back by more than the lease's age plus two skews. The code stops the child there, which is right; the sentence was wrong. The test now asserts the stop and that the design says so.
- The 400 random schedules of the guard asserted that `SIGTERM` comes only when the wall clock has reached the expiry or a check refused. With the second deadline it may come up to one skew earlier on the wall clock, after a clock set back; the test knows that deadline now and asserts both.
- In the first review's file, one line asserted that a clock set back by a skew moves the stop later by that much. That was the fault of finding N2; it now asserts that the stop stays inside the bound.

**The decisions, with an injected clock** (`core.test.mjs`): every refusal of section 7 with its message; the edges of the freshness window; a recording sent again, at once, while fresh, after the next lease, and after the controller's clock is set back; a lost answer; a stored lease sent again until two skews before its end, to the millisecond, and the id of a replaced lease accepted; the time of the last grant never going down; the spacing; a copy of a host and the freeze, also for a copy that shares one nonce; a move, with the old holder refused at once and the new one made to wait to the millisecond; a move and an unassign ending a freeze; one key per host; an upgrade with two releases and the way back; the binding to a network, an engine and a fence domain; the start rule for a running lease, an ended lease and a tenure without a lease; a controller that lost its state; a replacement controller whose clock is behind the old one's.

**The kit's real `guard()`** on what the controller issues, on a v5 and a v4 network: accepted; accepted at the longest lifetime a config allows and on host clocks from two skews behind to one millisecond before the end; refused one millisecond outside on both sides; refused under settings that name another key, release, genesis, signer identity or engine; refused under an authority that is not pinned or pinned for another role; refused when changed after signing. A rotation of the authority key in the four steps of section 9.

**Files, crashes, races, the clock** (`service.test.mjs`): two writers of one state number; the parent each file names; a damaged newest file; a crash after the state is written and before the answer, then a new process and the same request; a write that fails before it is durable, and for five leases in a row that the lease is on disk when the answer returns; the same request twice at once; two machines with one host key at once; two services on one directory; a move racing a renewal, eight times; state files replaced under a running service by older ones, by another file under the same number, by a file with another parent, and with a gap; a wall clock set under the service, forward and back, inside and outside the skew; a start and five commands refused on a state from a later clock; `clock-was-ahead`, without and with a lease that was dated by the wrong clock; the service's own timer ending it; 74 requests at once against a queue of 64; the server's timeouts.

**The service and the agent on localhost**, with the real guard: a first lease, a refusal at each step before it, twelve renewals while another reader parses the lease file as fast as it can, the end of a lease. Answers the agent must not install, each differing from the true answer in one thing: another host, an older lease, another key, release, signer, genesis, engine, authority, a changed payload, a lifetime above five minutes, no enforcement claim, a date ahead of the host's clock, a lower token, an earlier end, a lease past `renew_by_utc`, and some that are no answers. A redirect that is not followed. A lease file that cannot be read: nothing is sent. A lease in a directory of its own, written with mode 0644 under a umask of 077 (the mode is checked on Linux and macOS only). A lost answer repeated with the same nonce; a lost agent state and the freeze. The agent's loop and its log. Key files through a link and of unusual size. The lock. Every command, with its refusals. The example configs.

**Random schedules** (`simulation.mjs`, `safety.test.mjs`). A simulated world: true time; four hosts and the controllers' machines, each with a clock anywhere within half a skew of true time and often exactly at its edge, redrawn at random moments; requests and answers that are delayed, lost, repeated and replayed, recordings of the newest requests among them; a controller that is killed, that dies just before or just after the state write, whose disk reports an error before or after the write; one or two live processes on one state directory; a start from the current state, from any state ever written, or from none, with settings that change between starts; state files replaced under a running service; commands on a restored or lost state before and after the start; two releases, and hosts that go forward and back between them; an operator who assigns, moves, unassigns, unfreezes and re-tokens keys at random moments; hosts that lose their agent state. The real controller code runs over a store in memory, which removes old files when a service asks, as the real store does. Every lease a host installs is checked by the kit's `signed()` on that host's clock, and by the agent's own rules. After every step the simulation checks S1, both ways (no two hosts with a live lease; and at each installation, that every lease another host ever had for the key ended at least 30 s ago, the smallest stop time, in the worst case A1 allows), S2 at every issue, and the cause of every freeze: the host lost its lease or agent state, or the controller's state was put back to one that does not hold that host's lease as the newest for its key, and nothing else. A recording that freezes a key without such a cause fails the run.

- The test file runs 40 schedules of 2,500 steps: about 4,000 leases installed, 370 changes of host with a lease installed, 690 restores, 110 lost states, 490 commands on a restored state before the start, 150 second processes, 120 replacements under a running service, 2,900 answers delivered late, 5,000 recordings sent again.
- By hand, once, on this form of the simulation: 121 more schedules of 2,500 steps (11,500 leases installed, 1,000 changes of host, 2,100 restores, 350 lost states, 340 replacements under a running service, 96 freezes, each with a named cause). No claim failed. Before that, on earlier forms of the simulation: 401, 601, 401 and 501 schedules. The last of those forms excused every freeze after any put-back of the state. This one excuses it only for a host whose lease the state in place does not hold as the newest.
- **The same schedules must notice a broken controller.** Three tests remove one rule each and require a failure: no wait before a tenure's first lease; no start rule; a lease sent although the state write failed.
- By hand, in the code itself, before the review: three parts of the start rule broken one at a time; each was noticed by a unit test, and two of them by the simulation. After the review: the refusal of recordings removed (noticed in schedule 2, as "a recorded request froze a key"), and the check of a state file's parent removed (noticed in schedule 5, as two hosts with a live lease).
- **What the review showed about these schedules:** they never produced a recorded repeat arriving fresh after the next lease, nor a controller that follows foreign files. Both are produced now. A simulation finds what its schedules reach; the reviewer's tests found what mine did not.

**The guard's stop** (`guard-stop.test.mjs`): the bound of 14.1 for a lease that ends before, at, after and between two checks, for checks of eleven durations from 0 to 45 s and one that never returns, and for a check that then refuses, hangs or cannot read: 132 cases, each requiring `SIGTERM` less than 5 s and `SIGKILL` less than 15 s after the expiry, and nothing before it. A lease renewed every minute under checks of up to 31 s. No stop for a clock stepped forward 13 s or back 10 s, a launcher that did not run for 13 s or 100 s, a directory that does not answer for 16 s, errors of the file system for 100 s; a stop when such errors outlast the lease, and when the clock is stepped past its end. With the wall clock set back 60 s after a lease verified: `SIGTERM` when the lease would have ended on the clock as it was and `SIGKILL` 10 s later, for a check that then refuses, hangs or cannot read; a newer lease that verifies after the step counts from its own verification; a clock set forward stops at the expiry it reaches. A lease that has ended when the watch is created, by 0, 1 ms or 2 s: stopped at once. A refusal stops at once. The kill armed before a callback that throws. One test starts a real process that ignores `SIGTERM`. It is skipped on Windows, where no process can, and Windows is where these tests were run.

## 16. Not verified, and what I am unsure of

- **It ran with CometBFT 0.38.26, two remote signers (tmkms 0.15.0, Cosmos-KMS 0.1.0) and Docker on several machines**, in the kit rehearsal of 2026-11-19 (`deploy/lease-controller/README.md`, "What the rehearsal showed"). Measured there, in three campaigns: CometBFT ended 185 to 211 ms after its lease's expiry, on `SIGTERM`, and the validator's last vote in the chain was dated before the expiry each time. Not measured: a CometBFT that does not end on `SIGTERM` after its lease's end and is killed (section 14; the same kill was seen only after a stop from Compose, once the signer had gone), a move of a key, a controller restart, and a signer that keeps a connection after CometBFT has gone (the signer's container is ended by Compose, which then stops the stack).
- **All tests ran on Windows**, with Node 26.13, **and once on Linux** (2026-11-18, the project's test run on AWS: 110 tests, none skipped). What Windows skips ran there and passed: the test with a real process that ignores `SIGTERM`, the check of a key file's permissions, and the mode of the lease file under a umask. The sync of a directory, which the code leaves out on Windows, ran there without an error; no test cuts the power to see what it keeps.
- **The statements about tmkms, Horcrux and Cosmos-KMS** are another task's reading of public sources. I did not check them.
- **The argument for the start rule** is the least obvious part. It is argued in 5.3 and attacked by the random schedules and by the review. It is not proven formally.
- **The clock checks of 5.5** were tested with injected clocks, and once with the real clocks of one Windows machine. That a monotonic clock does not follow a step of the wall clock, and does not count a suspension, is a property of the platform that was not tested on Linux.
- **A4 on real disks.** The tests run on one file system on one machine and cannot cut the power.
- **A1 is an assumption.** Section 5.5 lists what is checked and what is not.
- **The simulation stays inside A1.** It produces no clock outside the bound and never runs `clock-was-ahead`. What happens outside A1 is covered by unit tests and by the two reviews' tests only; both reviews found faults there that the simulation could not have found.
- **A2 is an assumption that nothing checks across machines.**
- **The guard's bound** leaves out the kernel's time to end a killed process and a launcher that does not run (14.1).
- **Fork detection freezes on honest accidents** (a reinstalled host, a restored operator directory). How often that happens in practice is unknown.
- **The command lines** (`ctl.mjs`, `lease-agent.mjs`, `start.mjs` as programs) were run once by hand against a service on localhost, before the review's changes. The tests call their functions, not the programs.
- **The service under load, and a TLS proxy in front of it,** were not tested.
- **The numbers** (`σ` = 10 s, `stop_seconds` = 40, `L` = 240) are chosen by reasoning, not from measurements of real hosts.
