# Fixing a fault fast: the emergency procedure

This is what validators do when a fault in the rules must be fixed sooner than the 21 days of notice allow.

It is written for operators. Read it before you need it. Rehearse it.

**Where this stands.** The engine's part is built and tested on one computer. The cloud rehearsal ran on 23 November 2026: kinds B and C, twice each, on networks of seven laboratory validators in two regions, started by the test harness and not by the kit (`tc-v5-emergency-1` and `tc-v5-emergency-2`; the times are in section 12). The deployment kit now has the two things this procedure needed from it, a start of a chain that stood and the agreed root (section 13). They ran once on real machines, on 23 November, in the harness's rehearsal of the kit on seven validators in one region (`tc-v5-kit-7`): a coordinated stop with the kit, every validator refused without a resume order, an order with another root refused by the node, and the chain going on with the agreed root. That run started again the release that had stopped, not a fix release (section 4). No operator has followed this document, and no step that people take in it has been rehearsed: treat every such step as unproven.

Design: `docs/design/upgrade-mechanism.md`, section 10. Engine: `v5/README.md`, "Stopping at a height, and emergencies". Rehearsal: `campaign/README.md`, "An emergency fix, rehearsed".

## 1. The rule that does not change

Nothing shortens the notice of an upgrade. There is no faster vote.

A faster vote would turn the theft of signalling keys into a change of rules within hours. So an emergency is not a vote. It is a new program, installed by the operators themselves, with their own hands, on their own machines.

That is slow and it is meant to be. More than a third of the voting power must act to stop the chain. More than two thirds must act to start it again.

## 2. Three kinds of fix

Decide which kind you have before you do anything. The people who found the fault and wrote the fix decide it, and say so in the announcement.

| Kind | What it is | What it needs |
|---|---|---|
| **A. No rule changes** | The fix changes how the program works, not what a block means. Two validators, one on the old program and one on the new, agree on every block. Examples: a crash on a malformed network message, a memory leak, a slow query. | Install it. Nothing else. |
| **B. A rule changes, and the chain still runs** | The fault is in the rules: the old and the new program would disagree on some block. The chain is alive. | Stop at an agreed height. Restart on a fix release. |
| **C. Every node stopped in the middle of a block** | A block was decided and no node can execute it. Every node printed `FAILED ON A DECIDED BLOCK` and ended. The chain makes no blocks. | A fix release built for that one block. |

If you are not sure between A and B, it is B. A fix that changes a rule and is installed as if it did not splits nothing, because nodes that disagree stop, but it halts the chain at a moment nobody chose.

## 3. What must be ready before any emergency

None of this can be done in the hour it is needed.

1. **A private security contact for every validator.** A name, two ways to reach them that do not depend on each other, and a time zone. Kept by the coordinators. Tested every three months by a message that must be answered. The worst failure of 2026 on other networks was a fix that was ready while several validators could not be reached.
2. **A private channel** that every validator can read and that the public cannot. The fault is not discussed anywhere else until the fix is in force. A public vote, a public issue or a public chat would publish the fault to the people who could use it.
3. **A second channel**, not run by the same people or on the same service, to compare hashes over.
4. **The project's private security contact**, published in `SECURITY.md`: the repository's private vulnerability reporting form.
5. **Who may announce a fix release**, and with which key. Every operator holds that public key before the emergency. See section 4 for what exists and what is missing.
6. **Who the coordinators are**: at least two people, in different time zones, who choose the height and collect the answers.
7. **A rehearsal**, on a test network that runs the same release, by the operators who will do it. At least once a year, and after every change to this document. A cloud rehearsal exists for the harness (`campaign/README.md`); it does not replace operators doing it by hand.
8. **Each operator knows**: where the node's log is, how to read the node's exit code, how to run the recount, how to stop the supervisor from restarting the node, and where the signer keeps its record.

## 4. How to know a release is genuine

A fix release is a program that changes the rules without notice. Installing a false one is the worst mistake in this document. Take the time.

**What exists.**

- A release is made by `tools/release-v5.mjs`. Its manifest names every source file by its SHA-256 and has one identity, the `release_id`.
- `deploy/build.mjs build` refuses to build if a source file differs from the manifest. It records the image digest and the SHA-256 of every program in the image.
- Every operator can build the image from the release directory and compare the digest with the announced one. Two operators who built it themselves and got the same digest did not get it from each other.
- A validator started by the kit runs only with a signer lease that names the `release_id`. The lease controller of each organization issues leases only for a release that its own operator approved (`deploy/lease-controller/README.md`, "An upgrade: approving the next release").
- The program says what it is. `time-node-v5 --version` prints one line and opens nothing. A fix release prints `switch=VERSION@HEIGHT` in that line. At its start it logs one line that begins `FIX RELEASE:` with the network, the height and the version. A running node lists the switch in its status (`upgrade.switches`).

**What is missing.**

- The project has no published key for signing release announcements, and no command that checks a signed announcement. `deploy/README.md` tells operators to sign with "your external release authority". Until the owner publishes a key and a check, operators compare by hand over the second channel.
- The release tool was not changed for fix releases. A real fix release prints a version line that the kit of this tree refuses (the kit compares that line exactly). The kit that pins the new line must come with the fix release.

**The steps, for every operator, for every fix release.**

1. Read the announcement on the private channel. It must name: the kind (A, B or C); the `release_id`; the image digest; the SHA-256 of the node program; for kinds B and C the new version, the hash of its specification, and the switch text (section 6 or 7).
2. Compare those values with the same announcement on the second channel. If any value differs, stop and say so on both channels.
3. Build the image from the release directory yourself: `node RELEASE/context/deploy/build.mjs build RELEASE TAG`. Compare the digest it prints with the announced one. If you cannot build, ask two other operators for the digest they built, over the second channel.
4. Run `time-node-v5 --version` from that image. For kind A the line must be the line of the release you run now, or the line the announcement gives. For kinds B and C it must contain `switch=VERSION@HEIGHT` with the announced version and the height of the switch block.
5. Approve the `release_id` on your lease controller. Do this only after steps 1 to 4.
6. Tell the coordinators: "verified, digest D, ready". Give the digest, not just the word.

## 5. Kind A: a fix that changes no rule

Nobody stops. Nobody agrees on a height.

1. Verify the release (section 4).
2. Replace the program on one validator at a time:
   1. Stop the stack cleanly. The node saves its state and ends with exit code 0.
   2. Pin the new `release_manifest` and `release_id` in the settings.
   3. Start the stack on the same volumes.
   4. Check `node deploy/operator.mjs probe SETTINGS`. Wait until the validator signs again.
3. Go to the next validator only when the one before signs.
4. Never have a third of the voting power down at once.

With the kit, a validator that was signing can start again only 100 blocks after its last signature (`deploy/README.md`, "A validator starts again only 100 blocks after it last signed"). Plan for that wait on each validator.

If validators crash faster than they can be replaced, and more than a third are down, the chain stops by itself. Nothing is lost. Keep replacing. The chain goes on when more than two thirds run.

## 6. Kind B: a rule fix at an agreed height

Words used here: `H` is the agreed height. `N` is the version in force. The fix release switches to version `N + 1` in block `H + 1`.

### What happens

- Validators restart with a stop height `H`. With more than a third of the voting power stopping after block `H`, no block `H + 1` can be decided. The chain stands at `H` for everyone.
- The fix release carries a switch for this one network, compiled in: "after block `H`". On any other network it changes nothing.
- A validator on the fix release proposes exactly one block after `H`: one transaction, the switch, and nothing else. It accepts only that block.
- When more than two thirds of the voting power run the fix release, that block is decided. It ends by writing version `N + 1`. The fix applies from block `H + 2`.
- The faulty rules run up to and including block `H + 1`.

### The coordinators

1. Choose `H`. It must be far enough ahead for every operator who will stop to restart once before it. Say `H` and the present height on the private channel.
2. Count the answers. You need operators with **more than a third** of the voting power to confirm that they run with the stop height. More is better. With a third or less, the chain goes on past `H`: choose a later `H` and start again.
3. The switch text of the fix release is `NETWORK:after:H`, with the network id as 64 hexadecimal characters. Give it to the people who build the release, and put it in the announcement.
4. When the chain stands, collect from every operator the height and the root their node holds (step 4 below). They must all be `H` and one root. Announce that root as the agreed root.
5. When operators with **more than two thirds** of the voting power have said "verified, ready", say "start".

### Each operator

1. **Set the stop height.** With the kit: put `"stop_after_height": H` in the settings and restart the stack before `H` (section 13). Without the kit: start the node with `--stop-after-height H`.
   - Check: the node's status shows `"stop_after_height": "H"`.
   - A node whose state is already above `H` refuses to start with exit code 1 and changes nothing. Tell the coordinators: they need a later `H`.
   - With the kit a validator that restarts while the chain runs is out for 100 blocks: CometBFT refuses to join while one of the last 100 blocks carries its own signature. So restart in groups of less than a third of the voting power (six of twenty equal validators at most), one group after the other, each once the chain is 100 blocks past its last signature. Coordinators: choose `H` far enough ahead for every group.
2. **Wait for the stop.** After it commits block `H` the node prints `STOPPED AS ASKED` and ends with exit code 4. CometBFT ends by itself. Do not start anything.
3. **If your validator was not restarted in time,** it keeps running at `H` and its rounds fail. That is safe. Stop the stack cleanly once the coordinators confirm that the chain stands. A validator that keeps trying makes its rounds longer and longer. With the kit, stop it this way instead: set `"stop_after_height": H` and restart the stack once. The node, already at `H`, stops at once with `STOPPED AS ASKED`. The kit's start of a chain that stood needs a node that stopped by itself (section 13).
4. **Recount.** Run `time-node-v5 --devnet --db PATH --audit` on the saved state. It prints a height and a root. Send both to the coordinators. With the kit, recount a copy of the ledger volume (section 13).
5. **Verify the fix release** (section 4). The version line must show `switch=N+1@H+1`.
6. **Wait for the agreed root and for "start".**
7. **Start the fix release** on the same data, without the stop height, and with the agreed root: `--expect-root H:ROOT`.
   - The node starts only if its state at `H` has that root. If it has another root, the node changes nothing and ends with exit code 1. Do not start that validator. Tell the coordinators.
   - Its log has one line that begins `FIX RELEASE:` and one that begins `This node goes on from height H only on the state with the root`.
   - With the kit: write a resume order with `H:ROOT` and start the stack (section 13). The kit passes `--expect-root` and starts CometBFT once without its double-sign check, which would otherwise refuse every validator of a chain that stood.
8. **Watch.** Nothing happens until more than two thirds run the fix release. Then block `H + 1` appears. Your node logs a line that begins `RULE SWITCH:`. Its status shows `"app_version": "N+1"`.
9. **At the next ordinary restart, remove `--expect-root`.** A node that has gone past `H` refuses to start with it, and changes nothing. With the kit there is nothing to remove: the order applies only while the node's state is at or below `H`, and turns the check off for one start only.

### A validator that was not replaced

It rejects the switch block as a proposal and goes on trying. When the block is decided it does not execute it. It prints `STOPPED AT A SWITCH` and ends with exit code 4, with its state at `H`.

Install the fix release and start it on the same data. CometBFT hands it block `H + 1` again. No rollback, and no file to delete.

### If it goes wrong

- **The chain did not stand at `H`.** Too few stopped. The nodes that stopped are behind and safe. Start them on the old release without the stop height. Choose a later `H`.
- **A fix release was built for an `H` the chain did not stop at.** A node on it does not execute the block after `H`, prints `STOPPED AT A SWITCH`, and says that the block is not its switch block. Started on a state that is already past `H`, it prints the same first line and says that the chain passed that block without the switch. In both cases: start the release the state was made by. Wait for a fix release built for a later height.
- **Roots differ at `H`.** Do not start. The operators whose root is in the minority recount again. If it still differs, that node's state is damaged: it is rebuilt from another node after the emergency. If no root has two thirds, nobody starts, and the developers are called.
- **Too few start the fix release.** The chain stands. Nothing is lost. It goes on when more than two thirds run it.

## 7. Kind C: a stop in the middle of a block

### What happened

A block was decided: validators with more than two thirds of the voting power signed it. Then no node could execute it. Each node failed closed and ended with **exit code 1**.

The last lines of the node say where it stands:

```
FAILED ON A DECIDED BLOCK
The decided block S (hash B) failed a check of this program and was not executed: REASON. The state of this node is at height S-1 with the root R, and nothing of block S is in it. ...
```

### What state each node is in

- **The node:** its state is the block before, `S - 1`. Nothing of block `S` is in it. Its last snapshot on disk may be older; that is normal.
- **CometBFT:** it has stored block `S` with the signatures that decided it. It has not recorded the block as executed.
- **The signer:** it has signed for block `S`.
- **At every start,** CometBFT hands block `S` to the node again. The same program fails on it again. Restarting does not help.

Block `S` is final. It cannot be undone, replaced or skipped. Every validator signed it. A validator that signs another block at that height signs twice, and loses its bond.

So the only way forward is a program that can execute block `S`.

### The steps

1. **Stop the restarts.** If a supervisor restarts the node, switch that off. The kit does not restart.
2. **Write down four values** from the node's last lines: the height `S`, the block hash `B`, the height of the state (`S - 1`) and its root `R`.
3. **Send them to the coordinators** on the private channel. Do nothing else. Delete nothing.
4. **The coordinators compare.** Every validator must name the same four values. If two groups name different blocks or roots, nobody starts anything, and the developers are called.
5. **The developers find the fault and write the fix.** The fix release names that one block: its switch text is `NETWORK:block:S:B:R`. It executes block `S` with the transactions it was decided with, under the corrected rule, and ends it by writing version `N + 1`. It executes no other block at that height, and that block on no other state.
6. **Verify the fix release** (section 4). The version line must show `switch=N+1@S`.
7. **Start the fix release** on the same data with `--expect-root S-1:R`. With the kit: write a resume order with `S-1:R` and start the stack (section 13).
   - CometBFT hands it block `S`. It executes it.
   - If the node's state at `S - 1` has another root, it stops before it executes anything further and ends with exit code 1.
8. **Watch.** When more than two thirds of the voting power run the fix release, block `S + 1` appears, under version `N + 1`.

### What the fix must do with the block's transactions

Wallets accept a payment when the block that holds it is final. They do not ask again. So every transaction in block `S` must be executed by the fix release, or a wallet somewhere believes in a payment that did not happen.

If block `S` holds a transaction that must not take effect, no program can make that safe (section 9). The developers say so in the announcement, and say which transaction.

## 8. What you must never do

- **Never delete the node's data or CometBFT's data** to make a start work. Every message of the node ends with "Delete nothing". It means it.
- **Never run `cometbft unsafe-reset-all` or `cometbft rollback`.** A decided block is final. Removing it from one machine removes nothing from the chain.
- **Never reset, copy or restore the signer's record** of what it signed (`priv_validator_state.json`, the signer's state volume). It is what keeps your validator from signing twice.
- **Never run one validator key on two machines.** Not for a minute, not "to test the fix release".
- **Never start the old release after the switch on new or wiped data** as a validator. On its own data the old release stops by itself. On other data it is a second signer.
- **Never start a fix release you did not verify.**
- **Never start with a root other than the agreed one.** If the node refuses the agreed root, the node is right and you do not start.
- **Never restart a failed node in a loop.**
- **Never talk about the fault in public** before the fix is in force.
- **Never lower a safety setting to get a start through,** unless this document names the setting and the moment. It names one: the kit's resume order, for the start of a chain that stood (section 13). Never edit CometBFT's configuration by hand instead: the kit writes it at every start.
- **Never write a resume order** on a machine that is not the one validator the key belongs to, and never copy, clone or restore a validator host while the chain stands.

## 9. What software cannot make safe

- **The agreement is between people.** The height, the root and the release are agreed outside the chain. The programs check what they are told. A wrong height stops nodes; a wrong root stops nodes; neither can be detected before people have talked.
- **A fix release is trusted code.** Whoever can make two thirds of the voting power install a program can change any rule at once. The switch has no notice: nobody can sell, unbond or leave before it. The only brake is that each operator verifies and installs by hand.
- **The faulty rules run until the switch.** What the fault did before height `H` stays done. Nothing is rolled back.
- **A block that is final stays final.** In kind C the transactions of block `S` are in the chain for good. If one of them must not take effect, either wallets are misled or the fix lets it take effect.
- **Wallets and servers get no notice.** Software that does not know version `N + 1` stops with `UPGRADE_REQUIRED` at the switch. After a scheduled upgrade it had 21 days. After an emergency it has none. Payments through such software wait until it is updated.
- **The chain waits for people.** It stands until more than two thirds have acted. At night, on a holiday, with a contact list that is out of date, that can be a long time.
- **Not signing twice depends on the signer's record.** No program can protect a validator whose operator resets it.

## 10. What is missing today

1. **The kit's start of a chain that stood has run once, by the test harness, and not with a fix release.** Its CometBFT configuration sets `double_sign_check_height = 100`: CometBFT refuses to join consensus if its own key signed one of the last 100 blocks. After a stop at `H`, or after a stop in the middle of a block, every validator signed the last blocks, and the chain makes no new ones. Read from CometBFT's source (`consensus/state.go`, `checkDoubleSigningRisk`); the pinned program says the same in the configuration it writes, and its default is 0; seen for one validator in the kit rehearsal of 19 November, and for all seven on 23 November. The kit now has a resume order (section 13): one start with the check off, after the operator names the agreed height and root, and `--expect-root` passed to the node. It is tested without Docker, and it ran on seven validators in one region on 23 November (`tc-v5-kit-7`): after a coordinated stop at 1,605, every validator was refused without an order and the chain made no block; an order with another root was refused by the node and nothing was signed; with the agreed root, block 1,606 came 10 seconds after the starts and every validator signed again; and the next start had the check on again. That run started again the release that had stopped: a fix release cannot go through the kit yet (item 5 and section 4). No operator has done it.
2. **The resume order turns a safety check off.** It cannot tell a copy of a validator host made during the standstill from the host itself (`deploy/README.md`, "A chain that stood", who could misuse it).
3. **No signed announcements** (section 4).
4. **No security contact** is set in `SECURITY.md`, and no contact list of validators exists.
5. **No real fix release has been made.** The rehearsal's fix release is the rehearsal program built with a switch. The release tool, the kit's pinned version line and the lease flow for a fix release were not exercised.
6. **Wallets and servers** have no way to learn the new version faster than by an update of their own software.

## 11. What each message means

| Exit code | First line | Meaning | What to do |
|---|---|---|---|
| 4 | `STOPPED AS ASKED` | The stop height was reached. State saved at `H`. | Recount. Wait for the coordinators. |
| 4 | `STOPPED AT A SWITCH` | The node and the chain disagree about a rule switch. Nothing was executed. The second line says which of three cases it is. | Old release, and a block carries a switch: install the fix release. Fix release, and the block is not its switch block, or the state is past it: start the release the state was made by. |
| 4 | `STOPPED FOR UPGRADE` | The chain is under a version this program lacks. | Install the release that implements it. |
| 1 | `FAILED ON A DECIDED BLOCK` | Kind C. | Section 7. Do not restart. |
| 1 | `The node did not start: --expect-root ...` | The state is not the agreed one, or the node is past that height. Nothing was changed. | Do not start that validator. Tell the coordinators. |
| 1 | `The node did not start: --stop-after-height ...` | The node is already above the stop height. Nothing was changed. | Tell the coordinators. |

## 12. How long things took

Measured on real machines so far, on 18 November 2026, on seven laboratory validators in two regions, started by the test harness and not by the kit (`campaign/README.md`):

| Step | Time |
|---|---|
| Replace the program on one running validator: clean stop, start on the same data, caught up and signing | 5 to 8 seconds |
| A validator that had stopped at an upgrade, started on the new program, signing again | 7 and 9 seconds |
| All seven restarted with a stop height about two minutes ahead, each stopped at it | all seven, exit code 4 |
| Chain started again after the stop: first new block after the order | about 5 seconds |

With the kit, allow more for each restart: containers, the remote signer, a lease for the new release, and the 100-block rule of section 5.

**The emergency path itself**, measured on 23 November 2026 by the cloud rehearsal (`campaign/README.md`, "An emergency fix, rehearsed"): two runs, each on two networks of seven laboratory validators in two regions, started by the test harness and not by the kit. The two numbers are the two runs.

| Kind B: a fix at an agreed height | Time |
|---|---|
| Agreed height chosen (about 290 blocks ahead), to the chain standing there | 98 and 100 seconds |
| Fix release built, as the builder measured it (the tree was already built once on that machine) | 15 and 16 seconds |
| Fix release fetched by every host and checked by its hash | 14 and 14 seconds |
| Chain standing at the agreed height, from the stop to the switch block | 147 and 145 seconds |
| Last start that put more than two thirds on the fix release, to the switch block | 33 and 26 seconds |
| A validator that stopped at the switch, started on the fix release, signing again | 8 and 9 seconds |

| Kind C: every node stopped in the middle of a block | Time |
|---|---|
| The payment that no node can execute sent, to all seven nodes ended and reported | 8 and 9 seconds |
| Fix release for that block ordered, to the builder's report | 17 and 23 seconds |
| Fix release fetched by every host and checked by its hash | 8 and 11 seconds |
| Order to start on the fix release, to the first block after the repaired one | 12 and 6 seconds |
| No block at all, from the payment to the first block after the repaired one | 53 and 57 seconds |

**These are the times of machines, not of people.** A program gave every order the moment the step before it had ended. Nobody was woken, no announcement was written or checked, no hashes were compared between operators over two channels, and no operator typed anything. In a real emergency those steps take hours, and they are the ones this document is about. What the rehearsal shows is how little of that time is the software's: seconds to build and to fetch a fix release, and about half a minute from the last start that was needed to a chain that makes blocks again.

`node campaign/report-v5.mjs --campaign NAME` prints these numbers under "how long it took" after every run of the rehearsal.

The engine's own tests run these steps in milliseconds on one computer. They show that the rules hold. They say nothing about how long people and machines take.

## 13. With the deployment kit: what you type

These are the commands on a validator host set up as `deploy/README.md` says: the release in `/opt/time-v5`, the settings in `/etc/time-v5/operator/settings.json`, the images in `/etc/time-v5/operator.env`, the unit `time-v5`. Run them as root. `H`, `ROOT`, `S` and `R` are the values the coordinators announced. The unit's journal holds what every container printed: `journalctl -u time-v5 --no-pager`.

**The kit and a chain that stood.** CometBFT refuses to join consensus while one of the last 100 blocks carries its own key's signature (`double_sign_check_height = 100`). After a stop of the whole chain every validator signed the last blocks, and no block comes, so nobody could start. The kit's **resume order** lets each validator start once without that check, only on the agreed state: `operator.mjs resume-order` writes it, and the next start passes `--expect-root` to the node and runs CometBFT once with the check off. It works only after a node that stopped by itself (exit code 4) or failed on a decided block (exit code 1), and only while the node's state is at or below the agreed height. Every later start has the check on again. `deploy/README.md`, "A chain that stood", says what it does and who could misuse it. Write the order last: after the settings pin the release you will start and no longer carry `stop_after_height`.

### Kind A with the kit

One validator at a time:

```sh
systemctl stop time-v5          # the node saves its state and ends with exit code 0
# Pin the fix release: release_manifest and release_id in /etc/time-v5/operator/settings.json, TIME_IMAGE in
# /etc/time-v5/operator.env. Approve its release_id on your lease controller.
# Wait until the chain is 100 blocks past this validator's last signature (about two minutes at a block a second).
systemctl start time-v5
docker exec time-v5-private-devnet-validator-1 node /opt/time/deploy/operator.mjs probe /operator/settings.json
```

No resume order: the chain runs, and the 100 blocks pass.

### Kind B with the kit

```sh
# 1. Before H, with your group (less than a third of the votes at once; six of twenty equal validators at most):
systemctl stop time-v5
#    Add "stop_after_height": H to the settings. Wait until the chain is 100 blocks past this validator's last
#    signature (CometBFT refuses an earlier start), then:
systemctl start time-v5
docker exec time-v5-private-devnet-validator-1 node /opt/time/deploy/operator.mjs probe /operator/settings.json   # upgrade.stop_after_height is "H"
# 2. After H the node ends with exit code 4. The unit stops.
journalctl -u time-v5 --no-pager | grep -A1 'STOPPED AS ASKED'
#    A validator that was not restarted in time runs on at H once the chain stands: add "stop_after_height": H to
#    its settings and run `systemctl restart time-v5` once. The node, already at H, stops at once.
# 4. Recount a copy of the ledger volume, and send the "height" and "root" it prints to the coordinators.
set -a; . /etc/time-v5/operator.env; set +a
install -d -m 0700 -o 10001 -g 10001 /var/tmp/time-recount
docker run --rm --network none -v time-v5-private-devnet_ledger:/data/ledger:ro -v /var/tmp/time-recount:/copy --entrypoint cp "$TIME_IMAGE" -a /data/ledger/. /copy/
docker run --rm --network none -v /var/tmp/time-recount:/copy --entrypoint time-node-v5 "$TIME_IMAGE" --devnet --db /copy/v5-state --audit
# 5. Verify the fix release (section 4). 6. Wait for the agreed root and for "start". Then:
#    pin the fix release (settings.json and operator.env), remove "stop_after_height", approve the release on your
#    lease controller, and write the order:
node /opt/time-v5/context/deploy/operator.mjs resume-order /etc/time-v5/operator/settings.json H:ROOT
systemctl start time-v5
# 7. and 8. What the start did, and what the chain does:
journalctl -u time-v5 --no-pager | grep -E 'RESUME:|FIX RELEASE:|goes on from height|RULE SWITCH:'
rm -r /var/tmp/time-recount
```

- `RESUME: resume order ... double_sign_check_height = 0 for this one start` is the consensus launcher; the next start writes 100 again by itself.
- If the node refuses the root, the unit stops and its journal says `--expect-root`. Do not start that validator again. Tell the coordinators.
- If the start fails before CometBFT joins (a signer that answered late, a lease that was not there yet), the order is used up: remove `resume.json`, write a new order and start again.
- A validator that was not replaced and stopped at the switch (`STOPPED AT A SWITCH`) while the chain went on needs no order: install the fix release and start it once the chain is 100 blocks past its last signature.

### Kind C with the kit

```sh
# 1. The kit does not restart. 2. and 3. The node's last lines, for the coordinators:
journalctl -u time-v5 --no-pager | grep -A2 'FAILED ON A DECIDED BLOCK'
# 6. Verify the fix release (section 4). When the coordinators say "start": pin the fix release and approve it on
#    your lease controller, then:
node /opt/time-v5/context/deploy/operator.mjs resume-order /etc/time-v5/operator/settings.json S-1:R
systemctl start time-v5
journalctl -u time-v5 --no-pager | grep -E 'RESUME:|FIX RELEASE:|goes on from height'
```

Write `S-1` as the number, as the node printed it: the height of the state, one below the failed block.

**An upgrade that more than a third did not install in time.** The chain stands at the activation height for the same reason. Each validator that stopped there (`STOPPED FOR UPGRADE`) installs the release, recounts its state as in kind B, step 4, and, once the coordinators have compared the roots, writes an order with that height and root before it starts.
