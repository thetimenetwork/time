# Starting a production-profile network on the version-5 engine

This is the order of work for starting a network with the production profile: twenty starting validators, all new time to validators, the stake hand-over rule, two-day recovery delays, and owner accounts that are protected from the first block. It covers the genesis ceremony, where the validators run, and the first months.

**What this does not allow.** The engine accepts only `time-devnet-v4-` chains and every binary reports `publicLaunchAllowed=false`. A network started this way is a full rehearsal of a launch, with real operators, regions and keys. It is not a network that may hold value. That needs three more things: the devnet guard lifted in the engine, an external security audit, and the signed gates of `deploy/launch-check.mjs`. These are decisions for the project owner, not steps in this guide.

## 1. The genesis ceremony

Nobody has to trust the coordinator.
- Every input is public.
- Each operator signs its own entry with its consensus key, so nobody else can change its owner account, that account's keys or its commission.
- Every operator rebuilds the genesis from the published inputs, finds its own entry in them unchanged, and pins the hash it computed itself.

**The coordinator** first chooses the chain id and the genesis time, writes the ceremony, and tells every operator the chain id:

```sh
node tools/genesis-v5.mjs ceremony --chain-id time-devnet-v4-NAME   --genesis-time 2026-12-01T12:00:00.000Z --out ceremony.json
```

The ceremony holds the network's fee choices. Left out, they are the protocol-4 values:
- a fee of 1,000 microseconds;
- no fee paid on to validators;
- registration at 10,000 microseconds;
- two-day recovery delays.

`--fee-micros`, `--fees-to-validators-ppm`, `--registration-fee-micros` and `--recovery-min-delay-days` change them. Choose a genesis time far enough ahead for every operator to check and start; the tool refuses one less than an hour away.

**What each operator prepares.** The account that owns a validator receives its rewards. On this network it never has one key that can do everything: it starts with four keys, each with one role (`v5/README.md`, "Account security" and "Accounts protected from the start"). The tool refuses an entry without them.

| Key | What it does | Where it lives |
|---|---|---|
| A payment key | Pays up to the daily limit. Sends the validator's upgrade signal. With one recovery key, does everything else at once | Offline, apart from the recovery keys |
| A login key | Signs in to websites. Signs nothing the chain accepts | On the device used for signing in |
| Two recovery keys, or more | Each can freeze the account. Two together replace all its keys, after the wait | Each in its own place, apart from each other and from the payment key |

Each operator also chooses:
- the daily limit, in seconds of currency (`--daily-limit-seconds`). Staking and the fees of the account count against it. A payment above it waits, or needs a recovery key as well;
- the wait and the length of a freeze, in days (`--wait-days`, `--freeze-days`). Each is two days unless said otherwise, and at most thirty. A ceremony with a longer minimum refuses a shorter wait.

Make the login key and each recovery key where it will be kept, one file each. A recovery key made and left beside another one is no second proof:

```sh
node tools/genesis-v5.mjs account-key --out /place-1/recovery-key-1.json --label recovery-1
node tools/genesis-v5.mjs account-key --out /place-2/recovery-key-2.json --label recovery-2
node tools/genesis-v5.mjs account-key --out /login-device/login-key.json --label login
```

Each command prints the public key of the key it made. A key from another tool works as well: the entry takes public keys.

**Each operator**, on its offline enrollment host, before the consensus key leaves it:

```sh
node deploy/keygen.mjs /secure/NEW-operator-directory
node tools/genesis-v5.mjs entry --enrollment /secure/NEW-operator-directory --chain-id time-devnet-v4-NAME   --organization "Example Org" --account-name op_example --commission-bps 1000   --provider aws --region eu-west-3 --owner-key-file /offline/payment-key.json   --login-public-key HEX --recovery-public-keys HEX,HEX --daily-limit-seconds 3600
```

- `validator-entry.json` (in the enrollment directory) holds public keys, the limit and the waits, and the consensus key's signature over the entry and the chain id. Send it to the coordinator and keep a copy: `check` needs it.
- The owner key file holds the payment key of the account. It is also the key the account is known by.
  - It must be outside the enrollment directory, which goes to the signer.
  - It is readable by your user only, on Windows too. So is every file `account-key` writes.
  - Keep it offline, and apart from the recovery keys.
  - To use a key you already hold instead, pass `--owner-public-key HEX`, and no key file is made.
- `--proofs N` asks for more than two proofs for a root operation. It needs as many recovery keys.
- `consensus-enrollment.json` then goes to the remote signer and nowhere else (`deploy/README.md`).
- `node-identity.json` goes to the validator host.

No key of an owner account may be a consensus key, and no key may be on two accounts. `build` refuses both and names the operators.

**Account names.** A production network refuses a new account name that looks like a name that exists (`v5/README.md`, "Names that look alike"). The ceremony writes that setting, `distinct_names`, into the genesis, and the node refuses a production genesis without it.
- The twenty owners' names must not look alike either: the node would refuse the genesis. `build` finds such a pair first and names both operators (`op_1` beside `opl`, `acme` beside `ac_me`). One of them makes a new entry with another name.
- A name of underscores alone is refused when the entry is made.
- The rule holds from the first block and cannot be added later. Choose the names with that in mind: whoever holds a name keeps every name that looks like it out.

**Waits, and accounts protected from the start.** The ceremony writes two more settings, and the node refuses a production genesis without either.
- `waits_survive_stops`: the waits and freezes of account security do not run while the chain is stopped (`v5/README.md`, "Waits that survive a stop"). A stop still takes up to five minutes off each wait.
- `protected_registration`: a new account can be registered with its keys in their roles, and the genesis can list accounts that start that way (`v5/README.md`, "Accounts protected from the start"). The ceremony lists all twenty owner accounts.
- Neither can be added to a network later.

**Service records.** The ceremony writes one more setting, `service_records`, last in the genesis, and the node refuses a production genesis without it (`v5/README.md`, "Service records").
- From the first block the chain keeps facts that no rule reads yet: when each validator was registered and under which key, how many blocks it was to sign and signed, week by week, who proposed the blocks that left its signature out, every punishment, how long each stake has been in place, and when each account was created. A later rule may give a say only to validators and stake with a long, clean history; it could not measure the time before the records began.
- They cannot be added to a network later: whatever happened before they began is lost for good.

**The coordinator** collects the entries as they arrive, then builds:

```sh
node tools/genesis-v5.mjs collect --out entries.json operator-*/validator-entry.json
node tools/genesis-v5.mjs build --ceremony ceremony.json --entries entries.json --out genesis-NAME
```

`collect` checks every signature and writes the list in one order. `build` needs exactly twenty entries and writes four public files:
- `genesis.json`: CometBFT's genesis;
- `genesis.sha256`;
- `network.json`: the manifest the gateway and wallets load;
- `report.json`: the settings, the hashes of all inputs and outputs, and who runs how many validators where.

The coordinator publishes `ceremony.json`, `entries.json`, `genesis.json` and `network.json`.

**Every operator** checks from the published files, with its own entry:

```sh
node tools/genesis-v5.mjs check --ceremony ceremony.json --entries entries.json --genesis genesis.json   --network network.json --entry /secure/NEW-operator-directory/validator-entry.json
```

`check` fails unless three things hold:
- your entry is in the list exactly as you made it;
- the genesis is byte for byte the one these inputs give;
- `network.json` is byte for byte the manifest they give.

Then:
- compare the printed hashes (`genesis_sha256`, `network_json_sha256`, and the two input hashes) with the other operators over a second channel;
- put `genesis_sha256` in your operator settings.

The tool reads only files in the form it writes: two-space JSON with each key once and one newline at the end. A file edited by hand, or with a key written twice so that it reads one way and parses another, is refused. Pass the files on exactly as they are. Anything that changes line endings on the way (git with `autocrlf`, some editors and mail clients) makes the tool refuse them.

**What the tool writes.**
- Account `i` owns validator `i`, in the order of the validators' consensus keys.
- Account `i` starts with the keys, the limit and the waits of its entry, and with no key that holds every power (`protected_accounts` in the genesis). Its payment key is the key it is known by.
- Each validator starts with the production power: one minimum bond, 86,400 seconds.
- Keys are refused if the node would refuse them, points of small order included. The engine tests compare the two on two thousand keys.
- The protocol-4 format also needs bitcoin, treasury and auction sections. On this network their actions are refused (kinds 40 to 42 and 60 to 63). Their keys are points derived from a hash of the chain id, so nobody holds them; anyone can recompute them.
- The consensus parameters are the ones the application sets at InitChain.

`v5/tests/production_genesis.rs` starts the node from such a genesis, with twenty validators, and runs blocks on it.

## 2. Where the validators run

`report.json` counts validators by organization, provider and region. These labels are what each operator declared; nothing can prove them. It warns about two thresholds:
- One party running more than a third of the starting validators can stop the network by going offline. If it signs twice, it can also help two conflicting blocks be finalized; the evidence of that is punished afterwards.
- One party running more than two thirds can sign blocks on its own.

This applies to an organization, a cloud provider or a region alike.

While one organization runs all twenty starting validators, the report warns that it runs more than two thirds. That is true, and it stays true until independent validators hold stake (section 4).

**On one provider.** Regions protect against a region failing, not against the provider. An outage of the whole provider, a suspended account, or a stolen cloud login takes all twenty at once. Use a separate cloud account per group of validators, with its own credentials and hardware keys for its administrators. Within it, spread the twenty over at least four regions, at most six in each, so that no single region takes more than a third.

**On two providers.** At most thirteen validators on either. With two, one always holds at least half, so a full outage of either one stops the network; only a third provider removes that.

**Sentries.** Each validator connects only to its own sentries, at least two, in the same region and on separate hosts.

**Lease controllers.** A validator started by the kit runs only while its host holds a fresh signer lease, and a lease lasts at most five minutes. Whatever issues the leases is therefore a point whose failure stops validators. `deploy/lease-controller/` is a reference controller; `docs/design/signer-lease-controller.md` says what it promises and what it does not.
- A controller that is down stops every validator it serves within about four minutes, and each must then be started by hand. Twenty validators behind one controller means one failure halts the network.
- Run at least four controllers, each for its own consensus keys, and none for a third or more of the voting power: at most six of twenty equal validators. Never two controllers for one key.
- Each controller has its own host, authority key and state. Each validator host pins only its own controller's authority in its trust file.
- Put a controller in the region of the validators it serves, on another host, with other credentials.
- A lease is checked by the guard every five seconds, not by the signer at every signature. It does not replace the rules for the signer in `deploy/README.md`: never copy or restore a signer's state, and move it together with the key.
- The controller's clock matters as much as a validator's: it assumes every clock within five seconds of true time.

**Clocks.** Every validator host keeps time with NTP. On AWS, use chrony with the Amazon Time Sync Service (`169.254.169.123`). A node whose clock is off cannot judge block times.

## 3. Starting

The deployment kit does the work; `deploy/README.md` explains every step. For one network, the order is:

1. **One release for everyone.** The coordinator runs `node tools/release-v5.mjs`, then `deploy/build.mjs build` and `node deploy/verify.mjs --engine v5`. The release must carry `"engine": "v5"` and the image is pinned by digest. Each operator rebuilds the image from the release and compares digests before running it.
   - Only a v5 release starts `time-node-v5`.
   - A v4 release, or a kit older than the v5 port, starts the version-4 engine. That engine refuses this genesis at InitChain: it does not know `all_new_time_to_validators`.
   - A v5 release before 0.9.0 refuses this genesis too: it does not know `waits_survive_stops`, `protected_registration` and `service_records`, and one made before the rule for names that look alike does not know `distinct_names` either. Programs that printed 0.8.0 were development builds and were never released; none of them is to run on a network with this genesis: those built before the service records do not know `service_records`. This release prints `time-node-v5 0.9.0`. Two programs printed `time-node-v5 0.7.0`, with and without the rule for names; the release id tells those apart.
2. **Each validator host.**
   - Fill `settings.example.json`: `release_id`, the `chain_id` from the ceremony, the `genesis_sha256` you computed with `check`, your consensus public key and at least two sentry peers.
   - Import `consensus-enrollment.json` into the remote signer. The kit has no file-validator fallback.
   - Obtain a signer lease scoped to this release, genesis, chain, key and `"engine": "v5"`. A lease lasts at most five minutes, so something must keep issuing them: the lease controller of your organization (section 2, "Lease controllers"). With the reference controller, the operator approves the release and assigns the key to the host on the controller, and `deploy/lease-agent.mjs` on the host asks for the lease, checks it with the guard and keeps it fresh (`deploy/lease-controller/README.md`, "First start"). Check the clock of the controller host first: every wait is counted on it. The first lease for a key comes six minutes after the key was assigned on the controller: plan for it before the genesis time.
   - The controller must refuse a v5 lease for a network that runs version 4. On fresh volumes, that refusal is the only thing that keeps a v5 node off a v4 network. The reference controller is bound to one genesis and one engine and refuses the other.
   - `clock_tolerance_seconds` is optional: from 1 to 60, default 30. A validator refuses a proposed block dated further ahead of its own clock than that, so keep NTP running; a node whose clock lags refuses honest blocks.
   - Every validator runs the same engine version. Version 0.6.0 changed consensus rules (the clock check and automatic double-sign penalties), so 0.5.0 and 0.6.0 nodes never share a network; 0.7.0 accepts the validators' upgrade signals, which 0.6.0 rejects, so those two never share one either. 0.9.0 knows more genesis settings (`waits_survive_stops`, `protected_registration`, `service_records`), which this genesis carries and which 0.7.0 refuses at InitChain; on a network without them the two programs follow the same rules. 0.10.0 knows one more genesis setting, `market` (`spec/market.md`), which a 0.9.0 node refuses at InitChain; the two programs have not been run together on one network. From 0.7.0 on, the rules of a running network change only through the upgrade mechanism (`docs/design/upgrade-mechanism.md`): a version scheduled on the chain at least 21 days ahead, the release that implements it installed before its start, and exit code 4 for a node that was not replaced. `deploy/README.md`, "Upgrades and exit code 4", is the runbook, including the coordinated stop of an emergency.
3. **Before the genesis time,** start the stack from the v5 files: `deploy/compose.v5.yaml` (project `time-v5-private-devnet`) or the unit `deploy/time-v5.service`. They start with fresh ledger and consensus volumes, and the launcher writes a marker binding both volumes to this engine, genesis and chain. A later start with another engine or genesis is refused. CometBFT waits for the genesis time and makes the first block once more than two thirds of the power is online, so 14 of the 20 validators.
4. **Check:** `node deploy/operator.mjs probe SETTINGS` must report engine v5 and the supply identity. `deploy/monitor.mjs` exposes readiness and metrics.
5. **Wallets and shops** use `network.json` from the ceremony as the gateway's trust manifest (`deploy/gateway/README.md`). Give operators its hash through a channel other than the gateway.

A node that exits with code 3 lost its CometBFT connection. Read "Stopping and exit code 3" in `deploy/README.md` before restarting anything; never wipe a volume to make a restart work.

## 4. The first months

**The owner accounts start protected.** Each has the keys, the limit and the waits of its entry from the first block (section 1), and no key that can do everything. What is left to do:
- Run the alert watch (`deploy/watch/README.md`) on all twenty owner accounts from the first day, so a payment or a key replacement started by someone else is seen while it still waits.
- Check that each recovery key can be reached, and that no two are in one place. An owner left with a single proof cannot repair the account.
- Mind the daily limit. Staking counts against it, and so does a validator's repair of its own collateral, which is refused while the account is frozen. A payment above the limit waits two days or more, or takes the payment key and one recovery key together.
- After a stop of the chain of more than five minutes, waits and freezes end later than the chain's time says, by the stops. The wallet and the alert watch read the clock of the waits and give such a date as the earliest ("not before", "at the earliest"). The alert watch did so after a real stop of nine minutes, on a laboratory network on 23 November; the wallet ran on such a network only where the chain did not stop, and across a stop on stand-in chains only (`v5/README.md`, "Waits that survive a stop"). The chain itself counts right.
- Not verified: how an operator uses these keys afterwards. The wallet makes its own keys from passwords, and no step that loads a key file made by this tool into it was tested. Rehearse it before the start: sign in, pay within the limit, freeze and lift the freeze with these four keys.

**New time goes to the starting validators.**
- Each block pays all its new time, at most 60 seconds, to the validators that signed it.
- At first that means only the twenty starting validators, whose voting power is lent by the bootstrap rule. The stake hand-over rule (`v5/README.md`) keeps more than half of the power with them until independent stake has held its target for 14 days, with at least seven funded independent validators and day 90 at the earliest.
- Who receives this early time and what they do with it decides how fair the launch is. Publish the plan.

**Bringing in independent validators.**
- An outside validator needs its own minimum bond: 86,400 seconds in the production profile.
- In the first months nobody holds that much except the starting validators' owners. So early validators are funded by them, or by people who stake through them, until rewards spread.
- Selection keeps any single key below a third of the power, and power changes are rationed to under a third an hour (`pos/README.md`). A key count says nothing about who controls the keys.

**Retiring the starting validators.**
- Retire them only after the hand-over has happened, one at a time.
- Never let what remains fall below seven active validators.
- Never switch off validators that together still hold a third of the power: the network would stop.
- Unbonding takes 14 days, during which stake can still be slashed for double signing. Keep each retiring validator's signer fenced until its key is out of the roster.

**Watch, every day:**
- missed blocks;
- peers;
- the clock offset on every host;
- disk on the ledger and CometBFT volumes (both grow with every block);
- signer lease freshness (`node deploy/lease-agent.mjs status CONFIG 120` on each validator host), and that every lease controller answers (`GET /health`);
- the clock offset on every lease controller;
- the alert watch's health;
- the concentration of power by organization, provider and region, against the thresholds in section 2.

## 5. After the start: history, joining nodes, public services, upgrades

Each point below is described in full where the link says. None of them has run on a network of real operators yet.

**Nodes that keep every block.** Run at least two full nodes, not validators, that were synced from genesis and keep every block (no `keep_blocks` in their settings).
- The HTTP API, the explorer and gateways for wallets and shops must read from such a node. A node that prunes, or that joined from a snapshot, cannot answer for old blocks.
- They are also what a lost ledger is rebuilt from, and what a new node that syncs from genesis downloads from.
- A validator may prune (`keep_blocks`, 2,000,000 or more) once those nodes exist. See `deploy/README.md`, "Snapshots, replay, state sync and pruning".

**A node that joins later** has two ways in.
- *From genesis:* it downloads and executes every block. It has then checked every rule itself. This is what the kit does, and what a new validator should do while the chain is short enough.
- *From a snapshot (state sync):* it starts from a recent state that it checks against validator signatures, without executing the blocks before it. The operator configures it by hand, with a trusted height and block hash taken from a source they trust (`v5/README.md`, "Joining from a snapshot (state sync)"). Two limits follow:
  - For about 23 days after its restore, such a node stops if a block carries evidence about a height before its snapshot, and must sync again. Keep validators that restored within that time under a third of the voting power, and activate a new validator that joined this way only after it.
  - Its recount (`--audit`) says that it did not verify the history before the snapshot.
  - This way in has run once, on 2026-11-18, on a laboratory network of seven validators: a node that was not a validator joined from a snapshot and had caught up 25 seconds after its start, on a chain of about 1,200 blocks with a very small state. It has not run for a validator, for a state of realistic size, or with evidence about a height before the snapshot (`v5/README.md`, "What ran on a network, and what did not").
- For a snapshot to be on offer, nodes set `state_sync_snapshot_blocks`, the same number on every node.

**Public services.** Each is one process with its own config file and README. None holds a validator key.
- *The HTTP API and its index* (`deploy/api/README.md`, `docs/integration-guide.md`): what exchanges, shops and wallets integrate with. With `"serve_explorer": true` it also serves the explorer pages (`web-v4/explorer/README.md`), where anyone looks up a block, an action or an account and their own browser checks the proofs.
- *The gateway for wallets* (`deploy/gateway/README.md`).
- *The alert watch* (`deploy/watch/README.md`): run it for the validators' owner accounts from the first day (section 4).
- *The faucet* (`deploy/faucet/README.md`) is for test networks only. It refuses any other chain.
- Give every service the `network.json` of the ceremony, and publish its hash through a channel other than the services themselves: a wallet, a shop or an explorer page is only as sure as the manifest it starts from.

**Changing the rules.** After the start, the rules change only through an upgrade that validators schedule on the chain (section 3, point 2, and `deploy/README.md`, "Upgrades and exit code 4").
- A plan needs four fifths of the voting power and gives at least 21 days' notice. It is cancelled if support falls under three quarters.
- Each validator's owner signals support from the wallet, in the tab "Validator signal", with the owner account's key that may spend (`web-v4/wallet/README.md`, "Validator signal"). The owner types the version, the specification hash and the start time from the release announcement, after installing the release on the validator and checking that the node lists that version with that hash. The same tab withdraws support.
  - Publish the three values with every release, through the channel operators already trust for release hashes: the version, the hash of `spec/protocol-N.md`, and the start time as microseconds of network time and as a date in UTC. Every owner must signal exactly the same three values, or their votes do not add up.
  - A wallet can send the signal only through a gateway whose node runs the new release: other nodes refuse it by their own policy. Plan the order: install, check, then signal.
  - The owner accounts of the starting validators need a key that may spend within reach for this. Decide before the start who holds it and how they are reached.
  - Not verified: the wallet tab has not been run in a browser and has sent no signal on a live network. The upgrade rehearsal sent its signals from the test harness. Include the wallet tab in the next rehearsal.
- **The order of work.** A node admits and proposes a support signal only for a version its own program implements, so a signal sent before any validator runs the new release is refused where it is handed in, and none enters a block.
  1. The release that implements the new version is published and verified by every operator (section 3, point 1).
  2. Validators install it, one at a time. It runs the present rules until the start.
  3. Owners signal, each through a node that runs the new release. Wait until enough validators run it for the chain to go on at the start.
  4. The plan is scheduled at four fifths, and the notice runs to the start time the signals named. The remaining validators install the release in that time.
  5. At the start, validators with more than two thirds of the voting power must run the new release, or the chain waits for them.
- **How many of the twenty.** While the twenty starting validators hold all the voting power in equal parts, sixteen schedule a plan and fifteen keep it scheduled. Five that do not signal keep every plan from being scheduled; after scheduling with exactly sixteen, the second withdrawal cancels the plan and the next one starts its 21 days from zero. Fourteen must run the new release at the start. More than sixteen supporters give a margin against withdrawals, and owners should signal only once at least fourteen validators run the release.
- **When independent validators hold part of the power** (section 4), each starting validator weighs less. At 90% of the power, eighteen of the twenty schedule a plan without anyone else and seventeen keep it; at 85%, nineteen and eighteen; at 80%, all twenty and nineteen. Below 80% the twenty cannot schedule alone, and below 75% they cannot keep a plan alone: independent validators must signal too. The twenty can still keep any plan from being scheduled while they hold more than a fifth of the power, and cancel one while they hold more than a quarter; until the hand-over they hold more than half.
- **Which program a validator runs.** `time-node-v5 --version` prints the release's line (`time-node-v5 0.10.0 protocol=4 devnet-only publicLaunchAllowed=false` for this one), and a running node lists the versions it implements in its `/status` (`deploy/README.md`, "Which program runs"). A line with `rehearsal=5` is the rehearsal build: never on this network.
- **A validator that was not replaced by the start** commits the last block under the old rules like everyone, then stops by itself: the node prints `STOPPED FOR UPGRADE` with the version and the heights and ends with exit code 4, and CometBFT ends after it with exit code 0. Nothing is lost and nothing is deleted: install the release and start the stack on the same volumes.
- Wallets, the alert watch and the explorer learn of a plan from proven state. The watch tells owners when one is scheduled or cancelled, and when it runs a release that does not implement the scheduled version.
- Rehearse every upgrade first on a test network that runs the same release, with the same steps the operators will take.
- **A fault that cannot wait 21 days.** There is no faster vote, and there will not be one. The procedure is `docs/emergency-fix.md`: a fix that changes no rule, a rule fix at a height the validators agree on, and a stop in the middle of a block.
  - Read it before the start, not when it is needed. It lists what must be ready beforehand: a private security contact for every validator, a private channel, a second channel to compare hashes over, and a rehearsal by the operators themselves.
  - What an operator types with this kit, in each of the three kinds, is in its section 13. In short:
    - *A fix that changes no rule (A):* one validator at a time, `systemctl stop time-v5`, pin the fix release and approve it on the lease controller, wait until the chain is 100 blocks past the validator's last signature, `systemctl start time-v5`.
    - *A rule fix at an agreed height (B):* in groups of less than a third of the votes, stop the stack, add `"stop_after_height": H` to the settings, wait 100 blocks, start it. After `H` every node ends with `STOPPED AS ASKED`. Recount a copy of the ledger volume and send the height and the root. When the coordinators say "start": pin the fix release, remove `stop_after_height`, approve the release, then `node /opt/time-v5/context/deploy/operator.mjs resume-order /etc/time-v5/operator/settings.json H:ROOT` and `systemctl start time-v5`.
    - *A stop in the middle of a block (C):* send the four values of the node's last lines. When the coordinators say "start": pin the fix release, approve it, then `node /opt/time-v5/context/deploy/operator.mjs resume-order /etc/time-v5/operator/settings.json S-1:R` and `systemctl start time-v5`.
  - **Why the resume order.** After a stop of the whole chain every validator signed the last blocks, and the kit's CometBFT refuses to join while one of the last 100 blocks carries its own signature (`double_sign_check_height = 100`). No block comes, so no validator could start again. The order lets each validator start once without that check, only on the agreed state (`--expect-root`), and only after a node that stopped by itself; every later start has the check on again (`deploy/README.md`, "A chain that stood"). Never write an order on a machine that is not the one validator the key belongs to, and never copy or restore a validator host while the chain stands: the kit cannot tell such a copy from the host.
  - Not verified: no operator has followed it. Its cloud rehearsal ran on 23 November, by the test harness and without this kit, on networks of seven laboratory validators (`docs/emergency-fix.md`, section 12, has the times). The kit's resume order ran once on real machines the same day, in the harness's kit rehearsal on seven validators in one region: after a coordinated stop with the kit, each validator was refused without an order, an order with another root was refused by the node, and with the agreed root the chain went on and every validator signed (`deploy/README.md`, "A chain that stood"). That run started again the release that had stopped; no fix release has gone through this kit.
- **What has run.** One upgrade, on 2026-11-18, on a laboratory network of seven validators on AWS under CometBFT 0.38.26, with the node and CometBFT started directly by the test harness and a key file (`campaign/README.md`). Replacing the program on a validator took 5 to 8 seconds; the last block under the old rules was dated 0.019 s after the start; two validators left on the old program stopped with exit code 4, block production paused about 2.3 s, and the two were back and signing 7 and 9 seconds after they were started on the new program. A coordinated stop left all seven at the same height and root. Not run: this kit with its image, remote signer and leases; independent operators; the 21-day notice (the laboratory notice is 120 seconds); a chain that waits for more than a third of the votes; a plan postponed by a safety hold or cancelled because it could not activate (`v5/README.md`, "What ran on a network, and what did not"). The emergency switch ran on 23 November, by the test harness and without this kit, on laboratory networks (same place).
