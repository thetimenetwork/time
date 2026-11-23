# The signer-lease controller

The kit's guard (`deploy/operator.mjs`) runs a validator only while a file on the host holds a fresh **signer lease**: a short statement, signed by an authority the host trusts, that this host may run this consensus key on this release, genesis, chain and engine. This folder is a reference **controller** that issues those leases, and `deploy/lease-agent.mjs` is the **agent** that keeps the lease file fresh on each validator host.

`docs/design/signer-lease-controller.md` is the design: what is promised, on which assumptions, and why. This file is the operator's guide.

## Read this first: what a lease does not do

- **A lease does not stop a signer from signing.** The guard checks the lease every five seconds and stops CometBFT when it is no longer valid. Your remote signer never sees the lease.
- The controller never issues leases for one consensus key to two hosts so that both are valid at the same time, also across its own crashes and restarts. **That holds under conditions**: every clock is within five seconds of true time; one controller, on one state directory, signs with the authority key; no key is stolen. The design states them (section 4) and says what is checked about the clock and what is not (section 5.5).
- That keeps two *validators started by this kit* from running one key at once. It does not make a lease useless on a second machine: **a lease file copied to another machine together with the settings is accepted by the guard there**, which cannot know which machine it runs on.
- It does **not** protect you when a signer's record of what it last signed is copied, restored from a backup, or left behind when a key moves. With a remote signer, that record is the only thing that prevents a second signature at the same height and round.
- It has run beside CometBFT 0.38.26 and two remote signers on several machines, in four short campaigns of one day (the kit rehearsal, `campaign/README.md`, "The deployment kit, rehearsed"). See "What the rehearsal showed" and "Not verified" at the end.

**What you must still do, always:**

1. Never copy a signer's state and never restore it from a backup. Move it with the key, and delete it where it was.
2. When a key moves to another host, carry over the signer's last signed height, round and step, or wait until the chain has passed that height. **Do not move a key while the chain stands still unless the signer's state moves with it.** `deploy/restore-check.mjs` checks such a hand-over.
3. Wipe the key from the signer of a host that no longer holds it.
4. Never clone a validator machine, and never restore one from an image.
5. Keep NTP running on the controller and on every validator host, and alert on clock offset.
6. Never run two controllers for one consensus key.

## The declaration about the signer

The guard accepts only a lease that says `"enforcement": "EVERY_SIGNATURE"`. That field states that the signer on the host refuses to sign unless a fencing check passes **at every signature**. The controller cannot check a signer. So it writes the field only for a host whose entry in the config says `"signer_fencing": "EVERY_SIGNATURE"`. **That entry is your declaration, as the operating organization, about that host's signer.** Every lease also says `"enforcement_basis": "OPERATOR_DECLARATION"`, and the service logs at start which hosts carry the declaration.

Before you write it, know this:

- An ordinary remote signer keeps its own record of the last height, round and step and refuses to sign below it. That is necessary. It is **not** a fencing check at every signature.
- It is reported that no maintained remote signer for CometBFT 0.38 can check a lease or ask an outside authority at every signature without custom code. This project has not verified that report.
- If your signer is such an ordinary signer, the declaration is not true for it. The design document says so plainly (section 10.3) and recommends that the kit accept an honest second value instead. Until the project decides that, the choice is yours and the risks of the section above are yours to cover by procedure.

A host with `"signer_fencing": "NOT_DECLARED"` is known to the controller and gets no lease (`SIGNER_NOT_DECLARED`).

## How many controllers

A controller that is down stops every validator it serves within one lease, about four minutes, and each must then be started by hand. **Twenty validators behind one controller means one failure halts the network.**

- Run at least four controllers. No controller serves a third or more of the voting power: at most six of twenty equal validators.
- Each controller has its own host, its own authority key, its own `fence_domain` and its own state. A consensus key belongs to exactly one controller.
- Each validator host's trust file pins only its own controller's authority. The guard accepts any pinned authority with the role `signer_lease` for any key, so the trust file is what keeps another controller's leases out.
- Put a controller in the region of the validators it serves, on another host, with other credentials.

There is no standby that takes over by itself, and no way to skip a wait.

## Setting up a controller

On a host that is not a validator host, with Node 26 and this kit. The host admits the lease port from its validator hosts and the operator's login, and nothing else.

```sh
node deploy/lease-controller/ctl.mjs keygen authority /etc/time-lease-controller/authority.json lease-authority-1
```

It prints the entry for the trust files. The key file is created with mode 0600 and is never replaced; the controller refuses a key file that other users can read. Copy `config.example.json`, fill every placeholder, and start:

```sh
node deploy/lease-controller/start.mjs /etc/time-lease-controller/config.json
```

| Setting | Default | Meaning |
|---|---|---|
| `data_directory` | none | An absolute path. The state lives in `state/` under it, one numbered file per change. Only the controller's user may write it. |
| `authority_key_file` | none | The key file made by `keygen authority`. |
| `fence_domain` | none | A name for this controller's fence tokens: lower-case letters, digits, dot, dash, underscore. Never reuse it for another controller. |
| `network.chain_id`, `network.genesis_sha256` | none | The network, as in the operator settings. |
| `network.engine` | none | `"v4"` or `"v5"`: the engine every validator of this network runs. It cannot be read from the genesis. The state is bound to it for ever: the controller never signs a lease for the other engine on this genesis. |
| `hosts` | none | One entry per validator host: `id`, `public_key_hex` (printed by the host's `keygen`), `signer_identity` (the one in that host's operator settings; each host has its own), `signer_fencing` (see above). |
| `host`, `port` | `127.0.0.1`, `8960` | Where the service listens. Give the address of the private link to the validator hosts. |
| `lease_seconds` | 240 | How long a lease lasts. 60 to 280. |
| `clock_skew_seconds` | 10 | Every clock is within half of this of true time, so any two differ by at most this. 1 to 20. |
| `stop_seconds` | 40 | How long after its lease ended a validator may still ask its signer. At least 30. |

An unknown setting is refused. `lease_seconds` plus twice `clock_skew_seconds` may not pass 300: the guard refuses a lease whose dates are further apart.

**What follows from the numbers** (with the defaults): a lease is dated 20 s back, so that a host whose clock is behind accepts it. The **margin** is 60 s (twice the skew plus the stop time). The **start wait** is 360 s. New leases for one key are at least 31 s apart.

**The transport.** The service speaks plain HTTP. Requests are signed by the host, leases by the authority, and a lease names the request it answers. Someone on the path can read which host asks for which key, and can drop traffic so that validators stop; they cannot obtain or change a lease. Run it over a private link, and let the firewall admit only the validator hosts. For `https://`, put a TLS proxy in front. The agent refuses plain `http://` to another machine unless its config says `"allow_plain_http": true`.

**The log** is JSON lines on standard output: each lease issued (host, the first characters of the key, lease id, fence token, expiry), each refusal with its code, and the start. A key that is frozen is logged at level `error`: alert on it. The log holds no key and no signature. `GET /health` answers `{"status":"ok"}`.

## On each validator host: the agent

The agent runs on the host, outside the containers. It needs to write one directory only: the one the lease file is in.

- **Give the lease a directory of its own.** In the operator settings, name the lease as `/operator/lease/signer-lease.json`, and make the directory `lease/` under the operator directory writable for the agent's user alone. The settings, the genesis and above all the trust file then stay out of the agent's reach: it reads them and cannot change them.
- **Who must be able to read the lease.** The containers run as UID 10001 and read the lease through the read-only mount at `/operator`. The agent sets the file's mode to 0644 itself, whatever the umask of its unit (the kit's own unit uses 077). The directory `lease/` must let others enter and read (mode 0755). A lease is not a secret.
- **Who runs the agent.** A user of its own, not root and not UID 10001: it owns `lease/`, the host key file (mode 0600) and its state file.

```sh
node deploy/lease-agent.mjs keygen /etc/time-v5/lease-agent/host-key.json val-eu-1
```

It prints the entry for the controller's `hosts`. Then:

1. Add the authority entry that the controller's `keygen` printed to this host's trust file, with your organization's name.
2. Copy `deploy/lease-agent.example.json` and fill it in.
3. Run `node deploy/lease-agent.mjs run /etc/time-v5/lease-agent/config.json` under your process supervisor, started before the validator stack and restarted when it fails. Restarting the agent is harmless. **Run exactly one agent per host.** Two agents on one host look to the controller like two machines with one host key, and the key is frozen.

| Setting | Default | Meaning |
|---|---|---|
| `controller_url` | none | The controller's address, such as `https://lease.example:8960`. |
| `allow_plain_http` | false | `true` states that the link to the controller is private. Needed for `http://` to another machine. |
| `host_id` | none | This host's id in the controller config. |
| `host_key_file` | none | The key file made by `keygen`. |
| `settings_file` | none | The operator settings the validator runs with, as a path on the host. |
| `operator_directory` | none | The host directory that the containers see as `/operator`. Paths in the settings that start with `/operator/` are read from it. |
| `state_file` | beside the key | Where the agent keeps the nonce of its current request. Keep it on a disk that survives a reboot. |
| `request_timeout_seconds` | 10 | 1 to 60. |

What the agent does each round: it reads the settings and the release manifest, asks for exactly what they name, and checks the answer with **the kit's own guard** before it relies on anything in it. It never installs a lease for another key, release, genesis, chain, engine or signer identity, from an authority the trust file does not pin, one that is not the answer to its own request, one the controller has since replaced (a lease says until when it is sent again), or one older than the installed lease. It writes only the three signed parts of the answer, as a finished file that it renames into place, so the guard never reads half a lease. If the lease file is there and cannot be read as a lease, it asks nothing that round and says so: a host that names no lease while it holds one looks like a second machine. An empty lease file counts as no lease file: a tool that creates the file to set its owner does no harm before the first lease. It asks again after a quarter of the lease's life (60 s), and every 10 s after a failure.

**Monitoring.** `node deploy/lease-agent.mjs status CONFIG 120` prints what the guard says about the installed lease and exits with code 2 when fewer than 120 seconds are left. Alert on it.

## When the controller cannot be reached

- The agent logs `no new lease` with the reason and `installed_lease_seconds_left`.
- The validator runs on until the lease ends: between three and four minutes after the last successful round.
- Then the guard fails with `Attestation expired or future-dated`. The node and CometBFT stop, the monitor reports not ready, and `TimeOperatorNotReady` fires.
- Nothing restarts by itself. When the controller is back, the agent installs a lease again. Then start the stack.

A controller restart of under three minutes goes unnoticed.

## Runbooks

`ctl.mjs` runs on the controller host as the controller's user. It changes the state files beside the running service; the service reads the change before its next answer. `CONFIG` is the controller's config file, `KEY` a validator's consensus public key in hexadecimal.

### First start

1. Make the authority key, write the config, start the service.
2. `node deploy/lease-controller/ctl.mjs CONFIG approve-release /path/to/release.json`. It reads the release manifest, checks it, and refuses a release of the other engine.
3. For each validator: `ctl.mjs CONFIG assign KEY HOST`.
4. `ctl.mjs CONFIG list` shows each key as `WAITING` with the seconds left.

**Check the clock of the controller host before the first start** (`chronyc tracking`, or your time service's equivalent). Every wait is counted on it.

**The first lease for a key comes six minutes after the key was assigned.** A key the state does not know may have a lease running that a lost controller issued, so it waits as if that were so. Do not restart the controller while keys wait: each start begins the wait again.

**Run the controller under a supervisor that starts it again when it ends.** It ends on purpose when it finds that its clock was set while it ran, or that its state files were replaced under it; the last log line says why. A start applies the start rule, and inside the conditions of the design (section 4) that makes a start safe. On a machine whose clock is wrong a start is not safe by itself: see "After the clock was wrong".

### Adding a host

1. On the host: `lease-agent.mjs keygen`, the trust file entry, the agent config.
2. Add the host to `hosts` in the controller config and restart the controller. Hosts with a running lease do not notice.
3. `ctl.mjs CONFIG assign KEY HOST`. A host holds one key.

### Moving a key to another host

For a failed host, a planned migration, or new hardware.

1. Stop the validator on the old host if it still runs.
2. `ctl.mjs CONFIG move KEY NEW_HOST --from OLD_HOST`. It is refused unless `OLD_HOST` holds the key, so that a move is never made on a wrong belief.
3. From that moment the old host gets no lease. The new host gets its first lease when the old host's last lease has ended on every clock, plus the margin: at most five minutes after the old host's last renewal, or six minutes after the controller's last start if that is later. `list` shows the time. Nothing shortens it. Moving back is a move like any other.
4. **While you wait:** move the signer's record of what it last signed together with the key, and delete both on the old host. The lease checks none of this.
5. Start the stack on the new host when its agent has installed a lease.

There is no automatic failover. The controller cannot tell a dead host from one it cannot reach, and a standby that already holds the key is the arrangement most likely to sign twice.

### An upgrade: approving the next release

The network schedules a new protocol version at least 21 days ahead (`deploy/README.md`, "Upgrades and exit code 4").

1. Build and verify the new release. `ctl.mjs CONFIG approve-release /path/to/new/release.json`.
2. On each host, well before the start time: stop cleanly, install the release, pin its `release_manifest` and `release_id` in the settings. The agent asks for the new release at its next round and installs the lease. Start the stack on the same volumes.
3. A key that has had a lease for the new release is refused the old one (`RELEASE_ROLLBACK`). To go back on purpose: `approve-release OLD_RELEASE.json --again`.
4. When every key runs the new release: `ctl.mjs CONFIG retire-release OLD_RELEASE_ID`. It is refused while a key still runs that release.

### Rotating the authority key

The guard reads the trust file at every check, so no validator stops.

1. `ctl.mjs keygen authority NEW_FILE NEW_ID`, with a new id.
2. Add the new entry to every host's trust file, beside the old one.
3. Set `authority_key_file` to the new file and restart the controller.
4. Five minutes later, remove the old entry from every trust file.

**If the key was stolen:** the same steps at once, and step 4 without waiting on any host that can be down for a few minutes. A guard refuses a removed authority at its next check that can read the lease file. While that file cannot be read, the validator runs on until its lease ends, at most five minutes. A thief of the authority key can sign any lease. That alone signs no block. To make two hosts sign with one key they also need a second machine that holds the consensus key in a working signer, and a way to put their lease into that machine's lease file.

### After the state was lost or restored

**First make sure the old controller is stopped for good.** Two controllers with one authority key on two state directories is a mistake the controller cannot catch. It is not the only one: see "Not verified" and the design, sections 4 and 5.5.

**Then check the clock of the machine the controller will run on**, against a time source you trust, before you start anything. A replacement machine that has just booted is where a clock is most likely to be wrong, and every wait is counted on it.

**The service follows only its own line of state files.** Never put files into `state/` while the service runs: stop it first. Each file names the one it was made from; a running service that finds a file it did not descend from stops and says so. After that, start it: the start rule applies to the files that are there.

- **Restored from a copy.** Start the controller. Keys whose lease still runs go on with the same holder. Every other key waits 360 s. A host that renewed after the copy was taken names a lease the restored state does not know; that looks like a copied machine, so its key is frozen. Check that each host is one machine, then `unfreeze`. Commands given after the copy was taken are gone: run `list`, compare with what you know, and give them again.
- **Lost entirely.** Start with an empty `data_directory`. Approve the release and assign every key again. Each waits 360 s from the moment it is assigned.
- **Fence tokens** are taken from the clock, so a controller without memory does not reuse one, as long as the old controller's clock was right. If you cannot vouch for it: read `fence_token` inside `payload` of the last lease file of each validator host and run `ctl.mjs CONFIG refence KEY --above THAT_TOKEN`. A token is a clock reading in milliseconds; a number more than a hundred years ahead of the clock is refused as a typing mistake.
- **A newest state file that cannot be read** is never skipped: nothing falls back to an older file by itself. A start is refused with a message that names the file. A service that already runs stays up and answers every request with an error until you act. If you decide to go on from the state before it, move that file out of `state/` and start: this is a restore from a copy.

### After the clock was wrong

Every wait is counted on the controller's clock. The controller checks three things about it (design, 5.5):

- **The clock is set while the service runs** (NTP steps it, or the machine was suspended): the service notices within a second that the wall clock and the elapsed time disagree by more than `clock_skew_seconds`, stops and says so. Check the clock and start it again. Every wait is then counted again on the corrected clock.
- **The clock reads earlier than the state was last written**: the start is refused, and so is every command, with `FIRST check this machine's clock`. Do that. If the clock is behind, correct it and start.
- **The clock is right and the state was written while it was ahead**: run `ctl.mjs CONFIG clock-was-ahead`, then start. The command writes what a start on the checked clock writes: a key whose issued lease still runs keeps its holder and goes on; every other key starts a new wait of six minutes. It never goes below the end of a lease the controller really issued: if a lease was handed out with dates from the wrong clock, other hosts wait until it has ended, and the command says so. **A small error heals by waiting, and that is the better way:** once the clock has passed the time the state was last written, less `clock_skew_seconds`, a start is accepted and nothing was changed. After a clock that was one minute ahead, that takes under a minute. It is refused when the state holds no time later than the clock. **It trusts your check of the clock and nothing else: run it only after that check.**

What no check catches: a clock that is wrong and stays wrong together with the clocks of the validator hosts (one bad time source for all).

### A frozen key

A request named a lease that is not the last one issued for the key. Either two machines act as one host (a cloned or restored machine), or two agents run on one host, or the host's lease file or the agent's state file was replaced or lost.

1. Find out which. Make sure exactly one machine is that host.
2. `ctl.mjs CONFIG unfreeze KEY`. A new tenure starts, with a higher fence token, after the last lease has ended plus the margin.

Until then no machine gets a lease for the key, and each stops when the lease it holds runs out.

### Replacing a host key

Make a new key on the host, put its public key into `hosts`, restart the controller, and run `ctl.mjs CONFIG move KEY HOST --from HOST`. A host with a new key is a new holder and waits like one.

### After a signer was restored

`ctl.mjs CONFIG refence KEY` gives the same holder a new, higher fence token, after the usual wait. See "Backup, restoration and monitoring" in `deploy/README.md` first.

## What each refusal means

The agent logs the code and the message, and says in the same line that the answer is unsigned. **A refusal is not signed: anyone on the network path can have written it.** Do nothing it asks without checking on the controller itself (`ctl.mjs CONFIG list`). The agent acts on none of it except to wait.

| Code | Meaning | What to do |
|---|---|---|
| `BAD_REQUEST` | Not a lease request. | Use the agent of this kit, in the same version as the controller. |
| `UNKNOWN_HOST` | The controller's config lists no such host. | Add the host to `hosts` and restart the controller. |
| `BAD_SIGNATURE` | The request is not signed by the key registered for the host. | Check `host_key_file`; see "Replacing a host key". |
| `CLOCK` | The request's time is more than 10 s ahead of the controller's clock or more than 20 s behind; or it is not later than the last request that got a new lease for the key; or it repeats an earlier request that was answered, after a later one was served. | Check NTP on the host and on the controller. A recording of an earlier request is refused like this, and so is a request from a host whose clock was set back, which passes by itself. |
| `WRONG_NETWORK` | The host's settings name another chain or genesis. | Check `chain_id` and `genesis_sha256` on the host. |
| `WRONG_ENGINE` | The host's release runs the other engine. | Pin a release of this network's engine. The controller never signs for the other one. |
| `RELEASE_NOT_APPROVED` | The release is not approved here. | `approve-release`, if it is the release to run. |
| `RELEASE_ROLLBACK` | The key already ran a release approved later. | `approve-release OLD.json --again`, if going back is intended. |
| `KEY_NOT_ASSIGNED` | No host holds the key. | `assign`. |
| `NOT_HOLDER` | Another host holds the key. | `move`, after stopping the validator there. |
| `HOST_KEY_CHANGED` | The host's key in the config is not the one the key was given to. | "Replacing a host key". |
| `SIGNER_MISMATCH` | The settings name another signer identity than the config. | Correct one of them. |
| `SIGNER_NOT_DECLARED` | The config does not carry the declaration for this host. | "The declaration about the signer". |
| `WAIT` | The tenure's first lease is not due yet. | Wait. `list` shows the time. |
| `TOO_SOON` | The last new lease is under 31 s old. | Nothing. The installed lease is good. |
| `FROZEN` | See "A frozen key". | `unfreeze`, after checking. |
| `BUSY` | The controller could not decide or save. Nothing was issued. | The agent asks again. If it persists, read the controller's log and check its disk. |

## Files

| File | What |
|---|---|
| `start.mjs` | The service. |
| `ctl.mjs` | The operator's commands. |
| `core.mjs` | Every decision, as functions of a state, a clock value and an input. |
| `store.mjs` | The numbered state files and the lock. |
| `../lease-agent.mjs`, `../lease-protocol.mjs` | The agent and what both sides agree on. They import nothing outside `deploy/`. |
| `*.test.mjs`, `simulation.mjs`, `fixtures.mjs` | The tests. `node --test "deploy/lease-controller/*.test.mjs"` runs them. `review-*.test.mjs` are the tests of an independent review. |

## What the rehearsal showed

On AWS, 2026-11-19 (campaigns `tc-v5-kit-2` to `tc-v5-kit-5`): this controller on a host of its own, an agent on each validator host, each validator running `compose.v5.yaml` with tmkms 0.15.0 or Cosmos-KMS 0.1.0 under CometBFT 0.38.26.
- The first lease for each key came 360 s after `assign`, as stated; the agents installed it within the next poll.
- A second machine (another validator host, signing with its own registered host key) asked for a key held by another host: refused `NOT_HOLDER`. `ctl.mjs assign` of a held key: refused, exit code 2.
- The agent on one validator host was stopped. The installed lease ended 194 s later. The guard logged `The last signer lease that verified ended at ...` 14 ms after the expiry; CometBFT's container ended 211 ms after it (exit code 1) and the node's 273 ms after it (exit code 1). The validator's last vote in the chain was dated 0.6 s before the expiry. The stack stayed down, as the kit's policy says. (In `tc-v5-kit-2`, by hand: 236 ms and 249 ms after the expiry. In `tc-v5-kit-4`: guard 9 ms, CometBFT 209 ms, node 265 ms, last vote 1.1 s before the expiry. In `tc-v5-kit-5`: guard 11 ms, CometBFT 185 ms, node 274 ms, last vote 0.2 s before the expiry.) In none of these did the guard have to kill CometBFT.
- With the agent back, a valid lease was installed within a second.
- The agent logs a `WAIT` refusal at level `error`, also the expected one of a first start.
- The validator could then not be started again on the four-validator network of `tc-v5-kit-3`: `deploy/README.md`, "A validator starts again only 100 blocks after it last signed". On seven validators (`tc-v5-kit-4`, `tc-v5-kit-5`) the operator's start 100 blocks after its last vote joined at the first attempt, and the validator signed again 10 to 11 s later.

## Not verified

- The tests run the controller, the agent and the kit's real guard on one machine, with injected clocks. Beside CometBFT it ran only in the rehearsal above: one controller, a few hours, no controller restart, no move of a key, no clock fault, no lost state.
- That a validator has stopped asking its signer within `stop_seconds` of its lease's end rests on the guard's stop of CometBFT. The rehearsal measured that stop in three campaigns and once by hand (above), and each time CometBFT ended on `SIGTERM`. The guard's kill of a CometBFT that does not end after a lease's end was tested only with a stand-in process; on AWS the same kill ran only after a stop from Compose, once the signer had gone (`tc-v5-kit-5`, `deploy/README.md`).
- The statements about remote signers are another reading of public sources.
- The state files rely on hard links and on `fsync`. The tests cannot cut the power.
- The service does not speak TLS; a proxy in front of it was not tested.
- **Run once on Linux** (2026-11-18, the project's test run on AWS, Node 26: 110 tests, none skipped); every other run was on Windows. Three tests cannot run on Windows and passed there: a real process that ignores the stop signal is killed by the guard; the lease file gets mode 0644 under a umask of 077; a key file that other users can read is refused. A key file behind a link is tested only where the system lets the test make a link.
- **Assumed for Linux, not tested:** that the monotonic clock does not follow a step of the wall clock, and does not count the time a machine is suspended. The controller's clock check and the guard's second deadline rest on it. They were tested with injected clocks, and the controller's once with the real clocks of one Windows machine.
- The numbers are chosen by reasoning, not measured on real hosts.
