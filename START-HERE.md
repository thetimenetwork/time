# Start here

Read the "Status" section of [README.md](README.md) first: the network has not launched, the software accepts development chains only, it has had no external audit, and nothing in it holds real value.

## If you want to read

1. [README.md](README.md): what Time is and what each folder holds.
2. [v5/README.md](v5/README.md): the node application and its rules.
3. [AUDIT-2026-11.md](AUDIT-2026-11.md): the internal security review, with what is fixed and what is open.

## If you want to build and test

The commands are in [README.md](README.md), under "Build and test". They need Rust 1.99.1 and Node.js 26 and nothing else.

## If you want to try the wallet on your own computer

[v4/README.md](v4/README.md) walks through the local test network: create an account, earn test coins, send them, stake, add a second device, recover an account, and sign in to an example shop.

```sh
node tools/start-v4-lab.mjs
```

It runs several validators, a wallet and the example shop on one computer, with test coins that have no value. It expects binaries you have built yourself (the node, CometBFT as [consensus/BUILD.md](consensus/BUILD.md) describes, and Bitcoin Core for its test mode) and downloads nothing. Stop it with `node tools/start-v4-lab.mjs --stop`; it keeps its data and resumes later.

The local network runs the protocol-4 node. The version-5 engine has no launcher of this kind yet: its tests and `time-bench-v5` drive it directly ([v5/README.md](v5/README.md)).

## If you want to run validators

[deploy/README.md](deploy/README.md) describes the deployment kit, and [deploy/PRODUCTION-V5.md](deploy/PRODUCTION-V5.md) the order of work for starting a network with the production profile. Such a network is a rehearsal, not a launch.

## If you found a security problem

Report it privately, as [SECURITY.md](SECURITY.md) says.

---

This file used to be the walkthrough of the first laboratory network (protocol 1). That network's wallet and SDK are not part of the published repository; the walkthrough for the current local network is [v4/README.md](v4/README.md).
