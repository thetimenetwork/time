# V4 wallet and own-app rehearsal

Start the isolated lab from the project root:

```powershell
node production/tools/start-v4-lab.mjs
```

Open the wallet URL printed by the launcher (normally `http://127.0.0.1:8907`) and the separate app URL (normally `http://127.0.0.1:8908`). Earlier V1–V3 source and networks remain separate. Test seconds and mined Bitcoin regtest coins have no monetary value.

Create an `@name` with a strong password. The lab operator sponsors its paid registration commitment; your device signs consent, then reveals the name in a later block. The sponsor cannot manage or spend from your account. Download an encrypted backup from the device screen. The browser creates and locally encrypts a random device key; the password cannot recreate that key after browser data loss. Restore the backup with its existing password, request approval from an existing device, or use an already configured guardian policy.

On **Earn**, approve a regtest bid. The funding helper checks the supported compact receipt budget before broadcasting Bitcoin. Private local Bitcoin Core mines a real test transaction. The wallet relays bounded public headers, submits a signed receipt binding your account, Time network, target epoch and treasury revision, and shows the earning epoch. After close, approve **Claim seconds**. No legacy synthetic bid is used. Send seconds to another finalized `@name`; inspect the amount, fee and recipient before approval.

The own-app page opens the wallet for a separate login challenge. Its backend verifies the device and recovery status from fresh proofs. A payment opens another explicit approval and binds the exact sender nonce, recipient, amount and order reference. Replaying that order from a different approved wallet cannot spend it again after its nonce was consumed. An unrelated action can make a pending quote stale; request and approve a new quote.

Staking uses actual PoS candidate and owner rows. Reward version one splits gross reward between live self collateral, live delegation and any still-voting departure weight. Before bootstrap handoff, the genesis operator's actual remaining virtual weight also counts as owner weight. Commission applies only to the delegated gross share; departures and rounding retain their unallocated share in the bank. Per-block integer rounding can leave very small delegations with zero reward. Delegation is priced at finalized pool NAV. Self bond, self exit and validator registration require separate approvals. Registration takes only a public enrollment and possession proof from the operator's validator node; consensus private keys remain on that node. Announced voting changes become effective at H+2. Every profile retains the full **14-day** exposure window. A self exit remains exposed until actual active/scheduled removal, then waits fourteen days; the wallet does not advertise a fixed unlock time while it remains active. Laboratory stakes/fade/churn differ from production, and the production profile requires at least a two-day guardian recovery delay after quorum. Guardians have seven days to coordinate their approvals.

The trust-refresh panel requires a checkpoint file and a separately authenticated full block hash. After seven days offline, a fresh RPC response cannot silently restore trust. Protect the installed manifest, wallet origin and checkpoint storage. Hardware support is limited to explicit Ed25519 transports through the SDK adapter; arbitrary passkeys or hardware devices are not claimed compatible.

The security inbox collects on-chain observations when checked. For timely warnings while your devices are offline, operate an independent watcher and notification delivery service. Retain encrypted vault backups and merchant receipt archives. Neither public receipt files nor wallet backups make the initial trust anchor self-authenticating.

See [the SDK integration and trust contract](../client-v4/README.md) and [the encrypted backup format](wallet/BACKUP_FORMAT.md). This is a test candidate with real protocol mechanisms, not authorization to accept public funds.

The owned headless Chrome runner uses a fresh isolated profile, never your normal browser profile, and removes its own profile afterward:

```powershell
node production/web-v4/wallet/tests/browser-e2e.mjs --url http://127.0.0.1:8907 --backup --recovery --out production/results-v4/wallet-browser.json
```

Live withdrawal waits fourteen days; the browser check verifies pending exposure and refusal of early withdrawal. Mature withdrawal is exercised by the native virtual-time tests, without shortening the client trusting period or live slash window.
