# Foundation Bitcoin treasury: custody and destination control

The user's selected economic direction is **Bitcoin bids paid to the Time foundation to fund development and network work**. This is not a burn or a promise that seconds are redeemable for Bitcoin.

This crate implements and tests the destination-policy state machine below. **It is an offline prototype, not wired into the running devnet's consensus, Bitcoin verification or bid admission. No real deposit address has been configured, and the wallet must continue to label earning as synthetic.** The `Context` API deliberately documents its external validation requirement; supplying an arbitrary height is not a Bitcoin proof.

## Two different risks

A Bitcoin address is public. A stolen **Bitcoin spending-key quorum** can spend existing treasury funds. A stolen **Time policy-governance quorum** can authorize a different destination for future bids. Use distinct keys, devices and responsibilities for those operations; do not use a validator key or a web-server secret for either.

The proposed custody profile is a 4-of-7 native SegWit multisignature script using sorted compressed public keys. The code constructs the actual P2WSH script and network-encoded address using rust-bitcoin. Bitcoin Core supports `wsh(sortedmulti(...))` descriptors. [Bitcoin Core descriptor reference](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md).

The 4-of-7 and 5-of-7 thresholds are project design choices, not security certifications or thresholds prescribed by Bitcoin. Signers must be genuinely independent, with protected backups and a verified shared descriptor. A coordinator displaying an address is insufficient: each signer must verify the wallet configuration and receiving/change addresses on its trusted device. [Bitcoin Secure Multisig Setup, BIP 129](https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki).

## Implemented policy controls

The prototype uses seven separate Ed25519 governance public keys with five required approvals. Only public keys exist in the policy. It implements:

1. A genesis-pinned policy containing the seven Bitcoin public keys, governance keys and revision. No HTTP administrator or environment variable changes an active policy.
2. A proposed next revision signed by five current governance keys. Five proposed future governance keys must also acknowledge the exact policy; this prevents accidental installation of an unacknowledged council. This acknowledgement is **not an independent veto** against a compromised current council, because that council can propose attacker-controlled future keys.
3. Activation only after **both** seven accepted Time days and 1,008 additional validated Bitcoin blocks. Bitcoin block time is variable; 1,008 blocks are not an exact wall-clock week. The proposal expires within 30 Time days.
4. A five-signature emergency pause that stops accepting new foundation bids without selecting a replacement recipient. Pause does not disable Bitcoin spending from existing UTXOs.
5. Explicit cancellation and resume, each signed for the network, active policy, control sequence, complete pending policy/schedule and a short deadline. Rotation preserves a pause; it never silently resumes deposits.
6. Exact revision/sequence checks, distinct signers, strict Ed25519 signatures, canonical key encodings, network separation, immutable failure behavior and monotone validated-chain coordinates.

The complete pending-policy hash includes destination keys, future governance keys, Time activation bound, Bitcoin activation bound and proposal expiry. The independent review reproduced missing schedule binding in the first implementation; that defect is fixed and has an adversarial regression.

## Incident behavior

| Incident | Protection and response | Limit |
| --- | --- | --- |
| Website/RPC database displays an attacker's address | A production wallet must derive/verify the recipient from a proved, authorized policy, rather than trust the website field. | Consensus/wallet policy integration is still required; this crate alone does not authenticate an RPC response. |
| One Bitcoin signer is compromised | One key cannot spend a 4-of-7 output. Pause new bids, prepare replacement custody, verify it with all signers and schedule rotation. | Four compromised Bitcoin keys can spend existing funds. A Time governance pause cannot undo that spend. |
| Four Bitcoin spending keys are compromised | Independent governance can pause new bids and schedule a new destination. Move remaining old UTXOs with the old Bitcoin quorum if still possible. | Stolen BTC cannot be recovered by changing an address or editing the Time chain. |
| One governance key is compromised | A single key cannot pause, cancel or redirect the destination. Replace exposed governance through the reviewed delayed process. | Independence and secure key storage remain operational requirements. |
| Five current governance keys are compromised or collude | The delay gives observers time to detect an announced redirect and stop bidding. | The attacker can authorize a redirect after the delay, including choosing its own new council. No guarantee against an authorized quorum is claimed. A separate pretrusted veto authority would be a further governance change, with its own liveness and recovery costs. |
| Some keys are lost | Thresholds tolerate limited key loss; independently held backups and a rehearsed replacement procedure are necessary. | Losing enough governance keys can prevent destination updates. Losing enough spending keys can lock existing BTC. |

Rotating a destination protects **future payments**. It does not move old Bitcoin automatically. A normal custody migration requires a separately reviewed Bitcoin PSBT spending old UTXOs to the independently verified new script, approved by the old 4-of-7 Bitcoin quorum. Do not broadcast or configure mainnet destinations until the signers complete that ceremony.

## Required before real Bitcoin earning

The production receipt must bind an actual Bitcoin transaction/output to the Time network, payer account, auction epoch and treasury-policy revision. For example, a bounded commitment can use `TIMEBID1 || network32 || account8 || epoch8 || policyRevision8`; actual wire rules still need a reviewed consensus version. Validators must verify the exact output amount and script, validated Bitcoin chain inclusion and the confirmation policy, then mark that outpoint consumed exactly once. A caller-supplied weight or transaction ID is not evidence.

The production implementation still needs header/PoW/difficulty/chain-selection validation or an explicitly trusted locally validated Bitcoin Core integration, authenticated checkpoints, reorganization handling, old-policy cutoff/grace rules, receipt deadlines, outpoint replay protection, and consensus/wallet wiring. Bitcoin confirmation is probabilistic: a sufficiently deep reorganization cannot be made impossible by choosing a fixed number of confirmations. Do not silently reverse finalized Time payments; define and test the response to that failure first.

Validator admission/slashing, independent operators, the 90-day genesis handoff and external security review remain separate launch gates. Funding a foundation does not itself implement permissionless proof of stake.

## Reproduce

From `production`:

```powershell
$env:CARGO_BUILD_JOBS = '1'
.\tools\cargo.ps1 test --manifest-path treasury/Cargo.toml --locked
.\tools\cargo.ps1 clippy --manifest-path treasury/Cargo.toml --locked --all-targets '--' -D warnings
```

Nine tests exercise actual Bitcoin script/address construction and actual signatures, including substitution, duplicate signers, insufficient old/new quorums, both delays, expiry, control-role/network replay, full pending-schedule binding, pause persistence and coordinate rollback. These tests do not constitute an independent audit or a production Bitcoin deposit service.
