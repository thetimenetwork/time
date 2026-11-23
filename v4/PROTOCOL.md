# Protocol 4 candidate contract

This is a new development network. It cannot reinterpret a version 2/3 database
or move balances from one. The executable requires `--devnet`, loopback ABCI,
and an explicit database. Public monetary launch and mainnet BTC receipts remain
disabled. The laboratory uses Bitcoin Core regtest coins, which have no value.

## Supply and time

Genesis supply is zero. Each accepted increase in CometBFT block time mints
exactly that many integer microseconds. The independently recounted identity is:

`bank + liquid account balances + PoS escrow + unclaimed auction reserve = elapsed microseconds since genesis`.

This proves conservation against accepted consensus time. It does not prove that
UTC clocks are correct. Validators need maintained, monitored clocks. Reversed
time, overflow and discontinuous heights fail closed. A long stall accrues the
elapsed supply into the bank; validator rewards cover at most 60 seconds of a
single block interval so its final signers cannot capture the entire outage.
The remainder stays in the bank. Leap handling follows the selected CometBFT
timestamp implementation; browsers do not set protocol time.

Reward version one pays a validator group according to its previous actual
voting power, then divides that group's budget by live self collateral, live
delegated assets and bounded still-voting exit weights. The owner earns its
capital share plus commission on the delegated share. A first dust delegation
cannot switch the owner's entire reward to a delegation pool. Actual bootstrap
virtual owner backing participates only before handoff. Requested exit capital
earns nothing: its share remains in the bank through the H+2 power lag. These
historical reward weights last at most two persisted height buckets; fourteen-day
exit escrow does not continue earning. Zero eligible weight and integer rounding
also leave value in the bank. See the reproduced attack in [the audit log](AUDIT.md).

## Earning with Bitcoin

An earning bid pays the active foundation P2WSH output and includes exactly one
minimal, zero-value OP_RETURN containing 64 bytes:

`TIMEBID1 || Time network ID (32) || account ID (BE8) || earning epoch (BE8) || policy revision (BE8)`.

The account signs its receipt submission. Headers are validated for proof of
work, difficulty, median time, bounded future time and accumulated-work fork
choice. A Core `gettxoutproof` partial Merkle tree must match exactly the intended
transaction. Network, amount, output, destination, beneficiary, epoch, policy
window and confirmation count are checked. The canonical outpoint is consumed
permanently in the same authenticated transaction as its bid credit. Repeating
it under another account, device, transaction or restart cannot credit it again.

Headers are public bounded relays; a relay has no account authority. A relay that
retains no new validated effect is rejected. Retained header state, fork tips,
batch size and proof allocation are bounded. Header relays cannot redirect BTC.
New receipts require a fresh best tip and an unpaused bridge and treasury.

Production defaults are hourly earning epochs and a configured lead time.
Laboratory epochs last ten seconds. A receipt must finalize while its target is
inside the configured future interval; publishing a Bitcoin transaction alone
does not reserve an earning allocation. Late proofs, missed deadlines, changed
policies and Bitcoin transaction fees can lose a bidder money without receiving
Time. The wallet must disclose this before a real payment. Production admission
therefore remains gated on review of confirmation/lead-time policy, connectivity
and custody. Time cannot refund a foundation UTXO by changing its own state.

Each populated epoch reserves 80% of that epoch's minted microseconds, computed
as `floor(4*end/5)-floor(4*start/5)`. Closing touches bounded epoch summaries,
not every bidder. Each account claims `floor(epoch pot * its sats / total sats)`
once. Multiple outputs aggregate linearly. The last claim returns rounding dust
to the bank. Receipt submission and earning claims have zero Time fee so a
new, zero-balance account can earn. Other operations have the ordinary fee.
Empty epochs leave their issuance in the bank. Unclaimed earnings remain a
liability in the reserve; there is no silent forfeiture deadline.

A sufficiently deep Bitcoin fork or a fork removing a credited output halts new
Bitcoin earning. It does not rewrite finalized Time payments or automatically
resume through an unauthenticated API. SPV inclusion does not independently
validate every Bitcoin transaction script or prove an output remains unspent.
Those assumptions, mainnet checkpoint bootstrap and exceptional bridge recovery
require independent review before monetary use.

Receipt encoding version one uses canonical hex and decimal satoshi strings.
Supported funding transactions are at most 240 KiB, with at most 4 KiB of Merkle
proof. Funding software checks the signed transaction before broadcasting BTC.
Larger valid Bitcoin transactions are outside this version's funding contract.

## Foundation custody and destination governance

Bitcoin spending uses four of seven distinct compressed secp256k1 keys. The
reference lab keeps its test keys in the isolated Core wallet. Production must
use separately controlled devices/operators; seven keys on one computer are
one custody failure domain.

Destination governance uses five of seven separate Ed25519 keys. A proposal
binds the Time network, previous policy, monotonic sequence, exact new policy,
activation times and expiry. Five current council signatures and five proposed
council acknowledgements are required. Activation waits at least seven accepted
Time days and 1008 validated Bitcoin blocks. A proposal expires within 30 days.
Pause/resume/cancel signatures also bind the pending proposal. Activation never
silently clears an emergency pause. Changing policy does not move BTC already
paid to an old output. A compromised quorum can approve a malicious future
destination; delays and public monitoring provide an intervention window, not
immunity. Lost BTC cannot be restored by protocol governance.

Pause/cancel remain available after a valid greatest-work Bitcoin fork reduces
height. Their accepted Time coordinates remain monotonic, and the previous
Bitcoin high-water mark is preserved. Resume, new proposals and activation keep
their full Bitcoin guards; the exception cannot enable receipts or redirect BTC.

A confirmed payment included before the recorded old Bitcoin height cutoff may
deliver its receipt for one accepted Time day after rotation. The old Bitcoin
cutoff is never extended. Treasury pause, Bitcoin halt, confirmations, duplicate
checks and earning deadlines still apply. Transactions merely waiting in the
Bitcoin mempool can miss this cutoff; funding near a known rotation must be
refused. Cross-chain timing is not an unconditional refund guarantee.

## Validator staking and membership

Production begins with 20 explicitly pinned bootstrap organizations. They must
actually be independently operated. Self collateral is at least 86,400 currency
seconds, delegated shares are integer pro-rata claims, commission is at most
20%, and the roster has at most 100 validators. The candidate index is bounded
to 256; new registration atomically escrows the minimum self collateral and
proves possession of a distinct consensus key. Retiring a candidate requires no
remaining authority, shares, escrow, claims or evidence exposure. A used
consensus key cannot be recycled by deleting an account.

Laboratory parameters are explicitly separate: four initial keys, a one-second
minimum bond and a 60-second bootstrap fade. They accelerate experiments and
do not represent production economic security. The 14-day exposure period and
seven-day client trust period are retained even in the lab.

Ordinary membership changes charge a rolling voting-power churn budget. Changes
announced in Finalize(H) become effective at H+2. The authenticated exact roster
pointer and timestamp at each height bind evidence and light-client checks.
H+2 changes and their ABCI responses survive commit/restart and exact replay.

The virtual bootstrap continues beyond its nominal 90-day fade if fewer than
seven genuinely funded successors exist or the proposed authority is unsafe.
After handoff, virtual authority never returns. One hundred one-day self bonds
need at least 100 days of global issuance, so a full 100-member funded roster
cannot exist on day 90. Twenty bootstrap operators sharing only their 20%
reward stream also cannot all fund one-day bonds in 90 days without auctions
or other transfers. Calendar time is not evidence of a funded handoff.

Signed conflicting CometBFT votes are checked against exact historical authority,
chain, height, round, vote type and distinct block IDs. Evidence is replay-bound
and limited to 14 accepted days. Slashing covers active collateral and pending
exit pools and returns value to the bank. A proven equivocation forfeits all
self collateral/own exits and 5% of live/departing delegated assets, then
permanently jails the key. Correlation-scaled penalties are not enabled in this
candidate; their economic effect needs explicit review. It does not destroy
supply. Missed
committers receive no reward. An additional automatic downtime slash is not
enabled: its original proposal needs a precise, reviewed attribution rule.

Proven equivocators may be removed at H+2 outside ordinary churn if at least four
unjailed authorities with strictly less than one third power each remain. Real
funded replacements may repair a roster with at least three surviving known
authorities; virtual genesis authority is never resurrected. If safe removal is
impossible, the critical hold allows only header relay, evidence and existing
accounts adding self collateral/registering funded candidates. Payments,
withdrawals, new device/recovery authority and earning are frozen until the
safe roster actually activates. Severe compromise can require coordinated
recovery. No selection rule manufactures honest operators after total compromise.

Self exits are withdrawable only after actual voting exposure ends and a full
14-day delay has elapsed. The clock begins at the later of authenticated H+2
release time and actual last roster removal. Delegated decreases must fit the
announced H+2 power change or reject atomically. A request timestamp alone is
insufficient. Pending claims remain slashable until withdrawal.

## Wallet and application trust

Names map to permanent account IDs and bounded device credentials. Passwords
unlock random local encrypted keys; they never deterministically generate a
spending key or appear as a public password verifier. New devices need an
authorized device or a preconfigured recovery policy. A password alone cannot
recover an unexported lost key. Software backups are copies of the same device
and do not establish independent hardware custody.

Signup uses a paid sponsored commitment, independently signed by the new device.
The sponsor pays the registration fee and gains no device or recovery authority.
Any funded account can sponsor. Pending commitments are individual authenticated
rows with bounded, garbage-collected expiry queues; there is no global 256-name
queue or ten-million-account hard limit. Registration fees are a resource price,
not a proof of Sybil resistance. Defaults require economic and load review.
One sponsor account's sequential nonce currently limits normal mempool admission
to about one registration per block; multiple funded sponsors can operate in
parallel. Guardian approvals have a seven-day coordination window, followed by
the full configured delay starting when quorum is reached.

Usernames, public account balances and transaction history are public blockchain
data. A website login does not make those balances private.

The client pins a network and validator checkpoint independently of its gateway.
Dynamic light blocks authenticate both current and next voting sets. Skips
require sufficient old voting-power overlap; otherwise the client bisects.
The trust period is seven days, shorter than 14-day exposed unbonding. An expired
client requires an independently authenticated fresh checkpoint; an API cannot
replace it. An arbitrary Bitcoin OP_RETURN cannot authenticate an unknown Time
validator history by itself.

Old payment receipts prove their block hash/time and the following header in a
compact history commitment under a fresh current state root. Current per-height
indexes are pruned outside the 14-day evidence window. A separate append archive
retains proof material; corrupted or absent archives cannot forge a payment but
can make old receipts unavailable. Live exits retain referenced release clocks
until withdrawal so accessing funds does not require that archive. A wallet
offline beyond its trust period still needs independently authenticated checkpoint
refresh, including a newly installed wallet after the network's first seven days.
Cached balances must display their verified height/time and offline status.

Web login proofs bind the exact origin, audience, browser session, network,
account, authority version, one-use challenge and expiry. Login is separate from
spending. Each payment shows and signs an exact recipient, amount, fee, reserved
nonce and expiry. Background spending allowances are not enabled; the supported
website API requests a separate approval for each exact payment.
A web wallet still trusts the origin delivering its executable code. Hardware
support requires readable approval and actual vendor/model/firmware testing;
a generic external signer interface is not evidence of hardware support.

## Evidence limits and live launch gates

Local tests establish the exercised invariants for the recorded source and
workload. They are not a proof that no exploit exists. Component TPS is not WAN
finalized TPS. Seven local processes are not seven independent operators.
Production requires independent review, an adversarial multi-host testnet,
funded handoff, clock/storage/failure rehearsals, diversity of custody and power,
supported device testing, release signatures, incident ownership and maintained
security updates. The executable deliberately has no mainnet enable switch.
