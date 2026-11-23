# Protocol 4 stake policy

This new crate defines deterministic stake accounting and validator selection.
It does not modify the protocol 2/3 chains. The application must authenticate
account authority and tree rows, apply each returned `Movement` together with
all row changes, enforce fees/nonces, and publish the resulting root atomically.
The library alone is not a running network or an external security audit.

## Assets and exits

Registration requires proof of possession of a separate canonical Ed25519
consensus key and an actual minimum self bond. There are at most 256 live
candidates, 100 selected validators, 64 delegation positions per owner, and 64
pending exits per owner. Registration cannot reserve a directory slot for free. Initial self bond may
exceed the minimum. If the eligibility directory is full, a strictly stronger
entrant can archive its weakest inactive candidate, with owner ID breaking ties
deterministically. Active, scheduled and still-exposed signers cannot be evicted.
When every slot is protected, admission must wait. No unconditional entry
availability is claimed.
Historic consensus-key reservations remain archived when a candidate retires;
the adapter must never allow an old key to become another candidate's identity.
After actual inactivity and the 14-day evidence window, retirement removes a
candidate from the 256-entry eligibility directory while preserving every
delegator position and pending claim. Unfunded inactive entries are also
archived automatically, so malicious owners cannot keep directory slots by
leaving dust and declining to retire. Archived pools accept no new delegation,
self bond or reward; existing claims can unbond and withdraw. An account can
register a new consensus identity only after its archive has fully settled.
Reactivation of the same archived row is not enabled: it would require
separating old exit cohorts before exposing any assets to new votes. If another
owner leaves claims unsettled, the operator can use a fresh account and key
without seizing those claims.
This avoids both recovered-bond directory exhaustion and third-party dust
delegations pinning an operator's self bond forever.

Self bonds, delegated assets and pending exits are real currency escrow.
Delegation and exit pool units redeem at the corresponding pool's current
asset value. Only the delegated capital's reward enters the live pool after commission. Double signing
forfeits all self collateral and five percent of live and departing delegated
assets, returning the forfeiture to the Time bank. This preserves total currency.
One candidate cannot be slashed repeatedly through reordered evidence.

Every unbond must atomically reserve its complete resulting power reduction
for H+2, or the application must reject and roll back the action. The 14-day
withdrawal delay starts from the authenticated accepted timestamp at that
height. Self exits additionally wait until the candidate has no active or
scheduled authority and at least 14 days have passed since its actual final
roster removal. This is deliberately conservative for partial self exits.

Actual Comet vote signatures, chain ID, height, round, vote type, distinct
block IDs and historic membership are checked for double-sign evidence. The
application must supply authenticated roster history, authenticated block time
and replay absence. Evidence older than 14 days is rejected. Timestamp changes
alone are not a double-sign offense. No automatic downtime slashing policy is
claimed; a missed commit receives no reward through application reward logic.

## Reward version 1

Protocol-4 genesis must pin `reward_version: 1`; previous development networks
and their benchmark artifacts are historical, with no implicit migration. The
previous rule paid the entire noncommission reward to the delegated pool as soon
as it had one share, excluding the validator's own bond. An unsolicited tiny
delegation could therefore capture most rewards. The new rule weights both kinds
of live capital and withholds the fraction belonging to recently exited capital.

Each eligible validator's gross allocation `R` still comes from its previous
actual roster power and the block's validator budget. Let `S` be its live self
bond, `P` live delegated pool assets, and `X` capital exited at request heights
whose H+2 release has not yet been paid. During the previous state's bootstrap
phase only, a genesis authority also receives virtual owner weight
`V = max(0, previous_actual_power * 1_000_000 - S - P - X)`.
After handoff, `V = 0`. With `D = S + V + P + X`:

```
owner_gross     = floor(R * (S + V) / D)
delegated_gross = floor(R * P / D)
commission     = floor(delegated_gross * commission_bps / 10_000)
owner_credit   = owner_gross + commission
pool_credit    = delegated_gross - commission
bank_debit     = owner_gross + delegated_gross
```

Zero total weight pays nothing. The exited-capital fraction and integer rounding
stay in the bank. Exits receive no reward growth. For equal self and delegated
capital, a 10,000-unit reward at ten-percent commission credits 5,500 to the owner
and 4,500 to the live pool. Adding one microsecond of delegated capital cannot
capture the much larger self bond's allocation.

At begin block H the adapter pays the previous actual H-1 roster. A request at T
therefore withholds exited weight while `T+2 >= H`, including the final interval
paid at activation H=T+2. Only after payment does it prune release heights <=H.
Requests at the same height coalesce, so candidate metadata retains at most two
height buckets. The action must still reserve its complete H+2 reduction under
the ordinary churn rule; a rejected action publishes neither exit nor bucket.
Archived or jailed candidates never earn rewards and retain no such buckets.
Deposits accepted in a block first affect the following interval's reward split.

`tests/rewards.rs` covers the original exploit at zero, ten and twenty percent
commission, bootstrap virtual weights, full and partial exits, last pool-share
exit, bucket bounds, zero weights, slashing and exact conservation across 192
capital/commission combinations. Native engine reward tests additionally exercise
actual scheduled H+2 reductions/removals and full state/archive audits after
every block. These checks are regression evidence, not a formal economic proof.

## Bootstrap and validator changes

The production profile uses a minimum self bond of 86,400 currency seconds,
20 explicitly trusted genesis authorities, a nominal 90-day fade, and a rolling
one-hour power-change budget below one third. Genesis virtual voting power is
authority only: it creates no currency. The laboratory profile uses a one-second
self bond, four to twenty explicit genesis authorities, a 60-second fade and
20-second churn window. Both profiles retain the
same 14-day unbond delay and require a shorter seven-day light-client trust
period; the laboratory profile is not a monetary launch configuration.

One hundred production minimum bonds require 100 days of total issuance, so a
fully funded top-100 set cannot exist by day 90 without changing those rules.
The approved amendment retains explicit bootstrap authority until at least
seven candidates are funded and a safe handoff has actually activated. Once
bootstrap ends it never resurrects waived genesis authority. Seven is the initial handoff threshold. Subsequent healthy rosters may have
four to one hundred authorities while preserving the per-key power bound.
Exits that would leave an unsafe roster are rejected. The policy cannot
manufacture independent operators or restore consensus after a quorum stops.

Selection ranks funded candidates by stake, breaking ties by owner ID. Assigned
power is clipped toward a 30-percent single-key ceiling, while every proposed
intermediate set stays below one third per key. This cannot establish that
different keys belong to independent people, companies, clouds or jurisdictions.
A single operator can control multiple funded candidates.

A proven double-sign offense is an explicit emergency exception to ordinary
churn: jailed keys are removed at H+2 when at least four surviving authorities
can remain below one third per key. When three existing unjailed authorities
remain, already funded new candidates may supply replacement authority. Fewer
than three known survivors requires coordinated recovery. Virtual genesis
authority is never resurrected. While any jailed authority remains active or
scheduled, `safety_hold` freezes payments, enrollment, recovery, exits, auction
and Bitcoin claims. Only header relay, further equivocation evidence, and
existing-account registration/self-bond repair are permitted. Payments resume
only after the safe removal actually activates. This does not prove safety
following a Byzantine quorum compromise.

Churn measures total variation of normalized voting power, including additions
and removals. Each announced step is charged; the sum retained in the rolling
journal remains below one third. Expiry rounds upward to a minute in production
or a second in the laboratory, never releasing budget early. At most 61 expiry
buckets are retained. Updates announced in Finalize(H) activate at H+2; the
application must return removals as zero-power Comet updates and archive the
effective roster for evidence and light clients. There can be at most two
future roster snapshots.

## Evidence and remaining gates

`tests/policy.rs` exercises 120 virtual days, zero-supply accounting, delayed
bootstrap, no authority resurrection, weighted rolling churn, concentration,
actual signed Comet equivocation, exposed exits, retirement and bounds. The
120-day simulation allocates already minted bank currency to test bonds; it
does not establish Bitcoin auction admission or real independent operators.
Tests are evidence about these transitions, not a formal security proof.

Application integration must still demonstrate actual Comet H+2 changes,
historical roster proofs, atomic supply accounting, rollback/replay, reward
eligibility, and external Bitcoin/treasury rules. A public monetary launch also
requires an independent protocol/implementation audit and actual independent
operators with an exercised incident process. See the existing
[launch gates](../v2/LAUNCH_GATES.md) for the older chain's separately scoped
limitations; passing an older chain's checks does not certify protocol 4.
