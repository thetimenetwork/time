//! SECOND REVIEW. Stake held by a starting validator that is not funded
//! (a delegation to it, or a self bond below the minimum) is counted as
//! seated stake by `stake_gap`, but gives that validator no voting power:
//! its power is its part of the gap whatever it holds. Every such unit
//! therefore removes one unit of voting power from the network, and the
//! outsiders' share rises above seated / target.
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const POWER: u64 = 86_400;
const HOUR: u64 = 3600 * SECOND;

fn target(elapsed: u64) -> u64 {
    40 * POWER + elapsed / SECOND / 5
}
fn signing(id: u64) -> SigningKey {
    use sha2::{Digest, Sha256};
    SigningKey::from_bytes(&Sha256::digest(id.to_be_bytes()).into())
}
fn public(id: u64) -> String {
    hex::encode(signing(id).verifying_key().as_bytes())
}
fn is_starting(owner: u64) -> bool {
    owner < 20
}
fn is_attacker(owner: u64) -> bool {
    (100..200).contains(&owner)
}
fn pct(part: u64, whole: u64) -> f64 {
    part as f64 * 100.0 / whole as f64
}

#[derive(Clone)]
struct Net {
    summary: Summary,
    candidates: Vec<Candidate>,
    owners: BTreeMap<u64, OwnerStake>,
    now: u64,
}
impl Net {
    fn production(stake_rule: bool) -> Self {
        let profile = Profile::Production;
        let candidates: Vec<Candidate> = (0..20)
            .map(|id| Candidate {
                owner: id,
                consensus_key: public(id),
                commission_bps: 0,
                self_bond: 0,
                pool_assets: 0,
                pool_shares: 0,
                self_exits: ExitPool::default(),
                delegated_exits: ExitPool::default(),
                pending_reward_exits: Vec::new(),
                jailed: false,
                genesis: true,
                archived: false,
                last_active_end: 0,
            })
            .collect();
        let roster = candidates
            .iter()
            .map(|c| Validator {
                owner: c.owner,
                consensus_key: c.consensus_key.clone(),
                power: profile.genesis_power(),
            })
            .collect();
        Self {
            summary: Summary::with_rules(roster, profile, stake_rule).unwrap(),
            candidates,
            owners: BTreeMap::new(),
            now: 0,
        }
    }
    fn row(&mut self, id: u64) -> &mut Candidate {
        self.candidates.iter_mut().find(|c| c.owner == id).unwrap()
    }
    fn admit(&mut self, id: u64, extra: u64) {
        let proof = signing(id)
            .sign(&register_message([4; 32], id, &public(id), 0).unwrap())
            .to_bytes();
        let (mut item, _) =
            register_bonded([4; 32], id, public(id), 0, &proof, self.summary.profile).unwrap();
        if extra > 0 {
            bond_self(&mut item, extra).unwrap();
        }
        self.summary.admit_candidate(&item, &self.candidates).unwrap();
        self.candidates.push(item);
        self.candidates.sort_by_key(|c| c.owner);
        self.summary.reconcile(&self.candidates, None).unwrap();
    }
    fn bond(&mut self, id: u64, amount: u64) {
        bond_self(self.row(id), amount).unwrap();
        self.summary.escrow += amount;
        self.summary.reconcile(&self.candidates, None).unwrap();
    }
    fn delegate(&mut self, delegator: u64, candidate: u64, amount: u64) {
        let row = self.candidates.iter_mut().find(|c| c.owner == candidate).unwrap();
        let stake = self
            .owners
            .entry(delegator)
            .or_insert_with(|| OwnerStake::new(delegator));
        delegate(row, stake, amount, 1).unwrap();
        self.summary.escrow += amount;
        self.summary.reconcile(&self.candidates, None).unwrap();
    }
    fn block(&mut self, delta: u64) {
        self.now += delta;
        let height = self.summary.last_height + 1;
        self.summary
            .begin_block(height, self.now, &mut self.candidates)
            .unwrap();
        for row in &mut self.candidates {
            row.prune_reward_exits(height);
        }
        self.summary.reconcile(&self.candidates, None).unwrap();
        self.summary.validate().unwrap();
    }
    fn run_to(&mut self, elapsed: u64, step: u64) {
        while self.now < elapsed {
            self.block(step);
        }
    }
    fn exit(&mut self, account: u64, candidate: u64, kind: ExitKind, quantity: u64) -> Result<u64, String> {
        let saved = (self.summary.clone(), self.candidates.clone(), self.owners.clone());
        let id = self.summary.next_exit_id;
        let height = self.summary.last_height;
        let first = {
            let row = self.candidates.iter_mut().find(|c| c.owner == candidate).unwrap();
            let stake = self
                .owners
                .entry(account)
                .or_insert_with(|| OwnerStake::new(account));
            unbond(row, stake, kind, quantity, 1, height, id)
        };
        let outcome = first.and_then(|_| {
            self.summary.next_exit_id += 1;
            self.summary.reconcile(&self.candidates, Some(candidate))
        });
        match outcome {
            Ok(_) => Ok(id),
            Err(error) => {
                (self.summary, self.candidates, self.owners) = saved;
                Err(error.to_string())
            }
        }
    }
    fn power(roster: &[Validator], pick: impl Fn(u64) -> bool) -> (u64, u64) {
        (
            roster.iter().filter(|v| pick(v.owner)).map(|v| v.power).sum(),
            roster.iter().map(|v| v.power).sum(),
        )
    }
}

/// Seven attacker validators, `extra` more bonds of the attacker in an
/// eighth one, day 120; then an honest delegator (900) puts `each` on every
/// starting validator, as people do who trust the founders. Returns the
/// attacker's share of the roster in force (min, max, last) over the next
/// three days of hourly blocks, and the number of hourly rosters that
/// changed in the last day.
fn trusting_delegators(attacker_bonds: u64, each: u64) -> (f64, f64, f64, f64, u64) {
    let mut net = Net::production(true);
    net.block(HOUR);
    for id in 100..107 {
        net.admit(id, 0);
    }
    if attacker_bonds > 7 {
        net.admit(107, (attacker_bonds - 8) * BOND);
    }
    net.run_to(120 * DAY, DAY);
    for _ in 0..5 {
        net.block(HOUR);
    }
    let (own, total) = Net::power(&net.summary.active, is_attacker);
    let promised = pct(own, target(net.now));
    if each > 0 {
        for id in 0..20 {
            net.delegate(900, id, each);
        }
    }
    let (mut low, mut high, mut changes) = (f64::MAX, f64::MIN, 0);
    for hour in 0..72 {
        let before = net.summary.active.clone();
        net.block(HOUR);
        let (own, total) = Net::power(&net.summary.active, is_attacker);
        let share = pct(own, total);
        low = low.min(share);
        high = high.max(share);
        if hour >= 48 && net.summary.active != before {
            changes += 1;
        }
    }
    let (own2, total2) = Net::power(&net.summary.active, is_attacker);
    let _ = (own, total);
    (promised, low, high, pct(own2, total2), changes)
}

#[test]
fn review2_1_trusting_delegations_to_starting_validators_inflate_the_attackers_share() {
    println!("attacker bonds | delegated to each starting validator | promised seated/T | share in force over 72 h: min / max / last | roster changes in the last 24 h");
    let mut worst = 0.0f64;
    for attacker in [7u64, 14, 24] {
        for each in [0u64, BOND / 2, BOND, 2 * BOND, 4 * BOND] {
            let (promised, low, high, last, changes) = trusting_delegators(attacker, each);
            println!(
                "{attacker:>3} | {:>4.1} bonds | {promised:>5.1}% | {low:>5.1}% / {high:>5.1}% / {last:>5.1}% | {changes}",
                each as f64 / BOND as f64
            );
            if each == 0 {
                assert!(high < promised + 1.0, "no delegations: {high} vs {promised}");
            }
            worst = worst.max(high - promised);
        }
    }
    // Fourth design: stake delegated to a starting validator counts for
    // nothing, so trusting delegations never raise the attacker's share.
    assert!(worst < 0.5, "largest excess {worst}");
}

/// How long the attacker holds a third and a half of the roster in force
/// over three days after honest delegators put `each` on every starting
/// validator, at once or one validator an hour.
#[test]
fn review2_1b_hours_above_a_third_and_a_half() {
    for (attacker, each, spread) in [
        (7u64, 4 * BOND, false),
        (7, 4 * BOND, true),
        (14, 2 * BOND, false),
        (14, 2 * BOND, true),
        (14, BOND, false),
        (24, BOND, true),
    ] {
        let mut net = Net::production(true);
        net.block(HOUR);
        for id in 100..107 {
            net.admit(id, 0);
        }
        if attacker > 7 {
            net.admit(107, (attacker - 8) * BOND);
        }
        net.run_to(120 * DAY, DAY);
        for _ in 0..5 {
            net.block(HOUR);
        }
        if !spread {
            for id in 0..20 {
                net.delegate(900, id, each);
            }
        }
        let (mut third, mut half, mut peak, mut trace) = (0, 0, 0.0f64, Vec::new());
        for hour in 0..72u64 {
            if spread && hour < 20 {
                net.delegate(900, hour, each);
            }
            net.block(HOUR);
            let (own, total) = Net::power(&net.summary.active, is_attacker);
            let share = pct(own, total);
            peak = peak.max(share);
            third += u64::from(own * 3 > total);
            half += u64::from(own * 2 > total);
            if hour < 12 || hour % 12 == 11 {
                trace.push(format!("{share:.0}"));
            }
        }
        println!(
            "attacker {attacker} bonds, {} bonds on each starting validator {}: promised {:.1}%, peak {peak:.1}%, \
             hours above a third {third}, above a half {half}; hourly shares {}",
            each as f64 / BOND as f64,
            if spread { "one an hour" } else { "at once     " },
            pct(attacker * POWER, target(net.now)),
            trace.join(" ")
        );
        assert_eq!(half, 0, "the attacker held half");
    }
}

/// Exits while the starting validators' roster chases a target that moves
/// with their own escrow: an honest operator (owner 300, one bond and twenty
/// delegated by 901) takes out one delegated bond each hour.
#[test]
fn review2_2_exits_while_the_starting_validators_chase_their_own_escrow() {
    for each in [0u64, 4 * BOND] {
        let mut net = Net::production(true);
        net.block(HOUR);
        for id in 100..107 {
            net.admit(id, 0);
        }
        net.admit(300, 0);
        net.delegate(901, 300, 20 * BOND);
        net.run_to(120 * DAY, DAY);
        for _ in 0..5 {
            net.block(HOUR);
        }
        for id in 0..20 {
            if each > 0 {
                net.delegate(900, id, each);
            }
        }
        let (mut refused, mut tried) = (0, 0);
        for _ in 0..24 {
            net.block(HOUR);
            tried += 1;
            // After twenty hours the delegator has nothing left to take out.
            if let Err(error) = net.exit(901, 300, ExitKind::Delegation, BOND)
                && error != "no delegation"
            {
                refused += 1;
            }
        }
        println!(
            "{} bonds delegated to each starting validator: {refused} of {tried} hourly one-bond exits refused",
            each / BOND
        );
        // Fourth design: no exit waits for the starting validators.
        assert_eq!(refused, 0);
    }
}

/// Starting validators that bond the minimum leave the gap to the others;
/// when few are left the 30% cap stops them from filling it.
#[test]
fn review2_3_founders_that_bond_leave_the_gap_unfilled() {
    for funded in [0u64, 15, 18, 19, 20] {
        let mut net = Net::production(true);
        net.block(HOUR);
        for id in 100..107 {
            net.admit(id, 0);
        }
        net.run_to(110 * DAY, DAY);
        for id in 0..funded {
            net.bond(id, BOND);
        }
        net.run_to(120 * DAY, DAY);
        for _ in 0..3 {
            net.block(HOUR);
        }
        let (own, total) = Net::power(&net.summary.active, is_attacker);
        let (starting, _) = Net::power(&net.summary.active, is_starting);
        println!(
            "{funded:>2} founders funded: attacker {:.1}% (seated/T {:.1}%), total in force {:.1} bonds of a target of {:.1}, starting validators {:.1} bonds",
            pct(own, total),
            pct(own, target(net.now)),
            total as f64 / POWER as f64,
            target(net.now) as f64 / POWER as f64,
            starting as f64 / POWER as f64
        );
        // Fourth design: every unjailed starting validator takes its part,
        // funded or not, so the gap is filled and they keep more than half.
        assert!(starting * 2 > total, "{funded}");
        assert!(total >= target(net.now - DAY), "{funded}: {total}");
    }
}

/// The hold is counted in block time. Third design: while seated stake was
/// at the target the starting validators were taken out, so the holder of
/// the target held every vote during the hold, and with more than a third of
/// the votes BFT time is whatever its proposals say. Fourth design: the
/// starting validators keep more than half until the end, so a block needs
/// their votes, and the engine's clock check refuses one dated ahead.
#[test]
fn review2_4_the_hold_is_measured_in_time_the_stake_holder_controls() {
    let mut net = Net::production(true);
    net.block(HOUR);
    for id in 100..107 {
        net.admit(id, 0);
    }
    net.run_to(100 * DAY, DAY);
    for id in 100..107 {
        net.delegate(900, id, 10 * BOND);
    }
    let mut hours = 0;
    while !net.summary.bootstrap_ended {
        net.block(HOUR);
        hours += 1;
        let (own, total) = Net::power(&net.summary.active, is_attacker);
        let (starting, _) = Net::power(&net.summary.active, is_starting);
        assert!(own * 2 < total && starting * 2 > total, "hour {hours}");
        assert!(hours < 16 * 24, "never ended");
    }
    println!("ended after {hours} hourly blocks; the attacker never held half");
    assert!(hours >= 14 * 24);
}
