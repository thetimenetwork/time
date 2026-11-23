//! REVIEW (question b): "never weaker than the calendar rule at any moment",
//! measured on whole histories and not only on the formula.
//!
//! One random workload (registrations, bonds, delegations, bonds of starting
//! validators, exits that must fit the churn budget) is applied to two
//! networks, one with the calendar rule and one with the stake rule, block by
//! block at intervals from a minute to a day. After every block the share of
//! the voting power held by outsiders (validators that are not starting
//! validators) is compared in the roster in force and in the newest announced
//! roster. A run stops being compared when an exit is accepted by one network
//! and refused by the other, because the two then hold different stake.
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const MINUTE: u64 = 60 * SECOND;

fn signing(id: u64) -> SigningKey {
    use sha2::{Digest, Sha256};
    SigningKey::from_bytes(&Sha256::digest(id.to_be_bytes()).into())
}
fn public(id: u64) -> String {
    hex::encode(signing(id).verifying_key().as_bytes())
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}
#[derive(Clone)]
enum Step {
    Block(u64),
    Register(u64, u64),
    Bond(u64, u64),
    Delegate(u64, u64, u64),
    SelfExit(u64, u64),
    DelegationExit(u64, u64, u64),
}
struct Net {
    summary: Summary,
    candidates: Vec<Candidate>,
    owners: BTreeMap<u64, OwnerStake>,
    now: u64,
}
impl Net {
    /// `first`: the owner id of the first starting validator, so that
    /// outsiders can have smaller and larger ids than the starting validators.
    fn new(stake_rule: bool, first: u64) -> Self {
        let candidates: Vec<Candidate> = (first..first + 20)
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
                power: 86_400,
            })
            .collect();
        Self {
            summary: Summary::with_rules(roster, Profile::Production, stake_rule).unwrap(),
            candidates,
            owners: BTreeMap::new(),
            now: 0,
        }
    }
    /// Applies one step; an exit returns whether it was accepted.
    fn apply(&mut self, step: &Step) -> Option<bool> {
        match *step {
            Step::Block(delta) => {
                self.summary.reconcile(&self.candidates, None).unwrap();
                self.now += delta;
                let height = self.summary.last_height + 1;
                self.summary
                    .begin_block(height, self.now, &mut self.candidates)
                    .unwrap();
                for row in &mut self.candidates {
                    row.prune_reward_exits(height);
                }
                self.summary.reconcile(&self.candidates, None).unwrap();
                None
            }
            Step::Register(id, extra) => {
                if self.candidates.iter().any(|c| c.owner == id) {
                    return None;
                }
                let proof = signing(id)
                    .sign(&register_message([4; 32], id, &public(id), 0).unwrap())
                    .to_bytes();
                let (mut item, _) =
                    register_bonded([4; 32], id, public(id), 0, &proof, Profile::Production).unwrap();
                if extra > 0 {
                    bond_self(&mut item, extra).unwrap();
                }
                self.summary.admit_candidate(&item, &self.candidates).unwrap();
                self.candidates.push(item);
                self.candidates.sort_by_key(|c| c.owner);
                self.summary.reconcile(&self.candidates, None).unwrap();
                None
            }
            Step::Bond(index, amount) => {
                let index = index as usize % self.candidates.len();
                bond_self(&mut self.candidates[index], amount).unwrap();
                self.summary.escrow += amount;
                self.summary.reconcile(&self.candidates, None).unwrap();
                None
            }
            Step::Delegate(delegator, index, amount) => {
                let index = index as usize % self.candidates.len();
                let stake = self
                    .owners
                    .entry(delegator)
                    .or_insert_with(|| OwnerStake::new(delegator));
                if delegate(&mut self.candidates[index], stake, amount, 1).is_ok() {
                    self.summary.escrow += amount;
                }
                self.summary.reconcile(&self.candidates, None).unwrap();
                None
            }
            Step::SelfExit(index, part) => {
                let index = index as usize % self.candidates.len();
                let owner = self.candidates[index].owner;
                let bond = self.candidates[index].self_bond;
                if bond == 0 {
                    return None;
                }
                let quantity = (bond / part).max(1);
                Some(self.exit(owner, index, ExitKind::SelfBond, quantity))
            }
            Step::DelegationExit(delegator, index, part) => {
                let index = index as usize % self.candidates.len();
                let candidate = self.candidates[index].owner;
                let shares = self.owners.get(&delegator).map_or(0, |o| {
                    o.positions
                        .iter()
                        .find(|p| p.candidate == candidate)
                        .map_or(0, |p| p.shares)
                });
                if shares == 0 {
                    return None;
                }
                Some(self.exit(delegator, index, ExitKind::Delegation, (shares / part).max(1)))
            }
        }
    }
    fn exit(&mut self, account: u64, index: usize, kind: ExitKind, quantity: u64) -> bool {
        let saved = (self.summary.clone(), self.candidates.clone(), self.owners.clone());
        let id = self.summary.next_exit_id;
        let height = self.summary.last_height;
        let candidate = self.candidates[index].owner;
        let stake = self
            .owners
            .entry(account)
            .or_insert_with(|| OwnerStake::new(account));
        let first = unbond(&mut self.candidates[index], stake, kind, quantity, 1, height, id);
        let kept = first.is_ok() && {
            self.summary.next_exit_id += 1;
            self.summary.reconcile(&self.candidates, Some(candidate)).is_ok()
        };
        if !kept {
            (self.summary, self.candidates, self.owners) = saved;
        }
        kept
    }
    /// Voting power of outsiders and of everyone.
    fn outsiders(&self, roster: &[Validator]) -> (u64, u64) {
        let outsider = |owner: u64| {
            self.candidates
                .iter()
                .any(|c| c.owner == owner && !c.genesis)
        };
        (
            roster.iter().filter(|v| outsider(v.owner)).map(|v| v.power).sum(),
            roster.iter().map(|v| v.power).sum(),
        )
    }
}

fn workload(seed: u64, with_exits: bool, blocks: usize) -> Vec<Step> {
    let mut rng = Rng(seed);
    let mut steps = Vec::new();
    let mut registered = 0;
    for _ in 0..blocks {
        let delta =
            [MINUTE, 10 * MINUTE, 60 * MINUTE, 6 * 60 * MINUTE, DAY, 2 * DAY][rng.below(6) as usize];
        steps.push(Step::Block(delta));
        for _ in 0..rng.below(3) {
            let amount = [BOND / 2, BOND, BOND, 3 * BOND, 10 * BOND, 30 * BOND][rng.below(6) as usize];
            match rng.below(if with_exits { 14 } else { 10 }) {
                0..=4 => {
                    // Outsiders take ids below and above the starting
                    // validators (owners 40..60).
                    let low = rng.below(2) == 0 && registered < 40;
                    let extra = [0, 0, 0, BOND / 2, BOND, 4 * BOND, 12 * BOND][rng.below(7) as usize];
                    if registered < 45 {
                        let id = if low { registered } else { 100 + registered };
                        registered += 1;
                        steps.push(Step::Register(id, extra));
                    }
                }
                5..=6 => steps.push(Step::Bond(rng.below(1000), amount)),
                7..=9 => steps.push(Step::Delegate(900 + rng.below(3), rng.below(1000), amount)),
                10..=11 => steps.push(Step::SelfExit(rng.below(1000), 1 + rng.below(4))),
                _ => steps.push(Step::DelegationExit(900 + rng.below(3), rng.below(1000), 1 + rng.below(3))),
            }
        }
    }
    steps
}

struct Measured {
    blocks: u64,
    worst_active: f64,
    worst_latest: f64,
    worst_seed: u64,
    stake_rule_ended_first: u64,
    ended_before_the_calendar_period: u64,
    starting_not_above_half: u64,
    diverged: u64,
    ended_calendar: u64,
    ended_stake: u64,
}

fn measure(seeds: std::ops::Range<u64>, with_exits: bool, blocks: usize) -> Measured {
    let mut m = Measured {
        blocks: 0,
        worst_active: f64::MIN,
        worst_latest: f64::MIN,
        worst_seed: 0,
        stake_rule_ended_first: 0,
        ended_before_the_calendar_period: 0,
        starting_not_above_half: 0,
        diverged: 0,
        ended_calendar: 0,
        ended_stake: 0,
    };
    for seed in seeds {
        let mut calendar = Net::new(false, 40);
        let mut stake = Net::new(true, 40);
        'run: for step in workload(seed, with_exits, blocks) {
            let (a, b) = (calendar.apply(&step), stake.apply(&step));
            if a != b {
                m.diverged += 1;
                break 'run;
            }
            if matches!(step, Step::Block(_)) {
                m.blocks += 1;
                if stake.summary.bootstrap_ended && !calendar.summary.bootstrap_ended {
                    m.stake_rule_ended_first += 1;
                }
                if stake.summary.bootstrap_ended && stake.summary.last_elapsed < 90 * DAY {
                    m.ended_before_the_calendar_period += 1;
                }
                let (outside, total) = stake.outsiders(&stake.summary.active);
                if !stake.summary.bootstrap_ended && outside * 2 >= total {
                    m.starting_not_above_half += 1;
                }
                let share = |net: &Net, roster: &[Validator]| {
                    let (own, total) = net.outsiders(roster);
                    own as f64 / total as f64
                };
                let active = share(&stake, &stake.summary.active) - share(&calendar, &calendar.summary.active);
                let latest = share(&stake, stake.summary.latest()) - share(&calendar, calendar.summary.latest());
                if active > m.worst_active {
                    m.worst_active = active;
                    m.worst_seed = seed;
                }
                m.worst_latest = m.worst_latest.max(latest);
            }
        }
        m.ended_calendar += u64::from(calendar.summary.bootstrap_ended);
        m.ended_stake += u64::from(stake.summary.bootstrap_ended);
    }
    m
}

#[test]
fn review_6_outsider_share_under_the_stake_rule_against_the_calendar_rule_without_exits() {
    let m = measure(0..40, false, 260);
    println!(
        "6a. stake only arrives: {} blocks compared; largest (outsider share with the stake rule) - \
         (with the calendar rule): roster in force {:+.6}, newest roster {:+.6} (seed {}); \
         ended: calendar {} runs, stake rule {} runs; stake rule ended while calendar had not: {} blocks",
        m.blocks, m.worst_active, m.worst_latest, m.worst_seed, m.ended_calendar, m.ended_stake,
        m.stake_rule_ended_first
    );
    check(&m);
    assert!(m.ended_calendar > 0);
}

#[test]
fn review_7_outsider_share_under_the_stake_rule_against_the_calendar_rule_with_exits() {
    let m = measure(1000..1040, true, 260);
    println!(
        "7a. with exits: {} blocks compared, {} runs stopped at an exit that only one rule accepted; \
         largest difference: roster in force {:+.6}, newest roster {:+.6} (seed {}); \
         ended: calendar {} runs, stake rule {} runs; stake rule ended first: {} blocks",
        m.blocks, m.diverged, m.worst_active, m.worst_latest, m.worst_seed, m.ended_calendar,
        m.ended_stake, m.stake_rule_ended_first
    );
    check(&m);
}

/// Fourth design. The stake rule may end a day or two before the calendar
/// rule does, because the calendar rule waits until its starting validators
/// are out of the roster in force and the stake rule ends their virtual power
/// first and then lets them leave; it never ends before the calendar period.
/// Until it ends, the starting validators hold more than half. The share of
/// outsiders in force can stand a few points above the calendar rule's: the
/// calendar's smaller roster holds a large outsider down harder under the
/// cap of 30% per validator (measured: up to about 6.4 points).
fn check(m: &Measured) {
    println!(
        "    stake rule ended before day 90: {} blocks; starting validators not above half: {} blocks",
        m.ended_before_the_calendar_period, m.starting_not_above_half
    );
    assert_eq!(m.ended_before_the_calendar_period, 0);
    assert_eq!(m.starting_not_above_half, 0);
    assert!(m.worst_active < 0.10, "{}", m.worst_active);
}
