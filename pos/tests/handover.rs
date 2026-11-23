//! The stake hand-over rule (`StakeHandover`): the starting validators keep
//! more than half of the voting power, and stand in for the independent
//! stake that is missing from a target, until independent stake has held the
//! target for fourteen days.
//!
//! Production profile unless stated: twenty starting validators (owners
//! 0..20) of 86,400 voting power, one bond = 86,400 seconds of stake, a
//! ninety-day fade period. The target is forty bonds plus a fifth of all the
//! time issued since genesis: 3,456,000 + 17,280 per day, in voting power.
//! The attacks of the reviews of this rule are here as tests that the attack
//! fails.
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const POWER: u64 = 86_400;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;
/// The starting validators' parts are rounded up to a hundredth of their
/// genesis power: twenty of them hold at most this much more.
const ROUNDING: u64 = 20 * (POWER / 100);

/// The target on a given day, in voting power.
fn target(day: u64) -> u64 {
    40 * POWER + day * POWER / 5
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
    (100..107).contains(&owner)
}
fn percent(part: u64, whole: u64) -> f64 {
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
    fn new(profile: Profile, count: u64, stake_rule: bool) -> Self {
        let candidates: Vec<Candidate> = (0..count)
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
    fn production(stake_rule: bool) -> Self {
        Self::new(Profile::Production, 20, stake_rule)
    }
    fn row(&mut self, id: u64) -> &mut Candidate {
        self.candidates.iter_mut().find(|c| c.owner == id).unwrap()
    }
    /// A new funded validator with `extra` on top of the minimum bond.
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
    }
    fn bond(&mut self, id: u64, amount: u64) {
        bond_self(self.row(id), amount).unwrap();
        self.summary.escrow += amount;
    }
    fn delegate(&mut self, delegator: u64, candidate: u64, amount: u64) {
        let row = self.candidates.iter_mut().find(|c| c.owner == candidate).unwrap();
        let stake = self
            .owners
            .entry(delegator)
            .or_insert_with(|| OwnerStake::new(delegator));
        delegate(row, stake, amount, 1).unwrap();
        self.summary.escrow += amount;
    }
    fn begin(&mut self, delta: u64) {
        self.now += delta;
        let height = self.summary.last_height + 1;
        self.summary
            .begin_block(height, self.now, &mut self.candidates)
            .unwrap();
        for row in &mut self.candidates {
            row.prune_reward_exits(height);
        }
    }
    /// The reconcile that ends every block (and follows every action).
    fn settle(&mut self) {
        self.summary.reconcile(&self.candidates, None).unwrap();
        self.summary.validate().unwrap();
    }
    fn block(&mut self, delta: u64) {
        self.begin(delta);
        self.settle();
    }
    /// One block a day.
    fn run_to_day(&mut self, day: u64) {
        while self.now < day * DAY {
            self.block(DAY);
        }
    }
    /// An exit as the engines do it: the complete decrease must fit the
    /// churn budget, or everything is rolled back.
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
    fn shares_of(&self, delegator: u64, candidate: u64) -> u64 {
        self.owners.get(&delegator).map_or(0, |o| {
            o.positions
                .iter()
                .find(|p| p.candidate == candidate)
                .map_or(0, |p| p.shares)
        })
    }
    /// Voting power of the picked owners and of everyone in a roster.
    fn power(roster: &[Validator], pick: impl Fn(u64) -> bool) -> (u64, u64) {
        (
            roster.iter().filter(|v| pick(v.owner)).map(|v| v.power).sum(),
            roster.iter().map(|v| v.power).sum(),
        )
    }
    /// Whether the starting validators hold more than half of the roster in
    /// force.
    fn starting_above_half(&self) -> bool {
        let (starting, total) = Self::power(&self.summary.active, is_starting);
        starting * 2 > total
    }
    fn reached_at(&self) -> Option<u64> {
        self.summary.stake_handover.as_ref().and_then(|rule| rule.reached_at)
    }
    /// The reward step of `pos_adapter::begin_block`: `amount` of new time
    /// split by voting power among `signers` (the roster in force before the
    /// block), by the protocol-4 reward rule, paid in full; a starting
    /// validator's lent power counts as its own until the end (`ended`, as it
    /// stood before the block). What each owner was paid.
    fn pay(&mut self, signers: &[Validator], ended: bool, amount: u64) -> BTreeMap<u64, u64> {
        let height = self.summary.last_height;
        let total: u64 = signers.iter().map(|v| v.power).sum();
        let mut paid = BTreeMap::new();
        for signer in signers {
            let row = self.candidates.iter_mut().find(|c| c.owner == signer.owner).unwrap();
            if row.jailed {
                continue;
            }
            let share = ratio(amount, signer.power, total).unwrap();
            let before = row.escrow().unwrap();
            let lent = (row.genesis && !ended).then_some(signer.power);
            let movement = reward_with_weights(row, share, height, lent).unwrap();
            let after = row.escrow().unwrap();
            self.summary.escrow = self.summary.escrow - before + after;
            *paid.entry(signer.owner).or_default() += movement.credit;
        }
        paid
    }
}

/// The finding. Under the calendar rule, seven minimum bonds of one owner
/// hold a third of the voting power in force on day 29, more than two
/// thirds on day 77 and everything after day 90. Under the stake rule they
/// hold seven bonds of the target, a share that falls as the target grows,
/// and the starting validators hold the rest.
#[test]
fn seven_minimum_bonds_take_the_network_by_the_calendar_and_never_by_the_stake_rule() {
    let mut calendar = Net::production(false);
    let mut stake = Net::production(true);
    for net in [&mut calendar, &mut stake] {
        net.begin(DAY);
        for id in 100..107 {
            net.admit(id, 0);
        }
        net.settle();
    }
    let (mut third, mut two_thirds) = (None, None);
    for day in 3..=400 {
        calendar.run_to_day(day);
        stake.run_to_day(day);
        let (own, total) = Net::power(&calendar.summary.active, is_attacker);
        if third.is_none() && own * 3 >= total {
            third = Some(day);
        }
        if two_thirds.is_none() && own * 3 > total * 2 {
            two_thirds = Some(day);
        }
        let (own, total) = Net::power(&stake.summary.active, is_attacker);
        assert_eq!(own, 7 * POWER);
        assert!(own * 3 < total, "day {day}: {own} of {total}");
        assert!(stake.starting_above_half(), "day {day}");
        assert!(!stake.summary.bootstrap_ended && stake.reached_at().is_none());
        if day >= 10 {
            // The starting validators fill the gap to the target of two
            // days before (the roster announced then is in force now).
            let gap = target(day - 2) - 7 * POWER;
            let starting = Net::power(&stake.summary.active, is_starting).0;
            assert!(starting >= gap && starting <= gap + ROUNDING, "day {day}: {starting} for a gap of {gap}");
        }
    }
    assert_eq!((third, two_thirds), (Some(29), Some(77)));
    assert!(calendar.summary.bootstrap_ended);
    let (own, total) = Net::power(&stake.summary.active, is_attacker);
    println!("day 400: seven bonds hold {:.1}% under the stake rule", percent(own, total));
    assert!(own * 100 < total * 6, "the share falls as the target grows");
}

/// Seven minimum bonds of an attacker (owners 100..107) and `honest` bonds of
/// somebody else: in one validator (one bond of its own, the rest delegated
/// to it) or in `honest` validators of one bond each. Day 120.
fn with_honest_stake(honest: u64, concentrated: bool) -> Net {
    let mut net = Net::production(true);
    net.begin(DAY);
    for id in 100..107 {
        net.admit(id, 0);
    }
    if concentrated {
        net.admit(200, 0);
        if honest > 1 {
            net.delegate(900, 200, (honest - 1) * BOND);
        }
    } else {
        for id in 200..200 + honest {
            net.admit(id, 0);
        }
    }
    net.settle();
    net.run_to_day(120);
    net
}

/// First review, finding 1: stake that the 30% cap kept out of the roster
/// still counted, so one large honest validator raised the attacker's
/// share. Only seated stake counts, the starting validators fill the rest of
/// the target and hold more than half: the attacker never holds more than
/// its seven bonds of the target.
#[test]
fn honest_stake_never_raises_an_outsiders_share() {
    for (honest, concentrated) in [
        (1, true),
        (10, true),
        (18, true),
        (30, true),
        (33, true),
        (60, true),
        (100, true),
        (10, false),
        (33, false),
        (40, false),
    ] {
        let net = with_honest_stake(honest, concentrated);
        let (attacker, total) = Net::power(&net.summary.active, is_attacker);
        println!(
            "{honest} honest bonds ({}): attacker {:.2}%, total {:.1} bonds",
            if concentrated { "one validator" } else { "spread" },
            percent(attacker, total),
            total as f64 / POWER as f64
        );
        assert!(!net.summary.bootstrap_ended);
        assert!(net.starting_above_half(), "{honest}");
        assert_eq!(attacker, 7 * POWER);
        assert!(total >= target(118), "{honest}: total {total} below the target {}", target(118));
    }
}

/// First review, findings 2 and 3: stake brought for a few hours, or for a
/// single block, ended the bootstrap for good. Now the stake must hold the
/// target for fourteen days, the starting validators keep more than half all
/// along, and leaving brings back the starting validators' stand-in power.
#[test]
fn stake_brought_for_hours_ends_nothing() {
    let mut net = Net::production(true);
    net.begin(DAY);
    for id in 100..107 {
        net.admit(id, 0);
    }
    net.settle();
    net.run_to_day(100);
    // A second account of the attacker delegates seventy bonds to its seven
    // validators: seventy-seven bonds against a target of 60.
    net.begin(MINUTE);
    for id in 100..107 {
        net.delegate(900, id, 10 * BOND);
    }
    net.settle();
    let mut minutes = 0;
    while net.reached_at().is_none() {
        net.block(MINUTE);
        minutes += 1;
        assert!(net.starting_above_half(), "minute {minutes}");
        assert!(minutes < 24 * 60, "never reached");
    }
    let (attacker, total) = Net::power(&net.summary.active, is_attacker);
    println!(
        "seventy-seven bonds reach the target after {minutes} minutes; the attacker holds {:.1}% while they stay",
        percent(attacker, total)
    );
    assert!(attacker * 2 < total);
    // The delegations leave again, from each validator in turn; each exit
    // has to fit the churn budget.
    let mut waited = 0;
    loop {
        let mut left = false;
        for id in 100..107 {
            let shares = net.shares_of(900, id);
            if shares == 0 {
                continue;
            }
            left = true;
            // Five bonds at a time: one account may have 64 exits pending.
            if net.exit(900, id, ExitKind::Delegation, shares.min(5 * BOND)).is_err() {
                net.block(MINUTE);
                waited += 1;
                assert!(waited < 2 * 24 * 60, "exits never fit");
            }
            assert!(net.starting_above_half());
        }
        if !left {
            break;
        }
    }
    println!("the seventy bonds were taken out within {waited} more minutes");
    for _ in 0..5 {
        net.block(MINUTE);
        assert!(net.starting_above_half());
    }
    assert!(net.reached_at().is_none());
    assert!(!net.summary.bootstrap_ended);
    // Fourteen days later nothing has ended, and seven bonds hold seven bonds
    // of the target again.
    net.run_to_day(116);
    assert!(!net.summary.bootstrap_ended && net.reached_at().is_none());
    let (attacker, total) = Net::power(&net.summary.active, is_attacker);
    println!("day 116: attacker {:.1}%", percent(attacker, total));
    assert_eq!(attacker, 7 * POWER);
    assert!(total >= target(114));
}

/// The end needs the target held for fourteen days, then is for good; until
/// then the starting validators hold more than half, and after it they
/// leave as fast as the churn limit allows.
#[test]
fn the_end_needs_the_target_held_for_fourteen_days() {
    let mut net = Net::production(true);
    net.run_to_day(99);
    // Before anyone stakes, the starting validators hold the whole target.
    let (starting, total) = Net::power(&net.summary.active, is_starting);
    assert_eq!(starting, total);
    assert!(total >= target(97) && total <= target(97) + ROUNDING);
    // Eighty honest validators of one bond each, against a target of 60.
    net.begin(DAY);
    for id in 200..280 {
        net.admit(id, 0);
    }
    net.settle();
    let mut reached = None;
    let mut ended = None;
    for day in 101..=400 {
        net.run_to_day(day);
        if reached.is_none() {
            reached = net.reached_at().map(|at| at / DAY);
        }
        if ended.is_none() && net.summary.bootstrap_ended {
            ended = Some(day);
        }
        match ended {
            None => assert!(net.starting_above_half(), "day {day}"),
            Some(end) if day >= end + 3 => {
                assert!(net.summary.active.iter().all(|v| !is_starting(v.owner)), "day {day}")
            }
            Some(_) => {}
        }
    }
    let (reached, ended) = (reached.unwrap(), ended.unwrap());
    println!("target reached on day {reached}, the bootstrap ended on day {ended}");
    assert_eq!(ended, reached + 14);
    // The target grew past eighty bonds on day 200. Nothing returned.
    assert!(net.summary.bootstrap_ended);
    assert_eq!(Net::power(&net.summary.active, is_starting).0, 0);
}

/// One block a day carrying a day of rewards, a fifth of the new time (the
/// protocol-4 issuance), split by voting power. The attacker bonds what it
/// is paid. Returns the days on which the attacker's seven validators reach
/// a third, pass two thirds, and on which the bootstrap ends, and the
/// attacker's share on day 10 and at the end.
fn compounding(stake_rule: bool, days: u64) -> ([Option<u64>; 3], f64, (u64, u64)) {
    let mut net = Net::production(stake_rule);
    net.begin(DAY);
    for id in 100..107 {
        net.admit(id, 0);
    }
    net.settle();
    let mut found = [None; 3];
    let mut early = 0.0;
    for day in 2..=days {
        let signers = net.summary.active.clone();
        let ended = net.summary.bootstrap_ended;
        net.begin(DAY);
        let earned = net.pay(&signers, ended, DAY / 5);
        for (owner, amount) in earned {
            if is_attacker(owner) && amount > 0 {
                net.bond(owner, amount);
            }
        }
        net.settle();
        let (attacker, total) = Net::power(&net.summary.active, is_attacker);
        if day == 10 {
            early = percent(attacker, total);
        }
        if found[0].is_none() && attacker * 3 >= total {
            found[0] = Some(day);
        }
        if found[1].is_none() && attacker * 3 > total * 2 {
            found[1] = Some(day);
        }
        if found[2].is_none() && net.summary.bootstrap_ended {
            found[2] = Some(day);
        }
    }
    (found, early, Net::power(&net.summary.active, is_attacker))
}

/// First review, finding 4: seven minimum bonds that bond their rewards took
/// the network by waiting, on day 92 under the calendar. Under the stake
/// rule the target grows as fast as all validators are paid together, so
/// stake that only bonds its rewards keeps its share of the target and
/// never gains by waiting.
#[test]
fn bonding_rewards_alone_never_takes_the_network() {
    let (found, early, (attacker, total)) = compounding(true, 600);
    println!(
        "stake rule, the attacker bonds its rewards for 600 days: third / two thirds / end {found:?}, \
         share {early:.2}% on day 10 and {:.2}% at the end",
        percent(attacker, total)
    );
    assert_eq!(found, [None, None, None]);
    assert!(percent(attacker, total) <= early + 0.05, "{early} -> {attacker} of {total}");
    let (calendar, _, _) = compounding(false, 100);
    println!("calendar rule, for comparison: {calendar:?}");
    assert!(calendar[1].is_some() && calendar[2].is_some());
}

/// Seven validators of one bond, and an operator (owner 200) with one bond
/// of its own and `delegated` bonds that a stranger delegated to it. On day
/// 120 the operator asks for its bond back. Accepted at once?
fn operator_leaves(stake_rule: bool, delegated: u64) -> Result<u64, String> {
    let mut net = Net::production(stake_rule);
    net.begin(DAY);
    for id in 100..107 {
        net.admit(id, 0);
    }
    net.admit(200, 0);
    if delegated > 0 {
        net.delegate(900, 200, delegated * BOND);
    }
    net.settle();
    net.run_to_day(120);
    net.begin(MINUTE);
    net.exit(200, 200, ExitKind::SelfBond, BOND)
}

/// First review, finding 5: a stranger's delegation of six bonds or more
/// pinned the operator's own bond, because its exit had to make room for
/// the starting validators' return. While an exit must fit, the starting
/// validators stay as they are.
#[test]
fn an_exit_never_waits_for_the_starting_validators() {
    for delegated in [0, 1, 5, 6, 10, 20, 30] {
        assert!(operator_leaves(false, delegated).is_ok(), "calendar, {delegated}");
        let outcome = operator_leaves(true, delegated);
        assert!(outcome.is_ok(), "stake rule, {delegated} bonds delegated: {outcome:?}");
    }
}

/// Second review, finding 6: a second exit soon after a first one waited
/// while the starting validators' group move spent the churn budget. Exits
/// from a delegator taken out every minute, while the starting validators
/// follow: none waits.
#[test]
fn exits_in_a_row_never_wait_for_the_starting_validators() {
    let mut net = Net::production(true);
    net.begin(DAY);
    for id in 100..107 {
        net.admit(id, 0);
    }
    for id in 400..420 {
        net.admit(id, 0);
    }
    net.admit(300, 0);
    net.delegate(901, 300, 15 * BOND);
    net.admit(301, 0);
    net.delegate(902, 301, 5 * BOND);
    net.settle();
    net.run_to_day(120);
    net.begin(MINUTE);
    net.exit(901, 300, ExitKind::Delegation, net.shares_of(901, 300)).unwrap();
    for minute in 0..5 {
        net.block(MINUTE);
        let shares = net.shares_of(902, 301);
        net.exit(902, 301, ExitKind::Delegation, shares / 5)
            .unwrap_or_else(|error| panic!("minute {minute}: {error}"));
        assert!(net.starting_above_half());
    }
}

/// Real stake that leaves gives the starting validators its seats back,
/// until the hand-over is complete.
#[test]
fn stake_that_leaves_before_the_end_returns_the_starting_power() {
    let mut net = Net::production(true);
    net.begin(DAY);
    for id in 20..50 {
        net.admit(id, 0);
    }
    net.settle();
    net.run_to_day(120);
    let before = Net::power(&net.summary.active, is_starting).0;
    // Ten validators lose their funding (as after an exit).
    net.begin(DAY);
    for candidate in net.candidates.iter_mut().filter(|c| (40..50).contains(&c.owner)) {
        net.summary.escrow -= candidate.self_bond;
        candidate.self_bond = 0;
    }
    net.settle();
    net.run_to_day(125);
    let after = Net::power(&net.summary.active, is_starting).0;
    println!("starting validators: {before} before, {after} after");
    // Ten bonds of seats, and five days of growth of the target.
    assert!(after >= before + 10 * POWER && after <= before + 12 * POWER, "{before} -> {after}");
    assert!(!net.summary.bootstrap_ended);
}

/// With independent stake above the target from the first days, the stake
/// rule ends on the day the calendar ends the starting validators' virtual
/// power (day 90), never before; until then they hold more than half, and a
/// few days later both networks have the same roster.
#[test]
fn with_enough_stake_the_rule_ends_when_the_calendar_does() {
    let mut calendar = Net::production(false);
    let mut stake = Net::production(true);
    let mut ended = [None, None];
    for day in 1..=150 {
        for net in [&mut calendar, &mut stake] {
            net.begin(DAY);
            // Eighty bonds in the first eight days, ten validators a day.
            if day <= 8 {
                for slot in 0..10 {
                    net.admit(200 + (day - 1) * 10 + slot, 0);
                }
            }
            net.settle();
        }
        for (index, net) in [&calendar, &stake].into_iter().enumerate() {
            if ended[index].is_none() && net.summary.bootstrap_ended {
                ended[index] = Some(day);
            }
        }
        if ended[1].is_none() {
            assert!(stake.starting_above_half(), "day {day}");
        }
        if day >= 96 {
            assert_eq!(stake.summary.active, calendar.summary.active, "day {day}");
        }
    }
    println!("the bootstrap ended on day {:?} (calendar) and {:?} (stake rule)", ended[0], ended[1]);
    let (calendar_end, stake_end) = (ended[0].unwrap(), ended[1].unwrap());
    assert_eq!(stake_end, 90);
    assert!(calendar_end >= 90 && calendar_end <= 93);
}

/// The starting validators' own stake never ends their bootstrap: not their
/// own bonds, not stake delegated to them, however large. And the end needs
/// seven funded validators other than theirs.
#[test]
fn their_own_stake_never_ends_the_bootstrap() {
    let mut net = Net::production(true);
    net.begin(DAY);
    // Ten bonds of each starting validator's own, and ten delegated to each:
    // four hundred bonds, ten times the target.
    for id in 0..20 {
        net.bond(id, 10 * BOND);
        net.delegate(900, id, 10 * BOND);
    }
    net.settle();
    for day in 2..=200 {
        net.run_to_day(day);
        assert!(net.reached_at().is_none() && !net.summary.bootstrap_ended, "day {day}");
    }
    // Six independent validators of twenty bonds each: far above the target,
    // held for months, still no end.
    for id in 200..206 {
        net.admit(id, 19 * BOND);
    }
    net.settle();
    net.run_to_day(260);
    assert!(net.reached_at().is_some(), "six validators hold the target");
    assert!(!net.summary.bootstrap_ended, "but six are not seven");
    assert!(net.starting_above_half());
    // A seventh, and the end comes once it is in force.
    net.begin(DAY);
    net.admit(206, 0);
    net.settle();
    net.run_to_day(265);
    assert!(net.summary.bootstrap_ended);
}

/// Massive stake brought at once, concentrated or spread over every free
/// seat: the starting validators rise first, nobody else's raise takes them
/// below half, and the end still waits fourteen days.
#[test]
fn the_starting_validators_rise_first_and_keep_more_than_half() {
    for spread in [false, true] {
        let mut net = Net::production(true);
        net.run_to_day(100);
        net.begin(HOUR);
        if spread {
            // Eighty validators (every seat the starting validators leave
            // free) of ten bonds each.
            for id in 200..280 {
                net.admit(id, 9 * BOND);
            }
        } else {
            // Seven validators of a hundred bonds each.
            for id in 100..107 {
                net.admit(id, 99 * BOND);
            }
        }
        net.settle();
        let mut hours = 0;
        let mut seated_after = None;
        while !net.summary.bootstrap_ended {
            net.block(HOUR);
            hours += 1;
            assert!(net.starting_above_half(), "spread {spread}, hour {hours}");
            if seated_after.is_none() && net.reached_at().is_some() {
                seated_after = Some(hours);
            }
            assert!(hours < 20 * 24, "never ended");
        }
        let seated_after = seated_after.unwrap();
        println!("spread {spread}: target reached after {seated_after} hours, the end after {hours}");
        assert!(hours >= seated_after + 14 * 24 - 1);
    }
}

/// A starting validator jailed for signing twice leaves its seat at once;
/// the others take its part at their next move.
#[test]
fn the_others_take_a_jailed_starting_validators_part() {
    let mut net = Net::production(true);
    net.begin(DAY);
    for id in 200..230 {
        net.admit(id, 0);
    }
    net.settle();
    net.run_to_day(100);
    // Five starting validators sign twice and are jailed (nothing of theirs
    // is staked, so nothing is taken).
    net.begin(MINUTE);
    for id in 0..5 {
        slash(net.row(id)).unwrap();
    }
    net.settle();
    let mut minutes = 0;
    while net.summary.active.iter().any(|v| v.owner < 5) || !net.starting_above_half() {
        net.block(MINUTE);
        minutes += 1;
        assert!(minutes < 60, "the others never took the part");
    }
    println!("the jailed validators were out and the others above half after {minutes} minutes");
    let (starting, total) = Net::power(&net.summary.active, is_starting);
    assert!(starting * 2 > total && total >= target(100) - POWER);
}

/// Second review, finding 4: the hold is counted in block time. Under the
/// stake rule the starting validators hold more than half of the votes all
/// through the hold, so a block dated ahead needs their votes, and the
/// clock check of the engine refuses such a proposal.
#[test]
fn during_the_hold_the_starting_validators_hold_more_than_half() {
    let mut net = Net::production(true);
    net.block(HOUR);
    for id in 100..107 {
        net.admit(id, 0);
    }
    net.run_to_day(100);
    for id in 100..107 {
        net.delegate(900, id, 10 * BOND);
    }
    let mut hours = 0;
    while !net.summary.bootstrap_ended {
        net.block(HOUR);
        hours += 1;
        let (attacker, total) = Net::power(&net.summary.active, is_attacker);
        assert!(attacker * 2 < total && net.starting_above_half(), "hour {hours}");
        assert!(hours < 16 * 24);
    }
    println!("ended after {hours} hourly blocks; the attacker never held half");
    assert!(hours >= 14 * 24);
}

/// A network that pays all new time to validators, under the stake rule (so
/// that nothing is bonded for the starting validators, `pos_adapter`). Their
/// operator gives `given` parts in a hundred of what they are paid to seven
/// independent validators (owners 300..307) in turn, which stake everything
/// they get and everything they earn. One block a day. Returns the day the
/// bootstrap ends (None within `days`) and the largest share of the votes in
/// force the independents held before it.
fn handed_over(given: u64, days: u64) -> (Option<u64>, f64) {
    let mut net = Net::production(true);
    let mut held: BTreeMap<u64, u64> = BTreeMap::new();
    let mut turn = 0u64;
    let mut largest = 0.0f64;
    for day in 1..=days {
        let signers = net.summary.active.clone();
        let ended = net.summary.bootstrap_ended;
        net.begin(DAY);
        for (owner, amount) in net.pay(&signers, ended, DAY) {
            if is_starting(owner) {
                *held.entry(300 + turn % 7).or_default() += amount * given / 100;
                turn += 1;
            } else {
                *held.entry(owner).or_default() += amount;
            }
        }
        for id in 300..307 {
            let amount = std::mem::take(held.entry(id).or_default());
            if net.candidates.iter().any(|c| c.owner == id) {
                if amount > 0 {
                    net.bond(id, amount);
                }
            } else if amount >= BOND {
                net.admit(id, amount - BOND);
            } else {
                held.insert(id, amount);
            }
        }
        net.settle();
        if net.summary.bootstrap_ended {
            return (Some(day), largest);
        }
        let (independent, total) = Net::power(&net.summary.active, |owner| !is_starting(owner));
        assert!(independent * 2 < total, "day {day}");
        largest = largest.max(percent(independent, total));
    }
    (None, largest)
}

/// How soon the hand-over can come when all new time goes to validators and
/// the starting validators are paid in full: it depends on how much of what
/// they are paid their operator passes on. Whoever receives it can approach
/// half of the votes before the end, never reach it.
#[test]
fn paid_in_full_the_operator_decides_when_the_hand_over_comes() {
    let mut ends = Vec::new();
    for given in [100, 50, 25, 10, 5] {
        let (end, largest) = handed_over(given, 3 * 365);
        println!("operator passes on {given}%: end {end:?}, independents held at most {largest:.1}% before it");
        assert!(largest < 50.0);
        ends.push(end.unwrap_or(u64::MAX));
    }
    // Everything passed on: the end comes with the calendar period.
    assert_eq!(ends[0], 90);
    // The less is passed on, the later the end.
    assert!(ends.windows(2).all(|pair| pair[0] <= pair[1]), "{ends:?}");
}

#[test]
fn the_rule_is_written_into_the_summary_only_when_it_is_used() {
    let roster = |profile: Profile, count: u64| -> Vec<Validator> {
        (0..count)
            .map(|id| Validator {
                owner: id,
                consensus_key: public(id),
                power: profile.genesis_power(),
            })
            .collect()
    };
    let old = Summary::with_profile(roster(Profile::Production, 20), Profile::Production).unwrap();
    let same = Summary::with_rules(roster(Profile::Production, 20), Profile::Production, false).unwrap();
    assert_eq!(old, same);
    let text = serde_json::to_string(&old).unwrap();
    assert!(!text.contains("stake_handover"), "{text}");
    assert!(text.ends_with(r#""safety_hold":false}"#), "{text}");
    assert!(old.handover_matches(false, 20).unwrap());
    assert!(!old.handover_matches(true, 20).unwrap());

    let new = Summary::with_rules(roster(Profile::Production, 20), Profile::Production, true).unwrap();
    assert_eq!(
        new.stake_handover,
        Some(StakeHandover { target_power: 40 * POWER, supply_share_ppm: 200_000, reached_at: None })
    );
    assert!(new.handover_matches(true, 20).unwrap());
    assert!(!new.handover_matches(false, 20).unwrap());
    assert!(!new.handover_matches(true, 19).unwrap(), "the target follows the starting validators");
    let rule = r#""stake_handover":{"target_power":"3456000","supply_share_ppm":"200000"}}"#;
    let text = serde_json::to_string(&new).unwrap();
    assert!(text.ends_with(&format!(r#""safety_hold":false,{rule}"#)), "{text}");
    assert_eq!(serde_json::from_str::<Summary>(&text).unwrap(), new);
    let mut reached = new.clone();
    reached.last_elapsed = 7;
    reached.stake_handover.as_mut().unwrap().reached_at = Some(7);
    let with_time = serde_json::to_string(&reached).unwrap();
    assert!(with_time.contains(r#""supply_share_ppm":"200000","reached_at":"7"}"#), "{with_time}");
    assert_eq!(serde_json::from_str::<Summary>(&with_time).unwrap(), reached);
    reached.validate().unwrap();
    // The time it was reached is state, not a parameter.
    assert!(reached.handover_matches(true, 20).unwrap());
    // Other parameters than the genesis sets are refused by the engines.
    for (target_power, supply_share_ppm) in [(40 * POWER + 1, 200_000), (40 * POWER, 250_000), (40 * POWER, 0)] {
        let mut changed = new.clone();
        changed.stake_handover = Some(StakeHandover { target_power, supply_share_ppm, reached_at: None });
        changed.validate().unwrap();
        assert!(!changed.handover_matches(true, 20).unwrap(), "{target_power} {supply_share_ppm}");
    }
    // Forms that are refused.
    for bad in [
        r#""stake_handover":{"target_power":3456000,"supply_share_ppm":"200000"}}"#,
        r#""stake_handover":{"target_power":"03456000","supply_share_ppm":"200000"}}"#,
        r#""stake_handover":{"target_power":"3456000"}}"#,
        r#""stake_handover":{"target_power":"3456000","supply_share_ppm":"200000","more":"1"}}"#,
        r#""stake_handover":{"target_power":"3456000","supply_share_ppm":"200000","reached_at":7}}"#,
        r#""stake_handover":{"target_power":"3456000","supply_share_ppm":"200000","reached_at":null}}"#,
        r#""stake_handover":{"target_power":"3456000","supply_share_ppm":"200000","reached_at":"07"}}"#,
        r#""stake_handover":{}}"#,
    ] {
        let forged = text.replace(rule, bad);
        assert_ne!(forged, text);
        assert!(serde_json::from_str::<Summary>(&forged).is_err(), "{bad}");
    }
    for broken in [
        StakeHandover { target_power: 0, supply_share_ppm: 200_000, reached_at: None },
        StakeHandover { target_power: 1, supply_share_ppm: 1_000_001, reached_at: None },
        StakeHandover { target_power: 1, supply_share_ppm: 200_000, reached_at: Some(1) },
    ] {
        let mut summary = new.clone();
        summary.stake_handover = Some(broken.clone());
        assert!(summary.validate().is_err(), "{broken:?}");
    }
    // The laboratory profile: four starting validators of power one.
    let lab = Summary::with_rules(roster(Profile::Laboratory, 4), Profile::Laboratory, true).unwrap();
    assert_eq!(lab.stake_handover.as_ref().unwrap().target_power, 8);
    assert!(lab.handover_matches(true, 4).unwrap());
}

/// The laboratory profile in its own small numbers: a target of eight
/// seconds of stake plus a fifth of the elapsed time, and a hold of sixty
/// seconds.
#[test]
fn the_laboratory_profile_hands_over_once_stake_holds_the_target() {
    let mut net = Net::new(Profile::Laboratory, 4, true);
    let step = |net: &mut Net, admissions: &dyn Fn(&mut Net)| {
        net.begin(20 * SECOND);
        admissions(net);
        net.settle();
    };
    for _ in 0..30 {
        step(&mut net, &|_| {});
    }
    // Ten minutes and nobody stakes: the starting validators fill the target
    // of two blocks before, 8 + 560 / 5 = 120 seconds of stake, far above
    // their power of one.
    let (starting, total) = Net::power(&net.summary.active, |owner| owner < 4);
    assert_eq!(starting, total);
    assert_eq!(total, 120);
    assert!(!net.summary.bootstrap_ended);
    // Seven validators of a thousand seconds each.
    step(&mut net, &|net| {
        for id in 4..11 {
            net.admit(id, 999 * SECOND);
        }
    });
    let mut steps = 0;
    while !net.summary.bootstrap_ended {
        step(&mut net, &|_| {});
        steps += 1;
        let (starting, total) = Net::power(&net.summary.active, |owner| owner < 4);
        assert!(starting * 2 > total, "step {steps}");
        assert!(steps < 30, "never ended");
    }
    println!("laboratory: ended {steps} blocks of twenty seconds after the stake arrived");
    assert!(steps >= 3, "not before the sixty-second hold");
    for _ in 0..5 {
        step(&mut net, &|_| {});
    }
    // Owners 0..4 are the starting validators of this profile.
    assert_eq!(Net::power(&net.summary.active, |owner| owner < 4).0, 0);
}
