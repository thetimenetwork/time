//! THIRD REVIEW (independent). Attacks on the stake hand-over rule.
//!
//! Finding A: stake delegated to a FUNDED starting validator counts as the
//! starting validators' own stake, so it lowers every starting validator's
//! virtual part. When the delegator takes it out, the exit has
//! `required_owner` = that starting validator: the group is frozen, the
//! starting validator's own decrease runs through the ordinary loop without
//! the majority guard, and the exit itself spends the churn budget, so the
//! group cannot rise again until the budget frees (an hour of block time).
mod review3_common;
use review3_common::Net;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const POWER: u64 = 86_400;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;
fn is_attacker(owner: u64) -> bool {
    (100..200).contains(&owner)
}

/// Scenario: production, day 100 (target 60 bonds). Two starting validators
/// (0 and 1) are funded by their operator with one bond each. The attacker
/// runs seven validators with `attacker_bonds` bonds in all, and delegates
/// `delegated` bonds to each of starting validators 0 and 1. Once all of it
/// is in force and the churn budget is clear, it takes both delegations out
/// in one block. Returns the attacker's largest share of the roster in force
/// over the next hour of block time, with blocks every `step`.
fn delegation_exit(attacker_bonds: u64, delegated: [u64; 2], step: u64) -> (f64, f64, f64, u64) {
    let mut net = Net::new(Profile::Production, 20, true);
    net.block(HOUR);
    net.bond(0, BOND);
    net.bond(1, BOND);
    net.settle();
    net.run_to(100 * DAY, 6 * HOUR);
    // Seven attacker validators, `attacker_bonds` bonds in all (in tenths).
    net.begin(HOUR);
    let each = attacker_bonds * BOND / 70;
    for id in 100..107 {
        net.admit(id, each - BOND);
    }
    net.settle();
    for (i, d) in delegated.iter().enumerate() {
        if *d > 0 {
            net.delegate(900, i as u64, d * BOND / 10);
        }
    }
    net.settle();
    net.run_to(net.now + 2 * DAY, HOUR);
    let before = net.share(&net.summary.active, is_attacker);
    let starting_before = net.share(&net.summary.active, |o| o < 20);
    assert!(starting_before > 0.5, "setup: starting {starting_before}");
    let seated_attacker = Net::power(&net.summary.active, is_attacker).0;
    println!(
        "before: target {} bonds, attacker seated {:.2} bonds = {:.1}% of the target, holds {:.1}% of votes; starting {:.1}%; churn used {}",
        net.target_now() as f64 / POWER as f64,
        seated_attacker as f64 / POWER as f64,
        100.0 * seated_attacker as f64 / net.target_now() as f64,
        100.0 * before,
        100.0 * starting_before,
        net.churn_used()
    );
    // One block: both delegations leave.
    net.begin(MINUTE);
    for g in 0..2u64 {
        let shares = net.shares_of(900, g);
        if shares > 0 {
            let r = net.exit(900, g, ExitKind::Delegation, shares);
            println!("exit of the delegation to starting validator {g}: {r:?}; churn used {}", net.churn_used());
        }
    }
    net.settle();
    let mut largest = 0.0f64;
    let mut lowest_starting = 1.0f64;
    let mut blocks_above_half = 0;
    let count = if step >= MINUTE { (HOUR + 2 * MINUTE) / step } else { 300 };
    for _ in 0..count {
        net.block(step);
        let a = net.share(&net.summary.active, is_attacker);
        let s = net.share(&net.summary.active, |o| o < 20);
        if a >= 0.5 {
            blocks_above_half += 1;
        }
        largest = largest.max(a);
        lowest_starting = lowest_starting.min(s);
    }
    println!(
        "after: the attacker holds up to {:.1}% of the votes in force, the starting validators as little as {:.1}%; {} blocks with the attacker at half or more",
        100.0 * largest,
        100.0 * lowest_starting,
        blocks_above_half
    );
    (before, largest, lowest_starting, blocks_above_half)
}

/// Third review, finding A: a delegator's exit from a starting validator
/// took the starting validators below half (design 4 counted the delegation
/// as theirs). Design 4.1: delegated stake comes on top of their part, so
/// taking it out leaves them above half, and the attacker holds no more than
/// its seated stake divided by the target.
#[test]
fn a_delegators_exit_never_takes_the_starting_validators_below_half() {
    let (before, largest, starting, blocks) = delegation_exit(240, [100, 100], MINUTE);
    assert!(before < 0.40);
    assert!(largest < 0.40, "the attacker reached {largest}");
    assert!(starting > 0.5);
    assert_eq!(blocks, 0);
}

/// The same with the attacker at about half of the target: design 4 gave it
/// more than two thirds. Design 4.1: below half, at its seated stake divided
/// by the target (48.8%).
#[test]
fn a_delegators_exit_never_gives_an_outsider_half() {
    let (_, largest, starting, _) = delegation_exit(295, [100, 100], MINUTE);
    assert!(largest < 0.49, "the attacker reached {largest}");
    assert!(starting > 0.5, "starting fell to {starting}");
}

/// Design 4 let the attacker freeze block time once it held two thirds.
/// Design 4.1: blocks one microsecond apart change nothing, since the
/// starting validators never fell below half.
#[test]
fn with_block_time_frozen_the_starting_validators_still_hold_half() {
    let (_, largest, starting, _) = delegation_exit(295, [100, 100], 1);
    println!("blocks one microsecond apart: attacker {largest}, starting {starting}");
    assert!(largest < 0.49 && starting > 0.5);
}

/// Design 4 gave a third of the votes (enough to halt) to seated stake well
/// under a third of the target. Design 4.1: a third of the votes costs a
/// third of the target.
#[test]
fn a_third_costs_a_third_of_the_target() {
    let (before, largest, _, _) = delegation_exit(150, [100, 100], MINUTE);
    println!("attacker share before {before}, after {largest}");
    assert!(before < 0.30);
    assert!(largest * 3.0 < 1.0, "the attacker reached {largest}");
}
