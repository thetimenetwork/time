//! FOURTH REVIEW (independent) of design 4.1.
mod review3_common;
use review3_common::Net;
use std::sync::mpsc;
use std::time::Duration;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const POWER: u64 = 86_400;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

/// Finding 1: with every starting validator jailed, `part` is 0 (count == 0)
/// and the doubling loop of the cap iteration multiplies 0 forever: reconcile
/// never returns, so every node spins in begin_block and the chain halts.
fn all_jailed(profile: Profile, starting: u64) {
    let mut net = Net::new(profile, starting, true);
    net.block(if profile == Profile::Production { HOUR } else { SECOND });
    // Four outsiders, so that the roster without the starting validators is
    // large enough (MIN_ACTIVE) for the jailed ones to be removed.
    for id in 100..104 {
        net.admit(id, 0);
    }
    net.settle();
    for _ in 0..10 {
        net.block(if profile == Profile::Production { HOUR } else { SECOND });
    }
    net.begin(if profile == Profile::Production { MINUTE } else { SECOND });
    for id in 0..starting {
        slash(net.row(id)).unwrap();
    }
    net.settle(); // the clean path removes them
    let (tx, rx) = mpsc::channel();
    let mut moved = net.clone();
    std::thread::spawn(move || {
        for _ in 0..3 {
            moved.block(if moved.summary.profile == Profile::Production { MINUTE } else { SECOND });
        }
        let _ = tx.send(());
    });
    let finished = rx.recv_timeout(Duration::from_secs(60)).is_ok();
    assert!(finished, "reconcile never returned with every starting validator jailed");
}

#[test]
fn every_starting_validator_jailed_the_others_go_on_production() {
    all_jailed(Profile::Production, 20);
}

#[test]
fn every_starting_validator_jailed_the_others_go_on_laboratory() {
    all_jailed(Profile::Laboratory, 4);
}

/// Finding 2: a delegator's exit from a starting validator now needs the
/// group's whole pending move to fit at once. While the group catches up
/// with a large arrival of stake (hours), such exits are refused. Design 4
/// accepted them at once. Prints how long the exit waits.
#[test]
fn a_large_founder_bond_and_the_cap_iteration() {
    let mut net = Net::new(Profile::Production, 20, true);
    net.block(HOUR);
    net.bond(0, 50 * BOND);
    net.settle();
    net.run_to(100 * DAY, 6 * HOUR);
    net.begin(HOUR);
    for id in 100..107 {
        net.admit(id, 3 * BOND);
    }
    net.settle();
    net.run_to(net.now + 3 * DAY, HOUR);
    let (a, t) = Net::power(&net.summary.active, |o| (100..200).contains(&o));
    let (s, _) = Net::power(&net.summary.active, |o| o < 20);
    let target = net.target_now();
    println!(
        "attacker {:.1} bonds = {:.1}% of the votes; starting {:.1} bonds; total {:.1} bonds; target {:.1}",
        a as f64 / POWER as f64,
        100.0 * a as f64 / t as f64,
        s as f64 / POWER as f64,
        t as f64 / POWER as f64,
        target as f64 / POWER as f64
    );
    assert!(s > t - s);
    assert!(t + POWER >= target, "total in force {t} below the target {target}");
}
