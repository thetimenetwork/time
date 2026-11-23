//! THIRD REVIEW (independent). Finding B: a delegation parked on one funded
//! starting validator counts as their own stake and lowers every virtual
//! part, but the 30% cap of `cap_concentration` then cuts that validator, so
//! the starting validators' target falls below max(gap, others + 1). The
//! majority guard is then all that holds them, just above everyone else: an
//! outsider seated at 30% of the target holds about half of the votes, for
//! as long as the delegation stays (no exit, no timing). The lib.rs claim
//! "until the end the total voting power is at least the target" fails.
mod review3_common;
use review3_common::Net;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const POWER: u64 = 86_400;
const HOUR: u64 = 3600 * SECOND;

/// Design 4.1: the delegation comes on top of the starting validators' part,
/// and their part rises until, after the cap, they hold what they need. The
/// outsider holds less than its seated share of the target, and the total in
/// force is at least the target.
#[test]
fn a_parked_delegation_never_lets_thirty_percent_of_the_target_hold_half() {
    let mut net = Net::new(Profile::Production, 20, true);
    net.block(HOUR);
    net.bond(0, BOND); // starting validator 0: its operator bonds one bond
    net.settle();
    net.run_to(100 * DAY, 6 * HOUR);
    net.begin(HOUR);
    for id in 100..107 {
        net.admit(id, 18 * BOND / 7 - BOND); // eighteen bonds in all
    }
    net.settle();
    net.run_to(net.now + DAY, HOUR);
    let (a0, t0) = Net::power(&net.summary.active, |o| (100..200).contains(&o));
    println!("before: attacker {:.1}% of votes, total {:.1} bonds, target {:.1}", 100.0 * a0 as f64 / t0 as f64, t0 as f64 / POWER as f64, net.target_now() as f64 / POWER as f64);
    // A second account of the attacker delegates forty bonds to starting validator 0.
    net.delegate(900, 0, 40 * BOND);
    net.settle();
    net.run_to(net.now + 3 * DAY, HOUR);
    let (a1, t1) = Net::power(&net.summary.active, |o| (100..200).contains(&o));
    let target = net.target_now();
    println!(
        "after: attacker seated {:.1} bonds ({:.1}% of the target) holds {:.1}% of votes; total in force {:.1} bonds vs a target of {:.1}",
        a1 as f64 / POWER as f64,
        100.0 * a1 as f64 / target as f64,
        100.0 * a1 as f64 / t1 as f64,
        t1 as f64 / POWER as f64,
        target as f64 / POWER as f64
    );
    assert!(t1 >= target - POWER, "total in force below the target");
    assert!(a1 * 100 < target * 31);
    assert!(a1 * 100 < t1 * 30, "the outsider holds more than its share of the target");
}
