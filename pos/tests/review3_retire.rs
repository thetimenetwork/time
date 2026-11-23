//! THIRD REVIEW (independent). Finding D: delegations parked on funded
//! starting validators make `part` zero; after the calendar period the
//! unfunded starting validators then have no virtual power, leave the
//! roster, and fourteen days later the engine archives them
//! (`pos_adapter::begin_block` retires every unfunded candidate that is not
//! in a roster and whose exposure has expired). Archived, they never return,
//! before the end of the bootstrap. The retirement step of the adapter is
//! reproduced here.
mod review3_common;
use review3_common::Net;
use time_pos::*;

const BOND: u64 = SELF_BOND_MIN;
const HOUR: u64 = 3600 * SECOND;

fn retire(net: &mut Net) {
    let mut rows = net.candidates.clone();
    for row in &mut rows {
        if !row.funded(net.summary.profile.min_self_bond())
            && !net.summary.current_or_scheduled(row.owner)
            && net.summary.exposure_expired(row).unwrap()
        {
            net.summary.retire_candidate(row).unwrap();
        }
    }
    net.candidates = rows.into_iter().filter(|c| !c.archived).collect();
}

/// Design 4.1: every unjailed starting validator holds at least a hundredth
/// of its genesis power until the end, so none leaves the roster or is
/// archived before it.
#[test]
fn parked_delegations_never_retire_a_starting_validator() {
    let mut net = Net::new(Profile::Production, 20, true);
    net.block(HOUR);
    for g in 0..4 {
        net.bond(g, BOND);
    }
    // Three minimum bonds of the attacker: seven funded candidates in all.
    for id in 100..103 {
        net.admit(id, 0);
    }
    net.settle();
    net.run_to(95 * DAY, 6 * HOUR);
    for g in 0..4 {
        net.delegate(900, g, 17 * BOND);
    }
    net.settle();
    for _ in 0..20 * 4 {
        net.begin(6 * HOUR);
        retire(&mut net);
        net.settle();
    }
    let left: Vec<u64> = net.candidates.iter().filter(|c| c.genesis).map(|c| c.owner).collect();
    println!("starting validators left as candidates on day {}: {left:?}", net.now / DAY);
    assert!(!net.summary.bootstrap_ended);
    assert_eq!(left, (0..20).collect::<Vec<u64>>(), "starting validators archived before the end");
}
