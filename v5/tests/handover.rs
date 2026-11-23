//! The stake hand-over rule as a setting of the network (`stake_handover` in
//! the genesis). The rule itself is tested in `pos/tests/handover.rs`; here:
//! how a network chooses it, that a network that does not is unchanged, and
//! how it works with `all_new_time_to_validators`.
mod common;
use common::*;
use serde_json::{Value, json};
use timecurrency_v5::engine::{Engine, Meta};
use timecurrency_v5::genesis::{BootstrapValidator, Genesis};
use timecurrency_v5::pos_adapter::SUMMARY_KEY;
use timecurrency_v5::store::Store;

const SECOND: u64 = 1_000_000;

struct Chain {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Chain {
    fn new(genesis: Genesis) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open_with_history(
            Store::open(dir.path().join("state.v5state")).unwrap(),
            dir.path().join("history"),
        )
        .unwrap();
        engine.initialize(genesis).unwrap();
        Self { _dir: dir, engine }
    }
    fn meta(&self) -> &Meta {
        self.engine.meta().unwrap()
    }
    fn summary(&self) -> pos::Summary {
        serde_json::from_slice(&self.engine.version().unwrap().get(SUMMARY_KEY).unwrap()).unwrap()
    }
    /// A block `delta` after the last one, signed by the whole roster.
    fn block(&mut self, delta: u64) {
        let meta = self.meta();
        let (height, time) = (meta.height + 1, meta.time_micros + delta as i64);
        let signers: Vec<String> = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|validator| validator.consensus_key)
            .collect();
        let hash = sha(height as u64);
        let none: [Vec<u8>; 0] = [];
        let prepared = self.engine.prepare(height, time, &none, &signers, hash).unwrap();
        self.engine.commit(prepared, hash).unwrap();
        let meta = self.meta();
        assert_eq!(
            meta.bank + meta.liquid_total + meta.pos_assets_total + meta.auction_reserve_total,
            meta.elapsed_micros().unwrap(),
            "supply rule"
        );
    }
}

#[test]
fn a_network_without_the_setting_is_unchanged() {
    let genesis = genesis_v5();
    assert!(!genesis.stake_handover);
    let text = serde_json::to_string(&genesis).unwrap();
    assert!(!text.contains("stake_handover"), "{text}");
    assert_eq!(genesis.network_id().unwrap(), network_id(), "protocol-4 network id");
    let mut chain = Chain::new(genesis);
    assert_eq!(chain.summary().stake_handover, None);
    let row = chain.engine.version().unwrap().get(SUMMARY_KEY).unwrap();
    assert!(!String::from_utf8_lossy(&row).contains("stake_handover"));
    for _ in 0..5 {
        chain.block(30 * SECOND);
    }
    chain.engine.audit().unwrap();
}

#[test]
fn a_network_that_sets_it_records_the_target_and_runs() {
    let mut genesis = genesis_v5();
    genesis.stake_handover = true;
    assert_ne!(genesis.network_id().unwrap(), network_id(), "the setting is part of the network id");
    let mut chain = Chain::new(genesis);
    // Four starting validators of power one: twice their combined power.
    assert_eq!(
        chain.summary().stake_handover,
        Some(pos::StakeHandover { target_power: 8, supply_share_ppm: 200_000, reached_at: None })
    );
    // Past the laboratory fade period of sixty seconds with no other stake:
    // the starting validators keep their seats and fill the target, eight
    // seconds of stake plus a fifth of the elapsed time.
    for _ in 0..8 {
        chain.block(30 * SECOND);
    }
    let state = chain.summary();
    assert!(!state.bootstrap_ended);
    assert_eq!(state.active.len(), 4);
    let first = state.active[0].power;
    assert!(state.active.iter().all(|validator| validator.power == first));
    // The roster in force was announced two blocks before, at 180 seconds:
    // a target of 8 + 36 = 44, in four parts of 11.
    assert_eq!(first, 11, "{:?}", state.active);
    chain.engine.audit().unwrap();
}

/// A summary whose rule differs from the genesis in any parameter is refused
/// by the engine's reads and by its audit, not only one without the rule.
#[test]
fn the_engine_refuses_a_rule_other_than_the_genesis_one() {
    let mut genesis = genesis_v5();
    genesis.stake_handover = true;
    let mut chain = Chain::new(genesis);
    chain.block(30 * SECOND);
    let summary = chain.summary();
    assert!(summary.handover_matches(true, 4).unwrap());
    let mut other = summary.clone();
    other.stake_handover.as_mut().unwrap().supply_share_ppm = 250_000;
    other.validate().unwrap();
    assert!(!other.handover_matches(true, 4).unwrap());
    let mut none = summary;
    none.stake_handover = None;
    assert!(!none.handover_matches(true, 4).unwrap());
}

#[test]
fn the_setting_is_written_one_way_and_last() {
    let parse = |value: Value| {
        let mut genesis = serde_json::to_value(genesis_v5()).unwrap();
        genesis["stake_handover"] = value;
        serde_json::from_value::<Genesis>(genesis)
    };
    assert!(parse(json!(true)).unwrap().stake_handover);
    // Not using the rule is written by leaving the field out.
    for refused in [json!(false), json!("true"), json!(1), json!(null), json!({})] {
        assert!(parse(refused.clone()).is_err(), "{refused}");
    }
    // Tools that build a genesis compute the network id from their own
    // encoding, so the position of the field is part of the format: last,
    // after every other optional setting.
    let mut genesis = genesis_v5();
    genesis.validators = (0..7)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.fees_to_validators_ppm = 1_000_000;
    genesis.fee_micros = 10;
    genesis.all_new_time_to_validators = true;
    let without = serde_json::to_string(&genesis).unwrap();
    assert!(without.ends_with(r#""all_new_time_to_validators":true}"#), "{without}");
    genesis.stake_handover = true;
    let with = serde_json::to_string(&genesis).unwrap();
    assert_eq!(with, format!("{},\"stake_handover\":true}}", without.strip_suffix('}').unwrap()));
    let parsed: Genesis = serde_json::from_str(&with).unwrap();
    assert_eq!(parsed.network_id().unwrap(), genesis.network_id().unwrap());
}

#[test]
fn the_production_profile_requires_it() {
    // A production genesis: twenty starting organizations, hourly auction,
    // two-day recovery delay.
    let mut genesis: Genesis =
        serde_json::from_slice(&serde_json::to_vec(&genesis_v4_with(24)).unwrap()).unwrap();
    genesis.profile = pos::Profile::Production;
    genesis.validators = (0..20)
        .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
        .collect();
    genesis.auction.epoch_seconds = 3600;
    genesis.recovery_min_delay_micros = 2 * pos::DAY;
    // The profile's other requirement, distinct account names, is met here:
    // `tests/distinct_names.rs` tests it, and that neither stands in for
    // the other.
    genesis.distinct_names = true;
    // And its three later requirements, which `tests/waits_survive_stops.rs`,
    // `tests/protected_registration.rs` and `tests/service_records.rs` test.
    genesis.waits_survive_stops = true;
    genesis.protected_registration = true;
    genesis.service_records = true;
    // A new network is refused; a state created before the rule still opens.
    genesis.validate().unwrap();
    let refusal = genesis.validate_new().unwrap_err().to_string();
    assert!(refusal.contains("stake hand-over"), "{refusal}");
    genesis.stake_handover = true;
    genesis.validate_new().unwrap();
    let chain = Chain::new(genesis);
    // Twenty starting validators of 86,400: forty bonds.
    assert_eq!(
        chain.summary().stake_handover,
        Some(pos::StakeHandover { target_power: 3_456_000, supply_share_ppm: 200_000, reached_at: None })
    );
    chain.engine.audit().unwrap();
}

/// Both settings: all new time to validators, and the stake hand-over rule.
/// Nothing is bonded for the starting validators: they are paid in full (the
/// rule keeps them above half by itself, and independent stake can come only
/// from what they are paid). Without independent validators the bootstrap
/// never ends, long after the calendar period and the hold.
#[test]
fn with_all_new_time_the_starting_validators_are_paid_in_full() {
    for handover in [false, true] {
        let mut genesis = genesis_v5();
        genesis.validators = (0..7)
            .map(|owner| BootstrapValidator { owner, consensus_key: pk(owner as u8 + 101), commission_bps: 1000 })
            .collect();
        genesis.all_new_time_to_validators = true;
        genesis.stake_handover = handover;
        let mut chain = Chain::new(genesis);
        chain.block(10 * SECOND);
        let (liquid, staked) = (chain.meta().liquid_total, chain.meta().pos_assets_total);
        for _ in 0..30 {
            chain.block(10 * SECOND);
        }
        let paid = chain.meta().liquid_total - liquid;
        let bonded = chain.meta().pos_assets_total - staked;
        // Three hundred seconds of new time, all to the validators.
        let issued = 300 * SECOND;
        if handover {
            assert_eq!(bonded, 0, "nothing is bonded for them");
            assert!(paid <= issued && issued - paid <= 30 * 7, "paid {paid} of {issued}");
            let state = chain.summary();
            assert!(!state.bootstrap_ended, "no independent stake, no end");
            assert_eq!(state.active.len(), 7);
            // Their power fills the target of two blocks before: 14 + a fifth
            // of 290 seconds = 72 seconds of stake, in seven parts.
            assert!(state.active.iter().all(|v| v.power == 11), "{:?}", state.active);
        } else {
            // Without the rule: nineteen twentieths bonded while the lent
            // power lasted (in the laboratory profile it ends within about a
            // minute), then paid in full.
            assert!(bonded > 0 && paid + bonded <= issued, "paid {paid}, bonded {bonded}");
            assert!(chain.summary().bootstrap_ended);
        }
        chain.engine.audit().unwrap();
    }
}
