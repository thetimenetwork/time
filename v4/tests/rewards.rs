mod common;
use common::{genesis, key, pk};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use tempfile::TempDir;
use timecurrency_node::ledger::{self, Action, ActionPayload, Delegate, Transfer, Undelegate};
use timecurrency_v4::{
    engine::{Engine, account_key, canonical_decode},
    pos_adapter,
    store::Store,
    wire,
};

struct Harness {
    _directory: TempDir,
    engine: Engine,
}
impl Harness {
    fn new(validators: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = genesis();
        config.validators = (0..validators as u64)
            .map(|owner| timecurrency_v4::genesis::BootstrapValidator {
                owner,
                consensus_key: pk(owner as u8 + 101),
                commission_bps: 1000,
            })
            .collect();
        let mut engine = Engine::open_with_history(
            Store::open(directory.path().join("ledger.redb")).unwrap(),
            directory.path().join("history"),
        )
        .unwrap();
        engine.initialize(config).unwrap();
        Self {
            _directory: directory,
            engine,
        }
    }
    fn row<T: DeserializeOwned + Serialize>(&self, key: Vec<u8>) -> T {
        canonical_decode(
            &self
                .engine
                .store()
                .snapshot()
                .unwrap()
                .get(&key)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }
    fn account(&self, id: u64) -> ledger::Account {
        self.row(account_key(id))
    }
    fn candidate(&self, id: u64) -> pos::Candidate {
        self.row(pos_adapter::candidate_key(id))
    }
    fn summary(&self) -> pos::Summary {
        self.row(pos_adapter::SUMMARY_KEY.to_vec())
    }
    fn extension(&self, id: u64, kind: u8, payload: serde_json::Value) -> Vec<u8> {
        let account = self.account(id);
        wire::sign(
            &self.engine.meta().unwrap().network_id,
            id,
            account.nonce + 1,
            account.auth_epoch,
            kind,
            &payload,
            &key(id as u8 + 1),
        )
        .unwrap()
    }
    fn action(&self, id: u64, payload: ActionPayload) -> Vec<u8> {
        let account = self.account(id);
        ledger::sign_action(
            &Action {
                network_id: self.engine.meta().unwrap().network_id.clone(),
                from: id,
                nonce: account.nonce + 1,
                auth_epoch: account.auth_epoch,
                public_key: pk(id as u8 + 1),
                payload,
                signature: vec![],
            },
            &key(id as u8 + 1),
        )
        .unwrap()
    }
    fn block(&mut self, delta: u64, txs: Vec<Vec<u8>>) {
        use sha2::{Digest, Sha256};
        let meta = self.engine.meta().unwrap();
        let height = meta.height + 1;
        let timestamp = meta.time_micros + delta as i64;
        let eligible = self
            .engine
            .active_roster_at(meta.height as u64)
            .unwrap()
            .into_iter()
            .map(|v| v.consensus_key)
            .collect::<Vec<_>>();
        let hash = Sha256::digest(height.to_be_bytes()).into();
        let prepared = self
            .engine
            .prepare(height, timestamp, &txs, &eligible, hash)
            .unwrap();
        self.engine.commit(prepared, hash).unwrap();
        self.engine.audit().unwrap();
    }
    fn funded_seven() -> Self {
        let mut h = Self::new(7);
        h.block(60 * pos::SECOND, vec![]);
        let bonds = (0..7)
            .map(|id| h.extension(id, 18, json!({"amount":pos::SECOND.to_string()})))
            .collect();
        h.block(pos::SECOND, bonds);
        h.block(20 * pos::SECOND, vec![]);
        assert!(h.summary().bootstrap_ended);
        h
    }
    fn dust(&mut self, owner: u64, delegator: u64) {
        let fund = self.action(
            owner,
            ActionPayload::Transfer(Transfer {
                to: delegator,
                amount: 10_000,
            }),
        );
        self.block(pos::SECOND, vec![fund]);
        let delegate = self.action(
            delegator,
            ActionPayload::Delegate(Delegate {
                operator: owner,
                amount: 1,
                min_shares: 1,
            }),
        );
        self.block(pos::SECOND, vec![delegate]);
    }
}

#[test]
fn bootstrap_and_normal_funded_validator_rewards_resist_unsolicited_dust() {
    let mut bootstrap = Harness::new(4);
    bootstrap.block(60 * pos::SECOND, vec![]);
    bootstrap.dust(0, 4);
    let before = bootstrap.account(0).balance;
    bootstrap.block(pos::SECOND, vec![]);
    assert_eq!(bootstrap.candidate(0).pool_assets, 1);
    assert_eq!(bootstrap.account(0).balance - before, 49_999);
    assert!(!bootstrap.summary().bootstrap_ended);

    let mut normal = Harness::funded_seven();
    normal.dust(0, 7);
    let before = normal.account(0).balance;
    normal.block(pos::SECOND, vec![]);
    assert_eq!(normal.candidate(0).pool_assets, 1);
    assert_eq!(normal.account(0).balance - before, 28_570);
}

#[test]
fn partial_self_exit_withholds_old_power_rewards_until_h_plus_two_is_paid() {
    let mut h = Harness::funded_seven();
    let topup = h.extension(0, 18, json!({"amount":pos::SECOND.to_string()}));
    h.block(20 * pos::SECOND, vec![topup]);
    h.dust(0, 7);
    h.block(20 * pos::SECOND, vec![]);
    assert_eq!(
        h.summary()
            .active
            .iter()
            .find(|v| v.owner == 0)
            .unwrap()
            .power,
        2
    );
    let exit = h.extension(
        0,
        19,
        json!({"amount":pos::SECOND.to_string(),"min_amount":"1"}),
    );
    h.block(20 * pos::SECOND, vec![exit]);
    let release = h.engine.meta().unwrap().height as u64 + 2;
    assert_eq!(
        h.candidate(0).pending_reward_exits[0].release_height,
        release
    );
    for _ in 0..2 {
        let before = h.account(0).balance;
        h.block(pos::SECOND, vec![]);
        assert_eq!(h.account(0).balance - before, 24_999);
        assert_eq!(h.candidate(0).pool_assets, 1);
    }
    assert_eq!(h.engine.meta().unwrap().height as u64, release);
    assert!(h.candidate(0).pending_reward_exits.is_empty());
    let before = h.account(0).balance;
    h.block(pos::SECOND, vec![]);
    assert_eq!(h.account(0).balance - before, 28_570);
}

#[test]
fn complete_self_exit_dust_never_inherits_departing_or_removed_authority_rewards() {
    let mut h = Harness::funded_seven();
    h.dust(0, 7);
    let exit = h.extension(
        0,
        19,
        json!({"amount":pos::SECOND.to_string(),"min_amount":"1"}),
    );
    h.block(20 * pos::SECOND, vec![exit]);
    let before = h.account(0).balance;
    for _ in 0..3 {
        h.block(pos::SECOND, vec![]);
        assert_eq!(h.account(0).balance, before);
        assert_eq!(h.candidate(0).pool_assets, 1);
    }
    assert!(!h.summary().active.iter().any(|v| v.owner == 0));
    assert!(h.candidate(0).pending_reward_exits.is_empty());
}

#[test]
fn last_pool_share_exit_keeps_departed_fraction_in_bank_until_power_reduction() {
    let mut h = Harness::funded_seven();
    let funding = h.action(
        1,
        ActionPayload::Transfer(Transfer {
            to: 7,
            amount: 1_010_000,
        }),
    );
    h.block(20 * pos::SECOND, vec![funding]);
    let delegation = h.action(
        7,
        ActionPayload::Delegate(Delegate {
            operator: 0,
            amount: pos::SECOND,
            min_shares: 1,
        }),
    );
    h.block(20 * pos::SECOND, vec![delegation]);
    h.block(20 * pos::SECOND, vec![]);
    let unbond = h.action(
        7,
        ActionPayload::Undelegate(Undelegate {
            operator: 0,
            shares: pos::SECOND,
            min_amount: 1,
        }),
    );
    h.block(20 * pos::SECOND, vec![unbond]);
    let departing = h.candidate(0).delegated_exits.assets;
    assert!(departing >= pos::SECOND);
    assert_eq!(h.candidate(0).pool_shares, 0);
    for _ in 0..2 {
        let s = h.summary();
        let power = s.active.iter().find(|v| v.owner == 0).unwrap().power;
        let total: u64 = s.active.iter().map(|v| v.power).sum();
        let gross = 200_000u128 * u128::from(power) / u128::from(total);
        let expected = gross * u128::from(pos::SECOND) / u128::from(pos::SECOND + departing);
        let before = h.account(0).balance;
        h.block(pos::SECOND, vec![]);
        assert_eq!(u128::from(h.account(0).balance - before), expected);
        assert_eq!(h.candidate(0).pool_assets, 0);
        assert_eq!(h.candidate(0).delegated_exits.assets, departing);
    }
    assert!(h.candidate(0).pending_reward_exits.is_empty());
    let before = h.account(0).balance;
    h.block(pos::SECOND, vec![]);
    assert_eq!(h.account(0).balance - before, 28_571);
}
