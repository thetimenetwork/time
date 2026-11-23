//! SECOND REVIEW. `an_exit_never_waits_for_the_starting_validators` tests one
//! exit on a settled network. Here a second exit follows a first one: two
//! blocks after the first takes effect the starting validators' target
//! rises, the group move runs first in every reconcile and spends the
//! budget, and the second exit waits for it.
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
}

fn show(net: &Net, label: &str) {
    let sum = |roster: &[Validator], pick: &dyn Fn(u64) -> bool| -> f64 {
        roster.iter().filter(|v| pick(v.owner)).map(|v| v.power).sum::<u64>() as f64 / 86_400.0
    };
    let churn: u64 = net.summary.churn.iter().map(|c| c.units).sum();
    println!(
        "{label}: height {} | in force: total {:.2}, founders {:.2} | newest: total {:.2}, founders {:.2}, 300 {:.2}, 301 {:.2} | churn used {:.3} | ended {}",
        net.summary.last_height,
        sum(&net.summary.active, &|_| true),
        sum(&net.summary.active, &|o| o < 20),
        sum(net.summary.latest(), &|_| true),
        sum(net.summary.latest(), &|o| o < 20),
        sum(net.summary.latest(), &|o| o == 300),
        sum(net.summary.latest(), &|o| o == 301),
        churn as f64 / 1e9,
        net.summary.bootstrap_ended
    );
}

/// Day 120, seven attacker bonds, twenty honest validators of one bond
/// (400..420) and two honest operators: 300 (one bond and fifteen delegated
/// by 901) and 301 (one bond and five delegated by 902): 49 bonds, below the
/// target since day 36, so the bootstrap has not ended. 300's delegator
/// takes out fifteen bonds; `wait` blocks of a minute later 301's delegator
/// asks for two bonds. Accepted?
fn second_exit(stake_rule: bool, wait: u64, trace: bool) -> (bool, Result<u64, String>) {
    let mut net = Net::production(stake_rule);
    net.block(DAY);
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
    while net.now < 120 * DAY {
        net.block(DAY);
    }
    for _ in 0..3 {
        net.block(MINUTE);
    }
    if trace {
        show(&net, "settled");
    }
    let first = net.exit(901, 300, ExitKind::Delegation, 15 * BOND).is_ok();
    if trace {
        show(&net, "after the first exit");
    }
    for i in 0..wait {
        net.block(MINUTE);
        if trace {
            show(&net, &format!("block +{}", i + 1));
        }
    }
    let second = net.exit(902, 301, ExitKind::Delegation, 2 * BOND);
    if trace {
        show(&net, &format!("second exit {:?}", second.is_ok()));
    }
    (first, second)
}

#[test]
fn review2_6_a_second_exit_waits_for_the_starting_validators_return() {
    second_exit(true, 3, true);
    for stake_rule in [false, true] {
        for wait in [0, 1, 2, 3] {
            let (first, second) = second_exit(stake_rule, wait, false);
            println!(
                "{} rule: first exit accepted {first}; second exit {wait} minutes later: {:?}",
                if stake_rule { "stake   " } else { "calendar" },
                second.map(|_| "accepted")
            );
        }
    }
}
