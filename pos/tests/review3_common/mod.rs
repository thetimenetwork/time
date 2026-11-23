#![allow(dead_code)]
//! Harness shared by the third review tests (a copy of the one in handover.rs).
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use time_pos::*;

pub fn signing(id: u64) -> SigningKey {
    use sha2::{Digest, Sha256};
    SigningKey::from_bytes(&Sha256::digest(id.to_be_bytes()).into())
}
pub fn public(id: u64) -> String {
    hex::encode(signing(id).verifying_key().as_bytes())
}
#[derive(Clone)]
pub struct Net {
    pub summary: Summary,
    pub candidates: Vec<Candidate>,
    pub owners: BTreeMap<u64, OwnerStake>,
    pub now: u64,
    pub starting: u64,
}
impl Net {
    pub fn new(profile: Profile, count: u64, stake_rule: bool) -> Self {
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
            .map(|c| Validator { owner: c.owner, consensus_key: c.consensus_key.clone(), power: profile.genesis_power() })
            .collect();
        Self {
            summary: Summary::with_rules(roster, profile, stake_rule).unwrap(),
            candidates,
            owners: BTreeMap::new(),
            now: 0,
            starting: count,
        }
    }
    pub fn row(&mut self, id: u64) -> &mut Candidate {
        self.candidates.iter_mut().find(|c| c.owner == id).unwrap()
    }
    pub fn admit(&mut self, id: u64, extra: u64) {
        let proof = signing(id).sign(&register_message([4; 32], id, &public(id), 0).unwrap()).to_bytes();
        let (mut item, _) = register_bonded([4; 32], id, public(id), 0, &proof, self.summary.profile).unwrap();
        if extra > 0 {
            bond_self(&mut item, extra).unwrap();
        }
        self.summary.admit_candidate(&item, &self.candidates).unwrap();
        self.candidates.push(item);
        self.candidates.sort_by_key(|c| c.owner);
    }
    pub fn bond(&mut self, id: u64, amount: u64) {
        bond_self(self.row(id), amount).unwrap();
        self.summary.escrow += amount;
    }
    pub fn delegate(&mut self, delegator: u64, candidate: u64, amount: u64) {
        let row = self.candidates.iter_mut().find(|c| c.owner == candidate).unwrap();
        let stake = self.owners.entry(delegator).or_insert_with(|| OwnerStake::new(delegator));
        delegate(row, stake, amount, 1).unwrap();
        self.summary.escrow += amount;
    }
    pub fn begin(&mut self, delta: u64) {
        self.now += delta;
        let height = self.summary.last_height + 1;
        self.summary.begin_block(height, self.now, &mut self.candidates).unwrap();
        for row in &mut self.candidates {
            row.prune_reward_exits(height);
        }
    }
    pub fn settle(&mut self) {
        self.summary.reconcile(&self.candidates, None).unwrap();
        self.summary.validate().unwrap();
    }
    pub fn block(&mut self, delta: u64) {
        self.begin(delta);
        self.settle();
    }
    pub fn run_to(&mut self, until: u64, step: u64) {
        while self.now < until {
            self.block(step);
        }
    }
    pub fn exit(&mut self, account: u64, candidate: u64, kind: ExitKind, quantity: u64) -> Result<u64, String> {
        let saved = (self.summary.clone(), self.candidates.clone(), self.owners.clone());
        let id = self.summary.next_exit_id;
        let height = self.summary.last_height;
        let first = {
            let row = self.candidates.iter_mut().find(|c| c.owner == candidate).unwrap();
            let stake = self.owners.entry(account).or_insert_with(|| OwnerStake::new(account));
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
    pub fn shares_of(&self, delegator: u64, candidate: u64) -> u64 {
        self.owners.get(&delegator).map_or(0, |o| {
            o.positions.iter().find(|p| p.candidate == candidate).map_or(0, |p| p.shares)
        })
    }
    pub fn power(roster: &[Validator], pick: impl Fn(u64) -> bool) -> (u64, u64) {
        (roster.iter().filter(|v| pick(v.owner)).map(|v| v.power).sum(), roster.iter().map(|v| v.power).sum())
    }
    pub fn share(&self, roster: &[Validator], pick: impl Fn(u64) -> bool) -> f64 {
        let (a, t) = Self::power(roster, pick);
        a as f64 / t as f64
    }
    pub fn target_now(&self) -> u64 {
        let rule = self.summary.stake_handover.as_ref().unwrap();
        rule.target_power + self.now / SECOND / 5
    }
    pub fn churn_used(&self) -> u64 {
        self.summary.churn.iter().map(|c| c.units).sum()
    }
}

