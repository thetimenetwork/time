use super::*;
use std::collections::BTreeSet;
const SCALE: u64 = 1_000_000_000;
const CHURN_LIMIT: u64 = 333_333_333;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    #[serde(with = "decimal::u64")]
    pub owner: u64,
    pub consensus_key: String,
    #[serde(with = "decimal::u64")]
    pub power: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetSnapshot {
    #[serde(with = "decimal::u64")]
    pub announced_height: u64,
    #[serde(with = "decimal::u64")]
    pub effective_height: u64,
    pub validators: Vec<Validator>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChurnCharge {
    #[serde(with = "decimal::u64")]
    pub expires_at: u64,
    #[serde(with = "decimal::u64")]
    pub units: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub profile: Profile,
    pub candidate_ids: Vec<String>,
    #[serde(with = "decimal::u64")]
    pub escrow: u64,
    #[serde(with = "decimal::u64")]
    pub archived_escrow: u64,
    #[serde(with = "decimal::u64")]
    pub archived_candidates: u64,
    #[serde(with = "decimal::u64")]
    pub next_exit_id: u64,
    #[serde(with = "decimal::u64")]
    pub last_height: u64,
    #[serde(with = "decimal::u64")]
    pub last_elapsed: u64,
    pub bootstrap_ended: bool,
    pub active: Vec<Validator>,
    pub scheduled: Vec<SetSnapshot>,
    pub churn: Vec<ChurnCharge>,
    pub safety_hold: bool,
    /// Present on a network whose starting validators fade against the real
    /// stake that replaces them as well as against the calendar. Absent: the
    /// protocol-4 rule, the calendar alone. Written only when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stake_handover: Option<StakeHandover>,
}
impl Summary {
    pub fn new(genesis: Vec<Validator>) -> Result<Self> {
        Self::with_profile(genesis, Profile::Production)
    }
    pub fn with_profile(genesis: Vec<Validator>, profile: Profile) -> Result<Self> {
        Self::with_rules(genesis, profile, false)
    }
    /// `stake_handover`: the starting validators fade against real stake as
    /// well as the calendar (see `StakeHandover`).
    pub fn with_rules(
        genesis: Vec<Validator>,
        profile: Profile,
        stake_handover: bool,
    ) -> Result<Self> {
        ensure!(
            (profile == Profile::Production && genesis.len() == 20)
                || (profile == Profile::Laboratory && (4..=20).contains(&genesis.len())),
            "production needs20 and laboratory needs4..20 explicit genesis authorities"
        );
        validate_set(&genesis)?;
        ensure!(
            genesis.iter().all(|v| v.power == profile.genesis_power()),
            "genesis virtual power differs from profile"
        );
        let stake_handover = if stake_handover {
            let starting = genesis.iter().try_fold(0, |sum, v| add(sum, v.power))?;
            Some(StakeHandover::for_starting_power(starting)?)
        } else {
            None
        };
        Ok(Self {
            profile,
            candidate_ids: genesis.iter().map(|v| v.owner.to_string()).collect(),
            escrow: 0,
            archived_escrow: 0,
            archived_candidates: 0,
            next_exit_id: 0,
            last_height: 0,
            last_elapsed: 0,
            bootstrap_ended: false,
            active: genesis,
            scheduled: Vec::new(),
            churn: Vec::new(),
            safety_hold: false,
            stake_handover,
        })
    }
    /// Whether this summary carries the stake hand-over rule that a genesis
    /// with `enabled` and `starting_count` starting validators sets: all of
    /// its parameters, not only whether it is there.
    pub fn handover_matches(&self, enabled: bool, starting_count: usize) -> Result<bool> {
        let expected = if enabled {
            let starting = u64::try_from(starting_count)?
                .checked_mul(self.profile.genesis_power())
                .ok_or_else(|| anyhow!("hand-over target overflow"))?;
            Some(StakeHandover::for_starting_power(starting)?)
        } else {
            None
        };
        Ok(match (&self.stake_handover, &expected) {
            (None, None) => true,
            (Some(rule), Some(expected)) => rule.same_rule(expected),
            _ => false,
        })
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.candidate_ids.len() <= MAX_CANDIDATES, "candidate cap");
        ensure!(
            self.stake_handover.as_ref().is_none_or(|rule| {
                rule.target_power > 0
                    && rule.supply_share_ppm <= 1_000_000
                    && rule.reached_at.is_none_or(|at| at <= self.last_elapsed)
            }),
            "stake hand-over rule"
        );
        ensure!(
            self.archived_escrow <= self.escrow && self.archived_candidates < u64::MAX,
            "archive aggregate bounds"
        );
        let mut ids = BTreeSet::new();
        let mut previous = None;
        for text in &self.candidate_ids {
            let id: u64 = text.parse()?;
            ensure!(
                id.to_string() == *text
                    && ids.insert(id)
                    && previous.is_none_or(|before| before < id),
                "candidate index IDs"
            );
            previous = Some(id);
        }
        validate_set(&self.active)?;
        ensure!(
            self.scheduled.len() <= 2
                && self
                    .scheduled
                    .windows(2)
                    .all(|w| w[0].effective_height < w[1].effective_height),
            "scheduled roster order/cap"
        );
        for set in &self.scheduled {
            validate_set(&set.validators)?;
            ensure!(
                set.effective_height
                    == set
                        .announced_height
                        .checked_add(2)
                        .ok_or_else(|| anyhow!("height overflow"))?
                    && set.effective_height > self.last_height,
                "H+2 schedule coordinates"
            );
        }
        ensure!(
            self.churn.len() <= 61
                && self
                    .churn
                    .windows(2)
                    .all(|w| w[0].expires_at < w[1].expires_at)
                && self
                    .churn
                    .iter()
                    .all(|c| c.expires_at > self.last_elapsed && c.units > 0),
            "rolling churn journal"
        );
        ensure!(
            self.churn.iter().try_fold(0u64, |s, c| add(s, c.units))? <= CHURN_LIMIT,
            "rolling churn exceedsone third"
        );
        Ok(())
    }
    pub fn latest(&self) -> &[Validator] {
        self.scheduled
            .last()
            .map_or(&self.active, |s| &s.validators)
    }
    pub fn current_or_scheduled(&self, owner: u64) -> bool {
        self.active
            .iter()
            .chain(self.scheduled.iter().flat_map(|s| &s.validators))
            .any(|v| v.owner == owner)
    }
    pub fn admit_candidate(&mut self, candidate: &Candidate, existing: &[Candidate]) -> Result<()> {
        self.validate()?;
        candidate.validate()?;
        ensure!(
            !candidate.genesis
                && candidate.funded(self.profile.min_self_bond())
                && candidate.self_exits.units == 0
                && candidate.delegated_exits.units == 0
                && candidate.pool_shares == 0,
            "registration requires real minimum self bond"
        );
        ensure!(
            self.candidate_ids.len() < MAX_CANDIDATES
                && !self
                    .candidate_ids
                    .iter()
                    .any(|id| id == &candidate.owner.to_string())
                && !existing
                    .iter()
                    .any(|c| c.consensus_key == candidate.consensus_key),
            "candidate capacity/identity"
        );
        let mut ids: Vec<u64> = self
            .candidate_ids
            .iter()
            .map(|s| s.parse())
            .collect::<std::result::Result<_, _>>()?;
        let escrow = add(self.escrow, candidate.escrow()?)?;
        ids.push(candidate.owner);
        ids.sort();
        self.candidate_ids = ids.into_iter().map(|id| id.to_string()).collect();
        self.escrow = escrow;
        Ok(())
    }
    pub fn retire_candidate(&mut self, candidate: &mut Candidate) -> Result<()> {
        self.validate()?;
        candidate.validate()?;
        ensure!(
            !candidate.archived && !self.current_or_scheduled(candidate.owner),
            "candidate still has active/scheduled authority"
        );
        ensure!(
            self.exposure_expired(candidate)?,
            "historic evidence exposure remains"
        );
        let index = self
            .candidate_ids
            .iter()
            .position(|id| id == &candidate.owner.to_string())
            .ok_or_else(|| anyhow!("candidate not indexed"))?;
        let archived_escrow = add(self.archived_escrow, candidate.escrow()?)?;
        let archived_candidates = add(self.archived_candidates, 1)?;
        self.candidate_ids.remove(index);
        self.archived_escrow = archived_escrow;
        self.archived_candidates = archived_candidates;
        candidate.archived = true;
        candidate.pending_reward_exits.clear();
        Ok(())
    }
    /// Never-active regular candidates have no historic votes to expose.
    /// Every removed signer has a positive actual removal time; genesis
    /// authorities are separately protected until their exposure expires.
    pub fn exposure_expired(&self, candidate: &Candidate) -> Result<bool> {
        Ok((!candidate.genesis && candidate.last_active_end == 0)
            || self.last_elapsed > add(candidate.last_active_end, UNBOND_DELAY)?)
    }
    /// Bounded eligibility admission may archive a strictly weaker inactive
    /// candidate. Assets and claims stay on that archived row. The caller
    /// persists modified old rows and appends the new candidate atomically.
    pub fn admit_with_priority(
        &mut self,
        candidate: &Candidate,
        existing: &mut [Candidate],
    ) -> Result<Option<u64>> {
        self.validate_directory(existing)?;
        candidate.validate()?;
        let mut next = self.clone();
        let mut rows = existing.to_vec();
        let mut evicted = None;
        if next.candidate_ids.len() == MAX_CANDIDATES {
            let power = candidate.power()?;
            let mut victim = None;
            for (index, row) in rows.iter().enumerate() {
                if !next.current_or_scheduled(row.owner)
                    && next.exposure_expired(row)?
                    && row.power()? < power
                {
                    let rank = (row.power()?, std::cmp::Reverse(row.owner));
                    if victim.as_ref().is_none_or(|(_, old_rank)| rank < *old_rank) {
                        victim = Some((index, rank));
                    }
                }
            }
            let (index, _) = victim.ok_or_else(|| {
                anyhow!("candidate capacity: no safely replaceable lower-power entry")
            })?;
            evicted = Some(rows[index].owner);
            next.retire_candidate(&mut rows[index])?;
        }
        next.admit_candidate(candidate, &rows)?;
        *self = next;
        existing.clone_from_slice(&rows);
        Ok(evicted)
    }
    /// Historic key reservations remain even when all archived claims settle.
    pub fn clear_archive(&mut self, candidate: &Candidate) -> Result<()> {
        self.validate()?;
        candidate.validate()?;
        ensure!(
            candidate.archived
                && candidate.escrow()? == 0
                && candidate.pool_shares == 0
                && candidate.self_exits.units == 0
                && candidate.delegated_exits.units == 0,
            "archived claims remain"
        );
        self.archived_candidates = self
            .archived_candidates
            .checked_sub(1)
            .ok_or_else(|| anyhow!("archive count underflow"))?;
        Ok(())
    }
    pub fn begin_block(
        &mut self,
        height: u64,
        now: u64,
        candidates: &mut [Candidate],
    ) -> Result<Option<SetSnapshot>> {
        let mut next = self.clone();
        let mut rows = candidates.to_vec();
        let activated = next.begin_block_inner(height, now, &mut rows)?;
        *self = next;
        candidates.clone_from_slice(&rows);
        Ok(activated)
    }
    fn begin_block_inner(
        &mut self,
        height: u64,
        now: u64,
        candidates: &mut [Candidate],
    ) -> Result<Option<SetSnapshot>> {
        self.validate()?;
        self.validate_directory(candidates)?;
        ensure!(
            height
                == self
                    .last_height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("height exhausted"))?
                && (now > self.last_elapsed || (height == 1 && now == 0)),
            "block coordinates"
        );
        self.last_height = height;
        self.last_elapsed = now;
        self.churn.retain(|c| c.expires_at > now);
        let activated = if self
            .scheduled
            .first()
            .is_some_and(|s| s.effective_height == height)
        {
            let set = self.scheduled.remove(0);
            for old in &self.active {
                if !set.validators.iter().any(|v| v.owner == old.owner)
                    && let Some(candidate) = candidates.iter_mut().find(|c| c.owner == old.owner)
                {
                    candidate.last_active_end = now;
                }
            }
            self.active = set.validators.clone();
            Some(set)
        } else {
            None
        };
        // Under the stake hand-over rule: since when the seated stake has
        // been at the target, and whether it has stayed there long enough.
        let mut held = true;
        if !self.bootstrap_ended
            && let Some(gap) = self.stake_gap(candidates)?
        {
            let hold = self.profile.handover_hold_micros();
            let rule = self
                .stake_handover
                .as_mut()
                .ok_or_else(|| anyhow!("stake hand-over rule"))?;
            if gap == 0 {
                let since = *rule.reached_at.get_or_insert(now);
                held = now >= add(since, hold)?;
            } else {
                rule.reached_at = None;
                held = false;
            }
        }
        // Under the stake hand-over rule the starting validators keep their
        // power until the end, so it cannot wait for a roster without them:
        // it needs seven funded validators in force other than theirs.
        let ready = if self.stake_handover.is_some() {
            self.active
                .iter()
                .filter(|v| {
                    candidates.iter().any(|c| {
                        c.owner == v.owner && !c.genesis && c.funded(self.profile.min_self_bond())
                    })
                })
                .count()
                >= MIN_FUNDED
        } else {
            self.active.len() >= MIN_FUNDED
                && self.active.iter().all(|v| {
                    candidates
                        .iter()
                        .any(|c| c.owner == v.owner && c.funded(self.profile.min_self_bond()))
                })
        };
        if !self.bootstrap_ended && held && now >= self.profile.fade_micros() && ready {
            self.bootstrap_ended = true;
        }
        self.safety_hold = self
            .active
            .iter()
            .any(|v| candidates.iter().any(|c| c.owner == v.owner && c.jailed));
        self.validate()?;
        Ok(activated)
    }
    /// Effects announced by Finalize(H) take effect at H+2. required_owner is a
    /// stake exit whose complete decrease must fit, or the caller rolls back.
    pub fn reconcile(
        &mut self,
        candidates: &[Candidate],
        required_owner: Option<u64>,
    ) -> Result<Option<SetSnapshot>> {
        let mut next = self.clone();
        let snapshot = next.reconcile_inner(candidates, required_owner)?;
        *self = next;
        Ok(snapshot)
    }
    fn validate_directory(&self, candidates: &[Candidate]) -> Result<()> {
        self.validate()?;
        ensure!(
            candidates.len() == self.candidate_ids.len() && candidates.len() <= MAX_CANDIDATES,
            "candidate directory mismatch"
        );
        let mut candidate_ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut escrow = 0;
        for candidate in candidates {
            candidate.validate()?;
            ensure!(!candidate.archived, "archived candidate remains eligible");
            ensure!(
                candidate_ids.insert(candidate.owner)
                    && keys.insert(&candidate.consensus_key)
                    && self
                        .candidate_ids
                        .iter()
                        .any(|id| id == &candidate.owner.to_string()),
                "candidate identity mismatch"
            );
            escrow = add(escrow, candidate.escrow()?)?;
        }
        ensure!(
            add(escrow, self.archived_escrow)? == self.escrow,
            "stake escrow summary mismatch"
        );
        for authority in self
            .active
            .iter()
            .chain(self.scheduled.iter().flat_map(|s| &s.validators))
        {
            ensure!(
                candidates
                    .iter()
                    .any(|c| c.owner == authority.owner
                        && c.consensus_key == authority.consensus_key),
                "roster references absent or mismatched candidate"
            );
        }
        Ok(())
    }
    fn reconcile_inner(
        &mut self,
        candidates: &[Candidate],
        required_owner: Option<u64>,
    ) -> Result<Option<SetSnapshot>> {
        self.validate_directory(candidates)?;
        // A verified equivocation is not a voluntary stake rotation. Exclude
        // jailed authorities at H+2 even if the ordinary churn budget is spent,
        // provided the surviving roster can still satisfy the stated bounds.
        let mut clean: Vec<_> = self
            .latest()
            .iter()
            .filter(|v| !candidates.iter().any(|c| c.owner == v.owner && c.jailed))
            .cloned()
            .collect();
        if clean.len() != self.latest().len() {
            // Repair can add real funded candidates, but cannot conjure trust
            // after all known authorities are compromised. At least three
            // unjailed existing authorities must survive this automatic path.
            if clean.len() >= 3 && clean.len() < MIN_ACTIVE {
                let mut replacements: Vec<_> = candidates
                    .iter()
                    .filter(|c| {
                        c.funded(self.profile.min_self_bond())
                            && !clean.iter().any(|v| v.owner == c.owner)
                    })
                    .collect();
                replacements.sort_by(|a, b| {
                    b.power()
                        .unwrap_or(0)
                        .cmp(&a.power().unwrap_or(0))
                        .then(a.owner.cmp(&b.owner))
                });
                for candidate in replacements {
                    clean.push(Validator {
                        owner: candidate.owner,
                        consensus_key: candidate.consensus_key.clone(),
                        power: candidate.power()?,
                    });
                    if clean.len() >= MIN_ACTIVE {
                        break;
                    }
                }
                clean.sort_by_key(|v| v.owner);
            }
            if clean.len() >= MIN_ACTIVE {
                cap_concentration(&mut clean)?;
            }
            if clean.len() < MIN_ACTIVE || max_concentration(&clean)? > CHURN_LIMIT {
                self.safety_hold = true;
                ensure!(
                    required_owner.is_none(),
                    "critical hold: jailed authority cannot be safely removed"
                );
                return Ok(None);
            }
            let set = SetSnapshot {
                announced_height: self.last_height,
                effective_height: add(self.last_height, 2)?,
                validators: clean,
            };
            if self
                .scheduled
                .last()
                .is_some_and(|s| s.announced_height == self.last_height)
            {
                *self.scheduled.last_mut().unwrap() = set.clone();
            } else {
                self.scheduled.push(set.clone());
            }
            self.safety_hold = self.has_jailed_authority(candidates);
            self.validate()?;
            return Ok(Some(set));
        }
        let mut funded: Vec<_> = candidates
            .iter()
            .filter(|c| c.funded(self.profile.min_self_bond()))
            .collect();
        funded.sort_by(|a, b| {
            b.power()
                .unwrap_or(0)
                .cmp(&a.power().unwrap_or(0))
                .then(a.owner.cmp(&b.owner))
        });
        let fade_ready = funded.len() >= MIN_FUNDED;
        // The calendar (protocol 4): full power until seven funded validators
        // exist, then a linear fade to nothing at the end of the period.
        let fade = self.profile.fade_micros();
        let calendar = (!fade_ready || self.last_elapsed < fade)
            .then(|| {
                if fade_ready {
                    Ok(ratio(
                        self.profile.genesis_power(),
                        fade - self.last_elapsed.min(fade),
                        fade,
                    )?
                    .max(1))
                } else {
                    Ok::<u64, anyhow::Error>(self.profile.genesis_power())
                }
            })
            .transpose()?;
        // Under the stake hand-over rule, until the end, every unjailed
        // starting validator holds the same part of what the rule asks of
        // them (see `StakeHandover`): a funded one on top of its own stake and
        // of what is delegated to it, one that is not funded never below what
        // the calendar leaves it, and none below a hundredth of its genesis
        // power, so that none leaves the roster before the end. `need` is
        // what they must hold together after the concentration cap: the gap,
        // and what keeps them above everyone else together once everyone else
        // holds the stake it asks for (counted on what is asked, not on what
        // is in force, so that they rise first and the others follow).
        let step = (self.profile.genesis_power() / 100).max(1);
        let (part, need) = match self.stake_gap(candidates)? {
            None => (0, None),
            Some(_) if self.bootstrap_ended => (0, None),
            Some(gap) => {
                // Their own bonds hold part of what they need, so they are
                // taken off their virtual power. Stake delegated to them is
                // not theirs to keep (its owner can take it out at any
                // moment), so it comes on top and never lowers their part.
                // None of it ever counts as seated stake.
                let (mut own, mut others) = (0u64, 0u64);
                for candidate in &funded {
                    if candidate.genesis {
                        own = add(own, candidate.self_bond / SECOND)?;
                    } else {
                        others = add(others, candidate.power()?)?;
                    }
                }
                let need = gap.max(add(others, 1)?);
                let count = candidates.iter().filter(|c| c.genesis && !c.jailed).count() as u64;
                // Rounded up to a hundredth of the genesis power, so that the
                // roster changes once in a while as the target grows, not at
                // every block.
                let part = if count == 0 {
                    0
                } else {
                    need.saturating_sub(own)
                        .div_ceil(count)
                        .div_ceil(step)
                        .checked_mul(step)
                        .ok_or_else(|| anyhow!("starting power overflow"))?
                        .max(step)
                };
                (part, Some(need))
            }
        };
        if need.is_some() {
            // The funded starting validators first, so that the size limit
            // never leaves out the ones that hold the majority. Stable: by
            // power within each group, as before.
            funded.sort_by_key(|c| !c.genesis);
        }
        // The target roster for a given part (zero without the rule and after
        // the end), capped.
        let build = |part: u64| -> Result<Vec<Validator>> {
            let virtual_power = if need.is_some() {
                Some(calendar.unwrap_or(0).max(part)).filter(|power| *power > 0)
            } else {
                calendar
            };
            let mut target = Vec::new();
            if !self.bootstrap_ended
                && let Some(virtual_power) = virtual_power
            {
                for candidate in candidates
                    .iter()
                    .filter(|c| c.genesis && !c.jailed && !c.funded(self.profile.min_self_bond()))
                {
                    target.push(Validator {
                        owner: candidate.owner,
                        consensus_key: candidate.consensus_key.clone(),
                        power: virtual_power,
                    });
                }
            }
            for candidate in &funded {
                if target.len() == MAX_VALIDATORS {
                    break;
                }
                let own = candidate.power()?;
                target.push(Validator {
                    owner: candidate.owner,
                    consensus_key: candidate.consensus_key.clone(),
                    power: if candidate.genesis { add(own, part)? } else { own },
                });
            }
            if target.len() >= MIN_ACTIVE {
                target.sort_by_key(|v| v.owner);
                cap_concentration(&mut target)?;
            }
            Ok(target)
        };
        let mut target = build(part)?;
        if target.len() < MIN_ACTIVE {
            self.safety_hold = self.has_jailed_authority(candidates);
            ensure!(required_owner.is_none(), "no safe replacement roster");
            return Ok(None);
        }
        if let Some(need) = need {
            // The concentration cap can cut a starting validator much is
            // delegated to; their part then rises until, after the cap, they
            // hold what they need (the least multiple of the step that does).
            let starting_power = |set: &[Validator]| -> Result<u64> {
                set.iter()
                    .filter(|v| candidates.iter().any(|c| c.owner == v.owner && c.genesis))
                    .try_fold(0, |sum, v| add(sum, v.power))
            };
            // With no unjailed starting validator the part is zero and there is
            // nothing to raise. The doublings are bounded: at most forty, and
            // never past a ceiling far below the bound on a roster's power.
            if part > 0 && starting_power(&target)? < need {
                let ceiling = u64::MAX / SECOND / (4 * MAX_VALIDATORS as u64);
                let (mut low, mut high) = (part, part);
                let mut enough = None;
                for _ in 0..40 {
                    if high > ceiling / 2 {
                        break;
                    }
                    high *= 2;
                    let trial = build(high)?;
                    if starting_power(&trial)? >= need {
                        enough = Some(trial);
                        break;
                    }
                    low = high;
                }
                if let Some(mut best) = enough {
                    let (mut low, mut high) = (low / step, high / step);
                    while high - low > 1 {
                        let middle = low + (high - low) / 2;
                        let trial = build(middle * step)?;
                        if starting_power(&trial)? >= need {
                            high = middle;
                            best = trial;
                        } else {
                            low = middle;
                        }
                    }
                    target = best;
                }
            }
        }
        let base = self.latest().to_vec();
        let mut next = base.clone();
        let mut budget = CHURN_LIMIT - self.churn.iter().map(|c| c.units).sum::<u64>();
        let mut charged = 0;
        // Under the stake hand-over rule, until the end: whether a change of
        // roster keeps the starting validators above everyone else together,
        // or, when they already are not, at least does not lower their share.
        let ended = self.bootstrap_ended;
        let split = |set: &[Validator]| -> Result<(u64, u64)> {
            let (mut starting, mut others) = (0u64, 0u64);
            for v in set {
                if candidates.iter().any(|c| c.owner == v.owner && c.genesis) {
                    starting = add(starting, v.power)?;
                } else {
                    others = add(others, v.power)?;
                }
            }
            Ok((starting, others))
        };
        let majority_kept = |before: &[Validator], after: &[Validator]| -> Result<bool> {
            if self.stake_handover.is_none() || ended {
                return Ok(true);
            }
            let (s0, o0) = split(before)?;
            let (s1, o1) = split(after)?;
            Ok(s1 > o1 || s1 as u128 * o0 as u128 >= s0 as u128 * o1 as u128)
        };
        // Someone else's raise, under the rule and until the end, goes no
        // further than keeps the starting validators above everyone else
        // together. None: no raise at all.
        let capped = |mut proposed: Vec<Validator>, owner: u64, before: u64| -> Result<Option<Vec<Validator>>> {
            if self.stake_handover.is_none()
                || ended
                || candidates.iter().any(|c| c.owner == owner && c.genesis)
            {
                return Ok(Some(proposed));
            }
            let i = proposed
                .iter()
                .position(|v| v.owner == owner)
                .ok_or_else(|| anyhow!("power target missing"))?;
            if proposed[i].power <= before {
                return Ok(Some(proposed));
            }
            let (starting, others) = split(&proposed)?;
            let rest = others - proposed[i].power;
            let limit = starting.saturating_sub(add(rest, 1)?);
            if limit <= before {
                return Ok(None);
            }
            proposed[i].power = proposed[i].power.min(limit);
            Ok(Some(proposed))
        };
        // Under the stake hand-over rule the starting validators move as one
        // group, before anyone else: each of them the same fraction of the
        // way from its power in the roster being built to its power in the
        // target, in one step charged as one change. Moved one at a time, a
        // raise that leaves their shares among themselves as they were is
        // charged as if they had changed, and in a small roster cannot be
        // made at all (one of four equal validators may never pass a third
        // on its own). While someone else's stake exit must fit they stay as
        // they are, so that the exit never waits for them; they follow at the
        // next reconcile. A starting validator's own exit moves the whole
        // group with it, in full or not at all, so that the others take up
        // its part at once. They never move one at a time.
        let mut handled = BTreeSet::new();
        if self.stake_handover.is_some() {
            let exit_of_starting = required_owner
                .is_some_and(|owner| candidates.iter().any(|c| c.owner == owner && c.genesis));
            let starting: Vec<&Candidate> = candidates
                .iter()
                .filter(|c| c.genesis && !c.jailed)
                .collect();
            handled.extend(starting.iter().map(|c| c.owner));
            let power_in = |set: &[Validator], owner: u64| {
                set.iter().find(|v| v.owner == owner).map_or(0, |v| v.power)
            };
            let moves: Vec<(&Candidate, u64, u64)> = starting
                .iter()
                .map(|c| (*c, power_in(&next, c.owner), power_in(&target, c.owner)))
                .collect();
            if (required_owner.is_none() || exit_of_starting)
                && moves.iter().any(|(_, from, to)| from != to)
            {
                const PARTS: u64 = 1_000_000;
                let trial = |parts: u64| -> Result<Vec<Validator>> {
                    let mut proposed: Vec<Validator> = next
                        .iter()
                        .filter(|v| !handled.contains(&v.owner))
                        .cloned()
                        .collect();
                    for (candidate, from, to) in &moves {
                        let power = if to >= from {
                            from + ratio(to - from, parts, PARTS)?
                        } else {
                            from - ratio(from - to, parts, PARTS)?
                        };
                        if power > 0 {
                            proposed.push(Validator {
                                owner: candidate.owner,
                                consensus_key: candidate.consensus_key.clone(),
                                power,
                            });
                        }
                    }
                    proposed.sort_by_key(|v| v.owner);
                    Ok(proposed)
                };
                let fits = |proposed: &[Validator]| -> Result<Option<u64>> {
                    if proposed.len() < MIN_ACTIVE || proposed.len() > MAX_VALIDATORS {
                        return Ok(None);
                    }
                    let charge = churn_units_trusted(&next, proposed)?;
                    Ok((charge <= budget
                        && max_concentration(proposed)? <= CHURN_LIMIT
                        && majority_kept(&next, proposed)?)
                        .then_some(charge))
                };
                // The largest fraction of the way that fits.
                let (mut low, mut high) = (0u64, PARTS);
                while low < high {
                    let parts = low + (high - low).div_ceil(2);
                    if fits(&trial(parts)?)?.is_some() {
                        low = parts;
                    } else {
                        high = parts - 1;
                    }
                }
                if low > 0 {
                    let proposed = trial(low)?;
                    if let Some(charge) = fits(&proposed)? {
                        next = proposed;
                        budget -= charge;
                        charged += charge;
                    }
                }
            }
        }
        // Add/replace before removing old authorities, keeping >=7 validators.
        for wanted in &target {
            if handled.contains(&wanted.owner) {
                continue;
            }
            if let Some(i) = next.iter().position(|v| v.owner == wanted.owner) {
                if next[i] != *wanted {
                    let mut proposed = next.clone();
                    proposed[i] = wanted.clone();
                    let Some(proposed) = capped(proposed, wanted.owner, next[i].power)? else {
                        continue;
                    };
                    let (proposed, charge) =
                        fit_power(&next, proposed, wanted.owner, next[i].power, budget)?;
                    if charge > 0 {
                        next = proposed;
                        budget -= charge;
                        charged += charge;
                    }
                }
            } else {
                let mut proposed = next.clone();
                if proposed.len() == MAX_VALIDATORS {
                    if let Some(i) = proposed.iter().position(|v| {
                        !handled.contains(&v.owner) && !target.iter().any(|t| t.owner == v.owner)
                    }) {
                        proposed.remove(i);
                    } else {
                        continue;
                    }
                }
                proposed.push(wanted.clone());
                proposed.sort_by_key(|v| v.owner);
                let Some(proposed) = capped(proposed, wanted.owner, 0)? else {
                    continue;
                };
                let (proposed, charge) = fit_power(&next, proposed, wanted.owner, 0, budget)?;
                if charge > 0 {
                    next = proposed;
                    budget -= charge;
                    charged += charge;
                }
            }
        }
        for old in base
            .iter()
            .filter(|v| !handled.contains(&v.owner) && !target.iter().any(|t| t.owner == v.owner))
        {
            if next.len() <= MIN_ACTIVE {
                break;
            }
            let mut proposed = next.clone();
            proposed.retain(|v| v.owner != old.owner);
            let charge = churn_units_trusted(&next, &proposed)?;
            if charge <= budget && max_concentration(&proposed)? <= CHURN_LIMIT {
                next = proposed;
                budget -= charge;
                charged += charge;
            }
        }
        if let Some(owner) = required_owner {
            let desired = target.iter().find(|v| v.owner == owner);
            let actual = next.iter().find(|v| v.owner == owner);
            ensure!(desired == actual, "exit waits for rolling churn capacity");
        }
        validate_set(&next)?;
        ensure!(
            max_concentration(&next)? <= 333_333_333,
            "proposed roster concentration exceedsone third"
        );
        self.safety_hold = self.has_jailed_authority(candidates);
        if next == base {
            return Ok(None);
        }
        if charged > 0 {
            self.record_churn(charged)?;
        }
        let snapshot = SetSnapshot {
            announced_height: self.last_height,
            effective_height: self
                .last_height
                .checked_add(2)
                .ok_or_else(|| anyhow!("height exhausted"))?,
            validators: next,
        };
        if self
            .scheduled
            .last()
            .is_some_and(|s| s.announced_height == self.last_height)
        {
            *self.scheduled.last_mut().unwrap() = snapshot.clone();
        } else {
            self.scheduled.push(snapshot.clone());
        }
        self.validate()?;
        Ok(Some(snapshot))
    }
    /// Under the stake hand-over rule: the voting power by which seated stake
    /// falls short of the target. None without the rule.
    ///
    /// Seated stake is independent stake: the power, in the roster in force,
    /// of the validators that are not starting validators, unless jailed.
    /// That does not depend on a bond of the moment, so a validator that asks
    /// to leave counts until the roster without it is in force. A starting
    /// validator counts for nothing, funded or not, and so does stake
    /// delegated to it: the hand-over is to stake other than theirs, so their
    /// own stake, bonded rewards included, can never end their bootstrap.
    fn stake_gap(&self, candidates: &[Candidate]) -> Result<Option<u64>> {
        let Some(rule) = &self.stake_handover else {
            return Ok(None);
        };
        let mut seated = 0u64;
        for validator in &self.active {
            let candidate = candidates
                .iter()
                .find(|c| c.owner == validator.owner)
                .ok_or_else(|| anyhow!("roster references absent candidate"))?;
            if !candidate.jailed && !candidate.genesis {
                seated = add(seated, validator.power)?;
            }
        }
        let supply = ratio(self.last_elapsed / SECOND, rule.supply_share_ppm, 1_000_000)?;
        Ok(Some(add(rule.target_power, supply)?.saturating_sub(seated)))
    }
    fn record_churn(&mut self, units: u64) -> Result<()> {
        ensure!(units > 0, "zero churn charge");
        let bucket = self.profile.churn_bucket();
        let expiry = add(
            add(self.last_elapsed, self.profile.churn_window())?,
            bucket - 1,
        )? / bucket
            * bucket;
        if let Some(last) = self.churn.last_mut().filter(|c| c.expires_at == expiry) {
            last.units = add(last.units, units)?;
        } else {
            self.churn.push(ChurnCharge {
                expires_at: expiry,
                units,
            });
        }
        Ok(())
    }
    fn has_jailed_authority(&self, candidates: &[Candidate]) -> bool {
        self.active
            .iter()
            .chain(self.scheduled.iter().flat_map(|s| &s.validators))
            .any(|v| candidates.iter().any(|c| c.owner == v.owner && c.jailed))
    }
}

pub fn validate_set(set: &[Validator]) -> Result<()> {
    ensure!(
        !set.is_empty()
            && set.len() <= MAX_VALIDATORS
            && set.windows(2).all(|w| w[0].owner < w[1].owner),
        "validator set size/order"
    );
    let mut keys = BTreeSet::new();
    let mut total = 0;
    for v in set {
        public_key(&v.consensus_key)?;
        ensure!(
            v.power > 0 && keys.insert(&v.consensus_key),
            "validator key/power"
        );
        total = add(total, v.power)?;
    }
    ensure!(total <= u64::MAX / SECOND, "validator power bound");
    Ok(())
}
// Move one authority toward its target without ever crossing the rolling
// budget or concentration bound. Tiny funded entrants can thus replace faded
// bootstrap power; requiring their full target immediately would deadlock.
fn fit_power(
    old: &[Validator],
    proposed: Vec<Validator>,
    owner: u64,
    before: u64,
    budget: u64,
) -> Result<(Vec<Validator>, u64)> {
    let full_charge = churn_units_trusted(old, &proposed)?;
    if full_charge <= budget && max_concentration(&proposed)? <= CHURN_LIMIT {
        return Ok((proposed, full_charge));
    }
    let desired = proposed
        .iter()
        .find(|v| v.owner == owner)
        .ok_or_else(|| anyhow!("power target missing"))?
        .power;
    let distance = desired.abs_diff(before);
    let mut low = 0;
    let mut high = distance;
    while low < high {
        let step = low + (high - low).div_ceil(2);
        let power = if desired >= before {
            before + step
        } else {
            before - step
        };
        let mut trial = proposed.clone();
        trial.iter_mut().find(|v| v.owner == owner).unwrap().power = power;
        let charge = churn_units_trusted(old, &trial)?;
        if charge <= budget && max_concentration(&trial)? <= CHURN_LIMIT {
            low = step;
        } else {
            high = step - 1;
        }
    }
    if low == 0 {
        return Ok((old.to_vec(), 0));
    }
    let mut result = proposed;
    result.iter_mut().find(|v| v.owner == owner).unwrap().power = if desired >= before {
        before + low
    } else {
        before - low
    };
    let charge = churn_units_trusted(old, &result)?;
    Ok((result, charge))
}

/// Finalize(H) returns these changes to Comet; they become the actual roster
/// at H+2. Removals explicitly carry zero power and key order is deterministic.
pub fn validator_updates(old: &[Validator], new: &[Validator]) -> Result<Vec<Validator>> {
    validate_set(old)?;
    validate_set(new)?;
    let mut changes = Vec::new();
    for previous in old {
        if !new
            .iter()
            .any(|v| v.consensus_key == previous.consensus_key)
        {
            let mut removed = previous.clone();
            removed.power = 0;
            changes.push(removed);
        }
    }
    for next in new {
        if !old
            .iter()
            .any(|v| v.consensus_key == next.consensus_key && v.power == next.power)
        {
            changes.push(next.clone());
        }
    }
    changes.sort_by(|a, b| a.consensus_key.cmp(&b.consensus_key));
    Ok(changes)
}
pub fn churn_units(old: &[Validator], new: &[Validator]) -> Result<u64> {
    validate_set(old)?;
    validate_set(new)?;
    churn_units_trusted(old, new)
}
fn churn_units_trusted(old: &[Validator], new: &[Validator]) -> Result<u64> {
    let old_total = old.iter().try_fold(0, |s, v| add(s, v.power))? as u128;
    let new_total = new.iter().try_fold(0, |s, v| add(s, v.power))? as u128;
    let mut decrease = 0u128;
    for before in old {
        let after = new
            .iter()
            .find(|v| v.consensus_key == before.consensus_key)
            .map_or(0, |v| v.power) as u128;
        let lhs = before.power as u128 * new_total;
        let rhs = after * old_total;
        if lhs > rhs {
            decrease = decrease
                .checked_add(lhs - rhs)
                .ok_or_else(|| anyhow!("churn overflow"))?;
        }
    }
    let denominator = old_total * new_total;
    Ok(u64::try_from(
        (decrease * SCALE as u128).div_ceil(denominator),
    )?)
}
fn max_concentration(set: &[Validator]) -> Result<u64> {
    let total = set.iter().try_fold(0, |s, v| add(s, v.power))?;
    Ok(u64::try_from(
        (set.iter().map(|v| v.power).max().unwrap_or(0) as u128 * SCALE as u128)
            .div_ceil(total as u128),
    )?)
}
fn cap_concentration(set: &mut [Validator]) -> Result<()> {
    let maximum = set.iter().map(|v| v.power).max().unwrap_or(0);
    let mut low = 1;
    let mut high = maximum;
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let sum = set.iter().try_fold(0, |s, v| add(s, v.power.min(mid)))?;
        if mid as u128 * 10 <= sum as u128 * 3 {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    for v in set {
        v.power = v.power.min(low);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuous_second_updates_have_at_most_sixty_one_conservative_expiry_buckets() {
        let roster = (0..20)
            .map(|id| Validator {
                owner: id,
                consensus_key: hex::encode(
                    ed25519_dalek::SigningKey::from_bytes(&[id as u8 + 1; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
                power: Profile::Production.genesis_power(),
            })
            .collect();
        let mut s = Summary::new(roster).unwrap();
        for second in 1..=7200 {
            s.last_elapsed = second * SECOND;
            s.churn.retain(|c| c.expires_at > s.last_elapsed);
            s.record_churn(1).unwrap();
            assert!(s.churn.len() <= 61);
            for entry in &s.churn {
                assert!(entry.expires_at > s.last_elapsed);
            }
            assert_eq!(s.churn.last().unwrap().expires_at % (60 * SECOND), 0);
            assert!(s.churn.last().unwrap().expires_at >= s.last_elapsed + 3600 * SECOND);
        }
        s.validate().unwrap();
        assert_eq!(s.churn.len(), 60);
    }
}
