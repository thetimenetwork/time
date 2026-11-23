use bitcoin::{
    Network, PublicKey,
    secp256k1::{Secp256k1, SecretKey},
};
use ed25519_dalek::{Signer, SigningKey};
use time_treasury_policy::{
    Approval, Context, Control, MIN_BITCOIN_DELAY_BLOCKS, MIN_DELAY_MICROS, Policy, Proposal,
    Treasury,
};

// Deterministic test identities only. No private keys are exported or printed.
fn council(offset: u8) -> Vec<SigningKey> {
    (0..7)
        .map(|i| SigningKey::from_bytes(&[offset + i; 32]))
        .collect()
}
fn policy(revision: u64, offset: u8) -> Policy {
    let secp = Secp256k1::new();
    Policy {
        revision,
        governance_keys: council(offset)
            .iter()
            .map(|k| hex::encode(k.verifying_key().as_bytes()))
            .collect(),
        treasury_keys: (0..7)
            .map(|i| {
                let secret = SecretKey::from_slice(&[offset + i; 32]).unwrap();
                PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
                    &secp, &secret,
                ))
                .to_string()
            })
            .collect(),
    }
}
fn approvals(keys: &[SigningKey], message: &[u8], count: usize) -> Vec<Approval> {
    keys.iter()
        .take(count)
        .map(|key| Approval {
            public_key: hex::encode(key.verifying_key().as_bytes()),
            signature: key.sign(message).to_bytes().to_vec(),
        })
        .collect()
}
fn context() -> Context {
    Context {
        time_height: 100,
        elapsed_micros: 100_000_000,
        bitcoin_height: 1_000_000,
    }
}
fn initial() -> Treasury {
    Treasury::new([42; 32], policy(1, 10), context()).unwrap()
}
#[test]
fn restrictive_emergency_controls_survive_a_shorter_bitcoin_fork_without_weakening_resume() {
    let state = initial();
    let now = context();
    let rollback = Context {
        time_height: now.time_height + 1,
        elapsed_micros: now.elapsed_micros + 1,
        bitcoin_height: now.bitcoin_height - 1,
    };
    let expires = rollback.elapsed_micros + 1000;
    let signed = approvals(
        &council(10),
        &state.control_message(Control::Pause, expires).unwrap(),
        5,
    );
    let paused = state
        .control(Control::Pause, expires, &signed, rollback)
        .unwrap();
    assert!(paused.paused());
    let resume = approvals(
        &council(10),
        &paused.control_message(Control::Resume, expires).unwrap(),
        5,
    );
    assert!(
        paused
            .control(Control::Resume, expires, &resume, rollback)
            .is_err()
    );
    let recovered = Context {
        bitcoin_height: now.bitcoin_height,
        ..rollback
    };
    assert!(
        !paused
            .control(Control::Resume, expires, &resume, recovered)
            .unwrap()
            .paused()
    );
    let pending = propose(&state, proposal());
    let cancel = approvals(
        &council(10),
        &pending.control_message(Control::Cancel, expires).unwrap(),
        5,
    );
    assert!(
        pending
            .control(Control::Cancel, expires, &cancel, rollback)
            .unwrap()
            .pending()
            .is_none()
    );
    let reversed = Context {
        time_height: now.time_height - 1,
        ..rollback
    };
    assert!(
        state
            .control(Control::Pause, expires, &signed, reversed)
            .is_err()
    );
}
fn proposal() -> Proposal {
    Proposal {
        next: policy(2, 30),
        activate_after_time: context().elapsed_micros + MIN_DELAY_MICROS,
        activate_after_bitcoin_height: context().bitcoin_height + MIN_BITCOIN_DELAY_BLOCKS,
        proposal_expires: context().elapsed_micros + MIN_DELAY_MICROS + 86_400_000_000,
    }
}
fn propose(state: &Treasury, proposed: Proposal) -> Treasury {
    let old = approvals(
        &council(10),
        &state.proposal_message(&proposed, false).unwrap(),
        5,
    );
    let new = approvals(
        &council(30),
        &state.proposal_message(&proposed, true).unwrap(),
        5,
    );
    state.propose(proposed, &old, &new, context()).unwrap()
}

#[test]
fn receiving_output_is_four_of_seven_sorted_multisig_with_network_checked_address() {
    let state = initial();
    let script = state.active().witness_script().unwrap();
    let address = state.active().address(Network::Regtest).unwrap();
    assert!(address.to_string().starts_with("bcrt1"));
    assert_eq!(address.script_pubkey(), script.to_p2wsh());
    let mut reversed = state.active().clone();
    reversed.treasury_keys.reverse();
    assert_eq!(reversed.witness_script().unwrap(), script);
    assert_ne!(reversed.hash().unwrap(), state.active().hash().unwrap());
}
#[test]
fn duplicate_weak_noncanonical_or_wrong_authority_keys_are_rejected() {
    let mut p = policy(1, 10);
    p.treasury_keys[1] = p.treasury_keys[0].clone();
    assert!(p.validate().is_err());
    let mut p = policy(1, 10);
    p.governance_keys[1] = p.governance_keys[0].clone();
    assert!(p.validate().is_err());
    let mut p = policy(1, 10);
    p.governance_keys[0] = "00".repeat(32);
    assert!(p.validate().is_err());
    let mut p = policy(1, 10);
    p.treasury_keys[0] = p.treasury_keys[0].to_uppercase();
    assert!(p.validate().is_err());
}
#[test]
fn rotation_needs_old_and_new_governance_quorums_and_both_timelocks() {
    let state = initial();
    let p = proposal();
    let old = approvals(&council(10), &state.proposal_message(&p, false).unwrap(), 5);
    let new = approvals(&council(30), &state.proposal_message(&p, true).unwrap(), 5);
    assert!(
        state
            .propose(p.clone(), &old[..4], &new, context())
            .is_err()
    );
    assert!(
        state
            .propose(p.clone(), &old, &new[..4], context())
            .is_err()
    );
    let scheduled = state.propose(p.clone(), &old, &new, context()).unwrap();
    assert_eq!(scheduled.active(), state.active());
    let mut mature = Context {
        time_height: 1000,
        elapsed_micros: p.activate_after_time,
        bitcoin_height: p.activate_after_bitcoin_height,
    };
    mature.bitcoin_height -= 1;
    assert!(scheduled.activate(mature).is_err());
    mature.bitcoin_height += 1;
    mature.elapsed_micros -= 1;
    assert!(scheduled.activate(mature).is_err());
    mature.elapsed_micros += 1;
    assert_eq!(scheduled.activate(mature).unwrap().active(), &p.next);
}
#[test]
fn server_substitution_replay_and_duplicate_signatures_cannot_change_destination() {
    let state = initial();
    let p = proposal();
    let old = approvals(&council(10), &state.proposal_message(&p, false).unwrap(), 5);
    let new = approvals(&council(30), &state.proposal_message(&p, true).unwrap(), 5);
    let mut changed = p.clone();
    changed.next.treasury_keys = policy(2, 50).treasury_keys;
    assert!(state.propose(changed, &old, &new, context()).is_err());
    let foreign = Treasury::new([43; 32], policy(1, 10), context()).unwrap();
    assert!(foreign.propose(p.clone(), &old, &new, context()).is_err());
    let repeated = vec![old[0].clone(); 5];
    assert!(
        state
            .propose(p.clone(), &repeated, &new, context())
            .is_err()
    );
    let pending = state.propose(p, &old, &new, context()).unwrap();
    assert!(pending.propose(proposal(), &old, &new, context()).is_err());
}
#[test]
fn pause_cannot_redirect_or_silently_resume_on_rotation() {
    let state = initial();
    let expires = context().elapsed_micros + 1_000_000;
    let signed = approvals(
        &council(10),
        &state.control_message(Control::Pause, expires).unwrap(),
        5,
    );
    let paused = state
        .control(Control::Pause, expires, &signed, context())
        .unwrap();
    assert!(paused.receiving_script().is_err());
    assert_eq!(paused.active(), state.active());
    assert!(
        paused
            .control(Control::Resume, expires, &signed, context())
            .is_err()
    );
    let pending = propose(&paused, proposal());
    let p = proposal();
    let mature = Context {
        time_height: 1000,
        elapsed_micros: p.activate_after_time,
        bitcoin_height: p.activate_after_bitcoin_height,
    };
    let rotated = pending.activate(mature).unwrap();
    assert!(rotated.paused());
    assert!(rotated.receiving_script().is_err());
    let deadline = mature.elapsed_micros + 1_000_000;
    let signed = approvals(
        &council(30),
        &rotated.control_message(Control::Resume, deadline).unwrap(),
        5,
    );
    assert!(
        !rotated
            .control(Control::Resume, deadline, &signed, mature)
            .unwrap()
            .paused()
    );
}
#[test]
fn cancel_replacement_expiry_and_replay_are_bound_to_full_state() {
    let state = initial();
    let pending = propose(&state, proposal());
    let deadline = context().elapsed_micros + 1_000_000;
    let signed = approvals(
        &council(10),
        &pending.control_message(Control::Cancel, deadline).unwrap(),
        5,
    );
    let cancelled = pending
        .control(Control::Cancel, deadline, &signed, context())
        .unwrap();
    assert_eq!(cancelled.active(), state.active());
    assert!(cancelled.pending().is_none());
    assert!(
        cancelled
            .control(Control::Cancel, deadline, &signed, context())
            .is_err()
    );
    let late = Context {
        elapsed_micros: deadline + 1,
        ..context()
    };
    assert!(
        pending
            .control(Control::Cancel, deadline, &signed, late)
            .is_err()
    );
    let p = proposal();
    let scheduled = propose(&state, p.clone());
    let expired = Context {
        time_height: 1000,
        elapsed_micros: p.proposal_expires + 1,
        bitcoin_height: p.activate_after_bitcoin_height,
    };
    assert!(scheduled.activate(expired).is_err());
    let mut too_soon = p;
    too_soon.activate_after_time -= 1;
    let old = approvals(
        &council(10),
        &state.proposal_message(&too_soon, false).unwrap(),
        5,
    );
    let new = approvals(
        &council(30),
        &state.proposal_message(&too_soon, true).unwrap(),
        5,
    );
    assert!(state.propose(too_soon, &old, &new, context()).is_err());
}
