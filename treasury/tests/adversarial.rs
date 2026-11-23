use bitcoin::{
    PublicKey,
    secp256k1::{Secp256k1, SecretKey},
};
use ed25519_dalek::{Signer, SigningKey};
use time_treasury_policy::{
    Approval, Context, Control, MIN_BITCOIN_DELAY_BLOCKS, MIN_DELAY_MICROS, Policy, Proposal,
    Treasury,
};

fn council(seed: u8) -> Vec<SigningKey> {
    (0..7)
        .map(|i| SigningKey::from_bytes(&[seed + i; 32]))
        .collect()
}
fn policy(revision: u64, seed: u8) -> Policy {
    let secp = Secp256k1::new();
    Policy {
        revision,
        governance_keys: council(seed)
            .iter()
            .map(|key| hex::encode(key.verifying_key().as_bytes()))
            .collect(),
        treasury_keys: (0..7)
            .map(|i| {
                PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&[seed + i; 32]).unwrap(),
                ))
                .to_string()
            })
            .collect(),
    }
}
fn context() -> Context {
    Context {
        time_height: 100,
        elapsed_micros: 100_000_000,
        bitcoin_height: 1_000_000,
    }
}
fn sign(seed: u8, message: &[u8]) -> Vec<Approval> {
    council(seed)
        .iter()
        .take(5)
        .map(|key| Approval {
            public_key: hex::encode(key.verifying_key().as_bytes()),
            signature: key.sign(message).to_bytes().to_vec(),
        })
        .collect()
}
fn proposal() -> Proposal {
    let now = context();
    Proposal {
        next: policy(2, 40),
        activate_after_time: now.elapsed_micros + MIN_DELAY_MICROS,
        activate_after_bitcoin_height: now.bitcoin_height + MIN_BITCOIN_DELAY_BLOCKS,
        proposal_expires: now.elapsed_micros + MIN_DELAY_MICROS + 86_400_000_000,
    }
}
fn pending(initial: &Treasury, proposal: Proposal) -> Treasury {
    let old = sign(10, &initial.proposal_message(&proposal, false).unwrap());
    let new = sign(40, &initial.proposal_message(&proposal, true).unwrap());
    initial.propose(proposal, &old, &new, context()).unwrap()
}

#[test]
fn control_authorization_must_bind_the_full_pending_schedule() {
    let initial = Treasury::new([9; 32], policy(1, 10), context()).unwrap();
    let a = proposal();
    let mut b = a.clone();
    b.activate_after_time += 100;
    b.activate_after_bitcoin_height += 1;
    b.proposal_expires += 100;
    let first = pending(&initial, a);
    let second = pending(&initial, b);
    let deadline = context().elapsed_micros + 1_000_000;
    let message = first.control_message(Control::Cancel, deadline).unwrap();
    let signatures = sign(10, &message);
    assert_ne!(
        message,
        second.control_message(Control::Cancel, deadline).unwrap(),
        "a control signature must identify exact activation/expiry coordinates, not only the next keys"
    );
    assert!(
        second
            .control(Control::Cancel, deadline, &signatures, context())
            .is_err()
    );
}

#[test]
fn approval_roles_and_every_proposal_coordinate_are_bound() {
    let initial = Treasury::new([9; 32], policy(1, 10), context()).unwrap();
    let original = proposal();
    let old = sign(10, &initial.proposal_message(&original, false).unwrap());
    let new = sign(40, &initial.proposal_message(&original, true).unwrap());
    assert!(
        initial
            .propose(original.clone(), &new, &old, context())
            .is_err()
    );
    for kind in 0..3 {
        let mut changed = original.clone();
        match kind {
            0 => changed.activate_after_time += 1,
            1 => changed.activate_after_bitcoin_height += 1,
            _ => changed.proposal_expires += 1,
        };
        assert!(initial.propose(changed, &old, &new, context()).is_err());
    }
}

#[test]
fn unsigned_activation_requires_monotone_validated_context_and_both_delays() {
    let initial = Treasury::new([9; 32], policy(1, 10), context()).unwrap();
    let p = proposal();
    let scheduled = pending(&initial, p.clone());
    let mature = Context {
        time_height: 1000,
        elapsed_micros: p.activate_after_time,
        bitcoin_height: p.activate_after_bitcoin_height,
    };
    let mut rolled_back = mature;
    rolled_back.time_height = 99;
    assert!(scheduled.activate(rolled_back).is_err());
    let activated = scheduled.activate(mature).unwrap();
    assert_eq!(activated.active(), &p.next);
    assert!(activated.activate(mature).is_err());
}
