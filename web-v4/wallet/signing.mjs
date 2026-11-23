// How this wallet signs and sends one action of an account: the one place where a private key
// signs for the chain (the Security tab's own actions, kinds 70 to 77, are built in
// security-ui.mjs). app.js makes one `sendSigned` from this module and hands it to every tab.
//
// It lives in a module of its own, with what it needs handed in, so that tests can call it:
// which key may sign which kind of action must not rest on lines no test can reach.
//
// The rules it holds, each checked before any key signs:
// - A payment key (`signer`: the spend key of a secured account, unlocked for one action) signs
//   only the kinds security-flows.mjs lists for it (`assertSpendKeySigns`): payments, the Earn
//   tab's staking and a validator's upgrade signal. Never a registration or a recovery.
// - On a secured account the login key signs nothing here: an action without a `signer` is
//   refused. Whether the account is secured is read from the state verified for this very
//   action (`accountSecured`), not handed in.
// - While a guardian recovery freezes the account, only its cancellation or its completion.
// - One signed action at a time: the pending record is written before the bytes leave, and it
//   is cleared by a verified receipt only.
import { withSigningLock } from './guards.mjs';
import { accountActionHeader, recoveryFrozen, emergencyCancelSlot, nonceCancelSlot, authorityReservationObsolete, emergencyReservationObsolete } from './actions.mjs';
import { recoveryCaseReady } from './recovery.mjs';
import { assertSpendKeySigns, accountSecured } from './security-flows.mjs';
import { b64, fromB64 } from './vault.mjs';

function assert(value, message) { if (!value) throw new Error(message); }

/// `c`: { sdk, session(), network(), client(), locks(), capture(), ownAccount(state?),
/// verifiedState(), pending, paymentMarkers, notice(text, type), record(receipt, label) }.
export function createSendSigned(c) {
  return async function sendSigned(kind, payload, label, { anonymous = false, recoveryFinalization = false, merchantOrigin = 'unknown', signer = null } = {}) {
    const sdk = c.sdk, session = c.session(), network = c.network(), pending = c.pending, paymentMarkers = c.paymentMarkers;
    assert(session?.privateKey, 'Unlock this device first.');
    // The spend key of a secured account signs an explicit list of kinds only: payments, the Earn tab's staking,
    // and a validator's upgrade signal from the Validator signal tab.
    if (signer) { assert(!anonymous && !recoveryFinalization, 'A payment key signs payments, staking and a validator\'s upgrade signal only.'); assertSpendKeySigns(kind); }
    const check = c.capture(), binding = { ...session.binding, ...(signer ? { publicKey: signer.publicKey } : {}) }, key = signer?.privateKey || session.privateKey;
    const initialAccount = c.ownAccount(), owner = anonymous ? `register-${binding.publicKey}` : String(initialAccount?.id);
    return withSigningLock(c.locks(), network.networkId, owner, async () => {
      check(); const state = await c.verifiedState(); check();
      const account = c.ownAccount(state);
      if (!anonymous) {
        assert(account, 'Account is not registered.');
        assert(recoveryFinalization||kind==='cancel_recovery'||!recoveryFrozen(state,account.id),'Guardian recovery freezes this account. Cancel recovery or complete the approved recovery before signing another action.');
        // A secured account's login key signs nothing on the chain: everything here goes through its payment key.
        assert(signer || recoveryFinalization || !accountSecured(state, account), 'This account is secured. Its login key cannot sign this; use your payment password.');
        if (recoveryFinalization) {
          assert(kind === 'finalize_recovery', 'Only recovery finalization may use the new-device authority path.');
          const recoveryCase = (state.recovery_cases || []).find(r => r.target === String(account.id) && r.recovery_id === payload.recovery_id && r.new_public_key === binding.publicKey);
          assert(recoveryCaseReady(recoveryCase, state), 'The new key needs an approved recovery case and the completed full delay.');
        } else accountActionHeader({ account, publicKey: binding.publicKey, networkId: network.networkId, kind, payload });
      }
      const cancel = kind === 'cancel_recovery' || kind === 'cancel_pending';
      const storageOwner = kind === 'cancel_recovery' ? emergencyCancelSlot(owner) : kind === 'cancel_pending' ? nonceCancelSlot(owner) : owner;
      if (kind === 'merchant_payment') {
        const previousPayment = paymentMarkers.get(network.networkId, owner, payload.reference);
        assert(!previousPayment, `This order already has a signed payment record (${previousPayment?.hash || ''}). Recheck that receipt; this wallet will not pay the same order twice.`);
      }
      const old = pending.get(network.networkId, owner);
      if (kind === 'cancel_recovery' && old) assert(recoveryFrozen(state, account.id), 'A separate emergency cancellation requires a verified active recovery freeze.');
      else if (kind === 'cancel_pending') assert(!recoveryFrozen(state, account.id), 'Use owner recovery cancellation while a guardian quorum freezes this account.');
      else assert(!old, `A signed action is already pending (${old?.hash || ''}). Check its receipt before signing again.`);
      const args = anonymous || recoveryFinalization ? { networkId: network.networkId, kind, from: anonymous ? sdk.MAX_U64 : String(account.id), nonce: anonymous ? '0' : (BigInt(account.nonce) + 1n).toString(), authEpoch: anonymous ? '0' : String(account.auth_epoch), publicKey: binding.publicKey, payload } : accountActionHeader({ networkId: network.networkId, kind, account, publicKey: binding.publicKey, payload });
      // Checked against the state just verified; checkMerchantQuote reads the version from it.
      if(kind==='merchant_payment')sdk.checkMerchantQuote(payload.reference,args.nonce,state);
      let existingCancel = cancel ? pending.get(network.networkId, storageOwner) : null;
      if (existingCancel && emergencyReservationObsolete(account, existingCancel)) { pending.clear(network.networkId, storageOwner, existingCancel.hash); existingCancel = null; }
      let tx;
      if (existingCancel) {
        tx = fromB64(existingCancel.tx, 512*1024+512); const action = sdk.decodeAction(tx);
        assert(action.kind === sdk.KINDS[kind] && action.networkId === args.networkId && action.from === args.from && action.nonce === args.nonce && action.authEpoch === args.authEpoch && action.publicKey === args.publicKey, 'Previous cancellation must be reconciled before changing it.');
      } else tx = await sdk.signAction(args, key);
      check(); const hash = await sdk.transactionHash(tx); check();
      if (existingCancel) assert(hash === existingCancel.hash.toUpperCase(), 'Emergency cancellation bytes are damaged.');
      else pending.put(network.networkId, storageOwner, { hash, tx: b64(tx), nonce: args.nonce, authEpoch: args.authEpoch, kind, label, at: Date.now() });
      if (kind === 'merchant_payment') paymentMarkers.reserve(network.networkId, owner, payload.reference, hash, merchantOrigin);
      c.notice(`Submitting ${label.toLowerCase()}… Waiting for an independently verified receipt.`, 'busy');
      const client = c.client();
      let receipt;
      if (kind === 'bid') {
        try { await client.submit(tx, { wait: false }); receipt = await client.waitReceipt(hash, { timeoutMs: 8000 }); }
        catch (error) {
          const fresh = await c.verifiedState(); check(); const current = c.ownAccount(fresh);
          if (current && BigInt(fresh.auction_epoch) > BigInt(payload.epoch) && BigInt(current.nonce) < BigInt(args.nonce)) {
            pending.clear(network.networkId, storageOwner, hash);
            throw new Error('The short test-bid epoch closed before inclusion. This signed bid cannot execute in a future epoch. Review a fresh bid to try again.');
          }
          throw error;
        }
      } else receipt = await client.submit(tx);
      check();
      assert(receipt?.verified === true, 'Transaction proof unavailable; action remains pending.');
      pending.clear(network.networkId, storageOwner, hash); c.record(receipt, label);
      if (cancel && old) {
        const after = await c.verifiedState(); check(); const current = c.ownAccount(after);
        if (current && authorityReservationObsolete(current, old)) pending.clear(network.networkId, owner, old.hash);
      }
      return receipt;
    });
  };
}
/// Which function signs a validator's upgrade signal from the Validator signal tab: on a secured
/// account the Security tab's `signalAction` (the payment key, with the payment password), and
/// otherwise `sendSigned` with this browser's key. The kind is fixed here: the tab can have
/// nothing else signed. `secured()` says whether the unlocked account is secured now.
export function signalSigner({ secured, signalAction, sendSigned }) {
  return (payload, label) => (secured() ? signalAction(payload, label) : sendSigned('upgrade_signal', payload, label));
}
