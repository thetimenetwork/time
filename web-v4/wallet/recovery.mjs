import { hex } from './vault.mjs';
import { guardianChecks, guardianAlikeWords, GUARDIAN_ACKNOWLEDGE } from './names.mjs';
const $ = id => document.getElementById(id);
function assert(value, message) { if (!value) throw new Error(message); }
function node(tag, text, className) { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; }
const elapsed = state => BigInt(state.time_micros) - BigInt(state.genesis.genesis_time_micros);
export function validateRecoveryClaim(claim, state) {
  assert(claim && Object.keys(claim).sort().join(',') === 'auth_epoch,expires_elapsed_micros,networkId,new_public_key,policy_version,proof,recovery_id,target,version', 'Unknown or missing recovery request fields.');
  assert(claim.version === 1 && claim.networkId === state.network_id, 'Wrong recovery network or version.');
  for (const field of ['target', 'policy_version', 'auth_epoch', 'expires_elapsed_micros']) assert(typeof claim[field] === 'string' && /^(0|[1-9][0-9]*)$/.test(claim[field]) && BigInt(claim[field]) <= 18446744073709551615n, 'Invalid recovery integer.');
  for (const field of ['recovery_id', 'new_public_key']) assert(typeof claim[field] === 'string' && /^[0-9a-f]{64}$/.test(claim[field]), 'Invalid recovery identifier/key.');
  assert(typeof claim.proof === 'string' && /^[0-9a-f]{128}$/.test(claim.proof), 'Invalid new-key proof.');
  const target = state.accounts.find(a => String(a.id) === claim.target);
  assert(target?.recovery_policy && String(target.recovery_version) === claim.policy_version && String(target.auth_epoch) === claim.auth_epoch, 'Recovery policy or account authority changed. Generate a fresh request.');
  assert(BigInt(claim.expires_elapsed_micros) > elapsed(state), 'Recovery request expired. Generate a fresh one.');
  assert(BigInt(claim.expires_elapsed_micros) <= elapsed(state) + BigInt(target.recovery_policy.delay_seconds) * 1000000n + BigInt(state.config.recovery_approval_window_micros), 'Recovery request expiry exceeds the allowed claim window.');
  assert(!target.devices.some(d => d.public_key === claim.new_public_key), 'This key is already an approved device.');
  return target;
}
export function recoveryCaseReady(caseRecord, state) {
  return Boolean(caseRecord && caseRecord.ready_elapsed_micros !== null && BigInt(caseRecord.ready_elapsed_micros) <= elapsed(state) && BigInt(caseRecord.expires_elapsed_micros) > elapsed(state));
}
export function createRecoveryUI(c) {
  let currentClaim;let lookupTargetName='';
  const key = () => `timecurrency.recovery-claim.v1:${c.network().networkId}:${c.session().binding.name}:${c.session().binding.publicKey}`;
  function actionRow(title, detail, buttonLabel, callback) {
    const r = node('div', '', 'row'), text = node('div', ''); text.append(node('strong', title), node('small', detail)); r.append(text);
    if (buttonLabel) { const b = node('button', buttonLabel, 'secondary'); b.type = 'button'; if (buttonLabel !== 'Cancel recovery') b.dataset.chainAction = 'true'; b.addEventListener('click', () => c.run(callback)); r.append(b); }
    return r;
  }
  $('recovery-policy-form').addEventListener('submit', event => { event.preventDefault(); c.run(async () => {
    const check = c.capture();
    assert(typeof c.sdk.recoveryProofBytes === 'function', 'Recovery protocol is unavailable in this wallet SDK.');
    const names = $('recovery-guardians').value.split(',').map(n => n.trim().replace(/^@/, ''));
    assert(names.length >= 2 && names.length <= 5 && new Set(names).size === names.length, 'Choose two to five different guardians.');
    const state = await c.verifiedState({ names }); check(); const own = c.ownAccount(state);
    const accounts = names.map(name => state.accounts.find(a => a.name === name)); assert(accounts.every(Boolean), 'Every guardian name must exist on the verified network.');
    assert(accounts.every(a => String(a.id) !== String(own.id)), 'An account cannot be its own guardian.');
    const threshold = $('recovery-threshold').value; assert(/^[2-5]$/.test(threshold) && Number(threshold) <= names.length && Number(threshold) > names.length / 2, 'Use at least two approvals and a strict majority of the guardians.');
    const guardians = accounts.map(a => String(a.id)).sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1);
    // Guardians can take the account over: a typed name that reads like the account's own name, like a name it has
    // paid from this browser, or like a guardian typed before it may be someone else's account (names.mjs,
    // guardianChecks). The review then shows both names and asks for a tick before the button that signs works.
    const alike = guardianChecks(names, { ownName: own.name, paidNames: typeof c.paidNames === 'function' ? c.paidNames() : [] });
    if (!await c.review('Set guardian recovery policy', [['Guardians', names.map(n => '@' + n).join(', ')], ['Required approvals', `${threshold} of ${names.length}`], ['Trust', 'A colluding quorum can replace all your devices and take over the account.'], ['Full delay', String((BigInt(state.config.recovery_min_delay_micros)+999999n)/1000000n)+' seconds; production profile requires at least two days.'], ['Fee', c.fee()]], 'Set recovery policy', alike.length ? { warnings: alike.map(guardianAlikeWords), acknowledge: GUARDIAN_ACKNOWLEDGE } : {})) return;
    check(); c.setBusy(true); await c.sendSigned('set_recovery', { guardians, threshold, delay_seconds: ((BigInt(state.config.recovery_min_delay_micros)+999999n)/1000000n).toString() }, 'Set guardian recovery policy'); await c.refresh(); c.notice('Recovery policy finalized. Each nominee must separately consent before being used.');
  }); });
  $('recovery-approve-form').addEventListener('submit', event => { event.preventDefault(); c.run(async () => {
    const check = c.capture(), raw = $('recovery-request').value; assert(raw.length < 4096, 'Recovery request is too large.');
    let claim; try { claim = JSON.parse(raw); } catch { throw new Error('Paste a valid public recovery request.'); }
    const state = await c.verifiedState({ ids: [claim.target] }); check(); const own = c.ownAccount(state), target = validateRecoveryClaim(claim, state);
    assert(target.recovery_policy.guardians.includes(String(own.id)) && target.recovery_policy.accepted.includes(String(own.id)), 'This account is not an opted-in guardian for that policy.');
    assert(!(state.recovery_cases || []).some(r => r.target === claim.target && r.recovery_id === claim.recovery_id && r.approvals.includes(String(own.id))), 'This guardian already approved this request.');
    const pub = await crypto.subtle.importKey('raw', c.sdk.hexToBytes(claim.new_public_key), 'Ed25519', false, ['verify']);
    assert(await crypto.subtle.verify('Ed25519', pub, c.sdk.hexToBytes(claim.proof), c.sdk.recoveryProofBytes(claim)), 'New device key-possession proof failed.'); check();
    if (!await c.review('Approve account recovery', [['Account being recovered', '@' + target.name], ['New public key · compare with the person', claim.new_public_key], ['Recovery identifier', claim.recovery_id], ['Effect', 'Quorum freezes spending. After 30 seconds the new device can replace every previous device.'], ['Fee', c.fee()]], 'Approve recovery')) return;
    check(); c.setBusy(true); await c.sendSigned('approve_recovery', { target: claim.target, policy_version: claim.policy_version, recovery_id: claim.recovery_id, new_public_key: claim.new_public_key, expires_elapsed_micros: claim.expires_elapsed_micros, proof: claim.proof }, 'Guardian recovery approval'); await c.refresh(); $('recovery-request').value = ''; c.notice('Guardian approval finalized. Share no passwords or private keys.');
  }); });
  $('copy-recovery-claim').addEventListener('click', () => c.run(async () => { await navigator.clipboard.writeText($('recovery-claim-code').value); c.notice('Public recovery request copied.'); }));
  $('check-recovery-claim').addEventListener('click', () => c.run(async () => { c.setBusy(true); await c.refresh(); }));
  $('finalize-recovery').addEventListener('click', () => c.run(async () => {
    const check = c.capture(), state = await c.verifiedState(); check(); const target = validateRecoveryClaim(currentClaim, state);
    const caseRecord = (state.recovery_cases || []).find(r => r.target === String(target.id) && r.recovery_id === currentClaim.recovery_id);
    assert(recoveryCaseReady(caseRecord, state), 'Guardian quorum or the full recovery delay is not complete.');
    if (!await c.review('Finalize account recovery', [['Account', '@' + target.name], ['New public key', currentClaim.new_public_key], ['Effect', 'Every previous device loses authority. This device becomes the managing and spending device.'], ['Fee', '0 seconds']], 'Replace previous devices')) return;
    check(); c.setBusy(true); await c.sendSigned('finalize_recovery', { recovery_id: currentClaim.recovery_id }, 'Finalize guardian recovery', { recoveryFinalization: true });
    check(); localStorage.removeItem(key()); await c.refresh(); c.notice('Recovery finalized and verified. All old device authorities were replaced.');
  }));
  function render(own, state) {
    const supported = typeof c.sdk.recoveryProofBytes === 'function';
    $('recovery-policy-summary').replaceChildren(); $('recovery-consent-list').replaceChildren(); $('recovery-owner-cases').replaceChildren();
    if (!supported) { $('recovery-policy-summary').append(node('p', 'Guardian recovery is not available on this network.', 'subtle')); return; }
    const policy = own.recovery_policy;
    if (policy) {
      const names = policy.guardians.map(id => '@' + (state.accounts.find(a => String(a.id) === id)?.name || id));
      $('recovery-policy-summary').append(node('h3', `Policy ${own.recovery_version}: ${policy.threshold} of ${names.length}`), node('p', `${names.join(', ')} · ${policy.accepted.length} have consented · delay ${policy.delay_seconds}s`, 'subtle'));
    } else $('recovery-policy-summary').append(node('p', 'No recovery policy configured. Losing all approved devices can permanently lose access.', 'subtle'));
    const ownCases = (state.recovery_cases || []).filter(r => r.target === String(own.id));
    for (const r of ownCases) $('recovery-owner-cases').append(node('p', `${r.approvals.length} guardian approvals for ${r.new_public_key}. ${r.ready_elapsed_micros !== null ? 'Quorum reached: spending is frozen until recovery is finalized or canceled.' : 'No quorum yet.'}`, 'subtle'));
    if (ownCases.length) $('recovery-owner-cases').append(actionRow('Unexpected recovery?', 'A current managing device can cancel every pending case for zero fee.', 'Cancel recovery', async () => {
      const check = c.capture(); if (!await c.review('Cancel pending recovery', [['Account', '@' + own.name], ['Effect', 'Clear all pending recovery cases, unfreeze spending and invalidate old recovery proofs.'], ['Fee', '0 seconds']], 'Cancel recovery')) return;
      check(); c.setBusy(true); await c.sendSigned('cancel_recovery', {}, 'Cancel guardian recovery'); await c.refresh(); c.notice('Pending recovery canceled and account authority epoch advanced.');
    }));
    const nominees = state.accounts.filter(a => a.recovery_policy?.guardians.includes(String(own.id)));
    $('recovery-consent-list').append(node('p', 'Look up a target account to view its verified guardian nomination. Compact account proofs do not scan every account.', 'subtle'));
    const lookup = document.createElement('input'); lookup.id = 'guardian-target-name';lookup.value=lookupTargetName; lookup.placeholder = '@account to check'; lookup.setAttribute('aria-label', 'Guardian nomination target account');
    const checkTarget = node('button', 'Check nomination', 'secondary'); checkTarget.type = 'button'; checkTarget.id = 'guardian-target-check';
    checkTarget.addEventListener('click', () => c.run(async () => {
      const name = lookup.value.trim().replace(/^@/, ''); assert(/^[a-z0-9_]{2,15}$/.test(name), 'Enter a valid target account name.');
      const check = c.capture(), view = await c.verifiedState({ names: [name] }); check();
      const target = view.accounts.find(a => a.name === name); assert(target, 'Target account does not exist.');
      assert(target.recovery_policy?.guardians.includes(String(own.id)), 'This account has not nominated you in its current verified policy.');
      lookupTargetName=name;c.rememberGuardianTarget(name);render(c.ownAccount(view), view);
    }));
    $('recovery-consent-list').append(lookup, checkTarget);
    for (const target of nominees) {
      const accepted = target.recovery_policy.accepted.includes(String(own.id));
      $('recovery-consent-list').append(actionRow(`@${target.name} nominated you`, accepted ? 'You consented to act as a guardian.' : 'Nomination is inactive until you consent.', accepted ? 'Withdraw consent' : 'Consent', async () => {
        const check = c.capture(); if (!await c.review(accepted ? 'Withdraw guardian consent' : 'Consent to be a guardian', [['Target account', '@' + target.name], ['Responsibility', accepted ? 'You will stop authorizing recoveries for this policy.' : 'Verify the person before approving any future key replacement. Consent alone does not approve a recovery.'], ['Fee', accepted ? '0 seconds' : c.fee()]])) return;
        check(); c.setBusy(true); await c.sendSigned('consent_recovery', { target: String(target.id), policy_version: String(target.recovery_version), accept: !accepted }, accepted ? 'Withdraw guardian consent' : 'Consent as guardian'); await c.refresh(); c.notice('Guardian consent choice finalized.');
      }));
    }
  }
  async function renderClaim(target, state) {
    const check = c.capture(), policy = target.recovery_policy;
    assert(policy && policy.accepted.length >= Number(policy.threshold), 'This account has no active guardian quorum. Use approved-device enrollment or configure recovery on an existing device first.');
    let claim; try { claim = JSON.parse(localStorage.getItem(key()) || 'null'); if (claim) validateRecoveryClaim(claim, state); } catch { claim = null; }
    if (!claim) {
      claim = { version: 1, networkId: c.network().networkId, target: String(target.id), policy_version: String(target.recovery_version), auth_epoch: String(target.auth_epoch), recovery_id: hex(crypto.getRandomValues(new Uint8Array(32))), new_public_key: c.session().binding.publicKey, expires_elapsed_micros: (elapsed(state) + BigInt(policy.delay_seconds) * 1000000n + BigInt(state.config.recovery_approval_window_micros)).toString() };
      claim.proof = hex(await crypto.subtle.sign('Ed25519', c.session().privateKey, c.sdk.recoveryProofBytes(claim))); check(); localStorage.setItem(key(), JSON.stringify(claim));
    }
    assert(claim.new_public_key === c.session().binding.publicKey, 'Recovery request targets a different local key.'); currentClaim = claim; $('recovery-claim-code').value = JSON.stringify(claim);
    const caseRecord = state.recovery_cases?.find(r => r.target === String(target.id) && r.recovery_id === claim.recovery_id);
    let status = `${caseRecord?.approvals.length || 0} of ${policy.threshold} approvals received.`;
    if (caseRecord?.ready_elapsed_micros !== null && caseRecord?.ready_elapsed_micros !== undefined) status += recoveryCaseReady(caseRecord, state) ? ' The waiting period is over. You can finish the recovery.' : ` Spending frozen; wait about ${(BigInt(caseRecord.ready_elapsed_micros) - elapsed(state) + 999999n) / 1000000n} seconds.`;
    $('recovery-claim-status').textContent = status; $('finalize-recovery').disabled = !recoveryCaseReady(caseRecord, state);
  }
  function availability(ready, device, frozen) {
    $('recovery-policy-form').querySelector('button').disabled = !ready || !device?.can_manage || frozen;
    $('recovery-approve-form').querySelector('button').disabled = !ready || !device?.can_manage || frozen;
    const state = c.state();
    const caseRecord = (state?.recovery_cases || []).find(r => r.recovery_id === currentClaim?.recovery_id && r.new_public_key === c.session()?.binding.publicKey);
    $('finalize-recovery').disabled = !ready || !recoveryCaseReady(caseRecord, state);
  }
  return {render,renderClaim,availability,resetTarget(){lookupTargetName='';currentClaim=undefined;}};
}
