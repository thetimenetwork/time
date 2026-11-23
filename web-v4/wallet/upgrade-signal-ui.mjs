// The "Validator signal" tab: the page side of a validator owner's upgrade signal. The decisions
// and every sentence are in upgrade-signal.mjs and in the SDK; this module reads the form, shows
// what proven state says, asks for the review, has the action signed through the wallet's own
// signing path (signing.mjs `sendSigned`, with the payment key on a secured account) and shows
// the result from proven state.
//
// What it never does:
// - fill in a version, a hash or a start time. The three fields hold only what the owner typed,
//   and they are emptied once a signal has been signed and when the wallet locks;
// - show what a gateway answered. A refusal the SDK marks as a gateway's is replaced by a fixed
//   sentence of this wallet (`guarded`), and the line under the form takes only refusals this
//   wallet states itself (`isOwnRefusal`).
// The tab itself is shown only while proven state holds a validator candidate of the account
// that is not archived.
import { fromB64 } from './vault.mjs';
import { parsePlanInput, planMatch, matchText, nearTexts, statusLines, refusalText, refusal, isOwnRefusal, GATEWAY_REFUSED_TEXT, NOT_FINISHED_TEXT, notTakenText, NOT_READ_TEXT, NO_RECEIPT_TEXT, supportReview, withdrawReview, SUPPORT_ACKNOWLEDGE, WITHDRAW_ACKNOWLEDGE, DISCARD_ACKNOWLEDGE, resultLines, withoutReceiptLines, pendingText, discardReview, DISCARDED_NOTICE, ALREADY_PLACED_TEXT, samePayload, compareEntry, expectSignal, unexpectSignal, forgetSignal, changeLines, entryMark, DROPPED_TEXT } from './upgrade-signal.mjs';

const $ = id => document.getElementById(id);
/// Every sentence this module states is this wallet's own refusal.
const assert = (value, message) => { if (!value) throw refusal(message); };
function node(tag, text, className) { const el = document.createElement(tag); el.textContent = text; if (className) el.className = className; return el; }
const PLAN_FIELDS = ['signal-version', 'signal-spec', 'signal-start'];
const TICK_FIRST = 'First check your validator\'s node, then tick the box: the node must run a release that lists this version with this hash. If it does not, do not signal: at the start your node would stop.';
const PENDING_UNREAD = 'This wallet holds a signed signal that it has not seen in a block. Press "Read again from proven state" to see what it is.';

export function createSignalUI(c) {
  let shownFor = null, shownNonce = null, last = null, loading = null, owns = false, retryAt = 0, active = false;
  const scrub = () => { $('signal-payment').value = ''; };
  const pause = c.pause ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const net = () => c.network().networkId;
  /// Empties the three fields and the box: nothing typed for one attempt is left for the next.
  function clearForm() { for (const id of PLAN_FIELDS) $(id).value = ''; $('signal-node-ready').checked = false; }
  const paragraphs = (lines, className) => lines.map(line => node('p', line, className));
  function row(title, detail, extra) { const r = node('div', '', 'row'), copy = node('div', ''); copy.append(node('strong', title)); if (extra) copy.append(node('code', extra)); for (const line of [].concat(detail)) copy.append(node('small', line)); r.append(copy); return r; }
  /// Whether this browser's key may sign "Cancel pending action" (asked of app.js, which offers it).
  const canCancel = () => { try { return c.canCancelPending?.() === true; } catch { return false; } };
  /// One step of this tab. A refusal the SDK marks as a gateway's never leaves the tab in the
  /// gateway's words: the mark is read, never the text.
  async function guarded(fn) {
    try { return await fn(); }
    catch (error) { if (error?.gateway === true && !c.sdk.isUpgradeRequired(error)) throw refusal(GATEWAY_REFUSED_TEXT); throw error; }
  }
  /// Runs a step unless one of this tab is already running: a key held down on the form or on a
  /// button starts one step, not several side by side.
  const step = fn => (active ? undefined : c.run(async () => { if (active) return; active = true; try { await guarded(fn); } finally { active = false; } }));

  // ---------------------------------------------------------------- what this wallet remembers of the account's signal
  // Kept in the browser's storage, by network and account, so that a change made while the wallet
  // was locked is noticed at the next reading. It holds what proven state showed and the payloads
  // of signals signed or discarded here: nothing secret. The storage is read at every comparison, never a copy of
  // this page: two tabs of the wallet share it, and a signal signed in one must not look foreign to the other.
  // Without storage, or where a write failed, what this page kept is used, and it lasts as long as the page.
  const kept = new Map(), unsaved = new Set();
  const memoryKey = id => `timecurrency.signal.v1:${net()}:${id}`;
  function recall(id) {
    const key = memoryKey(id);
    if (c.storage && !unsaved.has(key)) { try { const raw = c.storage.getItem(key); if (raw) return JSON.parse(raw); } catch { /* what this page kept */ } }
    return kept.get(key) ?? null;
  }
  function remember(id, memory) {
    const key = memoryKey(id); kept.set(key, memory);
    if (!c.storage) return;
    try { c.storage.setItem(key, JSON.stringify(memory)); unsaved.delete(key); } catch { unsaved.add(key); }
  }
  /// Compares a status with the memory and keeps the new memory. Returns the standing warning:
  /// the lines to show while proven state holds an entry this wallet did not make.
  function compare(status) {
    const own = status.account, id = String(own.id), waiting = pendingSignal(id);
    const { memory, change } = compareEntry(recall(id), status, { pending: waiting ? waiting.action.payload : null });
    remember(id, memory);
    if (change === 'dropped') c.notice(DROPPED_TEXT);
    else if (change) c.notice(changeLines(status, change)[0], 'error');
    return memory.alert && memory.alert.entry === entryMark(own) ? changeLines(status, memory.alert.kind) : [];
  }

  // ---------------------------------------------------------------- the status, from proven state
  function show(status) {
    last = status;
    const lines = statusLines(status), warning = status.account ? compare(status) : [];
    $('signal-status').replaceChildren(...paragraphs(warning, 'warning'), ...paragraphs(lines.summary), ...paragraphs(lines.own), node('p', lines.note, 'field-note'));
    $('signal-plans').replaceChildren(...(lines.plans.length ? lines.plans.map(plan => row(plan.title, plan.lines, plan.hash)) : [node('p', 'No validator of the current validator sets supports a plan.', 'subtle')]));
    $('signal-validators').replaceChildren(...lines.validators.map(item => row(item.title, item.detail)));
    const own = status.account;
    $('signal-withdraw-note').textContent = own?.supports ? 'Takes back your validator\'s support. Its votes then count for no plan.' : 'Your validator supports no plan, so there is nothing to withdraw.';
    showPending();
  }
  /// A signed signal of this account that the wallet still holds as pending, read from its own bytes.
  function pendingSignal(accountId) {
    let item; try { item = c.pending.get(net(), String(accountId)); } catch { return null; }
    if (!item) return null;
    try { const action = c.sdk.decodeAction(fromB64(item.tx, 512 * 1024 + 512)); return action.kind === c.sdk.KINDS.upgrade_signal && action.from === String(accountId) ? { item, action } : null; } catch { return null; }
  }
  function showPending() {
    const account = c.ownAccount(), waiting = account ? pendingSignal(account.id) : null;
    $('signal-pending-card').hidden = !waiting;
    $('signal-pending-text').textContent = !waiting ? '' : last?.account && last.account.id === String(account.id) ? pendingText(last, waiting.action, { canCancel: canCancel() }) : PENDING_UNREAD;
  }
  /// Reads the status with proofs and shows it. The one place the status comes from. What dates the end of a freeze
  /// (upgrade-signal.mjs, stoppedText) comes with it: the rule of the waits and the total of the stops of the state it
  /// was read from (`status.waits`, TimeSDK.signalStatusOf).
  async function load() {
    const check = c.capture(), account = c.ownAccount(); assert(account, 'Unlock an account first.');
    const status = await c.client().getSignalStatus(String(account.id)); check();
    show(status); shownFor = String(account.id); shownNonce = String(status.account.nonce);
    return status;
  }
  /// A reading without a busy state (when the tab appears, and when the account's action number
  /// has moved): a failure is said in the tab, in this wallet's words.
  function loadQuietly() {
    if (loading) return loading;
    loading = load().catch(error => {
      // A version this app does not implement is the app's own finding: the update screen says it.
      if (c.sdk.isUpgradeRequired(error)) return;
      retryAt = Date.now() + 60000;
      $('signal-status').replaceChildren(node('p', 'The status could not be read with a proof just now. Nothing is shown rather than something unproven. Press "Read again from proven state".', 'warning'));
    }).finally(() => { loading = null; });
    return loading;
  }

  // ---------------------------------------------------------------- signing
  /// Whether this browser can sign for the account, in words, or null.
  function signerRefusal(status) {
    if (c.secured()) return null; // the payment key is unlocked with the payment password when signing
    return status.account.signers.includes(c.session().binding.publicKey) ? null : 'This browser\'s key may not spend for this account, so it cannot sign a signal. Use a device of the account whose key may spend.';
  }
  /// Signs and sends, then reads the result from proven state. A signal that is signed and has no
  /// verified receipt stays pending, and what became of it is read from proven state, never from
  /// what the gateway said.
  async function send(intent, payload, label) {
    const check = c.capture(), id = String(c.ownAccount().id), signed = intent.withdraw ? intent : { version: payload.version, spec: payload.spec, activate_elapsed_micros: payload.activate_elapsed_micros };
    const started = Date.now();
    remember(id, expectSignal(recall(id), payload));
    let receipt;
    try { receipt = await c.sign(payload, label); }
    catch (error) {
      check();
      // Its own finding that the network runs rules this app does not know: for the update screen.
      if (c.sdk.isUpgradeRequired(error)) throw error;
      // Whether THIS attempt signed anything: the wallet's pending record must hold this very
      // signal, written during this attempt. A pending signal of another tab (another payload, or
      // an older record) is not this attempt's: then nothing was signed here, and the error says why.
      const waiting = pendingSignal(id);
      const mine = Boolean(waiting) && samePayload(waiting.action.payload, payload) && !(typeof waiting.item.at === 'number' && waiting.item.at < started);
      if (!mine) { remember(id, unexpectSignal(recall(id), payload)); throw error; }
      clearForm();
      // Only the SDK's own mark is read, never the words: a request to the gateway was refused. That
      // may have been the signal (the node did not take it) or only its receipt (the signal went
      // through). So proven state is read for a few blocks: has the account's action number moved?
      const refused = error?.gateway === true, tries = refused ? 6 : 2, discarded = recall(id)?.discarded || [];
      let status = null, used = false;
      for (let attempt = 0; attempt < tries && !used; attempt++) {
        if (attempt) { await pause(1000); check(); }
        try { status = await load(); } catch (again) { if (c.sdk.isUpgradeRequired(again)) throw again; status = null; }
        check();
        used = Boolean(status) && BigInt(status.account.nonce) >= BigInt(waiting.item.nonce);
      }
      let said;
      if (used) said = withoutReceiptLines({ status, intent: signed, discarded });
      // No status was read with a proof after signing: nothing is said about proven state or about the node.
      else if (!status) said = { ok: false, lines: [NOT_READ_TEXT] };
      else if (refused) { const judged = c.sdk.judgeSignal(status, intent); said = { ok: false, lines: [judged.ok ? notTakenText(intent) : refusalText(status, judged, intent, { fee: c.seconds(c.fee()) }) + ' The signed signal is kept as pending (see below, and Activity).'] }; }
      else said = { ok: false, lines: [NO_RECEIPT_TEXT] };
      showPending(); result(said.ok, said.lines); c.notice(said.lines[0], said.ok ? '' : 'error');
      return null;
    }
    check(); clearForm();
    // The receipt proves the block. The state of that block may be served a moment later.
    let status = null;
    for (let attempt = 0; attempt < 12; attempt++) {
      try { status = await load(); } catch (error) { if (c.sdk.isUpgradeRequired(error)) throw error; status = null; }
      check();
      if (status && BigInt(status.height) >= BigInt(receipt.height)) break;
      await pause(500); check();
    }
    // The wallet's own refresh; the result is shown whether or not it could be read.
    try { await c.refresh(); } catch (error) { if (c.sdk.isUpgradeRequired(error)) throw error; }
    check();
    if (!status || BigInt(status.height) < BigInt(receipt.height)) { const text = `The signal is in block ${receipt.height}. Proven state of that block could not be read yet. Press "Read again from proven state" in a moment: your validator's signal above then shows it.`; result(false, [text]); c.notice(text); return receipt; }
    const said = resultLines({ status, intent: signed, receipt });
    result(said.ok, said.lines); c.notice(said.lines[0], said.ok ? '' : 'error');
    return receipt;
  }
  function result(ok, lines) { $('signal-result').replaceChildren(...paragraphs(lines, ok ? '' : 'warning')); $('signal-result-card').hidden = false; }
  /// The checks before any review: a fresh proven status, the engine's rules, the key, the daily limit.
  async function prepare(intent) {
    const check = c.capture(), status = await load(); check();
    const judged = c.sdk.judgeSignal(status, intent);
    if (!judged.ok) throw refusal(refusalText(status, judged, intent, { fee: c.seconds(c.fee()) }));
    const unable = signerRefusal(status) || await c.spendRefusal(); check();
    assert(!unable, unable);
    assert(!pendingSignal(status.account.id), 'A signed signal of this account is still waiting. Check it under Activity, or discard it below, before you sign another.');
    return { status, judged };
  }
  $('signal-form').addEventListener('submit', event => { event.preventDefault(); return step(async () => {
    const check = c.capture();
    try {
      await guarded(async () => {
        const intent = parsePlanInput({ version: $('signal-version').value, spec: $('signal-spec').value, start: $('signal-start').value });
        const { status, judged } = await prepare(intent), match = planMatch(status, intent);
        const compared = [matchText(status, match), ...nearTexts(status, match)].join(' ');
        $('signal-check').textContent = compared;
        if ($('signal-node-ready').checked !== true) { $('signal-check').textContent = compared + ' ' + TICK_FIRST; c.notice(TICK_FIRST, 'error'); return; }
        const secured = c.secured();
        if (!await c.review(`Support version ${judged.plan.version} of the network's rules`, supportReview({ status, judged, match, secured, fee: c.seconds(c.fee()) }), 'Sign the signal', { acknowledge: SUPPORT_ACKNOWLEDGE })) { c.notice('Nothing was signed.'); return; }
        check(); c.setBusy(true);
        await send(intent, judged.payload, `Signal: support version ${judged.plan.version}`);
      });
    } catch (error) {
      // Under the form stands only what this wallet states itself. Anything else (the browser, the
      // verifier, a module of the wallet) gets one fixed sentence; the notice at the top says why.
      if (!c.sdk.isUpgradeRequired(error)) $('signal-check').textContent = isOwnRefusal(error) ? error.message : NOT_FINISHED_TEXT;
      throw error;
    } finally { $('signal-node-ready').checked = false; scrub(); }
  }); });
  $('signal-withdraw').addEventListener('click', () => step(async () => {
    const check = c.capture(), intent = { withdraw: true };
    try {
      const { status, judged } = await prepare(intent);
      if (!await c.review('Withdraw your validator\'s support', withdrawReview({ status, secured: c.secured(), fee: c.seconds(c.fee()) }), 'Sign the withdrawal', { acknowledge: WITHDRAW_ACKNOWLEDGE })) { c.notice('Nothing was signed.'); return; }
      check(); c.setBusy(true);
      await send(intent, judged.payload, 'Signal: withdraw support');
    } finally { scrub(); }
  }));
  $('signal-refresh').addEventListener('click', () => step(async () => { c.setBusy(true); await load(); c.notice('Read again from proven state.'); }));
  /// Forgets a signed signal the wallet holds as pending. It moves nothing, and the signal stays
  /// valid until another action of the account is in a block, which the review says. The wallet
  /// remembers what was discarded: if it is included after all, the next reading says so.
  $('signal-discard').addEventListener('click', () => step(async () => {
    const check = c.capture(), status = await load(); check();
    const id = String(status.account.id), waiting = pendingSignal(id); assert(waiting, 'No signed signal is waiting.');
    assert(BigInt(status.account.nonce) < BigInt(waiting.item.nonce), ALREADY_PLACED_TEXT);
    const cancel = canCancel();
    if (!await c.review('Discard the signed signal', [['The signal', pendingText(status, waiting.action, { canCancel: cancel })], ...discardReview({ canCancel: cancel })], 'Discard it', { acknowledge: DISCARD_ACKNOWLEDGE })) return;
    check();
    const still = pendingSignal(id); assert(still && still.item.hash === waiting.item.hash, 'The signed signal changed while this review was open. Nothing was discarded.');
    remember(id, forgetSignal(recall(id), { hash: waiting.item.hash, nonce: String(waiting.item.nonce), payload: waiting.action.payload }));
    c.pending.clear(net(), id, waiting.item.hash);
    showPending();
    try { await c.refresh(); } catch (error) { if (c.sdk.isUpgradeRequired(error)) throw error; }
    c.notice(DISCARDED_NOTICE);
  }));
  $('tab-upgrade').addEventListener('click', () => { if (owns) loadQuietly(); });

  // ---------------------------------------------------------------- hooks for app.js
  /// After every verified refresh: the tab is there only while proven state holds a validator
  /// candidate of this account that is not archived. The status is read with proofs when the tab
  /// appears and again whenever the account's action number has moved since it was read: an
  /// action of the account is in a block then, and it may be a signal this wallet did not send.
  function render(account, state) {
    const candidate = state?.candidates?.[String(account.id)];
    owns = Boolean(candidate) && candidate.archived !== true && String(candidate.owner) === String(account.id);
    $('tab-upgrade').hidden = !owns;
    if (!owns) { $('panel-upgrade').hidden = true; shownFor = null; shownNonce = null; return; }
    $('signal-payment-wrap').hidden = !c.secured();
    const moved = shownFor !== String(account.id) || String(account.nonce) !== shownNonce;
    if (moved && !active && Date.now() >= retryAt) loadQuietly();
  }
  function availability(ready, frozen) {
    for (const id of ['signal-submit', 'signal-withdraw', 'signal-discard']) $(id).disabled = !ready || !owns || Boolean(frozen);
    $('signal-refresh').disabled = !ready || !owns;
  }
  /// When the wallet locks: nothing of one session is left for the next.
  function reset() {
    owns = false; shownFor = null; shownNonce = null; last = null; retryAt = 0; active = false; clearForm(); scrub();
    for (const id of ['signal-status', 'signal-plans', 'signal-validators', 'signal-result']) $(id).replaceChildren();
    for (const id of ['signal-check', 'signal-withdraw-note', 'signal-pending-text']) $(id).textContent = '';
    $('tab-upgrade').hidden = $('panel-upgrade').hidden = $('signal-pending-card').hidden = $('signal-result-card').hidden = $('signal-payment-wrap').hidden = true;
  }
  return { render, availability, reset, load };
}
