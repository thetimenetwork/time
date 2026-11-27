// The wallet and a change of the protocol version (docs/design/upgrade-mechanism.md, section 8):
// the version it shows and decides by is the one of a verified state, a scheduled upgrade is a
// banner read from proven state, and a version this app does not implement is an "update this
// app" screen that no gateway can bring up and that holds this app's own words only.
// Whether a network's nodes answer the upgrade question comes from its pinned trust data, never
// from what a gateway says. The proofs of the two independent reviews are in
// client-v4/upgrade-review.test.mjs and client-v4/upgrade-review2-*.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import '../../client-v4/time-sdk.js';
import { sinceVersion4, upgradeBanner, upgradeProblem, upgradeRequiredScreen, upgradeWhileWaiting, failureNotice, gatewayWords, gatewayNotification, createUpgradeMonitor, pendingIsObsolete } from './actions.mjs';

const sdk = globalThis.TimeSDK;
const state = { protocol_version: '4', time_micros: '1700000600000000', genesis: { genesis_time_micros: '1700000000000000' } };
const plan = { activate_elapsed_micros: '1814400000000', scheduled_elapsed_micros: '0', spec: '5e'.repeat(32), version: '5' };
const REFUSAL = 'UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.';
// What the SDK's `request` throws for a gateway's refusal: its text, marked as the gateway's.
const fromGateway = (text) => Object.assign(new Error(text), { gateway: true });
const timedOut = () => Object.assign(new Error('No verified answer within 15 s'), { timeout: true });

test('the rules of version 4 hold at version 4 and at every later one, by the verified state alone', () => {
  for (const version of ['4', '5', '6', '40', '18446744073709551615']) assert.equal(sinceVersion4({ protocol_version: version }), true, version);
  for (const version of ['3', '2', '0', '04', ' 4', '4.0', '', 4, 5, null, undefined, ['4']]) assert.equal(sinceVersion4({ protocol_version: version }), false, String(version));
  for (const none of [undefined, null, {}, 'state']) assert.equal(sinceVersion4(none), false);
  // A merchant payment whose quote has expired on the chain is obsolete at version 4 and after an
  // upgrade (before this change it was kept as pending for ever at version 5).
  const account = { nonce: '0', auth_epoch: '0' }, pending = { nonce: '1', authEpoch: '0' };
  const action = { kind: 10, payload: { reference: '0000000000000001' + '0000000000000064' + 'ab'.repeat(16) } };
  const at = (version, time) => ({ protocol_version: version, time_micros: time, genesis: { genesis_time_micros: '0' } });
  for (const version of ['4', '5', '9']) {
    assert.equal(pendingIsObsolete(account, pending, action, at(version, '101')), true, version);
    assert.equal(pendingIsObsolete(account, pending, action, at(version, '100')), false, version);
  }
  for (const version of ['3', '2', undefined]) assert.equal(pendingIsObsolete(account, pending, action, at(version, '101')), false, String(version));
});

test('the banner says when a scheduled upgrade starts and whether this app is ready for it', () => {
  // Nothing scheduled: no banner.
  assert.equal(upgradeBanner({ status: { version: '4', scheduled: null, known: true }, state }), null);
  // Scheduled, and this app does not know the version: 21 days after a genesis of 2023-11-14 22:13:20 UTC.
  const unknown = upgradeBanner({ status: { version: '4', scheduled: plan, known: false }, state });
  assert.equal(unknown.urgent, true);
  assert.equal(unknown.text, 'The network is scheduled to move to version 5 of its rules on 2023-12-05 22:13 UTC. This app only knows version 4: from that time on it stops working until it is updated. Your seconds are not affected. Update this app before then, from the place you got it.');
  // Scheduled, and this app knows it.
  const known = upgradeBanner({ status: { version: '4', scheduled: plan, known: true }, state });
  assert.equal(known.urgent, false);
  assert.match(known.text, /^The network is scheduled to move to version 5 of its rules on 2023-12-05 22:13 UTC\. This app is ready for it\./);
  // A start beyond what a calendar holds is still a sentence.
  assert.match(upgradeBanner({ status: { version: '4', scheduled: { ...plan, activate_elapsed_micros: '18446744073709551615' }, known: false }, state }).text, /on a date beyond the calendar\./);
  // "Known" means the version under exactly the scheduled specification: this build implements
  // version 4 only, and no plan can name that.
  assert.equal(sdk.upgradeStatusOf({ protocol_version: '4', upgrade: { plan, signals: [] } }).known, false);
});

const STANDING = (words) => `This app could not check whether an upgrade of the network is scheduled: ${words}. This network does not state that its nodes report upgrades, so they may not be able to. This app keeps asking.`;
// What a node before 0.7.0 answers through a gateway, and what a gateway before this change answers itself.
const OLD_NODE = ['Could not obtain compatible certified V4 state: Pinned state unavailable: unknown field `include_upgrade`, expected one of `names`, `ids`', 'Pinned state unavailable: unknown field "include_upgrade"', 'Invalid proof selection'];
const memoryStorage = () => { const map = new Map(); return { map, getItem: (k) => map.get(k) ?? null, setItem: (k, v) => { map.set(k, v); }, removeItem: (k) => { map.delete(k); } }; };

test('when the plan cannot be read, the wallet says so in its own words and never shows "nothing scheduled"; no text of an error decides anything', () => {
  // Two kinds of failure, told apart by a mark this wallet's own SDK sets. The text is never read.
  assert.equal(upgradeProblem(timedOut()), 'timeout');
  for (const error of [new Error('missing requested proof for 757067726164652f7374617465'), new Error('invalid key/value proof: x'), fromGateway('Gateway HTTP 502'), fromGateway('rate limited'), ...OLD_NODE.map(fromGateway), new Error('unknown field `include_upgrade`'), 'offline', null, undefined]) assert.equal(upgradeProblem(error), 'unverified', String(error?.message ?? error));
  // A gateway cannot choose the wallet's words by choosing its own: whatever it says, with or
  // without the words an older node uses, the wallet shows the same line.
  const shown = new Set([...OLD_NODE, 'Gateway HTTP 502', 'anything at all', ''].map((text) => JSON.stringify(upgradeBanner({ problem: upgradeProblem(fromGateway(text)), state }))));
  assert.equal(shown.size, 1);
  for (const [problem, words] of [['timeout', 'the gateway did not answer in time'], ['unverified', 'the answer could not be verified']]) {
    assert.deepEqual(upgradeBanner({ problem, state }), { text: STANDING(words), urgent: false });
  }
  // The problem wins over an older answer.
  assert.match(upgradeBanner({ problem: 'unverified', status: { version: '4', scheduled: null, known: true }, state }).text, /could not check/);
  // The SDK refuses to read a state that was verified without the entry.
  assert.throws(() => sdk.upgradeStatusOf({ protocol_version: '4' }), /verified without the upgrade entry/);
});

test('a network whose trust data says that its nodes report upgrades: the question is on every read from the first, nothing is probed, learned or stored', () => {
  const storage = memoryStorage();
  const monitor = createUpgradeMonitor({ storage, networkId: 'ab'.repeat(32), declared: true });
  assert.deepEqual([monitor.declared(), monitor.capable(), monitor.learned(), monitor.selection(), monitor.probeDue()], [true, true, false, { include_upgrade: true }, false]);
  // Nothing changes that: not an unlock, not an answer, not a request to forget.
  monitor.unlocked(); assert.equal(monitor.probeDue(), false);
  assert.deepEqual(monitor.fromState({ ...state, upgrade: null }, { version: '4', scheduled: null, known: true }), { banner: null });
  assert.equal(monitor.fromState({ ...state, upgrade: { plan, signals: [] } }, { version: '4', scheduled: plan, known: false }).banner.urgent, true);
  assert.equal(monitor.forget(), false);
  assert.deepEqual([monitor.capable(), monitor.learned(), monitor.selection(), storage.map.size], [true, false, { include_upgrade: true }, 0]);
  // A flag an earlier build stored for this network plays no part.
  storage.setItem('timecurrency.upgrade-entry.v1:' + 'ab'.repeat(32), '1');
  const again = createUpgradeMonitor({ storage, networkId: 'ab'.repeat(32), declared: true });
  assert.deepEqual([again.learned(), again.forget(), storage.map.size], [false, false, 1]);
  // The SDK's reading of the trust data, which the wallet passes on: true, false or absent only.
  assert.deepEqual([sdk.nodesReportUpgrades({ nodes_report_upgrades: true }), sdk.nodesReportUpgrades({ nodes_report_upgrades: false }), sdk.nodesReportUpgrades({}), sdk.nodesReportUpgrades(undefined)], [true, false, false, false]);
  for (const said of ['true', 1, 0, null, {}, []]) assert.throws(() => sdk.nodesReportUpgrades({ nodes_report_upgrades: said }), /trust\.nodes_report_upgrades is true or false/, JSON.stringify(said));
});

test('a network that does not say so: the wallet asks on its own until a node has answered, shows one standing line while that fails, then asks with every read, and can forget', () => {
  const storage = memoryStorage(), memory = storage.map;
  let clock = 1_000_000;
  const monitor = createUpgradeMonitor({ storage, networkId: 'ab'.repeat(32), now: () => clock });
  assert.deepEqual([monitor.declared(), monitor.capable(), monitor.learned(), monitor.selection(), monitor.probeDue()], [false, false, false, {}, true]);
  // A node that does not know the question (a lab on an older engine): the standing, quiet line.
  // It is the same line at every failed probe, whatever the gateway said, and nothing of the
  // gateway's text is in it.
  monitor.probeStarted(); assert.equal(monitor.probeDue(), false);
  const first = monitor.probeFailed(fromGateway(OLD_NODE[0]));
  assert.deepEqual(first, { banner: { text: STANDING('the answer could not be verified'), urgent: false } });
  assert.equal(/include_upgrade|unknown field|Pinned/.test(first.banner.text), false);
  // Asked again every minute, and the line stands for as long as the probe fails.
  clock += 59_000; assert.equal(monitor.probeDue(), false); clock += 1_000; assert.equal(monitor.probeDue(), true);
  for (const text of [OLD_NODE[1], OLD_NODE[2], 'Gateway HTTP 502']) { monitor.probeStarted(); assert.deepEqual(monitor.probeFailed(fromGateway(text)), first); clock += 60_000; }
  // After an unlock it is asked at once.
  monitor.probeStarted(); assert.equal(monitor.probeDue(), false); monitor.unlocked(); assert.equal(monitor.probeDue(), true);
  // No answer in time: the same line with the other reason.
  monitor.probeStarted();
  assert.deepEqual(monitor.probeFailed(timedOut()), { banner: { text: STANDING('the gateway did not answer in time'), urgent: false } });
  assert.equal(memory.size, 0, 'nothing is remembered until a node has answered');
  // A node answers: from now on every read carries the question, also after the page is reopened.
  const shown = monitor.fromState({ ...state, upgrade: { plan, signals: [] } }, { version: '4', scheduled: plan, known: false });
  assert.equal(shown.banner.urgent, true);
  assert.deepEqual([monitor.capable(), monitor.learned(), monitor.selection(), monitor.probeDue()], [true, true, { include_upgrade: true }, false]);
  assert.deepEqual([...memory.keys()], ['timecurrency.upgrade-entry.v1:' + 'ab'.repeat(32)]);
  assert.deepEqual(createUpgradeMonitor({ storage, networkId: 'ab'.repeat(32) }).selection(), { include_upgrade: true });
  assert.deepEqual(createUpgradeMonitor({ storage, networkId: 'cd'.repeat(32) }).selection(), {});
  assert.deepEqual(monitor.fromState({ ...state, upgrade: null }, { version: '4', scheduled: null, known: true }), { banner: null });
  // The way out when the node was replaced by one that does not know the question: forget.
  assert.equal(monitor.forget(), true);
  assert.deepEqual([monitor.capable(), monitor.learned(), monitor.selection(), monitor.probeDue(), memory.size], [false, false, {}, true, 0]);
  assert.equal(monitor.forget(), false);
  assert.deepEqual(createUpgradeMonitor({ storage, networkId: 'ab'.repeat(32) }).selection(), {});
  // Storage that fails does not stop the wallet: the answer is remembered, and forgotten, for the page.
  const broken = createUpgradeMonitor({ storage: { getItem() { throw new Error('denied'); }, setItem() { throw new Error('full'); }, removeItem() { throw new Error('denied'); } }, networkId: 'ab'.repeat(32) });
  broken.fromState({ ...state, upgrade: null }, { version: '4', scheduled: null, known: true });
  assert.equal(broken.capable(), true); assert.equal(broken.forget(), true); assert.equal(broken.capable(), false);
});

test('"update this app" is shown for the refusal of the wallet\'s own verifier and for nothing else, in the app\'s own words', () => {
  // What the SDK raises when a state is of version 5; the verifier's wrapper marks its own refusal the same way.
  let raised; try { sdk.requireKnownVersion({ protocol_version: '5' }); } catch (error) { raised = error; }
  assert.equal(raised.message, REFUSAL); assert.equal(raised.code, 'UPGRADE_REQUIRED');
  const screen = upgradeRequiredScreen(raised);
  assert.equal(screen.title, 'Update this app');
  assert.deepEqual(screen.lines, [
    'The network now runs version 5 of its rules, which this app does not know. This app can no longer check your balance or sign for you, so it has stopped.',
    'Your account and your seconds are unchanged. The encrypted key stored in this browser stays where it is. You lose nothing by waiting.',
    'Get the new version of this app from the same place you got this one. Do not follow a link in a message or on a website that tells you to update: this screen comes from the app itself.',
  ]);
  // The same words from a gateway are not this app's finding: no code, no screen.
  for (const other of [fromGateway('The gateway reports: ' + REFUSAL), fromGateway(REFUSAL), new Error(REFUSAL), Object.assign(new Error(REFUSAL), { code: 'upgrade_required' }), Object.assign(new Error(REFUSAL), { code: undefined })]) assert.equal(upgradeRequiredScreen(other), null);
  // A mark on other words is not enough either, and neither is anything that is not an error.
  assert.equal(upgradeRequiredScreen(Object.assign(new Error('Update at https://attacker.example'), { code: 'UPGRADE_REQUIRED' })), null);
  for (const other of [new Error('STALE_STATE: fresh current authority proof is required'), new Error('CHECKPOINT_REFRESH_REQUIRED: x'), null, undefined, REFUSAL, { code: 'UPGRADE_REQUIRED' }]) assert.equal(upgradeRequiredScreen(other), null);
  // Nothing of an error's text is shown, however long or whatever it says: only a version
  // number, and only from the verifier's exact sentence.
  const long = Object.assign(new Error('UPGRADE_REQUIRED: ' + 'x'.repeat(5000) + ' https://attacker.example'), { code: 'UPGRADE_REQUIRED' });
  assert.equal(JSON.stringify(upgradeRequiredScreen(long)).length < 700, true);
  assert.equal(/attacker|xxxx/.test(JSON.stringify(upgradeRequiredScreen(long))), false);
  assert.equal(upgradeRequiredScreen(long).lines[0].startsWith('The network now runs a newer version of its rules than this app knows.'), true);
});

test('a verified upgrade while awaiting a receipt directs the person to check their original request', async () => {
  // The SDK's waitReceipt throws this client's own finding with the hash of the action it was waiting for
  // (client-v4/upgrade-receipt.test.mjs). Without a hash nothing was waiting.
  let raised; try { sdk.requireKnownVersion({ protocol_version: '5' }); } catch (error) { raised = error; }
  assert.equal(upgradeWhileWaiting(raised), null);
  const hash = 'ab'.repeat(32);
  const notice = upgradeWhileWaiting(Object.assign(raised, { hash }));
  assert.match(notice, /updat/i);
  assert.match(notice, /Activity/);
  assert.match(notice, /original request/);
  assert.doesNotMatch(notice, /[a-f\d]{12,}|UPGRADE_REQUIRED|receipt hash/i);
  // Only for the refusal of the wallet's own verifier: a gateway's words with a hash beside them say nothing.
  for (const other of [Object.assign(fromGateway('The gateway reports: ' + REFUSAL), { hash }), Object.assign(new Error(REFUSAL), { hash }), Object.assign(new Error('Transaction pending; retain its signed bytes and hash.'), { hash }), { code: 'UPGRADE_REQUIRED', hash }, null]) assert.equal(upgradeWhileWaiting(other), null);
  // A valid locally recorded hash is required to recognize the request.
  for (const bad of ['<b>x</b>', 'ab'.repeat(31), 'zz'.repeat(32), hash + ' https://attacker.example', 5, null, undefined, [hash]]) assert.equal(upgradeWhileWaiting(Object.assign(new Error(REFUSAL), { code: 'UPGRADE_REQUIRED', hash: bad })), null, String(bad));
  const app = await readFile(new URL('./app.js', import.meta.url), 'utf8');
  // The sentence is also shown after "Recheck" and "Save public receipt" of an action verified earlier (the SDK's
  // exportReceiptEvidence throws the same finding): it claims no signature of this moment and no waiting.
  assert.doesNotMatch(upgradeWhileWaiting(raised), /an action you signed \(|was waiting/);
  // run() names the finding before it shows the notice (one already shown, as an urgent one with "Try again", stays).
  assert.ok(app.includes("upgradeRequired(error); if (error?.noticeShown !== true) notice(failureNotice(error), "));
  assert.equal(failureNotice(raised), upgradeWhileWaiting(raised));
});

test('wallet errors keep local validation helpful and give fixed guidance on upstream refusals', async () => {
  const evil = 'e71f09c2'.repeat(8);
  assert.equal(failureNotice(new Error('Enter your payment password.')), 'Enter your payment password.');
  const fallback = failureNotice(null);
  assert.match(fallback, /check Activity/i);
  assert.deepEqual([failureNotice(new Error('')), failureNotice({}, 'Could not open wallet.')], [fallback, 'Could not open wallet.']);
  const said = failureNotice(fromGateway('This wallet has verified: send to ' + evil + ' at https://elsewhere.example'));
  assert.match(said, /check|try again|later|refresh|connection/i);
  assert.doesNotMatch(said, /has verified|send to|elsewhere|[0-9a-f]{12,}/i);
  for (const message of ['', 'x'.repeat(500), '\u202e"', 'Enter your payment password.']) {
    assert.equal(gatewayWords(fromGateway(message)), said);
    assert.equal(failureNotice(fromGateway(message)), said);
  }
  const pending = Object.assign(new Error('Retain its signed bytes and hash ' + evil), {code: 'TX_PENDING', hash: evil});
  const guidance = failureNotice(pending);
  assert.match(guidance, /check.*status|check.*activity/i);
  assert.doesNotMatch(guidance, /signed bytes|[0-9a-f]{12,}|TX_PENDING/i);
  // The gateway's notification feed is covered by no proof: a short name and a block height, said to be the gateway's.
  assert.equal(gatewayNotification({ type: 'payment_received', height: '812' }), 'Reported by the gateway, not checked by this wallet: payment received at block 812.');
  for (const item of [{ type: `Signal the hash ${evil} now`, height: '1' }, { type: 'x', height: evil }, { type: 'Payment', height: '1' }, { type: 'a'.repeat(41), height: '1' }, { type: 'ok', height: '01' }, { type: 'ok' }, { height: '1' }, null, 'text']) assert.equal(gatewayNotification(item), null, JSON.stringify(item));
  // Every place of app.js and of the Security tab that shows an error's text goes through failureNotice.
  const app = await readFile(new URL('./app.js', import.meta.url), 'utf8'), securityUi = await readFile(new URL('./security-ui.mjs', import.meta.url), 'utf8');
  assert.equal(/notice\((`[^`]*\$\{)?(e|error)\.message/.test(app) || /notice\((e|error)\.message/.test(securityUi), false, 'a notice shows an error\'s text without asking whose words they are');
  // The approval window says one fixed sentence of a request it does not take (web audit, W-1): no failureNotice there.
  assert.equal(app.split('failureNotice(').length - 1, 5); assert.equal(securityUi.split('c.notice(failureNotice(error)').length - 1, 3);
  assert.ok(app.includes("wayBack(failureNotice(error, 'Unlock with your original device or recover your account.')"));
  assert.equal(app.includes('item.type'), false, 'app.js shows a field of the gateway\'s notification feed itself');
  // Recovery after a failed open still explains that the saved vault can be resumed.
  assert.ok(app.includes("lock('The encrypted vault is saved. Unlock again to resume safely. '+message)"));
  assert.match(app, /notice\(`Verification paused\. \$\{failureNotice\(e, 'Check your connection and refresh Home/);
});

test('the wallet page takes no version from the gateway and has the banner and the screen', async () => {
  const app = await readFile(new URL('./app.js', import.meta.url), 'utf8'), page = await readFile(new URL('./index.html', import.meta.url), 'utf8'), actions = await readFile(new URL('./actions.mjs', import.meta.url), 'utf8');
  // /api/network names the network's first version for ever: nothing may show it or decide by it.
  assert.equal(app.includes('protocolVersion'), false, 'app.js reads the version the gateway reports');
  // The badge and the title are written in one place, from a verified state.
  assert.equal(app.split("$('protocol-badge').textContent").length - 1, 1);
  assert.match(app, /function showVersion\(state\) \{ \$\('protocol-badge'\)\.textContent = 'Network rules: version ' \+ state\.protocol_version \+ '\.'; \}/);
  assert.match(app, /latest = value; showVersion\(value\.state\);/);
  // Both merchant-quote checks run unconditionally on the verified state.
  // (The first is in signing.mjs, which holds the wallet's `sendSigned` since the review of the Validator signal tab.)
  assert.match(await readFile(new URL('./signing.mjs', import.meta.url), 'utf8'), /\n      if\(kind==='merchant_payment'\)sdk\.checkMerchantQuote\(payload\.reference,args\.nonce,state\);/);
  assert.match(app, /\n    sdk\.checkMerchantQuote\(r\.orderId,\(BigInt\(account\.nonce\)\+1n\)\.toString\(\),state\);/);
  // The upgrade question: whether it is carried from the first read comes from the client's
  // pinned trust data; otherwise a probe with a time limit, then on every read; a failed probe is shown.
  assert.match(app, /upgrades = createUpgradeMonitor\(\{ storage: localStorage, networkId: network\.networkId, declared: client\.nodesReportUpgrades === true \}\);/);
  assert.match(app, /client\.getVerifiedState\(\{ include_upgrade: true \}, \{ timeoutMs: 15000 \}\)/);
  assert.match(app, /\.\.\.\(upgrades\?\.selection\(\) \|\| \{\}\) \}\);/);
  assert.match(app, /showUpgrade\(upgrades\.probeFailed\(error\)\)/);
  assert.match(app, /await openPrivate\(unlocked\.storageKey\); session\.storageKey = null; check\(\); upgrades\?\.unlocked\(\);/);
  // Nothing in the wallet reads the text of an error to decide about upgrades: the words an older
  // node or gateway uses for the unknown question appear nowhere in its code.
  for (const [name, source] of [['app.js', app], ['actions.mjs', actions]]) {
    assert.equal(/unknown field|Invalid proof selection|unsupported/.test(source), false, name + ' matches a gateway\'s error text');
    assert.equal(/include_upgrade[^\n]*\.(?:test|includes|match|startsWith)\(/.test(source), false, name);
  }
  assert.equal(/error\??\.message[^\n]*(?:upgrade|Upgrade)|(?:upgradeProblem|probeFailed)[^\n]*\.message/.test(actions), false);
  // The control to forget a learned answer: with the network's trust details, shown only while there is one.
  assert.equal(page.split('id="upgrade-forget"').length - 1, 1);
  assert.match(page, /<summary>Offline trust and checkpoint refresh<\/summary>[\s\S]*<p id="upgrade-forget-row" hidden>[\s\S]*<button type="button" id="upgrade-forget" class="secondary">Forget the answer about upgrades<\/button><\/p>[\s\S]*?<\/details>/);
  assert.match(app, /\$\('upgrade-forget-row'\)\.hidden = !upgrades\?\.learned\(\);/);
  assert.match(app, /\$\('upgrade-forget'\)\.addEventListener\('click',\(\)=>run\(async\(\)=>\{\s*if\(!upgrades\?\.forget\(\)\)/);
  // The banner shows the monitor's words; no error text is written into it.
  assert.match(app, /\$\('upgrade-banner'\)\.textContent = banner\?\.text \|\| '';/);
  assert.equal(/upgrade-banner'\)\.textContent = [^;]*(?:error|message)/.test(app), false);
  for (const id of ['upgrade-banner', 'upgrade-required', 'upgrade-required-title', 'upgrade-required-text']) assert.equal(page.split(`id="${id}"`).length - 1, 1, id);
  // Every place that reports a failed verified read also offers the update screen.
  assert.ok(app.split('upgradeRequired(e').length - 1 >= 5, 'start, unlock, the refresh timer, actions and the banner');
});
