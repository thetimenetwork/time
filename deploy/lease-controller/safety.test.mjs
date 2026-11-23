// The safety property of the signer-lease controller under random schedules
// (docs/design/signer-lease-controller.md, section 4 and section 15). simulation.mjs is the
// simulated world. After every step it checks claim S1 (no two hosts with a live lease for one
// key, and the distance of the stop time between them), claim S2 (fence tokens), and that a key
// is frozen only for a cause the design names.
// The last tests break one rule each and require the same schedules to notice.
import test from 'node:test';
import assert from 'node:assert/strict';
import { simulate } from './simulation.mjs';

const sum = (list, field) => list.reduce((total, item) => total + item[field], 0);
const FAILURES = /(host .* got a live lease|hosts .* both hold|a fence token went down|a lease for another host does not carry a higher fence token|a key was frozen without a cause|a recorded request froze a key)/;

test('no two hosts ever hold live leases for one key, tokens only rise, and a key is frozen only for a named cause, under 40 random schedules', async (context) => {
  const all = [];
  for (let seed = 1; seed <= 40; seed++) all.push(await simulate(seed, 2500));
  // The schedules must have exercised what the claims are about.
  const total = Object.fromEntries(Object.keys(all[0]).filter((field) => typeof all[0][field] === 'number' && field !== 'steps').map((field) => [field, sum(all, field)]));
  const refused = {}; for (const stats of all) for (const [code, count] of Object.entries(stats.refused)) refused[code] = (refused[code] ?? 0) + count;
  context.diagnostic('what the schedules did: ' + JSON.stringify({ ...total, refused }));
  // holderChanges: a lease for a key was installed on another host than the lease before it.
  assert.ok(total.installed > 3000 && total.holderChanges > 200, JSON.stringify(total));
  assert.ok(total.restores > 300 && total.wipes > 40 && total.commandsBeforeStart > 100 && total.starts > 800 && total.settingsChanges > 100, JSON.stringify(total));
  assert.ok(total.crashesBeforeWrite > 80 && total.crashesAfterWrite > 80 && total.writeErrors > 80 && total.kills > 150, JSON.stringify(total));
  assert.ok(total.secondProcesses > 30 && total.replacedUnderService > 30 && total.fatal > 20 && total.frozenAfterRestore > 5, JSON.stringify(total));
  assert.ok(total.frozenAfterHostLoss > 5 && total.replays > 3000 && total.lateAnswers > 500 && total.releaseSwitches > 50, JSON.stringify(total));
  for (const code of ['WAIT', 'NOT_HOLDER', 'KEY_NOT_ASSIGNED', 'CLOCK', 'FROZEN', 'TOO_SOON', 'RELEASE_NOT_APPROVED', 'RELEASE_ROLLBACK']) assert.ok(refused[code] > 20, code + ' ' + JSON.stringify(refused));
});

test('the same schedules notice a controller that does not wait before the first lease of a tenure', async () => {
  await assert.rejects((async () => { for (let seed = 1; seed <= 30; seed++) await simulate(seed, 2500, 'no-wait'); })(), (error) => /sabotage no-wait/.test(error.message) && FAILURES.test(error.message));
});

test('the same schedules notice a controller that trusts a restored state instead of applying the start rule', async () => {
  await assert.rejects((async () => { for (let seed = 1; seed <= 30; seed++) await simulate(seed, 2500, 'no-start-rule'); })(), (error) => /sabotage no-start-rule/.test(error.message) && FAILURES.test(error.message));
});

test('the same schedules notice a lease that leaves before the state is written', async () => {
  await assert.rejects((async () => { for (let seed = 1; seed <= 60; seed++) await simulate(seed, 2500, 'send-before-write'); })(), (error) => /sabotage send-before-write/.test(error.message) && FAILURES.test(error.message));
});
