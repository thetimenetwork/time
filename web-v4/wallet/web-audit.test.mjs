// The findings of the web audit of 23 and 24 November 2026 that the wallet's page fixes, each turned from the
// reviewer's proof script into a test that failed before its fix. The finding's id names the test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { failureNotice, foreignWords, FOREIGN_ERROR } from './actions.mjs';
import { formatSeconds } from './guards.mjs';

const PHISH = 'Your Time wallet was locked by the network. Type your recovery words on shop.example to unlock it.';
const said = text => /recovery words|shop\.example|unlock it/i.test(text);

// ------------------------------------------------------------------ W-2
test('W-2: an error that is not the wallet\'s own is told in fixed words; nothing it quotes reaches the notice', async () => {
  // A non-numeric amount from a website (approval-amount.mjs): BigInt quotes it in its SyntaxError.
  let thrown; try { formatSeconds(String(PHISH)); } catch (error) { thrown = error; }
  assert.ok(thrown instanceof SyntaxError && said(thrown.message), 'the engine quotes the text');
  assert.ok(!said(failureNotice(thrown)));
  assert.equal(failureNotice(thrown), 'An answer could not be read, so nothing was done with it. (SyntaxError)');
  // A gateway's body that is not JSON (verifier-words.mjs, part 2): JSON.parse quotes its start.
  for (const body of [PHISH, 'Unfreeze: visit time-help.example', '<b>Session expired. Re-enter your recovery words below</b>']) {
    let error; try { JSON.parse(body); } catch (caught) { error = caught; }
    assert.ok(!/visit|Re-enter|recovery|Unfreeze|Session/.test(failureNotice(error)), failureNotice(error));
  }
  // Other kinds of error, by name only; a kind the wallet does not know gets no name.
  assert.equal(failureNotice(new TypeError(PHISH)), 'The network could not be reached, or an answer could not be used. Check your connection and try again. (TypeError)');
  assert.equal(failureNotice(new RangeError(PHISH)), 'A number in an answer is out of range, so nothing was done with it. (RangeError)');
  assert.equal(failureNotice(Object.assign(new Error(PHISH), { name: 'AbortError' })), PHISH, 'a plain Error is the wallet\'s or the SDK\'s own: its name is not looked at');
  class Odd extends Error { constructor(m) { super(m); this.name = PHISH; } }
  assert.equal(failureNotice(new Odd(PHISH)), FOREIGN_ERROR);
  assert.equal(foreignWords({ name: 'TimeoutError' }), 'No answer came in time. Try again. (TimeoutError)');
  // The wallet's own sentences, and the SDK's, as before.
  assert.equal(failureNotice(new Error('Enter your payment password.')), 'Enter your payment password.');
  assert.equal(failureNotice({ message: PHISH }), 'Action failed.', 'an object that is not an Error is not shown');
  assert.equal(failureNotice(PHISH, 'Could not open wallet.'), 'Could not open wallet.');
});

test('W-2: a refusal of the verifier, as the wallet imports it, reaches the notice as a code and fixed words', async () => {
  const verifier = await import('../../client-v4/proof-verifier.mjs');
  const dynamic = JSON.parse(await readFile(new URL('../../verifier-v4/fixtures/dynamic.json', import.meta.url), 'utf8'));
  const phish = 'Your account was frozen by the network. To unfreeze it type your five recovery words at https://time-unfreeze.example now';
  const variants = [
    b => { b.validators[0].pub_key.type = phish; },
    b => { b.signed_header.commit.signatures[0].block_id_flag = phish; },
    b => { b.signed_header = phish; },
  ];
  for (const edit of variants) {
    const block = structuredClone(dynamic.blocks[0]); edit(block);
    await assert.rejects(verifier.verifyLightUpdate(block, dynamic.trust, dynamic.now_ms), error => {
      const notice = failureNotice(error);
      assert.ok(!/unfreeze|recovery words|https/i.test(notice), notice);
      assert.match(notice, /^INVALID_(JSON|LIGHT_BLOCK): /);
      assert.match(error.detail, /unfreeze/, 'the verifier\'s text is kept for logs and tests');
      return true;
    });
  }
});

// ------------------------------------------------------------------ W-1
test('W-1: the approval window takes a website\'s request only in its forms; anything else is one fixed sentence', async () => {
  const { acceptApprovalEvent, APPROVAL_NOT_UNDERSTOOD } = await import('./guards.mjs');
  const opener = {}, origin = 'https://shop.example', net = 'ab'.repeat(32), orderId = 'cd'.repeat(32);
  const event = request => ({ source: opener, origin, data: { type: 'time:request', version: 1, id: 'abcdefgh1234', request } });
  const pay = { type: 'payment', networkId: net, to: '7', amount: '1', orderId };
  // approval-text.mjs: a recipient that is a sentence. approval-amount.mjs: an amount that is one.
  const to = '7 (Time Support). SECURITY CHECK REQUIRED: this website must confirm your recovery words before you can pay.';
  for (const request of [{ ...pay, to }, { ...pay, amount: PHISH }, { ...pay, amount: '0' }, { ...pay, amount: '1.5' }, { ...pay, to: '07' }, { ...pay, to: '18446744073709551616' },
    { ...pay, networkId: net.toUpperCase() }, { ...pay, orderId: 'x' }, { ...pay, extra: 1 }, { ...pay, description: 'x'.repeat(201) }, { ...pay, fee: '-1' }, { ...pay, expiresAt: '1' },
    { type: 'payment' }, { type: 'grant' }, { type: 'login', challenge: { origin } }, { type: 'login', challenge: { purpose: 'login', origin, networkId: net, nonce: orderId, issuedAt: 1, expiresAt: 2, note: to } },
    { type: 'login', challenge: { purpose: 'login', origin: 'https://other.example', networkId: net, nonce: orderId, issuedAt: 1, expiresAt: 2 } }, null, 'payment']) {
    assert.throws(() => acceptApprovalEvent(event(request), opener), error => error.message === APPROVAL_NOT_UNDERSTOOD, JSON.stringify(request)?.slice(0, 60));
  }
  assert.throws(() => acceptApprovalEvent({ ...event(pay), data: { ...event(pay).data, extra: to } }, opener), error => error.message === APPROVAL_NOT_UNDERSTOOD);
  // The forms: the SDK's payment, the demo blog's (with its fee, description and expiry, never shown), and a login.
  assert.equal(acceptApprovalEvent(event(pay), opener).request.to, '7');
  assert.equal(acceptApprovalEvent(event({ ...pay, fee: '1000', description: 'Support the Time blog (demo)', expiresAt: 1795000000000 }), opener).request.amount, '1');
  assert.equal(acceptApprovalEvent(event({ type: 'login', challenge: { purpose: 'login', origin, networkId: net, nonce: orderId, issuedAt: 1, expiresAt: 2 } }), opener).request.type, 'login');
});

// ------------------------------------------------------------------ K-1
// With "words only" both recovery keys come from the words. Whoever takes the only copy can ask for new keys, the account
// freezes, and cancelling that is an operation of two recovery keys (v5/src/security.rs, ROOT): the payment key is one
// vote. What stops it is "New recovery words", the payment key with one recovery key, which the engine installs at once
// (`install` clears the waiting replacement and the freeze). The page said "you can cancel it", true only for an owner who
// still has the words.
test('K-1: every place says that only the recovery words stop a takeover, and the step asks for two copies', async () => {
  const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  const after = 'On paper only: not in a photo, a note or a message. Nobody can show them to you again.';
  const copies = 'Write them twice and keep the two papers in different places. If one is lost, the other brings your account back. If one is taken, the other lets you stop whoever took it. The fridge door does not count.';
  const only = 'Anyone who has these words can ask to take over your account. That waits your waiting period. You can stop it only with these words, so a paper that is your only copy must never be lost or taken.';
  for (const prefix of ['signup', 'secure', 'rr']) {
    const from = page.indexOf(`id="${prefix}-phrase-shown"`), step = page.slice(from, page.indexOf('</div>', from));
    const at = [after, `<p id="${prefix}-tip">${copies}</p>`, only].map(text => step.indexOf(text));
    assert.ok(at.every(i => i > 0) && at[0] < at[1] && at[1] < at[2], `${prefix}: ${JSON.stringify(at)}`);
  }
  assert.equal(page.split('I wrote them down. Create my account').length - 1, 1, 'the button stays as it was');
  // Nowhere does the wallet say that the owner "can cancel" what the recovery words ask for.
  const sources = await Promise.all(['index.html', 'security-ui.mjs', 'alerts.mjs', 'actions.mjs', 'papers.mjs'].map(name => readFile(new URL(`./${name}`, import.meta.url), 'utf8')));
  for (const text of sources) {
    for (const wrong of ['Anyone who has this paper can ask to take over your account. That waits your waiting period, and you can cancel it', 'that waits your waiting period, and you can cancel it', 'that waits, frozen, and you can cancel it', 'frozen, and you can cancel it on Home', 'or at least cancel it', 'Extra careful?']) assert.ok(!text.includes(wrong), wrong);
  }
});

test('K-1: the alert of a replacement that waits leads to the one operation that ends it, then to cancelling, then says what is left', async () => {
  await import('../../client-v4/time-sdk.js');
  const { alertsOf } = await import('./alerts.mjs');
  const key = n => n.toString(16).padStart(2, '0').repeat(32), DAY = 86400000000n, NOW = 10n * DAY;
  const devices = [{ public_key: key(1), can_manage: false, can_spend: false }, { public_key: key(2), can_manage: false, can_spend: true }, { public_key: key(3), can_manage: true, can_spend: false }, { public_key: key(4), can_manage: true, can_spend: false }];
  const security = { account: '7', version: '3', freezes: '0', next_id: '1', frozen_until_elapsed_micros: '0', allowance_micros: '0', allowance_elapsed_micros: '0', policy: { daily_limit_micros: '600000000', delay_seconds: '86400', freeze_seconds: '172800', threshold: '2' }, pending_payments: [], pending_limit: null, pending_root: { devices, policy: { daily_limit_micros: '600000000', delay_seconds: '86400', freeze_seconds: '172800', threshold: '2' }, ready_elapsed_micros: String(NOW + DAY), expires_elapsed_micros: String(NOW + 2n * DAY) } };
  const state = { time_micros: String(NOW), genesis: { genesis_time_micros: '0' }, accounts: [{ id: '7', name: 'alice', balance: '1', nonce: '4', auth_epoch: '2', devices }], security: [security] };
  const { alerts } = alertsOf({ sdk: globalThis.TimeSDK, state, account: '7', formatDate: date => date.toISOString() });
  const text = alerts.find(a => a.title === 'Your keys are being replaced').text;
  const make = text.indexOf('make new recovery words now, under Keys, “Change something”: it needs your payment password and your recovery words, it ends this change at once, and the words that were used stop working.');
  const cancel = text.indexOf('Cancelling it'), left = text.indexOf('Without your recovery words you cannot stop this.');
  assert.ok(make > 0 && make < cancel && cancel < left, text);
});

test('K-1: Keys offers a Recovery Kit in one quiet line, only for a recovery that is one paper on an account that holds more than an hour', async () => {
  const { keysView, KIT_HINT } = await import('./actions.mjs');
  const card = (recoveryKind, balanceMicros) => keysView({ protectedAccount: true, name: 'alice', limit: '600 seconds', waiting: '48 hours', recoveryKind, balanceMicros }).cards.find(c => c.id === 'phrase');
  assert.deepEqual(card('words', '3600000001').hint, KIT_HINT);
  assert.deepEqual(KIT_HINT, { text: 'Your recovery is one paper.', link: 'Add a Recovery Kit so that a paper alone is not enough.' });
  for (const [kind, balance] of [['words', '3600000000'], ['words', '0'], ['kit', '9000000000'], [null, '9000000000'], ['words', 'not a number']]) assert.equal(card(kind, balance).hint, undefined, `${kind} ${balance}`);
  const words = keysView({ protectedAccount: true, name: 'alice', recoveryKind: 'words', waiting: '48 hours' });
  assert.match(words.note, /only these words can stop it: keep two copies in different places\./);
  assert.match(Object.fromEntries(words.cards.find(c => c.id === 'phrase').rows)['If someone may have seen them'], /only these words can stop it\.$/);
});

// ------------------------------------------------------------------ W-4 and F-3
test('W-4: two names this browser has paid that look alike are said in the review, with the tick, instead of "paid"', async () => {
  const { paidNamesFrom, payeeCheck, paidAlikeWords } = await import('./names.mjs');
  // paid-names.mjs: one localStorage.setItem by whoever can write the origin's storage plants a look-alike as "paid".
  const honest = paidNamesFrom({ paid: ['binance', 'bob'] }), planted = paidNamesFrom(JSON.parse('{"paid":["binance","bob","b1nance"]}'));
  assert.deepEqual(payeeCheck('b1nance', honest, 'me_here'), { kind: 'alike', other: 'binance', reason: 'loose' });
  assert.deepEqual(payeeCheck('b1nance', planted, 'me_here'), { kind: 'paid-alike', other: 'binance' });
  assert.deepEqual(payeeCheck('binance', planted, 'me_here'), { kind: 'paid-alike', other: 'b1nance' });
  assert.deepEqual(payeeCheck('bob', planted, 'me_here'), { kind: 'paid' });
  assert.equal(paidAlikeWords('b1nance', 'binance').join(''), 'You have paid @b1nance before, and also @binance, which looks like it. One of them may not be who you think. Check every letter.');
  // The page asks for the tick for it, as for every other likeness (app.js, payeeLines).
  const app = await readFile(new URL('./app.js', import.meta.url), 'utf8');
  assert.ok(app.includes("if (check.kind === 'paid-alike') return { lines: [nameLine(paidAlikeWords(name, check.other), true)], acknowledge: NAME_ACKNOWLEDGE };"));
});

test('F-3: the wallet reads cl as d and nn as m: aclmin, leclger and annazon look like admin, ledger and amazon', async () => {
  await import('../../client-v4/time-sdk.js');
  const { resembles, looseKey, payeeCheck } = await import('./names.mjs');
  for (const [known, alike] of [['admin', 'aclmin'], ['ledger', 'leclger'], ['amazon', 'annazon'], ['donate', 'clonate'], ['admin', 'ac1min']]) {
    assert.equal(resembles(alike, known), 'loose', `${alike} looks like ${known}`);
    assert.equal(looseKey(alike), looseKey(known));
    assert.equal(payeeCheck(alike, [known]).kind, 'alike');
  }
  // The chain's rule is unchanged until the next reset (a genesis setting): its skeleton still tells them apart.
  assert.notEqual(globalThis.TimeSDK.nameSkeleton('aclmin'), globalThis.TimeSDK.nameSkeleton('admin'));
  // Names that only share letters stay apart.
  for (const [a, b] of [['clay', 'day'], ['anna', 'ama'], ['click', 'dick']]) assert.ok(resembles(a, b) !== null || looseKey(a) !== looseKey(b), `${a} ${b}`);
});

// ------------------------------------------------------------------ K-6
// A vault is Argon2id of 64 MiB and three passes: about 1,650 guesses a second on one graphics card. A guessing program
// tries repeats, keyboard runs, letters or digits in order and common words with digits first (keys\passwords.mjs).
test('K-6: the easy passwords of the reviewer\'s list are refused when a password is chosen, and ordinary passphrases pass', async () => {
  const { checkPassword, openVault } = await import('./vault.mjs');
  const easy = ['passwordpassword1', 'Password!Password', 'qwertyuiopasdfghj', 'abcdeabcdeabcde', '123451234512345', 'iloveyouiloveyou1', 'Summer2024Summer!', 'aaaaabbbbbcdefg', 'mynameisalice123', 'alicealice12345',
    'letmeinletmein1234', '1q2w3e4r5t6y7u8i', 'password1234567890', 'Password12345678', 'qwerty123456789!!',
    // and their kin: a reversed keyboard row, a column walk, a run down, a run repeated, a common word between signs
    'jhgfdsapoiuytrewq', 'qazwsxedcrfvtgby', '987654321987654', 'zyxwvutsrqponml', '!!!welcome2024!!!', 'dragonmonkey1234'];
  for (const password of easy) assert.throws(() => checkPassword(password, 'alice'), /too easy to guess/, password);
  // What each says: what makes it easy, and what to do.
  assert.throws(() => checkPassword('passwordpassword1', 'alice'), { message: 'This password is too easy to guess: it repeats the same part. Choose four or five unrelated words.' });
  assert.throws(() => checkPassword('Summer2024Summer!', 'alice'), { message: 'This password is too easy to guess: it has the same word twice. Choose four or five unrelated words.' });
  assert.throws(() => checkPassword('qwertyuiopasdfghj', 'alice'), { message: 'This password is too easy to guess: it follows the keys of a keyboard. Choose four or five unrelated words.' });
  assert.throws(() => checkPassword('aaaaabbbbbcdefg', 'alice'), { message: 'This password is too easy to guess: it is letters or digits in order. Choose four or five unrelated words.' });
  assert.throws(() => checkPassword('mynameisalice123', 'alice'), { message: 'This password is too easy to guess: it is a common word with digits or signs. Choose four or five unrelated words.' });
  const good = ['violet anchor gravel minute', 'copper lantern whisper meadow', 'seven quiet otters juggle', 'marble tundra pickle orbit', 'rusty kettle sings at dawn', 'blue fox under a tin roof',
    'paper boats drift north', 'wild thyme and cold tea', 'my aunt grows red cactus', 'eleven frogs sang jazz', 'lemon bridge velvet storm', 'glass owl reads slowly', 'hidden canyon brass drum',
    'oak leaf ninja pancake', 'train ticket mango river', 'silent harbor fizzy socks', 'purple tractor dances twice', 'cocoa planet zipper fern', 'garden of loud bees hums', 'quiet thunder salt lamp',
    'Kaffee mit Milch am Fluss', 'élan vital du matin calme', 'correct horse battery staple 41', 'quiet harbour lanterns at dawn 77'];
  for (const password of good) assert.equal(checkPassword(password, 'alice'), true, password);
  // A vault that exists opens as before: opening reads no rule of a chosen password.
  assert.ok(!String(openVault).includes('checkPassword'));
});

test('K-6: a payment password close to the login password is refused; one already in use is not held to the new rules', async () => {
  const { checkPasswords, closePasswords } = await import('./security-flows.mjs');
  assert.throws(() => checkPasswords({ login: 'MyLoginPassword1', payment: 'MyLoginPassword2', name: 'alice' }), /too close to your login password/);
  assert.throws(() => checkPasswords({ login: 'violet anchor gravel minute', payment: 'violet anchor gravel minutes', name: 'alice' }), { message: 'Your payment password is too close to your login password: whoever learns one could guess the other. Choose four or five other words for it.' });
  assert.throws(() => checkPasswords({ login: 'violet anchor gravel minute', payment: 'violet anchor gravel minut', name: 'alice' }), /too close/);
  assert.equal(checkPasswords({ login: 'violet anchor gravel minute', payment: 'copper lantern whisper meadow', name: 'alice' }), true);
  for (const [a, b, close] of [['abcdefghij klmno', 'abcdefghij klmnp', true], ['seven quiet otters juggle', 'Seven Quiet Otters Juggles!!', true], ['seven quiet otters juggle', 'marble tundra pickle orbit', false], ['oak leaf ninja pancake', 'oak leaf ninja waffles', false]]) assert.equal(closePasswords(a, b), close, `${a} / ${b}`);
  // "Replace my login": the payment password is the current one. It is not held to the rules of a new password (it was
  // chosen under the old ones), but the new login password must not be close to it.
  assert.equal(checkPasswords({ login: 'violet anchor gravel minute', payment: 'passwordpassword1', name: 'alice', current: 'payment' }), true);
  assert.throws(() => checkPasswords({ login: 'passwordpassword1', payment: 'violet anchor gravel minute', name: 'alice', current: 'payment' }), /too easy/);
  assert.throws(() => checkPasswords({ login: 'violet anchor gravel minutes', payment: 'violet anchor gravel minute', name: 'alice', current: 'payment' }), { message: 'Your new login password is too close to your payment password: whoever learns one could guess the other. Choose four or five other words for it.' });
  const ui = await readFile(new URL('./security-ui.mjs', import.meta.url), 'utf8');
  assert.equal(ui.split("checkPasswords({ login, payment: password, name, current: 'payment' });").length - 1, 2, 'both places where the payment password is the current one say so');
});
