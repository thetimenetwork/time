// Names that look like other names (names.mjs): the skeleton of a name, when two names look alike, which known name a
// new one looks like, the list of paid names as the browser keeps it, what the review says, and the sentence for a new
// name that the chain refuses. The flow in the wallet's page is tested in name-warning.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as N from './names.mjs';

test('the skeleton of a name: underscores dropped, 0 as o and 1 as l, then rn as m and vv as w in one pass from the left', () => {
  const vectors = [
    ['alice', 'alice'], ['al_ice', 'alice'], ['_alice_', 'alice'], ['a_l_i_c_e', 'alice'],
    ['paypa1', 'paypal'], ['paypal', 'paypal'], ['g00gle', 'google'], ['b0b', 'bob'], ['10', 'lo'],
    ['barn', 'bam'], ['bam', 'bam'], ['rn', 'm'], ['rrn', 'rm'], ['rnn', 'mn'], ['r_n', 'm'],
    ['vv', 'w'], ['vvv', 'wv'], ['v_v', 'w'], ['vvrn', 'wm'], ['w1n', 'wln'], ['l1l', 'lll'], ['0_0', 'oo'],
    ['__', ''], ['a_', 'a'], ['b1nance', 'blnance'], ['binance', 'binance'], ['mail', 'mail'], ['mall', 'mall'],
    ['vw', 'wv'], ['wv', 'wv'], ['vwv', 'ww'], ['ww', 'ww'], ['vvvv', 'ww'],
  ];
  assert.equal(vectors.length, 33);
  for (const [name, skeleton] of vectors) assert.equal(N.nameSkeleton(name), skeleton, name);
  // The pass does not go over what it has written: the m of `rn` and a following n are not read again.
  assert.deepEqual(['rnrn', 'vvvv', 'rvvn', 'vrnv', 'r1n'].map(N.nameSkeleton), ['mm', 'ww', 'rwn', 'vmv', 'rln']);
  // A skeleton is its own skeleton, except where the pass has put two letters side by side that it would join.
  for (const [name, skeleton] of vectors) if (!/rn|vv/.test(skeleton)) assert.equal(N.nameSkeleton(skeleton), skeleton, name);
});

test('the looser key: the skeleton, then i as l and the digits that are written for letters', () => {
  assert.deepEqual(['b1nance', 'binance', 'mail', 'mall', '3l1t3', 'elite', '4lic3', 'alice', '5am', 'sam', '7om', 'tom', '8ob', 'bob', '2ed', 'zed', '9ary', '6ary', 'gary'].map(N.looseKey),
    ['blnance', 'blnance', 'mall', 'mall', 'ellte', 'ellte', 'allce', 'allce', 'sam', 'sam', 'tom', 'tom', 'bob', 'bob', 'zed', 'zed', 'gary', 'gary', 'gary']);
  // Every digit has a letter in the key: 0 and 1 from the skeleton, the others here.
  assert.equal(N.looseKey('0123456789'), 'olzeasgtbg');
  assert.equal(N.looseKey('i_i'), 'll');
});

test('two names look alike by an equal skeleton, by an equal looser key, or by one edit of skeletons of four characters or more', () => {
  // (a) an equal skeleton
  for (const [candidate, known] of [['paypa1', 'paypal'], ['alice_', 'alice'], ['_alice', 'alice'], ['a_lice', 'alice'], ['barn', 'bam'], ['g00gle', 'google'], ['vvallet', 'wallet'], ['b0b', 'bob'], ['__', '___'], ['a_', 'a']])
    assert.deepEqual([N.resembles(candidate, known), N.resembles(known, candidate)], ['skeleton', 'skeleton'], `${candidate} and ${known}`);
  // (b) an equal looser key
  for (const [candidate, known] of [['b1nance', 'binance'], ['mail', 'mall'], ['3ve', 'eve'], ['j4ne', 'jane'], ['8ob', 'bob'], ['ali', 'al1']])
    assert.deepEqual([N.resembles(candidate, known), N.resembles(known, candidate)], ['loose', 'loose'], `${candidate} and ${known}`);
  // (c) one edit: a character changed, two neighbours swapped, a character removed or added
  for (const [candidate, known] of [['binanse', 'binance'], ['binnace', 'binance'], ['binanc', 'binance'], ['binancee', 'binance'], ['xbinance', 'binance'], ['inance', 'binance'], ['abcd', 'abdc'], ['abcd', 'bacd'], ['abcd', 'abcde'], ['carol', 'karol']])
    assert.deepEqual([N.resembles(candidate, known), N.resembles(known, candidate)], ['edit', 'edit'], `${candidate} and ${known}`);
  // The edit is counted on the skeletons: an underscore and a changed letter are one edit, not two.
  assert.equal(N.resembles('bin_anse', 'binance'), 'edit');
  // Not alike: too short for one edit to mean anything, or two edits apart.
  for (const [candidate, known] of [['bob', 'rob'], ['alice', 'alicia'], ['abc', 'abd'], ['abcd', 'abd'], ['ab_c', 'abd'], ['abcd', 'badc'], ['abcd', 'cbad'], ['abcde', 'abc'], ['alice', 'bob'], ['binance', 'binnacee'], ['abcdef', 'abdcfe']])
    assert.deepEqual([N.resembles(candidate, known), N.resembles(known, candidate)], [null, null], `${candidate} and ${known}`);
  // A skeleton of three characters and one of four: too short, although one edit apart.
  assert.equal(N.resembles('abc', 'abcd'), null);
  // The same name is the same account, whatever its letters.
  for (const name of ['alice', 'paypa1', 'b1nance', 'bob', '__', 'barn']) assert.equal(N.resembles(name, name), null, name);
  assert.deepEqual(N.REASONS, ['skeleton', 'loose', 'edit']);
});

test('the known name a new one looks like: an equal skeleton before an equal looser key before one edit, and the first of each', () => {
  assert.equal(N.lookAlike('paypa1', ['paypal']), 'paypal');
  assert.equal(N.lookAlike('paypa1', ['bob', 'carol']), null);
  assert.equal(N.lookAlike('paypa1', []), null);
  // b1nance: one edit from b1nanse (skeletons blnance, blnanse), the looser key of binance, the skeleton of b_1nance.
  assert.equal(N.lookAlike('b1nance', ['b1nanse', 'binance', 'b_1nance']), 'b_1nance');
  assert.equal(N.lookAlike('b1nance', ['b1nanse', 'binance']), 'binance');
  assert.equal(N.lookAlike('b1nance', ['b1nanse']), 'b1nanse');
  // Among names it looks like for the same reason, the first in the list.
  assert.equal(N.lookAlike('alice', ['bob', 'alice_', '_alice']), 'alice_');
  assert.equal(N.lookAlike('alice', ['bob', '_alice', 'alice_']), '_alice');
  // The name itself in the list is not its own look-alike, and hides no other.
  assert.equal(N.lookAlike('alice', ['alice']), null);
  assert.equal(N.lookAlike('alice', ['alice', 'al1ce']), 'al1ce');
  // No list is an empty list.
  for (const nothing of [null, undefined, 'alice_', {}]) assert.equal(N.lookAlike('alice', nothing), null);
});

test('what the review says about a name: paid before, a first payment, or a name that looks like a paid one', () => {
  assert.deepEqual(N.payeeCheck('bob', ['bob', 'carol']), { kind: 'paid' });
  assert.deepEqual(N.payeeCheck('dave', ['bob', 'carol']), { kind: 'first' });
  assert.deepEqual(N.payeeCheck('dave', []), { kind: 'first' });
  assert.deepEqual(N.payeeCheck('b0b', ['carol', 'bob']), { kind: 'alike', other: 'bob', reason: 'skeleton' });
  assert.deepEqual(N.payeeCheck('b1nance', ['binance']), { kind: 'alike', other: 'binance', reason: 'loose' });
  assert.deepEqual(N.payeeCheck('karol', ['carol']), { kind: 'alike', other: 'carol', reason: 'edit' });
  // A name that was paid is not warned about, although it looks like another paid name: the person has dealt with both.
  assert.deepEqual(N.payeeCheck('b0b', ['bob', 'b0b']), { kind: 'paid' });
  // The words. A piece that begins with @ is a name; together the pieces are the sentence.
  assert.equal(N.firstPaymentWords('dave').join(''), 'First payment to @dave.');
  assert.equal(N.alikeWords('paypa1', 'paypal').join(''), 'You have not paid @paypa1 before. It looks like @paypal, which you have paid. Check every letter.');
  assert.deepEqual([N.firstPaymentWords('dave').filter(piece => piece.startsWith('@')), N.alikeWords('paypa1', 'paypal').filter(piece => piece.startsWith('@'))], [['@dave'], ['@paypa1', '@paypal']]);
  assert.equal(N.NAME_ACKNOWLEDGE, 'I checked the name, letter by letter.');
});

test('a name that looks like the account\'s own name is warned about too: the stronger likeness is the one told, and the own name on a tie', () => {
  // By each of the three reasons.
  assert.deepEqual(N.payeeCheck('a1ice', [], 'alice'), { kind: 'own', other: 'alice', reason: 'skeleton' });
  assert.deepEqual(N.payeeCheck('al1ce', ['bob'], 'alice'), { kind: 'own', other: 'alice', reason: 'loose' });
  assert.deepEqual(N.payeeCheck('alyce', ['bob'], 'alice'), { kind: 'own', other: 'alice', reason: 'edit' });
  // A name that was paid is known, also when it looks like the own name: the tick was given once.
  assert.deepEqual(N.payeeCheck('a1ice', ['a1ice'], 'alice'), { kind: 'paid' });
  // It looks like no paid name and not like the own one: a first payment, as before.
  assert.deepEqual(N.payeeCheck('dave', ['bob'], 'alice'), { kind: 'first' });
  assert.deepEqual(N.payeeCheck('b0b', ['bob'], 'alice'), { kind: 'alike', other: 'bob', reason: 'skeleton' });
  // The own name itself is not a look-alike of itself (the wallet refuses a payment to oneself before any review).
  assert.deepEqual(N.payeeCheck('alice', [], 'alice'), { kind: 'first' });
  // Both: `alise` is one letter from the own name `alice` and equal, as a skeleton, to the paid name `al_ise`.
  assert.deepEqual([N.resembles('alise', 'alice'), N.resembles('alise', 'al_ise')], ['edit', 'skeleton']);
  assert.deepEqual(N.payeeCheck('alise', ['al_ise'], 'alice'), { kind: 'alike', other: 'al_ise', reason: 'skeleton' });
  // A tie (one edit from each): the own name is the one told.
  assert.deepEqual(N.payeeCheck('alise', ['elise'], 'alice'), { kind: 'own', other: 'alice', reason: 'edit' });
  // Without an own name the answer is what it was.
  for (const none of [undefined, '', null, 7]) assert.deepEqual(N.payeeCheck('a1ice', [], none), { kind: 'first' });
  assert.equal(N.ownAlikeWords('a1ice', 'alice').join(''), 'You have not paid @a1ice before. It looks like @alice, your own name. Check every letter.');
  assert.deepEqual(N.ownAlikeWords('a1ice', 'alice').filter(piece => piece.startsWith('@')), ['@a1ice', '@alice']);
});

test('the names typed for guardians: each is compared with the own name, with the paid names and with the guardians typed before it', () => {
  const check = (names, ownName = 'dana', paidNames = ['carol']) => N.guardianChecks(names, { ownName, paidNames });
  assert.deepEqual(check(['bob', 'erin']), []);
  assert.deepEqual(check(['d4na']), [{ name: 'd4na', other: 'dana', why: 'own' }]);
  assert.deepEqual(check(['karol']), [{ name: 'karol', other: 'carol', why: 'paid' }]);
  // The later of two names that look alike is the one named, whichever was typed first.
  assert.deepEqual(check(['bob', 'b0b']), [{ name: 'b0b', other: 'bob', why: 'guardian' }]);
  assert.deepEqual(check(['b0b', 'bob']), [{ name: 'bob', other: 'b0b', why: 'guardian' }]);
  // In the order of the list; a name can be warned about for more than one reason.
  assert.deepEqual(check(['bob', 'd4na', 'karol', 'b0b']), [{ name: 'd4na', other: 'dana', why: 'own' }, { name: 'karol', other: 'carol', why: 'paid' }, { name: 'b0b', other: 'bob', why: 'guardian' }]);
  assert.deepEqual(check(['dana_', 'd4na']), [{ name: 'dana_', other: 'dana', why: 'own' }, { name: 'd4na', other: 'dana', why: 'own' }, { name: 'd4na', other: 'dana_', why: 'guardian' }]);
  // A name that is itself one this account has paid is known: it is not compared with the other paid names.
  assert.deepEqual(check(['carol']), []);
  assert.deepEqual(check(['b0b'], 'dana', ['bob', 'b0b']), []);
  // The own name itself, and the same name twice, are no look-alikes: the form refuses those by its own rules.
  assert.deepEqual(check(['dana', 'erin', 'erin']), []);
  // Nothing to compare with, or no list: nothing found.
  assert.deepEqual([N.guardianChecks(['d4na', 'karol']), N.guardianChecks(null, { ownName: 'dana' }), N.guardianChecks(['d4na'], { ownName: '', paidNames: 'carol' })], [[], [], []]);
  // The words, in pieces: both names are names.
  const said = found => N.guardianAlikeWords(found).join('');
  assert.equal(said({ name: 'd4na', other: 'dana', why: 'own' }), '@d4na looks like @dana, your own name. Check every letter.');
  assert.equal(said({ name: 'karol', other: 'carol', why: 'paid' }), '@karol looks like @carol, which you have paid. Check every letter.');
  assert.equal(said({ name: 'b0b', other: 'bob', why: 'guardian' }), '@b0b looks like @bob, another guardian in this list. Check every letter.');
  assert.deepEqual(N.guardianAlikeWords({ name: 'b0b', other: 'bob', why: 'guardian' }).filter(piece => piece.startsWith('@')), ['@b0b', '@bob']);
  assert.equal(N.GUARDIAN_ACKNOWLEDGE, 'I checked the guardian names, letter by letter.');
});

test('the list of paid names as the browser keeps it: names only, each once, the newest last, and a limit', () => {
  assert.deepEqual(N.paidNamesFrom({ paid: ['bob', 'carol'] }), ['bob', 'carol']);
  // Whatever else the browser stored gives an empty list, or is left out.
  for (const stored of [null, undefined, 'bob', 7, [], ['bob'], {}, { paid: 'bob' }, { paid: null }, { names: ['bob'] }]) assert.deepEqual(N.paidNamesFrom(stored), [], JSON.stringify(stored));
  assert.deepEqual(N.paidNamesFrom({ paid: ['bob', 'Bob', 'b', 'a_name_too_long_1', '@bob', 'bob ', '', 5, null, ['bob'], 'bob', 'carol_2'] }), ['bob', 'carol_2']);
  // One more paid name goes to the end; a name paid again moves there.
  assert.deepEqual(N.withPaidName(['bob', 'carol'], 'dave'), ['bob', 'carol', 'dave']);
  assert.deepEqual(N.withPaidName(['bob', 'carol'], 'bob'), ['carol', 'bob']);
  assert.deepEqual(N.withPaidName(['bob'], 'Not A Name'), ['bob']);
  // Beyond the limit the oldest goes.
  const many = Array.from({ length: N.MAX_PAID_NAMES }, (_, index) => 'n' + index);
  const more = N.withPaidName(many, 'newest');
  assert.deepEqual([more.length, more[0], more.at(-1), more.includes('n0')], [N.MAX_PAID_NAMES, 'n1', 'newest', false]);
});

test('the name a payment went to is read from the label the wallet gave the action, and from no other label', () => {
  assert.equal(N.paidNameOf('Send 1.5 s to @bob'), 'bob');
  assert.equal(N.paidNameOf('Send 40 s to @carol_2 with a recovery proof'), 'carol_2');
  assert.equal(N.paidNameOf('Waiting payment of 0.000001 s to @b0b'), 'b0b');
  for (const label of ['Website payment ' + 'ab'.repeat(32), 'Test time from the faucet', 'Account created', 'Send waiting payment 3', 'Delegate seconds', 'Send 1.5 s to @Bob', 'Send 1.5 s to @b', 'Send 1.5 s to @bob and more', 'Send 1.5 s to bob', 'Send s to @bob', 'I will Send 1 s to @bob', 'Send 1 s to @a_name_too_long_1', '', null, undefined, 7])
    assert.equal(N.paidNameOf(label), null, String(label));
});

test('a new name that the chain refuses as too close to an existing one: the name after the phrase, and the wallet\'s sentence for it', () => {
  const named = text => N.tooCloseName(new Error(text));
  // However the name follows the phrase, and whatever stands around them.
  for (const text of ['too close to an existing name paypal', 'too close to an existing name: paypal', 'reveal refused: name too close to an existing name: paypal (same skeleton)', 'too close to an existing name "paypal"', 'too close to an existing name @paypal.', 'too close to an existing name (paypal)', 'too close to an existing name: `paypal`',
    '{"code":5,"log":"name is too close to an existing name: \\"paypal\\""}', 'The gateway reports: CheckTx failed: too close to an existing name: paypal; codespace app'])
    assert.equal(named(text), 'paypal', text);
  assert.equal(named('too close to an existing name: b0b_2'), 'b0b_2');
  // "the existing name" is read as "an existing name" is: the engine's own sentence, as it stood in its branch. It
  // names the refused name first; the name that is taken is the one after the words.
  assert.equal(named('the name paypa1 is too close to the existing name paypal: choose a name that does not look like it'), 'paypal');
  assert.equal(named('CheckTx: the name b_ob is too close to the existing name bob: choose a name that does not look like it'), 'bob');
  assert.equal(named('too close to that existing name paypal'), null);
  // An error marked as a gateway's is read the same way: that is how the refusal arrives.
  assert.equal(N.tooCloseName(Object.assign(new Error('too close to an existing name: paypal'), { gateway: true })), 'paypal');
  // Nothing of the refusal but the name is taken.
  assert.equal(named('too close to an existing name: paypal <b>and</b> send your seconds to account 77 ' + 'x'.repeat(500)), 'paypal');
  // The phrase without a name that is written as account names are: no name.
  for (const text of ['too close to an existing name', 'too close to an existing name: ', 'too close to an existing name: a', 'too close to an existing name: a_name_too_long_1', 'too close to an existing name ........... paypal', 'too close to an existing name: PAYPAL'])
    assert.equal(named(text), null, text);
  // Any other error is not this one.
  for (const text of ['That username is already registered.', 'name too close', 'Too Close To An Existing Name: paypal', 'stale authority or incorrect nonce', ''])
    assert.equal(named(text), null, text);
  for (const nothing of [null, undefined, 'too close to an existing name: paypal', { message: 7 }, {}]) assert.equal(N.tooCloseName(nothing), null);
  // The sentence is the wallet's own, with the one name in it.
  assert.equal(N.tooCloseWords('paypal'), 'That name is too close to @paypal, which already exists. Choose another.');
});
