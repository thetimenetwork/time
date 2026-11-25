// One bad answer must not cost the honest ones after it (AUDIT-2026-11.md, "Found by fuzzing").
//
// A commit signature that was not base64 made the compiled verifier panic. In WebAssembly a
// panic is a trap, and an instance that had trapped about a hundred times failed on every
// answer. proof-verifier.mjs now refuses such texts before the compiled verifier reads them,
// and throws an instance away after any trap.
//
// These tests pass with the compiled verifier that is committed, whether it is the build from
// before the fix of the Rust source or a build after it. The one test that needs a build after
// it says so when it is skipped; TIME_VERIFIER_REBUILT=1 makes it required.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as wrapper from './proof-verifier.mjs';

// The module exports its five functions and no other (see the note at its end); what these tests
// need beside them is kept under this name.
const { verifyTrust, verifyViewProof } = wrapper;
const { createVerifier, refusal, base64StopsTheDecoder, dateStopsTheReader, BASE64_REFUSAL, DATE_REFUSAL } = verifyTrust[Symbol.for('time-currency.proof-verifier.internals')];

const f = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/proof.json', import.meta.url), 'utf8'));
const STOPPING = ['A========', '=', '==', '=A', 'AAAA=A', 'AAAA====', '9999-12-31T23:59:59-00:01', '9999-12-31 00:01:00.5-23:59'];
/// The fixture with one text changed: `path` is the way to it.
function changed(path, text) {
  const copy = structuredClone(f);
  let at = copy;
  for (const step of path.slice(0, -1)) at = at[step];
  assert.equal(typeof at[path.at(-1)], 'string', path.join('.') + ' is a text of the fixture');
  at[path.at(-1)] = text;
  return copy;
}
const SIGNATURE = ['proof', 'light_block', 'signed_header', 'commit', 'signatures', 0, 'signature'];

test('the rules for texts the compiled verifier cannot take are those of the Rust source', async () => {
  const { vectors } = JSON.parse(await readFile(new URL('../spec/untrusted-text-vectors.json', import.meta.url), 'utf8'));
  assert(vectors.length > 400 && vectors.filter((v) => v.base64).length > 40 && vectors.filter((v) => v.date).length > 15);
  for (const { text, base64, date } of vectors) {
    assert.equal(base64StopsTheDecoder(text), base64, 'base64 ' + JSON.stringify(text));
    assert.equal(dateStopsTheReader(text), date, 'date ' + JSON.stringify(text));
    assert.equal(refusal(text), base64 ? BASE64_REFUSAL : date ? DATE_REFUSAL : null, JSON.stringify(text));
  }
  for (const text of STOPPING) assert.notEqual(refusal(text), null, text);
  // The module still exports its five functions and nothing else: its stand-in in an upgrade rehearsal exports the same.
  assert.deepEqual(Object.keys(wrapper).sort(), ['verifyFastReceipt', 'verifyLightUpdate', 'verifyReceipt', 'verifyTrust', 'verifyViewProof']);
  // What base64 is, and a date of this century, are never named.
  for (const text of ['', 'QQ==', 'QUI=', 'QUJD', 'QUJDRA', f.proof.light_block.signed_header.commit.signatures[0].signature, f.proof.light_block.signed_header.header.time, '2026-11-22T10:00:00+01:00']) assert.equal(refusal(text), null, text);
});

test('a text the compiled verifier cannot take is refused before it is loaded; honest answers verify as before', async () => {
  const verifier = createVerifier();
  for (const text of STOPPING) {
    // In the answer of a gateway, in the trust and in what the wallet itself asks for.
    for (const path of [SIGNATURE, ['proof', 'light_block', 'signed_header', 'header', 'time'], ['proof', 'light_block', 'validators', 0, 'pub_key', 'value'], ['trust', 'initial_validators', 0, 'pub_key', 'value'], ['trust', 'chain_id'], ['request', 'names', 0]]) {
      const bad = changed(path, text);
      await assert.rejects(verifier.verifyViewProof(bad.proof, bad.trust, bad.request, bad.now_ms), (error) => error instanceof Error && error.code === undefined && /^INVALID_JSON: a (text is not base64|date is beyond the year 9999)/.test(error.message), text + ' at ' + path.join('.'));
    }
    const receipt = structuredClone(f.receipt);
    receipt.signed_header.commit.signatures[0].signature = text;
    await assert.rejects(verifier.verifyReceipt(receipt, f.trust, f.now_ms), /^Error: INVALID_JSON: a /);
    await assert.rejects(verifier.verifyLightUpdate(changed(SIGNATURE, text).proof.light_block, f.trust, f.now_ms), /^Error: INVALID_JSON: a /);
    await assert.rejects(verifier.verifyTrust(changed(['trust', 'initial_validators', 0, 'pub_key', 'value'], text).trust, f.now_ms), /^Error: INVALID_JSON: a /);
    await assert.rejects(verifier.verifyFastReceipt({ tx: text, headers: [] }, f.trust, f.now_ms), /^Error: INVALID_JSON: a /);
  }
  // Nothing of that reached the compiled verifier: it was not even loaded.
  assert.equal(verifier.instances(), 0);
  assert.equal((await verifier.verifyViewProof(f.proof, f.trust, f.request, f.now_ms)).verified, true);
  assert.equal((await verifier.verifyReceipt(f.receipt, f.trust, f.now_ms)).executionVerified, true);
  assert.equal(verifier.instances(), 1);
  // A text the verifier merely cannot read is its own to refuse, in its own words.
  const odd = changed(SIGNATURE, 'not base64!');
  await assert.rejects(verifier.verifyViewProof(odd.proof, odd.trust, odd.request, odd.now_ms), (error) => !(error instanceof WebAssembly.RuntimeError) && !error.message.includes(BASE64_REFUSAL));
  assert.equal(verifier.instances(), 1);
  // The functions the wallet imports are one such verifier.
  const bad = changed(SIGNATURE, 'A========');
  await assert.rejects(verifyViewProof(bad.proof, bad.trust, bad.request, bad.now_ms), /INVALID_JSON: a text is not base64/);
});

/// A stand-in for the generated loader: its functions do what `behave` says for each call.
function standIn(behave) {
  const made = [];
  const load = async (number) => {
    const instance = { number, calls: 0 };
    made.push(instance);
    const act = (name) => (...args) => { instance.calls++; return behave({ instance, name, args }); };
    return Object.fromEntries(['verify_trust', 'verify_light_update', 'verify_view_proof', 'verify_receipt', 'verify_fast_receipt'].map((name) => [name, act(name)]));
  };
  return { load, made };
}

test('an instance that trapped is thrown away: the next call gets a new one, and a refusal keeps the one there is', async () => {
  let trapNext = false;
  const { load, made } = standIn(({ instance, name, args }) => {
    if (trapNext) { trapNext = false; throw new WebAssembly.RuntimeError('unreachable'); }
    if (args[0] === '"refuse"') throw 'INVALID_LIGHT_BLOCK: no';
    if (args[0] === '"upgrade"') throw 'UPGRADE_REQUIRED: the network runs protocol version 9';
    return JSON.stringify({ instance: instance.number, name, args });
  });
  const verifier = createVerifier({ load });
  assert.deepEqual(await verifier.verifyTrust({ a: 1 }, 5), { instance: 0, name: 'verify_trust', args: ['{"a":1}', 5] });
  // The texts and the clock reach the compiled function in the order it takes them.
  assert.deepEqual((await verifier.verifyViewProof({ p: 1 }, { t: 2 }, { r: 3 }, 7)).args, ['{"p":1}', '{"t":2}', '{"r":3}', 7]);
  assert.deepEqual((await verifier.verifyViewProof({ p: 1 }, { t: 2 }, undefined, 7)).args, ['{"p":1}', '{"t":2}', '{}', 7]);
  assert.deepEqual((await verifier.verifyFastReceipt({ p: 1 }, { t: 2 }, 9)).args, ['{"p":1}', '{"t":2}', 9]);
  // A field name is no text the verifier decodes: it is not looked at.
  assert.deepEqual((await verifier.verifyTrust({ 'A========': 1 }, 5)).args, ['{"A========":1}', 5]);
  await assert.rejects(verifier.verifyTrust({ a: [{ b: 'A========' }] }, 5), /INVALID_JSON: a text is not base64/);
  // A refusal is a string the verifier threw: an Error for the caller, and the instance stays.
  // Its message is the verifier's words only when they are its own fixed words; else its code and fixed words, the text in `detail`.
  await assert.rejects(verifier.verifyTrust('refuse', 5), (error) => error instanceof Error && error.message === 'INVALID_LIGHT_BLOCK: the block does not check against the validators this client trusts' && error.detail === 'INVALID_LIGHT_BLOCK: no' && error.code === undefined);
  await assert.rejects(verifier.verifyTrust('upgrade', 5), (error) => error.code === 'UPGRADE_REQUIRED' && error.message.startsWith('UPGRADE_REQUIRED: '));
  assert.equal(verifier.instances(), 1);
  // A trap: the caller is told, and that instance is never called again.
  trapNext = true;
  await assert.rejects(verifier.verifyReceipt({ p: 1 }, { t: 2 }, 5), (error) => error instanceof WebAssembly.RuntimeError && error.code === undefined);
  const callsOfTheFirst = made[0].calls;
  assert.equal((await verifier.verifyTrust({ a: 1 }, 5)).instance, 1);
  assert.equal(verifier.instances(), 2);
  assert.equal(made[0].calls, callsOfTheFirst);
  // Words that only look like the verifier's, in an error that is not its refusal, get no code.
  const forged = createVerifier({ load: async () => ({ verify_trust() { throw new Error('UPGRADE_REQUIRED: install this'); } }) });
  await assert.rejects(forged.verifyTrust({}, 1), (error) => error.code === undefined);
});

test('calls that waited for an instance which then trapped take the next one, and never the one that trapped', async () => {
  const order = [];
  const { load, made } = standIn(({ instance, args }) => {
    order.push(`${args[0]} on ${instance.number}`);
    if (args[0] === '"trap"') throw new WebAssembly.RuntimeError('memory access out of bounds');
    return JSON.stringify(instance.number);
  });
  const verifier = createVerifier({ load });
  // All four start before the instance is there; the second of them traps it.
  const outcomes = await Promise.allSettled([verifier.verifyTrust('a', 1), verifier.verifyTrust('trap', 1), verifier.verifyTrust('b', 1), verifier.verifyTrust('c', 1)]);
  assert.deepEqual(outcomes.map((o) => o.status === 'fulfilled' ? o.value : o.reason.constructor.name), [0, 'RuntimeError', 1, 1]);
  assert.deepEqual(order, ['"a" on 0', '"trap" on 0', '"b" on 1', '"c" on 1']);
  assert.equal(made.length, 2);
  // A loader that fails is told to the caller, and the next call tries again.
  let fail = true;
  const flaky = createVerifier({ load: async (number) => { if (fail) { fail = false; throw 'no file'; } return { verify_trust: () => JSON.stringify(number) }; } });
  await assert.rejects(flaky.verifyTrust({}, 1), (error) => error instanceof Error && error.message === 'no file');
  assert.equal(await flaky.verifyTrust({}, 1), 1);
});

// The compiled verifier itself, with nothing kept from it: what it does with the text that was
// found. A build from before the fix traps; a build after it refuses.
const UNGUARDED = { refuse: () => null };
async function compiledVerifierTraps() {
  const verifier = createVerifier(UNGUARDED), bad = changed(SIGNATURE, 'A========');
  try { await verifier.verifyViewProof(bad.proof, bad.trust, bad.request, bad.now_ms); } catch (error) { return error instanceof WebAssembly.RuntimeError; }
  throw Error('the compiled verifier took a signature that is not base64');
}

test('with the compiled verifier as it is committed, 130 traps or refusals in a row cost no honest answer', async () => {
  // (One instance that went on after its traps failed on honest answers after about 116 of them.
  // A light block is the smallest answer that reaches the place: an instance that is thrown
  // away stays in memory, because a loaded module cannot be unloaded.)
  const verifier = createVerifier(UNGUARDED), RUNS = 130;
  let traps = 0;
  for (let i = 0; i < RUNS; i++) {
    const bad = changed(i % 2 ? SIGNATURE : ['proof', 'light_block', 'signed_header', 'header', 'time'], i % 2 ? 'A========' : '9999-12-31T23:59:59-00:01');
    await assert.rejects(verifier.verifyLightUpdate(bad.proof.light_block, bad.trust, bad.now_ms), (error) => { traps += error instanceof WebAssembly.RuntimeError ? 1 : 0; return true; });
    // An honest answer between them, and after the last.
    if (i % 65 === 64) assert.equal((await verifier.verifyViewProof(f.proof, f.trust, f.request, f.now_ms)).verified, true);
  }
  // Every trap cost one instance and no more. (A build after the fix does not trap: one instance.)
  assert.equal(verifier.instances(), 1 + traps);
  assert(traps === 0 || traps === RUNS, `${traps} of ${RUNS} calls trapped`);
});

test('the compiled verifier itself refuses such a text without a trap (needs a build after the fix)', async (t) => {
  const required = process.env.TIME_VERIFIER_REBUILT === '1';
  if (await compiledVerifierTraps()) {
    if (!required) return t.skip('web-v4/shared/verifier holds the build from before the fix of verifier-v4/src (it traps on a signature that is not base64). Rebuild it on Linux x86-64 with `node tools/build-verifier.mjs`; this test then runs by itself, and TIME_VERIFIER_REBUILT=1 makes it fail instead of skip.');
    assert.fail('TIME_VERIFIER_REBUILT=1, and the compiled verifier still traps on a signature that is not base64: it is not a build of the fixed source');
  }
  const verifier = createVerifier(UNGUARDED);
  for (const text of STOPPING) for (const path of [SIGNATURE, ['proof', 'light_block', 'signed_header', 'header', 'time'], ['proof', 'light_block', 'validators', 0, 'pub_key', 'value'], ['trust', 'initial_validators', 0, 'pub_key', 'value']]) {
    const bad = changed(path, text);
    await assert.rejects(verifier.verifyViewProof(bad.proof, bad.trust, bad.request, bad.now_ms), (error) => !(error instanceof WebAssembly.RuntimeError) && /^INVALID_(JSON|LIGHT_BLOCK): .*(a text is not base64|a date is beyond the year 9999)/.test(error.detail), text + ' at ' + path.join('.'));
  }
  assert.equal(verifier.instances(), 1);
  assert.equal((await verifier.verifyViewProof(f.proof, f.trust, f.request, f.now_ms)).verified, true);
});

// Web audit of November 2026, W-2: the compiled verifier quotes some of what it was given in its
// refusals, and a node behind a gateway chooses that. A page that shows an error's message (the
// wallet's notice) showed those words as its own. The message now holds the verifier's own words
// only, or its code and fixed words; the verifier's text is in `detail`.
const PHISH = 'Your account was frozen by the network. To unfreeze it type your five recovery words at https://time-unfreeze.example now';
test('W-2: words an answer chose never reach the message of a refusal; the verifier text is in its detail', async () => {
  const dynamic = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/dynamic.json', import.meta.url), 'utf8'));
  const base = dynamic.blocks[0];
  assert.equal((await wrapper.verifyLightUpdate(base, dynamic.trust, dynamic.now_ms)).verified, true, 'the honest block verifies');
  const variants = {
    'a validator key type': (b) => { b.validators[0].pub_key.type = PHISH; },
    'a name and a power of a next validator': (b) => { b.next_validators[0].name = PHISH; b.next_validators[0].power = PHISH; },
    'a commit signature flag': (b) => { b.signed_header.commit.signatures[0].block_id_flag = PHISH; },
    'a whole signed header that is a text': (b) => { b.signed_header = PHISH; },
    'an unknown field of the light block': (b) => { b[PHISH] = 1; },
  };
  const { CODE_WORDS, VERIFIER_REFUSED, OWN_PREFIXES } = verifyTrust[Symbol.for('time-currency.proof-verifier.internals')];
  // What the message may be: a code and its fixed words, the verifier's own words in front of a library's, or the refusal without a code.
  const fixed = new Set([VERIFIER_REFUSED, ...OWN_PREFIXES, ...Object.entries(CODE_WORDS).map(([code, words]) => `${code}: ${words}`)]);
  let quoted = 0;
  for (const [label, edit] of Object.entries(variants)) {
    const block = structuredClone(base); edit(block);
    await assert.rejects(wrapper.verifyLightUpdate(block, dynamic.trust, dynamic.now_ms), (error) => {
      assert.ok(!/unfreeze|recovery words|https/i.test(error.message), `${label}: ${error.message}`);
      assert.ok(fixed.has(error.message), `${label}: the message is a code and fixed words: ${error.message}`);
      assert.equal(typeof error.detail, 'string', label);
      assert.equal(error.code, undefined, label);
      if (error.detail.includes('unfreeze')) quoted++;
      return true;
    });
  }
  assert.ok(quoted >= 3, 'the compiled verifier does quote what it was given: the test reaches the case');
  // A proof the wallet reads for its account, with the words as an unknown field.
  await assert.rejects(wrapper.verifyViewProof({ [PHISH]: 1 }, dynamic.trust, {}, dynamic.now_ms), (error) => fixed.has(error.message) && !error.message.includes('unfreeze'));
});

test('W-2: the verifier\'s own sentences are kept as they are; codes keep their beginnings; the upgrade refusal keeps its code and numbers', () => {
  const { refusalWords, VERIFIER_REFUSED } = verifyTrust[Symbol.for('time-currency.proof-verifier.internals')];
  for (const text of ['INVALID_CLOCK', 'INVALID_LIGHT_BLOCK: header exceeds future clock bound', 'STALE_STATE: fresh current authority proof is required', 'HEADER_ROLLBACK: header is below the highest trusted checkpoint',
    'CHECKPOINT_REFRESH_REQUIRED: local trusted checkpoint expired; obtain an independently authenticated checkpoint', 'INVALID_LIGHT_BLOCK: application version is lower than the trusted checkpoint\'s',
    'missing requested proof for 7365637572697479', 'INVALID_DECIMAL: noncanonical genesis time', 'account nonce must be a decimal string', 'transaction hash mismatch',
    'UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 5.']) assert.equal(refusalWords(text), text);
  // A text that only begins like one of them, or holds a quote, is not the verifier's own sentence.
  assert.equal(refusalWords('INVALID_JSON: unknown field `' + PHISH + '`, expected one of `validators`'), 'INVALID_JSON: the answer is not in the form the verifier reads');
  assert.equal(refusalWords('INVALID_LIGHT_BLOCK: invalid validator: invalid type: string "' + PHISH + '"'), 'INVALID_LIGHT_BLOCK: invalid validator');
  assert.equal(refusalWords('invalid key/value proof: ' + PHISH), 'invalid key/value proof');
  assert.equal(refusalWords('INVALID_DECIMAL: ' + PHISH + ' must be a decimal string'), 'INVALID_DECIMAL: a number in the answer is not written as the verifier reads numbers');
  assert.equal(refusalWords(PHISH + ' has missing or unknown fields'), VERIFIER_REFUSED);
  assert.equal(refusalWords('UPGRADE_REQUIRED: the network runs protocol version 5; install ' + PHISH), 'UPGRADE_REQUIRED: the network runs a protocol version this software does not implement; install a release that implements it');
  assert.equal(refusalWords('UPGRADE_REQUIRED: the network runs protocol version 5; this software implements versions 4 to 4. Install a release that implements version 6.'), 'UPGRADE_REQUIRED: the network runs a protocol version this software does not implement; install a release that implements it');
  assert.equal(refusalWords('missing requested proof for ' + PHISH), VERIFIER_REFUSED);
  assert.equal(refusalWords('header/quorum/hash verification failed: Invalid("' + PHISH + '")'), VERIFIER_REFUSED);
  assert.equal(refusalWords('NOT_A_CODE_OF_IT: ' + PHISH), VERIFIER_REFUSED);
  assert.equal(refusalWords(PHISH), VERIFIER_REFUSED);
});

test('W-2: the list of the verifier\'s own sentences is every sentence of its Rust sources, and nothing an answer can write', async () => {
  const { OWN_SENTENCES, OWN_PREFIXES } = verifyTrust[Symbol.for('time-currency.proof-verifier.internals')];
  const { readdir } = await import('node:fs/promises');
  const found = new Set(), formats = new Set();
  for (const dir of ['verifier-v4/src', 'history/src']) {
    for (const name of await readdir(new URL(`../${dir}/`, import.meta.url))) {
      if (!name.endsWith('.rs') || /tests?\.rs$/.test(name) || name === 'fixtures.rs') continue;
      let text = await readFile(new URL(`../${dir}/${name}`, import.meta.url), 'utf8');
      const cut = text.search(/#\[cfg\(test\)\]\s*mod \w+ \{/); if (cut >= 0) text = text.slice(0, cut);
      for (const match of text.matchAll(/"((?:[^"\\]|\\.)*)"/gs)) {
        const value = match[1].replace(/\\\r?\n\s*/g, '').replace(/\\'/g, "'");
        if (!/ /.test(value) || !/[a-z]/.test(value) || !/^[A-Za-z]/.test(value) || /[\r\n`]/.test(value) || ['any JSON', 'minus one'].includes(value)) continue;
        (/\{[^}]*\}/.test(value) ? formats : found).add(value);
      }
    }
  }
  assert.ok(found.size > 250, `${found.size} sentences read`);
  assert.deepEqual([...found].filter(s => !OWN_SENTENCES.has(s)), [], 'every sentence of the verifier is in the list');
  assert.deepEqual([...OWN_SENTENCES].filter(s => s !== 'INVALID_CLOCK' && !found.has(s)), [], 'nothing else is in the list');
  // Each sentence with a variable part is handled: by its own pattern, by the verifier's words in front of it, or by its code.
  const handled = (format) => /^(INVALID_JSON|INVALID_LIGHT_BLOCK|UPGRADE_REQUIRED|INVALID_DECIMAL): /.test(format) || /^missing requested proof for |^\{(field|what)\} /.test(format)
    || OWN_PREFIXES.some((words) => format.startsWith(words.replace(/^INVALID_LIGHT_BLOCK: /, '') + ': '));
  assert.deepEqual([...formats].filter(f => !handled(f)), [], 'every sentence with a variable part is known to this test');
  // No sentence of the list could hold a quote of an answer.
  for (const s of OWN_SENTENCES) assert.ok(!/["`{}]/.test(s), s);
});
