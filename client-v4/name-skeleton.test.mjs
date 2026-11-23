// Names that look alike: the SDK's skeleton of a name against the vectors the engine is tested with
// (spec/name-skeleton-vectors.json, read by v5/src/names.rs), and how a verified state says that its network
// refuses such names.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import './time-sdk.js';

const sdk = globalThis.TimeSDK;
const { vectors } = JSON.parse(await readFile(new URL('../spec/name-skeleton-vectors.json', import.meta.url), 'utf8'));

test('the skeleton of every vector is the one the engine computes', () => {
  // The file is shared with the engine's test: neither may pass on a shortened list.
  assert.equal(vectors.length, 33);
  for (const { name, skeleton } of vectors) assert.equal(sdk.nameSkeleton(name), skeleton, name);
});

test('the vectors hold the cases the rule is made of', () => {
  const of = Object.fromEntries(vectors.map(({ name, skeleton }) => [name, skeleton]));
  // Underscores are removed, wherever they stand.
  for (const name of ['al_ice', '_alice_', 'a_l_i_c_e']) assert.equal(of[name], of.alice);
  // 0 reads as o and 1 as l.
  assert.equal(of.paypa1, of.paypal);
  assert.equal(of.g00gle, 'google');
  assert.equal(of['10'], 'lo');
  // rn reads as m and vv as w: one pass from left to right, without overlap, after the underscores are gone.
  assert.equal(of.barn, of.bam);
  assert.deepEqual([of.rn, of.rrn, of.rnn, of.r_n], ['m', 'rm', 'mn', 'm']);
  assert.deepEqual([of.vv, of.vvv, of.v_v, of.vvrn], ['w', 'wv', 'w', 'wm']);
  // A name of underscores alone has no skeleton.
  assert.equal(of.__, '');
  // What the rule leaves to a wallet's warning: a 1 for an i, an i for an l.
  assert.notEqual(of.b1nance, of.binance);
  assert.notEqual(of.mail, of.mall);
});

test('a skeleton is taken of a name only', () => {
  for (const value of ['a', '', 'Alice', 'al ice', 'alice!', 'a'.repeat(16), 'ålice', 'paypaı', undefined, null, 7, ['alice']]) assert.throws(() => sdk.nameSkeleton(value), /Name must contain/, String(value));
  // The longest and the shortest names.
  assert.equal(sdk.nameSkeleton('a'.repeat(15)), 'a'.repeat(15));
  assert.equal(sdk.nameSkeleton('_'.repeat(15)), '');
  assert.equal(sdk.nameSkeleton('rnrnrnrnrnrnrn'), 'mmmmmmm');
  assert.equal(sdk.nameSkeleton('vvvvvvvvvvvvvvv'), 'wwwwwwwv');
});

test('a skeleton is its own skeleton', () => {
  // A skeleton of two or more characters is itself a name. The pass leaves no _, 0, 1, rn or vv behind, so
  // taking the skeleton a second time changes nothing: every short name over the letters the rule touches.
  for (const { name, skeleton } of vectors) if (skeleton.length >= 2) assert.equal(sdk.nameSkeleton(skeleton), skeleton, name);
  const letters = ['r', 'n', 'v', 'w', 'm', '_', '0', '1', 'a'];
  let names = letters.flatMap((first) => letters.map((second) => first + second)), checked = 0;
  for (let length = 2; length <= 5; length += 1) {
    for (const name of names) {
      const skeleton = sdk.nameSkeleton(name);
      assert.doesNotMatch(skeleton, /_|0|1|rn|vv/, name);
      assert.ok(skeleton.length <= name.length, name);
      if (skeleton.length >= 2) assert.equal(sdk.nameSkeleton(skeleton), skeleton, name);
      checked += 1;
    }
    names = names.flatMap((name) => letters.map((next) => name + next));
  }
  assert.equal(checked, 9 ** 2 + 9 ** 3 + 9 ** 4 + 9 ** 5);
});

test('the genesis ceremony computes the skeleton the SDK computes', async () => {
  // Three programs compute a skeleton: the engine, this SDK and the genesis ceremony (tools/genesis-v5.mjs). The
  // engine's tests compare the engine with the ceremony on thousands of names (v5/tests/distinct_names.rs); this
  // compares the ceremony with the SDK: every name of up to five characters over the letters the rule touches,
  // and 20,000 names of every length drawn from the whole alphabet.
  const ceremony = await import('../tools/genesis-v5.mjs');
  const letters = ['r', 'n', 'v', 'w', 'm', '_', '0', '1', 'a'];
  let names = letters.flatMap((first) => letters.map((second) => first + second)), checked = 0;
  for (let length = 2; length <= 5; length += 1) {
    for (const name of names) { assert.equal(ceremony.nameSkeleton(name), sdk.nameSkeleton(name), name); checked += 1; }
    names = names.flatMap((name) => letters.map((next) => name + next));
  }
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789_', touched = 'rnvwm_01lo';
  let seed = 20261122;
  const below = (limit) => { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return (seed >>> 8) % limit; };
  for (let i = 0; i < 20_000; i += 1) {
    let name = '';
    for (let length = 2 + below(14); name.length < length; ) name += below(3) === 0 ? alphabet[below(alphabet.length)] : touched[below(touched.length)];
    assert.equal(ceremony.nameSkeleton(name), sdk.nameSkeleton(name), name);
    checked += 1;
  }
  assert.equal(checked, 9 ** 2 + 9 ** 3 + 9 ** 4 + 9 ** 5 + 20_000);
  // Both refuse what is not a name.
  for (const value of ['a', 'Alice', 'a'.repeat(16), undefined]) { assert.throws(() => ceremony.nameSkeleton(value)); assert.throws(() => sdk.nameSkeleton(value)); }
});

test('whether a network refuses names that look alike is read from its verified state', () => {
  assert.equal(sdk.distinctNames({ config: {} }), false);
  assert.equal(sdk.distinctNames({ config: { fee_micros: '10' } }), false);
  assert.equal(sdk.distinctNames({ config: { distinct_names: true } }), true);
  // The genesis writes the setting one way: `false` and every other spelling are no state of any network.
  for (const written of [false, 'true', 1, null, {}]) assert.throws(() => sdk.distinctNames({ config: { distinct_names: written } }), /Unsupported setting/);
  for (const state of [undefined, null, {}, { config: null }, { config: [] }]) assert.throws(() => sdk.distinctNames(state), /verified state/);
});
