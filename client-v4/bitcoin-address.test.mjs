// The Bitcoin address codec of the market (web-v4/shared/bitcoin-address.mjs, and the same module as
// client-v4/bitcoin-address.mjs). It decides where a person's bitcoin goes, so it is held to:
// - the test vectors of BIP173 and BIP350 and Bitcoin Core's own address data (spec/bitcoin-address-vectors.json);
// - the engine's Bitcoin library: the address of every standard script on each network, the form of scripts, and
//   transactions with and without witness data (spec/market-vectors.json, written by v5/tests/market.rs);
// - an independent Base58Check written here with node:crypto;
// - every single wrong, missing, added or swapped character of an address of each form on each network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import * as codec from './bitcoin-address.mjs';
import * as shared from '../web-v4/shared/bitcoin-address.mjs';

const { NETWORKS, FORMS, scriptForm, addressToScript, scriptToAddress, decodeBech32, encodeBech32, stripWitness, transactionId, transactionOutputs, merkleProofMatches, proofPayload } = codec;
const vectors = JSON.parse(await readFile(new URL('../spec/bitcoin-address-vectors.json', import.meta.url), 'utf8'));
const engine = JSON.parse(await readFile(new URL('../spec/market-vectors.json', import.meta.url), 'utf8'));
const HRP = { bc: 'mainnet', tb: 'testnet3', bcrt: 'regtest' };
const standard = (script) => { try { return scriptForm(script); } catch { return null; } };
const refused = (address, network, why = /./) => assert.rejects(addressToScript(address, network), why, `${JSON.stringify(address)} on ${network}`);
const refusedEverywhere = async (address, why) => { for (const network of NETWORKS) await refused(address, network, why); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
/// A generator of bytes that gives the same bytes on every run.
function source(label) {
  let counter = 0;
  return (length) => { let out = Buffer.alloc(0); while (out.length < length) out = Buffer.concat([out, sha256(Buffer.from(`${label}/${counter++}`))]); return out.subarray(0, length); };
}
const SCRIPT = {
  p2pkh: (hash) => `76a914${hash}88ac`, p2sh: (hash) => `a914${hash}87`, p2wpkh: (hash) => `0014${hash}`, p2wsh: (hash) => `0020${hash}`, p2tr: (hash) => `5120${hash}`,
};
const HASH_BYTES = { p2pkh: 20, p2sh: 20, p2wpkh: 20, p2wsh: 32, p2tr: 32 };

test('both paths give the one module, and its lists are the chain\'s names', () => {
  assert.deepEqual(Object.keys(codec).sort(), Object.keys(shared).sort());
  for (const name of Object.keys(codec)) assert.equal(codec[name], shared[name]);
  assert.deepEqual(NETWORKS, ['mainnet', 'testnet3', 'regtest']);
  assert.deepEqual(FORMS, ['p2pkh', 'p2sh', 'p2tr', 'p2wpkh', 'p2wsh']);
  assert.deepEqual([...FORMS].sort(), FORMS, 'ascending, as a buy order lists them');
  assert.ok(Object.isFrozen(NETWORKS) && Object.isFrozen(FORMS));
});

test('BIP173 and BIP350: every valid text is read with its own checksum and written back, every invalid one is refused', () => {
  for (const [list, encoding] of [[vectors.bech32_valid, 'bech32'], [vectors.bech32m_valid, 'bech32m']]) {
    assert.equal(list.length, 7);
    for (const text of list) {
      const read = decodeBech32(text);
      assert.equal(read.encoding, encoding, text);
      assert.equal(encodeBech32(read.hrp, read.words, encoding), text.toLowerCase());
      // The same words under the other checksum are another text, and each reads as what it is.
      const other = encoding === 'bech32' ? 'bech32m' : 'bech32';
      const twin = encodeBech32(read.hrp, read.words, other);
      assert.notEqual(twin, text.toLowerCase());
      assert.equal(decodeBech32(twin).encoding, other);
    }
  }
  assert.ok(vectors.bech32_invalid.length >= 12 && vectors.bech32m_invalid.length >= 14);
  for (const [text, why] of [...vectors.bech32_invalid, ...vectors.bech32m_invalid]) assert.throws(() => decodeBech32(text), Error, `${JSON.stringify(text)}: ${why}`);
  for (const text of [undefined, null, 7, ['a12uel5l'], { length: 8 }, '', '1', 'a1', 'a12uel5', 'a12uel5l ', ' a12uel5l', 'a12uel5l\n', 'a12uel5L', 'a12uel5K']) assert.throws(() => decodeBech32(text), Error, JSON.stringify(text));
  assert.throws(() => encodeBech32('BC', [0], 'bech32'), /small letters/);
  assert.throws(() => encodeBech32('bc', [32], 'bech32'), /five-bit/);
  assert.throws(() => encodeBech32('bc', [0], 'bech32x'), /bech32 or bech32m/);
  assert.throws(() => encodeBech32('bc', new Array(90).fill(0), 'bech32'), /at most 90/);
});

test('BIP173 and BIP350: an address of a standard form gives its script on its network alone; every other valid address is refused for what it is', async () => {
  let taken = 0;
  for (const [address, script, bip] of vectors.segwit_valid) {
    const network = HRP[decodeBech32(address).hrp];
    assert.ok(network, address);
    if (bip === 350 && standard(script)) {
      taken += 1;
      assert.equal(await addressToScript(address, network), script, address);
      assert.equal(await scriptToAddress(script, network), address.toLowerCase());
      for (const other of NETWORKS) if (other !== network) await refused(address, other, new RegExp(`This is an address of Bitcoin ${network} .*the network here is ${other}`));
    } else await refusedEverywhere(address);
  }
  assert.equal(taken, 8);
  // What the refusals say.
  const says = {
    bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y: /taproot\) holds 32 bytes: this one holds 40/,
    BC1SW50QGDZ25J: /witness version 16: the market takes versions 0 and 1 only/,
    bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs: /witness version 2/,
    bc1pfeessrawgf: /holds 32 bytes: this one holds 2/,
    bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx: /carries a Bech32m checksum \(BIP350\): this one carries a Bech32 checksum/,
    BC1SW50QA3JX3S: /witness version 16/,
    bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj: /witness version 2/,
  };
  for (const [address, why] of Object.entries(says)) {
    assert.ok(vectors.segwit_valid.some(([text]) => text === address), address);
    await refused(address, 'mainnet', why);
  }
});

test('BIP173 and BIP350: every invalid address is refused on every network, for its own reason', async () => {
  const says = {
    tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty: /not a Bitcoin \w+ address: those begin with \w+1, and this one with tc1/,
    bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5: /checksum of this Bech32 text is wrong/,
    BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2: /witness version that does not exist/,
    bc1rw5uspcuh: /witness version 3/,
    bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90: /witness version 15/,
    BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P: /holds 20 or 32 bytes: this one holds 16/,
    tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7: /mixes/,
    BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3t4: /mixes/,
    bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du: /witness version 2/,
    tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv: /padding bits that are not zero/,
    bc1gmk9yu: /no data after its prefix/,
    tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut: /this one with tc1/,
    bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd: /carries a Bech32m checksum \(BIP350\): this one carries a Bech32 checksum/,
    tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf: /witness version 2/,
    BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL: /witness version 16/,
    bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh: /carries a Bech32 checksum \(BIP173\): this one carries a Bech32m checksum/,
    tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47: /carries a Bech32 checksum \(BIP173\): this one carries a Bech32m checksum/,
    bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4: /alphabet does not have: o/,
    BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R: /witness version that does not exist/,
    bc1pw5dgrnzv: /holds 32 bytes: this one holds 1/,
    bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav: /holds 32 bytes: this one holds 41/,
    tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq: /mixes/,
    bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf: /more padding than Bech32 allows/,
    tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j: /padding bits that are not zero/,
  };
  assert.equal(vectors.segwit_invalid.length, 24);
  for (const [address, why] of vectors.segwit_invalid) {
    assert.ok(Object.hasOwn(says, address), `${address} (${why}) has its reason here`);
    await refusedEverywhere(address);
    const network = HRP[address.toLowerCase().split('1')[0]] ?? 'mainnet';
    await refused(address, network, says[address]);
  }
});

test('Bitcoin Core\'s addresses: each of the five forms on each network, both ways; what is not an address of the market is refused', async () => {
  const seen = new Map();
  for (const [address, script, network] of vectors.core_addresses) {
    const form = standard(script), legacy = /^[13mn2]/.test(address);
    if (!form) { await refusedEverywhere(address); await refused(address, network, /witness version/); assert.equal(legacy, false); continue; }
    seen.set(`${network}/${form}`, (seen.get(`${network}/${form}`) ?? 0) + 1);
    assert.equal(await addressToScript(address, network), script, address);
    assert.equal(await scriptToAddress(script, network), address);
    assert.equal(legacy, form === 'p2pkh' || form === 'p2sh');
    for (const other of NETWORKS) {
      if (other === network) continue;
      // The legacy addresses of testnet3 and regtest are the same texts.
      if (legacy && network !== 'mainnet' && other !== 'mainnet') assert.equal(await addressToScript(address, other), script);
      else await refused(address, other, new RegExp(`This is an address of Bitcoin .*${network}.*the network here is ${other}`));
    }
    // All in capitals: Bech32 allows it and the script is the same; a Base58Check address is another text and is refused.
    if (legacy) await refusedEverywhere(address.toUpperCase());
    else assert.equal(await addressToScript(address.toUpperCase(), network), script);
    if (legacy) await refusedEverywhere(address.toLowerCase());
  }
  for (const network of NETWORKS) for (const form of FORMS) assert.ok(seen.get(`${network}/${form}`) >= 2, `${network}/${form}: ${seen.get(`${network}/${form}`)}`);
  assert.equal(vectors.core_private_keys.length, 16);
  for (const text of vectors.core_private_keys) await refusedEverywhere(text);
  assert.equal(vectors.core_invalid.length, 70);
  for (const text of vectors.core_invalid) await refusedEverywhere(text);
});

test('the engine\'s Bitcoin library writes the same address for every standard script on every network', async () => {
  assert.equal(engine.addresses.length, 30);
  const seen = new Set();
  for (const { address, network, script } of engine.addresses) {
    seen.add(`${network}/${scriptForm(script)}`);
    assert.equal(await scriptToAddress(script, network), address);
    assert.equal(await addressToScript(address, network), script);
  }
  assert.equal(seen.size, 15);
});

test('the form of a script is the engine\'s, and a script is lowercase hexadecimal of exactly a standard form', () => {
  assert.ok(engine.forms.length >= 39);
  for (const { form, script } of engine.forms) {
    if (form === null) assert.throws(() => scriptForm(script), /five standard forms/, script);
    else assert.equal(scriptForm(script), form);
  }
  const good = engine.forms.filter(entry => entry.form !== null).map(entry => entry.script);
  assert.deepEqual([...new Set(engine.forms.map(entry => entry.form).filter(Boolean))].sort(), FORMS);
  for (const script of good) {
    for (const bad of [script.toUpperCase(), script.slice(0, -1), script.slice(0, -2), `${script}00`, `${script} `, ` ${script}`, `0x${script}`, `${script}\n`, script.replace(/^../, 'zz')]) {
      if (bad !== script) assert.throws(() => scriptForm(bad), /five standard forms/, bad);
    }
  }
  for (const bad of [undefined, null, 0, [], {}, [good[0]], Buffer.from(good[0], 'hex'), new String(good[0])]) assert.throws(() => scriptForm(bad), /five standard forms/);
});

test('an unknown network is refused by name, whatever is asked of it', async () => {
  const script = '0014751e76e8199196d454941c45d1b3a323f1433bd6', address = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
  for (const network of [undefined, null, '', 'main', 'bitcoin', 'testnet', 'testnet4', 'signet', 'Mainnet', 'MAINNET', 'mainnet ', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 0, ['mainnet'], { toString: () => 'mainnet' }]) {
    await assert.rejects(addressToScript(address, network), /Unknown Bitcoin network: name one of mainnet, testnet3, regtest/);
    await assert.rejects(scriptToAddress(script, network), /Unknown Bitcoin network/);
  }
  for (const bad of [undefined, null, 5, '', [address], { toString: () => address }]) await assert.rejects(addressToScript(bad, 'mainnet'), /An address is a text/);
  for (const bad of [` ${address}`, `${address} `, `${address}\n`, `${address}\t`, address.replace('q', 'q '), ` ${address}`, `${address} `]) await assert.rejects(addressToScript(bad, 'mainnet'), /no space/);
  await assert.rejects(scriptToAddress('6a0100', 'mainnet'), /five standard forms/);
  await assert.rejects(scriptToAddress(script.toUpperCase(), 'mainnet'), /five standard forms/);
});

test('addresses everyone knows, and a hash that begins with zero bytes', async () => {
  // The address of the first block's reward, and the address of twenty zero bytes.
  assert.equal(await addressToScript('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'mainnet'), '76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac');
  assert.equal(await scriptToAddress(`76a914${'00'.repeat(20)}88ac`, 'mainnet'), '1111111111111111111114oLvT2');
  assert.equal(await addressToScript('1111111111111111111114oLvT2', 'mainnet'), `76a914${'00'.repeat(20)}88ac`);
  // One 1 more or fewer is another number of zero bytes, not the same address written otherwise.
  await refusedEverywhere('111111111111111111114oLvT2');
  await refusedEverywhere('11111111111111111111114oLvT2');
  // BIP173's own examples.
  assert.equal(await addressToScript('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'mainnet'), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
  assert.equal(await addressToScript('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 'testnet3'), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
});

// An independent Base58Check, with node:crypto and BigInt arithmetic of its own.
function referenceBase58Check(version, hashHex) {
  const body = Buffer.concat([Buffer.from([version]), Buffer.from(hashHex, 'hex')]);
  const whole = Buffer.concat([body, sha256(sha256(body)).subarray(0, 4)]);
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let number = BigInt(`0x${whole.toString('hex')}`), text = '';
  while (number > 0n) { text = alphabet[Number(number % 58n)] + text; number /= 58n; }
  for (const byte of whole) { if (byte !== 0) break; text = `1${text}`; }
  return text;
}

test('every byte of a Base58Check checksum is compared, and an address holds 25 bytes, not 24 or 26', async () => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const text = (whole) => { let number = BigInt(`0x${whole.toString('hex')}`), out = ''; while (number > 0n) { out = alphabet[Number(number % 58n)] + out; number /= 58n; } for (const byte of whole) { if (byte !== 0) break; out = `1${out}`; } return out; };
  for (const [version, network] of [[0x00, 'mainnet'], [0x05, 'mainnet'], [0x6f, 'testnet3'], [0xc4, 'regtest']]) {
    const body = Buffer.concat([Buffer.from([version]), sha256(Buffer.from(`checksum ${version}`)).subarray(0, 20)]);
    const whole = Buffer.concat([body, sha256(sha256(body)).subarray(0, 4)]);
    assert.match(await addressToScript(text(whole), network), /^(76a914|a914)/);
    // One bit of each of the four checksum bytes, by itself.
    for (let at = 21; at < 25; at++) for (const bit of [1, 0x80]) {
      const wrong = Buffer.from(whole); wrong[at] ^= bit;
      await refused(text(wrong), network, /The checksum of this address is wrong/);
    }
    // A byte fewer or a byte more, with a checksum of its own: another text altogether, and no address.
    await refusedEverywhere(text(whole.subarray(0, 24)));
    await refusedEverywhere(text(Buffer.concat([whole, Buffer.from([0])])));
    const longer = Buffer.concat([body, Buffer.from([7])]);
    await refusedEverywhere(text(Buffer.concat([longer, sha256(sha256(longer)).subarray(0, 4)])));
    // One zero byte more in front is one 1 more: 26 bytes.
    if (version === 0x00) await refused(`1${text(whole)}`, network, /A Base58Check address holds 25 bytes/);
  }
});

test('script to address to script, for scripts of every form on every network, against an independent Base58Check', async () => {
  const VERSION = { mainnet: { p2pkh: 0x00, p2sh: 0x05 }, testnet3: { p2pkh: 0x6f, p2sh: 0xc4 }, regtest: { p2pkh: 0x6f, p2sh: 0xc4 } };
  const PREFIX = { mainnet: { p2pkh: /^1/, p2sh: /^3/, p2wpkh: /^bc1q/, p2wsh: /^bc1q/, p2tr: /^bc1p/ }, testnet3: { p2pkh: /^[mn]/, p2sh: /^2/, p2wpkh: /^tb1q/, p2wsh: /^tb1q/, p2tr: /^tb1p/ }, regtest: { p2pkh: /^[mn]/, p2sh: /^2/, p2wpkh: /^bcrt1q/, p2wsh: /^bcrt1q/, p2tr: /^bcrt1p/ } };
  const LENGTH = { p2wpkh: 39, p2wsh: 59, p2tr: 59 }, HRP_OF = { mainnet: 'bc', testnet3: 'tb', regtest: 'bcrt' };
  const bytes = source('round trips');
  const all = new Set();
  for (const network of NETWORKS) for (const form of FORMS) {
    const hashes = ['00'.repeat(HASH_BYTES[form]), 'ff'.repeat(HASH_BYTES[form]), `${'00'.repeat(HASH_BYTES[form] - 1)}01`, `0000${'ab'.repeat(HASH_BYTES[form] - 2)}`];
    for (let i = 0; i < 150; i++) hashes.push(bytes(HASH_BYTES[form]).toString('hex'));
    for (const hash of hashes) {
      const script = SCRIPT[form](hash), address = await scriptToAddress(script, network);
      assert.match(address, PREFIX[network][form]);
      assert.equal(await addressToScript(address, network), script, address);
      if (form === 'p2pkh' || form === 'p2sh') assert.equal(address, referenceBase58Check(VERSION[network][form], hash));
      else assert.equal(address.length, HRP_OF[network].length + 1 + LENGTH[form]);
      all.add(`${network === 'regtest' && (form === 'p2pkh' || form === 'p2sh') ? 'testnet3' : network}/${address}`);
    }
  }
  // No two scripts share an address on a network. testnet3 and regtest share their legacy addresses: the four hashes
  // that are the same for both, in the two legacy forms, are counted once.
  assert.equal(all.size, 3 * 5 * 154 - 2 * 4);
});

test('one wrong, missing, added or swapped character is never another address', async () => {
  const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const bytes = source('mutations');
  let tried = 0;
  for (const network of NETWORKS) for (const form of FORMS) {
    const script = SCRIPT[form](bytes(HASH_BYTES[form]).toString('hex')), address = await scriptToAddress(script, network);
    const legacy = form === 'p2pkh' || form === 'p2sh', alphabet = legacy ? BASE58 : BECH32;
    const others = new Set();
    for (let at = 0; at < address.length; at++) {
      for (const letter of alphabet) if (letter !== address[at]) others.add(address.slice(0, at) + letter + address.slice(at + 1));
      others.add(address.slice(0, at) + address.slice(at + 1));
      if (at + 1 < address.length && address[at] !== address[at + 1]) others.add(address.slice(0, at) + address[at + 1] + address[at] + address.slice(at + 2));
    }
    for (let at = 0; at <= address.length; at++) for (const letter of alphabet) others.add(address.slice(0, at) + letter + address.slice(at));
    others.delete(address);
    for (const other of others) {
      tried += 1;
      // Refused on its own network; and on no network does it give a script.
      await refused(other, network);
    }
    // In another case: a Bech32 address in mixed case is refused; in capitals it is the same address.
    if (!legacy) {
      await refused(address[0].toUpperCase() + address.slice(1), network, /mixes/);
      const at = address.search(/[a-z][^a-z]*$/);
      await refused(address.slice(0, at) + address[at].toUpperCase() + address.slice(at + 1), network, /mixes/);
      assert.equal(await addressToScript(address.toUpperCase(), network), script);
    }
  }
  assert.ok(tried > 50_000, String(tried));
});

test('a transaction without its witness data is what the engine\'s Bitcoin library writes, and its id does not change', async () => {
  const names = engine.transactions.map(entry => entry.name);
  for (const name of ['p2wpkh_spend', 'p2tr_key_spend', 'p2tr_script_spend', 'legacy', 'some_inputs_without_witness', 'an_empty_witness_item', '253_outputs', '253_inputs_and_a_long_script']) assert.ok(names.includes(name), name);
  for (const { name, transaction, txid, without_witness: bare } of engine.transactions) {
    assert.equal(stripWitness(transaction), bare, name);
    assert.equal(stripWitness(bare), bare, `${name}: nothing to remove`);
    assert.equal(await transactionId(transaction), txid, name);
    assert.equal(await transactionId(bare), txid, name);
    // The id is the double SHA-256 of the bytes without witness data, byte-reversed.
    assert.equal(Buffer.from(sha256(sha256(Buffer.from(bare, 'hex')))).reverse().toString('hex'), txid);
    assert.equal(name === 'legacy', transaction === bare, name);
    if (transaction !== bare) assert.equal(transaction.slice(8, 12), '0001');
  }
});

test('what is not exactly one transaction is refused', async () => {
  const of = (name) => engine.transactions.find(entry => entry.name === name);
  const spend = of('p2wpkh_spend'), legacy = of('legacy'), mixed = of('some_inputs_without_witness');
  for (const { transaction, without_witness: bare } of [spend, legacy, mixed, of('p2tr_script_spend')]) {
    // Every beginning of it, a byte more, and its two serializations one after the other.
    for (const whole of new Set([transaction, bare])) {
      for (let length = 0; length < whole.length; length += 2) assert.throws(() => stripWitness(whole.slice(0, length)), /ends too early|not a Bitcoin transaction|at least one/, `${length / 2} of ${whole.length / 2} bytes`);
      assert.throws(() => stripWitness(`${whole}00`), /bytes follow its end/);
      assert.throws(() => stripWitness(whole + whole), /bytes follow its end|ends too early/);
      assert.throws(() => stripWitness(whole.toUpperCase().replace(/^[0-9]+$/, 'AB')), /lowercase hexadecimal/);
      assert.throws(() => stripWitness(whole.slice(1)), /lowercase hexadecimal|ends too early|not a Bitcoin transaction|bytes follow|at least one|longer form/);
    }
  }
  // Another flag; the marker with no witness in any input; no input; no output.
  assert.throws(() => stripWitness(spend.transaction.slice(0, 10) + '02' + spend.transaction.slice(12)), /a marker this code does not know/);
  const bare = legacy.without_witness, emptyWitnesses = `${bare.slice(0, 8)}0001${bare.slice(8, -8)}0000${bare.slice(-8)}`;
  assert.throws(() => stripWitness(emptyWitnesses), /marked as having witness data and has none/);
  assert.throws(() => stripWitness('02000000' + '00' + '00' + '00000000'), /no input, or a marker/);
  assert.throws(() => stripWitness('02000000' + '0001' + '00' + '00' + '00000000'), /at least one input/);
  const oneInput = `01${'11'.repeat(36)}00ffffffff`;
  assert.throws(() => stripWitness(`02000000${oneInput}00${'00000000'}`), /at least one output/);
  // A size written in a longer form than needed: the count of inputs as fd 01 00, as fe 01 00 00 00, as ff ….
  const tail = bare.slice(10);
  assert.equal(bare.slice(8, 10), '02');
  assert.throws(() => stripWitness(`${bare.slice(0, 8)}fd0200${tail}`), /longer form than needed/);
  assert.throws(() => stripWitness(`${bare.slice(0, 8)}fe02000000${tail}`), /longer form than needed/);
  assert.throws(() => stripWitness(`${bare.slice(0, 8)}ff0200000000000000${tail}`), /a size nothing has/);
  // A count that the bytes left cannot hold is refused before anything is read for it.
  assert.throws(() => stripWitness(`02000000feffffff7f${'00'.repeat(64)}`), /ends too early/);
  for (const bad of [undefined, null, 5, '', 'zz', '0', [spend.transaction], Buffer.from(spend.transaction, 'hex')]) assert.throws(() => stripWitness(bad), /lowercase hexadecimal|ends too early/);
  await assert.rejects(transactionId(`${spend.transaction}00`), /bytes follow its end/);
  await assert.rejects(transactionId('00'), /ends too early/);
});

test('the outputs of a transaction, with or without its witness data', () => {
  const spend = engine.transactions.find(entry => entry.name === 'p2wpkh_spend');
  const outputs = [{ sats: '10000', script: `0014${'01'.repeat(20)}` }, { sats: '89000', script: `5120${'44'.repeat(32)}` }];
  assert.deepEqual(transactionOutputs(spend.transaction), outputs);
  assert.deepEqual(transactionOutputs(spend.without_witness), outputs);
  assert.equal(transactionOutputs(engine.transactions.find(entry => entry.name === '253_outputs').transaction).length, 253);
  // Every satoshi of an output's eight bytes is read: 21 million bitcoin, and the largest number the bytes hold.
  const paying = (valueHex) => `01000000${`01${'11'.repeat(36)}00ffffffff`}01${valueHex}16${`0014${'07'.repeat(20)}`}00000000`;
  assert.deepEqual(transactionOutputs(paying('0040075af0750700')), [{ sats: '2100000000000000', script: `0014${'07'.repeat(20)}` }]);
  assert.deepEqual(transactionOutputs(paying('ffffffffffffffff'))[0].sats, '18446744073709551615');
  assert.throws(() => transactionOutputs(`${spend.transaction}00`), /bytes follow its end/);
});

test('the payload of a proof, from what a Bitcoin node gives, is the one the engine accepted', async () => {
  const proofs = engine.actions.filter(entry => entry.kind === 54);
  assert.deepEqual(proofs.map(entry => entry.name), ['proof_of_a_part', 'proof']);
  // Both pay the first script of the sell order.
  const script = engine.actions.find(entry => entry.name === 'sell_order').payload.scripts[0];
  for (const { name, payload, bitcoin_node: node } of proofs) {
    const given = { fill: payload.fill, script, blockHash: payload.block_hash, transaction: node.transaction, coinbase: node.coinbase, merkleProof: payload.merkle_proof };
    assert.notEqual(node.transaction, payload.transaction, `${name}: the node gives witness data`);
    assert.notEqual(node.coinbase, payload.coinbase);
    assert.deepEqual(await proofPayload(given), payload, name);
    assert.equal(JSON.stringify(await proofPayload(given)), JSON.stringify(payload), 'the fields in the order they are signed');
    for (const vout of [payload.vout, Number(payload.vout), BigInt(payload.vout)]) assert.deepEqual(await proofPayload({ ...given, vout }), payload);
    assert.deepEqual(await proofPayload({ ...given, vout: undefined }), payload);
    assert.deepEqual(await proofPayload({ ...given, fill: BigInt(payload.fill) }), payload);
    assert.deepEqual(await proofPayload({ ...given, fill: Number(payload.fill) }), payload);
    // Transactions that have lost their witness data already.
    assert.deepEqual(await proofPayload({ ...given, transaction: payload.transaction, coinbase: payload.coinbase }), payload);
    assert.equal(transactionOutputs(node.transaction)[Number(payload.vout)].script, script);
    assert.equal(await transactionId(node.transaction), await transactionId(payload.transaction));
  }
  assert.equal(proofs[1].payload.vout, '1', 'the second proof names an output that is not the first');
});

test('a proof that would not pay for the fill is refused before it is signed', async () => {
  const [part, whole] = engine.actions.filter(entry => entry.kind === 54);
  const script = engine.actions.find(entry => entry.name === 'sell_order').payload.scripts[0], other = `5120${'44'.repeat(32)}`;
  const of = ({ payload, bitcoin_node: node }) => ({ fill: payload.fill, script, blockHash: payload.block_hash, transaction: node.transaction, coinbase: node.coinbase, merkleProof: payload.merkle_proof });
  const given = of(whole), refused = (changes, why) => assert.rejects(proofPayload({ ...given, ...changes }), why, JSON.stringify(Object.keys(changes)));
  // The script of another fill; an output that pays something else; an output the transaction does not have.
  await refused({ script: `0014${'09'.repeat(20)}` }, /No output of this transaction pays the receiving script of the fill/);
  await refused({ vout: 0 }, /Output 0 of this transaction does not pay the receiving script of the fill: output 1 does/);
  await refused({ script: other, vout: 1 }, /Output 1 of this transaction does not pay the receiving script of the fill: output 0 does/);
  assert.equal((await proofPayload({ ...given, script: other })).vout, '0');
  await refused({ script: `0014${'09'.repeat(20)}`, vout: 1 }, /does not pay the receiving script of the fill, and no other output does/);
  await refused({ vout: 82 }, /This transaction has 82 outputs: it has no output 82/);
  for (const vout of [-1, 1.5, '01', '1 ', 'one', -1n, 1n << 32n, 2 ** 32, NaN, [1], {}]) await refused({ vout }, /vout is the place of an output/);
  for (const bad of ['6a0100', script.toUpperCase().replace(/^[0-9]+$/, 'AB'), `${script}00`, undefined, null, 5]) await refused({ script: bad }, /five standard forms|needs script/);
  // The two transactions in each other's place, the same one twice, and those of another block.
  await refused({ transaction: given.coinbase, coinbase: given.transaction }, /coinbase is the first transaction of the block, which spends nothing/);
  await refused({ coinbase: given.transaction }, /coinbase is the first transaction of the block/);
  await refused({ transaction: given.coinbase }, /No output of this transaction pays|The payment is a coinbase transaction/);
  await refused({ transaction: given.coinbase, script: transactionOutputs(given.coinbase)[0].script }, /The payment is a coinbase transaction/);
  await refused({ coinbase: of(part).coinbase }, /does not hold the coinbase transaction/);
  await refused({ transaction: of(part).transaction }, /does not hold the payment/);
  // The Merkle proof of another block, a block hash of another block, and a proof that is not whole.
  await refused({ merkleProof: of(part).merkleProof }, /merkleProof is for another block than blockHash/);
  await refused({ blockHash: of(part).blockHash }, /merkleProof is for another block than blockHash/);
  await refused({ blockHash: given.blockHash.toUpperCase().replace(/^[0-9]+$/, 'AB') }, /blockHash is 64 lowercase hexadecimal characters/);
  // The hash as the bytes stand in the header, not as Bitcoin software prints it.
  await refused({ blockHash: given.blockHash.match(/../g).reverse().join('') }, /merkleProof is for another block than blockHash/);
  const proof = given.merkleProof;
  await refused({ merkleProof: `${proof}00` }, /does not end where its own sizes say/);
  await refused({ merkleProof: proof.slice(0, -2) }, /does not end where its own sizes say/);
  await refused({ merkleProof: proof.slice(0, -4) }, /a number of hashes that no proof of two transactions has/);
  await refused({ merkleProof: proof.slice(0, 170) }, /86 to 4,096 bytes/);
  await refused({ merkleProof: proof.slice(0, 172) + '00'.repeat(4096) }, /86 to 4,096 bytes/);
  await refused({ merkleProof: proof.toUpperCase() }, /merkleProof is lowercase hexadecimal/);
  await refused({ merkleProof: `${proof.slice(0, 168)}41${proof.slice(170)}` }, /a number of hashes that no proof of two transactions has/);
  await refused({ merkleProof: `${proof.slice(0, 168)}00${proof.slice(170)}` }, /a number of hashes that no proof of two transactions has/);
  // The block of the vectors holds two transactions: a header, their number, two hashes, and one byte of three flag
  // bits (the root is above a match, the first is one, the second is one: 07).
  assert.equal(proof.length, 2 * (80 + 4 + 1 + 64 + 1 + 1), 'a block of two transactions');
  assert.equal(proof.slice(-2), '07');
  const flags = (byte) => proof.slice(0, -2) + byte;
  // A proof of the payment alone, as gettxoutproof gives it for one id (05), and of the coinbase alone (03): the same
  // hashes, and the engine would refuse both. A proof of nothing; the flag bits nothing uses are not read.
  await refused({ merkleProof: flags('05') }, /merkleProof does not hold the coinbase transaction: ask gettxoutproof for both ids/);
  await refused({ merkleProof: flags('03') }, /merkleProof does not hold the payment: ask gettxoutproof for both ids/);
  await refused({ merkleProof: flags('01') }, /does not hold the coinbase transaction/);
  await refused({ merkleProof: flags('00') }, /holds hashes or flag bytes that nothing uses/);
  assert.deepEqual(await proofPayload({ ...given, merkleProof: flags('f7') }), { ...whole.payload, merkle_proof: flags('f7') });
  await refused({ merkleProof: `${proof.slice(0, -4)}020700` }, /holds hashes or flag bytes that nothing uses/);
  // One bit of a hash changed, or one bit of the header's Merkle root
  // (with the hash of that header): the hashes do not lead to the root. Another number of transactions: another tree.
  await refused({ merkleProof: `${proof.slice(0, 170)}${(parseInt(proof[170], 16) ^ 1).toString(16)}${proof.slice(171)}` }, /merkleProof does not lead to the Merkle root of its block/);
  const header = Buffer.from(proof.slice(0, 160), 'hex');
  header[40] ^= 1;
  const moved = { merkleProof: header.toString('hex') + proof.slice(160), blockHash: Buffer.from(sha256(sha256(header))).reverse().toString('hex') };
  await refused(moved, /merkleProof does not lead to the Merkle root of its block/);
  for (const total of ['03000000', '01000000', '00000000', '1b410000', 'ffffffff']) await refused({ merkleProof: proof.slice(0, 160) + total + proof.slice(168) }, /Merkle/);
  // The two transactions in each other's place in the proof: the tree's root is another.
  await refused({ merkleProof: proof.slice(0, 170) + proof.slice(234, 298) + proof.slice(170, 234) + proof.slice(298) }, /does not lead to the Merkle root/);
  // The fill's id; the arguments.
  for (const fill of ['0', '01', '', -1, 1.5, '18446744073709551616', [1], true]) await refused({ fill }, /fill is the id of a fill/);
  for (const name of ['fill', 'script', 'blockHash', 'transaction', 'coinbase', 'merkleProof']) {
    await refused({ [name]: undefined }, new RegExp(`proofPayload needs ${name}`));
    await refused({ [name]: null }, new RegExp(`proofPayload needs ${name}`));
  }
  await refused({ block_hash: given.blockHash }, /proofPayload has no argument block_hash/);
  for (const bad of [undefined, null, 'x', [given]]) await assert.rejects(proofPayload(bad), /proofPayload takes one object of named arguments/);
  // Two outputs to the fill's script: each is proven by itself, and none is chosen for the caller. An output of nothing.
  const input = `01${'11'.repeat(36)}00ffffffff`, pay = (sats) => `${sats.toString(16).padStart(2, '0')}0000000000000016${script}`;
  const twice = `01000000${input}03${pay(5)}${pay(0)}${pay(7)}00000000`;
  assert.deepEqual(transactionOutputs(twice).map(output => output.sats), ['5', '0', '7']);
  await refused({ transaction: twice }, /Outputs 0, 1, 2 of this transaction pay the receiving script of the fill: name one with vout/);
  await refused({ transaction: twice, vout: 1 }, /The output that pays the fill has no value/);
  await refused({ transaction: twice, vout: 2 }, /does not hold the payment/);
  // What the engine's sizes refuse: a transaction of 64 bytes or fewer, and one above 240 KiB without its witness data.
  await refused({ transaction: `01000000${input}01050000000000000004${'00'.repeat(4)}00000000` }, /too short to be proven/);
  const huge = `01000000${input}01${`0500000000000000fe00c00300${'51'.repeat(0x3c000)}`}00000000`;
  assert.equal(stripWitness(huge), huge);
  await refused({ transaction: huge }, /The payment is larger than a proof may carry \(100,000 bytes without its witness data\)/);
  await refused({ coinbase: huge }, /The coinbase transaction is larger than a proof may carry \(150,000 bytes/);
  // A payment of 100,000 bytes and a coinbase of 60 are within the sizes: what is refused is something else.
  const sized = (total) => `01000000${input}01${'0500000000000000'}fe${(total - 64).toString(16).padStart(8, '0').match(/../g).reverse().join('')}${'51'.repeat(total - 64)}00000000`;
  assert.equal(sized(100000).length, 200000);
  assert.equal(stripWitness(sized(100000)), sized(100000));
  await refused({ transaction: sized(100000) }, /No output of this transaction pays the receiving script of the fill/);
  await refused({ transaction: sized(100001) }, /The payment is larger than a proof may carry/);
  const shortest = `01000000${`01${'00'.repeat(32)}ffffffff00ffffffff`}01${'0000000000000000'}00${'00000000'}`;
  assert.equal(shortest.length, 120);
  await refused({ coinbase: shortest }, /merkleProof does not hold the coinbase transaction/);
  await refused({ transaction: `01000000${input}02${'0040075af0750700'}16${script}${'0100000000000000'}16${script}00000000`, vout: 1 }, /sum to more bitcoin than exists/);
  await refused({ transaction: `01000000${'02'}${`${'11'.repeat(36)}00ffffffff`.repeat(2)}01${pay(5)}00000000` }, /spends one output twice/);
});

test('a Merkle proof proves the transactions the engine\'s Bitcoin library reads from it, at their places', async () => {
  assert.ok(engine.merkle_proofs.length >= 13);
  const sizes = new Set();
  for (const { block_hash: blockHash, matched, merkle_proof: proof, transactions } of engine.merkle_proofs) {
    sizes.add(transactions);
    assert.deepEqual(await merkleProofMatches(proof, blockHash), matched, `${transactions} transactions, ${matched.length} proven`);
    // One bit changed in the number of hashes or in a hash: refused. In the number of transactions of the block:
    // refused, or the same answer (a block's Merkle root does not say how many transactions it has; the number shapes
    // the tree, and a proof that does not touch the side where the shape differs reads the same). One flag bit changed:
    // refused, or a proof of other transactions of the same block (the flags say which leaves are meant, and the
    // hashes are the same), which is why a proof of payment is held to exactly its two.
    const bytes = Buffer.from(proof, 'hex'), flagsFrom = 85 + 32 * bytes[84] + 1;
    assert.ok(bytes[84] < 0xfd && bytes[flagsFrom - 1] === bytes.length - flagsFrom);
    for (let at = 80; at < bytes.length; at++) {
      const changed = Buffer.from(bytes); changed[at] ^= 1 << (at % 8);
      const answer = await merkleProofMatches(changed.toString('hex'), blockHash).catch(error => error);
      if (at < 84) { if (!(answer instanceof Error)) assert.deepEqual(answer, matched, `byte ${at}`); }
      else if (at < flagsFrom) { assert.ok(answer instanceof Error, `byte ${at} of ${bytes.length}`); assert.match(answer.message, /merkleProof/); }
      else if (!(answer instanceof Error)) for (const { hash } of answer) assert.ok(proof.includes(hash));
    }
    for (let length = 0; length < proof.length; length += 2) await assert.rejects(merkleProofMatches(proof.slice(0, length), blockHash), /merkleProof/, `${length / 2} bytes`);
    await assert.rejects(merkleProofMatches(`${proof}00`, blockHash), /merkleProof/);
    await assert.rejects(merkleProofMatches(proof, engine.merkle_proofs[0].block_hash === blockHash ? engine.merkle_proofs[1].block_hash : engine.merkle_proofs[0].block_hash), /for another block/);
  }
  for (const size of [1, 2, 3, 7, 12, 33, 100]) assert.ok(sizes.has(size), `a block of ${size}`);
  const { block_hash: blockHash, merkle_proof: proof } = engine.merkle_proofs[0];
  for (const bad of [undefined, null, 5, '', proof.toUpperCase(), `${proof}0`, `0x${proof}`]) await assert.rejects(merkleProofMatches(bad, blockHash), /merkleProof is lowercase hexadecimal|merkleProof is 86 to 4,096 bytes/);
  for (const bad of [undefined, null, '', blockHash.toUpperCase().replace(/^[0-9]+$/, 'AB'), blockHash.slice(2), `${blockHash}00`]) await assert.rejects(merkleProofMatches(proof, bad), /blockHash is 64 lowercase hexadecimal characters/);
});
