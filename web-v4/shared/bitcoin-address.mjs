// Bitcoin addresses and receiving scripts, for the market of seconds against bitcoin (spec/market.md).
//
// An order of the market lists receiving scripts, in lowercase hexadecimal; a person knows an address. This module turns
// one into the other, for the five standard forms of spec/market.md, section 5.1, and no other, on the three Bitcoin
// networks the chain knows: `mainnet`, `testnet3`, `regtest`.
//
//   p2pkh   76a914 <20 bytes> 88ac   Base58Check, version 0x00 (mainnet), 0x6f (testnet3, regtest)
//   p2sh    a914 <20 bytes> 87       Base58Check, version 0x05 (mainnet), 0xc4 (testnet3, regtest)
//   p2wpkh  0014 <20 bytes>          Bech32 (BIP173), witness version 0; prefix bc, tb, bcrt
//   p2wsh   0020 <32 bytes>          Bech32 (BIP173), witness version 0
//   p2tr    5120 <32 bytes>          Bech32m (BIP350), witness version 1
//
// THIS CODE DECIDES WHERE A PERSON'S BITCOIN GOES. It refuses whatever it is not sure of: a wrong checksum, mixed case, a
// prefix of another network, a program of another length, a witness version above 1, a version-0 address with a Bech32m
// checksum or a version-1 address with a Bech32 one, a character or a space that does not belong. It never corrects.
//
// What it cannot know:
// - The legacy addresses (p2pkh, p2sh) of testnet3 and regtest are the same texts: the two networks share their
//   version bytes. Such an address is accepted on both.
// - Whether anyone holds the key of an address. A valid address that was typed wrong in a way its checksum does not see
//   (about one in a thousand million for Bech32 with more than four wrong characters, one in four thousand million for
//   Base58Check) is a valid address of nobody.
// - A Bech32 address written all in capitals is valid (BIP173) and is accepted; `scriptToAddress` writes small letters.
//   So `addressToScript(scriptToAddress(s))` is `s`, always, and `scriptToAddress(addressToScript(a))` is `a` in small
//   letters for a Bech32 address, and `a` itself for a Base58Check one.
//
// It also holds what a proof of payment (kind 54) needs of Bitcoin transactions: `stripWitness` (the serialization
// without witness data, which a proof must carry), `transactionId`, `transactionOutputs`, and `proofPayload`, which puts
// the payload of a proof together from what a Bitcoin node gives and calls no node itself.
//
// No dependency. SHA-256 is WebCrypto's (`crypto.subtle`), in a browser and under Node alike, so the functions that need
// a Base58Check checksum or a transaction id return promises.

const fail = (message) => { throw new Error(message); };

/// The Bitcoin networks, by the names the chain's genesis uses (`bitcoin.network`).
export const NETWORKS = Object.freeze(['mainnet', 'testnet3', 'regtest']);
/// The five forms of receiving script, by the names of spec/market.md, section 5.1, ascending.
export const FORMS = Object.freeze(['p2pkh', 'p2sh', 'p2tr', 'p2wpkh', 'p2wsh']);

const PARAMS = Object.freeze({
  mainnet: Object.freeze({ hrp: 'bc', p2pkh: 0x00, p2sh: 0x05 }),
  testnet3: Object.freeze({ hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 }),
  regtest: Object.freeze({ hrp: 'bcrt', p2pkh: 0x6f, p2sh: 0xc4 }),
});
function paramsOf(network) {
  if (typeof network !== 'string' || !Object.hasOwn(PARAMS, network)) fail(`Unknown Bitcoin network: name one of ${NETWORKS.join(', ')}`);
  return PARAMS[network];
}
/// The networks other than `network` on which `test` holds, as words for a refusal.
function elsewhere(network, test) {
  const names = NETWORKS.filter(name => name !== network && test(PARAMS[name]));
  return names.length ? names.join(' or ') : null;
}

// ---------------------------------------------------------------- hexadecimal and bytes
function hexOf(bytes) { let text = ''; for (const byte of bytes) text += byte.toString(16).padStart(2, '0'); return text; }
function bytesOf(hex, what) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) fail(`${what} is lowercase hexadecimal, two characters for each byte`);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}
async function sha256(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) fail('SHA-256 is not available: this needs WebCrypto (a page served over https or from localhost, or Node 19 or later)');
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}
async function sha256d(bytes) { return sha256(await sha256(bytes)); }

// ---------------------------------------------------------------- receiving scripts
const SCRIPT_FORMS = Object.freeze([
  ['p2pkh', /^76a914[0-9a-f]{40}88ac$/],
  ['p2sh', /^a914[0-9a-f]{40}87$/],
  ['p2wpkh', /^0014[0-9a-f]{40}$/],
  ['p2wsh', /^0020[0-9a-f]{64}$/],
  ['p2tr', /^5120[0-9a-f]{64}$/],
]);
const NOT_STANDARD = 'A receiving script is one of the five standard forms (p2pkh, p2sh, p2wpkh, p2wsh, p2tr), in lowercase hexadecimal';
/// The form of a receiving script in lowercase hexadecimal: 'p2pkh', 'p2sh', 'p2tr', 'p2wpkh' or 'p2wsh'. Throws for
/// anything else: another script, capital letters, a byte too many or too few. The engine's `market::form_of` over
/// `bitcoin_bridge::standard_script`, and its rule that a script is written in lowercase.
export function scriptForm(scriptHex) {
  if (typeof scriptHex !== 'string') fail(NOT_STANDARD);
  for (const [form, pattern] of SCRIPT_FORMS) if (pattern.test(scriptHex)) return form;
  return fail(NOT_STANDARD);
}

// ---------------------------------------------------------------- Bech32 and Bech32m (BIP173, BIP350)
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = Object.freeze([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]);
const CHECKSUM = Object.freeze({ bech32: 1, bech32m: 0x2bc830a3 });
function polymod(values) {
  let check = 1;
  for (const value of values) {
    const top = check >>> 25;
    check = ((check & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) check ^= GENERATOR[i];
  }
  return check >>> 0;
}
function expand(hrp) {
  const out = [];
  for (const letter of hrp) out.push(letter.charCodeAt(0) >>> 5);
  out.push(0);
  for (const letter of hrp) out.push(letter.charCodeAt(0) & 31);
  return out;
}
/// Reads a Bech32 or Bech32m text (BIP173, BIP350): `{ hrp, words, encoding }`, with `hrp` in small letters, `words` the
/// five-bit values of the data part without its checksum, and `encoding` 'bech32' or 'bech32m', whichever checksum the
/// text carries. Throws for every other text. Not an address yet: `addressToScript` reads what the words mean.
export function decodeBech32(text) {
  if (typeof text !== 'string') fail('A Bech32 text is a string');
  if (text.length > 90) fail('A Bech32 text has at most 90 characters');
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 33 || code > 126) fail('A Bech32 text holds a character that does not belong in one (a space, a control character, or a letter outside ASCII)');
  }
  const lower = text.toLowerCase();
  if (text !== lower && text !== text.toUpperCase()) fail('A Bech32 text is written all in small letters or all in capitals: this one mixes them');
  const at = lower.lastIndexOf('1');
  if (at < 0) fail('A Bech32 text has a prefix, the separator 1 and a data part: this one has no separator');
  if (at === 0) fail('A Bech32 text has a prefix before its separator: this one has none');
  if (at + 7 > lower.length) fail('A Bech32 text ends with a checksum of six characters: this one is too short');
  const hrp = lower.slice(0, at), words = [];
  for (const letter of lower.slice(at + 1)) {
    const value = CHARSET.indexOf(letter);
    if (value < 0) fail(`A Bech32 text holds a character that its alphabet does not have: ${letter}`);
    words.push(value);
  }
  const check = polymod([...expand(hrp), ...words]);
  const encoding = check === CHECKSUM.bech32 ? 'bech32' : check === CHECKSUM.bech32m ? 'bech32m' : fail('The checksum of this Bech32 text is wrong: a character was mistyped, left out or added');
  return { hrp, words: words.slice(0, -6), encoding };
}
/// Writes a Bech32 ('bech32') or Bech32m ('bech32m') text in small letters.
export function encodeBech32(hrp, words, encoding) {
  if (!Object.hasOwn(CHECKSUM, encoding)) fail('The encoding is bech32 or bech32m');
  if (typeof hrp !== 'string' || !/^[\x21-\x7e]{1,83}$/.test(hrp) || hrp !== hrp.toLowerCase()) fail('A Bech32 prefix is 1 to 83 printable ASCII characters, in small letters');
  if (!Array.isArray(words) || !words.every(word => Number.isInteger(word) && word >= 0 && word < 32)) fail('Bech32 data is a list of five-bit values');
  const values = [...expand(hrp), ...words];
  const check = polymod([...values, 0, 0, 0, 0, 0, 0]) ^ CHECKSUM[encoding];
  const all = [...words];
  for (let i = 0; i < 6; i++) all.push((check >>> (5 * (5 - i))) & 31);
  const text = `${hrp}1${all.map(word => CHARSET[word]).join('')}`;
  if (text.length > 90) fail('A Bech32 text has at most 90 characters');
  return text;
}
/// Five-bit values to bytes, as BIP173 has it: at most four bits of padding, all zero.
function fromWords(words) {
  const bytes = [];
  let acc = 0, bits = 0;
  for (const word of words) {
    acc = (acc << 5) | word; bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((acc >>> bits) & 0xff); acc &= (1 << bits) - 1; }
  }
  if (bits >= 5) fail('This address has more padding than Bech32 allows');
  if (acc !== 0) fail('This address has padding bits that are not zero');
  return Uint8Array.from(bytes);
}
function toWords(bytes) {
  const words = [];
  let acc = 0, bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; words.push((acc >>> bits) & 31); acc &= (1 << bits) - 1; }
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);
  return words;
}

function witnessScript(address, network) {
  const params = paramsOf(network);
  const { hrp, words, encoding } = decodeBech32(address);
  if (hrp !== params.hrp) {
    const other = elsewhere(network, p => p.hrp === hrp);
    fail(other ? `This is an address of Bitcoin ${other} (it begins with ${hrp}1); the network here is ${network}, whose addresses begin with ${params.hrp}1` : `This is not a Bitcoin ${network} address: those begin with ${params.hrp}1, and this one with ${hrp}1`);
  }
  if (words.length === 0) fail('This address has no data after its prefix');
  const version = words[0];
  if (version > 16) fail('This address names a witness version that does not exist');
  if (version > 1) fail(`This address is of witness version ${version}: the market takes versions 0 and 1 only (p2wpkh, p2wsh, p2tr)`);
  // The checksum says which rules the writer followed: a version-0 address under BIP350's checksum, or a version-1
  // address under BIP173's, is refused by every wallet, and here.
  if (version === 0 && encoding !== 'bech32') fail('A version-0 address (bc1q…) carries a Bech32 checksum (BIP173): this one carries a Bech32m checksum');
  if (version === 1 && encoding !== 'bech32m') fail('A version-1 address (bc1p…) carries a Bech32m checksum (BIP350): this one carries a Bech32 checksum');
  const program = fromWords(words.slice(1));
  if (version === 0 && program.length !== 20 && program.length !== 32) fail(`A version-0 address holds 20 or 32 bytes: this one holds ${program.length}`);
  if (version === 1 && program.length !== 32) fail(`A version-1 address (taproot) holds 32 bytes: this one holds ${program.length}`);
  return (version === 0 ? '00' : '51') + hexOf([program.length]) + hexOf(program);
}

// ---------------------------------------------------------------- Base58Check
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Bytes(text) {
  let value = 0n, zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros += 1;
  for (const letter of text) {
    const digit = BASE58.indexOf(letter);
    if (digit < 0) fail(`This address holds a character that Base58 does not have: ${letter === ' ' ? 'a space' : letter}`);
    value = value * 58n + BigInt(digit);
  }
  const body = [];
  for (; value > 0n; value >>= 8n) body.unshift(Number(value & 0xffn));
  return Uint8Array.from([...new Array(zeros).fill(0), ...body]);
}
function base58Text(bytes) {
  let value = 0n, zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let text = '';
  for (; value > 0n; value /= 58n) text = BASE58[Number(value % 58n)] + text;
  return '1'.repeat(zeros) + text;
}
async function legacyScript(address, network) {
  const params = paramsOf(network);
  if (address.length < 26 || address.length > 35) fail('A Base58Check address has 26 to 35 characters');
  const bytes = base58Bytes(address);
  if (bytes.length !== 25) fail('A Base58Check address holds 25 bytes: a version, a hash of 20 bytes and a checksum of 4');
  const check = await sha256d(bytes.subarray(0, 21));
  if (!check.subarray(0, 4).every((byte, i) => byte === bytes[21 + i])) fail('The checksum of this address is wrong: a character was mistyped, left out or added');
  const version = bytes[0], hash = hexOf(bytes.subarray(1, 21));
  if (version === params.p2pkh) return `76a914${hash}88ac`;
  if (version === params.p2sh) return `a914${hash}87`;
  const other = elsewhere(network, p => p.p2pkh === version || p.p2sh === version);
  return fail(other ? `This is an address of Bitcoin ${other}; the network here is ${network}` : `This is not a Bitcoin ${network} address (its version byte is 0x${hexOf([version])})`);
}

// ---------------------------------------------------------------- addresses
/// The receiving script of a Bitcoin address on `network` ('mainnet', 'testnet3' or 'regtest'), in lowercase
/// hexadecimal. Throws, with the reason, for a text that is not an address of one of the five standard forms on that
/// network. Returns a promise (a Base58Check checksum is two SHA-256).
export async function addressToScript(address, network) {
  paramsOf(network);
  if (typeof address !== 'string' || address.length === 0) fail('An address is a text');
  if (/\s/.test(address)) fail('An address holds no space and no line break: remove them and check the address again');
  // An address that begins with 1, 3, m, n or 2 is a Base58Check one or nothing: no Bech32 prefix begins so.
  const script = /^[13mn2]/.test(address) ? await legacyScript(address, network) : witnessScript(address, network);
  scriptForm(script);
  if (await scriptToAddress(script, network) !== (/^[13mn2]/.test(address) ? address : address.toLowerCase())) fail('This address is not written the one way an address is written');
  return script;
}
/// The address of a receiving script (lowercase hexadecimal, one of the five standard forms) on `network`. Bech32
/// addresses are written in small letters. Returns a promise.
export async function scriptToAddress(scriptHex, network) {
  const params = paramsOf(network), form = scriptForm(scriptHex);
  if (form === 'p2pkh' || form === 'p2sh') {
    const body = Uint8Array.from([params[form], ...bytesOf(form === 'p2pkh' ? scriptHex.slice(6, 46) : scriptHex.slice(4, 44), 'A receiving script')]);
    return base58Text(Uint8Array.from([...body, ...(await sha256d(body)).subarray(0, 4)]));
  }
  const program = bytesOf(scriptHex.slice(4), 'A receiving script');
  return encodeBech32(params.hrp, [form === 'p2tr' ? 1 : 0, ...toWords(program)], form === 'p2tr' ? 'bech32m' : 'bech32');
}

// ---------------------------------------------------------------- a payment's transaction, for a proof (kind 54)
// A proof of payment (spec/market.md, 5.2 and 6.5) carries the payment's transaction and the coinbase transaction of its
// block, each serialized WITHOUT witness data, and a Merkle proof of the two. A Bitcoin node gives transactions with
// their witness data. `stripWitness` removes it, and `proofPayload` puts a proof together from what a node gives.
const MAX_TRANSACTION_BYTES = 4_000_000, MAX_PAYMENT_BYTES = 100_000, MAX_COINBASE_BYTES = 150_000, MAX_MERKLE_PROOF_BYTES = 4096, MAX_SATS = 2_100_000_000_000_000n;
/// Reads a size as Bitcoin writes one (1, 3 or 5 bytes here), in its shortest form only. Returns [value, next offset].
function sizeAt(bytes, at, short) {
  if (at >= bytes.length) short();
  const first = bytes[at];
  if (first < 0xfd) return [first, at + 1];
  if (first === 0xff) fail('This is not Bitcoin data: it names a size nothing has');
  const width = first === 0xfd ? 2 : 4;
  if (width > bytes.length - at - 1) short();
  let value = 0;
  for (let i = width; i >= 1; i--) value = value * 256 + bytes[at + i];
  if (value < (width === 2 ? 0xfd : 0x10000)) fail('A size is written in a longer form than needed: this is not serialized the one way Bitcoin data is');
  return [value, at + 1 + width];
}
/// Reads a serialized Bitcoin transaction strictly, to its last byte: its bytes without witness data, its inputs
/// (the output each spends) and its outputs.
function readTransaction(bytes) {
  const short = () => fail('This is not a whole Bitcoin transaction: it ends too early');
  let at = 0;
  const take = (count) => { if (count > bytes.length - at) short(); at += count; return at - count; };
  const size = () => { const [value, next] = sizeAt(bytes, at, short); at = next; return value; };
  if (bytes.length > MAX_TRANSACTION_BYTES) fail('This is larger than any Bitcoin transaction');
  take(4);
  const witness = bytes[at] === 0x00;
  if (witness) {
    take(1);
    if (bytes[take(1)] !== 0x01) fail('This is not a Bitcoin transaction: it has no input, or a marker this code does not know');
  }
  const bodyStart = at, count = size(), inputs = [], outputs = [];
  if (count === 0) fail('A Bitcoin transaction has at least one input');
  if (count > (bytes.length - at) / 41) short();
  for (let i = 0; i < count; i++) {
    const start = take(36);
    inputs.push(hexOf(bytes.subarray(start, start + 36)));
    take(size()); take(4);
  }
  const outputCount = size();
  if (outputCount === 0) fail('A Bitcoin transaction has at least one output');
  if (outputCount > (bytes.length - at) / 9) short();
  for (let i = 0; i < outputCount; i++) {
    const start = take(8);
    let sats = 0n;
    for (let j = 7; j >= 0; j--) sats = (sats << 8n) | BigInt(bytes[start + j]);
    const length = size(), script = take(length);
    outputs.push({ sats, script: hexOf(bytes.subarray(script, script + length)) });
  }
  const bodyEnd = at;
  if (witness) {
    let some = false;
    for (let i = 0; i < count; i++) {
      const items = size();
      if (items > bytes.length - at) short();
      if (items > 0) some = true;
      for (let j = 0; j < items; j++) take(size());
    }
    if (!some) fail('This transaction is marked as having witness data and has none: it is not serialized the one way a transaction is');
  }
  const lock = take(4);
  if (at !== bytes.length) fail('This is not one Bitcoin transaction: bytes follow its end');
  let bare = bytes;
  if (witness) {
    bare = new Uint8Array(4 + (bodyEnd - bodyStart) + 4);
    bare.set(bytes.subarray(0, 4), 0); bare.set(bytes.subarray(bodyStart, bodyEnd), 4); bare.set(bytes.subarray(lock, lock + 4), 4 + bodyEnd - bodyStart);
  }
  return { bare, inputs, outputs };
}
/// A serialized Bitcoin transaction (lowercase hexadecimal) without its witness data: the marker and flag after the
/// version and the witness stacks before the lock time are removed. A transaction serialized without witness data comes
/// back as it is. The transaction id is the same before and after: it never covered the witness. Throws for anything
/// that is not exactly one transaction serialized the canonical way.
export function stripWitness(transactionHex) {
  return hexOf(readTransaction(bytesOf(transactionHex, 'A Bitcoin transaction')).bare);
}
/// The id of a serialized Bitcoin transaction (with or without witness data), as Bitcoin software prints it: the double
/// SHA-256 of its serialization without witness data, byte-reversed, in lowercase hexadecimal. Returns a promise.
export async function transactionId(transactionHex) {
  return hexOf((await sha256d(readTransaction(bytesOf(transactionHex, 'A Bitcoin transaction')).bare)).reverse());
}
/// The outputs of a serialized Bitcoin transaction, in their order: `[{ sats, script }, …]`, with `sats` a decimal
/// string and `script` lowercase hexadecimal. The place of an output in the list is its `vout`.
export function transactionOutputs(transactionHex) {
  return readTransaction(bytesOf(transactionHex, 'A Bitcoin transaction')).outputs.map(({ sats, script }) => ({ sats: sats.toString(), script }));
}
const NULL_INPUT = `${'00'.repeat(32)}ffffffff`;
/// A transaction as a proof carries it (bitcoin-bridge/src/payment.rs, `carried`), from one a node gave.
function carried(transactionHex, what, most, least) {
  const read = readTransaction(bytesOf(transactionHex, `The ${what}`));
  if (read.bare.length > most) fail(`The ${what} is larger than a proof may carry (${most.toLocaleString('en-US')} bytes without its witness data)`);
  if (read.bare.length < least) fail(`The ${what} is too short to be proven (64 bytes or fewer)`);
  if (read.outputs.reduce((sum, output) => sum + output.sats, 0n) > MAX_SATS) fail(`The outputs of the ${what} sum to more bitcoin than exists`);
  return read;
}
/// Reads a Merkle proof as Bitcoin Core's gettxoutproof writes one (a block header, the number of transactions in the
/// block, hashes, and flag bits: BIP37's partial Merkle tree), strictly, and checks it: it is for the block `blockHash`
/// and its hashes and flags give the Merkle root of that header. Returns the transactions it proves to be in the block,
/// in the block's order: `[{ hash, place }, …]`, `hash` being the transaction id as its bytes stand (not reversed, as
/// Bitcoin software prints an id) and `place` the transaction's place in the block, from 0. Returns a promise. The sizes
/// are the engine's for a proof of payment: at most 4,096 bytes and 64 hashes.
export async function merkleProofMatches(merkleProofHex, blockHash) {
  if (typeof blockHash !== 'string' || !/^[0-9a-f]{64}$/.test(blockHash)) fail('blockHash is 64 lowercase hexadecimal characters');
  const proof = bytesOf(merkleProofHex, 'merkleProof');
  const short = () => fail('merkleProof is not a whole Merkle proof: it ends too early'), wrong = (why) => fail(`merkleProof is not a Merkle proof Bitcoin software writes: ${why}`);
  if (proof.length < 86 || proof.length > MAX_MERKLE_PROOF_BYTES) fail('merkleProof is 86 to 4,096 bytes: what gettxoutproof returns for the two transaction ids');
  if (hexOf((await sha256d(proof.subarray(0, 80))).reverse()) !== blockHash) fail('merkleProof is for another block than blockHash');
  const total = proof[80] + 256 * proof[81] + 65536 * proof[82] + 16777216 * proof[83];
  // A block holds at most 4,000,000 weight units and a transaction weighs at least 240.
  if (total < 1 || total > 16666) wrong('it names a number of transactions no block has');
  const [hashCount, afterCount] = sizeAt(proof, 84, short);
  if (hashCount < 1 || hashCount > 64 || hashCount > total || afterCount + 32 * hashCount >= proof.length) wrong('it holds a number of hashes that no proof of two transactions has');
  const [flagCount, afterFlags] = sizeAt(proof, afterCount + 32 * hashCount, short);
  if (flagCount < 1 || flagCount > 1024 || afterFlags + flagCount !== proof.length) wrong('it does not end where its own sizes say');
  if (flagCount * 8 < hashCount) wrong('it has fewer flag bits than hashes');
  const width = (height) => Math.floor((total + 2 ** height - 1) / 2 ** height);
  let height = 0, usedHashes = 0, usedBits = 0;
  while (width(height) > 1) height += 1;
  const matched = [];
  const walk = async (level, place) => {
    if (usedBits >= flagCount * 8) wrong('its flag bits run out');
    const above = (proof[afterFlags + (usedBits >> 3)] >> (usedBits & 7)) & 1;
    usedBits += 1;
    if (level === 0 || !above) {
      if (usedHashes >= hashCount) wrong('its hashes run out');
      const hash = proof.subarray(afterCount + 32 * usedHashes, afterCount + 32 * usedHashes + 32);
      usedHashes += 1;
      if (level === 0 && above) matched.push({ hash: hexOf(hash), place });
      return hash;
    }
    const left = await walk(level - 1, place * 2);
    let right = left;
    if (place * 2 + 1 < width(level - 1)) {
      right = await walk(level - 1, place * 2 + 1);
      // Two equal halves would let one transaction stand at two places.
      if (hexOf(right) === hexOf(left)) wrong('two halves of its tree are the same');
    }
    const pair = new Uint8Array(64);
    pair.set(left, 0); pair.set(right, 32);
    return sha256d(pair);
  };
  const root = await walk(height, 0);
  // The bits of the last flag byte that nothing uses are not read, as Bitcoin software does not read them.
  if (usedHashes !== hashCount || Math.ceil(usedBits / 8) !== flagCount) wrong('it holds hashes or flag bytes that nothing uses');
  if (hexOf(root) !== hexOf(proof.subarray(36, 68))) fail('merkleProof does not lead to the Merkle root of its block: it does not prove that its transactions are in the block');
  return matched;
}
/// The payload of a proof of payment (kind 54) from what a Bitcoin node gives. It calls no node. With Bitcoin Core:
///
///   getblock <block hash> 2                 → `tx[0].hex` is the block's coinbase transaction, `tx[0].txid` its id;
///                                             the payment is the entry whose `txid` is the payment's (its `hex`)
///   getrawtransaction <txid> false <block hash>   gives the same `hex` for one transaction
///   gettxoutproof '["<coinbase txid>","<txid>"]' <block hash>   → the Merkle proof of the two
///
/// Arguments, in one object:
///   fill         the fill's id (a decimal string, a BigInt or a safe integer)
///   script       the fill's receiving script, lowercase hexadecimal, read from the chain
///   blockHash    the hash of the block the payment is in, as Bitcoin software prints it
///   transaction  the payment, lowercase hexadecimal, with or without witness data
///   coinbase     the coinbase transaction of that block, likewise
///   merkleProof  what gettxoutproof returned
///   vout         optional: which output to prove. Left out, the one output that pays `script` is found; a transaction
///                with several such outputs needs it named, one proof for each.
/// Both transactions lose their witness data. Refused here, before anything is signed: a payment that does not pay
/// `script` at that output, a coinbase that is not one, a Merkle proof that is not for `blockHash`, does not lead to that
/// block's Merkle root, or does not prove exactly the two transactions with the coinbase at the first place of the block,
/// and anything the engine's size bounds refuse. What only the chain can say
/// stays unsaid: whether the block is on the chain of most work with the confirmations the fill asks, and whether the
/// output has paid already. Returns a promise of `{ block_hash, coinbase, fill, merkle_proof, transaction, vout }`.
export async function proofPayload(given) {
  const NAMES = ['fill', 'script', 'blockHash', 'transaction', 'coinbase', 'merkleProof', 'vout'];
  if (!given || typeof given !== 'object' || Array.isArray(given)) fail(`proofPayload takes one object of named arguments: ${NAMES.join(', ')}`);
  for (const name of Object.keys(given)) if (!NAMES.includes(name)) fail(`proofPayload has no argument ${name}: it takes ${NAMES.join(', ')}`);
  for (const name of NAMES.slice(0, 6)) if (given[name] === undefined || given[name] === null) fail(`proofPayload needs ${name}`);
  let fill = given.fill;
  if (typeof fill === 'bigint' || (typeof fill === 'number' && Number.isSafeInteger(fill))) fill = fill.toString();
  if (typeof fill !== 'string' || !/^[1-9][0-9]{0,19}$/.test(fill) || BigInt(fill) >= 1n << 64n) fail('fill is the id of a fill: a whole number from 1');
  scriptForm(given.script);
  if (typeof given.blockHash !== 'string' || !/^[0-9a-f]{64}$/.test(given.blockHash)) fail('blockHash is 64 lowercase hexadecimal characters');
  // The payment is longer than 64 bytes (a shorter one could pass for a node of the Merkle tree); the coinbase may be
  // as short as a miner makes it.
  const payment = carried(given.transaction, 'payment', MAX_PAYMENT_BYTES, 65), coinbase = carried(given.coinbase, 'coinbase transaction', MAX_COINBASE_BYTES, 0);
  if (coinbase.inputs.length !== 1 || coinbase.inputs[0] !== NULL_INPUT) fail('coinbase is the first transaction of the block, which spends nothing: this is another transaction');
  if (payment.inputs.includes(NULL_INPUT)) fail('The payment is a coinbase transaction, or spends nothing: it cannot pay for a fill');
  if (new Set(payment.inputs).size !== payment.inputs.length) fail('The payment spends one output twice');
  const paying = payment.outputs.flatMap((output, index) => output.script === given.script ? [index] : []);
  let vout = given.vout;
  if (vout === undefined || vout === null) {
    if (paying.length === 0) fail('No output of this transaction pays the receiving script of the fill');
    if (paying.length > 1) fail(`Outputs ${paying.join(', ')} of this transaction pay the receiving script of the fill: name one with vout, and prove each with a proof of its own`);
    vout = paying[0];
  } else {
    if (typeof vout === 'string' && /^(0|[1-9][0-9]{0,9})$/.test(vout)) vout = Number(vout);
    if (typeof vout === 'bigint' && vout >= 0n && vout <= 0xffffffffn) vout = Number(vout);
    if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) fail('vout is the place of an output: a whole number from 0');
    if (vout >= payment.outputs.length) fail(`This transaction has ${payment.outputs.length} outputs: it has no output ${vout}`);
    if (payment.outputs[vout].script !== given.script) fail(`Output ${vout} of this transaction does not pay the receiving script of the fill${paying.length ? `: output ${paying.join(', ')} does` : ', and no other output does'}`);
  }
  if (payment.outputs[vout].sats < 1n) fail('The output that pays the fill has no value');
  const matched = await merkleProofMatches(given.merkleProof, given.blockHash);
  const ids = [hexOf(await sha256d(coinbase.bare)), hexOf(await sha256d(payment.bare))];
  if (!matched.some(match => match.hash === ids[0])) fail('merkleProof does not hold the coinbase transaction: ask gettxoutproof for both ids, the coinbase and the payment');
  if (!matched.some(match => match.hash === ids[1])) fail('merkleProof does not hold the payment: ask gettxoutproof for both ids, the coinbase and the payment');
  if (matched.length !== 2) fail(`merkleProof is a proof of ${matched.length} transactions: a proof of payment is one of exactly two, the coinbase and the payment`);
  if (matched[0].hash !== ids[0] || matched[0].place !== 0) fail('The transaction given as coinbase is not at the first place of the block');
  return { block_hash: given.blockHash, coinbase: hexOf(coinbase.bare), fill, merkle_proof: given.merkleProof, transaction: hexOf(payment.bare), vout: String(vout) };
}
