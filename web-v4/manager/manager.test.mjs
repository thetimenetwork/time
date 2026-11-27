import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { acceptRequest, changedRole, confirmMaster, masterKey, newProfile, prepareAccount, readRole, ROLES, walletOrigin } from './store.mjs';

const bundled = { exports: {} };
new Function('module', 'exports', await readFile(new URL('../wallet/vendor/argon2-4.12.0.umd.min.js', import.meta.url), 'utf8'))(bundled, bundled.exports);
const { argon2id } = bundled.exports;
const manager = 'https://vault.testnet.thetimenetwork.org', wallet = 'https://wallet.testnet.thetimenetwork.org';
const networkId = '0f'.repeat(32), name = 'walnut', opener = {};
const secrets = { signin: 'kerine-netoji-nesimo-vebine', spend: 'dabofi-gihaba-keleri-mibosi', recover: 'kerine netoji nesimo vebine kedafi' };
const common = { type: 'time:vault-request', v: 1, id: crypto.randomUUID(), networkId, name };
const save = { ...common, operation: 'save', secrets }, get = { ...common, operation: 'get', role: 'spend' };
const accept = (data, origin = wallet, source = opener) => acceptRequest({ data, origin, source }, manager, opener);

test('only a pinned wallet opener can request one exact action', () => {
  assert.equal(walletOrigin(manager), wallet);
  assert.equal(walletOrigin('http://localhost:8786'), 'http://localhost:8780');
  assert.equal(walletOrigin('http://127.0.0.1:8786'), null);
  for (const bad of [wallet, manager + '.example.com', 'http://localhost:8780', 'https://localhost:8786']) assert.equal(walletOrigin(bad), null);
  assert.equal(accept(save), save); assert.equal(accept(get), get);
  for (const rejected of [
    accept(save, manager), accept(save, wallet, {}), accept({ ...get, role: 'all' }), accept({ ...get, name: 'a/b' }),
    accept({ ...get, networkId: 'chain' }), accept({ ...get, id: 'any' }), accept({ ...get, operation: 'update' }),
    accept({ ...get, role: 'spend', secrets }), accept({ ...save, secrets: { ...secrets, recover: 'too short' } }),
    accept({ ...save, secrets: { ...secrets, spend: secrets.signin } }),
  ]) assert.equal(rejected, null);
});

test('enrollment, replay, single-purpose unlock, role rotation, tamper and incorrect factors', async () => {
  const profile = newProfile('AAAAAAAAAAAAAAAAAAAAAA'), device = crypto.getRandomValues(new Uint8Array(32));
  const passphrase = 'Unrelated lanterns gather sea glass';
  const master = await masterKey(profile, passphrase, device, argon2id);
  assert.equal(master.extractable, false);
  await confirmMaster(master, profile, true);
  const record = await prepareAccount(master, profile, save);
  for (const role of ROLES) {
    assert.equal(await readRole(master, profile, record, networkId, name, role), secrets[role]);
    assert.ok(!JSON.stringify({ profile, record }).includes(secrets[role]));
  }
  assert.ok(!JSON.stringify({ profile, record }).includes(passphrase));
  assert.equal(await prepareAccount(master, profile, save, record), record);
  await assert.rejects(prepareAccount(master, profile, { ...save, secrets: { ...secrets, signin: secrets.spend } }, record));
  assert.equal(await readRole(master, profile, record, networkId, name, 'signin'), secrets.signin);
  const rotated = await changedRole(master, profile, record, 'spend', 'another wallet payment password');
  assert.equal(await readRole(master, profile, rotated, networkId, name, 'spend'), 'another wallet payment password');
  assert.deepEqual(rotated.signin, record.signin);
  assert.deepEqual(rotated.recover, record.recover);
  await assert.rejects(changedRole(master, profile, record, 'recover', 'wrong words'));
  for (const altered of [
    { ...record, signin: record.spend }, { ...record, signin: { ...record.signin, iv: '00'.repeat(12) } },
    { ...record, name: 'other' }, { ...record, networkId: '42'.repeat(32) },
  ]) await assert.rejects(readRole(master, profile, altered, altered.networkId, altered.name, 'signin'));
  for (const [password, prf] of [[passphrase, new Uint8Array(32)], ['different master passphrase', device]]) {
    const wrong = await masterKey(profile, password, prf, argon2id);
    await assert.rejects(confirmMaster(wrong, profile, false));
    await assert.rejects(readRole(wrong, profile, record, networkId, name, 'recover'));
  }
  const retry = await masterKey(profile, passphrase, device, argon2id);
  await confirmMaster(retry, profile, false);
  assert.equal(await readRole(retry, profile, record, networkId, name, 'signin'), secrets.signin);
});
