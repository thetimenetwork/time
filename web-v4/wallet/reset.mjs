// A test network that was reset: a new chain under the same addresses (testnet/README.md, "Resetting a network"). The
// wallet keeps everything it stores under the network's id (its keys, its activity, the names it paid, the checkpoint of
// its light client), so what this browser kept of the old chain stays, out of the way, under the old id. Nothing here
// touches the page or the network.
//
// - The start screen says that the network was reset when this browser keeps accounts of another network and none of
//   this one (`resetSeen`), and offers to remove what it keeps of the other networks (`oldEntries`), and nothing else.
// - A page that is open while its network is reset fails to verify. Before it says so, it reads the site's trust file
//   again; when that names another network, it says that the network was reset (`trustReader`).

/// The network id in a key this wallet stores, or null for a key that is not one of the wallet's: every such key is a
/// name that begins with "timecurrency", then up to its first colon, then the 64 hexadecimal characters of the id.
const KEY = /^timecurrency[.a-z0-9-]*:([0-9a-f]{64})(?::|$)/;
export const networkOfKey = key => KEY.exec(String(key))?.[1] ?? null;
const VAULT = 'timecurrency.vault.v1:';

/// What this browser keeps of networks other than `networkId`: the keys of every entry, and the names of the accounts
/// (their vaults) by network.
export function elsewhere(keys, networkId) {
  const entries = [], accounts = new Map();
  for (const key of keys) {
    const id = networkOfKey(key); if (id === null || id === networkId) continue;
    entries.push(key);
    if (key.startsWith(VAULT)) { const name = key.slice(VAULT.length + 65); if (/^[a-z0-9_]{2,15}$/.test(name)) accounts.set(id, [...(accounts.get(id) || []), name]); }
  }
  return { entries, names: [...new Set([...accounts.values()].flat())].sort(), networks: [...accounts.keys()] };
}
/// Whether the start screen says that the test network was reset: this browser keeps accounts of another network, and
/// none of this one.
export function resetSeen(keys, networkId) {
  if (keys.some(key => key.startsWith(`${VAULT}${networkId}:`))) return false;
  return elsewhere(keys, networkId).names.length > 0;
}
/// The keys to remove when the person asks to forget the old network: every entry of the wallet stored under another
/// network's id, and nothing else.
export const oldEntries = (keys, networkId) => elsewhere(keys, networkId).entries;

const list = names => names.map(name => '@' + name).join(names.length === 2 ? ' and ' : ', ').replace(/, (@[a-z0-9_]+)$/, ', and $1');
/// The start screen's sentence.
export function resetWords(names) {
  const one = names.length === 1;
  return `The test network was reset. Your old account${one ? '' : 's'} ${list(names)} and ${one ? 'its' : 'their'} test seconds no longer exist. Create a new account. This browser still keeps the old keys; they open nothing now.`;
}
/// What "Open my account" says, in place of "no vault for this account", when the network was reset.
export const resetOpenWords = (name, names) => (names.includes(name) ? `The test network was reset: @${name} and its test seconds no longer exist. Create a new account.` : 'The test network was reset: the accounts this browser kept are of the old one, and no longer exist. Create a new account.');
/// What an open page says once it found that its network was reset.
export const RESET_RELOAD = 'The test network was reset. Reload this page.';

/// Reads the site's trust file again, at most once every `everyMs`, and says whether it names another network than
/// `networkId`. Once it did, it says so without asking again. A file that cannot be read says nothing: the page then
/// shows its own failure as before. `read()` returns the parsed file.
export function trustReader({ read, now = Date.now, everyMs = 30000 }) {
  let seen = false, last = -Infinity;
  return {
    async changed(networkId) {
      if (seen) return true;
      if (now() - last < everyMs) return false;
      last = now();
      try { const trust = await read(); seen = typeof trust?.network_id === 'string' && /^[0-9a-f]{64}$/.test(trust.network_id) && trust.network_id !== networkId; } catch { return false; }
      return seen;
    },
  };
}
