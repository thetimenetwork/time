// Formatting for the explorer, and the checks every value from the API passes before it is shown.
// Everything the API answers is treated as written by an attacker: a value is used only after one
// of the tests below has accepted it, and free text only after `cleanText` has made it plain.
// The same holds for join.json, the page's optional file of this network's facts for new validators.
// Nothing here touches the page.

const MAX_U64 = 18446744073709551615n;
export const isHash = (value) => typeof value === 'string' && /^[0-9A-Fa-f]{64}$/.test(value);
export const isReference = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const isKey = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const isMicros = (value) => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= MAX_U64;
export const isAccountId = (value) => isMicros(value) && BigInt(value) < MAX_U64;
export const isHeight = (value) => typeof value === 'string' && /^[1-9][0-9]{0,15}$/.test(value);
export const isName = (value) => typeof value === 'string' && /^[a-z0-9_]{2,15}$/.test(value);
export const isCount = (value) => Number.isSafeInteger(value) && value >= 0;
/// A page cursor of the API: a height, or "height.index". Only this form is ever sent back.
export const isCursor = (value) => typeof value === 'string' && /^[1-9][0-9]{0,15}(?:\.(?:0|[1-9][0-9]{0,5}))?$/.test(value);

/// Free text from outside, made plain: every character that is not printable ASCII is written as
/// its code (so no control character, no right-to-left override, no look-alike letter reaches the
/// page), and it is cut at `max` characters. `lines` keeps line breaks, for data shown in a block
/// of its own. Returns the text and whether it was cut.
export function cleanText(value, max = 200, { lines = false } = {}) {
  const source = typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value);
  let out = '', cut = false, count = 0;
  for (const character of source) {
    if (count >= max) { cut = true; break; }
    const code = character.codePointAt(0);
    out += (code >= 0x20 && code <= 0x7e) || (lines && code === 0x0a) ? character : `\\u{${code.toString(16)}}`;
    count += 1;
  }
  return { text: out, cut };
}

const group = (digits, separator) => digits.replace(/\B(?=(\d{3})+(?!\d))/g, separator);
/// An amount of time as a person reads it: "2 h 5 min 3.25 s". Exact: nothing is rounded, the
/// seconds carry up to six decimals. `words` gives the unit names and separators (the strings
/// table). Returns null for anything that is not a whole number of microseconds.
export function formatAmount(micros, words = {}) {
  if (!isMicros(micros)) return null;
  const { h = 'h', min = 'min', s = 's', thousands = ',', decimal = '.' } = words;
  const total = BigInt(micros), hours = total / 3600000000n, minutes = (total / 60000000n) % 60n, seconds = (total / 1000000n) % 60n, fraction = total % 1000000n;
  const parts = [];
  if (hours > 0n) parts.push(`${group(hours.toString(), thousands)} ${h}`);
  if (minutes > 0n) parts.push(`${minutes} ${min}`);
  if (seconds > 0n || fraction > 0n || parts.length === 0) parts.push(`${seconds}${fraction > 0n ? decimal + fraction.toString().padStart(6, '0').replace(/0+$/, '') : ''} ${s}`);
  return parts.join(' ');
}
/// The same amount, exactly: "7,503,250,000 µs".
export function formatMicros(micros, words = {}) {
  if (!isMicros(micros)) return null;
  return `${group(micros, words.thousands ?? ',')} ${words.micros ?? 'µs'}`;
}
/// A whole number with digit groups, for heights and counts. Null if it is not one.
export function formatNumber(value, words = {}) {
  const text = typeof value === 'number' && isCount(value) ? String(value) : value;
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(text)) return null;
  return group(text, words.thousands ?? ',');
}
/// A share of a total in percent with two decimals, from two whole numbers: "33.33".
export function formatShare(part, total, words = {}) {
  if (!isMicros(part) || !isMicros(total) || BigInt(total) === 0n || BigInt(part) > BigInt(total)) return null;
  const hundredths = (BigInt(part) * 10000n) / BigInt(total);
  return `${hundredths / 100n}${words.decimal ?? '.'}${(hundredths % 100n).toString().padStart(2, '0')}`;
}

/// The moment a block was made, in milliseconds, from the API's microseconds. Null if unusable.
export function timeOfMicros(micros) {
  if (!isMicros(micros)) return null;
  const ms = Number(BigInt(micros) / 1000n);
  return ms <= 8640000000000000 ? ms : null;
}
/// The same from the API's text form ("2026-11-17T10:00:00.000000Z"). Null if it is not that form.
export function timeOfIso(text) {
  if (typeof text !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:.[0-9]{1,9})?Z$/.test(text)) return null;
  const ms = Date.parse(text.replace(/(.[0-9]{3})[0-9]+Z$/, '$1Z'));
  return Number.isFinite(ms) ? ms : null;
}
/// A moment in the reader's time zone, or in UTC when asked. `locale` and `timeZone` are for tests.
export function formatTime(ms, { utc = false, locale, timeZone } = {}) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || Math.abs(ms) > 8640000000000000) return null;
  const zone = utc ? 'UTC' : timeZone;
  try {
    return new Intl.DateTimeFormat(locale, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'short', ...(zone ? { timeZone: zone } : {}) }).format(new Date(ms));
  } catch { return null; }
}
/// How long ago a moment was, as a unit and a count: { unit: 'now' | 's' | 'min' | 'h' | 'd', count }.
/// A moment slightly in the future (clocks differ) counts as now; one further ahead is 'future'.
export function ago(ms, nowMs) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || typeof nowMs !== 'number') return null;
  const seconds = Math.floor((nowMs - ms) / 1000);
  if (seconds < -60) return { unit: 'future', count: 0 };
  if (seconds < 5) return { unit: 'now', count: 0 };
  if (seconds < 60) return { unit: 's', count: seconds };
  if (seconds < 3600) return { unit: 'min', count: Math.floor(seconds / 60) };
  if (seconds < 86400) return { unit: 'h', count: Math.floor(seconds / 3600) };
  return { unit: 'd', count: Math.floor(seconds / 86400) };
}
/// A long hexadecimal value shortened for a list: first eight and last six characters.
export function shortHex(value) {
  return typeof value === 'string' && /^[0-9A-Fa-f]{20,}$/.test(value) ? `${value.slice(0, 8)}…${value.slice(-6)}` : null;
}
/// Bytes written in hexadecimal, laid out for reading: four bytes to a group, thirty-two to a
/// line. Null if the text is not an even number of hexadecimal characters.
export function hexLines(value) {
  if (typeof value !== 'string' || value.length > 2 * 1024 * 1024 || !/^(?:[0-9A-Fa-f]{2})*$/.test(value)) return null;
  let out = '';
  for (let i = 0; i < value.length; i += 2) { const count = i / 2 + 1; out += value.slice(i, i + 2).toLowerCase() + (count % 32 === 0 ? '\n' : count % 4 === 0 ? ' ' : ''); }
  return out.trim();
}
/// Bytes in base64 as lines of hexadecimal, or null if the text is not base64.
export function hexOfBase64(value, decode = globalThis.atob) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length > 1024 * 1024) return null;
  let binary;
  try { binary = decode(value); } catch { return null; }
  let hex = '';
  for (let i = 0; i < binary.length; i++) hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
  return hexLines(hex);
}

// ------------------------------------------------------------------ this network's join.json
/// The only addresses outside the explorer that the page links to, both named by a network's join.json: the
/// wallet's origin, and the join script at its one path. An https: address with a plain host: lower-case labels
/// of letters, digits and hyphens, the last one starting with a letter (so that no browser reads the host as a
/// number address), an optional port, and nothing else (no user name, password, other path, query or fragment).
/// The internal links of the page are another rule (route.mjs, SAFE_HREF).
export const OUTSIDE_HREF = /^https:\/\/((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?(\/join\/join\.sh)?$/;
/// What an outside address is: 'origin' (a wallet), 'script' (the join script), or null for anything else.
/// The port is 1 to 65535 and never 443 written out, and the address must read back unchanged as a browser
/// parses it: what the page shows is where the link goes.
export function outsideAddress(value) {
  if (typeof value !== 'string' || value.length > 300) return null;
  const match = OUTSIDE_HREF.exec(value);
  if (!match || match[1].length > 253 || (match[2] !== undefined && (Number(match[2]) > 65535 || match[2] === '443'))) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.username || url.password || url.search || url.hash) return null;
  if (match[3]) return url.href === value ? 'script' : null;
  return url.origin === value && url.href === `${value}/` ? 'origin' : null;
}
/// An entry node of join.json: a node id (40 of 0-9 and a-f), an IPv4 address written plainly, and a port.
export function isPeer(value) {
  const match = typeof value === 'string' ? /^[0-9a-f]{40}@((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])):([1-9][0-9]{0,4})$/.exec(value) : null;
  return match !== null && Number(match[2]) <= 65535;
}
const JOIN_KEYS = ['script_url', 'wallet_url', 'chain_id', 'min_self_bond_micros', 'files', 'peers'], JOIN_FILES = ['node_sha256', 'cometbft_sha256', 'genesis_sha256'];
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
/// The text of join.json, read as everything from outside is: every value must pass its own strict test, no key
/// may be missing and none may be added. Returns a frozen copy of what passed, or null if anything did not. The
/// copy holds nothing but the values tested here.
export function readJoin(text) {
  if (typeof text !== 'string' || text.length > 16384) return null;
  let value;
  try { value = JSON.parse(text); } catch { return null; }
  if (!record(value) || Object.keys(value).some((key) => !JOIN_KEYS.includes(key) && !['pace', 'release_key', 'script_sha256', 'source_url'].includes(key)) || JOIN_KEYS.some((key) => !Object.hasOwn(value, key))) return null;
  // The release key, the script's hash and where the source publishes it (testnet/join.mjs, explorerJoin): shown as text.
  for (const key of ['release_key', 'script_sha256']) if (value[key] !== undefined && (typeof value[key] !== 'string' || !/^[0-9a-f]{64}$/.test(value[key]))) return null;
  if (value.source_url !== undefined && (typeof value.source_url !== 'string' || !/^https:\/\/github\.com\/[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}\/blob\/[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._/-]{1,200}$/.test(value.source_url))) return null;
  const { script_url: script, wallet_url: wallet, chain_id: chain, min_self_bond_micros: bond, files, peers, pace } = value;
  if (outsideAddress(script) !== 'script' || outsideAddress(wallet) !== 'origin') return null;
  if (typeof chain !== 'string' || !/^[a-z0-9-]{3,64}$/.test(chain)) return null;
  if (typeof bond !== 'string' || !/^[1-9][0-9]{0,15}$/.test(bond) || BigInt(bond) > 1000000000000000n) return null;
  if (!record(files) || Object.keys(files).length !== JOIN_FILES.length || !JOIN_FILES.every((key) => Object.hasOwn(files, key) && typeof files[key] === 'string' && /^[0-9a-f]{64}$/.test(files[key]))) return null;
  if (!Array.isArray(peers) || peers.length < 1 || peers.length > 8 || !peers.every(isPeer) || new Set(peers).size !== peers.length) return null;
  if (pace !== undefined && (typeof pace !== 'string' || !/^(?:[1-9][0-9]{2}ms|[1-5]s)$/.test(pace))) return null;
  return Object.freeze({ script_url: script, wallet_url: wallet, chain_id: chain, min_self_bond_micros: bond,
    files: Object.freeze(Object.fromEntries(JOIN_FILES.map((key) => [key, files[key]]))), peers: Object.freeze([...peers]), ...(pace === undefined ? {} : { pace }),
    ...Object.fromEntries(['release_key', 'script_sha256', 'source_url'].filter((key) => value[key] !== undefined).map((key) => [key, value[key]])) });
}
