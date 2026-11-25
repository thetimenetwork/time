// The shop's own full node: a second witness for large payments.
//
// The light client (light-client.mjs, verifiedReceipt in server.mjs) accepts what validators
// holding more than two thirds of the voting power signed. It checks signatures and Merkle
// proofs, not the execution of the transactions: validators above two thirds could sign a block
// whose payment the rules refuse, and the light client would accept its receipt. A full node
// runs every block itself; the time-node-v5 application stops at the first block it cannot
// execute. So for an order from `aboveMicros` on, the merchant's own full node must report the
// same payment committed as well (README.md, "Large payments: confirm with your own node").
//
// The node is reached directly, at its own RPC address or through an rpc function the merchant
// supplies. Never through the gateway: the light client checks the gateway's answers, but the
// gateway could answer anything, and this check must not depend on it.
//
// What the node must report (CometBFT RPC):
// - /status: the network of the trust manifest, and a height above the payment's block H. The
//   node has then accepted block H+1, whose header commits to the results of block H; it accepts
//   that header only when those are the results of its own execution of H.
// - /tx?hash=0x... (needs the node's transaction index) or, failing that, /block?height=H and
//   /block_results?height=H: the same transaction bytes and hash, at height H, result code 0.
// No answer within the timeout, an unreachable or lagging node, or any other answer refuses.
import { createHash } from 'node:crypto';

// UNAVAILABLE: no usable answer (down, too slow, behind, block no longer kept); a later attempt
// can succeed. MISMATCH: the node answered and contradicts the light-client receipt; find out why
// before shipping anything.
export const OWN_NODE_UNAVAILABLE = 'OWN_NODE_UNAVAILABLE';
export const OWN_NODE_MISMATCH = 'OWN_NODE_MISMATCH';
export class OwnNodeRefusal extends Error {
  constructor(code, reason) {
    const lead = code === OWN_NODE_MISMATCH ? 'Own node contradicts the light-client receipt; the order stays unsettled' : 'Own node has not confirmed the payment; the order stays unsettled, retry later';
    super(`${lead}: ${String(reason).slice(0, 150)}`);
    this.name = 'OwnNodeRefusal'; this.code = code; this.reason = String(reason);
  }
}
const unavailable = reason => new OwnNodeRefusal(OWN_NODE_UNAVAILABLE, reason);
const mismatch = reason => new OwnNodeRefusal(OWN_NODE_MISMATCH, reason);

const MAX_U64 = 18446744073709551615n, MAX_ANSWER = 16 * 1024 * 1024;
const METHODS = new Set(['/status', '/tx', '/block', '/block_results']);
const fail = message => { throw new Error(message); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex').toUpperCase();
const said = error => String(error?.reason ?? error?.message ?? error).slice(0, 100);
function heightOf(value) {
  if (Number.isSafeInteger(value) && value > 0) return String(value);
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) ? value : null;
}
function bytesOf(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length && bytes.toString('base64') === value ? bytes : null;
}
// ABCI result code. CometBFT leaves a zero code out of the JSON, so a missing key is 0; a key
// that is present must hold a number (null, text or anything else is not a success).
function codeOf(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) return { malformed: true };
  if (!Object.hasOwn(result, 'code')) return { code: 0 };
  return Number.isSafeInteger(result.code) && result.code >= 0 ? { code: result.code } : { code: JSON.stringify(result.code) ?? String(result.code) };
}

// Why a connection failed, without an address: the system's code (ECONNREFUSED), or the words with any address taken out.
function connectionProblem(error) {
  const code = String(error?.cause?.code ?? '');
  if (/^[A-Z][A-Z0-9_]{1,40}$/.test(code)) return code;
  return String(error?.cause?.message ?? said(error)).replace(/\[[0-9A-Fa-f:.]+\](?::\d{1,5})?|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b|\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b/g, 'the node').slice(0, 100);
}
function nodeUrl(url) {
  let base = null;
  try { if (typeof url === 'string') base = new URL(url); } catch {}
  if (!base || !['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) fail('ownNode.url must be the plain http(s) RPC address of your own full node, such as http://127.0.0.1:26757/');
  if (!base.pathname.endsWith('/')) base.pathname += '/';
  return base;
}
// CometBFT JSON-RPC over HTTP GET: the four read-only methods of the check, no redirects,
// bounded answers. The error text of the node (for example "tx (...) not found") is kept.
export function ownNodeRpc(url) {
  const base = nodeUrl(url);
  return async (method, parameters = {}, { signal } = {}) => {
    if (!METHODS.has(method)) fail('RPC method not used by the own-node check');
    const target = new URL(method.slice(1), base);
    for (const [key, value] of Object.entries(parameters)) target.searchParams.set(key, String(value));
    let response;
    // A refusal names no address: the node's is the merchant's own business (endpoint, on the alerts), and the words
    // of a failed connection can hold one too.
    try { response = await fetch(target, { redirect: 'error', signal, headers: { accept: 'application/json' } }); }
    catch (error) { fail(`unreachable (${connectionProblem(error)})`); }
    let size = 0; const chunks = [];
    for await (const chunk of response.body ?? []) { size += chunk.length; if (size > MAX_ANSWER) fail('answer exceeds 16 MiB'); chunks.push(chunk); }
    let answer = null;
    try { answer = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
    if (answer?.error) fail(String(answer.error.data || answer.error.message || 'JSON-RPC error'));
    if (!response.ok || !answer?.result || typeof answer.result !== 'object') fail(`HTTP ${response.status} without a JSON-RPC result`);
    return answer.result;
  };
}

// {url} or {rpc}, the chainId the node must be on (createV4Servers sets it from the pinned
// manifest), aboveMicros (default '0': every order), timeoutMs (default 5000) and retryAfterMs
// (default 2000: how long an order is not checked again after the node could not confirm it).
export function ownNodeOptions(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('ownNode must be an object such as {url, chainId, aboveMicros}');
  if (Object.keys(options).some(key => !['url', 'rpc', 'chainId', 'aboveMicros', 'timeoutMs', 'retryAfterMs'].includes(key))) fail('ownNode takes url or rpc, chainId, aboveMicros, timeoutMs and retryAfterMs only');
  if ((options.url === undefined) === (options.rpc === undefined)) fail('ownNode needs exactly one of url (the RPC address of your own full node) or rpc (a function that calls it)');
  if (options.rpc !== undefined && typeof options.rpc !== 'function') fail('ownNode.rpc must be a function (method, parameters) => result');
  if (typeof options.chainId !== 'string' || !/^[\x21-\x7e]{1,50}$/.test(options.chainId)) fail('ownNode.chainId must be the CometBFT chain id of the network (createV4Servers sets it from the pinned manifest)');
  const rpc = options.rpc ?? ownNodeRpc(options.url), endpoint = options.rpc ? 'rpc function' : nodeUrl(options.url).href;
  const aboveMicros = options.aboveMicros === undefined ? '0' : Number.isSafeInteger(options.aboveMicros) && options.aboveMicros >= 0 ? String(options.aboveMicros) : options.aboveMicros;
  if (typeof aboveMicros !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(aboveMicros) || BigInt(aboveMicros) > MAX_U64) fail('ownNode.aboveMicros must be an amount in whole microseconds (0: every order)');
  const timeoutMs = options.timeoutMs === undefined ? 5000 : options.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60000) fail('ownNode.timeoutMs must be a whole number of milliseconds from 100 to 60000');
  const retryAfterMs = options.retryAfterMs === undefined ? 2000 : options.retryAfterMs;
  if (!Number.isSafeInteger(retryAfterMs) || retryAfterMs < 0 || retryAfterMs > 60000) fail('ownNode.retryAfterMs must be a whole number of milliseconds from 0 to 60000');
  return Object.freeze({ rpc, endpoint, aboveMicros, timeoutMs, retryAfterMs, chainId: options.chainId });
}

// The node's indexed record of the transaction (/tx).
function fromIndex(found, hash, raw, height) {
  const bytes = bytesOf(found?.tx), at = heightOf(found?.height), result = codeOf(found?.tx_result);
  if (!bytes || typeof found.hash !== 'string' || !at || result.malformed) throw unavailable('unexpected /tx answer');
  if (found.hash.toUpperCase() !== hash || !bytes.equals(raw)) throw mismatch('the node returned other transaction bytes for this hash');
  if (at !== height) throw mismatch(`the node has the transaction at height ${at}, the light client at ${height}`);
  if (result.code !== 0) throw mismatch(`the node reports result code ${result.code} for the transaction`);
}
// The node's block at the light client's height must hold the same bytes (/block) ...
function fromBlock(block, raw, height) {
  const data = block?.block?.data, txs = data?.txs ?? [];
  if (heightOf(block?.block?.header?.height) !== height || !data || typeof data !== 'object' || !Array.isArray(txs)) throw unavailable(`unexpected /block answer for height ${height}`);
  const index = txs.findIndex(tx => bytesOf(tx)?.equals(raw));
  if (index < 0) throw mismatch(`the node's block ${height} does not contain the transaction`);
  return { index, count: txs.length };
}
// ... with a successful result in that block's results (/block_results).
function fromResults(results, { index, count }, height) {
  const list = results?.txs_results ?? [];
  if (heightOf(results?.height) !== height || !Array.isArray(list) || list.length !== count) throw unavailable(`unexpected /block_results answer for height ${height}`);
  const result = codeOf(list[index]);
  if (result.malformed) throw unavailable(`unexpected /block_results answer for height ${height}`);
  if (result.code !== 0) throw mismatch(`the node reports result code ${result.code} for the transaction`);
}

export function createOwnNode(options) {
  const { rpc, endpoint, aboveMicros, timeoutMs, retryAfterMs, chainId } = ownNodeOptions(options), threshold = BigInt(aboveMicros);
  // Resolves when the node reports this payment committed successfully; throws otherwise.
  async function confirm({ hash, rawHex, height }) {
    if (typeof hash !== 'string' || !/^[A-Fa-f0-9]{64}$/.test(hash)) fail('The own-node check needs the payment transaction hash');
    if (typeof rawHex !== 'string' || !rawHex || rawHex.length % 2 || !/^[0-9A-Fa-f]+$/.test(rawHex)) fail('The own-node check needs the transaction bytes the light client proved');
    hash = hash.toUpperCase(); const raw = Buffer.from(rawHex, 'hex');
    if (sha256(raw) !== hash) fail('The light-client receipt bytes are not those of the payment hash');
    if (heightOf(height) !== height) fail('The own-node check needs the height the light client proved');
    // One deadline for the whole check; a request still running at the end is aborted.
    const deadline = new AbortController(), timer = setTimeout(() => deadline.abort(), timeoutMs);
    const late = new Promise((_, reject) => deadline.signal.addEventListener('abort', () => reject(unavailable(`no answer within ${timeoutMs} ms`)), { once: true }));
    late.catch(() => {});
    const ask = async (method, parameters) => {
      try { return await Promise.race([Promise.resolve().then(() => rpc(method, parameters, { signal: deadline.signal })), late]); }
      catch (error) { throw deadline.signal.aborted ? unavailable(`no answer within ${timeoutMs} ms`) : error; }
    };
    try {
      let status;
      try { status = await ask('/status', {}); } catch (error) { throw error instanceof OwnNodeRefusal ? error : unavailable(`no status from the node: ${said(error)}`); }
      const tip = heightOf(status?.sync_info?.latest_block_height);
      if (!tip) throw unavailable('unexpected /status answer');
      if (status?.node_info?.network !== chainId) throw mismatch(`the node is on network ${JSON.stringify(String(status?.node_info?.network).slice(0, 50))}, the trust manifest names ${chainId}`);
      if (BigInt(tip) <= BigInt(height)) throw unavailable(`the node is at height ${tip} and has not yet accepted block ${BigInt(height) + 1n}, the one after the payment's block ${height}`);
      // The transaction index, when the node keeps one and has indexed the payment.
      let missing;
      try { fromIndex(await ask('/tx', { hash: '0x' + hash }), hash, raw, height); return { path: 'tx-index', height, nodeHeight: tip }; }
      catch (error) { if (deadline.signal.aborted || error instanceof OwnNodeRefusal && error.code === OWN_NODE_MISMATCH) throw error; missing = said(error); }
      // Otherwise the block the light client names, and its results.
      let block, results;
      try { block = await ask('/block', { height }); } catch (error) { throw error instanceof OwnNodeRefusal ? error : unavailable(`the node has neither indexed the transaction (${missing}) nor kept block ${height} (${said(error)})`); }
      const found = fromBlock(block, raw, height);
      try { results = await ask('/block_results', { height }); } catch (error) { throw error instanceof OwnNodeRefusal ? error : unavailable(`no results of block ${height} from the node: ${said(error)}`); }
      fromResults(results, found, height);
      return { path: 'block', height, nodeHeight: tip };
    } finally { clearTimeout(timer); deadline.abort(); }
  }
  return Object.freeze({ endpoint, aboveMicros, retryAfterMs, requiredFor: amount => BigInt(amount) >= threshold, confirm });
}
