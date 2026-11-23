// The documents of the services against the services themselves. Each test takes a statement an
// operator or an integrator acts on (a README, the integration guide, the description of the API)
// and holds it against the code: where the document was wrong or silent on the first live run
// (2026-11-18), the test fails until both say the same. The rules the review of the guide added afterwards (what
// carries no nonce, the fourth condition of step 4, the authority epoch, one hash for one withdrawal) are held
// against the engine's source and the API's answers in the same way.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import './time-sdk.js';
import { ROUTES, EXPLORER_FILES, NEWER_ACTIONS, loadExplorerFiles } from './api.mjs';
import { createV4Servers } from './server.mjs';
import { validateConfig as apiConfig } from '../deploy/api/start.mjs';
import { validateConfig as faucetConfig } from '../deploy/faucet/start.mjs';
import { validateConfig as watchConfig, start as startWatch } from '../deploy/watch/start.mjs';

const root = new URL('../', import.meta.url);
const text = (file) => readFile(new URL(file, root), 'utf8');
const [apiReadme, faucetReadme, watchReadme, guide, apiSource, faucetSource, indexerSource, engineSecurity, engine, ledger] = await Promise.all(['deploy/api/README.md', 'deploy/faucet/README.md', 'deploy/watch/README.md', 'docs/integration-guide.md', 'client-v4/api.mjs', 'client-v4/faucet.mjs', 'client-v4/indexer.mjs', 'v5/src/security.rs', 'v5/src/engine.rs', 'src/ledger/v1.rs'].map(text));
/// A section of the guide: from one of its lines to another.
const part = (from, to) => { const start = guide.indexOf(from), end = guide.indexOf(to, start + 1); assert.ok(start >= 0 && end > start, `the guide has no part from "${from}" to "${to}"`); return guide.slice(start, end); };
const openapi = JSON.parse(await text('client-v4/api/openapi.json'));
const fixture = JSON.parse(await text('verifier-v4/fixtures/fast-receipt.json'));
const freePort = () => new Promise((resolve) => { const server = net.createServer(); server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); }); });
/// The rows of the first Markdown table after `heading`: each a list of its cells.
function tableAfter(document, heading) {
  const lines = document.slice(document.indexOf(heading)).split('\n'), start = lines.findIndex((line) => line.startsWith('|'));
  const rows = [];
  for (const line of lines.slice(start)) { if (!line.startsWith('|')) break; rows.push(line.slice(1, line.lastIndexOf('|')).split(' | ').map((cell) => cell.trim())); }
  return rows.slice(2);
}

test('the guide takes the nonce of a withdrawal from the signer\'s own count, and says when a proven nonce is behind', () => {
  // The old recipe read the nonce from a proof for each withdrawal. A proof trails the newest block by one, and no
  // answer shows an action that still waits for a block: two withdrawals in a row got one nonce.
  assert.doesNotMatch(guide, /Read your account's nonce from its proven state, sign with the SDK/);
  assert.doesNotMatch(guide, /\/\/ the account's nonce plus one/);
  const section = guide.slice(guide.indexOf('### The nonce: count it yourself'), guide.indexOf('| Answer | Meaning | Do |'));
  assert.ok(section.length > 500, 'the guide has no section on the nonce');
  for (const said of ['Take the nonce from your own records, not from the chain', '`next_nonce`', 'A withdrawal gets its nonce and its signature once', 'carries **that same nonce**', '`indexed.state_is_behind` is false', 'Do not renumber them',
    // What is stored with the bytes, because step 4 asks for it; and the two facts every later rule rests on.
    'the authority epoch you signed with, and the `state_height` of the account answer you read before signing', '**Two actions with one nonce can never both be included.**', 'A second signature under *another* nonce is how a customer gets paid twice',
    'Two signers of one account need one count between them']) assert.ok(section.includes(said), `the section on the nonce does not say: ${said}`);
  // What the answer says of the index is what the service computes: by the height of the proof, not by the nonce after it.
  assert.match(apiSource, /const newer = Number\.isSafeInteger\(stateHeight\) \? store\.sentAbove\(id, stateHeight, 'asc', NEWER_ACTIONS\) : \[\];/);
  assert.match(openapi.components.schemas.Account.properties.indexed.allOf[1].properties.state_is_behind.description, /^True when the index holds an action that this account sent in a block above `state_height`/);
  assert.match(apiReadme, /`indexed\.state_is_behind` is true when the index holds an action that the account sent in a block above `state_height`\. `indexed\.newer_actions` lists those, oldest first, at most 16; `indexed\.last_sent` is the newest of them, also when there are more than 16/);
  // The table of what is index and what is proof lists that part of the account answer as the index's word.
  assert.match(part('| You read | It is | Use it for |', 'Rule: **find with the index'), /\| Lists of blocks[^\n]*the `indexed` part of an account answer \(`indexed\.state_is_behind`, `indexed\.newer_actions`, `indexed\.last_sent`, the totals\); `used_by` in a refused submission[^\n]*\| This server's word\./);
  // What the guide tells the reader to look at is what the API answers and describes.
  const indexed = openapi.components.schemas.Account.properties.indexed.allOf[1];
  assert.deepEqual(['state_is_behind', 'newer_actions', 'last_sent'].filter((name) => !indexed.properties[name] || !indexed.required.includes(name)), []);
  assert.equal(indexed.properties.newer_actions.maxItems, NEWER_ACTIONS);
  for (const name of ['state_is_behind', 'newer_actions', 'last_sent']) assert.ok(apiSource.includes(`${name}:`) && guide.includes(`indexed.${name}`) && apiReadme.includes(`indexed.${name}`), `${name} is not in the service, the guide and the README alike`);
  // The payer of a deposit: the same answer, and what happens when the nonce moved all the same.
  assert.match(guide, /\*\*The payer's nonce can have moved\.\*\*[^\n]*`indexed\.state_is_behind`[^\n]*This payment quote reserved another nonce[^\n]*you issue a new one\. \*\*Keep looking for the old reference until its expiry all the same\*\*[^\n]*a shop that asks for the new reference only never sees that payment/);
  // Nothing rests on two signatures being equal, and the guide no longer says that they are.
  assert.doesNotMatch(guide, /The same key gives the same signature for the same nonce and content, however often it signs/);
  assert.match(guide, /nothing in this guide rests on two signatures being equal/);
});

test('the guide keeps steps 3 and 4 to actions that carry a nonce, and the kinds it names as carrying none are the engine\'s', () => {
  const said = /\*\*This step and step 4 are for actions that carry a nonce:\*\* a transfer \(kind 3\), a payment to a shop \(kind 10\) and the two actions of a payment that waits \(kind 75\)\. Four kinds carry no nonce \(the field is 0\) and no authority epoch: a freeze \((\d+)\), an operation approved by several keys[^\n]*\((\d+)\), the finishing of a replacement of keys \((\d+)\) and a cancellation \((\d+)\)\.[^\n]*\*\*step 4 must never be applied to them\*\*/.exec(guide);
  assert.ok(said, 'the guide does not say which actions steps 3 and 4 are for');
  // v5/src/security.rs: the kinds that carry nonce and authority epoch zero, and those that take the next nonce.
  const kind = (name) => Number(new RegExp(`pub const ${name}: u8 = (\\d+);`).exec(engineSecurity)[1]);
  const listed = (fn) => /matches!\(kind, ([A-Z |]+)\)/.exec(engineSecurity.slice(engineSecurity.indexOf(`pub fn ${fn}(kind: u8)`)))[1].split(' | ').map(kind);
  assert.deepEqual(said.slice(1).map(Number), listed('protective'));
  assert.deepEqual(listed('sequenced'), [70, 71, 75, 77]);
  // The service never names "the action that used the nonce" for nonce 0.
  assert.ok(indexerSource.includes("actionBySenderNonce: (sender, nonce, hash) => (nonce === '0' ? null :"));
  // What holds instead, for the two ways above the limit.
  const above = part('### Withdrawals above the daily limit', '## 4. Look it up');
  // The refusal the guide quotes is the engine's, and a transfer refused with it comes back to life with the limit.
  assert.ok(above.includes('(422, "over the daily limit of this account")') && engineSecurity.includes('"over the daily limit of this account: use a payment that waits, or a second proof"'));
  assert.match(above, /\*\*A transfer that was refused for the limit is not dead\.\*\*[^\n]*The `request` of a payment that waits takes the transfer's own nonce[^\n]*A payment by second proof carries no nonce, so before its approvals are collected another action is signed under the transfer's nonce and verified in a block/);
  for (const sentence of ['**Keep withdrawals within the limit where you can:**', 'the payment is **requested, not paid**', 'For a request, 200 `already_included`, and 409 `nonce_used` with `same_content` true, mean "requested"', '**The withdrawal is paid when an `execute` that names its id is in a block,**',
    'It carries no nonce, so none of the rules above protects it, and step 4 must not be applied to it', '**It is paid when its hash is in a block,**', 'Its bytes are dead once a proof shows a state time past its `expires_elapsed_micros`', '**of two operations approved for one version at most one is ever included.**', 'is approved for **the version you stored**, never for a version read anew']) assert.ok(above.includes(sentence), `"Withdrawals above the daily limit" does not say: ${sentence}`);
  // The engine facts those sentences rest on: an approval names the version, every such operation moves it; a
  // payment with a second proof is dated; an id is completed once and only when its wait is over.
  assert.match(engineSecurity, /approved\(\s*meta,\s*account\.id,\s*version,\s*input\.expires_elapsed_micros,/);
  assert.match(engineSecurity, /\n            next_version\(&mut security\)\?;\n            let row = settle_fee\(host, action, reduced\)\?;/);
  // The date of the approvals is judged on the chain's time (the state time the guide names), on every network:
  // also on one whose waits survive a stop, where `now`, the clock of the waits, is another clock.
  assert.match(engineSecurity, /let chain_time = host\.meta\(\)\.elapsed_micros\(\)\?;/);
  assert.match(engineSecurity, /dated\(chain_time, margin, input\.expires_elapsed_micros, MAX_PAY_LIFETIME_MICROS\)\?;/);
  assert.doesNotMatch(engineSecurity, /dated\(now,/);
  assert.match(engineSecurity, /let now = host\.meta\(\)\.active_micros\(\)\?;/);
  assert.match(engineSecurity, /\.ok_or_else\(\|\| anyhow!\("no such waiting payment"\)\)\?;\s*let payment = security\.pending_payments\.remove\(index\);\s*ensure!\(\s*now >= payment\.ready_elapsed_micros,/);
  assert.match(engineSecurity, /pub const MAX_PENDING_PAYMENTS: usize = 4;/);
});

test('step 4 concludes "never included" from a verified action or on four conditions, and the rule of the authority epoch is the engine\'s', () => {
  const four = part('## 4. Look it up', '## Limits and errors');
  for (const sentence of ['the withdrawal is paid when its proof verifies with your own trust anchor, not when an index says so', '**find the action that used the nonce.**', '**Verify it as in step 2, and check in the proven bytes that `from` is your account and `nonce` is this nonce.**',
    'nothing proves that an action is *not* in a block', 'only on an instance of the API that you run yourself, on a node of your own, and only when all four hold', 'Verify that proof yourself (`proof.view_proof`',
    '**The index covers the whole time since you signed:** the `index.start_height` of that 404 is at or below the `state_height` you stored with the bytes when you signed them', 'Only one thing uses a nonce without an action that carries it: a replacement of the account\'s keys taking effect, and that always moves `account.auth_epoch` on',
    '**It is still the one you signed with.** No replacement happened. An action used the nonce and this index does not show it; it may be your withdrawal. **Conclude nothing,**', 'If it is not there either, this index does not show what used the nonce: conclude nothing']) assert.ok(four.includes(sentence), `step 4 does not say: ${sentence}`);
  assert.doesNotMatch(guide, /If no action carries it, a replacement of the account's keys consumed it/);
  assert.doesNotMatch(guide, /Only when all three hold/);
  // The 404 the fourth condition reads carries the start of the index, and the account answer the proof to verify.
  assert.ok(apiSource.includes('start_height: String(s.start_height), indexed_height:') && openapi.components.schemas.IndexNote.properties.start_height && openapi.components.schemas.NotInIndex.required.includes('index'));
  assert.ok(apiSource.includes('view_proof: result.proof ?? null'));
  // v5/src/security.rs, `install`: the nonce moves without an action that carries it, and the epoch with it.
  const install = engineSecurity.slice(engineSecurity.indexOf('fn install('), engineSecurity.indexOf('#[derive', engineSecurity.indexOf('fn install(')));
  assert.match(install, /row\.nonce = row\s*\.nonce\s*\.checked_add\(1\)[^;]*;\s*bump\(&mut row\)\?;/);
  assert.match(engineSecurity, /fn bump\(row: &mut Account\) -> Result<\(\)> \{\s*row\.auth_epoch = row\s*\.auth_epoch\s*\.checked_add\(1\)/);
  // An action whose epoch is not the account's is refused, on each path, with the words the guide quotes.
  const moved = part('**An authority epoch that has moved kills every signature made before it, whatever its nonce.**', '4. **Where the count starts.**');
  for (const words of ['stale authority epoch', 'stale authority or incorrect nonce']) assert.ok(moved.includes(`"${words}`) && (engine + ledger).includes(`"${words}"`), words);
  assert.match(engine, /owner\.auth_epoch == action\.auth_epoch\s*&& owner\.nonce\.checked_add\(1\) == Some\(action\.nonce\),\s*"stale authority or incorrect nonce"/);
  assert.match(engine, /sender\.auth_epoch == action\.auth_epoch,\s*"stale authority epoch"/);
  for (const sentence of ['sign the withdrawal again under the same nonce with the new epoch', 'until they are filled every later action of the account is refused with "incorrect nonce"']) assert.ok(moved.includes(sentence), sentence);
  // After a loss of records: the epoch first, then every action matched, then the count.
  const lost = part('**After your records were lost**', '5. **When the chain is ahead of your count**');
  const order = ['treat every signature the account has ever made as alive', '1. Sign no withdrawal.', '2. **Move the account\'s authority epoch.**', 'until a proof shows `account.auth_epoch` above the one you started from', '3. From the `state_height` of that proof on, nothing with a nonce that was signed before can be included',
    'replace the keys instead', '4. **Match every action the account sent**', '`index.start_height` at or below the `state_height` of your last trusted record', '5. Only then set `next_nonce` to `account.nonce` plus one'].map((sentence) => [sentence, lost.indexOf(sentence)]);
  assert.deepEqual(order.filter(([, at], i) => at < 0 || (i > 0 && at < order[i - 1][1])).map(([sentence]) => sentence), [], 'the procedure after a loss of records is not there, or not in this order');
  assert.doesNotMatch(guide, /At the first withdrawal, or after your records were lost, read the account/);
});

test('a deposit cursor never skips what the index holds, and the guide says what it does not hold; the service refuses a cursor from below its start', () => {
  assert.doesNotMatch(guide, /so a cursor never skips a payment\. /);
  assert.doesNotMatch(guide, /the cursor cannot miss a payment\. /);
  const said = /\*\*An index does not hold what lies below its start\.\*\*[^\n]*\(409 `cursor_below_index_start`, with `index\.start_height`\)[^\n]*Do not get around the refusal by starting again without a cursor[^\n]*a list read without a cursor says nothing about deposits made below `index\.start_height`/.exec(guide);
  assert.ok(said, 'the guide does not say what a cursor misses when the index starts later');
  assert.ok(guide.includes('so a cursor never skips a payment that this index holds'));
  // The service: the refusal, in the routes that take a cursor, described; and the stream's word for the same.
  assert.match(apiSource, /throw new ApiError\(409, 'cursor_below_index_start',/);
  assert.equal((apiSource.match(/cursorWithinIndex\(query\.cursor/g) ?? []).length, 3);
  for (const route of ['/v1/blocks', '/v1/accounts/{id}/activity', '/v1/accounts/{id}/payments']) assert.equal(openapi.paths[route].get.responses['409'].$ref, '#/components/responses/CursorBelowStart', route);
  assert.match(apiReadme, /\*\*A cursor below the start of the index is refused:\*\* 409 `cursor_below_index_start`/);
  assert.match(apiSource, /This index starts at height \$\{store\.startHeight\} and does not hold these heights/);
  assert.match(guide, /409 `cursor_below_index_start`: your cursor is from below the start of this index/);
});

test('one hash settles one withdrawal: the guide, the answer and its description say so, and none says "it is done"', () => {
  const rows = tableAfter(guide, '| Answer | Meaning | Do |'), used = rows.find((row) => row[0] === '409 `nonce_used`');
  for (const sentence of ['This is the index\'s word', 'First verify `used_by.hash` as in step 2, and check in the proven bytes that it is an action of your account (`from`) with this nonce. Only then are your bytes dead',
    'or another withdrawal of yours to the same recipient for the same amount', '**A hash settles one withdrawal:** if `used_by.hash` already settles another withdrawal of yours, this one is not paid']) assert.ok(`${used[1]} | ${used[2]}`.includes(sentence), `the row for nonce_used does not say: ${sentence}`);
  assert.doesNotMatch(guide, /it is this payment under another signature: \*\*it is paid\*\*/);
  assert.doesNotMatch(apiSource, /it is done\. Do not sign it again/);
  assert.match(apiSource, /One hash is one payment: if used_by\.hash is not the hash of another payment in your records, this payment is made by it/);
  const usedBy = openapi.components.schemas.UsedBy, sameContent = usedBy.properties?.same_content ?? usedBy.allOf.map((form) => form.properties?.same_content).find(Boolean);
  assert.match(sameContent.description, /or another payment of the same amount to the same recipient: this answer cannot tell the two apart\. One hash is one payment/);
  assert.doesNotMatch(JSON.stringify(openapi), /if `same_content` is true the payment is made/);
});

test('the guide\'s table of answers has the answer that never comes, and names only answers the API gives', () => {
  const rows = tableAfter(guide, '| Answer | Meaning | Do |');
  const lost = rows.find((row) => row[0].startsWith('**No answer**'));
  assert.ok(lost, 'no row for a lost answer');
  // Both answers a second sending can get, and the third; each leads to step 4, and nothing is signed.
  for (const said of ['Send the same bytes again', '409 `already_submitted`', '200 `already_included`', '202 `submitted`', 'go to step 4', 'Sign nothing']) assert.ok(lost[2].includes(said), `the row for a lost answer does not say: ${said}`);
  // Every status with a code in the first column is one the service answers with.
  const named = rows.flatMap((row) => [...row[0].matchAll(/(\d{3}) `([a-z_]+)`/g)].map((m) => [Number(m[1]), m[2]]));
  assert.deepEqual(named.map(([, code]) => code).sort(), ['already_included', 'already_submitted', 'node_unavailable', 'nonce_used', 'rejected', 'rejected', 'submitted']);
  for (const [status, code] of named) assert.ok(new RegExp(`(?:ApiError\\(${status}, '${code}'|status: ${status}, body: \\{ hash, status: '${code}')`).test(apiSource), `the API does not answer ${status} ${code}`);
  // A refused first sending is not "sign anew": the bytes are in no block, have not used their nonce, and stay valid.
  // (The row said "The nonce is not used", which is false when the refusal is for the nonce itself.)
  const refused = rows.find((row) => /422 `rejected`, for bytes you send \*\*for the first time\*\*/.test(row[0]));
  assert.ok(refused[1].includes('The node refused them, and they are in no block') && refused[2].includes('The bytes have not used their nonce, and they stay valid for as long as it is free and the authority epoch has not moved') && !/Fix the cause, sign anew/.test(guide));
  assert.doesNotMatch(guide, /The nonce is not used and the bytes are still valid/);
  // Bytes sent before and refused for good: the replacement goes under the same nonce, never under another.
  const before = rows.find((row) => /422 `rejected`, for bytes you have \*\*sent before\*\*/.test(row[0]));
  assert.ok(before[2].includes('sign nothing under another nonce') && before[2].includes('the replacement is signed under the same nonce (point 3)'));
  // A 400 judges the request. The service's own message for bytes it cannot decode says the same.
  const bad = rows.find((row) => row[0] === '400');
  assert.ok(bad[2].includes('**A 400 judges the request, not the chain:**') && bad[2].includes('sign nothing under another nonce because of it') && !/Such bytes can never be included, and their nonce is free/.test(guide));
  assert.match(apiSource, /bad\('invalid_action', 'These bytes are not a signed action that the SDK of this service can decode\. This says nothing about the chain: a node may still take them'\)/);
  // A node that did not answer may have taken the bytes; one that says it has them may have them in a block.
  assert.ok(rows.find((row) => row[0] === '502 `node_unavailable`')[1].includes('It may have taken the bytes all the same'));
  assert.ok(rows.find((row) => row[0] === '409 `already_submitted`')[1].includes('in its waiting list, or in a block'));
});

test('the watch is given the gateway\'s public address: a gateway started as documented refuses its loopback address, and a watch pointed there ends blind', { timeout: 60_000 }, async () => {
  const row = tableAfter(watchReadme, '| Setting | Meaning |').find((cells) => cells[0] === '`gateway`');
  assert.match(row[1], /its public `https:\/\/` origin \(`public_origins\.wallet`/);
  assert.match(watchReadme, /\*\*Which gateway address\.\*\*[^\n]*403 "Loopback host rejected"[^\n]*`watch_blind`[^\n]*started without public origins/);
  assert.throws(() => watchConfig({ gateway: 'http://203.0.113.5:8907', trust: fixture.trust, subscriptions: [{ account: '5' }], data_directory: path.resolve('/var/lib/time-watch') }), /give the public origin of the wallet gateway/);
  // What the README says, as it happens.
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-docs-'));
  // A trust anchor of today: the watch's own client checks it before it asks the gateway anything.
  const trust = { ...fixture.trust, genesis_time_micros: String((Date.now() - 60_000) * 1000) };
  const manifest = { networkId: trust.network_id, trust }, noNode = async () => { throw new Error('no node'); };
  const gateway = await createV4Servers({ root: fileURLToPath(root), manifest, rpc: noNode, walletPort: 0, merchantPort: 0, checkpointPath: path.join(directory, 'checkpoint.json'), ordersPath: path.join(directory, 'orders.json'), archivePath: path.join(directory, 'archive'),
    publicOrigins: { wallet: 'https://wallet.example', merchant: 'https://app.example' }, upgradeCheck: { firstMs: 0, everyMs: 0 } });
  let watch = null, clock = Date.now();
  const logs = [];
  try {
    const refused = await fetch(`${gateway.walletListenOrigin}/api/network`);
    assert.deepEqual([refused.status, await refused.json()], [403, { error: 'Loopback host rejected' }]);
    watch = await startWatch({ gateway: gateway.walletListenOrigin, trust, subscriptions: [{ account: '5' }], data_directory: path.join(directory, 'watch'), port: await freePort(), poll_seconds: 5, max_lag_seconds: 2, gateway_timeout_seconds: 2 },
      { now: () => clock, log: (level, message, fields) => logs.push({ level, message, ...fields }) });
    await watch.watch.poll();
    clock += 5000;
    await watch.watch.poll(); await watch.watch.settled();
    assert.ok(logs.some((line) => line.level === 'warn' && /poll failed/.test(line.message) && /Loopback host rejected/.test(line.error)), JSON.stringify(logs));
    assert.deepEqual(watch.feed.list('5').map((event) => event.type), ['watch_blind']);
  } finally { await watch?.close(); await gateway.close(); await rm(directory, { recursive: true, force: true }).catch(() => {}); }
});

test('a node on another machine: plain http is refused with what to do instead, and the READMEs say how', () => {
  const base = { trust: fixture.trust, data_directory: path.resolve('/var/lib/time-api') };
  for (const url of ['http://10.0.0.7:26657/', 'http://node.internal:26657/']) assert.throws(() => apiConfig({ ...base, rpc_url: url }), /http:\/\/ only on this machine.*through a tunnel to this machine or a TLS proxy.*deploy\/api\/README\.md/);
  assert.throws(() => faucetConfig({ test_network: true, network_id: fixture.trust.network_id, trust: fixture.trust, rpc_url: 'http://10.0.0.7:26657/' }), /through a tunnel to this machine or a TLS proxy/);
  assert.equal(apiConfig({ ...base, rpc_url: 'http://127.0.0.1:26657/' }).rpc_url, 'http://127.0.0.1:26657/');
  const section = apiReadme.slice(apiReadme.indexOf('### A node on another machine'), apiReadme.indexOf('## Routes'));
  for (const said of ['has no authentication and no encryption', 'ssh -N -L 127.0.0.1:26657:127.0.0.1:26657', '"rpc_url": "http://127.0.0.1:26657/"', 'a TLS proxy in front of the node\'s RPC', 'It is not what makes an answer true', 'Neither a tunnel nor a TLS proxy has been run with this service']) assert.ok(section.includes(said), `the section does not say: ${said}`);
  assert.match(faucetReadme, /`rpc_url`[^\n]*never as plain `http:\/\/`[^\n]*"A node on another machine"/);
});

test('serve_explorer: the README names the files it needs, and a missing one stops the start with its name', () => {
  const needs = /With `serve_explorer` it also needs `web-v4\/explorer\/`/;
  assert.match(apiReadme.slice(apiReadme.indexOf('## Running it'), apiReadme.indexOf('| Setting | Meaning |')), needs);
  // Every file the service reads for the explorer is in a directory the README lists.
  const listed = ['client-v4/', 'web-v4/shared/verifier/', 'web-v4/explorer/', 'web-v4/shared/network-menu.'];
  for (const [, location] of EXPLORER_FILES) { const file = location.replace(/^\.\.\//, '').replace(/^\.\//, 'client-v4/'); assert.ok(listed.some((directory) => file.startsWith(directory) && apiReadme.includes(`\`${directory}\``)), `${file} is in no directory the README names`); }
  assert.equal(loadExplorerFiles().size, EXPLORER_FILES.length);
  // An installation without the explorer (the files of the README's first list only).
  assert.throws(() => loadExplorerFiles(pathToFileURL(path.join(os.tmpdir(), 'time-api-installed-without-explorer', 'client-v4', 'api.mjs'))), /^Error: serve_explorer is on, but a file of the explorer is not installed with this service: web-v4\/explorer\/index\.html\. .*turn serve_explorer off$/);
});

test('the description of the API uses no oneOf: its forms contain one another, and a strict reader would refuse a documented answer', () => {
  const found = [];
  (function walk(node, at) { if (Array.isArray(node)) node.forEach((item, i) => walk(item, `${at}[${i}]`)); else if (node && typeof node === 'object') for (const [key, value] of Object.entries(node)) { if (key === 'oneOf') found.push(at); walk(value, `${at}.${key}`); } })(openapi, '');
  assert.deepEqual(found, []);
  // The answer that showed it: `not_in_history` comes with a proof, and is an error like any other as well.
  const forms = openapi.paths['/v1/blocks/{height}/proof'].get.responses['404'].content['application/json'].schema.anyOf.map((form) => form.$ref);
  assert.deepEqual(forms, ['#/components/schemas/StateNotFound', '#/components/schemas/Error']);
});

test('the faucet\'s README lists every refusal code the faucet answers with', () => {
  const codes = new Set([...faucetSource.matchAll(/new ApiError\(\d{3}, '([a-z_]+)'/g), ...faucetSource.matchAll(/\bbad\('([a-z_]+)'/g), ...faucetSource.matchAll(/^\s+([a-z_]+): \[\d{3}, '/gm)].map((m) => m[1]));
  assert.ok(codes.size >= 30, `only ${codes.size} codes were found in the source`);
  const refusals = faucetReadme.slice(faucetReadme.indexOf('Refusals are plain and have a stable `error.code`'), faucetReadme.indexOf('## How a grant survives trouble'));
  assert.deepEqual([...codes].filter((code) => !refusals.includes(`\`${code}\``)).sort(), []);
});

test('the faucet\'s README says how its health check and its pace are, as the service has them', () => {
  // Health: one reason is no fault.
  assert.match(faucetReadme, /one reason that is no fault and leaves the answer at 200: `daily_total_given`/);
  assert.ok(faucetSource.includes("reasons.push('daily_total_given')") && /status: faults\.length \? 503 : 200/.test(faucetSource));
  assert.doesNotMatch(faucetReadme, /200 while the faucet gives, 503 when it does not/);
  // Pace: the numbers of the README are the defaults of the service.
  const idle = Number(/idleReadMs = (\d+)/.exec(faucetSource)[1]) / 1000, pass = Number(/reconcileMs = (\d+)/.exec(faucetSource)[1]) / 1000;
  assert.ok(faucetReadme.includes(`reads its account every ${idle} seconds when nothing else is going on, and every ${pass} seconds while something waits`), `the README does not give the pace of ${idle} and ${pass} seconds`);
  assert.ok(faucetReadme.includes(`at most about ${idle + pass} seconds after its block`));
});

test('the README\'s table of routes says what each route takes from the rate-limit budget', () => {
  const rows = tableAfter(apiReadme, '| Route | Answers | From | Takes |');
  const takes = new Map(rows.map((cells) => [cells[0].replace(/`/g, '').replace('{number or name}', '{account}').replace('{number}', '{id}'), Number(cells.at(-1))]));
  assert.deepEqual(ROUTES.map((route) => [`${route.method} ${route.path}`, takes.get(`${route.method} ${route.path}`)]), ROUTES.map((route) => [`${route.method} ${route.path}`, route.cost]));
  assert.equal(takes.size, ROUTES.length);
  // The description says the same for every route that takes more than one.
  for (const route of ROUTES.filter((entry) => entry.cost > 1)) assert.match(openapi.paths[route.path][route.method.toLowerCase()].description, new RegExp(`Costs ${route.cost} from the rate-limit budget`), `${route.method} ${route.path}`);
  assert.match(guide, /A list or a block takes 1 from it; an action by hash, an account and every other answer that comes with a proof take 5; a submission or a stream 10/);
});

test('no document still says that a service has never run against a live network; each says what ran and what did not', async () => {
  const explorerReadme = await text('web-v4/explorer/README.md'), clientReadme = await text('client-v4/README.md');
  for (const [name, document] of Object.entries({ apiReadme, faucetReadme, watchReadme, explorerReadme, guide, clientReadme })) assert.doesNotMatch(document, /has not run against a live network yet/, name);
  for (const [name, document] of Object.entries({ apiReadme, faucetReadme, watchReadme })) {
    const said = /- \*\*What has run against a live network, and what has not\.\*\* On 2026-11-18 [^\n]*seven validators in two regions on AWS[^\n]*about two minutes[^]*?\n\n  What has not run: [^\n]+/.exec(document);
    assert.ok(said, `${name} does not say what ran and what did not`);
  }
  // What no run has had, said where a reader decides whether to rely on it.
  assert.match(apiReadme, /What has not run: more than a few minutes[^\n]*load[^\n]*a TLS proxy, a tunnel or a second machine[^\n]*an integration by an exchange/);
  // A browser opened the pages for the first time on 2026-11-19 (Chrome, on a live network, for a minute at a time).
  // Each document says that, says what the run found, and says what a browser has still not shown.
  assert.match(apiReadme, /\*\*In a browser: Chrome, once, for a minute at a time\.\*\* On 2026-11-19 Chrome 158[^\n]*loaded in no browser[^\n]*Not looked at: [^\n]*any browser but Chrome/);
  assert.doesNotMatch(apiReadme, /No browser has opened these pages/);
  assert.match(faucetReadme, /On 2026-11-19 a browser used it for the first time \(Chrome 158[^\n]*without a TLS proxy\./);
  assert.match(faucetReadme, /What has not run: a browser other than Chrome on the page, or Chrome for longer than a minute/);
  assert.doesNotMatch(faucetReadme, /What has not run: a browser on the page/);
  assert.match(watchReadme, /What has not run: hours[^\n]*a gateway behind its TLS proxy/);
  assert.match(explorerReadme, /A browser ran this code for the first time on 2026-11-19: Chrome 158[^\n]*What still needs a real browser: [^\n]*any browser but Chrome\./);
  assert.doesNotMatch(explorerReadme, /No browser has run this code/);
  assert.match(guide, /## What has run\n\nOn 2026-11-18 a script followed the steps of this guide[^]*No exchange has integrated by this guide/);
  // The guide says of each rule added since where it has run: on the second live network of that day, under
  // the API's tests only, or nowhere.
  const ran = guide.slice(guide.indexOf('## What has run'));
  assert.match(ran, /on the three conditions step 4 had then/);
  assert.match(ran, /- \*\*Run on a second live network of the same kind, later on 2026-11-18\*\*[^\n]*52 of 52 steps[^\n]*points 1 and 2, point 3 as far as one refused first sending[^\n]*point 5 with a second signer[^\n]*the fourth condition of step 4 against a second instance with a later start/);
  assert.match(ran, /- \*\*Under the API's own tests only:\*\* an account answer whose proof is behind the index\.[^\n]*was never true\./);
  assert.doesNotMatch(ran, /Run against a stand-in network only/);
  assert.match(ran, /- \*\*Run nowhere:\*\*[^\n]*an authority epoch that moved[^\n]*the procedure after a loss of records[^\n]*everything in "Withdrawals above the daily limit"/);
  assert.doesNotMatch(guide, /they have run under tests, against a stand-in network, not on a live one/);
  // Figures the report of that run does not hold are gone; the one it holds for webhooks is given as it is.
  for (const [name, document] of Object.entries({ apiReadme, faucetReadme, watchReadme })) assert.doesNotMatch(document, /all eight webhooks|three grants|nearly all of them empty/, name);
  for (const [name, document] of Object.entries({ apiReadme, watchReadme })) assert.match(document, /The receiver of the run took 16 deliveries in all/, name);
  assert.match(apiReadme, /\(six deposits, none delivered twice\)/);
});
