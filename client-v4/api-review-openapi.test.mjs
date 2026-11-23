// Compares real answers with client-v4/api/openapi.json: schema violations and undocumented fields/statuses.
// Written by the independent reviewer of the API (as review-openapi.test.mjs). Brought into the suite
// unchanged except for the one place marked "ADAPTED".
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import './time-sdk.js';
import * as verifier from './proof-verifier.mjs';
import { describeAction, IndexerError } from './indexer.mjs';
import { createApiService } from './api.mjs';

const SDK = globalThis.TimeSDK;
const fixture = JSON.parse(await readFile(new URL('../verifier-v4/fixtures/fast-receipt.json', import.meta.url), 'utf8'));
const openapi = JSON.parse(await readFile(new URL('./api/openapi.json', import.meta.url), 'utf8'));
const NETWORK = fixture.trust.network_id, CHAIN = fixture.trust.chain_id;
const sha = (bytes) => createHash('sha256').update(bytes).digest();

const deref = (schema) => { while (schema && schema.$ref) schema = schema.$ref.split('/').slice(1).reduce((o, k) => o[k], openapi); return schema; };
function flat(schema) { // merged properties/required of allOf
  schema = deref(schema) ?? {};
  const out = { properties: { ...(schema.properties || {}) }, required: [...(schema.required || [])], type: schema.type, items: schema.items, enum: schema.enum, pattern: schema.pattern };
  for (const part of schema.allOf || []) { const f = flat(part); Object.assign(out.properties, f.properties); out.required.push(...f.required); out.type ??= f.type; }
  return out;
}
function check(value, schema, at, problems) {
  const s = flat(schema);
  const typeOf = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
  const types = s.type === undefined ? null : [].concat(s.type);
  if (types && !types.includes(typeOf) && !(typeOf === 'integer' && types.includes('number'))) problems.push(`${at}: is ${typeOf}, described as ${types.join('|')}`);
  if (s.enum && !s.enum.includes(value)) problems.push(`${at}: ${JSON.stringify(value)} not in enum ${JSON.stringify(s.enum)}`);
  if (s.pattern && typeof value === 'string' && !new RegExp(s.pattern).test(value)) problems.push(`${at}: ${JSON.stringify(value).slice(0, 40)} does not match ${s.pattern}`);
  if (typeOf === 'object') {
    for (const name of s.required) if (!(name in value)) problems.push(`${at}: required "${name}" is missing`);
    const described = Object.keys(s.properties);
    if (described.length) for (const name of Object.keys(value)) {
      if (!(name in s.properties)) problems.push(`${at}.${name}: not described`);
      else check(value[name], s.properties[name], `${at}.${name}`, problems);
    }
  }
  if (typeOf === 'array' && s.items) value.slice(0, 3).forEach((item, i) => check(item, s.items, `${at}[${i}]`, problems));
}

function fakeRpc(state) {
  const block = (h) => { const b = fixture.blocks[Number(h) - 1]; if (!b || Number(h) > state.tip) throw new IndexerError('RPC_REFUSED', 'height is not available'); return b; };
  return async (method, parameters = {}) => {
    if (method === '/status') return { node_info: { network: CHAIN }, sync_info: { latest_block_height: String(state.tip) } };
    if (method === '/block') return { block: { header: block(parameters.height).signed_header.header, data: { txs: fixture.txs[parameters.height] } } };
    if (method === '/blockchain') { const metas = []; for (let h = Number(parameters.maxHeight); h >= Number(parameters.minHeight); h--) metas.push({ header: block(h).signed_header.header }); return { block_metas: metas }; }
    if (method === '/commit') return { signed_header: block(parameters.height ?? state.tip).signed_header };
    if (method === '/validators') { const h = Number(parameters.height); if (h > state.tip + 1) throw new IndexerError('RPC_REFUSED', 'height is not available'); return { block_height: parameters.height, total: '4', validators: h <= fixture.blocks.length ? fixture.blocks[h - 1].validators : fixture.blocks.at(-1).next_validators }; }
    if (method === '/broadcast_tx_sync') return state.broadcast(parameters);
    throw new IndexerError('RPC_REFUSED', 'not available on this node');
  };
}

test('real answers against the OpenAPI description', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'time-api-openapi-'));
  const state = { tip: 4, broadcast: (p) => ({ code: 0, hash: sha(Buffer.from(p.tx.slice(2), 'hex')).toString('hex').toUpperCase() }) };
  const account = { id: '7', name: 'payer', balance: '85', nonce: '3', auth_epoch: '0', devices: [] };
  const service = await createApiService({ trust: fixture.trust, rpc: fakeRpc(state), verifier, dataFile: path.join(directory, 'index.sqlite'), port: 0, autoStart: false, pollMs: 5, now: () => fixture.now_ms,
    readState: async (selection) => { if (state.down) throw new Error('down'); return { verified: true, requested: selection, proof: { height: '3', entries: [] }, state: { network_id: NETWORK, height: '3', time_micros: '1000003000000', accounts: selection.ids?.[0] === '7' ? [account] : [], config: {} } }; },
    rateLimit: { perSecond: 1000, burst: 100000 }, maxStreams: 1 });
  try {
    for (let i = 0; i < 50 && (service.store.high() ?? 0) < 4; i++) await service.indexer.step();
    const hash = sha(Buffer.from(fixture.txs['2'][0], 'base64')).toString('hex').toUpperCase();
    const tx = Buffer.from(SDK.concat(SDK.buildAction({ networkId: NETWORK, from: '5', nonce: '1', authEpoch: '0', publicKey: 'bb'.repeat(32), kind: 3, payload: { to: '8', amount: '5' } }), new Uint8Array(64))).toString('base64');
    const json = { 'Content-Type': 'application/json' };
    const requests = [
      ['GET', '/v1/status'], ['GET', '/v1/health'], ['GET', '/v1/blocks'], ['GET', '/v1/blocks?cursor=3&order=asc&limit=1'], ['GET', '/v1/blocks/2'], ['GET', '/v1/blocks/99'], ['GET', '/v1/blocks/2/actions'],
      ['GET', `/v1/actions/${hash}`], ['GET', `/v1/actions/${'AB'.repeat(32)}`], ['GET', '/v1/accounts/7'], ['GET', '/v1/accounts/999'], ['GET', '/v1/accounts/7/activity'], ['GET', '/v1/accounts/1/payments'],
      ['GET', '/v1/accounts/1/payments?bogus=1'], ['POST', '/v1/transactions', { headers: json, body: JSON.stringify({ tx }) }], ['POST', '/v1/transactions', { headers: json, body: '{}' }],
      ['POST', '/v1/transactions', { headers: { 'Content-Type': 'text/plain' }, body: '{}' }], ['DELETE', '/v1/status'], ['GET', '/v1/nothing'], ['GET', '/v1/status', { headers: { Origin: 'https://evil.example' } }],
      ['GET', `/v1/blocks?limit=${'1'.repeat(3000)}`],
    ];
    const problems = [];
    for (const [method, route, options = {}] of requests) {
      const response = await fetch(service.url + route, { method, ...options });
      const body = await response.json().catch(() => null);
      const template = Object.keys(openapi.paths).find((p) => new RegExp(`^${p.replace(/\{[a-z]+\}/g, '[^/]+')}$`).test(route.split('?')[0]));
      const operation = template && openapi.paths[template][method.toLowerCase()];
      // ADAPTED: answers that do not depend on the route (an unknown route, a method the route does not
      // take) cannot be listed under an operation, since there is none: the description lists them under
      // "x-any-request". The reviewer's line was: operation && deref(operation.responses[String(response.status)]).
      const described = deref(operation?.responses[String(response.status)]) ?? (operation ? undefined : deref(openapi['x-any-request'].responses[String(response.status)]));
      if (!described) { problems.push(`${method} ${route.slice(0, 60)} -> ${response.status} ${body?.error?.code ?? ''}: status not described for this route`); continue; }
      const schema = described.content?.['application/json']?.schema;
      if (schema && body) check(body, schema, `${method} ${route.slice(0, 50)} ${response.status}`, problems);
    }
    // The stream: what its events hold is not described at all.
    const stream = deref(openapi.paths['/v1/stream'].get.responses['200']);
    problems.push(`stream 200 schema: ${JSON.stringify(stream.content)}`);
    problems.push(`stream parameters: ${openapi.paths['/v1/stream'].get.parameters.map((p) => `${p.in}:${p.name}`).join(', ')} (Last-Event-ID header ${openapi.paths['/v1/stream'].get.parameters.some((p) => p.in === 'header') ? 'described' : 'not described as a parameter'})`);
    problems.push(`/v1/blocks cursor: ${JSON.stringify(openapi.paths['/v1/blocks'].get.parameters.find((p) => p.name === 'cursor'))}`);
    for (const line of problems) console.log('   ' + line);
    assert.equal(problems.length, 3, 'see the lines above');
  } finally { await service.close(); await rm(directory, { recursive: true, force: true }); }
});
