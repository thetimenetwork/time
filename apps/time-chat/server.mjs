import { messageStart, messageEnd } from './public/armor.mjs';
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { createHmac, randomBytes } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  AEADEncryptedDataPacket, PacketList, PublicKeyEncryptedSessionKeyPacket,
  SymEncryptedIntegrityProtectedDataPacket, enums, unarmor,
} from 'openpgp';
import { parsePublic } from './public/crypto.mjs';
import { createAuth } from './auth.mjs';
import { ApiError, openStore } from './store.mjs';
import { openPush, validateSubscription } from './push.mjs';
import { serveAsset } from './assets.mjs';

const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const encryptedPackets = Object.fromEntries([
  PublicKeyEncryptedSessionKeyPacket, SymEncryptedIntegrityProtectedDataPacket, AEADEncryptedDataPacket,
].map(packet => [packet.tag, packet]));
const knownErrors = new Set([400, 401, 403, 404, 409, 413, 415, 429, 503]);
export function json(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Referrer-Policy': 'no-referrer',
  });
  res.end(JSON.stringify(data));
}
function shape(body, allowed) {
  if (
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body) ||
    Object.keys(body).some((k) => !allowed.includes(k))
  )
    throw new ApiError(400, 'Unexpected request fields.');
  return body;
}
async function readBody(req) {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json')
    throw new ApiError(415, 'JSON required.');
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 160 * 1024) throw new ApiError(413, 'Request too large.');
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new ApiError(400, 'Invalid JSON.');
  }
}
function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .map((pair) => pair.trim().split(/=(.*)/s))
      .filter(([k, v]) => k && v)
  );
}
const armoredEnvelope = new RegExp('^' + messageStart + String.raw`\r?\n\r?\n[A-Za-z0-9+/=\r\n]+\r?\n` + messageEnd + String.raw`\s*$`);
async function requireCiphertext(armor) {
  if (
    typeof armor !== 'string' ||
    armor.length > 128 * 1024 ||
    !armoredEnvelope.test(
      armor
    )
  )
    throw new ApiError(400, 'Expected an encrypted chat envelope.');
  try {
    // A relay only handles encrypted outer packets. A general message reader can
    // decompress plaintext before the caller ever gets to inspect the packet tags.
    const { type, data } = await unarmor(armor);
    if (type !== enums.armor.message) throw Error();
    const packets = await PacketList.fromBinary(data, encryptedPackets);
    const tags = packets.map((p) => p.constructor.tag);
    if (
      ![enums.packet.symEncryptedIntegrityProtectedData, enums.packet.aeadEncryptedData].includes(tags.at(-1)) ||
      tags.length < 2 ||
      tags.length > 17 ||
      tags
        .slice(0, -1)
        .some((t) => t !== enums.packet.publicKeyEncryptedSessionKey)
    )
      throw Error();
  } catch {
    throw new ApiError(400, 'Invalid encrypted chat envelope.');
  }
}

export function loginRateAddress(peer, forwardedFor, trustLoopbackProxy) {
  if (!trustLoopbackProxy || !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer) ||
      typeof forwardedFor !== 'string') return peer;
  // The trusted reverse proxy appends its directly connected peer. Earlier hops
  // may be supplied by a client and must never select its rate-limit bucket.
  const lastHop = forwardedFor.slice(forwardedFor.lastIndexOf(',') + 1).trim();
  return isIP(lastHop) ? lastHop : peer;
}

export function createChatServer({
  auth: primaryAuth,
  store,
  push = null,
  origin: primaryOrigin,
  installed = null,
  hosts = [new URL(primaryOrigin).host],
  trustLoopbackProxy = false,
}) {
  const csrfSecret = randomBytes(32);
  const csrfFor = (token) =>
    createHmac('sha256', csrfSecret).update(token).digest('hex');
  const streams = new Map(), sessionStreams = new Map(),
    buckets = new Map();
  const cookie = (name, value, ttl) =>
    name +
    '=' +
    value +
    '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' +
    ttl +
    (primaryOrigin.startsWith('https:') ? '; Secure' : '');
  const signal = (members) => {
    for (const { id } of members) {
      for (const res of streams.get(id) || []) {
        if (res.writableEnded || res.destroyed) continue;
        if (res.writableNeedDrain) res.destroy();
        else res.write('event: change\ndata: {}\n\n');
      }
    }
  };
  function logout(auth, token) {
    auth.logout(token);
    for (const res of sessionStreams.get(token) || []) res.end();
  }
  function limit(key, max) {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || b.until <= now) {
      b = { n: 0, until: now + 60000 };
      buckets.set(key, b);
    }
    if (++b.n > max)
      throw new ApiError(429, 'Please wait a minute before trying again.');
  }
  const cleanup = setInterval(() => {
    for (const [k, b] of buckets) if (b.until <= Date.now()) buckets.delete(k);
  }, 60000).unref();
  const server = createServer(async (req, res) => {
    try {
      const viaInstalled = installed && req.headers['x-time-chat-client'] === 'installed';
      const auth = viaInstalled ? installed.auth : primaryAuth;
      const origin = viaInstalled ? installed.origin : primaryOrigin;
      if (!hosts.includes(req.headers.host))
        throw new ApiError(403, 'Unrecognized host.');
      const url = new URL(req.url, origin),
        p = url.pathname,
        post = req.method === 'POST';
      if (!p.startsWith('/api/')) {
        if (await serveAsset(req, res, p)) return;
        throw new ApiError(404, 'Page unavailable.');
      }
      if (!post && req.method !== 'GET')
        throw new ApiError(404, 'Route unavailable.');
      if (
        (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') ||
        (req.headers['sec-fetch-dest'] && req.headers['sec-fetch-dest'] !== 'empty') ||
        (req.headers.origin && req.headers.origin !== origin) ||
        (post && req.headers.origin !== origin)
      )
        throw new ApiError(403, 'App origin required.');
      // A sibling website cannot plant a __Host- cookie for the HTTPS chat site.
      // The installed client's relay cookies travel over its private server-side connection.
      const cookiePrefix = !viaInstalled && primaryOrigin.startsWith('https:') ? '__Host-' : '';
      const sessionCookie = cookiePrefix + 'time_chat_session', preCookie = cookiePrefix + 'time_chat_pre';
      const cookies = parseCookies(req), token = cookies[sessionCookie];
      if (!post && p === '/api/config')
        return json(res, 200, {
          networkId: auth.networkId,
          walletOrigin: auth.walletOrigin,
          loginRelayOrigin: primaryOrigin,
          enrollmentOrigins: installed ? [primaryOrigin, installed.origin] : [primaryOrigin],
          pushKey: push?.publicKey ?? null,
        });
      if (post && p === '/api/login/challenge') {
        limit('login:' + loginRateAddress(req.socket.remoteAddress, req.headers['x-forwarded-for'], trustLoopbackProxy), 40);
        const { publicKey } = shape(await readBody(req), ['publicKey']);
        if (publicKey != null) {
          if (
            !token ||
            req.headers['x-csrf-token'] !== csrfFor(token) ||
            !(await auth.current(token))
          )
            throw new ApiError(403, 'Sign in before linking a device.');
          try {
            const key = await parsePublic(publicKey);
            // The wallet must bind exactly the public certificate that clients verify.
            if (key.armor().trim() !== publicKey.replaceAll('\r\n', '\n').trim()) throw Error();
          } catch {
            throw new ApiError(400, 'Invalid chat public key.');
          }
        }
        const issue = auth.issue(publicKey, token);
        res.setHeader('Set-Cookie', cookie(preCookie, issue.token, 180));
        return json(res, 200, {
          challenge: issue.challenge,
          salt: issue.salt ?? null,
        });
      }
      if (post && p === '/api/login/finish') {
        limit('finish:' + loginRateAddress(req.socket.remoteAddress, req.headers['x-forwarded-for'], trustLoopbackProxy), 40);
        const proof = shape(await readBody(req), ['message', 'signature']);
        const result = await auth.finish(cookies[preCookie], proof, token);
        if (result.publicKey)
          store.enroll({
            id: result.accountId,
            name: result.name,
            publicKey: result.publicKey,
            attestation: result.attestation,
          });
        if (token && token !== result.token) logout(auth, token);
        res.setHeader('Set-Cookie', [
          cookie(sessionCookie, result.token, 3600),
          cookie(preCookie, '', 0),
        ]);
        return json(res, 200, { ok: true });
      }
      if (post && p === '/api/logout') {
        if (!token || req.headers['x-csrf-token'] !== csrfFor(token))
          throw new ApiError(403, 'Refresh your session.');
        shape(await readBody(req), []);
        logout(auth, token);
        res.setHeader('Set-Cookie', [
          cookie(sessionCookie, '', 0),
          cookie(preCookie, '', 0),
        ]);
        return json(res, 200, { ok: true });
      }
      if (post && token && req.headers['x-csrf-token'] !== csrfFor(token))
        throw new ApiError(403, 'Refresh your session.');
      // Use the locally issued session only to select a rate bucket. The Time
      // authority check below still runs before any data is served or changed.
      const rateAccount = auth.sessionAccount(token);
      if (rateAccount) limit('api:' + rateAccount, 600);
      const active = await auth.current(token);
      if (!post && p === '/api/me') {
        if (!active) return json(res, 200, { user: null });
        const enrolled = store.user(active.accountId);
        return json(res, 200, {
          user: {
            id: active.accountId,
            name: active.name,
            publicKey: enrolled?.publicKey ?? null,
          },
          csrf: csrfFor(token),
        });
      }
      if (!active) throw new ApiError(401, 'Sign in with Time.');
      const owner = active.accountId;
      if (!store.user(owner))
        throw new ApiError(403, 'Link your chat key first.');
      if (p === '/api/blocks') {
        if (!post) return json(res, 200, { users: store.blocks(owner) });
        const { id, blocked } = shape(await readBody(req), ['id', 'blocked']);
        if (store.block(owner, id, blocked)) signal([{ id: owner }, { id }]);
        return json(res, 200, { ok: true });
      }
      if (!post && p === '/api/events') {
        const set = streams.get(owner) || new Set();
        if (set.size >= 6) throw new ApiError(429, 'Too many open chat tabs.');
        streams.set(owner, set);
        set.add(res);
        const forSession = sessionStreams.get(token) || new Set();
        forSession.add(res);
        sessionStreams.set(token, forSession);
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-store',
          'X-Accel-Buffering': 'no',
          'X-Content-Type-Options': 'nosniff',
        });
        res.write(': connected\n\n');
        const expiry = setTimeout(() => res.end(), Math.max(0, active.expiresAt - Date.now())).unref();
        let checking = false;
        const refresh = setInterval(async () => {
          if (checking) return;
          checking = true;
          try {
            if (res.writableNeedDrain) res.destroy();
            else if (!(await auth.current(token))) res.end();
            else res.write(': open\n\n');
          } catch {
            res.end();
          } finally {
            checking = false;
          }
        }, 30000).unref();
        res.on('close', () => {
          clearInterval(refresh);
          clearTimeout(expiry);
          set.delete(res);
          if (!set.size) streams.delete(owner);
          forSession.delete(res);
          if (!forSession.size) sessionStreams.delete(token);
        });
        return;
      }
      if (!post && p === '/api/contacts') {
        limit('contacts:' + owner, 90);
        return json(res, 200, {
          users: store.contact(url.searchParams.get('q') ?? ''),
        });
      }
      const proofPath = p.match(/^\/api\/contacts\/(\d{1,20})\/proof$/);
      if (!post && proofPath) {
        limit('contacts:' + owner, 90);
        const binding = store.binding(proofPath[1]);
        const checked = await auth.verifyAttestation({
          ...binding,
          accountId: binding.id,
        });
        return json(res, 200, {
          ...binding,
          name: checked.name,
          verified: true,
        });
      }
      if (p === '/api/chats') {
        if (!post) {
          const params = [...url.searchParams.keys()];
          if (params.length && (params.length !== 1 || params[0] !== 'cursor'))
            throw new ApiError(400, 'Invalid conversation cursor.');
          return json(res, 200, store.list(owner, url.searchParams.get('cursor')));
        }
        limit('new-room:' + owner, 30);
        const { members } = shape(await readBody(req), ['members']);
        const room = store.createChat(owner, members);
        signal(room.members);
        return json(res, 200, { chat: room });
      }
      const roomPath = p.match(/^\/api\/chats\/([a-f0-9]{64})$/);
      if (!post && roomPath) return json(res, 200, { chat: store.chat(roomPath[1], owner) });
      const route = p.match(/^\/api\/chats\/([a-f0-9]{64})\/(messages|read)$/);
      if (route) {
        const [, id, op] = route;
        if (op === 'messages' && !post) {
          const before = url.searchParams.has('before')
            ? Number(url.searchParams.get('before'))
            : undefined;
          if (
            before !== undefined &&
            (!Number.isSafeInteger(before) || before < 1)
          )
            throw new ApiError(400, 'Invalid message position.');
          return json(res, 200, store.history(id, owner, before));
        }
        if (op === 'messages' && post) {
          limit('send:' + owner, 120);
          store.requireMember(id, owner);
          const { messageId, ciphertext } = shape(await readBody(req), [
            'messageId',
            'ciphertext',
          ]);
          if (typeof messageId !== 'string' || !uuid.test(messageId))
            throw new ApiError(400, 'Invalid message ID.');
          await requireCiphertext(ciphertext);
          const saved = store.append(id, owner, messageId, ciphertext);
          if (saved.inserted) {
            const members = store.visibleParticipants(id);
            signal(members);
            for (const { id: peer } of members)
              if (peer !== owner && push)
                void push.notify(store, peer).catch(() => {});
          }
          return json(res, 200, { seq: saved.seq, messageId });
        }
        if (op === 'read' && post) {
          const { seq } = shape(await readBody(req), ['seq']);
          if (!Number.isSafeInteger(seq) || seq < 1)
            throw new ApiError(400, 'Invalid message position.');
          store.markRead(id, owner, seq);
          return json(res, 200, { ok: true });
        }
      }
      if (post && p === '/api/push') {
        if (!push) throw new ApiError(503, 'Notifications unavailable.');
        const { subscription } = shape(await readBody(req), ['subscription']);
        store.subscribe(owner, validateSubscription(subscription));
        return json(res, 200, { ok: true });
      }
      if (post && p === '/api/push/remove') {
        const { endpoint } = shape(await readBody(req), ['endpoint']);
        if (typeof endpoint !== 'string' || endpoint.length > 2048)
          throw new ApiError(400, 'Invalid subscription.');
        store.unsubscribe(owner, endpoint);
        return json(res, 200, { ok: true });
      }
      throw new ApiError(404, 'Route unavailable.');
    } catch (error) {
      if (res.headersSent) {
        res.end();
        return;
      }
      const status = knownErrors.has(error.status)
        ? error.status
        : req.url.startsWith('/api/login/')
          ? 401
          : 503;
      json(res, status, {
        error:
          error instanceof ApiError
            ? error.message
            : status === 401
              ? 'Time sign-in or key verification failed.'
              : 'The request could not be verified or completed.',
      });
    }
  });
  server.on('close', () => clearInterval(cleanup));
  server.closeStreams = () => {
    for (const set of streams.values()) for (const res of set) res.end();
  };
  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const port = Number(process.env.TIME_CHAT_PORT || 4173),
    host = process.env.TIME_CHAT_HOST || '127.0.0.1';
  const origin = process.env.TIME_CHAT_ORIGIN || 'http://127.0.0.1:' + port;
  const data = path.resolve(
    process.env.TIME_CHAT_DATA || path.join(root, 'data')
  );
  await mkdir(data, { recursive: true, mode: 0o700 });
  const installedOrigin = process.env.TIME_CHAT_INSTALLED_ORIGIN;
  if (installedOrigin && (installedOrigin !== new URL(installedOrigin).origin ||
      new URL(installedOrigin).protocol !== 'http:' || new URL(installedOrigin).hostname !== '127.0.0.1' || installedOrigin === origin)) {
    throw new Error('Set TIME_CHAT_INSTALLED_ORIGIN to the separate installed client loopback origin.');
  }
  const enrollmentOrigins = installedOrigin ? [origin, installedOrigin] : [origin];
  const auth = await createAuth({ origin, enrollmentOrigins, dataDirectory: data });
  const installed = installedOrigin ? {
    origin: installedOrigin,
    auth: await createAuth({ origin: installedOrigin, loginRelayOrigin: origin, enrollmentOrigins, dataDirectory: path.join(data,'installed-checkpoint') })
  } : null;
  const store = openStore(
    path.join(data, 'chat-' + auth.networkId + '.sqlite'),
    auth.networkId
  );
  const push = await openPush(data);
  const hosts = [
    new URL(origin).host,
    new URL(process.env.TIME_CHAT_RELAY || origin).host,
    '127.0.0.1:' + port,
    'localhost:' + port,
  ];
  const trustLoopbackProxy = process.env.TIME_CHAT_TRUST_LOOPBACK_PROXY === '1';
  const server = createChatServer({ auth, store, push, origin, installed, hosts, trustLoopbackProxy });
  // Keep each verifier within the network's trusting period even when nobody signs in.
  const checkpointReaders = installed ? [auth, installed.auth] : [auth];
  async function updateCheckpoints() {
    for (const reader of checkpointReaders) {
      try { await reader.refreshCheckpoint(); }
      catch { console.warn('Time checkpoint refresh unavailable.'); }
    }
  }
  void updateCheckpoints();
  const checkpointTimer = setInterval(updateCheckpoints, 6 * 60 * 60 * 1000).unref();
  server.once('close', () => clearInterval(checkpointTimer));
  server.listen(port, host, () =>
    console.log(
      'Time Chat listening on ' + host + ':' + port + ' for ' + origin
    )
  );
  for (const signame of ['SIGINT', 'SIGTERM'])
    process.once(signame, () => {
      server.closeStreams();
      server.close(() => {
        store.close();
        process.exit(0);
      });
    });
}
