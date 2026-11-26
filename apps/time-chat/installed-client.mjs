import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createAuth, keyCommitment } from './auth.mjs';
import { serveAsset } from './assets.mjs';

const hour = 60 * 60 * 1000;
const hex32 = /^[a-f0-9]{64}$/;
const cookieName = 'time_chat_installed';
const fixedGet = new Set(['/api/config', '/api/me', '/api/events', '/api/contacts', '/api/chats', '/api/blocks']);
const fixedPost = new Set(['/api/login/challenge', '/api/login/finish', '/api/logout', '/api/chats', '/api/push', '/api/push/remove', '/api/blocks']);
const proofRoute = /^\/api\/contacts\/(0|[1-9]\d{0,19})\/proof$/;
const roomRoute = /^\/api\/chats\/[a-f0-9]{64}\/(messages|read)$/;
const preToken = /^(?:bind\.[a-f0-9]{64}|[a-f0-9]{64}\.\d{1,16}\.\d{1,16}\.[a-f0-9]{64})$/;
const apiHeaders = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Cross-Origin-Resource-Policy': 'same-origin'
};

function refuse(status, message) { throw Object.assign(new Error(message), { status }); }
function json(res, status, value) {
  res.writeHead(status, { ...apiHeaders, 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
}
function checkRoutes(method, url) {
  const p = url.pathname, room = roomRoute.exec(p);
  const allowed = method === 'GET' ? fixedGet.has(p) || proofRoute.test(p) || room?.[1] === 'messages'
    : method === 'POST' && (fixedPost.has(p) || Boolean(room));
  if (!allowed) refuse(404, 'Unknown client route.');
  const params = [...url.searchParams.keys()];
  if (!params.length) return;
  if (method === 'GET' && params.length === 1 &&
      (p === '/api/contacts' && params[0] === 'q' && url.searchParams.get('q').length <= 40 ||
       room?.[1] === 'messages' && params[0] === 'before' && /^[1-9]\d{0,15}$/.test(url.searchParams.get('before')))) return;
  refuse(400, 'Unexpected query parameters.');
}
async function readJson(stream, limit, upstream) {
  const chunks = []; let bytes = 0;
  for await (const chunk of stream) {
    bytes += chunk.length;
    if (bytes > limit) refuse(upstream ? 502 : 413, 'Message exceeds the client limit.');
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  } catch {}
  refuse(upstream ? 502 : 400, 'Expected a JSON object.');
}

function canonicalRelay(value) {
  if (!value) throw new Error('Set TIME_CHAT_RELAY to the relay HTTPS origin or a loopback HTTP origin.');
  const url = new URL(value);
  if (url.origin !== value || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)))) {
    throw new Error('Invalid TIME_CHAT_RELAY origin.');
  }
  return url;
}

function relayCookie(response, name, pattern) {
  const entries = response.headers.getSetCookie().filter(entry => entry.startsWith(name + '='));
  const value = entries[0]?.split(';')[0].slice(name.length + 1);
  if (entries.length !== 1 || !pattern.test(value || '')) refuse(502, 'Relay authentication state was invalid.');
  return value;
}

async function eventHints(response, res, controller) {
  if (response.headers.get('content-type')?.split(';')[0] !== 'text/event-stream') refuse(502, 'Relay event stream unavailable.');
  res.writeHead(200, { ...apiHeaders, 'Content-Type': 'text/event-stream' });
  res.write(': connected\n\n');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let partial = '', lastChange = 0, lastKeepAlive = 0;
  let idle = setTimeout(() => controller.abort(), 90000).unref();
  try {
    for await (const chunk of response.body) {
      idle.refresh();
      if (chunk.length > 16384) break;
      partial += decoder.decode(chunk, { stream: true });
      let end;
      while ((end = /\r?\n\r?\n/.exec(partial))) {
        const frame = partial.slice(0, end.index).replaceAll('\r\n', '\n');
        partial = partial.slice(end.index + end[0].length);
        if (frame.length > 256) refuse(502, 'Invalid event stream.');
        if (frame === 'event: change\ndata: {}' && Date.now() - lastChange >= 100) {
          lastChange = Date.now();
          if (!res.write('event: change\ndata: {}\n\n')) await once(res, 'drain', { signal: controller.signal });
        } else if (frame.startsWith(':') && Date.now() - lastKeepAlive >= 15000) {
          lastKeepAlive = Date.now();
          if (!res.write(': open\n\n')) await once(res, 'drain', { signal: controller.signal });
        }
      }
      if (partial.length > 256) break;
    }
  } finally { clearTimeout(idle); controller.abort(); res.end(); }
}

/** UI assets are always installed files. The relay can supply only parsed data on fixed routes. */
export function createInstalledClient({ origin, relay, auth, fetcher = fetch }) {
  const local = new URL(origin), target = canonicalRelay(relay);
  if (local.origin !== origin || local.protocol !== 'http:' || local.hostname !== '127.0.0.1') throw new Error('Use a 127.0.0.1 client origin.');
  if (['127.0.0.1', '[::1]', 'localhost'].includes(target.hostname) && target.port === local.port) throw new Error('Use different ports for the relay and the installed client.');
  const sessions = new Map(), pendingStreams = new Set();
  function prune() { for (const [key,s] of sessions) if (s.expires <= Date.now()) sessions.delete(key); }
  const clean = setInterval(prune, 60_000).unref();
  function getSession(req) {
    const value = (req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(cookieName+'='))?.slice(cookieName.length+1);
    const session = value && sessions.get(value);
    if (session?.expires > Date.now()) return session;
    return null;
  }
  function startSession(res) {
    prune();
    if (sessions.size >= 128) refuse(429, 'Too many open sign-in requests.');
    const id = randomBytes(32).toString('hex');
    const session = { id, expires: Date.now()+180000, pre: null, token: null, accountId: null, challenge: null };
    sessions.set(id, session);
    res.setHeader('Set-Cookie', cookieName+'='+id+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600');
    return session;
  }
  function clearSession(res, session) {
    sessions.delete(session?.id);
    res.setHeader('Set-Cookie', cookieName+'=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  }
  const server = createServer(async (req,res) => {
    const controller = new AbortController();
    res.once('close', () => controller.abort());
    let timer;
    try {
      if (req.headers.host !== local.host || !req.url?.startsWith('/') || req.url.startsWith('//') || req.url.includes('\\') || req.url.length > 2048) refuse(403, 'Local host required.');
      const url = new URL(req.url, origin), p = url.pathname, post = req.method === 'POST';
      if (url.origin !== origin) refuse(403, 'Local origin required.');
      if (!p.startsWith('/api/')) {
        if (!url.search && await serveAsset(req,res,p)) return;
        refuse(404, 'Page unavailable.');
      }
      if ((req.headers.origin && req.headers.origin !== origin) || (post && req.headers.origin !== origin) ||
          (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') ||
          (req.headers['sec-fetch-dest'] && req.headers['sec-fetch-dest'] !== 'empty')) refuse(403, 'Open the installed Time Chat client.');
      checkRoutes(req.method,url);
      let session = getSession(req), body;
      if (post) {
        if (req.headers['content-type']?.split(';')[0] !== 'application/json') refuse(415, 'JSON required.');
        body = await readJson(req,160*1024,false);
      }
      if (p === '/api/me' && !session?.token) return json(res,200,{user:null});
      if (!session && p === '/api/login/challenge') session = startSession(res);
      if (p !== '/api/config' && !session) refuse(401, 'Sign in with Time.');
      let signedUser = null;
      if (p === '/api/login/finish') {
        const request = session.challenge;
        session.challenge = null;
        if (!request || request.expiresAt <= Date.now()) refuse(401,'Open the wallet to sign in again.');
        try { signedUser = await auth.verifyFreshLogin(request,body); }
        catch { refuse(401,'The wallet signature or current Time account could not be verified.'); }
        if (session.bound && session.accountId !== signedUser.accountId) refuse(401,'Link a key using the same Time account.');
      }
      const headers = { Accept: p === '/api/events' ? 'text/event-stream' : 'application/json', 'X-Time-Chat-Client':'installed' };
      if (post) { headers.Origin=origin; headers['Content-Type']='application/json'; }
      const csrf = req.headers['x-csrf-token'];
      if (csrf !== undefined) {
        if (typeof csrf !== 'string' || !hex32.test(csrf)) refuse(403,'Invalid session token.');
        headers['X-CSRF-Token']=csrf;
      }
      const cookies = [];
      if (session?.token) cookies.push('time_chat_session='+session.token);
      if (session?.pre && p === '/api/login/finish') cookies.push('time_chat_pre='+session.pre);
      if (cookies.length) headers.Cookie = cookies.join('; ');
      timer = setTimeout(() => controller.abort(),30000).unref();
      const remote = await fetcher(new URL(p+url.search,target),{
        method:req.method, headers, body:post ? JSON.stringify(body) : undefined, redirect:'error', signal:controller.signal
      });
      if (!remote.ok) {
        await remote.body?.cancel();
        if (p === '/api/logout') { clearSession(res,session); return json(res,200,{ok:true}); }
        const status = [400,401,403,404,409,413,415,429,503].includes(remote.status) ? remote.status : 502;
        return json(res,status,{error:status===401?'Sign in with Time again.':status===409?'The requested change conflicts with an existing record.':'The relay declined or could not complete this request.'});
      }
      if (p === '/api/events') {
        clearTimeout(timer); pendingStreams.add(controller);
        try { await eventHints(remote,res,controller); } finally { pendingStreams.delete(controller); }
        return;
      }
      if (remote.headers.get('content-type')?.split(';')[0] !== 'application/json') refuse(502,'Invalid relay response format.');
      let output = await readJson(remote.body,roomRoute.test(p) && !post ? 8*1024*1024 : 2*1024*1024,true);
      if (p === '/api/config') {
        if (output.networkId !== auth.networkId || output.walletOrigin !== auth.walletOrigin) refuse(502,'The relay uses another Time network or wallet.');
        // A relay cannot nominate a different service as an authority for enrollment.
        output = {networkId:auth.networkId,walletOrigin:auth.walletOrigin,enrollmentOrigins:[origin,target.origin],pushKey:typeof output.pushKey==='string' && /^[a-zA-Z0-9_-]{87}$/.test(output.pushKey) ? output.pushKey : null};
      } else if (p === '/api/login/challenge') {
        const c = output.challenge;
        if (c?.purpose!=='login' || c.origin!==origin || c.networkId!==auth.networkId || !hex32.test(c.nonce) ||
            !Number.isSafeInteger(c.issuedAt) || !Number.isSafeInteger(c.expiresAt) || c.issuedAt > Date.now()+10000 ||
            c.expiresAt<=Date.now() || c.expiresAt-c.issuedAt!==180000) refuse(502,'The relay returned an invalid Time challenge.');
        session.bound = body.publicKey != null;
        if (session.bound && (!session.accountId || c.nonce !== keyCommitment(output.salt,body.publicKey))) refuse(502,'The relay did not bind this device key.');
        session.pre=relayCookie(remote,'time_chat_pre',preToken);
        session.challenge={purpose:'login',origin,networkId:auth.networkId,nonce:c.nonce,issuedAt:c.issuedAt,expiresAt:c.expiresAt};
        output={challenge:session.challenge,salt:session.bound?output.salt:null};
      } else if (p === '/api/login/finish') {
        session.token=relayCookie(remote,'time_chat_session',hex32);
        session.accountId=signedUser.accountId; session.name=signedUser.name; session.pre=null;
        session.expires=Date.now()+hour;
        res.setHeader('Set-Cookie',cookieName+'='+session.id+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600');
        output={ok:true};
      } else if (p === '/api/logout') {
        clearSession(res,session); output={ok:true};
      } else if (p === '/api/me') {
        if (!output.user) { clearSession(res,session); output={user:null}; }
        else {
          if (output.user.id!==session.accountId || output.user.name!==session.name || !hex32.test(output.csrf)) refuse(502,'Relay session does not match the signed Time account.');
          output={user:{id:session.accountId,name:session.name,publicKey:output.user.publicKey??null},csrf:output.csrf};
        }
      } else if (proofRoute.test(p)) {
        const id=proofRoute.exec(p)[1];
        if (output.id!==id || typeof output.publicKey!=='string') refuse(502,'The relay returned another contact.');
        let checked;
        try { checked=await auth.verifyAttestation({accountId:id,publicKey:output.publicKey,attestation:output.attestation}); }
        catch { refuse(502,'The contact key could not be independently verified against Time.'); }
        if (checked.accountId!==id || checked.name!==output.name) refuse(502,'The contact name does not match Time.');
        output={id,name:checked.name,publicKey:output.publicKey,attestation:output.attestation,verified:true};
      }
      json(res,200,output);
    } catch(error) {
      if (!res.headersSent && !res.destroyed) json(res,error.status||502,{error:error.status?error.message:'Could not reach the configured relay.'});
      else res.end();
    } finally { clearTimeout(timer); controller.abort(); }
  });
  server.stopStreams=()=>{for(const controller of pendingStreams)controller.abort();};
  server.on('close',()=>clearInterval(clean));
  return server;
}

if(process.argv[1] && pathToFileURL(process.argv[1]).href===import.meta.url) {
  const root=path.dirname(fileURLToPath(import.meta.url));
  const port=Number(process.env.TIME_CHAT_CLIENT_PORT||4175);
  if (!Number.isInteger(port)||port<1||port>65535) throw new Error('Invalid TIME_CHAT_CLIENT_PORT.');
  const origin='http://127.0.0.1:'+port, relay=canonicalRelay(process.env.TIME_CHAT_RELAY);
  const data=path.resolve(process.env.TIME_CHAT_CLIENT_DATA||path.join(root,'data','client-'+port));
  const auth=await createAuth({origin,enrollmentOrigins:[origin,relay.origin],dataDirectory:data});
  const server=createInstalledClient({origin,relay:relay.origin,auth});
  server.listen(port,'127.0.0.1',()=>console.log('Installed Time Chat is available at '+origin));
  for (const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>{server.stopStreams();server.close();});
}
