import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request as httpRequest } from 'node:http';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createInstalledClient } from '../installed-client.mjs';
import { loginNoncePrefix } from '../public/login-nonce.mjs';

const origin = 'http://127.0.0.1:4173', relay = 'https://relay.example';
const networkId = 'a'.repeat(64), walletOrigin = 'https://wallet.example';
const asJson = (value, headers = {}) => new Response(JSON.stringify(value), {headers: {'Content-Type':'application/json',...headers}});

async function setup(t) {
  const calls=[], keys=[];
  const state = { checkedName:'bob', denyKey:false, signedId:'7', relayId:'7', configId:networkId, proofId:'9', offline:false };
  const challenge = {purpose:'login',origin,networkId,nonce:await loginNoncePrefix(relay)+'8'.repeat(32),issuedAt:Date.now(),expiresAt:Date.now()+180000};
  challenge.expiresAt=challenge.issuedAt+180000;
  const fetcher = async (url,options) => {
    calls.push({path:url.pathname,headers:options.headers,redirect:options.redirect,body:options.body});
    assert.equal(url.origin,relay);
    if (state.offline) throw Error('Relay offline');
    assert.equal(options.headers['X-Time-Chat-Local'],undefined);
    assert.equal(options.headers['x-time-chat-local'],undefined);
    if (url.pathname === '/api/config') return asJson({networkId:state.configId,walletOrigin,pushKey:null,extraneous:'omitted'});
    if (url.pathname === '/api/login/challenge') return asJson({challenge},{'Set-Cookie':'time_chat_pre='+['1'.repeat(64),'1710000000','1719999999','2'.repeat(64)].join('.')+'; Domain=relay.example; Path=/anything; SameSite=None'});
    if (url.pathname === '/api/login/finish') return asJson({ok:true},{'Set-Cookie':['time_chat_session='+'3'.repeat(64)+'; Path=/; SameSite=None']});
    if (url.pathname === '/api/me') return asJson({user:{id:state.relayId,name:'alice',publicKey:null},csrf:'4'.repeat(64)});
    if (url.pathname.includes('/proof')) return asJson({id:state.proofId,name:'bob',publicKey:'public armor',attestation:{version:1},verified:true});
    if (url.pathname === '/api/blocks') return asJson({users:[]});
    if (url.pathname === '/api/chats' && url.searchParams.has('cursor')) return asJson({chats:[],nextCursor:null});
    if (url.pathname === '/api/chats/'+'7'.repeat(64)) return asJson({chat:{id:'7'.repeat(64)}});
    if (url.pathname === '/api/events') return new Response(': relay-controlled comment\n\nevent: other\ndata: secret\n\nevent: change\ndata: {}\n\n',{headers:{'Content-Type':'text/event-stream','Service-Worker-Allowed':'/'}});
    return new Response('<script>untrusted</script>',{headers:{'Content-Type':'text/html','Set-Cookie':'foreign=bad','Service-Worker-Allowed':'/'}});
  };
  const auth = {networkId,walletOrigin,
    verifyFreshLogin:async(challenge,proof)=>{assert.equal(proof.message.nonce,challenge.nonce);return {accountId:state.signedId,name:'alice'};},
    verifyAttestation:async input=>{keys.push(input);if(state.denyKey)throw Error('Unverified');return {accountId:input.accountId,name:state.checkedName};}
  };
  const server = createInstalledClient({origin,relay,auth,fetcher});
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  t.after(async()=>{server.stopStreams();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  let browserCookie;
  async function fetchLocal(route,body,headers={}) {
    const h={Host:'127.0.0.1:4173','X-Time-Chat-Local':'5'.repeat(64),...browserCookie?{Cookie:browserCookie}:{},...body?{Origin:origin,'Content-Type':'application/json'}:{},...headers};
    const result=await new Promise((resolve,reject)=>{
      const req=httpRequest({hostname:'127.0.0.1',port:server.address().port,path:route,method:body?'POST':'GET',headers:h},res=>{
        const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('error',reject);
        res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,text:Buffer.concat(chunks).toString('utf8')}));
      });req.on('error',reject);req.end(body?JSON.stringify(body):undefined);
    });
    const cookie=result.headers['set-cookie']?.[0];if(cookie)browserCookie=cookie.split(';')[0];
    return result;
  }
  async function login(){
    const start=await fetchLocal('/api/login/challenge',{});
    assert.equal(start.status,200);
    assert.match(start.headers['set-cookie'][0],/HttpOnly; SameSite=Strict/);
    assert.doesNotMatch(start.headers['set-cookie'][0],/time_chat_pre|Domain=/);
    const finish=await fetchLocal('/api/login/finish',{message:challenge});
    assert.equal(finish.status,200);
    assert.equal(calls.at(-1).headers.Cookie.startsWith('time_chat_pre='),true);
    assert.notEqual(start.headers['set-cookie'][0].split(';')[0],finish.headers['set-cookie'][0].split(';')[0]);
    assert.equal(JSON.parse((await fetchLocal('/api/me',null,{Cookie:start.headers['set-cookie'][0].split(';')[0]})).text).user,null);
  }
  return {fetchLocal,login,calls,keys,state,challenge};
}

test('installed shell never asks the relay for executable files; API origin, host and route are constrained',async t=>{
  const {fetchLocal,calls,state}=await setup(t);
  const asset=await fetchLocal('/app.mjs');
  try {
    const installed=await readFile(new URL('../dist/app.mjs',import.meta.url),'utf8');
    assert.equal(asset.status,200);assert.equal(asset.text,installed);
  } catch(error){if(error.code!=='ENOENT')throw error;assert.equal(asset.status,502);}
  assert.equal((await fetchLocal('/injected-script.js')).status,404);
  assert.equal((await fetchLocal('/api/private')).status,404);
  assert.equal((await fetchLocal('/api/config?url=https://elsewhere.example')).status,400);
  assert.equal((await fetchLocal('/api/config',null,{Host:'untrusted.example:4173'})).status,403);
  assert.equal((await fetchLocal('/api/config',null,{'Sec-Fetch-Site':'same-site'})).status,403);
  assert.equal((await fetchLocal('/api/login/challenge',{},{Origin:'https://foreign.example'})).status,403);
  assert.equal(calls.length,0);
  const config=await fetchLocal('/api/config');
  assert.deepEqual(JSON.parse(config.text),{networkId,walletOrigin,loginRelayOrigin:relay,installedClient:true,enrollmentOrigins:[origin,relay],pushKey:null});
  assert.equal(calls[0].redirect,'error');
  state.configId='b'.repeat(64);
  assert.equal((await fetchLocal('/api/config')).status,502);
});

test('the installed session needs its origin credential and logout clears it while the relay is offline',async t=>{
  const {fetchLocal,login,calls,state}=await setup(t);
  await login();
  const count=calls.length;
  const otherBinding={'X-Time-Chat-Local':'6'.repeat(64)};
  assert.equal(JSON.parse((await fetchLocal('/api/me',null,otherBinding)).text).user,null);
  assert.equal((await fetchLocal('/api/events',null,otherBinding)).status,401);
  assert.equal(calls.length,count);
  state.offline=true;
  const logout=await fetchLocal('/api/logout',{});
  assert.equal(logout.status,200);
  assert.match(logout.headers['set-cookie'][0],/Max-Age=0/);
  assert.equal(JSON.parse((await fetchLocal('/api/me')).text).user,null);
});

test('installed login requires the ordinary login purpose and the configured relay',async t=>{
  const {fetchLocal,challenge}=await setup(t);
  challenge.nonce=(await loginNoncePrefix('https://other.example'))+'8'.repeat(32);
  assert.equal((await fetchLocal('/api/login/challenge',{})).status,502);
  challenge.nonce='7'.repeat(64);
  assert.equal((await fetchLocal('/api/login/challenge',{})).status,502);
});

test('installed client binds the session to the local wallet and checks each contact against Time',async t=>{
  const {fetchLocal,login,calls,keys,state}=await setup(t);
  await login();
  const session=await fetchLocal('/api/me');
  assert.equal(JSON.parse(session.text).user.id,'7');
  assert.equal(calls.at(-1).headers.Cookie,'time_chat_session='+'3'.repeat(64));
  state.relayId='8';
  assert.equal((await fetchLocal('/api/me')).status,502);
  const route='/api/contacts/9/proof';
  assert.equal((await fetchLocal(route)).status,200);
  assert.deepEqual(keys.at(-1),{accountId:'9',publicKey:'public armor',attestation:{version:1}});
  state.checkedName='impostor';
  assert.equal((await fetchLocal(route)).status,502);
  state.proofId='10';
  assert.equal((await fetchLocal(route)).status,502);
  state.proofId='9';state.denyKey=true;
  assert.equal((await fetchLocal(route)).status,502);
});

test('installed client relays fixed notification hints and rejects HTML returned from JSON APIs',async t=>{
  const {fetchLocal,login}=await setup(t);await login();
  const sse=await fetchLocal('/api/events');
  assert.equal(sse.status,200);assert.equal(sse.headers['content-type'],'text/event-stream');
  assert.equal(sse.text,': connected\n\n: open\n\nevent: change\ndata: {}\n\n');
  assert.equal(sse.headers['service-worker-allowed'],undefined);
  const html=await fetchLocal('/api/chats');
  assert.equal(html.status,502);assert.equal(html.headers['x-content-type-options'],'nosniff');
  assert.match(html.headers['content-security-policy'],/default-src 'none'/);
  assert.doesNotMatch(html.text,/script/);assert.equal(html.headers['set-cookie'],undefined);
  assert.deepEqual(JSON.parse((await fetchLocal('/api/blocks')).text),{users:[]});
  const cursor='1740000000000.'+'a'.repeat(64);
  assert.deepEqual(JSON.parse((await fetchLocal('/api/chats?cursor='+cursor)).text),{chats:[],nextCursor:null});
  assert.equal((await fetchLocal('/api/chats?cursor=unknown')).status,400);
  assert.equal((await fetchLocal('/api/chats?cursor='+cursor+'&cursor='+cursor)).status,400);
  const single='/api/chats/'+'7'.repeat(64);
  assert.deepEqual(JSON.parse((await fetchLocal(single)).text),{chat:{id:'7'.repeat(64)}});
  assert.equal((await fetchLocal(single+'?cursor='+cursor)).status,400);
  assert.equal((await fetchLocal(single,{})).status,404);
});
