import test from'node:test';import assert from'node:assert/strict';import{mkdtemp}from'node:fs/promises';import{tmpdir}from'node:os';import path from'node:path';import{validateSettings,rpcAdapter,claimDirectory,ownNodeOption,startReport}from'./start.mjs';
const valid={manifest_file:process.platform==='win32'?'C:\\operator\\manifest.json':'/operator/manifest.json',manifest_sha256:'01'.repeat(32),native_rpc_url:'http://127.0.0.1:26657/',data_directory:process.platform==='win32'?'C:\\gateway-data':'/data/gateway',recipient:'0',wallet_port:8907,merchant_port:8908,public_origins:{wallet:'https://wallet.example',merchant:'https://app.example'}};
test('gateway bootstrap refuses lab callbacks and malformed independent manifest/settings',()=>{assert.equal(validateSettings(valid),valid);for(const patch of [{onSponsorRegistration:()=>{}},{onRegtestBid:()=>{}},{manifest_sha256:'bad'},{manifest_file:'relative'},{recipient:'01'},{wallet_port:0},{wallet_port:8908}])assert.throws(()=>validateSettings({...valid,...patch}));});
test('gateway bootstrap requires exact distinct HTTPS origins and literal private RPC',()=>{for(const url of ['https://public-rpc.example/','http://localhost:26657/','http://127.1:26657/','http://127.0.0.1:0/','http://127.0.0.1:26657/path','http://user:pass@127.0.0.1:26657/'])assert.throws(()=>validateSettings({...valid,native_rpc_url:url}));for(const origins of [{wallet:'http://wallet.example',merchant:'https://app.example'},{wallet:'https://wallet.example/',merchant:'https://app.example'},{wallet:'https://same.example',merchant:'https://same.example'}])assert.throws(()=>validateSettings({...valid,public_origins:origins}));});
test('RPC adapter forwards only explicitly allowed methods/strings with redirect refusal',async()=>{let observed;const rpc=rpcAdapter(valid.native_rpc_url,async(url,options)=>{observed={url:String(url),options};return new Response(JSON.stringify({result:{height:'7'}}));});assert.deepEqual(await rpc('/commit',{height:'7'}),{height:'7'});assert.equal(observed.url,'http://127.0.0.1:26657/commit?height=7');assert.equal(observed.options.redirect,'error');await assert.rejects(rpc('/unsafe_flush_mempool'));await assert.rejects(rpc('/commit',{height:7}));});
test('RPC adapter fails closed for malformed responses and byte-bound violations',async()=>{for(const response of [new Response('{}'),new Response(JSON.stringify({error:{code:-1}})),new Response('bad'),new Response('unavailable',{status:503}),new Response('x'.repeat(8*1024*1024+1))]){const rpc=rpcAdapter(valid.native_rpc_url,async()=>response);await assert.rejects(rpc('/commit'));}});
test('gateway checkpoint/order directory permits one writer and deliberate clean release',async()=>{const directory=await mkdtemp(path.join(tmpdir(),'time-gateway-lock-')),release=await claimDirectory(directory);await assert.rejects(claimDirectory(directory),/already claimed/);await release();await release();const second=await claimDirectory(directory);await second();});

test('RPC adapter lets the receipt watcher read heights, blocks and headers',async()=>{
  const seen=[];const rpc=rpcAdapter(valid.native_rpc_url,async url=>{seen.push(new URL(url).pathname);return new Response(JSON.stringify({result:{ok:true}}));});
  for(const method of ['/status','/block','/header','/commit','/validators','/abci_query','/tx','/broadcast_tx_sync'])await rpc(method,method==='/status'?{}:{height:'1'});
  assert.equal(seen.length,8);
  for(const method of ['/unsafe_flush_mempool','/dial_peers','/broadcast_tx_async','/genesis'])await assert.rejects(rpc(method,{}),/not allowed/);
});

test('own full node setting: optional, its own literal-loopback origin, never the native RPC',()=>{
  // Without the setting the gateway gets no ownNode option: settlement as before.
  assert.equal(ownNodeOption(valid),undefined);
  const own={rpc_url:'http://127.0.0.1:26757/',above_micros:'1000000000',timeout_ms:5000};
  assert.equal(validateSettings({...valid,own_node:own}).own_node,own);
  assert.deepEqual(ownNodeOption({...valid,own_node:own}),{url:'http://127.0.0.1:26757/',aboveMicros:'1000000000',timeoutMs:5000});
  // Defaults (every order, 5000 ms) are applied by the order service.
  assert.deepEqual(ownNodeOption(validateSettings({...valid,own_node:{rpc_url:'http://127.0.0.1:26757/'}})),{url:'http://127.0.0.1:26757/'});
  for(const bad of [null,[],'http://127.0.0.1:26757/',{},{above_micros:'0'},
    {rpc_url:valid.native_rpc_url},{rpc_url:'https://node.example/'},{rpc_url:'http://localhost:26757/'},{rpc_url:'http://127.0.0.1:26757'},{rpc_url:'http://127.0.0.1:26757/status'},{rpc_url:'http://127.0.0.1:0/'},{rpc_url:'http://user:pass@127.0.0.1:26757/'},
    {...own,above_micros:0},{...own,above_micros:'01'},{...own,above_micros:'-1'},{...own,above_micros:'18446744073709551616'},
    {...own,timeout_ms:50},{...own,timeout_ms:60001},{...own,timeout_ms:'5000'},{...own,rpc:'http://127.0.0.1:26757/'}])
    assert.throws(()=>validateSettings({...valid,own_node:bad}),/own_node/,JSON.stringify(bad));
});

test('the start log says whether the pinned manifest declares that the nodes report upgrades, and warns when it does not',()=>{
  const server={walletListenOrigin:'http://127.0.0.1:8907',merchantListenOrigin:'http://127.0.0.1:8908'};
  const declared=startReport({...server,nodesReportUpgrades:true});
  assert.deepEqual(declared.ready,{status:'PRIVATE_HTTPS_PROXY_UPSTREAMS_READY',wallet:'http://127.0.0.1:8907',merchant:'http://127.0.0.1:8908',public_funds_allowed:false,signing_callbacks:false,nodes_report_upgrades:true});
  assert.equal(declared.warning,null);
  // Anything but the server's own `true` is "not declared": the weaker way is never chosen silently.
  for(const said of [false,undefined,'true',1]){
    const report=startReport({...server,nodesReportUpgrades:said});
    assert.equal(report.ready.nodes_report_upgrades,false);
    assert.deepEqual([report.warning.event,report.warning.level],['UPGRADE_REPORTS_NOT_DECLARED','warn']);
    assert.match(report.warning.message,/^The pinned manifest does not say that this network's nodes report upgrades \(trust\.nodes_report_upgrades is not true\)\./);
  }
});

test('registration_service is optional and, when given, a canonical HTTPS origin that is neither the wallet nor the shop',()=>{
  assert.equal(validateSettings({...valid,registration_service:'https://faucet.example'}).registration_service,'https://faucet.example');
  for(const bad of ['http://faucet.example','https://faucet.example/','https://faucet.example/v1','https://user:secret@faucet.example','http://127.0.0.1:8940','faucet.example','',42,null,"https://faucet.example; script-src *",'https://wallet.example','https://app.example'])assert.throws(()=>validateSettings({...valid,registration_service:bad}),/registration_service must/,String(bad));
  // It is a place the wallet page may ask, never a key the gateway holds: signing callbacks stay refused.
  assert.throws(()=>validateSettings({...valid,registration_service:'https://faucet.example',onSponsorRegistration:()=>{}}),/signing callbacks are forbidden/);
});
