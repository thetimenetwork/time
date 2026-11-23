#!/usr/bin/env node
// Run inside the same private namespace. Never expose diagnostics as a wallet
// proof service; the independent light client authenticates application state.
import{createServer}from'node:http';import{json}from'./lib.mjs';import{probe,metricsText,failedSample}from'./operator.mjs';
if(process.argv.length!==3)throw new Error('Usage: monitor.mjs SETTINGS_JSON');
const settings=await json(process.argv[2]);let latest={ready:false,error:'initializing'},busy=false;
async function sample(){if(busy)return;busy=true;try{latest={ready:true,observed_utc:new Date().toISOString(),...await probe(settings)};}catch(e){latest=failedSample(latest,e,new Date().toISOString());}finally{busy=false;}}
await sample();setInterval(sample,5000);
createServer((request,response)=>{if(request.url==='/metrics'){response.writeHead(200,{'content-type':'text/plain; version=0.0.4'});response.end(metricsText(latest));}else if(request.url==='/ready'){response.writeHead(latest.ready?200:503,{'content-type':'application/json'});response.end(JSON.stringify(latest));}else{response.writeHead(404);response.end();}}).listen(26661,'127.0.0.1');
