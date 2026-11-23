// A proof of the second independent review of the upgrade clients, kept as a test.
// Unchanged but for its import paths: it failed against the lock before the fix (commit a483778) and passes now.
// Round 2 (c): the lock of the watch's data directory. `release` clears the heartbeat timer but does
// not wait for a heartbeat that is already running. That heartbeat has read the lock, writes its
// next copy and renames it into place AFTER release has removed the lock.
// File under test: deploy/watch/start.mjs at commit 4251ceb (claim / holding).
import test from 'node:test';import assert from 'node:assert/strict';
import os from 'node:os';import path from 'node:path';
import {mkdtemp,readFile,readdir,rm,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {claim} from '../deploy/watch/start.mjs';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const exists=async file=>readFile(file,'utf8').then(text=>text,()=>null);

test('RACE: after release() the lock is back in the folder, written by a heartbeat that was in flight',async()=>{
  const rounds=400;let left=0,temporaries=0,first=null;
  const directory=await mkdtemp(path.join(os.tmpdir(),'r2-lock-'));
  try{
    for(let i=0;i<rounds;i++){
      const folder=path.join(directory,String(i));await (await import('node:fs/promises')).mkdir(folder);
      const release=await claim(folder,{beatMs:1,exitOnLost:false});
      await sleep(1+(i%7));         // let some heartbeats run; release then lands at a varying point of one
      await release();
      await sleep(25);              // anything in flight has finished
      const text=await exists(path.join(folder,'watch.lock'));
      if(text!==null){left++;first??={round:i,text};}
      temporaries+=(await readdir(folder)).filter(name=>name!=='watch.lock').length;
    }
    console.log(` ${left} of ${rounds} clean stops left watch.lock behind (heartbeat every 1 ms here; 10 s in production)`);
    if(first)console.log(' the file left behind:',first.text,'| this process:',process.pid);
    console.log(' other files left in the folders:',temporaries);
    assert.equal(left,0,'release() resolved and the lock was put back afterwards');
  }finally{await rm(directory,{recursive:true,force:true});}
});

test('CONSEQUENCE: what the next start does with such a lock',async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),'r2-lock-next-')),file=path.join(directory,'watch.lock');
  const child=spawn(process.execPath,['-e','setTimeout(()=>{},20000)'],{stdio:'ignore'});
  try{
    const outcome=async()=>{try{const release=await claim(directory,{exitOnLost:false});await release();return 'starts at once';}catch(error){return 'refused: '+error.message.slice(0,60);}};
    // The pid is gone (the usual case after a stop): stale at once.
    child.kill();await sleep(200);
    await writeFile(file,JSON.stringify({pid:child.pid,run:'the-run-that-stopped',beat:Date.now()}));
    console.log(' pid of the stopped watch is dead        ->',await outcome());
    // The pid is this one with another run (a restarted container is pid 1 again): stale at once.
    await writeFile(file,JSON.stringify({pid:process.pid,run:'the-run-that-stopped',beat:Date.now()}));
    console.log(' same pid, another run (container)       ->',await outcome());
    // The pid is alive (the old process has not exited yet, or the number was given to another process).
    const other=spawn(process.execPath,['-e','setTimeout(()=>{},20000)'],{stdio:'ignore'});
    try{
      await writeFile(file,JSON.stringify({pid:other.pid,run:'the-run-that-stopped',beat:Date.now()}));
      console.log(' pid alive, heartbeat under 30 s old     ->',await outcome());
      await writeFile(file,JSON.stringify({pid:other.pid,run:'the-run-that-stopped',beat:Date.now()-31_000}));
      console.log(' pid alive, heartbeat over 30 s old      ->',await outcome());
    }finally{other.kill();}
  }finally{child.kill();await rm(directory,{recursive:true,force:true});}
});

test('WORSE, in one process: a start that follows the stop at once has its lock overwritten and gives up',async()=>{
  // The late rename replaces whatever is at watch.lock, also the lock of a successor that claimed
  // the folder between the unlink and the rename. Two runs cannot be made in one process (RUN is
  // per process), so this shows the mechanism with a lock written by hand as the successor's.
  const rounds=400;let overwritten=0;
  const directory=await mkdtemp(path.join(os.tmpdir(),'r2-lock-steal-'));
  try{
    for(let i=0;i<rounds;i++){
      const folder=path.join(directory,String(i));await (await import('node:fs/promises')).mkdir(folder);const file=path.join(folder,'watch.lock');
      const release=await claim(folder,{beatMs:1,exitOnLost:false});
      await sleep(1+(i%7));await release();
      const successor=JSON.stringify({pid:1,run:'the-successor',beat:Date.now()});
      await writeFile(file,successor).catch(()=>{});   // the next watch places its lock right after the stop
      await sleep(25);
      const now=await exists(file);if(now!==null&&now!==successor)overwritten++;
    }
    console.log(` ${overwritten} of ${rounds}: the successor's lock was replaced by the stopped run's (the successor would then stop itself with exit code 75 at its next heartbeat)`);
    assert.equal(overwritten,0,'a stopped run wrote over the lock of its successor');
  }finally{await rm(directory,{recursive:true,force:true});}
});
