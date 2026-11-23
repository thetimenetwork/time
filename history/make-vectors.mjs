// Independent recursive JavaScript oracle for the Rust append/frontier code.
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
const hash=(...parts)=>createHash('sha256').update(Buffer.concat(parts)).digest();
const network=Buffer.from(Array.from({length:32},(_,i)=>i+1));
const be=n=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));return b;};
const leaf=n=>({height:String(n),block_hash:hash(Buffer.from('block:'+n)).toString('hex'),time_micros:String(1000+n)});
const leafHash=l=>hash(Buffer.from([0]),Buffer.from('TIME-HISTORY-V1\0'),network,be(l.height),Buffer.from(l.block_hash,'hex'),be(l.time_micros));
const node=(l,r)=>hash(Buffer.from([1]),l,r);
const commit=(size,root)=>hash(Buffer.from([2]),Buffer.from('TIME-HISTORY-V1\0'),network,be(size),root);
const split=n=>2**Math.floor(Math.log2(n-1));
function tree(rows){if(rows.length===0)return hash();if(rows.length===1)return leafHash(rows[0]);const k=split(rows.length);return node(tree(rows.slice(0,k)),tree(rows.slice(k)));}
function path(rows,index){if(rows.length===1)return [];const k=split(rows.length);return index<k?[...path(rows.slice(0,k),index),tree(rows.slice(k)).toString('hex')]:[...path(rows.slice(k),index-k),tree(rows.slice(0,k)).toString('hex')];}
const vectors=[];
for(const size of [1,2,3,7,8,17,65,257]){
  const rows=Array.from({length:size},(_,i)=>leaf(i+1));let start=0;const peaks=[];
  for(let bit=Math.floor(Math.log2(size));bit>=0;bit--)if((BigInt(size)&(1n<<BigInt(bit)))!==0n){const count=2**bit;peaks.push(tree(rows.slice(start,start+count)).toString('hex'));start+=count;}
  vectors.push({summary:{version:1,network_id:network.toString('hex'),size:String(size),root:commit(size,tree(rows)).toString('hex'),last_time_micros:String(1000+size),peaks},leaves:rows,proofs:[...new Set([1,Math.floor(size/2)+1,size])].map(height=>({leaf:rows[height-1],siblings:path(rows,height-1)}))});
}
await writeFile(new URL('./vectors.json',import.meta.url),JSON.stringify({format:'time-history-v1-cross-language',vectors},null,2)+'\n');
