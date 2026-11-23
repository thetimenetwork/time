// Node 26 SQLite: durable exact-reference merchant orders with indexed lookups.
// No full order-history reload or rewrite for each purchase.
import {DatabaseSync} from 'node:sqlite';
export function createOrderStore({filename,networkId,recipient}){
 if(!filename||!/^[0-9a-f]{64}$/.test(networkId)||!/^(0|[1-9][0-9]*)$/.test(recipient))throw Error('Invalid durable merchant scope');
 const db=new DatabaseSync(filename);db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
 db.exec('CREATE TABLE IF NOT EXISTS scope (id INTEGER PRIMARY KEY CHECK(id=1), network TEXT NOT NULL, recipient TEXT NOT NULL);CREATE TABLE IF NOT EXISTS orders (reference TEXT PRIMARY KEY, payer TEXT NOT NULL, hash TEXT UNIQUE, fulfilled INTEGER NOT NULL CHECK(fulfilled IN(0,1)), value TEXT NOT NULL);CREATE INDEX IF NOT EXISTS orders_payer ON orders(payer);');
 const scope=db.prepare('SELECT network,recipient FROM scope WHERE id=1').get();if(scope&&(scope.network!==networkId||scope.recipient!==recipient)){db.close();throw Error('Merchant database belongs to another network or recipient');}if(!scope)db.prepare('INSERT INTO scope VALUES(1,?,?)').run(networkId,recipient);
 const get=db.prepare('SELECT value FROM orders WHERE reference=?'),used=db.prepare('SELECT reference FROM orders WHERE hash=?'),insert=db.prepare('INSERT INTO orders(reference,payer,hash,fulfilled,value) VALUES(?,?,NULL,0,?)'),settle=db.prepare('UPDATE orders SET hash=?,fulfilled=1,value=? WHERE reference=? AND fulfilled=0'),note=db.prepare('UPDATE orders SET value=? WHERE reference=? AND fulfilled=0'),paid=db.prepare('SELECT 1 AS paid FROM orders WHERE payer=? AND fulfilled=1 LIMIT 1');
 function validate(order){if(order?.networkId!==networkId||order.to!==recipient||!/^[0-9a-f]{64}$/.test(order.orderId)||typeof order.accountId!=='string'||!order.reservedNonce||!order.expiresElapsedMicros)throw Error('Invalid merchant record scope');}
 return Object.freeze({
  get:reference=>{const row=get.get(reference);return row?JSON.parse(row.value):null;},
  usedHash:hash=>used.get(hash)?.reference||null,
  // Whether the account has an order that is settled. Only settle() marks one, and server-auth.mjs calls it only
  // after it verified the payment (the demo blog's "supporter" mark, server.mjs).
  paidBy:payer=>typeof payer==='string'&&paid.get(payer)!==undefined,
  insert:order=>{validate(order);if(order.fulfilled)throw Error('Cannot insert a pre-settled order');insert.run(order.orderId,order.accountId,JSON.stringify(order));},
  settle:order=>{validate(order);if(!order.fulfilled||!/^[A-F0-9]{64}$/.test(order.hash))throw Error('Finalized payment hash required');const result=settle.run(order.hash,JSON.stringify(order),order.orderId);if(result.changes!==1)throw Error('Order settlement race or missing order');},
  // The record of an own node that contradicted the light client (server-auth.mjs), on an unsettled
  // order; nothing else of the order may change.
  note:order=>{validate(order);if(order.fulfilled||!Array.isArray(order.ownNodeMismatches))throw Error('A note records own-node mismatches on an unsettled order');const row=get.get(order.orderId);if(!row)throw Error('Order note for a missing order');const {ownNodeMismatches:_before,...was}=JSON.parse(row.value),{ownNodeMismatches,...rest}=order;if(JSON.stringify(was)!==JSON.stringify(rest))throw Error('A note changes only the record of own-node mismatches');if(note.run(JSON.stringify(order),order.orderId).changes!==1)throw Error('Order note race or settled order');},
  close:()=>db.close(),
 });
}
