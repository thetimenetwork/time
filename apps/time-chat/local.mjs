import { once } from 'node:events';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { createAuth } from './auth.mjs';
import { createChatServer } from './server.mjs';
import { createInstalledClient } from './installed-client.mjs';
import { openPush } from './push.mjs';
import { openStore } from './store.mjs';

const args = parseArgs({ options: { port: { type: 'string', default: '4175' } } });
const port = Number(args.values.port);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Choose a local port from 1 to 65535.');
const origin = 'http://127.0.0.1:' + port;
const root = path.dirname(fileURLToPath(import.meta.url));
const directory = path.resolve(process.env.TIME_CHAT_DATA || path.join(root, 'data', 'local-' + port));
await mkdir(directory, { recursive:true, mode:0o700 });
const [relayAuth,clientAuth,push] = await Promise.all([
  createAuth({origin,dataDirectory:path.join(directory,'relay-checkpoint')}),
  createAuth({origin,dataDirectory:path.join(directory,'client-checkpoint')}),
  openPush(directory)
]);
const db = openStore(path.join(directory,relayAuth.networkId + '.sqlite'), relayAuth.networkId);
const hosts = [];
const relay = createChatServer({auth:relayAuth,store:db,push,origin,hosts});
let client;
try {
  relay.listen(0,'127.0.0.1');
  await once(relay,'listening');
  const relayHost = '127.0.0.1:' + relay.address().port;
  hosts.push(relayHost);
  client = createInstalledClient({origin,relay:'http://' + relayHost,loginRelayOrigin:origin,auth:clientAuth});
  client.listen(port,'127.0.0.1');
  await once(client,'listening');
  console.log('Time Chat is ready at ' + origin);
} catch(error) {
  relay.close();
  db.close();
  throw error;
}
async function stop() {
  client.stopStreams();
  relay.closeStreams();
  await Promise.all([client,relay].map(server=>new Promise(resolve=>server.close(resolve))));
  db.close();
}
process.once('SIGINT',stop);
process.once('SIGTERM',stop);
