import { messageStart } from '../public/armor.mjs';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdir, readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { chromium } from 'playwright-core';
import { createAuth } from '../auth.mjs';
import { createChatServer } from '../server.mjs';
import { createInstalledClient } from '../installed-client.mjs';
import { openStore } from '../store.mjs';

const appRoot = fileURLToPath(new URL('../', import.meta.url));
const browserPath = [
  process.env.CHROME_PATH, chromium.executablePath(), '/usr/bin/chromium', '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
].find(value => value && existsSync(value));

async function fixtureAccount(id, name) {
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKey = Buffer.from(await crypto.subtle.exportKey('raw', keys.publicKey)).toString('hex');
  return {
    privateJwk: await crypto.subtle.exportKey('jwk', keys.privateKey),
    account: { id, name, auth_epoch: '0', devices: [{ public_key: publicKey, can_spend: true, can_manage: true }] },
  };
}

// This function executes inside the test-only wallet origin. It signs the app's actual
// challenge with the upstream Time SDK and an ephemeral account generated for this run.
function fixturePopup(appOrigin, { privateJwk, account }) {
  window.addEventListener('message', async event => {
    if (event.source !== window.opener || event.origin !== appOrigin || event.data?.type !== 'time:request') return;
    const request = event.data.request;
    if (request.type !== 'login' || request.challenge.origin !== appOrigin) return;
    const privateKey = await crypto.subtle.importKey('jwk', privateJwk, 'Ed25519', false, ['sign']);
    const result = await TimeSDK.signLogin(request.challenge, { account, publicKey: account.devices[0].public_key, privateKey });
    window.opener.postMessage({ type: 'time:response', version: 1, id: event.data.id, result }, appOrigin);
    setTimeout(() => window.close(), 50);
  });
  window.opener.postMessage({ type: 'time:ready', version: 1 }, appOrigin);
}

async function session(browser, user, { origin, walletOrigin, sdk }) {
  const context = await browser.newContext({ viewport: { width: 1200, height: 800 } });
  const popup = '<script src="/sdk.js"></script><script>(' + fixturePopup.toString() + ')(' +
    JSON.stringify(origin) + ',' + JSON.stringify(user) + ')</script>';
  await context.route(walletOrigin + '/**', route => {
    if (route.request().url() === walletOrigin + '/approve') return route.fulfill({ contentType: 'text/html', body: popup });
    if (route.request().url() === walletOrigin + '/sdk.js') return route.fulfill({ contentType: 'application/javascript', body: sdk });
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(9000);
  await page.goto(origin);
  await page.getByRole('button', { name: 'Sign in with Time' }).click();
  await page.getByRole('button', { name: 'Link this device' }).click();
  await page.locator('#workspace').waitFor({ state: 'visible' });
  return page;
}

async function fixtureRelay(users, installed) {
  const { network_id: networkId } = JSON.parse(await readFile(path.join(appRoot, 'config/testnet-trust.json'), 'utf8'));
  const listener = http.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const origin = 'http://127.0.0.1:' + listener.address().port;
  // Playwright intercepts this entire origin in each test browser. No remote wallet or network is contacted.
  const walletOrigin = 'http://127.0.0.1:32713';
  const store = openStore(':memory:', networkId);
  const upstream = installed ? http.createServer() : null;
  if (upstream) {
    upstream.listen(0,'127.0.0.1');
    await once(upstream,'listening');
  }
  const hostedOrigin = upstream ? 'http://127.0.0.1:' + upstream.address().port : origin;
  try {
    const authFor = loginOrigin => createAuth({
      origin:loginOrigin, loginRelayOrigin:hostedOrigin, enrollmentOrigins:[origin,hostedOrigin], walletOrigin, gateway: origin,
      verifiedState: async () => ({
        verified: true,
        state: {
          protocol_version: '4', network_id: networkId, height: '3',
          time_micros: '3000000', genesis: { genesis_time_micros: '1000000' },
          accounts: users.map(user => user.account), security: [], recovery_cases: [],
        },
      }),
    });
    const auth=await authFor(hostedOrigin);
    const localAuth=installed?await authFor(origin):null;
    const relay = createChatServer({auth,store,push:null,origin:hostedOrigin,installed:localAuth?{origin,auth:localAuth}:null});
    let front=relay;
    if(installed) {
      upstream.on('request',(request,response)=>relay.emit('request',request,response));
      front=createInstalledClient({origin,relay:hostedOrigin,auth:await authFor(origin)});
    }
    listener.on('request', (request, response) => front.emit('request', request, response));
    return {
      origin, hostedOrigin, walletOrigin, sdk: await readFile(auth.sdkPath, 'utf8'), store,
      async close() {
        if(installed) {
          front.stopStreams();front.emit('close');relay.closeStreams();
          upstream.close();upstream.closeAllConnections();relay.emit('close');
        } else relay.emit('close');
        const closed = once(listener, 'close');
        listener.close();
        listener.closeAllConnections();
        await closed;
        store.db.close();
      },
    };
  } catch (error) { listener.close(); upstream?.close(); store.db.close(); throw error; }
}

for (const mode of ['hosted','installed','mixed']) test('two isolated browsers sign in, verify each other and exchange ciphertext in '+mode+' mode', {
  skip: browserPath ? false : 'Set CHROME_PATH to run the two-browser flow', timeout: 65000,
}, async () => {
  // Exercise the actual shipped bundle even on a fresh checkout with no dist directory.
  await import('../build.mjs');
  const users = await Promise.all([fixtureAccount('51', 'alice'), fixtureAccount('62', 'bob')]);
  const relay = await fixtureRelay(users,mode!=='hosted');
  let browser;
  try {
    browser = await chromium.launch({ headless: true, executablePath: browserPath });
    const [alice, bob] = await Promise.all(users.map((user,i) => session(browser, user, mode==='mixed' && i===1 ? {...relay,origin:relay.hostedOrigin} : relay)));
    const requests = [];
    for (const page of [alice, bob]) {
      page.on('request', request => {
        if ([relay.origin,relay.hostedOrigin].includes(new URL(request.url()).origin)) requests.push([request.url(), request.postData() || '']);
      });
    }

    await alice.locator('#new-chat').click();
    await alice.getByLabel('Find a Time account').fill('@bob');
    await alice.getByRole('button', { name: 'Find contact' }).click();
    await alice.getByRole('button', { name: '@bob · #62', exact: true }).click();
    await alice.getByRole('button', { name: 'Start conversation' }).click();
    // Bob must receive the live change via EventSource; this test never refreshes him to discover the new room.
    await bob.locator('#chats .chat-row', { hasText: '@alice' }).click();
    await bob.locator('#verify').click();
    await Promise.all([alice, bob].map(async page => {
      try { await page.locator('.peer-card code').waitFor(); }
      catch (error) {
        throw new Error('Verification screen: ' + await page.locator('body').innerText(), { cause: error });
      }
    }));
    assert.equal(await alice.locator('#draft').isDisabled(), true);
    assert.equal(await bob.locator('#draft').isDisabled(), true);
    const aliceCode = await alice.locator('.peer-card code').innerText();
    const bobCode = await bob.locator('.peer-card code').innerText();
    assert.equal(aliceCode, bobCode);
    assert.match(aliceCode, /^([\dA-F]{4} ){15}[\dA-F]{4}$/);
    await Promise.all([[alice, bobCode], [bob, aliceCode]].map(async ([page, code]) => {
      await page.getByLabel('Their safety code').fill(code);
      await page.getByRole('button', { name: 'Verify code' }).click();
      await page.locator('#dialog').waitFor({ state: 'hidden' });
    }));

    const firstText = 'Meet me by the bookshop at six?';
    const replyText = 'See you there! ';
    await alice.locator('#draft').fill(firstText);
    await alice.locator('#send').click();
    await bob.locator('#messages').getByText(firstText, { exact: true }).waitFor();
    await bob.locator('#draft').fill(replyText);
    await bob.locator('#emoji').click();
    await bob.locator('#emoji-tray').getByRole('button', { name: '🙂', exact: true }).click();
    await bob.locator('#send').click();
    await alice.locator('#messages').getByText(replyText + '🙂', { exact: true }).waitFor();
    await alice.reload();
    await alice.locator('#chats .chat-row', { hasText: '@bob' }).click();
    await alice.locator('#messages').getByText(firstText, { exact: true }).waitFor();
    await alice.locator('#messages').getByText(replyText + '🙂', { exact: true }).waitFor();

    assert.equal(relay.store.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 2);
    const stored = relay.store.db.prepare('SELECT * FROM messages ORDER BY seq').all();
    assert.equal(stored.length, 2);
    assert.deepEqual(stored.map(item => item.senderId), ['51', '62']);
    assert.ok(stored.every(item => item.ciphertext.startsWith(messageStart)));
    const wire = JSON.stringify(requests);
    const rows = JSON.stringify(stored);
    for (const cleartext of [firstText, replyText]) {
      assert.equal(wire.includes(cleartext), false);
      assert.equal(rows.includes(cleartext), false);
    }
    if (process.env.TIME_CHAT_SCREENSHOT) {
      const screenshot = path.resolve(process.env.TIME_CHAT_SCREENSHOT);
      await mkdir(path.dirname(screenshot), { recursive: true });
      await alice.screenshot({ path: screenshot, fullPage: true });
    }
    const actionsFor=(page, text)=>page.getByRole('article').filter({has:page.locator('p',{hasText:text})}).getByRole('button',{name:'Message actions'});
    const edited='Meet me by the library instead.';
    await actionsFor(alice,firstText).click();
    await alice.getByRole('button',{name:'Edit message',exact:true}).click();
    await alice.locator('#draft').fill(edited);
    await alice.locator('#send').click();
    await bob.locator('.bubble p').getByText(edited,{exact:true}).waitFor();
    await actionsFor(bob,edited).click();
    await bob.getByRole('button',{name:'React ❤️',exact:true}).click();
    await alice.locator('.reaction').first().waitFor();
    await actionsFor(bob,edited).click();
    await bob.getByRole('button',{name:'Reply',exact:true}).click();
    const answer='OK, by the library.';
    await bob.locator('#draft').fill(answer);
    await bob.locator('#send').click();
    await alice.locator('.reply-preview').first().waitFor();
    await actionsFor(alice,edited).click();
    await alice.getByRole('button',{name:'Remove message…'}).click();
    await alice.getByRole('button',{name:'Remove message',exact:true}).click();
    await bob.locator('.bubble.removed').waitFor();
    for(const text of [edited,answer]) {
      assert.ok(!JSON.stringify(requests).includes(text));
      assert.ok(!JSON.stringify(relay.store.db.prepare('SELECT * FROM messages').all()).includes(text));
    }
    if (mode === 'installed') {
      // A legitimate network rename can reach the verified state before the directory.
      // Existing safety-code pins must not authorize a stale name on a new page.
      users[1].account.name = 'bobby';
      await alice.reload();
      await alice.locator('#chats .chat-row', {hasText:'@bob'}).click();
      await alice.getByText('Could not verify contacts', {exact:true}).waitFor();
      assert.equal(await alice.locator('#draft').isDisabled(),true);
      assert.equal(await alice.locator('#messages .bubble').count(),0);
      relay.store.enroll({...relay.store.binding('62'),name:'bobby'});
      await alice.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
      await alice.locator('#room-title').getByText('@bobby',{exact:true}).waitFor();
      await alice.locator('#messages .bubble').first().waitFor();
      assert.equal(await alice.locator('#draft').isEnabled(),true);
    }
    if (mode === 'hosted') {
      // A second tab can still be restoring its session when the user signs out.
      // Deliver its genuine earlier account response after the logout broadcast.
      const tab = await alice.context().newPage();
      const pending = Promise.withResolvers(), release = Promise.withResolvers();
      await tab.route('**/api/me', async route => {
        const response = await route.fetch();
        pending.resolve();
        await release.promise;
        await route.fulfill({response});
      });
      try {
        await tab.goto(relay.origin);
        await pending.promise;
        await alice.route('**/api/logout', route => route.abort());
        await alice.locator('#settings').click();
        await alice.getByRole('button',{name:'Sign out',exact:true}).click();
        await tab.locator('#signin-status').getByText('Signed out in another tab.',{exact:true}).waitFor();
        const delivered = tab.waitForResponse('**/api/me');
        release.resolve();
        await (await delivered).finished();
        await tab.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
        assert.equal(await tab.locator('#workspace').isHidden(),true);
        assert.equal(await tab.locator('#user-name').textContent(),'');
        await alice.locator('#signin-status').getByText(/could not confirm session revocation/).waitFor();
        await alice.reload();
        await alice.getByText('Signed out on this device.', {exact:true}).waitFor();
        assert.equal(await alice.locator('#workspace').isHidden(),true);
      } finally { release.resolve(); }
    }
  } finally {
    await browser?.close();
    await relay.close();
  }
});

test('three installed clients verify the full group roster before reading encrypted group text', {
  skip: browserPath ? false : 'Set CHROME_PATH to run the three-browser flow', timeout: 75000,
}, async () => {
  await import('../build.mjs');
  const users = await Promise.all([fixtureAccount('51', 'alice'), fixtureAccount('62', 'bob'), fixtureAccount('73', 'cara')]);
  const relay = await fixtureRelay(users, true);
  let browser;
  try {
    browser = await chromium.launch({ headless: true, executablePath: browserPath });
    const pages = await Promise.all(users.map(user => session(browser, user, relay)));
    const [alice, bob, cara] = pages;
    await alice.locator('#new-chat').click();
    for (const { account } of users.slice(1)) {
      await alice.getByLabel('Find a Time account').fill('@' + account.name);
      await alice.getByRole('button', { name: 'Find contact' }).click();
      await alice.getByRole('button', { name: '@' + account.name + ' · #' + account.id, exact: true }).click();
    }
    await alice.getByRole('button', { name: 'Start group chat' }).click();
    await Promise.all([bob, cara].map(async page => {
      await page.locator('#chats .chat-row', { hasText: '3 members' }).click();
      await page.locator('#verify').click();
    }));
    const peerCard = (i, j) => pages[i].locator('.peer-card', { hasText: '@' + users[j].account.name + ' · #' + users[j].account.id });
    const peerCode = (i, j) => peerCard(i,j).locator('code').innerText();
    const codes = await Promise.all(pages.map((_, i) => Promise.all(pages.map((__, j) => i === j ? null : peerCode(i,j)))));
    for (const [i,j] of [[0,1],[0,2],[1,2]]) assert.equal(codes[i][j],codes[j][i]);
    assert.equal(new Set([codes[0][1],codes[0][2],codes[1][2]]).size,3);
    for (const page of pages) assert.equal(await page.locator('#draft').isDisabled(),true);

    await Promise.all(pages.map(async (page, i) => {
      const peers = [0,1,2].filter(j => j !== i);
      for (const [index,j] of peers.entries()) {
        const card=peerCard(i,j);
        await card.getByLabel('Their safety code').fill(codes[j][i]);
        await card.getByRole('button',{name:'Verify code'}).click();
        // Review redraws after each pin. The creator already approved the roster when selecting members.
        if (index === 0 || i !== 0) await card.getByText('Safety code verified on this device.').waitFor();
      }
    }));
    await alice.locator('#dialog').waitFor({state:'hidden'});
    for (const page of [bob,cara]) {
      assert.equal(await page.locator('#draft').isDisabled(),true);
      await page.getByText('@alice (#51) · @bob (#62) · @cara (#73)', {exact:true}).waitFor();
    }
    await bob.getByRole('button',{name:'Confirm these members'}).click();
    await bob.locator('#dialog').waitFor({state:'hidden'});
    const message='The three of us meet at noon 🌤️';
    await alice.locator('#draft').fill(message);
    await alice.locator('#send').click();
    await bob.locator('#messages').getByText(message,{exact:true}).waitFor();
    assert.equal(await cara.locator('#messages').getByText(message,{exact:true}).count(),0);
    assert.equal(await cara.locator('#draft').isDisabled(),true);
    await cara.getByRole('button',{name:'Confirm these members'}).click();
    await cara.locator('#messages').getByText(message,{exact:true}).waitFor();

    const rows=relay.store.db.prepare('SELECT senderId,ciphertext FROM messages').all();
    assert.equal(rows.length,1);
    assert.equal(rows[0].senderId, '51');
    assert.ok(rows[0].ciphertext.startsWith(messageStart));
    assert.equal(rows[0].ciphertext.includes(message),false);

    // Exercise the page boundary with two genuine enrolled conversations. The
    // fixture narrows only the first page; later pages and room lookup use the API.
    const direct = relay.store.createChat('51',['62']);
    const groupId = relay.store.db.prepare('SELECT room FROM messages LIMIT 1').get().room;
    await alice.route(url => url.pathname === '/api/chats' && !url.search, async route => {
      if (route.request().method() !== 'GET') return route.continue();
      const response = await route.fetch();
      const { chats } = await response.json();
      const first = chats[0];
      assert.equal(first.id,direct.id);
      await route.fulfill({response,json:{chats:[first],nextCursor:first.updatedAt + '.' + first.id}});
    });
    await alice.reload();
    await alice.locator('#filter').fill('cara');
    await alice.getByRole('button',{name:'Load more conversations'}).click();
    await alice.locator('#chats .chat-row',{hasText:'@cara'}).click();
    await alice.locator('#messages').getByText(message,{exact:true}).waitFor();
    const checkedRoom = alice.waitForResponse(response => new URL(response.url()).pathname === '/api/chats/' + groupId && response.ok());
    await alice.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await checkedRoom;
    await alice.locator('#messages').getByText(message,{exact:true}).waitFor();
    assert.equal(await alice.locator('#chats .chat-row',{hasText:'@cara'}).count(),1);
  } finally {
    await browser?.close();
    await relay.close();
  }
});
