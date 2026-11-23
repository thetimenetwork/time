// Drives a headless Chrome, with a new empty profile, through the wallet's screens on preview-server.mjs: takes a
// screenshot of each screen, and walks the paths of campaign/lib/browser-check.mjs that the mock chain can carry, with
// the same selectors in the same order. Nothing here touches a network; see preview-server.mjs for what it proves
// (nothing about the wallet's checks) and what it shows (the pages, their layout, their wiring, their CSP).
//
//   node web-v4/wallet/tests/preview-server.mjs &
//   node web-v4/wallet/tests/preview-drive.mjs [--out DIR] [--chrome PATH] [--widths 390,1280] [--theme light|dark] [--only screens,flows]
//
// DIR receives NNNN-name.png per screen and width, and log.txt: each step with ok or FAIL, and what the pages complained of.
import { launchChrome, createBrowser } from '../../../campaign/lib/browser-check.mjs';
import { mkdir, readdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const argument = (name, fallback) => { const at = process.argv.indexOf(name); return at < 0 ? fallback : process.argv[at + 1]; };
const out = path.resolve(argument('--out', path.join(os.tmpdir(), `time-wallet-preview-${Date.now()}`)));
const widths = argument('--widths', '390,1280').split(',').map(Number), theme = argument('--theme', 'light'), only = new Set(argument('--only', 'screens,flows').split(','));
const chromePath = argument('--chrome', process.platform === 'win32' ? 'C:/Program Files/Google/Chrome/Application/chrome.exe' : '/usr/bin/google-chrome');
const port = Number(argument('--port', '8977')), W = `http://127.0.0.1:${port}`, F = `http://127.0.0.1:${port + 1}`;
const PASSWORD = 'correct horse battery staple 41', PAYMENT = 'quiet harbour lanterns at dawn 77';
await mkdir(out, { recursive: true });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const chrome = await launchChrome({ chrome: chromePath, profile: path.join(out, 'profile') });
const cdp = chrome.cdp, browser = createBrowser({ cdp, screenshots: out });
const log = [], pages = [];
const expect = (condition, message) => { if (!condition) throw new Error(message); };
const until = (page, expression, what, ms = 60000) => browser.until(page, expression, what, ms);
const notice = (page, words, what, ms = 60000) => until(page, `(() => { const n = document.querySelector('#notice'); return n && !n.hidden && n.textContent.includes(${JSON.stringify(words)}); })()`, what, ms);
const metrics = (width, height) => ({ width, height: height ?? (width < 600 ? 844 : 900), deviceScaleFactor: 1, mobile: width < 600 });
async function look(page, width) {
  await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] }, page.sessionId);
  await cdp.send('Emulation.setDeviceMetricsOverride', metrics(width), page.sessionId);
}
/// A picture of the screen; `full`: of the whole page (the viewport is made as tall as the page for it).
async function shot(page, name, width, { full = false } = {}) {
  await delay(250);
  if (full) {
    const { cssContentSize } = await cdp.send('Page.getLayoutMetrics', {}, page.sessionId);
    await cdp.send('Emulation.setDeviceMetricsOverride', metrics(width, Math.min(Math.ceil(cssContentSize.height), 7000)), page.sessionId); await delay(250);
  }
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' }, page.sessionId);
  await writeFile(path.join(out, `${width}-${name}.png`), Buffer.from(data, 'base64'));
  if (full) await cdp.send('Emulation.setDeviceMetricsOverride', metrics(width), page.sessionId);
}
async function opened(seed, width = 1280) {
  const page = await browser.open(W + '/'); pages.push(page); await look(page, width);
  await until(page, `!document.querySelector('#auth-submit').disabled`, 'the wallet is ready');
  if (seed) {
    await browser.ask(page, `fetch('/__seed?s=${seed}').then(r => r.json()).then(o => { for (const [k, v] of Object.entries(o)) localStorage.setItem(k, v); return true; })`);
    await browser.go(page, W + '/'); await until(page, `!document.querySelector('#auth-submit').disabled`, 'the wallet is ready again');
  }
  return page;
}
async function unlock(page, name) {
  await browser.click(page, '#mode-unlock'); await browser.fill(page, 'username', name); await browser.fill(page, 'password', PASSWORD); await browser.click(page, '#auth-submit');
  await until(page, `(!document.querySelector('#dashboard').hidden && document.querySelector('#account-name').textContent === '@${name}' && document.querySelector('#account-verification').textContent === 'Checked by this browser')`, 'the dashboard', 120000);
}
const faucetMode = (page, mode) => browser.ask(page, `fetch('/__faucet?mode=${mode}').then(() => true)`);
async function step(name, work) {
  const at = Date.now();
  try { const detail = await work(); log.push(`ok   ${name} (${Date.now() - at} ms) ${JSON.stringify(detail ?? {}).slice(0, 400)}`); }
  catch (error) { log.push(`FAIL ${name}: ${String(error.message).slice(0, 700)}`); }
}

if (only.has('screens')) for (const width of widths) {
  await step(`screens ${width}: start`, async () => {
    const page = await opened(null, width);
    await shot(page, '01-start-create', width);
    await browser.click(page, '#mode-unlock'); await shot(page, '02-start-open', width);
    await browser.ask(page, `(document.querySelectorAll('.other-ways details').forEach(d => d.open = true), true)`); await shot(page, '03-start-other-ways', width, { full: true });
  });
  await step(`screens ${width}: an account with one key`, async () => {
    const page = await opened('single', width); await unlock(page, 'alice');
    await shot(page, '10-home', width, { full: true });
    await browser.click(page, '#home-receive'); await shot(page, '11-receive', width);
    await browser.click(page, '.nav [data-panel="send"]'); await browser.fill(page, 'recipient', 'bob'); await browser.fill(page, 'amount', '1.5'); await shot(page, '12-send', width);
    await browser.click(page, '#send-submit'); await until(page, `document.querySelector('#review-dialog').open`, 'the review'); await shot(page, '13-send-review', width);
    await delay(800); await browser.click(page, '#review-confirm'); await notice(page, 'needs to do nothing', 'sent'); await shot(page, '14-sent', width);
    await browser.click(page, '.nav [data-panel="home"]'); await faucetMode(page, 'ok');
    await browser.click(page, '#faucet-button'); await notice(page, 'You received', 'test time'); await shot(page, '15-test-time', width);
    await faucetMode(page, 'account_limit'); await browser.click(page, '#faucet-button'); await until(page, `document.querySelector('#notice').className.includes('error')`, 'a refusal'); await shot(page, '16-test-time-refused', width);
    await faucetMode(page, 'odd'); await browser.click(page, '#faucet-button'); await notice(page, 'The test faucet refused this request', 'the faucet\'s words'); await shot(page, '17-test-time-faucet-words', width);
    await faucetMode(page, 'ok');
    await browser.click(page, '#tab-security'); await shot(page, '20-keys-one-key', width, { full: true });
    await browser.ask(page, `(document.querySelector('#secure-open').open = true)`); await shot(page, '21-keys-protect-form', width, { full: true });
    await browser.click(page, '.nav [data-panel="activity"]'); await shot(page, '32-activity', width, { full: true });
    await browser.ask(page, `(() => { const s = document.querySelector('#activity-search'); s.value = 'nothing like this'; s.dispatchEvent(new Event('input')); return true; })()`); await shot(page, '32b-activity-search-none', width);
    await browser.ask(page, `(() => { const s = document.querySelector('#activity-search'); s.value = ''; s.dispatchEvent(new Event('input')); return true; })()`);
    await browser.click(page, '.nav [data-panel="more"]'); await shot(page, '30-more', width);
    for (const [panel, name] of [['earn', '31-staking'], ['devices', '33-devices'], ['recovery', '34-guardians'], ['integrate', '35-use-in-your-app']]) {
      await browser.click(page, `.more-list [data-panel="${panel}"]`); await shot(page, name, width, { full: true }); await browser.click(page, `#panel-${panel} .back`);
    }
    await browser.click(page, '#lock-button'); await until(page, `document.querySelector('#dashboard').hidden`, 'locked'); await shot(page, '04-locked', width);
  });
  await step(`screens ${width}: a protected account`, async () => {
    const page = await opened('protected', width); await browser.ask(page, `fetch('/__reset').then(() => true)`); await unlock(page, 'carol');
    await shot(page, '40-home-protected', width, { full: true });
    // The Protection card on Home: each of its steps open, and the card of an account that is paused, then frozen.
    const sheet = await browser.ask(page, `fetch('/__papers').then(r => r.json()).then(p => p.sheet)`);
    const stepOpen = (id) => until(page, `document.querySelector('#${id}').getClientRects().length > 0`, `the step ${id}`);
    const confirmed = async (words) => { await until(page, `document.querySelector('#review-dialog').open`, 'the review'); await delay(800); await browser.click(page, '#review-confirm'); await notice(page, words, words, 120000); };
    await browser.click(page, '#limit-open'); await stepOpen('limit-form'); await browser.fill(page, 'limit-amount', '45'); await shot(page, '45-protect-limit-step', width, { full: true }); await browser.click(page, '#limit-cancel');
    await browser.click(page, '#pause-switch'); await stepOpen('pause-form'); await shot(page, '46-protect-pause-step', width, { full: true });
    await browser.fill(page, 'pause-payment', PAYMENT); await browser.click(page, '#pause-form button[type=submit]');
    await until(page, `document.querySelector('#review-dialog').open`, 'the review of the pause'); await shot(page, '47-protect-pause-review', width);
    await confirmed('Payments are paused'); await shot(page, '48-protect-paused', width, { full: true });
    await browser.click(page, '.nav [data-panel="send"]'); await browser.fill(page, 'recipient', 'bob'); await browser.fill(page, 'amount', '0.5'); await browser.fill(page, 'send-payment', PAYMENT);
    await browser.click(page, '#send-submit'); await until(page, `!document.querySelector('#send-over-limit').hidden`, 'a payment while paused'); await browser.fill(page, 'send-payment', PAYMENT); await browser.click(page, '#send-wait'); await confirmed('Your payment is waiting');
    await browser.click(page, '.nav [data-panel="home"]'); await until(page, `document.querySelector('#security-inbox-card').getClientRects().length > 0`, 'what waits'); await shot(page, '49-protect-paused-waiting', width, { full: true });
    await browser.click(page, '#pause-switch'); await stepOpen('resume-step'); await shot(page, '50-protect-resume-step', width, { full: true });
    await browser.fill(page, 'resume-payment', PAYMENT); await browser.fill(page, 'resume-secret', sheet); await browser.click(page, '#resume-now');
    await until(page, `document.querySelector('#review-dialog').open`, 'the review of the end of the pause'); await shot(page, '51-protect-resume-review', width);
    await confirmed('Payments are no longer paused'); await shot(page, '52-protect-pause-ended', width, { full: true });
    await browser.click(page, '#freeze-switch'); await stepOpen('freeze-form'); await shot(page, '53-protect-freeze-step', width, { full: true });
    await browser.fill(page, 'freeze-secret', PAYMENT); await browser.click(page, '#freeze-form button[type=submit]'); await confirmed('Your account is frozen'); await shot(page, '54-protect-frozen', width, { full: true });
    await browser.click(page, '#unfreeze-open'); await stepOpen('unfreeze-form'); await shot(page, '55-protect-unfreeze-step', width, { full: true }); await browser.click(page, '#unfreeze-cancel');
    // Whether anything on Home is wider than the screen, in any of these states.
    const wide = await browser.ask(page, `({ window: window.innerWidth, page: document.documentElement.scrollWidth, rows: [...document.querySelectorAll('#protect-card .switch-row')].map(r => Math.round(r.getBoundingClientRect().height)) })`);
    expect(wide.page <= wide.window, `Home is ${wide.page} wide in a window of ${wide.window}`);
    expect(wide.rows.every(height => height >= 44), `the rows of the switches are ${JSON.stringify(wide.rows)} pixels tall`);
    await browser.ask(page, `fetch('/__reset').then(() => true)`); await browser.click(page, '#refresh'); await notice(page, 'Your balance was checked again', 'read again');
    await browser.click(page, '#tab-security'); await shot(page, '41-keys-protected', width, { full: true });
    await browser.ask(page, `(document.querySelector('#keys-change').open = true)`); await shot(page, '42-keys-change', width, { full: true });
    await browser.click(page, '.nav [data-panel="send"]'); await browser.fill(page, 'recipient', 'bob'); await browser.fill(page, 'amount', '40'); await browser.fill(page, 'send-payment', PAYMENT);
    await browser.click(page, '#send-submit'); await until(page, `!document.querySelector('#send-over-limit').hidden`, 'over the limit'); await shot(page, '43-send-over-limit', width, { full: true });
    // What "Print this page" prints: the print stylesheet with the class that button sets.
    await browser.click(page, '#tab-security'); await browser.ask(page, `(document.body.classList.add('print-keys'), true)`);
    await cdp.send('Emulation.setEmulatedMedia', { media: 'print' }, page.sessionId); await shot(page, '44-keys-print', width, { full: true }); await look(page, width);
    await browser.ask(page, `(document.body.classList.remove('print-keys'), true)`);
  });
  await step(`screens ${width}: a website's window`, async () => {
    const page = await opened('single', width), shop = await browser.open(F + '/shop', { context: page.browserContextId });
    await browser.click(shop, '#login');
    const popup = await browser.opened(shop, W + '/approve'); pages.push(popup); const small = Math.min(width, 460); await look(popup, small);
    await until(popup, `!document.querySelector('#auth-submit').disabled`, 'the window is ready'); await shot(popup, '50-website-window-locked', small, { full: true });
    await unlock(popup, 'alice').catch(() => {});
    await until(popup, `/^https?:/.test(document.querySelector('#approval-origin').textContent) && !document.querySelector('#approve-request').disabled`, 'the request', 120000); await shot(popup, '51-website-sign-in', small, { full: true });
    await browser.click(popup, '#approve-request'); await until(popup, `document.querySelector('#review-dialog').open`, 'the review'); await shot(popup, '52-website-review', small);
    await delay(800); await browser.click(popup, '#review-confirm'); await until(popup, `document.querySelector('#approval-title').textContent === 'Done'`, 'done'); await shot(popup, '53-website-done', small);
    return { website_says: (await browser.text(shop, '#out')).slice(0, 80) };
  });
}

if (only.has('flows')) {
  const downloads = path.join(out, 'downloads'); await mkdir(downloads, { recursive: true });
  const alice = await opened('single'); await unlock(alice, 'alice');
  await step('flow: a held Enter key in the amount field signs nothing', async () => {
    const nonce = () => browser.ask(alice, `fetch('/api/view-proof?query=' + encodeURIComponent(JSON.stringify({ names: ['alice'] }))).then(r => r.json()).then(p => p.state.accounts[0].nonce)`);
    await browser.click(alice, '[data-panel="send"]'); await browser.fill(alice, 'recipient', 'bob'); await browser.fill(alice, 'amount', '0.02');
    await browser.ask(alice, `(document.querySelector('#amount').focus(), document.activeElement.id)`);
    const before = await nonce(); let opened = false;
    await browser.key(alice, 'keyDown', { text: '\r' });
    for (let i = 0; i < 40; i++) { await browser.key(alice, 'keyDown', { text: '\r', repeat: true }); await delay(50); opened ||= await browser.ask(alice, `document.querySelector('#review-dialog').open === true`); }
    await browser.key(alice, 'keyUp'); await delay(2500);
    const after = await browser.ask(alice, `({ open: document.querySelector('#review-dialog').open === true, focus: document.activeElement?.id || document.activeElement?.tagName })`), now = await nonce();
    if (after.open) await browser.ask(alice, `(document.querySelector('#review-dialog').close('cancel'), true)`);
    expect(now === before, `a held Enter key signed: nonce ${before} -> ${now}`);
    return { review_opened: opened, after };
  });
  await step('flow: the backup file from Keys, restored in a fresh profile, a wrong password refused', async () => {
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads, eventsEnabled: true, browserContextId: alice.browserContextId });
    await browser.click(alice, '#tab-security'); await browser.fill(alice, 'backup-export-password', PASSWORD); await browser.click(alice, '#backup-export-submit');
    await notice(alice, 'Backup file downloaded', 'downloaded', 120000); await delay(1500);
    const name = (await readdir(downloads)).find(f => f.endsWith('.vault.json')); expect(name, 'no file was downloaded');
    expect(await browser.ask(alice, `document.querySelector('#backup-export-password').value === '' && document.querySelector('#home-backup').hidden`), 'the password stayed, or Home still suggests the backup');
    const fresh = await opened(null);
    await until(fresh, `!document.querySelector('#backup-import-submit').disabled`, 'restore ready');
    await browser.ask(fresh, `(document.querySelector('.backup-import').open = true)`);
    const root = await cdp.send('DOM.getDocument', { depth: 0 }, fresh.sessionId), input = await cdp.send('DOM.querySelector', { nodeId: root.root.nodeId, selector: '#backup-file' }, fresh.sessionId);
    await cdp.send('DOM.setFileInputFiles', { files: [path.join(downloads, name)], nodeId: input.nodeId }, fresh.sessionId);
    await browser.fill(fresh, 'backup-password', 'not the password of this backup 5512'); await browser.click(fresh, '#backup-import-submit');
    await until(fresh, `(() => { const n = document.querySelector('#notice'); return n && !n.hidden && n.className.includes('error'); })()`, 'refused', 120000);
    await cdp.send('DOM.setFileInputFiles', { files: [path.join(downloads, name)], nodeId: input.nodeId }, fresh.sessionId);
    await browser.fill(fresh, 'backup-password', PASSWORD); await browser.click(fresh, '#backup-import-submit');
    await notice(fresh, 'Backup restored', 'restored', 120000); await unlock(fresh, 'alice');
    return { file: name };
  });
  // The step "protection-not-yet" of campaign/lib/browser-check.mjs, with its selectors.
  await step('flow: Home of an account that is not protected: the card, and its button to "Protect my account" with the suggested limit', async () => {
    await browser.click(alice, '[data-panel="home"]');
    const card = await browser.ask(alice, `({ shown: document.querySelector('#protect-none').getClientRects().length > 0, on: document.querySelector('#protect-on').getClientRects().length > 0, says: document.querySelector('#protect-none').innerText.replace(/\\s+/g, ' ').trim() })`);
    expect(card.shown && !card.on && card.says.includes('Not protected yet') && card.says.includes('One key can move everything, and a forgotten password cannot be replaced.') && card.says.includes('Protect my account'), JSON.stringify(card));
    const usable = await browser.ask(alice, `({ send: !document.querySelector('#home-send').disabled, payment_password_asked: !document.querySelector('#send-payment-wrap').hidden })`);
    expect(usable.send && !usable.payment_password_asked, JSON.stringify(usable));
    await browser.click(alice, '#protect-start');
    await until(alice, `(() => { const form = document.querySelector('#secure-form'), b = form.querySelector('button[type=submit]'); return !document.querySelector('#panel-security').hidden && document.querySelector('#secure-open').open === true && form.getClientRects().length > 0 && !b.disabled; })()`, 'the form of "Protect my account"');
    const form = await browser.ask(alice, `({ limit: document.querySelector('#secure-limit').value, suggested: document.querySelector('#secure-limit-suggested').textContent, focus: document.activeElement?.id || document.activeElement?.tagName || '' })`);
    expect(form.limit === '600' && form.suggested.includes('10 minutes of seconds a day (600)'), JSON.stringify(form));
    return { ...card, ...form };
  });
  await step('flow: "Protect my account" up to its review (the review is cancelled: the mock chain cannot take it)', async () => {
    await browser.click(alice, '#tab-security');
    await until(alice, `!document.querySelector('#panel-security').hidden && !document.querySelector('#security-adopt').hidden`, 'offers to protect');
    await browser.ask(alice, `(document.querySelector('#secure-open').open = true)`);
    await until(alice, `(() => { const b = document.querySelector('#secure-form button[type=submit]'); return !document.querySelector('#panel-security').hidden && b && !b.disabled; })()`, 'the form');
    for (const [id, value] of [['secure-login', 'harbor lantern login words 1'], ['secure-login-confirm', 'harbor lantern login words 1'], ['secure-payment', 'copper meadow pay words 22'], ['secure-payment-confirm', 'copper meadow pay words 22'], ['secure-limit', '0.03']]) await browser.fill(alice, id, value);
    await browser.click(alice, '#secure-form button[type=submit]');
    await until(alice, `(!document.querySelector('#secure-sheet-step').hidden && document.querySelector('#secure-sheet').textContent.length > 20)`, 'the sheet', 240000);
    const written = await browser.ask(alice, `({ sheet: document.querySelector('#secure-sheet').textContent, phrase: document.querySelector('#secure-phrase-shown').textContent })`);
    const groups = written.sheet.toUpperCase().replace(/[^0-9A-HJKMNP-TV-Z]/g, '').match(/.{1,4}/g);
    await browser.click(alice, '#secure-sheet-done'); await until(alice, `!document.querySelector('#secure-confirm-step').hidden`, 'asks back');
    const asked = await browser.ask(alice, `[document.querySelector('#secure-confirm-a-label').textContent, document.querySelector('#secure-confirm-b-label').textContent]`);
    const pick = label => groups[Number(/Group (\d+)/.exec(label)[1]) - 1];
    await browser.fill(alice, 'secure-confirm-a', pick(asked[0])); await browser.fill(alice, 'secure-confirm-b', pick(asked[1])); await browser.fill(alice, 'secure-confirm-phrase', written.phrase);
    await browser.click(alice, '#secure-submit'); await until(alice, `document.querySelector('#review-dialog').open === true`, 'the review');
    const title = await browser.text(alice, '#review-title'); await browser.ask(alice, `(document.querySelector('#review-dialog').close('cancel'), true)`);
    expect(title === 'Protect my account', title);
    return { groups: groups.length, asked };
  });
  // The steps of campaign/lib/browser-check.mjs for the Protection card ("protection-card", "protection-pause",
  // "protection-pause-off", "security-freeze"), with its selectors in its order, on the mock chain.
  await step('flow: the Protection card of a protected account: its state, pause on, a payment that waits, pause off with the recovery sheet, and the freeze from the switch', async () => {
    const carol = await opened('protected'); await browser.ask(carol, `fetch('/__reset').then(() => true)`); await unlock(carol, 'carol');
    const sheet = await browser.ask(carol, `fetch('/__papers').then(r => r.json()).then(p => p.sheet)`);
    const cardOf = () => browser.ask(carol, `(() => { const q = (s) => document.querySelector(s), seen = (s) => { const e = q(s); return Boolean(e) && e.getClientRects().length > 0; }; return { shown: seen('#protect-card'), not_protected: seen('#protect-none'), protected: seen('#protect-on'), status: q('#protect-status').textContent, alert: q('#protect-status').className.includes('warning'), freeze_on: q('#freeze-switch').checked, freeze_says: q('#freeze-switch-state').textContent, freeze_note: q('#freeze-note').textContent, pause_on: q('#pause-switch').checked, pause_says: q('#pause-switch-state').textContent, pause_note: q('#pause-note').textContent, bar: q('#limit-bar').value, limit: q('#limit-text').textContent, waiting: q('#protect-waiting').textContent, rule: seen('#protect-rule') ? q('#protect-rule').textContent : '', open_steps: ['freeze-form', 'unfreeze-form', 'limit-form', 'pause-form', 'resume-step'].filter((id) => seen('#' + id)) }; })()`);
    const confirmReview = async (title) => { await until(carol, `document.querySelector('#review-dialog').open === true`, 'the review'); const shown = await browser.ask(carol, `({ title: document.querySelector('#review-title').textContent, body: document.querySelector('#review-body').innerText })`); expect(shown.title === title, `the review is titled "${shown.title}", expected "${title}"`); await browser.click(carol, '#review-confirm'); return shown; };
    const homeChecked = async () => { await browser.click(carol, '[data-panel="home"]'); await browser.click(carol, '#refresh'); await notice(carol, 'Your balance was checked again against the network', 'read again'); };
    await homeChecked();
    let card = await cardOf();
    expect(card.shown && card.protected && !card.not_protected && card.status === 'Your account is protected.' && !card.alert, JSON.stringify(card));
    expect(!card.freeze_on && card.freeze_says === 'Off' && !card.pause_on && card.pause_says === 'Off' && card.limit === 'You can pay 30 of 30 seconds now without waiting, fees included.' && Number(card.bar) === 1000 && card.waiting === 'Nothing is waiting.' && card.open_steps.length === 0, JSON.stringify(card));
    expect(card.rule.startsWith('Switching protection on is immediate') && card.rule.includes('recovery paper') && card.rule.includes('thief'), card.rule);
    const switches = await browser.ask(carol, `['freeze-switch', 'pause-switch'].map((id) => { const e = document.getElementById(id); return { id, type: e.type, role: e.getAttribute('role'), label: e.labels?.[0]?.querySelector('.switch-name')?.textContent ?? '', disabled: e.disabled, tab: e.tabIndex }; })`);
    expect(switches.every((s) => s.type === 'checkbox' && s.role === 'switch' && s.label && !s.disabled && s.tab === 0), JSON.stringify(switches));
    // A real key on the switch that has the focus: the space bar presses it, as a click does.
    await browser.ask(carol, `(document.querySelector('#pause-switch').focus(), true)`);
    await browser.key(carol, 'keyDown', { key: ' ', code: 'Space', virtual: 32, text: ' ' }); await browser.key(carol, 'keyUp', { key: ' ', code: 'Space', virtual: 32 });
    await until(carol, `document.querySelector('#pause-form').getClientRects().length > 0`, 'the space bar on the switch opens its step');
    expect((await browser.ask(carol, `document.querySelector('#pause-switch').checked`)) === false, 'the switch shows "on" before the chain says so');
    await browser.click(carol, '#pause-cancel');
    // Pause on.
    await browser.click(carol, '#pause-switch');
    await until(carol, `document.querySelector('#pause-form').getClientRects().length > 0`, 'the switch opens its step');
    expect((await browser.ask(carol, `document.querySelector('#pause-switch').checked`)) === false, 'the switch shows "on" before the chain says so');
    await browser.fill(carol, 'pause-payment', PAYMENT); await browser.click(carol, '#pause-form button[type=submit]');
    const pause = await confirmReview('Pause payments');
    expect(pause.body.includes('A payment started then waits') && pause.body.includes('recovery paper'), pause.body.slice(0, 300));
    await notice(carol, 'Payments are paused', 'paused', 120000);
    card = await cardOf();
    expect(card.pause_on && card.pause_says === 'On' && card.status === 'Payments are paused.' && card.limit === 'Paused: nothing can be paid at once.' && Number(card.bar) === 0 && card.open_steps.length === 0, JSON.stringify(card));
    expect(card.pause_note.includes('A payment started now waits') && card.pause_note.includes('you can cancel it'), card.pause_note);
    const remembered = await browser.ask(carol, `Object.entries(localStorage).filter(([k]) => k.startsWith('timecurrency.pause.v1:')).map(([, v]) => JSON.parse(v).limit)`);
    expect(remembered.length === 1 && remembered[0] === '30000000', JSON.stringify(remembered));
    // A payment now waits.
    await browser.click(carol, '[data-panel="send"]');
    await browser.fill(carol, 'recipient', 'bob'); await browser.fill(carol, 'amount', '0.001'); await browser.fill(carol, 'send-payment', PAYMENT);
    await browser.click(carol, '#send-submit');
    await until(carol, `!document.querySelector('#send-over-limit').hidden`, 'the choices of a payment while paused');
    const offered = await browser.ask(carol, `({ review_open: document.querySelector('#review-dialog').open, wait_offered: !document.querySelector('#send-wait').disabled })`);
    expect(offered.review_open === false && offered.wait_offered, JSON.stringify(offered));
    await browser.fill(carol, 'send-payment', PAYMENT); await browser.click(carol, '#send-wait');
    await confirmReview('Pay after the waiting period'); await notice(carol, 'Your payment is waiting', 'waits', 120000);
    await browser.click(carol, '[data-panel="home"]');
    await until(carol, `/payments? (is|are) waiting/.test(document.querySelector('#protect-waiting').textContent)`, 'the card counts the waiting payment');
    await until(carol, `(document.querySelector('#security-inbox-card').getClientRects().length > 0 && document.querySelector('#security-inbox').innerText.includes('Waiting payment'))`, 'Home lists the waiting payment');
    // Pause off, with the recovery sheet.
    await homeChecked();
    await browser.click(carol, '#pause-switch');
    await until(carol, `document.querySelector('#resume-step').getClientRects().length > 0`, 'the step that ends the pause');
    const ways = await browser.ask(carol, `(() => { const q = (s) => document.querySelector(s), seen = (s) => q(s).getClientRects().length > 0; return { switch_on: q('#pause-switch').checked, amount: q('#resume-amount').value, amount_note: q('#resume-amount-note').textContent, wait_note: q('#resume-wait-note').textContent, wait_shown: seen('#resume-wait'), wait_enabled: !q('#resume-wait').disabled, now_shown: seen('#resume-now'), now_enabled: !q('#resume-now').disabled }; })()`);
    expect(ways.switch_on === true && ways.amount === '30' && ways.amount_note.includes('as this browser remembers it') && ways.wait_shown && ways.now_shown && ways.now_enabled, JSON.stringify(ways));
    expect(!ways.wait_enabled && ways.wait_note.startsWith('Not possible right now'), JSON.stringify(ways));
    await browser.ask(carol, `(document.querySelector('#resume-method').value = 'sheet', document.querySelector('#resume-method').dispatchEvent(new Event('change', { bubbles: true })), true)`);
    await browser.fill(carol, 'resume-payment', PAYMENT); await browser.fill(carol, 'resume-secret', sheet);
    await browser.click(carol, '#resume-now');
    const resume = await confirmReview('End the pause now with a recovery paper');
    expect(resume.body.includes('30 seconds a day, at once') && resume.body.includes('is cancelled') && resume.body.includes('fills up over 24 hours'), resume.body.slice(0, 400));
    await notice(carol, 'Payments are no longer paused', 'the pause has ended', 180000);
    const after = await browser.ask(carol, `({ unlocked: !document.querySelector('#dashboard').hidden, removed: !document.querySelector('#security-removed-panel').hidden, password: document.querySelector('#resume-payment').value, sheet: document.querySelector('#resume-secret').value, remembered: Object.keys(localStorage).filter((k) => k.startsWith('timecurrency.pause.v1:')).length })`);
    expect(after.unlocked && !after.removed && after.password === '' && after.sheet === '' && after.remembered === 0, JSON.stringify({ ...after, password: after.password.length, sheet: after.sheet.length }));
    card = await cardOf();
    expect(!card.pause_on && card.pause_says === 'Off' && card.status === 'Your account is protected.' && card.waiting === 'Nothing is waiting.' && card.open_steps.length === 0 && Number(card.bar) < 100, JSON.stringify(card));
    await browser.click(carol, '#tab-security');
    expect((await browser.text(carol, '#security-limit')).includes('30'), 'the Keys screen does not show the limit');
    // The freeze, from the switch.
    await homeChecked();
    await browser.click(carol, '#freeze-switch');
    await until(carol, `document.querySelector('#freeze-form').getClientRects().length > 0`, 'the step that freezes');
    expect((await browser.ask(carol, `document.querySelector('#freeze-switch').checked`)) === false, 'the switch shows "on" before the chain says so');
    await browser.ask(carol, `(document.querySelector('#freeze-method').value = 'payment', document.querySelector('#freeze-method').dispatchEvent(new Event('change', { bubbles: true })), true)`);
    await browser.fill(carol, 'freeze-secret', PAYMENT); await browser.click(carol, '#freeze-form button[type=submit]');
    await confirmReview('Freeze account'); await notice(carol, 'Your account is frozen', 'frozen', 120000);
    card = await cardOf();
    expect(card.freeze_on && card.freeze_says === 'On' && card.alert && card.status.startsWith('Your account is frozen until ') && card.freeze_note.includes('It ends by itself') && card.freeze_note.includes('freeze again'), JSON.stringify(card));
    const offers = await browser.ask(carol, `(() => { const q = (s) => document.querySelector(s), seen = (s) => q(s).getClientRects().length > 0; return { end_the_freeze: seen('#unfreeze-open'), freeze_again: seen('#freeze-again'), pause_disabled: q('#pause-switch').disabled, change_disabled: q('#limit-open').disabled, step_open: seen('#freeze-form'), secret: q('#freeze-secret').value.length }; })()`);
    expect(offers.end_the_freeze && !offers.freeze_again && offers.pause_disabled && !offers.step_open && offers.secret === 0, JSON.stringify(offers));
    await browser.click(carol, '#freeze-switch');
    await until(carol, `document.querySelector('#unfreeze-form').getClientRects().length > 0`, 'switching the freeze off opens "End the freeze"');
    const off = await browser.ask(carol, `({ still_on: document.querySelector('#freeze-switch').checked, asks_for: [...document.querySelectorAll('#unfreeze-form label')].map((l) => l.textContent) })`);
    expect(off.still_on === true && off.asks_for.includes('Payment password') && off.asks_for.includes('Recovery paper'), JSON.stringify(off));
    // And the freeze is ended with the payment password and the recovery sheet.
    await browser.fill(carol, 'unfreeze-payment', PAYMENT); await browser.fill(carol, 'unfreeze-secret', sheet); await browser.click(carol, '#unfreeze-form button[type=submit]');
    await confirmReview('Unfreeze account'); await notice(carol, 'Your account is no longer frozen', 'the freeze has ended', 120000);
    card = await cardOf();
    expect(!card.freeze_on && card.status === 'Your account is protected.', JSON.stringify(card));
    await browser.ask(carol, `fetch('/__reset').then(() => true)`);
    return { paused_note: pause.body.replace(/\s+/g, ' ').slice(0, 160), ways: ways.wait_note, switches };
  });
  await step('flow: a payment of a protected account within its limit', async () => {
    const carol = await opened('protected'); await browser.ask(carol, `fetch('/__reset').then(() => true)`); await unlock(carol, 'carol');
    await browser.click(carol, '[data-panel="send"]'); await until(carol, `!document.querySelector('#send-payment-wrap').hidden`, 'the payment password');
    await browser.fill(carol, 'recipient', 'bob'); await browser.fill(carol, 'amount', '0.01'); await browser.fill(carol, 'send-payment', PAYMENT);
    await browser.click(carol, '#send-submit'); await until(carol, `document.querySelector('#review-dialog').open === true`, 'the payment review');
    const review = await browser.ask(carol, `({ title: document.querySelector('#review-title').textContent, body: document.querySelector('#review-body').innerText })`);
    await delay(800); await browser.click(carol, '#review-confirm'); await notice(carol, 'Sent. @bob has the 0.01 seconds now and needs to do nothing.', 'sent', 90000);
    expect(review.title === 'Send seconds' && review.body.includes('Left to pay today after this'), JSON.stringify(review).slice(0, 200));
    expect(await browser.ask(carol, `document.querySelector('#send-payment').value`) === '', 'the payment password stayed in its field');
  });
}
for (const page of pages) for (const p of page.problems) if (!/favicon\.ico/.test(p.text)) log.push(`page: ${p.kind}: ${p.text}`);
await writeFile(path.join(out, 'log.txt'), log.join('\n') + '\n');
console.log(`${out}\n${log.join('\n')}`);
await chrome.close();
